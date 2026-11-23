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

package proxy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
)

// ============================================================================
// F6: HEAD body suppression, Content-Length, and multi-filter_path + gzip
// ============================================================================

type headResponseWriterR64 struct {
	http.ResponseWriter
}

func (hw *headResponseWriterR64) Unwrap() http.ResponseWriter {
	return hw.ResponseWriter
}

func (hw *headResponseWriterR64) Write(b []byte) (int, error) {
	// Suppress body writes on HEAD while preserving ResponseWriter byte-count semantics.
	return len(b), nil
}

func (hw *headResponseWriterR64) Flush() {
	if fl, ok := hw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func unwrapResponseFormatAndHeadR64(w http.ResponseWriter) (esResponseFormatOptions, bool, bool) {
	var opts esResponseFormatOptions
	hasOpts := false
	isHead := false
	for w != nil {
		switch tw := w.(type) {
		case *headResponseWriterR64:
			isHead = true
			w = tw.ResponseWriter
		case *gzipResponseWriter:
			w = tw.ResponseWriter
		case *esFormatResponseWriter:
			if !hasOpts {
				opts = tw.opts
				hasOpts = true
			}
			w = tw.ResponseWriter
		default:
			if uw, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
				next := uw.Unwrap()
				if next == nil || next == w {
					return opts, hasOpts, isHead
				}
				w = next
				continue
			}
			return opts, hasOpts, isHead
		}
	}
	return opts, hasOpts, isHead
}

func extractESResponseFormatOptionsR64(w http.ResponseWriter) (esResponseFormatOptions, bool) {
	opts, hasOpts, _ := unwrapResponseFormatAndHeadR64(w)
	return opts, hasOpts
}

func refreshFormatOptionsMultiFilterPathR64(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	if w == nil || r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return w
	}
	opts, hasOpts := parseESResponseFormatOptionsRound61(r)
	if !hasOpts {
		return w
	}
	cur := w
	for cur != nil {
		switch tw := cur.(type) {
		case *headResponseWriterR64:
			cur = tw.ResponseWriter
		case *gzipResponseWriter:
			cur = tw.ResponseWriter
		case *esFormatResponseWriter:
			tw.opts = opts
			return w
		default:
			if uw, ok := cur.(interface{ Unwrap() http.ResponseWriter }); ok {
				next := uw.Unwrap()
				if next == nil || next == cur {
					cur = nil
				} else {
					cur = next
				}
				continue
			}
			cur = nil
		}
	}
	return &esFormatResponseWriter{ResponseWriter: w, opts: opts}
}

// ============================================================================
// F28: UTF-16 code unit offset -> UTF-8 byte offset helper for highlights
// ============================================================================

func utf16OffsetsToByteOffsetsR64(s string) []int {
	if s == "" {
		return []int{0}
	}
	// Pre-size upper bound cleanly; append 1 entry per BMP code unit and 2 per supplementary rune.
	out := make([]int, 0, len(s)+1)
	bytePos := 0
	for bytePos < len(s) {
		r, size := utf8.DecodeRuneInString(s[bytePos:])
		if size <= 0 {
			out = append(out, bytePos)
			bytePos++
			continue
		}
		out = append(out, bytePos)
		if r >= 0x10000 {
			// Surrogate pair: map second code unit to the start of the rune so spans never split UTF-8.
			out = append(out, bytePos)
		}
		bytePos += size
	}
	out = append(out, len(s))
	return out
}

func resolveUTF16HighlightSpanBytesR64(u16ToByte []int, startU16, endU16 int) (int, int, bool) {
	if startU16 < 0 || endU16 <= startU16 || endU16 >= len(u16ToByte) {
		return 0, 0, false
	}
	bStart := u16ToByte[startU16]
	bEnd := u16ToByte[endU16]
	if bEnd <= bStart {
		return 0, 0, false
	}
	return bStart, bEnd, true
}

// ============================================================================
// F3: ILM policy validation, delete-in-use, multi-wildcard & explain
// ============================================================================

var ilmPhaseOrderR64 = []string{"hot", "warm", "cold", "frozen", "delete"}

var ilmValidActionsByPhaseR64 = map[string]map[string]bool{
	"hot": {
		"rollover":            true,
		"set_priority":        true,
		"unfollow":            true,
		"searchable_snapshot": true,
		"downsample":          true,
		"wait_for_snapshot":   true,
	},
	"warm": {
		"set_priority":      true,
		"unfollow":          true,
		"readonly":          true,
		"allocate":          true,
		"migrate":           true,
		"forcemerge":        true,
		"shrink":            true,
		"downsample":        true,
		"wait_for_snapshot": true,
	},
	"cold": {
		"set_priority":        true,
		"readonly":            true,
		"allocate":            true,
		"migrate":             true,
		"freeze":              true,
		"searchable_snapshot": true,
		"downsample":          true,
		"wait_for_snapshot":   true,
	},
	"frozen": {
		"searchable_snapshot": true,
		"downsample":          true,
		"wait_for_snapshot":   true,
		"allocate":            true,
	},
	"delete": {
		"delete":            true,
		"wait_for_snapshot": true,
	},
}

func parseILMDurationMillisR64(raw string, allowCalendar bool) (float64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	i := 0
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid duration [%s]", raw)
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil || math.IsNaN(num) || math.IsInf(num, 0) || num < 0 {
		return 0, fmt.Errorf("invalid duration [%s]", raw)
	}
	unit := strings.TrimSpace(s[i:])
	if unit == "" {
		unit = "ms"
	}
	if allowCalendar {
		switch unit {
		case "w":
			return num * float64(7*24*time.Hour/time.Millisecond), nil
		case "M":
			return num * float64(30*24*time.Hour/time.Millisecond), nil
		case "q":
			return num * float64(90*24*time.Hour/time.Millisecond), nil
		case "y":
			return num * float64(365*24*time.Hour/time.Millisecond), nil
		}
	}
	switch strings.ToLower(unit) {
	case "nanos":
		return num / 1e6, nil
	case "micros":
		return num / 1e3, nil
	case "ms":
		return num, nil
	case "s":
		return num * 1000, nil
	case "m":
		return num * 60 * 1000, nil
	case "h":
		return num * 3600 * 1000, nil
	case "d":
		return num * 86400 * 1000, nil
	default:
		return 0, fmt.Errorf("unknown time unit [%s] in [%s]", unit, raw)
	}
}

func validateILMPolicyBodyR64(polInner map[string]any) (string, bool) {
	if polInner == nil {
		return "", true
	}
	rawPhases, hasPhases := polInner["phases"]
	if !hasPhases || rawPhases == nil {
		return "", true
	}
	phasesMap, ok := rawPhases.(map[string]any)
	if !ok {
		return "illegal_argument_exception: lifecycle policy phases must be an object", false
	}
	for phaseName, rawPhase := range phasesMap {
		allowedActions, known := ilmValidActionsByPhaseR64[phaseName]
		if !known {
			return fmt.Sprintf("unknown phase [%s] in lifecycle policy", phaseName), false
		}
		if rawPhase == nil {
			continue
		}
		phaseObj, okObj := rawPhase.(map[string]any)
		if !okObj {
			return fmt.Sprintf("phase [%s] must be an object", phaseName), false
		}
		actionsMap, _ := phaseObj["actions"].(map[string]any)
		for actName := range actionsMap {
			if !allowedActions[actName] {
				return fmt.Sprintf("action [%s] is not allowed in phase [%s]", actName, phaseName), false
			}
		}
		if _, hasDownsample := actionsMap["downsample"]; hasDownsample && phaseName == "hot" {
			if _, hasRollover := actionsMap["rollover"]; !hasRollover {
				return "the [downsample] action(s) may not be used in the [hot] phase without an accompanying [rollover] action", false
			}
		}
	}

	hasPrevAge := false
	var prevAgePhase, prevAgeRaw string
	var prevAgeMillis float64

	hasPrevDS := false
	var prevDSPhase, prevDSRaw string
	var prevDSMillis float64

	for _, phaseName := range ilmPhaseOrderR64 {
		rawPhase, exists := phasesMap[phaseName]
		if !exists || rawPhase == nil {
			continue
		}
		phaseObj, _ := rawPhase.(map[string]any)
		if phaseObj == nil {
			continue
		}
		curAgeRaw := "0ms"
		if rawMinAge, okMA := phaseObj["min_age"]; okMA && rawMinAge != nil {
			curAgeRaw = strings.TrimSpace(fmt.Sprintf("%v", rawMinAge))
		}
		curAgeMillis, ageErr := parseILMDurationMillisR64(curAgeRaw, false)
		if ageErr != nil {
			return fmt.Sprintf("invalid min_age [%s] for phase [%s]: %v", curAgeRaw, phaseName, ageErr), false
		}
		if hasPrevAge && curAgeMillis < prevAgeMillis {
			return fmt.Sprintf(
				"Your policy is configured to run the %s phase (min_age: %s) before the %s phase (min_age: %s). You should change the phase timing so that the phases will execute in the order of hot, warm, then cold.",
				phaseName, curAgeRaw, prevAgePhase, prevAgeRaw,
			), false
		}
		hasPrevAge = true
		prevAgePhase = phaseName
		prevAgeRaw = curAgeRaw
		prevAgeMillis = curAgeMillis

		if actionsMap, okA := phaseObj["actions"].(map[string]any); okA {
			if rawDS, okDS := actionsMap["downsample"]; okDS {
				dsMap, okDSM := rawDS.(map[string]any)
				if !okDSM {
					return fmt.Sprintf("downsample configuration for phase [%s] must be an object", phaseName), false
				}
				fiRaw, _ := dsMap["fixed_interval"].(string)
				fiRaw = strings.TrimSpace(fiRaw)
				if fiRaw == "" {
					return fmt.Sprintf("missing [fixed_interval] for downsample action in phase [%s]", phaseName), false
				}
				fiMillis, fiErr := parseILMDurationMillisR64(fiRaw, true)
				if fiErr != nil || fiMillis <= 0 {
					return fmt.Sprintf("invalid downsample fixed_interval [%s] in phase [%s]", fiRaw, phaseName), false
				}
				if hasPrevDS && fiMillis <= prevDSMillis {
					return fmt.Sprintf(
						"Downsampling interval [%s] for phase [%s] must be greater than the interval [%s] for phase [%s]",
						fiRaw, phaseName, prevDSRaw, prevDSPhase,
					), false
				}
				hasPrevDS = true
				prevDSPhase = phaseName
				prevDSRaw = fiRaw
				prevDSMillis = fiMillis
			}
		}
	}
	return "", true
}

func hasMultiWildcardPatternListR64(policy string) bool {
	if !strings.Contains(policy, ",") {
		return false
	}
	for _, part := range strings.Split(policy, ",") {
		part = strings.TrimSpace(part)
		if strings.ContainsAny(part, "*?") {
			return true
		}
	}
	return false
}

func extractIndexILMPolicyNameR64(cs map[string]any, owningDS map[string]any) string {
	if cs != nil {
		if pol, _, _ := extractILMPolicyFromSettingsR62Search(cs); pol != "" {
			return pol
		}
	}
	if owningDS != nil {
		if pol, ok := owningDS["ilm_policy"].(string); ok && pol != "" {
			return pol
		}
	}
	return ""
}

func (s *Server) collectIndicesUsingILMPolicyLockedR64(policy string) []string {
	seen := make(map[string]bool)
	for idx := range s.indices {
		// Still consider closed indices if configured with this policy, matching ES.
		var owningDS map[string]any
		if dsName := s.findOwningDataStreamLockedR62Search(idx); dsName != "" {
			owningDS = s.dataStreams[dsName]
		}
		if extractIndexILMPolicyNameR64(s.indexCustomSettings[idx], owningDS) == policy {
			seen[idx] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for idx := range seen {
		out = append(out, idx)
	}
	sort.Strings(out)
	return out
}

func (s *Server) collectAllILMExplainTargetsR64() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool)
	for name := range s.indices {
		if s.isIndexExplicitlyHiddenLocked(name) {
			continue
		}
		seen[name] = true
	}
	for _, ds := range s.dataStreams {
		if hv, okH := ds["hidden"].(bool); okH && hv {
			continue
		}
		for _, bi := range extractDataStreamBackingIndexNames(ds) {
			if _, ok := s.indices[bi]; ok {
				seen[bi] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for idx := range seen {
		out = append(out, idx)
	}
	sort.Strings(out)
	return out
}

func buildILMExplainIndexEntryR64(
	idx string,
	cs map[string]any,
	owningDS map[string]any,
	idxSchema *schema.IndexSchema,
	ilmPolicies map[string]map[string]any,
) (map[string]any, bool, bool) {
	polName := extractIndexILMPolicyNameR64(cs, owningDS)
	if polName == "" {
		return map[string]any{
			"index":   idx,
			"managed": false,
		}, false, false
	}

	phase := "new"
	action := "complete"
	step := "complete"
	if cs != nil {
		if p, okP := cs["__ilm_phase"].(string); okP && p != "" {
			phase = p
		}
		if a, okA := cs["__ilm_action"].(string); okA && a != "" {
			action = a
		}
		if st, okS := cs["__ilm_step"].(string); okS && st != "" {
			step = st
		}
	}

	createdMs := int64(1700000000000)
	if cs != nil {
		if rawMs, okMs := toInt64(cs["creation_date"]); okMs && rawMs > 0 {
			createdMs = rawMs
		}
	}
	_ = idxSchema
	nowMs := time.Now().UnixMilli()
	if nowMs < createdMs {
		nowMs = createdMs
	}
	ageSec := (nowMs - createdMs) / 1000
	ageStr := fmt.Sprintf("%ds", ageSec)

	polEntry, polExists := ilmPolicies[polName]
	hasError := step == "ERROR" || !polExists || polEntry == nil

	entry := map[string]any{
		"index":                      idx,
		"managed":                    true,
		"policy":                     polName,
		"index_creation_date_millis": createdMs,
		"time_since_index_creation":  ageStr,
		"lifecycle_date_millis":      createdMs,
		"age":                        ageStr,
		"phase":                      phase,
		"phase_time_millis":          createdMs,
		"action":                     action,
		"action_time_millis":         createdMs,
		"step":                       step,
		"step_time_millis":           createdMs,
	}

	if hasError {
		failedStep := step
		if !polExists || polEntry == nil {
			entry["step"] = "ERROR"
			failedStep = "check-policy-exists"
			entry["step_info"] = map[string]any{
				"type":   "illegal_argument_exception",
				"reason": fmt.Sprintf("policy [%s] for index [%s] does not exist", polName, idx),
			}
		} else {
			if failedStep == "" || failedStep == "ERROR" {
				failedStep = action
			}
			entry["step_info"] = map[string]any{
				"type":   "illegal_argument_exception",
				"reason": fmt.Sprintf("index [%s] encountered an error in lifecycle step [%s]", idx, failedStep),
			}
		}
		entry["failed_step"] = failedStep
		entry["is_auto_retryable_error"] = true
	} else {
		ver := 1
		if v, okV := toInt64(polEntry["version"]); okV && v > 0 {
			ver = int(v)
		}
		entry["phase_execution"] = map[string]any{
			"policy":                  polName,
			"version":                 ver,
			"modified_date_in_millis": createdMs,
		}
	}
	return entry, true, hasError
}

type vwhNodeR64 struct {
	cluster vwhClusterR63
	prev    int
	next    int
	alive   bool
	version int
	pos     int
}

type vwhMergeCandidateR64 struct {
	left     int
	right    int
	leftVer  int
	rightVer int
	dist     float64
	leftPos  int
}

type vwhMergeHeapR64 []vwhMergeCandidateR64

func (h vwhMergeHeapR64) Len() int { return len(h) }

func (h vwhMergeHeapR64) Less(i, j int) bool {
	if h[i].dist != h[j].dist {
		return h[i].dist < h[j].dist
	}
	return h[i].leftPos < h[j].leftPos
}

func (h vwhMergeHeapR64) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *vwhMergeHeapR64) Push(x any) { *h = append(*h, x.(vwhMergeCandidateR64)) }

func (h *vwhMergeHeapR64) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// ============================================================================
// F14: Runtime geo_shape emit context, coercion, WKT/GeoJSON formatting
// ============================================================================

func runtimeFieldTypeToEmitContextR64(esType string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "geo_shape", "shape":
		return "geo_shape", true
	default:
		return runtimeFieldTypeToEmitContextRound60(esType)
	}
}

func formatJavaFloatOrCoordWKT(v float64) string {
	return painless.FormatJavaFloat64(v)
}

func formatRingToWKTCoordsR64(ring [][2]float64) string {
	parts := make([]string, len(ring))
	for i, pt := range ring {
		// pt is [lat, lon]; WKT expects "lon lat"
		parts[i] = formatJavaFloatOrCoordWKT(pt[1]) + " " + formatJavaFloatOrCoordWKT(pt[0])
	}
	return strings.Join(parts, ", ")
}

func normalizeGeoShapeValueToGeoJSONR64(rv any, quantize bool) (any, bool) {
	if rv == nil {
		return nil, false
	}
	if gs, ok := rv.(*painless.GeoShapeDocValues); ok && gs != nil {
		return gs.ToGeoJSONMap(), true
	}
	if gp, ok := rv.(*painless.GeoPointVal); ok && gp != nil {
		lat, lon := gp.Lat, gp.Lon
		if quantize {
			lat, lon = painless.QuantizeLuceneGeoPoint(lat, lon)
		}
		return map[string]any{"type": "Point", "coordinates": []any{lon, lat}}, true
	}
	if bb, ok := rv.(*painless.GeoBoundingBoxVal); ok && bb != nil {
		return map[string]any{
			"type":        "Envelope",
			"coordinates": []any{[]any{bb.GetMinLon(), bb.GetMaxLat()}, []any{bb.GetMaxLon(), bb.GetMinLat()}},
		}, true
	}
	// Handle WKT strings (including BBOX(left, top, right, bottom)) cleanly.
	if s, ok := rv.(string); ok {
		if parsed, okP := parseSingleWKTEnvelopeOrShapeToGeoJSONR64(s, quantize); okP {
			return parsed, true
		}
	}
	if gs, err := painless.ParseGeoShapeDocValuesWithOpts(rv, quantize); err == nil && gs != nil {
		if m := gs.ToGeoJSONMap(); m != nil {
			return m, true
		}
	}
	return nil, false
}

func parseWKTBBoxCoordsR64(s string) (topLat, leftLon, botLat, rightLon float64, ok bool) {
	trimmed := strings.TrimSpace(s)
	openP := strings.IndexByte(trimmed, '(')
	closeP := strings.LastIndexByte(trimmed, ')')
	if openP <= 0 || closeP <= openP {
		return 0, 0, 0, 0, false
	}
	kind := strings.ToUpper(strings.TrimSpace(trimmed[:openP]))
	if kind != "BBOX" && kind != "ENVELOPE" {
		return 0, 0, 0, 0, false
	}
	parts := strings.Split(trimmed[openP+1:closeP], ",")
	if len(parts) != 4 {
		return 0, 0, 0, 0, false
	}
	var c [4]float64
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, 0, 0, 0, false
		}
		c[i] = v
	}
	if kind == "BBOX" {
		// Elastic WKT BBOX(leftLon, topLat, rightLon, bottomLat) vs minLon/maxLon/maxLat/minLat:
		// If c[1] > c[3] or c[0] < c[2], treat (leftLon, topLat, rightLon, bottomLat);
		// note ENVELOPE uses (minLon, maxLon, maxLat, minLat).
		leftLon = c[0]
		topLat = c[1]
		rightLon = c[2]
		botLat = c[3]
		if topLat < botLat && c[2] >= c[3] && c[0] <= c[1] {
			leftLon, rightLon, topLat, botLat = c[0], c[1], c[2], c[3]
		}
		return topLat, leftLon, botLat, rightLon, true
	}
	// WKT ENVELOPE(minLon, maxLon, maxLat, minLat)
	return math.Max(c[2], c[3]), math.Min(c[0], c[1]), math.Min(c[2], c[3]), math.Max(c[0], c[1]), true
}

func parseSingleWKTEnvelopeOrShapeToGeoJSONR64(s string, quantize bool) (any, bool) {
	if topLat, leftLon, botLat, rightLon, okB := parseWKTBBoxCoordsR64(s); okB {
		if quantize {
			topLat, leftLon = painless.QuantizeLuceneGeoPoint(topLat, leftLon)
			botLat, rightLon = painless.QuantizeLuceneGeoPoint(botLat, rightLon)
		}
		return map[string]any{
			"type":        "Envelope",
			"coordinates": []any{[]any{leftLon, topLat}, []any{rightLon, botLat}},
		}, true
	}
	gs, err := painless.ParseGeoShapeDocValuesWithOpts(s, quantize)
	if err == nil && gs != nil {
		if m := gs.ToGeoJSONMap(); m != nil {
			return m, true
		}
	}
	return nil, false
}

func formatGeoShapeSingleWKTR64(v any) (string, bool) {
	if s, ok := v.(string); ok {
		trimmed := strings.TrimSpace(s)
		shapes, okP := parseRawShapesR64(trimmed, false)
		if okP && len(shapes) > 0 {
			return formatParsedShapesToWKTR64(shapes), true
		}
		if trimmed != "" {
			return trimmed, true
		}
		return "", false
	}
	shapes, okP := parseRawShapesR64(v, false)
	if !okP || len(shapes) == 0 {
		if m, okM := v.(map[string]any); okM {
			return fmt.Sprintf("%v", convertSpatialWKTAndGeoJSONR63(m, true)), true
		}
		return "", false
	}
	return formatParsedShapesToWKTR64(shapes), true
}

func formatParsedShapesToWKTR64(shapes []parsedGeomR64) string {
	if len(shapes) == 0 {
		return ""
	}
	if len(shapes) == 1 {
		return shapes[0].toWKT()
	}
	parts := make([]string, 0, len(shapes))
	for _, sh := range shapes {
		parts = append(parts, sh.toWKT())
	}
	return "GEOMETRYCOLLECTION (" + strings.Join(parts, ",") + ")"
}

func formatGeoShapeValuesForFieldsR64(rawVals []any, wantWKT bool) []any {
	if len(rawVals) == 0 {
		return nil
	}
	if !wantWKT {
		out := make([]any, 0, len(rawVals))
		for _, el := range rawVals {
			if norm, ok := normalizeGeoShapeValueToGeoJSONR64(el, false); ok && norm != nil {
				out = append(out, norm)
			} else {
				out = append(out, convertSpatialWKTAndGeoJSONR63(el, false))
			}
		}
		return out
	}
	var wktParts []string
	for _, el := range rawVals {
		if w, ok := formatGeoShapeSingleWKTR64(el); ok && w != "" {
			wktParts = append(wktParts, w)
		}
	}
	if len(wktParts) == 0 {
		return nil
	}
	if len(wktParts) == 1 {
		return []any{wktParts[0]}
	}
	return []any{"GEOMETRYCOLLECTION (" + strings.Join(wktParts, ",") + ")"}
}

// ============================================================================
// Geometry Representation & Exact Planar/Geographic Operations (F12, F13)
// ============================================================================

type geomKindR64 int

const (
	geomPointR64 geomKindR64 = iota
	geomLineR64
	geomPolygonR64
	geomEnvelopeR64
)

type parsedGeomR64 struct {
	kind            geomKindR64
	pt              [2]float64     // [y/lat, x/lon]
	line            [][2]float64   // sequence of [y/lat, x/lon]
	outer           [][2]float64   // polygon outer ring [y/lat, x/lon]
	holes           [][][2]float64 // polygon hole rings [y/lat, x/lon]
	topLat          float64        // envelope top (maxY)
	botLat          float64        // envelope bottom (minY)
	leftLon         float64        // envelope left (minX)
	rightLon        float64        // envelope right (maxX)
	crossesDateline bool
}

func (g parsedGeomR64) dim() int {
	switch g.kind {
	case geomPointR64:
		return 0
	case geomLineR64:
		return 1
	case geomPolygonR64, geomEnvelopeR64:
		return 2
	default:
		return 0
	}
}

func (g parsedGeomR64) toWKT() string {
	switch g.kind {
	case geomPointR64:
		return fmt.Sprintf("POINT (%s %s)", formatJavaFloatOrCoordWKT(g.pt[1]), formatJavaFloatOrCoordWKT(g.pt[0]))
	case geomLineR64:
		return "LINESTRING (" + formatRingToWKTCoordsR64(g.line) + ")"
	case geomPolygonR64:
		rings := make([]string, 0, 1+len(g.holes))
		rings = append(rings, "("+formatRingToWKTCoordsR64(g.outer)+")")
		for _, h := range g.holes {
			rings = append(rings, "("+formatRingToWKTCoordsR64(h)+")")
		}
		return "POLYGON (" + strings.Join(rings, ", ") + ")"
	case geomEnvelopeR64:
		return fmt.Sprintf("BBOX (%s, %s, %s, %s)",
			formatJavaFloatOrCoordWKT(g.leftLon),
			formatJavaFloatOrCoordWKT(g.topLat),
			formatJavaFloatOrCoordWKT(g.rightLon),
			formatJavaFloatOrCoordWKT(g.botLat),
		)
	default:
		return ""
	}
}

func (g parsedGeomR64) vertices() [][2]float64 {
	switch g.kind {
	case geomPointR64:
		return [][2]float64{g.pt}
	case geomLineR64:
		return g.line
	case geomPolygonR64:
		return g.outer
	case geomEnvelopeR64:
		return [][2]float64{
			{g.topLat, g.leftLon},
			{g.topLat, g.rightLon},
			{g.botLat, g.rightLon},
			{g.botLat, g.leftLon},
		}
	default:
		return nil
	}
}

func (g parsedGeomR64) bbox() (topLat, leftLon, botLat, rightLon float64) {
	if g.kind == geomEnvelopeR64 {
		return g.topLat, g.leftLon, g.botLat, g.rightLon
	}
	vs := g.vertices()
	if len(vs) == 0 {
		return 0, 0, 0, 0
	}
	minY, maxY := vs[0][0], vs[0][0]
	minX, maxX := vs[0][1], vs[0][1]
	for _, p := range vs[1:] {
		if p[0] < minY {
			minY = p[0]
		}
		if p[0] > maxY {
			maxY = p[0]
		}
		if p[1] < minX {
			minX = p[1]
		}
		if p[1] > maxX {
			maxX = p[1]
		}
	}
	return maxY, minX, minY, maxX
}

func quantizeCoordIfR64(yLat, xLon float64, quantize bool) [2]float64 {
	if quantize {
		ql, qg := painless.QuantizeLuceneGeoPoint(yLat, xLon)
		return [2]float64{ql, qg}
	}
	return [2]float64{yLat, xLon}
}

func checkSeqDatelineR64(seq [][2]float64, quantize bool) bool {
	if !quantize || len(seq) < 2 {
		return false
	}
	for i := 0; i < len(seq)-1; i++ {
		if math.Abs(seq[i+1][1]-seq[i][1]) > 180.0 {
			return true
		}
	}
	return false
}

func parseWKTParenGroupsR64(s string) []string {
	var groups []string
	depth := 0
	start := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				groups = append(groups, s[start:i])
				start = -1
			}
		}
	}
	return groups
}

func splitTopLevelWKTR64(s string) []string {
	var items []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				if part := strings.TrimSpace(s[start:i]); part != "" {
					items = append(items, part)
				}
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		items = append(items, tail)
	}
	return items
}

func isFiniteCoordR64(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func parseWKTCoordSeqR64(seqStr string, quantize bool) ([][2]float64, bool) {
	items := strings.Split(seqStr, ",")
	out := make([][2]float64, 0, len(items))
	for _, it := range items {
		fields := strings.Fields(strings.Trim(strings.TrimSpace(it), "()"))
		if len(fields) < 2 {
			return nil, false
		}
		x, errX := strconv.ParseFloat(fields[0], 64)
		y, errY := strconv.ParseFloat(fields[1], 64)
		if errX != nil || errY != nil || !isFiniteCoordR64(x) || !isFiniteCoordR64(y) {
			return nil, false
		}
		out = append(out, quantizeCoordIfR64(y, x, quantize))
	}
	return out, len(out) > 0
}

func parseJSONCoordPairR64(raw any, quantize bool) ([2]float64, bool) {
	switch v := raw.(type) {
	case []any:
		if len(v) < 2 {
			return [2]float64{}, false
		}
		x, okX := toFloat64(v[0])
		y, okY := toFloat64(v[1])
		if !okX || !okY || !isFiniteCoordR64(x) || !isFiniteCoordR64(y) {
			return [2]float64{}, false
		}
		return quantizeCoordIfR64(y, x, quantize), true
	case []float64:
		if len(v) < 2 || !isFiniteCoordR64(v[0]) || !isFiniteCoordR64(v[1]) {
			return [2]float64{}, false
		}
		return quantizeCoordIfR64(v[1], v[0], quantize), true
	}
	return [2]float64{}, false
}

func parseJSONCoordSeqR64(raw any, quantize bool) ([][2]float64, bool) {
	arr, ok := raw.([]any)
	if !ok {
		if fa, okF := raw.([][]float64); okF {
			out := make([][2]float64, 0, len(fa))
			for _, pt := range fa {
				if len(pt) < 2 || !isFiniteCoordR64(pt[0]) || !isFiniteCoordR64(pt[1]) {
					return nil, false
				}
				out = append(out, quantizeCoordIfR64(pt[1], pt[0], quantize))
			}
			return out, len(out) > 0
		}
		return nil, false
	}
	out := make([][2]float64, 0, len(arr))
	for _, item := range arr {
		pt, okP := parseJSONCoordPairR64(item, quantize)
		if !okP {
			return nil, false
		}
		out = append(out, pt)
	}
	return out, len(out) > 0
}

func parseRawShapesR64(raw any, quantize bool) ([]parsedGeomR64, bool) {
	if raw == nil {
		return nil, false
	}
	switch v := raw.(type) {
	case *painless.GeoShapeDocValues:
		if v == nil {
			return nil, false
		}
		return parseRawShapesR64(v.ToGeoJSONMap(), quantize)
	case *painless.GeoPointVal:
		if v == nil || !isFiniteCoordR64(v.Lat) || !isFiniteCoordR64(v.Lon) {
			return nil, false
		}
		pt := quantizeCoordIfR64(v.Lat, v.Lon, quantize)
		return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
	case *painless.GeoBoundingBoxVal:
		if v == nil ||
			!isFiniteCoordR64(v.GetMaxLat()) || !isFiniteCoordR64(v.GetMinLon()) ||
			!isFiniteCoordR64(v.GetMinLat()) || !isFiniteCoordR64(v.GetMaxLon()) {
			return nil, false
		}
		tl := quantizeCoordIfR64(v.GetMaxLat(), v.GetMinLon(), quantize)
		br := quantizeCoordIfR64(v.GetMinLat(), v.GetMaxLon(), quantize)
		return []parsedGeomR64{{
			kind:     geomEnvelopeR64,
			topLat:   tl[0],
			leftLon:  tl[1],
			botLat:   br[0],
			rightLon: br[1],
		}}, true
	case string:
		str := strings.TrimSpace(v)
		if str == "" {
			return nil, false
		}
		if strings.HasPrefix(str, "{") || strings.HasPrefix(str, "[") {
			var decoded any
			dec := json.NewDecoder(strings.NewReader(str))
			dec.UseNumber()
			if dec.Decode(&decoded) == nil && decoded != nil {
				if res, ok := parseRawShapesR64(decoded, quantize); ok {
					return res, true
				}
			}
		}
		upper := strings.ToUpper(str)
		openP := strings.IndexByte(str, '(')
		closeP := strings.LastIndexByte(str, ')')
		if openP > 0 && closeP > openP {
			kind := strings.TrimSpace(upper[:openP])
			inner := strings.TrimSpace(str[openP+1 : closeP])
			switch kind {
			case "POINT":
				seq, ok := parseWKTCoordSeqR64(inner, quantize)
				if ok && len(seq) > 0 {
					return []parsedGeomR64{{kind: geomPointR64, pt: seq[0]}}, true
				}
			case "MULTIPOINT":
				groups := parseWKTParenGroupsR64(inner)
				var pts [][2]float64
				if len(groups) > 0 {
					for _, g := range groups {
						if seq, ok := parseWKTCoordSeqR64(g, quantize); ok {
							pts = append(pts, seq...)
						}
					}
				} else if seq, ok := parseWKTCoordSeqR64(inner, quantize); ok {
					pts = seq
				}
				if len(pts) > 0 {
					out := make([]parsedGeomR64, len(pts))
					for i, pt := range pts {
						out[i] = parsedGeomR64{kind: geomPointR64, pt: pt}
					}
					return out, true
				}
			case "LINESTRING":
				if seq, ok := parseWKTCoordSeqR64(inner, quantize); ok && len(seq) > 0 {
					return []parsedGeomR64{{kind: geomLineR64, line: seq, crossesDateline: checkSeqDatelineR64(seq, quantize)}}, true
				}
			case "MULTILINESTRING":
				groups := parseWKTParenGroupsR64(inner)
				var out []parsedGeomR64
				for _, g := range groups {
					if seq, ok := parseWKTCoordSeqR64(g, quantize); ok && len(seq) > 0 {
						out = append(out, parsedGeomR64{kind: geomLineR64, line: seq, crossesDateline: checkSeqDatelineR64(seq, quantize)})
					}
				}
				if len(out) > 0 {
					return out, true
				}
			case "POLYGON":
				groups := parseWKTParenGroupsR64(inner)
				if len(groups) > 0 {
					outer, ok := parseWKTCoordSeqR64(groups[0], quantize)
					if ok && len(outer) >= 3 {
						cd := checkSeqDatelineR64(outer, quantize)
						var holes [][][2]float64
						for _, hg := range groups[1:] {
							if hs, okH := parseWKTCoordSeqR64(hg, quantize); okH && len(hs) >= 3 {
								if checkSeqDatelineR64(hs, quantize) {
									cd = true
								}
								holes = append(holes, hs)
							}
						}
						return []parsedGeomR64{{kind: geomPolygonR64, outer: outer, holes: holes, crossesDateline: cd}}, true
					}
				}
			case "MULTIPOLYGON":
				polyGroups := parseWKTParenGroupsR64(inner)
				var out []parsedGeomR64
				for _, pg := range polyGroups {
					ringGroups := parseWKTParenGroupsR64(pg)
					if len(ringGroups) == 0 {
						continue
					}
					outer, ok := parseWKTCoordSeqR64(ringGroups[0], quantize)
					if !ok || len(outer) < 3 {
						continue
					}
					cd := checkSeqDatelineR64(outer, quantize)
					var holes [][][2]float64
					for _, hg := range ringGroups[1:] {
						if hs, okH := parseWKTCoordSeqR64(hg, quantize); okH && len(hs) >= 3 {
							if checkSeqDatelineR64(hs, quantize) {
								cd = true
							}
							holes = append(holes, hs)
						}
					}
					out = append(out, parsedGeomR64{kind: geomPolygonR64, outer: outer, holes: holes, crossesDateline: cd})
				}
				if len(out) > 0 {
					return out, true
				}
			case "BBOX", "ENVELOPE":
				if topLat, leftLon, botLat, rightLon, okB := parseWKTBBoxCoordsR64(str); okB {
					tl := quantizeCoordIfR64(topLat, leftLon, quantize)
					br := quantizeCoordIfR64(botLat, rightLon, quantize)
					return []parsedGeomR64{{
						kind:     geomEnvelopeR64,
						topLat:   tl[0],
						leftLon:  tl[1],
						botLat:   br[0],
						rightLon: br[1],
					}}, true
				}
			case "GEOMETRYCOLLECTION":
				items := splitTopLevelWKTR64(inner)
				var out []parsedGeomR64
				for _, item := range items {
					if subs, okSub := parseRawShapesR64(item, quantize); okSub {
						out = append(out, subs...)
					}
				}
				if len(out) > 0 {
					return out, true
				}
			}
		}
		if lat, lon, okPt := parseGeoPointLatLon(str); okPt && isFiniteCoordR64(lat) && isFiniteCoordR64(lon) {
			pt := quantizeCoordIfR64(lat, lon, quantize)
			return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
		}
	case map[string]any:
		if rawType, ok := v["type"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(rawType)) {
			case "point":
				if pt, okP := parseJSONCoordPairR64(v["coordinates"], quantize); okP {
					return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
				}
			case "multipoint":
				if seq, okS := parseJSONCoordSeqR64(v["coordinates"], quantize); okS && len(seq) > 0 {
					out := make([]parsedGeomR64, len(seq))
					for i, pt := range seq {
						out[i] = parsedGeomR64{kind: geomPointR64, pt: pt}
					}
					return out, true
				}
			case "linestring":
				if seq, okS := parseJSONCoordSeqR64(v["coordinates"], quantize); okS && len(seq) > 0 {
					return []parsedGeomR64{{kind: geomLineR64, line: seq, crossesDateline: checkSeqDatelineR64(seq, quantize)}}, true
				}
			case "multilinestring":
				if arr, okA := v["coordinates"].([]any); okA {
					var out []parsedGeomR64
					for _, ls := range arr {
						if seq, okS := parseJSONCoordSeqR64(ls, quantize); okS && len(seq) > 0 {
							out = append(out, parsedGeomR64{kind: geomLineR64, line: seq, crossesDateline: checkSeqDatelineR64(seq, quantize)})
						}
					}
					if len(out) > 0 {
						return out, true
					}
				}
			case "polygon":
				if rings, okR := v["coordinates"].([]any); okR && len(rings) > 0 {
					outer, okO := parseJSONCoordSeqR64(rings[0], quantize)
					if okO && len(outer) >= 3 {
						cd := checkSeqDatelineR64(outer, quantize)
						var holes [][][2]float64
						for _, hr := range rings[1:] {
							if hs, okH := parseJSONCoordSeqR64(hr, quantize); okH && len(hs) >= 3 {
								if checkSeqDatelineR64(hs, quantize) {
									cd = true
								}
								holes = append(holes, hs)
							}
						}
						return []parsedGeomR64{{kind: geomPolygonR64, outer: outer, holes: holes, crossesDateline: cd}}, true
					}
				}
			case "multipolygon":
				if polys, okP := v["coordinates"].([]any); okP {
					var out []parsedGeomR64
					for _, pr := range polys {
						if rings, okR := pr.([]any); okR && len(rings) > 0 {
							outer, okO := parseJSONCoordSeqR64(rings[0], quantize)
							if okO && len(outer) >= 3 {
								cd := checkSeqDatelineR64(outer, quantize)
								var holes [][][2]float64
								for _, hr := range rings[1:] {
									if hs, okH := parseJSONCoordSeqR64(hr, quantize); okH && len(hs) >= 3 {
										if checkSeqDatelineR64(hs, quantize) {
											cd = true
										}
										holes = append(holes, hs)
									}
								}
								out = append(out, parsedGeomR64{kind: geomPolygonR64, outer: outer, holes: holes, crossesDateline: cd})
							}
						}
					}
					if len(out) > 0 {
						return out, true
					}
				}
			case "envelope":
				if coords, okC := v["coordinates"].([]any); okC && len(coords) >= 2 {
					p1, ok1 := parseJSONCoordPairR64(coords[0], quantize)
					p2, ok2 := parseJSONCoordPairR64(coords[1], quantize)
					if ok1 && ok2 {
						return []parsedGeomR64{{
							kind:     geomEnvelopeR64,
							topLat:   math.Max(p1[0], p2[0]),
							botLat:   math.Min(p1[0], p2[0]),
							leftLon:  p1[1],
							rightLon: p2[1],
						}}, true
					}
				}
			case "geometrycollection":
				if geoms, okG := v["geometries"].([]any); okG {
					var out []parsedGeomR64
					for _, gm := range geoms {
						if subs, okSub := parseRawShapesR64(gm, quantize); okSub {
							out = append(out, subs...)
						}
					}
					if len(out) > 0 {
						return out, true
					}
				}
			}
		}
		if lat, lon, okLatLon := parseGeoPointLatLon(v); okLatLon && isFiniteCoordR64(lat) && isFiniteCoordR64(lon) {
			pt := quantizeCoordIfR64(lat, lon, quantize)
			return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
		}
		if xv, okX := toFloat64(v["x"]); okX && isFiniteCoordR64(xv) {
			if yv, okY := toFloat64(v["y"]); okY && isFiniteCoordR64(yv) {
				pt := quantizeCoordIfR64(yv, xv, quantize)
				return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
			}
		}
	case []any:
		if pt, okP := parseJSONCoordPairR64(v, quantize); okP {
			return []parsedGeomR64{{kind: geomPointR64, pt: pt}}, true
		}
		var out []parsedGeomR64
		for _, el := range v {
			if subs, okSub := parseRawShapesR64(el, quantize); okSub {
				out = append(out, subs...)
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

func extractDocFieldRawValueR64(doc map[string]any, field string, idxSchema *schema.IndexSchema) (any, bool) {
	if doc == nil || field == "" {
		return nil, false
	}
	if v, ok := doc[field]; ok {
		return v, true
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	pathSegs := strings.Split(clean, ".")
	if idxSchema != nil {
		if b := idxSchema.ResolveField(field); len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	return lookupNestedMapPathR61Search(doc, pathSegs)
}

func parseDocShapesR64(doc map[string]any, field string, idxSchema *schema.IndexSchema, quantize bool) ([]parsedGeomR64, string) {
	esType := ""
	var nullVal any
	if idxSchema != nil {
		b := idxSchema.ResolveField(field)
		if b.ESType != "" {
			esType = strings.ToLower(strings.TrimSpace(b.ESType))
		}
		nullVal = b.NullValue
	}
	raw, ok := extractDocFieldRawValueR64(doc, field, idxSchema)
	if !ok {
		return nil, esType
	}
	if raw == nil {
		if nullVal == nil {
			return nil, esType
		}
		shapes, _ := parseRawShapesR64(nullVal, quantize)
		return shapes, esType
	}
	if arr, isArr := raw.([]any); isArr && nullVal != nil {
		hasNil := false
		for _, el := range arr {
			if el == nil {
				hasNil = true
				break
			}
		}
		if hasNil {
			expanded := make([]any, 0, len(arr))
			for _, el := range arr {
				if el == nil {
					expanded = append(expanded, nullVal)
				} else {
					expanded = append(expanded, el)
				}
			}
			raw = expanded
		}
	}
	shapes, _ := parseRawShapesR64(raw, quantize)
	return shapes, esType
}

// ============================================================================
// Geometry Intersections & Centroids
// ============================================================================

func ringCentroidSignedAreaR64(ring [][2]float64) (cx, cy, absArea float64) {
	if len(ring) < 3 {
		return 0, 0, 0
	}
	var sumA, sumX, sumY float64
	n := len(ring)
	for i := 0; i < n; i++ {
		p1 := ring[i]
		p2 := ring[(i+1)%n]
		// x = lon (p[1]), y = lat (p[0])
		cross := p1[1]*p2[0] - p2[1]*p1[0]
		sumA += cross
		sumX += (p1[1] + p2[1]) * cross
		sumY += (p1[0] + p2[0]) * cross
	}
	signedArea := 0.5 * sumA
	if math.Abs(signedArea) < 1e-18 {
		// Degenerate zero-area ring fallback to vertex average
		var vx, vy float64
		for _, p := range ring {
			vx += p[1]
			vy += p[0]
		}
		return vx / float64(n), vy / float64(n), 0
	}
	cx = sumX / (6.0 * signedArea)
	cy = sumY / (6.0 * signedArea)
	return cx, cy, math.Abs(signedArea)
}

type centroidAccumR64 struct {
	maxDim   int
	sumW     float64
	sumWX    float64
	sumWY    float64
	docCount int64
}

func (c *centroidAccumR64) addGeom(g parsedGeomR64) {
	d := g.dim()
	if d < c.maxDim {
		return
	}
	if d > c.maxDim {
		c.maxDim = d
		c.sumW = 0
		c.sumWX = 0
		c.sumWY = 0
	}
	switch g.kind {
	case geomPointR64:
		c.sumW += 1.0
		c.sumWX += g.pt[1]
		c.sumWY += g.pt[0]
	case geomLineR64:
		if len(g.line) == 1 {
			c.sumW += 1.0
			c.sumWX += g.line[0][1]
			c.sumWY += g.line[0][0]
			return
		}
		var segSumW, segSumWX, segSumWY float64
		for i := 0; i < len(g.line)-1; i++ {
			p1, p2 := g.line[i], g.line[i+1]
			dx := p2[1] - p1[1]
			dy := p2[0] - p1[0]
			segLen := math.Hypot(dx, dy)
			midX := 0.5 * (p1[1] + p2[1])
			midY := 0.5 * (p1[0] + p2[0])
			segSumW += segLen
			segSumWX += midX * segLen
			segSumWY += midY * segLen
		}
		if segSumW > 0 {
			c.sumW += segSumW
			c.sumWX += segSumWX
			c.sumWY += segSumWY
		} else if len(g.line) > 0 {
			c.sumW += 1e-12
			c.sumWX += g.line[0][1] * 1e-12
			c.sumWY += g.line[0][0] * 1e-12
		}
	case geomPolygonR64:
		cx, cy, area := ringCentroidSignedAreaR64(g.outer)
		totA := area
		totWX := cx * area
		totWY := cy * area
		for _, hole := range g.holes {
			hx, hy, ha := ringCentroidSignedAreaR64(hole)
			totA -= ha
			totWX -= hx * ha
			totWY -= hy * ha
		}
		if totA > 0 {
			c.sumW += totA
			c.sumWX += totWX
			c.sumWY += totWY
		} else {
			c.sumW += 1e-12
			c.sumWX += cx * 1e-12
			c.sumWY += cy * 1e-12
		}
	case geomEnvelopeR64:
		w := math.Abs(g.rightLon - g.leftLon)
		h := math.Abs(g.topLat - g.botLat)
		area := w * h
		cx := 0.5 * (g.leftLon + g.rightLon)
		cy := 0.5 * (g.topLat + g.botLat)
		if area > 0 {
			c.sumW += area
			c.sumWX += cx * area
			c.sumWY += cy * area
		} else {
			c.sumW += 1e-12
			c.sumWX += cx * 1e-12
			c.sumWY += cy * 1e-12
		}
	}
}

func pointInRingR64(lat, lon float64, ring [][2]float64) bool {
	if len(ring) < 3 {
		return false
	}
	inside := false
	j := len(ring) - 1
	for i := 0; i < len(ring); i++ {
		yi, xi := ring[i][0], ring[i][1]
		yj, xj := ring[j][0], ring[j][1]
		if onSegment2DR64(lon, lat, xi, yi, xj, yj) {
			return true
		}
		if (yi > lat) != (yj > lat) {
			xInt := xi + (lat-yi)*(xj-xi)/(yj-yi)
			if lon <= xInt {
				inside = !inside
			}
		}
		j = i
	}
	return inside
}

func pointInPolygonR64(lat, lon float64, outer [][2]float64, holes [][][2]float64) bool {
	if !pointInRingR64(lat, lon, outer) {
		return false
	}
	for _, h := range holes {
		if pointInRingR64(lat, lon, h) {
			return false
		}
	}
	return true
}

func onSegment2DR64(px, py, ax, ay, bx, by float64) bool {
	const eps = 1e-12
	cross := (bx-ax)*(py-ay) - (by-ay)*(px-ax)
	if math.Abs(cross) > eps*math.Max(1.0, math.Abs(bx-ax)+math.Abs(by-ay)) {
		return false
	}
	return px >= math.Min(ax, bx)-eps && px <= math.Max(ax, bx)+eps &&
		py >= math.Min(ay, by)-eps && py <= math.Max(ay, by)+eps
}

func segmentsIntersect2DR64(ax, ay, bx, by, cx, cy, dx, dy float64) bool {
	orient := func(px, py, qx, qy, rx, ry float64) float64 {
		return (qx-px)*(ry-py) - (qy-py)*(rx-px)
	}
	o1 := orient(ax, ay, bx, by, cx, cy)
	o2 := orient(ax, ay, bx, by, dx, dy)
	o3 := orient(cx, cy, dx, dy, ax, ay)
	o4 := orient(cx, cy, dx, dy, bx, by)
	if ((o1 > 0 && o2 < 0) || (o1 < 0 && o2 > 0)) && ((o3 > 0 && o4 < 0) || (o3 < 0 && o4 > 0)) {
		return true
	}
	const eps = 1e-12
	if math.Abs(o1) <= eps && onSegment2DR64(cx, cy, ax, ay, bx, by) {
		return true
	}
	if math.Abs(o2) <= eps && onSegment2DR64(dx, dy, ax, ay, bx, by) {
		return true
	}
	if math.Abs(o3) <= eps && onSegment2DR64(ax, ay, cx, cy, dx, dy) {
		return true
	}
	if math.Abs(o4) <= eps && onSegment2DR64(bx, by, cx, cy, dx, dy) {
		return true
	}
	return false
}

func segmentIntersectsBox2DR64(ax, ay, bx, by, minX, minY, maxX, maxY float64) bool {
	if (ax >= minX && ax <= maxX && ay >= minY && ay <= maxY) ||
		(bx >= minX && bx <= maxX && by >= minY && by <= maxY) {
		return true
	}
	if math.Max(ax, bx) < minX || math.Min(ax, bx) > maxX || math.Max(ay, by) < minY || math.Min(ay, by) > maxY {
		return false
	}
	return segmentsIntersect2DR64(ax, ay, bx, by, minX, minY, maxX, minY) ||
		segmentsIntersect2DR64(ax, ay, bx, by, maxX, minY, maxX, maxY) ||
		segmentsIntersect2DR64(ax, ay, bx, by, maxX, maxY, minX, maxY) ||
		segmentsIntersect2DR64(ax, ay, bx, by, minX, maxY, minX, minY)
}

func geomIntersectsSimpleBoxR64(g parsedGeomR64, topLat, leftLon, botLat, rightLon float64) bool {
	switch g.kind {
	case geomPointR64:
		return g.pt[0] >= botLat && g.pt[0] <= topLat && g.pt[1] >= leftLon && g.pt[1] <= rightLon
	case geomEnvelopeR64:
		return g.botLat <= topLat && g.topLat >= botLat && g.leftLon <= rightLon && g.rightLon >= leftLon
	case geomLineR64:
		if len(g.line) == 1 {
			return g.line[0][0] >= botLat && g.line[0][0] <= topLat && g.line[0][1] >= leftLon && g.line[0][1] <= rightLon
		}
		for i := 0; i < len(g.line)-1; i++ {
			if segmentIntersectsBox2DR64(g.line[i][1], g.line[i][0], g.line[i+1][1], g.line[i+1][0], leftLon, botLat, rightLon, topLat) {
				return true
			}
		}
		return false
	case geomPolygonR64:
		gTop, gLeft, gBot, gRight := g.bbox()
		if gBot > topLat || gTop < botLat || gLeft > rightLon || gRight < leftLon {
			return false
		}
		// Any outer vertex inside box?
		for _, pt := range g.outer {
			if pt[0] >= botLat && pt[0] <= topLat && pt[1] >= leftLon && pt[1] <= rightLon {
				return true
			}
		}
		// Any box corner or center inside polygon (and not in hole)?
		boxPts := [][2]float64{
			{botLat, leftLon},
			{topLat, leftLon},
			{topLat, rightLon},
			{botLat, rightLon},
			{0.5 * (botLat + topLat), 0.5 * (leftLon + rightLon)},
		}
		for _, bp := range boxPts {
			if pointInPolygonR64(bp[0], bp[1], g.outer, g.holes) {
				return true
			}
		}
		// Any polygon edge crosses box edge?
		n := len(g.outer)
		for i := 0; i < n; i++ {
			p1 := g.outer[i]
			p2 := g.outer[(i+1)%n]
			if segmentIntersectsBox2DR64(p1[1], p1[0], p2[1], p2[0], leftLon, botLat, rightLon, topLat) {
				return true
			}
		}
		return false
	}
	return false
}

func geomIntersectsBoxR64(g parsedGeomR64, topLat, leftLon, botLat, rightLon float64) bool {
	if leftLon <= rightLon {
		return geomIntersectsSimpleBoxR64(g, topLat, leftLon, botLat, rightLon)
	}
	return geomIntersectsSimpleBoxR64(g, topLat, leftLon, botLat, 180.0) ||
		geomIntersectsSimpleBoxR64(g, topLat, -180.0, botLat, rightLon)
}

func geomBoxContainsGeomR64(g parsedGeomR64, topLat, leftLon, botLat, rightLon float64) bool {
	// True if g is completely inside box
	for _, v := range g.vertices() {
		if !geoPointInBox(v[0], v[1], topLat, leftLon, botLat, rightLon) {
			return false
		}
	}
	return len(g.vertices()) > 0
}

func geomIntersectsQueryShapeR64(docGeom, queryGeom parsedGeomR64) bool {
	if queryGeom.kind == geomEnvelopeR64 {
		return geomIntersectsBoxR64(docGeom, queryGeom.topLat, queryGeom.leftLon, queryGeom.botLat, queryGeom.rightLon)
	}
	if docGeom.kind == geomEnvelopeR64 {
		return geomIntersectsBoxR64(queryGeom, docGeom.topLat, docGeom.leftLon, docGeom.botLat, docGeom.rightLon)
	}
	switch queryGeom.kind {
	case geomPointR64:
		return geomIntersectsSimpleBoxR64(docGeom, queryGeom.pt[0]+1e-11, queryGeom.pt[1]-1e-11, queryGeom.pt[0]-1e-11, queryGeom.pt[1]+1e-11)
	case geomLineR64:
		for _, pt := range queryGeom.line {
			if geomIntersectsSimpleBoxR64(docGeom, pt[0]+1e-11, pt[1]-1e-11, pt[0]-1e-11, pt[1]+1e-11) {
				return true
			}
		}
		if docGeom.kind == geomPointR64 {
			return false
		}
		// Check edges against docGeom edges / vertices
		var docSegs [][2][2]float64
		switch docGeom.kind {
		case geomLineR64:
			for i := 0; i < len(docGeom.line)-1; i++ {
				docSegs = append(docSegs, [2][2]float64{docGeom.line[i], docGeom.line[i+1]})
			}
		case geomPolygonR64:
			for i := 0; i < len(docGeom.outer); i++ {
				docSegs = append(docSegs, [2][2]float64{docGeom.outer[i], docGeom.outer[(i+1)%len(docGeom.outer)]})
			}
		}
		for i := 0; i < len(queryGeom.line)-1; i++ {
			qa, qb := queryGeom.line[i], queryGeom.line[i+1]
			for _, ds := range docSegs {
				if segmentsIntersect2DR64(qa[1], qa[0], qb[1], qb[0], ds[0][1], ds[0][0], ds[1][1], ds[1][0]) {
					return true
				}
			}
		}
		return false
	case geomPolygonR64:
		switch docGeom.kind {
		case geomPointR64:
			return pointInPolygonR64(docGeom.pt[0], docGeom.pt[1], queryGeom.outer, queryGeom.holes)
		case geomLineR64:
			for _, pt := range docGeom.line {
				if pointInPolygonR64(pt[0], pt[1], queryGeom.outer, queryGeom.holes) {
					return true
				}
			}
			qn := len(queryGeom.outer)
			for i := 0; i < len(docGeom.line)-1; i++ {
				da, db := docGeom.line[i], docGeom.line[i+1]
				for j := 0; j < qn; j++ {
					qa, qb := queryGeom.outer[j], queryGeom.outer[(j+1)%qn]
					if segmentsIntersect2DR64(da[1], da[0], db[1], db[0], qa[1], qa[0], qb[1], qb[0]) {
						return true
					}
				}
			}
			return false
		case geomPolygonR64:
			for _, pt := range docGeom.outer {
				if pointInPolygonR64(pt[0], pt[1], queryGeom.outer, queryGeom.holes) {
					return true
				}
			}
			for _, pt := range queryGeom.outer {
				if pointInPolygonR64(pt[0], pt[1], docGeom.outer, docGeom.holes) {
					return true
				}
			}
			dn, qn := len(docGeom.outer), len(queryGeom.outer)
			for i := 0; i < dn; i++ {
				da, db := docGeom.outer[i], docGeom.outer[(i+1)%dn]
				for j := 0; j < qn; j++ {
					qa, qb := queryGeom.outer[j], queryGeom.outer[(j+1)%qn]
					if segmentsIntersect2DR64(da[1], da[0], db[1], db[0], qa[1], qa[0], qb[1], qb[0]) {
						return true
					}
				}
			}
			return false
		}
	}
	return false
}

func minDistanceMetersFromGeomR64(g parsedGeomR64, qLat, qLon float64) float64 {
	if geomIntersectsSimpleBoxR64(g, qLat+1e-9, qLon-1e-9, qLat-1e-9, qLon+1e-9) {
		return 0
	}
	minD := math.MaxFloat64
	for _, v := range g.vertices() {
		d := haversineDistanceMeters(qLat, qLon, v[0], v[1])
		if d < minD {
			minD = d
		}
	}
	// Sample midpoints along edges for tighter distance bound on edges
	checkSeq := func(seq [][2]float64, closed bool) {
		n := len(seq)
		if n < 2 {
			return
		}
		limit := n - 1
		if closed {
			limit = n
		}
		for i := 0; i < limit; i++ {
			a := seq[i]
			b := seq[(i+1)%n]
			// Closest point approximation in degree space mapped to haversine
			dx := b[1] - a[1]
			dy := b[0] - a[0]
			denom := dx*dx + dy*dy
			if denom > 0 {
				t := ((qLon-a[1])*dx + (qLat-a[0])*dy) / denom
				if t > 0 && t < 1 {
					projLat := a[0] + t*dy
					projLon := a[1] + t*dx
					d := haversineDistanceMeters(qLat, qLon, projLat, projLon)
					if d < minD {
						minD = d
					}
				}
			}
		}
	}
	switch g.kind {
	case geomLineR64:
		checkSeq(g.line, false)
	case geomPolygonR64:
		checkSeq(g.outer, true)
	case geomEnvelopeR64:
		checkSeq(g.vertices(), true)
	}
	return minD
}

// ============================================================================
// Grid Cell Enumeration (geohex_grid, geotile_grid, geohash_grid)
// ============================================================================

func decodeGeotileBoundsR64(tileStr string) (topLat, leftLon, botLat, rightLon float64, zoom, x, y int, ok bool) {
	parts := strings.Split(strings.TrimSpace(tileStr), "/")
	if len(parts) != 3 {
		return 0, 0, 0, 0, 0, 0, 0, false
	}
	z, errZ := strconv.Atoi(parts[0])
	tx, errX := strconv.Atoi(parts[1])
	ty, errY := strconv.Atoi(parts[2])
	if errZ != nil || errX != nil || errY != nil || z < 0 || z > 29 {
		return 0, 0, 0, 0, 0, 0, 0, false
	}
	maxTile := int(1 << uint(z))
	if z >= 30 || tx < 0 || ty < 0 || tx >= maxTile || ty >= maxTile {
		return 0, 0, 0, 0, 0, 0, 0, false
	}
	n := math.Pow(2.0, float64(z))
	leftLon = float64(tx)/n*360.0 - 180.0
	rightLon = float64(tx+1)/n*360.0 - 180.0
	latFromY := func(yf float64) float64 {
		return math.Atan(math.Sinh(math.Pi*(1.0-2.0*yf/n))) * 180.0 / math.Pi
	}
	topLat = latFromY(float64(ty))
	botLat = latFromY(float64(ty + 1))
	return topLat, leftLon, botLat, rightLon, z, tx, ty, true
}

func geotileCoordsForLatLonR64(lat, lon float64, zoom int) (int, int) {
	if zoom < 0 {
		zoom = 0
	}
	if zoom > 29 {
		zoom = 29
	}
	n := math.Pow(2.0, float64(zoom))
	x := int(math.Floor((lon + 180.0) / 360.0 * n))
	if x < 0 {
		x = 0
	}
	if float64(x) >= n {
		x = int(n) - 1
	}
	cLat := math.Max(-85.05112878, math.Min(85.05112878, lat))
	latRad := cLat * math.Pi / 180.0
	y := int(math.Floor((1.0 - math.Log(math.Tan(latRad)+1.0/math.Cos(latRad))/math.Pi) / 2.0 * n))
	if y < 0 {
		y = 0
	}
	if float64(y) >= n {
		y = int(n) - 1
	}
	return x, y
}

func geoBoxIntersectsBoxR64(aTop, aLeft, aBot, aRight, bTop, bLeft, bBot, bRight float64) bool {
	if aBot > bTop || aTop < bBot {
		return false
	}
	if bLeft <= bRight {
		if aLeft <= aRight {
			return !(aLeft > bRight || aRight < bLeft)
		}
		return aRight >= bLeft || aLeft <= bRight
	}
	// Dateline-wrapping bounds box [bLeft, 180] U [-180, bRight]
	if aLeft <= aRight {
		return aRight >= bLeft || aLeft <= bRight
	}
	return true
}

func clampGeoGridPrecisionR65(gridKind string, prec int) int {
	switch gridKind {
	case "geotile":
		if prec < 0 {
			return 0
		}
		if prec > 29 {
			return 29
		}
		return prec
	case "geohex":
		if prec < 0 {
			return 0
		}
		if prec > spatial.MaxRes {
			return spatial.MaxRes
		}
		return prec
	default: // geohash
		if prec < 1 {
			return 1
		}
		if prec > 12 {
			return 12
		}
		return prec
	}
}

func enumerateGeotileCellsForGeomR64(g parsedGeomR64, zoom int, hasBounds bool, bTop, bLeft, bBot, bRight float64) []string {
	zoom = clampGeoGridPrecisionR65("geotile", zoom)
	if g.kind == geomPointR64 {
		if !isFiniteCoordR64(g.pt[0]) || !isFiniteCoordR64(g.pt[1]) {
			return nil
		}
		tx, ty := geotileCoordsForLatLonR64(g.pt[0], g.pt[1], zoom)
		tile := fmt.Sprintf("%d/%d/%d", zoom, tx, ty)
		if hasBounds {
			cTop, cLeft, cBot, cRight, _, _, _, ok := decodeGeotileBoundsR64(tile)
			if !ok || !geoBoxIntersectsBoxR64(cTop, cLeft, cBot, cRight, bTop, bLeft, bBot, bRight) {
				return nil
			}
		}
		return []string{tile}
	}
	gTop, gLeft, gBot, gRight := g.bbox()
	if !isFiniteCoordR64(gTop) || !isFiniteCoordR64(gLeft) || !isFiniteCoordR64(gBot) || !isFiniteCoordR64(gRight) {
		return nil
	}
	if hasBounds {
		gTop = math.Min(gTop, bTop)
		gBot = math.Max(gBot, bBot)
		if bLeft <= bRight {
			gLeft = math.Max(gLeft, bLeft)
			gRight = math.Min(gRight, bRight)
			if gLeft > gRight || gBot > gTop {
				return nil
			}
		} else if gBot > gTop {
			return nil
		}
	}
	xMin, yMin := geotileCoordsForLatLonR64(gTop, gLeft, zoom)
	xMax, yMax := geotileCoordsForLatLonR64(gBot, gRight, zoom)
	if xMin > xMax {
		xMin, xMax = xMax, xMin
	}
	if yMin > yMax {
		yMin, yMax = yMax, yMin
	}
	nMax := (1 << uint(zoom)) - 1
	dx := int64(xMax) - int64(xMin) + 1
	dy := int64(yMax) - int64(yMin) + 1
	if dx <= 0 || dy <= 0 || dx > 4096 || dy > 4096 || dx*dy > 4096 {
		// Fallback sparse sampling along vertices for extreme zooms
		seen := make(map[string]bool)
		var out []string
		for _, v := range g.vertices() {
			if !isFiniteCoordR64(v[0]) || !isFiniteCoordR64(v[1]) {
				continue
			}
			tx, ty := geotileCoordsForLatLonR64(v[0], v[1], zoom)
			k := fmt.Sprintf("%d/%d/%d", zoom, tx, ty)
			if hasBounds {
				cTop, cLeft, cBot, cRight, _, _, _, ok := decodeGeotileBoundsR64(k)
				if !ok || !geoBoxIntersectsBoxR64(cTop, cLeft, cBot, cRight, bTop, bLeft, bBot, bRight) {
					continue
				}
			}
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
				if len(out) >= 4096 {
					break
				}
			}
		}
		return out
	}
	var out []string
	n := math.Pow(2.0, float64(zoom))
	latFromY := func(yf float64) float64 {
		return math.Atan(math.Sinh(math.Pi*(1.0-2.0*yf/n))) * 180.0 / math.Pi
	}
	for tx := xMin; tx <= xMax && tx <= nMax; tx++ {
		cLeft := float64(tx)/n*360.0 - 180.0
		cRight := float64(tx+1)/n*360.0 - 180.0
		for ty := yMin; ty <= yMax && ty <= nMax; ty++ {
			cTop := latFromY(float64(ty))
			cBot := latFromY(float64(ty + 1))
			if hasBounds && !geoBoxIntersectsBoxR64(cTop, cLeft, cBot, cRight, bTop, bLeft, bBot, bRight) {
				continue
			}
			if geomIntersectsSimpleBoxR64(g, cTop, cLeft, cBot, cRight) {
				out = append(out, fmt.Sprintf("%d/%d/%d", zoom, tx, ty))
			}
		}
	}
	return out
}

func enumerateGeohashCellsForGeomR64(g parsedGeomR64, prec int, hasBounds bool, bTop, bLeft, bBot, bRight float64) []string {
	prec = clampGeoGridPrecisionR65("geohash", prec)
	if g.kind == geomPointR64 {
		if !isFiniteCoordR64(g.pt[0]) || !isFiniteCoordR64(g.pt[1]) {
			return nil
		}
		h := encodeGeohash(g.pt[0], g.pt[1], prec)
		if h == "" {
			return nil
		}
		if hasBounds {
			cBot, cTop, cLeft, cRight, okB := decodeGeohashBBoxR61Search(h)
			if !okB || !geoBoxIntersectsBoxR64(cTop, cLeft, cBot, cRight, bTop, bLeft, bBot, bRight) {
				return nil
			}
		}
		return []string{h}
	}
	gTop, gLeft, gBot, gRight := g.bbox()
	if !isFiniteCoordR64(gTop) || !isFiniteCoordR64(gLeft) || !isFiniteCoordR64(gBot) || !isFiniteCoordR64(gRight) {
		return nil
	}
	if hasBounds {
		gTop = math.Min(gTop, bTop)
		gBot = math.Max(gBot, bBot)
		if bLeft <= bRight {
			gLeft = math.Max(gLeft, bLeft)
			gRight = math.Min(gRight, bRight)
			if gLeft > gRight || gBot > gTop {
				return nil
			}
		} else if gBot > gTop {
			return nil
		}
	}
	// Determine cell dimensions from sample cell
	_, _, _, _, okSample := decodeGeohashBBoxR61Search(encodeGeohash(0.5*(gTop+gBot), 0.5*(gLeft+gRight), prec))
	_ = okSample
	latMinC, latMaxC, lonMinC, lonMaxC, okC := decodeGeohashBBoxR61Search(encodeGeohash(gBot, gLeft, prec))
	dLat, dLon := 0.05, 0.05
	if okC {
		dLat = math.Max(1e-6, latMaxC-latMinC)
		dLon = math.Max(1e-6, lonMaxC-lonMinC)
	}
	rawStepsLat := math.Ceil((gTop-gBot)/dLat) + 2
	rawStepsLon := math.Ceil((gRight-gLeft)/dLon) + 2
	seen := make(map[string]bool)
	var out []string
	tryCell := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		cBot, cTop, cLeft, cRight, okB := decodeGeohashBBoxR61Search(h)
		if !okB {
			return
		}
		if hasBounds && !geoBoxIntersectsBoxR64(cTop, cLeft, cBot, cRight, bTop, bLeft, bBot, bRight) {
			return
		}
		if geomIntersectsSimpleBoxR64(g, cTop, cLeft, cBot, cRight) {
			out = append(out, h)
		}
	}
	if isFiniteCoordR64(rawStepsLat) && isFiniteCoordR64(rawStepsLon) &&
		rawStepsLat >= 1 && rawStepsLon >= 1 && rawStepsLat <= 4096 && rawStepsLon <= 4096 &&
		int64(rawStepsLat)*int64(rawStepsLon) <= 4096 {
		stepsLat := int(rawStepsLat)
		stepsLon := int(rawStepsLon)
		for i := 0; i <= stepsLat; i++ {
			lat := math.Min(90.0, math.Max(-90.0, gBot+float64(i)*dLat*0.75))
			for j := 0; j <= stepsLon; j++ {
				lon := math.Min(180.0, math.Max(-180.0, gLeft+float64(j)*dLon*0.75))
				tryCell(encodeGeohash(lat, lon, prec))
			}
		}
	}
	for _, v := range g.vertices() {
		if len(out) >= 4096 {
			break
		}
		if !isFiniteCoordR64(v[0]) || !isFiniteCoordR64(v[1]) {
			continue
		}
		tryCell(encodeGeohash(v[0], v[1], prec))
	}
	return out
}

func enumerateGeohexCellsForGeomR64(g parsedGeomR64, res int, hasBounds bool, bTop, bLeft, bBot, bRight float64, boundsSet map[uint64]bool) []string {
	res = clampGeoGridPrecisionR65("geohex", res)
	allowCell := func(cell uint64) bool {
		if cell == 0 {
			return false
		}
		if !hasBounds {
			return true
		}
		if boundsSet != nil {
			return boundsSet[cell]
		}
		cLat, cLon := spatial.CellToLatLon(cell)
		if geoPointInBox(cLat, cLon, bTop, bLeft, bBot, bRight) {
			return true
		}
		for _, bp := range spatial.CellToBoundary(cell) {
			if geoPointInBox(bp[0], bp[1], bTop, bLeft, bBot, bRight) {
				return true
			}
		}
		return false
	}
	switch g.kind {
	case geomPointR64:
		if !isFiniteCoordR64(g.pt[0]) || !isFiniteCoordR64(g.pt[1]) {
			return nil
		}
		cell, err := spatial.LatLonToCell(g.pt[0], g.pt[1], res)
		if err != nil {
			return nil
		}
		if !allowCell(cell) {
			if !hasBounds || boundsSet != nil || !geoPointInBox(g.pt[0], g.pt[1], bTop, bLeft, bBot, bRight) {
				return nil
			}
		}
		return []string{spatial.CellToString(cell)}
	case geomEnvelopeR64:
		if !isFiniteCoordR64(g.topLat) || !isFiniteCoordR64(g.leftLon) || !isFiniteCoordR64(g.botLat) || !isFiniteCoordR64(g.rightLon) {
			return nil
		}
		cells, err := spatial.BBoxToCells(g.topLat, g.leftLon, g.botLat, g.rightLon, res)
		if err == nil {
			out := make([]string, 0, len(cells))
			for _, cell := range cells {
				if allowCell(cell) {
					out = append(out, spatial.CellToString(cell))
				}
			}
			return out
		}
	case geomPolygonR64:
		cells, err := spatial.PolygonIntersectingCells(g.outer, g.holes, res)
		if err == nil && len(cells) > 0 {
			out := make([]string, 0, len(cells))
			for _, cell := range cells {
				if allowCell(cell) {
					out = append(out, spatial.CellToString(cell))
				}
			}
			return out
		}
	}
	// Fallback / LineString: sample along segments + vertices
	seen := make(map[string]bool)
	var out []string
	addPt := func(lat, lon float64) {
		if !isFiniteCoordR64(lat) || !isFiniteCoordR64(lon) || len(out) >= 4096 {
			return
		}
		cell, err := spatial.LatLonToCell(lat, lon, res)
		if err == nil && allowCell(cell) {
			s := spatial.CellToString(cell)
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	vs := g.vertices()
	for _, v := range vs {
		addPt(v[0], v[1])
	}
	if g.kind == geomLineR64 {
		for i := 0; i < len(g.line)-1; i++ {
			a, b := g.line[i], g.line[i+1]
			if !isFiniteCoordR64(a[0]) || !isFiniteCoordR64(a[1]) || !isFiniteCoordR64(b[0]) || !isFiniteCoordR64(b[1]) {
				continue
			}
			distKm := haversineDistanceMeters(a[0], a[1], b[0], b[1]) / 1000.0
			steps := int(math.Ceil(distKm / 5.0))
			if steps < 4 {
				steps = 4
			}
			if steps > 256 {
				steps = 256
			}
			for s := 1; s < steps; s++ {
				t := float64(s) / float64(steps)
				addPt(a[0]*(1-t)+b[0]*t, a[1]*(1-t)+b[1]*t)
			}
		}
	}
	return out
}

func extractGeoGridCellKeysForDocR64(
	md runtimeMatchedDoc,
	field string,
	gridKind string, // "geohash", "geotile", "geohex"
	prec int,
	bounds map[string]any,
	boundsHexSet map[uint64]bool,
	idxSchema *schema.IndexSchema,
) []string {
	var bTopLat, bLeftLon, bBotLat, bRightLon float64
	hasBounds := false
	if bounds != nil {
		bTopLat, bLeftLon, bBotLat, bRightLon, hasBounds = extractGeoBoundingBoxMapCoords(bounds)
		if hasBounds && (!isFiniteCoordR64(bTopLat) || !isFiniteCoordR64(bLeftLon) || !isFiniteCoordR64(bBotLat) || !isFiniteCoordR64(bRightLon)) {
			hasBounds = false
		}
	}
	effSchema := md.EffectiveSchema(idxSchema)
	shapes, _ := parseDocShapesR64(md.doc, field, effSchema, true)
	if len(shapes) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(shapes))
	var out []string
	for _, sh := range shapes {
		var cells []string
		switch gridKind {
		case "geohex":
			cells = enumerateGeohexCellsForGeomR64(sh, prec, hasBounds, bTopLat, bLeftLon, bBotLat, bRightLon, boundsHexSet)
		case "geotile":
			cells = enumerateGeotileCellsForGeomR64(sh, prec, hasBounds, bTopLat, bLeftLon, bBotLat, bRightLon)
		default:
			cells = enumerateGeohashCellsForGeomR64(sh, prec, hasBounds, bTopLat, bLeftLon, bBotLat, bRightLon)
		}
		for _, c := range cells {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// ============================================================================
// Aggregations: geo_line, cartesian_bounds, cartesian_centroid, geohex_grid,
// enhanced geo_bounds, geo_centroid, geohash_grid, geotile_grid, time_series
// ============================================================================

func emitRuntimeGeoGridAggRowsR64(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	gridKind := "geohash"
	spec := aggSpec.GeohashGrid
	prec := 5
	switch {
	case aggSpec.GeotileGrid != nil:
		gridKind = "geotile"
		spec = aggSpec.GeotileGrid
		prec = 7
	case aggSpec.GeoHexGrid != nil:
		gridKind = "geohex"
		spec = aggSpec.GeoHexGrid
		prec = 5
	}
	if spec == nil {
		return
	}
	if spec.Precision != nil {
		prec = *spec.Precision
	}
	prec = clampGeoGridPrecisionR65(gridKind, prec)
	maxSize := 10000
	if spec.Size > 0 {
		maxSize = spec.Size
	}
	const maxGeoGridBucketsCapR65 = 100000
	if maxSize > maxGeoGridBucketsCapR65 {
		maxSize = maxGeoGridBucketsCapR65
	}
	maxTrackedBuckets := maxSize * 4
	if maxTrackedBuckets < 65536 {
		maxTrackedBuckets = 65536
	}
	if maxTrackedBuckets > maxGeoGridBucketsCapR65 {
		maxTrackedBuckets = maxGeoGridBucketsCapR65
	}
	var bTopLat, bLeftLon, bBotLat, bRightLon float64
	hasBounds := false
	var boundsHexSet map[uint64]bool
	if spec.Bounds != nil {
		bTopLat, bLeftLon, bBotLat, bRightLon, hasBounds = extractGeoBoundingBoxMapCoords(spec.Bounds)
		if hasBounds && (!isFiniteCoordR64(bTopLat) || !isFiniteCoordR64(bLeftLon) || !isFiniteCoordR64(bBotLat) || !isFiniteCoordR64(bRightLon)) {
			hasBounds = false
		}
		if hasBounds && gridKind == "geohex" {
			if cells, err := spatial.BBoxToCells(bTopLat, bLeftLon, bBotLat, bRightLon, prec); err == nil && len(cells) > 0 {
				boundsHexSet = make(map[uint64]bool, len(cells))
				for _, c := range cells {
					boundsHexSet[c] = true
				}
			}
		}
	}
	byBucket := make(map[string][]runtimeMatchedDoc)
	var keys []string
	for _, md := range docs {
		cells := extractGeoGridCellKeysForDocR64(md, spec.Field, gridKind, prec, spec.Bounds, boundsHexSet, idxSchema)
		for _, cell := range cells {
			if _, exists := byBucket[cell]; !exists {
				if len(byBucket) >= maxTrackedBuckets {
					continue
				}
				keys = append(keys, cell)
			}
			byBucket[cell] = append(byBucket[cell], md)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		ci, cj := len(byBucket[keys[i]]), len(byBucket[keys[j]])
		if ci != cj {
			return ci > cj
		}
		if gridKind == "geotile" {
			return compareGeotileStringsR62Search(keys[i], keys[j]) > 0
		}
		return keys[i] > keys[j]
	})
	if len(keys) > maxSize {
		keys = keys[:maxSize]
	}
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeGeoBoundsAggRowsR64(fullAggName, metricBucketKey string, spec *esast.GeoBoundsAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var minLat, maxLat, minLon, maxLon float64
	var posMinLon, posMaxLon float64 = 180, -180
	var negMinLon, negMaxLon float64 = 180, -180
	hasPos, hasNeg := false, false
	hasAny := false
	crossesDateline := false
	var count int64

	for _, md := range bDocs {
		shapes, _ := parseDocShapesR64(md.doc, spec.Field, md.EffectiveSchema(nil), true)
		for _, sh := range shapes {
			if sh.crossesDateline {
				crossesDateline = true
			}
			for _, pt := range sh.vertices() {
				lat, lon := pt[0], pt[1]
				if !hasAny {
					minLat, maxLat = lat, lat
					minLon, maxLon = lon, lon
					hasAny = true
				} else {
					if lat < minLat {
						minLat = lat
					}
					if lat > maxLat {
						maxLat = lat
					}
					if lon < minLon {
						minLon = lon
					}
					if lon > maxLon {
						maxLon = lon
					}
				}
				if lon >= 0 {
					hasPos = true
					if lon < posMinLon {
						posMinLon = lon
					}
					if lon > posMaxLon {
						posMaxLon = lon
					}
				} else {
					hasNeg = true
					if lon < negMinLon {
						negMinLon = lon
					}
					if lon > negMaxLon {
						negMaxLon = lon
					}
				}
				count++
			}
		}
	}
	if !hasAny {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{}, 0, out)
		return
	}
	wrap := true
	if spec.WrapLongitude != nil {
		wrap = *spec.WrapLongitude
	}
	leftLon, rightLon := minLon, maxLon
	if wrap && hasPos && hasNeg {
		unwrappedSpan := maxLon - minLon
		wrappedSpan := (180.0 - posMinLon) + (negMaxLon + 180.0)
		if crossesDateline || wrappedSpan < unwrappedSpan {
			leftLon = posMinLon
			rightLon = negMaxLon
		}
	} else if !wrap && crossesDateline {
		leftLon = -180.0
		rightLon = 180.0
	}
	obj := map[string]any{
		"bounds": map[string]any{
			"top_left": map[string]any{
				"lat": maxLat,
				"lon": leftLon,
			},
			"bottom_right": map[string]any{
				"lat": minLat,
				"lon": rightLon,
			},
		},
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(count), out)
}

func emitRuntimeGeoCentroidAggRowsR64(fullAggName, metricBucketKey string, spec *esast.MetricAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var acc centroidAccumR64
	for _, md := range bDocs {
		shapes, esType := parseDocShapesR64(md.doc, spec.Field, md.EffectiveSchema(nil), true)
		if len(shapes) == 0 {
			continue
		}
		if esType == "" || esType == "geo_point" || esType == "point" {
			allPts := true
			for _, sh := range shapes {
				if sh.kind != geomPointR64 {
					allPts = false
					break
				}
			}
			if allPts {
				for _, sh := range shapes {
					acc.addGeom(sh)
					acc.docCount++
				}
				continue
			}
		}
		// Keep doc's max dimensional geometries for geo_shape
		docMaxDim := 0
		for _, sh := range shapes {
			if d := sh.dim(); d > docMaxDim {
				docMaxDim = d
			}
		}
		for _, sh := range shapes {
			if sh.dim() == docMaxDim {
				acc.addGeom(sh)
			}
		}
		acc.docCount++
	}
	if acc.docCount == 0 || acc.sumW == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"count": int64(0)}, 0, out)
		return
	}
	obj := map[string]any{
		"location": map[string]any{
			"lat": acc.sumWY / acc.sumW,
			"lon": acc.sumWX / acc.sumW,
		},
		"count": acc.docCount,
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(acc.docCount), out)
}

func emitRuntimeCartesianBoundsAggRowsR64(fullAggName, metricBucketKey string, spec *esast.CartesianBoundsAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var minX, maxX, minY, maxY float64
	hasAny := false
	var cnt int64
	for _, md := range bDocs {
		shapes, _ := parseDocShapesR64(md.doc, spec.Field, md.EffectiveSchema(nil), false)
		for _, sh := range shapes {
			for _, pt := range sh.vertices() {
				y, x := pt[0], pt[1]
				if !hasAny {
					minX, maxX = x, x
					minY, maxY = y, y
					hasAny = true
				} else {
					if x < minX {
						minX = x
					}
					if x > maxX {
						maxX = x
					}
					if y < minY {
						minY = y
					}
					if y > maxY {
						maxY = y
					}
				}
				cnt++
			}
		}
	}
	if !hasAny {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{}, 0, out)
		return
	}
	obj := map[string]any{
		"bounds": map[string]any{
			"top_left":     map[string]any{"x": minX, "y": maxY},
			"bottom_right": map[string]any{"x": maxX, "y": minY},
		},
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(cnt), out)
}

func emitRuntimeCartesianCentroidAggRowsR64(fullAggName, metricBucketKey string, spec *esast.CartesianCentroidAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var acc centroidAccumR64
	for _, md := range bDocs {
		shapes, _ := parseDocShapesR64(md.doc, spec.Field, md.EffectiveSchema(nil), false)
		if len(shapes) == 0 {
			continue
		}
		var docAcc centroidAccumR64
		for _, sh := range shapes {
			docAcc.addGeom(sh)
		}
		if docAcc.sumW == 0 {
			continue
		}
		// Lucene XYDocValues stores one float32-quantized centroid per document,
		// accumulated at the document's max geometry dimension and weighted into the bucket.
		docCX := float64(float32(docAcc.sumWX / docAcc.sumW))
		docCY := float64(float32(docAcc.sumWY / docAcc.sumW))
		if docAcc.maxDim > acc.maxDim {
			acc.maxDim = docAcc.maxDim
			acc.sumW = 0
			acc.sumWX = 0
			acc.sumWY = 0
		}
		if docAcc.maxDim == acc.maxDim {
			acc.sumW += docAcc.sumW
			acc.sumWX += docCX * docAcc.sumW
			acc.sumWY += docCY * docAcc.sumW
		}
		acc.docCount++
	}
	if acc.docCount == 0 || acc.sumW == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"count": int64(0)}, 0, out)
		return
	}
	obj := map[string]any{
		"location": map[string]any{
			"x": acc.sumWX / acc.sumW,
			"y": acc.sumWY / acc.sumW,
		},
		"count": acc.docCount,
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(acc.docCount), out)
}

func round6DecimalsR64(v float64) float64 {
	return math.Round(v*1e6) / 1e6
}

func extractGeoLineSortValueR64(md runtimeMatchedDoc, sortField string, idxSchema *schema.IndexSchema) (float64, any, bool) {
	effSchema := md.EffectiveSchema(idxSchema)
	if sortField == "" {
		return 0, float64(0), true
	}
	raw, ok := extractDocFieldRawValueR64(md.doc, sortField, effSchema)
	if !ok || raw == nil {
		return 0, nil, false
	}
	if arr, isArr := raw.([]any); isArr && len(arr) > 0 {
		raw = arr[0]
	}
	isDate := sortField == "@timestamp"
	if effSchema != nil {
		b := effSchema.ResolveField(sortField)
		if b.ESType == "date" || b.ESType == "date_nanos" {
			isDate = true
		}
	}
	if isDate {
		if ms, okD := parseDateValueToEpochMillisR64(raw); okD {
			return float64(ms), ms, true
		}
	}
	if fv, okF := toFloat64(raw); okF && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		return fv, fv, true
	}
	if ms, okD := parseDateValueToEpochMillisR64(raw); okD {
		return float64(ms), ms, true
	}
	return 0, nil, false
}

func parseDateValueToEpochMillisR64(v any) (int64, bool) {
	switch tv := v.(type) {
	case int64:
		return tv, true
	case int:
		return int64(tv), true
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv, true
		}
		if fv, err := tv.Float64(); err == nil {
			return int64(fv), true
		}
	case float64:
		return int64(tv), true
	case string:
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(tv, "", time.Now().UTC()); ok {
			return ms, true
		}
	}
	return 0, false
}

func emptyGeoLineFeatureObjectR64(includeSort bool) map[string]any {
	props := map[string]any{"complete": true}
	if includeSort {
		props["sort_values"] = []any{}
	}
	return map[string]any{
		"type": "Feature",
		"geometry": map[string]any{
			"type":        "LineString",
			"coordinates": []any{},
		},
		"properties": props,
	}
}

func emitRuntimeGeoLineAggRowsR64(fullAggName, metricBucketKey string, spec *esast.GeoLineAggSpec, bDocs []runtimeMatchedDoc, idxSchema *schema.IndexSchema, out *[]AggRow) {
	if spec == nil {
		return
	}
	includeSort := spec.IncludeSort != nil && *spec.IncludeSort
	sortField := ""
	if spec.Sort != nil {
		sortField = strings.TrimSpace(spec.Sort.Field)
	}
	var sc *schema.IndexSchema
	if len(bDocs) > 0 {
		sc = bDocs[0].EffectiveSchema(idxSchema)
	} else {
		sc = idxSchema
	}
	if sortField == "" && sc != nil && sc.IndexMode == "time_series" {
		sortField = "@timestamp"
	}

	type geoLineItem struct {
		lat     float64
		lon     float64
		sortNum float64
		sortRaw any
		seq     int
		docID   string
	}
	var items []geoLineItem
	seq := 0
	for _, md := range bDocs {
		pts := extractDocGeoPoints(md, spec.Point.Field)
		if len(pts) == 0 {
			continue
		}
		var sortNum float64
		var sortRaw any
		if sortField != "" {
			sn, sr, okS := extractGeoLineSortValueR64(md, sortField, idxSchema)
			if !okS {
				continue
			}
			sortNum = sn
			sortRaw = sr
		}
		for _, pt := range pts {
			items = append(items, geoLineItem{
				lat:     pt[0],
				lon:     pt[1],
				sortNum: sortNum,
				sortRaw: sortRaw,
				seq:     seq,
				docID:   md.hit.ID,
			})
			seq++
		}
	}
	if len(items) == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, emptyGeoLineFeatureObjectR64(includeSort), 0, out)
		return
	}
	desc := strings.EqualFold(strings.TrimSpace(spec.SortOrder), "desc")
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].sortNum != items[j].sortNum {
			if desc {
				return items[i].sortNum > items[j].sortNum
			}
			return items[i].sortNum < items[j].sortNum
		}
		if items[i].docID != items[j].docID {
			return items[i].docID < items[j].docID
		}
		return items[i].seq < items[j].seq
	})
	limit := 10000
	if spec.Size != nil && *spec.Size > 0 {
		limit = *spec.Size
	}
	complete := len(items) <= limit
	if !complete {
		items = items[:limit]
	}
	coords := make([]any, len(items))
	var sortVals []any
	if includeSort {
		sortVals = make([]any, len(items))
	}
	for i, it := range items {
		coords[i] = []any{round6DecimalsR64(it.lon), round6DecimalsR64(it.lat)}
		if includeSort {
			sortVals[i] = it.sortRaw
		}
	}
	props := map[string]any{"complete": complete}
	if includeSort {
		props["sort_values"] = sortVals
	}
	geom := map[string]any{
		"type":        "LineString",
		"coordinates": coords,
	}
	if len(items) == 1 {
		geom = map[string]any{
			"type":        "Point",
			"coordinates": coords[0],
		}
	}
	obj := map[string]any{
		"type":       "Feature",
		"geometry":   geom,
		"properties": props,
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(len(items)), out)
}

func formatTimeSeriesJavaKeyR64(keyMap map[string]any) string {
	if len(keyMap) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(keyMap))
	for k := range keyMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		fmt.Fprintf(&sb, "%v", keyMap[k])
	}
	sb.WriteByte('}')
	return sb.String()
}

func extractTimeSeriesDimsForDocR64(md runtimeMatchedDoc, idxSchema *schema.IndexSchema) (string, map[string]any) {
	eff := md.EffectiveSchema(idxSchema)
	dimMap := make(map[string]any)
	if eff != nil {
		for k, b := range eff.Fields {
			if b.TimeSeriesDimension != nil && *b.TimeSeriesDimension && !strings.HasSuffix(k, ".keyword") {
				if v, ok := extractDocFieldRawValueR64(md.doc, k, eff); ok && v != nil {
					dimMap[k] = v
				}
			}
		}
	}
	canon := canonicalTSKeyStringR62Search(dimMap)
	rawJSON, _ := json.Marshal(dimMap)
	tsid := ""
	if eff != nil {
		if rawTS, ok := md.doc["__tsid"].(string); ok && rawTS != "" {
			tsid = rawTS
		}
	}
	if tsid == "" {
		tsid = canon
	}
	return tsid + "|" + string(rawJSON), dimMap
}

func emitRuntimeTimeSeriesAggRowsR64(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	if aggSpec.TimeSeries == nil {
		return
	}
	byKey := make(map[string][]runtimeMatchedDoc)
	var order []string
	for _, md := range docs {
		bucketChild, _ := extractTimeSeriesDimsForDocR64(md, idxSchema)
		if _, exists := byKey[bucketChild]; !exists {
			order = append(order, bucketChild)
		}
		byKey[bucketChild] = append(byKey[bucketChild], md)
	}
	subAggs := aggSpec.SubAggs()
	for _, ck := range order {
		bDocs := byKey[ck]
		rowKey := ck
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + ck
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func validateSpatialAndTimeSeriesAggTreeR64(aggs map[string]esast.AggSpec, underTimeSeries bool) (int, string, string) {
	for _, spec := range aggs {
		if spec.GeoHexGrid != nil && spec.GeoHexGrid.Precision != nil {
			p := *spec.GeoHexGrid.Precision
			if p < 0 || p > spatial.MaxRes {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Precision [%d] must be between 0 and %d", p, spatial.MaxRes)
			}
		}
		if spec.GeotileGrid != nil && spec.GeotileGrid.Precision != nil {
			p := *spec.GeotileGrid.Precision
			if p < 0 || p > 29 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Precision [%d] must be between 0 and 29", p)
			}
		}
		if spec.GeohashGrid != nil && spec.GeohashGrid.Precision != nil {
			p := *spec.GeohashGrid.Precision
			if p < 1 || p > 12 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Precision [%d] must be between 1 and 12", p)
			}
		}
		if spec.GeoLine != nil && underTimeSeries {
			if spec.GeoLine.Sort != nil && spec.GeoLine.Sort.Field != "" && spec.GeoLine.Sort.Field != "@timestamp" {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("invalid field [sort]='%s' configured for time-series aggregations", spec.GeoLine.Sort.Field)
			}
		}
		nextTS := underTimeSeries || spec.TimeSeries != nil
		if sub := spec.SubAggs(); len(sub) > 0 {
			if st, et, er := validateSpatialAndTimeSeriesAggTreeR64(sub, nextTS); st != 0 {
				return st, et, er
			}
		}
	}
	return 0, "", ""
}

// ============================================================================
// F13: Spatial Queries (`geo_grid`, `geo_shape`, `geo_bounding_box`, `geo_distance`, `geo_polygon`)
// ============================================================================

func evalDocGeoGridQueryR64(idxSchema *schema.IndexSchema, doc map[string]any, gg *esast.GeoGridQuery) bool {
	if gg == nil || gg.Field == "" {
		return false
	}
	shapes, _ := parseDocShapesR64(doc, gg.Field, idxSchema, true)
	if len(shapes) == 0 {
		return false
	}
	switch gg.GridType() {
	case "geohash":
		bBot, bTop, bLeft, bRight, ok := decodeGeohashBBoxR61Search(gg.Geohash)
		if !ok {
			return false
		}
		for _, sh := range shapes {
			if geomIntersectsBoxR64(sh, bTop, bLeft, bBot, bRight) {
				return true
			}
		}
	case "geotile":
		bTop, bLeft, bBot, bRight, _, _, _, ok := decodeGeotileBoundsR64(gg.Geotile)
		if !ok {
			return false
		}
		for _, sh := range shapes {
			if geomIntersectsBoxR64(sh, bTop, bLeft, bBot, bRight) {
				return true
			}
		}
	case "geohex":
		targetCell, err := spatial.StringToCell(gg.Geohex)
		if err != nil || !spatial.IsValidCell(targetCell) {
			return false
		}
		res := spatial.Resolution(targetCell)
		boundary := spatial.CellToBoundary(targetCell)
		hexPoly := parsedGeomR64{kind: geomPolygonR64, outer: boundary}
		for _, sh := range shapes {
			if sh.kind == geomPointR64 {
				c, errC := spatial.LatLonToCell(sh.pt[0], sh.pt[1], res)
				if errC == nil && c == targetCell {
					return true
				}
			} else if geomIntersectsQueryShapeR64(sh, hexPoly) {
				return true
			}
		}
	}
	return false
}

func evalDocGeoBoundingBoxQueryR64(idxSchema *schema.IndexSchema, doc map[string]any, gb *esast.GeoBoundingBoxQuery) bool {
	if gb == nil || gb.Field == "" {
		return false
	}
	shapes, _ := parseDocShapesR64(doc, gb.Field, idxSchema, true)
	if len(shapes) == 0 {
		return false
	}
	for _, sh := range shapes {
		if geomIntersectsBoxR64(sh, gb.Top, gb.Left, gb.Bottom, gb.Right) {
			return true
		}
	}
	return false
}

func evalDocGeoDistanceQueryR64(idxSchema *schema.IndexSchema, doc map[string]any, gd *esast.GeoDistanceQuery) bool {
	if gd == nil || gd.Field == "" {
		return false
	}
	shapes, _ := parseDocShapesR64(doc, gd.Field, idxSchema, true)
	if len(shapes) == 0 {
		return false
	}
	for _, sh := range shapes {
		if minDistanceMetersFromGeomR64(sh, gd.Lat, gd.Lon) <= gd.DistanceMeters {
			return true
		}
	}
	return false
}

func evalDocGeoPolygonQueryR64(idxSchema *schema.IndexSchema, doc map[string]any, gp *esast.GeoPolygonQuery) bool {
	if gp == nil || gp.Field == "" || len(gp.Points) < 3 {
		return false
	}
	shapes, _ := parseDocShapesR64(doc, gp.Field, idxSchema, true)
	if len(shapes) == 0 {
		return false
	}
	ring := make([][2]float64, 0, len(gp.Points))
	for _, pt := range gp.Points {
		if isFiniteCoordR64(pt[0]) && isFiniteCoordR64(pt[1]) {
			ring = append(ring, [2]float64{pt[0], pt[1]})
		}
	}
	if len(ring) < 3 {
		return false
	}
	cd := checkSeqDatelineR64(ring, false)
	poly := parsedGeomR64{kind: geomPolygonR64, outer: ring, crossesDateline: cd}
	for _, sh := range shapes {
		if geomIntersectsQueryShapeR64(sh, poly) {
			return true
		}
	}
	return false
}

func evalDocGeoShapeQueryR64(idxSchema *schema.IndexSchema, doc map[string]any, gs *esast.GeoShapeQuery) bool {
	if gs == nil || gs.Field == "" {
		return false
	}
	shapes, _ := parseDocShapesR64(doc, gs.Field, idxSchema, true)
	if len(shapes) == 0 {
		return false
	}
	if gs.Shape == nil {
		return len(shapes) > 0
	}
	qShapes, okQ := parseRawShapesR64(gs.Shape, true)
	if !okQ || len(qShapes) == 0 {
		return false
	}
	rel := strings.ToUpper(strings.TrimSpace(gs.Relation))
	if rel == "" {
		rel = "INTERSECTS"
	}
	switch rel {
	case "DISJOINT":
		for _, ds := range shapes {
			for _, qs := range qShapes {
				if geomIntersectsQueryShapeR64(ds, qs) {
					return false
				}
			}
		}
		return true
	case "WITHIN":
		for _, ds := range shapes {
			withinAny := false
			for _, qs := range qShapes {
				if qs.kind == geomEnvelopeR64 && geomBoxContainsGeomR64(ds, qs.topLat, qs.leftLon, qs.botLat, qs.rightLon) {
					withinAny = true
					break
				}
				if qs.kind == geomPolygonR64 {
					allIn := true
					for _, v := range ds.vertices() {
						if !pointInPolygonR64(v[0], v[1], qs.outer, qs.holes) {
							allIn = false
							break
						}
					}
					if allIn {
						withinAny = true
						break
					}
				}
			}
			if !withinAny {
				return false
			}
		}
		return true
	case "CONTAINS":
		for _, qs := range qShapes {
			contained := false
			for _, ds := range shapes {
				if ds.kind == geomEnvelopeR64 && geomBoxContainsGeomR64(qs, ds.topLat, ds.leftLon, ds.botLat, ds.rightLon) {
					contained = true
					break
				}
				if ds.kind == geomPolygonR64 {
					allIn := true
					for _, v := range qs.vertices() {
						if !pointInPolygonR64(v[0], v[1], ds.outer, ds.holes) {
							allIn = false
							break
						}
					}
					if allIn {
						contained = true
						break
					}
				}
			}
			if !contained {
				return false
			}
		}
		return true
	default: // INTERSECTS
		for _, ds := range shapes {
			for _, qs := range qShapes {
				if geomIntersectsQueryShapeR64(ds, qs) {
					return true
				}
			}
		}
		return false
	}
}

func queryHasSpatialLeafR64(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.GeoGrid != nil || q.GeoShape != nil || q.GeoBoundingBox != nil || q.GeoDistance != nil || q.GeoPolygon != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasSpatialLeafR64(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryHasSpatialLeafR64(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryHasSpatialLeafR64(&q.Bool.MustNot[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasSpatialLeafR64(&q.Bool.Should[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryHasSpatialLeafR64(&q.ConstantScore.Filter) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryHasSpatialLeafR64(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if queryHasSpatialLeafR64(&q.Boosting.Positive) || queryHasSpatialLeafR64(&q.Boosting.Negative) {
			return true
		}
	}
	if q.Nested != nil && queryHasSpatialLeafR64(&q.Nested.Query) {
		return true
	}
	if q.ScriptScore != nil && queryHasSpatialLeafR64(q.ScriptScore.Query) {
		return true
	}
	if q.FunctionScore != nil && queryHasSpatialLeafR64(q.FunctionScore.Query) {
		return true
	}
	if q.Wrapper != nil && queryHasSpatialLeafR64(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && queryHasSpatialLeafR64(q.Pinned.Organic) {
		return true
	}
	return false
}

func queryNeedsRuntimeSpatialEvalR64(q *esast.Query, idxSchema *schema.IndexSchema) bool {
	if q == nil {
		return false
	}
	if q.GeoGrid != nil {
		return true
	}
	isShapeOrRTField := func(field string) bool {
		if field == "" || idxSchema == nil {
			return false
		}
		b := idxSchema.ResolveField(field)
		ft := strings.ToLower(strings.TrimSpace(b.ESType))
		return ft == "geo_shape" || ft == "shape" || ft == "point" || b.FromRuntime
	}
	if q.GeoBoundingBox != nil && isShapeOrRTField(q.GeoBoundingBox.Field) {
		return true
	}
	if q.GeoDistance != nil && isShapeOrRTField(q.GeoDistance.Field) {
		return true
	}
	if q.GeoPolygon != nil && isShapeOrRTField(q.GeoPolygon.Field) {
		return true
	}
	if q.GeoShape != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryNeedsRuntimeSpatialEvalR64(&q.Bool.Must[i], idxSchema) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryNeedsRuntimeSpatialEvalR64(&q.Bool.Filter[i], idxSchema) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryNeedsRuntimeSpatialEvalR64(&q.Bool.MustNot[i], idxSchema) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryNeedsRuntimeSpatialEvalR64(&q.Bool.Should[i], idxSchema) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryNeedsRuntimeSpatialEvalR64(&q.ConstantScore.Filter, idxSchema) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryNeedsRuntimeSpatialEvalR64(&q.DisMax.Queries[i], idxSchema) {
				return true
			}
		}
	}
	if q.Boosting != nil && (queryNeedsRuntimeSpatialEvalR64(&q.Boosting.Positive, idxSchema) || queryNeedsRuntimeSpatialEvalR64(&q.Boosting.Negative, idxSchema)) {
		return true
	}
	if q.Nested != nil && queryNeedsRuntimeSpatialEvalR64(&q.Nested.Query, idxSchema) {
		return true
	}
	if q.ScriptScore != nil && queryNeedsRuntimeSpatialEvalR64(q.ScriptScore.Query, idxSchema) {
		return true
	}
	if q.FunctionScore != nil && queryNeedsRuntimeSpatialEvalR64(q.FunctionScore.Query, idxSchema) {
		return true
	}
	if q.Wrapper != nil && queryNeedsRuntimeSpatialEvalR64(q.Wrapper.Decoded, idxSchema) {
		return true
	}
	if q.Pinned != nil && queryNeedsRuntimeSpatialEvalR64(q.Pinned.Organic, idxSchema) {
		return true
	}
	return false
}

func evalDocWithSpatialFallbackR64(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query) bool {
	if q == nil {
		return true
	}
	if q.GeoGrid != nil {
		return evalDocGeoGridQueryR64(idxSchema, doc, q.GeoGrid)
	}
	if q.GeoBoundingBox != nil {
		return evalDocGeoBoundingBoxQueryR64(idxSchema, doc, q.GeoBoundingBox)
	}
	if q.GeoDistance != nil {
		return evalDocGeoDistanceQueryR64(idxSchema, doc, q.GeoDistance)
	}
	if q.GeoPolygon != nil {
		return evalDocGeoPolygonQueryR64(idxSchema, doc, q.GeoPolygon)
	}
	if q.GeoShape != nil {
		return evalDocGeoShapeQueryR64(idxSchema, doc, q.GeoShape)
	}
	if q.Exists != nil && idxSchema != nil && strings.TrimSpace(q.Exists.Field) != "" {
		b := idxSchema.ResolveField(q.Exists.Field)
		if b.FromRuntime || b.ESType == "geo_shape" || b.ESType == "shape" {
			rv, ok := extractDocFieldRawValueR64(doc, q.Exists.Field, idxSchema)
			if !ok || rv == nil {
				return false
			}
			if sl, isSl := rv.([]any); isSl {
				return len(sl) > 0
			}
			return true
		}
	}
	if q.Bool != nil && queryHasSpatialLeafR64(q) {
		for i := range q.Bool.Must {
			if !evalDocWithSpatialFallbackR64(idxSchema, doc, &q.Bool.Must[i]) {
				return false
			}
		}
		for i := range q.Bool.Filter {
			if !evalDocWithSpatialFallbackR64(idxSchema, doc, &q.Bool.Filter[i]) {
				return false
			}
		}
		for i := range q.Bool.MustNot {
			if evalDocWithSpatialFallbackR64(idxSchema, doc, &q.Bool.MustNot[i]) {
				return false
			}
		}
		if len(q.Bool.Should) > 0 {
			reqMin := resolveMinimumShouldMatch(q.Bool.MinimumShouldMatch, len(q.Bool.Should), len(q.Bool.Must) == 0 && len(q.Bool.Filter) == 0)
			if reqMin > 0 {
				matched := 0
				for i := range q.Bool.Should {
					if evalDocWithSpatialFallbackR64(idxSchema, doc, &q.Bool.Should[i]) {
						matched++
					}
				}
				if matched < reqMin {
					return false
				}
			}
		}
		return true
	}
	if q.ConstantScore != nil && queryHasSpatialLeafR64(&q.ConstantScore.Filter) {
		return evalDocWithSpatialFallbackR64(idxSchema, doc, &q.ConstantScore.Filter)
	}
	if q.DisMax != nil && queryHasSpatialLeafR64(q) {
		for i := range q.DisMax.Queries {
			if evalDocWithSpatialFallbackR64(idxSchema, doc, &q.DisMax.Queries[i]) {
				return true
			}
		}
		return false
	}
	if q.Boosting != nil && queryHasSpatialLeafR64(&q.Boosting.Positive) {
		return evalDocWithSpatialFallbackR64(idxSchema, doc, &q.Boosting.Positive)
	}
	if q.Nested != nil && queryHasSpatialLeafR64(&q.Nested.Query) {
		pathSegs := strings.Split(q.Nested.Path, ".")
		nestedSchema := deriveNestedEvalSchema(idxSchema, q.Nested.Path)
		for _, cand := range extractNestedElementsAtPath(doc, pathSegs) {
			elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
			if evalDocWithSpatialFallbackR64(nestedSchema, elemDoc, &q.Nested.Query) {
				return true
			}
		}
		return false
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil && queryHasSpatialLeafR64(q.ScriptScore.Query) {
		return evalDocWithSpatialFallbackR64(idxSchema, doc, q.ScriptScore.Query)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil && queryHasSpatialLeafR64(q.FunctionScore.Query) {
		return evalDocWithSpatialFallbackR64(idxSchema, doc, q.FunctionScore.Query)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryHasSpatialLeafR64(q.Wrapper.Decoded) {
		return evalDocWithSpatialFallbackR64(idxSchema, doc, q.Wrapper.Decoded)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil && queryHasSpatialLeafR64(q.Pinned.Organic) {
		if _, ok := pinnedRankForDoc(idxSchema, doc, q.Pinned); ok {
			return true
		}
		return evalDocWithSpatialFallbackR64(idxSchema, doc, q.Pinned.Organic)
	}
	return docMatchesNonScriptClauseNoSpatialR64(idxSchema, doc, q)
}

func validateGeoGridQueryFieldsR64(idxSchema *schema.IndexSchema, q *esast.Query) (int, string, string) {
	if q == nil {
		return 0, "", ""
	}
	if q.GeoGrid != nil {
		gg := q.GeoGrid
		if strings.TrimSpace(gg.Field) == "" {
			return http.StatusBadRequest, "parsing_exception", "[geo_grid] failed to parse query: field is missing"
		}
		if strings.TrimSpace(gg.GridType()) == "" {
			return http.StatusBadRequest, "parsing_exception", "[geo_grid] query requires one of [geohash], [geotile], or [geohex]"
		}
		if idxSchema != nil {
			b := idxSchema.ResolveField(gg.Field)
			if b.NotIndexed && b.DocValuesFalse {
				return http.StatusBadRequest, "query_shard_exception", fmt.Sprintf("failed to create query: Cannot search on field [%s] since it is not indexed nor has doc values.", gg.Field)
			}
			if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" && b.ESType != "point" && b.ESType != "shape" {
				return http.StatusBadRequest, "query_shard_exception", fmt.Sprintf("failed to find geo_point or geo_shape field [%s]", gg.Field)
			}
		}
	}
	if q.GeoShape != nil && idxSchema != nil && strings.TrimSpace(q.GeoShape.Field) != "" {
		gs := q.GeoShape
		b := idxSchema.ResolveField(gs.Field)
		if b.NotIndexed && b.DocValuesFalse {
			return http.StatusBadRequest, "query_shard_exception", fmt.Sprintf("failed to create query: Cannot search on field [%s] since it is not indexed nor has doc values.", gs.Field)
		}
		if b.NotIndexed && b.ESType != "geo_shape" && b.ESType != "geo_point" {
			return http.StatusBadRequest, "query_shard_exception", fmt.Sprintf("cannot search on field [%s] since it is not indexed", gs.Field)
		}
		if b.ESType != "" && b.ESType != "geo_shape" && b.ESType != "geo_point" && b.ESType != "point" && b.ESType != "shape" {
			return http.StatusBadRequest, "query_shard_exception", fmt.Sprintf("failed to find geo_shape field [%s]", gs.Field)
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Bool.Must[i]); st != 0 {
				return st, et, er
			}
		}
		for i := range q.Bool.Filter {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Bool.Filter[i]); st != 0 {
				return st, et, er
			}
		}
		for i := range q.Bool.Should {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Bool.Should[i]); st != 0 {
				return st, et, er
			}
		}
		for i := range q.Bool.MustNot {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Bool.MustNot[i]); st != 0 {
				return st, et, er
			}
		}
	}
	if q.ConstantScore != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.ConstantScore.Filter); st != 0 {
			return st, et, er
		}
	}
	if q.Boosting != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Boosting.Positive); st != 0 {
			return st, et, er
		}
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Boosting.Negative); st != 0 {
			return st, et, er
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.DisMax.Queries[i]); st != 0 {
				return st, et, er
			}
		}
	}
	if q.FunctionScore != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, q.FunctionScore.Query); st != 0 {
			return st, et, er
		}
		for i := range q.FunctionScore.Functions {
			if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, q.FunctionScore.Functions[i].Filter); st != 0 {
				return st, et, er
			}
		}
	}
	if q.Nested != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.Nested.Query); st != 0 {
			return st, et, er
		}
	}
	if q.HasChild != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.HasChild.Query); st != 0 {
			return st, et, er
		}
	}
	if q.HasParent != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, &q.HasParent.Query); st != 0 {
			return st, et, er
		}
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, q.Pinned.Organic); st != 0 {
			return st, et, er
		}
	}
	if q.Rule != nil && q.Rule.Organic != nil {
		if st, et, er := validateGeoGridQueryFieldsR64(idxSchema, q.Rule.Organic); st != 0 {
			return st, et, er
		}
	}
	return 0, "", ""
}

func computeRuntimeCountedTermsBucketDocsR64(idxSchema *schema.IndexSchema, docs []runtimeMatchedDoc, tSpec *esast.TermsAggSpec) (map[string][]runtimeMatchedDoc, map[string]int64, []string) {
	byBucket := make(map[string][]runtimeMatchedDoc)
	counts := make(map[string]int64)
	var keys []string
	seenKey := make(map[string]bool)
	if tSpec == nil {
		return byBucket, counts, keys
	}
	src, _ := extractScriptSourceAndParams(tSpec.Script)
	missingStr := ""
	if tSpec.Missing != nil {
		missingStr = painless.FormatValueSafe(tSpec.Missing)
	}
	for _, md := range docs {
		effSchema := md.EffectiveSchema(idxSchema)
		var fieldBinding schema.FieldBinding
		hasFieldBinding := false
		if effSchema != nil && tSpec.Field != "" {
			fieldBinding = effSchema.ResolveField(tSpec.Field)
			hasFieldBinding = true
		}
		var vals []string
		if src != "" {
			rawVals := extractDocRawValuesForMetric(md, &esast.MetricAggSpec{
				Field:   tSpec.Field,
				Missing: tSpec.Missing,
				Script:  tSpec.Script,
			})
			for _, el := range rawVals {
				if el != nil {
					s := formatTermsScriptScalarKeyRound60(el, tSpec, hasFieldBinding, fieldBinding)
					if s != "" {
						vals = append(vals, s)
					}
				}
			}
		} else if tSpec.Field != "" {
			clean := strings.TrimSuffix(strings.TrimSuffix(tSpec.Field, ".keyword"), ".ngram")
			pathSegs := strings.Split(clean, ".")
			if hasFieldBinding && len(fieldBinding.SourceJSONPath) > 0 {
				pathSegs = fieldBinding.SourceJSONPath
			}
			nowUTC := time.Now().UTC()
			for _, rv := range collectSchemaAwareScalarValues(md.doc, tSpec.Field, pathSegs, effSchema) {
				if rv != nil {
					s := painless.FormatValueSafe(rv)
					if s != "" {
						if hasFieldBinding {
							if fieldBinding.ESType == "date" || fieldBinding.ESType == "date_nanos" {
								trimmed := strings.TrimSpace(s)
								if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
									if fieldBinding.ESType == "date_nanos" && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
										iv /= 1_000_000
									}
									s = strconv.FormatInt(iv, 10)
								} else if ms, ok := schema.ParseESDateToEpochMillis(trimmed, nowUTC); ok {
									s = strconv.FormatInt(ms, 10)
								}
							} else if fieldBinding.ESType == "boolean" || fieldBinding.DorisType == schema.DorisBoolean {
								switch strings.ToLower(strings.TrimSpace(s)) {
								case "1", "true":
									s = "true"
								case "0", "false":
									s = "false"
								}
							}
							if fieldBinding.EffectiveLowercase(!strings.HasSuffix(tSpec.Field, ".keyword")) {
								s = strings.ToLower(s)
							}
						}
						vals = append(vals, s)
					}
				}
			}
		}
		if len(vals) == 0 {
			if missingStr != "" {
				vals = []string{missingStr}
			} else if tSpec.MissingBucket {
				vals = []string{"__ES_MISSING_BUCKET__"}
			}
		}
		seenDocVal := make(map[string]bool, len(vals))
		for _, v := range vals {
			if v == "" {
				continue
			}
			if !seenKey[v] {
				seenKey[v] = true
				keys = append(keys, v)
			}
			counts[v]++
			if !seenDocVal[v] {
				seenDocVal[v] = true
				byBucket[v] = append(byBucket[v], md)
			}
		}
	}
	bucketESType := strings.TrimSpace(tSpec.ValueType)
	if bucketESType == "" && idxSchema != nil && tSpec.Field != "" {
		bucketESType = idxSchema.ResolveField(tSpec.Field).ESType
	}
	sort.Slice(keys, func(i, j int) bool {
		ci, cj := counts[keys[i]], counts[keys[j]]
		if ci != cj {
			return ci > cj
		}
		return compareTermsKeysSchemaAwareR62Search(keys[i], keys[j], bucketESType)
	})
	return byBucket, counts, keys
}

func emitRuntimeCountedTermsAggRowsR64(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	tSpec := aggSpec.CountedTerms
	if tSpec == nil {
		return
	}
	byBucket, counts, keys := computeRuntimeCountedTermsBucketDocsR64(idxSchema, docs, tSpec)
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		rowBucketKey := k
		if parentBucketKey != "" {
			rowBucketKey = parentBucketKey + "\x1f" + k
		}
		cnt := counts[k]
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowBucketKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowBucketKey, subAggs, byBucket[k], out, idxSchema)
		}
	}
}

func isPureMatchAllQueryR64(q *esast.Query) bool {
	if q == nil {
		return true
	}
	if q.MatchAll != nil &&
		q.MatchNone == nil &&
		q.Bool == nil &&
		q.DisMax == nil &&
		q.Boosting == nil &&
		len(q.Term) == 0 &&
		q.Terms == nil &&
		len(q.TermsSet) == 0 &&
		q.Ids == nil &&
		len(q.Range) == 0 &&
		q.Exists == nil &&
		len(q.Prefix) == 0 &&
		len(q.Wildcard) == 0 &&
		len(q.Regexp) == 0 &&
		len(q.Fuzzy) == 0 &&
		len(q.Match) == 0 &&
		len(q.MatchPhrase) == 0 &&
		len(q.MatchPhrasePrefix) == 0 &&
		len(q.MatchBoolPrefix) == 0 &&
		len(q.Common) == 0 &&
		q.MultiMatch == nil &&
		q.CombinedFields == nil &&
		q.QueryString == nil &&
		q.SimpleQueryString == nil &&
		q.Nested == nil &&
		q.ConstantScore == nil &&
		q.FunctionScore == nil &&
		q.ScriptScore == nil &&
		q.Script == nil &&
		q.KNN == nil &&
		q.GeoDistance == nil &&
		q.GeoBoundingBox == nil &&
		q.GeoPolygon == nil &&
		q.GeoShape == nil &&
		q.GeoGrid == nil &&
		q.Wrapper == nil &&
		q.Pinned == nil &&
		q.MoreLikeThis == nil &&
		len(q.Intervals) == 0 &&
		len(q.SpanTerm) == 0 &&
		q.SpanNear == nil &&
		q.SpanOr == nil &&
		q.SpanNot == nil &&
		q.SpanFirst == nil &&
		q.SpanMulti == nil &&
		q.SpanContaining == nil &&
		q.SpanWithin == nil &&
		q.FieldMaskingSpan == nil &&
		q.RankFeature == nil &&
		q.DistanceFeature == nil &&
		q.HasChild == nil &&
		q.HasParent == nil &&
		q.ParentID == nil &&
		q.Percolate == nil &&
		q.Rule == nil &&
		q.SparseVector == nil {
		return true
	}
	if q.Bool != nil && len(q.Bool.Filter) == 0 && len(q.Bool.Should) == 0 && len(q.Bool.MustNot) == 0 && len(q.Bool.Must) == 1 {
		return isPureMatchAllQueryR64(&q.Bool.Must[0])
	}
	return false
}

func aggsHaveMinDocCountZeroR64(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Global != nil {
			return true
		}
		if spec.Terms != nil && spec.Terms.MinDocCount != nil && *spec.Terms.MinDocCount == 0 {
			return true
		}
		if spec.CountedTerms != nil && spec.CountedTerms.MinDocCount != nil && *spec.CountedTerms.MinDocCount == 0 {
			return true
		}
		if spec.MultiTerms != nil && spec.MultiTerms.MinDocCount != nil && *spec.MultiTerms.MinDocCount == 0 {
			return true
		}
		if spec.Histogram != nil && spec.Histogram.MinDocCount != nil && *spec.Histogram.MinDocCount == 0 {
			return true
		}
		if spec.DateHistogram != nil && spec.DateHistogram.MinDocCount != nil && *spec.DateHistogram.MinDocCount == 0 {
			return true
		}
		if spec.Missing != nil {
			return true
		}
		if subs := spec.SubAggs(); len(subs) > 0 && aggsHaveMinDocCountZeroR64(subs) {
			return true
		}
	}
	return false
}

func searchReqNeedsSpatialEvalR64(targets []string, schemas []*schema.IndexSchema, req *esast.SearchRequest, aliasFilters map[string]*esast.Query) bool {
	if req == nil {
		return false
	}
	for i, sc := range schemas {
		if queryNeedsRuntimeSpatialEvalR64(req.Query, sc) || queryNeedsRuntimeSpatialEvalR64(req.PostFilter, sc) {
			return true
		}
		if i < len(targets) && aliasFilters != nil {
			if af := aliasFilters[targets[i]]; af != nil && queryNeedsRuntimeSpatialEvalR64(af, sc) {
				return true
			}
		}
	}
	if len(schemas) == 0 {
		if queryNeedsRuntimeSpatialEvalR64(req.Query, nil) || queryNeedsRuntimeSpatialEvalR64(req.PostFilter, nil) {
			return true
		}
	}
	return false
}

func aggSpecIsDirectSpatialR64(spec esast.AggSpec) bool {
	return spec.GeoBounds != nil || spec.GeoCentroid != nil ||
		spec.CartesianBounds != nil || spec.CartesianCentroid != nil ||
		spec.GeoLine != nil || spec.GeoDistance != nil ||
		spec.GeohashGrid != nil || spec.GeotileGrid != nil || spec.GeoHexGrid != nil
}

func aggSpecHasSpatialSubtreeR64(spec esast.AggSpec) bool {
	if aggSpecIsDirectSpatialR64(spec) {
		return true
	}
	for _, sub := range spec.SubAggs() {
		if aggSpecHasSpatialSubtreeR64(sub) {
			return true
		}
	}
	return false
}

func dropSpatialLeafAggRowsR64(aggRows []AggRow, fullKey string, spec esast.AggSpec) []AggRow {
	if aggSpecIsDirectSpatialR64(spec) {
		return dropRuntimeAggRows(aggRows, fullKey, "")
	}
	for subName, subSpec := range spec.SubAggs() {
		if aggSpecHasSpatialSubtreeR64(subSpec) {
			aggRows = dropSpatialLeafAggRowsR64(aggRows, fullKey+"."+subName, subSpec)
		}
	}
	return aggRows
}

func hitsToRuntimeMatchedDocsWithSchemasR64(hits []HitRow, schemasByIndex map[string]*schema.IndexSchema, primarySchema *schema.IndexSchema) []runtimeMatchedDoc {
	out := make([]runtimeMatchedDoc, 0, len(hits))
	for _, h := range hits {
		sc := schemasByIndex[h.Index]
		if sc == nil {
			sc = primarySchema
		}
		hCopy := h
		hCopy.Schema = sc
		var doc map[string]any
		src := hCopy.EffectiveSource()
		if len(src) > 0 {
			dec := json.NewDecoder(strings.NewReader(string(src)))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
		if doc == nil {
			doc = make(map[string]any)
		}
		doc["__meta_id"] = hCopy.ID
		if hCopy.Index != "" {
			doc["__meta_index"] = hCopy.Index
		}
		if hCopy.Version > 0 {
			doc["__meta_version"] = hCopy.Version
		} else {
			doc["__meta_version"] = int64(1)
		}
		out = append(out, runtimeMatchedDoc{
			hit:        hCopy,
			doc:        doc,
			rootDoc:    doc,
			rootSchema: sc,
		})
	}
	return out
}

func recomputeMultiIndexSpatialAggsR64(
	aggs map[string]esast.AggSpec,
	allFetchedHits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	aggRows []AggRow,
) []AggRow {
	if len(aggs) == 0 {
		return aggRows
	}
	spatialAggs := make(map[string]esast.AggSpec)
	for aggName, spec := range aggs {
		if aggSpecHasSpatialSubtreeR64(spec) {
			spatialAggs[aggName] = spec
			aggRows = dropSpatialLeafAggRowsR64(aggRows, aggName, spec)
		}
	}
	if len(spatialAggs) == 0 {
		return aggRows
	}
	matchedDocs := hitsToRuntimeMatchedDocsWithSchemasR64(allFetchedHits, schemasByIndex, primarySchema)
	return applyRuntimeScriptAggsForMap("", "", spatialAggs, matchedDocs, matchedDocs, aggRows, primarySchema)
}

func isFieldUnindexedInSchemasR64(field string, schemasByIndex map[string]*schema.IndexSchema, primarySchema *schema.IndexSchema) bool {
	if field == "" {
		return false
	}
	checkSchema := func(sc *schema.IndexSchema) bool {
		if sc == nil {
			return false
		}
		b := sc.ResolveField(field)
		if b.FromRuntime {
			return true
		}
		if b.NotIndexed && b.ESType != "constant_keyword" {
			return true
		}
		return false
	}
	if checkSchema(primarySchema) {
		return true
	}
	for _, sc := range schemasByIndex {
		if checkSchema(sc) {
			return true
		}
	}
	return false
}

func queryUsesUnindexedFieldR64(q *esast.Query, schemasByIndex map[string]*schema.IndexSchema, primarySchema *schema.IndexSchema) bool {
	if q == nil {
		return false
	}
	checkMapKeys := func(m map[string]esast.TermEntry) bool {
		for k := range m {
			if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
				return true
			}
		}
		return false
	}
	if checkMapKeys(q.Term) {
		return true
	}
	for k := range q.Range {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Prefix {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Wildcard {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Regexp {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Fuzzy {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Match {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.MatchPhrase {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.MatchPhrasePrefix {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.MatchBoolPrefix {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.Common {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	for k := range q.TermsSet {
		if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
			return true
		}
	}
	if q.Terms != nil {
		for k := range q.Terms.Fields {
			if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
				return true
			}
		}
		for k := range q.Terms.Lookups {
			if isFieldUnindexedInSchemasR64(k, schemasByIndex, primarySchema) {
				return true
			}
		}
	}
	if q.Nested != nil && queryUsesUnindexedFieldR64(&q.Nested.Query, schemasByIndex, primarySchema) {
		return true
	}
	if q.ConstantScore != nil && queryUsesUnindexedFieldR64(&q.ConstantScore.Filter, schemasByIndex, primarySchema) {
		return true
	}
	if q.Boosting != nil {
		if queryUsesUnindexedFieldR64(&q.Boosting.Positive, schemasByIndex, primarySchema) || queryUsesUnindexedFieldR64(&q.Boosting.Negative, schemasByIndex, primarySchema) {
			return true
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryUsesUnindexedFieldR64(&q.DisMax.Queries[i], schemasByIndex, primarySchema) {
				return true
			}
		}
	}
	if q.FunctionScore != nil {
		if queryUsesUnindexedFieldR64(q.FunctionScore.Query, schemasByIndex, primarySchema) {
			return true
		}
		for _, fn := range q.FunctionScore.Functions {
			if queryUsesUnindexedFieldR64(fn.Filter, schemasByIndex, primarySchema) {
				return true
			}
		}
	}
	if q.ScriptScore != nil && queryUsesUnindexedFieldR64(q.ScriptScore.Query, schemasByIndex, primarySchema) {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryUsesUnindexedFieldR64(&q.Bool.Must[i], schemasByIndex, primarySchema) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryUsesUnindexedFieldR64(&q.Bool.Filter[i], schemasByIndex, primarySchema) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryUsesUnindexedFieldR64(&q.Bool.Should[i], schemasByIndex, primarySchema) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryUsesUnindexedFieldR64(&q.Bool.MustNot[i], schemasByIndex, primarySchema) {
				return true
			}
		}
	}
	return false
}

func aggsHaveIndexTermsMinDocCountZeroR64(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Terms != nil && spec.Terms.Field == "_index" && spec.Terms.MinDocCount != nil && *spec.Terms.MinDocCount == 0 {
			return true
		}
		if subs := spec.SubAggs(); len(subs) > 0 && aggsHaveIndexTermsMinDocCountZeroR64(subs) {
			return true
		}
	}
	return false
}

func injectZeroIndexTermsAggRowsR64(
	prefix string,
	aggs map[string]esast.AggSpec,
	targets []string,
	perIdxHasDocs map[string]bool,
	allAggRows []AggRow,
) []AggRow {
	for aggName, spec := range aggs {
		fullKey := aggName
		if prefix != "" {
			fullKey = prefix + "." + aggName
		}
		if spec.Terms != nil && spec.Terms.Field == "_index" && spec.Terms.MinDocCount != nil && *spec.Terms.MinDocCount == 0 && prefix == "" {
			present := make(map[string]bool, len(targets))
			for _, r := range allAggRows {
				if r.AggName == fullKey {
					present[r.BucketKey] = true
				}
			}
			for _, tName := range targets {
				if perIdxHasDocs[tName] && !present[tName] {
					allAggRows = append(allAggRows, AggRow{
						AggName:   fullKey,
						BucketKey: tName,
						DocCount:  0,
						Value:     0,
					})
					present[tName] = true
				}
			}
		}
	}
	return allAggRows
}
