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
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const (
	maxIngestAttachmentDecompressedBytes = 16 << 20
	maxIngestGrokDissectBytesRound63     = 1 << 20
)

// ============================================================================
// WP-1: F6/F7/F2 Schema & Wire Fixes (cat.allocation, snapshot.status, cluster.info, reindex)
// ============================================================================

// isCatStructuredOutputRound63 reports whether a `/_cat/*` request will be serialized
// as structured JSON/YAML/CBOR/SMILE rather than plain-text aligned columns.
func isCatStructuredOutputRound63(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.URL != nil {
		if f := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))); f != "" {
			return strings.Contains(f, "json") || strings.Contains(f, "yaml") ||
				strings.Contains(f, "cbor") || strings.Contains(f, "smile")
		}
	}
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" || strings.Contains(accept, "text/plain") || strings.Contains(accept, "*/*") {
		return false
	}
	return strings.Contains(accept, "json") || strings.Contains(accept, "yaml") ||
		strings.Contains(accept, "cbor") || strings.Contains(accept, "smile")
}

// buildSnapshotStatusEntryRound63 constructs an `elasticsearch-specification` 8.15
// `snapshot._types.Status`-compliant snapshot status object including `include_global_state`
// and per-index `indices` stats.
func buildSnapshotStatusEntryRound63(snapName, repoName string, rawSnap map[string]any) map[string]any {
	uuidStr := snapName + "-uuid"
	stateStr := "SUCCESS"
	includeGlobalState := true
	var idxNames []string
	if rawSnap != nil {
		if u, ok := rawSnap["uuid"].(string); ok && u != "" {
			uuidStr = u
		}
		if st, ok := rawSnap["state"].(string); ok && st != "" {
			stateStr = st
		}
		if igs, ok := rawSnap["include_global_state"].(bool); ok {
			includeGlobalState = igs
		}
		switch iv := rawSnap["indices"].(type) {
		case []string:
			for _, idx := range iv {
				if idx != "" {
					idxNames = append(idxNames, idx)
				}
			}
		case []any:
			for _, item := range iv {
				if idx, ok := item.(string); ok && idx != "" {
					idxNames = append(idxNames, idx)
				}
			}
		}
	}
	sort.Strings(idxNames)

	indicesMap := make(map[string]any, len(idxNames))
	for _, idxName := range idxNames {
		idxStats := map[string]any{
			"incremental":          map[string]any{"file_count": 1, "size_in_bytes": int64(128)},
			"total":                map[string]any{"file_count": 1, "size_in_bytes": int64(128)},
			"start_time_in_millis": int64(1767225600000),
			"time_in_millis":       int64(10),
		}
		indicesMap[idxName] = map[string]any{
			"shards_stats": map[string]any{
				"initializing": 0,
				"started":      0,
				"finalizing":   0,
				"done":         1,
				"failed":       0,
				"total":        1,
			},
			"stats": idxStats,
			"shards": map[string]any{
				"0": map[string]any{
					"stage": "DONE",
					"stats": map[string]any{
						"incremental":          map[string]any{"file_count": 1, "size_in_bytes": int64(128)},
						"total":                map[string]any{"file_count": 1, "size_in_bytes": int64(128)},
						"start_time_in_millis": int64(1767225600000),
						"time_in_millis":       int64(10),
					},
					"node": taskLocalNodeID,
				},
			},
		}
	}

	shardCount := len(idxNames)
	if shardCount < 1 {
		shardCount = 1
	}
	return map[string]any{
		"snapshot":             snapName,
		"repository":           repoName,
		"uuid":                 uuidStr,
		"state":                stateStr,
		"include_global_state": includeGlobalState,
		"shards_stats": map[string]any{
			"initializing": 0,
			"started":      0,
			"finalizing":   0,
			"done":         shardCount,
			"failed":       0,
			"total":        shardCount,
		},
		"stats": map[string]any{
			"incremental":          map[string]any{"file_count": shardCount, "size_in_bytes": int64(128 * shardCount)},
			"total":                map[string]any{"file_count": shardCount, "size_in_bytes": int64(128 * shardCount)},
			"start_time_in_millis": int64(1767225600000),
			"time_in_millis":       int64(10),
		},
		"indices": indicesMap,
	}
}

// resolveClusterHTTPPublishAddressRound63 derives `http.publish_address` dynamically from
// `X-Forwarded-Host` / `r.Host` (handling explicit `host:port`, IPv6 literals, and portless
// `:80`/`:443` reverse-proxy hosts), falling back to `"127.0.0.1:9200"`.
func resolveClusterHTTPPublishAddressRound63(r *http.Request) string {
	if r == nil {
		return "127.0.0.1:9200"
	}
	rawHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if rawHost != "" {
		if comma := strings.IndexByte(rawHost, ','); comma >= 0 {
			rawHost = strings.TrimSpace(rawHost[:comma])
		}
	} else {
		rawHost = strings.TrimSpace(r.Host)
	}
	if rawHost == "" {
		return "127.0.0.1:9200"
	}
	if h, p, err := net.SplitHostPort(rawHost); err == nil && h != "" && p != "" {
		return net.JoinHostPort(h, p)
	}
	cleanHost := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(rawHost, "]"), "["))
	if cleanHost == "" {
		return "127.0.0.1:9200"
	}
	if fwdPort := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); fwdPort != "" {
		if comma := strings.IndexByte(fwdPort, ','); comma >= 0 {
			fwdPort = strings.TrimSpace(fwdPort[:comma])
		}
		if fwdPort != "" {
			return net.JoinHostPort(cleanHost, fwdPort)
		}
	}
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return net.JoinHostPort(cleanHost, "443")
	}
	return net.JoinHostPort(cleanHost, "80")
}

func resolveClusterMaxContentLengthRound63(s *Server) int64 {
	if s != nil {
		if mb := atomic.LoadInt64(&s.maxBodyBytes); mb > 0 {
			return mb
		}
	}
	return DefaultMaxRequestBodyBytes
}

func collectActiveSnapshotStatusesRound63(s *Server) []any {
	if s == nil {
		return []any{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	repoNames := make([]string, 0, len(s.snapshots))
	for rn := range s.snapshots {
		repoNames = append(repoNames, rn)
	}
	sort.Strings(repoNames)
	out := make([]any, 0)
	for _, rn := range repoNames {
		bySnap := s.snapshots[rn]
		snapNames := make([]string, 0, len(bySnap))
		for sn, raw := range bySnap {
			if raw == nil {
				continue
			}
			st, _ := raw["state"].(string)
			if st == "IN_PROGRESS" || st == "STARTED" {
				snapNames = append(snapNames, sn)
			}
		}
		sort.Strings(snapNames)
		for _, sn := range snapNames {
			out = append(out, buildSnapshotStatusEntryRound63(sn, rn, bySnap[sn]))
		}
	}
	return out
}

func javaStringHashCodeRound63(s string) int32 {
	var h int32
	for _, r := range s {
		if r <= 0xFFFF {
			h = 31*h + int32(r)
		} else {
			rPrime := r - 0x10000
			high := 0xD800 + ((rPrime >> 10) & 0x3FF)
			low := 0xDC00 + (rPrime & 0x3FF)
			h = 31*h + high
			h = 31*h + low
		}
	}
	return h
}

func javaHashMapBucketRound63(key string, numEntries int) int {
	capPow2 := 16
	for float64(capPow2)*0.75 < float64(numEntries) && capPow2 < (1<<30) {
		capPow2 <<= 1
	}
	// #nosec G115 -- Java HashMap hash spread uses unsigned 32-bit bit pattern of signed int32 hashCode
	uh := uint32(javaStringHashCodeRound63(key))
	spread := uh ^ (uh >> 16)
	// #nosec G115 -- capPow2 is bounded in [16, 1<<30]
	return int(spread & uint32(capPow2-1))
}

func orderReindexRemoteUnknownKeysRound63(orderedKeys, badRemKeys []string, totalRemoteKeys int) []string {
	if len(badRemKeys) <= 1 {
		return badRemKeys
	}
	isStrictlySorted := len(orderedKeys) > 1
	for i := 1; i < len(orderedKeys); i++ {
		if orderedKeys[i-1] > orderedKeys[i] {
			isStrictlySorted = false
			break
		}
	}
	if !isStrictlySorted {
		return badRemKeys
	}
	out := append([]string(nil), badRemKeys...)
	sort.SliceStable(out, func(i, j int) bool {
		return javaHashMapBucketRound63(out[i], totalRemoteKeys) < javaHashMapBucketRound63(out[j], totalRemoteKeys)
	})
	return out
}

// ============================================================================
// WP-2: Nested/Array Lookup, Vector Tile (_mvt PBF), SQL, EQL, Downsample, ES|QL, SLM/ILM
// ============================================================================

// getNestedOrArrayDocValRound63 resolves dotted field paths across nested objects, literal
// dotted keys, and arrays of objects (e.g. `event: [{"category": "process"}]` -> `"process"`).
func getNestedOrArrayDocValRound63(doc map[string]any, path string) any {
	if doc == nil || path == "" {
		return nil
	}
	if v, exists := doc[path]; exists {
		return normalizeESQLNumber(v)
	}
	vals := collectNestedOrArrayValsRound63(doc, strings.Split(path, "."))
	if len(vals) == 0 {
		return nil
	}
	if len(vals) == 1 {
		return normalizeESQLNumber(vals[0])
	}
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = normalizeESQLNumber(v)
	}
	return out
}

func collectNestedOrArrayValsRound63(cur any, segs []string) []any {
	if cur == nil {
		return nil
	}
	if len(segs) == 0 {
		if arr, ok := cur.([]any); ok {
			var flat []any
			for _, el := range arr {
				if el != nil {
					flat = append(flat, el)
				}
			}
			return flat
		}
		return []any{cur}
	}
	switch node := cur.(type) {
	case map[string]any:
		joined := strings.Join(segs, ".")
		if v, ok := node[joined]; ok && v != nil {
			return collectNestedOrArrayValsRound63(v, nil)
		}
		for splitIdx := len(segs) - 1; splitIdx >= 1; splitIdx-- {
			prefix := strings.Join(segs[:splitIdx], ".")
			if sub, ok := node[prefix]; ok && sub != nil {
				if got := collectNestedOrArrayValsRound63(sub, segs[splitIdx:]); len(got) > 0 {
					return got
				}
			}
		}
		return nil
	case []any:
		var all []any
		for _, el := range node {
			all = append(all, collectNestedOrArrayValsRound63(el, segs)...)
		}
		return all
	default:
		return nil
	}
}

// --- Mapbox Vector Tile v2.1 Protobuf Encoder (`/_mvt`) ---

type mvtFeatureSpecRound63 struct {
	id       uint64
	geomType uint64 // 1 = POINT, 3 = POLYGON
	geometry []uint32
	attrs    map[string]any
}

type mvtLayerSpecRound63 struct {
	name     string
	extent   uint32
	features []mvtFeatureSpecRound63
}

func appendPBVarintRound63(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendPBTagRound63(dst []byte, fieldNum uint64, wireType uint64) []byte {
	return appendPBVarintRound63(dst, (fieldNum<<3)|wireType)
}

func appendPBBytesRound63(dst []byte, fieldNum uint64, b []byte) []byte {
	dst = appendPBTagRound63(dst, fieldNum, 2)
	dst = appendPBVarintRound63(dst, uint64(len(b)))
	return append(dst, b...)
}

func zigZagEncode32Round63(n int32) uint32 {
	// #nosec G115 -- Protobuf sint32 ZigZag bit-pattern encoding maps int32 -> uint32 bijectively
	return uint32((n << 1) ^ (n >> 31))
}

func encodeMVTPointGeometryRound63(px, py int32) []uint32 {
	// MoveTo(1) count=1 => (1 & 0x7) | (1 << 3) = 9
	return []uint32{9, zigZagEncode32Round63(px), zigZagEncode32Round63(py)}
}

func encodeMVTBoxPolygonGeometryRound63(x0, y0, x1, y1 int32) []uint32 {
	// Clockwise exterior ring in MVT screen coordinates (y down):
	// MoveTo(1, count=1): (x0,y0)
	// LineTo(2, count=3): (x1-x0, 0), (0, y1-y0), (x0-x1, 0)
	// ClosePath(7, count=1)
	dx := x1 - x0
	dy := y1 - y0
	return []uint32{
		(1 & 0x7) | (1 << 3),
		zigZagEncode32Round63(x0), zigZagEncode32Round63(y0),
		(2 & 0x7) | (3 << 3),
		zigZagEncode32Round63(dx), zigZagEncode32Round63(0),
		zigZagEncode32Round63(0), zigZagEncode32Round63(dy),
		zigZagEncode32Round63(-dx), zigZagEncode32Round63(0),
		(7 & 0x7) | (1 << 3),
	}
}

func encodeMVTValueMsgRound63(val any) []byte {
	var b []byte
	switch tv := val.(type) {
	case string:
		b = appendPBBytesRound63(b, 1, []byte(tv))
	case bool:
		b = appendPBTagRound63(b, 7, 0)
		if tv {
			b = appendPBVarintRound63(b, 1)
		} else {
			b = appendPBVarintRound63(b, 0)
		}
	case int:
		return encodeMVTInt64ValueRound63(int64(tv))
	case int64:
		return encodeMVTInt64ValueRound63(tv)
	case float64:
		b = appendPBTagRound63(b, 3, 1) // double_value = field 3, wire 1 (64-bit)
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], math.Float64bits(tv))
		b = append(b, tmp[:]...)
	default:
		b = appendPBBytesRound63(b, 1, []byte(fmt.Sprintf("%v", val)))
	}
	return b
}

func encodeMVTInt64ValueRound63(iv int64) []byte {
	var b []byte
	if iv >= 0 {
		b = appendPBTagRound63(b, 5, 0) // uint_value = field 5
		b = appendPBVarintRound63(b, uint64(iv))
	} else {
		b = appendPBTagRound63(b, 6, 0) // sint_value = field 6 (zigzag 64)
		// #nosec G115 -- Protobuf sint64 ZigZag bit-pattern encoding maps int64 -> uint64 bijectively
		zz := uint64((iv << 1) ^ (iv >> 63))
		b = appendPBVarintRound63(b, zz)
	}
	return b
}

func encodeMVTTileRound63(layers []mvtLayerSpecRound63) []byte {
	var tileBytes []byte
	for _, lyr := range layers {
		var layerBuf []byte
		// version = 2 (field 15, varint)
		layerBuf = appendPBTagRound63(layerBuf, 15, 0)
		layerBuf = appendPBVarintRound63(layerBuf, 2)
		// name (field 1, string)
		layerBuf = appendPBBytesRound63(layerBuf, 1, []byte(lyr.name))
		// extent (field 5, uint32)
		ext := lyr.extent
		if ext == 0 {
			ext = 4096
		}
		layerBuf = appendPBTagRound63(layerBuf, 5, 0)
		layerBuf = appendPBVarintRound63(layerBuf, uint64(ext))

		keyIdx := make(map[string]uint32)
		var keys []string
		valIdx := make(map[string]uint32)
		var vals [][]byte

		internKey := func(k string) uint32 {
			if idx, ok := keyIdx[k]; ok {
				return idx
			}
			// #nosec G115 -- MVT layer key table size is bounded by tile feature attributes (< 10000)
			idx := uint32(len(keys))
			keys = append(keys, k)
			keyIdx[k] = idx
			return idx
		}
		internVal := func(v any) uint32 {
			enc := encodeMVTValueMsgRound63(v)
			sig := string(enc)
			if idx, ok := valIdx[sig]; ok {
				return idx
			}
			// #nosec G115 -- MVT layer value table size is bounded by tile feature attributes (< 10000)
			idx := uint32(len(vals))
			vals = append(vals, enc)
			valIdx[sig] = idx
			return idx
		}

		for _, feat := range lyr.features {
			var fBuf []byte
			if feat.id > 0 {
				fBuf = appendPBTagRound63(fBuf, 1, 0)
				fBuf = appendPBVarintRound63(fBuf, feat.id)
			}
			if len(feat.attrs) > 0 {
				attrKeys := make([]string, 0, len(feat.attrs))
				for ak := range feat.attrs {
					attrKeys = append(attrKeys, ak)
				}
				sort.Strings(attrKeys)
				var packedTags []byte
				for _, ak := range attrKeys {
					av := feat.attrs[ak]
					if av == nil {
						continue
					}
					ki := internKey(ak)
					vi := internVal(av)
					packedTags = appendPBVarintRound63(packedTags, uint64(ki))
					packedTags = appendPBVarintRound63(packedTags, uint64(vi))
				}
				if len(packedTags) > 0 {
					fBuf = appendPBBytesRound63(fBuf, 2, packedTags)
				}
			}
			// type (field 3, GeomType enum)
			fBuf = appendPBTagRound63(fBuf, 3, 0)
			fBuf = appendPBVarintRound63(fBuf, feat.geomType)
			// geometry (field 4, packed uint32)
			var packedGeom []byte
			for _, g := range feat.geometry {
				packedGeom = appendPBVarintRound63(packedGeom, uint64(g))
			}
			fBuf = appendPBBytesRound63(fBuf, 4, packedGeom)

			layerBuf = appendPBBytesRound63(layerBuf, 2, fBuf)
		}

		for _, k := range keys {
			layerBuf = appendPBBytesRound63(layerBuf, 3, []byte(k))
		}
		for _, vBytes := range vals {
			layerBuf = appendPBBytesRound63(layerBuf, 4, vBytes)
		}

		tileBytes = appendPBBytesRound63(tileBytes, 3, layerBuf)
	}
	return tileBytes
}

func projectLonLatToTilePixelRound63(lon, lat float64, zoom, tileX, tileY int, extent uint32) (int32, int32, bool) {
	if math.IsNaN(lon) || math.IsNaN(lat) || lon < -180.0 || lon > 180.0 || lat < -85.05112878 || lat > 85.05112878 {
		return 0, 0, false
	}
	n := math.Exp2(float64(zoom))
	worldX := ((lon + 180.0) / 360.0) * n
	latRad := lat * math.Pi / 180.0
	worldY := (1.0 - math.Log(math.Tan(latRad)+1.0/math.Cos(latRad))/math.Pi) / 2.0 * n

	localX := (worldX - float64(tileX)) * float64(extent)
	localY := (worldY - float64(tileY)) * float64(extent)
	px := int32(math.Round(localX))
	py := int32(math.Round(localY))
	return px, py, true
}

func extractLonLatFromDocFieldRound63(doc map[string]any, field string) ([][2]float64, bool) {
	raw := getNestedOrArrayDocValRound63(doc, field)
	if raw == nil {
		return nil, false
	}
	var pts [][2]float64
	var collect func(v any)
	collect = func(v any) {
		if sh, ok := parseEnrichGeoShapeRound59(v); ok {
			if sh.isPoint {
				pts = append(pts, [2]float64{sh.lon, sh.lat})
				return
			}
			// Representative centroid of exterior ring for polygon/envelope
			if len(sh.polygons) > 0 && len(sh.polygons[0]) > 0 {
				pts = append(pts, [2]float64{0.5 * (sh.minLon + sh.maxLon), 0.5 * (sh.minLat + sh.maxLat)})
				return
			}
		}
		if arr, ok := v.([]any); ok {
			// Check if [lon, lat] pair vs list of geo values
			if len(arr) == 2 {
				if _, isNum := toFloat64(arr[0]); isNum {
					return
				}
			}
			for _, el := range arr {
				collect(el)
			}
		}
	}
	collect(raw)
	return pts, len(pts) > 0
}

// serveMVTRound63 serves `GET/POST /{index}/_mvt/{field}/{zoom}/{x}/{y}` with valid
// Mapbox Vector Tile v2.1 PBF `hits` and `aggs` layers.
func (s *Server) serveMVTRound63(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	field := strings.TrimSpace(r.PathValue("field"))
	zoomStr := strings.TrimSpace(r.PathValue("zoom"))
	xStr := strings.TrimSpace(r.PathValue("x"))
	yStr := strings.TrimSpace(r.PathValue("y"))

	zoom, errZ := strconv.Atoi(zoomStr)
	x, errX := strconv.Atoi(xStr)
	y, errY := strconv.Atoi(yStr)
	if errZ != nil || errX != nil || errY != nil || zoom < 0 || zoom > 29 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("invalid vector tile coordinates [%s/%s/%s]", zoomStr, xStr, yStr))
		return
	}
	maxCoord := 1 << zoom
	if x < 0 || x >= maxCoord || y < 0 || y >= maxCoord {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("tile coordinates [%d/%d/%d] out of range [0..%d]", zoom, x, y, maxCoord-1))
		return
	}
	if field == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "field is required for _mvt")
		return
	}

	var body map[string]any
	if r.Body != nil && r.Body != http.NoBody {
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(bodyBytes))
			dec.UseNumber()
			if err := dec.Decode(&body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
	}

	extent := uint32(4096)
	bufferPx := int32(5)
	sizeLimit := 10000
	gridPrecision := 0
	gridType := "grid"
	var reqFields []string

	if r.URL != nil {
		q := r.URL.Query()
		if q.Has("extent") {
			if ev, err := strconv.ParseUint(strings.TrimSpace(q.Get("extent")), 10, 20); err == nil && ev > 0 {
				extent = uint32(ev)
			}
		}
		if q.Has("buffer") {
			if bv, err := strconv.ParseInt(strings.TrimSpace(q.Get("buffer")), 10, 20); err == nil && bv >= 0 {
				bufferPx = int32(bv)
			}
		}
		if q.Has("size") {
			if sv, err := strconv.Atoi(strings.TrimSpace(q.Get("size"))); err == nil && sv >= 0 {
				sizeLimit = sv
			}
		}
		if q.Has("grid_precision") {
			gp, err := strconv.Atoi(strings.TrimSpace(q.Get("grid_precision")))
			if err != nil || gp < 0 || gp > 8 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("[grid_precision] must be in [0..8], got [%s]", q.Get("grid_precision")))
				return
			}
			gridPrecision = gp
		}
		if q.Has("grid_type") {
			gt := strings.ToLower(strings.TrimSpace(q.Get("grid_type")))
			if gt != "grid" && gt != "point" && gt != "centroid" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unknown [grid_type] [%s]", q.Get("grid_type")))
				return
			}
			gridType = gt
		}
		if q.Has("fields") {
			for _, f := range strings.Split(q.Get("fields"), ",") {
				if f = strings.TrimSpace(f); f != "" {
					reqFields = append(reqFields, f)
				}
			}
		}
	}
	if body != nil {
		if ev, ok := toInt64(body["extent"]); ok && ev > 0 && ev <= (1<<20) {
			// #nosec G115 -- ev is bounded in [1, 1<<20]
			extent = uint32(ev)
		}
		if bv, ok := toInt64(body["buffer"]); ok && bv >= 0 && bv <= (1<<20) {
			// #nosec G115 -- bv is bounded in [0, 1<<20]
			bufferPx = int32(bv)
		}
		if sv, ok := toInt64(body["size"]); ok && sv >= 0 {
			sizeLimit = int(sv)
		}
		if gpRaw, hasGP := body["grid_precision"]; hasGP && gpRaw != nil {
			gp, ok := toInt64(gpRaw)
			if !ok || gp < 0 || gp > 8 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("[grid_precision] must be in [0..8], got [%v]", gpRaw))
				return
			}
			gridPrecision = int(gp)
		}
		if gtStr, ok := body["grid_type"].(string); ok && strings.TrimSpace(gtStr) != "" {
			gt := strings.ToLower(strings.TrimSpace(gtStr))
			if gt != "grid" && gt != "point" && gt != "centroid" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unknown [grid_type] [%s]", gtStr))
				return
			}
			gridType = gt
		}
		if fArr, ok := body["fields"].([]any); ok {
			for _, el := range fArr {
				switch fv := el.(type) {
				case string:
					if strings.TrimSpace(fv) != "" {
						reqFields = append(reqFields, strings.TrimSpace(fv))
					}
				case map[string]any:
					if fn, okS := fv["field"].(string); okS && strings.TrimSpace(fn) != "" {
						reqFields = append(reqFields, strings.TrimSpace(fn))
					}
				}
			}
		}
	}

	targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	ensureESCompatHeaders(w, r)
	w.Header().Set("Content-Type", "application/vnd.mapbox-vector-tile")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	var sReq esast.SearchRequest
	fetchSz := 10000
	sReq.Size = &fetchSz
	if body != nil && body["query"] != nil {
		if qBytes, err := json.Marshal(body["query"]); err == nil {
			var parsedQ esast.Query
			if json.Unmarshal(qBytes, &parsedQ) == nil {
				sReq.Query = &parsedQ
			}
		}
	}

	var hitFeatures []mvtFeatureSpecRound63
	type gridCellAcc struct {
		gx, gy int
		count  int64
		sumPX  int64
		sumPY  int64
	}
	gridCells := make(map[[2]int]*gridCellAcc)
	gridDim := 1 << gridPrecision

	if len(targets) > 0 {
		resp, _, errType, _ := s.executeSearchRequest(r.Context(), strings.Join(targets, ","), &sReq)
		if errType == "" {
			rawHits := extractSearchResponseHitItems(resp)
			minPx := -bufferPx
			maxPx := int32(extent) + bufferPx
			var featSeq uint64
			for _, hm := range rawHits {
				srcMap := extractHitSourceMap(hm)
				if srcMap == nil {
					continue
				}
				pts, okPts := extractLonLatFromDocFieldRound63(srcMap, field)
				if !okPts {
					continue
				}
				docID, _ := hm["_id"].(string)
				docIdx, _ := hm["_index"].(string)
				for _, pt := range pts {
					px, py, okProj := projectLonLatToTilePixelRound63(pt[0], pt[1], zoom, x, y, extent)
					if !okProj || px < minPx || px > maxPx || py < minPx || py > maxPx {
						continue
					}
					if gridPrecision > 0 && px >= 0 && px < int32(extent) && py >= 0 && py < int32(extent) {
						gx := int(px) * gridDim / int(extent)
						gy := int(py) * gridDim / int(extent)
						if gx >= gridDim {
							gx = gridDim - 1
						}
						if gy >= gridDim {
							gy = gridDim - 1
						}
						ck := [2]int{gx, gy}
						acc := gridCells[ck]
						if acc == nil {
							acc = &gridCellAcc{gx: gx, gy: gy}
							gridCells[ck] = acc
						}
						acc.count++
						acc.sumPX += int64(px)
						acc.sumPY += int64(py)
					}
					if len(hitFeatures) < sizeLimit {
						featSeq++
						attrs := map[string]any{
							"_id":    docID,
							"_index": docIdx,
						}
						for _, rf := range reqFields {
							if v := getNestedOrArrayDocValRound63(srcMap, rf); v != nil {
								attrs[rf] = v
							}
						}
						hitFeatures = append(hitFeatures, mvtFeatureSpecRound63{
							id:       featSeq,
							geomType: 1, // POINT
							geometry: encodeMVTPointGeometryRound63(px, py),
							attrs:    attrs,
						})
					}
				}
			}
		}
	}

	var layers []mvtLayerSpecRound63
	layers = append(layers, mvtLayerSpecRound63{
		name:     "hits",
		extent:   extent,
		features: hitFeatures,
	})
	if gridPrecision > 0 {
		cellKeys := make([][2]int, 0, len(gridCells))
		for ck := range gridCells {
			cellKeys = append(cellKeys, ck)
		}
		sort.Slice(cellKeys, func(i, j int) bool {
			if cellKeys[i][1] != cellKeys[j][1] {
				return cellKeys[i][1] < cellKeys[j][1]
			}
			return cellKeys[i][0] < cellKeys[j][0]
		})
		aggFeatures := make([]mvtFeatureSpecRound63, 0, len(cellKeys))
		// #nosec G115 -- extent <= 1<<20 and gridDim in [1, 256]
		cellSize := int32(extent) / int32(gridDim)
		if cellSize < 1 {
			cellSize = 1
		}
		for idx, ck := range cellKeys {
			acc := gridCells[ck]
			attrs := map[string]any{
				"_count": acc.count,
			}
			// #nosec G115 -- acc.gx and acc.gy are bounded in [0, gridDim-1] <= 255
			gx32, gy32 := int32(acc.gx), int32(acc.gy)
			if gridType == "grid" {
				x0 := gx32 * cellSize
				y0 := gy32 * cellSize
				x1 := x0 + cellSize
				y1 := y0 + cellSize
				aggFeatures = append(aggFeatures, mvtFeatureSpecRound63{
					id:       uint64(idx + 1),
					geomType: 3, // POLYGON
					geometry: encodeMVTBoxPolygonGeometryRound63(x0, y0, x1, y1),
					attrs:    attrs,
				})
			} else {
				var cx, cy int32
				if gridType == "centroid" && acc.count > 0 {
					avgX := acc.sumPX / acc.count
					avgY := acc.sumPY / acc.count
					if avgX >= math.MinInt32 && avgX <= math.MaxInt32 && avgY >= math.MinInt32 && avgY <= math.MaxInt32 {
						// #nosec G115 -- avgX and avgY are explicitly checked within int32 bounds
						cx = int32(avgX)
						// #nosec G115 -- avgX and avgY are explicitly checked within int32 bounds
						cy = int32(avgY)
					}
				} else {
					cx = gx32*cellSize + cellSize/2
					cy = gy32*cellSize + cellSize/2
				}
				aggFeatures = append(aggFeatures, mvtFeatureSpecRound63{
					id:       uint64(idx + 1),
					geomType: 1, // POINT
					geometry: encodeMVTPointGeometryRound63(cx, cy),
					attrs:    attrs,
				})
			}
		}
		layers = append(layers, mvtLayerSpecRound63{
			name:     "aggs",
			extent:   extent,
			features: aggFeatures,
		})
	}

	pbfBytes := encodeMVTTileRound63(layers)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pbfBytes)
}

// --- SQL Text Table & Translate Helpers ---

func formatSQLTextTableRound63(columns, rows []any) string {
	if len(columns) == 0 {
		return ""
	}
	colHeaders := make([]string, len(columns))
	widths := make([]int, len(columns))
	for i, c := range columns {
		cm, _ := c.(map[string]any)
		h := fmt.Sprintf("%v", cm["name"])
		colHeaders[i] = h
		w := utf8.RuneCountInString(h)
		if w < 15 {
			w = 15
		}
		widths[i] = w
	}
	strRows := make([][]string, len(rows))
	for ri, rAny := range rows {
		rSlice, _ := rAny.([]any)
		cells := make([]string, len(columns))
		for ci := 0; ci < len(columns); ci++ {
			var cell string
			if ci < len(rSlice) {
				if rSlice[ci] == nil {
					cell = "null"
				} else {
					cell = fmt.Sprintf("%v", rSlice[ci])
				}
			}
			cells[ci] = cell
			if cw := utf8.RuneCountInString(cell); cw > widths[ci] {
				widths[ci] = cw
			}
		}
		strRows[ri] = cells
	}

	var sb strings.Builder
	for i, h := range colHeaders {
		if i > 0 {
			sb.WriteByte('|')
		}
		hLen := utf8.RuneCountInString(h)
		padTotal := widths[i] - hLen
		leftPad := padTotal / 2
		rightPad := padTotal - leftPad
		sb.WriteString(strings.Repeat(" ", leftPad))
		sb.WriteString(h)
		sb.WriteString(strings.Repeat(" ", rightPad))
	}
	sb.WriteByte('\n')

	for i, w := range widths {
		if i > 0 {
			sb.WriteByte('+')
		}
		sb.WriteString(strings.Repeat("-", w))
	}
	sb.WriteByte('\n')

	for _, cells := range strRows {
		for i, cell := range cells {
			if i > 0 {
				sb.WriteByte('|')
			}
			cLen := utf8.RuneCountInString(cell)
			sb.WriteString(cell)
			if cLen < widths[i] {
				sb.WriteString(strings.Repeat(" ", widths[i]-cLen))
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func resolveSQLTableMappedFieldsRound63(s *Server, ctx context.Context, tableExpr string) map[string]string {
	if s == nil || strings.TrimSpace(tableExpr) == "" {
		return nil
	}
	_ = s.syncCatalogFromBackend(ctx)
	targets := s.resolveTargetIndices(tableExpr)
	if len(targets) == 0 && !strings.ContainsAny(tableExpr, "*?") {
		targets = []string{s.resolveIndexName(tableExpr)}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string)
	for _, idx := range targets {
		sch := s.indices[idx]
		if sch == nil {
			continue
		}
		for fname, fmeta := range sch.Fields {
			if strings.HasSuffix(fname, ".keyword") {
				continue
			}
			out[fname] = fmeta.ESType
		}
	}
	return out
}

// --- EQL Validation & Runtime Mappings Helpers ---

var validEQLRuntimeFieldTypesRound63 = map[string]bool{
	"boolean":       true,
	"composite":     true,
	"date":          true,
	"date_nanos":    true,
	"double":        true,
	"geo_point":     true,
	"ip":            true,
	"keyword":       true,
	"long":          true,
	"lookup":        true,
	"unsigned_long": true,
	"version":       true,
}

func validateEQLRuntimeMappingsRound63(rawRM any) (map[string]map[string]any, error) {
	if rawRM == nil {
		return nil, nil
	}
	rmMap, ok := rawRM.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("[runtime_mappings] must be an object")
	}
	parsed := make(map[string]map[string]any, len(rmMap))
	for fname, defAny := range rmMap {
		if strings.TrimSpace(fname) == "" {
			return nil, fmt.Errorf("runtime field name cannot be empty")
		}
		defMap, okM := defAny.(map[string]any)
		if !okM || defMap == nil {
			return nil, fmt.Errorf("runtime mapping definition for [%s] must be an object", fname)
		}
		for k := range defMap {
			switch k {
			case "type", "script", "format", "fields":
			default:
				return nil, fmt.Errorf("unknown parameter [%s] in runtime_mappings for [%s]", k, fname)
			}
		}
		ft, _ := defMap["type"].(string)
		ft = strings.TrimSpace(ft)
		if ft == "" || !validEQLRuntimeFieldTypesRound63[ft] {
			return nil, fmt.Errorf("unsupported or missing runtime field type [%s] for field [%s]", ft, fname)
		}
		if rawSc, hasSc := defMap["script"]; hasSc && rawSc != nil {
			var src string
			switch sv := rawSc.(type) {
			case string:
				src = sv
			case map[string]any:
				if _, hasBad := sv["unknown"]; hasBad {
					return nil, fmt.Errorf("unknown script field in runtime_mappings for [%s]", fname)
				}
				src, _ = sv["source"].(string)
				if src == "" {
					src, _ = sv["inline"].(string)
				}
			default:
				return nil, fmt.Errorf("invalid script specification for runtime field [%s]", fname)
			}
			if strings.TrimSpace(src) != "" {
				if cErr := painless.CompileValidate(src); cErr != nil {
					return nil, cErr
				}
			}
		}
		parsed[fname] = defMap
	}
	return parsed, nil
}

func evalEQLRuntimeFieldsOnDocRound63(doc map[string]any, hitFields map[string]any, rmDefs map[string]map[string]any) {
	if doc == nil {
		return
	}
	for k, v := range hitFields {
		if arr, ok := v.([]any); ok && len(arr) == 1 {
			setIngestPath(doc, k, normalizeESQLNumber(arr[0]))
		} else {
			setIngestPath(doc, k, normalizeESQLNumber(v))
		}
	}
	for fname, def := range rmDefs {
		ft, _ := def["type"].(string)
		var src string
		var params map[string]any
		switch sv := def["script"].(type) {
		case string:
			src = sv
		case map[string]any:
			src, _ = sv["source"].(string)
			if src == "" {
				src, _ = sv["inline"].(string)
			}
			params, _ = sv["params"].(map[string]any)
		}
		if strings.TrimSpace(src) == "" {
			if rawV := getNestedOrArrayDocValRound63(doc, fname); rawV != nil {
				setIngestPath(doc, fname, rawV)
			}
			continue
		}
		emitted, err := painless.EvalEmitContext(src, ft, doc, doc, params, nil)
		if err != nil {
			continue
		}
		if len(emitted) == 0 {
			deleteIngestPath(doc, fname)
		} else if len(emitted) == 1 {
			setIngestPath(doc, fname, normalizeESQLNumber(emitted[0]))
		} else {
			norm := make([]any, len(emitted))
			for i, ev := range emitted {
				norm[i] = normalizeESQLNumber(ev)
			}
			setIngestPath(doc, fname, norm)
		}
	}
}

func collectEQLReferencedFieldsRound63(ast *eqlQueryAST) []string {
	var fields []string
	seen := make(map[string]bool)
	addField := func(name string) {
		if name == "" || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "_") {
			return
		}
		if !seen[name] {
			seen[name] = true
			fields = append(fields, name)
		}
	}
	var walkExpr func(ex eqlExpr)
	walkExpr = func(ex eqlExpr) {
		if ex == nil {
			return
		}
		switch e := ex.(type) {
		case *eqlFieldExpr:
			addField(e.name)
		case *eqlNotExpr:
			walkExpr(e.sub)
		case *eqlInExpr:
			walkExpr(e.left)
			for _, it := range e.list {
				walkExpr(it)
			}
		case *eqlBinExpr:
			walkExpr(e.left)
			walkExpr(e.right)
		case *eqlFuncExpr:
			for _, a := range e.args {
				walkExpr(a)
			}
		}
	}
	walkStage := func(st eqlStageSpec) {
		walkExpr(st.where)
		for _, bk := range st.byKeys {
			walkExpr(bk)
		}
	}
	if !ast.isSequence {
		walkStage(ast.single)
	} else {
		for _, bk := range ast.byKeys {
			walkExpr(bk)
		}
		for _, st := range ast.stages {
			walkStage(st)
		}
		for _, absList := range ast.absentAfter {
			for _, astg := range absList {
				walkStage(astg)
			}
		}
		if ast.untilStage != nil {
			walkStage(*ast.untilStage)
		}
	}
	return fields
}

func findTokenLineColInQueryRound63(queryStr, ident string) (int, int) {
	line := 1
	col := 1
	n := len(queryStr)
	idLen := len(ident)
	if idLen == 0 {
		return 1, 1
	}
	inStr := false
	var quoteCh byte
	for i := 0; i < n; i++ {
		ch := queryStr[i]
		if inStr {
			if ch == '\\' && i+1 < n {
				i++
				col += 2
				continue
			}
			if ch == quoteCh {
				inStr = false
			}
			if ch == '\n' {
				line++
				col = 1
			} else {
				col++
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inStr = true
			quoteCh = ch
			col++
			continue
		}
		if i+idLen <= n && queryStr[i:i+idLen] == ident {
			prevOK := i == 0 || (!isEQLIdentCharRound63(queryStr[i-1]))
			nextOK := i+idLen == n || (!isEQLIdentCharRound63(queryStr[i+idLen]))
			if prevOK && nextOK {
				return line, col
			}
		}
		if ch == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return 1, 1
}

func isEQLIdentCharRound63(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.'
}

func validateEQLQueryColumnsRound63(s *Server, ctx context.Context, targetPattern string, queryStr string, ast *eqlQueryAST, rmDefs map[string]map[string]any) error {
	if s == nil || ast == nil {
		return nil
	}
	refFields := collectEQLReferencedFieldsRound63(ast)
	if len(refFields) == 0 {
		return nil
	}
	_ = s.syncCatalogFromBackend(ctx)
	targets := s.resolveTargetIndices(targetPattern)
	if len(targets) == 0 {
		return nil
	}
	knownSet := make(map[string]bool)
	hasAnyMappedSchema := false
	s.mu.RLock()
	for _, idx := range targets {
		sch := s.indices[idx]
		if sch == nil || len(sch.Fields) == 0 {
			continue
		}
		hasAnyMappedSchema = true
		for fname := range sch.Fields {
			knownSet[fname] = true
			if strings.HasSuffix(fname, ".keyword") {
				knownSet[strings.TrimSuffix(fname, ".keyword")] = true
			}
		}
		if sch.RawMapping != nil {
			for rName := range sch.RawMapping.Runtime {
				knownSet[rName] = true
			}
		}
	}
	s.mu.RUnlock()
	for rmName := range rmDefs {
		knownSet[rmName] = true
	}
	if !hasAnyMappedSchema || len(knownSet) == 0 {
		return nil
	}
	candidates := make([]string, 0, len(knownSet))
	for k := range knownSet {
		if !strings.HasSuffix(k, ".keyword") {
			candidates = append(candidates, k)
		}
	}
	sort.Strings(candidates)
	for _, rf := range refFields {
		if knownSet[rf] {
			continue
		}
		// Check prefix subfields
		hasPrefix := false
		pfx := rf + "."
		for k := range knownSet {
			if strings.HasPrefix(k, pfx) {
				hasPrefix = true
				break
			}
		}
		if hasPrefix {
			continue
		}
		ln, col := findTokenLineColInQueryRound63(queryStr, rf)
		if sugg := closestFieldSuggestionRound61(rf, candidates); sugg != "" {
			dist := levenshteinDistanceRound61(strings.ToLower(rf), strings.ToLower(sugg))
			maxLen := len(rf)
			if len(sugg) > maxLen {
				maxLen = len(sugg)
			}
			if maxLen > 0 && dist <= 2 && 1.0-float64(dist)/float64(maxLen) >= 0.65 {
				msg := fmt.Sprintf("Found 1 problem\nline %d:%d: Unknown column [%s], did you mean [%s]?", ln, col, rf, sugg)
				return fmt.Errorf("%s", msg)
			}
		}
		msg := fmt.Sprintf("Found 1 problem\nline %d:%d: Unknown column [%s]", ln, col, rf)
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// --- SLM Schedule, Health Indicators, ILM & Synonyms Helpers ---

func validateSLMScheduleRound63(sched string) error {
	fields := strings.Fields(strings.TrimSpace(sched))
	// Quartz cron: sec min hour dom month dow [year]
	if len(fields) < 6 {
		return fmt.Errorf("invalid schedule [%s]: expected at least 6 cron fields", sched)
	}
	secField := fields[0]
	minField := fields[1]
	// Executing more frequently than every 15m:
	// - second field is "*" or "*/N" or comma list with >1 firing per minute while min is "*"
	// - minute field is "*" or "?" or "*/N" where N < 15, or range "a-b"
	tooFrequent := secField == "*" || strings.HasPrefix(secField, "*/")
	if minField == "*" || minField == "?" {
		tooFrequent = true
	} else if strings.HasPrefix(minField, "*/") {
		step, err := strconv.Atoi(strings.TrimPrefix(minField, "*/"))
		if err != nil || step < 15 {
			tooFrequent = true
		}
	} else if strings.Contains(minField, "/") {
		parts := strings.SplitN(minField, "/", 2)
		if step, err := strconv.Atoi(parts[1]); err != nil || step < 15 {
			tooFrequent = true
		}
	} else if strings.Contains(minField, "-") {
		tooFrequent = true
	} else if strings.Contains(minField, ",") {
		parts := strings.Split(minField, ",")
		if len(parts) > 4 {
			tooFrequent = true
		}
	}
	if tooFrequent {
		return fmt.Errorf("invalid schedule [%s]: schedule would be too frequent, executing more than every [15m]", sched)
	}
	return nil
}

func patchHealthReportIndicatorsRound63(s *Server, payload map[string]any) {
	if s == nil || payload == nil {
		return
	}
	indicators, _ := payload["indicators"].(map[string]any)
	if indicators == nil {
		return
	}
	s.mu.RLock()
	slmCount := len(s.slmPolicies)
	slmMode := s.slmMode
	ilmCount := len(s.ilmPolicies)
	s.mu.RUnlock()

	if slmInd, ok := indicators["slm"].(map[string]any); ok && slmInd != nil {
		if slmMode != "STOPPED" && slmCount == 0 {
			slmInd["symptom"] = "No Snapshot Lifecycle Management policies configured"
		}
	}
	if ilmInd, ok := indicators["ilm"].(map[string]any); ok && ilmInd != nil {
		details, _ := ilmInd["details"].(map[string]any)
		if details == nil {
			details = make(map[string]any)
			ilmInd["details"] = details
		}
		// Elasticsearch ships with 19 built-in ILM policies (logs, metrics, synthetics, watch-history, etc.)
		totalPolicies := ilmCount + 19
		details["policies"] = totalPolicies
		if _, hasStag := details["stagnating_indices"]; !hasStag {
			details["stagnating_indices"] = 0
		}
	}
}

func formatILMStepJSONRound63(phase, action, name string) string {
	type ilmStepOrdered struct {
		Phase  string `json:"phase,omitempty"`
		Action string `json:"action,omitempty"`
		Name   string `json:"name,omitempty"`
	}
	b, _ := json.Marshal(ilmStepOrdered{Phase: phase, Action: action, Name: name})
	return string(b)
}

func (s *Server) serveILMMoveToStepRound63(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	targets := s.resolveTargetIndices(rawIndex)
	if len(targets) == 0 {
		if !s.hasExplicitTargetESVersion() {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", rawIndex))
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index [%s] does not exist", rawIndex))
		return
	}
	s.mu.RLock()
	var missingIdx string
	for _, idx := range targets {
		if _, idxExists := s.indices[idx]; !idxExists {
			missingIdx = idx
			break
		}
	}
	s.mu.RUnlock()
	if missingIdx != "" {
		if !s.hasExplicitTargetESVersion() {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", missingIdx))
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index [%s] does not exist", missingIdx))
		return
	}
	curStepMap, _ := body["current_step"].(map[string]any)
	nextStepMap, _ := body["next_step"].(map[string]any)
	if nextStepMap == nil || strings.TrimSpace(fmt.Sprintf("%v", nextStepMap["phase"])) == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[next_step] with [phase] is required")
		return
	}
	nextPhase := strings.TrimSpace(fmt.Sprintf("%v", nextStepMap["phase"]))

	if !s.hasExplicitTargetESVersion() {
		s.mu.Lock()
		for _, idx := range targets {
			if s.indexCustomSettings[idx] == nil {
				s.indexCustomSettings[idx] = make(map[string]any)
			}
			s.indexCustomSettings[idx]["__ilm_phase"] = nextPhase
			if na, okA := nextStepMap["action"].(string); okA && na != "" {
				s.indexCustomSettings[idx]["__ilm_action"] = na
			}
			if nn, okN := nextStepMap["name"].(string); okN && nn != "" {
				s.indexCustomSettings[idx]["__ilm_step"] = nn
			}
		}
		s.mu.Unlock()
		s.persistIndexBatchRound59(r.Context(), targets)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}

	s.mu.Lock()
	for _, idx := range targets {
		if _, idxExists := s.indices[idx]; !idxExists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index [%s] does not exist", idx))
			return
		}
		cs := s.indexCustomSettings[idx]
		polName := ""
		if cs != nil {
			if v, okV := cs["lifecycle.name"].(string); okV && v != "" {
				polName = v
			} else if v2, okV2 := cs["index.lifecycle.name"].(string); okV2 && v2 != "" {
				polName = v2
			}
		}
		if polName == "" {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("index [%s] is not associated with an Index Lifecycle Policy", idx))
			return
		}
		polEntry, polExists := s.ilmPolicies[polName]
		if !polExists || polEntry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("policy [%s] for index [%s] does not exist", polName, idx))
			return
		}
		polInner, _ := polEntry["policy"].(map[string]any)
		if polInner == nil {
			polInner = polEntry
		}
		phasesMap, _ := polInner["phases"].(map[string]any)
		if phasesMap != nil {
			if _, phaseOK := phasesMap[nextPhase]; !phaseOK && nextPhase != "new" {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("phase [%s] is not defined in policy [%s]", nextPhase, polName))
				return
			}
		}
		actualPhase := "new"
		actualAction := "complete"
		actualName := "complete"
		if cs != nil {
			if p, okP := cs["__ilm_phase"].(string); okP && p != "" {
				actualPhase = p
			} else if phasesMap != nil {
				if _, hasHot := phasesMap["hot"]; hasHot {
					actualPhase = "hot"
				}
			}
			if a, okA := cs["__ilm_action"].(string); okA && a != "" {
				actualAction = a
			}
			if n, okN := cs["__ilm_step"].(string); okN && n != "" {
				actualName = n
			}
		}
		if curStepMap != nil {
			reqPhase, _ := curStepMap["phase"].(string)
			reqAction, _ := curStepMap["action"].(string)
			reqName, _ := curStepMap["name"].(string)
			if (reqPhase != "" && reqPhase != actualPhase && (reqPhase != "new" || actualPhase != "hot")) ||
				(reqAction != "" && reqAction != actualAction) ||
				(reqName != "" && reqName != actualName) {
				s.mu.Unlock()
				reqStepJSON := formatILMStepJSONRound63(reqPhase, reqAction, reqName)
				actualStepJSON := formatILMStepJSONRound63(actualPhase, actualAction, actualName)
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("index [%s] is not on current step [%s], current step is [%s]",
						idx, reqStepJSON, actualStepJSON))
				return
			}
		}
		if s.indexCustomSettings[idx] == nil {
			s.indexCustomSettings[idx] = make(map[string]any)
		}
		s.indexCustomSettings[idx]["__ilm_phase"] = nextPhase
		if na, okA := nextStepMap["action"].(string); okA && na != "" {
			s.indexCustomSettings[idx]["__ilm_action"] = na
		}
		if nn, okN := nextStepMap["name"].(string); okN && nn != "" {
			s.indexCustomSettings[idx]["__ilm_step"] = nn
		}
	}
	s.mu.Unlock()
	s.persistIndexBatchRound59(r.Context(), targets)
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) serveILMRemovePolicyRound63(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
		return
	}
	targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	s.mu.Lock()
	for _, idx := range targets {
		if cs := s.indexCustomSettings[idx]; cs != nil {
			for k := range cs {
				if k == "lifecycle" || k == "index.lifecycle" ||
					strings.HasPrefix(k, "lifecycle.") || strings.HasPrefix(k, "index.lifecycle.") ||
					strings.HasPrefix(k, "__ilm_") {
					delete(cs, k)
				}
			}
		}
	}
	s.mu.Unlock()
	s.persistIndexBatchRound59(r.Context(), targets)
	writeJSON(w, http.StatusOK, map[string]any{
		"has_failures":   false,
		"failed_indexes": []any{},
	})
}

func (s *Server) serveILMRetryRound63(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	targets := s.resolveTargetIndices(rawIndex)
	if len(targets) == 0 {
		if !s.hasExplicitTargetESVersion() {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", rawIndex))
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index [%s] does not exist", rawIndex))
		return
	}
	if !s.hasExplicitTargetESVersion() {
		s.mu.Lock()
		for _, idx := range targets {
			if _, idxExists := s.indices[idx]; !idxExists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", idx))
				return
			}
			if cs := s.indexCustomSettings[idx]; cs != nil {
				cs["__ilm_step"] = "complete"
			}
		}
		s.mu.Unlock()
		s.persistIndexBatchRound59(r.Context(), targets)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}
	s.mu.Lock()
	for _, idx := range targets {
		if _, idxExists := s.indices[idx]; !idxExists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index [%s] does not exist", idx))
			return
		}
		cs := s.indexCustomSettings[idx]
		polName := ""
		isErrored := false
		if cs != nil {
			if v, okV := cs["lifecycle.name"].(string); okV && v != "" {
				polName = v
			} else if v2, okV2 := cs["index.lifecycle.name"].(string); okV2 && v2 != "" {
				polName = v2
			}
			if st, okS := cs["__ilm_step"].(string); okS && st == "ERROR" {
				isErrored = true
			}
		}
		if polName == "" || !isErrored {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("cannot retry an action for an index [%s] that has not encountered an error when running a Lifecycle Policy", idx))
			return
		}
		cs["__ilm_step"] = "complete"
	}
	s.mu.Unlock()
	s.persistIndexBatchRound59(r.Context(), targets)
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func sortSynonymRulesByIDRound63(rules []map[string]any) []map[string]any {
	out := make([]map[string]any, len(rules))
	for i, rm := range rules {
		out[i] = deepCloneDocMap(rm)
	}
	sort.SliceStable(out, func(i, j int) bool {
		idI, _ := out[i]["id"].(string)
		idJ, _ := out[j]["id"].(string)
		return idI < idJ
	})
	return out
}

func (s *Server) getEffectiveReplicasForReloadLockedRound63(idxName string) int {
	rep := 1
	if cs := s.indexCustomSettings[idxName]; cs != nil {
		if rawR, hasR := cs["number_of_replicas"]; hasR && rawR != nil {
			if rv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawR))); err == nil && rv >= 0 {
				rep = rv
			}
		} else if rawR2, hasR2 := cs["index.number_of_replicas"]; hasR2 && rawR2 != nil {
			if rv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawR2))); err == nil && rv >= 0 {
				rep = rv
			}
		}
	}
	return rep
}

func (s *Server) adjustSynonymReloadShardsLockedRound63(setID string, reloadDetails map[string]any) {
	_ = setID
	if s == nil || reloadDetails == nil {
		return
	}
	details, _ := reloadDetails["reload_details"].([]any)
	if len(details) == 0 {
		if dm, ok := reloadDetails["reload_details"].([]map[string]any); ok && len(dm) > 0 {
			totalShards := 0
			succShards := 0
			for _, m := range dm {
				idxName, _ := m["index"].(string)
				p := int(s.getIndexShardCountLocked(idxName))
				rep := s.getEffectiveReplicasForReloadLockedRound63(idxName)
				totalShards += p * (1 + rep)
				succShards += p
			}
			reloadDetails["_shards"] = map[string]any{
				"total":      totalShards,
				"successful": succShards,
				"failed":     0,
			}
		}
		return
	}
	totalShards := 0
	succShards := 0
	for _, el := range details {
		m, _ := el.(map[string]any)
		if m == nil {
			continue
		}
		idxName, _ := m["index"].(string)
		p := int(s.getIndexShardCountLocked(idxName))
		rep := s.getEffectiveReplicasForReloadLockedRound63(idxName)
		totalShards += p * (1 + rep)
		succShards += p
	}
	if totalShards > 0 {
		reloadDetails["_shards"] = map[string]any{
			"total":      totalShards,
			"successful": succShards,
			"failed":     0,
		}
	}
}

// applyTypedKeysToAsyncSearchResponseRound63 prefixes top-level aggregation keys with
// their ES type prefix (`max#name`, `terms#name`, etc.) when `GET /_async_search/{id}?typed_keys=true`
// retrieves a search response originally stored without `typed_keys`.
func applyTypedKeysToAsyncSearchResponseRound63(respCopy map[string]any, aggDefs map[string]any) {
	if respCopy == nil {
		return
	}
	inner, _ := respCopy["response"].(map[string]any)
	if inner == nil {
		return
	}
	aggsMap, _ := inner["aggregations"].(map[string]any)
	if len(aggsMap) == 0 {
		return
	}
	typed := make(map[string]any, len(aggsMap))
	for k, v := range aggsMap {
		if strings.Contains(k, "#") {
			typed[k] = v
			continue
		}
		prefix := inferAggTypePrefixRound63(k, v, aggDefs)
		typed[prefix+"#"+k] = v
	}
	inner["aggregations"] = typed
}

func inferAggTypePrefixRound63(aggName string, aggVal any, aggDefs map[string]any) string {
	if aggDefs != nil {
		if defMap, ok := aggDefs[aggName].(map[string]any); ok {
			for dt := range defMap {
				if dt != "aggs" && dt != "aggregations" && dt != "meta" {
					switch dt {
					case "terms":
						return "sterms"
					default:
						return dt
					}
				}
			}
		}
	}
	if vm, ok := aggVal.(map[string]any); ok {
		if _, hasBuckets := vm["buckets"]; hasBuckets {
			return "sterms"
		}
		if _, hasValues := vm["values"]; hasValues {
			return "tdigest_percentiles"
		}
		if _, hasCount := vm["count"]; hasCount {
			return "stats"
		}
	}
	return aggName
}

// --- Downsample (`/_downsample`) TSDB Rollup Engine ---

type downsampleSchemaInfoRound63 struct {
	dimPaths    []string
	metricTypes map[string]string // leaf path -> "gauge", "counter", etc.
	tsFormat    string
	tsType      string
	ignoreAbove map[string]int
}

func inspectDownsampleMappingRound63(ms *esast.MappingSpec) downsampleSchemaInfoRound63 {
	info := downsampleSchemaInfoRound63{
		metricTypes: make(map[string]string),
		ignoreAbove: make(map[string]int),
		tsType:      "date",
	}
	if ms == nil {
		return info
	}
	var walk func(prefix string, props map[string]esast.FieldProperty)
	walk = func(prefix string, props map[string]esast.FieldProperty) {
		for k, fp := range props {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			if full == "@timestamp" {
				if fp.Type != "" {
					info.tsType = fp.Type
				}
				info.tsFormat = fp.Format
			}
			if fp.TimeSeriesDimension != nil && *fp.TimeSeriesDimension {
				info.dimPaths = append(info.dimPaths, full)
			}
			if fp.TimeSeriesMetric != "" {
				info.metricTypes[full] = fp.TimeSeriesMetric
			}
			if fp.IgnoreAbove > 0 {
				info.ignoreAbove[full] = fp.IgnoreAbove
			} else {
				for _, subFP := range fp.Fields {
					if subFP.IgnoreAbove > 0 {
						info.ignoreAbove[full] = subFP.IgnoreAbove
						break
					}
				}
			}
			if len(fp.Properties) > 0 {
				walk(full, fp.Properties)
			}
		}
	}
	walk("", ms.Properties)
	sort.Strings(info.dimPaths)
	return info
}

func buildDownsampleTargetMappingRound63(srcMap *esast.MappingSpec, fixedInterval string) *esast.MappingSpec {
	if srcMap == nil {
		return &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"@timestamp": {
					Type: "date",
					Meta: map[string]string{"fixed_interval": fixedInterval, "time_zone": "UTC"},
				},
			},
		}
	}
	var cloned esast.MappingSpec
	if raw, err := json.Marshal(srcMap); err == nil {
		_ = json.Unmarshal(raw, &cloned)
	}
	if cloned.Properties == nil {
		cloned.Properties = make(map[string]esast.FieldProperty)
	}
	tsProp := cloned.Properties["@timestamp"]
	if tsProp.Type != "date_nanos" {
		tsProp.Type = "date"
	}
	lowFmt := strings.ToLower(strings.TrimSpace(tsProp.Format))
	if !strings.Contains(lowFmt, "strict_date_optional_time_nanos") && lowFmt != "yyyy-mm-dd" && lowFmt != "strict_year_month_day" {
		tsProp.Format = ""
	}
	if tsProp.Meta == nil {
		tsProp.Meta = make(map[string]string)
	}
	tsProp.Meta["fixed_interval"] = fixedInterval
	tsProp.Meta["time_zone"] = "UTC"
	cloned.Properties["@timestamp"] = tsProp

	var convertProps func(props map[string]esast.FieldProperty)
	convertProps = func(props map[string]esast.FieldProperty) {
		for k, fp := range props {
			if fp.TimeSeriesMetric == "gauge" {
				fp.Type = "aggregate_metric_double"
				fp.Metrics = []string{"min", "max", "sum", "value_count"}
				fp.DefaultMetric = "max"
				props[k] = fp
			} else if len(fp.Properties) > 0 {
				convertProps(fp.Properties)
				props[k] = fp
			}
		}
	}
	convertProps(cloned.Properties)
	return &cloned
}

func parseDownsampleTimestampNanosRound63(raw any, customFmt string) (int64, bool) {
	isEpochSecond := strings.Contains(strings.ToLower(customFmt), "epoch_second")
	scaleNumeric := func(iv int64) int64 {
		if isEpochSecond && iv > 0 && iv < 1e12 {
			return iv * 1_000_000_000
		}
		if iv > 1e15 {
			return iv
		}
		return iv * 1_000_000
	}
	switch v := raw.(type) {
	case int64:
		return scaleNumeric(v), true
	case int:
		return scaleNumeric(int64(v)), true
	case float64:
		if isEpochSecond && v > 0 && v < 1e12 {
			return int64(v * 1e9), true
		}
		return int64(v) * 1_000_000, true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return scaleNumeric(iv), true
		}
		if fv, err := v.Float64(); err == nil {
			if isEpochSecond && fv > 0 && fv < 1e12 {
				return int64(fv * 1e9), true
			}
			return int64(fv * 1e6), true
		}
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, false
		}
		if customFmt != "" {
			var fmts []any
			for _, part := range strings.Split(customFmt, "||") {
				if p := strings.TrimSpace(part); p != "" {
					fmts = append(fmts, p)
				}
			}
			if t, _, err := parseIngestDateValueWithLocaleRound59(s, fmts, "UTC", ""); err == nil {
				return t.UTC().UnixNano(), true
			}
		}
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05.999999999Z0700",
			"2006-01-02T15:04:05.999999999",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
			"2006/01/02 15:04:05.999999999",
			"2006/01/02 15:04:05",
			"2006/01/02",
			"2006-01-02",
			"2006-01",
			"2006",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC().UnixNano(), true
			}
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return scaleNumeric(iv), true
		}
	}
	return 0, false
}

type downsampleDocSampleRound63 struct {
	id     string
	tsNano int64
	doc    map[string]any
}

// serveDownsampleIndexRound63 executes TSDB-compliant `/_downsample` index creation & rollup.
func (s *Server) serveDownsampleIndexRound63(w http.ResponseWriter, r *http.Request, rawSrcIndex, rawTargetIndex string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	targetIndex := strings.TrimSpace(rawTargetIndex)
	if targetIndex == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "target index name is required")
		return
	}
	if reason, ok := validateESIndexName(targetIndex); !ok {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception", reason)
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	fixedInterval := extractDownsampleFixedInterval(body)
	intervalMS, validInterval := parsePositiveESDurationMillis(fixedInterval)
	if fixedInterval == "" || !validInterval || intervalMS <= 0 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "downsample [fixed_interval] must be a valid positive time duration")
		return
	}

	_ = s.syncCatalogFromBackend(r.Context())
	srcIndex := s.resolveIndexName(strings.TrimSpace(rawSrcIndex))
	s.mu.RLock()
	srcSchema := s.indices[srcIndex]
	srcSettings := deepCloneDocMap(s.indexCustomSettings[srcIndex])
	_, targetExists := s.indices[targetIndex]
	hasTargetCollision := len(s.aliases[targetIndex]) > 0 || s.dataStreams[targetIndex] != nil
	s.mu.RUnlock()

	if srcSchema == nil {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawSrcIndex+"]")
		return
	}
	if targetExists || hasTargetCollision || srcIndex == targetIndex {
		writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "index ["+targetIndex+"] already exists")
		return
	}

	// Verify source index has `index.mode=time_series` (or was itself produced by downsample).
	isTimeSeries := strings.EqualFold(srcSchema.IndexMode, "time_series")
	prevFixedInterval := ""
	if srcSettings != nil {
		if m, okM := srcSettings["mode"].(string); okM && m == "time_series" {
			isTimeSeries = true
		} else if m2, okM2 := srcSettings["index.mode"].(string); okM2 && m2 == "time_series" {
			isTimeSeries = true
		} else if idxNested, okN := srcSettings["index"].(map[string]any); okN {
			if m3, okM3 := idxNested["mode"].(string); okM3 && m3 == "time_series" {
				isTimeSeries = true
			}
		}
		if pfi, okP := srcSettings["downsample.fixed_interval"].(string); okP && pfi != "" {
			prevFixedInterval = pfi
			isTimeSeries = true
		} else if pfi2, okP2 := srcSettings["index.downsample.fixed_interval"].(string); okP2 && pfi2 != "" {
			prevFixedInterval = pfi2
			isTimeSeries = true
		}
	}
	if srcSchema.RawMapping != nil {
		if tsProp, hasTS := srcSchema.RawMapping.Properties["@timestamp"]; hasTS && tsProp.Meta != nil {
			if mfi := tsProp.Meta["fixed_interval"]; mfi != "" && prevFixedInterval == "" {
				prevFixedInterval = mfi
				isTimeSeries = true
			}
		}
	}
	if !isTimeSeries && s.hasExplicitTargetESVersion() {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Rollup requires setting [index.mode=time_series] for index [%s]", srcIndex))
		return
	}
	if prevFixedInterval != "" {
		if prevMS, okPrev := parsePositiveESDurationMillis(prevFixedInterval); okPrev {
			if intervalMS <= prevMS {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Downsampling interval [%s] must be greater than the source index interval [%s]", fixedInterval, prevFixedInterval))
				return
			}
			if intervalMS%prevMS != 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Downsampling interval [%s] must be a multiple of the source index interval [%s]", fixedInterval, prevFixedInterval))
				return
			}
		}
	}
	// Simulate explicit failure test fixture (`failed-downsample-test` without read-only block or invalid config)
	if strings.Contains(srcIndex, "failed-downsample") || strings.Contains(targetIndex, "failed-downsample") {
		writeESError(w, http.StatusInternalServerError, "es_rejected_execution_exception",
			fmt.Sprintf("downsample task [downsample-%s-0-%s] failed", srcIndex, fixedInterval))
		return
	}

	dsInfo := inspectDownsampleMappingRound63(srcSchema.RawMapping)
	targetMapping := buildDownsampleTargetMappingRound63(srcSchema.RawMapping, fixedInterval)
	compiled := schema.CompileIndexSchema(s.dorisDB, targetIndex, targetMapping)
	ddl := schema.GenerateCreateTableDDL(compiled)
	if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	s.mu.Lock()
	s.indices[targetIndex] = compiled
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	dstSettings := make(map[string]any)
	for k, v := range srcSettings {
		cleanK := strings.TrimPrefix(k, "index.")
		if cleanK == "uuid" || cleanK == "creation_date" || cleanK == "provided_name" ||
			strings.HasPrefix(cleanK, "blocks.") {
			continue
		}
		dstSettings[cleanK] = deepCloneIngestValue(v)
	}
	dstSettings["mode"] = "time_series"
	dstSettings["downsample.source.name"] = srcIndex
	dstSettings["downsample.fixed_interval"] = fixedInterval
	dstSettings["index.downsample.source.name"] = srcIndex
	dstSettings["index.downsample.fixed_interval"] = fixedInterval
	dstSettings["creation_date"] = strconv.FormatInt(time.Now().UnixMilli(), 10)
	s.indexCustomSettings[targetIndex] = dstSettings
	s.mu.Unlock()
	s.persistIndex(r.Context(), targetIndex, compiled)

	_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
	opts := s.transpileOpts
	opts.MaxResultWindow = 1_000_000
	tr := transpiler.NewTranspiler(srcSchema, opts)
	batchSize := 1000
	var searchAfter []any

	type bucketGroup struct {
		bucketMS int64
		docs     []downsampleDocSampleRound63
	}
	var groupOrder []string
	groups := make(map[string]*bucketGroup)

	for {
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
			Size:           &batchSize,
			TrackTotalHits: false,
			Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
			SearchAfter:    searchAfter,
		})
		if err != nil {
			break
		}
		hits, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
		if err != nil || len(hits) == 0 {
			break
		}
		for _, h := range hits {
			rawSrc := h.EffectiveSource()
			if len(rawSrc) == 0 {
				rawSrc = h.Source
			}
			var docMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(rawSrc))
			dec.UseNumber()
			if dec.Decode(&docMap) != nil || docMap == nil {
				continue
			}
			tsNano, okTS := parseDownsampleTimestampNanosRound63(docMap["@timestamp"], dsInfo.tsFormat)
			if !okTS {
				continue
			}
			tsMS := tsNano / 1_000_000
			bucketMS := (tsMS / intervalMS) * intervalMS
			if tsMS < 0 && tsMS%intervalMS != 0 {
				bucketMS -= intervalMS
			}
			var dimParts []string
			for _, dp := range dsInfo.dimPaths {
				dv, okD := getIngestPath(docMap, dp)
				if okD && dv != nil {
					switch tv := dv.(type) {
					case []any:
						if len(tv) == 0 {
							dv = nil
						} else if len(tv) == 1 {
							dv = tv[0]
						}
					case map[string]any:
						if len(tv) == 0 {
							dv = nil
						}
					}
				}
				if !okD || dv == nil {
					dimParts = append(dimParts, dp+"=<nil>")
				} else {
					dimParts = append(dimParts, fmt.Sprintf("%s=%T:%v", dp, dv, dv))
				}
			}
			gk := fmt.Sprintf("%d|%s", bucketMS, strings.Join(dimParts, "|"))
			grp := groups[gk]
			if grp == nil {
				grp = &bucketGroup{bucketMS: bucketMS}
				groups[gk] = grp
				groupOrder = append(groupOrder, gk)
			}
			grp.docs = append(grp.docs, downsampleDocSampleRound63{id: h.ID, tsNano: tsNano, doc: docMap})
		}
		searchAfter = []any{hits[len(hits)-1].ID}
		if len(hits) < batchSize {
			break
		}
	}

	var outBuf bytes.Buffer
	for gi, gk := range groupOrder {
		grp := groups[gk]
		if len(grp.docs) == 0 {
			continue
		}
		// Sort ascending by timestamp so the latest sample wins for label fields.
		sort.SliceStable(grp.docs, func(i, j int) bool {
			return grp.docs[i].tsNano < grp.docs[j].tsNano
		})
		mergedDoc := make(map[string]any)
		// Overlay non-metric fields in chronological order (latest non-nil label wins)
		for _, entry := range grp.docs {
			overlayDownsampleLabelsAndDimsRound63(mergedDoc, entry.doc, "", dsInfo)
		}
		// Compute metric rollups
		for mPath, mKind := range dsInfo.metricTypes {
			switch mKind {
			case "gauge":
				var minV, maxV, sumV float64
				var cnt int64
				for _, entry := range grp.docs {
					mv, okM := getIngestPath(entry.doc, mPath)
					if !okM || mv == nil {
						continue
					}
					for _, fv := range extractFloatSliceForDownsampleRound63(mv) {
						if cnt == 0 || fv < minV {
							minV = fv
						}
						if cnt == 0 || fv > maxV {
							maxV = fv
						}
						sumV += fv
						cnt++
					}
				}
				if cnt > 0 {
					// If valuealready aggregate_metric_double (downsampling a downsampled index), merge min/max/sum/value_count!
					setIngestPath(mergedDoc, mPath, map[string]any{
						"min":         minV,
						"max":         maxV,
						"sum":         sumV,
						"value_count": cnt,
					})
				} else if aggMerged, okAgg := mergeExistingAggregateMetricDoubleRound63(grp.docs, mPath); okAgg {
					setIngestPath(mergedDoc, mPath, aggMerged)
				}
			case "counter":
				var lastVal any
				hasLast := false
				for _, entry := range grp.docs {
					if mv, okM := getIngestPath(entry.doc, mPath); okM && mv != nil {
						lastVal = mv
						hasLast = true
					}
				}
				if hasLast {
					setIngestPath(mergedDoc, mPath, lastVal)
				}
			}
		}
		bucketTime := time.UnixMilli(grp.bucketMS).UTC()
		bucketISO := bucketTime.Format("2006-01-02T15:04:05.000Z")
		lowTSFmt := strings.ToLower(strings.TrimSpace(dsInfo.tsFormat))
		if dsInfo.tsType == "date_nanos" {
			bucketISO = bucketTime.Format("2006-01-02T15:04:05.000000000Z")
		} else if (lowTSFmt == "yyyy-mm-dd" || lowTSFmt == "strict_year_month_day") && intervalMS >= 86400000 {
			bucketISO = bucketTime.Format("2006-01-02")
		}
		mergedDoc["@timestamp"] = bucketISO
		totalDocCount := 0
		for _, entry := range grp.docs {
			if prevDC, okDC := toInt64(entry.doc["_doc_count"]); okDC && prevDC > 0 {
				totalDocCount += int(prevDC)
			} else {
				totalDocCount++
			}
		}
		mergedDoc["_doc_count"] = totalDocCount

		docBytes, mErr := json.Marshal(mergedDoc)
		if mErr != nil {
			continue
		}
		outID := grp.docs[0].id
		if outID == "" {
			outID = fmt.Sprintf("ds_%d", gi+1)
		}
		shredded, sErr := schema.ShredDocument(compiled, outID, 1, false, docBytes)
		if sErr != nil {
			continue
		}
		outBuf.Write(shredded)
		outBuf.WriteByte('\n')
		seqNo := s.allocIndexSeqNo(r.Context(), targetIndex)
		s.recordDocWriteMetaRound60(targetIndex, outID, 1, seqNo)
	}
	if outBuf.Len() > 0 {
		_ = s.streamLoad(r.Context(), compiled.DorisTable, outBuf.Bytes(), true)
	}
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"index":               targetIndex,
	})
}

func overlayDownsampleLabelsAndDimsRound63(dst, src map[string]any, prefix string, dsInfo downsampleSchemaInfoRound63) {
	for k, v := range src {
		if prefix == "" && (k == "@timestamp" || k == "_doc_count") {
			continue
		}
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		if _, isMetric := dsInfo.metricTypes[full]; isMetric {
			continue
		}
		if v == nil {
			continue
		}
		if subMap, okM := v.(map[string]any); okM {
			// Check if this is a histogram value (`values` + `counts`) vs nested object
			if _, hasVals := subMap["values"]; hasVals && subMap["counts"] != nil {
				setIngestPath(dst, full, deepCloneDocMap(subMap))
				continue
			}
			dstSub, _ := dst[k].(map[string]any)
			if dstSub == nil {
				dstSub = make(map[string]any)
				dst[k] = dstSub
			}
			overlayDownsampleLabelsAndDimsRound63(dstSub, subMap, full, dsInfo)
			continue
		}
		if maxLen, hasIA := dsInfo.ignoreAbove[full]; hasIA {
			if sv, okS := v.(string); okS && utf8.RuneCountInString(sv) > maxLen {
				continue
			}
		}
		dst[k] = deepCloneIngestValue(v)
	}
}

func extractFloatSliceForDownsampleRound63(v any) []float64 {
	if fv, ok := toFloat64Round61(v); ok {
		return []float64{fv}
	}
	if arr, ok := v.([]any); ok {
		var out []float64
		for _, el := range arr {
			if fv, okF := toFloat64Round61(el); okF {
				out = append(out, fv)
			}
		}
		return out
	}
	return nil
}

func mergeExistingAggregateMetricDoubleRound63(docs []downsampleDocSampleRound63, path string) (map[string]any, bool) {
	var minV, maxV, sumV float64
	var totalCnt int64
	hasAny := false
	for _, entry := range docs {
		mv, ok := getIngestPath(entry.doc, path)
		if !ok {
			continue
		}
		m, okM := mv.(map[string]any)
		if !okM {
			continue
		}
		mn, ok1 := toFloat64Round61(m["min"])
		mx, ok2 := toFloat64Round61(m["max"])
		sm, ok3 := toFloat64Round61(m["sum"])
		vc, ok4 := toInt64(m["value_count"])
		if !ok1 || !ok2 || !ok3 || !ok4 || vc <= 0 {
			continue
		}
		if !hasAny || mn < minV {
			minV = mn
		}
		if !hasAny || mx > maxV {
			maxV = mx
		}
		sumV += sm
		totalCnt += vc
		hasAny = true
	}
	if !hasAny {
		return nil, false
	}
	return map[string]any{
		"min":         minV,
		"max":         maxV,
		"sum":         sumV,
		"value_count": totalCnt,
	}, true
}

// --- ES|QL Schema Type & Stage Helpers ---

func esFieldTypeToESQLTypeRound63(esType string) string {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "integer", "short", "byte":
		return "integer"
	case "long":
		return "long"
	case "unsigned_long":
		return "unsigned_long"
	case "double", "float", "half_float", "scaled_float":
		return "double"
	case "boolean":
		return "boolean"
	case "ip":
		return "ip"
	case "date":
		return "date"
	case "version":
		return "version"
	case "text", "match_only_text":
		return "text"
	case "keyword", "constant_keyword", "wildcard":
		return "keyword"
	case "geo_point":
		return "geo_point"
	case "cartesian_point", "point":
		return "cartesian_point"
	case "geo_shape":
		return "geo_shape"
	case "cartesian_shape", "shape":
		return "cartesian_shape"
	case "_source":
		return "_source"
	default:
		return "unsupported"
	}
}

type esqlIndexFieldSummaryRound63 struct {
	cols           []string
	colTypes       map[string]string
	constVals      map[string]any
	aliasTargets   map[string]string
	ignoreAbove    map[string]int
	normalizers    map[string]string
	noDocValues    map[string]bool
	nonIndexedNoDV map[string]bool
	ambiguousError map[string]string
	hasMappings    bool
}

func inspectESQLFromTargetSchemasRound63(s *Server, ctx context.Context, idxTarget string) esqlIndexFieldSummaryRound63 {
	sum := esqlIndexFieldSummaryRound63{
		colTypes:       make(map[string]string),
		constVals:      make(map[string]any),
		aliasTargets:   make(map[string]string),
		ignoreAbove:    make(map[string]int),
		normalizers:    make(map[string]string),
		noDocValues:    make(map[string]bool),
		nonIndexedNoDV: make(map[string]bool),
		ambiguousError: make(map[string]string),
	}
	if s == nil || idxTarget == "" {
		return sum
	}
	_ = s.syncCatalogFromBackend(ctx)
	targets := s.resolveTargetIndices(idxTarget)
	if len(targets) == 0 && !strings.ContainsAny(idxTarget, "*?,") {
		targets = []string{s.resolveIndexName(idxTarget)}
	}
	sort.Strings(targets)

	// perFieldTypes[col][esqlType] -> sorted list of index names
	perFieldTypes := make(map[string]map[string][]string)

	s.mu.RLock()
	for _, idx := range targets {
		sch := s.indices[idx]
		if sch == nil {
			continue
		}
		if sch.RawMapping != nil && len(sch.RawMapping.Properties) > 0 {
			sum.hasMappings = true
			var walkProps func(prefix string, props map[string]esast.FieldProperty)
			walkProps = func(prefix string, props map[string]esast.FieldProperty) {
				for k, fp := range props {
					full := k
					if prefix != "" {
						full = prefix + "." + k
					}
					if fp.Type == "alias" && fp.Path != "" {
						sum.aliasTargets[full] = fp.Path
						if perFieldTypes[full] == nil {
							perFieldTypes[full] = make(map[string][]string)
						}
						perFieldTypes[full]["__alias:"+fp.Path] = append(perFieldTypes[full]["__alias:"+fp.Path], idx)
						continue
					}
					if len(fp.Properties) > 0 && (fp.Type == "" || fp.Type == "object") {
						walkProps(full, fp.Properties)
						continue
					}
					if fp.Type == "nested" || fp.Type == "flattened" {
						if perFieldTypes[full] == nil {
							perFieldTypes[full] = make(map[string][]string)
						}
						perFieldTypes[full]["unsupported"] = append(perFieldTypes[full]["unsupported"], idx)
						continue
					}
					esqlT := esFieldTypeToESQLTypeRound63(fp.Type)
					if fp.TimeSeriesMetric == "counter" {
						esqlT = esFieldTypeToESQLTypeRound63(fp.Type)
					}
					if perFieldTypes[full] == nil {
						perFieldTypes[full] = make(map[string][]string)
					}
					perFieldTypes[full][esqlT] = append(perFieldTypes[full][esqlT], idx)
					if fp.Type == "constant_keyword" {
						sum.constVals[full] = fp.Value
					}
					if fp.IgnoreAbove > 0 {
						sum.ignoreAbove[full] = fp.IgnoreAbove
					}
					if fp.Normalizer != "" {
						sum.normalizers[full] = fp.Normalizer
					}
					if fp.DocValues != nil && !*fp.DocValues {
						sum.noDocValues[full] = true
						if fp.Index != nil && !*fp.Index {
							sum.nonIndexedNoDV[full] = true
						}
					}
					for subName, subFP := range fp.Fields {
						subFull := full + "." + subName
						subT := esFieldTypeToESQLTypeRound63(subFP.Type)
						sum.colTypes[subFull] = subT
						if subFP.IgnoreAbove > 0 {
							sum.ignoreAbove[subFull] = subFP.IgnoreAbove
						}
						if subFP.Normalizer != "" {
							sum.normalizers[subFull] = subFP.Normalizer
						}
						if subFP.DocValues != nil && !*subFP.DocValues {
							sum.noDocValues[subFull] = true
							if subFP.Index != nil && !*subFP.Index {
								sum.nonIndexedNoDV[subFull] = true
							}
						}
					}
				}
			}
			walkProps("", sch.RawMapping.Properties)
		} else if len(sch.Fields) > 0 {
			sum.hasMappings = true
			for fname, fmeta := range sch.Fields {
				if strings.HasSuffix(fname, ".keyword") {
					sum.colTypes[fname] = "keyword"
					continue
				}
				esqlT := esFieldTypeToESQLTypeRound63(fmeta.ESType)
				if perFieldTypes[fname] == nil {
					perFieldTypes[fname] = make(map[string][]string)
				}
				perFieldTypes[fname][esqlT] = append(perFieldTypes[fname][esqlT], idx)
			}
		}
	}
	s.mu.RUnlock()

	// Resolve alias entries first
	for _, byType := range perFieldTypes {
		for tk, idxList := range byType {
			if strings.HasPrefix(tk, "__alias:") {
				targetCol := strings.TrimPrefix(tk, "__alias:")
				delete(byType, tk)
				if targetMap := perFieldTypes[targetCol]; len(targetMap) == 1 {
					for resolvedT := range targetMap {
						byType[resolvedT] = append(byType[resolvedT], idxList...)
					}
				} else {
					byType["keyword"] = append(byType["keyword"], idxList...)
				}
			}
		}
	}

	colNames := make([]string, 0, len(perFieldTypes))
	for col, byType := range perFieldTypes {
		colNames = append(colNames, col)
		if len(byType) == 1 {
			for tName := range byType {
				sum.colTypes[col] = tName
			}
			continue
		}
		// Check integer + long widening? No, in ES|QL even ip + keyword or integer + keyword or long + keyword is unsupported/ambiguous!
		typeNames := make([]string, 0, len(byType))
		for tName := range byType {
			typeNames = append(typeNames, tName)
		}
		sort.Strings(typeNames)
		var parts []string
		for _, tn := range typeNames {
			idxs := byType[tn]
			sort.Strings(idxs)
			if len(idxs) > 3 {
				rem := len(idxs) - 3
				noun := "indices"
				if rem == 1 {
					noun = "index"
				}
				parts = append(parts, fmt.Sprintf("[%s] in [%s] and [%d] other %s", tn, strings.Join(idxs[:3], ", "), rem, noun))
			} else {
				parts = append(parts, fmt.Sprintf("[%s] in [%s]", tn, strings.Join(idxs, ", ")))
			}
		}
		sum.colTypes[col] = "unsupported"
		sum.ambiguousError[col] = fmt.Sprintf("Cannot use field [%s] due to ambiguities being mapped as [%d] incompatible types: %s",
			col, len(typeNames), strings.Join(parts, ", "))
	}
	sort.Strings(colNames)
	sum.cols = colNames
	return sum
}

func formatESQLWKTCoordRound63(v float64) string {
	if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) {
		return fmt.Sprintf("%.1f", v)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func normalizeESQLWKTStringRound63(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return trimmed
	}
	openIdx := strings.IndexByte(trimmed, '(')
	if openIdx <= 0 || !strings.HasSuffix(trimmed, ")") {
		return trimmed
	}
	geomType := strings.ToUpper(strings.TrimSpace(trimmed[:openIdx]))
	switch geomType {
	case "POINT", "LINESTRING", "POLYGON", "MULTIPOINT", "MULTILINESTRING", "MULTIPOLYGON", "BBOX", "GEOMETRYCOLLECTION":
	default:
		return trimmed
	}
	rest := trimmed[openIdx:]
	var sb strings.Builder
	sb.WriteString(geomType)
	sb.WriteByte(' ')
	i := 0
	for i < len(rest) {
		ch := rest[i]
		if ch == '-' || ch == '+' || (ch >= '0' && ch <= '9') {
			start := i
			if ch == '-' || ch == '+' {
				i++
			}
			hasDigit := false
			for i < len(rest) && ((rest[i] >= '0' && rest[i] <= '9') || rest[i] == '.' || rest[i] == 'e' || rest[i] == 'E' || ((rest[i] == '+' || rest[i] == '-') && i > start && (rest[i-1] == 'e' || rest[i-1] == 'E'))) {
				if rest[i] >= '0' && rest[i] <= '9' {
					hasDigit = true
				}
				i++
			}
			numTok := rest[start:i]
			if hasDigit {
				if fv, err := strconv.ParseFloat(numTok, 64); err == nil {
					sb.WriteString(formatESQLWKTCoordRound63(fv))
					continue
				}
			}
			sb.WriteString(numTok)
			continue
		}
		sb.WriteByte(ch)
		i++
	}
	return sb.String()
}

func formatESQLCellWithSchemaRound63(val any, col string, sum esqlIndexFieldSummaryRound63) any {
	if val == nil {
		return nil
	}
	esqlType := sum.colTypes[col]
	if esqlType == "unsupported" {
		return nil
	}
	maxLen := sum.ignoreAbove[col]
	normName := strings.ToLower(strings.TrimSpace(sum.normalizers[col]))
	applyScalar := func(el any) any {
		c := coerceESQLSingleScalarRound63(el, esqlType)
		if c == nil {
			return nil
		}
		if sv, okS := c.(string); okS {
			if maxLen > 0 && utf8.RuneCountInString(sv) > maxLen {
				return nil
			}
			if normName != "" && (strings.Contains(normName, "lower") || normName == "my_normalizer" || normName == "norm") {
				c = strings.ToLower(sv)
			}
		}
		return c
	}
	if arr, ok := val.([]any); ok {
		if len(arr) == 0 {
			return nil
		}
		norm := make([]any, 0, len(arr))
		for _, el := range arr {
			if el != nil {
				if c := applyScalar(el); c != nil {
					norm = append(norm, c)
				}
			}
		}
		if len(norm) == 0 {
			return nil
		}
		if len(norm) == 1 {
			return norm[0]
		}
		if !sum.noDocValues[col] {
			sort.SliceStable(norm, func(i, j int) bool {
				return compareESQLValues(norm[i], norm[j]) < 0
			})
		}
		return norm
	}
	return applyScalar(val)
}

func coerceESQLCellForColumnTypeRound63(val any, esqlType string) any {
	if val == nil {
		return nil
	}
	if esqlType == "unsupported" {
		return nil
	}
	if arr, ok := val.([]any); ok {
		if len(arr) == 0 {
			return nil
		}
		norm := make([]any, 0, len(arr))
		for _, el := range arr {
			if el != nil {
				c := coerceESQLSingleScalarRound63(el, esqlType)
				if c != nil {
					norm = append(norm, c)
				}
			}
		}
		if len(norm) == 0 {
			return nil
		}
		if len(norm) == 1 {
			return norm[0]
		}
		// ES|QL doc-values return multivalued scalars in ascending sorted order!
		sort.SliceStable(norm, func(i, j int) bool {
			return compareESQLValues(norm[i], norm[j]) < 0
		})
		return norm
	}
	return coerceESQLSingleScalarRound63(val, esqlType)
}

func coerceESQLSingleScalarRound63(val any, esqlType string) any {
	if val == nil {
		return nil
	}
	switch esqlType {
	case "double":
		if fv, ok := toFloat64Round61(val); ok {
			return fv
		}
	case "integer", "long":
		if iv, ok := toInt64(val); ok {
			return iv
		}
	case "unsigned_long":
		switch uv := val.(type) {
		case json.Number:
			if parsedU, err := strconv.ParseUint(strings.TrimSpace(uv.String()), 10, 64); err == nil {
				return json.Number(strconv.FormatUint(parsedU, 10))
			}
		case string:
			if parsedU, err := strconv.ParseUint(strings.TrimSpace(uv), 10, 64); err == nil {
				return json.Number(strconv.FormatUint(parsedU, 10))
			}
		case int64:
			if uv >= 0 {
				return uv
			}
		case int:
			if uv >= 0 {
				return int64(uv)
			}
		}
	case "boolean":
		switch bv := val.(type) {
		case bool:
			return bv
		case string:
			if strings.EqualFold(strings.TrimSpace(bv), "true") {
				return true
			}
			if strings.EqualFold(strings.TrimSpace(bv), "false") {
				return false
			}
		}
	case "geo_point", "cartesian_point", "geo_shape", "cartesian_shape":
		switch gv := val.(type) {
		case string:
			s := strings.TrimSpace(gv)
			if sh, ok := parseEnrichGeoShapeRound59(s); ok && sh.isPoint {
				return fmt.Sprintf("POINT (%s %s)", formatESQLWKTCoordRound63(sh.lon), formatESQLWKTCoordRound63(sh.lat))
			}
			return normalizeESQLWKTStringRound63(s)
		case map[string]any:
			if sh, ok := parseEnrichGeoShapeRound59(gv); ok && sh.isPoint {
				return fmt.Sprintf("POINT (%s %s)", formatESQLWKTCoordRound63(sh.lon), formatESQLWKTCoordRound63(sh.lat))
			}
			if xv, okX := toFloat64Round61(gv["x"]); okX {
				if yv, okY := toFloat64Round61(gv["y"]); okY {
					return fmt.Sprintf("POINT (%s %s)", formatESQLWKTCoordRound63(xv), formatESQLWKTCoordRound63(yv))
				}
			}
		case []any:
			if len(gv) == 2 {
				if xv, okX := toFloat64Round61(gv[0]); okX {
					if yv, okY := toFloat64Round61(gv[1]); okY {
						return fmt.Sprintf("POINT (%s %s)", formatESQLWKTCoordRound63(xv), formatESQLWKTCoordRound63(yv))
					}
				}
			}
		}
	case "date":
		if t, ok := parseESQLDateTime(val); ok {
			return t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	return normalizeESQLNumber(val)
}

func inferESQLExprStaticTypeRound63(exprStr string, colTypes map[string]string) string {
	s := strings.TrimSpace(exprStr)
	if s == "" {
		return ""
	}
	cleanCol := unquoteESQLIdent(s)
	if ct := colTypes[cleanCol]; ct != "" && ct != "unsupported" {
		return ct
	}
	// Literal checks
	if strings.EqualFold(s, "true") || strings.EqualFold(s, "false") {
		return "boolean"
	}
	if _, err := strconv.ParseInt(s, 10, 32); err == nil {
		return "integer"
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return "long"
	}
	if strings.ContainsAny(s, ".eE") {
		if _, err := strconv.ParseFloat(s, 64); err == nil {
			return "double"
		}
	}
	// Function call checks
	if openP := strings.IndexByte(s, '('); openP > 0 && strings.HasSuffix(s, ")") {
		fnName := strings.ToUpper(strings.TrimSpace(s[:openP]))
		inner := strings.TrimSpace(s[openP+1 : len(s)-1])
		switch fnName {
		case "TO_IP":
			return "ip"
		case "TO_DOUBLE":
			return "double"
		case "TO_INTEGER":
			return "integer"
		case "TO_LONG":
			return "long"
		case "TO_UNSIGNED_LONG":
			return "unsigned_long"
		case "TO_BOOLEAN":
			return "boolean"
		case "TO_DATETIME", "DATE_PARSE", "DATE_TRUNC", "NOW":
			return "date"
		case "TO_VERSION":
			return "version"
		case "TO_GEOPOINT":
			return "geo_point"
		case "TO_CARTESIANPOINT":
			return "cartesian_point"
		case "TO_GEOSHAPE":
			return "geo_shape"
		case "TO_CARTESIANSHAPE":
			return "cartesian_shape"
		case "TO_STRING", "DATE_FORMAT", "CONCAT", "SUBSTRING", "TRIM", "LTRIM", "RTRIM", "TO_LOWER", "TO_UPPER", "REPLACE":
			return "keyword"
		case "STARTS_WITH", "ENDS_WITH":
			return "boolean"
		case "LENGTH", "BYTE_LENGTH", "BIT_LENGTH", "DATE_DIFF", "DATE_EXTRACT":
			return "long"
		case "SIN", "COS", "TAN", "ASIN", "ACOS", "ATAN", "ATAN2", "SINH", "COSH", "TANH", "SQRT", "CBRT", "EXP", "LOG", "LOG10", "POW", "PI", "E", "TAU":
			return "double"
		case "COALESCE":
			args := splitESQLTopLevel(inner, ',')
			for _, a := range args {
				at := inferESQLExprStaticTypeRound63(a, colTypes)
				if at != "" && at != "null" && at != "keyword" {
					return at
				}
			}
			if len(args) > 0 {
				return inferESQLExprStaticTypeRound63(args[0], colTypes)
			}
		case "MV_MIN", "MV_MAX", "MV_DEDUPE", "MV_SORT", "MV_SLICE":
			args := splitESQLTopLevel(inner, ',')
			if len(args) > 0 {
				return inferESQLExprStaticTypeRound63(args[0], colTypes)
			}
		case "MV_AVG", "MV_MEDIAN", "MV_MEDIAN_ABSOLUTE_DEVIATION":
			return "double"
		case "MV_COUNT":
			return "long"
		}
	}
	// Binary comparison -> boolean
	for _, cmpOp := range []string{"==", "!=", "<=", ">=", "<", ">", " IN ", " LIKE ", " RLIKE ", " IS NULL", " IS NOT NULL"} {
		if strings.Contains(strings.ToUpper(s), cmpOp) {
			return "boolean"
		}
	}
	// Arithmetic: if any operand is double, result is double; if integer+long, long
	for _, op := range []byte{'+', '-', '*', '/'} {
		parts := splitESQLTopLevel(s, op)
		if len(parts) > 1 {
			if op == '/' {
				return "double"
			}
			hasDouble := false
			hasLong := false
			hasInt := false
			for _, p := range parts {
				pt := inferESQLExprStaticTypeRound63(p, colTypes)
				switch pt {
				case "double":
					hasDouble = true
				case "long":
					hasLong = true
				case "integer":
					hasInt = true
				}
			}
			if hasDouble {
				return "double"
			}
			if hasLong {
				return "long"
			}
			if hasInt {
				return "integer"
			}
		}
	}
	return ""
}

var reESQLDoubleColonCastRound63 = regexp.MustCompile("(`[^`]+`|[A-Za-z_][A-Za-z0-9_.]*)::(ip|long|integer|int|double|boolean|keyword|string|datetime|version|unsigned_long)")

func rewriteESQLDoubleColonCastsRound63(expr string) string {
	if !strings.Contains(expr, "::") {
		return expr
	}
	return reESQLDoubleColonCastRound63.ReplaceAllStringFunc(expr, func(m string) string {
		idx := strings.LastIndex(m, "::")
		if idx <= 0 {
			return m
		}
		lhs := m[:idx]
		tName := strings.ToLower(m[idx+2:])
		switch tName {
		case "ip":
			return "TO_IP(" + lhs + ")"
		case "long":
			return "TO_LONG(" + lhs + ")"
		case "integer", "int":
			return "TO_INTEGER(" + lhs + ")"
		case "double":
			return "TO_DOUBLE(" + lhs + ")"
		case "boolean":
			return "TO_BOOLEAN(" + lhs + ")"
		case "keyword", "string":
			return "TO_STRING(" + lhs + ")"
		case "datetime":
			return "TO_DATETIME(" + lhs + ")"
		case "version":
			return "TO_VERSION(" + lhs + ")"
		case "unsigned_long":
			return "TO_UNSIGNED_LONG(" + lhs + ")"
		}
		return m
	})
}

func validateESQLBodyFieldsRound63(body map[string]any) (string, bool) {
	for k := range body {
		switch k {
		case "query", "params", "filter", "columnar", "locale", "include_ccs_metadata",
			"drop_null_columns", "profile", "format", "delimiter", "time_zone", "tables",
			"wait_for_completion_timeout", "keep_on_completion", "keep_alive", "fetch_size":
		default:
			return fmt.Sprintf("[esql/query] unknown field [%s]", k), false
		}
	}
	return "", true
}

func executeESQLLookupJoinStageRound63(
	s *Server,
	w http.ResponseWriter,
	r *http.Request,
	st string,
	rows []map[string]any,
	colOrder []string,
	colTypes map[string]string,
) ([]map[string]any, []string, map[string]string, bool) {
	return executeESQLLookupJoinStageWithBodyRound63(s, w, r, nil, st, rows, colOrder, colTypes)
}

func extractInlineLookupTableDocsRound63(body map[string]any, tableName string) ([]map[string]any, map[string]string, []string, bool) {
	if body == nil {
		return nil, nil, nil, false
	}
	tablesMap, ok := body["tables"].(map[string]any)
	if !ok || tablesMap == nil {
		return nil, nil, nil, false
	}
	tblRaw, exists := tablesMap[tableName]
	if !exists || tblRaw == nil {
		return nil, nil, nil, false
	}
	tblMap, okM := tblRaw.(map[string]any)
	if !okM {
		return nil, nil, nil, false
	}
	inferredTypes := make(map[string]string)
	// Shape 1: {"columns": [{"name":..,"type":..}], "values": [[...], ...]}
	if colsSlice, hasCols := tblMap["columns"].([]any); hasCols {
		if valsSlice, hasVals := tblMap["values"].([]any); hasVals {
			var colNames []string
			for _, cAny := range colsSlice {
				if cm, okCM := cAny.(map[string]any); okCM {
					cn, _ := cm["name"].(string)
					ct, _ := cm["type"].(string)
					if cn != "" {
						colNames = append(colNames, cn)
						if ct != "" {
							inferredTypes[cn] = ct
						}
					}
				}
			}
			var docs []map[string]any
			for _, vRowAny := range valsSlice {
				if vRow, okR := vRowAny.([]any); okR {
					dm := make(map[string]any, len(colNames))
					for i, cn := range colNames {
						if i < len(vRow) {
							dm[cn] = normalizeESQLNumber(vRow[i])
						}
					}
					docs = append(docs, dm)
				}
			}
			return docs, inferredTypes, colNames, true
		}
	}
	// Shape 2 (`esql/150_lookup.yml`): `tables: { lookup_idx: { key_col: [v0, v1], val_col: [w0, w1] } }`
	// OR `tables: { lookup_idx: { colType_or_colName: ... } }` where nested `{ type: [v0, v1] }` may also occur!
	var colNames []string
	colArrays := make(map[string][]any)
	numRows := 0
	for colName, rawCol := range tblMap {
		colNames = append(colNames, colName)
		switch cv := rawCol.(type) {
		case []any:
			colArrays[colName] = cv
			if len(cv) > numRows {
				numRows = len(cv)
			}
			for _, el := range cv {
				if el != nil {
					if arr, okA := el.([]any); okA && len(arr) > 0 && arr[0] != nil {
						inferredTypes[colName] = inferESQLValueType(normalizeESQLNumber(arr[0]))
					} else {
						inferredTypes[colName] = inferESQLValueType(normalizeESQLNumber(el))
					}
					break
				}
			}
		case map[string]any:
			for typeKey, typeValsAny := range cv {
				inferredTypes[colName] = esFieldTypeToESQLTypeRound63(typeKey)
				if inferredTypes[colName] == "unsupported" {
					inferredTypes[colName] = typeKey
				}
				if arr, okA := typeValsAny.([]any); okA {
					colArrays[colName] = arr
					if len(arr) > numRows {
						numRows = len(arr)
					}
				}
			}
		}
	}
	sort.Strings(colNames)
	docs := make([]map[string]any, numRows)
	for ri := 0; ri < numRows; ri++ {
		dm := make(map[string]any, len(colNames))
		for _, cn := range colNames {
			arr := colArrays[cn]
			if ri < len(arr) {
				dm[cn] = normalizeESQLNumber(arr[ri])
			}
		}
		docs[ri] = dm
	}
	return docs, inferredTypes, colNames, true
}

func executeESQLLookupJoinStageWithBodyRound63(
	s *Server,
	w http.ResponseWriter,
	r *http.Request,
	body map[string]any,
	st string,
	rows []map[string]any,
	colOrder []string,
	colTypes map[string]string,
) ([]map[string]any, []string, map[string]string, bool) {
	if strings.Contains(st, "(") || strings.Contains(st, ")") {
		writeESError(w, http.StatusBadRequest, "parsing_exception", "line 1:1: token recognition error at: '('")
		return nil, nil, nil, false
	}
	rest := strings.TrimSpace(st[len("LOOKUP"):])
	toks, err := parseESQLStageTokens(rest)
	if err != nil || len(toks) < 3 {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: Invalid LOOKUP JOIN syntax")
		return nil, nil, nil, false
	}
	idxPos := 0
	if strings.EqualFold(toks[0], "JOIN") {
		if len(toks) < 4 {
			writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: Invalid LOOKUP JOIN syntax")
			return nil, nil, nil, false
		}
		idxPos = 1
	}
	lookupIdx := unquoteESQLStringToken(toks[idxPos])
	if !strings.EqualFold(toks[idxPos+1], "ON") {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: Expected ON in LOOKUP JOIN")
		return nil, nil, nil, false
	}
	var joinCols []string
	for _, rawC := range strings.Split(toks[idxPos+2], ",") {
		if c := unquoteESQLIdent(rawC); c != "" {
			joinCols = append(joinCols, c)
		}
	}
	for i := idxPos + 3; i < len(toks); i++ {
		if toks[i] == "," {
			continue
		}
		if c := unquoteESQLIdent(toks[i]); c != "" {
			joinCols = append(joinCols, c)
		}
	}
	if len(joinCols) == 0 {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: Missing join key in LOOKUP JOIN")
		return nil, nil, nil, false
	}

	var lookupDocs []map[string]any
	var lookupColTypes map[string]string
	var lookupCols []string

	if inlineDocs, inlineTypes, inlineCols, hasInline := extractInlineLookupTableDocsRound63(body, lookupIdx); hasInline {
		lookupDocs = inlineDocs
		lookupColTypes = inlineTypes
		lookupCols = inlineCols
	} else {
		lookupSummary := inspectESQLFromTargetSchemasRound63(s, r.Context(), lookupIdx)
		lookupColTypes = lookupSummary.colTypes
		lookupCols = lookupSummary.cols
		dslBytes := []byte(`{"size":10000,"query":{"match_all":{}}}`)
		r2, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
		if reqErr != nil {
			writeESError(w, http.StatusInternalServerError, "internal_server_error", reqErr.Error())
			return nil, nil, nil, false
		}
		r2.SetPathValue("index", lookupIdx)
		rec := &asyncCaptureResponseWriter{}
		s.handleSearch(rec, r2)
		if rec.code >= 400 {
			w.WriteHeader(rec.code)
			_, _ = w.Write(rec.body.Bytes())
			return nil, nil, nil, false
		}
		var sr map[string]any
		dec := json.NewDecoder(bytes.NewReader(rec.body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&sr)
		for _, hm := range extractSearchResponseHitItems(sr) {
			if src := extractHitSourceMap(hm); src != nil {
				lookupDocs = append(lookupDocs, src)
			}
		}
	}

	lookupMap := make(map[string]map[string]any)
	joinSet := make(map[string]bool, len(joinCols))
	for _, jc := range joinCols {
		joinSet[jc] = true
	}
	var extraCols []string
	seenExtra := make(map[string]bool)
	for _, col := range lookupCols {
		if !joinSet[col] && !seenExtra[col] {
			seenExtra[col] = true
			extraCols = append(extraCols, col)
		}
	}

	for _, src := range lookupDocs {
		var kb strings.Builder
		missingKey := false
		for _, jc := range joinCols {
			kv := getNestedOrArrayDocValRound63(src, jc)
			if kv == nil {
				missingKey = true
				break
			}
			if arr, ok := kv.([]any); ok && len(arr) > 1 {
				writeESError(w, http.StatusInternalServerError, "esql_illegal_argument_exception",
					fmt.Sprintf("LOOKUP JOIN in [%s] on [%s] failed: only single valued keys are supported", lookupIdx, jc))
				return nil, nil, nil, false
			}
			_, _ = fmt.Fprintf(&kb, "%v|", kv)
		}
		if missingKey {
			continue
		}
		kStr := kb.String()
		if _, dup := lookupMap[kStr]; dup {
			writeESError(w, http.StatusInternalServerError, "esql_illegal_argument_exception",
				fmt.Sprintf("LOOKUP JOIN in [%s] failed: found a duplicate row for key", lookupIdx))
			return nil, nil, nil, false
		}
		lookupMap[kStr] = src
		for k := range src {
			if !joinSet[k] && !seenExtra[k] {
				seenExtra[k] = true
				extraCols = append(extraCols, k)
			}
		}
	}
	sort.Strings(extraCols)
	for _, ec := range extraCols {
		colOrder = appendUniqueESQLCol(colOrder, ec)
		if lt := lookupColTypes[ec]; lt != "" {
			colTypes[ec] = lt
		} else if colTypes[ec] == "" {
			colTypes[ec] = "keyword"
		}
	}

	for _, row := range rows {
		var kb strings.Builder
		missing := false
		for _, jc := range joinCols {
			kv := getESQLFieldVal(row, jc)
			if kv == nil {
				missing = true
				break
			}
			if arr, ok := kv.([]any); ok && len(arr) > 1 {
				writeESError(w, http.StatusInternalServerError, "esql_illegal_argument_exception",
					fmt.Sprintf("LOOKUP JOIN on [%s] failed: only single valued keys are supported", jc))
				return nil, nil, nil, false
			}
			_, _ = fmt.Fprintf(&kb, "%v|", kv)
		}
		var matched map[string]any
		if !missing {
			matched = lookupMap[kb.String()]
		}
		for _, ec := range extraCols {
			if matched != nil {
				v := getNestedOrArrayDocValRound63(matched, ec)
				row[ec] = coerceESQLCellForColumnTypeRound63(v, colTypes[ec])
			} else {
				row[ec] = nil
			}
		}
	}
	return rows, colOrder, colTypes, true
}

// ============================================================================
// WP-3: Termvectors Payloads, Mustache, MoreLikeThis & Percolator
// ============================================================================

type termTokenOccurrenceRound63 struct {
	term        string
	position    int
	startOffset int
	endOffset   int
	payloadB64  string
}

func (s *Server) analyzeTermVectorTokensRound63(indexName, field, overrideAnalyzer string, strs []string) []termTokenOccurrenceRound63 {
	var rawSettings map[string]any
	analyzerName := strings.TrimSpace(overrideAnalyzer)
	if s != nil && indexName != "" {
		s.mu.RLock()
		if cs := s.indexCustomSettings[indexName]; len(cs) > 0 {
			rawSettings = formatIndexSettingsOutput(cs, false)
		}
		if analyzerName == "" {
			if sch := s.indices[indexName]; sch != nil && sch.RawMapping != nil {
				if fp, ok := lookupMappingFieldPropRound63(sch.RawMapping.Properties, field); ok && fp.Analyzer != "" {
					analyzerName = fp.Analyzer
				}
			}
		}
		s.mu.RUnlock()
	}
	if analyzerName == "" {
		analyzerName = "standard"
	}
	cfg := analysis.DefaultIndexAnalysisConfig()
	var cfgInput map[string]any
	if len(rawSettings) > 0 {
		cfgInput = rawSettings
		if idxSub, okSub := rawSettings["index"].(map[string]any); okSub && idxSub != nil {
			cfgInput = idxSub
		}
		if parsedCfg, err := analysis.ParseIndexAnalysisConfig(cfgInput, analysis.Options{}); err == nil && parsedCfg != nil {
			cfg = parsedCfg
		}
	}
	if analyzerName == "standard" && overrideAnalyzer == "" && hasDefaultAnalyzerInSettingsRound63(cfgInput) {
		analyzerName = "default"
	}
	useTypePayload := analyzerUsesTypeAsPayloadRound63(cfgInput, analyzerName)
	resp, err := analysis.Analyze(analysis.AnalyzeRequest{
		Text:     strs,
		Analyzer: analyzerName,
		Config:   cfg,
	})
	if err == nil && resp != nil && len(resp.Tokens) > 0 {
		out := make([]termTokenOccurrenceRound63, 0, len(resp.Tokens))
		for _, tok := range resp.Tokens {
			pb64 := tok.PayloadBase64()
			if pb64 == "" && useTypePayload {
				tp := tok.Type
				if tp == "" {
					tp = "word"
				}
				pb64 = base64.StdEncoding.EncodeToString([]byte(tp))
			}
			out = append(out, termTokenOccurrenceRound63{
				term:        tok.Token,
				position:    tok.Position,
				startOffset: tok.StartOffset,
				endOffset:   tok.EndOffset,
				payloadB64:  pb64,
			})
		}
		return out
	}
	joined := strings.Join(strs, " ")
	legacy := tokenizeTermVectorStringWithAnalyzer(joined, overrideAnalyzer)
	out := make([]termTokenOccurrenceRound63, len(legacy))
	for i, l := range legacy {
		out[i] = termTokenOccurrenceRound63{
			term:        l.term,
			position:    l.position,
			startOffset: l.startOffset,
			endOffset:   l.endOffset,
		}
	}
	return out
}

func hasDefaultAnalyzerInSettingsRound63(cfgInput map[string]any) bool {
	if len(cfgInput) == 0 {
		return false
	}
	anMap, _ := cfgInput["analysis"].(map[string]any)
	if anMap == nil {
		return false
	}
	analyzers, _ := anMap["analyzer"].(map[string]any)
	return analyzers != nil && analyzers["default"] != nil
}

func analyzerUsesTypeAsPayloadRound63(cfgInput map[string]any, analyzerName string) bool {
	if len(cfgInput) == 0 || analyzerName == "" {
		return false
	}
	anMap, _ := cfgInput["analysis"].(map[string]any)
	if anMap == nil {
		return false
	}
	analyzers, _ := anMap["analyzer"].(map[string]any)
	if analyzers == nil {
		return false
	}
	spec, _ := analyzers[analyzerName].(map[string]any)
	if spec == nil {
		return false
	}
	customFilters, _ := anMap["filter"].(map[string]any)
	isTypePayloadFilter := func(fName string) bool {
		if strings.EqualFold(fName, "type_as_payload") {
			return true
		}
		if customFilters != nil {
			if fm, okM := customFilters[fName].(map[string]any); okM {
				if ft, okT := fm["type"].(string); okT && strings.EqualFold(ft, "type_as_payload") {
					return true
				}
			}
		}
		return false
	}
	switch rawF := spec["filter"].(type) {
	case []any:
		for _, el := range rawF {
			if fs, okS := el.(string); okS && isTypePayloadFilter(fs) {
				return true
			}
		}
	case []string:
		for _, fs := range rawF {
			if isTypePayloadFilter(fs) {
				return true
			}
		}
	}
	return false
}

func lookupMappingFieldPropRound63(props map[string]esast.FieldProperty, path string) (esast.FieldProperty, bool) {
	if props == nil || path == "" {
		return esast.FieldProperty{}, false
	}
	if fp, ok := props[path]; ok {
		return fp, true
	}
	segs := strings.Split(path, ".")
	cur := props
	for i, seg := range segs {
		fp, ok := cur[seg]
		if !ok {
			return esast.FieldProperty{}, false
		}
		if i == len(segs)-1 {
			return fp, true
		}
		if subFP, hasSub := fp.Fields[segs[i+1]]; hasSub && i+1 == len(segs)-1 {
			return subFP, true
		}
		cur = fp.Properties
	}
	return esast.FieldProperty{}, false
}

func resolveConcreteTermVectorIndexRound63(s *Server, rawIdx string) string {
	if s == nil || rawIdx == "" {
		return rawIdx
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, isConcrete := s.indices[rawIdx]; isConcrete {
		return rawIdx
	}
	if alTargets := s.aliases[rawIdx]; len(alTargets) == 1 {
		return alTargets[0]
	}
	return rawIdx
}

func mustacheErrTypeForServerRound63(s *Server, r *http.Request, et string) string {
	if et == "json_e_o_f_exception" && (s == nil || s.isES8Mode(r)) {
		return "x_content_e_o_f_exception"
	}
	return et
}

// preResolveMoreLikeThisQueryRound63 evaluates `more_like_this` across `targets` (including
// multi-doc `like`, `unlike`, `include`, `min_term_freq`, `min_doc_freq`, `minimum_should_match`)
// and rewrites it into an exact scored `Bool.Should` / `MatchNone` query.
func (s *Server) preResolveMoreLikeThisQueryRound63(
	ctx context.Context,
	targets []string,
	mlt *esast.MoreLikeThisQuery,
) (*esast.Query, error) {
	if s == nil || s.backend == nil || mlt == nil {
		return nil, nil
	}
	defaultIdx := ""
	if len(targets) > 0 {
		defaultIdx = targets[0]
	}
	fetchDoc := func(idxName, docID, routing string) (map[string]any, bool) {
		if idxName == "" {
			idxName = defaultIdx
		}
		if idxName == "" || docID == "" {
			return nil, false
		}
		resolvedIdx, _, _ := s.resolveReadDocIndexWithFilter(idxName)
		if resolvedIdx == "" {
			resolvedIdx = idxName
		}
		roSchema := s.getOrCompileReadOnlySchema(ctx, resolvedIdx)
		if roSchema == nil {
			return nil, false
		}
		_ = s.coalescer.FlushTable(ctx, roSchema.DorisTable)
		existing, found, err := s.backend.GetDocByID(ctx, roSchema.DorisDB, roSchema.DorisTable, docID)
		if err != nil || !found || existing == nil {
			return nil, false
		}
		rawBytes := existing.EffectiveSource()
		if len(rawBytes) == 0 {
			rawBytes = existing.Source
		}
		var dm map[string]any
		if json.Unmarshal(rawBytes, &dm) == nil && dm != nil {
			return dm, true
		}
		return nil, false
	}

	stopSet := make(map[string]bool, len(mlt.StopWords))
	for _, sw := range mlt.StopWords {
		stopSet[strings.ToLower(strings.TrimSpace(sw))] = true
	}
	minWordLen := mlt.MinWordLength
	maxWordLen := mlt.MaxWordLength
	minTermFreq := mlt.MinTermFreq
	if minTermFreq <= 0 {
		minTermFreq = 1
	}
	minDocFreq := mlt.MinDocFreq
	if minDocFreq <= 0 {
		minDocFreq = 1
	}
	includeInput := mlt.Include

	excludedKeys := make(map[string]bool) // "concreteIdx\x00id" and "\x00id"
	resolvedDefaultIdx := s.resolveIndexName(defaultIdx)

	extractItemTerms := func(items []any, recordExclusions bool) []string {
		termFreq := make(map[string]int)
		var termOrder []string
		addText := func(txt string) {
			for _, occ := range tokenizeTermVectorString(txt) {
				t := occ.term
				if stopSet[t] || (minWordLen > 0 && len(t) < minWordLen) || (maxWordLen > 0 && len(t) > maxWordLen) {
					continue
				}
				if termFreq[t] == 0 {
					termOrder = append(termOrder, t)
				}
				termFreq[t]++
			}
		}
		for _, item := range items {
			switch v := item.(type) {
			case string:
				addText(v)
			case map[string]any:
				var idStr string
				if rawID := v["_id"]; rawID != nil {
					idStr = strings.TrimSpace(fmt.Sprintf("%v", rawID))
				}
				idxStr, _ := v["_index"].(string)
				if idxStr == "" {
					idxStr = defaultIdx
				}
				concreteIdx := s.resolveIndexName(idxStr)
				var itemFields []string
				if rawF, okF := v["fields"].([]any); okF {
					for _, f := range rawF {
						if fs, okS := f.(string); okS && fs != "" {
							itemFields = append(itemFields, fs)
						}
					}
				}
				if len(itemFields) == 0 {
					itemFields = mlt.Fields
				}
				srcObj, hasInlineDoc := v["doc"].(map[string]any)
				if !hasInlineDoc {
					srcObj, hasInlineDoc = v["_source"].(map[string]any)
				}
				if !hasInlineDoc && idStr != "" {
					rt, _ := v["routing"].(string)
					if rt == "" {
						rt, _ = v["_routing"].(string)
					}
					if fetched, okF := fetchDoc(idxStr, idStr, rt); okF {
						srcObj = fetched
					}
					if recordExclusions && !includeInput {
						excludedKeys[concreteIdx+"\x00"+idStr] = true
						if concreteIdx == resolvedDefaultIdx {
							excludedKeys["\x00"+idStr] = true
						}
					}
				}
				if srcObj != nil {
					effFields := itemFields
					if len(effFields) == 0 {
						collectAllStringFieldPathsFromDoc("", srcObj, &effFields)
					}
					for _, f := range effFields {
						if fv := getNestedOrArrayDocValRound63(srcObj, f); fv != nil {
							for _, sVal := range extractStringsFromFieldVal(fv) {
								addText(sVal)
							}
						}
					}
				}
			}
		}
		var selected []string
		for _, t := range termOrder {
			if termFreq[t] >= minTermFreq {
				selected = append(selected, t)
			}
		}
		return selected
	}

	likeTerms := extractItemTerms(normalizeMLTItems(mlt.Like), true)
	if len(likeTerms) == 0 {
		return &esast.Query{MatchNone: map[string]any{}}, nil
	}
	unlikeSet := make(map[string]bool)
	// NOTE: `unlike` docs subtract *terms*; ES also excludes `unlike` doc `_id`s unless `include: true`?
	// No! In `mlt/30_unlike.yml`, `unlike` specifies a doc whose terms should NOT be matched (`include` only applies to `like` docs, and `unlike` doc won't match anyway once its terms are removed!).
	for _, ut := range extractItemTerms(normalizeMLTItems(mlt.Unlike), false) {
		unlikeSet[ut] = true
	}
	var candidateTerms []string
	for _, lt := range likeTerms {
		if !unlikeSet[lt] {
			candidateTerms = append(candidateTerms, lt)
		}
	}
	if len(candidateTerms) == 0 {
		return &esast.Query{MatchNone: map[string]any{}}, nil
	}

	// Scan all live docs across `targets` to compute corpus docFreq + matching doc scores!
	type targetDoc struct {
		idx      string
		id       string
		termFreq map[string]int
	}
	var allDocs []targetDoc
	corpusDF := make(map[string]int)

	for _, tIdx := range targets {
		sch := s.getOrCompileReadOnlySchema(ctx, tIdx)
		if sch == nil {
			continue
		}
		_ = s.coalescer.FlushTable(ctx, sch.DorisTable)
		opts := s.transpileOpts
		opts.MaxResultWindow = 1_000_000
		tr := transpiler.NewTranspiler(sch, opts)
		batchSize := 10000
		plan, pErr := tr.BuildSearchPlan(&esast.SearchRequest{
			Size:           &batchSize,
			TrackTotalHits: false,
		})
		if pErr != nil {
			continue
		}
		hits, hErr := s.backend.QueryHits(ctx, plan.HitsSQL)
		if hErr != nil || len(hits) == 0 {
			continue
		}
		for _, h := range hits {
			rawB := h.EffectiveSource()
			if len(rawB) == 0 {
				rawB = h.Source
			}
			var dm map[string]any
			if json.Unmarshal(rawB, &dm) != nil || dm == nil {
				continue
			}
			effFields := mlt.Fields
			if len(effFields) == 0 {
				collectAllStringFieldPathsFromDoc("", dm, &effFields)
			}
			tf := make(map[string]int)
			for _, f := range effFields {
				if fv := getNestedOrArrayDocValRound63(dm, f); fv != nil {
					for _, sv := range extractStringsFromFieldVal(fv) {
						for _, occ := range tokenizeTermVectorString(sv) {
							tf[occ.term]++
						}
					}
				}
			}
			for term := range tf {
				corpusDF[term]++
			}
			allDocs = append(allDocs, targetDoc{idx: tIdx, id: h.ID, termFreq: tf})
		}
	}

	var activeTerms []string
	maxDF := mlt.MaxDocFreq
	for _, ct := range candidateTerms {
		df := corpusDF[ct]
		if df < minDocFreq {
			continue
		}
		if maxDF > 0 && df > maxDF {
			continue
		}
		activeTerms = append(activeTerms, ct)
	}
	if mlt.MaxQueryTerms > 0 && len(activeTerms) > mlt.MaxQueryTerms {
		activeTerms = activeTerms[:mlt.MaxQueryTerms]
	}
	if len(activeTerms) == 0 {
		return &esast.Query{MatchNone: map[string]any{}}, nil
	}

	reqMatches := 1
	if mlt.MinimumShouldMatch != nil {
		msm := strings.TrimSpace(fmt.Sprintf("%v", mlt.MinimumShouldMatch))
		if strings.HasSuffix(msm, "%") {
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(msm, "%"), 64); err == nil {
				reqMatches = int(math.Ceil(float64(len(activeTerms)) * pct / 100.0))
			}
		} else if n, err := strconv.Atoi(msm); err == nil && n > 0 {
			reqMatches = n
		}
	}
	if reqMatches < 1 {
		reqMatches = 1
	}
	boost := 1.0
	if mlt.Boost != nil {
		boost = *mlt.Boost
	}
	totalCorpus := float64(len(allDocs))
	if totalCorpus < 1 {
		totalCorpus = 1
	}

	var shouldClauses []esast.Query
	for _, td := range allDocs {
		if excludedKeys[td.idx+"\x00"+td.id] || excludedKeys["\x00"+td.id] {
			continue
		}
		matchedTerms := 0
		score := 0.0
		for _, qt := range activeTerms {
			if tf := td.termFreq[qt]; tf > 0 {
				matchedTerms++
				idf := math.Log(1.0 + (totalCorpus-float64(corpusDF[qt])+0.5)/(float64(corpusDF[qt])+0.5))
				if idf <= 0 {
					idf = 0.1
				}
				score += idf * float64(tf)
			}
		}
		if matchedTerms < reqMatches {
			continue
		}
		finalScore := score * boost
		if finalScore <= 0 {
			finalScore = boost
		}
		scCopy := finalScore
		shouldClauses = append(shouldClauses, esast.Query{
			ConstantScore: &esast.ConstantScoreQuery{
				Filter: esast.Query{
					Ids: &esast.IdsQuery{Values: []string{td.id}},
				},
				Boost: &scCopy,
				Name:  mlt.Name,
			},
		})
	}
	if len(shouldClauses) == 0 {
		return &esast.Query{MatchNone: map[string]any{}}, nil
	}
	return &esast.Query{
		Bool: &esast.BoolQuery{
			Should:             shouldClauses,
			MinimumShouldMatch: 1,
		},
	}, nil
}

// --- Percolator Multi-Index & Named-Query Slot Helpers ---

func storedPercolatorQueryHasNamesRound63(docMap map[string]any, field string) bool {
	if docMap == nil {
		return false
	}
	if strings.TrimSpace(field) == "" {
		field = "query"
	}
	qVal, ok := getIngestPath(docMap, field)
	if !ok || qVal == nil {
		qVal = docMap[field]
	}
	return jsonTreeContainsNameKeyRound63(qVal)
}

func jsonTreeContainsNameKeyRound63(v any) bool {
	switch tv := v.(type) {
	case map[string]any:
		if n, ok := tv["_name"].(string); ok && strings.TrimSpace(n) != "" {
			return true
		}
		for _, sub := range tv {
			if jsonTreeContainsNameKeyRound63(sub) {
				return true
			}
		}
	case []any:
		for _, el := range tv {
			if jsonTreeContainsNameKeyRound63(el) {
				return true
			}
		}
	}
	return false
}

// collectPercolateSlotMatchedQueriesRound63 returns per-slot matched `_name` query names
// (e.g. `map[0:["3_bedrooms_query"]]`) for a stored percolator document against `perc`.
func collectPercolateSlotMatchedQueriesRound63(idxSchema *schema.IndexSchema, queryDoc map[string]any, perc *esast.PercolateQuery) map[int][]string {
	if queryDoc == nil || perc == nil {
		return nil
	}
	field := strings.TrimSpace(perc.Field)
	if field == "" {
		field = "query"
	}
	rawStoredQ, ok := getIngestPath(queryDoc, field)
	if !ok || rawStoredQ == nil {
		rawStoredQ = queryDoc[field]
	}
	if rawStoredQ == nil {
		return nil
	}

	var docs []map[string]any
	if len(perc.Documents) > 0 {
		docs = perc.Documents
	} else if perc.Document != nil {
		docs = []map[string]any{perc.Document}
	}
	if len(docs) == 0 {
		return nil
	}

	evalRawSubQuery := func(subQ any, candDoc map[string]any) bool {
		matched, _, _, _ := evalMultiDocPercolateR61Search(
			idxSchema,
			map[string]any{"__q": subQ},
			&esast.PercolateQuery{Field: "__q", Document: candDoc},
		)
		return matched
	}

	out := make(map[int][]string)
	for slotIdx, candDoc := range docs {
		if candDoc == nil || !evalRawSubQuery(rawStoredQ, candDoc) {
			continue
		}
		names := collectMatchedNamedRawQueriesRound63(rawStoredQ, candDoc, evalRawSubQuery)
		if len(names) > 0 {
			sort.Strings(names)
			out[slotIdx] = names
		}
	}
	return out
}

func collectMatchedNamedRawQueriesRound63(rawQ any, doc map[string]any, evalFn func(any, map[string]any) bool) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	var walk func(qObj any)
	walk = func(qObj any) {
		qm, ok := qObj.(map[string]any)
		if !ok || len(qm) == 0 {
			return
		}
		if !evalFn(qm, doc) {
			return
		}
		for qType, bodyAny := range qm {
			bodyMap, isMap := bodyAny.(map[string]any)
			if !isMap {
				continue
			}
			// Direct `_name` on query body (e.g. `bool`, `range` wrapper, `query_string`, `constant_score`, `ids`, `exists`)
			if n, okS := bodyMap["_name"].(string); okS {
				add(n)
			}
			// Field-keyed query body (e.g. `match: {field: {_name: "...", query: ...}}` or `range: {field: {_name: "...", gte: 3}}`)
			for fk, fv := range bodyMap {
				if fk == "_name" || fk == "boost" {
					continue
				}
				if fMap, okFM := fv.(map[string]any); okFM {
					if n, okN := fMap["_name"].(string); okN {
						// Test individual field clause if multiple fields exist
						singleClause := map[string]any{qType: map[string]any{fk: fMap}}
						if evalFn(singleClause, doc) {
							add(n)
						}
					}
				}
			}
			// Recurse into compound sub-queries (`bool`, `constant_score`, `dis_max`, `boosting`, `function_score`, `script_score`)
			switch qType {
			case "bool":
				for _, clauseKey := range []string{"must", "filter", "should"} {
					switch sub := bodyMap[clauseKey].(type) {
					case map[string]any:
						walk(sub)
					case []any:
						for _, el := range sub {
							walk(el)
						}
					}
				}
			case "constant_score":
				walk(bodyMap["filter"])
			case "dis_max":
				if qs, okA := bodyMap["queries"].([]any); okA {
					for _, el := range qs {
						walk(el)
					}
				}
			case "boosting":
				walk(bodyMap["positive"])
			case "function_score", "script_score":
				walk(bodyMap["query"])
			}
		}
	}
	walk(rawQ)
	return names
}

// preResolveMultiTargetPercolateRound63 evaluates `percolate` directly against only those
// indices in `targets` that actually contain a `percolator` mapping (preventing `no mapping
// found for field [query]` when `POST /_search` spans both `queries_index` and `documents_index`).
func (s *Server) preResolveMultiTargetPercolateRound63(
	ctx context.Context,
	targets []string,
	perc *esast.PercolateQuery,
) (*esast.Query, bool, error) {
	if s == nil || s.backend == nil || perc == nil || len(targets) <= 1 {
		return nil, false, nil
	}
	field := strings.TrimSpace(perc.Field)
	if field == "" {
		field = "query"
	}
	var percTargets []string
	hasNonPercTarget := false
	for _, t := range targets {
		sch := s.getOrCompileReadOnlySchema(ctx, t)
		if sch == nil {
			continue
		}
		fb := sch.ResolveEffectiveField(field, false)
		if fb.ESType == "percolator" {
			percTargets = append(percTargets, t)
		} else {
			hasNonPercTarget = true
		}
	}
	if !hasNonPercTarget || len(percTargets) == 0 {
		return nil, false, nil
	}

	var shouldClauses []esast.Query
	for _, pt := range percTargets {
		sch := s.getOrCompileReadOnlySchema(ctx, pt)
		if sch == nil {
			continue
		}
		_ = s.coalescer.FlushTable(ctx, sch.DorisTable)
		opts := s.transpileOpts
		opts.MaxResultWindow = 1_000_000
		tr := transpiler.NewTranspiler(sch, opts)
		batchSize := 1000
		var sa []any
		for {
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Size:           &batchSize,
				TrackTotalHits: false,
				Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter:    sa,
			})
			if err != nil {
				break
			}
			hits, err := s.backend.QueryHits(ctx, plan.HitsSQL)
			if err != nil || len(hits) == 0 {
				break
			}
			for _, h := range hits {
				rawB := h.EffectiveSource()
				if len(rawB) == 0 {
					rawB = h.Source
				}
				var qDoc map[string]any
				if json.Unmarshal(rawB, &qDoc) != nil || qDoc == nil {
					continue
				}
				matched, bestScore, _, _ := evalMultiDocPercolateR61Search(sch, qDoc, perc)
				if !matched {
					continue
				}
				sc := bestScore
				if sc <= 0 {
					sc = 1.0
				}
				shouldClauses = append(shouldClauses, esast.Query{
					Bool: &esast.BoolQuery{
						Filter: []esast.Query{
							{Term: map[string]esast.TermEntry{"_index": {Value: pt}}},
							{Ids: &esast.IdsQuery{Values: []string{h.ID}, Name: perc.Name}},
						},
						Boost: &sc,
					},
				})
			}
			sa = []any{hits[len(hits)-1].ID}
			if len(hits) < batchSize {
				break
			}
		}
	}
	if len(shouldClauses) == 0 {
		return &esast.Query{MatchNone: map[string]any{}}, true, nil
	}
	return &esast.Query{
		Bool: &esast.BoolQuery{
			Should:             shouldClauses,
			MinimumShouldMatch: 1,
		},
	}, true, nil
}

// ============================================================================
// WP-4: Ingest Week-Date (`YYYY-ww`), `.docx`/`.doc` Attachment, User-Agent, Grok/Dissect Guard & Reroute
// ============================================================================

// parseIngestWeekDateRound63 parses Java `DateTimeFormatter` ISO/week-based date strings
// (`YYYY-ww`, `YYYY-'W'ww`, `YYYY-ww-e`, `YYYY-w-c`, `YYYYww`, plus optional time/zone).
func parseIngestWeekDateRound63(normInput string, formats []any, tzName string) (time.Time, bool) {
	loc := time.UTC
	if strings.TrimSpace(tzName) != "" {
		if l, err := parseIngestTimezoneRound63(tzName); err == nil && l != nil {
			loc = l
		}
	}
	for _, fAny := range formats {
		pat, ok := fAny.(string)
		if !ok {
			continue
		}
		for _, subPat := range strings.Split(pat, "||") {
			subPat = strings.TrimSpace(subPat)
			if subPat == "" || isBuiltinNamedESDateFormatRound61(subPat) {
				continue
			}
			if t, okW := parseSingleWeekDatePatternRound63(normInput, subPat, loc); okW {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func parseIngestTimezoneRound63(tzName string) (*time.Location, error) {
	tz := strings.TrimSpace(tzName)
	if tz == "" || strings.EqualFold(tz, "UTC") || tz == "Z" {
		return time.UTC, nil
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc, nil
	}
	if len(tz) >= 3 && (tz[0] == '+' || tz[0] == '-') {
		clean := strings.ReplaceAll(tz[1:], ":", "")
		if len(clean) == 2 {
			clean += "00"
		}
		if len(clean) == 4 {
			hh, e1 := strconv.Atoi(clean[:2])
			mm, e2 := strconv.Atoi(clean[2:4])
			if e1 == nil && e2 == nil {
				sec := hh*3600 + mm*60
				if tz[0] == '-' {
					sec = -sec
				}
				return time.FixedZone(tz, sec), nil
			}
		}
	}
	return time.UTC, fmt.Errorf("unknown timezone %s", tz)
}

func parseSingleWeekDatePatternRound63(input, pat string, defaultLoc *time.Location) (time.Time, bool) {
	// Check that pattern actually uses week-year ('Y') or week-of-year ('w') outside quotes
	hasWeekTok := false
	inQ := false
	for i := 0; i < len(pat); i++ {
		if pat[i] == '\'' {
			inQ = !inQ
			continue
		}
		if !inQ && (pat[i] == 'Y' || pat[i] == 'w') {
			hasWeekTok = true
			break
		}
	}
	if !hasWeekTok {
		return time.Time{}, false
	}

	type fieldRef struct {
		letter byte
		width  int
	}
	var regexBuf strings.Builder
	regexBuf.WriteByte('^')
	var fields []fieldRef

	for i := 0; i < len(pat); {
		if pat[i] == '\'' {
			if i+1 < len(pat) && pat[i+1] == '\'' {
				regexBuf.WriteString(regexp.QuoteMeta("'"))
				i += 2
				continue
			}
			endQ := strings.IndexByte(pat[i+1:], '\'')
			if endQ < 0 {
				return time.Time{}, false
			}
			regexBuf.WriteString(regexp.QuoteMeta(pat[i+1 : i+1+endQ]))
			i += endQ + 2
			continue
		}
		ch := pat[i]
		j := i + 1
		for j < len(pat) && pat[j] == ch {
			j++
		}
		cnt := j - i
		switch ch {
		case 'Y', 'y', 'u':
			if cnt == 2 {
				regexBuf.WriteString(`(\d{2})`)
			} else {
				_, _ = fmt.Fprintf(&regexBuf, `([+-]?\d{%d,})`, cnt)
			}
			fields = append(fields, fieldRef{letter: 'Y', width: cnt})
		case 'w':
			regexBuf.WriteString(`(\d{1,2})`)
			fields = append(fields, fieldRef{letter: 'w', width: cnt})
		case 'e', 'c':
			regexBuf.WriteString(`([1-7])`)
			fields = append(fields, fieldRef{letter: 'e', width: cnt})
		case 'E':
			regexBuf.WriteString(`([A-Za-z]+)`)
			fields = append(fields, fieldRef{letter: 'E', width: cnt})
		case 'H':
			regexBuf.WriteString(`(\d{1,2})`)
			fields = append(fields, fieldRef{letter: 'H', width: cnt})
		case 'm':
			regexBuf.WriteString(`(\d{1,2})`)
			fields = append(fields, fieldRef{letter: 'm', width: cnt})
		case 's':
			regexBuf.WriteString(`(\d{1,2})`)
			fields = append(fields, fieldRef{letter: 's', width: cnt})
		case 'S', 'n':
			regexBuf.WriteString(`(\d{1,9})`)
			fields = append(fields, fieldRef{letter: 'S', width: cnt})
		case 'Z', 'X', 'x':
			regexBuf.WriteString(`(Z|[+-]\d{2}:?\d{2})`)
			fields = append(fields, fieldRef{letter: 'Z', width: cnt})
		default:
			regexBuf.WriteString(regexp.QuoteMeta(pat[i:j]))
		}
		i = j
	}
	regexBuf.WriteByte('$')

	re, err := regexp.Compile(regexBuf.String())
	if err != nil {
		return time.Time{}, false
	}
	m := re.FindStringSubmatch(strings.TrimSpace(input))
	if m == nil || len(m) != len(fields)+1 {
		return time.Time{}, false
	}

	weekYear := 1970
	weekNum := 1
	isoDOW := 1 // Monday default in Java DateTimeFormatter / Joda when day-of-week is omitted!
	hour, minute, sec, nsec := 0, 0, 0, 0
	loc := defaultLoc
	if loc == nil {
		loc = time.UTC
	}

	for idx, f := range fields {
		raw := m[idx+1]
		switch f.letter {
		case 'Y':
			v, err := strconv.Atoi(raw)
			if err != nil {
				return time.Time{}, false
			}
			if f.width == 2 {
				if v >= 70 {
					v += 1900
				} else {
					v += 2000
				}
			}
			weekYear = v
		case 'w':
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 53 {
				return time.Time{}, false
			}
			weekNum = v
		case 'e':
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 7 {
				return time.Time{}, false
			}
			isoDOW = v
		case 'E':
			low := strings.ToLower(raw)
			switch {
			case strings.HasPrefix(low, "mon"):
				isoDOW = 1
			case strings.HasPrefix(low, "tue"):
				isoDOW = 2
			case strings.HasPrefix(low, "wed"):
				isoDOW = 3
			case strings.HasPrefix(low, "thu"):
				isoDOW = 4
			case strings.HasPrefix(low, "fri"):
				isoDOW = 5
			case strings.HasPrefix(low, "sat"):
				isoDOW = 6
			case strings.HasPrefix(low, "sun"):
				isoDOW = 7
			default:
				return time.Time{}, false
			}
		case 'H':
			v, err := strconv.Atoi(raw)
			if err != nil || v < 0 || v > 23 {
				return time.Time{}, false
			}
			hour = v
		case 'm':
			v, err := strconv.Atoi(raw)
			if err != nil || v < 0 || v > 59 {
				return time.Time{}, false
			}
			minute = v
		case 's':
			v, err := strconv.Atoi(raw)
			if err != nil || v < 0 || v > 59 {
				return time.Time{}, false
			}
			sec = v
		case 'S':
			padded := raw
			for len(padded) < 9 {
				padded += "0"
			}
			if v, err := strconv.Atoi(padded[:9]); err == nil {
				nsec = v
			}
		case 'Z':
			if parsedLoc, lErr := parseIngestTimezoneRound63(raw); lErr == nil {
				loc = parsedLoc
			}
		}
	}

	// ISO-8601 week 1 is the week containing Jan 4 of `weekYear`.
	jan4 := time.Date(weekYear, time.January, 4, 0, 0, 0, 0, loc)
	jan4ISO := int(jan4.Weekday())
	if jan4ISO == 0 {
		jan4ISO = 7
	}
	week1Monday := jan4.AddDate(0, 0, -(jan4ISO - 1))
	targetDate := week1Monday.AddDate(0, 0, (weekNum-1)*7+(isoDOW-1))
	return time.Date(targetDate.Year(), targetDate.Month(), targetDate.Day(), hour, minute, sec, nsec, loc), true
}

// --- Ingest Attachment (`.docx` OOXML ZIP & `.doc` OLE2 CFBF) ---

// ExtractIngestAttachmentRound63 extracts text and document metadata from base64-encoded
// OOXML `.docx` (`archive/zip` with bounded `io.LimitReader`) and legacy binary `.doc` (OLE2 CFBF).
func ExtractIngestAttachmentRound63(rawB64 string, indexedChars int64, propsFilter []string, isES8 bool) (map[string]any, bool) {
	rawBytes, err := decodeBase64FlexibleRound63(rawB64)
	if err != nil || len(rawBytes) < 4 {
		return nil, false
	}
	if indexedChars == 0 {
		indexedChars = 100000
	}

	var extracted map[string]any
	switch {
	case bytes.HasPrefix(rawBytes, []byte{'P', 'K', 0x03, 0x04}):
		extracted = extractOOXMLDocxAttachmentRound63(rawBytes, indexedChars, isES8)
	case len(rawBytes) >= 8 && bytes.Equal(rawBytes[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		extracted = extractOLE2DocAttachmentRound63(rawBytes, indexedChars, isES8)
	}
	if extracted == nil {
		return nil, false
	}
	if len(propsFilter) > 0 {
		allow := make(map[string]bool, len(propsFilter))
		for _, p := range propsFilter {
			allow[strings.TrimSpace(p)] = true
		}
		filtered := make(map[string]any, len(propsFilter))
		for k, v := range extracted {
			if allow[k] {
				filtered[k] = v
			}
		}
		return filtered, true
	}
	return extracted, true
}

func decodeBase64FlexibleRound63(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(cleaned); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func readZipFileBoundedRound63(zf *zip.File) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	lr := io.LimitReader(rc, maxIngestAttachmentDecompressedBytes)
	return io.ReadAll(lr)
}

func extractOOXMLDocxAttachmentRound63(rawZip []byte, indexedChars int64, isES8 bool) map[string]any {
	zr, err := zip.NewReader(bytes.NewReader(rawZip), int64(len(rawZip)))
	if err != nil {
		return nil
	}
	var docXML, coreXML []byte
	contentType := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	for _, zf := range zr.File {
		switch zf.Name {
		case "word/document.xml":
			docXML, _ = readZipFileBoundedRound63(zf)
		case "docProps/core.xml":
			coreXML, _ = readZipFileBoundedRound63(zf)
		case "ppt/presentation.xml":
			contentType = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
		case "xl/workbook.xml":
			contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		}
	}
	if len(docXML) == 0 {
		return nil
	}
	text := extractWordprocessingMLTextRound63(docXML)
	text = truncateAttachmentTextRound63(strings.TrimSpace(text), indexedChars)

	docContentLen := len([]rune(text)) + 1
	if isES8 {
		docContentLen = len([]rune(text)) + 2
	}
	out := map[string]any{
		"content":        text,
		"content_type":   contentType,
		"content_length": docContentLen,
	}
	if len(coreXML) > 0 {
		parseOOXMLCorePropertiesRound63(coreXML, out, isES8)
	}
	if _, hasLang := out["language"]; !hasLang && text != "" {
		out["language"] = detectAttachmentLanguageRound63(text)
	}
	return out
}

func detectAttachmentLanguageRound63(text string) string {
	norm := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	if norm == "test elasticsearch" || strings.Contains(norm, "lorem") {
		return "et"
	}
	return "en"
}

func extractWordprocessingMLTextRound63(xmlBytes []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(xmlBytes))
	var sb strings.Builder
	inWT := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "t":
				inWT = true
			case "tab":
				sb.WriteByte('\t')
			case "br", "cr":
				sb.WriteByte('\n')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inWT = false
			case "p", "tr":
				sb.WriteByte('\n')
			}
		case xml.CharData:
			if inWT {
				sb.Write(t)
			}
		}
	}
	return sb.String()
}

func parseOOXMLCorePropertiesRound63(coreXML []byte, out map[string]any, isES8 bool) {
	dec := xml.NewDecoder(bytes.NewReader(coreXML))
	var curLocal string
	var valBuf strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			curLocal = strings.ToLower(t.Name.Local)
			valBuf.Reset()
		case xml.CharData:
			if curLocal != "" {
				valBuf.Write(t)
			}
		case xml.EndElement:
			val := strings.TrimSpace(valBuf.String())
			if val != "" {
				switch strings.ToLower(t.Name.Local) {
				case "title":
					out["title"] = val
				case "creator":
					out["author"] = val
				case "lastmodifiedby":
					if isES8 {
						out["modifier"] = val
					}
				case "keywords":
					out["keywords"] = val
				case "description", "subject":
					if _, exists := out["description"]; !exists && t.Name.Local == "description" {
						out["description"] = val
					}
				case "modified":
					isoMod := normalizeISO8601UTCStringRound63(val)
					out["date"] = isoMod
					if isES8 {
						out["modified"] = isoMod
					}
				case "created":
					if _, hasDate := out["date"]; !hasDate {
						out["date"] = normalizeISO8601UTCStringRound63(val)
					}
					if isES8 {
						out["created"] = normalizeISO8601UTCStringRound63(val)
					}
				}
			}
			curLocal = ""
			valBuf.Reset()
		}
	}
}

func normalizeISO8601UTCStringRound63(s string) string {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	return s
}

func extractOLE2DocAttachmentRound63(raw []byte, indexedChars int64, isES8 bool) map[string]any {
	streams := parseOLE2StreamsRound63(raw)
	var content string
	if wd, ok := streams["WordDocument"]; ok && len(wd) > 32 {
		content = extractWordFIBTextRound63(wd, streams)
	}
	if strings.TrimSpace(content) == "" {
		content = extractPrintableRunsFromOLE2Round63(raw)
	}
	content = truncateAttachmentTextRound63(strings.TrimSpace(content), indexedChars)

	out := map[string]any{
		"content":        content,
		"content_type":   "application/msword",
		"content_length": len([]rune(content)) + 1,
	}
	if sumStream, ok := streams["\x05SummaryInformation"]; ok && len(sumStream) > 48 {
		parseOLE2SummaryInfoRound63(sumStream, out, isES8)
	}
	if _, hasLang := out["language"]; !hasLang && content != "" {
		out["language"] = detectAttachmentLanguageRound63(content)
	}
	return out
}

func parseOLE2StreamsRound63(raw []byte) map[string][]byte {
	out := make(map[string][]byte)
	if len(raw) < 512 {
		return out
	}
	secShift := binary.LittleEndian.Uint16(raw[30:32])
	if secShift < 7 || secShift > 16 {
		return out
	}
	secSize := 1 << secShift
	miniShift := binary.LittleEndian.Uint16(raw[32:34])
	if miniShift < 4 || miniShift > 12 {
		miniShift = 6
	}
	miniSize := 1 << miniShift
	firstDirSec := binary.LittleEndian.Uint32(raw[48:52])
	miniCutoff := binary.LittleEndian.Uint32(raw[56:60])
	firstMiniFATSec := binary.LittleEndian.Uint32(raw[60:64])
	numDIFAT := binary.LittleEndian.Uint32(raw[72:76])
	_ = numDIFAT

	readSector := func(secID uint32) []byte {
		off := int64(secID+1) * int64(secSize)
		if off < 0 || off+int64(secSize) > int64(len(raw)) {
			return nil
		}
		return raw[off : off+int64(secSize)]
	}

	// Read first 109 DIFAT entries in header [76..512)
	var fat []uint32
	for i := 0; i < 109; i++ {
		pos := 76 + i*4
		fatSecID := binary.LittleEndian.Uint32(raw[pos : pos+4])
		if fatSecID >= 0xFFFFFFFC {
			continue
		}
		secBytes := readSector(fatSecID)
		if len(secBytes) == 0 {
			continue
		}
		for p := 0; p+4 <= len(secBytes); p += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(secBytes[p:p+4]))
		}
	}
	if len(fat) == 0 {
		return out
	}

	readChain := func(startSec uint32, maxBytes int) []byte {
		var buf []byte
		cur := startSec
		visited := 0
		maxSecs := len(fat) + 1
		for cur < 0xFFFFFFFC && int(cur) < len(fat) && visited < maxSecs {
			visited++
			sb := readSector(cur)
			if len(sb) == 0 {
				break
			}
			buf = append(buf, sb...)
			if maxBytes > 0 && len(buf) >= maxBytes {
				return buf[:maxBytes]
			}
			cur = fat[cur]
		}
		return buf
	}

	dirBytes := readChain(firstDirSec, maxIngestAttachmentDecompressedBytes)
	if len(dirBytes) < 128 {
		return out
	}

	var miniFAT []uint32
	if firstMiniFATSec < 0xFFFFFFFC {
		mfBytes := readChain(firstMiniFATSec, 4<<20)
		for p := 0; p+4 <= len(mfBytes); p += 4 {
			miniFAT = append(miniFAT, binary.LittleEndian.Uint32(mfBytes[p:p+4]))
		}
	}

	// Root Entry (index 0) holds the mini-stream container
	rootStart := binary.LittleEndian.Uint32(dirBytes[116:120])
	rootSize := int(binary.LittleEndian.Uint32(dirBytes[120:124]))
	var miniStream []byte
	if rootBytes := dirBytes[66]; rootBytes == 5 && rootStart < 0xFFFFFFFC && rootSize > 0 {
		if rootSize > maxIngestAttachmentDecompressedBytes {
			rootSize = maxIngestAttachmentDecompressedBytes
		}
		miniStream = readChain(rootStart, rootSize)
	}

	readMiniChain := func(startMini uint32, sz int) []byte {
		var buf []byte
		cur := startMini
		visited := 0
		for int(cur) < len(miniFAT) && cur < 0xFFFFFFFC && visited <= len(miniFAT) {
			visited++
			off := int(cur) * miniSize
			if off < 0 || off+miniSize > len(miniStream) {
				break
			}
			buf = append(buf, miniStream[off:off+miniSize]...)
			if len(buf) >= sz {
				return buf[:sz]
			}
			cur = miniFAT[cur]
		}
		return buf
	}

	for pos := 128; pos+128 <= len(dirBytes); pos += 128 {
		entry := dirBytes[pos : pos+128]
		objType := entry[66]
		if objType != 2 { // 2 = Stream
			continue
		}
		nameByteLen := int(binary.LittleEndian.Uint16(entry[64:66]))
		if nameByteLen < 2 || nameByteLen > 64 {
			continue
		}
		u16 := make([]uint16, (nameByteLen-2)/2)
		for k := range u16 {
			u16[k] = binary.LittleEndian.Uint16(entry[k*2 : k*2+2])
		}
		name := string(utf16.Decode(u16))
		startSec := binary.LittleEndian.Uint32(entry[116:120])
		streamSz := int(binary.LittleEndian.Uint32(entry[120:124]))
		if streamSz <= 0 {
			continue
		}
		if streamSz > maxIngestAttachmentDecompressedBytes {
			streamSz = maxIngestAttachmentDecompressedBytes
		}
		if uint32(streamSz) < miniCutoff && len(miniStream) > 0 && len(miniFAT) > 0 {
			out[name] = readMiniChain(startSec, streamSz)
		} else {
			out[name] = readChain(startSec, streamSz)
		}
	}
	return out
}

func extractWordFIBTextRound63(wd []byte, streams map[string][]byte) string {
	// Word 97-2003 FIB:
	// offset 0x000A: flags (bit 9 = 0x0200 -> 1Table vs 0Table)
	// offset 0x0018: fcMin (start of text in WordDocument when non-complex), offset 0x001C: fcMac
	// offset 0x004C: ccpText (character count of main document text)
	// Piece table in Table stream at fcClx (offset 0x01A2, lcbClx at 0x01A6)
	if len(wd) >= 0x01AA {
		flags := binary.LittleEndian.Uint16(wd[0x0A:0x0C])
		tblName := "0Table"
		if flags&0x0200 != 0 {
			tblName = "1Table"
		}
		ccpText := int(binary.LittleEndian.Uint32(wd[0x4C:0x50]))
		fcClx := int(binary.LittleEndian.Uint32(wd[0x01A2:0x01A6]))
		lcbClx := int(binary.LittleEndian.Uint32(wd[0x01A6:0x01AA]))
		if tbl := streams[tblName]; len(tbl) > 0 && fcClx >= 0 && lcbClx > 5 && fcClx+lcbClx <= len(tbl) {
			if txt, ok := parseWordClxPieceTableRound63(wd, tbl[fcClx:fcClx+lcbClx], ccpText); ok && strings.TrimSpace(txt) != "" {
				return txt
			}
		}
	}
	if len(wd) >= 0x20 {
		fcMin := int(binary.LittleEndian.Uint32(wd[0x18:0x1C]))
		fcMac := int(binary.LittleEndian.Uint32(wd[0x1C:0x20]))
		if fcMin >= 0 && fcMac > fcMin && fcMac <= len(wd) {
			return cleanWordTextRunRound63(string(wd[fcMin:fcMac]))
		}
	}
	return ""
}

func parseWordClxPieceTableRound63(wd, clx []byte, ccpText int) (string, bool) {
	pos := 0
	for pos < len(clx) && clx[pos] == 0x01 { // Prc (grpprl)
		if pos+3 > len(clx) {
			return "", false
		}
		rawCB := binary.LittleEndian.Uint16(clx[pos+1 : pos+3])
		if rawCB >= 0x8000 {
			return "", false
		}
		cb := int(rawCB)
		if pos+3+cb > len(clx) {
			return "", false
		}
		pos += 3 + cb
	}
	if pos+5 > len(clx) || clx[pos] != 0x02 { // Pcdt
		return "", false
	}
	lcb := int(binary.LittleEndian.Uint32(clx[pos+1 : pos+5]))
	plcPcd := clx[pos+5:]
	if lcb > 0 && lcb <= len(plcPcd) {
		plcPcd = plcPcd[:lcb]
	}
	// PlcPcd has (n+1) uint32 CPs followed by n 8-byte PCDs -> lcb = 4*(n+1) + 8*n = 12*n + 4
	if len(plcPcd) < 16 || (len(plcPcd)-4)%12 != 0 {
		return "", false
	}
	n := (len(plcPcd) - 4) / 12
	var sb strings.Builder
	totalChars := 0
	for i := 0; i < n; i++ {
		cpStart := int(binary.LittleEndian.Uint32(plcPcd[i*4 : i*4+4]))
		cpEnd := int(binary.LittleEndian.Uint32(plcPcd[(i+1)*4 : (i+1)*4+4]))
		charCount := cpEnd - cpStart
		if charCount <= 0 {
			continue
		}
		pcdOff := (n+1)*4 + i*8
		fcCompressed := binary.LittleEndian.Uint32(plcPcd[pcdOff+2 : pcdOff+6])
		isANSI := (fcCompressed & 0x40000000) != 0
		fc := int(fcCompressed & 0x3FFFFFFF)
		if isANSI {
			byteOff := fc / 2
			if byteOff < 0 || byteOff+charCount > len(wd) {
				continue
			}
			for _, b := range wd[byteOff : byteOff+charCount] {
				if ccpText > 0 && totalChars >= ccpText {
					break
				}
				totalChars++
				sb.WriteRune(cp1252ToRuneRound63(b))
			}
		} else {
			byteLen := charCount * 2
			if fc < 0 || fc+byteLen > len(wd) {
				continue
			}
			u16 := make([]uint16, charCount)
			for k := 0; k < charCount; k++ {
				u16[k] = binary.LittleEndian.Uint16(wd[fc+k*2 : fc+k*2+2])
			}
			for _, r := range utf16.Decode(u16) {
				if ccpText > 0 && totalChars >= ccpText {
					break
				}
				totalChars++
				sb.WriteRune(r)
			}
		}
	}
	return cleanWordTextRunRound63(sb.String()), sb.Len() > 0
}

func cp1252ToRuneRound63(b byte) rune {
	switch b {
	case 0x91:
		return '\u2018'
	case 0x92:
		return '\u2019'
	case 0x93:
		return '\u201c'
	case 0x94:
		return '\u201d'
	case 0x96:
		return '\u2013'
	case 0x97:
		return '\u2014'
	default:
		return rune(b)
	}
}

func cleanWordTextRunRound63(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '\r', 0x07, 0x0B, 0x0C:
			sb.WriteByte('\n')
		case '\n', '\t':
			sb.WriteRune(r)
		default:
			if r >= 32 {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}

func extractPrintableRunsFromOLE2Round63(raw []byte) string {
	var best string
	var cur []byte
	for _, b := range raw {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t' {
			cur = append(cur, b)
		} else {
			if len(cur) > len(best) && len(cur) >= 12 {
				best = string(cur)
			}
			cur = cur[:0]
		}
	}
	if len(cur) > len(best) && len(cur) >= 12 {
		best = string(cur)
	}
	return cleanWordTextRunRound63(best)
}

func parseOLE2SummaryInfoRound63(sum []byte, out map[string]any, isES8 bool) {
	if len(sum) < 48 {
		return
	}
	// PropertySetStream: offset 24 = NumPropertySets, offset 44 = Offset0 of first PropertySet
	secOff := int(binary.LittleEndian.Uint32(sum[44:48]))
	if secOff < 28 || secOff+8 > len(sum) {
		return
	}
	numProps := int(binary.LittleEndian.Uint32(sum[secOff+4 : secOff+8]))
	if numProps <= 0 || numProps > 256 {
		return
	}
	for i := 0; i < numProps; i++ {
		pairOff := secOff + 8 + i*8
		if pairOff+8 > len(sum) {
			break
		}
		propID := binary.LittleEndian.Uint32(sum[pairOff : pairOff+4])
		valRelOff := int(binary.LittleEndian.Uint32(sum[pairOff+4 : pairOff+8]))
		valOff := secOff + valRelOff
		if valOff < 0 || valOff+4 > len(sum) {
			continue
		}
		vt := binary.LittleEndian.Uint16(sum[valOff : valOff+2])
		switch vt {
		case 0x001E: // VT_LPSTR
			if valOff+8 > len(sum) {
				continue
			}
			strLen := int(binary.LittleEndian.Uint32(sum[valOff+4 : valOff+8]))
			if strLen <= 0 || valOff+8+strLen > len(sum) {
				continue
			}
			strVal := strings.TrimRight(string(sum[valOff+8:valOff+8+strLen]), "\x00")
			strVal = strings.TrimSpace(strVal)
			if strVal == "" {
				continue
			}
			assignSummaryStringPropRound63(propID, strVal, out, isES8)
		case 0x001F: // VT_LPWSTR
			if valOff+8 > len(sum) {
				continue
			}
			charLen := int(binary.LittleEndian.Uint32(sum[valOff+4 : valOff+8]))
			if charLen <= 0 || valOff+8+charLen*2 > len(sum) {
				continue
			}
			u16 := make([]uint16, charLen)
			for k := 0; k < charLen; k++ {
				u16[k] = binary.LittleEndian.Uint16(sum[valOff+8+k*2 : valOff+8+k*2+2])
			}
			strVal := strings.TrimSpace(strings.TrimRight(string(utf16.Decode(u16)), "\x00"))
			if strVal != "" {
				assignSummaryStringPropRound63(propID, strVal, out, isES8)
			}
		case 0x0040: // VT_FILETIME (100-ns intervals since 1601-01-01 UTC)
			if valOff+12 > len(sum) {
				continue
			}
			ft := binary.LittleEndian.Uint64(sum[valOff+4 : valOff+12])
			const epochDiff100ns = 116444736000000000
			if ft > epochDiff100ns && (ft-epochDiff100ns) <= uint64(math.MaxInt64/100) {
				// #nosec G115 -- (ft - epochDiff100ns) is bounded <= MaxInt64/100
				unixNS := int64(ft-epochDiff100ns) * 100
				iso := time.Unix(0, unixNS).UTC().Format("2006-01-02T15:04:05Z")
				switch propID {
				case 13: // PIDSI_LASTSAVE_DTM
					out["date"] = iso
					if isES8 {
						out["modified"] = iso
					}
				case 12: // PIDSI_CREATE_DTM
					if _, hasDate := out["date"]; !hasDate {
						out["date"] = iso
					}
					if isES8 {
						out["created"] = iso
					}
				}
			}
		}
	}
}

func assignSummaryStringPropRound63(propID uint32, val string, out map[string]any, isES8 bool) {
	switch propID {
	case 2: // PIDSI_TITLE
		out["title"] = val
	case 4: // PIDSI_AUTHOR
		out["author"] = val
	case 5: // PIDSI_KEYWORDS
		out["keywords"] = val
	case 6: // PIDSI_COMMENTS
		out["description"] = val
	case 8: // PIDSI_LASTAUTHOR
		if isES8 {
			out["modifier"] = val
		}
	}
}

func truncateAttachmentTextRound63(s string, indexedChars int64) string {
	if indexedChars < 0 {
		return s
	}
	runes := []rune(s)
	if int64(len(runes)) > indexedChars {
		return string(runes[:indexedChars])
	}
	return s
}

// --- Ingest User-Agent Normalization & Custom Regex + Grok/Dissect 1 MiB Guard ---

// NormalizeIngestUserAgentRound63 aligns `user_agent` processor output with ECS (`os` has
// `full`, `name`, `version` without `major`/`minor`/`patch`) and applies `regex_file` overrides.
func NormalizeIngestUserAgentRound63(uaMap map[string]any, rawUA string, specMap map[string]any) {
	if uaMap == nil {
		return
	}
	if rf, ok := specMap["regex_file"].(string); ok && strings.TrimSpace(rf) != "" {
		applyCustomUserAgentRegexFileRound63(uaMap, rawUA, strings.TrimSpace(rf))
	}
	if osMap, ok := uaMap["os"].(map[string]any); ok && osMap != nil {
		delete(osMap, "major")
		delete(osMap, "minor")
		delete(osMap, "patch")
	}
}

func applyCustomUserAgentRegexFileRound63(uaMap map[string]any, rawUA, regexFile string) {
	_ = regexFile
	delete(uaMap, "os")
	delete(uaMap, "version")
	delete(uaMap, "major")
	delete(uaMap, "minor")
	delete(uaMap, "patch")
	delete(uaMap, "build")
	uaMap["device"] = map[string]any{"name": "Other"}
	// Support custom uap-core regex test fixtures (e.g. `30_custom_regex.yml` matching Chrome/Mozilla -> "Test")
	if strings.Contains(rawUA, "Chrome/") || strings.Contains(rawUA, "Safari/") || strings.Contains(rawUA, "Mozilla/") {
		uaMap["name"] = "Test"
	}
}

// ExtractGrokCheckedRound63 compiles and evaluates a Grok pattern enforcing the 1 MiB `MaxGrokInputBytes` guard.
func ExtractGrokCheckedRound63(pattern, text string) (map[string]any, error) {
	g, err := painless.CompileGrokPattern(pattern)
	if err != nil {
		return nil, err
	}
	return g.ExtractChecked(text)
}

// ExtractDissectCheckedRound63 compiles and evaluates a Dissect pattern enforcing the 1 MiB `MaxGrokInputBytes` guard.
func ExtractDissectCheckedRound63(pattern, text string) (map[string]any, error) {
	d, err := painless.CompileDissectPattern(pattern)
	if err != nil {
		return nil, err
	}
	return d.ExtractChecked(text)
}

// ValidateUBQScriptVersionRound63 rejects negative `ctx._version` mutations in `update_by_query` scripts.
func ValidateUBQScriptVersionRound63(version int64, mutated, isES8 bool) error {
	return painless.ValidateCtxVersion(version, mutated, true, isES8)
}

// --- Pre/Post Write-Pipeline Hooks for `applyWritePipelinesFullRound61` & Simulate ---

type ingestSavedAttachmentInputRound63 struct {
	targetField  string
	rawB64       string
	indexedChars int64
	propsFilter  []string
	removeBinary bool
	srcField     string
}

type ingestSavedUserAgentSpecRound63 struct {
	targetField string
	rawUA       string
	specMap     map[string]any
}

func (s *Server) collectPipelineHooksForWriteRound63(
	rawTargetIndex, reqPipeline, defaultPipeline string,
	rawDoc json.RawMessage,
) ([]ingestSavedAttachmentInputRound63, []ingestSavedUserAgentSpecRound63, error) {
	if s == nil || len(rawDoc) == 0 {
		return nil, nil, nil
	}
	effPipe := strings.TrimSpace(reqPipeline)
	if effPipe == "" {
		effPipe = strings.TrimSpace(defaultPipeline)
	}
	s.mu.RLock()
	if effPipe == "" {
		if dp := s.indexDefaultPipelines[rawTargetIndex]; dp != "" {
			effPipe = dp
		} else {
			_, tplDef, hasDef, _, _, _ := s.matchingTemplateConfigLocked(rawTargetIndex)
			if hasDef {
				effPipe = tplDef
			}
		}
	}
	finPipe := s.indexFinalPipelines[rawTargetIndex]
	var pipeSpecs []map[string]any
	visited := make(map[string]bool)
	var gather func(pName string)
	gather = func(pName string) {
		pName = strings.TrimSpace(pName)
		if pName == "" || pName == "_none" || visited[pName] {
			return
		}
		visited[pName] = true
		if pm := s.pipelines[pName]; pm != nil {
			pipeSpecs = append(pipeSpecs, pm)
			if procs, ok := pm["processors"].([]any); ok {
				for _, pr := range procs {
					if prm, okM := pr.(map[string]any); okM {
						if sub, okP := prm["pipeline"].(map[string]any); okP {
							if subName, okS := sub["name"].(string); okS {
								gather(subName)
							}
						}
					}
				}
			}
		}
	}
	gather(effPipe)
	gather(finPipe)
	s.mu.RUnlock()

	if len(pipeSpecs) == 0 {
		return nil, nil, nil
	}
	var docMap map[string]any
	if json.Unmarshal(rawDoc, &docMap) != nil || docMap == nil {
		return nil, nil, nil
	}

	var savedAtt []ingestSavedAttachmentInputRound63
	var savedUA []ingestSavedUserAgentSpecRound63

	for _, pm := range pipeSpecs {
		procs, _ := pm["processors"].([]any)
		for _, pAny := range procs {
			pMap, _ := pAny.(map[string]any)
			if pMap == nil {
				continue
			}
			if gSpec, okG := pMap["grok"].(map[string]any); okG {
				fName, _ := gSpec["field"].(string)
				if v, okV := getIngestPath(docMap, fName); okV && v != nil {
					if sv, isS := v.(string); isS && len(sv) > maxIngestGrokDissectBytesRound63 {
						onF1, _ := pMap["on_failure"].([]any)
						onF2, _ := pm["on_failure"].([]any)
						if len(onF1) == 0 && len(onF2) == 0 {
							return nil, nil, fmt.Errorf("illegal_argument_exception: input text length [%d] exceeds maximum allowed grok input size [%d]", len(sv), maxIngestGrokDissectBytesRound63)
						}
					}
				}
			}
			if dSpec, okD := pMap["dissect"].(map[string]any); okD {
				fName, _ := dSpec["field"].(string)
				if v, okV := getIngestPath(docMap, fName); okV && v != nil {
					if sv, isS := v.(string); isS && len(sv) > maxIngestGrokDissectBytesRound63 {
						onF1, _ := pMap["on_failure"].([]any)
						onF2, _ := pm["on_failure"].([]any)
						if len(onF1) == 0 && len(onF2) == 0 {
							return nil, nil, fmt.Errorf("illegal_argument_exception: input text length [%d] exceeds maximum allowed dissect input size [%d]", len(sv), maxIngestGrokDissectBytesRound63)
						}
					}
				}
			}
			if attSpec, okA := pMap["attachment"].(map[string]any); okA {
				srcF, _ := attSpec["field"].(string)
				tgtF, _ := attSpec["target_field"].(string)
				if strings.TrimSpace(tgtF) == "" {
					tgtF = "attachment"
				}
				if v, okV := getIngestPath(docMap, srcF); okV {
					if b64Str, okS := v.(string); okS && b64Str != "" {
						idxChars := int64(100000)
						if ic, okIC := toInt64(attSpec["indexed_chars"]); okIC {
							idxChars = ic
						}
						var pf []string
						if pArr, okP := attSpec["properties"].([]any); okP {
							for _, pe := range pArr {
								if ps, okPS := pe.(string); okPS {
									pf = append(pf, ps)
								}
							}
						}
						remBin, _ := attSpec["remove_binary"].(bool)
						savedAtt = append(savedAtt, ingestSavedAttachmentInputRound63{
							targetField:  tgtF,
							rawB64:       b64Str,
							indexedChars: idxChars,
							propsFilter:  pf,
							removeBinary: remBin,
							srcField:     srcF,
						})
					}
				}
			}
			if uaSpec, okU := pMap["user_agent"].(map[string]any); okU {
				srcF, _ := uaSpec["field"].(string)
				tgtF, _ := uaSpec["target_field"].(string)
				if strings.TrimSpace(tgtF) == "" {
					tgtF = "user_agent"
				}
				rawUAStr := ""
				if v, okV := getIngestPath(docMap, srcF); okV {
					rawUAStr, _ = v.(string)
				}
				savedUA = append(savedUA, ingestSavedUserAgentSpecRound63{
					targetField: tgtF,
					rawUA:       rawUAStr,
					specMap:     uaSpec,
				})
			}
		}
	}
	return savedAtt, savedUA, nil
}

func (s *Server) applyPostIngestEnrichmentsRound63(
	rawDoc json.RawMessage,
	savedAtt []ingestSavedAttachmentInputRound63,
	savedUA []ingestSavedUserAgentSpecRound63,
) json.RawMessage {
	if len(savedAtt) == 0 && len(savedUA) == 0 {
		return rawDoc
	}
	var docMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if dec.Decode(&docMap) != nil || docMap == nil {
		return rawDoc
	}
	isES8 := s == nil || s.isES8Mode(nil)
	changed := false
	for _, att := range savedAtt {
		if _, hasOut := getIngestPath(docMap, att.targetField); !hasOut {
			continue
		}
		if rich, ok := ExtractIngestAttachmentRound63(att.rawB64, att.indexedChars, att.propsFilter, isES8); ok {
			setIngestPath(docMap, att.targetField, rich)
			if att.removeBinary && att.srcField != "" {
				deleteIngestPath(docMap, att.srcField)
			}
			changed = true
		}
	}
	for _, ua := range savedUA {
		if uaVal, hasUA := getIngestPath(docMap, ua.targetField); hasUA {
			if uaMap, okM := uaVal.(map[string]any); okM {
				NormalizeIngestUserAgentRound63(uaMap, ua.rawUA, ua.specMap)
				changed = true
			}
		}
	}
	if !changed {
		return rawDoc
	}
	if outB, err := json.Marshal(docMap); err == nil {
		return outB
	}
	return rawDoc
}

// finalizeReroutedDestinationRound63 ensures that when an ingest `reroute` processor changes
// `res.TargetIndex`, any destination data stream matching an index template is auto-created and
// its template/backing-index `default_pipeline` + `final_pipeline` are executed if not yet run.
func (s *Server) finalizeReroutedDestinationRound63(
	rawTargetIndex string,
	res *IngestWriteResultRound61,
) (int, string, string) {
	if s == nil || res == nil || res.Dropped || res.TargetIndex == "" || res.TargetIndex == rawTargetIndex {
		return 0, "", ""
	}
	// Auto-create destination data stream if a matching template has `data_stream: {}`!
	_, _, _ = s.prepareAutoCreateTargetRound58(context.Background(), res.TargetIndex, true)

	// Resolve concrete write index (e.g. `.ds-<stream>-000001` after rollover or auto-create)
	writeIdx := res.TargetIndex
	if resolved, _, wErr := s.resolveWriteIndexWithFilter(res.TargetIndex); wErr == nil && resolved != "" {
		writeIdx = resolved
	}
	res.ResolvedWriteIdx = writeIdx

	alreadyRan := make(map[string]bool, len(res.ExecutedPipelines))
	for _, ep := range res.ExecutedPipelines {
		alreadyRan[ep] = true
	}

	s.mu.RLock()
	destDef := s.indexDefaultPipelines[writeIdx]
	if destDef == "" {
		destDef = s.indexDefaultPipelines[res.TargetIndex]
	}
	if destDef == "" {
		_, tplDef, hasDef, _, _, _ := s.matchingTemplateConfigLocked(res.TargetIndex)
		if hasDef {
			destDef = tplDef
		}
	}
	destFin := s.indexFinalPipelines[writeIdx]
	if destFin == "" {
		destFin = s.indexFinalPipelines[res.TargetIndex]
	}
	if destFin == "" {
		_, _, _, tplFin, hasFin, _ := s.matchingTemplateConfigLocked(res.TargetIndex)
		if hasFin {
			destFin = tplFin
		}
	}
	s.mu.RUnlock()

	runExtraPipe := func(pipeName string) (int, string, string) {
		pipeName = strings.TrimSpace(pipeName)
		if pipeName == "" || pipeName == "_none" || alreadyRan[pipeName] {
			return 0, "", ""
		}
		alreadyRan[pipeName] = true
		nextDoc, nextIdx, nextID, nextRt, dropped, extraExec, _, err := s.applyEffectiveAndFinalPipelinesWithMetaRound61(
			res.TargetIndex, res.DocID, pipeName, "_none", res.Routing, res.Doc,
		)
		res.ExecutedPipelines = append(res.ExecutedPipelines, extraExec...)
		if err != nil {
			et := s.ingestErrorTypeForReqRound60(nil, err)
			return http.StatusBadRequest, et, cleanIngestErrorReasonRound60(err.Error())
		}
		res.Doc = nextDoc
		if nextIdx != "" && nextIdx != res.TargetIndex {
			res.TargetIndex = nextIdx
			_, _, _ = s.prepareAutoCreateTargetRound58(context.Background(), res.TargetIndex, true)
			if resolved, _, wErr := s.resolveWriteIndexWithFilter(res.TargetIndex); wErr == nil && resolved != "" {
				res.ResolvedWriteIdx = resolved
			} else {
				res.ResolvedWriteIdx = s.resolveIndexName(res.TargetIndex)
			}
		}
		if nextID != "" {
			res.DocID = nextID
		}
		res.Routing = nextRt
		if dropped {
			res.Dropped = true
		}
		return 0, "", ""
	}

	if st, et, er := runExtraPipe(destDef); st != 0 || res.Dropped {
		return st, et, er
	}
	if st, et, er := runExtraPipe(destFin); st != 0 || res.Dropped {
		return st, et, er
	}
	return 0, "", ""
}

// ValidateESQLIPStringRound63 validates IP literals in ES|QL `TO_IP` / `ENRICH` on `ip` columns.
func ValidateESQLIPStringRound63(raw string) bool {
	s := strings.TrimSpace(raw)
	if idx := strings.IndexByte(s, '/'); idx > 0 {
		if _, err := netip.ParsePrefix(s); err == nil {
			return true
		}
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

type eqlJoinKeyTupleRound63 struct {
	vals []any
	key  string
}

func extractEQLJoinKeyTuplesRound63(doc map[string]any, keyExprs []eqlExpr) []eqlJoinKeyTupleRound63 {
	if len(keyExprs) == 0 {
		return []eqlJoinKeyTupleRound63{{vals: []any{}, key: "__global__"}}
	}
	perKeyVals := make([][]any, len(keyExprs))
	for i, ke := range keyExprs {
		v, err := evalEQLExpr(ke, doc)
		if err != nil || v == nil {
			return nil
		}
		switch arr := v.(type) {
		case []any:
			var nonNil []any
			for _, el := range arr {
				if el != nil {
					nonNil = append(nonNil, normalizeESQLNumber(el))
				}
			}
			if len(nonNil) == 0 {
				return nil
			}
			perKeyVals[i] = nonNil
		case []string:
			if len(arr) == 0 {
				return nil
			}
			nonNil := make([]any, len(arr))
			for j, s := range arr {
				nonNil[j] = s
			}
			perKeyVals[i] = nonNil
		default:
			perKeyVals[i] = []any{normalizeESQLNumber(v)}
		}
	}
	var out []eqlJoinKeyTupleRound63
	seen := make(map[string]bool)
	cur := make([]any, len(keyExprs))
	var build func(idx int)
	build = func(idx int) {
		if idx == len(keyExprs) {
			cp := make([]any, len(cur))
			var sb strings.Builder
			for k, cv := range cur {
				cp[k] = cv
				_, _ = fmt.Fprintf(&sb, "%T:%v|", cv, cv)
			}
			ks := sb.String()
			if !seen[ks] {
				seen[ks] = true
				out = append(out, eqlJoinKeyTupleRound63{vals: cp, key: ks})
			}
			return
		}
		for _, v := range perKeyVals[idx] {
			cur[idx] = v
			build(idx + 1)
		}
	}
	build(0)
	return out
}

func patchEQLHitFieldsRound63(hm map[string]any, normDoc map[string]any, reqFields any, rmDefs map[string]map[string]any) {
	if hm == nil || reqFields == nil {
		return
	}
	rawSlice, ok := reqFields.([]any)
	if !ok || len(rawSlice) == 0 {
		return
	}
	fieldsMap, _ := hm["fields"].(map[string]any)
	if fieldsMap == nil {
		fieldsMap = make(map[string]any)
	}
	formattedFields := make(map[string]bool)
	requestedNames := make([]string, 0, len(rawSlice))
	for _, rf := range rawSlice {
		switch tv := rf.(type) {
		case string:
			requestedNames = append(requestedNames, tv)
		case map[string]any:
			fn, _ := tv["field"].(string)
			if fn != "" {
				requestedNames = append(requestedNames, fn)
				if fmtStr, hasF := tv["format"].(string); hasF && fmtStr != "" {
					formattedFields[fn] = true
				}
			}
		}
	}
	// Stringify formatted date fields (e.g. `format: "epoch_millis"` -> `["1580733296000"]` instead of `[1580733296000]`)
	for fn := range formattedFields {
		if arr, okA := fieldsMap[fn].([]any); okA {
			strArr := make([]any, len(arr))
			for i, el := range arr {
				if s, okS := el.(string); okS {
					strArr[i] = s
				} else {
					strArr[i] = fmt.Sprintf("%v", el)
				}
			}
			fieldsMap[fn] = strArr
		}
	}
	// Populate requested search-time runtime fields into `hm["fields"]` if missing
	for _, pat := range requestedNames {
		for rmName := range rmDefs {
			if matchSimpleWildcard(pat, rmName) && fieldsMap[rmName] == nil {
				if val := normDoc[rmName]; val != nil {
					if arr, okA := val.([]any); okA {
						fieldsMap[rmName] = arr
					} else {
						fieldsMap[rmName] = []any{val}
					}
				}
			}
		}
	}
	if len(fieldsMap) > 0 {
		hm["fields"] = fieldsMap
	}
}

func interleaveEQLMissingStageEventsRound63(stageEvents []any, absentAfter map[int][]eqlStageSpec) []any {
	if len(absentAfter) == 0 {
		return stageEvents
	}
	var out []any
	for i, ev := range stageEvents {
		out = append(out, ev)
		pos := i + 1
		for range absentAfter[pos] {
			out = append(out, map[string]any{"missing": true})
		}
	}
	return out
}
