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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func catIndexUUID22(indexName string) string {
	sum := sha256.Sum256([]byte("es-uuid:" + indexName))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func generateESAutoIDRound60() string {
	var b [15]byte
	if _, err := rand.Read(b[:]); err == nil {
		return base64.RawURLEncoding.EncodeToString(b[:])
	}
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return base64.RawURLEncoding.EncodeToString(sum[:15])
}

// DorisPhysicalDeleteBackend is implemented by MemoryBackend and DorisSQLBackend to execute
// physical/MoW SQL DELETE by `_id`, clearing Doris's `function_column.sequence_col = "_version"`
// floor so re-created documents can start cleanly at `_version = 1`.
type DorisPhysicalDeleteBackend interface {
	DeleteDocsByIDs(ctx context.Context, db, table string, ids []string) error
}

func (s *Server) physicalDeleteDocs(ctx context.Context, idxSchema *schema.IndexSchema, ids []string) (bool, error) {
	if idxSchema == nil || len(ids) == 0 {
		return false, nil
	}
	pdb, ok := s.backend.(DorisPhysicalDeleteBackend)
	if !ok {
		return false, nil
	}
	_ = s.coalescer.FlushTable(ctx, idxSchema.DorisTable)
	if err := pdb.DeleteDocsByIDs(ctx, idxSchema.DorisDB, idxSchema.DorisTable, ids); err != nil {
		return true, err
	}
	s.queryCache.InvalidateAll()
	return true, nil
}

// SetTargetESVersion configures the default Elasticsearch wire compatibility version
// (e.g. "7.17.0" or "8.15.5").
func (s *Server) SetTargetESVersion(ver string) {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		ver = "7.10.2"
	}
	s.mu.Lock()
	s.targetESVersion = ver
	s.explicitTargetESVersion = true
	s.mu.Unlock()
}

func (s *Server) hasExplicitTargetESVersion() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	v := s.explicitTargetESVersion
	s.mu.RUnlock()
	return v
}

func (s *Server) getTargetESVersion() string {
	if s == nil {
		return "7.10.2"
	}
	s.mu.RLock()
	ver := s.targetESVersion
	s.mu.RUnlock()
	if ver == "" {
		return "7.10.2"
	}
	return ver
}

// isES8Mode reports whether the server or the inbound request negotiated ES 8 compatibility.
func (s *Server) isES8Mode(r *http.Request) bool {
	if r != nil {
		accept := r.Header.Get("Accept")
		ct := r.Header.Get("Content-Type")
		if strings.Contains(accept, "compatible-with=8") || strings.Contains(ct, "compatible-with=8") {
			return true
		}
		if strings.Contains(accept, "compatible-with=7") || strings.Contains(ct, "compatible-with=7") {
			return false
		}
	}
	return strings.HasPrefix(s.getTargetESVersion(), "8.")
}

func (s *Server) effectiveClusterESVersionNumber(r *http.Request) string {
	ver := s.getTargetESVersion()
	if s.isES8Mode(r) {
		if strings.HasPrefix(ver, "8.") {
			return ver
		}
		return "8.15.5"
	}
	if strings.HasPrefix(ver, "7.") {
		return ver
	}
	return "7.10.2"
}

func extractCompatibleWithParam(hdrVal string) (string, bool) {
	if !strings.Contains(strings.ToLower(hdrVal), "compatible-with") {
		return "", false
	}
	for _, mediaPart := range strings.Split(hdrVal, ",") {
		params := strings.Split(mediaPart, ";")
		for _, p := range params[1:] {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if strings.EqualFold(strings.TrimSpace(kv[0]), "compatible-with") {
				if len(kv) < 2 {
					return "", true
				}
				return strings.Trim(strings.TrimSpace(kv[1]), `"`), true
			}
		}
	}
	return "", false
}

// validateWireAcceptAndCompatHeadersRound60 enforces ES 7/8 Content-Type & Accept media-type
// negotiation rules, returning false after writing HTTP 406 Not Acceptable when invalid.
func (s *Server) validateWireAcceptAndCompatHeadersRound60(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return true
	}
	accept := strings.TrimSpace(r.Header.Get("Accept"))
	reqCT := strings.TrimSpace(r.Header.Get("Content-Type"))

	accCompat, hasAccCompat := extractCompatibleWithParam(accept)
	ctCompat, hasCTCompat := extractCompatibleWithParam(reqCT)

	if hasAccCompat && accCompat != "7" && accCompat != "8" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		writeESError(w, http.StatusNotAcceptable, "not_acceptable_exception",
			fmt.Sprintf("Compatible-with version [%s] is not supported; must be 7 or 8", accCompat))
		return false
	}
	if hasCTCompat && ctCompat != "7" && ctCompat != "8" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		writeESError(w, http.StatusNotAcceptable, "not_acceptable_exception",
			fmt.Sprintf("Content-Type compatible-with version [%s] is not supported; must be 7 or 8", ctCompat))
		return false
	}
	if hasAccCompat && hasCTCompat && accCompat != ctCompat {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		writeESError(w, http.StatusNotAcceptable, "not_acceptable_exception",
			fmt.Sprintf("Accept version [%s] conflicts with Content-Type version [%s]", accCompat, ctCompat))
		return false
	}
	if strings.Contains(strings.ToLower(reqCT), "application/vnd.elasticsearch+") && !hasCTCompat {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		writeESError(w, http.StatusNotAcceptable, "not_acceptable_exception",
			"Content-Type [application/vnd.elasticsearch+...] requires compatible-with parameter")
		return false
	}
	if accept != "" {
		acceptable := false
		for _, rawMedia := range strings.Split(accept, ",") {
			semi := strings.Split(strings.TrimSpace(rawMedia), ";")
			mt := strings.ToLower(strings.TrimSpace(semi[0]))
			if mt == "" {
				continue
			}
			switch mt {
			case "*/*", "application/*", "text/*",
				"application/json", "application/x-ndjson",
				"application/yaml", "application/cbor", "application/smile",
				"text/plain", "text/html", "text/yaml":
				acceptable = true
			case "application/vnd.elasticsearch+json",
				"application/vnd.elasticsearch+x-ndjson",
				"application/vnd.elasticsearch+yaml",
				"application/vnd.elasticsearch+cbor",
				"application/vnd.elasticsearch+smile":
				if hasAccCompat && (accCompat == "7" || accCompat == "8") {
					acceptable = true
				}
			}
		}
		if !acceptable {
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			writeESError(w, http.StatusNotAcceptable, "not_acceptable_exception",
				fmt.Sprintf("Header Accept=[%s] is not supported", accept))
			return false
		}
	}
	return true
}

type legacyDocTypeCtxKey struct{}

func withLegacyDocType(r *http.Request, docType string) *http.Request {
	if r == nil || docType == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), legacyDocTypeCtxKey{}, docType))
}

func explicitLegacyDocTypeFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v, ok := r.Context().Value(legacyDocTypeCtxKey{}).(string); ok && v != "" {
		return v
	}
	if pv := strings.TrimSpace(r.PathValue("type")); pv != "" {
		return pv
	}
	return ""
}

func legacyDocTypeFromRequest(r *http.Request) string {
	if t := explicitLegacyDocTypeFromRequest(r); t != "" {
		return t
	}
	return "_doc"
}

func (s *Server) applyDocTypeFieldRound60(m map[string]any, r *http.Request, explicitType string) {
	if m == nil {
		return
	}
	if foundVal, okF := m["found"].(bool); okF && foundVal && r != nil && isTruthyBoolQueryParam(r, "force_synthetic_source") {
		m[forceSynSourceMarkerKeyR62Admin] = true
	}
	if s.isES8Mode(r) {
		delete(m, "_type")
		return
	}
	reqType := explicitType
	if reqType == "" {
		reqType = explicitLegacyDocTypeFromRequest(r)
	}
	if reqType == "" && r != nil && r.URL != nil {
		up := r.URL.Path
		if strings.Contains(up, "/_doc") || strings.Contains(up, "/_create") || strings.Contains(up, "/_update") {
			m["_type"] = "_doc"
			return
		}
	}
	if reqType == "" || reqType == "_all" {
		if idxName, _ := m["_index"].(string); idxName != "" && s != nil {
			s.mu.RLock()
			idx := s.indices[idxName]
			s.mu.RUnlock()
			if idx != nil && idx.LegacyTypeName != "" {
				m["_type"] = idx.LegacyTypeName
				return
			}
		}
		m["_type"] = "_doc"
		return
	}
	m["_type"] = reqType
}

// ---------- Per-Index SeqNo & Per-Document Monotonic Versioning ----------

type persistedIndexSeqState struct {
	NextSeqNo int64 `json:"next_seq_no"`
}

func (s *Server) allocIndexSeqNo(ctx context.Context, indexName string) int64 {
	s.mu.Lock()
	if s.indexNextSeqNo == nil {
		s.indexNextSeqNo = make(map[string]int64)
	}
	seq := s.indexNextSeqNo[indexName]
	s.indexNextSeqNo[indexName] = seq + 1
	nextToPersist := seq + 1
	s.mu.Unlock()
	s.persistIndexSeqState(ctx, indexName, nextToPersist)
	return seq
}

func (s *Server) persistIndexSeqState(ctx context.Context, indexName string, nextSeq int64) {
	if indexName == "" {
		return
	}
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(persistedIndexSeqState{NextSeqNo: nextSeq}); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "index_seq_state",
				EntityKey:      indexName,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) recordDocWriteMetaRound60(indexName, docID string, ver, seqNo int64) {
	if indexName == "" || docID == "" {
		return
	}
	s.mu.Lock()
	if s.docVersions == nil {
		s.docVersions = make(map[string]map[string]int64)
	}
	if s.docVersions[indexName] == nil {
		s.docVersions[indexName] = make(map[string]int64)
	}
	s.docVersions[indexName][docID] = ver
	boundInt64DocMapLockedR62Admin(s.docVersions[indexName], docID)

	if s.docSeqNos == nil {
		s.docSeqNos = make(map[string]map[string]int64)
	}
	if s.docSeqNos[indexName] == nil {
		s.docSeqNos[indexName] = make(map[string]int64)
	}
	s.docSeqNos[indexName][docID] = seqNo
	boundInt64DocMapLockedR62Admin(s.docSeqNos[indexName], docID)

	if s.docRouting != nil && s.docRouting[indexName] != nil {
		boundStringDocMapLockedR62Admin(s.docRouting[indexName], docID)
	}
	if s.docDeleted != nil && s.docDeleted[indexName] != nil {
		delete(s.docDeleted[indexName], docID)
	}
	if s.docExtTombstones != nil && s.docExtTombstones[indexName] != nil {
		delete(s.docExtTombstones[indexName], docID)
	}
	s.mu.Unlock()
}

func (s *Server) recordDocDeleteMetaRound60(indexName, docID string, delVer, seqNo int64, isExternal bool) {
	if indexName == "" || docID == "" {
		return
	}
	s.mu.Lock()
	if s.docVersions != nil && s.docVersions[indexName] != nil {
		delete(s.docVersions[indexName], docID)
	}
	if s.docSeqNos == nil {
		s.docSeqNos = make(map[string]map[string]int64)
	}
	if s.docSeqNos[indexName] == nil {
		s.docSeqNos[indexName] = make(map[string]int64)
	}
	s.docSeqNos[indexName][docID] = seqNo
	boundInt64DocMapLockedR62Admin(s.docSeqNos[indexName], docID)

	if s.docDeleted == nil {
		s.docDeleted = make(map[string]map[string]bool)
	}
	if s.docDeleted[indexName] == nil {
		s.docDeleted[indexName] = make(map[string]bool)
	}
	s.docDeleted[indexName][docID] = true
	boundBoolDocMapLockedR62Admin(s.docDeleted[indexName], docID)

	if isExternal {
		if s.docExtTombstones == nil {
			s.docExtTombstones = make(map[string]map[string]int64)
		}
		if s.docExtTombstones[indexName] == nil {
			s.docExtTombstones[indexName] = make(map[string]int64)
		}
		s.docExtTombstones[indexName][docID] = delVer
		boundInt64DocMapLockedR62Admin(s.docExtTombstones[indexName], docID)
	} else if s.docExtTombstones != nil && s.docExtTombstones[indexName] != nil {
		delete(s.docExtTombstones[indexName], docID)
	}
	s.mu.Unlock()
}

func (s *Server) wasDocDeletedRound60(indexName, docID string) bool {
	if indexName == "" || docID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.docDeleted == nil {
		return false
	}
	return s.docDeleted[indexName][docID]
}

func (s *Server) getDocSeqNo(indexName, docID string, fallbackVer int64) int64 {
	if indexName != "" && docID != "" {
		s.mu.RLock()
		if s.docSeqNos != nil {
			if m, ok := s.docSeqNos[indexName]; ok {
				if seq, has := m[docID]; has {
					s.mu.RUnlock()
					return seq
				}
			}
		}
		s.mu.RUnlock()
	}
	if fallbackVer > 0 {
		return fallbackVer - 1
	}
	return 0
}

func (s *Server) getDocExternalTombstone(indexName, docID string) (int64, bool) {
	if indexName == "" || docID == "" {
		return 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.docExtTombstones == nil {
		return 0, false
	}
	if m, ok := s.docExtTombstones[indexName]; ok {
		v, has := m[docID]
		return v, has
	}
	return 0, false
}

// ---------- UTF-16LE Murmur3 Shard Routing & Unrefreshed Buffer Overlay ----------

func defaultESRoutingNumShards(numShards int) int {
	if numShards <= 1 {
		return 1
	}
	routingShards := numShards
	for routingShards*2 <= 1024 {
		routingShards *= 2
	}
	return routingShards
}

// esMurmur3HashUTF16LE computes Elasticsearch's Murmur3HashFunction.hash(String routing),
// which hashes UTF-16LE code units with MurmurHash3_x86_32(seed = 0).
func esMurmur3HashUTF16LE(routing string) int32 {
	u16 := utf16.Encode([]rune(routing))
	byteLen := len(u16) * 2
	buf := make([]byte, byteLen)
	for i, cu := range u16 {
		buf[i*2] = byte(cu) // #nosec G115 -- intentional UTF-16LE low byte
		buf[i*2+1] = byte(cu >> 8)
	}
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	var h1 uint32
	nblocks := byteLen / 4
	for i := 0; i < nblocks; i++ {
		off := i * 4
		k1 := uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16 | uint32(buf[off+3])<<24
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}
	tail := buf[nblocks*4:]
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
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(byteLen) // #nosec G115 -- MurmurHash3_x86_32 length mix
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1) // #nosec G115 -- Java signed 32-bit hash
}

func esFloorMod(x, y int) int {
	m := x % y
	if (m^y) < 0 && m != 0 {
		m += y
	}
	return m
}

func esMurmur3Shard(routing string, numShards, routingNumShards int) int {
	if numShards <= 1 {
		return 0
	}
	if routingNumShards < numShards || routingNumShards%numShards != 0 {
		routingNumShards = defaultESRoutingNumShards(numShards)
	}
	factor := routingNumShards / numShards
	if factor <= 0 {
		factor = 1
	}
	h := int(esMurmur3HashUTF16LE(routing))
	return esFloorMod(h, routingNumShards) / factor
}

func (s *Server) getIndexShardAndReplicaCounts(indexName string) (numShards, numReplicas, routingNumShards int) {
	numShards = 1
	numReplicas = 0
	s.mu.RLock()
	cs := s.indexCustomSettings[indexName]
	if cs != nil {
		for _, k := range []string{"number_of_shards", "index.number_of_shards"} {
			if raw, ok := cs[k]; ok && raw != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil && n > 0 {
					numShards = n
					break
				}
			}
		}
		for _, k := range []string{"number_of_replicas", "index.number_of_replicas"} {
			if raw, ok := cs[k]; ok && raw != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil && n >= 0 {
					numReplicas = n
					break
				}
			}
		}
		for _, k := range []string{"number_of_routing_shards", "index.number_of_routing_shards"} {
			if raw, ok := cs[k]; ok && raw != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil && n > 0 {
					routingNumShards = n
					break
				}
			}
		}
	}
	s.mu.RUnlock()
	if routingNumShards <= 0 {
		routingNumShards = defaultESRoutingNumShards(numShards)
	}
	return numShards, numReplicas, routingNumShards
}

func (s *Server) shardForDocRoutingRound60(indexName, docID, routing string) int {
	numShards, _, routingShards := s.getIndexShardAndReplicaCounts(indexName)
	if numShards <= 1 {
		return 0
	}
	eff := strings.TrimSpace(routing)
	if eff == "" {
		eff = docID
	}
	return esMurmur3Shard(eff, numShards, routingShards)
}

func (s *Server) isIndexRefreshDisabled(indexName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cs := s.indexCustomSettings[indexName]
	if cs == nil {
		return false
	}
	for _, k := range []string{"refresh_interval", "index.refresh_interval"} {
		if v, ok := cs[k]; ok && v != nil {
			sv := strings.TrimSpace(fmt.Sprintf("%v", v))
			if sv == "-1" {
				return true
			}
		}
	}
	return false
}

// unrefreshedDocState captures the search-visible state of a document BEFORE unrefreshed
// mutations on an index with `refresh_interval: -1`.
type unrefreshedDocState struct {
	existedBefore bool
	prevHit       HitRow
}

func (s *Server) recordPreMutationUnrefreshedState(indexName string, shard int, docID string, existedBefore bool, prevHit *HitRow, refreshedNow bool) {
	if indexName == "" || docID == "" {
		return
	}
	if refreshedNow {
		s.refreshIndexShardRound60(indexName, shard)
		return
	}
	if !s.isIndexRefreshDisabled(indexName) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unrefreshedDocs == nil {
		s.unrefreshedDocs = make(map[string]map[int]map[string]unrefreshedDocState)
	}
	if countTotalUnrefreshedDocsLockedR62Admin(s.unrefreshedDocs) >= maxUnrefreshedDocsTotalR62Admin {
		s.unrefreshedDocs = make(map[string]map[int]map[string]unrefreshedDocState)
	}
	if s.unrefreshedDocs[indexName] == nil {
		s.unrefreshedDocs[indexName] = make(map[int]map[string]unrefreshedDocState)
	}
	if s.unrefreshedDocs[indexName][shard] == nil {
		s.unrefreshedDocs[indexName][shard] = make(map[string]unrefreshedDocState)
	}
	// Preserve the snapshot from the last refresh point; do not overwrite if already buffered!
	if _, alreadyBuffered := s.unrefreshedDocs[indexName][shard][docID]; alreadyBuffered {
		return
	}
	var st unrefreshedDocState
	st.existedBefore = existedBefore
	if existedBefore && prevHit != nil {
		st.prevHit = *prevHit
		st.prevHit.Index = indexName
	}
	s.unrefreshedDocs[indexName][shard][docID] = st
}

func (s *Server) refreshIndexShardRound60(indexName string, shard int) {
	s.mu.Lock()
	if s.unrefreshedDocs != nil && s.unrefreshedDocs[indexName] != nil {
		delete(s.unrefreshedDocs[indexName], shard)
		if len(s.unrefreshedDocs[indexName]) == 0 {
			delete(s.unrefreshedDocs, indexName)
		}
	}
	s.mu.Unlock()
}

func (s *Server) refreshAllIndexShardsRound60(indexName string) {
	s.mu.Lock()
	if s.unrefreshedDocs != nil {
		delete(s.unrefreshedDocs, indexName)
	}
	s.mu.Unlock()
}

func (s *Server) getUnrefreshedDocsForIndex(indexName string) map[string]unrefreshedDocState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.unrefreshedDocs == nil {
		return nil
	}
	byShard := s.unrefreshedDocs[indexName]
	if len(byShard) == 0 {
		return nil
	}
	out := make(map[string]unrefreshedDocState)
	for _, m := range byShard {
		for docID, st := range m {
			out[docID] = st
		}
	}
	return out
}

// parseAndValidateRefreshParamRound60 validates `?refresh=` against ES RefreshPolicy values:
// "" or "true" -> syncRefresh=true, immediateForced=true
// "wait_for"   -> syncRefresh=true, immediateForced=false
// "false" or absent -> syncRefresh=false, immediateForced=false
func parseAndValidateRefreshParamRound60(r *http.Request) (syncRefresh bool, immediateForced bool, err error) {
	if r == nil || r.URL == nil || !r.URL.Query().Has("refresh") {
		return false, false, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get("refresh"))
	switch strings.ToLower(raw) {
	case "", "true":
		return true, true, nil
	case "wait_for":
		return true, false, nil
	case "false":
		return false, false, nil
	default:
		return false, false, fmt.Errorf("Invalid refresh value [%s]; must be [true, false, wait_for]", raw) //nolint:staticcheck // ES exact error message
	}
}

// ---------- F3 & F5 Request Body Pre-Normalizers ----------

func stringifyScalarIDOrRouting(v any) (string, bool) {
	switch tv := v.(type) {
	case string:
		return tv, true
	case json.Number:
		return tv.String(), true
	case float64:
		if tv == math.Trunc(tv) {
			return strconv.FormatInt(int64(tv), 10), true
		}
		return strconv.FormatFloat(tv, 'f', -1, 64), true
	case bool:
		if tv {
			return "true", true
		}
		return "false", true
	default:
		return "", false
	}
}

// normalizeMGetBodyRound60 converts numeric/boolean `ids` and `docs[i]._id` / `routing` / `_routing`
// values to strings so Go struct unmarshaling handles all ES REST spec `_mget` forms cleanly.
func normalizeMGetBodyRound60(raw []byte) ([]byte, int, string, string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: no documents to get;"
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, http.StatusBadRequest, "parse_exception", err.Error()
	}
	if m == nil {
		return nil, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: no documents to get;"
	}
	hasDocs, hasIDs := false, false
	if rawIDs, ok := m["ids"]; ok && rawIDs != nil {
		arr, isArr := rawIDs.([]any)
		if !isArr {
			return nil, http.StatusBadRequest, "parse_exception", "[ids] must be an array"
		}
		hasIDs = len(arr) > 0
		strIDs := make([]any, 0, len(arr))
		for _, item := range arr {
			if item == nil {
				strIDs = append(strIDs, "")
				continue
			}
			sv, okS := stringifyScalarIDOrRouting(item)
			if !okS {
				return nil, http.StatusBadRequest, "parse_exception", "invalid id in [ids]"
			}
			strIDs = append(strIDs, sv)
		}
		m["ids"] = strIDs
	}
	if rawDocs, ok := m["docs"]; ok && rawDocs != nil {
		arr, isArr := rawDocs.([]any)
		if !isArr {
			return nil, http.StatusBadRequest, "parse_exception", "[docs] must be an array"
		}
		hasDocs = len(arr) > 0
		for i, elem := range arr {
			dm, okM := elem.(map[string]any)
			if !okM {
				return nil, http.StatusBadRequest, "parse_exception", "mget doc item must be an object"
			}
			for _, k := range []string{"_id", "routing", "_routing"} {
				if val, exists := dm[k]; exists && val != nil {
					if sv, okS := stringifyScalarIDOrRouting(val); okS {
						dm[k] = sv
					}
				}
			}
			arr[i] = dm
		}
		m["docs"] = arr
	}
	if !hasDocs && !hasIDs {
		return nil, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: no documents to get;"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw, 0, "", ""
	}
	return out, 0, "", ""
}

// normalizeMLTDocIDsInRawJSONRound60 walks decoded JSON to stringify numeric/boolean `_id` and `routing`
// inside `more_like_this` `like` / `unlike` document specifiers.
func normalizeMLTDocIDsInRawJSONRound60(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("more_like_this")) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return raw
	}
	modified := walkNormalizeMLTNode(root)
	if !modified {
		return raw
	}
	out, err := json.Marshal(root)
	if err != nil {
		return raw
	}
	return out
}

func walkNormalizeMLTNode(node any) bool {
	modified := false
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "more_like_this" {
				if mltMap, ok := v.(map[string]any); ok {
					for _, listKey := range []string{"like", "unlike"} {
						if lv, has := mltMap[listKey]; has {
							if normalizeMLTLikeVal(lv) {
								modified = true
							}
						}
					}
				}
			} else if walkNormalizeMLTNode(v) {
				modified = true
			}
		}
	case []any:
		for _, elem := range n {
			if walkNormalizeMLTNode(elem) {
				modified = true
			}
		}
	}
	return modified
}

func normalizeMLTLikeVal(v any) bool {
	modified := false
	switch tv := v.(type) {
	case map[string]any:
		for _, k := range []string{"_id", "routing", "_routing"} {
			if fv, ok := tv[k]; ok && fv != nil {
				if _, isStr := fv.(string); !isStr {
					if sv, okS := stringifyScalarIDOrRouting(fv); okS {
						tv[k] = sv
						modified = true
					}
				}
			}
		}
		if docSub, ok := tv["doc"].(map[string]any); ok {
			if normalizeMLTLikeVal(docSub) {
				modified = true
			}
		}
	case []any:
		for _, item := range tv {
			if normalizeMLTLikeVal(item) {
				modified = true
			}
		}
	}
	return modified
}

type bulkActionMetaInfoRound60 struct {
	explicitEmptyID bool
	missingID       bool
	autoGeneratedID bool
	docType         string
}

// preprocessBulkNDJSONRound60 pre-validates and normalizes `_bulk` NDJSON lines:
// - Empty `{}` action line N -> 400 illegal_argument_exception: "Malformed action/metadata line [N], expected FIELD_NAME but found [END_OBJECT]"
// - Explicit `"_id": ""` -> tracked so handleBulk emits per-item 400 illegal_argument_exception: "if _id is specified it must not be empty"
// - Omitted `"_id"` on `create`/`update`/`delete` -> tracked for per-item 400 action_request_validation_exception
// - `"op_type": "create" | "index"` inside `{"index": {...}}` -> rewritten to create/index action
// - Numeric/boolean `_id` and `routing` / `_routing` -> converted to strings
func preprocessBulkNDJSONRound60(raw []byte) ([]byte, []bulkActionMetaInfoRound60, int, string, string) {
	lines := bytes.Split(raw, []byte{'\n'})
	// Trim single trailing empty line after final '\n'
	if len(lines) > 0 && len(bytes.TrimSpace(lines[len(lines)-1])) == 0 {
		lines = lines[:len(lines)-1]
	}
	var outBuf bytes.Buffer
	var metaInfos []bulkActionMetaInfoRound60

	lineIdx := 0
	for lineIdx < len(lines) {
		lineNum := lineIdx + 1
		line := bytes.TrimRight(lines[lineIdx], "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			lineIdx++
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Malformed action/metadata line [%d], %v", lineNum, err)
		}
		if delim, ok := tok.(json.Delim); !ok || delim != '{' {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Malformed action/metadata line [%d], expected START_OBJECT", lineNum)
		}
		if !dec.More() {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Malformed action/metadata line [%d], expected FIELD_NAME but found [END_OBJECT]", lineNum)
		}

		decFull := json.NewDecoder(bytes.NewReader(trimmed))
		decFull.UseNumber()
		var actionObj map[string]any
		if err := decFull.Decode(&actionObj); err != nil {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Malformed action/metadata line [%d], %v", lineNum, err)
		}
		if len(actionObj) != 1 {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Malformed action/metadata line [%d], expected exactly one action key", lineNum)
		}

		var actName string
		var rawMeta any
		for k, v := range actionObj {
			actName = k
			rawMeta = v
		}
		switch actName {
		case "index", "create", "update", "delete":
		default:
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Invalid bulk action [%s] on line [%d]", actName, lineNum)
		}
		metaMap, okM := rawMeta.(map[string]any)
		if !okM {
			if rawMeta == nil {
				metaMap = map[string]any{}
			} else {
				return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Malformed action/metadata line [%d], action metadata must be an object", lineNum)
			}
		}

		var info bulkActionMetaInfoRound60
		if dt, okDT := metaMap["_type"].(string); okDT && dt != "" {
			info.docType = dt
		}

		if actName == "index" {
			if opTypeRaw, hasOT := metaMap["op_type"]; hasOT && opTypeRaw != nil {
				otStr := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", opTypeRaw)))
				switch otStr {
				case "create":
					actName = "create"
					delete(metaMap, "op_type")
				case "index":
					delete(metaMap, "op_type")
				default:
					return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Invalid op_type [%s] on line [%d]", otStr, lineNum)
				}
			}
		}

		idVal, hasIDKey := metaMap["_id"]
		if !hasIDKey || idVal == nil {
			switch actName {
			case "index":
				// esast.ParseBulkNDJSON auto-generates an _id and sets AutoGeneratedID = true.
			case "create":
				// ES 7.5+ supports auto-generated IDs on `create` when `_id` is omitted.
				info.autoGeneratedID = true
				metaMap["_id"] = generateESAutoIDRound60()
			default:
				info.missingID = true
				metaMap["_id"] = "__round60_missing_id__"
			}
		} else {
			sv, okS := stringifyScalarIDOrRouting(idVal)
			if !okS {
				return nil, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Malformed _id on line [%d]", lineNum)
			}
			if sv == "" {
				info.explicitEmptyID = true
				metaMap["_id"] = "__round60_empty_id__"
			} else {
				metaMap["_id"] = sv
			}
		}

		for _, rk := range []string{"routing", "_routing"} {
			if rv, hasR := metaMap[rk]; hasR && rv != nil {
				if sv, okS := stringifyScalarIDOrRouting(rv); okS {
					metaMap[rk] = sv
				}
			}
		}

		rewrittenMeta, err := json.Marshal(map[string]any{actName: metaMap})
		if err != nil {
			return nil, nil, http.StatusBadRequest, "illegal_argument_exception", err.Error()
		}

		lineIdx++
		if actName != "delete" {
			for lineIdx < len(lines) && len(bytes.TrimSpace(lines[lineIdx])) == 0 {
				lineIdx++
			}
			if lineIdx >= len(lines) {
				break
			}
			outBuf.Write(rewrittenMeta)
			outBuf.WriteByte('\n')
			metaInfos = append(metaInfos, info)
			srcLine := bytes.TrimRight(lines[lineIdx], "\r")
			outBuf.Write(srcLine)
			outBuf.WriteByte('\n')
			lineIdx++
		} else {
			outBuf.Write(rewrittenMeta)
			outBuf.WriteByte('\n')
			metaInfos = append(metaInfos, info)
		}
	}
	return outBuf.Bytes(), metaInfos, 0, "", ""
}

// validateRequireAliasForWriteRound60 checks `?require_alias=true` semantics:
//   - If target is an alias or data stream -> 0 (allowed)
//   - If target is an existing concrete index -> 404 index_not_found_exception (Alias [<name>] missing) or 400?
//     Wait: in ES 7.x/8.x (`Alias [<name>] missing` / `index_not_found_exception` when target doesn't exist OR isn't an alias:
//     Specifically in ES `TransportBulkAction`: ifconcreteIndex exists: `illegal_argument_exception: The provided expression [idx] matches an index, specify the corresponding alias instead` OR `index_not_found_exception: Alias [missing] missing` when neither index nor alias exists).
func (s *Server) validateRequireAliasForWriteRound60(ctx context.Context, rawTarget string) (int, string, string) {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return http.StatusBadRequest, "illegal_argument_exception", "target alias name is required when require_alias=true"
	}
	if s.isTargetAliasOrDataStream(rawTarget) {
		return 0, "", ""
	}
	_ = s.syncCatalogFromBackend(ctx)
	if s.isTargetAliasOrDataStream(rawTarget) {
		return 0, "", ""
	}
	s.mu.RLock()
	_, isConcrete := s.indices[rawTarget]
	s.mu.RUnlock()
	if isConcrete {
		return http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("The provided expression [%s] matches an index, specify the corresponding alias instead", rawTarget)
	}
	return http.StatusNotFound, "index_not_found_exception",
		fmt.Sprintf("no such index [%s] and [require_alias] request flag is [true] and [%s] is not an alias", rawTarget, rawTarget)
}

// checkAutoCreateIndexClusterSettingRound60 enforces cluster setting `action.auto_create_index`
// (`true`, `false`, or comma-separated `+pattern,-pattern,pattern` rules).
func (s *Server) checkAutoCreateIndexClusterSettingRound60(indexName string) (int, string, string) {
	s.mu.RLock()
	rawRule, ok := s.getClusterSettingStringLocked("action.auto_create_index")
	s.mu.RUnlock()
	if !ok {
		return 0, "", ""
	}
	rule := strings.TrimSpace(rawRule)
	if rule == "" || strings.EqualFold(rule, "true") {
		return 0, "", ""
	}
	if strings.EqualFold(rule, "false") {
		return http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such index [%s] and [action.auto_create_index] is [false]", indexName)
	}
	for _, pat := range strings.Split(rule, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "-") {
			if matchWildcardPattern(strings.TrimPrefix(pat, "-"), indexName) {
				return http.StatusNotFound, "index_not_found_exception",
					fmt.Sprintf("no such index [%s] and [action.auto_create_index] ([%s]) blocks auto-creation", indexName, rule)
			}
			continue
		}
		clean := strings.TrimPrefix(pat, "+")
		if matchWildcardPattern(clean, indexName) {
			return 0, "", ""
		}
	}
	return http.StatusNotFound, "index_not_found_exception",
		fmt.Sprintf("no such index [%s] and [action.auto_create_index] ([%s]) did not match", indexName, rule)
}

// normalizeTemplateBodyIndexPatternsRound60 rewrites `"index_patterns": "test-*"` (single string)
// to `["test-*"]` in legacy/composable template and simulate bodies.
func normalizeTemplateBodyIndexPatternsRound60(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !bytes.Contains(trimmed, []byte("index_patterns")) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return raw
	}
	changed := false
	if ip, ok := m["index_patterns"].(string); ok {
		m["index_patterns"] = []any{ip}
		changed = true
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// normalizeAliasActionsBodyRound60 converts numeric/boolean `routing`, `index_routing`, `search_routing`
// fields inside `_aliases` actions or `PUT /{index}/_alias/{name}` bodies to strings.
func normalizeAliasActionsBodyRound60(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return raw
	}
	changed := normalizeAliasRoutingMapFields(m)
	if actions, ok := m["actions"].([]any); ok {
		for _, act := range actions {
			am, okM := act.(map[string]any)
			if !okM {
				continue
			}
			for _, bodyVal := range am {
				if bm, okBM := bodyVal.(map[string]any); okBM {
					if normalizeAliasRoutingMapFields(bm) {
						changed = true
					}
				}
			}
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func normalizeAliasRoutingMapFields(m map[string]any) bool {
	changed := false
	for _, k := range []string{"routing", "index_routing", "search_routing"} {
		if v, exists := m[k]; exists && v != nil {
			if _, isStr := v.(string); !isStr {
				if sv, ok := stringifyScalarIDOrRouting(v); ok {
					m[k] = sv
					changed = true
				}
			}
		}
	}
	for _, arrKey := range []string{"aliases", "indices"} {
		if sv, isStr := m[arrKey].(string); isStr {
			m[arrKey] = []any{sv}
			changed = true
		}
	}
	return changed
}

// ---------- F6: Per-Index Live Atomic Stats, `/_stats/{metric}`, Split `_nodes`, `_cluster/state` & `_cluster/stats` ----------

type indexLiveStats struct {
	indexTotal       atomic.Int64
	deleteTotal      atomic.Int64
	noopUpdateTotal  atomic.Int64
	getTotal         atomic.Int64
	getExistsTotal   atomic.Int64
	getMissingTotal  atomic.Int64
	searchQueryTotal atomic.Int64
	searchFetchTotal atomic.Int64
	refreshTotal     atomic.Int64
	flushTotal       atomic.Int64
}

func (s *Server) getOrCreateIndexLiveStats(indexName string) *indexLiveStats {
	if indexName == "" {
		return nil
	}
	s.mu.RLock()
	if s.indexStats != nil {
		if st := s.indexStats[indexName]; st != nil {
			s.mu.RUnlock()
			return st
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indexStats == nil {
		s.indexStats = make(map[string]*indexLiveStats)
	}
	if st := s.indexStats[indexName]; st != nil {
		return st
	}
	st := &indexLiveStats{}
	st.refreshTotal.Store(1)
	st.flushTotal.Store(1)
	s.indexStats[indexName] = st
	return st
}

var validIndexStatMetricsRound60 = map[string]bool{
	"_all":          true,
	"docs":          true,
	"store":         true,
	"indexing":      true,
	"get":           true,
	"search":        true,
	"merges":        true,
	"refresh":       true,
	"flush":         true,
	"warmer":        true,
	"query_cache":   true,
	"fielddata":     true,
	"completion":    true,
	"segments":      true,
	"translog":      true,
	"request_cache": true,
	"recovery":      true,
}

func formatUnrecognizedMetricErrorRound61(reqPath, tok string, validMap map[string]bool) error {
	cands := make([]string, 0, len(validMap))
	for k := range validMap {
		cands = append(cands, k)
	}
	sort.Strings(cands)
	var suggestions []string
	for _, c := range cands {
		if d := queryRuleLevenshtein(tok, c); d > 0 && d <= 2 {
			suggestions = append(suggestions, c)
		}
	}
	msg := fmt.Sprintf("request [%s] contains unrecognized metric: [%s]", reqPath, tok)
	if len(suggestions) > 0 {
		msg += fmt.Sprintf(" -> did you mean [%s]?", strings.Join(suggestions, ", "))
	}
	return fmt.Errorf("%s", msg)
}

func parseRequestedIndexStatMetricsWithPathRound61(raw, reqPath string) (map[string]bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "_all" || raw == "*" {
		all := make(map[string]bool, len(validIndexStatMetricsRound60))
		for k := range validIndexStatMetricsRound60 {
			if k != "_all" {
				all[k] = true
			}
		}
		return all, nil
	}
	selected := make(map[string]bool)
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == "merge" {
			selected["merges"] = true
			continue
		}
		if !validIndexStatMetricsRound60[tok] {
			return nil, formatUnrecognizedMetricErrorRound61(reqPath, tok, validIndexStatMetricsRound60)
		}
		if tok == "_all" {
			for k := range validIndexStatMetricsRound60 {
				if k != "_all" {
					selected[k] = true
				}
			}
		} else {
			selected[tok] = true
		}
	}
	return selected, nil
}

type indexStatsRenderOptionsRound61 struct {
	isES8                   bool
	isClosed                bool
	includeSegFileSizes     bool
	includeUnloadedSegments bool
	groupPatterns           []string
	typePatterns            []string
	hasFielddataFields      bool
	fielddataPatterns       []string
	hasCompletionFields     bool
	completionPatterns      []string
	recordedSearchGroups    map[string]*round61SearchGroupCounters
	anyRecordedGroupsInSrv  bool
	recordedDocTypes        map[string]*round61DocTypeCounters
	fielddataSizes          map[string]int64
	totalFielddataBytes     int64
	completionSizes         map[string]int64
	totalCompletionBytes    int64
	hasTranslogOverride     bool
	tlogOps                 int64
	tlogUncommOps           int64
	tlogSizeBytes           int64
	tlogUncommBytes         int64
	reqCacheHits            int64
	reqCacheMisses          int64
}

func buildStatSectionsMapRound61(metrics map[string]bool, docCount, deletedCount, storeBytes int64, st *indexLiveStats, opts indexStatsRenderOptionsRound61) map[string]any {
	var idxTot, delTot, noopTot, getTot, getEx, getMiss, sqTot, sfTot, refTot, flTot int64
	if st != nil {
		idxTot = st.indexTotal.Load()
		delTot = st.deleteTotal.Load()
		noopTot = st.noopUpdateTotal.Load()
		getTot = st.getTotal.Load()
		getEx = st.getExistsTotal.Load()
		getMiss = st.getMissingTotal.Load()
		sqTot = st.searchQueryTotal.Load()
		sfTot = st.searchFetchTotal.Load()
		refTot = st.refreshTotal.Load()
		flTot = st.flushTotal.Load()
	}
	if refTot == 0 {
		refTot = 1
	}
	if flTot == 0 {
		flTot = 1
	}
	out := make(map[string]any, len(metrics))
	if metrics["docs"] {
		out["docs"] = map[string]any{
			"count":   docCount,
			"deleted": deletedCount,
		}
	}
	if metrics["store"] {
		out["store"] = map[string]any{
			"size_in_bytes":                storeBytes,
			"total_data_set_size_in_bytes": storeBytes,
			"reserved_in_bytes":            int64(0),
		}
	}
	if metrics["indexing"] {
		indexingMap := map[string]any{
			"index_total":             idxTot,
			"index_time_in_millis":    int64(0),
			"index_current":           int64(0),
			"index_failed":            int64(0),
			"delete_total":            delTot,
			"delete_time_in_millis":   int64(0),
			"delete_current":          int64(0),
			"noop_update_total":       noopTot,
			"is_throttled":            false,
			"throttle_time_in_millis": int64(0),
			"write_load":              float64(0.0),
		}
		if !opts.isES8 && len(opts.typePatterns) > 0 {
			typesOut := make(map[string]any)
			srcTypes := opts.recordedDocTypes
			if len(srcTypes) == 0 && (idxTot > 0 || delTot > 0) {
				srcTypes = map[string]*round61DocTypeCounters{
					"_doc": {indexTotal: idxTot, deleteTotal: delTot},
				}
			}
			for tName, tc := range srcTypes {
				if tc == nil {
					continue
				}
				for _, pat := range opts.typePatterns {
					if pat == "_all" || pat == "*" || matchWildcardPattern(pat, tName) {
						typesOut[tName] = map[string]any{
							"index_total":             tc.indexTotal,
							"index_time_in_millis":    int64(0),
							"index_current":           int64(0),
							"index_failed":            int64(0),
							"delete_total":            tc.deleteTotal,
							"delete_time_in_millis":   int64(0),
							"delete_current":          int64(0),
							"noop_update_total":       int64(0),
							"is_throttled":            false,
							"throttle_time_in_millis": int64(0),
						}
						break
					}
				}
			}
			indexingMap["types"] = typesOut
		}
		out["indexing"] = indexingMap
	}
	if metrics["get"] {
		out["get"] = map[string]any{
			"total":                  getTot,
			"time_in_millis":         int64(0),
			"exists_total":           getEx,
			"exists_time_in_millis":  int64(0),
			"missing_total":          getMiss,
			"missing_time_in_millis": int64(0),
			"current":                int64(0),
		}
	}
	if metrics["search"] {
		searchMap := map[string]any{
			"open_contexts":          int64(0),
			"query_total":            sqTot,
			"query_time_in_millis":   int64(0),
			"query_current":          int64(0),
			"fetch_total":            sfTot,
			"fetch_time_in_millis":   int64(0),
			"fetch_current":          int64(0),
			"scroll_total":           int64(0),
			"scroll_time_in_millis":  int64(0),
			"scroll_current":         int64(0),
			"suggest_total":          int64(0),
			"suggest_time_in_millis": int64(0),
			"suggest_current":        int64(0),
		}
		if len(opts.groupPatterns) > 0 {
			gm := make(map[string]any)
			mkGroupEntry := func(qCnt, fCnt int64) map[string]any {
				return map[string]any{
					"query_total":            qCnt,
					"query_time_in_millis":   int64(0),
					"query_current":          int64(0),
					"fetch_total":            fCnt,
					"fetch_time_in_millis":   int64(0),
					"fetch_current":          int64(0),
					"scroll_total":           int64(0),
					"scroll_time_in_millis":  int64(0),
					"scroll_current":         int64(0),
					"suggest_total":          int64(0),
					"suggest_time_in_millis": int64(0),
					"suggest_current":        int64(0),
				}
			}
			for gName, gc := range opts.recordedSearchGroups {
				if gc == nil {
					continue
				}
				for _, pat := range opts.groupPatterns {
					if pat == "_all" || pat == "*" || matchWildcardPattern(pat, gName) {
						gm[gName] = mkGroupEntry(gc.queryTotal, gc.fetchTotal)
						break
					}
				}
			}
			if !opts.anyRecordedGroupsInSrv {
				for _, pat := range opts.groupPatterns {
					if pat != "" && !strings.ContainsAny(pat, "*?") && pat != "_all" {
						if _, exists := gm[pat]; !exists {
							gm[pat] = mkGroupEntry(0, 0)
						}
					}
				}
			}
			searchMap["groups"] = gm
		}
		out["search"] = searchMap
	}
	if metrics["merges"] {
		out["merges"] = map[string]any{
			"current":                        int64(0),
			"current_docs":                   int64(0),
			"current_size_in_bytes":          int64(0),
			"total":                          int64(0),
			"total_time_in_millis":           int64(0),
			"total_docs":                     int64(0),
			"total_size_in_bytes":            int64(0),
			"total_stopped_time_in_millis":   int64(0),
			"total_throttled_time_in_millis": int64(0),
			"total_auto_throttle_in_bytes":   int64(20971520),
		}
	}
	if metrics["refresh"] {
		out["refresh"] = map[string]any{
			"total":                         refTot,
			"total_time_in_millis":          int64(0),
			"external_total":                refTot,
			"external_total_time_in_millis": int64(0),
			"listeners":                     int64(0),
		}
	}
	if metrics["flush"] {
		out["flush"] = map[string]any{
			"total":                flTot,
			"periodic":             int64(0),
			"total_time_in_millis": int64(0),
		}
	}
	if metrics["warmer"] {
		out["warmer"] = map[string]any{
			"current":              int64(0),
			"total":                int64(1),
			"total_time_in_millis": int64(0),
		}
	}
	if metrics["query_cache"] {
		out["query_cache"] = map[string]any{
			"memory_size_in_bytes": int64(0),
			"total_count":          int64(0),
			"hit_count":            int64(0),
			"miss_count":           int64(0),
			"cache_size":           int64(0),
			"cache_count":          int64(0),
			"evictions":            int64(0),
		}
	}
	if metrics["fielddata"] {
		fdMap := map[string]any{
			"memory_size_in_bytes": opts.totalFielddataBytes,
			"evictions":            int64(0),
		}
		var goFields map[string]any
		if opts.hasFielddataFields {
			fdFields := make(map[string]any)
			goFields = make(map[string]any)
			maxValCnt := docCount
			if maxValCnt < 1 {
				maxValCnt = 1
			}
			for fn, sz := range opts.fielddataSizes {
				for _, pat := range opts.fielddataPatterns {
					if pat == "_all" || pat == "*" || matchWildcardPattern(pat, fn) {
						fdFields[fn] = map[string]any{
							"memory_size_in_bytes": sz,
						}
						goFields[fn] = map[string]any{
							"build_time_in_millis":  int64(0),
							"shard_max_value_count": maxValCnt,
						}
						break
					}
				}
			}
			fdMap["fields"] = fdFields
		}
		if opts.isES8 {
			goObj := map[string]any{
				"build_time_in_millis": int64(0),
			}
			if opts.hasFielddataFields {
				goObj["fields"] = goFields
			}
			fdMap["global_ordinals"] = goObj
		}
		out["fielddata"] = fdMap
	}
	if metrics["completion"] {
		compMap := map[string]any{
			"size_in_bytes": opts.totalCompletionBytes,
		}
		if opts.hasCompletionFields {
			cFields := make(map[string]any)
			for fn, sz := range opts.completionSizes {
				for _, pat := range opts.completionPatterns {
					if pat == "_all" || pat == "*" || matchWildcardPattern(pat, fn) {
						cFields[fn] = map[string]any{
							"size_in_bytes": sz,
						}
						break
					}
				}
			}
			compMap["fields"] = cFields
		}
		out["completion"] = compMap
	}
	if metrics["segments"] {
		segCount := int64(0)
		if !opts.isClosed && docCount > 0 {
			segCount = 1
		} else if opts.isClosed && opts.includeUnloadedSegments && docCount > 0 {
			segCount = 1
		}
		segMap := map[string]any{
			"count":                         segCount,
			"memory_in_bytes":               int64(0),
			"terms_memory_in_bytes":         int64(0),
			"stored_fields_memory_in_bytes": int64(0),
			"term_vectors_memory_in_bytes":  int64(0),
			"norms_memory_in_bytes":         int64(0),
			"points_memory_in_bytes":        int64(0),
			"doc_values_memory_in_bytes":    int64(0),
			"index_writer_memory_in_bytes":  int64(0),
			"version_map_memory_in_bytes":   int64(0),
			"fixed_bit_set_memory_in_bytes": int64(0),
			"max_unsafe_auto_id_timestamp":  int64(-1),
		}
		if opts.includeSegFileSizes {
			cfsBytes := storeBytes
			if cfsBytes <= 0 {
				cfsBytes = 256
			}
			segCntForFiles := segCount
			if segCntForFiles <= 0 {
				segCntForFiles = 1
			}
			segMap["file_sizes"] = map[string]any{
				"si": map[string]any{
					"size_in_bytes":         int64(256),
					"count":                 segCntForFiles,
					"description":           "Segment Info",
					"min_size_in_bytes":     int64(256) / int64(segCntForFiles),
					"max_size_in_bytes":     int64(256),
					"average_size_in_bytes": int64(256) / int64(segCntForFiles),
				},
				"cfs": map[string]any{
					"size_in_bytes":         cfsBytes,
					"count":                 segCntForFiles,
					"description":           "Compound File",
					"min_size_in_bytes":     cfsBytes / int64(segCntForFiles),
					"max_size_in_bytes":     cfsBytes,
					"average_size_in_bytes": cfsBytes / int64(segCntForFiles),
				},
			}
		}
		out["segments"] = segMap
	}
	if metrics["translog"] {
		tOps := idxTot + delTot
		tUncommOps := int64(0)
		tBytes := int64(55)
		tUncommBytes := int64(55)
		if opts.hasTranslogOverride {
			tOps = opts.tlogOps
			tUncommOps = opts.tlogUncommOps
			tBytes = opts.tlogSizeBytes
			tUncommBytes = opts.tlogUncommBytes
		}
		out["translog"] = map[string]any{
			"operations":                 tOps,
			"size_in_bytes":              tBytes,
			"uncommitted_operations":     tUncommOps,
			"uncommitted_size_in_bytes":  tUncommBytes,
			"earliest_last_modified_age": int64(0),
		}
	}
	if metrics["request_cache"] {
		out["request_cache"] = map[string]any{
			"memory_size_in_bytes": int64(0),
			"evictions":            int64(0),
			"hit_count":            opts.reqCacheHits,
			"miss_count":           opts.reqCacheMisses,
		}
	}
	if metrics["recovery"] {
		out["recovery"] = map[string]any{
			"current_as_source":       int64(0),
			"current_as_target":       int64(0),
			"throttle_time_in_millis": int64(0),
		}
	}
	return out
}

func (s *Server) collectIndexFielddataAndCompletionSizesRound61(indexName string, docCount int64) (fdSizes map[string]int64, totalFD int64, compSizes map[string]int64, totalComp int64) {
	fdSizes = make(map[string]int64)
	compSizes = make(map[string]int64)

	s.mu.RLock()
	sc := s.indices[indexName]
	var rawProps map[string]esast.FieldProperty
	if sc != nil && sc.RawMapping != nil {
		rawProps = sc.RawMapping.Properties
	}
	if sc != nil {
		for fn, fb := range sc.Fields {
			if fb.ESType == "completion" {
				sz := docCount * 64
				compSizes[fn] = sz
				totalComp += sz
				continue
			}
			if docCount > 0 && (fb.ESType == "keyword" || fb.ESType == "text" || fb.DorisType == schema.DorisString) {
				sz := docCount * 64
				fdSizes[fn] = sz
				totalFD += sz
			}
		}
	}
	var scanRawCompletion func(prefix string, props map[string]esast.FieldProperty)
	scanRawCompletion = func(prefix string, props map[string]esast.FieldProperty) {
		for pn, prop := range props {
			full := pn
			if prefix != "" {
				full = prefix + "." + pn
			}
			if strings.EqualFold(strings.TrimSpace(prop.Type), "completion") {
				if _, exists := compSizes[full]; !exists {
					sz := docCount * 64
					compSizes[full] = sz
					totalComp += sz
				}
			} else if docCount > 0 && (prop.Fielddata == true) {
				if _, exists := fdSizes[full]; !exists {
					sz := docCount * 64
					fdSizes[full] = sz
					totalFD += sz
				}
			}
			if len(prop.Fields) > 0 {
				scanRawCompletion(full, prop.Fields)
			}
			if len(prop.Properties) > 0 {
				scanRawCompletion(full, prop.Properties)
			}
		}
	}
	if len(rawProps) > 0 {
		scanRawCompletion("", rawProps)
	}
	s.mu.RUnlock()

	st := getOrCreateRound61AdminState(s)
	st.mu.RLock()
	for fn, fc := range st.fieldAccesses[indexName] {
		if fc == nil || strings.HasPrefix(fn, "_") {
			continue
		}
		if _, isComp := compSizes[fn]; isComp {
			continue
		}
		if _, exists := fdSizes[fn]; !exists {
			sz := max(docCount, 1) * 64
			fdSizes[fn] = sz
			totalFD += sz
		}
	}
	st.mu.RUnlock()
	return fdSizes, totalFD, compSizes, totalComp
}

func parseStatsFieldAndGroupParamsRound61(r *http.Request) (groups, types []string, hasFD bool, fdPats []string, hasComp bool, compPats []string) {
	if r == nil || r.URL == nil {
		return nil, nil, false, nil, false, nil
	}
	q := r.URL.Query()
	for _, gRaw := range q["groups"] {
		for _, g := range strings.Split(gRaw, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
	}
	for _, tRaw := range q["types"] {
		for _, tp := range strings.Split(tRaw, ",") {
			if tp = strings.TrimSpace(tp); tp != "" {
				types = append(types, tp)
			}
		}
	}
	if q.Has("fields") {
		for _, fRaw := range q["fields"] {
			for _, fp := range strings.Split(fRaw, ",") {
				if fp = strings.TrimSpace(fp); fp != "" {
					hasFD = true
					hasComp = true
					fdPats = append(fdPats, fp)
					compPats = append(compPats, fp)
				}
			}
		}
	}
	if q.Has("fielddata_fields") {
		for _, fRaw := range q["fielddata_fields"] {
			for _, fp := range strings.Split(fRaw, ",") {
				if fp = strings.TrimSpace(fp); fp != "" {
					hasFD = true
					fdPats = append(fdPats, fp)
				}
			}
		}
	}
	if q.Has("completion_fields") {
		for _, fRaw := range q["completion_fields"] {
			for _, fp := range strings.Split(fRaw, ",") {
				if fp = strings.TrimSpace(fp); fp != "" {
					hasComp = true
					compPats = append(compPats, fp)
				}
			}
		}
	}
	return groups, types, hasFD, fdPats, hasComp, compPats
}

func decorateShardStatsEntryRound61(shSec map[string]any, idxName string, sh int, primary bool, shDocs int64) {
	shSec["routing"] = map[string]any{
		"state":   "STARTED",
		"primary": primary,
		"node":    taskLocalNodeID,
	}
	maxSeq := shDocs - 1
	localCP := maxSeq
	userCP := localCP
	if userCP < 0 {
		userCP = 0
	}
	shSec["commit"] = map[string]any{
		"id":         fmt.Sprintf("commit-%s-%d", idxName, sh),
		"generation": int64(1),
		"user_data": map[string]any{
			"local_checkpoint":             strconv.FormatInt(userCP, 10),
			"max_unsafe_auto_id_timestamp": "-1",
			"translog_uuid":                idxName + "-tlog",
			"history_uuid":                 idxName + "-hist",
		},
	}
	shSec["seq_no"] = map[string]any{
		"max_seq_no":        maxSeq,
		"local_checkpoint":  localCP,
		"global_checkpoint": localCP,
	}
	shSec["retention_leases"] = map[string]any{
		"primary_term": int64(1),
		"version":      int64(0),
		"leases":       []any{},
	}
	shSec["shard_path"] = map[string]any{
		"state_path":          "/var/lib/elasticsearch/nodes/0",
		"data_path":           "/var/lib/elasticsearch/nodes/0",
		"is_custom_data_path": false,
	}
	shSec["search_idle"] = false
	shSec["search_idle_time"] = int64(0)
}

func (s *Server) handleIndexStatsRound60(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	reqPath := "/_stats"
	if r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	metrics, mErr := parseRequestedIndexStatMetricsWithPathRound61(r.PathValue("metric"), reqPath)
	if mErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", mErr.Error())
		return
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if level == "" {
		level = "indices"
	}
	if level != "cluster" && level != "indices" && level != "shards" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("No enum constant org.elasticsearch.action.admin.indices.stats.CommonStatsFlags.Level.%s", level))
		return
	}
	includeSegFileSizes, _, segBoolErr := parseStrictQueryBoolParamRound59(r, "include_segment_file_sizes")
	if segBoolErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", segBoolErr.Error())
		return
	}
	includeUnloadedSegments, _, unloadErr := parseStrictQueryBoolParamRound59(r, "include_unloaded_segments")
	if unloadErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", unloadErr.Error())
		return
	}
	forbidClosed := true
	if parsedForbid, hasForbid, forbidErr := parseStrictQueryBoolParamRound59(r, "forbid_closed_indices"); forbidErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", forbidErr.Error())
		return
	} else if hasForbid {
		forbidClosed = parsedForbid
	}
	if _, _, expErr := parseStrictQueryBoolParamRound59(r, "expand_wildcards_open"); expErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", expErr.Error())
		return
	}

	groups, typePatterns, hasFD, fdPats, hasComp, compPats := parseStatsFieldAndGroupParamsRound61(r)

	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "_all" {
		rawIndex = ""
	}
	targets, aliasFilters, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	if forbidClosed {
		if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
			writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
			return
		}
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	isES8 := s.isES8Mode(r)
	adminSt := getOrCreateRound61AdminState(s)
	adminSt.mu.RLock()
	anyRecordedGroups := len(adminSt.searchGroups) > 0
	adminSt.mu.RUnlock()

	indicesMap := make(map[string]any, len(targets))
	var totalDocs, totalDeleted, totalBytes int64
	var totalFDBytes, totalCompBytes int64
	aggFDSizes := make(map[string]int64)
	aggCompSizes := make(map[string]int64)
	aggSearchGroups := make(map[string]*round61SearchGroupCounters)
	aggDocTypes := make(map[string]*round61DocTypeCounters)
	var aggTlogOps, aggTlogUncommOps, aggTlogBytes, aggTlogUncommBytes int64
	var aggReqCacheHits, aggReqCacheMisses int64
	aggStats := &indexLiveStats{}
	totalShards := 0
	successfulShards := 0

	adminSt.mu.RLock()
	for gName, gc := range adminSt.searchGroups["_all"] {
		if gc != nil {
			aggSearchGroups[gName] = &round61SearchGroupCounters{queryTotal: gc.queryTotal, fetchTotal: gc.fetchTotal}
		}
	}
	adminSt.mu.RUnlock()

	for _, name := range targets {
		closed := s.isIndexClosed(name)
		if closed && forbidClosed {
			continue
		}
		numShards, numReplicas, _ := s.getIndexShardAndReplicaCounts(name)
		if !closed {
			idxTotalShards := numShards * (1 + numReplicas)
			totalShards += idxTotalShards
			successfulShards += idxTotalShards
		}

		var cnt, delCnt, estBytes int64
		if af := aliasFilters[name]; af != nil && !closed {
			zero := 0
			if resp, _, errType, _ := s.executeSearchRequest(r.Context(), name, &esast.SearchRequest{
				Size:           &zero,
				TrackTotalHits: true,
				Query:          af,
			}); errType == "" {
				cnt, _ = extractTotalAndHitIDs(resp)
			}
			estBytes = cnt * 256
		} else {
			cnt, delCnt, estBytes = s.computeAdjustedLiveDocCountRound61(r.Context(), name)
		}
		if estBytes == 0 && cnt > 0 {
			estBytes = cnt * 256
		}
		st := s.getOrCreateIndexLiveStats(name)

		var tOps, tUncommOps, tBytes, tUncommBytes int64
		if closed {
			if sdDisabled, retTrimmed := isIndexSoftDeletesDisabledR62Admin(s, name); sdDisabled && !retTrimmed && st != nil {
				totClosedOps := st.indexTotal.Load() + st.deleteTotal.Load()
				tOps, tUncommOps, tBytes, tUncommBytes = totClosedOps, 0, 55+totClosedOps*64, 19
			} else {
				tOps, tUncommOps, tBytes, tUncommBytes = 0, 0, 55, 55
			}
		} else {
			tOps, tUncommOps, tBytes, tUncommBytes = computeIndexUncommittedTranslogRound61(s, name, st)
		}
		aggTlogOps += tOps
		aggTlogUncommOps += tUncommOps
		aggTlogBytes += tBytes
		aggTlogUncommBytes += tUncommBytes

		fdSizes, fdTot, compSizes, compTot := s.collectIndexFielddataAndCompletionSizesRound61(name, cnt)
		totalFDBytes += fdTot
		totalCompBytes += compTot
		for k, v := range fdSizes {
			aggFDSizes[k] += v
		}
		for k, v := range compSizes {
			aggCompSizes[k] += v
		}

		idxGroups := make(map[string]*round61SearchGroupCounters)
		idxDocTypes := make(map[string]*round61DocTypeCounters)
		adminSt.mu.RLock()
		for gName, gc := range adminSt.searchGroups[name] {
			if gc != nil {
				idxGroups[gName] = &round61SearchGroupCounters{queryTotal: gc.queryTotal, fetchTotal: gc.fetchTotal}
				if aggSearchGroups[gName] == nil {
					aggSearchGroups[gName] = &round61SearchGroupCounters{}
				}
				aggSearchGroups[gName].queryTotal += gc.queryTotal
				aggSearchGroups[gName].fetchTotal += gc.fetchTotal
			}
		}
		for tName, tc := range adminSt.docTypeCounts[name] {
			if tc != nil {
				idxDocTypes[tName] = &round61DocTypeCounters{indexTotal: tc.indexTotal, deleteTotal: tc.deleteTotal}
				if aggDocTypes[tName] == nil {
					aggDocTypes[tName] = &round61DocTypeCounters{}
				}
				aggDocTypes[tName].indexTotal += tc.indexTotal
				aggDocTypes[tName].deleteTotal += tc.deleteTotal
			}
		}
		var idxReqCacheHits, idxReqCacheMisses int64
		if adminSt.reqCacheHits != nil {
			idxReqCacheHits = adminSt.reqCacheHits[name]
		}
		if adminSt.reqCacheMisses != nil {
			idxReqCacheMisses = adminSt.reqCacheMisses[name]
		}
		adminSt.mu.RUnlock()
		aggReqCacheHits += idxReqCacheHits
		aggReqCacheMisses += idxReqCacheMisses

		totalDocs += cnt
		totalDeleted += delCnt
		totalBytes += estBytes
		if st != nil {
			aggStats.indexTotal.Add(st.indexTotal.Load())
			aggStats.deleteTotal.Add(st.deleteTotal.Load())
			aggStats.noopUpdateTotal.Add(st.noopUpdateTotal.Load())
			aggStats.getTotal.Add(st.getTotal.Load())
			aggStats.getExistsTotal.Add(st.getExistsTotal.Load())
			aggStats.getMissingTotal.Add(st.getMissingTotal.Load())
			aggStats.searchQueryTotal.Add(st.searchQueryTotal.Load())
			aggStats.searchFetchTotal.Add(st.searchFetchTotal.Load())
			aggStats.refreshTotal.Add(st.refreshTotal.Load())
			aggStats.flushTotal.Add(st.flushTotal.Load())
		}

		idxOpts := indexStatsRenderOptionsRound61{
			isES8:                   isES8,
			isClosed:                closed,
			includeSegFileSizes:     includeSegFileSizes,
			includeUnloadedSegments: includeUnloadedSegments,
			groupPatterns:           groups,
			typePatterns:            typePatterns,
			hasFielddataFields:      hasFD,
			fielddataPatterns:       fdPats,
			hasCompletionFields:     hasComp,
			completionPatterns:      compPats,
			recordedSearchGroups:    idxGroups,
			anyRecordedGroupsInSrv:  anyRecordedGroups,
			recordedDocTypes:        idxDocTypes,
			fielddataSizes:          fdSizes,
			totalFielddataBytes:     fdTot,
			completionSizes:         compSizes,
			totalCompletionBytes:    compTot,
			hasTranslogOverride:     true,
			tlogOps:                 tOps,
			tlogUncommOps:           tUncommOps,
			tlogSizeBytes:           tBytes,
			tlogUncommBytes:         tUncommBytes,
			reqCacheHits:            idxReqCacheHits,
			reqCacheMisses:          idxReqCacheMisses,
		}

		primMap := buildStatSectionsMapRound61(metrics, cnt, delCnt, estBytes, st, idxOpts)
		totMap := buildStatSectionsMapRound61(metrics, cnt, delCnt, estBytes, st, idxOpts)
		idxEntry := map[string]any{
			"uuid":      name,
			"primaries": primMap,
			"total":     totMap,
		}
		if level == "shards" {
			shardsObj := make(map[string]any, numShards)
			if !closed {
				for sh := 0; sh < numShards; sh++ {
					shDocs := int64(0)
					shDel := int64(0)
					if sh == 0 {
						shDocs = cnt
						shDel = delCnt
					}
					shSec := buildStatSectionsMapRound61(metrics, shDocs, shDel, shDocs*256, st, idxOpts)
					decorateShardStatsEntryRound61(shSec, name, sh, true, shDocs)
					shardReplicas := []any{shSec}
					for rep := 0; rep < numReplicas; rep++ {
						repSec := buildStatSectionsMapRound61(metrics, shDocs, shDel, shDocs*256, st, idxOpts)
						decorateShardStatsEntryRound61(repSec, name, sh, false, shDocs)
						shardReplicas = append(shardReplicas, repSec)
					}
					shardsObj[strconv.Itoa(sh)] = shardReplicas
				}
			}
			idxEntry["shards"] = shardsObj
		}
		indicesMap[name] = idxEntry
	}

	if len(targets) == 0 {
		aggTlogBytes = 55
		aggTlogUncommBytes = 55
	}
	allOpts := indexStatsRenderOptionsRound61{
		isES8:                   isES8,
		includeSegFileSizes:     includeSegFileSizes,
		includeUnloadedSegments: includeUnloadedSegments,
		groupPatterns:           groups,
		typePatterns:            typePatterns,
		hasFielddataFields:      hasFD,
		fielddataPatterns:       fdPats,
		hasCompletionFields:     hasComp,
		completionPatterns:      compPats,
		recordedSearchGroups:    aggSearchGroups,
		anyRecordedGroupsInSrv:  anyRecordedGroups,
		recordedDocTypes:        aggDocTypes,
		fielddataSizes:          aggFDSizes,
		totalFielddataBytes:     totalFDBytes,
		completionSizes:         aggCompSizes,
		totalCompletionBytes:    totalCompBytes,
		hasTranslogOverride:     true,
		tlogOps:                 aggTlogOps,
		tlogUncommOps:           aggTlogUncommOps,
		tlogSizeBytes:           aggTlogBytes,
		tlogUncommBytes:         aggTlogUncommBytes,
		reqCacheHits:            aggReqCacheHits,
		reqCacheMisses:          aggReqCacheMisses,
	}

	allPrim := buildStatSectionsMapRound61(metrics, totalDocs, totalDeleted, totalBytes, aggStats, allOpts)
	allTot := buildStatSectionsMapRound61(metrics, totalDocs, totalDeleted, totalBytes, aggStats, allOpts)

	resp := map[string]any{
		"_shards": map[string]any{
			"total":      totalShards,
			"successful": successfulShards,
			"failed":     0,
		},
		"_all": map[string]any{
			"primaries": allPrim,
			"total":     allTot,
		},
	}
	if level != "cluster" {
		resp["indices"] = indicesMap
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

// ---------- Split `_nodes` Info vs `_nodes/stats` ----------

var validNodeInfoMetricsRound60 = map[string]bool{
	"_all":         true,
	"settings":     true,
	"os":           true,
	"process":      true,
	"jvm":          true,
	"thread_pool":  true,
	"transport":    true,
	"http":         true,
	"plugins":      true,
	"modules":      true,
	"ingest":       true,
	"indices":      true,
	"aggregations": true,
}

var validNodeStatsMetricsRound60 = map[string]bool{
	"_all":               true,
	"indices":            true,
	"fs":                 true,
	"http":               true,
	"jvm":                true,
	"os":                 true,
	"process":            true,
	"thread_pool":        true,
	"transport":          true,
	"breaker":            true,
	"discovery":          true,
	"ingest":             true,
	"adaptive_selection": true,
	"script":             true,
	"script_cache":       true,
	"indexing_pressure":  true,
	"repositories":       true,
	"allocations":        true,
}

func localNodeMatchesFilterRound60(nodeFilter string) bool {
	nodeFilter = strings.TrimSpace(nodeFilter)
	if nodeFilter == "" || nodeFilter == "_all" || nodeFilter == "*" || nodeFilter == "_local" || nodeFilter == "_master" {
		return true
	}
	const (
		nodeID   = taskLocalNodeID
		nodeName = "doris-es-proxy-node-1"
		nodeIP   = "127.0.0.1"
		nodeHost = "localhost"
	)
	matched := false
	hasPos := false
	for _, tok := range strings.Split(nodeFilter, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		neg := false
		if strings.HasPrefix(tok, "-") {
			neg = true
			tok = strings.TrimSpace(strings.TrimPrefix(tok, "-"))
		} else {
			hasPos = true
		}
		tokMatch := false
		switch {
		case tok == "_all" || tok == "*" || tok == "_local" || tok == "_master":
			tokMatch = true
		case strings.Contains(tok, ":"):
			kv := strings.SplitN(tok, ":", 2)
			roleKey := strings.ToLower(strings.TrimSpace(kv[0]))
			roleVal := strings.TrimSpace(kv[1])
			roleValLower := strings.ToLower(roleVal)
			switch roleKey {
			case "master", "data", "ingest", "ml", "transform", "remote_cluster_client", "coordinating_only",
				"data_hot", "data_content", "data_warm", "data_cold", "data_frozen":
				roleHas := roleKey != "coordinating_only"
				if (roleValLower == "true" && roleHas) || (roleValLower == "false" && !roleHas) {
					tokMatch = true
				}
			case "backend":
				tokMatch = matchWildcardPattern(roleVal, "doris")
			case "testattr":
				tokMatch = matchWildcardPattern(roleVal, "test")
			default:
				if roleValLower == "true" {
					tokMatch = false
				}
			}
		default:
			if matchWildcardPattern(tok, nodeID) || matchWildcardPattern(tok, "doris-es-proxy") || matchWildcardPattern(tok, "doris-node-1") || matchWildcardPattern(tok, nodeName) || matchWildcardPattern(tok, nodeIP) || matchWildcardPattern(tok, nodeHost) {
				tokMatch = true
			}
		}
		if neg && tokMatch {
			return false
		}
		if !neg && tokMatch {
			matched = true
		}
	}
	if !hasPos {
		return true
	}
	return matched
}

func (s *Server) handleNodesRound60(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	// Route `hot_threads` / `_hot_threads` (`/_nodes/hot_threads` and `/_nodes/{node_id}/hot_threads`):
	if len(segs) >= 2 && (segs[1] == "hot_threads" || segs[1] == "_hot_threads") {
		if len(segs) >= 3 {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
			return
		}
		s.serveNodesHotThreadsRound61(w, r, "_all")
		return
	}
	if len(segs) >= 3 && (segs[2] == "hot_threads" || segs[2] == "_hot_threads") {
		if len(segs) >= 4 {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
			return
		}
		s.serveNodesHotThreadsRound61(w, r, segs[1])
		return
	}
	// Route `stats`:
	if len(segs) >= 2 && segs[1] == "stats" {
		metricStr := ""
		idxMetricStr := ""
		if len(segs) >= 3 {
			metricStr = segs[2]
		}
		if len(segs) >= 4 {
			idxMetricStr = segs[3]
		}
		s.serveNodesStatsRound60(w, r, "_all", metricStr, idxMetricStr)
		return
	}
	if len(segs) >= 3 && segs[2] == "stats" {
		metricStr := ""
		idxMetricStr := ""
		if len(segs) >= 4 {
			metricStr = segs[3]
		}
		if len(segs) >= 5 {
			idxMetricStr = segs[4]
		}
		s.serveNodesStatsRound60(w, r, segs[1], metricStr, idxMetricStr)
		return
	}
	nodeFilter := "_all"
	metricStr := "_all"
	if len(segs) == 2 {
		// Disambiguate `/_nodes/{metric}` vs `/_nodes/{node_id}`:
		allValidMetrics := true
		for _, tok := range strings.Split(segs[1], ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || (!validNodeInfoMetricsRound60[tok] && tok != "_none") {
				allValidMetrics = false
				break
			}
		}
		if allValidMetrics {
			metricStr = segs[1]
		} else {
			nodeFilter = segs[1]
		}
	} else if len(segs) >= 3 {
		nodeFilter = segs[1]
		metricStr = segs[2]
	}
	s.serveNodesInfoRound60(w, r, nodeFilter, metricStr)
}

func (s *Server) serveNodesInfoRound60(w http.ResponseWriter, r *http.Request, nodeFilter, metricStr string) {
	reqPath := "/_nodes"
	if r != nil && r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	selected := make(map[string]bool)
	if metricStr == "" || metricStr == "_all" || metricStr == "*" {
		for k := range validNodeInfoMetricsRound60 {
			if k != "_all" {
				selected[k] = true
			}
		}
	} else if metricStr != "_none" {
		for _, tok := range strings.Split(metricStr, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || tok == "_none" {
				continue
			}
			if !validNodeInfoMetricsRound60[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					formatUnrecognizedMetricErrorRound61(reqPath, tok, validNodeInfoMetricsRound60).Error())
				return
			}
			if tok == "_all" {
				for k := range validNodeInfoMetricsRound60 {
					if k != "_all" {
						selected[k] = true
					}
				}
			} else {
				selected[tok] = true
			}
		}
	}

	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	esVer := s.effectiveClusterESVersionNumber(r)
	isES8 := s.isES8Mode(r)
	human := isTruthyBoolQueryParam(r, "human")

	roles := []string{"data", "ingest", "master", "remote_cluster_client"}
	if isES8 {
		roles = []string{
			"data", "data_cold", "data_content", "data_frozen", "data_hot", "data_warm",
			"ingest", "master", "ml", "remote_cluster_client", "transform",
		}
	}

	nodesMap := map[string]any{}
	totalNodes := 1
	if localNodeMatchesFilterRound60(nodeFilter) {
		nodeObj := map[string]any{
			"name":              "doris-es-proxy",
			"transport_address": "127.0.0.1:9300",
			"host":              "localhost",
			"ip":                "127.0.0.1",
			"version":           esVer,
			"build_flavor":      "default",
			"build_type":        "docker",
			"build_hash":        "0000000000000000000000000000000000000000",
			"roles":             roles,
			"attributes":        map[string]any{"backend": "doris", "testattr": "test"},
		}
		if selected["indices"] {
			const indexingBufBytes int64 = 107374182
			nodeObj["total_indexing_buffer_in_bytes"] = indexingBufBytes
			if human {
				nodeObj["total_indexing_buffer"] = "102.3mb"
			} else {
				nodeObj["total_indexing_buffer"] = indexingBufBytes
			}
		}
		if selected["settings"] {
			flat := isTruthyBoolQueryParam(r, "flat_settings")
			if flat {
				nodeObj["settings"] = map[string]any{
					"cluster.name":       "apache-doris-search-cluster",
					"node.name":          "doris-es-proxy-node-1",
					"node.attr.backend":  "doris",
					"node.attr.testattr": "test",
					"http.type":          "netty4",
					"transport.type":     "netty4",
					"client.type":        "node",
				}
			} else {
				nodeObj["settings"] = map[string]any{
					"cluster":   map[string]any{"name": "apache-doris-search-cluster"},
					"node":      map[string]any{"name": "doris-es-proxy-node-1", "attr": map[string]any{"backend": "doris", "testattr": "test"}},
					"http":      map[string]any{"type": "netty4"},
					"transport": map[string]any{"type": "netty4"},
					"client":    map[string]any{"type": "node"},
				}
			}
		}
		if selected["os"] {
			nodeObj["os"] = map[string]any{
				"refresh_interval_in_millis": 1000,
				"name":                       runtime.GOOS,
				"pretty_name":                runtime.GOOS,
				"arch":                       runtime.GOARCH,
				"version":                    "1.0",
				"available_processors":       runtime.NumCPU(),
				"allocated_processors":       runtime.NumCPU(),
			}
		}
		if selected["process"] {
			nodeObj["process"] = map[string]any{
				"refresh_interval_in_millis": 1000,
				"id":                         1,
				"mlockall":                   false,
			}
		}
		if selected["jvm"] {
			nodeObj["jvm"] = map[string]any{
				"pid":                  1,
				"version":              "21.0.1",
				"vm_name":              "Go Runtime",
				"vm_version":           runtime.Version(),
				"vm_vendor":            "Go",
				"bundled_jdk":          true,
				"using_bundled_jdk":    true,
				"start_time_in_millis": time.Now().Add(-time.Hour).UnixMilli(),
				"mem": map[string]any{
					"heap_init_in_bytes":     int64(268435456),
					"heap_max_in_bytes":      int64(1073741824),
					"non_heap_init_in_bytes": int64(7667712),
					"non_heap_max_in_bytes":  int64(0),
					"direct_max_in_bytes":    int64(0),
				},
				"gc_collectors": []string{"G1 Young Generation", "G1 Old Generation"},
				"memory_pools":  []string{"CodeCache", "Metaspace", "G1 Eden Space", "G1 Old Gen"},
			}
		}
		if selected["thread_pool"] {
			nodeObj["thread_pool"] = map[string]any{
				"search": map[string]any{"type": "fixed_auto_queue_size", "size": runtime.NumCPU(), "queue_size": 1000},
				"write":  map[string]any{"type": "fixed", "size": runtime.NumCPU(), "queue_size": 10000},
				"get":    map[string]any{"type": "fixed", "size": runtime.NumCPU(), "queue_size": 1000},
			}
		}
		if selected["transport"] {
			nodeObj["transport"] = map[string]any{
				"bound_address":   []string{"127.0.0.1:9300"},
				"publish_address": "127.0.0.1:9300",
				"profiles":        map[string]any{},
			}
		}
		if selected["http"] {
			pubAddr := "127.0.0.1:9200"
			if r != nil && strings.TrimSpace(r.Host) != "" {
				cand := strings.TrimSpace(r.Host)
				if _, _, splitErr := net.SplitHostPort(cand); splitErr == nil {
					pubAddr = cand
				} else {
					pubAddr = net.JoinHostPort(strings.Trim(cand, "[]"), "9200")
				}
			}
			nodeObj["http"] = map[string]any{
				"bound_address":               []string{pubAddr},
				"publish_address":             pubAddr,
				"max_content_length_in_bytes": s.maxBodyBytes,
			}
		}
		if selected["plugins"] {
			nodeObj["plugins"] = []any{}
		}
		if selected["modules"] || selected["plugins"] {
			modNames := []string{
				"aggs-matrix-stats", "analysis-common", "constant-keyword",
				"ingest-attachment", "ingest-common", "ingest-geoip", "ingest-user-agent",
				"lang-expression", "lang-mustache", "lang-painless",
				"mapper-extras", "parent-join", "percolator", "rank-eval", "reindex",
			}
			mods := make([]any, 0, len(modNames))
			for _, mn := range modNames {
				mods = append(mods, map[string]any{
					"name":                  mn,
					"version":               esVer,
					"elasticsearch_version": esVer,
					"java_version":          "17",
					"description":           mn + " module",
					"classname":             "org.elasticsearch.module." + mn,
					"extended_plugins":      []any{},
					"has_native_controller": false,
					"licensed":              false,
					"type":                  "isolated",
				})
			}
			nodeObj["modules"] = mods
		}
		if selected["ingest"] {
			rawProcs := s.ingestProcessorTypes()
			procs := make([]any, len(rawProcs))
			for i, pm := range rawProcs {
				procs[i] = pm
			}
			nodeObj["ingest"] = map[string]any{"processors": procs}
		}
		if selected["aggregations"] {
			nodeObj["aggregations"] = buildClusterAggregationsInfoMapRound61()
		}
		nodesMap[taskLocalNodeID] = nodeObj
	} else {
		totalNodes = 0
	}

	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"_nodes": map[string]any{
			"total":      totalNodes,
			"successful": totalNodes,
			"failed":     0,
		},
		"cluster_name": "apache-doris-search-cluster",
		"nodes":        nodesMap,
	})
}

func (s *Server) serveNodesStatsRound60(w http.ResponseWriter, r *http.Request, nodeFilter, metricStr, idxMetricStr string) {
	reqPath := "/_nodes/stats"
	if r != nil && r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	selected := make(map[string]bool)
	if metricStr == "" || metricStr == "_all" || metricStr == "*" {
		for k := range validNodeStatsMetricsRound60 {
			if k != "_all" {
				selected[k] = true
			}
		}
	} else {
		for _, tok := range strings.Split(metricStr, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if !validNodeStatsMetricsRound60[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					formatUnrecognizedMetricErrorRound61(reqPath, tok, validNodeStatsMetricsRound60).Error())
				return
			}
			if tok == "_all" {
				for k := range validNodeStatsMetricsRound60 {
					if k != "_all" {
						selected[k] = true
					}
				}
			} else {
				selected[tok] = true
			}
		}
	}
	idxMetrics, idxErr := parseRequestedNodeIndexStatMetricsRound61(idxMetricStr, reqPath)
	if idxErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", idxErr.Error())
		return
	}

	var nodeIndicesMap map[string]any
	var totalShards int
	var totalStoreBytes int64
	if selected["indices"] || selected["allocations"] {
		var errSt int
		var errTp, errRsn string
		nodeIndicesMap, totalShards, totalStoreBytes, errSt, errTp, errRsn = s.buildNodesStatsIndicesSectionRound61(r, idxMetrics)
		if errSt != 0 {
			writeESError(w, errSt, errTp, errRsn)
			return
		}
	}

	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	human := isTruthyBoolQueryParam(r, "human")
	isES8 := s.isES8Mode(r)
	roles := []string{"data", "ingest", "master", "remote_cluster_client"}
	if isES8 {
		roles = []string{
			"data", "data_cold", "data_content", "data_frozen", "data_hot", "data_warm",
			"ingest", "master", "ml", "remote_cluster_client", "transform",
		}
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	heapMax := uint64(1073741824)
	if mem.Sys > heapMax {
		heapMax = mem.Sys
	}
	pctU := (mem.HeapAlloc * 100) / heapMax
	if pctU > 100 {
		pctU = 100
	}
	heapPct := int(pctU) // #nosec G115 -- bounded to [0, 100]

	nowMS := time.Now().UnixMilli()
	if nowMS < 1700000000000 {
		nowMS = 1700000000000
	}

	var dorisTel *DorisClusterTelemetry
	if tb, ok := s.backend.(TelemetryBackend); ok && tb != nil {
		dorisTel = tb.CollectClusterTelemetry(r.Context(), s.dorisDB)
	}

	buildSingleNodeStats := func(nodeName, hostName, ipAddr string, fsCapTotal, fsCapFree int64, cpuCores int) map[string]any {
		effCPU := runtime.NumCPU()
		if cpuCores > 0 {
			effCPU = cpuCores
		}
		nodeStats := map[string]any{
			"timestamp":         nowMS,
			"name":              nodeName,
			"transport_address": ipAddr + ":9300",
			"host":              hostName,
			"ip":                ipAddr,
			"roles":             roles,
			"attributes":        map[string]any{"backend": "doris", "testattr": "test"},
		}
		if selected["indices"] {
			nodeStats["indices"] = nodeIndicesMap
		}
		if selected["os"] {
			nodeStats["os"] = map[string]any{
				"timestamp": nowMS,
				"cpu":       map[string]any{"percent": 1, "load_average": map[string]any{"1m": 0.1, "5m": 0.1, "15m": 0.1}},
				"mem": map[string]any{
					"total_in_bytes": mem.Sys,
					"free_in_bytes":  mem.Sys - mem.Alloc,
					"used_in_bytes":  mem.Alloc,
					"free_percent":   100 - heapPct,
					"used_percent":   heapPct,
				},
				"swap": map[string]any{"total_in_bytes": int64(0), "free_in_bytes": int64(0), "used_in_bytes": int64(0)},
			}
		}
		if selected["process"] {
			nodeStats["process"] = map[string]any{
				"timestamp":             nowMS,
				"open_file_descriptors": 64,
				"max_file_descriptors":  65536,
				"cpu":                   map[string]any{"percent": 1, "total_in_millis": 100},
				"mem":                   map[string]any{"total_virtual_in_bytes": mem.Sys},
			}
		}
		if selected["jvm"] {
			nodeStats["jvm"] = map[string]any{
				"timestamp":        nowMS,
				"uptime_in_millis": 3600000,
				"mem": map[string]any{
					"heap_used_in_bytes":          mem.HeapAlloc,
					"heap_used_percent":           heapPct,
					"heap_committed_in_bytes":     mem.HeapSys,
					"heap_max_in_bytes":           heapMax,
					"non_heap_used_in_bytes":      mem.StackInuse,
					"non_heap_committed_in_bytes": mem.StackSys,
					"pools": map[string]any{
						"young": map[string]any{"used_in_bytes": mem.HeapAlloc / 2, "max_in_bytes": heapMax / 2, "peak_used_in_bytes": mem.HeapAlloc / 2, "peak_max_in_bytes": heapMax / 2},
						"old":   map[string]any{"used_in_bytes": mem.HeapAlloc / 2, "max_in_bytes": heapMax / 2, "peak_used_in_bytes": mem.HeapAlloc / 2, "peak_max_in_bytes": heapMax / 2},
					},
				},
				"threads": map[string]any{"count": runtime.NumGoroutine(), "peak_count": runtime.NumGoroutine()},
				"gc":      map[string]any{"collectors": map[string]any{"young": map[string]any{"collection_count": 1, "collection_time_in_millis": 5}, "old": map[string]any{"collection_count": 0, "collection_time_in_millis": 0}}},
				"buffer_pools": map[string]any{
					"direct": map[string]any{"count": 1, "used_in_bytes": int64(4096), "total_capacity_in_bytes": int64(4096)},
					"mapped": map[string]any{"count": 0, "used_in_bytes": int64(0), "total_capacity_in_bytes": int64(0)},
				},
				"classes": map[string]any{"current_loaded_count": 1000, "total_loaded_count": 1000, "total_unloaded_count": 0},
			}
		}
		if selected["thread_pool"] {
			nodeStats["thread_pool"] = map[string]any{
				"search": map[string]any{"threads": effCPU, "queue": 0, "active": 0, "rejected": 0, "largest": effCPU, "completed": 0},
				"write":  map[string]any{"threads": effCPU, "queue": 0, "active": 0, "rejected": 0, "largest": effCPU, "completed": 0},
				"get":    map[string]any{"threads": effCPU, "queue": 0, "active": 0, "rejected": 0, "largest": effCPU, "completed": 0},
			}
		}
		if selected["fs"] {
			fsTotalBytes := int64(107374182400)
			fsFreeBytes := int64(53687091200)
			if fsCapTotal > 0 {
				fsTotalBytes = fsCapTotal
				fsFreeBytes = fsCapFree
			}
			fsLowWM := (fsTotalBytes * 15) / 100
			fsHighWM := (fsTotalBytes * 10) / 100
			fsFloodWM := (fsTotalBytes * 5) / 100
			dataEntry := map[string]any{
				"path":                               "/var/lib/doris-es-proxy/data",
				"mount":                              "/ (/dev/disk1s1)",
				"type":                               "apfs",
				"total_in_bytes":                     fsTotalBytes,
				"free_in_bytes":                      fsFreeBytes,
				"available_in_bytes":                 fsFreeBytes,
				"low_watermark_free_space_in_bytes":  fsLowWM,
				"high_watermark_free_space_in_bytes": fsHighWM,
				"flood_stage_free_space_in_bytes":    fsFloodWM,
			}
			totalEntry := map[string]any{
				"total_in_bytes":     fsTotalBytes,
				"free_in_bytes":      fsFreeBytes,
				"available_in_bytes": fsFreeBytes,
			}
			if human {
				dataEntry["total"] = formatBytesHuman(fsTotalBytes)
				dataEntry["free"] = formatBytesHuman(fsFreeBytes)
				dataEntry["available"] = formatBytesHuman(fsFreeBytes)
				dataEntry["low_watermark_free_space"] = formatBytesHuman(fsLowWM)
				dataEntry["high_watermark_free_space"] = formatBytesHuman(fsHighWM)
				dataEntry["flood_stage_free_space"] = formatBytesHuman(fsFloodWM)
				totalEntry["total"] = formatBytesHuman(fsTotalBytes)
				totalEntry["free"] = formatBytesHuman(fsFreeBytes)
				totalEntry["available"] = formatBytesHuman(fsFreeBytes)
			}
			nodeStats["fs"] = map[string]any{
				"timestamp": nowMS,
				"total":     totalEntry,
				"data":      []any{dataEntry},
			}
		}
		if selected["transport"] {
			tMap := map[string]any{
				"server_open":                1,
				"total_outbound_connections": 0,
				"rx_count":                   int64(1),
				"rx_size_in_bytes":           int64(128),
				"tx_count":                   int64(1),
				"tx_size_in_bytes":           int64(128),
				"inbound_handling_time_histogram": []any{
					map[string]any{"ge_millis": 0, "lt_millis": 1, "count": 1},
				},
				"outbound_handling_time_histogram": []any{
					map[string]any{"ge_millis": 0, "lt_millis": 1, "count": 1},
				},
			}
			if human {
				tMap["rx_size"] = "128b"
				tMap["tx_size"] = "128b"
			}
			nodeStats["transport"] = tMap
		}
		if selected["http"] {
			totalOpened := atomic.LoadInt64(&s.totalHTTPRequests)
			if totalOpened < 1 {
				totalOpened = 1
			}
			adminSt := getOrCreateRound61AdminState(s)
			adminSt.mu.RLock()
			clients := make([]any, 0, len(adminSt.httpClients))
			for _, cl := range adminSt.httpClients {
				cm := map[string]any{
					"id":                       cl.id,
					"agent":                    cl.agent,
					"local_address":            cl.localAddress,
					"remote_address":           cl.remoteAddress,
					"last_uri":                 cl.lastURI,
					"x_forwarded_for":          cl.xForwardedFor,
					"opened_time_millis":       cl.openedTimeMillis,
					"last_request_time_millis": cl.lastRequestTimeMillis,
					"request_count":            cl.requestCount,
					"request_size_bytes":       cl.requestSizeBytes,
				}
				if cl.xOpaqueID != "" {
					cm["x_opaque_id"] = cl.xOpaqueID
				}
				clients = append(clients, cm)
			}
			adminSt.mu.RUnlock()
			if len(clients) == 0 {
				lastURI := "/_nodes/stats"
				remoteAddr := "127.0.0.1:50000"
				userAgent := "es-rest-client"
				if r != nil {
					if r.URL != nil && r.URL.RequestURI() != "" {
						lastURI = r.URL.RequestURI()
					}
					if strings.TrimSpace(r.RemoteAddr) != "" {
						remoteAddr = strings.TrimSpace(r.RemoteAddr)
					}
					if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
						userAgent = ua
					}
				}
				clients = []any{
					map[string]any{
						"id":                       int64(1),
						"agent":                    userAgent,
						"local_address":            "127.0.0.1:9200",
						"remote_address":           remoteAddr,
						"last_uri":                 lastURI,
						"x_forwarded_for":          "",
						"opened_time_millis":       nowMS - 1000,
						"last_request_time_millis": nowMS,
						"request_count":            totalOpened,
						"request_size_bytes":       int64(0),
					},
				}
			}
			if int64(len(clients)) > totalOpened {
				totalOpened = int64(len(clients))
			}
			nodeStats["http"] = map[string]any{
				"current_open": len(clients),
				"total_opened": totalOpened,
				"clients":      clients,
				"routes":       map[string]any{},
			}
		}
		if selected["breaker"] {
			nodeStats["breakers"] = map[string]any{
				"request": map[string]any{"limit_size_in_bytes": s.maxBodyBytes, "limit_size": "100mb", "estimated_size_in_bytes": 0, "estimated_size": "0b", "overhead": 1.0, "tripped": 0},
			}
		}
		if selected["script"] {
			nodeStats["script"] = map[string]any{
				"compilations": 0, "cache_evictions": 0, "compilation_limit_triggered": 0,
			}
		}
		if selected["discovery"] {
			mkStateUpdateStat := func(cnt, compMS, appMS int64) map[string]any {
				m := map[string]any{
					"count":                            cnt,
					"computation_time_millis":          compMS,
					"notification_time_millis":         compMS,
					"completion_time_millis":           compMS,
					"publication_time_millis":          compMS,
					"context_construction_time_millis": int64(0),
					"commit_time_millis":               compMS,
					"master_apply_time_millis":         appMS,
					"context_wait_time_millis":         int64(0),
					"application_time_millis":          appMS,
				}
				if human {
					m["computation_time"] = fmt.Sprintf("%dms", compMS)
					m["notification_time"] = fmt.Sprintf("%dms", compMS)
					m["completion_time"] = fmt.Sprintf("%dms", compMS)
					m["publication_time"] = fmt.Sprintf("%dms", compMS)
					m["context_construction_time"] = "0s"
					m["commit_time"] = fmt.Sprintf("%dms", compMS)
					m["master_apply_time"] = fmt.Sprintf("%dms", appMS)
					m["context_wait_time"] = "0s"
					m["application_time"] = fmt.Sprintf("%dms", appMS)
				}
				return m
			}
			mkSerStateStat := func(cnt, uncBytes, compBytes int64) map[string]any {
				m := map[string]any{
					"count":                      cnt,
					"uncompressed_size_in_bytes": uncBytes,
					"compressed_size_in_bytes":   compBytes,
				}
				if human {
					m["uncompressed_size"] = formatBytesHuman(uncBytes)
					m["compressed_size"] = formatBytesHuman(compBytes)
				}
				return m
			}
			rec := map[string]any{
				"name":                             "IndicesClusterStateService",
				"class_name":                       "org.elasticsearch.indices.cluster.IndicesClusterStateService",
				"priority":                         "NORMAL",
				"cumulative_execution_count":       int64(1),
				"cumulative_execution_time_millis": int64(1),
			}
			if human {
				rec["cumulative_execution_time"] = "1ms"
			}
			nodeStats["discovery"] = map[string]any{
				"cluster_state_queue": map[string]any{"total": 0, "pending": 0, "committed": 0},
				"published_cluster_states": map[string]any{
					"full_states":        int64(1),
					"incompatible_diffs": int64(0),
					"compatible_diffs":   int64(1),
				},
				"cluster_state_update": map[string]any{
					"unchanged": mkStateUpdateStat(0, 0, 0),
					"success":   mkStateUpdateStat(1, 1, 1),
					"failure":   mkStateUpdateStat(0, 0, 0),
				},
				"cluster_applier_stats": map[string]any{
					"recordings": []any{rec},
				},
				"serialized_cluster_states": map[string]any{
					"full_states": mkSerStateStat(1, 1024, 512),
					"diffs":       mkSerStateStat(1, 256, 128),
				},
			}
		}
		if selected["ingest"] {
			nodeStats["ingest"] = s.buildNodeIngestStatsRound61(isES8, human)
		}
		if selected["adaptive_selection"] {
			nodeStats["adaptive_selection"] = map[string]any{}
		}
		if selected["script_cache"] {
			nodeStats["script_cache"] = map[string]any{"sum": map[string]any{"compilations": 0, "cache_evictions": 0}, "contexts": []any{}}
		}
		if selected["indexing_pressure"] {
			limitBytes := int64(107374182)
			curMem := map[string]any{
				"combined_coordinating_and_primary_in_bytes": int64(0),
				"coordinating_in_bytes":                      int64(0),
				"primary_in_bytes":                           int64(0),
				"replica_in_bytes":                           int64(0),
				"all_in_bytes":                               int64(0),
			}
			totMem := map[string]any{
				"combined_coordinating_and_primary_in_bytes": int64(0),
				"coordinating_in_bytes":                      int64(0),
				"primary_in_bytes":                           int64(0),
				"replica_in_bytes":                           int64(0),
				"all_in_bytes":                               int64(0),
				"coordinating_rejections":                    int64(0),
				"primary_rejections":                         int64(0),
				"replica_rejections":                         int64(0),
			}
			ipMem := map[string]any{
				"current":        curMem,
				"total":          totMem,
				"limit_in_bytes": limitBytes,
			}
			if human {
				ipMem["limit"] = formatBytesHuman(limitBytes)
				curMem["combined_coordinating_and_primary"] = "0b"
				curMem["coordinating"] = "0b"
				curMem["primary"] = "0b"
				curMem["replica"] = "0b"
				curMem["all"] = "0b"
				totMem["combined_coordinating_and_primary"] = "0b"
				totMem["coordinating"] = "0b"
				totMem["primary"] = "0b"
				totMem["replica"] = "0b"
				totMem["all"] = "0b"
			}
			nodeStats["indexing_pressure"] = map[string]any{"memory": ipMem}
		}
		if selected["repositories"] {
			s.mu.RLock()
			repoNames := make([]string, 0, len(s.snapshotRepos))
			for rn := range s.snapshotRepos {
				repoNames = append(repoNames, rn)
			}
			s.mu.RUnlock()
			sort.Strings(repoNames)
			repoStats := make(map[string]any, len(repoNames))
			for _, rn := range repoNames {
				entry := map[string]any{
					"total_read_throttled_time_nanos":  int64(0),
					"total_write_throttled_time_nanos": int64(0),
				}
				if human {
					entry["total_read_throttled_time"] = "0s"
					entry["total_write_throttled_time"] = "0s"
				}
				repoStats[rn] = entry
			}
			nodeStats["repositories"] = repoStats
		}
		if selected["allocations"] {
			allocMap := map[string]any{
				"shards":                         totalShards,
				"undesired_shards":               0,
				"forecasted_ingest_load":         float64(0.0),
				"forecasted_disk_usage_in_bytes": totalStoreBytes,
				"current_disk_usage_in_bytes":    totalStoreBytes,
			}
			if human {
				allocMap["forecasted_disk_usage"] = formatBytesHuman(totalStoreBytes)
				allocMap["current_disk_usage"] = formatBytesHuman(totalStoreBytes)
			}
			nodeStats["allocations"] = allocMap
		}
		return nodeStats
	}

	nodesMap := map[string]any{}
	totalNodes := 0
	if dorisTel != nil && len(dorisTel.Backends) > 0 {
		if localNodeMatchesFilterRound60(nodeFilter) {
			for idx, be := range dorisTel.Backends {
				nodeID := fmt.Sprintf("doris-be-%s", be.BackendID)
				if be.BackendID == "" {
					nodeID = fmt.Sprintf("doris-be-%d", idx+1)
				}
				host := be.Host
				if host == "" {
					host = "127.0.0.1"
				}
				freeCap := be.AvailCapacityBytes
				if freeCap <= 0 && be.DataUsedCapacityBytes < be.TotalCapacityBytes {
					freeCap = be.TotalCapacityBytes - be.DataUsedCapacityBytes
				}
				nodesMap[nodeID] = buildSingleNodeStats(nodeID, host, host, be.TotalCapacityBytes, freeCap, be.CpuCores)
			}
			totalNodes = len(nodesMap)
		}
	} else if localNodeMatchesFilterRound60(nodeFilter) {
		nodesMap[taskLocalNodeID] = buildSingleNodeStats("doris-es-proxy", "localhost", "127.0.0.1", 0, 0, 0)
		totalNodes = 1
	}

	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"_nodes": map[string]any{
			"total":      totalNodes,
			"successful": totalNodes,
			"failed":     0,
		},
		"cluster_name": "apache-doris-search-cluster",
		"nodes":        nodesMap,
	})
}

var validClusterStateMetricsRound60 = map[string]bool{
	"_all":          true,
	"version":       true,
	"master_node":   true,
	"nodes":         true,
	"routing_table": true,
	"routing_nodes": true,
	"metadata":      true,
	"blocks":        true,
	"customs":       true,
}

func (s *Server) handleClusterStateRound60(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	metricStr := "_all"
	indexPattern := ""
	if len(segs) >= 3 {
		metricStr = segs[2]
	}
	if len(segs) >= 4 {
		indexPattern = segs[3]
	}

	selected := make(map[string]bool)
	if metricStr == "" || metricStr == "_all" || metricStr == "*" {
		for k := range validClusterStateMetricsRound60 {
			if k != "_all" {
				selected[k] = true
			}
		}
	} else {
		for _, tok := range strings.Split(metricStr, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if !validClusterStateMetricsRound60[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("request [/_cluster/state] contains unrecognized metric: [%s]", tok))
				return
			}
			if tok == "_all" {
				for k := range validClusterStateMetricsRound60 {
					if k != "_all" {
						selected[k] = true
					}
				}
			} else {
				selected[tok] = true
			}
		}
	}

	_ = s.syncCatalogFromBackend(r.Context())
	rawEW := strings.TrimSpace(r.URL.Query().Get("expand_wildcards"))
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(rawEW)
	if ewErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
		return
	}
	if rawEW == "" {
		ewOpen = true
		ewClosed = true
		ewHidden = true
	}
	hasExplicitIgnoreUnavail := r.URL.Query().Has("ignore_unavailable")
	ignoreUnavail := true
	if hasExplicitIgnoreUnavail {
		ignoreUnavail = isTruthyBoolQueryParam(r, "ignore_unavailable")
	}
	allowNoIndices := true
	if r.URL.Query().Has("allow_no_indices") {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}

	var allowedIndices map[string]bool
	if indexPattern != "" {
		allowedIndices = make(map[string]bool)
		if indexPattern == "_all" || indexPattern == "*" {
			if !ewNone {
				s.mu.RLock()
				for idxName := range s.indices {
					isClosed := s.closedIndices[idxName]
					if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
						continue
					}
					isHid := s.isIndexExplicitlyHiddenLocked(idxName) || strings.HasPrefix(idxName, ".")
					if isHid && !ewHidden {
						continue
					}
					allowedIndices[idxName] = true
				}
				s.mu.RUnlock()
			}
			if len(allowedIndices) == 0 && !allowNoIndices {
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+indexPattern+"]")
				return
			}
		} else {
			s.mu.RLock()
			var missingConcrete string
			concreteSet := make(map[string]bool)
			explicitDot := false
			for _, part := range strings.Split(indexPattern, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") {
					continue
				}
				if strings.HasPrefix(part, ".") {
					explicitDot = true
				}
				if strings.ContainsAny(part, "*?") || part == "_all" {
					continue
				}
				_, isIdx := s.indices[part]
				alTargets, isAl := s.aliases[part]
				_, isDS := s.dataStreams[part]
				if !isIdx && (!isAl || len(alTargets) == 0) && !isDS && missingConcrete == "" {
					missingConcrete = part
				}
				if isIdx {
					concreteSet[part] = true
				}
				for _, at := range alTargets {
					concreteSet[at] = true
				}
			}
			s.mu.RUnlock()
			if missingConcrete != "" && !ignoreUnavail {
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+missingConcrete+"]")
				return
			}
			targets, _ := s.resolveTargetIndicesWithOptions(indexPattern, ewHidden || explicitDot)
			s.mu.RLock()
			for _, t := range targets {
				if _, exists := s.indices[t]; !exists {
					continue
				}
				if !concreteSet[t] {
					if ewNone {
						continue
					}
					isClosed := s.closedIndices[t]
					if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
						continue
					}
					isHid := s.isIndexExplicitlyHiddenLocked(t) || strings.HasPrefix(t, ".")
					if isHid && !ewHidden && !explicitDot {
						continue
					}
				} else if _, isDirectIdx := s.indices[indexPattern]; !isDirectIdx && rawEW != "" {
					isClosed := s.closedIndices[t]
					if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
						continue
					}
				}
				allowedIndices[t] = true
			}
			s.mu.RUnlock()
			if len(allowedIndices) == 0 && !allowNoIndices {
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+indexPattern+"]")
				return
			}
		}
	} else if rawEW != "" {
		allowedIndices = make(map[string]bool)
		if !ewNone {
			s.mu.RLock()
			for idxName := range s.indices {
				isClosed := s.closedIndices[idxName]
				if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
					continue
				}
				isHid := s.isIndexExplicitlyHiddenLocked(idxName) || strings.HasPrefix(idxName, ".")
				if isHid && !ewHidden {
					continue
				}
				allowedIndices[idxName] = true
			}
			s.mu.RUnlock()
		}
	}

	s.mu.RLock()
	indicesMeta := make(map[string]any, len(s.indices))
	routingIndices := make(map[string]any, len(s.indices))
	var stateTargetList []string
	for name, idx := range s.indices {
		if allowedIndices != nil && !allowedIndices[name] {
			continue
		}
		stateTargetList = append(stateTargetList, name)
		state := "open"
		if s.closedIndices[name] {
			state = "close"
		}
		mappings := map[string]any{}
		if docMap := buildMappingResponseMapRound59(idx); len(docMap) > 0 {
			mappings["_doc"] = docMap
		}
		var aliasList []string
		for alias, targets := range s.aliases {
			for _, t := range targets {
				if t == name {
					aliasList = append(aliasList, alias)
				}
			}
		}
		if aliasList == nil {
			aliasList = []string{}
		}
		shortFlat := s.buildIndexSettingsMapLocked(name)
		indicesMeta[name] = map[string]any{
			"state":    state,
			"settings": formatIndexSettingsOutput(shortFlat, isTruthyBoolQueryParam(r, "flat_settings")),
			"mappings": mappings,
			"aliases":  aliasList,
		}
		routingIndices[name] = map[string]any{
			"shards": map[string]any{
				"0": []any{
					map[string]any{
						"state":   "STARTED",
						"primary": true,
						"node":    taskLocalNodeID,
						"shard":   0,
						"index":   name,
					},
				},
			},
		}
	}
	votingExcl := make([]any, 0, len(s.votingExclusions))
	for _, ve := range s.votingExclusions {
		votingExcl = append(votingExcl, deepCloneDocMap(ve))
	}
	s.mu.RUnlock()

	resp := map[string]any{
		"cluster_name":             "apache-doris-search-cluster",
		"cluster_uuid":             "doris-es-proxy-uuid-0001",
		"compressed_size_in_bytes": 1024,
		"state_uuid":               "state-uuid-0001",
	}
	if selected["version"] {
		resp["version"] = 1
	}
	if selected["master_node"] {
		resp["master_node"] = taskLocalNodeID
	}
	if selected["blocks"] {
		resp["blocks"] = s.buildClusterStateBlocksR62Admin(stateTargetList)
	}
	if selected["customs"] {
		resp["customs"] = map[string]any{}
	}
	if selected["nodes"] {
		resp["nodes"] = map[string]any{
			taskLocalNodeID: map[string]any{
				"name":              "doris-es-proxy",
				"ephemeral_id":      "doris-ephemeral-1",
				"transport_address": "127.0.0.1:9300",
				"attributes":        map[string]any{"backend": "doris"},
				"roles":             []string{"data", "ingest", "master"},
			},
		}
	}
	if selected["metadata"] {
		coord := map[string]any{
			"voting_config_exclusions": votingExcl,
		}
		resp["metadata"] = map[string]any{
			"cluster_uuid":           "doris-es-proxy-uuid-0001",
			"cluster_uuid_committed": true,
			"templates":              map[string]any{},
			"indices":                indicesMeta,
			"cluster_coordination":   coord,
		}
		resp["cluster_coordination"] = coord
	}
	if selected["routing_table"] {
		resp["routing_table"] = map[string]any{
			"indices": routingIndices,
		}
	}
	if selected["routing_nodes"] {
		resp["routing_nodes"] = map[string]any{
			"unassigned": []any{},
			"nodes":      map[string]any{taskLocalNodeID: []any{}},
		}
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) handleClusterStatsRound60(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	nodeFilter := "_all"
	if len(segs) >= 4 && segs[2] == "nodes" {
		nodeFilter = segs[3]
	}
	matched := localNodeMatchesFilterRound60(nodeFilter)

	_ = s.syncCatalogFromBackend(r.Context())

	var dorisTel *DorisClusterTelemetry
	if tb, ok := s.backend.(TelemetryBackend); ok && tb != nil {
		dorisTel = tb.CollectClusterTelemetry(r.Context(), s.dorisDB)
	}

	s.mu.RLock()
	openIndices := make([]string, 0, len(s.indices))
	schemasByIdx := make(map[string]*schema.IndexSchema, len(s.indices))
	numPipelines := len(s.pipelines)
	hasYellowReplica := false
	for idxName, sc := range s.indices {
		if s.closedIndices[idxName] {
			continue
		}
		openIndices = append(openIndices, idxName)
		schemasByIdx[idxName] = sc
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, rk := range []string{"number_of_replicas", "index.number_of_replicas"} {
				if rv, okR := cust[rk]; okR {
					if rn, errR := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rv))); errR == nil && rn > 0 {
						hasYellowReplica = true
					}
				}
			}
		}
	}
	s.mu.RUnlock()
	sort.Strings(openIndices)

	indexCount := len(openIndices)
	var totalDocs, totalDeleted, totalStoreBytes int64
	if matched {
		for _, idxName := range openIndices {
			dCnt, delCnt, bCnt := s.computeAdjustedLiveDocCountRound61(r.Context(), idxName)
			if bCnt == 0 && dorisTel != nil && len(dorisTel.Tables) > 0 {
				if sc := schemasByIdx[idxName]; sc != nil {
					if td, okT := dorisTel.Tables[sc.DorisTable]; okT {
						if td.SizeBytes > 0 {
							bCnt = td.SizeBytes
						}
						if dCnt == 0 && td.RowCount > 0 {
							dCnt = td.RowCount
						}
					}
				}
			}
			totalDocs += dCnt
			totalDeleted += delCnt
			totalStoreBytes += bCnt
		}
	}

	fsTotalBytes := int64(107374182400)
	fsFreeBytes := int64(53687091200)
	if dorisTel != nil && len(dorisTel.Backends) > 0 && dorisTel.TotalCapacityBytes > 0 {
		fsTotalBytes = dorisTel.TotalCapacityBytes
		fsFreeBytes = dorisTel.AvailCapacityBytes
		if fsFreeBytes <= 0 && dorisTel.DataUsedBytes < fsTotalBytes {
			fsFreeBytes = fsTotalBytes - dorisTel.DataUsedBytes
		}
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	esVer := s.effectiveClusterESVersionNumber(r)

	nodeCnt := 1
	if dorisTel != nil && dorisTel.AliveNodes > 0 {
		nodeCnt = dorisTel.AliveNodes
	} else if dorisTel != nil && len(dorisTel.Backends) > 0 {
		nodeCnt = len(dorisTel.Backends)
	}
	if !matched {
		nodeCnt = 0
		indexCount = 0
		totalDocs = 0
		totalDeleted = 0
		totalStoreBytes = 0
	}
	clusterStatus := "green"
	if hasYellowReplica && (dorisTel == nil || dorisTel.AliveNodes <= 1) {
		clusterStatus = "yellow"
	}

	indicesStatsMap := map[string]any{
		"count": indexCount,
		"shards": map[string]any{
			"total":       indexCount,
			"primaries":   indexCount,
			"replication": 0.0,
		},
		"docs": map[string]any{
			"count":   totalDocs,
			"deleted": totalDeleted,
		},
		"store": map[string]any{
			"size_in_bytes":     totalStoreBytes,
			"reserved_in_bytes": int64(0),
		},
		"fielddata":   map[string]any{"memory_size_in_bytes": int64(0), "evictions": 0},
		"query_cache": map[string]any{"memory_size_in_bytes": int64(0), "total_count": int64(0), "hit_count": int64(0), "miss_count": int64(0), "cache_size": int64(0), "cache_count": 0, "evictions": int64(0)},
		"completion":  map[string]any{"size_in_bytes": int64(0)},
		"segments": map[string]any{
			"count":                         indexCount,
			"memory_in_bytes":               int64(0),
			"terms_memory_in_bytes":         int64(0),
			"stored_fields_memory_in_bytes": int64(0),
			"term_vectors_memory_in_bytes":  int64(0),
			"norms_memory_in_bytes":         int64(0),
			"points_memory_in_bytes":        int64(0),
			"doc_values_memory_in_bytes":    int64(0),
			"index_writer_memory_in_bytes":  int64(0),
			"version_map_memory_in_bytes":   int64(0),
			"fixed_bit_set_memory_in_bytes": int64(0),
			"max_unsafe_auto_id_timestamp":  int64(-1),
			"file_sizes":                    map[string]any{},
		},
	}
	nodesStatsMap := map[string]any{
		"count": map[string]any{
			"total":                 nodeCnt,
			"coordinating_only":     0,
			"data":                  nodeCnt,
			"ingest":                nodeCnt,
			"master":                nodeCnt,
			"remote_cluster_client": nodeCnt,
		},
		"versions": []string{esVer},
		"os": map[string]any{
			"available_processors": runtime.NumCPU(),
			"allocated_processors": runtime.NumCPU(),
			"names":                []any{map[string]any{"name": runtime.GOOS, "count": nodeCnt}},
			"mem":                  map[string]any{"total_in_bytes": mem.Sys, "free_in_bytes": mem.Sys - mem.Alloc, "used_in_bytes": mem.Alloc, "free_percent": 50, "used_percent": 50},
		},
		"process": map[string]any{
			"cpu":                   map[string]any{"percent": 1},
			"open_file_descriptors": map[string]any{"min": 64, "max": 64, "avg": 64},
		},
		"jvm": map[string]any{
			"max_uptime_in_millis": 3600000,
			"versions":             []any{map[string]any{"version": "21.0.1", "vm_name": "Go Runtime", "vm_version": runtime.Version(), "vm_vendor": "Go", "bundled_jdk": true, "using_bundled_jdk": true, "count": nodeCnt}},
			"mem":                  map[string]any{"heap_used_in_bytes": mem.HeapAlloc, "heap_max_in_bytes": 1073741824},
			"threads":              runtime.NumGoroutine(),
		},
		"fs": map[string]any{
			"total_in_bytes":     fsTotalBytes,
			"free_in_bytes":      fsFreeBytes,
			"available_in_bytes": fsFreeBytes,
		},
		"plugins": []any{},
		"network_types": map[string]any{
			"transport_types": map[string]any{"netty4": nodeCnt},
			"http_types":      map[string]any{"netty4": nodeCnt},
		},
		"discovery_types": map[string]any{
			"single-node": nodeCnt,
		},
		"packaging_types": []any{
			map[string]any{"flavor": "default", "type": "docker", "count": nodeCnt},
		},
		"ingest": map[string]any{
			"number_of_pipelines": numPipelines,
			"processor_stats":     map[string]any{},
		},
	}
	respMap := map[string]any{
		"_nodes": map[string]any{
			"total":      nodeCnt,
			"successful": nodeCnt,
			"failed":     0,
		},
		"cluster_name": "apache-doris-search-cluster",
		"cluster_uuid": "doris-es-proxy-uuid-0001",
		"timestamp":    time.Now().UnixMilli(),
		"status":       clusterStatus,
		"indices":      indicesStatsMap,
		"nodes":        nodesStatsMap,
	}
	enrIndices := openIndices
	if !matched {
		enrIndices = nil
	}
	s.enrichClusterStatsR62Admin(r, enrIndices, totalDocs, totalStoreBytes, indicesStatsMap, nodesStatsMap, respMap)
	writeJSONWithRequest(w, r, http.StatusOK, respMap)
}

// ---------- Search Validation Helpers (F8 & F9) ----------

// validateRestTotalHitsAsIntWithRawBody checks ES search/220_total_hits_object.yml rules:
// - `rest_total_hits_as_int=true` + `track_total_hits: false` -> 200 OK with `hits.total: -1`
// - `rest_total_hits_as_int=true` + `track_total_hits: true` or `-1` or omitted -> 200 OK with integer total
// - `rest_total_hits_as_int=true` + `track_total_hits: <int != -1>` -> 400 illegal_argument_exception
func validateRestTotalHitsAsIntWithRawBody(r *http.Request, rawBody []byte, forceRestTotalHits bool) (isNegOneAccurate bool, errReason string) {
	restAsInt := forceRestTotalHits || isTruthyBoolQueryParam(r, "rest_total_hits_as_int")
	// Check query parameter track_total_hits first if present
	if r != nil && r.URL != nil && r.URL.Query().Has("track_total_hits") {
		qv := strings.TrimSpace(r.URL.Query().Get("track_total_hits"))
		low := strings.ToLower(qv)
		if low != "true" && low != "false" {
			n, err := strconv.ParseInt(qv, 10, 64)
			if err != nil {
				return false, fmt.Sprintf("Failed to parse value [%s] as track_total_hits", qv)
			}
			if n == -1 {
				return true, ""
			}
			if n <= 0 {
				return false, fmt.Sprintf("[track_total_hits] parameter must be positive or equals to -1, got %d", n)
			}
			if restAsInt {
				return false, fmt.Sprintf("[rest_total_hits_as_int] cannot be used if the tracking of total hits is not accurate, got %d", n)
			}
		}
	}
	if len(bytes.TrimSpace(rawBody)) == 0 || !bytes.Contains(rawBody, []byte("track_total_hits")) {
		return false, ""
	}
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return false, ""
	}
	tth, exists := m["track_total_hits"]
	if !exists || tth == nil {
		return false, ""
	}
	switch v := tth.(type) {
	case bool:
		return false, ""
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return false, fmt.Sprintf("Failed to parse value [%s] as track_total_hits", v.String())
		}
		if n == -1 {
			return true, ""
		}
		if n <= 0 {
			return false, fmt.Sprintf("[track_total_hits] parameter must be positive or equals to -1, got %d", n)
		}
		if restAsInt {
			return false, fmt.Sprintf("[rest_total_hits_as_int] cannot be used if the tracking of total hits is not accurate, got %d", n)
		}
	case string:
		low := strings.ToLower(strings.TrimSpace(v))
		if low == "true" || low == "false" {
			return false, ""
		}
		n, err := strconv.ParseInt(low, 10, 64)
		if err != nil {
			return false, fmt.Sprintf("Failed to parse value [%s] as track_total_hits", v)
		}
		if n == -1 {
			return true, ""
		}
		if n <= 0 {
			return false, fmt.Sprintf("[track_total_hits] parameter must be positive or equals to -1, got %d", n)
		}
		if restAsInt {
			return false, fmt.Sprintf("[rest_total_hits_as_int] cannot be used if the tracking of total hits is not accurate, got %d", n)
		}
	}
	return false, ""
}

// extractScrollFromBodyAndMaxKeepAlive extracts `"scroll"` from a POST /_search JSON body if not in URL
// and enforces `search.max_keep_alive` (default 24h).
func (s *Server) extractAndValidateScrollParamRound60(r *http.Request, rawBody []byte) (hasScroll bool, scrollTTL time.Duration, errReason string) {
	rawScroll := ""
	if r != nil && r.URL != nil && r.URL.Query().Has("scroll") {
		hasScroll = true
		rawScroll = r.URL.Query().Get("scroll")
	} else if len(bytes.TrimSpace(rawBody)) > 0 && bytes.Contains(rawBody, []byte(`"scroll"`)) {
		dec := json.NewDecoder(bytes.NewReader(rawBody))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err == nil && m != nil {
			if sv, ok := m["scroll"].(string); ok {
				hasScroll = true
				rawScroll = sv
				if r != nil && r.URL != nil {
					q := r.URL.Query()
					q.Set("scroll", sv)
					r.URL.RawQuery = q.Encode()
				}
			}
		}
	}
	if !hasScroll {
		return false, 0, ""
	}
	ttl, err := parseESPositiveDuration(rawScroll)
	if err != nil {
		return true, 0, fmt.Sprintf("failed to parse scroll duration [%s]: %v", rawScroll, err)
	}
	maxKeepAlive := 24 * time.Hour
	s.mu.RLock()
	if rawMax, ok := s.getClusterSettingStringLocked("search.max_keep_alive"); ok && strings.TrimSpace(rawMax) != "" {
		if parsedMax, mErr := parseESPositiveDuration(rawMax); mErr == nil && parsedMax > 0 {
			maxKeepAlive = parsedMax
		}
	}
	s.mu.RUnlock()
	if ttl > maxKeepAlive {
		return true, 0, fmt.Sprintf("Keep alive for scroll (%s) is too large. It must be less than or equal to (%s). This limit can be set by changing the [search.max_keep_alive] cluster level setting.", rawScroll, formatESDurationR61Admin(maxKeepAlive))
	}
	return true, ttl, ""
}

func (s *Server) findMissingConcreteSearchIndexRound60(ctx context.Context, r *http.Request, rawIndex string, ignoreUnavailableOverride *bool) string {
	if !s.hasAuthoritativeIndexCatalog() {
		return ""
	}
	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	if ignoreUnavailableOverride != nil {
		ignoreUnavailable = *ignoreUnavailableOverride
	}
	if ignoreUnavailable {
		return ""
	}
	rawIndex = strings.TrimSpace(rawIndex)
	if rawIndex == "" || rawIndex == "_all" || rawIndex == "*" {
		return ""
	}
	checkOnce := func() string {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, part := range strings.Split(rawIndex, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
				continue
			}
			_, isIdx := s.indices[part]
			aliasTargets, isAlias := s.aliases[part]
			_, isDS := s.dataStreams[part]
			if !isIdx && (!isAlias || len(aliasTargets) == 0) && !isDS {
				if strings.HasPrefix(part, ".ds-") && strings.HasSuffix(part, "-000001") {
					dsName := strings.TrimSuffix(strings.TrimPrefix(part, ".ds-"), "-000001")
					if _, okDS := s.dataStreams[dsName]; okDS {
						continue
					}
				}
				return part
			}
		}
		return ""
	}
	missing := checkOnce()
	if missing != "" {
		_ = s.syncCatalogFromBackend(ctx)
		missing = checkOnce()
	}
	return missing
}

// isReservedActionEndpointSegment returns true if seg starts with `_` (excluding `_doc` when checking legacy types).
func isReservedActionEndpointSegment(seg string) bool {
	return strings.HasPrefix(seg, "_")
}

func (s *Server) applyDocTypeToSearchResponseRound60(resp map[string]any, r *http.Request) {
	if resp == nil {
		return
	}
	if rawSID, okSID := resp["_scroll_id"].(string); okSID && rawSID != "" {
		if uniqueSID, okU := popPendingUniqueScrollTokenR62Admin(s, rawSID); okU {
			resp["_scroll_id"] = uniqueSID
		}
	}
	es8 := s.isES8Mode(r)
	docType := legacyDocTypeFromRequest(r)
	resolveHitType := func(hm map[string]any) string {
		if docType == "" || docType == "_doc" || docType == "_all" {
			if idxName, _ := hm["_index"].(string); idxName != "" && s != nil {
				s.mu.RLock()
				idx := s.indices[idxName]
				s.mu.RUnlock()
				if idx != nil && idx.LegacyTypeName != "" {
					return idx.LegacyTypeName
				}
			}
			if docType == "" || docType == "_all" {
				return "_doc"
			}
		}
		return docType
	}
	var patchHitsEnv func(env map[string]any)
	patchHitsEnv = func(env map[string]any) {
		if env == nil {
			return
		}
		switch hs := env["hits"].(type) {
		case []map[string]any:
			for _, hm := range hs {
				if hm == nil {
					continue
				}
				if es8 {
					delete(hm, "_type")
				} else {
					hm["_type"] = resolveHitType(hm)
				}
				if ihMap, ok := hm["inner_hits"].(map[string]any); ok {
					for _, ihv := range ihMap {
						if ihe, ok := ihv.(map[string]any); ok {
							if subHits, ok := ihe["hits"].(map[string]any); ok {
								patchHitsEnv(subHits)
							}
						}
					}
				}
			}
		case []any:
			for _, item := range hs {
				hm, ok := item.(map[string]any)
				if !ok || hm == nil {
					continue
				}
				if es8 {
					delete(hm, "_type")
				} else {
					hm["_type"] = resolveHitType(hm)
				}
				if ihMap, ok := hm["inner_hits"].(map[string]any); ok {
					for _, ihv := range ihMap {
						if ihe, ok := ihv.(map[string]any); ok {
							if subHits, ok := ihe["hits"].(map[string]any); ok {
								patchHitsEnv(subHits)
							}
						}
					}
				}
			}
		}
	}
	if topHits, ok := resp["hits"].(map[string]any); ok {
		patchHitsEnv(topHits)
	}
	var walkAggs func(m map[string]any)
	walkAggs = func(m map[string]any) {
		for k, v := range m {
			if k == "hits" {
				if he, ok := v.(map[string]any); ok {
					patchHitsEnv(he)
				}
				continue
			}
			if k == "buckets" {
				switch bs := v.(type) {
				case []map[string]any:
					for _, b := range bs {
						walkAggs(b)
					}
				case []any:
					for _, item := range bs {
						if b, ok := item.(map[string]any); ok {
							walkAggs(b)
						}
					}
				case map[string]any:
					for _, item := range bs {
						if b, ok := item.(map[string]any); ok {
							walkAggs(b)
						}
					}
				}
				continue
			}
			if sub, ok := v.(map[string]any); ok {
				walkAggs(sub)
			}
		}
	}
	if aggs, ok := resp["aggregations"].(map[string]any); ok {
		walkAggs(aggs)
	}
}

func (s *Server) overlayUnrefreshedDocsOnHitsRound60(
	ctx context.Context,
	indexName string,
	rawIdxSchema *schema.IndexSchema,
	query *esast.Query,
	size int,
	hits []HitRow,
	aggRows []AggRow,
	idxTotal int64,
) ([]HitRow, []AggRow, int64) {
	unref := s.getUnrefreshedDocsForIndex(indexName)
	if len(unref) == 0 {
		return hits, aggRows, idxTotal
	}
	docIDs := make([]string, 0, len(unref))
	for id := range unref {
		docIDs = append(docIDs, id)
	}
	sort.Strings(docIDs)
	for _, docID := range docIDs {
		st := unref[docID]
		hitPos := -1
		for i := range hits {
			if hits[i].ID == docID {
				hitPos = i
				break
			}
		}
		liveMatched := hitPos >= 0
		if !liveMatched && size == 0 && rawIdxSchema != nil {
			if liveHit, found, err := s.backend.GetDocByID(ctx, rawIdxSchema.DorisDB, rawIdxSchema.DorisTable, docID); err == nil && found && liveHit != nil {
				liveMatched = query == nil || s.docMatchesAliasFilter(ctx, indexName, docID, liveHit.Source, query)
			}
		}
		prevMatched := st.existedBefore && (query == nil || s.docMatchesAliasFilter(ctx, indexName, docID, st.prevHit.Source, query))
		switch {
		case liveMatched && !prevMatched:
			if idxTotal > 0 {
				idxTotal--
			}
			if hitPos >= 0 {
				hits = append(hits[:hitPos], hits[hitPos+1:]...)
			}
		case !liveMatched && prevMatched:
			idxTotal++
			if size > 0 {
				restored := st.prevHit
				restored.Index = indexName
				if restored.Score == 0 {
					restored.Score = 1.0
				}
				restored.SeqNo = s.getDocSeqNo(indexName, docID, restored.Version)
				restored.HasSeqNo = true
				hits = append(hits, restored)
			}
		case liveMatched && prevMatched:
			if hitPos >= 0 {
				restored := st.prevHit
				restored.Index = indexName
				restored.Score = hits[hitPos].Score
				restored.SeqNo = s.getDocSeqNo(indexName, docID, restored.Version)
				restored.HasSeqNo = true
				hits[hitPos] = restored
			}
		}
	}
	for i := range hits {
		hits[i].TotalHits = idxTotal
	}
	for i := range aggRows {
		if aggRows[i].AggName == "__meta_total" || aggRows[i].AggName == "__meta_query_total" {
			aggRows[i].DocCount = idxTotal
			aggRows[i].Value = float64(idxTotal)
		}
	}
	return hits, aggRows, idxTotal
}

var _ = io.Discard
