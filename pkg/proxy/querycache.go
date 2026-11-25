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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

const (
	defaultShardRequestCacheMaxEntriesR63    = 512
	defaultShardRequestCacheMaxBytesR63      = 64 << 20 // 64 MiB total payload budget
	defaultShardRequestCacheMaxEntryBytesR63 = 1 << 20  // 1 MiB per-entry payload cap
)

type shardRequestCacheEntryR63 struct {
	payload        []byte
	unindexedField []string
	targets        []string
}

type shardRequestCacheStoreR63 struct {
	mu             sync.RWMutex
	entries        map[string]shardRequestCacheEntryR63
	order          []string
	maxSize        int
	maxBytes       int64
	maxEntryBytes  int64
	totalBytes     int64
	hitsByIdx      map[string]int64
	missesByIdx    map[string]int64
	evictionsByIdx map[string]int64
	bytesByIdx     map[string]int64
}

var (
	serverShardReqCachesMuR63 sync.Mutex
	serverShardReqCachesR63   = make(map[*Server]*shardRequestCacheStoreR63)
)

func (s *Server) getOrCreateShardRequestCacheR63() *shardRequestCacheStoreR63 {
	if s == nil {
		return nil
	}
	serverShardReqCachesMuR63.Lock()
	defer serverShardReqCachesMuR63.Unlock()
	st := serverShardReqCachesR63[s]
	if st == nil {
		st = &shardRequestCacheStoreR63{
			entries:        make(map[string]shardRequestCacheEntryR63),
			maxSize:        defaultShardRequestCacheMaxEntriesR63,
			maxBytes:       defaultShardRequestCacheMaxBytesR63,
			maxEntryBytes:  defaultShardRequestCacheMaxEntryBytesR63,
			hitsByIdx:      make(map[string]int64),
			missesByIdx:    make(map[string]int64),
			evictionsByIdx: make(map[string]int64),
			bytesByIdx:     make(map[string]int64),
		}
		serverShardReqCachesR63[s] = st
	}
	return st
}

func (s *Server) invalidateShardRequestCacheR63() {
	if s == nil {
		return
	}
	serverShardReqCachesMuR63.Lock()
	st := serverShardReqCachesR63[s]
	serverShardReqCachesMuR63.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	clear(st.entries)
	st.order = st.order[:0]
	st.totalBytes = 0
	clear(st.bytesByIdx)
	st.mu.Unlock()
}

func (s *Server) cleanupShardRequestCacheR63() {
	if s == nil {
		return
	}
	serverShardReqCachesMuR63.Lock()
	delete(serverShardReqCachesR63, s)
	serverShardReqCachesMuR63.Unlock()
}

// isShardRequestCacheEnabledForSearchR63 implements Elasticsearch's shard request cache eligibility rules:
//   - Explicit `?request_cache=true` enables caching (even when `size > 0`); `?request_cache=false` disables it.
//   - Index setting `index.requests.cache.enable: false` disables it unless overridden by `?request_cache=true`.
//   - When `?request_cache` is omitted, ES enables the shard request cache by default when `size == 0`
//     (aggregation / count-only searches) and the query does not use `scroll`, `profile`, `pit`, `now`, or `random_score`.
func (s *Server) isShardRequestCacheEnabledForSearchR63(
	httpReq *http.Request,
	targets []string,
	req *esast.SearchRequest,
	rawSearchBody []byte,
	aliasHasNow bool,
	bypassCache bool,
) bool {
	if s == nil || httpReq == nil || req == nil || len(targets) == 0 || aliasHasNow || bypassCache {
		return false
	}
	if httpReq != nil && httpReq.URL != nil {
		q := httpReq.URL.Query()
		if q.Has("scroll") {
			return false
		}
		if q.Has("request_cache") {
			rawRC := strings.TrimSpace(q.Get("request_cache"))
			if strings.EqualFold(rawRC, "false") || rawRC == "0" {
				return false
			}
			if strings.EqualFold(rawRC, "true") || rawRC == "1" {
				return !searchBodyIsNonDeterministicForCacheR63(req, rawSearchBody)
			}
		}
	}

	// Default when `?request_cache` query param is not set: enabled only for `size == 0`
	if req.Size == nil || *req.Size != 0 {
		return false
	}

	// Respect `index.requests.cache.enable` setting across target indices (flat or nested map)
	s.mu.RLock()
	for _, t := range targets {
		if cs := s.indexCustomSettings[t]; len(cs) > 0 {
			if rawV, ok := lookupRawIndexSettingPresenceR62Admin(cs, "requests.cache.enable"); ok && rawV != nil {
				if en, okB := parseOptionalBoolAny(rawV); okB && !en {
					s.mu.RUnlock()
					return false
				}
			}
			for _, k := range []string{"index.requests.cache.enable", "requests.cache.enable"} {
				if v, ok := cs[k]; ok && v != nil {
					if en, okB := parseOptionalBoolAny(v); okB && !en {
						s.mu.RUnlock()
						return false
					}
				}
			}
		}
	}
	s.mu.RUnlock()

	return !searchBodyIsNonDeterministicForCacheR63(req, rawSearchBody)
}

func searchBodyIsNonDeterministicForCacheR63(req *esast.SearchRequest, rawBody []byte) bool {
	if req != nil && queryContainsNow(req.Query) {
		return true
	}
	if req != nil && queryHasRandomScoreR63(req.Query) {
		return true
	}
	if bytes.Contains(rawBody, []byte(`"random_score"`)) {
		return true
	}
	if bytes.Contains(rawBody, []byte("now")) && (bytes.Contains(rawBody, []byte(`"now"`)) || bytes.Contains(rawBody, []byte("now-")) || bytes.Contains(rawBody, []byte("now+")) || bytes.Contains(rawBody, []byte("now/"))) {
		return true
	}
	return false
}

func queryHasRandomScoreR63(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.RandomScore != nil {
			return true
		}
		for _, fn := range q.FunctionScore.Functions {
			if fn.RandomScore != nil || queryHasRandomScoreR63(fn.Filter) {
				return true
			}
		}
		if queryHasRandomScoreR63(q.FunctionScore.Query) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasRandomScoreR63(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasRandomScoreR63(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryHasRandomScoreR63(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryHasRandomScoreR63(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryHasRandomScoreR63(&q.ConstantScore.Filter) {
		return true
	}
	return false
}

func (s *Server) buildShardRequestCacheKeyR63(
	httpReq *http.Request,
	cacheTargets []string,
	targets []string,
	req *esast.SearchRequest,
	rawBody []byte,
) string {
	h := sha256.New()
	sortedTargets := append([]string(nil), cacheTargets...)
	sort.Strings(sortedTargets)
	for _, ct := range sortedTargets {
		_, _ = h.Write([]byte(ct))
		_, _ = h.Write([]byte{0})
	}

	// Bind key to live schema content + write sequence numbers + unrefreshed pending counts + auth/principal identity
	// so any mapping update (`PUT /_mapping`, dynamic promotion), document mutation, or security/credential change
	// automatically isolates/busts the cache, without depending on `*schema.IndexSchema` pointer identity.
	s.mu.RLock()
	for _, t := range targets {
		sc := s.indices[t]
		seq := s.indexNextSeqNo[t]
		unrefCount := 0
		if byShard := s.unrefreshedDocs[t]; len(byShard) > 0 {
			for _, m := range byShard {
				unrefCount += len(m)
			}
		}
		fieldsCount := 0
		var rawMapBytes []byte
		if sc != nil {
			fieldsCount = len(sc.Fields)
			if sc.RawMapping != nil {
				rawMapBytes, _ = json.Marshal(sc.RawMapping)
			}
		}
		_, _ = fmt.Fprintf(h, "idx=%s|fc=%d|seq=%d|ur=%d|", t, fieldsCount, seq, unrefCount)
		_, _ = h.Write(rawMapBytes)
		_, _ = h.Write([]byte{';'})
	}
	s.appendAuthPrincipalToCacheKeyLockedR65(h, httpReq)
	s.mu.RUnlock()

	if httpReq != nil && httpReq.URL != nil {
		q := httpReq.URL.Query()
		for _, k := range []string{"q", "df", "analyzer", "default_operator", "lenient", "routing", "preference", "search_type", "typed_keys", "rest_total_hits_as_int"} {
			if v := q.Get(k); v != "" {
				_, _ = fmt.Fprintf(h, "qp:%s=%s;", k, v)
			}
		}
	}
	if len(bytes.TrimSpace(rawBody)) > 0 {
		_, _ = h.Write(bytes.TrimSpace(rawBody))
		_, _ = h.Write([]byte{0})
	}
	if req != nil {
		if b, err := json.Marshal(req); err == nil {
			_, _ = h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) appendUserAndRolesToCacheKeyLockedR65(h hash.Hash, label, username string) {
	u := strings.TrimSpace(username)
	if u == "" {
		return
	}
	_, _ = fmt.Fprintf(h, "%s=%s|", label, u)
	uObj, okU := s.securityUsers[u]
	if !okU || uObj == nil {
		return
	}
	if ub, err := json.Marshal(uObj); err == nil {
		_, _ = h.Write(ub)
		_, _ = h.Write([]byte{'|'})
	}
	var roleNames []string
	switch rv := uObj["roles"].(type) {
	case []string:
		roleNames = append(roleNames, rv...)
	case []any:
		for _, item := range rv {
			if rs, ok := item.(string); ok && strings.TrimSpace(rs) != "" {
				roleNames = append(roleNames, strings.TrimSpace(rs))
			}
		}
	}
	sort.Strings(roleNames)
	for _, rn := range roleNames {
		if rObj, okR := s.securityRoles[rn]; okR && rObj != nil {
			if rb, err := json.Marshal(rObj); err == nil {
				_, _ = fmt.Fprintf(h, "role:%s=", rn)
				_, _ = h.Write(rb)
				_, _ = h.Write([]byte{'|'})
			}
		}
	}
}

func (s *Server) appendAuthPrincipalToCacheKeyLockedR65(h hash.Hash, httpReq *http.Request) {
	if httpReq == nil {
		_, _ = h.Write([]byte("auth:nil;"))
		return
	}
	authHdr := strings.TrimSpace(httpReq.Header.Get("Authorization"))
	runAs := strings.TrimSpace(httpReq.Header.Get("es-security-runas-user"))
	if authHdr == "" && runAs == "" {
		_, _ = h.Write([]byte("auth:anon;"))
		return
	}
	credSum := sha256.Sum256([]byte(authHdr + "\x00" + runAs))
	_, _ = fmt.Fprintf(h, "auth:%x|", credSum[:])
	if authHdr != "" {
		parts := strings.SplitN(authHdr, " ", 2)
		if len(parts) == 2 {
			scheme := strings.ToLower(strings.TrimSpace(parts[0]))
			token := strings.TrimSpace(parts[1])
			switch scheme {
			case "basic":
				if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
					cred := string(decoded)
					if colon := strings.IndexByte(cred, ':'); colon >= 0 {
						s.appendUserAndRolesToCacheKeyLockedR65(h, "user", cred[:colon])
					}
				}
			case "apikey":
				if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
					cred := string(decoded)
					if colon := strings.IndexByte(cred, ':'); colon > 0 {
						keyID := cred[:colon]
						_, _ = fmt.Fprintf(h, "apikey=%s|", keyID)
						if kObj := s.securityAPIKeys[keyID]; kObj != nil {
							if kb, err := json.Marshal(kObj); err == nil {
								_, _ = h.Write(kb)
								_, _ = h.Write([]byte{'|'})
							}
							if owner, ok := kObj["username"].(string); ok {
								s.appendUserAndRolesToCacheKeyLockedR65(h, "keyuser", owner)
							}
						}
					}
				}
			}
		}
	}
	if runAs != "" {
		s.appendUserAndRolesToCacheKeyLockedR65(h, "runas", runAs)
	}
	_, _ = h.Write([]byte{';'})
}

func (s *Server) buildQueryCacheAuthScopeR66(httpReq *http.Request) string {
	if s == nil {
		return ""
	}
	h := sha256.New()
	s.mu.RLock()
	s.appendAuthPrincipalToCacheKeyLockedR65(h, httpReq)
	s.mu.RUnlock()
	return hex.EncodeToString(h.Sum(nil))
}

func (st *shardRequestCacheStoreR63) removeFromOrderLocked(key string) {
	for i, k := range st.order {
		if k == key {
			st.order = append(st.order[:i], st.order[i+1:]...)
			return
		}
	}
}

func (st *shardRequestCacheStoreR63) touchOrderLocked(key string) {
	n := len(st.order)
	if n == 0 || st.order[n-1] == key {
		return
	}
	st.removeFromOrderLocked(key)
	st.order = append(st.order, key)
}

func (s *Server) lookupShardRequestCacheR63(key string) (map[string]any, []string, bool) {
	st := s.getOrCreateShardRequestCacheR63()
	if st == nil || key == "" {
		return nil, nil, false
	}
	st.mu.Lock()
	entry, ok := st.entries[key]
	if ok && len(entry.payload) > 0 {
		st.touchOrderLocked(key)
	}
	st.mu.Unlock()
	if !ok || len(entry.payload) == 0 {
		return nil, nil, false
	}
	var cloned map[string]any
	dec := json.NewDecoder(bytes.NewReader(entry.payload))
	dec.UseNumber()
	if err := dec.Decode(&cloned); err != nil || cloned == nil {
		return nil, nil, false
	}
	return cloned, append([]string(nil), entry.unindexedField...), true
}

func (s *Server) recordShardRequestCacheHitR63(targets []string) {
	st := s.getOrCreateShardRequestCacheR63()
	if st == nil || len(targets) == 0 {
		return
	}
	st.mu.Lock()
	for _, t := range targets {
		if t != "" {
			st.hitsByIdx[t]++
		}
	}
	st.mu.Unlock()
}

func (s *Server) storeAndRecordShardRequestCacheMissR63(key string, targets []string, resp map[string]any, unindexed []string) {
	st := s.getOrCreateShardRequestCacheR63()
	if st == nil || key == "" || resp == nil {
		return
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, t := range targets {
		if t != "" {
			st.missesByIdx[t]++
		}
	}
	if prev, exists := st.entries[key]; exists {
		prevBytes := int64(len(prev.payload))
		st.totalBytes -= prevBytes
		if st.totalBytes < 0 {
			st.totalBytes = 0
		}
		for _, pt := range prev.targets {
			st.bytesByIdx[pt] -= prevBytes
			if st.bytesByIdx[pt] < 0 {
				st.bytesByIdx[pt] = 0
			}
		}
		delete(st.entries, key)
		st.removeFromOrderLocked(key)
	}

	entryBytes := int64(len(encoded))
	if (st.maxEntryBytes > 0 && entryBytes > st.maxEntryBytes) ||
		(st.maxBytes > 0 && entryBytes > st.maxBytes) {
		return
	}

	for len(st.order) > 0 &&
		((st.maxSize > 0 && len(st.order) >= st.maxSize) ||
			(st.maxBytes > 0 && st.totalBytes+entryBytes > st.maxBytes)) {
		evictKey := st.order[0]
		st.order = st.order[1:]
		if evicted, hadEv := st.entries[evictKey]; hadEv {
			evBytes := int64(len(evicted.payload))
			st.totalBytes -= evBytes
			if st.totalBytes < 0 {
				st.totalBytes = 0
			}
			for _, et := range evicted.targets {
				st.evictionsByIdx[et]++
				st.bytesByIdx[et] -= evBytes
				if st.bytesByIdx[et] < 0 {
					st.bytesByIdx[et] = 0
				}
			}
			delete(st.entries, evictKey)
		}
	}

	st.order = append(st.order, key)
	st.totalBytes += entryBytes
	cpTargets := append([]string(nil), targets...)
	for _, t := range cpTargets {
		if t != "" {
			st.bytesByIdx[t] += entryBytes
		}
	}
	st.entries[key] = shardRequestCacheEntryR63{
		payload:        encoded,
		unindexedField: append([]string(nil), unindexed...),
		targets:        cpTargets,
	}
}

func (s *Server) clearShardRequestCacheEntriesR63(targets []string) {
	st := s.getOrCreateShardRequestCacheR63()
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(targets) == 0 {
		for _, entry := range st.entries {
			for _, et := range entry.targets {
				st.evictionsByIdx[et]++
			}
		}
		clear(st.entries)
		st.order = st.order[:0]
		st.totalBytes = 0
		clear(st.bytesByIdx)
		return
	}
	targetSet := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t != "" {
			targetSet[t] = true
		}
	}
	keptOrder := st.order[:0]
	for _, k := range st.order {
		entry, ok := st.entries[k]
		if !ok {
			continue
		}
		matched := false
		for _, et := range entry.targets {
			if targetSet[et] {
				matched = true
				break
			}
		}
		if matched {
			entryBytes := int64(len(entry.payload))
			st.totalBytes -= entryBytes
			if st.totalBytes < 0 {
				st.totalBytes = 0
			}
			for _, et := range entry.targets {
				st.evictionsByIdx[et]++
				st.bytesByIdx[et] -= entryBytes
				if st.bytesByIdx[et] < 0 {
					st.bytesByIdx[et] = 0
				}
			}
			delete(st.entries, k)
		} else {
			keptOrder = append(keptOrder, k)
		}
	}
	st.order = keptOrder
	for t := range targetSet {
		st.bytesByIdx[t] = 0
	}
}

func (s *Server) purgeShardRequestCacheIndicesR63(targets []string) {
	if len(targets) == 0 {
		return
	}
	s.clearShardRequestCacheEntriesR63(targets)
	st := s.getOrCreateShardRequestCacheR63()
	if st == nil {
		return
	}
	st.mu.Lock()
	for _, t := range targets {
		delete(st.hitsByIdx, t)
		delete(st.missesByIdx, t)
		delete(st.evictionsByIdx, t)
		delete(st.bytesByIdx, t)
	}
	st.mu.Unlock()
}

func (s *Server) getShardRequestCacheStatsR63(indexName string) (hits, misses, evictions, memBytes int64) {
	if s == nil || indexName == "" {
		return 0, 0, 0, 0
	}
	serverShardReqCachesMuR63.Lock()
	st := serverShardReqCachesR63[s]
	serverShardReqCachesMuR63.Unlock()
	if st == nil {
		return 0, 0, 0, 0
	}
	st.mu.RLock()
	hits = st.hitsByIdx[indexName]
	misses = st.missesByIdx[indexName]
	evictions = st.evictionsByIdx[indexName]
	memBytes = st.bytesByIdx[indexName]
	st.mu.RUnlock()
	return hits, misses, evictions, memBytes
}
