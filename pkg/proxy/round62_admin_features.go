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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const (
	maxAsyncRegistryEntriesR62Admin  = 256
	maxFieldAccessesPerIndexR62Admin = 2048
	maxSearchGroupsPerIndexR62Admin  = 256
	maxDocMetaPerIndexR62Admin       = 50000
	maxUnrefreshedDocsTotalR62Admin  = 50000
	defaultMaxOpenScrollsR62Admin    = 500
	forceSynSourceMarkerKeyR62Admin  = "__force_synthetic_source_r62"
)

var (
	asyncSearchSeqR62Admin        atomic.Uint64
	esqlAsyncSeqR62Admin          atomic.Uint64
	eqlSearchSeqR62Admin          atomic.Uint64
	scrollSessionNonceSeqR62Admin atomic.Uint64
)

// ============================================================================
// F28: Global Registry Cleanup, Atomic Async IDs, Scroll Caps & State Bounds
// ============================================================================

// CleanupAdminAndCRUDRegistriesOnCloseR62Admin removes s from package-level
// Round-61 admin and CRUD registries when a Server is closed.
func CleanupAdminAndCRUDRegistriesOnCloseR62Admin(s *Server) {
	if s == nil {
		return
	}
	round61AdminRegistryMu.Lock()
	delete(round61AdminRegistry, s)
	round61AdminRegistryMu.Unlock()

	serverStateRegistryMuR61CRUD.Lock()
	delete(serverStateRegistryR61CRUD, s)
	serverStateRegistryMuR61CRUD.Unlock()
}

func nextAsyncSearchIDR62Admin() string {
	seq := asyncSearchSeqR62Admin.Add(1)
	return fmt.Sprintf("async-search-%d", seq)
}

func nextESQLAsyncQueryIDR62Admin() string {
	seq := esqlAsyncSeqR62Admin.Add(1)
	return fmt.Sprintf("esql-query-%d", seq)
}

func nextEQLSearchIDR62Admin() string {
	seq := eqlSearchSeqR62Admin.Add(1)
	return fmt.Sprintf("eql_%d", seq)
}

func evictBoundedAsyncRegistryLockedR62Admin(m map[string]map[string]any) {
	for len(m) >= maxAsyncRegistryEntriesR62Admin {
		var oldestKey string
		var oldestTime int64
		hasTime := false
		for k, v := range m {
			if v == nil {
				oldestKey = k
				break
			}
			if ts, ok := toInt64(v["start_time_in_millis"]); ok {
				if !hasTime || ts < oldestTime {
					oldestKey = k
					oldestTime = ts
					hasTime = true
				}
			} else if oldestKey == "" {
				oldestKey = k
			}
		}
		if oldestKey == "" {
			break
		}
		delete(m, oldestKey)
	}
}

func recordIndexRecoverySourceR62Admin(s *Server, indexName, source string) {
	if s == nil || indexName == "" || source == "" {
		return
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	if st.recoverySources == nil {
		st.recoverySources = make(map[string]string)
	}
	st.recoverySources[indexName] = source
	st.mu.Unlock()
}

func getIndexRecoverySourceR62Admin(s *Server, indexName string) string {
	if s == nil || indexName == "" {
		return "EMPTY_STORE"
	}
	round61AdminRegistryMu.RLock()
	st := round61AdminRegistry[s]
	round61AdminRegistryMu.RUnlock()
	if st != nil {
		st.mu.RLock()
		src := st.recoverySources[indexName]
		st.mu.RUnlock()
		if src != "" {
			return src
		}
	}
	s.mu.RLock()
	if cs := s.indexCustomSettings[indexName]; cs != nil {
		if srcStr, okS := cs["__recovery_source"].(string); okS && srcStr != "" {
			s.mu.RUnlock()
			return srcStr
		}
	}
	s.mu.RUnlock()
	return "EMPTY_STORE"
}

func attachScrollSessionNonceR62Admin(baseToken string, nonce uint64) string {
	if baseToken == "" || nonce == 0 {
		return baseToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(baseToken)
	if err != nil {
		return baseToken
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return baseToken
	}
	m["_sid"] = nonce
	encoded, err := json.Marshal(m)
	if err != nil {
		return baseToken
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func popPendingUniqueScrollTokenR62Admin(s *Server, rawToken string) (string, bool) {
	if s == nil || rawToken == "" {
		return "", false
	}
	serverStateRegistryMuR61CRUD.RLock()
	st := serverStateRegistryR61CRUD[s]
	serverStateRegistryMuR61CRUD.RUnlock()
	if st == nil {
		return "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.pendingScrollTokens) == 0 {
		return "", false
	}
	q := st.pendingScrollTokens[rawToken]
	if len(q) == 0 {
		return "", false
	}
	tok := q[0]
	if len(q) == 1 {
		delete(st.pendingScrollTokens, rawToken)
	} else {
		st.pendingScrollTokens[rawToken] = q[1:]
	}
	return tok, true
}

func purgeDeletedIndicesAdminStateR62Admin(s *Server, deleted []string) {
	if s == nil || len(deleted) == 0 {
		return
	}
	round61AdminRegistryMu.Lock()
	st := round61AdminRegistry[s]
	round61AdminRegistryMu.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	for _, idx := range deleted {
		delete(st.fieldAccesses, idx)
		delete(st.searchGroups, idx)
		delete(st.docTypeCounts, idx)
		delete(st.flushedOps, idx)
		delete(st.recoverySources, idx)
		delete(st.reqCacheHits, idx)
		delete(st.reqCacheMisses, idx)
	}
	st.mu.Unlock()
}

func boundInt64DocMapLockedR62Admin(m map[string]int64, keepKey string) {
	if len(m) <= maxDocMetaPerIndexR62Admin {
		return
	}
	for k := range m {
		if k != keepKey {
			delete(m, k)
			if len(m) <= maxDocMetaPerIndexR62Admin {
				break
			}
		}
	}
}

func boundBoolDocMapLockedR62Admin(m map[string]bool, keepKey string) {
	if len(m) <= maxDocMetaPerIndexR62Admin {
		return
	}
	for k := range m {
		if k != keepKey {
			delete(m, k)
			if len(m) <= maxDocMetaPerIndexR62Admin {
				break
			}
		}
	}
}

func boundStringDocMapLockedR62Admin(m map[string]string, keepKey string) {
	if len(m) <= maxDocMetaPerIndexR62Admin {
		return
	}
	for k := range m {
		if k != keepKey {
			delete(m, k)
			if len(m) <= maxDocMetaPerIndexR62Admin {
				break
			}
		}
	}
}

func countTotalUnrefreshedDocsLockedR62Admin(u map[string]map[int]map[string]unrefreshedDocState) int {
	total := 0
	for _, byShard := range u {
		for _, byDoc := range byShard {
			total += len(byDoc)
		}
	}
	return total
}

func lookupNestedClusterSettingR62Admin(m map[string]any, dottedKey string) (any, bool) {
	if len(m) == 0 {
		return nil, false
	}
	if v, ok := m[dottedKey]; ok && v != nil {
		return v, true
	}
	parts := strings.Split(dottedKey, ".")
	cur := m
	for i, p := range parts {
		val, exists := cur[p]
		if !exists || val == nil {
			return nil, false
		}
		if i == len(parts)-1 {
			return val, true
		}
		next, okM := val.(map[string]any)
		if !okM {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

func (s *Server) getMaxOpenScrollContextR62Admin() int {
	if s == nil {
		return defaultMaxOpenScrollsR62Admin
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, src := range []map[string]any{s.clusterTransientSettings, s.clusterPersistentSettings} {
		if raw, ok := lookupNestedClusterSettingR62Admin(src, "search.max_open_scroll_context"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil && n >= 0 {
				return n
			}
		}
	}
	return defaultMaxOpenScrollsR62Admin
}

func sweepExpiredScrollSessionsLockedR62Admin(st *serverStateR61CRUD, nowMs int64) int {
	if st == nil {
		return 0
	}
	seen := make(map[*scrollSessionStateR61CRUD]bool)
	var expired []*scrollSessionStateR61CRUD
	activeCount := 0
	if len(st.openScrollList) > 0 {
		kept := st.openScrollList[:0]
		for _, sess := range st.openScrollList {
			if sess == nil || sess.Cleared || seen[sess] {
				continue
			}
			seen[sess] = true
			if sess.ExpiresAtMs > 0 && nowMs > sess.ExpiresAtMs {
				expired = append(expired, sess)
			} else {
				kept = append(kept, sess)
				activeCount++
			}
		}
		st.openScrollList = kept
	}
	for tok, sess := range st.scrollSessions {
		if sess == nil || sess.Cleared {
			delete(st.scrollSessions, tok)
			continue
		}
		if seen[sess] {
			continue
		}
		seen[sess] = true
		if sess.ExpiresAtMs > 0 && nowMs > sess.ExpiresAtMs {
			expired = append(expired, sess)
		} else {
			activeCount++
		}
	}
	if len(expired) > 0 {
		expSet := make(map[*scrollSessionStateR61CRUD]bool, len(expired))
		for _, es := range expired {
			es.Cleared = true
			expSet[es] = true
			for _, t := range es.Tokens {
				if st.scrollSessions[t] == es {
					delete(st.scrollSessions, t)
				}
			}
		}
		for tok, sess := range st.scrollSessions {
			if expSet[sess] {
				delete(st.scrollSessions, tok)
			}
		}
	}
	return activeCount
}

func appendBoundedScrollTokenLockedR62Admin(st *serverStateR61CRUD, sess *scrollSessionStateR61CRUD, newToken string) {
	if st == nil || sess == nil || newToken == "" {
		return
	}
	for _, existing := range sess.Tokens {
		if existing == newToken {
			st.scrollSessions[newToken] = sess
			return
		}
	}
	sess.Tokens = append(sess.Tokens, newToken)
	st.scrollSessions[newToken] = sess
	// Retain initial token (Tokens[0]) + previous token + current token (at most 3 tokens per session).
	for len(sess.Tokens) > 3 {
		evictTok := sess.Tokens[1]
		sess.Tokens = append(sess.Tokens[:1], sess.Tokens[2:]...)
		if evictTok != sess.Tokens[0] && evictTok != newToken {
			delete(st.scrollSessions, evictTok)
		}
	}
}

func (s *Server) checkMaxOpenScrollContextR62Admin(r *http.Request, rawIndex string, req *esast.SearchRequest) (int, string, string) {
	if s == nil || r == nil || r.URL == nil {
		return 0, "", ""
	}
	rawScroll := strings.TrimSpace(r.URL.Query().Get("scroll"))
	if rawScroll == "" {
		return 0, "", ""
	}
	if isTruthyBoolQueryParam(r, "request_cache") {
		return 0, "", ""
	}
	if req != nil {
		if (req.From != nil && *req.From > 0) || (req.Size != nil && *req.Size == 0) || req.PIT != nil || req.Collapse != nil {
			return 0, "", ""
		}
	}
	// If concrete target index is missing and ignore_unavailable is false, let standard 404 take precedence.
	rawIndex = strings.TrimSpace(rawIndex)
	if rawIndex != "" && !strings.ContainsAny(rawIndex, "*?,") && rawIndex != "_all" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
		s.mu.RLock()
		_, isIdx := s.indices[rawIndex]
		_, isAlias := s.aliases[rawIndex]
		_, isDS := s.dataStreams[rawIndex]
		s.mu.RUnlock()
		if !isIdx && !isAlias && !isDS {
			return 0, "", ""
		}
	}
	maxScrolls := s.getMaxOpenScrollContextR62Admin()
	st := getOrCreateServerStateR61CRUD(s)
	nowMs := time.Now().UnixMilli()
	st.mu.Lock()
	active := sweepExpiredScrollSessionsLockedR62Admin(st, nowMs)
	st.mu.Unlock()
	if active >= maxScrolls {
		return http.StatusTooManyRequests, "too_many_requests",
			fmt.Sprintf("Trying to create too many scroll contexts. Must be less than or equal to: [%d]. This limit can be set by changing the [search.max_open_scroll_context] setting.", maxScrolls)
	}
	return 0, "", ""
}

// ============================================================================
// F20: `/_analyze` Wiring & `buildIndexAnalysisConfigR62Admin`
// ============================================================================

func (s *Server) analysisOptionsR62Admin() analysis.Options {
	return analysis.Options{
		ResolveSynonymSet: func(setID string) ([]string, error) {
			if s == nil {
				return nil, &analysis.AnalysisError{
					ErrType: "illegal_argument_exception",
					Reason:  fmt.Sprintf("synonyms set [%s] not found", setID),
					Status:  http.StatusBadRequest,
				}
			}
			s.mu.RLock()
			rules, exists := s.synonymSets[strings.TrimSpace(setID)]
			if !exists {
				s.mu.RUnlock()
				return nil, &analysis.AnalysisError{
					ErrType: "illegal_argument_exception",
					Reason:  fmt.Sprintf("synonyms set [%s] not found", setID),
					Status:  http.StatusBadRequest,
				}
			}
			out := make([]string, 0, len(rules))
			for _, rm := range rules {
				if syn, ok := rm["synonyms"].(string); ok && strings.TrimSpace(syn) != "" {
					out = append(out, syn)
				}
			}
			s.mu.RUnlock()
			return out, nil
		},
		EvalPredicateScript: analysis.DefaultEvalPredicateScript,
	}
}

// buildIndexAnalysisConfigR62Admin compiles the `IndexAnalysisConfig` and runtime `Options`
// for `idx` so `/_analyze`, query transpilation, and search callers share identical tokenization.
func (s *Server) buildIndexAnalysisConfigR62Admin(idx string) (*analysis.IndexAnalysisConfig, analysis.Options) {
	cfg, opts, err := s.parseStrictIndexAnalysisConfigR62Admin(idx)
	if err != nil || cfg == nil {
		return analysis.DefaultIndexAnalysisConfig(), opts
	}
	return cfg, opts
}

func (s *Server) parseStrictIndexAnalysisConfigR62Admin(idx string) (*analysis.IndexAnalysisConfig, analysis.Options, error) {
	opts := s.analysisOptionsR62Admin()
	if s == nil || strings.TrimSpace(idx) == "" {
		return analysis.DefaultIndexAnalysisConfig(), opts, nil
	}
	s.mu.RLock()
	resolved := strings.TrimSpace(idx)
	if commaIdx := strings.IndexByte(resolved, ','); commaIdx > 0 {
		resolved = strings.TrimSpace(resolved[:commaIdx])
	}
	if targets, ok := s.aliases[resolved]; ok && len(targets) > 0 {
		resolved = targets[0]
	}
	var cloned map[string]any
	if cs := s.indexCustomSettings[resolved]; len(cs) > 0 {
		cloned = deepCloneDocMap(cs)
	}
	s.mu.RUnlock()
	if len(cloned) == 0 {
		return analysis.DefaultIndexAnalysisConfig(), opts, nil
	}
	cfg, err := analysis.ParseIndexAnalysisConfig(cloned, opts)
	return cfg, opts, err
}

func lookupFieldPropertyInRawMappingR62Admin(m *esast.MappingSpec, fieldPath string) (esast.FieldProperty, bool) {
	if m == nil || len(m.Properties) == 0 || fieldPath == "" {
		return esast.FieldProperty{}, false
	}
	if prop, ok := m.Properties[fieldPath]; ok {
		return prop, true
	}
	parts := strings.Split(fieldPath, ".")
	props := m.Properties
	for i, part := range parts {
		p, exists := props[part]
		if !exists {
			return esast.FieldProperty{}, false
		}
		if i == len(parts)-1 {
			return p, true
		}
		if i == len(parts)-2 && len(p.Fields) > 0 {
			if sub, okSub := p.Fields[parts[len(parts)-1]]; okSub {
				return sub, true
			}
		}
		if len(p.Properties) == 0 {
			return esast.FieldProperty{}, false
		}
		props = p.Properties
	}
	return esast.FieldProperty{}, false
}

const maxAnalyzeAliasDepthR63Admin = 16

func (s *Server) resolveAnalyzeFieldTargetCheckedR63Admin(
	ctx context.Context,
	idxName, fieldPath string,
	cfg *analysis.IndexAnalysisConfig,
	visited map[string]bool,
	depth int,
) (analyzer string, normalizer string, err error) {
	idxSchema := s.getOrCompileReadOnlySchema(ctx, idxName)
	if idxSchema != nil && idxSchema.RawMapping != nil {
		if prop, ok := lookupFieldPropertyInRawMappingR62Admin(idxSchema.RawMapping, fieldPath); ok {
			pType := strings.ToLower(strings.TrimSpace(prop.Type))
			if pType == "alias" && strings.TrimSpace(prop.Path) != "" {
				nextField := strings.TrimSpace(prop.Path)
				if visited == nil {
					visited = make(map[string]bool, 4)
				}
				visited[fieldPath] = true
				if visited[nextField] || depth >= maxAnalyzeAliasDepthR63Admin {
					msg := fmt.Sprintf("Cycle detected in field alias [%s] referencing [%s] in index [%s]", fieldPath, nextField, idxName)
					return "", "", fmt.Errorf("%s", msg)
				}
				return s.resolveAnalyzeFieldTargetCheckedR63Admin(ctx, idxName, nextField, cfg, visited, depth+1)
			}
			if prop.SearchAnalyzer != "" {
				return prop.SearchAnalyzer, "", nil
			}
			if prop.Analyzer != "" {
				return prop.Analyzer, "", nil
			}
			if prop.Normalizer != "" {
				return "", prop.Normalizer, nil
			}
			switch pType {
			case "keyword", "constant_keyword", "wildcard":
				return "keyword", "", nil
			case "search_as_you_type":
				return "standard", "", nil
			}
		}
	}
	if idxSchema != nil {
		b := idxSchema.ResolveField(fieldPath)
		if b.Analyzer != "" {
			return b.Analyzer, "", nil
		}
		if b.LowercaseNormalizer {
			return "", "lowercase", nil
		}
		if (b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard") ||
			(b.DorisType == schema.DorisVarchar && b.ESType == "" && b.Analyzer == "") {
			return "keyword", "", nil
		}
	}
	if cfg != nil {
		if _, hasDefSearch := cfg.AnalyzerDefs["default_search"]; hasDefSearch {
			return "default_search", "", nil
		}
		if _, hasDef := cfg.AnalyzerDefs["default"]; hasDef {
			return "default", "", nil
		}
	}
	return "standard", "", nil
}

func (s *Server) resolveAnalyzeFieldTargetR62Admin(
	ctx context.Context,
	idxName, fieldPath string,
	cfg *analysis.IndexAnalysisConfig,
) (analyzer string, normalizer string) {
	an, norm, err := s.resolveAnalyzeFieldTargetCheckedR63Admin(ctx, idxName, fieldPath, cfg, nil, 0)
	if err != nil {
		return "standard", ""
	}
	return an, norm
}

func parseAnalyzeTextsR62Admin(rawText any) ([]string, error) {
	switch tv := rawText.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{tv}, nil
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			if item == nil {
				continue
			}
			switch sv := item.(type) {
			case string:
				out = append(out, sv)
			default:
				out = append(out, fmt.Sprintf("%v", sv))
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("[text] must be a string or an array of strings")
	}
}

func parseAnalyzeFilterStepsR62Admin(raw any) ([]any, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []any:
		return v, nil
	case string:
		return []any{v}, nil
	case map[string]any:
		return []any{v}, nil
	default:
		return nil, fmt.Errorf("filter specification must be an array or string")
	}
}

func (s *Server) serveAnalyzeR62Admin(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	rawIdx := strings.TrimSpace(r.PathValue("index"))
	resolvedIdx := ""
	if rawIdx != "" {
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.RLock()
		_, isConcrete := s.indices[rawIdx]
		aliasTargets := append([]string(nil), s.aliases[rawIdx]...)
		_, isDS := s.dataStreams[rawIdx]
		s.mu.RUnlock()

		if !isConcrete && !isDS && len(aliasTargets) > 1 {
			sort.Strings(aliasTargets)
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Alias [%s] has more than one index associated with it [%v], can't execute a single index op", rawIdx, aliasTargets))
			return
		}
		resolvedIdx = s.resolveIndexName(rawIdx)
		if !s.indexExistsRound59(r.Context(), resolvedIdx) {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIdx+"]")
			return
		}
		if s.isIndexClosed(resolvedIdx) {
			writeESError(w, http.StatusBadRequest, "index_closed_exception", "closed ["+resolvedIdx+"]")
			return
		}
	}

	var bodyMap map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	for k := range bodyMap {
		switch k {
		case "text", "analyzer", "normalizer", "field", "tokenizer", "filter", "token_filter", "char_filter", "char_filters", "explain", "attributes":
		default:
			writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("request does not support [%s]", k))
			return
		}
	}

	var rawText any
	hasText := false
	if v, exists := bodyMap["text"]; exists {
		rawText = v
		hasText = v != nil
	}
	if !hasText && r.URL != nil && r.URL.Query().Has("text") {
		qTexts := r.URL.Query()["text"]
		if len(qTexts) == 1 {
			rawText = qTexts[0]
		} else {
			arr := make([]any, len(qTexts))
			for i, qt := range qTexts {
				arr[i] = qt
			}
			rawText = arr
		}
		hasText = true
	}
	if !hasText {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: text is missing;")
		return
	}
	texts, tErr := parseAnalyzeTextsR62Admin(rawText)
	if tErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", tErr.Error())
		return
	}

	strParam := func(key string) string {
		if v, okB := bodyMap[key].(string); okB && v != "" {
			return v
		}
		if r.URL != nil {
			return r.URL.Query().Get(key)
		}
		return ""
	}
	analyzerName := strings.TrimSpace(strParam("analyzer"))
	normalizerName := strings.TrimSpace(strParam("normalizer"))
	fieldName := strings.TrimSpace(strParam("field"))

	var tokenizerSpec any
	if v, exists := bodyMap["tokenizer"]; exists && v != nil {
		tokenizerSpec = v
	} else if r.URL != nil && r.URL.Query().Get("tokenizer") != "" {
		tokenizerSpec = r.URL.Query().Get("tokenizer")
	}

	rawFilter := bodyMap["filter"]
	if rawFilter == nil {
		rawFilter = bodyMap["token_filter"]
	}
	if rawFilter == nil && r.URL != nil && len(r.URL.Query()["filter"]) > 0 {
		arr := make([]any, 0)
		for _, fv := range r.URL.Query()["filter"] {
			for _, p := range strings.Split(fv, ",") {
				if strings.TrimSpace(p) != "" {
					arr = append(arr, strings.TrimSpace(p))
				}
			}
		}
		if len(arr) > 0 {
			rawFilter = arr
		}
	}
	filterSteps, fErr := parseAnalyzeFilterStepsR62Admin(rawFilter)
	if fErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fErr.Error())
		return
	}

	rawCharFilter := bodyMap["char_filter"]
	if rawCharFilter == nil {
		rawCharFilter = bodyMap["char_filters"]
	}
	if rawCharFilter == nil && r.URL != nil && len(r.URL.Query()["char_filter"]) > 0 {
		arr := make([]any, 0)
		for _, cfv := range r.URL.Query()["char_filter"] {
			for _, p := range strings.Split(cfv, ",") {
				if strings.TrimSpace(p) != "" {
					arr = append(arr, strings.TrimSpace(p))
				}
			}
		}
		if len(arr) > 0 {
			rawCharFilter = arr
		}
	}
	charFilterSteps, cfErr := parseAnalyzeFilterStepsR62Admin(rawCharFilter)
	if cfErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", cfErr.Error())
		return
	}

	explain := isTruthyBoolQueryParam(r, "explain")
	if bExp, okE := bodyMap["explain"].(bool); okE {
		explain = bExp
	} else if sExp, okS := bodyMap["explain"].(string); okS {
		explain = strings.EqualFold(strings.TrimSpace(sExp), "true")
	}

	var attrs []string
	if rawAttr, exists := bodyMap["attributes"]; exists && rawAttr != nil {
		switch av := rawAttr.(type) {
		case []any:
			for _, el := range av {
				attrs = append(attrs, fmt.Sprintf("%v", el))
			}
		case string:
			for _, el := range strings.Split(av, ",") {
				if strings.TrimSpace(el) != "" {
					attrs = append(attrs, strings.TrimSpace(el))
				}
			}
		}
	}
	if r.URL != nil && len(r.URL.Query()["attributes"]) > 0 {
		for _, qav := range r.URL.Query()["attributes"] {
			for _, el := range strings.Split(qav, ",") {
				if strings.TrimSpace(el) != "" {
					attrs = append(attrs, strings.TrimSpace(el))
				}
			}
		}
	}

	cfg, opts, cfgErr := s.parseStrictIndexAnalysisConfigR62Admin(resolvedIdx)
	if cfgErr != nil {
		if aErr, isAE := analysis.AsAnalysisError(cfgErr); isAE {
			writeESError(w, aErr.Status, aErr.ErrType, aErr.Reason)
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", cfgErr.Error())
		return
	}

	if fieldName != "" {
		if resolvedIdx == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: must specify an index to analyze on a field;")
			return
		}
		if analyzerName != "" || normalizerName != "" || tokenizerSpec != nil || len(filterSteps) > 0 || len(charFilterSteps) > 0 {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: analyzer/normalizer/tokenizer/filters cannot be specified together with field;")
			return
		}
		var fieldErr error
		analyzerName, normalizerName, fieldErr = s.resolveAnalyzeFieldTargetCheckedR63Admin(r.Context(), resolvedIdx, fieldName, cfg, nil, 0)
		if fieldErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fieldErr.Error())
			return
		}
	}

	// Preserve legacy cluster-wide `normalizer: "custom_normalizer"` fallback (`round38_test.go:649`).
	if resolvedIdx == "" && normalizerName == "custom_normalizer" && (cfg == nil || cfg.NormalizerDefs["custom_normalizer"] == nil) {
		normalizerName = "lowercase"
	}

	res, err := analysis.Analyze(analysis.AnalyzeRequest{
		Text:       texts,
		Analyzer:   analyzerName,
		Normalizer: normalizerName,
		Tokenizer:  tokenizerSpec,
		CharFilter: charFilterSteps,
		Filter:     filterSteps,
		Explain:    explain,
		Attributes: attrs,
		Config:     cfg,
		Options:    opts,
	})
	if err != nil {
		if aErr, isAE := analysis.AsAnalysisError(err); isAE {
			writeESError(w, aErr.Status, aErr.ErrType, aErr.Reason)
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
		return
	}
	if !s.isES8Mode(r) {
		usedHTMLStrip := false
		checkSteps := func(steps []any) {
			for _, st := range steps {
				switch v := st.(type) {
				case string:
					if v == "htmlStrip" {
						usedHTMLStrip = true
					}
				case map[string]any:
					if tp, _ := v["type"].(string); tp == "htmlStrip" {
						usedHTMLStrip = true
					}
				}
			}
		}
		checkSteps(charFilterSteps)
		if !usedHTMLStrip && cfg != nil && analyzerName != "" {
			if aDef, okA := cfg.AnalyzerDefs[analyzerName]; okA && aDef != nil {
				switch cfRaw := aDef["char_filter"].(type) {
				case []any:
					checkSteps(cfRaw)
				case string:
					if cfRaw == "htmlStrip" {
						usedHTMLStrip = true
					}
				}
			}
		}
		if usedHTMLStrip {
			emitESDeprecationWarningRound61(w, s, r,
				"The [htmpStrip] char filter name is deprecated and will be removed in a future version. Please change the filter name to [html_strip] instead.")
		}
	}
	writeJSONWithRequest(w, r, http.StatusOK, res)
}

// ============================================================================
// F2: `_cat/*` Right-Alignment, `cat.fielddata` & ES 8 `cat.shards` Columns
// ============================================================================

var rightAlignedCatColumnsR62Admin = map[string]bool{
	"disk.percent":           true,
	"disk.indices":           true,
	"disk.indices.forecast":  true,
	"disk.used":              true,
	"disk.avail":             true,
	"disk.total":             true,
	"heap.current":           true,
	"heap.percent":           true,
	"heap.max":               true,
	"ram.current":            true,
	"ram.percent":            true,
	"ram.max":                true,
	"file_desc.current":      true,
	"file_desc.percent":      true,
	"file_desc.max":          true,
	"cpu":                    true,
	"load_1m":                true,
	"load_5m":                true,
	"load_15m":               true,
	"shards":                 true,
	"shards.undesired":       true,
	"write_load.forecast":    true,
	"pri":                    true,
	"rep":                    true,
	"docs.count":             true,
	"docs.deleted":           true,
	"store.size":             true,
	"pri.store.size":         true,
	"dataset.size":           true,
	"pri.dataset.size":       true,
	"docs":                   true,
	"store":                  true,
	"dataset":                true,
	"size":                   true,
	"size.memory":            true,
	"version":                true,
	"active":                 true,
	"queue":                  true,
	"rejected":               true,
	"completed":              true,
	"largest":                true,
	"pool_size":              true,
	"core":                   true,
	"max":                    true,
	"total":                  true,
	"order":                  true,
	"indices":                true,
	"unassign":               true,
	"init":                   true,
	"relo":                   true,
	"active_shards_percent":  true,
	"max_task_wait_time":     true,
	"pending_tasks":          true,
	"time":                   true,
	"files":                  true,
	"files_recovered":        true,
	"files_percent":          true,
	"files_total":            true,
	"bytes":                  true,
	"bytes_recovered":        true,
	"bytes_percent":          true,
	"bytes_total":            true,
	"translog_ops":           true,
	"translog_ops_recovered": true,
	"translog_ops_percent":   true,
}

func isRightAlignedCatColumnR62Admin(col string) bool {
	return rightAlignedCatColumnsR62Admin[strings.ToLower(strings.TrimSpace(col))]
}

func collectFielddataEnabledPathsR62Admin(prefix string, props map[string]esast.FieldProperty, dst map[string]bool) {
	for name, prop := range props {
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		if isFielddataEnabledRound61(prop.Fielddata) {
			dst[full] = true
		}
		if len(prop.Fields) > 0 {
			collectFielddataEnabledPathsR62Admin(full, prop.Fields, dst)
		}
		if len(prop.Properties) > 0 {
			collectFielddataEnabledPathsR62Admin(full, prop.Properties, dst)
		}
	}
}

func (s *Server) collectCatFielddataRowsR62Admin(r *http.Request) []map[string]any {
	nodeFilter := ""
	var rawFields []string
	if r != nil {
		if f := strings.TrimSpace(r.PathValue("fields")); f != "" {
			rawFields = append(rawFields, strings.Split(f, ",")...)
		}
		if r.URL != nil {
			for _, qf := range r.URL.Query()["fields"] {
				rawFields = append(rawFields, strings.Split(qf, ",")...)
			}
			nodeFilter = strings.TrimSpace(r.URL.Query().Get("nodes"))
		}
	}
	if nodeFilter != "" && nodeFilter != "_all" && nodeFilter != "*" && nodeFilter != "_local" && nodeFilter != "_master" &&
		!matchMultiWildcardWithExclusions(nodeFilter, taskLocalNodeID) && !matchMultiWildcardWithExclusions(nodeFilter, "doris-es-proxy-node-1") {
		return nil
	}

	fdEnabledByIndex := make(map[string]map[string]bool)
	s.mu.RLock()
	for idxName, sch := range s.indices {
		if sch == nil || s.closedIndices[idxName] || sch.RawMapping == nil || len(sch.RawMapping.Properties) == 0 {
			continue
		}
		enabled := make(map[string]bool)
		collectFielddataEnabledPathsR62Admin("", sch.RawMapping.Properties, enabled)
		if len(enabled) > 0 {
			fdEnabledByIndex[idxName] = enabled
		}
	}
	s.mu.RUnlock()

	fieldBytes := make(map[string]int64)
	round61AdminRegistryMu.Lock()
	st := round61AdminRegistry[s]
	round61AdminRegistryMu.Unlock()
	if st != nil && len(fdEnabledByIndex) > 0 {
		st.mu.RLock()
		for idxName, byField := range st.fieldAccesses {
			enabled := fdEnabledByIndex[idxName]
			if len(enabled) == 0 {
				continue
			}
			for fn, fa := range byField {
				if fa == nil || strings.HasPrefix(fn, "_") || !enabled[fn] {
					continue
				}
				cnt := fa.anyCount
				if cnt <= 0 {
					cnt = 1
				}
				fieldBytes[fn] += cnt * 64
			}
		}
		st.mu.RUnlock()
	}

	fieldPat := strings.Join(rawFields, ",")
	names := make([]string, 0, len(fieldBytes))
	for fn := range fieldBytes {
		if fieldPat == "" || fieldPat == "*" || matchMultiWildcardWithExclusions(fieldPat, fn) {
			names = append(names, fn)
		}
	}
	sort.Strings(names)

	bytesUnit := ""
	if r != nil && r.URL != nil {
		bytesUnit = strings.TrimSpace(r.URL.Query().Get("bytes"))
	}
	rows := make([]map[string]any, 0, len(names))
	for _, fn := range names {
		sz := formatCatBytesValueRound61(fieldBytes[fn], bytesUnit, 1)
		rows = append(rows, map[string]any{
			"id":    taskLocalNodeID,
			"host":  "127.0.0.1",
			"ip":    "127.0.0.1",
			"node":  "doris-es-proxy-node-1",
			"field": fn,
			"size":  sz,
		})
	}
	return rows
}

func catShardsHelpColsR62Admin(isES8 bool) []string {
	cols := []string{"index", "shard", "prirep", "state", "docs", "store"}
	if isES8 {
		cols = append(cols, "dataset")
	}
	cols = append(cols,
		"ip", "id", "node", "sync_id",
		"unassigned.reason", "unassigned.at", "unassigned.for", "unassigned.details",
		"recoverysource.type", "completion.size", "fielddata.memory_size", "fielddata.evictions",
		"query_cache.memory_size", "query_cache.evictions", "flush.total", "flush.total_time",
		"get.current", "get.time", "get.total", "get.exists_time", "get.exists_total", "get.missing_time", "get.missing_total",
		"indexing.delete_current", "indexing.delete_time", "indexing.delete_total", "indexing.index_current", "indexing.index_time", "indexing.index_total", "indexing.index_failed",
		"merges.current", "merges.current_docs", "merges.current_size", "merges.total", "merges.total_docs", "merges.total_size", "merges.total_time",
		"refresh.total", "refresh.time", "refresh.external_total", "refresh.external_time", "refresh.listeners",
		"search.fetch_current", "search.fetch_time", "search.fetch_total", "search.open_contexts", "search.query_current", "search.query_time", "search.query_total",
		"search.scroll_current", "search.scroll_time", "search.scroll_total",
		"segments.count", "segments.memory", "segments.index_writer_memory", "segments.version_map_memory", "segments.fixed_bitset_memory",
		"seq_no.max", "seq_no.local_checkpoint", "seq_no.global_checkpoint",
		"warmer.current", "warmer.total", "warmer.total_time", "path.data", "path.state",
	)
	if isES8 {
		cols = append(cols,
			"bulk.total_operations", "bulk.total_time", "bulk.total_size_in_bytes", "bulk.avg_time", "bulk.avg_size_in_bytes",
			"dense_vector.value_count", "sparse_vector.value_count",
		)
	}
	return cols
}

// ============================================================================
// F3: `_cluster/*` & `_snapshot/*` Helpers
// ============================================================================

func nodeRolesListR62Admin(isES8 bool) []string {
	if isES8 {
		return []string{
			"data", "data_cold", "data_content", "data_frozen", "data_hot", "data_warm",
			"ingest", "master", "ml", "remote_cluster_client", "transform",
		}
	}
	return []string{
		"data", "data_cold", "data_content", "data_hot", "data_warm",
		"ingest", "master", "ml", "remote_cluster_client", "transform",
	}
}

func (s *Server) serveClusterAllocationExplainR62Admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())

	var reqMap map[string]any
	hasBodyFields := false
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		hasBodyFields = len(reqMap) > 0
	}

	idxName := ""
	shardNum := 0
	primary := true

	if hasBodyFields {
		idxName, _ = reqMap["index"].(string)
		idxName = strings.TrimSpace(idxName)
		if idxName == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[index] must be provided when explaining a specific shard")
			return
		}
		if sv, okS := toInt64(reqMap["shard"]); okS {
			shardNum = int(sv)
		}
		if pv, okP := reqMap["primary"].(bool); okP {
			primary = pv
		}
		resolved := s.resolveIndexName(idxName)
		s.mu.RLock()
		_, exists := s.indices[resolved]
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+idxName+"]")
			return
		}
		idxName = resolved
		numShards, numReplicas, _ := s.getIndexShardAndReplicaCounts(idxName)
		if shardNum < 0 || shardNum >= numShards || (!primary && numReplicas <= 0) {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("unable to find shard [%s][%d], primary=[%v]", idxName, shardNum, primary))
			return
		}
	} else {
		// Body-less request: find the first unassigned replica shard across open indices on our 1-node cluster.
		s.mu.RLock()
		names := make([]string, 0, len(s.indices))
		for k := range s.indices {
			if !s.closedIndices[k] {
				names = append(names, k)
			}
		}
		s.mu.RUnlock()
		sort.Strings(names)
		foundUnassigned := false
		for _, candidate := range names {
			_, numReplicas, _ := s.getIndexShardAndReplicaCounts(candidate)
			if numReplicas > 0 {
				idxName = candidate
				shardNum = 0
				primary = false
				foundUnassigned = true
				break
			}
		}
		if !foundUnassigned {
			if !s.hasExplicitTargetESVersion() && len(names) > 0 {
				idxName = names[0]
				shardNum = 0
				primary = true
			} else {
				includeYes := isTruthyBoolQueryParam(r, "include_yes_decisions")
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unable to find any unassigned shards to explain [ClusterAllocationExplainRequest[useAnyUnassignedShard=true,includeYesDecisions=%v]]", includeYes))
				return
			}
		}
	}

	isES8 := s.isES8Mode(r)
	roles := nodeRolesListR62Admin(isES8)
	nodeAttrs := map[string]any{"testattr": "test"}

	var resp map[string]any
	if primary {
		resp = map[string]any{
			"index":         idxName,
			"shard":         shardNum,
			"primary":       true,
			"current_state": "started",
			"current_node": map[string]any{
				"id":                taskLocalNodeID,
				"name":              "doris-es-proxy-node-1",
				"transport_address": "127.0.0.1:9300",
				"attributes":        nodeAttrs,
				"roles":             roles,
				"weight_ranking":    1,
			},
			"can_remain_on_current_node":  "yes",
			"can_rebalance_cluster":       "no",
			"can_rebalance_to_other_node": "no",
			"rebalance_explanation":       "cannot rebalance as no target node exists that can both allocate this shard and improve the cluster balance",
			"node_allocation_decisions": []any{
				map[string]any{
					"node_id":           taskLocalNodeID,
					"node_name":         "doris-es-proxy-node-1",
					"transport_address": "127.0.0.1:9300",
					"node_attributes":   nodeAttrs,
					"node_decision":     "no",
					"weight_ranking":    1,
					"deciders": []any{
						map[string]any{
							"decider":     "same_shard",
							"decision":    "NO",
							"explanation": "the shard cannot be allocated to the same node on which a copy of the shard already exists [[" + idxName + "][" + strconv.Itoa(shardNum) + "], node[" + taskLocalNodeID + "], [P], s[STARTED]]",
						},
					},
				},
			},
		}
	} else {
		createdAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		s.mu.RLock()
		if cs := s.indexCustomSettings[idxName]; cs != nil {
			if cd, okC := cs["creation_date"]; okC {
				if ms, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", cd)), 10, 64); err == nil && ms > 0 {
					createdAt = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
				}
			}
		}
		s.mu.RUnlock()
		resp = map[string]any{
			"index":         idxName,
			"shard":         shardNum,
			"primary":       false,
			"current_state": "unassigned",
			"unassigned_info": map[string]any{
				"reason":                 "INDEX_CREATED",
				"at":                     createdAt,
				"last_allocation_status": "no_attempt",
			},
			"can_allocate":         "no",
			"allocate_explanation": "cannot allocate because allocation is not permitted to any of the nodes",
			"node_allocation_decisions": []any{
				map[string]any{
					"node_id":           taskLocalNodeID,
					"node_name":         "doris-es-proxy-node-1",
					"transport_address": "127.0.0.1:9300",
					"node_attributes":   nodeAttrs,
					"node_decision":     "no",
					"weight_ranking":    1,
					"deciders": []any{
						map[string]any{
							"decider":     "same_shard",
							"decision":    "NO",
							"explanation": "the shard cannot be allocated to the same node on which a copy of the shard already exists [[" + idxName + "][" + strconv.Itoa(shardNum) + "], node[" + taskLocalNodeID + "], [P], s[STARTED]]",
						},
					},
				},
			},
		}
	}

	if isTruthyBoolQueryParam(r, "include_disk_info") {
		resp["cluster_info"] = map[string]any{
			"nodes": map[string]any{
				taskLocalNodeID: map[string]any{
					"node_name": "doris-es-proxy-node-1",
					"least_available": map[string]any{
						"path":              "/var/lib/doris-es-proxy",
						"total_bytes":       107374182400,
						"used_bytes":        10737418240,
						"free_bytes":        96636764160,
						"free_disk_percent": 90.0,
						"used_disk_percent": 10.0,
					},
					"most_available": map[string]any{
						"path":              "/var/lib/doris-es-proxy",
						"total_bytes":       107374182400,
						"used_bytes":        10737418240,
						"free_bytes":        96636764160,
						"free_disk_percent": 90.0,
						"used_disk_percent": 10.0,
					},
				},
			},
			"shard_sizes":    map[string]any{},
			"shard_paths":    map[string]any{},
			"reserved_sizes": []any{},
		}
	}

	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) serveClusterRerouteR62Admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())

	var body struct {
		Commands []map[string]any `json:"commands"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}

	explain := isTruthyBoolQueryParam(r, "explain")
	explanations := make([]any, 0, len(body.Commands))
	for _, cmd := range body.Commands {
		if len(cmd) != 1 {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "reroute command must specify a single action")
			return
		}
		for cmdName, rawParams := range cmd {
			pMap, _ := rawParams.(map[string]any)
			if pMap == nil {
				pMap = map[string]any{}
			}
			switch cmdName {
			case "cancel", "move", "allocate_replica", "allocate_stale_primary", "allocate_empty_primary":
			default:
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("unknown reroute command [%s]", cmdName))
				return
			}
			idxStr, _ := pMap["index"].(string)
			shardVal := 0
			if sv, okS := toInt64(pMap["shard"]); okS {
				shardVal = int(sv)
			}
			nodeStr, _ := pMap["node"].(string)
			paramsOut := make(map[string]any, len(pMap)+1)
			for pk, pv := range pMap {
				paramsOut[pk] = pv
			}
			paramsOut["shard"] = shardVal
			if cmdName == "cancel" {
				if _, hasAP := paramsOut["allow_primary"]; !hasAP {
					paramsOut["allow_primary"] = false
				}
			}
			deciderName := cmdName + "_allocation_command"
			decision := "NO"
			explanation := fmt.Sprintf("reroute command [%s] is not applicable on shard [%s][%d] on node [%s]", cmdName, idxStr, shardVal, nodeStr)
			if !explain {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("[%s] allocation of [%s][%d] on node [%s] is not allowed", cmdName, idxStr, shardVal, nodeStr))
				return
			}
			explanations = append(explanations, map[string]any{
				"command":    cmdName,
				"parameters": paramsOut,
				"decisions": []any{
					map[string]any{
						"decider":     deciderName,
						"decision":    decision,
						"explanation": explanation,
					},
				},
			})
		}
	}

	metricParam := strings.TrimSpace(r.URL.Query().Get("metric"))
	if metricParam != "" && metricParam != "none" && metricParam != "_all" {
		validRerouteMetrics := map[string]bool{
			"_all": true, "none": true, "version": true, "master_node": true,
			"nodes": true, "routing_table": true, "metadata": true, "blocks": true,
		}
		for _, p := range strings.Split(metricParam, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !validRerouteMetrics[p] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					formatUnrecognizedMetricErrorRound61("/_cluster/reroute", p, validRerouteMetrics).Error())
				return
			}
		}
	}
	if s.isES8Mode(r) && metricParam != "none" {
		emitESDeprecationWarningRound61(w, s, r,
			"The [state] field in the response to the reroute API is deprecated and will be removed in a future version. Specify ?metric=none to adopt the future behaviour.")
	}

	resp := map[string]any{
		"acknowledged": true,
	}
	if explain {
		resp["explanations"] = explanations
	}
	if metricParam != "none" {
		wantAll := metricParam == "" || metricParam == "_all"
		metricSet := make(map[string]bool)
		for _, p := range strings.Split(metricParam, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				metricSet[p] = true
			}
		}
		stateMap := map[string]any{
			"cluster_name": "doris-es-proxy",
			"cluster_uuid": "doris-es-proxy-uuid",
		}
		if wantAll || metricSet["version"] {
			stateMap["version"] = 1
		}
		if wantAll || metricSet["master_node"] {
			stateMap["master_node"] = taskLocalNodeID
		}
		if wantAll || metricSet["nodes"] {
			stateMap["nodes"] = map[string]any{
				taskLocalNodeID: map[string]any{
					"name":              "doris-es-proxy-node-1",
					"ephemeral_id":      taskLocalNodeID + "-ephemeral",
					"transport_address": "127.0.0.1:9300",
					"attributes":        map[string]any{"testattr": "test"},
					"roles":             nodeRolesListR62Admin(s.isES8Mode(r)),
				},
			}
		}
		if metricParam == "_all" || metricSet["metadata"] {
			s.mu.RLock()
			metaIndices := make(map[string]any, len(s.indices))
			for idxName := range s.indices {
				stStr := "open"
				if s.closedIndices[idxName] {
					stStr = "close"
				}
				shortFlat := s.buildIndexSettingsMapLocked(idxName)
				metaIndices[idxName] = map[string]any{
					"state":    stStr,
					"settings": formatIndexSettingsOutput(shortFlat, false),
					"aliases":  []string{},
				}
			}
			s.mu.RUnlock()
			stateMap["metadata"] = map[string]any{
				"cluster_uuid": "doris-es-proxy-uuid",
				"templates":    map[string]any{},
				"indices":      metaIndices,
			}
		}
		if wantAll || metricSet["routing_table"] {
			stateMap["routing_table"] = map[string]any{"indices": map[string]any{}}
		}
		if wantAll || metricSet["blocks"] {
			stateMap["blocks"] = map[string]any{}
		}
		resp["state"] = stateMap
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) buildClusterStateBlocksR62Admin(targetIndices []string) map[string]any {
	if s == nil || len(targetIndices) == 0 {
		return map[string]any{}
	}
	indicesBlocks := make(map[string]any)
	s.mu.RLock()
	for _, idxName := range targetIndices {
		idxBlk := make(map[string]any)
		if s.isIndexSettingTrueLocked(idxName, "blocks.read_only") {
			idxBlk["5"] = map[string]any{
				"description": "index read-only (api)",
				"retryable":   false,
				"levels":      []string{"write", "metadata_write"},
			}
		}
		if s.isIndexSettingTrueLocked(idxName, "blocks.read") {
			idxBlk["7"] = map[string]any{
				"description": "index read (api)",
				"retryable":   false,
				"levels":      []string{"read"},
			}
		}
		if s.isIndexSettingTrueLocked(idxName, "blocks.write") {
			idxBlk["8"] = map[string]any{
				"description": "index write (api)",
				"retryable":   false,
				"levels":      []string{"write"},
			}
		}
		if s.isIndexSettingTrueLocked(idxName, "blocks.metadata") {
			idxBlk["9"] = map[string]any{
				"description": "index metadata (api)",
				"retryable":   false,
				"levels":      []string{"metadata_read", "metadata_write"},
			}
		}
		if s.isIndexSettingTrueLocked(idxName, "blocks.read_only_allow_delete") {
			idxBlk["12"] = map[string]any{
				"description": "index read-only / allow delete (api)",
				"retryable":   false,
				"levels":      []string{"write"},
			}
		}
		if len(idxBlk) > 0 {
			indicesBlocks[idxName] = idxBlk
		}
	}
	s.mu.RUnlock()
	if len(indicesBlocks) == 0 {
		return map[string]any{}
	}
	return map[string]any{"indices": indicesBlocks}
}

func computeRepoUUIDR62Admin(repoName string, repoObj map[string]any) string {
	seed := repoName
	if repoObj != nil {
		if stMap, ok := repoObj["settings"].(map[string]any); ok {
			if loc, okL := stMap["location"].(string); okL && strings.TrimSpace(loc) != "" {
				seed = "loc:" + strings.TrimSpace(loc)
			}
		}
	}
	sum := sha256.Sum256([]byte("doris-es-proxy-repo-uuid:" + seed))
	return hex.EncodeToString(sum[:11])
}

func collectFieldAnalyzerRefsFromRawPropsR62Admin(props map[string]esast.FieldProperty, out *[]string) {
	for _, prop := range props {
		if prop.Analyzer != "" {
			*out = append(*out, prop.Analyzer)
		}
		if prop.SearchAnalyzer != "" {
			*out = append(*out, prop.SearchAnalyzer)
		}
		if prop.SearchQuoteAnalyzer != "" {
			*out = append(*out, prop.SearchQuoteAnalyzer)
		}
		if len(prop.Properties) > 0 {
			collectFieldAnalyzerRefsFromRawPropsR62Admin(prop.Properties, out)
		}
		if len(prop.Fields) > 0 {
			collectFieldAnalyzerRefsFromRawPropsR62Admin(prop.Fields, out)
		}
	}
}

type fieldTypeAggR62Admin struct {
	count              int
	indexSet           map[string]bool
	indexedCount       int
	indexedVectorCount int
	indexedDimsMin     int
	indexedDimsMax     int
	hasDocValuesCnt    int
	dimsSum            int
	dimsMax            int
	indexTypes         map[string]int
	similarities       map[string]int
}

func collectVectorPathsByTypeR63Admin(
	props map[string]esast.FieldProperty,
	prefix string,
	densePaths map[string]bool,
	sparsePaths map[string]bool,
) {
	for pName, prop := range props {
		full := pName
		if prefix != "" {
			full = prefix + "." + pName
		}
		pType := strings.ToLower(strings.TrimSpace(prop.Type))
		switch pType {
		case "dense_vector":
			densePaths[full] = true
		case "sparse_vector":
			sparsePaths[full] = true
		}
		if len(prop.Properties) > 0 {
			collectVectorPathsByTypeR63Admin(prop.Properties, full, densePaths, sparsePaths)
		}
	}
}

func countDocVectorFieldPresenceR63Admin(doc map[string]any, path string, wantMap bool) int {
	if len(doc) == 0 || path == "" {
		return 0
	}
	parts := strings.Split(path, ".")
	var walk func(cur any, idx int) int
	walk = func(cur any, idx int) int {
		if cur == nil {
			return 0
		}
		if idx == len(parts) {
			if wantMap {
				if m, ok := cur.(map[string]any); ok && len(m) > 0 {
					return 1
				}
				return 0
			}
			switch arr := cur.(type) {
			case []any:
				if len(arr) == 0 {
					return 0
				}
				if _, isNestedArr := arr[0].([]any); isNestedArr {
					cnt := 0
					for _, sub := range arr {
						cnt += walk(sub, idx)
					}
					return cnt
				}
				return 1
			case []float64:
				if len(arr) > 0 {
					return 1
				}
			}
			return 0
		}
		switch typed := cur.(type) {
		case map[string]any:
			return walk(typed[parts[idx]], idx+1)
		case []any:
			cnt := 0
			for _, elem := range typed {
				cnt += walk(elem, idx)
			}
			return cnt
		}
		return 0
	}
	return walk(doc, 0)
}

func walkRawPropsForClusterFieldTypesR62Admin(
	idxName string,
	props map[string]esast.FieldProperty,
	agg map[string]*fieldTypeAggR62Admin,
	dedupFields map[string]bool,
	prefix string,
) {
	for pName, prop := range props {
		full := pName
		if prefix != "" {
			full = prefix + "." + pName
		}
		pType := strings.ToLower(strings.TrimSpace(prop.Type))
		if pType == "" && len(prop.Properties) > 0 {
			pType = "object"
		}
		if pType != "" {
			dedupFields[full+":"+pType] = true
			ent := agg[pType]
			if ent == nil {
				ent = &fieldTypeAggR62Admin{
					indexSet:       make(map[string]bool),
					indexedDimsMin: -1,
					indexedDimsMax: -1,
					indexTypes:     make(map[string]int),
					similarities:   make(map[string]int),
				}
				agg[pType] = ent
			}
			ent.count++
			ent.indexSet[idxName] = true
			isIndexed := prop.Index == nil || *prop.Index
			if pType == "dense_vector" {
				if prop.Index != nil && !*prop.Index {
					isIndexed = false
				} else {
					isIndexed = true
				}
			}
			if isIndexed && pType != "object" && pType != "nested" && pType != "binary" {
				ent.indexedCount++
			}
			hasDV := prop.DocValues == nil || *prop.DocValues
			if pType != "text" && pType != "match_only_text" && pType != "object" && pType != "nested" && pType != "binary" && hasDV {
				ent.hasDocValuesCnt++
			}
			if pType == "dense_vector" {
				dims := prop.EffectiveDims()
				if dims <= 0 {
					dims = 1
				}
				ent.dimsSum += dims
				if dims > ent.dimsMax {
					ent.dimsMax = dims
				}
				if isIndexed {
					ent.indexedVectorCount++
					explicitDims := prop.EffectiveDims()
					if explicitDims > 0 {
						if ent.indexedDimsMin == -1 || explicitDims < ent.indexedDimsMin {
							ent.indexedDimsMin = explicitDims
						}
						if ent.indexedDimsMax == -1 || explicitDims > ent.indexedDimsMax {
							ent.indexedDimsMax = explicitDims
						}
					}
					it := "hnsw"
					if ioMap, okIO := prop.IndexOptions.(map[string]any); okIO {
						if tStr, okT := ioMap["type"].(string); okT && tStr != "" {
							it = strings.ToLower(tStr)
						}
					}
					ent.indexTypes[it]++
					sim := "cosine"
					if prop.Similarity != "" {
						sim = strings.ToLower(prop.Similarity)
					}
					ent.similarities[sim]++
				}
			}
		}
		if len(prop.Properties) > 0 {
			walkRawPropsForClusterFieldTypesR62Admin(idxName, prop.Properties, agg, dedupFields, full)
		}
		if len(prop.Fields) > 0 {
			walkRawPropsForClusterFieldTypesR62Admin(idxName, prop.Fields, agg, dedupFields, full)
		}
	}
}

func (s *Server) enrichClusterStatsR62Admin(
	r *http.Request,
	openIndices []string,
	totalDocs, totalSizeBytes int64,
	indicesMap map[string]any,
	nodesMap map[string]any,
	resp map[string]any,
) {
	isHuman := isTruthyBoolQueryParam(r, "human")

	if docsMap, ok := indicesMap["docs"].(map[string]any); ok {
		docsMap["total_size_in_bytes"] = totalSizeBytes
		if isHuman {
			docsMap["total_size"] = formatBytesHuman(totalSizeBytes)
		}
	}

	ftAgg := make(map[string]*fieldTypeAggR62Admin)
	dedupFields := make(map[string]bool)
	analysisInputs := make([]analysis.IndexStatsInput, 0, len(openIndices))
	sparseFieldCount := 0
	var rawMappingBytesTotal int64

	s.mu.RLock()
	snapCount := 0
	for _, snapsByName := range s.snapshots {
		snapCount += len(snapsByName)
	}
	repoTypesByName := make(map[string]string, len(s.snapshotRepos))
	for repoName, repoCfg := range s.snapshotRepos {
		rType := "fs"
		if repoCfg != nil {
			if ts, okT := repoCfg["type"].(string); okT && strings.TrimSpace(ts) != "" {
				rType = strings.TrimSpace(ts)
			}
		}
		repoTypesByName[repoName] = rType
	}
	rawSettingsByIdx := make(map[string]map[string]any, len(openIndices))
	rawMappingsByIdx := make(map[string]*esast.MappingSpec, len(openIndices))
	for _, idxName := range openIndices {
		if cs := s.indexCustomSettings[idxName]; len(cs) > 0 {
			rawSettingsByIdx[idxName] = deepCloneDocMap(cs)
		}
		if sch := s.indices[idxName]; sch != nil && sch.RawMapping != nil {
			if cloned := sch.CloneIndexSchema(); cloned != nil && cloned.RawMapping != nil {
				rawMappingsByIdx[idxName] = cloned.RawMapping
			}
		}
	}
	s.mu.RUnlock()

	var denseValueCount, sparseValueCount int64
	reqCtx := context.Background()
	if r != nil && r.Context() != nil {
		reqCtx = r.Context()
	}

	opts := s.analysisOptionsR62Admin()
	for _, idxName := range openIndices {
		var refs []string
		if rm := rawMappingsByIdx[idxName]; rm != nil {
			if b, err := json.Marshal(rm); err == nil {
				rawMappingBytesTotal += int64(len(b))
			}
			walkRawPropsForClusterFieldTypesR62Admin(idxName, rm.Properties, ftAgg, dedupFields, "")
			collectFieldAnalyzerRefsFromRawPropsR62Admin(rm.Properties, &refs)

			densePaths := make(map[string]bool)
			sparsePaths := make(map[string]bool)
			collectVectorPathsByTypeR63Admin(rm.Properties, "", densePaths, sparsePaths)
			if len(densePaths) > 0 || len(sparsePaths) > 0 {
				docs := s.collectIndexedDocsWithIDsRound61(reqCtx, idxName, nil)
				for _, d := range docs {
					for dp := range densePaths {
						denseValueCount += int64(countDocVectorFieldPresenceR63Admin(d.Source, dp, false))
					}
					for sp := range sparsePaths {
						sparseValueCount += int64(countDocVectorFieldPresenceR63Admin(d.Source, sp, true))
					}
				}
			}
		}
		cfg, _ := analysis.ParseIndexAnalysisConfig(rawSettingsByIdx[idxName], opts)
		analysisInputs = append(analysisInputs, analysis.IndexStatsInput{
			Config:                cfg,
			FieldAnalyzerRefsList: refs,
		})
	}
	if aggSV := ftAgg["sparse_vector"]; aggSV != nil {
		sparseFieldCount = aggSV.count
	}

	ftNames := make([]string, 0, len(ftAgg))
	for k := range ftAgg {
		ftNames = append(ftNames, k)
	}
	sort.Strings(ftNames)
	fieldTypesSlice := make([]any, 0, len(ftNames))
	totalFieldCount := 0
	for _, ftName := range ftNames {
		ent := ftAgg[ftName]
		totalFieldCount += ent.count
		item := map[string]any{
			"name":                 ftName,
			"count":                ent.count,
			"index_count":          len(ent.indexSet),
			"has_doc_values_count": ent.hasDocValuesCnt,
			"indexed_count":        ent.indexedCount,
			"script_count":         0,
		}
		if ftName == "dense_vector" {
			item["indexed_vector_count"] = ent.indexedVectorCount
			item["indexed_vector_dim_min"] = ent.indexedDimsMin
			item["indexed_vector_dim_max"] = ent.indexedDimsMax
			item["dims"] = map[string]any{
				"min": ent.dimsMax,
				"max": ent.dimsMax,
				"sum": ent.dimsSum,
			}
			itList := make([]any, 0, len(ent.indexTypes))
			for itk, itc := range ent.indexTypes {
				itList = append(itList, map[string]any{"name": itk, "count": itc})
			}
			simList := make([]any, 0, len(ent.similarities))
			for sk, sc := range ent.similarities {
				simList = append(simList, map[string]any{"name": sk, "count": sc})
			}
			item["index_types"] = itList
			item["similarities"] = simList
		}
		fieldTypesSlice = append(fieldTypesSlice, item)
	}

	type runtimeFieldTypeStat struct {
		count         int
		indexSet      map[string]bool
		scriptlessCnt int
		shadowedCnt   int
		linesMax      int
		linesTotal    int
		charsMax      int
		charsTotal    int
		langs         map[string]bool
	}
	rtAgg := make(map[string]*runtimeFieldTypeStat)
	for _, idxName := range openIndices {
		if rm := rawMappingsByIdx[idxName]; rm != nil && len(rm.Runtime) > 0 {
			for rtFieldName, rtProp := range rm.Runtime {
				rtType := strings.ToLower(strings.TrimSpace(rtProp.Type))
				if rtType == "" {
					rtType = "keyword"
				}
				ent := rtAgg[rtType]
				if ent == nil {
					ent = &runtimeFieldTypeStat{
						indexSet: make(map[string]bool),
						langs:    make(map[string]bool),
					}
					rtAgg[rtType] = ent
				}
				ent.count++
				ent.indexSet[idxName] = true
				if _, shadowed := lookupFieldPropertyInRawMappingR62Admin(rm, rtFieldName); shadowed {
					ent.shadowedCnt++
				}
				srcStr, _ := extractScriptSourceAndParams(rtProp.Script)
				if rtProp.Script == nil || strings.TrimSpace(srcStr) == "" {
					ent.scriptlessCnt++
				} else {
					ent.langs["painless"] = true
					cLen := len([]rune(srcStr))
					lCnt := strings.Count(srcStr, "\n") + 1
					ent.charsTotal += cLen
					if cLen > ent.charsMax {
						ent.charsMax = cLen
					}
					ent.linesTotal += lCnt
					if lCnt > ent.linesMax {
						ent.linesMax = lCnt
					}
				}
			}
		}
	}
	rtNames := make([]string, 0, len(rtAgg))
	for k := range rtAgg {
		rtNames = append(rtNames, k)
	}
	sort.Strings(rtNames)
	runtimeFieldTypesSlice := make([]any, 0, len(rtNames))
	for _, rtName := range rtNames {
		ent := rtAgg[rtName]
		langSlice := make([]string, 0, len(ent.langs))
		for l := range ent.langs {
			langSlice = append(langSlice, l)
		}
		sort.Strings(langSlice)
		rtItem := map[string]any{
			"name":             rtName,
			"count":            ent.count,
			"index_count":      len(ent.indexSet),
			"scriptless_count": ent.scriptlessCnt,
			"shadowed_count":   ent.shadowedCnt,
			"lang":             langSlice,
			"source_max":       0,
			"source_total":     0,
			"lines_max":        ent.linesMax,
			"lines_total":      ent.linesTotal,
			"chars_max":        ent.charsMax,
			"chars_total":      ent.charsTotal,
			"doc_max":          0,
			"doc_total":        0,
		}
		runtimeFieldTypesSlice = append(runtimeFieldTypesSlice, rtItem)
	}

	mappingsStats := map[string]any{
		"field_types":                              fieldTypesSlice,
		"runtime_field_types":                      runtimeFieldTypesSlice,
		"total_field_count":                        totalFieldCount,
		"total_deduplicated_field_count":           len(dedupFields),
		"total_deduplicated_mapping_size_in_bytes": rawMappingBytesTotal,
	}
	if isHuman {
		mappingsStats["total_deduplicated_mapping_size"] = formatBytesHuman(rawMappingBytesTotal)
	}
	indicesMap["mappings"] = mappingsStats
	indicesMap["analysis"] = analysis.ComputeClusterAnalysisStats(analysisInputs)
	indicesMap["dense_vector"] = map[string]any{
		"value_count": denseValueCount,
	}
	indicesMap["sparse_vector"] = map[string]any{
		"field_count": sparseFieldCount,
		"value_count": sparseValueCount,
	}
	_ = totalDocs

	memPressure := map[string]any{
		"current": map[string]any{
			"combined_coordinating_and_primary_in_bytes": 0,
			"coordinating_in_bytes":                      0,
			"primary_in_bytes":                           0,
			"replica_in_bytes":                           0,
			"all_in_bytes":                               0,
		},
		"total": map[string]any{
			"combined_coordinating_and_primary_in_bytes":        0,
			"coordinating_in_bytes":                             0,
			"primary_in_bytes":                                  0,
			"replica_in_bytes":                                  0,
			"all_in_bytes":                                      0,
			"coordinating_rejections":                           0,
			"primary_rejections":                                0,
			"replica_rejections":                                0,
			"limit_in_bytes":                                    107374182,
			"last_successful_request_timestamp":                 0,
			"Last_successful_combined_coordinating_and_primary": 0,
		},
		"limit_in_bytes": 107374182,
	}
	if isHuman {
		curMap := memPressure["current"].(map[string]any)
		curMap["combined_coordinating_and_primary"] = "0b"
		curMap["coordinating"] = "0b"
		curMap["primary"] = "0b"
		curMap["replica"] = "0b"
		curMap["all"] = "0b"
		memPressure["limit"] = formatBytesHuman(107374182)
	}
	nodesMap["indexing_pressure"] = map[string]any{
		"memory": memPressure,
	}

	repoStatsOut := make(map[string]any, len(repoTypesByName))
	for repoName, repoType := range repoTypesByName {
		repoEntry := map[string]any{
			"type": repoType,
			"current_counts": map[string]any{
				"snapshots":          0,
				"clones":             0,
				"finalizations":      0,
				"deletions":          0,
				"snapshot_deletions": 0,
				"active_deletions":   0,
				"shards": map[string]any{
					"total":      0,
					"complete":   0,
					"incomplete": 0,
					"states": map[string]any{
						"INIT":    0,
						"SUCCESS": 0,
						"FAILED":  0,
						"ABORTED": 0,
						"MISSING": 0,
						"WAITING": 0,
						"QUEUED":  0,
					},
				},
			},
			"oldest_start_time_millis": 0,
		}
		if isHuman {
			repoEntry["oldest_start_time"] = "1970-01-01T00:00:00.000Z"
		}
		repoStatsOut[repoName] = repoEntry
	}

	resp["snapshots"] = map[string]any{
		"count":        snapCount,
		"repositories": repoStatsOut,
		"current_counts": map[string]any{
			"total":                 0,
			"clones":                0,
			"deletes":               0,
			"snapshots":             0,
			"shard_snapshots":       0,
			"snapshot_deletions":    0,
			"concurrent_operations": 0,
			"cleanups":              0,
		},
	}
}

// ============================================================================
// F4, F5, F7, F19, F25: Synthetic Source, Validate Query, Templates & Shadow
// ============================================================================

func redactShadowURLR62Admin(rawURL string) string {
	if strings.TrimSpace(rawURL) == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return rawURL
	}
	return u.Redacted()
}

func validateGetMGetForceSyntheticSourceR62Admin(idxSchema *schema.IndexSchema) error {
	if idxSchema == nil || idxSchema.RawMapping == nil || len(idxSchema.RawMapping.Properties) == 0 {
		return nil
	}
	var walk func(props map[string]esast.FieldProperty, prefix string) error
	walk = func(props map[string]esast.FieldProperty, prefix string) error {
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			prop := props[k]
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			pType := strings.ToLower(strings.TrimSpace(prop.Type))
			if pType == "text" || pType == "match_only_text" {
				isStored := prop.Store != nil && *prop.Store
				hasValidKeywordSub := false
				for _, sub := range prop.Fields {
					if strings.ToLower(strings.TrimSpace(sub.Type)) == "keyword" && strings.TrimSpace(sub.Normalizer) == "" {
						dvEnabled := sub.DocValues == nil || *sub.DocValues
						subStored := sub.Store != nil && *sub.Store
						if dvEnabled || subStored {
							hasValidKeywordSub = true
							break
						}
					}
				}
				if !isStored && !hasValidKeywordSub {
					return fmt.Errorf(
						"field [%s] of type [%s] doesn't support synthetic source unless it is stored or has a sub-field of type [keyword] with doc values or stored and without a normalizer",
						full, pType,
					)
				}
			}
			if len(prop.Properties) > 0 {
				if err := walk(prop.Properties, full); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(idxSchema.RawMapping.Properties, "")
}

var knownESQueryClausesR62Admin = []string{
	"bool", "boosting", "combined_fields", "common", "constant_score", "dis_max", "distance_feature",
	"exists", "field_masking_span", "function_score", "fuzzy", "geo_bounding_box", "geo_distance",
	"geo_polygon", "geo_shape", "has_child", "has_parent", "ids", "intervals", "knn", "match",
	"match_all", "match_bool_prefix", "match_none", "match_phrase", "match_phrase_prefix",
	"more_like_this", "multi_match", "nested", "parent_id", "percolate", "pinned", "prefix",
	"query_string", "range", "rank_feature", "regexp", "rule", "script", "script_score",
	"semantic", "shape", "simple_query_string", "span_containing", "span_first", "span_multi",
	"span_near", "span_not", "span_or", "span_term", "span_within", "sparse_vector", "term",
	"terms", "terms_set", "wildcard", "wrapper",
}

func editDistanceR62Admin(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	prev := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			ins := cur[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			m := ins
			if del < m {
				m = del
			}
			if sub < m {
				m = sub
			}
			cur[j] = m
		}
		prev = cur
	}
	return prev[len(rb)]
}

func enrichValidateQueryErrorSuggestionR62Admin(errMsg string) string {
	// Normalize `unknown query clause [foo]` -> `unknown query [foo]` and append ` did you mean [bar]?` when Levenshtein distance <= 2.
	errMsg = strings.ReplaceAll(errMsg, "unknown query clause [", "unknown query [")
	const marker = "unknown query ["
	idx := strings.Index(errMsg, marker)
	if idx < 0 || strings.Contains(errMsg, "did you mean") {
		return errMsg
	}
	rest := errMsg[idx+len(marker):]
	end := strings.IndexByte(rest, ']')
	if end <= 0 {
		return errMsg
	}
	badName := rest[:end]
	best := ""
	bestDist := 3
	for _, cand := range knownESQueryClausesR62Admin {
		d := editDistanceR62Admin(badName, cand)
		if d > 0 && d < bestDist {
			bestDist = d
			best = cand
		}
	}
	insertPos := idx + len(marker) + end + 1
	tail := errMsg[insertPos:]
	if tail == "" {
		tail = ";"
	}
	if best == "" {
		return errMsg[:insertPos] + tail
	}
	return errMsg[:insertPos] + " did you mean [" + best + "]?" + tail
}

func (s *Server) formatValidateQueryExplanationR62Admin(
	ctx context.Context,
	idxName string,
	idxSchema *schema.IndexSchema,
	subReq *esast.SearchRequest,
	aliasFilter *esast.Query,
	hitsSQL string,
	trOpts transpiler.TranspilerOptions,
) string {
	_ = ctx
	var baseQ *esast.Query
	if subReq != nil {
		baseQ = subReq.Query
	}
	if s == nil || !s.hasExplicitTargetESVersion() {
		if baseQ == nil && aliasFilter == nil {
			return "*:*"
		}
		if hitsSQL != "" {
			return hitsSQL
		}
	}
	effQ := combineQueryWithAliasFilter(baseQ, aliasFilter)
	if effQ == nil {
		return "*:*"
	}
	cfg := trOpts.AnalysisConfig
	opts := trOpts.AnalysisOpts
	if cfg == nil && s != nil {
		cfg, opts = s.buildIndexAnalysisConfigR62Admin(idxName)
	}
	return transpiler.FormatLuceneValidateExplanation(effQ, idxSchema, cfg, opts)
}

func formatComponentTemplateForOutputR62Admin(comp map[string]any, flatSettings, includeDefaults, isES8 bool) map[string]any {
	if comp == nil {
		return map[string]any{"template": map[string]any{}}
	}
	out := deepCloneDocMap(comp)
	tplObj, _ := out["template"].(map[string]any)
	if tplObj == nil {
		tplObj = map[string]any{}
		out["template"] = tplObj
	}
	if rawSet, okS := tplObj["settings"].(map[string]any); okS && len(rawSet) > 0 {
		tplObj["settings"] = formatCanonicalTemplateSettings(rawSet, flatSettings)
	}
	if lcRaw, okLC := tplObj["lifecycle"].(map[string]any); okLC {
		lcCopy := deepCloneDocMap(lcRaw)
		if isES8 {
			if _, hasEn := lcCopy["enabled"]; !hasEn {
				lcCopy["enabled"] = true
			}
		}
		if includeDefaults && isES8 {
			if _, hasRO := lcCopy["rollover"]; !hasRO {
				lcCopy["rollover"] = map[string]any{"max_age": "30d", "max_primary_shard_size": "50gb", "min_docs": 1}
			}
		}
		tplObj["lifecycle"] = lcCopy
	}
	return out
}

func (s *Server) normalizeStoredComponentTemplatesR62Admin(r *http.Request) {
	if s == nil {
		return
	}
	isES8 := s.isES8Mode(r)
	s.mu.Lock()
	for name, comp := range s.componentTemplates {
		if comp != nil {
			s.componentTemplates[name] = formatComponentTemplateForOutputR62Admin(comp, false, false, isES8)
		}
	}
	s.mu.Unlock()
}

func (s *Server) serveGetComponentTemplateR62Admin(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	trimmedPath := strings.Trim(r.URL.Path, "/")
	name := ""
	if strings.HasPrefix(trimmedPath, "_component_template/") {
		name = strings.TrimSpace(strings.TrimPrefix(trimmedPath, "_component_template/"))
	}
	patterns := []string{"*"}
	if name != "" && name != "_all" {
		patterns = strings.Split(name, ",")
		for i := range patterns {
			patterns[i] = strings.TrimSpace(patterns[i])
		}
	}
	flatSettings := isTruthyBoolQueryParam(r, "flat_settings")
	includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")
	isES8 := s.isES8Mode(r)

	s.mu.RLock()
	var matchedNames []string
	for k := range s.componentTemplates {
		if matchesTemplateNamePatterns(k, patterns) {
			matchedNames = append(matchedNames, k)
		}
	}
	sort.Strings(matchedNames)
	list := make([]any, 0, len(matchedNames))
	for _, k := range matchedNames {
		formatted := formatComponentTemplateForOutputR62Admin(s.componentTemplates[k], flatSettings, includeDefaults, isES8)
		list = append(list, map[string]any{
			"name":               k,
			"component_template": formatted,
		})
	}
	s.mu.RUnlock()

	if name != "" && !strings.ContainsAny(name, "*?,") && !strings.HasPrefix(name, "-") && name != "_all" && len(list) == 0 {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", "component_template ["+name+"] missing")
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"component_templates": list})
}

func overlayNestedRawPropsR62Admin(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	srcProps, _ := src["properties"].(map[string]any)
	dstProps, _ := dst["properties"].(map[string]any)
	if srcProps == nil || dstProps == nil {
		return
	}
	for fName, rawProp := range srcProps {
		sp, okS := rawProp.(map[string]any)
		dp, okD := dstProps[fName].(map[string]any)
		if !okS || !okD {
			continue
		}
		for _, extraKey := range []string{"include_in_parent", "include_in_root"} {
			if ev, exists := sp[extraKey]; exists {
				dp[extraKey] = ev
			}
		}
		overlayNestedRawPropsR62Admin(dp, sp)
	}
}

func lookupRawIndexSettingPresenceR62Admin(settings map[string]any, shortKey string) (val any, present bool) {
	if len(settings) == 0 {
		return nil, false
	}
	for _, k := range []string{shortKey, "index." + shortKey} {
		if v, ok := settings[k]; ok {
			return v, true
		}
	}
	if idxMap, ok := settings["index"].(map[string]any); ok {
		if v, ok2 := idxMap[shortKey]; ok2 {
			return v, true
		}
		parts := strings.Split(shortKey, ".")
		cur := idxMap
		for i, p := range parts {
			v, exists := cur[p]
			if !exists {
				break
			}
			if i == len(parts)-1 {
				return v, true
			}
			sub, okM := v.(map[string]any)
			if !okM {
				break
			}
			cur = sub
		}
	}
	parts := strings.Split(shortKey, ".")
	cur := settings
	for i, p := range parts {
		v, exists := cur[p]
		if !exists {
			break
		}
		if i == len(parts)-1 {
			return v, true
		}
		sub, okM := v.(map[string]any)
		if !okM {
			break
		}
		cur = sub
	}
	return nil, false
}

func validateRolloverBodyAndTypeR62Admin(w http.ResponseWriter, s *Server, r *http.Request, bodyBytes []byte, conditions map[string]any) bool {
	isES8 := s.isES8Mode(r)
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var rawBody map[string]any
		if json.Unmarshal(bodyBytes, &rawBody) == nil {
			if rawMap, okM := rawBody["mappings"].(map[string]any); okM && len(rawMap) == 1 {
				for typeKey, typeVal := range rawMap {
					if _, isObj := typeVal.(map[string]any); isObj && !reservedMappingRootKeysR61CRUD[typeKey] {
						if !isES8 && isTruthyBoolQueryParam(r, "include_type_name") {
							continue
						}
						if isES8 {
							writeESError(w, http.StatusBadRequest, "mapper_parsing_exception",
								fmt.Sprintf("Root mapping definition has unsupported parameters:  [%s : %v]", typeKey, typeVal))
							return false
						}
						errReason := fmt.Sprintf("The mapping definition cannot be nested under a type [%s] unless include_type_name is set to true.", typeKey)
						writeJSON(w, http.StatusBadRequest, map[string]any{
							"error": map[string]any{
								"root_cause": []map[string]any{
									{"type": "illegal_argument_exception", "reason": errReason},
								},
								"type":   "illegal_argument_exception",
								"reason": errReason,
								"caused_by": map[string]any{
									"type":   "illegal_argument_exception",
									"reason": errReason,
								},
							},
							"status": http.StatusBadRequest,
						})
						return false
					}
				}
			}
		}
	}
	if isES8 && len(conditions) > 0 {
		hasMin := false
		hasMax := false
		for k := range conditions {
			if strings.HasPrefix(k, "min_") {
				hasMin = true
			} else if strings.HasPrefix(k, "max_") {
				hasMax = true
			}
		}
		if hasMin && !hasMax {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: at least one max_* rollover condition must be set when using min_* conditions;")
			return false
		}
	}
	return true
}
