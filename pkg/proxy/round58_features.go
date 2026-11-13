package proxy

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- deterministic non-cryptographic bucket ID hashing for ES transform/rollup
	"encoding/base64"
	"encoding/hex"
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
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func ensureESCompatHeaders(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	if r != nil {
		if opaqueID := r.Header.Get("X-Opaque-Id"); opaqueID != "" {
			w.Header().Set("X-Opaque-Id", opaqueID)
		}
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if tp := r.Header.Get("traceparent"); tp != "" {
			w.Header().Set("traceparent", tp)
		}
	}
}

func writeJSONWithRequest(w http.ResponseWriter, r *http.Request, status int, v any) {
	ensureESCompatHeaders(w, r)
	if r != nil {
		if _, ok := extractESResponseFormatOptions(w); !ok {
			if opts, hasOpts := parseESResponseFormatOptions(r); hasOpts {
				w = &esFormatResponseWriter{ResponseWriter: w, opts: opts}
			}
		}
	}
	writeJSON(w, status, v)
}

func (s *Server) handleCatTemplatesRound58(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	emptyBoth := len(s.templates) == 0 && len(s.legacyTemplates) == 0
	s.mu.RUnlock()
	if emptyBoth {
		s.handleCatTemplates(w, r)
		return
	}
	pat := strings.TrimSpace(r.PathValue("name"))
	s.mu.RLock()
	seen := make(map[string]bool, len(s.templates)+len(s.legacyTemplates))
	names := make([]string, 0, len(s.templates)+len(s.legacyTemplates))
	for k := range s.templates {
		if pat == "" || matchMultiWildcardWithExclusions(pat, k) {
			seen[k] = true
			names = append(names, k)
		}
	}
	for k := range s.legacyTemplates {
		if !seen[k] && (pat == "" || matchMultiWildcardWithExclusions(pat, k)) {
			seen[k] = true
			names = append(names, k)
		}
	}
	sort.Strings(names)
	list := make([]map[string]any, 0, len(names))
	for _, k := range names {
		tpl, isComp := s.templates[k]
		if !isComp {
			tpl = s.legacyTemplates[k]
		}
		patterns := "[" + strings.Join(tpl.EffectivePatterns(), ", ") + "]"
		verStr := ""
		if tpl.Version != nil {
			verStr = strconv.Itoa(*tpl.Version)
		} else if isComp {
			if v, hasVer := s.templateVersions[k]; hasVer {
				verStr = strconv.Itoa(v)
			}
		}
		list = append(list, map[string]any{
			"name":           k,
			"index_patterns": patterns,
			"order":          fmt.Sprintf("%d", tpl.EffectivePriority()),
			"version":        verStr,
			"composed_of":    "[" + strings.Join(tpl.ComposedOf, ", ") + "]",
		})
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"name", "index_patterns", "order", "version", "composed_of"}, list)
}

// ---------------------------------------------------------------------------
// Round 58 F2: Stateful Point-in-Time (PIT) & Scroll Context Lifecycle
// ---------------------------------------------------------------------------

type pitContextEntry struct {
	ID        string
	Targets   []string
	RawIndex  string
	ExpiresAt time.Time
}

type scrollContextEntry struct {
	Token     string
	SessionID string
	ExpiresAt time.Time
}

// parseESPositiveDuration parses an Elasticsearch positive time-unit string
// (d, h, m, s, ms, micros, us, nanos, ns). Case-sensitive on 'm' vs 'M'.
func parseESPositiveDuration(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("time value must not be empty")
	}
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("time value [%s] must be positive", raw)
	}
	type unitDef struct {
		suffix string
		mult   float64
	}
	// Longer suffixes must come before shorter prefixes (micros/ms/nanos/ns before m/s).
	units := []unitDef{
		{"micros", float64(time.Microsecond)},
		{"nanos", float64(time.Nanosecond)},
		{"ms", float64(time.Millisecond)},
		{"us", float64(time.Microsecond)},
		{"ns", float64(time.Nanosecond)},
		{"d", float64(24 * time.Hour)},
		{"h", float64(time.Hour)},
		{"m", float64(time.Minute)},
		{"s", float64(time.Second)},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			numPart := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			if numPart == "" {
				return 0, fmt.Errorf("missing numeric value in [%s]", raw)
			}
			val, err := strconv.ParseFloat(numPart, 64)
			if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
				return 0, fmt.Errorf("invalid time value [%s]", raw)
			}
			dur := time.Duration(val * u.mult)
			if dur <= 0 {
				dur = 1 * time.Nanosecond
			}
			return dur, nil
		}
	}
	return 0, fmt.Errorf("missing or unsupported time unit in [%s]", raw)
}

func (s *Server) ensurePITStoreLocked() {
	if s.pits == nil {
		s.pits = make(map[string]*pitContextEntry)
	}
}

func (s *Server) ensureScrollStoreLocked() {
	if s.scrollContexts == nil {
		s.scrollContexts = make(map[string]*scrollContextEntry)
	}
	if s.invalidatedScrollSessions == nil {
		s.invalidatedScrollSessions = make(map[string]bool)
	}
}

func (s *Server) handlePITRound58(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if r.PathValue("pit_all") == "true" {
		if r.Method != http.MethodDelete {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.ensurePITStoreLocked()
		pitResults := make([]map[string]any, 0, len(s.pits))
		freed := 0
		ids := make([]string, 0, len(s.pits))
		for id := range s.pits {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			entry := s.pits[id]
			if entry != nil && !now.After(entry.ExpiresAt) {
				freed++
				pitResults = append(pitResults, map[string]any{"pit_id": id, "successful": true})
			}
		}
		s.pits = make(map[string]*pitContextEntry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"succeeded": true,
			"num_freed": freed,
			"pits":      pitResults,
		})
		return
	}

	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "" {
		// Root /_pit supports DELETE only.
		if r.Method != http.MethodDelete {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var ids []string
		deleteAll := false
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var payload map[string]any
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
			rawID, hasID := payload["id"]
			if !hasID || rawID == nil {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
				return
			}
			switch v := rawID.(type) {
			case string:
				trimmed := strings.TrimSpace(v)
				if trimmed == "" {
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
					return
				}
				if trimmed == "_all" {
					deleteAll = true
				} else {
					ids = append(ids, trimmed)
				}
			case []any:
				if len(v) == 0 {
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: no pit ids specified;")
					return
				}
				for _, item := range v {
					strItem, isStr := item.(string)
					if !isStr || strings.TrimSpace(strItem) == "" {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "pit id must be a non-empty string")
						return
					}
					if strings.TrimSpace(strItem) == "_all" {
						deleteAll = true
					} else {
						ids = append(ids, strings.TrimSpace(strItem))
					}
				}
			default:
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[id] must be a string or array of strings")
				return
			}
		} else if qID := strings.TrimSpace(r.URL.Query().Get("id")); qID != "" {
			if qID == "_all" {
				deleteAll = true
			} else {
				ids = append(ids, qID)
			}
		} else {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}

		s.mu.Lock()
		s.ensurePITStoreLocked()
		if deleteAll {
			freed := 0
			pitResults := make([]map[string]any, 0, len(s.pits))
			allIDs := make([]string, 0, len(s.pits))
			for id := range s.pits {
				allIDs = append(allIDs, id)
			}
			sort.Strings(allIDs)
			for _, id := range allIDs {
				if e := s.pits[id]; e != nil && !now.After(e.ExpiresAt) {
					freed++
					pitResults = append(pitResults, map[string]any{"pit_id": id, "successful": true})
				}
			}
			s.pits = make(map[string]*pitContextEntry)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"succeeded": true,
				"num_freed": freed,
				"pits":      pitResults,
			})
			return
		}

		allSucceeded := true
		numFreed := 0
		pitResults := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			entry, exists := s.pits[id]
			delete(s.pits, id)
			if exists && entry != nil && !now.After(entry.ExpiresAt) {
				numFreed++
				pitResults = append(pitResults, map[string]any{"pit_id": id, "successful": true})
			} else {
				allSucceeded = false
				pitResults = append(pitResults, map[string]any{"pit_id": id, "successful": false})
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"succeeded": allSucceeded,
			"num_freed": numFreed,
			"pits":      pitResults,
		})
		return
	}

	// /{index}/_pit supports POST only.
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawKeepAlive := strings.TrimSpace(r.URL.Query().Get("keep_alive"))
	if rawKeepAlive == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: keep_alive is missing;")
		return
	}
	ttl, err := parseESPositiveDuration(rawKeepAlive)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("failed to parse setting [keep_alive] with value [%s] as a time value: %v", rawKeepAlive, err))
		return
	}
	if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
		return
	}
	if _, reason := s.findReadBlockedTargetIndex(r, rawIndex); reason != "" {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
		return
	}
	targets, aliasFilters, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	for _, t := range targets {
		if s.isIndexClosed(t) {
			writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", t))
			return
		}
	}

	pitPattern := rawIndex
	if len(aliasFilters) == 0 && len(targets) > 0 {
		pitPattern = strings.Join(targets, ",")
	}
	s.mu.Lock()
	s.ensurePITStoreLocked()
	s.pitSeq++
	seq := s.pitSeq
	pitID := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("pit:%s#%d", pitPattern, seq)))
	s.pits[pitID] = &pitContextEntry{
		ID:        pitID,
		Targets:   append([]string(nil), targets...),
		RawIndex:  pitPattern,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id": pitID})
}

func (s *Server) validateAndResolvePITRequest(rawIndex string, req *esast.SearchRequest) (string, int, string, string) {
	if req == nil || req.PIT == nil {
		return rawIndex, 0, "", ""
	}
	if strings.TrimSpace(rawIndex) != "" {
		return "", http.StatusBadRequest, "illegal_argument_exception", "[pit] cannot be used together with index"
	}
	pitID := strings.TrimSpace(req.PIT.ID)
	if pitID == "" {
		return "", http.StatusBadRequest, "illegal_argument_exception", "[pit.id] must not be empty"
	}
	var extendTTL time.Duration
	if rawKA := strings.TrimSpace(req.PIT.KeepAlive); rawKA != "" {
		ttl, err := parseESPositiveDuration(rawKA)
		if err != nil {
			return "", http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("failed to parse [pit.keep_alive] value [%s]: %v", rawKA, err)
		}
		extendTTL = ttl
	}
	now := time.Now()
	s.mu.Lock()
	s.ensurePITStoreLocked()
	entry, exists := s.pits[pitID]
	if !exists || entry == nil || now.After(entry.ExpiresAt) {
		if exists {
			delete(s.pits, pitID)
		}
		s.mu.Unlock()
		return "", http.StatusNotFound, "search_context_missing_exception", fmt.Sprintf("No search context found for id [%s]", pitID)
	}
	if extendTTL > 0 {
		entry.ExpiresAt = now.Add(extendTTL)
	}
	pitTarget := entry.RawIndex
	s.mu.Unlock()

	ensurePITDeterministicSort(req)
	return pitTarget, 0, "", ""
}

func (s *Server) isPITActive(pitID string) bool {
	pitID = strings.TrimSpace(pitID)
	if pitID == "" {
		return false
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pits == nil {
		return false
	}
	entry, ok := s.pits[pitID]
	return ok && entry != nil && !now.After(entry.ExpiresAt)
}

func ensurePITDeterministicSort(req *esast.SearchRequest) {
	if req == nil || req.PIT == nil {
		return
	}
	hasIDTie := false
	for i := range req.Sort {
		if req.Sort[i].Entry.Field == "_shard_doc" {
			req.Sort[i].Entry.Field = "_id"
			if req.Sort[i].Entry.Order == "" {
				req.Sort[i].Entry.Order = "asc"
			}
		}
		if req.Sort[i].Entry.Field == "_id" {
			hasIDTie = true
		}
	}
	if len(req.Sort) == 0 {
		isUnscored := req.Query == nil || req.Query.MatchAll != nil
		if len(req.SearchAfter) == 2 || (!isUnscored && len(req.SearchAfter) != 1) {
			req.Sort = esast.SortSlice{
				{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
				{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
			}
		} else {
			req.Sort = esast.SortSlice{
				{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
			}
		}
		return
	}
	if !hasIDTie {
		req.Sort = append(req.Sort, esast.SortSpec{
			Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"},
		})
	}
}

func (s *Server) registerInitialScrollContext(token string, ttl time.Duration) {
	if token == "" {
		return
	}
	s.mu.Lock()
	s.ensureScrollStoreLocked()
	s.scrollSeq++
	sessionID := fmt.Sprintf("scroll-sess-%d", s.scrollSeq)
	s.scrollContexts[token] = &scrollContextEntry{
		Token:     token,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
}

func (s *Server) validateAndAdvanceScrollToken(token, nextToken string, extendTTL time.Duration) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureScrollStoreLocked()
	entry, ok := s.scrollContexts[token]
	if !ok || entry == nil {
		return false
	}
	if s.invalidatedScrollSessions[entry.SessionID] || now.After(entry.ExpiresAt) {
		delete(s.scrollContexts, token)
		return false
	}
	newExp := entry.ExpiresAt
	if extendTTL > 0 {
		newExp = now.Add(extendTTL)
		entry.ExpiresAt = newExp
	}
	if nextToken != "" {
		s.scrollContexts[nextToken] = &scrollContextEntry{
			Token:     nextToken,
			SessionID: entry.SessionID,
			ExpiresAt: newExp,
		}
	}
	return true
}

func (s *Server) clearScrollTokens(ids []string, clearAll bool) (bool, int) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureScrollStoreLocked()
	if clearAll {
		activeSessions := make(map[string]bool)
		for tok, entry := range s.scrollContexts {
			if entry != nil && !s.invalidatedScrollSessions[entry.SessionID] && !now.After(entry.ExpiresAt) {
				activeSessions[entry.SessionID] = true
			}
			if entry != nil {
				s.invalidatedScrollSessions[entry.SessionID] = true
			}
			delete(s.scrollContexts, tok)
		}
		return true, len(activeSessions)
	}
	allSucceeded := true
	numFreed := 0
	sessionsToInvalidate := make(map[string]bool)
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			allSucceeded = false
			continue
		}
		entry, exists := s.scrollContexts[id]
		if exists && entry != nil && !s.invalidatedScrollSessions[entry.SessionID] && !now.After(entry.ExpiresAt) {
			delete(s.scrollContexts, id)
			numFreed++
			sessionsToInvalidate[entry.SessionID] = true
		} else {
			delete(s.scrollContexts, id)
			allSucceeded = false
		}
	}
	for sessID := range sessionsToInvalidate {
		s.invalidatedScrollSessions[sessID] = true
		for tok, entry := range s.scrollContexts {
			if entry != nil && entry.SessionID == sessID {
				delete(s.scrollContexts, tok)
			}
		}
	}
	return allSucceeded, numFreed
}

// ---------------------------------------------------------------------------
// Round 58 F4: Composable vs Legacy Index Templates & Data Stream Write Guards
// ---------------------------------------------------------------------------

func (s *Server) ensureTemplateStoresLocked() {
	if s.templates == nil {
		s.templates = make(map[string]esast.IndexTemplateRequest)
	}
	if s.legacyTemplates == nil {
		s.legacyTemplates = make(map[string]esast.IndexTemplateRequest)
	}
}

func marshalTemplatePreservingEmptyMaps(tpl esast.IndexTemplateRequest) ([]byte, error) {
	raw, err := json.Marshal(tpl)
	if err != nil {
		return nil, err
	}
	if tpl.DataStream == nil && tpl.Meta == nil {
		return raw, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, nil
	}
	if m == nil {
		m = make(map[string]any)
	}
	if tpl.DataStream != nil {
		m["data_stream"] = tpl.DataStream
	}
	if tpl.Meta != nil {
		m["_meta"] = tpl.Meta
	}
	return json.Marshal(m)
}

func (s *Server) persistLegacyTemplate(ctx context.Context, name string, tpl *esast.IndexTemplateRequest) {
	if tpl == nil {
		s.deleteCatalogEntity(ctx, "legacy_template", name)
		return
	}
	cb, ok := s.backend.(CatalogBackend)
	if !ok || cb == nil {
		return
	}
	if raw, err := marshalTemplatePreservingEmptyMaps(*tpl); err == nil {
		_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
			EntityType:     "legacy_template",
			EntityKey:      name,
			PayloadJSON:    string(raw),
			UpdatedEpochMs: s.allocVersion(0),
		})
	}
}

// wildcardPatternsOverlap reports whether two glob patterns (* and ?) have a
// non-empty intersection (could match at least one identical concrete string).
func wildcardPatternsOverlap(p1, p2 string) bool {
	type state struct{ i, j int }
	visited := make(map[state]bool)
	var dfs func(i, j int) bool
	dfs = func(i, j int) bool {
		st := state{i, j}
		if visited[st] {
			return false
		}
		visited[st] = true
		if i == len(p1) && j == len(p2) {
			return true
		}
		if i < len(p1) && p1[i] == '*' {
			if dfs(i+1, j) {
				return true
			}
			if j < len(p2) && dfs(i, j+1) {
				return true
			}
		}
		if j < len(p2) && p2[j] == '*' {
			if dfs(i, j+1) {
				return true
			}
			if i < len(p1) && dfs(i+1, j) {
				return true
			}
		}
		if i < len(p1) && j < len(p2) && p1[i] != '*' && p2[j] != '*' {
			if p1[i] == '?' || p2[j] == '?' || p1[i] == p2[j] {
				return dfs(i+1, j+1)
			}
		}
		return false
	}
	return dfs(0, 0)
}

func matchesTemplateIndexPatterns(indexName string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	matchedPositive := false
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "-") {
			if matchWildcardPattern(strings.TrimPrefix(pat, "-"), indexName) {
				return false
			}
			continue
		}
		if matchWildcardPattern(pat, indexName) {
			matchedPositive = true
		}
	}
	return matchedPositive
}

func formatComposableTemplateOutput(name string, tpl esast.IndexTemplateRequest, lifecycle map[string]any) map[string]any {
	tObj := map[string]any{}
	if m := tpl.EffectiveMappings(); m != nil {
		tObj["mappings"] = m
	}
	if st := tpl.EffectiveSettings(); len(st) > 0 {
		tObj["settings"] = st
	}
	if al := tpl.EffectiveAliases(); len(al) > 0 {
		tObj["aliases"] = al
	}
	if len(lifecycle) > 0 {
		tObj["lifecycle"] = lifecycle
	}
	item := map[string]any{
		"index_patterns": tpl.EffectivePatterns(),
		"template":       tObj,
		"composed_of":    nonNilStringSlice(tpl.ComposedOf),
		"priority":       tpl.EffectivePriority(),
	}
	if tpl.Version != nil {
		item["version"] = *tpl.Version
	}
	if tpl.Meta != nil {
		item["_meta"] = tpl.Meta
	}
	if tpl.DataStream != nil {
		item["data_stream"] = tpl.DataStream
	}
	if tpl.AllowAutoCreate != nil {
		item["allow_auto_create"] = *tpl.AllowAutoCreate
	}
	return map[string]any{
		"name":           name,
		"index_template": item,
	}
}

func formatLegacyTemplateOutput(tpl esast.IndexTemplateRequest) map[string]any {
	orderVal := 0
	if tpl.Order != nil {
		orderVal = *tpl.Order
	} else if tpl.Priority != nil {
		orderVal = *tpl.Priority
	}
	mappingsOut := any(map[string]any{})
	if m := tpl.EffectiveMappings(); m != nil {
		mappingsOut = m
	}
	settingsOut := map[string]any{}
	if st := tpl.EffectiveSettings(); len(st) > 0 {
		settingsOut = st
	}
	aliasesOut := map[string]map[string]any{}
	if al := tpl.EffectiveAliases(); len(al) > 0 {
		aliasesOut = al
	}
	out := map[string]any{
		"order":          orderVal,
		"index_patterns": tpl.EffectivePatterns(),
		"settings":       settingsOut,
		"mappings":       mappingsOut,
		"aliases":        aliasesOut,
	}
	if tpl.Version != nil {
		out["version"] = *tpl.Version
	}
	return out
}

func nonNilStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (s *Server) handleComposableOrLegacyTemplateRound58(w http.ResponseWriter, r *http.Request, name string) {
	isLegacyEndpoint := strings.HasPrefix(strings.Trim(r.URL.Path, "/"), "_template")
	switch r.Method {
	case http.MethodHead:
		_ = s.syncCatalogFromBackend(r.Context())
		ensureESCompatHeaders(w, r)
		s.mu.RLock()
		store := s.templates
		if isLegacyEndpoint {
			store = s.legacyTemplates
		}
		found := false
		if name == "" || name == "*" || name == "_all" {
			found = len(store) > 0
		} else if !strings.ContainsAny(name, "*?") && !strings.HasPrefix(name, "-") {
			found = true
			hasAny := false
			for _, part := range strings.Split(name, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				hasAny = true
				if _, exists := store[part]; !exists {
					found = false
					break
				}
			}
			if !hasAny {
				found = false
			}
		} else {
			for k := range store {
				if matchMultiWildcardWithExclusions(name, k) {
					found = true
					break
				}
			}
		}
		s.mu.RUnlock()
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		if strings.ContainsAny(name, "*?,") {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("template name [%s] must not contain wildcards or commas", name))
			return
		}
		var tpl esast.IndexTemplateRequest
		var parsedTemplateLifecycle map[string]any
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &tpl); err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
			var rawTplMap map[string]any
			if err := json.Unmarshal(bodyBytes, &rawTplMap); err == nil {
				if innerTpl, okT := rawTplMap["template"].(map[string]any); okT {
					if lcRaw, okLC := innerTpl["lifecycle"].(map[string]any); okLC {
						lcNorm, err := normalizeAndValidateDataStreamLifecycle(lcRaw)
						if err != nil {
							writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
							return
						}
						parsedTemplateLifecycle = lcNorm
					}
				}
			}
		}
		tpl.Legacy = isLegacyEndpoint
		patterns := tpl.EffectivePatterns()
		if len(patterns) == 0 {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index_patterns must not be empty;")
			return
		}
		for _, p := range patterns {
			if strings.TrimSpace(p) == "" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "index template pattern must not be empty")
				return
			}
		}
		if !isLegacyEndpoint && len(tpl.ComposedOf) > 0 {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			var missingComp string
			for _, compName := range tpl.ComposedOf {
				if _, exists := s.componentTemplates[compName]; !exists {
					missingComp = compName
					break
				}
			}
			s.mu.RUnlock()
			if missingComp != "" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("index_template [%s] invalid, cause [Validation Failed: 1: component template [%s] not found;]", name, missingComp))
				return
			}
		}
		if m := tpl.EffectiveMappings(); m != nil {
			if err := schema.ValidateMappingSpec(m); err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
		}

		isCreateOnly := isTruthyBoolQueryParam(r, "create")
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.Lock()
		s.ensureTemplateStoresLocked()
		if isLegacyEndpoint {
			if isCreateOnly {
				if _, exists := s.legacyTemplates[name]; exists {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", fmt.Sprintf("index_template [%s] already exists", name))
					return
				}
			}
			s.legacyTemplates[name] = tpl
			s.mu.Unlock()
			s.persistLegacyTemplate(r.Context(), name, &tpl)
		} else {
			if isCreateOnly {
				if _, exists := s.templates[name]; exists {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", fmt.Sprintf("index_template [%s] already exists", name))
					return
				}
			}
			effPrio := tpl.EffectivePriority()
			for otherName, otherTpl := range s.templates {
				if otherName == name {
					continue
				}
				if otherTpl.EffectivePriority() != effPrio {
					continue
				}
				for _, p1 := range patterns {
					p1 = strings.TrimSpace(p1)
					if p1 == "" || strings.HasPrefix(p1, "-") {
						continue
					}
					for _, p2 := range otherTpl.EffectivePatterns() {
						p2 = strings.TrimSpace(p2)
						if p2 == "" || strings.HasPrefix(p2, "-") {
							continue
						}
						if wildcardPatternsOverlap(p1, p2) {
							s.mu.Unlock()
							writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
								fmt.Sprintf("index template [%s] has index patterns %v matching patterns from existing templates [%s] with patterns (%v) that have the same priority [%d], multiple index templates may not match during index creation, please use a different priority",
									name, patterns, otherName, otherTpl.EffectivePatterns(), effPrio))
							return
						}
					}
				}
			}
			s.templates[name] = tpl
			if s.templateLifecycles == nil {
				s.templateLifecycles = make(map[string]map[string]any)
			}
			if parsedTemplateLifecycle != nil {
				s.templateLifecycles[name] = parsedTemplateLifecycle
			} else {
				delete(s.templateLifecycles, name)
			}
			if s.templateVersions == nil {
				s.templateVersions = make(map[string]int)
			}
			if tpl.Version != nil {
				s.templateVersions[name] = *tpl.Version
			} else {
				delete(s.templateVersions, name)
			}
			s.mu.Unlock()
			s.persistTemplate(r.Context(), name, tpl)
		}
		s.queryCache.InvalidateAll()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet:
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.RLock()
		store := s.templates
		if isLegacyEndpoint {
			store = s.legacyTemplates
		}
		var names []string
		if name == "" || name == "*" || name == "_all" {
			for k := range store {
				names = append(names, k)
			}
		} else if hasExclusionOrWildcard(name) || strings.Contains(name, ",") {
			for _, part := range strings.Split(name, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
					continue
				}
				if _, ok := store[part]; !ok {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("index_template [%s] missing", part))
					return
				}
			}
			for k := range store {
				if matchMultiWildcardWithExclusions(name, k) {
					names = append(names, k)
				}
			}
		} else {
			if _, ok := store[name]; !ok {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("index_template [%s] missing", name))
				return
			}
			names = []string{name}
		}
		sort.Strings(names)
		if isLegacyEndpoint {
			legacyResp := make(map[string]any, len(names))
			for _, k := range names {
				legacyResp[k] = formatLegacyTemplateOutput(store[k])
			}
			s.mu.RUnlock()
			writeJSONWithRequest(w, r, http.StatusOK, legacyResp)
			return
		}
		list := make([]any, 0, len(names))
		for _, k := range names {
			list = append(list, formatComposableTemplateOutput(k, store[k], s.templateLifecycles[k]))
		}
		s.mu.RUnlock()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"index_templates": list})

	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.Lock()
		s.ensureTemplateStoresLocked()
		store := s.templates
		if isLegacyEndpoint {
			store = s.legacyTemplates
		}
		var deletedNames []string
		if name == "*" || name == "_all" || strings.ContainsAny(name, "*?,") || strings.HasPrefix(name, "-") {
			for k := range store {
				if name == "*" || name == "_all" || matchMultiWildcardWithExclusions(name, k) {
					deletedNames = append(deletedNames, k)
				}
			}
			if len(deletedNames) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_template_missing_exception", fmt.Sprintf("index_template [%s] missing", name))
				return
			}
			for _, k := range deletedNames {
				delete(store, k)
				if !isLegacyEndpoint {
					delete(s.templateVersions, k)
					delete(s.templateLifecycles, k)
				}
			}
		} else {
			if _, exists := store[name]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_template_missing_exception", fmt.Sprintf("index_template [%s] missing", name))
				return
			}
			delete(store, name)
			if !isLegacyEndpoint {
				delete(s.templateVersions, name)
				delete(s.templateLifecycles, name)
			}
			deletedNames = []string{name}
		}
		s.mu.Unlock()
		for _, k := range deletedNames {
			if isLegacyEndpoint {
				s.persistLegacyTemplate(r.Context(), k, nil)
			} else {
				s.deleteCatalogEntity(r.Context(), "template", k)
			}
		}
		s.queryCache.InvalidateAll()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// matchingTemplateFullConfigLocked resolves template configuration for indexName:
//   - If >= 1 composable template matches, ONLY the single highest-priority composable
//     template is applied (its composed_of component templates in slice order, then itself).
//   - Legacy templates (/_template) are applied in ascending order ONLY if zero composable
//     templates matched indexName.
func (s *Server) matchingTemplateFullConfigLocked(indexName string) (
	merged *esast.MappingSpec,
	defaultPipeline string,
	hasDefaultPipeline bool,
	finalPipeline string,
	hasFinalPipeline bool,
	mergedAliases map[string]map[string]any,
	mergedCustomSettings map[string]any,
	winningComposable *esast.IndexTemplateRequest,
) {
	applyTemplateSpec := func(t esast.IndexTemplateRequest) {
		if m := t.EffectiveMappings(); m != nil {
			merged = schema.MergeMappingSpecs(merged, m)
		}
		if ts := t.EffectiveSettings(); len(ts) > 0 {
			if p, found := extractDefaultPipelineFromSettings(ts); found {
				defaultPipeline = p
				hasDefaultPipeline = true
			}
			if fp, found := extractFinalPipelineFromSettings(ts); found {
				finalPipeline = fp
				hasFinalPipeline = true
			}
			if cust := extractCustomIndexSettings(ts); len(cust) > 0 {
				if mergedCustomSettings == nil {
					mergedCustomSettings = make(map[string]any, len(cust))
				}
				for ck, cv := range cust {
					mergedCustomSettings[ck] = cv
				}
			}
		}
		if ta := t.EffectiveAliases(); len(ta) > 0 {
			if mergedAliases == nil {
				mergedAliases = make(map[string]map[string]any, len(ta))
			}
			for al, meta := range ta {
				mergedAliases[al] = meta
			}
		}
	}

	var composableMatches []string
	for k, tpl := range s.templates {
		if matchesTemplateIndexPatterns(indexName, tpl.EffectivePatterns()) {
			composableMatches = append(composableMatches, k)
		}
	}
	if len(composableMatches) > 0 {
		sort.Slice(composableMatches, func(i, j int) bool {
			pi := s.templates[composableMatches[i]].EffectivePriority()
			pj := s.templates[composableMatches[j]].EffectivePriority()
			if pi != pj {
				return pi > pj // highest priority first
			}
			return composableMatches[i] < composableMatches[j]
		})
		winName := composableMatches[0]
		winTpl := s.templates[winName]
		winCopy := winTpl
		winningComposable = &winCopy
		for _, compName := range winTpl.ComposedOf {
			if compRaw, ok := s.componentTemplates[compName]; ok && len(compRaw) > 0 {
				if rawBytes, err := json.Marshal(compRaw); err == nil {
					var compTpl esast.IndexTemplateRequest
					if err := json.Unmarshal(rawBytes, &compTpl); err == nil {
						applyTemplateSpec(compTpl)
					}
				}
			}
		}
		applyTemplateSpec(winTpl)
		return
	}

	var legacyMatches []string
	for k, tpl := range s.legacyTemplates {
		if matchesTemplateIndexPatterns(indexName, tpl.EffectivePatterns()) {
			legacyMatches = append(legacyMatches, k)
		}
	}
	sort.Slice(legacyMatches, func(i, j int) bool {
		pi := s.legacyTemplates[legacyMatches[i]].EffectivePriority()
		pj := s.legacyTemplates[legacyMatches[j]].EffectivePriority()
		if pi != pj {
			return pi < pj // lowest order first, higher order overrides
		}
		return legacyMatches[i] < legacyMatches[j]
	})
	for _, name := range legacyMatches {
		applyTemplateSpec(s.legacyTemplates[name])
	}
	return
}

// prepareAutoCreateTargetRound58 checks composable template allow_auto_create and
// data_stream auto-creation when writing to a target name that does not yet exist.
func (s *Server) prepareAutoCreateTargetRound58(ctx context.Context, rawTarget string, isCreateOp bool) (int, string, string) {
	target := strings.TrimSpace(rawTarget)
	if target == "" || strings.ContainsAny(target, "*?,") || strings.HasPrefix(target, "<") {
		return 0, "", ""
	}
	_ = s.syncCatalogFromBackend(ctx)
	s.mu.RLock()
	_, isIdx := s.indices[target]
	_, isAlias := s.aliases[target]
	_, isDS := s.dataStreams[target]
	_, _, _, _, _, _, _, winComp := s.matchingTemplateFullConfigLocked(target)
	s.mu.RUnlock()

	if isDS {
		if !isCreateOp && s.isDataStream(target) {
			return http.StatusBadRequest, "illegal_argument_exception", "only write ops with an op_type of create are allowed in data streams"
		}
		return 0, "", ""
	}
	if isIdx || isAlias || winComp == nil {
		return 0, "", ""
	}
	if winComp.AllowAutoCreate != nil && !*winComp.AllowAutoCreate {
		return http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s] and [allow_auto_create] is [false] on matching index template", target)
	}
	if winComp.DataStream != nil {
		if !isCreateOp {
			return http.StatusBadRequest, "illegal_argument_exception", "only write ops with an op_type of create are allowed in data streams"
		}
		if reason, valid := validateESIndexName(target); !valid || strings.HasPrefix(target, ".") {
			if reason == "" {
				reason = fmt.Sprintf("Invalid data stream name [%s], must not start with '.'", target)
			}
			return http.StatusBadRequest, "invalid_index_name_exception", reason
		}
		_ = s.ensureWritableIndexSchemaWithDocs(ctx, target, nil)
		isHidden := false
		if h, ok := winComp.DataStream["hidden"].(bool); ok {
			isHidden = h
		}
		s.mu.Lock()
		if s.dataStreams == nil {
			s.dataStreams = make(map[string]map[string]any)
		}
		dsMeta := map[string]any{
			"name":            target,
			"timestamp_field": map[string]any{"name": "@timestamp"},
			"indices": []any{
				map[string]any{
					"index_name": target,
					"index_uuid": target,
				},
			},
			"generation": 1,
			"status":     "GREEN",
			"hidden":     isHidden,
			"system":     false,
			"replicated": false,
		}
		if tplLC := s.extractMatchingTemplateLifecycleLocked(target); len(tplLC) > 0 {
			dsMeta["lifecycle"] = tplLC
		}
		if _, exists := s.dataStreams[target]; !exists {
			s.dataStreams[target] = dsMeta
		} else {
			dsMeta = s.dataStreams[target]
		}
		s.mu.Unlock()
		s.persistDataStream(ctx, target, dsMeta)
	}
	return 0, "", ""
}

// ---------------------------------------------------------------------------
// Round 58 F5: Single-Doc Target Validation, index.hidden & _resolve/index
// ---------------------------------------------------------------------------

func validateSingleDocTargetName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	// Resolve <prefix{date_math}> if used.
	resolved := resolveDateMathIndexExpr(trimmed)
	if strings.Contains(resolved, ",") {
		return "", fmt.Errorf("single-document request target [%s] must not contain multiple indices", raw)
	}
	if resolved == "_all" || strings.ContainsAny(resolved, "*?") {
		return "", fmt.Errorf("single-document request target [%s] must not contain wildcards or _all", raw)
	}
	return resolved, nil
}

func resolveDateMathIndexExpr(raw string) string {
	if !strings.HasPrefix(raw, "<") || !strings.HasSuffix(raw, ">") {
		return raw
	}
	inner := raw[1 : len(raw)-1]
	openBrace := strings.IndexByte(inner, '{')
	closeBrace := strings.LastIndexByte(inner, '}')
	if openBrace < 0 || closeBrace <= openBrace {
		return inner
	}
	prefix := inner[:openBrace]
	suffix := inner[closeBrace+1:]
	spec := inner[openBrace+1 : closeBrace]
	dateFmt := "2006.01.02"
	if pipeIdx := strings.IndexByte(spec, '|'); pipeIdx >= 0 {
		customFmt := spec[pipeIdx+1:]
		if strings.Contains(customFmt, "yyyy") {
			r := strings.NewReplacer("yyyy", "2006", "MM", "01", "dd", "02", "HH", "15", "mm", "04", "ss", "05")
			dateFmt = r.Replace(customFmt)
		}
	}
	return prefix + time.Now().UTC().Format(dateFmt) + suffix
}

func (s *Server) isIndexExplicitlyHiddenLocked(idxName string) bool {
	if s.indexCustomSettings != nil {
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			if hv, ok := cust["hidden"]; ok {
				switch v := hv.(type) {
				case bool:
					if v {
						return true
					}
				case string:
					if strings.EqualFold(strings.TrimSpace(v), "true") {
						return true
					}
				}
			}
		}
	}
	if ds, ok := s.dataStreams[idxName]; ok && ds != nil {
		if hv, ok := ds["hidden"].(bool); ok && hv {
			return true
		}
	}
	return false
}

func parseExpandWildcardsFlags(raw string) (ewOpen, ewClosed, ewHidden, ewNone bool, err error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return true, false, false, false, nil
	}
	parts := strings.Split(trimmed, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "":
			continue
		case "open":
			ewOpen = true
		case "closed":
			ewClosed = true
		case "hidden":
			ewHidden = true
		case "none":
			ewNone = true
		case "all":
			ewOpen = true
			ewClosed = true
			ewHidden = true
		default:
			return false, false, false, false, fmt.Errorf("invalid expand_wildcards value [%s]", p)
		}
	}
	if ewNone && !ewOpen && !ewClosed && !ewHidden {
		return false, false, false, true, nil
	}
	return ewOpen, ewClosed, ewHidden, false, nil
}

func (s *Server) handleResolveIndexRound58(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	rawName := strings.TrimSpace(r.PathValue("name"))
	if rawName == "" {
		rawName = strings.TrimSpace(r.URL.Query().Get("name"))
	}
	if rawName == "" {
		rawName = "*"
	}
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
	if ewErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
		return
	}

	concreteParts := make(map[string]bool)
	for _, part := range strings.Split(rawName, ",") {
		part = strings.TrimSpace(part)
		if part != "" && !strings.HasPrefix(part, "-") && !strings.ContainsAny(part, "*?") && part != "_all" {
			concreteParts[part] = true
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	backingToDS := make(map[string]string)
	for dsName, ds := range s.dataStreams {
		if ds == nil {
			continue
		}
		for _, biName := range extractDataStreamBackingIndexNames(ds) {
			backingToDS[biName] = dsName
		}
	}

	var indicesOut []map[string]any
	var idxNames []string
	for k := range s.indices {
		idxNames = append(idxNames, k)
	}
	sort.Strings(idxNames)
	for _, name := range idxNames {
		if _, isDS := s.dataStreams[name]; isDS && backingToDS[name] == "" {
			continue
		}
		if strings.HasPrefix(name, ".ds-") && !concreteParts[name] && !ewHidden {
			continue
		}
		if !matchMultiWildcardWithExclusions(rawName, name) {
			continue
		}
		isClosed := s.closedIndices[name]
		isHidden := s.isIndexExplicitlyHiddenLocked(name) || strings.HasPrefix(name, ".ds-")
		if !concreteParts[name] {
			if ewNone {
				continue
			}
			stateMatch := (isClosed && ewClosed) || (!isClosed && ewOpen)
			if !stateMatch {
				continue
			}
			if isHidden && !ewHidden {
				continue
			}
		}
		var idxAliases []string
		for al, targets := range s.aliases {
			for _, t := range targets {
				if t == name {
					if !ewHidden && s.aliasMeta[al] != nil {
						if m := s.aliasMeta[al][name]; m.IsHidden != nil && *m.IsHidden {
							continue
						}
					}
					idxAliases = append(idxAliases, al)
				}
			}
		}
		sort.Strings(idxAliases)
		attrs := []string{"open"}
		stateStr := "open"
		isOpen := true
		if isClosed {
			attrs = []string{"close"}
			stateStr = "close"
			isOpen = false
		}
		if isHidden {
			attrs = append(attrs, "hidden")
		}
		entry := map[string]any{
			"name":       name,
			"attributes": attrs,
			"state":      stateStr,
			"open":       isOpen,
			"hidden":     isHidden,
		}
		if len(idxAliases) > 0 {
			entry["aliases"] = idxAliases
		}
		if dsName, ok := backingToDS[name]; ok {
			entry["data_stream"] = dsName
		}
		indicesOut = append(indicesOut, entry)
	}
	if indicesOut == nil {
		indicesOut = []map[string]any{}
	}

	var aliasesOut []map[string]any
	var aliasNames []string
	for al := range s.aliases {
		aliasNames = append(aliasNames, al)
	}
	sort.Strings(aliasNames)
	for _, al := range aliasNames {
		if !matchMultiWildcardWithExclusions(rawName, al) {
			continue
		}
		tCopy := append([]string(nil), s.aliases[al]...)
		sort.Strings(tCopy)
		isAliasHidden := false
		if metaByIdx := s.aliasMeta[al]; metaByIdx != nil {
			allHidden := len(tCopy) > 0
			for _, t := range tCopy {
				m, hasM := metaByIdx[t]
				if !hasM || m.IsHidden == nil || !*m.IsHidden {
					allHidden = false
					break
				}
			}
			isAliasHidden = allHidden
		}
		if !concreteParts[al] {
			if ewNone {
				continue
			}
			if isAliasHidden && !ewHidden {
				continue
			}
			hasMatchingTarget := false
			for _, t := range tCopy {
				tClosed := s.closedIndices[t]
				tHidden := s.isIndexExplicitlyHiddenLocked(t)
				if ((tClosed && ewClosed) || (!tClosed && ewOpen)) && (!tHidden || ewHidden || !isAliasHidden) {
					hasMatchingTarget = true
					break
				}
			}
			if !hasMatchingTarget {
				continue
			}
		}
		aliasesOut = append(aliasesOut, map[string]any{
			"name":    al,
			"indices": tCopy,
		})
	}
	if aliasesOut == nil {
		aliasesOut = []map[string]any{}
	}

	var dsOut []map[string]any
	var dsNames []string
	for ds := range s.dataStreams {
		dsNames = append(dsNames, ds)
	}
	sort.Strings(dsNames)
	for _, dsName := range dsNames {
		if !matchMultiWildcardWithExclusions(rawName, dsName) {
			continue
		}
		dsMeta := s.dataStreams[dsName]
		dsHidden := false
		if dsMeta != nil {
			if hv, ok := dsMeta["hidden"].(bool); ok && hv {
				dsHidden = true
			}
		}
		if !concreteParts[dsName] {
			if ewNone || !ewOpen {
				continue
			}
			if dsHidden && !ewHidden {
				continue
			}
		}
		backing := extractDataStreamBackingIndexNames(dsMeta)
		if len(backing) == 0 {
			backing = []string{".ds-" + dsName + "-000001"}
		}
		tsField := "@timestamp"
		if dsMeta != nil {
			if tf, ok := dsMeta["timestamp_field"].(map[string]any); ok {
				if n, ok := tf["name"].(string); ok && n != "" {
					tsField = n
				}
			} else if tf, ok := dsMeta["timestamp"].(map[string]any); ok {
				if n, ok := tf["name"].(string); ok && n != "" {
					tsField = n
				}
			}
		}
		dsOut = append(dsOut, map[string]any{
			"name":            dsName,
			"backing_indices": backing,
			"timestamp_field": tsField,
		})
	}
	if dsOut == nil {
		dsOut = []map[string]any{}
	}

	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"indices":      indicesOut,
		"aliases":      aliasesOut,
		"data_streams": dsOut,
	})
}

// ---------------------------------------------------------------------------
// Round 58 F6: _field_caps & _mapping/field Helpers
// ---------------------------------------------------------------------------

func (s *Server) isDataStreamOrBackingIndexLocked(idxName string) bool {
	if idxName == "" {
		return false
	}
	if _, ok := s.dataStreams[idxName]; ok {
		return true
	}
	if strings.HasPrefix(idxName, ".ds-") {
		return true
	}
	for _, ds := range s.dataStreams {
		for _, b := range extractDataStreamBackingIndexNames(ds) {
			if b == idxName {
				return true
			}
		}
	}
	return false
}

func matchesFieldCapsPatterns(field string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	hasPositive := false
	matchedPositive := false
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "-") {
			if matchWildcardPattern(strings.TrimPrefix(p, "-"), field) {
				return false
			}
			continue
		}
		hasPositive = true
		if matchWildcardPattern(p, field) {
			matchedPositive = true
		}
	}
	if !hasPositive {
		return true
	}
	return matchedPositive
}

type fieldCapsFilterFlags struct {
	onlyMetadata bool
	noMetadata   bool
	noMultifield bool
	noNested     bool
	noParent     bool
}

func parseFieldCapsFilters(tokens []string) (fieldCapsFilterFlags, error) {
	var f fieldCapsFilterFlags
	for _, raw := range tokens {
		for _, part := range strings.Split(raw, ",") {
			tok := strings.ToLower(strings.TrimSpace(part))
			if tok == "" {
				continue
			}
			switch tok {
			case "+metadata":
				f.onlyMetadata = true
			case "-metadata":
				f.noMetadata = true
			case "-multifield":
				f.noMultifield = true
			case "-nested":
				f.noNested = true
			case "-parent":
				f.noParent = true
			default:
				return f, fmt.Errorf("unknown field_caps filter [%s]", part)
			}
		}
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Round 58 F7: GET /{index} Full Settings & /_aliases Exclusions
// ---------------------------------------------------------------------------

func (s *Server) buildIndexSettingsMapLocked(indexName string) map[string]any {
	shortFlat := map[string]any{
		"number_of_shards":   "1",
		"number_of_replicas": "0",
		"provided_name":      indexName,
		"creation_date":      "1700000000000",
		"uuid":               indexName,
		"version.created":    "8120099",
	}
	if cust, ok := s.indexCustomSettings[indexName]; ok {
		for k, v := range cust {
			shortFlat[k] = v
		}
	}
	if p := s.indexDefaultPipelines[indexName]; p != "" {
		shortFlat["default_pipeline"] = p
	}
	if fp := s.indexFinalPipelines[indexName]; fp != "" {
		shortFlat["final_pipeline"] = fp
	}
	return shortFlat
}

func splitCommaTrimmedTokens(in []string) []string {
	var out []string
	for _, item := range in {
		for _, sub := range strings.Split(item, ",") {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				out = append(out, sub)
			}
		}
	}
	return out
}

func expandNamesWithExclusions(patterns []string, universe []string) []string {
	tokens := splitCommaTrimmedTokens(patterns)
	if len(tokens) == 0 {
		return nil
	}
	var positives []string
	var negatives []string
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negatives = append(negatives, strings.TrimPrefix(tok, "-"))
		} else {
			positives = append(positives, tok)
		}
	}
	matched := make(map[string]bool)
	if len(positives) == 0 && len(negatives) > 0 {
		for _, u := range universe {
			matched[u] = true
		}
	} else {
		for _, pos := range positives {
			if pos == "_all" || pos == "*" {
				for _, u := range universe {
					matched[u] = true
				}
				continue
			}
			if strings.ContainsAny(pos, "*?") {
				for _, u := range universe {
					if matchWildcardPattern(pos, u) {
						matched[u] = true
					}
				}
			} else {
				matched[pos] = true
			}
		}
	}
	for _, neg := range negatives {
		for k := range matched {
			if neg == "_all" || neg == "*" || matchWildcardPattern(neg, k) {
				delete(matched, k)
			}
		}
	}
	out := make([]string, 0, len(matched))
	for k := range matched {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Round 58 F8: By-Query / Reindex Source Index Validation
// ---------------------------------------------------------------------------

func (s *Server) hasAuthoritativeIndexCatalog() bool {
	if s == nil || s.backend == nil {
		return false
	}
	if _, ok := s.backend.(CatalogBackend); ok {
		return true
	}
	s.mu.RLock()
	hasCatalog := len(s.indices) > 0 || len(s.aliases) > 0 || len(s.dataStreams) > 0
	s.mu.RUnlock()
	return hasCatalog
}

// ---------------------------------------------------------------------------
// Round 58 F9: Escaped-Dot filter_path & _cat/* Format, Wildcards, Validation, Sort
// ---------------------------------------------------------------------------

// splitFilterPathExpressions splits comma-separated filter_path patterns while
// respecting backslash escapes.
func splitFilterPathExpressions(raw string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			cur.WriteByte(raw[i])
			cur.WriteByte(raw[i+1])
			i++
			continue
		}
		if raw[i] == ',' {
			if trimmed := strings.TrimSpace(cur.String()); trimmed != "" {
				out = append(out, trimmed)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(raw[i])
	}
	if trimmed := strings.TrimSpace(cur.String()); trimmed != "" {
		out = append(out, trimmed)
	}
	return out
}

// parseFilterPathSegments splits a single filter_path pattern on unescaped '.'
// while unescaping '\.' into a literal '.' inside the segment.
func parseFilterPathSegments(fp string) []string {
	var segs []string
	var cur strings.Builder
	for i := 0; i < len(fp); i++ {
		if fp[i] == '\\' && i+1 < len(fp) && fp[i+1] == '.' {
			cur.WriteByte('.')
			i++
			continue
		}
		if fp[i] == '.' {
			segs = append(segs, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(fp[i])
	}
	segs = append(segs, cur.String())
	return segs
}

// advanceArrayFilterPatterns returns the sub-patterns applicable to array element idx.
func advanceArrayFilterPatterns(patterns [][]string, idx int) (elemPatterns [][]string, matchedLeaf bool) {
	idxStr := strconv.Itoa(idx)
	for _, p := range patterns {
		if len(p) == 0 {
			matchedLeaf = true
			continue
		}
		head := p[0]
		switch head {
		case "**":
			elemPatterns = append(elemPatterns, p)
			if len(p) == 1 {
				matchedLeaf = true
			} else {
				elemPatterns = append(elemPatterns, p[1:])
			}
		case "*", idxStr:
			if len(p) == 1 {
				matchedLeaf = true
			} else {
				elemPatterns = append(elemPatterns, p[1:])
			}
		default:
			// ES implicit array-of-objects traversal (e.g. hits.hits._source.title).
			elemPatterns = append(elemPatterns, p)
		}
	}
	return elemPatterns, matchedLeaf
}

var catColumnShortAliases = map[string][]string{
	"i":    {"index", "id"},
	"idx":  {"index"},
	"s":    {"status", "state", "shard"},
	"st":   {"store", "state", "status"},
	"h":    {"health", "host"},
	"p":    {"pri", "prirep"},
	"r":    {"rep", "node.role"},
	"role": {"node.role", "role"},
	"d":    {"docs"},
	"dc":   {"docs.count"},
	"dd":   {"docs.deleted"},
	"ss":   {"store.size"},
	"pss":  {"pri.store.size"},
	"u":    {"uuid", "unassign"},
	"n":    {"name", "node"},
	"nt":   {"node.total"},
	"nd":   {"node.data"},
	"m":    {"master"},
	"hp":   {"heap.percent"},
	"rp":   {"ram.percent"},
	"dt":   {"disk.total"},
	"du":   {"disk.used"},
	"c":    {"cpu", "count", "cluster"},
	"a":    {"alias"},
	"is":   {"is_write_index"},
	"ip":   {"ip", "index_patterns"},
}

func resolveCatColumnToken(tok string, headers []string, knownCols map[string]bool) ([]string, bool) {
	if knownCols[tok] {
		return []string{tok}, true
	}
	if cands, ok := catColumnShortAliases[tok]; ok {
		for _, c := range cands {
			if knownCols[c] {
				return []string{c}, true
			}
		}
	}
	if strings.ContainsAny(tok, "*?") {
		var matched []string
		for _, hdr := range headers {
			if matchWildcardPattern(tok, hdr) {
				matched = append(matched, hdr)
			}
		}
		return matched, true
	}
	return nil, false
}

type catValueKind int

const (
	catKindOther catValueKind = iota
	catKindNumber
	catKindBytes
	catKindPercent
	catKindDuration
)

func parseComparableCatValue(raw string) (catValueKind, float64) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "-" || s == "null" {
		return catKindOther, 0
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return catKindNumber, f
	}
	if strings.HasSuffix(s, "%") {
		if f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, "%")), 64); err == nil && !math.IsNaN(f) {
			return catKindPercent, f
		}
	}
	lower := strings.ToLower(s)
	byteUnits := []struct {
		suf  string
		mult float64
	}{
		{"pb", 1 << 50}, {"tb", 1 << 40}, {"gb", 1 << 30}, {"mb", 1 << 20}, {"kb", 1 << 10}, {"b", 1},
	}
	for _, bu := range byteUnits {
		if strings.HasSuffix(lower, bu.suf) {
			numPart := strings.TrimSpace(lower[:len(lower)-len(bu.suf)])
			if f, err := strconv.ParseFloat(numPart, 64); err == nil && !math.IsNaN(f) {
				return catKindBytes, f * bu.mult
			}
		}
	}
	if dur, err := parseESPositiveDuration(s); err == nil {
		return catKindDuration, float64(dur)
	}
	return catKindOther, 0
}

func compareCatValues(a, b string) int {
	ka, va := parseComparableCatValue(a)
	kb, vb := parseComparableCatValue(b)
	if ka != catKindOther && ka == kb {
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
		return 0
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func negotiateCatFormat(r *http.Request) (string, error) {
	if r == nil {
		return "json", nil
	}
	rawFmt := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch rawFmt {
	case "":
		accept := strings.ToLower(r.Header.Get("Accept"))
		if strings.Contains(accept, "application/yaml") || strings.Contains(accept, "text/yaml") {
			return "yaml", nil
		}
		if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
			return "text", nil
		}
		return "json", nil
	case "json":
		return "json", nil
	case "text", "txt":
		return "text", nil
	case "yaml", "yml":
		return "yaml", nil
	default:
		return "", fmt.Errorf("format [%s] is not supported", rawFmt)
	}
}

func marshalCatYAML(headers []string, rows []map[string]any) []byte {
	if len(rows) == 0 {
		return []byte("--- []\n")
	}
	var buf strings.Builder
	buf.WriteString("---\n")
	for _, row := range rows {
		keys := headers
		if len(keys) == 0 {
			for k := range row {
				keys = append(keys, k)
			}
			sort.Strings(keys)
		}
		first := true
		for _, k := range keys {
			v, exists := row[k]
			if !exists {
				continue
			}
			prefix := "  "
			if first {
				prefix = "- "
				first = false
			}
			if v == nil {
				fmt.Fprintf(&buf, "%s%s: null\n", prefix, k)
				continue
			}
			rawJSON, _ := json.Marshal(fmt.Sprintf("%v", v))
			fmt.Fprintf(&buf, "%s%s: %s\n", prefix, k, string(rawJSON))
		}
	}
	return []byte(buf.String())
}

func writeCatResponseRound58(w http.ResponseWriter, r *http.Request, headers []string, rows []map[string]any) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	ensureESCompatHeaders(w, r)

	if isTruthyBoolQueryParam(r, "help") {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r != nil && r.Method == http.MethodHead {
			return
		}
		for _, hdr := range headers {
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintf(w, "%-20s |   | %s\n", hdr, hdr)
		}
		return
	}

	outFmt, fmtErr := negotiateCatFormat(r)
	if fmtErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmtErr.Error())
		return
	}

	knownCols := make(map[string]bool, len(headers)+8)
	for _, h := range headers {
		knownCols[h] = true
	}
	for _, row := range rows {
		for k := range row {
			knownCols[k] = true
		}
	}

	selectedHeaders := headers
	if r != nil {
		if rawH := strings.TrimSpace(r.URL.Query().Get("h")); rawH != "" {
			var filtered []string
			for _, part := range strings.Split(rawH, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				resolvedCols, ok := resolveCatColumnToken(part, headers, knownCols)
				if !ok {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unable tokes/header [%s] not recognized; valid headers: %v", part, headers))
					return
				}
				filtered = append(filtered, resolvedCols...)
			}
			selectedHeaders = filtered
		}
	}

	type sortCol struct {
		name string
		desc bool
	}
	var sortCols []sortCol
	if r != nil {
		if rawS := strings.TrimSpace(r.URL.Query().Get("s")); rawS != "" {
			for _, part := range strings.Split(rawS, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				colName := part
				desc := false
				if colon := strings.IndexByte(part, ':'); colon >= 0 {
					colName = strings.TrimSpace(part[:colon])
					dir := strings.ToLower(strings.TrimSpace(part[colon+1:]))
					switch dir {
					case "asc", "a":
						desc = false
					case "desc", "d":
						desc = true
					default:
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unable to parse cat sort order [%s] for column [%s]", dir, colName))
						return
					}
				}
				resolvedCols, ok := resolveCatColumnToken(colName, headers, knownCols)
				if !ok || len(resolvedCols) == 0 || strings.ContainsAny(colName, "*?") {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unknown sort column [%s]", colName))
					return
				}
				sortCols = append(sortCols, sortCol{name: resolvedCols[0], desc: desc})
			}
		}
	}

	if len(sortCols) > 0 && len(rows) > 1 {
		sortedRows := make([]map[string]any, len(rows))
		copy(sortedRows, rows)
		sort.SliceStable(sortedRows, func(i, j int) bool {
			for _, sc := range sortCols {
				vi := fmt.Sprintf("%v", sortedRows[i][sc.name])
				vj := fmt.Sprintf("%v", sortedRows[j][sc.name])
				cmp := compareCatValues(vi, vj)
				if cmp == 0 {
					continue
				}
				if sc.desc {
					return cmp > 0
				}
				return cmp < 0
			}
			return false
		})
		rows = sortedRows
	}

	var projectedRows []map[string]any
	if len(selectedHeaders) > 0 && len(selectedHeaders) != len(headers) {
		projectedRows = make([]map[string]any, len(rows))
		for i, row := range rows {
			m := make(map[string]any, len(selectedHeaders))
			for _, col := range selectedHeaders {
				if val, ok := row[col]; ok {
					m[col] = val
				} else {
					m[col] = nil
				}
			}
			projectedRows[i] = m
		}
	} else {
		projectedRows = rows
		if projectedRows == nil {
			projectedRows = []map[string]any{}
		}
	}

	switch outFmt {
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r != nil && r.Method == http.MethodHead {
			return
		}
		if isTruthyBoolQueryParam(r, "v") {
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(selectedHeaders, "\t"))
		}
		for _, row := range projectedRows {
			vals := make([]string, 0, len(selectedHeaders))
			for _, col := range selectedHeaders {
				v, exists := row[col]
				if !exists || v == nil {
					vals = append(vals, "")
				} else {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(vals, "\t"))
		}

	case "yaml":
		body := marshalCatYAML(selectedHeaders, projectedRows)
		w.Header().Set("Content-Type", "application/yaml; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r != nil && r.Method == http.MethodHead {
			return
		}
		// #nosec G705 -- Content-Type is application/yaml with X-Content-Type-Options: nosniff
		_, _ = w.Write(body)

	default:
		if r != nil && r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, projectedRows)
	}
}

// ---------------------------------------------------------------------------
// Round 58 F27, F28, F29: Ingest Pipeline Cycle Detection, Dissect & Reroute
// ---------------------------------------------------------------------------

func collectReferencedIngestPipelines(procs []any) []string {
	var refs []string
	var walkProcMap func(pMap map[string]any)
	walkProcMap = func(pMap map[string]any) {
		for pType, rawSpec := range pMap {
			if pType == "tag" || pType == "description" || pType == "if" || pType == "ignore_failure" || pType == "on_failure" {
				continue
			}
			specMap, ok := rawSpec.(map[string]any)
			if !ok {
				continue
			}
			switch pType {
			case "pipeline":
				if target, ok := specMap["name"].(string); ok && strings.TrimSpace(target) != "" {
					refs = append(refs, strings.TrimSpace(target))
				}
			case "foreach":
				if inner, ok := specMap["processor"].(map[string]any); ok {
					walkProcMap(inner)
				}
			}
			if onFail, ok := specMap["on_failure"].([]any); ok {
				refs = append(refs, collectReferencedIngestPipelines(onFail)...)
			}
		}
	}
	for _, p := range procs {
		if pMap, ok := p.(map[string]any); ok {
			walkProcMap(pMap)
		}
	}
	return refs
}

func validateNoIngestPipelineCycleLocked(newID string, newBody map[string]any, existing map[string]map[string]any) error {
	if newID == "" || newBody == nil {
		return nil
	}
	edgesOf := func(id string) []string {
		var body map[string]any
		if id == newID {
			body = newBody
		} else if existing != nil {
			body = existing[id]
		}
		if body == nil {
			return nil
		}
		var out []string
		if procs, ok := body["processors"].([]any); ok {
			out = append(out, collectReferencedIngestPipelines(procs)...)
		}
		if onFail, ok := body["on_failure"].([]any); ok {
			out = append(out, collectReferencedIngestPipelines(onFail)...)
		}
		return out
	}

	const (
		stateUnvisited = 0
		stateVisiting  = 1
		stateVisited   = 2
	)
	state := make(map[string]int)
	var dfs func(cur string) error
	dfs = func(cur string) error {
		state[cur] = stateVisiting
		for _, next := range edgesOf(cur) {
			if strings.Contains(next, "{{") {
				continue
			}
			if state[next] == stateVisiting {
				return fmt.Errorf("illegal_argument_exception: cycle detected in pipeline [%s] referencing [%s]", cur, next)
			}
			if state[next] == stateUnvisited {
				if err := dfs(next); err != nil {
					return err
				}
			}
		}
		state[cur] = stateVisited
		return nil
	}
	return dfs(newID)
}

func validateDissectPatternGrammar(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("illegal_argument_exception: dissect pattern must not be empty")
	}
	firstIdx := strings.Index(pattern, "%{")
	if firstIdx < 0 {
		return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: no tokens found", pattern)
	}

	type tokInfo struct {
		padRight bool
		nextLit  string
	}
	var tokens []tokInfo
	definedRefKeys := make(map[string]bool)
	var referencedKeys []string

	rem := pattern[firstIdx:]
	for len(rem) > 0 {
		if !strings.HasPrefix(rem, "%{") {
			break
		}
		endBrace := strings.IndexByte(rem, '}')
		if endBrace < 0 {
			return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: unclosed token", pattern)
		}
		inner := rem[2:endBrace]
		if strings.Contains(inner, "%{") {
			return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: nested token", pattern)
		}
		rem = rem[endBrace+1:]

		var nextLit string
		if nextStart := strings.Index(rem, "%{"); nextStart >= 0 {
			nextLit = rem[:nextStart]
			rem = rem[nextStart:]
		} else {
			nextLit = rem
			rem = ""
		}
		if strings.Contains(nextLit, "%{") {
			return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: unclosed token", pattern)
		}

		padRight := false
		if strings.HasSuffix(inner, "->") {
			padRight = true
			inner = strings.TrimSuffix(inner, "->")
			inner = strings.TrimRight(inner, "-")
		}
		inner = strings.TrimSpace(inner)

		switch {
		case inner == "":
			// Anonymous skip token %{} or %{->} is valid.
		case strings.HasPrefix(inner, "?"):
			rk := strings.TrimSpace(strings.TrimPrefix(inner, "?"))
			if strings.Contains(rk, "/") {
				return fmt.Errorf("illegal_argument_exception: invalid dissect order modifier on skip key [%s]", inner)
			}
			if rk != "" {
				definedRefKeys[rk] = true
			}
		case strings.HasPrefix(inner, "*"):
			rk := strings.TrimSpace(strings.TrimPrefix(inner, "*"))
			if rk == "" {
				return fmt.Errorf("illegal_argument_exception: empty dissect reference key in pattern [%s]", pattern)
			}
			if strings.Contains(rk, "/") {
				return fmt.Errorf("illegal_argument_exception: invalid dissect order modifier on reference key [%s]", inner)
			}
			definedRefKeys[rk] = true
		case strings.HasPrefix(inner, "+") || strings.HasPrefix(inner, "&"):
			hasAppend := false
			hasIndirect := false
			rest := inner
			for strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "&") {
				if strings.HasPrefix(rest, "+") {
					hasAppend = true
					rest = strings.TrimPrefix(rest, "+")
				}
				if strings.HasPrefix(rest, "&") {
					hasIndirect = true
					rest = strings.TrimPrefix(rest, "&")
				}
			}
			rest = strings.TrimSpace(rest)
			if rest == "" {
				return fmt.Errorf("illegal_argument_exception: empty dissect modifier key in pattern [%s]", pattern)
			}
			if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
				if !hasAppend {
					return fmt.Errorf("illegal_argument_exception: dissect order modifier requires '+' in [%s]", inner)
				}
				keyPart := strings.TrimSpace(rest[:slashIdx])
				ordPart := rest[slashIdx+1:]
				ord, err := strconv.Atoi(ordPart)
				if keyPart == "" || err != nil || ord <= 0 {
					return fmt.Errorf("illegal_argument_exception: invalid dissect append order in [%s]", inner)
				}
				rest = keyPart
			}
			if hasIndirect {
				referencedKeys = append(referencedKeys, rest)
			} else if rest != "" {
				definedRefKeys[rest] = true
			}
		default:
			if strings.Contains(inner, "/") {
				return fmt.Errorf("illegal_argument_exception: dissect append order requires '+' modifier in [%s]", inner)
			}
			if inner != "" {
				definedRefKeys[inner] = true
			}
		}

		tokens = append(tokens, tokInfo{padRight: padRight, nextLit: nextLit})
	}

	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i].nextLit == "" && !tokens[i].padRight {
			return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: consecutive tokens without delimiter or ->", pattern)
		}
	}
	for _, rk := range referencedKeys {
		if !definedRefKeys[rk] {
			return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: reference key [%s] is missing matching *%s or ?%s", pattern, rk, rk, rk)
		}
	}
	return nil
}

func stripDissectRightPadding(s, delim string, fromPrefix bool) string {
	if delim == "" || s == "" {
		return s
	}
	if fromPrefix {
		for strings.HasPrefix(s, delim) {
			s = s[len(delim):]
		}
	} else {
		for strings.HasSuffix(s, delim) {
			s = s[:len(s)-len(delim)]
		}
	}
	firstRune, w := utf8.DecodeRuneInString(delim)
	if firstRune != utf8.RuneError && w > 0 {
		allSameRune := true
		for _, r := range delim {
			if r != firstRune {
				allSameRune = false
				break
			}
		}
		if allSameRune {
			if fromPrefix {
				s = strings.TrimLeft(s, string(firstRune))
			} else {
				s = strings.TrimRight(s, string(firstRune))
			}
		}
	}
	return s
}

func tryRenderMustacheStrict(tpl string, doc map[string]any) (string, bool) {
	var out strings.Builder
	rem := tpl
	for {
		openIdx := strings.Index(rem, "{{")
		if openIdx < 0 {
			out.WriteString(rem)
			break
		}
		out.WriteString(rem[:openIdx])
		rem = rem[openIdx+2:]
		triple := false
		if strings.HasPrefix(rem, "{") {
			triple = true
			rem = rem[1:]
		}
		closeTok := "}}"
		if triple {
			closeTok = "}}}"
		}
		closeIdx := strings.Index(rem, closeTok)
		if closeIdx < 0 {
			return "", false
		}
		key := strings.TrimSpace(rem[:closeIdx])
		rem = rem[closeIdx+len(closeTok):]
		if key == "" {
			return "", false
		}
		val, ok := getIngestPath(doc, key)
		if !ok || val == nil {
			return "", false
		}
		valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
		if valStr == "" {
			return "", false
		}
		out.WriteString(valStr)
	}
	return out.String(), true
}

func executeRerouteProcessorRound58(doc map[string]any, specMap map[string]any) (bool, error) {
	ignoreMissing := true
	if im, ok := specMap["ignore_missing"].(bool); ok {
		ignoreMissing = im
	}
	prevIdx, _ := doc["_index"].(string)
	removeFieldsExplicit, hasRemoveFields := specMap["remove_fields"].(bool)
	rawDest, _ := specMap["destination"].(string)
	dest := ""
	if strings.TrimSpace(rawDest) != "" {
		if strings.Contains(rawDest, "{{") {
			rendered, okTpl := tryRenderMustacheStrict(rawDest, doc)
			if okTpl && strings.TrimSpace(rendered) != "" {
				dest = strings.TrimSpace(rendered)
			} else if !ignoreMissing {
				return false, fmt.Errorf("illegal_argument_exception: reroute destination template [%s] references missing or empty field", rawDest)
			}
		} else {
			dest = strings.TrimSpace(rawDest)
		}
	} else {
		dsType := "logs"
		if v, ok := getIngestPath(doc, "data_stream.type"); ok && v != nil {
			if sVal := strings.TrimSpace(fmt.Sprintf("%v", v)); sVal != "" {
				dsType = strings.ReplaceAll(sVal, "-", "_")
			}
		} else if curIdx, ok := doc["_index"].(string); ok && curIdx != "" {
			if dash := strings.IndexByte(curIdx, '-'); dash > 0 {
				dsType = curIdx[:dash]
			}
		}
		resolveReroutePart := func(rawSpec any, docPath string, defaultVal string) (string, error) {
			switch rv := rawSpec.(type) {
			case string:
				if rv != "" {
					if strings.Contains(rv, "{{") {
						if rendered, okTpl := tryRenderMustacheStrict(rv, doc); okTpl && strings.TrimSpace(rendered) != "" {
							return strings.ReplaceAll(strings.TrimSpace(rendered), "-", "_"), nil
						}
						if !ignoreMissing {
							return "", fmt.Errorf("illegal_argument_exception: reroute template [%s] references missing or empty field", rv)
						}
					} else {
						return strings.ReplaceAll(strings.TrimSpace(rv), "-", "_"), nil
					}
				}
			case []any:
				for _, item := range rv {
					sItem := strings.TrimSpace(fmt.Sprintf("%v", item))
					if sItem == "" {
						continue
					}
					if strings.Contains(sItem, "{{") {
						if rendered, okTpl := tryRenderMustacheStrict(sItem, doc); okTpl && strings.TrimSpace(rendered) != "" {
							return strings.ReplaceAll(strings.TrimSpace(rendered), "-", "_"), nil
						}
						continue
					}
					if v, ok := getIngestPath(doc, sItem); ok && v != nil {
						if vs := strings.TrimSpace(fmt.Sprintf("%v", v)); vs != "" {
							if hasRemoveFields && removeFieldsExplicit {
								deleteIngestPath(doc, sItem)
							}
							return strings.ReplaceAll(vs, "-", "_"), nil
						}
					}
				}
				if !ignoreMissing {
					return "", fmt.Errorf("illegal_argument_exception: reroute source field %v is missing or empty", rv)
				}
			}
			if v, ok := getIngestPath(doc, docPath); ok && v != nil {
				if sVal := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(fmt.Sprintf("%v", v), doc))); sVal != "" {
					if !hasRemoveFields || removeFieldsExplicit {
						deleteIngestPath(doc, docPath)
					}
					return strings.ReplaceAll(sVal, "-", "_"), nil
				}
			}
			if rawSpec == nil && !ignoreMissing {
				// Only fail on default docPath if neither dataset nor namespace was explicitly literal.
				if _, hasDS := specMap["dataset"]; !hasDS && docPath == "data_stream.dataset" {
					if _, hasNS := specMap["namespace"]; !hasNS {
						return "", fmt.Errorf("illegal_argument_exception: reroute field [%s] is missing", docPath)
					}
				}
			}
			return defaultVal, nil
		}
		dataset, err := resolveReroutePart(specMap["dataset"], "data_stream.dataset", "generic")
		if err != nil {
			return false, err
		}
		namespace, err := resolveReroutePart(specMap["namespace"], "data_stream.namespace", "default")
		if err != nil {
			return false, err
		}
		if dsObj, ok := getIngestPath(doc, "data_stream"); ok {
			if dsMap, isMap := dsObj.(map[string]any); isMap && len(dsMap) == 0 {
				deleteIngestPath(doc, "data_stream")
			}
		}
		dest = fmt.Sprintf("%s-%s-%s", dsType, dataset, namespace)
	}

	if dest != "" {
		doc["_index"] = dest
		if strings.TrimSpace(rawDest) != "" || dest != prevIdx {
			doc["__internal_ingest_rerouted"] = true
		}
		return true, nil
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Round 58 F3: _transform (pivot & latest) & _rollup Materialization + Search
// ---------------------------------------------------------------------------

type transformMaterializedDoc struct {
	ID     string
	Source map[string]any
}

func (s *Server) collectSourceDocsForJob(ctx context.Context, srcIndices []string, rawQuery any, runtimeMappings map[string]esast.FieldProperty) ([]map[string]any, error) {
	pattern := strings.Join(srcIndices, ",")
	if pattern == "" {
		return nil, nil
	}
	var parsedQuery *esast.Query
	if rawQuery != nil {
		if qBytes, err := json.Marshal(rawQuery); err == nil && len(qBytes) > 0 && string(qBytes) != "null" {
			var q esast.Query
			if err := json.Unmarshal(qBytes, &q); err == nil {
				parsedQuery = &q
			}
		}
	}
	fetchSize := 10000
	zero := 0
	sReq := &esast.SearchRequest{
		From:            &zero,
		Size:            &fetchSize,
		Query:           parsedQuery,
		RuntimeMappings: runtimeMappings,
		Sort: esast.SortSlice{
			{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
		},
	}
	resp, status, _, reason := s.executeSearchRequest(ctx, pattern, sReq)
	if status >= 400 && status != http.StatusNotFound {
		return nil, fmt.Errorf("source search failed (%d): %s", status, reason)
	}
	var docs []map[string]any
	hitsOuter, _ := resp["hits"].(map[string]any)
	appendHitMap := func(hm map[string]any) {
		if hm == nil {
			return
		}
		var docMap map[string]any
		switch src := hm["_source"].(type) {
		case json.RawMessage:
			_ = json.Unmarshal(src, &docMap)
		case []byte:
			_ = json.Unmarshal(src, &docMap)
		case string:
			_ = json.Unmarshal([]byte(src), &docMap)
		case map[string]any:
			rawBytes, _ := json.Marshal(src)
			_ = json.Unmarshal(rawBytes, &docMap)
		}
		if docMap != nil {
			docs = append(docs, docMap)
		}
	}
	switch hitsList := hitsOuter["hits"].(type) {
	case []map[string]any:
		for _, hm := range hitsList {
			appendHitMap(hm)
		}
	case []any:
		for _, rawHit := range hitsList {
			if hm, ok := rawHit.(map[string]any); ok {
				appendHitMap(hm)
			}
		}
	}
	return docs, nil
}

func extractTransformSourceIndices(srcMap map[string]any) []string {
	if srcMap == nil {
		return nil
	}
	switch iv := srcMap["index"].(type) {
	case string:
		if strings.TrimSpace(iv) != "" {
			return []string{strings.TrimSpace(iv)}
		}
	case []any:
		var out []string
		for _, item := range iv {
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return iv
	}
	return nil
}

func extractDocFieldValues(doc map[string]any, fieldPath string) []any {
	if doc == nil || fieldPath == "" {
		return nil
	}
	fieldPath = strings.TrimSuffix(fieldPath, ".keyword")
	var walk func(cur any, parts []string) []any
	walk = func(cur any, parts []string) []any {
		if cur == nil {
			return nil
		}
		if len(parts) == 0 {
			if sl, ok := cur.([]any); ok {
				var flat []any
				for _, elem := range sl {
					flat = append(flat, walk(elem, nil)...)
				}
				return flat
			}
			return []any{cur}
		}
		switch m := cur.(type) {
		case map[string]any:
			fullKey := strings.Join(parts, ".")
			if v, exists := m[fullKey]; exists {
				return walk(v, nil)
			}
			if v, exists := m[parts[0]]; exists {
				return walk(v, parts[1:])
			}
		case []any:
			var out []any
			for _, elem := range m {
				out = append(out, walk(elem, parts)...)
			}
			return out
		}
		return nil
	}
	return walk(doc, strings.Split(fieldPath, "."))
}

func parseAnyTimestampMillis(v any) (int64, bool) {
	switch tv := v.(type) {
	case float64:
		return int64(tv), true
	case int64:
		return tv, true
	case int:
		return int64(tv), true
	case json.Number:
		if i, err := tv.Int64(); err == nil {
			return i, true
		}
		if f, err := tv.Float64(); err == nil {
			return int64(f), true
		}
	case string:
		s := strings.TrimSpace(tv)
		if s == "" {
			return 0, false
		}
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000Z07:00",
			"2006-01-02T15:04:05.000",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, s); err == nil {
				return parsed.UTC().UnixMilli(), true
			}
		}
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func parseCalendarOrFixedIntervalMillis(spec map[string]any) int64 {
	raw := ""
	for _, k := range []string{"fixed_interval", "calendar_interval", "interval"} {
		if sv, ok := spec[k].(string); ok && strings.TrimSpace(sv) != "" {
			raw = strings.TrimSpace(sv)
			break
		}
	}
	if raw == "" {
		return 3600_000 // default 1h
	}
	if raw == "1M" {
		return 30 * 86400_000
	}
	switch strings.ToLower(raw) {
	case "minute", "1m":
		return 60_000
	case "hour", "1h":
		return 3600_000
	case "day", "1d":
		return 86400_000
	case "week", "1w":
		return 7 * 86400_000
	case "month":
		return 30 * 86400_000
	case "year", "1y":
		return 365 * 86400_000
	}
	if dur, err := parseESPositiveDuration(raw); err == nil && dur >= time.Millisecond {
		return dur.Milliseconds()
	}
	return 3600_000
}

func bucketDateMillis(ms int64, spec map[string]any) string {
	rawCal, _ := spec["calendar_interval"].(string)
	t := time.UnixMilli(ms).UTC()
	switch strings.TrimSpace(rawCal) {
	case "month", "1M":
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000Z")
	case "year", "1y":
		return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05.000Z")
	}
	iv := parseCalendarOrFixedIntervalMillis(spec)
	if iv <= 0 {
		iv = 3600_000
	}
	floored := ms - ((ms%iv)+iv)%iv
	return time.UnixMilli(floored).UTC().Format("2006-01-02T15:04:05.000Z")
}

func setNestedMapField(dst map[string]any, dotted string, val any) {
	parts := strings.Split(dotted, ".")
	cur := dst
	for i := 0; i < len(parts)-1; i++ {
		next, ok := cur[parts[i]].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[parts[i]] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = val
}

func deterministicBucketDocID(parts []string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\x1f"))) // #nosec G401 -- deterministic non-crypto bucket ID
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func compareAnyDocValues(a, b any) int {
	if tsa, oka := parseAnyTimestampMillis(a); oka {
		if tsb, okb := parseAnyTimestampMillis(b); okb {
			if tsa < tsb {
				return -1
			}
			if tsa > tsb {
				return 1
			}
			return 0
		}
	}
	fa, oka := toFloat64(a)
	fb, okb := toFloat64(b)
	if oka && okb {
		if fa < fb {
			return -1
		}
		if fa > fb {
			return 1
		}
		return 0
	}
	sa := fmt.Sprintf("%v", a)
	sb := fmt.Sprintf("%v", b)
	if sa < sb {
		return -1
	}
	if sa > sb {
		return 1
	}
	return 0
}

func (s *Server) materializeTransformConfig(ctx context.Context, cfg map[string]any) ([]transformMaterializedDoc, map[string]any, int, error) {
	srcMap, _ := cfg["source"].(map[string]any)
	srcIndices := extractTransformSourceIndices(srcMap)
	var srcQuery any
	if srcMap != nil {
		srcQuery = srcMap["query"]
	}
	docs, err := s.collectSourceDocsForJob(ctx, srcIndices, srcQuery, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	docsProcessed := len(docs)

	// Mode 1: latest transform (unique_key + sort)
	if latestCfg, ok := cfg["latest"].(map[string]any); ok && latestCfg != nil {
		var uniqueKeys []string
		switch uk := latestCfg["unique_key"].(type) {
		case string:
			if strings.TrimSpace(uk) != "" {
				uniqueKeys = []string{strings.TrimSpace(uk)}
			}
		case []any:
			for _, item := range uk {
				if ks := strings.TrimSpace(fmt.Sprintf("%v", item)); ks != "" {
					uniqueKeys = append(uniqueKeys, ks)
				}
			}
		}
		sortField, _ := latestCfg["sort"].(string)
		sortField = strings.TrimSpace(sortField)

		type latestGroup struct {
			keyParts []string
			bestDoc  map[string]any
			bestSort any
		}
		groups := make(map[string]*latestGroup)
		var groupOrder []string

		for _, doc := range docs {
			keyParts := make([]string, 0, len(uniqueKeys))
			missingKey := false
			for _, uk := range uniqueKeys {
				vals := extractDocFieldValues(doc, uk)
				if len(vals) == 0 || vals[0] == nil {
					missingKey = true
					break
				}
				keyParts = append(keyParts, fmt.Sprintf("%v", vals[0]))
			}
			if missingKey {
				continue
			}
			gKey := strings.Join(keyParts, "\x1f")
			var sVal any
			if sortField != "" {
				if sVals := extractDocFieldValues(doc, sortField); len(sVals) > 0 {
					sVal = sVals[0]
				}
			}
			existing, ok := groups[gKey]
			if !ok {
				groups[gKey] = &latestGroup{keyParts: keyParts, bestDoc: doc, bestSort: sVal}
				groupOrder = append(groupOrder, gKey)
			} else if sortField == "" || compareAnyDocValues(sVal, existing.bestSort) >= 0 {
				existing.bestDoc = doc
				existing.bestSort = sVal
			}
		}

		sort.Strings(groupOrder)
		out := make([]transformMaterializedDoc, 0, len(groupOrder))
		for _, gk := range groupOrder {
			grp := groups[gk]
			cpBytes, _ := json.Marshal(grp.bestDoc)
			var cpMap map[string]any
			_ = json.Unmarshal(cpBytes, &cpMap)
			out = append(out, transformMaterializedDoc{
				ID:     deterministicBucketDocID(grp.keyParts),
				Source: cpMap,
			})
		}

		inferredProps := map[string]any{}
		for _, srcIdx := range srcIndices {
			sc := s.getOrCompileReadOnlySchema(ctx, srcIdx)
			if sc != nil && sc.RawMapping != nil {
				rawB, _ := json.Marshal(sc.RawMapping.Properties)
				_ = json.Unmarshal(rawB, &inferredProps)
				break
			}
		}
		return out, inferredProps, docsProcessed, nil
	}

	// Mode 2: pivot transform (group_by + aggregations)
	pivotCfg, _ := cfg["pivot"].(map[string]any)
	if pivotCfg == nil {
		return []transformMaterializedDoc{}, map[string]any{}, docsProcessed, nil
	}
	groupByMap, _ := pivotCfg["group_by"].(map[string]any)
	aggsMap := map[string]any{}
	if a, ok := pivotCfg["aggregations"].(map[string]any); ok {
		aggsMap = a
	} else if a, ok := pivotCfg["aggs"].(map[string]any); ok {
		aggsMap = a
	}

	var groupNames []string
	for gn := range groupByMap {
		groupNames = append(groupNames, gn)
	}
	sort.Strings(groupNames)

	inferredProps := make(map[string]any)
	for _, gn := range groupNames {
		gSpec, _ := groupByMap[gn].(map[string]any)
		switch {
		case gSpec["date_histogram"] != nil:
			setNestedMapField(inferredProps, gn, map[string]any{"type": "date"})
		case gSpec["histogram"] != nil:
			setNestedMapField(inferredProps, gn, map[string]any{"type": "double"})
		default:
			setNestedMapField(inferredProps, gn, map[string]any{"type": "keyword"})
		}
	}
	var aggNames []string
	for an := range aggsMap {
		aggNames = append(aggNames, an)
	}
	sort.Strings(aggNames)
	for _, an := range aggNames {
		aSpec, _ := aggsMap[an].(map[string]any)
		switch {
		case aSpec["value_count"] != nil || aSpec["cardinality"] != nil:
			setNestedMapField(inferredProps, an, map[string]any{"type": "long"})
		case aSpec["stats"] != nil:
			setNestedMapField(inferredProps, an, map[string]any{
				"properties": map[string]any{
					"count": map[string]any{"type": "long"},
					"min":   map[string]any{"type": "double"},
					"max":   map[string]any{"type": "double"},
					"avg":   map[string]any{"type": "double"},
					"sum":   map[string]any{"type": "double"},
				},
			})
		case aSpec["sum"] != nil || aSpec["avg"] != nil || aSpec["min"] != nil || aSpec["max"] != nil || aSpec["weighted_avg"] != nil:
			setNestedMapField(inferredProps, an, map[string]any{"type": "double"})
		default:
			setNestedMapField(inferredProps, an, map[string]any{"type": "object"})
		}
	}

	type pivotBucket struct {
		keyValues  map[string]any
		keyStrings []string
		docs       []map[string]any
	}
	buckets := make(map[string]*pivotBucket)
	var bucketOrder []string

	for _, doc := range docs {
		type kvChoice struct {
			str string
			val any
		}
		choicesPerGroup := make([][]kvChoice, len(groupNames))
		skipDoc := false
		for gi, gn := range groupNames {
			gSpec, _ := groupByMap[gn].(map[string]any)
			var list []kvChoice
			if termsSpec, ok := gSpec["terms"].(map[string]any); ok {
				field, _ := termsSpec["field"].(string)
				vals := extractDocFieldValues(doc, field)
				if len(vals) == 0 {
					if mv, hasMissing := termsSpec["missing"]; hasMissing && mv != nil {
						vals = []any{mv}
					}
				}
				for _, v := range vals {
					if v != nil {
						list = append(list, kvChoice{str: fmt.Sprintf("%v", v), val: v})
					}
				}
			} else if histSpec, ok := gSpec["histogram"].(map[string]any); ok {
				field, _ := histSpec["field"].(string)
				iv, _ := toFloat64(histSpec["interval"])
				if iv <= 0 {
					iv = 1
				}
				for _, v := range extractDocFieldValues(doc, field) {
					if fv, okF := toFloat64(v); okF {
						bVal := math.Floor(fv/iv) * iv
						list = append(list, kvChoice{str: fmt.Sprintf("%g", bVal), val: bVal})
					}
				}
			} else if dhSpec, ok := gSpec["date_histogram"].(map[string]any); ok {
				field, _ := dhSpec["field"].(string)
				for _, v := range extractDocFieldValues(doc, field) {
					if ms, okTS := parseAnyTimestampMillis(v); okTS {
						iso := bucketDateMillis(ms, dhSpec)
						list = append(list, kvChoice{str: iso, val: iso})
					}
				}
			}
			if len(list) == 0 {
				skipDoc = true
				break
			}
			choicesPerGroup[gi] = list
		}
		if skipDoc {
			continue
		}

		// Expand Cartesian product across group_by fields (typically 1 choice per field).
		var expand func(idx int, curVals map[string]any, curStrs []string)
		expand = func(idx int, curVals map[string]any, curStrs []string) {
			if idx == len(groupNames) {
				bKey := strings.Join(curStrs, "\x1f")
				b, exists := buckets[bKey]
				if !exists {
					kvCopy := make(map[string]any, len(curVals))
					for k, v := range curVals {
						kvCopy[k] = v
					}
					ksCopy := append([]string(nil), curStrs...)
					b = &pivotBucket{keyValues: kvCopy, keyStrings: ksCopy}
					buckets[bKey] = b
					bucketOrder = append(bucketOrder, bKey)
				}
				b.docs = append(b.docs, doc)
				return
			}
			gn := groupNames[idx]
			for _, ch := range choicesPerGroup[idx] {
				curVals[gn] = ch.val
				expand(idx+1, curVals, append(curStrs, gn+"="+ch.str))
			}
		}
		expand(0, make(map[string]any, len(groupNames)), nil)
	}

	sort.Strings(bucketOrder)
	out := make([]transformMaterializedDoc, 0, len(bucketOrder))
	for _, bk := range bucketOrder {
		b := buckets[bk]
		row := make(map[string]any)
		for gn, gv := range b.keyValues {
			setNestedMapField(row, gn, gv)
		}
		for _, an := range aggNames {
			aSpec, _ := aggsMap[an].(map[string]any)
			val := computeTransformMetricAgg(b.docs, aSpec)
			setNestedMapField(row, an, val)
		}
		out = append(out, transformMaterializedDoc{
			ID:     deterministicBucketDocID(b.keyStrings),
			Source: row,
		})
	}
	return out, inferredProps, docsProcessed, nil
}

func computeTransformMetricAgg(docs []map[string]any, aSpec map[string]any) any {
	collectFloats := func(field string) []float64 {
		var nums []float64
		for _, d := range docs {
			for _, v := range extractDocFieldValues(d, field) {
				if fv, ok := toFloat64(v); ok {
					nums = append(nums, fv)
				}
			}
		}
		return nums
	}
	if sumSpec, ok := aSpec["sum"].(map[string]any); ok {
		field, _ := sumSpec["field"].(string)
		sum := 0.0
		for _, v := range collectFloats(field) {
			sum += v
		}
		return sum
	}
	if avgSpec, ok := aSpec["avg"].(map[string]any); ok {
		field, _ := avgSpec["field"].(string)
		nums := collectFloats(field)
		if len(nums) == 0 {
			return nil
		}
		sum := 0.0
		for _, v := range nums {
			sum += v
		}
		return sum / float64(len(nums))
	}
	if minSpec, ok := aSpec["min"].(map[string]any); ok {
		field, _ := minSpec["field"].(string)
		nums := collectFloats(field)
		if len(nums) == 0 {
			return nil
		}
		m := nums[0]
		for _, v := range nums[1:] {
			if v < m {
				m = v
			}
		}
		return m
	}
	if maxSpec, ok := aSpec["max"].(map[string]any); ok {
		field, _ := maxSpec["field"].(string)
		nums := collectFloats(field)
		if len(nums) == 0 {
			return nil
		}
		m := nums[0]
		for _, v := range nums[1:] {
			if v > m {
				m = v
			}
		}
		return m
	}
	if vcSpec, ok := aSpec["value_count"].(map[string]any); ok {
		field, _ := vcSpec["field"].(string)
		cnt := int64(0)
		for _, d := range docs {
			for _, v := range extractDocFieldValues(d, field) {
				if v != nil {
					cnt++
				}
			}
		}
		return cnt
	}
	if cardSpec, ok := aSpec["cardinality"].(map[string]any); ok {
		field, _ := cardSpec["field"].(string)
		uniq := make(map[string]bool)
		for _, d := range docs {
			for _, v := range extractDocFieldValues(d, field) {
				if v != nil {
					uniq[fmt.Sprintf("%v", v)] = true
				}
			}
		}
		return int64(len(uniq))
	}
	if statsSpec, ok := aSpec["stats"].(map[string]any); ok {
		field, _ := statsSpec["field"].(string)
		nums := collectFloats(field)
		if len(nums) == 0 {
			return map[string]any{"count": int64(0), "min": nil, "max": nil, "avg": nil, "sum": 0.0}
		}
		sum := 0.0
		mn, mx := nums[0], nums[0]
		for _, v := range nums {
			sum += v
			if v < mn {
				mn = v
			}
			if v > mx {
				mx = v
			}
		}
		return map[string]any{
			"count": int64(len(nums)),
			"min":   mn,
			"max":   mx,
			"avg":   sum / float64(len(nums)),
			"sum":   sum,
		}
	}
	if thSpec, ok := aSpec["top_hits"].(map[string]any); ok {
		size := 1
		if sz, okS := toFloat64(thSpec["size"]); okS && int(sz) > 0 {
			size = int(sz)
		}
		if size > len(docs) {
			size = len(docs)
		}
		outDocs := make([]any, 0, size)
		for i := 0; i < size; i++ {
			outDocs = append(outDocs, docs[i])
		}
		if size == 1 && len(outDocs) == 1 {
			return outDocs[0]
		}
		return outDocs
	}
	if latSpec, ok := aSpec["latest"].(map[string]any); ok {
		sortField, _ := latSpec["sort"].(string)
		var best map[string]any
		var bestVal any
		for _, d := range docs {
			var sv any
			if sortField != "" {
				if vals := extractDocFieldValues(d, sortField); len(vals) > 0 {
					sv = vals[0]
				}
			}
			if best == nil || (sortField != "" && compareAnyDocValues(sv, bestVal) >= 0) {
				best = d
				bestVal = sv
			}
		}
		return best
	}
	return int64(len(docs))
}

func (s *Server) executeTransformStartRound58(ctx context.Context, transformID string) error {
	s.mu.RLock()
	entry, exists := s.transforms[transformID]
	if !exists || entry == nil {
		s.mu.RUnlock()
		return fmt.Errorf("transform [%s] not found", transformID)
	}
	cfgBytes, _ := json.Marshal(entry)
	s.mu.RUnlock()

	var cfgCopy map[string]any
	_ = json.Unmarshal(cfgBytes, &cfgCopy)

	matDocs, inferredProps, docsProcessed, err := s.materializeTransformConfig(ctx, cfgCopy)
	if err != nil {
		return err
	}

	dstMap, _ := cfgCopy["dest"].(map[string]any)
	destIdx, _ := dstMap["index"].(string)
	destPipeline, _ := dstMap["pipeline"].(string)
	destIdx = strings.TrimSpace(destIdx)
	if destIdx == "" {
		return nil
	}

	var mappingSpec *esast.MappingSpec
	if len(inferredProps) > 0 {
		if rawM, errM := json.Marshal(map[string]any{"properties": inferredProps}); errM == nil {
			var ms esast.MappingSpec
			if json.Unmarshal(rawM, &ms) == nil {
				mappingSpec = &ms
			}
		}
	}

	sampleRaws := make([]json.RawMessage, 0, len(matDocs))
	type preparedDoc struct {
		id     string
		idx    string
		route  string
		rawSrc json.RawMessage
	}
	prepared := make([]preparedDoc, 0, len(matDocs))
	for _, md := range matDocs {
		rawDoc, errJ := json.Marshal(md.Source)
		if errJ != nil {
			continue
		}
		curRaw, curIdx, curID, curRoute, dropped, pErr := s.applyEffectiveAndFinalPipelinesWithRouting(destIdx, md.ID, destPipeline, "", "", rawDoc)
		if pErr != nil {
			return pErr
		}
		if dropped {
			continue
		}
		if curIdx == "" {
			curIdx = destIdx
		}
		if curID == "" {
			curID = md.ID
		}
		sampleRaws = append(sampleRaws, curRaw)
		prepared = append(prepared, preparedDoc{id: curID, idx: curIdx, route: curRoute, rawSrc: curRaw})
	}

	if mappingSpec != nil {
		s.mu.Lock()
		if _, exists := s.indices[destIdx]; !exists {
			compiled := schema.CompileIndexSchema(s.dorisDB, destIdx, mappingSpec)
			ddl := schema.GenerateCreateTableDDL(compiled)
			s.mu.Unlock()
			if err := s.backend.ExecDDL(ctx, ddl); err != nil {
				return err
			}
			s.mu.Lock()
			if _, exists2 := s.indices[destIdx]; !exists2 {
				s.indices[destIdx] = compiled
			}
			s.mu.Unlock()
			s.persistIndex(ctx, destIdx, compiled)
		} else {
			s.mu.Unlock()
		}
	}
	idxSchema := s.ensureWritableIndexSchemaWithDocs(ctx, destIdx, sampleRaws)

	var ndjson bytes.Buffer
	docsIndexed := 0
	for _, pd := range prepared {
		targetSchema := idxSchema
		if pd.idx != destIdx {
			targetSchema = s.ensureWritableIndexSchemaWithDocs(ctx, pd.idx, []json.RawMessage{pd.rawSrc})
		}
		ver := s.allocVersion(s.getDocVersion(pd.idx, pd.id) + 1)
		s.setDocVersion(pd.idx, pd.id, ver)
		rowBytes, sErr := schema.ShredDocument(targetSchema, pd.id, ver, false, pd.rawSrc)
		if sErr != nil {
			return sErr
		}
		if pd.idx == destIdx {
			ndjson.Write(rowBytes)
			ndjson.WriteByte('\n')
		} else {
			if lErr := s.streamLoad(ctx, targetSchema.DorisTable, append(rowBytes, '\n'), true); lErr != nil {
				return lErr
			}
		}
		if pd.route != "" {
			s.setDocRouting(pd.idx, pd.id, pd.route)
		}
		docsIndexed++
	}
	if ndjson.Len() > 0 {
		if err := s.streamLoad(ctx, idxSchema.DorisTable, ndjson.Bytes(), true); err != nil {
			return err
		}
	}
	s.queryCache.InvalidateAll()

	s.mu.Lock()
	if cur := s.transforms[transformID]; cur != nil {
		cur["state"] = "started"
		prevProc, _ := toFloat64(cur["documents_processed"])
		prevIdx, _ := toFloat64(cur["documents_indexed"])
		prevPages, _ := toFloat64(cur["pages_processed"])
		prevTrig, _ := toFloat64(cur["trigger_count"])
		cur["documents_processed"] = int64(prevProc) + int64(docsProcessed)
		cur["documents_indexed"] = int64(prevIdx) + int64(docsIndexed)
		cur["pages_processed"] = int64(prevPages) + 1
		cur["trigger_count"] = int64(prevTrig) + 1
	}
	s.mu.Unlock()
	return nil
}

// buildRollupCapabilitiesFields constructs ES GET /_rollup/data capabilities map
// from a rollup job configuration.
func buildRollupCapabilitiesFields(cfg map[string]any) map[string]any {
	fields := make(map[string]any)
	appendCap := func(field string, desc map[string]any) {
		field = strings.TrimSpace(field)
		if field == "" {
			return
		}
		list, _ := fields[field].([]any)
		fields[field] = append(list, desc)
	}
	if groups, ok := cfg["groups"].(map[string]any); ok {
		if dh, ok := groups["date_histogram"].(map[string]any); ok {
			f, _ := dh["field"].(string)
			iv := ""
			for _, k := range []string{"fixed_interval", "calendar_interval", "interval"} {
				if sv, okS := dh[k].(string); okS && sv != "" {
					iv = sv
					break
				}
			}
			if iv == "" {
				iv = "1h"
			}
			tz, _ := dh["time_zone"].(string)
			if tz == "" {
				tz = "UTC"
			}
			appendCap(f, map[string]any{
				"agg":               "date_histogram",
				"calendar_interval": iv,
				"fixed_interval":    iv,
				"time_zone":         tz,
			})
		}
		if hist, ok := groups["histogram"].(map[string]any); ok {
			iv := hist["interval"]
			if fs, okF := hist["fields"].([]any); okF {
				for _, rf := range fs {
					appendCap(fmt.Sprintf("%v", rf), map[string]any{"agg": "histogram", "interval": iv})
				}
			}
		}
		if terms, ok := groups["terms"].(map[string]any); ok {
			if fs, okF := terms["fields"].([]any); okF {
				for _, rf := range fs {
					appendCap(fmt.Sprintf("%v", rf), map[string]any{"agg": "terms"})
				}
			}
		}
	}
	if metrics, ok := cfg["metrics"].([]any); ok {
		for _, rm := range metrics {
			mm, okM := rm.(map[string]any)
			if !okM {
				continue
			}
			f, _ := mm["field"].(string)
			if mList, okL := mm["metrics"].([]any); okL {
				for _, mt := range mList {
					mName := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", mt)))
					if mName != "" {
						appendCap(f, map[string]any{"agg": mName})
					}
				}
			}
		}
	}
	return fields
}

func (s *Server) executeRollupStartRound58(ctx context.Context, jobID string) error {
	s.mu.RLock()
	jobEntry, exists := s.rollupJobs[jobID]
	if !exists || jobEntry == nil {
		s.mu.RUnlock()
		return fmt.Errorf("rollup job [%s] not found", jobID)
	}
	cfgBytes, _ := json.Marshal(jobEntry["config"])
	s.mu.RUnlock()

	var cfg map[string]any
	_ = json.Unmarshal(cfgBytes, &cfg)
	idxPattern, _ := cfg["index_pattern"].(string)
	rollupIdx, _ := cfg["rollup_index"].(string)
	idxPattern = strings.TrimSpace(idxPattern)
	rollupIdx = strings.TrimSpace(rollupIdx)
	if idxPattern == "" || rollupIdx == "" {
		return nil
	}

	srcTargets := s.resolveTargetIndices(idxPattern)
	var filteredSrc []string
	for _, t := range srcTargets {
		if t != rollupIdx {
			filteredSrc = append(filteredSrc, t)
		}
	}
	docs, err := s.collectSourceDocsForJob(ctx, filteredSrc, nil, nil)
	if err != nil {
		return err
	}

	groups, _ := cfg["groups"].(map[string]any)
	dhSpec, _ := groups["date_histogram"].(map[string]any)
	histSpec, _ := groups["histogram"].(map[string]any)
	termsSpec, _ := groups["terms"].(map[string]any)

	type groupDim struct {
		field string
		kind  string // "date_histogram", "histogram", "terms"
		spec  map[string]any
	}
	var dims []groupDim
	if dhSpec != nil {
		if f, _ := dhSpec["field"].(string); strings.TrimSpace(f) != "" {
			dims = append(dims, groupDim{field: strings.TrimSpace(f), kind: "date_histogram", spec: dhSpec})
		}
	}
	if histSpec != nil {
		if fs, ok := histSpec["fields"].([]any); ok {
			for _, rf := range fs {
				if f := strings.TrimSpace(fmt.Sprintf("%v", rf)); f != "" {
					dims = append(dims, groupDim{field: f, kind: "histogram", spec: histSpec})
				}
			}
		}
	}
	if termsSpec != nil {
		if fs, ok := termsSpec["fields"].([]any); ok {
			for _, rf := range fs {
				if f := strings.TrimSpace(fmt.Sprintf("%v", rf)); f != "" {
					dims = append(dims, groupDim{field: f, kind: "terms", spec: termsSpec})
				}
			}
		}
	}

	type metricSpec struct {
		field string
		aggs  map[string]bool
	}
	var metrics []metricSpec
	if rawMetrics, ok := cfg["metrics"].([]any); ok {
		for _, rm := range rawMetrics {
			mm, okM := rm.(map[string]any)
			if !okM {
				continue
			}
			f, _ := mm["field"].(string)
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			aSet := make(map[string]bool)
			if ml, okL := mm["metrics"].([]any); okL {
				for _, mt := range ml {
					aSet[strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", mt)))] = true
				}
			}
			metrics = append(metrics, metricSpec{field: f, aggs: aSet})
		}
	}

	type rollupBucket struct {
		dimVals    map[string]any
		dimKinds   map[string]string
		keyStrings []string
		docs       []map[string]any
	}
	buckets := make(map[string]*rollupBucket)
	var bucketOrder []string

	for _, doc := range docs {
		keyStrs := make([]string, 0, len(dims)+1)
		dimVals := make(map[string]any, len(dims))
		dimKinds := make(map[string]string, len(dims))
		skip := false
		for _, dim := range dims {
			vals := extractDocFieldValues(doc, dim.field)
			if len(vals) == 0 || vals[0] == nil {
				skip = true
				break
			}
			switch dim.kind {
			case "date_histogram":
				ms, okTS := parseAnyTimestampMillis(vals[0])
				if !okTS {
					skip = true
					break
				}
				iso := bucketDateMillis(ms, dim.spec)
				parsedT, _ := time.Parse("2006-01-02T15:04:05.000Z", iso)
				dimVals[dim.field] = parsedT.UTC().UnixMilli()
				dimKinds[dim.field] = "date_histogram"
				keyStrs = append(keyStrs, dim.field+"="+iso)
			case "histogram":
				fv, okF := toFloat64(vals[0])
				if !okF {
					skip = true
					break
				}
				iv, _ := toFloat64(dim.spec["interval"])
				if iv <= 0 {
					iv = 1
				}
				bVal := math.Floor(fv/iv) * iv
				dimVals[dim.field] = bVal
				dimKinds[dim.field] = "histogram"
				keyStrs = append(keyStrs, fmt.Sprintf("%s=%g", dim.field, bVal))
			default:
				sv := fmt.Sprintf("%v", vals[0])
				dimVals[dim.field] = vals[0]
				dimKinds[dim.field] = "terms"
				keyStrs = append(keyStrs, dim.field+"="+sv)
			}
			if skip {
				break
			}
		}
		if skip {
			continue
		}
		bKey := jobID + "\x1f" + strings.Join(keyStrs, "\x1f")
		b, exists := buckets[bKey]
		if !exists {
			b = &rollupBucket{dimVals: dimVals, dimKinds: dimKinds, keyStrings: append([]string{jobID}, keyStrs...)}
			buckets[bKey] = b
			bucketOrder = append(bucketOrder, bKey)
		}
		b.docs = append(b.docs, doc)
	}

	sort.Strings(bucketOrder)
	sampleRaws := make([]json.RawMessage, 0, len(bucketOrder))
	type rollupPrepared struct {
		id  string
		raw json.RawMessage
	}
	prepared := make([]rollupPrepared, 0, len(bucketOrder))
	for _, bk := range bucketOrder {
		b := buckets[bk]
		rollupDoc := map[string]any{
			"_rollup": map[string]any{
				"id":      jobID,
				"version": 2,
			},
		}
		for df, dv := range b.dimVals {
			kind := b.dimKinds[df]
			setNestedMapField(rollupDoc, df+"."+kind+"._count", int64(len(b.docs)))
			setNestedMapField(rollupDoc, df+"."+kind+".value", dv)
		}
		for _, ms := range metrics {
			var nums []float64
			valCount := int64(0)
			for _, d := range b.docs {
				for _, v := range extractDocFieldValues(d, ms.field) {
					if v != nil {
						valCount++
						if fv, okF := toFloat64(v); okF {
							nums = append(nums, fv)
						}
					}
				}
			}
			sum := 0.0
			var mn, mx float64
			for i, fv := range nums {
				sum += fv
				if i == 0 || fv < mn {
					mn = fv
				}
				if i == 0 || fv > mx {
					mx = fv
				}
			}
			if ms.aggs["min"] && len(nums) > 0 {
				setNestedMapField(rollupDoc, ms.field+".min.value", mn)
			}
			if ms.aggs["max"] && len(nums) > 0 {
				setNestedMapField(rollupDoc, ms.field+".max.value", mx)
			}
			if ms.aggs["sum"] {
				setNestedMapField(rollupDoc, ms.field+".sum.value", sum)
			}
			if ms.aggs["value_count"] {
				setNestedMapField(rollupDoc, ms.field+".value_count.value", valCount)
			}
			if ms.aggs["avg"] {
				setNestedMapField(rollupDoc, ms.field+".avg.value", sum)
				setNestedMapField(rollupDoc, ms.field+".avg._count", int64(len(nums)))
			}
		}
		sumHash := sha1.Sum([]byte(strings.Join(b.keyStrings, "\x1f"))) // #nosec G401 -- deterministic rollup doc ID
		docID := jobID + "$" + hex.EncodeToString(sumHash[:12])
		rawB, errM := json.Marshal(rollupDoc)
		if errM != nil {
			continue
		}
		sampleRaws = append(sampleRaws, rawB)
		prepared = append(prepared, rollupPrepared{id: docID, raw: rawB})
	}

	idxSchema := s.ensureWritableIndexSchemaWithDocs(ctx, rollupIdx, sampleRaws)
	if len(prepared) > 0 {
		var ndjson bytes.Buffer
		for _, rp := range prepared {
			ver := s.allocVersion(s.getDocVersion(rollupIdx, rp.id) + 1)
			s.setDocVersion(rollupIdx, rp.id, ver)
			rowB, sErr := schema.ShredDocument(idxSchema, rp.id, ver, false, rp.raw)
			if sErr != nil {
				return sErr
			}
			ndjson.Write(rowB)
			ndjson.WriteByte('\n')
		}
		if err := s.streamLoad(ctx, idxSchema.DorisTable, ndjson.Bytes(), true); err != nil {
			return err
		}
	}
	s.queryCache.InvalidateAll()

	s.mu.Lock()
	if cur := s.rollupJobs[jobID]; cur != nil {
		if st, ok := cur["status"].(map[string]any); ok {
			st["job_state"] = "started"
		}
		statsMap, _ := cur["stats"].(map[string]any)
		if statsMap == nil {
			statsMap = make(map[string]any)
			cur["stats"] = statsMap
		}
		prevDocs, _ := toFloat64(statsMap["documents_processed"])
		prevRollups, _ := toFloat64(statsMap["rollups_indexed"])
		prevPages, _ := toFloat64(statsMap["pages_processed"])
		prevTrig, _ := toFloat64(statsMap["trigger_count"])
		statsMap["documents_processed"] = int64(prevDocs) + int64(len(docs))
		statsMap["rollups_indexed"] = int64(prevRollups) + int64(len(prepared))
		statsMap["pages_processed"] = int64(prevPages) + 1
		statsMap["trigger_count"] = int64(prevTrig) + 1
	}
	s.mu.Unlock()
	return nil
}

// tryEvaluateRollupSearchAggs evaluates _rollup_search aggregations against
// materialized rollup bucket documents when targeting or covering a rollup_index.
func (s *Server) tryEvaluateRollupSearchAggs(ctx context.Context, rawIndex string, sReq *esast.SearchRequest) (map[string]any, bool) {
	if sReq == nil || len(sReq.EffectiveAggs()) == 0 {
		return nil, false
	}
	targets := s.resolveTargetIndices(rawIndex)
	s.mu.RLock()
	var rollupIndices []string
	seenRollup := make(map[string]bool)
	targetSet := make(map[string]bool, len(targets))
	for _, t := range targets {
		targetSet[t] = true
	}
	for _, job := range s.rollupJobs {
		cfg, _ := job["config"].(map[string]any)
		rIdx, _ := cfg["rollup_index"].(string)
		idxPat, _ := cfg["index_pattern"].(string)
		if rIdx == "" {
			continue
		}
		_, rExists := s.indices[rIdx]
		if !rExists {
			continue
		}
		if targetSet[rIdx] || matchMultiWildcardWithExclusions(rawIndex, rIdx) || (idxPat != "" && rawIndex == idxPat) {
			if !seenRollup[rIdx] {
				seenRollup[rIdx] = true
				rollupIndices = append(rollupIndices, rIdx)
			}
		}
	}
	s.mu.RUnlock()

	if len(rollupIndices) == 0 {
		return nil, false
	}
	// Check if rollupIndices actually contain _rollup bucket docs.
	docs, err := s.collectSourceDocsForJob(ctx, rollupIndices, nil, nil)
	if err != nil || len(docs) == 0 {
		return nil, false
	}
	var rollupDocs []map[string]any
	for _, d := range docs {
		if _, hasMeta := d["_rollup"]; hasMeta {
			if matchesRollupBucketQuery(d, sReq.Query) {
				rollupDocs = append(rollupDocs, d)
			}
		}
	}
	if len(rollupDocs) == 0 && len(docs) > 0 {
		hasAnyRollup := false
		for _, d := range docs {
			if _, ok := d["_rollup"]; ok {
				hasAnyRollup = true
				break
			}
		}
		if !hasAnyRollup {
			return nil, false
		}
	}

	aggsOut := evalRollupAggMap(rollupDocs, sReq.EffectiveAggs())
	return map[string]any{
		"took":      1,
		"timed_out": false,
		"_shards": map[string]any{
			"total":      len(rollupIndices),
			"successful": len(rollupIndices),
			"skipped":    0,
			"failed":     0,
		},
		"hits": map[string]any{
			"total": map[string]any{
				"value":    0,
				"relation": "eq",
			},
			"max_score": nil,
			"hits":      []any{},
		},
		"aggregations": aggsOut,
	}, true
}

func extractRollupDimValue(doc map[string]any, field string) (any, int64, bool) {
	field = strings.TrimSuffix(field, ".keyword")
	for _, kind := range []string{"terms", "date_histogram", "histogram"} {
		vals := extractDocFieldValues(doc, field+"."+kind+".value")
		if len(vals) > 0 && vals[0] != nil {
			cnt := int64(1)
			if cVals := extractDocFieldValues(doc, field+"."+kind+"._count"); len(cVals) > 0 {
				if cf, ok := toFloat64(cVals[0]); ok && int64(cf) > 0 {
					cnt = int64(cf)
				}
			}
			return vals[0], cnt, true
		}
	}
	return nil, 0, false
}

func matchesRollupBucketQuery(doc map[string]any, q *esast.Query) bool {
	if q == nil || q.MatchAll != nil {
		return true
	}
	if len(q.Term) > 0 {
		for f, tv := range q.Term {
			dv, _, ok := extractRollupDimValue(doc, f)
			if !ok || fmt.Sprintf("%v", dv) != fmt.Sprintf("%v", tv.Value) {
				return false
			}
		}
		return true
	}
	if q.Terms != nil && len(q.Terms.Fields) > 0 {
		for f, vals := range q.Terms.Fields {
			dv, _, ok := extractRollupDimValue(doc, f)
			if !ok {
				return false
			}
			dvStr := fmt.Sprintf("%v", dv)
			matched := false
			for _, v := range vals {
				if fmt.Sprintf("%v", v) == dvStr {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if !matchesRollupBucketQuery(doc, &q.Bool.Must[i]) {
				return false
			}
		}
		for i := range q.Bool.Filter {
			if !matchesRollupBucketQuery(doc, &q.Bool.Filter[i]) {
				return false
			}
		}
		for i := range q.Bool.MustNot {
			if matchesRollupBucketQuery(doc, &q.Bool.MustNot[i]) {
				return false
			}
		}
		if len(q.Bool.Should) > 0 {
			anyShould := false
			for i := range q.Bool.Should {
				if matchesRollupBucketQuery(doc, &q.Bool.Should[i]) {
					anyShould = true
					break
				}
			}
			if !anyShould {
				return false
			}
		}
	}
	return true
}

func evalRollupAggMap(docs []map[string]any, aggs map[string]esast.AggSpec) map[string]any {
	out := make(map[string]any, len(aggs))
	for name, spec := range aggs {
		switch {
		case spec.Sum != nil:
			f := strings.TrimSuffix(spec.Sum.Field, ".keyword")
			sum := 0.0
			for _, d := range docs {
				if vals := extractDocFieldValues(d, f+".sum.value"); len(vals) > 0 {
					if fv, ok := toFloat64(vals[0]); ok {
						sum += fv
					}
				}
			}
			out[name] = map[string]any{"value": sum}

		case spec.Min != nil:
			f := strings.TrimSuffix(spec.Min.Field, ".keyword")
			var mn *float64
			for _, d := range docs {
				if vals := extractDocFieldValues(d, f+".min.value"); len(vals) > 0 {
					if fv, ok := toFloat64(vals[0]); ok {
						if mn == nil || fv < *mn {
							v := fv
							mn = &v
						}
					}
				}
			}
			if mn == nil {
				out[name] = map[string]any{"value": nil}
			} else {
				out[name] = map[string]any{"value": *mn}
			}

		case spec.Max != nil:
			f := strings.TrimSuffix(spec.Max.Field, ".keyword")
			var mx *float64
			for _, d := range docs {
				if vals := extractDocFieldValues(d, f+".max.value"); len(vals) > 0 {
					if fv, ok := toFloat64(vals[0]); ok {
						if mx == nil || fv > *mx {
							v := fv
							mx = &v
						}
					}
				}
			}
			if mx == nil {
				out[name] = map[string]any{"value": nil}
			} else {
				out[name] = map[string]any{"value": *mx}
			}

		case spec.ValueCount != nil:
			f := strings.TrimSuffix(spec.ValueCount.Field, ".keyword")
			vc := int64(0)
			for _, d := range docs {
				if vals := extractDocFieldValues(d, f+".value_count.value"); len(vals) > 0 {
					if fv, ok := toFloat64(vals[0]); ok {
						vc += int64(fv)
					}
				}
			}
			out[name] = map[string]any{"value": vc}

		case spec.Avg != nil:
			f := strings.TrimSuffix(spec.Avg.Field, ".keyword")
			sum := 0.0
			cnt := int64(0)
			for _, d := range docs {
				sVals := extractDocFieldValues(d, f+".avg.value")
				cVals := extractDocFieldValues(d, f+".avg._count")
				if len(sVals) > 0 && len(cVals) > 0 {
					sf, ok1 := toFloat64(sVals[0])
					cf, ok2 := toFloat64(cVals[0])
					if ok1 && ok2 {
						sum += sf
						cnt += int64(cf)
					}
				}
			}
			if cnt == 0 {
				out[name] = map[string]any{"value": nil}
			} else {
				out[name] = map[string]any{"value": sum / float64(cnt)}
			}

		case spec.Terms != nil:
			type termGroup struct {
				key   any
				count int64
				docs  []map[string]any
			}
			groups := make(map[string]*termGroup)
			for _, d := range docs {
				dv, cnt, ok := extractRollupDimValue(d, spec.Terms.Field)
				if !ok {
					continue
				}
				ks := fmt.Sprintf("%v", dv)
				g := groups[ks]
				if g == nil {
					g = &termGroup{key: dv}
					groups[ks] = g
				}
				g.count += cnt
				g.docs = append(g.docs, d)
			}
			keys := make([]string, 0, len(groups))
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				gi, gj := groups[keys[i]], groups[keys[j]]
				if gi.count != gj.count {
					return gi.count > gj.count
				}
				return keys[i] < keys[j]
			})
			size := 10
			if spec.Terms.Size > 0 {
				size = spec.Terms.Size
			}
			if size > len(keys) {
				size = len(keys)
			}
			bList := make([]any, 0, size)
			for _, k := range keys[:size] {
				g := groups[k]
				bMap := map[string]any{
					"key":       g.key,
					"doc_count": g.count,
				}
				for subK, subV := range evalRollupAggMap(g.docs, spec.SubAggs()) {
					bMap[subK] = subV
				}
				bList = append(bList, bMap)
			}
			out[name] = map[string]any{
				"doc_count_error_upper_bound": 0,
				"sum_other_doc_count":         0,
				"buckets":                     bList,
			}

		case spec.DateHistogram != nil:
			dhMap := map[string]any{
				"fixed_interval":    spec.DateHistogram.FixedInterval,
				"calendar_interval": spec.DateHistogram.CalendarInterval,
				"interval":          spec.DateHistogram.Interval,
			}
			type dhGroup struct {
				iso   string
				ms    int64
				count int64
				docs  []map[string]any
			}
			groups := make(map[string]*dhGroup)
			for _, d := range docs {
				dv, cnt, ok := extractRollupDimValue(d, spec.DateHistogram.Field)
				if !ok {
					continue
				}
				ms, okTS := parseAnyTimestampMillis(dv)
				if !okTS {
					continue
				}
				iso := bucketDateMillis(ms, dhMap)
				parsedT, _ := time.Parse("2006-01-02T15:04:05.000Z", iso)
				g := groups[iso]
				if g == nil {
					g = &dhGroup{iso: iso, ms: parsedT.UTC().UnixMilli()}
					groups[iso] = g
				}
				g.count += cnt
				g.docs = append(g.docs, d)
			}
			keys := make([]string, 0, len(groups))
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			bList := make([]any, 0, len(keys))
			for _, k := range keys {
				g := groups[k]
				bMap := map[string]any{
					"key_as_string": g.iso,
					"key":           g.ms,
					"doc_count":     g.count,
				}
				for subK, subV := range evalRollupAggMap(g.docs, spec.SubAggs()) {
					bMap[subK] = subV
				}
				bList = append(bList, bMap)
			}
			out[name] = map[string]any{"buckets": bList}

		case spec.Histogram != nil:
			iv := spec.Histogram.Interval
			if iv <= 0 {
				iv = 1
			}
			type hGroup struct {
				key   float64
				count int64
				docs  []map[string]any
			}
			groups := make(map[float64]*hGroup)
			for _, d := range docs {
				dv, cnt, ok := extractRollupDimValue(d, spec.Histogram.Field)
				if !ok {
					continue
				}
				fv, okF := toFloat64(dv)
				if !okF {
					continue
				}
				bk := math.Floor(fv/iv) * iv
				g := groups[bk]
				if g == nil {
					g = &hGroup{key: bk}
					groups[bk] = g
				}
				g.count += cnt
				g.docs = append(g.docs, d)
			}
			keys := make([]float64, 0, len(groups))
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Float64s(keys)
			bList := make([]any, 0, len(keys))
			for _, k := range keys {
				g := groups[k]
				bMap := map[string]any{
					"key":       g.key,
					"doc_count": g.count,
				}
				for subK, subV := range evalRollupAggMap(g.docs, spec.SubAggs()) {
					bMap[subK] = subV
				}
				bList = append(bList, bMap)
			}
			out[name] = map[string]any{"buckets": bList}
		}
	}
	return out
}
