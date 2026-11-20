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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// Per-Server State for Round 61 CRUD / Indices / Scroll / Legacy Types / Admin
// ============================================================================

type scrollSessionStateR61CRUD struct {
	mu              sync.Mutex
	SessionNonce    uint64
	Index           string
	Req             esast.SearchRequest
	LastSort        []any
	Total           int64
	FetchedCount    int64
	Exhausted       bool
	MaxSeqNoByIndex map[string]int64
	Tokens          []string
	ExpiresAtMs     int64
	Cleared         bool
	EOFScrollID     string
}

type serverStateR61CRUD struct {
	mu                        sync.RWMutex
	legacyTemplateTypes       map[string]string
	legacyTemplateHasMappings map[string]bool
	scrollSessions            map[string]*scrollSessionStateR61CRUD
	openScrollList            []*scrollSessionStateR61CRUD
	pendingScrollTokens       map[string][]string
	testRemoteWhitelist       string
}

var (
	serverStateRegistryMuR61CRUD sync.RWMutex
	serverStateRegistryR61CRUD   = make(map[*Server]*serverStateR61CRUD)
)

func getOrCreateServerStateR61CRUD(s *Server) *serverStateR61CRUD {
	if s == nil {
		return &serverStateR61CRUD{
			legacyTemplateTypes:       make(map[string]string),
			legacyTemplateHasMappings: make(map[string]bool),
			scrollSessions:            make(map[string]*scrollSessionStateR61CRUD),
			pendingScrollTokens:       make(map[string][]string),
		}
	}
	serverStateRegistryMuR61CRUD.RLock()
	st := serverStateRegistryR61CRUD[s]
	serverStateRegistryMuR61CRUD.RUnlock()
	if st != nil {
		return st
	}
	serverStateRegistryMuR61CRUD.Lock()
	defer serverStateRegistryMuR61CRUD.Unlock()
	if st = serverStateRegistryR61CRUD[s]; st != nil {
		return st
	}
	st = &serverStateR61CRUD{
		legacyTemplateTypes:       make(map[string]string),
		legacyTemplateHasMappings: make(map[string]bool),
		scrollSessions:            make(map[string]*scrollSessionStateR61CRUD),
		pendingScrollTokens:       make(map[string][]string),
	}
	serverStateRegistryR61CRUD[s] = st
	return st
}

// SetRemoteReindexWhitelistForTest configures `reindex.remote.whitelist` on `s`
// for upstream conformance tests without polluting `GET /_cluster/settings` persistent settings (`F23`).
func (s *Server) SetRemoteReindexWhitelistForTest(pattern string) {
	if s == nil {
		return
	}
	st := getOrCreateServerStateR61CRUD(s)
	st.mu.Lock()
	st.testRemoteWhitelist = strings.TrimSpace(pattern)
	st.mu.Unlock()
}

// refreshFormatOptionsMultiFilterPathR61Admin upgrades `esFormatResponseWriter` options so
// repeated `?filter_path=a&filter_path=-b` query parameters compose across all endpoints (`F4`).
func refreshFormatOptionsMultiFilterPathR61Admin(w http.ResponseWriter, r *http.Request) {
	if fw, ok := w.(*esFormatResponseWriter); ok && fw != nil && r != nil {
		if opts, hasOpts := parseESResponseFormatOptionsRound61(r); hasOpts {
			fw.opts = opts
		}
	}
}

// formatESDurationR61Admin formats a `time.Duration` in Elasticsearch style (`5m` instead of `5m0s`).
func formatESDurationR61Admin(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", d/time.Second)
	}
	if d%time.Millisecond == 0 {
		return fmt.Sprintf("%dms", d/time.Millisecond)
	}
	if d%time.Microsecond == 0 {
		return fmt.Sprintf("%dmicros", d/time.Microsecond)
	}
	return fmt.Sprintf("%dns", d.Nanoseconds())
}

// effectiveTranspileOptsR61CRUD returns `s.transpileOpts` with `ES8Compat` populated from `s.isES8Mode(r)` (`F10`).
func (s *Server) effectiveTranspileOptsR61CRUD(r *http.Request) transpiler.TranspilerOptions {
	var opts transpiler.TranspilerOptions
	if s != nil {
		opts = s.transpileOpts
		opts.ES8Compat = s.isES8Mode(r)
		opts.LegacyFlatMatchScore = !s.hasExplicitTargetESVersion()
	} else {
		opts.ES8Compat = true
	}
	return opts
}

// ============================================================================
// F1: `GET /_capabilities` (ES 8 Endpoint Probe + Capabilities Map)
// ============================================================================

var unsupportedEndpointCapabilitiesR61Admin = map[string]bool{
	"lazy_rollover_failure_store":   true,
	"failure_store":                 true,
	"data_stream_failure_store":     true,
	"project_routing":               true,
	"serverless":                    true,
	"esql_async":                    true,
	"esql_enrich":                   true,
	"esql_lookup_join":              true,
	"retriever_rrf":                 true,
	"retriever_text_similarity":     true,
	"searchable_snapshots_shared":   true,
	"cross_cluster_replication_ilm": true,
}

var capabilitiesEndpointAllowedParamsR61Admin = map[string]bool{
	"method":       true,
	"path":         true,
	"parameters":   true,
	"capabilities": true,
	"pretty":       true,
	"human":        true,
	"error_trace":  true,
	"source":       true,
	"filter_path":  true,
	"opaque_id":    true,
}

func splitCSVTokensR61Admin(vals []string) []string {
	var out []string
	for _, raw := range vals {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func (s *Server) probeEndpointCapabilityR61Admin(method, rawPath string, params, caps []string) bool {
	for _, c := range caps {
		cLow := strings.ToLower(strings.TrimSpace(c))
		if unsupportedEndpointCapabilitiesR61Admin[cLow] {
			return false
		}
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = http.MethodGet
	}
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead:
	default:
		return false
	}

	p := strings.TrimSpace(rawPath)
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	if p == "/_capabilities" {
		if m != http.MethodGet && m != http.MethodPost && m != http.MethodHead {
			return false
		}
		for _, prm := range params {
			if !capabilitiesEndpointAllowedParamsR61Admin[prm] {
				return false
			}
		}
		return true
	}

	// Reject clearly unknown parameters when probing specific endpoints.
	for _, prm := range params {
		pLow := strings.ToLower(strings.TrimSpace(prm))
		if pLow == "unknown" || pLow == "nonexistent" || pLow == "invalid_param" || strings.HasPrefix(pLow, "unsupported_") {
			return false
		}
		if s.isES8Mode(nil) && pLow == "include_type_name" {
			return false
		}
	}
	return true
}

func (s *Server) handleCapabilitiesR61Admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	q := r.URL.Query()
	for k := range q {
		if !capabilitiesEndpointAllowedParamsR61Admin[k] {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [/_capabilities] contains unrecognized parameter: [%s]", k))
			return
		}
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	hasProbe := q.Has("path") || q.Has("method") || q.Has("parameters")
	var probeMethod, probePath string
	var probeParams, probeCaps []string
	if hasProbe {
		probeMethod = q.Get("method")
		probePath = q.Get("path")
		probeParams = splitCSVTokensR61Admin(q["parameters"])
		probeCaps = splitCSVTokensR61Admin(q["capabilities"])
	}
	if body != nil {
		if mv, ok := body["method"].(string); ok && mv != "" {
			hasProbe = true
			probeMethod = mv
		}
		if pv, ok := body["path"].(string); ok && pv != "" {
			hasProbe = true
			probePath = pv
		}
		if body["parameters"] != nil {
			hasProbe = true
			probeParams = append(probeParams, extractStringSliceAny(body["parameters"])...)
		}
		if body["capabilities"] != nil {
			probeCaps = append(probeCaps, extractStringSliceAny(body["capabilities"])...)
		}
	}

	if hasProbe {
		supported := s.probeEndpointCapabilityR61Admin(probeMethod, probePath, probeParams, probeCaps)
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"supported": supported,
		})
		return
	}

	// Non-probe mode: return full capabilities map + `"supported": true` for compatibility.
	defaultCapSpec := func() map[string]any {
		return map[string]any{"parameters": []string{}}
	}
	allCaps := map[string]any{
		"create_pit":             defaultCapSpec(),
		"search":                 map[string]any{"parameters": []string{"allow_no_indices", "ccs_minimize_roundtrips", "expand_wildcards", "ignore_throttled", "ignore_unavailable", "preference", "request_cache", "routing", "scroll", "search_type", "track_total_hits", "typed_keys"}},
		"knn":                    defaultCapSpec(),
		"sub_searches":           defaultCapSpec(),
		"retriever":              defaultCapSpec(),
		"esql":                   defaultCapSpec(),
		"eql":                    defaultCapSpec(),
		"sql":                    defaultCapSpec(),
		"ingest":                 defaultCapSpec(),
		"synonyms":               defaultCapSpec(),
		"query_rules":            defaultCapSpec(),
		"inference":              defaultCapSpec(),
		"connectors":             defaultCapSpec(),
		"search_application":     defaultCapSpec(),
		"security":               defaultCapSpec(),
		"fleet":                  defaultCapSpec(),
		"ml":                     defaultCapSpec(),
		"slm":                    defaultCapSpec(),
		"searchable_snapshots":   defaultCapSpec(),
		"rest_capabilities_api":  defaultCapSpec(),
		"field_capabilities_api": defaultCapSpec(),
	}
	requested := splitCSVTokensR61Admin(q["capabilities"])
	if body != nil {
		requested = append(requested, extractStringSliceAny(body["capabilities"])...)
	}
	outCaps := make(map[string]any)
	if len(requested) == 0 {
		outCaps = allCaps
	} else {
		for _, rc := range requested {
			if v, ok := allCaps[rc]; ok {
				outCaps[rc] = v
			}
		}
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"supported":    len(requested) == 0 || len(outCaps) == len(requested),
		"capabilities": outCaps,
	})
}

// handleResolveClusterCompatR61Admin preserves ES 8 `GET /_resolve/cluster/{index_expression}`
// while supporting bare remote-cluster alias wildcards (`GET /_resolve/cluster/rc_*`) when matching
// a configured remote cluster (`cluster.remote.<alias>.*`) and no local index/alias/data_stream.
func (s *Server) handleResolveClusterCompatR61Admin(w http.ResponseWriter, r *http.Request, rawPat string) {
	if s != nil {
		s.mu.RLock()
		remotes := make(map[string]bool)
		for alias := range s.remoteClusters {
			remotes[alias] = true
		}
		collectRemotes := func(settings map[string]any) {
			for k, v := range settings {
				if v != nil && strings.HasPrefix(k, "cluster.remote.") {
					rest := strings.TrimPrefix(k, "cluster.remote.")
					if dot := strings.IndexByte(rest, '.'); dot > 0 {
						remotes[rest[:dot]] = true
					}
				}
			}
			if clMap, ok := settings["cluster"].(map[string]any); ok {
				if remMap, ok := clMap["remote"].(map[string]any); ok {
					for alias, cfg := range remMap {
						if cfg != nil {
							remotes[alias] = true
						}
					}
				}
			}
		}
		collectRemotes(s.clusterPersistentSettings)
		collectRemotes(s.clusterTransientSettings)

		if len(remotes) > 0 {
			parts := strings.Split(rawPat, ",")
			changed := false
			for i, p := range parts {
				tok := strings.TrimSpace(p)
				if tok == "" || tok == "*" || tok == "_all" || strings.Contains(tok, ":") || strings.HasPrefix(tok, "-") {
					continue
				}
				matchedLocal := false
				for idxName := range s.indices {
					if matchWildcardPattern(tok, idxName) {
						matchedLocal = true
						break
					}
				}
				if !matchedLocal {
					for aliasName := range s.aliases {
						if matchWildcardPattern(tok, aliasName) {
							matchedLocal = true
							break
						}
					}
				}
				if !matchedLocal {
					for dsName := range s.dataStreams {
						if matchWildcardPattern(tok, dsName) {
							matchedLocal = true
							break
						}
					}
				}
				if !matchedLocal {
					for remAlias := range remotes {
						if matchWildcardPattern(tok, remAlias) {
							parts[i] = tok + ":*"
							changed = true
							break
						}
					}
				}
			}
			if changed {
				rawPat = strings.Join(parts, ",")
			}
		}
		s.mu.RUnlock()
	}
	r.SetPathValue("name", rawPat)
	s.handleResolveCluster(w, r)
}

// ============================================================================
// F4 & F9: `GET /_cluster/health` & `GET /_cluster/health/{index}`
// ============================================================================

var validClusterHealthQueryParamsR61Admin = map[string]bool{
	"level":                           true,
	"wait_for_status":                 true,
	"wait_for_no_relocating_shards":   true,
	"wait_for_no_initializing_shards": true,
	"wait_for_active_shards":          true,
	"wait_for_nodes":                  true,
	"wait_for_events":                 true,
	"timeout":                         true,
	"master_timeout":                  true,
	"local":                           true,
	"expand_wildcards":                true,
	"ignore_unavailable":              true,
	"allow_no_indices":                true,
	"pretty":                          true,
	"human":                           true,
	"error_trace":                     true,
	"source":                          true,
	"filter_path":                     true,
	"opaque_id":                       true,
}

func parseHealthDurationAllowZeroR61Admin(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" || trimmed == "0s" || trimmed == "0ms" || trimmed == "0m" || trimmed == "-1" {
		return nil
	}
	_, err := parseESPositiveDuration(trimmed)
	return err
}

func evalWaitForNodesCondR61Admin(expr string, actualNodes int) (bool, error) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return true, nil
	}
	parseNum := func(numStr string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(numStr))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("cannot parse wait_for_nodes value [%s]", expr)
		}
		return n, nil
	}
	switch {
	case strings.HasPrefix(s, ">="):
		n, err := parseNum(s[2:])
		return actualNodes >= n, err
	case strings.HasPrefix(s, "<="):
		n, err := parseNum(s[2:])
		return actualNodes <= n, err
	case strings.HasPrefix(s, ">"):
		n, err := parseNum(s[1:])
		return actualNodes > n, err
	case strings.HasPrefix(s, "<"):
		n, err := parseNum(s[1:])
		return actualNodes < n, err
	case strings.HasPrefix(s, "ge(") && strings.HasSuffix(s, ")"):
		n, err := parseNum(s[3 : len(s)-1])
		return actualNodes >= n, err
	case strings.HasPrefix(s, "le(") && strings.HasSuffix(s, ")"):
		n, err := parseNum(s[3 : len(s)-1])
		return actualNodes <= n, err
	case strings.HasPrefix(s, "gt(") && strings.HasSuffix(s, ")"):
		n, err := parseNum(s[3 : len(s)-1])
		return actualNodes > n, err
	case strings.HasPrefix(s, "lt(") && strings.HasSuffix(s, ")"):
		n, err := parseNum(s[3 : len(s)-1])
		return actualNodes < n, err
	case strings.HasPrefix(s, "eq(") && strings.HasSuffix(s, ")"):
		n, err := parseNum(s[3 : len(s)-1])
		return actualNodes == n, err
	default:
		n, err := parseNum(s)
		return actualNodes == n, err
	}
}

func healthStatusRankR61Admin(status string) int {
	switch status {
	case "green":
		return 2
	case "yellow":
		return 1
	default:
		return 0
	}
}

func (s *Server) handleClusterHealthR61Admin(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	reqPath := "/_cluster/health"
	if r != nil && r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	q := r.URL.Query()
	for k := range q {
		if !validClusterHealthQueryParamsR61Admin[k] {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [%s] contains unrecognized parameter: [%s]", reqPath, k))
			return
		}
	}

	level := "cluster"
	if q.Has("level") {
		lv := strings.ToLower(strings.TrimSpace(q.Get("level")))
		switch lv {
		case "cluster", "indices", "shards":
			level = lv
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("No enum constant org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest.Level.%s", strings.ToUpper(lv)))
			return
		}
	}

	waitForStatus := ""
	if q.Has("wait_for_status") {
		wfs := strings.ToLower(strings.TrimSpace(q.Get("wait_for_status")))
		switch wfs {
		case "green", "yellow", "red":
			waitForStatus = wfs
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("No enum constant org.elasticsearch.cluster.health.ClusterHealthStatus.%s", strings.ToUpper(wfs)))
			return
		}
	}

	if q.Has("wait_for_events") {
		wfe := strings.ToLower(strings.TrimSpace(q.Get("wait_for_events")))
		switch wfe {
		case "immediate", "urgent", "high", "normal", "low", "languid":
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("No enum constant org.elasticsearch.common.Priority.%s", strings.ToUpper(wfe)))
			return
		}
	}

	for _, boolKey := range []string{"wait_for_no_relocating_shards", "wait_for_no_initializing_shards", "local", "ignore_unavailable", "allow_no_indices"} {
		if q.Has(boolKey) {
			if _, _, err := parseStrictQueryBoolParamRound59(r, boolKey); err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
		}
	}

	for _, durKey := range []string{"timeout", "master_timeout"} {
		if q.Has(durKey) {
			if err := parseHealthDurationAllowZeroR61Admin(q.Get(durKey)); err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("failed to parse setting [%s] with value [%s] as a time value: %v", durKey, q.Get(durKey), err))
				return
			}
		}
	}

	waitForActiveAll := false
	waitForActiveTarget := -1
	if q.Has("wait_for_active_shards") {
		rawWFA := strings.ToLower(strings.TrimSpace(q.Get("wait_for_active_shards")))
		if rawWFA == "all" || rawWFA == "index-setting" {
			waitForActiveAll = rawWFA == "all"
		} else {
			n, err := strconv.Atoi(rawWFA)
			if err != nil || n < 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse value [%s] for [wait_for_active_shards]", q.Get("wait_for_active_shards")))
				return
			}
			waitForActiveTarget = n
		}
	}

	rawEW := strings.TrimSpace(q.Get("expand_wildcards"))
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

	numNodes := 1
	numDataNodes := 1
	if tb, ok := s.backend.(TelemetryBackend); ok && tb != nil {
		if tel := tb.CollectClusterTelemetry(r.Context(), s.dorisDB); tel != nil && tel.AliveNodes > 1 {
			numNodes = tel.AliveNodes
			numDataNodes = tel.AliveNodes
		}
	}

	nodesSatisfied := true
	if q.Has("wait_for_nodes") {
		okNodes, errNodes := evalWaitForNodesCondR61Admin(q.Get("wait_for_nodes"), numNodes)
		if errNodes != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", errNodes.Error())
			return
		}
		nodesSatisfied = okNodes
	}

	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))

	var targetIndices []string
	if rawIndex != "" && rawIndex != "_all" {
		if ewNone && (strings.ContainsAny(rawIndex, "*?") || rawIndex == "_all") {
			targetIndices = nil
		} else {
			s.mu.RLock()
			concreteMap := make(map[string]bool)
			for _, part := range strings.Split(rawIndex, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
					continue
				}
				concreteMap[part] = true
				for _, at := range s.aliases[part] {
					concreteMap[at] = true
				}
			}
			s.mu.RUnlock()

			resolved, _ := s.resolveTargetIndicesWithOptions(rawIndex, ewHidden)
			s.mu.RLock()
			for _, name := range resolved {
				if _, ok := s.indices[name]; !ok {
					continue
				}
				if !concreteMap[name] {
					if ewNone {
						continue
					}
					isClosed := s.closedIndices[name]
					if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
						continue
					}
					if (s.isIndexExplicitlyHiddenLocked(name) || strings.HasPrefix(name, ".")) && !ewHidden {
						continue
					}
				}
				targetIndices = append(targetIndices, name)
			}
			s.mu.RUnlock()
		}
	} else {
		if !ewNone {
			s.mu.RLock()
			for name := range s.indices {
				isClosed := s.closedIndices[name]
				if rawEW != "" {
					if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
						continue
					}
					if (s.isIndexExplicitlyHiddenLocked(name) || strings.HasPrefix(name, ".")) && !ewHidden {
						continue
					}
				}
				targetIndices = append(targetIndices, name)
			}
			s.mu.RUnlock()
		}
	}
	sort.Strings(targetIndices)

	backendHealthy := true
	if err := s.backend.Ping(r.Context()); err != nil {
		backendHealthy = false
	}

	totalPrimaryActive := 0
	totalActive := 0
	totalUnassigned := 0
	clusterStatus := "green"
	if !backendHealthy {
		clusterStatus = "red"
	}

	indicesHealthMap := make(map[string]any, len(targetIndices))
	for _, idxName := range targetIndices {
		numShards, numReplicas, _ := s.getIndexShardAndReplicaCounts(idxName)
		if numShards <= 0 {
			numShards = 1
		}
		if numReplicas < 0 {
			numReplicas = 0
		}
		idxPriActive := numShards
		if !backendHealthy {
			idxPriActive = 0
		}
		allocRepPerShard := 0
		if backendHealthy && numReplicas > 0 && numDataNodes > 1 {
			allocRepPerShard = numDataNodes - 1
			if allocRepPerShard > numReplicas {
				allocRepPerShard = numReplicas
			}
		}
		idxActive := idxPriActive + numShards*allocRepPerShard
		idxUnassigned := (numShards * (1 + numReplicas)) - idxActive

		idxStatus := "green"
		if !backendHealthy {
			idxStatus = "red"
		} else if idxUnassigned > 0 {
			idxStatus = "yellow"
		}
		if healthStatusRankR61Admin(idxStatus) < healthStatusRankR61Admin(clusterStatus) {
			clusterStatus = idxStatus
		}

		totalPrimaryActive += idxPriActive
		totalActive += idxActive
		totalUnassigned += idxUnassigned

		if level == "indices" || level == "shards" {
			idxEntry := map[string]any{
				"status":                idxStatus,
				"number_of_shards":      numShards,
				"number_of_replicas":    numReplicas,
				"active_primary_shards": idxPriActive,
				"active_shards":         idxActive,
				"relocating_shards":     0,
				"initializing_shards":   0,
				"unassigned_shards":     idxUnassigned,
			}
			if level == "shards" {
				shardsOut := make(map[string]any, numShards)
				for sh := 0; sh < numShards; sh++ {
					shActive := 0
					if backendHealthy {
						shActive = 1 + allocRepPerShard
					}
					shUnassigned := (1 + numReplicas) - shActive
					shStatus := "green"
					if !backendHealthy {
						shStatus = "red"
					} else if shUnassigned > 0 {
						shStatus = "yellow"
					}
					shardsOut[strconv.Itoa(sh)] = map[string]any{
						"status":              shStatus,
						"primary_active":      backendHealthy,
						"active_shards":       shActive,
						"relocating_shards":   0,
						"initializing_shards": 0,
						"unassigned_shards":   shUnassigned,
					}
				}
				idxEntry["shards"] = shardsOut
			}
			indicesHealthMap[idxName] = idxEntry
		}
	}

	timedOut := !nodesSatisfied ||
		(waitForActiveAll && totalUnassigned > 0) ||
		(waitForActiveTarget >= 0 && totalActive < waitForActiveTarget) ||
		(waitForStatus != "" && healthStatusRankR61Admin(clusterStatus) < healthStatusRankR61Admin(waitForStatus))

	httpCode := http.StatusOK
	if !backendHealthy && q.Get("local") == "false" {
		httpCode = http.StatusServiceUnavailable
	} else if timedOut {
		httpCode = http.StatusRequestTimeout
	}

	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(httpCode)
		return
	}

	activePct := 100.0
	if !backendHealthy && totalActive+totalUnassigned == 0 {
		activePct = 0.0
	} else if totalActive+totalUnassigned > 0 {
		activePct = (float64(totalActive) * 100.0) / float64(totalActive+totalUnassigned)
	}

	resp := map[string]any{
		"cluster_name":                     "apache-doris-search-cluster",
		"status":                           clusterStatus,
		"timed_out":                        timedOut,
		"number_of_nodes":                  numNodes,
		"number_of_data_nodes":             numDataNodes,
		"active_primary_shards":            totalPrimaryActive,
		"active_shards":                    totalActive,
		"relocating_shards":                0,
		"initializing_shards":              0,
		"unassigned_shards":                totalUnassigned,
		"delayed_unassigned_shards":        0,
		"number_of_pending_tasks":          0,
		"number_of_in_flight_fetch":        0,
		"task_max_waiting_in_queue_millis": 0,
		"active_shards_percent_as_number":  activePct,
	}
	if level == "indices" || level == "shards" {
		resp["indices"] = indicesHealthMap
	}
	writeJSONWithRequest(w, r, httpCode, resp)
}

// ============================================================================
// F5, F8, F14, F21, F26: Create Index, `include_type_name`, Mappings & TSDB
// ============================================================================

var reservedMappingRootKeysR61CRUD = map[string]bool{
	"properties":           true,
	"dynamic":              true,
	"dynamic_templates":    true,
	"_source":              true,
	"_size":                true,
	"_meta":                true,
	"_routing":             true,
	"_field_names":         true,
	"runtime":              true,
	"date_detection":       true,
	"numeric_detection":    true,
	"dynamic_date_formats": true,
	"subobjects":           true,
}

func effectiveIndexLegacyTypeR61CRUD(idx *schema.IndexSchema) string {
	if idx != nil && strings.TrimSpace(idx.LegacyTypeName) != "" {
		return strings.TrimSpace(idx.LegacyTypeName)
	}
	return "_doc"
}

func checkIncludeTypeNameParamR61CRUD(w http.ResponseWriter, s *Server, r *http.Request, opDesc string) (includeTypeName bool, hasParam bool, ok bool) {
	if r == nil || r.URL == nil || !r.URL.Query().Has("include_type_name") {
		return false, false, true
	}
	reqPath := r.URL.Path
	if reqPath == "" {
		reqPath = "/"
	}
	if s.isES8Mode(r) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("request [%s %s] contains unrecognized parameter: [include_type_name]", r.Method, reqPath))
		return false, true, false
	}
	bv, _, err := parseStrictQueryBoolParamRound59(r, "include_type_name")
	if err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
		return false, true, false
	}
	_ = opDesc
	return bv, true, true
}

func writeDuplicateIndexExistsErrorR61CRUD(w http.ResponseWriter, r *http.Request, indexName string) {
	uuid := catIndexUUID22(indexName)
	reason := fmt.Sprintf("index [%s/%s] already exists", indexName, uuid)
	cause := map[string]any{
		"type":       "resource_already_exists_exception",
		"reason":     reason,
		"index_uuid": uuid,
		"index":      indexName,
	}
	writeJSONWithRequest(w, r, http.StatusBadRequest, map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{cause},
			"type":       "resource_already_exists_exception",
			"reason":     reason,
			"index_uuid": uuid,
			"index":      indexName,
		},
		"status": http.StatusBadRequest,
	})
}

func unwrapTypeKeyedMappingsJSONR61CRUD(rawMappings any, includeTypeName bool) (unwrapped any, typeName string, hasExplicitMappings bool, errType string, errReason string) {
	if rawMappings == nil {
		return nil, "", false, "", ""
	}
	mMap, ok := rawMappings.(map[string]any)
	if !ok {
		return nil, "", true, "mapper_parsing_exception", "Expected map for mapping definition"
	}
	if len(mMap) == 0 {
		if includeTypeName {
			return map[string]any{}, "_doc", false, "", ""
		}
		return map[string]any{}, "", false, "", ""
	}
	if !includeTypeName {
		for k, v := range mMap {
			if _, isObj := v.(map[string]any); isObj && !reservedMappingRootKeysR61CRUD[k] {
				if k == "_doc" {
					return nil, "", true, "illegal_argument_exception",
						"The mapping definition cannot be nested under a type [_doc] unless include_type_name is set to true."
				}
				return nil, "", true, "mapper_parsing_exception",
					fmt.Sprintf("Root mapping definition has unsupported parameters:  [%s : %v]", k, v)
			}
		}
		return mMap, "_doc", true, "", ""
	}

	// includeTypeName == true
	for k := range mMap {
		if reservedMappingRootKeysR61CRUD[k] {
			return nil, "", true, "mapper_parsing_exception",
				fmt.Sprintf("Failed to parse mapping [%s]: Root mapping definition has unsupported parameters", k)
		}
	}
	if len(mMap) > 1 {
		keys := make([]string, 0, len(mMap))
		for k := range mMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return nil, "", true, "illegal_argument_exception",
			fmt.Sprintf("Rejecting mapping update as the final mapping would have more than 1 type: [%s]", strings.Join(keys, ", "))
	}
	for k, v := range mMap {
		if strings.TrimSpace(k) == "" {
			return nil, "", true, "illegal_argument_exception", "Type name cannot be empty"
		}
		if strings.HasPrefix(k, "_") && k != "_doc" {
			return nil, "", true, "invalid_type_name_exception",
				fmt.Sprintf("Document mapping type name can't start with '_', found: [%s]", k)
		}
		if v == nil {
			return map[string]any{}, k, true, "", ""
		}
		sub, okSub := v.(map[string]any)
		if !okSub {
			return nil, "", true, "mapper_parsing_exception",
				fmt.Sprintf("Expected map for type mapping [%s]", k)
		}
		return sub, k, true, "", ""
	}
	return map[string]any{}, "_doc", false, "", ""
}

func validateCreateIndexRootAndMappingsR61CRUD(bodyBytes []byte, includeTypeName bool) ([]byte, string, bool, string, string) {
	trimmed := bytes.TrimSpace(bodyBytes)
	if len(trimmed) == 0 {
		return bodyBytes, "", false, "", ""
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, "", false, "parsing_exception", err.Error()
	}
	var rawMappingsVal any
	hasMappingsKey := false
	for k, v := range root {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "settings", "mappings", "aliases":
			if strings.EqualFold(strings.TrimSpace(k), "mappings") {
				rawMappingsVal = v
				hasMappingsKey = true
			}
		default:
			return nil, "", false, "parsing_exception",
				fmt.Sprintf("Unknown key for a START_OBJECT in [%s].", k)
		}
	}
	if hasMappingsKey && rawMappingsVal != nil {
		if !includeTypeName {
			if mObj, okM := rawMappingsVal.(map[string]any); okM && mObj != nil {
				if nestedSettings, okS := mObj["settings"].(map[string]any); okS {
					topSettings, _ := root["settings"].(map[string]any)
					if topSettings == nil {
						topSettings = make(map[string]any)
					}
					for sk, sv := range nestedSettings {
						if _, exists := topSettings[sk]; !exists {
							topSettings[sk] = sv
						}
					}
					root["settings"] = topSettings
					mCopy := make(map[string]any, len(mObj))
					for mk, mv := range mObj {
						if mk != "settings" {
							mCopy[mk] = mv
						}
					}
					rawMappingsVal = mCopy
				}
			}
		}
		unwrapped, typeName, hasExplicit, errTp, errRsn := unwrapTypeKeyedMappingsJSONR61CRUD(rawMappingsVal, includeTypeName)
		if errTp != "" {
			return nil, "", false, errTp, errRsn
		}
		root["mappings"] = unwrapped
		rewritten, err := json.Marshal(root)
		if err != nil {
			return nil, "", false, "parsing_exception", err.Error()
		}
		return rewritten, typeName, hasExplicit, "", ""
	}
	return bodyBytes, "", false, "", ""
}

func (s *Server) matchingLegacyTemplateTypeLockedR61CRUD(indexName string) (typeName string, hasMappings bool) {
	st := getOrCreateServerStateR61CRUD(s)
	st.mu.RLock()
	defer st.mu.RUnlock()

	type matchedLegacy struct {
		name  string
		order int
	}
	var matches []matchedLegacy
	for tplName, tpl := range s.legacyTemplates {
		for _, pat := range tpl.EffectivePatterns() {
			if matchWildcardPattern(strings.TrimSpace(pat), indexName) {
				ord := 0
				if tpl.Order != nil {
					ord = *tpl.Order
				}
				matches = append(matches, matchedLegacy{name: tplName, order: ord})
				break
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].order != matches[j].order {
			return matches[i].order < matches[j].order
		}
		return matches[i].name < matches[j].name
	})
	for _, m := range matches {
		if st.legacyTemplateHasMappings[m.name] {
			hasMappings = true
			if tn := st.legacyTemplateTypes[m.name]; tn != "" {
				typeName = tn
			} else {
				typeName = "_doc"
			}
		}
	}
	return typeName, hasMappings
}

func validateTSDBSyntheticTextFieldsR61CRUD(m *esast.MappingSpec) error {
	if m == nil {
		return nil
	}
	var walk func(props map[string]esast.FieldProperty, prefix string) error
	walk = func(props map[string]esast.FieldProperty, prefix string) error {
		for k, prop := range props {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			fType := strings.ToLower(strings.TrimSpace(prop.Type))
			if fType == "text" {
				stored := prop.Store != nil && *prop.Store
				hasKWSub := false
				for _, sf := range prop.Fields {
					sft := strings.ToLower(strings.TrimSpace(sf.Type))
					if sft == "keyword" && sf.Normalizer == "" && ((sf.DocValues == nil || *sf.DocValues) || (sf.Store != nil && *sf.Store)) {
						hasKWSub = true
						break
					}
				}
				if !stored && !hasKWSub && (prop.Store != nil && !*prop.Store || strings.EqualFold(prop.SyntheticSourceKeep, "none")) {
					return fmt.Errorf(
						"illegal_argument_exception: field [%s] of type [text] doesn't support synthetic source unless it is stored or has a sub-field of type [keyword] with doc values or stored and without a normalizer",
						full,
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
	return walk(m.Properties, "")
}

func splitSchemaErrorPrefixR61CRUD(err error, fallbackType string) (string, string) {
	if err == nil {
		return fallbackType, ""
	}
	msg := err.Error()
	for _, pfx := range []string{"illegal_argument_exception: ", "mapper_parsing_exception: ", "parsing_exception: ", "script_exception: "} {
		if strings.HasPrefix(msg, pfx) {
			return strings.TrimSuffix(pfx, ": "), strings.TrimPrefix(msg, pfx)
		}
	}
	if strings.Contains(msg, "Cycle detected") || strings.Contains(msg, "compile error") {
		return "illegal_argument_exception", msg
	}
	return fallbackType, msg
}

func validateAliasNoRoutingOnTSDBR61CRUD(meta AliasMetadata) error {
	if strings.TrimSpace(meta.Routing) != "" || strings.TrimSpace(meta.IndexRouting) != "" || strings.TrimSpace(meta.SearchRouting) != "" {
		return fmt.Errorf("routing is forbidden on CRUD operations that target indices in [index.mode=time_series]")
	}
	return nil
}

// interceptIndexTemplateTypesR61CRUD handles ES 8 `include_type_name` rejection and ES 7
// `/_template` `include_type_name` warning + type-wrapper unwrapping/wrapping (`F5`).
func (s *Server) interceptIndexTemplateTypesR61CRUD(w http.ResponseWriter, r *http.Request, name string) bool {
	trimmedPath := strings.Trim(r.URL.Path, "/")
	isLegacyEndpoint := trimmedPath == "_template" || strings.HasPrefix(trimmedPath, "_template/")
	incType, hasIncParam, ok := checkIncludeTypeNameParamR61CRUD(w, s, r, "index template")
	if !ok {
		return true
	}
	if !isLegacyEndpoint {
		return false
	}
	st := getOrCreateServerStateR61CRUD(s)

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		bodyBytes, readOK := readRequestBody(w, r)
		if !readOK {
			return true
		}
		normBytes := normalizeTemplateBodyIndexPatternsRound60(bodyBytes)
		recordedType := ""
		hasMappings := false
		if len(bytes.TrimSpace(normBytes)) > 0 {
			var rawTplMap map[string]any
			if err := json.Unmarshal(normBytes, &rawTplMap); err == nil && rawTplMap != nil {
				if rawMappings, exists := rawTplMap["mappings"]; exists && rawMappings != nil {
					unwrapped, tName, hadExp, errTp, errRsn := unwrapTypeKeyedMappingsJSONR61CRUD(rawMappings, incType)
					if errTp != "" {
						writeESError(w, http.StatusBadRequest, errTp, errRsn)
						return true
					}
					hasMappings = hadExp
					recordedType = tName
					rawTplMap["mappings"] = unwrapped
					if rewritten, mErr := json.Marshal(rawTplMap); mErr == nil {
						bodyBytes = rewritten
					}
				}
			}
		}
		// Restore r.Body (without include_type_name=true double-unwrapping in Round58).
		rClone := r.Clone(r.Context())
		if incType && rClone.URL != nil {
			uCopy := *rClone.URL
			qCopy := uCopy.Query()
			qCopy.Del("include_type_name")
			uCopy.RawQuery = qCopy.Encode()
			rClone.URL = &uCopy
		}
		rClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		rClone.ContentLength = int64(len(bodyBytes))

		rec := httptest.NewRecorder()
		s.handleComposableOrLegacyTemplateRound58(rec, rClone, name)
		res := rec.Result()
		defer func() { _ = res.Body.Close() }()
		respBytes, _ := io.ReadAll(res.Body)
		if res.StatusCode >= 200 && res.StatusCode < 300 && name != "" {
			st.mu.Lock()
			st.legacyTemplateHasMappings[name] = hasMappings
			if recordedType != "" {
				st.legacyTemplateTypes[name] = recordedType
			} else {
				st.legacyTemplateTypes[name] = "_doc"
			}
			st.mu.Unlock()
		}
		for hk, hvs := range res.Header {
			if strings.EqualFold(hk, "Warning") {
				for _, hv := range hvs {
					w.Header().Add("Warning", hv)
				}
				continue
			}
			for _, hv := range hvs {
				w.Header().Set(hk, hv)
			}
		}
		w.WriteHeader(res.StatusCode)
		// #nosec G705 -- JSON response proxied from internal template handler with nosniff/JSON Content-Type
		_, _ = w.Write(respBytes)
		return true

	case http.MethodGet:
		if !hasIncParam || !incType {
			return false
		}
		rec := httptest.NewRecorder()
		s.handleComposableOrLegacyTemplateRound58(rec, r, name)
		res := rec.Result()
		defer func() { _ = res.Body.Close() }()
		respBytes, _ := io.ReadAll(res.Body)
		if res.StatusCode == http.StatusOK {
			var outMap map[string]any
			if json.Unmarshal(respBytes, &outMap) == nil && outMap != nil {
				st.mu.RLock()
				for tplName, rawEntry := range outMap {
					if entryMap, okE := rawEntry.(map[string]any); okE {
						tn := st.legacyTemplateTypes[tplName]
						if tn == "" {
							tn = "_doc"
						}
						if mVal, okM := entryMap["mappings"].(map[string]any); okM {
							if len(mVal) == 0 && !st.legacyTemplateHasMappings[tplName] {
								entryMap["mappings"] = map[string]any{}
							} else {
								entryMap["mappings"] = map[string]any{tn: mVal}
							}
						}
					}
				}
				st.mu.RUnlock()
				writeJSONWithRequest(w, r, http.StatusOK, outMap)
				return true
			}
		}
		copyRecorderHeadersSetR63(w, res.Header)
		w.WriteHeader(res.StatusCode)
		// #nosec G705 -- JSON error response proxied from internal template handler
		_, _ = w.Write(respBytes)
		return true

	case http.MethodDelete:
		if name != "" {
			st.mu.Lock()
			delete(st.legacyTemplateTypes, name)
			delete(st.legacyTemplateHasMappings, name)
			st.mu.Unlock()
		}
		return false
	}
	return false
}

func wrapMappingsResponseForTypeR61CRUD(idx *schema.IndexSchema, mappings map[string]any, includeTypeName bool, pathType string) map[string]any {
	if mappings == nil {
		mappings = map[string]any{}
	}
	typeName := effectiveIndexLegacyTypeR61CRUD(idx)
	if pathType != "" {
		matched := false
		for _, pt := range strings.Split(pathType, ",") {
			pt = strings.TrimSpace(pt)
			if pt == "_all" || pt == "*" || matchWildcardPattern(pt, typeName) {
				matched = true
				break
			}
		}
		if !matched {
			return map[string]any{}
		}
	}
	if includeTypeName || pathType != "" {
		if len(mappings) == 0 && idx != nil && idx.RawMapping == nil && idx.LegacyTypeName == "" {
			return map[string]any{}
		}
		return map[string]any{typeName: mappings}
	}
	return mappings
}

func recordNewPutMappingFieldsSeqNoR61CRUD(oldSchema, newSchema *schema.IndexSchema, nextSeqNo int64) {
	if newSchema == nil || oldSchema == nil || nextSeqNo <= 0 {
		return
	}
	if newSchema.FieldAddedAtSeqNo == nil {
		newSchema.FieldAddedAtSeqNo = make(map[string]int64)
	}
	for k, v := range oldSchema.FieldAddedAtSeqNo {
		newSchema.FieldAddedAtSeqNo[k] = v
	}
	for fPath := range newSchema.Fields {
		if _, existed := oldSchema.Fields[fPath]; !existed {
			if _, hasRec := newSchema.FieldAddedAtSeqNo[fPath]; !hasRec {
				newSchema.FieldAddedAtSeqNo[fPath] = nextSeqNo
			}
		}
	}
}

// buildMetadataFieldMappingDefR61CRUD builds the field-mapping entry for ES metadata fields
// (`_id`, `_source`, `_routing`, `_index`, `_field_names`, `_ignored`, and `_type` in ES 7).
func buildMetadataFieldMappingDefR61CRUD(metaField string, idx *schema.IndexSchema, isES8, includeDefaults bool) (map[string]any, bool) {
	switch metaField {
	case "_id":
		return map[string]any{"_id": map[string]any{}}, true
	case "_index":
		return map[string]any{"_index": map[string]any{"enabled": false}}, true
	case "_source":
		srcCfg := map[string]any{"enabled": !idx.SourceDisabled()}
		if idx != nil && idx.SyntheticSource {
			srcCfg["mode"] = "synthetic"
		}
		inc, exc := idx.SourceIncludesExcludes()
		if len(inc) > 0 || includeDefaults {
			if inc == nil {
				inc = []string{}
			}
			srcCfg["includes"] = inc
		}
		if len(exc) > 0 || includeDefaults {
			if exc == nil {
				exc = []string{}
			}
			srcCfg["excludes"] = exc
		}
		return map[string]any{"_source": srcCfg}, true
	case "_routing":
		req := false
		if idx != nil && idx.RawMapping != nil && idx.RawMapping.Routing != nil {
			req = idx.RawMapping.Routing.Required
		}
		return map[string]any{"_routing": map[string]any{"required": req}}, true
	case "_field_names":
		return map[string]any{"_field_names": map[string]any{"enabled": true}}, true
	case "_ignored":
		return map[string]any{"_ignored": map[string]any{"enabled": true}}, true
	case "_type":
		if isES8 {
			return nil, false
		}
		return map[string]any{"_type": map[string]any{}}, true
	default:
		return nil, false
	}
}

func (s *Server) handleGetFieldMappingR61CRUD(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	isES8 := s.isES8Mode(r)
	pathType := strings.TrimSpace(r.PathValue("type"))
	if isES8 && pathType != "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Types cannot be provided in get_field_mapping requests, got [%s]", pathType))
		return
	}
	if r.URL.Query().Has("local") {
		if isES8 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [%s] contains unrecognized parameter: [local]", r.URL.Path))
			return
		}
		emitESDeprecationWarningRound61(w, s, r,
			"Use [local] in get field mapping requests is deprecated. The parameter will be removed in the next major version")
	}
	incType, _, okInc := checkIncludeTypeNameParamR61CRUD(w, s, r, "get field mapping")
	if !okInc {
		return
	}
	if !isES8 && pathType != "" && !r.URL.Query().Has("include_type_name") {
		incType = true
	}

	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var targets []string
	if rawIndex != "" {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	} else {
		ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
		if ewErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
			return
		}
		if !ewNone {
			allTargets, _ := s.resolveTargetIndicesWithOptions("", ewHidden)
			for _, t := range allTargets {
				isClosed := s.isIndexClosed(t)
				if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
					continue
				}
				targets = append(targets, t)
			}
		}
	}

	rawFields := r.PathValue("fields")
	if rawFields == "" {
		rawFields = "*"
	}
	fieldPatterns := strings.Split(rawFields, ",")
	includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")

	metaCandidates := []string{"_id", "_source", "_routing", "_index", "_field_names", "_ignored"}
	if !isES8 {
		metaCandidates = append(metaCandidates, "_type")
	}

	s.mu.RLock()
	out := make(map[string]any, len(targets))
	anyTypeMatched := false
	for _, idxName := range targets {
		idxSchema, ok := s.indices[idxName]
		if !ok {
			continue
		}
		idxType := effectiveIndexLegacyTypeR61CRUD(idxSchema)
		if pathType != "" {
			hasIndexType := idxSchema.LegacyTypeName != "" || idxSchema.RawMapping != nil || len(idxSchema.Fields) > 0
			typeMatched := false
			if hasIndexType {
				for _, pt := range strings.Split(pathType, ",") {
					pt = strings.TrimSpace(pt)
					if pt == "_all" || pt == "*" || matchWildcardPattern(pt, idxType) {
						typeMatched = true
						break
					}
				}
			}
			if !typeMatched {
				continue
			}
			anyTypeMatched = true
		}

		augSchema := s.augmentSchemaWithRuntimeMappings(idxSchema, nil)
		mappingsOut := make(map[string]any)

		// Metadata fields (`_id`, `_source`, `_routing`, `_index`, `_field_names`, `_ignored`, `_type`).
		for _, mf := range metaCandidates {
			explicitMetaMatch := false
			for _, pat := range fieldPatterns {
				pat = strings.TrimSpace(pat)
				if pat == mf || (strings.HasPrefix(pat, "_") && matchWildcardPattern(pat, mf)) {
					explicitMetaMatch = true
					break
				}
			}
			if explicitMetaMatch {
				if metaMap, okM := buildMetadataFieldMappingDefR61CRUD(mf, idxSchema, isES8, includeDefaults); okM {
					mappingsOut[mf] = map[string]any{
						"full_name": mf,
						"mapping":   metaMap,
					}
				}
			}
		}

		for esPath, fb := range augSchema.Fields {
			if matchesFieldCapsPatterns(esPath, fieldPatterns) {
				esType := fb.ESType
				if esType == "" {
					esType = "keyword"
					switch fb.DorisType {
					case schema.DorisLargeInt:
						esType = "unsigned_long"
					case schema.DorisBigInt:
						if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
							esType = "date"
						} else {
							esType = "long"
						}
					case schema.DorisDouble:
						esType = "double"
					case schema.DorisBoolean:
						esType = "boolean"
					case schema.DorisString:
						esType = "text"
					}
				}
				lastSeg := esPath
				if dot := strings.LastIndexByte(esPath, '.'); dot >= 0 {
					lastSeg = esPath[dot+1:]
				}
				fieldDef := map[string]any{"type": esType}
				if fb.AliasTarget != "" {
					fieldDef["type"] = "alias"
					fieldDef["path"] = fb.AliasTarget
				}
				applyFieldMappingEntryRound60(fieldDef, fb, includeDefaults)
				if includeDefaults && esType == "text" && fb.AliasTarget == "" && fieldDef["analyzer"] == nil {
					fieldDef["analyzer"] = "default"
				}
				mappingsOut[esPath] = map[string]any{
					"full_name": esPath,
					"mapping": map[string]any{
						lastSeg: fieldDef,
					},
				}
			}
			if fb.KeywordCompanion != "" && fb.AliasTarget == "" {
				kwPath := esPath + ".keyword"
				if _, explicitKW := augSchema.Fields[kwPath]; !explicitKW && matchesFieldCapsPatterns(kwPath, fieldPatterns) {
					kwDef := map[string]any{"type": "keyword"}
					applyFieldMappingEntryRound60(kwDef, schema.FieldBinding{ESType: "keyword", IgnoreAbove: 256}, includeDefaults)
					mappingsOut[kwPath] = map[string]any{
						"full_name": kwPath,
						"mapping": map[string]any{
							"keyword": kwDef,
						},
					}
				}
			}
			if fb.ESType == "search_as_you_type" && fb.AliasTarget == "" {
				for _, suffix := range searchAsYouTypeSubfieldsRound58(fb) {
					subPath := esPath + suffix
					subName := strings.TrimPrefix(suffix, ".")
					if _, explicitSub := augSchema.Fields[subPath]; !explicitSub && matchesFieldCapsPatterns(subPath, fieldPatterns) {
						subDef := map[string]any{"type": "search_as_you_type"}
						applyFieldMappingEntryRound60(subDef, schema.FieldBinding{ESType: "search_as_you_type"}, includeDefaults)
						mappingsOut[subPath] = map[string]any{
							"full_name": subPath,
							"mapping": map[string]any{
								subName: subDef,
							},
						}
					}
				}
			}
		}
		if matchesFieldCapsPatterns("@timestamp", fieldPatterns) && mappingsOut["@timestamp"] == nil && s.isDataStreamOrBackingIndexLocked(idxName) {
			tsDef := map[string]any{"type": "date"}
			applyFieldMappingEntryRound60(tsDef, schema.FieldBinding{ESType: "date"}, includeDefaults)
			mappingsOut["@timestamp"] = map[string]any{
				"full_name": "@timestamp",
				"mapping": map[string]any{
					"@timestamp": tsDef,
				},
			}
		}

		if incType {
			if len(mappingsOut) > 0 {
				out[idxName] = map[string]any{"mappings": map[string]any{idxType: mappingsOut}}
			}
		} else {
			out[idxName] = map[string]any{"mappings": mappingsOut}
		}
	}
	s.mu.RUnlock()

	if pathType != "" && !anyTypeMatched && pathType != "_all" && pathType != "*" {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeESError(w, http.StatusNotFound, "type_missing_exception", fmt.Sprintf("type[[%s]] missing", pathType))
		return
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, out)
}

func validateNonEmptyPropertyNamesR61CRUD(m *esast.MappingSpec) error {
	if m == nil {
		return nil
	}
	var walk func(props map[string]esast.FieldProperty) error
	walk = func(props map[string]esast.FieldProperty) error {
		for k, p := range props {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("illegal_argument_exception: Field name cannot be an empty string")
			}
			if len(p.Properties) > 0 {
				if err := walk(p.Properties); err != nil {
					return err
				}
			}
			for fk := range p.Fields {
				if strings.TrimSpace(fk) == "" {
					return fmt.Errorf("illegal_argument_exception: Field name cannot be an empty string")
				}
			}
		}
		return nil
	}
	return walk(m.Properties)
}

func (s *Server) handleGetMappingsWithTypesR61CRUD(w http.ResponseWriter, r *http.Request, isAll bool) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	isES8 := s.isES8Mode(r)
	pathType := strings.TrimSpace(r.PathValue("type"))
	if isES8 && pathType != "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			"Types cannot be provided in get mapping requests, unless include_type_name is set to true.")
		return
	}
	incType, hasInc, okInc := checkIncludeTypeNameParamR61CRUD(w, s, r, "get mapping")
	if !okInc {
		return
	}
	if !isES8 && pathType != "" && !hasInc {
		incType = true
		emitESDeprecationWarningRound61(w, s, r,
			"[types removal] Specifying types in get mapping requests is deprecated.")
	}

	var targets []string
	if isAll {
		ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
		if ewErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
			return
		}
		if !ewNone {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			for indexName := range s.indices {
				isClosed := s.closedIndices[indexName]
				if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
					continue
				}
				if s.isIndexExplicitlyHiddenLocked(indexName) && !ewHidden {
					continue
				}
				targets = append(targets, indexName)
			}
			s.mu.RUnlock()
			sort.Strings(targets)
		}
	} else {
		rawIdx := strings.TrimSpace(r.PathValue("index"))
		_, _, _, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
		if ewErr != nil {
			if r.Method == http.MethodHead {
				ensureESCompatHeaders(w, r)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
			return
		}
		if ewNone && (strings.ContainsAny(rawIdx, "*?") || rawIdx == "_all") {
			var concreteOnly []string
			for _, p := range strings.Split(rawIdx, ",") {
				p = strings.TrimSpace(p)
				if p != "" && p != "_all" && !strings.ContainsAny(p, "*?") && !strings.HasPrefix(p, "-") {
					concreteOnly = append(concreteOnly, p)
				}
			}
			if len(concreteOnly) == 0 {
				allowNo := !r.URL.Query().Has("allow_no_indices") || isTruthyBoolQueryParam(r, "allow_no_indices")
				if !allowNo {
					if r.Method == http.MethodHead {
						ensureESCompatHeaders(w, r)
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIdx+"]")
					return
				}
				targets = nil
			} else {
				var ok bool
				targets, _, ok = s.resolveValidatedReadTargets(w, r, strings.Join(concreteOnly, ","))
				if !ok {
					return
				}
			}
		} else {
			var ok bool
			targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIdx)
			if !ok {
				return
			}
		}
	}

	s.mu.RLock()
	lookupIdxLocked := func(indexName string) (*schema.IndexSchema, bool) {
		idx, exists := s.indices[indexName]
		if !exists && strings.HasPrefix(indexName, ".ds-") && strings.HasSuffix(indexName, "-000001") {
			dsName := strings.TrimSuffix(strings.TrimPrefix(indexName, ".ds-"), "-000001")
			if _, isDS := s.dataStreams[dsName]; isDS {
				idx, exists = s.indices[dsName]
			}
		}
		return idx, exists
	}

	out := make(map[string]any, len(targets)+2)
	if pathType == "" {
		for _, indexName := range targets {
			if idx, exists := lookupIdxLocked(indexName); exists {
				mappings := wrapMappingsResponseForTypeR61CRUD(idx, buildMappingResponseMapRound59(idx), incType, "")
				out[indexName] = map[string]any{
					"mappings": mappings,
				}
			}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, out)
		return
	}

	typePats := splitCSVTokensR61Admin([]string{pathType})
	patMatchedCount := make(map[string]int, len(typePats))
	totalMatched := 0
	for _, indexName := range targets {
		idx, exists := lookupIdxLocked(indexName)
		if !exists || idx == nil {
			continue
		}
		hasIndexType := idx.LegacyTypeName != "" || idx.RawMapping != nil || len(idx.Fields) > 0
		if !hasIndexType {
			continue
		}
		tName := effectiveIndexLegacyTypeR61CRUD(idx)
		idxMatched := false
		for _, tp := range typePats {
			if tp == "_all" || tp == "*" || matchWildcardPattern(tp, tName) {
				patMatchedCount[tp]++
				idxMatched = true
			}
		}
		if idxMatched {
			totalMatched++
			mBody := buildMappingResponseMapRound59(idx)
			if incType {
				out[indexName] = map[string]any{"mappings": map[string]any{tName: mBody}}
			} else {
				out[indexName] = map[string]any{"mappings": mBody}
			}
		}
	}
	s.mu.RUnlock()

	var missingPats []string
	seenMiss := make(map[string]bool)
	for _, tp := range typePats {
		if tp != "_all" && tp != "*" && patMatchedCount[tp] == 0 && !seenMiss[tp] {
			seenMiss[tp] = true
			missingPats = append(missingPats, tp)
		}
	}
	if len(missingPats) > 0 {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if totalMatched == 0 && len(typePats) == 1 && !strings.ContainsAny(typePats[0], "*?") {
			writeESError(w, http.StatusNotFound, "type_missing_exception", fmt.Sprintf("type[[%s]] missing", typePats[0]))
			return
		}
		sort.Strings(missingPats)
		if len(missingPats) == 1 {
			out["error"] = fmt.Sprintf("type [%s] missing", missingPats[0])
		} else {
			out["error"] = fmt.Sprintf("types [%s] missing", strings.Join(missingPats, ","))
		}
		out["status"] = http.StatusNotFound
		writeJSONWithRequest(w, r, http.StatusNotFound, out)
		return
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, out)
}

func (s *Server) handlePutMappingR61CRUD(w http.ResponseWriter, r *http.Request) {
	isES8 := s.isES8Mode(r)
	pathType := strings.TrimSpace(r.PathValue("type"))
	if isES8 && pathType != "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			"Types cannot be provided in put mapping requests")
		return
	}
	incType, hasInc, okInc := checkIncludeTypeNameParamR61CRUD(w, s, r, "put mapping")
	if !okInc {
		return
	}
	if !isES8 && pathType != "" && !hasInc {
		incType = true
	}

	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex == "" {
		rawIndex = "_all"
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	effectivePutType := pathType
	if incType {
		if effectivePutType == "" && len(bytes.TrimSpace(bodyBytes)) == 0 {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: mapping type is missing;")
			return
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var rawMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(bodyBytes))
			dec.UseNumber()
			if err := dec.Decode(&rawMap); err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
			hasOnlyTypeWrapper := len(rawMap) == 1
			var singleKey string
			var singleVal any
			for k, v := range rawMap {
				singleKey = k
				singleVal = v
				if reservedMappingRootKeysR61CRUD[k] {
					hasOnlyTypeWrapper = false
				}
			}
			if hasOnlyTypeWrapper {
				if effectivePutType != "" && singleKey != effectivePutType {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception",
						fmt.Sprintf("Root mapping definition has unsupported parameters:  [%s : %v]", singleKey, singleVal))
					return
				}
				effectivePutType = singleKey
				if singleVal == nil {
					bodyBytes = []byte("{}")
				} else if subMap, okSub := singleVal.(map[string]any); okSub {
					if unwrappedBytes, mErr := json.Marshal(subMap); mErr == nil {
						bodyBytes = unwrappedBytes
					}
				} else {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception",
						fmt.Sprintf("Expected map for type mapping [%s]", singleKey))
					return
				}
			} else if effectivePutType == "" {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
					"Validation Failed: 1: mapping type is missing;")
				return
			}
		}
		if strings.HasPrefix(effectivePutType, "_") && effectivePutType != "_doc" {
			writeESError(w, http.StatusBadRequest, "invalid_type_name_exception",
				fmt.Sprintf("Document mapping type name can't start with '_', found: [%s]", effectivePutType))
			return
		}
	} else if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var rawMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err == nil {
			for k, v := range rawMap {
				if k == "mappings" || reservedMappingRootKeysR61CRUD[k] {
					continue
				}
				if _, isObj := v.(map[string]any); isObj {
					if k == "_doc" {
						if isES8 {
							writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
								"Types cannot be provided in put mapping requests")
							return
						}
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							"Types cannot be provided in put mapping requests, unless the include_type_name parameter is set to true.")
						return
					}
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception",
						fmt.Sprintf("Root mapping definition has unsupported parameters:  [%s : %v]", k, v))
					return
				}
			}
		}
	}

	var spec esast.MappingSpec
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &spec); err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
		if len(spec.Properties) == 0 && len(spec.Runtime) == 0 {
			var envelope struct {
				Mappings *esast.MappingSpec `json:"mappings"`
			}
			if err := json.Unmarshal(bodyBytes, &envelope); err == nil && envelope.Mappings != nil {
				spec = *envelope.Mappings
			}
		}
	}
	if err := validateNonEmptyPropertyNamesR61CRUD(&spec); err != nil {
		et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
		writeESError(w, http.StatusBadRequest, et, er)
		return
	}

	targets := s.resolveTargetIndices(rawIndex)
	s.mu.RLock()
	var validTargets []string
	var missingConcrete string
	for _, part := range strings.Split(rawIndex, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
			continue
		}
		if _, isAlias := s.aliases[part]; !isAlias {
			if _, isIdx := s.indices[part]; !isIdx && missingConcrete == "" {
				missingConcrete = part
			}
		}
	}
	for _, t := range targets {
		if _, exists := s.indices[t]; exists {
			validTargets = append(validTargets, t)
		}
	}
	s.mu.RUnlock()

	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	if rawAllow := strings.TrimSpace(r.URL.Query().Get("allow_no_indices")); rawAllow != "" {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}
	if missingConcrete != "" && !ignoreUnavailable {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", missingConcrete))
		return
	}
	if len(validTargets) == 0 {
		if (hasExclusionOrWildcard(rawIndex) || rawIndex == "_all") && allowNoIndices {
			writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
			return
		}
		missingName := rawIndex
		if missingConcrete != "" {
			missingName = missingConcrete
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", missingName))
		return
	}
	if _, reason := s.findMetadataBlockedTargetIndex(validTargets, false); reason != "" {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
		return
	}

	if err := schema.ValidateMappingSpec(&spec); err != nil {
		et, er := splitSchemaErrorPrefixR61CRUD(err, "mapper_parsing_exception")
		writeESError(w, http.StatusBadRequest, et, er)
		return
	}

	s.mu.RLock()
	for _, indexName := range validTargets {
		oldSchema := s.indices[indexName]
		if effectivePutType != "" && oldSchema != nil {
			if oldSchema.LegacyTypeName != "" || len(oldSchema.Fields) > 0 || (oldSchema.RawMapping != nil && len(oldSchema.RawMapping.Properties) > 0) {
				curType := effectiveIndexLegacyTypeR61CRUD(oldSchema)
				if curType != effectivePutType {
					s.mu.RUnlock()
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Rejecting mapping update to [%s] as the final mapping would have more than 1 type: [%s, %s]", indexName, curType, effectivePutType))
					return
				}
			}
		}
		var oldRaw *esast.MappingSpec
		if oldSchema != nil {
			oldRaw = oldSchema.RawMapping
		}
		if err := schema.ValidateMappingUpdateCompatibility(oldRaw, &spec); err != nil {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
		if len(spec.Runtime) > 0 {
			if err := ValidateRuntimeMappingsPainlessRound61(oldSchema, spec.Runtime); err != nil {
				s.mu.RUnlock()
				et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
				writeESError(w, http.StatusBadRequest, et, er)
				return
			}
			if !s.explicitTargetESVersion {
				mergedRT := effectiveRuntimeMappings(oldSchema, spec.Runtime)
				if _, err := TopoSortRuntimeMappingsRound61(mergedRT); err != nil {
					s.mu.RUnlock()
					et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
					writeESError(w, http.StatusBadRequest, et, er)
					return
				}
			}
		}
		mergedPreview := schema.MergeMappingSpecs(oldRaw, &spec)
		if err := validateAliasFieldsInMapping(mergedPreview); err != nil {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
		if err := schema.ValidateSyntheticSourceMapping(mergedPreview); err != nil {
			s.mu.RUnlock()
			et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
			writeESError(w, http.StatusBadRequest, et, er)
			return
		}
		if oldSchema != nil && oldSchema.IndexMode == "time_series" {
			if err := schema.ValidateTSDBMapping(mergedPreview, oldSchema.RoutingPath); err != nil {
				s.mu.RUnlock()
				et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
				writeESError(w, http.StatusBadRequest, et, er)
				return
			}
			if err := validateTSDBSyntheticTextFieldsR61CRUD(mergedPreview); err != nil {
				s.mu.RUnlock()
				et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
				writeESError(w, http.StatusBadRequest, et, er)
				return
			}
		}
		if err := schema.ValidateMappingLimits(oldSchema, mergedPreview); err != nil {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
	}
	s.mu.RUnlock()

	for _, indexName := range validTargets {
		s.mu.Lock()
		oldSchema := s.indices[indexName]
		var oldRaw *esast.MappingSpec
		if oldSchema != nil {
			oldRaw = oldSchema.RawMapping
		}
		mergedSpec := schema.MergeMappingSpecs(oldRaw, &spec)
		normalizeMappingScriptsInPlaceR62Search(mergedSpec)
		newSchema := schema.CompileIndexSchema(s.dorisDB, indexName, mergedSpec)
		newSchema.ES8Mode = isES8
		if oldSchema != nil {
			newSchema.CopyIndexMappingSettingsFrom(oldSchema)
		} else if custom := s.indexCustomSettings[indexName]; len(custom) > 0 {
			_ = parseAndApplyIndexMappingSettingsRound59(custom, newSchema)
		}
		if effectivePutType != "" && newSchema.LegacyTypeName == "" {
			newSchema.LegacyTypeName = effectivePutType
		}
		var nextSeq int64
		if s.indexNextSeqNo != nil {
			nextSeq = s.indexNextSeqNo[indexName]
		}
		recordNewPutMappingFieldsSeqNoR61CRUD(oldSchema, newSchema, nextSeq)
		s.indices[indexName] = newSchema
		s.mu.Unlock()
		s.persistIndex(r.Context(), indexName, newSchema)

		if oldSchema == nil {
			ddl := schema.GenerateCreateTableDDL(newSchema)
			if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
				writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
				return
			}
		} else {
			for _, stmt := range schema.GenerateAlterTableDDL(oldSchema, newSchema) {
				if err := s.backend.ExecDDL(r.Context(), stmt); err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
					return
				}
			}
		}
	}
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
}

// ============================================================================
// F6: `handleDeleteIndex`, `get_alias` & `delete_alias`
// ============================================================================

func (s *Server) isDestructiveRequiresNameR61CRUD() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if raw, ok := s.getClusterSettingStringLocked("action.destructive_requires_name"); ok {
		low := strings.ToLower(strings.TrimSpace(raw))
		return low == "true" || low == "1"
	}
	return false
}

func (s *Server) handleDeleteIndexR61CRUD(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	_ = s.syncCatalogFromBackend(r.Context())

	if s.isDestructiveRequiresNameR61CRUD() {
		for _, tok := range strings.Split(rawIndex, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "_all" || strings.ContainsAny(tok, "*?") {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					"Wildcard expressions or all indices are not allowed")
				return
			}
		}
	}

	rawEW := strings.TrimSpace(r.URL.Query().Get("expand_wildcards"))
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(rawEW)
	if ewErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
		return
	}
	if rawEW == "" {
		ewOpen = true
		ewClosed = true
		// In ES `DELETE *` / `DELETE _all` without explicit expand_wildcards deletes open & closed indices;
		// explicit dot-prefixed patterns (`DELETE .foo*`) match hidden indices too.
		ewHidden = false
	}

	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	if r.URL.Query().Has("allow_no_indices") {
		bv, _, bErr := parseStrictQueryBoolParamRound59(r, "allow_no_indices")
		if bErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", bErr.Error())
			return
		}
		allowNoIndices = bv
	}

	parts := strings.Split(rawIndex, ",")
	var exclusions []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "-") {
			if excl := strings.TrimSpace(strings.TrimPrefix(part, "-")); excl != "" {
				exclusions = append(exclusions, excl)
			}
		}
	}
	isExcluded := func(idx string) bool {
		for _, excl := range exclusions {
			if excl == "_all" || excl == "*" || matchWildcardPattern(excl, idx) {
				return true
			}
		}
		return false
	}
	seen := make(map[string]bool)
	var targets []string

	s.mu.RLock()
	canExpandIdxLocked := func(idxName string, pat string) bool {
		if ewNone {
			return false
		}
		isClosed := s.closedIndices[idxName]
		if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
			return false
		}
		isHidden := s.isIndexExplicitlyHiddenLocked(idxName) || strings.HasPrefix(idxName, ".")
		if isHidden && !ewHidden && !strings.HasPrefix(pat, ".") {
			return false
		}
		return true
	}

	addDeleteTarget := func(idx string) {
		if idx != "" && !seen[idx] && !isExcluded(idx) {
			seen[idx] = true
			targets = append(targets, idx)
		}
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") {
			continue
		}
		if part == "_all" || part == "*" {
			if ewNone {
				if !allowNoIndices {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
					return
				}
				continue
			}
			matchedPart := false
			for idxName := range s.indices {
				if canExpandIdxLocked(idxName, part) && !isExcluded(idxName) {
					addDeleteTarget(idxName)
					matchedPart = true
				}
			}
			if !matchedPart && !allowNoIndices {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
				return
			}
			continue
		}
		if strings.ContainsAny(part, "*?") {
			matchedPart := false
			for idxName := range s.indices {
				if matchWildcardPattern(part, idxName) && canExpandIdxLocked(idxName, part) && !isExcluded(idxName) {
					addDeleteTarget(idxName)
					matchedPart = true
				}
			}
			// In ES 7 (`!s.isES8Mode(r)`), a wildcard matching a filtered alias fails with 400 (`TestRound11`),
			// while unfiltered wildcards do not expand to aliases (`indices.delete/10_basic.yml`).
			if !s.isES8Mode(r) && !matchedPart && !ignoreUnavailable {
				for aliasName, aliasTargets := range s.aliases {
					hasAliasFilter := false
					for _, am := range s.aliasMeta[aliasName] {
						if am.Filter != nil || len(am.RawFilter) > 0 {
							hasAliasFilter = true
							break
						}
					}
					if len(aliasTargets) > 0 && hasAliasFilter && matchWildcardPattern(part, aliasName) {
						s.mu.RUnlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("The provided expression [%s] matches an alias, specify the corresponding concrete indices instead.", rawIndex))
						return
					}
				}
			}
			if !matchedPart && !allowNoIndices {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
				return
			}
			continue
		}
		_, isConcreteIndex := s.indices[part]
		aliasTargets, isAlias := s.aliases[part]
		if isAlias && len(aliasTargets) > 0 && !isConcreteIndex {
			if ignoreUnavailable {
				continue
			}
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("The provided expression [%s] matches an alias, specify the corresponding concrete indices instead.", rawIndex))
			return
		}
		if !isConcreteIndex {
			if !ignoreUnavailable {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
				return
			}
			continue
		}
		addDeleteTarget(part)
	}
	s.mu.RUnlock()

	if len(targets) == 0 && !allowNoIndices {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	if _, reason := s.findMetadataBlockedTargetIndex(targets, true); reason != "" {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
		return
	}

	modifiedAliases := make(map[string][]string)
	modifiedDataStreams := make(map[string]map[string]any)
	var tablesToDrop []*schema.IndexSchema
	s.mu.Lock()
	for _, indexName := range targets {
		if ownerDS, isWriteIdx := isDataStreamActiveWriteIndexLockedR63(s, indexName); isWriteIdx {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("index [%s] is the write index for data stream [%s] and cannot be deleted", indexName, ownerDS))
			return
		}
	}
	for _, indexName := range targets {
		if idx, ok := s.indices[indexName]; ok {
			tablesToDrop = append(tablesToDrop, idx)
		}
		for dsName, dsSnap := range removeDeletedBackingIndexFromDataStreamsLockedR63(s, indexName) {
			modifiedDataStreams[dsName] = dsSnap
		}
		delete(s.indices, indexName)
		delete(s.docRouting, indexName)
		delete(s.docVersions, indexName)
		delete(s.indexDefaultPipelines, indexName)
		delete(s.indexFinalPipelines, indexName)
		delete(s.closedIndices, indexName)
		delete(s.indexCustomSettings, indexName)
		delete(s.indexNextSeqNo, indexName)
		delete(s.docSeqNos, indexName)
		delete(s.docDeleted, indexName)
		delete(s.docExtTombstones, indexName)
		delete(s.unrefreshedDocs, indexName)
		delete(s.indexStats, indexName)
		for alias := range s.aliases {
			s.removeAliasTargetLocked(alias, indexName)
			modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
		}
	}
	s.mu.Unlock()
	for _, indexName := range targets {
		s.clearTSDBIndexTombstonesR63(indexName)
		s.deleteCatalogEntity(r.Context(), "index", indexName)
		s.deleteCatalogEntity(r.Context(), "index_seq_state", indexName)
	}
	for dsName, dsSnap := range modifiedDataStreams {
		s.persistDataStream(r.Context(), dsName, dsSnap)
	}
	for alias, aliasTargets := range modifiedAliases {
		s.persistAlias(r.Context(), alias, aliasTargets)
	}
	for _, idx := range tablesToDrop {
		ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
		_ = s.backend.ExecDDL(r.Context(), ddl)
	}
	s.emitSystemIndexTasksWarningIfNeededRound61(w, r, append(append([]string(nil), targets...), rawIndex))
	purgeDeletedIndicesAdminStateR62Admin(s, targets)
	s.purgeShardRequestCacheIndicesR63(targets)
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
}

func emitGetAliasLocalDeprecationIfNeededR61CRUD(w http.ResponseWriter, s *Server, r *http.Request) {
	if s != nil && s.isES8Mode(r) && r != nil && r.URL != nil && r.URL.Query().Has("local") {
		val := strings.TrimSpace(r.URL.Query().Get("local"))
		if val == "" {
			val = "true"
		}
		emitESDeprecationWarningRound61(w, s, r,
			fmt.Sprintf("the [?local=%s] query parameter to get-aliases requests has no effect and will be removed in a future version", val))
	}
}

func formatMissingAliasesStringR61CRUD(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	dedup := make(map[string]bool, len(missing))
	uniq := make([]string, 0, len(missing))
	for _, m := range missing {
		if !dedup[m] {
			dedup[m] = true
			uniq = append(uniq, m)
		}
	}
	sort.Strings(uniq)
	if len(uniq) == 1 {
		return fmt.Sprintf("alias [%s] missing", uniq[0])
	}
	return fmt.Sprintf("aliases [%s] missing", strings.Join(uniq, ","))
}

func (s *Server) resolveGetAliasTargetIndicesR61CRUD(w http.ResponseWriter, r *http.Request, rawIndex string) ([]string, bool) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawEW := strings.TrimSpace(r.URL.Query().Get("expand_wildcards"))
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(rawEW)
	if ewErr != nil {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusBadRequest)
			return nil, false
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
		return nil, false
	}
	if rawEW == "" {
		ewOpen = true
		ewClosed = true
		ewHidden = false
	}
	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	if r.URL.Query().Has("allow_no_indices") {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}

	rawIndex = strings.TrimSpace(rawIndex)
	if rawIndex == "" || rawIndex == "_all" || rawIndex == "*" {
		if ewNone {
			if rawIndex != "" && !allowNoIndices {
				if r.Method == http.MethodHead {
					ensureESCompatHeaders(w, r)
					w.WriteHeader(http.StatusNotFound)
					return nil, false
				}
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
				return nil, false
			}
			return nil, true
		}
		s.mu.RLock()
		var out []string
		for idxName := range s.indices {
			isClosed := s.closedIndices[idxName]
			if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
				continue
			}
			isHidden := s.isIndexExplicitlyHiddenLocked(idxName) || strings.HasPrefix(idxName, ".")
			if isHidden && !ewHidden {
				continue
			}
			out = append(out, idxName)
		}
		s.mu.RUnlock()
		sort.Strings(out)
		if len(out) == 0 && rawIndex != "" && !allowNoIndices {
			if r.Method == http.MethodHead {
				ensureESCompatHeaders(w, r)
				w.WriteHeader(http.StatusNotFound)
				return nil, false
			}
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return nil, false
		}
		return out, true
	}

	if ewNone && strings.ContainsAny(rawIndex, "*?") {
		if !allowNoIndices {
			if r.Method == http.MethodHead {
				ensureESCompatHeaders(w, r)
				w.WriteHeader(http.StatusNotFound)
				return nil, false
			}
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return nil, false
		}
		return nil, true
	}

	s.mu.RLock()
	var missingConcrete string
	concreteTargets := make(map[string]bool)
	explicitDot := false
	for _, part := range strings.Split(rawIndex, ",") {
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
		concreteTargets[part] = true
		for _, at := range s.aliases[part] {
			concreteTargets[at] = true
		}
		_, isIdx := s.indices[part]
		aliasList, isAlias := s.aliases[part]
		_, isDS := s.dataStreams[part]
		if !isIdx && (!isAlias || len(aliasList) == 0) && !isDS && missingConcrete == "" {
			missingConcrete = part
		}
	}
	s.mu.RUnlock()

	if missingConcrete != "" && !ignoreUnavailable {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusNotFound)
			return nil, false
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+missingConcrete+"]")
		return nil, false
	}

	resolved, _ := s.resolveTargetIndicesWithOptions(rawIndex, ewHidden || explicitDot)
	s.mu.RLock()
	var valid []string
	for _, idxName := range resolved {
		if _, ok := s.indices[idxName]; !ok {
			continue
		}
		if !concreteTargets[idxName] {
			if ewNone {
				continue
			}
			isClosed := s.closedIndices[idxName]
			if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
				continue
			}
			isHidden := s.isIndexExplicitlyHiddenLocked(idxName) || strings.HasPrefix(idxName, ".")
			if isHidden && !ewHidden && !explicitDot {
				continue
			}
		} else {
			// Even if resolved via concrete alias (`test_alias`), filter closed/hidden backing indices when expand_wildcards restricts them (`10_basic.yml:326`).
			if _, isDirectIdx := s.indices[rawIndex]; !isDirectIdx {
				isClosed := s.closedIndices[idxName]
				if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
					continue
				}
			}
		}
		valid = append(valid, idxName)
	}
	s.mu.RUnlock()
	sort.Strings(valid)
	if len(valid) == 0 && !allowNoIndices {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusNotFound)
			return nil, false
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return nil, false
	}
	return valid, true
}

func (s *Server) executeGetAliasesCoreR61CRUD(w http.ResponseWriter, r *http.Request, rawIndex, aliasFilter string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	emitGetAliasLocalDeprecationIfNeededR61CRUD(w, s, r)
	targetIndices, ok := s.resolveGetAliasTargetIndicesR61CRUD(w, r, rawIndex)
	if !ok {
		return
	}
	rawEW := strings.TrimSpace(r.URL.Query().Get("expand_wildcards"))
	_, _, ewHidden, ewNone, _ := parseExpandWildcardsFlags(rawEW)
	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")

	targetSet := make(map[string]bool, len(targetIndices))
	for _, idx := range targetIndices {
		targetSet[idx] = true
	}

	aliasFilter = strings.TrimSpace(aliasFilter)
	s.mu.RLock()
	if aliasFilter == "" {
		out := make(map[string]any, len(targetIndices))
		totalMatched := 0
		for _, idxName := range targetIndices {
			idxAliases := make(map[string]any)
			for al, alTargets := range s.aliases {
				if strings.HasPrefix(al, ".") && !ewHidden {
					continue
				}
				for _, t := range alTargets {
					if t == idxName {
						idxAliases[al] = s.getAliasMetaMapLocked(al, idxName)
						totalMatched++
					}
				}
			}
			out[idxName] = map[string]any{"aliases": idxAliases}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			if totalMatched == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, out)
		return
	}

	// Left-to-right alias pattern + exclusion evaluation (`indices.get_alias/10_basic.yml` & `30_wildcards.yml`).
	matchedPairs := make(map[string]map[string]bool) // idx -> alias -> bool
	var missingAliases []string
	hasSeenInclusionOrWildcard := false

	for _, tok := range strings.Split(aliasFilter, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			excl := strings.TrimPrefix(tok, "-")
			isWild := strings.ContainsAny(excl, "*?")
			for idxName, alSet := range matchedPairs {
				for al := range alSet {
					if excl == "_all" || matchWildcardPattern(excl, al) {
						delete(alSet, al)
					}
				}
				if len(alSet) == 0 {
					delete(matchedPairs, idxName)
				}
			}
			if !isWild && !hasSeenInclusionOrWildcard && !ignoreUnavailable {
				missingAliases = append(missingAliases, tok)
			}
			if isWild {
				hasSeenInclusionOrWildcard = true
			}
			continue
		}

		hasSeenInclusionOrWildcard = true
		isWild := tok == "_all" || strings.ContainsAny(tok, "*?")
		explicitDotAlias := strings.HasPrefix(tok, ".")
		tokMatchedCount := 0
		if !isWild || !ewNone {
			for al, alTargets := range s.aliases {
				if isWild && strings.HasPrefix(al, ".") && !ewHidden && !explicitDotAlias {
					continue
				}
				if tok == "_all" || matchWildcardPattern(tok, al) {
					for _, t := range alTargets {
						if !targetSet[t] {
							continue
						}
						if matchedPairs[t] == nil {
							matchedPairs[t] = make(map[string]bool)
						}
						matchedPairs[t][al] = true
						tokMatchedCount++
					}
				}
			}
		}
		if !isWild && tokMatchedCount == 0 && !ignoreUnavailable {
			missingAliases = append(missingAliases, tok)
		}
	}

	out := make(map[string]any, len(matchedPairs)+2)
	totalMatched := 0
	for idxName, alSet := range matchedPairs {
		if len(alSet) == 0 {
			continue
		}
		idxAliases := make(map[string]any, len(alSet))
		for al := range alSet {
			idxAliases[al] = s.getAliasMetaMapLocked(al, idxName)
			totalMatched++
		}
		out[idxName] = map[string]any{"aliases": idxAliases}
	}
	s.mu.RUnlock()

	if len(missingAliases) > 0 {
		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		out["error"] = formatMissingAliasesStringR61CRUD(missingAliases)
		out["status"] = http.StatusNotFound
		writeJSONWithRequest(w, r, http.StatusNotFound, out)
		return
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		if totalMatched == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, out)
}

func (s *Server) handleGetAliasesR61CRUD(w http.ResponseWriter, r *http.Request) {
	s.executeGetAliasesCoreR61CRUD(w, r, "", r.PathValue("name"))
}

func (s *Server) handleGetIndexAliasesR61CRUD(w http.ResponseWriter, r *http.Request) {
	s.executeGetAliasesCoreR61CRUD(w, r, r.PathValue("index"), "")
}

func (s *Server) handleIndexAliasByNameR61CRUD(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.executeGetAliasesCoreR61CRUD(w, r, r.PathValue("index"), r.PathValue("name"))
		return
	}

	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	aliasName := strings.TrimSpace(r.PathValue("name"))

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

	if rawIndex != "" && rawIndex != "*" && rawIndex != "_all" {
		s.mu.RLock()
		var missingPart string
		for _, part := range strings.Split(rawIndex, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
				continue
			}
			if s.indices[part] == nil && len(s.aliases[part]) == 0 && s.dataStreams[part] == nil {
				missingPart = part
				break
			}
		}
		s.mu.RUnlock()
		if missingPart != "" {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+missingPart+"]")
			return
		}
	}
	var targetIndices []string
	if !ewNone || (!strings.ContainsAny(rawIndex, "*?") && rawIndex != "_all") {
		resolved, _ := s.resolveTargetIndicesWithOptions(rawIndex, ewHidden)
		s.mu.RLock()
		for _, idx := range resolved {
			isClosed := s.closedIndices[idx]
			if strings.ContainsAny(rawIndex, "*?") || rawIndex == "_all" {
				if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
					continue
				}
			}
			targetIndices = append(targetIndices, idx)
		}
		s.mu.RUnlock()
	}
	if len(targetIndices) == 0 && rawIndex != "" && !strings.ContainsAny(rawIndex, "*?,") && rawIndex != "_all" {
		targetIndices = []string{s.resolveIndexName(rawIndex)}
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if reason, ok := validateESIndexName(aliasName); !ok {
			writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception",
				strings.Replace(reason, "Invalid index name", "Invalid alias name", 1))
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		bodyBytes = normalizeAliasActionsBodyRound60(bodyBytes)
		var meta AliasMetadata
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &meta); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		s.mu.Lock()
		var existingTargets []string
		for _, indexName := range targetIndices {
			if sc, ok := s.indices[indexName]; ok {
				if sc != nil && sc.IndexMode == "time_series" {
					if err := validateAliasNoRoutingOnTSDBR61CRUD(meta); err != nil {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
						return
					}
				}
				existingTargets = append(existingTargets, indexName)
			}
		}
		if len(existingTargets) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return
		}
		for _, indexName := range existingTargets {
			if blocked, reason := s.isIndexMetadataBlockedLocked(indexName, false); blocked {
				s.mu.Unlock()
				writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
				return
			}
		}
		if _, exists := s.indices[aliasName]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], an index exists with the same name as the alias", aliasName))
			return
		}
		if _, exists := s.dataStreams[aliasName]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], a data stream exists with the same name as the alias", aliasName))
			return
		}
		for _, indexName := range existingTargets {
			s.addAliasWithMetaLocked(aliasName, indexName, meta)
		}
		targets := append([]string(nil), s.aliases[aliasName]...)
		s.mu.Unlock()
		s.persistAlias(r.Context(), aliasName, targets)
		s.queryCache.InvalidateAll()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodDelete:
		modifiedAliases := make(map[string][]string)
		s.mu.Lock()
		var existingTargets []string
		for _, indexName := range targetIndices {
			if _, ok := s.indices[indexName]; ok {
				existingTargets = append(existingTargets, indexName)
			}
		}
		if len(existingTargets) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return
		}
		for _, indexName := range existingTargets {
			if blocked, reason := s.isIndexMetadataBlockedLocked(indexName, false); blocked {
				s.mu.Unlock()
				writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
				return
			}
		}
		aliasHasAnyTargetLocked := func(al string, idxs []string) bool {
			for _, t := range s.aliases[al] {
				for _, idx := range idxs {
					if t == idx {
						return true
					}
				}
			}
			return false
		}
		var missingConcreteAliases []string
		removedAny := false
		for _, tok := range strings.Split(aliasName, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if tok == "_all" || strings.ContainsAny(tok, "*?") || strings.HasPrefix(tok, "-") {
				for al := range s.aliases {
					if tok == "_all" || matchMultiWildcardWithExclusions(aliasName, al) {
						if aliasHasAnyTargetLocked(al, existingTargets) {
							removedAny = true
							for _, indexName := range existingTargets {
								s.removeAliasTargetLocked(al, indexName)
							}
							modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
						}
					}
				}
			} else {
				if aliasHasAnyTargetLocked(tok, existingTargets) {
					removedAny = true
					for _, indexName := range existingTargets {
						s.removeAliasTargetLocked(tok, indexName)
					}
					modifiedAliases[tok] = append([]string(nil), s.aliases[tok]...)
				} else {
					missingConcreteAliases = append(missingConcreteAliases, tok)
				}
			}
		}
		if len(missingConcreteAliases) > 0 || !removedAny {
			s.mu.Unlock()
			msg := formatMissingAliasesStringR61CRUD(missingConcreteAliases)
			if msg == "" {
				msg = fmt.Sprintf("aliases [%s] missing", aliasName)
			}
			writeESError(w, http.StatusNotFound, "aliases_not_found_exception", msg)
			return
		}
		s.mu.Unlock()
		for al, targets := range modifiedAliases {
			s.persistAlias(r.Context(), al, targets)
		}
		s.queryCache.InvalidateAll()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

// ============================================================================
// F7: CRUD Reads (`_doc`, `_source`, `HEAD`), `_mget`, `realtime=false`,
//     `stored_fields` vs `_source`, `_ignored` & 512-Byte `_id`
// ============================================================================

func validateDocIDByteLimitR61CRUD(docID string) (int, string, string) {
	if docID != "" && len(docID) > 512 {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("The length of [_id] field of [%s] doc cannot be more than [512] bytes, but got [%d]", docID, len(docID))
	}
	return 0, "", ""
}

// validateTypedDocWriteR61CRUD checks ES 7 legacy type compatibility when writing via `/{index}/{type}/{id}`
// or typed bulk items (`20_mix_typeless_typeful.yml`), and records ES 7 doc-type stats (`F3`, `F5`).
func (s *Server) validateTypedDocWriteR61CRUD(r *http.Request, indexName, explicitDocType string) (string, int, string, string) {
	if s.isES8Mode(r) {
		return "_doc", 0, "", ""
	}
	docType := strings.TrimSpace(explicitDocType)
	hasExplicitType := docType != ""
	if !hasExplicitType && r != nil {
		if v, ok := r.Context().Value(legacyDocTypeCtxKey{}).(string); ok && strings.TrimSpace(v) != "" {
			docType = strings.TrimSpace(v)
			hasExplicitType = true
		}
	}
	if !hasExplicitType || docType == "_doc" {
		s.mu.RLock()
		idx := s.indices[indexName]
		s.mu.RUnlock()
		if idx != nil && idx.LegacyTypeName != "" {
			return idx.LegacyTypeName, 0, "", ""
		}
		return "_doc", 0, "", ""
	}

	s.mu.RLock()
	idx := s.indices[indexName]
	tplType, tplHasMap := s.matchingLegacyTemplateTypeLockedR61CRUD(indexName)
	s.mu.RUnlock()

	if idx != nil {
		curType := effectiveIndexLegacyTypeR61CRUD(idx)
		if (idx.LegacyTypeName != "" || len(idx.Fields) > 0 || (idx.RawMapping != nil && len(idx.RawMapping.Properties) > 0)) && curType != docType {
			return docType, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Rejecting mapping update to [%s] as the final mapping would have more than 1 type: [%s, %s]", indexName, curType, docType)
		}
		return docType, 0, "", ""
	}
	if tplHasMap && tplType != "" && tplType != docType {
		return docType, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Rejecting mapping update to [%s] as the final mapping would have more than 1 type: [%s, %s]", indexName, tplType, docType)
	}
	return docType, 0, "", ""
}

func docMatchesLegacyReadTypeR61CRUD(s *Server, r *http.Request, idxSchema *schema.IndexSchema, explicitType string) bool {
	if s == nil || s.isES8Mode(r) {
		return true
	}
	reqType := strings.TrimSpace(explicitType)
	if reqType == "" {
		reqType = legacyDocTypeFromRequest(r)
	}
	if reqType == "" || reqType == "_doc" || reqType == "_all" {
		return true
	}
	return effectiveIndexLegacyTypeR61CRUD(idxSchema) == reqType
}

func formatRoutingMissingReasonR61CRUD(s *Server, r *http.Request, indexName, docID string) string {
	if s != nil && s.isES8Mode(r) {
		return fmt.Sprintf("routing is required for [%s]/[%s]", indexName, docID)
	}
	return fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID)
}

// resolveRealtimeAndRefreshOnGetR61CRUD enforces `?refresh=true` and `?realtime=false` on GET/HEAD/_mget (`F7`).
func (s *Server) resolveRealtimeAndRefreshOnGetR61CRUD(
	r *http.Request,
	indexName, docID, effRouting string,
	bodyRealtime *bool,
) (realtime bool, errStatus int, errType string, errReason string) {
	realtime = true
	if bodyRealtime != nil {
		realtime = *bodyRealtime
	}
	if r != nil && r.URL != nil {
		if r.URL.Query().Has("force_synthetic_source") {
			fsVal, _, fsErr := parseStrictQueryBoolParamRound59(r, "force_synthetic_source")
			if fsErr != nil {
				return true, http.StatusBadRequest, "illegal_argument_exception", fsErr.Error()
			}
			if fsVal && indexName != "" && s != nil {
				idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
				if vErr := validateGetMGetForceSyntheticSourceR62Admin(idxSchema); vErr != nil {
					return true, http.StatusBadRequest, "illegal_argument_exception", vErr.Error()
				}
			}
		}
		if r.URL.Query().Has("realtime") {
			bv, _, bErr := parseStrictQueryBoolParamRound59(r, "realtime")
			if bErr != nil {
				return true, http.StatusBadRequest, "illegal_argument_exception", bErr.Error()
			}
			realtime = bv
		}
		if r.URL.Query().Has("refresh") {
			rv, _, rErr := parseStrictQueryBoolParamRound59(r, "refresh")
			if rErr != nil {
				return realtime, http.StatusBadRequest, "illegal_argument_exception", rErr.Error()
			}
			if rv {
				if docID != "" {
					s.refreshIndexShardRound60(indexName, s.shardForDocRoutingRound60(indexName, docID, effRouting))
				} else {
					s.refreshAllIndexShardsRound60(indexName)
				}
				if st := s.getOrCreateIndexLiveStats(indexName); st != nil {
					st.refreshTotal.Add(1)
				}
			}
		}
	}
	return realtime, 0, "", ""
}

func (s *Server) applyUnrefreshedSnapshotToReadDocR61CRUD(
	indexName, docID string,
	liveHit *HitRow,
	liveFound bool,
	realtime bool,
) (*HitRow, bool) {
	if realtime {
		return liveHit, liveFound
	}
	unrefMap := s.getUnrefreshedDocsForIndex(indexName)
	if len(unrefMap) == 0 {
		return liveHit, liveFound
	}
	st, hasUnref := unrefMap[docID]
	if !hasUnref {
		return liveHit, liveFound
	}
	if !st.existedBefore {
		return nil, false
	}
	cp := st.prevHit
	if cp.ID == "" {
		cp.ID = docID
	}
	cp.Index = indexName
	return &cp, true
}

func isFieldExplicitlyStoredInSchemaR61CRUD(idxSchema *schema.IndexSchema, fieldPath string) bool {
	if idxSchema == nil || idxSchema.RawMapping == nil {
		return false
	}
	var lookup func(props map[string]esast.FieldProperty, parts []string) (esast.FieldProperty, bool)
	lookup = func(props map[string]esast.FieldProperty, parts []string) (esast.FieldProperty, bool) {
		if len(props) == 0 || len(parts) == 0 {
			return esast.FieldProperty{}, false
		}
		if p, ok := props[parts[0]]; ok {
			if len(parts) == 1 {
				return p, true
			}
			if sp, okS := lookup(p.Properties, parts[1:]); okS {
				return sp, true
			}
			if len(parts) == 2 && len(p.Fields) > 0 {
				if sf, okF := p.Fields[parts[1]]; okF {
					return sf, true
				}
			}
		}
		for i := len(parts); i >= 2; i-- {
			joined := strings.Join(parts[:i], ".")
			if p, ok := props[joined]; ok {
				if i == len(parts) {
					return p, true
				}
				if sp, okS := lookup(p.Properties, parts[i:]); okS {
					return sp, true
				}
			}
		}
		return esast.FieldProperty{}, false
	}
	prop, ok := lookup(idxSchema.RawMapping.Properties, strings.Split(fieldPath, "."))
	if !ok {
		return false
	}
	if prop.Store != nil {
		return *prop.Store
	}
	if idxSchema.ES8Mode || schemaHasAnyExplicitStoreConfigR61CRUD(idxSchema.RawMapping.Properties) {
		return false
	}
	return true
}

func schemaHasAnyExplicitStoreConfigR61CRUD(props map[string]esast.FieldProperty) bool {
	for _, p := range props {
		if p.Store != nil {
			return true
		}
		if len(p.Fields) > 0 && schemaHasAnyExplicitStoreConfigR61CRUD(p.Fields) {
			return true
		}
		if len(p.Properties) > 0 && schemaHasAnyExplicitStoreConfigR61CRUD(p.Properties) {
			return true
		}
	}
	return false
}

func computeDocIgnoredFieldsR61CRUD(idxSchema *schema.IndexSchema, rawSrc json.RawMessage) []string {
	if idxSchema == nil || len(bytes.TrimSpace(rawSrc)) == 0 {
		return nil
	}
	shredded, err := schema.ShredDocument(idxSchema, "_probe", 1, false, rawSrc)
	if err != nil || len(shredded) == 0 || !bytes.Contains(shredded, []byte(`"_ignored"`)) {
		return nil
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil || row == nil {
		return nil
	}
	var out []string
	switch ig := row["_ignored"].(type) {
	case []string:
		out = append(out, ig...)
	case []any:
		for _, elem := range ig {
			if s, ok := elem.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	if len(out) > 1 {
		sort.Strings(out)
	}
	return out
}

func hasExplicitURLSourceParamR61CRUD(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	q := r.URL.Query()
	return q.Has("_source") || q.Has("_source_includes") || q.Has("_source_excludes")
}

// populateGetStoredFieldsAndSourceR61CRUD implements ES `stored_fields` vs `_source` suppression,
// `stored_fields=_none_`, `store: true` filtering, `recordFieldUsageAccessRound61`, and `_ignored` (`F7`).
func populateGetStoredFieldsAndSourceR61CRUD(
	s *Server,
	indexName string,
	hit HitRow,
	idxSchema *schema.IndexSchema,
	effSF *esast.SourceFilter,
	hasExplicitSource bool,
	hasExplicitStoredFields bool,
	storedFields []string,
	targetMap map[string]any,
) {
	forceSynth, _ := targetMap[forceSynSourceMarkerKeyR62Admin].(bool)
	delete(targetMap, forceSynSourceMarkerKeyR62Admin)
	if forceSynth {
		if vErr := validateGetMGetForceSyntheticSourceR62Admin(idxSchema); vErr != nil {
			errReason := vErr.Error()
			delete(targetMap, "found")
			delete(targetMap, "_version")
			delete(targetMap, "_seq_no")
			delete(targetMap, "_primary_term")
			delete(targetMap, "_routing")
			targetMap["error"] = map[string]any{
				"root_cause": []map[string]any{
					{"type": "illegal_argument_exception", "reason": errReason, "index": indexName},
				},
				"type":   "illegal_argument_exception",
				"reason": errReason,
				"index":  indexName,
			}
			return
		}
		if idxSchema != nil && !idxSchema.SyntheticSource {
			cpSc := *idxSchema
			cpSc.SyntheticSource = true
			idxSchema = &cpSc
		}
	}

	hasStoredNone := false
	storedRequestsSource := false
	storedRequestsIgnored := false
	var filteredSFSpecs []esast.FieldRequestSpec
	var accessedFields []string

	for _, sf := range storedFields {
		sf = strings.TrimSpace(sf)
		if sf == "" {
			continue
		}
		if sf == "_none_" {
			hasStoredNone = true
			continue
		}
		if sf == "_source" {
			storedRequestsSource = true
			accessedFields = append(accessedFields, "_source")
			continue
		}
		if sf == "_ignored" {
			storedRequestsIgnored = true
			continue
		}
		if sf == "_routing" {
			accessedFields = append(accessedFields, "_routing")
			continue
		}
		if sf == "_size" {
			if idxSchema != nil {
				if _, ok := idxSchema.Fields["_size"]; ok || (idxSchema.RawMapping != nil && schema.IsSizeMetadataEnabled(idxSchema.RawMapping)) {
					targetMap["_size"] = int64(len(hit.EffectiveSource()))
					accessedFields = append(accessedFields, "_size")
				}
			}
			continue
		}
		// Wildcard or explicit stored field check against `store: true` in idxSchema.
		if strings.ContainsAny(sf, "*?") {
			if idxSchema != nil {
				for fPath := range idxSchema.Fields {
					if matchWildcardPattern(sf, fPath) && isFieldExplicitlyStoredInSchemaR61CRUD(idxSchema, fPath) {
						filteredSFSpecs = append(filteredSFSpecs, esast.FieldRequestSpec{Field: fPath})
						accessedFields = append(accessedFields, fPath)
					}
				}
			}
		} else if isFieldExplicitlyStoredInSchemaR61CRUD(idxSchema, sf) {
			filteredSFSpecs = append(filteredSFSpecs, esast.FieldRequestSpec{Field: sf})
			accessedFields = append(accessedFields, sf)
		}
	}

	// `_source` suppression rule (`get/20_stored_fields.yml` & `mget/20_stored_fields.yml`):
	// When `stored_fields` was explicitly passed (and non-empty), omit `_source` UNLESS
	// `_source` was ALSO explicitly requested via `_source` / `_source_includes` / `_source_excludes`
	// OR `"_source"` was listed inside `stored_fields`!
	wantSource := true
	if effSF != nil && effSF.Disabled {
		wantSource = false
	} else if hasStoredNone {
		wantSource = hasExplicitSource || storedRequestsSource
	} else if hasExplicitStoredFields && len(storedFields) > 0 {
		wantSource = hasExplicitSource || storedRequestsSource
	}

	if wantSource {
		rawSrcForFetch := hit.Source
		if idxSchema != nil && idxSchema.SyntheticSource {
			if synSrc := reconstructHitSyntheticSourceR61Search(hit.Source, idxSchema); synSrc != nil {
				rawSrcForFetch = synSrc
			}
		}
		if filteredSrc, ok := filterDocumentSourceRound59(rawSrcForFetch, idxSchema, effSF); ok {
			targetMap["_source"] = filteredSrc
			accessedFields = append(accessedFields, "_source")
		}
	}

	if len(accessedFields) > 0 {
		recordFieldUsageAccessRound61(s, []string{indexName}, accessedFields)
	}

	if !hasStoredNone && len(filteredSFSpecs) > 0 {
		if fm := extractHitFieldsMap(hit, indexName, &esast.SearchRequest{Fields: filteredSFSpecs}, idxSchema); len(fm) > 0 {
			targetMap["fields"] = fm
		}
	}

	if storedRequestsIgnored {
		// Upstream `get/120_stored_fields_ignored.yml`: `_ignored` on GET / MGET is ONLY returned when
		// `_ignored` is requested in `stored_fields` (`_ignored: [...]`, or `_ignored: null` when none)!
		ignoredList := computeDocIgnoredFieldsR61CRUD(idxSchema, hit.Source)
		if len(ignoredList) > 0 {
			targetMap["_ignored"] = ignoredList
		} else {
			targetMap["_ignored"] = nil
		}
	}
}

func validateMGetRawBodyR61CRUD(s *Server, r *http.Request, rawBody []byte) (
	bodyRealtime *bool,
	hasTopSource bool,
	hasTopStored bool,
	docHasExplicitSource map[int]bool,
	docHasExplicitStored map[int]bool,
	status int,
	errType string,
	errReason string,
) {
	docHasExplicitSource = make(map[int]bool)
	docHasExplicitStored = make(map[int]bool)
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		return nil, false, false, docHasExplicitSource, docHasExplicitStored, 0, "", ""
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil {
		return nil, false, false, docHasExplicitSource, docHasExplicitStored, 0, "", ""
	}
	isES8 := s.isES8Mode(r)

	if rtVal, hasRT := root["realtime"]; hasRT && rtVal != nil {
		b, ok := parseOptionalBoolAny(rtVal)
		if !ok {
			return nil, false, false, nil, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Failed to parse value [%v] as only [true] or [false] are allowed.", rtVal)
		}
		bodyRealtime = &b
	}
	_, hasSrc := root["_source"]
	_, hasSrcInc := root["_source_includes"]
	_, hasSrcExc := root["_source_excludes"]
	hasTopSource = hasSrc || hasSrcInc || hasSrcExc
	_, hasTopStored = root["stored_fields"]

	if docsSlice, ok := root["docs"].([]any); ok {
		for i, rawItem := range docsSlice {
			dm, okM := rawItem.(map[string]any)
			if !okM || dm == nil {
				continue
			}
			// Upstream `mget/80_deprecated.yml`: `_routing`, `_version`, `_version_type` fail in ES 7 & ES 8; `_type` fails in ES 8!
			for _, removedField := range []string{"_routing", "_version", "_version_type"} {
				if _, hasRemoved := dm[removedField]; hasRemoved {
					return nil, false, false, nil, nil, http.StatusBadRequest, "parsing_exception",
						fmt.Sprintf("[multi_get] unknown field [%s], parser not found", removedField)
				}
			}
			if isES8 {
				if _, hasType := dm["_type"]; hasType {
					return nil, false, false, nil, nil, http.StatusBadRequest, "parsing_exception",
						"[multi_get] unknown field [_type], parser not found"
				}
			}
			_, dSrc := dm["_source"]
			_, dInc := dm["_source_includes"]
			_, dExc := dm["_source_excludes"]
			if dSrc || dInc || dExc {
				docHasExplicitSource[i] = true
			}
			if _, dSF := dm["stored_fields"]; dSF {
				docHasExplicitStored[i] = true
			}
		}
	}
	return bodyRealtime, hasTopSource, hasTopStored, docHasExplicitSource, docHasExplicitStored, 0, "", ""
}

// ============================================================================
// F8: Stateful Reusable `scroll_id` with Snapshot Isolation & `_msearch` Error `index`
// ============================================================================

func (s *Server) snapshotMaxSeqNoByIndexR61CRUD(rawIndex string) map[string]int64 {
	targets, _ := s.resolveTargetIndicesWithOptions(rawIndex, true)
	out := make(map[string]int64, len(targets))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, idx := range targets {
		if _, exists := s.indices[idx]; !exists {
			continue
		}
		// `indexNextSeqNo[idx]` is the NEXT seq_no to be allocated (so existing docs have seq_no < nextSeq, i.e., <= nextSeq-1).
		nextSeq := int64(0)
		if s.indexNextSeqNo != nil {
			nextSeq = s.indexNextSeqNo[idx]
		}
		out[idx] = nextSeq - 1
	}
	return out
}

func (s *Server) registerStatefulScrollR61CRUD(initialToken, rawIndex string, req *esast.SearchRequest, lastSort []any, total, fetched int64, exhausted bool, ttl time.Duration) {
	if initialToken == "" {
		return
	}
	nonce := scrollSessionNonceSeqR62Admin.Add(1)
	uniqueToken := attachScrollSessionNonceR62Admin(initialToken, nonce)
	s.registerInitialScrollContext(uniqueToken, ttl)
	var reqCopy esast.SearchRequest
	if req != nil {
		reqCopy = *req
	}
	nowMs := time.Now().UnixMilli()
	expMs := int64(0)
	if ttl > 0 {
		expMs = time.Now().Add(ttl).UnixMilli()
	}
	sess := &scrollSessionStateR61CRUD{
		SessionNonce:    nonce,
		Index:           rawIndex,
		Req:             reqCopy,
		LastSort:        append([]any(nil), lastSort...),
		Total:           total,
		FetchedCount:    fetched,
		Exhausted:       exhausted,
		MaxSeqNoByIndex: s.snapshotMaxSeqNoByIndexR61CRUD(rawIndex),
		Tokens:          []string{uniqueToken},
		ExpiresAtMs:     expMs,
	}
	st := getOrCreateServerStateR61CRUD(s)
	st.mu.Lock()
	sweepExpiredScrollSessionsLockedR62Admin(st, nowMs)
	st.scrollSessions[uniqueToken] = sess
	st.openScrollList = append(st.openScrollList, sess)
	if st.pendingScrollTokens == nil {
		st.pendingScrollTokens = make(map[string][]string)
	}
	q := append(st.pendingScrollTokens[initialToken], uniqueToken)
	if len(q) > 64 {
		q = q[len(q)-64:]
	}
	st.pendingScrollTokens[initialToken] = q
	st.mu.Unlock()
}

func (s *Server) clearStatefulScrollR61CRUD(ids []string, clearAll bool) (bool, int) {
	st := getOrCreateServerStateR61CRUD(s)
	nowMs := time.Now().UnixMilli()
	st.mu.Lock()
	sweepExpiredScrollSessionsLockedR62Admin(st, nowMs)
	if clearAll {
		for _, sess := range st.openScrollList {
			if sess != nil {
				sess.Cleared = true
			}
		}
		for _, sess := range st.scrollSessions {
			if sess != nil {
				sess.Cleared = true
			}
		}
		st.openScrollList = nil
		st.scrollSessions = make(map[string]*scrollSessionStateR61CRUD)
		st.pendingScrollTokens = make(map[string][]string)
	} else {
		for _, id := range ids {
			if sess := st.scrollSessions[id]; sess != nil {
				sess.Cleared = true
				for _, tk := range sess.Tokens {
					if st.scrollSessions[tk] == sess {
						delete(st.scrollSessions, tk)
					}
				}
			}
		}
		if len(st.openScrollList) > 0 {
			kept := st.openScrollList[:0]
			for _, sess := range st.openScrollList {
				if sess != nil && !sess.Cleared {
					kept = append(kept, sess)
				}
			}
			st.openScrollList = kept
		}
	}
	st.mu.Unlock()
	return s.clearScrollTokens(ids, clearAll)
}

func (s *Server) filterScrollHitsBySnapshotSeqNoR61CRUD(resp map[string]any, maxSeqByIdx map[string]int64) (filteredCount int, lastRawSort []any) {
	if resp == nil {
		return 0, nil
	}
	hitsMap, ok := resp["hits"].(map[string]any)
	if !ok {
		return 0, nil
	}
	lastRawSort = extractLastHitSort(resp)
	if len(maxSeqByIdx) == 0 {
		return extractRespReturnedHitsCount(resp), lastRawSort
	}

	keepHit := func(hm map[string]any) bool {
		if hm == nil {
			return false
		}
		idxName, _ := hm["_index"].(string)
		docID, _ := hm["_id"].(string)
		maxSeq, tracked := maxSeqByIdx[idxName]
		if !tracked {
			return false
		}
		ver := int64(1)
		if v, okV := toInt64(hm["_version"]); okV && v > 0 {
			ver = v
		}
		curSeq := s.getDocSeqNo(idxName, docID, ver)
		return curSeq <= maxSeq
	}

	switch hs := hitsMap["hits"].(type) {
	case []map[string]any:
		kept := make([]map[string]any, 0, len(hs))
		for _, hm := range hs {
			if keepHit(hm) {
				kept = append(kept, hm)
			}
		}
		hitsMap["hits"] = kept
		if len(kept) == 0 {
			hitsMap["max_score"] = nil
		}
		return len(kept), lastRawSort
	case []any:
		kept := make([]any, 0, len(hs))
		for _, item := range hs {
			if hm, okM := item.(map[string]any); okM && keepHit(hm) {
				kept = append(kept, hm)
			}
		}
		hitsMap["hits"] = kept
		if len(kept) == 0 {
			hitsMap["max_score"] = nil
		}
		return len(kept), lastRawSort
	}
	return 0, lastRawSort
}

func (s *Server) executeStatefulScrollR61CRUD(w http.ResponseWriter, r *http.Request, scrollID string, extendTTL time.Duration) {
	st := getOrCreateServerStateR61CRUD(s)
	nowMs := time.Now().UnixMilli()
	st.mu.Lock()
	sweepExpiredScrollSessionsLockedR62Admin(st, nowMs)
	sess := st.scrollSessions[scrollID]
	st.mu.Unlock()

	validatedStateless := false
	if sess == nil {
		cursor, ok := decodeScrollCursor(scrollID)
		if !ok {
			writeESError(w, http.StatusNotFound, "search_context_missing_exception", "No search context found for id ["+scrollID+"]")
			return
		}
		// Check activeScrolls expiry BEFORE inserting into st.scrollSessions so expired/forged stateless probes never leak memory!
		if !s.validateAndAdvanceScrollToken(scrollID, "", extendTTL) {
			writeESError(w, http.StatusNotFound, "search_context_missing_exception", "No search context found for id ["+scrollID+"]")
			return
		}
		validatedStateless = true
		expMs := int64(0)
		if extendTTL > 0 {
			expMs = time.Now().Add(extendTTL).UnixMilli()
		}
		sess = &scrollSessionStateR61CRUD{
			SessionNonce: scrollSessionNonceSeqR62Admin.Add(1),
			Index:        cursor.Index,
			Req:          cursor.Req,
			LastSort:     append([]any(nil), cursor.LastSort...),
			Total:        cursor.Total,
			FetchedCount: cursor.FetchedCount,
			Exhausted:    cursor.Exhausted,
			Tokens:       []string{scrollID},
			ExpiresAtMs:  expMs,
		}
		st.mu.Lock()
		st.scrollSessions[scrollID] = sess
		st.openScrollList = append(st.openScrollList, sess)
		st.mu.Unlock()
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.Cleared || (sess.ExpiresAtMs > 0 && time.Now().UnixMilli() > sess.ExpiresAtMs) {
		sess.Cleared = true
		st.mu.Lock()
		for _, tk := range sess.Tokens {
			if st.scrollSessions[tk] == sess {
				delete(st.scrollSessions, tk)
			}
		}
		st.mu.Unlock()
		writeESError(w, http.StatusNotFound, "search_context_missing_exception", "No search context found for id ["+scrollID+"]")
		return
	}

	// Validate that the scroll context is still alive (neither cleared nor expired),
	// refreshing only `sess.Tokens[0]` in `s.activeScrolls` so 1 session == 1 `num_freed`.
	rootToken := sess.Tokens[0]
	if !validatedStateless && !s.validateAndAdvanceScrollToken(rootToken, "", extendTTL) {
		sess.Cleared = true
		st.mu.Lock()
		for _, tk := range sess.Tokens {
			if st.scrollSessions[tk] == sess {
				delete(st.scrollSessions, tk)
			}
		}
		st.mu.Unlock()
		writeESError(w, http.StatusNotFound, "search_context_missing_exception", "No search context found for id ["+scrollID+"]")
		return
	}
	if extendTTL > 0 {
		sess.ExpiresAtMs = time.Now().Add(extendTTL).UnixMilli()
	}

	writeEOFPage := func() {
		eofScrollID := sess.EOFScrollID
		if eofScrollID == "" {
			eofScrollID = attachScrollSessionNonceR62Admin(
				encodeScrollCursorWithFetched(sess.Index, &sess.Req, nil, sess.Total, sess.FetchedCount, true),
				sess.SessionNonce,
			)
			sess.EOFScrollID = eofScrollID
			_ = s.validateAndAdvanceScrollToken(rootToken, eofScrollID, extendTTL)
			if eofScrollID != "" {
				st.mu.Lock()
				appendBoundedScrollTokenLockedR62Admin(st, sess, eofScrollID)
				st.mu.Unlock()
			}
		} else {
			_ = s.validateAndAdvanceScrollToken(rootToken, "", extendTTL)
		}
		sess.Exhausted = true
		sess.LastSort = nil
		eofRel := "eq"
		if thresh, okT := trackTotalHitsThreshold(&sess.Req); okT && thresh > 0 && sess.Total >= thresh {
			eofRel = "gte"
		}
		eofTotal := any(map[string]any{"value": sess.Total, "relation": eofRel})
		if !sess.Req.ShouldTrackTotalHits() {
			eofTotal = nil
		}
		if isTruthyBoolQueryParam(r, "rest_total_hits_as_int") {
			if !sess.Req.ShouldTrackTotalHits() {
				eofTotal = int64(-1)
			} else {
				eofTotal = sess.Total
			}
		}
		hitsMap := map[string]any{
			"max_score": nil,
			"hits":      []any{},
		}
		if eofTotal != nil {
			hitsMap["total"] = eofTotal
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"_scroll_id": eofScrollID,
			"took":       1,
			"timed_out":  false,
			"_shards":    map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
			"hits":       hitsMap,
		})
	}

	if sess.Exhausted || len(sess.LastSort) == 0 {
		writeEOFPage()
		return
	}

	pageSize := 10
	if sess.Req.Size != nil && *sess.Req.Size > 0 {
		pageSize = *sess.Req.Size
	}

	// Fetch pages, skipping any post-scroll mutated docs (`seq_no > maxSeqNo`), until we gather up to `pageSize` snapshot-visible hits or exhaust the index!
	var collectedHits []any
	var maxScoreVal any
	var finalResp map[string]any
	curAfter := append([]any(nil), sess.LastSort...)
	for len(collectedHits) < pageSize && len(curAfter) > 0 {
		req := sess.Req
		zero := 0
		need := pageSize - len(collectedHits)
		req.From = &zero
		req.Size = &need
		req.SearchAfter = curAfter
		req.Aggs = nil
		req.Aggregations = nil
		req.Suggest = nil

		resp, status, errType, errReason := s.executeSearchRequest(r.Context(), sess.Index, &req)
		if errType != "" {
			writeESError(w, status, errType, errReason)
			return
		}
		rawReturned := extractRespReturnedHitsCount(resp)
		keptCnt, rawLastSort := s.filterScrollHitsBySnapshotSeqNoR61CRUD(resp, sess.MaxSeqNoByIndex)
		if finalResp == nil {
			finalResp = resp
			if hm, okH := resp["hits"].(map[string]any); okH {
				maxScoreVal = hm["max_score"]
			}
		}
		if keptCnt > 0 {
			if hm, okH := resp["hits"].(map[string]any); okH {
				switch hs := hm["hits"].(type) {
				case []map[string]any:
					for _, h := range hs {
						collectedHits = append(collectedHits, h)
					}
				case []any:
					collectedHits = append(collectedHits, hs...)
				}
			}
		}
		curAfter = rawLastSort
		if rawReturned < need || len(rawLastSort) == 0 {
			if keptCnt == 0 && len(collectedHits) == 0 {
				curAfter = nil
			}
			break
		}
	}

	if finalResp == nil {
		writeEOFPage()
		return
	}
	if hm, okH := finalResp["hits"].(map[string]any); okH {
		hm["hits"] = collectedHits
		if len(collectedHits) == 0 {
			hm["max_score"] = nil
		} else if maxScoreVal != nil {
			hm["max_score"] = maxScoreVal
		}
	}

	total := sess.Total
	if sess.Req.ShouldTrackTotalHits() {
		remaining := total - sess.FetchedCount
		if remaining < 0 {
			remaining = 0
		}
		if int64(len(collectedHits)) > remaining {
			trimRespHitsToMax(finalResp, int(remaining))
			collectedHits = collectedHits[:int(remaining)]
		}
		if hitsMap, okH := finalResp["hits"].(map[string]any); okH {
			rel := "eq"
			if thresh, okT := trackTotalHitsThreshold(&sess.Req); okT && thresh > 0 && total >= thresh {
				rel = "gte"
			}
			hitsMap["total"] = map[string]any{"value": total, "relation": rel}
			if len(collectedHits) == 0 {
				hitsMap["max_score"] = nil
			}
		}
	}

	returnedNow := int64(len(collectedHits))
	nextFetched := sess.FetchedCount + returnedNow
	exhausted := len(curAfter) == 0 || returnedNow == 0 || (sess.Req.ShouldTrackTotalHits() && nextFetched >= total)
	nextScrollID := attachScrollSessionNonceR62Admin(
		encodeScrollCursorWithFetched(sess.Index, &sess.Req, curAfter, total, nextFetched, exhausted),
		sess.SessionNonce,
	)
	_ = s.validateAndAdvanceScrollToken(rootToken, nextScrollID, extendTTL)

	sess.LastSort = curAfter
	sess.FetchedCount = nextFetched
	sess.Exhausted = exhausted
	if exhausted && sess.EOFScrollID == "" {
		sess.EOFScrollID = nextScrollID
	}
	if nextScrollID != "" {
		st.mu.Lock()
		appendBoundedScrollTokenLockedR62Admin(st, sess, nextScrollID)
		st.mu.Unlock()
	}

	finalResp["_scroll_id"] = nextScrollID
	s.applyDocTypeToSearchResponseRound60(finalResp, r)
	if isTruthyBoolQueryParam(r, "rest_total_hits_as_int") {
		applyRestTotalHitsAsInt(finalResp, &sess.Req)
	}
	writeJSONWithRequest(w, r, http.StatusOK, finalResp)
}

func (s *Server) buildMSearchErrItemR61CRUD(status int, eType, eReason, idxName string) map[string]any {
	rc := map[string]any{
		"type":   eType,
		"reason": eReason,
	}
	errObj := map[string]any{
		"type":   eType,
		"reason": eReason,
	}
	if strings.TrimSpace(idxName) != "" {
		cleanIdx := strings.TrimSpace(idxName)
		if comma := strings.IndexByte(cleanIdx, ','); comma > 0 {
			cleanIdx = strings.TrimSpace(cleanIdx[:comma])
		}
		uuid := "_na_"
		if s != nil {
			s.mu.RLock()
			if _, ok := s.indices[cleanIdx]; ok {
				uuid = catIndexUUID22(cleanIdx)
			}
			s.mu.RUnlock()
		}
		rc["index_uuid"] = uuid
		rc["index"] = cleanIdx
		errObj["index_uuid"] = uuid
		errObj["index"] = cleanIdx
	}
	errObj["root_cause"] = []map[string]any{rc}
	return map[string]any{
		"status": status,
		"error":  errObj,
	}
}

// ============================================================================
// F12, F14, F20-F23, F26-F28: ES 8 Dynamic Mapping, AutoDims, TSDB Write,
//     UBQ/DBQ Immutability & Painless Update Fields API
// ============================================================================

func (s *Server) validateAndEvolveExistingIndexR61CRUD(
	ctx context.Context,
	es8Mode bool,
	indexName string,
	idx *schema.IndexSchema,
	sampleDocs []json.RawMessage,
) (*schema.IndexSchema, error) {
	if idx == nil || len(sampleDocs) == 0 {
		return idx, nil
	}
	effES8 := es8Mode || idx.ES8Mode
	if nextRaw, added := applyDynamicRuntimeInferenceRound59(sampleDocs, idx.RawMapping); added {
		cand := schema.CompileIndexSchema(s.dorisDB, indexName, nextRaw)
		cand.CopyIndexMappingSettingsFrom(idx)
		cand.ES8Mode = effES8
		if err := schema.ValidateMappingLimits(cand, nextRaw); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.indices[indexName] = cand
		s.mu.Unlock()
		s.persistIndex(ctx, indexName, cand)
		s.queryCache.InvalidateAll()
		idx = cand
	} else if idx.RawMapping == nil || idx.RawMapping.Dynamic == nil || idx.RawMapping.Dynamic == true || idx.RawMapping.Dynamic == "true" {
		inferred := schema.InferMappingFromSampleDocsWithES8(sampleDocs, effES8, idx.RawMapping)
		s.recordDynamicallyInferredFieldsWave3R63(indexName, idx.RawMapping, inferred, sampleDocs)
		mergedPreview := schema.MergeMappingSpecs(inferred, idx.RawMapping)
		if err := schema.ValidateMappingSpec(mergedPreview); err != nil {
			return nil, err
		}
		if err := schema.ValidateMappingLimits(idx, mergedPreview); err != nil {
			return nil, err
		}
		cand := schema.CompileIndexSchema(s.dorisDB, indexName, mergedPreview)
		cand.CopyIndexMappingSettingsFrom(idx)
		cand.ES8Mode = effES8
		alterStmts := schema.GenerateAlterTableDDL(idx, cand)
		if len(cand.Fields) > len(idx.Fields) || len(alterStmts) > 0 {
			for _, stmt := range alterStmts {
				_ = s.backend.ExecDDL(ctx, stmt)
			}
			s.mu.Lock()
			s.indices[indexName] = cand
			s.mu.Unlock()
			s.persistIndex(ctx, indexName, cand)
			s.queryCache.InvalidateAll()
			idx = cand
		}
	}
	idxCloneForCK := idx.CloneIndexSchema()
	if updated, err := adoptConstantKeywordValuesFromDocsRound59(idxCloneForCK, sampleDocs); err != nil {
		return nil, err
	} else if updated {
		s.mu.Lock()
		s.indices[indexName] = idxCloneForCK
		s.mu.Unlock()
		idx = idxCloneForCK
		s.persistIndex(ctx, indexName, idx)
		s.queryCache.InvalidateAll()
	}
	if delta := detectArrayPromotions(idx, sampleDocs); delta != nil {
		idx = s.applyArrayPromotionDelta(ctx, indexName, idx, delta)
	}
	return idx, nil
}

func (s *Server) ensureWritableIndexSchemaWithDocsErrR61CRUD(
	ctx context.Context,
	r *http.Request,
	indexName string,
	sampleDocs []json.RawMessage,
) (*schema.IndexSchema, error) {
	es8Mode := s.isES8Mode(r)
	var explicitLegacyType string
	if !es8Mode && r != nil {
		if v, ok := r.Context().Value(legacyDocTypeCtxKey{}).(string); ok && strings.TrimSpace(v) != "" && v != "_doc" {
			explicitLegacyType = strings.TrimSpace(v)
		}
	}

	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok := s.indices[indexName]
	if ok && (len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0) {
		s.mu.RUnlock()
		return s.validateAndEvolveExistingIndexR61CRUD(ctx, es8Mode, indexName, idx, sampleDocs)
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(ctx)

	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok = s.indices[indexName]
	if ok && (len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0) {
		s.mu.RUnlock()
		return s.validateAndEvolveExistingIndexR61CRUD(ctx, es8Mode, indexName, idx, sampleDocs)
	}
	var existingEmptySchema *schema.IndexSchema
	if ok {
		existingEmptySchema = idx
	}
	tplMappings, tplDefPipe, hasTplDefPipe, tplFinPipe, hasTplFinPipe, tplAliases, tplCustomSettings, _ := s.matchingTemplateFullConfigLocked(indexName)
	tplLegacyType, tplHasMap := s.matchingLegacyTemplateTypeLockedR61CRUD(indexName)
	if existingEmptySchema != nil && existingEmptySchema.RawMapping != nil {
		tplMappings = schema.MergeMappingSpecs(tplMappings, existingEmptySchema.RawMapping)
	}
	if s.isDataStreamOrBackingIndexLocked(indexName) {
		tsSpec := &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"@timestamp": {Type: "date"},
			},
		}
		tplMappings = schema.MergeMappingSpecs(tsSpec, tplMappings)
	}
	var curCustomSettings map[string]any
	if existing := s.indexCustomSettings[indexName]; len(existing) > 0 {
		curCustomSettings = make(map[string]any, len(existing))
		for k, v := range existing {
			curCustomSettings[k] = v
		}
	}
	s.mu.RUnlock()

	effectiveMappings := tplMappings
	if len(sampleDocs) > 0 {
		if tplMappings != nil && tplMappings.Dynamic == "runtime" {
			if nextMap, added := applyDynamicRuntimeInferenceRound59(sampleDocs, effectiveMappings); added {
				effectiveMappings = nextMap
			}
		} else if tplMappings == nil || tplMappings.Dynamic == nil || tplMappings.Dynamic == true || tplMappings.Dynamic == "true" {
			inferred := schema.InferMappingFromSampleDocsWithES8(sampleDocs, es8Mode, tplMappings)
			s.recordDynamicallyInferredFieldsWave3R63(indexName, tplMappings, inferred, sampleDocs)
			effectiveMappings = schema.MergeMappingSpecs(inferred, tplMappings)
		}
	}
	if err := schema.ValidateMappingSpec(effectiveMappings); err != nil {
		return nil, err
	}

	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
	compiled.ES8Mode = es8Mode
	if existingEmptySchema != nil {
		compiled.CopyIndexMappingSettingsFrom(existingEmptySchema)
	}
	if compiled.LegacyTypeName == "" {
		if explicitLegacyType != "" {
			compiled.LegacyTypeName = explicitLegacyType
		} else if tplHasMap && tplLegacyType != "" {
			compiled.LegacyTypeName = tplLegacyType
		}
	}
	if len(tplCustomSettings) > 0 {
		if err := parseAndApplyIndexMappingSettingsRound59(tplCustomSettings, compiled); err != nil {
			return nil, err
		}
		if mode, rp, stTime, etTime, tsErr := schema.ExtractTSDBSettings(tplCustomSettings); tsErr != nil {
			return nil, tsErr
		} else if mode == "time_series" {
			compiled.IndexMode = "time_series"
			compiled.RoutingPath = rp
			compiled.TimeSeriesStartTime = stTime
			compiled.TimeSeriesEndTime = etTime
			compiled.SyntheticSource = true
		}
	}
	if len(curCustomSettings) > 0 {
		if err := parseAndApplyIndexMappingSettingsRound59(curCustomSettings, compiled); err != nil {
			return nil, err
		}
		if mode, rp, stTime, etTime, tsErr := schema.ExtractTSDBSettings(curCustomSettings); tsErr != nil {
			return nil, tsErr
		} else if mode == "time_series" {
			compiled.IndexMode = "time_series"
			compiled.RoutingPath = rp
			compiled.TimeSeriesStartTime = stTime
			compiled.TimeSeriesEndTime = etTime
			compiled.SyntheticSource = true
		}
	}
	if len(sampleDocs) > 0 {
		if delta := detectArrayPromotions(compiled, sampleDocs); delta != nil {
			prev := compiled
			effectiveMappings = schema.MergeMappingSpecs(effectiveMappings, delta)
			compiled = schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
			compiled.CopyIndexMappingSettingsFrom(prev)
		}
		if err := schema.ValidateMappingLimits(compiled, compiled.RawMapping); err != nil {
			return nil, err
		}
		if _, err := adoptConstantKeywordValuesFromDocsRound59(compiled, sampleDocs); err != nil {
			return nil, err
		}
	}

	_ = s.backend.ExecDDL(ctx, schema.GenerateCreateTableDDL(compiled))
	if existingEmptySchema != nil {
		for _, stmt := range schema.GenerateAlterTableDDL(existingEmptySchema, compiled) {
			_ = s.backend.ExecDDL(ctx, stmt)
		}
	}
	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	if existing, exists := s.indices[indexName]; exists && (len(existing.Fields) > 0 || len(existing.NestedRoots) > 0) {
		s.mu.Unlock()
		return s.validateAndEvolveExistingIndexR61CRUD(ctx, es8Mode, indexName, existing, sampleDocs)
	}
	s.indices[indexName] = compiled
	if existingEmptySchema == nil {
		if hasTplDefPipe && tplDefPipe != "" {
			if _, hasCur := s.indexDefaultPipelines[indexName]; !hasCur {
				s.indexDefaultPipelines[indexName] = tplDefPipe
			}
		}
		if hasTplFinPipe && tplFinPipe != "" {
			if _, hasCur := s.indexFinalPipelines[indexName]; !hasCur {
				s.indexFinalPipelines[indexName] = tplFinPipe
			}
		}
		if len(tplCustomSettings) > 0 {
			if s.indexCustomSettings == nil {
				s.indexCustomSettings = make(map[string]map[string]any)
			}
			if s.indexCustomSettings[indexName] == nil {
				s.indexCustomSettings[indexName] = make(map[string]any)
			}
			for k, v := range tplCustomSettings {
				if k == "default_pipeline" || k == "final_pipeline" || v == nil {
					continue
				}
				if _, exists := s.indexCustomSettings[indexName][k]; !exists {
					s.indexCustomSettings[indexName][k] = normalizeCustomSettingValue(v)
				}
			}
		}
		s.ensureIndexCreationDateLocked(indexName)
		for alias, rawMeta := range tplAliases {
			meta := parseAliasMetadata(rawMeta)
			s.addAliasWithMetaLocked(alias, indexName, meta)
			aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
		}
	}
	s.mu.Unlock()
	s.persistIndex(ctx, indexName, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(ctx, alias, targets)
	}
	s.queryCache.InvalidateAll()
	return compiled, nil
}

func snapshotAutoDimsFieldsR61CRUD(idxSchema *schema.IndexSchema) map[string]bool {
	if idxSchema == nil {
		return nil
	}
	var out map[string]bool
	for fPath, fb := range idxSchema.Fields {
		if fb.AutoDims && fb.VectorDims == 0 {
			if out == nil {
				out = make(map[string]bool)
			}
			out[fPath] = true
		}
	}
	return out
}

func (s *Server) shredDocumentAndPersistAutoDimsR61CRUD(
	ctx context.Context,
	indexName string,
	idxSchema *schema.IndexSchema,
	docID string,
	nextVer int64,
	isDelete bool,
	docPayload json.RawMessage,
) ([]byte, error) {
	preAuto := snapshotAutoDimsFieldsR61CRUD(idxSchema)
	shredded, err := schema.ShredDocument(idxSchema, docID, nextVer, isDelete, docPayload)
	if err != nil {
		return nil, err
	}
	if len(preAuto) > 0 && idxSchema != nil {
		lockedAny := false
		for fPath := range preAuto {
			if fb, ok := idxSchema.Fields[fPath]; ok && !fb.AutoDims && fb.VectorDims > 0 {
				lockedAny = true
				break
			}
		}
		if lockedAny {
			s.persistIndex(ctx, indexName, idxSchema)
			s.queryCache.InvalidateAll()
		}
	}
	return shredded, nil
}

// prepareTSDBDocWriteR61CRUD validates TSDB write constraints (`ValidateTSDBDocID`, explicit routing rejection,
// `ComputeTSDBIdentityWithRoutingHash`) and returns the deterministic `_id` and `_ts_routing_hash` (`F14`).
func (s *Server) prepareTSDBDocWriteR61CRUD(
	idxSchema *schema.IndexSchema,
	indexName, explicitDocID, explicitRouting string,
	rawDoc json.RawMessage,
) (docID string, routingHash string, status int, errType string, errReason string) {
	if idxSchema == nil || idxSchema.IndexMode != "time_series" {
		return explicitDocID, explicitRouting, 0, "", ""
	}
	if strings.TrimSpace(explicitRouting) != "" {
		return "", "", http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("specifying routing is not supported because the destination index [%s] is in time series mode", indexName)
	}
	if explicitDocID != "" {
		if err := schema.ValidateTSDBDocID(explicitDocID, indexName); err != nil {
			et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
			return "", "", http.StatusBadRequest, et, er
		}
	}
	var docMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if err := dec.Decode(&docMap); err != nil {
		return "", "", http.StatusBadRequest, "mapper_parsing_exception", err.Error()
	}
	var idxSettings map[string]any
	if s != nil {
		s.mu.RLock()
		if cust := s.indexCustomSettings[indexName]; len(cust) > 0 {
			idxSettings = make(map[string]any, len(cust))
			for k, v := range cust {
				idxSettings[k] = v
			}
		}
		s.mu.RUnlock()
	}
	if len(idxSchema.RoutingPath) > 0 && !docHasAnyTSDBRoutingPathFieldR63(idxSchema.RoutingPath, docMap) {
		return "", "", http.StatusBadRequest, "mapper_parsing_exception",
			"Error extracting routing: source didn't contain any routing fields"
	}
	_, detID, _, rHash, err := schema.ComputeTSDBIdentityWithRoutingHash(idxSchema, docMap, idxSettings)
	if err != nil {
		et, er := splitSchemaErrorPrefixR61CRUD(err, "mapper_parsing_exception")
		return "", "", http.StatusBadRequest, et, er
	}
	if explicitDocID != "" && explicitDocID != detID {
		return "", "", http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("explicit id [%s] does not match generated time series id [%s] for index [%s]", explicitDocID, detID, indexName)
	}
	return detID, rHash, 0, "", ""
}

// applyUpdateDocWithFieldsAPIR61CRUD executes `_update` / bulk `update` / `_update_by_query`
// using `EvalUpdateScriptWithFieldsAPIRound61` when a Painless script is provided (`F26`, `F28`).
func applyUpdateDocWithFieldsAPIR61CRUD(
	baseSource json.RawMessage,
	updReq *painless.UpdateRequest,
	found bool,
	routingRequired bool,
	isUBQ bool,
	isES8 bool,
) (json.RawMessage, string, error) {
	if updReq == nil {
		return baseSource, "updated", nil
	}
	if updReq.Script == nil || strings.TrimSpace(updReq.Script.EffectiveSource()) == "" {
		if isUBQ {
			// Touch/reindex UBQ (`update_by_query` with no script) re-indexes matched documents!
			return baseSource, "updated", nil
		}
		return painless.ApplyUpdateWithResult(baseSource, updReq, found)
	}

	// Non-scripted_upsert insert path: when document does not exist and scripted_upsert is false,
	// ES inserts `upsert` directly without running `script`!
	if !found && !updReq.ScriptedUpsert {
		if updReq.Upsert != nil {
			rawUpsert, err := json.Marshal(updReq.Upsert)
			if err != nil {
				return nil, "", err
			}
			return rawUpsert, "created", nil
		}
		return painless.ApplyUpdateWithResult(baseSource, updReq, found)
	}

	docMap := make(map[string]any)
	if found && len(bytes.TrimSpace(baseSource)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(baseSource))
		dec.UseNumber()
		if err := dec.Decode(&docMap); err != nil {
			return nil, "", err
		}
	} else if !found && updReq.Upsert != nil {
		rawUp, err := json.Marshal(updReq.Upsert)
		if err == nil {
			dec := json.NewDecoder(bytes.NewReader(rawUp))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
		}
	}
	if docMap == nil {
		docMap = make(map[string]any)
	}

	lang := strings.ToLower(strings.TrimSpace(updReq.Script.Lang))
	if lang != "" && lang != "painless" {
		return nil, "", fmt.Errorf("illegal_argument_exception: script_lang not supported [%s]", updReq.Script.Lang)
	}
	srcCode := updReq.Script.EffectiveSource()
	if err := painless.CompileValidate(srcCode); err != nil {
		return nil, "", err
	}

	origID := updReq.MetaID
	origRouting := updReq.MetaRouting
	params := make(map[string]any, len(updReq.Script.Params)+12)
	for k, v := range updReq.Script.Params {
		params[k] = v
	}
	params["_ctx_id"] = origID
	params["_ctx_index"] = updReq.MetaIndex
	if updReq.MetaVersion != 0 {
		params["_ctx_version"] = updReq.MetaVersion
	} else {
		params["_ctx_version"] = int64(1)
	}
	if origRouting != "" {
		params["_ctx_routing"] = origRouting
	}
	params["__is_ubq"] = isUBQ
	params["__is_update_doc"] = !isUBQ
	params["__is_es8"] = isES8
	params["__mutable_fields_api"] = true
	if !found {
		params["__upsert_insert_mode"] = true
		if routingRequired && origRouting == "" {
			params["__upsert_forbid_routing"] = true
		}
	}

	origVer := params["_ctx_version"]
	op, err := painless.EvalPainlessWithOp(docMap, srcCode, params)
	if err != nil {
		if !isUBQ && strings.Contains(err.Error(), "Cannot modify _id in update script") {
			return nil, "", fmt.Errorf("script_exception: Cannot modify _id in update script")
		}
		return nil, "", err
	}
	if op == "" {
		op = "index"
	}

	mutatedID := origID
	if idVal, ok := params["_ctx_id"]; ok && idVal != nil {
		mutatedID = fmt.Sprintf("%v", idVal)
	}
	if !isUBQ && mutatedID != origID {
		return nil, "", fmt.Errorf("script_exception: Cannot modify _id in update script")
	}
	if isUBQ && mutatedID != "" {
		updReq.MetaID = mutatedID
	}
	if idxVal, ok := params["_ctx_index"]; ok && idxVal != nil {
		if idxStr := fmt.Sprintf("%v", idxVal); idxStr != "" {
			updReq.MetaIndex = idxStr
		}
	}
	mutatedRouting := ""
	if rVal, ok := params["_ctx_routing"]; ok && rVal != nil {
		mutatedRouting = fmt.Sprintf("%v", rVal)
	}
	if !found {
		if err := painless.CheckUpsertRoutingGuardRound61(routingRequired, origRouting, "", mutatedRouting, false); err != nil {
			return nil, "", err
		}
	} else if routingRequired && origRouting == "" && mutatedRouting == "" {
		return nil, "", fmt.Errorf("routing_missing_exception: routing is required")
	}
	updReq.MetaRouting = mutatedRouting

	versionMutated := fmt.Sprintf("%v", params["_ctx_version"]) != fmt.Sprintf("%v", origVer)
	if err := painless.ValidateUBQAndUpdateCtx(
		map[string]any{
			"_source":  docMap,
			"_id":      origID,
			"_index":   params["_ctx_index"],
			"_version": params["_ctx_version"],
			"op":       op,
		},
		origID,
		isUBQ,
		isES8,
		versionMutated,
	); err != nil {
		return nil, "", err
	}

	switch op {
	case "none", "noop":
		if found {
			return baseSource, "noop", nil
		}
		return nil, "noop", nil
	case "delete":
		return nil, "deleted", nil
	case "create":
		marshaled, mErr := json.Marshal(docMap)
		if mErr != nil {
			return nil, "", painless.ErrSelfReferencingIterable
		}
		return marshaled, "created", nil
	default:
		marshaled, mErr := json.Marshal(docMap)
		if mErr != nil {
			return nil, "", painless.ErrSelfReferencingIterable
		}
		if found {
			return marshaled, "updated", nil
		}
		return marshaled, "created", nil
	}
}

var allowedUpdateBodyKeysR61CRUD = []string{
	"doc",
	"doc_as_upsert",
	"script",
	"scripted_upsert",
	"upsert",
	"detect_noop",
	"_source",
	"_source_includes",
	"_source_excludes",
	"fields",
	"lang",
}

// validateUpdateBodyFieldsR61CRUD validates top-level UpdateRequest JSON keys (`update/90_error.yml`)
// while permitting valid `_source_includes`, `_source_excludes`, and `fields` options.
func validateUpdateBodyFieldsR61CRUD(rawBody []byte) (int, string, string) {
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		return 0, "", ""
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return 0, "", ""
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, "", ""
	}
	for dec.More() {
		kt, kErr := dec.Token()
		if kErr != nil {
			break
		}
		key, ok := kt.(string)
		if !ok {
			break
		}
		allowed := false
		for _, a := range allowedUpdateBodyKeysR61CRUD {
			if key == a {
				allowed = true
				break
			}
		}
		if !allowed {
			if suggestion := closestFieldSuggestionRound61(key, allowedUpdateRequestTopFieldsRound61); suggestion != "" {
				return http.StatusBadRequest, "x_content_parse_exception",
					fmt.Sprintf("[UpdateRequest] unknown field [%s] did you mean [%s]?", key, suggestion)
			}
			return http.StatusBadRequest, "x_content_parse_exception",
				fmt.Sprintf("[UpdateRequest] unknown field [%s]", key)
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			break
		}
	}
	return 0, "", ""
}

// validateBulkDeprecatedParamsR61CRUD validates ES 7/8 removed bulk action metadata parameters
// (`_version`, `_routing`, `_parent`, `parent`, `retryOnConflict`, plus `_type`/`?type=` in ES 8)
// while allowing valid `"op_type"` (on `"index"`) and `"_source"` / `"_source_includes"` / `"_source_excludes"`.
func (s *Server) validateBulkDeprecatedParamsR61CRUD(r *http.Request, rawBulk []byte) (int, string, string) {
	isES8 := s == nil || s.isES8Mode(r)
	if isES8 && r != nil && r.URL != nil {
		if r.URL.Path != "" && strings.Count(strings.Trim(r.URL.Path, "/"), "/") >= 2 {
			segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(segs) == 3 && segs[2] == "_bulk" {
				return http.StatusBadRequest, "illegal_argument_exception",
					"Action/metadata line [1] contains an unknown parameter [_type]"
			}
		}
		if r.URL.Query().Has("type") {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [%s] contains unrecognized parameter: [type]", r.URL.Path)
		}
	}
	rawLines := bytes.Split(rawBulk, []byte{'\n'})
	lineNo := 0
	for i := 0; i < len(rawLines); i++ {
		trimmed := bytes.TrimSpace(rawLines[i])
		if len(trimmed) == 0 {
			continue
		}
		lineNo++
		var actionEnv map[string]map[string]any
		if err := json.Unmarshal(trimmed, &actionEnv); err != nil {
			continue
		}
		for op, meta := range actionEnv {
			for k := range meta {
				switch k {
				case "_index", "_id", "routing", "pipeline", "version", "version_type",
					"if_seq_no", "if_primary_term", "require_alias", "require_data_stream", "dynamic_templates",
					"_source", "_source_includes", "_source_excludes":
				case "_type":
					if isES8 {
						return http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
					}
				case "op_type":
					if op != "index" {
						return http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
					}
				case "retry_on_conflict", "doc_as_upsert", "detect_noop", "scripted_upsert", "fields":
					if op != "update" {
						return http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
					}
				default:
					return http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
				}
			}
			if op != "delete" {
				i++
				for i < len(rawLines) && len(bytes.TrimSpace(rawLines[i])) == 0 {
					i++
				}
			}
		}
	}
	return 0, "", ""
}

// checkTSDBImmutabilityOnUBQR61CRUD rejects `_update_by_query` mutations to `@timestamp` or
// `time_series_dimension` fields on `index.mode: time_series` indices (`F14`, `F21`).
func checkTSDBImmutabilityOnUBQR61CRUD(idxSchema *schema.IndexSchema, beforeRaw, afterRaw json.RawMessage) error {
	if idxSchema == nil || idxSchema.IndexMode != "time_series" {
		return nil
	}
	var beforeDoc, afterDoc map[string]any
	decB := json.NewDecoder(bytes.NewReader(beforeRaw))
	decB.UseNumber()
	_ = decB.Decode(&beforeDoc)
	decA := json.NewDecoder(bytes.NewReader(afterRaw))
	decA.UseNumber()
	_ = decA.Decode(&afterDoc)

	lookupDot := func(m map[string]any, path string) (any, bool) {
		if m == nil {
			return nil, false
		}
		parts := strings.Split(path, ".")
		var curr any = m
		for i, p := range parts {
			cm, ok := curr.(map[string]any)
			if !ok {
				return nil, false
			}
			if v, exists := cm[p]; exists {
				curr = v
				continue
			}
			if joined := strings.Join(parts[i:], "."); cm[joined] != nil {
				return cm[joined], true
			}
			return nil, false
		}
		return curr, true
	}

	bTS, hasBTS := lookupDot(beforeDoc, "@timestamp")
	aTS, hasATS := lookupDot(afterDoc, "@timestamp")
	if hasBTS != hasATS || fmt.Sprintf("%v", bTS) != fmt.Sprintf("%v", aTS) {
		return fmt.Errorf("[@timestamp] cannot be updated on time_series index [%s]", idxSchema.IndexName)
	}

	for fPath, fb := range idxSchema.Fields {
		if fb.AliasTarget != "" || strings.HasSuffix(fPath, ".keyword") {
			continue
		}
		if fb.TimeSeriesDimension != nil && *fb.TimeSeriesDimension {
			bVal, hasB := lookupDot(beforeDoc, fPath)
			aVal, hasA := lookupDot(afterDoc, fPath)
			if hasB != hasA || fmt.Sprintf("%v", bVal) != fmt.Sprintf("%v", aVal) {
				return fmt.Errorf("time_series_dimension field [%s] cannot be updated on time_series index [%s]", fPath, idxSchema.IndexName)
			}
		}
	}
	return nil
}

// checkByQueryConflictSafeR61CRUD detects optimistic-concurrency conflicts on UBQ/DBQ (`10_basic.yml`)
// while handling unrefreshed brand-new docs (`refresh_interval: -1`) and direct MockBackend test rows.
func (s *Server) checkByQueryConflictSafeR61CRUD(
	indexName, docID string,
	snapVersions, liveSnapVersions map[string]map[string]int64,
) (skipUnrefreshedNew bool, conflicted bool, reason string) {
	if s == nil {
		return false, false, ""
	}
	s.mu.RLock()
	curVer, trackedLive := s.docVersions[indexName][docID]
	var unrefNew bool
	var unrefExistedBefore bool
	if unrefIdx := s.unrefreshedDocs[indexName]; len(unrefIdx) > 0 {
		for _, shardMap := range unrefIdx {
			if st, ok := shardMap[docID]; ok {
				if st.existedBefore {
					unrefExistedBefore = true
				} else {
					unrefNew = true
				}
				break
			}
		}
	}
	refreshDisabled := false
	if cust := s.indexCustomSettings[indexName]; cust != nil {
		for _, rk := range []string{"refresh_interval", "index.refresh_interval"} {
			if v, ok := cust[rk]; ok && strings.TrimSpace(fmt.Sprintf("%v", v)) == "-1" {
				refreshDisabled = true
			}
		}
	}
	s.mu.RUnlock()

	if !trackedLive && curVer == 0 {
		return false, false, ""
	}
	if unrefNew && !unrefExistedBefore {
		if refreshDisabled {
			return true, false, ""
		}
		if liveVer, okL := liveSnapVersions[indexName][docID]; okL && liveVer == curVer {
			return false, false, ""
		}
	}
	c, rsn := s.checkByQueryPointInTimeConflictRound61(indexName, docID, snapVersions)
	return false, c, rsn
}

// validateTSDBSearchConstraintsR61CRUD enforces TSDB search restrictions (`tsdb/90_unsupported_operations.yml`):
//   - Explicit `?routing=` / `req.Routing` is rejected on `time_series` indices.
//   - Explicit `sort` or `aggs` on `_id` is rejected because `_id` fielddata is unsupported in `time_series` indices.
func (s *Server) validateTSDBSearchConstraintsR61CRUD(r *http.Request, rawIndex string, req *esast.SearchRequest) (int, string, string) {
	if s == nil {
		return 0, "", ""
	}
	if scSt, scET, scER := s.checkMaxOpenScrollContextR62Admin(r, rawIndex, req); scSt != 0 {
		return scSt, scET, scER
	}
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	targets := s.resolveTargetIndices(rawIndex)
	if len(targets) == 0 && rawIndex != "" && !hasExclusionOrWildcard(rawIndex) && rawIndex != "_all" {
		targets = []string{s.resolveIndexName(rawIndex)}
	}
	var tsIdx string
	for _, t := range targets {
		if sc := s.getOrCompileReadOnlySchema(ctx, t); sc != nil && sc.IndexMode == "time_series" {
			tsIdx = t
			break
		}
	}
	if tsIdx == "" {
		return 0, "", ""
	}
	hasExplicitRouting := (r != nil && r.URL != nil && strings.TrimSpace(r.URL.Query().Get("routing")) != "") ||
		(req != nil && strings.TrimSpace(req.Routing) != "")
	if hasExplicitRouting {
		return http.StatusBadRequest,
			"illegal_argument_exception",
			fmt.Sprintf("searching with a specified routing is not supported because the destination index [%s] is in time series mode", tsIdx)
	}
	if req != nil {
		for _, sp := range req.Sort {
			if strings.TrimSpace(sp.Entry.Field) == "_id" {
				return http.StatusBadRequest,
					"illegal_argument_exception",
					"Fielddata is not supported on [_id] field in [time_series] indices"
			}
		}
		if aggsReferenceIDFieldR61CRUD(req.EffectiveAggs()) {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				"Fielddata is not supported on [_id] field in [time_series] indices"
		}
	}
	return 0, "", ""
}

func aggsReferenceIDFieldR61CRUD(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if t := spec.EffectiveTerms(); t != nil && strings.TrimSpace(t.Field) == "_id" {
			return true
		}
		if spec.RareTerms != nil && strings.TrimSpace(spec.RareTerms.Field) == "_id" {
			return true
		}
		if spec.MultiTerms != nil {
			for _, mt := range spec.MultiTerms.Terms {
				if strings.TrimSpace(mt.Field) == "_id" {
					return true
				}
			}
		}
		if spec.Composite != nil {
			for _, srcMap := range spec.Composite.Sources {
				if aggsReferenceIDFieldR61CRUD(srcMap) {
					return true
				}
			}
		}
		if aggsReferenceIDFieldR61CRUD(spec.SubAggs()) {
			return true
		}
	}
	return false
}
