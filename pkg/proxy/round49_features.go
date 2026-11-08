package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// handleKNNSearch implements `POST/GET /_knn_search` and `POST/GET /{index}/_knn_search` (F1).
func (s *Server) handleKNNSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body map[string]any
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		if body != nil {
			knnObj, hasKNNObj := body["knn"].(map[string]any)
			if !hasKNNObj && body["knn"] == nil && (body["field"] != nil || body["query_vector"] != nil) {
				knnObj = make(map[string]any)
				for _, k := range []string{"field", "query_vector", "k", "num_candidates", "similarity", "boost"} {
					if v, exists := body[k]; exists {
						knnObj[k] = v
						delete(body, k)
					}
				}
				body["knn"] = knnObj
				hasKNNObj = true
			}
			if hasKNNObj && knnObj != nil {
				if filterVal, hasFilter := body["filter"]; hasFilter && filterVal != nil {
					if knnObj["filter"] == nil {
						knnObj["filter"] = filterVal
					}
					delete(body, "filter")
				}
				if body["size"] == nil && knnObj["k"] != nil {
					body["size"] = knnObj["k"]
				}
			} else if knnSlice, okSlice := body["knn"].([]any); okSlice && len(knnSlice) > 0 {
				if filterVal, hasFilter := body["filter"]; hasFilter && filterVal != nil {
					for _, item := range knnSlice {
						if m, okM := item.(map[string]any); okM && m["filter"] == nil {
							m["filter"] = filterVal
						}
					}
					delete(body, "filter")
				}
				if body["size"] == nil {
					if m, okM := knnSlice[0].(map[string]any); okM && m["k"] != nil {
						body["size"] = m["k"]
					}
				}
			}
			if normBytes, err := json.Marshal(body); err == nil {
				bodyBytes = normBytes
			}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	s.handleSearch(w, r)
}

// handleCatDataStreams implements `GET /_cat/data_streams` and `GET /_cat/data_streams/{name}` (F1).
func (s *Server) handleCatDataStreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	nameFilter := strings.TrimSpace(r.PathValue("name"))

	s.mu.RLock()
	if nameFilter != "" && nameFilter != "_all" && nameFilter != "*" {
		for _, pat := range strings.Split(nameFilter, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" || strings.HasPrefix(pat, "-") || strings.ContainsAny(pat, "*?") || pat == "_all" {
				continue
			}
			if _, exists := s.dataStreams[pat]; !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("data_stream [%s] is missing", pat))
				return
			}
		}
	}
	var names []string
	for dsName := range s.dataStreams {
		if nameFilter == "" || nameFilter == "_all" || nameFilter == "*" || matchMultiWildcardWithExclusions(nameFilter, dsName) {
			names = append(names, dsName)
		}
	}
	sort.Strings(names)
	rows := make([]map[string]any, 0, len(names))
	for _, dsName := range names {
		ds := s.dataStreams[dsName]
		tsField := "@timestamp"
		if tfMap, ok := ds["timestamp_field"].(map[string]any); ok {
			if n, ok := tfMap["name"].(string); ok && n != "" {
				tsField = n
			}
		}
		backing := extractDataStreamBackingIndexNames(ds)
		status := "GREEN"
		if st, ok := ds["status"].(string); ok && st != "" {
			status = st
		}
		tmpl := "-"
		if t, ok := ds["template"].(string); ok && t != "" {
			tmpl = t
		}
		ilm := "-"
		if p, ok := ds["ilm_policy"].(string); ok && p != "" {
			ilm = p
		}
		rows = append(rows, map[string]any{
			"name":            dsName,
			"timestamp_field": tsField,
			"indices":         fmt.Sprintf("%d", len(backing)),
			"status":          status,
			"template":        tmpl,
			"ilm_policy":      ilm,
		})
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"name", "timestamp_field", "indices", "status", "template", "ilm_policy"}, rows)
}

// handleDataStreamsStats implements `GET /_data_stream/_stats` and `GET /_data_stream/{name}/_stats` (F2).
func (s *Server) handleDataStreamsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	nameFilter := strings.TrimSpace(r.PathValue("name"))

	s.mu.RLock()
	if nameFilter != "" && nameFilter != "_all" && nameFilter != "*" {
		for _, pat := range strings.Split(nameFilter, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" || strings.HasPrefix(pat, "-") || strings.ContainsAny(pat, "*?") || pat == "_all" {
				continue
			}
			if _, exists := s.dataStreams[pat]; !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("data_stream [%s] is missing", pat))
				return
			}
		}
	}
	var names []string
	for dsName := range s.dataStreams {
		if nameFilter == "" || nameFilter == "_all" || nameFilter == "*" || matchMultiWildcardWithExclusions(nameFilter, dsName) {
			names = append(names, dsName)
		}
	}
	sort.Strings(names)
	streams := make([]any, 0, len(names))
	totalBacking := 0
	for _, dsName := range names {
		ds := s.dataStreams[dsName]
		backing := extractDataStreamBackingIndexNames(ds)
		totalBacking += len(backing)
		streams = append(streams, map[string]any{
			"data_stream":       dsName,
			"backing_indices":   len(backing),
			"store_size_bytes":  0,
			"store_size":        "0b",
			"maximum_timestamp": 0,
		})
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"_shards":                map[string]any{"total": 1, "successful": 1, "failed": 0},
		"data_stream_count":      len(streams),
		"backing_indices":        totalBacking,
		"total_store_size_bytes": 0,
		"total_store_size":       "0b",
		"data_streams":           streams,
	})
}

// handleRemoteInfo implements `GET /_remote/info` (F1).
func (s *Server) handleRemoteInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleReloadSecureSettings implements `POST /_nodes/reload_secure_settings` and `POST /_nodes/{node_id}/reload_secure_settings` (F1).
func (s *Server) handleReloadSecureSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "doris-es-cluster",
		"nodes": map[string]any{
			"node-1": map[string]any{"name": "doris-es-proxy-node-1"},
		},
	})
}

// handleSnapshotRoot implements `GET /_snapshot` (F1).
func (s *Server) handleSnapshotRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	s.mu.RLock()
	out := make(map[string]any, len(s.snapshotRepos))
	for k, v := range s.snapshotRepos {
		out[k] = deepCloneDocMap(v)
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

func cloneSnapshotWithoutInternal(snapObj map[string]any) map[string]any {
	if snapObj == nil {
		return nil
	}
	cp := deepCloneDocMap(snapObj)
	delete(cp, "__schemas")
	return cp
}

// handleSnapshotRepo implements `/_snapshot/{repository}` (including `/_snapshot/_all` and `/_snapshot/_status`) (F1).
func (s *Server) handleSnapshotRepo(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.PathValue("repository"))
	if repo == "_status" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": []any{}})
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		if repo == "" || repo == "_all" || repo == "*" {
			out := make(map[string]any, len(s.snapshotRepos))
			for k, v := range s.snapshotRepos {
				out[k] = deepCloneDocMap(v)
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				if len(out) == 0 {
					w.WriteHeader(http.StatusNotFound)
				} else {
					w.WriteHeader(http.StatusOK)
				}
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		out := make(map[string]any)
		for _, pat := range strings.Split(repo, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if strings.ContainsAny(pat, "*?") {
				for k, v := range s.snapshotRepos {
					if matchWildcardPattern(pat, k) {
						out[k] = deepCloneDocMap(v)
					}
				}
			} else if v, exists := s.snapshotRepos[pat]; exists {
				out[pat] = deepCloneDocMap(v)
			} else {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", pat))
				return
			}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			if len(out) == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPut, http.MethodPost:
		if repo == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: repository is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var reqMap map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		repoType := "fs"
		if t, ok := reqMap["type"].(string); ok && strings.TrimSpace(t) != "" {
			repoType = strings.TrimSpace(t)
		}
		settings := map[string]any{}
		if st, ok := reqMap["settings"].(map[string]any); ok && st != nil {
			settings = st
		}
		repoObj := map[string]any{
			"type":     repoType,
			"settings": settings,
		}
		s.mu.Lock()
		if s.snapshotRepos == nil {
			s.snapshotRepos = make(map[string]map[string]any)
		}
		if s.snapshots == nil {
			s.snapshots = make(map[string]map[string]map[string]any)
		}
		s.snapshotRepos[repo] = repoObj
		if s.snapshots[repo] == nil {
			s.snapshots[repo] = make(map[string]map[string]any)
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		s.mu.Lock()
		if _, exists := s.snapshotRepos[repo]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
			return
		}
		delete(s.snapshotRepos, repo)
		delete(s.snapshots, repo)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

// handleSnapshotActionOrItem implements `/_snapshot/{repository}/_verify`, `/_snapshot/{repository}/_status`, and `/_snapshot/{repository}/{snapshot}` (F1).
func (s *Server) handleSnapshotActionOrItem(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.PathValue("repository"))
	snap := strings.TrimSpace(r.PathValue("snapshot"))

	s.mu.RLock()
	_, repoExists := s.snapshotRepos[repo]
	s.mu.RUnlock()
	if !repoExists {
		writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
		return
	}

	if snap == "_verify" && (r.Method == http.MethodPost || r.Method == http.MethodGet) {
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes": map[string]any{
				"node-1": map[string]any{"name": "doris-es-proxy-node-1"},
			},
		})
		return
	}

	if snap == "_status" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		s.mu.RLock()
		bySnap := s.snapshots[repo]
		names := make([]string, 0, len(bySnap))
		for k := range bySnap {
			names = append(names, k)
		}
		sort.Strings(names)
		list := make([]any, 0, len(names))
		for _, k := range names {
			list = append(list, map[string]any{
				"snapshot":   k,
				"repository": repo,
				"uuid":       k + "-uuid",
				"state":      "SUCCESS",
				"shards_stats": map[string]any{
					"initializing": 0,
					"started":      0,
					"finalizing":   0,
					"done":         1,
					"failed":       0,
					"total":        1,
				},
			})
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": list})
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var reqMap map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		var indices []string
		if rawIdx := reqMap["indices"]; rawIdx != nil {
			switch iv := rawIdx.(type) {
			case string:
				for _, p := range strings.Split(iv, ",") {
					if p = strings.TrimSpace(p); p != "" {
						indices = append(indices, p)
					}
				}
			case []any:
				for _, item := range iv {
					if str := strings.TrimSpace(fmt.Sprintf("%v", item)); str != "" {
						indices = append(indices, str)
					}
				}
			}
		}
		if indices == nil {
			s.mu.RLock()
			for idxName := range s.indices {
				if !strings.HasPrefix(idxName, ".") {
					indices = append(indices, idxName)
				}
			}
			s.mu.RUnlock()
			sort.Strings(indices)
			if indices == nil {
				indices = []string{}
			}
		}
		includeGlobalState := true
		if b, ok := reqMap["include_global_state"].(bool); ok {
			includeGlobalState = b
		}
		snapObj := map[string]any{
			"snapshot":             snap,
			"uuid":                 snap + "-uuid",
			"version":              "8.12.0",
			"indices":              indices,
			"data_streams":         []any{},
			"include_global_state": includeGlobalState,
			"state":                "SUCCESS",
			"start_time":           "2026-01-01T00:00:00.000Z",
			"start_time_in_millis": int64(1767225600000),
			"end_time":             "2026-01-01T00:00:01.000Z",
			"end_time_in_millis":   int64(1767225601000),
			"duration_in_millis":   int64(1000),
			"failures":             []any{},
			"shards": map[string]any{
				"total":      1,
				"failed":     0,
				"successful": 1,
			},
		}
		s.mu.Lock()
		if s.snapshots != nil && s.snapshots[repo] != nil && s.snapshots[repo][snap] != nil {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "invalid_snapshot_name_exception",
				fmt.Sprintf("[%s:%s] Invalid snapshot name [%s], snapshot with the same name already exists", repo, snap, snap))
			return
		}
		savedSchemas := make(map[string]*schema.IndexSchema, len(indices))
		for _, idxName := range indices {
			if sch := s.indices[idxName]; sch != nil {
				savedSchemas[idxName] = sch
			}
		}
		snapObj["__schemas"] = savedSchemas
		if s.snapshots == nil {
			s.snapshots = make(map[string]map[string]map[string]any)
		}
		if s.snapshots[repo] == nil {
			s.snapshots[repo] = make(map[string]map[string]any)
		}
		s.snapshots[repo][snap] = snapObj
		respSnap := cloneSnapshotWithoutInternal(snapObj)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": true,
			"snapshot": respSnap,
		})
	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		bySnap := s.snapshots[repo]
		var matched []any
		if snap == "_all" || snap == "*" {
			names := make([]string, 0, len(bySnap))
			for k := range bySnap {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				matched = append(matched, cloneSnapshotWithoutInternal(bySnap[k]))
			}
		} else {
			for _, pat := range strings.Split(snap, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" {
					continue
				}
				if strings.ContainsAny(pat, "*?") {
					var names []string
					for k := range bySnap {
						if matchWildcardPattern(pat, k) {
							names = append(names, k)
						}
					}
					sort.Strings(names)
					for _, k := range names {
						matched = append(matched, cloneSnapshotWithoutInternal(bySnap[k]))
					}
				} else if obj, exists := bySnap[pat]; exists {
					matched = append(matched, cloneSnapshotWithoutInternal(obj))
				} else {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, pat))
					return
				}
			}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			if len(matched) == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		if matched == nil {
			matched = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"snapshots": matched,
			"total":     len(matched),
			"remaining": 0,
		})
	case http.MethodDelete:
		s.mu.Lock()
		bySnap := s.snapshots[repo]
		for _, pat := range strings.Split(snap, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if _, exists := bySnap[pat]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, pat))
				return
			}
		}
		for _, pat := range strings.Split(snap, ",") {
			pat = strings.TrimSpace(pat)
			delete(bySnap, pat)
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

// handleSnapshotItemAction implements `POST /_snapshot/{repository}/{snapshot}/_restore` and `GET /_snapshot/{repository}/{snapshot}/_status` (F1).
func (s *Server) handleSnapshotItemAction(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.PathValue("repository"))
	snap := strings.TrimSpace(r.PathValue("snapshot"))
	action := strings.TrimSpace(r.PathValue("action"))

	s.mu.RLock()
	_, repoExists := s.snapshotRepos[repo]
	var snapObj map[string]any
	var savedSchemas map[string]*schema.IndexSchema
	if repoExists && s.snapshots[repo] != nil {
		if rawSnap := s.snapshots[repo][snap]; rawSnap != nil {
			savedSchemas, _ = rawSnap["__schemas"].(map[string]*schema.IndexSchema)
			snapObj = cloneSnapshotWithoutInternal(rawSnap)
		}
	}
	s.mu.RUnlock()

	if !repoExists {
		writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
		return
	}
	if snapObj == nil {
		writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, snap))
		return
	}

	switch action {
	case "_restore":
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var reqMap map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		var snapIndices []string
		switch iv := snapObj["indices"].(type) {
		case []string:
			snapIndices = append(snapIndices, iv...)
		case []any:
			for _, item := range iv {
				if sStr, okS := item.(string); okS && sStr != "" {
					snapIndices = append(snapIndices, sStr)
				}
			}
		}
		sourceIndices := snapIndices
		if rawReqIdx := reqMap["indices"]; rawReqIdx != nil {
			var patterns []string
			switch iv := rawReqIdx.(type) {
			case string:
				for _, p := range strings.Split(iv, ",") {
					if p = strings.TrimSpace(p); p != "" {
						patterns = append(patterns, p)
					}
				}
			case []any:
				for _, item := range iv {
					if str := strings.TrimSpace(fmt.Sprintf("%v", item)); str != "" {
						patterns = append(patterns, str)
					}
				}
			}
			if len(patterns) > 0 {
				joinedPat := strings.Join(patterns, ",")
				filtered := make([]string, 0, len(snapIndices))
				for _, idxName := range snapIndices {
					if joinedPat == "_all" || joinedPat == "*" || matchMultiWildcardWithExclusions(joinedPat, idxName) {
						filtered = append(filtered, idxName)
					}
				}
				sourceIndices = filtered
			}
		}
		var renameRe *regexp.Regexp
		renamePattern, _ := reqMap["rename_pattern"].(string)
		renameReplacement, _ := reqMap["rename_replacement"].(string)
		if renamePattern != "" {
			var err error
			renameRe, err = regexp.Compile(renamePattern)
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
		}
		restoredIndices := make([]string, 0, len(sourceIndices))
		for _, srcIdx := range sourceIndices {
			targetIdx := srcIdx
			if renameRe != nil {
				targetIdx = renameRe.ReplaceAllString(srcIdx, normalizeGsubReplacement(renameReplacement))
			}
			restoredIndices = append(restoredIndices, targetIdx)
			s.mu.Lock()
			_, alreadyExists := s.indices[targetIdx]
			s.mu.Unlock()
			if !alreadyExists {
				var restoredSchema *schema.IndexSchema
				if savedSchemas != nil && savedSchemas[srcIdx] != nil {
					restoredSchema = schema.CompileIndexSchema(s.dorisDB, targetIdx, savedSchemas[srcIdx].RawMapping)
				} else {
					restoredSchema = schema.CompileIndexSchema(s.dorisDB, targetIdx, nil)
				}
				if restoredSchema != nil {
					_ = s.backend.ExecDDL(r.Context(), schema.GenerateCreateTableDDL(restoredSchema))
					s.mu.Lock()
					if s.indices == nil {
						s.indices = make(map[string]*schema.IndexSchema)
					}
					if s.indices[targetIdx] == nil {
						s.indices[targetIdx] = restoredSchema
					}
					delete(s.closedIndices, targetIdx)
					s.mu.Unlock()
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": true,
			"snapshot": map[string]any{
				"snapshot": snap,
				"indices":  restoredIndices,
				"shards": map[string]any{
					"total":      1,
					"failed":     0,
					"successful": 1,
				},
			},
		})
	case "_status":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"snapshots": []any{
				map[string]any{
					"snapshot":   snap,
					"repository": repo,
					"uuid":       snap + "-uuid",
					"state":      "SUCCESS",
					"shards_stats": map[string]any{
						"initializing": 0,
						"started":      0,
						"finalizing":   0,
						"done":         1,
						"failed":       0,
						"total":        1,
					},
				},
			},
		})
	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

// handleCatSnapshots implements `GET /_cat/snapshots` and `GET /_cat/snapshots/{repository}` (F1).
func (s *Server) handleCatSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	repoFilter := strings.TrimSpace(r.PathValue("repository"))
	if repoFilter == "" {
		repoFilter = strings.TrimSpace(r.PathValue("name"))
	}
	if repoFilter == "" {
		repoFilter = strings.TrimSpace(r.URL.Query().Get("repository"))
	}

	s.mu.RLock()
	if repoFilter != "" && repoFilter != "_all" && repoFilter != "*" {
		for _, pat := range strings.Split(repoFilter, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" || strings.ContainsAny(pat, "*?") || pat == "_all" {
				continue
			}
			if _, exists := s.snapshotRepos[pat]; !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", pat))
				return
			}
		}
	}
	var repos []string
	for rName := range s.snapshotRepos {
		if repoFilter == "" || repoFilter == "_all" || repoFilter == "*" || matchMultiWildcardWithExclusions(repoFilter, rName) {
			repos = append(repos, rName)
		}
	}
	sort.Strings(repos)
	rows := make([]map[string]any, 0)
	for _, rName := range repos {
		bySnap := s.snapshots[rName]
		var sNames []string
		for sName := range bySnap {
			sNames = append(sNames, sName)
		}
		sort.Strings(sNames)
		for _, sName := range sNames {
			snapObj := bySnap[sName]
			idxCnt := 0
			switch iv := snapObj["indices"].(type) {
			case []string:
				idxCnt = len(iv)
			case []any:
				idxCnt = len(iv)
			}
			rows = append(rows, map[string]any{
				"id":                sName,
				"repository":        rName,
				"status":            "SUCCESS",
				"start_epoch":       "1767225600",
				"start_time":        "00:00:00",
				"end_epoch":         "1767225601",
				"end_time":          "00:00:01",
				"duration":          "1s",
				"indices":           fmt.Sprintf("%d", idxCnt),
				"successful_shards": "1",
				"failed_shards":     "0",
				"total_shards":      "1",
			})
		}
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"id", "status", "start_epoch", "start_time", "end_epoch", "end_time", "duration", "indices", "successful_shards", "failed_shards", "total_shards"}, rows)
}

// handleSimulateIndexTemplate implements `POST /_index_template/_simulate` and `POST /_index_template/_simulate/{name}` (F3).
func (s *Server) handleSimulateIndexTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	name := strings.TrimSpace(r.PathValue("name"))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	var tpl esast.IndexTemplateRequest
	hasBody := len(bytes.TrimSpace(bodyBytes)) > 0
	if hasBody {
		if err := json.Unmarshal(bodyBytes, &tpl); err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
	}

	s.mu.RLock()
	if name != "" && !hasBody {
		existing, exists := s.templates[name]
		if !exists {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "index_template ["+name+"] missing")
			return
		}
		tpl = existing
	} else if name != "" && hasBody {
		if len(tpl.IndexPatterns) == 0 && tpl.Template == nil && len(tpl.ComposedOf) == 0 {
			if existing, exists := s.templates[name]; exists {
				tpl = existing
			} else {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "index_template ["+name+"] missing")
				return
			}
		}
	}
	for _, compName := range tpl.ComposedOf {
		if _, exists := s.componentTemplates[compName]; !exists {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("index_template [%s] invalid, cause [Validation Failed: 1: component template [%s] not found;]", name, compName))
			return
		}
	}
	resolvedTpl, overlapping := s.simulateTemplateConfigLocked(name, tpl)
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"template":    resolvedTpl,
		"overlapping": overlapping,
	})
}

// handleSimulateIndexTemplateIndex implements `POST /_index_template/_simulate_index/{name}` (F3).
func (s *Server) handleSimulateIndexTemplateIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	indexName := strings.TrimSpace(r.PathValue("name"))
	_, _ = readRequestBody(w, r)

	s.mu.RLock()
	var matchedNames []string
	for k, tpl := range s.templates {
		for _, pat := range tpl.EffectivePatterns() {
			if matchWildcardPattern(pat, indexName) {
				matchedNames = append(matchedNames, k)
				break
			}
		}
	}
	if len(matchedNames) == 0 {
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	sort.Slice(matchedNames, func(i, j int) bool {
		pi := s.templates[matchedNames[i]].EffectivePriority()
		pj := s.templates[matchedNames[j]].EffectivePriority()
		if pi != pj {
			return pi > pj
		}
		return matchedNames[i] < matchedNames[j]
	})
	winnerName := matchedNames[0]
	winnerTpl := s.templates[winnerName]
	resolvedTpl, _ := s.simulateTemplateConfigLocked(winnerName, winnerTpl)
	overlapping := make([]any, 0)
	for _, otherName := range matchedNames[1:] {
		otherTpl := s.templates[otherName]
		overlapping = append(overlapping, map[string]any{
			"name":           otherName,
			"index_patterns": otherTpl.EffectivePatterns(),
		})
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"template":    resolvedTpl,
		"overlapping": overlapping,
	})
}

func (s *Server) simulateTemplateConfigLocked(excludeName string, tpl esast.IndexTemplateRequest) (map[string]any, []any) {
	var mergedMappings *esast.MappingSpec
	mergedSettings := make(map[string]any)
	mergedAliases := make(map[string]any)

	applyComponentMap := func(compRaw map[string]any) {
		tplBlock, ok := compRaw["template"].(map[string]any)
		if !ok {
			tplBlock = compRaw
		}
		if rawSet, ok := tplBlock["settings"].(map[string]any); ok {
			for k, v := range rawSet {
				mergedSettings[k] = v
			}
		}
		if rawAl, ok := tplBlock["aliases"].(map[string]any); ok {
			for k, v := range rawAl {
				mergedAliases[k] = v
			}
		}
		if rawMap, ok := tplBlock["mappings"]; ok && rawMap != nil {
			if b, err := json.Marshal(rawMap); err == nil {
				var ms esast.MappingSpec
				if err := json.Unmarshal(b, &ms); err == nil {
					mergedMappings = schema.MergeMappingSpecs(mergedMappings, &ms)
				}
			}
		}
	}

	for _, compName := range tpl.ComposedOf {
		if compRaw, ok := s.componentTemplates[compName]; ok && len(compRaw) > 0 {
			applyComponentMap(compRaw)
		}
	}
	if ts := tpl.EffectiveSettings(); len(ts) > 0 {
		for k, v := range ts {
			mergedSettings[k] = v
		}
	}
	if ta := tpl.EffectiveAliases(); len(ta) > 0 {
		for k, v := range ta {
			mergedAliases[k] = v
		}
	}
	if tm := tpl.EffectiveMappings(); tm != nil {
		mergedMappings = schema.MergeMappingSpecs(mergedMappings, tm)
	}

	mappingsOut := make(map[string]any)
	if mergedMappings != nil {
		if b, err := json.Marshal(mergedMappings); err == nil {
			_ = json.Unmarshal(b, &mappingsOut)
		}
	}

	overlapping := make([]any, 0)
	tplPatterns := tpl.EffectivePatterns()
	var otherNames []string
	for k := range s.templates {
		if k == excludeName {
			continue
		}
		otherNames = append(otherNames, k)
	}
	sort.Strings(otherNames)
	for _, k := range otherNames {
		other := s.templates[k]
		otherPats := other.EffectivePatterns()
		overlaps := false
		for _, p1 := range tplPatterns {
			for _, p2 := range otherPats {
				if p1 == p2 || matchWildcardPattern(p1, p2) || matchWildcardPattern(p2, p1) {
					overlaps = true
					break
				}
			}
			if overlaps {
				break
			}
		}
		if overlaps {
			overlapping = append(overlapping, map[string]any{
				"name":           k,
				"index_patterns": otherPats,
			})
		}
	}

	return map[string]any{
		"settings": mergedSettings,
		"mappings": mappingsOut,
		"aliases":  mergedAliases,
	}, overlapping
}
