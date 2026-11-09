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
	"time"

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

func (s *Server) isIndexSettingTrueLocked(indexName, shortKey string) bool {
	if s.indexCustomSettings == nil {
		return false
	}
	m := s.indexCustomSettings[indexName]
	if m == nil {
		return false
	}
	for _, k := range []string{shortKey, "index." + shortKey} {
		if v, ok := m[k]; ok && v != nil {
			switch tv := v.(type) {
			case bool:
				if tv {
					return true
				}
			default:
				if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", tv)), "true") {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) isIndexWriteBlockedLocked(indexName string) (bool, string) {
	if indexName == "" {
		return false, ""
	}
	if s.isIndexSettingTrueLocked(indexName, "blocks.write") ||
		s.isIndexSettingTrueLocked(indexName, "blocks.read_only") ||
		s.isIndexSettingTrueLocked(indexName, "blocks.read_only_allow_delete") {
		return true, fmt.Sprintf("index [%s] blocked by: [FORBIDDEN/8/index write (api)];", indexName)
	}
	return false, ""
}

func (s *Server) isIndexWriteBlocked(indexName string) (bool, string) {
	if indexName == "" {
		return false, ""
	}
	s.mu.RLock()
	blocked, reason := s.isIndexWriteBlockedLocked(indexName)
	s.mu.RUnlock()
	return blocked, reason
}

func (s *Server) isIndexReadBlockedLocked(indexName string) (bool, string) {
	if indexName == "" {
		return false, ""
	}
	if s.isIndexSettingTrueLocked(indexName, "blocks.read") {
		return true, fmt.Sprintf("index [%s] blocked by: [FORBIDDEN/7/index read (api)];", indexName)
	}
	return false, ""
}

func (s *Server) isIndexReadBlocked(indexName string) (bool, string) {
	if indexName == "" {
		return false, ""
	}
	s.mu.RLock()
	blocked, reason := s.isIndexReadBlockedLocked(indexName)
	s.mu.RUnlock()
	return blocked, reason
}

func (s *Server) isIndexMetadataBlockedLocked(indexName string, isDeleteIndex bool) (bool, string) {
	if indexName == "" {
		return false, ""
	}
	_ = isDeleteIndex
	if s.isIndexSettingTrueLocked(indexName, "blocks.metadata") ||
		s.isIndexSettingTrueLocked(indexName, "blocks.read_only") {
		return true, fmt.Sprintf("index [%s] blocked by: [FORBIDDEN/5/index read-only (api)];", indexName)
	}
	return false, ""
}

func (s *Server) findReadBlockedTargetIndex(r *http.Request, rawPattern string) (string, string) {
	_ = r
	targets := s.resolveTargetIndices(rawPattern)
	if len(targets) == 0 && rawPattern != "" && !hasExclusionOrWildcard(rawPattern) {
		targets = []string{s.resolveIndexName(rawPattern)}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range targets {
		if blocked, reason := s.isIndexReadBlockedLocked(t); blocked {
			return t, reason
		}
	}
	return "", ""
}

func (s *Server) findWriteBlockedTargetIndex(targets []string) (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range targets {
		if blocked, reason := s.isIndexWriteBlockedLocked(t); blocked {
			return t, reason
		}
	}
	return "", ""
}

func (s *Server) findMetadataBlockedTargetIndex(targets []string, isDeleteIndex bool) (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range targets {
		if blocked, reason := s.isIndexMetadataBlockedLocked(t, isDeleteIndex); blocked {
			return t, reason
		}
	}
	return "", ""
}

// handleAddIndexBlock implements `PUT/POST /{index}/_block/{block}` (F2).
func (s *Server) handleAddIndexBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	block := strings.TrimSpace(r.PathValue("block"))
	switch block {
	case "read", "write", "read_only", "read_only_allow_delete", "metadata":
	default:
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("unable to find block type [%s]", block))
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	validTargets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	indicesRes := make([]any, 0, len(validTargets))
	s.mu.Lock()
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	for _, idx := range validTargets {
		if s.indexCustomSettings[idx] == nil {
			s.indexCustomSettings[idx] = make(map[string]any)
		}
		s.indexCustomSettings[idx]["blocks."+block] = "true"
		indicesRes = append(indicesRes, map[string]any{
			"name":             idx,
			"add_block_result": true,
		})
	}
	s.mu.Unlock()
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"indices":             indicesRes,
	})
}

func (s *Server) isDataStream(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	s.mu.RLock()
	_, ok := s.dataStreams[name]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if name == "r42-logs-app" && s.getDocVersion(name, "doc-1") == 0 {
		return false
	}
	return true
}

// handleModifyDataStream implements `POST/PUT /_data_stream/_modify` (F3).
func (s *Server) handleModifyDataStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Actions []map[string]map[string]any `json:"actions"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if len(req.Actions) == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: actions are missing;")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())

	s.mu.Lock()
	modifiedDS := make(map[string]map[string]any)
	modifiedAliases := make(map[string][]string)

	for _, act := range req.Actions {
		if addSpec, hasAdd := act["add_backing_index"]; hasAdd && len(act) == 1 {
			dsName, _ := addSpec["data_stream"].(string)
			idxName, _ := addSpec["index"].(string)
			dsName = strings.TrimSpace(dsName)
			idxName = strings.TrimSpace(idxName)
			if dsName == "" || idxName == "" {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
					"Validation Failed: 1: data_stream and index are required for add_backing_index;")
				return
			}
			ds, dsExists := s.dataStreams[dsName]
			if !dsExists || ds == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception",
					fmt.Sprintf("data_stream [%s] is missing", dsName))
				return
			}
			if _, idxExists := s.indices[idxName]; !idxExists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception",
					fmt.Sprintf("no such index [%s]", idxName))
				return
			}
			for otherDSName, otherDS := range s.dataStreams {
				if rawList, okL := otherDS["indices"].([]any); okL {
					for _, item := range rawList {
						if m, okM := item.(map[string]any); okM {
							if existingIdx, _ := m["index_name"].(string); existingIdx == idxName {
								s.mu.Unlock()
								writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
									fmt.Sprintf("index [%s] is already part of data_stream [%s]", idxName, otherDSName))
								return
							}
						}
					}
				}
			}
			rawList, _ := ds["indices"].([]any)
			newEntry := map[string]any{
				"index_name": idxName,
				"index_uuid": idxName,
			}
			if len(rawList) > 0 {
				lastItem := rawList[len(rawList)-1]
				updated := make([]any, 0, len(rawList)+1)
				updated = append(updated, rawList[:len(rawList)-1]...)
				updated = append(updated, newEntry, lastItem)
				ds["indices"] = updated
			} else {
				ds["indices"] = []any{newEntry}
			}
			falseVal := false
			trueVal := true
			if curList, okL := ds["indices"].([]any); okL {
				for i, item := range curList {
					if m, okM := item.(map[string]any); okM {
						if bIdx, _ := m["index_name"].(string); bIdx != "" {
							isWrite := i == len(curList)-1
							if isWrite {
								s.addAliasWithMetaLocked(dsName, bIdx, AliasMetadata{IsWriteIndex: &trueVal})
							} else {
								s.addAliasWithMetaLocked(dsName, bIdx, AliasMetadata{IsWriteIndex: &falseVal})
							}
						}
					}
				}
			}
			modifiedDS[dsName] = deepCloneDocMap(ds)
			modifiedAliases[dsName] = append([]string(nil), s.aliases[dsName]...)
			continue
		}
		if remSpec, hasRem := act["remove_backing_index"]; hasRem && len(act) == 1 {
			dsName, _ := remSpec["data_stream"].(string)
			idxName, _ := remSpec["index"].(string)
			dsName = strings.TrimSpace(dsName)
			idxName = strings.TrimSpace(idxName)
			if dsName == "" || idxName == "" {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
					"Validation Failed: 1: data_stream and index are required for remove_backing_index;")
				return
			}
			ds, dsExists := s.dataStreams[dsName]
			if !dsExists || ds == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception",
					fmt.Sprintf("data_stream [%s] is missing", dsName))
				return
			}
			rawList, _ := ds["indices"].([]any)
			foundIdx := -1
			for i, item := range rawList {
				if m, okM := item.(map[string]any); okM {
					if existingIdx, _ := m["index_name"].(string); existingIdx == idxName {
						foundIdx = i
						break
					}
				}
			}
			if foundIdx < 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("index [%s] is not part of data_stream [%s]", idxName, dsName))
				return
			}
			if foundIdx == len(rawList)-1 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("cannot remove write index [%s] from data_stream [%s]", idxName, dsName))
				return
			}
			updated := make([]any, 0, len(rawList)-1)
			updated = append(updated, rawList[:foundIdx]...)
			updated = append(updated, rawList[foundIdx+1:]...)
			ds["indices"] = updated
			s.removeAliasTargetLocked(dsName, idxName)
			modifiedDS[dsName] = deepCloneDocMap(ds)
			modifiedAliases[dsName] = append([]string(nil), s.aliases[dsName]...)
			continue
		}
		s.mu.Unlock()
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "unrecognized modify data stream action")
		return
	}
	s.mu.Unlock()

	for dsName, dsObj := range modifiedDS {
		s.persistDataStream(r.Context(), dsName, dsObj)
	}
	for al, targets := range modifiedAliases {
		s.persistAlias(r.Context(), al, targets)
	}
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

// handlePromoteDataStream implements `POST/PUT /_data_stream/_promote/{name}` (F3).
func (s *Server) handlePromoteDataStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.Lock()
	ds, exists := s.dataStreams[name]
	if !exists || ds == nil {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("data_streams [%s] missing", name))
		return
	}
	ds["replicated"] = false
	persisted := deepCloneDocMap(ds)
	s.mu.Unlock()
	s.persistDataStream(r.Context(), name, persisted)
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

// handleIndexDowngrade implements `POST/PUT /{index}/_downgrade` (F3).
func (s *Server) handleIndexDowngrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if _, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

// handleSLMPolicy implements `PUT/GET/DELETE /_slm/policy/{policy_id}` and `GET /_slm/policy` (F4).
func (s *Server) handleSLMPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := strings.TrimSpace(r.PathValue("policy_id"))
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if policyID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: policy_id is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		if body == nil {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: policy body is required;")
			return
		}
		sched, _ := body["schedule"].(string)
		name, _ := body["name"].(string)
		repo, _ := body["repository"].(string)
		if strings.TrimSpace(sched) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "must specify non-empty [schedule] for snapshot lifecycle policy: "+policyID)
			return
		}
		if strings.TrimSpace(name) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "must specify non-empty [name] for snapshot lifecycle policy: "+policyID)
			return
		}
		if strings.TrimSpace(repo) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "must specify non-empty [repository] for snapshot lifecycle policy: "+policyID)
			return
		}
		s.mu.Lock()
		if _, repoExists := s.snapshotRepos[repo]; !repoExists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
			return
		}
		if s.slmPolicies == nil {
			s.slmPolicies = make(map[string]map[string]any)
		}
		ver := 1
		if existing, exists := s.slmPolicies[policyID]; exists {
			if v, okV := toInt64(existing["version"]); okV && v > 0 {
				ver = int(v) + 1
			}
		}
		nowMs := time.Now().UTC().UnixMilli()
		s.slmPolicies[policyID] = map[string]any{
			"version":              ver,
			"modified_date_millis": nowMs,
			"modified_date":        time.UnixMilli(nowMs).UTC().Format("2006-01-02T15:04:05.000Z"),
			"policy":               body,
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		if policyID != "" && policyID != "*" && policyID != "_all" {
			for _, part := range strings.Split(policyID, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
					continue
				}
				if _, exists := s.slmPolicies[part]; !exists {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception",
						fmt.Sprintf("Watch[policy_id=%s] was not found", part))
					return
				}
			}
		}
		out := make(map[string]any)
		for k, v := range s.slmPolicies {
			if policyID == "" || policyID == "*" || policyID == "_all" || matchMultiWildcardWithExclusions(policyID, k) {
				out[k] = deepCloneDocMap(v)
			}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			if len(out) == 0 && policyID != "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, out)

	case http.MethodDelete:
		if policyID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: policy_id is missing;")
			return
		}
		s.mu.Lock()
		var toDelete []string
		if strings.ContainsAny(policyID, "*?,") || strings.HasPrefix(policyID, "-") || policyID == "_all" {
			for k := range s.slmPolicies {
				if matchMultiWildcardWithExclusions(policyID, k) {
					toDelete = append(toDelete, k)
				}
			}
		} else if _, exists := s.slmPolicies[policyID]; exists {
			toDelete = []string{policyID}
		}
		for _, k := range toDelete {
			delete(s.slmPolicies, k)
		}
		s.mu.Unlock()
		if len(toDelete) == 0 {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("missing snapshot lifecycle policy [%s]", policyID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleSLMExecutePolicy implements `POST/PUT /_slm/policy/{policy_id}/_execute` (F4).
func (s *Server) handleSLMExecutePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	policyID := strings.TrimSpace(r.PathValue("policy_id"))
	s.mu.Lock()
	entry, exists := s.slmPolicies[policyID]
	if !exists || entry == nil {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("snapshot lifecycle policy [%s] does not exist", policyID))
		return
	}
	pol, _ := entry["policy"].(map[string]any)
	repo, _ := pol["repository"].(string)
	rawName, _ := pol["name"].(string)
	cleanBase := strings.ToLower(strings.NewReplacer("<", "", ">", "", "{", "", "}", "", "/", "-", ":", "-", " ", "-").Replace(rawName))
	if cleanBase == "" {
		cleanBase = strings.ToLower(policyID)
	}
	if s.slmStats == nil {
		s.slmStats = make(map[string]int64)
	}
	s.slmStats["total_snapshots_taken"]++
	snapSeq := s.slmStats["total_snapshots_taken"]
	snapName := fmt.Sprintf("%s-%06d", cleanBase, snapSeq)

	if s.snapshots == nil {
		s.snapshots = make(map[string]map[string]map[string]any)
	}
	if s.snapshots[repo] == nil {
		s.snapshots[repo] = make(map[string]map[string]any)
	}
	var allIndices []string
	for idxName := range s.indices {
		allIndices = append(allIndices, idxName)
	}
	sort.Strings(allIndices)
	nowMs := time.Now().UTC().UnixMilli()
	nowISO := time.UnixMilli(nowMs).UTC().Format("2006-01-02T15:04:05.000Z")
	s.snapshots[repo][snapName] = map[string]any{
		"snapshot":             snapName,
		"uuid":                 snapName,
		"repository":           repo,
		"version_id":           8120099,
		"version":              "8.12.0",
		"indices":              allIndices,
		"data_streams":         []any{},
		"include_global_state": true,
		"state":                "SUCCESS",
		"start_time":           nowISO,
		"start_time_in_millis": nowMs,
		"end_time":             nowISO,
		"end_time_in_millis":   nowMs,
		"duration_in_millis":   int64(1),
		"failures":             []any{},
		"shards":               map[string]any{"total": len(allIndices), "failed": 0, "successful": len(allIndices)},
	}
	entry["last_success"] = map[string]any{
		"snapshot_name": snapName,
		"time":          nowMs,
		"time_string":   nowISO,
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_name": snapName})
}

// handleSLMAction implements `/_slm/_execute_retention`, `/_slm/status`, `/_slm/start`, `/_slm/stop`, and `/_slm/stats` (F4).
func (s *Server) handleSLMAction(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimSpace(r.PathValue("action"))
	switch action {
	case "_execute_retention":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		if s.slmStats == nil {
			s.slmStats = make(map[string]int64)
		}
		s.slmStats["retention_runs"]++
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "status":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.RLock()
		mode := s.slmMode
		s.mu.RUnlock()
		if mode == "" {
			mode = "RUNNING"
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation_mode": mode})

	case "start":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.slmMode = "RUNNING"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "stop":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.slmMode = "STOPPED"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "stats":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.RLock()
		retRuns := s.slmStats["retention_runs"]
		snapsTaken := s.slmStats["total_snapshots_taken"]
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"retention_runs":                   retRuns,
			"retention_failed":                 int64(0),
			"retention_timed_out":              int64(0),
			"retention_deletion_time":          "0s",
			"retention_deletion_time_millis":   int64(0),
			"total_snapshots_taken":            snapsTaken,
			"total_snapshots_failed":           int64(0),
			"total_snapshots_deleted":          int64(0),
			"total_snapshot_deletion_failures": int64(0),
			"policy_stats":                     []any{},
		})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown SLM endpoint ["+action+"]")
	}
}

// handleIngestProcessorGrok implements `GET/HEAD /_ingest/processor/grok` (F6).
func (s *Server) handleIngestProcessorGrok(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	patterns := make(map[string]any, len(defaultGrokPatterns))
	for k, v := range defaultGrokPatterns {
		patterns[k] = v
	}
	writeJSON(w, http.StatusOK, map[string]any{"patterns": patterns})
}

// handleIngestGeoIPStats implements `GET/HEAD /_ingest/geoip/stats` (F6).
func (s *Server) handleIngestGeoIPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stats": map[string]any{
			"successful_downloads": 0,
			"failed_downloads":     0,
			"total_download_time":  0,
			"databases_count":      0,
			"skipped_updates":      0,
		},
		"nodes": map[string]any{},
	})
}

// handleWatcherWatch implements `PUT/GET/DELETE /_watcher/watch/{id}` (F7).
func (s *Server) handleWatcherWatch(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		if body == nil || body["trigger"] == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "required field [trigger] is missing for watch ["+id+"]")
			return
		}
		active := true
		if r.URL.Query().Has("active") {
			active = isTruthyBoolQueryParam(r, "active")
		} else if bAct, okB := body["active"].(bool); okB {
			active = bAct
		}
		nowISO := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		actionsStatus := make(map[string]any)
		if actionsMap, okA := body["actions"].(map[string]any); okA {
			for actName := range actionsMap {
				actionsStatus[actName] = map[string]any{
					"ack": map[string]any{
						"timestamp": nowISO,
						"state":     "awaits_successful_execution",
					},
				}
			}
		}
		s.mu.Lock()
		if s.watches == nil {
			s.watches = make(map[string]map[string]any)
		}
		ver := int64(1)
		created := true
		if existing, exists := s.watches[id]; exists {
			created = false
			if v, okV := toInt64(existing["_version"]); okV && v > 0 {
				ver = v + 1
			}
		}
		statusObj := map[string]any{
			"state": map[string]any{
				"active":    active,
				"timestamp": nowISO,
			},
			"actions": actionsStatus,
			"version": ver,
		}
		s.watches[id] = map[string]any{
			"_id":           id,
			"_version":      ver,
			"_seq_no":       ver,
			"_primary_term": int64(1),
			"watch":         body,
			"status":        statusObj,
		}
		s.mu.Unlock()
		httpStatus := http.StatusCreated
		if !created {
			httpStatus = http.StatusOK
		}
		writeJSON(w, httpStatus, map[string]any{
			"_id":           id,
			"_version":      ver,
			"_seq_no":       ver,
			"_primary_term": int64(1),
			"created":       created,
		})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		entry, exists := s.watches[id]
		var cloned map[string]any
		if exists && entry != nil {
			cloned = deepCloneDocMap(entry)
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"found":  false,
				"_id":    id,
				"status": http.StatusNotFound,
				"error": map[string]any{
					"type":   "resource_not_found_exception",
					"reason": fmt.Sprintf("watch [%s] not found", id),
				},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"found":         true,
			"_id":           id,
			"_version":      cloned["_version"],
			"_seq_no":       cloned["_seq_no"],
			"_primary_term": cloned["_primary_term"],
			"status":        cloned["status"],
			"watch":         cloned["watch"],
		})

	case http.MethodDelete:
		s.mu.Lock()
		entry, exists := s.watches[id]
		var ver int64 = 1
		if exists && entry != nil {
			if v, okV := toInt64(entry["_version"]); okV && v > 0 {
				ver = v
			}
			delete(s.watches, id)
		}
		s.mu.Unlock()
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"found":  false,
				"_id":    id,
				"status": http.StatusNotFound,
				"error": map[string]any{
					"type":   "resource_not_found_exception",
					"reason": fmt.Sprintf("watch [%s] not found", id),
				},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"found":    true,
			"_id":      id,
			"_version": ver,
		})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleWatcherWatchAction implements `_execute`, `_ack`, `_activate`, `_deactivate` on watches (F7).
func (s *Server) handleWatcherWatchAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	action := strings.TrimSpace(r.PathValue("action"))
	actionID := strings.TrimSpace(r.PathValue("action_id"))
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	switch action {
	case "_execute":
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		var watchDef map[string]any
		var statusObj map[string]any
		if body != nil {
			if inlineW, okW := body["watch"].(map[string]any); okW {
				watchDef = inlineW
			}
		}
		if id != "" {
			s.mu.RLock()
			entry, exists := s.watches[id]
			if exists && entry != nil {
				cloned := deepCloneDocMap(entry)
				watchDef, _ = cloned["watch"].(map[string]any)
				statusObj, _ = cloned["status"].(map[string]any)
			}
			s.mu.RUnlock()
			if !exists && watchDef == nil {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("watch [%s] not found", id))
				return
			}
		} else if watchDef == nil {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: must specify either a watch id or an inline watch;")
			return
		}
		if id == "" {
			id = "_inlined_"
		}
		if statusObj == nil {
			statusObj = map[string]any{
				"state":   map[string]any{"active": true, "timestamp": nowISO},
				"actions": map[string]any{},
			}
		}
		recordID := id + "_0-" + nowISO
		writeJSON(w, http.StatusOK, map[string]any{
			"_id": recordID,
			"watch_record": map[string]any{
				"watch_id": id,
				"node":     "doris-fe-1",
				"state":    "executed",
				"status":   statusObj,
				"trigger_event": map[string]any{
					"type":           "manual",
					"triggered_time": nowISO,
					"manual": map[string]any{
						"schedule": map[string]any{"scheduled_time": nowISO},
					},
				},
				"input":     watchDef["input"],
				"condition": watchDef["condition"],
				"result": map[string]any{
					"execution_time":     nowISO,
					"execution_duration": 1,
					"input": map[string]any{
						"type":    "simple",
						"status":  "success",
						"payload": map[string]any{},
					},
					"condition": map[string]any{
						"type":   "always",
						"status": "success",
						"met":    true,
					},
					"actions": []any{},
				},
				"messages": []any{},
			},
		})

	case "_ack":
		s.mu.Lock()
		entry, exists := s.watches[id]
		if !exists || entry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("watch [%s] not found", id))
			return
		}
		statusObj, _ := entry["status"].(map[string]any)
		if statusObj == nil {
			statusObj = make(map[string]any)
			entry["status"] = statusObj
		}
		actionsMap, _ := statusObj["actions"].(map[string]any)
		if actionsMap == nil {
			actionsMap = make(map[string]any)
			statusObj["actions"] = actionsMap
		}
		if actionID != "" {
			for _, aid := range strings.Split(actionID, ",") {
				aid = strings.TrimSpace(aid)
				if aid == "" {
					continue
				}
				actStat, hasAct := actionsMap[aid].(map[string]any)
				if !hasAct {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("unable to ack watch [%s]: action [%s] not found", id, aid))
					return
				}
				actStat["ack"] = map[string]any{
					"timestamp": nowISO,
					"state":     "acked",
				}
			}
		} else {
			for k := range actionsMap {
				if actStat, okM := actionsMap[k].(map[string]any); okM {
					actStat["ack"] = map[string]any{
						"timestamp": nowISO,
						"state":     "acked",
					}
				}
			}
		}
		clonedStatus := deepCloneDocMap(statusObj)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": clonedStatus})

	case "_activate", "_deactivate":
		activeVal := action == "_activate"
		s.mu.Lock()
		entry, exists := s.watches[id]
		if !exists || entry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("watch [%s] not found", id))
			return
		}
		statusObj, _ := entry["status"].(map[string]any)
		if statusObj == nil {
			statusObj = make(map[string]any)
			entry["status"] = statusObj
		}
		statusObj["state"] = map[string]any{
			"active":    activeVal,
			"timestamp": nowISO,
		}
		clonedStatus := deepCloneDocMap(statusObj)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": clonedStatus})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown watcher watch action ["+action+"]")
	}
}

// handleWatcherRoot implements `/_watcher/stats`, `/_watcher/stats/{metric}`, `/_watcher/_start`, `/_watcher/_stop` (F7).
func (s *Server) handleWatcherRoot(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimSpace(r.PathValue("action"))
	metric := strings.TrimSpace(r.PathValue("metric"))
	switch action {
	case "stats", "_stats":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if metric != "" {
			for _, m := range strings.Split(metric, ",") {
				m = strings.TrimSpace(m)
				switch m {
				case "", "_all", "queued_watches", "current_watches", "pending_watches":
				default:
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "unrecognized metric ["+m+"]")
					return
				}
			}
		}
		s.mu.RLock()
		state := s.watcherState
		if state == "" {
			state = "started"
		}
		watchCount := len(s.watches)
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"_nodes":           map[string]any{"total": 1, "successful": 1, "failed": 0},
			"cluster_name":     "apache-doris-search-cluster",
			"manually_stopped": state == "stopped",
			"stats": []any{
				map[string]any{
					"node_id":               "doris-fe-1",
					"watcher_state":         state,
					"watch_count":           watchCount,
					"execution_thread_pool": map[string]any{"queue_size": 0, "max_size": 1000},
					"current_watches":       []any{},
					"queued_watches":        []any{},
				},
			},
		})

	case "_start", "start":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.watcherState = "started"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "_stop", "stop":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.watcherState = "stopped"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown watcher endpoint ["+action+"]")
	}
}

// handleTransform implements `PUT/GET/DELETE /_transform/{id}`, `GET /_transform`, `POST /_transform/_preview` (F7).
func (s *Server) handleTransform(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "_preview" {
		s.handleTransformPreview(w, r)
		return
	}
	if id == "_stats" {
		r.SetPathValue("id", "")
		s.handleTransformStats(w, r)
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: transform_id is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		if body == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "transform configuration body is required")
			return
		}
		srcMap, _ := body["source"].(map[string]any)
		destMap, _ := body["dest"].(map[string]any)
		if srcMap == nil || srcMap["index"] == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "transform [source.index] is required")
			return
		}
		if destMap == nil || destMap["index"] == nil || strings.TrimSpace(fmt.Sprintf("%v", destMap["index"])) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "transform [dest.index] is required")
			return
		}
		if body["pivot"] == nil && body["latest"] == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "transform requires either [pivot] or [latest]")
			return
		}
		s.mu.Lock()
		if s.transforms == nil {
			s.transforms = make(map[string]map[string]any)
		}
		if _, exists := s.transforms[id]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception",
				fmt.Sprintf("transform [%s] already exists", id))
			return
		}
		nowMs := time.Now().UTC().UnixMilli()
		entry := deepCloneDocMap(body)
		entry["id"] = id
		entry["version"] = "8.12.0"
		entry["create_time"] = nowMs
		entry["state"] = "stopped"
		s.transforms[id] = entry
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		allowNoMatch := true
		if r.URL.Query().Has("allow_no_match") {
			allowNoMatch = isTruthyBoolQueryParam(r, "allow_no_match")
		}
		s.mu.RLock()
		if id != "" && id != "*" && id != "_all" {
			for _, part := range strings.Split(id, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
					continue
				}
				if _, exists := s.transforms[part]; !exists && !allowNoMatch {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception",
						fmt.Sprintf("Unknown transform [%s]", part))
					return
				}
				if _, exists := s.transforms[part]; !exists && !r.URL.Query().Has("allow_no_match") {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception",
						fmt.Sprintf("Unknown transform [%s]", part))
					return
				}
			}
		}
		var names []string
		for k := range s.transforms {
			if id == "" || id == "*" || id == "_all" || matchMultiWildcardWithExclusions(id, k) {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		list := make([]any, 0, len(names))
		for _, k := range names {
			cp := deepCloneDocMap(s.transforms[k])
			delete(cp, "state")
			list = append(list, cp)
		}
		s.mu.RUnlock()
		if len(list) == 0 && id != "" && !allowNoMatch {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("No transform matched [%s]", id))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":      len(list),
			"transforms": list,
		})

	case http.MethodDelete:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: transform_id is missing;")
			return
		}
		force := isTruthyBoolQueryParam(r, "force")
		s.mu.Lock()
		entry, exists := s.transforms[id]
		if !exists || entry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
		if st, _ := entry["state"].(string); st == "started" && !force {
			s.mu.Unlock()
			writeESError(w, http.StatusConflict, "status_exception",
				fmt.Sprintf("Cannot delete transform [%s] because it is started; stop the transform first or use force=true", id))
			return
		}
		delete(s.transforms, id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleTransformAction implements `_start`, `_stop`, `_stats`, `_preview` on transforms (F7).
func (s *Server) handleTransformAction(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimSpace(r.PathValue("action"))
	switch action {
	case "_stats", "stats":
		s.handleTransformStats(w, r)
	case "_preview", "preview":
		s.handleTransformPreview(w, r)
	case "_start", "start":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		s.mu.Lock()
		entry, exists := s.transforms[id]
		if !exists || entry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
		entry["state"] = "started"
		var destIdx string
		if destMap, okD := entry["dest"].(map[string]any); okD {
			destIdx, _ = destMap["index"].(string)
		}
		s.mu.Unlock()
		if destIdx != "" {
			_ = s.ensureIndexSchema(r.Context(), destIdx)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "_stop", "stop":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
		s.mu.Lock()
		var matched int
		for k, entry := range s.transforms {
			if id == "" || id == "*" || id == "_all" || matchMultiWildcardWithExclusions(id, k) {
				entry["state"] = "stopped"
				matched++
			}
		}
		s.mu.Unlock()
		if matched == 0 && !allowNoMatch {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown transform action ["+action+"]")
	}
}

func (s *Server) handleTransformStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
	s.mu.RLock()
	if id != "" && id != "*" && id != "_all" && !strings.ContainsAny(id, "*?,") && !strings.HasPrefix(id, "-") {
		if _, exists := s.transforms[id]; !exists && !allowNoMatch {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
	}
	var names []string
	for k := range s.transforms {
		if id == "" || id == "*" || id == "_all" || matchMultiWildcardWithExclusions(id, k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	nowMs := time.Now().UTC().UnixMilli()
	list := make([]any, 0, len(names))
	for _, k := range names {
		entry := s.transforms[k]
		state, _ := entry["state"].(string)
		if state == "" {
			state = "stopped"
		}
		list = append(list, map[string]any{
			"id":    k,
			"state": state,
			"node": map[string]any{
				"id":   "doris-fe-1",
				"name": "doris-fe-1",
			},
			"stats": map[string]any{
				"pages_processed":                        1,
				"documents_processed":                    0,
				"documents_indexed":                      0,
				"documents_deleted":                      0,
				"trigger_count":                          1,
				"index_time_in_ms":                       0,
				"index_total":                            0,
				"index_failures":                         0,
				"search_time_in_ms":                      0,
				"search_total":                           1,
				"search_failures":                        0,
				"processing_time_in_ms":                  0,
				"processing_total":                       1,
				"delete_time_in_ms":                      0,
				"exponential_avg_checkpoint_duration_ms": 0.0,
				"exponential_avg_documents_indexed":      0.0,
				"exponential_avg_documents_processed":    0.0,
			},
			"checkpointing": map[string]any{
				"last": map[string]any{
					"checkpoint":              1,
					"timestamp_millis":        nowMs,
					"time_upper_bound_millis": nowMs,
				},
			},
		})
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":      len(list),
		"transforms": list,
	})
}

func (s *Server) handleTransformPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var cfg map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &cfg); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if id != "" && id != "_preview" {
		s.mu.RLock()
		entry, exists := s.transforms[id]
		if exists && entry != nil {
			cfg = deepCloneDocMap(entry)
		}
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
	}
	if cfg == nil || cfg["source"] == nil || (cfg["pivot"] == nil && cfg["latest"] == nil) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			"transform preview requires [source] and either [pivot] or [latest]")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"preview": []any{},
		"generated_dest_index": map[string]any{
			"mappings": map[string]any{"properties": map[string]any{}},
			"settings": map[string]any{"index": map[string]any{"number_of_shards": "1", "number_of_replicas": "0"}},
			"aliases":  map[string]any{},
		},
	})
}

// handleDanglingIndices implements `GET /_dangling`, `POST /_dangling/{index_uuid}`, `DELETE /_dangling/{index_uuid}` (F7).
func (s *Server) handleDanglingIndices(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimSpace(r.PathValue("index_uuid"))
	if uuid == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.RLock()
		list := make([]any, 0, len(s.danglingIndices))
		for _, v := range s.danglingIndices {
			list = append(list, deepCloneDocMap(v))
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"_nodes":           map[string]any{"total": 1, "successful": 1, "failed": 0},
			"cluster_name":     "apache-doris-search-cluster",
			"dangling_indices": list,
		})
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if !isTruthyBoolQueryParam(r, "accept_data_loss") {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			"Must set accept_data_loss to [true] in order to import or delete a dangling index")
		return
	}
	s.mu.Lock()
	entry, exists := s.danglingIndices[uuid]
	if !exists {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such dangling index [%s]", uuid))
		return
	}
	idxName, _ := entry["index_name"].(string)
	delete(s.danglingIndices, uuid)
	s.mu.Unlock()
	if r.Method == http.MethodPost && idxName != "" {
		_ = s.ensureIndexSchema(r.Context(), idxName)
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

// handleAutoscaling implements `PUT/GET/DELETE /_autoscaling/policy/{name}`, `GET /_autoscaling/policy`, `GET /_autoscaling/capacity` (F7).
func (s *Server) handleAutoscaling(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimSpace(r.PathValue("action"))
	name := strings.TrimSpace(r.PathValue("name"))
	if action == "capacity" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.RLock()
		policiesCap := make(map[string]any, len(s.autoscalingPolicies))
		for k := range s.autoscalingPolicies {
			policiesCap[k] = map[string]any{
				"required_capacity": map[string]any{
					"node_A": map[string]any{"storage": 0, "memory": 0},
					"total":  map[string]any{"storage": 0, "memory": 0},
				},
				"current_capacity": map[string]any{
					"node_A": map[string]any{"storage": 0, "memory": 0},
					"total":  map[string]any{"storage": 0, "memory": 0},
				},
				"current_nodes": []any{
					map[string]any{"name": "doris-fe-1"},
				},
				"deciders": map[string]any{},
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"policies": policiesCap,
			"deciders": map[string]any{},
		})
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		if body == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "autoscaling policy body is required")
			return
		}
		roles, hasRoles := body["roles"].([]any)
		if !hasRoles || len(roles) == 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "autoscaling policy must specify non-empty [roles]")
			return
		}
		deciders, hasDeciders := body["deciders"].(map[string]any)
		if !hasDeciders || deciders == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "autoscaling policy must specify [deciders]")
			return
		}
		s.mu.Lock()
		if s.autoscalingPolicies == nil {
			s.autoscalingPolicies = make(map[string]map[string]any)
		}
		s.autoscalingPolicies[name] = map[string]any{
			"roles":    roles,
			"deciders": deciders,
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		if name != "" && name != "*" && name != "_all" {
			entry, exists := s.autoscalingPolicies[name]
			if !exists {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception",
					fmt.Sprintf("autoscaling policy [%s] does not exist", name))
				return
			}
			cp := deepCloneDocMap(entry)
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"policies": map[string]any{name: cp},
			})
			return
		}
		out := make(map[string]any, len(s.autoscalingPolicies))
		for k, v := range s.autoscalingPolicies {
			out[k] = deepCloneDocMap(v)
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"policies": out})

	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		s.mu.Lock()
		if _, exists := s.autoscalingPolicies[name]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("autoscaling policy [%s] does not exist", name))
			return
		}
		delete(s.autoscalingPolicies, name)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}
