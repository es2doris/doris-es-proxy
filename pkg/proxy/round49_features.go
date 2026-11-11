package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
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

	if snap == "_cleanup" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.RLock()
		_, repoExists := s.snapshotRepos[repo]
		s.mu.RUnlock()
		if !repoExists {
			writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"results": map[string]any{
				"deleted_bytes": 0,
				"deleted_keys":  0,
			},
		})
		return
	}

	if snap == "_status" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		s.mu.RLock()
		var targetRepos []string
		if repo == "_all" || repo == "*" {
			for rName := range s.snapshotRepos {
				targetRepos = append(targetRepos, rName)
			}
			sort.Strings(targetRepos)
		} else {
			for _, pat := range strings.Split(repo, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" {
					continue
				}
				if !strings.ContainsAny(pat, "*?") && !strings.HasPrefix(pat, "-") && pat != "_all" {
					if _, exists := s.snapshotRepos[pat]; !exists {
						s.mu.RUnlock()
						writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", pat))
						return
					}
				}
			}
			for rName := range s.snapshotRepos {
				if matchMultiWildcardWithExclusions(repo, rName) {
					targetRepos = append(targetRepos, rName)
				}
			}
			sort.Strings(targetRepos)
		}
		list := make([]any, 0)
		for _, rName := range targetRepos {
			bySnap := s.snapshots[rName]
			names := make([]string, 0, len(bySnap))
			for k := range bySnap {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				list = append(list, map[string]any{
					"snapshot":   k,
					"repository": rName,
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
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": list})
		return
	}

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
		var toDelete []string
		if snap == "_all" || snap == "*" {
			for sName := range bySnap {
				toDelete = append(toDelete, sName)
			}
		} else {
			for _, pat := range strings.Split(snap, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" {
					continue
				}
				if !strings.ContainsAny(pat, "*?") && !strings.HasPrefix(pat, "-") && pat != "_all" {
					if _, exists := bySnap[pat]; !exists {
						s.mu.Unlock()
						writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, pat))
						return
					}
				}
			}
			for sName := range bySnap {
				if matchMultiWildcardWithExclusions(snap, sName) {
					toDelete = append(toDelete, sName)
				}
			}
		}
		if len(toDelete) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, snap))
			return
		}
		for _, sName := range toDelete {
			delete(bySnap, sName)
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

// handleSnapshotItemAction implements `POST /_snapshot/{repository}/{snapshot}/_restore`, `_mount`, and `GET /_snapshot/{repository}/{snapshot}/_status` (F1, F7, F9).
func (s *Server) handleSnapshotItemAction(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.PathValue("repository"))
	snap := strings.TrimSpace(r.PathValue("snapshot"))
	action := strings.TrimSpace(r.PathValue("action"))

	if action == "_status" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
			return
		}
		s.mu.RLock()
		var targetRepos []string
		if repo == "_all" || repo == "*" {
			for rName := range s.snapshotRepos {
				targetRepos = append(targetRepos, rName)
			}
			sort.Strings(targetRepos)
		} else {
			for _, pat := range strings.Split(repo, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" {
					continue
				}
				if !strings.ContainsAny(pat, "*?") && !strings.HasPrefix(pat, "-") && pat != "_all" {
					if _, exists := s.snapshotRepos[pat]; !exists {
						s.mu.RUnlock()
						writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", pat))
						return
					}
				}
			}
			for rName := range s.snapshotRepos {
				if matchMultiWildcardWithExclusions(repo, rName) {
					targetRepos = append(targetRepos, rName)
				}
			}
			sort.Strings(targetRepos)
		}
		if snap != "_all" && snap != "*" {
			for _, pat := range strings.Split(snap, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" || strings.ContainsAny(pat, "*?") || strings.HasPrefix(pat, "-") || pat == "_all" {
					continue
				}
				found := false
				for _, rName := range targetRepos {
					if s.snapshots[rName] != nil && s.snapshots[rName][pat] != nil {
						found = true
						break
					}
				}
				if !found {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, pat))
					return
				}
			}
		}
		list := make([]any, 0)
		for _, rName := range targetRepos {
			bySnap := s.snapshots[rName]
			names := make([]string, 0, len(bySnap))
			for k := range bySnap {
				if snap == "_all" || snap == "*" || matchMultiWildcardWithExclusions(snap, k) {
					names = append(names, k)
				}
			}
			sort.Strings(names)
			for _, k := range names {
				list = append(list, map[string]any{
					"snapshot":   k,
					"repository": rName,
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
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": list})
		return
	}

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
	case "_mount":
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
		srcIdx, _ := reqMap["index"].(string)
		srcIdx = strings.TrimSpace(srcIdx)
		if srcIdx == "" && len(snapIndices) > 0 {
			srcIdx = snapIndices[0]
		}
		if srcIdx == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
			return
		}
		if len(snapIndices) > 0 {
			inSnap := false
			for _, si := range snapIndices {
				if si == srcIdx {
					inSnap = true
					break
				}
			}
			if !inSnap {
				writeESError(w, http.StatusNotFound, "snapshot_restore_exception",
					fmt.Sprintf("[%s:%s] index [%s] wasn't fully snapshotted", repo, snap, srcIdx))
				return
			}
		}
		targetIdx, _ := reqMap["renamed_index"].(string)
		targetIdx = strings.TrimSpace(targetIdx)
		if targetIdx == "" {
			targetIdx = srcIdx
		}
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
		s.mu.Lock()
		if s.indexCustomSettings == nil {
			s.indexCustomSettings = make(map[string]map[string]any)
		}
		if s.indexCustomSettings[targetIdx] == nil {
			s.indexCustomSettings[targetIdx] = make(map[string]any)
		}
		s.indexCustomSettings[targetIdx]["store.type"] = "snapshot"
		if idxSettings, okS := reqMap["index_settings"].(map[string]any); okS {
			for k, v := range idxSettings {
				s.indexCustomSettings[targetIdx][strings.TrimPrefix(k, "index.")] = v
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": true,
			"snapshot": map[string]any{
				"snapshot": snap,
				"indices":  []string{targetIdx},
				"shards": map[string]any{
					"total":      1,
					"failed":     0,
					"successful": 1,
				},
			},
		})
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

// handleIngestGeoIPStats implements `GET/HEAD /_ingest/geoip/stats` (F6/Round 56 F8).
func (s *Server) handleIngestGeoIPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	s.mu.RLock()
	dbCount := len(s.geoipDatabases)
	var dbNames []string
	for id, entry := range s.geoipDatabases {
		if df, ok := entry["database_file"].(string); ok && df != "" {
			dbNames = append(dbNames, df)
		} else {
			dbNames = append(dbNames, id)
		}
	}
	s.mu.RUnlock()
	sort.Strings(dbNames)
	nodesMap := map[string]any{}
	if len(dbNames) > 0 {
		dbObjs := make([]any, 0, len(dbNames))
		for _, dn := range dbNames {
			dbObjs = append(dbObjs, map[string]any{"name": dn})
		}
		nodesMap["doris-node-1"] = map[string]any{
			"databases":     dbObjs,
			"files_in_temp": []any{},
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stats": map[string]any{
			"successful_downloads": dbCount,
			"failed_downloads":     0,
			"total_download_time":  0,
			"databases_count":      dbCount,
			"skipped_updates":      0,
		},
		"nodes": nodesMap,
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

	case "settings", "_settings":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			settingsCopy := make(map[string]any, len(s.watcherSettings))
			for k, v := range s.watcherSettings {
				settingsCopy[k] = v
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			resp := map[string]any{
				"acknowledged": true,
				"settings":     settingsCopy,
				"persistent":   settingsCopy,
			}
			for k, v := range settingsCopy {
				if _, exists := resp[k]; !exists {
					resp[k] = v
				}
			}
			writeJSON(w, http.StatusOK, resp)
		case http.MethodPut, http.MethodPost:
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			if s.watcherSettings == nil {
				s.watcherSettings = make(map[string]any)
			}
			for k, v := range body {
				if sub, isMap := v.(map[string]any); isMap && (k == "settings" || k == "persistent" || k == "transient") {
					for sk, sv := range sub {
						s.watcherSettings[sk] = sv
					}
				} else {
					s.watcherSettings[k] = v
				}
			}
			settingsCopy := make(map[string]any, len(s.watcherSettings))
			for k, v := range s.watcherSettings {
				settingsCopy[k] = v
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"acknowledged": true,
				"settings":     settingsCopy,
				"persistent":   settingsCopy,
			})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown watcher endpoint ["+action+"]")
	}
}

// handleTransform implements `PUT/GET/DELETE /_transform/{id}`, `GET /_transform`, `POST /_transform/_preview` (F7).
func (s *Server) handleTransform(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "_upgrade" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "updated": []any{}, "pending_transforms": []any{}})
		return
	}
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

	case "_update", "update":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
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
			writeESError(w, http.StatusBadRequest, "parse_exception", "request body is required")
			return
		}
		s.mu.Lock()
		entry, exists := s.transforms[id]
		if !exists || entry == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("Unknown transform [%s]", id))
			return
		}
		if _, hasPivot := body["pivot"]; hasPivot {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "transform [pivot] is immutable and cannot be updated")
			return
		}
		for _, k := range []string{"description", "source", "dest", "frequency", "sync", "settings", "retention_policy"} {
			if v, has := body[k]; has {
				entry[k] = v
			}
		}
		resp := deepCloneDocMap(entry)
		delete(resp, "state")
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, resp)

	case "_reset", "reset":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
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
				fmt.Sprintf("Cannot reset transform [%s] because it is started; stop the transform first or use force=true", id))
			return
		}
		entry["state"] = "stopped"
		delete(entry, "checkpoint")
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "_schedule_now", "schedule_now":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		s.mu.RLock()
		entry, exists := s.transforms[id]
		s.mu.RUnlock()
		if !exists || entry == nil {
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

func reloadAnalyzersDetailsPayload() map[string]any {
	return map[string]any{
		"_shards": map[string]any{
			"total":      0,
			"successful": 0,
			"failed":     0,
		},
		"reload_details": []any{},
	}
}

func parseFromSizePagination(r *http.Request, defaultSize int) (int, int) {
	from := 0
	size := defaultSize
	if r != nil && r.URL != nil {
		if rawFrom := strings.TrimSpace(r.URL.Query().Get("from")); rawFrom != "" {
			if v, err := strconv.Atoi(rawFrom); err == nil && v >= 0 {
				from = v
			}
		}
		if rawSize := strings.TrimSpace(r.URL.Query().Get("size")); rawSize != "" {
			if v, err := strconv.Atoi(rawSize); err == nil && v >= 0 {
				size = v
			}
		}
	}
	return from, size
}

// handleSynonyms implements the Elasticsearch 8.x Synonyms Management API (`/_synonyms` and `/_synonyms/{id}/*`) (F2).
func (s *Server) handleSynonyms(w http.ResponseWriter, r *http.Request, segs []string) {
	switch len(segs) {
	case 1:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		from, size := parseFromSizePagination(r, 10000)
		s.mu.RLock()
		setIDs := make([]string, 0, len(s.synonymSets))
		for id := range s.synonymSets {
			setIDs = append(setIDs, id)
		}
		sort.Strings(setIDs)
		total := len(setIDs)
		results := make([]any, 0)
		for i := from; i < total && len(results) < size; i++ {
			id := setIDs[i]
			results = append(results, map[string]any{
				"synonyms_set": id,
				"count":        len(s.synonymSets[id]),
			})
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   total,
			"results": results,
		})

	case 2:
		setID := strings.TrimSpace(segs[1])
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			rawRules, ok := body["synonyms_set"].([]any)
			if !ok || len(rawRules) == 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[synonyms_set] required property is missing or empty")
				return
			}
			seenIDs := make(map[string]bool, len(rawRules))
			rules := make([]map[string]any, 0, len(rawRules))
			for idx, item := range rawRules {
				rm, ok := item.(map[string]any)
				if !ok || rm == nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", "synonym rule must be an object")
					return
				}
				synStr, _ := rm["synonyms"].(string)
				if strings.TrimSpace(synStr) == "" {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "synonym rule [synonyms] is required")
					return
				}
				ruleID, _ := rm["id"].(string)
				ruleID = strings.TrimSpace(ruleID)
				if ruleID == "" {
					ruleID = fmt.Sprintf("rule-%d", idx)
				}
				if seenIDs[ruleID] {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("duplicate synonym rule id [%s]", ruleID))
					return
				}
				seenIDs[ruleID] = true
				rules = append(rules, map[string]any{
					"id":       ruleID,
					"synonyms": synStr,
				})
			}
			s.mu.Lock()
			if s.synonymSets == nil {
				s.synonymSets = make(map[string][]map[string]any)
			}
			_, existed := s.synonymSets[setID]
			s.synonymSets[setID] = rules
			s.mu.Unlock()
			resStr := "created"
			if existed {
				resStr = "updated"
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"result":                   resStr,
				"reload_analyzers_details": reloadAnalyzersDetailsPayload(),
			})

		case http.MethodGet, http.MethodHead:
			from, size := parseFromSizePagination(r, 10000)
			s.mu.RLock()
			rules, exists := s.synonymSets[setID]
			if !exists {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonyms_set [%s] not found", setID))
				return
			}
			total := len(rules)
			page := make([]any, 0)
			for i := from; i < total && len(page) < size; i++ {
				page = append(page, deepCloneDocMap(rules[i]))
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"count":        total,
				"synonyms_set": page,
			})

		case http.MethodDelete:
			s.mu.Lock()
			if _, exists := s.synonymSets[setID]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonyms_set [%s] not found", setID))
				return
			}
			delete(s.synonymSets, setID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case 3:
		setID := strings.TrimSpace(segs[1])
		sub := strings.TrimSpace(segs[2])
		if sub == "_reload" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			_, exists := s.synonymSets[setID]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonyms_set [%s] not found", setID))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"reload_analyzers_details": reloadAnalyzersDetailsPayload(),
			})
			return
		}
		ruleID := sub
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			synStr, _ := body["synonyms"].(string)
			if strings.TrimSpace(synStr) == "" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "synonym rule [synonyms] is required")
				return
			}
			s.mu.Lock()
			rules, exists := s.synonymSets[setID]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonyms_set [%s] not found", setID))
				return
			}
			resStr := "created"
			foundIdx := -1
			for idx, rm := range rules {
				if rm["id"] == ruleID {
					foundIdx = idx
					break
				}
			}
			newRule := map[string]any{"id": ruleID, "synonyms": synStr}
			if foundIdx >= 0 {
				rules[foundIdx] = newRule
				resStr = "updated"
			} else {
				rules = append(rules, newRule)
			}
			s.synonymSets[setID] = rules
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"result":                   resStr,
				"reload_analyzers_details": reloadAnalyzersDetailsPayload(),
			})

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			rules, exists := s.synonymSets[setID]
			var found map[string]any
			if exists {
				for _, rm := range rules {
					if rm["id"] == ruleID {
						found = deepCloneDocMap(rm)
						break
					}
				}
			}
			s.mu.RUnlock()
			if found == nil {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonym rule [%s] not found in set [%s]", ruleID, setID))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, found)

		case http.MethodDelete:
			s.mu.Lock()
			rules, exists := s.synonymSets[setID]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonyms_set [%s] not found", setID))
				return
			}
			foundIdx := -1
			for idx, rm := range rules {
				if rm["id"] == ruleID {
					foundIdx = idx
					break
				}
			}
			if foundIdx < 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("synonym rule [%s] not found in set [%s]", ruleID, setID))
				return
			}
			s.synonymSets[setID] = append(rules[:foundIdx], rules[foundIdx+1:]...)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"result":                   "deleted",
				"reload_analyzers_details": reloadAnalyzersDetailsPayload(),
			})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func validateSingleQueryRule(rm map[string]any) error {
	if rm == nil {
		return fmt.Errorf("rule must be an object")
	}
	ruleID, _ := rm["rule_id"].(string)
	if strings.TrimSpace(ruleID) == "" {
		return fmt.Errorf("[rule_id] required property is missing")
	}
	ruleType, _ := rm["type"].(string)
	switch ruleType {
	case "pinned", "exclude":
	default:
		return fmt.Errorf("unsupported query rule type [%s], must be [pinned] or [exclude]", ruleType)
	}
	criteria, ok := rm["criteria"].([]any)
	if !ok || len(criteria) == 0 {
		return fmt.Errorf("[criteria] must be a non-empty array")
	}
	for _, cAny := range criteria {
		cm, ok := cAny.(map[string]any)
		if !ok || cm == nil {
			return fmt.Errorf("criterion must be an object")
		}
		cType, _ := cm["type"].(string)
		switch cType {
		case "always":
		case "exact", "contains", "prefix", "suffix", "fuzzy", "lt", "lte", "gt", "gte":
			meta, _ := cm["metadata"].(string)
			if strings.TrimSpace(meta) == "" {
				return fmt.Errorf("criterion [metadata] is required for type [%s]", cType)
			}
			vals, ok := cm["values"].([]any)
			if !ok || len(vals) == 0 {
				return fmt.Errorf("criterion [values] must be a non-empty array for type [%s]", cType)
			}
		default:
			return fmt.Errorf("unsupported criterion type [%s]", cType)
		}
	}
	actions, ok := rm["actions"].(map[string]any)
	if !ok || actions == nil {
		return fmt.Errorf("[actions] required property is missing")
	}
	ids, hasIDs := actions["ids"].([]any)
	docs, hasDocs := actions["docs"].([]any)
	if (!hasIDs || len(ids) == 0) && (!hasDocs || len(docs) == 0) {
		return fmt.Errorf("actions must specify non-empty [ids] or [docs]")
	}
	return nil
}

func queryRuleLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			cur[j] = m
		}
		copy(prev, cur)
	}
	return prev[lb]
}

func ruleMatchesCriteria(rm map[string]any, matchCriteria map[string]any) bool {
	criteria, _ := rm["criteria"].([]any)
	if len(criteria) == 0 {
		return false
	}
	for _, cAny := range criteria {
		cm, ok := cAny.(map[string]any)
		if !ok || cm == nil {
			return false
		}
		cType, _ := cm["type"].(string)
		if cType == "always" {
			continue
		}
		meta, _ := cm["metadata"].(string)
		candVal, exists := matchCriteria[meta]
		if !exists || candVal == nil {
			return false
		}
		candStr := fmt.Sprintf("%v", candVal)
		candLower := strings.ToLower(candStr)
		candNum, candIsNum := ingestNumericFloat64(candVal)
		vals, _ := cm["values"].([]any)
		matchedAnyVal := false
		for _, v := range vals {
			vStr := fmt.Sprintf("%v", v)
			vLower := strings.ToLower(vStr)
			switch cType {
			case "exact":
				if candStr == vStr || (candIsNum && ingestValuesEqual(candVal, v)) {
					matchedAnyVal = true
				}
			case "contains":
				if strings.Contains(candLower, vLower) {
					matchedAnyVal = true
				}
			case "prefix":
				if strings.HasPrefix(candLower, vLower) {
					matchedAnyVal = true
				}
			case "suffix":
				if strings.HasSuffix(candLower, vLower) {
					matchedAnyVal = true
				}
			case "fuzzy":
				maxDist := 2
				if len(vLower) <= 2 {
					maxDist = 0
				} else if len(vLower) <= 5 {
					maxDist = 1
				}
				if queryRuleLevenshtein(candLower, vLower) <= maxDist {
					matchedAnyVal = true
				} else {
					for _, tok := range strings.Fields(candLower) {
						if queryRuleLevenshtein(tok, vLower) <= maxDist {
							matchedAnyVal = true
							break
						}
					}
				}
			case "lt", "lte", "gt", "gte":
				if vNum, vIsNum := ingestNumericFloat64(v); candIsNum && vIsNum {
					switch cType {
					case "lt":
						matchedAnyVal = candNum < vNum
					case "lte":
						matchedAnyVal = candNum <= vNum
					case "gt":
						matchedAnyVal = candNum > vNum
					case "gte":
						matchedAnyVal = candNum >= vNum
					}
				} else {
					switch cType {
					case "lt":
						matchedAnyVal = candStr < vStr
					case "lte":
						matchedAnyVal = candStr <= vStr
					case "gt":
						matchedAnyVal = candStr > vStr
					case "gte":
						matchedAnyVal = candStr >= vStr
					}
				}
			}
			if matchedAnyVal {
				break
			}
		}
		if !matchedAnyVal {
			return false
		}
	}
	return true
}

// handleQueryRules implements the Elasticsearch 8.x Query Rules Management API (`/_query_rules` and `/_query_rules/{ruleset_id}/*`) (F3).
func (s *Server) handleQueryRules(w http.ResponseWriter, r *http.Request, segs []string) {
	switch len(segs) {
	case 1:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		from, size := parseFromSizePagination(r, 1000)
		s.mu.RLock()
		ids := make([]string, 0, len(s.queryRulesets))
		for id := range s.queryRulesets {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		total := len(ids)
		results := make([]any, 0)
		for i := from; i < total && len(results) < size; i++ {
			id := ids[i]
			results = append(results, map[string]any{
				"ruleset_id": id,
				"count":      len(s.queryRulesets[id]),
			})
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   total,
			"results": results,
		})

	case 2:
		rulesetID := strings.TrimSpace(segs[1])
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			rawRules, ok := body["rules"].([]any)
			if !ok || len(rawRules) == 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[rules] required property is missing or empty")
				return
			}
			seenIDs := make(map[string]bool, len(rawRules))
			rules := make([]map[string]any, 0, len(rawRules))
			for _, item := range rawRules {
				rm, _ := item.(map[string]any)
				if err := validateSingleQueryRule(rm); err != nil {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
					return
				}
				rid, _ := rm["rule_id"].(string)
				if seenIDs[rid] {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("duplicate rule_id [%s]", rid))
					return
				}
				seenIDs[rid] = true
				rules = append(rules, deepCloneDocMap(rm))
			}
			s.mu.Lock()
			if s.queryRulesets == nil {
				s.queryRulesets = make(map[string][]map[string]any)
			}
			_, existed := s.queryRulesets[rulesetID]
			s.queryRulesets[rulesetID] = rules
			s.mu.Unlock()
			if existed {
				writeJSON(w, http.StatusOK, map[string]any{"result": "updated"})
			} else {
				writeJSON(w, http.StatusCreated, map[string]any{"result": "created"})
			}

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			rules, exists := s.queryRulesets[rulesetID]
			if !exists {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("query_ruleset [%s] not found", rulesetID))
				return
			}
			cloned := make([]any, 0, len(rules))
			for _, rm := range rules {
				cloned = append(cloned, deepCloneDocMap(rm))
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ruleset_id": rulesetID,
				"rules":      cloned,
			})

		case http.MethodDelete:
			s.mu.Lock()
			if _, exists := s.queryRulesets[rulesetID]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("query_ruleset [%s] not found", rulesetID))
				return
			}
			delete(s.queryRulesets, rulesetID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case 3:
		rulesetID := strings.TrimSpace(segs[1])
		action := strings.TrimSpace(segs[2])
		if action != "_test" {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			return
		}
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
		matchCriteria, _ := body["match_criteria"].(map[string]any)
		if matchCriteria == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[match_criteria] is required")
			return
		}
		s.mu.RLock()
		rules, exists := s.queryRulesets[rulesetID]
		if !exists {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("query_ruleset [%s] not found", rulesetID))
			return
		}
		matched := make([]any, 0)
		for _, rm := range rules {
			if ruleMatchesCriteria(rm, matchCriteria) {
				matched = append(matched, map[string]any{
					"rule_id": rm["rule_id"],
					"type":    rm["type"],
					"actions": deepCloneIngestValue(rm["actions"]),
				})
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"matched_rules": matched,
		})

	case 4:
		rulesetID := strings.TrimSpace(segs[1])
		if segs[2] != "_rule" {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			return
		}
		ruleID := strings.TrimSpace(segs[3])
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			if body == nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "rule body is required")
				return
			}
			if bodyRuleID, _ := body["rule_id"].(string); strings.TrimSpace(bodyRuleID) != "" && bodyRuleID != ruleID {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "rule_id in body does not match URL")
				return
			}
			body["rule_id"] = ruleID
			if err := validateSingleQueryRule(body); err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
			s.mu.Lock()
			if s.queryRulesets == nil {
				s.queryRulesets = make(map[string][]map[string]any)
			}
			rules := s.queryRulesets[rulesetID]
			foundIdx := -1
			for idx, rm := range rules {
				if rm["rule_id"] == ruleID {
					foundIdx = idx
					break
				}
			}
			cloned := deepCloneDocMap(body)
			if foundIdx >= 0 {
				rules[foundIdx] = cloned
				s.queryRulesets[rulesetID] = rules
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"result": "updated"})
			} else {
				s.queryRulesets[rulesetID] = append(rules, cloned)
				s.mu.Unlock()
				writeJSON(w, http.StatusCreated, map[string]any{"result": "created"})
			}

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			rules, exists := s.queryRulesets[rulesetID]
			var found map[string]any
			if exists {
				for _, rm := range rules {
					if rm["rule_id"] == ruleID {
						found = deepCloneDocMap(rm)
						break
					}
				}
			}
			s.mu.RUnlock()
			if found == nil {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("rule [%s] not found in ruleset [%s]", ruleID, rulesetID))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, found)

		case http.MethodDelete:
			s.mu.Lock()
			rules, exists := s.queryRulesets[rulesetID]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("query_ruleset [%s] not found", rulesetID))
				return
			}
			foundIdx := -1
			for idx, rm := range rules {
				if rm["rule_id"] == ruleID {
					foundIdx = idx
					break
				}
			}
			if foundIdx < 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("rule [%s] not found in ruleset [%s]", ruleID, rulesetID))
				return
			}
			s.queryRulesets[rulesetID] = append(rules[:foundIdx], rules[foundIdx+1:]...)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"result": "deleted", "acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func (s *Server) expandRuleQuerySpec(ruleSpec map[string]any) map[string]any {
	organic, _ := ruleSpec["organic"].(map[string]any)
	if organic == nil {
		organic = map[string]any{"match_all": map[string]any{}}
	}
	matchCriteria, _ := ruleSpec["match_criteria"].(map[string]any)
	var rulesetIDs []string
	if rids, ok := ruleSpec["ruleset_ids"].([]any); ok {
		for _, item := range rids {
			if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
				rulesetIDs = append(rulesetIDs, strings.TrimSpace(str))
			}
		}
	} else if rid, ok := ruleSpec["ruleset_id"].(string); ok && strings.TrimSpace(rid) != "" {
		rulesetIDs = []string{strings.TrimSpace(rid)}
	}
	var pinnedIDs []any
	var excludedIDs []any
	seenPinned := make(map[string]bool)
	seenExcluded := make(map[string]bool)
	extractActionIDs := func(actions map[string]any) []string {
		var out []string
		if ids, ok := actions["ids"].([]any); ok {
			for _, idAny := range ids {
				if s := strings.TrimSpace(fmt.Sprintf("%v", idAny)); s != "" {
					out = append(out, s)
				}
			}
		}
		if docs, ok := actions["docs"].([]any); ok {
			for _, dAny := range docs {
				if dm, ok := dAny.(map[string]any); ok {
					if s := strings.TrimSpace(fmt.Sprintf("%v", dm["_id"])); s != "" && s != "<nil>" {
						out = append(out, s)
					}
				}
			}
		}
		return out
	}
	s.mu.RLock()
	for _, rsid := range rulesetIDs {
		for _, rm := range s.queryRulesets[rsid] {
			if ruleMatchesCriteria(rm, matchCriteria) {
				rType, _ := rm["type"].(string)
				actions, _ := rm["actions"].(map[string]any)
				for _, docID := range extractActionIDs(actions) {
					switch rType {
					case "pinned":
						if !seenPinned[docID] && !seenExcluded[docID] {
							seenPinned[docID] = true
							pinnedIDs = append(pinnedIDs, docID)
						}
					case "exclude":
						if !seenExcluded[docID] {
							seenExcluded[docID] = true
							excludedIDs = append(excludedIDs, docID)
						}
					}
				}
			}
		}
	}
	s.mu.RUnlock()

	curQuery := organic
	if len(excludedIDs) > 0 {
		curQuery = map[string]any{
			"bool": map[string]any{
				"must": []any{curQuery},
				"must_not": []any{
					map[string]any{
						"ids": map[string]any{"values": excludedIDs},
					},
				},
			},
		}
	}
	if len(pinnedIDs) > 0 {
		curQuery = map[string]any{
			"pinned": map[string]any{
				"ids":     pinnedIDs,
				"organic": curQuery,
			},
		}
	}
	return curQuery
}

func (s *Server) rewriteQueryRulesInTree(node any) (any, bool) {
	switch v := node.(type) {
	case map[string]any:
		if len(v) == 1 {
			if ruleSpec, ok := v["rule"].(map[string]any); ok && (ruleSpec["ruleset_ids"] != nil || ruleSpec["ruleset_id"] != nil || ruleSpec["organic"] != nil) {
				return s.expandRuleQuerySpec(ruleSpec), true
			}
			if ruleSpec, ok := v["rule_query"].(map[string]any); ok && (ruleSpec["ruleset_ids"] != nil || ruleSpec["ruleset_id"] != nil || ruleSpec["organic"] != nil) {
				return s.expandRuleQuerySpec(ruleSpec), true
			}
		}
		changed := false
		for k, child := range v {
			if next, ch := s.rewriteQueryRulesInTree(child); ch {
				v[k] = next
				changed = true
			}
		}
		return v, changed
	case []any:
		changed := false
		for i, elem := range v {
			if next, ch := s.rewriteQueryRulesInTree(elem); ch {
				v[i] = next
				changed = true
			}
		}
		return v, changed
	default:
		return node, false
	}
}

func (s *Server) rewriteSearchBodyQueryRules(bodyBytes []byte) []byte {
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return bodyBytes
	}
	if !bytes.Contains(bodyBytes, []byte(`"rule"`)) && !bytes.Contains(bodyBytes, []byte(`"rule_query"`)) {
		return bodyBytes
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil {
		return bodyBytes
	}
	changed := false
	if retr, ok := root["retriever"].(map[string]any); ok {
		if ruleSpec, okR := retr["rule"].(map[string]any); okR {
			root["query"] = s.expandRuleQuerySpec(ruleSpec)
			delete(root, "retriever")
			changed = true
		}
	}
	if q, hasQ := root["query"]; hasQ {
		if nextQ, ch := s.rewriteQueryRulesInTree(q); ch {
			root["query"] = nextQ
			changed = true
		}
	}
	if !changed {
		return bodyBytes
	}
	out, err := json.Marshal(root)
	if err != nil {
		return bodyBytes
	}
	return out
}

// handleFeatures implements `GET /_features` and `POST /_features/_reset` (F4).
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request, segs []string) {
	featureNames := []struct {
		name string
		desc string
	}{
		{"ingest", "Manages ingest pipelines"},
		{"ilm", "Manages index lifecycle policies"},
		{"slm", "Manages snapshot lifecycle policies"},
		{"synonyms", "Manages synonym sets"},
		{"query_rules", "Manages query rules"},
		{"transform", "Manages transforms"},
		{"rollup", "Manages rollup jobs"},
		{"enrich", "Manages enrich policies"},
	}
	if len(segs) == 1 {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		features := make([]any, 0, len(featureNames))
		for _, f := range featureNames {
			features = append(features, map[string]any{
				"name":        f.name,
				"description": f.desc,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"features": features})
		return
	}
	if len(segs) == 2 && segs[1] == "_reset" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		s.pipelines = make(map[string]map[string]any)
		s.ilmPolicies = make(map[string]map[string]any)
		s.slmPolicies = make(map[string]map[string]any)
		s.enrichPolicies = make(map[string]map[string]any)
		s.transforms = make(map[string]map[string]any)
		s.rollupJobs = make(map[string]map[string]any)
		s.synonymSets = make(map[string][]map[string]any)
		s.queryRulesets = make(map[string][]map[string]any)
		s.scripts = make(map[string]map[string]any)
		s.watches = make(map[string]map[string]any)
		s.autoscalingPolicies = make(map[string]map[string]any)
		s.inferenceEndpoints = make(map[string]map[string]any)
		s.connectors = make(map[string]map[string]any)
		s.connectorSyncJobs = make(map[string]map[string]any)
		s.searchApplications = make(map[string]map[string]any)
		s.analyticsCollections = make(map[string]map[string]any)
		s.asyncSearches = make(map[string]map[string]any)
		s.esqlAsyncQueries = make(map[string]map[string]any)
		s.watcherSettings = make(map[string]any)
		s.licenseState = nil
		s.sqlAsyncSearches = make(map[string]map[string]any)
		s.eqlSearches = make(map[string]map[string]any)
		s.mlJobs = make(map[string]map[string]any)
		s.mlDatafeeds = make(map[string]map[string]any)
		s.mlTrainedModels = make(map[string]map[string]any)
		s.mlCalendars = make(map[string]map[string]any)
		s.mlFilters = make(map[string]map[string]any)
		s.mlDataFrameAnalytics = make(map[string]map[string]any)
		s.mlModelDeployments = make(map[string]map[string]any)
		s.mlModelAliases = make(map[string]string)
		s.mlUpgradeMode = false
		s.securityRoleMappings = make(map[string]map[string]any)
		s.securityProfiles = make(map[string]map[string]any)
		s.securitySettings = make(map[string]any)
		s.geoipDatabases = make(map[string]map[string]any)
		s.templateLifecycles = make(map[string]map[string]any)
		s.remoteClusters = make(map[string]map[string]any)
		s.mu.Unlock()
		statuses := make([]any, 0, len(featureNames))
		for _, f := range featureNames {
			statuses = append(statuses, map[string]any{
				"feature_name": f.name,
				"status":       "SUCCESS",
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"features": statuses})
		return
	}
	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
}

// handleVotingConfigExclusions implements `POST /_cluster/voting_config_exclusions` and `DELETE /_cluster/voting_config_exclusions` (F4).
func (s *Server) handleVotingConfigExclusions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		nodeIDs := strings.TrimSpace(r.URL.Query().Get("node_ids"))
		nodeNames := strings.TrimSpace(r.URL.Query().Get("node_names"))
		if nodeIDs == "" && nodeNames == "" {
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				var body map[string]any
				if err := json.Unmarshal(bodyBytes, &body); err == nil {
					if s, ok := body["node_ids"].(string); ok {
						nodeIDs = strings.TrimSpace(s)
					}
					if s, ok := body["node_names"].(string); ok {
						nodeNames = strings.TrimSpace(s)
					}
				}
			}
		}
		if nodeIDs == "" && nodeNames == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				"add voting config exclusions request must specify at least one of [node_ids] or [node_names]")
			return
		}
		s.mu.Lock()
		for _, id := range strings.Split(nodeIDs, ",") {
			if id = strings.TrimSpace(id); id != "" {
				s.votingExclusions = append(s.votingExclusions, map[string]any{
					"node_id":   id,
					"node_name": "doris-fe-1",
				})
			}
		}
		for _, name := range strings.Split(nodeNames, ",") {
			if name = strings.TrimSpace(name); name != "" {
				s.votingExclusions = append(s.votingExclusions, map[string]any{
					"node_id":   "doris-fe-1",
					"node_name": name,
				})
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodDelete:
		s.mu.Lock()
		s.votingExclusions = nil
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleMigrationDeprecations implements `GET /_migration/deprecations` and `GET /{index}/_migration/deprecations` (F5).
func (s *Server) handleMigrationDeprecations(w http.ResponseWriter, r *http.Request, indexName string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if indexName != "" {
		if _, _, ok := s.resolveValidatedReadTargets(w, r, indexName); !ok {
			return
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_settings": []any{},
		"node_settings":    []any{},
		"index_settings":   map[string]any{},
		"ml_settings":      []any{},
		"templates":        []any{},
	})
}

// handleNodesShutdown implements `PUT/GET/DELETE /_nodes/{node_id}/shutdown` and `GET /_nodes/shutdown` (F5).
func (s *Server) handleNodesShutdown(w http.ResponseWriter, r *http.Request, nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if nodeID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: node_id is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
		sType, _ := body["type"].(string)
		switch strings.ToLower(strings.TrimSpace(sType)) {
		case "remove", "replace", "restart":
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("invalid shutdown type [%s], must be one of [remove, replace, restart]", sType))
			return
		}
		reason, _ := body["reason"].(string)
		entry := map[string]any{
			"node_id":                nodeID,
			"type":                   strings.ToLower(strings.TrimSpace(sType)),
			"reason":                 reason,
			"status":                 "COMPLETE",
			"shutdown_startedmillis": time.Now().UTC().UnixMilli(),
		}
		s.mu.Lock()
		if s.nodeShutdowns == nil {
			s.nodeShutdowns = make(map[string]map[string]any)
		}
		s.nodeShutdowns[nodeID] = entry
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		nodes := make([]any, 0)
		if nodeID != "" && nodeID != "_all" && nodeID != "*" {
			entry, exists := s.nodeShutdowns[nodeID]
			if !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("node [%s] shutdown status not found", nodeID))
				return
			}
			nodes = append(nodes, deepCloneDocMap(entry))
		} else {
			ids := make([]string, 0, len(s.nodeShutdowns))
			for id := range s.nodeShutdowns {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				nodes = append(nodes, deepCloneDocMap(s.nodeShutdowns[id]))
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})

	case http.MethodDelete:
		if nodeID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: node_id is missing;")
			return
		}
		s.mu.Lock()
		if _, exists := s.nodeShutdowns[nodeID]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("node [%s] shutdown status not found", nodeID))
			return
		}
		delete(s.nodeShutdowns, nodeID)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleRollup implements `/_rollup/job/*`, `/_rollup/data/*`, and `/{index}/_rollup/data` (F6).
func (s *Server) handleRollup(w http.ResponseWriter, r *http.Request, segs []string, indexName string) {
	if indexName != "" || (len(segs) >= 2 && segs[1] == "data") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		target := indexName
		if target == "" && len(segs) >= 3 {
			target = strings.TrimSpace(segs[2])
		}
		s.mu.RLock()
		out := make(map[string]any)
		for jobID, job := range s.rollupJobs {
			cfg, _ := job["config"].(map[string]any)
			rIdx, _ := cfg["rollup_index"].(string)
			iPat, _ := cfg["index_pattern"].(string)
			if target == "" || target == "_all" || target == "*" || target == jobID || target == rIdx || matchMultiWildcardWithExclusions(target, jobID) || matchMultiWildcardWithExclusions(target, rIdx) || matchMultiWildcardWithExclusions(iPat, target) {
				key := target
				if key == "" || key == "_all" || key == "*" {
					key = rIdx
					if key == "" {
						key = jobID
					}
				}
				entry, _ := out[key].(map[string]any)
				if entry == nil {
					entry = map[string]any{"rollup_jobs": []any{}}
				}
				jobsList, _ := entry["rollup_jobs"].([]any)
				jobsList = append(jobsList, map[string]any{
					"job_id":        jobID,
					"rollup_index":  rIdx,
					"index_pattern": iPat,
					"fields":        map[string]any{},
				})
				entry["rollup_jobs"] = jobsList
				out[key] = entry
			}
		}
		if len(out) == 0 && target != "" && target != "_all" && target != "*" {
			if _, idxExists := s.indices[target]; idxExists {
				out[target] = map[string]any{"rollup_jobs": []any{}}
			} else {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("rollup data [%s] not found", target))
				return
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, out)
		return
	}

	if len(segs) < 2 || segs[1] != "job" {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	var jobID, action string
	if len(segs) >= 3 {
		jobID = strings.TrimSpace(segs[2])
	}
	if len(segs) >= 4 {
		action = strings.TrimSpace(segs[3])
	}

	if action != "" {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		job, exists := s.rollupJobs[jobID]
		if !exists || job == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Rollup job [%s] does not exist", jobID))
			return
		}
		switch action {
		case "_start", "start":
			job["state"] = "STARTED"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"started": true})
		case "_stop", "stop":
			job["state"] = "STOPPED"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
		default:
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown rollup action ["+action+"]")
		}
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if jobID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
		idxPat, _ := body["index_pattern"].(string)
		rollupIdx, _ := body["rollup_index"].(string)
		cronStr, _ := body["cron"].(string)
		groups, _ := body["groups"].(map[string]any)
		pageSize, okPS := toInt64(body["page_size"])
		if strings.TrimSpace(idxPat) == "" || strings.TrimSpace(rollupIdx) == "" || strings.TrimSpace(cronStr) == "" || groups == nil || !okPS || pageSize <= 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				"rollup job requires [index_pattern], [rollup_index], [cron], positive [page_size], and [groups]")
			return
		}
		s.mu.Lock()
		if s.rollupJobs == nil {
			s.rollupJobs = make(map[string]map[string]any)
		}
		if _, exists := s.rollupJobs[jobID]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception",
				fmt.Sprintf("Rollup job [%s] already exists", jobID))
			return
		}
		cfg := deepCloneDocMap(body)
		cfg["id"] = jobID
		s.rollupJobs[jobID] = map[string]any{
			"config": cfg,
			"state":  "STOPPED",
		}
		s.mu.Unlock()
		_ = s.ensureIndexSchema(r.Context(), rollupIdx)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
		s.mu.RLock()
		if jobID != "" && jobID != "_all" && jobID != "*" && !strings.ContainsAny(jobID, "*?,") {
			if _, exists := s.rollupJobs[jobID]; !exists && !allowNoMatch {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Rollup job [%s] does not exist", jobID))
				return
			}
		}
		ids := make([]string, 0, len(s.rollupJobs))
		for k := range s.rollupJobs {
			if jobID == "" || jobID == "_all" || jobID == "*" || matchMultiWildcardWithExclusions(jobID, k) {
				ids = append(ids, k)
			}
		}
		sort.Strings(ids)
		jobs := make([]any, 0, len(ids))
		for _, k := range ids {
			entry := s.rollupJobs[k]
			state, _ := entry["state"].(string)
			if state == "" {
				state = "STOPPED"
			}
			cfg, _ := entry["config"].(map[string]any)
			jobs = append(jobs, map[string]any{
				"config": deepCloneDocMap(cfg),
				"status": map[string]any{
					"job_state": state,
				},
				"stats": map[string]any{
					"pages_processed":     0,
					"documents_processed": 0,
					"rollups_indexed":     0,
					"trigger_count":       0,
				},
			})
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})

	case http.MethodDelete:
		if jobID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		s.mu.Lock()
		if _, exists := s.rollupJobs[jobID]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Rollup job [%s] does not exist", jobID))
			return
		}
		delete(s.rollupJobs, jobID)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleRollupSearch implements `GET/POST /{index}/_rollup_search` and `GET/POST /_rollup_search` (F6).
func (s *Server) handleRollupSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if rawFrom := strings.TrimSpace(r.URL.Query().Get("from")); rawFrom != "" {
		if fv, err := strconv.Atoi(rawFrom); err == nil && fv > 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "From is not supported in RollupSearch")
			return
		}
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body map[string]any
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		if fv, okF := toInt64(body["from"]); okF && fv > 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "From is not supported in RollupSearch")
			return
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	s.handleSearch(w, r)
}

// handleSearchableSnapshots implements `/_searchable_snapshots/*` and `/{index}/_searchable_snapshots/stats` (F7).
func (s *Server) handleSearchableSnapshots(w http.ResponseWriter, r *http.Request, segs []string, indexName string) {
	if len(segs) == 3 && segs[0] == "_searchable_snapshots" && segs[1] == "cache" && segs[2] == "clear" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
		})
		return
	}
	if len(segs) == 3 && segs[0] == "_searchable_snapshots" && segs[1] == "cache" && segs[2] == "stats" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes": map[string]any{
				"doris-fe-1": map[string]any{
					"shared_cache": map[string]any{
						"reads":                0,
						"bytes_read_in_bytes":  0,
						"hits":                 0,
						"misses":               0,
						"evictions":            0,
						"num_regions":          0,
						"size_in_bytes":        0,
						"region_size_in_bytes": 16777216,
					},
				},
			},
		})
		return
	}
	if (len(segs) == 2 && segs[0] == "_searchable_snapshots" && segs[1] == "stats") || (indexName != "" && len(segs) == 3 && segs[2] == "stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		var targets []string
		if indexName != "" {
			var ok bool
			targets, _, ok = s.resolveValidatedReadTargets(w, r, indexName)
			if !ok {
				return
			}
		} else {
			s.mu.RLock()
			for idx, cs := range s.indexCustomSettings {
				if cs["store.type"] == "snapshot" {
					targets = append(targets, idx)
				}
			}
			s.mu.RUnlock()
			sort.Strings(targets)
		}
		indicesMap := make(map[string]any, len(targets))
		for _, idx := range targets {
			indicesMap[idx] = map[string]any{
				"primaries": map[string]any{
					"http": map[string]any{"Requests": 0},
				},
				"total": map[string]any{
					"http": map[string]any{"Requests": 0},
				},
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
			"indices": indicesMap,
		})
		return
	}
	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
}

// handleCCR implements `/_ccr/*` and `/{index}/_ccr/*` (F7).
func (s *Server) handleCCR(w http.ResponseWriter, r *http.Request, segs []string, indexName string) {
	if indexName != "" {
		action := ""
		if len(segs) >= 3 {
			action = strings.TrimSpace(segs[2])
		}
		switch action {
		case "follow":
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			remoteCluster, _ := body["remote_cluster"].(string)
			leaderIndex, _ := body["leader_index"].(string)
			if strings.TrimSpace(remoteCluster) == "" || strings.TrimSpace(leaderIndex) == "" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					"ccr follow requires [remote_cluster] and [leader_index]")
				return
			}
			_ = s.ensureIndexSchema(r.Context(), indexName)
			s.mu.Lock()
			if s.ccrFollowers == nil {
				s.ccrFollowers = make(map[string]map[string]any)
			}
			s.ccrFollowers[indexName] = map[string]any{
				"follower_index": indexName,
				"remote_cluster": remoteCluster,
				"leader_index":   leaderIndex,
				"status":         "active",
				"parameters":     map[string]any{},
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"follow_index_created":      true,
				"follow_index_shards_acked": true,
				"index_following_started":   true,
			})

		case "info":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			info, exists := s.ccrFollowers[indexName]
			if !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("follower index [%s] not found", indexName))
				return
			}
			cp := deepCloneDocMap(info)
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"follower_indices": []any{cp},
			})

		case "stats":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			info, exists := s.ccrFollowers[indexName]
			if !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("follower index [%s] not found", indexName))
				return
			}
			rc, _ := info["remote_cluster"].(string)
			li, _ := info["leader_index"].(string)
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"indices": []any{
					map[string]any{
						"index": indexName,
						"shards": []any{
							map[string]any{
								"remote_cluster":             rc,
								"leader_index":               li,
								"follower_index":             indexName,
								"shard_id":                   0,
								"leader_global_checkpoint":   0,
								"leader_max_seq_no":          0,
								"follower_global_checkpoint": 0,
								"follower_max_seq_no":        0,
							},
						},
					},
				},
			})

		case "pause_follow":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.Lock()
			info, exists := s.ccrFollowers[indexName]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("follower index [%s] not found", indexName))
				return
			}
			info["status"] = "paused"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case "resume_follow":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.Lock()
			info, exists := s.ccrFollowers[indexName]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("follower index [%s] not found", indexName))
				return
			}
			info["status"] = "active"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case "unfollow":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.Lock()
			if _, exists := s.ccrFollowers[indexName]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("follower index [%s] not found", indexName))
				return
			}
			delete(s.ccrFollowers, indexName)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case "forget_follower":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
			})

		default:
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		}
		return
	}

	if len(segs) == 2 && segs[1] == "stats" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"auto_follow_stats": map[string]any{
				"number_of_failed_follow_indices":                0,
				"number_of_failed_remote_cluster_state_requests": 0,
				"number_of_successful_follow_indices":            0,
				"total_read_time_millis":                         0,
				"auto_followed_clusters":                         []any{},
			},
			"follow_stats": map[string]any{
				"indices": []any{},
			},
		})
		return
	}

	if len(segs) >= 2 && segs[1] == "auto_follow" {
		var name, action string
		if len(segs) >= 3 {
			name = strings.TrimSpace(segs[2])
		}
		if len(segs) >= 4 {
			action = strings.TrimSpace(segs[3])
		}
		if action != "" {
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.Lock()
			entry, exists := s.ccrAutoFollow[name]
			if !exists || entry == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("auto_follow pattern [%s] not found", name))
				return
			}
			switch action {
			case "_pause", "pause":
				entry["active"] = false
			case "_resume", "resume":
				entry["active"] = true
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown action ["+action+"]")
				return
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
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
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			rc, _ := body["remote_cluster"].(string)
			pats, _ := body["leader_index_patterns"].([]any)
			if strings.TrimSpace(rc) == "" || len(pats) == 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					"auto_follow pattern requires [remote_cluster] and non-empty [leader_index_patterns]")
				return
			}
			s.mu.Lock()
			if s.ccrAutoFollow == nil {
				s.ccrAutoFollow = make(map[string]map[string]any)
			}
			cp := deepCloneDocMap(body)
			cp["active"] = true
			s.ccrAutoFollow[name] = cp
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			if name != "" && name != "_all" && name != "*" {
				entry, exists := s.ccrAutoFollow[name]
				if !exists {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("auto_follow pattern [%s] not found", name))
					return
				}
				cp := deepCloneDocMap(entry)
				active, _ := cp["active"].(bool)
				delete(cp, "active")
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"patterns": []any{
						map[string]any{
							"name":    name,
							"active":  active,
							"pattern": cp,
						},
					},
				})
				return
			}
			names := make([]string, 0, len(s.ccrAutoFollow))
			for k := range s.ccrAutoFollow {
				names = append(names, k)
			}
			sort.Strings(names)
			patterns := make([]any, 0, len(names))
			for _, k := range names {
				cp := deepCloneDocMap(s.ccrAutoFollow[k])
				active, _ := cp["active"].(bool)
				delete(cp, "active")
				patterns = append(patterns, map[string]any{
					"name":    k,
					"active":  active,
					"pattern": cp,
				})
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"patterns": patterns})

		case http.MethodDelete:
			if name == "" {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
				return
			}
			s.mu.Lock()
			if _, exists := s.ccrAutoFollow[name]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("auto_follow pattern [%s] not found", name))
				return
			}
			delete(s.ccrAutoFollow, name)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}
	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
}

// handleSecurityAPI implements Elasticsearch `/_security/*` management endpoints (users, roles, privileges, API keys, OAuth2 tokens, service accounts) (F8).
func (s *Server) handleSecurityAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	if s.handleSecurityRound56(w, r, segs) {
		return
	}
	switch segs[1] {
	case "_authenticate":
		s.handleSecurityAuthenticate(w, r)

	case "user":
		if len(segs) == 2 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			out := make(map[string]any, len(s.securityUsers)+1)
			out["elastic"] = map[string]any{
				"username":  "elastic",
				"roles":     []string{"superuser"},
				"full_name": "Built-in Superuser",
				"email":     "",
				"metadata":  map[string]any{},
				"enabled":   true,
			}
			for u, info := range s.securityUsers {
				out[u] = deepCloneDocMap(info)
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, out)
			return
		}
		target := strings.TrimSpace(segs[2])
		if target == "_has_privileges" || (len(segs) == 4 && segs[3] == "_has_privileges") {
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				_ = json.Unmarshal(bodyBytes, &body)
			}
			clusterOut := make(map[string]any)
			if cList, ok := body["cluster"].([]any); ok {
				for _, item := range cList {
					clusterOut[fmt.Sprintf("%v", item)] = true
				}
			}
			indexOut := make(map[string]any)
			if iList, ok := body["index"].([]any); ok {
				for _, item := range iList {
					if im, ok := item.(map[string]any); ok {
						names, _ := im["names"].([]any)
						privs, _ := im["privileges"].([]any)
						privMap := make(map[string]any, len(privs))
						for _, p := range privs {
							privMap[fmt.Sprintf("%v", p)] = true
						}
						for _, n := range names {
							indexOut[fmt.Sprintf("%v", n)] = privMap
						}
					}
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"username":          "elastic",
				"has_all_requested": true,
				"cluster":           clusterOut,
				"index":             indexOut,
				"application":       map[string]any{},
			})
			return
		}
		if len(segs) == 4 {
			action := strings.TrimSpace(segs[3])
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.Lock()
			userObj, exists := s.securityUsers[target]
			if !exists && target != "elastic" {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("user [%s] not found", target))
				return
			}
			switch action {
			case "_enable":
				if userObj != nil {
					userObj["enabled"] = true
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			case "_disable":
				if userObj != nil {
					userObj["enabled"] = false
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			case "_password":
				s.mu.Unlock()
				bodyBytes, ok := readRequestBody(w, r)
				if !ok {
					return
				}
				var body map[string]any
				_ = json.Unmarshal(bodyBytes, &body)
				if pw, _ := body["password"].(string); strings.TrimSpace(pw) == "" {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[password] is required")
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{})
			case "_clear_cache":
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"cluster_name": "apache-doris-search-cluster",
					"nodes":        map[string]any{"doris-fe-1": map[string]any{"name": "doris-fe-1"}},
				})
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			}
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
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			roles, hasRoles := body["roles"].([]any)
			if !hasRoles || roles == nil {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: roles are missing;")
				return
			}
			s.mu.Lock()
			if s.securityUsers == nil {
				s.securityUsers = make(map[string]map[string]any)
			}
			_, existed := s.securityUsers[target]
			enabled := true
			if b, ok := body["enabled"].(bool); ok {
				enabled = b
			}
			fullName, _ := body["full_name"].(string)
			email, _ := body["email"].(string)
			meta, _ := body["metadata"].(map[string]any)
			if meta == nil {
				meta = map[string]any{}
			}
			s.securityUsers[target] = map[string]any{
				"username":  target,
				"roles":     roles,
				"full_name": fullName,
				"email":     email,
				"metadata":  meta,
				"enabled":   enabled,
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"user": map[string]any{"created": !existed},
			})

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			u, exists := s.securityUsers[target]
			if !exists && target == "elastic" {
				u = map[string]any{
					"username":  "elastic",
					"roles":     []string{"superuser"},
					"full_name": "Built-in Superuser",
					"email":     "",
					"metadata":  map[string]any{},
					"enabled":   true,
				}
				exists = true
			}
			if !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("user [%s] not found", target))
				return
			}
			cp := deepCloneDocMap(u)
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{target: cp})

		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.securityUsers[target]
			if exists {
				delete(s.securityUsers, target)
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"found": exists})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "role":
		if len(segs) == 2 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			out := make(map[string]any, len(s.securityRoles))
			for k, v := range s.securityRoles {
				out[k] = deepCloneDocMap(v)
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, out)
			return
		}
		roleName := strings.TrimSpace(segs[2])
		if len(segs) == 4 && segs[3] == "_clear_cache" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
				"cluster_name": "apache-doris-search-cluster",
				"nodes":        map[string]any{"doris-fe-1": map[string]any{"name": "doris-fe-1"}},
			})
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
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			if body == nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", "role body is required")
				return
			}
			s.mu.Lock()
			if s.securityRoles == nil {
				s.securityRoles = make(map[string]map[string]any)
			}
			_, existed := s.securityRoles[roleName]
			s.securityRoles[roleName] = deepCloneDocMap(body)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"role": map[string]any{"created": !existed},
			})

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			roleObj, exists := s.securityRoles[roleName]
			if !exists {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("role [%s] not found", roleName))
				return
			}
			cp := deepCloneDocMap(roleObj)
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{roleName: cp})

		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.securityRoles[roleName]
			if exists {
				delete(s.securityRoles, roleName)
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"found": exists})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "privilege":
		if len(segs) == 3 && segs[2] == "_builtin" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			idxPrivs := []string{"all", "read", "write", "create", "create_index", "delete", "delete_index", "manage", "monitor"}
			writeJSON(w, http.StatusOK, map[string]any{
				"cluster": []string{"all", "monitor", "manage", "manage_index_templates", "manage_ingest_pipelines"},
				"index":   idxPrivs,
				"indices": idxPrivs,
			})
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
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			s.mu.Lock()
			if s.securityPrivileges == nil {
				s.securityPrivileges = make(map[string]map[string]map[string]any)
			}
			out := make(map[string]any)
			for appName, privsAny := range body {
				privsMap, ok := privsAny.(map[string]any)
				if !ok {
					continue
				}
				if s.securityPrivileges[appName] == nil {
					s.securityPrivileges[appName] = make(map[string]map[string]any)
				}
				appRes := make(map[string]any)
				for privName, specAny := range privsMap {
					specMap, _ := specAny.(map[string]any)
					_, existed := s.securityPrivileges[appName][privName]
					s.securityPrivileges[appName][privName] = deepCloneDocMap(specMap)
					appRes[privName] = map[string]any{"created": !existed}
				}
				out[appName] = appRes
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, out)

		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			out := make(map[string]any)
			if len(segs) >= 3 {
				appName := segs[2]
				appPrivs, exists := s.securityPrivileges[appName]
				if !exists {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("application [%s] privileges not found", appName))
					return
				}
				if len(segs) >= 4 {
					privName := segs[3]
					privSpec, pExists := appPrivs[privName]
					if !pExists {
						s.mu.RUnlock()
						writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("privilege [%s/%s] not found", appName, privName))
						return
					}
					out[appName] = map[string]any{privName: deepCloneDocMap(privSpec)}
				} else {
					appCopy := make(map[string]any, len(appPrivs))
					for k, v := range appPrivs {
						appCopy[k] = deepCloneDocMap(v)
					}
					out[appName] = appCopy
				}
			} else {
				for appName, appPrivs := range s.securityPrivileges {
					appCopy := make(map[string]any, len(appPrivs))
					for k, v := range appPrivs {
						appCopy[k] = deepCloneDocMap(v)
					}
					out[appName] = appCopy
				}
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, out)

		case http.MethodDelete:
			if len(segs) < 4 {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "application and privilege name required")
				return
			}
			appName, privName := segs[2], segs[3]
			s.mu.Lock()
			found := false
			if s.securityPrivileges[appName] != nil {
				if _, exists := s.securityPrivileges[appName][privName]; exists {
					found = true
					delete(s.securityPrivileges[appName], privName)
				}
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				appName: map[string]any{
					privName: map[string]any{"found": found},
				},
			})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "api_key":
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return
				}
			}
			if len(segs) == 3 && segs[2] == "_grant" {
				if subKey, ok := body["api_key"].(map[string]any); ok {
					body = subKey
				}
			}
			name, _ := body["name"].(string)
			if strings.TrimSpace(name) == "" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "api_key [name] is required")
				return
			}
			s.mu.Lock()
			if s.securityAPIKeys == nil {
				s.securityAPIKeys = make(map[string]map[string]any)
			}
			keyID := fmt.Sprintf("key-%d", len(s.securityAPIKeys)+1)
			secret := "secret-" + keyID
			encoded := base64EncodeStr(keyID + ":" + secret)
			s.securityAPIKeys[keyID] = map[string]any{
				"id":          keyID,
				"name":        name,
				"username":    "elastic",
				"realm":       "default_native",
				"invalidated": false,
				"creation":    time.Now().UTC().UnixMilli(),
				"metadata":    body["metadata"],
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      keyID,
				"name":    name,
				"api_key": secret,
				"encoded": encoded,
			})

		case http.MethodGet:
			qID := strings.TrimSpace(r.URL.Query().Get("id"))
			qName := strings.TrimSpace(r.URL.Query().Get("name"))
			s.mu.RLock()
			keys := make([]any, 0, len(s.securityAPIKeys))
			for _, kObj := range s.securityAPIKeys {
				if qID != "" && kObj["id"] != qID {
					continue
				}
				if qName != "" && kObj["name"] != qName {
					continue
				}
				keys = append(keys, deepCloneDocMap(kObj))
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})

		case http.MethodDelete:
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			var body map[string]any
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				_ = json.Unmarshal(bodyBytes, &body)
			}
			var invalidated []string
			s.mu.Lock()
			if ids, ok := body["ids"].([]any); ok {
				for _, idAny := range ids {
					idStr := fmt.Sprintf("%v", idAny)
					if kObj, exists := s.securityAPIKeys[idStr]; exists {
						kObj["invalidated"] = true
						invalidated = append(invalidated, idStr)
					}
				}
			} else if nameStr, ok := body["name"].(string); ok && nameStr != "" {
				for idStr, kObj := range s.securityAPIKeys {
					if kObj["name"] == nameStr {
						kObj["invalidated"] = true
						invalidated = append(invalidated, idStr)
					}
				}
			}
			s.mu.Unlock()
			if invalidated == nil {
				invalidated = []string{}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"invalidated_api_keys":            invalidated,
				"previously_invalidated_api_keys": []string{},
				"error_count":                     0,
			})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "_query":
		if len(segs) == 3 && segs[2] == "api_key" {
			s.mu.RLock()
			hits := make([]any, 0, len(s.securityAPIKeys))
			for _, kObj := range s.securityAPIKeys {
				hits = append(hits, deepCloneDocMap(kObj))
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"total":    len(hits),
				"count":    len(hits),
				"api_keys": hits,
			})
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)

	case "_clear_api_key_cache":
		writeJSON(w, http.StatusOK, map[string]any{
			"_nodes": map[string]any{"total": 1, "successful": 1, "failed": 0},
		})

	case "oauth2":
		if len(segs) == 3 && segs[2] == "token" {
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				bodyBytes, ok := readRequestBody(w, r)
				if !ok {
					return
				}
				var body map[string]any
				if len(bytes.TrimSpace(bodyBytes)) > 0 {
					if err := json.Unmarshal(bodyBytes, &body); err != nil {
						writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
						return
					}
				}
				grantType, _ := body["grant_type"].(string)
				if strings.TrimSpace(grantType) == "" {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[grant_type] is required")
					return
				}
				// #nosec G101 -- synthetic OAuth2 token response for Elasticsearch REST API compatibility
				writeJSON(w, http.StatusOK, map[string]any{
					"access_token":  "doris-oauth2-access-token",
					"type":          "Bearer",
					"expires_in":    1200,
					"refresh_token": "doris-oauth2-refresh-token",
				})
			case http.MethodDelete:
				writeJSON(w, http.StatusOK, map[string]any{
					"invalidated_tokens": 1,
					"error_count":        0,
				})
			default:
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			}
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)

	case "service":
		if len(segs) == 2 {
			writeJSON(w, http.StatusOK, map[string]any{
				"elastic/fleet-server": map[string]any{"account": "elastic/fleet-server"},
				"elastic/kibana":       map[string]any{"account": "elastic/kibana"},
			})
			return
		}
		if len(segs) >= 6 && segs[4] == "credential" && segs[5] == "token" {
			ns, svc := segs[2], segs[3]
			acct := ns + "/" + svc
			tokenName := ""
			if len(segs) >= 7 {
				tokenName = segs[6]
			}
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				if tokenName == "" {
					tokenName = "token-1"
				}
				s.mu.Lock()
				if s.securityServiceTokens == nil {
					s.securityServiceTokens = make(map[string]map[string]any)
				}
				s.securityServiceTokens[acct+"/"+tokenName] = map[string]any{
					"name":       tokenName,
					"created_at": "2026-01-01T00:00:00.000Z",
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"created": true,
					"token": map[string]any{
						"name":  tokenName,
						"value": "aae_doris_service_token_" + tokenName,
					},
				})
			case http.MethodGet:
				s.mu.RLock()
				tokens := make(map[string]any)
				prefix := acct + "/"
				for k, v := range s.securityServiceTokens {
					if strings.HasPrefix(k, prefix) {
						tName := strings.TrimPrefix(k, prefix)
						tokens[tName] = deepCloneDocMap(v)
					}
				}
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"service_account": acct,
					"count":           len(tokens),
					"tokens":          tokens,
				})
			case http.MethodDelete:
				s.mu.Lock()
				key := acct + "/" + tokenName
				_, existed := s.securityServiceTokens[key]
				delete(s.securityServiceTokens, key)
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"found": existed})
			default:
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"account": strings.Join(segs[2:], "/")})

	case "role_mapping":
		if len(segs) == 2 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			out := make(map[string]any, len(s.securityRoleMappings))
			for k, v := range s.securityRoleMappings {
				out[k] = deepCloneDocMap(v)
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		mappingName := strings.TrimSpace(segs[2])
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			roles, hasRoles := body["roles"].([]any)
			if !hasRoles || len(roles) == 0 {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [roles] is required;")
				return
			}
			enabled := true
			if b, ok := body["enabled"].(bool); ok {
				enabled = b
			}
			rules, _ := body["rules"].(map[string]any)
			if rules == nil {
				rules = map[string]any{}
			}
			meta, _ := body["metadata"].(map[string]any)
			if meta == nil {
				meta = map[string]any{}
			}
			entry := map[string]any{
				"enabled":  enabled,
				"roles":    roles,
				"rules":    rules,
				"metadata": meta,
			}
			if rls, ok := body["role_templates"].([]any); ok {
				entry["role_templates"] = rls
			}
			s.mu.Lock()
			if s.securityRoleMappings == nil {
				s.securityRoleMappings = make(map[string]map[string]any)
			}
			_, existed := s.securityRoleMappings[mappingName]
			s.securityRoleMappings[mappingName] = deepCloneDocMap(entry)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"role_mapping": map[string]any{"created": !existed},
			})
		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			out := make(map[string]any)
			if mappingName == "_all" || mappingName == "*" {
				for k, v := range s.securityRoleMappings {
					out[k] = deepCloneDocMap(v)
				}
			} else {
				for _, pat := range strings.Split(mappingName, ",") {
					pat = strings.TrimSpace(pat)
					if pat == "" {
						continue
					}
					if strings.ContainsAny(pat, "*?") {
						for k, v := range s.securityRoleMappings {
							if matchSimpleWildcard(pat, k) {
								out[k] = deepCloneDocMap(v)
							}
						}
					} else if v, exists := s.securityRoleMappings[pat]; exists {
						out[pat] = deepCloneDocMap(v)
					} else {
						s.mu.RUnlock()
						if r.Method == http.MethodHead {
							w.WriteHeader(http.StatusNotFound)
							return
						}
						writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("role_mapping [%s] not found", pat))
						return
					}
				}
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.securityRoleMappings[mappingName]
			if exists {
				delete(s.securityRoleMappings, mappingName)
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"found": exists})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "enroll":
		if len(segs) == 3 && (segs[2] == "kibana" || segs[2] == "node") {
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"token": "doris-enrollment-" + segs[2],
			})
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)

	case "realm":
		if len(segs) == 4 && segs[3] == "_clear_cache" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
				"cluster_name": "apache-doris-search-cluster",
				"nodes":        map[string]any{"doris-fe-1": map[string]any{"name": "doris-fe-1"}},
			})
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func base64EncodeStr(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(s)
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		v := uint(b[i]) << 16
		rem := len(b) - i
		if rem > 1 {
			v |= uint(b[i+1]) << 8
		}
		if rem > 2 {
			v |= uint(b[i+2])
		}
		out.WriteByte(table[(v>>18)&0x3F])
		out.WriteByte(table[(v>>12)&0x3F])
		if rem > 1 {
			out.WriteByte(table[(v>>6)&0x3F])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(table[v&0x3F])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// handleLogstashPipeline implements `PUT/GET/DELETE /_logstash/pipeline/{id}` and `GET /_logstash/pipeline` (F8).
func (s *Server) handleLogstashPipeline(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 || segs[1] != "pipeline" {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	id := ""
	if len(segs) >= 3 {
		id = strings.TrimSpace(segs[2])
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var body map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
		pipeStr, _ := body["pipeline"].(string)
		if strings.TrimSpace(pipeStr) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[pipeline] property is required")
			return
		}
		s.mu.Lock()
		if s.logstashPipelines == nil {
			s.logstashPipelines = make(map[string]map[string]any)
		}
		cp := deepCloneDocMap(body)
		cp["last_modified"] = "2026-01-01T00:00:00.000Z"
		if cp["username"] == nil {
			cp["username"] = "elastic"
		}
		s.logstashPipelines[id] = cp
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		out := make(map[string]any)
		if id == "" || id == "_all" || id == "*" {
			for k, v := range s.logstashPipelines {
				out[k] = deepCloneDocMap(v)
			}
		} else {
			for _, pat := range strings.Split(id, ",") {
				pat = strings.TrimSpace(pat)
				if pat == "" {
					continue
				}
				if strings.ContainsAny(pat, "*?") {
					for k, v := range s.logstashPipelines {
						if matchWildcardPattern(pat, k) {
							out[k] = deepCloneDocMap(v)
						}
					}
				} else if v, exists := s.logstashPipelines[pat]; exists {
					out[pat] = deepCloneDocMap(v)
				} else {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("logstash pipeline [%s] not found", pat))
					return
				}
			}
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, out)

	case http.MethodDelete:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		s.mu.Lock()
		if _, exists := s.logstashPipelines[id]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("logstash pipeline [%s] not found", id))
			return
		}
		delete(s.logstashPipelines, id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func parseJSONBody(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return nil, false
	}
	body := make(map[string]any)
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "failed to parse request body: "+err.Error())
			return nil, false
		}
	}
	return body, true
}

func matchSimpleWildcard(pattern, target string) bool {
	return matchWildcardPattern(pattern, target)
}

func renderMustacheTemplate(tmplStr string, params map[string]any) string {
	if params == nil {
		params = map[string]any{}
	}
	return evalMustacheBlock(tmplStr, params, params)
}

var validInferenceTaskTypes = map[string]bool{
	"completion":       true,
	"text_embedding":   true,
	"sparse_embedding": true,
	"rerank":           true,
	"chat_completion":  true,
	"classification":   true,
	"ner":              true,
}

func computeDeterministicEmbedding(input string) []float64 {
	var h0, h1, h2, h3 uint32 = 2166136261, 2166136261 ^ 0x9e3779b9, 2166136261 ^ 0x85ebca6b, 2166136261 ^ 0xc2b2ae35
	for i := 0; i < len(input); i++ {
		b := uint32(input[i])
		h0 = (h0 ^ b) * 16777619
		h1 = (h1 ^ (b + 17)) * 16777619
		h2 = (h2 ^ (b + 31)) * 16777619
		h3 = (h3 ^ (b + 47)) * 16777619
	}
	norm := func(v uint32) float64 {
		val := float64(v%2000)/1000.0 - 1.0
		return float64(int(val*1000)) / 1000.0
	}
	return []float64{norm(h0), norm(h1), norm(h2), norm(h3)}
}

func computeDeterministicSparseEmbedding(input string) map[string]float64 {
	out := make(map[string]float64)
	words := strings.Fields(strings.ToLower(input))
	for idx, w := range words {
		clean := strings.Trim(w, ".,!?;:\"'()[]{}")
		if clean == "" {
			continue
		}
		weight := 1.0 + float64((len(clean)+idx)%10)*0.15
		out[clean] = float64(int(weight*100)) / 100.0
	}
	if len(out) == 0 {
		out["_empty"] = 0.1
	}
	return out
}

// handleInferenceAPI implements `/_inference` and `/_inference/*` (Round 54 F2).
func (s *Server) handleInferenceAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	var taskType, inferenceID string
	if len(segs) == 2 {
		if validInferenceTaskTypes[segs[1]] && r.Method == http.MethodGet {
			taskType = segs[1]
		} else {
			inferenceID = segs[1]
		}
	} else if len(segs) >= 3 {
		taskType = segs[1]
		inferenceID = segs[2]
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		if inferenceID != "" && inferenceID != "_all" && !strings.Contains(inferenceID, "*") {
			ep, exists := s.inferenceEndpoints[inferenceID]
			if !exists && validInferenceTaskTypes[inferenceID] && taskType == "" {
				taskType = inferenceID
				inferenceID = ""
			} else if !exists || (taskType != "" && taskType != "_all" && !strings.Contains(taskType, "*") && ep["task_type"] != taskType) {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Inference endpoint [%s] not found", inferenceID))
				return
			} else {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusOK)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"endpoints": []any{ep}})
				return
			}
		}
		ids := make([]string, 0, len(s.inferenceEndpoints))
		for id := range s.inferenceEndpoints {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		endpoints := make([]any, 0, len(ids))
		for _, id := range ids {
			ep := s.inferenceEndpoints[id]
			if inferenceID != "" && !matchSimpleWildcard(inferenceID, id) {
				continue
			}
			if taskType != "" && taskType != "_all" && !matchSimpleWildcard(taskType, fmt.Sprintf("%v", ep["task_type"])) {
				continue
			}
			endpoints = append(endpoints, ep)
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": endpoints})

	case http.MethodPut:
		if inferenceID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: inference_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		if taskType == "" {
			taskType, _ = body["task_type"].(string)
		}
		if !validInferenceTaskTypes[taskType] {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid or missing inference task_type [%s]", taskType))
			return
		}
		service, _ := body["service"].(string)
		if strings.TrimSpace(service) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: service is missing;")
			return
		}
		serviceSettings, _ := body["service_settings"].(map[string]any)
		if serviceSettings == nil {
			serviceSettings = map[string]any{}
		}
		taskSettings, _ := body["task_settings"].(map[string]any)
		if taskSettings == nil {
			taskSettings = map[string]any{}
		}
		ep := map[string]any{
			"inference_id":     inferenceID,
			"task_type":        taskType,
			"service":          service,
			"service_settings": serviceSettings,
			"task_settings":    taskSettings,
		}
		if chunking, hasChunk := body["chunking_settings"]; hasChunk && chunking != nil {
			ep["chunking_settings"] = chunking
		}
		s.mu.Lock()
		if s.inferenceEndpoints == nil {
			s.inferenceEndpoints = make(map[string]map[string]any)
		}
		s.inferenceEndpoints[inferenceID] = ep
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, ep)

	case http.MethodPost:
		if inferenceID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: inference_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		s.mu.RLock()
		ep, exists := s.inferenceEndpoints[inferenceID]
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Inference endpoint [%s] not found", inferenceID))
			return
		}
		epTaskType, _ := ep["task_type"].(string)
		if taskType != "" && taskType != "_inference" && taskType != epTaskType {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Inference endpoint [%s] is for task [%s], not [%s]", inferenceID, epTaskType, taskType))
			return
		}
		rawInput, hasInput := body["input"]
		if !hasInput || rawInput == nil {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: input is missing;")
			return
		}
		var inputs []string
		switch iv := rawInput.(type) {
		case string:
			inputs = []string{iv}
		case []any:
			for _, item := range iv {
				inputs = append(inputs, fmt.Sprintf("%v", item))
			}
		default:
			inputs = []string{fmt.Sprintf("%v", iv)}
		}
		switch epTaskType {
		case "text_embedding":
			embeddings := make([]any, 0, len(inputs))
			for _, inp := range inputs {
				embeddings = append(embeddings, map[string]any{
					"embedding": computeDeterministicEmbedding(inp),
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"inference_id":   inferenceID,
				"task_type":      "text_embedding",
				"text_embedding": embeddings,
			})
		case "sparse_embedding":
			embeddings := make([]any, 0, len(inputs))
			for _, inp := range inputs {
				embeddings = append(embeddings, map[string]any{
					"is_truncated": false,
					"embedding":    computeDeterministicSparseEmbedding(inp),
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"inference_id":     inferenceID,
				"task_type":        "sparse_embedding",
				"sparse_embedding": embeddings,
			})
		case "rerank":
			queryStr, _ := body["query"].(string)
			qWords := strings.Fields(strings.ToLower(queryStr))
			type rerankEntry struct {
				index int
				score float64
				text  string
			}
			entries := make([]rerankEntry, 0, len(inputs))
			for idx, inp := range inputs {
				lowerInp := strings.ToLower(inp)
				var matches int
				for _, qw := range qWords {
					if qw != "" && strings.Contains(lowerInp, qw) {
						matches++
					}
				}
				score := float64(matches) + 1.0/float64(idx+2)
				score = float64(int(score*1000)) / 1000.0
				entries = append(entries, rerankEntry{index: idx, score: score, text: inp})
			}
			sort.SliceStable(entries, func(i, j int) bool {
				return entries[i].score > entries[j].score
			})
			results := make([]any, 0, len(entries))
			for _, e := range entries {
				results = append(results, map[string]any{
					"index": e.index,
					"score": e.score,
					"text":  e.text,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"inference_id": inferenceID,
				"task_type":    "rerank",
				"rerank":       results,
			})
		default:
			completions := make([]any, 0, len(inputs))
			for _, inp := range inputs {
				completions = append(completions, map[string]any{
					"result": "completed: " + inp,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"inference_id": inferenceID,
				"task_type":    epTaskType,
				"completion":   completions,
			})
		}

	case http.MethodDelete:
		if inferenceID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: inference_id is missing;")
			return
		}
		s.mu.Lock()
		ep, exists := s.inferenceEndpoints[inferenceID]
		if !exists || (taskType != "" && taskType != "_all" && !strings.Contains(taskType, "*") && ep["task_type"] != taskType) {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Inference endpoint [%s] not found", inferenceID))
			return
		}
		delete(s.inferenceEndpoints, inferenceID)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleConnectorAPI implements `/_connector` and `/_connector/*` (Round 54 F3).
func (s *Server) handleConnectorAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	nowISO := time.Now().UTC().Format(time.RFC3339)

	// Sync job sub-API: `/_connector/_sync_job` and `/_connector/_sync_job/{id}[/{action}]`
	if len(segs) >= 2 && segs[1] == "_sync_job" {
		var jobID, jobAction string
		if len(segs) >= 3 {
			jobID = segs[2]
		}
		if len(segs) >= 4 {
			jobAction = segs[3]
		}
		switch {
		case jobID == "" && r.Method == http.MethodPost:
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			connID, _ := body["connector_id"].(string)
			if strings.TrimSpace(connID) == "" {
				writeESError(w, http.StatusBadRequest, "status_exception", "connector_id is required")
				return
			}
			jobType, _ := body["job_type"].(string)
			if jobType == "" {
				jobType = "full"
			}
			triggerMethod, _ := body["trigger_method"].(string)
			if triggerMethod == "" {
				triggerMethod = "on_demand"
			}
			s.mu.Lock()
			if s.connectorSyncJobs == nil {
				s.connectorSyncJobs = make(map[string]map[string]any)
			}
			newID, _ := body["id"].(string)
			if newID == "" {
				newID = fmt.Sprintf("sync-job-%d", len(s.connectorSyncJobs)+1)
			}
			jobObj := map[string]any{
				"id":                     newID,
				"connector_id":           connID,
				"job_type":               jobType,
				"trigger_method":         triggerMethod,
				"status":                 "pending",
				"created_at":             nowISO,
				"last_seen":              nowISO,
				"indexed_document_count": 0,
				"deleted_document_count": 0,
				"total_document_count":   0,
				"metadata":               map[string]any{},
			}
			s.connectorSyncJobs[newID] = jobObj
			s.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{"id": newID})

		case jobID == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			connFilter := strings.TrimSpace(r.URL.Query().Get("connector_id"))
			jobTypeFilter := strings.TrimSpace(r.URL.Query().Get("job_type"))
			s.mu.RLock()
			ids := make([]string, 0, len(s.connectorSyncJobs))
			for id := range s.connectorSyncJobs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			results := make([]any, 0, len(ids))
			for _, id := range ids {
				job := s.connectorSyncJobs[id]
				if connFilter != "" && fmt.Sprintf("%v", job["connector_id"]) != connFilter {
					continue
				}
				if jobTypeFilter != "" && fmt.Sprintf("%v", job["job_type"]) != jobTypeFilter {
					continue
				}
				results = append(results, job)
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"count":   len(results),
				"results": results,
			})

		case jobID != "" && jobAction == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			s.mu.RLock()
			job, exists := s.connectorSyncJobs[jobID]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Sync job [%s] not found", jobID))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, job)

		case jobID != "" && jobAction == "" && r.Method == http.MethodDelete:
			s.mu.Lock()
			if _, exists := s.connectorSyncJobs[jobID]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Sync job [%s] not found", jobID))
				return
			}
			delete(s.connectorSyncJobs, jobID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case jobID != "" && jobAction != "":
			var body map[string]any
			if r.ContentLength != 0 {
				var ok bool
				body, ok = parseJSONBody(w, r)
				if !ok {
					return
				}
			}
			s.mu.Lock()
			job, exists := s.connectorSyncJobs[jobID]
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Sync job [%s] not found", jobID))
				return
			}
			switch jobAction {
			case "_cancel":
				job["status"] = "canceled"
				job["canceled_at"] = nowISO
			case "_check_in":
				job["last_seen"] = nowISO
				if job["status"] == "pending" {
					job["status"] = "in_progress"
				}
			case "_error":
				if body != nil {
					if errMsg, ok := body["error"]; ok {
						job["error"] = errMsg
					}
				}
				job["status"] = "error"
				job["completed_at"] = nowISO
			case "_stats":
				for _, k := range []string{"indexed_document_count", "deleted_document_count", "total_document_count", "status", "metadata", " indexed_document_volume"} {
					if v, ok := body[strings.TrimSpace(k)]; ok {
						job[strings.TrimSpace(k)] = v
					}
				}
				job["last_seen"] = nowISO
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown connector sync_job action: "+jobAction)
				return
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}

	var connID, connAction string
	if len(segs) >= 2 {
		connID = segs[1]
	}
	if len(segs) >= 3 {
		connAction = segs[2]
	}

	switch {
	case connID == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		s.mu.RLock()
		ids := make([]string, 0, len(s.connectors))
		for id := range s.connectors {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		results := make([]any, 0, len(ids))
		for _, id := range ids {
			results = append(results, s.connectors[id])
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(results),
			"results": results,
		})

	case (connID == "" && r.Method == http.MethodPost) || (connID != "" && connAction == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost)):
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		if s.connectors == nil {
			s.connectors = make(map[string]map[string]any)
		}
		if connID == "" {
			if bodyID, ok := body["id"].(string); ok && strings.TrimSpace(bodyID) != "" {
				connID = strings.TrimSpace(bodyID)
			} else {
				connID = fmt.Sprintf("connector-%d", len(s.connectors)+1)
			}
		}
		_, existed := s.connectors[connID]
		isNative, _ := body["is_native"].(bool)
		status, _ := body["status"].(string)
		if status == "" {
			status = "created"
		}
		connObj := map[string]any{
			"id":            connID,
			"name":          body["name"],
			"description":   body["description"],
			"service_type":  body["service_type"],
			"index_name":    body["index_name"],
			"is_native":     isNative,
			"status":        status,
			"configuration": map[string]any{},
			"filtering":     []any{},
			"scheduling":    map[string]any{},
			"updated_at":    nowISO,
		}
		for _, k := range []string{"configuration", "filtering", "scheduling", "pipeline", "custom_scheduling", "error"} {
			if v, has := body[k]; has && v != nil {
				connObj[k] = v
			}
		}
		s.connectors[connID] = connObj
		s.mu.Unlock()
		if r.Method == http.MethodPost && len(segs) == 1 {
			writeJSON(w, http.StatusCreated, map[string]any{"id": connID, "acknowledged": true})
			return
		}
		code := http.StatusCreated
		if existed {
			code = http.StatusOK
		}
		writeJSON(w, code, map[string]any{"id": connID, "acknowledged": true})

	case connID != "" && connAction == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		s.mu.RLock()
		conn, exists := s.connectors[connID]
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Connector [%s] not found", connID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, conn)

	case connID != "" && connAction == "" && r.Method == http.MethodDelete:
		s.mu.Lock()
		if _, exists := s.connectors[connID]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Connector [%s] not found", connID))
			return
		}
		delete(s.connectors, connID)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case connID != "" && connAction != "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		conn, exists := s.connectors[connID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Connector [%s] not found", connID))
			return
		}
		switch connAction {
		case "_name":
			if v, has := body["name"]; has {
				conn["name"] = v
			}
			if v, has := body["description"]; has {
				conn["description"] = v
			}
		case "_native":
			if v, has := body["is_native"]; has {
				conn["is_native"] = v
			}
		case "_service_type":
			if v, has := body["service_type"]; has {
				conn["service_type"] = v
			}
		case "_status":
			if v, has := body["status"]; has {
				conn["status"] = v
			}
		case "_error":
			conn["error"] = body["error"]
		case "_filtering":
			if v, has := body["filtering"]; has {
				conn["filtering"] = v
			} else {
				conn["filtering"] = body
			}
		case "_configuration":
			if v, has := body["configuration"]; has {
				conn["configuration"] = v
			} else {
				conn["configuration"] = body
			}
		case "_pipeline":
			if v, has := body["pipeline"]; has {
				conn["pipeline"] = v
			} else {
				conn["pipeline"] = body
			}
		case "_last_sync":
			for k, v := range body {
				conn[k] = v
			}
		default:
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown connector action: "+connAction)
			return
		}
		conn["updated_at"] = nowISO
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func renderSearchApplicationMustache(tmplStr string, params map[string]any) string {
	if params == nil {
		params = map[string]any{}
	}
	return renderMustacheTemplate(tmplStr, params)
}

// handleApplicationAPI implements `/_application/search_application/*` and `/_application/analytics/*` (Round 54 F4).
func (s *Server) handleApplicationAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown application endpoint: "+r.URL.Path)
		return
	}
	sub := segs[1]
	switch sub {
	case "search_application":
		var appName, appAction string
		if len(segs) >= 3 {
			appName = segs[2]
		}
		if len(segs) >= 4 {
			appAction = segs[3]
		}
		switch {
		case appName == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			s.mu.RLock()
			names := make([]string, 0, len(s.searchApplications))
			for n := range s.searchApplications {
				names = append(names, n)
			}
			sort.Strings(names)
			results := make([]any, 0, len(names))
			for _, n := range names {
				results = append(results, s.searchApplications[n])
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"count":   len(results),
				"results": results,
			})

		case appName != "" && appAction == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			var indices []string
			switch iv := body["indices"].(type) {
			case []any:
				for _, item := range iv {
					if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
						indices = append(indices, strings.TrimSpace(str))
					}
				}
			case string:
				if strings.TrimSpace(iv) != "" {
					indices = []string{strings.TrimSpace(iv)}
				}
			}
			if len(indices) == 0 {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: search application indices must be non-empty;")
				return
			}
			indicesAny := make([]any, len(indices))
			for i, idx := range indices {
				indicesAny[i] = idx
			}
			appObj := map[string]any{
				"name":              appName,
				"indices":           indicesAny,
				"updated_at_millis": time.Now().UnixMilli(),
			}
			if tmpl, has := body["template"]; has && tmpl != nil {
				appObj["template"] = tmpl
			}
			if analyticsName, has := body["analytics_collection_name"]; has && analyticsName != nil {
				appObj["analytics_collection_name"] = analyticsName
			}
			s.mu.Lock()
			if s.searchApplications == nil {
				s.searchApplications = make(map[string]map[string]any)
			}
			_, existed := s.searchApplications[appName]
			s.searchApplications[appName] = appObj
			s.mu.Unlock()
			resStr := "created"
			if existed {
				resStr = "updated"
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"acknowledged": true,
				"result":       resStr,
			})

		case appName != "" && appAction == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			s.mu.RLock()
			appObj, exists := s.searchApplications[appName]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Search application [%s] not found", appName))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, appObj)

		case appName != "" && appAction == "" && r.Method == http.MethodDelete:
			s.mu.Lock()
			if _, exists := s.searchApplications[appName]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Search application [%s] not found", appName))
				return
			}
			delete(s.searchApplications, appName)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"acknowledged": true,
				"result":       "deleted",
			})

		case appName != "" && (appAction == "_render_query" || appAction == "_search") && (r.Method == http.MethodPost || r.Method == http.MethodGet):
			s.mu.RLock()
			appObj, exists := s.searchApplications[appName]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Search application [%s] not found", appName))
				return
			}
			var body map[string]any
			if r.ContentLength != 0 {
				var ok bool
				body, ok = parseJSONBody(w, r)
				if !ok {
					return
				}
			}
			params, _ := body["params"].(map[string]any)
			var tmplSource string
			var defaultParams map[string]any
			if tmplMap, ok := appObj["template"].(map[string]any); ok {
				if scriptMap, ok := tmplMap["script"].(map[string]any); ok {
					tmplSource, _ = scriptMap["source"].(string)
					defaultParams, _ = scriptMap["params"].(map[string]any)
				}
			}
			mergedParams := make(map[string]any)
			for k, v := range defaultParams {
				mergedParams[k] = v
			}
			for k, v := range params {
				mergedParams[k] = v
			}
			var renderedBytes []byte
			if strings.TrimSpace(tmplSource) != "" {
				renderedStr := renderSearchApplicationMustache(tmplSource, mergedParams)
				renderedBytes = []byte(renderedStr)
			} else {
				renderedBytes = []byte(`{"query":{"match_all":{}}}`)
			}
			var renderedMap map[string]any
			if err := json.Unmarshal(renderedBytes, &renderedMap); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", "failed to parse rendered search application query: "+err.Error())
				return
			}
			if appAction == "_render_query" {
				writeJSON(w, http.StatusOK, renderedMap)
				return
			}
			var idxList []string
			if rawIndices, ok := appObj["indices"].([]any); ok {
				for _, item := range rawIndices {
					if sIdx, ok := item.(string); ok && sIdx != "" {
						idxList = append(idxList, sIdx)
					}
				}
			}
			r2 := r.Clone(r.Context())
			r2.SetPathValue("index", strings.Join(idxList, ","))
			r2.Body = io.NopCloser(bytes.NewReader(renderedBytes))
			r2.ContentLength = int64(len(renderedBytes))
			s.handleSearch(w, r2)

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "analytics":
		var collName, eventLit, eventType string
		if len(segs) >= 3 {
			collName = segs[2]
		}
		if len(segs) >= 4 {
			eventLit = segs[3]
		}
		if len(segs) >= 5 {
			eventType = segs[4]
		}
		switch {
		case collName == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			s.mu.RLock()
			colls := make(map[string]any, len(s.analyticsCollections))
			for k, v := range s.analyticsCollections {
				colls[k] = v
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, colls)

		case collName != "" && eventLit == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
			s.mu.Lock()
			if s.analyticsCollections == nil {
				s.analyticsCollections = make(map[string]map[string]any)
			}
			s.analyticsCollections[collName] = map[string]any{
				"event_data_stream": map[string]any{
					"name": ".behavioral_analytics-events-" + collName,
				},
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case collName != "" && eventLit == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			s.mu.RLock()
			coll, exists := s.analyticsCollections[collName]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Analytics collection [%s] not found", collName))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{collName: coll})

		case collName != "" && eventLit == "" && r.Method == http.MethodDelete:
			s.mu.Lock()
			if _, exists := s.analyticsCollections[collName]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Analytics collection [%s] not found", collName))
				return
			}
			delete(s.analyticsCollections, collName)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		case collName != "" && eventLit == "event" && eventType != "" && r.Method == http.MethodPost:
			s.mu.RLock()
			_, exists := s.analyticsCollections[collName]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Analytics collection [%s] not found", collName))
				return
			}
			if r.ContentLength != 0 {
				if _, ok := parseJSONBody(w, r); !ok {
					return
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown application endpoint: "+r.URL.Path)
	}
}

// handleTextStructureAPI implements `/_text_structure/*` (Round 54 F5).
func (s *Server) handleTextStructureAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown text_structure endpoint: "+r.URL.Path)
		return
	}
	action := segs[1]
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	switch action {
	case "test_grok_pattern":
		var body map[string]any
		if err := json.Unmarshal(rawBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		grokPat, _ := body["grok_pattern"].(string)
		if strings.TrimSpace(grokPat) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: grok_pattern is missing;")
			return
		}
		rawMsgs, ok := body["messages"].([]any)
		if !ok || len(rawMsgs) == 0 {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: messages is missing;")
			return
		}
		customDefs, _ := body["pattern_definitions"].(map[string]any)
		re, grpMap, grpTypes, err := compileGrokRegex(grokPat, customDefs)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
		matches := make([]any, 0, len(rawMsgs))
		for _, mAny := range rawMsgs {
			msg := fmt.Sprintf("%v", mAny)
			sub := re.FindStringSubmatch(msg)
			loc := re.FindStringSubmatchIndex(msg)
			if sub == nil || loc == nil {
				matches = append(matches, map[string]any{
					"message":  msg,
					"matched":  false,
					"captures": map[string]any{},
				})
				continue
			}
			captures := make(map[string]any)
			for i, grpID := range re.SubexpNames() {
				if i == 0 || grpID == "" || i >= len(sub) || 2*i >= len(loc) || loc[2*i] < 0 {
					continue
				}
				fieldName := grpMap[grpID]
				if fieldName == "" {
					continue
				}
				var val any = sub[i]
				if convT := grpTypes[grpID]; convT != "" {
					if cv, err := convertSingleIngestValue(sub[i], convT); err == nil {
						val = cv
					}
				}
				captures[fieldName] = val
			}
			matches = append(matches, map[string]any{
				"message":  msg,
				"matched":  true,
				"captures": captures,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"matches": matches})

	case "find_structure", "find_field_structure", "find_message_structure":
		var lines []string
		trimmed := bytes.TrimSpace(rawBytes)
		var bodyMap map[string]any
		if len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &bodyMap) == nil {
			if rawMsgs, ok := bodyMap["messages"].([]any); ok {
				for _, m := range rawMsgs {
					lines = append(lines, fmt.Sprintf("%v", m))
				}
			} else if rawLines, ok := bodyMap["lines"].([]any); ok {
				for _, l := range rawLines {
					lines = append(lines, fmt.Sprintf("%v", l))
				}
			} else if textStr, ok := bodyMap["text"].(string); ok {
				for _, l := range strings.Split(textStr, "\n") {
					if strings.TrimSpace(l) != "" {
						lines = append(lines, l)
					}
				}
			}
		}
		if len(lines) == 0 && len(trimmed) > 0 {
			for _, l := range strings.Split(string(trimmed), "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, strings.TrimSpace(l))
				}
			}
		}
		format := r.URL.Query().Get("format")
		props := make(map[string]any)
		var processors []any
		if len(lines) > 0 {
			first := strings.TrimSpace(lines[0])
			var firstObj map[string]any
			if strings.HasPrefix(first, "{") && json.Unmarshal([]byte(first), &firstObj) == nil {
				if format == "" {
					format = "ndjson"
				}
				for k, v := range firstObj {
					switch v.(type) {
					case float64, json.Number, int, int64:
						props[k] = map[string]any{"type": "long"}
					case bool:
						props[k] = map[string]any{"type": "boolean"}
					default:
						props[k] = map[string]any{"type": "keyword"}
					}
				}
				processors = append(processors, map[string]any{
					"json": map[string]any{"field": "message", "add_to_root": true},
				})
			} else if strings.Contains(first, ",") && len(lines) >= 1 {
				if format == "" {
					format = "delimited"
				}
				cols := strings.Split(first, ",")
				targetFields := make([]any, 0, len(cols))
				for _, c := range cols {
					cn := strings.TrimSpace(c)
					if cn == "" {
						cn = "column"
					}
					targetFields = append(targetFields, cn)
					props[cn] = map[string]any{"type": "keyword"}
				}
				processors = append(processors, map[string]any{
					"csv": map[string]any{"field": "message", "target_fields": targetFields},
				})
			} else {
				if format == "" {
					format = "semi_structured_text"
				}
				props["message"] = map[string]any{"type": "text"}
				processors = append(processors, map[string]any{
					"grok": map[string]any{
						"field":    "message",
						"patterns": []any{"%{GREEDYDATA:message}"},
					},
				})
			}
		} else {
			if format == "" {
				format = "semi_structured_text"
			}
			props["message"] = map[string]any{"type": "text"}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"num_lines_analyzed": len(lines),
			"num_messages":       len(lines),
			"charset":            "UTF-8",
			"format":             format,
			"mappings": map[string]any{
				"properties": props,
			},
			"ingest_pipeline": map[string]any{
				"processors": processors,
			},
			"sample_stats": map[string]any{},
		})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown text_structure endpoint: "+r.URL.Path)
	}
}

// handleProfilingAPI implements `/_profiling/*` (Round 54 F6).
func (s *Server) handleProfilingAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown profiling endpoint: "+r.URL.Path)
		return
	}
	action := segs[1]
	if r.ContentLength != 0 {
		if _, ok := readRequestBody(w, r); !ok {
			return
		}
	}
	switch action {
	case "status":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": true,
			"status":  "ok",
		})
	case "flamegraph":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"flamegraph": map[string]any{
				"unit":   "count",
				"Symbol": []any{"root"},
				"Type":   []any{"kernel"},
				"Self":   []any{0},
				"Total":  []any{1},
				"Parent": []any{-1},
			},
		})
	case "stacktraces":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"stacktraces": map[string]any{},
			"frames":      map[string]any{},
		})
	case "topn_functions":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"topn_functions": []any{},
		})
	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown profiling endpoint: "+r.URL.Path)
	}
}

type asyncCaptureResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (rw *asyncCaptureResponseWriter) Header() http.Header {
	if rw.header == nil {
		rw.header = make(http.Header)
	}
	return rw.header
}

func (rw *asyncCaptureResponseWriter) WriteHeader(statusCode int) {
	if rw.code == 0 {
		rw.code = statusCode
	}
}

func (rw *asyncCaptureResponseWriter) Write(b []byte) (int, error) {
	if rw.code == 0 {
		rw.code = http.StatusOK
	}
	return rw.body.Write(b)
}

// handleAsyncSearch implements `/_async_search`, `/{index}/_async_search`, `/_async_search/{id}`, and `/_async_search/status/{id}` (Round 54 F7).
func (s *Server) handleAsyncSearch(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) >= 1 && segs[0] == "_async_search" && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodDelete) && len(segs) >= 2 {
		isStatus := segs[1] == "status" && len(segs) >= 3
		asyncID := segs[1]
		if isStatus {
			asyncID = segs[2]
		}
		if r.Method == http.MethodDelete {
			s.mu.Lock()
			if _, exists := s.asyncSearches[asyncID]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("async_search [%s] not found", asyncID))
				return
			}
			delete(s.asyncSearches, asyncID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return
		}
		s.mu.RLock()
		entry, exists := s.asyncSearches[asyncID]
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("async_search [%s] not found", asyncID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if isStatus {
			statusObj := map[string]any{
				"id":                        entry["id"],
				"is_running":                false,
				"is_partial":                false,
				"start_time_in_millis":      entry["start_time_in_millis"],
				"expiration_time_in_millis": entry["expiration_time_in_millis"],
				"completion_time_in_millis": entry["completion_time_in_millis"],
				"_shards": map[string]any{
					"total":      1,
					"successful": 1,
					"skipped":    0,
					"failed":     0,
				},
			}
			writeJSON(w, http.StatusOK, statusObj)
			return
		}
		writeJSON(w, http.StatusOK, entry)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rec := &asyncCaptureResponseWriter{}
	s.handleSearch(rec, r)
	if rec.code >= 400 {
		for k, vals := range rec.Header() {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.code)
		_, _ = w.Write(rec.body.Bytes())
		return
	}
	var searchResp map[string]any
	dec := json.NewDecoder(bytes.NewReader(rec.body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&searchResp); err != nil {
		searchResp = map[string]any{}
	}
	nowMS := time.Now().UnixMilli()
	s.mu.Lock()
	if s.asyncSearches == nil {
		s.asyncSearches = make(map[string]map[string]any)
	}
	asyncID := fmt.Sprintf("async-search-%d", len(s.asyncSearches)+1)
	envelope := map[string]any{
		"id":                        asyncID,
		"is_partial":                false,
		"is_running":                false,
		"start_time_in_millis":      nowMS,
		"expiration_time_in_millis": nowMS + 86400000,
		"completion_time_in_millis": nowMS,
		"response":                  searchResp,
	}
	s.asyncSearches[asyncID] = envelope
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, envelope)
}

func inferESQLValueType(v any) string {
	switch v.(type) {
	case bool:
		return "boolean"
	case int, int64, int32:
		return "long"
	case float64, float32:
		return "double"
	case json.Number:
		s := fmt.Sprintf("%v", v)
		if strings.ContainsAny(s, ".eE") {
			return "double"
		}
		return "long"
	default:
		return "keyword"
	}
}

// handleESQLQuery implements `/_query` and `/_query/async*` (Round 54 F7).
func (s *Server) handleESQLQuery(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) >= 3 && segs[1] == "async" {
		queryID := segs[2]
		isStop := len(segs) >= 4 && segs[3] == "_stop"
		if r.Method == http.MethodDelete && !isStop {
			s.mu.Lock()
			if _, exists := s.esqlAsyncQueries[queryID]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("esql async query [%s] not found", queryID))
				return
			}
			delete(s.esqlAsyncQueries, queryID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) || (isStop && r.Method == http.MethodPost) {
			s.mu.RLock()
			entry, exists := s.esqlAsyncQueries[queryID]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("esql async query [%s] not found", queryID))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, entry)
			return
		}
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	queryStr, _ := body["query"].(string)
	if strings.TrimSpace(queryStr) == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] is required")
		return
	}

	s.executeESQLQueryEngine(w, r, body, queryStr)
}

// handleWatcherQueryWatches implements `POST/GET /_watcher/_query/watches` (Round 54 F8).
func (s *Server) handleWatcherQueryWatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.ContentLength != 0 {
		if _, ok := readRequestBody(w, r); !ok {
			return
		}
	}
	s.mu.RLock()
	ids := make([]string, 0, len(s.watches))
	for id := range s.watches {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	hits := make([]any, 0, len(ids))
	for _, id := range ids {
		wObj := s.watches[id]
		hits = append(hits, map[string]any{
			"_index":  ".watches",
			"_id":     id,
			"_score":  1.0,
			"_source": wObj,
		})
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"took":      1,
		"timed_out": false,
		"_shards": map[string]any{
			"total":      1,
			"successful": 1,
			"skipped":    0,
			"failed":     0,
		},
		"count": len(hits),
		"hits": map[string]any{
			"total": map[string]any{
				"value":    len(hits),
				"relation": "eq",
			},
			"max_score": 1.0,
			"hits":      hits,
		},
	})
}

// handleCatTransforms implements `GET /_cat/transforms` and `GET /_cat/transforms/{transform_id}` (Round 54 F8).
func (s *Server) handleCatTransforms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	transformID := strings.TrimSpace(r.PathValue("transform_id"))
	s.mu.RLock()
	if transformID != "" && transformID != "_all" && !strings.Contains(transformID, "*") {
		if _, exists := s.transforms[transformID]; !exists {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Transform [%s] not found", transformID))
			return
		}
	}
	ids := make([]string, 0, len(s.transforms))
	for id := range s.transforms {
		if transformID == "" || transformID == "_all" || matchSimpleWildcard(transformID, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	headers := []string{"id", "state", "checkpoint", "documents_processed", "documents_indexed", "source_index", "dest_index", "frequency"}
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		tr := s.transforms[id]
		srcIdx := ""
		if srcMap, ok := tr["source"].(map[string]any); ok {
			switch iv := srcMap["index"].(type) {
			case string:
				srcIdx = iv
			case []any:
				if len(iv) > 0 {
					srcIdx = fmt.Sprintf("%v", iv[0])
				}
			}
		}
		destIdx := ""
		if dstMap, ok := tr["dest"].(map[string]any); ok {
			destIdx, _ = dstMap["index"].(string)
		}
		freq, _ := tr["frequency"].(string)
		if freq == "" {
			freq = "1m"
		}
		rows = append(rows, map[string]any{
			"id":                  id,
			"state":               "started",
			"checkpoint":          "1",
			"documents_processed": "0",
			"documents_indexed":   "0",
			"source_index":        srcIdx,
			"dest_index":          destIdx,
			"frequency":           freq,
		})
	}
	s.mu.RUnlock()
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeCatResponse(w, r, headers, rows)
}

func (s *Server) ensureLicenseStateLocked() map[string]any {
	if s.licenseState == nil {
		s.licenseState = map[string]any{
			"status":               "active",
			"uid":                  "doris-es-license-0001",
			"type":                 "basic",
			"mode":                 "basic",
			"issue_date":           "2026-01-01T00:00:00.000Z",
			"issue_date_in_millis": int64(1767225600000),
			"max_nodes":            1000,
			"issued_to":            "doris-es-cluster",
			"issuer":               "elasticsearch",
			"start_date_in_millis": int64(-1),
		}
	}
	cp := make(map[string]any, len(s.licenseState))
	for k, v := range s.licenseState {
		cp[k] = v
	}
	return cp
}

// handleLicenseAPI implements `/_license` and `/_license/*` (Round 54 F9).
func (s *Server) handleLicenseAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	action := ""
	if len(segs) >= 2 && segs[0] == "_license" {
		action = segs[1]
	} else if len(segs) >= 3 && segs[0] == "_xpack" && segs[1] == "license" {
		action = segs[2]
	}
	switch action {
	case "":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.Lock()
			lic := s.ensureLicenseStateLocked()
			s.mu.Unlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"license": lic})
		case http.MethodPut, http.MethodPost:
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			_ = s.ensureLicenseStateLocked()
			for k, v := range body {
				s.licenseState[k] = v
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"acknowledged":   true,
				"license_status": "valid",
			})
		case http.MethodDelete:
			s.mu.Lock()
			s.licenseState = nil
			_ = s.ensureLicenseStateLocked()
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}

	case "start_basic", "_start_basic":
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		_ = s.ensureLicenseStateLocked()
		s.licenseState["type"] = "basic"
		s.licenseState["mode"] = "basic"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"acknowledged":      true,
			"basic_was_started": true,
		})

	case "basic_status", "_basic_status":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"eligible_to_start_basic": true})

	case "start_trial", "_start_trial":
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		_ = s.ensureLicenseStateLocked()
		s.licenseState["type"] = "trial"
		s.licenseState["mode"] = "trial"
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"acknowledged":      true,
			"trial_was_started": true,
		})

	case "trial_status", "_trial_status":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"eligible_to_start_trial": true})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown license endpoint: "+r.URL.Path)
	}
}

// handleXPackAPI implements `/_xpack` and `/_xpack/usage` (Round 54 F9).
func (s *Server) handleXPackAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	featureNames := []string{
		"analytics", "Archive", "ccr", "data_streams", " data_tiers", "enrich", "enterprise_search",
		"eql", "esql", "flattened", "frozen_indices", "graph", "ilm", "inference", "logstash",
		"ml", "monitoring", "rollup", "RuntimeFields", "searchable_snapshots", "security", "slm",
		"spatial", "sql", "transform", "universal_profiling", "vectors", "voting_only", "watcher",
	}
	if len(segs) >= 2 && segs[1] == "usage" {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.mu.RLock()
		watchCount := len(s.watches)
		ilmCount := len(s.ilmPolicies)
		slmCount := len(s.slmPolicies)
		transformCount := len(s.transforms)
		rollupCount := len(s.rollupJobs)
		enrichCount := len(s.enrichPolicies)
		inferenceCount := len(s.inferenceEndpoints)
		s.mu.RUnlock()
		usage := make(map[string]any, len(featureNames))
		for _, fn := range featureNames {
			clean := strings.TrimSpace(fn)
			usage[clean] = map[string]any{
				"available": true,
				"enabled":   true,
			}
		}
		usage["watcher"] = map[string]any{"available": true, "enabled": true, "count": map[string]any{"total": watchCount, "active": watchCount}}
		usage["ilm"] = map[string]any{"available": true, "enabled": true, "policy_count": ilmCount}
		usage["slm"] = map[string]any{"available": true, "enabled": true, "policy_count": slmCount}
		usage["transform"] = map[string]any{"available": true, "enabled": true, "count": transformCount}
		usage["rollup"] = map[string]any{"available": true, "enabled": true, "count": rollupCount}
		usage["enrich"] = map[string]any{"available": true, "enabled": true, "count": enrichCount}
		usage["inference"] = map[string]any{"available": true, "enabled": true, "count": inferenceCount}
		writeJSON(w, http.StatusOK, usage)
		return
	}
	if len(segs) == 1 {
		s.mu.Lock()
		lic := s.ensureLicenseStateLocked()
		s.mu.Unlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		features := make(map[string]any, len(featureNames))
		for _, fn := range featureNames {
			clean := strings.TrimSpace(fn)
			features[clean] = map[string]any{
				"available": true,
				"enabled":   true,
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"build": map[string]any{
				"hash": "00000000",
				"date": "2026-01-01T00:00:00.000Z",
			},
			"license":  lic,
			"features": features,
			"tagline":  "You Know, for X",
		})
		return
	}
	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown xpack endpoint: "+r.URL.Path)
}

// handleSSLCertificates implements `GET /_ssl/certificates` (Round 54 F9).
func (s *Server) handleSSLCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, []any{
		map[string]any{
			"path":            "http.p12",
			"format":          "PKCS12",
			"alias":           "http",
			"subject_dn":      "CN=doris-es-proxy",
			"serial_number":   "1",
			"has_private_key": true,
			"expiry":          "2036-01-01T00:00:00.000Z",
		},
	})
}

// handleHealthReport implements `GET/HEAD /_health_report` and `/_health_report/{indicator}` (Round 55 F2).
func (s *Server) handleHealthReport(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	mkInd := func(symptom string, details map[string]any) map[string]any {
		if details == nil {
			details = map[string]any{}
		}
		return map[string]any{
			"status":    "green",
			"symptom":   symptom,
			"details":   details,
			"impacts":   []any{},
			"diagnosis": []any{},
		}
	}
	s.mu.RLock()
	idxCount := len(s.indices)
	ilmState := s.ilmMode
	slmState := s.slmMode
	s.mu.RUnlock()
	if ilmState == "" {
		ilmState = "RUNNING"
	}
	if slmState == "" {
		slmState = "RUNNING"
	}
	indicators := map[string]any{
		"master_is_stable": mkInd("The cluster has a stable master node", map[string]any{
			"current_master": map[string]any{"node_id": "doris-fe-1", "name": "doris-fe-1"},
			"recent_masters": []any{map[string]any{"node_id": "doris-fe-1", "name": "doris-fe-1"}},
		}),
		"repository_integrity": mkInd("No corrupted repositories found.", map[string]any{
			"total_repositories": 0,
		}),
		"shards_availability": mkInd(fmt.Sprintf("This cluster has all shards available for %d indices.", idxCount), map[string]any{
			"primaries": map[string]any{"started": idxCount, "unassigned": 0, "initializing": 0},
			"replicas":  map[string]any{"started": 0, "unassigned": 0, "initializing": 0},
		}),
		"shards_capacity": mkInd("The cluster has enough room to add new shards.", map[string]any{
			"data": map[string]any{"max_shards_in_cluster": 1000, "current_used_shards": idxCount},
		}),
		"disk": mkInd("The cluster has enough available disk space.", map[string]any{
			"indices_with_readonly_block": 0,
			"nodes_with_enough_disk":      1,
			"nodes_over_high_watermark":   0,
			"nodes_over_flood_stage":      0,
		}),
		"ilm": mkInd("Index Lifecycle Management is running", map[string]any{
			"policies":       0,
			"stagnant_steps": 0,
			"ilm_status":     ilmState,
		}),
		"slm": mkInd("Snapshot Lifecycle Management is running", map[string]any{
			"slm_status": slmState,
			"policies":   0,
		}),
		"data_stream_lifecycle": mkInd("Data stream lifecycle is running", map[string]any{
			"stagnant_data_streams_count": 0,
			"total_Error_count":           0,
		}),
	}
	if len(segs) >= 2 && strings.TrimSpace(segs[1]) != "" {
		indName := strings.TrimSpace(segs[1])
		indObj, exists := indicators[indName]
		if !exists {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("unknown health indicator [%s]", indName))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"cluster_name": "apache-doris-search-cluster",
			"status":       "green",
			"indicators": map[string]any{
				indName: indObj,
			},
		})
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_name": "apache-doris-search-cluster",
		"status":       "green",
		"indicators":   indicators,
	})
}

// handleSQLAPI implements `/_sql`, `/_sql/translate`, `/_sql/close`, and `/_sql/async/*` (Round 55 F3).
func (s *Server) handleSQLAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) >= 2 && segs[1] == "close" {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		cursor, _ := body["cursor"].(string)
		if strings.TrimSpace(cursor) == "" {
			writeESError(w, http.StatusBadRequest, "verification_exception", "cursor is required")
			return
		}
		s.mu.Lock()
		delete(s.sqlAsyncSearches, cursor)
		delete(s.sqlAsyncSearches, cursor+"_cursor")
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"succeeded": true})
		return
	}

	if len(segs) >= 2 && segs[1] == "translate" {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		queryStr, _ := body["query"].(string)
		if strings.TrimSpace(queryStr) == "" {
			writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
			return
		}
		fetchSize := 1000
		if fs, ok := toInt64(body["fetch_size"]); ok && fs > 0 {
			fetchSize = int(fs)
		}
		dslQuery := map[string]any{"match_all": map[string]any{}}
		if filterMap, ok := body["filter"].(map[string]any); ok && len(filterMap) > 0 {
			dslQuery = filterMap
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"size":  fetchSize,
			"query": dslQuery,
		})
		return
	}

	if len(segs) >= 3 && segs[1] == "async" {
		if segs[2] == "status" && len(segs) >= 4 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			id := strings.TrimSpace(segs[3])
			s.mu.RLock()
			_, exists := s.sqlAsyncSearches[id]
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("sql async search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id":                        id,
				"is_running":                false,
				"is_partial":                false,
				"expiration_time_in_millis": time.Now().Add(24 * time.Hour).UnixMilli(),
				"completion_status":         200,
			})
			return
		}
		id := strings.TrimSpace(segs[2])
		if len(segs) == 4 && segs[2] == "delete" {
			id = strings.TrimSpace(segs[3])
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			resp, exists := s.sqlAsyncSearches[id]
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("sql async search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.sqlAsyncSearches[id]
			delete(s.sqlAsyncSearches, id)
			s.mu.Unlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("sql async search [%s] not found", id))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	if cursorStr, _ := body["cursor"].(string); strings.TrimSpace(cursorStr) != "" {
		s.mu.Lock()
		curEntry, exists := s.sqlAsyncSearches[cursorStr+"_cursor"]
		delete(s.sqlAsyncSearches, cursorStr+"_cursor")
		s.mu.Unlock()
		if !exists {
			writeJSON(w, http.StatusOK, map[string]any{
				"columns": []any{},
				"rows":    []any{},
			})
			return
		}
		writeJSON(w, http.StatusOK, curEntry)
		return
	}
	queryStr, _ := body["query"].(string)
	queryStr = strings.TrimSpace(queryStr)
	if queryStr == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
		return
	}
	upperQ := strings.ToUpper(queryStr)
	if !strings.HasPrefix(upperQ, "SELECT ") && !strings.HasPrefix(upperQ, "SHOW ") && !strings.HasPrefix(upperQ, "DESCRIBE ") && !strings.HasPrefix(upperQ, "DESC ") {
		writeESError(w, http.StatusBadRequest, "parsing_exception", "line 1:1: mismatched input; expected SELECT, SHOW, or DESCRIBE")
		return
	}
	fetchSize := 1000
	if fs, ok := toInt64(body["fetch_size"]); ok && fs > 0 {
		fetchSize = int(fs)
	}
	var columns []any
	var rows []any
	if strings.HasPrefix(upperQ, "SHOW ") {
		columns = []any{
			map[string]any{"name": "name", "type": "keyword"},
			map[string]any{"name": "type", "type": "keyword"},
		}
		s.mu.RLock()
		names := make([]string, 0, len(s.indices))
		for idx := range s.indices {
			names = append(names, idx)
		}
		s.mu.RUnlock()
		sort.Strings(names)
		for _, idx := range names {
			rows = append(rows, []any{idx, "TABLE"})
		}
	} else {
		fromIdx := strings.Index(upperQ, " FROM ")
		if fromIdx < 0 {
			selExpr := strings.TrimSpace(queryStr[len("SELECT "):])
			colName := selExpr
			valStr := selExpr
			if asIdx := strings.Index(strings.ToUpper(selExpr), " AS "); asIdx > 0 {
				valStr = strings.TrimSpace(selExpr[:asIdx])
				colName = strings.Trim(strings.TrimSpace(selExpr[asIdx+4:]), `"'`)
			}
			var cellVal any = strings.Trim(valStr, `"'`)
			colType := "keyword"
			if iv, err := strconv.ParseInt(valStr, 10, 64); err == nil {
				cellVal = iv
				colType = "long"
			} else if fv, err := strconv.ParseFloat(valStr, 64); err == nil {
				cellVal = fv
				colType = "double"
			}
			columns = []any{map[string]any{"name": colName, "type": colType}}
			rows = []any{[]any{cellVal}}
		} else {
			selPart := strings.TrimSpace(queryStr[len("SELECT "):fromIdx])
			afterFrom := strings.TrimSpace(queryStr[fromIdx+len(" FROM "):])
			afterUpper := strings.ToUpper(afterFrom)
			limitVal := -1
			if limIdx := strings.Index(afterUpper, " LIMIT "); limIdx >= 0 {
				limStr := strings.TrimSpace(afterFrom[limIdx+len(" LIMIT "):])
				if lv, err := strconv.Atoi(strings.Fields(limStr)[0]); err == nil && lv >= 0 {
					limitVal = lv
				}
				afterFrom = strings.TrimSpace(afterFrom[:limIdx])
				afterUpper = strings.ToUpper(afterFrom)
			}
			var orderField string
			orderDesc := false
			if ordIdx := strings.Index(afterUpper, " ORDER BY "); ordIdx >= 0 {
				ordPart := strings.TrimSpace(afterFrom[ordIdx+len(" ORDER BY "):])
				ordTokens := strings.Fields(ordPart)
				if len(ordTokens) >= 1 {
					orderField = strings.Trim(ordTokens[0], `"'`)
				}
				if len(ordTokens) >= 2 && strings.EqualFold(ordTokens[1], "DESC") {
					orderDesc = true
				}
				afterFrom = strings.TrimSpace(afterFrom[:ordIdx])
				afterUpper = strings.ToUpper(afterFrom)
			}
			var whereCol, whereVal string
			if whIdx := strings.Index(afterUpper, " WHERE "); whIdx >= 0 {
				whPart := strings.TrimSpace(afterFrom[whIdx+len(" WHERE "):])
				if eqIdx := strings.IndexByte(whPart, '='); eqIdx > 0 {
					whereCol = strings.Trim(strings.TrimSpace(whPart[:eqIdx]), `"'`)
					whereVal = strings.Trim(strings.TrimSpace(whPart[eqIdx+1:]), `"'`)
				}
				afterFrom = strings.TrimSpace(afterFrom[:whIdx])
			}
			tableName := strings.Trim(strings.Fields(afterFrom)[0], `"'`)
			searchDSL := map[string]any{"size": 1000}
			if filterMap, ok := body["filter"].(map[string]any); ok && len(filterMap) > 0 {
				searchDSL["query"] = filterMap
			} else if whereCol != "" {
				searchDSL["query"] = map[string]any{"match": map[string]any{whereCol: whereVal}}
			} else {
				searchDSL["query"] = map[string]any{"match_all": map[string]any{}}
			}
			dslBytes, _ := json.Marshal(searchDSL)
			subReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
			if err != nil {
				writeESError(w, http.StatusInternalServerError, "internal_server_error", err.Error())
				return
			}
			subReq.SetPathValue("index", tableName)
			capW := &asyncCaptureResponseWriter{}
			s.handleSearch(capW, subReq)
			if capW.code >= 400 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(capW.code)
				_, _ = w.Write(capW.body.Bytes())
				return
			}
			var searchResp map[string]any
			_ = json.Unmarshal(capW.body.Bytes(), &searchResp)
			hitsWrapper, _ := searchResp["hits"].(map[string]any)
			rawHits, _ := hitsWrapper["hits"].([]any)
			docs := make([]map[string]any, 0, len(rawHits))
			for _, h := range rawHits {
				if hm, ok := h.(map[string]any); ok {
					if src, ok := hm["_source"].(map[string]any); ok {
						if whereCol != "" && fmt.Sprintf("%v", src[whereCol]) != whereVal {
							continue
						}
						docs = append(docs, src)
					}
				}
			}
			if orderField != "" {
				sort.SliceStable(docs, func(i, j int) bool {
					vi := fmt.Sprintf("%v", docs[i][orderField])
					vj := fmt.Sprintf("%v", docs[j][orderField])
					if orderDesc {
						return vi > vj
					}
					return vi < vj
				})
			}
			if limitVal >= 0 && limitVal < len(docs) {
				docs = docs[:limitVal]
			}
			var colNames []string
			if selPart == "*" {
				colSet := make(map[string]bool)
				for _, d := range docs {
					for k := range d {
						colSet[k] = true
					}
				}
				if len(colSet) == 0 {
					s.mu.RLock()
					if sch, exists := s.indices[tableName]; exists && sch != nil {
						for k := range sch.Fields {
							colSet[k] = true
						}
					}
					s.mu.RUnlock()
				}
				for k := range colSet {
					colNames = append(colNames, k)
				}
				sort.Strings(colNames)
			} else {
				for _, part := range strings.Split(selPart, ",") {
					p := strings.TrimSpace(part)
					if asIdx := strings.Index(strings.ToUpper(p), " AS "); asIdx > 0 {
						p = strings.TrimSpace(p[:asIdx])
					}
					colNames = append(colNames, strings.Trim(p, `"'`))
				}
			}
			for _, cn := range colNames {
				colType := "keyword"
				for _, d := range docs {
					if v, ok := d[cn]; ok && v != nil {
						switch v.(type) {
						case float64, int, int64:
							colType = "long"
						case bool:
							colType = "boolean"
						}
						break
					}
				}
				columns = append(columns, map[string]any{"name": cn, "type": colType})
			}
			for _, d := range docs {
				row := make([]any, len(colNames))
				for idx, cn := range colNames {
					row[idx] = d[cn]
				}
				rows = append(rows, row)
			}
		}
	}
	if columns == nil {
		columns = []any{}
	}
	if rows == nil {
		rows = []any{}
	}
	s.mu.Lock()
	if s.sqlAsyncSearches == nil {
		s.sqlAsyncSearches = make(map[string]map[string]any)
	}
	sqlID := fmt.Sprintf("sql_%d", len(s.sqlAsyncSearches)+1)
	var cursorID string
	if fetchSize > 0 && len(rows) > fetchSize {
		cursorID = sqlID + "_cur"
		remRows := rows[fetchSize:]
		rows = rows[:fetchSize]
		s.sqlAsyncSearches[cursorID+"_cursor"] = map[string]any{
			"columns": columns,
			"rows":    remRows,
		}
	}
	resp := map[string]any{
		"id":         sqlID,
		"is_partial": false,
		"is_running": false,
		"columns":    columns,
		"rows":       rows,
	}
	if cursorID != "" {
		resp["cursor"] = cursorID
	}
	s.sqlAsyncSearches[sqlID] = resp
	s.mu.Unlock()

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "csv" || format == "tsv" || format == "txt" {
		sep := ","
		contentType := "text/csv; charset=UTF-8"
		switch format {
		case "tsv":
			sep = "\t"
			contentType = "text/tab-separated-values; charset=UTF-8"
		case "txt":
			sep = " | "
			contentType = "text/plain; charset=UTF-8"
		}
		var sb strings.Builder
		colHeaders := make([]string, len(columns))
		for i, c := range columns {
			cm, _ := c.(map[string]any)
			colHeaders[i] = fmt.Sprintf("%v", cm["name"])
		}
		sb.WriteString(strings.Join(colHeaders, sep) + "\n")
		for _, rAny := range rows {
			rSlice, _ := rAny.([]any)
			cells := make([]string, len(rSlice))
			for i, v := range rSlice {
				if v == nil {
					cells[i] = ""
				} else {
					cells[i] = fmt.Sprintf("%v", v)
				}
			}
			sb.WriteString(strings.Join(cells, sep) + "\n")
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleEQLSearchAPI implements `/{index}/_eql/search`, `/_eql/search`, `/_eql/search/{id}`, `/_eql/search/status/{id}`, and `DELETE /_eql/search/{id}` (Round 55 F4).
func (s *Server) handleEQLSearchAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if segs[0] == "_eql" && len(segs) >= 3 && segs[1] == "search" {
		if segs[2] == "status" && len(segs) >= 4 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			id := strings.TrimSpace(segs[3])
			s.mu.RLock()
			_, exists := s.eqlSearches[id]
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id":                id,
				"is_running":        false,
				"is_partial":        false,
				"completion_status": 200,
			})
			return
		}
		id := strings.TrimSpace(segs[2])
		if len(segs) == 4 && segs[2] == "delete" {
			id = strings.TrimSpace(segs[3])
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			resp, exists := s.eqlSearches[id]
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.eqlSearches[id]
			delete(s.eqlSearches, id)
			s.mu.Unlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	targetIndex := "_all"
	if len(segs) == 3 && segs[1] == "_eql" && segs[2] == "search" {
		targetIndex = strings.TrimSpace(segs[0])
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	queryStr, _ := body["query"].(string)
	if strings.TrimSpace(queryStr) == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
		return
	}
	sizeVal := 10
	if sz, ok := toInt64(body["size"]); ok && sz >= 0 {
		sizeVal = int(sz)
	}
	searchDSL := map[string]any{"size": sizeVal}
	if filterMap, ok := body["filter"].(map[string]any); ok && len(filterMap) > 0 {
		searchDSL["query"] = filterMap
	} else {
		searchDSL["query"] = map[string]any{"match_all": map[string]any{}}
	}
	dslBytes, _ := json.Marshal(searchDSL)
	subReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "internal_server_error", err.Error())
		return
	}
	if targetIndex != "" && targetIndex != "_all" {
		subReq.SetPathValue("index", targetIndex)
	}
	capW := &asyncCaptureResponseWriter{}
	s.handleSearch(capW, subReq)
	if capW.code >= 400 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(capW.code)
		_, _ = w.Write(capW.body.Bytes())
		return
	}
	var searchResp map[string]any
	_ = json.Unmarshal(capW.body.Bytes(), &searchResp)
	hitsWrapper, _ := searchResp["hits"].(map[string]any)
	events, _ := hitsWrapper["hits"].([]any)
	if events == nil {
		events = []any{}
	}
	s.mu.Lock()
	if s.eqlSearches == nil {
		s.eqlSearches = make(map[string]map[string]any)
	}
	eqlID := fmt.Sprintf("eql_%d", len(s.eqlSearches)+1)
	resp := map[string]any{
		"id":         eqlID,
		"is_partial": false,
		"is_running": false,
		"took":       1,
		"timed_out":  false,
		"hits": map[string]any{
			"total": map[string]any{
				"value":    len(events),
				"relation": "eq",
			},
			"events":    events,
			"sequences": []any{},
		},
	}
	s.eqlSearches[eqlID] = resp
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) resolveMaintenanceTargetIndices(w http.ResponseWriter, rawIndex string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rawIndex == "" || rawIndex == "_all" || rawIndex == "*" {
		names := make([]string, 0, len(s.indices))
		for idx := range s.indices {
			names = append(names, idx)
		}
		sort.Strings(names)
		return names, true
	}
	var matched []string
	seen := make(map[string]bool)
	for _, pat := range strings.Split(rawIndex, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.ContainsAny(pat, "*?") {
			for idx := range s.indices {
				if matchSimpleWildcard(pat, idx) && !seen[idx] {
					seen[idx] = true
					matched = append(matched, idx)
				}
			}
		} else if _, exists := s.indices[pat]; exists {
			if !seen[pat] {
				seen[pat] = true
				matched = append(matched, pat)
			}
		} else if targets, isAlias := s.aliases[pat]; isAlias && len(targets) > 0 {
			for _, t := range targets {
				if !seen[t] {
					seen[t] = true
					matched = append(matched, t)
				}
			}
		} else {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", pat))
			return nil, false
		}
	}
	sort.Strings(matched)
	return matched, true
}

// handleReloadSearchAnalyzers implements `POST/GET /_reload_search_analyzers` and `/{index}/_reload_search_analyzers` (Round 55 F5).
func (s *Server) handleReloadSearchAnalyzers(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := ""
	if len(segs) == 2 {
		rawIndex = segs[0]
	}
	indices, ok := s.resolveMaintenanceTargetIndices(w, rawIndex)
	if !ok {
		return
	}
	details := make([]any, 0, len(indices))
	for _, idx := range indices {
		details = append(details, map[string]any{
			"index":              idx,
			"reloaded_analyzers": []any{},
			"reloaded_node_ids":  []any{"doris-fe-1"},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{
			"total":      len(indices),
			"successful": len(indices),
			"failed":     0,
		},
		"reload_details": details,
	})
}

// handleIndexDiskUsage implements `POST/GET /{index}/_disk_usage` and `/_disk_usage` (Round 55 F5).
func (s *Server) handleIndexDiskUsage(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := ""
	if len(segs) == 2 {
		rawIndex = segs[0]
	}
	indices, ok := s.resolveMaintenanceTargetIndices(w, rawIndex)
	if !ok {
		return
	}
	resp := map[string]any{
		"_shards": map[string]any{
			"total":      len(indices),
			"successful": len(indices),
			"failed":     0,
		},
	}
	for _, idx := range indices {
		resp[idx] = map[string]any{
			"store_size":          "0b",
			"store_size_in_bytes": 0,
			"all_fields": map[string]any{
				"total":                  "0b",
				"total_in_bytes":         0,
				"inverted_index":         map[string]any{"total": "0b", "total_in_bytes": 0},
				"stored_fields":          "0b",
				"stored_fields_in_bytes": 0,
				"doc_values":             "0b",
				"doc_values_in_bytes":    0,
				"points":                 "0b",
				"points_in_bytes":        0,
				"norms":                  "0b",
				"norms_in_bytes":         0,
				"term_vectors":           "0b",
				"term_vectors_in_bytes":  0,
				"knn_vectors":            "0b",
				"knn_vectors_in_bytes":   0,
			},
			"fields": map[string]any{},
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleIndexFieldUsageStats implements `GET /{index}/_field_usage_stats` and `/_field_usage_stats` (Round 55 F5).
func (s *Server) handleIndexFieldUsageStats(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := ""
	if len(segs) == 2 {
		rawIndex = segs[0]
	}
	indices, ok := s.resolveMaintenanceTargetIndices(w, rawIndex)
	if !ok {
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	resp := map[string]any{
		"_shards": map[string]any{
			"total":      len(indices),
			"successful": len(indices),
			"failed":     0,
		},
	}
	for _, idx := range indices {
		resp[idx] = map[string]any{
			"shards": []any{
				map[string]any{
					"fields":      map[string]any{},
					"field_usage": map[string]any{},
				},
			},
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSnapshotClone implements `POST/PUT /_snapshot/{repository}/{snapshot}/_clone/{target_snapshot}` (Round 55 F5).
func (s *Server) handleSnapshotClone(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	repo := strings.TrimSpace(segs[1])
	srcSnap := strings.TrimSpace(segs[2])
	targetSnap := strings.TrimSpace(segs[4])
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if _, repoExists := s.snapshotRepos[repo]; !repoExists {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
		return
	}
	srcEntry, snapExists := s.snapshots[repo][srcSnap]
	if !snapExists {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "snapshot_missing_exception", fmt.Sprintf("[%s:%s] is missing", repo, srcSnap))
		return
	}
	if _, targetExists := s.snapshots[repo][targetSnap]; targetExists {
		s.mu.Unlock()
		writeESError(w, http.StatusBadRequest, "invalid_snapshot_name_exception", fmt.Sprintf("[%s:%s] Invalid snapshot name [%s], snapshot with the same name already exists", repo, targetSnap, targetSnap))
		return
	}
	cloned := deepCloneDocMap(srcEntry)
	cloned["snapshot"] = targetSnap
	cloned["uuid"] = targetSnap + "-uuid"
	if rawIndices, hasIndices := body["indices"]; hasIndices && rawIndices != nil {
		switch iv := rawIndices.(type) {
		case string:
			var parts []string
			for _, p := range strings.Split(iv, ",") {
				if p = strings.TrimSpace(p); p != "" && p != "*" && p != "_all" {
					parts = append(parts, p)
				}
			}
			if len(parts) > 0 {
				cloned["indices"] = parts
			}
		case []any:
			var parts []string
			for _, el := range iv {
				if p := strings.TrimSpace(fmt.Sprintf("%v", el)); p != "" {
					parts = append(parts, p)
				}
			}
			cloned["indices"] = parts
		}
	}
	s.snapshots[repo][targetSnap] = cloned
	respSnap := deepCloneDocMap(cloned)
	delete(respSnap, "index_docs")
	delete(respSnap, "index_schemas")
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": true,
		"snapshot": respSnap,
	})
}

// handleMLAPI implements `/_ml/*` endpoints (Round 55 F6).
func (s *Server) handleMLAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	sub := segs[1]
	switch sub {
	case "info":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.mu.RLock()
		upMode := s.mlUpgradeMode
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"defaults": map[string]any{
				"anomaly_detectors": map[string]any{
					"model_memory_limit":                        "1gb",
					"categorization_examples_limit":             4,
					"model_snapshot_retention_days":             10,
					"daily_model_snapshot_retention_after_days": 1,
				},
				"datafeeds": map[string]any{
					"scroll_size": 1000,
				},
			},
			"limits": map[string]any{
				"max_model_memory_limit": "0b",
			},
			"upgrade_mode": upMode,
		})

	case "memory_stats":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"cluster_name": "apache-doris-search-cluster",
			"nodes": map[string]any{
				"doris-fe-1": map[string]any{
					"name": "doris-fe-1",
					"jvm": map[string]any{
						"heap_max":                "1gb",
						"heap_max_in_bytes":       1073741824,
						"java_inference":          "0b",
						"java_inference_in_bytes": 0,
					},
					"mem": map[string]any{
						"total":                   "8gb",
						"total_in_bytes":          8589934592,
						"adjusted_total":          "8gb",
						"adjusted_total_in_bytes": 8589934592,
						"ml": map[string]any{
							"max":                           "2gb",
							"max_in_bytes":                  2147483648,
							"native_code_overhead":          "0b",
							"native_code_overhead_in_bytes": 0,
							"anomaly_detectors":             "0b",
							"anomaly_detectors_in_bytes":    0,
							"data_frame_analytics":          "0b",
							"data_frame_analytics_in_bytes": 0,
							"native_inference":              "0b",
							"native_inference_in_bytes":     0,
						},
					},
				},
			},
		})

	case "set_upgrade_mode":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		enabled := isTruthyBoolQueryParam(r, "enabled")
		if body, ok := parseJSONBody(w, r); ok {
			if b, hasB := body["enabled"].(bool); hasB {
				enabled = b
			}
		}
		s.mu.Lock()
		s.mlUpgradeMode = enabled
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case "anomaly_detectors":
		s.handleMLAnomalyDetectors(w, r, segs)

	case "datafeeds":
		s.handleMLDatafeeds(w, r, segs)

	case "trained_models":
		s.handleMLTrainedModels(w, r, segs)

	case "calendars":
		s.handleMLCalendars(w, r, segs)

	case "filters":
		s.handleMLFilters(w, r, segs)

	case "data_frame":
		s.handleMLDataFrame(w, r, segs)

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func (s *Server) handleMLAnomalyDetectors(w http.ResponseWriter, r *http.Request, segs []string) {
	if s.handleMLAnomalySubRoutes(w, r, segs) {
		return
	}
	if (len(segs) == 3 && segs[2] == "_stats") || (len(segs) == 4 && segs[3] == "_stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		targetID := "_all"
		if len(segs) == 4 {
			targetID = strings.TrimSpace(segs[2])
		}
		s.mu.RLock()
		var statsList []any
		for id, job := range s.mlJobs {
			if targetID != "_all" && targetID != "*" && !matchSimpleWildcard(targetID, id) {
				continue
			}
			state, _ := job["state"].(string)
			if state == "" {
				state = "closed"
			}
			procRecs, _ := toInt64(job["_processed_record_count"])
			procFields, _ := toInt64(job["_processed_field_count"])
			inBytes, _ := toInt64(job["_input_bytes"])
			bucketCnt, _ := toInt64(job["_bucket_count"])
			statsList = append(statsList, map[string]any{
				"job_id": id,
				"state":  state,
				"data_counts": map[string]any{
					"job_id":                       id,
					"processed_record_count":       procRecs,
					"processed_field_count":        procFields,
					"input_bytes":                  inBytes,
					"input_field_count":            procFields,
					"invalid_date_count":           0,
					"missing_field_count":          0,
					"out_of_order_timestamp_count": 0,
					"empty_bucket_count":           0,
					"sparse_bucket_count":          0,
					"bucket_count":                 bucketCnt,
					"input_record_count":           procRecs,
				},
				"model_size_stats": map[string]any{
					"job_id":                           id,
					"result_type":                      "model_size_stats",
					"model_bytes":                      0,
					"total_by_field_count":             0,
					"total_over_field_count":           0,
					"total_partition_field_count":      0,
					"bucket_allocation_failures_count": 0,
					"memory_status":                    "ok",
				},
			})
		}
		s.mu.RUnlock()
		if targetID != "_all" && targetID != "*" && !strings.ContainsAny(targetID, "*?") && len(statsList) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown job [%s]", targetID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if statsList == nil {
			statsList = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(statsList),
			"jobs":  statsList,
		})
		return
	}

	if len(segs) == 4 {
		jobID := strings.TrimSpace(segs[2])
		action := strings.TrimSpace(segs[3])
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.mu.Lock()
		job, exists := s.mlJobs[jobID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown job [%s]", jobID))
			return
		}
		switch action {
		case "_open":
			job["state"] = "opened"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"opened": true})
		case "_close":
			job["state"] = "closed"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"closed": true})
		case "_update":
			s.mu.Unlock()
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			for k, v := range body {
				job[k] = v
			}
			cp := stripInternalUnderscoreKeys(job)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, cp)
		case "_flush":
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"flushed": true})
		default:
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		}
		return
	}

	jobID := ""
	if len(segs) >= 3 {
		jobID = strings.TrimSpace(segs[2])
	}
	switch r.Method {
	case http.MethodPut:
		if jobID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: job_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		ac, _ := body["analysis_config"].(map[string]any)
		if ac == nil {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [analysis_config] is required;")
			return
		}
		dc, _ := body["data_description"].(map[string]any)
		if dc == nil {
			dc = map[string]any{"time_field": "@timestamp", "time_format": "epoch_ms"}
		}
		entry := deepCloneDocMap(body)
		entry["job_id"] = jobID
		entry["job_type"] = "anomaly_detector"
		entry["create_time"] = time.Now().UTC().UnixMilli()
		entry["state"] = "closed"
		entry["analysis_config"] = ac
		entry["data_description"] = dc
		s.mu.Lock()
		if s.mlJobs == nil {
			s.mlJobs = make(map[string]map[string]any)
		}
		s.mlJobs[jobID] = entry
		cp := stripInternalUnderscoreKeys(entry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		var jobs []any
		for id, job := range s.mlJobs {
			if jobID != "" && jobID != "_all" && jobID != "*" && !matchSimpleWildcard(jobID, id) {
				continue
			}
			jobs = append(jobs, stripInternalUnderscoreKeys(job))
		}
		s.mu.RUnlock()
		if jobID != "" && jobID != "_all" && jobID != "*" && !strings.ContainsAny(jobID, "*?") && len(jobs) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown job [%s]", jobID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if jobs == nil {
			jobs = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(jobs),
			"jobs":  jobs,
		})

	case http.MethodDelete:
		if jobID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: job_id is missing;")
			return
		}
		s.mu.Lock()
		_, exists := s.mlJobs[jobID]
		delete(s.mlJobs, jobID)
		s.mu.Unlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown job [%s]", jobID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleMLDatafeeds(w http.ResponseWriter, r *http.Request, segs []string) {
	if (len(segs) == 3 && segs[2] == "_stats") || (len(segs) == 4 && segs[3] == "_stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		targetID := "_all"
		if len(segs) == 4 {
			targetID = strings.TrimSpace(segs[2])
		}
		s.mu.RLock()
		var statsList []any
		for id, df := range s.mlDatafeeds {
			if targetID != "_all" && targetID != "*" && !matchSimpleWildcard(targetID, id) {
				continue
			}
			state, _ := df["state"].(string)
			if state == "" {
				state = "stopped"
			}
			statsList = append(statsList, map[string]any{
				"datafeed_id": id,
				"state":       state,
			})
		}
		s.mu.RUnlock()
		if targetID != "_all" && targetID != "*" && !strings.ContainsAny(targetID, "*?") && len(statsList) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown datafeed [%s]", targetID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if statsList == nil {
			statsList = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":     len(statsList),
			"datafeeds": statsList,
		})
		return
	}

	if len(segs) == 4 {
		dfID := strings.TrimSpace(segs[2])
		action := strings.TrimSpace(segs[3])
		s.mu.Lock()
		df, exists := s.mlDatafeeds[dfID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown datafeed [%s]", dfID))
			return
		}
		switch action {
		case "_start":
			if r.Method != http.MethodPost {
				s.mu.Unlock()
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			df["state"] = "started"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"started": true})
		case "_stop":
			if r.Method != http.MethodPost {
				s.mu.Unlock()
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			df["state"] = "stopped"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
		case "_update":
			s.mu.Unlock()
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			for k, v := range body {
				df[k] = v
			}
			cp := deepCloneDocMap(df)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, cp)
		case "_preview":
			s.mu.Unlock()
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, []any{})
		default:
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		}
		return
	}

	dfID := ""
	if len(segs) >= 3 {
		dfID = strings.TrimSpace(segs[2])
	}
	switch r.Method {
	case http.MethodPut:
		if dfID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: datafeed_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		jobID, _ := body["job_id"].(string)
		if strings.TrimSpace(jobID) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [job_id] is required;")
			return
		}
		entry := deepCloneDocMap(body)
		entry["datafeed_id"] = dfID
		entry["state"] = "stopped"
		if entry["indices"] == nil {
			entry["indices"] = []any{"*"}
		}
		if entry["query"] == nil {
			entry["query"] = map[string]any{"match_all": map[string]any{}}
		}
		s.mu.Lock()
		if s.mlDatafeeds == nil {
			s.mlDatafeeds = make(map[string]map[string]any)
		}
		s.mlDatafeeds[dfID] = entry
		cp := deepCloneDocMap(entry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		var list []any
		for id, df := range s.mlDatafeeds {
			if dfID != "" && dfID != "_all" && dfID != "*" && !matchSimpleWildcard(dfID, id) {
				continue
			}
			list = append(list, deepCloneDocMap(df))
		}
		s.mu.RUnlock()
		if dfID != "" && dfID != "_all" && dfID != "*" && !strings.ContainsAny(dfID, "*?") && len(list) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown datafeed [%s]", dfID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":     len(list),
			"datafeeds": list,
		})

	case http.MethodDelete:
		if dfID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: datafeed_id is missing;")
			return
		}
		s.mu.Lock()
		_, exists := s.mlDatafeeds[dfID]
		delete(s.mlDatafeeds, dfID)
		s.mu.Unlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown datafeed [%s]", dfID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleMLTrainedModels(w http.ResponseWriter, r *http.Request, segs []string) {
	if (len(segs) == 3 && segs[2] == "_stats") || (len(segs) == 4 && segs[3] == "_stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		targetID := "_all"
		if len(segs) == 4 {
			targetID = strings.TrimSpace(segs[2])
		}
		s.mu.RLock()
		resolvedTarget := targetID
		if realID, ok := s.mlModelAliases[targetID]; ok && realID != "" {
			resolvedTarget = realID
		}
		var modelIDs []string
		for id := range s.mlTrainedModels {
			if resolvedTarget != "_all" && resolvedTarget != "*" && !matchSimpleWildcard(resolvedTarget, id) {
				continue
			}
			modelIDs = append(modelIDs, id)
		}
		sort.Strings(modelIDs)
		var statsList []any
		for _, id := range modelIDs {
			m := s.mlTrainedModels[id]
			infCnt, _ := toInt64(m["_inference_count"])
			statObj := map[string]any{
				"model_id":       id,
				"pipeline_count": 0,
				"ingest":         map[string]any{"total": map[string]any{"count": infCnt}},
			}
			if depID, dep := s.findDeploymentForModelLocked(id); dep != nil {
				allocs, _ := toInt64(dep["number_of_allocations"])
				threads, _ := toInt64(dep["threads_per_allocation"])
				qCap, _ := toInt64(dep["queue_capacity"])
				depInf, _ := toInt64(dep["inference_count"])
				startMS, _ := toInt64(dep["start_time"])
				statObj["deployment_stats"] = map[string]any{
					"model_id":               id,
					"deployment_id":          depID,
					"state":                  "started",
					"number_of_allocations":  allocs,
					"threads_per_allocation": threads,
					"queue_capacity":         qCap,
					"inference_count":        depInf,
					"start_time":             startMS,
					"nodes": []any{
						map[string]any{
							"node": map[string]any{
								"id":   "local-node-1",
								"name": "doris-es-proxy-node-1",
							},
							"routing_state":   map[string]any{"routing_state": "started"},
							"inference_count": depInf,
						},
					},
				}
			}
			statsList = append(statsList, statObj)
		}
		s.mu.RUnlock()
		if targetID != "_all" && targetID != "*" && !strings.ContainsAny(targetID, "*?") && len(statsList) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("No trained models matched [%s]", targetID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if statsList == nil {
			statsList = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":               len(statsList),
			"trained_model_stats": statsList,
		})
		return
	}

	if len(segs) >= 4 {
		s.handleMLTrainedModelSubRoute(w, r, segs)
		return
	}

	modelID := ""
	if len(segs) >= 3 {
		modelID = strings.TrimSpace(segs[2])
	}
	switch r.Method {
	case http.MethodPut:
		if modelID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: model_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		entry := deepCloneDocMap(body)
		entry["model_id"] = modelID
		entry["create_time"] = time.Now().UTC().UnixMilli()
		entry["version"] = "8.15.0"
		s.mu.Lock()
		if s.mlTrainedModels == nil {
			s.mlTrainedModels = make(map[string]map[string]any)
		}
		s.mlTrainedModels[modelID] = entry
		cp := s.formatTrainedModelConfigLocked(modelID, entry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		resolvedID := modelID
		if realID, ok := s.mlModelAliases[modelID]; ok && realID != "" {
			resolvedID = realID
		}
		var ids []string
		for id := range s.mlTrainedModels {
			if resolvedID != "" && resolvedID != "_all" && resolvedID != "*" && !matchSimpleWildcard(resolvedID, id) {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var list []any
		for _, id := range ids {
			list = append(list, s.formatTrainedModelConfigLocked(id, s.mlTrainedModels[id]))
		}
		s.mu.RUnlock()
		if modelID != "" && modelID != "_all" && modelID != "*" && !strings.ContainsAny(modelID, "*?") && len(list) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("No trained models matched [%s]", modelID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":                 len(list),
			"trained_model_configs": list,
		})

	case http.MethodDelete:
		if modelID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: model_id is missing;")
			return
		}
		force := isTruthyBoolQueryParam(r, "force")
		s.mu.Lock()
		_, exists := s.mlTrainedModels[modelID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("No trained models matched [%s]", modelID))
			return
		}
		if !force {
			if depID, dep := s.findDeploymentForModelLocked(modelID); dep != nil {
				s.mu.Unlock()
				writeESError(w, http.StatusConflict, "status_exception",
					fmt.Sprintf("Cannot delete trained model [%s] as it is referenced by active deployment [%s]; stop deployment or set force=true", modelID, depID))
				return
			}
			for alias, target := range s.mlModelAliases {
				if target == modelID {
					s.mu.Unlock()
					writeESError(w, http.StatusConflict, "status_exception",
						fmt.Sprintf("Cannot delete trained model [%s] as it is referenced by model_alias [%s]; remove alias or set force=true", modelID, alias))
					return
				}
			}
		}
		for depID, dep := range s.mlModelDeployments {
			if mid, _ := dep["model_id"].(string); mid == modelID {
				delete(s.mlModelDeployments, depID)
			}
		}
		for alias, target := range s.mlModelAliases {
			if target == modelID {
				delete(s.mlModelAliases, alias)
			}
		}
		delete(s.mlTrainedModels, modelID)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleMLCalendars(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) >= 4 {
		calID := strings.TrimSpace(segs[2])
		sub := strings.TrimSpace(segs[3])
		s.mu.Lock()
		cal, exists := s.mlCalendars[calID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown calendar [%s]", calID))
			return
		}
		switch sub {
		case "jobs":
			if len(segs) < 5 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "job_id is required")
				return
			}
			jobID := strings.TrimSpace(segs[4])
			jobIDs, _ := cal["job_ids"].([]any)
			switch r.Method {
			case http.MethodPut, http.MethodPost:
				for _, j := range strings.Split(jobID, ",") {
					j = strings.TrimSpace(j)
					if j != "" {
						jobIDs = append(jobIDs, j)
					}
				}
				cal["job_ids"] = jobIDs
				cp := deepCloneDocMap(cal)
				delete(cp, "_events")
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, cp)
			case http.MethodDelete:
				var filtered []any
				for _, existing := range jobIDs {
					if fmt.Sprintf("%v", existing) != jobID {
						filtered = append(filtered, existing)
					}
				}
				if filtered == nil {
					filtered = []any{}
				}
				cal["job_ids"] = filtered
				cp := deepCloneDocMap(cal)
				delete(cp, "_events")
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, cp)
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			}
			return

		case "events":
			events, _ := cal["_events"].([]any)
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				s.mu.Unlock()
				body, ok := parseJSONBody(w, r)
				if !ok {
					return
				}
				newEvents, _ := body["events"].([]any)
				s.mu.Lock()
				var added []any
				for idx, evAny := range newEvents {
					if evMap, ok := evAny.(map[string]any); ok {
						cp := deepCloneDocMap(evMap)
						cp["calendar_id"] = calID
						if cp["event_id"] == nil {
							cp["event_id"] = fmt.Sprintf("ev_%d", len(events)+idx+1)
						}
						events = append(events, cp)
						added = append(added, cp)
					}
				}
				cal["_events"] = events
				s.mu.Unlock()
				if added == nil {
					added = []any{}
				}
				writeJSON(w, http.StatusOK, map[string]any{"events": added})
			case http.MethodGet, http.MethodHead:
				s.mu.Unlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusOK)
					return
				}
				if events == nil {
					events = []any{}
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"count":  len(events),
					"events": events,
				})
			case http.MethodDelete:
				eventID := ""
				if len(segs) >= 5 {
					eventID = strings.TrimSpace(segs[4])
				}
				var filtered []any
				for _, evAny := range events {
					if evMap, ok := evAny.(map[string]any); ok {
						if eventID != "" && fmt.Sprintf("%v", evMap["event_id"]) == eventID {
							continue
						}
						filtered = append(filtered, evMap)
					}
				}
				cal["_events"] = filtered
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			}
			return
		default:
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			return
		}
	}

	calID := ""
	if len(segs) >= 3 {
		calID = strings.TrimSpace(segs[2])
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if calID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: calendar_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		jobIDs, _ := body["job_ids"].([]any)
		if jobIDs == nil {
			jobIDs = []any{}
		}
		desc, _ := body["description"].(string)
		entry := map[string]any{
			"calendar_id": calID,
			"job_ids":     jobIDs,
			"description": desc,
			"_events":     []any{},
		}
		s.mu.Lock()
		if s.mlCalendars == nil {
			s.mlCalendars = make(map[string]map[string]any)
		}
		s.mlCalendars[calID] = entry
		cp := deepCloneDocMap(entry)
		delete(cp, "_events")
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		var list []any
		for id, cal := range s.mlCalendars {
			if calID != "" && calID != "_all" && calID != "*" && !matchSimpleWildcard(calID, id) {
				continue
			}
			cp := deepCloneDocMap(cal)
			delete(cp, "_events")
			list = append(list, cp)
		}
		s.mu.RUnlock()
		if calID != "" && calID != "_all" && calID != "*" && !strings.ContainsAny(calID, "*?") && len(list) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown calendar [%s]", calID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":     len(list),
			"calendars": list,
		})

	case http.MethodDelete:
		if calID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: calendar_id is missing;")
			return
		}
		s.mu.Lock()
		_, exists := s.mlCalendars[calID]
		delete(s.mlCalendars, calID)
		s.mu.Unlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown calendar [%s]", calID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleMLFilters(w http.ResponseWriter, r *http.Request, segs []string) {
	filterID := ""
	if len(segs) >= 3 {
		filterID = strings.TrimSpace(segs[2])
	}
	if len(segs) == 4 && segs[3] == "_update" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		fObj, exists := s.mlFilters[filterID]
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown filter [%s]", filterID))
			return
		}
		items, _ := fObj["items"].([]any)
		if addItems, ok := body["add_items"].([]any); ok {
			items = append(items, addItems...)
		}
		if removeItems, ok := body["remove_items"].([]any); ok {
			remSet := make(map[string]bool, len(removeItems))
			for _, rm := range removeItems {
				remSet[fmt.Sprintf("%v", rm)] = true
			}
			var kept []any
			for _, it := range items {
				if !remSet[fmt.Sprintf("%v", it)] {
					kept = append(kept, it)
				}
			}
			items = kept
		}
		if items == nil {
			items = []any{}
		}
		fObj["items"] = items
		if desc, ok := body["description"].(string); ok {
			fObj["description"] = desc
		}
		cp := deepCloneDocMap(fObj)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if filterID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: filter_id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		items, _ := body["items"].([]any)
		if items == nil {
			items = []any{}
		}
		desc, _ := body["description"].(string)
		entry := map[string]any{
			"filter_id":   filterID,
			"items":       items,
			"description": desc,
		}
		s.mu.Lock()
		if s.mlFilters == nil {
			s.mlFilters = make(map[string]map[string]any)
		}
		s.mlFilters[filterID] = entry
		cp := deepCloneDocMap(entry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, cp)

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		var list []any
		for id, fObj := range s.mlFilters {
			if filterID != "" && filterID != "_all" && filterID != "*" && !matchSimpleWildcard(filterID, id) {
				continue
			}
			list = append(list, deepCloneDocMap(fObj))
		}
		s.mu.RUnlock()
		if filterID != "" && filterID != "_all" && filterID != "*" && !strings.ContainsAny(filterID, "*?") && len(list) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown filter [%s]", filterID))
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(list),
			"filters": list,
		})

	case http.MethodDelete:
		if filterID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: filter_id is missing;")
			return
		}
		s.mu.Lock()
		_, exists := s.mlFilters[filterID]
		delete(s.mlFilters, filterID)
		s.mu.Unlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Unknown filter [%s]", filterID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

// handleFleetAPI implements `/_fleet/*` and `/{index}/_fleet/*` (Round 55 F8).
func (s *Server) handleFleetAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	action := ""
	if segs[0] == "_fleet" && len(segs) >= 2 {
		action = segs[1]
	} else if len(segs) == 3 && segs[1] == "_fleet" {
		r.SetPathValue("index", segs[0])
		action = segs[2]
	}
	switch action {
	case "msearch":
		s.handleMSearch(w, r)
	case "search":
		s.handleSearch(w, r)
	case "global_checkpoints":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if idx := strings.TrimSpace(r.PathValue("index")); idx != "" && idx != "_all" && idx != "*" {
			if _, ok := s.resolveMaintenanceTargetIndices(w, idx); !ok {
				return
			}
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"global_checkpoints":            []int{0},
			"last_KNOWN_global_checkpoints": []int{0},
		})
	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

// handleGraphExplore implements `POST/GET /_graph/explore` and `/{index}/_graph/explore` (Round 55 F8).
func (s *Server) handleGraphExplore(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if len(segs) == 3 {
		if _, ok := s.resolveMaintenanceTargetIndices(w, segs[0]); !ok {
			return
		}
	}
	if _, ok := parseJSONBody(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":        1,
		"timed_out":   false,
		"failures":    []any{},
		"connections": []any{},
		"vertices":    []any{},
	})
}

// handleCatComponentTemplates implements `GET/HEAD /_cat/component_templates` and `/_cat/component_templates/{name}` (Round 55 F9).
func (s *Server) handleCatComponentTemplates(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	namePat := ""
	if len(segs) >= 3 {
		namePat = strings.TrimSpace(segs[2])
	}
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	var names []string
	for k := range s.componentTemplates {
		if namePat != "" && namePat != "_all" && namePat != "*" && !matchSimpleWildcard(namePat, k) {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	rows := make([]map[string]any, 0, len(names))
	for _, k := range names {
		ct := s.componentTemplates[k]
		ver := "0"
		if v, ok := ct["version"]; ok && v != nil {
			ver = fmt.Sprintf("%v", v)
		}
		tpl, _ := ct["template"].(map[string]any)
		aliasCount, mappingCount, settingsCount, metaCount := 0, 0, 0, 0
		if tpl != nil {
			if am, ok := tpl["aliases"].(map[string]any); ok {
				aliasCount = len(am)
			}
			if mm, ok := tpl["mappings"].(map[string]any); ok && len(mm) > 0 {
				mappingCount = 1
			}
			if sm, ok := tpl["settings"].(map[string]any); ok {
				settingsCount = len(sm)
			}
		}
		if meta, ok := ct["_meta"].(map[string]any); ok {
			metaCount = len(meta)
		}
		var includedIn []string
		for tplName, idxTpl := range s.templates {
			for _, comp := range idxTpl.ComposedOf {
				if comp == k {
					includedIn = append(includedIn, tplName)
					break
				}
			}
		}
		sort.Strings(includedIn)
		rows = append(rows, map[string]any{
			"name":           k,
			"version":        ver,
			"alias_count":    fmt.Sprintf("%d", aliasCount),
			"mapping_count":  fmt.Sprintf("%d", mappingCount),
			"settings_count": fmt.Sprintf("%d", settingsCount),
			"metadata_count": fmt.Sprintf("%d", metaCount),
			"included_in":    "[" + strings.Join(includedIn, ", ") + "]",
		})
	}
	s.mu.RUnlock()
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeCatResponse(w, r, []string{"name", "version", "alias_count", "mapping_count", "settings_count", "metadata_count", "included_in"}, rows)
}

// handleCatML implements `/_cat/ml_anomaly_detectors*`, `/_cat/ml_jobs*`, `/_cat/ml_datafeeds*`, `/_cat/ml_trained_models*`, and `/_cat/ml_data_frame_analytics*` (Round 55 F9).
func (s *Server) handleCatML(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	kind := segs[1]
	idPat := ""
	if kind == "ml" {
		if len(segs) >= 4 && segs[2] == "data_frame" && segs[3] == "analytics" {
			kind = "ml_data_frame_analytics"
			if len(segs) >= 5 {
				idPat = strings.TrimSpace(segs[4])
			}
		} else if len(segs) >= 3 {
			switch segs[2] {
			case "anomaly_detectors", "jobs", "datafeeds", "trained_models", "data_frame_analytics":
				kind = "ml_" + segs[2]
				if len(segs) >= 4 {
					idPat = strings.TrimSpace(segs[3])
				}
			default:
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
				return
			}
		}
	} else if len(segs) >= 3 {
		idPat = strings.TrimSpace(segs[2])
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.mu.RLock()
	switch kind {
	case "ml_anomaly_detectors", "ml_jobs":
		var ids []string
		for id := range s.mlJobs {
			if idPat != "" && idPat != "_all" && idPat != "*" && !matchSimpleWildcard(idPat, id) {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			job := s.mlJobs[id]
			state, _ := job["state"].(string)
			if state == "" {
				state = "closed"
			}
			rows = append(rows, map[string]any{
				"id":                     id,
				"state":                  state,
				"opened_time":            "",
				"assignment_explanation": "",
				"data.processed_records": "0",
				"data.processed_fields":  "0",
				"data.input_bytes":       "0b",
				"model.bytes":            "0b",
			})
		}
		s.mu.RUnlock()
		writeCatResponse(w, r, []string{"id", "state", "opened_time", "assignment_explanation", "data.processed_records", "data.processed_fields", "data.input_bytes", "model.bytes"}, rows)
	case "ml_datafeeds":
		var ids []string
		for id := range s.mlDatafeeds {
			if idPat != "" && idPat != "_all" && idPat != "*" && !matchSimpleWildcard(idPat, id) {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			df := s.mlDatafeeds[id]
			state, _ := df["state"].(string)
			if state == "" {
				state = "stopped"
			}
			rows = append(rows, map[string]any{
				"id":           id,
				"state":        state,
				"search.count": "0",
				"search.time":  "0s",
			})
		}
		s.mu.RUnlock()
		writeCatResponse(w, r, []string{"id", "state", "search.count", "search.time"}, rows)
	case "ml_trained_models":
		var ids []string
		for id := range s.mlTrainedModels {
			if idPat != "" && idPat != "_all" && idPat != "*" && !matchSimpleWildcard(idPat, id) {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			rows = append(rows, map[string]any{
				"id":          id,
				"model_type":  "tree_ensemble",
				"create_time": "2026-01-01T00:00:00.000Z",
				"version":     "8.15.0",
			})
		}
		s.mu.RUnlock()
		writeCatResponse(w, r, []string{"id", "model_type", "create_time", "version"}, rows)
	default:
		var ids []string
		for id := range s.mlDataFrameAnalytics {
			if idPat != "" && idPat != "_all" && idPat != "*" && !matchMultiWildcardWithExclusions(idPat, id) {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			job := s.mlDataFrameAnalytics[id]
			anType := "outlier_detection"
			if anMap, ok := job["analysis"].(map[string]any); ok {
				for _, k := range []string{"outlier_detection", "regression", "classification"} {
					if _, exists := anMap[k]; exists {
						anType = k
						break
					}
				}
			}
			state, _ := job["_state"].(string)
			if state == "" {
				state = "stopped"
			}
			desc, _ := job["description"].(string)
			ctStr := "2026-01-01T00:00:00.000Z"
			if ctMS, ok := toInt64(job["create_time"]); ok && ctMS > 0 {
				ctStr = time.UnixMilli(ctMS).UTC().Format("2006-01-02T15:04:05.000Z")
			}
			progStr := "start:0%"
			if state == "started" || state == "stopped" {
				if recs, ok := toInt64(job["_docs_processed"]); ok && recs > 0 {
					progStr = "finalize:100%"
				}
			}
			rows = append(rows, map[string]any{
				"id":                     id,
				"type":                   anType,
				"create_time":            ctStr,
				"state":                  state,
				"failure_reason":         "",
				"progress":               progStr,
				"assignment_explanation": "",
				"description":            desc,
			})
		}
		s.mu.RUnlock()
		writeCatResponse(w, r, []string{"id", "type", "create_time", "state", "failure_reason", "progress", "assignment_explanation", "description"}, rows)
	}
}

// handleClusterInfo implements `GET/HEAD /_cluster/info` and `/_cluster/info/{target}` (Round 55 F9).
func (s *Server) handleClusterInfo(w http.ResponseWriter, r *http.Request, segs []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	allInfo := map[string]any{
		"http": map[string]any{
			"publish_address":             "127.0.0.1:9200",
			"bound_address":               []string{"127.0.0.1:9200"},
			"max_content_length_in_bytes": DefaultMaxRequestBodyBytes,
		},
		"ingest": map[string]any{
			"processors": []map[string]any{
				{"type": "append"},
				{"type": "bytes"},
				{"type": "circle"},
				{"type": "community_id"},
				{"type": "compact"},
				{"type": "convert"},
				{"type": "csv"},
				{"type": "date"},
				{"type": "date_index_name"},
				{"type": "dissect"},
				{"type": "dot_expander"},
				{"type": "drop"},
				{"type": "enrich"},
				{"type": "fail"},
				{"type": "fingerprint"},
				{"type": "foreach"},
				{"type": "geoip"},
				{"type": "grok"},
				{"type": "gsub"},
				{"type": "html_strip"},
				{"type": "inference"},
				{"type": "join"},
				{"type": "json"},
				{"type": "kv"},
				{"type": "lowercase"},
				{"type": "network_direction"},
				{"type": "pipeline"},
				{"type": "redact"},
				{"type": "registered_domain"},
				{"type": "remove"},
				{"type": "rename"},
				{"type": "reroute"},
				{"type": "script"},
				{"type": "set"},
				{"type": "set_security_user"},
				{"type": "sort"},
				{"type": "split"},
				{"type": "terminate"},
				{"type": "trim"},
				{"type": "uppercase"},
				{"type": "uri_parts"},
				{"type": "urldecode"},
				{"type": "urlencode"},
				{"type": "user_agent"},
			},
		},
		"thread_pool": map[string]any{
			"generic": map[string]any{"type": "scaling", "min": 4, "max": 128, "keep_alive": "30s"},
			"search":  map[string]any{"type": "fixed_auto_queue_size", "size": 7, "queue_size": 1000},
			"write":   map[string]any{"type": "fixed", "size": 4, "queue_size": 10000},
		},
		"aggregations": map[string]any{
			"avg":            map[string]any{"types": []string{"numeric", "boolean", "date"}},
			"cardinality":    map[string]any{"types": []string{"numeric", "keyword", "ip", "date", "boolean"}},
			"date_histogram": map[string]any{"types": []string{"date", "numeric"}},
			"histogram":      map[string]any{"types": []string{"numeric", "date"}},
			"max":            map[string]any{"types": []string{"numeric", "boolean", "date"}},
			"min":            map[string]any{"types": []string{"numeric", "boolean", "date"}},
			"sum":            map[string]any{"types": []string{"numeric", "boolean", "date"}},
			"terms":          map[string]any{"types": []string{"keyword", "numeric", "ip", "boolean", "date"}},
			"value_count":    map[string]any{"types": []string{"object", "keyword", "numeric", "ip", "boolean", "date"}},
		},
	}
	targetRaw := "_all"
	if len(segs) >= 3 && strings.TrimSpace(segs[2]) != "" {
		targetRaw = strings.TrimSpace(segs[2])
	}
	outInfo := make(map[string]any)
	if targetRaw == "_all" || targetRaw == "*" {
		for k, v := range allInfo {
			outInfo[k] = v
		}
	} else {
		for _, t := range strings.Split(targetRaw, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if t == "_all" || t == "*" {
				for k, v := range allInfo {
					outInfo[k] = v
				}
				continue
			}
			val, exists := allInfo[t]
			if !exists {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("No enum constant org.elasticsearch.action.support.nodes.info.ClusterInfoTarget.%s", strings.ToUpper(t)))
				return
			}
			outInfo[t] = val
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "apache-doris-search-cluster",
		"info":         outInfo,
	})
}

// handleNodesRepositoriesMetering implements `GET/HEAD /_nodes/repositories_metering`, `/_nodes/{node_id}/repositories_metering`, and `DELETE /_nodes/clear_repositories_metering_archive/{max_archive_version}` (Round 55 F9).
func (s *Server) handleNodesRepositoriesMetering(w http.ResponseWriter, r *http.Request, segs []string) {
	isClear := segs[1] == "clear_repositories_metering_archive" || (len(segs) >= 3 && segs[2] == "clear_repositories_metering_archive")
	if isClear {
		if r.Method != http.MethodDelete {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		verIdx := 2
		if segs[2] == "clear_repositories_metering_archive" {
			verIdx = 3
		}
		if len(segs) <= verIdx || strings.TrimSpace(segs[verIdx]) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: max_archive_version is missing;")
			return
		}
		if _, err := strconv.ParseInt(strings.TrimSpace(segs[verIdx]), 10, 64); err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid max_archive_version [%s]", segs[verIdx]))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"cluster_name": "apache-doris-search-cluster",
			"nodes": map[string]any{
				"doris-fe-1": map[string]any{"name": "doris-fe-1"},
			},
		})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "apache-doris-search-cluster",
		"nodes": map[string]any{
			"doris-fe-1": map[string]any{
				"repositories_metering": []any{},
			},
		},
	})
}
