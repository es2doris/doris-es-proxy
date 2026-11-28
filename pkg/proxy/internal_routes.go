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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var validDesiredNodeRolesR67 = map[string]bool{
	"master":                true,
	"voting_only":           true,
	"data":                  true,
	"data_content":          true,
	"data_hot":              true,
	"data_warm":             true,
	"data_cold":             true,
	"data_frozen":           true,
	"ingest":                true,
	"ml":                    true,
	"remote_cluster_client": true,
	"transform":             true,
	"coordinating_only":     true,
}

type desiredNodesVersionRecordR67 struct {
	version int64
	digest  string
}

type desiredNodesStateR67 struct {
	HistoryID string
	Version   int64
	Nodes     []map[string]any
	Digest    string
	Versions  map[int64]desiredNodesVersionRecordR67
}

type internalClusterStateR67 struct {
	mu                    sync.RWMutex
	desiredNodes          *desiredNodesStateR67
	desiredBalanceResetAt int64
}

func newInternalClusterStateR67() *internalClusterStateR67 {
	return &internalClusterStateR67{}
}

func (s *Server) handleInternalAPI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
		return
	}
	switch segs[1] {
	case "desired_balance":
		if len(segs) != 2 {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.handleGetDesiredBalanceR67(w, r)
		case http.MethodDelete:
			s.handleDeleteDesiredBalanceR67(w, r)
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
	case "desired_nodes":
		s.handleDesiredNodesRouteR67(w, r, segs)
	case "prevalidate_node_removal":
		if len(segs) != 2 {
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
			return
		}
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.handlePrevalidateNodeRemovalR67(w, r)
	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
	}
}

func zeroMetricStatsObjR67() map[string]any {
	return map[string]any{
		"total":   float64(0),
		"min":     float64(0),
		"max":     float64(0),
		"average": float64(0),
		"std_dev": float64(0),
	}
}

func (s *Server) handleGetDesiredBalanceR67(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	isES8 := s.isES8Mode(r)
	roles := []string{"data", "ingest", "master", "remote_cluster_client"}
	if isES8 {
		roles = []string{
			"data", "data_cold", "data_content", "data_frozen", "data_hot", "data_warm",
			"ingest", "master", "ml", "remote_cluster_client", "transform",
		}
	}

	s.mu.RLock()
	indexNames := make([]string, 0, len(s.indices))
	for name := range s.indices {
		indexNames = append(indexNames, name)
	}
	sort.Strings(indexNames)
	var totalBytes int64
	for _, name := range indexNames {
		if st := s.indexStats[name]; st != nil {
			liveDocs := st.indexTotal.Load() - st.deleteTotal.Load()
			if liveDocs > 0 {
				totalBytes += liveDocs * 1024
			}
		}
	}
	s.mu.RUnlock()

	routingTable := make(map[string]any, len(indexNames))
	var totalShards int64
	for _, idxName := range indexNames {
		nShards, _, _ := s.getIndexShardAndReplicaCounts(idxName)
		if nShards <= 0 {
			nShards = 1
		}
		shardMap := make(map[string]any, nShards)
		for sh := 0; sh < nShards; sh++ {
			totalShards++
			shardMap[strconv.Itoa(sh)] = map[string]any{
				"current": []any{
					map[string]any{
						"state":                        "STARTED",
						"shard_id":                     sh,
						"index":                        idxName,
						"node_id":                      taskLocalNodeID,
						"node_is_desired":              true,
						"relocating_node":              false,
						"relocating_node_is_desired":   false,
						"forecast_write_load":          false,
						"forecast_shard_size_in_bytes": false,
						"tier_preference":              []string{"data_content"},
					},
				},
				"desired": map[string]any{
					"total":      1,
					"unassigned": 0,
					"ignored":    0,
					"node_ids":   []string{taskLocalNodeID},
				},
			}
		}
		routingTable[idxName] = shardMap
	}

	shardStatsObj := map[string]any{
		"total":   totalShards,
		"min":     totalShards,
		"max":     totalShards,
		"average": float64(totalShards),
		"std_dev": float64(0),
	}
	diskStatsObj := map[string]any{
		"total":   totalBytes,
		"min":     totalBytes,
		"max":     totalBytes,
		"average": float64(totalBytes),
		"std_dev": float64(0),
	}

	nodeBalanceStats := map[string]any{
		"node_id":                          taskLocalNodeID,
		"roles":                            roles,
		"shard_count":                      totalShards,
		"forecast_write_load":              float64(0),
		"forecast_disk_usage_bytes":        totalBytes,
		"actual_disk_usage_bytes":          totalBytes,
		"undesired_shard_allocation_count": int64(0),
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"stats": map[string]any{
			"computation_submitted":         int64(0),
			"computation_executed":          int64(0),
			"computation_converged":         int64(0),
			"computation_iterations":        int64(0),
			"computation_converged_index":   int64(0),
			"computation_time_in_millis":    int64(0),
			"reconciliation_time_in_millis": int64(0),
			"computed_shard_movements":      int64(0),
			"unassigned_shards":             int64(0),
			"total_allocations":             totalShards,
			"undesired_allocations":         int64(0),
			"undesired_allocations_ratio":   float64(0),
		},
		"routing_table": routingTable,
		"cluster_balance_stats": map[string]any{
			"shard_count":                      totalShards,
			"undesired_shard_allocation_count": int64(0),
			"tiers": map[string]any{
				"data_content": map[string]any{
					"shard_count":                      shardStatsObj,
					"forecast_write_load":              zeroMetricStatsObjR67(),
					"forecast_disk_usage":              diskStatsObj,
					"actual_disk_usage":                diskStatsObj,
					"undesired_shard_allocation_count": zeroMetricStatsObjR67(),
				},
			},
			"nodes": map[string]any{
				"doris-es-proxy": nodeBalanceStats,
			},
		},
		"cluster_info": map[string]any{
			"data_tiers": map[string]any{
				"data_content": map[string]any{
					"nodes": []string{taskLocalNodeID},
				},
			},
		},
	})
}

func (s *Server) handleDeleteDesiredBalanceR67(w http.ResponseWriter, r *http.Request) {
	if s.internalClusterState != nil {
		s.internalClusterState.mu.Lock()
		s.internalClusterState.desiredBalanceResetAt++
		s.internalClusterState.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleDesiredNodesRouteR67(w http.ResponseWriter, r *http.Request, segs []string) {
	switch {
	case len(segs) == 2:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.handleGetDesiredNodesR67(w, r)
		case http.MethodDelete:
			s.handleDeleteDesiredNodesR67(w, r)
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
	case len(segs) == 3 && segs[2] == "_latest":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		s.handleGetDesiredNodesR67(w, r)
	case len(segs) >= 3 && r.Method == http.MethodPut:
		// Re-extract raw path segments to catch whitespace-only history_id or empty segments cleanly.
		historyID := segs[2]
		versionStr := ""
		if len(segs) == 4 {
			versionStr = segs[3]
		}
		if r.URL != nil {
			rawTrim := strings.TrimPrefix(r.URL.Path, "/_internal/desired_nodes/")
			if parts := strings.Split(rawTrim, "/"); len(parts) == 2 {
				if decH, err := url.PathUnescape(parts[0]); err == nil {
					historyID = decH
				} else {
					historyID = parts[0]
				}
				if decV, err := url.PathUnescape(parts[1]); err == nil {
					versionStr = decV
				} else {
					versionStr = parts[1]
				}
			} else if len(segs) != 4 {
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
				return
			}
		}
		s.handleUpdateDesiredNodesR67(w, r, historyID, versionStr)
	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "no handler found for uri ["+r.URL.Path+"]")
	}
}

func cloneJSONValueR67(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, val := range tv {
			out[k] = cloneJSONValueR67(val)
		}
		return out
	case []any:
		out := make([]any, len(tv))
		for i, val := range tv {
			out[i] = cloneJSONValueR67(val)
		}
		return out
	default:
		return tv
	}
}

func cloneDesiredNodesSliceR67(in []map[string]any) []map[string]any {
	out := make([]map[string]any, len(in))
	for i, n := range in {
		if cloned, ok := cloneJSONValueR67(n).(map[string]any); ok {
			out[i] = cloned
		} else {
			out[i] = map[string]any{}
		}
	}
	return out
}

func (s *Server) handleGetDesiredNodesR67(w http.ResponseWriter, r *http.Request) {
	var cur *desiredNodesStateR67
	if s.internalClusterState != nil {
		s.internalClusterState.mu.RLock()
		if s.internalClusterState.desiredNodes != nil {
			cp := *s.internalClusterState.desiredNodes
			cp.Nodes = cloneDesiredNodesSliceR67(s.internalClusterState.desiredNodes.Nodes)
			cur = &cp
		}
		s.internalClusterState.mu.RUnlock()
	}
	if cur == nil {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", "desired nodes not found")
		return
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"history_id": cur.HistoryID,
		"version":    cur.Version,
		"nodes":      cur.Nodes,
	})
}

func (s *Server) handleDeleteDesiredNodesR67(w http.ResponseWriter, _ *http.Request) {
	if s.internalClusterState != nil {
		s.internalClusterState.mu.Lock()
		s.internalClusterState.desiredNodes = nil
		s.internalClusterState.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func insertNestedSettingR67(root map[string]any, dottedKey string, val any) error {
	parts := strings.Split(dottedKey, ".")
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		seg := parts[i]
		if seg == "" {
			return fmt.Errorf("invalid empty setting segment in [%s]", dottedKey)
		}
		existing, exists := cur[seg]
		if !exists {
			nextMap := make(map[string]any)
			cur[seg] = nextMap
			cur = nextMap
			continue
		}
		nextMap, ok := existing.(map[string]any)
		if !ok {
			return fmt.Errorf("conflicting setting [%s]", dottedKey)
		}
		cur = nextMap
	}
	leaf := parts[len(parts)-1]
	if leaf == "" {
		return fmt.Errorf("invalid empty setting segment in [%s]", dottedKey)
	}
	if subMap, ok := val.(map[string]any); ok {
		for k, sv := range subMap {
			if err := insertNestedSettingR67(cur, leaf+"."+k, sv); err != nil {
				return err
			}
		}
		return nil
	}
	cur[leaf] = cloneJSONValueR67(val)
	return nil
}

func parseDesiredNodeRolesListR67(raw any) ([]string, bool, error) {
	var rawRoles []string
	switch rv := raw.(type) {
	case string:
		if strings.TrimSpace(rv) != "" {
			for _, part := range strings.Split(rv, ",") {
				p := strings.TrimSpace(part)
				if p == "" {
					return nil, true, fmt.Errorf("unknown node role []")
				}
				rawRoles = append(rawRoles, p)
			}
		}
	case []any:
		for _, item := range rv {
			rs, ok := item.(string)
			if !ok {
				return nil, true, fmt.Errorf("node role must be a string")
			}
			p := strings.TrimSpace(rs)
			if !validDesiredNodeRolesR67[p] {
				return nil, true, fmt.Errorf("unknown node role [%s]", p)
			}
			rawRoles = append(rawRoles, p)
		}
	default:
		return nil, true, fmt.Errorf("invalid node.roles format")
	}
	for _, r := range rawRoles {
		if !validDesiredNodeRolesR67[r] {
			return nil, true, fmt.Errorf("unknown node role [%s]", r)
		}
	}
	return rawRoles, true, nil
}

func parseStrictPositiveFiniteFloatR67(raw any, field string) (float64, error) {
	var val float64
	switch v := raw.(type) {
	case json.Number:
		s := strings.TrimSpace(v.String())
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse numeric [%s]: %v", field, err)
		}
		val = f
	case float64:
		val = v
	case float32:
		val = float64(v)
	case int:
		val = float64(v)
	case int64:
		val = float64(v)
	case string:
		return 0, fmt.Errorf("numeric field [%s] must be a number, found string [%s]", field, v)
	default:
		return 0, fmt.Errorf("numeric field [%s] is required", field)
	}
	if math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
		return 0, fmt.Errorf("[%s] must be a positive finite number", field)
	}
	return val, nil
}

const errMissingDesiredNodeIdentityR67 = "[node.name] or [node.external_id] is missing or empty"

func parseAndNormalizeDesiredNodesBodyR67(bodyBytes []byte, esVersion string) ([]map[string]any, string, bool, int, string, string) {
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "request body is required"
	}
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	var rawReq map[string]any
	if err := dec.Decode(&rawReq); err != nil || rawReq == nil {
		errMsg := "failed to parse request body"
		if err != nil {
			errMsg = err.Error()
		}
		return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", errMsg
	}

	rawNodesAny, exists := rawReq["nodes"]
	if !exists || rawNodesAny == nil {
		return nil, "", false, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: nodes must contain at least one master node;"
	}
	rawNodes, ok := rawNodesAny.([]any)
	if !ok {
		return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[nodes] must be an array"
	}
	if len(rawNodes) == 0 {
		return nil, "", false, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: nodes must contain at least one master node;"
	}

	normNodes := make([]map[string]any, 0, len(rawNodes))
	canonicalNodes := make([]string, 0, len(rawNodes))
	seenExtIDs := make(map[string]struct{}, len(rawNodes))
	hasMaster := false
	usedDeprecatedNodeVer := false
	_ = esVersion

	for _, item := range rawNodes {
		nodeObj, okObj := item.(map[string]any)
		if !okObj || nodeObj == nil {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "node entry must be an object"
		}

		// Validate settings.
		rawSettingsAny, hasSettings := nodeObj["settings"]
		if !hasSettings || rawSettingsAny == nil {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[settings] is required"
		}
		rawSettings, okSet := rawSettingsAny.(map[string]any)
		if !okSet || rawSettings == nil {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[settings] must be an object"
		}
		normSettings := make(map[string]any, len(rawSettings))
		for k, v := range rawSettings {
			if err := insertNestedSettingR67(normSettings, k, v); err != nil {
				return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", err.Error()
			}
		}

		nodeSub, _ := normSettings["node"].(map[string]any)
		var nodeName, extID string
		if nodeSub != nil {
			if ns, okS := nodeSub["name"].(string); okS {
				nodeName = strings.TrimSpace(ns)
			}
			if es, okE := nodeSub["external_id"].(string); okE {
				extID = strings.TrimSpace(es)
			}
		}
		if nodeName == "" && extID == "" {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception",
				errMissingDesiredNodeIdentityR67
		}
		if extID != "" {
			if _, dup := seenExtIDs[extID]; dup {
				return nil, "", false, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Some nodes contain the same setting value [%s] for [node.external_id]", extID)
			}
			seenExtIDs[extID] = struct{}{}
		}

		// Validate roles if present; nodes without explicit node.roles are master-eligible by default.
		if nodeSub != nil {
			if rawRoles, hasRoles := nodeSub["roles"]; hasRoles {
				rolesList, _, roleErr := parseDesiredNodeRolesListR67(rawRoles)
				if roleErr != nil {
					return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", roleErr.Error()
				}
				for _, rn := range rolesList {
					if rn == "master" {
						hasMaster = true
						break
					}
				}
			} else {
				hasMaster = true
			}
		} else {
			hasMaster = true
		}

		// Validate processors XOR processors_range.
		rawProc, hasProc := nodeObj["processors"]
		rawProcRange, hasProcRange := nodeObj["processors_range"]
		if (!hasProc && !hasProcRange) || (hasProc && rawProc == nil && !hasProcRange) {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[processors] or [processors_range] is required"
		}
		if hasProc && hasProcRange {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[processors] and [processors_range] cannot both be specified"
		}

		outNode := map[string]any{
			"settings": normSettings,
		}
		if hasProc {
			procVal, procErr := parseStrictPositiveFiniteFloatR67(rawProc, "processors")
			if procErr != nil {
				return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", procErr.Error()
			}
			outNode["processors"] = procVal
		} else {
			rngMap, okRng := rawProcRange.(map[string]any)
			if !okRng || rngMap == nil {
				return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[processors_range] must be an object"
			}
			rawMin, hasMin := rngMap["min"]
			if !hasMin || rawMin == nil {
				return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[processors_range.min] is required"
			}
			minVal, minErr := parseStrictPositiveFiniteFloatR67(rawMin, "processors_range.min")
			if minErr != nil {
				return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", minErr.Error()
			}
			normRange := map[string]any{"min": minVal}
			if rawMax, hasMax := rngMap["max"]; hasMax && rawMax != nil {
				maxVal, maxErr := parseStrictPositiveFiniteFloatR67(rawMax, "processors_range.max")
				if maxErr != nil {
					return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", maxErr.Error()
				}
				if minVal > maxVal {
					return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[processors_range.min] must be less than or equal to [processors_range.max]"
				}
				normRange["max"] = maxVal
			}
			outNode["processors_range"] = normRange
		}

		// Validate memory & storage.
		rawMem, hasMem := nodeObj["memory"]
		memStr, okMem := rawMem.(string)
		if !hasMem || rawMem == nil || !okMem || strings.TrimSpace(memStr) == "" {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[memory] is required"
		}
		if _, err := parseAutoscalingByteSizeR65(memStr); err != nil {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", err.Error()
		}
		outNode["memory"] = memStr

		rawStor, hasStor := nodeObj["storage"]
		storStr, okStor := rawStor.(string)
		if !hasStor || rawStor == nil || !okStor || strings.TrimSpace(storStr) == "" {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", "[storage] is required"
		}
		if _, err := parseAutoscalingByteSizeR65(storStr); err != nil {
			return nil, "", false, http.StatusBadRequest, "x_content_parse_exception", err.Error()
		}
		outNode["storage"] = storStr

		if nv, hasNV := nodeObj["node_version"]; hasNV && nv != nil {
			if nvStr, okNV := nv.(string); okNV && strings.TrimSpace(nvStr) != "" {
				outNode["node_version"] = nvStr
				usedDeprecatedNodeVer = true
			}
		}

		normNodes = append(normNodes, outNode)
		if jb, err := json.Marshal(outNode); err == nil {
			canonicalNodes = append(canonicalNodes, string(jb))
		}
	}

	if !hasMaster {
		return nil, "", false, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: nodes must contain at least one master node;"
	}

	sort.Strings(canonicalNodes)
	sum := sha256.Sum256([]byte(strings.Join(canonicalNodes, "\n")))
	digest := hex.EncodeToString(sum[:])
	return normNodes, digest, usedDeprecatedNodeVer, 0, "", ""
}

func (s *Server) handleUpdateDesiredNodesR67(w http.ResponseWriter, r *http.Request, historyID, versionStr string) {
	if strings.TrimSpace(historyID) == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: historyID should not be empty;")
		return
	}
	version, err := strconv.ParseInt(strings.TrimSpace(versionStr), 10, 64)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Failed to parse long parameter [version] with value [%s]", versionStr))
		return
	}
	if version <= 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: version must be positive;")
		return
	}

	qv := requestQueryValuesR67(r)
	dryRun := false
	if qv.Has("dry_run") {
		rawDry := strings.ToLower(strings.TrimSpace(qv.Get("dry_run")))
		switch rawDry {
		case "true", "1":
			dryRun = true
		case "false", "0", "":
			dryRun = false
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Failed to parse value [%s] as only [true] or [false] are allowed.", qv.Get("dry_run")))
			return
		}
	}

	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	normNodes, digest, usedDeprecatedNodeVer, errSt, errType, errReason := parseAndNormalizeDesiredNodesBodyR67(
		bodyBytes,
		s.effectiveClusterESVersionNumber(r),
	)
	if errSt != 0 {
		if errReason == errMissingDesiredNodeIdentityR67 {
			writeJSONWithRequest(w, r, http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"root_cause": []map[string]any{{"type": "x_content_parse_exception", "reason": errMissingDesiredNodeIdentityR67}},
					"type":       "x_content_parse_exception",
					"reason":     "[1:1] [desired_nodes] failed to parse field [nodes]",
					"caused_by": map[string]any{
						"type":   "x_content_parse_exception",
						"reason": "[1:1] [desired_node] failed to parse object",
						"caused_by": map[string]any{
							"type":   "illegal_argument_exception",
							"reason": errMissingDesiredNodeIdentityR67,
						},
					},
				},
				"status": http.StatusBadRequest,
			})
			return
		}
		writeESError(w, errSt, errType, errReason)
		return
	}

	if usedDeprecatedNodeVer {
		emitESDeprecationWarningRound61(w, s, r, "[version removal] Specifying node_version in desired nodes requests is deprecated.")
	}

	replacedExisting := false
	if s.internalClusterState != nil {
		s.internalClusterState.mu.Lock()
		cur := s.internalClusterState.desiredNodes
		if cur != nil && cur.HistoryID == historyID {
			if version < cur.Version {
				supersededBy := cur.Version
				s.internalClusterState.mu.Unlock()
				writeESError(w, http.StatusConflict, "version_conflict_exception",
					fmt.Sprintf("version [%d] has been superseded by version [%d] for history [%s]", version, supersededBy, historyID))
				return
			}
			if verRec, hasVer := cur.Versions[version]; hasVer || version == cur.Version {
				existingDigest := cur.Digest
				if hasVer {
					existingDigest = verRec.digest
				}
				if existingDigest != digest {
					s.internalClusterState.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Desired nodes with history [%s] and version [%d] already exists with a different definition", historyID, version))
					return
				}
				s.internalClusterState.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"replaced_existing_history_id": false,
					"dry_run":                      dryRun,
				})
				return
			}
			if !dryRun {
				cur.Version = version
				cur.Nodes = normNodes
				cur.Digest = digest
				if cur.Versions == nil {
					cur.Versions = make(map[int64]desiredNodesVersionRecordR67)
				}
				cur.Versions[version] = desiredNodesVersionRecordR67{version: version, digest: digest}
			}
		} else {
			if cur != nil {
				replacedExisting = true
			}
			if !dryRun {
				s.internalClusterState.desiredNodes = &desiredNodesStateR67{
					HistoryID: historyID,
					Version:   version,
					Nodes:     normNodes,
					Digest:    digest,
					Versions: map[int64]desiredNodesVersionRecordR67{
						version: {version: version, digest: digest},
					},
				}
			}
		}
		s.internalClusterState.mu.Unlock()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"replaced_existing_history_id": replacedExisting,
		"dry_run":                      dryRun,
	})
}

func splitCommaParamsR67(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) handlePrevalidateNodeRemovalR67(w http.ResponseWriter, r *http.Request) {
	qv := requestQueryValuesR67(r)
	names := splitCommaParamsR67(qv.Get("names"))
	ids := splitCommaParamsR67(qv.Get("ids"))
	externalIDs := splitCommaParamsR67(qv.Get("external_ids"))

	hasNames := qv.Has("names") && len(names) > 0
	hasIDs := qv.Has("ids") && len(ids) > 0
	hasExtIDs := qv.Has("external_ids") && len(externalIDs) > 0

	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body map[string]any
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "x_content_parse_exception", err.Error())
			return
		}
		if !hasNames {
			if sl, okS := extractPrevalidateStringListR67(body["names"]); okS && len(sl) > 0 {
				names = sl
				hasNames = true
			}
		}
		if !hasIDs {
			if sl, okS := extractPrevalidateStringListR67(body["ids"]); okS && len(sl) > 0 {
				ids = sl
				hasIDs = true
			}
		}
		if !hasExtIDs {
			if sl, okS := extractPrevalidateStringListR67(body["external_ids"]); okS && len(sl) > 0 {
				externalIDs = sl
				hasExtIDs = true
			}
		}
	}

	specifiedCount := 0
	if hasNames {
		specifiedCount++
	}
	if hasIDs {
		specifiedCount++
	}
	if hasExtIDs {
		specifiedCount++
	}

	if specifiedCount == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: request must contain one of the parameters 'names', 'ids', or 'external_ids';")
		return
	}
	if specifiedCount > 1 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: request must contain only one of the parameters 'names', 'ids', or 'external_ids';")
		return
	}

	var (
		resolved []map[string]any
		missing  []string
		missKind string
	)
	switch {
	case hasNames:
		missKind = "names"
		for _, n := range names {
			if n == taskLocalNodeID || n == "doris-es-proxy" {
				resolved = append(resolved, map[string]any{
					"id":   taskLocalNodeID,
					"name": taskLocalNodeID,
					"result": map[string]any{
						"is_safe": true,
						"reason":  "no_problems",
						"message": "",
					},
				})
			} else {
				missing = append(missing, n)
			}
		}
	case hasIDs:
		missKind = "IDs"
		for _, id := range ids {
			if id == taskLocalNodeID {
				resolved = append(resolved, map[string]any{
					"id":   taskLocalNodeID,
					"name": taskLocalNodeID,
					"result": map[string]any{
						"is_safe": true,
						"reason":  "no_problems",
						"message": "",
					},
				})
			} else {
				missing = append(missing, id)
			}
		}
	case hasExtIDs:
		missKind = "external IDs"
		for _, eid := range externalIDs {
			if eid == taskLocalNodeID {
				resolved = append(resolved, map[string]any{
					"id":   taskLocalNodeID,
					"name": taskLocalNodeID,
					"result": map[string]any{
						"is_safe": true,
						"reason":  "no_problems",
						"message": "",
					},
				})
			} else {
				missing = append(missing, eid)
			}
		}
	}

	if len(missing) > 0 {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("could not resolve node %s [%s]", missKind, strings.Join(missing, ",")))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"is_safe": true,
		"nodes":   resolved,
	})
}

func extractPrevalidateStringListR67(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case string:
		out := splitCommaParamsR67(v)
		return out, len(out) > 0
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out, len(out) > 0
	case []string:
		return v, len(v) > 0
	default:
		return nil, false
	}
}
