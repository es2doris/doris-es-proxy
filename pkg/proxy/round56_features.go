package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// parsePositiveESDurationMillis parses positive Elasticsearch time units (`ms`, `s`, `m`, `h`, `d`, `w`, `M`, `y`).
func parsePositiveESDurationMillis(raw string) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "-") {
		return 0, false
	}
	type unitSpec struct {
		suffix string
		mult   float64
	}
	units := []unitSpec{
		{"nanos", 1e-6},
		{"micros", 1e-3},
		{"ms", 1},
		{"ns", 1e-6},
		{"us", 1e-3},
		{"s", 1000},
		{"m", 60 * 1000},
		{"h", 3600 * 1000},
		{"d", 86400 * 1000},
		{"w", 7 * 86400 * 1000},
		{"M", 30 * 86400 * 1000},
		{"y", 365 * 86400 * 1000},
		{"Y", 365 * 86400 * 1000},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			numPart := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			if numPart == "" {
				return 0, false
			}
			val, err := strconv.ParseFloat(numPart, 64)
			if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
				return 0, false
			}
			ms := int64(math.Round(val * u.mult))
			if ms <= 0 {
				ms = 1
			}
			return ms, true
		}
	}
	return 0, false
}

func stripInternalUnderscoreKeys(m map[string]any) map[string]any {
	cp := deepCloneDocMap(m)
	for k := range cp {
		if strings.HasPrefix(k, "_") {
			delete(cp, k)
		}
	}
	return cp
}

// ============================================================================
// F2: Data Stream Lifecycle & Index Downsampling
// ============================================================================

func normalizeAndValidateDataStreamLifecycle(raw map[string]any) (map[string]any, error) {
	out := make(map[string]any)
	if raw != nil {
		out = deepCloneDocMap(raw)
	}
	if rawDR, hasDR := out["data_retention"]; hasDR && rawDR != nil {
		drStr, ok := rawDR.(string)
		if !ok {
			return nil, fmt.Errorf("[data_retention] must be a duration string")
		}
		drStr = strings.TrimSpace(drStr)
		if drStr != "" {
			if _, valid := parsePositiveESDurationMillis(drStr); !valid {
				return nil, fmt.Errorf("failed to parse setting [data_retention] with value [%s] as a time value: unit is missing or unrecognized, or value is non-positive", drStr)
			}
			out["data_retention"] = drStr
		}
	}
	if rawEn, hasEn := out["enabled"]; hasEn && rawEn != nil {
		if _, ok := rawEn.(bool); !ok {
			return nil, fmt.Errorf("[enabled] must be a boolean")
		}
	} else {
		out["enabled"] = true
	}
	if rawDS, hasDS := out["downsampling"]; hasDS && rawDS != nil {
		dsArr, ok := rawDS.([]any)
		if !ok {
			return nil, fmt.Errorf("[downsampling] must be an array of downsampling rounds")
		}
		for _, item := range dsArr {
			roundMap, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("[downsampling] entries must be objects")
			}
			if fi, hasFI := roundMap["fixed_interval"]; hasFI && fi != nil {
				fiStr, ok := fi.(string)
				if !ok {
					return nil, fmt.Errorf("[fixed_interval] must be a duration string")
				}
				if _, valid := parsePositiveESDurationMillis(fiStr); !valid {
					return nil, fmt.Errorf("invalid [fixed_interval] duration [%s]", fiStr)
				}
			}
		}
	}
	return out, nil
}

func (s *Server) extractMatchingTemplateLifecycleLocked(dsName string) map[string]any {
	bestPriority := -1
	bestName := ""
	for tplName, tpl := range s.templates {
		matched := false
		for _, pat := range tpl.EffectivePatterns() {
			if matchSimpleWildcard(pat, dsName) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		prio := 0
		if tpl.Priority != nil {
			prio = *tpl.Priority
		}
		if bestName == "" || prio > bestPriority || (prio == bestPriority && tplName < bestName) {
			bestPriority = prio
			bestName = tplName
		}
	}
	if bestName == "" {
		return nil
	}
	bestTpl := s.templates[bestName]
	var merged map[string]any
	for _, compName := range bestTpl.ComposedOf {
		if comp, ok := s.componentTemplates[compName]; ok {
			if tplPart, ok := comp["template"].(map[string]any); ok {
				if lc, ok := tplPart["lifecycle"].(map[string]any); ok && len(lc) > 0 {
					merged = deepCloneDocMap(lc)
				}
			}
		}
	}
	if lc := s.templateLifecycles[bestName]; len(lc) > 0 {
		merged = deepCloneDocMap(lc)
	}
	if len(merged) == 0 {
		return nil
	}
	if _, hasEn := merged["enabled"]; !hasEn {
		merged["enabled"] = true
	}
	return merged
}

func (s *Server) handleDataStreamLifecycle(w http.ResponseWriter, r *http.Request, rawName string) {
	_ = s.syncCatalogFromBackend(r.Context())
	name := strings.TrimSpace(rawName)
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		lcMap, err := normalizeAndValidateDataStreamLifecycle(body)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
		s.mu.Lock()
		ds, exists := s.dataStreams[name]
		if !exists || ds == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_stream ["+name+"] missing")
			return
		}
		ds["lifecycle"] = lcMap
		dsCopy := deepCloneDocMap(ds)
		s.mu.Unlock()
		s.persistDataStream(r.Context(), name, dsCopy)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		expandWildcards := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
		includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")
		s.mu.RLock()
		if expandWildcards != "none" && name != "" && name != "*" && name != "_all" {
			for _, part := range strings.Split(name, ",") {
				part = strings.TrimSpace(part)
				if part == "" || part == "_all" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
					continue
				}
				if _, exists := s.dataStreams[part]; !exists {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No matching data streams for ["+part+"]")
					return
				}
			}
		}
		var names []string
		for dsName := range s.dataStreams {
			if expandWildcards == "none" {
				for _, part := range strings.Split(name, ",") {
					if strings.TrimSpace(part) == dsName {
						names = append(names, dsName)
						break
					}
				}
				continue
			}
			if name == "" || name == "*" || name == "_all" || matchMultiWildcardWithExclusions(name, dsName) {
				names = append(names, dsName)
			}
		}
		sort.Strings(names)
		list := make([]any, 0, len(names))
		for _, dsName := range names {
			ds := s.dataStreams[dsName]
			lcMap := map[string]any{}
			if rawLC, ok := ds["lifecycle"].(map[string]any); ok && rawLC != nil {
				lcMap = deepCloneDocMap(rawLC)
			}
			entry := map[string]any{
				"name":      dsName,
				"lifecycle": lcMap,
			}
			if includeDefaults {
				if _, hasEn := lcMap["enabled"]; !hasEn {
					lcMap["enabled"] = false
				}
				effRet := "infinite"
				if dr, ok := lcMap["data_retention"].(string); ok && dr != "" {
					effRet = dr
				}
				entry["global_retention"] = map[string]any{}
				entry["effective_retention"] = effRet
			}
			list = append(list, entry)
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		resp := map[string]any{"data_streams": list}
		if includeDefaults {
			resp["global_retention"] = map[string]any{}
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodDelete:
		s.mu.Lock()
		ds, exists := s.dataStreams[name]
		if !exists || ds == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_stream ["+name+"] missing")
			return
		}
		delete(ds, "lifecycle")
		dsCopy := deepCloneDocMap(ds)
		s.mu.Unlock()
		s.persistDataStream(r.Context(), name, dsCopy)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleExplainDataLifecycle(w http.ResponseWriter, r *http.Request, rawTarget string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	target := strings.TrimSpace(rawTarget)
	allowNoIndices := true
	if r.URL.Query().Has("allow_no_indices") {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}

	s.mu.RLock()
	if target != "" && target != "*" && target != "_all" {
		for _, part := range strings.Split(target, ",") {
			part = strings.TrimSpace(part)
			if part == "" || part == "_all" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
				continue
			}
			_, inIdx := s.indices[part]
			_, inDS := s.dataStreams[part]
			inAlias := len(s.aliases[part]) > 0
			if !inIdx && !inDS && !inAlias && (!r.URL.Query().Has("allow_no_indices") || !allowNoIndices) {
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
				return
			}
		}
	}

	seen := make(map[string]bool)
	var matchedIndices []string
	addIdx := func(idx string) {
		if idx != "" && !seen[idx] {
			seen[idx] = true
			matchedIndices = append(matchedIndices, idx)
		}
	}
	for dsName, ds := range s.dataStreams {
		if target == "" || target == "*" || target == "_all" || matchMultiWildcardWithExclusions(target, dsName) {
			addedBacking := false
			if rawArr, ok := ds["indices"].([]any); ok {
				for _, item := range rawArr {
					if m, ok := item.(map[string]any); ok {
						if bIdx, ok := m["index_name"].(string); ok && bIdx != "" {
							addIdx(bIdx)
							addedBacking = true
						}
					}
				}
			}
			if !addedBacking {
				addIdx(dsName)
			}
		}
	}
	for idxName := range s.indices {
		if target == "" || target == "*" || target == "_all" || matchMultiWildcardWithExclusions(target, idxName) {
			addIdx(idxName)
		}
	}
	for aliasName, aliasTargets := range s.aliases {
		if target != "" && matchMultiWildcardWithExclusions(target, aliasName) {
			for _, t := range aliasTargets {
				addIdx(t)
			}
		}
	}
	sort.Strings(matchedIndices)

	backingToLifecycle := make(map[string]map[string]any)
	for dsName, ds := range s.dataStreams {
		lc, _ := ds["lifecycle"].(map[string]any)
		if len(lc) == 0 {
			continue
		}
		backingToLifecycle[dsName] = deepCloneDocMap(lc)
		if rawArr, ok := ds["indices"].([]any); ok {
			for _, item := range rawArr {
				if m, ok := item.(map[string]any); ok {
					if bIdx, ok := m["index_name"].(string); ok && bIdx != "" {
						backingToLifecycle[bIdx] = deepCloneDocMap(lc)
					}
				}
			}
		}
	}

	indicesOut := make(map[string]any, len(matchedIndices))
	for _, idx := range matchedIndices {
		lcObj := map[string]any{}
		managed := false
		if lc := backingToLifecycle[idx]; len(lc) > 0 {
			lcObj = lc
			managed = true
			if en, ok := lc["enabled"].(bool); ok {
				managed = en
			}
		}
		indicesOut[idx] = map[string]any{
			"index":                     idx,
			"managed_by_lifecycle":      managed,
			"lifecycle":                 lcObj,
			"time_since_index_creation": "0ms",
		}
	}
	s.mu.RUnlock()

	if len(matchedIndices) == 0 && !allowNoIndices {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+target+"]")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"indices": indicesOut})
}

func extractDownsampleFixedInterval(body map[string]any) string {
	if body == nil {
		return ""
	}
	if fi, ok := body["fixed_interval"].(string); ok && strings.TrimSpace(fi) != "" {
		return strings.TrimSpace(fi)
	}
	if settings, ok := body["settings"].(map[string]any); ok {
		for _, k := range []string{"index.downsample.fixed_interval", "downsample.fixed_interval"} {
			if fi, ok := settings[k].(string); ok && strings.TrimSpace(fi) != "" {
				return strings.TrimSpace(fi)
			}
		}
		if idxMap, ok := settings["index"].(map[string]any); ok {
			if fi, ok := idxMap["downsample.fixed_interval"].(string); ok && strings.TrimSpace(fi) != "" {
				return strings.TrimSpace(fi)
			}
			if dsMap, ok := idxMap["downsample"].(map[string]any); ok {
				if fi, ok := dsMap["fixed_interval"].(string); ok && strings.TrimSpace(fi) != "" {
					return strings.TrimSpace(fi)
				}
			}
		}
		if dsMap, ok := settings["downsample"].(map[string]any); ok {
			if fi, ok := dsMap["fixed_interval"].(string); ok && strings.TrimSpace(fi) != "" {
				return strings.TrimSpace(fi)
			}
		}
	}
	return ""
}

func (s *Server) handleDownsampleIndex(w http.ResponseWriter, r *http.Request, rawSrcIndex, rawTargetIndex string) {
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
	if fixedInterval == "" || !validInterval {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "downsample [fixed_interval] must be a valid positive time duration")
		return
	}

	_ = s.syncCatalogFromBackend(r.Context())
	srcIndex := s.resolveIndexName(strings.TrimSpace(rawSrcIndex))
	s.mu.RLock()
	srcSchema := s.indices[srcIndex]
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

	compiled := schema.CompileIndexSchema(s.dorisDB, targetIndex, srcSchema.RawMapping)
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
	if s.indexCustomSettings[targetIndex] == nil {
		s.indexCustomSettings[targetIndex] = make(map[string]any)
	}
	s.indexCustomSettings[targetIndex]["downsample.source.name"] = srcIndex
	s.indexCustomSettings[targetIndex]["downsample.fixed_interval"] = fixedInterval
	s.indexCustomSettings[targetIndex]["index.downsample.source.name"] = srcIndex
	s.indexCustomSettings[targetIndex]["index.downsample.fixed_interval"] = fixedInterval
	s.mu.Unlock()
	s.persistIndex(r.Context(), targetIndex, compiled)

	_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
	opts := s.transpileOpts
	opts.MaxResultWindow = 0
	tr := transpiler.NewTranspiler(srcSchema, opts)
	batchSize := 1000
	var searchAfter []any
	seenBuckets := make(map[string]bool)
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
		var buf bytes.Buffer
		for _, h := range hits {
			srcBytes := h.Source
			var docMap map[string]any
			if json.Unmarshal(h.Source, &docMap) == nil && docMap != nil && intervalMS > 0 {
				if rawTS, hasTS := docMap["@timestamp"]; hasTS && rawTS != nil {
					if tsMS, okTS := parseDownsampleTimestampMillis(rawTS); okTS {
						bucketMS := (tsMS / intervalMS) * intervalMS
						bucketISO := time.UnixMilli(bucketMS).UTC().Format(time.RFC3339)
						var dimParts []string
						for k, v := range docMap {
							if k == "@timestamp" {
								continue
							}
							switch v.(type) {
							case string, bool:
								dimParts = append(dimParts, fmt.Sprintf("%s=%v", k, v))
							}
						}
						sort.Strings(dimParts)
						bucketKey := fmt.Sprintf("%d|%s", bucketMS, strings.Join(dimParts, "|"))
						if seenBuckets[bucketKey] {
							continue
						}
						seenBuckets[bucketKey] = true
						docMap["@timestamp"] = bucketISO
						if b, mErr := json.Marshal(docMap); mErr == nil {
							srcBytes = b
						}
					}
				}
			}
			shredded, sErr := schema.ShredDocument(compiled, h.ID, h.Version, false, srcBytes)
			if sErr != nil {
				continue
			}
			buf.Write(shredded)
			buf.WriteByte('\n')
		}
		if buf.Len() > 0 {
			_ = s.streamLoad(r.Context(), compiled.DorisTable, buf.Bytes(), true)
		}
		searchAfter = []any{hits[len(hits)-1].ID}
		if len(hits) < batchSize {
			break
		}
	}
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"index":               targetIndex,
	})
}

func parseDownsampleTimestampMillis(raw any) (int64, bool) {
	switch v := raw.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		return int64(v), true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return iv, true
		}
	case string:
		s := strings.TrimSpace(v)
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC().UnixMilli(), true
			}
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
	}
	return 0, false
}

// ============================================================================
// F8: Ingest GeoIP Database CRUD & ILM Migrate to Data Tiers
// ============================================================================

func (s *Server) handleIngestGeoIPDatabase(w http.ResponseWriter, r *http.Request, segs []string) {
	id := ""
	if len(segs) >= 4 {
		id = strings.TrimSpace(segs[3])
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		dbFile, _ := body["database_file"].(string)
		if strings.TrimSpace(dbFile) == "" {
			if cfgMap, ok := body["config"].(map[string]any); ok {
				if mmMap, ok := cfgMap["max_mind"].(map[string]any); ok {
					dbFile, _ = mmMap["database_file"].(string)
				}
			}
		}
		nameStr, _ := body["name"].(string)
		if strings.TrimSpace(dbFile) == "" && strings.TrimSpace(nameStr) != "" {
			dbFile = strings.TrimSpace(nameStr) + ".mmdb"
		}
		if strings.TrimSpace(dbFile) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[database_file] is required")
			return
		}
		sum := sha256.Sum256([]byte(id + ":" + dbFile))
		shaHex := hex.EncodeToString(sum[:])
		if customSha, ok := body["sha256"].(string); ok && strings.TrimSpace(customSha) != "" {
			shaHex = strings.TrimSpace(customSha)
		}
		entry := map[string]any{
			"id":                   id,
			"name":                 nameStr,
			"database_file":        strings.TrimSpace(dbFile),
			"sha256":               shaHex,
			"modified_date_millis": time.Now().UTC().UnixMilli(),
		}
		if entry["name"] == "" {
			entry["name"] = id
		}
		s.mu.Lock()
		if s.geoipDatabases == nil {
			s.geoipDatabases = make(map[string]map[string]any)
		}
		s.geoipDatabases[id] = entry
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet, http.MethodHead:
		s.mu.RLock()
		if id != "" && id != "*" && id != "_all" {
			for _, part := range strings.Split(id, ",") {
				part = strings.TrimSpace(part)
				if part == "" || part == "_all" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
					continue
				}
				if _, exists := s.geoipDatabases[part]; !exists {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "geoip database ["+part+"] does not exist")
					return
				}
			}
		}
		var ids []string
		for k := range s.geoipDatabases {
			if id == "" || id == "*" || id == "_all" || matchMultiWildcardWithExclusions(id, k) {
				ids = append(ids, k)
			}
		}
		sort.Strings(ids)
		list := make([]any, 0, len(ids))
		for _, k := range ids {
			list = append(list, deepCloneDocMap(s.geoipDatabases[k]))
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"databases": list})

	case http.MethodDelete:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		s.mu.Lock()
		if _, exists := s.geoipDatabases[id]; !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "geoip database ["+id+"] does not exist")
			return
		}
		delete(s.geoipDatabases, id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleILMMigrateToDataTiers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	dryRun := isTruthyBoolQueryParam(r, "dry_run")
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":                  true,
		"dry_run":                       dryRun,
		"migrated_ilm_policies":         []any{},
		"migrated_indices":              []any{},
		"migrated_legacy_templates":     []any{},
		"migrated_composable_templates": []any{},
		"migrated_component_templates":  []any{},
	})
}

// ============================================================================
// F3: ML Data Frame Analytics & Evaluation
// ============================================================================

func extractMLSourceIndex(srcMap map[string]any) string {
	if srcMap == nil {
		return ""
	}
	switch v := srcMap["index"].(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var parts []string
		for _, el := range v {
			if s, ok := el.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func extractMLAnalysisType(analysis map[string]any) string {
	for _, t := range []string{"outlier_detection", "regression", "classification"} {
		if _, ok := analysis[t].(map[string]any); ok {
			return t
		}
	}
	return ""
}

func enrichMLDataFrameSource(src map[string]any, analysisType, resultsField string) map[string]any {
	cp := deepCloneDocMap(src)
	if resultsField == "" {
		resultsField = "ml"
	}
	switch analysisType {
	case "outlier_detection":
		cp[resultsField] = map[string]any{"outlier_score": 0.1}
	case "classification":
		cp[resultsField] = map[string]any{"predicted_value": "class_a", "prediction_probability": 0.95}
	default:
		cp[resultsField] = map[string]any{"predicted_value": 1.0}
	}
	return cp
}

func (s *Server) handleMLDataFrame(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 3 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	if len(segs) == 3 && segs[2] == "_evaluate" {
		s.handleMLDataFrameEvaluate(w, r)
		return
	}
	if segs[2] != "analytics" {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}

	// Static or ID-scoped _stats / _preview / _explain
	if (len(segs) == 4 && segs[3] == "_stats") || (len(segs) == 5 && segs[4] == "_stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		targetID := "_all"
		if len(segs) == 5 {
			targetID = strings.TrimSpace(segs[3])
		}
		allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
		s.mu.RLock()
		if targetID != "_all" && targetID != "*" && !allowNoMatch {
			for _, part := range strings.Split(targetID, ",") {
				part = strings.TrimSpace(part)
				if part == "" || part == "_all" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
					continue
				}
				if _, exists := s.mlDataFrameAnalytics[part]; !exists {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+part+"]")
					return
				}
			}
		}
		var ids []string
		for id := range s.mlDataFrameAnalytics {
			if targetID == "_all" || targetID == "*" || matchMultiWildcardWithExclusions(targetID, id) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		list := make([]any, 0, len(ids))
		for _, id := range ids {
			job := s.mlDataFrameAnalytics[id]
			state, _ := job["_state"].(string)
			if state == "" {
				state = "stopped"
			}
			docsCount, _ := toInt64(job["_docs_count"])
			list = append(list, map[string]any{
				"id":       id,
				"state":    state,
				"progress": []any{map[string]any{"phase": "reindexing", "progress_percent": 100}},
				"data_counts": map[string]any{
					"training_docs_count": docsCount,
					"test_docs_count":     0,
					"skipped_docs_count":  0,
				},
				"memory_usage": map[string]any{
					"peak_usage_bytes": 0,
					"status":           "ok",
				},
			})
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":                len(list),
			"data_frame_analytics": list,
		})
		return
	}

	if (len(segs) == 4 && segs[3] == "_preview") || (len(segs) == 5 && segs[4] == "_preview") {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		var cfg map[string]any
		if len(segs) == 5 {
			id := strings.TrimSpace(segs[3])
			s.mu.RLock()
			job, exists := s.mlDataFrameAnalytics[id]
			if exists {
				cfg = deepCloneDocMap(job)
			}
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
				return
			}
		} else {
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			if subCfg, ok := body["config"].(map[string]any); ok {
				cfg = subCfg
			} else {
				cfg = body
			}
		}
		srcMap, _ := cfg["source"].(map[string]any)
		destMap, _ := cfg["dest"].(map[string]any)
		analysisMap, _ := cfg["analysis"].(map[string]any)
		srcIdx := extractMLSourceIndex(srcMap)
		analysisType := extractMLAnalysisType(analysisMap)
		resultsField := "ml"
		if destMap != nil {
			if rf, ok := destMap["results_field"].(string); ok && strings.TrimSpace(rf) != "" {
				resultsField = strings.TrimSpace(rf)
			}
		}
		previewDocs := []any{}
		if srcIdx != "" {
			sz := 10
			if resp, _, errType, _ := s.executeSearchRequest(r.Context(), srcIdx, &esast.SearchRequest{Size: &sz}); errType == "" && resp != nil {
				for _, hitItem := range extractSearchResponseHitItems(resp) {
					if srcDoc := extractHitSourceMap(hitItem); srcDoc != nil {
						previewDocs = append(previewDocs, enrichMLDataFrameSource(srcDoc, analysisType, resultsField))
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"preview": previewDocs})
		return
	}

	if (len(segs) == 4 && segs[3] == "_explain") || (len(segs) == 5 && segs[4] == "_explain") {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		if len(segs) == 5 {
			id := strings.TrimSpace(segs[3])
			s.mu.RLock()
			_, exists := s.mlDataFrameAnalytics[id]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
				return
			}
		} else {
			if _, ok := parseJSONBody(w, r); !ok {
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"index_selection_explanation": map[string]any{},
			"field_selection":             []any{},
			"memory_estimation": map[string]any{
				"expected_memory_without_disk": "1mb",
				"expected_memory_with_disk":    "1mb",
			},
		})
		return
	}

	if len(segs) == 5 {
		id := strings.TrimSpace(segs[3])
		action := strings.TrimSpace(segs[4])
		switch action {
		case "_update":
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			job, exists := s.mlDataFrameAnalytics[id]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
				return
			}
			for _, k := range []string{"description", "model_memory_limit", "max_num_threads", "dest", "allow_lazy_start"} {
				if v, has := body[k]; has {
					job[k] = v
				}
			}
			clean := stripInternalUnderscoreKeys(job)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, clean)
			return

		case "_start":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			s.mu.RLock()
			job, exists := s.mlDataFrameAnalytics[id]
			var cfg map[string]any
			if exists && job != nil {
				cfg = deepCloneDocMap(job)
			}
			s.mu.RUnlock()
			if !exists || cfg == nil {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
				return
			}
			srcMap, _ := cfg["source"].(map[string]any)
			destMap, _ := cfg["dest"].(map[string]any)
			analysisMap, _ := cfg["analysis"].(map[string]any)
			srcIdx := extractMLSourceIndex(srcMap)
			destIdx, _ := destMap["index"].(string)
			destIdx = strings.TrimSpace(destIdx)
			resultsField := "ml"
			if rf, ok := destMap["results_field"].(string); ok && strings.TrimSpace(rf) != "" {
				resultsField = strings.TrimSpace(rf)
			}
			analysisType := extractMLAnalysisType(analysisMap)
			copiedCount := 0
			if destIdx != "" {
				_ = s.ensureIndexSchema(r.Context(), destIdx)
				s.mu.RLock()
				destSchema := s.indices[destIdx]
				s.mu.RUnlock()
				if srcIdx != "" && destSchema != nil {
					sz := 1000
					if resp, _, errType, _ := s.executeSearchRequest(r.Context(), srcIdx, &esast.SearchRequest{Size: &sz}); errType == "" && resp != nil {
						var buf bytes.Buffer
						for _, hitItem := range extractSearchResponseHitItems(resp) {
							srcDoc := extractHitSourceMap(hitItem)
							docID, _ := hitItem["_id"].(string)
							if srcDoc != nil {
								enriched := enrichMLDataFrameSource(srcDoc, analysisType, resultsField)
								if rawEn, mErr := json.Marshal(enriched); mErr == nil {
									if shredded, sErr := schema.ShredDocument(destSchema, docID, s.allocVersion(0), false, rawEn); sErr == nil {
										buf.Write(shredded)
										buf.WriteByte('\n')
										copiedCount++
									}
								}
							}
						}
						if buf.Len() > 0 {
							_ = s.streamLoad(r.Context(), destSchema.DorisTable, buf.Bytes(), true)
						}
					}
				}
			}
			s.mu.Lock()
			if curJob := s.mlDataFrameAnalytics[id]; curJob != nil {
				curJob["_state"] = "started"
				curJob["_docs_count"] = copiedCount
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return

		case "_stop":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
			s.mu.Lock()
			matched := 0
			for k, job := range s.mlDataFrameAnalytics {
				if id == "_all" || id == "*" || matchMultiWildcardWithExclusions(id, k) {
					job["_state"] = "stopped"
					matched++
				}
			}
			s.mu.Unlock()
			if matched == 0 && !allowNoMatch && !strings.ContainsAny(id, "*?") && id != "_all" {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}

	id := ""
	if len(segs) >= 4 {
		id = strings.TrimSpace(segs[3])
	}
	switch r.Method {
	case http.MethodPut:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		srcMap, _ := body["source"].(map[string]any)
		destMap, _ := body["dest"].(map[string]any)
		analysisMap, _ := body["analysis"].(map[string]any)
		if extractMLSourceIndex(srcMap) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[source.index] is required")
			return
		}
		if destMap == nil || strings.TrimSpace(fmt.Sprintf("%v", destMap["index"])) == "" || destMap["index"] == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[dest.index] is required")
			return
		}
		if extractMLAnalysisType(analysisMap) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[analysis] must specify one of [outlier_detection, regression, classification]")
			return
		}
		s.mu.Lock()
		if s.mlDataFrameAnalytics == nil {
			s.mlDataFrameAnalytics = make(map[string]map[string]any)
		}
		if _, exists := s.mlDataFrameAnalytics[id]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "data_frame_analytics job ["+id+"] already exists")
			return
		}
		entry := deepCloneDocMap(body)
		entry["id"] = id
		if _, hasMem := entry["model_memory_limit"]; !hasMem {
			entry["model_memory_limit"] = "1gb"
		}
		entry["create_time"] = time.Now().UTC().UnixMilli()
		entry["version"] = "8.15.0"
		entry["_state"] = "stopped"
		entry["_docs_count"] = 0
		s.mlDataFrameAnalytics[id] = entry
		clean := stripInternalUnderscoreKeys(entry)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, clean)

	case http.MethodGet, http.MethodHead:
		allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
		s.mu.RLock()
		if id != "" && id != "_all" && id != "*" && !allowNoMatch {
			for _, part := range strings.Split(id, ",") {
				part = strings.TrimSpace(part)
				if part == "" || part == "_all" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") {
					continue
				}
				if _, exists := s.mlDataFrameAnalytics[part]; !exists {
					s.mu.RUnlock()
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+part+"]")
					return
				}
			}
		}
		var ids []string
		for k := range s.mlDataFrameAnalytics {
			if id == "" || id == "_all" || id == "*" || matchMultiWildcardWithExclusions(id, k) {
				ids = append(ids, k)
			}
		}
		sort.Strings(ids)
		list := make([]any, 0, len(ids))
		for _, k := range ids {
			list = append(list, stripInternalUnderscoreKeys(s.mlDataFrameAnalytics[k]))
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":                len(list),
			"data_frame_analytics": list,
		})

	case http.MethodDelete:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
		force := isTruthyBoolQueryParam(r, "force")
		s.mu.Lock()
		job, exists := s.mlDataFrameAnalytics[id]
		if !exists || job == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown data_frame_analytics job ["+id+"]")
			return
		}
		if st, _ := job["_state"].(string); st == "started" && !force {
			s.mu.Unlock()
			writeESError(w, http.StatusConflict, "status_exception", "Cannot delete data_frame_analytics job ["+id+"] while started; stop first or use force=true")
			return
		}
		delete(s.mlDataFrameAnalytics, id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}

func (s *Server) handleMLDataFrameEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	idxName, _ := body["index"].(string)
	idxName = strings.TrimSpace(idxName)
	if idxName == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[index] is required")
		return
	}
	evalMap, _ := body["evaluation"].(map[string]any)
	if evalMap == nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[evaluation] is required")
		return
	}
	evalType := ""
	var evalCfg map[string]any
	for _, t := range []string{"classification", "outlier_detection", "regression", "binary_soft_classification"} {
		if cfg, ok := evalMap[t].(map[string]any); ok {
			evalType = t
			evalCfg = cfg
			break
		}
	}
	if evalType == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[evaluation] must contain one of [classification, outlier_detection, regression, binary_soft_classification]")
		return
	}

	actualField, _ := evalCfg["actual_field"].(string)
	if actualField == "" {
		actualField = "actual"
	}
	predictedField, _ := evalCfg["predicted_field"].(string)
	if predictedField == "" {
		if pp, ok := evalCfg["predicted_probability_field"].(string); ok && pp != "" {
			predictedField = pp
		} else {
			predictedField = "predicted"
		}
	}

	var docs []map[string]any
	sz := 1000
	if resp, _, errType, _ := s.executeSearchRequest(r.Context(), idxName, &esast.SearchRequest{Size: &sz}); errType == "" && resp != nil {
		for _, hitItem := range extractSearchResponseHitItems(resp) {
			if d := extractHitSourceMap(hitItem); d != nil {
				docs = append(docs, d)
			}
		}
	}

	switch evalType {
	case "classification":
		acc := 1.0
		if len(docs) > 0 {
			correct := 0
			total := 0
			for _, d := range docs {
				av, okA := getIngestPath(d, actualField)
				pv, okP := getIngestPath(d, predictedField)
				if okA && okP && av != nil && pv != nil {
					total++
					if fmt.Sprintf("%v", av) == fmt.Sprintf("%v", pv) {
						correct++
					}
				}
			}
			if total > 0 {
				acc = float64(correct) / float64(total)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"classification": map[string]any{
				"accuracy":                    acc,
				"multiclass_confusion_matrix": []any{},
				"precision":                   map[string]any{"avg": acc},
				"recall":                      map[string]any{"avg": acc},
				"f1_score":                    map[string]any{"avg": acc},
			},
		})

	case "outlier_detection", "binary_soft_classification":
		tp, fp, tn, fn := 0, 0, 0, 0
		for _, d := range docs {
			av, okA := getIngestPath(d, actualField)
			pv, okP := getIngestPath(d, predictedField)
			if !okA || !okP || av == nil || pv == nil {
				continue
			}
			actualPos := false
			switch v := av.(type) {
			case bool:
				actualPos = v
			default:
				if fv, okF := toFloat64(v); okF {
					actualPos = fv > 0
				}
			}
			predScore, _ := toFloat64(pv)
			predPos := predScore >= 0.5
			switch {
			case actualPos && predPos:
				tp++
			case !actualPos && predPos:
				fp++
			case !actualPos && !predPos:
				tn++
			default:
				fn++
			}
		}
		prec := 1.0
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		rec := 1.0
		if tp+fn > 0 {
			rec = float64(tp) / float64(tp+fn)
		}
		metrics := map[string]any{
			"confusion_matrix": map[string]any{
				"0.5": map[string]any{"tp": tp, "fp": fp, "tn": tn, "fn": fn},
			},
			"roc_auc": 1.0,
		}
		if evalType == "outlier_detection" {
			metrics["precision"] = map[string]any{"0.5": prec}
			metrics["recall"] = map[string]any{"0.5": rec}
		}
		writeJSON(w, http.StatusOK, map[string]any{evalType: metrics})

	case "regression":
		mse := 0.0
		r2 := 1.0
		var pairs [][2]float64
		for _, d := range docs {
			av, okA := getIngestPath(d, actualField)
			pv, okP := getIngestPath(d, predictedField)
			if okA && okP {
				af, okAF := toFloat64(av)
				pf, okPF := toFloat64(pv)
				if okAF && okPF {
					pairs = append(pairs, [2]float64{af, pf})
				}
			}
		}
		if len(pairs) > 0 {
			sumSq := 0.0
			sumAct := 0.0
			for _, p := range pairs {
				diff := p[0] - p[1]
				sumSq += diff * diff
				sumAct += p[0]
			}
			mse = sumSq / float64(len(pairs))
			meanAct := sumAct / float64(len(pairs))
			ssTot := 0.0
			for _, p := range pairs {
				dAct := p[0] - meanAct
				ssTot += dAct * dAct
			}
			if ssTot > 0 {
				r2 = 1.0 - (sumSq / ssTot)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"regression": map[string]any{
				"mse":       mse,
				"r_squared": r2,
				"huber":     0.0,
				"msle":      0.0,
			},
		})
	}
}

// ============================================================================
// F4: ML Trained Model Deployments, Inference, Aliases, Definition & Vocabulary
// ============================================================================

func (s *Server) resolveTrainedModelLocked(idOrAlias string) (string, map[string]any, bool) {
	if m, ok := s.mlTrainedModels[idOrAlias]; ok && m != nil {
		return idOrAlias, m, true
	}
	if realID, ok := s.mlModelAliases[idOrAlias]; ok && realID != "" {
		if m, ok2 := s.mlTrainedModels[realID]; ok2 && m != nil {
			return realID, m, true
		}
	}
	return "", nil, false
}

func (s *Server) formatTrainedModelConfigLocked(modelID string, m map[string]any) map[string]any {
	cp := stripInternalUnderscoreKeys(m)
	aliases := []string{}
	for alias, target := range s.mlModelAliases {
		if target == modelID {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	cp["model_aliases"] = aliases
	return cp
}

func (s *Server) findDeploymentForModelLocked(target string) (string, map[string]any) {
	if dep, ok := s.mlModelDeployments[target]; ok && dep != nil {
		return target, dep
	}
	realID := target
	if mapped, ok := s.mlModelAliases[target]; ok && mapped != "" {
		realID = mapped
	}
	for depID, dep := range s.mlModelDeployments {
		if mid, _ := dep["model_id"].(string); mid == realID {
			return depID, dep
		}
	}
	return "", nil
}

func buildDeploymentAssignment(modelID, depID string, allocs, threads, queueCap int64, priority string, startMS int64) map[string]any {
	return map[string]any{
		"task_parameters": map[string]any{
			"model_id":               modelID,
			"deployment_id":          depID,
			"model_bytes":            int64(1024),
			"threads_per_allocation": threads,
			"number_of_allocations":  allocs,
			"queue_capacity":         queueCap,
			"priority":               priority,
		},
		"routing_table": map[string]any{
			"local-node-1": map[string]any{
				"current_allocations": allocs,
				"target_allocations":  allocs,
				"routing_state":       "started",
				"reason":              "",
			},
		},
		"assignment_state":         "started",
		"start_time":               startMS,
		"max_assigned_allocations": allocs,
	}
}

func (s *Server) handleMLTrainedModelSubRoute(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 4 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	rawTarget := strings.TrimSpace(segs[2])

	// POST /_ml/trained_models/{model_id}/deployment/_start|_stop|_update|_infer
	if len(segs) == 5 && segs[3] == "deployment" {
		subAct := strings.TrimSpace(segs[4])
		switch subAct {
		case "_start":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			resolvedModelID, _, exists := s.resolveTrainedModelLocked(rawTarget)
			if !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
				return
			}
			depID := strings.TrimSpace(r.URL.Query().Get("deployment_id"))
			if depID == "" {
				if bd, ok := body["deployment_id"].(string); ok && strings.TrimSpace(bd) != "" {
					depID = strings.TrimSpace(bd)
				} else {
					depID = resolvedModelID
				}
			}
			if s.mlModelDeployments == nil {
				s.mlModelDeployments = make(map[string]map[string]any)
			}
			if _, depExists := s.mlModelDeployments[depID]; depExists {
				s.mu.Unlock()
				writeESError(w, http.StatusConflict, "resource_already_exists_exception", "deployment ["+depID+"] is already started")
				return
			}
			allocs := int64(1)
			if q := strings.TrimSpace(r.URL.Query().Get("number_of_allocations")); q != "" {
				if iv, err := strconv.ParseInt(q, 10, 64); err == nil && iv > 0 {
					allocs = iv
				}
			} else if iv, okI := toInt64(body["number_of_allocations"]); okI && iv > 0 {
				allocs = iv
			}
			threads := int64(1)
			if q := strings.TrimSpace(r.URL.Query().Get("threads_per_allocation")); q != "" {
				if iv, err := strconv.ParseInt(q, 10, 64); err == nil && iv > 0 {
					threads = iv
				}
			} else if iv, okI := toInt64(body["threads_per_allocation"]); okI && iv > 0 {
				threads = iv
			}
			queueCap := int64(1024)
			if q := strings.TrimSpace(r.URL.Query().Get("queue_capacity")); q != "" {
				if iv, err := strconv.ParseInt(q, 10, 64); err == nil && iv > 0 {
					queueCap = iv
				}
			} else if iv, okI := toInt64(body["queue_capacity"]); okI && iv > 0 {
				queueCap = iv
			}
			priority := strings.TrimSpace(r.URL.Query().Get("priority"))
			if priority == "" {
				if bp, ok := body["priority"].(string); ok && strings.TrimSpace(bp) != "" {
					priority = strings.TrimSpace(bp)
				} else {
					priority = "normal"
				}
			}
			nowMS := time.Now().UTC().UnixMilli()
			assignment := buildDeploymentAssignment(resolvedModelID, depID, allocs, threads, queueCap, priority, nowMS)
			s.mlModelDeployments[depID] = map[string]any{
				"deployment_id":          depID,
				"model_id":               resolvedModelID,
				"number_of_allocations":  allocs,
				"threads_per_allocation": threads,
				"queue_capacity":         queueCap,
				"priority":               priority,
				"start_time":             nowMS,
				"inference_count":        int64(0),
				"assignment":             assignment,
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"assignment": assignment})
			return

		case "_stop":
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
			if _, ok := parseJSONBody(w, r); !ok {
				return
			}
			s.mu.Lock()
			resolvedID := rawTarget
			if mapped, ok := s.mlModelAliases[rawTarget]; ok && mapped != "" {
				resolvedID = mapped
			}
			var toRemove []string
			for depID, dep := range s.mlModelDeployments {
				mid, _ := dep["model_id"].(string)
				if rawTarget == "_all" || rawTarget == "*" || depID == rawTarget || mid == resolvedID || matchMultiWildcardWithExclusions(rawTarget, depID) {
					toRemove = append(toRemove, depID)
				}
			}
			for _, depID := range toRemove {
				delete(s.mlModelDeployments, depID)
			}
			s.mu.Unlock()
			if len(toRemove) == 0 && !allowNoMatch {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No deployment matched ["+rawTarget+"]")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
			return

		case "_update":
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return
			}
			s.mu.Lock()
			depID, dep := s.findDeploymentForModelLocked(rawTarget)
			if dep == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No deployment matched ["+rawTarget+"]")
				return
			}
			allocs, _ := toInt64(dep["number_of_allocations"])
			if iv, okI := toInt64(body["number_of_allocations"]); okI && iv > 0 {
				allocs = iv
				dep["number_of_allocations"] = allocs
			}
			priority, _ := dep["priority"].(string)
			if pStr, okP := body["priority"].(string); okP && strings.TrimSpace(pStr) != "" {
				priority = strings.TrimSpace(pStr)
				dep["priority"] = priority
			}
			threads, _ := toInt64(dep["threads_per_allocation"])
			queueCap, _ := toInt64(dep["queue_capacity"])
			startMS, _ := toInt64(dep["start_time"])
			modelID, _ := dep["model_id"].(string)
			assignment := buildDeploymentAssignment(modelID, depID, allocs, threads, queueCap, priority, startMS)
			dep["assignment"] = assignment
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"assignment": assignment})
			return

		case "_infer":
			s.handleMLTrainedModelInfer(w, r, rawTarget, true)
			return
		}
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}

	// POST /_ml/trained_models/{model_id}/_infer
	if len(segs) == 4 && segs[3] == "_infer" {
		s.handleMLTrainedModelInfer(w, r, rawTarget, false)
		return
	}

	// PUT/DELETE /_ml/trained_models/{model_id}/model_aliases/{model_alias}
	if len(segs) == 5 && segs[3] == "model_aliases" {
		alias := strings.TrimSpace(segs[4])
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			reassign := isTruthyBoolQueryParam(r, "reassign")
			s.mu.Lock()
			if _, exists := s.mlTrainedModels[rawTarget]; !exists {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
				return
			}
			if s.mlModelAliases == nil {
				s.mlModelAliases = make(map[string]string)
			}
			if curTarget, has := s.mlModelAliases[alias]; has && curTarget != rawTarget && !reassign {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("model_alias [%s] already refers to trained model [%s]; set reassign=true to move it", alias, curTarget))
				return
			}
			s.mlModelAliases[alias] = rawTarget
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"acknowledged": true,
				"model_id":     rawTarget,
				"model_alias":  alias,
			})
			return

		case http.MethodDelete:
			s.mu.Lock()
			curTarget, has := s.mlModelAliases[alias]
			if !has || curTarget != rawTarget {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception",
					fmt.Sprintf("model_alias [%s] is not associated with trained model [%s]", alias, rawTarget))
				return
			}
			delete(s.mlModelAliases, alias)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
	}

	// PUT /_ml/trained_models/{model_id}/definition/{part}
	if len(segs) == 5 && segs[3] == "definition" {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		part := strings.TrimSpace(segs[4])
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		_, model, exists := s.resolveTrainedModelLocked(rawTarget)
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
			return
		}
		parts, _ := model["_definition_parts"].(map[string]any)
		if parts == nil {
			parts = make(map[string]any)
		}
		parts[part] = deepCloneDocMap(body)
		model["_definition_parts"] = parts
		model["fully_defined"] = true
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}

	// PUT/GET /_ml/trained_models/{model_id}/vocabulary
	if len(segs) == 4 && segs[3] == "vocabulary" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			s.mu.RLock()
			_, model, exists := s.resolveTrainedModelLocked(rawTarget)
			var vocab []any
			if exists && model != nil {
				if v, okV := model["_vocabulary"].([]any); okV {
					vocab = append([]any(nil), v...)
				} else {
					vocab = []any{}
				}
			}
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"vocabulary": vocab})
			return
		}
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		vocab, hasVocab := body["vocabulary"].([]any)
		if !hasVocab {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[vocabulary] array is required")
			return
		}
		s.mu.Lock()
		_, model, exists := s.resolveTrainedModelLocked(rawTarget)
		if !exists {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
			return
		}
		model["_vocabulary"] = vocab
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}

	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
}

func (s *Server) handleMLTrainedModelInfer(w http.ResponseWriter, r *http.Request, rawTarget string, requireDeployment bool) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	docsArr, okDocs := body["docs"].([]any)
	if !okDocs || len(docsArr) == 0 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[docs] must be a non-empty array")
		return
	}

	s.mu.Lock()
	resolvedID, model, exists := s.resolveTrainedModelLocked(rawTarget)
	_, dep := s.findDeploymentForModelLocked(rawTarget)
	if !exists && requireDeployment && dep != nil {
		if mid, okM := dep["model_id"].(string); okM && mid != "" {
			resolvedID, model, exists = s.resolveTrainedModelLocked(mid)
		}
	}
	if !exists {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No trained models matched ["+rawTarget+"]")
		return
	}
	if dep == nil {
		_, dep = s.findDeploymentForModelLocked(resolvedID)
	}
	if requireDeployment && dep == nil {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", "No deployment matched ["+rawTarget+"]")
		return
	}
	if dep != nil {
		curCnt, _ := toInt64(dep["inference_count"])
		dep["inference_count"] = curCnt + int64(len(docsArr))
	}
	infCfg, _ := model["inference_config"].(map[string]any)
	s.mu.Unlock()

	results := make([]any, 0, len(docsArr))
	for _, dAny := range docsArr {
		var predVal any = "true"
		if infCfg != nil {
			if _, okTE := infCfg["text_embedding"]; okTE {
				predVal = []float64{0.1, 0.2, 0.3}
			} else if _, okReg := infCfg["regression"]; okReg {
				predVal = 1.0
			} else if _, okPT := infCfg["pass_through"]; okPT {
				if dMap, okM := dAny.(map[string]any); okM {
					for _, v := range dMap {
						predVal = v
						break
					}
				}
			}
		}
		results = append(results, map[string]any{
			"predicted_value":        predVal,
			"prediction_probability": 0.95,
			"prediction_score":       0.95,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"inference_results": results})
}

// ============================================================================
// F5: ML Anomaly Detection Sub-Actions
// ============================================================================

func (s *Server) handleMLAnomalySubRoutes(w http.ResponseWriter, r *http.Request, segs []string) bool {
	// Static routes before job-ID lookup
	if len(segs) == 3 && segs[2] == "_validate" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return true
		}
		ac, _ := body["analysis_config"].(map[string]any)
		dets, _ := ac["detectors"].([]any)
		if ac == nil || len(dets) == 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[analysis_config.detectors] must be a non-empty list")
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return true
	}
	if len(segs) == 4 && segs[2] == "_validate" && segs[3] == "detector" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return true
		}
		fn, _ := body["function"].(string)
		if strings.TrimSpace(fn) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "detector [function] is required")
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return true
	}
	if len(segs) == 3 && segs[2] == "_estimate_model_memory" {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		if _, ok := parseJSONBody(w, r); !ok {
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"model_memory_estimate": "12mb"})
		return true
	}

	if len(segs) < 4 {
		return false
	}
	jobID := strings.TrimSpace(segs[2])
	sub := strings.TrimSpace(segs[3])

	// DELETE /_ml/anomaly_detectors/{job_id}/_forecast[/{forecast_id}]
	if (sub == "_forecast") && r.Method == http.MethodDelete {
		allowNoForecasts := isTruthyBoolQueryParam(r, "allow_no_forecasts")
		fcTarget := "_all"
		if len(segs) >= 5 {
			fcTarget = strings.TrimSpace(segs[4])
		}
		s.mu.Lock()
		job, exists := s.mlJobs[jobID]
		if !exists || job == nil {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
			return true
		}
		fcs, _ := job["_forecasts"].(map[string]any)
		if fcs == nil {
			fcs = make(map[string]any)
		}
		if fcTarget == "_all" || fcTarget == "*" {
			job["_forecasts"] = make(map[string]any)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return true
		}
		matched := 0
		for _, part := range strings.Split(fcTarget, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := fcs[part]; ok {
				delete(fcs, part)
				matched++
			} else if !allowNoForecasts {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown forecast ["+part+"]")
				return true
			}
		}
		s.mu.Unlock()
		if matched == 0 && !allowNoForecasts {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown forecast ["+fcTarget+"]")
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return true
	}

	// 4-segment POST actions not handled by legacy switch: _data, _reset, _forecast, _delete_expired_data
	if len(segs) == 4 && (sub == "_data" || sub == "_reset" || sub == "_forecast" || sub == "_delete_expired_data") {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		switch sub {
		case "_data":
			rawBytes, ok := readRequestBody(w, r)
			if !ok {
				return true
			}
			records, err := parseMLAnomalyDataRecords(rawBytes)
			if err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return true
			}
			s.mu.Lock()
			job, exists := s.mlJobs[jobID]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			if st, _ := job["state"].(string); st != "opened" {
				s.mu.Unlock()
				writeESError(w, http.StatusConflict, "status_exception", "Cannot post data to job ["+jobID+"] when state is ["+st+"]")
				return true
			}
			fieldCount := int64(0)
			for _, rec := range records {
				fieldCount += int64(len(rec))
			}
			prevRecs, _ := toInt64(job["_processed_record_count"])
			prevFields, _ := toInt64(job["_processed_field_count"])
			prevBytes, _ := toInt64(job["_input_bytes"])
			prevBuckets, _ := toInt64(job["_bucket_count"])
			newRecs := prevRecs + int64(len(records))
			newFields := prevFields + fieldCount
			newBytes := prevBytes + int64(len(rawBytes))
			newBuckets := prevBuckets
			if len(records) > 0 {
				if newBuckets == 0 {
					newBuckets = 1
				}
				buckets, _ := job["_buckets"].(map[string]any)
				if buckets == nil {
					buckets = make(map[string]any)
				}
				buckets["1700000000000"] = map[string]any{
					"timestamp":             int64(1700000000000),
					"anomaly_score":         0.0,
					"initial_anomaly_score": 0.0,
					"bucket_span":           3600,
					"is_interim":            false,
					"job_id":                jobID,
					"result_type":           "bucket",
				}
				job["_buckets"] = buckets
				snaps, _ := job["_snapshots"].(map[string]any)
				if snaps == nil {
					snaps = make(map[string]any)
				}
				if _, hasSnap := snaps["1"]; !hasSnap {
					snaps["1"] = map[string]any{
						"snapshot_id": "1",
						"job_id":      jobID,
						"timestamp":   time.Now().UTC().UnixMilli(),
						"description": "auto",
						"retain":      false,
					}
				}
				job["_snapshots"] = snaps
			}
			job["_processed_record_count"] = newRecs
			job["_processed_field_count"] = newFields
			job["_input_bytes"] = newBytes
			job["_bucket_count"] = newBuckets
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"job_id":                       jobID,
				"processed_record_count":       len(records),
				"processed_field_count":        fieldCount,
				"input_bytes":                  len(rawBytes),
				"input_field_count":            fieldCount,
				"invalid_date_count":           0,
				"missing_field_count":          0,
				"out_of_order_timestamp_count": 0,
				"empty_bucket_count":           0,
				"sparse_bucket_count":          0,
				"bucket_count":                 newBuckets,
			})
			return true

		case "_reset":
			force := isTruthyBoolQueryParam(r, "force")
			s.mu.Lock()
			job, exists := s.mlJobs[jobID]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			if st, _ := job["state"].(string); st == "opened" && !force {
				s.mu.Unlock()
				writeESError(w, http.StatusConflict, "status_exception", "Cannot reset opened job ["+jobID+"] without force=true")
				return true
			}
			delete(job, "_processed_record_count")
			delete(job, "_processed_field_count")
			delete(job, "_input_bytes")
			delete(job, "_bucket_count")
			delete(job, "_buckets")
			delete(job, "_records")
			delete(job, "_forecasts")
			delete(job, "_snapshots")
			job["state"] = "closed"
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "reset": true})
			return true

		case "_forecast":
			if _, ok := parseJSONBody(w, r); !ok {
				return true
			}
			s.mu.Lock()
			job, exists := s.mlJobs[jobID]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			fcs, _ := job["_forecasts"].(map[string]any)
			if fcs == nil {
				fcs = make(map[string]any)
			}
			seq, _ := toInt64(job["_forecast_seq"])
			seq++
			job["_forecast_seq"] = seq
			fid := fmt.Sprintf("fc_%d", seq)
			fcs[fid] = map[string]any{"forecast_id": fid, "created_at": time.Now().UTC().UnixMilli()}
			job["_forecasts"] = fcs
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "forecast_id": fid})
			return true

		case "_delete_expired_data":
			if _, ok := parseJSONBody(w, r); !ok {
				return true
			}
			s.mu.RLock()
			_, exists := s.mlJobs[jobID]
			s.mu.RUnlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
			return true
		}
	}

	// Results endpoints: /_ml/anomaly_detectors/{job_id}/results/{buckets|overall_buckets|records|categories|influencers}[/{arg}]
	if len(segs) >= 5 && sub == "results" {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		if r.Method == http.MethodPost {
			if _, ok := parseJSONBody(w, r); !ok {
				return true
			}
		}
		allowNoMatch := isTruthyBoolQueryParam(r, "allow_no_match")
		resKind := strings.TrimSpace(segs[4])
		s.mu.RLock()
		job, exists := s.mlJobs[jobID]
		if !exists && jobID != "_all" && jobID != "*" && !strings.ContainsAny(jobID, "*?,") && !allowNoMatch {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
			return true
		}
		switch resKind {
		case "buckets":
			bucketsMap, _ := job["_buckets"].(map[string]any)
			if len(segs) == 6 {
				ts := strings.TrimSpace(segs[5])
				bObj, okB := bucketsMap[ts].(map[string]any)
				if !okB {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Bucket ["+ts+"] not found")
					return true
				}
				cp := deepCloneDocMap(bObj)
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, cp)
				return true
			}
			list := []any{}
			var keys []string
			for k := range bucketsMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if m, okM := bucketsMap[k].(map[string]any); okM {
					list = append(list, deepCloneDocMap(m))
				}
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "buckets": list})
			return true

		case "overall_buckets":
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"count": 0, "overall_buckets": []any{}})
			return true

		case "records":
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"count": 0, "records": []any{}})
			return true

		case "categories":
			s.mu.RUnlock()
			if len(segs) == 6 {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Category ["+segs[5]+"] not found")
				return true
			}
			writeJSON(w, http.StatusOK, map[string]any{"count": 0, "categories": []any{}})
			return true

		case "influencers":
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"count": 0, "influencers": []any{}})
			return true
		}
		s.mu.RUnlock()
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return true
	}

	// Model snapshots: /_ml/anomaly_detectors/{job_id}/model_snapshots[/{snapshot_id}[/_update|_revert]]
	if len(segs) >= 4 && sub == "model_snapshots" {
		if len(segs) == 6 {
			snapID := strings.TrimSpace(segs[4])
			act := strings.TrimSpace(segs[5])
			if r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return true
			}
			s.mu.Lock()
			job, exists := s.mlJobs[jobID]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			snaps, _ := job["_snapshots"].(map[string]any)
			snap, okS := snaps[snapID].(map[string]any)
			if !okS || snap == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown snapshot ["+snapID+"]")
				return true
			}
			switch act {
			case "_update":
				if desc, okD := body["description"].(string); okD {
					snap["description"] = desc
				}
				if ret, okR := body["retain"].(bool); okR {
					snap["retain"] = ret
				}
				cp := deepCloneDocMap(snap)
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "model": cp})
				return true
			case "_revert":
				cp := deepCloneDocMap(snap)
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"model": cp})
				return true
			}
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			return true
		}

		if len(segs) == 5 && r.Method == http.MethodDelete {
			snapID := strings.TrimSpace(segs[4])
			s.mu.Lock()
			job, exists := s.mlJobs[jobID]
			if !exists || job == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
				return true
			}
			snaps, _ := job["_snapshots"].(map[string]any)
			if _, okS := snaps[snapID]; !okS {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown snapshot ["+snapID+"]")
				return true
			}
			delete(snaps, snapID)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return true
		}

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		if r.Method == http.MethodPost {
			if _, ok := parseJSONBody(w, r); !ok {
				return true
			}
		}
		snapPat := ""
		if len(segs) == 5 {
			snapPat = strings.TrimSpace(segs[4])
		}
		s.mu.RLock()
		job, exists := s.mlJobs[jobID]
		if !exists || job == nil {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown job ["+jobID+"]")
			return true
		}
		snaps, _ := job["_snapshots"].(map[string]any)
		if snapPat != "" && snapPat != "_all" && snapPat != "*" && !strings.ContainsAny(snapPat, "*?,") {
			if _, okS := snaps[snapPat]; !okS {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "Unknown snapshot ["+snapPat+"]")
				return true
			}
		}
		var keys []string
		for k := range snaps {
			if snapPat == "" || snapPat == "_all" || snapPat == "*" || matchMultiWildcardWithExclusions(snapPat, k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		list := make([]any, 0, len(keys))
		for _, k := range keys {
			if m, okM := snaps[k].(map[string]any); okM {
				list = append(list, deepCloneDocMap(m))
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "model_snapshots": list})
		return true
	}

	return false
}

func parseMLAnomalyDataRecords(rawBytes []byte) ([]map[string]any, error) {
	trimmed := bytes.TrimSpace(rawBytes)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var rec map[string]any
		err := dec.Decode(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, rec)
		}
	}
	return out, nil
}

// ============================================================================
// F6: Security Profiles, Dynamic Settings & Cross-Cluster API Keys
// ============================================================================

func (s *Server) handleSecurityRound56(w http.ResponseWriter, r *http.Request, segs []string) bool {
	if len(segs) < 2 {
		return false
	}
	switch segs[1] {
	case "profile":
		// POST /_security/profile/_activate
		if len(segs) == 3 && segs[2] == "_activate" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return true
			}
			username := "elastic"
			roles := []any{"superuser"}
			email := ""
			fullName := "Built-in Superuser"
			if gMap, okG := body["grant"].(map[string]any); okG {
				if uStr, okU := gMap["username"].(string); okU && strings.TrimSpace(uStr) != "" {
					username = strings.TrimSpace(uStr)
				} else if uSub, okUS := gMap["user"].(map[string]any); okUS {
					if uStr, okU2 := uSub["username"].(string); okU2 && strings.TrimSpace(uStr) != "" {
						username = strings.TrimSpace(uStr)
					}
					if rArr, okR := uSub["roles"].([]any); okR {
						roles = rArr
					}
					if em, okE := uSub["email"].(string); okE {
						email = em
					}
					if fn, okF := uSub["full_name"].(string); okF {
						fullName = fn
					}
				}
			} else if uStr, okU := body["username"].(string); okU && strings.TrimSpace(uStr) != "" {
				username = strings.TrimSpace(uStr)
			}

			s.mu.Lock()
			if s.securityProfiles == nil {
				s.securityProfiles = make(map[string]map[string]any)
			}
			if username != "elastic" {
				if uInfo, okU := s.securityUsers[username]; okU {
					if rArr, okR := uInfo["roles"].([]any); okR {
						roles = rArr
					} else if rStrs, okRS := uInfo["roles"].([]string); okRS {
						roles = make([]any, 0, len(rStrs))
						for _, rs := range rStrs {
							roles = append(roles, rs)
						}
					} else {
						roles = []any{}
					}
					if em, okE := uInfo["email"].(string); okE {
						email = em
					}
					if fn, okF := uInfo["full_name"].(string); okF {
						fullName = fn
					} else {
						fullName = ""
					}
				} else if len(roles) == 1 && roles[0] == "superuser" {
					roles = []any{}
					fullName = ""
				}
			}
			uid := "u_" + username
			existing, exists := s.securityProfiles[uid]
			isNew := !exists
			userMap := map[string]any{
				"username":   username,
				"roles":      roles,
				"realm_name": "native",
				"email":      email,
				"full_name":  fullName,
			}
			var prof map[string]any
			if isNew || existing == nil {
				prof = map[string]any{
					"uid":     uid,
					"enabled": true,
					"user":    userMap,
					"labels":  map[string]any{},
					"data":    map[string]any{},
				}
				s.securityProfiles[uid] = prof
			} else {
				existing["user"] = userMap
				prof = existing
			}
			enabledBool, _ := prof["enabled"].(bool)
			resp := map[string]any{
				"uid":           uid,
				"username":      username,
				"enabled":       enabledBool,
				"was_activated": isNew,
				"user":          deepCloneDocMap(userMap),
				"labels":        deepCloneIngestValue(prof["labels"]),
				"data":          deepCloneIngestValue(prof["data"]),
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, resp)
			return true
		}

		// GET /_security/profile/{uid}
		if len(segs) == 3 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			rawUIDs := strings.Split(segs[2], ",")
			s.mu.RLock()
			profiles := []any{}
			detailsMap := make(map[string]any)
			for _, rawU := range rawUIDs {
				u := strings.TrimSpace(rawU)
				if u == "" {
					continue
				}
				if p, exists := s.securityProfiles[u]; exists && p != nil {
					profiles = append(profiles, deepCloneDocMap(p))
				} else {
					detailsMap[u] = map[string]any{
						"type":   "resource_not_found_exception",
						"reason": fmt.Sprintf("profile [%s] not found", u),
					}
				}
			}
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				if len(profiles) == 0 {
					w.WriteHeader(http.StatusNotFound)
					return true
				}
				w.WriteHeader(http.StatusOK)
				return true
			}
			resp := map[string]any{"profiles": profiles}
			if len(detailsMap) > 0 {
				resp["errors"] = map[string]any{
					"count":   len(detailsMap),
					"details": detailsMap,
				}
			}
			writeJSON(w, http.StatusOK, resp)
			return true
		}

		// Sub-actions on /_security/profile/{uid}/{action}
		if len(segs) == 4 {
			uid := strings.TrimSpace(segs[2])
			action := strings.TrimSpace(segs[3])
			switch action {
			case "_data":
				if r.Method != http.MethodPost && r.Method != http.MethodPut {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
					return true
				}
				body, ok := parseJSONBody(w, r)
				if !ok {
					return true
				}
				s.mu.Lock()
				prof, exists := s.securityProfiles[uid]
				if !exists || prof == nil {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "profile ["+uid+"] not found")
					return true
				}
				labelsMap, _ := prof["labels"].(map[string]any)
				if labelsMap == nil {
					labelsMap = make(map[string]any)
				}
				if inLabels, okL := body["labels"].(map[string]any); okL {
					for k, v := range inLabels {
						if v == nil {
							delete(labelsMap, k)
						} else {
							labelsMap[k] = v
						}
					}
				}
				prof["labels"] = labelsMap
				dataMap, _ := prof["data"].(map[string]any)
				if dataMap == nil {
					dataMap = make(map[string]any)
				}
				for _, dKey := range []string{"data", "application"} {
					if inData, okD := body[dKey].(map[string]any); okD {
						for k, v := range inData {
							if v == nil {
								delete(dataMap, k)
							} else {
								dataMap[k] = v
							}
						}
					}
				}
				prof["data"] = dataMap
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
				return true

			case "_enable", "_disable":
				if r.Method != http.MethodPut && r.Method != http.MethodPost {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
					return true
				}
				s.mu.Lock()
				prof, exists := s.securityProfiles[uid]
				if !exists || prof == nil {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "profile ["+uid+"] not found")
					return true
				}
				prof["enabled"] = (action == "_enable")
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
				return true

			case "_has_privileges":
				if r.Method != http.MethodGet && r.Method != http.MethodPost {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
					return true
				}
				body, ok := parseJSONBody(w, r)
				if !ok {
					return true
				}
				s.mu.RLock()
				prof, exists := s.securityProfiles[uid]
				if !exists || prof == nil {
					s.mu.RUnlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "profile ["+uid+"] not found")
					return true
				}
				enabled, _ := prof["enabled"].(bool)
				uMap, _ := prof["user"].(map[string]any)
				username, _ := uMap["username"].(string)
				s.mu.RUnlock()

				allowed := enabled
				hasAll := enabled
				clusterRes := make(map[string]any)
				if cList, okC := body["cluster"].([]any); okC {
					for _, item := range cList {
						clusterRes[fmt.Sprintf("%v", item)] = allowed
					}
				}
				indexRes := make(map[string]any)
				if iList, okI := body["index"].([]any); okI {
					for _, item := range iList {
						if im, okM := item.(map[string]any); okM {
							names, _ := im["names"].([]any)
							privs, _ := im["privileges"].([]any)
							pm := make(map[string]any, len(privs))
							for _, p := range privs {
								pm[fmt.Sprintf("%v", p)] = allowed
							}
							for _, n := range names {
								indexRes[fmt.Sprintf("%v", n)] = pm
							}
						}
					}
				}
				appRes := make(map[string]any)
				if aList, okA := body["application"].([]any); okA {
					for _, item := range aList {
						if am, okM := item.(map[string]any); okM {
							appName := fmt.Sprintf("%v", am["application"])
							privs, _ := am["privileges"].([]any)
							resList, _ := am["resources"].([]any)
							if len(resList) == 0 {
								resList = []any{"*"}
							}
							pm := make(map[string]any, len(privs))
							for _, p := range privs {
								pm[fmt.Sprintf("%v", p)] = allowed
							}
							rm := make(map[string]any, len(resList))
							for _, rn := range resList {
								rm[fmt.Sprintf("%v", rn)] = pm
							}
							appRes[appName] = rm
						}
					}
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"username":          username,
					"uid":               uid,
					"has_all_requested": hasAll,
					"cluster":           clusterRes,
					"index":             indexRes,
					"application":       appRes,
				})
				return true
			}
		}

	case "_suggest_profiles":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return true
		}
		needle := ""
		if nStr, okN := body["name"].(string); okN {
			needle = strings.ToLower(strings.TrimSpace(nStr))
		} else if hStr, okH := body["hint"].(string); okH {
			needle = strings.ToLower(strings.TrimSpace(hStr))
		} else if hMap, okHM := body["hint"].(map[string]any); okHM {
			if tStr, okT := hMap["text"].(string); okT {
				needle = strings.ToLower(strings.TrimSpace(tStr))
			}
		}
		maxSize := 10
		if sz, okS := toInt64(body["size"]); okS && sz > 0 && sz <= 10000 {
			maxSize = int(sz)
		}
		s.mu.RLock()
		var uids []string
		for u := range s.securityProfiles {
			uids = append(uids, u)
		}
		sort.Strings(uids)
		matches := []any{}
		for _, u := range uids {
			p := s.securityProfiles[u]
			if en, _ := p["enabled"].(bool); !en {
				continue
			}
			if needle != "" {
				uMap, _ := p["user"].(map[string]any)
				un := strings.ToLower(fmt.Sprintf("%v", uMap["username"]))
				fn := strings.ToLower(fmt.Sprintf("%v", uMap["full_name"]))
				em := strings.ToLower(fmt.Sprintf("%v", uMap["email"]))
				if !strings.Contains(un, needle) && !strings.Contains(fn, needle) && !strings.Contains(em, needle) {
					continue
				}
			}
			matches = append(matches, deepCloneDocMap(p))
			if len(matches) >= maxSize {
				break
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"count":    len(matches),
			"profiles": matches,
		})
		return true

	case "settings":
		if len(segs) == 2 {
			switch r.Method {
			case http.MethodGet, http.MethodHead:
				s.mu.RLock()
				cp := deepCloneDocMap(s.securitySettings)
				s.mu.RUnlock()
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusOK)
					return true
				}
				resp := map[string]any{
					"main":    cp,
					"tokens":  map[string]any{},
					"profile": map[string]any{},
				}
				for k, v := range cp {
					if _, exists := resp[k]; !exists {
						resp[k] = v
					}
				}
				writeJSON(w, http.StatusOK, resp)
				return true
			case http.MethodPut, http.MethodPost:
				body, ok := parseJSONBody(w, r)
				if !ok {
					return true
				}
				s.mu.Lock()
				if s.securitySettings == nil {
					s.securitySettings = make(map[string]any)
				}
				for k, v := range body {
					if v == nil {
						delete(s.securitySettings, k)
					} else {
						s.securitySettings[k] = v
					}
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
				return true
			default:
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
		}

	case "cross_cluster":
		if len(segs) >= 3 && segs[2] == "api_key" {
			if len(segs) == 3 && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
				body, ok := parseJSONBody(w, r)
				if !ok {
					return true
				}
				name, _ := body["name"].(string)
				name = strings.TrimSpace(name)
				if name == "" {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[name] is required for cross_cluster api_key")
					return true
				}
				access, okAcc := body["access"].(map[string]any)
				if !okAcc || access == nil {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[access] object is required for cross_cluster api_key")
					return true
				}
				nowMS := time.Now().UTC().UnixMilli()
				var expVal any
				if expStr, okE := body["expiration"].(string); okE && strings.TrimSpace(expStr) != "" {
					durMS, valid := parsePositiveESDurationMillis(expStr)
					if !valid {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "invalid [expiration] duration ["+expStr+"]")
						return true
					}
					expVal = nowMS + durMS
				}
				meta, _ := body["metadata"].(map[string]any)
				if meta == nil {
					meta = map[string]any{}
				}
				s.mu.Lock()
				if s.securityAPIKeys == nil {
					s.securityAPIKeys = make(map[string]map[string]any)
				}
				id := fmt.Sprintf("cck_%d_%d", nowMS, len(s.securityAPIKeys)+1)
				secret := fmt.Sprintf("ccsec_%s_%d", name, nowMS)
				encoded := base64EncodeStr(id + ":" + secret)
				s.securityAPIKeys[id] = map[string]any{
					"id":          id,
					"name":        name,
					"type":        "cross_cluster",
					"access":      deepCloneDocMap(access),
					"metadata":    deepCloneDocMap(meta),
					"creation":    nowMS,
					"expiration":  expVal,
					"invalidated": false,
					"api_key":     secret,
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"id":         id,
					"name":       name,
					"expiration": expVal,
					"api_key":    secret,
					"encoded":    encoded,
				})
				return true
			}
			if len(segs) == 4 && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
				keyID := strings.TrimSpace(segs[3])
				body, ok := parseJSONBody(w, r)
				if !ok {
					return true
				}
				s.mu.Lock()
				keyObj, exists := s.securityAPIKeys[keyID]
				isCC := keyObj != nil && keyObj["type"] == "cross_cluster"
				isInv, _ := keyObj["invalidated"].(bool)
				if !exists || !isCC || isInv {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "cross_cluster api_key ["+keyID+"] not found")
					return true
				}
				if acc, okA := body["access"].(map[string]any); okA && acc != nil {
					keyObj["access"] = deepCloneDocMap(acc)
				}
				if meta, okM := body["metadata"].(map[string]any); okM {
					keyObj["metadata"] = deepCloneDocMap(meta)
				}
				if expStr, okE := body["expiration"].(string); okE && strings.TrimSpace(expStr) != "" {
					durMS, valid := parsePositiveESDurationMillis(expStr)
					if !valid {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "invalid [expiration] duration ["+expStr+"]")
						return true
					}
					keyObj["expiration"] = time.Now().UTC().UnixMilli() + durMS
				}
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, map[string]any{"updated": true})
				return true
			}
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
	}
	return false
}

// ============================================================================
// F7: ES|QL Execution Engine (Stage Splitter, Expression & Condition Evaluator)
// ============================================================================

func splitESQLStages(query string) []string {
	var stages []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if inSingle {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(query) {
				i++
				cur.WriteByte(query[i])
			} else if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(query) {
				i++
				cur.WriteByte(query[i])
			} else if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			cur.WriteByte(ch)
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		if ch == '/' && i+1 < len(query) && query[i+1] == '*' {
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				break
			}
			cur.WriteByte(' ')
			i += 2 + end + 1
			continue
		}
		if ch == '/' && i+1 < len(query) && query[i+1] == '/' {
			nl := strings.IndexByte(query[i+2:], '\n')
			if nl < 0 {
				break
			}
			cur.WriteByte(' ')
			i += 2 + nl
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			cur.WriteByte(ch)
		case '"':
			inDouble = true
			cur.WriteByte(ch)
		case '`':
			inBacktick = true
			cur.WriteByte(ch)
		case '|':
			if i+1 < len(query) && query[i+1] == '|' {
				cur.WriteString("||")
				i++
				continue
			}
			stages = append(stages, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	stages = append(stages, cur.String())
	return stages
}

func splitESQLTopLevel(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inS {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else if ch == '\'' {
				inS = false
			}
			continue
		}
		if inD {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else if ch == '"' {
				inD = false
			}
			continue
		}
		if inB {
			cur.WriteByte(ch)
			if ch == '`' {
				inB = false
			}
			continue
		}
		switch ch {
		case '\'':
			inS = true
			cur.WriteByte(ch)
		case '"':
			inD = true
			cur.WriteByte(ch)
		case '`':
			inB = true
			cur.WriteByte(ch)
		case '(':
			depth++
			cur.WriteByte(ch)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(ch)
		default:
			if ch == sep && depth == 0 {
				out = append(out, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(ch)
			}
		}
	}
	out = append(out, cur.String())
	return out
}

func splitESQLAssignment(s string) (string, string, bool) {
	depth := 0
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inS {
			if ch == '\\' && i+1 < len(s) {
				i++
			} else if ch == '\'' {
				inS = false
			}
			continue
		}
		if inD {
			if ch == '\\' && i+1 < len(s) {
				i++
			} else if ch == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if ch == '`' {
				inB = false
			}
			continue
		}
		switch ch {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				prev := byte(0)
				if i > 0 {
					prev = s[i-1]
				}
				next := byte(0)
				if i+1 < len(s) {
					next = s[i+1]
				}
				if prev != '=' && prev != '!' && prev != '<' && prev != '>' && next != '=' {
					lhs := unquoteESQLIdent(strings.TrimSpace(s[:i]))
					rhs := strings.TrimSpace(s[i+1:])
					return lhs, rhs, true
				}
			}
		}
	}
	return "", strings.TrimSpace(s), false
}

func unquoteESQLIdent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1]
	}
	return s
}

func bindESQLParamsInStage(stage string, params []any, cursor *int) string {
	if len(params) == 0 {
		return stage
	}
	var out strings.Builder
	inS, inD, inB := false, false, false
	for i := 0; i < len(stage); i++ {
		ch := stage[i]
		if inS {
			out.WriteByte(ch)
			if ch == '\\' && i+1 < len(stage) {
				i++
				out.WriteByte(stage[i])
			} else if ch == '\'' {
				inS = false
			}
			continue
		}
		if inD {
			out.WriteByte(ch)
			if ch == '\\' && i+1 < len(stage) {
				i++
				out.WriteByte(stage[i])
			} else if ch == '"' {
				inD = false
			}
			continue
		}
		if inB {
			out.WriteByte(ch)
			if ch == '`' {
				inB = false
			}
			continue
		}
		switch ch {
		case '\'':
			inS = true
			out.WriteByte(ch)
		case '"':
			inD = true
			out.WriteByte(ch)
		case '`':
			inB = true
			out.WriteByte(ch)
		case '?':
			if *cursor < len(params) {
				val := params[*cursor]
				*cursor++
				out.WriteString(formatESQLBoundLiteral(val))
			} else {
				out.WriteByte('?')
			}
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

func formatESQLBoundLiteral(val any) string {
	if val == nil {
		return "null"
	}
	switch v := val.(type) {
	case string:
		b, _ := json.Marshal(v)
		return string(b)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

type esqlTokKind int

const (
	esqlTokEOF esqlTokKind = iota
	esqlTokIdent
	esqlTokLit
	esqlTokOp
	esqlTokLParen
	esqlTokRParen
	esqlTokComma
)

type esqlTok struct {
	kind esqlTokKind
	str  string
	val  any
}

func tokenizeESQLExpr(expr string) []esqlTok {
	var toks []esqlTok
	i := 0
	for i < len(expr) {
		r, w := utf8.DecodeRuneInString(expr[i:])
		if unicode.IsSpace(r) {
			i += w
			continue
		}
		ch := expr[i]
		if ch == '"' || ch == '\'' {
			quote := ch
			i++
			var sb strings.Builder
			for i < len(expr) {
				c := expr[i]
				if c == '\\' && i+1 < len(expr) {
					i++
					switch expr[i] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					default:
						sb.WriteByte(expr[i])
					}
					i++
					continue
				}
				if c == quote {
					i++
					break
				}
				sb.WriteByte(c)
				i++
			}
			toks = append(toks, esqlTok{kind: esqlTokLit, val: sb.String()})
			continue
		}
		if ch == '`' {
			i++
			start := i
			for i < len(expr) && expr[i] != '`' {
				i++
			}
			id := expr[start:i]
			if i < len(expr) {
				i++
			}
			toks = append(toks, esqlTok{kind: esqlTokIdent, str: id})
			continue
		}
		if ch == '(' {
			toks = append(toks, esqlTok{kind: esqlTokLParen, str: "("})
			i++
			continue
		}
		if ch == ')' {
			toks = append(toks, esqlTok{kind: esqlTokRParen, str: ")"})
			i++
			continue
		}
		if ch == ',' {
			toks = append(toks, esqlTok{kind: esqlTokComma, str: ","})
			i++
			continue
		}
		if i+1 < len(expr) {
			two := expr[i : i+2]
			if two == "==" || two == "!=" || two == "<=" || two == ">=" || two == "&&" || two == "||" {
				toks = append(toks, esqlTok{kind: esqlTokOp, str: two})
				i += 2
				continue
			}
		}
		if strings.ContainsRune("+-*/%<>=", rune(ch)) {
			toks = append(toks, esqlTok{kind: esqlTokOp, str: string(ch)})
			i++
			continue
		}
		if ch >= '0' && ch <= '9' {
			start := i
			hasDot := false
			for i < len(expr) {
				c := expr[i]
				if c >= '0' && c <= '9' {
					i++
				} else if c == '.' && !hasDot {
					hasDot = true
					i++
				} else {
					break
				}
			}
			numStr := expr[start:i]
			if hasDot {
				fv, _ := strconv.ParseFloat(numStr, 64)
				toks = append(toks, esqlTok{kind: esqlTokLit, val: fv})
			} else {
				iv, _ := strconv.ParseInt(numStr, 10, 64)
				toks = append(toks, esqlTok{kind: esqlTokLit, val: iv})
			}
			continue
		}
		start := i
		for i < len(expr) {
			c := expr[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '@' || c == '-' {
				if c == '-' && i > start {
					// Keep hyphen only if part of field name? In ES|QL bare `-` is subtraction!
					break
				}
				i++
			} else {
				break
			}
		}
		if i == start {
			i++
			continue
		}
		word := expr[start:i]
		switch strings.ToUpper(word) {
		case "TRUE":
			toks = append(toks, esqlTok{kind: esqlTokLit, val: true})
		case "FALSE":
			toks = append(toks, esqlTok{kind: esqlTokLit, val: false})
		case "NULL":
			toks = append(toks, esqlTok{kind: esqlTokLit, val: nil})
		default:
			toks = append(toks, esqlTok{kind: esqlTokIdent, str: word})
		}
	}
	return toks
}

type esqlParser struct {
	toks []esqlTok
	pos  int
	row  map[string]any
}

func (p *esqlParser) peek() esqlTok {
	if p.pos >= len(p.toks) {
		return esqlTok{kind: esqlTokEOF}
	}
	return p.toks[p.pos]
}

func (p *esqlParser) next() esqlTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *esqlParser) matchIdentCI(word string) bool {
	t := p.peek()
	if t.kind == esqlTokIdent && strings.EqualFold(t.str, word) {
		p.pos++
		return true
	}
	return false
}

func getESQLFieldVal(row map[string]any, name string) any {
	if row == nil {
		return nil
	}
	if v, ok := row[name]; ok {
		return normalizeESQLNumber(v)
	}
	if v, ok := getIngestPath(row, name); ok {
		return normalizeESQLNumber(v)
	}
	return nil
}

func normalizeESQLNumber(v any) any {
	if jn, ok := v.(json.Number); ok {
		if iv, err := jn.Int64(); err == nil {
			return iv
		}
		if fv, err := jn.Float64(); err == nil {
			return fv
		}
		return jn.String()
	}
	return v
}

func evalESQLExpr(expr string, row map[string]any) any {
	p := &esqlParser{toks: tokenizeESQLExpr(expr), row: row}
	return p.parseOr()
}

func evalESQLCond(expr string, row map[string]any) bool {
	res := evalESQLExpr(expr, row)
	if b, ok := res.(bool); ok {
		return b
	}
	return false
}

func (p *esqlParser) parseOr() any {
	left := p.parseAnd()
	for {
		if p.matchIdentCI("OR") || (p.peek().kind == esqlTokOp && p.peek().str == "||") {
			if p.peek().kind == esqlTokOp && p.peek().str == "||" {
				p.next()
			}
			right := p.parseAnd()
			lb, _ := left.(bool)
			rb, _ := right.(bool)
			left = lb || rb
		} else {
			break
		}
	}
	return left
}

func (p *esqlParser) parseAnd() any {
	left := p.parseNot()
	for {
		if p.matchIdentCI("AND") || (p.peek().kind == esqlTokOp && p.peek().str == "&&") {
			if p.peek().kind == esqlTokOp && p.peek().str == "&&" {
				p.next()
			}
			right := p.parseNot()
			lb, _ := left.(bool)
			rb, _ := right.(bool)
			left = lb && rb
		} else {
			break
		}
	}
	return left
}

func (p *esqlParser) parseNot() any {
	if p.matchIdentCI("NOT") {
		v := p.parseNot()
		if v == nil {
			return false
		}
		bv, _ := v.(bool)
		return !bv
	}
	return p.parseComparison()
}

func (p *esqlParser) parseComparison() any {
	left := p.parseAddSub()
	if p.matchIdentCI("IS") {
		isNot := p.matchIdentCI("NOT")
		if p.peek().kind == esqlTokLit && p.peek().val == nil {
			p.next()
		} else {
			_ = p.matchIdentCI("NULL")
		}
		if isNot {
			return left != nil
		}
		return left == nil
	}
	negIn := false
	savedPos := p.pos
	if p.matchIdentCI("NOT") {
		if p.matchIdentCI("IN") {
			negIn = true
		} else if p.matchIdentCI("LIKE") {
			pat := p.parseAddSub()
			return left != nil && pat != nil && !matchESQLLike(fmt.Sprintf("%v", left), fmt.Sprintf("%v", pat))
		} else if p.matchIdentCI("RLIKE") {
			pat := p.parseAddSub()
			if left == nil || pat == nil {
				return false
			}
			re, err := regexp.Compile(fmt.Sprintf("%v", pat))
			return err == nil && !re.MatchString(fmt.Sprintf("%v", left))
		} else {
			p.pos = savedPos
		}
	}
	if negIn || p.matchIdentCI("IN") {
		var items []any
		if p.peek().kind == esqlTokLParen {
			p.next()
			for p.peek().kind != esqlTokEOF && p.peek().kind != esqlTokRParen {
				items = append(items, p.parseOr())
				if p.peek().kind == esqlTokComma {
					p.next()
				} else {
					break
				}
			}
			if p.peek().kind == esqlTokRParen {
				p.next()
			}
		}
		if left == nil {
			return false
		}
		found := false
		for _, it := range items {
			if it != nil && compareESQLValues(left, it) == 0 {
				found = true
				break
			}
		}
		if negIn {
			return !found
		}
		return found
	}
	if p.matchIdentCI("LIKE") {
		pat := p.parseAddSub()
		if left == nil || pat == nil {
			return false
		}
		return matchESQLLike(fmt.Sprintf("%v", left), fmt.Sprintf("%v", pat))
	}
	if p.matchIdentCI("RLIKE") {
		pat := p.parseAddSub()
		if left == nil || pat == nil {
			return false
		}
		re, err := regexp.Compile(fmt.Sprintf("%v", pat))
		return err == nil && re.MatchString(fmt.Sprintf("%v", left))
	}
	t := p.peek()
	if t.kind == esqlTokOp && (t.str == "==" || t.str == "=" || t.str == "!=" || t.str == "<" || t.str == "<=" || t.str == ">" || t.str == ">=") {
		p.next()
		right := p.parseAddSub()
		if left == nil || right == nil {
			return false
		}
		cmp := compareESQLValues(left, right)
		switch t.str {
		case "==", "=":
			return cmp == 0
		case "!=":
			return cmp != 0
		case "<":
			return cmp < 0
		case "<=":
			return cmp <= 0
		case ">":
			return cmp > 0
		case ">=":
			return cmp >= 0
		}
	}
	return left
}

func (p *esqlParser) parseAddSub() any {
	left := p.parseMulDiv()
	for p.peek().kind == esqlTokOp && (p.peek().str == "+" || p.peek().str == "-") {
		op := p.next().str
		right := p.parseMulDiv()
		left = evalESQLArith(op, left, right)
	}
	return left
}

func (p *esqlParser) parseMulDiv() any {
	left := p.parseUnary()
	for p.peek().kind == esqlTokOp && (p.peek().str == "*" || p.peek().str == "/" || p.peek().str == "%") {
		op := p.next().str
		right := p.parseUnary()
		left = evalESQLArith(op, left, right)
	}
	return left
}

func (p *esqlParser) parseUnary() any {
	if p.peek().kind == esqlTokOp && p.peek().str == "-" {
		p.next()
		v := p.parseUnary()
		if v == nil {
			return nil
		}
		if iv, ok := esqlAsInt64Exact(v); ok {
			return -iv
		}
		if fv, ok := toFloat64(v); ok {
			return -fv
		}
		return nil
	}
	return p.parsePrimary()
}

func (p *esqlParser) parsePrimary() any {
	t := p.peek()
	switch t.kind {
	case esqlTokLit:
		p.next()
		return t.val
	case esqlTokLParen:
		p.next()
		val := p.parseOr()
		if p.peek().kind == esqlTokRParen {
			p.next()
		}
		return val
	case esqlTokIdent:
		p.next()
		if p.peek().kind == esqlTokLParen {
			p.next()
			var args []any
			for p.peek().kind != esqlTokEOF && p.peek().kind != esqlTokRParen {
				args = append(args, p.parseOr())
				if p.peek().kind == esqlTokComma {
					p.next()
				} else {
					break
				}
			}
			if p.peek().kind == esqlTokRParen {
				p.next()
			}
			return evalESQLFunc(t.str, args)
		}
		return getESQLFieldVal(p.row, t.str)
	default:
		p.next()
		return nil
	}
}

func esqlAsInt64Exact(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case json.Number:
		if iv, err := n.Int64(); err == nil {
			return iv, true
		}
	}
	return 0, false
}

func evalESQLArith(op string, a, b any) any {
	if a == nil || b == nil {
		return nil
	}
	ai, aIsInt := esqlAsInt64Exact(a)
	bi, bIsInt := esqlAsInt64Exact(b)
	if aIsInt && bIsInt && op != "/" {
		switch op {
		case "+":
			return ai + bi
		case "-":
			return ai - bi
		case "*":
			return ai * bi
		case "%":
			if bi == 0 {
				return nil
			}
			return ai % bi
		}
	}
	af, okA := toFloat64(a)
	bf, okB := toFloat64(b)
	if !okA || !okB {
		return nil
	}
	switch op {
	case "+":
		return af + bf
	case "-":
		return af - bf
	case "*":
		return af * bf
	case "/":
		if bf == 0 {
			return nil
		}
		return af / bf
	case "%":
		if bf == 0 {
			return nil
		}
		return math.Mod(af, bf)
	}
	return nil
}

func evalESQLFunc(name string, args []any) any {
	switch strings.ToUpper(name) {
	case "COALESCE":
		for _, a := range args {
			if a != nil {
				return a
			}
		}
		return nil
	case "CONCAT":
		var sb strings.Builder
		for _, a := range args {
			if a != nil {
				_, _ = fmt.Fprintf(&sb, "%v", a)
			}
		}
		return sb.String()
	case "TO_STRING":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return fmt.Sprintf("%v", args[0])
	case "TO_INTEGER", "TO_INT", "TO_LONG":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		switch v := args[0].(type) {
		case bool:
			if v {
				return int64(1)
			}
			return int64(0)
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		default:
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
				return iv
			}
			if fv, err := strconv.ParseFloat(s, 64); err == nil {
				return int64(fv)
			}
			return nil
		}
	case "TO_DOUBLE", "TO_FLOAT":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		if b, ok := args[0].(bool); ok {
			if b {
				return 1.0
			}
			return 0.0
		}
		if fv, ok := toFloat64(args[0]); ok {
			return fv
		}
		if fv, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprintf("%v", args[0])), 64); err == nil {
			return fv
		}
		return nil
	case "TO_BOOLEAN", "TO_BOOL":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		switch v := args[0].(type) {
		case bool:
			return v
		default:
			if fv, ok := toFloat64(v); ok {
				return fv != 0
			}
			s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
			if s == "true" || s == "1" {
				return true
			}
			if s == "false" || s == "0" {
				return false
			}
			return nil
		}
	case "TO_LOWER":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.ToLower(fmt.Sprintf("%v", args[0]))
	case "TO_UPPER":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.ToUpper(fmt.Sprintf("%v", args[0]))
	case "TRIM":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.TrimSpace(fmt.Sprintf("%v", args[0]))
	case "LENGTH":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return int64(utf8.RuneCountInString(fmt.Sprintf("%v", args[0])))
	case "ROUND":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		fv, ok := toFloat64(args[0])
		if !ok {
			return nil
		}
		prec := int64(0)
		if len(args) >= 2 && args[1] != nil {
			if p, okP := toInt64(args[1]); okP {
				prec = p
			}
		}
		pow := math.Pow(10, float64(prec))
		res := math.Round(fv*pow) / pow
		if _, wasInt := esqlAsInt64Exact(args[0]); wasInt && prec <= 0 {
			return int64(res)
		}
		return res
	case "ABS":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		if iv, ok := esqlAsInt64Exact(args[0]); ok {
			if iv < 0 {
				return -iv
			}
			return iv
		}
		if fv, ok := toFloat64(args[0]); ok {
			return math.Abs(fv)
		}
		return nil
	}
	return nil
}

func compareESQLValues(a, b any) int {
	af, okA := toESQLNumber(a)
	bf, okB := toESQLNumber(b)
	if okA && okB {
		if af < bf {
			return -1
		}
		if af > bf {
			return 1
		}
		return 0
	}
	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	if as < bs {
		return -1
	}
	if as > bs {
		return 1
	}
	return 0
}

func toESQLNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case json.Number:
		if fv, err := n.Float64(); err == nil {
			return fv, true
		}
	case string:
		s := strings.TrimSpace(n)
		if s != "" {
			if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return fv, true
			}
		}
	}
	return 0, false
}

func matchESQLLike(val, pattern string) bool {
	var rb strings.Builder
	rb.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '\\' && i+1 < len(pattern) {
			i++
			rb.WriteString(regexp.QuoteMeta(string(pattern[i])))
			continue
		}
		switch ch {
		case '*', '%':
			rb.WriteString(".*")
		case '?', '_':
			rb.WriteString(".")
		default:
			rb.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	rb.WriteString("$")
	re, err := regexp.Compile("(?s)" + rb.String())
	return err == nil && re.MatchString(val)
}

type esqlAggSpec struct {
	outCol string
	fn     string
	arg    string
}

type esqlGroupSpec struct {
	outCol string
	expr   string
}

func splitESQLStatsByClause(s string) (string, string) {
	depth := 0
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inS {
			if ch == '\\' && i+1 < len(s) {
				i++
			} else if ch == '\'' {
				inS = false
			}
			continue
		}
		if inD {
			if ch == '\\' && i+1 < len(s) {
				i++
			} else if ch == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if ch == '`' {
				inB = false
			}
			continue
		}
		switch ch {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+2 <= len(s) && strings.EqualFold(s[i:i+2], "BY") {
				prevOK := i == 0 || unicode.IsSpace(rune(s[i-1])) || s[i-1] == ')'
				nextOK := i+2 == len(s) || unicode.IsSpace(rune(s[i+2]))
				if prevOK && nextOK {
					return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:])
				}
			}
		}
	}
	return strings.TrimSpace(s), ""
}

func parseESQLAggCall(expr string) (string, string) {
	s := strings.TrimSpace(expr)
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp > 0 && rp > lp {
		fn := strings.ToUpper(strings.TrimSpace(s[:lp]))
		arg := strings.TrimSpace(s[lp+1 : rp])
		return fn, arg
	}
	return "VALUES", s
}

func computeESQLAggregate(fn, arg string, grpRows []map[string]any) (any, string) {
	switch fn {
	case "COUNT":
		if arg == "" || arg == "*" {
			return int64(len(grpRows)), "long"
		}
		cnt := int64(0)
		for _, r := range grpRows {
			if evalESQLExpr(arg, r) != nil {
				cnt++
			}
		}
		return cnt, "long"

	case "COUNT_DISTINCT":
		seen := make(map[string]bool)
		for _, r := range grpRows {
			v := evalESQLExpr(arg, r)
			if v != nil {
				seen[fmt.Sprintf("%T:%v", v, v)] = true
			}
		}
		return int64(len(seen)), "long"

	case "SUM":
		hasVal := false
		allInt := true
		sumInt := int64(0)
		sumFlt := 0.0
		for _, r := range grpRows {
			v := evalESQLExpr(arg, r)
			if v == nil {
				continue
			}
			if iv, ok := esqlAsInt64Exact(v); ok {
				hasVal = true
				sumInt += iv
				sumFlt += float64(iv)
			} else if fv, ok := toFloat64(v); ok {
				hasVal = true
				allInt = false
				sumFlt += fv
			}
		}
		if !hasVal {
			return nil, "double"
		}
		if allInt {
			return sumInt, "long"
		}
		return sumFlt, "double"

	case "AVG":
		cnt := 0
		sum := 0.0
		for _, r := range grpRows {
			v := evalESQLExpr(arg, r)
			if v == nil {
				continue
			}
			if fv, ok := toFloat64(v); ok {
				sum += fv
				cnt++
			}
		}
		if cnt == 0 {
			return nil, "double"
		}
		return sum / float64(cnt), "double"

	case "MIN", "MAX":
		var best any
		for _, r := range grpRows {
			v := evalESQLExpr(arg, r)
			if v == nil {
				continue
			}
			if best == nil {
				best = v
				continue
			}
			cmp := compareESQLValues(v, best)
			if (fn == "MIN" && cmp < 0) || (fn == "MAX" && cmp > 0) {
				best = v
			}
		}
		if best == nil {
			return nil, "double"
		}
		return best, inferESQLValueType(best)

	case "VALUES":
		seen := make(map[string]bool)
		vals := []any{}
		elemType := "keyword"
		for _, r := range grpRows {
			v := evalESQLExpr(arg, r)
			if v == nil {
				continue
			}
			k := fmt.Sprintf("%T:%v", v, v)
			if !seen[k] {
				seen[k] = true
				vals = append(vals, v)
				elemType = inferESQLValueType(v)
			}
		}
		return vals, elemType
	}
	return nil, "keyword"
}

func (s *Server) executeESQLQueryEngine(w http.ResponseWriter, r *http.Request, body map[string]any, queryStr string) {
	params, _ := body["params"].([]any)
	paramCursor := 0
	stages := splitESQLStages(queryStr)

	var rows []map[string]any
	var colOrder []string
	colTypes := make(map[string]string)
	limit := 1000

	for idx, rawStage := range stages {
		st := strings.TrimSpace(rawStage)
		if st == "" {
			continue
		}
		st = bindESQLParamsInStage(st, params, &paramCursor)
		upper := strings.ToUpper(st)

		switch {
		case idx == 0 && (upper == "ROW" || strings.HasPrefix(upper, "ROW ")):
			rest := ""
			if len(st) > 3 {
				rest = strings.TrimSpace(st[3:])
			}
			assigns := splitESQLTopLevel(rest, ',')
			row := make(map[string]any)
			for _, a := range assigns {
				a = strings.TrimSpace(a)
				if a == "" {
					continue
				}
				if col, exprStr, hasEq := splitESQLAssignment(a); hasEq && col != "" {
					val := evalESQLExpr(exprStr, row)
					row[col] = val
					colOrder = append(colOrder, col)
					colTypes[col] = inferESQLValueType(val)
				} else {
					val := evalESQLExpr(a, row)
					col := fmt.Sprintf("col_%d", len(colOrder)+1)
					row[col] = val
					colOrder = append(colOrder, col)
					colTypes[col] = inferESQLValueType(val)
				}
			}
			rows = []map[string]any{row}

		case idx == 0 && strings.HasPrefix(upper, "FROM "):
			rest := strings.TrimSpace(st[5:])
			idxTarget := rest
			var metaCols []string
			if upIdx := strings.Index(strings.ToUpper(rest), " METADATA "); upIdx >= 0 {
				idxTarget = strings.TrimSpace(rest[:upIdx])
				for _, mc := range strings.Split(rest[upIdx+10:], ",") {
					mc = strings.TrimSpace(mc)
					if mc != "" {
						metaCols = append(metaCols, mc)
					}
				}
			} else if sp := strings.Fields(idxTarget); len(sp) > 0 {
				idxTarget = sp[0]
			}
			idxTarget = unquoteESQLIdent(idxTarget)
			queryObj := any(map[string]any{"match_all": map[string]any{}})
			if body["filter"] != nil {
				queryObj = body["filter"]
			}
			searchPayload := map[string]any{
				"size":  1000,
				"query": queryObj,
			}
			searchBody, _ := json.Marshal(searchPayload)
			r2 := r.Clone(r.Context())
			r2.Method = http.MethodPost
			r2.URL.RawQuery = ""
			r2.SetPathValue("index", idxTarget)
			r2.Body = io.NopCloser(bytes.NewReader(searchBody))
			r2.ContentLength = int64(len(searchBody))
			rec := &asyncCaptureResponseWriter{}
			s.handleSearch(rec, r2)
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
			var sr map[string]any
			dec := json.NewDecoder(bytes.NewReader(rec.body.Bytes()))
			dec.UseNumber()
			_ = dec.Decode(&sr)
			seenCols := make(map[string]bool)
			for _, mc := range metaCols {
				seenCols[mc] = true
				colOrder = append(colOrder, mc)
				if mc == "_version" {
					colTypes[mc] = "long"
				} else {
					colTypes[mc] = "keyword"
				}
			}
			var srcCols []string
			if hitsMap, ok := sr["hits"].(map[string]any); ok {
				if hitList, ok := hitsMap["hits"].([]any); ok {
					for _, hAny := range hitList {
						if hMap, ok := hAny.(map[string]any); ok {
							srcMap, _ := hMap["_source"].(map[string]any)
							row := make(map[string]any, len(srcMap)+len(metaCols))
							for k, v := range srcMap {
								nv := normalizeESQLNumber(v)
								row[k] = nv
								if !seenCols[k] {
									seenCols[k] = true
									srcCols = append(srcCols, k)
								}
								if nv != nil && (colTypes[k] == "" || colTypes[k] == "keyword") {
									colTypes[k] = inferESQLValueType(nv)
								}
							}
							for _, mc := range metaCols {
								row[mc] = normalizeESQLNumber(hMap[mc])
							}
							rows = append(rows, row)
						}
					}
				}
			}
			sort.Strings(srcCols)
			colOrder = append(colOrder, srcCols...)

		case idx == 0:
			writeESError(w, http.StatusBadRequest, "verification_exception", fmt.Sprintf("Found 1 problem\nline 1:1: unsupported ES|QL source command [%s]", st))
			return

		case strings.HasPrefix(upper, "LIMIT "):
			if n, err := strconv.Atoi(strings.TrimSpace(st[6:])); err == nil && n >= 0 {
				limit = n
			}

		case strings.HasPrefix(upper, "WHERE "):
			cond := strings.TrimSpace(st[6:])
			filtered := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				if evalESQLCond(cond, row) {
					filtered = append(filtered, row)
				}
			}
			rows = filtered

		case strings.HasPrefix(upper, "EVAL "):
			assigns := splitESQLTopLevel(strings.TrimSpace(st[5:]), ',')
			for _, a := range assigns {
				a = strings.TrimSpace(a)
				if a == "" {
					continue
				}
				col, exprStr, hasEq := splitESQLAssignment(a)
				if !hasEq || col == "" {
					col = unquoteESQLIdent(a)
					exprStr = a
				}
				inferred := ""
				for _, row := range rows {
					val := evalESQLExpr(exprStr, row)
					row[col] = val
					if val != nil && inferred == "" {
						inferred = inferESQLValueType(val)
					}
				}
				hasCol := false
				for _, c := range colOrder {
					if c == col {
						hasCol = true
						break
					}
				}
				if !hasCol {
					colOrder = append(colOrder, col)
				}
				if inferred != "" {
					colTypes[col] = inferred
				} else if colTypes[col] == "" {
					colTypes[col] = "keyword"
				}
			}

		case strings.HasPrefix(upper, "STATS "):
			aggPart, byPart := splitESQLStatsByClause(strings.TrimSpace(st[6:]))
			var aggSpecs []esqlAggSpec
			if aggPart != "" {
				for _, rawA := range splitESQLTopLevel(aggPart, ',') {
					rawA = strings.TrimSpace(rawA)
					if rawA == "" {
						continue
					}
					outCol, callStr, hasEq := splitESQLAssignment(rawA)
					if !hasEq || outCol == "" {
						outCol = rawA
						callStr = rawA
					}
					fn, arg := parseESQLAggCall(callStr)
					aggSpecs = append(aggSpecs, esqlAggSpec{outCol: outCol, fn: fn, arg: arg})
				}
			}
			var grpSpecs []esqlGroupSpec
			if byPart != "" {
				for _, rawG := range splitESQLTopLevel(byPart, ',') {
					rawG = strings.TrimSpace(rawG)
					if rawG == "" {
						continue
					}
					outCol, exprStr, hasEq := splitESQLAssignment(rawG)
					if !hasEq || outCol == "" {
						outCol = unquoteESQLIdent(rawG)
						exprStr = rawG
					}
					grpSpecs = append(grpSpecs, esqlGroupSpec{outCol: outCol, expr: exprStr})
				}
			}

			type grpBucket struct {
				gVals []any
				rows  []map[string]any
			}
			var bucketOrder []string
			buckets := make(map[string]*grpBucket)
			if len(rows) == 0 && len(grpSpecs) == 0 {
				bucketOrder = []string{""}
				buckets[""] = &grpBucket{rows: nil}
			} else {
				for _, row := range rows {
					gVals := make([]any, len(grpSpecs))
					var kb strings.Builder
					for gi, gs := range grpSpecs {
						gv := evalESQLExpr(gs.expr, row)
						gVals[gi] = gv
						_, _ = fmt.Fprintf(&kb, "%T:%v|", gv, gv)
					}
					key := kb.String()
					b, exists := buckets[key]
					if !exists {
						b = &grpBucket{gVals: gVals}
						buckets[key] = b
						bucketOrder = append(bucketOrder, key)
					}
					b.rows = append(b.rows, row)
				}
			}

			newColOrder := make([]string, 0, len(aggSpecs)+len(grpSpecs))
			newColTypes := make(map[string]string)
			for _, as := range aggSpecs {
				newColOrder = append(newColOrder, as.outCol)
			}
			for _, gs := range grpSpecs {
				newColOrder = append(newColOrder, gs.outCol)
			}

			nextRows := make([]map[string]any, 0, len(bucketOrder))
			for _, bk := range bucketOrder {
				b := buckets[bk]
				outRow := make(map[string]any, len(aggSpecs)+len(grpSpecs))
				for _, as := range aggSpecs {
					val, tName := computeESQLAggregate(as.fn, as.arg, b.rows)
					outRow[as.outCol] = val
					if newColTypes[as.outCol] == "" || val != nil {
						newColTypes[as.outCol] = tName
					}
				}
				for gi, gs := range grpSpecs {
					gv := b.gVals[gi]
					outRow[gs.outCol] = gv
					if gv != nil {
						newColTypes[gs.outCol] = inferESQLValueType(gv)
					} else if newColTypes[gs.outCol] == "" {
						newColTypes[gs.outCol] = colTypes[gs.outCol]
					}
				}
				nextRows = append(nextRows, outRow)
			}
			rows = nextRows
			colOrder = newColOrder
			colTypes = newColTypes

		case strings.HasPrefix(upper, "KEEP "):
			var nextCols []string
			seenKeep := make(map[string]bool)
			for _, kc := range splitESQLTopLevel(strings.TrimSpace(st[5:]), ',') {
				pat := unquoteESQLIdent(kc)
				if pat == "" {
					continue
				}
				if strings.ContainsAny(pat, "*?") {
					for _, existing := range colOrder {
						if matchSimpleWildcard(pat, existing) && !seenKeep[existing] {
							seenKeep[existing] = true
							nextCols = append(nextCols, existing)
						}
					}
				} else if !seenKeep[pat] {
					seenKeep[pat] = true
					nextCols = append(nextCols, pat)
					if colTypes[pat] == "" {
						colTypes[pat] = "keyword"
					}
				}
			}
			if len(nextCols) > 0 {
				colOrder = nextCols
			}

		case strings.HasPrefix(upper, "DROP "):
			var patterns []string
			for _, dc := range splitESQLTopLevel(strings.TrimSpace(st[5:]), ',') {
				p := unquoteESQLIdent(dc)
				if p != "" {
					patterns = append(patterns, p)
				}
			}
			shouldDrop := func(c string) bool {
				for _, pat := range patterns {
					if matchSimpleWildcard(pat, c) {
						return true
					}
				}
				return false
			}
			var nextCols []string
			for _, c := range colOrder {
				if !shouldDrop(c) {
					nextCols = append(nextCols, c)
				}
			}
			for _, row := range rows {
				for k := range row {
					if shouldDrop(k) {
						delete(row, k)
					}
				}
			}
			colOrder = nextCols

		case strings.HasPrefix(upper, "RENAME "):
			for _, spec := range splitESQLTopLevel(strings.TrimSpace(st[7:]), ',') {
				spec = strings.TrimSpace(spec)
				upSpec := strings.ToUpper(spec)
				asIdx := strings.Index(upSpec, " AS ")
				if asIdx <= 0 {
					continue
				}
				oldCol := unquoteESQLIdent(spec[:asIdx])
				newCol := unquoteESQLIdent(spec[asIdx+4:])
				if oldCol == "" || newCol == "" {
					continue
				}
				for i, c := range colOrder {
					if c == oldCol {
						colOrder[i] = newCol
					}
				}
				if colTypes[oldCol] != "" {
					colTypes[newCol] = colTypes[oldCol]
				}
				for _, row := range rows {
					if val, exists := row[oldCol]; exists {
						row[newCol] = val
						if oldCol != newCol {
							delete(row, oldCol)
						}
					}
				}
			}

		case strings.HasPrefix(upper, "SORT "):
			type sortClause struct {
				col        string
				desc       bool
				nullsFirst bool
			}
			var clauses []sortClause
			for _, rawS := range splitESQLTopLevel(strings.TrimSpace(st[5:]), ',') {
				toks := strings.Fields(strings.TrimSpace(rawS))
				if len(toks) == 0 {
					continue
				}
				sc := sortClause{col: unquoteESQLIdent(toks[0])}
				hasNulls := false
				for i := 1; i < len(toks); i++ {
					switch strings.ToUpper(toks[i]) {
					case "DESC":
						sc.desc = true
					case "ASC":
						sc.desc = false
					case "NULLS":
						if i+1 < len(toks) {
							i++
							hasNulls = true
							sc.nullsFirst = strings.EqualFold(toks[i], "FIRST")
						}
					}
				}
				if !hasNulls {
					sc.nullsFirst = sc.desc
				}
				clauses = append(clauses, sc)
			}
			if len(clauses) > 0 {
				sort.SliceStable(rows, func(i, j int) bool {
					for _, cl := range clauses {
						vi := getESQLFieldVal(rows[i], cl.col)
						vj := getESQLFieldVal(rows[j], cl.col)
						if vi == nil && vj == nil {
							continue
						}
						if vi == nil {
							return cl.nullsFirst
						}
						if vj == nil {
							return !cl.nullsFirst
						}
						cmp := compareESQLValues(vi, vj)
						if cmp == 0 {
							continue
						}
						if cl.desc {
							return cmp > 0
						}
						return cmp < 0
					}
					return false
				})
			}
		}
	}

	if len(rows) > limit {
		rows = rows[:limit]
	}

	columns := make([]any, 0, len(colOrder))
	for _, c := range colOrder {
		t := colTypes[c]
		if t == "" {
			t = "keyword"
		}
		columns = append(columns, map[string]any{
			"name": c,
			"type": t,
		})
	}

	columnar, _ := body["columnar"].(bool)
	if !columnar && r.URL.Query().Has("columnar") {
		columnar = isTruthyBoolQueryParam(r, "columnar")
	}
	var values []any
	if columnar {
		values = make([]any, len(colOrder))
		for ci, c := range colOrder {
			colSlice := make([]any, len(rows))
			for ri, row := range rows {
				colSlice[ri] = row[c]
			}
			values[ci] = colSlice
		}
	} else {
		values = make([]any, 0, len(rows))
		for _, row := range rows {
			vals := make([]any, 0, len(colOrder))
			for _, c := range colOrder {
				vals = append(vals, row[c])
			}
			values = append(values, vals)
		}
	}

	s.mu.Lock()
	if s.esqlAsyncQueries == nil {
		s.esqlAsyncQueries = make(map[string]map[string]any)
	}
	queryID := fmt.Sprintf("esql-query-%d", len(s.esqlAsyncQueries)+1)
	respObj := map[string]any{
		"id":         queryID,
		"is_running": false,
		"is_partial": false,
		"columns":    columns,
		"values":     values,
	}
	s.esqlAsyncQueries[queryID] = respObj
	s.mu.Unlock()

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		if fStr, ok := body["format"].(string); ok {
			format = strings.ToLower(strings.TrimSpace(fStr))
		}
	}
	if format == "csv" || format == "tsv" || format == "txt" {
		sep := ","
		switch format {
		case "tsv":
			sep = "\t"
		case "txt":
			sep = " | "
		}
		var b strings.Builder
		b.WriteString(strings.Join(colOrder, sep) + "\n")
		for _, row := range rows {
			parts := make([]string, 0, len(colOrder))
			for _, c := range colOrder {
				if row[c] == nil {
					parts = append(parts, "")
				} else {
					parts = append(parts, fmt.Sprintf("%v", row[c]))
				}
			}
			b.WriteString(strings.Join(parts, sep) + "\n")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
		return
	}

	writeJSON(w, http.StatusOK, respObj)
}

func extractSearchResponseHitItems(resp map[string]any) []map[string]any {
	if resp == nil {
		return nil
	}
	hitsOuter, ok := resp["hits"].(map[string]any)
	if !ok || hitsOuter == nil {
		return nil
	}
	switch arr := hitsOuter["hits"].(type) {
	case []map[string]any:
		return arr
	case []any:
		out := make([]map[string]any, 0, len(arr))
		for _, it := range arr {
			if m, okM := it.(map[string]any); okM && m != nil {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func extractHitSourceMap(hitItem map[string]any) map[string]any {
	if hitItem == nil {
		return nil
	}
	switch src := hitItem["_source"].(type) {
	case map[string]any:
		return deepCloneDocMap(src)
	case json.RawMessage:
		var m map[string]any
		if json.Unmarshal(src, &m) == nil && m != nil {
			return m
		}
	case []byte:
		var m map[string]any
		if json.Unmarshal(src, &m) == nil && m != nil {
			return m
		}
	}
	return nil
}
