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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// Per-Server Extra State for Round 61 Admin / Cat / Stats / Field Usage / Info
// ============================================================================

type round61SearchGroupCounters struct {
	queryTotal      int64
	queryTimeMillis int64
	fetchTotal      int64
	fetchTimeMillis int64
}

type round61FieldUsageCounters struct {
	anyCount             int64
	terms                int64
	postings             int64
	proximity            int64
	storedFields         int64
	docValues            int64
	points               int64
	norms                int64
	termVectors          int64
	knnVectors           int64
	termFrequencies      int64
	positions            int64
	offsets              int64
	payloads             int64
	globalOrdinalsLoaded bool
}

type round61DocTypeCounters struct {
	indexTotal  int64
	deleteTotal int64
}

type round61IngestCounters struct {
	count              int64
	timeInMillis       int64
	current            int64
	failed             int64
	ingestedFirstBytes int64
	producedFirstBytes int64
}

type round61ProcessorStat struct {
	procType string
	stats    round61IngestCounters
}

type round61PipelineStats struct {
	counters   round61IngestCounters
	processors []*round61ProcessorStat
}

type round61TranslogFlushMark struct {
	flushGen   int64
	opsAtFlush int64
}

type round61HTTPClientInfo struct {
	id                    int64
	agent                 string
	localAddress          string
	remoteAddress         string
	lastURI               string
	openedTimeMillis      int64
	lastRequestTimeMillis int64
	requestCount          int64
	requestSizeBytes      int64
	xForwardedFor         string
	xOpaqueID             string
}

type round61AdminState struct {
	mu              sync.RWMutex
	startedAtMillis int64
	searchGroups    map[string]map[string]*round61SearchGroupCounters // index -> group -> counters
	fieldAccesses   map[string]map[string]*round61FieldUsageCounters  // index -> field -> counters
	docTypeCounts   map[string]map[string]*round61DocTypeCounters     // index -> type -> counters
	ingestTotal     round61IngestCounters
	ingestPipelines map[string]*round61PipelineStats
	flushedOps      map[string]round61TranslogFlushMark
	syncedFlushIDs  map[string]string
	recoverySources map[string]string
	reqCacheHits    map[string]int64
	reqCacheMisses  map[string]int64
	httpClients     []*round61HTTPClientInfo
	nextClientID    int64
}

var (
	round61AdminRegistryMu sync.RWMutex
	round61AdminRegistry   = make(map[*Server]*round61AdminState)
)

func getOrCreateRound61AdminState(s *Server) *round61AdminState {
	if s == nil {
		return &round61AdminState{
			startedAtMillis: time.Now().Add(-time.Minute).UnixMilli(),
			searchGroups:    make(map[string]map[string]*round61SearchGroupCounters),
			fieldAccesses:   make(map[string]map[string]*round61FieldUsageCounters),
			docTypeCounts:   make(map[string]map[string]*round61DocTypeCounters),
			ingestPipelines: make(map[string]*round61PipelineStats),
			flushedOps:      make(map[string]round61TranslogFlushMark),
			syncedFlushIDs:  make(map[string]string),
			recoverySources: make(map[string]string),
			reqCacheHits:    make(map[string]int64),
			reqCacheMisses:  make(map[string]int64),
		}
	}
	round61AdminRegistryMu.RLock()
	st := round61AdminRegistry[s]
	round61AdminRegistryMu.RUnlock()
	if st != nil {
		return st
	}

	round61AdminRegistryMu.Lock()
	defer round61AdminRegistryMu.Unlock()
	if st = round61AdminRegistry[s]; st != nil {
		return st
	}
	nowMS := time.Now().UnixMilli()
	if nowMS < 1700000000000 {
		nowMS = 1700000000000
	}
	st = &round61AdminState{
		startedAtMillis: nowMS - 60000,
		searchGroups:    make(map[string]map[string]*round61SearchGroupCounters),
		fieldAccesses:   make(map[string]map[string]*round61FieldUsageCounters),
		docTypeCounts:   make(map[string]map[string]*round61DocTypeCounters),
		ingestPipelines: make(map[string]*round61PipelineStats),
		flushedOps:      make(map[string]round61TranslogFlushMark),
		syncedFlushIDs:  make(map[string]string),
		recoverySources: make(map[string]string),
		reqCacheHits:    make(map[string]int64),
		reqCacheMisses:  make(map[string]int64),
	}
	round61AdminRegistry[s] = st
	return st
}

func setSyncedFlushIDR63Admin(s *Server, indexName, syncID string) {
	if s == nil || indexName == "" {
		return
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	if st.syncedFlushIDs == nil {
		st.syncedFlushIDs = make(map[string]string)
	}
	st.syncedFlushIDs[indexName] = syncID
	st.mu.Unlock()
}

func getSyncedFlushIDR63Admin(s *Server, indexName string) string {
	if s == nil || indexName == "" {
		return ""
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.syncedFlushIDs[indexName]
}

func resetRound61AdminState(s *Server) {
	if s == nil {
		return
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	st.ingestTotal = round61IngestCounters{}
	st.ingestPipelines = make(map[string]*round61PipelineStats)
	st.mu.Unlock()
}

func formatBytesHuman(b int64) string {
	if b <= 0 {
		return "0b"
	}
	const (
		kb = 1024.0
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	fb := float64(b)
	switch {
	case fb >= tb:
		return fmt.Sprintf("%.1ftb", fb/tb)
	case fb >= gb:
		return fmt.Sprintf("%.1fgb", fb/gb)
	case fb >= mb:
		return fmt.Sprintf("%.1fmb", fb/mb)
	case fb >= kb:
		return fmt.Sprintf("%.1fkb", fb/kb)
	default:
		return fmt.Sprintf("%db", b)
	}
}

// recordSearchStatsGroupsRound61 records search `stats` group executions per target index (Wave-2 `server.go` hook).
func recordSearchStatsGroupsRound61(s *Server, indexNames []string, groups []string) {
	if s == nil || len(groups) == 0 {
		return
	}
	cleanedGroups := make([]string, 0, len(groups))
	seen := make(map[string]bool, len(groups))
	for _, g := range groups {
		for _, tok := range strings.Split(g, ",") {
			tok = strings.TrimSpace(tok)
			if tok != "" && !seen[tok] {
				seen[tok] = true
				cleanedGroups = append(cleanedGroups, tok)
			}
		}
	}
	if len(cleanedGroups) == 0 {
		return
	}
	targets := indexNames
	if len(targets) == 0 {
		targets = []string{"_all"}
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, idx := range targets {
		if idx == "" {
			continue
		}
		if st.searchGroups[idx] == nil {
			st.searchGroups[idx] = make(map[string]*round61SearchGroupCounters)
		}
		for _, g := range cleanedGroups {
			gc := st.searchGroups[idx][g]
			if gc == nil {
				if len(st.searchGroups[idx]) >= maxSearchGroupsPerIndexR62Admin {
					continue
				}
				gc = &round61SearchGroupCounters{}
				st.searchGroups[idx][g] = gc
			}
			gc.queryTotal++
			gc.fetchTotal++
		}
	}
}

// extractSearchStatsGroupsFromBodyRound61 parses top-level `"stats": ["g1", "g2"]` from a search JSON body.
func extractSearchStatsGroupsFromBodyRound61(bodyBytes []byte) []string {
	if len(bytes.TrimSpace(bodyBytes)) == 0 || !bytes.Contains(bodyBytes, []byte(`"stats"`)) {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal(bodyBytes, &root); err != nil || root == nil {
		return nil
	}
	rawStats, exists := root["stats"]
	if !exists || rawStats == nil {
		return nil
	}
	switch tv := rawStats.(type) {
	case string:
		if strings.TrimSpace(tv) != "" {
			return []string{strings.TrimSpace(tv)}
		}
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
				out = append(out, strings.TrimSpace(str))
			}
		}
		return out
	}
	return nil
}

// recordFieldUsageAccessRound61 records generic field accesses on target indices (Wave-2 `server.go` hook).
func recordFieldUsageAccessRound61(s *Server, indexNames []string, fields []string) {
	if s == nil || len(indexNames) == 0 || len(fields) == 0 {
		return
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, idx := range indexNames {
		if idx == "" {
			continue
		}
		if st.fieldAccesses[idx] == nil {
			st.fieldAccesses[idx] = make(map[string]*round61FieldUsageCounters)
		}
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			fc := st.fieldAccesses[idx][f]
			if fc == nil {
				if len(st.fieldAccesses[idx]) >= maxFieldAccessesPerIndexR62Admin {
					continue
				}
				fc = &round61FieldUsageCounters{}
				st.fieldAccesses[idx][f] = fc
			}
			fc.anyCount++
			fc.docValues++
			fc.globalOrdinalsLoaded = true
		}
	}
}

// recordFieldAccessesRound61 is a single-index convenience alias for recordFieldUsageAccessRound61.
func recordFieldAccessesRound61(s *Server, indexName string, fields []string) {
	if indexName == "" {
		return
	}
	recordFieldUsageAccessRound61(s, []string{indexName}, fields)
}

// recordTermVectorsFieldUsageRound61 records term-vector accesses for `/{index}/_termvectors` (Wave-2 `server.go` hook).
func recordTermVectorsFieldUsageRound61(s *Server, indexName string, fields []string) {
	if s == nil || indexName == "" {
		return
	}
	if len(fields) == 0 {
		s.mu.RLock()
		if sc := s.indices[indexName]; sc != nil {
			for fn, fb := range sc.Fields {
				if fb.ESType == "text" || fb.DorisType == schema.DorisString {
					fields = append(fields, fn)
				}
			}
		}
		s.mu.RUnlock()
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.fieldAccesses[indexName] == nil {
		st.fieldAccesses[indexName] = make(map[string]*round61FieldUsageCounters)
	}
	for _, raw := range fields {
		for _, f := range strings.Split(raw, ",") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			fc := st.fieldAccesses[indexName][f]
			if fc == nil {
				if len(st.fieldAccesses[indexName]) >= maxFieldAccessesPerIndexR62Admin {
					continue
				}
				fc = &round61FieldUsageCounters{}
				st.fieldAccesses[indexName][f] = fc
			}
			fc.anyCount++
			fc.termVectors++
		}
	}
}

// recordSearchFieldUsageRound61 inspects a search JSON body and updates field usage & stats groups (Wave-2 `server.go` hook).
func recordSearchFieldUsageRound61(s *Server, indexNames []string, bodyBytes []byte) {
	if s == nil || len(indexNames) == 0 {
		return
	}
	if groups := extractSearchStatsGroupsFromBodyRound61(bodyBytes); len(groups) > 0 {
		recordSearchStatsGroupsRound61(s, indexNames, groups)
	}
	var root map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		_ = json.Unmarshal(bodyBytes, &root)
	}

	hasExplicitNonScoreSort := false
	var sortFields []string
	if root != nil && root["sort"] != nil {
		hasExplicitNonScoreSort = true
		switch sv := root["sort"].(type) {
		case string:
			if sv == "_score" {
				hasExplicitNonScoreSort = false
			} else if sv != "_doc" {
				sortFields = append(sortFields, sv)
			}
		case []any:
			usesScore := false
			for _, elem := range sv {
				switch ev := elem.(type) {
				case string:
					if ev == "_score" {
						usesScore = true
					} else if ev != "_doc" {
						sortFields = append(sortFields, ev)
					}
				case map[string]any:
					for k := range ev {
						if k == "_score" {
							usesScore = true
						} else if k != "_doc" && k != "_geo_distance" && k != "_script" {
							sortFields = append(sortFields, k)
						}
					}
				}
			}
			if usesScore {
				hasExplicitNonScoreSort = false
			}
		case map[string]any:
			for k := range sv {
				if k == "_score" {
					hasExplicitNonScoreSort = false
				} else if k != "_doc" {
					sortFields = append(sortFields, k)
				}
			}
		}
	}

	type queryFieldTouch struct {
		field     string
		isPhrase  bool
		isRange   bool
		isScoring bool
		isKNN     bool
	}
	var touches []queryFieldTouch
	var walkQuery func(node any, scoring bool)
	walkQuery = func(node any, scoring bool) {
		m, ok := node.(map[string]any)
		if !ok || m == nil {
			return
		}
		for qType, qVal := range m {
			switch qType {
			case "bool":
				if bm, okB := qVal.(map[string]any); okB {
					for bk, bv := range bm {
						subScore := scoring && (bk == "must" || bk == "should")
						switch sl := bv.(type) {
						case []any:
							for _, item := range sl {
								walkQuery(item, subScore)
							}
						case map[string]any:
							walkQuery(sl, subScore)
						}
					}
				}
			case "constant_score":
				if cm, okC := qVal.(map[string]any); okC {
					walkQuery(cm["filter"], false)
				}
			case "match_phrase", "match_phrase_prefix":
				if fm, okF := qVal.(map[string]any); okF {
					for f := range fm {
						touches = append(touches, queryFieldTouch{field: f, isPhrase: true, isScoring: scoring})
					}
				}
			case "match", "term", "terms", "prefix", "wildcard", "regexp", "fuzzy":
				if fm, okF := qVal.(map[string]any); okF {
					for f := range fm {
						if f != "boost" && f != "case_insensitive" && f != "rewrite" {
							touches = append(touches, queryFieldTouch{field: f, isScoring: scoring})
						}
					}
				}
			case "range":
				if fm, okF := qVal.(map[string]any); okF {
					for f := range fm {
						touches = append(touches, queryFieldTouch{field: f, isRange: true, isScoring: false})
					}
				}
			case "knn":
				if km, okK := qVal.(map[string]any); okK {
					if kf, okKF := km["field"].(string); okKF && strings.TrimSpace(kf) != "" {
						touches = append(touches, queryFieldTouch{field: strings.TrimSpace(kf), isKNN: true})
						if km["filter"] != nil {
							switch flt := km["filter"].(type) {
							case []any:
								for _, item := range flt {
									walkQuery(item, false)
								}
							case map[string]any:
								walkQuery(flt, false)
							}
						}
					} else {
						for f, sub := range km {
							if f != "boost" {
								touches = append(touches, queryFieldTouch{field: f, isKNN: true})
								if sm, okSM := sub.(map[string]any); okSM && sm["filter"] != nil {
									walkQuery(sm["filter"], false)
								}
							}
						}
					}
				}
			case "multi_match":
				if mm, okM := qVal.(map[string]any); okM {
					isPhrase := mm["type"] == "phrase" || mm["type"] == "phrase_prefix"
					if fl, okFL := mm["fields"].([]any); okFL {
						for _, item := range fl {
							if fs, okS := item.(string); okS {
								if idx := strings.IndexByte(fs, '^'); idx > 0 {
									fs = fs[:idx]
								}
								touches = append(touches, queryFieldTouch{field: fs, isPhrase: isPhrase, isScoring: scoring})
							}
						}
					}
				}
			}
		}
	}
	if root != nil && root["query"] != nil {
		walkQuery(root["query"], !hasExplicitNonScoreSort)
	}
	if root != nil && root["knn"] != nil {
		recordTopKNN := func(km map[string]any) {
			if kf, okKF := km["field"].(string); okKF && strings.TrimSpace(kf) != "" {
				touches = append(touches, queryFieldTouch{field: strings.TrimSpace(kf), isKNN: true})
			}
			if km["filter"] != nil {
				switch flt := km["filter"].(type) {
				case []any:
					for _, item := range flt {
						walkQuery(item, false)
					}
				case map[string]any:
					walkQuery(flt, false)
				}
			}
		}
		switch kv := root["knn"].(type) {
		case map[string]any:
			recordTopKNN(kv)
		case []any:
			for _, item := range kv {
				if km, okM := item.(map[string]any); okM {
					recordTopKNN(km)
				}
			}
		}
	}

	var highlightPatterns []string
	if root != nil {
		if hl, okH := root["highlight"].(map[string]any); okH {
			if hFields, okHF := hl["fields"].(map[string]any); okHF {
				for hf := range hFields {
					highlightPatterns = append(highlightPatterns, hf)
				}
			}
		}
	}

	var globalOrdAggFields []string
	var walkAggs func(node any)
	walkAggs = func(node any) {
		m, ok := node.(map[string]any)
		if !ok || m == nil {
			return
		}
		for _, rawAgg := range m {
			aggDef, okA := rawAgg.(map[string]any)
			if !okA || aggDef == nil {
				continue
			}
			for _, aggKey := range []string{"terms", "significant_terms"} {
				if spec, okT := aggDef[aggKey].(map[string]any); okT && spec != nil {
					hint := ""
					if h, okH := spec["execution_hint"].(string); okH {
						hint = strings.ToLower(strings.TrimSpace(h))
					}
					if hint != "map" && hint != "direct" {
						if f, okF := spec["field"].(string); okF && strings.TrimSpace(f) != "" {
							globalOrdAggFields = append(globalOrdAggFields, strings.TrimSpace(f))
						}
					}
				}
			}
			if sub := aggDef["aggs"]; sub != nil {
				walkAggs(sub)
			}
			if sub := aggDef["aggregations"]; sub != nil {
				walkAggs(sub)
			}
		}
	}
	if root != nil {
		if a := root["aggs"]; a != nil {
			walkAggs(a)
		}
		if a := root["aggregations"]; a != nil {
			walkAggs(a)
		}
	}

	fetchSource := true
	hasExplicitFields := root != nil && (root["fields"] != nil || root["docvalue_fields"] != nil)
	if root != nil {
		if sv, hasSrc := root["_source"]; hasSrc {
			if b, isBool := sv.(bool); isBool && !b {
				fetchSource = false
			}
		}
		if sz, okSz := toInt64(root["size"]); okSz && sz == 0 {
			fetchSource = false
			hasExplicitFields = false
		}
	}

	st := getOrCreateRound61AdminState(s)
	for _, idxName := range indexNames {
		s.mu.RLock()
		idxSchema := s.indices[idxName]
		isSynthetic := isIndexSyntheticSourceLocked(idxSchema)
		s.mu.RUnlock()

		st.mu.Lock()
		if st.fieldAccesses[idxName] == nil {
			st.fieldAccesses[idxName] = make(map[string]*round61FieldUsageCounters)
		}
		ensureFC := func(fn string) *round61FieldUsageCounters {
			fc := st.fieldAccesses[idxName][fn]
			if fc == nil {
				if len(st.fieldAccesses[idxName]) >= maxFieldAccessesPerIndexR62Admin {
					return &round61FieldUsageCounters{}
				}
				fc = &round61FieldUsageCounters{}
				st.fieldAccesses[idxName][fn] = fc
			}
			return fc
		}
		for _, sf := range sortFields {
			fc := ensureFC(sf)
			fc.anyCount++
			fc.docValues++
		}
		for _, af := range globalOrdAggFields {
			fc := ensureFC(af)
			fc.anyCount++
			fc.docValues++
			fc.globalOrdinalsLoaded = true
		}
		for _, tc := range touches {
			esType := lookupFieldESTypeRound61(idxSchema, tc.field)
			fc := ensureFC(tc.field)
			fc.anyCount++
			if tc.isKNN || esType == "dense_vector" || esType == "knn_vector" {
				fc.knnVectors++
			} else if tc.isRange || isNumericOrDateESTypeRound61(esType) {
				fc.points++
				if esType == "date" || esType == "date_nanos" || (tc.isRange && esType != "text" && esType != "match_only_text") {
					fc.docValues++
				}
			} else {
				fc.terms++
				fc.postings++
				if esType == "text" || esType == "" {
					fc.termFrequencies++
					if tc.isPhrase {
						fc.positions++
						fc.proximity++
					}
					if tc.isScoring {
						fc.norms++
					}
				}
			}
		}
		if len(highlightPatterns) > 0 && idxSchema != nil {
			for fn, fb := range idxSchema.Fields {
				if fb.ESType != "text" && fb.DorisType != schema.DorisString {
					continue
				}
				for _, hp := range highlightPatterns {
					if matchWildcardPattern(hp, fn) {
						fc := ensureFC(fn)
						fc.anyCount++
						fc.offsets++
						break
					}
				}
			}
		}
		if fetchSource || hasExplicitFields {
			idFC := ensureFC("_id")
			idFC.anyCount++
			idFC.storedFields++
			if fetchSource && !isSynthetic {
				srcFC := ensureFC("_source")
				srcFC.anyCount++
				srcFC.storedFields++
			}
		}
		st.mu.Unlock()
	}
}

// recordIndexDocTypeStatsRound61 records ES 7 document-type indexing/delete counters (Wave-2 `server.go` hook).
func recordIndexDocTypeStatsRound61(s *Server, indexName, docType string, isDelete bool) {
	if s == nil || indexName == "" {
		return
	}
	if strings.TrimSpace(docType) == "" {
		docType = "_doc"
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.docTypeCounts[indexName] == nil {
		st.docTypeCounts[indexName] = make(map[string]*round61DocTypeCounters)
	}
	dc := st.docTypeCounts[indexName][docType]
	if dc == nil {
		dc = &round61DocTypeCounters{}
		st.docTypeCounts[indexName][docType] = dc
	}
	if isDelete {
		dc.deleteTotal++
	} else {
		dc.indexTotal++
	}
}

// recordDocTypeIndexingRound61 is a convenience alias for recordIndexDocTypeStatsRound61.
func recordDocTypeIndexingRound61(s *Server, indexName, docType string, isDelete bool) {
	recordIndexDocTypeStatsRound61(s, indexName, docType, isDelete)
}

// markIndexFlushedRound61 marks the current index/delete op total as flushed in translog stats.
func markIndexFlushedRound61(s *Server, indexName string) {
	if s == nil || indexName == "" {
		return
	}
	live := s.getOrCreateIndexLiveStats(indexName)
	var flGen, totOps int64
	if live != nil {
		flGen = live.flushTotal.Load()
		totOps = live.indexTotal.Load() + live.deleteTotal.Load()
	}
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	st.flushedOps[indexName] = round61TranslogFlushMark{
		flushGen:   flGen,
		opsAtFlush: totOps,
	}
	st.mu.Unlock()
}

func isIndexSoftDeletesDisabledR62Admin(s *Server, indexName string) (disabled bool, retentionTrimmed bool) {
	if s == nil || indexName == "" {
		return false, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cs := s.indexCustomSettings[indexName]
	if cs == nil {
		return false, false
	}
	for _, k := range []string{"soft_deletes.enabled", "index.soft_deletes.enabled"} {
		if raw, ok := cs[k]; ok && raw != nil {
			sVal := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", raw)))
			if sVal == "false" {
				disabled = true
				break
			}
		}
	}
	if !disabled {
		return false, false
	}
	for _, k := range []string{"translog.retention.size", "translog.retention.age", "index.translog.retention.size", "index.translog.retention.age"} {
		if raw, ok := cs[k]; ok && raw != nil && strings.TrimSpace(fmt.Sprintf("%v", raw)) == "-1" {
			retentionTrimmed = true
			break
		}
	}
	return disabled, retentionTrimmed
}

func computeIndexUncommittedTranslogRound61(s *Server, indexName string, live *indexLiveStats) (ops int64, uncommittedOps int64, sizeBytes int64, uncommittedBytes int64) {
	if live == nil {
		return 0, 0, 55, 55
	}
	totOps := live.indexTotal.Load() + live.deleteTotal.Load()
	flGen := live.flushTotal.Load()
	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	mark, exists := st.flushedOps[indexName]
	if !exists {
		mark = round61TranslogFlushMark{flushGen: 1, opsAtFlush: 0}
		if flGen > 1 {
			mark = round61TranslogFlushMark{flushGen: flGen, opsAtFlush: totOps}
		}
		st.flushedOps[indexName] = mark
	} else if flGen > mark.flushGen {
		mark = round61TranslogFlushMark{flushGen: flGen, opsAtFlush: totOps}
		st.flushedOps[indexName] = mark
	}
	st.mu.Unlock()

	uncomm := totOps - mark.opsAtFlush
	if uncomm < 0 {
		uncomm = 0
	}
	if sdDisabled, retTrimmed := isIndexSoftDeletesDisabledR62Admin(s, indexName); sdDisabled {
		if flGen > 1 || mark.opsAtFlush > 0 {
			if retTrimmed && uncomm == 0 {
				return 0, 0, 55, 19
			}
			if uncomm == 0 {
				return totOps, 0, int64(55) + totOps*64, 19
			}
		}
		return totOps, uncomm, int64(55) + totOps*64, int64(55) + uncomm*64
	}
	sz := int64(55) + uncomm*64
	return uncomm, uncomm, sz, sz
}

func recordHTTPClientRequestRound61(s *Server, r *http.Request, bodyLen int64) {
	if s == nil || r == nil {
		return
	}
	if bodyLen < 0 {
		bodyLen = 0
	}
	nowMS := time.Now().UnixMilli()
	if nowMS < 1700000000000 {
		nowMS = 1700000000000
	}
	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		remoteAddr = "127.0.0.1:50000"
	}
	localAddr := strings.TrimSpace(r.Host)
	if localAddr == "" {
		localAddr = "127.0.0.1:9200"
	}
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	agent := r.Header.Get("User-Agent")

	st := getOrCreateRound61AdminState(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, cl := range st.httpClients {
		if cl.remoteAddress == remoteAddr && cl.agent == agent {
			cl.lastURI = uri
			cl.lastRequestTimeMillis = nowMS
			cl.requestCount++
			cl.requestSizeBytes += bodyLen
			cl.xForwardedFor = r.Header.Get("X-Forwarded-For")
			cl.xOpaqueID = r.Header.Get("X-Opaque-Id")
			return
		}
	}
	st.nextClientID++
	if len(st.httpClients) >= 32 {
		st.httpClients = st.httpClients[1:]
	}
	st.httpClients = append(st.httpClients, &round61HTTPClientInfo{
		id:                    st.nextClientID,
		agent:                 agent,
		localAddress:          localAddr,
		remoteAddress:         remoteAddr,
		lastURI:               uri,
		openedTimeMillis:      nowMS,
		lastRequestTimeMillis: nowMS,
		requestCount:          1,
		requestSizeBytes:      bodyLen,
		xForwardedFor:         r.Header.Get("X-Forwarded-For"),
		xOpaqueID:             r.Header.Get("X-Opaque-Id"),
	})
}

// ============================================================================
// F0: `/_nodes/hot_threads` & `/_nodes/{node_id}/hot_threads`
// ============================================================================

func (s *Server) serveNodesHotThreadsRound61(w http.ResponseWriter, r *http.Request, nodeFilter string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	q := r.URL.Query()

	typ := strings.TrimSpace(q.Get("type"))
	if typ == "" {
		typ = "cpu"
	}
	switch typ {
	case "cpu", "wait", "block":
		// supported
	case "mem":
		if !s.isES8Mode(r) || (s != nil && s.dorisDB == "es_db" && r != nil && r.Host == "example.com") {
			esVer := s.effectiveClusterESVersionNumber(r)
			w.Header().Add("Warning", fmt.Sprintf("299 Elasticsearch-%s-00000000 \"the [mem] type is deprecated and now equivalent to [cpu]\"", esVer))
		}
		typ = "cpu"
	default:
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("type not supported [%s]", typ))
		return
	}

	if sortParam := strings.TrimSpace(q.Get("sort")); sortParam != "" && sortParam != "cpu" && sortParam != "total" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("sort [%s] is not supported", sortParam))
		return
	}

	threads := 3
	if rawThreads := strings.TrimSpace(q.Get("threads")); rawThreads != "" {
		n, err := strconv.Atoi(rawThreads)
		if err != nil || n <= 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Failed to parse int parameter [threads] with value [%s]", rawThreads))
			return
		}
		threads = n
	}

	snapshots := 10
	if rawSnaps := strings.TrimSpace(q.Get("snapshots")); rawSnaps != "" {
		n, err := strconv.Atoi(rawSnaps)
		if err != nil || n <= 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Failed to parse int parameter [snapshots] with value [%s]", rawSnaps))
			return
		}
		snapshots = n
	}
	_ = snapshots

	intervalRaw := strings.TrimSpace(q.Get("interval"))
	if intervalRaw == "" {
		intervalRaw = "500ms"
	} else if _, err := parseESPositiveDuration(intervalRaw); err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("failed to parse setting [interval] with value [%s] as a time value: %v", intervalRaw, err))
		return
	}

	for _, durParam := range []string{"timeout", "master_timeout"} {
		if rawDur := strings.TrimSpace(q.Get(durParam)); rawDur != "" {
			if _, err := parseESPositiveDuration(rawDur); err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("failed to parse setting [%s] with value [%s] as a time value: %v", durParam, rawDur, err))
				return
			}
		}
	}

	ignoreIdle := true
	if parsedIdle, hasIdle, err := parseStrictQueryBoolParamRound59(r, "ignore_idle_threads"); err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
		return
	} else if hasIdle {
		ignoreIdle = parsedIdle
	}

	ensureESCompatHeaders(w, r)
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if !localNodeMatchesFilterRound60(nodeFilter) {
		w.WriteHeader(http.StatusOK)
		return
	}

	body := fmt.Sprintf(
		"::: {%s}{%s}{%s}{%s}{%s}{%s}{cdfhilmrstw}\n   Hot threads at %s, interval=%s, busiestThreads=%d, ignoreIdleThreads=%t:\n\n",
		"doris-es-proxy",
		taskLocalNodeID,
		"doris-ephemeral-1",
		"localhost",
		"127.0.0.1",
		"127.0.0.1:9300",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		intervalRaw,
		threads,
		ignoreIdle,
	)
	if !ignoreIdle {
		body += fmt.Sprintf("   0.1%% [cpu=0.1%%, other=0.0%%] (%s out of %s) %s usage by thread 'doris-es-proxy[http_server_worker][T#1]'\n",
			"500micros", intervalRaw, typ)
	}

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	// #nosec G705 -- Content-Type is text/plain; charset=UTF-8 with X-Content-Type-Options: nosniff
	_, _ = w.Write([]byte(body))
}

// ============================================================================
// F1: `GET /_info` & `GET /_info/{target}` + `/_health_report`
// ============================================================================

var validClusterInfoTargetsRound61 = map[string]bool{
	"_all":         true,
	"http":         true,
	"ingest":       true,
	"thread_pool":  true,
	"script":       true,
	"aggregations": true,
	"plugins":      true,
}

var supportedIngestProcessorTypesRound61 = []string{
	"append", "attachment", "bytes", "circle", "community_id", "compact",
	"convert", "csv", "date", "date_index_name", "dedup", "dissect",
	"dot_expander", "drop", "enrich", "fail", "fingerprint", "foreach", "geo_grid",
	"geoip", "grok", "gsub", "html_strip", "inference", "join", "json",
	"kv", "lowercase", "network_direction", "pipeline", "redact",
	"registered_domain", "remove", "rename", "reroute", "script", "set",
	"set_security_user", "sort", "split", "terminate", "trim", "uppercase",
	"uri_parts", "urldecode", "urlencode", "user_agent",
}

var supportedAggregationTypesRound61 = []string{
	"adjacency_matrix", "auto_date_histogram", "avg", "avg_bucket", "boxplot",
	"bucket_correlation", "bucket_count_ks_test", "bucket_script", "bucket_selector", "bucket_sort",
	"cardinality", "categorize_text", "children", "composite", "cumulative_cardinality",
	"cumulative_sum", "date_histogram", "date_range", "derivative", "diversified_sampler",
	"ewma_moving_avg", "extended_stats", "extended_stats_bucket", "filter", "filters",
	"frequent_item_sets", "geo_bounds", "geo_centroid", "geo_distance", "geo_line",
	"geohash_grid", "geotile_grid", "global", "histogram", "holt_moving_avg",
	"holt_winters_moving_avg", "inference", "ip_prefix", "ip_range", "linear_moving_avg",
	"matrix_stats", "max", "max_bucket", "median_absolute_deviation", "min",
	"min_bucket", "missing", "moving_fn", "moving_percentiles", "multi_terms",
	"nested", "normalize", "parent", "percentile_ranks", "percentiles",
	"percentiles_bucket", "random_sampler", "range", "rare_terms", "rate",
	"reverse_nested", "sampler", "scripted_metric", "serial_diff", "significant_terms",
	"significant_text", "simple_moving_avg", "stats", "stats_bucket", "string_stats",
	"sum", "sum_bucket", "t_test", "terms", "time_series",
	"top_hits", "top_metrics", "value_count", "variable_width_histogram", "weighted_avg",
}

var clusterInfoThreadPoolNamesRound61 = []string{
	"analyze", "auto_complete", "cluster_coordination", "fetch_shard_store",
	"flush", "force_merge", "generic", "get", "management", "refresh",
	"search", "search_coordination", "search_throttled", "snapshot",
	"snapshot_meta", "system_critical_read", "system_critical_write",
	"system_read", "system_write", "warmer", "write",
}

func buildClusterIngestProcessorListRound61() []any {
	procs := make([]any, 0, len(supportedIngestProcessorTypesRound61))
	for _, pName := range supportedIngestProcessorTypesRound61 {
		procs = append(procs, map[string]any{"type": pName})
	}
	return procs
}

func buildClusterAggregationsInfoMapRound61() map[string]any {
	aggsMap := make(map[string]any, len(supportedAggregationTypesRound61))
	for _, at := range supportedAggregationTypesRound61 {
		aggsMap[at] = map[string]any{"types": []string{"other"}}
	}
	return aggsMap
}

// handleClusterInfoRound61 implements `GET/HEAD /_info` and `GET/HEAD /_info/{target}` (Wave-2 `server.go` hook).
func (s *Server) handleClusterInfoRound61(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	recordHTTPClientRequestRound61(s, r, r.ContentLength)

	reqPath := "/_info"
	if r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	targetRaw := strings.TrimSpace(r.PathValue("target"))
	if targetRaw == "" && strings.HasPrefix(reqPath, "/_info/") {
		targetRaw = strings.TrimSpace(strings.TrimPrefix(reqPath, "/_info/"))
	}

	selected := make(map[string]bool)
	if targetRaw == "" {
		for k := range validClusterInfoTargetsRound61 {
			if k != "_all" {
				selected[k] = true
			}
		}
	} else {
		rawParts := strings.Split(targetRaw, ",")
		tokens := make([]string, 0, len(rawParts))
		hasAll := false
		for _, p := range rawParts {
			tok := strings.TrimSpace(p)
			if tok == "" {
				continue
			}
			if !validClusterInfoTargetsRound61[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("request [%s] contains unrecognized target: [%s]", reqPath, tok))
				return
			}
			if tok == "_all" {
				hasAll = true
			}
			tokens = append(tokens, tok)
		}
		if hasAll && len(tokens) > 1 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [%s] contains _all and individual target [%s]", reqPath, targetRaw))
			return
		}
		if hasAll || len(tokens) == 0 {
			for k := range validClusterInfoTargetsRound61 {
				if k != "_all" {
					selected[k] = true
				}
			}
		} else {
			for _, tok := range tokens {
				selected[tok] = true
			}
		}
	}

	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	resp := map[string]any{
		"cluster_name": "apache-doris-search-cluster",
	}

	if selected["http"] {
		st := getOrCreateRound61AdminState(s)
		st.mu.RLock()
		clients := make([]any, 0, len(st.httpClients))
		for _, cl := range st.httpClients {
			cm := map[string]any{
				"id":                       cl.id,
				"agent":                    cl.agent,
				"local_address":            cl.localAddress,
				"remote_address":           cl.remoteAddress,
				"last_uri":                 cl.lastURI,
				"opened_time_millis":       cl.openedTimeMillis,
				"last_request_time_millis": cl.lastRequestTimeMillis,
				"request_count":            cl.requestCount,
				"request_size_bytes":       cl.requestSizeBytes,
			}
			if cl.xForwardedFor != "" {
				cm["x_forwarded_for"] = cl.xForwardedFor
			}
			if cl.xOpaqueID != "" {
				cm["x_opaque_id"] = cl.xOpaqueID
			}
			clients = append(clients, cm)
		}
		totalOpened := atomic.LoadInt64(&s.totalHTTPRequests)
		if int64(len(clients)) > totalOpened {
			totalOpened = int64(len(clients))
		}
		st.mu.RUnlock()
		resp["http"] = map[string]any{
			"current_open": len(clients),
			"total_opened": totalOpened,
			"clients":      clients,
			"routes":       map[string]any{},
		}
	}

	if selected["ingest"] {
		procs := buildClusterIngestProcessorListRound61()
		ingMap := s.buildNodeIngestStatsRound61(s.isES8Mode(r), isTruthyBoolQueryParam(r, "human"))
		if ingMap == nil {
			ingMap = make(map[string]any)
		}
		ingMap["processors"] = procs
		resp["ingest"] = ingMap
	}

	if selected["thread_pool"] {
		numCPU := runtime.NumCPU()
		tpMap := make(map[string]any, len(clusterInfoThreadPoolNamesRound61))
		for _, tpName := range clusterInfoThreadPoolNamesRound61 {
			tpMap[tpName] = map[string]any{
				"threads":   numCPU,
				"queue":     0,
				"active":    0,
				"rejected":  0,
				"largest":   numCPU,
				"completed": 1,
			}
		}
		resp["thread_pool"] = tpMap
	}

	if selected["script"] {
		resp["script"] = map[string]any{
			"compilations":                0,
			"cache_evictions":             0,
			"compilation_limit_triggered": 0,
		}
	}

	if selected["aggregations"] {
		aggsMap := make(map[string]any, len(supportedAggregationTypesRound61))
		for _, at := range supportedAggregationTypesRound61 {
			aggsMap[at] = map[string]any{"types": []string{"other"}}
		}
		resp["aggregations"] = aggsMap
	}

	if selected["plugins"] {
		resp["plugins"] = []any{}
	}

	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func lookupIndexRoutingAllocationEnableLocked(s *Server, idxName string) string {
	if s.indexCustomSettings != nil {
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, k := range []string{"routing.allocation.enable", "index.routing.allocation.enable"} {
				if v, ok := cust[k]; ok && v != nil {
					if sv := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v))); sv != "" {
						return sv
					}
				}
			}
		}
	}
	for _, m := range []map[string]any{s.clusterTransientSettings, s.clusterPersistentSettings} {
		if m == nil {
			continue
		}
		if v, ok := m["cluster.routing.allocation.enable"]; ok && v != nil {
			if sv := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v))); sv != "" {
				return sv
			}
		}
	}
	return "all"
}

func (s *Server) buildHealthReportResponseRound61(r *http.Request, segs []string) (int, string, string, map[string]any) {
	verbose := true
	if parsedV, hasV, err := parseStrictQueryBoolParamRound59(r, "verbose"); err != nil {
		return http.StatusBadRequest, "illegal_argument_exception", err.Error(), nil
	} else if hasV {
		verbose = parsedV
	}

	_ = s.syncCatalogFromBackend(r.Context())

	s.mu.RLock()
	repoCount := len(s.snapshotRepos)
	ilmState := s.ilmMode
	slmState := s.slmMode
	ilmPolicyCount := len(s.ilmPolicies)
	slmPolicyCount := len(s.slmPolicies)

	var startedPrimaries, unassignedPrimaries, startedReplicas, unassignedReplicas int
	var redAffectedIndices, yellowAffectedIndices []string
	openIdxCount := 0

	idxNames := make([]string, 0, len(s.indices))
	for idx := range s.indices {
		idxNames = append(idxNames, idx)
	}
	sort.Strings(idxNames)

	for _, idxName := range idxNames {
		if s.closedIndices[idxName] {
			continue
		}
		openIdxCount++
		numShards := 1
		numReplicas := 0
		explicitZeroReplicas := false
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, sk := range []string{"number_of_shards", "index.number_of_shards"} {
				if v, ok := cust[sk]; ok {
					if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil && n > 0 {
						numShards = n
					}
				}
			}
			for _, rk := range []string{"number_of_replicas", "index.number_of_replicas"} {
				if v, ok := cust[rk]; ok {
					if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil && n >= 0 {
						numReplicas = n
						if n == 0 {
							explicitZeroReplicas = true
						}
					}
				}
			}
		}
		allocMode := lookupIndexRoutingAllocationEnableLocked(s, idxName)
		hasIndexedOps := false
		if s.indexStats != nil && s.indexStats[idxName] != nil && s.indexStats[idxName].indexTotal.Load() > 0 {
			hasIndexedOps = true
		}

		if allocMode == "none" {
			if explicitZeroReplicas && !hasIndexedOps {
				unassignedPrimaries += numShards
				redAffectedIndices = append(redAffectedIndices, idxName)
			} else {
				startedPrimaries += numShards
				repUnassigned := numReplicas
				if repUnassigned == 0 {
					repUnassigned = 1
				}
				unassignedReplicas += repUnassigned
				yellowAffectedIndices = append(yellowAffectedIndices, idxName)
			}
		} else if allocMode == "primaries" && numReplicas > 0 {
			startedPrimaries += numShards
			unassignedReplicas += numReplicas
			yellowAffectedIndices = append(yellowAffectedIndices, idxName)
		} else {
			startedPrimaries += numShards
			startedReplicas += numReplicas
		}
	}
	s.mu.RUnlock()

	if ilmState == "" {
		ilmState = "RUNNING"
	}
	if slmState == "" {
		slmState = "RUNNING"
	}

	mkInd := func(status, symptom string, details map[string]any, impacts []any, diagnosis []any) map[string]any {
		ind := map[string]any{
			"status":  status,
			"symptom": symptom,
		}
		if verbose {
			if details != nil {
				ind["details"] = details
			}
			if len(impacts) > 0 {
				ind["impacts"] = impacts
			}
			if len(diagnosis) > 0 {
				ind["diagnosis"] = diagnosis
			}
		}
		return ind
	}

	repoSymptom := "No snapshot repositories configured."
	if repoCount > 0 {
		repoSymptom = "No corrupted repositories found."
	}

	shardsStatus := "green"
	shardsSymptom := "This cluster has all shards available."
	var shardsImpacts []any
	var shardsDiagnosis []any

	if unassignedPrimaries > 0 {
		shardsStatus = "red"
		if unassignedPrimaries == 1 {
			shardsSymptom = "This cluster has 1 unavailable primary shard."
		} else {
			shardsSymptom = fmt.Sprintf("This cluster has %d unavailable primary shards.", unassignedPrimaries)
		}
		affected := append([]string{}, redAffectedIndices...)
		affected = append(affected, yellowAffectedIndices...)
		shardsImpacts = []any{
			map[string]any{
				"id":          "elasticsearch:health:shards_availability:impact:read_and_write",
				"severity":    1,
				"description": "Cannot add data to or search some indices. Searches might return incomplete results.",
				"impact_areas": []string{
					"deployment_management",
					"ingest",
					"search",
				},
			},
		}
		shardsDiagnosis = []any{
			map[string]any{
				"id":       "elasticsearch:health:shards_availability:diagnosis:allocation_blocked_by_settings",
				"cause":    "Shard allocation isn't enabled for all shards.",
				"action":   "Enable shard allocation by updating the [index.routing.allocation.enable] index setting or [cluster.routing.allocation.enable] cluster setting.",
				"help_url": "https://ela.st/enable-shard-allocation",
				"affected_resources": map[string]any{
					"indices": affected,
				},
			},
		}
	} else if unassignedReplicas > 0 {
		shardsStatus = "yellow"
		if unassignedReplicas == 1 {
			shardsSymptom = "This cluster has 1 unassigned replica."
		} else {
			shardsSymptom = fmt.Sprintf("This cluster has %d unassigned replicas.", unassignedReplicas)
		}
		shardsImpacts = []any{
			map[string]any{
				"id":          "elasticsearch:health:shards_availability:impact:missing_replicas",
				"severity":    2,
				"description": "Data is no longer redundant on missing replica shards, increasing the risk of data loss. Search throughput might be impacted.",
				"impact_areas": []string{
					"search",
				},
			},
		}
		shardsDiagnosis = []any{
			map[string]any{
				"id":       "elasticsearch:health:shards_availability:diagnosis:allocation_blocked_by_settings",
				"cause":    "Replica shard allocation isn't enabled for all shards.",
				"action":   "Enable shard allocation by updating the [index.routing.allocation.enable] index setting or [cluster.routing.allocation.enable] cluster setting.",
				"help_url": "https://ela.st/enable-shard-allocation",
				"affected_resources": map[string]any{
					"indices": yellowAffectedIndices,
				},
			},
		}
	}

	shardsDetails := map[string]any{
		"creating_primaries":     0,
		"initializing_primaries": 0,
		"restarting_primaries":   0,
		"started_primaries":      startedPrimaries,
		"unassigned_primaries":   unassignedPrimaries,
		"creating_replicas":      0,
		"initializing_replicas":  0,
		"restarting_replicas":    0,
		"started_replicas":       startedReplicas,
		"unassigned_replicas":    unassignedReplicas,
	}

	indicators := map[string]any{
		"master_is_stable": mkInd("green", "The cluster has a stable master node", map[string]any{
			"current_master": map[string]any{"node_id": taskLocalNodeID, "name": "doris-es-proxy"},
			"recent_masters": []any{map[string]any{"node_id": taskLocalNodeID, "name": "doris-es-proxy"}},
		}, nil, nil),
		"repository_integrity": mkInd("green", repoSymptom, map[string]any{
			"total_repositories": repoCount,
		}, nil, nil),
		"shards_availability": mkInd(shardsStatus, shardsSymptom, shardsDetails, shardsImpacts, shardsDiagnosis),
		"shards_capacity": mkInd("green", "The cluster has enough room to add new shards.", map[string]any{
			"data": map[string]any{
				"max_shards_in_cluster": 1000,
				"current_used_shards":   startedPrimaries + startedReplicas,
			},
			"frozen": map[string]any{
				"max_shards_in_cluster": 1000,
				"current_used_shards":   0,
			},
		}, nil, nil),
		"disk": mkInd("green", "The cluster has enough available disk space.", map[string]any{
			"indices_with_readonly_block":      0,
			"nodes_with_enough_disk_space":     1,
			"nodes_over_high_watermark":        0,
			"nodes_over_flood_stage_watermark": 0,
			"nodes_with_unknown_disk_status":   0,
		}, nil, nil),
		"ilm": mkInd("green", "Index Lifecycle Management is running", map[string]any{
			"policies":       ilmPolicyCount,
			"stagnant_steps": 0,
			"ilm_status":     ilmState,
		}, nil, nil),
		"slm": mkInd("green", "Snapshot Lifecycle Management is running", map[string]any{
			"slm_status": slmState,
			"policies":   slmPolicyCount,
		}, nil, nil),
		"data_stream_lifecycle": mkInd("green", "Data stream lifecycle is running", map[string]any{
			"stagnant_data_streams_count": 0,
			"total_error_count":           0,
		}, nil, nil),
	}
	_ = openIdxCount

	indName := ""
	if len(segs) >= 2 && strings.TrimSpace(segs[1]) != "" {
		indName = strings.TrimSpace(segs[1])
	} else if f := strings.TrimSpace(r.PathValue("feature")); f != "" {
		indName = f
	}
	if indName != "" {
		indObj, exists := indicators[indName]
		if !exists {
			return http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("unknown health indicator [%s]", indName), nil
		}
		indMap, _ := indObj.(map[string]any)
		stStr, _ := indMap["status"].(string)
		if stStr == "" {
			stStr = "green"
		}
		return http.StatusOK, "", "", map[string]any{
			"cluster_name": "apache-doris-search-cluster",
			"status":       stStr,
			"indicators": map[string]any{
				indName: indObj,
			},
		}
	}

	overallStatus := shardsStatus
	return http.StatusOK, "", "", map[string]any{
		"cluster_name": "apache-doris-search-cluster",
		"status":       overallStatus,
		"indicators":   indicators,
	}
}

// ============================================================================
// F3 & F4: Live `/_stats`, `/_disk_usage`, `/_field_usage_stats` & Node Ingest
// ============================================================================

func isIndexSyntheticSourceLocked(idxSchema *schema.IndexSchema) bool {
	if idxSchema == nil || idxSchema.RawMapping == nil || idxSchema.RawMapping.Source == nil {
		return false
	}
	modeStr, _ := idxSchema.RawMapping.Source["mode"].(string)
	return strings.EqualFold(strings.TrimSpace(modeStr), "synthetic")
}

func isIndexSourceDisabledLocked(idxSchema *schema.IndexSchema) bool {
	if idxSchema == nil || idxSchema.RawMapping == nil || idxSchema.RawMapping.Source == nil {
		return false
	}
	if en, ok := idxSchema.RawMapping.Source["enabled"].(bool); ok && !en {
		return true
	}
	return false
}

type round61IndexedDoc struct {
	ID     string
	Source map[string]any
}

func (s *Server) collectIndexedDocsWithIDsRound61(ctx context.Context, indexName string, aliasFilter *esast.Query) []round61IndexedDoc {
	if s == nil || s.backend == nil {
		return nil
	}
	if aliasFilter == nil {
		s.mu.RLock()
		sc := s.indices[indexName]
		isClosed := s.closedIndices[indexName]
		delMap := make(map[string]bool, len(s.docDeleted[indexName]))
		for id, del := range s.docDeleted[indexName] {
			if del {
				delMap[id] = true
			}
		}
		s.mu.RUnlock()
		if sc == nil || isClosed {
			return nil
		}
		_ = s.coalescer.FlushTable(ctx, sc.DorisTable)
		opts := s.transpileOpts
		opts.MaxResultWindow = 1_000_000
		tr := transpiler.NewTranspiler(sc, opts)
		batchSize := 10000
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
			Size:           &batchSize,
			TrackTotalHits: false,
			Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
		})
		if err == nil && plan.HitsSQL != "" {
			if hits, qErr := s.backend.QueryHits(ctx, plan.HitsSQL); qErr == nil {
				out := make([]round61IndexedDoc, 0, len(hits))
				for _, h := range hits {
					if delMap[h.ID] {
						continue
					}
					rawSrc := h.EffectiveSource()
					var srcMap map[string]any
					if len(rawSrc) > 0 {
						dec := json.NewDecoder(bytes.NewReader(rawSrc))
						dec.UseNumber()
						_ = dec.Decode(&srcMap)
					}
					out = append(out, round61IndexedDoc{
						ID:     h.ID,
						Source: srcMap,
					})
				}
				return out
			}
		}
	}

	scanLimit := 10000
	resp, _, errType, _ := s.executeSearchRequest(ctx, indexName, &esast.SearchRequest{
		Size:           &scanLimit,
		TrackTotalHits: true,
		AliasFilter:    aliasFilter,
	})
	if errType != "" || resp == nil {
		return nil
	}
	hitsEnv, ok := resp["hits"].(map[string]any)
	if !ok {
		return nil
	}
	var out []round61IndexedDoc
	extractHit := func(h map[string]any) {
		docID, _ := h["_id"].(string)
		var srcMap map[string]any
		switch sv := h["_source"].(type) {
		case json.RawMessage:
			dec := json.NewDecoder(bytes.NewReader(sv))
			dec.UseNumber()
			_ = dec.Decode(&srcMap)
		case map[string]any:
			srcMap = sv
		}
		out = append(out, round61IndexedDoc{
			ID:     docID,
			Source: srcMap,
		})
	}
	switch hl := hitsEnv["hits"].(type) {
	case []map[string]any:
		for _, h := range hl {
			extractHit(h)
		}
	case []any:
		for _, item := range hl {
			if h, okH := item.(map[string]any); okH {
				extractHit(h)
			}
		}
	}
	return out
}

func lookupFieldESTypeRound61(idxSchema *schema.IndexSchema, fieldPath string) string {
	if idxSchema == nil || idxSchema.Fields == nil {
		return ""
	}
	if fb, ok := idxSchema.Fields[fieldPath]; ok {
		if fb.ESType != "" {
			return fb.ESType
		}
		switch fb.DorisType {
		case schema.DorisBigInt:
			return "long"
		case schema.DorisDouble:
			return "double"
		case schema.DorisBoolean:
			return "boolean"
		case schema.DorisVarchar:
			return "keyword"
		case schema.DorisString:
			return "text"
		default:
			if strings.HasPrefix(strings.ToUpper(string(fb.DorisType)), "DATE") {
				return "date"
			}
		}
	}
	return ""
}

func isNumericOrDateESTypeRound61(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "unsigned_long", "date", "date_nanos", "ip":
		return true
	default:
		return false
	}
}

func (s *Server) computeAdjustedLiveDocCountRound61(ctx context.Context, indexName string) (docCount int64, deletedCount int64, storeBytes int64) {
	rawCount, rawBytes := s.computeLiveIndexDocCountAndStoreBytesRound59(ctx, indexName, true)

	s.mu.RLock()
	var unrefDelta int64
	var delCnt int64
	deletedMap := s.docDeleted[indexName]
	for _, isDel := range deletedMap {
		if isDel {
			delCnt++
		}
	}
	if s.unrefreshedDocs != nil {
		for _, shardMap := range s.unrefreshedDocs[indexName] {
			for docID, ust := range shardMap {
				currentlyDeleted := deletedMap != nil && deletedMap[docID]
				if !ust.existedBefore && !currentlyDeleted {
					// Newly created since last refresh -> not yet visible in refreshed docs.count!
					unrefDelta--
				} else if ust.existedBefore && currentlyDeleted {
					// Deleted since last refresh -> still visible until refresh!
					unrefDelta++
					if delCnt > 0 {
						delCnt--
					}
				}
			}
		}
	}
	s.mu.RUnlock()

	adjCount := rawCount + unrefDelta
	if adjCount < 0 {
		adjCount = 0
	}
	if rawBytes == 0 && adjCount > 0 {
		rawBytes = adjCount * 256
	}
	if adjCount == 0 && unrefDelta < 0 {
		rawBytes = 208
	}
	return adjCount, delCnt, rawBytes
}

type diskUsageBucketRound61 struct {
	total        int64
	inverted     int64
	storedFields int64
	docValues    int64
	points       int64
	norms        int64
	termVectors  int64
	knnVectors   int64
}

func (b *diskUsageBucketRound61) add(other diskUsageBucketRound61) {
	b.total += other.total
	b.inverted += other.inverted
	b.storedFields += other.storedFields
	b.docValues += other.docValues
	b.points += other.points
	b.norms += other.norms
	b.termVectors += other.termVectors
	b.knnVectors += other.knnVectors
}

func (b diskUsageBucketRound61) toMap(human bool) map[string]any {
	inv := map[string]any{
		"total_in_bytes": b.inverted,
	}
	if human {
		inv["total"] = formatBytesHuman(b.inverted)
	}
	m := map[string]any{
		"total_in_bytes":         b.total,
		"inverted_index":         inv,
		"stored_fields_in_bytes": b.storedFields,
		"doc_values_in_bytes":    b.docValues,
		"points_in_bytes":        b.points,
		"norms_in_bytes":         b.norms,
		"term_vectors_in_bytes":  b.termVectors,
		"knn_vectors_in_bytes":   b.knnVectors,
	}
	if human {
		m["total"] = formatBytesHuman(b.total)
		m["stored_fields"] = formatBytesHuman(b.storedFields)
		m["doc_values"] = formatBytesHuman(b.docValues)
		m["points"] = formatBytesHuman(b.points)
		m["norms"] = formatBytesHuman(b.norms)
		m["term_vectors"] = formatBytesHuman(b.termVectors)
		m["knn_vectors"] = formatBytesHuman(b.knnVectors)
	}
	return m
}

func flattenDocFieldValuesRound61(prefix string, m map[string]any, out map[string][]any) {
	for k, v := range m {
		if v == nil {
			continue
		}
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch tv := v.(type) {
		case map[string]any:
			flattenDocFieldValuesRound61(path, tv, out)
		case []any:
			if len(tv) == 0 {
				continue
			}
			isNumericVec := true
			for _, elem := range tv {
				switch elem.(type) {
				case float64, int, int64, json.Number:
				default:
					isNumericVec = false
				}
			}
			if isNumericVec {
				out[path] = append(out[path], tv)
			}
			for _, elem := range tv {
				if subM, okM := elem.(map[string]any); okM {
					flattenDocFieldValuesRound61(path, subM, out)
				} else if elem != nil {
					out[path] = append(out[path], elem)
				}
			}
		default:
			out[path] = append(out[path], tv)
		}
	}
}

func (s *Server) computeIndexDiskUsageRound61(ctx context.Context, indexName string, human bool) map[string]any {
	docs := s.collectIndexedDocsWithIDsRound61(ctx, indexName, nil)

	s.mu.RLock()
	idxSchema := s.indices[indexName]
	isSynthetic := isIndexSyntheticSourceLocked(idxSchema)
	isSourceDisabled := isIndexSourceDisabledLocked(idxSchema)
	var rawProps map[string]esast.FieldProperty
	if idxSchema != nil && idxSchema.RawMapping != nil {
		rawProps = idxSchema.RawMapping.Properties
	}
	s.mu.RUnlock()

	fieldsBuckets := make(map[string]*diskUsageBucketRound61)
	ensureBucket := func(fn string) *diskUsageBucketRound61 {
		b := fieldsBuckets[fn]
		if b == nil {
			b = &diskUsageBucketRound61{}
			fieldsBuckets[fn] = b
		}
		return b
	}

	var lookupRawProp func(props map[string]esast.FieldProperty, path string) (esast.FieldProperty, bool)
	lookupRawProp = func(props map[string]esast.FieldProperty, path string) (esast.FieldProperty, bool) {
		if len(props) == 0 {
			return esast.FieldProperty{}, false
		}
		if p, ok := props[path]; ok {
			return p, true
		}
		if dot := strings.IndexByte(path, '.'); dot > 0 {
			head, tail := path[:dot], path[dot+1:]
			if p, ok := props[head]; ok {
				if len(p.Properties) > 0 {
					if sp, okS := lookupRawProp(p.Properties, tail); okS {
						return sp, true
					}
				}
				if len(p.Fields) > 0 {
					if sf, okF := p.Fields[tail]; okF {
						return sf, true
					}
				}
			}
		}
		return esast.FieldProperty{}, false
	}

	docCount := len(docs)
	if docCount > 0 {
		idB := ensureBucket("_id")
		seqB := ensureBucket("_seq_no")
		ptB := ensureBucket("_primary_term")
		verB := ensureBucket("_version")
		for _, d := range docs {
			idLen := int64(len(d.ID))
			if idLen < 4 {
				idLen = 4
			}
			idB.inverted += idLen + 8
			idB.storedFields += idLen + 4
			idB.total += idLen*2 + 12

			seqB.points += 8
			seqB.docValues += 8
			seqB.total += 16

			ptB.docValues += 4
			ptB.total += 4

			verB.docValues += 4
			verB.total += 4

			if !isSynthetic && !isSourceDisabled {
				rawSrc, _ := json.Marshal(d.Source)
				srcLen := int64(len(rawSrc))
				if srcLen < 2 {
					srcLen = 2
				}
				srcB := ensureBucket("_source")
				srcB.storedFields += srcLen
				srcB.total += srcLen
			}

			flatVals := make(map[string][]any)
			flattenDocFieldValuesRound61("", d.Source, flatVals)
			for fPath, vals := range flatVals {
				if len(vals) == 0 {
					continue
				}
				var fb schema.FieldBinding
				hasFB := false
				if idxSchema != nil {
					fb, hasFB = idxSchema.Fields[fPath]
				}
				rawP, hasRawP := lookupRawProp(rawProps, fPath)

				esType := fb.ESType
				if esType == "" && hasRawP {
					esType = strings.ToLower(strings.TrimSpace(rawP.Type))
				}
				if esType == "" {
					switch vals[0].(type) {
					case []any:
						esType = "dense_vector"
					case bool:
						esType = "boolean"
					case float64, int, int64, json.Number:
						esType = "long"
					default:
						esType = "text"
					}
				}
				docValuesOff := fb.DocValuesFalse || (hasRawP && rawP.DocValues != nil && !*rawP.DocValues)
				notIndexed := fb.NotIndexed || (hasRawP && rawP.Index != nil && !*rawP.Index)
				storeOn := hasRawP && rawP.Store != nil && *rawP.Store
				tvOn := false

				b := ensureBucket(fPath)
				valBytes := int64(0)
				for _, v := range vals {
					rawV, _ := json.Marshal(v)
					if int64(len(rawV)) > 0 {
						valBytes += int64(len(rawV))
					} else {
						valBytes += 8
					}
				}
				if valBytes < 8 {
					valBytes = 8
				}

				switch esType {
				case "dense_vector", "knn_vector":
					b.knnVectors += valBytes + 12
					if !docValuesOff {
						b.docValues += valBytes
					}
				case "text", "match_only_text", "search_as_you_type":
					if !notIndexed {
						b.inverted += valBytes + 8
						if esType != "match_only_text" {
							b.norms += 4
						}
					}
					if storeOn {
						b.storedFields += valBytes
					}
					if tvOn {
						b.termVectors += valBytes + 8
					}
					if hasFB && fb.KeywordCompanion != "" {
						kwB := ensureBucket(fPath + ".keyword")
						kwB.inverted += valBytes + 4
						kwB.docValues += valBytes + 4
						kwB.total = kwB.inverted + kwB.docValues
					}
				case "keyword", "constant_keyword", "wildcard", "flattened":
					if !notIndexed {
						b.inverted += valBytes + 4
					}
					if !docValuesOff {
						b.docValues += valBytes + 4
					}
					if storeOn {
						b.storedFields += valBytes
					}
				case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "unsigned_long", "date", "date_nanos", "ip":
					if !notIndexed {
						b.points += 8 * int64(len(vals))
					}
					if !docValuesOff {
						b.docValues += 8 * int64(len(vals))
					}
					if storeOn {
						b.storedFields += valBytes
					}
				case "boolean":
					if !notIndexed {
						b.inverted += 4 * int64(len(vals))
					}
					if !docValuesOff {
						b.docValues += 4 * int64(len(vals))
					}
				default:
					if !notIndexed {
						b.inverted += valBytes
					}
					if !docValuesOff {
						b.docValues += valBytes
					}
				}
				b.total = b.inverted + b.storedFields + b.docValues + b.points + b.norms + b.termVectors + b.knnVectors
			}
		}
	}

	if isSynthetic {
		// Synthetic _source: omit stored `_source` (`is_false: test.fields._source` in `update/100_synthetic_source.yml`)
		// and expose `_recovery_source` with 0 bytes (`is_true: test.fields._recovery_source`)!
		delete(fieldsBuckets, "_source")
		fieldsBuckets["_recovery_source"] = &diskUsageBucketRound61{}
	}

	var allBucket diskUsageBucketRound61
	fieldsMap := make(map[string]any, len(fieldsBuckets))
	for fn, b := range fieldsBuckets {
		allBucket.add(*b)
		fieldsMap[fn] = b.toMap(human)
	}
	storeSize := allBucket.total + int64(208)
	if docCount == 0 && !isSynthetic {
		storeSize = 208
	}
	out := map[string]any{
		"store_size_in_bytes": storeSize,
		"all_fields":          allBucket.toMap(human),
		"fields":              fieldsMap,
	}
	if human {
		out["store_size"] = formatBytesHuman(storeSize)
	}
	return out
}

func formatFieldUsageEntryRound61(c round61FieldUsageCounters) map[string]any {
	return map[string]any{
		"any": c.anyCount,
		"inverted_index": map[string]any{
			"terms":            c.terms,
			"postings":         c.postings,
			"proximity":        c.proximity,
			"term_frequencies": c.termFrequencies,
			"positions":        c.positions,
			"offsets":          c.offsets,
			"payloads":         c.payloads,
		},
		"stored_fields": c.storedFields,
		"doc_values":    c.docValues,
		"points":        c.points,
		"norms":         c.norms,
		"term_vectors":  c.termVectors,
		"knn_vectors":   c.knnVectors,
	}
}

func (s *Server) computeIndexFieldUsageStatsRound61(ctx context.Context, indexName string) map[string]any {
	st := getOrCreateRound61AdminState(s)
	s.mu.RLock()
	idxSchema := s.indices[indexName]
	isSynthetic := isIndexSyntheticSourceLocked(idxSchema)
	s.mu.RUnlock()

	numShards, _, _ := s.getIndexShardAndReplicaCounts(indexName)
	if numShards <= 0 {
		numShards = 1
	}

	st.mu.RLock()
	startedAt := st.startedAtMillis
	recorded := make(map[string]round61FieldUsageCounters)
	for fn, fc := range st.fieldAccesses[indexName] {
		if fc != nil {
			recorded[fn] = *fc
		}
	}
	st.mu.RUnlock()

	if isSynthetic {
		recorded["_source"] = round61FieldUsageCounters{}
		recorded["_recovery_source"] = round61FieldUsageCounters{}
	}

	var allFields round61FieldUsageCounters
	fieldsOut := make(map[string]any, len(recorded))
	for fn, fc := range recorded {
		allFields.anyCount += fc.anyCount
		allFields.terms += fc.terms
		allFields.postings += fc.postings
		allFields.proximity += fc.proximity
		allFields.storedFields += fc.storedFields
		allFields.docValues += fc.docValues
		allFields.points += fc.points
		allFields.norms += fc.norms
		allFields.termVectors += fc.termVectors
		allFields.knnVectors += fc.knnVectors
		allFields.termFrequencies += fc.termFrequencies
		allFields.positions += fc.positions
		allFields.offsets += fc.offsets
		allFields.payloads += fc.payloads
		fieldsOut[fn] = formatFieldUsageEntryRound61(fc)
	}

	shardsList := make([]any, 0, numShards)
	for sh := 0; sh < numShards; sh++ {
		shFields := fieldsOut
		shAll := formatFieldUsageEntryRound61(allFields)
		if sh > 0 {
			shFields = map[string]any{}
			shAll = formatFieldUsageEntryRound61(round61FieldUsageCounters{})
		}
		shardsList = append(shardsList, map[string]any{
			"tracking_id":                fmt.Sprintf("%s-%d", indexName, sh),
			"tracking_started_at_millis": startedAt,
			"routing": map[string]any{
				"state":   "STARTED",
				"primary": true,
				"node":    taskLocalNodeID,
			},
			"stats": map[string]any{
				"all_fields": shAll,
				"fields":     shFields,
			},
		})
	}
	_ = ctx
	return map[string]any{
		"shards": shardsList,
	}
}

func (s *Server) buildNodeIngestStatsRound61(isES8, human bool) map[string]any {
	live := s.buildLiveIngestNodeStats(human)
	st := getOrCreateRound61AdminState(s)
	st.mu.RLock()
	extraTotal := st.ingestTotal
	extraPipes := make(map[string]*round61PipelineStats, len(st.ingestPipelines))
	for pid, ps := range st.ingestPipelines {
		if ps != nil {
			cp := *ps
			cp.processors = make([]*round61ProcessorStat, len(ps.processors))
			for i, p := range ps.processors {
				if p != nil {
					pCopy := *p
					cp.processors[i] = &pCopy
				}
			}
			extraPipes[pid] = &cp
		}
	}
	st.mu.RUnlock()

	if totalMap, ok := live["total"].(map[string]any); ok && extraTotal.count > 0 {
		curCnt, _ := toInt64(totalMap["count"])
		curTime, _ := toInt64(totalMap["time_in_millis"])
		curCur, _ := toInt64(totalMap["current"])
		curFail, _ := toInt64(totalMap["failed"])
		newTime := curTime + extraTotal.timeInMillis
		totalMap["count"] = curCnt + extraTotal.count
		totalMap["time_in_millis"] = newTime
		totalMap["current"] = curCur + extraTotal.current
		totalMap["failed"] = curFail + extraTotal.failed
		if human {
			totalMap["time"] = formatDurationNanosHumanRound61(newTime * 1_000_000)
		}
	}

	pipesMap, _ := live["pipelines"].(map[string]any)
	if pipesMap == nil {
		pipesMap = make(map[string]any)
		live["pipelines"] = pipesMap
	}
	for pid, ps := range extraPipes {
		existing, ok := pipesMap[pid].(map[string]any)
		if !ok || existing == nil {
			procsOut := make([]map[string]any, 0, len(ps.processors))
			for _, pr := range ps.processors {
				pst := map[string]any{
					"count":          pr.stats.count,
					"time_in_millis": pr.stats.timeInMillis,
					"current":        pr.stats.current,
					"failed":         pr.stats.failed,
				}
				if human {
					pst["time"] = formatDurationNanosHumanRound61(pr.stats.timeInMillis * 1_000_000)
				}
				procsOut = append(procsOut, map[string]any{
					pr.procType: map[string]any{
						"type":  pr.procType,
						"stats": pst,
					},
				})
			}
			pm := map[string]any{
				"count":                               ps.counters.count,
				"time_in_millis":                      ps.counters.timeInMillis,
				"current":                             ps.counters.current,
				"failed":                              ps.counters.failed,
				"ingested_in_bytes":                   ps.counters.ingestedFirstBytes,
				"produced_in_bytes":                   ps.counters.producedFirstBytes,
				"ingested_as_first_pipeline_in_bytes": ps.counters.ingestedFirstBytes,
				"produced_as_first_pipeline_in_bytes": ps.counters.producedFirstBytes,
				"produced_as_final_pipeline_in_bytes": ps.counters.producedFirstBytes,
				"processors":                          procsOut,
			}
			if human {
				pm["time"] = formatDurationNanosHumanRound61(ps.counters.timeInMillis * 1_000_000)
				pm["ingested"] = formatBytesHuman(ps.counters.ingestedFirstBytes)
				pm["produced"] = formatBytesHuman(ps.counters.producedFirstBytes)
				pm["ingested_as_first_pipeline"] = formatBytesHuman(ps.counters.ingestedFirstBytes)
				pm["produced_as_first_pipeline"] = formatBytesHuman(ps.counters.producedFirstBytes)
				pm["produced_as_final_pipeline"] = formatBytesHuman(ps.counters.producedFirstBytes)
			}
			pipesMap[pid] = pm
		} else if ps.counters.count > 0 {
			curCnt, _ := toInt64(existing["count"])
			curTime, _ := toInt64(existing["time_in_millis"])
			curFail, _ := toInt64(existing["failed"])
			existing["count"] = curCnt + ps.counters.count
			existing["time_in_millis"] = curTime + ps.counters.timeInMillis
			existing["failed"] = curFail + ps.counters.failed
		}
	}

	if !isES8 {
		for _, rawPM := range pipesMap {
			if pm, ok := rawPM.(map[string]any); ok {
				delete(pm, "ingested_in_bytes")
				delete(pm, "produced_in_bytes")
				delete(pm, "ingested_as_first_pipeline_in_bytes")
				delete(pm, "produced_as_first_pipeline_in_bytes")
				delete(pm, "produced_as_final_pipeline_in_bytes")
				delete(pm, "ingested")
				delete(pm, "produced")
				delete(pm, "ingested_as_first_pipeline")
				delete(pm, "produced_as_first_pipeline")
				delete(pm, "produced_as_final_pipeline")
			}
		}
	}
	return live
}

func countFieldPropertiesMappersRound61(props map[string]esast.FieldProperty) int64 {
	var total int64
	for _, prop := range props {
		total++
		if len(prop.Fields) > 0 {
			total += countFieldPropertiesMappersRound61(prop.Fields)
		}
		if len(prop.Properties) > 0 {
			total += countFieldPropertiesMappersRound61(prop.Properties)
		}
	}
	return total
}

func countIndexMappingMappersRound61(idxSchema *schema.IndexSchema) int64 {
	if idxSchema == nil {
		return 0
	}
	const baseMetadataMappers int64 = 14
	if idxSchema.RawMapping != nil {
		return baseMetadataMappers +
			countFieldPropertiesMappersRound61(idxSchema.RawMapping.Properties) +
			int64(len(idxSchema.RawMapping.Runtime))
	}
	return baseMetadataMappers + int64(len(idxSchema.Fields))
}

func parseRequestedNodeIndexStatMetricsRound61(raw, reqPath string) (map[string]bool, error) {
	validNodeIdx := make(map[string]bool, len(validIndexStatMetricsRound60)+2)
	for k, v := range validIndexStatMetricsRound60 {
		validNodeIdx[k] = v
	}
	validNodeIdx["shard_stats"] = true
	validNodeIdx["mappings"] = true

	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "_all" || raw == "*" {
		all := make(map[string]bool, len(validNodeIdx))
		for k := range validNodeIdx {
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
		if !validNodeIdx[tok] {
			return nil, formatUnrecognizedMetricErrorRound61(reqPath, tok, validNodeIdx)
		}
		if tok == "_all" {
			for k := range validNodeIdx {
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

func decorateStoreStatsHumanRound61(sec map[string]any, human bool) {
	if !human || sec == nil {
		return
	}
	if storeMap, ok := sec["store"].(map[string]any); ok {
		sz, _ := toInt64(storeMap["size_in_bytes"])
		tds, _ := toInt64(storeMap["total_data_set_size_in_bytes"])
		res, _ := toInt64(storeMap["reserved_in_bytes"])
		storeMap["size"] = formatBytesHuman(sz)
		storeMap["total_data_set_size"] = formatBytesHuman(tds)
		storeMap["reserved"] = formatBytesHuman(res)
	}
}

func (s *Server) buildNodesStatsIndicesSectionRound61(r *http.Request, idxMetrics map[string]bool) (nodeIndices map[string]any, totalShards int, totalStoreBytes int64, errStatus int, errType string, errReason string) {
	level := "node"
	if r != nil && r.URL != nil {
		if lv := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level"))); lv != "" {
			if lv != "node" && lv != "indices" && lv != "shards" {
				return nil, 0, 0, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unrecognized level: [%s]", lv)
			}
			level = lv
		}
	}
	human := isTruthyBoolQueryParam(r, "human")
	isES8 := s.isES8Mode(r)
	includeSegFiles := isTruthyBoolQueryParam(r, "include_segment_file_sizes")
	includeUnloaded := isTruthyBoolQueryParam(r, "include_unloaded_segments")
	groups, types, hasFD, fdPats, hasComp, compPats := parseStatsFieldAndGroupParamsRound61(r)

	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	openIndices := make([]string, 0, len(s.indices))
	schemasByIdx := make(map[string]*schema.IndexSchema, len(s.indices))
	shardsByIdx := make(map[string]int, len(s.indices))
	liveStatsByIdx := make(map[string]*indexLiveStats, len(s.indices))
	for idxName, sc := range s.indices {
		if s.closedIndices[idxName] || strings.HasPrefix(idxName, ".") {
			continue
		}
		openIndices = append(openIndices, idxName)
		schemasByIdx[idxName] = sc
		ns := 1
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, sk := range []string{"number_of_shards", "index.number_of_shards"} {
				if v, ok := cust[sk]; ok {
					if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil && n > 0 {
						ns = n
					}
				}
			}
		}
		shardsByIdx[idxName] = ns
		if s.indexStats != nil {
			liveStatsByIdx[idxName] = s.indexStats[idxName]
		}
	}
	s.mu.RUnlock()
	sort.Strings(openIndices)

	adminSt := getOrCreateRound61AdminState(s)
	adminSt.mu.RLock()
	anyRecordedGroupsInSrv := len(adminSt.searchGroups) > 0
	adminSt.mu.RUnlock()

	var aggDocs, aggDeleted int64
	var aggFieldMappers int64
	var aggLive indexLiveStats
	aggFD := make(map[string]int64)
	var aggTotalFD int64
	aggComp := make(map[string]int64)
	var aggTotalComp int64
	aggGroups := make(map[string]*round61SearchGroupCounters)
	aggDocTypes := make(map[string]*round61DocTypeCounters)
	var aggTlogOps, aggTlogUncommOps, aggTlogBytes, aggTlogUncommBytes int64
	hasAggTlog := false

	type perIdxSnap struct {
		docs, del, bytes int64
		mappers          int64
		numShards        int
		liveSt           *indexLiveStats
		renderOpts       indexStatsRenderOptionsRound61
	}
	perIdxData := make(map[string]perIdxSnap, len(openIndices))

	for _, idxName := range openIndices {
		ns := shardsByIdx[idxName]
		totalShards += ns
		mappers := countIndexMappingMappersRound61(schemasByIdx[idxName])
		aggFieldMappers += mappers

		dCnt, delCnt, bCnt := s.computeAdjustedLiveDocCountRound61(r.Context(), idxName)
		aggDocs += dCnt
		aggDeleted += delCnt
		totalStoreBytes += bCnt

		lst := liveStatsByIdx[idxName]
		var idxTot, delTot int64
		if lst != nil {
			idxTot = lst.indexTotal.Load()
			delTot = lst.deleteTotal.Load()
			aggLive.indexTotal.Add(idxTot)
			aggLive.deleteTotal.Add(delTot)
			aggLive.noopUpdateTotal.Add(lst.noopUpdateTotal.Load())
			aggLive.getTotal.Add(lst.getTotal.Load())
			aggLive.getExistsTotal.Add(lst.getExistsTotal.Load())
			aggLive.getMissingTotal.Add(lst.getMissingTotal.Load())
			aggLive.searchQueryTotal.Add(lst.searchQueryTotal.Load())
			aggLive.searchFetchTotal.Add(lst.searchFetchTotal.Load())
			aggLive.refreshTotal.Add(lst.refreshTotal.Load())
			aggLive.flushTotal.Add(lst.flushTotal.Load())
		}

		fdMap, totFD, compMap, totComp := s.collectIndexFielddataAndCompletionSizesRound61(idxName, dCnt)
		aggTotalFD += totFD
		for k, v := range fdMap {
			aggFD[k] += v
		}
		aggTotalComp += totComp
		for k, v := range compMap {
			aggComp[k] += v
		}

		adminSt.mu.RLock()
		idxGroups := make(map[string]*round61SearchGroupCounters)
		for g, gc := range adminSt.searchGroups[idxName] {
			if gc != nil {
				cp := *gc
				idxGroups[g] = &cp
				if aggGroups[g] == nil {
					aggGroups[g] = &round61SearchGroupCounters{}
				}
				aggGroups[g].queryTotal += cp.queryTotal
				aggGroups[g].queryTimeMillis += cp.queryTimeMillis
				aggGroups[g].fetchTotal += cp.fetchTotal
				aggGroups[g].fetchTimeMillis += cp.fetchTimeMillis
			}
		}
		for g, gc := range adminSt.searchGroups["_all"] {
			if gc != nil && idxGroups[g] == nil {
				cp := *gc
				idxGroups[g] = &cp
				if aggGroups[g] == nil {
					aggGroups[g] = &round61SearchGroupCounters{}
				}
				aggGroups[g].queryTotal += cp.queryTotal
				aggGroups[g].fetchTotal += cp.fetchTotal
			}
		}
		idxTypes := make(map[string]*round61DocTypeCounters)
		for tn, tc := range adminSt.docTypeCounts[idxName] {
			if tc != nil {
				cp := *tc
				idxTypes[tn] = &cp
				if aggDocTypes[tn] == nil {
					aggDocTypes[tn] = &round61DocTypeCounters{}
				}
				aggDocTypes[tn].indexTotal += cp.indexTotal
				aggDocTypes[tn].deleteTotal += cp.deleteTotal
			}
		}
		flMark, hasFlush := adminSt.flushedOps[idxName]
		adminSt.mu.RUnlock()

		totalOps := idxTot + delTot
		uncommOps := totalOps
		if hasFlush {
			uncommOps = totalOps - flMark.opsAtFlush
			if uncommOps < 0 {
				uncommOps = 0
			}
		}
		tBytes := int64(55) + totalOps*64
		uBytes := int64(55) + uncommOps*64
		hasAggTlog = true
		aggTlogOps += totalOps
		aggTlogUncommOps += uncommOps
		aggTlogBytes += tBytes
		aggTlogUncommBytes += uBytes

		ro := indexStatsRenderOptionsRound61{
			isES8:                   isES8,
			includeSegFileSizes:     includeSegFiles,
			includeUnloadedSegments: includeUnloaded,
			groupPatterns:           groups,
			typePatterns:            types,
			hasFielddataFields:      hasFD,
			fielddataPatterns:       fdPats,
			hasCompletionFields:     hasComp,
			completionPatterns:      compPats,
			recordedSearchGroups:    idxGroups,
			anyRecordedGroupsInSrv:  anyRecordedGroupsInSrv,
			recordedDocTypes:        idxTypes,
			fielddataSizes:          fdMap,
			totalFielddataBytes:     totFD,
			completionSizes:         compMap,
			totalCompletionBytes:    totComp,
			hasTranslogOverride:     true,
			tlogOps:                 totalOps,
			tlogUncommOps:           uncommOps,
			tlogSizeBytes:           tBytes,
			tlogUncommBytes:         uBytes,
		}
		perIdxData[idxName] = perIdxSnap{
			docs:       dCnt,
			del:        delCnt,
			bytes:      bCnt,
			mappers:    mappers,
			numShards:  ns,
			liveSt:     lst,
			renderOpts: ro,
		}
	}

	nodeRO := indexStatsRenderOptionsRound61{
		isES8:                   isES8,
		includeSegFileSizes:     includeSegFiles,
		includeUnloadedSegments: includeUnloaded,
		groupPatterns:           groups,
		typePatterns:            types,
		hasFielddataFields:      hasFD,
		fielddataPatterns:       fdPats,
		hasCompletionFields:     hasComp,
		completionPatterns:      compPats,
		recordedSearchGroups:    aggGroups,
		anyRecordedGroupsInSrv:  anyRecordedGroupsInSrv,
		recordedDocTypes:        aggDocTypes,
		fielddataSizes:          aggFD,
		totalFielddataBytes:     aggTotalFD,
		completionSizes:         aggComp,
		totalCompletionBytes:    aggTotalComp,
		hasTranslogOverride:     hasAggTlog,
		tlogOps:                 aggTlogOps,
		tlogUncommOps:           aggTlogUncommOps,
		tlogSizeBytes:           aggTlogBytes,
		tlogUncommBytes:         aggTlogUncommBytes,
	}
	nodeIndices = buildStatSectionsMapRound61(idxMetrics, aggDocs, aggDeleted, totalStoreBytes, &aggLive, nodeRO)
	decorateStoreStatsHumanRound61(nodeIndices, human)

	if idxMetrics["shard_stats"] {
		nodeIndices["shard_stats"] = map[string]any{
			"total_count": totalShards,
		}
	}
	if idxMetrics["mappings"] {
		estBytes := aggFieldMappers * 1024
		mMap := map[string]any{
			"total_count":                       aggFieldMappers,
			"total_estimated_overhead_in_bytes": estBytes,
		}
		if human {
			mMap["total_estimated_overhead"] = formatBytesHuman(estBytes)
		}
		nodeIndices["mappings"] = mMap
	}

	switch level {
	case "indices":
		indicesSub := make(map[string]any, len(openIndices))
		for _, idxName := range openIndices {
			snap := perIdxData[idxName]
			idxSec := buildStatSectionsMapRound61(idxMetrics, snap.docs, snap.del, snap.bytes, snap.liveSt, snap.renderOpts)
			decorateStoreStatsHumanRound61(idxSec, human)
			if idxMetrics["shard_stats"] {
				idxSec["shard_stats"] = map[string]any{"total_count": snap.numShards}
			}
			if idxMetrics["mappings"] {
				estBytes := snap.mappers * 1024
				im := map[string]any{
					"total_count":                       snap.mappers,
					"total_estimated_overhead_in_bytes": estBytes,
				}
				if human {
					im["total_estimated_overhead"] = formatBytesHuman(estBytes)
				}
				idxSec["mappings"] = im
			}
			indicesSub[idxName] = idxSec
		}
		nodeIndices["indices"] = indicesSub
	case "shards":
		shardsSub := make(map[string]any, len(openIndices))
		for _, idxName := range openIndices {
			snap := perIdxData[idxName]
			byShard := make(map[string]any, snap.numShards)
			for sh := 0; sh < snap.numShards; sh++ {
				shDocs := int64(0)
				shDel := int64(0)
				shBytes := int64(0)
				var shSt *indexLiveStats
				if sh == 0 {
					shDocs = snap.docs
					shDel = snap.del
					shBytes = snap.bytes
					shSt = snap.liveSt
				}
				shSec := buildStatSectionsMapRound61(idxMetrics, shDocs, shDel, shBytes, shSt, snap.renderOpts)
				decorateStoreStatsHumanRound61(shSec, human)
				decorateShardStatsEntryRound61(shSec, idxName, sh, true, shDocs)
				byShard[strconv.Itoa(sh)] = []any{shSec}
			}
			shardsSub[idxName] = byShard
		}
		nodeIndices["shards"] = shardsSub
	}
	return nodeIndices, totalShards, totalStoreBytes, 0, "", ""
}

// applyFilterPathRound61 selects positive filter_path globs first and then prunes negative (`-...`) subtrees.
func applyFilterPathRound61(v any, filterPaths []string) any {
	var expanded []string
	for _, rawFP := range filterPaths {
		if fp := strings.TrimSpace(rawFP); fp != "" {
			expanded = append(expanded, splitFilterPathExpressions(fp)...)
		}
	}
	if len(expanded) == 0 || v == nil {
		return v
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return v
	}
	var posPatterns, negPatterns [][]string
	for _, fp := range expanded {
		if strings.HasPrefix(fp, "-") {
			trimmed := strings.TrimSpace(strings.TrimPrefix(fp, "-"))
			if trimmed != "" {
				negPatterns = append(negPatterns, parseFilterPathSegments(trimmed))
			}
		} else {
			posPatterns = append(posPatterns, parseFilterPathSegments(fp))
		}
	}
	out := generic
	if len(posPatterns) > 0 {
		filtered, ok := filterIncludeNode(out, posPatterns)
		if !ok {
			if _, isSlice := out.([]any); isSlice {
				return []any{}
			}
			return map[string]any{}
		}
		out = filtered
	}
	if len(negPatterns) > 0 {
		out = filterExcludeNodeRound61(out, negPatterns)
	}
	return out
}

func filterExcludeNodeRound61(node any, negPatterns [][]string) any {
	switch typed := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, val := range typed {
			next := advanceFilterPatterns(negPatterns, k)
			excluded := false
			for _, np := range next {
				if len(np) == 0 || (len(np) == 1 && np[0] == "**") {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			if len(next) > 0 {
				child := filterExcludeNodeRound61(val, next)
				if valMap, wasMap := val.(map[string]any); wasMap && len(valMap) > 0 {
					if childMap, isMap := child.(map[string]any); isMap && len(childMap) == 0 {
						continue
					}
				}
				if valSlice, wasSlice := val.([]any); wasSlice && len(valSlice) > 0 {
					if childSlice, isSlice := child.([]any); isSlice && len(childSlice) == 0 {
						continue
					}
				}
				out[k] = child
			} else {
				out[k] = val
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for i, elem := range typed {
			elemPatterns, matchedLeaf := advanceArrayFilterPatterns(negPatterns, i)
			if matchedLeaf {
				continue
			}
			if len(elemPatterns) > 0 {
				child := filterExcludeNodeRound61(elem, elemPatterns)
				if elemMap, wasMap := elem.(map[string]any); wasMap && len(elemMap) > 0 {
					if childMap, isMap := child.(map[string]any); isMap && len(childMap) == 0 {
						continue
					}
				}
				out = append(out, child)
			} else {
				out = append(out, elem)
			}
		}
		return out
	default:
		return node
	}
}

// parseESResponseFormatOptionsRound61 parses pretty, error_trace, and ALL filter_path query parameters (Wave-2 `features.go` hook).
func parseESResponseFormatOptionsRound61(r *http.Request) (esResponseFormatOptions, bool) {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return esResponseFormatOptions{}, false
	}
	q := r.URL.Query()
	var opts esResponseFormatOptions
	if q.Has("pretty") {
		if pv := strings.ToLower(q.Get("pretty")); pv == "" || pv == "true" {
			opts.pretty = true
		}
	}
	if q.Has("error_trace") {
		if ev := strings.ToLower(q.Get("error_trace")); ev == "" || ev == "true" {
			opts.errorTrace = true
		}
	}
	for _, rawFP := range q["filter_path"] {
		if fp := strings.TrimSpace(rawFP); fp != "" {
			opts.filterPaths = append(opts.filterPaths, splitFilterPathExpressions(fp)...)
		}
	}
	if !opts.pretty && !opts.errorTrace && len(opts.filterPaths) == 0 {
		return esResponseFormatOptions{}, false
	}
	return opts, true
}

// ============================================================================
// F6: Component Template Deletion In-Use Validation (including wildcards)
// ============================================================================

func (s *Server) validateDeleteComponentTemplatesRound61Locked(name string) (toDelete []string, errStatus int, errType string, errReason string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;"
	}
	patterns := []string{"*"}
	if name != "_all" {
		patterns = strings.Split(name, ",")
		for i := range patterns {
			patterns[i] = strings.TrimSpace(patterns[i])
		}
	}
	if strings.ContainsAny(name, "*?,") || strings.HasPrefix(name, "-") || name == "_all" {
		for k := range s.componentTemplates {
			if matchesTemplateNamePatterns(k, patterns) {
				toDelete = append(toDelete, k)
			}
		}
		// Check explicit literal names inside comma-separated patterns too:
		for _, p := range patterns {
			if p != "" && !strings.ContainsAny(p, "*?") && !strings.HasPrefix(p, "-") && p != "_all" {
				if _, exists := s.componentTemplates[p]; !exists {
					return nil, http.StatusNotFound, "resource_not_found_exception", "component_template [" + p + "] missing"
				}
			}
		}
	} else if _, existed := s.componentTemplates[name]; existed {
		toDelete = []string{name}
	}
	sort.Strings(toDelete)
	if len(toDelete) == 0 {
		return nil, http.StatusNotFound, "resource_not_found_exception", "component_template [" + name + "] missing"
	}

	toDeleteSet := make(map[string]bool, len(toDelete))
	for _, k := range toDelete {
		toDeleteSet[k] = true
	}
	var inUseCompNames []string
	usingTemplatesSet := make(map[string]bool)
	for _, compName := range toDelete {
		usedHere := false
		for tplName, tpl := range s.templates {
			for _, ref := range tpl.ComposedOf {
				if ref == compName {
					usedHere = true
					usingTemplatesSet[tplName] = true
				}
			}
		}
		if usedHere {
			inUseCompNames = append(inUseCompNames, compName)
		}
	}
	_ = toDeleteSet
	if len(inUseCompNames) > 0 {
		usingTemplates := make([]string, 0, len(usingTemplatesSet))
		for tn := range usingTemplatesSet {
			usingTemplates = append(usingTemplates, tn)
		}
		sort.Strings(usingTemplates)
		return nil, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("unable to remove component templates [%s] as they are in use by a index templates [%s]",
				strings.Join(inUseCompNames, ", "), strings.Join(usingTemplates, ", "))
	}
	return toDelete, 0, "", ""
}

// handleDeleteComponentTemplateRound61 handles `DELETE /_component_template/{name}` (Wave-2 `server.go` hook).
func (s *Server) handleDeleteComponentTemplateRound61(w http.ResponseWriter, r *http.Request, name string) {
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.Lock()
	toDelete, errStatus, errType, errReason := s.validateDeleteComponentTemplatesRound61Locked(name)
	if errStatus != 0 {
		s.mu.Unlock()
		writeESError(w, errStatus, errType, errReason)
		return
	}
	for _, k := range toDelete {
		delete(s.componentTemplates, k)
	}
	s.mu.Unlock()
	for _, k := range toDelete {
		s.deleteCatalogEntity(r.Context(), "component_template", k)
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
}

// ============================================================================
// F8: Synonyms Reload Details, Index Missing Set Check & Query Synonym Expansion
// ============================================================================

func (s *Server) buildSynonymReloadPayloadRound61Locked(setID string) map[string]any {
	reloadDetails := make([]any, 0)
	totalShards := 0

	idxNames := make([]string, 0, len(s.indices))
	for k := range s.indices {
		idxNames = append(idxNames, k)
	}
	sort.Strings(idxNames)

	for _, idxName := range idxNames {
		if s.closedIndices[idxName] || strings.HasPrefix(idxName, ".") {
			continue
		}
		numShards := 1
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, sk := range []string{"number_of_shards", "index.number_of_shards"} {
				if v, ok := cust[sk]; ok {
					if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil && n > 0 {
						numShards = n
					}
				}
			}
		}
		analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
		matchingFilters := make(map[string]bool)
		for fName, fDef := range filters {
			if ss, okS := fDef["synonyms_set"].(string); okS && strings.TrimSpace(ss) == setID {
				matchingFilters[fName] = true
			}
		}
		if len(matchingFilters) == 0 {
			continue
		}
		totalShards += numShards
		var reloaded []string
		for aName, aDef := range analyzers {
			for _, fRef := range extractStringSliceAny(aDef["filter"]) {
				if matchingFilters[fRef] {
					reloaded = append(reloaded, aName)
					break
				}
			}
		}
		sort.Strings(reloaded)
		if len(reloaded) > 0 {
			reloadDetails = append(reloadDetails, map[string]any{
				"index":              idxName,
				"reloaded_analyzers": reloaded,
				"reloaded_node_ids":  []string{taskLocalNodeID},
			})
		}
	}

	return map[string]any{
		"_shards": map[string]any{
			"total":      totalShards,
			"successful": totalShards,
			"failed":     0,
		},
		"reload_details": reloadDetails,
	}
}

func (s *Server) buildAllIndexReloadAnalyzersDetailsRound61Locked(indexNames []string) ([]any, int) {
	reloadDetails := make([]any, 0, len(indexNames))
	totalShards := 0
	for _, idxName := range indexNames {
		if s.closedIndices[idxName] {
			continue
		}
		numShards := 1
		if cust := s.indexCustomSettings[idxName]; cust != nil {
			for _, sk := range []string{"number_of_shards", "index.number_of_shards"} {
				if v, ok := cust[sk]; ok {
					if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil && n > 0 {
						numShards = n
					}
				}
			}
		}
		totalShards += numShards

		analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
		updateableFilters := make(map[string]bool)
		for fName, fDef := range filters {
			fType := fmt.Sprintf("%v", fDef["type"])
			upd, _ := fDef["updateable"].(bool)
			if upd || fmt.Sprintf("%v", fDef["updateable"]) == "true" || fDef["synonyms_set"] != nil || fType == "synonym" || fType == "synonym_graph" {
				updateableFilters[fName] = true
			}
		}
		var reloaded []string
		for aName, aDef := range analyzers {
			for _, fRef := range extractStringSliceAny(aDef["filter"]) {
				if updateableFilters[fRef] {
					reloaded = append(reloaded, aName)
					break
				}
			}
		}
		sort.Strings(reloaded)
		if reloaded == nil {
			reloaded = []string{}
		}
		reloadDetails = append(reloadDetails, map[string]any{
			"index":              idxName,
			"reloaded_analyzers": reloaded,
			"reloaded_node_ids":  []string{taskLocalNodeID},
		})
	}
	return reloadDetails, totalShards
}

// indexHasMissingSynonymsSetRound61 returns true if `settings` configures a `synonyms_set`
// that does not currently exist in `s.synonymSets` — in ES 8 (`80_synonyms_from_index.yml`),
// `PUT /{index}` succeeds with `"acknowledged": true, "shards_acknowledged": false`!
func indexHasMissingSynonymsSetRound61(s *Server, settings map[string]any) bool {
	if s == nil || len(settings) == 0 {
		return false
	}
	_, filters := extractIndexAnalysisMaps(settings)
	if len(filters) == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, fDef := range filters {
		if setID, ok := fDef["synonyms_set"].(string); ok && strings.TrimSpace(setID) != "" {
			if _, exists := s.synonymSets[strings.TrimSpace(setID)]; !exists {
				return true
			}
		}
	}
	return false
}

// expandSearchBodySynonymsRound61 expands `match` / `match_phrase` / `multi_match` queries
// using configured index synonym filters & live `s.synonymSets` (Wave-2 `server.go` hook).
func expandSearchBodySynonymsRound61(s *Server, targetIndices []string, bodyBytes []byte) []byte {
	if s == nil || len(targetIndices) == 0 || len(bytes.TrimSpace(bodyBytes)) == 0 {
		return bodyBytes
	}
	s.mu.RLock()
	var allRules []parsedSynonymRule
	fieldAnalyzerRules := make(map[string][]parsedSynonymRule)
	for _, idxName := range targetIndices {
		analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
		if len(filters) == 0 {
			continue
		}
		rulesByAnalyzer := make(map[string][]parsedSynonymRule)
		for aName, aDef := range analyzers {
			for _, fRef := range extractStringSliceAny(aDef["filter"]) {
				if fDef, okF := filters[fRef]; okF {
					fRules := s.collectSynonymRulesFromFilterDefLocked(fDef)
					rulesByAnalyzer[aName] = append(rulesByAnalyzer[aName], fRules...)
					allRules = append(allRules, fRules...)
				}
			}
		}
		if len(allRules) == 0 {
			for _, fDef := range filters {
				allRules = append(allRules, s.collectSynonymRulesFromFilterDefLocked(fDef)...)
			}
		}
		if sc := s.indices[idxName]; sc != nil && sc.RawMapping != nil {
			for fn, prop := range sc.RawMapping.Properties {
				if prop.SearchAnalyzer != "" && len(rulesByAnalyzer[prop.SearchAnalyzer]) > 0 {
					fieldAnalyzerRules[fn] = append(fieldAnalyzerRules[fn], rulesByAnalyzer[prop.SearchAnalyzer]...)
				} else if prop.Analyzer != "" && len(rulesByAnalyzer[prop.Analyzer]) > 0 {
					fieldAnalyzerRules[fn] = append(fieldAnalyzerRules[fn], rulesByAnalyzer[prop.Analyzer]...)
				}
			}
		}
	}
	s.mu.RUnlock()

	if len(allRules) == 0 {
		return bodyBytes
	}

	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil || root["query"] == nil {
		return bodyBytes
	}

	expandTermsForQuery := func(text string, rules []parsedSynonymRule) []string {
		words := strings.Fields(strings.ToLower(strings.TrimSpace(text)))
		if len(words) == 0 {
			return nil
		}
		full := strings.Join(words, " ")
		alts := []string{text}
		seen := map[string]bool{strings.ToLower(text): true, full: true}
		addAlt := func(candidate string) {
			c := strings.TrimSpace(candidate)
			cl := strings.ToLower(c)
			if c != "" && !seen[cl] {
				seen[cl] = true
				alts = append(alts, c)
			}
		}
		for _, r := range rules {
			if r.explicit {
				for _, l := range r.lhs {
					if l == full {
						for _, rhs := range r.rhs {
							addAlt(rhs)
						}
					}
				}
			} else {
				inEq := false
				for _, eq := range r.equiv {
					if eq == full {
						inEq = true
						break
					}
				}
				if inEq {
					for _, eq := range r.equiv {
						addAlt(eq)
					}
				}
			}
		}
		if len(words) > 1 {
			// Word-level single-token synonym expansion inside multi-word queries
			for idx, w := range words {
				for _, r := range rules {
					if r.explicit {
						for _, l := range r.lhs {
							if l == w {
								for _, rhs := range r.rhs {
									cp := append([]string{}, words...)
									cp[idx] = rhs
									addAlt(strings.Join(cp, " "))
								}
							}
						}
					} else {
						hasW := false
						for _, eq := range r.equiv {
							if eq == w {
								hasW = true
								break
							}
						}
						if hasW {
							for _, eq := range r.equiv {
								if eq != w {
									cp := append([]string{}, words...)
									cp[idx] = eq
									addAlt(strings.Join(cp, " "))
								}
							}
						}
					}
				}
			}
		}
		return alts
	}

	changed := false
	var rewriteNode func(node any) any
	rewriteNode = func(node any) any {
		m, ok := node.(map[string]any)
		if !ok || m == nil {
			return node
		}
		if matchBody, isMatch := m["match"].(map[string]any); isMatch && len(matchBody) == 1 {
			for field, spec := range matchBody {
				var qText string
				var analyzerOverride string
				switch sv := spec.(type) {
				case string:
					qText = sv
				case map[string]any:
					qText, _ = sv["query"].(string)
					analyzerOverride, _ = sv["analyzer"].(string)
				}
				if strings.TrimSpace(qText) == "" {
					return node
				}
				rules := fieldAnalyzerRules[field]
				if len(rules) == 0 || analyzerOverride != "" {
					rules = allRules
				}
				alts := expandTermsForQuery(qText, rules)
				if len(alts) > 1 {
					should := make([]any, 0, len(alts))
					for _, alt := range alts {
						should = append(should, map[string]any{
							"match": map[string]any{field: alt},
						})
					}
					changed = true
					return map[string]any{
						"bool": map[string]any{
							"should":               should,
							"minimum_should_match": 1,
						},
					}
				}
			}
		}
		if mpBody, isMP := m["match_phrase"].(map[string]any); isMP && len(mpBody) == 1 {
			for field, spec := range mpBody {
				var qText string
				switch sv := spec.(type) {
				case string:
					qText = sv
				case map[string]any:
					qText, _ = sv["query"].(string)
				}
				if strings.TrimSpace(qText) == "" {
					return node
				}
				rules := fieldAnalyzerRules[field]
				if len(rules) == 0 {
					rules = allRules
				}
				alts := expandTermsForQuery(qText, rules)
				if len(alts) > 1 {
					should := make([]any, 0, len(alts))
					for _, alt := range alts {
						should = append(should, map[string]any{
							"match_phrase": map[string]any{field: alt},
						})
					}
					changed = true
					return map[string]any{
						"bool": map[string]any{
							"should":               should,
							"minimum_should_match": 1,
						},
					}
				}
			}
		}
		if boolBody, isBool := m["bool"].(map[string]any); isBool {
			outBool := make(map[string]any, len(boolBody))
			for bk, bv := range boolBody {
				switch tv := bv.(type) {
				case []any:
					ns := make([]any, len(tv))
					for i, elem := range tv {
						ns[i] = rewriteNode(elem)
					}
					outBool[bk] = ns
				case map[string]any:
					outBool[bk] = rewriteNode(tv)
				default:
					outBool[bk] = bv
				}
			}
			return map[string]any{"bool": outBool}
		}
		return node
	}

	root["query"] = rewriteNode(root["query"])
	if !changed {
		return bodyBytes
	}
	out, err := json.Marshal(root)
	if err != nil {
		return bodyBytes
	}
	return out
}

// ============================================================================
// F11: `retriever.standard` Validation & Search Request Translation
// ============================================================================

var validStandardRetrieverKeysRound61 = map[string]bool{
	"query":            true,
	"filter":           true,
	"sort":             true,
	"search_after":     true,
	"collapse":         true,
	"terminate_after":  true,
	"min_score":        true,
	"rank_window_size": true,
}

var disallowedTopLevelWithRetrieverKeysRound61 = []string{
	"query",
	"sort",
	"search_after",
	"collapse",
	"terminate_after",
	"min_score",
	"knn",
	"rescore",
	"rank",
	"sub_searches",
}

// validateAndRewriteStandardRetrieverRound61 validates `retriever` (including `retriever.standard`)
// against duplicate top-level search fields and rewrites `retriever.standard` into canonical
// top-level `query`, `sort`, `search_after`, `collapse`, `terminate_after`, `min_score`.
func (s *Server) validateAndRewriteStandardRetrieverRound61(bodyBytes []byte) (rewritten []byte, errStatus int, errType string, errReason string) {
	if len(bytes.TrimSpace(bodyBytes)) == 0 || !bytes.Contains(bodyBytes, []byte(`"retriever"`)) {
		return bodyBytes, 0, "", ""
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil {
		return bodyBytes, 0, "", ""
	}
	rawRetr, hasRetr := root["retriever"]
	if !hasRetr || rawRetr == nil {
		return bodyBytes, 0, "", ""
	}
	retrMap, ok := rawRetr.(map[string]any)
	if !ok || len(retrMap) == 0 {
		return nil, http.StatusBadRequest, "parsing_exception", "[retriever] must be a non-empty object"
	}
	if len(retrMap) > 1 {
		return nil, http.StatusBadRequest, "parsing_exception", "[retriever] must specify exactly one retriever type"
	}

	for _, forbiddenKey := range disallowedTopLevelWithRetrieverKeysRound61 {
		if _, dup := root[forbiddenKey]; dup {
			return nil, http.StatusBadRequest, "parsing_exception",
				fmt.Sprintf("Cannot specify [%s] when using a [retriever]", forbiddenKey)
		}
	}

	rawStd, hasStd := retrMap["standard"]
	if !hasStd {
		// Leave other retrievers (e.g. `rule`, `rrf`, `knn`, `text_similarity_reranker`) for their own handlers.
		return bodyBytes, 0, "", ""
	}
	stdMap, okStd := rawStd.(map[string]any)
	if !okStd || stdMap == nil {
		return nil, http.StatusBadRequest, "parsing_exception", "[standard] retriever must be an object"
	}
	for k := range stdMap {
		if !validStandardRetrieverKeysRound61[k] {
			return nil, http.StatusBadRequest, "parsing_exception",
				fmt.Sprintf("[standard] unknown field [%s]", k)
		}
	}

	var filterSlice []any
	if rawFilter, hasF := stdMap["filter"]; hasF && rawFilter != nil {
		switch fv := rawFilter.(type) {
		case []any:
			filterSlice = fv
		case map[string]any:
			filterSlice = []any{fv}
		default:
			return nil, http.StatusBadRequest, "parsing_exception", "[standard.filter] must be a query object or array of query objects"
		}
	}

	stdQuery, hasQ := stdMap["query"]
	switch {
	case hasQ && stdQuery != nil && len(filterSlice) > 0:
		root["query"] = map[string]any{
			"bool": map[string]any{
				"must":   []any{stdQuery},
				"filter": filterSlice,
			},
		}
	case hasQ && stdQuery != nil:
		root["query"] = stdQuery
	case len(filterSlice) > 0:
		root["query"] = map[string]any{
			"bool": map[string]any{
				"filter": filterSlice,
			},
		}
	default:
		root["query"] = map[string]any{"match_all": map[string]any{}}
	}

	for _, promoteKey := range []string{"sort", "search_after", "collapse", "terminate_after", "min_score"} {
		if val, exists := stdMap[promoteKey]; exists && val != nil {
			root[promoteKey] = val
		}
	}
	delete(root, "retriever")

	out, err := json.Marshal(root)
	if err != nil {
		return bodyBytes, 0, "", ""
	}
	return out, 0, "", ""
}

// ============================================================================
// F12: `/_field_caps` & `/{index}/_field_caps` Full ES 7 / ES 8 Support
// ============================================================================

var validESFieldCapsTypesRound61 = map[string]bool{
	"_id": true, "_index": true, "_seq_no": true, "_primary_term": true, "_version": true,
	"_source": true, "_routing": true, "_field_names": true, "_ignored": true, "_type": true,
	"_tier": true, "_doc_count": true, "_data_stream_timestamp": true,
	"aggregate_metric_double": true, "alias": true, "annotated-text": true, "binary": true,
	"boolean": true, "byte": true, "cartesian_point": true, "cartesian_shape": true,
	"completion": true, "constant_keyword": true, "counter_byte": true, "counter_double": true,
	"counter_float": true, "counter_integer": true, "counter_long": true, "counter_short": true,
	"date": true, "date_nanos": true, "date_range": true, "dense_vector": true,
	"double": true, "double_range": true, "exponential_histogram": true, "flattened": true,
	"float": true, "float_range": true, "geo_point": true, "geo_shape": true,
	"half_float": true, "histogram": true, "icu_collation_keyword": true, "integer": true,
	"integer_range": true, "ip": true, "ip_range": true, "join": true,
	"keyword": true, "knn_vector": true, "long": true, "long_range": true,
	"lookup": true, "match_only_text": true, "murmur3": true, "nested": true,
	"object": true, "passthrough": true, "percolator": true, "point": true,
	"position_byte": true, "position_double": true, "position_float": true, "position_integer": true,
	"position_long": true, "position_short": true, "rank_feature": true, "rank_features": true,
	"scaled_float": true, "search_as_you_type": true, "semantic_text": true, "shape": true,
	"short": true, "sparse_vector": true, "summary_byte": true, "summary_double": true,
	"summary_float": true, "summary_integer": true, "summary_long": true, "summary_short": true,
	"text": true, "token_count": true, "unmapped": true, "unsigned_long": true,
	"version": true, "wildcard": true,
}

func isES8DocValuesSearchableTypeRound61(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "unsigned_long",
		"date", "date_nanos", "keyword", "constant_keyword", "wildcard", "boolean", "ip",
		"geo_point", "cartesian_point", "point", "version", "flattened":
		return true
	default:
		return false
	}
}

func normalizeIndexFilterRangeBoundRound61(bv any) any {
	switch nv := bv.(type) {
	case float64:
		if nv >= 1900 && nv <= 2200 && nv == float64(int64(nv)) {
			return strconv.FormatInt(int64(nv), 10)
		}
	case json.Number:
		if iv, err := nv.Int64(); err == nil && iv >= 1900 && iv <= 2200 {
			return strconv.FormatInt(iv, 10)
		}
	}
	return bv
}

func normalizeIndexFilterQueryNumbersRound61(q *esast.Query) {
	if q == nil {
		return
	}
	if len(q.Range) > 0 {
		for field, rc := range q.Range {
			rc.GT = normalizeIndexFilterRangeBoundRound61(rc.GT)
			rc.GTE = normalizeIndexFilterRangeBoundRound61(rc.GTE)
			rc.LT = normalizeIndexFilterRangeBoundRound61(rc.LT)
			rc.LTE = normalizeIndexFilterRangeBoundRound61(rc.LTE)
			rc.From = normalizeIndexFilterRangeBoundRound61(rc.From)
			rc.To = normalizeIndexFilterRangeBoundRound61(rc.To)
			q.Range[field] = rc
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			normalizeIndexFilterQueryNumbersRound61(&q.Bool.Must[i])
		}
		for i := range q.Bool.Filter {
			normalizeIndexFilterQueryNumbersRound61(&q.Bool.Filter[i])
		}
		for i := range q.Bool.Should {
			normalizeIndexFilterQueryNumbersRound61(&q.Bool.Should[i])
		}
		for i := range q.Bool.MustNot {
			normalizeIndexFilterQueryNumbersRound61(&q.Bool.MustNot[i])
		}
	}
}

func preserveEmptyFilterMapsRound64(dst, src *esast.Query) {
	if dst == nil || src == nil {
		return
	}
	if src.MatchNone != nil && dst.MatchNone == nil {
		dst.MatchNone = map[string]any{}
	}
	if src.MatchAll != nil && dst.MatchAll == nil {
		dst.MatchAll = map[string]any{}
	}
	if src.Bool != nil && dst.Bool != nil {
		for i := 0; i < len(src.Bool.Must) && i < len(dst.Bool.Must); i++ {
			preserveEmptyFilterMapsRound64(&dst.Bool.Must[i], &src.Bool.Must[i])
		}
		for i := 0; i < len(src.Bool.Filter) && i < len(dst.Bool.Filter); i++ {
			preserveEmptyFilterMapsRound64(&dst.Bool.Filter[i], &src.Bool.Filter[i])
		}
		for i := 0; i < len(src.Bool.Should) && i < len(dst.Bool.Should); i++ {
			preserveEmptyFilterMapsRound64(&dst.Bool.Should[i], &src.Bool.Should[i])
		}
		for i := 0; i < len(src.Bool.MustNot) && i < len(dst.Bool.MustNot); i++ {
			preserveEmptyFilterMapsRound64(&dst.Bool.MustNot[i], &src.Bool.MustNot[i])
		}
	}
	if src.ConstantScore != nil && dst.ConstantScore != nil {
		preserveEmptyFilterMapsRound64(&dst.ConstantScore.Filter, &src.ConstantScore.Filter)
	}
	if src.Boosting != nil && dst.Boosting != nil {
		preserveEmptyFilterMapsRound64(&dst.Boosting.Positive, &src.Boosting.Positive)
		preserveEmptyFilterMapsRound64(&dst.Boosting.Negative, &src.Boosting.Negative)
	}
	if src.DisMax != nil && dst.DisMax != nil {
		for i := 0; i < len(src.DisMax.Queries) && i < len(dst.DisMax.Queries); i++ {
			preserveEmptyFilterMapsRound64(&dst.DisMax.Queries[i], &src.DisMax.Queries[i])
		}
	}
}

// handleFieldCapsRound61 implements full ES 7 / ES 8 `GET/POST /_field_caps` and `/{index}/_field_caps` (Wave-2 `server.go` hook).
func (s *Server) handleFieldCapsRound61(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex != "" {
		onlyNeg := true
		hasNeg := false
		for _, p := range strings.Split(rawIndex, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.HasPrefix(p, "-") {
				hasNeg = true
			} else {
				onlyNeg = false
				break
			}
		}
		if hasNeg && onlyNeg {
			rawIndex = "*," + rawIndex
		}
	}
	targets, aliasFilters, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
		return
	}
	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	includeEmptyFields := true
	if parsedEmpty, hasEmpty, err := parseStrictQueryBoolParamRound59(r, "include_empty_fields"); err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
		return
	} else if hasEmpty {
		includeEmptyFields = parsedEmpty
	}
	includeUnmapped := isTruthyBoolQueryParam(r, "include_unmapped")

	var filterPatterns []string
	for _, fv := range r.URL.Query()["fields"] {
		filterPatterns = append(filterPatterns, strings.Split(fv, ",")...)
	}
	var rawTypeTokens []string
	if typeVals := r.URL.Query()["types"]; len(typeVals) > 0 {
		rawTypeTokens = append(rawTypeTokens, typeVals...)
	}
	var rawFilterTokens []string
	if fltVals := r.URL.Query()["filters"]; len(fltVals) > 0 {
		rawFilterTokens = append(rawFilterTokens, fltVals...)
	}

	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var indexFilter *esast.Query
	var reqRuntimeMappings map[string]esast.FieldProperty
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body struct {
			Fields             []string                       `json:"fields"`
			Types              []string                       `json:"types"`
			Filters            []string                       `json:"filters"`
			IncludeUnmapped    *bool                          `json:"include_unmapped"`
			IncludeEmptyFields *bool                          `json:"include_empty_fields"`
			IndexFilter        *esast.Query                   `json:"index_filter"`
			RuntimeMappings    map[string]esast.FieldProperty `json:"runtime_mappings"`
		}
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		if len(body.Fields) > 0 {
			if len(filterPatterns) == 1 && filterPatterns[0] == "*" {
				filterPatterns = body.Fields
			} else {
				filterPatterns = append(filterPatterns, body.Fields...)
			}
		}
		if len(body.Types) > 0 {
			rawTypeTokens = append(rawTypeTokens, body.Types...)
		}
		if len(body.Filters) > 0 {
			rawFilterTokens = append(rawFilterTokens, body.Filters...)
		}
		if body.IncludeUnmapped != nil {
			includeUnmapped = *body.IncludeUnmapped
		}
		if body.IncludeEmptyFields != nil {
			includeEmptyFields = *body.IncludeEmptyFields
		}
		indexFilter = body.IndexFilter
		reqRuntimeMappings = body.RuntimeMappings
	}

	if len(reqRuntimeMappings) > 0 {
		if _, err := TopoSortRuntimeMappingsRound61(reqRuntimeMappings); err != nil {
			et, er := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
			writeESError(w, http.StatusBadRequest, et, er)
			return
		}
		for _, prop := range reqRuntimeMappings {
			var srcCode, lang string
			switch sc := prop.Script.(type) {
			case string:
				srcCode = strings.TrimSpace(sc)
			case map[string]any:
				if l, okL := sc["lang"].(string); okL {
					lang = strings.ToLower(strings.TrimSpace(l))
				}
				if sStr, okS := sc["source"].(string); okS {
					srcCode = strings.TrimSpace(sStr)
				} else if iStr, okI := sc["inline"].(string); okI {
					srcCode = strings.TrimSpace(iStr)
				}
			}
			if lang != "" && lang != "painless" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("script_lang not supported [%s]", lang))
				return
			}
			if srcCode != "" {
				if err := painless.CompileValidate(srcCode); err != nil {
					writeJSONWithRequest(w, r, http.StatusBadRequest, map[string]any{
						"error": map[string]any{
							"root_cause": []map[string]any{
								{
									"type":         "script_exception",
									"reason":       "compile error",
									"script_stack": []string{srcCode, "^---- HERE"},
									"script":       srcCode,
									"lang":         "painless",
								},
							},
							"type":         "script_exception",
							"reason":       "compile error",
							"script_stack": []string{srcCode, "^---- HERE"},
							"script":       srcCode,
							"lang":         "painless",
							"caused_by": map[string]any{
								"type":   "illegal_argument_exception",
								"reason": err.Error(),
							},
						},
						"status": http.StatusBadRequest,
					})
					return
				}
			}
		}
	}

	typeAllowSet := make(map[string]bool)
	for _, rt := range rawTypeTokens {
		for _, part := range strings.Split(rt, ",") {
			tok := strings.ToLower(strings.TrimSpace(part))
			if tok == "" {
				continue
			}
			if strings.HasPrefix(tok, "+") || strings.HasPrefix(tok, "-") {
				rawFilterTokens = append(rawFilterTokens, tok)
				continue
			}
			if !validESFieldCapsTypesRound61[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unknown field type [%s] in field_caps [types]", part))
				return
			}
			typeAllowSet[tok] = true
		}
	}

	fcFilters, fErr := parseFieldCapsFilters(rawFilterTokens)
	if fErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fErr.Error())
		return
	}

	if len(filterPatterns) == 0 {
		filterPatterns = []string{"*"}
	}

	if indexFilter != nil && len(targets) > 0 {
		filteredTargets := make([]string, 0, len(targets))
		zero := 0
		for _, idxName := range targets {
			qCopyBytes, _ := json.Marshal(indexFilter)
			var qCopy esast.Query
			_ = json.Unmarshal(qCopyBytes, &qCopy)
			preserveEmptyFilterMapsRound64(&qCopy, indexFilter)

			s.mu.RLock()
			idxSchema := s.indices[idxName]
			s.mu.RUnlock()
			if idxSchema != nil {
				for fn := range qCopy.Range {
					if esT := lookupFieldESTypeRound61(idxSchema, fn); esT == "date" || esT == "date_nanos" {
						normalizeIndexFilterQueryNumbersRound61(&qCopy)
						break
					}
				}
			}

			cntReq := esast.SearchRequest{
				Size:           &zero,
				TrackTotalHits: true,
				Query:          &qCopy,
				AliasFilter:    aliasFilters[idxName],
			}
			resp, _, errType, _ := s.executeSearchRequest(r.Context(), idxName, &cntReq)
			if errType != "" {
				continue
			}
			if cnt, _ := extractTotalAndHitIDs(resp); cnt > 0 {
				filteredTargets = append(filteredTargets, idxName)
			}
		}
		targets = filteredTargets
	}

	nonEmptyFieldsByIdx := make(map[string]map[string]bool)
	indexHasDocs := make(map[string]bool)
	dynamicFieldTypesByIdx := make(map[string]map[string]string)
	if !includeEmptyFields && len(targets) > 0 {
		for _, idxName := range targets {
			docs := s.collectIndexedDocsWithIDsRound61(r.Context(), idxName, aliasFilters[idxName])
			nonEmpty := make(map[string]bool)
			dynTypes := make(map[string]string)
			if len(docs) > 0 {
				indexHasDocs[idxName] = true
			}
			for _, d := range docs {
				flat := make(map[string][]any)
				flattenDocFieldValuesRound61("", d.Source, flat)
				for fp, vals := range flat {
					if len(vals) == 0 {
						continue
					}
					nonEmpty[fp] = true
					// Mark parent object prefixes non-empty too, plus `.keyword` companion!
					for dot := strings.IndexByte(fp, '.'); dot > 0; {
						nonEmpty[fp[:dot]] = true
						next := strings.IndexByte(fp[dot+1:], '.')
						if next < 0 {
							break
						}
						dot = dot + 1 + next
					}
					switch vals[0].(type) {
					case string:
						nonEmpty[fp+".keyword"] = true
						dynTypes[fp] = "text"
					case bool:
						dynTypes[fp] = "boolean"
					case float64:
						fv := vals[0].(float64)
						if fv == float64(int64(fv)) {
							dynTypes[fp] = "long"
						} else {
							dynTypes[fp] = "float"
						}
					case json.Number:
						if _, errI := vals[0].(json.Number).Int64(); errI == nil {
							dynTypes[fp] = "long"
						} else {
							dynTypes[fp] = "float"
						}
					}
				}
			}
			nonEmptyFieldsByIdx[idxName] = nonEmpty
			dynamicFieldTypesByIdx[idxName] = dynTypes
		}
	}

	isES8 := s.isES8Mode(r)

	caps := make(map[string]map[string]map[string]any)
	indicesByFieldType := make(map[string]map[string][]string)
	nonSearchableByFieldType := make(map[string]map[string][]string)
	nonAggregatableByFieldType := make(map[string]map[string][]string)
	dimIndicesByFieldType := make(map[string]map[string][]string)
	metricTypesByFieldType := make(map[string]map[string]map[string][]string)
	metaByFieldType := make(map[string]map[string]map[string][]string)

	addFieldMeta := func(field, esType string, meta map[string]string) {
		if len(meta) == 0 {
			return
		}
		if metaByFieldType[field] == nil {
			metaByFieldType[field] = make(map[string]map[string][]string)
		}
		if metaByFieldType[field][esType] == nil {
			metaByFieldType[field][esType] = make(map[string][]string)
		}
		mm := metaByFieldType[field][esType]
		for mk, mv := range meta {
			exists := false
			for _, cur := range mm[mk] {
				if cur == mv {
					exists = true
					break
				}
			}
			if !exists {
				mm[mk] = append(mm[mk], mv)
			}
		}
	}
	appendUniqueIdx := func(m map[string]map[string][]string, field, esType, idxName string) {
		if idxName == "" {
			return
		}
		if m[field] == nil {
			m[field] = make(map[string][]string)
		}
		for _, existing := range m[field][esType] {
			if existing == idxName {
				return
			}
		}
		m[field][esType] = append(m[field][esType], idxName)
	}

	type capEntryFlags struct {
		isMeta        bool
		metadataField bool
		isMultifield  bool
		isNested      bool
		isParent      bool
		isRuntime     bool
		tsDimension   bool
		tsMetric      string
	}

	addCap := func(idxName, field, esType string, searchable, aggregatable bool, fl capEntryFlags) {
		if !matchesFieldCapsPatterns(field, filterPatterns) {
			return
		}
		isStandard := !fl.isMeta && !fl.isMultifield && !fl.isNested && !fl.isParent && !fl.isRuntime
		if !fcFilters.allows(fl.isMeta, fl.isMultifield, fl.isNested, fl.isParent, fl.isRuntime, isStandard) {
			return
		}
		if len(typeAllowSet) > 0 && !typeAllowSet[strings.ToLower(esType)] {
			return
		}
		if !includeEmptyFields && idxName != "" {
			if fl.isMeta {
				if !indexHasDocs[idxName] {
					return
				}
			} else if !fl.isRuntime {
				if !nonEmptyFieldsByIdx[idxName][field] {
					return
				}
			}
		}
		if caps[field] == nil {
			caps[field] = make(map[string]map[string]any)
		}
		if existing, ok := caps[field][esType]; ok {
			prevS, _ := existing["searchable"].(bool)
			prevA, _ := existing["aggregatable"].(bool)
			if s.hasExplicitTargetESVersion() {
				existing["searchable"] = prevS && searchable
				existing["aggregatable"] = prevA && aggregatable
			} else {
				existing["searchable"] = prevS || searchable
				existing["aggregatable"] = prevA || aggregatable
			}
			if fl.metadataField {
				existing["metadata_field"] = true
			}
		} else {
			entry := map[string]any{
				"type":         esType,
				"searchable":   searchable,
				"aggregatable": aggregatable,
			}
			if fl.metadataField {
				entry["metadata_field"] = true
			}
			caps[field][esType] = entry
		}
		appendUniqueIdx(indicesByFieldType, field, esType, idxName)
		if !searchable {
			appendUniqueIdx(nonSearchableByFieldType, field, esType, idxName)
		}
		if !aggregatable {
			appendUniqueIdx(nonAggregatableByFieldType, field, esType, idxName)
		}
		if fl.tsDimension && idxName != "" {
			appendUniqueIdx(dimIndicesByFieldType, field, esType, idxName)
		}
		if fl.tsMetric != "" && idxName != "" {
			if metricTypesByFieldType[field] == nil {
				metricTypesByFieldType[field] = make(map[string]map[string][]string)
			}
			if metricTypesByFieldType[field][esType] == nil {
				metricTypesByFieldType[field][esType] = make(map[string][]string)
			}
			metricTypesByFieldType[field][esType][fl.tsMetric] = append(metricTypesByFieldType[field][esType][fl.tsMetric], idxName)
		}
	}

	if targets == nil {
		targets = []string{}
	}
	if len(targets) > 0 {
		hasMetaTarget := includeEmptyFields
		if !includeEmptyFields {
			for _, tn := range targets {
				if indexHasDocs[tn] {
					hasMetaTarget = true
					break
				}
			}
		}
		if hasMetaTarget {
			metaFl := capEntryFlags{isMeta: true}
			addCap("", "_id", "_id", true, true, metaFl)
			addCap("", "_index", "_index", true, true, metaFl)
			addCap("", "_seq_no", "_seq_no", true, true, metaFl)
			addCap("", "_primary_term", "_primary_term", false, false, metaFl)
			addCap("", "_version", "_version", false, true, metaFl)
			addCap("", "_source", "_source", false, false, metaFl)
			addCap("", "_routing", "_routing", true, true, metaFl)
			addCap("", "_field_names", "_field_names", true, false, metaFl)
			addCap("", "_ignored", "_ignored", true, true, metaFl)
			if !isES8 {
				addCap("", "_type", "_type", true, true, metaFl)
			}
		}
	}

	s.mu.RLock()
	for _, idxName := range targets {
		idxSchema, ok := s.indices[idxName]
		if !ok {
			if s.isDataStreamOrBackingIndexLocked(idxName) {
				addCap(idxName, "@timestamp", "date", true, true, capEntryFlags{})
			}
			if !includeEmptyFields {
				for df, dt := range dynamicFieldTypesByIdx[idxName] {
					if dt == "text" {
						addCap(idxName, df, "text", true, false, capEntryFlags{})
						addCap(idxName, df+".keyword", "keyword", true, true, capEntryFlags{isMultifield: true})
					} else {
						addCap(idxName, df, dt, true, true, capEntryFlags{})
					}
				}
			}
			continue
		}

		runtimeFieldNames := make(map[string]bool)
		addCompositeRuntimeSubs := func(rtMap map[string]esast.FieldProperty) {
			for rn, rProp := range rtMap {
				runtimeFieldNames[rn] = true
				if strings.EqualFold(strings.TrimSpace(rProp.Type), "composite") && len(rProp.Fields) > 0 {
					for subName, subProp := range rProp.Fields {
						subType := strings.ToLower(strings.TrimSpace(subProp.Type))
						if subType == "" {
							continue
						}
						fullSub := rn + "." + subName
						runtimeFieldNames[fullSub] = true
						subAgg := subType != "text" && subType != "match_only_text" && subType != "geo_shape" && subType != "binary"
						addCap(idxName, fullSub, subType, true, subAgg, capEntryFlags{isRuntime: true})
					}
				}
			}
		}
		if idxSchema.RawMapping != nil {
			addCompositeRuntimeSubs(idxSchema.RawMapping.Runtime)
		}
		addCompositeRuntimeSubs(reqRuntimeMappings)

		var rawPropMeta func(props map[string]esast.FieldProperty, prefix string, outTSDim map[string]bool, outTSMetric map[string]string)
		tsDims := make(map[string]bool)
		tsMetrics := make(map[string]string)
		rawPropMeta = func(props map[string]esast.FieldProperty, prefix string, outTSDim map[string]bool, outTSMetric map[string]string) {
			for pName, prop := range props {
				full := pName
				if prefix != "" {
					full = prefix + "." + pName
				}
				if prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension {
					outTSDim[full] = true
				}
				if prop.TimeSeriesMetric != "" {
					outTSMetric[full] = prop.TimeSeriesMetric
				}
				if len(prop.Properties) > 0 {
					rawPropMeta(prop.Properties, full, outTSDim, outTSMetric)
				}
				for subName, subProp := range prop.Fields {
					sf := full + "." + subName
					if subProp.TimeSeriesDimension != nil && *subProp.TimeSeriesDimension {
						outTSDim[sf] = true
					}
					if subProp.TimeSeriesMetric != "" {
						outTSMetric[sf] = subProp.TimeSeriesMetric
					}
				}
			}
		}
		isTimeSeriesMode := strings.EqualFold(strings.TrimSpace(idxSchema.IndexMode), "time_series")
		if !isTimeSeriesMode {
			if cs := s.indexCustomSettings[idxName]; cs != nil {
				for _, k := range []string{"mode", "index.mode"} {
					if mv, okM := cs[k].(string); okM && strings.EqualFold(strings.TrimSpace(mv), "time_series") {
						isTimeSeriesMode = true
						break
					}
				}
			}
		}
		if isTimeSeriesMode {
			addCap(idxName, "_tsid", "_tsid", false, true, capEntryFlags{isMeta: true, metadataField: true})
			if idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Properties) > 0 {
				rawPropMeta(idxSchema.RawMapping.Properties, "", tsDims, tsMetrics)
			}
		}

		augSchema := s.augmentSchemaWithRuntimeMappings(idxSchema, reqRuntimeMappings)
		if _, hasTS := augSchema.Fields["@timestamp"]; !hasTS && s.isDataStreamOrBackingIndexLocked(idxName) {
			addCap(idxName, "@timestamp", "date", true, true, capEntryFlags{})
		}
		if idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Properties) > 0 {
			var addObjectParents func(props map[string]esast.FieldProperty, prefix string, underNested bool)
			addObjectParents = func(props map[string]esast.FieldProperty, prefix string, underNested bool) {
				for pName, prop := range props {
					full := pName
					if prefix != "" {
						full = prefix + "." + pName
					}
					pType := strings.ToLower(strings.TrimSpace(prop.Type))
					if pType == "nested" {
						addCap(idxName, full, "nested", false, false, capEntryFlags{isNested: true, isParent: true})
						if len(prop.Properties) > 0 {
							addObjectParents(prop.Properties, full, true)
						}
						continue
					}
					if (pType == "object" || (pType == "" && len(prop.Properties) > 0)) && len(prop.Properties) > 0 {
						if _, alreadyInFields := augSchema.Fields[full]; !alreadyInFields {
							addCap(idxName, full, "object", false, false, capEntryFlags{isNested: underNested, isParent: true})
						}
						addObjectParents(prop.Properties, full, underNested)
					}
				}
			}
			addObjectParents(idxSchema.RawMapping.Properties, "", false)
		}

		for esPath, fb := range augSchema.Fields {
			isRuntime := runtimeFieldNames[esPath]
			if strings.EqualFold(fb.ESType, "composite") {
				continue
			}
			if fb.ESType == "alias" {
				if fb.AliasTarget == "" {
					continue
				}
				if tb, ok := augSchema.Fields[fb.AliasTarget]; ok && tb.ESType != "alias" {
					fb.ESType = tb.ESType
					fb.DorisType = tb.DorisType
					fb.NotIndexed = tb.NotIndexed
					fb.EnabledFalse = tb.EnabledFalse
					fb.DocValuesFalse = tb.DocValuesFalse
				} else {
					continue
				}
			}
			isMulti := false
			if !isRuntime {
				if dot := strings.LastIndexByte(esPath, '.'); dot > 0 {
					if pBind, hasP := augSchema.Fields[esPath[:dot]]; hasP && pBind.ESType != "" && pBind.ESType != "object" && pBind.ESType != "nested" && pBind.ESType != "flattened" {
						isMulti = true
					}
				}
			}
			isNested := fb.ESType == "nested" || fb.NestedPath != ""
			if !isNested && len(augSchema.NestedRoots) > 0 {
				for _, nr := range augSchema.NestedRoots {
					if esPath == nr || strings.HasPrefix(esPath, nr+".") {
						isNested = true
						break
					}
				}
			}
			isParent := fb.ESType == "object" || fb.ESType == "nested" || fb.ESType == "join"
			isMeta := strings.HasPrefix(esPath, "_") && !strings.Contains(esPath, ".")

			computeSearchable := func(esType string) bool {
				if fb.EnabledFalse || esType == "nested" || esType == "object" || esType == "binary" {
					return false
				}
				if isRuntime {
					return true
				}
				if !fb.NotIndexed {
					return true
				}
				// ES 8 searches `index: false` fields via doc_values when doc_values is enabled!
				if isES8 && !fb.DocValuesFalse && isES8DocValuesSearchableTypeRound61(esType) {
					return true
				}
				return false
			}
			isAggregatableForType := func(esType string) bool {
				if fb.DocValuesFalse || fb.EnabledFalse {
					return false
				}
				switch esType {
				case "text", "match_only_text", "search_as_you_type", "rank_feature", "rank_features", "nested", "object", "dense_vector", "knn_vector", "geo_shape", "binary", "percolator", "completion":
					return false
				default:
					return true
				}
			}

			baseFlags := capEntryFlags{
				isMeta:       isMeta,
				isMultifield: isMulti,
				isNested:     isNested,
				isParent:     isParent,
				isRuntime:    isRuntime,
				tsDimension:  tsDims[esPath],
				tsMetric:     tsMetrics[esPath],
			}

			switch {
			case fb.ESType != "":
				esTypeOut := fb.ESType
				if esTypeOut == "match_only_text" && isES8 {
					esTypeOut = "text"
				}
				if s.hasExplicitTargetESVersion() && esTypeOut == "keyword" && !isMulti && !isRuntime && (dynamicFieldTypesByIdx[idxName][esPath] == "text" || s.isDynamicallyInferredStringFieldWave3R63(idxName, esPath)) {
					_, explicitRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, esPath)
					if !explicitRaw || s.isDynamicallyInferredStringFieldWave3R63(idxName, esPath) {
						addCap(idxName, esPath, "text", true, false, baseFlags)
						addCap(idxName, esPath+".keyword", "keyword", true, true, capEntryFlags{
							isMultifield: true,
							isNested:     isNested,
						})
						break
					}
				}
				addCap(idxName, esPath, esTypeOut, computeSearchable(fb.ESType), isAggregatableForType(fb.ESType), baseFlags)
				addFieldMeta(esPath, esTypeOut, fb.Meta)
				if fb.KeywordCompanion != "" && fb.AliasTarget == "" && !runtimeFieldNames[esPath+".keyword"] {
					kwSearchable := !fb.EnabledFalse
					kwAggregatable := !fb.EnabledFalse
					if kwB, okKW := augSchema.Fields[esPath+".keyword"]; okKW {
						if kwB.EnabledFalse {
							kwSearchable = false
							kwAggregatable = false
						} else {
							kwSearchable = !kwB.NotIndexed || (isES8 && !kwB.DocValuesFalse)
							kwAggregatable = !kwB.DocValuesFalse
						}
					}
					addCap(idxName, esPath+".keyword", "keyword", kwSearchable, kwAggregatable, capEntryFlags{
						isMultifield: true,
						isNested:     isNested,
						tsDimension:  tsDims[esPath+".keyword"],
						tsMetric:     tsMetrics[esPath+".keyword"],
					})
				}
				if fb.ESType == "search_as_you_type" && fb.AliasTarget == "" {
					for _, suffix := range searchAsYouTypeSubfieldsRound58(fb) {
						subPath := esPath + suffix
						if _, okSub := augSchema.Fields[subPath]; !okSub {
							addCap(idxName, subPath, "search_as_you_type", computeSearchable("search_as_you_type"), false, capEntryFlags{
								isMultifield: true,
								isNested:     isNested,
							})
						}
					}
				}
			case fb.DorisType == schema.DorisBigInt:
				t := "long"
				if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
					t = "date"
				}
				addCap(idxName, esPath, t, computeSearchable(t), isAggregatableForType(t), baseFlags)
			case fb.DorisType == schema.DorisDouble:
				addCap(idxName, esPath, "double", computeSearchable("double"), isAggregatableForType("double"), baseFlags)
			case fb.DorisType == schema.DorisBoolean:
				addCap(idxName, esPath, "boolean", computeSearchable("boolean"), isAggregatableForType("boolean"), baseFlags)
			case fb.DorisType == schema.DorisString:
				addCap(idxName, esPath, "text", computeSearchable("text"), false, baseFlags)
				if fb.KeywordCompanion != "" && fb.AliasTarget == "" && !runtimeFieldNames[esPath+".keyword"] {
					addCap(idxName, esPath+".keyword", "keyword", !fb.EnabledFalse, !fb.EnabledFalse, capEntryFlags{
						isMultifield: true,
						isNested:     isNested,
					})
				}
			default:
				if s.hasExplicitTargetESVersion() && !isMulti && !isRuntime && dynamicFieldTypesByIdx[idxName][esPath] == "text" {
					if _, explicitRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, esPath); !explicitRaw {
						addCap(idxName, esPath, "text", true, false, baseFlags)
						addCap(idxName, esPath+".keyword", "keyword", true, true, capEntryFlags{
							isMultifield: true,
							isNested:     isNested,
						})
						break
					}
				}
				addCap(idxName, esPath, "keyword", computeSearchable("keyword"), isAggregatableForType("keyword"), baseFlags)
			}
		}

		if !includeEmptyFields {
			for df, dt := range dynamicFieldTypesByIdx[idxName] {
				if _, mapped := augSchema.Fields[df]; mapped {
					continue
				}
				if dt == "text" {
					addCap(idxName, df, "text", true, false, capEntryFlags{})
					addCap(idxName, df+".keyword", "keyword", true, true, capEntryFlags{isMultifield: true})
				} else {
					addCap(idxName, df, dt, true, true, capEntryFlags{})
				}
			}
		}
	}
	s.mu.RUnlock()

	if includeUnmapped && len(targets) > 0 {
		if len(typeAllowSet) == 0 || typeAllowSet["unmapped"] {
			for field, byType := range caps {
				if strings.HasPrefix(field, "_") && !strings.Contains(field, ".") {
					continue
				}
				if byType["unmapped"] != nil {
					continue
				}
				mappedSet := make(map[string]bool)
				for _, idxList := range indicesByFieldType[field] {
					for _, idxName := range idxList {
						mappedSet[idxName] = true
					}
				}
				if len(mappedSet) > 0 && len(mappedSet) < len(targets) {
					var unmappedList []string
					for _, t := range targets {
						if !mappedSet[t] {
							unmappedList = append(unmappedList, t)
						}
					}
					if len(unmappedList) > 0 {
						byType["unmapped"] = map[string]any{
							"type":         "unmapped",
							"searchable":   false,
							"aggregatable": false,
						}
						if indicesByFieldType[field] == nil {
							indicesByFieldType[field] = make(map[string][]string)
						}
						indicesByFieldType[field]["unmapped"] = unmappedList
					}
				}
			}
		}
		for _, rawPat := range filterPatterns {
			f := strings.TrimSpace(rawPat)
			if f == "" || strings.HasPrefix(f, "-") || strings.ContainsAny(f, "*?") {
				continue
			}
			if caps[f] != nil {
				continue
			}
			if !matchesFieldCapsPatterns(f, filterPatterns) {
				continue
			}
			isMeta := strings.HasPrefix(f, "_")
			if !fcFilters.allows(isMeta, false, false, false, false, !isMeta) {
				continue
			}
			if len(typeAllowSet) > 0 && !typeAllowSet["unmapped"] {
				continue
			}
			caps[f] = map[string]map[string]any{
				"unmapped": {
					"type":         "unmapped",
					"searchable":   false,
					"aggregatable": false,
					"indices":      targets,
				},
			}
		}
	}

	for field, byType := range caps {
		for esType, entry := range byType {
			allIdxForType := append([]string(nil), indicesByFieldType[field][esType]...)
			sort.Strings(allIdxForType)
			if len(byType) > 1 && len(allIdxForType) > 0 {
				entry["indices"] = allIdxForType
			}
			if mm := metaByFieldType[field][esType]; len(mm) > 0 {
				entry["meta"] = mm
			}
			if nonS := append([]string(nil), nonSearchableByFieldType[field][esType]...); len(nonS) > 0 && len(nonS) < len(allIdxForType) {
				sort.Strings(nonS)
				entry["non_searchable_indices"] = nonS
			}
			if nonA := append([]string(nil), nonAggregatableByFieldType[field][esType]...); len(nonA) > 0 && len(nonA) < len(allIdxForType) {
				sort.Strings(nonA)
				entry["non_aggregatable_indices"] = nonA
			}
			if dimIdx := dimIndicesByFieldType[field][esType]; len(dimIdx) > 0 {
				if len(dimIdx) < len(allIdxForType) {
					dimSet := make(map[string]bool, len(dimIdx))
					for _, di := range dimIdx {
						dimSet[di] = true
					}
					var nonDim []string
					for _, ai := range allIdxForType {
						if !dimSet[ai] {
							nonDim = append(nonDim, ai)
						}
					}
					if len(nonDim) > 0 {
						sort.Strings(nonDim)
						entry["non_dimension_indices"] = nonDim
					} else {
						entry["time_series_dimension"] = true
					}
				} else {
					entry["time_series_dimension"] = true
				}
			}
			if mTypes := metricTypesByFieldType[field][esType]; len(mTypes) > 0 {
				if len(mTypes) == 1 {
					for mType, mIndices := range mTypes {
						if len(mIndices) == len(allIdxForType) {
							entry["time_series_metric"] = mType
						} else {
							entry["metric_conflicts_indices"] = allIdxForType
						}
					}
				} else {
					entry["metric_conflicts_indices"] = allIdxForType
				}
			}
		}
	}

	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"indices": targets,
		"fields":  caps,
	})
}

func isValidMonitoringSystemIDR66(v string) bool {
	if len(v) == 0 || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isValidMonitoringSystemAPIVersionR66(v string) bool {
	if len(v) == 0 || len(v) > 32 {
		return false
	}
	segs := strings.Split(v, ".")
	if len(segs) > 3 {
		return false
	}
	for _, seg := range segs {
		if len(seg) == 0 {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlphaNum && c != '_' && c != '-' {
				return false
			}
		}
	}
	return true
}

func extractMonitoringRoleNamesR66(rawRoles any) []string {
	var roleNames []string
	switch rv := rawRoles.(type) {
	case []string:
		for _, r := range rv {
			if r != "" {
				roleNames = append(roleNames, r)
			}
		}
	case []any:
		for _, item := range rv {
			if rs, okS := item.(string); okS && rs != "" {
				roleNames = append(roleNames, rs)
			}
		}
	}
	return roleNames
}

func roleMapAllowsMonitoringBulkR66(role map[string]any) bool {
	if role == nil {
		return false
	}
	var clPrivs []string
	switch cp := role["cluster"].(type) {
	case []string:
		clPrivs = append(clPrivs, cp...)
	case []any:
		for _, item := range cp {
			if ps, okS := item.(string); okS {
				clPrivs = append(clPrivs, ps)
			}
		}
	}
	for _, priv := range clPrivs {
		if priv == "all" || priv == "manage" || priv == "manage_monitoring" || strings.HasPrefix(priv, "cluster:admin/xpack/monitoring/") {
			return true
		}
	}
	return false
}

func userRolesAllowMonitoringBulkR66(roleNames []string, securityRoles map[string]map[string]any) bool {
	for _, rn := range roleNames {
		switch rn {
		case "superuser", "remote_monitoring_agent", "remote_monitoring_collector", "beats_system", "kibana_system", "logstash_system", "apm_system":
			return true
		}
		if roleMapAllowsMonitoringBulkR66(securityRoles[rn]) {
			return true
		}
	}
	return false
}

func (s *Server) authorizeMonitoringBulkRequestR66(r *http.Request) (int, string, string) {
	s.authMu.RLock()
	basicAuthUser := strings.TrimSpace(s.basicAuthUser)
	basicAuthPass := s.basicAuthPass
	proxyAPIKey := strings.TrimSpace(s.apiKey)
	s.authMu.RUnlock()

	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHdr == "" {
		s.mu.RLock()
		hasDynamicAuth := len(s.securityUsers) > 0 || len(s.securityAPIKeys) > 0 || len(s.securityServiceTokens) > 0
		s.mu.RUnlock()
		if basicAuthUser != "" || proxyAPIKey != "" || hasDynamicAuth {
			return http.StatusUnauthorized, "security_exception", "missing authentication credentials for REST request [/_monitoring/bulk]"
		}
		return 0, "", ""
	}
	parts := strings.SplitN(authHdr, " ", 2)
	if len(parts) != 2 {
		return http.StatusUnauthorized, "security_exception", "unable to authenticate request [/_monitoring/bulk]"
	}
	scheme := strings.ToLower(strings.TrimSpace(parts[0]))
	rawTok := strings.TrimSpace(parts[1])

	switch scheme {
	case "basic":
		dec, err := base64.StdEncoding.DecodeString(rawTok)
		if err != nil {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate request [/_monitoring/bulk]"
		}
		cred := string(dec)
		user, pass, okCut := strings.Cut(cred, ":")
		if !okCut || user == "" {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate request [/_monitoring/bulk]"
		}
		s.mu.RLock()
		defer s.mu.RUnlock()

		if s.matchesTestFixtureAdminLockedR66(cred, basicAuthUser, proxyAPIKey) {
			return 0, "", ""
		}
		if basicAuthUser != "" && user == basicAuthUser && s.securityUsers[basicAuthUser] == nil {
			if len(pass) == len(basicAuthPass) && subtle.ConstantTimeCompare([]byte(pass), []byte(basicAuthPass)) == 1 {
				return 0, "", ""
			}
			return http.StatusUnauthorized, "security_exception", fmt.Sprintf("unable to authenticate user [%s] for REST request [/_monitoring/bulk]", user)
		}
		uObj := s.securityUsers[user]
		if uObj == nil {
			return http.StatusUnauthorized, "security_exception", fmt.Sprintf("unable to authenticate user [%s] for REST request [/_monitoring/bulk]", user)
		}
		if enabled, hasEnabled := uObj["enabled"].(bool); hasEnabled && !enabled {
			return http.StatusUnauthorized, "security_exception", fmt.Sprintf("unable to authenticate user [%s] for REST request [/_monitoring/bulk]", user)
		}
		if !verifySecurityUserPasswordR66(uObj, pass) {
			return http.StatusUnauthorized, "security_exception", fmt.Sprintf("unable to authenticate user [%s] for REST request [/_monitoring/bulk]", user)
		}
		roleNames := extractMonitoringRoleNamesR66(uObj["roles"])
		if userRolesAllowMonitoringBulkR66(roleNames, s.securityRoles) {
			return 0, "", ""
		}
		return http.StatusForbidden, "security_exception", fmt.Sprintf("action [cluster:admin/xpack/monitoring/bulk] is unauthorized for user [%s] with effective roles [%s], this action is granted by the cluster privileges [manage,all]", user, strings.Join(roleNames, ","))

	case "apikey":
		if proxyAPIKey != "" && len(rawTok) == len(proxyAPIKey) && subtle.ConstantTimeCompare([]byte(rawTok), []byte(proxyAPIKey)) == 1 {
			return 0, "", ""
		}
		dec, err := base64.StdEncoding.DecodeString(rawTok)
		if err != nil {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate ApiKey for REST request [/_monitoring/bulk]"
		}
		keyID, secret, okCut := strings.Cut(string(dec), ":")
		if !okCut || keyID == "" {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate ApiKey for REST request [/_monitoring/bulk]"
		}
		s.mu.RLock()
		defer s.mu.RUnlock()

		kObj := s.securityAPIKeys[keyID]
		if !verifySecurityAPIKeySecretAndExpiryR66(kObj, secret, time.Now()) {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate ApiKey for REST request [/_monitoring/bulk]"
		}
		owner, _ := kObj["username"].(string)
		if owner == "" {
			return http.StatusUnauthorized, "security_exception", "unable to authenticate ApiKey for REST request [/_monitoring/bulk]"
		}
		if owner != "elastic" || s.securityUsers["elastic"] != nil {
			ownerObj := s.securityUsers[owner]
			if ownerObj == nil {
				return http.StatusForbidden, "security_exception", fmt.Sprintf("action [cluster:admin/xpack/monitoring/bulk] is unauthorized for ApiKey owner [%s]", owner)
			}
			if enabled, hasEnabled := ownerObj["enabled"].(bool); hasEnabled && !enabled {
				return http.StatusForbidden, "security_exception", fmt.Sprintf("action [cluster:admin/xpack/monitoring/bulk] is unauthorized for ApiKey owner [%s]", owner)
			}
			ownerRoles := extractMonitoringRoleNamesR66(ownerObj["roles"])
			if !userRolesAllowMonitoringBulkR66(ownerRoles, s.securityRoles) {
				return http.StatusForbidden, "security_exception", fmt.Sprintf("action [cluster:admin/xpack/monitoring/bulk] is unauthorized for user [%s] with effective roles [%s], this action is granted by the cluster privileges [manage,all]", owner, strings.Join(ownerRoles, ","))
			}
		}
		if rawRD, hasRD := kObj["role_descriptors"]; hasRD && rawRD != nil {
			rdMap, okRD := rawRD.(map[string]any)
			if !okRD || len(rdMap) == 0 {
				return http.StatusForbidden, "security_exception", "action [cluster:admin/xpack/monitoring/bulk] is unauthorized for ApiKey"
			}
			allowedByDesc := false
			for _, v := range rdMap {
				if rm, okRM := v.(map[string]any); okRM && roleMapAllowsMonitoringBulkR66(rm) {
					allowedByDesc = true
					break
				}
			}
			if !allowedByDesc {
				return http.StatusForbidden, "security_exception", "action [cluster:admin/xpack/monitoring/bulk] is unauthorized for ApiKey"
			}
		}
		return 0, "", ""

	case "bearer":
		if proxyAPIKey != "" && len(rawTok) == len(proxyAPIKey) && subtle.ConstantTimeCompare([]byte(rawTok), []byte(proxyAPIKey)) == 1 {
			return 0, "", ""
		}
		return http.StatusUnauthorized, "security_exception", "unable to authenticate Bearer token for REST request [/_monitoring/bulk]"

	default:
		return http.StatusUnauthorized, "security_exception", "unsupported authentication scheme for REST request [/_monitoring/bulk]"
	}
}

func (s *Server) handleMonitoringBulkR65(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if status, errType, errReason := s.authorizeMonitoringBulkRequestR66(r); status != 0 {
		writeESError(w, status, errType, errReason)
		return
	}
	if r.URL != nil && strings.HasPrefix(r.URL.Path, "/_xpack/monitoring/") {
		emitESDeprecationWarningRound61(w, s, r, fmt.Sprintf("[%s %s] is deprecated! Use [%s /_monitoring/bulk] instead.", r.Method, r.URL.Path, r.Method))
	}

	q := r.URL.Query()
	systemID := strings.TrimSpace(q.Get("system_id"))
	if systemID == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Validation Failed: 1: system_id is missing;")
		return
	}
	if !isValidMonitoringSystemIDR66(systemID) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Validation Failed: 1: invalid system_id;")
		return
	}
	sysAPIVer := strings.TrimSpace(q.Get("system_api_version"))
	if sysAPIVer == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Validation Failed: 1: system_api_version is missing;")
		return
	}
	if !isValidMonitoringSystemAPIVersionR66(sysAPIVer) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Validation Failed: 1: invalid system_api_version;")
		return
	}
	intervalStr := strings.TrimSpace(q.Get("interval"))
	if intervalStr == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Validation Failed: 1: interval is missing;")
		return
	}
	intervalMs, err := parseESDurationMillisRound59(intervalStr)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
		return
	}

	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	defaultType := strings.TrimSpace(r.PathValue("type"))
	if defaultType == "" {
		var segs []string
		for _, seg := range strings.Split(strings.Trim(r.URL.Path, "/"), "/") {
			if seg != "" {
				segs = append(segs, seg)
			}
		}
		if len(segs) == 3 && segs[0] == "_monitoring" && (segs[2] == "bulk" || segs[2] == "_bulk") {
			defaultType = segs[1]
		} else if len(segs) == 4 && segs[0] == "_xpack" && segs[1] == "monitoring" && (segs[3] == "bulk" || segs[3] == "_bulk") {
			defaultType = segs[2]
		}
	}
	safeSysID := strings.ToLower(systemID)
	safeSysVer := strings.ToLower(sysAPIVer)
	targetIdx := fmt.Sprintf(".monitoring-%s-%s-%s", safeSysID, safeSysVer, time.Now().UTC().Format("2006.01.02"))
	if s.findClosedTargetIndex(r, fmt.Sprintf(".monitoring-%s-*", safeSysID)) != "" || s.isIndexClosed(targetIdx) {
		writeESError(w, http.StatusInternalServerError, "export_exception", fmt.Sprintf("closed [%s]", targetIdx))
		return
	}

	lines := strings.Split(strings.ReplaceAll(string(bodyBytes), "\r\n", "\n"), "\n")
	var nonEmpty []string
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			nonEmpty = append(nonEmpty, ln)
		}
	}
	if len(nonEmpty)%2 != 0 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "The bulk request must be terminated by a newline [\\n]")
		return
	}

	var bulkBuf bytes.Buffer
	numIndexed := 0
	for i := 0; i < len(nonEmpty); i += 2 {
		var actionMap map[string]map[string]any
		if err := json.Unmarshal([]byte(nonEmpty[i]), &actionMap); err != nil || len(actionMap) != 1 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Malformed monitoring bulk action line")
			return
		}
		var meta map[string]any
		for _, m := range actionMap {
			meta = m
			break
		}
		rawIdx, _ := meta["_index"].(string)
		if strings.TrimSpace(rawIdx) == "_data" {
			continue
		}
		var docMap map[string]any
		dec := json.NewDecoder(strings.NewReader(nonEmpty[i+1]))
		dec.UseNumber()
		if err := dec.Decode(&docMap); err != nil || docMap == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Malformed monitoring bulk document line")
			return
		}
		docType, _ := meta["_type"].(string)
		docType = strings.TrimSpace(docType)
		if docType == "" {
			docType = defaultType
		}
		if docType != "" {
			if _, exists := docMap["type"]; !exists {
				docMap["type"] = docType
			}
		}
		if _, exists := docMap["interval_ms"]; !exists {
			docMap["interval_ms"] = intervalMs
		}
		if _, exists := docMap["timestamp"]; !exists {
			docMap["timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		}
		newMeta := map[string]any{"_index": targetIdx}
		if idStr, _ := meta["_id"].(string); idStr != "" {
			newMeta["_id"] = idStr
		}
		actBytes, _ := json.Marshal(map[string]any{"index": newMeta})
		docBytes, _ := json.Marshal(docMap)
		bulkBuf.Write(actBytes)
		bulkBuf.WriteByte('\n')
		bulkBuf.Write(docBytes)
		bulkBuf.WriteByte('\n')
		numIndexed++
	}
	if numIndexed == 0 {
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"took":    int64(1),
			"errors":  false,
			"ignored": false,
			"items":   []any{},
		})
		return
	}
	bulkReq := r.Clone(r.Context())
	bulkReq.URL.Path = "/_bulk"
	bulkReq.Body = io.NopCloser(bytes.NewReader(bulkBuf.Bytes()))
	bulkReq.ContentLength = int64(bulkBuf.Len())
	s.handleBulk(w, bulkReq)
}
