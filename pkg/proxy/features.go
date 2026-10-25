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
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const (
	// DefaultMaxRequestBodyBytes bounds both compressed and decompressed HTTP request bodies (100 MiB, matching ES http.max_content_length).
	DefaultMaxRequestBodyBytes int64 = 100 * 1024 * 1024
	slowLogRingCapacity              = 100
	shadowDiffRingCapacity           = 50
)

var (
	gzipReaderPool sync.Pool
	gzipWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
			return w
		},
	}
)

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.Header().Del("Content-Length")
		w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
		w.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.gz.Write(b)
}

func (w *gzipResponseWriter) Close() {
	if w.gz != nil {
		_ = w.gz.Close()
		w.gz.Reset(io.Discard)
		gzipWriterPool.Put(w.gz)
		w.gz = nil
	}
}

// withWireMiddleware wraps the proxy router with:
// 1. CORS headers & global OPTIONS preflight handling for browser GUIs (Elasticvue, Cerebro, Kibana)
// 2. Bounded request body size (`http.MaxBytesReader`)
// 3. Transparent `Content-Encoding: gzip` / `x-gzip` request decompression (Vector, Fluent Bit, Filebeat, OTel)
// 4. Optional `Accept-Encoding: gzip` outbound response compression
func (s *Server) withWireMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setESCompatHeaders(w, r)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		maxBytes := s.maxBodyBytes
		if maxBytes <= 0 {
			maxBytes = DefaultMaxRequestBodyBytes
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}

		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
		case "gzip", "x-gzip":
			var gz *gzip.Reader
			if pooled := gzipReaderPool.Get(); pooled != nil {
				gz = pooled.(*gzip.Reader)
				if err := gz.Reset(r.Body); err != nil {
					gzipReaderPool.Put(gz)
					writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid gzip stream: "+err.Error())
					return
				}
			} else {
				var err error
				gz, err = gzip.NewReader(r.Body)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid gzip stream: "+err.Error())
					return
				}
			}
			defer func() {
				_ = gz.Close()
				gzipReaderPool.Put(gz)
			}()
			r.Body = http.MaxBytesReader(w, gz, maxBytes)
			r.Header.Del("Content-Encoding")
			r.Header.Del("Content-Length")
		case "", "identity":
			// pass through
		default:
			writeESError(w, http.StatusUnsupportedMediaType, "illegal_argument_exception",
				"unsupported Content-Encoding: "+r.Header.Get("Content-Encoding"))
			return
		}

		if r.Method != http.MethodHead && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w)
			gzw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
			defer gzw.Close()
			w = gzw
		}

		next.ServeHTTP(w, r)
	})
}

// SlowQueryEntry records a search execution and any unpromoted `_doc[...]` VARIANT fields it touched.
type SlowQueryEntry struct {
	Timestamp              string   `json:"timestamp"`
	Index                  string   `json:"index"`
	TookMs                 int64    `json:"took_ms"`
	TotalHits              int64    `json:"total_hits"`
	HitsSQL                string   `json:"hits_sql,omitempty"`
	AggsSQL                string   `json:"aggs_sql,omitempty"`
	UnindexedVariantFields []string `json:"unindexed_variant_fields,omitempty"`
}

// AutoIndexRecommendation suggests `ALTER TABLE` statements to promote frequently queried dynamic fields.
type AutoIndexRecommendation struct {
	Index          string   `json:"index"`
	Field          string   `json:"field"`
	AccessCount    int64    `json:"access_count"`
	AlterTableDDLs []string `json:"alter_table_ddls"`
}

// SlowQueryTracker maintains a thread-safe ring buffer of query executions and dynamic field access counts.
type SlowQueryTracker struct {
	mu            sync.RWMutex
	entries       []SlowQueryEntry
	unindexedFreq map[string]map[string]int64 // index -> field -> count
}

func newSlowQueryTracker() *SlowQueryTracker {
	return &SlowQueryTracker{
		entries:       make([]SlowQueryEntry, 0, slowLogRingCapacity),
		unindexedFreq: make(map[string]map[string]int64),
	}
}

func (t *SlowQueryTracker) record(entry SlowQueryEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= slowLogRingCapacity {
		copy(t.entries, t.entries[1:])
		t.entries[len(t.entries)-1] = entry
	} else {
		t.entries = append(t.entries, entry)
	}
	if len(entry.UnindexedVariantFields) > 0 {
		byField, ok := t.unindexedFreq[entry.Index]
		if !ok {
			byField = make(map[string]int64)
			t.unindexedFreq[entry.Index] = byField
		}
		for _, f := range entry.UnindexedVariantFields {
			byField[f]++
		}
	}
}

func (s *Server) handleDorisSlowlog(w http.ResponseWriter, r *http.Request) {
	indexFilter := r.PathValue("index")
	if indexFilter != "" {
		indexFilter = s.resolveIndexName(indexFilter)
	}

	s.slowTracker.mu.RLock()
	entries := make([]SlowQueryEntry, 0, len(s.slowTracker.entries))
	for i := len(s.slowTracker.entries) - 1; i >= 0; i-- {
		e := s.slowTracker.entries[i]
		if indexFilter == "" || e.Index == indexFilter {
			entries = append(entries, e)
		}
	}
	freqSnapshot := make(map[string]map[string]int64, len(s.slowTracker.unindexedFreq))
	for idx, fields := range s.slowTracker.unindexedFreq {
		if indexFilter != "" && idx != indexFilter {
			continue
		}
		cp := make(map[string]int64, len(fields))
		for f, cnt := range fields {
			cp[f] = cnt
		}
		freqSnapshot[idx] = cp
	}
	s.slowTracker.mu.RUnlock()

	var recommendations []AutoIndexRecommendation
	idxNames := make([]string, 0, len(freqSnapshot))
	for idx := range freqSnapshot {
		idxNames = append(idxNames, idx)
	}
	sort.Strings(idxNames)

	for _, idxName := range idxNames {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		fields := freqSnapshot[idxName]
		fNames := make([]string, 0, len(fields))
		for f := range fields {
			fNames = append(fNames, f)
		}
		sort.Strings(fNames)
		for _, f := range fNames {
			ddls := schema.GeneratePromoteVariantFieldDDL(idxSchema, f, "keyword")
			recommendations = append(recommendations, AutoIndexRecommendation{
				Index:          idxName,
				Field:          f,
				AccessCount:    fields[f],
				AlterTableDDLs: ddls,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_recorded_queries":     len(entries),
		"queries":                    entries,
		"unindexed_variant_accesses": freqSnapshot,
		"auto_index_recommendations": recommendations,
	})
}

// ShadowDiffEntry records a discrepancy between Apache Doris and a shadow Elasticsearch cluster.
type ShadowDiffEntry struct {
	Timestamp   string  `json:"timestamp"`
	Index       string  `json:"index"`
	DorisTotal  int64   `json:"doris_total"`
	ESTotal     int64   `json:"es_total"`
	TopKJaccard float64 `json:"topk_jaccard"`
	DorisTookMs int64   `json:"doris_took_ms"`
	ESTookMs    int64   `json:"es_took_ms"`
}

// ShadowVerifier compares Doris search responses against a legacy Elasticsearch cluster (`--shadow-es-url`).
type ShadowVerifier struct {
	mu               sync.RWMutex
	targetURL        string
	client           *http.Client
	totalQueries     int64
	hitParityMatches int64
	jaccardSum       float64
	dorisTookSumMs   int64
	esTookSumMs      int64
	recentDiffs      []ShadowDiffEntry
}

func newShadowVerifier(targetURL string) *ShadowVerifier {
	return &ShadowVerifier{
		targetURL: strings.TrimRight(strings.TrimSpace(targetURL), "/"),
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SetShadowESURL configures dual-read shadow verification against an existing Elasticsearch/OpenSearch endpoint.
func (s *Server) SetShadowESURL(url string) {
	s.shadowVerifier.mu.Lock()
	defer s.shadowVerifier.mu.Unlock()
	s.shadowVerifier.targetURL = strings.TrimRight(strings.TrimSpace(url), "/")
}

func (s *Server) maybeRunShadowSearch(rawIndex string, req *esast.SearchRequest, dorisResp map[string]any, dorisTookMs int64, syncMode bool) {
	s.shadowVerifier.mu.RLock()
	targetURL := s.shadowVerifier.targetURL
	s.shadowVerifier.mu.RUnlock()
	if targetURL == "" {
		return
	}
	run := func() {
		s.executeShadowComparison(targetURL, rawIndex, req, dorisResp, dorisTookMs)
	}
	if syncMode {
		run()
	} else {
		go run()
	}
}

func (s *Server) executeShadowComparison(targetURL, rawIndex string, req *esast.SearchRequest, dorisResp map[string]any, dorisTookMs int64) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return
	}
	endpoint := targetURL + "/_search"
	if rawIndex != "" {
		endpoint = targetURL + "/" + rawIndex + "/_search"
	}
	start := time.Now()
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.shadowVerifier.client.Do(httpReq)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	esTookMs := time.Since(start).Milliseconds()
	if esTookMs <= 0 {
		esTookMs = 1
	}

	var esPayload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&esPayload); err != nil {
		return
	}

	dorisTotal, dorisIDs := extractTotalAndHitIDs(dorisResp)
	esTotal, esIDs := extractTotalAndHitIDs(esPayload)
	if t, ok := toInt64(esPayload["took"]); ok && t > 0 {
		esTookMs = t
	}
	jaccard := computeJaccard(dorisIDs, esIDs)

	s.shadowVerifier.mu.Lock()
	defer s.shadowVerifier.mu.Unlock()
	s.shadowVerifier.totalQueries++
	if dorisTotal == esTotal {
		s.shadowVerifier.hitParityMatches++
	}
	s.shadowVerifier.jaccardSum += jaccard
	s.shadowVerifier.dorisTookSumMs += dorisTookMs
	s.shadowVerifier.esTookSumMs += esTookMs

	if dorisTotal != esTotal || jaccard < 1.0 {
		diff := ShadowDiffEntry{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Index:       rawIndex,
			DorisTotal:  dorisTotal,
			ESTotal:     esTotal,
			TopKJaccard: jaccard,
			DorisTookMs: dorisTookMs,
			ESTookMs:    esTookMs,
		}
		if len(s.shadowVerifier.recentDiffs) >= shadowDiffRingCapacity {
			copy(s.shadowVerifier.recentDiffs, s.shadowVerifier.recentDiffs[1:])
			s.shadowVerifier.recentDiffs[len(s.shadowVerifier.recentDiffs)-1] = diff
		} else {
			s.shadowVerifier.recentDiffs = append(s.shadowVerifier.recentDiffs, diff)
		}
	}
}

func extractTotalAndHitIDs(resp map[string]any) (int64, []string) {
	var total int64
	var ids []string
	hitsWrapper, ok := resp["hits"].(map[string]any)
	if !ok {
		return 0, nil
	}
	if totalObj, ok := hitsWrapper["total"].(map[string]any); ok {
		total, _ = toInt64(totalObj["value"])
	} else {
		total, _ = toInt64(hitsWrapper["total"])
	}
	switch hList := hitsWrapper["hits"].(type) {
	case []map[string]any:
		for _, h := range hList {
			if id, ok := h["_id"].(string); ok {
				ids = append(ids, id)
			}
		}
	case []any:
		for _, item := range hList {
			if h, ok := item.(map[string]any); ok {
				if id, ok := h["_id"].(string); ok {
					ids = append(ids, id)
				}
			}
		}
	}
	return total, ids
}

func computeJaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	setA := make(map[string]bool, len(a))
	union := make(map[string]bool, len(a)+len(b))
	for _, x := range a {
		setA[x] = true
		union[x] = true
	}
	intersection := 0
	for _, y := range b {
		union[y] = true
		if setA[y] {
			intersection++
		}
	}
	if len(union) == 0 {
		return 1.0
	}
	return float64(intersection) / float64(len(union))
}

func (s *Server) handleDorisShadowStats(w http.ResponseWriter, _ *http.Request) {
	s.shadowVerifier.mu.RLock()
	defer s.shadowVerifier.mu.RUnlock()

	parityRate := 1.0
	avgJaccard := 1.0
	avgDorisMs := 0.0
	avgESMs := 0.0
	speedup := 1.0
	if s.shadowVerifier.totalQueries > 0 {
		q := float64(s.shadowVerifier.totalQueries)
		parityRate = float64(s.shadowVerifier.hitParityMatches) / q
		avgJaccard = s.shadowVerifier.jaccardSum / q
		avgDorisMs = float64(s.shadowVerifier.dorisTookSumMs) / q
		avgESMs = float64(s.shadowVerifier.esTookSumMs) / q
		if avgDorisMs > 0 {
			speedup = avgESMs / avgDorisMs
		}
	}
	diffs := make([]ShadowDiffEntry, len(s.shadowVerifier.recentDiffs))
	copy(diffs, s.shadowVerifier.recentDiffs)

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":                     s.shadowVerifier.targetURL != "",
		"shadow_es_url":               s.shadowVerifier.targetURL,
		"total_shadow_queries":        s.shadowVerifier.totalQueries,
		"hit_count_parity_matches":    s.shadowVerifier.hitParityMatches,
		"hit_count_parity_rate":       parityRate,
		"avg_topk_jaccard_similarity": avgJaccard,
		"avg_doris_took_ms":           avgDorisMs,
		"avg_es_took_ms":              avgESMs,
		"doris_speedup_factor":        speedup,
		"recent_diffs":                diffs,
	})
}

// handleResolveIndex implements `GET /_resolve/index/{name}` for Kibana 8.x Data Views & Grafana 10+.
func (s *Server) handleResolveIndex(w http.ResponseWriter, r *http.Request) {
	pattern := r.PathValue("name")
	if pattern == "" {
		pattern = "*"
	}
	_ = s.syncCatalogFromBackend(r.Context())

	s.mu.RLock()
	var indicesOut []map[string]any
	idxNames := make([]string, 0, len(s.indices))
	for name := range s.indices {
		idxNames = append(idxNames, name)
	}
	sort.Strings(idxNames)
	for _, name := range idxNames {
		if matchWildcardPattern(pattern, name) {
			var idxAliases []string
			for al, targets := range s.aliases {
				for _, t := range targets {
					if t == name {
						idxAliases = append(idxAliases, al)
					}
				}
			}
			sort.Strings(idxAliases)
			entry := map[string]any{
				"name":       name,
				"attributes": []string{"open"},
			}
			if len(idxAliases) > 0 {
				entry["aliases"] = idxAliases
			}
			indicesOut = append(indicesOut, entry)
		}
	}

	var aliasesOut []map[string]any
	alNames := make([]string, 0, len(s.aliases))
	for al := range s.aliases {
		alNames = append(alNames, al)
	}
	sort.Strings(alNames)
	for _, al := range alNames {
		if matchWildcardPattern(pattern, al) {
			aliasesOut = append(aliasesOut, map[string]any{
				"name":    al,
				"indices": s.aliases[al],
			})
		}
	}
	s.mu.RUnlock()

	if indicesOut == nil {
		indicesOut = []map[string]any{}
	}
	if aliasesOut == nil {
		aliasesOut = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"indices":      indicesOut,
		"aliases":      aliasesOut,
		"data_streams": []any{},
	})
}

// handleIndexStats implements `GET /_stats` and `GET /{index}/_stats` for Elasticvue, Cerebro, and monitoring clients.
func (s *Server) handleIndexStats(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	targets := s.resolveTargetIndices(rawIndex)

	indicesMap := make(map[string]any, len(targets))
	var totalDocs int64

	for _, idxName := range targets {
		zero := 0
		resp, _, errType, _ := s.executeSearchRequest(r.Context(), idxName, &esast.SearchRequest{Size: &zero})
		var docCount int64
		if errType == "" {
			docCount, _ = extractTotalAndHitIDs(resp)
		}
		totalDocs += docCount
		statsObj := map[string]any{
			"docs": map[string]any{
				"count":   docCount,
				"deleted": 0,
			},
			"store": map[string]any{
				"size_in_bytes": docCount * 512,
			},
		}
		indicesMap[idxName] = map[string]any{
			"uuid":      "doris-" + schema.SanitizeDorisIdentifier(idxName),
			"primaries": statsObj,
			"total":     statsObj,
		}
	}

	aggStats := map[string]any{
		"docs": map[string]any{
			"count":   totalDocs,
			"deleted": 0,
		},
		"store": map[string]any{
			"size_in_bytes": totalDocs * 512,
		},
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": len(targets), "successful": len(targets), "failed": 0},
		"_all": map[string]any{
			"primaries": aggStats,
			"total":     aggStats,
		},
		"indices": indicesMap,
	})
}

// handleSearchShards implements `GET /{index}/_search_shards` for Spark-ES / Hadoop-ES / Kibana clients.
func (s *Server) handleSearchShards(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	indicesOut := make(map[string]any, len(targets))
	var shardsOut [][]map[string]any
	for _, idx := range targets {
		indicesOut[idx] = map[string]any{}
		shardsOut = append(shardsOut, []map[string]any{
			{
				"state":   "STARTED",
				"primary": true,
				"node":    "doris-fe-1",
				"shard":   0,
				"index":   idx,
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": map[string]any{
			"doris-fe-1": map[string]any{
				"name":              "doris-fe-1",
				"transport_address": "127.0.0.1:9030",
				"attributes":        map[string]any{},
			},
		},
		"indices": indicesOut,
		"shards":  shardsOut,
	})
}

// handleIngestPipeline provides compatibility for Beats, OTel, and Logstash `/_ingest/pipeline` checks.
func (s *Server) handleIngestPipeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		if body == nil {
			body = map[string]any{"description": "doris-es-proxy compatibility pipeline", "processors": []any{}}
		}
		s.mu.Lock()
		if s.pipelines == nil {
			s.pipelines = make(map[string]map[string]any)
		}
		if id != "" {
			s.pipelines[id] = body
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.pipelines, id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()
		if id != "" {
			if p, ok := s.pipelines[id]; ok {
				writeJSON(w, http.StatusOK, map[string]any{id: p})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				id: map[string]any{"description": "doris-es-proxy default pipeline", "processors": []any{}},
			})
			return
		}
		out := make(map[string]any, len(s.pipelines))
		for k, v := range s.pipelines {
			out[k] = v
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

// handleCatNodes implements `GET /_cat/nodes` for Elasticvue & Cerebro.
func (s *Server) handleCatNodes(w http.ResponseWriter, r *http.Request) {
	rows := []map[string]any{
		{
			"ip":           "127.0.0.1",
			"heap.percent": "15",
			"ram.percent":  "30",
			"cpu":          "5",
			"node.role":    "cdfhilmrstw",
			"master":       "*",
			"name":         "doris-fe-1",
		},
	}
	writeCatResponse(w, r, []string{"ip", "heap.percent", "ram.percent", "cpu", "node.role", "master", "name"}, rows)
}

// handleCatShards implements `GET /_cat/shards` for Elasticvue & Cerebro.
func (s *Server) handleCatShards(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	names := make([]string, 0, len(s.indices))
	for name := range s.indices {
		names = append(names, name)
	}
	s.mu.RUnlock()
	sort.Strings(names)
	rows := make([]map[string]any, 0, len(names))
	for _, name := range names {
		rows = append(rows, map[string]any{
			"index":  name,
			"shard":  "0",
			"prirep": "p",
			"state":  "STARTED",
			"node":   "doris-fe-1",
		})
	}
	writeCatResponse(w, r, []string{"index", "shard", "prirep", "state", "node"}, rows)
}

// handleCatCount implements `GET /_cat/count`.
func (s *Server) handleCatCount(w http.ResponseWriter, r *http.Request) {
	zero := 0
	resp, _, _, _ := s.executeSearchRequest(r.Context(), r.PathValue("index"), &esast.SearchRequest{Size: &zero})
	total, _ := extractTotalAndHitIDs(resp)
	now := time.Now().UTC()
	rows := []map[string]any{
		{
			"epoch":     fmt.Sprintf("%d", now.Unix()),
			"timestamp": now.Format("15:04:05"),
			"count":     fmt.Sprintf("%d", total),
		},
	}
	writeCatResponse(w, r, []string{"epoch", "timestamp", "count"}, rows)
}

func writeCatResponse(w http.ResponseWriter, r *http.Request, headers []string, rows []map[string]any) {
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "txt" {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Has("v") {
			_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
		}
		for _, row := range rows {
			vals := make([]string, 0, len(headers))
			for _, h := range headers {
				vals = append(vals, fmt.Sprintf("%v", row[h]))
			}
			_, _ = fmt.Fprintln(w, strings.Join(vals, "\t"))
		}
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleReindex implements `POST /_reindex` to copy documents between indices with optional query filtering and Painless script mutation.
func (s *Server) handleReindex(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var body struct {
		Source struct {
			Index any          `json:"index"`
			Query *esast.Query `json:"query,omitempty"`
			Size  *int         `json:"size,omitempty"`
		} `json:"source"`
		Dest struct {
			Index string `json:"index"`
		} `json:"dest"`
		Script *painless.ScriptSpec `json:"script,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}

	var srcPattern string
	switch v := body.Source.Index.(type) {
	case string:
		srcPattern = v
	case []any:
		var parts []string
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		srcPattern = strings.Join(parts, ",")
	}
	destIndex := s.resolveIndexName(body.Dest.Index)
	if srcPattern == "" || destIndex == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "source.index and dest.index are required")
		return
	}

	destSchema := s.ensureWritableIndexSchema(r.Context(), destIndex)
	srcTargets := s.resolveTargetIndices(srcPattern)
	if len(srcTargets) == 0 {
		srcTargets = []string{s.resolveIndexName(srcPattern)}
	}

	var totalMatched, totalCreated, totalDeleted int
	updSpec := &painless.UpdateRequest{Script: body.Script}
	var batchBuf bytes.Buffer
	seqBase := time.Now().UnixNano()

	for _, srcIdx := range srcTargets {
		srcSchema := s.getOrCompileReadOnlySchema(r.Context(), srcIdx)
		tr := transpiler.NewTranspiler(srcSchema, s.transpileOpts)
		fetchSize := 10000
		if body.Source.Size != nil && *body.Source.Size > 0 {
			fetchSize = *body.Source.Size
		}
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
			Query: body.Source.Query,
			Size:  &fetchSize,
		})
		if err != nil {
			writeESError(w, http.StatusBadRequest, "search_phase_execution_exception", err.Error())
			return
		}
		hits, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
		if err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
			return
		}
		for i, h := range hits {
			totalMatched++
			docSource := h.Source
			if body.Script != nil {
				mutated, opRes, err := painless.ApplyUpdateWithResult(h.Source, updSpec, true)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
					return
				}
				if opRes == "noop" {
					continue
				}
				if opRes == "deleted" {
					totalDeleted++
					continue
				}
				docSource = mutated
			}
			shredded, err := schema.ShredDocument(destSchema, h.ID, seqBase+int64(i), false, docSource)
			if err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
			batchBuf.Write(shredded)
			batchBuf.WriteByte('\n')
			totalCreated++
		}
	}

	if batchBuf.Len() > 0 {
		if err := s.backend.StreamLoad(r.Context(), destSchema.DorisTable, batchBuf.Bytes(), true); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":      tookMs,
		"timed_out": false,
		"total":     totalMatched,
		"updated":   0,
		"created":   totalCreated,
		"deleted":   totalDeleted,
		"batches":   1,
		"noops":     totalMatched - totalCreated - totalDeleted,
		"failures":  []any{},
	})
}
