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
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	gz            *gzip.Writer
	wroteHeader   bool
	gzInitialized bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified {
			w.ResponseWriter.Header().Del("Content-Length")
			w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
			w.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
			w.gz.Reset(w.ResponseWriter)
			w.gzInitialized = true
		}
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.gzInitialized {
		return w.ResponseWriter.Write(b)
	}
	return w.gz.Write(b)
}

func (w *gzipResponseWriter) Close() {
	if w.gz != nil {
		if w.gzInitialized {
			_ = w.gz.Close()
		}
		w.gz.Reset(io.Discard)
		gzipWriterPool.Put(w.gz)
		w.gz = nil
	}
}

type esResponseFormatOptions struct {
	pretty      bool
	errorTrace  bool
	filterPaths []string
}

type esFormatResponseWriter struct {
	http.ResponseWriter
	opts esResponseFormatOptions
}

func extractESResponseFormatOptions(w http.ResponseWriter) (esResponseFormatOptions, bool) {
	if gw, ok := w.(*gzipResponseWriter); ok {
		w = gw.ResponseWriter
	}
	if fw, ok := w.(*esFormatResponseWriter); ok {
		return fw.opts, true
	}
	return esResponseFormatOptions{}, false
}

func parseESResponseFormatOptions(r *http.Request) (esResponseFormatOptions, bool) {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return esResponseFormatOptions{}, false
	}
	q := r.URL.Query()
	var opts esResponseFormatOptions
	if q.Has("pretty") && strings.ToLower(q.Get("pretty")) != "false" {
		opts.pretty = true
	}
	if q.Has("error_trace") && strings.ToLower(q.Get("error_trace")) != "false" {
		opts.errorTrace = true
	}
	if fp := strings.TrimSpace(q.Get("filter_path")); fp != "" {
		for _, p := range strings.Split(fp, ",") {
			if p = strings.TrimSpace(p); p != "" {
				opts.filterPaths = append(opts.filterPaths, p)
			}
		}
	}
	if !opts.pretty && !opts.errorTrace && len(opts.filterPaths) == 0 {
		return esResponseFormatOptions{}, false
	}
	return opts, true
}

func applyESFilterPath(v any, filterPaths []string) any {
	if len(filterPaths) == 0 || v == nil {
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
	for _, fp := range filterPaths {
		if strings.HasPrefix(fp, "-") {
			trimmed := strings.TrimPrefix(fp, "-")
			if trimmed != "" {
				negPatterns = append(negPatterns, strings.Split(trimmed, "."))
			}
		} else {
			posPatterns = append(posPatterns, strings.Split(fp, "."))
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
		out = filterExcludeNode(out, negPatterns)
	}
	return out
}

func advanceFilterPatterns(patterns [][]string, key string) [][]string {
	var next [][]string
	hasDot := strings.Contains(key, ".")
	for _, p := range patterns {
		if len(p) == 0 {
			next = append(next, []string{})
			continue
		}
		if p[0] == "**" {
			next = append(next, p)
			if len(p) == 1 {
				next = append(next, []string{})
			} else {
				if matchWildcardPattern(p[1], key) {
					next = append(next, p[2:])
				}
				if hasDot && len(p) >= 3 {
					for k := 3; k <= len(p); k++ {
						if matchWildcardPattern(strings.Join(p[1:k], "."), key) {
							next = append(next, p[k:])
						}
					}
				}
			}
			continue
		}
		if matchWildcardPattern(p[0], key) {
			next = append(next, p[1:])
		}
		if hasDot && len(p) >= 2 {
			for k := 2; k <= len(p); k++ {
				if matchWildcardPattern(strings.Join(p[:k], "."), key) {
					next = append(next, p[k:])
				}
			}
		}
	}
	return next
}

func filterIncludeNode(node any, patterns [][]string) (any, bool) {
	for _, p := range patterns {
		if len(p) == 0 || (len(p) == 1 && p[0] == "**") {
			return node, true
		}
	}
	switch typed := node.(type) {
	case map[string]any:
		out := make(map[string]any)
		for k, val := range typed {
			next := advanceFilterPatterns(patterns, k)
			if len(next) == 0 {
				continue
			}
			if child, ok := filterIncludeNode(val, next); ok {
				out[k] = child
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case []any:
		var out []any
		for _, elem := range typed {
			if child, ok := filterIncludeNode(elem, patterns); ok {
				out = append(out, child)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

func filterExcludeNode(node any, negPatterns [][]string) any {
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
				child := filterExcludeNode(val, next)
				if valMap, wasMap := val.(map[string]any); wasMap && len(valMap) > 0 {
					if childMap, isMap := child.(map[string]any); isMap && len(childMap) == 0 {
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
		out := make([]any, len(typed))
		for i, elem := range typed {
			out[i] = filterExcludeNode(elem, negPatterns)
		}
		return out
	default:
		return node
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

		if fmtOpts, ok := parseESResponseFormatOptions(r); ok {
			w = &esFormatResponseWriter{ResponseWriter: w, opts: fmtOpts}
		}

		if !s.checkInboundAuth(w, r) {
			return
		}

		if tp, opq, reqID := r.Header.Get("traceparent"), r.Header.Get("X-Opaque-Id"), r.Header.Get("X-Request-ID"); tp != "" || opq != "" || reqID != "" {
			r = r.WithContext(WithTraceMeta(r.Context(), TraceMeta{
				Traceparent: tp,
				OpaqueID:    opq,
				RequestID:   reqID,
			}))
		}

		maxBytes := atomic.LoadInt64(&s.maxBodyBytes)
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
			gzw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
			defer gzw.Close()
			w = gzw
		}

		atomic.AddInt64(&s.totalHTTPRequests, 1)
		next.ServeHTTP(w, r)
	})
}

func isPublicHealthProbePath(urlPath string) bool {
	switch strings.Trim(urlPath, "/") {
	case "healthz", "_healthz", "livez", "readyz", "_readyz":
		return true
	default:
		return false
	}
}

func constantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func matchConfiguredAPIKey(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	if constantTimeEquals(provided, expected) {
		return true
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if decoded, err := enc.DecodeString(provided); err == nil && len(decoded) > 0 {
			decStr := string(decoded)
			if constantTimeEquals(decStr, expected) {
				return true
			}
			if idx := strings.IndexByte(decStr, ':'); idx >= 0 {
				if constantTimeEquals(decStr[idx+1:], expected) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) checkInboundAuth(w http.ResponseWriter, r *http.Request) bool {
	s.authMu.RLock()
	basicUser := s.basicAuthUser
	basicPass := s.basicAuthPass
	apiKey := s.apiKey
	s.authMu.RUnlock()

	hasBasic := basicUser != "" && basicPass != ""
	hasAPIKey := apiKey != ""
	if !hasBasic && !hasAPIKey {
		return true
	}
	if isPublicHealthProbePath(r.URL.Path) {
		return true
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		if hasBasic && strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
			if u, p, ok := r.BasicAuth(); ok {
				uMatch := subtle.ConstantTimeCompare([]byte(u), []byte(basicUser))
				pMatch := subtle.ConstantTimeCompare([]byte(p), []byte(basicPass))
				if (uMatch & pMatch) == 1 {
					return true
				}
			}
		}
		if hasAPIKey {
			lower := strings.ToLower(authHeader)
			var token string
			switch {
			case strings.HasPrefix(lower, "apikey "):
				token = strings.TrimSpace(authHeader[len("apikey "):])
			case strings.HasPrefix(lower, "bearer "):
				token = strings.TrimSpace(authHeader[len("bearer "):])
			}
			if token != "" && matchConfiguredAPIKey(token, apiKey) {
				return true
			}
		}
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="security" charset="UTF-8", ApiKey`)
	reason := "missing authentication credentials for REST request [" + r.URL.Path + "]"
	if authHeader != "" {
		reason = "unable to authenticate credentials for REST request [" + r.URL.Path + "]"
	}
	writeESError(w, http.StatusUnauthorized, "security_exception", reason)
	return false
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

func (t *SlowQueryTracker) recordWithThreshold(entry SlowQueryEntry, threshold int64) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= slowLogRingCapacity {
		copy(t.entries, t.entries[1:])
		t.entries[len(t.entries)-1] = entry
	} else {
		t.entries = append(t.entries, entry)
	}
	var promoteFields []string
	if len(entry.UnindexedVariantFields) > 0 {
		const (
			maxTrackedIndices        = 256
			maxTrackedFieldsPerIndex = 1024
		)
		byField, ok := t.unindexedFreq[entry.Index]
		if !ok {
			if len(t.unindexedFreq) >= maxTrackedIndices {
				for k := range t.unindexedFreq {
					delete(t.unindexedFreq, k)
					break
				}
			}
			byField = make(map[string]int64)
			t.unindexedFreq[entry.Index] = byField
		}
		for _, f := range entry.UnindexedVariantFields {
			if _, exists := byField[f]; !exists && len(byField) >= maxTrackedFieldsPerIndex {
				for k := range byField {
					delete(byField, k)
					break
				}
			}
			byField[f]++
			if threshold > 0 && byField[f] >= threshold {
				promoteFields = append(promoteFields, f)
				delete(byField, f)
			}
		}
		if len(byField) == 0 {
			delete(t.unindexedFreq, entry.Index)
		}
	}
	return promoteFields
}

// SetAutoPromoteThreshold configures automatic promotion of hot unindexed `_doc[...]` fields
// once they are queried at least `threshold` times (0 disables automatic promotion).
func (s *Server) SetAutoPromoteThreshold(threshold int64) {
	atomic.StoreInt64(&s.autoPromoteThreshold, threshold)
}

func (s *Server) getAutoPromoteThreshold() int64 {
	return atomic.LoadInt64(&s.autoPromoteThreshold)
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
	sem              chan struct{}
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
		sem:       make(chan struct{}, 16),
	}
}

// SetShadowESURL configures dual-read shadow verification against an existing Elasticsearch/OpenSearch endpoint.
func (s *Server) SetShadowESURL(urlStr string) {
	s.shadowVerifier.mu.Lock()
	defer s.shadowVerifier.mu.Unlock()
	s.shadowVerifier.targetURL = strings.TrimRight(strings.TrimSpace(urlStr), "/")
}

func (s *Server) maybeRunShadowSearch(rawIndex string, rawReqBody []byte, dorisResp map[string]any, dorisTookMs int64, syncMode bool) {
	s.shadowVerifier.mu.RLock()
	targetURL := s.shadowVerifier.targetURL
	s.shadowVerifier.mu.RUnlock()
	if targetURL == "" {
		return
	}
	dorisTotal, dorisIDs := extractTotalAndHitIDs(dorisResp)
	bodyCopy := make([]byte, len(rawReqBody))
	copy(bodyCopy, rawReqBody)
	if len(bytes.TrimSpace(bodyCopy)) == 0 {
		bodyCopy = []byte(`{}`)
	}
	run := func() {
		s.executeShadowComparison(targetURL, rawIndex, bodyCopy, dorisTotal, dorisIDs, dorisTookMs)
	}
	if syncMode {
		run()
	} else {
		select {
		case s.shadowVerifier.sem <- struct{}{}:
			go func() {
				defer func() { <-s.shadowVerifier.sem }()
				run()
			}()
		default:
			// Drop background shadow replay when all 16 shadow workers are saturated.
		}
	}
}

func (s *Server) executeShadowComparison(targetURL, rawIndex string, bodyBytes []byte, dorisTotal int64, dorisIDs []string, dorisTookMs int64) {
	endpoint := targetURL + "/_search"
	if rawIndex != "" {
		endpoint = targetURL + "/" + url.PathEscape(rawIndex) + "/_search"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	// #nosec G704 -- targetURL is operator-configured via --shadow-es-url and rawIndex is URL-path-escaped
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- operator-configured shadow Elasticsearch comparison client
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 50*1024*1024)).Decode(&esPayload); err != nil {
		return
	}

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
				"indices": append([]string(nil), s.aliases[al]...),
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
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)

	indicesMap := make(map[string]any, len(targets))
	var totalDocs int64

	for _, idxName := range targets {
		zero := 0
		resp, _, errType, _ := s.executeSearchRequest(r.Context(), idxName, &esast.SearchRequest{
			Size:        &zero,
			AliasFilter: aliasFilters[idxName],
		})
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
		if id != "" {
			s.persistIngestPipeline(r.Context(), id, body)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.Lock()
		delete(s.pipelines, id)
		s.mu.Unlock()
		if id != "" {
			s.deleteIngestPipelineCatalog(r.Context(), id)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet:
		_ = s.syncCatalogFromBackend(r.Context())
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

func (s *Server) applyIngestPipelineForWriteWithMeta(pipelineID, indexName, docID string, raw json.RawMessage) (json.RawMessage, string, string, bool, error) {
	pipelineID = strings.TrimSpace(pipelineID)
	if pipelineID == "" || len(bytes.TrimSpace(raw)) == 0 {
		return raw, indexName, docID, false, nil
	}
	s.mu.RLock()
	pipe, ok := s.pipelines[pipelineID]
	s.mu.RUnlock()
	if !ok {
		_ = s.syncCatalogFromBackend(context.Background())
		s.mu.RLock()
		pipe, ok = s.pipelines[pipelineID]
		s.mu.RUnlock()
	}
	if !ok || pipe == nil {
		return raw, indexName, docID, false, nil
	}
	out, outIdx, outID, dropped, _, err := applyIngestPipelineSpecVerboseWithMeta(s, pipe, indexName, docID, raw, false)
	return out, outIdx, outID, dropped, err
}

func (s *Server) applyEffectiveAndFinalPipelines(indexName, reqPipeline, defaultPipeline string, raw json.RawMessage) (json.RawMessage, bool, error) {
	out, _, _, dropped, err := s.applyEffectiveAndFinalPipelinesWithMeta(indexName, "", reqPipeline, defaultPipeline, raw)
	return out, dropped, err
}

func (s *Server) applyEffectiveAndFinalPipelinesWithMeta(indexName, docID, reqPipeline, defaultPipeline string, raw json.RawMessage) (json.RawMessage, string, string, bool, error) {
	effPipeline := s.resolveEffectivePipeline(indexName, reqPipeline, defaultPipeline)
	cur := raw
	curIndex := indexName
	curID := docID
	if effPipeline != "" {
		next, nextIdx, nextID, dropped, err := s.applyIngestPipelineForWriteWithMeta(effPipeline, curIndex, curID, cur)
		if err != nil || dropped {
			return next, nextIdx, nextID, dropped, err
		}
		cur = next
		if nextIdx != "" {
			curIndex = nextIdx
		}
		if nextID != "" {
			curID = nextID
		}
	}
	finalPipeline := s.resolveFinalPipeline(curIndex)
	if finalPipeline == "" && s != nil {
		if resolved, _, wErr := s.resolveWriteIndexWithFilter(curIndex); wErr == nil && resolved != "" && resolved != curIndex {
			finalPipeline = s.resolveFinalPipeline(resolved)
		}
		if finalPipeline == "" {
			if resolved := s.resolveIndexName(curIndex); resolved != "" && resolved != curIndex {
				finalPipeline = s.resolveFinalPipeline(resolved)
			}
		}
	}
	if finalPipeline != "" {
		next, nextIdx, nextID, dropped, err := s.applyIngestPipelineForWriteWithMeta(finalPipeline, curIndex, curID, cur)
		if err != nil || dropped {
			return next, nextIdx, nextID, dropped, err
		}
		cur = next
		if nextIdx != "" {
			curIndex = nextIdx
		}
		if nextID != "" {
			curID = nextID
		}
	}
	return cur, curIndex, curID, false, nil
}

func isIngestIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '@' || c == '-'
}

func rewriteIngestCtxReferences(s string) string {
	var out strings.Builder
	out.Grow(len(s) + 16)
	inQuotes := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				out.WriteByte(s[i])
				continue
			}
			if c == inQuotes {
				inQuotes = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuotes = c
			out.WriteByte(c)
			continue
		}
		if (i == 0 || (!isIngestIdentByte(s[i-1]) && s[i-1] != '.')) && strings.HasPrefix(s[i:], "ctx") {
			rest := s[i+3:]
			if strings.HasPrefix(rest, "?.") {
				after := rest[2:]
				if !strings.HasPrefix(after, "_source") || (len(after) > 7 && isIngestIdentByte(after[7])) {
					out.WriteString("ctx?._source.")
					i += 4
					continue
				}
			} else if strings.HasPrefix(rest, ".") {
				after := rest[1:]
				isSource := strings.HasPrefix(after, "_source") && (len(after) == 7 || !isIngestIdentByte(after[7]))
				isOp := strings.HasPrefix(after, "op") && (len(after) == 2 || !isIngestIdentByte(after[2]))
				if !isSource && !isOp {
					out.WriteString("ctx._source.")
					i += 3
					continue
				}
			} else if strings.HasPrefix(rest, "?[") {
				after := strings.TrimSpace(rest[2:])
				if !strings.HasPrefix(after, "'_source'") && !strings.HasPrefix(after, `"_source"`) &&
					!strings.HasPrefix(after, "'op'") && !strings.HasPrefix(after, `"op"`) {
					out.WriteString("ctx?._source[")
					i += 4
					continue
				}
			} else if strings.HasPrefix(rest, "[") {
				after := strings.TrimSpace(rest[1:])
				if !strings.HasPrefix(after, "'_source'") && !strings.HasPrefix(after, `"_source"`) &&
					!strings.HasPrefix(after, "'op'") && !strings.HasPrefix(after, `"op"`) {
					out.WriteString("ctx._source[")
					i += 3
					continue
				}
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

func evalIngestIfCondition(cond string, doc map[string]any) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return true
	}
	normCond := rewriteIngestCtxReferences(cond)
	script := "if (" + normCond + ") { ctx.op = 'index' } else { ctx.op = 'noop' }"
	opRes, err := painless.EvalPainlessWithOp(doc, script, nil)
	if err != nil {
		return false
	}
	return opRes == "index"
}

func expandIngestTemplate(val any, doc map[string]any) any {
	switch v := val.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, elem := range v {
			out[k] = expandIngestTemplate(elem, doc)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = expandIngestTemplate(elem, doc)
		}
		return out
	}
	s, ok := val.(string)
	if !ok || !strings.Contains(s, "{{") {
		return val
	}
	var out strings.Builder
	i := 0
	for i < len(s) {
		start := strings.Index(s[i:], "{{")
		if start < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i : i+start])
		i += start
		triple := strings.HasPrefix(s[i:], "{{{")
		openLen := 2
		closeSeq := "}}"
		if triple {
			openLen = 3
			closeSeq = "}}}"
		}
		end := strings.Index(s[i+openLen:], closeSeq)
		if end < 0 {
			out.WriteString(s[i:])
			break
		}
		key := strings.TrimSpace(s[i+openLen : i+openLen+end])
		key = strings.TrimPrefix(key, "_source.")
		if v, exists := getIngestPath(doc, key); exists && v != nil {
			_, _ = fmt.Fprintf(&out, "%v", v)
		}
		i += openLen + end + len(closeSeq)
	}
	return out.String()
}

var defaultGrokPatterns = map[string]string{
	"USERNAME":          `[a-zA-Z0-9._-]+`,
	"USER":              `[a-zA-Z0-9._-]+`,
	"INT":               `(?:[+-]?(?:[0-9]+))`,
	"BASE10NUM":         `(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+))`,
	"NUMBER":            `(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+))`,
	"WORD":              `\b\w+\b`,
	"NOTSPACE":          `\S+`,
	"SPACE":             `\s*`,
	"DATA":              `.*?`,
	"GREEDYDATA":        `.*`,
	"QUOTEDSTRING":      `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"QS":                `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"UUID":              `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`,
	"MAC":               `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`,
	"IPV4":              `(?:[0-9]{1,3}\.){3}[0-9]{1,3}`,
	"IPV6":              `(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}`,
	"IP":                `(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})`,
	"HOSTNAME":          `\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(?:\.?|\b)`,
	"IPORHOST":          `(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*)`,
	"POSINT":            `\b(?:[1-9][0-9]*)\b`,
	"NONNEGINT":         `\b(?:[0-9]+)\b`,
	"LOGLEVEL":          `(?:[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)`,
	"TIMESTAMP_ISO8601": `[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?`,
	"MONTH":             `\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b`,
	"MONTHNUM":          `(?:0?[1-9]|1[0-2])`,
	"MONTHDAY":          `(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])`,
	"DAY":               `(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)`,
	"YEAR":              `(?:\d\d){1,2}`,
	"HOUR":              `(?:2[0123]|[01]?[0-9])`,
	"MINUTE":            `(?:[0-5][0-9])`,
	"SECOND":            `(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)`,
	"TIME":              `(?:[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?)`,
	"SYSLOGTIMESTAMP":   `%{MONTH} +%{MONTHDAY} %{TIME}`,
	"HTTPDATE":          `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`,
	"URIPROTO":          `[A-Za-z]+(?:\+[A-Za-z+]+)?`,
	"URIHOST":           `[0-9A-Za-z._-]+(?::[0-9]+)?`,
	"URIPATH":           `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+`,
	"PATH":              `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+`,
	"URIPARAM":          `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`,
	"URIPATHPARAM":      `%{URIPATH}(?:%{URIPARAM})?`,
	"URI":               `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`,
	"COMMONAPACHELOG":   `%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`,
	"COMBINEDAPACHELOG": `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`,
	"EMAILADDRESS":      `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`,
}

var reGrokToken = regexp.MustCompile(`%\{([A-Za-z0-9_]+)(?::([A-Za-z0-9_.\-\[\]@]+))?(?::(int|integer|long|float|double|boolean|bool|string))?\}`)

func normalizeGrokFieldName(fieldName string) string {
	if strings.HasPrefix(fieldName, "[") && strings.HasSuffix(fieldName, "]") {
		trimmed := strings.TrimPrefix(strings.TrimSuffix(fieldName, "]"), "[")
		return strings.ReplaceAll(trimmed, "][", ".")
	}
	return fieldName
}

func compileGrokRegex(pat string, customDefs map[string]any) (*regexp.Regexp, map[string]string, map[string]string, error) {
	groupKeyMap := make(map[string]string)
	groupTypes := make(map[string]string)
	groupSeq := 0
	expanded := pat
	for pass := 0; pass < 8; pass++ {
		if !strings.Contains(expanded, "%{") {
			break
		}
		var resolveErr error
		expanded = reGrokToken.ReplaceAllStringFunc(expanded, func(m string) string {
			sub := reGrokToken.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			patName := sub[1]
			fieldName := normalizeGrokFieldName(sub[2])
			fieldType := sub[3]
			var rawRegex string
			if customDefs != nil {
				if cv, ok := customDefs[patName].(string); ok && cv != "" {
					rawRegex = cv
				}
			}
			if rawRegex == "" {
				rawRegex = defaultGrokPatterns[patName]
			}
			if rawRegex == "" {
				resolveErr = fmt.Errorf("grok pattern [%s] is not defined", patName)
				return m
			}
			if fieldName != "" {
				groupSeq++
				grpID := fmt.Sprintf("g%d", groupSeq)
				groupKeyMap[grpID] = fieldName
				if fieldType != "" {
					groupTypes[grpID] = fieldType
				}
				return fmt.Sprintf("(?P<%s>%s)", grpID, rawRegex)
			}
			return "(?:" + rawRegex + ")"
		})
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
	}
	re, err := regexp.Compile(expanded)
	if err != nil {
		return nil, nil, nil, err
	}
	return re, groupKeyMap, groupTypes, nil
}

func convertESDateFormatToGoLayouts(esFmt string) []string {
	switch esFmt {
	case "ISO8601", "strict_date_optional_time", "date_optional_time":
		return []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999Z0700",
			"2006-01-02T15:04:05Z0700",
			"2006-01-02T15:04:05.000Z0700",
			"2006-01-02T15:04:05.000Z07:00",
			"2006-01-02T15:04:05.000",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
	case "UNIX", "epoch_second":
		return []string{"UNIX"}
	case "UNIX_MS", "epoch_millis":
		return []string{"UNIX_MS"}
	}
	r := strings.NewReplacer(
		"yyyy", "2006",
		"yy", "06",
		"MMM", "Jan",
		"MM", "01",
		"dd", "02",
		"HH", "15",
		"mm", "04",
		"ss", "05",
		"SSS", "000",
		"Z", "Z0700",
		"XXX", "Z07:00",
		"'T'", "T",
	)
	layout := r.Replace(esFmt)
	layouts := []string{layout}
	if strings.Contains(esFmt, "Z") {
		layouts = append(layouts, strings.ReplaceAll(layout, "Z0700", "Z07:00"))
	}
	return layouts
}

func parseIngestDateValue(raw string, formats []any, tzName string) (time.Time, error) {
	loc := time.UTC
	if tzName != "" {
		if l, err := time.LoadLocation(tzName); err == nil {
			loc = l
		} else if len(tzName) == 6 && (tzName[0] == '+' || tzName[0] == '-') && tzName[3] == ':' {
			h, err1 := strconv.Atoi(tzName[1:3])
			m, err2 := strconv.Atoi(tzName[4:6])
			if err1 == nil && err2 == nil {
				offset := (h*3600 + m*60)
				if tzName[0] == '-' {
					offset = -offset
				}
				loc = time.FixedZone(tzName, offset)
			}
		} else if len(tzName) == 5 && (tzName[0] == '+' || tzName[0] == '-') {
			h, err1 := strconv.Atoi(tzName[1:3])
			m, err2 := strconv.Atoi(tzName[3:5])
			if err1 == nil && err2 == nil {
				offset := (h*3600 + m*60)
				if tzName[0] == '-' {
					offset = -offset
				}
				loc = time.FixedZone(tzName, offset)
			}
		}
	}
	if len(formats) == 0 {
		formats = []any{"ISO8601"}
	}
	for _, fAny := range formats {
		fStr, ok := fAny.(string)
		if !ok || fStr == "" {
			continue
		}
		for _, layout := range convertESDateFormatToGoLayouts(fStr) {
			switch layout {
			case "UNIX":
				if fv, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
					sec := int64(fv)
					nsec := int64((fv - float64(sec)) * 1e9)
					return time.Unix(sec, nsec).In(loc), nil
				}
			case "UNIX_MS":
				if iv, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
					return time.UnixMilli(iv).In(loc), nil
				}
				if fv, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
					return time.UnixMilli(int64(fv)).In(loc), nil
				}
			default:
				if t, err := time.ParseInLocation(layout, strings.TrimSpace(raw), loc); err == nil {
					return t.In(loc), nil
				}
			}
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date [%s]", raw)
}

var reHTMLTags = regexp.MustCompile(`<[^>]*>`)

func parseIngestByteSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	type unitSpec struct {
		suffix string
		mult   float64
	}
	units := []unitSpec{
		{"pib", 1 << 50},
		{"pb", 1 << 50},
		{"tib", 1 << 40},
		{"gib", 1 << 30},
		{"mib", 1 << 20},
		{"kib", 1 << 10},
		{"tb", 1 << 40},
		{"gb", 1 << 30},
		{"mb", 1 << 20},
		{"kb", 1 << 10},
		{"b", 1},
		{"p", 1 << 50},
		{"t", 1 << 40},
		{"g", 1 << 30},
		{"m", 1 << 20},
		{"k", 1 << 10},
	}
	mult := float64(1)
	numPart := s
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			numPart = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			mult = u.mult
			break
		}
	}
	fv, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to convert [%s] to bytes", s)
	}
	return int64(fv * mult), nil
}

func evalDissectPattern(pattern, input, appendSep string) (map[string]any, error) {
	type dissectToken struct {
		rawKey      string
		nextLit     string
		padRight    bool
		skip        bool
		append      bool
		appendOrder int
		indirect    bool
	}
	var prefixLit string
	var tokens []dissectToken

	rem := pattern
	firstIdx := strings.Index(rem, "%{")
	if firstIdx < 0 {
		if input != pattern {
			return nil, fmt.Errorf("unable to dissect [%s] with pattern [%s]", input, pattern)
		}
		return map[string]any{}, nil
	}
	prefixLit = rem[:firstIdx]
	rem = rem[firstIdx:]

	for strings.HasPrefix(rem, "%{") {
		endBrace := strings.IndexByte(rem, '}')
		if endBrace < 0 {
			return nil, fmt.Errorf("invalid dissect pattern [%s]: unclosed token", pattern)
		}
		inner := rem[2:endBrace]
		rem = rem[endBrace+1:]

		var nextLit string
		if nextStart := strings.Index(rem, "%{"); nextStart >= 0 {
			nextLit = rem[:nextStart]
			rem = rem[nextStart:]
		} else {
			nextLit = rem
			rem = ""
		}

		tok := dissectToken{nextLit: nextLit}
		if strings.HasSuffix(inner, "->") {
			tok.padRight = true
			inner = strings.TrimSuffix(inner, "->")
		}
		switch {
		case inner == "" || strings.HasPrefix(inner, "?"):
			tok.skip = true
			tok.rawKey = strings.TrimPrefix(inner, "?")
		case strings.HasPrefix(inner, "*"):
			tok.skip = true
			tok.rawKey = strings.TrimPrefix(inner, "*")
		case strings.HasPrefix(inner, "+"):
			tok.append = true
			inner = strings.TrimPrefix(inner, "+")
			if slashIdx := strings.IndexByte(inner, '/'); slashIdx > 0 {
				if ord, err := strconv.Atoi(inner[slashIdx+1:]); err == nil && ord > 0 {
					tok.appendOrder = ord
				}
				inner = inner[:slashIdx]
			}
			tok.rawKey = inner
		case strings.HasPrefix(inner, "&"):
			tok.indirect = true
			tok.rawKey = strings.TrimPrefix(inner, "&")
		default:
			tok.rawKey = inner
		}
		tokens = append(tokens, tok)
	}

	if !strings.HasPrefix(input, prefixLit) {
		return nil, fmt.Errorf("unable to dissect [%s] with pattern [%s]", input, pattern)
	}
	cur := input[len(prefixLit):]
	out := make(map[string]any)
	refValues := make(map[string]string)
	captured := make([]string, len(tokens))

	for i, tok := range tokens {
		var val string
		isLast := i == len(tokens)-1
		if isLast && tok.nextLit == "" {
			val = cur
			cur = ""
		} else if tok.nextLit == "" {
			val = ""
		} else {
			idx := strings.Index(cur, tok.nextLit)
			if idx < 0 {
				return nil, fmt.Errorf("unable to dissect [%s] with pattern [%s]: missing delimiter [%s]", input, pattern, tok.nextLit)
			}
			val = cur[:idx]
			cur = cur[idx+len(tok.nextLit):]
			if tok.padRight && tok.nextLit != "" {
				for strings.HasPrefix(cur, tok.nextLit) {
					cur = cur[len(tok.nextLit):]
				}
			}
			if isLast && cur != "" {
				return nil, fmt.Errorf("unable to dissect [%s] with pattern [%s]: trailing characters [%s]", input, pattern, cur)
			}
		}
		captured[i] = val
		if !tok.indirect && tok.rawKey != "" {
			refValues[tok.rawKey] = val
		}
	}

	type appendPiece struct {
		order int
		seq   int
		val   string
	}
	appendsByKey := make(map[string][]appendPiece)
	hasAppendKey := make(map[string]bool)
	for _, tok := range tokens {
		if tok.skip || tok.rawKey == "" || !tok.append {
			continue
		}
		targetKey := tok.rawKey
		if tok.indirect {
			targetKey = refValues[tok.rawKey]
		}
		if targetKey != "" {
			hasAppendKey[targetKey] = true
		}
	}

	for i, tok := range tokens {
		if tok.skip || tok.rawKey == "" {
			continue
		}
		targetKey := tok.rawKey
		if tok.indirect {
			targetKey = refValues[tok.rawKey]
			if targetKey == "" {
				continue
			}
		}
		val := captured[i]
		if tok.append || hasAppendKey[targetKey] {
			appendsByKey[targetKey] = append(appendsByKey[targetKey], appendPiece{
				order: tok.appendOrder,
				seq:   i,
				val:   val,
			})
		} else {
			out[targetKey] = val
		}
	}
	for targetKey, pieces := range appendsByKey {
		sort.SliceStable(pieces, func(a, b int) bool {
			if pieces[a].order != pieces[b].order {
				if pieces[a].order == 0 {
					return false
				}
				if pieces[b].order == 0 {
					return true
				}
				return pieces[a].order < pieces[b].order
			}
			return pieces[a].seq < pieces[b].seq
		})
		vals := make([]string, len(pieces))
		for idx, p := range pieces {
			vals[idx] = p.val
		}
		out[targetKey] = strings.Join(vals, appendSep)
	}
	return out, nil
}

func isExplicitIgnoreMissingFalse(specMap map[string]any) bool {
	if im, hasIM := specMap["ignore_missing"].(bool); hasIM && !im {
		return true
	}
	return false
}

func executeSingleIngestProcessor(s *Server, doc map[string]any, pMap map[string]any, depth int, trace *[]map[string]any) (mutated bool, dropped bool, procType string, procTag string, specMap map[string]any, procErr error) {
	if topIf, ok := pMap["if"].(string); ok && !evalIngestIfCondition(topIf, doc) {
		return false, false, "", "", nil, nil
	}
	for k, v := range pMap {
		switch k {
		case "if", "ignore_failure", "on_failure", "tag", "description":
			continue
		default:
			if sm, ok := v.(map[string]any); ok {
				procType = k
				specMap = sm
			}
		}
	}
	if procType == "" || specMap == nil {
		return false, false, "", "", nil, nil
	}
	procTag, _ = specMap["tag"].(string)
	if procTag == "" {
		procTag, _ = pMap["tag"].(string)
	}
	if cond, ok := specMap["if"].(string); ok && !evalIngestIfCondition(cond, doc) {
		return false, false, "", procTag, specMap, nil
	}

	switch procType {
	case "drop":
		return false, true, procType, procTag, specMap, nil
	case "fail":
		msg, _ := specMap["message"].(string)
		expanded := fmt.Sprintf("%v", expandIngestTemplate(msg, doc))
		if expanded == "" {
			expanded = "fail processor triggered"
		}
		return false, false, procType, procTag, specMap, fmt.Errorf("%s", expanded)
	case "pipeline":
		if depth > 16 {
			return false, false, procType, procTag, specMap, fmt.Errorf("ingest pipeline max depth (16) exceeded")
		}
		subName, _ := specMap["name"].(string)
		subName = strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(subName, doc)))
		var subPipe map[string]any
		if s != nil && subName != "" {
			s.mu.RLock()
			subPipe = s.pipelines[subName]
			s.mu.RUnlock()
			if subPipe == nil {
				_ = s.syncCatalogFromBackend(context.Background())
				s.mu.RLock()
				subPipe = s.pipelines[subName]
				s.mu.RUnlock()
			}
		}
		if subPipe == nil {
			if ignoreMissing, _ := specMap["ignore_missing_pipeline"].(bool); ignoreMissing {
				return false, false, procType, procTag, specMap, nil
			}
			return false, false, procType, procTag, specMap, fmt.Errorf("pipeline [%s] is missing", subName)
		}
		subProcs, _ := subPipe["processors"].([]any)
		subMut, subDropped, subErr := runIngestProcessorList(s, doc, subProcs, depth+1, trace)
		if subErr != nil {
			if pipeOnFail, ok := subPipe["on_failure"].([]any); ok && len(pipeOnFail) > 0 {
				ingestMeta, _ := doc["_ingest"].(map[string]any)
				if ingestMeta == nil {
					ingestMeta = make(map[string]any)
				}
				ingestMeta["on_failure_message"] = subErr.Error()
				doc["_ingest"] = ingestMeta
				subMut = true
				fMut, fDrop, fErr := runIngestProcessorList(s, doc, pipeOnFail, depth+1, trace)
				if fMut {
					subMut = true
				}
				if fDrop {
					return subMut, true, procType, procTag, specMap, nil
				}
				if fErr == nil {
					if curIngest, ok := doc["_ingest"].(map[string]any); ok {
						delete(curIngest, "on_failure_message")
						delete(curIngest, "on_failure_processor_type")
						delete(curIngest, "on_failure_processor_tag")
					}
				}
				subErr = fErr
			}
		}
		return subMut, subDropped, procType, procTag, specMap, subErr
	case "dissect":
		field, _ := specMap["field"].(string)
		pattern, _ := specMap["pattern"].(string)
		appendSep, _ := specMap["append_separator"].(string)
		if field != "" && pattern != "" {
			val, exists := getIngestPath(doc, field)
			if !exists || val == nil {
				ignoreMissing, _ := specMap["ignore_missing"].(bool)
				if !ignoreMissing {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
				}
				return false, false, procType, procTag, specMap, nil
			}
			strVal, ok := val.(string)
			if !ok {
				strVal = fmt.Sprintf("%v", val)
			}
			extracted, err := evalDissectPattern(pattern, strVal, appendSep)
			if err != nil {
				return false, false, procType, procTag, specMap, err
			}
			targetField, _ := specMap["target_field"].(string)
			if targetField != "" {
				setIngestPath(doc, targetField, map[string]any{})
				for k, v := range extracted {
					setIngestPath(doc, targetField+"."+k, v)
				}
			} else {
				for k, v := range extracted {
					setIngestPath(doc, k, v)
				}
			}
			mutated = true
		}
	case "set":
		if field, _ := specMap["field"].(string); field != "" {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
			if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
				if existing, exists := getIngestPath(doc, field); exists && existing != nil {
					return false, false, procType, procTag, specMap, nil
				}
			}
			if copyFrom, _ := specMap["copy_from"].(string); copyFrom != "" {
				copyFrom = fmt.Sprintf("%v", expandIngestTemplate(copyFrom, doc))
				if val, exists := getIngestPath(doc, copyFrom); exists {
					setIngestPath(doc, field, val)
					mutated = true
				} else if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", copyFrom)
				}
			} else if val, hasVal := specMap["value"]; hasVal {
				setIngestPath(doc, field, expandIngestTemplate(val, doc))
				mutated = true
			}
		}
	case "default":
		if field, _ := specMap["field"].(string); field != "" {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
			if existing, exists := getIngestPath(doc, field); !exists || existing == nil {
				setIngestPath(doc, field, expandIngestTemplate(specMap["value"], doc))
				mutated = true
			}
		}
	case "rename":
		srcField, _ := specMap["field"].(string)
		dstField, _ := specMap["target_field"].(string)
		if srcField != "" && dstField != "" {
			srcField = fmt.Sprintf("%v", expandIngestTemplate(srcField, doc))
			dstField = fmt.Sprintf("%v", expandIngestTemplate(dstField, doc))
			if val, exists := getIngestPath(doc, srcField); exists {
				setIngestPath(doc, dstField, val)
				deleteIngestPath(doc, srcField)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", srcField)
			}
		}
	case "copy":
		srcField, _ := specMap["field"].(string)
		dstField, _ := specMap["target_field"].(string)
		if srcField != "" && dstField != "" {
			srcField = fmt.Sprintf("%v", expandIngestTemplate(srcField, doc))
			dstField = fmt.Sprintf("%v", expandIngestTemplate(dstField, doc))
			if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
				if existing, exists := getIngestPath(doc, dstField); exists && existing != nil {
					return false, false, procType, procTag, specMap, nil
				}
			}
			if val, exists := getIngestPath(doc, srcField); exists {
				setIngestPath(doc, dstField, val)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", srcField)
			}
		}
	case "remove":
		switch f := specMap["field"].(type) {
		case string:
			if _, exists := getIngestPath(doc, f); !exists && isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", f)
			}
			deleteIngestPath(doc, f)
			mutated = true
		case []any:
			for _, item := range f {
				if ks, ok := item.(string); ok {
					if _, exists := getIngestPath(doc, ks); !exists && isExplicitIgnoreMissingFalse(specMap) {
						return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", ks)
					}
					deleteIngestPath(doc, ks)
					mutated = true
				}
			}
		}
	case "lowercase":
		if field, _ := specMap["field"].(string); field != "" {
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = tf
			}
			if val, ok := getIngestPath(doc, field); ok {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, strings.ToLower(v))
					mutated = true
				case []any:
					out := make([]any, len(v))
					for i, el := range v {
						if s, ok := el.(string); ok {
							out[i] = strings.ToLower(s)
						} else {
							out[i] = el
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "uppercase":
		if field, _ := specMap["field"].(string); field != "" {
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = tf
			}
			if val, ok := getIngestPath(doc, field); ok {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, strings.ToUpper(v))
					mutated = true
				case []any:
					out := make([]any, len(v))
					for i, el := range v {
						if s, ok := el.(string); ok {
							out[i] = strings.ToUpper(s)
						} else {
							out[i] = el
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "trim":
		if field, _ := specMap["field"].(string); field != "" {
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = tf
			}
			if val, ok := getIngestPath(doc, field); ok {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, strings.TrimSpace(v))
					mutated = true
				case []any:
					out := make([]any, len(v))
					for i, el := range v {
						if s, ok := el.(string); ok {
							out[i] = strings.TrimSpace(s)
						} else {
							out[i] = el
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "split":
		field, _ := specMap["field"].(string)
		sep, _ := specMap["separator"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" && sep != "" {
			if val, ok := getIngestPath(doc, field); ok {
				if strVal, ok := val.(string); ok {
					var parts []string
					if sep == "|" || sep == "." {
						parts = strings.Split(strVal, sep)
					} else if re, err := regexp.Compile(sep); err == nil {
						parts = re.Split(strVal, -1)
					} else {
						parts = strings.Split(strVal, sep)
					}
					out := make([]any, len(parts))
					for i, pt := range parts {
						out[i] = pt
					}
					setIngestPath(doc, target, out)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "join":
		field, _ := specMap["field"].(string)
		sep, _ := specMap["separator"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, ok := getIngestPath(doc, field); ok {
				if arr, ok := val.([]any); ok {
					strs := make([]string, len(arr))
					for i, el := range arr {
						strs[i] = fmt.Sprintf("%v", el)
					}
					setIngestPath(doc, target, strings.Join(strs, sep))
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "append":
		if field, _ := specMap["field"].(string); field != "" {
			allowDups := true
			if ad, hasAD := specMap["allow_duplicates"].(bool); hasAD {
				allowDups = ad
			}
			var curSlice []any
			if existing, exists := getIngestPath(doc, field); exists && existing != nil {
				if arr, ok := existing.([]any); ok {
					curSlice = append(curSlice, arr...)
				} else {
					curSlice = append(curSlice, existing)
				}
			}
			var toAdd []any
			if arr, ok := specMap["value"].([]any); ok {
				toAdd = arr
			} else if v, hasV := specMap["value"]; hasV {
				toAdd = []any{v}
			}
			for _, item := range toAdd {
				expanded := expandIngestTemplate(item, doc)
				if !allowDups {
					dup := false
					for _, ex := range curSlice {
						if fmt.Sprintf("%v", ex) == fmt.Sprintf("%v", expanded) {
							dup = true
							break
						}
					}
					if dup {
						continue
					}
				}
				curSlice = append(curSlice, expanded)
			}
			setIngestPath(doc, field, curSlice)
			mutated = true
		}
	case "convert":
		field, _ := specMap["field"].(string)
		convType, _ := specMap["type"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" && convType != "" {
			val, exists := getIngestPath(doc, field)
			if !exists || val == nil {
				if im, hasIM := specMap["ignore_missing"].(bool); hasIM && !im && !exists {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing and cannot be converted to [%s]", field, convType)
				}
			} else if arr, isArr := val.([]any); isArr {
				outArr := make([]any, len(arr))
				for idx, elem := range arr {
					cv, err := convertSingleIngestValue(elem, convType)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					outArr[idx] = cv
				}
				setIngestPath(doc, target, outArr)
				mutated = true
			} else {
				cv, err := convertSingleIngestValue(val, convType)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				setIngestPath(doc, target, cv)
				mutated = true
			}
		}
	case "gsub":
		field, _ := specMap["field"].(string)
		pat, _ := specMap["pattern"].(string)
		repl, _ := specMap["replacement"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" && pat != "" {
			re, err := regexp.Compile(pat)
			if err != nil {
				return false, false, procType, procTag, specMap, err
			}
			if val, exists := getIngestPath(doc, field); exists {
				if strVal, ok := val.(string); ok {
					setIngestPath(doc, target, re.ReplaceAllString(strVal, repl))
					mutated = true
				} else if arr, isArr := val.([]any); isArr {
					outArr := make([]any, len(arr))
					for idx, elem := range arr {
						if sElem, ok := elem.(string); ok {
							outArr[idx] = re.ReplaceAllString(sElem, repl)
						} else {
							outArr[idx] = elem
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "json":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		addToRoot, _ := specMap["add_to_root"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				if strVal, ok := val.(string); ok {
					dec := json.NewDecoder(strings.NewReader(strVal))
					dec.UseNumber()
					var parsed any
					if err := dec.Decode(&parsed); err != nil {
						return false, false, procType, procTag, specMap, err
					}
					if addToRoot {
						if m, ok := parsed.(map[string]any); ok {
							for k, v := range m {
								doc[k] = v
							}
							mutated = true
						}
					} else {
						setIngestPath(doc, target, parsed)
						mutated = true
					}
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "kv":
		field, _ := specMap["field"].(string)
		fieldSplit, _ := specMap["field_split"].(string)
		valueSplit, _ := specMap["value_split"].(string)
		targetField, _ := specMap["target_field"].(string)
		if field != "" && fieldSplit != "" && valueSplit != "" {
			if val, exists := getIngestPath(doc, field); exists {
				if strVal, ok := val.(string); ok {
					var pairs []string
					if fieldSplit == "|" || fieldSplit == "." {
						pairs = strings.Split(strVal, fieldSplit)
					} else if re, err := regexp.Compile(fieldSplit); err == nil {
						pairs = re.Split(strVal, -1)
					} else {
						pairs = strings.Split(strVal, fieldSplit)
					}
					kvMap := make(map[string]any)
					for _, pair := range pairs {
						if pair == "" {
							continue
						}
						idx := strings.Index(pair, valueSplit)
						if idx <= 0 {
							continue
						}
						k := strings.TrimSpace(pair[:idx])
						v := strings.TrimSpace(pair[idx+len(valueSplit):])
						kvMap[k] = v
					}
					if targetField != "" {
						setIngestPath(doc, targetField, map[string]any{})
						for k, v := range kvMap {
							setIngestPath(doc, targetField+"."+k, v)
						}
					} else {
						for k, v := range kvMap {
							setIngestPath(doc, k, v)
						}
					}
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "dot_expander":
		field, _ := specMap["field"].(string)
		subPath, _ := specMap["path"].(string)
		if field != "" {
			targetMap := doc
			if subPath != "" {
				if subAny, exists := getIngestPath(doc, subPath); exists {
					if sm, ok := subAny.(map[string]any); ok {
						targetMap = sm
					} else {
						targetMap = nil
					}
				} else {
					targetMap = nil
				}
			}
			if targetMap != nil {
				if val, exists := targetMap[field]; exists {
					delete(targetMap, field)
					setIngestPathMerge(targetMap, field, val)
					mutated = true
				}
			}
		}
	case "urldecode":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists {
				switch v := val.(type) {
				case string:
					decoded, err := url.QueryUnescape(v)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					setIngestPath(doc, target, decoded)
					mutated = true
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						if sEl, ok := el.(string); ok {
							decoded, err := url.QueryUnescape(sEl)
							if err != nil {
								return false, false, procType, procTag, specMap, err
							}
							outArr[idx] = decoded
						} else {
							outArr[idx] = el
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "bytes":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				if arr, isArr := val.([]any); isArr {
					outArr := make([]any, len(arr))
					for idx, el := range arr {
						bVal, err := parseIngestByteSize(fmt.Sprintf("%v", el))
						if err != nil {
							return false, false, procType, procTag, specMap, err
						}
						outArr[idx] = bVal
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				} else {
					bVal, err := parseIngestByteSize(fmt.Sprintf("%v", val))
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					setIngestPath(doc, target, bVal)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "html_strip":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, reHTMLTags.ReplaceAllString(v, ""))
					mutated = true
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						if sEl, ok := el.(string); ok {
							outArr[idx] = reHTMLTags.ReplaceAllString(sEl, "")
						} else {
							outArr[idx] = el
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "date":
		field, _ := specMap["field"].(string)
		target := "@timestamp"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		formats, _ := specMap["formats"].([]any)
		tzName, _ := specMap["timezone"].(string)
		if tzName != "" {
			tzName = fmt.Sprintf("%v", expandIngestTemplate(tzName, doc))
		}
		outFmt, _ := specMap["output_format"].(string)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				parsedTime, err := parseIngestDateValue(fmt.Sprintf("%v", val), formats, tzName)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				var formatted string
				if outFmt != "" {
					layouts := convertESDateFormatToGoLayouts(outFmt)
					switch layouts[0] {
					case "UNIX_MS":
						formatted = strconv.FormatInt(parsedTime.UnixMilli(), 10)
					case "UNIX":
						formatted = strconv.FormatInt(parsedTime.Unix(), 10)
					default:
						formatted = parsedTime.Format(layouts[0])
					}
				} else {
					formatted = parsedTime.Format(time.RFC3339Nano)
				}
				setIngestPath(doc, target, formatted)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "date_index_name":
		field, _ := specMap["field"].(string)
		prefix, _ := specMap["index_name_prefix"].(string)
		dateRounding, _ := specMap["date_rounding"].(string)
		idxFmt, _ := specMap["index_name_format"].(string)
		if idxFmt == "" {
			idxFmt = "yyyy-MM-dd"
		}
		formats, _ := specMap["formats"].([]any)
		if len(formats) == 0 {
			if df, ok := specMap["date_formats"].([]any); ok {
				formats = df
			}
		}
		tzName, _ := specMap["timezone"].(string)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				parsedTime, err := parseIngestDateValue(fmt.Sprintf("%v", val), formats, tzName)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				switch dateRounding {
				case "y":
					parsedTime = time.Date(parsedTime.Year(), 1, 1, 0, 0, 0, 0, parsedTime.Location())
				case "M":
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), 1, 0, 0, 0, 0, parsedTime.Location())
				case "w":
					wd := int(parsedTime.Weekday())
					if wd == 0 {
						wd = 7
					}
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day()-(wd-1), 0, 0, 0, 0, parsedTime.Location())
				case "d":
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 0, 0, 0, 0, parsedTime.Location())
				case "h":
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), parsedTime.Hour(), 0, 0, 0, parsedTime.Location())
				case "m":
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), parsedTime.Hour(), parsedTime.Minute(), 0, 0, parsedTime.Location())
				case "s":
					parsedTime = time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), parsedTime.Hour(), parsedTime.Minute(), parsedTime.Second(), 0, parsedTime.Location())
				}
				layouts := convertESDateFormatToGoLayouts(idxFmt)
				target := "_index"
				if tf, _ := specMap["target_field"].(string); tf != "" {
					target = tf
				}
				setIngestPath(doc, target, prefix+parsedTime.Format(layouts[0]))
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "grok":
		field, _ := specMap["field"].(string)
		patterns, _ := specMap["patterns"].([]any)
		customDefs, _ := specMap["pattern_definitions"].(map[string]any)
		targetField, _ := specMap["target_field"].(string)
		if field != "" && len(patterns) > 0 {
			val, exists := getIngestPath(doc, field)
			if !exists || val == nil {
				ignoreMissing, _ := specMap["ignore_missing"].(bool)
				if !ignoreMissing {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
				}
				return false, false, procType, procTag, specMap, nil
			}
			strVal := fmt.Sprintf("%v", val)
			matched := false
			for _, patAny := range patterns {
				patStr, ok := patAny.(string)
				if !ok || patStr == "" {
					continue
				}
				re, grpMap, grpTypes, err := compileGrokRegex(patStr, customDefs)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				m := re.FindStringSubmatch(strVal)
				loc := re.FindStringSubmatchIndex(strVal)
				if m == nil || loc == nil {
					continue
				}
				matched = true
				names := re.SubexpNames()
				for i, grpID := range names {
					if i == 0 || grpID == "" || i >= len(m) || 2*i >= len(loc) || loc[2*i] < 0 {
						continue
					}
					fieldName := grpMap[grpID]
					if fieldName == "" {
						continue
					}
					var finalVal any = m[i]
					if convT := grpTypes[grpID]; convT != "" {
						if cv, err := convertSingleIngestValue(m[i], convT); err == nil {
							finalVal = cv
						}
					}
					if targetField != "" {
						setIngestPath(doc, targetField+"."+fieldName, finalVal)
					} else {
						setIngestPath(doc, fieldName, finalVal)
					}
				}
				mutated = true
				break
			}
			if !matched {
				return false, false, procType, procTag, specMap, fmt.Errorf("provided Grok expressions do not match field value: [%s]", strVal)
			}
		}
	case "sort":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		order, _ := specMap["order"].(string)
		desc := strings.EqualFold(order, "desc")
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				arr, ok := val.([]any)
				if !ok {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not an array", field)
				}
				sorted := make([]any, len(arr))
				copy(sorted, arr)
				sort.SliceStable(sorted, func(i, j int) bool {
					cmp := compareAny(sorted[i], sorted[j])
					if desc {
						return cmp > 0
					}
					return cmp < 0
				})
				setIngestPath(doc, target, sorted)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "compact":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case []any:
					out := make([]any, 0, len(v))
					for _, el := range v {
						if el == nil || el == "" {
							continue
						}
						out = append(out, el)
					}
					setIngestPath(doc, target, out)
					mutated = true
				case map[string]any:
					out := make(map[string]any, len(v))
					for k, el := range v {
						if el == nil || el == "" {
							continue
						}
						if mEl, ok := el.(map[string]any); ok && len(mEl) == 0 {
							continue
						}
						if sEl, ok := el.([]any); ok && len(sEl) == 0 {
							continue
						}
						out[k] = el
					}
					setIngestPath(doc, target, out)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "fingerprint":
		fieldsAny, _ := specMap["fields"].([]any)
		target := "fingerprint"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		method, _ := specMap["method"].(string)
		salt, _ := specMap["salt"].(string)
		if len(fieldsAny) > 0 {
			var fields []string
			for _, f := range fieldsAny {
				if fs, ok := f.(string); ok && fs != "" {
					fields = append(fields, fs)
				}
			}
			sort.Strings(fields)
			var buf strings.Builder
			if salt != "" {
				buf.WriteString(salt)
			}
			hasAny := false
			for _, f := range fields {
				if val, exists := getIngestPath(doc, f); exists && val != nil {
					hasAny = true
					buf.WriteString("|")
					buf.WriteString(f)
					buf.WriteString("|")
					_, _ = fmt.Fprintf(&buf, "%v", val)
				} else if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", f)
				}
			}
			if hasAny {
				buf.WriteString("|")
				var digest []byte
				switch strings.ToUpper(strings.TrimSpace(method)) {
				case "SHA-384":
					sum := sha512.Sum384([]byte(buf.String()))
					digest = sum[:]
				case "SHA-512":
					sum := sha512.Sum512([]byte(buf.String()))
					digest = sum[:]
				default:
					sum := sha256.Sum256([]byte(buf.String()))
					digest = sum[:]
				}
				setIngestPath(doc, target, hex.EncodeToString(digest))
				mutated = true
			}
		}
	case "redact":
		field, _ := specMap["field"].(string)
		patterns, _ := specMap["patterns"].([]any)
		customDefs, _ := specMap["pattern_definitions"].(map[string]any)
		prefix := "<"
		if p, ok := specMap["prefix"].(string); ok {
			prefix = p
		}
		suffix := ">"
		if sfx, ok := specMap["suffix"].(string); ok {
			suffix = sfx
		}
		if field != "" && len(patterns) > 0 {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				strVal, ok := val.(string)
				if !ok {
					strVal = fmt.Sprintf("%v", val)
				}
				for _, patAny := range patterns {
					patStr, ok := patAny.(string)
					if !ok || patStr == "" {
						continue
					}
					re, grpMap, _, err := compileGrokRegex(patStr, customDefs)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					subexpNames := re.SubexpNames()
					locs := re.FindAllStringSubmatchIndex(strVal, -1)
					if len(locs) == 0 {
						continue
					}
					var b strings.Builder
					lastPos := 0
					for _, loc := range locs {
						if loc[0] < lastPos {
							continue
						}
						b.WriteString(strVal[lastPos:loc[0]])
						type subSpan struct {
							start int
							end   int
							label string
						}
						var spans []subSpan
						for si := 1; si < len(subexpNames) && 2*si+1 < len(loc); si++ {
							gID := subexpNames[si]
							lbl := grpMap[gID]
							if lbl == "" || loc[2*si] < 0 || loc[2*si+1] < loc[2*si] {
								continue
							}
							if len(spans) > 0 && loc[2*si] < spans[len(spans)-1].end {
								continue
							}
							spans = append(spans, subSpan{start: loc[2*si], end: loc[2*si+1], label: lbl})
						}
						if len(spans) == 0 {
							b.WriteString(prefix + "REDACTED" + suffix)
						} else {
							cur := loc[0]
							for _, sp := range spans {
								if sp.start > cur {
									b.WriteString(strVal[cur:sp.start])
								}
								b.WriteString(prefix + sp.label + suffix)
								cur = sp.end
							}
							if cur < loc[1] {
								b.WriteString(strVal[cur:loc[1]])
							}
						}
						lastPos = loc[1]
					}
					b.WriteString(strVal[lastPos:])
					strVal = b.String()
				}
				setIngestPath(doc, field, strVal)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "csv":
		field, _ := specMap["field"].(string)
		targetFields, _ := specMap["target_fields"].([]any)
		sepStr, _ := specMap["separator"].(string)
		quoteStr, _ := specMap["quote"].(string)
		trimFlag, _ := specMap["trim"].(bool)
		emptyVal, hasEmptyVal := specMap["empty_value"]
		if field != "" && len(targetFields) > 0 {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				strVal := fmt.Sprintf("%v", val)
				if strings.TrimSpace(strVal) == "" {
					return false, false, procType, procTag, specMap, nil
				}
				comma := ','
				if len(sepStr) > 0 {
					comma = rune(sepStr[0])
				}
				if len(quoteStr) > 0 && quoteStr[0] != '"' {
					strVal = strings.ReplaceAll(strVal, string(quoteStr[0]), `"`)
				}
				if trimFlag {
					reTrailingQuoteSpace := regexp.MustCompile(`"\s*(` + regexp.QuoteMeta(string(comma)) + `|$)`)
					strVal = reTrailingQuoteSpace.ReplaceAllString(strVal, `"$1`)
				}
				cr := csv.NewReader(strings.NewReader(strVal))
				cr.Comma = comma
				cr.TrimLeadingSpace = trimFlag
				cr.LazyQuotes = true
				record, err := cr.Read()
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				for idx, tfAny := range targetFields {
					tfName, ok := tfAny.(string)
					if !ok || tfName == "" {
						continue
					}
					var cell string
					if idx < len(record) {
						cell = record[idx]
					}
					if trimFlag {
						cell = strings.TrimSpace(cell)
					}
					if cell == "" {
						if hasEmptyVal {
							setIngestPath(doc, tfName, emptyVal)
						}
						continue
					}
					setIngestPath(doc, tfName, cell)
				}
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "user_agent":
		field, _ := specMap["field"].(string)
		target := "user_agent"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				uaStr := fmt.Sprintf("%v", val)
				uaMap := map[string]any{
					"original": uaStr,
					"name":     "Other",
					"os":       map[string]any{"name": "Other"},
					"device":   map[string]any{"name": "Other"},
				}
				switch {
				case strings.Contains(uaStr, "Edg/"):
					uaMap["name"] = "Edge"
				case strings.Contains(uaStr, "Chrome/"):
					uaMap["name"] = "Chrome"
				case strings.Contains(uaStr, "Firefox/"):
					uaMap["name"] = "Firefox"
				case strings.Contains(uaStr, "Safari/") && !strings.Contains(uaStr, "Chrome/"):
					uaMap["name"] = "Safari"
				case strings.Contains(uaStr, "curl/"):
					uaMap["name"] = "curl"
				}
				switch {
				case strings.Contains(uaStr, "Mac OS X"):
					uaMap["os"] = map[string]any{"name": "Mac OS X"}
				case strings.Contains(uaStr, "Windows"):
					uaMap["os"] = map[string]any{"name": "Windows"}
				case strings.Contains(uaStr, "Android"):
					uaMap["os"] = map[string]any{"name": "Android"}
				case strings.Contains(uaStr, "iPhone") || strings.Contains(uaStr, "iPad"):
					uaMap["os"] = map[string]any{"name": "iOS"}
				case strings.Contains(uaStr, "Linux"):
					uaMap["os"] = map[string]any{"name": "Linux"}
				}
				setIngestPath(doc, target, uaMap)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "uri_parts":
		field, _ := specMap["field"].(string)
		target := "url"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		keepOrig := true
		if ko, hasKO := specMap["keep_original"].(bool); hasKO {
			keepOrig = ko
		}
		removeIfSuccess, _ := specMap["remove_if_successful"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				rawURI := fmt.Sprintf("%v", val)
				u, err := url.Parse(rawURI)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				parts := map[string]any{}
				if keepOrig {
					parts["original"] = rawURI
				}
				if u.Scheme != "" {
					parts["scheme"] = u.Scheme
				}
				if h := u.Hostname(); h != "" {
					parts["domain"] = h
				}
				if p := u.Port(); p != "" {
					if pInt, err := strconv.Atoi(p); err == nil {
						parts["port"] = pInt
					}
				}
				if u.Path != "" {
					parts["path"] = u.Path
					if dotIdx := strings.LastIndexByte(u.Path, '.'); dotIdx > strings.LastIndexByte(u.Path, '/') && dotIdx+1 < len(u.Path) {
						parts["extension"] = u.Path[dotIdx+1:]
					}
				}
				if u.RawQuery != "" {
					parts["query"] = u.RawQuery
				}
				if u.Fragment != "" {
					parts["fragment"] = u.Fragment
				}
				if u.User != nil {
					if un := u.User.Username(); un != "" {
						parts["username"] = un
					}
					if pw, ok := u.User.Password(); ok {
						parts["password"] = pw
					}
				}
				setIngestPath(doc, target, parts)
				if removeIfSuccess && field != target {
					deleteIngestPath(doc, field)
				}
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "registered_domain":
		field, _ := specMap["field"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = tf
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val))), ".")
				labels := strings.Split(fqdn, ".")
				out := map[string]any{"domain": fqdn}
				if len(labels) >= 2 {
					tld := labels[len(labels)-1]
					regDom := labels[len(labels)-2] + "." + tld
					if len(labels) >= 3 && len(labels[len(labels)-2]) <= 3 && (labels[len(labels)-2] == "co" || labels[len(labels)-2] == "com" || labels[len(labels)-2] == "org" || labels[len(labels)-2] == "gov" || labels[len(labels)-2] == "ac") {
						tld = labels[len(labels)-2] + "." + labels[len(labels)-1]
						regDom = labels[len(labels)-3] + "." + tld
						if len(labels) > 3 {
							out["subdomain"] = strings.Join(labels[:len(labels)-3], ".")
						}
					} else if len(labels) > 2 {
						out["subdomain"] = strings.Join(labels[:len(labels)-2], ".")
					}
					out["top_level_domain"] = tld
					out["registered_domain"] = regDom
				}
				setIngestPath(doc, target, out)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "foreach":
		field, _ := specMap["field"].(string)
		var subProcs []any
		if subProc, ok := specMap["processor"].(map[string]any); ok && subProc != nil {
			subProcs = []any{subProc}
		} else if sps, ok := specMap["processors"].([]any); ok {
			subProcs = sps
		}
		if field != "" && len(subProcs) > 0 {
			if val, exists := getIngestPath(doc, field); exists {
				if arr, ok := val.([]any); ok {
					var prevVal any
					var hadPrev bool
					if origIngest, ok := doc["_ingest"].(map[string]any); ok && origIngest != nil {
						prevVal, hadPrev = origIngest["_value"]
					}
					restoreIngestVal := func() {
						if curIngest, ok := doc["_ingest"].(map[string]any); ok && curIngest != nil {
							if hadPrev {
								curIngest["_value"] = prevVal
							} else {
								delete(curIngest, "_value")
							}
						}
					}
					outArr := make([]any, len(arr))
					for idx, elem := range arr {
						ingestMeta, _ := doc["_ingest"].(map[string]any)
						if ingestMeta == nil {
							ingestMeta = make(map[string]any)
						}
						ingestMeta["_value"] = elem
						doc["_ingest"] = ingestMeta
						subMut, subDropped, subErr := runIngestProcessorList(s, doc, subProcs, depth+1, trace)
						if subMut {
							mutated = true
						}
						if subErr != nil {
							restoreIngestVal()
							return mutated, false, procType, procTag, specMap, subErr
						}
						if subDropped {
							restoreIngestVal()
							return mutated, true, procType, procTag, specMap, nil
						}
						if curIngest, ok := doc["_ingest"].(map[string]any); ok {
							outArr[idx] = curIngest["_value"]
						} else {
							outArr[idx] = elem
						}
					}
					restoreIngestVal()
					setIngestPath(doc, field, outArr)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "script":
		src, _ := specMap["source"].(string)
		if src == "" {
			src, _ = specMap["inline"].(string)
		}
		params, _ := specMap["params"].(map[string]any)
		if src != "" {
			normSrc := rewriteIngestCtxReferences(src)
			docBytes, err := json.Marshal(doc)
			if err == nil {
				upd := &painless.UpdateRequest{
					Script: &painless.ScriptSpec{
						Source: normSrc,
						Params: params,
					},
				}
				mutatedBytes, opRes, err := painless.ApplyUpdateWithResult(docBytes, upd, true)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				if opRes == "deleted" {
					return false, true, procType, procTag, specMap, nil
				}
				if opRes != "noop" {
					var nextDoc map[string]any
					dec2 := json.NewDecoder(bytes.NewReader(mutatedBytes))
					dec2.UseNumber()
					if err := dec2.Decode(&nextDoc); err == nil && nextDoc != nil {
						for k := range doc {
							delete(doc, k)
						}
						for k, v := range nextDoc {
							doc[k] = v
						}
						mutated = true
					}
				}
			}
		}
	}
	return mutated, false, procType, procTag, specMap, nil
}

func snapshotIngestDoc(doc map[string]any) map[string]any {
	raw, err := json.Marshal(doc)
	if err != nil {
		return map[string]any{}
	}
	var cp map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&cp)
	if im, ok := doc["_ingest"].(map[string]any); ok {
		if b, ok := im["_had_orig_index"].(bool); ok && !b {
			delete(cp, "_index")
		}
		if b, ok := im["_had_orig_id"].(bool); ok && !b {
			delete(cp, "_id")
		}
	}
	delete(cp, "_ingest")
	if cp == nil {
		cp = map[string]any{}
	}
	return cp
}

func runIngestProcessorList(s *Server, doc map[string]any, procs []any, depth int, trace *[]map[string]any) (bool, bool, error) {
	mutated := false
	for _, p := range procs {
		pMap, ok := p.(map[string]any)
		if !ok {
			continue
		}
		m, dropped, procType, procTag, specMap, procErr := executeSingleIngestProcessor(s, doc, pMap, depth, trace)
		if m {
			mutated = true
		}
		if trace != nil && procType != "" && procType != "pipeline" {
			entry := map[string]any{
				"processor_type": procType,
			}
			if procTag != "" {
				entry["tag"] = procTag
			}
			if procErr != nil {
				entry["status"] = "error"
				entry["error"] = map[string]any{
					"type":   "illegal_argument_exception",
					"reason": procErr.Error(),
				}
			} else if dropped {
				entry["status"] = "dropped"
			} else {
				stepIdx := "_index"
				if v, ok := doc["_index"].(string); ok && v != "" {
					stepIdx = v
				}
				stepID := "0"
				if v, ok := doc["_id"]; ok && v != nil {
					if sv := fmt.Sprintf("%v", v); sv != "" {
						stepID = sv
					}
				}
				entry["status"] = "success"
				entry["doc"] = map[string]any{
					"_index":   stepIdx,
					"_version": "-3",
					"_id":      stepID,
					"_source":  snapshotIngestDoc(doc),
				}
			}
			*trace = append(*trace, entry)
		}
		if dropped {
			return mutated, true, nil
		}
		if procErr != nil {
			ignoreFail, _ := specMap["ignore_failure"].(bool)
			if !ignoreFail {
				ignoreFail, _ = pMap["ignore_failure"].(bool)
			}
			if ignoreFail {
				continue
			}
			onFail, _ := specMap["on_failure"].([]any)
			if len(onFail) == 0 {
				onFail, _ = pMap["on_failure"].([]any)
			}
			if len(onFail) > 0 {
				ingestMeta, _ := doc["_ingest"].(map[string]any)
				if ingestMeta == nil {
					ingestMeta = make(map[string]any)
				}
				ingestMeta["on_failure_message"] = procErr.Error()
				_, hasInnerType := ingestMeta["on_failure_processor_type"]
				if (procType != "pipeline" && procType != "foreach") || !hasInnerType {
					ingestMeta["on_failure_processor_type"] = procType
					ingestMeta["on_failure_processor_tag"] = procTag
				}
				doc["_ingest"] = ingestMeta
				mutated = true
				subMut, subDropped, subErr := runIngestProcessorList(s, doc, onFail, depth+1, trace)
				if subMut {
					mutated = true
				}
				if subDropped {
					return mutated, true, nil
				}
				if subErr != nil {
					return mutated, false, subErr
				}
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					delete(curIngest, "on_failure_message")
					delete(curIngest, "on_failure_processor_type")
					delete(curIngest, "on_failure_processor_tag")
				}
				continue
			}
			ingestMeta, _ := doc["_ingest"].(map[string]any)
			if ingestMeta == nil {
				ingestMeta = make(map[string]any)
			}
			ingestMeta["on_failure_message"] = procErr.Error()
			_, hasInnerType := ingestMeta["on_failure_processor_type"]
			if (procType != "pipeline" && procType != "foreach") || !hasInnerType {
				if procType != "" {
					ingestMeta["on_failure_processor_type"] = procType
				}
				ingestMeta["on_failure_processor_tag"] = procTag
			}
			doc["_ingest"] = ingestMeta
			return mutated, false, procErr
		}
	}
	return mutated, false, nil
}

func applyIngestPipelineSpecVerboseWithMeta(s *Server, pipe map[string]any, indexName, docID string, raw json.RawMessage, verbose bool) (json.RawMessage, string, string, bool, []map[string]any, error) {
	if pipe == nil || len(bytes.TrimSpace(raw)) == 0 {
		return raw, indexName, docID, false, nil, nil
	}
	procs, _ := pipe["processors"].([]any)
	if len(procs) == 0 {
		return raw, indexName, docID, false, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return raw, indexName, docID, false, nil, err
	}
	_, hadOrigIndex := doc["_index"]
	_, hadOrigID := doc["_id"]
	if !hadOrigIndex && indexName != "" {
		doc["_index"] = indexName
	}
	if !hadOrigID && docID != "" {
		doc["_id"] = docID
	}
	ingestMeta, _ := doc["_ingest"].(map[string]any)
	if ingestMeta == nil {
		ingestMeta = make(map[string]any)
	}
	if _, hasTS := ingestMeta["timestamp"]; !hasTS {
		ingestMeta["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	ingestMeta["_had_orig_index"] = hadOrigIndex
	ingestMeta["_had_orig_id"] = hadOrigID
	doc["_ingest"] = ingestMeta

	var trace []map[string]any
	var tracePtr *[]map[string]any
	if verbose {
		trace = make([]map[string]any, 0)
		tracePtr = &trace
	}
	mutated, dropped, procErr := runIngestProcessorList(s, doc, procs, 0, tracePtr)
	if dropped {
		return json.RawMessage(`{}`), indexName, docID, true, trace, nil
	}
	if procErr != nil {
		if pipeOnFail, ok := pipe["on_failure"].([]any); ok && len(pipeOnFail) > 0 {
			ingestMeta, _ := doc["_ingest"].(map[string]any)
			if ingestMeta == nil {
				ingestMeta = make(map[string]any)
			}
			ingestMeta["on_failure_message"] = procErr.Error()
			ingestMeta["_had_orig_index"] = hadOrigIndex
			ingestMeta["_had_orig_id"] = hadOrigID
			doc["_ingest"] = ingestMeta
			mutated = true
			subMut, subDropped, subErr := runIngestProcessorList(s, doc, pipeOnFail, 1, tracePtr)
			if subMut {
				mutated = true
			}
			if subDropped {
				return json.RawMessage(`{}`), indexName, docID, true, trace, nil
			}
			if subErr == nil {
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					delete(curIngest, "on_failure_message")
					delete(curIngest, "on_failure_processor_type")
					delete(curIngest, "on_failure_processor_tag")
				}
			}
			procErr = subErr
		}
		if procErr != nil {
			return raw, indexName, docID, false, trace, procErr
		}
	}
	outIndex := indexName
	if v, ok := doc["_index"].(string); ok && v != "" {
		outIndex = v
	}
	outID := docID
	if v, ok := doc["_id"]; ok && v != nil {
		if sv := fmt.Sprintf("%v", v); sv != "" {
			outID = sv
		}
	}
	if !hadOrigIndex {
		delete(doc, "_index")
	}
	if !hadOrigID {
		delete(doc, "_id")
	}
	delete(doc, "_ingest")
	if !mutated {
		return raw, outIndex, outID, false, trace, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, outIndex, outID, false, trace, err
	}
	return json.RawMessage(out), outIndex, outID, false, trace, nil
}

// handleSimulateIngestPipeline implements `POST /_ingest/pipeline/_simulate` and `POST /_ingest/pipeline/{id}/_simulate`.
func (s *Server) handleSimulateIngestPipeline(w http.ResponseWriter, r *http.Request) {
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Pipeline map[string]any   `json:"pipeline,omitempty"`
		Docs     []map[string]any `json:"docs"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
		}
	}
	pipe := req.Pipeline
	if pipe == nil {
		if id := r.PathValue("id"); id != "" {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			pipe = s.pipelines[id]
			s.mu.RUnlock()
			if pipe == nil {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "pipeline ["+id+"] is missing")
				return
			}
		}
	}
	if pipe == nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", "[pipeline] required property is missing")
		return
	}

	vParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("verbose")))
	verbose := vParam == "true" || vParam == "1"
	docsOut := make([]map[string]any, 0, len(req.Docs))
	nowISO := time.Now().UTC().Format(time.RFC3339Nano)
	for i, item := range req.Docs {
		docObj := item
		if nested, ok := item["doc"].(map[string]any); ok {
			docObj = nested
		}
		idx, _ := docObj["_index"].(string)
		if idx == "" {
			idx = "_index"
		}
		id, _ := docObj["_id"].(string)
		if id == "" {
			id = fmt.Sprintf("%d", i)
		}
		srcAny, hasSrc := docObj["_source"]
		if !hasSrc {
			cpDoc := make(map[string]any, len(docObj))
			for k, v := range docObj {
				if k == "_index" || k == "_id" {
					continue
				}
				cpDoc[k] = v
			}
			srcAny = cpDoc
		}
		rawSrc, err := json.Marshal(srcAny)
		if err != nil {
			rawSrc = []byte(`{}`)
		}
		outBytes, outIdx, outID, dropped, trace, procErr := applyIngestPipelineSpecVerboseWithMeta(s, pipe, idx, id, rawSrc, verbose)
		if verbose {
			for _, te := range trace {
				if dMap, ok := te["doc"].(map[string]any); ok {
					if curIdx, _ := dMap["_index"].(string); curIdx == "" || curIdx == "_index" {
						dMap["_index"] = idx
					}
					if curID, _ := dMap["_id"].(string); curID == "" || curID == "0" {
						dMap["_id"] = id
					}
					dMap["_ingest"] = map[string]any{"timestamp": nowISO}
				}
			}
			docsOut = append(docsOut, map[string]any{"processor_results": trace})
			continue
		}
		if procErr != nil {
			docsOut = append(docsOut, map[string]any{
				"error": map[string]any{
					"type":   "illegal_argument_exception",
					"reason": procErr.Error(),
				},
			})
			continue
		}
		if dropped {
			docsOut = append(docsOut, map[string]any{"doc": nil})
			continue
		}
		var outSrc map[string]any
		dec := json.NewDecoder(bytes.NewReader(outBytes))
		dec.UseNumber()
		_ = dec.Decode(&outSrc)
		if outSrc == nil {
			outSrc = map[string]any{}
		}
		docsOut = append(docsOut, map[string]any{
			"doc": map[string]any{
				"_index":   outIdx,
				"_version": "-3",
				"_id":      outID,
				"_source":  outSrc,
				"_ingest": map[string]any{
					"timestamp": nowISO,
				},
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

func convertSingleIngestValue(val any, convType string) (any, error) {
	str := strings.TrimSpace(fmt.Sprintf("%v", val))
	switch strings.ToLower(convType) {
	case "integer", "int", "long":
		if iv, err := strconv.ParseInt(str, 10, 64); err == nil {
			return iv, nil
		}
		if fv, err := strconv.ParseFloat(str, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return int64(fv), nil
		}
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	case "float", "double":
		if fv, err := strconv.ParseFloat(str, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return fv, nil
		}
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	case "string":
		return fmt.Sprintf("%v", val), nil
	case "boolean", "bool":
		switch strings.ToLower(str) {
		case "true", "1":
			return true, nil
		case "false", "0":
			return false, nil
		}
		return nil, fmt.Errorf("unable to convert [%v] to boolean", val)
	case "ip":
		if net.ParseIP(str) != nil {
			return str, nil
		}
		return nil, fmt.Errorf("unable to convert [%v] to ip", val)
	case "auto":
		if iv, err := strconv.ParseInt(str, 10, 64); err == nil {
			return iv, nil
		}
		if fv, err := strconv.ParseFloat(str, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return fv, nil
		}
		switch strings.ToLower(str) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return str, nil
	default:
		return val, nil
	}
}

func parseIngestSliceIndex(seg string, length int) (int, bool) {
	if seg == "" || length <= 0 {
		return 0, false
	}
	idx, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	if idx < 0 {
		idx = length + idx
	}
	if idx < 0 || idx >= length {
		return 0, false
	}
	return idx, true
}

func getIngestPath(doc map[string]any, path string) (any, bool) {
	if val, ok := doc[path]; ok {
		return val, true
	}
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		return nil, false
	}
	var curr any = doc
	for i := 0; i < len(segs)-1; i++ {
		switch node := curr.(type) {
		case map[string]any:
			if flatVal, flatOk := node[strings.Join(segs[i:], ".")]; flatOk {
				return flatVal, true
			}
			next, exists := node[segs[i]]
			if !exists {
				return nil, false
			}
			curr = next
		case []any:
			idx, ok := parseIngestSliceIndex(segs[i], len(node))
			if !ok {
				return nil, false
			}
			curr = node[idx]
		default:
			return nil, false
		}
	}
	lastSeg := segs[len(segs)-1]
	switch node := curr.(type) {
	case map[string]any:
		val, ok := node[lastSeg]
		return val, ok
	case []any:
		idx, ok := parseIngestSliceIndex(lastSeg, len(node))
		if !ok {
			return nil, false
		}
		return node[idx], true
	default:
		return nil, false
	}
}

func deepMergeIngestMap(dst, src map[string]any) {
	for k, v := range src {
		if vMap, ok := v.(map[string]any); ok {
			if existing, ok := dst[k].(map[string]any); ok {
				deepMergeIngestMap(existing, vMap)
				continue
			}
		}
		dst[k] = v
	}
}

func setIngestPathMerge(doc map[string]any, path string, val any) {
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		if valMap, ok := val.(map[string]any); ok {
			if existing, ok := doc[path].(map[string]any); ok {
				deepMergeIngestMap(existing, valMap)
				return
			}
		}
		doc[path] = val
		return
	}
	delete(doc, path)
	var curr any = doc
	for i := 0; i < len(segs)-1; i++ {
		seg := segs[i]
		switch node := curr.(type) {
		case map[string]any:
			delete(node, strings.Join(segs[i:], "."))
			next, exists := node[seg]
			if !exists || next == nil {
				nextMap := make(map[string]any)
				node[seg] = nextMap
				curr = nextMap
				continue
			}
			if _, isMap := next.(map[string]any); isMap {
				curr = next
				continue
			}
			if _, isSlice := next.([]any); isSlice {
				curr = next
				continue
			}
			nextMap := make(map[string]any)
			node[seg] = nextMap
			curr = nextMap
		case []any:
			idx, ok := parseIngestSliceIndex(seg, len(node))
			if !ok {
				return
			}
			if node[idx] == nil {
				node[idx] = make(map[string]any)
			}
			curr = node[idx]
		default:
			return
		}
	}
	lastSeg := segs[len(segs)-1]
	switch node := curr.(type) {
	case map[string]any:
		if valMap, ok := val.(map[string]any); ok {
			if existing, ok := node[lastSeg].(map[string]any); ok {
				deepMergeIngestMap(existing, valMap)
				return
			}
		}
		node[lastSeg] = val
	case []any:
		if idx, ok := parseIngestSliceIndex(lastSeg, len(node)); ok {
			node[idx] = val
		}
	}
}

func setIngestPath(doc map[string]any, path string, val any) {
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		doc[path] = val
		return
	}
	delete(doc, path)
	var curr any = doc
	for i := 0; i < len(segs)-1; i++ {
		seg := segs[i]
		switch node := curr.(type) {
		case map[string]any:
			delete(node, strings.Join(segs[i:], "."))
			next, exists := node[seg]
			if !exists || next == nil {
				nextMap := make(map[string]any)
				node[seg] = nextMap
				curr = nextMap
				continue
			}
			if _, isMap := next.(map[string]any); isMap {
				curr = next
				continue
			}
			if _, isSlice := next.([]any); isSlice {
				curr = next
				continue
			}
			nextMap := make(map[string]any)
			node[seg] = nextMap
			curr = nextMap
		case []any:
			idx, ok := parseIngestSliceIndex(seg, len(node))
			if !ok {
				return
			}
			if node[idx] == nil {
				node[idx] = make(map[string]any)
			}
			curr = node[idx]
		default:
			return
		}
	}
	lastSeg := segs[len(segs)-1]
	switch node := curr.(type) {
	case map[string]any:
		node[lastSeg] = val
	case []any:
		if idx, ok := parseIngestSliceIndex(lastSeg, len(node)); ok {
			node[idx] = val
		}
	}
}

func deleteIngestPath(doc map[string]any, path string) {
	delete(doc, path)
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		return
	}
	var curr any = doc
	for i := 0; i < len(segs)-1; i++ {
		switch node := curr.(type) {
		case map[string]any:
			if _, flatOk := node[strings.Join(segs[i:], ".")]; flatOk {
				delete(node, strings.Join(segs[i:], "."))
				return
			}
			next, exists := node[segs[i]]
			if !exists {
				return
			}
			curr = next
		case []any:
			idx, ok := parseIngestSliceIndex(segs[i], len(node))
			if !ok {
				return
			}
			curr = node[idx]
		default:
			return
		}
	}
	if node, ok := curr.(map[string]any); ok {
		delete(node, segs[len(segs)-1])
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
	var names []string
	if pat := r.PathValue("index"); pat != "" {
		names = s.resolveTargetIndices(pat)
	} else {
		s.mu.RLock()
		names = make([]string, 0, len(s.indices))
		for name := range s.indices {
			names = append(names, name)
		}
		s.mu.RUnlock()
	}
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
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Has("v") {
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
		}
		for _, row := range rows {
			vals := make([]string, 0, len(headers))
			for _, h := range headers {
				vals = append(vals, fmt.Sprintf("%v", row[h]))
			}
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(vals, "\t"))
		}
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleReindex implements `POST /_reindex` to copy documents between indices with optional query filtering and Painless script mutation.
func (s *Server) handleReindex(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var body struct {
		MaxDocs   *int   `json:"max_docs,omitempty"`
		Size      *int   `json:"size,omitempty"`
		Conflicts string `json:"conflicts,omitempty"`
		Source    struct {
			Index  any                 `json:"index"`
			Query  *esast.Query        `json:"query,omitempty"`
			Size   *int                `json:"size,omitempty"`
			Source *esast.SourceFilter `json:"_source,omitempty"`
		} `json:"source"`
		Dest struct {
			Index    string `json:"index"`
			Pipeline string `json:"pipeline,omitempty"`
			OpType   string `json:"op_type,omitempty"`
		} `json:"dest"`
		Script *painless.ScriptSpec `json:"script,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	if body.Conflicts == "" {
		body.Conflicts = r.URL.Query().Get("conflicts")
	}
	if body.Dest.Pipeline == "" {
		body.Dest.Pipeline = r.URL.Query().Get("pipeline")
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
	if srcPattern == "" || strings.TrimSpace(body.Dest.Index) == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "source.index and dest.index are required")
		return
	}
	destIndex, destAliasFilter, writeErr := s.resolveWriteIndexWithFilter(body.Dest.Index)
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}

	maxDocs := 0
	if body.MaxDocs != nil && *body.MaxDocs > 0 {
		maxDocs = *body.MaxDocs
	} else if body.Size != nil && *body.Size > 0 {
		maxDocs = *body.Size
	}
	if qMax := r.URL.Query().Get("max_docs"); qMax != "" {
		if parsed, err := strconv.Atoi(qMax); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	} else if qSize := r.URL.Query().Get("size"); qSize != "" {
		if parsed, err := strconv.Atoi(qSize); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	}

	var destSchema *schema.IndexSchema
	srcTargets, aliasFilters := s.resolveTargetIndicesWithFilters(srcPattern)
	if len(srcTargets) == 0 && !hasExclusionOrWildcard(srcPattern) {
		target, f := s.resolveIndexNameWithFilter(srcPattern)
		srcTargets = []string{target}
		if f != nil {
			if aliasFilters == nil {
				aliasFilters = make(map[string]*esast.Query)
			}
			aliasFilters[target] = f
		}
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)

	var totalMatched, totalCreated, totalUpdated, totalDeleted, versionConflicts, batches int
	updSpec := &painless.UpdateRequest{Script: body.Script}
	hasReindexMetaScript := false
	if body.Script != nil && (strings.Contains(body.Script.Source, "ctx._id") || strings.Contains(body.Script.Source, "ctx._index")) {
		hasReindexMetaScript = true
		rewrittenSrc := strings.ReplaceAll(body.Script.Source, "ctx._id", "ctx._source.__reindex_id")
		rewrittenSrc = strings.ReplaceAll(rewrittenSrc, "ctx._index", "ctx._source.__reindex_index")
		updSpec = &painless.UpdateRequest{
			Script: &painless.ScriptSpec{
				Source: rewrittenSrc,
				Lang:   body.Script.Lang,
				Params: body.Script.Params,
			},
		}
	}
	batchSize := 1000
	if body.Source.Size != nil && *body.Source.Size > 0 && *body.Source.Size < batchSize {
		batchSize = *body.Source.Size
	}

	s.resolveTermsLookupsInQuery(r.Context(), body.Source.Query)
	for _, srcIdx := range srcTargets {
		srcSchema := s.getOrCompileReadOnlySchema(r.Context(), srcIdx)
		_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
		tr := transpiler.NewTranspiler(srcSchema, s.transpileOpts)
		var searchAfter []any
		effQuery := combineQueryWithAliasFilter(body.Source.Query, aliasFilters[srcIdx])
		hasRuntimeQueryScript := queryHasRuntimeScript(effQuery)

		for {
			fetchSize := batchSize
			if !hasRuntimeQueryScript && maxDocs > 0 && totalMatched+fetchSize > maxDocs {
				fetchSize = maxDocs - totalMatched
			}
			if fetchSize <= 0 || (maxDocs > 0 && totalMatched >= maxDocs) {
				break
			}
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Query:          effQuery,
				Size:           &fetchSize,
				TrackTotalHits: false,
				Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter:    searchAfter,
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
			if len(hits) == 0 {
				break
			}
			batches++
			type preparedDoc struct {
				id        string
				destIndex string
				source    json.RawMessage
				srcVer    int64
			}
			var prepared []preparedDoc
			sampleDocsByIdx := make(map[string][]json.RawMessage)
			candIDsByIdx := make(map[string][]string)
			for _, h := range hits {
				if maxDocs > 0 && totalMatched >= maxDocs {
					break
				}
				if hasRuntimeQueryScript {
					var rawMap map[string]any
					dec := json.NewDecoder(bytes.NewReader(h.Source))
					dec.UseNumber()
					_ = dec.Decode(&rawMap)
					if rawMap == nil {
						rawMap = make(map[string]any)
					}
					if !evalQueryScriptFilterOnDocWithSchema(srcSchema, rawMap, effQuery) {
						continue
					}
				}
				totalMatched++
				docID := h.ID
				docDestIdx := destIndex
				docSource := h.Source
				if body.Source.Source != nil {
					filtered := filterSourceJSON(docSource, body.Source.Source)
					if filtered == nil {
						docSource = json.RawMessage(`{}`)
					} else {
						docSource = filtered
					}
				}
				if body.Script != nil {
					scriptInput := docSource
					if hasReindexMetaScript {
						var tmpMap map[string]any
						dec := json.NewDecoder(bytes.NewReader(docSource))
						dec.UseNumber()
						_ = dec.Decode(&tmpMap)
						if tmpMap == nil {
							tmpMap = make(map[string]any)
						}
						tmpMap["__reindex_id"] = docID
						tmpMap["__reindex_index"] = docDestIdx
						if b, err := json.Marshal(tmpMap); err == nil {
							scriptInput = b
						}
					}
					mutated, opRes, err := painless.ApplyUpdateWithResult(scriptInput, updSpec, true)
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
					if hasReindexMetaScript {
						var tmpMap map[string]any
						dec := json.NewDecoder(bytes.NewReader(mutated))
						dec.UseNumber()
						if err := dec.Decode(&tmpMap); err == nil && tmpMap != nil {
							if v, ok := tmpMap["__reindex_id"]; ok && v != nil {
								docID = fmt.Sprintf("%v", v)
							}
							if v, ok := tmpMap["__reindex_index"]; ok && v != nil {
								if sIdx := strings.TrimSpace(fmt.Sprintf("%v", v)); sIdx != "" {
									resolvedIdx, _, rErr := s.resolveWriteIndexWithFilter(sIdx)
									if rErr != nil {
										writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
										return
									}
									docDestIdx = resolvedIdx
								}
							}
							delete(tmpMap, "__reindex_id")
							delete(tmpMap, "__reindex_index")
							if b, err := json.Marshal(tmpMap); err == nil {
								mutated = b
							}
						}
					}
					docSource = mutated
				}
				pipedDoc, nextDestIdx, nextDocID, dropped, pipeErr := s.applyEffectiveAndFinalPipelinesWithMeta(docDestIdx, docID, body.Dest.Pipeline, "", docSource)
				if pipeErr != nil {
					writeESError(w, http.StatusBadRequest, "ingest_processor_exception", pipeErr.Error())
					return
				}
				if dropped {
					continue
				}
				if nextDocID != "" {
					docID = nextDocID
				}
				if nextDestIdx != "" && nextDestIdx != docDestIdx {
					resolvedIdx, _, rErr := s.resolveWriteIndexWithFilter(nextDestIdx)
					if rErr != nil {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
						return
					}
					docDestIdx = resolvedIdx
				}
				docSource = pipedDoc
				if docDestIdx == destIndex && destAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), destIndex, docID, docSource, destAliasFilter) {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "document does not match destination alias filter")
					return
				}
				prepared = append(prepared, preparedDoc{id: docID, destIndex: docDestIdx, source: docSource, srcVer: h.Version})
				candIDsByIdx[docDestIdx] = append(candIDsByIdx[docDestIdx], docID)
				sampleDocsByIdx[docDestIdx] = append(sampleDocsByIdx[docDestIdx], docSource)
			}
			if len(prepared) == 0 {
				searchAfter = []any{hits[len(hits)-1].ID}
				if len(hits) < fetchSize || (maxDocs > 0 && totalMatched >= maxDocs) {
					break
				}
				continue
			}
			schemasByIdx := make(map[string]*schema.IndexSchema, len(sampleDocsByIdx))
			existingByIdx := make(map[string]map[string]HitRow, len(sampleDocsByIdx))
			for idxName, sDocs := range sampleDocsByIdx {
				sch := s.ensureWritableIndexSchemaWithDocs(r.Context(), idxName, sDocs)
				if idxName == destIndex {
					destSchema = sch
				}
				schemasByIdx[idxName] = sch
				_ = s.coalescer.FlushTable(r.Context(), sch.DorisTable)
				if ids := candIDsByIdx[idxName]; len(ids) > 0 {
					existingDocs, _ := s.backend.GetDocsByIDs(r.Context(), sch.DorisDB, sch.DorisTable, ids)
					if existingDocs == nil {
						existingDocs = make(map[string]HitRow)
					}
					existingByIdx[idxName] = existingDocs
				} else {
					existingByIdx[idxName] = make(map[string]HitRow)
				}
			}
			isCreate := strings.EqualFold(strings.TrimSpace(body.Dest.OpType), "create")
			proceedOnConflict := strings.EqualFold(strings.TrimSpace(body.Conflicts), "proceed")

			batchBufByTable := make(map[string]*bytes.Buffer, len(schemasByIdx))
			var tableOrder []string
			for _, pd := range prepared {
				sch := schemasByIdx[pd.destIndex]
				existingDocs := existingByIdx[pd.destIndex]
				var minVer int64
				if pd.srcVer > 0 {
					minVer = pd.srcVer + 1
				}
				existing, exists := existingDocs[pd.id]
				if exists {
					conflict := isCreate || (pd.destIndex == destIndex && destAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), destIndex, pd.id, existing.Source, destAliasFilter))
					if conflict {
						if proceedOnConflict {
							versionConflicts++
							continue
						}
						writeESError(w, http.StatusConflict, "version_conflict_engine_exception",
							fmt.Sprintf("[%s]: version conflict, document already exists or belongs to another alias partition", pd.id))
						return
					}
					if existing.Version+1 > minVer {
						minVer = existing.Version + 1
					}
				}
				nextVer := s.allocVersion(minVer)
				shredded, err := schema.ShredDocument(sch, pd.id, nextVer, false, pd.source)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
					return
				}
				buf, hasBuf := batchBufByTable[sch.DorisTable]
				if !hasBuf {
					buf = &bytes.Buffer{}
					batchBufByTable[sch.DorisTable] = buf
					tableOrder = append(tableOrder, sch.DorisTable)
				}
				buf.Write(shredded)
				buf.WriteByte('\n')
				existingDocs[pd.id] = HitRow{ID: pd.id, Version: nextVer, Source: pd.source}
				if exists {
					totalUpdated++
				} else {
					totalCreated++
				}
			}
			for _, tbl := range tableOrder {
				buf := batchBufByTable[tbl]
				if buf.Len() > 0 {
					if err := s.streamLoad(r.Context(), tbl, buf.Bytes(), true); err != nil {
						writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
						return
					}
				}
			}
			searchAfter = []any{hits[len(hits)-1].ID}
			if len(hits) < fetchSize || (maxDocs > 0 && totalMatched >= maxDocs) {
				break
			}
		}
	}
	if destSchema == nil {
		_ = s.ensureWritableIndexSchema(r.Context(), destIndex)
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":                   tookMs,
		"timed_out":              false,
		"total":                  totalMatched,
		"updated":                totalUpdated,
		"created":                totalCreated,
		"deleted":                totalDeleted,
		"batches":                batches,
		"version_conflicts":      versionConflicts,
		"noops":                  totalMatched - totalCreated - totalUpdated - totalDeleted - versionConflicts,
		"retries":                map[string]any{"bulk": 0, "search": 0},
		"throttled_millis":       0,
		"requests_per_second":    -1.0,
		"throttled_until_millis": 0,
		"failures":               []any{},
	})
}

// handleDorisPromoteField implements `POST /{index}/_doris/promote` to atomically promote an unindexed `_doc[...]`
// VARIANT field into a dedicated `f__*` column with a `USING INVERTED` index and update the index mapping.
func (s *Server) handleDorisPromoteField(w http.ResponseWriter, r *http.Request) {
	idxName := s.resolveIndexName(r.PathValue("index"))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Field string `json:"field"`
		Type  string `json:"type,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	req.Field = strings.TrimSpace(req.Field)
	if req.Field == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "field is required")
		return
	}
	if req.Type == "" {
		req.Type = "keyword"
	}

	ddls, err := s.promoteFieldInternal(r.Context(), idxName, req.Field, req.Type)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":    true,
		"index":           idxName,
		"promoted_field":  req.Field,
		"es_type":         req.Type,
		"doris_column":    "f__" + schema.SanitizeDorisIdentifier(req.Field),
		"promoted_column": "f__" + schema.SanitizeDorisIdentifier(req.Field),
		"executed_ddls":   ddls,
	})
}

func (s *Server) promoteFieldInternal(ctx context.Context, idxName, field, esType string) ([]string, error) {
	if esType == "" {
		esType = "keyword"
	}
	cleanField := strings.TrimSuffix(field, ".keyword")
	clearTrackerFreq := func() {
		s.slowTracker.mu.Lock()
		if byField, ok := s.slowTracker.unindexedFreq[idxName]; ok {
			delete(byField, field)
			delete(byField, cleanField)
			if len(byField) == 0 {
				delete(s.slowTracker.unindexedFreq, idxName)
			}
		}
		s.slowTracker.mu.Unlock()
	}
	idxSchema := s.ensureWritableIndexSchema(ctx, idxName)
	if existing, ok := idxSchema.Fields[cleanField]; ok && existing.Kind != schema.StorageDynamicVariant {
		clearTrackerFreq()
		return []string{}, nil
	}

	isMultiValued := schema.DefaultMultiValuedPaths[cleanField]
	if !isMultiValued && s.backend != nil {
		_ = s.coalescer.FlushTable(ctx, idxSchema.DorisTable)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		sampleSize := 16
		if plan, err := tr.BuildSearchPlan(&esast.SearchRequest{Size: &sampleSize, TrackTotalHits: false}); err == nil {
			if hits, err := s.backend.QueryHits(ctx, plan.HitsSQL); err == nil && len(hits) > 0 {
				var sampleDocs []json.RawMessage
				for _, h := range hits {
					sampleDocs = append(sampleDocs, h.Source)
				}
				if inferred := schema.InferMappingFromSampleDocs(sampleDocs); inferred != nil {
					if fp, found := lookupFieldPropertyByPath(inferred.Properties, strings.Split(cleanField, ".")); found && fp.MultiValued {
						isMultiValued = true
					}
				}
			}
		}
	}

	ddlType := esType
	if isMultiValued {
		ddlType = "array"
	}
	ddls := schema.GeneratePromoteVariantFieldDDL(idxSchema, cleanField, ddlType)
	for _, ddl := range ddls {
		if err := s.backend.ExecDDL(ctx, ddl); err != nil {
			return nil, err
		}
	}

	patchSpec := &esast.MappingSpec{
		Properties: buildNestedMappingProps(strings.Split(cleanField, "."), esast.FieldProperty{Type: esType, MultiValued: isMultiValued}),
	}
	s.mu.Lock()
	var oldRaw *esast.MappingSpec
	if cur := s.indices[idxName]; cur != nil {
		oldRaw = cur.RawMapping
	}
	mergedSpec := schema.MergeMappingSpecs(oldRaw, patchSpec)
	compiled := schema.CompileIndexSchema(s.dorisDB, idxName, mergedSpec)
	s.indices[idxName] = compiled
	s.mu.Unlock()
	s.persistIndex(ctx, idxName, compiled)
	s.backfillIndexSchema(ctx, compiled)
	s.queryCache.InvalidateAll()
	clearTrackerFreq()
	return ddls, nil
}

func lookupFieldPropertyByPath(props map[string]esast.FieldProperty, segs []string) (esast.FieldProperty, bool) {
	if len(segs) == 0 || len(props) == 0 {
		return esast.FieldProperty{}, false
	}
	fp, ok := props[segs[0]]
	if !ok {
		return esast.FieldProperty{}, false
	}
	if len(segs) == 1 {
		return fp, true
	}
	return lookupFieldPropertyByPath(fp.Properties, segs[1:])
}

func (s *Server) backfillIndexSchema(ctx context.Context, newSchema *schema.IndexSchema) {
	if newSchema == nil || s.backend == nil {
		return
	}
	_ = s.coalescer.FlushTable(ctx, newSchema.DorisTable)
	tr := transpiler.NewTranspiler(newSchema, s.transpileOpts)
	batchSize := 1000
	var searchAfter []any
	for {
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
			Size:           &batchSize,
			TrackTotalHits: false,
			Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
			SearchAfter:    searchAfter,
		})
		if err != nil {
			return
		}
		hits, err := s.backend.QueryHits(ctx, plan.HitsSQL)
		if err != nil || len(hits) == 0 {
			return
		}
		var buf bytes.Buffer
		for _, h := range hits {
			shredded, err := schema.ShredDocument(newSchema, h.ID, h.Version+1, false, h.Source)
			if err != nil {
				continue
			}
			buf.Write(shredded)
			buf.WriteByte('\n')
		}
		if buf.Len() > 0 {
			_ = s.streamLoad(ctx, newSchema.DorisTable, buf.Bytes(), true)
		}
		searchAfter = []any{hits[len(hits)-1].ID}
		if len(hits) < batchSize {
			break
		}
	}
}

func buildNestedMappingProps(segments []string, leaf esast.FieldProperty) map[string]esast.FieldProperty {
	if len(segments) == 0 {
		return nil
	}
	if len(segments) == 1 {
		return map[string]esast.FieldProperty{segments[0]: leaf}
	}
	return map[string]esast.FieldProperty{
		segments[0]: {
			Properties: buildNestedMappingProps(segments[1:], leaf),
		},
	}
}

// handleValidateQuery implements `GET/POST /_validate/query` and `GET/POST /{index}/_validate/query`.
func (s *Server) handleValidateQuery(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")

	raw, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req esast.SearchRequest
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"valid":   false,
				"error":   err.Error(),
				"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
			})
			return
		}
	}
	applyURISearchParams(r, &req)
	rawIndex = extractPITIndex(rawIndex, req.PIT)
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 {
		if rawIndex != "" && hasExclusionOrWildcard(rawIndex) {
			resp := map[string]any{
				"valid":   true,
				"_shards": map[string]any{"total": 0, "successful": 0, "failed": 0},
			}
			if r.URL.Query().Get("explain") == "true" || r.URL.Query().Has("explain") || r.URL.Query().Get("rewrite") == "true" {
				resp["explanations"] = []map[string]any{}
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if rawIndex != "" {
			target, f := s.resolveIndexNameWithFilter(rawIndex)
			targets = []string{target}
			if f != nil {
				if aliasFilters == nil {
					aliasFilters = make(map[string]*esast.Query)
				}
				aliasFilters[target] = f
			}
		} else {
			targets = []string{"_all"}
		}
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)
	_ = s.resolveTermsLookupsInSearchRequest(r.Context(), &req)

	var explanations []map[string]any
	for _, idxName := range targets {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		subReq := applyIndexAliasFilter(&req, aliasFilters[idxName])
		plan, err := tr.BuildSearchPlan(subReq)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"valid":   false,
				"error":   err.Error(),
				"_shards": map[string]any{"total": len(targets), "successful": len(targets), "failed": 0},
			})
			return
		}
		expl := plan.HitsSQL
		if plan.AggsSQL != "" {
			expl += " ; " + plan.AggsSQL
		}
		explanations = append(explanations, map[string]any{
			"index":       idxName,
			"valid":       true,
			"explanation": expl,
		})
	}

	resp := map[string]any{
		"valid":   true,
		"_shards": map[string]any{"total": len(targets), "successful": len(targets), "failed": 0},
	}
	if r.URL.Query().Get("explain") == "true" || r.URL.Query().Has("explain") || r.URL.Query().Get("rewrite") == "true" {
		resp["explanations"] = explanations
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyze implements `GET/POST /_analyze` and `GET/POST /{index}/_analyze`.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Analyzer   string `json:"analyzer,omitempty"`
		Tokenizer  string `json:"tokenizer,omitempty"`
		Normalizer string `json:"normalizer,omitempty"`
		Field      string `json:"field,omitempty"`
		Text       any    `json:"text,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		_ = json.Unmarshal(bodyBytes, &req)
	}
	if req.Analyzer == "" {
		req.Analyzer = r.URL.Query().Get("analyzer")
	}
	if req.Field == "" {
		req.Field = r.URL.Query().Get("field")
	}
	if req.Text == nil && r.URL.Query().Get("text") != "" {
		req.Text = r.URL.Query().Get("text")
	}

	analyzer := strings.ToLower(strings.TrimSpace(req.Analyzer))
	if analyzer == "" {
		analyzer = strings.ToLower(strings.TrimSpace(req.Tokenizer))
	}
	dorisParser := "standard"
	if rawIdx := r.PathValue("index"); rawIdx != "" && req.Field != "" {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), s.resolveIndexName(rawIdx))
		b := idxSchema.ResolveField(req.Field)
		if b.Analyzer != "" && analyzer == "" {
			analyzer = strings.ToLower(b.Analyzer)
		}
		if b.DorisType == schema.DorisVarchar && b.Analyzer == "" && analyzer == "" {
			analyzer = "keyword"
			dorisParser = "none (keyword exact)"
		}
	}
	switch {
	case strings.Contains(analyzer, "keyword") || req.Normalizer != "":
		dorisParser = "none (keyword)"
	case strings.Contains(analyzer, "unicode") || strings.Contains(analyzer, "icu"):
		dorisParser = "unicode"
	case strings.Contains(analyzer, "ngram"):
		dorisParser = "ngram"
	}

	var texts []string
	switch tv := req.Text.(type) {
	case string:
		texts = []string{tv}
	case []any:
		for _, item := range tv {
			texts = append(texts, fmt.Sprintf("%v", item))
		}
	}

	var tokens []map[string]any
	pos := 0
	for _, txt := range texts {
		if strings.Contains(analyzer, "keyword") || req.Normalizer != "" {
			tok := txt
			if strings.Contains(strings.ToLower(req.Normalizer), "lower") || strings.Contains(analyzer, "lower") {
				tok = strings.ToLower(tok)
			}
			tokens = append(tokens, map[string]any{
				"token":        tok,
				"start_offset": 0,
				"end_offset":   len(txt),
				"type":         "word",
				"position":     pos,
			})
			pos++
			continue
		}
		startOff := -1
		var cur strings.Builder
		for i, ch := range txt {
			isWord := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch > 127
			if strings.Contains(analyzer, "whitespace") {
				isWord = ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r'
			}
			if isWord {
				if startOff < 0 {
					startOff = i
				}
				if strings.Contains(analyzer, "whitespace") && !strings.Contains(analyzer, "lower") {
					cur.WriteRune(ch)
				} else {
					cur.WriteRune(unicodeToLower(ch))
				}
			} else if startOff >= 0 {
				tokens = append(tokens, map[string]any{
					"token":        cur.String(),
					"start_offset": startOff,
					"end_offset":   i,
					"type":         "<ALPHANUM>",
					"position":     pos,
				})
				pos++
				cur.Reset()
				startOff = -1
			}
		}
		if startOff >= 0 {
			tokens = append(tokens, map[string]any{
				"token":        cur.String(),
				"start_offset": startOff,
				"end_offset":   len(txt),
				"type":         "<ALPHANUM>",
				"position":     pos,
			})
			pos++
		}
	}
	if tokens == nil {
		tokens = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens":        tokens,
		"_doris_parser": dorisParser,
	})
}

func unicodeToLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// handleRollover implements `POST /{alias}/_rollover` and `POST /{alias}/_rollover/{new_index}`.
func (s *Server) handleRollover(w http.ResponseWriter, r *http.Request) {
	if _, ok := readRequestBody(w, r); !ok {
		return
	}
	alias := r.PathValue("alias")
	newIdx := r.PathValue("new_index")

	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	targets := s.aliases[alias]
	s.mu.RUnlock()

	oldIdx := alias + "-000001"
	if len(targets) > 0 {
		oldIdx = targets[len(targets)-1]
	}
	if newIdx == "" {
		newIdx = incrementRolloverIndexName(oldIdx)
	}

	var baseMapping *esast.MappingSpec
	s.mu.RLock()
	if oldSchema, ok := s.indices[oldIdx]; ok && oldSchema != nil {
		baseMapping = oldSchema.RawMapping
	} else {
		baseMapping = s.matchingTemplateMappingsLocked(newIdx)
	}
	s.mu.RUnlock()

	compiled := schema.CompileIndexSchema(s.dorisDB, newIdx, baseMapping)
	if err := s.backend.ExecDDL(r.Context(), schema.GenerateCreateTableDDL(compiled)); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	s.mu.Lock()
	s.indices[newIdx] = compiled
	var updatedTargets []string
	if metaByIdx := s.aliasMeta[alias]; metaByIdx != nil {
		if oldMeta, hasOld := metaByIdx[oldIdx]; hasOld && oldMeta.IsWriteIndex != nil && *oldMeta.IsWriteIndex {
			fVal := false
			tVal := true
			oldMeta.IsWriteIndex = &fVal
			metaByIdx[oldIdx] = oldMeta
			newMeta := oldMeta
			newMeta.IsWriteIndex = &tVal
			metaByIdx[newIdx] = newMeta
			foundNew := false
			for _, t := range s.aliases[alias] {
				if t == newIdx {
					foundNew = true
				}
			}
			if !foundNew {
				s.aliases[alias] = append(s.aliases[alias], newIdx)
			}
			updatedTargets = append([]string(nil), s.aliases[alias]...)
		} else {
			if oldMeta, hasOld := metaByIdx[oldIdx]; hasOld {
				delete(metaByIdx, oldIdx)
				metaByIdx[newIdx] = oldMeta
			}
			s.aliases[alias] = []string{newIdx}
			updatedTargets = []string{newIdx}
		}
	} else {
		s.aliases[alias] = []string{newIdx}
		updatedTargets = []string{newIdx}
	}
	s.mu.Unlock()
	s.persistIndex(r.Context(), newIdx, compiled)
	s.persistAlias(r.Context(), alias, updatedTargets)
	s.queryCache.InvalidateAll()

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"old_index":           oldIdx,
		"new_index":           newIdx,
		"rolled_over":         true,
		"dry_run":             false,
		"conditions":          map[string]bool{},
	})
}

func incrementRolloverIndexName(name string) string {
	if idx := strings.LastIndexByte(name, '-'); idx > 0 && idx < len(name)-1 {
		suffix := name[idx+1:]
		if n, err := strconv.Atoi(suffix); err == nil {
			return fmt.Sprintf("%s-%0*d", name[:idx], len(suffix), n+1)
		}
	}
	return name + "-000002"
}

// handleHealthz implements `GET /healthz` process liveness probe.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleReadyz implements `GET /readyz` backend readiness probe.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ready",
		"doris_db": s.dorisDB,
	})
}

// handleMetrics implements `GET /metrics` and `GET /_doris/metrics` in Prometheus text exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	numIndices := len(s.indices)
	numAliases := len(s.aliases)
	numTemplates := len(s.templates)
	s.mu.RUnlock()

	s.slowTracker.mu.RLock()
	numSlowQueries := len(s.slowTracker.entries)
	var unindexedTotal int64
	for _, fields := range s.slowTracker.unindexedFreq {
		for _, c := range fields {
			unindexedTotal += c
		}
	}
	s.slowTracker.mu.RUnlock()

	s.shadowVerifier.mu.RLock()
	shadowTotal := s.shadowVerifier.totalQueries
	shadowMatches := s.shadowVerifier.hitParityMatches
	shadowJaccardSum := s.shadowVerifier.jaccardSum
	s.shadowVerifier.mu.RUnlock()

	totalReqs := atomic.LoadInt64(&s.totalHTTPRequests)

	var sb strings.Builder
	sb.WriteString("# HELP doris_es_proxy_http_requests_total Total HTTP requests handled by doris-es-proxy.\n")
	sb.WriteString("# TYPE doris_es_proxy_http_requests_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_http_requests_total %d\n", totalReqs)

	sb.WriteString("# HELP doris_es_proxy_catalog_indices_total Number of registered Elasticsearch indices.\n")
	sb.WriteString("# TYPE doris_es_proxy_catalog_indices_total gauge\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_catalog_indices_total %d\n", numIndices)

	sb.WriteString("# HELP doris_es_proxy_catalog_aliases_total Number of registered Elasticsearch aliases.\n")
	sb.WriteString("# TYPE doris_es_proxy_catalog_aliases_total gauge\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_catalog_aliases_total %d\n", numAliases)

	sb.WriteString("# HELP doris_es_proxy_catalog_templates_total Number of registered Elasticsearch index templates.\n")
	sb.WriteString("# TYPE doris_es_proxy_catalog_templates_total gauge\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_catalog_templates_total %d\n", numTemplates)

	sb.WriteString("# HELP doris_es_proxy_recorded_queries_total Queries recorded in slowlog ring buffer.\n")
	sb.WriteString("# TYPE doris_es_proxy_recorded_queries_total gauge\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_recorded_queries_total %d\n", numSlowQueries)

	sb.WriteString("# HELP doris_es_proxy_unindexed_variant_accesses_total Unindexed _doc VARIANT field accesses detected.\n")
	sb.WriteString("# TYPE doris_es_proxy_unindexed_variant_accesses_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_unindexed_variant_accesses_total %d\n", unindexedTotal)

	sb.WriteString("# HELP doris_es_proxy_shadow_queries_total Total dual-read shadow comparison queries executed.\n")
	sb.WriteString("# TYPE doris_es_proxy_shadow_queries_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_shadow_queries_total %d\n", shadowTotal)

	sb.WriteString("# HELP doris_es_proxy_shadow_parity_matches_total Shadow queries with exact hit-count parity.\n")
	sb.WriteString("# TYPE doris_es_proxy_shadow_parity_matches_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_shadow_parity_matches_total %d\n", shadowMatches)

	sb.WriteString("# HELP doris_es_proxy_shadow_jaccard_sum Cumulative Top-K Jaccard similarity across shadow queries.\n")
	sb.WriteString("# TYPE doris_es_proxy_shadow_jaccard_sum counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_shadow_jaccard_sum %.4f\n", shadowJaccardSum)

	coalescedReqs, coalescedFlushes := s.coalescer.Stats()
	sb.WriteString("# HELP doris_es_proxy_bulk_coalesced_requests_total Write requests submitted through the Stream Load micro-batch coalescer.\n")
	sb.WriteString("# TYPE doris_es_proxy_bulk_coalesced_requests_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_bulk_coalesced_requests_total %d\n", coalescedReqs)

	sb.WriteString("# HELP doris_es_proxy_bulk_coalesced_flushes_total Batched Stream Load flushes executed by the coalescer.\n")
	sb.WriteString("# TYPE doris_es_proxy_bulk_coalesced_flushes_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_bulk_coalesced_flushes_total %d\n", coalescedFlushes)

	cacheHits, cacheMisses := s.queryCache.Stats()
	sb.WriteString("# HELP doris_es_proxy_query_cache_hits_total Search requests served from the TTL query cache.\n")
	sb.WriteString("# TYPE doris_es_proxy_query_cache_hits_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_query_cache_hits_total %d\n", cacheHits)

	sb.WriteString("# HELP doris_es_proxy_query_cache_misses_total Search requests that missed the TTL query cache.\n")
	sb.WriteString("# TYPE doris_es_proxy_query_cache_misses_total counter\n")
	_, _ = fmt.Fprintf(&sb, "doris_es_proxy_query_cache_misses_total %d\n", cacheMisses)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

// handleTermsEnum implements `POST /{index}/_terms_enum` for Kibana / Grafana autocomplete.
func (s *Server) handleTermsEnum(w http.ResponseWriter, r *http.Request) {
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Field           string       `json:"field"`
		String          string       `json:"string,omitempty"`
		Size            int          `json:"size,omitempty"`
		CaseInsensitive bool         `json:"case_insensitive,omitempty"`
		SearchAfter     string       `json:"search_after,omitempty"`
		IndexFilter     *esast.Query `json:"index_filter,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if strings.TrimSpace(req.Field) == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "field must be specified for _terms_enum")
		return
	}
	limit := req.Size
	if limit <= 0 {
		limit = 10
	}
	zero := 0
	searchReq := esast.SearchRequest{
		Size:  &zero,
		Query: req.IndexFilter,
		Aggs: map[string]esast.AggSpec{
			"_terms_enum": {
				Terms: &esast.TermsAggSpec{
					Field: req.Field,
					Size:  1000,
					Order: map[string]any{"_key": "asc"},
				},
			},
		},
	}
	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), r.PathValue("index"), &searchReq)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	termsOut := make([]string, 0, limit)
	complete := true
	prefix := req.String
	prefixLower := strings.ToLower(prefix)
	if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
		if teObj, ok := aggsMap["_terms_enum"].(map[string]any); ok {
			if buckets, ok := teObj["buckets"].([]map[string]any); ok {
				allKeys := make([]string, 0, len(buckets))
				for _, b := range buckets {
					allKeys = append(allKeys, fmt.Sprintf("%v", b["key"]))
				}
				if req.CaseInsensitive {
					sort.Slice(allKeys, func(i, j int) bool {
						li, lj := strings.ToLower(allKeys[i]), strings.ToLower(allKeys[j])
						if li != lj {
							return li < lj
						}
						return allKeys[i] < allKeys[j]
					})
				}
				saLower := strings.ToLower(req.SearchAfter)
				for _, k := range allKeys {
					if req.SearchAfter != "" {
						if req.CaseInsensitive {
							kLower := strings.ToLower(k)
							if kLower < saLower || (kLower == saLower && k <= req.SearchAfter) {
								continue
							}
						} else if k <= req.SearchAfter {
							continue
						}
					}
					if prefix != "" {
						if req.CaseInsensitive {
							if !strings.HasPrefix(strings.ToLower(k), prefixLower) {
								continue
							}
						} else if !strings.HasPrefix(k, prefix) {
							continue
						}
					}
					if len(termsOut) >= limit {
						complete = false
						break
					}
					termsOut = append(termsOut, k)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards":  map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
		"terms":    termsOut,
		"complete": complete,
	})
}

// handleExplainDoc implements `GET/POST /{index}/_explain/{id}` and `GET/POST /{index}/_doc/{id}/_explain`.
func (s *Server) handleExplainDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(r.PathValue("index"))
	if readErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	docID := r.PathValue("id")
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req esast.SearchRequest
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	applyURISearchParams(r, &req)

	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	s.resolveTermsLookupsInQuery(r.Context(), aliasFilter)
	resolvedReq := s.resolveTermsLookupsInSearchRequest(r.Context(), &req)
	effQuery := combineQueryWithAliasFilter(resolvedReq.Query, aliasFilter)
	tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
	if _, err := tr.BuildSearchPlan(&esast.SearchRequest{Query: effQuery}); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if !found || hit == nil || (aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter)) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"_index":  indexName,
			"_type":   "_doc",
			"_id":     docID,
			"matched": false,
			"explanation": map[string]any{
				"value":       0.0,
				"description": "Failure to meet condition(s) of document/etti: no such document [" + docID + "]",
				"details":     []any{},
			},
		})
		return
	}

	matched := s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, effQuery)
	cq := tr.CompileQuery(effQuery, true, nil)
	scoreVal := 0.0
	desc := "no match on required clause (" + cq.WhereSQL + ")"
	if matched {
		scoreVal = 1.0
		if shreddedBytes, err := schema.ShredDocument(idxSchema, docID, hit.Version, false, hit.Source); err == nil {
			var row map[string]any
			dec := json.NewDecoder(bytes.NewReader(shreddedBytes))
			dec.UseNumber()
			if err := dec.Decode(&row); err == nil && row != nil {
				var docMap map[string]any
				docDec := json.NewDecoder(bytes.NewReader(hit.Source))
				docDec.UseNumber()
				if err := docDec.Decode(&docMap); err == nil {
					row["_doc"] = docMap
				}
				if evalScore := evalNumericExpr(row, cq.ScoreSQL); evalScore > 0 || cq.ScoreSQL == "0.0" {
					scoreVal = evalScore
				}
			}
		}
		if queryHasRuntimeScript(effQuery) {
			var docMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(hit.Source))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
			if docMap == nil {
				docMap = make(map[string]any)
			}
			scoreVal = evalQueryScriptScoreOnDocWithSchema(idxSchema, docMap, effQuery, scoreVal)
		}
		if resolvedReq.MinScore != nil && scoreVal < *resolvedReq.MinScore {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *resolvedReq.MinScore)
		} else if effQuery != nil && effQuery.ScriptScore != nil && effQuery.ScriptScore.MinScore != nil && scoreVal < *effQuery.ScriptScore.MinScore {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *effQuery.ScriptScore.MinScore)
		} else if effQuery != nil && effQuery.FunctionScore != nil && effQuery.FunctionScore.MinScore != nil && scoreVal < *effQuery.FunctionScore.MinScore {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *effQuery.FunctionScore.MinScore)
		} else {
			desc = "weight(" + cq.WhereSQL + ") [DorisInvertedIndex], result of: " + cq.ScoreSQL
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_index":  indexName,
		"_type":   "_doc",
		"_id":     docID,
		"matched": matched,
		"explanation": map[string]any{
			"value":       scoreVal,
			"description": desc,
			"details":     []any{},
		},
	})
}
