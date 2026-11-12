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
	// #nosec G501 -- Elasticsearch ingest fingerprint processor supports MD5
	"crypto/md5"
	// #nosec G505 -- Community ID v1 network flow hashing and ingest fingerprint processor support SHA-1
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
func matchMultiWildcardWithExclusions(rawPattern, candidate string) bool {
	if rawPattern == "" || rawPattern == "*" || rawPattern == "_all" {
		return true
	}
	parts := strings.Split(rawPattern, ",")
	matchedPos := false
	excluded := false
	for _, rawPart := range parts {
		p := strings.TrimSpace(rawPart)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "-") {
			neg := strings.TrimSpace(strings.TrimPrefix(p, "-"))
			if neg != "" && (neg == "_all" || matchWildcardPattern(neg, candidate)) {
				excluded = true
			}
			continue
		}
		if p == "_all" || matchWildcardPattern(p, candidate) {
			matchedPos = true
		}
	}
	return matchedPos && !excluded
}

func (s *Server) handleResolveIndex(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	pattern := r.PathValue("name")
	if pattern == "" {
		pattern = "*"
	}
	_ = s.syncCatalogFromBackend(r.Context())

	s.mu.RLock()
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
	idxNames := make([]string, 0, len(s.indices))
	for name := range s.indices {
		idxNames = append(idxNames, name)
	}
	sort.Strings(idxNames)
	ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
	concreteParts := make(map[string]bool)
	for _, rawPart := range strings.Split(pattern, ",") {
		part := strings.TrimSpace(rawPart)
		if part != "" && !strings.HasPrefix(part, "-") && !strings.ContainsAny(part, "*?") && part != "_all" {
			concreteParts[part] = true
		}
	}
	for _, name := range idxNames {
		if ew == "none" && !concreteParts[name] {
			continue
		}
		if matchMultiWildcardWithExclusions(pattern, name) {
			isClosed := s.closedIndices[name]
			if ew != "" {
				if ew == "open" && isClosed {
					continue
				}
				if ew == "closed" && !isClosed {
					continue
				}
			}
			var idxAliases []string
			for al, targets := range s.aliases {
				for _, t := range targets {
					if t == name {
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
			entry := map[string]any{
				"name":       name,
				"attributes": attrs,
				"state":      stateStr,
				"open":       isOpen,
			}
			if len(idxAliases) > 0 {
				entry["aliases"] = idxAliases
			}
			if dsName, ok := backingToDS[name]; ok {
				entry["data_stream"] = dsName
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
		if matchMultiWildcardWithExclusions(pattern, al) {
			aliasesOut = append(aliasesOut, map[string]any{
				"name":    al,
				"indices": append([]string(nil), s.aliases[al]...),
			})
		}
	}

	var dataStreamsOut []map[string]any
	dsNames := make([]string, 0, len(s.dataStreams))
	for dsName := range s.dataStreams {
		dsNames = append(dsNames, dsName)
	}
	sort.Strings(dsNames)
	for _, dsName := range dsNames {
		if matchMultiWildcardWithExclusions(pattern, dsName) {
			ds := s.dataStreams[dsName]
			if ds == nil {
				continue
			}
			backing := extractDataStreamBackingIndexNames(ds)
			tsField := "@timestamp"
			if tfMap, ok := ds["timestamp_field"].(map[string]any); ok {
				if nameStr, ok := tfMap["name"].(string); ok && nameStr != "" {
					tsField = nameStr
				}
			}
			dataStreamsOut = append(dataStreamsOut, map[string]any{
				"name":            dsName,
				"backing_indices": backing,
				"timestamp_field": tsField,
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
	if dataStreamsOut == nil {
		dataStreamsOut = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"indices":      indicesOut,
		"aliases":      aliasesOut,
		"data_streams": dataStreamsOut,
	})
}

func extractDataStreamBackingIndexNames(ds map[string]any) []string {
	var backing []string
	switch raw := ds["indices"].(type) {
	case []any:
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				if idxName, ok := m["index_name"].(string); ok && idxName != "" {
					backing = append(backing, idxName)
				}
			}
		}
	case []map[string]any:
		for _, m := range raw {
			if idxName, ok := m["index_name"].(string); ok && idxName != "" {
				backing = append(backing, idxName)
			}
		}
	}
	if backing == nil {
		backing = []string{}
	}
	return backing
}

// handleIndexStats implements `GET /_stats` and `GET /{index}/_stats` for Elasticvue, Cerebro, and monitoring clients.
func (s *Server) handleIndexStats(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	var targets []string
	var aliasFilters map[string]*esast.Query
	if rawIndex == "" {
		targets, aliasFilters = s.resolveTargetIndicesWithFilters("")
	} else {
		var ok bool
		targets, aliasFilters, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}

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
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := r.PathValue("index")
	var targets []string
	if rawIndex == "" {
		targets = s.resolveTargetIndices("")
	} else {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
		if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" {
			writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
			return
		}
	}
	indicesOut := make(map[string]any, len(targets))
	shardsOut := make([][]map[string]any, 0, len(targets))
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
	id := strings.TrimSpace(r.PathValue("id"))
	switch r.Method {
	case http.MethodPut:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: pipeline id is missing;")
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
		if body == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "[processors] required property is missing")
			return
		}
		if err := validateIngestPipelineSpec(body); err != nil {
			writeESError(w, http.StatusBadRequest, ingestSpecValidationErrorType(err), err.Error())
			return
		}
		s.mu.Lock()
		if s.pipelines == nil {
			s.pipelines = make(map[string]map[string]any)
		}
		s.pipelines[id] = body
		s.mu.Unlock()
		s.persistIngestPipeline(r.Context(), id, body)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		if id == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: pipeline id is missing;")
			return
		}
		_ = s.syncCatalogFromBackend(r.Context())
		parts := strings.Split(id, ",")
		s.mu.Lock()
		var toDelete []string
		deletedSet := make(map[string]bool)
		for _, rawPart := range parts {
			pat := strings.TrimSpace(rawPart)
			if pat == "" {
				continue
			}
			if pat == "*" || pat == "_all" {
				for k := range s.pipelines {
					if !deletedSet[k] {
						deletedSet[k] = true
						toDelete = append(toDelete, k)
					}
				}
				continue
			}
			if strings.Contains(pat, "*") {
				matchedAny := false
				for k := range s.pipelines {
					if matchWildcardPattern(pat, k) {
						matchedAny = true
						if !deletedSet[k] {
							deletedSet[k] = true
							toDelete = append(toDelete, k)
						}
					}
				}
				if !matchedAny {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "pipeline ["+pat+"] is missing")
					return
				}
				continue
			}
			if _, ok := s.pipelines[pat]; !ok {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "pipeline ["+pat+"] is missing")
				return
			}
			if !deletedSet[pat] {
				deletedSet[pat] = true
				toDelete = append(toDelete, pat)
			}
		}
		for _, k := range toDelete {
			delete(s.pipelines, k)
		}
		s.mu.Unlock()
		for _, k := range toDelete {
			s.deleteIngestPipelineCatalog(r.Context(), k)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet, http.MethodHead:
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.RLock()
		defer s.mu.RUnlock()
		if id == "" || id == "*" || id == "_all" {
			if r.Method == http.MethodHead {
				if len(s.pipelines) == 0 {
					w.WriteHeader(http.StatusNotFound)
				} else {
					w.WriteHeader(http.StatusOK)
				}
				return
			}
			out := make(map[string]any, len(s.pipelines))
			for k, v := range s.pipelines {
				out[k] = v
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		parts := strings.Split(id, ",")
		out := make(map[string]any)
		for _, rawPart := range parts {
			pat := strings.TrimSpace(rawPart)
			if pat == "" {
				continue
			}
			if pat == "*" || pat == "_all" {
				for k, v := range s.pipelines {
					out[k] = v
				}
				continue
			}
			if strings.Contains(pat, "*") {
				for k, v := range s.pipelines {
					if matchWildcardPattern(pat, k) {
						out[k] = v
					}
				}
				continue
			}
			p, ok := s.pipelines[pat]
			if !ok {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "pipeline ["+pat+"] is missing")
				return
			}
			out[pat] = p
		}
		if len(out) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "pipeline ["+id+"] is missing")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func isSupportedIngestProcessorType(procType string) bool {
	switch procType {
	case "drop", "fail", "pipeline", "dissect", "set", "default", "rename", "copy",
		"remove", "lowercase", "uppercase", "trim", "split", "join", "append",
		"convert", "gsub", "json", "kv", "dot_expander", "urlencode", "url_encode", "URLEncode",
		"urldecode", "url_decode", "URLDecode",
		"bytes", "html_strip", "date", "date_index_name", "grok", "sort", "compact",
		"dedup", "dedupe", "fingerprint", "redact", "attachment", "csv", "user_agent",
		"uri_parts", "registered_domain", "network_direction", "community_id",
		"geoip", "enrich", "foreach", "script", "inference", "set_security_user",
		"circle", "reroute", "terminate":
		return true
	}
	return false
}

func isEmptyIngestSetValue(v any) bool {
	if v == nil {
		return true
	}
	switch tv := v.(type) {
	case string:
		return tv == ""
	case []any:
		return len(tv) == 0
	case map[string]any:
		return len(tv) == 0
	}
	return false
}

func validateIngestPipelineProcessors(procs []any) error {
	for _, p := range procs {
		pm, ok := p.(map[string]any)
		if !ok {
			return fmt.Errorf("processor must be a map")
		}
		if rawTopOnFail, hasTopOnFail := pm["on_failure"]; hasTopOnFail && rawTopOnFail != nil {
			topOnFail, ok := rawTopOnFail.([]any)
			if !ok {
				return fmt.Errorf("[on_failure] property isn't a list")
			}
			if err := validateIngestPipelineProcessors(topOnFail); err != nil {
				return err
			}
		}
		procCount := 0
		for procType, rawSpec := range pm {
			switch procType {
			case "tag", "ignore_failure", "on_failure", "if", "description":
				continue
			}
			procCount++
			if !isSupportedIngestProcessorType(procType) {
				return fmt.Errorf("no processor type exists with name [%s]", procType)
			}
			specMap, ok := rawSpec.(map[string]any)
			if !ok || specMap == nil {
				return fmt.Errorf("[%s] config isn't a map", procType)
			}
			reqStr := func(prop string) (string, error) {
				val, ok := specMap[prop].(string)
				if !ok || strings.TrimSpace(val) == "" {
					return "", fmt.Errorf("[%s] required property is missing", prop)
				}
				return val, nil
			}
			switch procType {
			case "set":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				_, hasVal := specMap["value"]
				copyFrom, _ := specMap["copy_from"].(string)
				if !hasVal && strings.TrimSpace(copyFrom) == "" {
					return fmt.Errorf("either [value] or [copy_from] must be present")
				}
			case "default", "append":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				if _, hasVal := specMap["value"]; !hasVal {
					return fmt.Errorf("[value] required property is missing")
				}
			case "remove":
				isValidFieldOrSlice := func(raw any) bool {
					switch fv := raw.(type) {
					case string:
						return strings.TrimSpace(fv) != ""
					case []any:
						if len(fv) == 0 {
							return false
						}
						for _, el := range fv {
							if s, ok := el.(string); !ok || strings.TrimSpace(s) == "" {
								return false
							}
						}
						return true
					default:
						return false
					}
				}
				rawField, hasField := specMap["field"]
				rawKeep, hasKeep := specMap["keep"]
				if (!hasField || rawField == nil) && (!hasKeep || rawKeep == nil) {
					return fmt.Errorf("[field] required property is missing")
				}
				if hasField && rawField != nil && !isValidFieldOrSlice(rawField) {
					return fmt.Errorf("[field] required property is missing")
				}
				if hasKeep && rawKeep != nil && !isValidFieldOrSlice(rawKeep) {
					return fmt.Errorf("[keep] required property is invalid")
				}
			case "rename", "copy":
				f, err := reqStr("field")
				if err != nil {
					return err
				}
				tf, err := reqStr("target_field")
				if err != nil {
					return err
				}
				if f == tf && pm["on_failure"] == nil && specMap["on_failure"] == nil {
					return fmt.Errorf("illegal_argument_exception: source and target_field are the same: [%s]", f)
				}
			case "lowercase", "uppercase", "trim", "bytes", "html_strip", "dot_expander",
				"urlencode", "url_encode", "URLEncode", "urldecode", "url_decode", "URLDecode",
				"compact", "dedup", "dedupe", "attachment", "user_agent", "uri_parts",
				"registered_domain", "geoip", "set_security_user":
				if _, err := reqStr("field"); err != nil {
					return err
				}
			case "sort":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				if rawOrd, hasOrd := specMap["order"]; hasOrd && rawOrd != nil {
					ordStr, ok := rawOrd.(string)
					if !ok || (!strings.EqualFold(ordStr, "asc") && !strings.EqualFold(ordStr, "desc")) {
						return fmt.Errorf("illegal_argument_exception: sort order [%v] is invalid, must be [asc] or [desc]", rawOrd)
					}
				}
			case "split":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				sep, ok := specMap["separator"].(string)
				if !ok || sep == "" {
					return fmt.Errorf("[separator] required property is missing")
				}
				if sep != "|" && sep != "." && !strings.Contains(sep, "{{") {
					if _, err := compileIngestJavaRegex(sep); err != nil {
						return fmt.Errorf("illegal_argument_exception: invalid separator [%s]: %v", sep, err)
					}
				}
				if rawPT, hasPT := specMap["preserve_trailing"]; hasPT && rawPT != nil {
					if _, ok := rawPT.(bool); !ok {
						return fmt.Errorf("illegal_argument_exception: [preserve_trailing] must be a boolean")
					}
				}
			case "join":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				if _, ok := specMap["separator"].(string); !ok {
					return fmt.Errorf("[separator] required property is missing")
				}
			case "convert":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				convType, err := reqStr("type")
				if err != nil {
					return err
				}
				switch strings.ToLower(strings.TrimSpace(convType)) {
				case "integer", "int", "long", "short", "byte", "unsigned_long",
					"float", "double", "half_float", "scaled_float", "string",
					"boolean", "bool", "ip", "auto":
				default:
					return fmt.Errorf("illegal_argument_exception: type [%s] not supported", convType)
				}
			case "gsub":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				pat, err := reqStr("pattern")
				if err != nil {
					return err
				}
				if _, ok := specMap["replacement"].(string); !ok {
					return fmt.Errorf("[replacement] required property is missing")
				}
				if !strings.Contains(pat, "{{") {
					if _, err := compileIngestJavaRegex(pat); err != nil {
						return fmt.Errorf("illegal_argument_exception: invalid pattern [%s]: %v", pat, err)
					}
				}
			case "json":
				for k := range specMap {
					switch k {
					case "field", "target_field", "add_to_root", "add_to_root_conflict_strategy",
						"allow_duplicate_keys", "strict_json_parsing", "ignore_missing",
						"if", "tag", "description", "ignore_failure", "on_failure":
					default:
						return fmt.Errorf("[json] property [%s] isn't a configuration property", k)
					}
				}
				if _, err := reqStr("field"); err != nil {
					return err
				}
				for _, bKey := range []string{"add_to_root", "allow_duplicate_keys", "strict_json_parsing", "ignore_missing"} {
					if rawB, hasB := specMap[bKey]; hasB && rawB != nil {
						if _, ok := rawB.(bool); !ok {
							return fmt.Errorf("illegal_argument_exception: [%s] must be a boolean", bKey)
						}
					}
				}
				addToRoot, _ := specMap["add_to_root"].(bool)
				tf, _ := specMap["target_field"].(string)
				if addToRoot && strings.TrimSpace(tf) != "" {
					return fmt.Errorf("cannot specify both [target_field] and [add_to_root]")
				}
				if rawStrat, hasStrat := specMap["add_to_root_conflict_strategy"]; hasStrat && rawStrat != nil {
					if !addToRoot {
						return fmt.Errorf("illegal_argument_exception: cannot specify [add_to_root_conflict_strategy] when [add_to_root] is false")
					}
					stratStr, ok := rawStrat.(string)
					if !ok || (stratStr != "replace" && stratStr != "merge") {
						return fmt.Errorf("illegal_argument_exception: [add_to_root_conflict_strategy] must be [replace] or [merge], got [%v]", rawStrat)
					}
				}
			case "kv":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				fs, okFS := specMap["field_split"].(string)
				if !okFS || fs == "" {
					return fmt.Errorf("[field_split] required property is missing")
				}
				vs, okVS := specMap["value_split"].(string)
				if !okVS || vs == "" {
					return fmt.Errorf("[value_split] required property is missing")
				}
				if fs != "|" && fs != "." && fs != " " && fs != "," && fs != ";" && fs != "&" && !strings.Contains(fs, "{{") {
					if _, err := compileIngestJavaRegex(fs); err != nil {
						return fmt.Errorf("illegal_argument_exception: invalid field_split [%s]: %v", fs, err)
					}
				}
				if vs != "=" && vs != ":" && vs != "|" && vs != "." && !strings.Contains(vs, "{{") {
					if _, err := compileIngestJavaRegex(vs); err != nil {
						return fmt.Errorf("illegal_argument_exception: invalid value_split [%s]: %v", vs, err)
					}
				}
				rawInc, hasInc := specMap["include_keys"]
				rawExc, hasExc := specMap["exclude_keys"]
				if hasInc && rawInc != nil && hasExc && rawExc != nil {
					return fmt.Errorf("illegal_argument_exception: cannot specify both [include_keys] and [exclude_keys]")
				}
				if hasInc && rawInc != nil {
					incArr, ok := rawInc.([]any)
					if !ok {
						return fmt.Errorf("illegal_argument_exception: [include_keys] must be a list of strings")
					}
					for _, el := range incArr {
						if s, ok := el.(string); !ok || s == "" {
							return fmt.Errorf("illegal_argument_exception: [include_keys] must contain only non-empty strings")
						}
					}
				}
				if hasExc && rawExc != nil {
					excArr, ok := rawExc.([]any)
					if !ok {
						return fmt.Errorf("illegal_argument_exception: [exclude_keys] must be a list of strings")
					}
					for _, el := range excArr {
						if s, ok := el.(string); !ok || s == "" {
							return fmt.Errorf("illegal_argument_exception: [exclude_keys] must contain only non-empty strings")
						}
					}
				}
				if rawTK, hasTK := specMap["transform_key"]; hasTK && rawTK != nil {
					tkStr, ok := rawTK.(string)
					if !ok || (tkStr != "lowercase" && tkStr != "uppercase") {
						return fmt.Errorf("illegal_argument_exception: [transform_key] must be [lowercase] or [uppercase], got [%v]", rawTK)
					}
				}
			case "csv":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				tfs, ok := specMap["target_fields"].([]any)
				if !ok || len(tfs) == 0 {
					return fmt.Errorf("[target_fields] required property is missing")
				}
				for _, tfAny := range tfs {
					tfStr, ok := tfAny.(string)
					if !ok || strings.TrimSpace(tfStr) == "" {
						return fmt.Errorf("illegal_argument_exception: [target_fields] must contain only non-empty strings")
					}
				}
				effSep := ","
				if rawSep, hasSep := specMap["separator"]; hasSep && rawSep != nil {
					sep, ok := rawSep.(string)
					if !ok || utf8.RuneCountInString(sep) != 1 {
						return fmt.Errorf("illegal_argument_exception: separator must be a single character")
					}
					effSep = sep
				}
				effQuote := `"`
				if rawQ, hasQ := specMap["quote"]; hasQ && rawQ != nil {
					q, ok := rawQ.(string)
					if !ok || utf8.RuneCountInString(q) != 1 {
						return fmt.Errorf("illegal_argument_exception: quote must be a single character")
					}
					effQuote = q
				}
				if effSep == effQuote {
					return fmt.Errorf("illegal_argument_exception: separator and quote character cannot be the same [%s]", effSep)
				}
			case "date":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				fmts, ok := specMap["formats"].([]any)
				if !ok || len(fmts) == 0 {
					return fmt.Errorf("[formats] required property is missing")
				}
				for _, fAny := range fmts {
					fStr, ok := fAny.(string)
					if !ok || strings.TrimSpace(fStr) == "" {
						return fmt.Errorf("illegal_argument_exception: [formats] must contain only non-empty strings")
					}
				}
				if tz, ok := specMap["timezone"].(string); ok && tz != "" && !strings.Contains(tz, "{{") {
					if _, err := parseIngestTimezone(tz); err != nil {
						return err
					}
				}
			case "date_index_name":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				rounding, err := reqStr("date_rounding")
				if err != nil {
					return err
				}
				switch rounding {
				case "y", "M", "w", "d", "h", "m", "s":
				default:
					return fmt.Errorf("invalid date rounding [%s], valid values are [y, M, w, d, h, m, s]", rounding)
				}
				for _, fmtKey := range []string{"date_formats", "formats"} {
					if rawDF, hasDF := specMap[fmtKey]; hasDF && rawDF != nil {
						dfArr, ok := rawDF.([]any)
						if !ok || len(dfArr) == 0 {
							return fmt.Errorf("illegal_argument_exception: [%s] must be a non-empty list of strings", fmtKey)
						}
						for _, fAny := range dfArr {
							fStr, ok := fAny.(string)
							if !ok || strings.TrimSpace(fStr) == "" {
								return fmt.Errorf("illegal_argument_exception: [%s] must contain only non-empty strings", fmtKey)
							}
						}
					}
				}
				if tz, ok := specMap["timezone"].(string); ok && tz != "" && !strings.Contains(tz, "{{") {
					if _, err := parseIngestTimezone(tz); err != nil {
						return err
					}
				}
			case "dissect":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				pat, err := reqStr("pattern")
				if err != nil {
					return err
				}
				if strings.Count(pat, "%{") != strings.Count(pat, "}") {
					return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: unclosed token", pat)
				}
				for rem := pat; ; {
					openIdx := strings.Index(rem, "%{")
					if openIdx < 0 {
						break
					}
					afterOpen := rem[openIdx+2:]
					closeIdx := strings.IndexByte(afterOpen, '}')
					nextOpen := strings.Index(afterOpen, "%{")
					if closeIdx < 0 || (nextOpen >= 0 && nextOpen < closeIdx) {
						return fmt.Errorf("illegal_argument_exception: invalid dissect pattern [%s]: unclosed token", pat)
					}
					rem = afterOpen[closeIdx+1:]
				}
				if rawSep, hasSep := specMap["append_separator"]; hasSep && rawSep != nil {
					if _, ok := rawSep.(string); !ok {
						return fmt.Errorf("illegal_argument_exception: [append_separator] must be a string")
					}
				}
			case "grok", "redact":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				pats, ok := specMap["patterns"].([]any)
				if !ok || len(pats) == 0 {
					return fmt.Errorf("[patterns] required property is missing")
				}
				if rawECS, hasECS := specMap["ecs_compatibility"]; hasECS && rawECS != nil {
					ecsStr, ok := rawECS.(string)
					if !ok || (ecsStr != "disabled" && ecsStr != "v1") {
						return fmt.Errorf("illegal_argument_exception: invalid ecs_compatibility [%v], must be [disabled] or [v1]", rawECS)
					}
				}
				if rawKEC, hasKEC := specMap["keep_empty_captures"]; hasKEC && rawKEC != nil {
					if _, ok := rawKEC.(bool); !ok {
						return fmt.Errorf("illegal_argument_exception: [keep_empty_captures] must be a boolean")
					}
				}
				customDefs, _ := specMap["pattern_definitions"].(map[string]any)
				for _, patAny := range pats {
					patStr, ok := patAny.(string)
					if !ok || patStr == "" {
						return fmt.Errorf("illegal_argument_exception: pattern must be a non-empty string")
					}
					if _, _, _, err := compileGrokRegex(patStr, customDefs); err != nil {
						return fmt.Errorf("illegal_argument_exception: %v", err)
					}
				}
			case "fingerprint":
				rawFields, hasFields := specMap["fields"]
				rawExcl, hasExcl := specMap["exclude_fields"]
				var fieldsAny, exclAny []any
				if hasFields && rawFields != nil {
					var ok bool
					fieldsAny, ok = rawFields.([]any)
					if !ok || len(fieldsAny) == 0 {
						return fmt.Errorf("illegal_argument_exception: [fields] must not be empty")
					}
					for _, el := range fieldsAny {
						if s, ok := el.(string); !ok || strings.TrimSpace(s) == "" {
							return fmt.Errorf("illegal_argument_exception: [fields] must contain only non-empty strings")
						}
					}
				}
				if hasExcl && rawExcl != nil {
					var ok bool
					exclAny, ok = rawExcl.([]any)
					if !ok {
						return fmt.Errorf("illegal_argument_exception: [exclude_fields] must be a list of strings")
					}
					for _, el := range exclAny {
						if s, ok := el.(string); !ok || strings.TrimSpace(s) == "" {
							return fmt.Errorf("illegal_argument_exception: [exclude_fields] must contain only non-empty strings")
						}
					}
				}
				if (hasFields && rawFields != nil && hasExcl && rawExcl != nil) && (len(fieldsAny) > 0 || len(exclAny) > 0) {
					return fmt.Errorf("cannot specify both [fields] and [exclude_fields]")
				}
				if rawMethod, ok := specMap["method"].(string); ok && strings.TrimSpace(rawMethod) != "" {
					normMethod := normalizeFingerprintMethod(rawMethod)
					switch normMethod {
					case "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "MURMUR3":
					default:
						return fmt.Errorf("illegal_argument_exception: unsupported fingerprint method [%s]", rawMethod)
					}
				}
			case "fail":
				if _, ok := specMap["message"].(string); !ok {
					return fmt.Errorf("[message] required property is missing")
				}
			case "pipeline":
				if _, err := reqStr("name"); err != nil {
					return err
				}
			case "script":
				src, _ := specMap["source"].(string)
				inl, _ := specMap["inline"].(string)
				id, _ := specMap["id"].(string)
				if strings.TrimSpace(src) == "" && strings.TrimSpace(inl) == "" && strings.TrimSpace(id) == "" {
					return fmt.Errorf("must specify either [source] or [id]")
				}
			case "enrich":
				if _, err := reqStr("policy_name"); err != nil {
					return err
				}
				if _, err := reqStr("field"); err != nil {
					return err
				}
				if _, err := reqStr("target_field"); err != nil {
					return err
				}
				if rawMM, hasMM := specMap["max_matches"]; hasMM && rawMM != nil {
					mm, ok := toInt64(rawMM)
					if !ok || mm < 1 || mm > 128 {
						return fmt.Errorf("[max_matches] must be between 1 and 128")
					}
				}
			case "foreach":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				subProc, hasSubProc := specMap["processor"].(map[string]any)
				subProcs, hasSubProcs := specMap["processors"].([]any)
				if (!hasSubProc || subProc == nil) && (!hasSubProcs || len(subProcs) == 0) {
					return fmt.Errorf("[processor] required property is missing")
				}
				if hasSubProc && subProc != nil {
					if err := validateIngestPipelineProcessors([]any{subProc}); err != nil {
						return err
					}
				}
				if hasSubProcs {
					if err := validateIngestPipelineProcessors(subProcs); err != nil {
						return err
					}
				}
			case "inference":
				if _, err := reqStr("model_id"); err != nil {
					return err
				}
			case "circle":
				if _, err := reqStr("field"); err != nil {
					return err
				}
				rawED, hasED := specMap["error_distance"]
				if !hasED || rawED == nil {
					return fmt.Errorf("[error_distance] required property is missing")
				}
				edVal, ok := toFloat64(rawED)
				if !ok || edVal <= 0 {
					return fmt.Errorf("illegal_argument_exception: [error_distance] must be a positive number")
				}
				st, err := reqStr("shape_type")
				if err != nil {
					return err
				}
				if st != "geo_shape" && st != "shape" {
					return fmt.Errorf("illegal_argument_exception: invalid shape_type [%s], must be [geo_shape] or [shape]", st)
				}
			case "terminate":
				// Optional if/tag/description/ignore_failure/on_failure
			case "reroute":
				for k := range specMap {
					switch k {
					case "destination", "dataset", "namespace", "ignore_missing", "remove_fields",
						"if", "tag", "description", "ignore_failure", "on_failure":
					default:
						return fmt.Errorf("[reroute] property [%s] isn't a configuration property", k)
					}
				}
				rawDest, hasDest := specMap["destination"]
				rawDS, hasDS := specMap["dataset"]
				rawNS, hasNS := specMap["namespace"]
				if hasDest && rawDest != nil {
					destStr, ok := rawDest.(string)
					if !ok || strings.TrimSpace(destStr) == "" {
						return fmt.Errorf("illegal_argument_exception: [destination] must be a non-empty string")
					}
					if (hasDS && rawDS != nil) || (hasNS && rawNS != nil) {
						return fmt.Errorf("illegal_argument_exception: cannot specify both [destination] and [dataset]/[namespace]")
					}
				}
				validateReroutePartSpec := func(propName string, raw any) error {
					switch v := raw.(type) {
					case string:
						if !strings.Contains(v, "{{") && strings.Contains(v, "-") {
							return fmt.Errorf("illegal_argument_exception: [%s] cannot contain '-'", propName)
						}
					case []any:
						if len(v) == 0 {
							return fmt.Errorf("illegal_argument_exception: [%s] cannot be an empty list", propName)
						}
						for _, item := range v {
							sItem, ok := item.(string)
							if !ok || strings.TrimSpace(sItem) == "" {
								return fmt.Errorf("illegal_argument_exception: [%s] entries must be non-empty strings", propName)
							}
							if !strings.Contains(sItem, "{{") && strings.Contains(sItem, "-") {
								return fmt.Errorf("illegal_argument_exception: [%s] cannot contain '-'", propName)
							}
						}
					default:
						return fmt.Errorf("illegal_argument_exception: [%s] must be a string or list of strings", propName)
					}
					return nil
				}
				if hasDS && rawDS != nil {
					if err := validateReroutePartSpec("dataset", rawDS); err != nil {
						return err
					}
				}
				if hasNS && rawNS != nil {
					if err := validateReroutePartSpec("namespace", rawNS); err != nil {
						return err
					}
				}
				for _, bKey := range []string{"ignore_missing", "remove_fields"} {
					if rawB, hasB := specMap[bKey]; hasB && rawB != nil {
						if _, ok := rawB.(bool); !ok {
							return fmt.Errorf("illegal_argument_exception: [%s] must be a boolean", bKey)
						}
					}
				}
			case "community_id":
				if rawSeed, hasSeed := specMap["seed"]; hasSeed && rawSeed != nil {
					var seedInt int64
					validSeed := false
					switch sv := rawSeed.(type) {
					case int:
						seedInt = int64(sv)
						validSeed = true
					case int64:
						seedInt = sv
						validSeed = true
					case float64:
						if sv == math.Trunc(sv) {
							seedInt = int64(sv)
							validSeed = true
						}
					}
					if !validSeed || seedInt < 0 || seedInt > 65535 {
						return fmt.Errorf("illegal_argument_exception: [seed] must be an integer between 0 and 65535, got [%v]", rawSeed)
					}
				}
			case "network_direction":
				if rawNets, hasNets := specMap["internal_networks"]; hasNets && rawNets != nil {
					netsArr, ok := rawNets.([]any)
					if !ok || len(netsArr) == 0 {
						return fmt.Errorf("illegal_argument_exception: [internal_networks] must be a non-empty list of network ranges or CIDRs")
					}
					for _, el := range netsArr {
						ns, ok := el.(string)
						if !ok || strings.TrimSpace(ns) == "" {
							return fmt.Errorf("illegal_argument_exception: [internal_networks] entries must be non-empty strings")
						}
						norm := strings.ToLower(strings.TrimSpace(ns))
						switch norm {
						case "private", "loopback", "link_local", "multicast", "unspecified",
							"iana_private", "rfc1918", "rfc6598", "carrier_grade_nat":
						default:
							if strings.Contains(norm, "{{") {
								continue
							}
							if _, cidr, err := net.ParseCIDR(norm); err == nil && cidr != nil {
								continue
							}
							if ip := net.ParseIP(norm); ip != nil {
								continue
							}
							return fmt.Errorf("illegal_argument_exception: invalid network range or CIDR [%s] in [internal_networks]", ns)
						}
					}
				}
			}
			if rawOnFail, hasOnFail := specMap["on_failure"]; hasOnFail && rawOnFail != nil {
				onFail, ok := rawOnFail.([]any)
				if !ok {
					return fmt.Errorf("[on_failure] property isn't a list")
				}
				if err := validateIngestPipelineProcessors(onFail); err != nil {
					return err
				}
			}
		}
		if procCount == 0 {
			return fmt.Errorf("processor doesn't specify type")
		}
		if procCount > 1 {
			return fmt.Errorf("processor cannot specify more than one type")
		}
	}
	return nil
}

func validateIngestPipelineSpec(body map[string]any) error {
	rawProcs, hasProcs := body["processors"]
	if !hasProcs {
		return fmt.Errorf("[processors] required property is missing")
	}
	procs, ok := rawProcs.([]any)
	if !ok {
		return fmt.Errorf("[processors] property isn't a list")
	}
	if err := validateIngestPipelineProcessors(procs); err != nil {
		return err
	}
	if rawOnFail, hasOnFail := body["on_failure"]; hasOnFail && rawOnFail != nil {
		onFail, ok := rawOnFail.([]any)
		if !ok {
			return fmt.Errorf("[on_failure] property isn't a list")
		}
		if err := validateIngestPipelineProcessors(onFail); err != nil {
			return err
		}
	}
	return nil
}

func ingestSpecValidationErrorType(err error) string {
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "must be between") || strings.Contains(msg, "invalid date rounding") || strings.Contains(msg, "illegal_argument_exception") {
			return "illegal_argument_exception"
		}
	}
	return "parse_exception"
}

func ingestErrorType(err error) string {
	if err != nil && (strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "must be between") || strings.Contains(err.Error(), "illegal_argument_exception")) {
		return "illegal_argument_exception"
	}
	return "ingest_processor_exception"
}

func (s *Server) applyIngestPipelineForWriteWithRoutingAndIngestMeta(pipelineID, indexName, docID, initialRouting string, raw json.RawMessage, initialIngestMeta map[string]any) (json.RawMessage, string, string, string, bool, map[string]any, error) {
	if pipelineID == "" || pipelineID == "_none" {
		return raw, indexName, docID, initialRouting, false, initialIngestMeta, nil
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
		return raw, indexName, docID, initialRouting, false, initialIngestMeta, fmt.Errorf("pipeline with id [%s] does not exist", pipelineID)
	}
	out, outIdx, outID, _, outRouting, dropped, _, outIngestMeta, err := applyIngestPipelineSpecWithNameAndRoutingAndIngestMeta(s, pipe, pipelineID, indexName, docID, initialRouting, raw, false, initialIngestMeta)
	return out, outIdx, outID, outRouting, dropped, outIngestMeta, err
}

func (s *Server) applyEffectiveAndFinalPipelinesWithRouting(indexName, docID, reqPipeline, defaultPipeline, initialRouting string, raw json.RawMessage) (json.RawMessage, string, string, string, bool, error) {
	effPipeline := s.resolveEffectivePipeline(indexName, reqPipeline, defaultPipeline)
	if effPipeline == "" && s != nil {
		if resolved, _, wErr := s.resolveWriteIndexWithFilter(indexName); wErr == nil && resolved != "" && resolved != indexName {
			effPipeline = s.resolveEffectivePipeline(resolved, reqPipeline, defaultPipeline)
		}
	}
	cur := raw
	curIndex := indexName
	curID := docID
	curRouting := initialRouting
	var curIngestMeta map[string]any
	if effPipeline != "" {
		next, nextIdx, nextID, nextRouting, dropped, nextIngestMeta, err := s.applyIngestPipelineForWriteWithRoutingAndIngestMeta(effPipeline, curIndex, curID, curRouting, cur, nil)
		if err != nil || dropped {
			return next, nextIdx, nextID, nextRouting, dropped, err
		}
		cur = next
		if nextIdx != "" {
			curIndex = nextIdx
		}
		if nextID != "" {
			curID = nextID
		}
		curRouting = nextRouting
		curIngestMeta = nextIngestMeta
	}
	if curIndex != indexName && reqPipeline != "_none" && defaultPipeline != "_none" {
		destDef := s.resolveEffectivePipeline(curIndex, "", "")
		if destDef == "" && s != nil {
			if resolved, _, wErr := s.resolveWriteIndexWithFilter(curIndex); wErr == nil && resolved != "" && resolved != curIndex {
				destDef = s.resolveEffectivePipeline(resolved, "", "")
			}
			if destDef == "" {
				if resolved := s.resolveIndexName(curIndex); resolved != "" && resolved != curIndex {
					destDef = s.resolveEffectivePipeline(resolved, "", "")
				}
			}
		}
		if destDef != "" && destDef != effPipeline {
			next, nextIdx, nextID, nextRouting, dropped, nextIngestMeta, err := s.applyIngestPipelineForWriteWithRoutingAndIngestMeta(destDef, curIndex, curID, curRouting, cur, curIngestMeta)
			if err != nil || dropped {
				return next, nextIdx, nextID, nextRouting, dropped, err
			}
			cur = next
			if nextIdx != "" {
				curIndex = nextIdx
			}
			if nextID != "" {
				curID = nextID
			}
			curRouting = nextRouting
			curIngestMeta = nextIngestMeta
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
		next, nextIdx, nextID, nextRouting, dropped, _, err := s.applyIngestPipelineForWriteWithRoutingAndIngestMeta(finalPipeline, curIndex, curID, curRouting, cur, curIngestMeta)
		if err != nil || dropped {
			return next, nextIdx, nextID, nextRouting, dropped, err
		}
		cur = next
		if nextIdx != "" {
			curIndex = nextIdx
		}
		if nextID != "" {
			curID = nextID
		}
		curRouting = nextRouting
	}
	return cur, curIndex, curID, curRouting, false, nil
}

func isIngestIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '@' || c == '-'
}

func isRegexStartContext(s string, slashIdx int) bool {
	j := slashIdx - 1
	for j >= 0 && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
		j--
	}
	if j < 0 {
		return true
	}
	switch s[j] {
	case '~', '=', '(', ',', '!', '&', '|', '?', ':', '[', '{', ';':
		return true
	}
	return false
}

func scanRegexLiteralEnd(s string, slashIdx int) int {
	inClass := false
	for i := slashIdx + 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if c == '\n' || c == '\r' {
			return -1
		}
		if c == '[' {
			inClass = true
		} else if c == ']' {
			inClass = false
		} else if c == '/' && !inClass {
			return i
		}
	}
	return -1
}

func rewriteIngestCtxReferences(s string) string {
	return rewriteIngestCtxReferencesWithOp(s, true)
}

func rewriteIngestCtxReferencesWithOp(s string, preserveOp bool) string {
	var out strings.Builder
	out.Grow(len(s) + 16)
	inQuotes := byte(0)
	directKws := []string{"_source", "_now", "_index", "_id", "_routing", "_version"}
	if preserveOp {
		directKws = append(directKws, "op")
	}
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
		if c == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				nl := strings.IndexByte(s[i+2:], '\n')
				if nl < 0 {
					out.WriteString(s[i:])
					break
				}
				out.WriteString(s[i : i+2+nl+1])
				i += 2 + nl
				continue
			}
			if s[i+1] == '*' {
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					out.WriteString(s[i:])
					break
				}
				out.WriteString(s[i : i+2+end+2])
				i += 2 + end + 1
				continue
			}
			if isRegexStartContext(s, i) {
				if endSlash := scanRegexLiteralEnd(s, i); endSlash > i {
					out.WriteString(s[i : endSlash+1])
					i = endSlash
					continue
				}
			}
		}
		if (i == 0 || (!isIngestIdentByte(s[i-1]) && s[i-1] != '.')) && strings.HasPrefix(s[i:], "ctx") {
			rest := s[i+3:]
			isDirectDot := func(after string) bool {
				for _, kw := range directKws {
					if strings.HasPrefix(after, kw) && (len(after) == len(kw) || !isIngestIdentByte(after[len(kw)])) {
						return true
					}
				}
				mapMethods := []string{
					"putIfAbsent", "putAll", "put", "remove",
					"getOrDefault", "get", "containsKey", "containsValue",
					"clear", "replaceAll", "replace", "isEmpty", "size",
					"keySet", "values", "entrySet", "forEach",
					"computeIfAbsent", "computeIfPresent", "compute", "merge",
				}
				for _, mm := range mapMethods {
					if strings.HasPrefix(after, mm) {
						rem := strings.TrimSpace(after[len(mm):])
						if strings.HasPrefix(rem, "(") {
							return true
						}
					}
				}
				return false
			}
			isDirectBracket := func(after string) bool {
				for _, kw := range directKws {
					if strings.HasPrefix(after, "'"+kw+"'") || strings.HasPrefix(after, `"`+kw+`"`) {
						return true
					}
				}
				return false
			}
			tryChainedGet := func(after string) (string, int, bool) {
				if !strings.HasPrefix(after, "get") || (len(after) > 3 && isIngestIdentByte(after[3])) {
					return "", 0, false
				}
				idx := 3
				for idx < len(after) && (after[idx] == ' ' || after[idx] == '\t') {
					idx++
				}
				if idx >= len(after) || after[idx] != '(' {
					return "", 0, false
				}
				idx++
				for idx < len(after) && (after[idx] == ' ' || after[idx] == '\t') {
					idx++
				}
				if idx >= len(after) || (after[idx] != '\'' && after[idx] != '"') {
					return "", 0, false
				}
				qChar := after[idx]
				litStart := idx
				idx++
				var keyBuf strings.Builder
				for idx < len(after) {
					if after[idx] == '\\' && idx+1 < len(after) {
						keyBuf.WriteByte(after[idx+1])
						idx += 2
						continue
					}
					if after[idx] == qChar {
						break
					}
					keyBuf.WriteByte(after[idx])
					idx++
				}
				if idx >= len(after) || after[idx] != qChar {
					return "", 0, false
				}
				rawQuoted := after[litStart : idx+1]
				idx++
				for idx < len(after) && (after[idx] == ' ' || after[idx] == '\t') {
					idx++
				}
				if idx >= len(after) || after[idx] != ')' {
					return "", 0, false
				}
				closeParenEnd := idx + 1
				litKey := keyBuf.String()
				for _, kw := range directKws {
					if litKey == kw {
						return "", 0, false
					}
				}
				remAfterParen := strings.TrimLeft(after[closeParenEnd:], " \t")
				if strings.HasPrefix(remAfterParen, ".") || strings.HasPrefix(remAfterParen, "?.") || strings.HasPrefix(remAfterParen, "[") || strings.HasPrefix(remAfterParen, "?[") {
					return rawQuoted, closeParenEnd, true
				}
				return "", 0, false
			}
			if strings.HasPrefix(rest, "?.") {
				after := rest[2:]
				if rawLit, endOff, okG := tryChainedGet(after); okG {
					out.WriteString("ctx?._source[" + rawLit + "]")
					i += 4 + endOff
					continue
				}
				if !isDirectDot(after) {
					out.WriteString("ctx?._source.")
					i += 4
					continue
				}
			} else if strings.HasPrefix(rest, ".") {
				after := rest[1:]
				if rawLit, endOff, okG := tryChainedGet(after); okG {
					out.WriteString("ctx._source[" + rawLit + "]")
					i += 3 + endOff
					continue
				}
				if !isDirectDot(after) {
					out.WriteString("ctx._source.")
					i += 3
					continue
				}
			} else if strings.HasPrefix(rest, "?[") {
				after := strings.TrimSpace(rest[2:])
				if !isDirectBracket(after) {
					out.WriteString("ctx?._source[")
					i += 4
					continue
				}
			} else if strings.HasPrefix(rest, "[") {
				after := strings.TrimSpace(rest[1:])
				if !isDirectBracket(after) {
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

func hasTopLevelSemicolonOrReturn(s string) bool {
	trimmed := strings.TrimSpace(s)
	for _, kw := range []string{"return", "if", "for", "while", "switch", "try", "do", "def", "int", "long", "double", "float", "boolean", "String", "List", "Map", "Set", "Object"} {
		if strings.HasPrefix(trimmed, kw) && (len(trimmed) == len(kw) || trimmed[len(kw)] == ' ' || trimmed[len(kw)] == '\t' || trimmed[len(kw)] == '\n' || trimmed[len(kw)] == '(' || trimmed[len(kw)] == '{' || trimmed[len(kw)] == ';') {
			return true
		}
	}
	inQuotes := byte(0)
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes != 0 {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == inQuotes {
				inQuotes = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuotes = c
			continue
		}
		if c == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				nl := strings.IndexByte(s[i+2:], '\n')
				if nl < 0 {
					break
				}
				i += 2 + nl
				continue
			}
			if s[i+1] == '*' {
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					break
				}
				i += 2 + end + 1
				continue
			}
			if isRegexStartContext(s, i) {
				if endSlash := scanRegexLiteralEnd(s, i); endSlash > i {
					i = endSlash
					continue
				}
			}
		}
		if (i == 0 || (!isIngestIdentByte(s[i-1]) && s[i-1] != '.')) && strings.HasPrefix(s[i:], "return") && (i+6 == len(s) || !isIngestIdentByte(s[i+6])) {
			return true
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';', '\n':
			if depth == 0 && strings.TrimSpace(s[i+1:]) != "" {
				return true
			}
		}
	}
	return false
}

func ingestMetaParamsFromDoc(doc map[string]any) map[string]any {
	if doc == nil {
		return nil
	}
	params := make(map[string]any, 4)
	if v, ok := doc["_index"]; ok && v != nil {
		params["_ctx_index"] = v
	}
	if v, ok := doc["_id"]; ok && v != nil {
		params["_ctx_id"] = v
	}
	if v, ok := doc["_routing"]; ok && v != nil {
		params["_ctx_routing"] = v
	}
	if v, ok := doc["_version"]; ok && v != nil {
		params["_ctx_version"] = v
	}
	return params
}

func evalIngestIfCondition(cond string, doc map[string]any) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return true
	}
	normCond := strings.TrimSpace(rewriteIngestCtxReferences(cond))
	metaParams := ingestMetaParamsFromDoc(doc)
	origMetaMap, _ := doc["__internal_ingest_orig"].(map[string]any)
	hadUserIndex, _ := origMetaMap["_had_orig_index"].(bool)
	hadUserID, _ := origMetaMap["_had_orig_id"].(bool)
	hadUserRouting, _ := origMetaMap["_had_orig_routing"].(bool)
	cleanDoc := make(map[string]any, len(doc))
	for k, v := range doc {
		switch k {
		case "__internal_ingest_orig", "__internal_ingest_terminated", "__internal_ingest_rerouted", "_version":
			continue
		case "_ingest":
			cleanDoc["_ingest"] = deepCloneIngestValue(v)
			continue
		case "_index":
			if !hadUserIndex {
				continue
			}
		case "_id":
			if !hadUserID {
				continue
			}
		case "_routing":
			if !hadUserRouting {
				continue
			}
		}
		cleanDoc[k] = v
	}
	if hasTopLevelSemicolonOrReturn(normCond) {
		ok, err := painless.EvalFilter(cleanDoc, normCond, metaParams)
		return err == nil && ok
	}
	normCond = strings.TrimSuffix(normCond, ";")
	script := "if (" + normCond + "\n) { ctx.op = 'index' } else { ctx.op = 'noop' }"
	opRes, err := painless.EvalPainlessWithOp(cleanDoc, script, metaParams)
	if err != nil {
		ok, fErr := painless.EvalFilter(cleanDoc, normCond, metaParams)
		return fErr == nil && ok
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
	"UNIXPATH":          `(?:/[\w_%!$@:.,+~-]+|\\.)+`,
	"WINPATH":           `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`,
	"PATH":              `(?:(?:/[\w_%!$@:.,+~-]+|\\.)+|(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+)`,
	"HOSTPORT":          `%{IPORHOST}:%{POSINT}`,
	"TTY":               `(?:/dev/(?:pts|tty(?:[pq])?)(?:\w+)?/?(?:[0-9]+))`,
	"BASE16NUM":         `\b0[xX][0-9a-fA-F]+\b`,
	"BASE16FLOAT":       `\b(?:[+-]?(?:0[xX])?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b`,
	"URIPARAM":          `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`,
	"URIPATHPARAM":      `%{URIPATH}(?:%{URIPARAM})?`,
	"URI":               `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`,
	"COMMONAPACHELOG":   `%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`,
	"COMBINEDAPACHELOG": `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`,
	"EMAILADDRESS":      `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`,
}

var ecsGrokPatterns = map[string]string{
	"COMMONAPACHELOG":   `%{IPORHOST:[client][address]} %{USER:[user][id]} %{USER:[user][name]} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:[http][request][method]} %{NOTSPACE:[url][original]}(?: HTTP/%{NUMBER:[http][version]})?|%{DATA})" %{NUMBER:[http][response][status_code]:int} (?:%{NUMBER:[http][response][body][bytes]:long}|-)`,
	"COMBINEDAPACHELOG": `%{COMMONAPACHELOG} %{QS:[http][request][referrer]} %{QS:[user_agent][original]}`,
}

var (
	reGrokToken        = regexp.MustCompile(`%\{([A-Za-z0-9_]+)(?::([A-Za-z0-9_.\-\[\]@]+))?(?::(int|integer|long|float|double|boolean|bool|string))?\}`)
	reGrokNamedCapture = regexp.MustCompile(`\(\?P?<([A-Za-z0-9_.\-\[\]@]+)(?::(int|integer|long|float|double|boolean|bool|string))?>`)
)

func compileIngestJavaRegex(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.Grow(len(pattern) + 8)
	inClass := false
	classStart := 0
	for i := 0; i < len(pattern); {
		ch := pattern[i]
		if ch == '\\' {
			if i+1 < len(pattern) {
				b.WriteByte('\\')
				b.WriteByte(pattern[i+1])
				i += 2
				continue
			}
			b.WriteByte('\\')
			i++
			continue
		}
		if inClass {
			if ch == ']' && (i > classStart+1 || (i == classStart+1 && pattern[classStart] != '^')) {
				// Note: '[]' or '[^]' at the start of a character class keeps ']' literal.
				if i != classStart+1 && (i != classStart+2 || pattern[classStart+1] != '^') {
					inClass = false
				}
			}
			b.WriteByte(ch)
			i++
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = i
			b.WriteByte('[')
			i++
			continue
		}
		if ch == '(' && i+3 < len(pattern) && pattern[i+1] == '?' && pattern[i+2] == '<' && pattern[i+3] != '=' && pattern[i+3] != '!' {
			b.WriteString("(?P<")
			i += 3
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return regexp.Compile(b.String())
}

func applyIngestGsubReplacement(re *regexp.Regexp, src, repl string) (string, error) {
	type replToken struct {
		lit      string
		groupIdx int // -1 for literal
	}
	numGroups := re.NumSubexp()
	nameToIdx := make(map[string]int)
	for idx, name := range re.SubexpNames() {
		if idx > 0 && name != "" {
			nameToIdx[name] = idx
		}
	}
	var tokens []replToken
	var litBuf strings.Builder
	flushLit := func() {
		if litBuf.Len() > 0 {
			tokens = append(tokens, replToken{lit: litBuf.String(), groupIdx: -1})
			litBuf.Reset()
		}
	}
	for cursor := 0; cursor < len(repl); {
		ch := repl[cursor]
		if ch == '\\' {
			cursor++
			if cursor >= len(repl) {
				return "", fmt.Errorf("illegal_argument_exception: character to be escaped is missing")
			}
			litBuf.WriteByte(repl[cursor])
			cursor++
			continue
		}
		if ch == '$' {
			flushLit()
			cursor++
			if cursor >= len(repl) {
				return "", fmt.Errorf("illegal_argument_exception: illegal group reference: group index is missing")
			}
			if repl[cursor] == '{' {
				cursor++
				gs := cursor
				for cursor < len(repl) && repl[cursor] != '}' {
					cursor++
				}
				if cursor >= len(repl) {
					return "", fmt.Errorf("illegal_argument_exception: named capturing group is missing trailing '}'")
				}
				gname := repl[gs:cursor]
				cursor++
				if gname == "" {
					return "", fmt.Errorf("illegal_argument_exception: named capturing group has 0 length name")
				}
				gIdx, ok := nameToIdx[gname]
				if !ok {
					return "", fmt.Errorf("illegal_argument_exception: No group with name {%s}", gname)
				}
				tokens = append(tokens, replToken{groupIdx: gIdx})
				continue
			}
			if repl[cursor] >= '0' && repl[cursor] <= '9' {
				refNum := int(repl[cursor] - '0')
				cursor++
				if refNum > numGroups {
					return "", fmt.Errorf("index_out_of_bounds_exception: No group %d", refNum)
				}
				for cursor < len(repl) && repl[cursor] >= '0' && repl[cursor] <= '9' {
					nextRefNum := refNum*10 + int(repl[cursor]-'0')
					if nextRefNum > numGroups {
						break
					}
					refNum = nextRefNum
					cursor++
				}
				tokens = append(tokens, replToken{groupIdx: refNum})
				continue
			}
			// Preserve literal uppercase currency tokens like "$USD" (Round 38 backward compatibility)
			// while rejecting bare '$', '$foo', '$$', '$-', etc. per Java Matcher.replaceAll.
			if repl[cursor] >= 'A' && repl[cursor] <= 'Z' {
				endUpper := cursor
				for endUpper < len(repl) && repl[endUpper] >= 'A' && repl[endUpper] <= 'Z' {
					endUpper++
				}
				if endUpper-cursor >= 2 && (endUpper == len(repl) || !isIngestIdentByte(repl[endUpper])) {
					litBuf.WriteByte('$')
					continue
				}
			}
			return "", fmt.Errorf("illegal_argument_exception: illegal group reference")
		}
		litBuf.WriteByte(ch)
		cursor++
	}
	flushLit()

	matches := re.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return src, nil
	}
	var out strings.Builder
	out.Grow(len(src) + 16)
	lastEnd := 0
	for _, loc := range matches {
		out.WriteString(src[lastEnd:loc[0]])
		for _, tok := range tokens {
			if tok.groupIdx < 0 {
				out.WriteString(tok.lit)
				continue
			}
			sIdx := loc[2*tok.groupIdx]
			eIdx := loc[2*tok.groupIdx+1]
			if sIdx >= 0 && eIdx >= sIdx {
				out.WriteString(src[sIdx:eIdx])
			}
		}
		lastEnd = loc[1]
	}
	out.WriteString(src[lastEnd:])
	return out.String(), nil
}

func deepCloneIngestValue(val any) any {
	switch tv := val.(type) {
	case map[string]any:
		cp := make(map[string]any, len(tv))
		for k, v := range tv {
			cp[k] = deepCloneIngestValue(v)
		}
		return cp
	case []any:
		cp := make([]any, len(tv))
		for i, v := range tv {
			cp[i] = deepCloneIngestValue(v)
		}
		return cp
	default:
		return val
	}
}

func normalizeGrokFieldName(fieldName string) string {
	if !strings.Contains(fieldName, "[") {
		return fieldName
	}
	s := strings.TrimSpace(fieldName)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	s = strings.ReplaceAll(s, "][", ".")
	s = strings.ReplaceAll(s, "[", ".")
	s = strings.ReplaceAll(s, "]", "")
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	return strings.Trim(s, ".")
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
	expanded = reGrokNamedCapture.ReplaceAllStringFunc(expanded, func(m string) string {
		sub := reGrokNamedCapture.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		if _, exists := groupKeyMap[sub[1]]; exists && sub[2] == "" && strings.HasPrefix(m, "(?P<") {
			return m
		}
		groupSeq++
		grpID := fmt.Sprintf("g%d", groupSeq)
		groupKeyMap[grpID] = normalizeGrokFieldName(sub[1])
		if len(sub) >= 3 && sub[2] != "" {
			groupTypes[grpID] = sub[2]
		}
		return fmt.Sprintf("(?P<%s>", grpID)
	})
	re, err := regexp.Compile(expanded)
	if err != nil {
		return nil, nil, nil, err
	}
	return re, groupKeyMap, groupTypes, nil
}

func convertESDateFormatToGoLayouts(esFmt string) []string {
	switch esFmt {
	case "ISO8601", "strict_date_optional_time", "date_optional_time", "strict_date_optional_time_nanos":
		return []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999Z0700",
			"2006-01-02T15:04:05Z0700",
			"2006-01-02T15:04:05.000Z0700",
			"2006-01-02T15:04:05.000Z07:00",
			"2006-01-02T15:04:05,000Z0700",
			"2006-01-02T15:04:05,000Z07:00",
			"2006-01-02T15:04:05,999999999Z07:00",
			"2006-01-02T15:04:05,999999999Z0700",
			"2006-01-02T15:04:05.000",
			"2006-01-02T15:04:05,000",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
	case "UNIX", "epoch_second":
		return []string{"UNIX"}
	case "UNIX_MS", "epoch_millis":
		return []string{"UNIX_MS"}
	case "TAI64N", "tai64n":
		return []string{"TAI64N"}
	case "ordinal_date", "strict_ordinal_date":
		return []string{
			"2006-002T15:04:05.999999999Z07:00",
			"2006-002T15:04:05.999999999Z0700",
			"2006-002T15:04:05Z07:00",
			"2006-002T15:04:05Z0700",
			"2006-002T15:04:05",
			"2006-002Z07:00",
			"2006-002Z0700",
			"2006-002",
		}
	case "ordinal_date_no_millis", "strict_ordinal_date_no_millis":
		return []string{
			"2006-002T15:04:05Z07:00",
			"2006-002T15:04:05Z0700",
			"2006-002T15:04:05",
			"2006-002Z07:00",
			"2006-002Z0700",
			"2006-002",
		}
	case "ordinal_date_time", "strict_ordinal_date_time":
		return []string{
			"2006-002T15:04:05.999999999Z07:00",
			"2006-002T15:04:05.999999999Z0700",
			"2006-002T15:04:05.000Z07:00",
			"2006-002T15:04:05.000Z0700",
		}
	case "ordinal_date_time_no_millis", "strict_ordinal_date_time_no_millis":
		return []string{
			"2006-002T15:04:05Z07:00",
			"2006-002T15:04:05Z0700",
			"2006-002T15:04:05",
		}
	case "basic_ordinal_date", "strict_basic_ordinal_date":
		return []string{"2006002Z0700", "2006002Z07:00", "2006002"}
	case "basic_ordinal_date_time", "strict_basic_ordinal_date_time":
		return []string{
			"2006002T150405.999999999Z0700",
			"2006002T150405.999999999Z07:00",
			"2006002T150405.000Z0700",
			"2006002T150405.000Z07:00",
		}
	case "basic_ordinal_date_time_no_millis", "strict_basic_ordinal_date_time_no_millis":
		return []string{"2006002T150405Z0700", "2006002T150405Z07:00", "2006002T150405"}
	case "basic_date", "strict_basic_date":
		return []string{"20060102"}
	case "basic_date_time", "strict_basic_date_time":
		return []string{
			"20060102T150405.000Z0700",
			"20060102T150405.000Z07:00",
			"20060102T150405.999999999Z0700",
			"20060102T150405.999999999Z07:00",
		}
	case "basic_date_time_no_millis", "strict_basic_date_time_no_millis":
		return []string{
			"20060102T150405Z0700",
			"20060102T150405Z07:00",
		}
	case "date", "strict_date", "year_month_day", "strict_year_month_day":
		return []string{"2006-01-02"}
	case "date_time", "strict_date_time":
		return []string{
			time.RFC3339Nano,
			"2006-01-02T15:04:05.000Z07:00",
			"2006-01-02T15:04:05.000Z0700",
			"2006-01-02T15:04:05.999999999Z0700",
		}
	case "date_time_no_millis", "strict_date_time_no_millis":
		return []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05Z0700",
			"2006-01-02T15:04:05",
		}
	case "date_hour_minute_second", "strict_date_hour_minute_second":
		return []string{"2006-01-02T15:04:05"}
	case "date_hour_minute_second_millis", "strict_date_hour_minute_second_millis", "date_hour_minute_second_fraction", "strict_date_hour_minute_second_fraction":
		return []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05.999999999"}
	case "rfc_1123_date_time":
		return []string{
			time.RFC1123,
			time.RFC1123Z,
			"Mon, 2 Jan 2006 15:04:05 MST",
			"Mon, 2 Jan 2006 15:04:05 -0700",
		}
	}
	r := strings.NewReplacer(
		"uuuu", "2006",
		"uuu", "2006",
		"uu", "06",
		"u", "2006",
		"yyyy", "2006",
		"yyy", "2006",
		"yy", "06",
		"y", "2006",
		"MMMM", "January",
		"MMM", "Jan",
		"MM", "01",
		"M", "1",
		"EEEE", "Monday",
		"EEE", "Mon",
		"DDD", "002",
		"dd", "02",
		"d", "2",
		"HH", "15",
		"H", "15",
		"hh", "03",
		"h", "3",
		"mm", "04",
		"ss", "05",
		"SSSSSSSSS", "000000000",
		"SSSSSS", "000000",
		"SSS", "000",
		"SS", "00",
		"S", "0",
		"a", "PM",
		"xxxx", "Z0700",
		"xxx", "Z07:00",
		"xx", "Z0700",
		"x", "Z07",
		"XXX", "Z07:00",
		"XX", "Z0700",
		"X", "Z07",
		"Z", "Z0700",
		"zzz", "MST",
		"z", "MST",
	)
	var b strings.Builder
	inQuote := false
	segStart := 0
	hasUnquotedZ := false
	for i := 0; i < len(esFmt); i++ {
		if esFmt[i] == '\'' {
			if !inQuote {
				unquoted := esFmt[segStart:i]
				if strings.ContainsAny(unquoted, "ZxX") {
					hasUnquotedZ = true
				}
				b.WriteString(r.Replace(unquoted))
				if i+1 < len(esFmt) && esFmt[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					segStart = i + 1
					continue
				}
				inQuote = true
				segStart = i + 1
			} else {
				if i+1 < len(esFmt) && esFmt[i+1] == '\'' {
					b.WriteString(esFmt[segStart : i+1])
					i++
					segStart = i + 1
					continue
				}
				b.WriteString(esFmt[segStart:i])
				inQuote = false
				segStart = i + 1
			}
		}
	}
	if segStart < len(esFmt) {
		rem := esFmt[segStart:]
		if inQuote {
			b.WriteString(rem)
		} else {
			if strings.ContainsAny(rem, "ZxX") {
				hasUnquotedZ = true
			}
			b.WriteString(r.Replace(rem))
		}
	}
	layout := b.String()
	layouts := []string{layout}
	flexFrac := strings.NewReplacer(
		".000000000", ".999999999",
		".000000", ".999999",
		".000", ".999",
		",000000000", ",999999999",
		",000000", ",999999",
		",000", ",999",
	).Replace(layout)
	if flexFrac != layout {
		layouts = append(layouts, flexFrac)
	}
	if hasUnquotedZ {
		layouts = append(layouts, strings.ReplaceAll(layout, "Z0700", "Z07:00"), strings.ReplaceAll(layout, "Z07:00", "Z0700"))
		if flexFrac != layout {
			layouts = append(layouts, strings.ReplaceAll(flexFrac, "Z0700", "Z07:00"), strings.ReplaceAll(flexFrac, "Z07:00", "Z0700"))
		}
	}
	return layouts
}

func formatIngestDateInput(val any) string {
	switch tv := val.(type) {
	case json.Number:
		return tv.String()
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return strconv.FormatFloat(tv, 'f', -1, 64)
		}
		if math.Trunc(tv) == tv && tv >= -9e18 && tv <= 9e18 {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(tv, 10)
	case int:
		return strconv.Itoa(tv)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func isNumericIngestDateValue(val any) bool {
	switch val.(type) {
	case json.Number, float64, float32, int, int64, int32, uint, uint64, uint32:
		return true
	default:
		return false
	}
}

func parseIngestTimezone(tzName string) (*time.Location, error) {
	tzName = strings.TrimSpace(tzName)
	if tzName == "" || strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "Z") || strings.EqualFold(tzName, "GMT") {
		return time.UTC, nil
	}
	if l, err := time.LoadLocation(tzName); err == nil {
		return l, nil
	}
	if len(tzName) == 6 && (tzName[0] == '+' || tzName[0] == '-') && tzName[3] == ':' {
		h, err1 := strconv.Atoi(tzName[1:3])
		m, err2 := strconv.Atoi(tzName[4:6])
		if err1 == nil && err2 == nil && h >= 0 && h <= 18 && m >= 0 && m <= 59 {
			offset := h*3600 + m*60
			if tzName[0] == '-' {
				offset = -offset
			}
			return time.FixedZone(tzName, offset), nil
		}
	}
	if len(tzName) == 5 && (tzName[0] == '+' || tzName[0] == '-') {
		h, err1 := strconv.Atoi(tzName[1:3])
		m, err2 := strconv.Atoi(tzName[3:5])
		if err1 == nil && err2 == nil && h >= 0 && h <= 18 && m >= 0 && m <= 59 {
			offset := h*3600 + m*60
			if tzName[0] == '-' {
				offset = -offset
			}
			return time.FixedZone(tzName, offset), nil
		}
	}
	if len(tzName) == 3 && (tzName[0] == '+' || tzName[0] == '-') {
		h, err1 := strconv.Atoi(tzName[1:3])
		if err1 == nil && h >= 0 && h <= 18 {
			offset := h * 3600
			if tzName[0] == '-' {
				offset = -offset
			}
			return time.FixedZone(tzName, offset), nil
		}
	}
	return nil, fmt.Errorf("illegal_argument_exception: timezone [%s] is not supported", tzName)
}

func parseIngestDateValue(raw string, formats []any, tzName string) (time.Time, error) {
	loc, err := parseIngestTimezone(tzName)
	if err != nil {
		return time.Time{}, err
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
			case "TAI64N":
				s := strings.TrimPrefix(strings.TrimSpace(raw), "@")
				if len(s) == 24 {
					hi, err1 := strconv.ParseUint(s[:16], 16, 64)
					lo, err2 := strconv.ParseUint(s[16:24], 16, 32)
					if err1 == nil && err2 == nil && lo < 1_000_000_000 {
						const taiEpoch uint64 = 0x400000000000000a
						if hi >= taiEpoch {
							diff := hi - taiEpoch
							if diff <= math.MaxInt64 {
								return time.Unix(int64(diff), int64(lo)).In(loc), nil
							}
						} else {
							diff := taiEpoch - hi
							if diff <= uint64(math.MaxInt64) {
								return time.Unix(-int64(diff), int64(lo)).In(loc), nil
							}
						}
					}
				}
			case "UNIX":
				trimmed := strings.TrimSpace(raw)
				if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= -1e14 && fv <= 1e14 {
					sec := int64(fv)
					nsec := int64(math.Round((fv - float64(sec)) * 1e9))
					return time.Unix(sec, nsec).In(loc), nil
				}
			case "UNIX_MS":
				trimmed := strings.TrimSpace(raw)
				if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
					return time.UnixMilli(iv).In(loc), nil
				}
				if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= -9e18 && fv <= 9e18 {
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

func normalizeFingerprintMethod(raw string) string {
	m := strings.ToUpper(strings.TrimSpace(raw))
	if atIdx := strings.IndexByte(m, '@'); atIdx >= 0 {
		m = strings.TrimSpace(m[:atIdx])
	}
	switch m {
	case "SHA1":
		return "SHA-1"
	case "", "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	}
	return m
}

func murmur3Sum128(data []byte) [16]byte {
	const (
		c1 uint64 = 0x87c37b91114253d5
		c2 uint64 = 0x4cf5ad432745937f
	)
	rotl64 := func(x uint64, r uint) uint64 {
		return (x << r) | (x >> (64 - r))
	}
	fmix64 := func(k uint64) uint64 {
		k ^= k >> 33
		k *= 0xff51afd7ed558ccd
		k ^= k >> 33
		k *= 0xc4ceb9fe1a85ec53
		k ^= k >> 33
		return k
	}
	var h1, h2 uint64
	nblocks := len(data) / 16
	for i := 0; i < nblocks; i++ {
		off := i * 16
		k1 := uint64(data[off]) | uint64(data[off+1])<<8 | uint64(data[off+2])<<16 | uint64(data[off+3])<<24 |
			uint64(data[off+4])<<32 | uint64(data[off+5])<<40 | uint64(data[off+6])<<48 | uint64(data[off+7])<<56
		k2 := uint64(data[off+8]) | uint64(data[off+9])<<8 | uint64(data[off+10])<<16 | uint64(data[off+11])<<24 |
			uint64(data[off+12])<<32 | uint64(data[off+13])<<40 | uint64(data[off+14])<<48 | uint64(data[off+15])<<56
		k1 *= c1
		k1 = rotl64(k1, 31)
		k1 *= c2
		h1 ^= k1
		h1 = rotl64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = rotl64(k2, 33)
		k2 *= c1
		h2 ^= k2
		h2 = rotl64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}
	tail := data[nblocks*16:]
	var k1, k2 uint64
	switch len(tail) {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8])
		k2 *= c2
		k2 = rotl64(k2, 33)
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0])
		k1 *= c1
		k1 = rotl64(k1, 31)
		k1 *= c2
		h1 ^= k1
	}
	dataLen := uint64(len(data)) // #nosec G115 -- slice length is non-negative
	h1 ^= dataLen
	h2 ^= dataLen
	h1 += h2
	h2 += h1
	h1 = fmix64(h1)
	h2 = fmix64(h2)
	h1 += h2
	h2 += h1
	var out [16]byte
	for i := uint(0); i < 8; i++ {
		out[i] = byte((h1 >> (i * 8)) & 0xFF)   // #nosec G115 -- masked to 8 bits
		out[8+i] = byte((h2 >> (i * 8)) & 0xFF) // #nosec G115 -- masked to 8 bits
	}
	return out
}

func unescapeKVQuotedString(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if next == '"' || next == '\'' || next == '\\' {
				b.WriteByte(next)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) || fv < 0 {
		return 0, fmt.Errorf("unable to convert [%s] to bytes", s)
	}
	return int64(fv * mult), nil
}

func splitIngestKVPairs(s, fieldSplit string) ([]string, error) {
	var re *regexp.Regexp
	if fieldSplit != "|" && fieldSplit != "." && fieldSplit != " " && fieldSplit != "," && fieldSplit != ";" && fieldSplit != "&" {
		var err error
		re, err = compileIngestJavaRegex(fieldSplit)
		if err != nil {
			return nil, fmt.Errorf("illegal_argument_exception: invalid field_split [%s]: %v", fieldSplit, err)
		}
	}
	if !strings.ContainsAny(s, `"'`) {
		if re != nil {
			return re.Split(s, -1), nil
		}
		return strings.Split(s, fieldSplit), nil
	}
	var pairs []string
	var cur strings.Builder
	quoteChar := byte(0)
	for i := 0; i < len(s); {
		ch := s[i]
		if quoteChar != 0 {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else if ch == quoteChar {
				quoteChar = 0
			}
			i++
			continue
		}
		if ch == '"' || ch == '\'' {
			quoteChar = ch
			cur.WriteByte(ch)
			i++
			continue
		}
		if re != nil {
			if loc := re.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 && loc[1] > 0 {
				pairs = append(pairs, cur.String())
				cur.Reset()
				i += loc[1]
				continue
			}
		} else if fieldSplit != "" && strings.HasPrefix(s[i:], fieldSplit) {
			pairs = append(pairs, cur.String())
			cur.Reset()
			i += len(fieldSplit)
			continue
		}
		cur.WriteByte(ch)
		i++
	}
	pairs = append(pairs, cur.String())
	return pairs, nil
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
			inner = strings.TrimRight(inner, "-")
		}
		inner = strings.TrimSpace(inner)
		switch {
		case inner == "" || strings.HasPrefix(inner, "?"):
			tok.skip = true
			tok.rawKey = strings.TrimSpace(strings.TrimPrefix(inner, "?"))
		case strings.HasPrefix(inner, "*"):
			tok.skip = true
			tok.rawKey = strings.TrimSpace(strings.TrimPrefix(inner, "*"))
		case strings.HasPrefix(inner, "+") || strings.HasPrefix(inner, "&"):
			for strings.HasPrefix(inner, "+") || strings.HasPrefix(inner, "&") {
				if strings.HasPrefix(inner, "+") {
					tok.append = true
					inner = strings.TrimPrefix(inner, "+")
				}
				if strings.HasPrefix(inner, "&") {
					tok.indirect = true
					inner = strings.TrimPrefix(inner, "&")
				}
			}
			if slashIdx := strings.IndexByte(inner, '/'); slashIdx > 0 {
				if ord, err := strconv.Atoi(inner[slashIdx+1:]); err == nil && ord > 0 {
					tok.appendOrder = ord
				}
				inner = inner[:slashIdx]
			}
			tok.rawKey = strings.TrimSpace(inner)
		default:
			tok.rawKey = strings.TrimSpace(inner)
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
			if tok.padRight {
				wsIdx := strings.IndexAny(cur, " \t")
				if wsIdx >= 0 {
					val = cur[:wsIdx]
					cur = strings.TrimLeft(cur[wsIdx:], " \t")
				} else {
					val = cur
					cur = ""
				}
			} else {
				val = ""
			}
		} else if isLast {
			if !strings.HasSuffix(cur, tok.nextLit) {
				return nil, fmt.Errorf("unable to dissect [%s] with pattern [%s]: missing delimiter [%s]", input, pattern, tok.nextLit)
			}
			val = cur[:len(cur)-len(tok.nextLit)]
			for tok.padRight && tok.nextLit != "" && strings.HasSuffix(val, tok.nextLit) {
				val = val[:len(val)-len(tok.nextLit)]
			}
			cur = ""
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
		}
		captured[i] = val
		if !tok.indirect && !tok.append && tok.rawKey != "" {
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

func hasIngestScalarAncestor(doc map[string]any, path string) (string, bool) {
	segs := strings.Split(path, ".")
	for i := 1; i < len(segs); i++ {
		prefix := strings.Join(segs[:i], ".")
		if ancVal, ok := getIngestPath(doc, prefix); ok && ancVal != nil {
			if _, isMap := ancVal.(map[string]any); isMap {
				continue
			}
			if _, isSlice := ancVal.([]any); isSlice {
				if _, err := strconv.Atoi(segs[i]); err == nil {
					continue
				}
			}
			return prefix, true
		}
	}
	return "", false
}

func ingestNumericFloat64(v any) (float64, bool) {
	switch tv := v.(type) {
	case int:
		return float64(tv), true
	case int32:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	case float32:
		return float64(tv), true
	case float64:
		return tv, true
	case json.Number:
		fv, err := tv.Float64()
		return fv, err == nil
	default:
		return 0, false
	}
}

func ingestValuesEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if fa, okA := ingestNumericFloat64(a); okA {
		if fb, okB := ingestNumericFloat64(b); okB {
			return fa == fb
		}
		return false
	}
	if _, okB := ingestNumericFloat64(b); okB {
		return false
	}
	return reflect.DeepEqual(a, b)
}

func expandIngestFieldName(raw string, doc map[string]any) string {
	if strings.Contains(raw, "{{") {
		return fmt.Sprintf("%v", expandIngestTemplate(raw, doc))
	}
	return raw
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
		var prevMsg, prevType, prevTag, prevPipe any
		var hadPrevMsg, hadPrevType, hadPrevTag, hadPrevPipe bool
		if preIngest, ok := doc["_ingest"].(map[string]any); ok && preIngest != nil {
			prevMsg, hadPrevMsg = preIngest["on_failure_message"]
			prevType, hadPrevType = preIngest["on_failure_processor_type"]
			prevTag, hadPrevTag = preIngest["on_failure_processor_tag"]
			prevPipe, hadPrevPipe = preIngest["on_failure_pipeline"]
		}
		origMeta, _ := doc["__internal_ingest_orig"].(map[string]any)
		var savedActivePipe any
		var hadSavedActivePipe bool
		if origMeta != nil {
			savedActivePipe, hadSavedActivePipe = origMeta["_active_pipeline"]
			origMeta["_active_pipeline"] = subName
		} else {
			origMeta = map[string]any{"_active_pipeline": subName}
			doc["__internal_ingest_orig"] = origMeta
		}
		restoreActivePipe := func() {
			if om, ok := doc["__internal_ingest_orig"].(map[string]any); ok && om != nil {
				if hadSavedActivePipe {
					om["_active_pipeline"] = savedActivePipe
				} else {
					delete(om, "_active_pipeline")
				}
			}
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
				if _, hasFP := ingestMeta["on_failure_pipeline"]; !hasFP && subName != "" {
					ingestMeta["on_failure_pipeline"] = subName
				}
				doc["_ingest"] = ingestMeta
				subMut = true
				fMut, fDrop, fErr := runIngestProcessorList(s, doc, pipeOnFail, depth+1, trace)
				if fMut {
					subMut = true
				}
				if fDrop {
					restoreActivePipe()
					return subMut, true, procType, procTag, specMap, nil
				}
				if fErr == nil {
					if curIngest, ok := doc["_ingest"].(map[string]any); ok {
						if hadPrevMsg {
							curIngest["on_failure_message"] = prevMsg
						} else {
							delete(curIngest, "on_failure_message")
						}
						if hadPrevType {
							curIngest["on_failure_processor_type"] = prevType
						} else {
							delete(curIngest, "on_failure_processor_type")
						}
						if hadPrevTag {
							curIngest["on_failure_processor_tag"] = prevTag
						} else {
							delete(curIngest, "on_failure_processor_tag")
						}
						if hadPrevPipe {
							curIngest["on_failure_pipeline"] = prevPipe
						} else {
							delete(curIngest, "on_failure_pipeline")
						}
					}
				}
				subErr = fErr
			}
		}
		restoreActivePipe()
		return subMut, subDropped, procType, procTag, specMap, subErr
	case "dissect":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
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
			var extracted map[string]any
			switch v := val.(type) {
			case string:
				res, err := evalDissectPattern(pattern, v, appendSep)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				extracted = make(map[string]any, len(res))
				for k, sv := range res {
					extracted[k] = sv
				}
			case []any:
				extracted = make(map[string]any)
				for _, elem := range v {
					strElem, isStr := elem.(string)
					if !isStr {
						return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
					}
					res, err := evalDissectPattern(pattern, strElem, appendSep)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					for k, sv := range res {
						arr, _ := extracted[k].([]any)
						extracted[k] = append(arr, sv)
					}
				}
			default:
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
			}
			targetField, _ := specMap["target_field"].(string)
			targetField = expandIngestFieldName(targetField, doc)
			if targetField != "" {
				if existing, ok := getIngestPath(doc, targetField); !ok || existing == nil {
					setIngestPath(doc, targetField, map[string]any{})
				} else if _, isMap := existing.(map[string]any); !isMap {
					setIngestPath(doc, targetField, map[string]any{})
				}
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
			ignoreEmpty, _ := specMap["ignore_empty_value"].(bool)
			if copyFrom, _ := specMap["copy_from"].(string); copyFrom != "" {
				copyFrom = fmt.Sprintf("%v", expandIngestTemplate(copyFrom, doc))
				val, exists := getIngestPath(doc, copyFrom)
				if !exists {
					if isExplicitIgnoreMissingFalse(specMap) {
						return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", copyFrom)
					}
					return false, false, procType, procTag, specMap, nil
				}
				if ignoreEmpty && isEmptyIngestSetValue(val) {
					return false, false, procType, procTag, specMap, nil
				}
				if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
					if existing, exOk := getIngestPath(doc, field); exOk && existing != nil {
						return false, false, procType, procTag, specMap, nil
					}
				}
				setIngestPath(doc, field, deepCloneIngestValue(val))
				mutated = true
			} else if val, hasVal := specMap["value"]; hasVal {
				if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
					if existing, exists := getIngestPath(doc, field); exists && existing != nil {
						return false, false, procType, procTag, specMap, nil
					}
				}
				expandedVal := expandIngestTemplate(val, doc)
				if ignoreEmpty && isEmptyIngestSetValue(expandedVal) {
					return false, false, procType, procTag, specMap, nil
				}
				setIngestPath(doc, field, deepCloneIngestValue(expandedVal))
				mutated = true
			}
		}
	case "default":
		if field, _ := specMap["field"].(string); field != "" {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
			if existing, exists := getIngestPath(doc, field); !exists || existing == nil {
				setIngestPath(doc, field, deepCloneIngestValue(expandIngestTemplate(specMap["value"], doc)))
				mutated = true
			}
		}
	case "rename":
		srcField, _ := specMap["field"].(string)
		dstField, _ := specMap["target_field"].(string)
		if srcField != "" && dstField != "" {
			srcField = fmt.Sprintf("%v", expandIngestTemplate(srcField, doc))
			dstField = fmt.Sprintf("%v", expandIngestTemplate(dstField, doc))
			if srcField == dstField {
				return false, false, procType, procTag, specMap, fmt.Errorf("source and target_field are the same: [%s]", srcField)
			}
			val, exists := getIngestPath(doc, srcField)
			if !exists {
				if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", srcField)
				}
				return false, false, procType, procTag, specMap, nil
			}
			if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
				if existing, exOk := getIngestPath(doc, dstField); exOk && existing != nil {
					return false, false, procType, procTag, specMap, nil
				}
				if anc, hasScalarAnc := hasIngestScalarAncestor(doc, dstField); hasScalarAnc && srcField != anc && !strings.HasPrefix(srcField, anc+".") {
					return false, false, procType, procTag, specMap, nil
				}
			}
			if anc, hasScalarAnc := hasIngestScalarAncestor(doc, dstField); hasScalarAnc && srcField != anc && !strings.HasPrefix(srcField, anc+".") && !strings.HasPrefix(dstField, srcField+".") {
				return false, false, procType, procTag, specMap, fmt.Errorf("target_field [%s] cannot be set because [%s] is not an object", dstField, anc)
			}
			cloned := deepCloneIngestValue(val)
			deleteIngestPath(doc, srcField)
			setIngestPath(doc, dstField, cloned)
			mutated = true
		}
	case "copy":
		srcField, _ := specMap["field"].(string)
		dstField, _ := specMap["target_field"].(string)
		if srcField != "" && dstField != "" {
			srcField = fmt.Sprintf("%v", expandIngestTemplate(srcField, doc))
			dstField = fmt.Sprintf("%v", expandIngestTemplate(dstField, doc))
			if srcField == dstField {
				return false, false, procType, procTag, specMap, fmt.Errorf("source and target_field are the same: [%s]", srcField)
			}
			val, exists := getIngestPath(doc, srcField)
			if !exists {
				if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", srcField)
				}
				return false, false, procType, procTag, specMap, nil
			}
			if override, hasOverride := specMap["override"].(bool); hasOverride && !override {
				if existing, exOk := getIngestPath(doc, dstField); exOk && existing != nil {
					return false, false, procType, procTag, specMap, nil
				}
				if _, hasScalarAnc := hasIngestScalarAncestor(doc, dstField); hasScalarAnc {
					return false, false, procType, procTag, specMap, nil
				}
			}
			if anc, hasScalarAnc := hasIngestScalarAncestor(doc, dstField); hasScalarAnc {
				return false, false, procType, procTag, specMap, fmt.Errorf("target_field [%s] cannot be set because [%s] is not an object", dstField, anc)
			}
			setIngestPath(doc, dstField, deepCloneIngestValue(val))
			mutated = true
		}
	case "remove":
		extractRemoveStrings := func(raw any) []string {
			var res []string
			switch tv := raw.(type) {
			case string:
				s := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(tv, doc)))
				if s != "" {
					res = append(res, s)
				}
			case []any:
				for _, item := range tv {
					if ks, ok := item.(string); ok {
						s := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(ks, doc)))
						if s != "" {
							res = append(res, s)
						}
					}
				}
			}
			return res
		}
		fieldsToRemove := extractRemoveStrings(specMap["field"])
		fieldsToKeep := extractRemoveStrings(specMap["keep"])
		if len(fieldsToRemove) == 0 && len(fieldsToKeep) == 0 {
			return false, false, procType, procTag, specMap, fmt.Errorf("either [field] or [keep] must be specified")
		}
		if len(fieldsToRemove) > 0 && len(fieldsToKeep) > 0 {
			keepSet := make(map[string]bool, len(fieldsToKeep))
			for _, kp := range fieldsToKeep {
				keepSet[kp] = true
			}
			for _, rm := range fieldsToRemove {
				if keepSet[rm] {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] cannot be present in both [field] and [keep]", rm)
				}
			}
		}
		for _, f := range fieldsToRemove {
			if _, exists := getIngestPath(doc, f); !exists {
				if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", f)
				}
			} else {
				deleteIngestPath(doc, f)
				mutated = true
			}
		}
		if len(fieldsToKeep) > 0 {
			isInternalIngestKey := func(k string) bool {
				switch k {
				case "_ingest", "_index", "_id", "_version", "_routing", "__internal_ingest_orig":
					return true
				}
				return false
			}
			kept := make(map[string]any)
			for _, metaKey := range []string{"_ingest", "_index", "_id", "_version", "_routing", "__internal_ingest_orig"} {
				if mv, ok := doc[metaKey]; ok {
					kept[metaKey] = mv
				}
			}
			for _, kp := range fieldsToKeep {
				foundAny := false
				if !isInternalIngestKey(kp) {
					if val, exists := getIngestPath(doc, kp); exists {
						setIngestPath(kept, kp, deepCloneIngestValue(val))
						foundAny = true
					}
				}
				prefix := kp + "."
				for k, v := range doc {
					if isInternalIngestKey(k) {
						continue
					}
					if strings.HasPrefix(k, prefix) || (strings.Contains(kp, "*") && matchWildcardPattern(kp, k)) {
						setIngestPath(kept, k, deepCloneIngestValue(v))
						foundAny = true
					}
				}
				if strings.Contains(kp, "*") {
					if keepMatchingIngestPaths(doc, kept, strings.Split(kp, "."), isInternalIngestKey) {
						foundAny = true
					}
				}
				if !foundAny && isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", kp)
				}
			}
			for k := range doc {
				delete(doc, k)
			}
			for k, v := range kept {
				doc[k] = v
			}
			mutated = true
		}
	case "lowercase":
		if field, _ := specMap["field"].(string); field != "" {
			field = expandIngestFieldName(field, doc)
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = expandIngestFieldName(tf, doc)
			}
			if val, ok := getIngestPath(doc, field); ok && val != nil {
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
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "uppercase":
		if field, _ := specMap["field"].(string); field != "" {
			field = expandIngestFieldName(field, doc)
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = expandIngestFieldName(tf, doc)
			}
			if val, ok := getIngestPath(doc, field); ok && val != nil {
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
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "trim":
		if field, _ := specMap["field"].(string); field != "" {
			field = expandIngestFieldName(field, doc)
			target := field
			if tf, _ := specMap["target_field"].(string); tf != "" {
				target = expandIngestFieldName(tf, doc)
			}
			if val, ok := getIngestPath(doc, field); ok && val != nil {
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
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, out)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "split":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		sep, _ := specMap["separator"].(string)
		if strings.Contains(sep, "{{") {
			sep = fmt.Sprintf("%v", expandIngestTemplate(sep, doc))
		}
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		preserveTrailing, _ := specMap["preserve_trailing"].(bool)
		if field != "" && sep != "" {
			var splitRe *regexp.Regexp
			if sep != "|" && sep != "." {
				var err error
				splitRe, err = compileIngestJavaRegex(sep)
				if err != nil {
					return false, false, procType, procTag, specMap, fmt.Errorf("illegal_argument_exception: invalid separator [%s]: %v", sep, err)
				}
			}
			if val, ok := getIngestPath(doc, field); ok && val != nil {
				splitOne := func(strVal string) []any {
					var parts []string
					if splitRe != nil {
						parts = splitRe.Split(strVal, -1)
					} else {
						parts = strings.Split(strVal, sep)
					}
					if !preserveTrailing && strVal != "" {
						for len(parts) > 0 && parts[len(parts)-1] == "" {
							parts = parts[:len(parts)-1]
						}
					}
					out := make([]any, len(parts))
					for i, pt := range parts {
						out[i] = pt
					}
					return out
				}
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, splitOne(v))
					mutated = true
				case []any:
					var out []any
					for _, elem := range v {
						strElem, isStr := elem.(string)
						if !isStr {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
						}
						out = append(out, splitOne(strElem)...)
					}
					if out == nil {
						out = []any{}
					}
					setIngestPath(doc, target, out)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "join":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		sep, _ := specMap["separator"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" {
			if val, ok := getIngestPath(doc, field); ok && val != nil {
				if arr, ok := val.([]any); ok {
					strs := make([]string, len(arr))
					for i, el := range arr {
						strs[i] = fmt.Sprintf("%v", el)
					}
					setIngestPath(doc, target, strings.Join(strs, sep))
					mutated = true
				} else {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not an array, cannot join", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "append":
		if field, _ := specMap["field"].(string); field != "" {
			field = expandIngestFieldName(field, doc)
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
			appendSingleItem := func(val any) {
				if !allowDups {
					for _, ex := range curSlice {
						if ingestValuesEqual(ex, val) {
							return
						}
					}
				}
				curSlice = append(curSlice, val)
			}
			for _, item := range toAdd {
				if s, ok := item.(string); ok {
					trimmedT := strings.TrimSpace(s)
					var tplKey string
					if strings.HasPrefix(trimmedT, "{{{") && strings.HasSuffix(trimmedT, "}}}") && !strings.Contains(trimmedT[3:len(trimmedT)-3], "{{") {
						tplKey = strings.TrimPrefix(strings.TrimSpace(trimmedT[3:len(trimmedT)-3]), "_source.")
					} else if strings.HasPrefix(trimmedT, "{{") && strings.HasSuffix(trimmedT, "}}") && !strings.Contains(trimmedT[2:len(trimmedT)-2], "{{") {
						tplKey = strings.TrimPrefix(strings.TrimSpace(trimmedT[2:len(trimmedT)-2]), "_source.")
					}
					if tplKey != "" {
						if rawV, exists := getIngestPath(doc, tplKey); exists {
							if expSlice, okSlice := rawV.([]any); okSlice {
								for _, el := range expSlice {
									appendSingleItem(deepCloneIngestValue(el))
								}
								continue
							}
						}
					}
				}
				expanded := deepCloneIngestValue(expandIngestTemplate(item, doc))
				appendSingleItem(expanded)
			}
			setIngestPath(doc, field, curSlice)
			mutated = true
		}
	case "convert":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		convType, _ := specMap["type"].(string)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" && convType != "" {
			val, exists := getIngestPath(doc, field)
			if !exists || val == nil {
				if isExplicitIgnoreMissingFalse(specMap) {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing and cannot be converted to [%s]", field, convType)
				}
			} else if arr, isArr := val.([]any); isArr {
				outArr := make([]any, len(arr))
				for idx, elem := range arr {
					if elem == nil {
						outArr[idx] = nil
						continue
					}
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
		if strings.Contains(field, "{{") {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
		}
		pat, _ := specMap["pattern"].(string)
		repl, _ := specMap["replacement"].(string)
		if strings.Contains(repl, "{{") {
			repl = fmt.Sprintf("%v", expandIngestTemplate(repl, doc))
		}
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			if strings.Contains(tf, "{{") {
				tf = fmt.Sprintf("%v", expandIngestTemplate(tf, doc))
			}
			target = tf
		}
		if field != "" && pat != "" {
			re, err := compileIngestJavaRegex(pat)
			if err != nil {
				return false, false, procType, procTag, specMap, err
			}
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				if strVal, ok := val.(string); ok {
					replaced, err := applyIngestGsubReplacement(re, strVal, repl)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					setIngestPath(doc, target, replaced)
					mutated = true
				} else if arr, isArr := val.([]any); isArr {
					outArr := make([]any, len(arr))
					for idx, elem := range arr {
						if sElem, ok := elem.(string); ok {
							replaced, err := applyIngestGsubReplacement(re, sElem, repl)
							if err != nil {
								return false, false, procType, procTag, specMap, err
							}
							outArr[idx] = replaced
						} else {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				} else {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "json":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		rawTF, _ := specMap["target_field"].(string)
		addToRoot, _ := specMap["add_to_root"].(bool)
		if addToRoot && strings.TrimSpace(rawTF) != "" {
			return false, false, procType, procTag, specMap, fmt.Errorf("cannot specify both [target_field] and [add_to_root]")
		}
		target := field
		if rawTF != "" {
			target = expandIngestFieldName(rawTF, doc)
		}
		conflictStrategy, _ := specMap["add_to_root_conflict_strategy"].(string)
		allowDup, _ := specMap["allow_duplicate_keys"].(bool)
		strictParsing := true
		if sp, ok := specMap["strict_json_parsing"].(bool); ok {
			strictParsing = sp
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case string:
					if !allowDup {
						if err := validateJSONNoDuplicateKeys(v, strictParsing); err != nil {
							return false, false, procType, procTag, specMap, err
						}
					}
					dec := json.NewDecoder(strings.NewReader(v))
					dec.UseNumber()
					var parsed any
					if err := dec.Decode(&parsed); err != nil {
						return false, false, procType, procTag, specMap, err
					}
					if strictParsing {
						var extra any
						if err := dec.Decode(&extra); err != io.EOF {
							return false, false, procType, procTag, specMap, fmt.Errorf("unexpected trailing token in json field [%s]", field)
						}
					}
					if addToRoot {
						m, ok := parsed.(map[string]any)
						if !ok {
							return false, false, procType, procTag, specMap, fmt.Errorf("json must be an object when [add_to_root] is true")
						}
						cleanM := make(map[string]any, len(m))
						for k, mv := range m {
							switch k {
							case "_ingest", "__internal_ingest_orig", "__internal_ingest_terminated", "__internal_ingest_rerouted", "_index", "_id", "_routing", "_version":
								continue
							}
							cleanM[k] = mv
						}
						if strings.EqualFold(strings.TrimSpace(conflictStrategy), "merge") {
							deepMergeIngestMap(doc, cleanM)
						} else {
							for k, mv := range cleanM {
								doc[k] = mv
							}
						}
						mutated = true
					} else {
						setIngestPath(doc, target, parsed)
						mutated = true
					}
				case []any:
					if addToRoot {
						return false, false, procType, procTag, specMap, fmt.Errorf("cannot use [add_to_root] when field [%s] is an array", field)
					}
					outArr := make([]any, len(v))
					for i, elem := range v {
						sElem, ok := elem.(string)
						if !ok {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
						if !allowDup {
							if err := validateJSONNoDuplicateKeys(sElem, strictParsing); err != nil {
								return false, false, procType, procTag, specMap, err
							}
						}
						dec := json.NewDecoder(strings.NewReader(sElem))
						dec.UseNumber()
						var parsed any
						if err := dec.Decode(&parsed); err != nil {
							return false, false, procType, procTag, specMap, err
						}
						if strictParsing {
							var extra any
							if err := dec.Decode(&extra); err != io.EOF {
								return false, false, procType, procTag, specMap, fmt.Errorf("unexpected trailing token in json field [%s]", field)
							}
						}
						outArr[i] = parsed
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "kv":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		fieldSplit, _ := specMap["field_split"].(string)
		valueSplit, _ := specMap["value_split"].(string)
		targetField, _ := specMap["target_field"].(string)
		targetField = expandIngestFieldName(targetField, doc)
		prefix, _ := specMap["prefix"].(string)
		prefix = expandIngestFieldName(prefix, doc)
		trimKey, _ := specMap["trim_key"].(string)
		trimVal, _ := specMap["trim_value"].(string)
		transformKey, _ := specMap["transform_key"].(string)
		stripBrackets, _ := specMap["strip_brackets"].(bool)
		var includeSet, excludeSet map[string]bool
		if incArr, ok := specMap["include_keys"].([]any); ok && len(incArr) > 0 {
			includeSet = make(map[string]bool, len(incArr))
			for _, item := range incArr {
				includeSet[fmt.Sprintf("%v", item)] = true
			}
		}
		if excArr, ok := specMap["exclude_keys"].([]any); ok && len(excArr) > 0 {
			excludeSet = make(map[string]bool, len(excArr))
			for _, item := range excArr {
				excludeSet[fmt.Sprintf("%v", item)] = true
			}
		}
		if field != "" && fieldSplit != "" && valueSplit != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				var strInputs []string
				switch v := val.(type) {
				case string:
					strInputs = []string{v}
				case []any:
					for _, elem := range v {
						strElem, isStr := elem.(string)
						if !isStr {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
						}
						strInputs = append(strInputs, strElem)
					}
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
				var valSplitRe *regexp.Regexp
				if valueSplit != "=" && valueSplit != ":" && valueSplit != "|" && valueSplit != "." {
					var err error
					valSplitRe, err = compileIngestJavaRegex(valueSplit)
					if err != nil {
						return false, false, procType, procTag, specMap, fmt.Errorf("illegal_argument_exception: invalid value_split [%s]: %v", valueSplit, err)
					}
				}
				hasMatchingOuterKVBrackets := func(s string, openB, closeB byte) bool {
					depth := 0
					inQuote := byte(0)
					escaped := false
					for i := 0; i < len(s); i++ {
						ch := s[i]
						if escaped {
							escaped = false
							continue
						}
						if ch == '\\' && inQuote != 0 {
							escaped = true
							continue
						}
						if inQuote != 0 {
							if ch == inQuote {
								inQuote = 0
							}
							continue
						}
						if ch == '"' || ch == '\'' {
							inQuote = ch
							continue
						}
						switch ch {
						case openB:
							depth++
						case closeB:
							depth--
							if depth == 0 {
								return i == len(s)-1
							}
						}
					}
					return false
				}
				stripKVEnclosingBrackets := func(s string) string {
					for len(s) >= 2 {
						first, last := s[0], s[len(s)-1]
						if ((first == '[' && last == ']') || (first == '(' && last == ')') || (first == '<' && last == '>') || (first == '{' && last == '}')) &&
							hasMatchingOuterKVBrackets(s, first, last) {
							s = s[1 : len(s)-1]
						} else {
							break
						}
					}
					return s
				}
				kvMap := make(map[string]any)
				for _, strVal := range strInputs {
					if stripBrackets {
						strVal = stripKVEnclosingBrackets(strings.TrimSpace(strVal))
					}
					pairs, splitErr := splitIngestKVPairs(strVal, fieldSplit)
					if splitErr != nil {
						return false, false, procType, procTag, specMap, splitErr
					}
					for _, pair := range pairs {
						pair = strings.TrimSpace(pair)
						if stripBrackets {
							pair = stripKVEnclosingBrackets(pair)
						}
						if pair == "" {
							continue
						}
						var k, v string
						if valSplitRe != nil {
							loc := valSplitRe.FindStringIndex(pair)
							if loc == nil || loc[0] <= 0 {
								continue
							}
							k = pair[:loc[0]]
							v = pair[loc[1]:]
						} else {
							idx := strings.Index(pair, valueSplit)
							if idx <= 0 {
								continue
							}
							k = pair[:idx]
							v = pair[idx+len(valueSplit):]
						}
						k = strings.TrimSpace(k)
						if stripBrackets {
							k = stripKVEnclosingBrackets(k)
						}
						if trimKey != "" {
							k = strings.Trim(k, trimKey)
						}
						switch transformKey {
						case "lowercase":
							k = strings.ToLower(k)
						case "uppercase":
							k = strings.ToUpper(k)
						}
						if includeSet != nil && !includeSet[k] {
							continue
						}
						if excludeSet != nil && excludeSet[k] {
							continue
						}
						v = strings.TrimSpace(v)
						if len(v) >= 2 {
							first, last := v[0], v[len(v)-1]
							if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
								v = unescapeKVQuotedString(v[1 : len(v)-1])
							} else if stripBrackets {
								v = stripKVEnclosingBrackets(v)
							}
						}
						if trimVal != "" {
							v = strings.Trim(v, trimVal)
						}
						fullKey := prefix + k
						if prev, hasPrev := kvMap[fullKey]; hasPrev {
							if prevArr, isArr := prev.([]any); isArr {
								kvMap[fullKey] = append(prevArr, v)
							} else {
								kvMap[fullKey] = []any{prev, v}
							}
						} else {
							kvMap[fullKey] = v
						}
					}
				}
				if targetField != "" {
					if existing, ok := getIngestPath(doc, targetField); !ok || existing == nil {
						setIngestPath(doc, targetField, map[string]any{})
					} else if _, isMap := existing.(map[string]any); !isMap {
						setIngestPath(doc, targetField, map[string]any{})
					}
					for k, v := range kvMap {
						setIngestPath(doc, targetField+"."+k, v)
					}
				} else {
					for k, v := range kvMap {
						setIngestPath(doc, k, v)
					}
				}
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "dot_expander":
		field, _ := specMap["field"].(string)
		if strings.Contains(field, "{{") {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
		}
		subPath, _ := specMap["path"].(string)
		if strings.Contains(subPath, "{{") {
			subPath = fmt.Sprintf("%v", expandIngestTemplate(subPath, doc))
		}
		override := true
		if ov, hasOv := specMap["override"].(bool); hasOv {
			override = ov
		}
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
			expandKeyInMap := func(m map[string]any, k string) bool {
				val, exists := m[k]
				if !exists {
					return false
				}
				if !override {
					firstSeg := k
					if dotIdx := strings.IndexByte(k, '.'); dotIdx > 0 {
						firstSeg = k[:dotIdx]
					}
					if existing, hasEx := m[firstSeg]; hasEx {
						if _, isMap := existing.(map[string]any); !isMap {
							return false
						}
					}
					if strings.Contains(k, ".") {
						segs := strings.Split(k, ".")
						cur := m
						leafConflict := false
						for i, seg := range segs {
							ex, hasEx := cur[seg]
							if !hasEx {
								break
							}
							if i == len(segs)-1 {
								if _, isMap := ex.(map[string]any); !isMap {
									leafConflict = true
								} else if _, valIsMap := val.(map[string]any); !valIsMap {
									leafConflict = true
								}
								break
							}
							nextMap, isMap := ex.(map[string]any)
							if !isMap {
								return false
							}
							cur = nextMap
						}
						if leafConflict {
							delete(m, k)
							return true
						}
					}
				}
				delete(m, k)
				setIngestPathMergeWithOverride(m, k, expandDottedIngestValueWithOverride(val, override), override)
				return true
			}
			if targetMap != nil {
				if field == "*" {
					var dottedKeys []string
					for k := range targetMap {
						if strings.Contains(k, ".") {
							dottedKeys = append(dottedKeys, k)
						}
					}
					sort.Strings(dottedKeys)
					for _, k := range dottedKeys {
						if expandKeyInMap(targetMap, k) {
							mutated = true
						}
					}
					for k, v := range targetMap {
						if k == "_ingest" || k == "_id" || k == "_index" {
							continue
						}
						switch v.(type) {
						case map[string]any, []any:
							targetMap[k] = expandDottedIngestValueWithOverride(v, override)
							mutated = true
						}
					}
				} else if expandKeyInMap(targetMap, field) {
					mutated = true
				} else if strings.Contains(field, ".") {
					parts := strings.Split(field, ".")
					curMap := targetMap
					for i := 0; i < len(parts)-1; i++ {
						nextMap, ok := curMap[parts[i]].(map[string]any)
						if !ok {
							break
						}
						remKey := strings.Join(parts[i+1:], ".")
						if strings.Contains(remKey, ".") {
							if expandKeyInMap(nextMap, remKey) {
								mutated = true
								break
							}
						}
						curMap = nextMap
					}
				}
			}
		}
	case "urlencode", "url_encode", "URLEncode":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, url.QueryEscape(v))
					mutated = true
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						if sEl, ok := el.(string); ok {
							outArr[idx] = url.QueryEscape(sEl)
						} else {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "urldecode", "url_decode", "URLDecode":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
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
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "bytes":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				parseByteElem := func(el any) (int64, error) {
					switch ev := el.(type) {
					case string:
						return parseIngestByteSize(ev)
					case int:
						return int64(ev), nil
					case int64:
						return ev, nil
					case float64:
						return int64(ev), nil
					case json.Number:
						if iv, err := ev.Int64(); err == nil {
							return iv, nil
						}
						if fv, err := ev.Float64(); err == nil {
							return int64(fv), nil
						}
						return parseIngestByteSize(ev.String())
					default:
						return 0, fmt.Errorf("field [%s] is not a string", field)
					}
				}
				switch v := val.(type) {
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						bVal, err := parseByteElem(el)
						if err != nil {
							return false, false, procType, procTag, specMap, err
						}
						outArr[idx] = bVal
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					bVal, err := parseByteElem(v)
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
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		escapedTags := make(map[string]bool)
		if rawEsc, ok := specMap["escaped_tags"].([]any); ok {
			for _, t := range rawEsc {
				if ts, ok := t.(string); ok && ts != "" {
					escapedTags[strings.ToLower(strings.TrimSpace(ts))] = true
				}
			}
		}
		stripHTMLStr := func(s string) string {
			if len(escapedTags) == 0 {
				return html.UnescapeString(reHTMLTags.ReplaceAllString(s, ""))
			}
			stripped := reHTMLTags.ReplaceAllStringFunc(s, func(tag string) string {
				inner := strings.TrimSpace(tag)
				inner = strings.TrimPrefix(inner, "<")
				inner = strings.TrimSuffix(inner, ">")
				inner = strings.TrimSpace(inner)
				inner = strings.TrimPrefix(inner, "/")
				inner = strings.TrimSuffix(inner, "/")
				inner = strings.TrimSpace(inner)
				if spIdx := strings.IndexAny(inner, " \t\r\n"); spIdx >= 0 {
					inner = inner[:spIdx]
				}
				if escapedTags[strings.ToLower(inner)] {
					return tag
				}
				return ""
			})
			return html.UnescapeString(stripped)
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case string:
					setIngestPath(doc, target, stripHTMLStr(v))
					mutated = true
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						if sEl, ok := el.(string); ok {
							outArr[idx] = stripHTMLStr(sEl)
						} else {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] contains non-string element", field)
						}
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "date":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := "@timestamp"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		formats, _ := specMap["formats"].([]any)
		tzName, _ := specMap["timezone"].(string)
		if tzName != "" {
			tzName = fmt.Sprintf("%v", expandIngestTemplate(tzName, doc))
		}
		outFmt, _ := specMap["output_format"].(string)
		formatOneDate := func(rawVal any) (string, error) {
			parsedTime, err := parseIngestDateValue(formatIngestDateInput(rawVal), formats, tzName)
			if err != nil {
				return "", err
			}
			if outFmt != "" {
				layouts := convertESDateFormatToGoLayouts(outFmt)
				switch layouts[0] {
				case "UNIX_MS":
					return strconv.FormatInt(parsedTime.UnixMilli(), 10), nil
				case "UNIX":
					return strconv.FormatInt(parsedTime.Unix(), 10), nil
				default:
					return parsedTime.Format(layouts[0]), nil
				}
			}
			return parsedTime.Format(time.RFC3339Nano), nil
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case []any:
					outArr := make([]any, len(v))
					for idx, el := range v {
						formatted, err := formatOneDate(el)
						if err != nil {
							return false, false, procType, procTag, specMap, err
						}
						outArr[idx] = formatted
					}
					setIngestPath(doc, target, outArr)
					mutated = true
				default:
					formatted, err := formatOneDate(v)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					setIngestPath(doc, target, formatted)
					mutated = true
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "date_index_name":
		field, _ := specMap["field"].(string)
		prefix, _ := specMap["index_name_prefix"].(string)
		if prefix != "" {
			prefix = fmt.Sprintf("%v", expandIngestTemplate(prefix, doc))
		}
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
		if tzName != "" {
			tzName = fmt.Sprintf("%v", expandIngestTemplate(tzName, doc))
		}
		if field != "" {
			field = fmt.Sprintf("%v", expandIngestTemplate(field, doc))
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				effFormats := formats
				if len(effFormats) == 0 && isNumericIngestDateValue(val) {
					effFormats = []any{"ISO8601", "UNIX_MS", "UNIX"}
				}
				parsedTime, err := parseIngestDateValue(formatIngestDateInput(val), effFormats, tzName)
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
				var formattedDate string
				switch layouts[0] {
				case "UNIX_MS":
					formattedDate = strconv.FormatInt(parsedTime.UnixMilli(), 10)
				case "UNIX":
					formattedDate = strconv.FormatInt(parsedTime.Unix(), 10)
				default:
					formattedDate = parsedTime.Format(layouts[0])
				}
				target := "_index"
				if tf, _ := specMap["target_field"].(string); tf != "" {
					target = expandIngestFieldName(tf, doc)
				}
				setIngestPath(doc, target, prefix+formattedDate)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "grok":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		patterns, _ := specMap["patterns"].([]any)
		customDefs, _ := specMap["pattern_definitions"].(map[string]any)
		ecsCompat, _ := specMap["ecs_compatibility"].(string)
		if ecsCompat == "v1" {
			mergedDefs := make(map[string]any, len(ecsGrokPatterns)+len(customDefs))
			for k, v := range ecsGrokPatterns {
				mergedDefs[k] = v
			}
			for k, v := range customDefs {
				mergedDefs[k] = v
			}
			customDefs = mergedDefs
		}
		keepEmptyCaptures, _ := specMap["keep_empty_captures"].(bool)
		targetField, _ := specMap["target_field"].(string)
		targetField = expandIngestFieldName(targetField, doc)
		if field != "" && len(patterns) > 0 {
			val, exists := getIngestPath(doc, field)
			if !exists || val == nil {
				ignoreMissing, _ := specMap["ignore_missing"].(bool)
				if !ignoreMissing {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
				}
				return false, false, procType, procTag, specMap, nil
			}
			var strInputs []string
			switch v := val.(type) {
			case string:
				strInputs = []string{v}
			case []any:
				for _, elem := range v {
					strElem, isStr := elem.(string)
					if !isStr {
						return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
					}
					strInputs = append(strInputs, strElem)
				}
			default:
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
			}
			traceMatch, _ := specMap["trace_match"].(bool)
			extracted := make(map[string]any)
			var extractedOrder []string
			for _, strVal := range strInputs {
				matched := false
				for patIdx, patAny := range patterns {
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
					if traceMatch {
						ingestMeta, _ := doc["_ingest"].(map[string]any)
						if ingestMeta == nil {
							ingestMeta = make(map[string]any)
							doc["_ingest"] = ingestMeta
						}
						ingestMeta["_grok_match_index"] = patIdx
						ingestMeta["_grok_match_pattern"] = patStr
					}
					names := re.SubexpNames()
					for i, grpID := range names {
						if i == 0 || grpID == "" || i >= len(m) || 2*i >= len(loc) {
							continue
						}
						fieldName := grpMap[grpID]
						if fieldName == "" {
							continue
						}
						if strings.HasPrefix(fieldName, "[") && strings.HasSuffix(fieldName, "]") {
							fieldName = strings.ReplaceAll(strings.Trim(fieldName, "[]"), "][", ".")
						}
						isEmptyCapture := loc[2*i] < 0 || m[i] == ""
						if isEmptyCapture && !keepEmptyCaptures {
							continue
						}
						var finalVal any
						if !isEmptyCapture {
							finalVal = m[i]
							if convT := grpTypes[grpID]; convT != "" {
								cv, err := convertSingleIngestValue(m[i], convT)
								if err != nil {
									return false, false, procType, procTag, specMap, err
								}
								finalVal = cv
							}
						}
						if prev, hasPrev := extracted[fieldName]; hasPrev {
							if prevArr, isArr := prev.([]any); isArr {
								extracted[fieldName] = append(prevArr, finalVal)
							} else {
								extracted[fieldName] = []any{prev, finalVal}
							}
						} else {
							extracted[fieldName] = finalVal
							extractedOrder = append(extractedOrder, fieldName)
						}
					}
					break
				}
				if !matched {
					return false, false, procType, procTag, specMap, fmt.Errorf("provided Grok expressions do not match field value: [%s]", strVal)
				}
			}
			for _, fieldName := range extractedOrder {
				finalVal := extracted[fieldName]
				if targetField != "" {
					setIngestPath(doc, targetField+"."+fieldName, finalVal)
				} else {
					setIngestPath(doc, fieldName, finalVal)
				}
			}
			mutated = true
		}
	case "sort":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
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
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				switch v := val.(type) {
				case []any:
					setIngestPath(doc, target, compactIngestSlice(v))
					mutated = true
				case map[string]any:
					setIngestPath(doc, target, compactIngestMap(v))
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is neither an array nor an object", field)
				}
			} else if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "dedup", "dedupe":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		ignoreEmpty, _ := specMap["ignore_empty"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				arr, ok := val.([]any)
				if !ok {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not an array", field)
				}
				deduped := make([]any, 0, len(arr))
				for _, el := range arr {
					if ignoreEmpty && (el == nil || el == "") {
						continue
					}
					seen := false
					for _, prev := range deduped {
						if ingestValuesEqual(prev, el) {
							seen = true
							break
						}
					}
					if !seen {
						deduped = append(deduped, el)
					}
				}
				setIngestPath(doc, target, deduped)
				mutated = true
			} else if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "fingerprint":
		fieldsAny, hasFields := specMap["fields"].([]any)
		excludeFieldsAny, hasExclude := specMap["exclude_fields"].([]any)
		if hasFields && hasExclude && (len(fieldsAny) > 0 || len(excludeFieldsAny) > 0) {
			return false, false, procType, procTag, specMap, fmt.Errorf("cannot specify both [fields] and [exclude_fields]")
		}
		target := "fingerprint"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		method, _ := specMap["method"].(string)
		salt, _ := specMap["salt"].(string)
		excludeSet := make(map[string]bool, len(excludeFieldsAny))
		for _, ef := range excludeFieldsAny {
			if efs, ok := ef.(string); ok && efs != "" {
				excludeSet[expandIngestFieldName(efs, doc)] = true
			}
		}
		isExcludedPath := func(p string) bool {
			if excludeSet[p] {
				return true
			}
			for ex := range excludeSet {
				if strings.HasPrefix(p, ex+".") {
					return true
				}
			}
			return false
		}
		var fields []string
		if len(fieldsAny) > 0 {
			for _, f := range fieldsAny {
				if fs, ok := f.(string); ok && fs != "" {
					expF := expandIngestFieldName(fs, doc)
					if !isExcludedPath(expF) {
						fields = append(fields, expF)
					}
				}
			}
		} else {
			var collectLeafPaths func(prefix string, m map[string]any)
			collectLeafPaths = func(prefix string, m map[string]any) {
				for k, v := range m {
					if prefix == "" {
						switch k {
						case "_ingest", "__internal_ingest_orig", "_index", "_id", "_routing", "_version":
							continue
						}
					}
					fullPath := k
					if prefix != "" {
						fullPath = prefix + "." + k
					}
					if isExcludedPath(fullPath) || v == nil {
						continue
					}
					if subM, ok := v.(map[string]any); ok {
						collectLeafPaths(fullPath, subM)
					} else {
						fields = append(fields, fullPath)
					}
				}
			}
			collectLeafPaths("", doc)
		}
		if len(fields) > 0 {
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
				switch normalizeFingerprintMethod(method) {
				case "MD5":
					// #nosec G401 -- Elasticsearch ingest fingerprint processor supports MD5
					sum := md5.Sum([]byte(buf.String()))
					digest = sum[:]
				case "SHA-1":
					// #nosec G401 -- Elasticsearch ingest fingerprint processor supports SHA-1
					sum := sha1.Sum([]byte(buf.String()))
					digest = sum[:]
				case "", "SHA-256":
					sum := sha256.Sum256([]byte(buf.String()))
					digest = sum[:]
				case "SHA-384":
					sum := sha512.Sum384([]byte(buf.String()))
					digest = sum[:]
				case "SHA-512":
					sum := sha512.Sum512([]byte(buf.String()))
					digest = sum[:]
				case "MURMUR3":
					sum := murmur3Sum128([]byte(buf.String()))
					digest = sum[:]
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("unsupported fingerprint method [%s]", method)
				}
				setIngestPath(doc, target, hex.EncodeToString(digest))
				mutated = true
			}
		}
	case "redact":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
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
				redactOneString := func(strVal string) (string, error) {
					for _, patAny := range patterns {
						patStr, ok := patAny.(string)
						if !ok || patStr == "" {
							continue
						}
						re, grpMap, _, err := compileGrokRegex(patStr, customDefs)
						if err != nil {
							return "", err
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
					return strVal, nil
				}
				switch tv := val.(type) {
				case string:
					redacted, err := redactOneString(tv)
					if err != nil {
						return false, false, procType, procTag, specMap, err
					}
					setIngestPath(doc, target, redacted)
					mutated = true
				case []any:
					outSlice := make([]any, len(tv))
					for idx, elem := range tv {
						elemStr, ok := elem.(string)
						if !ok {
							return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] element at index [%d] is not a string", field, idx)
						}
						redacted, err := redactOneString(elemStr)
						if err != nil {
							return false, false, procType, procTag, specMap, err
						}
						outSlice[idx] = redacted
					}
					setIngestPath(doc, target, outSlice)
					mutated = true
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] of type [%T] is not supported for redact processor", field, val)
				}
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "attachment":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := "attachment"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		removeBinary, _ := specMap["remove_binary"].(bool)
		indexedChars := -1
		if ic, ok := toInt64(specMap["indexed_chars"]); ok {
			indexedChars = int(ic)
		}
		if icField, _ := specMap["indexed_chars_field"].(string); strings.TrimSpace(icField) != "" {
			if icVal, exists := getIngestPath(doc, expandIngestFieldName(icField, doc)); exists && icVal != nil {
				if ic, ok := toInt64(icVal); ok {
					indexedChars = int(ic)
				}
			}
		}
		var allowedProps map[string]bool
		if propsAny, ok := specMap["properties"].([]any); ok && len(propsAny) > 0 {
			allowedProps = make(map[string]bool, len(propsAny))
			for _, p := range propsAny {
				if ps, ok := p.(string); ok && strings.TrimSpace(ps) != "" {
					allowedProps[strings.TrimSpace(ps)] = true
				}
			}
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				rawB64 := strings.TrimSpace(fmt.Sprintf("%v", val))
				decoded, err := base64.StdEncoding.DecodeString(rawB64)
				if err != nil {
					decoded, err = base64.RawStdEncoding.DecodeString(rawB64)
				}
				if err != nil {
					decoded, err = base64.URLEncoding.DecodeString(rawB64)
				}
				if err != nil {
					decoded, err = base64.RawURLEncoding.DecodeString(rawB64)
				}
				if err != nil {
					return false, false, procType, procTag, specMap, fmt.Errorf("failed to base64-decode attachment field [%s]: %w", field, err)
				}
				content := string(decoded)
				runes := []rune(content)
				origRuneLen := len(runes)
				if indexedChars >= 0 && len(runes) > indexedChars {
					content = string(runes[:indexedChars])
				}
				attMap := map[string]any{
					"content":        content,
					"content_length": origRuneLen,
					"content_type":   http.DetectContentType(decoded),
				}
				if allowedProps != nil {
					for k := range attMap {
						if !allowedProps[k] {
							delete(attMap, k)
						}
					}
				}
				setIngestPath(doc, target, attMap)
				if removeBinary && field != target {
					deleteIngestPath(doc, field)
				}
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "csv":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		targetFields, _ := specMap["target_fields"].([]any)
		sepStr, _ := specMap["separator"].(string)
		quoteStr, _ := specMap["quote"].(string)
		trimFlag, _ := specMap["trim"].(bool)
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		emptyVal, hasEmptyVal := specMap["empty_value"]
		if field != "" && len(targetFields) > 0 {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				strVal, isStr := val.(string)
				if !isStr {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
				if strings.TrimSpace(strVal) == "" {
					if hasEmptyVal {
						for _, tfAny := range targetFields {
							if tfName, ok := tfAny.(string); ok && tfName != "" {
								tfName = expandIngestFieldName(tfName, doc)
								setIngestPath(doc, tfName, emptyVal)
							}
						}
						mutated = true
						return mutated, false, procType, procTag, specMap, nil
					}
					return false, false, procType, procTag, specMap, nil
				}
				comma := ','
				if len(sepStr) > 0 {
					if r, sz := utf8.DecodeRuneInString(sepStr); sz > 0 && r != utf8.RuneError {
						comma = r
					} else {
						comma = rune(sepStr[0])
					}
				}
				quoteChar := '"'
				if len(quoteStr) > 0 {
					if r, sz := utf8.DecodeRuneInString(quoteStr); sz > 0 && r != utf8.RuneError {
						quoteChar = r
					} else {
						quoteChar = rune(quoteStr[0])
					}
				}
				record, quotedFlags, err := parseIngestCSVLine(strVal, comma, quoteChar, trimFlag)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				for idx, tfAny := range targetFields {
					tfName, ok := tfAny.(string)
					if !ok || tfName == "" {
						continue
					}
					tfName = expandIngestFieldName(tfName, doc)
					var cell string
					isQuoted := false
					if idx < len(record) {
						cell = record[idx]
						isQuoted = quotedFlags[idx]
					}
					if trimFlag && !isQuoted {
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
			} else if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "user_agent":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := "user_agent"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				uaStr := fmt.Sprintf("%v", val)
				extractUATokenVersion := func(s, prefix string) string {
					idx := strings.Index(s, prefix)
					if idx < 0 {
						return ""
					}
					rem := s[idx+len(prefix):]
					end := 0
					for end < len(rem) && ((rem[end] >= '0' && rem[end] <= '9') || rem[end] == '.' || rem[end] == '_') {
						end++
					}
					return strings.Trim(strings.ReplaceAll(rem[:end], "_", "."), ".")
				}
				uaMap := map[string]any{
					"original": uaStr,
					"name":     "Other",
					"os":       map[string]any{"name": "Other"},
					"device":   map[string]any{"name": "Other"},
				}
				var browserVer string
				switch {
				case strings.Contains(uaStr, "Edg/"):
					uaMap["name"] = "Edge"
					browserVer = extractUATokenVersion(uaStr, "Edg/")
				case strings.Contains(uaStr, "Chrome/"):
					uaMap["name"] = "Chrome"
					browserVer = extractUATokenVersion(uaStr, "Chrome/")
				case strings.Contains(uaStr, "Firefox/"):
					uaMap["name"] = "Firefox"
					browserVer = extractUATokenVersion(uaStr, "Firefox/")
				case strings.Contains(uaStr, "Safari/") && !strings.Contains(uaStr, "Chrome/"):
					uaMap["name"] = "Safari"
					browserVer = extractUATokenVersion(uaStr, "Version/")
					if browserVer == "" {
						browserVer = extractUATokenVersion(uaStr, "Safari/")
					}
				case strings.Contains(uaStr, "curl/"):
					uaMap["name"] = "curl"
					browserVer = extractUATokenVersion(uaStr, "curl/")
				}
				if browserVer != "" {
					uaMap["version"] = browserVer
					vParts := strings.Split(browserVer, ".")
					if len(vParts) >= 1 && vParts[0] != "" {
						uaMap["major"] = vParts[0]
					}
					if len(vParts) >= 2 && vParts[1] != "" {
						uaMap["minor"] = vParts[1]
					}
					if len(vParts) >= 3 && vParts[2] != "" {
						uaMap["patch"] = vParts[2]
					}
				}
				osMap := map[string]any{"name": "Other"}
				var osVer string
				switch {
				case strings.Contains(uaStr, "iPhone") || strings.Contains(uaStr, "iPad") || strings.Contains(uaStr, "iPod"):
					osMap["name"] = "iOS"
					if ver := extractUATokenVersion(uaStr, "OS "); ver != "" {
						osVer = ver
						osMap["version"] = ver
						osMap["full"] = "iOS " + ver
					}
				case strings.Contains(uaStr, "Android"):
					osMap["name"] = "Android"
					if ver := extractUATokenVersion(uaStr, "Android "); ver != "" {
						osVer = ver
						osMap["version"] = ver
						osMap["full"] = "Android " + ver
					}
				case strings.Contains(uaStr, "Mac OS X"):
					osMap["name"] = "Mac OS X"
					if ver := extractUATokenVersion(uaStr, "Mac OS X "); ver != "" {
						osVer = ver
						osMap["version"] = ver
						osMap["full"] = "Mac OS X " + ver
					}
				case strings.Contains(uaStr, "Windows"):
					osMap["name"] = "Windows"
					if ver := extractUATokenVersion(uaStr, "Windows NT "); ver != "" {
						osVer = ver
						osMap["version"] = ver
						osMap["full"] = "Windows " + ver
					}
				case strings.Contains(uaStr, "Linux"):
					osMap["name"] = "Linux"
				}
				if osVer != "" {
					osParts := strings.Split(osVer, ".")
					if len(osParts) >= 1 && osParts[0] != "" {
						osMap["major"] = osParts[0]
					}
					if len(osParts) >= 2 && osParts[1] != "" {
						osMap["minor"] = osParts[1]
					}
					if len(osParts) >= 3 && osParts[2] != "" {
						osMap["patch"] = osParts[2]
					}
				}
				uaMap["os"] = osMap
				switch {
				case strings.Contains(uaStr, "iPhone"):
					uaMap["device"] = map[string]any{"name": "iPhone"}
				case strings.Contains(uaStr, "iPad"):
					uaMap["device"] = map[string]any{"name": "iPad"}
				case strings.Contains(uaStr, "Macintosh"):
					uaMap["device"] = map[string]any{"name": "Mac"}
				}
				if propsAny, ok := specMap["properties"].([]any); ok && len(propsAny) > 0 {
					allowed := make(map[string]bool, len(propsAny))
					for _, p := range propsAny {
						if ps, ok := p.(string); ok && strings.TrimSpace(ps) != "" {
							allowed[strings.ToLower(strings.TrimSpace(ps))] = true
						}
					}
					filtered := make(map[string]any)
					if allowed["original"] {
						filtered["original"] = uaMap["original"]
					}
					if allowed["name"] {
						filtered["name"] = uaMap["name"]
					}
					if allowed["version"] && uaMap["version"] != nil {
						filtered["version"] = uaMap["version"]
					}
					if allowed["major"] && uaMap["major"] != nil {
						filtered["major"] = uaMap["major"]
					}
					if allowed["minor"] && uaMap["minor"] != nil {
						filtered["minor"] = uaMap["minor"]
					}
					if allowed["patch"] && uaMap["patch"] != nil {
						filtered["patch"] = uaMap["patch"]
					}
					if allowed["device"] {
						filtered["device"] = uaMap["device"]
					}
					if allowed["os"] {
						filtered["os"] = osMap
					} else if allowed["os_name"] || allowed["os_major"] || allowed["os_minor"] {
						subOS := make(map[string]any)
						if allowed["os_name"] && osMap["name"] != nil {
							subOS["name"] = osMap["name"]
						}
						if allowed["os_major"] && osMap["major"] != nil {
							subOS["major"] = osMap["major"]
						}
						if allowed["os_minor"] && osMap["minor"] != nil {
							subOS["minor"] = osMap["minor"]
						}
						if len(subOS) > 0 {
							filtered["os"] = subOS
						}
					}
					uaMap = filtered
				}
				setIngestPath(doc, target, uaMap)
				mutated = true
			} else if isExplicitIgnoreMissingFalse(specMap) {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "uri_parts":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := "url"
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		keepOrig := true
		if ko, hasKO := specMap["keep_original"].(bool); hasKO {
			keepOrig = ko
		}
		removeIfSuccess, _ := specMap["remove_if_successful"].(bool)
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				rawURI, isStr := val.(string)
				if !isStr {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is not a string", field)
				}
				parseInput := rawURI
				syntheticScheme := false
				if !strings.Contains(rawURI, "://") {
					slashIdx := strings.IndexByte(rawURI, '/')
					authority := rawURI
					if slashIdx >= 0 {
						authority = rawURI[:slashIdx]
					}
					opaqueScheme := false
					if cIdx := strings.IndexByte(rawURI, ':'); cIdx > 0 {
						switch strings.ToLower(rawURI[:cIdx]) {
						case "mailto", "urn", "tel", "data", "sip", "sips", "xmpp", "news", "about", "javascript", "magnet", "geo", "sms", "blob":
							opaqueScheme = true
						}
					}
					if !opaqueScheme {
						if strings.Contains(authority, "@") {
							parseInput = "http://" + rawURI
							syntheticScheme = true
						} else if colonIdx := strings.IndexByte(authority, ':'); colonIdx > 0 && colonIdx+1 < len(authority) && authority[colonIdx+1] >= '0' && authority[colonIdx+1] <= '9' {
							parseInput = "http://" + rawURI
							syntheticScheme = true
						}
					}
				}
				u, err := url.Parse(parseInput)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				if syntheticScheme {
					u.Scheme = ""
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
					lastSlash := strings.LastIndexByte(u.Path, '/')
					if dotIdx := strings.LastIndexByte(u.Path, '.'); dotIdx > lastSlash+1 && dotIdx+1 < len(u.Path) {
						parts["extension"] = u.Path[dotIdx+1:]
					}
				} else if u.Opaque != "" {
					parts["path"] = u.Opaque
					if strings.EqualFold(u.Scheme, "mailto") {
						if atIdx := strings.IndexByte(u.Opaque, '@'); atIdx > 0 && atIdx+1 < len(u.Opaque) {
							parts["username"] = u.Opaque[:atIdx]
							parts["domain"] = u.Opaque[atIdx+1:]
						}
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
				if removeIfSuccess && field != target {
					deleteIngestPath(doc, field)
				}
				if existingVal, hasExisting := getIngestPath(doc, target); hasExisting {
					if existingMap, ok := existingVal.(map[string]any); ok && existingMap != nil {
						for k, v := range parts {
							existingMap[k] = v
						}
						setIngestPath(doc, target, existingMap)
					} else {
						setIngestPath(doc, target, parts)
					}
				} else {
					setIngestPath(doc, target, parts)
				}
				mutated = true
			} else if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "registered_domain":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		target := field
		if tf, _ := specMap["target_field"].(string); tf != "" {
			target = expandIngestFieldName(tf, doc)
		}
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		if field != "" {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				fqdn := strings.TrimRight(strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val))), ".")
				labels := strings.Split(fqdn, ".")
				out := map[string]any{"domain": fqdn}
				isIP := net.ParseIP(strings.Trim(fqdn, "[]")) != nil
				isSecondLevelPublicSuffix := func(sld string) bool {
					switch sld {
					case "co", "com", "org", "gov", "govt", "ac", "net", "edu", "mil",
						"or", "ne", "go", "ed", "gr", "lg", "gob", "nom", "ind",
						"res", "ernet", "nic", "gen", "biz", "info", "per", "id", "asn", "me",
						"sch", "nhs", "police", "mod", "ltd", "plc", "geek", "kiwi", "maori", "iwi", "cri", "health":
						return true
					}
					return false
				}
				if !isIP && len(labels) >= 2 && labels[0] != "" && labels[len(labels)-1] != "" {
					tld := labels[len(labels)-1]
					if len(labels) == 2 && len(tld) == 2 && len(labels[0]) <= 5 && isSecondLevelPublicSuffix(labels[0]) {
						out["top_level_domain"] = labels[0] + "." + tld
					} else {
						regDom := labels[len(labels)-2] + "." + tld
						if len(labels) >= 3 && len(tld) == 2 && len(labels[len(labels)-2]) <= 5 && isSecondLevelPublicSuffix(labels[len(labels)-2]) {
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
				}
				setIngestPath(doc, target, out)
				mutated = true
			} else if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "network_direction":
		m, err := executeNetworkDirectionProcessor(doc, specMap)
		if err != nil {
			return false, false, procType, procTag, specMap, err
		}
		if m {
			mutated = true
		}
	case "community_id":
		m, err := executeCommunityIDProcessor(doc, specMap)
		if err != nil {
			return false, false, procType, procTag, specMap, err
		}
		if m {
			mutated = true
		}
	case "geoip":
		m, err := executeGeoIPProcessor(doc, specMap)
		if err != nil {
			return false, false, procType, procTag, specMap, err
		}
		if m {
			mutated = true
		}
	case "enrich":
		m, err := executeEnrichProcessor(s, doc, specMap)
		if err != nil {
			return false, false, procType, procTag, specMap, err
		}
		if m {
			mutated = true
		}
	case "foreach":
		field, _ := specMap["field"].(string)
		field = expandIngestFieldName(field, doc)
		ignoreMissing, _ := specMap["ignore_missing"].(bool)
		var subProcs []any
		if subProc, ok := specMap["processor"].(map[string]any); ok && subProc != nil {
			subProcs = []any{subProc}
		} else if sps, ok := specMap["processors"].([]any); ok {
			subProcs = sps
		}
		if field != "" && len(subProcs) > 0 {
			if val, exists := getIngestPath(doc, field); exists && val != nil {
				var prevVal, prevKey any
				var hadPrevVal, hadPrevKey bool
				if origIngest, ok := doc["_ingest"].(map[string]any); ok && origIngest != nil {
					prevVal, hadPrevVal = origIngest["_value"]
					prevKey, hadPrevKey = origIngest["_key"]
				}
				restoreIngestVal := func() {
					if curIngest, ok := doc["_ingest"].(map[string]any); ok && curIngest != nil {
						if hadPrevVal {
							curIngest["_value"] = prevVal
						} else {
							delete(curIngest, "_value")
						}
						if hadPrevKey {
							curIngest["_key"] = prevKey
						} else {
							delete(curIngest, "_key")
						}
					}
				}
				switch coll := val.(type) {
				case []any:
					outArr := make([]any, len(coll))
					copy(outArr, coll)
					elemChanged := false
					for idx, elem := range coll {
						ingestMeta, _ := doc["_ingest"].(map[string]any)
						if ingestMeta == nil {
							ingestMeta = make(map[string]any)
						}
						initVal := deepCloneIngestValue(elem)
						initValSnapshot := deepCloneIngestValue(elem)
						ingestMeta["_value"] = initVal
						delete(ingestMeta, "_key")
						doc["_ingest"] = ingestMeta
						subMut, subDropped, subErr := runIngestProcessorList(s, doc, subProcs, depth+1, trace)
						if subMut {
							mutated = true
						}
						if subErr != nil {
							if elemChanged {
								if _, stillExists := getIngestPath(doc, field); stillExists {
									setIngestPath(doc, field, outArr)
									mutated = true
								}
							}
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
						if !reflect.DeepEqual(outArr[idx], initValSnapshot) {
							elemChanged = true
							if _, stillExists := getIngestPath(doc, field); stillExists {
								setIngestPath(doc, field, outArr)
								mutated = true
							}
						}
					}
					restoreIngestVal()
					if elemChanged {
						if _, stillExists := getIngestPath(doc, field); stillExists {
							setIngestPath(doc, field, outArr)
							mutated = true
						}
					}
				case map[string]any:
					keys := make([]string, 0, len(coll))
					for k := range coll {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					changedEntries := make(map[string]any)
					deletedKeys := make(map[string]bool)
					for _, k := range keys {
						elem := coll[k]
						ingestMeta, _ := doc["_ingest"].(map[string]any)
						if ingestMeta == nil {
							ingestMeta = make(map[string]any)
						}
						initVal := deepCloneIngestValue(elem)
						initValSnapshot := deepCloneIngestValue(elem)
						ingestMeta["_key"] = k
						ingestMeta["_value"] = initVal
						doc["_ingest"] = ingestMeta
						subMut, subDropped, subErr := runIngestProcessorList(s, doc, subProcs, depth+1, trace)
						if subMut {
							mutated = true
						}
						if subErr != nil {
							return mutated, false, procType, procTag, specMap, subErr
						}
						if subDropped {
							restoreIngestVal()
							return mutated, true, procType, procTag, specMap, nil
						}
						if curIngest, ok := doc["_ingest"].(map[string]any); ok {
							newVal, hasVal := curIngest["_value"]
							rawKey, hasKey := curIngest["_key"]
							if !hasVal || !hasKey || rawKey == nil {
								deletedKeys[k] = true
							} else {
								newKey := fmt.Sprintf("%v", rawKey)
								if newKey != k {
									deletedKeys[k] = true
									changedEntries[newKey] = newVal
								} else if !reflect.DeepEqual(newVal, initValSnapshot) {
									changedEntries[k] = newVal
								}
							}
						}
					}
					restoreIngestVal()
					if len(changedEntries) > 0 || len(deletedKeys) > 0 {
						if curMapAny, stillExists := getIngestPath(doc, field); stillExists {
							if curMap, okM := curMapAny.(map[string]any); okM {
								for dk := range deletedKeys {
									delete(curMap, dk)
								}
								for k, v := range changedEntries {
									curMap[k] = v
								}
								mutated = true
							}
						}
					}
				default:
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is neither an array nor an object", field)
				}
			} else if !ignoreMissing {
				if exists && val == nil {
					return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is null, cannot iterate over it", field)
				}
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
		}
	case "script":
		resolvedSpec := specMap
		if s != nil {
			if rawID, _ := specMap["id"].(string); strings.TrimSpace(rawID) != "" {
				if src, _ := specMap["source"].(string); strings.TrimSpace(src) == "" {
					if inl, _ := specMap["inline"].(string); strings.TrimSpace(inl) == "" {
						if _, ok := s.lookupStoredScript(strings.TrimSpace(rawID)); !ok {
							return false, false, procType, procTag, specMap, fmt.Errorf("cannot execute stored script [%s] because it does not exist", strings.TrimSpace(rawID))
						}
					}
				}
			}
			if m, ok := s.resolveStoredScriptSpec(specMap).(map[string]any); ok {
				resolvedSpec = m
			}
		}
		src, _ := resolvedSpec["source"].(string)
		if src == "" {
			src, _ = resolvedSpec["inline"].(string)
		}
		params, _ := resolvedSpec["params"].(map[string]any)
		if src != "" {
			origMetaIndex, _ := doc["_index"].(string)
			origMetaID := ""
			if v, ok := doc["_id"]; ok && v != nil {
				origMetaID = fmt.Sprintf("%v", v)
			}
			origMetaRouting := ""
			if v, ok := doc["_routing"]; ok && v != nil {
				origMetaRouting = fmt.Sprintf("%v", v)
			}
			origMetaVersion, hadOrigVersion := toInt64(doc["_version"])
			savedIngestOrig := doc["__internal_ingest_orig"]
			savedIngestMeta := doc["_ingest"]
			origMetaMap, _ := savedIngestOrig.(map[string]any)
			hadUserIndex, _ := origMetaMap["_had_orig_index"].(bool)
			hadUserID, _ := origMetaMap["_had_orig_id"].(bool)
			hadUserRouting, _ := origMetaMap["_had_orig_routing"].(bool)

			cleanDoc := make(map[string]any, len(doc)+1)
			for k, v := range doc {
				switch k {
				case "__internal_ingest_orig", "_version":
					continue
				case "_index":
					if !hadUserIndex {
						continue
					}
				case "_id":
					if !hadUserID {
						continue
					}
				case "_routing":
					if !hadUserRouting {
						continue
					}
				}
				cleanDoc[k] = v
			}
			_, hadOrigOp := cleanDoc["op"]
			normSrc := rewriteIngestCtxReferencesWithOp(src, !hadOrigOp)
			docBytes, err := json.Marshal(cleanDoc)
			if err == nil {
				upd := &painless.UpdateRequest{
					Script: &painless.ScriptSpec{
						Source: normSrc,
						Params: params,
					},
					MetaID:            origMetaID,
					MetaIndex:         origMetaIndex,
					MetaRouting:       origMetaRouting,
					MetaVersion:       origMetaVersion,
					AllowMetaMutation: true,
				}
				mutatedBytes, opRes, err := painless.ApplyUpdateWithResult(docBytes, upd, true)
				if err != nil {
					return false, false, procType, procTag, specMap, err
				}
				if opRes == "deleted" {
					return false, true, procType, procTag, specMap, nil
				}
				applyMetaToTarget := func(target map[string]any) bool {
					metaChanged := upd.MetaIndex != origMetaIndex
					if upd.MetaIndex == "" {
						if !hadUserIndex {
							delete(target, "_index")
						}
					} else {
						target["_index"] = upd.MetaIndex
					}
					if upd.MetaID != origMetaID {
						metaChanged = true
					}
					if upd.MetaID == "" {
						if !hadUserID {
							delete(target, "_id")
						}
					} else {
						target["_id"] = upd.MetaID
					}
					if upd.MetaRouting != origMetaRouting {
						metaChanged = true
					}
					if upd.MetaRouting == "" {
						if !hadUserRouting {
							delete(target, "_routing")
						}
					} else {
						target["_routing"] = upd.MetaRouting
					}
					if upd.MetaVersionMutated {
						metaChanged = true
						if upd.MetaVersionNil {
							delete(target, "_version")
						} else {
							target["_version"] = upd.MetaVersion
						}
					} else if hadOrigVersion {
						target["_version"] = origMetaVersion
					}
					if savedIngestOrig != nil {
						target["__internal_ingest_orig"] = savedIngestOrig
					}
					if target["_ingest"] == nil && savedIngestMeta != nil {
						target["_ingest"] = savedIngestMeta
					}
					return metaChanged
				}
				if opRes == "noop" {
					if applyMetaToTarget(doc) {
						mutated = true
					}
				} else {
					var nextDoc map[string]any
					dec2 := json.NewDecoder(bytes.NewReader(mutatedBytes))
					dec2.UseNumber()
					if err := dec2.Decode(&nextDoc); err == nil && nextDoc != nil {
						_ = applyMetaToTarget(nextDoc)
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
	case "inference":
		modelID, _ := specMap["model_id"].(string)
		modelID = strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(modelID, doc)))
		if modelID == "" {
			return false, false, procType, procTag, specMap, fmt.Errorf("[model_id] required property is missing")
		}
		targetField, _ := specMap["target_field"].(string)
		targetField = strings.TrimSpace(expandIngestFieldName(targetField, doc))
		if targetField == "" {
			targetField = "ml.inference"
		}
		fieldMap, _ := specMap["field_map"].(map[string]any)
		var inputVal any
		hasInput := false
		if len(fieldMap) > 0 {
			for srcField := range fieldMap {
				if v, ok := getIngestPath(doc, srcField); ok && v != nil {
					inputVal = v
					hasInput = true
					break
				}
			}
			if !hasInput {
				if ignoreMissing, _ := specMap["ignore_missing"].(bool); ignoreMissing {
					return false, false, procType, procTag, specMap, nil
				}
			}
		}
		resultObj := map[string]any{
			"model_id":        modelID,
			"predicted_value": inputVal,
		}
		if resultObj["predicted_value"] == nil {
			resultObj["predicted_value"] = modelID
		}
		setIngestPath(doc, targetField, resultObj)
		mutated = true
	case "set_security_user":
		field, _ := specMap["field"].(string)
		field = strings.TrimSpace(expandIngestFieldName(field, doc))
		if field == "" {
			return false, false, procType, procTag, specMap, fmt.Errorf("[field] required property is missing")
		}
		userObj := map[string]any{
			"username":  "elastic",
			"roles":     []any{"superuser"},
			"full_name": nil,
			"email":     nil,
			"metadata":  map[string]any{},
			"enabled":   true,
			"authentication_realm": map[string]any{
				"name": "default_native",
				"type": "native",
			},
			"lookup_realm": map[string]any{
				"name": "default_native",
				"type": "native",
			},
			"authentication_type": "realm",
		}
		if props, ok := specMap["properties"].([]any); ok && len(props) > 0 {
			allowed := make(map[string]bool, len(props))
			for _, p := range props {
				if ps, ok := p.(string); ok {
					allowed[ps] = true
				}
			}
			for k := range userObj {
				if !allowed[k] {
					delete(userObj, k)
				}
			}
		}
		setIngestPath(doc, field, userObj)
		mutated = true
	case "circle":
		field, _ := specMap["field"].(string)
		field = strings.TrimSpace(expandIngestFieldName(field, doc))
		targetField, _ := specMap["target_field"].(string)
		targetField = strings.TrimSpace(expandIngestFieldName(targetField, doc))
		if targetField == "" {
			targetField = field
		}
		shapeType, _ := specMap["shape_type"].(string)
		if shapeType == "" {
			shapeType = "geo_shape"
		}
		errorDist, okED := toFloat64(specMap["error_distance"])
		if !okED || errorDist <= 0 {
			errorDist = 10.0
		}
		val, exists := getIngestPath(doc, field)
		if !exists || val == nil {
			ignoreMissing, _ := specMap["ignore_missing"].(bool)
			if !ignoreMissing {
				return false, false, procType, procTag, specMap, fmt.Errorf("field [%s] is missing", field)
			}
			return false, false, procType, procTag, specMap, nil
		}
		polyVal, err := convertIngestCircleToPolygon(val, shapeType, errorDist)
		if err != nil {
			return false, false, procType, procTag, specMap, err
		}
		setIngestPath(doc, targetField, polyVal)
		mutated = true
	case "terminate":
		doc["__internal_ingest_terminated"] = true
	case "reroute":
		prevIdx, _ := doc["_index"].(string)
		removeFieldsExplicit, hasRemoveFields := specMap["remove_fields"].(bool)
		dest, _ := specMap["destination"].(string)
		if dest != "" {
			dest = strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(dest, doc)))
		} else {
			dsType := "logs"
			if v, ok := getIngestPath(doc, "data_stream.type"); ok && v != nil {
				if sVal := strings.TrimSpace(fmt.Sprintf("%v", v)); sVal != "" {
					dsType = strings.ReplaceAll(sVal, "-", "_")
				}
			}
			resolveReroutePart := func(rawSpec any, docPath string, defaultVal string) string {
				switch rv := rawSpec.(type) {
				case string:
					if rv != "" {
						if strings.Contains(rv, "{{") {
							if exp := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(rv, doc))); exp != "" {
								return strings.ReplaceAll(exp, "-", "_")
							}
						} else {
							return strings.ReplaceAll(strings.TrimSpace(rv), "-", "_")
						}
					}
				case []any:
					for _, item := range rv {
						sItem, okS := item.(string)
						if !okS {
							sItem = fmt.Sprintf("%v", item)
						}
						sItem = strings.TrimSpace(sItem)
						if sItem == "" {
							continue
						}
						if strings.Contains(sItem, "{{") {
							if exp := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(sItem, doc))); exp != "" {
								return strings.ReplaceAll(exp, "-", "_")
							}
							continue
						}
						if v, ok := getIngestPath(doc, sItem); ok {
							if v != nil {
								if vs := strings.TrimSpace(fmt.Sprintf("%v", v)); vs != "" {
									if hasRemoveFields && removeFieldsExplicit {
										deleteIngestPath(doc, sItem)
									}
									return strings.ReplaceAll(vs, "-", "_")
								}
							}
							continue
						}
					}
				}
				out := defaultVal
				if v, ok := getIngestPath(doc, docPath); ok && v != nil {
					if sVal := strings.TrimSpace(fmt.Sprintf("%v", expandIngestTemplate(fmt.Sprintf("%v", v), doc))); sVal != "" {
						out = strings.ReplaceAll(sVal, "-", "_")
					}
					if !hasRemoveFields || removeFieldsExplicit {
						deleteIngestPath(doc, docPath)
					}
				}
				return out
			}
			dataset := resolveReroutePart(specMap["dataset"], "data_stream.dataset", "generic")
			namespace := resolveReroutePart(specMap["namespace"], "data_stream.namespace", "default")
			if dsObj, ok := getIngestPath(doc, "data_stream"); ok {
				if dsMap, isMap := dsObj.(map[string]any); isMap && len(dsMap) == 0 {
					deleteIngestPath(doc, "data_stream")
				}
			}
			dest = fmt.Sprintf("%s-%s-%s", dsType, dataset, namespace)
		}
		if dest != "" {
			doc["_index"] = dest
			mutated = true
			if dest != prevIdx {
				doc["__internal_ingest_rerouted"] = true
			}
		}
	default:
		return false, false, procType, procTag, specMap, fmt.Errorf("no processor type exists with name [%s]", procType)
	}
	return mutated, false, procType, procTag, specMap, nil
}

func parseIngestCircleRadius(raw any, shapeType string) (float64, error) {
	if fv, ok := toFloat64(raw); ok {
		if fv <= 0 {
			return 0, fmt.Errorf("circle radius must be positive")
		}
		if shapeType == "geo_shape" {
			return fv / 111320.0, nil
		}
		return fv, nil
	}
	s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", raw)))
	if s == "" {
		return 0, fmt.Errorf("circle radius is empty")
	}
	mult := 1.0
	numPart := s
	switch {
	case strings.HasSuffix(s, "km"):
		mult = 1000.0
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "km"))
	case strings.HasSuffix(s, "mi"):
		mult = 1609.344
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "mi"))
	case strings.HasSuffix(s, "yd"):
		mult = 0.9144
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "yd"))
	case strings.HasSuffix(s, "ft"):
		mult = 0.3048
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "ft"))
	case strings.HasSuffix(s, "cm"):
		mult = 0.01
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "cm"))
	case strings.HasSuffix(s, "mm"):
		mult = 0.001
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "mm"))
	case strings.HasSuffix(s, "m"):
		mult = 1.0
		numPart = strings.TrimSpace(strings.TrimSuffix(s, "m"))
	}
	fv, err := strconv.ParseFloat(numPart, 64)
	if err != nil || fv <= 0 {
		return 0, fmt.Errorf("invalid circle radius [%v]", raw)
	}
	distMeters := fv * mult
	if shapeType == "geo_shape" {
		return distMeters / 111320.0, nil
	}
	return distMeters, nil
}

func convertIngestCircleToPolygon(val any, shapeType string, errorDist float64) (any, error) {
	steps := 16
	if errorDist > 0 && errorDist < 1.0 {
		steps = 32
	}
	switch v := val.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "CIRCLE") {
			return nil, fmt.Errorf("illegal_argument_exception: invalid WKT circle [%s]", v)
		}
		openIdx := strings.IndexByte(trimmed, '(')
		closeIdx := strings.LastIndexByte(trimmed, ')')
		if openIdx < 0 || closeIdx <= openIdx {
			return nil, fmt.Errorf("illegal_argument_exception: invalid WKT circle [%s]", v)
		}
		inner := strings.TrimSpace(trimmed[openIdx+1 : closeIdx])
		inner = strings.ReplaceAll(inner, ",", " ")
		parts := strings.Fields(inner)
		if len(parts) < 3 {
			return nil, fmt.Errorf("illegal_argument_exception: WKT circle requires (x y radius), got [%s]", v)
		}
		cx, err1 := strconv.ParseFloat(parts[0], 64)
		cy, err2 := strconv.ParseFloat(parts[1], 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("illegal_argument_exception: invalid circle center coordinates in [%s]", v)
		}
		radStr := strings.Join(parts[2:], "")
		degRad, err := parseIngestCircleRadius(radStr, shapeType)
		if err != nil {
			return nil, fmt.Errorf("illegal_argument_exception: %v", err)
		}
		coords := make([]string, 0, steps+1)
		var firstPt string
		for i := 0; i < steps; i++ {
			angle := 2.0 * math.Pi * float64(i) / float64(steps)
			px := cx + degRad*math.Cos(angle)
			py := cy + degRad*math.Sin(angle)
			pt := fmt.Sprintf("%.6f %.6f", px, py)
			if i == 0 {
				firstPt = pt
			}
			coords = append(coords, pt)
		}
		coords = append(coords, firstPt)
		return "POLYGON ((" + strings.Join(coords, ", ") + "))", nil

	case map[string]any:
		tStr, _ := v["type"].(string)
		if !strings.EqualFold(strings.TrimSpace(tStr), "circle") {
			return nil, fmt.Errorf("illegal_argument_exception: expected GeoJSON Circle, got [%s]", tStr)
		}
		rawCoords, ok := v["coordinates"].([]any)
		if !ok || len(rawCoords) < 2 {
			return nil, fmt.Errorf("illegal_argument_exception: circle coordinates must be [lon, lat]")
		}
		cx, ok1 := toFloat64(rawCoords[0])
		cy, ok2 := toFloat64(rawCoords[1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("illegal_argument_exception: invalid circle coordinates")
		}
		degRad, err := parseIngestCircleRadius(v["radius"], shapeType)
		if err != nil {
			return nil, fmt.Errorf("illegal_argument_exception: %v", err)
		}
		ring := make([]any, 0, steps+1)
		var firstCoord []any
		for i := 0; i < steps; i++ {
			angle := 2.0 * math.Pi * float64(i) / float64(steps)
			px := math.Round((cx+degRad*math.Cos(angle))*1e6) / 1e6
			py := math.Round((cy+degRad*math.Sin(angle))*1e6) / 1e6
			pt := []any{px, py}
			if i == 0 {
				firstCoord = pt
			}
			ring = append(ring, pt)
		}
		ring = append(ring, firstCoord)
		return map[string]any{
			"type":        "Polygon",
			"coordinates": []any{ring},
		}, nil

	default:
		return nil, fmt.Errorf("illegal_argument_exception: unsupported circle value type")
	}
}

func compactIngestMap(v map[string]any) map[string]any {
	out := make(map[string]any, len(v))
	for k, el := range v {
		if cEl, keep := compactIngestElement(el); keep {
			out[k] = cEl
		}
	}
	return out
}

func compactIngestSlice(v []any) []any {
	out := make([]any, 0, len(v))
	for _, el := range v {
		if cEl, keep := compactIngestElement(el); keep {
			out = append(out, cEl)
		}
	}
	return out
}

func compactIngestElement(el any) (any, bool) {
	if el == nil || el == "" {
		return nil, false
	}
	switch sub := el.(type) {
	case map[string]any:
		cm := compactIngestMap(sub)
		if len(cm) == 0 {
			return nil, false
		}
		return cm, true
	case []any:
		cs := compactIngestSlice(sub)
		if len(cs) == 0 {
			return nil, false
		}
		return cs, true
	default:
		return el, true
	}
}

func shredErrorType(err error) string {
	if err != nil && strings.HasPrefix(err.Error(), "strict_dynamic_mapping_exception:") {
		return "strict_dynamic_mapping_exception"
	}
	return "mapper_parsing_exception"
}

func validateJSONNoDuplicateKeys(input string, strict bool) error {
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	var checkValue func() error
	checkValue = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := make(map[string]bool)
				for dec.More() {
					kt, kErr := dec.Token()
					if kErr != nil {
						return kErr
					}
					keyStr, isStr := kt.(string)
					if !isStr {
						return fmt.Errorf("expected string key in json object")
					}
					if seen[keyStr] {
						return fmt.Errorf("duplicate field '%s'", keyStr)
					}
					seen[keyStr] = true
					if vErr := checkValue(); vErr != nil {
						return vErr
					}
				}
				endTok, endErr := dec.Token()
				if endErr != nil || endTok != json.Delim('}') {
					return fmt.Errorf("malformed json object")
				}
			case '[':
				for dec.More() {
					if vErr := checkValue(); vErr != nil {
						return vErr
					}
				}
				endTok, endErr := dec.Token()
				if endErr != nil || endTok != json.Delim(']') {
					return fmt.Errorf("malformed json array")
				}
			}
		}
		return nil
	}
	if err := checkValue(); err != nil {
		return err
	}
	if strict {
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("unexpected trailing token in json")
		}
	}
	return nil
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
	if im, ok := doc["__internal_ingest_orig"].(map[string]any); ok {
		if b, ok := im["_had_orig_index"].(bool); ok {
			if b {
				cp["_index"] = im["_orig_index_val"]
			} else {
				delete(cp, "_index")
			}
		}
		if b, ok := im["_had_orig_id"].(bool); ok {
			if b {
				cp["_id"] = im["_orig_id_val"]
			} else {
				delete(cp, "_id")
			}
		}
		if b, ok := im["_had_orig_routing"].(bool); ok {
			if b {
				cp["_routing"] = im["_orig_routing_val"]
			} else {
				delete(cp, "_routing")
			}
		}
		if b, ok := im["_had_orig_version"].(bool); ok {
			if b {
				cp["_version"] = im["_orig_version_val"]
			} else {
				delete(cp, "_version")
			}
		}
	}
	delete(cp, "__internal_ingest_orig")
	delete(cp, "__internal_ingest_terminated")
	delete(cp, "__internal_ingest_rerouted")
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
		var prevMsg, prevType, prevTag, prevPipe any
		var hadPrevMsg, hadPrevType, hadPrevTag, hadPrevPipe bool
		if preIngest, ok := doc["_ingest"].(map[string]any); ok && preIngest != nil {
			prevMsg, hadPrevMsg = preIngest["on_failure_message"]
			prevType, hadPrevType = preIngest["on_failure_processor_type"]
			prevTag, hadPrevTag = preIngest["on_failure_processor_tag"]
			prevPipe, hadPrevPipe = preIngest["on_failure_pipeline"]
		}
		traceLenBefore := 0
		if trace != nil {
			traceLenBefore = len(*trace)
		}
		m, dropped, procType, procTag, specMap, procErr := executeSingleIngestProcessor(s, doc, pMap, depth, trace)
		if m {
			mutated = true
		}
		if trace != nil && procType != "" && (procType != "pipeline" || (procErr != nil && len(*trace) == traceLenBefore)) {
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
				stepTS := ""
				if ingMap, ok := doc["_ingest"].(map[string]any); ok {
					if ts, ok := ingMap["timestamp"].(string); ok {
						stepTS = ts
					} else if tsAny, ok := ingMap["timestamp"]; ok && tsAny != nil {
						stepTS = fmt.Sprintf("%v", tsAny)
					}
				}
				entry["status"] = "success"
				entryDoc := map[string]any{
					"_index":   stepIdx,
					"_version": "-3",
					"_id":      stepID,
					"_source":  snapshotIngestDoc(doc),
				}
				if ingMap, ok := doc["_ingest"].(map[string]any); ok && len(ingMap) > 0 {
					stepIngest := make(map[string]any, len(ingMap))
					for k, v := range ingMap {
						stepIngest[k] = v
					}
					if stepTS != "" {
						stepIngest["timestamp"] = stepTS
					}
					entryDoc["_ingest"] = stepIngest
				} else if stepTS != "" {
					entryDoc["_ingest"] = map[string]any{"timestamp": stepTS}
				}
				entry["doc"] = entryDoc
			}
			*trace = append(*trace, entry)
		}
		if dropped {
			return mutated, true, nil
		}
		if terminated, _ := doc["__internal_ingest_terminated"].(bool); terminated {
			delete(doc, "__internal_ingest_terminated")
			return mutated, false, nil
		}
		if rerouted, _ := doc["__internal_ingest_rerouted"].(bool); rerouted {
			if depth == 0 {
				delete(doc, "__internal_ingest_rerouted")
			}
			return mutated, false, nil
		}
		if procErr != nil {
			activePipeName := ""
			if om, ok := doc["__internal_ingest_orig"].(map[string]any); ok && om != nil {
				activePipeName, _ = om["_active_pipeline"].(string)
			}
			ignoreFail, _ := specMap["ignore_failure"].(bool)
			if !ignoreFail {
				ignoreFail, _ = pMap["ignore_failure"].(bool)
			}
			if ignoreFail {
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					if procType == "foreach" {
						delete(curIngest, "_value")
						delete(curIngest, "_key")
					}
					if hadPrevMsg {
						curIngest["on_failure_message"] = prevMsg
					} else {
						delete(curIngest, "on_failure_message")
					}
					if hadPrevType {
						curIngest["on_failure_processor_type"] = prevType
					} else {
						delete(curIngest, "on_failure_processor_type")
					}
					if hadPrevTag {
						curIngest["on_failure_processor_tag"] = prevTag
					} else {
						delete(curIngest, "on_failure_processor_tag")
					}
					if hadPrevPipe {
						curIngest["on_failure_pipeline"] = prevPipe
					} else {
						delete(curIngest, "on_failure_pipeline")
					}
				}
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
				curType, hasCurType := ingestMeta["on_failure_processor_type"]
				curTag := ingestMeta["on_failure_processor_tag"]
				innerUpdated := hasCurType && (!hadPrevType || curType != prevType || curTag != prevTag)
				ingestMeta["on_failure_message"] = procErr.Error()
				if (procType != "pipeline" && procType != "foreach") || !innerUpdated {
					ingestMeta["on_failure_processor_type"] = procType
					ingestMeta["on_failure_processor_tag"] = procTag
					if activePipeName != "" {
						ingestMeta["on_failure_pipeline"] = activePipeName
					}
				}
				doc["_ingest"] = ingestMeta
				mutated = true
				subMut, subDropped, subErr := runIngestProcessorList(s, doc, onFail, depth+1, trace)
				if subMut {
					mutated = true
				}
				if procType == "foreach" {
					if curIngest, ok := doc["_ingest"].(map[string]any); ok {
						delete(curIngest, "_value")
						delete(curIngest, "_key")
					}
				}
				if subDropped {
					return mutated, true, nil
				}
				if subErr != nil {
					return mutated, false, subErr
				}
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					if hadPrevMsg {
						curIngest["on_failure_message"] = prevMsg
					} else {
						delete(curIngest, "on_failure_message")
					}
					if hadPrevType {
						curIngest["on_failure_processor_type"] = prevType
					} else {
						delete(curIngest, "on_failure_processor_type")
					}
					if hadPrevTag {
						curIngest["on_failure_processor_tag"] = prevTag
					} else {
						delete(curIngest, "on_failure_processor_tag")
					}
					if hadPrevPipe {
						curIngest["on_failure_pipeline"] = prevPipe
					} else {
						delete(curIngest, "on_failure_pipeline")
					}
				}
				continue
			}
			if procType == "foreach" {
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					delete(curIngest, "_value")
					delete(curIngest, "_key")
				}
			}
			ingestMeta, _ := doc["_ingest"].(map[string]any)
			if ingestMeta == nil {
				ingestMeta = make(map[string]any)
			}
			curType, hasCurType := ingestMeta["on_failure_processor_type"]
			curTag := ingestMeta["on_failure_processor_tag"]
			innerUpdated := hasCurType && (!hadPrevType || curType != prevType || curTag != prevTag)
			ingestMeta["on_failure_message"] = procErr.Error()
			if (procType != "pipeline" && procType != "foreach") || !innerUpdated {
				if procType != "" {
					ingestMeta["on_failure_processor_type"] = procType
				}
				ingestMeta["on_failure_processor_tag"] = procTag
				if activePipeName != "" {
					ingestMeta["on_failure_pipeline"] = activePipeName
				}
			}
			doc["_ingest"] = ingestMeta
			return mutated, false, procErr
		}
	}
	return mutated, false, nil
}

func applyIngestPipelineSpecWithNameAndRoutingAndIngestMeta(s *Server, pipe map[string]any, pipelineName, indexName, docID, initialRouting string, raw json.RawMessage, verbose bool, initialIngestMeta map[string]any) (json.RawMessage, string, string, string, string, bool, []map[string]any, map[string]any, error) {
	if pipe == nil || len(bytes.TrimSpace(raw)) == 0 {
		return raw, indexName, docID, "", initialRouting, false, nil, initialIngestMeta, nil
	}
	procs, _ := pipe["processors"].([]any)
	if len(procs) == 0 {
		if verbose {
			return raw, indexName, docID, "", initialRouting, false, []map[string]any{}, initialIngestMeta, nil
		}
		return raw, indexName, docID, "", initialRouting, false, nil, initialIngestMeta, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return raw, indexName, docID, "", initialRouting, false, nil, initialIngestMeta, err
	}
	origIndexVal, hadOrigIndex := doc["_index"]
	origIDVal, hadOrigID := doc["_id"]
	origRoutingVal, hadOrigRouting := doc["_routing"]
	origVersionVal, hadOrigVersion := doc["_version"]
	if indexName != "" {
		doc["_index"] = indexName
	} else {
		delete(doc, "_index")
	}
	if docID != "" {
		doc["_id"] = docID
	} else {
		delete(doc, "_id")
	}
	if initialRouting != "" {
		doc["_routing"] = initialRouting
	} else {
		delete(doc, "_routing")
	}
	ingestMeta, _ := doc["_ingest"].(map[string]any)
	if ingestMeta == nil {
		ingestMeta = make(map[string]any)
	}
	for k, v := range initialIngestMeta {
		if _, exists := ingestMeta[k]; !exists {
			ingestMeta[k] = v
		}
	}
	if _, hasTS := ingestMeta["timestamp"]; !hasTS {
		ingestMeta["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	doc["_ingest"] = ingestMeta
	doc["__internal_ingest_orig"] = map[string]any{
		"_had_orig_index":   hadOrigIndex,
		"_orig_index_val":   origIndexVal,
		"_had_orig_id":      hadOrigID,
		"_orig_id_val":      origIDVal,
		"_had_orig_routing": hadOrigRouting,
		"_orig_routing_val": origRoutingVal,
		"_had_orig_version": hadOrigVersion,
		"_orig_version_val": origVersionVal,
		"_active_pipeline":  pipelineName,
	}

	var trace []map[string]any
	var tracePtr *[]map[string]any
	if verbose {
		trace = make([]map[string]any, 0)
		tracePtr = &trace
	}
	mutated, dropped, procErr := runIngestProcessorList(s, doc, procs, 0, tracePtr)
	delete(doc, "__internal_ingest_rerouted")
	if dropped {
		return json.RawMessage(`{}`), indexName, docID, "", initialRouting, true, trace, nil, nil
	}
	if procErr != nil {
		if pipeOnFail, ok := pipe["on_failure"].([]any); ok && len(pipeOnFail) > 0 {
			ingestMeta, _ := doc["_ingest"].(map[string]any)
			if ingestMeta == nil {
				ingestMeta = make(map[string]any)
			}
			ingestMeta["on_failure_message"] = procErr.Error()
			if _, hasFP := ingestMeta["on_failure_pipeline"]; !hasFP && pipelineName != "" {
				ingestMeta["on_failure_pipeline"] = pipelineName
			}
			doc["_ingest"] = ingestMeta
			doc["__internal_ingest_orig"] = map[string]any{
				"_had_orig_index":   hadOrigIndex,
				"_orig_index_val":   origIndexVal,
				"_had_orig_id":      hadOrigID,
				"_orig_id_val":      origIDVal,
				"_had_orig_routing": hadOrigRouting,
				"_orig_routing_val": origRoutingVal,
				"_had_orig_version": hadOrigVersion,
				"_orig_version_val": origVersionVal,
				"_active_pipeline":  pipelineName,
			}
			mutated = true
			subMut, subDropped, subErr := runIngestProcessorList(s, doc, pipeOnFail, 1, tracePtr)
			delete(doc, "__internal_ingest_rerouted")
			if subMut {
				mutated = true
			}
			if subDropped {
				return json.RawMessage(`{}`), indexName, docID, "", initialRouting, true, trace, nil, nil
			}
			if subErr == nil {
				if curIngest, ok := doc["_ingest"].(map[string]any); ok {
					delete(curIngest, "on_failure_message")
					delete(curIngest, "on_failure_processor_type")
					delete(curIngest, "on_failure_processor_tag")
					delete(curIngest, "on_failure_pipeline")
				}
			}
			procErr = subErr
		}
		if procErr != nil {
			delete(doc, "__internal_ingest_orig")
			return raw, indexName, docID, "", initialRouting, false, trace, nil, procErr
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
		} else if docID != "" {
			outID = esast.NextAutoID()
		}
	} else if docID != "" {
		outID = esast.NextAutoID()
	}
	outRouting := ""
	if v, ok := doc["_routing"]; ok && v != nil {
		outRouting = fmt.Sprintf("%v", v)
	}
	outIngestTS := ""
	var outIngestMeta map[string]any
	if curIngest, ok := doc["_ingest"].(map[string]any); ok {
		outIngestMeta = make(map[string]any, len(curIngest))
		for k, v := range curIngest {
			outIngestMeta[k] = v
		}
		if ts, ok := curIngest["timestamp"].(string); ok {
			outIngestTS = ts
		} else if tsAny, ok := curIngest["timestamp"]; ok && tsAny != nil {
			outIngestTS = fmt.Sprintf("%v", tsAny)
		}
	}
	if hadOrigIndex {
		doc["_index"] = origIndexVal
	} else {
		delete(doc, "_index")
	}
	if hadOrigID {
		doc["_id"] = origIDVal
	} else {
		delete(doc, "_id")
	}
	if hadOrigRouting {
		doc["_routing"] = origRoutingVal
	} else {
		delete(doc, "_routing")
	}
	if hadOrigVersion {
		doc["_version"] = origVersionVal
	} else {
		delete(doc, "_version")
	}
	delete(doc, "__internal_ingest_orig")
	delete(doc, "_ingest")
	if !mutated {
		return raw, outIndex, outID, outIngestTS, outRouting, false, trace, outIngestMeta, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, outIndex, outID, outIngestTS, outRouting, false, trace, outIngestMeta, err
	}
	return json.RawMessage(out), outIndex, outID, outIngestTS, outRouting, false, trace, outIngestMeta, nil
}

// handleSimulateIngestPipeline implements `POST /_ingest/pipeline/_simulate` and `POST /_ingest/pipeline/{id}/_simulate`.
func (s *Server) handleSimulateIngestPipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
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
	if pipe != nil {
		if err := validateIngestPipelineSpec(pipe); err != nil {
			writeESError(w, http.StatusBadRequest, ingestSpecValidationErrorType(err), err.Error())
			return
		}
	} else {
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
		inRouting, _ := docObj["_routing"].(string)
		srcAny, hasSrc := docObj["_source"]
		var srcMap map[string]any
		if !hasSrc {
			srcMap = make(map[string]any, len(docObj))
			for k, v := range docObj {
				if k == "_index" || k == "_id" || k == "_routing" {
					continue
				}
				srcMap[k] = v
			}
		} else if sm, ok := srcAny.(map[string]any); ok {
			srcMap = make(map[string]any, len(sm)+1)
			for k, v := range sm {
				srcMap[k] = v
			}
		} else {
			srcMap = make(map[string]any, 1)
		}
		docIngestTS := nowISO
		inIngest, _ := docObj["_ingest"].(map[string]any)
		if inIngest == nil {
			inIngest, _ = item["_ingest"].(map[string]any)
		}
		if len(inIngest) > 0 {
			ingClone := make(map[string]any, len(inIngest)+1)
			for k, v := range inIngest {
				ingClone[k] = v
			}
			if ts, ok := ingClone["timestamp"].(string); ok && ts != "" {
				docIngestTS = ts
			} else if tsAny, ok := ingClone["timestamp"]; ok && tsAny != nil {
				docIngestTS = fmt.Sprintf("%v", tsAny)
			} else {
				ingClone["timestamp"] = docIngestTS
			}
			srcMap["_ingest"] = ingClone
		} else if existingIng, ok := srcMap["_ingest"].(map[string]any); ok && len(existingIng) > 0 {
			if ts, ok := existingIng["timestamp"].(string); ok && ts != "" {
				docIngestTS = ts
			}
		} else {
			srcMap["_ingest"] = map[string]any{"timestamp": docIngestTS}
		}
		rawSrc, err := json.Marshal(srcMap)
		if err != nil {
			rawSrc = []byte(`{}`)
		}
		simPipeName := strings.TrimSpace(r.PathValue("id"))
		if simPipeName == "" {
			simPipeName = "_simulate"
		}
		outBytes, outIdx, outID, outIngestTS, outRouting, dropped, trace, outIngestMeta, procErr := applyIngestPipelineSpecWithNameAndRoutingAndIngestMeta(s, pipe, simPipeName, idx, id, inRouting, rawSrc, verbose, nil)
		if outIngestTS != "" {
			docIngestTS = outIngestTS
		}
		if verbose {
			for _, te := range trace {
				if dMap, ok := te["doc"].(map[string]any); ok {
					if curIdx, _ := dMap["_index"].(string); curIdx == "" || curIdx == "_index" {
						dMap["_index"] = idx
					}
					if curID, _ := dMap["_id"].(string); curID == "" || curID == "0" {
						dMap["_id"] = id
					}
					if dMap["_ingest"] == nil {
						dMap["_ingest"] = map[string]any{"timestamp": docIngestTS}
					}
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
		delete(outSrc, "_ingest")
		simIngest := map[string]any{
			"timestamp": docIngestTS,
		}
		for k, v := range outIngestMeta {
			simIngest[k] = v
		}
		simIngest["timestamp"] = docIngestTS
		simDoc := map[string]any{
			"_index":   outIdx,
			"_version": "-3",
			"_id":      outID,
			"_source":  outSrc,
			"_ingest":  simIngest,
		}
		if outRouting != "" {
			simDoc["_routing"] = outRouting
		}
		docsOut = append(docsOut, map[string]any{
			"doc": simDoc,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

func convertSingleIngestValue(val any, convType string) (any, error) {
	if val == nil {
		return nil, nil
	}
	switch val.(type) {
	case map[string]any, []any:
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	}
	lowerType := strings.ToLower(strings.TrimSpace(convType))
	switch lowerType {
	case "integer", "int", "long", "short", "byte":
		checkBounds := func(iv int64) bool {
			switch lowerType {
			case "integer", "int":
				return iv >= math.MinInt32 && iv <= math.MaxInt32
			case "short":
				return iv >= math.MinInt16 && iv <= math.MaxInt16
			case "byte":
				return iv >= math.MinInt8 && iv <= math.MaxInt8
			default:
				return true
			}
		}
		switch v := val.(type) {
		case string:
			iv, err := strconv.ParseInt(v, 10, 64)
			if err != nil || !checkBounds(iv) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return iv, nil
		case int:
			iv := int64(v)
			if !checkBounds(iv) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return iv, nil
		case int64:
			if !checkBounds(v) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return v, nil
		case int32:
			iv := int64(v)
			if !checkBounds(iv) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return iv, nil
		case int16:
			iv := int64(v)
			if !checkBounds(iv) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return iv, nil
		case int8:
			iv := int64(v)
			if !checkBounds(iv) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return iv, nil
		case uint:
			uv := uint64(v)
			if uv > math.MaxInt64 || !checkBounds(int64(uv)) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return int64(uv), nil
		case uint64:
			if v > math.MaxInt64 || !checkBounds(int64(v)) {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return int64(v), nil
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) && v >= float64(math.MinInt64) && v < float64(math.MaxInt64) {
				iv := int64(v)
				if checkBounds(iv) {
					return iv, nil
				}
			}
		case float32:
			fv := float64(v)
			if !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < float64(math.MaxInt64) {
				iv := int64(fv)
				if checkBounds(iv) {
					return iv, nil
				}
			}
		case json.Number:
			if iv, err := v.Int64(); err == nil {
				if checkBounds(iv) {
					return iv, nil
				}
			} else if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < float64(math.MaxInt64) {
				iv := int64(fv)
				if checkBounds(iv) {
					return iv, nil
				}
			}
		}
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	case "unsigned_long":
		switch v := val.(type) {
		case string:
			uv, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
			}
			return uv, nil
		case uint64:
			return v, nil
		case uint:
			return uint64(v), nil
		case int:
			if v >= 0 {
				return uint64(v), nil
			}
		case int64:
			if v >= 0 {
				return uint64(v), nil
			}
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v == math.Trunc(v) && v < 18446744073709551616.0 {
				return uint64(v), nil
			}
		case float32:
			fv := float64(v)
			if !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv == math.Trunc(fv) && fv < 18446744073709551616.0 {
				return uint64(fv), nil
			}
		case json.Number:
			if uv, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
				return uv, nil
			}
			if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv == math.Trunc(fv) && fv < 18446744073709551616.0 {
				return uint64(fv), nil
			}
		}
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	case "float", "double", "half_float", "scaled_float":
		switch v := val.(type) {
		case string:
			if v != "" && v == strings.TrimSpace(v) {
				if fv, err := strconv.ParseFloat(v, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
					return fv, nil
				}
			}
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				return v, nil
			}
		case float32:
			fv := float64(v)
			if !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return fv, nil
			}
		case int:
			return float64(v), nil
		case int64:
			return float64(v), nil
		case int32:
			return float64(v), nil
		case uint:
			return float64(v), nil
		case uint64:
			return float64(v), nil
		case json.Number:
			if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return fv, nil
			}
		}
		return nil, fmt.Errorf("unable to convert [%v] to %s", val, convType)
	case "string":
		if s, ok := val.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", val), nil
	case "boolean", "bool":
		switch v := val.(type) {
		case bool:
			return v, nil
		case string:
			if v == strings.TrimSpace(v) {
				switch strings.ToLower(v) {
				case "true", "1", "yes", "on":
					return true, nil
				case "false", "0", "no", "off":
					return false, nil
				}
			}
		}
		return nil, fmt.Errorf("unable to convert [%v] to boolean", val)
	case "ip":
		if s, ok := val.(string); ok && s != "" && s == strings.TrimSpace(s) {
			if ip := net.ParseIP(s); ip != nil {
				return ip.String(), nil
			}
		}
		return nil, fmt.Errorf("unable to convert [%v] to ip", val)
	case "auto":
		s, isStr := val.(string)
		if !isStr {
			return val, nil
		}
		if s == "" || s != strings.TrimSpace(s) {
			return s, nil
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, nil
		}
		if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return fv, nil
		}
		switch strings.ToLower(s) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return s, nil
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

func expandDottedIngestValueWithOverride(val any, override bool) any {
	if arr, ok := val.([]any); ok {
		outArr := make([]any, len(arr))
		for i, elem := range arr {
			outArr[i] = expandDottedIngestValueWithOverride(elem, override)
		}
		return outArr
	}
	m, ok := val.(map[string]any)
	if !ok {
		return val
	}
	out := make(map[string]any, len(m))
	var plainKeys, dottedKeys []string
	for k := range m {
		if strings.Contains(k, ".") {
			dottedKeys = append(dottedKeys, k)
		} else {
			plainKeys = append(plainKeys, k)
		}
	}
	sort.Strings(plainKeys)
	sort.Strings(dottedKeys)
	for _, k := range plainKeys {
		expandedV := expandDottedIngestValueWithOverride(m[k], override)
		if existing, ok := out[k].(map[string]any); ok {
			if subM, ok2 := expandedV.(map[string]any); ok2 {
				deepMergeIngestMapWithOverride(existing, subM, override)
				continue
			}
			if override {
				out[k] = expandedV
			}
		} else {
			out[k] = expandedV
		}
	}
	for _, k := range dottedKeys {
		expandedV := expandDottedIngestValueWithOverride(m[k], override)
		if !override {
			firstSeg := k[:strings.IndexByte(k, '.')]
			if existing, hasEx := out[firstSeg]; hasEx {
				if _, isMap := existing.(map[string]any); !isMap {
					out[k] = expandedV
					continue
				}
			}
		}
		setIngestPathMergeWithOverride(out, k, expandedV, override)
	}
	return out
}

func deepMergeIngestMap(dst, src map[string]any) {
	deepMergeIngestMapWithOverride(dst, src, true)
}

func deepMergeIngestMapWithOverride(dst, src map[string]any, override bool) {
	for k, v := range src {
		if vMap, ok := v.(map[string]any); ok {
			if existing, ok := dst[k].(map[string]any); ok {
				deepMergeIngestMapWithOverride(existing, vMap, override)
				continue
			}
		}
		if !override {
			if _, exists := dst[k]; exists {
				continue
			}
		}
		dst[k] = v
	}
}

func setIngestPathMergeWithOverride(doc map[string]any, path string, val any, override bool) {
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		if valMap, ok := val.(map[string]any); ok {
			if existing, ok := doc[path].(map[string]any); ok {
				deepMergeIngestMapWithOverride(existing, valMap, override)
				return
			}
		}
		if !override {
			if _, exists := doc[path]; exists {
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
			if !override {
				return
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
				deepMergeIngestMapWithOverride(existing, valMap, override)
				return
			}
		}
		if !override {
			if _, exists := node[lastSeg]; exists {
				return
			}
		}
		node[lastSeg] = val
	case []any:
		if idx, ok := parseIngestSliceIndex(lastSeg, len(node)); ok {
			if !override && node[idx] != nil {
				return
			}
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

func keepMatchingIngestPaths(src, dst map[string]any, patternSegs []string, isInternal func(string) bool) bool {
	if len(patternSegs) == 0 || src == nil || dst == nil {
		return false
	}
	seg := patternSegs[0]
	matchedAny := false
	for k, v := range src {
		if isInternal != nil && isInternal(k) {
			continue
		}
		if len(patternSegs) > 1 {
			joinedKey := strings.Join(patternSegs, ".")
			if matchWildcardPattern(joinedKey, k) {
				dst[k] = deepCloneIngestValue(v)
				matchedAny = true
				continue
			}
		}
		if !matchWildcardPattern(seg, k) {
			continue
		}
		if len(patternSegs) == 1 {
			dst[k] = deepCloneIngestValue(v)
			matchedAny = true
			continue
		}
		if subSrc, ok := v.(map[string]any); ok {
			subDst, _ := dst[k].(map[string]any)
			created := false
			if subDst == nil {
				subDst = make(map[string]any)
				created = true
			}
			if keepMatchingIngestPaths(subSrc, subDst, patternSegs[1:], nil) {
				if created {
					dst[k] = subDst
				}
				matchedAny = true
			}
		}
	}
	return matchedAny
}

func deleteIngestPath(doc map[string]any, path string) {
	delete(doc, path)
	segs := strings.Split(path, ".")
	if len(segs) <= 1 {
		return
	}
	var parent any
	var parentKey string
	var parentIdx int
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
			parent = node
			parentKey = segs[i]
			curr = next
		case []any:
			idx, ok := parseIngestSliceIndex(segs[i], len(node))
			if !ok {
				return
			}
			parent = node
			parentIdx = idx
			curr = node[idx]
		default:
			return
		}
	}
	lastSeg := segs[len(segs)-1]
	switch node := curr.(type) {
	case map[string]any:
		delete(node, lastSeg)
	case []any:
		if idx, ok := parseIngestSliceIndex(lastSeg, len(node)); ok {
			updated := append([]any{}, node[:idx]...)
			updated = append(updated, node[idx+1:]...)
			switch p := parent.(type) {
			case map[string]any:
				p[parentKey] = updated
			case []any:
				p[parentIdx] = updated
			}
		}
	}
}

// handleCatNodes implements `GET /_cat/nodes` and `GET /_cat/nodes/{node_id}` for Elasticvue & Cerebro.
func (s *Server) handleCatNodes(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
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
	nodePat := strings.TrimSpace(r.PathValue("node_id"))
	if nodePat == "" {
		nodePat = strings.TrimSpace(r.PathValue("name"))
	}
	if nodePat != "" && nodePat != "*" && nodePat != "_all" {
		if !matchMultiWildcardWithExclusions(nodePat, "doris-fe-1") &&
			!matchMultiWildcardWithExclusions(nodePat, "doris-node-1") &&
			!matchMultiWildcardWithExclusions(nodePat, "local-node-1") &&
			!matchMultiWildcardWithExclusions(nodePat, "127.0.0.1") &&
			nodePat != "_local" && nodePat != "_master" {
			rows = []map[string]any{}
		}
	}
	writeCatResponse(w, r, []string{"ip", "heap.percent", "ram.percent", "cpu", "node.role", "master", "name"}, rows)
}

// handleResolveCluster implements `GET /_resolve/cluster` and `GET /_resolve/cluster/{name}` (Round 56 F9).
func (s *Server) handleResolveCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	pat := strings.TrimSpace(r.PathValue("name"))
	if pat == "" {
		pat = "*"
	}
	s.mu.RLock()
	clusters := map[string]bool{"local": false}
	for alias, cfg := range s.remoteClusters {
		skip, _ := cfg["skip_unavailable"].(bool)
		clusters[alias] = skip
	}
	extractRemotesFromSettings := func(settings map[string]any) {
		for k, v := range settings {
			if strings.HasPrefix(k, "cluster.remote.") {
				rest := strings.TrimPrefix(k, "cluster.remote.")
				if dot := strings.IndexByte(rest, '.'); dot > 0 {
					alias := rest[:dot]
					prop := rest[dot+1:]
					if _, exists := clusters[alias]; !exists {
						clusters[alias] = false
					}
					if prop == "skip_unavailable" {
						if bv, ok := v.(bool); ok {
							clusters[alias] = bv
						} else if sv, ok := v.(string); ok {
							clusters[alias] = strings.EqualFold(sv, "true")
						}
					}
				}
			}
		}
		if clMap, ok := settings["cluster"].(map[string]any); ok {
			if remMap, ok := clMap["remote"].(map[string]any); ok {
				for alias, rawCfg := range remMap {
					if _, exists := clusters[alias]; !exists {
						clusters[alias] = false
					}
					if cfgMap, ok := rawCfg.(map[string]any); ok {
						if bv, ok := cfgMap["skip_unavailable"].(bool); ok {
							clusters[alias] = bv
						}
					}
				}
			}
		}
	}
	extractRemotesFromSettings(s.clusterPersistentSettings)
	extractRemotesFromSettings(s.clusterTransientSettings)
	s.mu.RUnlock()

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	out := make(map[string]any)
	for alias, skipUnavail := range clusters {
		if pat == "*" || pat == "_all" || matchMultiWildcardWithExclusions(pat, alias) {
			out[alias] = map[string]any{
				"connected":        true,
				"skip_unavailable": skipUnavail,
				"matching":         true,
				"version":          map[string]any{"number": "8.15.0"},
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCatShards implements `GET /_cat/shards` for Elasticvue & Cerebro.
func (s *Server) handleCatShards(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
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
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
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

// handleCatHealth implements `GET /_cat/health`.
func (s *Server) handleCatHealth(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	s.mu.RLock()
	numIndices := len(s.indices)
	s.mu.RUnlock()

	status := "green"
	if err := s.backend.Ping(r.Context()); err != nil {
		status = "red"
	}

	now := time.Now().UTC()
	headers := []string{
		"epoch", "timestamp", "cluster", "status",
		"node.total", "node.data", "shards", "pri",
		"relo", "init", "unassign", "pending_tasks",
		"max_task_wait_time", "active_shards_percent",
	}
	rows := []map[string]any{
		{
			"epoch":                 fmt.Sprintf("%d", now.Unix()),
			"timestamp":             now.Format("15:04:05"),
			"cluster":               "apache-doris-search-cluster",
			"status":                status,
			"node.total":            "1",
			"node.data":             "1",
			"shards":                fmt.Sprintf("%d", numIndices),
			"pri":                   fmt.Sprintf("%d", numIndices),
			"relo":                  "0",
			"init":                  "0",
			"unassign":              "0",
			"pending_tasks":         "0",
			"max_task_wait_time":    "-",
			"active_shards_percent": "100.0%",
		},
	}
	writeCatResponse(w, r, headers, rows)
}

func writeCatResponse(w http.ResponseWriter, r *http.Request, headers []string, rows []map[string]any) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if isTruthyBoolQueryParam(r, "help") {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		for _, h := range headers {
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintf(w, "%-20s |   | %s\n", h, h)
		}
		return
	}

	if rawSort := strings.TrimSpace(r.URL.Query().Get("s")); rawSort != "" && len(rows) > 1 {
		type sortCol struct {
			col  string
			desc bool
		}
		var scols []sortCol
		for _, part := range strings.Split(rawSort, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			col := part
			desc := false
			if colonIdx := strings.IndexByte(part, ':'); colonIdx > 0 {
				col = strings.TrimSpace(part[:colonIdx])
				ord := strings.ToLower(strings.TrimSpace(part[colonIdx+1:]))
				desc = ord == "desc" || ord == "d"
			}
			scols = append(scols, sortCol{col: col, desc: desc})
		}
		if len(scols) > 0 {
			sort.SliceStable(rows, func(i, j int) bool {
				for _, sc := range scols {
					cmp := compareAny(rows[i][sc.col], rows[j][sc.col])
					if cmp != 0 {
						if sc.desc {
							return cmp > 0
						}
						return cmp < 0
					}
				}
				return false
			})
		}
	}

	effHeaders := headers
	hasCustomH := false
	if rawH := strings.TrimSpace(r.URL.Query().Get("h")); rawH != "" {
		var custom []string
		for _, part := range strings.Split(rawH, ",") {
			col := strings.TrimSpace(part)
			if col != "" {
				custom = append(custom, col)
			}
		}
		if len(custom) > 0 {
			effHeaders = custom
			hasCustomH = true
		}
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "txt" {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if isTruthyBoolQueryParam(r, "v") {
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(effHeaders, "\t"))
		}
		for _, row := range rows {
			vals := make([]string, 0, len(effHeaders))
			for _, h := range effHeaders {
				v, exists := row[h]
				if !exists || v == nil {
					vals = append(vals, "")
				} else {
					vals = append(vals, fmt.Sprintf("%v", v))
				}
			}
			// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
			_, _ = fmt.Fprintln(w, strings.Join(vals, "\t"))
		}
		return
	}
	if hasCustomH {
		projected := make([]map[string]any, len(rows))
		for i, row := range rows {
			m := make(map[string]any, len(effHeaders))
			for _, h := range effHeaders {
				if v, ok := row[h]; ok {
					m[h] = v
				} else {
					m[h] = nil
				}
			}
			projected[i] = m
		}
		writeJSON(w, http.StatusOK, projected)
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
		MaxDocs           *int       `json:"max_docs,omitempty"`
		Size              *int       `json:"size,omitempty"`
		Conflicts         string     `json:"conflicts,omitempty"`
		RequestsPerSecond *float64   `json:"requests_per_second,omitempty"`
		Slices            any        `json:"slices,omitempty"`
		Slice             *sliceSpec `json:"slice,omitempty"`
		Source            struct {
			Index   any                 `json:"index"`
			Query   *esast.Query        `json:"query,omitempty"`
			Size    *int                `json:"size,omitempty"`
			Source  *esast.SourceFilter `json:"_source,omitempty"`
			Sort    esast.SortSlice     `json:"sort,omitempty"`
			Routing any                 `json:"routing,omitempty"`
			Slice   *sliceSpec          `json:"slice,omitempty"`
		} `json:"source"`
		Dest struct {
			Index       string `json:"index"`
			Pipeline    string `json:"pipeline,omitempty"`
			OpType      string `json:"op_type,omitempty"`
			VersionType string `json:"version_type,omitempty"`
			Routing     string `json:"routing,omitempty"`
		} `json:"dest"`
		Script *painless.ScriptSpec `json:"script,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	effSlice := body.Slice
	if effSlice == nil {
		effSlice = body.Source.Slice
	}
	var effSliceField string
	if effSlice != nil {
		effSliceField = effSlice.Field
	}
	sliceID, sliceMax, hasSlice, sliceErrStatus, sliceErrType, sliceErrReason := parseAndValidateSliceParams(r, body.Slices, effSlice)
	if sliceErrStatus != 0 {
		writeESError(w, sliceErrStatus, sliceErrType, sliceErrReason)
		return
	}
	if missingID := s.findMissingStoredScriptInRawBody(bodyBytes); missingID != "" {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("cannot execute stored script [%s] because it does not exist", missingID))
		return
	}
	if body.Source.Query != nil {
		if missingID := s.validateStoredScriptsInQuery(body.Source.Query); missingID != "" {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("cannot execute stored script [%s] because it does not exist", missingID))
			return
		}
	}
	s.resolvePainlessScriptSpecFromRaw(&body.Script, bodyBytes)
	if body.Conflicts == "" {
		body.Conflicts = r.URL.Query().Get("conflicts")
	}
	conflictsMode := strings.ToLower(strings.TrimSpace(body.Conflicts))
	if conflictsMode != "" && conflictsMode != "abort" && conflictsMode != "proceed" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("conflicts may only be \"abort\" or \"proceed\" but was [%s]", body.Conflicts))
		return
	}
	if body.Dest.Pipeline == "" {
		body.Dest.Pipeline = r.URL.Query().Get("pipeline")
	}
	if body.Dest.OpType == "" {
		body.Dest.OpType = r.URL.Query().Get("op_type")
	}
	destOpType := strings.ToLower(strings.TrimSpace(body.Dest.OpType))
	if destOpType != "" && destOpType != "index" && destOpType != "create" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("op_type must be 'index' or 'create', found: [%s]", body.Dest.OpType))
		return
	}
	destVerType := strings.ToLower(strings.TrimSpace(body.Dest.VersionType))
	if destVerType != "" && destVerType != "internal" && destVerType != "external" && destVerType != "external_gt" && destVerType != "external_gte" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unknown version_type [%s] for reindex dest", body.Dest.VersionType))
		return
	}
	destRoutingMode := strings.TrimSpace(body.Dest.Routing)
	if destRoutingMode != "" && destRoutingMode != "keep" && destRoutingMode != "discard" && !strings.HasPrefix(destRoutingMode, "=") {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid routing mode [%s] for reindex dest", body.Dest.Routing))
		return
	}
	rps := -1.0
	if body.RequestsPerSecond != nil {
		rps = *body.RequestsPerSecond
	}
	if qRPS := strings.TrimSpace(r.URL.Query().Get("requests_per_second")); qRPS != "" {
		if strings.EqualFold(qRPS, "unlimited") {
			rps = -1.0
		} else if parsed, err := strconv.ParseFloat(qRPS, 64); err == nil {
			rps = parsed
		}
	}
	var srcRoutingFilter string
	switch rv := body.Source.Routing.(type) {
	case string:
		srcRoutingFilter = strings.TrimSpace(rv)
	case []any:
		var rParts []string
		for _, item := range rv {
			if rs := strings.TrimSpace(fmt.Sprintf("%v", item)); rs != "" {
				rParts = append(rParts, rs)
			}
		}
		srcRoutingFilter = strings.Join(rParts, ",")
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
	if s.isIndexClosed(destIndex) {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", destIndex))
		return
	}
	if blocked, reason := s.isIndexWriteBlocked(destIndex); blocked {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
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
		srcTargets = []string{s.resolveIndexName(srcPattern)}
	}
	if closedIdx := s.findClosedTargetIndex(r, srcPattern); closedIdx != "" {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
		return
	}
	for _, srcIdx := range srcTargets {
		if s.isIndexClosed(srcIdx) {
			writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", srcIdx))
			return
		}
	}
	if _, reason := s.findReadBlockedTargetIndex(r, srcPattern); reason != "" {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
		return
	}
	for _, srcIdx := range srcTargets {
		if blocked, reason := s.isIndexReadBlocked(srcIdx); blocked {
			writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
			return
		}
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)

	var totalMatched, totalCreated, totalUpdated, totalDeleted, totalNoops, versionConflicts, batches int
	failures := make([]any, 0)
	deletedVerByIdx := make(map[string]map[string]int64)
	writtenDocsByIdx := make(map[string]map[string]HitRow)
	proceedOnConflict := strings.EqualFold(strings.TrimSpace(body.Conflicts), "proceed") ||
		strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("conflicts")), "proceed")
	updSpec := &painless.UpdateRequest{
		Script:            body.Script,
		AllowMetaMutation: true,
	}
	batchSize := 1000
	if body.Source.Size != nil && *body.Source.Size > 0 && *body.Source.Size < batchSize {
		batchSize = *body.Source.Size
	}
	if qScrollSize := r.URL.Query().Get("scroll_size"); qScrollSize != "" {
		if parsed, err := strconv.Atoi(qScrollSize); err == nil && parsed > 0 {
			batchSize = parsed
		}
	}

	s.resolveStoredScriptsInQuery(body.Source.Query)
	if rq, err := s.preResolveSpecialQueriesInQuery(r.Context(), srcTargets, body.Source.Query); err == nil {
		body.Source.Query = rq
	}
	s.resolveTermsLookupsInQuery(r.Context(), body.Source.Query)
	var effSort esast.SortSlice
	if len(body.Source.Sort) > 0 {
		effSort = append(effSort, body.Source.Sort...)
		hasIDTie := false
		for _, sp := range effSort {
			if sp.Entry.Field == "_id" {
				hasIDTie = true
				break
			}
		}
		if !hasIDTie {
			effSort = append(effSort, esast.SortSpec{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}})
		}
	} else {
		effSort = esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}}
	}

	useGlobalSort := len(body.Source.Sort) > 0 && (len(srcTargets) > 1 || sortsHaveScript(effSort) || (sortSpecsUseScore(effSort) && (queryHasRuntimeScript(body.Source.Query) || queryHasNestedScoring(body.Source.Query) || aliasFiltersHaveRuntimeScript(aliasFilters))))
	var globalSortedHits []HitRow
	loopTargets := srcTargets
	if useGlobalSort {
		for _, srcIdx := range srcTargets {
			srcSchema := s.getOrCompileReadOnlySchema(r.Context(), srcIdx)
			_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
			tr := transpiler.NewTranspiler(srcSchema, s.transpileOpts)
			effQuery := combineQueryWithAliasFilter(body.Source.Query, aliasFilters[srcIdx])
			hasRuntimeQueryScript := queryHasRuntimeScript(effQuery) || (effQuery != nil && ((effQuery.FunctionScore != nil && effQuery.FunctionScore.MinScore != nil) || (effQuery.ScriptScore != nil && effQuery.ScriptScore.MinScore != nil)))
			hasNestedScore := queryHasNestedScoring(effQuery)
			var sa []any
			chunkSz := 1000
			for {
				plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
					Query:          effQuery,
					Size:           &chunkSz,
					TrackTotalHits: false,
					Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
					SearchAfter:    sa,
				})
				if err != nil {
					writeESError(w, http.StatusBadRequest, "search_phase_execution_exception", err.Error())
					return
				}
				hRows, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
				if err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
					return
				}
				if len(hRows) == 0 {
					break
				}
				for _, h := range hRows {
					if hasSlice && !docMatchesSlice(h.ID, effSliceField, h.Source, sliceID, sliceMax) {
						continue
					}
					effSrcRouting := s.resolveEffectiveReadRouting(srcPattern, srcIdx, srcRoutingFilter)
					if effSrcRouting != "" && !s.docMatchesRequestRouting(srcIdx, h.ID, effSrcRouting) {
						continue
					}
					if hasRuntimeQueryScript || hasNestedScore {
						var rawMap map[string]any
						dec := json.NewDecoder(bytes.NewReader(h.Source))
						dec.UseNumber()
						_ = dec.Decode(&rawMap)
						if rawMap == nil {
							rawMap = make(map[string]any)
						}
						rawMap["__meta_id"] = h.ID
						rawMap["__meta_index"] = srcIdx
						rawMap["__meta_version"] = h.Version
						if hasRuntimeQueryScript && !evalQueryScriptFilterOnDocWithScore(srcSchema, rawMap, effQuery, h.Score) {
							continue
						}
						baseScore := h.Score
						if effQuery != nil && ((effQuery.ScriptScore != nil && effQuery.ScriptScore.Query == nil) || (effQuery.FunctionScore != nil && effQuery.FunctionScore.Query == nil)) {
							baseScore = 1.0
						}
						h.Score = evalQueryScriptScoreOnDocWithSchema(srcSchema, rawMap, effQuery, baseScore)
					}
					h.Index = srcIdx
					h.Schema = srcSchema
					globalSortedHits = append(globalSortedHits, h)
				}
				sa = []any{hRows[len(hRows)-1].ID}
				if len(hRows) < chunkSz {
					break
				}
			}
		}
		sort.SliceStable(globalSortedHits, func(i, j int) bool {
			if cmp := compareHitRowsBySortWithSchemas(globalSortedHits[i], globalSortedHits[j], effSort, globalSortedHits[i].Schema, globalSortedHits[j].Schema); cmp != 0 {
				return cmp < 0
			}
			return globalSortedHits[i].ID < globalSortedHits[j].ID
		})
		if len(globalSortedHits) > 0 {
			loopTargets = []string{"__global_sorted__"}
		} else {
			loopTargets = nil
		}
	}

	for _, srcIdx := range loopTargets {
		var srcSchema *schema.IndexSchema
		var tr *transpiler.Transpiler
		var searchAfter []any
		var effQuery *esast.Query
		var hasRuntimeQueryScript bool
		if !useGlobalSort {
			srcSchema = s.getOrCompileReadOnlySchema(r.Context(), srcIdx)
			_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
			tr = transpiler.NewTranspiler(srcSchema, s.transpileOpts)
			effQuery = combineQueryWithAliasFilter(body.Source.Query, aliasFilters[srcIdx])
			hasRuntimeQueryScript = queryHasRuntimeScript(effQuery) || (effQuery != nil && ((effQuery.FunctionScore != nil && effQuery.FunctionScore.MinScore != nil) || (effQuery.ScriptScore != nil && effQuery.ScriptScore.MinScore != nil)))
		}

		for {
			fetchSize := batchSize
			if !hasRuntimeQueryScript && !hasSlice && srcRoutingFilter == "" && maxDocs > 0 && totalMatched+fetchSize > maxDocs {
				fetchSize = maxDocs - totalMatched
			}
			if fetchSize <= 0 || (maxDocs > 0 && totalMatched >= maxDocs) {
				break
			}
			var hits []HitRow
			if useGlobalSort {
				if len(globalSortedHits) == 0 {
					break
				}
				take := fetchSize
				if take > len(globalSortedHits) {
					take = len(globalSortedHits)
				}
				hits = globalSortedHits[:take]
				globalSortedHits = globalSortedHits[take:]
			} else {
				plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
					Query:          effQuery,
					Size:           &fetchSize,
					TrackTotalHits: false,
					Sort:           effSort,
					SearchAfter:    searchAfter,
				})
				if err != nil {
					writeESError(w, http.StatusBadRequest, "search_phase_execution_exception", err.Error())
					return
				}
				hits, err = s.backend.QueryHits(r.Context(), plan.HitsSQL)
				if err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
					return
				}
				if len(hits) == 0 {
					break
				}
			}
			batches++
			type preparedDoc struct {
				id           string
				destIndex    string
				aliasFilter  *esast.Query
				source       json.RawMessage
				srcVer       int64
				scriptVerSet bool
				isDelete     bool
				isCreate     bool
				routing      string
			}
			var prepared []preparedDoc
			sampleDocsByIdx := make(map[string][]json.RawMessage)
			candIDsByIdx := make(map[string][]string)
			defaultIsCreate := strings.EqualFold(strings.TrimSpace(body.Dest.OpType), "create")
			for _, h := range hits {
				if maxDocs > 0 && totalMatched >= maxDocs {
					break
				}
				if !useGlobalSort && hasSlice && !docMatchesSlice(h.ID, effSliceField, h.Source, sliceID, sliceMax) {
					continue
				}
				effSrcIdx := srcIdx
				if effSrcIdx == "__global_sorted__" {
					effSrcIdx = h.Index
				}
				effSrcRouting := s.resolveEffectiveReadRouting(srcPattern, effSrcIdx, srcRoutingFilter)
				if effSrcRouting != "" && !s.docMatchesRequestRouting(effSrcIdx, h.ID, effSrcRouting) {
					continue
				}
				if hasRuntimeQueryScript {
					var rawMap map[string]any
					dec := json.NewDecoder(bytes.NewReader(h.Source))
					dec.UseNumber()
					_ = dec.Decode(&rawMap)
					if rawMap == nil {
						rawMap = make(map[string]any)
					}
					rawMap["__meta_id"] = h.ID
					rawMap["__meta_index"] = effSrcIdx
					rawMap["__meta_version"] = h.Version
					if !evalQueryScriptFilterOnDocWithScore(srcSchema, rawMap, effQuery, h.Score) {
						continue
					}
				}
				totalMatched++
				docID := h.ID
				docDestRawIdx := body.Dest.Index
				docDestIdx := destIndex
				docDestAliasFilter := destAliasFilter
				docSource := h.Source
				docSrcVer := h.Version
				docRouting := s.getDocRouting(effSrcIdx, h.ID)
				switch {
				case destRoutingMode == "discard":
					docRouting = ""
				case strings.HasPrefix(destRoutingMode, "="):
					docRouting = destRoutingMode[1:]
				}
				docIsCreate := defaultIsCreate
				scriptVerSet := false
				if body.Source.Source != nil {
					filtered := filterSourceJSON(docSource, body.Source.Source)
					if filtered == nil {
						docSource = json.RawMessage(`{}`)
					} else {
						docSource = filtered
					}
				}
				if body.Script != nil {
					updSpec.MetaID = docID
					updSpec.MetaIndex = docDestIdx
					updSpec.MetaRouting = docRouting
					updSpec.MetaVersion = docSrcVer
					updSpec.MetaVersionNil = false
					updSpec.MetaVersionMutated = false
					if docIsCreate {
						updSpec.MetaOp = "create"
					} else {
						updSpec.MetaOp = "index"
					}
					mutated, opRes, err := painless.ApplyUpdateWithResult(docSource, updSpec, true)
					if err != nil {
						writeESError(w, http.StatusBadRequest, updateScriptErrorType(err), err.Error())
						return
					}
					if opRes == "noop" {
						totalNoops++
						continue
					}
					docIsCreate = strings.EqualFold(updSpec.MetaOp, "create")
					if updSpec.MetaID != "" {
						docID = updSpec.MetaID
					} else {
						docID = esast.NextAutoID()
					}
					docRouting = updSpec.MetaRouting
					if sIdx := strings.TrimSpace(updSpec.MetaIndex); sIdx != "" && sIdx != docDestIdx {
						resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(sIdx)
						if rErr != nil {
							writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
							return
						}
						docDestRawIdx = sIdx
						docDestIdx = resolvedIdx
						docDestAliasFilter = resolvedFilter
					}
					if updSpec.MetaVersionNil {
						docSrcVer = 0
						scriptVerSet = false
					} else {
						docSrcVer = updSpec.MetaVersion
						scriptVerSet = updSpec.MetaVersionMutated
					}
					if opRes == "deleted" {
						effDelRouting := s.resolveEffectiveWriteRouting(docDestRawIdx, docDestIdx, "", docRouting)
						prepared = append(prepared, preparedDoc{id: docID, destIndex: docDestIdx, aliasFilter: docDestAliasFilter, srcVer: docSrcVer, scriptVerSet: scriptVerSet, isDelete: true, routing: effDelRouting})
						candIDsByIdx[docDestIdx] = append(candIDsByIdx[docDestIdx], docID)
						if _, hasKey := sampleDocsByIdx[docDestIdx]; !hasKey {
							sampleDocsByIdx[docDestIdx] = nil
						}
						continue
					}
					docSource = mutated
				}
				prePipeRouting := docRouting
				if prePipeRouting == "" {
					prePipeRouting = s.resolveEffectiveIndexRouting(docDestRawIdx, "")
				}
				pipedDoc, nextDestIdx, nextDocID, pipeRouting, dropped, pipeErr := s.applyEffectiveAndFinalPipelinesWithRouting(docDestRawIdx, docID, body.Dest.Pipeline, "", prePipeRouting, docSource)
				if pipeErr != nil {
					writeESError(w, http.StatusBadRequest, ingestErrorType(pipeErr), pipeErr.Error())
					return
				}
				if dropped {
					totalNoops++
					continue
				}
				if nextDocID != "" {
					docID = nextDocID
				}
				if nextDestIdx != "" && nextDestIdx != docDestRawIdx && nextDestIdx != docDestIdx {
					resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(nextDestIdx)
					if rErr != nil {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
						return
					}
					docDestRawIdx = nextDestIdx
					docDestIdx = resolvedIdx
					docDestAliasFilter = resolvedFilter
				}
				docSource = pipedDoc
				effRouting := s.resolveEffectiveWriteRouting(docDestRawIdx, docDestIdx, "", pipeRouting)
				if docDestAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), docDestIdx, docID, docSource, docDestAliasFilter) {
					if proceedOnConflict {
						versionConflicts++
						failures = append(failures, map[string]any{
							"index":  docDestIdx,
							"type":   "_doc",
							"id":     docID,
							"status": http.StatusBadRequest,
							"cause": map[string]any{
								"type":   "illegal_argument_exception",
								"reason": "document does not match destination alias filter",
							},
						})
						continue
					}
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "document does not match destination alias filter")
					return
				}
				prepared = append(prepared, preparedDoc{id: docID, destIndex: docDestIdx, aliasFilter: docDestAliasFilter, source: docSource, srcVer: docSrcVer, scriptVerSet: scriptVerSet, isCreate: docIsCreate, routing: effRouting})
				candIDsByIdx[docDestIdx] = append(candIDsByIdx[docDestIdx], docID)
				sampleDocsByIdx[docDestIdx] = append(sampleDocsByIdx[docDestIdx], docSource)
			}
			if len(prepared) == 0 {
				if !useGlobalSort {
					nextSA := extractHitSortValues(hits[len(hits)-1], effSort, srcSchema)
					if len(nextSA) == 0 {
						nextSA = []any{hits[len(hits)-1].ID}
					}
					searchAfter = nextSA
				}
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
					if prevWritten := writtenDocsByIdx[idxName]; prevWritten != nil {
						for wid, wdoc := range prevWritten {
							existingDocs[wid] = wdoc
						}
					}
					existingByIdx[idxName] = existingDocs
				} else {
					existingByIdx[idxName] = make(map[string]HitRow)
				}
			}
			batchBufByTable := make(map[string]*bytes.Buffer, len(schemasByIdx))
			var tableOrder []string
			for _, pd := range prepared {
				isCreate := pd.isCreate
				sch := schemasByIdx[pd.destIndex]
				existingDocs := existingByIdx[pd.destIndex]
				var minVer int64
				if delMap := deletedVerByIdx[pd.destIndex]; delMap != nil {
					if delVer, okDel := delMap[pd.id]; okDel && delVer+1 > minVer {
						minVer = delVer + 1
					}
				}
				if lastVer := s.getDocVersion(pd.destIndex, pd.id); lastVer > 0 && lastVer < 1_000_000_000_000 && lastVer+1 > minVer {
					minVer = lastVer + 1
				}
				existing, exists := existingDocs[pd.id]
				if !exists && minVer == 0 {
					if destHit, found, _ := s.backend.GetDocByID(r.Context(), sch.DorisDB, sch.DorisTable, pd.id); !found && destHit != nil && destHit.Version > 0 && destHit.Version < 1_000_000_000_000 {
						minVer = destHit.Version + 1
					}
				}
				if pd.isDelete {
					if s.isRoutingRequired(sch) && pd.routing == "" {
						writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[%s]/[%s]", pd.destIndex, "_doc", pd.id))
						return
					}
					if !exists {
						totalNoops++
						continue
					}
					if pd.routing != "" && !s.docMatchesRequestRouting(pd.destIndex, pd.id, pd.routing) {
						totalNoops++
						continue
					}
					if pd.aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), pd.destIndex, pd.id, existing.Source, pd.aliasFilter) {
						if proceedOnConflict {
							versionConflicts++
							continue
						}
						writeESError(w, http.StatusConflict, "version_conflict_engine_exception",
							fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", pd.id))
						return
					}
					if existing.Version+1 > minVer {
						minVer = existing.Version + 1
					}
					nextVer := s.allocVersion(minVer)
					if minVer > 0 && minVer < 1_000_000_000_000 {
						nextVer = minVer
					}
					shredded, err := schema.ShredDocument(sch, pd.id, nextVer, true, nil)
					if err != nil {
						writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
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
					delete(existingDocs, pd.id)
					if writtenDocsByIdx[pd.destIndex] != nil {
						delete(writtenDocsByIdx[pd.destIndex], pd.id)
					}
					if deletedVerByIdx[pd.destIndex] == nil {
						deletedVerByIdx[pd.destIndex] = make(map[string]int64)
					}
					deletedVerByIdx[pd.destIndex][pd.id] = nextVer
					s.setDocRouting(pd.destIndex, pd.id, "")
					s.setDocVersion(pd.destIndex, pd.id, nextVer)
					totalDeleted++
					continue
				}
				useExternalVer := (destVerType == "external" || destVerType == "external_gt" || destVerType == "external_gte") && pd.srcVer > 0
				if exists {
					verConflict := false
					if useExternalVer {
						if destVerType == "external_gte" {
							verConflict = existing.Version > pd.srcVer
						} else {
							verConflict = existing.Version >= pd.srcVer
						}
					} else if pd.scriptVerSet && pd.srcVer > 0 {
						verConflict = existing.Version != pd.srcVer
					}
					conflict := isCreate || verConflict || (pd.aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), pd.destIndex, pd.id, existing.Source, pd.aliasFilter))
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
				} else if useExternalVer {
					var delVer int64
					if delMap := deletedVerByIdx[pd.destIndex]; delMap != nil {
						delVer = delMap[pd.id]
					}
					if delVer == 0 {
						if lastVer := s.getDocVersion(pd.destIndex, pd.id); lastVer > 0 && lastVer < 1_000_000_000_000 {
							delVer = lastVer
						}
					}
					if delVer > 0 {
						extConflict := delVer >= pd.srcVer
						if destVerType == "external_gte" {
							extConflict = delVer > pd.srcVer
						}
						if extConflict {
							if proceedOnConflict {
								versionConflicts++
								continue
							}
							writeESError(w, http.StatusConflict, "version_conflict_engine_exception",
								fmt.Sprintf("[%s]: version conflict, current version [%d] is higher or equal to the one provided [%d]", pd.id, delVer, pd.srcVer))
							return
						}
					}
				}
				if s.isRoutingRequired(sch) && pd.routing == "" {
					writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[%s]/[%s]", pd.destIndex, "_doc", pd.id))
					return
				}
				var nextVer int64
				if useExternalVer || (!exists && pd.scriptVerSet && pd.srcVer > 0) {
					nextVer = pd.srcVer
					_ = s.allocVersion(nextVer)
				} else if exists && pd.scriptVerSet && pd.srcVer > 0 {
					nextVer = existing.Version + 1
					_ = s.allocVersion(nextVer)
				} else if !exists && minVer == 0 {
					nextVer = 1
				} else if minVer > 0 && minVer < 1_000_000_000_000 {
					nextVer = minVer
				} else {
					nextVer = s.allocVersion(minVer)
				}
				shredded, err := schema.ShredDocument(sch, pd.id, nextVer, false, pd.source)
				if err != nil {
					writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
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
				if writtenDocsByIdx[pd.destIndex] == nil {
					writtenDocsByIdx[pd.destIndex] = make(map[string]HitRow)
				}
				writtenDocsByIdx[pd.destIndex][pd.id] = HitRow{ID: pd.id, Version: nextVer, Source: pd.source}
				if deletedVerByIdx[pd.destIndex] != nil {
					delete(deletedVerByIdx[pd.destIndex], pd.id)
				}
				s.setDocRouting(pd.destIndex, pd.id, pd.routing)
				s.setDocVersion(pd.destIndex, pd.id, nextVer)
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
			if !useGlobalSort {
				nextSA := extractHitSortValues(hits[len(hits)-1], effSort, srcSchema)
				if len(nextSA) == 0 {
					nextSA = []any{hits[len(hits)-1].ID}
				}
				searchAfter = nextSA
			}
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
		"noops":                  totalNoops,
		"retries":                map[string]any{"bulk": 0, "search": 0},
		"throttled_millis":       0,
		"requests_per_second":    rps,
		"throttled_until_millis": 0,
		"failures":               failures,
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
		if strings.Contains(err.Error(), "cannot promote field") {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
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
	if ddls == nil {
		return nil, fmt.Errorf("cannot promote field [%s] with type [%s]", cleanField, esType)
	}
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
	opts := s.transpileOpts
	opts.MaxResultWindow = 0
	tr := transpiler.NewTranspiler(newSchema, opts)
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
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	wantsExplain := r.URL.Query().Get("explain") == "true" || r.URL.Query().Has("explain") || r.URL.Query().Get("rewrite") == "true"
	writeInvalidResp := func(errMsg string, targetList []string) {
		nShards := len(targetList)
		if nShards == 0 {
			nShards = 1
		}
		resp := map[string]any{
			"valid":   false,
			"error":   errMsg,
			"_shards": map[string]any{"total": nShards, "successful": nShards, "failed": 0},
		}
		if wantsExplain {
			idxForExpl := rawIndex
			if len(targetList) > 0 {
				idxForExpl = targetList[0]
			}
			resp["explanations"] = []map[string]any{
				{
					"index": idxForExpl,
					"valid": false,
					"error": errMsg,
				},
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}

	var targets []string
	var aliasFilters map[string]*esast.Query
	if rawIndex != "" {
		var ok bool
		targets, aliasFilters, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}

	raw, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req esast.SearchRequest
	if len(bytes.TrimSpace(raw)) > 0 {
		var rawTop map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawTop); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		for k := range rawTop {
			switch k {
			case "query", "pit", "aggs", "aggregations", "runtime_mappings":
			default:
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("Unknown key for a START_OBJECT in [validate/query]: [%s].", k))
				return
			}
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			writeInvalidResp(err.Error(), targets)
			return
		}
	}
	applyURISearchParams(r, &req)
	if req.PIT != nil && req.PIT.ID != "" {
		pitIdx, ok := decodePITIndex(req.PIT.ID)
		if !ok || pitIdx == "" {
			writeInvalidResp("invalid pit id ["+req.PIT.ID+"]", targets)
			return
		}
	}
	if errMsg := validatePipelineAggs(req.EffectiveAggs()); errMsg != "" {
		writeInvalidResp(errMsg, targets)
		return
	}
	if rawIndex == "" {
		rawIndex = extractPITIndex(rawIndex, req.PIT)
		targets, aliasFilters = s.resolveTargetIndicesWithFilters(rawIndex)
	}
	if len(targets) == 0 {
		if rawIndex != "" {
			resp := map[string]any{
				"valid":   true,
				"_shards": map[string]any{"total": 0, "successful": 0, "failed": 0},
			}
			if wantsExplain {
				resp["explanations"] = []map[string]any{}
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		targets = []string{"_all"}
	}
	s.resolveStoredScriptsInSearchRequest(&req)
	_ = s.preResolveSpecialQueriesInSearchRequest(r.Context(), targets, &req)
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)
	if resolved := s.resolveTermsLookupsInSearchRequest(r.Context(), &req); resolved != nil {
		req = *resolved
	}

	var explanations []map[string]any
	for _, idxName := range targets {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		subReq := applyIndexAliasFilter(&req, aliasFilters[idxName])
		plan, err := tr.BuildSearchPlan(subReq)
		if err != nil {
			writeInvalidResp(err.Error(), targets)
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
	if req.Normalizer == "" {
		req.Normalizer = r.URL.Query().Get("normalizer")
	}
	if req.Field == "" {
		req.Field = r.URL.Query().Get("field")
	}
	if req.Text == nil && r.URL.Query().Get("text") != "" {
		req.Text = r.URL.Query().Get("text")
	}

	if handled := s.tryHandleCustomIndexAnalyze(w, r, bodyBytes); handled {
		return
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
		if b.LowercaseNormalizer && req.Normalizer == "" {
			req.Normalizer = "lowercase"
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
			normLower := strings.ToLower(strings.TrimSpace(req.Normalizer))
			switch {
			case strings.Contains(normLower, "upper") || strings.Contains(analyzer, "upper"):
				tok = strings.ToUpper(tok)
			case (normLower != "" && normLower != "none") || strings.Contains(analyzer, "lower"):
				tok = strings.ToLower(tok)
			}
			tokens = append(tokens, map[string]any{
				"token":        tok,
				"start_offset": 0,
				"end_offset":   utf8.RuneCountInString(txt),
				"type":         "word",
				"position":     pos,
			})
			pos++
			continue
		}
		startOff := -1
		var cur strings.Builder
		runeIdx := 0
		for _, ch := range txt {
			isWord := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch > 127
			if strings.Contains(analyzer, "whitespace") {
				isWord = ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r'
			}
			if isWord {
				if startOff < 0 {
					startOff = runeIdx
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
					"end_offset":   runeIdx,
					"type":         "<ALPHANUM>",
					"position":     pos,
				})
				pos++
				cur.Reset()
				startOff = -1
			}
			runeIdx++
		}
		if startOff >= 0 {
			tokens = append(tokens, map[string]any{
				"token":        cur.String(),
				"start_offset": startOff,
				"end_offset":   runeIdx,
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
	if r != nil && r.Method != "" && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Conditions map[string]any     `json:"conditions,omitempty"`
		Mappings   *esast.MappingSpec `json:"mappings,omitempty"`
		Settings   map[string]any     `json:"settings,omitempty"`
		Aliases    map[string]any     `json:"aliases,omitempty"`
		DryRun     *bool              `json:"dry_run,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	dryRun := strings.EqualFold(r.URL.Query().Get("dry_run"), "true") || (req.DryRun != nil && *req.DryRun)
	alias := strings.TrimSpace(r.PathValue("alias"))
	newIdx := strings.TrimSpace(r.PathValue("new_index"))
	if alias == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: rollover target is missing;")
		return
	}
	if newIdx != "" {
		if reason, ok := validateESIndexName(newIdx); !ok {
			writeESError(w, http.StatusBadRequest, "invalid_index_name_exception", reason)
			return
		}
	}

	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	_, isConcreteIndex := s.indices[alias]
	_, newIdxExists := s.indices[newIdx]
	ds, isDataStream := s.dataStreams[alias]
	var dsGeneration int64 = 1
	var dsLastBacking string
	if isDataStream && ds != nil {
		if g, ok := toInt64(ds["generation"]); ok && g > 0 {
			dsGeneration = g
		}
		if rawIndices, ok := ds["indices"].([]any); ok && len(rawIndices) > 0 {
			if m, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM {
				dsLastBacking, _ = m["index_name"].(string)
			}
		}
		if dsLastBacking == "" {
			dsLastBacking = alias
		}
	}
	targets := append([]string(nil), s.aliases[alias]...)
	metaByIdx := s.aliasMeta[alias]
	writeIdx := ""
	explicitNonWriteCount := 0
	for _, t := range targets {
		if metaByIdx != nil {
			if m, ok := metaByIdx[t]; ok && m.IsWriteIndex != nil {
				if *m.IsWriteIndex {
					writeIdx = t
					break
				}
				explicitNonWriteCount++
			}
		}
	}
	s.mu.RUnlock()

	if isConcreteIndex && !isDataStream && len(targets) == 0 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("index_name [%s] must be an alias or data_stream", alias))
		return
	}
	if !isDataStream && len(targets) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such index or alias [%s]", alias))
		return
	}
	if newIdx != "" && newIdxExists {
		writeESError(w, http.StatusBadRequest, "resource_already_exists_exception",
			fmt.Sprintf("index [%s] already exists", newIdx))
		return
	}

	if isDataStream && writeIdx == "" {
		writeIdx = dsLastBacking
	}
	if !isDataStream && ((len(targets) > 1 && writeIdx == "") || (len(targets) == 1 && explicitNonWriteCount == 1)) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Alias [%s] has more than one write index or no write index is specified", alias))
		return
	}
	oldIdx := alias + "-000001"
	if writeIdx != "" {
		oldIdx = writeIdx
	} else if len(targets) > 0 {
		oldIdx = targets[len(targets)-1]
	}
	nextGen := int(dsGeneration) + 1
	if newIdx == "" {
		if isDataStream {
			newIdx = fmt.Sprintf(".ds-%s-%06d", alias, nextGen)
		} else {
			newIdx = incrementRolloverIndexName(oldIdx)
		}
	}
	s.mu.RLock()
	_, autoNewExists := s.indices[newIdx]
	newAliasCollision := len(s.aliases[newIdx]) > 0 || s.dataStreams[newIdx] != nil
	s.mu.RUnlock()
	if autoNewExists {
		writeESError(w, http.StatusBadRequest, "resource_already_exists_exception",
			fmt.Sprintf("index [%s] already exists", newIdx))
		return
	}
	if newAliasCollision {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception",
			fmt.Sprintf("Invalid index name [%s], already exists as alias", newIdx))
		return
	}

	condResults := make(map[string]bool)
	shouldRollover := true
	if len(req.Conditions) > 0 {
		anyMet := false
		if rawMD, hasMD := req.Conditions["max_docs"]; hasMD {
			maxDocs, _ := toInt64(rawMD)
			var docCount int64
			zero := 0
			if resp, _, errType, _ := s.executeSearchRequest(r.Context(), oldIdx, &esast.SearchRequest{Size: &zero, TrackTotalHits: true}); errType == "" {
				if hitsObj, ok := resp["hits"].(map[string]any); ok {
					if totalObj, ok := hitsObj["total"].(map[string]any); ok {
						docCount, _ = toInt64(totalObj["value"])
					}
				}
			}
			met := docCount >= maxDocs
			condResults[fmt.Sprintf("[max_docs: %d]", maxDocs)] = met
			if met {
				anyMet = true
			}
		}
		if rawMA, hasMA := req.Conditions["max_age"]; hasMA {
			ageStr := strings.TrimSpace(fmt.Sprintf("%v", rawMA))
			met := strings.HasPrefix(ageStr, "0")
			condResults[fmt.Sprintf("[max_age: %s]", ageStr)] = met
			if met {
				anyMet = true
			}
		}
		if rawMS, hasMS := req.Conditions["max_size"]; hasMS {
			sizeStr := strings.TrimSpace(fmt.Sprintf("%v", rawMS))
			met := strings.HasPrefix(sizeStr, "0")
			condResults[fmt.Sprintf("[max_size: %s]", sizeStr)] = met
			if met {
				anyMet = true
			}
		}
		if rawMPSS, hasMPSS := req.Conditions["max_primary_shard_size"]; hasMPSS {
			sizeStr := strings.TrimSpace(fmt.Sprintf("%v", rawMPSS))
			met := strings.HasPrefix(sizeStr, "0")
			condResults[fmt.Sprintf("[max_primary_shard_size: %s]", sizeStr)] = met
			if met {
				anyMet = true
			}
		}
		shouldRollover = anyMet
	}

	rolledOver := shouldRollover && !dryRun
	if rolledOver {
		var baseMapping *esast.MappingSpec
		s.mu.RLock()
		tplMapping, tplDefPipe, hasTplDefPipe, tplFinPipe, hasTplFinPipe, tplAliases := s.matchingTemplateConfigLocked(newIdx)
		if isDataStream {
			dsTplMap, dsDefPipe, hasDSDef, dsFinPipe, hasDSFin, dsAliases := s.matchingTemplateConfigLocked(alias)
			tplMapping = schema.MergeMappingSpecs(dsTplMap, tplMapping)
			if !hasTplDefPipe && hasDSDef {
				tplDefPipe, hasTplDefPipe = dsDefPipe, true
			}
			if !hasTplFinPipe && hasDSFin {
				tplFinPipe, hasTplFinPipe = dsFinPipe, true
			}
			if tplAliases == nil && len(dsAliases) > 0 {
				tplAliases = dsAliases
			}
		}
		if oldSchema, ok := s.indices[oldIdx]; ok && oldSchema != nil {
			baseMapping = schema.MergeMappingSpecs(tplMapping, oldSchema.RawMapping)
		} else {
			baseMapping = tplMapping
		}
		s.mu.RUnlock()
		if req.Mappings != nil {
			baseMapping = schema.MergeMappingSpecs(baseMapping, req.Mappings)
		}

		compiled := schema.CompileIndexSchema(s.dorisDB, newIdx, baseMapping)
		if err := s.backend.ExecDDL(r.Context(), schema.GenerateCreateTableDDL(compiled)); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
			return
		}

		var persistedDS map[string]any
		s.mu.Lock()
		s.indices[newIdx] = compiled
		if hasTplDefPipe && tplDefPipe != "" {
			s.indexDefaultPipelines[newIdx] = tplDefPipe
		}
		if hasTplFinPipe && tplFinPipe != "" {
			s.indexFinalPipelines[newIdx] = tplFinPipe
		}
		if p, found := extractDefaultPipelineFromSettings(req.Settings); found {
			if p == "" {
				delete(s.indexDefaultPipelines, newIdx)
			} else {
				s.indexDefaultPipelines[newIdx] = p
			}
		}
		if fp, found := extractFinalPipelineFromSettings(req.Settings); found {
			if fp == "" {
				delete(s.indexFinalPipelines, newIdx)
			} else {
				s.indexFinalPipelines[newIdx] = fp
			}
		}
		extraAliasTargets := make(map[string][]string, len(tplAliases)+len(req.Aliases))
		for tplAlias, rawMeta := range tplAliases {
			s.addAliasWithMetaLocked(tplAlias, newIdx, parseAliasMetadata(rawMeta))
			extraAliasTargets[tplAlias] = append([]string(nil), s.aliases[tplAlias]...)
		}
		for extraAlias, rawMeta := range req.Aliases {
			s.addAliasWithMetaLocked(extraAlias, newIdx, parseAliasMetadata(rawMeta))
			extraAliasTargets[extraAlias] = append([]string(nil), s.aliases[extraAlias]...)
		}
		var updatedTargets []string
		if isDataStream {
			fVal := false
			tVal := true
			s.addAliasWithMetaLocked(alias, oldIdx, AliasMetadata{IsWriteIndex: &fVal})
			s.addAliasWithMetaLocked(alias, newIdx, AliasMetadata{IsWriteIndex: &tVal})
			updatedTargets = append([]string(nil), s.aliases[alias]...)
			if curDS := s.dataStreams[alias]; curDS != nil {
				rawIndices, _ := curDS["indices"].([]any)
				rawIndices = append(rawIndices, map[string]any{
					"index_name": newIdx,
					"index_uuid": newIdx,
				})
				curDS["indices"] = rawIndices
				curDS["generation"] = nextGen
				persistedDS = deepCloneDocMap(curDS)
			}
		} else if metaByIdx := s.aliasMeta[alias]; metaByIdx != nil {
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
		if persistedDS != nil {
			s.persistDataStream(r.Context(), alias, persistedDS)
		}
		for extraAlias, extraTargets := range extraAliasTargets {
			s.persistAlias(r.Context(), extraAlias, extraTargets)
		}
		s.queryCache.InvalidateAll()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"old_index":           oldIdx,
		"new_index":           newIdx,
		"rolled_over":         rolledOver,
		"dry_run":             dryRun,
		"conditions":          condResults,
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
		var rawMap map[string]any
		if err := json.Unmarshal(bodyBytes, &rawMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		for k := range rawMap {
			switch k {
			case "field", "string", "size", "index_filter", "case_insensitive", "search_after", "timeout":
			default:
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("[terms_enum] unknown field [%s]", k))
				return
			}
		}
		if rawSize, hasSize := rawMap["size"]; hasSize {
			if sz, ok := toInt64(rawSize); !ok || sz <= 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "size must be greater than 0")
				return
			}
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if strings.TrimSpace(req.Field) == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "field must be specified for _terms_enum")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex != "" {
		targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
		s.mu.RLock()
		for _, idxName := range targets {
			if sch := s.indices[idxName]; sch != nil {
				if fb, exists := sch.Fields[req.Field]; exists && fb.ESType != "" {
					switch fb.ESType {
					case "keyword", "constant_keyword", "flattened", "version", "wildcard":
					default:
						s.mu.RUnlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("field [%s] is of an unsupported type [%s] for terms_enum", req.Field, fb.ESType))
						return
					}
				}
			}
		}
		s.mu.RUnlock()
	}
	limit := req.Size
	if limit <= 0 {
		limit = 10
	}
	aggSize := 10000
	if limit > aggSize {
		aggSize = limit * 2
	}
	zero := 0
	searchReq := esast.SearchRequest{
		Size:  &zero,
		Query: req.IndexFilter,
		Aggs: map[string]esast.AggSpec{
			"_terms_enum": {
				Terms: &esast.TermsAggSpec{
					Field: req.Field,
					Size:  aggSize,
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
	hasWildcard := strings.ContainsAny(prefix, "*?")
	if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
		if teObj, ok := aggsMap["_terms_enum"].(map[string]any); ok {
			var allKeys []string
			switch buckets := teObj["buckets"].(type) {
			case []map[string]any:
				allKeys = make([]string, 0, len(buckets))
				for _, b := range buckets {
					allKeys = append(allKeys, fmt.Sprintf("%v", b["key"]))
				}
			case []any:
				allKeys = make([]string, 0, len(buckets))
				for _, item := range buckets {
					if b, ok := item.(map[string]any); ok {
						allKeys = append(allKeys, fmt.Sprintf("%v", b["key"]))
					}
				}
			}
			if allKeys != nil {
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
						if hasWildcard {
							targetKey := k
							pat := prefix
							if req.CaseInsensitive {
								targetKey = strings.ToLower(k)
								pat = prefixLower
							}
							if !matchWildcardPattern(pat, targetKey) {
								continue
							}
						} else if req.CaseInsensitive {
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
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(rawIndex)
	if readErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	s.mu.RLock()
	_, idxExists := s.indices[indexName]
	isClosed := s.closedIndices[indexName]
	s.mu.RUnlock()
	if !idxExists {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	if isClosed {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", "closed ["+indexName+"]")
		return
	}
	if blocked, reason := s.isIndexReadBlocked(indexName); blocked {
		writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
		return
	}
	docID := r.PathValue("id")
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req esast.SearchRequest
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var rawTop map[string]json.RawMessage
		if err := json.Unmarshal(bodyBytes, &rawTop); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		for k := range rawTop {
			switch k {
			case "query", "post_filter", "min_score", "_source", "stored_fields", "fields", "docvalue_fields", "script_fields", "runtime_mappings":
			default:
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("Unknown key for a START_OBJECT in [explain]: [%s].", k))
				return
			}
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	applyURISearchParams(r, &req)

	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	effRouting := s.resolveEffectiveReadRouting(r.PathValue("index"), indexName, reqRouting)
	if s.isRoutingRequired(idxSchema) && effRouting == "" {
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[%s]/[%s]", indexName, "_doc", docID))
		return
	}
	s.resolveStoredScriptsInSearchRequest(&req)
	_ = s.preResolveSpecialQueriesInSearchRequest(r.Context(), []string{indexName}, &req)
	s.resolveTermsLookupsInQuery(r.Context(), aliasFilter)
	resolvedReq := s.resolveTermsLookupsInSearchRequest(r.Context(), &req)
	idxSchema = s.augmentSchemaWithRuntimeMappings(idxSchema, resolvedReq.RuntimeMappings)
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
	if found && hit != nil && effRouting != "" && !s.docMatchesRequestRouting(indexName, docID, effRouting) {
		found = false
		hit = nil
	}
	if found && hit != nil {
		hitSlice := []HitRow{*hit}
		s.evalRuntimeMappingsOnHitRows(idxSchema, resolvedReq.RuntimeMappings, hitSlice)
		*hit = hitSlice[0]
	}
	if !found || hit == nil || (aliasFilter != nil && !s.docMatchesAliasFilterWithSchema(r.Context(), indexName, idxSchema, docID, hit.EffectiveSource(), aliasFilter)) {
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

	effSrc := hit.EffectiveSource()
	matched := s.docMatchesAliasFilterWithSchema(r.Context(), indexName, idxSchema, docID, effSrc, effQuery)
	cq := tr.CompileQuery(effQuery, true, nil)
	scoreVal := 0.0
	desc := "no match on required clause (" + cq.WhereSQL + ")"
	if matched {
		scoreVal = 1.0
		if shreddedBytes, err := schema.ShredDocument(idxSchema, docID, hit.Version, false, effSrc); err == nil {
			var row map[string]any
			dec := json.NewDecoder(bytes.NewReader(shreddedBytes))
			dec.UseNumber()
			if err := dec.Decode(&row); err == nil && row != nil {
				var docMap map[string]any
				docDec := json.NewDecoder(bytes.NewReader(effSrc))
				docDec.UseNumber()
				if err := docDec.Decode(&docMap); err == nil {
					row["_doc"] = docMap
				}
				if cq.ScoreSQL != "" {
					scoreVal = evalNumericExpr(row, cq.ScoreSQL)
				}
			}
		}
		origQuery := resolvedReq.Query
		hasScoringWrapper := (effQuery != nil && (effQuery.FunctionScore != nil || effQuery.ScriptScore != nil)) ||
			(origQuery != nil && (origQuery.FunctionScore != nil || origQuery.ScriptScore != nil))
		if queryHasRuntimeScript(effQuery) || queryHasNestedScoring(effQuery) || hasScoringWrapper {
			var docMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(effSrc))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
			if docMap == nil {
				docMap = make(map[string]any)
			}
			docMap["__meta_id"] = docID
			baseScore := scoreVal
			if (effQuery != nil && ((effQuery.ScriptScore != nil && effQuery.ScriptScore.Query == nil) || (effQuery.FunctionScore != nil && effQuery.FunctionScore.Query == nil))) ||
				(origQuery != nil && ((origQuery.ScriptScore != nil && origQuery.ScriptScore.Query == nil) || (origQuery.FunctionScore != nil && origQuery.FunctionScore.Query == nil))) {
				baseScore = 1.0
			}
			scoreVal = evalQueryScriptScoreOnDocWithSchema(idxSchema, docMap, effQuery, baseScore)
		}
		var effScriptScoreMin, effFuncScoreMin *float64
		if effQuery != nil && effQuery.ScriptScore != nil && effQuery.ScriptScore.MinScore != nil {
			effScriptScoreMin = effQuery.ScriptScore.MinScore
		} else if origQuery != nil && origQuery.ScriptScore != nil && origQuery.ScriptScore.MinScore != nil {
			effScriptScoreMin = origQuery.ScriptScore.MinScore
		}
		if effQuery != nil && effQuery.FunctionScore != nil && effQuery.FunctionScore.MinScore != nil {
			effFuncScoreMin = effQuery.FunctionScore.MinScore
		} else if origQuery != nil && origQuery.FunctionScore != nil && origQuery.FunctionScore.MinScore != nil {
			effFuncScoreMin = origQuery.FunctionScore.MinScore
		}
		if resolvedReq.PostFilter != nil && !s.docMatchesAliasFilterWithSchema(r.Context(), indexName, idxSchema, docID, effSrc, resolvedReq.PostFilter) {
			matched = false
			scoreVal = 0.0
			desc = "no match on post_filter"
		} else if resolvedReq.MinScore != nil && scoreVal < *resolvedReq.MinScore {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *resolvedReq.MinScore)
		} else if effScriptScoreMin != nil && scoreVal < *effScriptScoreMin {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *effScriptScoreMin)
		} else if effFuncScoreMin != nil && scoreVal < *effFuncScoreMin {
			matched = false
			scoreVal = 0.0
			desc = fmt.Sprintf("score (< %.4f) is less than min_score", *effFuncScoreMin)
		} else {
			desc = "weight(" + cq.WhereSQL + ") [DorisInvertedIndex], result of: " + cq.ScoreSQL
		}
	}
	outResp := map[string]any{
		"_index":  indexName,
		"_type":   "_doc",
		"_id":     docID,
		"matched": matched,
		"explanation": map[string]any{
			"value":       scoreVal,
			"description": desc,
			"details":     []any{},
		},
	}
	if r.URL.Query().Has("_source") || r.URL.Query().Has("_source_includes") || r.URL.Query().Has("_source_excludes") || r.URL.Query().Has("stored_fields") {
		getObj := map[string]any{
			"found":         true,
			"_seq_no":       hit.Version,
			"_primary_term": 1,
			"_version":      hit.Version,
		}
		if resolvedReq.Source == nil || !resolvedReq.Source.Disabled {
			filtered := filterSourceJSON(hit.Source, resolvedReq.Source)
			var srcVal any
			if len(filtered) > 0 {
				dec := json.NewDecoder(bytes.NewReader(filtered))
				dec.UseNumber()
				_ = dec.Decode(&srcVal)
			}
			if srcVal == nil {
				srcVal = map[string]any{}
			}
			getObj["_source"] = srcVal
		}
		storedFieldsList := esast.StoredFieldsSlice(resolvedReq.StoredFields)
		omitAllStored := resolvedReq.HasStoredFieldsNone()
		if !omitAllStored && len(storedFieldsList) > 0 {
			var docMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(hit.Source))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
			fieldsMap := make(map[string]any)
			for _, sf := range storedFieldsList {
				if sf == "_none_" {
					continue
				}
				if val, exists := getIngestPath(docMap, sf); exists && val != nil {
					if arr, isArr := val.([]any); isArr {
						fieldsMap[sf] = arr
					} else {
						fieldsMap[sf] = []any{val}
					}
				}
			}
			if len(fieldsMap) > 0 {
				getObj["fields"] = fieldsMap
			}
		}
		outResp["get"] = getObj
	}
	writeJSON(w, http.StatusOK, outResp)
}

func parseIngestCSVLine(line string, sep, quote rune, trim bool) ([]string, []bool, error) {
	runes := []rune(line)
	n := len(runes)
	var fields []string
	var quoted []bool
	i := 0
	for {
		if trim {
			for i < n && (runes[i] == ' ' || runes[i] == '\t') && runes[i] != sep && runes[i] != quote {
				i++
			}
		}
		if i < n && runes[i] == quote {
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				if runes[i] == quote {
					if i+1 < n && runes[i+1] == quote {
						sb.WriteRune(quote)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				sb.WriteRune(runes[i])
				i++
			}
			if !closed {
				return nil, nil, fmt.Errorf("parse_exception: unterminated quoted field in csv")
			}
			if trim {
				for i < n && (runes[i] == ' ' || runes[i] == '\t') && runes[i] != sep {
					i++
				}
			}
			if i < n && runes[i] != sep && runes[i] != '\r' && runes[i] != '\n' {
				return nil, nil, fmt.Errorf("parse_exception: unexpected character after closing quote in csv")
			}
			fields = append(fields, sb.String())
			quoted = append(quoted, true)
		} else {
			start := i
			for i < n && runes[i] != sep && runes[i] != '\r' && runes[i] != '\n' {
				if runes[i] == quote {
					return nil, nil, fmt.Errorf("parse_exception: bare quote in unquoted csv field")
				}
				i++
			}
			val := string(runes[start:i])
			if trim {
				val = strings.TrimSpace(val)
			}
			fields = append(fields, val)
			quoted = append(quoted, false)
		}
		if i >= n || runes[i] == '\r' || runes[i] == '\n' {
			break
		}
		if runes[i] == sep {
			i++
			if i == n {
				fields = append(fields, "")
				quoted = append(quoted, false)
				break
			}
		}
	}
	return fields, quoted, nil
}

func isIPInNetworkDirectionNets(ip net.IP, nets []string) bool {
	if len(nets) == 0 {
		nets = []string{"private"}
	}
	for _, entry := range nets {
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch entry {
		case "private", "iana_private":
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return true
			}
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
				return true
			}
		case "rfc1918":
			if ip.IsPrivate() {
				return true
			}
		case "rfc6598", "carrier_grade_nat":
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
				return true
			}
		case "loopback":
			if ip.IsLoopback() {
				return true
			}
		case "link_local":
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return true
			}
		case "multicast":
			if ip.IsMulticast() {
				return true
			}
		case "unspecified":
			if ip.IsUnspecified() {
				return true
			}
		default:
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr != nil {
				if cidr.Contains(ip) {
					return true
				}
			} else if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func executeNetworkDirectionProcessor(doc map[string]any, specMap map[string]any) (bool, error) {
	srcField := "source.ip"
	if sf, _ := specMap["source_ip"].(string); sf != "" {
		srcField = expandIngestFieldName(sf, doc)
	}
	dstField := "destination.ip"
	if df, _ := specMap["destination_ip"].(string); df != "" {
		dstField = expandIngestFieldName(df, doc)
	}
	target := "network.direction"
	if tf, _ := specMap["target_field"].(string); tf != "" {
		target = expandIngestFieldName(tf, doc)
	}
	var nets []string
	if netsField, _ := specMap["internal_networks_field"].(string); netsField != "" {
		netsField = expandIngestFieldName(netsField, doc)
		if nfVal, ok := getIngestPath(doc, netsField); ok && nfVal != nil {
			switch tv := nfVal.(type) {
			case []any:
				for _, el := range tv {
					nets = append(nets, fmt.Sprintf("%v", el))
				}
			case string:
				nets = append(nets, tv)
			}
		}
	}
	if len(nets) == 0 {
		if netsArr, ok := specMap["internal_networks"].([]any); ok {
			for _, el := range netsArr {
				nets = append(nets, fmt.Sprintf("%v", el))
			}
		}
	}
	srcVal, hasSrc := getIngestPath(doc, srcField)
	dstVal, hasDst := getIngestPath(doc, dstField)
	if !hasSrc || srcVal == nil || !hasDst || dstVal == nil {
		if isExplicitIgnoreMissingFalse(specMap) {
			if !hasSrc || srcVal == nil {
				return false, fmt.Errorf("field [%s] is missing", srcField)
			}
			return false, fmt.Errorf("field [%s] is missing", dstField)
		}
		return false, nil
	}
	srcIP := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", srcVal)))
	dstIP := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", dstVal)))
	if srcIP == nil || dstIP == nil {
		return false, fmt.Errorf("invalid IP address in network_direction")
	}
	srcInt := isIPInNetworkDirectionNets(srcIP, nets)
	dstInt := isIPInNetworkDirectionNets(dstIP, nets)
	var dir string
	switch {
	case srcInt && dstInt:
		dir = "internal"
	case srcInt && !dstInt:
		dir = "outbound"
	case !srcInt && dstInt:
		dir = "inbound"
	default:
		dir = "external"
	}
	setIngestPath(doc, target, dir)
	return true, nil
}

func communityIDICMPEquiv(proto uint8, icmpType uint16) (uint16, bool) {
	switch proto {
	case 1:
		switch icmpType {
		case 8:
			return 0, true
		case 0:
			return 8, true
		case 13:
			return 14, true
		case 14:
			return 13, true
		case 15:
			return 16, true
		case 16:
			return 15, true
		case 17:
			return 18, true
		case 18:
			return 17, true
		}
	case 58:
		switch icmpType {
		case 128:
			return 129, true
		case 129:
			return 128, true
		case 130:
			return 131, true
		case 131:
			return 130, true
		case 133:
			return 134, true
		case 134:
			return 133, true
		case 135:
			return 136, true
		case 136:
			return 135, true
		case 139:
			return 140, true
		case 140:
			return 139, true
		case 144:
			return 145, true
		case 145:
			return 144, true
		case 146:
			return 147, true
		case 147:
			return 146, true
		}
	}
	return 0, false
}

func executeCommunityIDProcessor(doc map[string]any, specMap map[string]any) (bool, error) {
	srcIPField := "source.ip"
	if v, _ := specMap["source_ip"].(string); v != "" {
		srcIPField = expandIngestFieldName(v, doc)
	}
	dstIPField := "destination.ip"
	if v, _ := specMap["destination_ip"].(string); v != "" {
		dstIPField = expandIngestFieldName(v, doc)
	}
	srcPortField := "source.port"
	if v, _ := specMap["source_port"].(string); v != "" {
		srcPortField = expandIngestFieldName(v, doc)
	}
	dstPortField := "destination.port"
	if v, _ := specMap["destination_port"].(string); v != "" {
		dstPortField = expandIngestFieldName(v, doc)
	}
	transportField := "network.transport"
	if v, _ := specMap["transport"].(string); v != "" {
		transportField = expandIngestFieldName(v, doc)
	}
	ianaField := "network.iana_number"
	if v, _ := specMap["iana_number"].(string); v != "" {
		ianaField = expandIngestFieldName(v, doc)
	}
	icmpTypeField := "icmp.type"
	if v, _ := specMap["icmp_type"].(string); v != "" {
		icmpTypeField = expandIngestFieldName(v, doc)
	}
	icmpCodeField := "icmp.code"
	if v, _ := specMap["icmp_code"].(string); v != "" {
		icmpCodeField = expandIngestFieldName(v, doc)
	}
	target := "network.community_id"
	if tf, _ := specMap["target_field"].(string); tf != "" {
		target = expandIngestFieldName(tf, doc)
	}
	var seed uint16
	if sVal, ok := toInt64(specMap["seed"]); ok && sVal >= 0 && sVal <= 65535 {
		seed = uint16(sVal)
	}
	srcIPVal, hasSrc := getIngestPath(doc, srcIPField)
	dstIPVal, hasDst := getIngestPath(doc, dstIPField)
	if !hasSrc || srcIPVal == nil || !hasDst || dstIPVal == nil {
		if isExplicitIgnoreMissingFalse(specMap) {
			return false, fmt.Errorf("source or destination IP field is missing")
		}
		return false, nil
	}
	rawSrcIP := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", srcIPVal)))
	rawDstIP := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", dstIPVal)))
	if rawSrcIP == nil || rawDstIP == nil {
		return false, fmt.Errorf("invalid IP address in community_id")
	}
	ip1 := rawSrcIP.To4()
	if ip1 == nil {
		ip1 = rawSrcIP.To16()
	}
	ip2 := rawDstIP.To4()
	if ip2 == nil {
		ip2 = rawDstIP.To16()
	}
	if len(ip1) != len(ip2) {
		return false, fmt.Errorf("illegal_argument_exception: source IP [%v] and destination IP [%v] must be of the same IP version", srcIPVal, dstIPVal)
	}
	var proto uint8 = 6
	hasExplicitProto := false
	if ianaVal, ok := getIngestPath(doc, ianaField); ok && ianaVal != nil {
		if iv, okI := toInt64(ianaVal); okI && iv >= 0 && iv <= 255 {
			proto = uint8(iv)
			hasExplicitProto = true
		} else {
			return false, fmt.Errorf("illegal_argument_exception: invalid iana_number [%v]", ianaVal)
		}
	}
	if !hasExplicitProto {
		if trVal, ok := getIngestPath(doc, transportField); ok && trVal != nil {
			hasExplicitProto = true
			switch strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", trVal))) {
			case "tcp", "6":
				proto = 6
			case "udp", "17":
				proto = 17
			case "icmp", "1":
				proto = 1
			case "icmpv6", "ipv6-icmp", "58":
				proto = 58
			case "sctp", "132":
				proto = 132
			default:
				if iv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", trVal))); err == nil && iv >= 0 && iv <= 255 {
					proto = uint8(iv)
				} else {
					return false, fmt.Errorf("unsupported transport [%v]", trVal)
				}
			}
		}
	}
	parsePortInRange := func(raw any, maxVal int64, label string) (uint16, error) {
		v, ok := toInt64(raw)
		if !ok || v < 0 || v > maxVal {
			return 0, fmt.Errorf("illegal_argument_exception: invalid %s [%v], must be between 0 and %d", label, raw, maxVal)
		}
		// #nosec G115 -- v is bounded to [0, maxVal] where maxVal <= 65535
		return uint16(v), nil
	}
	var p1, p2 uint16
	hasPorts := false
	isOneWay := false
	if proto == 1 || proto == 58 {
		tVal, hasT := getIngestPath(doc, icmpTypeField)
		cVal, hasC := getIngestPath(doc, icmpCodeField)
		spVal, hasSP := getIngestPath(doc, srcPortField)
		dpVal, hasDP := getIngestPath(doc, dstPortField)
		var hasType, hasCode bool
		if hasT && tVal != nil {
			tv, err := parsePortInRange(tVal, 255, icmpTypeField)
			if err != nil {
				return false, err
			}
			p1 = tv
			hasType = true
		} else if hasSP && spVal != nil {
			tv, err := parsePortInRange(spVal, 255, srcPortField)
			if err != nil {
				return false, err
			}
			p1 = tv
			hasType = true
		}
		if hasC && cVal != nil {
			cv, err := parsePortInRange(cVal, 255, icmpCodeField)
			if err != nil {
				return false, err
			}
			p2 = cv
			hasCode = true
		} else if hasDP && dpVal != nil {
			cv, err := parsePortInRange(dpVal, 255, dstPortField)
			if err != nil {
				return false, err
			}
			p2 = cv
			hasCode = true
		}
		if hasType {
			hasPorts = true
			if mirror, equiv := communityIDICMPEquiv(proto, p1); equiv {
				p2 = mirror
			} else if !hasCode {
				p2 = 0
				isOneWay = true
			} else {
				isOneWay = true
			}
		} else if hasCode {
			return false, fmt.Errorf("illegal_argument_exception: icmp type / source_port is required when icmp code / destination_port is present")
		}
	} else {
		spVal, hasSP := getIngestPath(doc, srcPortField)
		dpVal, hasDP := getIngestPath(doc, dstPortField)
		var okSP, okDP bool
		if hasSP && spVal != nil {
			sp, err := parsePortInRange(spVal, 65535, srcPortField)
			if err != nil {
				return false, err
			}
			p1 = sp
			okSP = true
		}
		if hasDP && dpVal != nil {
			dp, err := parsePortInRange(dpVal, 65535, dstPortField)
			if err != nil {
				return false, err
			}
			p2 = dp
			okDP = true
		}
		if okSP && okDP {
			hasPorts = true
		} else if okSP || okDP {
			return false, fmt.Errorf("illegal_argument_exception: both source_port and destination_port must be present")
		}
	}
	if !hasExplicitProto && !hasPorts {
		if isExplicitIgnoreMissingFalse(specMap) {
			return false, fmt.Errorf("transport and port fields are missing")
		}
		return false, nil
	}
	if !isOneWay {
		cmp := bytes.Compare(ip1, ip2)
		if cmp > 0 || (cmp == 0 && hasPorts && p1 > p2) {
			ip1, ip2 = ip2, ip1
			p1, p2 = p2, p1
		}
	}
	buf := make([]byte, 0, 48)
	buf = append(buf, byte(seed>>8), byte(seed))
	buf = append(buf, ip1...)
	buf = append(buf, ip2...)
	buf = append(buf, proto, 0)
	if hasPorts {
		buf = append(buf, byte(p1>>8), byte(p1), byte(p2>>8), byte(p2))
	}
	// #nosec G401 -- Community ID v1 network flow hashing specification requires SHA-1
	sum := sha1.Sum(buf)
	setIngestPath(doc, target, "1:"+base64.StdEncoding.EncodeToString(sum[:]))
	return true, nil
}

func executeGeoIPProcessor(doc map[string]any, specMap map[string]any) (bool, error) {
	field, _ := specMap["field"].(string)
	field = expandIngestFieldName(field, doc)
	if field == "" {
		return false, nil
	}
	target := "geoip"
	if tf, _ := specMap["target_field"].(string); tf != "" {
		target = expandIngestFieldName(tf, doc)
	}
	val, exists := getIngestPath(doc, field)
	if !exists || val == nil {
		if isExplicitIgnoreMissingFalse(specMap) {
			return false, fmt.Errorf("field [%s] is missing", field)
		}
		return false, nil
	}
	var ipCandidates []string
	switch v := val.(type) {
	case string:
		ipCandidates = []string{v}
	case []any:
		for _, el := range v {
			if el != nil {
				ipCandidates = append(ipCandidates, fmt.Sprintf("%v", el))
			}
		}
	default:
		return false, fmt.Errorf("field [%s] is not an IP string", field)
	}
	var matchedIP net.IP
	for _, rawIP := range ipCandidates {
		parsed := net.ParseIP(strings.TrimSpace(rawIP))
		if parsed == nil {
			return false, fmt.Errorf("['%s'] is not an IP string literal", rawIP)
		}
		if !parsed.IsPrivate() && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() && !parsed.IsUnspecified() {
			matchedIP = parsed
			break
		}
	}
	if matchedIP == nil {
		return false, nil
	}
	fullGeo := map[string]any{
		"continent_name":   "North America",
		"country_iso_code": "US",
		"country_name":     "United States",
		"region_iso_code":  "US-CA",
		"region_name":      "California",
		"city_name":        "Mountain View",
		"timezone":         "America/Los_Angeles",
		"location": map[string]any{
			"lat": 37.386,
			"lon": -122.0838,
		},
		"ip": matchedIP.String(),
	}
	if propsArr, ok := specMap["properties"].([]any); ok && len(propsArr) > 0 {
		filtered := make(map[string]any, len(propsArr))
		for _, p := range propsArr {
			k := fmt.Sprintf("%v", p)
			if gv, hasG := fullGeo[k]; hasG {
				filtered[k] = gv
			}
		}
		fullGeo = filtered
	}
	setIngestPath(doc, target, fullGeo)
	return true, nil
}

func (s *Server) handleEnrichAPI(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	if strings.HasSuffix(r.URL.Path, "/_stats") || strings.HasSuffix(r.URL.Path, "/stats") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"executing_policies": []any{},
			"coordinator_stats":  []any{},
		})
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if r.PathValue("action") == "_execute" {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
			return
		}
		s.mu.RLock()
		pol, exists := s.enrichPolicies[name]
		s.mu.RUnlock()
		if !exists {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "enrich policy ["+name+"] not found")
			return
		}
		pIdx, _, _, _, pQuery := extractEnrichPolicyMeta(pol)
		var snapshotDocs []map[string]any
		for _, idxPat := range pIdx {
			for _, targetIdx := range s.resolveTargetIndices(idxPat) {
				scanLimit := 10000
				resp, _, errType, _ := s.executeSearchRequest(r.Context(), targetIdx, &esast.SearchRequest{
					Query: pQuery,
					Size:  &scanLimit,
				})
				if errType != "" {
					continue
				}
				if hitsEnv, ok := resp["hits"].(map[string]any); ok {
					appendHitDoc := func(h map[string]any) {
						if srcRaw, ok := h["_source"].(json.RawMessage); ok {
							var m map[string]any
							dec := json.NewDecoder(bytes.NewReader(srcRaw))
							dec.UseNumber()
							if dec.Decode(&m) == nil && m != nil {
								snapshotDocs = append(snapshotDocs, m)
							}
						} else if srcMap, ok := h["_source"].(map[string]any); ok && srcMap != nil {
							snapshotDocs = append(snapshotDocs, srcMap)
						}
					}
					switch hitsList := hitsEnv["hits"].(type) {
					case []map[string]any:
						for _, h := range hitsList {
							appendHitDoc(h)
						}
					case []any:
						for _, item := range hitsList {
							if h, ok := item.(map[string]any); ok {
								appendHitDoc(h)
							}
						}
					}
				}
			}
		}
		s.mu.Lock()
		if curPol := s.enrichPolicies[name]; curPol != nil {
			curPol["__snapshot_docs"] = snapshotDocs
			curPol["__executed"] = true
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"status": map[string]any{"phase": "COMPLETE"},
		})
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "enrich policy name is required")
			return
		}
		s.mu.RLock()
		_, alreadyExists := s.enrichPolicies[name]
		s.mu.RUnlock()
		if alreadyExists {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Cannot update enrich policy ["+name+"] - enrich policies are immutable")
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
		if len(body) == 0 {
			writeESError(w, http.StatusBadRequest, "parse_exception", "enrich policy must specify one of [match, geo_match, range]")
			return
		}
		var matchedType string
		var innerMap map[string]any
		for k, v := range body {
			switch k {
			case "match", "geo_match", "range":
				if matchedType != "" {
					writeESError(w, http.StatusBadRequest, "parse_exception", "enrich policy must specify only one policy type")
					return
				}
				m, ok := v.(map[string]any)
				if !ok || m == nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", "["+k+"] must be an object")
					return
				}
				matchedType = k
				innerMap = m
			default:
				writeESError(w, http.StatusBadRequest, "parse_exception", fmt.Sprintf("unknown field [%s] in enrich policy", k))
				return
			}
		}
		if matchedType == "" || innerMap == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "enrich policy must specify one of [match, geo_match, range]")
			return
		}
		pIdx, pMF, pEF, _, _ := extractEnrichPolicyMeta(map[string]any{matchedType: innerMap})
		if len(pIdx) == 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[indices] must not be empty")
			return
		}
		if strings.TrimSpace(pMF) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[match_field] must not be empty")
			return
		}
		if len(pEF) == 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "[enrich_fields] must not be empty")
			return
		}
		cp := make(map[string]any, len(innerMap)+1)
		for k, v := range innerMap {
			cp[k] = v
		}
		cp["name"] = name
		stored := map[string]any{
			matchedType: cp,
		}
		s.mu.Lock()
		if s.enrichPolicies == nil {
			s.enrichPolicies = make(map[string]map[string]any)
		}
		s.enrichPolicies[name] = stored
		s.mu.Unlock()
		s.persistEnrichPolicy(r.Context(), name, stored)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodGet:
		s.mu.RLock()
		if name != "" && !strings.ContainsAny(name, "*?,") && name != "_all" {
			if _, ok := s.enrichPolicies[name]; !ok {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "enrich policy ["+name+"] not found")
				return
			}
		}
		names := make([]string, 0, len(s.enrichPolicies))
		for k := range s.enrichPolicies {
			names = append(names, k)
		}
		sort.Strings(names)
		policies := make([]map[string]any, 0, len(names))
		patterns := strings.Split(name, ",")
		for _, k := range names {
			matched := name == "" || name == "*" || name == "_all"
			if !matched {
				for _, pat := range patterns {
					pat = strings.TrimSpace(pat)
					if pat != "" && matchWildcardPattern(pat, k) {
						matched = true
						break
					}
				}
			}
			if matched {
				cleanCfg := make(map[string]any, len(s.enrichPolicies[k]))
				for ck, cv := range s.enrichPolicies[k] {
					if !strings.HasPrefix(ck, "__") {
						cleanCfg[ck] = cv
					}
				}
				policies = append(policies, map[string]any{
					"config": cleanCfg,
				})
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"policies": policies})

	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "enrich policy name is required")
			return
		}
		s.mu.Lock()
		_, existed := s.enrichPolicies[name]
		delete(s.enrichPolicies, name)
		s.mu.Unlock()
		if !existed {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "enrich policy ["+name+"] not found")
			return
		}
		s.deleteEnrichPolicyCatalog(r.Context(), name)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func extractEnrichPolicyMeta(pol map[string]any) (indices []string, matchField string, enrichFields []string, policyType string, policyQuery *esast.Query) {
	if pol == nil {
		return nil, "", nil, "", nil
	}
	if cfgWrap, ok := pol["config"].(map[string]any); ok && cfgWrap != nil {
		pol = cfgWrap
	}
	inner := pol
	for _, pType := range []string{"match", "geo_match", "range"} {
		if m, ok := pol[pType].(map[string]any); ok {
			inner = m
			policyType = pType
			break
		}
	}
	matchField, _ = inner["match_field"].(string)
	switch rawIdx := inner["indices"].(type) {
	case string:
		for _, p := range strings.Split(rawIdx, ",") {
			if p = strings.TrimSpace(p); p != "" {
				indices = append(indices, p)
			}
		}
	case []any:
		for _, item := range rawIdx {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				indices = append(indices, strings.TrimSpace(s))
			}
		}
	case []string:
		indices = append(indices, rawIdx...)
	}
	switch rawEF := inner["enrich_fields"].(type) {
	case []any:
		for _, item := range rawEF {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				enrichFields = append(enrichFields, strings.TrimSpace(s))
			}
		}
	case []string:
		enrichFields = append(enrichFields, rawEF...)
	}
	if rawQ, hasQ := inner["query"]; hasQ && rawQ != nil {
		switch qt := rawQ.(type) {
		case string:
			qTrim := strings.TrimSpace(qt)
			if strings.HasPrefix(qTrim, "{") {
				var parsed esast.Query
				if json.Unmarshal([]byte(qTrim), &parsed) == nil {
					policyQuery = &parsed
				}
			} else if qTrim != "" {
				policyQuery = &esast.Query{
					QueryString: &esast.QueryStringQuery{Query: qTrim},
				}
			}
		case map[string]any:
			if rawBytes, err := json.Marshal(qt); err == nil {
				var parsed esast.Query
				if json.Unmarshal(rawBytes, &parsed) == nil {
					policyQuery = &parsed
				}
			}
		}
	}
	return indices, matchField, enrichFields, policyType, policyQuery
}

func compareEnrichRangeValues(a, b any) (int, bool) {
	if af, aOk := toFloat(a); aOk {
		if bf, bOk := toFloat(b); bOk {
			if af < bf {
				return -1, true
			}
			if af > bf {
				return 1, true
			}
			return 0, true
		}
	}
	aStr := strings.TrimSpace(fmt.Sprintf("%v", a))
	bStr := strings.TrimSpace(fmt.Sprintf("%v", b))
	if aIP := net.ParseIP(aStr); aIP != nil {
		if bIP := net.ParseIP(bStr); bIP != nil {
			return bytes.Compare(aIP.To16(), bIP.To16()), true
		}
	}
	if aMs, aOk := schema.ParseESDateWithFormatToEpochMillis(aStr, "", time.Now().UTC()); aOk {
		if bMs, bOk := schema.ParseESDateWithFormatToEpochMillis(bStr, "", time.Now().UTC()); bOk {
			if aMs < bMs {
				return -1, true
			}
			if aMs > bMs {
				return 1, true
			}
			return 0, true
		}
	}
	return strings.Compare(aStr, bStr), true
}

func enrichSingleSpecMatchesSingleValue(rangeSpec any, lookupVal any) bool {
	if rangeSpec == nil || lookupVal == nil {
		return false
	}
	switch rs := rangeSpec.(type) {
	case []any:
		for _, elem := range rs {
			if enrichSingleSpecMatchesSingleValue(elem, lookupVal) {
				return true
			}
		}
		return false
	case string:
		sTrim := strings.TrimSpace(rs)
		valStr := strings.TrimSpace(fmt.Sprintf("%v", lookupVal))
		if _, ipNet, err := net.ParseCIDR(sTrim); err == nil && ipNet != nil {
			if ip := net.ParseIP(valStr); ip != nil {
				return ipNet.Contains(ip)
			}
		}
		return sTrim == valStr
	case map[string]any:
		hasBound := false
		if bVal, ok := rs["gte"]; ok && bVal != nil {
			hasBound = true
			if cmp, okCmp := compareEnrichRangeValues(lookupVal, bVal); !okCmp || cmp < 0 {
				return false
			}
		}
		if bVal, ok := rs["gt"]; ok && bVal != nil {
			hasBound = true
			if cmp, okCmp := compareEnrichRangeValues(lookupVal, bVal); !okCmp || cmp <= 0 {
				return false
			}
		}
		if bVal, ok := rs["lte"]; ok && bVal != nil {
			hasBound = true
			if cmp, okCmp := compareEnrichRangeValues(lookupVal, bVal); !okCmp || cmp > 0 {
				return false
			}
		}
		if bVal, ok := rs["lt"]; ok && bVal != nil {
			hasBound = true
			if cmp, okCmp := compareEnrichRangeValues(lookupVal, bVal); !okCmp || cmp >= 0 {
				return false
			}
		}
		return hasBound
	default:
		return fmt.Sprintf("%v", rangeSpec) == fmt.Sprintf("%v", lookupVal)
	}
}

func enrichDocMatchesRangeValue(srcMap map[string]any, matchField string, lookupVal any) bool {
	rangeSpec, ok := getIngestPath(srcMap, matchField)
	if !ok || rangeSpec == nil {
		return false
	}
	if lookupSlice, isSlice := lookupVal.([]any); isSlice {
		for _, elem := range lookupSlice {
			if enrichSingleSpecMatchesSingleValue(rangeSpec, elem) {
				return true
			}
		}
		return false
	}
	return enrichSingleSpecMatchesSingleValue(rangeSpec, lookupVal)
}

func enrichScalarValuesEqual(a, b any) bool {
	if a == nil || b == nil {
		return false
	}
	if af, aOk := toFloat(a); aOk {
		if bf, bOk := toFloat(b); bOk {
			return af == bf
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func expandEnrichScalarSlice(v any) []any {
	switch s := v.(type) {
	case []any:
		out := make([]any, 0, len(s))
		for _, el := range s {
			if el != nil {
				out = append(out, el)
			}
		}
		return out
	case []string:
		out := make([]any, 0, len(s))
		for _, el := range s {
			out = append(out, el)
		}
		return out
	default:
		if v == nil {
			return nil
		}
		return []any{v}
	}
}

func enrichDocMatchesExactValue(srcMap map[string]any, matchField string, lookupVal any) bool {
	docVal, ok := getIngestPath(srcMap, matchField)
	if !ok || docVal == nil {
		return false
	}
	docVals := expandEnrichScalarSlice(docVal)
	lookupVals := expandEnrichScalarSlice(lookupVal)
	for _, dv := range docVals {
		for _, lv := range lookupVals {
			if enrichScalarValuesEqual(dv, lv) {
				return true
			}
		}
	}
	return false
}

func executeEnrichProcessor(s *Server, doc map[string]any, specMap map[string]any) (bool, error) {
	field, _ := specMap["field"].(string)
	field = expandIngestFieldName(field, doc)
	target, _ := specMap["target_field"].(string)
	target = expandIngestFieldName(target, doc)
	if field == "" || target == "" {
		return false, nil
	}
	maxMatches := 1
	if rawMM, hasMM := specMap["max_matches"]; hasMM && rawMM != nil {
		mm, ok := toInt64(rawMM)
		if !ok || mm < 1 || mm > 128 {
			return false, fmt.Errorf("[max_matches] must be between 1 and 128")
		}
		maxMatches = int(mm)
	}
	val, exists := getIngestPath(doc, field)
	if !exists || val == nil {
		if isExplicitIgnoreMissingFalse(specMap) {
			return false, fmt.Errorf("field [%s] is missing", field)
		}
		return false, nil
	}
	override := true
	if ov, hasOv := specMap["override"].(bool); hasOv {
		override = ov
	}
	if !override {
		if existing, hasEx := getIngestPath(doc, target); hasEx && existing != nil {
			return false, nil
		}
	}
	policyName, _ := specMap["policy_name"].(string)
	matchField, _ := specMap["match_field"].(string)
	var policyIndices []string
	var enrichFields []string
	var policyType string
	var policyQuery *esast.Query
	var snapshotDocs []map[string]any
	hadConfiguredSource := false
	if s != nil && policyName != "" {
		s.mu.RLock()
		pol := s.enrichPolicies[policyName]
		s.mu.RUnlock()
		if pol == nil {
			_ = s.syncCatalogFromBackend(context.Background())
			s.mu.RLock()
			pol = s.enrichPolicies[policyName]
			s.mu.RUnlock()
		}
		if pol != nil {
			hadConfiguredSource = true
			pIdx, pMF, pEF, pType, pQuery := extractEnrichPolicyMeta(pol)
			policyIndices = pIdx
			if matchField == "" && pMF != "" {
				matchField = pMF
			}
			enrichFields = pEF
			policyType = pType
			policyQuery = pQuery
			if snap, ok := pol["__snapshot_docs"].([]map[string]any); ok {
				snapshotDocs = snap
			}
		}
	}
	if len(enrichFields) == 0 {
		switch rawEF := specMap["enrich_fields"].(type) {
		case []any:
			for _, item := range rawEF {
				if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
					enrichFields = append(enrichFields, strings.TrimSpace(str))
				}
			}
		case []string:
			enrichFields = append(enrichFields, rawEF...)
		}
	}
	if matchField == "" {
		matchField = field
	}
	var matchKeys []string
	if valSlice, isSlice := val.([]any); isSlice {
		for _, elem := range valSlice {
			if elem != nil {
				matchKeys = append(matchKeys, fmt.Sprintf("%v", elem))
			}
		}
	} else {
		matchKeys = []string{fmt.Sprintf("%v", val)}
	}
	var matches []any
	if entries, ok := specMap["entries"].(map[string]any); ok {
		hadConfiguredSource = true
		for _, mk := range matchKeys {
			if entry, hasE := entries[mk]; hasE {
				matches = append(matches, entry)
			}
		}
	} else if lookup, ok := specMap["lookup"].(map[string]any); ok {
		hadConfiguredSource = true
		for _, mk := range matchKeys {
			if entry, hasL := lookup[mk]; hasL {
				matches = append(matches, entry)
			}
		}
	}
	if len(matches) == 0 && len(snapshotDocs) > 0 {
		for _, srcMap := range snapshotDocs {
			if len(matches) >= maxMatches {
				break
			}
			if policyType == "range" {
				if enrichDocMatchesRangeValue(srcMap, matchField, val) {
					matches = append(matches, srcMap)
				}
			} else if enrichDocMatchesExactValue(srcMap, matchField, val) {
				matches = append(matches, srcMap)
			}
		}
	}
	if len(matches) == 0 && s != nil && (policyName != "" || len(policyIndices) > 0) {
		candIndices := append([]string(nil), policyIndices...)
		if srcIdx, _ := specMap["source_index"].(string); srcIdx != "" {
			candIndices = append(candIndices, srcIdx)
		}
		if policyName != "" {
			candIndices = append(candIndices, policyName, strings.TrimSuffix(policyName, "-policy"), strings.TrimSuffix(policyName, "_policy"))
		}
		seenCand := make(map[string]bool, len(candIndices))
		for _, cIdx := range candIndices {
			if cIdx == "" || seenCand[cIdx] {
				continue
			}
			seenCand[cIdx] = true
			targets := s.resolveTargetIndices(cIdx)
			if len(targets) == 0 {
				continue
			}
			hadConfiguredSource = true
			if policyType == "range" {
				scanLimit := 1000
				resp, _, errType, _ := s.executeSearchRequest(context.Background(), cIdx, &esast.SearchRequest{
					Query: policyQuery,
					Size:  &scanLimit,
				})
				if errType == "" {
					if hitsEnv, ok := resp["hits"].(map[string]any); ok {
						extractRangeHit := func(h map[string]any) {
							if len(matches) >= maxMatches {
								return
							}
							var srcMap map[string]any
							if srcRaw, ok := h["_source"].(json.RawMessage); ok {
								dec := json.NewDecoder(bytes.NewReader(srcRaw))
								dec.UseNumber()
								_ = dec.Decode(&srcMap)
							} else if sm, ok := h["_source"].(map[string]any); ok {
								srcMap = sm
							}
							if srcMap != nil && enrichDocMatchesRangeValue(srcMap, matchField, val) {
								matches = append(matches, srcMap)
							}
						}
						switch hitsList := hitsEnv["hits"].(type) {
						case []map[string]any:
							for _, h := range hitsList {
								extractRangeHit(h)
							}
						case []any:
							for _, item := range hitsList {
								if h, ok := item.(map[string]any); ok {
									extractRangeHit(h)
								}
							}
						}
					}
				}
				if len(matches) >= maxMatches {
					break
				}
				continue
			}
			var q *esast.Query
			if valSlice, isSlice := val.([]any); isSlice {
				q = &esast.Query{
					Terms: &esast.TermsQuery{
						Fields: map[string][]any{
							matchField: valSlice,
						},
					},
				}
			} else {
				q = &esast.Query{
					Term: map[string]esast.TermEntry{
						matchField: {Value: val},
					},
				}
			}
			q = combineQueryWithAliasFilter(q, policyQuery)
			sz := maxMatches * 4
			if sz < 10 {
				sz = 10
			}
			resp, _, errType, _ := s.executeSearchRequest(context.Background(), cIdx, &esast.SearchRequest{
				Query: q,
				Size:  &sz,
			})
			extractExactHitsFromResp := func(rMap map[string]any) {
				if hitsEnv, ok := rMap["hits"].(map[string]any); ok {
					extractHitSource := func(h map[string]any) {
						if len(matches) >= maxMatches {
							return
						}
						var srcMap map[string]any
						if srcRaw, ok := h["_source"].(json.RawMessage); ok {
							dec := json.NewDecoder(bytes.NewReader(srcRaw))
							dec.UseNumber()
							_ = dec.Decode(&srcMap)
						} else if sm, ok := h["_source"].(map[string]any); ok {
							srcMap = sm
						}
						if srcMap != nil && enrichDocMatchesExactValue(srcMap, matchField, val) {
							matches = append(matches, srcMap)
						}
					}
					switch hitsList := hitsEnv["hits"].(type) {
					case []map[string]any:
						for _, h := range hitsList {
							extractHitSource(h)
						}
					case []any:
						for _, item := range hitsList {
							if h, ok := item.(map[string]any); ok {
								extractHitSource(h)
							}
						}
					}
				}
			}
			if errType == "" {
				extractExactHitsFromResp(resp)
			}
			if len(matches) == 0 {
				scanLimit := 1000
				scanResp, _, scanErr, _ := s.executeSearchRequest(context.Background(), cIdx, &esast.SearchRequest{
					Query: policyQuery,
					Size:  &scanLimit,
				})
				if scanErr == "" {
					extractExactHitsFromResp(scanResp)
				}
			}
			if len(matches) >= maxMatches {
				break
			}
		}
	}
	if len(matches) > 0 {
		if len(enrichFields) > 0 {
			paths := make([]string, 0, len(enrichFields)+1)
			paths = append(paths, matchField)
			paths = append(paths, enrichFields...)
			for i, item := range matches {
				if m, ok := item.(map[string]any); ok {
					filtered := make(map[string]any, len(paths))
					for _, p := range paths {
						if p == "" {
							continue
						}
						if v, exists := getIngestPath(m, p); exists {
							setIngestPath(filtered, p, deepCloneIngestValue(v))
						}
					}
					matches[i] = filtered
				}
			}
		} else {
			for i, item := range matches {
				matches[i] = deepCloneIngestValue(item)
			}
		}
	}
	if len(matches) == 0 {
		if hadConfiguredSource {
			return false, nil
		}
		synth := make(map[string]any)
		setIngestPath(synth, matchField, deepCloneIngestValue(val))
		if policyName != "" {
			synth["policy_name"] = policyName
		}
		matches = append(matches, synth)
	}
	if len(matches) > maxMatches {
		matches = matches[:maxMatches]
	}
	if maxMatches > 1 {
		setIngestPath(doc, target, matches)
	} else {
		setIngestPath(doc, target, matches[0])
	}
	return true, nil
}

// handleResizeOrCloneIndex implements `POST/PUT /{index}/_clone/{target}`,
// `/{index}/_shrink/{target}`, and `/{index}/_split/{target}` by creating the target
// index with the source index's mappings and settings (plus any request overrides)
// and copying all documents from the source index into the target index.
func (s *Server) handleResizeOrCloneIndex(w http.ResponseWriter, r *http.Request) {
	srcIndex := s.resolveIndexName(r.PathValue("index"))
	targetIndex := strings.TrimSpace(r.PathValue("target"))
	if targetIndex == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "target index name is required")
		return
	}
	if reason, ok := validateESIndexName(targetIndex); !ok {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception", reason)
		return
	}
	var req esast.IndexCreateRequest
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
	}

	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	srcSchema := s.indices[srcIndex]
	_, targetExists := s.indices[targetIndex]
	hasTargetAliasCollision := len(s.aliases[targetIndex]) > 0 || s.dataStreams[targetIndex] != nil
	var badAliasName string
	for alias := range req.Aliases {
		if alias == targetIndex || s.indices[alias] != nil || s.dataStreams[alias] != nil {
			badAliasName = alias
			break
		}
	}
	srcDefPipe, hasSrcDef := s.indexDefaultPipelines[srcIndex]
	srcFinPipe, hasSrcFin := s.indexFinalPipelines[srcIndex]
	s.mu.RUnlock()

	if srcSchema == nil {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+srcIndex+"]")
		return
	}
	if targetExists || srcIndex == targetIndex {
		writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "index ["+targetIndex+"] already exists")
		return
	}
	if hasTargetAliasCollision {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception", "Invalid index name ["+targetIndex+"], already exists as alias")
		return
	}
	if badAliasName != "" {
		writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", "Invalid alias name ["+badAliasName+"], an index or data stream exists with the same name as the alias")
		return
	}
	if p, found := extractDefaultPipelineFromSettings(req.Settings); found && p != "" && p != "_none" && p != "none" {
		s.mu.RLock()
		_, pipeExists := s.pipelines[p]
		s.mu.RUnlock()
		if !pipeExists {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("pipeline with id [%s] does not exist", p))
			return
		}
	}
	if fp, found := extractFinalPipelineFromSettings(req.Settings); found && fp != "" && fp != "_none" && fp != "none" {
		s.mu.RLock()
		_, pipeExists := s.pipelines[fp]
		s.mu.RUnlock()
		if !pipeExists {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("pipeline with id [%s] does not exist", fp))
			return
		}
	}

	effectiveMappings := schema.MergeMappingSpecs(srcSchema.RawMapping, req.Mappings)
	compiled := schema.CompileIndexSchema(s.dorisDB, targetIndex, effectiveMappings)
	ddl := schema.GenerateCreateTableDDL(compiled)
	if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	s.indices[targetIndex] = compiled
	if srcRouting := s.docRouting[srcIndex]; len(srcRouting) > 0 {
		if s.docRouting == nil {
			s.docRouting = make(map[string]map[string]string)
		}
		if s.docRouting[targetIndex] == nil {
			s.docRouting[targetIndex] = make(map[string]string, len(srcRouting))
		}
		for docID, rVal := range srcRouting {
			s.docRouting[targetIndex][docID] = rVal
		}
	}
	if srcVersions := s.docVersions[srcIndex]; len(srcVersions) > 0 {
		if s.docVersions == nil {
			s.docVersions = make(map[string]map[string]int64)
		}
		if s.docVersions[targetIndex] == nil {
			s.docVersions[targetIndex] = make(map[string]int64, len(srcVersions))
		}
		for docID, ver := range srcVersions {
			s.docVersions[targetIndex][docID] = ver
		}
	}
	if hasSrcDef && srcDefPipe != "" {
		s.indexDefaultPipelines[targetIndex] = srcDefPipe
	}
	if hasSrcFin && srcFinPipe != "" {
		s.indexFinalPipelines[targetIndex] = srcFinPipe
	}
	if p, found := extractDefaultPipelineFromSettings(req.Settings); found {
		if p == "" {
			delete(s.indexDefaultPipelines, targetIndex)
		} else {
			s.indexDefaultPipelines[targetIndex] = p
		}
	}
	if fp, found := extractFinalPipelineFromSettings(req.Settings); found {
		if fp == "" {
			delete(s.indexFinalPipelines, targetIndex)
		} else {
			s.indexFinalPipelines[targetIndex] = fp
		}
	}
	for alias, rawMeta := range req.Aliases {
		meta := parseAliasMetadata(rawMeta)
		s.addAliasWithMetaLocked(alias, targetIndex, meta)
		aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
	}
	s.mu.Unlock()
	s.persistIndex(r.Context(), targetIndex, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(r.Context(), alias, targets)
	}

	_ = s.coalescer.FlushTable(r.Context(), srcSchema.DorisTable)
	opts := s.transpileOpts
	opts.MaxResultWindow = 0
	tr := transpiler.NewTranspiler(srcSchema, opts)
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
			break
		}
		hits, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
		if err != nil || len(hits) == 0 {
			break
		}
		var buf bytes.Buffer
		for _, h := range hits {
			shredded, err := schema.ShredDocument(compiled, h.ID, h.Version, false, h.Source)
			if err != nil {
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
