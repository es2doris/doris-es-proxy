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
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultReadyzCacheTTL      = 2 * time.Second
	maxHTTPMetricRouteKeysR67  = 512
	defaultReadyzProbeTimeout  = 5 * time.Second
	maxSanitizedRequestIDBytes = 128
)

var defaultLatencyBucketsR67 = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

type sfCallR67 struct {
	wg  sync.WaitGroup
	val any
	err error
}

// sfGroupR67 coalesces concurrent duplicate calls by key without external dependencies.
type sfGroupR67 struct {
	mu sync.Mutex
	m  map[string]*sfCallR67
}

func (g *sfGroupR67) Do(key string, fn func() (any, error)) (v any, err error, shared bool) {
	if g == nil {
		res, e := fn()
		return res, e, false
	}
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCallR67)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := &sfCallR67{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			c.err = fmt.Errorf("singleflight panic: %v", r)
		}
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()

	c.val, c.err = fn()
	return c.val, c.err, false
}

type promHistogramR67 struct {
	buckets []float64
	counts  []atomic.Uint64 // len(buckets) + 1 (+Inf)
	count   atomic.Uint64
	sumBits atomic.Uint64 // IEEE 754 float64 bits
}

func newPromHistogramR67(buckets []float64) *promHistogramR67 {
	cp := append([]float64(nil), buckets...)
	return &promHistogramR67{
		buckets: cp,
		counts:  make([]atomic.Uint64, len(cp)+1),
	}
}

func (h *promHistogramR67) observe(seconds float64) {
	if h == nil || math.IsNaN(seconds) || seconds < 0 {
		if seconds < 0 {
			seconds = 0
		} else {
			return
		}
	}
	h.count.Add(1)
	for {
		oldBits := h.sumBits.Load()
		newSum := math.Float64frombits(oldBits) + seconds
		if h.sumBits.CompareAndSwap(oldBits, math.Float64bits(newSum)) {
			break
		}
	}
	for i, bound := range h.buckets {
		if seconds <= bound {
			h.counts[i].Add(1)
			return
		}
	}
	h.counts[len(h.buckets)].Add(1)
}

func (h *promHistogramR67) writePrometheus(sb *strings.Builder, name, help string) {
	if h == nil || sb == nil {
		return
	}
	_, _ = fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	_, _ = fmt.Fprintf(sb, "# TYPE %s histogram\n", name)
	var cumulative uint64
	for i, bound := range h.buckets {
		cumulative += h.counts[i].Load()
		_, _ = fmt.Fprintf(sb, "%s_bucket{le=\"%s\"} %d\n", name, strconv.FormatFloat(bound, 'g', -1, 64), cumulative)
	}
	cumulative += h.counts[len(h.buckets)].Load()
	_, _ = fmt.Fprintf(sb, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
	_, _ = fmt.Fprintf(sb, "%s_sum %.6f\n", name, math.Float64frombits(h.sumBits.Load()))
	_, _ = fmt.Fprintf(sb, "%s_count %d\n", name, h.count.Load())
}

type httpRouteMetricKeyR67 struct {
	method      string
	route       string
	statusClass string
}

// ProxyMetricsR67 stores Prometheus-formatted latency histograms and operational counters.
type ProxyMetricsR67 struct {
	httpDuration       *promHistogramR67
	httpRouteMu        sync.RWMutex
	httpByRoute        map[httpRouteMetricKeyR67]*atomic.Uint64
	sqlDuration        *promHistogramR67
	sqlErrors          atomic.Uint64
	streamLoadDuration *promHistogramR67
	streamLoadRetries  atomic.Uint64
	streamLoadBytes    atomic.Uint64
	streamLoadErrors   atomic.Uint64
	bm25Mu             sync.Mutex
	bm25Outcomes       map[string]uint64
	catMu              sync.Mutex
	catSyncOutcomes    map[string]uint64
}

func newProxyMetricsR67() *ProxyMetricsR67 {
	return &ProxyMetricsR67{
		httpDuration:       newPromHistogramR67(defaultLatencyBucketsR67),
		httpByRoute:        make(map[httpRouteMetricKeyR67]*atomic.Uint64, 64),
		sqlDuration:        newPromHistogramR67(defaultLatencyBucketsR67),
		streamLoadDuration: newPromHistogramR67(defaultLatencyBucketsR67),
		bm25Outcomes:       make(map[string]uint64, 8),
		catSyncOutcomes:    make(map[string]uint64, 8),
	}
}

func statusClassLabelR67(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}

func normalizePromRouteLabelR67(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "/"
	}
	segs := strings.Split(trimmed, "/")
	switch {
	case segs[0] == "healthz" || segs[0] == "_healthz" || segs[0] == "livez":
		return "/healthz"
	case segs[0] == "readyz" || segs[0] == "_readyz":
		return "/readyz"
	case segs[0] == "metrics" || segs[0] == "_prometheus" || (len(segs) >= 2 && segs[0] == "_doris" && segs[1] == "metrics"):
		return "/metrics"
	case strings.HasPrefix(segs[0], "_"):
		if len(segs) >= 2 && strings.HasPrefix(segs[1], "_") || len(segs) == 2 && segs[0] == "_internal" {
			return "/" + segs[0] + "/" + segs[1]
		}
		if len(segs) >= 2 && (segs[0] == "_cluster" || segs[0] == "_security" || segs[0] == "_cat" || segs[0] == "_doris" || segs[0] == "_internal") {
			return "/" + segs[0] + "/" + segs[1]
		}
		return "/" + segs[0]
	case len(segs) == 1:
		return "/{index}"
	case segs[1] == "_doc" || segs[1] == "_create" || segs[1] == "_update" || segs[1] == "_source":
		return "/{index}/" + segs[1]
	case strings.HasPrefix(segs[1], "_"):
		return "/{index}/" + segs[1]
	case len(segs) >= 3 && strings.HasPrefix(segs[2], "_"):
		return "/{index}/_type/" + segs[2]
	default:
		return "/{index}/{resource}"
	}
}

func escapePromLabelValueR67(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// RecordHTTPRequest records request latency and bounded route/status counters.
func (m *ProxyMetricsR67) RecordHTTPRequest(method, rawPath string, status int, dur time.Duration) {
	if m == nil {
		return
	}
	m.httpDuration.observe(dur.Seconds())
	if method == "" {
		method = http.MethodGet
	}
	key := httpRouteMetricKeyR67{
		method:      strings.ToUpper(method),
		route:       normalizePromRouteLabelR67(rawPath),
		statusClass: statusClassLabelR67(status),
	}
	m.httpRouteMu.RLock()
	ctr, ok := m.httpByRoute[key]
	m.httpRouteMu.RUnlock()
	if !ok {
		m.httpRouteMu.Lock()
		ctr, ok = m.httpByRoute[key]
		if !ok {
			if len(m.httpByRoute) >= maxHTTPMetricRouteKeysR67 {
				key.route = "/{other}"
				ctr = m.httpByRoute[key]
			}
			if ctr == nil {
				ctr = &atomic.Uint64{}
				m.httpByRoute[key] = ctr
			}
		}
		m.httpRouteMu.Unlock()
	}
	ctr.Add(1)
}

// RecordSQL records Doris SQL execution latency and errors.
func (m *ProxyMetricsR67) RecordSQL(dur time.Duration, err error) {
	if m == nil {
		return
	}
	m.sqlDuration.observe(dur.Seconds())
	if err != nil {
		m.sqlErrors.Add(1)
	}
}

// RecordStreamLoad records Doris Stream Load latency, payload size, retries, and errors.
func (m *ProxyMetricsR67) RecordStreamLoad(dur time.Duration, bytes int64, retries int, err error) {
	if m == nil {
		return
	}
	m.streamLoadDuration.observe(dur.Seconds())
	if bytes > 0 {
		m.streamLoadBytes.Add(uint64(bytes))
	}
	if retries > 0 {
		m.streamLoadRetries.Add(uint64(retries))
	}
	if err != nil {
		m.streamLoadErrors.Add(1)
	}
}

// RecordBM25Scan increments the BM25 corpus stats scan counter for the given outcome.
func (m *ProxyMetricsR67) RecordBM25Scan(outcome string) {
	if m == nil {
		return
	}
	if outcome == "" {
		outcome = "unknown"
	}
	m.bm25Mu.Lock()
	m.bm25Outcomes[outcome]++
	m.bm25Mu.Unlock()
}

// RecordCatalogSync increments the catalog sync counter for the given outcome.
func (m *ProxyMetricsR67) RecordCatalogSync(outcome string) {
	if m == nil {
		return
	}
	if outcome == "" {
		outcome = "unknown"
	}
	m.catMu.Lock()
	m.catSyncOutcomes[outcome]++
	m.catMu.Unlock()
}

// RecordSQLMetrics exposes Doris SQL metrics recording on Server for backend instrumentation.
func (s *Server) RecordSQLMetrics(dur time.Duration, err error) {
	if s != nil && s.metrics != nil {
		s.metrics.RecordSQL(dur, err)
	}
}

// RecordStreamLoadMetrics exposes Doris Stream Load metrics recording on Server for stream load instrumentation.
func (s *Server) RecordStreamLoadMetrics(dur time.Duration, bytes int64, retries int, err error) {
	if s != nil && s.metrics != nil {
		s.metrics.RecordStreamLoad(dur, bytes, retries, err)
	}
}

// RecordBM25ScanMetric records a BM25 corpus stats scan outcome on Server.
func (s *Server) RecordBM25ScanMetric(outcome string) {
	if s != nil && s.metrics != nil {
		s.metrics.RecordBM25Scan(outcome)
	}
}

// RecordCatalogSyncMetric records a catalog synchronization outcome on Server.
func (s *Server) RecordCatalogSyncMetric(outcome string) {
	if s != nil && s.metrics != nil {
		s.metrics.RecordCatalogSync(outcome)
	}
}

// WritePrometheusMetrics renders extended HTTP, SQL, Stream Load, BM25, catalog sync,
// database pool, and Go runtime metrics in Prometheus exposition format.
func (m *ProxyMetricsR67) WritePrometheusMetrics(sb *strings.Builder, dbStats *sql.DBStats) {
	if m == nil || sb == nil {
		return
	}
	m.httpDuration.writePrometheus(
		sb,
		"doris_es_proxy_http_request_duration_seconds",
		"HTTP request latency distribution in seconds.",
	)

	m.httpRouteMu.RLock()
	type routeRow struct {
		key httpRouteMetricKeyR67
		val uint64
	}
	rows := make([]routeRow, 0, len(m.httpByRoute))
	for k, v := range m.httpByRoute {
		rows = append(rows, routeRow{key: k, val: v.Load()})
	}
	m.httpRouteMu.RUnlock()
	if len(rows) > 0 {
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].key.method != rows[j].key.method {
				return rows[i].key.method < rows[j].key.method
			}
			if rows[i].key.route != rows[j].key.route {
				return rows[i].key.route < rows[j].key.route
			}
			return rows[i].key.statusClass < rows[j].key.statusClass
		})
	}
	sb.WriteString("# HELP doris_es_proxy_http_requests_by_route_total HTTP requests broken down by method, route template, and status class.\n")
	sb.WriteString("# TYPE doris_es_proxy_http_requests_by_route_total counter\n")
	for _, r := range rows {
		_, _ = fmt.Fprintf(
			sb,
			"doris_es_proxy_http_requests_by_route_total{method=\"%s\",route=\"%s\",status_class=\"%s\"} %d\n",
			escapePromLabelValueR67(r.key.method),
			escapePromLabelValueR67(r.key.route),
			escapePromLabelValueR67(r.key.statusClass),
			r.val,
		)
	}

	m.sqlDuration.writePrometheus(
		sb,
		"doris_es_proxy_doris_sql_duration_seconds",
		"Doris SQL execution duration in seconds.",
	)
	sb.WriteString("# HELP doris_es_proxy_doris_sql_errors_total Total failed Doris SQL executions.\n")
	sb.WriteString("# TYPE doris_es_proxy_doris_sql_errors_total counter\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_doris_sql_errors_total %d\n", m.sqlErrors.Load())

	m.streamLoadDuration.writePrometheus(
		sb,
		"doris_es_proxy_stream_load_duration_seconds",
		"Doris Stream Load execution duration in seconds.",
	)
	sb.WriteString("# HELP doris_es_proxy_stream_load_retries_total Total Stream Load retry attempts.\n")
	sb.WriteString("# TYPE doris_es_proxy_stream_load_retries_total counter\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_stream_load_retries_total %d\n", m.streamLoadRetries.Load())

	sb.WriteString("# HELP doris_es_proxy_stream_load_bytes_total Total bytes submitted to Doris Stream Load.\n")
	sb.WriteString("# TYPE doris_es_proxy_stream_load_bytes_total counter\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_stream_load_bytes_total %d\n", m.streamLoadBytes.Load())

	sb.WriteString("# HELP doris_es_proxy_stream_load_errors_total Total failed Doris Stream Load batches.\n")
	sb.WriteString("# TYPE doris_es_proxy_stream_load_errors_total counter\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_stream_load_errors_total %d\n", m.streamLoadErrors.Load())

	m.bm25Mu.Lock()
	bm25Keys := make([]string, 0, len(m.bm25Outcomes))
	bm25Copy := make(map[string]uint64, len(m.bm25Outcomes))
	for k, v := range m.bm25Outcomes {
		bm25Keys = append(bm25Keys, k)
		bm25Copy[k] = v
	}
	m.bm25Mu.Unlock()
	sort.Strings(bm25Keys)
	sb.WriteString("# HELP doris_es_proxy_bm25_corpus_scans_total BM25 corpus statistics scan outcomes.\n")
	sb.WriteString("# TYPE doris_es_proxy_bm25_corpus_scans_total counter\n")
	for _, k := range bm25Keys {
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_bm25_corpus_scans_total{outcome=\"%s\"} %d\n", escapePromLabelValueR67(k), bm25Copy[k])
	}

	m.catMu.Lock()
	catKeys := make([]string, 0, len(m.catSyncOutcomes))
	catCopy := make(map[string]uint64, len(m.catSyncOutcomes))
	for k, v := range m.catSyncOutcomes {
		catKeys = append(catKeys, k)
		catCopy[k] = v
	}
	m.catMu.Unlock()
	sort.Strings(catKeys)
	sb.WriteString("# HELP doris_es_proxy_catalog_syncs_total Catalog synchronization outcomes.\n")
	sb.WriteString("# TYPE doris_es_proxy_catalog_syncs_total counter\n")
	for _, k := range catKeys {
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_catalog_syncs_total{outcome=\"%s\"} %d\n", escapePromLabelValueR67(k), catCopy[k])
	}

	if dbStats != nil {
		sb.WriteString("# HELP doris_es_proxy_db_pool_connections Database connection pool metrics by state.\n")
		sb.WriteString("# TYPE doris_es_proxy_db_pool_connections gauge\n")
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_db_pool_connections{state=\"open\"} %d\n", dbStats.OpenConnections)
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_db_pool_connections{state=\"in_use\"} %d\n", dbStats.InUse)
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_db_pool_connections{state=\"idle\"} %d\n", dbStats.Idle)
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_db_pool_connections{state=\"wait_count\"} %d\n", dbStats.WaitCount)
		_, _ = fmt.Fprintf(sb, "doris_es_proxy_db_pool_connections{state=\"wait_duration_seconds\"} %.6f\n", dbStats.WaitDuration.Seconds())
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sb.WriteString("# HELP doris_es_proxy_go_goroutines Number of goroutines that currently exist.\n")
	sb.WriteString("# TYPE doris_es_proxy_go_goroutines gauge\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_go_goroutines %d\n", runtime.NumGoroutine())

	sb.WriteString("# HELP doris_es_proxy_go_mem_heap_inuse_bytes Bytes in in-use spans.\n")
	sb.WriteString("# TYPE doris_es_proxy_go_mem_heap_inuse_bytes gauge\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_go_mem_heap_inuse_bytes %d\n", ms.HeapInuse)

	sb.WriteString("# HELP doris_es_proxy_go_gc_pause_total_seconds Total GC stop-the-world pause duration in seconds.\n")
	sb.WriteString("# TYPE doris_es_proxy_go_gc_pause_total_seconds counter\n")
	_, _ = fmt.Fprintf(sb, "doris_es_proxy_go_gc_pause_total_seconds %.6f\n", float64(ms.PauseTotalNs)/1e9)
}

type readyzSnapshotR67 struct {
	checkedAt time.Time
	status    int
	payload   map[string]any
}

type readyzCacheR67 struct {
	mu       sync.RWMutex
	ttl      time.Duration
	snapshot *readyzSnapshotR67
	sf       sfGroupR67
}

func newReadyzCacheR67() *readyzCacheR67 {
	return &readyzCacheR67{
		ttl: defaultReadyzCacheTTL,
	}
}

func cloneReadyzPayloadR67(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (rc *readyzCacheR67) check(ctx context.Context, s *Server) (int, map[string]any) {
	if s == nil || s.backend == nil {
		return http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  "backend is not configured",
		}
	}
	if rc == nil {
		return probeReadyzOnceR67(ctx, s)
	}
	ttl := rc.ttl
	if ttl <= 0 {
		ttl = defaultReadyzCacheTTL
	}

	now := time.Now()
	rc.mu.RLock()
	snap := rc.snapshot
	rc.mu.RUnlock()
	if snap != nil && now.Sub(snap.checkedAt) < ttl {
		return snap.status, cloneReadyzPayloadR67(snap.payload)
	}

	res, _, _ := rc.sf.Do("readyz", func() (any, error) {
		rc.mu.RLock()
		cur := rc.snapshot
		rc.mu.RUnlock()
		if cur != nil && time.Since(cur.checkedAt) < ttl {
			return cur, nil
		}
		st, payload := probeReadyzOnceR67(ctx, s)
		nextSnap := &readyzSnapshotR67{
			checkedAt: time.Now(),
			status:    st,
			payload:   payload,
		}
		rc.mu.Lock()
		rc.snapshot = nextSnap
		rc.mu.Unlock()
		return nextSnap, nil
	})
	if outSnap, ok := res.(*readyzSnapshotR67); ok && outSnap != nil {
		return outSnap.status, cloneReadyzPayloadR67(outSnap.payload)
	}
	return probeReadyzOnceR67(ctx, s)
}

func probeReadyzOnceR67(ctx context.Context, s *Server) (int, map[string]any) {
	if s == nil || s.backend == nil {
		return http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  "backend is not configured",
		}
	}
	probeCtx := ctx
	if probeCtx == nil {
		probeCtx = context.Background()
	}
	var cancel context.CancelFunc
	if _, hasDeadline := probeCtx.Deadline(); !hasDeadline {
		probeCtx, cancel = context.WithTimeout(probeCtx, defaultReadyzProbeTimeout)
		defer cancel()
	}

	if err := s.backend.Ping(probeCtx); err != nil {
		return http.StatusServiceUnavailable, map[string]any{
			"status":   "not_ready",
			"doris_db": s.dorisDB,
			"error":    err.Error(),
		}
	}

	payload := map[string]any{
		"status":   "ready",
		"doris_db": s.dorisDB,
	}

	if ch, ok := s.backend.(ClusterHealthBackend); ok {
		aliveBEs, feHTTPOK, err := ch.CheckClusterHealth(probeCtx)
		payload["alive_bes"] = aliveBEs
		payload["fe_http_ok"] = feHTTPOK
		if err != nil {
			payload["status"] = "not_ready"
			payload["error"] = fmt.Sprintf("cluster health check failed: %v", err)
			return http.StatusServiceUnavailable, payload
		}
		if !feHTTPOK || aliveBEs < 1 {
			payload["status"] = "not_ready"
			payload["error"] = fmt.Sprintf("doris cluster unhealthy (fe_http_ok=%v, alive_bes=%d)", feHTTPOK, aliveBEs)
			return http.StatusServiceUnavailable, payload
		}
	}

	if inc, ok := s.backend.(IncrementalCatalogBackend); ok {
		if _, err := inc.LoadCatalogEntriesSince(probeCtx, s.dorisDB, math.MaxInt64); err != nil {
			payload["status"] = "not_ready"
			payload["error"] = fmt.Sprintf("catalog unreadable: %v", err)
			return http.StatusServiceUnavailable, payload
		}
	} else if cb, ok := s.backend.(CatalogBackend); ok {
		if _, err := cb.LoadCatalogEntries(probeCtx, s.dorisDB); err != nil {
			payload["status"] = "not_ready"
			payload["error"] = fmt.Sprintf("catalog unreadable: %v", err)
			return http.StatusServiceUnavailable, payload
		}
	}

	return http.StatusOK, payload
}

// SetReadyzCacheTTL configures the readiness probe cache duration (defaults to 2s).
func (s *Server) SetReadyzCacheTTL(d time.Duration) {
	if s == nil || s.readyzCache == nil || d <= 0 {
		return
	}
	s.readyzCache.mu.Lock()
	s.readyzCache.ttl = d
	s.readyzCache.snapshot = nil
	s.readyzCache.mu.Unlock()
}

type queryValuesCtxKeyR67 struct{}

// withCachedQueryValuesR67 parses r.URL.Query() once and stores it in r.Context().
func withCachedQueryValuesR67(r *http.Request) (*http.Request, url.Values) {
	if r == nil {
		return nil, url.Values{}
	}
	if cached, ok := r.Context().Value(queryValuesCtxKeyR67{}).(url.Values); ok && cached != nil {
		return r, cached
	}
	var vals url.Values
	if r.URL != nil {
		vals = r.URL.Query()
	} else {
		vals = url.Values{}
	}
	return r.WithContext(context.WithValue(r.Context(), queryValuesCtxKeyR67{}, vals)), vals
}

// requestQueryValuesR67 returns cached query values from request context or parses r.URL.Query().
func requestQueryValuesR67(r *http.Request) url.Values {
	if r == nil {
		return url.Values{}
	}
	if cached, ok := r.Context().Value(queryValuesCtxKeyR67{}).(url.Values); ok && cached != nil {
		return cached
	}
	if r.URL != nil {
		return r.URL.Query()
	}
	return url.Values{}
}

var requestIDCounterR67 atomic.Uint64

func generateRequestIDR67() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "req-" + hex.EncodeToString(b[:])
	}
	return "req-" + strconv.FormatUint(requestIDCounterR67.Add(1), 16)
}

func sanitizeRequestIDR67(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > maxSanitizedRequestIDBytes {
		s = s[:maxSanitizedRequestIDBytes]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < 0x20 || ch > 0x7e {
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func ensureRequestIDWireR67(w http.ResponseWriter, r *http.Request) (*http.Request, string) {
	if r == nil {
		return nil, ""
	}
	reqID := sanitizeRequestIDR67(r.Header.Get("X-Request-ID"))
	if reqID == "" {
		reqID = generateRequestIDR67()
	}
	if w != nil && w.Header().Get("X-Request-ID") == "" {
		w.Header().Set("X-Request-ID", reqID)
	}
	tp := r.Header.Get("traceparent")
	opq := r.Header.Get("X-Opaque-Id")
	r = r.WithContext(WithTraceMeta(r.Context(), TraceMeta{
		Traceparent: tp,
		OpaqueID:    opq,
		RequestID:   reqID,
	}))
	return r, reqID
}

// SetLogger configures a structured slog.Logger on Server for warnings and access logs.
func (s *Server) SetLogger(l *slog.Logger) {
	if s == nil {
		return
	}
	s.loggerMu.Lock()
	s.logger = l
	s.loggerMu.Unlock()
}

func (s *Server) getLogger() *slog.Logger {
	if s == nil {
		return nil
	}
	s.loggerMu.RLock()
	l := s.logger
	s.loggerMu.RUnlock()
	return l
}

func (s *Server) logWarn(msg string, args ...any) {
	if l := s.getLogger(); l != nil {
		l.Warn(msg, args...)
	}
}

func (s *Server) logAccess(r *http.Request, status int, dur time.Duration, reqID string) {
	l := s.getLogger()
	if l == nil || r == nil {
		return
	}
	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}
	l.Info("http_request",
		slog.String("request_id", reqID),
		slog.String("method", r.Method),
		slog.String("path", path),
		slog.Int("status", status),
		slog.Int64("duration_ms", dur.Milliseconds()),
	)
}

type statusCaptureWriterR67 struct {
	http.ResponseWriter
	status int
}

func (w *statusCaptureWriterR67) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriterR67) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusCaptureWriterR67) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusCaptureWriterR67) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// acquireAsyncTaskSlot bounds background async HTTP goroutines without blocking callers.
func (s *Server) acquireAsyncTaskSlot() bool {
	if s == nil || s.asyncTaskSem == nil {
		return true
	}
	select {
	case s.asyncTaskSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseAsyncTaskSlot() {
	if s == nil || s.asyncTaskSem == nil {
		return
	}
	select {
	case <-s.asyncTaskSem:
	default:
	}
}
