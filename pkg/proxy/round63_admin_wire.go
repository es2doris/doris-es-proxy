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
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// ============================================================================
// F6: HTTP Wire-Protocol Fidelity (Request Decompression, Accept-Encoding q=,
//     http_compression=false, Portless Host Sniffing)
// ============================================================================

type deflateReadCloserR63 struct {
	r      io.Reader
	closer io.Closer
	body   io.Closer
}

func (d *deflateReadCloserR63) Read(p []byte) (int, error) {
	return d.r.Read(p)
}

func (d *deflateReadCloserR63) Close() error {
	var firstErr error
	if d.closer != nil {
		if err := d.closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.body != nil {
		if err := d.body.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// extractHTTPCompressionQueryParamR63Wire parses and strips the optional `?http_compression=true|false`
// global wire parameter before strict endpoint query-parameter validation runs.
func extractHTTPCompressionQueryParamR63Wire(w http.ResponseWriter, r *http.Request) (disableGzip bool, ok bool) {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return false, true
	}
	q := r.URL.Query()
	if !q.Has("http_compression") {
		return false, true
	}
	raw := strings.ToLower(strings.TrimSpace(q.Get("http_compression")))
	switch raw {
	case "", "true", "1":
		disableGzip = false
	case "false", "0":
		disableGzip = true
	default:
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Failed to parse value [%s] as only [true] or [false] are allowed.", q.Get("http_compression")))
		return false, false
	}
	q.Del("http_compression")
	r.URL.RawQuery = q.Encode()
	return disableGzip, true
}

// parseMediaQualityWeightR63 extracts the RFC 9110 `;q=` weight from media/encoding parameters (default 1.0).
func parseMediaQualityWeightR63(params []string) float64 {
	q := 1.0
	for _, rawParam := range params {
		kv := strings.SplitN(strings.TrimSpace(rawParam), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil {
				if parsed < 0 {
					return 0
				}
				if parsed > 1 {
					return 1
				}
				q = parsed
			}
		}
	}
	return q
}

// acceptsGzipEncodingR63Wire evaluates RFC 9110 Accept-Encoding quality weights so `gzip;q=0`,
// `gzip;q=0.0`, and `identity;q=1, *;q=0` never compress responses.
func acceptsGzipEncodingR63Wire(headerVal string) bool {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "" {
		return false
	}
	seenGzip := false
	maxGzipQ := 0.0
	for _, part := range strings.Split(headerVal, ",") {
		semi := strings.Split(strings.TrimSpace(part), ";")
		coding := strings.ToLower(strings.TrimSpace(semi[0]))
		if coding == "" {
			continue
		}
		q := parseMediaQualityWeightR63(semi[1:])
		if coding == "gzip" || coding == "x-gzip" {
			if !seenGzip || q > maxGzipQ {
				maxGzipQ = q
			}
			seenGzip = true
		}
	}
	return seenGzip && maxGzipQ > 0
}

func readInitialHeaderBytesR63(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	total := 0
	for total < n {
		rn, err := r.Read(buf[total:])
		total += rn
		if err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

// decompressRequestBodyR63Wire transparently decompresses `gzip`, `x-gzip`, and `deflate` request bodies,
// treating 0-byte bodies as valid empty bodies and bounding decompressed output with `http.MaxBytesReader`.
func decompressRequestBodyR63Wire(w http.ResponseWriter, r *http.Request, maxBytes int64) (cleanup func(), ok bool) {
	rawCE := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	if rawCE == "" {
		return nil, true
	}
	var encodings []string
	for _, part := range strings.Split(rawCE, ",") {
		enc := strings.ToLower(strings.TrimSpace(part))
		if enc == "" || enc == "identity" {
			continue
		}
		encodings = append(encodings, enc)
	}
	if len(encodings) == 0 {
		r.Header.Del("Content-Encoding")
		return nil, true
	}
	if len(encodings) > 1 {
		writeESError(w, http.StatusUnsupportedMediaType, "illegal_argument_exception",
			"unsupported Content-Encoding: "+rawCE)
		return nil, false
	}

	enc := encodings[0]
	if enc != "gzip" && enc != "x-gzip" && enc != "deflate" {
		writeESError(w, http.StatusUnsupportedMediaType, "illegal_argument_exception",
			"unsupported Content-Encoding: "+rawCE)
		return nil, false
	}

	if r.Body == nil || r.Body == http.NoBody {
		r.Body = http.NoBody
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		return nil, true
	}

	origBody := r.Body
	hdr, hdrErr := readInitialHeaderBytesR63(origBody, 2)
	if len(hdr) == 0 && errors.Is(hdrErr, io.EOF) {
		_ = origBody.Close()
		r.Body = http.NoBody
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		return nil, true
	}
	if hdrErr != nil && !errors.Is(hdrErr, io.EOF) {
		_ = origBody.Close()
		var maxErr *http.MaxBytesError
		if errors.As(hdrErr, &maxErr) {
			writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception",
				fmt.Sprintf("[request] Data too large, data for [<http_request>] would be larger than limit of [%d]", maxBytes))
			return nil, false
		}
		writeESError(w, http.StatusBadRequest, "not_x_content_exception", "failed to read compressed request stream: "+hdrErr.Error())
		return nil, false
	}

	combined := io.MultiReader(bytes.NewReader(hdr), origBody)

	switch enc {
	case "gzip", "x-gzip":
		var gz *gzip.Reader
		if pooled := gzipReaderPool.Get(); pooled != nil {
			gz = pooled.(*gzip.Reader)
			if err := gz.Reset(combined); err != nil {
				gzipReaderPool.Put(gz)
				_ = origBody.Close()
				writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid gzip stream: "+err.Error())
				return nil, false
			}
		} else {
			var err error
			gz, err = gzip.NewReader(combined)
			if err != nil {
				_ = origBody.Close()
				writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid gzip stream: "+err.Error())
				return nil, false
			}
		}
		cleanupFn := func() {
			_ = gz.Close()
			gzipReaderPool.Put(gz)
			_ = origBody.Close()
		}
		r.Body = http.MaxBytesReader(w, gz, maxBytes)
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		return cleanupFn, true

	case "deflate":
		isZlibHeader := len(hdr) == 2 && (hdr[0]&0x0f) == 8 && ((int(hdr[0])<<8|int(hdr[1]))%31 == 0)
		var decomp io.ReadCloser
		if isZlibHeader {
			zr, zErr := zlib.NewReader(combined)
			if zErr != nil {
				_ = origBody.Close()
				writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid deflate stream: "+zErr.Error())
				return nil, false
			}
			decomp = zr
		} else {
			decomp = flate.NewReader(combined)
		}

		peek, peekErr := readInitialHeaderBytesR63(decomp, 64)
		if peekErr != nil && !errors.Is(peekErr, io.EOF) {
			_ = decomp.Close()
			_ = origBody.Close()
			var maxErr *http.MaxBytesError
			if errors.As(peekErr, &maxErr) {
				writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception",
					fmt.Sprintf("[request] Data too large, data for [<http_request>] would be larger than limit of [%d]", maxBytes))
				return nil, false
			}
			writeESError(w, http.StatusBadRequest, "not_x_content_exception", "invalid deflate stream: "+peekErr.Error())
			return nil, false
		}

		wrapped := &deflateReadCloserR63{
			r:      io.MultiReader(bytes.NewReader(peek), decomp),
			closer: decomp,
			body:   origBody,
		}
		r.Body = http.MaxBytesReader(w, wrapped, maxBytes)
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		return func() { _ = wrapped.Close() }, true
	}
	return nil, true
}

// resolveSniffPublishAddressR63Wire derives `http.publish_address`, `host`, and `ip` for `/_nodes` sniffing.
// When `r.Host` omits an explicit `:port`, it derives `:443` (TLS / X-Forwarded-Proto: https) or `:80` (HTTP)
// instead of hardcoding `:9200`.
func resolveSniffPublishAddressR63Wire(r *http.Request) (pubAddr, hostStr, ipStr string) {
	pubAddr = "127.0.0.1:9200"
	hostStr = "localhost"
	ipStr = "127.0.0.1"
	if r == nil || strings.TrimSpace(r.Host) == "" {
		return pubAddr, hostStr, ipStr
	}
	cand := strings.TrimSpace(r.Host)
	if h, p, splitErr := net.SplitHostPort(cand); splitErr == nil && p != "" {
		cleanHost := strings.Trim(h, "[]")
		if cleanHost == "" {
			cleanHost = "127.0.0.1"
		}
		pubAddr = net.JoinHostPort(cleanHost, p)
		hostStr = cleanHost
		if parsedIP := net.ParseIP(cleanHost); parsedIP != nil {
			ipStr = parsedIP.String()
		}
		return pubAddr, hostStr, ipStr
	}

	cleanHost := strings.Trim(cand, "[]")
	port := ""
	if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); xfp != "" {
		if pn, errP := strconv.Atoi(xfp); errP == nil && pn > 0 && pn <= 65535 {
			port = strconv.Itoa(pn)
		}
	}
	if port == "" {
		xfProto := ""
		if rawProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); rawProto != "" {
			xfProto = strings.ToLower(strings.TrimSpace(strings.Split(rawProto, ",")[0]))
		}
		if xfProto == "https" || (xfProto == "" && r.TLS != nil) {
			port = "443"
		} else {
			port = "80"
		}
	}
	pubAddr = net.JoinHostPort(cleanHost, port)
	hostStr = cleanHost
	if parsedIP := net.ParseIP(cleanHost); parsedIP != nil {
		ipStr = parsedIP.String()
	}
	return pubAddr, hostStr, ipStr
}

// ============================================================================
// F7: `GET /_nodes/usage` (`nodes.usage` schema.json endpoint)
// ============================================================================

var validNodeUsageMetricsR63 = map[string]bool{
	"_all":         true,
	"rest_actions": true,
	"aggregations": true,
}

func (s *Server) serveNodesUsageRound63(w http.ResponseWriter, r *http.Request, nodeFilter, metricStr string) {
	reqPath := "/_nodes/usage"
	if r != nil && r.URL != nil && r.URL.Path != "" {
		reqPath = r.URL.Path
	}
	selected := map[string]bool{}
	if metricStr == "" || metricStr == "_all" || metricStr == "*" {
		selected["rest_actions"] = true
		selected["aggregations"] = true
	} else if metricStr != "_none" {
		for _, tok := range strings.Split(metricStr, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || tok == "_none" {
				continue
			}
			if !validNodeUsageMetricsR63[tok] {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					formatUnrecognizedMetricErrorRound61(reqPath, tok, validNodeUsageMetricsR63).Error())
				return
			}
			if tok == "_all" {
				selected["rest_actions"] = true
				selected["aggregations"] = true
			} else {
				selected[tok] = true
			}
		}
	}

	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	st := getOrCreateRound61AdminState(s)
	st.mu.RLock()
	sinceMS := st.startedAtMillis
	st.mu.RUnlock()

	nowMS := time.Now().UnixMilli()
	if nowMS < sinceMS {
		nowMS = sinceMS
	}

	nodesMap := map[string]any{}
	totalNodes := 1
	if localNodeMatchesFilterRound60(nodeFilter) {
		restActions := map[string]any{}
		if selected["rest_actions"] {
			reqTotal := int(atomic.LoadInt64(&s.totalHTTPRequests))
			if reqTotal < 1 {
				reqTotal = 1
			}
			restActions["main_action"] = reqTotal
			restActions["nodes_usage_action"] = 1
		}
		aggsUsage := map[string]any{}
		nodesMap[taskLocalNodeID] = map[string]any{
			"timestamp":    nowMS,
			"since":        sinceMS,
			"rest_actions": restActions,
			"aggregations": aggsUsage,
		}
	} else {
		totalNodes = 0
	}

	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"_nodes": map[string]any{
			"total":      totalNodes,
			"successful": totalNodes,
			"failed":     0,
		},
		"cluster_name": "apache-doris-search-cluster",
		"nodes":        nodesMap,
	})
}

// ============================================================================
// F2: Search Shards Boost, Reindex Remote Key Order, Resolve System Index,
//     Synced Flush, Composable Index Templates, Wildcard Mappings & Settings
// ============================================================================

func normalizeCanonicalESQueryNodeR63(raw any) any {
	m, ok := raw.(map[string]any)
	if !ok {
		return raw
	}
	if termRaw, hasTerm := m["term"]; hasTerm {
		if termMap, okT := termRaw.(map[string]any); okT {
			normTerm := make(map[string]any, len(termMap))
			for field, fv := range termMap {
				if fm, okFM := fv.(map[string]any); okFM {
					cp := deepCloneDocMap(fm)
					if _, hasBoost := cp["boost"]; !hasBoost {
						cp["boost"] = 1.0
					}
					normTerm[field] = cp
				} else {
					normTerm[field] = map[string]any{
						"value": fv,
						"boost": 1.0,
					}
				}
			}
			out := deepCloneDocMap(m)
			out["term"] = normTerm
			return out
		}
	}
	if boolRaw, hasBool := m["bool"]; hasBool {
		if boolMap, okB := boolRaw.(map[string]any); okB {
			normBool := deepCloneDocMap(boolMap)
			for _, clause := range []string{"must", "filter", "should", "must_not"} {
				switch cv := normBool[clause].(type) {
				case []any:
					arr := make([]any, len(cv))
					for i, elem := range cv {
						arr[i] = normalizeCanonicalESQueryNodeR63(elem)
					}
					normBool[clause] = arr
				case map[string]any:
					normBool[clause] = normalizeCanonicalESQueryNodeR63(cv)
				}
			}
			if _, hasAPN := normBool["adjust_pure_negative"]; !hasAPN {
				normBool["adjust_pure_negative"] = true
			}
			if _, hasBoost := normBool["boost"]; !hasBoost {
				normBool["boost"] = 1.0
			}
			out := deepCloneDocMap(m)
			out["bool"] = normBool
			return out
		}
	}
	return m
}

func formatSearchShardsAliasFilterR63(aliasFilters []*esast.Query) any {
	toQueryMap := func(q *esast.Query) any {
		if q == nil {
			return map[string]any{}
		}
		b, err := json.Marshal(q)
		if err != nil {
			return q
		}
		var m any
		if err := json.Unmarshal(b, &m); err != nil {
			return q
		}
		return normalizeCanonicalESQueryNodeR63(m)
	}
	if len(aliasFilters) == 1 {
		return toQueryMap(aliasFilters[0])
	}
	shouldSlice := make([]any, len(aliasFilters))
	for i, fq := range aliasFilters {
		shouldSlice[i] = toQueryMap(fq)
	}
	return map[string]any{
		"bool": map[string]any{
			"should":               shouldSlice,
			"adjust_pure_negative": true,
			"boost":                1.0,
		},
	}
}

var allowedReindexRemoteKeysR63 = map[string]bool{
	"host":            true,
	"username":        true,
	"password":        true,
	"socket_timeout":  true,
	"connect_timeout": true,
	"max_retries":     true,
	"headers":         true,
}

func skipJSONValueR63(dec *json.Decoder, firstTok json.Token) error {
	if _, ok := firstTok.(json.Delim); !ok {
		return nil
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, isD := tok.(json.Delim); isD {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// rewriteReindexRemoteUnknownFieldsOrderR63 extracts unknown keys under `source.remote` in exact JSON
// wire appearance order so `Unsupported fields in [remote]: [weird,badkey]` is deterministic.
func rewriteReindexRemoteUnknownFieldsOrderR63(bodyBytes []byte, fallback string) string {
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	rootTok, err := dec.Token()
	if err != nil || rootTok != json.Delim('{') {
		return fallback
	}
	var unknown []string
	for dec.More() {
		kTok, err := dec.Token()
		if err != nil {
			return fallback
		}
		key, _ := kTok.(string)
		valTok, err := dec.Token()
		if err != nil {
			return fallback
		}
		if key != "source" || valTok != json.Delim('{') {
			if err := skipJSONValueR63(dec, valTok); err != nil {
				return fallback
			}
			continue
		}
		for dec.More() {
			skTok, err := dec.Token()
			if err != nil {
				return fallback
			}
			sKey, _ := skTok.(string)
			sValTok, err := dec.Token()
			if err != nil {
				return fallback
			}
			if sKey != "remote" || sValTok != json.Delim('{') {
				if err := skipJSONValueR63(dec, sValTok); err != nil {
					return fallback
				}
				continue
			}
			var allRemoteKeys []string
			for dec.More() {
				rkTok, err := dec.Token()
				if err != nil {
					return fallback
				}
				rKey, _ := rkTok.(string)
				rValTok, err := dec.Token()
				if err != nil {
					return fallback
				}
				allRemoteKeys = append(allRemoteKeys, rKey)
				if !allowedReindexRemoteKeysR63[rKey] {
					unknown = append(unknown, rKey)
				}
				if err := skipJSONValueR63(dec, rValTok); err != nil {
					return fallback
				}
			}
			unknown = orderReindexRemoteUnknownKeysRound63(allRemoteKeys, unknown, len(allRemoteKeys))
			_, _ = dec.Token() // consume '}' of remote
		}
		_, _ = dec.Token() // consume '}' of source
	}
	if len(unknown) == 0 {
		return fallback
	}
	return "Unsupported fields in [remote]: [" + strings.Join(unknown, ",") + "]"
}

func isSystemIndexNameR63(name string) bool {
	if !strings.HasPrefix(name, ".") {
		return false
	}
	switch name {
	case ".tasks", ".async-search", ".watches", ".triggered_watches", ".geoip_databases":
		return true
	}
	for _, pref := range []string{
		".security", ".kibana", ".apm-", ".fleet-", ".transform-internal",
		".ml-", ".watcher-history-", ".slm-history-", ".ilm-history-",
	} {
		if strings.HasPrefix(name, pref) {
			return true
		}
	}
	return false
}

type bufferedResponseCaptureR63 struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func newBufferedResponseCaptureR63() *bufferedResponseCaptureR63 {
	return &bufferedResponseCaptureR63{
		header: make(http.Header),
		status: http.StatusOK,
	}
}

func (b *bufferedResponseCaptureR63) Header() http.Header {
	return b.header
}

func (b *bufferedResponseCaptureR63) WriteHeader(code int) {
	b.status = code
}

func (b *bufferedResponseCaptureR63) Write(p []byte) (int, error) {
	return b.buf.Write(p)
}

func (b *bufferedResponseCaptureR63) flushTo(w http.ResponseWriter) {
	for k, vals := range b.header {
		w.Header().Del(k)
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(b.status)
	if b.buf.Len() > 0 {
		_, _ = w.Write(b.buf.Bytes())
	}
}

func (s *Server) serveResolveIndexR63Admin(w http.ResponseWriter, r *http.Request) {
	capW := newBufferedResponseCaptureR63()
	s.handleResolveIndexRound58(capW, r)
	if capW.status == http.StatusOK && (!s.hasExplicitTargetESVersion() || s.isES8Mode(r)) && capW.buf.Len() > 0 {
		var payload map[string]any
		if json.Unmarshal(capW.buf.Bytes(), &payload) == nil {
			if rawIndices, ok := payload["indices"].([]any); ok {
				mutated := false
				for _, elem := range rawIndices {
					idxObj, okM := elem.(map[string]any)
					if !okM {
						continue
					}
					idxName, _ := idxObj["name"].(string)
					if !isSystemIndexNameR63(idxName) {
						continue
					}
					stateAttr := "open"
					if rawAttrs, okA := idxObj["attributes"].([]any); okA {
						for _, av := range rawAttrs {
							if as, _ := av.(string); as == "closed" {
								stateAttr = "closed"
							}
						}
					}
					idxObj["attributes"] = []string{"hidden", stateAttr, "system"}
					mutated = true
				}
				if mutated {
					for k, vals := range capW.header {
						if strings.EqualFold(k, "Content-Length") {
							continue
						}
						w.Header().Del(k)
						for _, v := range vals {
							w.Header().Add(k, v)
						}
					}
					writeJSONWithRequest(w, r, http.StatusOK, payload)
					return
				}
			}
		}
	}
	capW.flushTo(w)
}

func (s *Server) serveSyncedFlushR63Admin(w http.ResponseWriter, r *http.Request, rawIndex string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if s.hasExplicitTargetESVersion() && !s.isES8Mode(r) {
		emitESDeprecationWarningRound61(w, s, r,
			"Synced flush is deprecated and will be removed in 8.0. Use flush at _/flush or /{index}/_flush instead.")
	}
	_ = s.syncCatalogFromBackend(r.Context())

	var targets []string
	if rawIndex == "" || rawIndex == "_all" || rawIndex == "*" {
		targets = s.resolveTargetIndices("")
	} else {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
		if !isTruthyBoolQueryParam(r, "ignore_unavailable") {
			if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" {
				writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
				return
			}
		}
	}

	totalShards := 0
	resp := map[string]any{}
	nowNano := time.Now().UnixNano()

	for i, idxName := range targets {
		s.mu.RLock()
		isClosed := s.closedIndices[idxName]
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
		s.mu.RUnlock()
		if isClosed {
			continue
		}
		s.refreshAllIndexShardsRound60(idxName)
		if st := s.getOrCreateIndexLiveStats(idxName); st != nil {
			st.flushTotal.Add(1)
		}
		markIndexFlushedRound61(s, idxName)
		syncID := fmt.Sprintf("sync-%s-%d-%d", idxName, nowNano, i)
		setSyncedFlushIDR63Admin(s, idxName, syncID)

		totalShards += numShards
		resp[idxName] = map[string]any{
			"total":      numShards,
			"successful": numShards,
			"failed":     0,
			"failures":   []any{},
		}
	}
	resp["_shards"] = map[string]any{
		"total":      totalShards,
		"successful": totalShards,
		"failed":     0,
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func decodeURLSegmentR63(raw string) string {
	if unesc, err := url.PathUnescape(raw); err == nil {
		return unesc
	}
	return raw
}

func extractStringSliceFieldR63(m map[string]any, keys ...string) ([]string, bool) {
	for _, k := range keys {
		raw, exists := m[k]
		if !exists || raw == nil {
			continue
		}
		switch tv := raw.(type) {
		case []any:
			out := make([]string, 0, len(tv))
			for _, elem := range tv {
				if sv, okS := elem.(string); okS {
					out = append(out, sv)
				}
			}
			return out, true
		case []string:
			cp := make([]string, len(tv))
			copy(cp, tv)
			return cp, true
		}
	}
	return nil, false
}

func matchesAnyTemplatePatternR63(candidate string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == "*" || pat == candidate || matchWildcardPattern(pat, candidate) {
			return true
		}
	}
	return false
}

func enrichSimulateTemplateLifecycleDefaultsR63(payload map[string]any, fallbackLifecycle map[string]any, includeDefaults, isES8 bool) bool {
	if !isES8 || payload == nil {
		return false
	}
	tplObj, okT := payload["template"].(map[string]any)
	if !okT || tplObj == nil {
		return false
	}
	lcRaw, okLC := tplObj["lifecycle"].(map[string]any)
	mutated := false
	if (!okLC || lcRaw == nil) && fallbackLifecycle != nil {
		lcRaw = deepCloneDocMap(fallbackLifecycle)
		tplObj["lifecycle"] = lcRaw
		mutated = true
	}
	if lcRaw == nil {
		return mutated
	}
	if _, hasEn := lcRaw["enabled"]; !hasEn {
		lcRaw["enabled"] = true
		mutated = true
	}
	if includeDefaults {
		if _, hasRO := lcRaw["rollover"]; !hasRO {
			lcRaw["rollover"] = map[string]any{
				"max_age":                "30d",
				"max_primary_shard_size": "50gb",
				"min_docs":               1,
			}
			mutated = true
		}
	}
	return mutated
}

var validIndexSettingExactKeysR63 = map[string]bool{
	"index.number_of_shards":                  true,
	"index.number_of_replicas":                true,
	"index.auto_expand_replicas":              true,
	"index.refresh_interval":                  true,
	"index.max_result_window":                 true,
	"index.max_inner_result_window":           true,
	"index.max_rescore_window":                true,
	"index.max_docvalue_fields_search":        true,
	"index.max_script_fields":                 true,
	"index.max_ngram_diff":                    true,
	"index.max_shingle_diff":                  true,
	"index.max_refresh_listeners":             true,
	"index.max_regex_length":                  true,
	"index.max_terms_count":                   true,
	"index.max_slices_per_scroll":             true,
	"index.max_adjacency_matrix_filters":      true,
	"index.codec":                             true,
	"index.routing_partition_size":            true,
	"index.load_fixed_bitset_filters_eagerly": true,
	"index.hidden":                            true,
	"index.verified_before_close":             true,
	"index.source_only":                       true,
	"index.mode":                              true,
	"index.lookahead_time":                    true,
	"index.gc_deletes":                        true,
	"index.default_pipeline":                  true,
	"index.final_pipeline":                    true,
	"index.top_metrics_max_size":              true,
	"index.frozen":                            true,
	"index.priority":                          true,
	"index.optimize_auto_generated_id":        true,
	"index.data_path":                         true,
	"index.shadow_replicas":                   true,
	"index.compound_format":                   true,
	"index.provided_name":                     true,
	"index.creation_date":                     true,
	"index.uuid":                              true,
	"index.format":                            true,
	"index.knn":                               true,
}

var validIndexSettingPrefixesR63 = []string{
	"index.soft_deletes.",
	"index.time_series.",
	"index.routing.",
	"index.shard.",
	"index.lifecycle.",
	"index.analysis.",
	"index.similarity.",
	"index.mapping.",
	"index.mapper.",
	"index.translog.",
	"index.merge.",
	"index.blocks.",
	"index.write.",
	"index.search.",
	"index.queries.",
	"index.query.",
	"index.query_string.",
	"index.highlight.",
	"index.fielddata.",
	"index.unassigned.",
	"index.recovery.",
	"index.indexing.",
	"index.store.",
	"index.warmer.",
	"index.percolator.",
	"index.sort.",
	"index.append_only.",
	"index.version.",
	"index.downsample.",
	"index.enrich.",
	"index.xpack.",
	"index.knn.",
	"index.vectors.",
	"index.sparse_vector.",
}

var staticIndexSettingKeysR63 = map[string]bool{
	"index.codec":                             true,
	"index.number_of_shards":                  true,
	"index.routing_partition_size":            true,
	"index.soft_deletes.enabled":              true,
	"index.shard.check_on_startup":            true,
	"index.load_fixed_bitset_filters_eagerly": true,
}

func isValidESIndexSettingKeyR63(fullKey string) bool {
	if validIndexSettingExactKeysR63[fullKey] {
		return true
	}
	for _, pref := range validIndexSettingPrefixesR63 {
		if strings.HasPrefix(fullKey, pref) {
			return true
		}
	}
	return false
}

func flattenIndexSettingsKeysR63(raw map[string]any) []string {
	var out []string
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			if prefix == "" && k == "settings" {
				if sub, okM := v.(map[string]any); okM {
					walk("", sub)
					continue
				}
			}
			next := k
			if prefix != "" {
				next = prefix + "." + k
			}
			if sub, okM := v.(map[string]any); okM && len(sub) > 0 {
				// Analysis & similarity blocks allow user-defined subkeys under `index.analysis.*` / `index.similarity.*`.
				canonCheck := next
				if !strings.HasPrefix(canonCheck, "index.") {
					canonCheck = "index." + canonCheck
				}
				if strings.HasPrefix(canonCheck, "index.analysis.") || strings.HasPrefix(canonCheck, "index.similarity.") {
					out = append(out, canonCheck)
					continue
				}
				walk(next, sub)
				continue
			}
			canon := next
			if !strings.HasPrefix(canon, "index.") {
				canon = "index." + canon
			}
			out = append(out, canon)
		}
	}
	walk("", raw)
	sort.Strings(out)
	return out
}

type translogWarningFilterWriterR63 struct {
	http.ResponseWriter
	suppressTranslogWarning bool
	filtered                bool
}

func (tw *translogWarningFilterWriterR63) filterWarnings() {
	if tw.filtered || !tw.suppressTranslogWarning {
		return
	}
	tw.filtered = true
	warns := tw.ResponseWriter.Header().Values("Warning")
	if len(warns) == 0 {
		return
	}
	tw.ResponseWriter.Header().Del("Warning")
	for _, wv := range warns {
		if strings.Contains(wv, "Translog retention settings") {
			continue
		}
		tw.ResponseWriter.Header().Add("Warning", wv)
	}
}

func (tw *translogWarningFilterWriterR63) WriteHeader(status int) {
	tw.filterWarnings()
	tw.ResponseWriter.WriteHeader(status)
}

func (tw *translogWarningFilterWriterR63) Write(b []byte) (int, error) {
	tw.filterWarnings()
	return tw.ResponseWriter.Write(b)
}

// tryHandleAdminWireR63 intercepts Round-63 admin/cluster/template/mapping/settings conformance
// routes inside `withWireMiddleware` without mutating sibling-owned router files.
func (s *Server) tryHandleAdminWireR63(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	trimmedPath := strings.Trim(r.URL.Path, "/")
	if trimmedPath == "" {
		return false
	}
	segs := strings.Split(trimmedPath, "/")

	// 0. `GET /_resolve/index` & `GET /_resolve/index/{name}`
	if segs[0] == "_resolve" && len(segs) >= 2 && segs[1] == "index" && r.Method == http.MethodGet {
		if len(segs) >= 3 {
			r.SetPathValue("name", decodeURLSegmentR63(strings.Join(segs[2:], "/")))
		}
		s.serveResolveIndexR63Admin(w, r)
		return true
	}

	// 1. `POST /_cluster/reroute`
	if trimmedPath == "_cluster/reroute" && r.Method == http.MethodPost {
		s.serveClusterRerouteR62Admin(w, r)
		return true
	}

	// 2. `GET|POST /_flush/synced` & `GET|POST /{index}/_flush/synced`
	if trimmedPath == "_flush/synced" {
		s.serveSyncedFlushR63Admin(w, r, "")
		return true
	}
	if len(segs) == 3 && segs[1] == "_flush" && segs[2] == "synced" {
		s.serveSyncedFlushR63Admin(w, r, decodeURLSegmentR63(segs[0]))
		return true
	}

	// 3. `/_index_template/...` (`get_index_template`, `put_index_template`, `simulate_index_template`)
	if segs[0] == "_index_template" {
		if len(segs) == 2 && r.Method == http.MethodGet {
			tplName := decodeURLSegmentR63(segs[1])
			if strings.Contains(tplName, ",") && s.hasExplicitTargetESVersion() && s.isES8Mode(r) {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Wildcard expressions or all templates are allowed, comma-separated lists are not: [%s]", tplName))
				return true
			}
			if tplName != "*" && tplName != "_all" && !strings.Contains(tplName, ",") && strings.ContainsAny(tplName, "*?") && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
				_ = s.syncCatalogFromBackend(r.Context())
				s.mu.RLock()
				matchedAny := false
				for k := range s.templates {
					if matchWildcardPattern(tplName, k) {
						matchedAny = true
						break
					}
				}
				s.mu.RUnlock()
				if !matchedAny {
					writeJSONWithRequest(w, r, http.StatusNotFound, map[string]any{
						"index_templates": []any{},
					})
					return true
				}
			}
			return false
		}

		isSimulate := len(segs) >= 2 && (segs[1] == "_simulate" || segs[1] == "_simulate_index")
		if (r.Method == http.MethodPut || r.Method == http.MethodPost) && (len(segs) == 2 || isSimulate) {
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return true
			}
			var rawBody map[string]any
			var bodyLifecycle map[string]any
			var origComposedOf []string
			hasOrigComposed := false
			tplName := ""
			if !isSimulate && len(segs) == 2 {
				tplName = decodeURLSegmentR63(segs[1])
			}
			if len(bytes.TrimSpace(bodyBytes)) > 0 && json.Unmarshal(bodyBytes, &rawBody) == nil && rawBody != nil {
				if tplSub, okT := rawBody["template"].(map[string]any); okT && tplSub != nil {
					if lcSub, okL := tplSub["lifecycle"].(map[string]any); okL && lcSub != nil {
						bodyLifecycle = deepCloneDocMap(lcSub)
					}
				}
				composedOf, hasComp := extractStringSliceFieldR63(rawBody, "composed_of")
				ignoreMissing, hasIgnore := extractStringSliceFieldR63(rawBody, "ignore_missing_component_templates", "ignore_missing_component_template")
				if hasComp && len(composedOf) > 0 {
					_ = s.syncCatalogFromBackend(r.Context())
					s.mu.RLock()
					var unignoredMissing []string
					var existingComposed []string
					for _, ct := range composedOf {
						if _, okCT := s.componentTemplates[ct]; okCT {
							existingComposed = append(existingComposed, ct)
							continue
						}
						if hasIgnore && matchesAnyTemplatePatternR63(ct, ignoreMissing) {
							continue
						}
						unignoredMissing = append(unignoredMissing, ct)
					}
					s.mu.RUnlock()
					if len(unignoredMissing) > 0 && tplName != "" {
						reason := fmt.Sprintf(
							"index_template [%s] invalid, cause [index template [%s] specifies a missing component templates [%s] that does not exist]",
							tplName, tplName, strings.Join(unignoredMissing, ", "),
						)
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", reason)
						return true
					}
					if hasIgnore && len(existingComposed) != len(composedOf) {
						origComposedOf = composedOf
						hasOrigComposed = true
						rawBody["composed_of"] = existingComposed
					}
				}
				if hasIgnore {
					delete(rawBody, "ignore_missing_component_templates")
					delete(rawBody, "ignore_missing_component_template")
					if rewritten, errM := json.Marshal(rawBody); errM == nil {
						bodyBytes = rewritten
					}
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if isSimulate {
				includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")
				isES8 := !s.hasExplicitTargetESVersion() || s.isES8Mode(r)
				fallbackLC := bodyLifecycle
				if fallbackLC == nil && len(segs) == 3 {
					simTarget := decodeURLSegmentR63(segs[2])
					s.mu.RLock()
					switch segs[1] {
					case "_simulate":
						if lc := s.templateLifecycles[simTarget]; lc != nil {
							fallbackLC = deepCloneDocMap(lc)
						}
					case "_simulate_index":
						bestPrio := -1
						for k, tpl := range s.templates {
							prio := 0
							if tpl.Priority != nil {
								prio = *tpl.Priority
							}
							if matchesAnyTemplatePatternR63(simTarget, tpl.IndexPatterns) && prio >= bestPrio {
								if lc := s.templateLifecycles[k]; lc != nil {
									bestPrio = prio
									fallbackLC = deepCloneDocMap(lc)
								}
							}
						}
					}
					s.mu.RUnlock()
				}
				capW := newBufferedResponseCaptureR63()
				next.ServeHTTP(capW, r)
				if capW.status == http.StatusOK && capW.buf.Len() > 0 {
					var simPayload map[string]any
					if json.Unmarshal(capW.buf.Bytes(), &simPayload) == nil {
						if enrichSimulateTemplateLifecycleDefaultsR63(simPayload, fallbackLC, includeDefaults, isES8) {
							for k, vals := range capW.header {
								if strings.EqualFold(k, "Content-Length") {
									continue
								}
								w.Header().Del(k)
								for _, v := range vals {
									w.Header().Add(k, v)
								}
							}
							writeJSONWithRequest(w, r, http.StatusOK, simPayload)
							return true
						}
					}
				}
				capW.flushTo(w)
				return true
			}

			capW := newBufferedResponseCaptureR63()
			next.ServeHTTP(capW, r)
			if tplName != "" && capW.status >= 200 && capW.status < 300 {
				s.mu.Lock()
				if hasOrigComposed {
					if savedTpl, okT := s.templates[tplName]; okT {
						savedTpl.ComposedOf = origComposedOf
						s.templates[tplName] = savedTpl
					}
				}
				if bodyLifecycle != nil {
					if s.templateLifecycles == nil {
						s.templateLifecycles = make(map[string]map[string]any)
					}
					s.templateLifecycles[tplName] = bodyLifecycle
				}
				s.mu.Unlock()
			}
			capW.flushTo(w)
			return true
		}
	}

	// 4. `GET /{index}/_mapping` with `expand_wildcards=none`
	if len(segs) == 2 && segs[1] == "_mapping" && r.Method == http.MethodGet && r.URL != nil {
		ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
		if ew == "none" {
			rawIdx := decodeURLSegmentR63(segs[0])
			ignoreUnavail := isTruthyBoolQueryParam(r, "ignore_unavailable")
			allowNoIndices := true
			if r.URL.Query().Has("allow_no_indices") {
				if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("allow_no_indices")), "false") {
					allowNoIndices = false
				}
			}
			isES8 := !s.hasExplicitTargetESVersion() || s.isES8Mode(r)
			_ = s.syncCatalogFromBackend(r.Context())

			parts := strings.Split(rawIdx, ",")
			var matchedConcrete []string
			for _, rawPart := range parts {
				part := strings.TrimSpace(rawPart)
				if part == "" {
					continue
				}
				if part == "_all" || part == "*" || strings.ContainsAny(part, "*?") {
					if isES8 && !ignoreUnavail {
						writeIndexNotFoundErrorR63(w, part)
						return true
					}
					continue
				}
				s.mu.RLock()
				_, existsIdx := s.indices[part]
				isClosed := s.closedIndices[part]
				aliasTargets := s.aliases[part]
				hasOpenAlias := false
				for _, at := range aliasTargets {
					if !s.closedIndices[at] {
						hasOpenAlias = true
						break
					}
				}
				s.mu.RUnlock()
				if (existsIdx && !isClosed) || hasOpenAlias {
					matchedConcrete = append(matchedConcrete, part)
				} else if !ignoreUnavail {
					writeIndexNotFoundErrorR63(w, part)
					return true
				}
			}
			if len(matchedConcrete) == 0 {
				if !allowNoIndices {
					firstTarget := strings.TrimSpace(parts[0])
					writeIndexNotFoundErrorR63(w, firstTarget)
					return true
				}
				writeJSONWithRequest(w, r, http.StatusOK, map[string]any{})
				return true
			}
		}
	}

	// 5. `PUT /_settings` & `PUT /{index}/_settings`
	if r.Method == http.MethodPut && (trimmedPath == "_settings" || (len(segs) == 2 && segs[1] == "_settings" && !strings.HasPrefix(segs[0], "_"))) {
		reopen := false
		if r.URL != nil && r.URL.Query().Has("reopen") {
			parsedReopen, _, errR := parseStrictQueryBoolParamRound59(r, "reopen")
			if errR != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", errR.Error())
				return true
			}
			reopen = parsedReopen
			q := r.URL.Query()
			q.Del("reopen")
			r.URL.RawQuery = q.Encode()
		}

		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		rawIdx := ""
		if len(segs) == 2 {
			rawIdx = decodeURLSegmentR63(segs[0])
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var rawSettings map[string]any
			if json.Unmarshal(bodyBytes, &rawSettings) == nil && len(rawSettings) > 0 {
				flatKeys := flattenIndexSettingsKeysR63(rawSettings)
				var staticTouched []string
				for _, fk := range flatKeys {
					if !isValidESIndexSettingKeyR63(fk) {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("unknown setting [%s] please check that any required plugins are installed, or check the breaking changes documentation for removed settings", fk))
						return true
					}
					if staticIndexSettingKeysR63[fk] {
						staticTouched = append(staticTouched, fk)
					}
				}
				if len(staticTouched) > 0 && !reopen {
					_ = s.syncCatalogFromBackend(r.Context())
					openTargets := s.resolveOpenIndicesForSettingsCheckR63(rawIdx)
					if len(openTargets) > 0 {
						firstOpen := openTargets[0]
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("Can't update non dynamic settings [[%s]] for open indices [[%s/%s]]",
								strings.Join(staticTouched, ", "), firstOpen, firstOpen))
						return true
					}
				}
			}
		}

		suppressTranslogWarn := s.shouldSuppressTranslogRetentionWarningR63(rawIdx)
		if suppressTranslogWarn {
			tw := &translogWarningFilterWriterR63{
				ResponseWriter:          w,
				suppressTranslogWarning: true,
			}
			next.ServeHTTP(tw, r)
			return true
		}
	}

	return false
}

func writeIndexNotFoundErrorR63(w http.ResponseWriter, idx string) {
	reason := fmt.Sprintf("no such index [%s]", idx)
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{
				{
					"type":          "index_not_found_exception",
					"reason":        reason,
					"resource.type": "index_or_alias",
					"resource.id":   idx,
					"index_uuid":    "_na_",
					"index":         idx,
				},
			},
			"type":          "index_not_found_exception",
			"reason":        reason,
			"resource.type": "index_or_alias",
			"resource.id":   idx,
			"index_uuid":    "_na_",
			"index":         idx,
		},
		"status": http.StatusNotFound,
	})
}

func (s *Server) resolveOpenIndicesForSettingsCheckR63(rawIdx string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var open []string
	if rawIdx == "" || rawIdx == "_all" || rawIdx == "*" {
		for idx := range s.indices {
			if !s.closedIndices[idx] {
				open = append(open, idx)
			}
		}
		sort.Strings(open)
		return open
	}
	for _, part := range strings.Split(rawIdx, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for idx := range s.indices {
			if s.closedIndices[idx] {
				continue
			}
			if idx == part || matchWildcardPattern(part, idx) {
				open = append(open, idx)
			}
		}
		for _, t := range s.aliases[part] {
			if !s.closedIndices[t] {
				open = append(open, t)
			}
		}
	}
	sort.Strings(open)
	return open
}

func (s *Server) shouldSuppressTranslogRetentionWarningR63(rawIdx string) bool {
	targets := s.resolveOpenIndicesForSettingsCheckR63(rawIdx)
	if len(targets) == 0 {
		return false
	}
	for _, idx := range targets {
		disabled, _ := isIndexSoftDeletesDisabledR62Admin(s, idx)
		if !disabled {
			return false
		}
	}
	return true
}
