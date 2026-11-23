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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

var (
	streamLoadPrefixLinkLocalV4 = netip.MustParsePrefix("169.254.0.0/16")
	streamLoadPrefixLinkLocalV6 = netip.MustParsePrefix("fe80::/10")
	streamLoadAddrAWSIMDSv6     = netip.MustParseAddr("fd00:ec2::254")
	streamLoadPrefixAWSIMDSv6   = netip.MustParsePrefix("fd00:ec2::/32")
)

const maxStreamLoadErrorDetailBytes = 512

// StreamLoadConfig configures the Apache Doris HTTP Stream Load client.
type StreamLoadConfig struct {
	FEHTTPEndpoint string // e.g. "http://127.0.0.1:8030"
	User           string // e.g. "root"
	Password       string
	Database       string // e.g. "es_compat"
	Timeout        time.Duration
	MaxBatchBytes  int // Optional maximum bytes per single HTTP Stream Load batch (default 64 MiB)
}

// StreamLoadClient streams NDJSON document batches into Apache Doris Unique Key Merge-on-Write
// tables while preserving Basic Auth headers across validated FE :8030 -> BE :8040 HTTP 307 redirects.
type StreamLoadClient struct {
	cfg            StreamLoadConfig
	httpClient     *http.Client
	errHTTPClient  *http.Client
	cachedBEBase   atomic.Value // string base URL (e.g. "http://127.0.0.1:8040") discovered from FE 307 redirect
	allowedHostsMu sync.RWMutex
	allowedBEHosts map[string]struct{}
	lookupNetIP    func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func NewStreamLoadClient(cfg StreamLoadConfig) *StreamLoadClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	c := &StreamLoadClient{
		cfg:            cfg,
		allowedBEHosts: make(map[string]struct{}),
	}
	c.seedConfiguredHosts()

	baseDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy: nil, // Explicitly ignore ambient HTTP_PROXY/HTTPS_PROXY so metadata/internal targets cannot be reached via proxy bypass.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if isBlockedStreamLoadHost(host) {
				return nil, fmt.Errorf("stream load dial blocked: metadata or link-local address %q", host)
			}
			feLoopback := c.isConfiguredFELoopback()
			if parsedIP, ok := parseNormalizedStreamLoadIP(host); ok {
				if isBlockedStreamLoadAddr(parsedIP) {
					return nil, fmt.Errorf("stream load dial blocked: metadata or link-local IP %s", parsedIP)
				}
				if !feLoopback && parsedIP.IsLoopback() {
					return nil, fmt.Errorf("stream load dial blocked: loopback IP %s disallowed for non-loopback FE endpoint", parsedIP)
				}
				return baseDialer.DialContext(ctx, network, net.JoinHostPort(parsedIP.String(), port))
			}
			ips, resolveErr := c.resolveNetIPs(ctx, "ip", host)
			if resolveErr != nil {
				return nil, resolveErr
			}
			for _, ip := range ips {
				cleanIP := ip.Unmap().WithZone("")
				if isBlockedStreamLoadAddr(cleanIP) {
					return nil, fmt.Errorf("stream load dial blocked: host %q resolved to metadata or link-local IP %s", host, ip)
				}
				if !feLoopback && cleanIP.IsLoopback() {
					return nil, fmt.Errorf("stream load dial blocked: host %q resolved to loopback IP %s for non-loopback FE endpoint", host, ip)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("stream load dial failed: no IP addresses resolved for %q", host)
			}
			var lastDialErr error
			for _, ip := range ips {
				conn, dialErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().WithZone("").String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastDialErr = dialErr
			}
			return nil, lastDialErr
		},
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 50 * time.Millisecond,
	}

	c.httpClient = &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		// Preserve Authorization and Stream Load headers only when Doris FE (:8030) redirects to a verified Doris BE (:8040) /_stream_load endpoint without scheme downgrade.
		CheckRedirect: c.checkStreamLoadRedirect,
	}
	errTimeout := cfg.Timeout
	if errTimeout > 10*time.Second {
		errTimeout = 10 * time.Second
	}
	c.errHTTPClient = &http.Client{
		Timeout:   errTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c
}

func (c *StreamLoadClient) isConfiguredFELoopback() bool {
	if c == nil {
		return false
	}
	feURL, err := c.parseConfiguredFEURL()
	if err != nil {
		return false
	}
	return isLoopbackStreamLoadHost(feURL.Hostname())
}

func (c *StreamLoadClient) resolveNetIPs(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if c != nil && c.lookupNetIP != nil {
		return c.lookupNetIP(ctx, network, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

func (c *StreamLoadClient) seedConfiguredHosts() {
	feURL, err := c.parseConfiguredFEURL()
	if err != nil {
		return
	}
	feHost := feURL.Hostname()
	if normFE := normalizeStreamLoadHost(feHost); normFE != "" && !isBlockedStreamLoadHost(feHost) {
		c.allowedBEHosts[normFE] = struct{}{}
	}
	if isLoopbackStreamLoadHost(feHost) {
		c.allowedBEHosts["127.0.0.1"] = struct{}{}
		c.allowedBEHosts["::1"] = struct{}{}
		c.allowedBEHosts["localhost"] = struct{}{}
	}
}

// AllowBEHosts registers Doris Backend (BE) hostnames or IP addresses (e.g. discovered from `SHOW BACKENDS`)
// in the thread-safe Stream Load redirect and ErrorURL allowlist. Cloud metadata and link-local addresses
// are unconditionally ignored; loopback addresses are only accepted when `FEHTTPEndpoint` is itself loopback.
func (c *StreamLoadClient) AllowBEHosts(hosts []string) {
	if c == nil || len(hosts) == 0 {
		return
	}
	feLoopback := false
	if feURL, err := c.parseConfiguredFEURL(); err == nil {
		feLoopback = isLoopbackStreamLoadHost(feURL.Hostname())
	}
	c.allowedHostsMu.Lock()
	defer c.allowedHostsMu.Unlock()
	if c.allowedBEHosts == nil {
		c.allowedBEHosts = make(map[string]struct{}, len(hosts))
	}
	for _, raw := range hosts {
		extracted := extractStreamLoadHost(raw)
		if extracted == "" || isBlockedStreamLoadHost(extracted) {
			continue
		}
		if isLoopbackStreamLoadHost(extracted) && !feLoopback {
			continue
		}
		if norm := normalizeStreamLoadHost(extracted); norm != "" {
			c.allowedBEHosts[norm] = struct{}{}
		}
	}
}

// AllowedBEHosts returns a sorted snapshot of currently allowlisted Doris FE/BE hosts.
func (c *StreamLoadClient) AllowedBEHosts() []string {
	if c == nil {
		return nil
	}
	c.allowedHostsMu.RLock()
	defer c.allowedHostsMu.RUnlock()
	out := make([]string, 0, len(c.allowedBEHosts))
	for h := range c.allowedBEHosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (c *StreamLoadClient) hasAllowedBEHost(normHost string) bool {
	if c == nil || normHost == "" {
		return false
	}
	c.allowedHostsMu.RLock()
	_, ok := c.allowedBEHosts[normHost]
	c.allowedHostsMu.RUnlock()
	return ok
}

func extractStreamLoadHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return u.Hostname()
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	if strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1 {
		if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
			return strings.TrimSpace(h)
		}
	}
	return s
}

func parseNormalizedStreamLoadIP(host string) (netip.Addr, bool) {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if zoneIdx := strings.IndexByte(h, '%'); zoneIdx >= 0 {
		h = h[:zoneIdx]
	}
	if h == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

func normalizeStreamLoadHost(raw string) string {
	h := extractStreamLoadHost(raw)
	if h == "" {
		return ""
	}
	if addr, ok := parseNormalizedStreamLoadIP(h); ok {
		return addr.String()
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

func isBlockedStreamLoadAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	clean := addr.Unmap().WithZone("")
	return clean.IsUnspecified() ||
		clean.IsMulticast() ||
		clean.IsLinkLocalUnicast() ||
		clean.IsLinkLocalMulticast() ||
		streamLoadPrefixLinkLocalV4.Contains(clean) ||
		streamLoadPrefixLinkLocalV6.Contains(clean) ||
		clean == streamLoadAddrAWSIMDSv6 ||
		streamLoadPrefixAWSIMDSv6.Contains(clean)
}

func isBlockedStreamLoadHost(host string) bool {
	h := extractStreamLoadHost(host)
	if h == "" {
		return true
	}
	if addr, ok := parseNormalizedStreamLoadIP(h); ok {
		return isBlockedStreamLoadAddr(addr)
	}
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	switch lower {
	case "metadata.google.internal", "metadata.goog", "metadata", "instance-data":
		return true
	default:
		return false
	}
}

func isLoopbackStreamLoadHost(host string) bool {
	h := extractStreamLoadHost(host)
	if h == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSuffix(h, "."), "localhost") {
		return true
	}
	if addr, ok := parseNormalizedStreamLoadIP(h); ok {
		return addr.IsLoopback()
	}
	return false
}

func isPrivateVPCStreamLoadIP(host string) bool {
	addr, ok := parseNormalizedStreamLoadIP(host)
	if !ok || isBlockedStreamLoadAddr(addr) {
		return false
	}
	return addr.IsPrivate()
}

func (c *StreamLoadClient) parseConfiguredFEURL() (*url.URL, error) {
	raw := strings.TrimSpace(c.cfg.FEHTTPEndpoint)
	if raw == "" {
		return nil, fmt.Errorf("empty Doris FEHTTPEndpoint")
	}
	feURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid Doris FEHTTPEndpoint: %w", err)
	}
	scheme := strings.ToLower(feURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported Doris FEHTTPEndpoint scheme %q", feURL.Scheme)
	}
	if feURL.Hostname() == "" {
		return nil, fmt.Errorf("missing host in Doris FEHTTPEndpoint")
	}
	return feURL, nil
}

func (c *StreamLoadClient) isTrustedTargetHost(feURL *url.URL, targetHost string) bool {
	if feURL == nil {
		return false
	}
	if isBlockedStreamLoadHost(targetHost) {
		return false
	}
	feHost := feURL.Hostname()
	normFE := normalizeStreamLoadHost(feHost)
	normTarget := normalizeStreamLoadHost(targetHost)
	if normFE == "" || normTarget == "" {
		return false
	}
	if normTarget == normFE {
		return true
	}
	feIsLoopback := isLoopbackStreamLoadHost(feHost)
	if isLoopbackStreamLoadHost(targetHost) {
		return feIsLoopback
	}
	if c.hasAllowedBEHost(normTarget) {
		return true
	}
	// Private VPC / container bridge bootstrap before SHOW BACKENDS has populated allowedBEHosts:
	// permit RFC1918/ULA BE targets ONLY when FE itself is RFC1918/ULA or loopback (never when FE is a public IP or DNS hostname).
	if (isPrivateVPCStreamLoadIP(feHost) || feIsLoopback) && isPrivateVPCStreamLoadIP(targetHost) {
		return true
	}
	return false
}

func (c *StreamLoadClient) validateStreamLoadTargetHostAndScheme(targetURL *url.URL) (*url.URL, error) {
	if targetURL == nil {
		return nil, fmt.Errorf("nil stream load target URL")
	}
	feURL, err := c.parseConfiguredFEURL()
	if err != nil {
		return nil, err
	}
	targetScheme := strings.ToLower(targetURL.Scheme)
	if targetScheme != "http" && targetScheme != "https" {
		return nil, fmt.Errorf("stream load rejected unsupported scheme %q", targetURL.Scheme)
	}
	if strings.EqualFold(feURL.Scheme, "https") && targetScheme != "https" {
		return nil, fmt.Errorf("stream load rejected scheme downgrade from https to %s", targetScheme)
	}
	if targetURL.User != nil {
		return nil, fmt.Errorf("stream load rejected embedded userinfo in target URL")
	}
	targetHost := targetURL.Hostname()
	if isBlockedStreamLoadHost(targetHost) {
		return nil, fmt.Errorf("stream load rejected blocked metadata or link-local host %q", targetHost)
	}
	if !c.isTrustedTargetHost(feURL, targetHost) {
		return nil, fmt.Errorf("stream load rejected untrusted redirect host %q", targetHost)
	}
	return feURL, nil
}

func (c *StreamLoadClient) validateStreamLoadTargetURL(targetURL *url.URL) error {
	if _, err := c.validateStreamLoadTargetHostAndScheme(targetURL); err != nil {
		return err
	}
	if !strings.HasSuffix(targetURL.Path, "/_stream_load") {
		return fmt.Errorf("stream load rejected non-stream-load redirect path %q", targetURL.Path)
	}
	return nil
}

func (c *StreamLoadClient) validateCachedBEBaseURL(rawBase string) bool {
	trimmed := strings.TrimSpace(rawBase)
	if trimmed == "" {
		return false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	uCopy := *u
	uCopy.Path = "/api/_db/_tbl/_stream_load"
	return c.validateStreamLoadTargetURL(&uCopy) == nil
}

func (c *StreamLoadClient) matchesConfiguredRedirectUserinfo(u *url.Userinfo) bool {
	if u == nil {
		return true
	}
	user := u.Username()
	pass, hasPass := u.Password()
	if user == "" && (!hasPass || pass == "") {
		return true
	}
	cfgUser := c.cfg.User
	cfgPass := c.cfg.Password
	passOK := !hasPass || pass == "" || pass == cfgPass
	if user == cfgUser && passOK {
		return true
	}
	// Apache Doris FE 307 Stream Load redirects may emit cluster-qualified usernames such as
	// "default_cluster:root" (encoded or raw) or "root@default_cluster" in Location userinfo.
	if cfgUser != "" && len(user) > len(cfgUser)+1 &&
		(strings.HasSuffix(user, ":"+cfgUser) || strings.HasPrefix(user, cfgUser+"@")) &&
		passOK {
		return true
	}
	if cfgUser != "" && user != "" && hasPass {
		if pass == cfgUser || pass == cfgUser+":" || pass == cfgUser+":"+cfgPass {
			return true
		}
	}
	return false
}

func (c *StreamLoadClient) checkStreamLoadRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		req.Header.Del("Authorization")
		return fmt.Errorf("stopped after 5 redirects")
	}
	if len(via) > 0 && req.URL != nil && req.URL.User != nil && c.matchesConfiguredRedirectUserinfo(req.URL.User) {
		req.URL.User = nil
	}
	_, err := c.validateStreamLoadTargetHostAndScheme(req.URL)
	if err != nil {
		req.Header.Del("Authorization")
		return err
	}
	if !strings.HasSuffix(req.URL.Path, "/_stream_load") {
		req.Header.Del("Authorization")
		return fmt.Errorf("stream load rejected non-stream-load redirect path %q", req.URL.Path)
	}
	if len(via) > 0 {
		if auth := via[0].Header.Get("Authorization"); auth != "" {
			// #nosec G119 -- validated Doris BE redirect on non-downgraded scheme, allowlisted BE host, and /_stream_load path
			req.Header.Set("Authorization", auth)
		}
		for _, h := range []string{"Expect", "format", "read_json_by_line", "strip_outer_array", "hidden_columns", "function_column.sequence_col"} {
			if v := via[0].Header.Get(h); v != "" && req.Header.Get(h) == "" {
				req.Header.Set(h, v)
			}
		}
	}
	return nil
}

type streamLoadResponse struct {
	Status             string `json:"Status"`
	Message            string `json:"Message"`
	ExistingJobStatus  string `json:"ExistingJobStatus"`
	NumberTotalRows    int64  `json:"NumberTotalRows"`
	NumberLoadedRows   int64  `json:"NumberLoadedRows"`
	NumberFilteredRows int64  `json:"NumberFilteredRows"`
	ErrorURL           string `json:"ErrorURL"`
}

// LoadNDJSON sends a batch of shredded NDJSON rows to Doris via transactional HTTP Stream Load.
// Note: Standard transactional Stream Load (without `group_commit` and without `fuzzy_parse: true`)
// commits synchronously before returning `Status: "Success"`, supports `merge_type: MERGE` with
// `delete: __DORIS_DELETE_SIGN__ = 1` and `function_column.sequence_col: _version`, and allows
// heterogeneous optional fields across documents in the same `/_bulk` NDJSON batch.
func (c *StreamLoadClient) LoadNDJSON(
	ctx context.Context,
	table string,
	ndjsonPayload []byte,
	_ bool,
) error {
	if len(bytes.TrimSpace(ndjsonPayload)) == 0 {
		return nil
	}
	maxBytes := c.cfg.MaxBatchBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024
	}
	if len(ndjsonPayload) > maxBytes {
		lines := bytes.Split(bytes.TrimRight(ndjsonPayload, "\n"), []byte("\n"))
		if len(lines) > 1 {
			var chunk bytes.Buffer
			for _, line := range lines {
				if len(bytes.TrimSpace(line)) == 0 {
					continue
				}
				if chunk.Len() > 0 && chunk.Len()+len(line)+1 > maxBytes {
					if err := c.loadSingleNDJSONBatch(ctx, table, chunk.Bytes()); err != nil {
						return err
					}
					chunk.Reset()
				}
				chunk.Write(line)
				chunk.WriteByte('\n')
			}
			if chunk.Len() > 0 {
				return c.loadSingleNDJSONBatch(ctx, table, chunk.Bytes())
			}
			return nil
		}
	}
	return c.loadSingleNDJSONBatch(ctx, table, ndjsonPayload)
}

func (c *StreamLoadClient) loadSingleNDJSONBatch(
	ctx context.Context,
	table string,
	ndjsonPayload []byte,
) error {
	if len(bytes.TrimSpace(ndjsonPayload)) == 0 {
		return nil
	}
	feURL, err := c.parseConfiguredFEURL()
	if err != nil {
		return err
	}
	if isBlockedStreamLoadHost(feURL.Hostname()) {
		return fmt.Errorf("stream load rejected blocked metadata or link-local FEHTTPEndpoint host %q", feURL.Hostname())
	}

	safeDB := url.PathEscape(schema.SanitizeDorisIdentifier(c.cfg.Database))
	safeTable := url.PathEscape(schema.SanitizeDorisIdentifier(table))
	feBase := strings.TrimRight(strings.TrimSpace(c.cfg.FEHTTPEndpoint), "/")

	const maxAttempts = 3
	backoff := 25 * time.Millisecond
	var lastErr error
	batchLabel := fmt.Sprintf("es_proxy_%s_%d_%d", safeTable, time.Now().UnixNano(), atomic.AddUint64(&streamLoadLabelSeq, 1))

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		targetBase := feBase
		usedCachedBE := false
		if attempt == 1 {
			if cached, ok := c.cachedBEBase.Load().(string); ok && cached != "" {
				if c.validateCachedBEBaseURL(cached) {
					targetBase = cached
					usedCachedBE = true
				} else {
					c.cachedBEBase.Store("")
				}
			}
		}
		endpoint := fmt.Sprintf("%s/api/%s/%s/_stream_load", targetBase, safeDB, safeTable)

		// #nosec G704 -- endpoint is constructed from validated FE/BE base URL and sanitized Doris identifiers
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(ndjsonPayload))
		if err != nil {
			return err
		}
		req.SetBasicAuth(c.cfg.User, c.cfg.Password)
		req.Header.Set("Expect", "100-continue")
		req.Header.Set("label", batchLabel)
		req.Header.Set("format", "json")
		req.Header.Set("read_json_by_line", "true")
		req.Header.Set("strip_outer_array", "false")
		req.Header.Set("hidden_columns", "__DORIS_DELETE_SIGN__")
		req.Header.Set("function_column.sequence_col", "_version")

		// #nosec G704 -- validated Doris FE/BE Stream Load HTTP request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			if usedCachedBE {
				c.cachedBEBase.Store("")
			}
			lastErr = fmt.Errorf("doris stream load HTTP error: %w", err)
			if ctx.Err() != nil {
				return lastErr
			}
			continue
		}

		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			if usedCachedBE {
				c.cachedBEBase.Store("")
			}
			lastErr = fmt.Errorf("reading stream load response: %w", readErr)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout {
			if usedCachedBE {
				c.cachedBEBase.Store("")
			}
			lastErr = fmt.Errorf("transient stream load HTTP %d: %s", resp.StatusCode, string(bodyBytes))
			continue
		}

		var slResp streamLoadResponse
		if err := json.Unmarshal(bodyBytes, &slResp); err != nil || (slResp.Status == "" && resp.StatusCode >= 400) {
			return fmt.Errorf("unexpected stream load response (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
		}
		if strings.EqualFold(slResp.Status, "Label Already Exists") && attempt > 1 {
			if strings.EqualFold(slResp.ExistingJobStatus, "VISIBLE") || strings.EqualFold(slResp.ExistingJobStatus, "COMMITTED") {
				return nil
			}
			if attempt < maxAttempts && !strings.EqualFold(slResp.ExistingJobStatus, "ABORTED") {
				lastErr = fmt.Errorf("doris stream load label already exists with status %q: %s", slResp.ExistingJobStatus, slResp.Message)
				continue
			}
			detail := c.fetchErrorURLDetail(ctx, slResp.ErrorURL)
			msg := slResp.Message
			if msg == "" {
				msg = string(bodyBytes)
			}
			return fmt.Errorf("doris stream load failed (HTTP %d, status=%s, existing_job_status=%s): %s (error_url=%s detail=%s)",
				resp.StatusCode, slResp.Status, slResp.ExistingJobStatus, msg, slResp.ErrorURL, detail)
		}
		if !strings.EqualFold(slResp.Status, "Success") && !strings.EqualFold(slResp.Status, "Publish Timeout") {
			if isTransientStreamLoadError(slResp.Status, slResp.Message) && attempt < maxAttempts {
				lastErr = fmt.Errorf("doris stream load transient failure (status=%s): %s", slResp.Status, slResp.Message)
				continue
			}
			detail := c.fetchErrorURLDetail(ctx, slResp.ErrorURL)
			msg := slResp.Message
			if msg == "" {
				msg = string(bodyBytes)
			}
			return fmt.Errorf("doris stream load failed (HTTP %d, status=%s): %s (error_url=%s detail=%s)", resp.StatusCode, slResp.Status, msg, slResp.ErrorURL, detail)
		}
		if slResp.NumberFilteredRows > 0 {
			detail := c.fetchErrorURLDetail(ctx, slResp.ErrorURL)
			return fmt.Errorf("doris stream load filtered %d/%d rows: %s (error_url=%s detail=%s)",
				slResp.NumberFilteredRows, slResp.NumberTotalRows, slResp.Message, slResp.ErrorURL, detail)
		}
		if resp.Request != nil && resp.Request.URL != nil &&
			c.validateStreamLoadTargetURL(resp.Request.URL) == nil {
			resolvedBase := strings.ToLower(resp.Request.URL.Scheme) + "://" + resp.Request.URL.Host
			if resolvedBase != feBase && c.validateCachedBEBaseURL(resolvedBase) {
				c.cachedBEBase.Store(resolvedBase)
			}
		}
		return nil
	}
	return lastErr
}

var streamLoadLabelSeq uint64

func isTransientStreamLoadError(status, msg string) bool {
	combined := strings.ToUpper(status + " " + msg)
	return strings.Contains(combined, "TOO_MANY_VERSIONS") ||
		strings.Contains(combined, "MEM_LIMIT_EXCEEDED") ||
		strings.Contains(combined, "SERVICE_UNAVAILABLE") ||
		strings.Contains(combined, "TRY AGAIN")
}

func (c *StreamLoadClient) validateErrorDetailURL(parsedErrURL *url.URL) (*url.URL, bool) {
	if parsedErrURL == nil || parsedErrURL.User != nil {
		return nil, false
	}
	feURL, err := c.parseConfiguredFEURL()
	if err != nil {
		return nil, false
	}
	errScheme := strings.ToLower(parsedErrURL.Scheme)
	if errScheme != "http" && errScheme != "https" {
		return nil, false
	}
	if strings.EqualFold(feURL.Scheme, "https") && errScheme != "https" {
		return nil, false
	}
	if !strings.Contains(parsedErrURL.Path, "_load_error") {
		return nil, false
	}
	targetHost := parsedErrURL.Hostname()
	if isBlockedStreamLoadHost(targetHost) || !c.isTrustedTargetHost(feURL, targetHost) {
		return nil, false
	}
	return feURL, true
}

func sanitizeStreamLoadErrorDetail(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") ||
		strings.HasPrefix(lower, "<head") ||
		strings.HasPrefix(lower, "<body") ||
		strings.HasPrefix(lower, "<script") ||
		strings.HasPrefix(lower, "<style") ||
		strings.HasPrefix(lower, "<?xml") ||
		strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<body") ||
		strings.Contains(lower, "<script") {
		return ""
	}
	cleaned := trimmed
	if strings.Contains(lower, "</") || strings.HasPrefix(trimmed, "<") {
		var noTags strings.Builder
		noTags.Grow(len(trimmed))
		inTag := false
		for i := 0; i < len(trimmed); i++ {
			switch trimmed[i] {
			case '<':
				inTag = true
			case '>':
				if inTag {
					inTag = false
					noTags.WriteByte(' ')
				} else {
					noTags.WriteByte('>')
				}
			default:
				if !inTag {
					noTags.WriteByte(trimmed[i])
				}
			}
		}
		cleaned = noTags.String()
	}

	var b strings.Builder
	b.Grow(min(len(cleaned), maxStreamLoadErrorDetailBytes))
	prevSpace := true
	for i := 0; i < len(cleaned); {
		r, width := utf8.DecodeRuneInString(cleaned[i:])
		i += width
		if r == utf8.RuneError && width == 1 {
			continue
		}
		if r == '\r' || r == '\n' || r == '\t' || unicode.IsSpace(r) {
			if !prevSpace && b.Len()+1 <= maxStreamLoadErrorDetailBytes {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			continue
		}
		var encoded [utf8.UTFMax]byte
		n := utf8.EncodeRune(encoded[:], r)
		if b.Len()+n > maxStreamLoadErrorDetailBytes {
			break
		}
		b.Write(encoded[:n])
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

func (c *StreamLoadClient) fetchErrorURLDetail(ctx context.Context, errURL string) string {
	trimmed := strings.TrimSpace(errURL)
	if trimmed == "" {
		return ""
	}
	parsedErrURL, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	feURL, ok := c.validateErrorDetailURL(parsedErrURL)
	if !ok {
		return ""
	}
	// #nosec G704 -- fetching diagnostic error summary from allowlisted Doris BE _load_error URL without following redirects
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedErrURL.String(), nil)
	if err != nil {
		return ""
	}
	if (c.cfg.User != "" || c.cfg.Password != "") && strings.EqualFold(feURL.Scheme, parsedErrURL.Scheme) {
		req.SetBasicAuth(c.cfg.User, c.cfg.Password)
	}
	httpCli := c.errHTTPClient
	if httpCli == nil {
		httpCli = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	// #nosec G704 -- validated Doris BE _load_error diagnostic GET request
	resp, err := httpCli.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return sanitizeStreamLoadErrorDetail(string(raw))
}
