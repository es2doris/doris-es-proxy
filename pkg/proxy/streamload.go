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
	"net/url"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// StreamLoadConfig configures the Apache Doris HTTP Stream Load client.
type StreamLoadConfig struct {
	FEHTTPEndpoint string // e.g. "http://127.0.0.1:8030"
	User           string // e.g. "root"
	Password       string
	Database       string // e.g. "es_compat"
	Timeout        time.Duration
}

// StreamLoadClient streams NDJSON document batches into Apache Doris Unique Key Merge-on-Write
// tables while preserving Basic Auth headers across FE :8030 -> BE :8040 HTTP 307 redirects.
type StreamLoadClient struct {
	cfg        StreamLoadConfig
	httpClient *http.Client
}

func NewStreamLoadClient(cfg StreamLoadConfig) *StreamLoadClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		// Preserve Authorization header when Doris FE (8030) issues a 307 Temporary Redirect to Doris BE (8040).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if len(via) > 0 && req.URL.Scheme == via[0].URL.Scheme {
				if auth := via[0].Header.Get("Authorization"); auth != "" {
					// #nosec G119 -- Doris FE (:8030) redirects Stream Load PUTs to Doris BE (:8040) on the same scheme
					req.Header.Set("Authorization", auth)
				}
			}
			return nil
		},
	}
	return &StreamLoadClient{
		cfg:        cfg,
		httpClient: client,
	}
}

type streamLoadResponse struct {
	Status             string `json:"Status"`
	Message            string `json:"Message"`
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
	safeDB := url.PathEscape(schema.SanitizeDorisIdentifier(c.cfg.Database))
	safeTable := url.PathEscape(schema.SanitizeDorisIdentifier(table))
	endpoint := fmt.Sprintf(
		"%s/api/%s/%s/_stream_load",
		strings.TrimRight(c.cfg.FEHTTPEndpoint, "/"),
		safeDB,
		safeTable,
	)

	// #nosec G704 -- endpoint is constructed from operator-configured FEHTTPEndpoint and sanitized Doris identifiers
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(ndjsonPayload))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.User, c.cfg.Password)
	req.Header.Set("Expect", "100-continue")
	req.Header.Set("format", "json")
	req.Header.Set("read_json_by_line", "true")
	req.Header.Set("strip_outer_array", "false")
	req.Header.Set("hidden_columns", "__DORIS_DELETE_SIGN__")
	req.Header.Set("function_column.sequence_col", "_version")

	// #nosec G704 -- operator-configured Doris FE/BE Stream Load HTTP request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("doris stream load HTTP error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading stream load response: %w", err)
	}

	var slResp streamLoadResponse
	if err := json.Unmarshal(bodyBytes, &slResp); err != nil {
		return fmt.Errorf("unexpected stream load response (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
	}
	if !strings.EqualFold(slResp.Status, "Success") && !strings.EqualFold(slResp.Status, "Publish Timeout") {
		detail := c.fetchErrorURLDetail(ctx, slResp.ErrorURL)
		return fmt.Errorf("doris stream load failed (status=%s): %s (error_url=%s detail=%s)", slResp.Status, slResp.Message, slResp.ErrorURL, detail)
	}
	if slResp.NumberFilteredRows > 0 {
		detail := c.fetchErrorURLDetail(ctx, slResp.ErrorURL)
		return fmt.Errorf("doris stream load filtered %d/%d rows: %s (error_url=%s detail=%s)",
			slResp.NumberFilteredRows, slResp.NumberTotalRows, slResp.Message, slResp.ErrorURL, detail)
	}
	return nil
}

func (c *StreamLoadClient) fetchErrorURLDetail(ctx context.Context, errURL string) string {
	if strings.TrimSpace(errURL) == "" {
		return ""
	}
	// #nosec G704 -- fetching diagnostic error summary from Doris BE ErrorURL on Stream Load failure
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, errURL, nil)
	if err != nil {
		return ""
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(raw))
}
