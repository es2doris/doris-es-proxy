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

package e2e_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// TestLiveApacheDoris_E2E executes the full OpenMetadata DDL + Stream Load + Search + Aggregation
// workflow against a live Apache Doris FE/BE cluster when `DORIS_E2E_DSN` and `DORIS_E2E_HTTP` are set.
func TestLiveApacheDoris_E2E(t *testing.T) {
	dsn := os.Getenv("DORIS_E2E_DSN")
	feHTTP := os.Getenv("DORIS_E2E_HTTP")
	if dsn == "" || feHTTP == "" {
		t.Skip("Skipping live Apache Doris container E2E test (set DORIS_E2E_DSN and DORIS_E2E_HTTP to run)")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("failed to open Doris MySQL connection: %v", err)
	}
	defer func() { _ = db.Close() }()

	dorisDB := fmt.Sprintf("es_e2e_%d", time.Now().Unix())
	if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", dorisDB)); err != nil {
		t.Fatalf("failed to create test Doris database %s: %v", dorisDB, err)
	}
	defer func() {
		_, _ = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s` FORCE", dorisDB))
	}()

	slClient := proxy.NewStreamLoadClient(proxy.StreamLoadConfig{
		FEHTTPEndpoint: feHTTP,
		User:           "root",
		Password:       "",
		Database:       dorisDB,
		Timeout:        30 * time.Second,
	})
	backend := proxy.NewDorisSQLBackend(db, slClient)
	srv := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	createJSON := `{
		"mappings": {
			"properties": {
				"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"serviceType": {"type": "keyword"},
				"deleted": {"type": "boolean"},
				"tags": {"properties": {"tagFQN": {"type": "keyword"}}},
				"columns": {
					"type": "nested",
					"properties": {
						"name": {"type": "keyword"},
						"dataType": {"type": "keyword"}
					}
				}
			}
		}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_table_index", strings.NewReader(createJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /live_table_index on live Doris failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	bulkPayload := strings.Join([]string{
		`{"index":{"_index":"live_table_index","_id":"live-1"}}`,
		`{"name":"customer_orders","serviceType":"BigQuery","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}],"columns":[{"name":"user_id","dataType":"INT"}]}`,
		"",
	}, "\n")
	resp, err = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulkPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk on live Doris failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	searchPayload := `{
		"size": 10,
		"query": {"match": {"name": "customer_orders"}},
		"aggs": {"serviceType": {"terms": {"field": "serviceType", "size": 10}}}
	}`
	resp, err = http.Post(ts.URL+"/live_table_index/_search", "application/json", strings.NewReader(searchPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_search on live Doris failed: status=%v err=%v", resp.StatusCode, err)
	}
	var searchRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&searchRes)
	_ = resp.Body.Close()

	hits := searchRes["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit from live Doris, got %d: %+v", len(hits), searchRes)
	}
}
