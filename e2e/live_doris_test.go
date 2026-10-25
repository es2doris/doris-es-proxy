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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
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

// TestLiveApacheDoris_E2E executes the full OpenMetadata DDL + Stream Load + Search + Aggregation +
// Painless Update + Soft-Delete + Dynamic Auto-Mapping + Stateless _es_catalog Rehydration
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
	backend.SetLogSQL(true)
	srv := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
	if err := srv.BootstrapCatalog(context.Background()); err != nil {
		t.Logf("initial BootstrapCatalog note: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Explicit Mapping Creation (VARIANT + Promoted Scalar/Array + Dense Vector + Correlated Nested Array + USING INVERTED)
	createJSON := `{
		"mappings": {
			"properties": {
				"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"serviceType": {"type": "keyword"},
				"deleted": {"type": "boolean"},
				"embedding": {"type": "dense_vector", "dims": 3, "similarity": "cosine"},
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
	var createBody []byte
	var createStatus int
	for attempt := 1; attempt <= 15; attempt++ {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_table_index", strings.NewReader(createJSON))
		resp, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil {
			t.Fatalf("PUT /live_table_index transport error: %v", reqErr)
		}
		createBody, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		createStatus = resp.StatusCode
		if createStatus == http.StatusOK {
			break
		}
		if strings.Contains(string(createBody), "Failed to find enough backend") && attempt < 15 {
			t.Logf("Waiting for Doris BE disk report before tablet creation (attempt %d/15)...", attempt)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if createStatus != http.StatusOK {
		t.Fatalf("PUT /live_table_index on live Doris failed: status=%d body=%s", createStatus, string(createBody))
	}

	// 2. Bulk Indexing (2 docs via HTTP Stream Load :8030 -> :8040 redirect)
	bulkPayload := strings.Join([]string{
		`{"index":{"_index":"live_table_index","_id":"live-1"}}`,
		`{"name":"customer_orders","serviceType":"BigQuery","deleted":false,"embedding":[0.9,0.1,0.0],"tags":[{"tagFQN":"PII.Sensitive"}],"columns":[{"name":"user_id","dataType":"INT"}]}`,
		`{"index":{"_index":"live_table_index","_id":"live-2"}}`,
		`{"name":"ephemeral_staging","serviceType":"Snowflake","deleted":false,"embedding":[0.1,0.9,0.0],"tags":[],"columns":[{"name":"temp_id","dataType":"VARCHAR"}]}`,
		"",
	}, "\n")
	resp, err := http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulkPayload))
	if err != nil {
		t.Fatalf("POST /_bulk transport error: %v", err)
	}
	bulkBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk on live Doris failed: status=%d body=%s", resp.StatusCode, string(bulkBody))
	}
	var bulkRes map[string]any
	_ = json.Unmarshal(bulkBody, &bulkRes)
	if bulkRes["errors"] == true {
		t.Fatalf("POST /_bulk returned item errors: %s", string(bulkBody))
	}

	// 3. Full-Text Match + Correlated Nested Filter + Terms Aggregation
	searchPayload := `{
		"size": 10,
		"query": {
			"bool": {
				"must": [
					{"match": {"name": "customer_orders"}},
					{
						"nested": {
							"path": "columns",
							"query": {
								"bool": {
									"must": [
										{"term": {"columns.name": "user_id"}},
										{"term": {"columns.dataType": "INT"}}
									]
								}
							}
						}
					}
				]
			}
		},
		"aggs": {"serviceType": {"terms": {"field": "serviceType", "size": 10}}}
	}`
	resp, err = http.Post(ts.URL+"/live_table_index/_search", "application/json", strings.NewReader(searchPayload))
	if err != nil {
		t.Fatalf("POST /_search transport error: %v", err)
	}
	searchBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_search on live Doris failed: status=%d body=%s", resp.StatusCode, string(searchBody))
	}
	var searchRes map[string]any
	_ = json.Unmarshal(searchBody, &searchRes)

	hits := searchRes["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit from live Doris, got %d: %s", len(hits), string(searchBody))
	}

	// 3b. Vector / kNN Search Pushdown (COSINE_DISTANCE on ARRAY<FLOAT>) on live Doris 4.x
	knnPayload := `{
		"knn": {
			"field": "embedding",
			"query_vector": [0.95, 0.05, 0.0],
			"k": 1,
			"num_candidates": 10
		}
	}`
	knnResp, err := http.Post(ts.URL+"/live_table_index/_search", "application/json", strings.NewReader(knnPayload))
	if err != nil {
		t.Fatalf("POST /_search (knn) transport error: %v", err)
	}
	knnBody, _ := io.ReadAll(knnResp.Body)
	_ = knnResp.Body.Close()
	if knnResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_search (knn) on live Doris failed: status=%d body=%s", knnResp.StatusCode, string(knnBody))
	}
	var knnRes map[string]any
	_ = json.Unmarshal(knnBody, &knnRes)
	knnHits := knnRes["hits"].(map[string]any)["hits"].([]any)
	if len(knnHits) != 1 || knnHits[0].(map[string]any)["_id"] != "live-1" {
		t.Fatalf("expected top-1 kNN hit to be live-1 on live Doris, got: %s", string(knnBody))
	}

	// 4. Painless Partial Update + Point Lookup (GET /_doc/live-1)
	updatePayload := `{"doc":{"serviceType":"Databricks"}}`
	resp, err = http.Post(ts.URL+"/live_table_index/_update/live-1?refresh=true", "application/json", strings.NewReader(updatePayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_update/live-1 failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/live_table_index/_doc/live-1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_doc/live-1 failed: status=%v err=%v", resp.StatusCode, err)
	}
	var getRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&getRes)
	_ = resp.Body.Close()
	if getRes["found"] != true || getRes["_source"].(map[string]any)["serviceType"] != "Databricks" {
		t.Fatalf("expected updated serviceType=Databricks on live Doris, got: %+v", getRes)
	}

	// 5. Soft-Delete via __DORIS_DELETE_SIGN__ = 1 (DELETE /_doc/live-2)
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/live_table_index/_doc/live-2?refresh=true", nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil || delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /_doc/live-2 failed: status=%v err=%v", delResp.StatusCode, err)
	}
	_ = delResp.Body.Close()

	resp, err = http.Get(ts.URL + "/live_table_index/_doc/live-2")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after DELETE /_doc/live-2 on live Doris, got status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 6. Dynamic Auto-Mapping on First Bulk Write (no prior PUT /live_auto_index)
	autoBulk := strings.Join([]string{
		`{"index":{"_index":"live_auto_index","_id":"auto-1"}}`,
		`{"service":"checkout-api","latency_ms":42,"ok":true}`,
		"",
	}, "\n")
	resp, err = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(autoBulk))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk on auto-created index failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 7. Stateless _es_catalog Rehydration across a fresh Server instance
	srv2 := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
	if err := srv2.BootstrapCatalog(context.Background()); err != nil {
		t.Fatalf("srv2.BootstrapCatalog failed: %v", err)
	}
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	resp, err = http.Get(ts2.URL + "/live_auto_index/_mapping")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /live_auto_index/_mapping on rehydrated server failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
}
