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

	// 6b. Live Doris Field Promotion + Backfill, Lucene [min TO max] + _exists_:, and Ingest Pipeline
	promoteResp, err := http.Post(ts.URL+"/live_auto_index/_doris/promote", "application/json",
		strings.NewReader(`{"field":"service","type":"keyword"}`))
	if err != nil || promoteResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_doris/promote failed: status=%v err=%v", promoteResp.StatusCode, err)
	}
	_ = promoteResp.Body.Close()

	luceneResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json",
		strings.NewReader(`{"query":{"query_string":{"query":"latency_ms:[10 TO 100] AND _exists_:service AND service:checkout-api"}}}`))
	if err != nil || luceneResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search after promote failed: status=%v err=%v", luceneResp.StatusCode, err)
	}
	var luceneRes map[string]any
	_ = json.NewDecoder(luceneResp.Body).Decode(&luceneRes)
	_ = luceneResp.Body.Close()
	if luceneRes["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected 1 hit after live Doris field promotion + Lucene range/_exists_ query, got: %+v", luceneRes)
	}

	pipePutReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/_ingest/pipeline/live-pipe",
		strings.NewReader(`{"processors":[{"set":{"field":"env","value":"prod"}}]}`))
	pipePutReq.Header.Set("Content-Type", "application/json")
	pipePutResp, err := http.DefaultClient.Do(pipePutReq)
	if err != nil || pipePutResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /_ingest/pipeline/live-pipe failed: status=%v err=%v", pipePutResp.StatusCode, err)
	}
	_ = pipePutResp.Body.Close()

	pipeDocReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_auto_index/_doc/auto-2?pipeline=live-pipe&refresh=true",
		strings.NewReader(`{"service":"billing-api","latency_ms":15}`))
	pipeDocReq.Header.Set("Content-Type", "application/json")
	pipeDocResp, err := http.DefaultClient.Do(pipeDocReq)
	if err != nil || (pipeDocResp.StatusCode != http.StatusOK && pipeDocResp.StatusCode != http.StatusCreated) {
		t.Fatalf("PUT /live_auto_index/_doc/auto-2?pipeline=live-pipe failed: status=%v err=%v", pipeDocResp.StatusCode, err)
	}
	_ = pipeDocResp.Body.Close()

	getAuto2Resp, err := http.Get(ts.URL + "/live_auto_index/_doc/auto-2")
	if err != nil || getAuto2Resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /live_auto_index/_doc/auto-2 failed: status=%v err=%v", getAuto2Resp.StatusCode, err)
	}
	var auto2Doc map[string]any
	_ = json.NewDecoder(getAuto2Resp.Body).Decode(&auto2Doc)
	_ = getAuto2Resp.Body.Close()
	if auto2Doc["_source"].(map[string]any)["env"] != "prod" {
		t.Fatalf("expected ingest pipeline to set env=prod on live Doris, got: %+v", auto2Doc)
	}

	// 6c. Round-5 & Round-6 Advanced DSL + Aggregations + Pipeline Aggs + filter_path + _field_caps on Live Doris 4.x
	advSearchPayload := `{
		"size": 10,
		"query": {
			"bool": {
				"must": [
					{"match_bool_prefix": {"service": "checkout"}},
					{"terms_set": {
						"service": {
							"terms": ["checkout-api", "billing-api"],
							"minimum_should_match_script": {"source": "Math.min(params.num_terms, 1)"}
						}
					}}
				]
			}
		},
		"aggs": {
			"sig_services": {
				"significant_terms": {"field": "service", "size": 5}
			},
			"comp_hist": {
				"composite": {
					"size": 1,
					"sources": [
						{"lat_bucket": {"histogram": {"field": "latency_ms", "interval": 20}}}
					]
				}
			},
			"lat_hist": {
				"histogram": {"field": "latency_ms", "interval": 20},
				"aggs": {
					"avg_lat": {"avg": {"field": "latency_ms"}},
					"cum_lat": {"cumulative_sum": {"buckets_path": "avg_lat"}},
					"deriv_lat": {"derivative": {"buckets_path": "avg_lat"}},
					"double_lat": {"bucket_script": {"buckets_path": {"v": "avg_lat"}, "script": "params.v * 2"}}
				}
			},
			"overall_lat_stats": {
				"stats_bucket": {"buckets_path": "lat_hist>avg_lat"}
			}
		}
	}`
	advResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(advSearchPayload))
	if err != nil || advResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(advResp.Body)
		t.Fatalf("POST /live_auto_index/_search (advanced DSL + aggs) failed: status=%v err=%v body=%s", advResp.StatusCode, err, string(b))
	}
	var advRes map[string]any
	_ = json.NewDecoder(advResp.Body).Decode(&advRes)
	_ = advResp.Body.Close()
	if advRes["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected 1 hit for match_bool_prefix + terms_set on live Doris, got: %+v", advRes)
	}
	aggsMap, _ := advRes["aggregations"].(map[string]any)
	compHist, _ := aggsMap["comp_hist"].(map[string]any)
	afterKey, _ := compHist["after_key"].(map[string]any)
	if afterKey == nil || afterKey["lat_bucket"] == nil {
		t.Fatalf("expected composite after_key.lat_bucket on live Doris, got: %+v", compHist)
	}
	// Verify composite `after` pagination works with numeric histogram key on live Doris
	afterSearch := fmt.Sprintf(`{"size":0,"aggs":{"comp_hist":{"composite":{"size":5,"after":{"lat_bucket":%v},"sources":[{"lat_bucket":{"histogram":{"field":"latency_ms","interval":20}}}]}}}}`, afterKey["lat_bucket"])
	afterResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(afterSearch))
	if err != nil || afterResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(afterResp.Body)
		t.Fatalf("POST /live_auto_index/_search (composite after) failed: status=%v err=%v body=%s", afterResp.StatusCode, err, string(b))
	}
	_ = afterResp.Body.Close()

	// Verify ?filter_path=hits.hits._id and _field_caps on live Doris
	fpResp, err := http.Post(ts.URL+"/live_auto_index/_search?filter_path=hits.hits._id", "application/json", strings.NewReader(`{"query":{"match_all":{}}}`))
	if err != nil || fpResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search?filter_path failed: status=%v err=%v", fpResp.StatusCode, err)
	}
	var fpRes map[string]any
	_ = json.NewDecoder(fpResp.Body).Decode(&fpRes)
	_ = fpResp.Body.Close()
	if _, hasTook := fpRes["took"]; hasTook || fpRes["hits"] == nil {
		t.Fatalf("expected filter_path=hits.hits._id to strip took and retain hits, got: %+v", fpRes)
	}

	fcResp, err := http.Get(ts.URL + "/live_table_index/_field_caps?fields=*")
	if err != nil || fcResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /live_table_index/_field_caps failed: status=%v err=%v", fcResp.StatusCode, err)
	}
	_ = fcResp.Body.Close()

	// Verify /readyz, /metrics, and /_doris/slowlog against live Doris
	for _, ep := range []string{"/readyz", "/metrics", "/_doris/slowlog"} {
		epResp, err := http.Get(ts.URL + ep)
		if err != nil || epResp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s on live Doris failed: status=%v err=%v", ep, epResp.StatusCode, err)
		}
		_ = epResp.Body.Close()
	}

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

	// 8. Round-8 Live Doris Verification: extended_stats, string_stats, boxplot, percentile_ranks,
	// top_metrics, global, sampler, anonymous filters + other_bucket, moving_avg, serial_diff,
	// extended_stats_bucket, percentiles_bucket, and filtered write-alias rehydration
	r8AliasReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/_aliases", strings.NewReader(`{
		"actions": [
			{
				"add": {
					"index": "live_auto_index",
					"alias": "live_checkout_alias",
					"is_write_index": true,
					"filter": {"term": {"service": "checkout-api"}}
				}
			}
		]
	}`))
	r8AliasReq.Header.Set("Content-Type", "application/json")
	r8AliasResp, err := http.DefaultClient.Do(r8AliasReq)
	if err != nil || r8AliasResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_aliases (filtered alias) on live Doris failed: status=%v err=%v", r8AliasResp.StatusCode, err)
	}
	_ = r8AliasResp.Body.Close()

	// Index a second checkout-api document through the filtered write alias (total 3 docs in live_auto_index, 2 matching live_checkout_alias)
	aliasWriteReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_checkout_alias/_doc/auto-3?refresh=true",
		strings.NewReader(`{"service":"checkout-api","latency_ms":85,"ok":true}`))
	aliasWriteReq.Header.Set("Content-Type", "application/json")
	aliasWriteResp, err := http.DefaultClient.Do(aliasWriteReq)
	if err != nil || (aliasWriteResp.StatusCode != http.StatusOK && aliasWriteResp.StatusCode != http.StatusCreated) {
		t.Fatalf("PUT /live_checkout_alias/_doc/auto-3 via write alias failed: status=%v err=%v", aliasWriteResp.StatusCode, err)
	}
	_ = aliasWriteResp.Body.Close()

	// Verify filtered alias single-doc GET enforces the alias filter on live Doris (auto-2 is payment-api -> 404; auto-3 is checkout-api -> 200)
	filteredMissResp, err := http.Get(ts.URL + "/live_checkout_alias/_doc/auto-2")
	if err != nil || filteredMissResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected GET /live_checkout_alias/_doc/auto-2 (payment-api) to return 404, got status=%v err=%v", filteredMissResp.StatusCode, err)
	}
	_ = filteredMissResp.Body.Close()
	filteredHitResp, err := http.Get(ts.URL + "/live_checkout_alias/_doc/auto-3")
	if err != nil || filteredHitResp.StatusCode != http.StatusOK {
		t.Fatalf("expected GET /live_checkout_alias/_doc/auto-3 (checkout-api) to return 200, got status=%v err=%v", filteredHitResp.StatusCode, err)
	}
	_ = filteredHitResp.Body.Close()

	r8SearchBody := `{
		"size": 0,
		"query": {"term": {"latency_ms": 42}},
		"aggs": {
			"all_global": {
				"global": {},
				"aggs": {
					"ext_lat": {"extended_stats": {"field": "latency_ms", "sigma": 2.0}}
				}
			},
			"str_svc": {"string_stats": {"field": "service"}},
			"lat_box": {"boxplot": {"field": "latency_ms"}},
			"lat_ranks": {"percentile_ranks": {"field": "latency_ms", "values": [25, 100]}},
			"latest_lat": {
				"top_metrics": {
					"metrics": {"field": "latency_ms"},
					"sort": [{"latency_ms": "desc"}],
					"size": 1
				}
			},
			"anon_filters": {
				"filters": {
					"other_bucket": true,
					"filters": [
						{"term": {"service": "checkout-api"}}
					]
				}
			},
			"by_lat": {
				"histogram": {"field": "latency_ms", "interval": 20},
				"aggs": {
					"sum_lat": {"sum": {"field": "latency_ms"}},
					"sub_box": {"boxplot": {"field": "latency_ms"}},
					"sub_ranks": {"percentile_ranks": {"field": "latency_ms", "values": [50]}},
					"sub_str": {"string_stats": {"field": "service"}},
					"mov_lat": {"moving_avg": {"buckets_path": "sum_lat", "window": 2}},
					"mov_max": {"moving_fn": {"buckets_path": "sum_lat", "window": 2, "script": "MovingFunctions.max(values)"}},
					"diff_lat": {"serial_diff": {"buckets_path": "sum_lat", "lag": 1}},
					"norm_lat": {"normalize": {"buckets_path": "sum_lat", "method": "percent_of_sum"}},
					"sub_range": {
						"range": {
							"field": "latency_ms",
							"ranges": [{"key": "fast", "to": 50}, {"key": "slow", "from": 50}]
						}
					}
				}
			},
			"ext_bucket": {"extended_stats_bucket": {"buckets_path": "by_lat>sum_lat"}},
			"pct_bucket": {"percentiles_bucket": {"buckets_path": "by_lat>sum_lat", "percents": [50, 95]}}
		}
	}`
	r8Resp, err := http.Post(ts.URL+"/live_checkout_alias/_search", "application/json", strings.NewReader(r8SearchBody))
	if err != nil || r8Resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r8Resp.Body)
		t.Fatalf("POST /live_checkout_alias/_search (Round-8/9/10 aggs) failed: status=%v err=%v body=%s", r8Resp.StatusCode, err, string(b))
	}
	var r8Res map[string]any
	_ = json.NewDecoder(r8Resp.Body).Decode(&r8Res)
	_ = r8Resp.Body.Close()

	if r8Res["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected filtered alias live_checkout_alias with latency_ms=42 query to match 1 doc on live Doris, got: %+v", r8Res["hits"])
	}
	r8Aggs := r8Res["aggregations"].(map[string]any)
	allGlobal := r8Aggs["all_global"].(map[string]any)
	if allGlobal["doc_count"] != float64(2) {
		t.Fatalf("expected global agg on live_checkout_alias to escape query (1->2) while respecting alias filter (excluding payment-api doc), got: %+v", allGlobal)
	}
	extLat := allGlobal["ext_lat"].(map[string]any)
	if extLat["sum_of_squares"] == nil || extLat["sum_of_squares"].(float64) <= 0 {
		t.Fatalf("expected extended_stats sum_of_squares > 0 on live Doris, got: %+v", extLat)
	}
	if r8Aggs["str_svc"] == nil || r8Aggs["lat_box"] == nil || r8Aggs["lat_ranks"] == nil || r8Aggs["latest_lat"] == nil || r8Aggs["ext_bucket"] == nil || r8Aggs["pct_bucket"] == nil {
		t.Fatalf("missing Round-8/9/10 aggregations in live Doris response: %+v", r8Aggs)
	}

	// 12. Verify Round-10 & Round-11 DELETE /{alias} guards (single, comma-separated, wildcard -> 400),
	// _terms_enum (including case_insensitive=true), _explain, _ingest/pipeline/_simulate, and composite order="desc" on live Doris
	for _, aliasTarget := range []string{"live_checkout_alias", "live_checkout_alias,live_checkout_alias", "live_checkout_*"} {
		delAliasReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/"+aliasTarget, nil)
		delAliasResp, err := http.DefaultClient.Do(delAliasReq)
		if err != nil || delAliasResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected DELETE /%s to return 400 Bad Request, got status=%v err=%v", aliasTarget, delAliasResp.StatusCode, err)
		}
		_ = delAliasResp.Body.Close()
	}

	teResp, err := http.Post(ts.URL+"/live_checkout_alias/_terms_enum", "application/json", strings.NewReader(`{"field":"service","string":"CHECK","case_insensitive":true}`))
	if err != nil || teResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_checkout_alias/_terms_enum failed: status=%v err=%v", teResp.StatusCode, err)
	}
	_ = teResp.Body.Close()

	explDocResp, err := http.Post(ts.URL+"/live_checkout_alias/_explain/auto-3", "application/json", strings.NewReader(`{"query":{"term":{"service":"checkout-api"}}}`))
	if err != nil || explDocResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_checkout_alias/_explain/auto-3 failed: status=%v err=%v", explDocResp.StatusCode, err)
	}
	_ = explDocResp.Body.Close()

	simResp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {"processors": [{"set": {"field": "env", "value": "prod"}}]},
		"docs": [{"_index": "live_auto_index", "_id": "sim-1", "_source": {"service": "checkout-api"}}]
	}`))
	if err != nil || simResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate failed: status=%v err=%v", simResp.StatusCode, err)
	}
	_ = simResp.Body.Close()

	compDescResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"size": 0,
		"aggs": {
			"comp_desc": {
				"composite": {
					"size": 1,
					"sources": [
						{"svc": {"terms": {"field": "service", "order": "desc"}}}
					]
				}
			}
		}
	}`))
	if err != nil || compDescResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (composite desc) failed: status=%v err=%v", compDescResp.StatusCode, err)
	}
	var compDescRes map[string]any
	_ = json.NewDecoder(compDescResp.Body).Decode(&compDescRes)
	_ = compDescResp.Body.Close()
	compDescAgg := compDescRes["aggregations"].(map[string]any)["comp_desc"].(map[string]any)
	compBuckets := compDescAgg["buckets"].([]any)
	if len(compBuckets) != 1 || compBuckets[0].(map[string]any)["key"].(map[string]any)["svc"] != "checkout-api" {
		t.Fatalf("expected first descending composite bucket on live Doris to be checkout-api (checkout-api > billing-api), got: %+v", compBuckets)
	}
	compPage2Resp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"size": 0,
		"aggs": {
			"comp_desc": {
				"composite": {
					"size": 1,
					"after": {"svc": "checkout-api"},
					"sources": [
						{"svc": {"terms": {"field": "service", "order": "desc"}}}
					]
				}
			}
		}
	}`))
	if err != nil || compPage2Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (composite desc page 2) failed: status=%v err=%v", compPage2Resp.StatusCode, err)
	}
	var compPage2Res map[string]any
	_ = json.NewDecoder(compPage2Resp.Body).Decode(&compPage2Res)
	_ = compPage2Resp.Body.Close()
	compPage2Buckets := compPage2Res["aggregations"].(map[string]any)["comp_desc"].(map[string]any)["buckets"].([]any)
	if len(compPage2Buckets) != 1 || compPage2Buckets[0].(map[string]any)["key"].(map[string]any)["svc"] != "billing-api" {
		t.Fatalf("expected second descending composite bucket on live Doris to be billing-api, got: %+v", compPage2Buckets)
	}

	// 13. Verify Round-12 self-exclusion search (`live_auto_index,-live_auto_index` -> 0 hits),
	// ingest `drop` processor (`"result": "noop"`), extended ingest processors (`kv`, `urldecode`, `bytes`, `html_strip`, `dot_expander`),
	// and composite metric + pipeline sub-aggregations on live Doris.
	selfExclResp, err := http.Post(ts.URL+"/live_auto_index,-live_auto_index/_search", "application/json", strings.NewReader(`{"query":{"match_all":{}}}`))
	if err != nil || selfExclResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index,-live_auto_index/_search failed: status=%v err=%v", selfExclResp.StatusCode, err)
	}
	var selfExclRes map[string]any
	_ = json.NewDecoder(selfExclResp.Body).Decode(&selfExclRes)
	_ = selfExclResp.Body.Close()
	if selfExclRes["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(0) {
		t.Fatalf("expected 0 hits for self-excluded live_auto_index,-live_auto_index on live Doris, got: %+v", selfExclRes["hits"])
	}

	putDropPipeReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/_ingest/pipeline/live_drop_pipe", strings.NewReader(`{
		"processors": [
			{"drop": {"if": "ctx.service == 'drop-me'"}}
		]
	}`))
	putDropPipeReq.Header.Set("Content-Type", "application/json")
	putDropPipeResp, err := http.DefaultClient.Do(putDropPipeReq)
	if err != nil || putDropPipeResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /_ingest/pipeline/live_drop_pipe failed: status=%v err=%v", putDropPipeResp.StatusCode, err)
	}
	_ = putDropPipeResp.Body.Close()

	putDroppedDocReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_auto_index/_doc/dropped-99?pipeline=live_drop_pipe&refresh=true", strings.NewReader(`{"service":"drop-me","latency_ms":999}`))
	putDroppedDocReq.Header.Set("Content-Type", "application/json")
	putDroppedDocResp, err := http.DefaultClient.Do(putDroppedDocReq)
	if err != nil || putDroppedDocResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT dropped doc failed: status=%v err=%v", putDroppedDocResp.StatusCode, err)
	}
	var droppedDocRes map[string]any
	_ = json.NewDecoder(putDroppedDocResp.Body).Decode(&droppedDocRes)
	_ = putDroppedDocResp.Body.Close()
	if droppedDocRes["result"] != "noop" {
		t.Fatalf("expected dropped doc result=noop on live Doris, got: %+v", droppedDocRes)
	}

	simR12Resp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{"kv": {"field": "qs", "field_split": "&", "value_split": "=", "target_field": "parsed"}},
				{"urldecode": {"field": "parsed.msg"}},
				{"html_strip": {"field": "parsed.msg"}},
				{"bytes": {"field": "parsed.mem", "target_field": "mem_bytes"}}
			]
		},
		"docs": [{"_index": "live_auto_index", "_id": "sim-r12", "_source": {"qs": "msg=%3Cb%3Eok%3C%2Fb%3E&mem=1kb"}}]
	}`))
	if err != nil || simR12Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R12 processors) failed: status=%v err=%v", simR12Resp.StatusCode, err)
	}
	_ = simR12Resp.Body.Close()

	// 14. Verify Round-13 features on live Doris:
	//   - `collapse.inner_hits` + `collapse.fields`
	//   - `dissect` ingest processor + `_simulate?verbose=true`
	//   - zero-downtime scalar-to-array promotion (`f__arr__<name>`) in live Doris
	collapseR13Resp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"sort": [{"latency_ms": "desc"}],
		"collapse": {
			"field": "service",
			"inner_hits": {
				"name": "by_svc",
				"size": 3,
				"sort": [{"latency_ms": "asc"}]
			}
		}
	}`))
	if err != nil || collapseR13Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (collapse inner_hits) failed: status=%v err=%v", collapseR13Resp.StatusCode, err)
	}
	var collapseR13Res map[string]any
	_ = json.NewDecoder(collapseR13Resp.Body).Decode(&collapseR13Res)
	_ = collapseR13Resp.Body.Close()
	cHits := collapseR13Res["hits"].(map[string]any)["hits"].([]any)
	if len(cHits) == 0 {
		t.Fatalf("expected collapsed hits on live_auto_index, got 0")
	}
	firstCollapsed := cHits[0].(map[string]any)
	if _, hasFields := firstCollapsed["fields"].(map[string]any); !hasFields {
		t.Fatalf("expected collapse hit on live Doris to include fields map, got: %+v", firstCollapsed)
	}
	if _, hasIH := firstCollapsed["inner_hits"].(map[string]any); !hasIH {
		t.Fatalf("expected collapse hit on live Doris to include inner_hits, got: %+v", firstCollapsed)
	}

	simR13Resp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate?verbose=true", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{"dissect": {"field": "raw", "pattern": "%{ip} %{method} %{path}"}}
			]
		},
		"docs": [{"_index": "live_auto_index", "_id": "sim-r13", "_source": {"raw": "10.0.0.1 GET /health"}}]
	}`))
	if err != nil || simR13Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate?verbose=true (R13 dissect) failed: status=%v err=%v", simR13Resp.StatusCode, err)
	}
	var simR13Res map[string]any
	_ = json.NewDecoder(simR13Resp.Body).Decode(&simR13Res)
	_ = simR13Resp.Body.Close()
	simR13Docs := simR13Res["docs"].([]any)
	if _, hasProcResults := simR13Docs[0].(map[string]any)["processor_results"].([]any); !hasProcResults {
		t.Fatalf("expected processor_results in verbose _simulate response, got: %+v", simR13Docs[0])
	}

	// 15. Verify Round-14 features on live Doris:
	//   - `collapse` + `search_after` keyset pagination on outer `_collapsed` subquery
	//   - `dissect` `/N` append ordering & reference-only keys (`%{*r1}=%{&r1}`) + array `convert`/`gsub`
	collapsePage2Resp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"size": 1,
		"sort": [{"latency_ms": "desc"}],
		"search_after": [999999],
		"collapse": {
			"field": "service",
			"inner_hits": {
				"name": "by_svc",
				"size": 3,
				"sort": [{"latency_ms": "asc"}]
			}
		}
	}`))
	if err != nil || collapsePage2Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (collapse + search_after) failed: status=%v err=%v", collapsePage2Resp.StatusCode, err)
	}
	var collapsePage2Res map[string]any
	_ = json.NewDecoder(collapsePage2Resp.Body).Decode(&collapsePage2Res)
	_ = collapsePage2Resp.Body.Close()
	if len(collapsePage2Res["hits"].(map[string]any)["hits"].([]any)) == 0 {
		t.Fatalf("expected collapsed hits with search_after on live_auto_index, got 0")
	}

	simR14Resp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{"dissect": {"field": "raw", "pattern": "%{*k}=%{&k} %{+name/2} %{+name/1}", "append_separator": " "}},
				{"convert": {"field": "nums", "type": "integer"}}
			]
		},
		"docs": [{"_index": "live_auto_index", "_id": "sim-r14", "_source": {"raw": "env=prod Doe Jane", "nums": ["1", "2"]}}]
	}`))
	if err != nil || simR14Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R14 dissect+array convert) failed: status=%v err=%v", simR14Resp.StatusCode, err)
	}
	_ = simR14Resp.Body.Close()

	// 16. Verify Round-15 features on live Doris:
	//   - `script_fields` + `_script` sort + `search_after` with `track_total_hits: true`
	//   - `composite` agg with `order: "desc"`
	//   - New ingest processors (`grok`, `csv`, `uri_parts`, `registered_domain`, `fingerprint`, `redact`)
	r15SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"size": 1,
		"track_total_hits": true,
		"script_fields": {
			"double_lat": {
				"script": {"source": "doc['latency_ms'].value * 2"}
			}
		},
		"sort": [{"latency_ms": {"order": "desc", "missing": "_last"}}],
		"search_after": [999999],
		"aggs": {
			"comp_svc_desc": {
				"composite": {
					"size": 5,
					"sources": [
						{"svc": {"terms": {"field": "service", "order": "desc"}}}
					]
				}
			}
		}
	}`))
	if err != nil || r15SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R15 script_fields + search_after + composite desc) failed: status=%v err=%v", r15SearchResp.StatusCode, err)
	}
	var r15SearchRes map[string]any
	_ = json.NewDecoder(r15SearchResp.Body).Decode(&r15SearchRes)
	_ = r15SearchResp.Body.Close()
	if len(r15SearchRes["hits"].(map[string]any)["hits"].([]any)) == 0 {
		t.Fatalf("expected R15 hits on live_auto_index, got 0")
	}

	simR15Resp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{"grok": {"field": "log", "patterns": ["%{IP:client_ip} %{WORD:method} %{URIPATHPARAM:uri}"]}},
				{"csv": {"field": "csv_row", "target_fields": ["col_a", "col_b"]}},
				{"uri_parts": {"field": "full_url", "target_field": "url_parsed"}},
				{"registered_domain": {"field": "fqdn", "target_field": "reg_dom"}},
				{"redact": {"field": "msg", "patterns": ["%{EMAILADDRESS:EMAIL}"]}},
				{"fingerprint": {"fields": ["client_ip", "method"], "target_field": "fp"}}
			]
		},
		"docs": [{
			"_index": "live_auto_index",
			"_id": "sim-r15",
			"_source": {
				"log": "10.0.0.1 GET /api/v1/items?limit=10",
				"csv_row": "alpha,beta",
				"full_url": "https://sub.example.co.uk:8443/path?x=1#frag",
				"fqdn": "api.sub.example.co.uk",
				"msg": "contact ops@example.com now"
			}
		}]
	}`))
	if err != nil || simR15Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R15 processors) failed: status=%v err=%v", simR15Resp.StatusCode, err)
	}
	_ = simR15Resp.Body.Close()

	// 17. Verify Round-16 features on live Doris:
	//   - `script_score` with `boost` & `min_score`, Painless `while` loop + `Math.*` in `script_fields`, and `sum.script` SQL pushdown
	//   - `COMBINEDAPACHELOG` grok, per-group `redact` tokens, `csv` `trim: true`, and `bytes` IEC `mib`
	r16SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['latency_ms'].value * 2"},
				"min_score": 10,
				"boost": 1.5
			}
		},
		"script_fields": {
			"loop_check": {
				"script": "def i = 1; def acc = 0; while (i <= 3) { acc += i; i++; } return acc + Math.abs(-4);"
			}
		},
		"aggs": {
			"floor_lat_sum": {
				"sum": {
					"script": {"source": "Math.floor(doc['latency_ms'].value)"}
				}
			}
		}
	}`))
	if err != nil || r16SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R16 script_score + while + sum.script) failed: status=%v err=%v", r16SearchResp.StatusCode, err)
	}
	var r16SearchRes map[string]any
	_ = json.NewDecoder(r16SearchResp.Body).Decode(&r16SearchRes)
	_ = r16SearchResp.Body.Close()
	if len(r16SearchRes["hits"].(map[string]any)["hits"].([]any)) == 0 {
		t.Fatalf("expected R16 hits on live_auto_index, got 0")
	}

	simR16Resp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{"grok": {"field": "apache_log", "patterns": ["%{COMBINEDAPACHELOG}"]}},
				{"redact": {"field": "pii", "patterns": ["%{EMAILADDRESS:EMAIL}", "%{IPV4:IP}"]}},
				{"csv": {"field": "csv_line", "target_fields": ["c1", "c2"], "trim": true}},
				{"bytes": {"field": "mem", "target_field": "mem_b"}}
			]
		},
		"docs": [{
			"_index": "live_auto_index",
			"_id": "sim-r16",
			"_source": {
				"apache_log": "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326 \"http://www.example.com/start.html\" \"Mozilla/4.08\"",
				"pii": "user bob@example.com from 192.168.1.10",
				"csv_line": "  hello , \"world\" ",
				"mem": "4mib"
			}
		}]
	}`))
	if err != nil || simR16Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R16 processors) failed: status=%v err=%v", simR16Resp.StatusCode, err)
	}
	_ = simR16Resp.Body.Close()

	// 18. Round-17: Top-level min_score + runtime metric script aggs + /_explain parity + Painless casts/regex
	r17SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"min_score": 1.0,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {
					"source": "doc['latency_ms'].value * 2.0"
				}
			}
		},
		"aggs": {
			"complex_avg": {
				"avg": {
					"script": {
						"source": "int base = (int) doc['latency_ms'].value; return base * 2;"
					}
				}
			}
		}
	}`))
	if err != nil || r17SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R17 min_score + runtime avg script) failed: status=%v err=%v", r17SearchResp.StatusCode, err)
	}
	var r17SearchRes map[string]any
	_ = json.NewDecoder(r17SearchResp.Body).Decode(&r17SearchRes)
	_ = r17SearchResp.Body.Close()
	if len(r17SearchRes["hits"].(map[string]any)["hits"].([]any)) == 0 {
		t.Fatalf("expected R17 hits on live_auto_index, got 0")
	}

	// 19. Round-18: Polymorphic script cardinality/value_count + histogram.script + _update detect_noop & _source retrieval
	r18SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"size": 0,
		"aggs": {
			"svc_card": {
				"cardinality": {
					"script": "doc['service'].value"
				}
			},
			"lat_hist_script": {
				"histogram": {
					"script": "doc['latency_ms'].value * 2",
					"interval": 20
				}
			}
		}
	}`))
	if err != nil || r18SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R18 polymorphic script cardinality + histogram.script) failed: status=%v err=%v", r18SearchResp.StatusCode, err)
	}
	var r18SearchRes map[string]any
	_ = json.NewDecoder(r18SearchResp.Body).Decode(&r18SearchRes)
	_ = r18SearchResp.Body.Close()
	r18Aggs, _ := r18SearchRes["aggregations"].(map[string]any)
	if r18Aggs == nil || r18Aggs["svc_card"].(map[string]any)["value"] == float64(0) {
		t.Fatalf("expected non-zero R18 svc_card on live_auto_index, got %+v", r18Aggs)
	}

	r18UpdResp, err := http.Post(ts.URL+"/live_auto_index/_update/auto-1?refresh=true&_source=true", "application/json", strings.NewReader(`{
		"doc": {"service": "checkout"}
	}`))
	if err != nil || r18UpdResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_update/auto-1 (R18 detect_noop + _source) failed: status=%v err=%v", r18UpdResp.StatusCode, err)
	}
	var r18UpdRes map[string]any
	_ = json.NewDecoder(r18UpdResp.Body).Decode(&r18UpdRes)
	_ = r18UpdResp.Body.Close()
	if r18UpdRes["get"] == nil {
		t.Fatalf("expected R18 _update?_source=true to include get._source, got %+v", r18UpdRes)
	}

	// 20. Round-19: Polymorphic string script pushdown (.toLowerCase/.trim/CONCAT), _script sort search_after & missing, and terminate_after
	r19SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search?terminate_after=2", "application/json", strings.NewReader(`{
		"size": 1,
		"sort": [
			{"_script": {"type": "number", "script": "doc['latency_ms'].value * 2", "order": "asc", "missing": -1}},
			{"_id": "asc"}
		],
		"aggs": {
			"svc_norm": {
				"terms": {
					"script": "doc['service'].value.trim().toLowerCase()"
				}
			}
		}
	}`))
	if err != nil || r19SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R19 string script pushdown + _script sort + terminate_after) failed: status=%v err=%v", r19SearchResp.StatusCode, err)
	}
	var r19SearchRes map[string]any
	_ = json.NewDecoder(r19SearchResp.Body).Decode(&r19SearchRes)
	_ = r19SearchResp.Body.Close()
	r19Aggs, _ := r19SearchRes["aggregations"].(map[string]any)
	if r19Aggs == nil || len(r19Aggs["svc_norm"].(map[string]any)["buckets"].([]any)) == 0 {
		t.Fatalf("expected non-empty R19 svc_norm buckets on live_auto_index, got %+v", r19Aggs)
	}

	// 21. Round-20: _script sort SQL pushdown, track_scores: true, unary +/-/! query_string with boost, and top-level anonymous filters agg
	r20SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"track_scores": true,
		"query": {
			"query_string": {
				"query": "+service:checkout -service:nonexistent",
				"boost": 2.5
			}
		},
		"sort": [
			{"_script": {"type": "number", "script": "doc['latency_ms'].value * 3", "order": "desc"}}
		],
		"aggs": {
			"anon_f": {
				"filters": {
					"filters": [
						{"term": {"service": "checkout"}},
						{"term": {"service": "missing"}}
					]
				}
			}
		}
	}`))
	if err != nil || r20SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R20 track_scores + query_string + anonymous filters) failed: status=%v err=%v", r20SearchResp.StatusCode, err)
	}
	var r20SearchRes map[string]any
	_ = json.NewDecoder(r20SearchResp.Body).Decode(&r20SearchRes)
	_ = r20SearchResp.Body.Close()
	r20Hits := r20SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r20Hits) == 0 || r20Hits[0].(map[string]any)["_score"] == nil {
		t.Fatalf("expected non-empty R20 hits with non-null _score when track_scores=true, got %+v", r20Hits)
	}
	r20Aggs, _ := r20SearchRes["aggregations"].(map[string]any)
	if r20Aggs == nil {
		t.Fatalf("expected R20 aggregations, got nil")
	}
	if _, ok := r20Aggs["anon_f"].(map[string]any)["buckets"].([]any); !ok {
		t.Fatalf("expected R20 anon_f.buckets array, got %T %+v", r20Aggs["anon_f"], r20Aggs["anon_f"])
	}

	// 22. Round-21: rescore, post_filter aggregation isolation, cumulative_cardinality, and GET _seq_no/_primary_term
	r21SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {"match_all": {}},
		"post_filter": {"term": {"service": "checkout"}},
		"rescore": {
			"window_size": 10,
			"query": {
				"rescore_query": {"term": {"service": "checkout"}},
				"query_weight": 1.0,
				"rescore_query_weight": 3.0,
				"score_mode": "total"
			}
		},
		"aggs": {
			"by_lat": {
				"histogram": {"field": "latency_ms", "interval": 50},
				"aggs": {
					"svc_card": {"cardinality": {"field": "service"}},
					"cum_svc": {"cumulative_cardinality": {"buckets_path": "svc_card"}}
				}
			}
		}
	}`))
	if err != nil || r21SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R21 rescore + post_filter + cumulative_cardinality) failed: status=%v err=%v", r21SearchResp.StatusCode, err)
	}
	var r21SearchRes map[string]any
	_ = json.NewDecoder(r21SearchResp.Body).Decode(&r21SearchRes)
	_ = r21SearchResp.Body.Close()
	r21Hits := r21SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r21Hits) == 0 || r21Hits[0].(map[string]any)["_score"].(float64) <= 1.0 {
		t.Fatalf("expected R21 rescored hits with _score > 1.0, got %+v", r21Hits)
	}
	r21GetResp, err := http.Get(ts.URL + "/live_auto_index/_doc/auto-1")
	if err != nil || r21GetResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /live_auto_index/_doc/auto-1 failed: status=%v err=%v", r21GetResp.StatusCode, err)
	}
	var r21GetRes map[string]any
	_ = json.NewDecoder(r21GetResp.Body).Decode(&r21GetRes)
	_ = r21GetResp.Body.Close()
	if r21GetRes["_seq_no"] == nil || r21GetRes["_primary_term"] != float64(1) {
		t.Fatalf("expected R21 GET response to include _seq_no and _primary_term=1, got %+v", r21GetRes)
	}

	// 23. Round-22: simple_query_string colon & unspaced operator handling, rescore before collapse, and pipeline agg over keyed filters
	r22SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {
			"simple_query_string": {
				"fields": ["service"],
				"query": "checkout|payments"
			}
		},
		"collapse": {"field": "service"},
		"rescore": {
			"window_size": 10,
			"query": {
				"rescore_query": {"term": {"service": "checkout"}},
				"query_weight": 1.0,
				"rescore_query_weight": 2.0
			}
		},
		"aggs": {
			"by_svc_filters": {
				"filters": {
					"filters": {
						"co": {"term": {"service": "checkout"}}
					}
				},
				"aggs": {
					"lat_stats": {"stats": {"field": "latency_ms"}}
				}
			},
			"max_filter_lat": {
				"max_bucket": {"buckets_path": "by_svc_filters>lat_stats.max"}
			}
		}
	}`))
	if err != nil || r22SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R22 simple_query_string + rescore+collapse + keyed filters pipeline agg) failed: status=%v err=%v", r22SearchResp.StatusCode, err)
	}
	var r22SearchRes map[string]any
	_ = json.NewDecoder(r22SearchResp.Body).Decode(&r22SearchRes)
	_ = r22SearchResp.Body.Close()
	r22Hits := r22SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r22Hits) == 0 {
		t.Fatalf("expected R22 collapsed hits on live_auto_index, got 0")
	}
	r22Aggs, _ := r22SearchRes["aggregations"].(map[string]any)
	if r22Aggs == nil || r22Aggs["max_filter_lat"] == nil {
		t.Fatalf("expected R22 max_filter_lat pipeline agg result, got %+v", r22Aggs)
	}

	// 24. Round-23: simple_query_string AND+OR+negation, Painless bitwise/Java11 script_fields, UTF-8 highlight, and statement-block bucket_script
	r23SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {
			"simple_query_string": {
				"fields": ["service"],
				"query": "checkout | payments -forbidden",
				"default_operator": "AND"
			}
		},
		"highlight": {
			"number_of_fragments": 1,
			"fields": {
				"service": {}
			}
		},
		"script_fields": {
			"bw_shift": {"script": "64 >> 2 >> 1"},
			"j11_str":  {"script": "'  ok  '.strip().repeat(2)"}
		},
		"aggs": {
			"by_svc": {
				"terms": {"field": "service"},
				"aggs": {
					"lat_sum": {"sum": {"field": "latency_ms"}},
					"lat_sqrt": {
						"bucket_script": {
							"buckets_path": {"s": "lat_sum"},
							"script": "double v = params.s; return Math.round(Math.sqrt(v));"
						}
					}
				}
			}
		}
	}`))
	if err != nil || r23SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R23 simple_query_string + script_fields + highlight + bucket_script) failed: status=%v err=%v", r23SearchResp.StatusCode, err)
	}
	var r23SearchRes map[string]any
	_ = json.NewDecoder(r23SearchResp.Body).Decode(&r23SearchRes)
	_ = r23SearchResp.Body.Close()
	r23Hits := r23SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r23Hits) == 0 {
		t.Fatalf("expected R23 hits on live_auto_index, got 0")
	}
	r23Fields, _ := r23Hits[0].(map[string]any)["fields"].(map[string]any)
	if r23Fields == nil || r23Fields["bw_shift"].([]any)[0] != float64(8) || r23Fields["j11_str"].([]any)[0] != "okok" {
		t.Fatalf("unexpected R23 script_fields on live_auto_index: %+v", r23Fields)
	}

	// 25. Round-24 through Round-28: enrich policy lifecycle, fuzzy edit-distance search, scripted_metric, and Painless Instant/Comparator/live _score
	r28UsersPutReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/live_users_r28/_doc/u1?refresh=true", strings.NewReader(`{"email":"alice@example.com","tier":"enterprise","region":"us-east"}`))
	r28UsersPutReq.Header.Set("Content-Type", "application/json")
	r28UsersPutResp, err := http.DefaultClient.Do(r28UsersPutReq)
	if err != nil || (r28UsersPutResp.StatusCode != http.StatusCreated && r28UsersPutResp.StatusCode != http.StatusOK) {
		t.Fatalf("PUT /live_users_r28/_doc/u1 failed: status=%v err=%v", r28UsersPutResp.StatusCode, err)
	}
	_ = r28UsersPutResp.Body.Close()

	r28PolPutReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/_enrich/policy/r28-users-pol", strings.NewReader(`{
		"match": {
			"indices": "live_users_r28",
			"match_field": "email",
			"enrich_fields": ["tier"]
		}
	}`))
	r28PolPutReq.Header.Set("Content-Type", "application/json")
	r28PolPutResp, err := http.DefaultClient.Do(r28PolPutReq)
	if err != nil || r28PolPutResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /_enrich/policy/r28-users-pol failed: status=%v err=%v", r28PolPutResp.StatusCode, err)
	}
	_ = r28PolPutResp.Body.Close()

	r28PolExecResp, err := http.Post(ts.URL+"/_enrich/policy/r28-users-pol/_execute", "application/json", strings.NewReader(`{}`))
	if err != nil || r28PolExecResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_enrich/policy/r28-users-pol/_execute failed: status=%v err=%v", r28PolExecResp.StatusCode, err)
	}
	_ = r28PolExecResp.Body.Close()

	r28SimResp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{
					"enrich": {
						"policy_name": "r28-users-pol",
						"field": "user_email",
						"target_field": "account"
					}
				},
				{
					"community_id": {
						"source_ip": "10.0.0.1",
						"destination_ip": "10.0.0.2",
						"source_port": "443",
						"destination_port": "51234",
						"transport": "tcp",
						"target_field": "net.cid"
					}
				}
			]
		},
		"docs": [
			{"_index": "live_auto_index", "_id": "sim-1", "_source": {"user_email": "alice@example.com", "10.0.0.1": "10.0.0.1", "10.0.0.2": "10.0.0.2", "443": 443, "51234": 51234, "tcp": "tcp"}}
		]
	}`))
	if err != nil || r28SimResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R28 enrich + community_id) failed: status=%v err=%v", r28SimResp.StatusCode, err)
	}
	var r28SimRes map[string]any
	_ = json.NewDecoder(r28SimResp.Body).Decode(&r28SimRes)
	_ = r28SimResp.Body.Close()
	r28SimDoc := r28SimRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	r28Acc, _ := r28SimDoc["account"].(map[string]any)
	if r28Acc == nil || r28Acc["tier"] != "enterprise" || r28Acc["region"] != nil {
		t.Fatalf("expected R28 enrich account.tier=enterprise without unrequested region, got %+v", r28Acc)
	}

	r28SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {
			"fuzzy": {
				"service": {
					"value": "checkouX",
					"fuzziness": 1
				}
			}
		},
		"script_fields": {
			"live_score": {"script": "_score * 2"},
			"epoch_sec":  {"script": "Instant.ofEpochMilli(1700000000000L).getEpochSecond()"},
			"sorted_arr": {"script": "def a = [3, 1, 2]; a.sort(Comparator.naturalOrder()); return a;"}
		},
		"aggs": {
			"custom_sm": {
				"scripted_metric": {
					"init_script": "state.sum = 0; state.cnt = 0;",
					"map_script": "state.sum += doc['latency_ms'].value; state.cnt += 1;",
					"combine_script": "return ['sum': state.sum, 'cnt': state.cnt];",
					"reduce_script": "double s = 0; int c = 0; for (st in states) { s += st.sum; c += st.cnt; } return ['total': s, 'count': c];"
				}
			}
		}
	}`))
	if err != nil || r28SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R24-R28 fuzzy + scripted_metric + Painless) failed: status=%v err=%v", r28SearchResp.StatusCode, err)
	}
	var r28SearchRes map[string]any
	_ = json.NewDecoder(r28SearchResp.Body).Decode(&r28SearchRes)
	_ = r28SearchResp.Body.Close()
	r28Hits := r28SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r28Hits) == 0 {
		t.Fatalf("expected R28 fuzzy search hits on live_auto_index, got 0")
	}
	r28Fields, _ := r28Hits[0].(map[string]any)["fields"].(map[string]any)
	if r28Fields == nil || r28Fields["epoch_sec"].([]any)[0] != float64(1700000000) {
		t.Fatalf("unexpected R28 script_fields on live_auto_index: %+v", r28Fields)
	}
	r28SmVal, _ := r28SearchRes["aggregations"].(map[string]any)["custom_sm"].(map[string]any)["value"].(map[string]any)
	if r28SmVal == nil || r28SmVal["count"].(float64) < 1 {
		t.Fatalf("unexpected R28 scripted_metric value: %+v", r28SmVal)
	}

	// 26. Round-29: Lucene field:[* TO *] / *:* exists, ids boost, date_histogram -> terms -> cumulative_sum + bucket_sort, foreach+script ingest, and Painless generic types / shift compound assignments
	r29SimResp, err := http.Post(ts.URL+"/_ingest/pipeline/_simulate", "application/json", strings.NewReader(`{
		"pipeline": {
			"processors": [
				{
					"foreach": {
						"field": "tags",
						"processor": {
							"script": {
								"source": "ctx._ingest._value.processed = true;"
							}
						}
					}
				}
			]
		},
		"docs": [
			{"_index": "live_auto_index", "_id": "r29-1", "_source": {"tags": [{"k": "a"}, {"k": "b"}]}}
		]
	}`))
	if err != nil || r29SimResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_ingest/pipeline/_simulate (R29 foreach+script) failed: status=%v err=%v", r29SimResp.StatusCode, err)
	}
	var r29SimRes map[string]any
	_ = json.NewDecoder(r29SimResp.Body).Decode(&r29SimRes)
	_ = r29SimResp.Body.Close()
	r29Tags := r29SimRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)["tags"].([]any)
	if r29Tags[0].(map[string]any)["processed"] != true || r29Tags[1].(map[string]any)["processed"] != true {
		t.Fatalf("expected R29 foreach+script in-place mutation on tags, got %+v", r29Tags)
	}

	r29SearchResp, err := http.Post(ts.URL+"/live_auto_index/_search", "application/json", strings.NewReader(`{
		"query": {
			"bool": {
				"must": [
					{"query_string": {"query": "latency_ms:[* TO *] AND *:*"}},
					{"ids": {"values": ["auto-1", "auto-2", "auto-3"], "boost": 2.5}}
				]
			}
		},
		"script_fields": {
			"shift_and_generic": {
				"script": "List<String> items = ['x', 'y']; int x = 3; x <<= 2; String label; label = items.get(0) + ':' + x; return label;"
			}
		},
		"aggs": {
			"by_day": {
				"date_histogram": {
					"field": "created_at",
					"calendar_interval": "1d"
				},
				"aggs": {
					"by_svc": {
						"terms": {
							"field": "service",
							"order": {"_key": "asc"}
						},
						"aggs": {
							"sum_lat": {"sum": {"field": "latency_ms"}},
							"cum_lat": {"cumulative_sum": {"buckets_path": "sum_lat"}},
							"page": {"bucket_sort": {"from": 0, "size": 5}}
						}
					}
				}
			}
		}
	}`))
	if err != nil || r29SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /live_auto_index/_search (R29) failed: status=%v err=%v", r29SearchResp.StatusCode, err)
	}
	var r29SearchRes map[string]any
	_ = json.NewDecoder(r29SearchResp.Body).Decode(&r29SearchRes)
	_ = r29SearchResp.Body.Close()
	r29Hits := r29SearchRes["hits"].(map[string]any)["hits"].([]any)
	if len(r29Hits) == 0 {
		t.Fatalf("expected R29 search hits on live_auto_index, got 0")
	}
	r29Fields, _ := r29Hits[0].(map[string]any)["fields"].(map[string]any)
	if r29Fields == nil || r29Fields["shift_and_generic"].([]any)[0] != "x:12" {
		t.Fatalf("expected R29 script_fields shift_and_generic='x:12', got %+v", r29Fields)
	}
}
