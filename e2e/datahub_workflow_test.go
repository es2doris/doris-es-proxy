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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestDataHubFullWorkflow_IndexTemplates_MultiIndexSearch_Aggregations_E2E(t *testing.T) {
	backend := NewMemDorisBackend()
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Step 1: DataHub registers an index template (`PUT /_index_template/datahub_entity_template`)
	tplJSON := `{
		"index_patterns": ["*index_v2"],
		"template": {
			"mappings": {
				"properties": {
					"urn": {"type": "keyword"},
					"name": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"}}},
					"platform": {"type": "keyword"},
					"origin": {"type": "keyword"},
					"removed": {"type": "boolean"},
					"customProperties": {"type": "keyword"},
					"owners": {"type": "keyword"},
					"rowCount": {"type": "long"}
				}
			}
		}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/_index_template/datahub_entity_template", strings.NewReader(tplJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /_index_template failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 2: Create `datasetindex_v2` and `dashboardindex_v2` (inheriting mappings from template)
	for _, idxName := range []string{"datasetindex_v2", "dashboardindex_v2"} {
		req, _ = http.NewRequest(http.MethodPut, ts.URL+"/"+idxName, strings.NewReader(`{}`))
		resp, err = http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT /%s failed: status=%v err=%v", idxName, resp.StatusCode, err)
		}
		_ = resp.Body.Close()
	}

	// Step 3: Index DataHub dataset and dashboard documents via `/_bulk`
	bulkDocs := strings.Join([]string{
		`{"index":{"_index":"datasetindex_v2","_id":"urn:li:dataset:(urn:li:dataPlatform:snowflake,fct_revenue,PROD)"}}`,
		`{"urn":"urn:li:dataset:(urn:li:dataPlatform:snowflake,fct_revenue,PROD)","name":"fct_revenue","platform":"snowflake","origin":"PROD","removed":false,"customProperties":["env=prod","team=finance"],"owners":["urn:li:corpuser:alice"],"rowCount":1500000}`,
		`{"index":{"_index":"datasetindex_v2","_id":"urn:li:dataset:(urn:li:dataPlatform:bigquery,dim_customers,PROD)"}}`,
		`{"urn":"urn:li:dataset:(urn:li:dataPlatform:bigquery,dim_customers,PROD)","name":"dim_customers","platform":"bigquery","origin":"PROD","removed":false,"customProperties":["env=prod","pii=true"],"owners":["urn:li:corpuser:bob"],"rowCount":500000}`,
		`{"index":{"_index":"dashboardindex_v2","_id":"urn:li:dashboard:(looker,exec_revenue)"}}`,
		`{"urn":"urn:li:dashboard:(looker,exec_revenue)","name":"Executive Revenue Dashboard","platform":"looker","origin":"PROD","removed":false,"customProperties":["env=prod","team=finance"],"owners":["urn:li:corpuser:alice"],"rowCount":0}`,
		"",
	}, "\n")
	resp, err = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulkDocs))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 4: Multi-index wildcard search across `/*index_v2/_search` with `query_string` wildcard + `prefix` on array + `cardinality` & `sum` metric aggs
	searchJSON := `{
		"from": 0,
		"size": 10,
		"query": {
			"bool": {
				"must": [
					{
						"query_string": {
							"query": "*revenue*",
							"fields": ["name"]
						}
					}
				],
				"filter": [
					{"term": {"removed": false}},
					{"prefix": {"customProperties": "team="}}
				]
			}
		},
		"aggs": {
			"platforms": {"terms": {"field": "platform", "size": 10}},
			"unique_platforms": {"cardinality": {"field": "platform"}},
			"total_rows": {"sum": {"field": "rowCount"}}
		}
	}`
	resp, err = http.Post(ts.URL+"/*index_v2/_search", "application/json", strings.NewReader(searchJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /*index_v2/_search failed: status=%v err=%v", resp.StatusCode, err)
	}
	var searchRes map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&searchRes); err != nil {
		t.Fatalf("failed to decode DataHub search response: %v", err)
	}
	_ = resp.Body.Close()

	hitsObj := searchRes["hits"].(map[string]any)
	totalHits := int(hitsObj["total"].(map[string]any)["value"].(float64))
	if totalHits != 2 {
		t.Fatalf("expected 2 multi-index hits matching *revenue* across datasetindex_v2 & dashboardindex_v2, got %d: %+v", totalHits, hitsObj)
	}

	aggsObj := searchRes["aggregations"].(map[string]any)
	uniqPlat := int(aggsObj["unique_platforms"].(map[string]any)["value"].(float64))
	if uniqPlat != 2 {
		t.Errorf("expected unique_platforms cardinality = 2 (snowflake, looker), got %d", uniqPlat)
	}
	totalRows := aggsObj["total_rows"].(map[string]any)["value"].(float64)
	if totalRows != 1500000 {
		t.Errorf("expected total_rows sum = 1500000, got %v", totalRows)
	}
}

func TestV02ExplainPaginationAggsAndStatelessCatalog_E2E(t *testing.T) {
	backend := NewMemDorisBackend()
	srv1 := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	if err := srv1.BootstrapCatalog(context.Background()); err != nil {
		t.Fatalf("BootstrapCatalog on srv1 failed: %v", err)
	}
	ts1 := httptest.NewServer(srv1.Handler())
	defer ts1.Close()

	// 1. Create index with timestamp (`date`), rowCount (`long`), and alias `usage_alias`
	createJSON := `{
		"aliases": {"usage_alias": {}},
		"mappings": {
			"properties": {
				"eventId": {"type": "keyword"},
				"platform": {"type": "keyword"},
				"timestampMillis": {"type": "date"},
				"latencyMs": {"type": "double"},
				"rowCount": {"type": "long"}
			}
		}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts1.URL+"/datahub_usage_event_v1", strings.NewReader(createJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /datahub_usage_event_v1 failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 2. Bulk ingest 4 events across 2 hours and 2 platforms
	bulkPayload := strings.Join([]string{
		`{"index":{"_index":"usage_alias","_id":"ev-1"}}`,
		`{"eventId":"ev-1","platform":"snowflake","timestampMillis":1700000000000,"latencyMs":12.5,"rowCount":100}`,
		`{"index":{"_index":"usage_alias","_id":"ev-2"}}`,
		`{"eventId":"ev-2","platform":"snowflake","timestampMillis":1700000600000,"latencyMs":28.0,"rowCount":250}`,
		`{"index":{"_index":"usage_alias","_id":"ev-3"}}`,
		`{"eventId":"ev-3","platform":"bigquery","timestampMillis":1700003600000,"latencyMs":65.0,"rowCount":600}`,
		`{"index":{"_index":"usage_alias","_id":"ev-4"}}`,
		`{"eventId":"ev-4","platform":"doris","timestampMillis":1700003700000,"latencyMs":8.0,"rowCount":1200}`,
		"",
	}, "\n")
	resp, err = http.Post(ts1.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulkPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 3. Simulate stateless proxy pod restart: spin up a brand new Server instance (`srv2`) on the same backend
	srv2 := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	if err := srv2.BootstrapCatalog(context.Background()); err != nil {
		t.Fatalf("BootstrapCatalog on srv2 failed: %v", err)
	}
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	// 4. Verify `/_field_caps` on the restarted server via the persisted alias `usage_alias`
	resp, err = http.Get(ts2.URL + "/usage_alias/_field_caps?fields=*")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /usage_alias/_field_caps failed: status=%v err=%v", resp.StatusCode, err)
	}
	var capsRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&capsRes)
	_ = resp.Body.Close()
	fieldsMap, _ := capsRes["fields"].(map[string]any)
	if _, ok := fieldsMap["timestampMillis"]; !ok {
		t.Fatalf("expected timestampMillis in _field_caps after restart, got: %+v", capsRes)
	}

	// 5. Verify `POST /usage_alias/_doris/explain` and `?doris_explain=true` with `date_histogram`, `histogram`, `range`, and `value_count`
	aggQuery := `{
		"size": 2,
		"sort": [{"timestampMillis": "asc"}, {"_id": "asc"}],
		"aggs": {
			"events_over_time": {
				"date_histogram": {"field": "timestampMillis", "fixed_interval": "1h"}
			},
			"latency_hist": {
				"histogram": {"field": "latencyMs", "interval": 25}
			},
			"row_ranges": {
				"range": {
					"field": "rowCount",
					"ranges": [
						{"key": "small", "to": 500},
						{"key": "large", "from": 500}
					]
				}
			},
			"event_count": {
				"value_count": {"field": "rowCount"}
			}
		}
	}`
	resp, err = http.Post(ts2.URL+"/usage_alias/_doris/explain", "application/json", strings.NewReader(aggQuery))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /usage_alias/_doris/explain failed: status=%v err=%v", resp.StatusCode, err)
	}
	var explainRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&explainRes)
	_ = resp.Body.Close()
	if !strings.Contains(explainRes["hits_sql"].(string), "f__timestampMillis") {
		t.Fatalf("expected explain hits_sql to use promoted f__timestampMillis column after restart, got: %v", explainRes["hits_sql"])
	}

	// Execute the search with `?doris_explain=true`
	resp, err = http.Post(ts2.URL+"/usage_alias/_search?doris_explain=true", "application/json", strings.NewReader(aggQuery))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /usage_alias/_search?doris_explain=true failed: status=%v err=%v", resp.StatusCode, err)
	}
	var page1 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&page1)
	_ = resp.Body.Close()
	if _, ok := page1["_doris_explain"].(map[string]any); !ok {
		t.Fatalf("expected _doris_explain block in search response")
	}

	aggs := page1["aggregations"].(map[string]any)
	ehBuckets := aggs["events_over_time"].(map[string]any)["buckets"].([]any)
	if len(ehBuckets) != 2 {
		t.Fatalf("expected 2 hourly date_histogram buckets, got %d: %+v", len(ehBuckets), ehBuckets)
	}
	rrBuckets := aggs["row_ranges"].(map[string]any)["buckets"].([]any)
	if len(rrBuckets) != 2 || int(rrBuckets[0].(map[string]any)["doc_count"].(float64)) != 2 || int(rrBuckets[1].(map[string]any)["doc_count"].(float64)) != 2 {
		t.Fatalf("expected 2 docs in small (<500) and 2 docs in large (>=500) range buckets, got: %+v", rrBuckets)
	}
	if int(aggs["event_count"].(map[string]any)["value"].(float64)) != 4 {
		t.Fatalf("expected event_count value_count = 4, got %v", aggs["event_count"])
	}

	// 6. Test `search_after` keyset pagination using `sort` values from page1's last hit
	p1Hits := page1["hits"].(map[string]any)["hits"].([]any)
	if len(p1Hits) != 2 {
		t.Fatalf("expected 2 hits on page 1, got %d", len(p1Hits))
	}
	lastSort := p1Hits[1].(map[string]any)["sort"].([]any)
	sortBytes, _ := json.Marshal(lastSort)
	page2Query := `{
		"size": 2,
		"sort": [{"timestampMillis": "asc"}, {"_id": "asc"}],
		"search_after": ` + string(sortBytes) + `
	}`
	resp, err = http.Post(ts2.URL+"/usage_alias/_search", "application/json", strings.NewReader(page2Query))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /usage_alias/_search (search_after) failed: status=%v err=%v", resp.StatusCode, err)
	}
	var page2 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&page2)
	_ = resp.Body.Close()
	p2Hits := page2["hits"].(map[string]any)["hits"].([]any)
	if len(p2Hits) != 2 || p2Hits[0].(map[string]any)["_id"] != "ev-3" || p2Hits[1].(map[string]any)["_id"] != "ev-4" {
		t.Fatalf("expected page 2 via search_after to return [ev-3, ev-4], got: %+v", p2Hits)
	}

	// 7. Test stateless `scroll` pagination (`POST /usage_alias/_search?scroll=1m` -> `POST /_search/scroll`)
	resp, err = http.Post(ts2.URL+"/usage_alias/_search?scroll=1m", "application/json", strings.NewReader(`{"size": 2}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /usage_alias/_search?scroll=1m failed: status=%v err=%v", resp.StatusCode, err)
	}
	var scrollPage1 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&scrollPage1)
	_ = resp.Body.Close()
	scrollID, _ := scrollPage1["_scroll_id"].(string)
	if scrollID == "" || scrollID == "doris-scroll-eof" {
		t.Fatalf("expected valid _scroll_id on scroll page 1, got %q", scrollID)
	}
	resp, err = http.Post(ts2.URL+"/_search/scroll", "application/json", strings.NewReader(`{"scroll":"1m","scroll_id":"`+scrollID+`"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_search/scroll failed: status=%v err=%v", resp.StatusCode, err)
	}
	var scrollPage2 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&scrollPage2)
	_ = resp.Body.Close()
	sp2Hits := scrollPage2["hits"].(map[string]any)["hits"].([]any)
	if len(sp2Hits) != 2 {
		t.Fatalf("expected 2 hits on scroll page 2, got %d: %+v", len(sp2Hits), sp2Hits)
	}

	// 8. Test `collapse` (field collapsing on `platform` -> 3 distinct platforms out of 4 events)
	collapseQuery := `{
		"size": 10,
		"collapse": {"field": "platform"},
		"sort": [{"rowCount": "desc"}]
	}`
	resp, err = http.Post(ts2.URL+"/usage_alias/_search", "application/json", strings.NewReader(collapseQuery))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /usage_alias/_search (collapse) failed: status=%v err=%v", resp.StatusCode, err)
	}
	var collapseRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&collapseRes)
	_ = resp.Body.Close()
	cHits := collapseRes["hits"].(map[string]any)["hits"].([]any)
	if len(cHits) != 3 {
		t.Fatalf("expected 3 collapsed hits (1 per distinct platform), got %d: %+v", len(cHits), cHits)
	}
}

func TestV03SecurityGzipSubAggsShadowSlowlogAndEcosystem_E2E(t *testing.T) {
	backend := NewMemDorisBackend()

	// Spin up Replica 1 and Replica 2 sharing the same Doris backend (without calling BootstrapCatalog on Replica 2 after Replica 1 creates indices/aliases)
	replica1 := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	_ = replica1.BootstrapCatalog(context.Background())
	ts1 := httptest.NewServer(replica1.Handler())
	defer ts1.Close()

	replica2 := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	_ = replica2.BootstrapCatalog(context.Background())
	// Configure Replica 2 to shadow-verify against Replica 1!
	replica2.SetShadowESURL(ts1.URL)
	ts2 := httptest.NewServer(replica2.Handler())
	defer ts2.Close()

	// 1. Verify OPTIONS preflight & CORS headers for browser GUIs (Elasticvue, Cerebro, Kibana)
	optReq, _ := http.NewRequest(http.MethodOptions, ts2.URL+"/logs_alias/_search", nil)
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil || optResp.StatusCode != http.StatusOK {
		t.Fatalf("OPTIONS preflight failed: status=%v err=%v", optResp.StatusCode, err)
	}
	if optResp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin: *, got %q", optResp.Header.Get("Access-Control-Allow-Origin"))
	}
	_ = optResp.Body.Close()

	// 2. Create `logs_v1` with alias `logs_alias` on Replica 1
	createJSON := `{
		"aliases": {"logs_alias": {}},
		"mappings": {
			"properties": {
				"service": {"type": "keyword"},
				"level": {"type": "keyword"},
				"latencyMs": {"type": "double"},
				"timestampMillis": {"type": "date"}
			}
		}
	}`
	putReq, _ := http.NewRequest(http.MethodPut, ts1.URL+"/logs_v1", strings.NewReader(createJSON))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil || putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /logs_v1 on Replica 1 failed: status=%v err=%v", putResp.StatusCode, err)
	}
	_ = putResp.Body.Close()

	// 3. Send GZIP-compressed `/_bulk` (`Content-Encoding: gzip`) directly to Replica 2 targeting `logs_alias`
	// Replica 2 must sync `_es_catalog` on alias miss and route to `logs_v1` (without creating an empty `logs_alias` table!)
	bulkNDJSON := strings.Join([]string{
		`{"index":{"_index":"logs_alias","_id":"log-1"}}`,
		`{"service":"checkout","level":"ERROR","latencyMs":120.0,"timestampMillis":1700000000000,"unindexedEnv":"prod"}`,
		`{"index":{"_index":"logs_alias","_id":"log-2"}}`,
		`{"service":"checkout","level":"INFO","latencyMs":40.0,"timestampMillis":1700000600000,"unindexedEnv":"prod"}`,
		`{"index":{"_index":"logs_alias","_id":"log-3"}}`,
		`{"service":"payments","level":"ERROR","latencyMs":300.0,"timestampMillis":1700003600000,"unindexedEnv":"staging"}`,
		"",
	}, "\n")
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, _ = gzw.Write([]byte(bulkNDJSON))
	_ = gzw.Close()

	bulkReq, _ := http.NewRequest(http.MethodPost, ts2.URL+"/_bulk?refresh=true", &gzBuf)
	bulkReq.Header.Set("Content-Encoding", "gzip")
	bulkReq.Header.Set("Accept-Encoding", "gzip")
	bulkReq.Header.Set("Content-Type", "application/x-ndjson")
	bulkResp, err := http.DefaultClient.Do(bulkReq)
	if err != nil || bulkResp.StatusCode != http.StatusOK {
		t.Fatalf("gzip POST /_bulk to Replica 2 failed: status=%v err=%v", bulkResp.StatusCode, err)
	}
	if bulkResp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip-compressed response when Accept-Encoding: gzip is set, got %q", bulkResp.Header.Get("Content-Encoding"))
	}
	gzr, err := gzip.NewReader(bulkResp.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	decompressedBulk, _ := io.ReadAll(gzr)
	_ = gzr.Close()
	_ = bulkResp.Body.Close()
	if !bytes.Contains(decompressedBulk, []byte(`"errors":false`)) {
		t.Fatalf("expected errors:false in decompressed bulk response, got: %s", string(decompressedBulk))
	}

	// 4. Query `logs_alias` on Replica 2 with:
	// - dynamic VARIANT filter (`unindexedEnv: "prod"`) to trigger Auto-Indexing Advisor
	// - string `value_count` aggregation on `service`
	// - `stats` and `percentiles` on `latencyMs`
	// - `filters` aggregation (`errors` vs `infos`)
	// - Bucket Sub-Aggregations (`by_service` -> `avg_latency` + `by_level`)
	// - `?shadow_sync=true` to verify dual-read parity against Replica 1
	searchJSON := `{
		"size": 10,
		"query": {
			"term": {"unindexedEnv": "prod"}
		},
		"aggs": {
			"service_val_count": {
				"value_count": {"field": "service"}
			},
			"latency_stats": {
				"stats": {"field": "latencyMs"}
			},
			"latency_pcts": {
				"percentiles": {"field": "latencyMs", "percents": [50, 99]}
			},
			"by_severity": {
				"filters": {
					"filters": {
						"errors": {"term": {"level": "ERROR"}},
						"infos": {"term": {"level": "INFO"}}
					}
				}
			},
			"by_service": {
				"terms": {"field": "service", "size": 10},
				"aggs": {
					"avg_latency": {"avg": {"field": "latencyMs"}},
					"by_level": {"terms": {"field": "level", "size": 10}}
				}
			}
		}
	}`
	sResp, err := http.Post(ts2.URL+"/logs_alias/_search?shadow_sync=true", "application/json", strings.NewReader(searchJSON))
	if err != nil || sResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /logs_alias/_search failed: status=%v err=%v", sResp.StatusCode, err)
	}
	var sRes map[string]any
	_ = json.NewDecoder(sResp.Body).Decode(&sRes)
	_ = sResp.Body.Close()

	aggs := sRes["aggregations"].(map[string]any)
	// Verify string value_count == 2
	if int(aggs["service_val_count"].(map[string]any)["value"].(float64)) != 2 {
		t.Fatalf("expected service_val_count == 2 on string field, got %v", aggs["service_val_count"])
	}
	// Verify stats (count=2, min=40, max=120, avg=80, sum=160)
	statsObj := aggs["latency_stats"].(map[string]any)
	if statsObj["avg"].(float64) != 80.0 || statsObj["sum"].(float64) != 160.0 {
		t.Fatalf("unexpected latency_stats: %+v", statsObj)
	}
	// Verify percentiles
	pctValues := aggs["latency_pcts"].(map[string]any)["values"].(map[string]any)
	if pctValues["50.0"].(float64) != 80.0 {
		t.Fatalf("expected p50 == 80.0, got %+v", pctValues)
	}
	// Verify filters aggregation
	sevBuckets := aggs["by_severity"].(map[string]any)["buckets"].(map[string]any)
	if int(sevBuckets["errors"].(map[string]any)["doc_count"].(float64)) != 1 {
		t.Fatalf("expected 1 error in prod, got %+v", sevBuckets)
	}
	// Verify bucket sub-aggregations (`by_service` -> `avg_latency` & `by_level`)
	svcBuckets := aggs["by_service"].(map[string]any)["buckets"].([]any)
	if len(svcBuckets) != 1 {
		t.Fatalf("expected 1 service bucket (checkout), got %+v", svcBuckets)
	}
	checkoutBucket := svcBuckets[0].(map[string]any)
	if checkoutBucket["avg_latency"].(map[string]any)["value"].(float64) != 80.0 {
		t.Fatalf("expected checkout avg_latency sub-agg == 80.0, got %+v", checkoutBucket)
	}
	levelBuckets := checkoutBucket["by_level"].(map[string]any)["buckets"].([]any)
	if len(levelBuckets) != 2 {
		t.Fatalf("expected 2 child level buckets under checkout, got %+v", levelBuckets)
	}

	// 5. Verify Shadow Verification metrics (`GET /_doris/shadow_stats`)
	shResp, err := http.Get(ts2.URL + "/_doris/shadow_stats")
	if err != nil || shResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_doris/shadow_stats failed: status=%v err=%v", shResp.StatusCode, err)
	}
	var shStats map[string]any
	_ = json.NewDecoder(shResp.Body).Decode(&shStats)
	_ = shResp.Body.Close()
	if shStats["hit_count_parity_rate"].(float64) != 1.0 || shStats["avg_topk_jaccard_similarity"].(float64) != 1.0 {
		t.Fatalf("expected 100%% shadow parity and Jaccard=1.0, got: %+v", shStats)
	}

	// 6. Verify Slowlog & Auto-Indexing Advisor (`GET /_doris/slowlog`) recommends promoting `unindexedEnv`
	slResp, err := http.Get(ts2.URL + "/_doris/slowlog")
	if err != nil || slResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_doris/slowlog failed: status=%v err=%v", slResp.StatusCode, err)
	}
	var slData map[string]any
	_ = json.NewDecoder(slResp.Body).Decode(&slData)
	_ = slResp.Body.Close()
	recs, _ := slData["auto_index_recommendations"].([]any)
	if len(recs) == 0 {
		t.Fatalf("expected auto_index_recommendations for unindexedEnv in /_doris/slowlog, got: %+v", slData)
	}
	firstRec := recs[0].(map[string]any)
	if firstRec["field"] != "unindexedEnv" {
		t.Fatalf("expected recommendation for unindexedEnv, got: %+v", firstRec)
	}

	// 7. Verify `POST /_reindex` with Painless script transformation
	reindexJSON := `{
		"source": {
			"index": "logs_alias",
			"query": {"term": {"level": "ERROR"}}
		},
		"dest": {
			"index": "error_logs_v1"
		},
		"script": {
			"source": "ctx._source.reindexed = true"
		}
	}`
	reResp, err := http.Post(ts2.URL+"/_reindex", "application/json", strings.NewReader(reindexJSON))
	if err != nil || reResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_reindex failed: status=%v err=%v", reResp.StatusCode, err)
	}
	var reData map[string]any
	_ = json.NewDecoder(reResp.Body).Decode(&reData)
	_ = reResp.Body.Close()
	if int(reData["created"].(float64)) != 2 {
		t.Fatalf("expected 2 ERROR docs reindexed into error_logs_v1, got: %+v", reData)
	}

	// 8. Verify Kibana/Grafana/Elasticvue discovery & Web UI endpoints
	for _, ep := range []string{
		"/_resolve/index/logs*",
		"/_stats",
		"/logs_v1/_stats",
		"/logs_v1/_search_shards",
		"/_cat/indices?format=txt&v",
		"/_cat/nodes",
		"/_cat/shards",
		"/_cat/count",
		"/_doris/ui",
	} {
		r, err := http.Get(ts2.URL + ep)
		if err != nil || r.StatusCode != http.StatusOK {
			t.Fatalf("GET %s failed: status=%v err=%v", ep, r.StatusCode, err)
		}
		_ = r.Body.Close()
	}
}

func TestV04DisMaxTopHitsCompositePromoteValidateAnalyzeRolloverMetrics_E2E(t *testing.T) {
	mem := NewMemDorisBackend()
	srv := proxy.NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Create rollover alias + initial index logs-000001
	putReq, err := http.NewRequest(http.MethodPut, ts.URL+"/logs-000001", strings.NewReader(`{
		"aliases": {"logs-write": {"is_write_index": true}},
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"service": {"type": "keyword"},
				"env": {"type": "keyword"},
				"latency_ms": {"type": "double"},
				"created_at": {"type": "date"}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil || putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /logs-000001 failed: status=%v err=%v", putResp.StatusCode, err)
	}
	_ = putResp.Body.Close()

	// 2. Test /_bulk partial failure isolation (valid docs + duplicate create + missing update + noop update + invalid JSON)
	bulkPayload := strings.Join([]string{
		`{"create":{"_index":"logs-000001","_id":"1"}}`,
		`{"title":"checkout timeout error","service":"checkout","env":"prod","latency_ms":250,"created_at":"2026-10-20T12:00:00Z","unmapped_region":"us-east-1"}`,
		`{"create":{"_index":"logs-000001","_id":"2"}}`,
		`{"title":"payment gateway retry","service":"payments","env":"prod","latency_ms":120,"created_at":"2026-10-22T12:00:00Z","unmapped_region":"us-west-2"}`,
		`{"create":{"_index":"logs-000001","_id":"3"}}`,
		`{"title":"legacy batch deprecated","service":"checkout","env":"staging","latency_ms":45,"created_at":"2026-09-01T12:00:00Z","unmapped_region":"eu-west-1"}`,
		`{"create":{"_index":"logs-000001","_id":"1"}}`, // conflict 409
		`{"title":"duplicate create should conflict"}`,
		`{"update":{"_index":"logs-000001","_id":"999"}}`, // missing 404 without doc_as_upsert
		`{"doc":{"latency_ms":999}}`,
		`{"update":{"_index":"logs-000001","_id":"2"}}`, // noop script
		`{"script":{"source":"ctx.op = 'noop'"}}`,
		`{"index":{"_index":"logs-000001","_id":"4"}}`, // invalid JSON 400
		`{"title":invalid_json}`,
	}, "\n") + "\n"

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/_bulk", strings.NewReader(bulkPayload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var bulkRes struct {
		Errors bool             `json:"errors"`
		Items  []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bulkRes); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !bulkRes.Errors || len(bulkRes.Items) != 7 {
		t.Fatalf("expected errors=true and 7 items in bulk response, got errors=%v len=%d", bulkRes.Errors, len(bulkRes.Items))
	}
	if createConflict, ok := bulkRes.Items[3]["create"].(map[string]any); !ok || int(createConflict["status"].(float64)) != 409 {
		t.Fatalf("expected item[3] create status 409, got %+v", bulkRes.Items[3])
	}
	if missingUpdate, ok := bulkRes.Items[4]["update"].(map[string]any); !ok || int(missingUpdate["status"].(float64)) != 404 {
		t.Fatalf("expected item[4] update status 404, got %+v", bulkRes.Items[4])
	}
	if noopUpdate, ok := bulkRes.Items[5]["update"].(map[string]any); !ok || noopUpdate["result"] != "noop" {
		t.Fatalf("expected item[5] update result=noop, got %+v", bulkRes.Items[5])
	}
	if badJSON, ok := bulkRes.Items[6]["index"].(map[string]any); !ok || int(badJSON["status"].(float64)) != 400 {
		t.Fatalf("expected item[6] index status 400, got %+v", bulkRes.Items[6])
	}

	// 3. Unknown query clause returns 400 parsing_exception instead of silently matching all rows
	badSearchReq, err := http.NewRequest(http.MethodPost, ts.URL+"/logs-000001/_search", strings.NewReader(`{"query":{"bogus_clause":{"title":"timeout"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	badSearchReq.Header.Set("Content-Type", "application/json")
	badSearchResp, err := http.DefaultClient.Do(badSearchReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = badSearchResp.Body.Close()
	if badSearchResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown query clause, got %d", badSearchResp.StatusCode)
	}

	// 4. Test dis_max, boosting, match_bool_prefix, top_hits (top-level + sub-agg), date_range, and composite aggs
	v04SearchResp, err := http.Post(ts.URL+"/logs-000001/_search", "application/json", strings.NewReader(`{
		"query": {
			"boosting": {
				"positive": {
					"dis_max": {
						"tie_breaker": 0.3,
						"queries": [
							{"match": {"title": "checkout"}},
							{"match_bool_prefix": {"title": "pay"}},
							{"term": {"service": "checkout"}}
						]
					}
				},
				"negative": {"term": {"env": "staging"}},
				"negative_boost": 0.2
			}
		},
		"aggs": {
			"latest_hit": {
				"top_hits": {
					"size": 1,
					"sort": [{"latency_ms": {"order": "desc"}}]
				}
			},
			"by_service": {
				"terms": {"field": "service"},
				"aggs": {
					"top_service_doc": {
						"top_hits": {
							"size": 1,
							"sort": [{"latency_ms": {"order": "desc"}}]
						}
					}
				}
			},
			"by_date_window": {
				"date_range": {
					"field": "created_at",
					"ranges": [
						{"key": "older", "to": "2026-10-01T00:00:00Z"},
						{"key": "recent", "from": "2026-10-01T00:00:00Z"}
					]
				}
			},
			"paged_composite": {
				"composite": {
					"size": 10,
					"sources": [
						{"service": {"terms": {"field": "service"}}},
						{"env": {"terms": {"field": "env"}}}
					]
				}
			}
		}
	}`))
	if err != nil || v04SearchResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /logs-000001/_search failed: status=%v err=%v", v04SearchResp.StatusCode, err)
	}
	var v04Search struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations map[string]map[string]any `json:"aggregations"`
	}
	if err := json.NewDecoder(v04SearchResp.Body).Decode(&v04Search); err != nil {
		t.Fatal(err)
	}
	_ = v04SearchResp.Body.Close()
	if v04Search.Hits.Total.Value != 3 {
		t.Fatalf("expected 3 total hits from boosting+dis_max query, got %d", v04Search.Hits.Total.Value)
	}
	latestHitAgg := v04Search.Aggregations["latest_hit"]
	topHitsWrapper, ok := latestHitAgg["hits"].(map[string]any)
	if !ok {
		t.Fatalf("expected top_hits hits wrapper, got %+v", latestHitAgg)
	}
	topHitsArr, _ := topHitsWrapper["hits"].([]any)
	if len(topHitsArr) != 1 {
		t.Fatalf("expected 1 top_hit in latest_hit, got %d", len(topHitsArr))
	}
	compBuckets, _ := v04Search.Aggregations["paged_composite"]["buckets"].([]any)
	if len(compBuckets) != 3 {
		t.Fatalf("expected 3 composite buckets, got %d (%+v)", len(compBuckets), compBuckets)
	}

	// 5. Query unmapped_region (triggers unindexed _doc['unmapped_region'] tracking) then promote via POST /{index}/_doris/promote
	unmappedResp, err := http.Post(ts.URL+"/logs-000001/_search", "application/json", strings.NewReader(`{"query":{"term":{"unmapped_region":"us-east-1"}}}`))
	if err != nil || unmappedResp.StatusCode != http.StatusOK {
		t.Fatalf("unmapped search failed: status=%v err=%v", unmappedResp.StatusCode, err)
	}
	_ = unmappedResp.Body.Close()
	promoteReq, err := http.NewRequest(http.MethodPost, ts.URL+"/logs-000001/_doris/promote", strings.NewReader(`{"field":"unmapped_region","type":"keyword"}`))
	if err != nil {
		t.Fatal(err)
	}
	promoteReq.Header.Set("Content-Type", "application/json")
	promoteResp, err := http.DefaultClient.Do(promoteReq)
	if err != nil {
		t.Fatal(err)
	}
	var promoteResult struct {
		Acknowledged   bool   `json:"acknowledged"`
		PromotedColumn string `json:"promoted_column"`
	}
	if err := json.NewDecoder(promoteResp.Body).Decode(&promoteResult); err != nil {
		t.Fatal(err)
	}
	_ = promoteResp.Body.Close()
	if !promoteResult.Acknowledged || promoteResult.PromotedColumn != "f__unmapped_region" {
		t.Fatalf("expected promoted_column=f__unmapped_region, got %+v", promoteResult)
	}

	// Verify /_validate/query?explain=true now binds unmapped_region to promoted column `f__unmapped_region`
	valReq, err := http.NewRequest(http.MethodPost, ts.URL+"/logs-000001/_validate/query?explain=true", strings.NewReader(`{"query":{"term":{"unmapped_region":"us-east-1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	valReq.Header.Set("Content-Type", "application/json")
	valResp, err := http.DefaultClient.Do(valReq)
	if err != nil {
		t.Fatal(err)
	}
	var valBody struct {
		Valid        bool `json:"valid"`
		Explanations []struct {
			Explanation string `json:"explanation"`
		} `json:"explanations"`
	}
	if err := json.NewDecoder(valResp.Body).Decode(&valBody); err != nil {
		t.Fatal(err)
	}
	_ = valResp.Body.Close()
	if !valBody.Valid || len(valBody.Explanations) == 0 || !strings.Contains(valBody.Explanations[0].Explanation, "`f__unmapped_region`") {
		t.Fatalf("expected validate/query explanation to reference promoted `f__unmapped_region`, got %+v", valBody)
	}

	// 6. Test /_analyze, /{alias}/_rollover, /metrics, /healthz, /readyz
	anReq, err := http.NewRequest(http.MethodPost, ts.URL+"/_analyze", strings.NewReader(`{"analyzer":"standard","text":"Apache Doris 4.0 Search"}`))
	if err != nil {
		t.Fatal(err)
	}
	anReq.Header.Set("Content-Type", "application/json")
	anResp, err := http.DefaultClient.Do(anReq)
	if err != nil {
		t.Fatal(err)
	}
	var anBody struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.NewDecoder(anResp.Body).Decode(&anBody); err != nil {
		t.Fatal(err)
	}
	_ = anResp.Body.Close()
	if len(anBody.Tokens) != 5 {
		t.Fatalf("expected 5 tokens from /_analyze, got %d", len(anBody.Tokens))
	}

	rollReq, err := http.NewRequest(http.MethodPost, ts.URL+"/logs-write/_rollover", strings.NewReader(`{"conditions":{"max_docs":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	rollReq.Header.Set("Content-Type", "application/json")
	rollResp, err := http.DefaultClient.Do(rollReq)
	if err != nil {
		t.Fatal(err)
	}
	var rollBody struct {
		RolledOver bool   `json:"rolled_over"`
		OldIndex   string `json:"old_index"`
		NewIndex   string `json:"new_index"`
	}
	if err := json.NewDecoder(rollResp.Body).Decode(&rollBody); err != nil {
		t.Fatal(err)
	}
	_ = rollResp.Body.Close()
	if !rollBody.RolledOver || rollBody.NewIndex != "logs-000002" {
		t.Fatalf("expected rollover to logs-000002, got %+v", rollBody)
	}

	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		r, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on %s, got %d", path, r.StatusCode)
		}
	}
}
