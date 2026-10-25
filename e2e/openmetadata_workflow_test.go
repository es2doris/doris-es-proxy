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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestOpenMetadataFullWorkflow_E2E(t *testing.T) {
	backend := NewMemDorisBackend()
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Step 1: OpenMetadata client boot handshake (`GET /` + `GET /_cluster/health` + `HEAD /table_search_index`)
	resp, err := http.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / failed: status=%v err=%v", resp.StatusCode, err)
	}
	if resp.Header.Get("X-Elastic-Product") != "Elasticsearch" {
		t.Errorf("expected X-Elastic-Product: Elasticsearch header")
	}
	_ = resp.Body.Close()

	// Verify GET /_alias/table_search_index returns 404 before index creation
	resp, err = http.Get(ts.URL + "/_alias/table_search_index")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for missing alias /_alias/table_search_index, got %v (err=%v)", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 2: Create physical timestamped index `table_search_index_rebuild_1` with OpenMetadata mapping
	createIndexJSON := `{
		"mappings": {
			"properties": {
				"name": {
					"type": "text",
					"fields": {
						"keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"}
					}
				},
				"displayName": {"type": "text"},
				"description": {"type": "text"},
				"serviceType": {"type": "keyword"},
				"deleted": {"type": "boolean"},
				"updatedAt": {"type": "long"},
				"tier": {"properties": {"tagFQN": {"type": "keyword"}}},
				"tags": {"properties": {"tagFQN": {"type": "keyword"}}},
				"owners": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
				"usageSummary": {
					"properties": {
						"weeklyStats": {"properties": {"count": {"type": "long"}}}
					}
				},
				"columns": {
					"type": "nested",
					"properties": {
						"name": {"type": "keyword"},
						"dataType": {"type": "keyword"},
						"tags": {"properties": {"tagFQN": {"type": "keyword"}}}
					}
				}
			}
		}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/table_search_index_rebuild_1", strings.NewReader(createIndexJSON))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /table_search_index_rebuild_1 failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 3: Blue-green alias swap (`POST /_aliases`) pointing `table_search_index` -> `table_search_index_rebuild_1`
	aliasPayload := `{
		"actions": [
			{"add": {"index": "table_search_index_rebuild_1", "alias": "table_search_index"}}
		]
	}`
	resp, err = http.Post(ts.URL+"/_aliases", "application/json", strings.NewReader(aliasPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_aliases failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 4:Incremental `PUT /table_search_index/_mapping` adding `domain.name` without losing `columns` or `name`
	putMappingJSON := `{
		"properties": {
			"domain": {
				"properties": {
					"name": {"type": "keyword"}
				}
			}
		}
	}`
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/table_search_index/_mapping", strings.NewReader(putMappingJSON))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /table_search_index/_mapping failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 5: `POST /_bulk?refresh=true` indexing 4 realistic OpenMetadata table assets via the alias
	bulkLines := []string{
		`{"index":{"_index":"table_search_index","_id":"tbl-orders"}}`,
		`{"name":"Customer_Orders","displayName":"Customer Orders Fact Table","description":"All e-commerce customer orders and revenue","serviceType":"BigQuery","deleted":false,"updatedAt":1729773296001,"tier":{"tagFQN":"Tier.Tier1"},"tags":[{"tagFQN":"PII.Sensitive"},{"tagFQN":"Finance"}],"owners":[{"id":"u-1","name":"alice"}],"usageSummary":{"weeklyStats":{"count":250}},"columns":[{"name":"user_id","dataType":"INT","tags":[{"tagFQN":"PII.Sensitive"}]},{"name":"order_amount","dataType":"DECIMAL","tags":[{"tagFQN":"Finance"}]}]}`,
		`{"index":{"_index":"table_search_index","_id":"tbl-payments"}}`,
		`{"name":"Stripe_Payments","displayName":"Stripe Payments Ledger","description":"Payment transactions for customer orders","serviceType":"Snowflake","deleted":false,"updatedAt":1729773296002,"tier":{"tagFQN":"Tier.Tier2"},"tags":[{"tagFQN":"PII.Sensitive"}],"owners":[{"id":"u-2","name":"bob"}],"usageSummary":{"weeklyStats":{"count":80}},"columns":[{"name":"user_id","dataType":"VARCHAR","tags":[{"tagFQN":"PII.Sensitive"}]},{"name":"payment_id","dataType":"INT","tags":[]}]}`,
		`{"index":{"_index":"table_search_index","_id":"tbl-clicks"}}`,
		`{"name":"Web_Clicks","displayName":"Website Clickstream","description":"Anonymous browser click events","serviceType":"BigQuery","deleted":false,"updatedAt":1729773296003,"tags":[{"tagFQN":"Marketing"}],"owners":[{"id":"u-1","name":"alice"}],"usageSummary":{"weeklyStats":{"count":10}},"columns":[{"name":"session_id","dataType":"VARCHAR","tags":[]}]}`,
		`{"index":{"_index":"table_search_index","_id":"tbl-legacy"}}`,
		`{"name":"Legacy_Orders","displayName":"Deprecated Orders","description":"Old customer orders table","serviceType":"Postgres","deleted":true,"updatedAt":1729773296000,"tags":[{"tagFQN":"PII.Sensitive"}],"columns":[{"name":"user_id","dataType":"INT","tags":[]}]}`,
		"",
	}
	resp, err = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(strings.Join(bulkLines, "\n")))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 6: Verify Correlated Nested Query (`columns.name == "user_id" AND columns.dataType == "INT"`)
	// Must match `tbl-orders` (where user_id is INT and deleted=false),
	// and MUST NOT match `tbl-payments` (where user_id is VARCHAR and payment_id is INT — cross-element false positive trap!)
	// and MUST NOT match `tbl-legacy` (where deleted=true).
	searchPayload := `{
		"from": 0,
		"size": 10,
		"_source": {"includes": ["name", "serviceType", "tier.*", "columns.name"], "excludes": ["description"]},
		"highlight": {
			"pre_tags": ["<em>"],
			"post_tags": ["</em>"],
			"fields": {"displayName": {}, "name": {}}
		},
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [
							{
								"multi_match": {
									"query": "orders",
									"fields": ["name^10", "displayName^5", "description^2"],
									"operator": "and"
								}
							},
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
						],
						"filter": [
							{"term": {"deleted": false}},
							{"term": {"tags.tagFQN": "PII.Sensitive"}}
						]
					}
				},
				"functions": [
					{
						"filter": {"term": {"tier.tagFQN": "Tier.Tier1"}},
						"weight": 3.0
					},
					{
						"field_value_factor": {
							"field": "usageSummary.weeklyStats.count",
							"factor": 0.05,
							"modifier": "log1p",
							"missing": 0
						}
					}
				],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}
		},
		"aggs": {
			"serviceType": {"terms": {"field": "serviceType", "size": 10}},
			"tags": {"terms": {"field": "tags.tagFQN", "size": 10}},
			"columns_by_type": {
				"nested": {"path": "columns"},
				"aggs": {
					"dataTypes": {"terms": {"field": "columns.dataType", "size": 10}}
				}
			}
		}
	}`
	resp, err = http.Post(ts.URL+"/table_search_index/_search", "application/json", strings.NewReader(searchPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /table_search_index/_search failed: status=%v err=%v", resp.StatusCode, err)
	}
	var searchRes map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&searchRes); err != nil {
		t.Fatalf("failed to decode search response: %v", err)
	}
	_ = resp.Body.Close()

	hitsWrapper := searchRes["hits"].(map[string]any)
	totalVal := int(hitsWrapper["total"].(map[string]any)["value"].(float64))
	if totalVal != 1 {
		t.Fatalf("expected exactly 1 correlated nested hit (tbl-orders), got %d: %+v", totalVal, hitsWrapper)
	}
	hitsList := hitsWrapper["hits"].([]any)
	firstHit := hitsList[0].(map[string]any)
	if firstHit["_id"] != "tbl-orders" {
		t.Errorf("expected hit _id=tbl-orders, got %v", firstHit["_id"])
	}
	// Verify _source filtering included `name` & `columns.name` and excluded `description`
	hitSource := firstHit["_source"].(map[string]any)
	if hitSource["name"] != "Customer_Orders" {
		t.Errorf("expected _source.name=Customer_Orders, got %v", hitSource["name"])
	}
	if _, hasDesc := hitSource["description"]; hasDesc {
		t.Errorf("expected _source.description to be excluded by _source filter")
	}
	// Verify highlight snippet generation
	hl, hasHL := firstHit["highlight"].(map[string]any)
	if !hasHL || len(hl) == 0 {
		t.Errorf("expected highlight snippets in hit, got %+v", firstHit)
	}

	// Step 7: Painless `/_update/tbl-clicks` adding `PII.Sensitive` tag + `/_update_by_query` propagating tier rename
	updateClicks := `{
		"script": {
			"source": "if (ctx._source.tags == null) { ctx._source.tags = []; } ctx._source.tags.add(params.tag);",
			"params": {"tag": {"tagFQN": "PII.Sensitive"}}
		}
	}`
	resp, err = http.Post(ts.URL+"/table_search_index/_update/tbl-clicks?refresh=true", "application/json", strings.NewReader(updateClicks))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_update/tbl-clicks failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	ubqPayload := `{
		"query": {"term": {"serviceType": "BigQuery"}},
		"script": {
			"source": "ctx._source.tier = params.newTier;",
			"params": {"newTier": {"tagFQN": "Tier.Gold"}}
		}
	}`
	resp, err = http.Post(ts.URL+"/table_search_index/_update_by_query?refresh=true", "application/json", strings.NewReader(ubqPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_update_by_query failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Step 8: Verify `/_mget` and raw `/_source/{id}` reflect updated `Tier.Gold` and `PII.Sensitive` on `tbl-clicks`
	mgetPayload := `{"ids": ["tbl-orders", "tbl-clicks"]}`
	resp, err = http.Post(ts.URL+"/table_search_index/_mget", "application/json", strings.NewReader(mgetPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_mget failed: status=%v err=%v", resp.StatusCode, err)
	}
	var mgetRes struct {
		Docs []map[string]any `json:"docs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&mgetRes)
	_ = resp.Body.Close()
	if len(mgetRes.Docs) != 2 || mgetRes.Docs[0]["found"] != true || mgetRes.Docs[1]["found"] != true {
		t.Fatalf("expected 2 found docs in _mget, got %+v", mgetRes.Docs)
	}

	resp, err = http.Get(ts.URL + "/table_search_index/_source/tbl-orders")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_source/tbl-orders failed: status=%v err=%v", resp.StatusCode, err)
	}
	rawSrcBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(rawSrcBytes), `"Tier.Gold"`) {
		t.Errorf("expected raw _source to contain Tier.Gold after _update_by_query, got %s", string(rawSrcBytes))
	}

	// Step 9: Verify `/_msearch` NDJSON multi-search
	msearchNDJSON := strings.Join([]string{
		`{"index":"table_search_index"}`,
		`{"query":{"term":{"tier.tagFQN":"Tier.Gold"}},"size":10}`,
		`{"index":"table_search_index"}`,
		`{"query":{"term":{"serviceType":"Snowflake"}},"size":10}`,
		"",
	}, "\n")
	resp, err = http.Post(ts.URL+"/_msearch", "application/x-ndjson", strings.NewReader(msearchNDJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_msearch failed: status=%v err=%v", resp.StatusCode, err)
	}
	var msearchRes struct {
		Responses []map[string]any `json:"responses"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&msearchRes)
	_ = resp.Body.Close()
	if len(msearchRes.Responses) != 2 {
		t.Fatalf("expected 2 responses from _msearch, got %d", len(msearchRes.Responses))
	}

	// Step 10: Verify `/_delete_by_query` removing `deleted: true` documents (`tbl-legacy`) and `/_count`
	dbqPayload := `{"query": {"term": {"deleted": true}}}`
	resp, err = http.Post(ts.URL+"/table_search_index/_delete_by_query?refresh=true", "application/json", strings.NewReader(dbqPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_delete_by_query failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/table_search_index/_count")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_count failed: status=%v err=%v", resp.StatusCode, err)
	}
	var countRes struct {
		Count int64 `json:"count"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&countRes)
	_ = resp.Body.Close()
	if countRes.Count != 3 {
		t.Fatalf("expected 3 remaining documents after _delete_by_query, got %d", countRes.Count)
	}
}
