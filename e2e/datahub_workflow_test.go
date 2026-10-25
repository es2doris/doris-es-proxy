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
