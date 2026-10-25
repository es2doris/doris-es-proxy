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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type mockDorisBackend struct {
	mu       sync.Mutex
	ddls     []string
	hitsSQLs []string
	aggsSQLs []string
	docs     map[string]HitRow
}

func newMockDorisBackend() *mockDorisBackend {
	return &mockDorisBackend{
		docs: make(map[string]HitRow),
	}
}

func (m *mockDorisBackend) Ping(_ context.Context) error {
	return nil
}

func (m *mockDorisBackend) ExecDDL(_ context.Context, ddl string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ddls = append(m.ddls, ddl)
	return nil
}

func (m *mockDorisBackend) QueryHits(_ context.Context, sql string) ([]HitRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hitsSQLs = append(m.hitsSQLs, sql)
	var out []HitRow
	for _, d := range m.docs {
		d.TotalHits = int64(len(m.docs))
		d.Score = 12.5
		out = append(out, d)
	}
	return out, nil
}

func (m *mockDorisBackend) QueryAggs(_ context.Context, sql string) ([]AggRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aggsSQLs = append(m.aggsSQLs, sql)
	return []AggRow{
		{AggName: "__meta_total", BucketKey: "_count", DocCount: int64(len(m.docs))},
		{AggName: "serviceType", BucketKey: "BigQuery", DocCount: int64(len(m.docs))},
	}, nil
}

func (m *mockDorisBackend) GetDocByID(_ context.Context, _, _, id string) (*HitRow, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[id]
	if !ok {
		return nil, false, nil
	}
	return &d, true, nil
}

func (m *mockDorisBackend) GetDocsByIDs(_ context.Context, _, _ string, ids []string) (map[string]HitRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]HitRow, len(ids))
	for _, id := range ids {
		if d, ok := m.docs[id]; ok {
			out[id] = d
		}
	}
	return out, nil
}

func (m *mockDorisBackend) StreamLoad(_ context.Context, _ string, ndjson []byte, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	scanner := bufio.NewScanner(bytes.NewReader(ndjson))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var row struct {
			ID         string `json:"_id"`
			Version    int64  `json:"_version"`
			DeleteSign int    `json:"__DORIS_DELETE_SIGN__"`
			Source     string `json:"_source"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		if row.DeleteSign == 1 {
			delete(m.docs, row.ID)
		} else {
			m.docs[row.ID] = HitRow{
				ID:      row.ID,
				Version: row.Version,
				Source:  json.RawMessage(row.Source),
			}
		}
	}
	return nil
}

func TestEndToEnd_OpenMetadataLifecycle_CreateIndex_Bulk_Update_Search(t *testing.T) {
	backend := newMockDorisBackend()
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. PUT /table_search_index (Create Index with explicit mappings)
	createBody := `{
		"mappings": {
			"properties": {
				"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"serviceType": {"type": "keyword"},
				"deleted": {"type": "boolean"},
				"tags": {"properties": {"tagFQN": {"type": "keyword"}}}
			}
		}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/table_search_index", strings.NewReader(createBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /table_search_index failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	if len(backend.ddls) != 1 || !strings.Contains(backend.ddls[0], "CREATE TABLE IF NOT EXISTS `es_compat`.`table_search_index`") {
		t.Fatalf("expected CREATE TABLE DDL to be executed, got: %+v", backend.ddls)
	}

	// 2. POST /_bulk (Index 2 documents)
	bulkPayload := strings.Join([]string{
		`{"index":{"_index":"table_search_index","_id":"tbl-1"}}`,
		`{"name":"customer_orders","serviceType":"BigQuery","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}]}`,
		`{"index":{"_index":"table_search_index","_id":"tbl-2"}}`,
		`{"name":"dim_users","serviceType":"BigQuery","deleted":false,"tags":[]}`,
		"",
	}, "\n")
	resp, err = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulkPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_bulk failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 3. POST /table_search_index/_update/tbl-2 (Painless script adding a tag)
	updatePayload := `{
		"script": {
			"source": "if (ctx._source.tags == null) { ctx._source.tags = []; } ctx._source.tags.add(params.tag);",
			"params": {"tag": {"tagFQN": "Tier.Tier1"}}
		}
	}`
	resp, err = http.Post(ts.URL+"/table_search_index/_update/tbl-2?refresh=true", "application/json", strings.NewReader(updatePayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_update failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 4. GET /table_search_index/_doc/tbl-2 (Verify Painless mutation preserved in _source)
	resp, err = http.Get(ts.URL + "/table_search_index/_doc/tbl-2")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_doc/tbl-2 failed: status=%v err=%v", resp.StatusCode, err)
	}
	var getDocResp struct {
		Found  bool           `json:"found"`
		Source map[string]any `json:"_source"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&getDocResp)
	_ = resp.Body.Close()
	if !getDocResp.Found {
		t.Fatalf("expected tbl-2 to be found")
	}
	tags, _ := getDocResp.Source["tags"].([]any)
	if len(tags) != 1 {
		t.Fatalf("expected 1 tag on tbl-2 after Painless update, got: %+v", getDocResp.Source)
	}

	// 5. POST /table_search_index/_search (Query + Facets)
	searchPayload := `{
		"size": 10,
		"query": {"match": {"name": "customer_orders"}},
		"aggs": {"serviceType": {"terms": {"field": "serviceType", "size": 10}}}
	}`
	resp, err = http.Post(ts.URL+"/table_search_index/_search", "application/json", strings.NewReader(searchPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_search failed: status=%v err=%v", resp.StatusCode, err)
	}
	var searchResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&searchResp)
	_ = resp.Body.Close()

	aggsMap, ok := searchResp["aggregations"].(map[string]any)
	if !ok || aggsMap["serviceType"] == nil {
		t.Fatalf("expected serviceType aggregation in search response, got: %+v", searchResp)
	}
}
