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
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestNormalizeDorisSQL_RewritesArrayExistsToBooleanScalar(t *testing.T) {
	in := "SELECT * FROM `db`.`tbl` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (array_exists(_el -> (json_extract_string(_el, '$.name') = 'user_id') AND (json_extract_string(_el, '$.dataType') = 'INT'), `n__columns`))"
	got := normalizeDorisSQL(in)
	want := "SELECT * FROM `db`.`tbl` WHERE (array_contains(array_exists(_el -> (json_extract_string(_el, '$.name') = 'user_id') AND (json_extract_string(_el, '$.dataType') = 'INT'), IFNULL(`n__columns`, CAST([] AS ARRAY<STRING>))), true))"
	if got != want {
		t.Fatalf("normalizeDorisSQL mismatch:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestStreamLoadClient_RedirectAuthAndErrorHandling(t *testing.T) {
	var beGotAuth string
	var beStatus = "Success"
	var beFiltered int64
	var beServer *httptest.Server
	beServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/_load_error_log" {
			_, _ = w.Write([]byte("row 1: invalid column format"))
			return
		}
		beGotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		resp := streamLoadResponse{
			Status:             beStatus,
			Message:            "load result",
			NumberTotalRows:    1,
			NumberLoadedRows:   1 - beFiltered,
			NumberFilteredRows: beFiltered,
			ErrorURL:           beServer.URL + "/api/_load_error_log",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer beServer.Close()

	feServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, beServer.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer feServer.Close()

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feServer.URL,
		User:           "root",
		Password:       "doris_pw",
		Database:       "es_compat",
		Timeout:        5 * time.Second,
	})

	// 1. Empty payload is a no-op
	if err := sl.LoadNDJSON(context.Background(), "tbl", []byte("   "), true); err != nil {
		t.Fatalf("expected nil error on empty NDJSON, got %v", err)
	}

	// 2. Successful 307 redirect preserving Basic Auth
	if err := sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected successful LoadNDJSON across 307 redirect, got %v", err)
	}
	if !strings.HasPrefix(beGotAuth, "Basic ") {
		t.Fatalf("expected Basic Authorization header preserved on BE after 307 redirect, got %q", beGotAuth)
	}

	// 3. Filtered rows error with ErrorURL detail fetched
	beFiltered = 1
	err := sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || !strings.Contains(err.Error(), "row 1: invalid column format") {
		t.Fatalf("expected filtered rows error with ErrorURL detail, got %v", err)
	}

	// 4. Status=Fail error with ErrorURL detail fetched
	beFiltered = 0
	beStatus = "Fail"
	err = sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || !strings.Contains(err.Error(), "status=Fail") || !strings.Contains(err.Error(), "row 1: invalid column format") {
		t.Fatalf("expected Fail error with ErrorURL detail, got %v", err)
	}
}

type stubSQLDriver struct{}
type stubSQLConn struct{}
type stubSQLRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (d *stubSQLDriver) Open(_ string) (driver.Conn, error) { return &stubSQLConn{}, nil }
func (c *stubSQLConn) Prepare(_ string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}
func (c *stubSQLConn) Close() error              { return nil }
func (c *stubSQLConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }
func (c *stubSQLConn) ExecContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (c *stubSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "_es_catalog"):
		return &stubSQLRows{
			cols: []string{"entity_type", "entity_key", "payload_json", "updated_epoch_ms"},
			data: [][]driver.Value{{"alias", "logs-read", `{"targets":{"logs-1":true}}`, int64(100)}},
		}, nil
	case strings.Contains(query, "WHERE `_id` = ?"):
		if len(args) > 0 && args[0].Value == "missing" {
			return &stubSQLRows{cols: []string{"_id", "_version", "_source"}}, nil
		}
		return &stubSQLRows{
			cols: []string{"_id", "_version", "_source"},
			data: [][]driver.Value{{"doc-1", int64(2), `{"name":"orders"}`}},
		}, nil
	case strings.Contains(query, "WHERE `_id` IN"):
		return &stubSQLRows{
			cols: []string{"_id", "_version", "_source"},
			data: [][]driver.Value{{"doc-1", int64(2), `{"name":"orders"}`}},
		}, nil
	case strings.Contains(query, "_agg_name"):
		return &stubSQLRows{
			cols: []string{"_agg_name", "_bucket_key", "_doc_count"},
			data: [][]driver.Value{{"__meta_total", "_count", float64(5)}},
		}, nil
	default:
		return &stubSQLRows{
			cols: []string{"_id", "_version", "_source", "_score", "_total_hits"},
			data: [][]driver.Value{{"doc-1", int64(2), `{"name":"orders"}`, float64(4.5), int64(1)}},
		}, nil
	}
}
func (r *stubSQLRows) Columns() []string { return r.cols }
func (r *stubSQLRows) Close() error      { return nil }
func (r *stubSQLRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

var registerStubOnce sync.Once

func TestDorisSQLBackend_AllMethods(t *testing.T) {
	registerStubOnce.Do(func() {
		sql.Register("doris_stub", &stubSQLDriver{})
	})
	db, err := sql.Open("doris_stub", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	slServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(streamLoadResponse{Status: "Success", NumberTotalRows: 1, NumberLoadedRows: 1})
	}))
	defer slServer.Close()

	sl := NewStreamLoadClient(StreamLoadConfig{FEHTTPEndpoint: slServer.URL, Database: "es_compat"})
	b := NewDorisSQLBackend(db, sl)
	b.SetLogSQL(true)
	ctx := context.Background()

	if err := b.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if err := b.ExecDDL(ctx, "CREATE TABLE `es_compat`.`t` (`_id` VARCHAR(64))"); err != nil {
		t.Fatalf("ExecDDL failed: %v", err)
	}
	hits, err := b.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, 1.0 AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`t`")
	if err != nil || len(hits) != 1 || hits[0].ID != "doc-1" {
		t.Fatalf("QueryHits unexpected: hits=%+v err=%v", hits, err)
	}
	aggs, err := b.QueryAggs(ctx, "SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, 5.0 AS `_doc_count`")
	if err != nil || len(aggs) != 1 || aggs[0].DocCount != 5 {
		t.Fatalf("QueryAggs unexpected: aggs=%+v err=%v", aggs, err)
	}
	doc, found, err := b.GetDocByID(ctx, "es_compat", "t", "doc-1")
	if err != nil || !found || doc.ID != "doc-1" {
		t.Fatalf("GetDocByID found unexpected: doc=%+v found=%v err=%v", doc, found, err)
	}
	if _, foundMissing, err := b.GetDocByID(ctx, "es_compat", "t", "missing"); err != nil || foundMissing {
		t.Fatalf("GetDocByID missing unexpected: found=%v err=%v", foundMissing, err)
	}
	docsMap, err := b.GetDocsByIDs(ctx, "es_compat", "t", []string{"doc-1", "doc-2"})
	if err != nil || len(docsMap) != 1 {
		t.Fatalf("GetDocsByIDs unexpected: %+v err=%v", docsMap, err)
	}
	if err := b.StreamLoad(ctx, "t", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("StreamLoad failed: %v", err)
	}
	if err := b.InitCatalog(ctx, "es_compat"); err != nil {
		t.Fatalf("InitCatalog failed: %v", err)
	}
	if err := b.UpsertCatalogEntry(ctx, "es_compat", CatalogEntry{EntityType: "alias", EntityKey: "a1", PayloadJSON: "{}", UpdatedEpochMs: 1}); err != nil {
		t.Fatalf("UpsertCatalogEntry failed: %v", err)
	}
	if err := b.DeleteCatalogEntry(ctx, "es_compat", "alias", "a1"); err != nil {
		t.Fatalf("DeleteCatalogEntry failed: %v", err)
	}
	entries, err := b.LoadCatalogEntries(ctx, "es_compat")
	if err != nil || len(entries) != 1 || entries[0].EntityKey != "logs-read" {
		t.Fatalf("LoadCatalogEntries unexpected: %+v err=%v", entries, err)
	}
}

func TestServerAllRESTEndpointsAndShadowVerification(t *testing.T) {
	mem := NewMemoryBackend(true)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})

	// Set up a mock shadow Elasticsearch server to test dual-read shadow verification
	shadowES := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":1},"hits":[{"_id":"doc-1","_score":1.0}]}}`))
	}))
	defer shadowES.Close()
	srv.SetShadowESURL(shadowES.URL)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// 1. Cluster, Cat, Settings, Ingest Pipeline, Index Template
	for _, ep := range []struct {
		method string
		path   string
		body   string
		status int
	}{
		{http.MethodGet, "/", "", http.StatusOK},
		{http.MethodGet, "/_cluster/health?wait_for_status=green", "", http.StatusOK},
		{http.MethodGet, "/_cluster/settings", "", http.StatusOK},
		{http.MethodPut, "/_cluster/settings", `{"persistent":{}}`, http.StatusOK},
		{http.MethodGet, "/_nodes", "", http.StatusOK},
		{http.MethodGet, "/_stats", "", http.StatusOK},
		{http.MethodGet, "/_cat/indices?v=true", "", http.StatusOK},
		{http.MethodGet, "/_cat/aliases?v=true", "", http.StatusOK},
		{http.MethodGet, "/_cat/nodes?v=true", "", http.StatusOK},
		{http.MethodGet, "/_cat/shards?v=true", "", http.StatusOK},
		{http.MethodGet, "/_cat/count?v=true", "", http.StatusOK},
		{http.MethodPut, "/_ingest/pipeline/my-pipe", `{"description":"test pipe","processors":[]}`, http.StatusOK},
		{http.MethodGet, "/_ingest/pipeline/my-pipe", "", http.StatusOK},
		{http.MethodDelete, "/_ingest/pipeline/my-pipe", "", http.StatusOK},
		{http.MethodPut, "/_index_template/logs-tpl", `{"index_patterns":["logs-*"],"template":{"mappings":{"properties":{"service":{"type":"keyword"},"latency_ms":{"type":"long"}}}}}`, http.StatusOK},
		{http.MethodGet, "/_index_template/logs-tpl", "", http.StatusOK},
	} {
		code, body := doReq(ep.method, ep.path, ep.body)
		if code != ep.status {
			t.Fatalf("%s %s returned %d (want %d): %s", ep.method, ep.path, code, ep.status, body)
		}
	}

	// 2. Index creation (matching template logs-*), GET/HEAD/settings/mapping/aliases
	for _, ep := range []struct {
		method string
		path   string
		body   string
		status int
	}{
		{http.MethodPut, "/logs-2026", `{"aliases":{"logs-alias":{}}}`, http.StatusOK},
		{http.MethodHead, "/logs-2026", "", http.StatusOK},
		{http.MethodHead, "/nonexistent-idx", "", http.StatusNotFound},
		{http.MethodGet, "/logs-2026", "", http.StatusOK},
		{http.MethodGet, "/_mapping", "", http.StatusOK},
		{http.MethodGet, "/logs-2026/_mapping", "", http.StatusOK},
		{http.MethodPut, "/logs-2026/_mapping", `{"properties":{"env":{"type":"keyword"}}}`, http.StatusOK},
		{http.MethodGet, "/logs-2026/_settings", "", http.StatusOK},
		{http.MethodPut, "/logs-2026/_settings", `{"index":{"number_of_replicas":0}}`, http.StatusOK},
		{http.MethodGet, "/_aliases", "", http.StatusOK},
		{http.MethodGet, "/logs-2026/_alias", "", http.StatusOK},
		{http.MethodPut, "/logs-2026/_alias/logs-alias-2", "", http.StatusOK},
		{http.MethodDelete, "/logs-2026/_alias/logs-alias-2", "", http.StatusOK},
		{http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"logs-2026","alias":"logs-alias-3"}},{"remove":{"index":"logs-2026","alias":"logs-alias-3"}}]}`, http.StatusOK},
		{http.MethodPost, "/logs-2026/_refresh", "", http.StatusOK},
		{http.MethodGet, "/logs-2026/_stats", "", http.StatusOK},
		{http.MethodGet, "/_resolve/index/logs-*", "", http.StatusOK},
		{http.MethodGet, "/logs-2026/_search_shards", "", http.StatusOK},
	} {
		code, body := doReq(ep.method, ep.path, ep.body)
		if code != ep.status {
			t.Fatalf("%s %s returned %d (want %d): %s", ep.method, ep.path, code, ep.status, body)
		}
	}

	// 3. Single-doc PUT/POST/GET/HEAD/DELETE, _source, _mget, URI search (?q=...), scroll, _update_by_query, _delete_by_query, _reindex
	for _, ep := range []struct {
		method string
		path   string
		body   string
		status int
	}{
		{http.MethodPut, "/logs-2026/_doc/doc-1?refresh=true", `{"service":"checkout","env":"prod","latency_ms":120}`, http.StatusCreated},
		{http.MethodPost, "/logs-2026/_doc?refresh=true", `{"service":"payments","env":"staging","latency_ms":40}`, http.StatusCreated},
		{http.MethodHead, "/logs-2026/_doc/doc-1", "", http.StatusOK},
		{http.MethodHead, "/logs-2026/_doc/missing-doc", "", http.StatusNotFound},
		{http.MethodGet, "/logs-2026/_source/doc-1", "", http.StatusOK},
		{http.MethodPost, "/logs-2026/_mget", `{"ids":["doc-1","missing-doc"]}`, http.StatusOK},
		{http.MethodGet, "/logs-2026/_search?q=service:checkout&default_operator=AND&size=5&from=0&sort=latency_ms:desc", "", http.StatusOK},
		{http.MethodPost, "/logs-2026/_count", `{"query":{"term":{"service":"checkout"}}}`, http.StatusOK},
		{http.MethodPost, "/logs-2026/_update_by_query", `{"query":{"term":{"service":"checkout"}},"script":{"source":"ctx._source.env = 'canary'"}}`, http.StatusOK},
		{http.MethodPost, "/_reindex", `{"source":{"index":"logs-2026"},"dest":{"index":"logs-backup"}}`, http.StatusOK},
		{http.MethodPost, "/logs-2026/_delete_by_query", `{"query":{"term":{"service":"payments"}}}`, http.StatusOK},
		{http.MethodDelete, "/logs-2026/_doc/doc-1", "", http.StatusOK},
		{http.MethodGet, "/_doris/ui", "", http.StatusOK},
		{http.MethodGet, "/_doris/slowlog", "", http.StatusOK},
		{http.MethodGet, "/_doris/shadow_stats", "", http.StatusOK},
		{http.MethodDelete, "/_index_template/logs-tpl", "", http.StatusOK},
		{http.MethodDelete, "/logs-2026", "", http.StatusOK},
	} {
		code, body := doReq(ep.method, ep.path, ep.body)
		if code != ep.status {
			t.Fatalf("%s %s returned %d (want %d): %s", ep.method, ep.path, code, ep.status, body)
		}
	}
}

func TestCriticalBugs_FieldPromoteBackfill_MultiIndexSortAndAggs_IngestPipeline_DynamicMultiValued(t *testing.T) {
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// 1. Security & X-Pack discovery endpoints
	if code, body := doReq(http.MethodGet, "/_security/_authenticate", ""); code != http.StatusOK || !strings.Contains(body, `"username"`) {
		t.Fatalf("unexpected /_security/_authenticate: %d %s", code, body)
	}
	if code, body := doReq(http.MethodGet, "/_xpack", ""); code != http.StatusOK || !strings.Contains(body, `"build"`) {
		t.Fatalf("unexpected /_xpack: %d %s", code, body)
	}

	// 2. Critical Bug #1: Read-before-create (GET missing doc before PUT /{index}) + Field Promotion Backfill
	_, _ = doReq(http.MethodGet, "/promo_idx/_doc/nonexistent", "")
	if code, body := doReq(http.MethodPut, "/promo_idx", `{"mappings":{"properties":{"service":{"type":"keyword"}}}}`); code != http.StatusOK {
		t.Fatalf("PUT /promo_idx failed: %d %s", code, body)
	}
	// Index a document with both mapped `service` and unmapped `region` + multi-valued `custom_tags`
	if code, body := doReq(http.MethodPut, "/promo_idx/_doc/1?refresh=true", `{"service":"checkout","region":"us-east-1","custom_tags":["alpha","beta"]}`); code != http.StatusCreated {
		t.Fatalf("PUT doc failed: %d %s", code, body)
	}
	// Promote `region` via POST /promo_idx/_doris/promote and verify existing doc 1 is backfilled and searchable!
	if code, body := doReq(http.MethodPost, "/promo_idx/_doris/promote", `{"field":"region","type":"keyword"}`); code != http.StatusOK {
		t.Fatalf("POST /promo_idx/_doris/promote failed: %d %s", code, body)
	}
	if code, body := doReq(http.MethodPost, "/promo_idx/_search", `{"query":{"term":{"region":"us-east-1"}}}`); code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) {
		t.Fatalf("expected promoted field `region` to backfill existing doc 1, got: %d %s", code, body)
	}
	// Test dynamic multi-valued array inference on a dynamically created index
	if code, body := doReq(http.MethodPut, "/dyn_array_idx/_doc/d1?refresh=true", `{"custom_tags":["alpha","beta"],"vec":[0.9,0.1,0.0]}`); code != http.StatusCreated {
		t.Fatalf("PUT /dyn_array_idx/_doc/d1 failed: %d %s", code, body)
	}
	if code, body := doReq(http.MethodPost, "/dyn_array_idx/_search", `{"query":{"term":{"custom_tags":"beta"}}}`); code != http.StatusOK || !strings.Contains(body, `"_id":"d1"`) {
		t.Fatalf("expected dynamically inferred multi-valued array `custom_tags` to match second element 'beta', got: %d %s", code, body)
	}

	// 3. Critical Bug #3: Multi-index search sort + 0-doc index stats.min preservation
	_, _ = doReq(http.MethodPut, "/multi-a", `{"mappings":{"properties":{"latency":{"type":"long"},"svc":{"type":"keyword"}}}}`)
	_, _ = doReq(http.MethodPut, "/multi-b", `{"mappings":{"properties":{"latency":{"type":"long"},"svc":{"type":"keyword"}}}}`)
	_, _ = doReq(http.MethodPut, "/multi-empty", `{"mappings":{"properties":{"latency":{"type":"long"},"svc":{"type":"keyword"}}}}`)
	_, _ = doReq(http.MethodPut, "/multi-a/_doc/a1?refresh=true", `{"latency":100,"svc":"api"}`)
	_, _ = doReq(http.MethodPut, "/multi-b/_doc/b1?refresh=true", `{"latency":500,"svc":"web"}`)

	code, multiBody := doReq(http.MethodPost, "/multi-*/_search", `{
		"sort": [{"latency": "desc"}],
		"aggs": {
			"lat_stats": {"stats": {"field": "latency"}},
			"by_svc": {"terms": {"field": "svc", "size": 1}}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("multi-index search failed: %d %s", code, multiBody)
	}
	var multiResp map[string]any
	if err := json.Unmarshal([]byte(multiBody), &multiResp); err != nil {
		t.Fatal(err)
	}
	hitsObj := multiResp["hits"].(map[string]any)
	hitsArr := hitsObj["hits"].([]any)
	if len(hitsArr) != 2 || hitsArr[0].(map[string]any)["_id"] != "b1" {
		t.Fatalf("expected multi-index sort by latency desc to return b1 (500) before a1 (100), got: %s", multiBody)
	}
	aggsObj := multiResp["aggregations"].(map[string]any)
	latStats := aggsObj["lat_stats"].(map[string]any)
	if latStats["min"] != float64(100) || latStats["max"] != float64(500) || latStats["avg"] != float64(300) {
		t.Fatalf("expected multi-index stats with empty index to have min=100, max=500, avg=300, got: %+v", latStats)
	}
	bySvc := aggsObj["by_svc"].(map[string]any)["buckets"].([]any)
	if len(bySvc) != 1 {
		t.Fatalf("expected multi-index terms size:1 to cap merged buckets to 1, got: %+v", bySvc)
	}

	// 4. Ingest pipeline execution on PUT /_doc?pipeline=... and POST /_bulk?pipeline=...
	_, _ = doReq(http.MethodPut, "/_ingest/pipeline/enrich", `{
		"description": "normalize and enrich",
		"processors": [
			{"set": {"field": "env", "value": "production"}},
			{"lowercase": {"field": "host"}},
			{"trim": {"field": "msg"}},
			{"rename": {"field": "old_key", "target_field": "new_key"}},
			{"remove": {"field": "secret"}}
		]
	}`)
	if code, body := doReq(http.MethodPut, "/ingest_idx/_doc/p1?pipeline=enrich&refresh=true", `{"host":"WEB-01","msg":"  hello  ","old_key":"val","secret":"dropme"}`); code != http.StatusCreated {
		t.Fatalf("PUT with pipeline failed: %d %s", code, body)
	}
	if code, body := doReq(http.MethodGet, "/ingest_idx/_doc/p1", ""); code != http.StatusOK ||
		!strings.Contains(body, `"env":"production"`) ||
		!strings.Contains(body, `"host":"web-01"`) ||
		!strings.Contains(body, `"msg":"hello"`) ||
		!strings.Contains(body, `"new_key":"val"`) ||
		strings.Contains(body, `"secret"`) {
		t.Fatalf("unexpected document after ingest pipeline: %d %s", code, body)
	}

	// 5. Deep-dive end-to-end regressions in MemoryBackend:
	//    a) Dynamic non-string arrays ("ports": [80, 443]) + idempotent array promotion
	_, _ = doReq(http.MethodPost, "/dyn_arr_idx/_doc/d1?refresh=true", `{"ports":[80,443],"tags":["alpha","beta"],"group":"g1"}`)
	_, _ = doReq(http.MethodPost, "/dyn_arr_idx/_doc/d2?refresh=true", `{"ports":[8080],"tags":["beta","gamma"],"group":"g1"}`)
	code, portSearchBody := doReq(http.MethodPost, "/dyn_arr_idx/_search", `{"query":{"term":{"ports":443}}}`)
	if code != http.StatusOK || !strings.Contains(portSearchBody, `"_id":"d1"`) {
		t.Fatalf("expected dynamic integer array element 443 at index 1 to match d1, got: %d %s", code, portSearchBody)
	}
	// Promote multi-valued field "tags" twice (idempotent + preserves array elements)
	if code, body := doReq(http.MethodPost, "/dyn_arr_idx/_doris/promote", `{"field":"tags","type":"keyword"}`); code != http.StatusOK {
		t.Fatalf("first promote on multi-valued tags failed: %d %s", code, body)
	}
	if code, body := doReq(http.MethodPost, "/dyn_arr_idx/_doris/promote", `{"field":"tags","type":"keyword"}`); code != http.StatusOK {
		t.Fatalf("second idempotent promote on tags failed: %d %s", code, body)
	}
	// Sub-aggregations on multi-valued array column "tags"
	code, subAggBody := doReq(http.MethodPost, "/dyn_arr_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_group": {
				"terms": {"field": "group"},
				"aggs": {
					"tag_terms": {"terms": {"field": "tags"}},
					"tag_card": {"cardinality": {"field": "tags"}},
					"tag_vc": {"value_count": {"field": "tags"}}
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(subAggBody, `"key":"beta"`) || !strings.Contains(subAggBody, `"value":3`) || !strings.Contains(subAggBody, `"value":4`) {
		t.Fatalf("expected multi-valued sub-aggregations on tags to return beta bucket, cardinality=3, value_count=4, got: %d %s", code, subAggBody)
	}

	//    b) Multi-index sub-aggregation min/max/avg + top_hits size cap
	_, _ = doReq(http.MethodPut, "/multi-b/_doc/b2?refresh=true", `{"latency":300,"svc":"api"}`)
	code, multiSubBody := doReq(http.MethodPost, "/multi-a,multi-b/_search", `{
		"size": 0,
		"aggs": {
			"by_svc": {
				"terms": {"field": "svc"},
				"aggs": {
					"min_lat": {"min": {"field": "latency"}},
					"max_lat": {"max": {"field": "latency"}},
					"avg_lat": {"avg": {"field": "latency"}}
				}
			},
			"sample_docs": {
				"top_hits": {"size": 1, "sort": [{"latency": "desc"}]}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("multi-index sub-agg search failed: %d %s", code, multiSubBody)
	}
	var multiSubResp map[string]any
	if err := json.Unmarshal([]byte(multiSubBody), &multiSubResp); err != nil {
		t.Fatal(err)
	}
	topHitsArr := multiSubResp["aggregations"].(map[string]any)["sample_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(topHitsArr) != 1 {
		t.Fatalf("expected multi-index top_hits size:1 to cap hits at 1, got: %+v", topHitsArr)
	}
	bySvcBuckets := multiSubResp["aggregations"].(map[string]any)["by_svc"].(map[string]any)["buckets"].([]any)
	var foundAPI bool
	for _, bRaw := range bySvcBuckets {
		bMap := bRaw.(map[string]any)
		if bMap["key"] == "api" {
			foundAPI = true
			minV := bMap["min_lat"].(map[string]any)["value"]
			maxV := bMap["max_lat"].(map[string]any)["value"]
			avgV := bMap["avg_lat"].(map[string]any)["value"]
			if minV != float64(100) || maxV != float64(300) || avgV != float64(200) {
				t.Fatalf("expected multi-index sub-agg on 'api' to have min=100, max=300, avg=200, got min=%v max=%v avg=%v", minV, maxV, avgV)
			}
		}
	}
	if !foundAPI {
		t.Fatalf("expected 'api' bucket in multi-index sub-agg response: %s", multiSubBody)
	}

	//    c) Nested numeric range (15 >= 10 matches, 2 >= 10 does NOT match lexicographically) & dotted ingest pipeline paths
	_, _ = doReq(http.MethodPut, "/nested_num_idx", `{
		"mappings": {
			"properties": {
				"comments": {
					"type": "nested",
					"properties": {
						"author": {"type": "keyword"},
						"likes": {"type": "integer"}
					}
				}
			}
		}
	}`)
	_, _ = doReq(http.MethodPost, "/nested_num_idx/_doc/n1?refresh=true", `{"comments":[{"author":"Alice","likes":2}]}`)
	_, _ = doReq(http.MethodPost, "/nested_num_idx/_doc/n2?refresh=true", `{"comments":[{"author":"Bob","likes":15}]}`)
	code, nestedRangeBody := doReq(http.MethodPost, "/nested_num_idx/_search", `{
		"query": {
			"nested": {
				"path": "comments",
				"query": {
					"bool": {
						"must": [
							{"range": {"comments.likes": {"gte": 10}}},
							{"term": {"comments.author": {"value": "bob", "case_insensitive": true}}}
						]
					}
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(nestedRangeBody, `"_id":"n2"`) || strings.Contains(nestedRangeBody, `"_id":"n1"`) {
		t.Fatalf("expected nested numeric range likes>=10 to match only n2 (15) and not n1 (2), got: %d %s", code, nestedRangeBody)
	}

	// Dotted nested ingest pipeline paths
	_, _ = doReq(http.MethodPut, "/_ingest/pipeline/dotted-pipe", `{
		"processors": [
			{"set": {"field": "service.env", "value": "staging"}},
			{"lowercase": {"field": "service.name"}},
			{"rename": {"field": "service.old", "target_field": "service.new"}},
			{"remove": {"field": "service.secret"}}
		]
	}`)
	if code, body := doReq(http.MethodPut, "/ingest_idx/_doc/p2?pipeline=dotted-pipe&refresh=true", `{"service":{"name":"BILLING","old":"v1","secret":"tok"}}`); code != http.StatusCreated {
		t.Fatalf("PUT with dotted ingest pipeline failed: %d %s", code, body)
	}
	if code, body := doReq(http.MethodGet, "/ingest_idx/_doc/p2", ""); code != http.StatusOK ||
		!strings.Contains(body, `"env":"staging"`) ||
		!strings.Contains(body, `"name":"billing"`) ||
		!strings.Contains(body, `"new":"v1"`) ||
		strings.Contains(body, `"secret"`) {
		t.Fatalf("unexpected document after dotted ingest pipeline: %d %s", code, body)
	}
}

func TestServer_DeepEvalProtocolAndMultiIndexFixes(t *testing.T) {
	srv := NewServer("logs_db", NewMemoryBackend(true), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// 1. normalizeDorisSQL replaces '\x1f' with CHAR(31)
	normSQL := normalizeDorisSQL("SELECT CONCAT(a, '\x1f', b) FROM t")
	if !strings.Contains(normSQL, "CHAR(31)") {
		t.Fatalf("expected normalizeDorisSQL to replace '\\x1f' with CHAR(31), got %q", normSQL)
	}

	// 2. PUT /{index}/_create/{id} and ?op_type=create return 409 Conflict on duplicate
	if code, body := doReq(http.MethodPut, "/create_idx/_create/c1?refresh=true", `{"msg":"first"}`); code != http.StatusCreated {
		t.Fatalf("expected 201 Created on first _create, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodPut, "/create_idx/_create/c1?refresh=true", `{"msg":"second"}`); code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on duplicate _create, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodPut, "/create_idx/_doc/c1?op_type=create&refresh=true", `{"msg":"third"}`); code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on duplicate ?op_type=create, got %d %s", code, body)
	}

	// 3. POST /{index}/_doc/_search and /{index}/_doc/_count route to search/count instead of indexing _id="_search"
	if code, body := doReq(http.MethodPost, "/create_idx/_doc/_search", `{"query":{"match_all":{}}}`); code != http.StatusOK || !strings.Contains(body, `"hits"`) {
		t.Fatalf("expected POST /{index}/_doc/_search to execute search, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodPost, "/create_idx/_doc/_count", `{"query":{"match_all":{}}}`); code != http.StatusOK || !strings.Contains(body, `"count":1`) {
		t.Fatalf("expected POST /{index}/_doc/_count to return count:1, got %d %s", code, body)
	}

	// 4. Pagination past end (from >= total_hits) preserves true hits.total.value
	if code, body := doReq(http.MethodPost, "/create_idx/_search", `{"from":50,"size":10,"query":{"match_all":{}}}`); code != http.StatusOK || !strings.Contains(body, `"value":1`) {
		t.Fatalf("expected from>=total_hits to preserve total.value=1, got %d %s", code, body)
	}

	// 5. Wildcard highlight ("*") + no <em> tag corruption when query contains "em"
	_, _ = doReq(http.MethodPut, "/hl_idx/_doc/h1?refresh=true", `{"title":"system emerald gem"}`)
	if code, body := doReq(http.MethodPost, "/hl_idx/_search", `{
		"query": {"match": {"title": "system em"}},
		"highlight": {"fields": {"*": {}}}
	}`); code != http.StatusOK || !strings.Contains(body, `\u003cem\u003esystem\u003c/em\u003e \u003cem\u003eem\u003c/em\u003eerald g\u003cem\u003eem\u003c/em\u003e`) {
		t.Fatalf("expected wildcard highlight without <em> tag corruption, got %d %s", code, body)
	}

	// 6. Multi-index stats weighted average, post_filter preserving aggs, _msearch indices array, and wildcard _mapping/_delete
	_, _ = doReq(http.MethodPut, "/m_idx_1/_doc/1?refresh=true", `{"env":"prod","latency":10}`)
	_, _ = doReq(http.MethodPut, "/m_idx_2/_doc/2?refresh=true", `{"env":"prod","latency":20}`)
	_, _ = doReq(http.MethodPut, "/m_idx_2/_doc/3?refresh=true", `{"env":"staging","latency":30}`)

	if code, body := doReq(http.MethodPost, "/m_idx_*/_search", `{
		"post_filter": {"term": {"env": "staging"}},
		"aggs": {
			"by_env": {"terms": {"field": "env"}},
			"lat_stats": {"stats": {"field": "latency"}}
		}
	}`); code != http.StatusOK || !strings.Contains(body, `"avg":20`) || !strings.Contains(body, `"doc_count":2,"key":"prod"`) {
		t.Fatalf("expected multi-index post_filter to preserve aggs across all indices and compute weighted stats avg=20, got %d %s", code, body)
	}

	if code, body := doReq(http.MethodPost, "/_msearch", `{"indices":["m_idx_1","m_idx_2"]}`+"\n"+`{"query":{"match_all":{}}}`+"\n"); code != http.StatusOK || !strings.Contains(body, `"value":3`) {
		t.Fatalf("expected _msearch with indices array to query both indices (total=3), got %d %s", code, body)
	}

	if code, body := doReq(http.MethodGet, "/m_idx_*/_mapping", ""); code != http.StatusOK || !strings.Contains(body, `"m_idx_1"`) || !strings.Contains(body, `"m_idx_2"`) {
		t.Fatalf("expected wildcard _mapping to return both m_idx_1 and m_idx_2, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodGet, "/_cat/indices/m_idx_*", ""); code != http.StatusOK || !strings.Contains(body, `"m_idx_1"`) || strings.Contains(body, `"create_idx"`) {
		t.Fatalf("expected /_cat/indices/m_idx_* to filter indices, got %d %s", code, body)
	}

	// 7. Auto-created destination index on _update (doc_as_upsert) and _reindex infers schema
	if code, body := doReq(http.MethodPost, "/up_auto_idx/_update/u1?refresh=true", `{"doc":{"score":42,"tag":"alpha"},"doc_as_upsert":true}`); code != http.StatusCreated || !strings.Contains(body, `"result":"created"`) {
		t.Fatalf("expected _update doc_as_upsert to return 201 created, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodPost, "/_reindex", `{"source":{"index":"up_auto_idx"},"dest":{"index":"reindexed_auto_idx"}}`); code != http.StatusOK {
		t.Fatalf("expected _reindex to succeed, got %d %s", code, body)
	}
	if code, body := doReq(http.MethodGet, "/reindexed_auto_idx/_mapping", ""); code != http.StatusOK || !strings.Contains(body, `"score"`) {
		t.Fatalf("expected _reindex into new index to infer dynamic mapping for 'score', got %d %s", code, body)
	}

	if code, body := doReq(http.MethodDelete, "/m_idx_*", ""); code != http.StatusOK {
		t.Fatalf("expected wildcard DELETE /m_idx_* to succeed, got %d %s", code, body)
	}
}

func TestObservabilityTracePropagationStreamLoadRetryAndHelmChart(t *testing.T) {
	// 1. SQL Trace comment propagation & sanitization
	ctx := WithTraceMeta(context.Background(), TraceMeta{
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		OpaqueID:    "kibana-dash-1*/;DROP",
		RequestID:   "req-99",
	})
	commented := prependSQLTraceComment(ctx, "SELECT * FROM `t`")
	if !strings.HasPrefix(commented, "/* traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01, opaque_id=kibana-dash-1DROP, request_id=req-99 */ SELECT * FROM `t`") {
		t.Fatalf("unexpected prependSQLTraceComment output: %q", commented)
	}

	// 2. HTTP middleware header propagation & echoing
	srv := NewServer("logs_db", NewMemoryBackend(true), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/_cluster/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Opaque-Id", "opq-123")
	req.Header.Set("X-Request-ID", "req-456")
	req.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("X-Opaque-Id") != "opq-123" ||
		resp.Header.Get("X-Request-ID") != "req-456" ||
		resp.Header.Get("traceparent") != "00-11111111111111111111111111111111-2222222222222222-01" {
		t.Fatalf("expected X-Opaque-Id, X-Request-ID, and traceparent headers to be echoed, got %+v", resp.Header)
	}

	// 3. StreamLoadClient transient retry backoff (503 -> TOO_MANY_VERSIONS -> Success)
	var attempts int32
	slServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("BE overloaded"))
		case 2:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Status":"Fail","Message":"TOO_MANY_VERSIONS on tablet 1001"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1,"NumberFilteredRows":0}`))
		}
	}))
	defer slServer.Close()

	slClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: slServer.URL,
		User:           "root",
		Database:       "logs_db",
		Timeout:        5 * time.Second,
	})
	if err := slClient.LoadNDJSON(context.Background(), "app_logs", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected StreamLoadClient to succeed after transient retries, got: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 StreamLoad attempts, got %d", got)
	}

	// 4. Verify Helm chart files exist and contain required K8s manifests
	helmFiles := []string{
		"../../deploy/helm/doris-es-proxy/Chart.yaml",
		"../../deploy/helm/doris-es-proxy/values.yaml",
		"../../deploy/helm/doris-es-proxy/templates/_helpers.tpl",
		"../../deploy/helm/doris-es-proxy/templates/deployment.yaml",
		"../../deploy/helm/doris-es-proxy/templates/service.yaml",
		"../../deploy/helm/doris-es-proxy/templates/hpa.yaml",
		"../../deploy/helm/doris-es-proxy/templates/pdb.yaml",
		"../../deploy/helm/doris-es-proxy/templates/servicemonitor.yaml",
	}
	for _, hf := range helmFiles {
		raw, err := os.ReadFile(hf)
		if err != nil || len(raw) == 0 {
			t.Fatalf("expected Helm chart file %q to exist and be non-empty: %v", hf, err)
		}
	}
}

func TestClientSDKKibanaDiscoverAndGrafanaLogsCompat(t *testing.T) {
	srv := NewServer("logs_db", NewMemoryBackend(true), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doSDKReq := func(method, path, body string) (*http.Response, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=8")
		req.Header.Set("Content-Type", "application/vnd.elasticsearch+json; compatible-with=8")
		req.Header.Set("X-Elastic-Client-Meta", "es=8.15.0p,go=1.25.0")
		req.Header.Set("X-Opaque-Id", "grafana-kibana-sdk-e2e")
		req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(raw)
	}

	// 1. Official go-elasticsearch v8 / elasticsearch-py v8 preflight & product check
	resp, body := doSDKReq(http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK ||
		resp.Header.Get("X-Elastic-Product") != "Elasticsearch" ||
		resp.Header.Get("Content-Type") != "application/vnd.elasticsearch+json; compatible-with=8" ||
		resp.Header.Get("X-Opaque-Id") != "grafana-kibana-sdk-e2e" {
		t.Fatalf("unexpected SDK root handshake headers/status: status=%d headers=%+v body=%s", resp.StatusCode, resp.Header, body)
	}

	// 2. Create index & ingest structured log documents via _bulk
	resp, body = doSDKReq(http.MethodPut, "/logs-k8s-2026.10", `{
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"service": {"type": "keyword"},
				"status": {"type": "integer"},
				"message": {"type": "text"}
			}
		}
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create index failed: %d %s", resp.StatusCode, body)
	}

	bulkPayload := strings.Join([]string{
		`{"index":{"_id":"doc-1"}}`,
		`{"@timestamp":"2026-10-25T10:15:00Z","service":"checkout","status":500,"message":"database connection timeout","host":{"name":"node-a"}}`,
		`{"index":{"_id":"doc-2"}}`,
		`{"@timestamp":"2026-10-25T10:15:00Z","service":"payments","status":200,"message":"payment processed timeout retry","host":{"name":"node-b"}}`,
		"",
	}, "\n")
	resp, body = doSDKReq(http.MethodPost, "/logs-k8s-2026.10/_bulk?refresh=true", bulkPayload)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `"errors":true`) {
		t.Fatalf("bulk ingest failed: %d %s", resp.StatusCode, body)
	}

	// Verify GET /{index}/_source/{id} preserves compatible-with=8 media type
	resp, body = doSDKReq(http.MethodGet, "/logs-k8s-2026.10/_source/doc-1", "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/vnd.elasticsearch+json; compatible-with=8" || !strings.Contains(body, `"checkout"`) {
		t.Fatalf("expected _source to preserve compatible-with=8 Content-Type, got status=%d ct=%q body=%s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	// 3. Grafana Elasticsearch Data Source & Logs Panel _msearch workflow:
	//    - sort by @timestamp desc and _doc desc (must map _doc -> _id, not VARIANT _doc)
	//    - docvalue_fields with epoch_millis format
	//    - wildcard highlight with custom @HIGHLIGHT@ tags
	//    - date_histogram with extended_bounds & min_doc_count: 0
	msearchBody := strings.Join([]string{
		`{"index":"logs-k8s-*","search_type":"query_then_fetch","ignore_unavailable":true}`,
		`{"size":500,"query":{"query_string":{"query":"timeout"}},"sort":[{"@timestamp":{"order":"desc","unmapped_type":"boolean"}},{"_doc":{"order":"desc"}}],"docvalue_fields":[{"field":"@timestamp","format":"epoch_millis"}],"highlight":{"pre_tags":["@HIGHLIGHT@"],"post_tags":["@/HIGHLIGHT@"],"fields":{"*":{}}}}`,
		`{"index":"logs-k8s-*","search_type":"query_then_fetch","ignore_unavailable":true}`,
		`{"size":0,"query":{"query_string":{"query":"timeout"}},"aggs":{"2":{"date_histogram":{"field":"@timestamp","fixed_interval":"1h","min_doc_count":0,"extended_bounds":{"min":"2026-10-25T10:00:00Z","max":"2026-10-25T12:00:00Z"}}}}}`,
		"",
	}, "\n")
	resp, body = doSDKReq(http.MethodPost, "/_msearch?max_concurrent_shard_requests=5", msearchBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Grafana _msearch failed: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"sort":[1792923300000,"doc-2"]`) ||
		!strings.Contains(body, `"fields":{"@timestamp":[1792923300000]}`) ||
		!strings.Contains(body, `@HIGHLIGHT@timeout@/HIGHLIGHT@`) {
		t.Fatalf("expected Grafana Logs _doc tie-breaker sort, epoch_millis docvalue_fields, and @HIGHLIGHT@ tags, got: %s", body)
	}

	// 4. Kibana / OpenSearch Dashboards Discover workflow:
	//    - GET /_resolve/index/logs-k8s-*
	//    - POST /logs-k8s-*/_field_caps?fields=* with JSON body {"fields":["@timestamp","service"]}
	//    - GET /logs-k8s-2026.10/_mapping/field/@timestamp,service and GET /_mapping/field/@timestamp
	//    - POST /logs-k8s-*/_search with "fields": [{"field":"*","include_unmapped":"true"},{"field":"@timestamp"}]
	resp, body = doSDKReq(http.MethodGet, "/_resolve/index/logs-k8s-*", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"logs-k8s-2026.10"`) {
		t.Fatalf("Kibana _resolve/index failed: %d %s", resp.StatusCode, body)
	}

	resp, body = doSDKReq(http.MethodPost, "/logs-k8s-*/_field_caps?fields=*", `{"fields":["@timestamp","service"]}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"@timestamp"`) || !strings.Contains(body, `"service"`) || strings.Contains(body, `"status"`) {
		t.Fatalf("Kibana POST _field_caps body filter failed: %d %s", resp.StatusCode, body)
	}

	resp, body = doSDKReq(http.MethodGet, "/logs-k8s-2026.10/_mapping/field/@timestamp,service", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"full_name":"@timestamp"`) || !strings.Contains(body, `"full_name":"service"`) {
		t.Fatalf("Kibana GET /{index}/_mapping/field/{fields} failed: %d %s", resp.StatusCode, body)
	}

	resp, body = doSDKReq(http.MethodGet, "/_mapping/field/@timestamp", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"full_name":"@timestamp"`) {
		t.Fatalf("Kibana GET /_mapping/field/{fields} failed: %d %s", resp.StatusCode, body)
	}

	resp, body = doSDKReq(http.MethodPost, "/logs-k8s-*/_search", `{
		"size": 10,
		"_source": false,
		"fields": [
			{"field": "*", "include_unmapped": "true"},
			{"field": "@timestamp", "format": "strict_date_optional_time"},
			"_id"
		],
		"sort": [{"@timestamp": "desc"}, "_doc"]
	}`)
	if resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, `"host.name":["node-a"]`) ||
		!strings.Contains(body, `"service":["checkout"]`) ||
		!strings.Contains(body, `"_id":["doc-1"]`) {
		t.Fatalf("Kibana Discover fields extraction failed: %d %s", resp.StatusCode, body)
	}
}

func TestBulkCoalescerAndQueryResultCache(t *testing.T) {
	srv := NewServer("logs_db", NewMemoryBackend(true), transpiler.TranspilerOptions{})
	srv.SetBulkCoalesce(80*time.Millisecond, 64*1024)
	srv.SetQueryCacheTTL(5*time.Second, 8)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(raw)
	}

	// Pre-create index so all 8 concurrent goroutines hit StreamLoadCoalescer simultaneously
	if code, body := doReq(http.MethodPut, "/coalesce_idx", `{"mappings":{"properties":{"service":{"type":"keyword"},"seq":{"type":"integer"}}}}`); code != http.StatusOK {
		t.Fatalf("create coalesce_idx failed: %d %s", code, body)
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		idx := i
		go func() {
			defer wg.Done()
			code, body := doReq(
				http.MethodPut,
				fmt.Sprintf("/coalesce_idx/_doc/doc-%d", idx),
				fmt.Sprintf(`{"service":"ingest","seq":%d}`, idx),
			)
			if code != http.StatusCreated {
				errs <- fmt.Errorf("worker %d got HTTP %d: %s", idx, code, body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	coalescedReqs, coalescedFlushes := srv.coalescer.Stats()
	if coalescedReqs != workers || coalescedFlushes < 1 || coalescedFlushes >= workers {
		t.Fatalf("expected %d concurrent writes to coalesce into < %d flushes, got reqs=%d flushes=%d",
			workers, workers, coalescedReqs, coalescedFlushes)
	}

	// Verify QueryResultCache miss -> hit -> automatic write invalidation
	searchPayload := `{"query":{"term":{"service":"ingest"}},"aggs":{"max_seq":{"max":{"field":"seq"}}}}`
	if code, body := doReq(http.MethodPost, "/coalesce_idx/_search", searchPayload); code != http.StatusOK || !strings.Contains(body, `"value":8`) {
		t.Fatalf("expected 8 hits on first search, got %d %s", code, body)
	}
	hits1, misses1 := srv.queryCache.Stats()
	if hits1 != 0 || misses1 != 1 {
		t.Fatalf("expected 0 hits / 1 miss after first query, got hits=%d misses=%d", hits1, misses1)
	}

	if code, body := doReq(http.MethodPost, "/coalesce_idx/_search", searchPayload); code != http.StatusOK || !strings.Contains(body, `"value":8`) {
		t.Fatalf("expected 8 hits on cached search, got %d %s", code, body)
	}
	hits2, misses2 := srv.queryCache.Stats()
	if hits2 != 1 || misses2 != 1 {
		t.Fatalf("expected 1 hit / 1 miss after second query, got hits=%d misses=%d", hits2, misses2)
	}

	// Write a 9th document with ?refresh=true (immediate flush + cache invalidation)
	if code, body := doReq(http.MethodPut, "/coalesce_idx/_doc/doc-8?refresh=true", `{"service":"ingest","seq":8}`); code != http.StatusCreated {
		t.Fatalf("expected 201 Created on doc-8, got %d %s", code, body)
	}

	// Next search must see 9 documents immediately (cache invalidated by write)
	if code, body := doReq(http.MethodPost, "/coalesce_idx/_search", searchPayload); code != http.StatusOK || !strings.Contains(body, `"value":9`) {
		t.Fatalf("expected 9 hits after write invalidation, got %d %s", code, body)
	}

	// Verify Prometheus /metrics exports coalescer & query cache counters
	if code, body := doReq(http.MethodGet, "/metrics", ""); code != http.StatusOK ||
		!strings.Contains(body, "doris_es_proxy_bulk_coalesced_requests_total 9") ||
		!strings.Contains(body, "doris_es_proxy_query_cache_hits_total 1") ||
		!strings.Contains(body, "doris_es_proxy_query_cache_misses_total 2") {
		t.Fatalf("expected /metrics to report coalescer and query cache counters, got %d:\n%s", code, body)
	}
}

func TestInboundAuthMiddlewareAndRound3DeepEvalFixes(t *testing.T) {
	srv := NewServer("logs_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetAuth("elastic", "s3cr3t!", "my-raw-api-key")
	srv.SetQueryCacheTTL(10*time.Second, 32)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doAuthReq := func(method, path, authHeader, body string) (*http.Response, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(raw)
	}

	// 1. Public Kubernetes probes (/healthz, /readyz) and OPTIONS preflight bypass auth
	if resp, _ := doAuthReq(http.MethodGet, "/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /healthz to bypass auth and return 200, got %d", resp.StatusCode)
	}
	if resp, _ := doAuthReq(http.MethodGet, "/readyz", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /readyz to bypass auth and return 200, got %d", resp.StatusCode)
	}
	if resp, _ := doAuthReq(http.MethodOptions, "/_search", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OPTIONS preflight to bypass auth and return 200, got %d", resp.StatusCode)
	}

	// 2. Unauthenticated or invalid credentials return 401 security_exception with WWW-Authenticate
	if resp, body := doAuthReq(http.MethodGet, "/", "", ""); resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(body, `"security_exception"`) ||
		!strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("expected 401 security_exception for unauthenticated GET /, got %d %s", resp.StatusCode, body)
	}
	badBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:wrong"))
	if resp, _ := doAuthReq(http.MethodGet, "/", badBasic, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong Basic Auth password, got %d", resp.StatusCode)
	}
	if resp, _ := doAuthReq(http.MethodGet, "/", "ApiKey wrong-key", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong ApiKey, got %d", resp.StatusCode)
	}

	// 3. Valid Basic Auth, raw ApiKey, base64(id:apiKey) ApiKey, and Bearer token all succeed
	goodBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:s3cr3t!"))
	if resp, body := doAuthReq(http.MethodGet, "/_security/_authenticate", goodBasic, ""); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, `"username":"elastic"`) {
		t.Fatalf("expected 200 from /_security/_authenticate with Basic Auth, got %d %s", resp.StatusCode, body)
	}
	if resp, _ := doAuthReq(http.MethodGet, "/", "ApiKey my-raw-api-key", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with raw ApiKey, got %d", resp.StatusCode)
	}
	b64IDKey := base64.StdEncoding.EncodeToString([]byte("key-id-1:my-raw-api-key"))
	if resp, _ := doAuthReq(http.MethodGet, "/", "ApiKey "+b64IDKey, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with base64(id:apiKey), got %d", resp.StatusCode)
	}
	if resp, _ := doAuthReq(http.MethodGet, "/", "Bearer my-raw-api-key", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with Bearer token, got %d", resp.StatusCode)
	}

	// 4. Create two indices behind a shared alias (`logs_all`) with `updatedAt: long` and `created_at: date`
	mappingJSON := `{
		"aliases": {"logs_all": {}},
		"mappings": {
			"properties": {
				"service": {"type": "keyword"},
				"env": {"type": "keyword"},
				"updatedAt": {"type": "long"},
				"created_at": {"type": "date"},
				"latency": {"type": "double"}
			}
		}
	}`
	if resp, body := doAuthReq(http.MethodPut, "/logs_p1", goodBasic, mappingJSON); resp.StatusCode != http.StatusOK {
		t.Fatalf("create logs_p1 failed: %d %s", resp.StatusCode, body)
	}
	if resp, body := doAuthReq(http.MethodPut, "/logs_p2", goodBasic, mappingJSON); resp.StatusCode != http.StatusOK {
		t.Fatalf("create logs_p2 failed: %d %s", resp.StatusCode, body)
	}

	// Verify GET /logs_all/_mapping returns both indices (`logs_p1` and `logs_p2`)
	if resp, body := doAuthReq(http.MethodGet, "/logs_all/_mapping", goodBasic, ""); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, `"logs_p1"`) || !strings.Contains(body, `"logs_p2"`) {
		t.Fatalf("expected GET /logs_all/_mapping to return both target indices, got %d %s", resp.StatusCode, body)
	}

	// Verify _field_caps and _mapping/field preserve `updatedAt` as `long` (not `date`)
	if resp, body := doAuthReq(http.MethodGet, "/logs_p1/_mapping/field/updatedAt,created_at", goodBasic, ""); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, `"updatedAt":{"type":"long"}`) || !strings.Contains(body, `"created_at":{"type":"date"}`) {
		t.Fatalf("expected updatedAt=long and created_at=date in field mapping, got %d %s", resp.StatusCode, body)
	}

	// 5. Index documents into logs_p1 ( leaving logs_p2 empty) to test:
	//    - collapse preserving pre-collapse total hits
	//    - scroll pagination on QueryResultCache hit
	//    - terms missing, composite after, histogram extended_bounds + min_doc_count: 0
	//    - fields wildcard + explicit format override + numeric epoch-millis date formatting
	bulkDocs := strings.Join([]string{
		`{"index":{"_index":"logs_p1","_id":"1"}}`,
		`{"service":"checkout","env":"prod","updatedAt":100,"created_at":1700000000000,"latency":10}`,
		`{"index":{"_index":"logs_p1","_id":"2"}}`,
		`{"service":"checkout","env":"staging","updatedAt":200,"created_at":1700003600000,"latency":30}`,
		`{"index":{"_index":"logs_p1","_id":"3"}}`,
		`{"service":"payments","updatedAt":300,"created_at":1700007200000,"latency":50}`,
	}, "\n") + "\n"
	if resp, body := doAuthReq(http.MethodPost, "/_bulk?refresh=true", goodBasic, bulkDocs); resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk failed: %d %s", resp.StatusCode, body)
	}

	// Collapse on `service` (3 total matching docs collapsed into 2 distinct services): hits.total.value must be 3
	collapseReq := `{"size":10,"collapse":{"field":"service"},"sort":[{"updatedAt":"desc"}]}`
	if resp, body := doAuthReq(http.MethodPost, "/logs_p1/_search", goodBasic, collapseReq); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, `"value":3`) {
		t.Fatalf("expected collapse to preserve pre-collapse total.value=3, got %d %s", resp.StatusCode, body)
	}

	// Scroll on QueryResultCache hit: prime cache first, then call ?scroll=1m with same request
	scrollInitReq := `{"size":2,"sort":[{"_id":"asc"}]}`
	_, _ = doAuthReq(http.MethodPost, "/logs_p1/_search", goodBasic, scrollInitReq)
	resp, scrollBody := doAuthReq(http.MethodPost, "/logs_p1/_search?scroll=1m", goodBasic, scrollInitReq)
	if resp.StatusCode != http.StatusOK || strings.Contains(scrollBody, `"_scroll_id":"doris-scroll-eof"`) {
		t.Fatalf("expected valid _scroll_id on cached scroll search, got %d %s", resp.StatusCode, scrollBody)
	}

	// Terms `missing`, Composite `after`, Histogram `min_doc_count: 0` + `extended_bounds`, and `fields` formatting
	aggsAndFieldsReq := `{
		"size": 1,
		"sort": [{"_id": "asc"}],
		"fields": [
			"*",
			{"field": "created_at", "format": "epoch_second"}
		],
		"aggs": {
			"env_with_missing": {
				"terms": {"field": "env", "missing": "MISSING_ENV"}
			},
			"comp_after": {
				"composite": {
					"sources": [{"service": {"terms": {"field": "service"}}}],
					"after": {"service": "checkout"}
				}
			},
			"lat_hist": {
				"histogram": {
					"field": "latency",
					"interval": 20,
					"min_doc_count": 0,
					"extended_bounds": {"min": 0, "max": 60}
				}
			}
		}
	}`
	resp, aggBody := doAuthReq(http.MethodPost, "/logs_all/_search", goodBasic, aggsAndFieldsReq)
	if resp.StatusCode != http.StatusOK ||
		!strings.Contains(aggBody, `"key":"MISSING_ENV"`) ||
		!strings.Contains(aggBody, `"service":"payments"`) ||
		!strings.Contains(aggBody, `"created_at":[1700000000]`) ||
		!strings.Contains(aggBody, `"doc_count":0,"key":60`) {
		t.Fatalf("expected missing bucket, composite after, epoch_second field override, and zero-count histogram bucket, got %d %s", resp.StatusCode, aggBody)
	}
}
