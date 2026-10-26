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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
