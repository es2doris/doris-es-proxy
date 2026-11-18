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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type roundTripperFuncRound61 func(*http.Request) (*http.Response, error)

func (f roundTripperFuncRound61) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newRound61TestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	return srv, srv.Handler()
}

func doRound61Req(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	if len(bytes.TrimSpace(rec.Body.Bytes())) > 0 && strings.Contains(rec.Header().Get("Content-Type"), "json") {
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&m)
	}
	return rec, m
}

func TestRound61TasksIngest_SQLParamsInjectionFix(t *testing.T) {
	t.Parallel()

	// 1. Direct unit test of substituteSQLParams for Doris MySQL-mode backslash+quote breakout.
	got, err := substituteSQLParams("SELECT * FROM users WHERE name = ?", []any{`\' OR 1=1 --`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `SELECT * FROM users WHERE name = '\\'' OR 1=1 --'`
	if got != want {
		t.Fatalf("SQLi escaping mismatch:\n got: %s\nwant: %s", got, want)
	}

	// Null byte stripping + double backslash escaping.
	got2, err := substituteSQLParams("SELECT ?", []any{"ab\x00c\\d'ef"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2 != `SELECT 'abc\\d''ef'` {
		t.Fatalf("unexpected escaped output: %s", got2)
	}

	// Non-finite floats must be rejected rather than emitting bare NaN/Inf tokens.
	for _, bad := range []any{math.NaN(), math.Inf(1), math.Inf(-1), float32(math.NaN()), float32(math.Inf(1)), json.Number("NaN"), json.Number("Inf")} {
		if _, err := substituteSQLParams("SELECT ?", []any{bad}); err == nil {
			t.Fatalf("expected error for non-finite param %v (%T)", bad, bad)
		}
	}

	// 2. End-to-end POST /_sql parameterized query test ensuring `\' OR 1=1 --` cannot bypass WHERE.
	_, h := newRound61TestServer(t)
	rec, _ := doRound61Req(t, h, http.MethodPut, "/users/_doc/1?refresh=true", `{"name":"alice","role":"admin"}`, nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("seed doc 1 failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/users/_doc/2?refresh=true", `{"name":"bob","role":"viewer"}`, nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("seed doc 2 failed: %d %s", rec.Code, rec.Body.String())
	}

	sqlPayload := `{"query":"SELECT name, role FROM users WHERE name = ?","params":["\\' OR 1=1 --"]}`
	rec, sqlResp := doRound61Req(t, h, http.MethodPost, "/_sql?format=json", sqlPayload, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /_sql, got %d: %s", rec.Code, rec.Body.String())
	}
	rows, _ := sqlResp["rows"].([]any)
	if len(rows) != 0 {
		t.Fatalf("SQL injection bypassed WHERE filter! returned rows: %#v", rows)
	}
}

func TestRound61TasksIngest_MigrationAndTermVectors(t *testing.T) {
	t.Parallel()
	_, h := newRound61TestServer(t)

	// F4: /_migration/system_features includes migration_status: NO_MIGRATION_NEEDED
	rec, mig := doRound61Req(t, h, http.MethodGet, "/_migration/system_features", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /_migration/system_features, got %d: %s", rec.Code, rec.Body.String())
	}
	if mig["migration_status"] != "NO_MIGRATION_NEEDED" {
		t.Fatalf("expected migration_status=NO_MIGRATION_NEEDED, got %#v", mig["migration_status"])
	}

	// Seed index + document for _termvectors / _mtermvectors
	rec, _ = doRound61Req(t, h, http.MethodPut, "/tv_idx/_doc/1?refresh=true", `{"text":"alpha alpha alpha beta beta gamma tiny supercalifragilistic"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed tv_idx failed: %d %s", rec.Code, rec.Body.String())
	}

	// F19: Transient `doc` without `_id` + `filter` options
	tvBody := `{
		"doc": {"text": "alpha alpha alpha beta beta gamma a longwordexceedinglimit"},
		"fields": ["text"],
		"term_statistics": true,
		"filter": {
			"min_term_freq": 2,
			"min_word_length": 4,
			"max_word_length": 10,
			"max_num_terms": 1
		}
	}`
	rec, tvResp := doRound61Req(t, h, http.MethodPost, "/tv_idx/_termvectors", tvBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("transient _termvectors failed: %d %s", rec.Code, rec.Body.String())
	}
	if tvResp["found"] != true {
		t.Fatalf("expected found=true for transient doc, got %#v", tvResp)
	}
	tvMap, _ := tvResp["term_vectors"].(map[string]any)
	textTV, _ := tvMap["text"].(map[string]any)
	termsMap, _ := textTV["terms"].(map[string]any)
	if len(termsMap) != 1 || termsMap["alpha"] == nil {
		t.Fatalf("expected filtered terms to keep only 'alpha', got %#v", termsMap)
	}

	// F19: version=0 returns 400 illegal_argument_exception
	rec, _ = doRound61Req(t, h, http.MethodGet, "/tv_idx/_termvectors/1?version=0&version_type=external", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for version=0 on _termvectors, got %d: %s", rec.Code, rec.Body.String())
	}

	// F19: _mtermvectors combining top-level `ids` + `docs` + missing doc (`found: false`) + per-item error without failing batch
	mtvBody := `{
		"ids": ["1", "missing_id"],
		"docs": [
			{"_index": "tv_idx", "doc": {"text": "transient hello world"}},
			{"_index": "no_such_index_mtv", "_id": "1"}
		]
	}`
	rec, mtvResp := doRound61Req(t, h, http.MethodPost, "/tv_idx/_mtermvectors", mtvBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on _mtermvectors, got %d: %s", rec.Code, rec.Body.String())
	}
	docsArr, _ := mtvResp["docs"].([]any)
	if len(docsArr) != 4 {
		t.Fatalf("expected 4 responses in _mtermvectors, got %d: %#v", len(docsArr), docsArr)
	}
	item1, _ := docsArr[1].(map[string]any)
	if item1["error"] == nil {
		t.Fatalf("expected per-item error for missing index in _mtermvectors, got %#v", item1)
	}
	item3, _ := docsArr[3].(map[string]any)
	if item3["found"] != false {
		t.Fatalf("expected missing_id found=false, got %#v", item3)
	}
}

func TestRound61TasksIngest_CatResolveUpgradeShardStores(t *testing.T) {
	t.Parallel()
	srv, h := newRound61TestServer(t)

	// Create visible index with 1 replica (triggers UNASSIGNED replica on 1-node cluster) and a .hidden index
	rec, _ := doRound61Req(t, h, http.MethodPut, "/vis_idx", `{"settings":{"number_of_shards":1,"number_of_replicas":1}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create vis_idx failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/.secret_hidden", `{"settings":{"hidden":true}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create .secret_hidden failed: %d %s", rec.Code, rec.Body.String())
	}

	// F2: _cat/allocation?bytes=mb&format=json includes UNASSIGNED row
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/allocation?bytes=mb&format=json", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "UNASSIGNED") {
		t.Fatalf("expected UNASSIGNED row in _cat/allocation, got %d: %s", rec.Code, rec.Body.String())
	}

	// F2: _cat/nodes 4-char short id unless full_id=true + ES 8 cdfhilmrstw roles
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/nodes?h=id,node.role&format=json", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_cat/nodes failed: %d %s", rec.Code, rec.Body.String())
	}
	var nodeRows []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &nodeRows)
	if len(nodeRows) == 0 {
		t.Fatalf("expected at least 1 row in _cat/nodes")
	}
	shortID, _ := nodeRows[0]["id"].(string)
	if len(shortID) != 4 {
		t.Fatalf("expected 4-char node id by default, got %q", shortID)
	}
	if role, _ := nodeRows[0]["node.role"].(string); role != "cdfhilmrstw" {
		t.Fatalf("expected ES 8 node.role=cdfhilmrstw, got %q", role)
	}
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/nodes?full_id=true&h=id&format=json", "", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &nodeRows)
	if fullID, _ := nodeRows[0]["id"].(string); len(fullID) <= 4 {
		t.Fatalf("expected full node id when full_id=true, got %q", fullID)
	}

	// F2: _cat/shards?expand_wildcards=hidden excludes visible indices & includes .secret_hidden
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/shards?expand_wildcards=hidden&format=json", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ".secret_hidden") || strings.Contains(rec.Body.String(), "vis_idx") {
		t.Fatalf("unexpected _cat/shards?expand_wildcards=hidden output: %d %s", rec.Code, rec.Body.String())
	}

	// F2: _cat/tasks with x_opaque_id, description & _cat/thread_pool extended columns
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/tasks?h=action,x_opaque_id,description&format=json", "", map[string]string{"X-Opaque-Id": "op-61"})
	if rec.Code != http.StatusOK {
		t.Fatalf("_cat/tasks failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_cat/thread_pool?h=node_name,name,active,queue,rejected,completed,core,max,size,keep_alive&format=json", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_cat/thread_pool failed: %d %s", rec.Code, rec.Body.String())
	}

	// F2: repo-less GET /_cat/snapshots + ignore_unavailable=true via handleCatSnapshotsRound61
	snapReq := httptest.NewRequest(http.MethodGet, "/_cat/snapshots?format=json", nil)
	snapRec := httptest.NewRecorder()
	srv.handleCatSnapshotsRound61(snapRec, snapReq)
	if snapRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on repo-less /_cat/snapshots, got %d: %s", snapRec.Code, snapRec.Body.String())
	}
	missRepoReq := httptest.NewRequest(http.MethodGet, "/_cat/snapshots/missing_repo?ignore_unavailable=true&format=json", nil)
	missRepoReq.SetPathValue("repository", "missing_repo")
	missRepoRec := httptest.NewRecorder()
	srv.handleCatSnapshotsRound61(missRepoRec, missRepoReq)
	if missRepoRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with ignore_unavailable=true on missing snapshot repo, got %d: %s", missRepoRec.Code, missRepoRec.Body.String())
	}

	// F2: Invalid byte/time unit validation -> 400
	for _, badPath := range []string{
		"/_cat/fielddata?bytes=bogus",
		"/_cat/segments?bytes=bogus",
		"/_cat/recovery?time=bogus",
		"/_cat/allocation?bytes=bogus",
	} {
		rec, _ = doRound61Req(t, h, http.MethodGet, badPath, "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d: %s", badPath, rec.Code, rec.Body.String())
		}
	}

	// F4: /_resolve/cluster ("(local)", "matching_indices", missing concrete index error, remote stub, ignore_throttled Warning)
	rec, _ = doRound61Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"cluster.remote.cluster_one.seeds":["127.0.0.1:9300"]}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put remote cluster seed failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, rcResp := doRound61Req(t, h, http.MethodGet, "/_resolve/cluster/vis_*,cluster_one:rem_idx?ignore_throttled=false", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_resolve/cluster failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Warning"), "ignore_throttled") {
		t.Fatalf("expected deprecation Warning header for ignore_throttled, got %q", rec.Header().Get("Warning"))
	}
	localEntry, _ := rcResp["(local)"].(map[string]any)
	if localEntry == nil || localEntry["matching_indices"] == nil {
		t.Fatalf("expected (local).matching_indices in _resolve/cluster, got %#v", rcResp)
	}
	remEntry, _ := rcResp["cluster_one"].(map[string]any)
	if remEntry == nil || remEntry["connected"] == nil {
		t.Fatalf("expected cluster_one remote stub in _resolve/cluster, got %#v", rcResp)
	}
	// Missing concrete local index captures error inside (local).error
	rec, rcMiss := doRound61Req(t, h, http.MethodGet, "/_resolve/cluster/definitely_missing_idx", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_resolve/cluster on missing concrete index should return 200 with embedded error, got %d", rec.Code)
	}
	localMiss, _ := rcMiss["(local)"].(map[string]any)
	if localMiss["error"] == nil {
		t.Fatalf("expected (local).error on missing concrete index, got %#v", rcMiss)
	}

	// F6: _shard_stores?status=bogus -> 400; _upgrade, _segments?verbose=true, _recovery?active_only=true
	rec, _ = doRound61Req(t, h, http.MethodGet, "/_shard_stores?status=bogus", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on _shard_stores?status=bogus, got %d", rec.Code)
	}
	upgPostReq := httptest.NewRequest(http.MethodPost, "/vis_idx/_upgrade", nil)
	upgPostReq.SetPathValue("index", "vis_idx")
	upgPostRec := httptest.NewRecorder()
	srv.handleUpgrade(upgPostRec, upgPostReq)
	if upgPostRec.Code != http.StatusOK || !strings.Contains(upgPostRec.Body.String(), "upgraded_indices") {
		t.Fatalf("unexpected POST /_upgrade response: %d %s", upgPostRec.Code, upgPostRec.Body.String())
	}
	upgGetReq := httptest.NewRequest(http.MethodGet, "/vis_idx/_upgrade?human=true", nil)
	upgGetReq.SetPathValue("index", "vis_idx")
	upgGetRec := httptest.NewRecorder()
	srv.handleGetUpgrade(upgGetRec, upgGetReq)
	if upgGetRec.Code != http.StatusOK || !strings.Contains(upgGetRec.Body.String(), "size_in_bytes") {
		t.Fatalf("unexpected GET /_upgrade response: %d %s", upgGetRec.Code, upgGetRec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodGet, "/vis_idx/_segments?verbose=true", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ram_tree") {
		t.Fatalf("expected ram_tree in _segments?verbose=true, got %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodGet, "/vis_idx/_recovery?active_only=true", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on _recovery?active_only=true, got %d", rec.Code)
	}
}

func TestRound61TasksIngest_ReindexPreflightOCCSlicesRemote(t *testing.T) {
	t.Parallel()
	srv, h := newRound61TestServer(t)

	// 1. F20: Preflight 400 BEFORE index lookup or remote whitelist lookup!
	preflight400Cases := []struct {
		name string
		path string
		body string
		hdrs map[string]string
	}{
		{"rps_zero", "/_reindex?requests_per_second=0", `{"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"bad_conflicts", "/_reindex?conflicts=cat", `{"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"bad_slices", "/_reindex?slices=0", `{"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"es8_size_rejected", "/_reindex", `{"size":5,"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}},
		{"max_docs_lt_slices", "/_reindex?slices=5&max_docs=3", `{"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"unknown_top_field", "/_reindex", `{"bogus":1,"source":{"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"unknown_source_field", "/_reindex", `{"source":{"index":"nonexistent","bogus":{}},"dest":{"index":"dst"}}`, nil},
		{"unknown_dest_field", "/_reindex", `{"source":{"index":"nonexistent"},"dest":{"index":"dst","bogus":1}}`, nil},
		{"unknown_remote_fields", "/_reindex", `{"source":{"remote":{"host":"http://127.0.0.1:9200","foo":1,"bar":2},"index":"nonexistent"},"dest":{"index":"dst"}}`, nil},
		{"source_false", "/_reindex", `{"source":{"index":"nonexistent","_source":false},"dest":{"index":"dst"}}`, nil},
		{"stored_fields", "/_reindex", `{"source":{"index":"nonexistent","stored_fields":["a"]},"dest":{"index":"dst"}}`, nil},
	}
	for _, tc := range preflight400Cases {
		rec, _ := doRound61Req(t, h, http.MethodPost, tc.path, tc.body, tc.hdrs)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("[%s] expected 400 BEFORE 404/whitelist, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
	}

	// Seed source index with 3 primary shards and 3 documents
	rec, _ := doRound61Req(t, h, http.MethodPut, "/re_src", `{"settings":{"number_of_shards":3,"number_of_replicas":0}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create re_src failed: %d %s", rec.Code, rec.Body.String())
	}
	for i := 1; i <= 3; i++ {
		rec, _ = doRound61Req(t, h, http.MethodPut, fmt.Sprintf("/re_src/_doc/%d?refresh=true", i), fmt.Sprintf(`{"k":"v%d","n":%d}`, i, i), nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed re_src doc %d failed: %d", i, rec.Code)
		}
	}

	// ES 7 mode: `size` accepted with Warning header; `source.sort` emits Warning header
	es7Hdr := map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=7"}
	srv.SetTargetESVersion("7.10.2")
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex", `{"size":2,"source":{"index":"re_src","sort":[{"n":"asc"}]},"dest":{"index":"re_dst_v7"}}`, es7Hdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("ES 7 reindex with size+sort failed: %d %s", rec.Code, rec.Body.String())
	}
	warnings := strings.Join(rec.Header().Values("Warning"), " | ")
	if !strings.Contains(warnings, "Deprecated field [size]") || !strings.Contains(warnings, "sort option in reindex is deprecated") {
		t.Fatalf("expected size and sort deprecation Warnings, got %q", warnings)
	}
	srv.SetTargetESVersion("8.15.5")

	// F20: Unstored `_source` (`_source.enabled: false`) returns 400 `didn't store _source`
	rec, _ = doRound61Req(t, h, http.MethodPut, "/no_src_idx", `{"mappings":{"_source":{"enabled":false}}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create no_src_idx failed: %d %s", rec.Code, rec.Body.String())
	}
	_, _ = doRound61Req(t, h, http.MethodPut, "/no_src_idx/_doc/1?refresh=true", `{"a":1}`, nil)
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"no_src_idx"},"dest":{"index":"no_src_dst"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "didn't store _source") {
		t.Fatalf("expected 400 didn't store _source, got %d: %s", rec.Code, rec.Body.String())
	}

	// F20: action.auto_create_index: false & pattern `-forbid*`
	_, _ = doRound61Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"false"}}`, nil)
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src"},"dest":{"index":"blocked_dst"}}`, nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "[action.auto_create_index] is [false]") {
		t.Fatalf("expected 404 auto_create_index false message, got %d: %s", rec.Code, rec.Body.String())
	}
	_, _ = doRound61Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"-forbid*,*"}}`, nil)
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src"},"dest":{"index":"forbid_dst"}}`, nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "contains [-forbid*]") {
		t.Fatalf("expected 404 contains [-forbid*] message, got %d: %s", rec.Code, rec.Body.String())
	}
	_, _ = doRound61Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"true"}}`, nil)

	// F21: Lazy `dest` creation skipped when all docs end in `ctx.op = "noop"`
	rec, noopResp := doRound61Req(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src"},"dest":{"index":"lazy_noop_dst"},"script":{"source":"ctx.op = 'noop'"}}`, nil)
	if rec.Code != http.StatusOK || fmt.Sprintf("%v", noopResp["noops"]) != "3" {
		t.Fatalf("expected 3 noops, got %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodHead, "/lazy_noop_dst", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected lazy_noop_dst NOT to be created when all docs are noop, got HEAD status %d", rec.Code)
	}

	// F21: op_type: create with conflicts=abort returns HTTP 409 with ByQuery status body (`failures`, NO top-level `error`)
	_, _ = doRound61Req(t, h, http.MethodPut, "/conflict_dst/_doc/1?refresh=true", `{"k":"existing"}`, nil)
	rec, cfResp := doRound61Req(t, h, http.MethodPost, "/_reindex?conflicts=abort", `{"source":{"index":"re_src"},"dest":{"index":"conflict_dst","op_type":"create"}}`, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on version conflict with conflicts=abort, got %d: %s", rec.Code, rec.Body.String())
	}
	if cfResp["error"] != nil {
		t.Fatalf("409 ByQuery response MUST NOT contain top-level 'error' object: %#v", cfResp)
	}
	cfFailures, _ := cfResp["failures"].([]any)
	if len(cfFailures) == 0 {
		t.Fatalf("expected non-empty failures array on 409 conflict, got %#v", cfResp)
	}

	// F21: Point-in-time `unrefreshedDocs` / `seqNo` optimistic concurrency helper check
	_, _ = doRound61Req(t, h, http.MethodPut, "/pit_idx", `{"settings":{"refresh_interval":"-1"}}`, nil)
	_, _ = doRound61Req(t, h, http.MethodPut, "/pit_idx/_doc/1?refresh=true", `{"v":1}`, nil)
	snap := srv.snapshotIndexDocVersionsRound61([]string{"pit_idx"})
	// Write without refresh so unrefreshedDocs advances live version beyond refreshed snapshot
	_, _ = doRound61Req(t, h, http.MethodPut, "/pit_idx/_doc/1", `{"v":2}`, nil)
	hasConflict, conflictReason := srv.checkByQueryPointInTimeConflictRound61("pit_idx", "1", snap)
	if !hasConflict || !strings.Contains(conflictReason, "required seqNo") {
		t.Fatalf("expected point-in-time seqNo conflict, got conflict=%v reason=%q", hasConflict, conflictReason)
	}

	// F21: wait_for_active_shards=all on index with replicas=1 returns HTTP 503 ByQuery envelope
	_, _ = doRound61Req(t, h, http.MethodPut, "/wfas_dst", `{"settings":{"number_of_shards":1,"number_of_replicas":1}}`, nil)
	rec, wfasResp := doRound61Req(t, h, http.MethodPost, "/_reindex?wait_for_active_shards=all&timeout=10ms", `{"source":{"index":"re_src"},"dest":{"index":"wfas_dst"}}`, nil)
	if rec.Code != http.StatusServiceUnavailable || wfasResp["failures"] == nil {
		t.Fatalf("expected 503 ByQuery envelope for unmet wait_for_active_shards, got %d: %s", rec.Code, rec.Body.String())
	}

	// F21: Runtime script error in query returns 400 search_phase_execution_exception ("Partial shards failure" on >1 shards)
	rec, searchFailResp := doRound61Req(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src","query":{"script":{"script":"1 / 0 == 1"}}},"dest":{"index":"err_dst"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Partial shards failure") {
		t.Fatalf("expected 400 Partial shards failure on 3-shard source runtime script error, got %d: %#v", rec.Code, searchFailResp)
	}

	// F22 & F29: slices=auto resolves 3 slices from 3-shard `re_src`, async task.status.slices, instant _rethrottle wakeup, throttled_millis > 0
	rec, asyncResp := doRound61Req(t, h, http.MethodPost, "/_reindex?wait_for_completion=false&slices=auto&requests_per_second=0.2",
		`{"source":{"index":"re_src","size":1},"dest":{"index":"sliced_dst"}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("async sliced reindex launch failed: %d %s", rec.Code, rec.Body.String())
	}
	taskID, _ := asyncResp["task"].(string)
	if taskID == "" {
		t.Fatalf("expected task id, got %#v", asyncResp)
	}
	// Poll until worker enters throttle sleep (batches >= 1), wait 20ms so throttled_millis > 0, then trigger instant _rethrottle!
	enteredThrottle := false
	for poll := 0; poll < 300; poll++ {
		pRec, pBody := doRound61Req(t, h, http.MethodGet, fmt.Sprintf("/_tasks/%s", taskID), "", nil)
		if pRec.Code == http.StatusOK {
			if pTask, _ := pBody["task"].(map[string]any); pTask != nil {
				if pStatus, _ := pTask["status"].(map[string]any); pStatus != nil {
					if bVal, _ := toInt64(pStatus["batches"]); bVal >= 1 {
						enteredThrottle = true
						break
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !enteredThrottle {
		t.Fatalf("timed out waiting for async reindex worker to enter first batch throttle")
	}
	time.Sleep(20 * time.Millisecond)
	rethrottleStart := time.Now()
	rec, _ = doRound61Req(t, h, http.MethodPost, fmt.Sprintf("/_reindex/%s/_rethrottle?requests_per_second=-1", taskID), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_rethrottle failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, taskDone := doRound61Req(t, h, http.MethodGet, fmt.Sprintf("/_tasks/%s?wait_for_completion=true", taskID), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("wait on task failed: %d %s", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(rethrottleStart); elapsed > 2*time.Second {
		t.Fatalf("_rethrottle did not wake sleeping worker immediately (took %v)", elapsed)
	}
	taskObj, _ := taskDone["task"].(map[string]any)
	statusObj, _ := taskObj["status"].(map[string]any)
	slicesArr, _ := statusObj["slices"].([]any)
	if len(slicesArr) != 3 {
		t.Fatalf("expected slices=auto on 3-shard index to produce 3 slice statuses, got %d: %#v", len(slicesArr), statusObj)
	}
	tmVal, _ := toInt64(statusObj["throttled_millis"])
	if tmVal <= 0 {
		t.Fatalf("expected throttled_millis > 0 to be recorded before _rethrottle wakeup, got %v", statusObj["throttled_millis"])
	}

	// F29: taskRegistry completed-task TTL/LRU bound
	reg := srv.getTaskRegistry()
	eOld := reg.register("indices:data/write/reindex", "old completed", -1, nil, func() {})
	eOld.markDone(map[string]any{"total": 1}, nil)
	eOld.mu.Lock()
	eOld.endTime = time.Now().Add(-31 * time.Minute)
	eOld.mu.Unlock()
	if _, ok := reg.lookup(eOld.fullID); ok {
		t.Fatalf("expected expired completed task (>30m TTL) to be evicted on lookup")
	}

	// F23: SSRF-hardened `source.remote` Reindex
	// Default empty whitelist MUST reject all remote hosts!
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://127.0.0.1:9200"},"index":"rem_src"},"dest":{"index":"rem_dst"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not whitelisted") {
		t.Fatalf("expected default empty reindex.remote.whitelist to reject remote host, got %d: %s", rec.Code, rec.Body.String())
	}

	// Whitelist remote.test:9200 and configure custom RoundTripper
	srv.SetStaticRemoteReindexWhitelist("remote.test:9200")
	_, _ = doRound61Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"reindex.remote.whitelist":"remote.test:9200"}}`, nil)
	// Pre-create destination index with `join` mapping to verify legacy `_parent` -> `join` conversion
	_, _ = doRound61Req(t, h, http.MethodPut, "/rem_join_dst", `{"mappings":{"properties":{"my_join":{"type":"join","relations":{"question":"answer"}}}}}`, nil)

	var scrollCalls atomic.Int32
	var sawBasicAuth atomic.Bool
	var clearedScroll atomic.Bool
	srv.SetRemoteReindexTransport(roundTripperFuncRound61(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte("elastic:secret")) {
			sawBasicAuth.Store(true)
		}
		if req.URL.Path == "/redirect_src/_search" {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"http://169.254.169.254/latest/meta-data"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		if req.URL.Path == "/down_src/_search" {
			return nil, errors.New("connection refused")
		}
		if req.Method == http.MethodDelete && req.URL.Path == "/_search/scroll" {
			clearedScroll.Store(true)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"succeeded":true}`)),
			}, nil
		}
		if req.URL.Path == "/rem_src/_search" {
			body := `{"_scroll_id":"sc-1","hits":{"hits":[{"_id":"p1","_type":"question","_version":1,"_source":{"title":"Parent Q"}}]}}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}
		if req.URL.Path == "/_search/scroll" {
			n := scrollCalls.Add(1)
			if n == 1 {
				body := `{"_scroll_id":"sc-2","hits":{"hits":[{"_id":"c1","_type":"answer","_parent":"p1","_version":1,"_source":{"body":"Child A"}}]}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(body)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"_scroll_id":"sc-2","hits":{"hits":[]}}`)),
			}, nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}))
	defer srv.SetRemoteReindexTransport(nil)

	// Redirect (302) must be blocked -> 500 connect_exception
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://remote.test:9200"},"index":"redirect_src"},"dest":{"index":"rem_join_dst"}}`, nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "connect_exception") {
		t.Fatalf("expected 500 connect_exception on SSRF redirect, got %d: %s", rec.Code, rec.Body.String())
	}

	// Dial failure -> 500 connect_exception
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://remote.test:9200"},"index":"down_src"},"dest":{"index":"rem_join_dst"}}`, nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "connect_exception") {
		t.Fatalf("expected 500 connect_exception on dial error, got %d: %s", rec.Code, rec.Body.String())
	}

	// Multi-page remote scroll + Basic Auth + legacy _parent -> join conversion
	rec, remResp := doRound61Req(t, h, http.MethodPost, "/_reindex", `{
		"source": {
			"remote": {
				"host": "http://remote.test:9200",
				"username": "elastic",
				"password": "secret",
				"socket_timeout": "5s",
				"connect_timeout": "5s"
			},
			"index": "rem_src",
			"size": 1
		},
		"dest": {"index": "rem_join_dst"}
	}`, nil)
	if rec.Code != http.StatusOK || fmt.Sprintf("%v", remResp["created"]) != "2" {
		t.Fatalf("expected remote reindex to create 2 docs across scroll pages, got %d: %s", rec.Code, rec.Body.String())
	}
	if !sawBasicAuth.Load() || !clearedScroll.Load() {
		t.Fatalf("expected Basic Auth (%v) and scroll cleanup DELETE (%v)", sawBasicAuth.Load(), clearedScroll.Load())
	}
	rec, childDoc := doRound61Req(t, h, http.MethodGet, "/rem_join_dst/_doc/c1", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected child doc c1 in rem_join_dst, got %d: %s", rec.Code, rec.Body.String())
	}
	cSrc, _ := childDoc["_source"].(map[string]any)
	joinObj, _ := cSrc["my_join"].(map[string]any)
	if joinObj["name"] != "answer" || joinObj["parent"] != "p1" {
		t.Fatalf("expected legacy _parent->join conversion {name:answer,parent:p1}, got %#v", cSrc)
	}
}

func TestRound61TasksIngest_IngestPainlessMustacheHelpers(t *testing.T) {
	t.Parallel()
	srv, h := newRound61TestServer(t)

	// 1. F27: Pipeline ?if_version= OCC (290_versioned_update.yml) + ?summary=true
	rec, _ := doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_unver", `{"description":"no_ver","processors":[]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put p_unver failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_unver?if_version=1", `{"description":"fail","processors":[]}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "because it has no version") {
		t.Fatalf("expected 400 missing-version error on p_unver, got %d: %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_ver", `{"version":1,"description":"v1","processors":[{"set":{"field":"step","value":"first"}}]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put p_ver failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_ver?if_version=99", `{"description":"mismatch","processors":[]}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "does not match current version") {
		t.Fatalf("expected 400 on mismatched if_version, got %d: %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_ver?if_version=1", `{"description":"v2","processors":[{"set":{"field":"step","value":"second"}}]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on matching if_version=1, got %d: %s", rec.Code, rec.Body.String())
	}
	rec, sumResp := doRound61Req(t, h, http.MethodGet, "/_ingest/pipeline/p_ver?summary=true", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET pipeline?summary=true failed: %d", rec.Code)
	}
	pVerObj, _ := sumResp["p_ver"].(map[string]any)
	if pVerObj["processors"] != nil || fmt.Sprintf("%v", pVerObj["version"]) != "2" {
		t.Fatalf("expected ?summary=true to omit processors and increment version to 2, got %#v", pVerObj)
	}

	// F27: [value] required property is missing in _simulate
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate",
		`{"pipeline":{"processors":[{"set":{"field":"x"}}]},"docs":[{"_source":{}}]}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "[value] required property is missing") {
		t.Fatalf("expected 400 [value] required property is missing, got %d: %s", rec.Code, rec.Body.String())
	}

	// F27: Unconditional painless.ValidateAcyclicValue after script processor even with ignore_failure: true
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate",
		`{"pipeline":{"processors":[{"script":{"source":"Map m = new HashMap(); m.self = m; ctx.loop = m;","ignore_failure":true}}]},"docs":[{"_source":{"a":1}}]}`, nil)
	if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "cycle") && !strings.Contains(rec.Body.String(), "Cyclic") {
		// Either top-level 400/500 or failed simulate error must reject cyclic reference instead of silently ignoring!
		simMap := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &simMap)
		docsSim, _ := simMap["docs"].([]any)
		firstSim, _ := docsSim[0].(map[string]any)
		if firstSim["error"] == nil {
			t.Fatalf("expected cyclic map in script processor to fail even with ignore_failure=true, got %s", rec.Body.String())
		}
	}

	// F27: ISO week-year `YYYY-ww-e` in `date` processor
	rec, isoSim := doRound61Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"date": {"field": "raw_d", "formats": ["YYYY-ww-e"], "timezone": "UTC"}}]},
		"docs": [{"_source": {"raw_d": "2024-01-1"}}]
	}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("ISO week-year date processor failed: %d %s", rec.Code, rec.Body.String())
	}
	isoDocs, _ := isoSim["docs"].([]any)
	isoDoc0, _ := isoDocs[0].(map[string]any)
	isoDocInner, _ := isoDoc0["doc"].(map[string]any)
	isoSrc, _ := isoDocInner["_source"].(map[string]any)
	if tsStr, _ := isoSrc["@timestamp"].(string); !strings.HasPrefix(tsStr, "2024-01-01") {
		t.Fatalf("expected 2024-01-1 ISO week-year to parse as 2024-01-01, got %q", tsStr)
	}

	// F29: Regex length guard (maxRegexPatternLen = 4096) + LRU cache
	if _, err := compileIngestJavaRegex(strings.Repeat("a", maxRegexPatternLen+1)); err == nil {
		t.Fatalf("expected regex exceeding maxRegexPatternLen to fail")
	}
	if re, err := compileIngestJavaRegex(`^foo-(\d+)$`); err != nil || !re.MatchString("foo-42") {
		t.Fatalf("expected valid cached regex to compile and match, err=%v", err)
	}

	// F27: Live ES 8 ingest byte counters + ingestProcessorTypes() + applyWritePipelinesFullRound61 (reroute + final_pipeline + require_alias + OCC)
	_, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_final", `{"processors":[{"set":{"field":"finalized","value":true}}]}`, nil)
	_, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_reroute", `{"processors":[{"set":{"field":"_version","value":7}},{"reroute":{"destination":"ing_dest"}}]}`, nil)
	_, _ = doRound61Req(t, h, http.MethodPut, "/ing_dest", `{"settings":{"index.final_pipeline":"p_final"},"aliases":{"ing_alias":{}}}`, nil)

	ingRes, st, et, er := srv.applyWritePipelinesFullRound61("ing_src", "d1", "p_reroute", "", "", json.RawMessage(`{"msg":"hello"}`), false)
	if st != 0 {
		t.Fatalf("applyWritePipelinesFullRound61 failed: %d %s %s", st, et, er)
	}
	if ingRes.ResolvedWriteIdx != "ing_dest" || !ingRes.HasVersion || ingRes.Version != 7 || !strings.Contains(string(ingRes.Doc), `"finalized":true`) {
		t.Fatalf("unexpected applyWritePipelinesFullRound61 result: %+v doc=%s", ingRes, string(ingRes.Doc))
	}
	// Post-ingest require_alias=true rejects concrete non-alias target
	if _, stAlias, _, _ := srv.applyWritePipelinesFullRound61("ing_dest", "d2", "", "", "", json.RawMessage(`{"msg":"x"}`), true); stAlias != http.StatusNotFound {
		t.Fatalf("expected 404 index_not_found_exception when post-ingest target is not an alias and require_alias=true, got %d", stAlias)
	}
	// Live ingest stats & processor types
	if len(srv.ingestProcessorTypes()) < 20 {
		t.Fatalf("expected ingestProcessorTypes() to expose built-in processors, got %d", len(srv.ingestProcessorTypes()))
	}
	liveIngest := srv.buildLiveIngestNodeStats(true)
	totalIngest, _ := liveIngest["total"].(map[string]any)
	if ib, _ := toInt64(totalIngest["ingested_in_bytes"]); ib <= 0 {
		t.Fatalf("expected live ingested_in_bytes > 0, got %#v", totalIngest)
	}
	if pb, _ := toInt64(totalIngest["produced_as_final_pipeline_in_bytes"]); pb <= 0 {
		t.Fatalf("expected live produced_as_final_pipeline_in_bytes > 0, got %#v", totalIngest)
	}

	// F27: Bulk upsert drop & failed-item executed_pipelines helpers
	_, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/p_drop", `{"processors":[{"drop":{}}]}`, nil)
	upRes, upSt, _, _ := srv.applyBulkUpsertIngestRound61("ing_dest", "u1", "p_drop", "", json.RawMessage(`{"a":1}`), false)
	if upSt != 0 || !upRes.Dropped {
		t.Fatalf("expected drop processor in upsert to return Dropped=true without error, got st=%d res=%+v", upSt, upRes)
	}
	bulkItem := map[string]any{"status": 400, "error": map[string]any{"type": "illegal_argument_exception"}}
	formatBulkFailedItemWithPipelinesRound61(bulkItem, true, []string{"p_reroute", "p_final"})
	if ep, _ := bulkItem["executed_pipelines"].([]string); len(ep) != 2 {
		t.Fatalf("expected executed_pipelines attached to failed bulk item, got %#v", bulkItem)
	}

	// 2. F26: Painless _context list + _context/{context} detail + real _score in _execute + stored script caused_by
	rec, ctxResp := doRound61Req(t, h, http.MethodGet, "/_scripts/painless/_context", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /_scripts/painless/_context failed: %d", rec.Code)
	}
	ctxs, _ := ctxResp["contexts"].([]any)
	if len(ctxs) == 0 {
		t.Fatalf("expected non-empty contexts string list, got %#v", ctxResp)
	}
	if _, isStr := ctxs[0].(string); !isStr {
		t.Fatalf("expected contexts elements to be strings, got %T (%#v)", ctxs[0], ctxs[0])
	}
	ctxDetailReq := httptest.NewRequest(http.MethodGet, "/_scripts/painless/_context/score", nil)
	ctxDetailReq.SetPathValue("context", "score")
	ctxDetailRec := httptest.NewRecorder()
	srv.handlePainlessContextDetailRound61(ctxDetailRec, ctxDetailReq)
	if ctxDetailRec.Code != http.StatusOK || !strings.Contains(ctxDetailRec.Body.String(), `"name":"score"`) {
		t.Fatalf("expected 200 on /_scripts/painless/_context/score, got %d: %s", ctxDetailRec.Code, ctxDetailRec.Body.String())
	}

	// Real query _score in /_scripts/painless/_execute score context
	execBody := `{
		"script": {"source": "_score * 2.0"},
		"context": "score",
		"context_setup": {
			"index": "ing_dest",
			"document": {"title": "hello"},
			"query": {"constant_score": {"filter": {"term": {"title": "hello"}}, "boost": 3.5}}
		}
	}`
	rec, execResp := doRound61Req(t, h, http.MethodPost, "/_scripts/painless/_execute", execBody, nil)
	if rec.Code != http.StatusOK || fmt.Sprintf("%v", execResp["result"]) != "7" && fmt.Sprintf("%v", execResp["result"]) != "7.0" {
		t.Fatalf("expected _score (3.5) * 2.0 = 7 in painless _execute, got %d: %s", rec.Code, rec.Body.String())
	}

	// Stored script runtime emit context rejection includes caused_by
	rec, errStored := doRound61Req(t, h, http.MethodPut, "/_scripts/bad_runtime_ctx/boolean_field", `{"script":{"lang":"painless","source":"emit(true)"}}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when storing runtime field context script, got %d: %s", rec.Code, rec.Body.String())
	}
	errObj, _ := errStored["error"].(map[string]any)
	if errObj["caused_by"] == nil {
		t.Fatalf("expected caused_by in runtime context stored script error, got %#v", errStored)
	}

	// 3. F28: _msearch/template truncated NDJSON -> x_content_e_o_f_exception + ?typed_keys=true + Wave-2 bulk/update helpers
	rec, _ = doRound61Req(t, h, http.MethodPost, "/ing_dest/_msearch/template", "{\"index\":\"ing_dest\"}\n{\"source\":\"{\\\"query\\\":", nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "x_content_e_o_f_exception") {
		t.Fatalf("expected 400 x_content_e_o_f_exception on truncated _msearch/template NDJSON, got %d: %s", rec.Code, rec.Body.String())
	}

	ndjsonTyped := "{\"index\":\"ing_dest\"}\n{\"source\":{\"query\":{\"match_all\":{}},\"aggs\":{\"c\":{\"value_count\":{\"field\":\"_id\"}}}},\"params\":{}}\n"
	rec, mstResp := doRound61Req(t, h, http.MethodPost, "/_msearch/template?typed_keys=true", ndjsonTyped, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "value_count#c") {
		t.Fatalf("expected value_count#c with ?typed_keys=true on _msearch/template, got %d: %#v (%s)", rec.Code, mstResp, rec.Body.String())
	}

	// Wave-2 helpers: validateBulkDeprecatedParamsRound61, validateUpdateRequestUnknownFieldsRound61, validateByQueryPreflightWithWarningsRound61
	bulkReq := httptest.NewRequest(http.MethodPost, "/_bulk", nil)
	bulkReq.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=8")
	if st, _, reason := srv.validateBulkDeprecatedParamsRound61(bulkReq, []byte("{\"index\":{\"_index\":\"idx\",\"_id\":\"1\",\"retry_on_conflict\":3}}\n{\"a\":1}\n")); st != http.StatusBadRequest || !strings.Contains(reason, "retry_on_conflict") {
		t.Fatalf("expected 400 on retry_on_conflict inside index action in _bulk, got %d %q", st, reason)
	}
	if st, _, reason := validateUpdateRequestUnknownFieldsRound61([]byte(`{"doc":{"a":1},"scripted_upser":true}`)); st != http.StatusBadRequest || !strings.Contains(reason, "did you mean [scripted_upsert]?") {
		t.Fatalf("expected UpdateRequest did-you-mean suggestion, got %d %q", st, reason)
	}
	ubqReq := httptest.NewRequest(http.MethodPost, "/nonexistent/_update_by_query?requests_per_second=0", strings.NewReader(`{}`))
	ubqRec := httptest.NewRecorder()
	if _, _, _, _, ubqSt, _, _ := srv.validateByQueryPreflightWithWarningsRound61(ubqRec, ubqReq, []byte(`{}`), false); ubqSt != http.StatusBadRequest {
		t.Fatalf("expected 400 preflight error on UBQ requests_per_second=0, got %d", ubqSt)
	}
}
