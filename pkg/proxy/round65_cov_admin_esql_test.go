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
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func r65CovBMustHTTP(t *testing.T, h http.Handler, method, path, body string, wantCode int) map[string]any {
	t.Helper()
	code, _, parsed, raw := doRound61AdminReq(t, h, method, path, body, nil)
	if code != wantCode {
		t.Fatalf("%s %s: expected status %d, got %d body=%s", method, path, wantCode, code, raw)
	}
	return parsed
}

func TestRound65CovAdminESQL_ResolveIndexAliasesAndHealth(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// Setup open, closed, dot-hidden, explicit-hidden indices + TSDB + data stream.
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_open_a", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_open_b", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_closed_c", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_closed_c/_close", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/.r65_hidden_dot", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_hidden_exp", `{"settings":{"index.hidden":true}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_tsdb_al", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"]}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}
	}`, http.StatusOK)

	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_ds_res_tpl", `{
		"index_patterns": ["r65-ds-*"],
		"data_stream": {},
		"template": {"settings":{"index.number_of_replicas": 1},"mappings":{"properties":{"@timestamp":{"type":"date"}}}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_data_stream/r65-ds-logs", "", http.StatusOK)

	// Hidden data stream for resolve hidden branch.
	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_ds_hid_tpl", `{
		"index_patterns": [".r65-hid-*"],
		"data_stream": {"hidden": true},
		"template": {"mappings":{"properties":{"@timestamp":{"type":"date"}}}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_data_stream/.r65-hid-ds", "", http.StatusOK)

	// 1. handleUpdateAliasesR62Search validation + add/remove/remove_index/action_results
	r65CovBMustHTTP(t, h, http.MethodGet, "/_aliases", "", http.StatusOK)
	cMethod, _, _, _ := doDirectHandlerReqRound61(t, srv.handleUpdateAliasesR62Search, http.MethodGet, "/_aliases", "", nil, nil)
	if cMethod != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET handleUpdateAliasesR62Search, got %d", cMethod)
	}
	for _, badBody := range []string{
		`{bad`,
		`{"actions":[{}]}`,
		`{"actions":[{"unknown":{}}]}`,
		`{"actions":[{"add":"bad"}]}`,
		`{"actions":[{"add":{"index":"r65_open_a","alias":"al_x","must_exist":true}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a"}}]}`,
		`{"actions":[{"add":{"index":"no_such_idx","alias":"al_x"}}]}`,
		`{"actions":[{"add":{"index":"r65_nomatch_*","alias":"al_x"}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a","alias":"r65_open_b"}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a","alias":"r65-ds-logs"}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a","alias":"INVALID_UPPER"}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a,r65_open_b","alias":"al_w","is_write_index":true}}]}`,
		`{"actions":[{"add":{"index":"r65_open_a","alias":"al_w","is_write_index":true}},{"add":{"index":"r65_open_b","alias":"al_w","is_write_index":true}}]}`,
		`{"actions":[{"add":{"index":"r65_tsdb_al","alias":"al_tsdb","routing":"r1"}}]}`,
		`{"actions":[{"remove_index":{"index":"r65_open_a","must_exist":true}}]}`,
		`{"actions":[{"remove_index":{}}]}`,
		`{"actions":[{"remove_index":{"index":"no_such_idx"}}]}`,
		`{"actions":[{"remove":{"index":"r65_open_a"}}]}`,
		`{"actions":[{"remove":{"index":"no_such_idx","alias":"al_x"}}]}`,
		`{"actions":[{"remove":{"index":"r65_open_a","alias":"al_missing"}}]}`,
		`{"actions":[{"remove":{"index":"r65_open_a","alias":"al_missing","must_exist":false}}]}`,
	} {
		code, _, _, raw := doRound61AdminReq(t, h, http.MethodPost, "/_aliases", badBody, nil)
		if code < 400 {
			t.Fatalf("expected 4xx for %s, got %d: %s", badBody, code, raw)
		}
	}

	// Add concrete, hidden, filtered, routing, and data-stream aliases.
	r65CovBMustHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"r65_open_a","alias":"al_open","filter":{"term":{"tag":"ok"}},"routing":"1","index_routing":"1","search_routing":"1","is_write_index":true}},
		{"add":{"index":"r65_closed_c","alias":"al_closed"}},
		{"add":{"index":"r65_open_a","alias":"al_hidden","is_hidden":true}},
		{"add":{"index":"r65-ds-logs","alias":"al_ds"}},
		{"add":{"index":"r65_open_b","alias":"al_keep"}},
		{"add":{"index":"r65_open_b","alias":"al_drop"}}
	]}`, http.StatusOK)

	// ES 8.15.5 multi-action partial error with action_results + -exclusion remove
	partialResp := r65CovBMustHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"r65_open_b","alias":"al_added_in_partial"}},
		{"remove":{"index":"r65_open_a","alias":"al_never_existed","must_exist":false}},
		{"remove":{"index":"r65_open_b","aliases":["al_*","-al_keep","-al_added_in_partial"]}}
	]}`, http.StatusOK)
	if partialResp["errors"] != true {
		t.Fatalf("expected errors=true on partial alias action_results, got %v", partialResp)
	}
	if ars, ok := partialResp["action_results"].([]any); !ok || len(ars) != 3 {
		t.Fatalf("expected 3 action_results, got %v", partialResp)
	}

	// Wildcard/all remove & remove_index
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_to_remove", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"r65_to_remove","alias":"al_tmp_rem"}},
		{"remove":{"index":"*","alias":"al_tmp_rem"}},
		{"remove_index":{"index":"r65_to_remove"}}
	]}`, http.StatusOK)

	// ES 7.10.2 strict must_exist failure on multi-action remove
	srv7, h7 := newRound61AdminTestServer(t, "7.10.2")
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_v7_idx", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"r65_v7_idx","alias":"al_v7"}},
		{"remove":{"index":"r65_v7_idx","alias":"al_missing_v7"}}
	]}`, http.StatusNotFound)
	_ = srv7

	// 2. handleGetAliasesR62Search (HEAD, date-math, data stream aliases, omits .ds-*)
	cHead, _, _, _ := doRound61AdminReq(t, h, http.MethodHead, "/_alias/al_open", "", nil)
	if cHead != http.StatusOK {
		t.Fatalf("HEAD /_alias/al_open expected 200, got %d", cHead)
	}
	alDS := r65CovBMustHTTP(t, h, http.MethodGet, "/_alias/al_ds", "", http.StatusOK)
	if _, ok := alDS["r65-ds-logs"]; !ok {
		t.Fatalf("expected r65-ds-logs in GET /_alias/al_ds, got %v", alDS)
	}
	alAll := r65CovBMustHTTP(t, h, http.MethodGet, "/_alias/<al_*>", "", http.StatusOK)
	for k := range alAll {
		if strings.HasPrefix(k, ".ds-") {
			t.Fatalf("did not expect .ds-* backing index %q in GET /_alias", k)
		}
	}

	// 3. handleResolveIndexR62Search
	cBadM, _, _, _ := doRound61AdminReq(t, h, http.MethodPost, "/_resolve/index/*", "", nil)
	if cBadM != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /_resolve/index/*, got %d", cBadM)
	}
	cMissName, _, _, _ := doDirectHandlerReqRound61(t, srv.handleResolveIndexR62Search, http.MethodGet, "/_resolve/index/", "", nil, nil)
	if cMissName != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing name, got %d", cMissName)
	}
	r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/*?expand_wildcards=bogus", "", http.StatusBadRequest)
	cHeadRes, _, _, _ := doRound61AdminReq(t, h, http.MethodHead, "/_resolve/index/*", "", nil)
	if cHeadRes != http.StatusOK {
		t.Fatalf("HEAD /_resolve/index/* expected 200, got %d", cHeadRes)
	}
	resOpen := r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/*", "", http.StatusOK)
	if len(resOpen["data_streams"].([]any)) == 0 {
		t.Fatalf("expected data_streams in resolve *, got %v", resOpen)
	}
	resAll := r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/*?expand_wildcards=open,closed,hidden", "", http.StatusOK)
	if len(resAll["indices"].([]any)) < 5 {
		t.Fatalf("expected >=5 indices with open,closed,hidden, got %v", resAll["indices"])
	}
	resNone := r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/*?expand_wildcards=none", "", http.StatusOK)
	if len(resNone["indices"].([]any)) != 0 {
		t.Fatalf("expected 0 indices for * with expand_wildcards=none, got %v", resNone)
	}
	resConcreteNone := r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/r65_open_a,r65-ds-logs?expand_wildcards=none", "", http.StatusOK)
	if len(resConcreteNone["indices"].([]any)) != 1 || len(resConcreteNone["data_streams"].([]any)) != 1 {
		t.Fatalf("expected concrete index+ds with expand_wildcards=none, got %v", resConcreteNone)
	}
	resExcl := r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/r65_*,-r65_closed_c,.r65_hidden_dot?expand_wildcards=open,closed", "", http.StatusOK)
	if len(resExcl["indices"].([]any)) == 0 {
		t.Fatalf("expected non-empty resolve with exclusions and explicit dot, got %v", resExcl)
	}
	r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/<r65_open_*>", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodGet, "/_resolve/index/remote_cluster:r65_*", "", http.StatusOK)

	// Without explicit target ES version: state + hidden fields emitted on resolve index.
	memNoVer := NewMemoryBackend(false)
	srvNoVer := NewServer("es_db", memNoVer, transpiler.TranspilerOptions{})
	hNoVer := srvNoVer.Handler()
	r65CovBMustHTTP(t, hNoVer, http.MethodPut, "/r65_nv_open", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, hNoVer, http.MethodPut, "/r65_nv_closed", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, hNoVer, http.MethodPost, "/r65_nv_closed/_close", "", http.StatusOK)
	resNV := r65CovBMustHTTP(t, hNoVer, http.MethodGet, "/_resolve/index/*?expand_wildcards=all", "", http.StatusOK)
	firstNV := resNV["indices"].([]any)[0].(map[string]any)
	if _, hasState := firstNV["state"]; !hasState {
		t.Fatalf("expected state field when explicitTargetESVersion=false, got %v", firstNV)
	}

	// 4. handleClusterHealthR62Search: green override when only DS backing has replicas > 0 vs yellow with regular replicated index
	memDSOnly := NewMemoryBackend(false)
	srvDSOnly := NewServer("es_db", memDSOnly, transpiler.TranspilerOptions{})
	srvDSOnly.SetTargetESVersion("8.15.5")
	hDSOnly := srvDSOnly.Handler()
	r65CovBMustHTTP(t, hDSOnly, http.MethodPut, "/_index_template/r65_rep_ds", `{
		"index_patterns": ["r65-rep-*"],
		"data_stream": {},
		"template": {"settings":{"index.number_of_replicas": 1},"mappings":{"properties":{"@timestamp":{"type":"date"}}}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, hDSOnly, http.MethodPut, "/_data_stream/r65-rep-1", "", http.StatusOK)
	hlthGreen := r65CovBMustHTTP(t, hDSOnly, http.MethodGet, "/_cluster/health?wait_for_status=green", "", http.StatusOK)
	if hlthGreen["status"] != "green" {
		t.Fatalf("expected green status for 1-node data-stream-only cluster, got %v", hlthGreen)
	}
	// Adding a regular replicated index makes wait_for_status=green fall through to handleClusterHealthR61Admin.
	r65CovBMustHTTP(t, hDSOnly, http.MethodPut, "/r65_reg_rep", `{"settings":{"number_of_replicas":1}}`, http.StatusOK)
	codeReg, _, hlthReg, rawReg := doRound61AdminReq(t, hDSOnly, http.MethodGet, "/_cluster/health?wait_for_status=green&timeout=1ms", "", nil)
	if codeReg != http.StatusRequestTimeout && hlthReg["status"] == "green" {
		t.Fatalf("expected non-green/timeout for regular replicated index, got %d %s", codeReg, rawReg)
	}
}

func TestRound65CovAdminESQL_DataStreamModifyAndLazyRollover(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	// Setup indices & data streams for _data_stream/_modify
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_unm_1", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_unm_2", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_unm_fs1", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_unm_fs2", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_aliased_idx", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"r65_aliased_idx","alias":"r65_blocking_al"}}]}`, http.StatusOK)

	// Method & validation errors on /_data_stream/_modify
	c405, _, _, _ := doRound61AdminReq(t, h, http.MethodGet, "/_data_stream/_modify", "", nil)
	if c405 != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /_data_stream/_modify, got %d", c405)
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{bad`, http.StatusBadRequest},
		{`{}`, http.StatusBadRequest},
		{`{"actions":[{"add_backing_index":{"data_stream":"a","index":"b"},"remove_backing_index":{"data_stream":"a","index":"b"}}]}`, http.StatusBadRequest},
		{`{"actions":[{"bogus_op":{}}]}`, http.StatusBadRequest},
		{`{"actions":[{"add_backing_index":{"data_stream":"ds_new"}}]}`, http.StatusBadRequest},
		{`{"actions":[{"add_backing_index":{"data_stream":"ds_new","index":"r65_unm_1","failure_store":"nope"}}]}`, http.StatusBadRequest},
		{`{"actions":[{"add_backing_index":{"data_stream":"ds_new","index":"missing_idx"}}]}`, http.StatusNotFound},
		{`{"actions":[{"add_backing_index":{"data_stream":"ds_new","index":"r65_aliased_idx"}}]}`, http.StatusBadRequest},
		{`{"actions":[{"remove_backing_index":{"data_stream":"no_such_ds","index":"r65_unm_1"}}]}`, http.StatusNotFound},
		{`{"actions":[{"data_stream_options":{"failure_store":true}}]}`, http.StatusBadRequest},
		{`{"actions":[{"data_stream_options":{"data_stream":"no_such_ds","failure_store":true}}]}`, http.StatusNotFound},
	} {
		r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", tc.body, tc.want)
	}

	// Valid add_backing_index creating new DS + failure store + second backing & second FS
	r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[
		{"add_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_1"}},
		{"add_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_2"}},
		{"add_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_fs1","failure_store":true}},
		{"add_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_fs2","failure_store":true}}
	]}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[
		{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":{"enabled":true}}}
	]}`, http.StatusOK)

	// Error cases after ownership: already owned (normal & FS), cannot remove write index (normal & FS), not found in DS, options validation
	for _, badBody := range []string{
		`{"actions":[{"add_backing_index":{"data_stream":"other_ds","index":"r65_unm_1"}}]}`,
		`{"actions":[{"add_backing_index":{"data_stream":"other_ds","index":"r65_unm_fs1"}}]}`,
		`{"actions":[{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_1"}}]}`,
		`{"actions":[{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_fs1","failure_store":true}}]}`,
		`{"actions":[{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_aliased_idx"}}]}`,
		`{"actions":[{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_aliased_idx","failure_store":true}}]}`,
		`{"actions":[{"data_stream_options":{"data_stream":"r65_mod_ds","unknown_key":1}}]}`,
		`{"actions":[{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":{"unknown":1}}}]}`,
		`{"actions":[{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":{"enabled":"bad"}}}]}`,
		`{"actions":[{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":"bad"}}]}`,
	} {
		r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", badBody, http.StatusBadRequest)
	}

	// Remove older backing index + older FS index + disable FS to remove active FS write index in same atomic batch, then re-enable FS
	r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[
		{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_2"}},
		{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_fs2","failure_store":true}},
		{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":{"enabled":false}}},
		{"remove_backing_index":{"data_stream":"r65_mod_ds","index":"r65_unm_fs1","failure_store":true}}
	]}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[
		{"data_stream_options":{"data_stream":"r65_mod_ds","failure_store":true}}
	]}`, http.StatusOK)

	// Normal data stream lazy rollover:
	// 1) Create pipeline and v1 template (no default_pipeline), create data stream (-000001)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_lazy_pipe", `{
		"processors": [{"set": {"field": "rolled_pipe", "value": true}}]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_lazy_tpl", `{
		"index_patterns": ["r65-lazy-ds*"],
		"data_stream": {},
		"priority": 100,
		"template": {
			"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "keyword"}}}
		}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_data_stream/r65-lazy-ds", "", http.StatusOK)

	// 2) Update template with default_pipeline BEFORE rollover
	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_lazy_tpl", `{
		"index_patterns": ["r65-lazy-ds*"],
		"data_stream": {},
		"priority": 100,
		"template": {
			"settings": {"index.default_pipeline": "r65_lazy_pipe"},
			"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "keyword"}}}
		}
	}`, http.StatusOK)

	// 3) Write before rollover must NOT inherit updated template's default_pipeline
	doc1 := r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_doc?refresh=true", `{"@timestamp":"2026-11-23T00:00:00Z","msg":"before"}`, http.StatusCreated)
	if !strings.Contains(doc1["_index"].(string), "-000001") {
		t.Fatalf("expected doc1 in -000001, got %v", doc1)
	}
	get1 := r65CovBMustHTTP(t, h, http.MethodGet, "/"+doc1["_index"].(string)+"/_doc/"+doc1["_id"].(string), "", http.StatusOK)
	if _, hasPipe := get1["_source"].(map[string]any)["rolled_pipe"]; hasPipe {
		t.Fatalf("expected doc1 before rollover NOT to inherit updated default_pipeline, got %v", get1)
	}

	// 4) Lazy rollover with conditions rejected; dry_run=true does not roll on next write; lazy=true marks pending without creating -000002 yet
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?lazy=true", `{"conditions":{"max_docs":1}}`, http.StatusBadRequest)
	dryRes := r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?lazy=true&dry_run=true", "", http.StatusOK)
	if dryRes["rolled_over"] != false || dryRes["dry_run"] != true {
		t.Fatalf("unexpected lazy dry_run response: %v", dryRes)
	}
	doc1b := r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_doc?refresh=true", `{"@timestamp":"2026-11-23T00:00:30Z","msg":"after_dry_run"}`, http.StatusCreated)
	if !strings.Contains(doc1b["_index"].(string), "-000001") {
		t.Fatalf("expected doc1b in -000001 after dry_run, got %v", doc1b)
	}
	lazyRes := r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?lazy=true", "", http.StatusOK)
	if lazyRes["acknowledged"] != true || lazyRes["rolled_over"] != false || lazyRes["new_index"] != nil {
		t.Fatalf("unexpected lazy rollover response: %v", lazyRes)
	}
	dsMeta := r65CovBMustHTTP(t, h, http.MethodGet, "/_data_stream/r65-lazy-ds", "", http.StatusOK)
	if indices := dsMeta["data_streams"].([]any)[0].(map[string]any)["indices"].([]any); len(indices) != 1 {
		t.Fatalf("expected still 1 backing index immediately after lazy=true, got %v", indices)
	}

	// 5) Next write triggers creation of -000002 with updated template & executes updated default_pipeline
	doc2 := r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_doc?refresh=true", `{"@timestamp":"2026-11-23T00:01:00Z","msg":"trigger_rollover"}`, http.StatusCreated)
	if !strings.Contains(doc2["_index"].(string), "-000002") {
		t.Fatalf("expected doc2 to trigger lazy rollover to -000002, got %v", doc2)
	}
	get2 := r65CovBMustHTTP(t, h, http.MethodGet, "/"+doc2["_index"].(string)+"/_doc/"+doc2["_id"].(string), "", http.StatusOK)
	if get2["_source"].(map[string]any)["rolled_pipe"] != true {
		t.Fatalf("expected doc2 in newly rolled -000002 to execute updated default_pipeline, got %v", get2)
	}

	// 6) Additional handleRolloverR62Search branches: non-DS target_failure_store error, DS new_index error,
	//    unknown field, dry_run=true, conditions unmet/met, failure_store lazy + dry_run + live rollover
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_unm_1/_rollover?target_failure_store=true", "", http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover/explicit_new", "", http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover", `{"bad_key":1}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?dry_run=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover", `{"conditions":{"max_docs":9999}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover", `{"conditions":{"max_docs":1}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true", `{"conditions":{"max_docs":1}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true&lazy=true", `{"conditions":{"max_docs":1}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true&lazy=true&dry_run=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true&lazy=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true&dry_run=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65-lazy-ds/_rollover?target_failure_store=true", `{"conditions":{"max_docs":9999}}`, http.StatusOK)
}

func TestRound65CovAdminESQL_RuntimeHelpersR62(t *testing.T) {
	// 1. matchesTermsFilterPrecompiledWithSchemaR62Search
	if !matchesTermsFilterPrecompiledWithSchemaR62Search("alpha", map[string]any{"partition": 0, "num_partitions": 1}, nil, "keyword") {
		t.Fatalf("expected partition 0/1 match")
	}
	reDate := regexp.MustCompile(`^2024-01-01`)
	if !matchesTermsFilterPrecompiledWithSchemaR62Search("1704067200000", []any{"2024-01-01T00:00:00Z"}, nil, "date") {
		t.Fatalf("expected date epoch millis match against ISO []any")
	}
	if matchesTermsFilterPrecompiledWithSchemaR62Search("1704067200000", []any{"2025-01-01T00:00:00Z"}, nil, "date") {
		t.Fatalf("did not expect mismatched date []any match")
	}
	if !matchesTermsFilterPrecompiledWithSchemaR62Search("2024-01-01T00:00:00Z", []string{"1704067200000"}, nil, "date_nanos") {
		t.Fatalf("expected date_nanos ISO key match against epoch []string")
	}
	if matchesTermsFilterPrecompiledWithSchemaR62Search("2024-01-01T00:00:00Z", []string{"1704067200001"}, nil, "date") {
		t.Fatalf("did not expect mismatched []string date match")
	}
	if !matchesTermsFilterPrecompiledWithSchemaR62Search("1704067200000", "2024.*", reDate, "date") {
		t.Fatalf("expected date regexp match")
	}
	if matchesTermsFilterPrecompiledWithSchemaR62Search("1704067200000", "^2099", regexp.MustCompile(`^2099`), "date") {
		t.Fatalf("did not expect date regexp match for 2099")
	}
	if !matchesTermsFilterPrecompiledWithSchemaR62Search("foo", "f.*", regexp.MustCompile(`^f`), "keyword") {
		t.Fatalf("expected keyword fallback match")
	}

	// 2. applyIPRangeCIDRMaskWithStrictR63
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(true, "not-a-cidr", map[string]any{}); ok {
		t.Fatalf("expected false for invalid CIDR")
	}
	e4Loose := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(false, "10.0.1.42/24", e4Loose); !ok || e4Loose["from"] != "10.0.1.0" || e4Loose["to"] != "10.0.1.255" {
		t.Fatalf("unexpected non-strict IPv4 CIDR: %v", e4Loose)
	}
	e4Strict := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(true, "10.0.1.42/24", e4Strict); !ok || e4Strict["to"] != "10.0.2.0" {
		t.Fatalf("unexpected strict IPv4 CIDR: %v", e4Strict)
	}
	e4Max := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(true, "255.255.255.255/32", e4Max); !ok || e4Max["to"] != nil {
		t.Fatalf("expected omitted 'to' on max IPv4, got %v", e4Max)
	}
	e6Loose := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(false, "2001:db8::1/120", e6Loose); !ok || e6Loose["from"] != "2001:db8::" || e6Loose["to"] != "2001:db8::ff" {
		t.Fatalf("unexpected non-strict IPv6 CIDR: %v", e6Loose)
	}
	e6Strict := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(true, "2001:db8::1/120", e6Strict); !ok || e6Strict["to"] != "2001:db8::100" {
		t.Fatalf("unexpected strict IPv6 CIDR: %v", e6Strict)
	}
	e6Max := map[string]any{}
	if _, _, ok := applyIPRangeCIDRMaskWithStrictR63(true, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", e6Max); !ok || e6Max["to"] != nil {
		t.Fatalf("expected omitted 'to' on max IPv6, got %v", e6Max)
	}

	// 3. extractFailingProcessorTypeAndTagR62Search
	if pt, tg := extractFailingProcessorTypeAndTagR62Search(nil, "fail_processor_exception"); pt != "fail" || tg != "" {
		t.Fatalf("expected fail/'', got %q/%q", pt, tg)
	}
	if pt, tg := extractFailingProcessorTypeAndTagR62Search(nil, "other_err"); pt != "" || tg != "" {
		t.Fatalf("expected ''/'', got %q/%q", pt, tg)
	}
	pipeSpec := map[string]any{
		"processors": []any{
			"bad_entry",
			map[string]any{"pipeline": map[string]any{"name": "sub"}},
			map[string]any{"set": map[string]any{"field": "a", "value": 1, "tag": "t_set"}},
			map[string]any{"fail": map[string]any{"message": "boom", "tag": "t_fail"}},
		},
	}
	if pt, tg := extractFailingProcessorTypeAndTagR62Search(pipeSpec, "ingest_processor_exception"); pt != "set" || tg != "t_set" {
		t.Fatalf("expected set/t_set, got %q/%q", pt, tg)
	}
	if pt, tg := extractFailingProcessorTypeAndTagR62Search(pipeSpec, "fail_processor_exception"); pt != "fail" || tg != "t_fail" {
		t.Fatalf("expected fail/t_fail, got %q/%q", pt, tg)
	}
	onlyPipe := map[string]any{"processors": []any{map[string]any{"pipeline": map[string]any{"name": "sub"}}}}
	if pt, _ := extractFailingProcessorTypeAndTagR62Search(onlyPipe, "fail_processor_exception"); pt != "fail" {
		t.Fatalf("expected fallback fail, got %q", pt)
	}
	if pt, _ := extractFailingProcessorTypeAndTagR62Search(onlyPipe, "other"); pt != "" {
		t.Fatalf("expected empty on non-fail pipe-only, got %q", pt)
	}

	// 4. queryHasPinnedDocsMissingIndexR65
	pinHit := &esast.Query{Pinned: &esast.PinnedQuery{HasDocsMissingIndex: true}}
	pinMiss := &esast.Query{MatchAll: map[string]any{}}
	for _, tc := range []struct {
		q    *esast.Query
		want bool
	}{
		{nil, false},
		{pinMiss, false},
		{pinHit, true},
		{&esast.Query{Pinned: &esast.PinnedQuery{Organic: pinHit}}, true},
		{&esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: *pinHit}}, true},
		{&esast.Query{Boosting: &esast.BoostingQuery{Positive: *pinHit, Negative: *pinMiss}}, true},
		{&esast.Query{Boosting: &esast.BoostingQuery{Positive: *pinMiss, Negative: *pinHit}}, true},
		{&esast.Query{DisMax: &esast.DisMaxQuery{Queries: esast.QuerySlice{*pinMiss, *pinHit}}}, true},
		{&esast.Query{FunctionScore: &esast.FunctionScoreQuery{Query: pinHit}}, true},
		{&esast.Query{ScriptScore: &esast.ScriptScoreQuery{Query: pinHit}}, true},
		{&esast.Query{Nested: &esast.NestedQuery{Path: "n", Query: *pinHit}}, true},
		{&esast.Query{HasChild: &esast.HasChildQuery{Type: "c", Query: *pinHit}}, true},
		{&esast.Query{HasParent: &esast.HasParentQuery{ParentType: "p", Query: *pinHit}}, true},
		{&esast.Query{Wrapper: &esast.WrapperQuery{Decoded: pinHit}}, true},
		{&esast.Query{Bool: &esast.BoolQuery{MustNot: esast.QuerySlice{*pinHit}}}, true},
		{&esast.Query{Bool: &esast.BoolQuery{Should: esast.QuerySlice{*pinMiss}}}, false},
	} {
		if got := queryHasPinnedDocsMissingIndexR65(tc.q); got != tc.want {
			t.Fatalf("queryHasPinnedDocsMissingIndexR65=%v want %v for %+v", got, tc.want, tc.q)
		}
	}

	// 5. normalizeSingleScriptSpecR62Search
	if normalizeSingleScriptSpecR62Search(nil) != nil {
		t.Fatalf("expected nil for nil script")
	}
	if m, ok := normalizeSingleScriptSpecR62Search("return 1;").(map[string]any); !ok || m["lang"] != "painless" || m["source"] != "return 1;" {
		t.Fatalf("unexpected string script norm: %v", m)
	}
	if m, ok := normalizeSingleScriptSpecR62Search(map[string]any{"source": "x"}).((map[string]any)); !ok || m["lang"] != "painless" {
		t.Fatalf("unexpected map script norm: %v", m)
	}
	var nilSpec *esast.ScriptSpec
	if normalizeSingleScriptSpecR62Search(nilSpec) != nil {
		t.Fatalf("expected nil for nil *ScriptSpec")
	}
	if m, ok := normalizeSingleScriptSpecR62Search(&esast.ScriptSpec{ID: "stored_1", Params: map[string]any{"a": 1}}).(map[string]any); !ok || m["id"] != "stored_1" {
		t.Fatalf("unexpected ID ScriptSpec norm: %v", m)
	}
	if m, ok := normalizeSingleScriptSpecR62Search(esast.ScriptSpec{Source: "emit(1)", Params: map[string]any{"k": 2}}).(map[string]any); !ok || m["lang"] != "painless" || m["params"] == nil {
		t.Fatalf("unexpected value ScriptSpec norm: %v", m)
	}
	if normalizeSingleScriptSpecR62Search(123) != 123 {
		t.Fatalf("expected passthrough for unknown script type")
	}

	// 6. extractSAYTBoolPrefixQueryStringR62Search
	if _, ok := extractSAYTBoolPrefixQueryStringR62Search(nil, "title"); ok {
		t.Fatalf("expected false for nil query")
	}
	if qs, ok := extractSAYTBoolPrefixQueryStringR62Search(&esast.Query{
		MatchBoolPrefix: map[string]esast.PhraseEntry{"title^2": {Query: "qui"}},
	}, "title"); !ok || qs != "qui" {
		t.Fatalf("expected match_bool_prefix 'qui', got %q %v", qs, ok)
	}
	if qs, ok := extractSAYTBoolPrefixQueryStringR62Search(&esast.Query{
		MultiMatch: &esast.MultiMatchQuery{Type: "bool_prefix", Query: "bro", Fields: []string{"title._2gram^3"}},
	}, "title"); !ok || qs != "bro" {
		t.Fatalf("expected multi_match bool_prefix 'bro', got %q %v", qs, ok)
	}
	if qs, ok := extractSAYTBoolPrefixQueryStringR62Search(&esast.Query{
		MultiMatch: &esast.MultiMatchQuery{Type: "bool_prefix", Query: "fox"},
	}, "title"); !ok || qs != "fox" {
		t.Fatalf("expected multi_match empty fields match 'fox', got %q %v", qs, ok)
	}
	if _, ok := extractSAYTBoolPrefixQueryStringR62Search(&esast.Query{
		MultiMatch: &esast.MultiMatchQuery{Type: "best_fields", Query: "fox"},
	}, "title"); ok {
		t.Fatalf("expected false for non-bool_prefix multi_match")
	}
}

func TestRound65CovAdminESQL_ESQLFunctionsStagesAndSimulate(t *testing.T) {
	// 1. Direct coverage of remaining branches in evalESQLFuncRound57 & computeESQLMedianOrPercentile
	for _, tc := range []struct {
		fn   string
		args []any
		want bool // whether result should be non-nil
	}{
		{"REPLACE", []any{nil, "a", "b"}, false},
		{"REPLACE", []any{"hello-12", `([a-z]+)-([0-9]+)`, `$2:$1`}, true},
		{"REPLACE", []any{"a[b", "[", "X"}, true},
		{"SUBSTRING", []any{nil, 1}, false},
		{"SUBSTRING", []any{"abc", "bad"}, false},
		{"SUBSTRING", []any{"abc", int64(-10)}, true},
		{"SUBSTRING", []any{"abc", int64(10)}, true},
		{"SUBSTRING", []any{"abc", int64(1), int64(-1)}, false},
		{"SUBSTRING", []any{"abcdef", int64(2), int64(100)}, true},
		{"SPLIT", []any{nil, ","}, false},
		{"STARTS_WITH", []any{nil, "a"}, false},
		{"ENDS_WITH", []any{nil, "a"}, false},
		{"LOCATE", []any{nil, "a"}, false},
		{"LOCATE", []any{"hello", "x", int64(0)}, true},
		{"LOCATE", []any{"hello", "", int64(2)}, true},
		{"LOCATE", []any{"hello", "", int64(99)}, true},
		{"LOCATE", []any{"hello", "z"}, true},
		{"LTRIM", []any{nil}, false},
		{"RTRIM", []any{nil}, false},
		{"LEFT", []any{nil, 2}, false},
		{"LEFT", []any{"abc", int64(-1)}, false},
		{"LEFT", []any{"abc", int64(10)}, true},
		{"RIGHT", []any{nil, 2}, false},
		{"RIGHT", []any{"abc", int64(-1)}, false},
		{"RIGHT", []any{"abc", int64(10)}, true},
		{"FLOOR", []any{nil}, false},
		{"FLOOR", []any{"bad"}, false},
		{"CEIL", []any{nil}, false},
		{"CEIL", []any{"bad"}, false},
		{"POW", []any{nil, 2}, false},
		{"POW", []any{"bad", 2}, false},
		{"POW", []any{float64(-1), float64(0.5)}, false},
		{"SQRT", []any{nil}, false},
		{"SQRT", []any{float64(-4)}, false},
		{"MOD", []any{nil, 2}, false},
		{"MOD", []any{int64(5), int64(0)}, false},
		{"MOD", []any{float64(5.5), float64(0)}, false},
		{"GREATEST", []any{nil, int64(1), nil, int64(9)}, true},
		{"LEAST", []any{nil, int64(9), nil, int64(1)}, true},
		{"CASE", []any{false, "a", false, "b"}, false},
		{"TO_DATETIME", []any{nil}, false},
		{"TO_DATETIME", []any{"not-a-date"}, false},
		{"TO_IP", []any{nil}, false},
		{"TO_IP", []any{"not-an-ip"}, false},
		{"TO_IP", []any{"10.1.2.3"}, true},
		{"TO_IP", []any{[]any{nil, "bad"}}, false},
		{"TO_IP", []any{[]any{"10.0.0.1"}}, true},
		{"TO_IP", []any{[]any{"10.0.0.1", "2001:db8::1"}}, true},
		{"TO_VERSION", []any{nil}, false},
		{"TO_VERSION", []any{"  "}, false},
		{"TO_VERSION", []any{"8.15.5"}, true},
		{"TO_UNSIGNED_LONG", []any{nil}, false},
		{"TO_UNSIGNED_LONG", []any{int64(42)}, true},
		{"TO_UNSIGNED_LONG", []any{"18446744073709551615"}, true},
		{"TO_UNSIGNED_LONG", []any{"bad"}, false},
		{"MV_MEDIAN", []any{nil}, false},
		{"MV_MEDIAN", []any{[]any{"bad"}}, false},
		{"MV_MEDIAN", []any{[]any{1, 5, 3}}, true},
		{"MV_MEDIAN", []any{[]any{1, 5, 3, 7}}, true},
		{"MV_MEDIAN_ABSOLUTE_DEVIATION", []any{nil}, false},
		{"MV_MEDIAN_ABSOLUTE_DEVIATION", []any{[]any{"bad"}}, false},
		{"MV_MEDIAN_ABSOLUTE_DEVIATION", []any{[]any{1, 2, 4}}, true},
		{"MV_MEDIAN_ABSOLUTE_DEVIATION", []any{[]any{1, 2, 4, 8}}, true},
		{"MV_COUNT", []any{nil}, false},
		{"MV_MIN", []any{nil}, false},
		{"MV_MIN", []any{[]any{nil, int64(3), int64(1)}}, true},
		{"MV_SUM", []any{nil}, false},
		{"MV_SUM", []any{[]any{"bad"}}, false},
		{"MV_AVG", []any{nil}, false},
		{"MV_AVG", []any{[]any{"bad"}}, false},
		{"MV_CONCAT", []any{nil, ","}, false},
		{"MV_CONCAT", []any{[]any{}, ","}, false},
		{"MV_CONCAT", []any{[]any{nil, "a", "b"}, ","}, true},
		{"MV_DEDUPE", []any{nil}, false},
		{"MV_DEDUPE", []any{[]any{nil, "x"}}, true},
		{"MV_SORT", []any{nil}, false},
		{"MV_SLICE", []any{nil, 0}, false},
		{"MV_SLICE", []any{[]any{}, 0}, true},
		{"MV_SLICE", []any{[]any{"a", "b"}, "bad"}, false},
		{"MV_SLICE", []any{[]any{"a", "b", "c"}, int64(-2), int64(-1)}, true},
		{"MV_SLICE", []any{[]any{"a", "b"}, int64(5), int64(1)}, true},
		{"MV_SLICE", []any{[]any{"a", "b"}, int64(0), int64(0)}, true},
		{"DATE_EXTRACT", []any{nil, "2026-01-01T00:00:00Z"}, false},
		{"DATE_EXTRACT", []any{"year", "bad"}, false},
		{"DATE_EXTRACT", []any{"month", "2026-03-01T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"day", "2026-03-01T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"day_of_year", "2026-03-01T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"dow", "2026-11-22T01:02:03.456Z"}, true}, // Sunday -> 7
		{"DATE_EXTRACT", []any{"hour", "2026-11-22T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"minute", "2026-11-22T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"second", "2026-11-22T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"millis", "2026-11-22T01:02:03.456Z"}, true},
		{"DATE_EXTRACT", []any{"unknown", "2026-11-22T01:02:03.456Z"}, false},
		{"DATE_TRUNC", []any{nil, "2026-01-01T00:00:00Z"}, false},
		{"DATE_TRUNC", []any{"1d", "bad"}, false},
		{"DATE_TRUNC", []any{"1y", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"month", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"1d", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"1h", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"5m", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"minute", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"second", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"1w", "2026-06-15T12:34:56Z"}, true},
		{"DATE_TRUNC", []any{"bad_unit", "2026-06-15T12:34:56Z"}, false},
		{"DATE_PARSE", []any{nil, "2026-01-01"}, false},
		{"DATE_PARSE", []any{"yyyy-MM-dd", "bad"}, false},
		{"DATE_FORMAT", []any{nil, "2026-01-01T00:00:00Z"}, false},
		{"DATE_FORMAT", []any{"2026-01-01T00:00:00Z", "yyyy-MM-dd", "en"}, true},
		{"DATE_FORMAT", []any{"bad", "bad"}, false},
		{"DATE_FORMAT", []any{"UNIX_MS", "2026-01-01T00:00:00Z"}, true},
		{"DATE_DIFF", []any{nil, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, false},
		{"DATE_DIFF", []any{"days", "bad", "2026-01-02T00:00:00Z"}, false},
		{"DATE_DIFF", []any{"years", "2025-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"months", "2025-01-01T00:00:00Z", "2026-03-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"weeks", "2026-01-01T00:00:00Z", "2026-01-20T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"hours", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"minutes", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"seconds", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"ms", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, true},
		{"DATE_DIFF", []any{"unknown", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"}, false},
		{"CIDR_MATCH", []any{nil, "10.0.0.0/8"}, false},
		{"CIDR_MATCH", []any{"10.1.2.3", "invalid_cidr"}, true},
		{"CIDR_MATCH", []any{[]any{nil, "bad_ip", "10.1.2.3"}, []any{nil, "10.0.0.0/8"}}, true},
		{"CIDR_MATCH", []any{"192.168.1.1", "10.0.0.0/8"}, true},
	} {
		v, ok := evalESQLFuncRound57(tc.fn, tc.args)
		if !ok {
			t.Fatalf("expected known ES|QL func %s", tc.fn)
		}
		if tc.want && v == nil {
			t.Fatalf("expected non-nil for %s(%v)", tc.fn, tc.args)
		}
	}
	if _, ok := evalESQLFuncRound57("UNKNOWN_FN_XYZ", nil); ok {
		t.Fatalf("expected false for unknown function")
	}

	if v, _, ok := computeESQLMedianOrPercentile("MEDIAN", "x", []map[string]any{{"x": []any{10.0, 20.0}}}); !ok || v != 15.0 {
		t.Fatalf("expected MEDIAN=15, got %v %v", v, ok)
	}
	if v, _, ok := computeESQLMedianOrPercentile("MEDIAN_ABSOLUTE_DEVIATION", "x", []map[string]any{{"x": []any{1.0, 5.0}}}); !ok || v != 2.0 {
		t.Fatalf("expected MAD=2, got %v %v", v, ok)
	}
	if v, _, ok := computeESQLMedianOrPercentile("MEDIAN_ABSOLUTE_DEVIATION", "x", []map[string]any{{"x": "bad"}}); !ok || v != nil {
		t.Fatalf("expected nil MAD on non-numeric, got %v", v)
	}
	if v, _, ok := computeESQLMedianOrPercentile("MEDIAN_ABSOLUTE_DEVIATION", "x", []map[string]any{{"x": 5.0}}); !ok || v != 0.0 {
		t.Fatalf("expected MAD=0 on single value, got %v", v)
	}
	if v, _, ok := computeESQLMedianOrPercentile("PERCENTILE", "x", nil); !ok || v != nil {
		t.Fatalf("expected nil PERCENTILE with missing pct arg, got %v", v)
	}
	if v, _, ok := computeESQLMedianOrPercentile("PERCENTILE", "x, 120", []map[string]any{{"x": 1.0}}); !ok || v != nil {
		t.Fatalf("expected nil PERCENTILE for pct>100, got %v", v)
	}
	if v, _, ok := computeESQLMedianOrPercentile("PERCENTILE", "x, 50", []map[string]any{{"x": 7.0}}); !ok || v != 7.0 {
		t.Fatalf("expected PERCENTILE=7 on single val, got %v", v)
	}
	if _, _, ok := computeESQLMedianOrPercentile("OTHER", "x", nil); ok {
		t.Fatalf("expected false for OTHER")
	}

	// 2. HTTP ES|QL stages: EVAL reorder, KEEP with dynamic:false, params (2.0 double vs 2 integer), DISSECT, GROK, ENRICH, LOOKUP JOIN, STATS MEDIAN/PERCENTILE, MV_EXPAND
	srv, h := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_esql_dynfalse", `{
		"mappings": {
			"dynamic": false,
			"properties": {
				"msg": {"type": "keyword"},
				"ip_s": {"type": "keyword"},
				"score": {"type": "double"},
				"loc": {"type": "geo_point"},
				"tags": {"type": "keyword"}
			}
		}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_esql_dynfalse/_doc/1?refresh=true", `{"msg":"u1-200:ok","ip_s":"10.0.0.5","score":10.0,"loc":"POINT (1.0 2.0)","tags":["a","b"],"unmapped_extra":"secret"}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_esql_dynfalse/_doc/2?refresh=true", `{"msg":"u2-404:miss","ip_s":"10.0.0.9","score":20.0,"loc":"POINT (3.0 4.0)","tags":["b"]}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_esql_dynfalse/_doc/3?refresh=true", `{"msg":"u3-500:err","ip_s":"192.168.1.1","score":30.0,"loc":"POINT (5.0 6.0)","tags":["c"]}`, http.StatusCreated)

	// Setup Enrich policies (match with multi-match + IP range) and Lookup index + inline tables
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_enrich_src", `{"mappings":{"properties":{"k":{"type":"keyword"},"tier":{"type":"keyword"},"cidr":{"type":"ip_range"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_enrich_src/_doc/1?refresh=true", `{"k":"u1","tier":"gold","cidr":"10.0.0.0/24"}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_enrich_src/_doc/2?refresh=true", `{"k":"u1","tier":"vip","cidr":"10.0.0.0/8"}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_enrich/policy/r65_pol_match", `{"match":{"indices":"r65_enrich_src","match_field":"k","enrich_fields":["tier"]}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_enrich/policy/r65_pol_match/_execute", "", http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_enrich/policy/r65_pol_ip", `{"range":{"indices":"r65_enrich_src","match_field":"cidr","enrich_fields":["tier"]}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_enrich/policy/r65_pol_ip/_execute", "", http.StatusOK)

	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_lkp", `{"settings":{"index":{"mode":"lookup"}},"mappings":{"properties":{"k":{"type":"keyword"},"dept":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_lkp/_doc/1?refresh=true", `{"k":"u1","dept":"eng"}`, http.StatusCreated)

	// Params double 2.0 vs integer 2 + EVAL reordering existing column + KEEP with dynamic:false + COALESCE/TO_IP/TO_GEOPOINT
	qParams := r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "ROW d = ?, i = ? | EVAL c = COALESCE(null, d), d = d + 1.0 | KEEP i, c, d",
		"params": [2.0, 2]
	}`, http.StatusOK)
	if cols := qParams["columns"].([]any); len(cols) != 3 || cols[2].(map[string]any)["name"] != "d" {
		t.Fatalf("expected EVAL column reordering placing updated 'd' last, got %v", cols)
	}
	if vals := qParams["values"].([]any)[0].([]any); len(vals) != 3 {
		t.Fatalf("expected 3 values, got %v", vals)
	}

	qDyn := r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "FROM r65_esql_dynfalse | EVAL score = score * 2.0, ip_val = TO_IP(ip_s), gp = TO_GEOPOINT(loc), fb = COALESCE(missing_f, \"none\") | KEEP msg, ip_val, gp, fb, score, unmapped_extra"
	}`, http.StatusOK)
	if rowsDyn := qDyn["values"].([]any); len(rowsDyn) != 3 {
		t.Fatalf("expected 3 rows from dynamic:false index, got %v", qDyn)
	} else if rowsDyn[0].([]any)[5] != nil {
		t.Fatalf("expected unmapped_extra=nil under dynamic:false, got %v", rowsDyn[0])
	}

	// DISSECT + GROK (with float, bool, unmatching) + ENRICH (multi-match + nil onField) + LOOKUP JOIN (index + inline) + MV_EXPAND + STATS MEDIAN/MAD/PERCENTILE
	qPipe := r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "FROM r65_esql_dynfalse | DISSECT msg \"%{k}-%{rest}\" | GROK rest \"%{INT:code:int}:%{WORD:status}\" | ENRICH r65_pol_match ON k WITH tier_out = tier | ENRICH r65_pol_ip ON ip_s | LOOKUP JOIN r65_lkp ON k | MV_EXPAND tags | STATS med = MEDIAN(score), mad = MEDIAN_ABSOLUTE_DEVIATION(score), p90 = PERCENTILE(score, 90)"
	}`, http.StatusOK)
	if vals := qPipe["values"].([]any); len(vals) != 1 {
		t.Fatalf("expected 1 STATS row, got %v", qPipe)
	}
	r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "ROW msg = null, g = \"1.5 true\", k = null | DISSECT msg \"%{a}-%{b}\" | GROK g \"%{NUMBER:f:float} %{WORD:b:boolean}\" | ENRICH r65_pol_match ON k"
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "ROW msg = \"no_sep\", g = \"no_match\" | DISSECT msg \"%{a}-%{b}\" | GROK g \"%{INT:n:int}\" | LOOKUP JOIN inl_t ON k",
		"tables": {"inl_t": {"columns": [{"name": "k", "type": "keyword"}, {"name": "v", "type": "long"}], "values": [["x", 1]]}}
	}`, http.StatusOK)

	// Error paths in DISSECT, GROK, ENRICH, MV_EXPAND
	for _, badQ := range []string{
		`ROW a="x" | DISSECT a`,
		`ROW a="x" | DISSECT a "%{unclosed"`,
		`ROW a="x" | GROK a`,
		`ROW a="x" | GROK a "%{NO_SUCH_PAT_XYZ}"`,
		`ROW a="x" | ENRICH`,
		`ROW a="x" | ENRICH no_such_pol`,
		`ROW arr=[1] | MV_EXPAND`,
	} {
		r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{"query":`+jsonMarshalStrR65(badQ)+`}`, http.StatusBadRequest)
	}
	// IP policy with invalid IP string triggers 500
	r65CovBMustHTTP(t, h, http.MethodPost, "/_query", `{"query":"ROW ip_s=\"not_an_ip\" | ENRICH r65_pol_ip ON ip_s"}`, http.StatusInternalServerError)

	// 3. handleFlushSyncedRound57 (direct + ES 8.15.5, ES 7.10.2 deprecation header, closed index, invalid method)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_fs_closed", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_fs_closed/_close", "", http.StatusOK)
	if c, _, _, _ := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		srv.handleFlushSyncedR62Search(w, r, "")
	}, http.MethodDelete, "/_flush/synced", "", nil, nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE handleFlushSyncedRound57, got %d", c)
	}
	if c, _, _, raw := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		srv.handleFlushSyncedR62Search(w, r, "r65_esql_dynfalse")
	}, http.MethodPost, "/r65_esql_dynfalse/_flush/synced", "", nil, nil); c != http.StatusOK {
		t.Fatalf("expected 200 on handleFlushSyncedRound57 index, got %d %s", c, raw)
	}
	if c, _, _, raw := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		srv.handleFlushSyncedR62Search(w, r, "")
	}, http.MethodGet, "/_flush/synced", "", nil, nil); c != http.StatusOK {
		t.Fatalf("expected 200 on handleFlushSyncedRound57 all, got %d %s", c, raw)
	}
	if c, _, _, _ := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		srv.handleFlushSyncedR62Search(w, r, "r65_missing_fs")
	}, http.MethodPost, "/r65_missing_fs/_flush/synced", "", nil, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing index handleFlushSyncedRound57, got %d", c)
	}
	if c, _, _, _ := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		srv.handleFlushSyncedR62Search(w, r, "r65_fs_closed")
	}, http.MethodPost, "/r65_fs_closed/_flush/synced", "", nil, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on closed index handleFlushSyncedRound57, got %d", c)
	}

	srv7, _ := newRound61AdminTestServer(t, "7.10.2")
	r65CovBMustHTTP(t, srv7.Handler(), http.MethodPut, "/r65_fs7", `{}`, http.StatusOK)
	cFS7, hdr7, _, rawFS7 := doDirectHandlerReqRound61(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Warning", `299 Elasticsearch-7.10.2 "Synced flush is deprecated"`)
		w.Header().Add("Warning", `299 Elasticsearch-7.10.2 "Other warning"`)
		srv7.handleFlushSyncedRound57(w, r, "r65_fs7")
	}, http.MethodPost, "/r65_fs7/_flush/synced", "", nil, nil)
	if cFS7 != http.StatusOK || len(hdr7.Values("Warning")) == 0 {
		t.Fatalf("expected 200 with deprecation Warning header on ES7 handleFlushSyncedRound57, got %d hdr=%v body=%s", cFS7, hdr7, rawFS7)
	}

	// 4. handleSimulateIndexIngestRound57: reroute destination default_pipeline + per-doc error envelope + drop + verbose
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_sim_reroute", `{
		"processors": [
			{"set": {"field": "_index", "value": "r65_sim_dest"}}
		]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_sim_dest_def", `{
		"processors": [
			{"set": {"field": "dest_enriched", "value": "yes"}},
			{"fail": {"if": "ctx.bad == true", "message": "sim boom"}}
		]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_sim_drop", `{
		"processors": [{"drop": {}}]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_sim_dest", `{
		"settings": {"index.default_pipeline": "r65_sim_dest_def"},
		"mappings": {"properties": {"nested_obj": {"properties": {"known": {"type": "keyword"}}}}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_sim_src", `{
		"settings": {"index.default_pipeline": "r65_sim_reroute"}
	}`, http.StatusOK)

	cSimBad, _, _, _ := doRound61AdminReq(t, h, http.MethodDelete, "/_ingest/_simulate", "", nil)
	if cSimBad != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE /_ingest/_simulate, got %d", cSimBad)
	}
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{"docs":["not_obj"]}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{"docs":[{"_source":{"a":1}}]}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{"docs":[{"_index":"r65_sim_src","_source":{"a":1}}],"pipeline_substitutions":{"bad":"x"}}`, http.StatusBadRequest)

	simRes := r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate?verbose=true", `{
		"docs": [
			{"_index": "r65_sim_src", "_id": "ok1", "_routing": "rt1", "_source": {"nested_obj": {"known": "k", "dyn": "v"}}},
			{"_index": "r65_sim_src", "_id": "err1", "_source": {"bad": true}},
			{"_index": "r65_sim_src", "_id": "drop1", "_pipeline": "r65_sim_drop", "_source": {"x": 1}}
		],
		"pipeline_substitutions": {
			"r65_sim_dest_def": {
				"processors": [
					{"set": {"field": "dest_enriched", "value": "yes"}},
					{"fail": {"if": "ctx.bad == true", "message": "sim boom"}}
				]
			}
		}
	}`, http.StatusOK)
	docsOut := simRes["docs"].([]any)
	if len(docsOut) != 3 {
		t.Fatalf("expected 3 simulate results, got %v", simRes)
	}
	okDoc := docsOut[0].(map[string]any)["doc"].(map[string]any)
	if okDoc["_index"] != "r65_sim_dest" || okDoc["_source"].(map[string]any)["dest_enriched"] != "yes" {
		t.Fatalf("expected reroute dest default_pipeline execution, got %v", okDoc)
	}
	errEntry := docsOut[1].(map[string]any)
	errDoc := errEntry["doc"].(map[string]any)
	if errDoc["_index"] != "r65_sim_dest" || errDoc["_id"] != "err1" || errDoc["error"] == nil {
		t.Fatalf("expected per-doc error envelope with _index/_id/error, got %v", errEntry)
	}
	if docsOut[2].(map[string]any)["doc"] != nil {
		t.Fatalf("expected nil doc for dropped doc, got %v", docsOut[2])
	}
	// Body index, body pipeline, template match on uncreated index, flat doc (no _source), invalid JSON
	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_sim_tpl", `{
		"index_patterns": ["r65_sim_tpl_*"],
		"template": {"settings": {"index.default_pipeline": "r65_sim_dest_def"}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{
		"index": "r65_sim_tpl_1",
		"pipeline": "r65_sim_reroute",
		"docs": [{"_id": "flat1", "a": 1}]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{bad`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ingest/_simulate", `{"docs":[{"_index":"r65_sim_src","_source":{"a":1}}],"pipeline_substitutions":{"p_bad":{"processors":[{"unknown_proc":{}}]}}}`, http.StatusInternalServerError)
	_ = srv
}

func jsonMarshalStrR65(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRound65CovAdminESQL_PutMappingAndSchemaHelpers(t *testing.T) {
	// 1. handlePutMappingR61CRUD across ES 8, ES 7, and edge cases
	srv8, h8 := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1", `{"mappings":{"properties":{"f1":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_2", `{"mappings":{"properties":{"f1":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_blk", `{"settings":{"index.blocks.metadata":true}}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_tsdb", `{
		"settings":{"index":{"mode":"time_series","routing_path":["dim"]}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"dim":{"type":"keyword","time_series_dimension":true},"val":{"type":"long","time_series_metric":"gauge"}}}
	}`, http.StatusOK)

	// ES 8 rejects path type & _doc body wrapper & unknown root key & empty prop & missing index & blocked & incompatible update
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping/_doc", `{"properties":{"a":{"type":"keyword"}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"_doc":{"properties":{"a":{"type":"keyword"}}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"unknown_root":{"a":1}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{bad`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"properties":{"":{"type":"keyword"}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_missing/_mapping", `{"properties":{"a":{"type":"keyword"}}}`, http.StatusNotFound)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_no_match_*/_mapping?allow_no_indices=false", `{"properties":{"a":{"type":"keyword"}}}`, http.StatusNotFound)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_no_match_*/_mapping?allow_no_indices=true", `{"properties":{"a":{"type":"keyword"}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_blk/_mapping", `{"properties":{"a":{"type":"keyword"}}}`, http.StatusForbidden)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"properties":{"f1":{"type":"long"}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_tsdb/_mapping", `{"_routing":{"required":true}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_tsdb/_mapping", `{"runtime":{"dim":{"type":"keyword","script":"emit('x')"}}}`, http.StatusBadRequest)

	// Valid updates: dynamic, ignore_above, subfields, multi-index, _meta, envelope, _all, write_index alias
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1,r65_pm_2/_mapping", `{
		"dynamic": "strict",
		"_meta": {"owner": "team-a"},
		"properties": {
			"title": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 128}}}
		}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"mappings":{"properties":{"env_f":{"type":"integer"}}}}`, http.StatusOK)
	_, hAll := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, hAll, http.MethodPut, "/r65_pm_all", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, hAll, http.MethodPut, "/_all/_mapping", `{"properties":{"all_f":{"type":"keyword"}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping?include_type_name=bad", `{"properties":{}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_1/_mapping", `{"runtime":{"bad_rt":{"type":"keyword","script":"if ("}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h8, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"r65_pm_1","alias":"r65_pm_al","is_write_index":true}}]}`, http.StatusOK)
	r65CovBMustHTTP(t, h8, http.MethodPut, "/r65_pm_al/_mapping", `{"properties":{"via_alias":{"type":"keyword"}}}`, http.StatusOK)

	// ES 7 include_type_name=true branches
	_, h7 := newRound61AdminTestServer(t, "7.10.2")
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", "", http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"properties":{}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"_bad":{"properties":{}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"mytype":"not_a_map"}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping/t1?include_type_name=true", `{"t2":{"properties":{}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"mytype":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"other_type":{"properties":{"k2":{"type":"keyword"}}}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_pm7_idx/_mapping?include_type_name=true", `{"mytype":null}`, http.StatusOK)

	// 2. unwrapTypeKeyedMappingsJSONR61CRUD
	if u, _, _, _, _ := unwrapTypeKeyedMappingsJSONR61CRUD(nil, false); u != nil {
		t.Fatalf("expected nil on nil mappings")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD("bad", false); et != "mapper_parsing_exception" {
		t.Fatalf("expected mapper_parsing_exception, got %q", et)
	}
	if _, tn, _, _, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{}, true); tn != "_doc" {
		t.Fatalf("expected _doc for empty map includeTypeName=true, got %q", tn)
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"_doc": map[string]any{}}, false); et != "illegal_argument_exception" {
		t.Fatalf("expected illegal_argument_exception on _doc without include_type_name")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"other": map[string]any{}}, false); et != "mapper_parsing_exception" {
		t.Fatalf("expected mapper_parsing_exception on unknown root key")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"properties": map[string]any{}}, true); et != "mapper_parsing_exception" {
		t.Fatalf("expected mapper_parsing_exception for reserved root key with includeTypeName=true")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"t1": map[string]any{}, "t2": map[string]any{}}, true); et != "illegal_argument_exception" {
		t.Fatalf("expected multi-type error")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{" ": map[string]any{}}, true); et != "illegal_argument_exception" {
		t.Fatalf("expected empty type error")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"_bad": map[string]any{}}, true); et != "invalid_type_name_exception" {
		t.Fatalf("expected invalid_type_name_exception")
	}
	if _, _, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"t1": "bad"}, true); et != "mapper_parsing_exception" {
		t.Fatalf("expected map error on non-map type body")
	}
	if _, tn, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"t1": nil}, true); et != "" || tn != "t1" {
		t.Fatalf("expected t1 nil unwrap success, got tn=%q et=%q", tn, et)
	}
	if _, tn, _, et, _ := unwrapTypeKeyedMappingsJSONR61CRUD(map[string]any{"_doc": map[string]any{"properties": map[string]any{}}}, true); et != "" || tn != "_doc" {
		t.Fatalf("expected _doc unwrap success, got tn=%q et=%q", tn, et)
	}

	// 3. isFieldExplicitlyStoredInSchemaR61CRUD
	if isFieldExplicitlyStoredInSchemaR61CRUD(nil, "a") {
		t.Fatalf("expected false on nil schema")
	}
	boolT, boolF := true, false
	scExplicit := &schema.IndexSchema{
		ES8Mode: false,
		RawMapping: &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"top_t": {Type: "keyword", Store: &boolT},
				"top_f": {Type: "keyword", Store: &boolF},
				"obj": {
					Type: "object",
					Properties: map[string]esast.FieldProperty{
						"sub": {Type: "keyword", Store: &boolT},
					},
				},
				"txt": {
					Type: "text",
					Fields: map[string]esast.FieldProperty{
						"kw": {Type: "keyword", Store: &boolT},
					},
				},
				"dot.grp": {
					Type: "object",
					Properties: map[string]esast.FieldProperty{
						"leaf": {Type: "keyword"},
					},
				},
			},
		},
	}
	if !isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "top_t") ||
		isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "top_f") ||
		!isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "obj.sub") ||
		!isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "txt.kw") ||
		isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "dot.grp.leaf") ||
		isFieldExplicitlyStoredInSchemaR61CRUD(scExplicit, "missing") {
		t.Fatalf("unexpected store evaluation on scExplicit")
	}
	scES7NoStore := &schema.IndexSchema{
		ES8Mode: false,
		RawMapping: &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"plain": {Type: "keyword"},
			},
		},
	}
	if !isFieldExplicitlyStoredInSchemaR61CRUD(scES7NoStore, "plain") {
		t.Fatalf("expected ES7 schema without explicit store config to default true")
	}
	_ = srv8
}

func TestRound65CovAdminESQL_SpatialUnindexedAndILM(t *testing.T) {
	// 1. queryUsesUnindexedFieldR64
	idxFalse := false
	sc := schema.CompileIndexSchema("es_db", "r65_unidx", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"idx_kw":   {Type: "keyword"},
			"unidx_kw": {Type: "keyword", Index: &idxFalse},
			"const_kw": {Type: "constant_keyword", Value: "v"},
		},
		Runtime: map[string]esast.FieldProperty{
			"rt_f": {Type: "keyword", Script: "emit('x')"},
		},
	})
	sc.Fields["rt_f"] = schema.FieldBinding{ESFieldPath: "rt_f", ESType: "keyword", FromRuntime: true}
	scOther := schema.CompileIndexSchema("es_db", "r65_unidx_other", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"other_unidx": {Type: "keyword", Index: &idxFalse}},
	})
	schemas := map[string]*schema.IndexSchema{"r65_unidx": sc, "r65_unidx_other": scOther}
	if !queryUsesUnindexedFieldR64(&esast.Query{Term: map[string]esast.TermEntry{"other_unidx": {Value: "v"}}}, schemas, sc) {
		t.Fatalf("expected unindexed in schemasByIndex to return true")
	}
	if queryUsesUnindexedFieldR64(nil, schemas, sc) {
		t.Fatalf("expected false on nil query")
	}
	if queryUsesUnindexedFieldR64(&esast.Query{Term: map[string]esast.TermEntry{"const_kw": {Value: "v"}}}, schemas, sc) {
		t.Fatalf("constant_keyword should not be treated as unindexed")
	}
	if queryUsesUnindexedFieldR64(&esast.Query{Term: map[string]esast.TermEntry{"idx_kw": {Value: "v"}}}, schemas, sc) {
		t.Fatalf("indexed keyword should return false")
	}
	unidxQueries := []*esast.Query{
		{Term: map[string]esast.TermEntry{"unidx_kw": {Value: "v"}}},
		{Range: map[string]esast.RangeCond{"unidx_kw": {GTE: "a"}}},
		{Prefix: map[string]esast.PrefixEntry{"unidx_kw": {Value: "a"}}},
		{Wildcard: map[string]esast.WildcardEntry{"unidx_kw": {Value: "a*"}}},
		{Regexp: map[string]esast.RegexpEntry{"unidx_kw": {Value: "a.*"}}},
		{Fuzzy: map[string]esast.FuzzyEntry{"unidx_kw": {Value: "a"}}},
		{Match: map[string]esast.MatchEntry{"unidx_kw": {Query: "a"}}},
		{MatchPhrase: map[string]esast.PhraseEntry{"unidx_kw": {Query: "a"}}},
		{MatchPhrasePrefix: map[string]esast.PhraseEntry{"unidx_kw": {Query: "a"}}},
		{MatchBoolPrefix: map[string]esast.PhraseEntry{"unidx_kw": {Query: "a"}}},
		{Common: map[string]esast.CommonTermsEntry{"unidx_kw": {Query: "a"}}},
		{TermsSet: map[string]esast.TermsSetEntry{"unidx_kw": {Terms: []any{"a"}}}},
		{Terms: &esast.TermsQuery{Fields: map[string][]any{"unidx_kw": {"a"}}}},
		{Terms: &esast.TermsQuery{Lookups: map[string]esast.TermsLookupSpec{"rt_f": {Index: "other", ID: "1", Path: "p"}}}},
		{Nested: &esast.NestedQuery{Path: "n", Query: esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{Boosting: &esast.BoostingQuery{Positive: esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{Boosting: &esast.BoostingQuery{Negative: esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{DisMax: &esast.DisMaxQuery{Queries: esast.QuerySlice{{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}},
		{FunctionScore: &esast.FunctionScoreQuery{Query: &esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{FunctionScore: &esast.FunctionScoreQuery{Functions: []esast.ScoreFunctionSpec{{Filter: &esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}}},
		{ScriptScore: &esast.ScriptScoreQuery{Query: &esast.Query{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}},
		{Bool: &esast.BoolQuery{Must: esast.QuerySlice{{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}},
		{Bool: &esast.BoolQuery{Filter: esast.QuerySlice{{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}},
		{Bool: &esast.BoolQuery{Should: esast.QuerySlice{{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}},
		{Bool: &esast.BoolQuery{MustNot: esast.QuerySlice{{Term: map[string]esast.TermEntry{"rt_f": {Value: "x"}}}}}},
	}
	for i, uq := range unidxQueries {
		if !queryUsesUnindexedFieldR64(uq, schemas, sc) {
			t.Fatalf("case %d: expected queryUsesUnindexedFieldR64=true", i)
		}
	}

	// 2. evalDocWithSpatialFallbackR64
	spSchema := schema.CompileIndexSchema("es_db", "r65_sp", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"loc":   {Type: "geo_point"},
			"shape": {Type: "geo_shape"},
			"items": {Type: "nested", Properties: map[string]esast.FieldProperty{"loc": {Type: "geo_point"}}},
		},
	})
	docSpatial := map[string]any{
		"_id":   "d1",
		"loc":   map[string]any{"lat": 40.7, "lon": -74.0},
		"shape": map[string]any{"type": "point", "coordinates": []any{-74.0, 40.7}},
		"items": []any{map[string]any{"loc": map[string]any{"lat": 40.7, "lon": -74.0}}},
	}
	if !evalDocWithSpatialFallbackR64(spSchema, docSpatial, nil) {
		t.Fatalf("expected true for nil spatial query")
	}
	bbox := &esast.Query{GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "loc", Top: 41, Left: -75, Bottom: 40, Right: -73}}
	gdist := &esast.Query{GeoDistance: &esast.GeoDistanceQuery{Field: "loc", Lat: 40.7, Lon: -74.0, Distance: "10km", DistanceMeters: 10000}}
	gpoly := &esast.Query{GeoPolygon: &esast.GeoPolygonQuery{Field: "loc", Points: [][2]float64{{40, -75}, {41, -75}, {41, -73}, {40, -73}}}}
	gshape := &esast.Query{GeoShape: &esast.GeoShapeQuery{Field: "shape", Shape: map[string]any{"type": "envelope", "coordinates": []any{[]any{-75.0, 41.0}, []any{-73.0, 40.0}}}, Relation: "INTERSECTS"}}
	ggrid := &esast.Query{GeoGrid: &esast.GeoGridQuery{Field: "loc", Geohash: "dr5r"}}
	for _, q := range []*esast.Query{
		bbox, gdist, gpoly, gshape, ggrid,
		{Exists: &esast.ExistsQuery{Field: "shape"}},
		{Bool: &esast.BoolQuery{Must: esast.QuerySlice{*gshape}, Filter: esast.QuerySlice{*bbox}, MustNot: esast.QuerySlice{{GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "loc", Top: 10, Left: 10, Bottom: 9, Right: 11}}}, Should: esast.QuerySlice{*gshape}, MinimumShouldMatch: 1}},
		{ConstantScore: &esast.ConstantScoreQuery{Filter: *gshape}},
		{DisMax: &esast.DisMaxQuery{Queries: esast.QuerySlice{*gshape}}},
		{Boosting: &esast.BoostingQuery{Positive: *gshape}},
		{Nested: &esast.NestedQuery{Path: "items", Query: esast.Query{GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "loc", Top: 41, Left: -75, Bottom: 40, Right: -73}}}},
		{ScriptScore: &esast.ScriptScoreQuery{Query: gshape}},
		{FunctionScore: &esast.FunctionScoreQuery{Query: gshape}},
		{Wrapper: &esast.WrapperQuery{Decoded: gshape}},
		{Pinned: &esast.PinnedQuery{IDs: []string{"d1"}, Organic: gshape}},
		{Pinned: &esast.PinnedQuery{IDs: []string{"other"}, Organic: gshape}},
	} {
		if !evalDocWithSpatialFallbackR64(spSchema, docSpatial, q) {
			t.Fatalf("expected true for spatial query %+v", q)
		}
	}
	if evalDocWithSpatialFallbackR64(spSchema, map[string]any{"shape": []any{}}, &esast.Query{Exists: &esast.ExistsQuery{Field: "shape"}}) {
		t.Fatalf("expected false for empty slice geo_shape exists")
	}

	// 3. collectAllILMExplainTargetsR64 + /_ilm/move on hot step with min_age vs empty hot
	srv, h := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ilm_vis", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ilm_hid", `{"settings":{"index.hidden":true}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_index_template/r65_ilm_ds_tpl", `{
		"index_patterns": ["r65-ilm-ds*"],
		"data_stream": {},
		"template": {"mappings":{"properties":{"@timestamp":{"type":"date"}}}}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_data_stream/r65-ilm-ds", "", http.StatusOK)

	targets := srv.collectAllILMExplainTargetsR64()
	if len(targets) < 2 {
		t.Fatalf("expected at least concrete + DS backing in collectAllILMExplainTargetsR64, got %v", targets)
	}
	r65CovBMustHTTP(t, h, http.MethodGet, "/_ilm/explain", "", http.StatusOK)

	// Hot step with min_age > 0 stays in "new"; empty hot starts in "hot".
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ilm/policy/r65_pol_minage", `{"policy":{"phases":{"hot":{"min_age":"1d","actions":{}},"warm":{"min_age":"2d","actions":{}}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ilm/policy/r65_pol_emptyhot", `{"policy":{"phases":{"hot":{"actions":{}},"warm":{"actions":{}}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ilm_idx_ma", `{"settings":{"index.lifecycle.name":"r65_pol_minage"}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ilm_idx_eh", `{"settings":{"index.lifecycle.name":"r65_pol_emptyhot"}}`, http.StatusOK)

	// min_age=1d -> actualPhase="new", so claiming current_step=hot fails 400, claiming new succeeds!
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_idx_ma", `{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"warm","action":"complete","name":"complete"}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_idx_ma", `{"current_step":{"phase":"new","action":"complete","name":"complete"},"next_step":{"phase":"warm","action":"complete","name":"complete"}}`, http.StatusOK)

	// Empty hot -> actualPhase="hot"; unknown target phase fails 400; valid move succeeds!
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_idx_eh", `{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"cold"}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_idx_eh", `{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"warm","action":"complete","name":"complete"}}`, http.StatusOK)

	// Additional serveILMMoveToStepRound63 edge cases (method, missing index, missing next_step, no policy, missing policy, no explicit ES version)
	if c, _, _, _ := doRound61AdminReq(t, h, http.MethodGet, "/_ilm/move/r65_ilm_idx_eh", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /_ilm/move, got %d", c)
	}
	if c, _, _, _ := doDirectHandlerReqRound61(t, srv.serveILMMoveToStepRound63, http.MethodPost, "/_ilm/move/", `{}`, nil, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing index path, got %d", c)
	}
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/no_such_ilm_idx", `{"next_step":{"phase":"warm"}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_idx_eh", `{}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_vis", `{"next_step":{"phase":"warm"}}`, http.StatusBadRequest)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ilm_missing_pol", `{"settings":{"index.lifecycle.name":"deleted_pol"}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/_ilm/move/r65_ilm_missing_pol", `{"next_step":{"phase":"warm"}}`, http.StatusBadRequest)
	srvNV := NewServer("es_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	hNV := srvNV.Handler()
	r65CovBMustHTTP(t, hNV, http.MethodPut, "/r65_ilm_nv", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, hNV, http.MethodPost, "/_ilm/move/no_such_nv", `{"next_step":{"phase":"warm"}}`, http.StatusNotFound)
	r65CovBMustHTTP(t, hNV, http.MethodPost, "/_ilm/move/r65_ilm_nv", `{"next_step":{"phase":"warm","action":"complete","name":"complete"}}`, http.StatusOK)
}

func TestRound65CovAdminESQL_NodeIngestStatsAndCollectDocs(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. Run real ingest pipelines (success + failure) then query GET /_nodes/stats/ingest?human=true
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_ing_p1", `{
		"processors": [
			{"set": {"field": "env", "value": "prod"}},
			{"fail": {"if": "ctx.should_fail == true", "message": "failed", "tag": "t1"}}
		]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_ing_idx", `{"mappings":{"properties":{"env":{"type":"keyword"},"v":{"type":"long"}}}}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_ing_idx/_doc/1?pipeline=r65_ing_p1&refresh=true", `{"v":1}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_ing_idx/_doc/2?pipeline=r65_ing_p1&refresh=true", `{"v":2,"should_fail":true}`, http.StatusBadRequest)

	nodeStats := r65CovBMustHTTP(t, h, http.MethodGet, "/_nodes/stats/ingest?human=true", "", http.StatusOK)
	if nodeStats["nodes"] == nil {
		t.Fatalf("expected nodes in /_nodes/stats/ingest, got %v", nodeStats)
	}

	// Also exercise legacy round61AdminState merge + ES7 stripping in buildNodeIngestStatsRound61
	st := getOrCreateRound61AdminState(srv)
	st.mu.Lock()
	st.ingestTotal = round61IngestCounters{count: 3, timeInMillis: 15, current: 0, failed: 1}
	st.ingestPipelines["r65_ing_p1"] = &round61PipelineStats{
		counters: round61IngestCounters{count: 1, timeInMillis: 5, failed: 0},
	}
	st.ingestPipelines["r65_extra_pipe"] = &round61PipelineStats{
		counters: round61IngestCounters{count: 2, timeInMillis: 10, failed: 1, ingestedFirstBytes: 128, producedFirstBytes: 256},
		processors: []*round61ProcessorStat{
			{procType: "set", stats: round61IngestCounters{count: 2, timeInMillis: 10}},
		},
	}
	st.mu.Unlock()
	es8Ing := srv.buildNodeIngestStatsRound61(true, true)
	es7Ing := srv.buildNodeIngestStatsRound61(false, true)
	pExtra8 := es8Ing["pipelines"].(map[string]any)["r65_extra_pipe"].(map[string]any)
	pExtra7 := es7Ing["pipelines"].(map[string]any)["r65_extra_pipe"].(map[string]any)
	if _, hasBytes := pExtra8["ingested_in_bytes"]; !hasBytes {
		t.Fatalf("expected ingested_in_bytes in ES8 stats, got %v", pExtra8)
	}
	if _, hasBytes := pExtra7["ingested_in_bytes"]; hasBytes {
		t.Fatalf("expected ingested_in_bytes stripped in ES7 stats, got %v", pExtra7)
	}

	// 2. collectIndexedDocsWithIDsRound61 (nil server, closed index, normal + tombstone skip, aliasFilter fallback)
	var nilSrv *Server
	if docs := nilSrv.collectIndexedDocsWithIDsRound61(context.Background(), "r65_ing_idx", nil); docs != nil {
		t.Fatalf("expected nil on nil server")
	}
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_ing_idx/_doc/3?refresh=true", `{"env":"dev","v":3}`, http.StatusCreated)
	srv.mu.Lock()
	if srv.docDeleted["r65_ing_idx"] == nil {
		srv.docDeleted["r65_ing_idx"] = make(map[string]bool)
	}
	srv.docDeleted["r65_ing_idx"]["3"] = true
	srv.mu.Unlock()
	docsNoFilter := srv.collectIndexedDocsWithIDsRound61(context.Background(), "r65_ing_idx", nil)
	if len(docsNoFilter) != 1 || docsNoFilter[0].ID != "1" {
		t.Fatalf("expected only doc 1 after tombstone skip, got %v", docsNoFilter)
	}
	docsFiltered := srv.collectIndexedDocsWithIDsRound61(context.Background(), "r65_ing_idx", &esast.Query{
		Term: map[string]esast.TermEntry{"env": {Value: "prod"}},
	})
	if len(docsFiltered) != 1 || docsFiltered[0].ID != "1" {
		t.Fatalf("expected doc 1 via aliasFilter fallback, got %v", docsFiltered)
	}
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_ing_idx/_close", "", http.StatusOK)
	if closedDocs := srv.collectIndexedDocsWithIDsRound61(context.Background(), "r65_ing_idx", nil); closedDocs != nil {
		t.Fatalf("expected nil for closed index, got %v", closedDocs)
	}
}

func TestRound65CovAdminESQL_SnapshotAutoscalingSLMSortAndDeprecations(t *testing.T) {
	// 1. mergeSimulatedIndexTemplateOverrideRound61
	p1, p2 := 10, 20
	v1, v2 := 1, 2
	baseTpl := esast.IndexTemplateRequest{
		IndexPatterns: []string{"logs-*"},
		Priority:      &p1,
		Template: &esast.IndexCreateRequest{
			Settings: map[string]any{"number_of_shards": 1},
			Mappings: &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"a": {Type: "keyword"}}},
			Aliases:  map[string]map[string]any{"al1": {}},
		},
	}
	partialOv := esast.IndexTemplateRequest{
		Patterns:   []string{"logs2-*"},
		Priority:   &p2,
		ComposedOf: []string{"comp1"},
		Version:    &v2,
		Meta:       map[string]any{"k": "v"},
		DataStream: map[string]any{},
		Template: &esast.IndexCreateRequest{
			Settings: map[string]any{"number_of_replicas": 0},
			Mappings: &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"b": {Type: "long"}}},
			Aliases:  map[string]map[string]any{"al2": {}},
		},
	}
	mergedPartial := mergeSimulatedIndexTemplateOverrideRound61(baseTpl, partialOv, map[string]any{
		"patterns": true, "priority": true, "composed_of": true, "version": true, "_meta": true, "data_stream": true,
		"template": map[string]any{"settings": true, "mappings": true, "aliases": true},
	})
	if *mergedPartial.Priority != 20 || len(mergedPartial.Template.Aliases) != 2 || len(mergedPartial.Template.Mappings.Properties) != 2 {
		t.Fatalf("unexpected partial template merge: %+v", mergedPartial)
	}
	_ = v1
	fullRepl := mergeSimulatedIndexTemplateOverrideRound61(baseTpl, esast.IndexTemplateRequest{
		IndexPatterns: []string{"new-*"},
		Template:      &esast.IndexCreateRequest{Settings: map[string]any{"x": 1}},
	}, map[string]any{"index_patterns": true, "template": map[string]any{}})
	if len(fullRepl.Template.Aliases) != 0 {
		t.Fatalf("expected full replacement when index_patterns + template given")
	}
	nilTpl := mergeSimulatedIndexTemplateOverrideRound61(baseTpl, esast.IndexTemplateRequest{Template: nil}, map[string]any{"template": nil})
	if nilTpl.Template != nil {
		t.Fatalf("expected nil Template")
	}
	fromNil := mergeSimulatedIndexTemplateOverrideRound61(esast.IndexTemplateRequest{}, esast.IndexTemplateRequest{Template: &esast.IndexCreateRequest{Settings: map[string]any{"a": 1}}}, map[string]any{"template": map[string]any{}})
	if fromNil.Template == nil {
		t.Fatalf("expected non-nil Template")
	}

	// 2. parseAutoscalingByteSizeR65
	for _, good := range []any{
		float64(100), int64(200), int(300), json.Number("400"),
		"1pb", "1tb", "1gb", "1mb", "1kb", "10b", "512",
	} {
		if got, err := parseAutoscalingByteSizeR65(good); err != nil || got <= 0 {
			t.Fatalf("parseAutoscalingByteSizeR65(%v) failed: %d %v", good, got, err)
		}
	}
	for _, bad := range []any{
		float64(-1), int64(-1), int(-1), json.Number("-5"), json.Number("bad"),
		"", "   ", "-1kb", "notnum", true,
	} {
		if _, err := parseAutoscalingByteSizeR65(bad); err == nil {
			t.Fatalf("expected error for parseAutoscalingByteSizeR65(%v)", bad)
		}
	}

	// 3. handleSLMAction
	_, h := newRound61AdminTestServer(t, "8.15.5")
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/_slm/_execute_retention", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_slm/_execute_retention", http.StatusOK},
		{http.MethodPost, "/_slm/status", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_slm/status", http.StatusOK},
		{http.MethodGet, "/_slm/stop", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_slm/stop", http.StatusOK},
		{http.MethodGet, "/_slm/start", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_slm/start", http.StatusOK},
		{http.MethodPost, "/_slm/stats", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_slm/stats", http.StatusOK},
		{http.MethodGet, "/_slm/unknown_act", http.StatusNotFound},
	} {
		r65CovBMustHTTP(t, h, tc.method, tc.path, "", tc.want)
	}

	// 4. formatSnapshotResponseItemRound61
	if formatSnapshotResponseItemRound61(nil, "r1", true, true, true, true) != nil {
		t.Fatalf("expected nil on nil rawSnap")
	}
	minSnap := formatSnapshotResponseItemRound61(map[string]any{"snapshot": "s1", "uuid": "u1", "state": "SUCCESS", "indices": []string{"i1"}}, "r1", false, true, true, false)
	if minSnap["repository"] != "r1" || minSnap["state"] != "SUCCESS" {
		t.Fatalf("unexpected non-verbose snapshot item: %v", minSnap)
	}
	detSnap1 := formatSnapshotResponseItemRound61(map[string]any{"snapshot": "s1", "uuid": "u1", "indices": []string{"i1"}}, "r1", true, false, false, true)
	if _, hasIdx := detSnap1["indices"]; hasIdx || detSnap1["index_details"].(map[string]any)["i1"] == nil {
		t.Fatalf("unexpected verbose []string snapshot item: %v", detSnap1)
	}
	detSnap2 := formatSnapshotResponseItemRound61(map[string]any{"snapshot": "s2", "uuid": "u2", "indices": []any{"i2"}}, "r1", true, true, true, true)
	if detSnap2["index_details"].(map[string]any)["i2"] == nil {
		t.Fatalf("unexpected verbose []any snapshot item: %v", detSnap2)
	}

	// 5. buildSnapshotURLTransportR65 (dial allowed loopback server + block SSRF/bad addresses)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer ts.Close()
	addr := ts.Listener.Addr().String()
	vAllowed, err := parseAndValidateSnapshotRepoURLR65("http://"+addr+"/repo", nil, []string{"http://" + addr + "/*"})
	if err != nil {
		t.Fatalf("parseAndValidateSnapshotRepoURLR65 failed: %v", err)
	}
	tr := buildSnapshotURLTransportR65(vAllowed)
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://" + addr + "/repo/ping")
	if err != nil {
		t.Fatalf("expected loopback dial to succeed when explicitly allowlisted: %v", err)
	}
	_ = resp.Body.Close()

	// Denied dials: invalid host:port, blocked IMDS IP, non-allowlisted loopback
	if _, dErr := tr.DialContext(context.Background(), "tcp", "no_port"); dErr == nil {
		t.Fatalf("expected error for invalid dial addr")
	}
	if _, dErr := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80"); dErr == nil {
		t.Fatalf("expected SSRF block for IMDS IP")
	}
	trRestrict := buildSnapshotURLTransportR65(&validatedSnapshotURLR65{explicitHostAllow: false})
	if _, dErr := trRestrict.DialContext(context.Background(), "tcp", addr); dErr == nil {
		t.Fatalf("expected SSRF block for unallowlisted loopback IP")
	}
	// Hostname DNS resolution branches (allowlisted vs SSRF-blocked vs DNS fail)
	port := strings.Split(addr, ":")[1]
	if _, dErr := trRestrict.DialContext(context.Background(), "tcp", "localhost:"+port); dErr == nil {
		t.Fatalf("expected SSRF block for resolved localhost IP")
	}
	if _, dErr := trRestrict.DialContext(context.Background(), "tcp", "nonexistent.r65cov.invalid:80"); dErr == nil {
		t.Fatalf("expected DNS failure for invalid host")
	}
	if vLocal, lErr := parseAndValidateSnapshotRepoURLR65("http://localhost:"+port+"/repo", nil, []string{"http://localhost:" + port + "/*"}); lErr == nil {
		trLocal := buildSnapshotURLTransportR65(vLocal)
		if conn, dErr := trLocal.DialContext(context.Background(), "tcp", "localhost:"+port); dErr == nil {
			_ = conn.Close()
		}
	}

	// 6. formatSortValueWithEntryFormatR63
	scSort := schema.CompileIndexSchema("es_db", "r65_sort", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"ts":    {Type: "date"},
			"ts_ns": {Type: "date_nanos"},
			"num":   {Type: "double"},
		},
	})
	if formatSortValueWithEntryFormatR63(nil, esast.SortSpec{}, scSort) != nil {
		t.Fatalf("expected nil on nil sort value")
	}
	if got := formatSortValueWithEntryFormatR63(float64(12.9), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "long"}}, scSort); got != int64(12) {
		t.Fatalf("expected int64(12), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(float32(7.8), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "long"}}, scSort); got != int64(7) {
		t.Fatalf("expected int64(7), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(json.Number("9.4"), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "long"}}, scSort); got != int64(9) {
		t.Fatalf("expected int64(9), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(uint64(42), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "double"}}, scSort); got != float64(42) {
		t.Fatalf("expected float64(42), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int64(43), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "double"}}, scSort); got != float64(43) {
		t.Fatalf("expected float64(43), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int64(math.MaxInt64), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "double"}}, scSort); got != int64(math.MaxInt64) {
		t.Fatalf("expected sentinel MaxInt64 preserved, got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int(44), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "num", NumericType: "double"}}, scSort); got != float64(44) {
		t.Fatalf("expected float64(44), got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int64(1704164645000000000), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "ts_ns", NumericType: "date"}}, scSort); got != int64(1704164645000) {
		t.Fatalf("expected ms conversion, got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int64(1704164645000), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "ts", NumericType: "date_nanos"}}, scSort); got != int64(1704164645000000000) {
		t.Fatalf("expected ns conversion, got %#v", got)
	}
	if got := formatSortValueWithEntryFormatR63(int64(1704164645000), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "ts", Format: "strict_date_optional_time"}}, scSort); got == nil {
		t.Fatalf("expected formatted date string")
	}

	// 7. emitRawBodyDeprecationWarningsR63: geo_bounding_box type on compatible-with=7 against 8.15.5 + ES7 common/cutoff_frequency/interval
	srvDep8, hDep8 := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, hDep8, http.MethodPut, "/r65_dep_idx", `{"mappings":{"properties":{"loc":{"type":"geo_point"},"title":{"type":"text"},"ts":{"type":"date"}}}}`, http.StatusOK)
	compat7Hdr := map[string]string{
		"Accept":       "application/vnd.elasticsearch+json; compatible-with=7",
		"Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
	}
	codeGB, hdrGB, _, rawGB := doRound61AdminReq(t, hDep8, http.MethodPost, "/r65_dep_idx/_search", `{
		"query":{"geo_bounding_box":{"type":"memory","loc":{"top_left":{"lat":1,"lon":-1},"bottom_right":{"lat":-1,"lon":1}}}}
	}`, compat7Hdr)
	if codeGB != http.StatusOK || !strings.Contains(strings.Join(hdrGB.Values("Warning"), " "), "Deprecated parameter [type] used") {
		t.Fatalf("expected geo_bounding_box type deprecation warning on compatible-with=7 against 8.15.5, got %d hdr=%v body=%s", codeGB, hdrGB, rawGB)
	}

	// ES 7.10.2 warnings for common, match.cutoff_frequency, multi_match.cutoff_frequency
	srvDep7, _ := newRound61AdminTestServer(t, "7.10.2")
	recDep := httptest.NewRecorder()
	reqDep := httptest.NewRequest(http.MethodPost, "/r65_dep_idx/_search", nil)
	emitRawBodyDeprecationWarningsR63(recDep, srvDep7, reqDep, []byte(`{
		"query":{"bool":{"must":[
			{"common":{"title":{"query":"hi"}}},
			{"match":{"title":{"query":"hi","cutoff_frequency":0.1}}},
			{"multi_match":{"query":"hi","fields":["title"],"cutoff_frequency":0.1}}
		]}},
		"aggs":{"dh":{"date_histogram":{"field":"ts","interval":"1d"}}}
	}`))
	if wJoined := strings.Join(recDep.Header().Values("Warning"), "\n"); !strings.Contains(wJoined, "[common]") || !strings.Contains(wJoined, "[match] query") || !strings.Contains(wJoined, "[multi_match]") || !strings.Contains(wJoined, "date_histogram") {
		t.Fatalf("expected common + match + multi_match + date_histogram warnings, got %q", wJoined)
	}
	_ = srvDep8
}

func TestRound65CovAdminESQL_SQLHelpersIngestDynamicTemplatesAndUpgrade(t *testing.T) {
	// 1. sqlbackend.go string scanning helpers
	lambdaSample := "'a->b', 'a''->b', 'a\\'->b', \"x->y\", \"x\\\"->y\", `k->v`, `k``->v`, (a -> b) -> c"
	if idx := findTopLevelLambdaArrowR64(lambdaSample); idx < 0 {
		t.Fatalf("expected top-level lambda arrow")
	} else if findTopLevelLambdaArrowR64("(a -> b)") != -1 {
		t.Fatalf("expected -1 when arrow is inside parens")
	}
	parenSample := "(a, 'b)', 'c'')', 'd\\')', \"e)\", \"f\\\")\", `g)`, `h``)`, (i))"
	if body, ok := extractBalancedParenBody(parenSample); !ok || !strings.HasPrefix(body, "a,") {
		t.Fatalf("expected balanced paren body, got (%q, %v)", body, ok)
	}
	if _, ok := extractBalancedParenBody("no_paren"); ok {
		t.Fatalf("expected false when not starting with '('")
	}
	if _, ok := extractBalancedParenBody("(unclosed"); ok {
		t.Fatalf("expected false for unclosed paren")
	}
	hitsSample := "SELECT 'FROM hits', 'a''FROM hits', 'b\\'FROM hits', \"FROM hits\", \"c\\\"FROM hits\", `FROM hits`, `d``FROM hits`"
	if containsHitsSelectOutsideLiterals(hitsSample, "FROM hits") {
		t.Fatalf("did not expect literal match in containsHitsSelectOutsideLiterals")
	}
	if !containsHitsSelectOutsideLiterals("SELECT 1 UNION SELECT `_id` FROM t", "SELECT `_id`") {
		t.Fatalf("expected match outside literals")
	}

	// 2. communityIDICMPEquiv (all ICMPv4 + ICMPv6 + unknown)
	for _, tc := range []struct {
		proto  uint8
		inType uint16
		want   uint16
		ok     bool
	}{
		{1, 8, 0, true}, {1, 0, 8, true}, {1, 13, 14, true}, {1, 14, 13, true},
		{1, 15, 16, true}, {1, 16, 15, true}, {1, 17, 18, true}, {1, 18, 17, true},
		{58, 128, 129, true}, {58, 129, 128, true}, {58, 130, 131, true}, {58, 131, 130, true},
		{58, 133, 134, true}, {58, 134, 133, true}, {58, 135, 136, true}, {58, 136, 135, true},
		{58, 139, 140, true}, {58, 140, 139, true}, {58, 144, 145, true}, {58, 145, 144, true},
		{58, 146, 147, true}, {58, 147, 146, true},
		{6, 8, 0, false}, {1, 99, 0, false}, {58, 99, 0, false},
	} {
		got, ok := communityIDICMPEquiv(tc.proto, tc.inType)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("communityIDICMPEquiv(%d, %d)=(%d,%v), want (%d,%v)", tc.proto, tc.inType, got, ok, tc.want, tc.ok)
		}
	}

	// 3. Ingest `_dynamic_templates` via set & script processors on single-doc and bulk writes
	_, h := newRound61AdminTestServer(t, "8.15.5")
	r65CovBMustHTTP(t, h, http.MethodPut, "/r65_dt_idx", `{
		"mappings": {
			"dynamic_templates": [
				{"kw_tpl": {"mapping": {"type": "keyword"}}},
				{"int_tpl": {"mapping": {"type": "integer"}}},
				{"long_tpl": {"mapping": {"type": "long"}}}
			]
		}
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_dt_set", `{
		"processors": [
			{"set": {"field": "_dynamic_templates.tag_set", "value": "kw_tpl"}}
		]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r65_dt_script", `{
		"processors": [
			{"script": {"source": "ctx._dynamic_templates.num_script = 'int_tpl'"}}
		]
	}`, http.StatusOK)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_dt_idx/_doc/1?pipeline=r65_dt_set&refresh=true", `{"tag_set":"42"}`, http.StatusCreated)
	r65CovBMustHTTP(t, h, http.MethodPost, "/r65_dt_idx/_doc/2?pipeline=r65_dt_script&refresh=true", `{"num_script":"7"}`, http.StatusCreated)

	bulkDT := strings.Join([]string{
		`{"index":{"_index":"r65_dt_idx","_id":"3","pipeline":"r65_dt_script","dynamic_templates":{"bulk_only":"long_tpl"}}}`,
		`{"num_script":"9","bulk_only":"100"}`,
	}, "\n") + "\n"
	bulkRes := r65CovBMustHTTP(t, h, http.MethodPost, "/_bulk?refresh=true", bulkDT, http.StatusOK)
	if bulkRes["errors"] != false {
		t.Fatalf("expected bulk dynamic_templates merge to succeed, got %v", bulkRes)
	}
	mapResp := r65CovBMustHTTP(t, h, http.MethodGet, "/r65_dt_idx/_mapping", "", http.StatusOK)
	props := mapResp["r65_dt_idx"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["tag_set"].(map[string]any)["type"] != "keyword" ||
		props["num_script"].(map[string]any)["type"] != "integer" ||
		props["bulk_only"].(map[string]any)["type"] != "long" {
		t.Fatalf("expected dynamic_templates types applied, got %v", props)
	}

	// 4. mergeExistingAggregateMetricDoubleRound63
	if _, ok := mergeExistingAggregateMetricDoubleRound63(nil, "m"); ok {
		t.Fatalf("expected false on empty docs")
	}
	if _, ok := mergeExistingAggregateMetricDoubleRound63([]downsampleDocSampleRound63{
		{id: "1", doc: map[string]any{"m": "not_map"}},
		{id: "2", doc: map[string]any{"m": map[string]any{"min": 1.0, "max": 2.0, "sum": 3.0, "value_count": 0}}},
	}, "m"); ok {
		t.Fatalf("expected false when all entries invalid or count=0")
	}
	mergedAgg, okAgg := mergeExistingAggregateMetricDoubleRound63([]downsampleDocSampleRound63{
		{id: "1", doc: map[string]any{"m": map[string]any{"min": 2.0, "max": 8.0, "sum": 10.0, "value_count": 2}}},
		{id: "2", doc: map[string]any{"m": map[string]any{"min": 1.0, "max": 10.0, "sum": 15.0, "value_count": 3}}},
	}, "m")
	if !okAgg || mergedAgg["min"] != 1.0 || mergedAgg["max"] != 10.0 || mergedAgg["sum"] != 25.0 || mergedAgg["value_count"] != int64(5) {
		t.Fatalf("unexpected merged aggregate_metric_double: %v (%v)", mergedAgg, okAgg)
	}

	// 5. POST/GET /_upgrade with compatible-with=7 on 8.15.5 vs ES 7.10.2
	compat7Hdr := map[string]string{
		"Accept":       "application/vnd.elasticsearch+json; compatible-with=7",
		"Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
	}
	cUpgPost8, hdrUpgPost8, _, rawUpgPost8 := doRound61AdminReq(t, h, http.MethodPost, "/r65_dt_idx/_upgrade", "", compat7Hdr)
	if cUpgPost8 != http.StatusBadRequest || len(hdrUpgPost8.Values("Warning")) == 0 {
		t.Fatalf("expected 400 + Warning on POST /_upgrade compat=7 against 8.15.5, got %d hdr=%v body=%s", cUpgPost8, hdrUpgPost8, rawUpgPost8)
	}
	cUpgGet8, hdrUpgGet8, _, rawUpgGet8 := doRound61AdminReq(t, h, http.MethodGet, "/_upgrade", "", compat7Hdr)
	if cUpgGet8 != http.StatusBadRequest || len(hdrUpgGet8.Values("Warning")) == 0 {
		t.Fatalf("expected 400 + Warning on GET /_upgrade compat=7 against 8.15.5, got %d hdr=%v body=%s", cUpgGet8, hdrUpgGet8, rawUpgGet8)
	}

	_, h7 := newRound61AdminTestServer(t, "7.10.2")
	r65CovBMustHTTP(t, h7, http.MethodPut, "/r65_upg7", `{}`, http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodPost, "/r65_upg7/_doc/1?refresh=true", `{"a":"b"}`, http.StatusCreated)
	r65CovBMustHTTP(t, h7, http.MethodPost, "/_upgrade", "", http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodPost, "/r65_upg7/_upgrade", "", http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodGet, "/_upgrade?human=true", "", http.StatusOK)
	r65CovBMustHTTP(t, h7, http.MethodGet, "/r65_upg7/_upgrade?human=true", "", http.StatusOK)
	cHeadUpg, _, _, _ := doRound61AdminReq(t, h7, http.MethodHead, "/r65_upg7/_upgrade", "", nil)
	if cHeadUpg != http.StatusOK {
		t.Fatalf("expected 200 on HEAD /r65_upg7/_upgrade, got %d", cHeadUpg)
	}
	cBadUpg, _, _, _ := doRound61AdminReq(t, h7, http.MethodDelete, "/_upgrade", "", nil)
	if cBadUpg != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE /_upgrade, got %d", cBadUpg)
	}
}
