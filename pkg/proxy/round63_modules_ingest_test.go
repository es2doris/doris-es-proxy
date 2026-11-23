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
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound63ModulesIngestTestServer(targetVer string) *Server {
	mb := NewMemoryBackend(false)
	srv := NewServer("default", mb, transpiler.TranspilerOptions{})
	if targetVer != "" {
		srv.SetTargetESVersion(targetVer)
	}
	return srv
}

func doRound63ModulesReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRound63_WP1_CatAllocationSnapshotStatusClusterInfoReindex(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// Create an index with 1 replica so cat.allocation emits both node and UNASSIGNED rows.
	recIdx := doRound63ModulesReq(t, h, http.MethodPut, "/r63_idx", `{"settings":{"number_of_shards":1,"number_of_replicas":1}}`)
	if recIdx.Code != http.StatusOK {
		t.Fatalf("create index status = %d, body = %s", recIdx.Code, recIdx.Body.String())
	}

	// 1. cat.allocation JSON vs text
	recAllocJSON := doRound63ModulesReq(t, h, http.MethodGet, "/_cat/allocation?format=json", "")
	if recAllocJSON.Code != http.StatusOK {
		t.Fatalf("cat.allocation json status = %d, body = %s", recAllocJSON.Code, recAllocJSON.Body.String())
	}
	var allocRows []map[string]any
	if err := json.Unmarshal(recAllocJSON.Body.Bytes(), &allocRows); err != nil {
		t.Fatalf("unmarshal cat.allocation json: %v", err)
	}
	if len(allocRows) < 2 {
		t.Fatalf("expected >= 2 allocation rows, got %d", len(allocRows))
	}
	for _, row := range allocRows {
		if row["node"] == "UNASSIGNED" {
			if row["write_load.forecast"] != nil {
				t.Fatalf("expected nil write_load.forecast on UNASSIGNED row, got %T (%v)", row["write_load.forecast"], row["write_load.forecast"])
			}
		} else {
			if _, ok := row["write_load.forecast"].(float64); !ok {
				t.Fatalf("expected float64 write_load.forecast on node row, got %T (%v)", row["write_load.forecast"], row["write_load.forecast"])
			}
		}
	}

	recAllocTxt := doRound63ModulesReq(t, h, http.MethodGet, "/_cat/allocation?v=true", "")
	if recAllocTxt.Code != http.StatusOK || !strings.Contains(recAllocTxt.Body.String(), "write_load.forecast") {
		t.Fatalf("cat.allocation text unexpected: %d %s", recAllocTxt.Code, recAllocTxt.Body.String())
	}
	if isCatStructuredOutputRound63(nil) {
		t.Fatalf("expected false for nil request")
	}
	reqAcceptYAML := httptest.NewRequest(http.MethodGet, "/_cat/allocation", nil)
	reqAcceptYAML.Header.Set("Accept", "application/yaml")
	if !isCatStructuredOutputRound63(reqAcceptYAML) {
		t.Fatalf("expected true for application/yaml Accept")
	}
	reqAcceptPlain := httptest.NewRequest(http.MethodGet, "/_cat/allocation", nil)
	reqAcceptPlain.Header.Set("Accept", "text/plain")
	if isCatStructuredOutputRound63(reqAcceptPlain) {
		t.Fatalf("expected false for text/plain Accept")
	}

	// 2. snapshot.status + cat.snapshots repository column
	recRepo := doRound63ModulesReq(t, h, http.MethodPut, "/_snapshot/r63_repo", `{"type":"fs","settings":{"location":"/tmp/r63_repo"}}`)
	if recRepo.Code != http.StatusOK {
		t.Fatalf("create repo status = %d", recRepo.Code)
	}

	recSnap := doRound63ModulesReq(t, h, http.MethodPut, "/_snapshot/r63_repo/snap_one?wait_for_completion=true", `{"indices":"r63_idx","include_global_state":false}`)
	if recSnap.Code != http.StatusOK {
		t.Fatalf("create snap status = %d, body = %s", recSnap.Code, recSnap.Body.String())
	}

	recCatSnaps := doRound63ModulesReq(t, h, http.MethodGet, "/_cat/snapshots/r63_repo?format=json", "")
	if recCatSnaps.Code != http.StatusOK || !strings.Contains(recCatSnaps.Body.String(), `"repository":"r63_repo"`) {
		t.Fatalf("cat.snapshots missing repository: %d %s", recCatSnaps.Code, recCatSnaps.Body.String())
	}

	for _, statusPath := range []string{"/_snapshot/_status", "/_snapshot/r63_repo/_status", "/_snapshot/r63_repo/snap_one/_status"} {
		recSt := doRound63ModulesReq(t, h, http.MethodGet, statusPath, "")
		if recSt.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, body = %s", statusPath, recSt.Code, recSt.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(recSt.Body.Bytes(), &payload); err != nil {
			t.Fatalf("unmarshal %s: %v", statusPath, err)
		}
		snaps, ok := payload["snapshots"].([]any)
		if !ok {
			t.Fatalf("%s missing snapshots array: %v", statusPath, payload)
		}
		if statusPath != "/_snapshot/_status" {
			if len(snaps) != 1 {
				t.Fatalf("%s expected 1 snapshot, got %d", statusPath, len(snaps))
			}
			entry, _ := snaps[0].(map[string]any)
			if igs, okB := entry["include_global_state"].(bool); !okB || igs {
				t.Fatalf("%s expected include_global_state=false, got %v", statusPath, entry["include_global_state"])
			}
			indicesMap, okI := entry["indices"].(map[string]any)
			if !okI || indicesMap["r63_idx"] == nil {
				t.Fatalf("%s expected indices.r63_idx, got %v", statusPath, entry["indices"])
			}
		}
		recHead := doRound63ModulesReq(t, h, http.MethodHead, statusPath, "")
		if recHead.Code != http.StatusOK {
			t.Fatalf("HEAD %s status = %d", statusPath, recHead.Code)
		}
	}

	// Exercise buildSnapshotStatusEntryRound63 with []string indices and nil rawSnap
	stNil := buildSnapshotStatusEntryRound63("s0", "repo0", nil)
	if stNil["include_global_state"] != true {
		t.Fatalf("expected default include_global_state=true")
	}
	stStrSlice := buildSnapshotStatusEntryRound63("s1", "repo0", map[string]any{
		"uuid":                 "u-123",
		"state":                "STARTED",
		"include_global_state": false,
		"indices":              []string{"idx_b", "idx_a"},
	})
	if stStrSlice["uuid"] != "u-123" || stStrSlice["state"] != "STARTED" {
		t.Fatalf("unexpected snapshot status entry: %v", stStrSlice)
	}
	if len(collectActiveSnapshotStatusesRound63(nil)) != 0 {
		t.Fatalf("expected empty active statuses for nil server")
	}

	srv.mu.Lock()
	srv.snapshots["r63_repo"]["snap_active"] = map[string]any{
		"state":                "IN_PROGRESS",
		"indices":              []any{"r63_idx"},
		"include_global_state": true,
	}
	srv.mu.Unlock()
	if got := collectActiveSnapshotStatusesRound63(srv); len(got) != 1 {
		t.Fatalf("expected 1 active snapshot, got %d", len(got))
	}

	// 3. /_cluster/info dynamic publish_address & max_content_length_in_bytes
	if resolveClusterMaxContentLengthRound63(nil) != DefaultMaxRequestBodyBytes {
		t.Fatalf("nil server max content length mismatch")
	}
	srv.SetMaxRequestBodyBytes(42 * 1024 * 1024)
	reqInfo := httptest.NewRequest(http.MethodGet, "/_cluster/info/http", nil)
	reqInfo.Host = "127.0.0.1:54321"
	recInfo := httptest.NewRecorder()
	h.ServeHTTP(recInfo, reqInfo)
	if recInfo.Code != http.StatusOK {
		t.Fatalf("/_cluster/info/http status = %d", recInfo.Code)
	}
	var infoMap map[string]any
	if err := json.Unmarshal(recInfo.Body.Bytes(), &infoMap); err != nil {
		t.Fatalf("unmarshal cluster info: %v", err)
	}
	httpObj, _ := infoMap["http"].(map[string]any)
	if httpObj == nil {
		if innerInfo, okI := infoMap["info"].(map[string]any); okI {
			httpObj, _ = innerInfo["http"].(map[string]any)
		}
	}
	if httpObj["publish_address"] != "127.0.0.1:54321" {
		t.Fatalf("publish_address = %v, want 127.0.0.1:54321", httpObj["publish_address"])
	}
	if resolveClusterHTTPPublishAddressRound63(nil) != "127.0.0.1:9200" {
		t.Fatalf("nil request fallback mismatch")
	}
	reqEmptyHost := httptest.NewRequest(http.MethodGet, "/_cluster/info", nil)
	reqEmptyHost.Host = ""
	if got := resolveClusterHTTPPublishAddressRound63(reqEmptyHost); got != "127.0.0.1:9200" {
		t.Fatalf("empty host fallback got %s", got)
	}
	reqFwd := httptest.NewRequest(http.MethodGet, "/_cluster/info", nil)
	reqFwd.Host = "es.internal"
	reqFwd.Header.Set("X-Forwarded-Host", "proxy1.example.com, proxy2.example.com")
	reqFwd.Header.Set("X-Forwarded-Port", "8443, 443")
	if got := resolveClusterHTTPPublishAddressRound63(reqFwd); got != "proxy1.example.com:8443" {
		t.Fatalf("X-Forwarded-Host/Port got %s", got)
	}
	reqTLS := httptest.NewRequest(http.MethodGet, "/_cluster/info", nil)
	reqTLS.Host = "secure.example.com"
	reqTLS.TLS = &tls.ConnectionState{}
	if got := resolveClusterHTTPPublishAddressRound63(reqTLS); got != "secure.example.com:443" {
		t.Fatalf("TLS portless host got %s", got)
	}
	reqHTTP := httptest.NewRequest(http.MethodGet, "/_cluster/info", nil)
	reqHTTP.Host = "plain.example.com"
	if got := resolveClusterHTTPPublishAddressRound63(reqHTTP); got != "plain.example.com:80" {
		t.Fatalf("HTTP portless host got %s", got)
	}

	// 4. orderReindexRemoteUnknownKeysRound63 + UTF-16 surrogate hash path
	_ = javaStringHashCodeRound63("emoji🚀key")
	_ = javaHashMapBucketRound63("emoji🚀key", 40)
	if single := orderReindexRemoteUnknownKeysRound63([]string{"only"}, []string{"only"}, 1); len(single) != 1 {
		t.Fatalf("single key mismatch: %v", single)
	}
	gotSorted := orderReindexRemoteUnknownKeysRound63([]string{"badkey", "host", "weird"}, []string{"badkey", "weird"}, 3)
	if len(gotSorted) != 2 || gotSorted[0] != "weird" || gotSorted[1] != "badkey" {
		t.Fatalf("expected [weird badkey], got %v", gotSorted)
	}
	gotExplicit := orderReindexRemoteUnknownKeysRound63([]string{"host", "foo", "bar"}, []string{"foo", "bar"}, 3)
	if len(gotExplicit) != 2 || gotExplicit[0] != "foo" || gotExplicit[1] != "bar" {
		t.Fatalf("expected explicit [foo bar], got %v", gotExplicit)
	}
}

func TestRound63_WP2_MVT_SQL_EQL_Downsample_ESQL_SLM_ILM(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// --- 1. Vector Tile (`/_mvt`) ---
	recGeo := doRound63ModulesReq(t, h, http.MethodPut, "/geo_idx", `{
		"mappings": {
			"properties": {
				"loc": {"type": "geo_point"},
				"shape": {"type": "geo_shape"},
				"title": {"type": "keyword"},
				"weight": {"type": "long"},
				"delta": {"type": "long"},
				"ratio": {"type": "double"},
				"active": {"type": "boolean"}
			}
		}
	}`)
	if recGeo.Code != http.StatusOK {
		t.Fatalf("create geo_idx: %d %s", recGeo.Code, recGeo.Body.String())
	}
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/geo_idx/_doc/1?refresh=true",
		`{"loc":{"lat":51.5,"lon":-0.1},"shape":"POLYGON((-1 -1, 1 -1, 1 1, -1 1, -1 -1))","title":"london","weight":10,"delta":-5,"ratio":1.25,"active":true}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/geo_idx/_doc/2?refresh=true",
		`{"loc":["POINT (2.35 48.85)","POINT (13.40 52.52)"],"title":"cities","weight":20,"delta":-2,"ratio":2.5,"active":false}`)

	recMVTHead := doRound63ModulesReq(t, h, http.MethodHead, "/geo_idx/_mvt/loc/0/0/0", "")
	if recMVTHead.Code != http.StatusOK || recMVTHead.Header().Get("Content-Type") != "application/vnd.mapbox-vector-tile" {
		t.Fatalf("HEAD _mvt got %d ct=%s", recMVTHead.Code, recMVTHead.Header().Get("Content-Type"))
	}
	for _, gt := range []string{"grid", "point", "centroid"} {
		recMVT := doRound63ModulesReq(t, h, http.MethodPost, "/geo_idx/_mvt/loc/0/0/0?extent=4096&buffer=8&size=10", `{
			"grid_precision": 2,
			"grid_type": "`+gt+`",
			"fields": ["title", {"field": "weight"}, "delta", "ratio", "active"],
			"query": {"match_all": {}}
		}`)
		if recMVT.Code != http.StatusOK || recMVT.Body.Len() < 16 {
			t.Fatalf("_mvt (%s) got %d len=%d", gt, recMVT.Code, recMVT.Body.Len())
		}
	}
	recMVTShape := doRound63ModulesReq(t, h, http.MethodGet, "/geo_idx/_mvt/shape/0/0/0?grid_precision=1&grid_type=point&fields=title", "")
	if recMVTShape.Code != http.StatusOK || recMVTShape.Body.Len() == 0 {
		t.Fatalf("_mvt shape got %d", recMVTShape.Code)
	}
	// Error cases for _mvt
	if c := doRound63ModulesReq(t, h, http.MethodDelete, "/geo_idx/_mvt/loc/0/0/0", "").Code; c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodGet, "/geo_idx/_mvt/loc/31/0/0", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid zoom, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodGet, "/geo_idx/_mvt/loc/1/5/0", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 out-of-range x, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodGet, "/geo_idx/_mvt/loc/0/0/0?grid_precision=9", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 grid_precision=9, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodGet, "/geo_idx/_mvt/loc/0/0/0?grid_type=hex", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 grid_type=hex, got %d", c)
	}
	if _, _, ok := projectLonLatToTilePixelRound63(999, 0, 1, 0, 0, 4096); ok {
		t.Fatalf("expected invalid lon to fail projection")
	}

	// --- 2. SQL (`/_sql` & `/_sql/translate`) ---
	for _, fmtName := range []string{"json", "txt", "csv", "tsv"} {
		recSQL := doRound63ModulesReq(t, h, http.MethodPost, "/_sql?format="+fmtName, `{"query":"SELECT title, weight FROM geo_idx ORDER BY weight DESC"}`)
		if recSQL.Code != http.StatusOK || recSQL.Body.Len() == 0 {
			t.Fatalf("/_sql?format=%s got %d %s", fmtName, recSQL.Code, recSQL.Body.String())
		}
	}
	recSQLTrans := doRound63ModulesReq(t, h, http.MethodPost, "/_sql/translate", `{"query":"SELECT title FROM geo_idx WHERE weight > 5 LIMIT 5"}`)
	if recSQLTrans.Code != http.StatusOK {
		t.Fatalf("/_sql/translate got %d %s", recSQLTrans.Code, recSQLTrans.Body.String())
	}
	tblTxt := formatSQLTextTableRound63(
		[]any{map[string]any{"name": "col_a"}, map[string]any{"name": "col_b"}},
		[]any{[]any{"hello", nil}, []any{"very_long_cell_value_exceeding_15_chars", 42}},
	)
	if !strings.Contains(tblTxt, "----+----") || !strings.Contains(tblTxt, "null") {
		t.Fatalf("unexpected formatSQLTextTableRound63: %s", tblTxt)
	}
	if mapped := resolveSQLTableMappedFieldsRound63(srv, context.Background(), "geo_idx"); mapped["title"] != "keyword" {
		t.Fatalf("expected title=keyword, got %v", mapped)
	}

	// --- 3. EQL (`/_eql/search`, sequence, sample, runtime_mappings, async status/delete) ---
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/eql_idx", `{
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"event": {"properties": {"category": {"type": "keyword"}}},
				"user": {"type": "keyword"},
				"raw_ip": {"type": "keyword"},
				"valid": {"type": "boolean"}
			}
		}
	}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/eql_idx/_doc/1?refresh=true", `{"@timestamp":"2023-01-01T00:00:01.000Z","event":{"category":"process"},"user":"SYSTEM","raw_ip":"10.0.0.1","valid":false}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/eql_idx/_doc/2?refresh=true", `{"@timestamp":"2023-01-01T00:00:02.000Z","event":[{"category":"process"}],"user":"SYSTEM","raw_ip":"10.0.0.2","valid":true}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/eql_idx/_doc/3?refresh=true", `{"@timestamp":"2023-01-01T00:00:03.000Z","event":{"category":"process"},"user":["OTHER","SYSTEM"],"raw_ip":"10.0.0.3","valid":false}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/eql_idx/_doc/4?refresh=true", `{"@timestamp":"2023-01-01T00:00:04.000Z","event":{"category":"process"},"user":"SYSTEM","raw_ip":"10.0.0.4","valid":true}`)

	// Single-event EQL with runtime_mappings + fields format
	recEQLEvt := doRound63ModulesReq(t, h, http.MethodPost, "/eql_idx/_eql/search", `{
		"runtime_mappings": {
			"addr": {"type": "ip", "script": "emit(doc['raw_ip'].value)"}
		},
		"fields": [{"field": "@timestamp", "format": "epoch_millis"}, "addr"],
		"query": "process where cidrMatch(addr, \"10.0.0.0/8\")"
	}`)
	if recEQLEvt.Code != http.StatusOK || !strings.Contains(recEQLEvt.Body.String(), `"1672531201000"`) || !strings.Contains(recEQLEvt.Body.String(), `"addr"`) {
		t.Fatalf("EQL runtime_mappings/fields failed: %d %s", recEQLEvt.Code, recEQLEvt.Body.String())
	}

	// Sequence matching 2 disjoint sequences + async status/get/delete
	recEQLSeq := doRound63ModulesReq(t, h, http.MethodPost, "/eql_idx/_eql/search?keep_on_completion=true", `{
		"query": "sequence by user with maxspan=1h [process where valid == false] ![network] [process where valid == true]"
	}`)
	if recEQLSeq.Code != http.StatusOK {
		t.Fatalf("EQL sequence failed: %d %s", recEQLSeq.Code, recEQLSeq.Body.String())
	}
	var eqlSeqMap map[string]any
	_ = json.Unmarshal(recEQLSeq.Body.Bytes(), &eqlSeqMap)
	eqlID, _ := eqlSeqMap["id"].(string)
	hitsMap, _ := eqlSeqMap["hits"].(map[string]any)
	totMap, _ := hitsMap["total"].(map[string]any)
	if totMap["value"] != float64(2) {
		t.Fatalf("expected 2 EQL sequences, got %v (%s)", totMap["value"], recEQLSeq.Body.String())
	}
	if eqlID != "" {
		if c := doRound63ModulesReq(t, h, http.MethodGet, "/_eql/search/status/"+eqlID, "").Code; c != http.StatusOK {
			t.Fatalf("EQL status got %d", c)
		}
		if c := doRound63ModulesReq(t, h, http.MethodGet, "/_eql/search/"+eqlID, "").Code; c != http.StatusOK {
			t.Fatalf("EQL get got %d", c)
		}
		if c := doRound63ModulesReq(t, h, http.MethodDelete, "/_eql/search/"+eqlID, "").Code; c != http.StatusOK {
			t.Fatalf("EQL delete got %d", c)
		}
	}

	// EQL sample with per-stage `by` after `]`
	recEQLSample := doRound63ModulesReq(t, h, http.MethodPost, "/eql_idx/_eql/search", `{
		"query": "sample [process where valid == false] by user [process where valid == true] by user"
	}`)
	if recEQLSample.Code != http.StatusOK {
		t.Fatalf("EQL sample failed: %d %s", recEQLSample.Code, recEQLSample.Body.String())
	}

	// EQL did-you-mean column & invalid runtime_mappings
	recEQLTypo := doRound63ModulesReq(t, h, http.MethodPost, "/eql_idx/_eql/search", `{"query":"process where used == \"SYSTEM\""}`)
	if recEQLTypo.Code != http.StatusBadRequest || !strings.Contains(recEQLTypo.Body.String(), "did you mean [user]?") {
		t.Fatalf("expected did you mean [user]?, got %d %s", recEQLTypo.Code, recEQLTypo.Body.String())
	}
	recEQLBadRM := doRound63ModulesReq(t, h, http.MethodPost, "/eql_idx/_eql/search", `{"runtime_mappings":{"x":{"type":"invalid_type"}},"query":"process where true"}`)
	if recEQLBadRM.Code != http.StatusBadRequest || !strings.Contains(recEQLBadRM.Body.String(), "action_request_validation_exception") {
		t.Fatalf("expected 400 action_request_validation_exception, got %d %s", recEQLBadRM.Code, recEQLBadRM.Body.String())
	}

	// --- 4. Downsample (`/_downsample`) ---
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/ts_src", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"tag": {"type": "keyword", "ignore_above": 5},
				"cpu": {"type": "double", "time_series_metric": "gauge"},
				"reqs": {"type": "long", "time_series_metric": "counter"}
			}
		}
	}`)
	if r1 := doRound63ModulesReq(t, h, http.MethodPost, "/ts_src/_doc?refresh=true", `{"@timestamp":"2023-05-01T10:10:00Z","host":"h1","tag":"ok","cpu":0.2,"reqs":100}`); r1.Code != http.StatusCreated {
		t.Fatalf("post ts_src doc 1: %d %s", r1.Code, r1.Body.String())
	}
	if r2 := doRound63ModulesReq(t, h, http.MethodPost, "/ts_src/_doc?refresh=true", `{"@timestamp":"2023-05-01T10:40:00Z","host":"h1","tag":"too_long_ignored","cpu":0.8,"reqs":150}`); r2.Code != http.StatusCreated {
		t.Fatalf("post ts_src doc 2: %d %s", r2.Code, r2.Body.String())
	}

	recDS1 := doRound63ModulesReq(t, h, http.MethodPost, "/ts_src/_downsample/ts_1h", `{"fixed_interval":"1h"}`)
	if recDS1.Code != http.StatusOK {
		t.Fatalf("downsample 1h failed: %d %s", recDS1.Code, recDS1.Body.String())
	}
	recDS2 := doRound63ModulesReq(t, h, http.MethodPost, "/ts_1h/_downsample/ts_2h", `{"fixed_interval":"2h"}`)
	if recDS2.Code != http.StatusOK {
		t.Fatalf("downsample 2h failed: %d %s", recDS2.Code, recDS2.Body.String())
	}
	recDSSearch := doRound63ModulesReq(t, h, http.MethodGet, "/ts_2h/_search", "")
	if !strings.Contains(recDSSearch.Body.String(), `"_doc_count":2`) {
		t.Fatalf("expected _doc_count:2 in ts_2h, got %s", recDSSearch.Body.String())
	}
	// Non-multiple interval should fail 400
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/ts_1h/_downsample/ts_90m", `{"fixed_interval":"90m"}`).Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 non-multiple interval, got %d", c)
	}

	// --- 5. ES|QL (`/_query`) ---
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/esql_t", `{
		"mappings": {
			"properties": {
				"k": {"type": "keyword", "fields": {"short": {"type": "keyword", "ignore_above": 4}, "norm": {"type": "keyword", "normalizer": "lowercase"}}},
				"v": {"type": "keyword"},
				"u": {"type": "unsigned_long"},
				"ip_col": {"type": "ip"},
				"poly": {"type": "geo_shape"}
			}
		}
	}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/esql_t/_doc/1?refresh=true", `{"k":"AlphaLong","v":"10","u":42,"ip_col":"10.0.0.1","poly":"POLYGON((-1 -1, 1 -1, 1 1, -1 1, -1 -1))"}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/esql_t/_doc/2?refresh=true", `{"k":"Beta","v":"20","u":84,"ip_col":"10.0.0.2","poly":"POINT(2 3)"}`)

	recESQL := doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{
		"profile": true,
		"tables": {
			"lkp": {
				"k": {"keyword": ["AlphaLong", "Beta"]},
				"label": {"keyword": ["first", "second"]}
			}
		},
		"query": "FROM esql_t | LOOKUP lkp ON k | EVAL num = v::long + 5 | STATS mx = MAX(v::long) BY label | SORT mx DESC"
	}`)
	if recESQL.Code != http.StatusOK || !strings.Contains(recESQL.Body.String(), `"took_nanos"`) || !strings.Contains(recESQL.Body.String(), `"second"`) {
		t.Fatalf("ES|QL LOOKUP/profile/::long failed: %d %s", recESQL.Code, recESQL.Body.String())
	}

	recESQLSpatial := doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM esql_t | KEEP k, k.short, k.norm, poly | SORT k ASC"}`)
	if recESQLSpatial.Code != http.StatusOK || !strings.Contains(recESQLSpatial.Body.String(), `"POLYGON ((-1.0 -1.0, 1.0 -1.0, 1.0 1.0, -1.0 1.0, -1.0 -1.0))"`) {
		t.Fatalf("ES|QL spatial/subfields failed: %d %s", recESQLSpatial.Code, recESQLSpatial.Body.String())
	}

	if !ValidateESQLIPStringRound63("192.168.1.1") || !ValidateESQLIPStringRound63("10.0.0.0/8") || ValidateESQLIPStringRound63("not_an_ip") {
		t.Fatalf("ValidateESQLIPStringRound63 unexpected result")
	}

	recESQLMeta := doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM esql_t METADATA _id | LIMIT 1"}`)
	if recESQLMeta.Code != http.StatusOK || !strings.Contains(recESQLMeta.Body.String(), `"_id"`) {
		t.Fatalf("ES|QL METADATA failed: %d %s", recESQLMeta.Code, recESQLMeta.Body.String())
	}

	// --- 6. SLM, ILM & XPack Usage ---
	recUsage := doRound63ModulesReq(t, h, http.MethodGet, "/_xpack/usage", "")
	if recUsage.Code != http.StatusOK || !strings.Contains(recUsage.Body.String(), `"meta":1`) {
		t.Fatalf("expected esql.features.meta in _xpack/usage: %d %s", recUsage.Code, recUsage.Body.String())
	}

	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_snapshot/slm_repo", `{"type":"fs","settings":{"location":"/tmp/slm_repo"}}`)
	if c := doRound63ModulesReq(t, h, http.MethodPut, "/_slm/policy/too-fast", `{"schedule":"0 * * * * ?","name":"<fast>","repository":"slm_repo"}`).Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 for <15m SLM schedule, got %d", c)
	}
	recSLMPut := doRound63ModulesReq(t, h, http.MethodPut, "/_slm/policy/daily-snapshots", `{"schedule":"0 30 1 * * ?","name":"<daily>","repository":"slm_repo"}`)
	if recSLMPut.Code != http.StatusOK {
		t.Fatalf("PUT SLM policy got %d %s", recSLMPut.Code, recSLMPut.Body.String())
	}
	recSLMGet := doRound63ModulesReq(t, h, http.MethodGet, "/_slm/policy/daily-snapshots", "")
	if recSLMGet.Code != http.StatusOK || !strings.Contains(recSLMGet.Body.String(), `"next_execution_millis"`) || !strings.Contains(recSLMGet.Body.String(), `"snapshots_taken"`) {
		t.Fatalf("GET SLM policy missing fields: %d %s", recSLMGet.Code, recSLMGet.Body.String())
	}

	// ILM move_to_step (`/_ilm/move/{index}`) / retry (`/{index}/_ilm/retry`) / remove_policy (`/{index}/_ilm/remove`)
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/_ilm/move/missing_idx", `{"next_step":{"phase":"warm"}}`).Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing index in _ilm/move, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/missing_idx/_ilm/retry", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing index in _ilm/retry, got %d", c)
	}
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_ilm/policy/r63_pol", `{"policy":{"phases":{"hot":{"actions":{}},"warm":{"min_age":"1d","actions":{}}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/ilm_managed_idx", `{"settings":{"index":{"lifecycle":{"name":"r63_pol"}}}}`)
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/_ilm/move/ilm_managed_idx", `{"current_step":{"phase":"warm","action":"forcemerge","name":"forcemerge"},"next_step":{"phase":"warm"}}`).Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 step mismatch, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/_ilm/move/ilm_managed_idx", `{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"warm","action":"complete","name":"complete"}}`).Code; c != http.StatusOK {
		t.Fatalf("expected 200 valid _ilm/move, got %d", c)
	}
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/ilm_managed_idx/_ilm/remove", "").Code; c != http.StatusOK {
		t.Fatalf("expected 200 _ilm/remove, got %d", c)
	}

	healthMock := map[string]any{
		"indicators": map[string]any{
			"slm": map[string]any{},
			"ilm": map[string]any{},
		},
	}
	patchHealthReportIndicatorsRound63(srv, healthMock)
	sortedRules := sortSynonymRulesByIDRound63([]map[string]any{{"id": "b"}, {"id": "a"}})
	if sortedRules[0]["id"] != "a" {
		t.Fatalf("expected sorted synonym rules, got %v", sortedRules)
	}
	srv.mu.RLock()
	reloadDet := map[string]any{"reload_details": []any{map[string]any{"index": "geo_idx"}}}
	srv.adjustSynonymReloadShardsLockedRound63("syn1", reloadDet)
	srv.mu.RUnlock()
	if reloadDet["_shards"] == nil {
		t.Fatalf("expected _shards on reloadDetails")
	}

	asyncMock := map[string]any{
		"response": map[string]any{
			"aggregations": map[string]any{
				"by_title": map[string]any{"buckets": []any{}},
				"max_w":    map[string]any{"value": 20.0},
			},
		},
	}
	applyTypedKeysToAsyncSearchResponseRound63(asyncMock, map[string]any{
		"by_title": map[string]any{"terms": map[string]any{"field": "title"}},
		"max_w":    map[string]any{"max": map[string]any{"field": "weight"}},
	})
	innerAggs := asyncMock["response"].(map[string]any)["aggregations"].(map[string]any)
	if innerAggs["sterms#by_title"] == nil || innerAggs["max#max_w"] == nil {
		t.Fatalf("expected typed_keys prefixes, got %v", innerAggs)
	}
}

func TestRound63_WP3_TermvectorsPayloads_MLT_Percolator_Mustache(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// 1. Termvectors with `type_as_payload`
	recTVIdx := doRound63ModulesReq(t, h, http.MethodPut, "/tv_idx", `{
		"settings": {
			"analysis": {
				"analyzer": {
					"payload_analyzer": {
						"tokenizer": "whitespace",
						"filter": ["type_as_payload"]
					}
				}
			}
		},
		"mappings": {
			"properties": {
				"text": {
					"type": "text",
					"term_vector": "with_positions_offsets_payloads",
					"analyzer": "payload_analyzer"
				}
			}
		}
	}`)
	if recTVIdx.Code != http.StatusOK {
		t.Fatalf("create tv_idx: %d %s", recTVIdx.Code, recTVIdx.Body.String())
	}
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/tv_idx/_doc/1?refresh=true", `{"text":"The brown fox brown"}`)

	recTV := doRound63ModulesReq(t, h, http.MethodGet, "/tv_idx/_termvectors/1?payloads=true", "")
	if recTV.Code != http.StatusOK || !strings.Contains(recTV.Body.String(), `"payload":"d29yZA=="`) {
		t.Fatalf("expected base64 payload d29yZA== in termvectors: %d %s", recTV.Code, recTV.Body.String())
	}

	// 2. MoreLikeThis (`like` docs, `unlike`, `include`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_idx", `{"mappings":{"properties":{"text":{"type":"text"}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_idx/_doc/1?refresh=true", `{"text":"quick brown fox"}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_idx/_doc/2?refresh=true", `{"text":"quick brown dog"}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_idx/_doc/3?refresh=true", `{"text":"fast brown cat"}`)

	recMLT := doRound63ModulesReq(t, h, http.MethodPost, "/mlt_idx/_search", `{
		"query": {
			"more_like_this": {
				"fields": ["text"],
				"like": [{"_index": "mlt_idx", "_id": "1"}],
				"unlike": [{"_index": "mlt_idx", "_id": "2"}],
				"min_term_freq": 1,
				"min_doc_freq": 1
			}
		}
	}`)
	if recMLT.Code != http.StatusOK {
		t.Fatalf("MLT search status = %d %s", recMLT.Code, recMLT.Body.String())
	}

	// 3. Percolator multi-index + named sub-queries + mustache error mapping
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/perc_q", `{"mappings":{"properties":{"query":{"type":"percolator"},"num_beds":{"type":"integer"},"fireplace":{"type":"boolean"}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/perc_docs", `{"mappings":{"properties":{"num_beds":{"type":"integer"}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/perc_q/_doc/q1?refresh=true", `{
		"query": {
			"bool": {
				"_name": "top_bool",
				"must": [
					{"range": {"num_beds": {"_name": "beds_3_plus", "gte": 3}}},
					{"term": {"fireplace": {"_name": "has_fp", "value": true}}}
				]
			}
		}
	}`)
	recPerc := doRound63ModulesReq(t, h, http.MethodPost, "/perc_q,perc_docs/_search", `{
		"query": {
			"percolate": {
				"field": "query",
				"documents": [
					{"num_beds": 4, "fireplace": true},
					{"num_beds": 1, "fireplace": false}
				]
			}
		}
	}`)
	if recPerc.Code != http.StatusOK || !strings.Contains(recPerc.Body.String(), `"q1"`) {
		t.Fatalf("multi-index percolate failed: %d %s", recPerc.Code, recPerc.Body.String())
	}

	srv.mu.RLock()
	percSch := srv.indices["perc_q"]
	srv.mu.RUnlock()
	storedDoc := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"_name": "top_bool",
				"filter": []any{
					map[string]any{"range": map[string]any{"num_beds": map[string]any{"_name": "beds_3_plus", "gte": 3}}},
				},
			},
		},
	}
	if !storedPercolatorQueryHasNamesRound63(storedDoc, "query") {
		t.Fatalf("expected storedPercolatorQueryHasNamesRound63=true")
	}
	slotMatched := collectPercolateSlotMatchedQueriesRound63(percSch, storedDoc, &esast.PercolateQuery{
		Field:     "query",
		Documents: []map[string]any{{"num_beds": 4}, {"num_beds": 1}},
	})
	if len(slotMatched[0]) != 2 {
		t.Fatalf("expected 2 matched query names on slot 0, got %v", slotMatched)
	}
	if mustacheErrTypeForServerRound63(srv, nil, "json_e_o_f_exception") != "x_content_e_o_f_exception" {
		t.Fatalf("expected ES8 x_content_e_o_f_exception")
	}
}

func buildMinimalTestDocxBase64(t *testing.T, bodyText string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	wDoc, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatalf("create word/document.xml: %v", err)
	}
	_, _ = wDoc.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>` + bodyText + `</w:t></w:r><w:tab/><w:br/></w:p></w:body></w:document>`))
	wCore, err := zw.Create("docProps/core.xml")
	if err != nil {
		t.Fatalf("create docProps/core.xml: %v", err)
	}
	_, _ = wCore.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">` +
		`<dc:title>Test Title</dc:title><dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy>` +
		`<cp:keywords>k1,k2</cp:keywords><dc:description>Desc</dc:description>` +
		`<dcterms:created>2023-05-01T12:00:00Z</dcterms:created><dcterms:modified>2023-05-02T12:00:00Z</dcterms:modified>` +
		`<dc:language>en-US</dc:language></cp:coreProperties>`))
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func buildMinimalTestOLE2DocBase64(bodyText string) string {
	// Construct a valid 4-sector (512-byte sectors) OLE2 CFBF `.doc` file:
	// Header (512B) + Sector 0 (FAT) + Sector 1 (Directory: Root + WordDocument + 1Table + \x05SummaryInformation)
	// + Sector 2 (WordDocument stream) + Sector 3 (1Table Clx stream) + Sector 4 (SummaryInformation stream)
	const secSize = 512
	raw := make([]byte, secSize*6)
	// Magic \xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
	copy(raw[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(raw[24:26], 0x003E) // minor version
	binary.LittleEndian.PutUint16(raw[26:28], 0x0003) // major version 3 (512B sectors)
	binary.LittleEndian.PutUint16(raw[28:30], 0xFFFE) // little-endian
	binary.LittleEndian.PutUint16(raw[30:32], 9)      // sector shift 2^9 = 512
	binary.LittleEndian.PutUint16(raw[32:34], 6)      // mini sector shift 2^6 = 64
	binary.LittleEndian.PutUint32(raw[44:48], 1)      // 1 FAT sector
	binary.LittleEndian.PutUint32(raw[48:52], 1)      // first directory sector = 1
	binary.LittleEndian.PutUint32(raw[56:60], 64)     // mini cutoff = 64 so 512B streams use regular FAT
	binary.LittleEndian.PutUint32(raw[60:64], 0xFFFFFFFE)
	binary.LittleEndian.PutUint32(raw[68:72], 0xFFFFFFFE)
	// DIFAT[0] = sector 0, rest = FREESECT
	binary.LittleEndian.PutUint32(raw[76:80], 0)
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(raw[76+i*4:80+i*4], 0xFFFFFFFF)
	}

	// Sector 0 (offset 512): FAT -> sec 0..4 = ENDOFCHAIN (0xFFFFFFFE)
	fatOff := secSize
	for s := 0; s < 128; s++ {
		val := uint32(0xFFFFFFFF)
		if s <= 4 {
			val = 0xFFFFFFFE
		}
		binary.LittleEndian.PutUint32(raw[fatOff+s*4:fatOff+(s+1)*4], val)
	}

	writeDirEntry := func(slot int, name string, objType byte, startSec, sz uint32) {
		off := secSize*2 + slot*128
		u16 := utf16.Encode([]rune(name))
		for i, ch := range u16 {
			binary.LittleEndian.PutUint16(raw[off+i*2:off+i*2+2], ch)
		}
		binary.LittleEndian.PutUint16(raw[off+64:off+66], uint16((len(u16)+1)*2))
		raw[off+66] = objType
		binary.LittleEndian.PutUint32(raw[off+116:off+120], startSec)
		binary.LittleEndian.PutUint32(raw[off+120:off+124], sz)
	}
	writeDirEntry(0, "Root Entry", 5, 0xFFFFFFFE, 0)
	writeDirEntry(1, "WordDocument", 2, 2, 512)
	writeDirEntry(2, "1Table", 2, 3, 128)
	writeDirEntry(3, "\x05SummaryInformation", 2, 4, 128)

	// Sector 2 (offset 512*3): WordDocument FIB + ANSI text at offset 0x1C0
	wd := raw[secSize*3 : secSize*4]
	binary.LittleEndian.PutUint16(wd[0x0A:0x0C], 0x0200) // use 1Table
	textOff := 0x1B0
	copy(wd[textOff:], []byte(bodyText))
	binary.LittleEndian.PutUint32(wd[0x18:0x1C], uint32(textOff))
	binary.LittleEndian.PutUint32(wd[0x1C:0x20], uint32(textOff+len(bodyText)))
	binary.LittleEndian.PutUint32(wd[0x4C:0x50], uint32(len(bodyText)))
	binary.LittleEndian.PutUint32(wd[0x01A2:0x01A6], 0)  // fcClx = 0
	binary.LittleEndian.PutUint32(wd[0x01A6:0x01AA], 21) // lcbClx = 1 + 4 + 16 = 21

	// Sector 3 (offset 512*4): 1Table Clx = [0x02][lcb=16][cp0=0][cp1=len][pcd: 2B][fcCompressed: 4B][prm: 2B]
	tbl := raw[secSize*4 : secSize*5]
	tbl[0] = 0x02
	binary.LittleEndian.PutUint32(tbl[1:5], 16)
	binary.LittleEndian.PutUint32(tbl[5:9], 0)
	binary.LittleEndian.PutUint32(tbl[9:13], uint32(len(bodyText)))
	fcComp := uint32(textOff*2) | 0x40000000 // ANSI flag
	binary.LittleEndian.PutUint32(tbl[15:19], fcComp)

	// Sector 4 (offset 512*5): \x05SummaryInformation with PIDSI_TITLE (2) & PIDSI_AUTHOR (4)
	sum := raw[secSize*5 : secSize*6]
	binary.LittleEndian.PutUint32(sum[24:28], 1)  // 1 property set
	binary.LittleEndian.PutUint32(sum[44:48], 48) // secOff = 48
	binary.LittleEndian.PutUint32(sum[48:52], 64) // section size
	binary.LittleEndian.PutUint32(sum[52:56], 2)  // 2 properties
	// Prop 0: PIDSI_TITLE = 2 at relOff 24
	binary.LittleEndian.PutUint32(sum[56:60], 2)
	binary.LittleEndian.PutUint32(sum[60:64], 24)
	// Prop 1: PIDSI_AUTHOR = 4 at relOff 44
	binary.LittleEndian.PutUint32(sum[64:68], 4)
	binary.LittleEndian.PutUint32(sum[68:72], 44)
	// Value at 48+24 = 72: VT_LPSTR (0x001E), len=9, "DocTitle\x00"
	binary.LittleEndian.PutUint16(sum[72:74], 0x001E)
	binary.LittleEndian.PutUint32(sum[76:80], 9)
	copy(sum[80:89], "DocTitle\x00")
	// Value at 48+44 = 92: VT_LPSTR (0x001E), len=6, "Carol\x00"
	binary.LittleEndian.PutUint16(sum[92:94], 0x001E)
	binary.LittleEndian.PutUint32(sum[96:100], 6)
	copy(sum[100:106], "Carol\x00")

	return base64.StdEncoding.EncodeToString(raw)
}

func TestRound63_WP4_IngestWeekDate_Attachment_UserAgent_GrokGuard_Reroute_UBQ(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// 1. Week-date parsing (`YYYY-ww`, `YYYY-'W'ww-e`, timezone offsets)
	wt1, okW1 := parseIngestWeekDateRound63("2020-33", []any{"YYYY-ww"}, "UTC")
	if !okW1 || wt1.Year() != 2020 {
		t.Fatalf("expected 2020-33 week-date parse, got ok=%v t=%v", okW1, wt1)
	}
	wt2, okW2 := parseIngestWeekDateRound63("2020-W02-3 14:30:00 +02:00", []any{"YYYY-'W'ww-e HH:mm:ss Z"}, "+02:00")
	if !okW2 || wt2.Year() != 2020 {
		t.Fatalf("expected YYYY-'W'ww-e parse, got ok=%v t=%v", okW2, wt2)
	}

	// 2. `.docx` OOXML ZIP & `.doc` OLE2 CFBF attachment extraction + end-to-end pipeline
	docxB64 := buildMinimalTestDocxBase64(t, "Lorem\nipsum dolor sit amet")
	docxOut, okDocx := ExtractIngestAttachmentRound63(docxB64, 100000, nil, true)
	if !okDocx || docxOut["language"] != "et" || docxOut["author"] != "Alice" || docxOut["modifier"] != "Bob" {
		t.Fatalf("unexpected docx attachment result: ok=%v %v", okDocx, docxOut)
	}
	docxFiltered, okFilt := ExtractIngestAttachmentRound63(docxB64, 5, []string{"content", "title"}, true)
	if !okFilt || docxFiltered["content"] != "Lorem" || docxFiltered["author"] != nil {
		t.Fatalf("unexpected filtered/truncated docx result: %v", docxFiltered)
	}

	docB64 := buildMinimalTestOLE2DocBase64("Lorem ipsum legacy word binary")
	docOut, okDoc := ExtractIngestAttachmentRound63(docB64, 100000, nil, true)
	if !okDoc || docOut["language"] != "et" || docOut["title"] != "DocTitle" || docOut["author"] != "Carol" {
		t.Fatalf("unexpected .doc attachment result: ok=%v %v", okDoc, docOut)
	}

	// End-to-end ingest pipeline with attachment (remove_binary), user_agent (regex_file), ES8 `field()` Write API, and external version
	recPipe := doRound63ModulesReq(t, h, http.MethodPut, "/_ingest/pipeline/r63_combo", `{
		"processors": [
			{"attachment": {"field": "raw_data", "target_field": "att", "remove_binary": true}},
			{"user_agent": {"field": "ua_raw", "target_field": "ua_custom", "regex_file": "custom_regexes.yml"}},
			{"user_agent": {"field": "ua_raw", "target_field": "ua_std"}},
			{"date": {"field": "week_str", "target_field": "week_ts", "formats": ["YYYY-ww"]}},
			{"script": {"source": "field('nested.flag').set(true); field('drop_me').remove();"}}
		]
	}`)
	if recPipe.Code != http.StatusOK {
		t.Fatalf("PUT r63_combo pipeline: %d %s", recPipe.Code, recPipe.Body.String())
	}

	recIngestDoc := doRound63ModulesReq(t, h, http.MethodPut, "/r63_ingest_idx/_doc/1?pipeline=r63_combo&version=9&version_type=external&refresh=true", `{
		"raw_data": "`+docxB64+`",
		"ua_raw": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.149 Safari/537.36",
		"week_str": "2020-33",
		"drop_me": "bye"
	}`)
	if recIngestDoc.Code != http.StatusCreated && recIngestDoc.Code != http.StatusOK {
		t.Fatalf("index with r63_combo failed: %d %s", recIngestDoc.Code, recIngestDoc.Body.String())
	}
	if !strings.Contains(recIngestDoc.Body.String(), `"_version":9`) {
		t.Fatalf("expected external _version:9 preserved, got %s", recIngestDoc.Body.String())
	}
	recGetDoc := doRound63ModulesReq(t, h, http.MethodGet, "/r63_ingest_idx/_doc/1", "")
	bodyStr := recGetDoc.Body.String()
	if strings.Contains(bodyStr, `"raw_data"`) || strings.Contains(bodyStr, `"drop_me"`) || !strings.Contains(bodyStr, `"flag":true`) || !strings.Contains(bodyStr, `"name":"Test"`) {
		t.Fatalf("unexpected ingested doc: %s", bodyStr)
	}

	// 3. Grok / Dissect 1 MiB guard (`F29`) + UBQ negative `_version` guard
	if m, err := ExtractGrokCheckedRound63("%{WORD:w}", "hello"); err != nil || m["w"] != "hello" {
		t.Fatalf("ExtractGrokCheckedRound63 valid failed: %v %v", m, err)
	}
	if m, err := ExtractDissectCheckedRound63("%{a}-%{b}", "foo-bar"); err != nil || m["a"] != "foo" {
		t.Fatalf("ExtractDissectCheckedRound63 valid failed: %v %v", m, err)
	}
	hugeInput := strings.Repeat("x", maxIngestGrokDissectBytesRound63+64)
	if _, err := ExtractGrokCheckedRound63("%{GREEDYDATA:x}", hugeInput); err == nil {
		t.Fatalf("expected >1MiB Grok input to return error")
	}
	if _, err := ExtractDissectCheckedRound63("%{x}", hugeInput); err == nil {
		t.Fatalf("expected >1MiB Dissect input to return error")
	}

	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_ingest/pipeline/grok_guard_pipe", `{"processors":[{"grok":{"field":"msg","patterns":["%{GREEDYDATA:x}"]}}]}`)
	hugeJSON, _ := json.Marshal(map[string]any{"msg": hugeInput})
	if _, _, hookErr := srv.collectPipelineHooksForWriteRound63("guard_idx", "grok_guard_pipe", "", hugeJSON); hookErr == nil {
		t.Fatalf("expected collectPipelineHooksForWriteRound63 >1MiB grok error")
	}

	if err := ValidateUBQScriptVersionRound63(-1, true, true); err == nil {
		t.Fatalf("expected negative _version in UBQ to fail")
	}
	if err := ValidateUBQScriptVersionRound63(0, false, true); err != nil {
		t.Fatalf("expected unmutated _version=0 in UBQ to succeed, got %v", err)
	}

	// 4. Reroute processor -> destination index template `default_pipeline` + data stream auto-creation
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_ingest/pipeline/dest_enrich", `{"processors":[{"set":{"field":"enriched_by_dest","value":true}}]}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_index_template/logs_tpl", `{
		"index_patterns": ["logs-r63-*"],
		"data_stream": {},
		"template": {
			"settings": {"index": {"default_pipeline": "dest_enrich"}}
		}
	}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_ingest/pipeline/intake_reroute", `{"processors":[{"reroute":{"destination":"logs-r63-app"}}]}`)
	recReroute := doRound63ModulesReq(t, h, http.MethodPost, "/intake/_doc?pipeline=intake_reroute&refresh=true", `{"@timestamp":"2023-06-01T00:00:00Z","msg":"routed"}`)
	if recReroute.Code != http.StatusCreated && recReroute.Code != http.StatusOK {
		t.Fatalf("reroute write failed: %d %s", recReroute.Code, recReroute.Body.String())
	}
	recSearchDS := doRound63ModulesReq(t, h, http.MethodGet, "/logs-r63-app/_search", "")
	if recSearchDS.Code != http.StatusOK || !strings.Contains(recSearchDS.Body.String(), `"enriched_by_dest":true`) {
		t.Fatalf("expected rerouted doc in logs-r63-app with enriched_by_dest=true, got %d %s", recSearchDS.Code, recSearchDS.Body.String())
	}
}

func TestRound63_WP5_HelperBranchCoverage(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// 1. ES|QL field types, cell coercions, static type inference & double-colon cast rewrites
	for _, ft := range []string{
		"integer", "short", "byte", "long", "unsigned_long", "double", "float",
		"boolean", "ip", "date", "version", "text", "keyword", "constant_keyword",
		"geo_point", "cartesian_point", "geo_shape", "cartesian_shape", "_source", "nested",
	} {
		_ = esFieldTypeToESQLTypeRound63(ft)
	}
	_ = coerceESQLCellForColumnTypeRound63(nil, "keyword")
	_ = coerceESQLCellForColumnTypeRound63("x", "unsupported")
	_ = coerceESQLCellForColumnTypeRound63([]any{}, "keyword")
	_ = coerceESQLCellForColumnTypeRound63([]any{"b", "a"}, "keyword")
	_ = coerceESQLCellForColumnTypeRound63([]any{"3.5"}, "double")
	_ = coerceESQLSingleScalarRound63(json.Number("18446744073709551615"), "unsigned_long")
	_ = coerceESQLSingleScalarRound63("42", "unsigned_long")
	_ = coerceESQLSingleScalarRound63(int64(7), "unsigned_long")
	_ = coerceESQLSingleScalarRound63(7, "unsigned_long")
	_ = coerceESQLSingleScalarRound63("true", "boolean")
	_ = coerceESQLSingleScalarRound63("false", "boolean")
	_ = coerceESQLSingleScalarRound63(true, "boolean")
	_ = coerceESQLSingleScalarRound63("123", "integer")
	_ = coerceESQLSingleScalarRound63(map[string]any{"x": 1.0, "y": 2.5}, "cartesian_point")
	_ = coerceESQLSingleScalarRound63([]any{1.25, 2.75}, "geo_point")
	_ = coerceESQLSingleScalarRound63("2023-05-01T00:00:00Z", "date")

	sum := esqlIndexFieldSummaryRound63{
		colTypes:    map[string]string{"k": "keyword", "u": "unsupported"},
		ignoreAbove: map[string]int{"k": 4},
		normalizers: map[string]string{"k": "my_normalizer"},
		noDocValues: map[string]bool{},
	}
	_ = formatESQLCellWithSchemaRound63(nil, "k", sum)
	_ = formatESQLCellWithSchemaRound63("x", "u", sum)
	_ = formatESQLCellWithSchemaRound63([]any{"Zebra", "Ab", "Cd"}, "k", sum)

	colTypes := map[string]string{"i": "integer", "l": "long", "d": "double", "s": "keyword"}
	for _, expr := range []string{
		"", "true", "42", "999999999999", "3.14",
		"TO_IP(s)", "TO_DOUBLE(s)", "TO_INTEGER(s)", "TO_LONG(s)", "TO_UNSIGNED_LONG(s)",
		"TO_BOOLEAN(s)", "TO_DATETIME(s)", "TO_VERSION(s)", "TO_GEOPOINT(s)", "TO_CARTESIANPOINT(s)",
		"TO_GEOSHAPE(s)", "TO_CARTESIANSHAPE(s)", "TO_STRING(i)", "STARTS_WITH(s, \"a\")",
		"LENGTH(s)", "SIN(d)", "COALESCE(null, l)", "MV_MIN(l)", "MV_AVG(l)", "MV_COUNT(l)",
		"i == 1", "i + l", "i + 2", "d * 2", "i / 2",
	} {
		_ = inferESQLExprStaticTypeRound63(expr, colTypes)
	}
	castExpr := rewriteESQLDoubleColonCastsRound63("a::ip, b::long, c::int, d::double, e::boolean, f::string, g::datetime, h::version, u::unsigned_long")
	if !strings.Contains(castExpr, "TO_IP(a)") || !strings.Contains(castExpr, "TO_UNSIGNED_LONG(u)") {
		t.Fatalf("unexpected cast rewrite: %s", castExpr)
	}
	if _, okB := validateESQLBodyFieldsRound63(map[string]any{"bad_field": 1}); okB {
		t.Fatalf("expected unknown ESQL body field error")
	}

	// 2. Inline & Index-backed LOOKUP JOIN + error branches
	docs1, _, _, okTbl := extractInlineLookupTableDocsRound63(map[string]any{
		"tables": map[string]any{
			"t1": map[string]any{
				"columns": []any{map[string]any{"name": "k", "type": "keyword"}, map[string]any{"name": "v", "type": "long"}},
				"values":  []any{[]any{"a", 1}, []any{"b", 2}},
			},
		},
	}, "t1")
	if !okTbl || len(docs1) != 2 {
		t.Fatalf("expected 2 inline table docs, got %v", docs1)
	}
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/lkp_idx", `{
		"settings": {"index": {"mode": "lookup"}},
		"mappings": {"properties": {"k": {"type": "keyword"}, "info": {"type": "keyword"}}}
	}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/lkp_idx/_doc/1?refresh=true", `{"k":"a","info":"alpha"}`)
	recW1 := httptest.NewRecorder()
	_, _, _, okL1 := executeESQLLookupJoinStageRound63(srv, recW1, httptest.NewRequest(http.MethodPost, "/_query", nil),
		"LOOKUP JOIN lkp_idx ON k", []map[string]any{{"k": "a"}}, []string{"k"}, map[string]string{"k": "keyword"})
	if !okL1 {
		t.Fatalf("expected index-backed LOOKUP JOIN to succeed: %s", recW1.Body.String())
	}
	recW2 := httptest.NewRecorder()
	_, _, _, _ = executeESQLLookupJoinStageRound63(srv, recW2, nil, "LOOKUP JOIN lkp_idx ON UPPER(k)", nil, nil, nil)
	recW3 := httptest.NewRecorder()
	_, _, _, _ = executeESQLLookupJoinStageRound63(srv, recW3, nil, "LOOKUP JOIN lkp_idx k", nil, nil, nil)

	// 3. Downsample timestamp parsing, float slices, histogram labels & ambiguous ES|QL schemas
	for _, tsIn := range []any{
		int64(1700000000), int(1700000000), float64(1700000000),
		json.Number("1700000000"), json.Number("1700000000.5"),
		"1700000000", "2023-05-01 12:00:00", "2023-05-01",
	} {
		_, _ = parseDownsampleTimestampNanosRound63(tsIn, "epoch_second")
	}
	_, _ = parseDownsampleTimestampNanosRound63(int64(1700000000000000000), "")
	if fs := extractFloatSliceForDownsampleRound63([]any{1.5, 2.5}); len(fs) != 2 {
		t.Fatalf("expected 2 floats, got %v", fs)
	}
	dstLbl := map[string]any{}
	overlayDownsampleLabelsAndDimsRound63(dstLbl, map[string]any{
		"@timestamp": "skip",
		"_doc_count": 2,
		"hist":       map[string]any{"values": []any{1.0, 2.0}, "counts": []any{3, 4}},
		"nested":     map[string]any{"k": "v"},
	}, "", downsampleSchemaInfoRound63{metricTypes: map[string]string{}, ignoreAbove: map[string]int{}})
	if dstLbl["hist"] == nil || dstLbl["nested"] == nil {
		t.Fatalf("expected hist and nested copied: %v", dstLbl)
	}

	// Ambiguous multi-index ES|QL inspection + alias field
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/amb_1", `{"mappings":{"properties":{"x":{"type":"integer"},"x_alias":{"type":"alias","path":"x"},"n":{"type":"nested"}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/amb_2", `{"mappings":{"properties":{"x":{"type":"ip"}}}}`)
	ambSum := inspectESQLFromTargetSchemasRound63(srv, context.Background(), "amb_*")
	if ambSum.ambiguousError["x"] == "" {
		t.Fatalf("expected ambiguousError on field x")
	}

	// 4. ILM retry happy/non-errored paths, synonym reload []map, agg prefixes, termvector helpers
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/_ilm/policy/err_pol", `{"policy":{"phases":{"hot":{"actions":{}}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/ilm_retry_idx", `{"settings":{"index":{"lifecycle":{"name":"err_pol"},"number_of_replicas":2}}}`)
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/ilm_retry_idx/_ilm/retry", "").Code; c != http.StatusBadRequest {
		t.Fatalf("expected 400 retry on non-errored index, got %d", c)
	}
	srv.mu.Lock()
	srv.indexCustomSettings["ilm_retry_idx"]["__ilm_step"] = "ERROR"
	srv.aliases["tv_alias"] = []string{"ilm_retry_idx"}
	srv.mu.Unlock()
	srv.persistIndexBatchRound59(context.Background(), []string{"ilm_retry_idx"})
	if c := doRound63ModulesReq(t, h, http.MethodPost, "/ilm_retry_idx/_ilm/retry", "").Code; c != http.StatusOK {
		t.Fatalf("expected 200 retry on ERROR index, got %d", c)
	}
	if got := resolveConcreteTermVectorIndexRound63(srv, "tv_alias"); got != "ilm_retry_idx" {
		t.Fatalf("expected ilm_retry_idx, got %s", got)
	}
	srv.mu.RLock()
	rdTyped := map[string]any{"reload_details": []map[string]any{{"index": "ilm_retry_idx"}}}
	srv.adjustSynonymReloadShardsLockedRound63("s", rdTyped)
	srv.mu.RUnlock()
	_ = inferAggTypePrefixRound63("p", map[string]any{"values": map[string]any{}}, nil)
	_ = inferAggTypePrefixRound63("st", map[string]any{"count": 1}, nil)

	propsTree := map[string]esast.FieldProperty{
		"outer": {
			Properties: map[string]esast.FieldProperty{
				"inner": {
					Type:   "text",
					Fields: map[string]esast.FieldProperty{"raw": {Type: "keyword"}},
				},
			},
		},
	}
	if _, okP := lookupMappingFieldPropRound63(propsTree, "outer.inner.raw"); !okP {
		t.Fatalf("expected lookupMappingFieldPropRound63 to resolve outer.inner.raw")
	}
	cfgCustom := map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{"my_pay": map[string]any{"type": "type_as_payload"}},
			"analyzer": map[string]any{
				"default": map[string]any{"tokenizer": "whitespace", "filter": []string{"my_pay"}},
			},
		},
	}
	if !hasDefaultAnalyzerInSettingsRound63(cfgCustom) || !analyzerUsesTypeAsPayloadRound63(cfgCustom, "default") {
		t.Fatalf("expected default analyzer & custom type_as_payload detection")
	}

	// 5. OLE2 printable fallback, cp1252 smart quotes, VT_LPWSTR & VT_FILETIME SummaryInfo, SLM schedules, EQL line/col
	for _, b := range []byte{0x91, 0x92, 0x93, 0x94, 0x96, 0x97, 'A'} {
		_ = cp1252ToRuneRound63(b)
	}
	if pr := extractPrintableRunsFromOLE2Round63([]byte("\x00\x01Lorem ipsum fallback printable text run\x00\x02")); !strings.Contains(pr, "Lorem") {
		t.Fatalf("unexpected printable run: %s", pr)
	}
	// SummaryInformation with VT_LPWSTR (0x001F) & VT_FILETIME (0x0040)
	sumBuf := make([]byte, 256)
	binary.LittleEndian.PutUint32(sumBuf[24:28], 1)
	binary.LittleEndian.PutUint32(sumBuf[44:48], 48)
	binary.LittleEndian.PutUint32(sumBuf[48:52], 180)
	binary.LittleEndian.PutUint32(sumBuf[52:56], 5)
	// 5 props: 5 (keywords LPSTR), 6 (comments LPSTR), 8 (lastauthor LPWSTR), 12 (created FILETIME), 13 (modified FILETIME)
	propsMeta := [][2]uint32{{5, 48}, {6, 68}, {8, 88}, {12, 116}, {13, 132}}
	for i, pm := range propsMeta {
		off := 56 + i*8
		binary.LittleEndian.PutUint32(sumBuf[off:off+4], pm[0])
		binary.LittleEndian.PutUint32(sumBuf[off+4:off+8], pm[1])
	}
	// rel 48 (abs 96): LPSTR "kw\x00"
	binary.LittleEndian.PutUint16(sumBuf[96:98], 0x001E)
	binary.LittleEndian.PutUint32(sumBuf[100:104], 3)
	copy(sumBuf[104:107], "kw\x00")
	// rel 68 (abs 116): LPSTR "cm\x00"
	binary.LittleEndian.PutUint16(sumBuf[116:118], 0x001E)
	binary.LittleEndian.PutUint32(sumBuf[120:124], 3)
	copy(sumBuf[124:127], "cm\x00")
	// rel 88 (abs 136): LPWSTR "Ed\x00" (3 utf16 chars)
	binary.LittleEndian.PutUint16(sumBuf[136:138], 0x001F)
	binary.LittleEndian.PutUint32(sumBuf[140:144], 3)
	binary.LittleEndian.PutUint16(sumBuf[144:146], 'E')
	binary.LittleEndian.PutUint16(sumBuf[146:148], 'd')
	binary.LittleEndian.PutUint16(sumBuf[148:150], 0)
	// rel 116 (abs 164) & rel 132 (abs 180): VT_FILETIME
	const sampleFT = uint64(133274160000000000)
	binary.LittleEndian.PutUint16(sumBuf[164:166], 0x0040)
	binary.LittleEndian.PutUint64(sumBuf[168:176], sampleFT)
	binary.LittleEndian.PutUint16(sumBuf[180:182], 0x0040)
	binary.LittleEndian.PutUint64(sumBuf[184:192], sampleFT)
	sumOut := map[string]any{}
	parseOLE2SummaryInfoRound63(sumBuf, sumOut, true)
	if sumOut["keywords"] != "kw" || sumOut["description"] != "cm" || sumOut["modifier"] != "Ed" || sumOut["created"] == nil {
		t.Fatalf("unexpected SummaryInfo parse: %v", sumOut)
	}

	for _, sched := range []string{"bad", "* 30 * * * ?", "0 */5 * * * ?", "0 0/10 * * * ?", "0 1-5 * * * ?", "0 1,2,3,4,5 * * * ?"} {
		if validateSLMScheduleRound63(sched) == nil {
			t.Fatalf("expected schedule %q to fail validation", sched)
		}
	}
	ln, col := findTokenLineColInQueryRound63("process where msg == \"escaped \\\" str\"\nand bad_col == 1", "bad_col")
	if ln != 2 || col <= 1 {
		t.Fatalf("expected line 2, got %d:%d", ln, col)
	}
	_, _ = parseIngestWeekDateRound63("20-03 Mon 12:00:00.123 ''", []any{"YY-ww EEE HH:mm:ss.SSS ''''"}, "America/New_York")

	// 6. EQL runtime_mappings validation/evaluation branches & named compound queries & MLT options
	_, _ = validateEQLRuntimeMappingsRound63("not_a_map")
	_, _ = validateEQLRuntimeMappingsRound63(map[string]any{"": map[string]any{}})
	_, _ = validateEQLRuntimeMappingsRound63(map[string]any{"f": "not_obj"})
	_, _ = validateEQLRuntimeMappingsRound63(map[string]any{"f": map[string]any{"bad_param": 1}})
	_, _ = validateEQLRuntimeMappingsRound63(map[string]any{"f": map[string]any{"type": "keyword", "script": map[string]any{"unknown": 1}}})
	_, _ = validateEQLRuntimeMappingsRound63(map[string]any{"f": map[string]any{"type": "keyword", "script": 123}})
	validRM, vErr := validateEQLRuntimeMappingsRound63(map[string]any{
		"f1": map[string]any{"type": "keyword", "script": map[string]any{"inline": "emit('v1'); emit('v2')", "params": map[string]any{"p": 1}}},
		"f2": map[string]any{"type": "keyword"},
		"f3": map[string]any{"type": "keyword", "script": "if (false) { emit('no'); }"},
	})
	if vErr != nil {
		t.Fatalf("unexpected validRM err: %v", vErr)
	}
	docRM := map[string]any{"f2": "existing", "f3": "will_be_deleted"}
	evalEQLRuntimeFieldsOnDocRound63(docRM, map[string]any{"hf1": []any{"one"}, "hf2": []any{"a", "b"}}, validRM)
	if docRM["f3"] != nil || docRM["hf1"] != "one" {
		t.Fatalf("unexpected evalEQLRuntimeFieldsOnDocRound63: %v", docRM)
	}

	compoundNamed := map[string]any{
		"bool": map[string]any{
			"must": map[string]any{
				"constant_score": map[string]any{
					"_name":  "cs_n",
					"filter": map[string]any{"exists": map[string]any{"_name": "ex_n", "field": "x"}},
				},
			},
			"should": []any{
				map[string]any{"dis_max": map[string]any{"_name": "dm_n", "queries": []any{map[string]any{"exists": map[string]any{"field": "x"}}}}},
				map[string]any{"boosting": map[string]any{"_name": "bst_n", "positive": map[string]any{"exists": map[string]any{"field": "x"}}, "negative": map[string]any{"exists": map[string]any{"field": "y"}}}},
				map[string]any{"function_score": map[string]any{"_name": "fs_n", "query": map[string]any{"exists": map[string]any{"field": "x"}}}},
			},
		},
	}
	namesFound := collectMatchedNamedRawQueriesRound63(compoundNamed, map[string]any{"x": 1}, func(any, map[string]any) bool { return true })
	if len(namesFound) < 5 {
		t.Fatalf("expected >= 5 named queries, got %v", namesFound)
	}

	// MLT inline doc, stop_words, minimum_should_match %, boost, max_query_terms
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_cov", `{"mappings":{"properties":{"t":{"type":"text"}}}}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_cov/_doc/1?refresh=true", `{"t":"alpha beta gamma delta"}`)
	_ = doRound63ModulesReq(t, h, http.MethodPut, "/mlt_cov/_doc/2?refresh=true", `{"t":"alpha beta epsilon"}`)
	boostVal := 2.0
	mltQ, mltErr := srv.preResolveMoreLikeThisQueryRound63(context.Background(), []string{"mlt_cov"}, &esast.MoreLikeThisQuery{
		Like:               []any{map[string]any{"doc": map[string]any{"t": "alpha beta gamma"}, "fields": []any{"t"}}, "delta the"},
		StopWords:          []string{"the"},
		MinWordLength:      2,
		MaxWordLength:      20,
		MinTermFreq:        1,
		MinDocFreq:         1,
		MaxDocFreq:         10,
		MaxQueryTerms:      3,
		MinimumShouldMatch: "50%",
		Boost:              &boostVal,
	})
	if mltErr != nil || mltQ == nil {
		t.Fatalf("unexpected MLT pre-resolve result: %v %v", mltQ, mltErr)
	}
}

func discoverRound63ModulesRestSpecDirs(root string) []string {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.HasSuffix(filepath.ToSlash(path), "/rest-api-spec/test") {
			dirs = append(dirs, path)
			return filepath.SkipDir
		}
		return nil
	})
	sort.Strings(dirs)
	return dirs
}

func TestRound63_OwnedConformanceCategories(t *testing.T) {
	cacheDir := strings.TrimSpace(os.Getenv("CONFORMANCE_CACHE_DIR"))
	catsEnv := strings.TrimSpace(os.Getenv("ROUND63_SUITE_CATS"))
	if cacheDir == "" || catsEnv == "" {
		t.Skip("set CONFORMANCE_CACHE_DIR and ROUND63_SUITE_CATS to run targeted Round63 category diagnostics")
	}
	ver := strings.TrimSpace(os.Getenv("ROUND63_SUITE_VER"))
	if ver == "" {
		ver = "8.15.5"
	}
	subDir := "es-v8.15.5"
	if strings.HasPrefix(ver, "7.") {
		subDir = "es-v7.10.2"
	}
	dirs := discoverRound63ModulesRestSpecDirs(filepath.Join(cacheDir, subDir))
	if len(dirs) == 0 {
		t.Skipf("no rest-api-spec dirs under %s/%s", cacheDir, subDir)
	}
	var cats []string
	for _, c := range strings.Split(catsEnv, ",") {
		if c = strings.TrimSpace(c); c != "" {
			cats = append(cats, c)
		}
	}
	var srvByHandler sync.Map
	opts := compliance.SuiteOptions{
		CorpusName:                  subDir,
		TargetVersion:               ver,
		SupportedClusterFeatures:    compliance.DefaultSupportedClusterFeatures(),
		SupportedTestRunnerFeatures: compliance.DefaultSupportedTestRunnerFeatures(),
		Categories:                  cats,
		ReuseSetupForReadOnlyFiles:  true,
		NewSectionHandler: func() (http.Handler, func()) {
			srv := newRound63ModulesIngestTestServer(ver)
			srv.SetStaticRemoteReindexWhitelist("127.0.0.1:*,localhost:*")
			srv.SetRemoteReindexAllowPrivateIPs(true)
			inner := srv.Handler()
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(w, r)
			})
			ptr := &wrapped
			srvByHandler.Store(ptr, srv)
			return ptr, func() {
				srvByHandler.Delete(ptr)
				_ = srv.Close(context.Background())
			}
		},
		ConfigureRemoteTransport: func(handler http.Handler, rt http.RoundTripper) {
			if v, ok := srvByHandler.Load(handler); ok {
				if srv, okS := v.(*Server); okS {
					srv.SetRemoteReindexTransport(rt)
				}
			}
		},
	}
	card, err := compliance.ScoreDirectories(opts, dirs...)
	if err != nil {
		t.Fatalf("ScoreDirectories: %v", err)
	}
	t.Logf("[%s] files=%d passed=%d failed=%d skipped=%d rate=%.2f%%",
		ver, card.TotalFiles, card.SectionsPassed, card.SectionsFailed, card.SectionsSkipped, card.PassRatePct)
	for _, cs := range card.Categories {
		t.Logf("  cat %-28s files=%d passed=%d failed=%d skipped=%d (%.2f%%)",
			cs.Category, cs.Files, cs.Passed, cs.Failed, cs.Skipped, cs.PassRatePct)
	}
	for i, fs := range card.FailureSamples {
		errClean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' || (r >= 32 && r < 127) {
				return r
			}
			return '?'
		}, fs.Error)
		if len(errClean) > 360 {
			errClean = errClean[:360] + "..."
		}
		t.Logf("  FAIL[%d] [%s] %s :: %s\n      %s", i+1, fs.Category, fs.File, fs.Section, errClean)
	}
}
