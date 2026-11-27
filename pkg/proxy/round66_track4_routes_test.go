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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR66Track4Server(t *testing.T, targetVersion string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if targetVersion != "" {
		srv.SetTargetESVersion(targetVersion)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR66Track4Req(
	t *testing.T,
	h http.Handler,
	method, target, body string,
	headers map[string]string,
) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rBody io.Reader
	if body != "" {
		rBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rBody)
	if body != "" {
		if _, ok := headers["Content-Type"]; !ok {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var decoded map[string]any
	if strings.TrimSpace(raw) != "" && strings.HasPrefix(strings.TrimSpace(raw), "{") {
		_ = json.Unmarshal([]byte(raw), &decoded)
	}
	return rec.Code, rec.Header(), decoded, raw
}

func TestRound66Track4_Cluster16ConformanceFixes(t *testing.T) {
	t.Run("voting_config_exclusions_warning_regex", func(t *testing.T) {
		_, h := newR66Track4Server(t, "8.15.5")
		code, hdr, _, raw := doR66Track4Req(t, h, http.MethodPost, "/_cluster/voting_config_exclusions/node_1", "", nil)
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 on removed voting_config_exclusions/{node_name}, got %d: %s", code, raw)
		}
		warnings := hdr.Values("Warning")
		pat := regexp.MustCompile(`.* /_cluster/voting_config_exclusions/\{node_name\} has been removed\. .*`)
		matched := false
		for _, wv := range warnings {
			if pat.MatchString(wv) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("expected Warning header matching %q, got %v", pat.String(), warnings)
		}
	})

	t.Run("rollup_deprecation_validation_and_sdk_compat", func(t *testing.T) {
		_, h := newR66Track4Server(t, "8.15.5")
		xpackAuth := map[string]string{
			"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("x_pack_rest_user:x-pack-test-password")),
		}

		// 1. ES8 + authenticated + no rollup usage -> deprecation failure BEFORE field validation.
		putBodyMissingField := `{
			"index_pattern": "sensor-*",
			"rollup_index": "sensor_rollup",
			"cron": "0 * * * * ?",
			"page_size": 10,
			"groups": {"terms": {"fields": ["field_doesnt_exist"]}},
			"metrics": [{"field": "field_doesnt_exist", "metrics": ["max"]}]
		}`
		cDep, _, _, rawDep := doR66Track4Req(t, h, http.MethodPut, "/_rollup/job/dep_job", putBodyMissingField, xpackAuth)
		if cDep != http.StatusBadRequest || !strings.Contains(rawDep, "new rollup jobs are not allowed in clusters that don't have any rollup usage, since rollup has been deprecated") {
			t.Fatalf("expected ES8 rollup deprecation 400 error, got %d: %s", cDep, rawDep)
		}

		// 2. ES8 + unauthenticated (SDK conformance Round65_08 pattern) succeeds without dummy-rollup-index.
		doR66Track4Req(t, h, http.MethodPut, "/sdk_src", `{"mappings":{"properties":{"ts":{"type":"date"},"val":{"type":"double"}}}}`, nil)
		sdkRollupBody := `{
			"index_pattern": "sdk_src",
			"rollup_index": "sdk_src_rollup",
			"cron": "0 * * * * ?",
			"page_size": 100,
			"groups": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}},
			"metrics": [{"field": "val", "metrics": ["avg"]}]
		}`
		cSDK, _, mSDK, rawSDK := doR66Track4Req(t, h, http.MethodPut, "/_rollup/job/sdk_job", sdkRollupBody, nil)
		if cSDK != http.StatusOK || mSDK["acknowledged"] != true {
			t.Fatalf("expected unauthenticated SDK rollup put_job to succeed, got %d: %s", cSDK, rawSDK)
		}

		// 3. ES8 + authenticated succeeds once cluster has _meta._rollup index usage.
		_, h2 := newR66Track4Server(t, "8.15.5")
		doR66Track4Req(t, h2, http.MethodPut, "/dummy-rollup-index", `{"mappings":{"_meta":{"_rollup":{"ver":1}}}}`, nil)
		cAuthOK, _, mAuthOK, rawAuthOK := doR66Track4Req(t, h2, http.MethodPut, "/_rollup/job/auth_job", `{
			"index_pattern": "dummy-*",
			"rollup_index": "dummy_rollup_out",
			"cron": "0 * * * * ?",
			"page_size": 10,
			"groups": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}}
		}`, xpackAuth)
		if cAuthOK != http.StatusOK || mAuthOK["acknowledged"] != true {
			t.Fatalf("expected authenticated rollup put_job to succeed when _meta._rollup exists, got %d: %s", cAuthOK, rawAuthOK)
		}

		// 4. ES < 8 allows authenticated put_job even without prior rollup usage.
		_, h7 := newR66Track4Server(t, "7.10.2")
		cV7, _, mV7, rawV7 := doR66Track4Req(t, h7, http.MethodPut, "/_rollup/job/v7_job", `{
			"index_pattern": "logs-*",
			"rollup_index": "logs_rollup_v7",
			"cron": "0 * * * * ?",
			"page_size": 10,
			"groups": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}}
		}`, xpackAuth)
		if cV7 != http.StatusOK || mV7["acknowledged"] != true {
			t.Fatalf("expected v7.10.2 rollup put_job to succeed, got %d: %s", cV7, rawV7)
		}
	})

	t.Run("snapshot_recovery_files_recovered", func(t *testing.T) {
		runCase := func(esVer string, wantSourceRecovered float64) {
			t.Helper()
			srv, h := newR66Track4Server(t, esVer)
			repoDir := t.TempDir()
			doR66Track4Req(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"path.repo":["`+repoDir+`"]}}`, nil)
			_ = srv

			doR66Track4Req(t, h, http.MethodPut, "/src_repo_idx", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`, nil)
			doR66Track4Req(t, h, http.MethodPut, "/src_repo_idx/_doc/1?refresh=true", `{"msg":"hello"}`, nil)

			doR66Track4Req(t, h, http.MethodPut, "/_snapshot/my_source_repo", `{"type":"source"}`, nil)
			doR66Track4Req(t, h, http.MethodPut, "/_snapshot/my_fs_repo", `{"type":"fs","settings":{"location":"`+repoDir+`"}}`, nil)

			doR66Track4Req(t, h, http.MethodPut, "/_snapshot/my_source_repo/snap_src?wait_for_completion=true", `{"indices":"src_repo_idx"}`, nil)
			doR66Track4Req(t, h, http.MethodPut, "/_snapshot/my_fs_repo/snap_fs?wait_for_completion=true", `{"indices":"src_repo_idx"}`, nil)

			// Restore from source repo -> recovered = 6 (ES >= 7.7) or 5 (< 7.7).
			cRestSrc, _, _, rawRestSrc := doR66Track4Req(t, h, http.MethodPost, "/_snapshot/my_source_repo/snap_src/_restore?wait_for_completion=true", `{"indices":"src_repo_idx","rename_pattern":"(.+)","rename_replacement":"restored_src_$1"}`, nil)
			if cRestSrc != http.StatusOK {
				t.Fatalf("source restore failed: %d %s", cRestSrc, rawRestSrc)
			}
			cRecSrc, _, mRecSrc, rawRecSrc := doR66Track4Req(t, h, http.MethodGet, "/restored_src_src_repo_idx/_recovery", "", nil)
			if cRecSrc != http.StatusOK {
				t.Fatalf("recovery failed: %d %s", cRecSrc, rawRecSrc)
			}
			shardSrc := mRecSrc["restored_src_src_repo_idx"].(map[string]any)["shards"].([]any)[0].(map[string]any)
			if shardSrc["type"] != "SNAPSHOT" {
				t.Fatalf("expected recovery type SNAPSHOT, got %v", shardSrc["type"])
			}
			gotSrcFiles := shardSrc["index"].(map[string]any)["files"].(map[string]any)["recovered"].(float64)
			if gotSrcFiles != wantSourceRecovered {
				t.Fatalf("esVer=%s source snapshot files.recovered = %v, want %v", esVer, gotSrcFiles, wantSourceRecovered)
			}

			// Restore from fs repo -> recovered stays 1.
			cRestFS, _, _, rawRestFS := doR66Track4Req(t, h, http.MethodPost, "/_snapshot/my_fs_repo/snap_fs/_restore?wait_for_completion=true", `{"indices":"src_repo_idx","rename_pattern":"(.+)","rename_replacement":"restored_fs_$1"}`, nil)
			if cRestFS != http.StatusOK {
				t.Fatalf("fs restore failed: %d %s", cRestFS, rawRestFS)
			}
			cRecFS, _, mRecFS, rawRecFS := doR66Track4Req(t, h, http.MethodGet, "/restored_fs_src_repo_idx/_recovery", "", nil)
			if cRecFS != http.StatusOK {
				t.Fatalf("fs recovery failed: %d %s", cRecFS, rawRecFS)
			}
			shardFS := mRecFS["restored_fs_src_repo_idx"].(map[string]any)["shards"].([]any)[0].(map[string]any)
			gotFSFiles := shardFS["index"].(map[string]any)["files"].(map[string]any)["recovered"].(float64)
			if gotFSFiles != 1 {
				t.Fatalf("esVer=%s fs snapshot files.recovered = %v, want 1", esVer, gotFSFiles)
			}
		}
		runCase("8.15.5", 6)
		runCase("7.6.2", 5)
	})
}

func TestRound66Track4_SearchableSnapshotsTransformNodesMetering(t *testing.T) {
	_, h := newR66Track4Server(t, "8.15.5")

	// 1. searchable_snapshots.cache_stats
	for _, path := range []string{
		"/_searchable_snapshots/cache/stats",
		"/_searchable_snapshots/doris-fe-1/cache/stats",
	} {
		code, _, m, raw := doR66Track4Req(t, h, http.MethodGet, path, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", path, code, raw)
		}
		sc := m["nodes"].(map[string]any)["doris-fe-1"].(map[string]any)["shared_cache"].(map[string]any)
		for _, reqKey := range []string{"reads", "bytes_read_in_bytes", "writes", "bytes_written_in_bytes", "evictions", "num_regions", "size_in_bytes", "region_size_in_bytes"} {
			if _, ok := sc[reqKey]; !ok {
				t.Fatalf("GET %s missing shared_cache.%s: %s", path, reqKey, raw)
			}
		}
	}
	if code, _, m, raw := doR66Track4Req(t, h, http.MethodGet, "/_searchable_snapshots/no-such-node/cache/stats", "", nil); code != http.StatusOK || len(m["nodes"].(map[string]any)) != 0 {
		t.Fatalf("expected empty nodes map for unmatched node_id, got %d %s", code, raw)
	}

	// 2. transform.get_transform_stats -> node.attributes
	doR66Track4Req(t, h, http.MethodPut, "/tf_src_r66", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, nil)
	cTF, _, _, rawTF := doR66Track4Req(t, h, http.MethodPut, "/_transform/tf_r66", `{"source":{"index":["tf_src_r66"]},"dest":{"index":"tf_dst_r66"},"pivot":{"group_by":{"k":{"terms":{"field":"k"}}},"aggregations":{}}}`, nil)
	if cTF != http.StatusOK {
		t.Fatalf("PUT transform failed: %d %s", cTF, rawTF)
	}
	cSt, _, mSt, rawSt := doR66Track4Req(t, h, http.MethodGet, "/_transform/tf_r66/_stats", "", nil)
	if cSt != http.StatusOK {
		t.Fatalf("GET transform stats failed: %d %s", cSt, rawSt)
	}
	nodeObj := mSt["transforms"].([]any)[0].(map[string]any)["node"].(map[string]any)
	if _, ok := nodeObj["attributes"].(map[string]any); !ok {
		t.Fatalf("expected node.attributes map in transform stats, got %+v", nodeObj)
	}

	// 3. nodes.clear_repositories_metering_archive
	for _, delPath := range []string{
		"/_nodes/doris-fe-1/_repositories_metering/5",
		"/_nodes/_repositories_metering/5",
		"/_nodes/doris-fe-1/repositories_metering/5",
	} {
		cDel, _, mDel, rawDel := doR66Track4Req(t, h, http.MethodDelete, delPath, "", nil)
		if cDel != http.StatusOK || mDel["cluster_name"] == nil {
			t.Fatalf("DELETE %s failed: %d %s", delPath, cDel, rawDel)
		}
		nodesMap, ok := mDel["nodes"].(map[string]any)
		if !ok || len(nodesMap) != 0 {
			t.Fatalf("expected schema-compliant empty nodes map on %s, got %+v", delPath, mDel["nodes"])
		}
	}
	if cBadVer, _, _, _ := doR66Track4Req(t, h, http.MethodDelete, "/_nodes/doris-fe-1/_repositories_metering/bad_ver", "", nil); cBadVer != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-int max_archive_version, got %d", cBadVer)
	}
	if cMissVer, _, _, _ := doR66Track4Req(t, h, http.MethodDelete, "/_nodes/doris-fe-1/_repositories_metering", "", nil); cMissVer != http.StatusBadRequest {
		t.Fatalf("expected 400 when max_archive_version missing on DELETE, got %d", cMissVer)
	}
}

func TestRound66Track4_FleetEndpoints(t *testing.T) {
	_, h := newR66Track4Server(t, "8.15.5")
	doR66Track4Req(t, h, http.MethodPut, "/r66_fleet_logs", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`, nil)
	doR66Track4Req(t, h, http.MethodPut, "/r66_fleet_logs/_doc/1?refresh=true", `{"msg":"fleet-ok"}`, nil)

	// Singular /_fleet/secret CRUD with redaction
	cPost, _, mPost, rawPost := doR66Track4Req(t, h, http.MethodPost, "/_fleet/secret", `{"value":"top-secret-fleet-val"}`, nil)
	if cPost != http.StatusOK || mPost["id"] == nil {
		t.Fatalf("POST /_fleet/secret failed: %d %s", cPost, rawPost)
	}
	secID := mPost["id"].(string)
	cGet, _, mGet, rawGet := doR66Track4Req(t, h, http.MethodGet, "/_fleet/secret/"+secID, "", nil)
	if cGet != http.StatusOK || mGet["id"] != secID || strings.Contains(rawGet, "top-secret-fleet-val") {
		t.Fatalf("GET /_fleet/secret/%s invalid or leaked secret: %d %s", secID, cGet, rawGet)
	}
	cDel, _, _, rawDel := doR66Track4Req(t, h, http.MethodDelete, "/_fleet/secret/"+secID, "", nil)
	if cDel != http.StatusOK {
		t.Fatalf("DELETE /_fleet/secret/%s failed: %d %s", secID, cDel, rawDel)
	}
	if cGone, _, _, _ := doR66Track4Req(t, h, http.MethodGet, "/_fleet/secret/"+secID, "", nil); cGone != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", cGone)
	}

	// _fleet_search
	for _, sPath := range []string{"/_fleet/_fleet_search", "/r66_fleet_logs/_fleet/_fleet_search"} {
		cS, _, mS, rawS := doR66Track4Req(t, h, http.MethodPost, sPath, `{"query":{"match_all":{}}}`, nil)
		if cS != http.StatusOK || mS["hits"] == nil || mS["timed_out"] == nil {
			t.Fatalf("POST %s failed: %d %s", sPath, cS, rawS)
		}
	}

	// _fleet_msearch -> schema requires docs[] alongside responses[]
	for _, mPath := range []string{"/_fleet/_fleet_msearch", "/r66_fleet_logs/_fleet/_fleet_msearch"} {
		cMS, _, mMS, rawMS := doR66Track4Req(t, h, http.MethodPost, mPath, "{}\n{\"query\":{\"match_all\":{}}}\n", nil)
		if cMS != http.StatusOK {
			t.Fatalf("POST %s failed: %d %s", mPath, cMS, rawMS)
		}
		docsArr, okD := mMS["docs"].([]any)
		if !okD || len(docsArr) != 1 {
			t.Fatalf("expected docs[1] in fleet msearch %s, got %s", mPath, rawMS)
		}
	}

	// global_checkpoints requires timed_out
	cGC, _, mGC, rawGC := doR66Track4Req(t, h, http.MethodGet, "/r66_fleet_logs/_fleet/global_checkpoints", "", nil)
	if cGC != http.StatusOK || mGC["timed_out"] != false || mGC["global_checkpoints"] == nil {
		t.Fatalf("GET global_checkpoints missing required fields: %d %s", cGC, rawGC)
	}
}

func TestRound66Track4_MLEndpoints(t *testing.T) {
	_, h := newR66Track4Server(t, "8.15.5")

	// 1. ml.get_memory_stats
	for _, p := range []string{"/_ml/memory/_stats", "/_ml/memory/doris-fe-1/_stats", "/_ml/memory_stats"} {
		c, _, m, raw := doR66Track4Req(t, h, http.MethodGet, p, "", nil)
		if c != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", p, c, raw)
		}
		node := m["nodes"].(map[string]any)["doris-fe-1"].(map[string]any)
		for _, k := range []string{"attributes", "roles", "transport_address", "ephemeral_id", "name", "jvm", "mem"} {
			if _, ok := node[k]; !ok {
				t.Fatalf("GET %s missing node.%s: %s", p, k, raw)
			}
		}
		jvm := node["jvm"].(map[string]any)
		if _, ok := jvm["java_inference_max_in_bytes"]; !ok {
			t.Fatalf("GET %s missing jvm.java_inference_max_in_bytes: %s", p, raw)
		}
	}
	if c, _, m, raw := doR66Track4Req(t, h, http.MethodGet, "/_ml/memory/no-node/_stats", "", nil); c != http.StatusOK || len(m["nodes"].(map[string]any)) != 0 {
		t.Fatalf("expected empty nodes for unknown node_id, got %d %s", c, raw)
	}

	// 2. ml.clear_trained_model_deployment_cache (cache and _cache)
	doR66Track4Req(t, h, http.MethodPut, "/_ml/trained_models/r66_tm", `{"input":{"field_names":["msg"]}}`, nil)
	doR66Track4Req(t, h, http.MethodPost, "/_ml/trained_models/r66_tm/deployment/_start", `{}`, nil)
	for _, p := range []string{
		"/_ml/trained_models/r66_tm/deployment/cache/_clear",
		"/_ml/trained_models/r66_tm/deployment/_cache/_clear",
	} {
		c, _, m, raw := doR66Track4Req(t, h, http.MethodPost, p, "", nil)
		if c != http.StatusOK || m["cleared"] != true || m["acknowledged"] != true {
			t.Fatalf("POST %s expected cleared=true & acknowledged=true, got %d %s", p, c, raw)
		}
	}
}

func TestRound66Track4_Security9Endpoints(t *testing.T) {
	srv, h := newR66Track4Server(t, "8.15.5")
	srv.SetAuth("elastic", "r66-pass", "")
	adminHdr := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:r66-pass")),
	}

	// 1 & 2. bulk_put_role / bulk_delete_role
	cBP, _, mBP, rawBP := doR66Track4Req(t, h, http.MethodPost, "/_security/role", `{"roles":{"r66_a":{"cluster":["monitor"]},"r66_b":{"cluster":["all"]}}}`, adminHdr)
	if cBP != http.StatusOK || len(mBP["created"].([]any)) != 2 {
		t.Fatalf("bulk_put_role failed: %d %s", cBP, rawBP)
	}
	cBP2, _, mBP2, rawBP2 := doR66Track4Req(t, h, http.MethodPost, "/_security/role", `{"roles":{"r66_a":{"cluster":["all"]},"r66_b":{"cluster":["all"]}}}`, adminHdr)
	if cBP2 != http.StatusOK || len(mBP2["updated"].([]any)) != 1 || len(mBP2["noop"].([]any)) != 1 {
		t.Fatalf("bulk_put_role update/noop failed: %d %s", cBP2, rawBP2)
	}
	cBD, _, mBD, rawBD := doR66Track4Req(t, h, http.MethodDelete, "/_security/role", `{"names":["r66_a","r66_missing"]}`, adminHdr)
	if cBD != http.StatusOK || len(mBD["deleted"].([]any)) != 1 || len(mBD["not_found"].([]any)) != 1 {
		t.Fatalf("bulk_delete_role failed: %d %s", cBD, rawBD)
	}
	cBDQ, _, mBDQ, rawBDQ := doR66Track4Req(t, h, http.MethodDelete, "/_security/role?names=r66_b", "", adminHdr)
	if cBDQ != http.StatusOK || len(mBDQ["deleted"].([]any)) != 1 {
		t.Fatalf("bulk_delete_role query names failed: %d %s", cBDQ, rawBDQ)
	}

	// Seed alice_r66 so grant_api_key verifies real user credentials.
	doR66Track4Req(t, h, http.MethodPut, "/_security/user/alice_r66", `{"roles":["superuser"],"password":"secret-password"}`, adminHdr)

	// 3 & 4. grant_api_key & clear_api_key_cache
	cGrant, _, mGrant, rawGrant := doR66Track4Req(t, h, http.MethodPost, "/_security/api_key/grant", `{
		"grant_type": "password",
		"username": "alice_r66",
		"password": "secret-password",
		"api_key": {"name": "r66_granted_key", "expiration": "1h"}
	}`, adminHdr)
	if cGrant != http.StatusOK || mGrant["id"] == nil || mGrant["api_key"] == nil || mGrant["encoded"] == nil {
		t.Fatalf("grant_api_key failed: %d %s", cGrant, rawGrant)
	}
	keyID := mGrant["id"].(string)
	_, _, mKeyGet, rawKeyGet := doR66Track4Req(t, h, http.MethodGet, "/_security/api_key?id="+keyID, "", adminHdr)
	if len(mKeyGet["api_keys"].([]any)) != 1 || mKeyGet["api_keys"].([]any)[0].(map[string]any)["username"] != "alice_r66" {
		t.Fatalf("unexpected granted api_key metadata: %s", rawKeyGet)
	}
	if cBadGT, _, _, _ := doR66Track4Req(t, h, http.MethodPost, "/_security/api_key/grant", `{"grant_type":"invalid","api_key":{"name":"x"}}`, adminHdr); cBadGT != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid grant_type, got %d", cBadGT)
	}
	cClearAK, _, mClearAK, rawClearAK := doR66Track4Req(t, h, http.MethodPost, "/_security/api_key/"+keyID+"/_clear_cache", "", adminHdr)
	if cClearAK != http.StatusOK || mClearAK["_nodes"] == nil || mClearAK["cluster_name"] == nil || mClearAK["nodes"] == nil {
		t.Fatalf("clear_api_key_cache failed: %d %s", cClearAK, rawClearAK)
	}

	// 5 & 6. enroll_kibana & enroll_node (GET schema + POST backwards compat)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		cEK, _, mEK, rawEK := doR66Track4Req(t, h, method, "/_security/enroll/kibana", "", adminHdr)
		if cEK != http.StatusOK {
			t.Fatalf("%s enroll/kibana failed: %d %s", method, cEK, rawEK)
		}
		tok, okT := mEK["token"].(map[string]any)
		if !okT || tok["name"] == nil || tok["value"] == nil || mEK["http_ca"] == nil {
			t.Fatalf("enroll/kibana schema mismatch: %s", rawEK)
		}
		cEN, _, mEN, rawEN := doR66Track4Req(t, h, method, "/_security/enroll/node", "", adminHdr)
		if cEN != http.StatusOK {
			t.Fatalf("%s enroll/node failed: %d %s", method, cEN, rawEN)
		}
		for _, k := range []string{"http_ca_key", "http_ca_cert", "transport_ca_cert", "transport_key", "transport_cert", "nodes_addresses"} {
			if _, ok := mEN[k]; !ok {
				t.Fatalf("enroll/node missing %s: %s", k, rawEN)
			}
		}
	}

	// 7. get_service_credentials
	doR66Track4Req(t, h, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/r66_tok", "", adminHdr)
	cSC, _, mSC, rawSC := doR66Track4Req(t, h, http.MethodGet, "/_security/service/elastic/fleet-server/credential", "", adminHdr)
	if cSC != http.StatusOK || mSC["service_account"] != "elastic/fleet-server" || mSC["count"].(float64) != 1 || mSC["nodes_credentials"] == nil {
		t.Fatalf("get_service_credentials failed: %d %s", cSC, rawSC)
	}
	if _, ok := mSC["tokens"].(map[string]any)["r66_tok"]; !ok {
		t.Fatalf("expected r66_tok in tokens: %s", rawSC)
	}

	// 8 & 9. has_privileges_user_profile & suggest_user_profiles
	doR66Track4Req(t, h, http.MethodPut, "/_security/role/analyst", `{"cluster":["monitor"]}`, adminHdr)
	_, _, prof1, _ := doR66Track4Req(t, h, http.MethodPost, "/_security/profile/_activate", `{"grant":{"user":{"username":"alice_p1","roles":["analyst"]}}}`, adminHdr)
	_, _, prof2, _ := doR66Track4Req(t, h, http.MethodPost, "/_security/profile/_activate", `{"grant":{"user":{"username":"bob_p2","roles":["viewer"]}}}`, adminHdr)
	uid1 := prof1["uid"].(string)
	uid2 := prof2["uid"].(string)
	doR66Track4Req(t, h, http.MethodPut, "/_security/profile/"+uid1+"/_data", `{"labels":{"env":"prod"}}`, adminHdr)
	doR66Track4Req(t, h, http.MethodPut, "/_security/profile/"+uid2+"/_disable", `{}`, adminHdr)

	cHP, _, mHP, rawHP := doR66Track4Req(t, h, http.MethodPost, "/_security/profile/_has_privileges", `{"uids":["`+uid1+`","`+uid2+`","missing_uid"],"privileges":{"cluster":["monitor"]}}`, adminHdr)
	if cHP != http.StatusOK {
		t.Fatalf("has_privileges_user_profile failed: %d %s", cHP, rawHP)
	}
	hpUIDs := mHP["has_privilege_uids"].([]any)
	if len(hpUIDs) != 1 || hpUIDs[0] != uid1 || mHP["errors"].(map[string]any)["count"].(float64) != 1 {
		t.Fatalf("unexpected has_privileges_user_profile result: %s", rawHP)
	}

	for _, method := range []string{http.MethodPost, http.MethodGet} {
		cSug, _, mSug, rawSug := doR66Track4Req(t, h, method, "/_security/profile/_suggest", `{"hint":{"text":"alice","labels":{"env":"prod"}},"size":5}`, adminHdr)
		if cSug != http.StatusOK || mSug["took"] == nil {
			t.Fatalf("%s profile/_suggest failed: %d %s", method, cSug, rawSug)
		}
		tot := mSug["total"].(map[string]any)
		if tot["value"].(float64) != 1 || tot["relation"] != "eq" {
			t.Fatalf("unexpected profile/_suggest total: %s", rawSug)
		}
		p0 := mSug["profiles"].([]any)[0].(map[string]any)
		u0 := p0["user"].(map[string]any)
		if u0["realm_name"] == nil || u0["roles"] == nil || p0["data"] == nil || p0["labels"] == nil {
			t.Fatalf("suggested UserProfile missing required fields: %s", rawSug)
		}
	}

	// Extra schema checks: put_user created, oauth2 token authentication, text_structure sample_start
	cPU, _, mPU, rawPU := doR66Track4Req(t, h, http.MethodPut, "/_security/user/r66_u1", `{"roles":["viewer"],"password":"secret"}`, adminHdr)
	if cPU != http.StatusOK || mPU["created"] != true {
		t.Fatalf("expected created=true on put_user, got %d %s", cPU, rawPU)
	}
	cOA, _, mOA, rawOA := doR66Track4Req(t, h, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"client_credentials"}`, adminHdr)
	if cOA != http.StatusOK || mOA["authentication"] == nil {
		t.Fatalf("expected authentication in oauth2 token response, got %d %s", cOA, rawOA)
	}
	cTS, _, mTS, rawTS := doR66Track4Req(t, h, http.MethodPost, "/_text_structure/find_structure", "2026-01-01T00:00:00Z hello\n", adminHdr)
	if cTS != http.StatusOK || mTS["sample_start"] == nil {
		t.Fatalf("expected sample_start in find_structure response, got %d %s", cTS, rawTS)
	}
}

func TestRound66Track4_ConnectorHandlersAndReset(t *testing.T) {
	_, h := newR66Track4Server(t, "8.15.5")

	// 1. Connector CRUD & result schema field
	cPut1, _, mPut1, rawPut1 := doR66Track4Req(t, h, http.MethodPut, "/_connector/c_r66", `{"name":"R66 Conn","service_type":"postgresql","index_name":"idx_c_r66"}`, nil)
	if cPut1 != http.StatusCreated || mPut1["result"] != "created" || mPut1["id"] != "c_r66" {
		t.Fatalf("PUT connector create failed: %d %s", cPut1, rawPut1)
	}
	cPut2, _, mPut2, rawPut2 := doR66Track4Req(t, h, http.MethodPut, "/_connector/c_r66", `{"name":"R66 Conn 2","service_type":"postgresql","index_name":"idx_c_r66"}`, nil)
	if cPut2 != http.StatusOK || mPut2["result"] != "updated" {
		t.Fatalf("PUT connector update failed: %d %s", cPut2, rawPut2)
	}
	cPutAuto, _, mPutAuto, rawPutAuto := doR66Track4Req(t, h, http.MethodPut, "/_connector", `{"name":"Auto Conn","service_type":"s3"}`, nil)
	if cPutAuto != http.StatusCreated || mPutAuto["result"] != "created" || mPutAuto["id"] == nil {
		t.Fatalf("PUT /_connector without id failed: %d %s", cPutAuto, rawPutAuto)
	}

	// 2. connector.check_in & connector.update_features
	cCI, _, mCI, rawCI := doR66Track4Req(t, h, http.MethodPut, "/_connector/c_r66/_check_in", "", nil)
	if cCI != http.StatusOK || mCI["result"] != "updated" {
		t.Fatalf("PUT _check_in failed: %d %s", cCI, rawCI)
	}
	cFeatBad, _, _, _ := doR66Track4Req(t, h, http.MethodPut, "/_connector/c_r66/_features", `{"features":"bad"}`, nil)
	if cFeatBad != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-object features, got %d", cFeatBad)
	}
	cFeat, _, mFeat, rawFeat := doR66Track4Req(t, h, http.MethodPut, "/_connector/c_r66/_features", `{"features":{"document_level_security":{"enabled":true}}}`, nil)
	if cFeat != http.StatusOK || mFeat["result"] != "updated" {
		t.Fatalf("PUT _features failed: %d %s", cFeat, rawFeat)
	}
	cGetConn, _, mGetConn, rawGetConn := doR66Track4Req(t, h, http.MethodGet, "/_connector/c_r66", "", nil)
	if cGetConn != http.StatusOK || mGetConn["last_seen"] == nil || mGetConn["features"].(map[string]any)["document_level_security"] == nil {
		t.Fatalf("expected last_seen and features stored on connector, got %d %s", cGetConn, rawGetConn)
	}

	// 3. connector.secret_post / secret_put / secret_get / secret_delete
	cSecPost, _, mSecPost, rawSecPost := doR66Track4Req(t, h, http.MethodPost, "/_connector/_secret", `{"value":"db-pass-1"}`, nil)
	if cSecPost != http.StatusCreated || mSecPost["id"] == nil || mSecPost["result"] != "created" {
		t.Fatalf("POST /_connector/_secret failed: %d %s", cSecPost, rawSecPost)
	}
	secID := mSecPost["id"].(string)

	cSecPutNew, _, mSecPutNew, rawSecPutNew := doR66Track4Req(t, h, http.MethodPut, "/_connector/_secret/sec_named", `{"value":"api-token-1"}`, nil)
	if cSecPutNew != http.StatusCreated || mSecPutNew["result"] != "created" {
		t.Fatalf("PUT /_connector/_secret/sec_named create failed: %d %s", cSecPutNew, rawSecPutNew)
	}
	cSecPutUpd, _, mSecPutUpd, rawSecPutUpd := doR66Track4Req(t, h, http.MethodPut, "/_connector/_secret/sec_named", `{"value":"api-token-2"}`, nil)
	if cSecPutUpd != http.StatusOK || mSecPutUpd["result"] != "updated" {
		t.Fatalf("PUT /_connector/_secret/sec_named update failed: %d %s", cSecPutUpd, rawSecPutUpd)
	}
	cSecGet, _, mSecGet, rawSecGet := doR66Track4Req(t, h, http.MethodGet, "/_connector/_secret/sec_named", "", nil)
	if cSecGet != http.StatusOK || mSecGet["value"] != nil || mSecGet["has_value"] != true || mSecGet["id"] != "sec_named" {
		t.Fatalf("GET /_connector/_secret/sec_named failed redaction check: %d %s", cSecGet, rawSecGet)
	}
	if cHead, _, _, _ := doR66Track4Req(t, h, http.MethodHead, "/_connector/_secret/"+secID, "", nil); cHead != http.StatusOK {
		t.Fatalf("HEAD /_connector/_secret/%s expected 200, got %d", secID, cHead)
	}

	// Ensure internal secret store never leaks into connector listing/lookup/sync_job
	cList, _, mList, rawList := doR66Track4Req(t, h, http.MethodGet, "/_connector", "", nil)
	if cList != http.StatusOK || strings.Contains(rawList, connectorSecretsStoreKeyR66) || len(mList["results"].([]any)) != 2 {
		t.Fatalf("connector list leaked secret store or wrong count: %d %s", cList, rawList)
	}
	if cHide, _, _, _ := doR66Track4Req(t, h, http.MethodGet, "/_connector/"+connectorSecretsStoreKeyR66, "", nil); cHide != http.StatusNotFound {
		t.Fatalf("expected 404 accessing reserved secret store key as connector, got %d", cHide)
	}
	if cHideSJ, _, _, _ := doR66Track4Req(t, h, http.MethodPost, "/_connector/_sync_job", `{"connector_id":"`+connectorSecretsStoreKeyR66+`"}`, nil); cHideSJ != http.StatusNotFound {
		t.Fatalf("expected 404 creating sync_job on reserved key, got %d", cHideSJ)
	}

	cSecDel, _, mSecDel, rawSecDel := doR66Track4Req(t, h, http.MethodDelete, "/_connector/_secret/sec_named", "", nil)
	if cSecDel != http.StatusOK || mSecDel["result"] != "deleted" {
		t.Fatalf("DELETE /_connector/_secret/sec_named failed: %d %s", cSecDel, rawSecDel)
	}
	if cSecGone, _, _, _ := doR66Track4Req(t, h, http.MethodGet, "/_connector/_secret/sec_named", "", nil); cSecGone != http.StatusNotFound {
		t.Fatalf("expected 404 after secret delete, got %d", cSecGone)
	}

	// 4. POST /_features/_reset wipes both connectors and connector secrets
	cReset, _, _, rawReset := doR66Track4Req(t, h, http.MethodPost, "/_features/_reset", "", nil)
	if cReset != http.StatusOK {
		t.Fatalf("POST /_features/_reset failed: %d %s", cReset, rawReset)
	}
	if cAfterReset, _, _, _ := doR66Track4Req(t, h, http.MethodGet, "/_connector/_secret/"+secID, "", nil); cAfterReset != http.StatusNotFound {
		t.Fatalf("expected 404 for secret after _features/_reset, got %d", cAfterReset)
	}
}
