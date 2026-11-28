package proxy

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestRound66CovFeatures_IngestProcessorsSimulateAndEnrich(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// Seed source index for enrich policy.
	mustR66CovHTTP(t, h, http.MethodPut, "/enrich_users", `{
		"mappings": {"properties": {"user_id": {"type": "keyword"}, "role": {"type": "keyword"}, "tier": {"type": "integer"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/enrich_users/_doc/u1?refresh=true", `{"user_id":"alice","role":"admin","tier":1}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/enrich_users/_doc/u2?refresh=true", `{"user_id":"bob","role":"viewer","tier":2}`, http.StatusCreated)

	// Enrich policy lifecycle + execute + stats.
	mustR66CovHTTP(t, h, http.MethodPut, "/_enrich/policy/users_match_policy", `{
		"match": {"indices": "enrich_users", "match_field": "user_id", "enrich_fields": ["role", "tier"]}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_enrich/policy/users_match_policy/_execute", "", http.StatusOK)

	st, _, statsResp, _ := doR66CovHTTP(t, h, http.MethodGet, "/_enrich/_stats", "", nil)
	if st != http.StatusOK || statsResp["executing_policies"] == nil {
		t.Fatalf("enrich stats unexpected: status=%d resp=%v", st, statsResp)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/_enrich/policy/users_match_*", "", http.StatusOK)

	// Range enrich policy.
	mustR66CovHTTP(t, h, http.MethodPut, "/enrich_ranges", `{
		"mappings": {"properties": {"net": {"type": "ip_range"}, "zone": {"type": "keyword"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/enrich_ranges/_doc/r1?refresh=true", `{"net":{"gte":"10.0.0.1","lte":"10.0.0.255"},"zone":"internal"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/_enrich/policy/range_policy", `{
		"range": {"indices": "enrich_ranges", "match_field": "net", "enrich_fields": ["zone"]}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_enrich/policy/range_policy/_execute", "", http.StatusOK)

	// Create comprehensive ingest pipeline exercising diverse processors.
	pipeBody := `{
		"version": 1,
		"description": "r66 full processor coverage",
		"processors": [
			{"set": {"field": "ingest_ts", "value": "{{_ingest.timestamp}}"}},
			{"set": {"field": "tag_copy", "copy_from": "raw_tag", "override": false}},
			{"copy": {"field": "raw_tag", "target_field": "copied_tag"}},
			{"copy": {"field": "raw_tag", "target_field": "copied_tag", "override": false}},
			{"lowercase": {"field": "mixed_tags"}},
			{"uppercase": {"field": "loud_word"}},
			{"trim": {"field": "padded_arr"}},
			{"gsub": {"field": "slug_src", "pattern": "[^a-z0-9]+", "replacement": "-"}},
			{"split": {"field": "csv_line", "separator": ",", "preserve_trailing": true}},
			{"convert": {"field": "str_nums", "type": "integer", "target_field": "int_nums"}},
			{"append": {"field": "arr_out", "value": ["x", "{{raw_tag}}"], "allow_duplicates": false}},
			{"json": {"field": "json_payload", "target_field": "parsed_obj", "strict_json_parsing": true, "allow_duplicate_keys": false}},
			{"json": {"field": "root_json", "add_to_root": true, "add_to_root_conflict_strategy": "merge"}},
			{"kv": {"field": "qs", "target_field": "qs_map", "field_split": "&", "value_split": "=", "include_keys": ["KeepMe", "Env"], "strip_brackets": true, "transform_key": "lowercase", "trim_key": " ", "trim_value": " "}},
			{"remove": {"field": ["drop_a", "tmp_secret"]}},
			{"enrich": {"policy_name": "users_match_policy", "field": "uid", "target_field": "user_meta", "max_matches": 1}},
			{"script": {"lang": "painless", "source": "ctx.scripted = ctx.uid + '-ok'"}}
		],
		"on_failure": [{"set": {"field": "ingest_err", "value": "{{_ingest.on_failure_message}}"}}]
	}`
	putResp := mustR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/p_cov_1", pipeBody, http.StatusOK)
	if ack, _ := putResp["acknowledged"].(bool); !ack {
		t.Fatalf("expected put pipeline ack, got %v", putResp)
	}

	// Update with matching if_version=1 to version=2, then fail on mismatch if_version=99.
	pipeBodyV2 := strings.Replace(pipeBody, `"version": 1`, `"version": 2`, 1)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/p_cov_1?if_version=1", pipeBodyV2, http.StatusOK)
	pipeBodyV3 := strings.Replace(pipeBody, `"version": 1`, `"version": 3`, 1)
	st, _, _, _ = doR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/p_cov_1?if_version=99", pipeBodyV3, nil)
	if st != http.StatusConflict && st != http.StatusBadRequest {
		t.Fatalf("expected 409 or 400 on if_version mismatch, got %d", st)
	}

	getResp := mustR66CovHTTP(t, h, http.MethodGet, "/_ingest/pipeline/*?summary=true", "", http.StatusOK)
	if getResp["p_cov_1"] == nil {
		t.Fatalf("expected p_cov_1 in summary get, got %v", getResp)
	}

	// Simulate stored pipeline with verbose=true.
	simBody := `{
		"docs": [
			{"_index": "idx1", "_id": "1", "_source": {
				"uid": "alice",
				"raw_tag": "Alpha",
				"copied_tag": "existing",
				"mixed_tags": ["One", "TWO"],
				"loud_word": "hello",
				"padded_arr": ["  a  ", " b "],
				"slug_src": "hello world!",
				"csv_line": "a,b,",
				"str_nums": ["10", "20"],
				"arr_out": ["x"],
				"json_payload": "{\"nested\":true}",
				"root_json": "{\"merged_k\":42}",
				"qs": " KeepMe = [val1] & Env = prod & Ignored = 1 ",
				"drop_a": 1,
				"tmp_secret": "hide",
				"keep_this": "yes",
				"title": "doc1"
			}}
		]
	}`
	// Simulate stored pipeline with verbose=false and verbose=true.
	simPlain := mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/p_cov_1/_simulate", simBody, http.StatusOK)
	docsOut, _ := simPlain["docs"].([]any)
	if len(docsOut) != 1 {
		t.Fatalf("expected 1 simulated doc, got %v", simPlain)
	}
	doc0, _ := docsOut[0].(map[string]any)
	docWrap, _ := doc0["doc"].(map[string]any)
	src, _ := docWrap["_source"].(map[string]any)
	if src["loud_word"] != "HELLO" || src["slug_src"] != "hello-world-" || src["scripted"] != "alice-ok" {
		t.Fatalf("unexpected simulated _source fields: %v", src)
	}
	if _, stillHasTmp := src["tmp_secret"]; stillHasTmp {
		t.Fatalf("expected tmp_secret removed, got %v", src)
	}
	if um, _ := src["user_meta"].(map[string]any); um == nil || um["role"] != "admin" {
		t.Fatalf("expected enriched user_meta, got %v", src["user_meta"])
	}
	simVerbose := mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/p_cov_1/_simulate?verbose=true", simBody, http.StatusOK)
	if vDocs, _ := simVerbose["docs"].([]any); len(vDocs) != 1 {
		t.Fatalf("expected 1 verbose simulated doc, got %v", simVerbose)
	}
	// Exercise remove.keep separately.
	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"remove": {"keep": ["keep_*", "title"]}}]},
		"docs": [{"_source": {"keep_this": "yes", "title": "doc1", "drop_me": 1}}]
	}`, http.StatusOK)

	// Inline simulate validation error branches + remove keep-only + per-doc _pipeline.
	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"set": {"field": "k", "value": "v"}}]},
		"docs": [{"_source": {"a": 1}}]
	}`, http.StatusOK)

	for _, bad := range []string{``, `{}`, `{"docs":"bad"}`, `{"docs":[null]}`, `{"docs":[{"_source":{}}],"unknown":1}`} {
		st, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", bad, nil)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad simulate body %q, got %d", bad, st)
		}
	}

	// Simulate scalar ancestor conflict on copy processor triggers on_failure.
	failSim := mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [{"copy": {"field": "src", "target_field": "scalar.child"}}],
			"on_failure": [{"set": {"field": "caught", "value": true}}]
		},
		"docs": [{"_source": {"src": "v", "scalar": "not-an-object"}}]
	}`, http.StatusOK)
	if docs, _ := failSim["docs"].([]any); len(docs) != 1 {
		t.Fatalf("expected 1 doc on_failure, got %v", failSim)
	}

	// Cleanup pipelines and enrich policies.
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ingest/pipeline/p_cov_*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_enrich/policy/users_match_policy,range_policy", "", http.StatusOK)
}

func TestRound66CovFeatures_RolloverResolveExplainPainlessRankEvalAndDownsample(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// Cluster settings for remote cluster resolution (both nested and dotted).
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{
		"persistent": {
			"cluster": {"remote": {"remote_a": {"seeds": ["127.0.0.1:9300"]}}},
			"cluster.remote.remote_b.seeds": ["127.0.0.2:9300"]
		}
	}`, http.StatusOK)
	rcResp := mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/remote_a,remote_b,missing_c", "", http.StatusOK)
	if rcResp["remote_a"] == nil || rcResp["remote_b"] == nil {
		t.Fatalf("expected resolved remote clusters, got %v", rcResp)
	}

	// Setup alias + write index for _rollover.
	mustR66CovHTTP(t, h, http.MethodPut, "/logs_cov-000001", `{
		"aliases": {"logs_roll_alias": {"is_write_index": true}},
		"mappings": {"properties": {"msg": {"type": "text"}, "score": {"type": "integer"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_doc/1?refresh=true", `{"msg":"hello world","score":10}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_doc/2?refresh=true", `{"msg":"hello doris","score":20}`, http.StatusCreated)

	// Dry-run rollover with max_docs: 1 condition met.
	dryRoll := mustR66CovHTTP(t, h, http.MethodPost, "/logs_roll_alias/_rollover?dry_run=true", `{
		"conditions": {"max_docs": 1}
	}`, http.StatusOK)
	if dry, _ := dryRoll["dry_run"].(bool); !dry {
		t.Fatalf("expected dry_run=true, got %v", dryRoll)
	}
	conds, _ := dryRoll["conditions"].(map[string]any)
	if conds["[max_docs: 1]"] != true {
		t.Fatalf("expected max_docs condition met on dry_run, got %v", dryRoll)
	}

	// Real rollover to auto-incremented logs_cov-000002, then custom rollover with settings/mappings/aliases.
	realRoll := mustR66CovHTTP(t, h, http.MethodPost, "/logs_roll_alias/_rollover", `{"conditions": {"max_docs": 1}}`, http.StatusOK)
	if ro, _ := realRoll["rolled_over"].(bool); !ro || realRoll["new_index"] != "logs_cov-000002" {
		t.Fatalf("expected rolled_over=true and new_index logs_cov-000002, got %v", realRoll)
	}
	customRoll := mustR66CovHTTP(t, h, http.MethodPost, "/logs_roll_alias/_rollover/logs_cov_custom", `{
		"mappings": {"properties": {"extra": {"type": "keyword"}}}
	}`, http.StatusOK)
	if customRoll["new_index"] != "logs_cov_custom" {
		t.Fatalf("expected custom new_index, got %v", customRoll)
	}
	// Concrete index rollover rejected.
	st, _, _, _ := doR66CovHTTP(t, h, http.MethodPost, "/logs_cov_custom/_rollover", `{}`, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on concrete index rollover, got %d", st)
	}

	// _explain endpoint: function_score + script_score + min_score + post_filter + stored_fields + missing doc.
	expOK := mustR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_explain/1?_source_includes=msg", `{
		"query": {"function_score": {"query": {"match": {"msg": "hello"}}, "script_score": {"script": {"source": "doc['score'].value * 2"}}}},
		"post_filter": {"range": {"score": {"gte": 5}}},
		"min_score": 1,
		"stored_fields": ["_source"]
	}`, http.StatusOK)
	if matched, _ := expOK["matched"].(bool); !matched {
		t.Fatalf("expected matched=true on explain, got %v", expOK)
	}
	st, _, expMiss, _ := doR66CovHTTP(t, h, http.MethodGet, "/logs_cov-000001/_explain/999?q=msg:hello", "", nil)
	if (st != http.StatusOK && st != http.StatusNotFound) || expMiss["matched"] == true {
		t.Fatalf("unexpected missing explain response: status=%d body=%v", st, expMiss)
	}

	// Painless _execute across score, filter, ingest, update, field, painless_test contexts.
	pTest := mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "1 + 2 * 3"}
	}`, http.StatusOK)
	if pTest["result"] == nil {
		t.Fatalf("expected painless_test result, got %v", pTest)
	}
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "doc['score'].value + params.inc", "params": {"inc": 5}},
		"context": "score",
		"context_setup": {"index": "logs_cov-000001", "document": {"msg": "hi", "score": 10}, "query": {"match_all": {}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "doc['score'].value > 5"},
		"context": "filter",
		"context_setup": {"index": "logs_cov-000001", "document": {"score": 10}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "ctx.flag = true"},
		"context": "ingest",
		"context_setup": {"document": {"_source": {"a": 1}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "ctx._source.cnt = 9"},
		"context": "update",
		"context_setup": {"document": {"_source": {"cnt": 1}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "emit(doc['score'].value)"},
		"context": "field",
		"context_setup": {"index": "logs_cov-000001", "document": {"score": 10}}
	}`, http.StatusOK)

	// _rank_eval across metrics + inline template + errors.
	mustR66CovHTTP(t, h, http.MethodPut, "/_scripts/cov_search_tpl", `{"script":{"lang":"mustache","source":"{\"query\":{\"match\":{\"msg\":\"{{q}}\"}}}"}}`, http.StatusOK)
	for _, metricSpec := range []string{
		`{"precision":{"k":5}}`,
		`{"recall":{"k":5}}`,
		`{"mean_reciprocal_rank":{"k":5}}`,
		`{"dcg":{"k":5,"normalize":true}}`,
		`{"expected_reciprocal_rank":{"k":5,"maximum_relevance":3}}`,
	} {
		reResp := mustR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_rank_eval", `{
			"requests": [
				{"id": "q1", "request": {"query": {"match": {"msg": "hello"}}}, "ratings": [{"_index": "logs_cov-000001", "_id": "1", "rating": 2}]},
				{"id": "q2", "template_id": "cov_search_tpl", "params": {"q": "doris"}, "ratings": [{"_index": "logs_cov-000001", "_id": "2", "rating": 3}]}
			],
			"templates": [{"id": "inline_t", "template": {"lang": "mustache", "source": "{\"query\":{\"match_all\":{}}}"}}],
			"metric": `+metricSpec+`
		}`, http.StatusOK)
		if reResp["metric_score"] == nil {
			t.Fatalf("expected metric_score in rank_eval, got %v", reResp)
		}
	}
	st, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_rank_eval", `{
		"requests": [{"id": "bad", "request": {"aggs": {}}, "ratings": [{"_index": "logs_cov-000001", "_id": "1", "rating": 1}]}],
		"metric": {"precision": {"k": 5}}
	}`, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for aggs in rank_eval, got %d", st)
	}

	// _downsample on time_series index + validation failures.
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_metrics_src", `{
		"settings": {"index.mode": "time_series", "index.routing_path": ["host"]},
		"mappings": {"properties": {
			"@timestamp": {"type": "date"},
			"host": {"type": "keyword", "time_series_dimension": true},
			"cpu": {"type": "double", "time_series_metric": "gauge"}
		}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_src/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:10Z","host":"h1","cpu":0.4}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_src/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:40Z","host":"h1","cpu":0.8}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_src/_downsample/ts_metrics_1m", `{"fixed_interval":"1m"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_1m/_downsample/ts_metrics_5m", `{"fixed_interval":"5m"}`, http.StatusOK)
	// Invalid interval (not multiple / <= prev).
	st, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_1m/_downsample/ts_metrics_bad", `{"fixed_interval":"90s"}`, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-multiple downsample interval, got %d", st)
	}
	st, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/logs_cov-000001/_downsample/non_ts_dst", `{"fixed_interval":"1m"}`, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-time_series downsample, got %d", st)
	}

	// Cleanup indices created here.
	mustR66CovHTTP(t, h, http.MethodDelete, "/ts_metrics_*,logs_cov*", "", http.StatusOK)
}

func TestRound66CovFeatures_SecurityDataStreamAutoscalingMLESQLSQLAndEQL(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// Security API routes (isolated sub-server so creating dynamic users does not lock out later open-cluster feature routes).
	_, secH := newR66CovServer(t, "8.15.0")
	mustSec := func(method, path, body string, hdrs map[string]string, want int) map[string]any {
		t.Helper()
		st, _, resp, raw := doR66CovHTTP(t, secH, method, path, body, hdrs)
		if st != want {
			t.Fatalf("%s %s status=%d want=%d raw=%s", method, path, st, want, raw)
		}
		return resp
	}
	alicePW1Hdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pw1"))}
	alicePW2Hdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pw2"))}
	mustSec(http.MethodGet, "/_security/user", "", nil, http.StatusOK)
	mustSec(http.MethodPut, "/_security/user/alice", `{"password":"pw1","roles":["superuser"],"full_name":"Alice"}`, nil, http.StatusOK)
	mustSec(http.MethodPost, "/_security/user/alice/_disable", "", alicePW1Hdr, http.StatusOK)
	// While alice is disabled, alice cannot authenticate with Basic auth; re-enable using admin-free sub-request on another admin or verify 401 first.
	stDisabled, _, _, _ := doR66CovHTTP(t, secH, http.MethodGet, "/_security/user/alice", "", alicePW1Hdr)
	if stDisabled != http.StatusUnauthorized {
		t.Fatalf("expected 401 for disabled alice, got %d", stDisabled)
	}
	// Configure an admin user on a separate security check or re-enable via handleSecurityAPI / static admin is covered elsewhere; create secadmin cleanly for enable/password/keys.
	_, secH2 := newR66CovServer(t, "8.15.0")
	adminHdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("secadmin:adminpw"))}
	mustSec2 := func(method, path, body string, hdrs map[string]string, want int) map[string]any {
		t.Helper()
		st, _, resp, raw := doR66CovHTTP(t, secH2, method, path, body, hdrs)
		if st != want {
			t.Fatalf("%s %s status=%d want=%d raw=%s", method, path, st, want, raw)
		}
		return resp
	}
	mustSec2(http.MethodPut, "/_security/user/secadmin", `{"password":"adminpw","roles":["superuser"]}`, nil, http.StatusOK)
	mustSec2(http.MethodPut, "/_security/user/alice", `{"password":"pw1","roles":["superuser"],"full_name":"Alice"}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/user/alice/_disable", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/user/alice/_enable", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPut, "/_security/user/alice/_password", `{"password":"pw2"}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/user/alice/_clear_cache", "", alicePW2Hdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/user/_has_privileges", `{"cluster":["monitor"],"index":[{"names":["logs*"],"privileges":["read"]}]}`, alicePW2Hdr, http.StatusOK)

	mustSec2(http.MethodPut, "/_security/role/cov_role", `{"cluster":["all"]}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/role/cov_role", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPut, "/_security/role_mapping/cov_rm", `{"roles":["cov_role"],"rules":{"field":{"username":"alice"}}}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/role_mapping/cov_rm", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/role_mapping", "", adminHdr, http.StatusOK)

	mustSec2(http.MethodGet, "/_security/privilege/_builtin", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPut, "/_security/privilege", `{"app1":{"read":{"actions":["data:read/*"]}}}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/api_key", `{"name":"ak1","expiration":"1d"}`, alicePW2Hdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/api_key/_grant", `{"grant_type":"password","username":"alice","password":"pw2","api_key":{"name":"ak2"}}`, nil, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/api_key?name=ak1", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/service", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/service/elastic/kibana/credential/token/t1", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodGet, "/_security/service/elastic/kibana/credential", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodDelete, "/_security/service/elastic/kibana/credential/token/t1", "", adminHdr, http.StatusOK)
	mustSec2(http.MethodPost, "/_security/oauth2/token", `{"grant_type":"client_credentials"}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodDelete, "/_security/oauth2/token", `{"token":"dummy"}`, adminHdr, http.StatusOK)
	mustSec2(http.MethodDelete, "/_security/role/cov_role", "", adminHdr, http.StatusOK)

	// Autoscaling policy + capacity.
	mustR66CovHTTP(t, h, http.MethodPut, "/_autoscaling/policy/as_cov", `{"roles":["data_hot"],"deciders":{"fixed":{"storage":"10gb","memory":"4gb","processors":2,"nodes":1}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_autoscaling/policy/as_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodHead, "/_autoscaling/policy/as_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_autoscaling/capacity", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_autoscaling/policy/as_cov", "", http.StatusOK)

	// Data stream _modify & _promote.
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/ds_cov_tpl", `{"index_patterns":["ds_cov*"], "data_stream": {}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/ds_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ds_cov/_rollover", "", http.StatusOK)
	dsInfo := mustR66CovHTTP(t, h, http.MethodGet, "/_data_stream/ds_cov", "", http.StatusOK)
	dsArr, _ := dsInfo["data_streams"].([]any)
	dsObj0, _ := dsArr[0].(map[string]any)
	dsIdxList, _ := dsObj0["indices"].([]any)
	firstBacking, _ := dsIdxList[0].(map[string]any)["index_name"].(string)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{
		"actions": [{"remove_backing_index": {"data_stream": "ds_cov", "index": "`+firstBacking+`"}}]
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_promote/ds_cov", "", http.StatusOK)

	// SLM control actions.
	mustR66CovHTTP(t, h, http.MethodGet, "/_slm/status", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_slm/stop", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_slm/start", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_slm/stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_slm/_execute_retention", "", http.StatusOK)

	// Nodes stats & cluster state routes.
	mustR66CovHTTP(t, h, http.MethodGet, "/_nodes/stats/indices,jvm,os/search,indexing?human=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/state/metadata,routing_table/*?expand_wildcards=all", "", http.StatusOK)

	// ML anomaly detector sub-routes.
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/_validate", `{"analysis_config":{"detectors":[{"function":"count"}]}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", `{"function":"mean","field_name":"val"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/_estimate_model_memory", `{"analysis_config":{"detectors":[{"function":"count"}]}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/anomaly_detectors/ml_cov_job", `{
		"analysis_config": {"bucket_span": "15m", "detectors": [{"function": "count"}]},
		"data_description": {"time_field": "@timestamp"}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/_open", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/_data", "{\"@timestamp\":1700000000000,\"val\":1}\n", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/_forecast", `{"duration":"1h"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/results/buckets", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/results/overall_buckets", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/results/records", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/results/categories", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/results/influencers", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/model_snapshots/1/_update", `{"description":"kept","retain":true}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/ml_cov_job/model_snapshots/1/_upgrade/_stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ml/anomaly_detectors/ml_cov_job/_forecast/_all", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/_close", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/ml_cov_job/_reset?force=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ml/anomaly_detectors/ml_cov_job/_delete_expired_data", "", http.StatusOK)

	// Seed index for SQL, ES|QL, and EQL.
	mustR66CovHTTP(t, h, http.MethodPut, "/events_cov", `{
		"mappings": {"properties": {
			"@timestamp": {"type": "date"},
			"user": {"type": "keyword"},
			"event": {"type": "keyword"},
			"latency": {"type": "integer"},
			"opt_note": {"type": "keyword"}
		}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/events_cov/_doc/1?refresh=true", `{"@timestamp":"2026-01-01T00:00:01Z","user":"alice","event":"login","latency":12}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/events_cov/_doc/2?refresh=true", `{"@timestamp":"2026-01-01T00:00:10Z","user":"alice","event":"exec","latency":45}`, http.StatusCreated)

	// ES|QL queries: full pipeline + profile + drop_null_columns + columnar + formats.
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{
		"query": "FROM events_cov | WHERE latency > 10 | EVAL doubled = latency * 2 | STATS cnt = COUNT(*), max_lat = MAX(doubled) BY user | KEEP user, cnt, max_lat | RENAME user AS actor | SORT max_lat DESC NULLS FIRST | LIMIT 5",
		"drop_null_columns": true,
		"profile": true
	}`, http.StatusOK)
	st, _, _, rawCSV := doR66CovHTTP(t, h, http.MethodPost, "/_query?format=csv", `{"query":"FROM events_cov | KEEP user, event"}`, nil)
	if st != http.StatusOK || !strings.Contains(rawCSV, "alice") {
		t.Fatalf("unexpected ES|QL CSV response: status=%d body=%q", st, rawCSV)
	}
	doR66CovHTTP(t, h, http.MethodPost, "/_query?format=txt", `{"query":"FROM events_cov | STATS c = COUNT(*) | DROP c","columnar":true}`, nil)

	// SQL API: DESCRIBE, SHOW, SELECT, cursor pagination, formats.
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"DESCRIBE events_cov"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SHOW TABLES LIKE 'events%'"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SHOW COLUMNS IN events_cov"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SHOW FUNCTIONS LIKE '%SUB%'"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SELECT 1 + 1 AS two"}`, http.StatusOK)
	page1 := mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SELECT DISTINCT event, COUNT(*) AS cnt FROM events_cov WHERE latency >= 10 GROUP BY event HAVING COUNT(*) >= 1 ORDER BY event ASC LIMIT 5","fetch_size":1}`, http.StatusOK)
	if cur, ok := page1["cursor"].(string); ok && cur != "" {
		mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"cursor":"`+cur+`"}`, http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPost, "/_sql/close", `{"cursor":"`+cur+`"}`, http.StatusOK)
	}
	for _, fmtName := range []string{"txt", "csv", "tsv"} {
		st, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/_sql?format="+fmtName, `{"query":"SELECT user, latency FROM events_cov"}`, nil)
		if st != http.StatusOK {
			t.Fatalf("SQL format %s failed: %d", fmtName, st)
		}
	}

	// EQL Search API: sequence with maxspan, until, negative step, async get/delete.
	eqlResp := mustR66CovHTTP(t, h, http.MethodPost, "/events_cov/_eql/search", `{
		"query": "sequence by user with maxspan=5m [any where event == \"login\"] [any where event == \"exec\"] ![any where event == \"logout\"]",
		"keep_on_completion": true,
		"size": 10
	}`, http.StatusOK)
	if eqlID, _ := eqlResp["id"].(string); eqlID != "" {
		mustR66CovHTTP(t, h, http.MethodGet, "/_eql/search/"+eqlID, "", http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodDelete, "/_eql/search/"+eqlID, "", http.StatusOK)
	}

	// _async_search, _downgrade, _reindex.
	asyncResp := mustR66CovHTTP(t, h, http.MethodPost, "/events_cov/_async_search?wait_for_completion_timeout=5s&keep_on_completion=true", `{
		"query": {"match_all": {}},
		"aggs": {"users": {"terms": {"field": "user"}}}
	}`, http.StatusOK)
	if aID, _ := asyncResp["id"].(string); aID != "" {
		mustR66CovHTTP(t, h, http.MethodGet, "/_async_search/status/"+aID, "", http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodGet, "/_async_search/"+aID+"?typed_keys=true", "", http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodDelete, "/_async_search/"+aID, "", http.StatusOK)
	}
	mustR66CovHTTP(t, h, http.MethodPost, "/events_cov/_downgrade", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "events_cov", "size": 2, "sort": [{"latency": "desc"}]},
		"dest": {"index": "events_cov_reindexed"},
		"script": {"source": "ctx._source.reindexed = true"}
	}`, http.StatusOK)

	// Snapshot repository, SLM policy execution + retention, snapshot restore & mount.
	mustR66CovHTTP(t, h, http.MethodPut, "/_snapshot/cov_repo", `{"type":"fs","settings":{"location":"/tmp/cov_repo"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_snapshot/cov_repo", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_snapshot/cov_repo/_analyze?blob_count=2", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_slm/policy/slm_cov", `{
		"schedule": "0 30 1 * * ?",
		"name": "<cov-snap-{now/d}>",
		"repository": "cov_repo",
		"config": {"indices": ["events_cov"]},
		"retention": {"expire_after": "30d", "min_count": 1, "max_count": 5}
	}`, http.StatusOK)
	slmExec := mustR66CovHTTP(t, h, http.MethodPost, "/_slm/policy/slm_cov/_execute", "", http.StatusOK)
	if snapName, _ := slmExec["snapshot_name"].(string); snapName != "" {
		mustR66CovHTTP(t, h, http.MethodGet, "/_snapshot/cov_repo/"+snapName+"/_status", "", http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPost, "/_snapshot/cov_repo/"+snapName+"/_restore?wait_for_completion=true", `{
			"indices": "events_cov",
			"rename_pattern": "events_cov",
			"rename_replacement": "events_cov_restored",
			"ignore_index_settings": ["index.refresh_interval"]
		}`, http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPost, "/_snapshot/cov_repo/"+snapName+"/_mount", `{
			"index": "events_cov",
			"renamed_index": "events_cov_mounted"
		}`, http.StatusOK)
	}
	mustR66CovHTTP(t, h, http.MethodPost, "/_slm/_execute_retention", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_slm/stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_slm/policy/slm_cov", "", http.StatusOK)
}

func TestRound66CovFeatures_ParseOLE2Streams(t *testing.T) {
	// Invalid inputs first.
	if res := parseOLE2StreamsRound63(nil); len(res) != 0 {
		t.Fatalf("expected empty map for short input")
	}

	// Build minimal valid 512-byte-sector OLE2 container with:
	// sector 0 = FAT, sector 1 = Directory, sector 2 = MiniFAT, sector 3 = MiniStream root, sector 4 = WordDocument (>4096 or <4096)
	const secSize = 512
	raw := make([]byte, secSize*(1+6))
	// Header: secShift=9 (512B), miniShift=6 (64B)
	binary.LittleEndian.PutUint16(raw[30:32], 9)
	binary.LittleEndian.PutUint16(raw[32:34], 6)
	binary.LittleEndian.PutUint32(raw[48:52], 1)    // firstDirSec = 1
	binary.LittleEndian.PutUint32(raw[56:60], 4096) // miniCutoff = 4096
	binary.LittleEndian.PutUint32(raw[60:64], 2)    // firstMiniFATSec = 2
	// DIFAT[0] = 0 (sector 0 holds FAT); rest EOC
	binary.LittleEndian.PutUint32(raw[76:80], 0)
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(raw[76+i*4:80+i*4], 0xFFFFFFFF)
	}

	fatOff := secSize * 1 // sector 0
	for i := 0; i < 128; i++ {
		binary.LittleEndian.PutUint32(raw[fatOff+i*4:fatOff+i*4+4], 0xFFFFFFFE)
	}

	// MiniFAT at sector 2: entry 0 -> EOC
	miniFATOff := secSize * 3
	binary.LittleEndian.PutUint32(raw[miniFATOff:miniFATOff+4], 0xFFFFFFFE)

	// MiniStream at sector 3: "mini-summary"
	miniStreamOff := secSize * 4
	copy(raw[miniStreamOff:], []byte("mini-summary-info"))

	// Regular WordDocument sector 4 (64B repeated)
	wordOff := secSize * 5
	copy(raw[wordOff:], []byte("Hello WordDocument Stream"))

	// Directory at sector 1: entry 0 = Root Entry (type 5), entry 1 = WordDocument (type 2), entry 2 = \x05SummaryInformation (mini)
	dirOff := secSize * 2
	writeDirEntry := func(slot int, name string, objType byte, startSec uint32, sz uint32) {
		ent := raw[dirOff+slot*128 : dirOff+(slot+1)*128]
		enc := utf16.Encode([]rune(name))
		for k, ch := range enc {
			binary.LittleEndian.PutUint16(ent[k*2:k*2+2], ch)
		}
		binary.LittleEndian.PutUint16(ent[64:66], uint16((len(enc)+1)*2))
		ent[66] = objType
		binary.LittleEndian.PutUint32(ent[116:120], startSec)
		binary.LittleEndian.PutUint32(ent[120:124], sz)
	}
	writeDirEntry(0, "Root Entry", 5, 3, 64)
	writeDirEntry(1, "WordDocument", 2, 4, 25)
	// Force SummaryInformation into MiniStream (sz < 4096), set WordDocument big or mini?
	// Note: parseOLE2StreamsRound63 uses miniStream whenever sz < miniCutoff (4096) & miniFAT exists; let's test both paths by making WordDocument >= 4096 via chain or mini!
	// Wait: with sz=25 < 4096 both use mini, so make raw slightly larger? Even simpler: miniCutoff=16! Then sz=12 -> mini, sz=25 -> regular chain!
	binary.LittleEndian.PutUint32(raw[56:60], 16) // miniCutoff = 16
	writeDirEntry(1, "WordDocument", 2, 4, 25)
	writeDirEntry(2, "\x05SummaryInformation", 2, 0, 12)

	streams := parseOLE2StreamsRound63(raw)
	if string(streams["WordDocument"]) != "Hello WordDocument Stream" {
		t.Fatalf("unexpected WordDocument stream: %q", streams["WordDocument"])
	}
	if string(streams["\x05SummaryInformation"]) != "mini-summary" {
		t.Fatalf("unexpected SummaryInformation mini stream: %q", streams["\x05SummaryInformation"])
	}
}

func TestRound66CovFeatures_RemoteReindexIngestAndBounds(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.5")
	srv.SetRemoteReindexWhitelistForTest("conformance.local:*")

	// 1. Mock remote ES server via RoundTripper for executeRemoteReindexRound61
	remoteMux := http.NewServeMux()
	remoteMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_search/scroll" && r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{"succeeded":true}`))
		case r.URL.Path == "/remote_src/_search":
			_, _ = w.Write([]byte(`{
				"_scroll_id":"r66_scroll_1",
				"hits":{
					"total":{"value":3},
					"hits":[
						{"_index":"remote_src","_id":"r1","_version":2,"_source":{"tag":"keep","v":10}},
						{"_index":"remote_src","_id":"r2","_version":5,"_source":{"tag":"drop","v":20}},
						{"_index":"remote_src","_id":"r3","_version":3,"_source":{"tag":"del","v":30}}
					]
				}
			}`))
		case r.URL.Path == "/remote_err/_search":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"type":"parsing_exception","reason":"remote bad query"}}`))
		case r.URL.Path == "/_search/scroll":
			_, _ = w.Write([]byte(`{"_scroll_id":"r66_scroll_1","hits":{"hits":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"version":{"number":"8.15.0"}}`))
		}
	})
	srv.SetRemoteReindexTransport(r66RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		remoteMux.ServeHTTP(rec, req)
		return rec.Result(), nil
	}))
	const remoteHostURL = "http://conformance.local:9200"

	mustR66CovHTTP(t, h, http.MethodPut, "/local_rem_dest", `{"mappings":{"properties":{"tag":{"type":"keyword"},"v":{"type":"long"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/local_rem_dest/_doc/r1?refresh=true", `{"tag":"existing","v":1}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/local_rem_dest/_doc/r3?refresh=true", `{"tag":"to_delete","v":3}`, http.StatusCreated)

	// Remote reindex with script (noop/delete/update), op_type=create + conflicts=proceed
	remRes := mustR66CovHTTP(t, h, http.MethodPost, "/_reindex?refresh=true", fmt.Sprintf(`{
		"conflicts":"proceed",
		"source":{"remote":{"host":%q},"index":"remote_src","size":10},
		"dest":{"index":"local_rem_dest","op_type":"create"},
		"script":{"source":"if (ctx._source.tag == 'del') { ctx.op = 'delete'; } else if (ctx._source.tag == 'drop') { ctx.op = 'noop'; }"}
	}`, remoteHostURL), http.StatusOK)
	if remRes["deleted"] == nil || remRes["version_conflicts"] == nil {
		t.Fatalf("unexpected remote reindex response: %v", remRes)
	}
	// Remote error propagation
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", fmt.Sprintf(`{
		"source":{"remote":{"host":%q},"index":"remote_err"},
		"dest":{"index":"local_rem_dest"}
	}`, remoteHostURL), http.StatusBadRequest)

	// 2. Bounded ingest template depth/size error & writeBoundedIngestTemplateValueR66 types
	deepMap := map[string]any{"x": "end"}
	for i := 0; i < 70; i++ {
		deepMap = map[string]any{"n": deepMap}
	}
	if _, err := estimateJSONMarshalBytesBoundedR66(deepMap, 0, 1024); err == nil {
		t.Fatal("expected depth limit error in estimateJSONMarshalBytesBoundedR66")
	}
	if _, err := estimateJSONMarshalBytesBoundedR66(strings.Repeat("a", 500), 0, 100); err == nil {
		t.Fatal("expected size limit error in estimateJSONMarshalBytesBoundedR66")
	}
	var sb strings.Builder
	budget := 1000
	if err := writeBoundedIngestTemplateValueR66(&sb, map[string]any{"a": []string{"x", "y"}, "b": []any{1, true}}, 0, &budget); err != nil {
		t.Fatalf("writeBoundedIngestTemplateValueR66 failed: %v", err)
	}
	smallBudget := 3
	if err := writeBoundedIngestTemplateValueR66(&sb, map[string]any{"k": "longval"}, 0, &smallBudget); err == nil {
		t.Fatal("expected budget error in writeBoundedIngestTemplateValueR66")
	}

	// 3. Ingest processors uncovered paths (copy_from, default, rename, copy, urldecode, user_agent partial os_*, script metadata mutation, OOXML docx attachment)
	var docxBuf bytes.Buffer
	zw := zip.NewWriter(&docxBuf)
	f1, _ := zw.Create("word/document.xml")
	_, _ = f1.Write([]byte(`<w:document><w:body><w:p><w:r><w:t>Hello Docx World</w:t></w:r></w:p></w:body></w:document>`))
	f2, _ := zw.Create("docProps/core.xml")
	_, _ = f2.Write([]byte(`<cp:coreProperties><dc:title>TestTitle</dc:title><dc:creator>Alice</dc:creator></cp:coreProperties>`))
	_ = zw.Close()
	docxB64 := base64.StdEncoding.EncodeToString(docxBuf.Bytes())

	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", fmt.Sprintf(`{
		"pipeline":{
			"processors":[
				{"set":{"field":"copied","copy_from":"orig","override":false}},
				{"default":{"field":"def_f","value":"defaulted"}},
				{"rename":{"field":"ren_src","target_field":"ren_dst"}},
				{"copy":{"field":"ren_dst","target_field":"cp_dst"}},
				{"urldecode":{"field":"uarr"}},
				{"user_agent":{"field":"ua","target_field":"ua_out","properties":["os_name","os_major","os_minor"]}},
				{"attachment":{"field":"bin","target_field":"att"}},
				{"script":{"source":"ctx._version = 5; ctx._version_type = 'external';"}}
			]
		},
		"docs":[
			{"_index":"i","_id":"1","_source":{"orig":"v1","ren_src":"rv","uarr":["hello%%20world","a+b"],"ua":"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36","bin":%q}}
		]
	}`, docxB64), http.StatusOK)

	// Ingest processor error cases (compile-time 400 vs per-doc runtime 200 error)
	for _, tc := range []struct {
		proc   string
		status int
	}{
		{`{"rename":{"field":"a","target_field":"a"}}`, http.StatusBadRequest},
		{`{"copy":{"field":"a","target_field":"a"}}`, http.StatusBadRequest},
		{`{"rename":{"field":"b","target_field":"a.sub"}}`, http.StatusOK},
		{`{"json":{"field":"arr_json","add_to_root":true}}`, http.StatusOK},
		{`{"urlencode":{"field":"num"}}`, http.StatusOK},
	} {
		sim := mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", fmt.Sprintf(`{
			"pipeline":{"processors":[%s]},
			"docs":[{"_index":"i","_id":"1","_source":{"a":"scalar","b":"v","arr_json":"[1,2]","num":123}}]
		}`, tc.proc), tc.status)
		if tc.status == http.StatusOK {
			docsArr, _ := sim["docs"].([]any)
			if len(docsArr) == 0 {
				t.Fatalf("expected error doc entry for %s: %v", tc.proc, sim)
			}
		}
	}
}

func TestRound66CovFeatures_AdminRoutesDataStreamTransformMLSecurity(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.5")

	// 1. Data stream + rollover + _data_stream/_modify (remove backing & failure_store index + errors)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/r66_mod_ds_tpl", `{
		"index_patterns":["r66-mod-*"],
		"data_stream":{"failure_store":{"enabled":true}},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/r66-mod-logs", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66-mod-logs/_rollover", "", http.StatusOK)
	dsInfo := mustR66CovHTTP(t, h, http.MethodGet, "/_data_stream/r66-mod-logs", "", http.StatusOK)
	var oldBacking string
	if streams, ok := dsInfo["data_streams"].([]any); ok && len(streams) > 0 {
		if dsObj, ok := streams[0].(map[string]any); ok {
			if idxs, ok := dsObj["indices"].([]any); ok && len(idxs) >= 2 {
				if first, ok := idxs[0].(map[string]any); ok {
					oldBacking, _ = first["index_name"].(string)
				}
			}
		}
	}
	if oldBacking != "" {
		mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", fmt.Sprintf(`{"actions":[{"remove_backing_index":{"data_stream":"r66-mod-logs","index":%q}}]}`, oldBacking), http.StatusOK)
	}
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"","index":""}}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"missing_ds","index":"x"}}]}`, http.StatusNotFound)

	// 2. Remote cluster settings + /_resolve/cluster/*
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"cluster.remote.rc1.seeds":["127.0.0.1:9300"],"cluster.remote.rc1.skip_unavailable":true,"cluster":{"remote":{"rc2":{"connected":false,"skip_unavailable":"true"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/(local):r66-*,rc*:logs,missing_idx?ignore_unavailable=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/unconfigured:foo", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/missing_idx", "", http.StatusOK)

	// 3. Query Rules CRUD + _test
	mustR66CovHTTP(t, h, http.MethodPut, "/_query_rules/qr_cov", `{
		"rules":[{"rule_id":"rule1","type":"pinned","criteria":[{"type":"exact","metadata":"q","values":["doris"]}],"actions":{"ids":["doc1"]}}]
	}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodHead, "/_query_rules/qr_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_query_rules/qr_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query_rules/qr_cov/_test", `{"match_criteria":{"q":"doris"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_query_rules/qr_cov", "", http.StatusOK)

	// 4. Transform validation & lifecycle
	for _, badTF := range []string{
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"BAD/Name"},"pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"frequency":"10ms","pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"frequency":"2h","pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*","runtime_mappings":{"x":{"type":"weird_rt"}}},"dest":{"index":"tf_out"},"pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"pivot":{"max_page_search_size":2,"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"a":{"value_count":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"pivot":{"group_by":{"a":{"terms":{"field":"a"}}},"aggregations":{"c":{"unknown_agg":{"field":"a"}}}}}`,
		`{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"latest":{"unique_key":[""],"sort":"@timestamp"}}`,
	} {
		st, _, _, _ := doR66CovHTTP(t, h, http.MethodPut, "/_transform/tf_bad", badTF, nil)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad transform %s, got %d", badTF, st)
		}
	}
	mustR66CovHTTP(t, h, http.MethodPut, "/_transform/tf_ok", `{"source":{"index":"r66-mod-*"},"dest":{"index":"tf_out"},"latest":{"unique_key":["_id"],"sort":"@timestamp"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_transform/tf_ok/_start", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_transform/tf_ok/_stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_transform/tf_ok/_schedule_now", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_transform/tf_ok/_stop?force=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_transform/tf_ok/_reset", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_transform/tf_ok", "", http.StatusOK)

	// 5. Security API extra endpoints: _query/api_key, _clear_api_key_cache, role_mappings wildcard/404, enroll, user profiles
	mustR66CovHTTP(t, h, http.MethodPost, "/_security/_query/api_key", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_security/_clear_api_key_cache", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_security/role", `{"roles":"not_a_map"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_security/role_mapping/missing_rm", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodHead, "/_security/role_mapping/missing_rm", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPost, "/_security/enroll/kibana", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_security/enroll/node", `{}`, http.StatusOK)
	profResp := mustR66CovHTTP(t, h, http.MethodPost, "/_security/profile/_activate", `{"grant":{"user":{"username":"elastic","roles":["superuser"]}}}`, http.StatusOK)
	if uid, _ := profResp["uid"].(string); uid != "" {
		mustR66CovHTTP(t, h, http.MethodGet, "/_security/profile/"+uid+",missing_uid", "", http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPut, "/_security/profile/"+uid+"/_data", `{"labels":{"team":"eng"},"data":{"pref":1}}`, http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPost, "/_security/profile/_has_privileges", `{"uids":[`+fmt.Sprintf("%q", uid)+`],"privileges":{"cluster":["all"]}}`, http.StatusOK)
		mustR66CovHTTP(t, h, http.MethodPost, "/_security/profile/_suggest", `{"name":"elastic"}`, http.StatusOK)
	}
	mustR66CovHTTP(t, h, http.MethodHead, "/_security/profile/missing_uid", "", http.StatusNotFound)

	// 6. ML info, memory, upgrade_mode, delete_expired_data, data_frame_analytics, model_aliases/definition/vocabulary
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/info", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/memory/_stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/set_upgrade_mode?enabled=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ml/_delete_expired_data", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/anomaly_detectors/no_job/model_snapshots/s1/_upgrade", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/anomaly_detectors/no_job/model_snapshots/s1/_upgrade", `{}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/data_frame/analytics/dfa_bad", `{"source":{}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/data_frame/analytics/dfa_bad", `{"source":{"index":"x"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/data_frame/analytics/dfa_bad", `{"source":{"index":"x"},"dest":{"index":"y"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/data_frame/analytics/dfa_ok", `{"source":{"index":"r66-mod-*"},"dest":{"index":"dfa_dest"},"analysis":{"outlier_detection":{}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/data_frame/analytics/dfa_*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/data_frame/analytics/missing_dfa", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ml/data_frame/analytics/dfa_ok", "", http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/trained_models/tm_cov", `{"input":{"field_names":["x"]},"definition":{"tree":{"feature_names":["x"],"target_type":"regression"}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/trained_models/tm_cov/model_aliases/tm_alias", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ml/trained_models/tm_cov/definition/0", `{"tree":{}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/trained_models/tm_cov/vocabulary", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_ml/trained_models/tm_cov/model_aliases/tm_alias", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/trained_models/tm_cov/deployment/_cache/_clear", "", http.StatusNotFound)

	// 7. Snapshot URL readonly + _clone + _termvectors + _nodes/stats?human=true + _text_structure + ES|QL/SQL errors
	srv.SetStaticRepositoriesURLAllowedURLs([]string{"http://localhost:9999/snaps"})
	mustR66CovHTTP(t, h, http.MethodPut, "/_snapshot/url_ro_repo", `{"type":"url","settings":{"url":"http://localhost:9999/snaps"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_snapshot/url_ro_repo/snap1", `{}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_snapshot/fs_cov_repo", `{"type":"fs","settings":{"location":"/tmp/fs_cov_repo"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_snapshot/fs_cov_repo/s1?wait_for_completion=true", `{"indices":"r66-mod-*"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_snapshot/fs_cov_repo/_all?verbose=false&index_names=false&include_repository=false", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_snapshot/fs_cov_repo/s1/_clone/s1_clone", `{"indices":"r66-mod-*"}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/tv_idx", `{"mappings":{"properties":{"msg":{"type":"text","term_vector":"with_positions_offsets"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/tv_idx/_doc/1?refresh=true", `{"msg":"hello term vectors world"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/tv_idx/_termvectors/1?realtime=false", `{"fields":["msg"],"positions":true,"offsets":true,"term_statistics":true,"field_statistics":true}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/tv_idx/_mtermvectors", `{"ids":["1","missing"],"fields":["msg"]}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodGet, "/_nodes/stats?human=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_text_structure/find_structure", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_text_structure/find_structure?lines_to_sample=2", "{\"ts\":\"2026-01-01T00:00:00Z\",\"level\":\"INFO\",\"msg\":\"ok\"}\n{\"ts\":\"2026-01-01T00:00:01Z\",\"level\":\"WARN\",\"msg\":\"hi\"}\n", http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM tv_idx | STATS c = COUNT_DISTINCT(_source)"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM tv_idx | STATS c = COUNT(nonexistent_col)"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"BADCMD tv_idx"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SHOW TABLES LIKE 123"}`, http.StatusBadRequest)
	_ = json.Marshal
}

type r66RoundTripFunc func(*http.Request) (*http.Response, error)

func (f r66RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRound66CovFeatures_DataStreamModifySynonymsSLMWatchLicenseMonitoringAndEQL(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	// 1. _data_stream/_modify remove_backing_index + failure_store errors + valid removal
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/ds_mod_tpl", `{"index_patterns":["ds-mod-*"],"data_stream":{}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/ds-mod-1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ds-mod-1/_rollover", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"","index":""}}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"no_ds","index":"idx"}}]}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"ds-mod-1","index":"not_member","failure_store":true}}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"ds-mod-1","index":".ds-ds-mod-1-2026.01.01-000001"}}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"ds-mod-1","index":"bad_idx"}}]}`, http.StatusBadRequest)

	// 2. _synonyms rule validation + multi-word match_phrase synonym rewrite inside bool
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/syn_cov_set", `{"synonyms_set":[{"id":"r1","synonyms":"quick brown, fast tan"},{"id":"r2","synonyms":"pc => laptop"}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/syn_cov_set/r1", `{"unknown":1}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/syn_cov_set/r1", `{"id":"wrong","synonyms":"a, b"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/syn_cov_set/r1", `{"synonyms":""}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/missing_set/r1", `{"synonyms":"a, b"}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/syn_idx", `{
		"settings":{"analysis":{"filter":{"my_syn":{"type":"synonym_graph","synonyms_set":"syn_cov_set"}},"analyzer":{"syn_an":{"type":"custom","tokenizer":"standard","filter":["lowercase","my_syn"]}}}},
		"mappings":{"properties":{"msg":{"type":"text","analyzer":"syn_an"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn_idx/_doc/1?refresh=true", `{"msg":"fast tan fox"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn_idx/_search", `{"query":{"bool":{"must":[{"match_phrase":{"msg":"quick brown fox"}},{"match":{"msg":"my pc"}}]}}}`, http.StatusOK)

	// 3. _slm/policy validation + _watcher/watch GET/HEAD/DELETE
	mustR66CovHTTP(t, h, http.MethodPut, "/_slm/policy/bad_slm", `{"schedule":""}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_slm/policy/bad_slm", `{"schedule":"0 30 1 * * ?","name":""}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_slm/policy/bad_slm", `{"schedule":"0 30 1 * * ?","name":"snap-name","repository":""}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_slm/policy/bad_slm", `{"schedule":"not_cron","name":"snap-name","repository":"r1"}`, http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodPut, "/_watcher/watch/w_cov", `{"trigger":{"schedule":{"interval":"5m"}},"input":{"simple":{"a":1}},"condition":{"always":{}},"actions":{"log":{"logging":{"text":"hi"}}}}`, http.StatusCreated)
	stWHead, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/_watcher/watch/w_cov", "", nil)
	if stWHead != http.StatusOK {
		t.Fatalf("expected 200 HEAD existing watch, got %d", stWHead)
	}
	stWMiss, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/_watcher/watch/no_watch", "", nil)
	if stWMiss != http.StatusNotFound {
		t.Fatalf("expected 404 HEAD missing watch, got %d", stWMiss)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/_watcher/watch/w_cov", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_watcher/watch/no_watch", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_watcher/watch/w_cov", "", http.StatusOK)

	// 4. _license validation, _monitoring/bulk ApiKey auth, _ml evaluate, _ilm/policy downsample validation, _resolve/cluster & remote settings
	mustR66CovHTTP(t, h, http.MethodPost, "/_license", `{}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_license", `{"license":{"type":"basic"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_license", `{"licenses":[{"type":"gold","uid":"u1","expiry_date_in_millis":4102444800000}]}`, http.StatusOK)

	monSrv, monH := newR66CovServer(t, "8.15.0")
	monSrv.SetAuth("elastic", "r66-mon", "")
	monAdminHdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:r66-mon"))}
	stAK, _, akResp, rawAK := doR66CovHTTP(t, monH, http.MethodPost, "/_security/api_key", `{"name":"mon_key","role_descriptors":{"bad_role":{"cluster":["monitor"]}}}`, monAdminHdr)
	if stAK != http.StatusOK {
		t.Fatalf("expected 200 creating mon_key, got %d %s", stAK, rawAK)
	}
	if id, _ := akResp["id"].(string); id != "" {
		secret, _ := akResp["api_key"].(string)
		tok := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
		stMon, _, _, _ := doR66CovHTTP(t, monH, http.MethodPost, "/_monitoring/bulk", "", map[string]string{"Authorization": "ApiKey " + tok})
		if stMon != http.StatusForbidden {
			t.Fatalf("expected 403 monitoring ApiKey lacking manage priv, got %d", stMon)
		}
	}
	stMonBad, _, _, _ := doR66CovHTTP(t, monH, http.MethodPost, "/_monitoring/bulk", "", map[string]string{"Authorization": "ApiKey bad_token"})
	if stMonBad != http.StatusUnauthorized {
		t.Fatalf("expected 401 bad ApiKey, got %d", stMonBad)
	}

	mustR66CovHTTP(t, h, http.MethodPut, "/ml_eval_src", `{"mappings":{"properties":{"actual":{"type":"keyword"},"pred":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ml_eval_src/_doc/1?refresh=true", `{"actual":"a","pred":"a"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ml/data_frame/_evaluate", `{"index":"ml_eval_src","evaluation":{"classification":{"actual_field":"actual","predicted_field":"pred"}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/data_frame/analytics/_stats", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_ml/data_frame/analytics/missing_dfa/_stats", "", http.StatusNotFound)

	mustR66CovHTTP(t, h, http.MethodPut, "/_ilm/policy/bad_ilm_ds", `{"policy":{"phases":{"warm":{"min_age":"1d","actions":{"downsample":"not_obj"}}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ilm/policy/bad_ilm_ds", `{"policy":{"phases":{"warm":{"min_age":"1d","actions":{"downsample":{}}}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ilm/policy/bad_ilm_ds", `{"policy":{"phases":{"warm":{"min_age":"1d","actions":{"downsample":{"fixed_interval":"bad"}}}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ilm/policy/bad_ilm_ds", `{"policy":{"phases":{"warm":{"min_age":"1d","actions":{"downsample":{"fixed_interval":"1d"}}},"cold":{"min_age":"2d","actions":{"downsample":{"fixed_interval":"1h"}}}}}}`, http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"cluster.remote.rc1":{"seeds":["127.0.0.1:9300"],"skip_unavailable":"true","connected":true}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"cluster.remote.rc1":{"seeds":null}}}`, http.StatusOK)

	// 5. _search/template stringified booleans + mustache render errors + ingest convert / date / painless_execute
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/cov_search_tpl", `{"script":{"lang":"mustache","source":"{\"_source\":\"false\",\"track_total_hits\":\"10\",\"profile\":\"true\",\"explain\":\"false\",\"query\":{\"match_all\":{}}}"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn_idx/_search/template", `{"id":"cov_search_tpl","params":{}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_render/template", `{"source":"{\"query\":{{unclosed","params":{}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline":{"processors":[
			{"convert":{"field":"f_int","type":"integer"}},
			{"convert":{"field":"f_flt","type":"float"}},
			{"convert":{"field":"f_str","type":"string"}},
			{"convert":{"field":"f_bool","type":"boolean"}},
			{"date":{"field":"d_ord","formats":["ordinal_date_time"]}},
			{"date":{"field":"d_rfc","formats":["rfc_1123_date_time"]}},
			{"network_direction":{"source_ip":"src_ip","destination_ip":"dst_ip","internal_networks":["10.0.0.0/8"]}}
		]},
		"docs":[{"_source":{"f_int":"42","f_flt":3,"f_str":99,"f_bool":"true","d_ord":"2026-002T15:04:05.000Z","d_rfc":"Fri, 2 Jan 2026 15:04:05 UTC","src_ip":"10.0.0.1","dst_ip":"8.8.8.8"}}]
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_scripts/painless/_execute", `{"script":{"source":"1 + params.v","params":{"v":2}}}`, http.StatusOK)

	// 6. _query ES|QL (triple quotes, FLOOR/CEIL/SQRT/MOD, multi-field .keyword, array comparison) & _eql/search sequence w/ absent & maxspan
	mustR66CovHTTP(t, h, http.MethodPut, "/esql_cov", `{"mappings":{"properties":{"msg":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"val":{"type":"double"},"tags":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_cov/_doc/1?refresh=true", `{"msg":"hi there","val":9.5,"tags":["a","b"]}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM esql_cov | EVAL s = \"\"\"raw \"str\"\"\"\", f = FLOOR(val), c = CEIL(val), sq = SQRT(val), m = MOD(10, 3) | WHERE tags == \"a\" AND val >= 1 | KEEP msg.keyword, s, f, c, sq, m"}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/eql_cov", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"category":{"type":"keyword"}}},"process":{"properties":{"pid":{"type":"long"},"name":{"type":"keyword"}}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_cov/_doc/e1?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","event":{"category":"process"},"process":{"pid":1,"name":"start"}}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_cov/_doc/e2?refresh=true", `{"@timestamp":"2026-01-01T00:00:02Z","event":{"category":"process"},"process":{"pid":1,"name":"stop"}}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_cov/_doc/e3?refresh=true", `{"@timestamp":"2026-01-01T00:00:03Z","event":{"category":"file"},"process":{"pid":1,"name":"done"}}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_cov/_eql/search", `{"query":"sequence by process.pid with maxspan=1m [process where process.name == \"start\"] ![process where process.name == \"stop\"]"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_cov/_eql/search", `{"query":"sequence by process.pid with maxspan=1m [process where process.name == \"start\"] [file where true] until [process where process.name == \"stop\"]"}`, http.StatusOK)

	// 7. persistFSSnapshotsDiskPayloadR65 + _nodes/stats?level=indices&human=true + parseTermsEnumDLSMinShouldMatchR65
	tmpDir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil && resolved != "" {
		tmpDir = resolved
	}
	persistFSSnapshotsDiskPayloadR65(map[string]any{"type": "fs", "settings": map[string]any{"location": tmpDir}}, []byte(`{"snapshots":[]}`), []string{tmpDir})
	if _, err := os.Stat(filepath.Join(tmpDir, proxySnapshotCatalogFileR64)); err != nil {
		t.Fatalf("expected persisted snapshot catalog: %v", err)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/_nodes/stats/indices?level=indices&human=true", "", http.StatusOK)
	for _, r := range []any{1, int64(2), json.Number("3"), "2", ""} {
		_, _ = parseTermsEnumDLSMinShouldMatchR65(r, 4)
	}
	_ = srv
}

func TestRound66CovFeatures_DSBackingAddRemoveSynonymExpandResolveAndCatTasks(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	// 1. round49_features.go handleModifyDataStream direct coverage + HTTP _data_stream/_modify add_backing_index / remove_backing_index
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/ds_m2_tpl", `{"index_patterns":["ds-m2-*"],"data_stream":{}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/ds-m2-1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ds-m2-1/_rollover", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/ds_extra_bk", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	callModifyDirect := func(body string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/_data_stream/_modify", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handleModifyDataStream(rec, req)
		if rec.Code != want {
			t.Fatalf("direct handleModifyDataStream %s: expected %d, got %d body=%s", body, want, rec.Code, rec.Body.String())
		}
	}
	callModifyDirect(`{"actions":[{"add_backing_index":{"data_stream":"","index":""}}]}`, http.StatusBadRequest)
	callModifyDirect(`{"actions":[{"add_backing_index":{"data_stream":"no_ds","index":"ds_extra_bk"}}]}`, http.StatusNotFound)
	callModifyDirect(`{"actions":[{"add_backing_index":{"data_stream":"ds-m2-1","index":"missing_idx"}}]}`, http.StatusNotFound)
	callModifyDirect(`{"actions":[{"add_backing_index":{"data_stream":"ds-m2-1","index":"ds_extra_bk"}}]}`, http.StatusOK)
	callModifyDirect(`{"actions":[{"add_backing_index":{"data_stream":"ds-m2-1","index":"ds_extra_bk"}}]}`, http.StatusBadRequest)
	callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"","index":""}}]}`, http.StatusBadRequest)
	callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"no_ds","index":"ds_extra_bk"}}]}`, http.StatusNotFound)
	callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"ds-m2-1","index":"not_member","failure_store":true}}]}`, http.StatusBadRequest)
	callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"ds-m2-1","index":"not_member"}}]}`, http.StatusBadRequest)
	callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"ds-m2-1","index":"ds_extra_bk"}}]}`, http.StatusOK)

	// Enable failure_store via _data_stream/_modify, create .fs-* index, then test direct removeFromFailureStore branches
	mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"data_stream_options":{"data_stream":"ds-m2-1","failure_store":{"enabled":true}}}]}`, http.StatusOK)
	fsDocResp := mustR66CovHTTP(t, h, http.MethodPost, "/ds-m2-1/_doc?refresh=true", `{"msg":"no_ts_goes_fs"}`, http.StatusCreated)
	fsIdxName, _ := fsDocResp["_index"].(string)
	if fsIdxName != "" {
		callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"ds-m2-1","index":"`+fsIdxName+`","failure_store":true}}]}`, http.StatusBadRequest)
		mustR66CovHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"data_stream_options":{"data_stream":"ds-m2-1","failure_store":{"enabled":false}}}]}`, http.StatusOK)
		callModifyDirect(`{"actions":[{"remove_backing_index":{"data_stream":"ds-m2-1","index":"`+fsIdxName+`"}}]}`, http.StatusOK)
	}

	// 2. Synonyms expansion with multi-word & match_phrase single-word rewrite inside bool
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/syn2_set", `{"synonyms_set":[{"id":"r1","synonyms":"quick brown, fast tan"},{"id":"r2","synonyms":"fox, hound"},{"id":"r3","synonyms":"pc => laptop"}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/syn2_idx", `{
		"settings":{"analysis":{"filter":{"my_syn2":{"type":"synonym_graph","synonyms_set":"syn2_set"}},"analyzer":{"syn2_an":{"type":"custom","tokenizer":"standard","filter":["lowercase","my_syn2"]}}}},
		"mappings":{"properties":{"msg":{"type":"text","analyzer":"syn2_an"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_doc/1?refresh=true", `{"msg":"fast tan hound on laptop"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_search", `{
		"query":{"bool":{"must":[
			{"match":{"msg":{"query":"pc","analyzer":"syn2_an"}}},
			{"match_phrase":{"msg":"quick brown"}},
			{"match_phrase":{"msg":{"query":"brown fox"}}}
		]}}
	}`, http.StatusOK)

	// 3. _cluster/settings nested remote clusters + _resolve/cluster query param validation & expansion
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"cluster":{"remote":{"rc_nested":{"seeds":["127.0.0.1:9300"],"skip_unavailable":true,"connected":true}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/*?ignore_throttled=true&ignore_unavailable=true&allow_no_indices=true&expand_wildcards=open,closed", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/*?ignore_throttled=bad", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_resolve/cluster/*?expand_wildcards=bogus", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"cluster":{"remote":{"rc_nested":{"seeds":null}}}}}`, http.StatusOK)

	// 4. _cat/tasks params & errors + _rollup/_search?typed_keys=true + _analyze phonetic double_metaphone
	mustR66CovHTTP(t, h, http.MethodGet, "/_cat/tasks?format=json&full_id=true&time=ms&detailed=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cat/tasks?time=bad_unit", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_cat/tasks", "", http.StatusMethodNotAllowed)

	mustR66CovHTTP(t, h, http.MethodPost, "/_analyze", `{
		"tokenizer":"standard",
		"filter":[{"type":"phonetic","encoder":"double_metaphone","max_code_len":6}],
		"text":"write where what box bordeaux pizza the van knight"
	}`, http.StatusOK)

	// 5. Direct expandSearchBodySynonymsRound61, handleIndexTemplate (/component_template), /_doris/explain, /_sql scalar funcs, /_search/template?source=, community_id, _snapshot restore pipelines/aliases
	synBody := []byte(`{"query":{"bool":{"must":[{"match":{"msg":{"query":"pc","analyzer":"syn2_an"}}},{"match_phrase":{"msg":"quick brown"}},{"match_phrase":{"msg":{"query":"brown fox"}}}]}}}`)
	if expOut := expandSearchBodySynonymsRound61(srv, []string{"syn2_idx"}, synBody); len(expOut) == len(synBody) {
		t.Fatalf("expected expandSearchBodySynonymsRound61 to expand query: %s", string(expOut))
	}

	// Direct handleIndexTemplate for component_template GET/DELETE/404/405
	mustR66CovHTTP(t, h, http.MethodPut, "/_component_template/direct_ct_1", `{"template":{"mappings":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusOK)
	for _, tc := range []struct {
		m, u, p string
		want    int
	}{
		{http.MethodGet, "/_component_template/direct_ct_*", "", http.StatusOK},
		{http.MethodGet, "/_component_template/missing_ct", "missing_ct", http.StatusNotFound},
		{http.MethodDelete, "/_component_template/direct_ct_1", "direct_ct_1", http.StatusOK},
		{http.MethodPatch, "/_component_template/direct_ct_1", "direct_ct_1", http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(tc.m, tc.u, nil)
		req.SetPathValue("name", tc.p)
		rec := httptest.NewRecorder()
		srv.handleIndexTemplate(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("direct handleIndexTemplate %s %s: expected %d got %d", tc.m, tc.u, tc.want, rec.Code)
		}
	}

	// _doris/explain error branches + indices_boost object deprecation on ES7
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_doris/explain", `{"from":-1}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_doris/explain", `{"collapse":{"field":"msg","collapse":{"field":"msg"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_doris/explain", `{"aggs":{"mad":{"median_absolute_deviation":{"field":"x","execution_hint":"bad"}}}}`, http.StatusBadRequest)
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/v7_exp", `{"mappings":{"properties":{"a":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodPost, "/v7_exp/_doris/explain", `{"indices_boost":{"v7_exp":1.5},"query":{"match_all":{}}}`, http.StatusOK)

	// _sql scalar functions (TRIM, LTRIM, RTRIM, COALESCE, IFNULL, FLOOR, CEIL, SQRT, MOD)
	mustR66CovHTTP(t, h, http.MethodPost, "/_sql", `{"query":"SELECT TRIM(' x '), LTRIM(' x'), RTRIM('x '), COALESCE(NULL, 1), IFNULL(NULL, 2), FLOOR(2.9), CEIL(2.1), SQRT(9), MOD(10, 3) FROM syn2_idx"}`, http.StatusOK)

	// _search/template ?source= param + invalid rendered JSON + typed_keys body propagation + _analyze mapped field
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_search/template?source=%7B%22source%22%3A%7B%22query%22%3A%7B%22match_all%22%3A%7B%7D%7D%7D%2C%22params%22%3A%7B%7D%7D&source_content_type=application/json", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_search/template", `{"source":"{\"query\":{{bad}}}","params":{"bad":"{invalid"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_search/template", `{"source":"{\"query\":{\"match_all\":{}},\"aggs\":{\"t\":{\"terms\":{\"field\":\"msg\"}}}}","params":{},"typed_keys":true}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn2_idx/_analyze", `{"field":"msg","text":"laptop"}`, http.StatusOK)

	// _ingest community_id processor with icmp_type/icmp_code & invalid port/type + invalid seed 400
	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline":{"processors":[{"community_id":{"icmp_type":"icmp.type","icmp_code":"icmp.code","transport":"network.transport","ignore_failure":true}}]},
		"docs":[
			{"_source":{"source":{"ip":"192.168.1.1"},"destination":{"ip":"192.168.1.2"},"network":{"transport":"icmp"},"icmp":{"type":8,"code":0}}},
			{"_source":{"source":{"ip":"192.168.1.1"},"destination":{"ip":"192.168.1.2"},"network":{"transport":"icmp"},"icmp":{"type":999,"code":0}}}
		]
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline":{"processors":[{"community_id":{"seed":70000}}]},
		"docs":[{"_source":{"source":{"ip":"192.168.1.1"},"destination":{"ip":"192.168.1.2"}}}]
	}`, http.StatusBadRequest)
}

func TestRound66CovFeatures_ReindexModesEQLRawStringsESQLMetadataEnrichAndFieldCaps(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// 1. handleReindex targets: new data stream (requires op_type=create), write alias, closed index, write-blocked index
	mustR66CovHTTP(t, h, http.MethodPut, "/re_src_b6", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/re_src_b6/_doc/1?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","msg":"hello"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/re_ds_b6_tpl", `{"index_patterns":["re_ds_b6*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src_b6"},"dest":{"index":"re_ds_b6_1"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex?refresh=true", `{"source":{"index":"re_src_b6"},"dest":{"index":"re_ds_b6_1","op_type":"create"}}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/re_alias_b6_backing", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"re_alias_b6_backing","alias":"re_write_b6","is_write_index":true}}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex?refresh=true", `{"source":{"index":"re_src_b6"},"dest":{"index":"re_write_b6"}}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/re_closed_b6", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/re_closed_b6/_close", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src_b6"},"dest":{"index":"re_closed_b6"}}`, http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodPut, "/re_ro_b6", `{"settings":{"index.blocks.write":true}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src_b6"},"dest":{"index":"re_ro_b6"}}`, http.StatusForbidden)

	// 2. tokenizeEQL raw triple-quoted strings, doubled quote/escape chars, and unclosed raw literal error
	mustR66CovHTTP(t, h, http.MethodPut, "/eql_str_b6", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"event.category":{"type":"keyword"},"message":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_str_b6/_doc/1?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","event":{"category":"process"},"message":"raw"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_str_b6/_eql/search", `{"query":"any where message == \"\"\"raw\"\"\""}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_str_b6/_eql/search", `{"query":"any where message == 'a''b\\n\\t\\r\\z'"}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/eql_str_b6/_eql/search", `{"query":"any where message == \"\"\"unclosed"}`, http.StatusBadRequest)

	// 3. ESQL METADATA _id,_index,_source,_ignored + multi-field + ENRICH multi-doc match
	mustR66CovHTTP(t, h, http.MethodPut, "/esql_meta_b6", `{"mappings":{"properties":{"title":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"cnt":{"type":"integer","ignore_malformed":true}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_meta_b6/_doc/1?refresh=true", `{"title":"abc","cnt":"bad_num"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM esql_meta_b6 METADATA _id, _index, _source, _ignored | LIMIT 5"}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/esql_enr_src", `{"mappings":{"properties":{"k":{"type":"keyword"},"val":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_enr_src/_doc/1?refresh=true", `{"k":"K1","val":"v1"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_enr_src/_doc/2?refresh=true", `{"k":"K1","val":"v2"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/_enrich/policy/esql_multi_b6", `{"match":{"indices":"esql_enr_src","match_field":"k","enrich_fields":["val"]}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_enrich/policy/esql_multi_b6/_execute", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/esql_events_b6", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_events_b6/_doc/1?refresh=true", `{"k":"K1"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_events_b6/_doc/2?refresh=true", `{"k":"MISSING"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM esql_events_b6 | ENRICH esql_multi_b6 ON k WITH val | LIMIT 5"}`, http.StatusOK)

	// 4. buildNodesStatsIndicesSectionRound61 searchGroups + handleFieldCapsRound61 (search_as_you_type, dynamic text, bigint time, double, boolean)
	mustR66CovHTTP(t, h, http.MethodPost, "/esql_meta_b6/_search?stats=grp1", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_search?stats=grp_all", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_nodes/stats/indices?groups=*", "", http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/fc_b6", `{"mappings":{"dynamic":true,"properties":{"sayt":{"type":"search_as_you_type"},"createdAt":{"type":"long"},"dval":{"type":"double"},"bval":{"type":"boolean"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_b6/_doc/1?refresh=true", `{"sayt":"quick fox","createdAt":1700000000,"dval":1.5,"bval":true,"dyn_txt":"hello world"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_b6/_field_caps?fields=*", "", http.StatusOK)
}

func TestRound66CovFeatures_SimulateIndexTemplateConnectorClaimAndHeadMappingTypes(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// 1. handleSimulateIndexTemplateIndex (`POST /_index_template/_simulate_index/{name}`)
	mustR66CovHTTP(t, h, http.MethodPut, "/_component_template/sim_comp_b7", `{"template":{"mappings":{"properties":{"a":{"type":"keyword"}}},"settings":{"number_of_shards":1}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/sim_tpl_b7", `{"index_patterns":["sim_b7_*"],"composed_of":["sim_comp_b7"],"priority":50,"template":{"mappings":{"properties":{"b":{"type":"long"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_index_template/_simulate_index/sim_b7_1", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodPost, "/_index_template/_simulate_index/sim_b7_1", `{invalid`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_index_template/_simulate_index/sim_b7_1", `{"index_patterns":["sim_b7_*"],"composed_of":["missing_ct"]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_index_template/_simulate_index/sim_b7_1?ignore_missing_component_template=true", `{"index_patterns":["sim_b7_*"],"composed_of":["missing_ct","sim_comp_b7"],"priority":99}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_index_template/_simulate_index/sim_b7_1", `{}`, http.StatusOK)

	// 2. handleConnectorSyncJobClaimRound57 (`POST /_connector/_sync_job/_claim` & `/{id}/_claim`)
	mustR66CovHTTP(t, h, http.MethodGet, "/_connector/_sync_job/_claim", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodPost, "/_connector/_sync_job/missing_job/_claim", `{}`, http.StatusNotFound)
	connResp := mustR66CovHTTP(t, h, http.MethodPost, "/_connector", `{"name":"conn_b7","index_name":"conn_idx_b7","service_type":"postgresql"}`, http.StatusCreated)
	connID, _ := connResp["id"].(string)
	if connID != "" {
		mustR66CovHTTP(t, h, http.MethodPost, "/_connector/_sync_job", `{"connector_id":"`+connID+`","job_type":"full"}`, http.StatusCreated)
		mustR66CovHTTP(t, h, http.MethodPost, "/_connector/_sync_job/_claim", `{"connector_id":"`+connID+`","job_types":["full"],"worker_hostname":"w1"}`, http.StatusOK)
		job2Resp := mustR66CovHTTP(t, h, http.MethodPost, "/_connector/_sync_job", `{"connector_id":"`+connID+`","job_type":"incremental"}`, http.StatusCreated)
		if j2ID, _ := job2Resp["id"].(string); j2ID != "" {
			mustR66CovHTTP(t, h, http.MethodPost, "/_connector/_sync_job/"+j2ID+"/_claim", `{"worker_hostname":"w2"}`, http.StatusOK)
		}
	}

	// 3. HEAD /{idx} + _mapping?include_type_name=true (handleHeadIndex / wrapMappingsResponseForTypeR61CRUD)
	mustR66CovHTTP(t, h, http.MethodPut, "/head_cov_b7", `{"mappings":{"properties":{"f":{"type":"keyword"}}}}`, http.StatusOK)
	stFound, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/head_cov_b7", "", nil)
	if stFound != http.StatusOK {
		t.Fatalf("expected 200 HEAD /head_cov_b7, got %d", stFound)
	}
	stMiss, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/missing_head_b7", "", nil)
	if stMiss != http.StatusNotFound {
		t.Fatalf("expected 404 HEAD /missing_head_b7, got %d", stMiss)
	}
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/v7_typed_b7?include_type_name=true", `{"mappings":{"_doc":{"properties":{"f":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/v7_typed_b7/_mapping/_doc?include_type_name=true", "", http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/v7_typed_b7/_mapping/_all?include_type_name=true", "", http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/v7_typed_b7/_mapping/other_t?include_type_name=true", "", http.StatusNotFound)
}
