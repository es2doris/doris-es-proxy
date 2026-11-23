package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRound64_WireLicenseFeatureUsageAndRepositoryURL(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. F0: GET/HEAD /_license/feature_usage
	rec := doRound63Req(t, h, http.MethodHead, "/_license/feature_usage", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("expected HEAD /_license/feature_usage 200 empty body, got %d %q", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_license/feature_usage", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected GET /_license/feature_usage 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var featResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &featResp); err != nil {
		t.Fatalf("invalid JSON from /_license/feature_usage: %v", err)
	}
	if feats, ok := featResp["features"].(map[string]any); !ok || len(feats) != 0 {
		t.Fatalf("expected empty features map, got %#v", featResp)
	}

	// 2. F0: nodes.info includes repository-url module & retriever_rrf is not flagged unsupported
	if unsupportedEndpointCapabilitiesR61Admin["retriever_rrf"] {
		t.Fatal("expected retriever_rrf removed from unsupportedEndpointCapabilitiesR61Admin")
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_nodes", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"repository-url"`) {
		t.Fatalf("expected nodes.info to advertise repository-url module, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. F0: repository-fs -> disk _proxy_snapshots.json -> repository-url (http:// & file://) read-only restore + error paths
	fsDir := t.TempDir()
	httpFS := httptest.NewServer(http.FileServer(http.Dir(fsDir)))
	defer httpFS.Close()

	filePrefix := "file:///" + strings.TrimPrefix(filepath.ToSlash(fsDir), "/") + "/"
	settingsPayload := fmt.Sprintf(`{"persistent":{"path.repo":[%q],"repositories.url.allowed_urls":["http://127.0.0.1:*",%q]}}`, filepath.ToSlash(fsDir), filePrefix+"*")
	rec = doRound63Req(t, h, http.MethodPut, "/_cluster/settings", []byte(settingsPayload), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put cluster settings failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRound63Req(t, h, http.MethodPut, "/_snapshot/r_fs", []byte(fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, fsDir)), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create r_fs failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/url_docs", []byte(`{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/url_docs/_doc/1?refresh=true", []byte(`{"tag":"snap-v1"}`), nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("index doc failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/_snapshot/r_fs/snap_one?wait_for_completion=true", []byte(`{"indices":"url_docs","include_global_state":false}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot create failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRound63Req(t, h, http.MethodPut, "/_snapshot/r_http", []byte(fmt.Sprintf(`{"type":"url","settings":{"url":%q}}`, httpFS.URL+"/")), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create r_http failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/_snapshot/r_file", []byte(fmt.Sprintf(`{"type":"url","settings":{"url":"file://%s/"}}`, fsDir)), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create r_file failed: %d %s", rec.Code, rec.Body.String())
	}

	for _, repo := range []string{"r_http", "r_file"} {
		rec = doRound63Req(t, h, http.MethodGet, "/_snapshot/"+repo+"/snap_one", nil, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"SUCCESS"`) {
			t.Fatalf("GET snapshot from %s failed: %d %s", repo, rec.Code, rec.Body.String())
		}
		// Delete index then restore from URL repo
		_ = doRound63Req(t, h, http.MethodDelete, "/url_docs", nil, nil)
		rec = doRound63Req(t, h, http.MethodPost, "/_snapshot/"+repo+"/snap_one/_restore?wait_for_completion=true", []byte(`{}`), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("restore from %s failed: %d %s", repo, rec.Code, rec.Body.String())
		}
		rec = doRound63Req(t, h, http.MethodGet, "/url_docs/_count", nil, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
			t.Fatalf("expected restored doc count=1 from %s, got %d %s", repo, rec.Code, rec.Body.String())
		}
		// F15: files.recovered == 1 after snapshot restore
		rec = doRound63Req(t, h, http.MethodGet, "/url_docs/_recovery", nil, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"recovered":1`) {
			t.Fatalf("expected files.recovered==1 after restore from %s, got %d %s", repo, rec.Code, rec.Body.String())
		}
		// Readonly error on existing snapshot delete (ES8 & ES7)
		rec = doRound63Req(t, h, http.MethodDelete, "/_snapshot/"+repo+"/snap_one", nil, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "repository is readonly") {
			t.Fatalf("expected 400 repository is readonly on ES8 delete from %s, got %d %s", repo, rec.Code, rec.Body.String())
		}
		// Missing snapshot get/delete -> snapshot_missing_exception; missing restore -> snapshot_restore_exception
		rec = doRound63Req(t, h, http.MethodDelete, "/_snapshot/"+repo+"/missing", nil, nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "snapshot_missing_exception") {
			t.Fatalf("expected 404 snapshot_missing_exception on %s delete missing, got %d %s", repo, rec.Code, rec.Body.String())
		}
		rec = doRound63Req(t, h, http.MethodPost, "/_snapshot/"+repo+"/missing/_restore?wait_for_completion=true", []byte(`{}`), nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "snapshot_restore_exception") {
			t.Fatalf("expected 404 snapshot_restore_exception on %s restore missing, got %d %s", repo, rec.Code, rec.Body.String())
		}
	}

	// Verify ES7 readonly wording when TargetESVersion is 7.10.2
	srv.SetTargetESVersion("7.10.2")
	rec = doRound63Req(t, h, http.MethodDelete, "/_snapshot/r_http/snap_one", nil, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cannot delete snapshot from a readonly repository") {
		t.Fatalf("expected ES7 readonly message on delete, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestRound64_WireProfilerAnalyzeFieldCapsAndFielddata(t *testing.T) {
	// 1. ES7 dense profiler & /_analyze unicodeSetFilter warning
	srv7, h7 := newRound60MemoryServer(t, "7.10.2")
	_ = srv7
	rec := doRound63Req(t, h7, http.MethodPut, "/prof_idx", []byte(`{"mappings":{"properties":{"k":{"type":"keyword"}}}}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create prof_idx failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h7, http.MethodPost, "/prof_idx/_doc/1?refresh=true", []byte(`{"k":"v1"}`), nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("index prof_idx doc failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h7, http.MethodPost, "/prof_idx/_search", []byte(`{"profile":true,"size":0,"aggs":{"t":{"terms":{"field":"k"}}}}`), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dense"`) {
		t.Fatalf("expected ES7 terms profiler collection_strategy=dense, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. F18: unicodeSetFilter deprecation warning on /_analyze
	rec = doRound63Req(t, h7, http.MethodPost, "/_analyze", []byte(`{"tokenizer":"standard","filter":[{"type":"icu_normalizer","unicodeSetFilter":"[a-z]"}],"text":"Hello"}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/_analyze failed: %d %s", rec.Code, rec.Body.String())
	}
	if warns := strings.Join(rec.Header().Values("Warning"), " | "); !strings.Contains(warns, "[unicodeSetFilter] has been deprecated in favor of [unicode_set_filter]") {
		t.Fatalf("expected unicodeSetFilter Warning header, got %v", rec.Header().Values("Warning"))
	}

	// 3. F5/F15/F16: field_caps metric_conflicts_indices + MatchNone + fielddata stats exclusion
	_, h8 := newRound61AdminTestServer(t, "8.15.5")
	_ = doRound63Req(t, h8, http.MethodPut, "/ts_metric_idx", []byte(`{
		"settings":{"index":{"mode":"time_series","routing_path":["metricset"],"time_series":{"start_time":"2021-04-28T00:00:00Z","end_time":"2021-04-29T00:00:00Z"}}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"metricset":{"type":"keyword","time_series_dimension":true},"metric":{"type":"double","time_series_metric":"gauge"},"body_txt":{"type":"text"}}}
	}`), nil)
	_ = doRound63Req(t, h8, http.MethodPut, "/std_metric_idx", []byte(`{
		"mappings":{"properties":{"@timestamp":{"type":"date"},"metricset":{"type":"keyword","time_series_dimension":true},"metric":{"type":"double","time_series_metric":"gauge"}}}
	}`), nil)

	rec = doRound63Req(t, h8, http.MethodGet, "/ts_metric_idx,std_metric_idx/_field_caps?fields=metric", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("field_caps failed: %d %s", rec.Code, rec.Body.String())
	}
	var fc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &fc)
	metricDouble := fc["fields"].(map[string]any)["metric"].(map[string]any)["double"].(map[string]any)
	if metricDouble["metric_conflicts_indices"] == nil || metricDouble["time_series_metric"] != nil {
		t.Fatalf("expected metric_conflicts_indices present and time_series_metric absent, got %#v", metricDouble)
	}

	// MatchNone index_filter preserves empty {} instead of 400 parsing_exception
	rec = doRound63Req(t, h8, http.MethodPost, "/ts_metric_idx/_field_caps?fields=metric", []byte(`{"index_filter":{"bool":{"filter":[{"match_none":{}}]}}}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("field_caps with match_none index_filter failed: %d %s", rec.Code, rec.Body.String())
	}

	// Plain text field without fielddata=true should report 0 fielddata memory
	_ = doRound63Req(t, h8, http.MethodPost, "/ts_metric_idx/_doc/1?refresh=true", []byte(`{"@timestamp":"2021-04-28T12:00:00Z","metricset":"m1","metric":1.5,"body_txt":"plain text"}`), nil)
	rec = doRound63Req(t, h8, http.MethodGet, "/ts_metric_idx/_stats/fielddata?fields=*", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("_stats/fielddata failed: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"body_txt"`) {
		t.Fatalf("expected plain text field without fielddata:true omitted from fielddata stats, got %s", rec.Body.String())
	}
}

func TestRound64_WireDataStreamsAsyncEnrichESQLTermsEnum(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")
	_ = srv

	// 1. Data stream expansion across _reload_search_analyzers, _rollup/data, _graph/explore & failure_store removal
	rec := doRound63Req(t, h, http.MethodPut, "/_index_template/r64_ds_tpl", []byte(`{
		"index_patterns":["logs-r64-*"],
		"data_stream":{},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ds template failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/_data_stream/logs-r64-app", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create ds failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, ep := range []struct{ method, path, body string }{
		{http.MethodPost, "/logs-r64-app/_reload_search_analyzers", ``},
		{http.MethodGet, "/logs-r64-app/_rollup/data", ``},
		{http.MethodPost, "/logs-r64-app/_graph/explore", `{"query":{"match_all":{}}}`},
	} {
		rec = doRound63Req(t, h, ep.method, ep.path, []byte(ep.body), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s against data stream failed: %d %s", ep.method, ep.path, rec.Code, rec.Body.String())
		}
	}

	// Non-active failure store backing index can be removed cleanly
	srv.mu.Lock()
	dsObj := srv.dataStreams["logs-r64-app"]
	dsObj["failure_store"] = map[string]any{
		"enabled": true,
		"indices": []any{
			map[string]any{"index_name": ".fs-logs-r64-app-2026.01.01-000001"},
			map[string]any{"index_name": ".fs-logs-r64-app-2026.01.02-000002"},
		},
	}
	dsSnap := deepCloneDocMap(dsObj)
	srv.mu.Unlock()
	srv.persistDataStream(context.Background(), "logs-r64-app", dsSnap)
	rec = doRound63Req(t, h, http.MethodPost, "/_data_stream/_modify", []byte(`{
		"actions":[{"remove_backing_index":{"data_stream":"logs-r64-app","index":".fs-logs-r64-app-2026.01.01-000001","failure_store":true}}]
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove non-active .fs backing index failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/_data_stream/_modify", []byte(`{
		"actions":[{"remove_backing_index":{"data_stream":"logs-r64-app","index":".fs-logs-r64-app-2026.01.02-000002","failure_store":true}}]
	}`), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when removing active .fs write index, got %d %s", rec.Code, rec.Body.String())
	}

	// 2. Enrich coordinator_stats & elasticsearch_version deprecation warning
	rec = doRound63Req(t, h, http.MethodPut, "/enr_src", []byte(`{"mappings":{"properties":{"k":{"type":"keyword"}}}}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create enr_src failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/_enrich/policy/p_ver", []byte(`{
		"match":{"indices":"enr_src","match_field":"k","enrich_fields":["k"]},
		"elasticsearch_version":"8.15.5"
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put enrich policy with elasticsearch_version failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Warning"), " "), "elasticsearch_version") {
		t.Fatalf("expected elasticsearch_version deprecation warning, got %v", rec.Header().Values("Warning"))
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_enrich/_stats", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"coordinator_stats"`) || !strings.Contains(rec.Body.String(), `"executed_searches_total"`) {
		t.Fatalf("expected enrich coordinator_stats with executed_searches_total, got %d %s", rec.Code, rec.Body.String())
	}

	// 3. AsyncSearch deprecated query + multi-index _shards.total
	_ = doRound63Req(t, h, http.MethodPut, "/as_1", []byte(`{"settings":{"number_of_shards":2,"number_of_replicas":0}}`), nil)
	_ = doRound63Req(t, h, http.MethodPut, "/as_2", []byte(`{"settings":{"number_of_shards":3,"number_of_replicas":0}}`), nil)
	_ = doRound63Req(t, h, http.MethodPost, "/as_1/_doc/1?refresh=true", []byte(`{"x":1}`), nil)
	rec = doRound63Req(t, h, http.MethodPost, "/as_*/_async_search?keep_on_completion=true&wait_for_completion_timeout=10s", []byte(`{"query":{"deprecated":{}}}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("async_search submit failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Warning"), " "), "[deprecated] query") {
		t.Fatalf("expected [deprecated] query warning on submit, got %v", rec.Header().Values("Warning"))
	}
	var asResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &asResp)
	asID, _ := asResp["id"].(string)
	rec = doRound63Req(t, h, http.MethodGet, "/_async_search/"+asID, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(strings.Join(rec.Header().Values("Warning"), " "), "[deprecated] query") {
		t.Fatalf("expected [deprecated] query replayed on async_search.get, got %d hdrs=%v", rec.Code, rec.Header().Values("Warning"))
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_async_search/status/"+asID, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total":5`) {
		t.Fatalf("expected summed multi-index _shards.total=5 in async_search.status, got %d %s", rec.Code, rec.Body.String())
	}

	// 4. ESQL live telemetry in /_xpack/usage (16 features + 3 queries buckets)
	rec = doRound63Req(t, h, http.MethodGet, "/_xpack/usage", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /_xpack/usage failed: %d %s", rec.Code, rec.Body.String())
	}
	var xpBefore map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &xpBefore)
	esqlBefore := xpBefore["esql"].(map[string]any)
	if len(esqlBefore["features"].(map[string]any)) != 16 || len(esqlBefore["queries"].(map[string]any)) != 3 {
		t.Fatalf("expected 16 esql features and 3 esql queries keys, got %#v", esqlBefore)
	}
	rec = doRound63Req(t, h, http.MethodPost, "/_query", []byte(`{"query":"FROM as_1 | WHERE x > 0 | LIMIT 1"}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /_query failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_xpack/usage", nil, nil)
	var xpAfter map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &xpAfter)
	featsAfter := xpAfter["esql"].(map[string]any)["features"].(map[string]any)
	if featsAfter["from"].(float64) < 1 || featsAfter["where"].(float64) < 1 || featsAfter["limit"].(float64) < 1 {
		t.Fatalf("expected live incremented ESQL feature counts, got %#v", featsAfter)
	}

	// 5. F9 C36: terms_enum DLS API key owner binding (Basic Auth owner preserved)
	_ = doRound63Req(t, h, http.MethodPut, "/dls_idx", []byte(`{"mappings":{"properties":{"secret":{"type":"keyword"}}}}`), nil)
	_ = doRound63Req(t, h, http.MethodPost, "/dls_idx/_doc/1?refresh=true", []byte(`{"secret":"top"}`), nil)
	_ = doRound63Req(t, h, http.MethodPost, "/_security/role/dls_r", []byte(`{"indices":[{"names":["dls_idx"],"privileges":["read"],"query":{"term":{"secret":"other"}}}]}`), nil)
	_ = doRound63Req(t, h, http.MethodPost, "/_security/user/bob", []byte(`{"password":"secret","roles":["dls_r"]}`), nil)
	basicHdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:secret"))}
	rec = doRound63Req(t, h, http.MethodPost, "/_security/api_key", []byte(`{"name":"bob_key"}`), basicHdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("create api_key failed: %d %s", rec.Code, rec.Body.String())
	}
	var keyResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &keyResp)
	encodedKey, _ := keyResp["encoded"].(string)
	rec = doRound63Req(t, h, http.MethodPost, "/dls_idx/_terms_enum", []byte(`{"field":"secret","string":"t"}`), map[string]string{"Authorization": "ApiKey " + encodedKey})
	if rec.Code != http.StatusOK {
		t.Fatalf("terms_enum with DLS ApiKey failed: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"top"`) {
		t.Fatalf("expected DLS-restricted API key to suppress terms_enum terms, got %s", rec.Body.String())
	}
}

func TestRound64_WireIngestGeoGridRerouteGrokAndMustacheCaps(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. geo_grid processor pipeline creation + simulate + doc ingest
	rec := doRound63Req(t, h, http.MethodPut, "/_ingest/pipeline/p_geogrid", []byte(`{
		"processors":[{"geo_grid":{"field":"tile","target_field":"pt","tile_type":"geotile"}}]
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put geo_grid pipeline failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/_ingest/pipeline/p_geogrid/_simulate", []byte(`{
		"docs":[{"_source":{"tile":"4/8/5"}}]
	}`), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pt"`) {
		t.Fatalf("simulate geo_grid failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. F9 C34: reroute destination default_pipeline re-resolution across chained destination
	rec = doRound63Req(t, h, http.MethodPut, "/_ingest/pipeline/p_reroute_a", []byte(`{
		"processors":[{"reroute":{"destination":"reroute_dest_b"}}]
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put p_reroute_a failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPut, "/_ingest/pipeline/p_tag_b", []byte(`{
		"processors":[{"set":{"field":"tagged_by_b","value":true}}]
	}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put p_tag_b failed: %d %s", rec.Code, rec.Body.String())
	}
	_ = doRound63Req(t, h, http.MethodPut, "/reroute_src_a", []byte(`{"settings":{"index.default_pipeline":"_none"}}`), nil)
	_ = doRound63Req(t, h, http.MethodPut, "/reroute_dest_b", []byte(`{"settings":{"index.default_pipeline":"p_tag_b"}}`), nil)
	rec = doRound63Req(t, h, http.MethodPost, "/reroute_src_a/_doc/1?pipeline=p_reroute_a&refresh=true", []byte(`{"msg":"hi"}`), nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("reroute doc ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodGet, "/reroute_dest_b/_doc/1", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tagged_by_b":true`) {
		t.Fatalf("expected destination default_pipeline p_tag_b to run after reroute, got %d %s", rec.Code, rec.Body.String())
	}

	// 3. F23: Grok cumulative 64KiB expansion cap + cycle rejection
	hugeDefs := map[string]any{
		"A": strings.Repeat("x", 1024),
		"B": strings.Repeat("%{A}", 70),
	}
	if _, _, _, err := compileGrokRegex("%{B}", hugeDefs); err == nil {
		t.Fatal("expected compileGrokRegex error for >64KiB expanded regex")
	}
	if _, err := compileIngestJavaRegex(strings.Repeat("a", maxExpandedGrokRegexLen+1)); err == nil {
		t.Fatal("expected compileIngestJavaRegex error for >64KiB pattern")
	}

	// 4. F23: Mustache nesting depth=32 and output=4MiB caps
	deepTpl := strings.Repeat("{{#x}}", 34) + "{{v}}" + strings.Repeat("{{/x}}", 34)
	if _, err := renderMustacheSearchTemplate(deepTpl, map[string]any{"x": true, "v": "ok"}); err == nil {
		t.Fatal("expected renderMustacheSearchTemplate error when nesting exceeds depth 32")
	}
	bigList := make([]string, 5000)
	for i := range bigList {
		bigList[i] = strings.Repeat("z", 1024)
	}
	if _, err := renderMustacheSearchTemplate(`{{#l}}{{.}}{{/l}}`, map[string]any{"l": bigList}); err == nil {
		t.Fatal("expected renderMustacheSearchTemplate error when output exceeds 4MiB")
	}

	// 5. F15: ES7 vs ES8 Mustache EOF wording
	_, h7 := newRound60MemoryServer(t, "7.10.2")
	rec = doRound63Req(t, h7, http.MethodPost, "/_render/template", []byte(`{"source":"{\"query\":"}`), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "json_e_o_f_exception") || !strings.Contains(rec.Body.String(), "Unexpected end-of-input") {
		t.Fatalf("expected ES7 json_e_o_f_exception + Unexpected end-of-input, got %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/_render/template", []byte(`{"source":"{\"query\":"}`), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "x_content_e_o_f_exception") || !strings.Contains(rec.Body.String(), "Unexpected end of file") {
		t.Fatalf("expected ES8 x_content_e_o_f_exception + Unexpected end of file, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestRound64_WireProtocolDeflateYAMLCSVOpenSearchAndBoundedContexts(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. Raw RFC-1951 deflate even when CMF/FLG happens to satisfy %31==0
	var rawFlate bytes.Buffer
	fw, _ := flate.NewWriter(&rawFlate, flate.DefaultCompression)
	_, _ = fw.Write([]byte(`{"query":{"match_all":{}}}`))
	_ = fw.Close()
	rawBytes := rawFlate.Bytes()
	req := httptest.NewRequest(http.MethodPost, "/_search", bytes.NewReader(rawBytes))
	req.Header.Set("Content-Encoding", "deflate")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	cleanup, ok := decompressRequestBodyR63Wire(rec, req, 4096)
	if !ok {
		t.Fatalf("expected raw RFC-1951 deflate to succeed, got %d %s", rec.Code, rec.Body.String())
	}
	gotBody, _ := io.ReadAll(req.Body)
	cleanup()
	if string(gotBody) != `{"query":{"match_all":{}}}` || req.ContentLength != -1 {
		t.Fatalf("unexpected raw deflate decode body=%q ContentLength=%d", string(gotBody), req.ContentLength)
	}

	// Corrupt zlib -> 400
	var zlBuf bytes.Buffer
	zw := zlib.NewWriter(&zlBuf)
	_, _ = zw.Write([]byte(`{"a":1}`))
	_ = zw.Close()
	corruptZL := append([]byte(nil), zlBuf.Bytes()...)
	corruptZL[len(corruptZL)-1] ^= 0xff
	reqBad := httptest.NewRequest(http.MethodPost, "/_search", bytes.NewReader(corruptZL))
	reqBad.Header.Add("Content-Encoding", "identity")
	reqBad.Header.Add("Content-Encoding", "deflate")
	recBad := httptest.NewRecorder()
	if cl, okBad := decompressRequestBodyR63Wire(recBad, reqBad, 4096); okBad || recBad.Code != http.StatusBadRequest {
		if cl != nil {
			cl()
		}
		t.Fatalf("expected 400 on corrupt deflate with multi Content-Encoding headers, got ok=%v code=%d", okBad, recBad.Code)
	}

	// 2. P2-2: NaN/Inf q-value rejection in Accept header
	if q := parseMediaQualityWeightR63([]string{"q=NaN"}); q != 0 {
		t.Fatalf("expected NaN q-value rejected (0), got %v", q)
	}
	if q := parseMediaQualityWeightR63([]string{"q=Inf"}); q != 0 {
		t.Fatalf("expected Inf q-value rejected (0), got %v", q)
	}

	// 3. Accept > Content-Type precedence + OpenSearch v2 header compatibility
	rec = doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{
		"Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
		"Accept":       "application/vnd.elasticsearch+json; compatible-with=8",
	})
	if !strings.Contains(rec.Header().Get("Content-Type"), "compatible-with=8") {
		t.Fatalf("expected Accept > Content-Type precedence, got %q", rec.Header().Get("Content-Type"))
	}
	rec = doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{
		"Accept": "application/vnd.opensearch+json; compatible-with=2",
	})
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/vnd.opensearch+json; compatible-with=2") {
		t.Fatalf("expected OpenSearch v2 Content-Type echo, got %q", rec.Header().Get("Content-Type"))
	}
	rec = doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{
		"Content-Type": "application/vnd.opensearch+json; compatible-with=2",
		"Accept":       "application/vnd.elasticsearch+json; compatible-with=8",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "application/vnd.elasticsearch+json; compatible-with=8") {
		t.Fatalf("expected 200 with Accept > Content-Type precedence (ES8 over OS2), got code=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}

	// 4. ?format=yaml + ?filter_path + gzip, GET/HEAD /_cat, _cat csv/tsv + HEAD Content-Length
	rec = doRound63Req(t, h, http.MethodGet, "/?format=yaml&filter_path=cluster_name", nil, map[string]string{
		"Accept-Encoding": "gzip",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "application/yaml") || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected 200 gzipped YAML response, got code=%d ct=%q ce=%q", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Content-Encoding"))
	}
	gzR, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("invalid gzip body on YAML response: %v", err)
	}
	yamlBytes, _ := io.ReadAll(gzR)
	_ = gzR.Close()
	if !strings.Contains(string(yamlBytes), "cluster_name:") || strings.Contains(string(yamlBytes), "version:") {
		t.Fatalf("unexpected filter_path YAML output: %s", string(yamlBytes))
	}

	rec = doRound63Req(t, h, http.MethodGet, "/_cat", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/_cat/indices") {
		t.Fatalf("expected GET /_cat help list, got %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodHead, "/_cat", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("expected HEAD /_cat 200 empty body, got %d %q", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_cat/indices?format=csv", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("expected text/csv for ?format=csv, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = doRound63Req(t, h, http.MethodGet, "/_cat/indices?format=tsv", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/tab-separated-values") {
		t.Fatalf("expected text/tab-separated-values for ?format=tsv, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = doRound63Req(t, h, http.MethodHead, "/_cat/indices?format=json", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("expected HEAD /_cat/indices empty body with Content-Length, got code=%d body=%d cl=%q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Length"))
	}

	// translogWarningFilterWriterR63 Flush calls filterWarnings before Flush
	innerRec := httptest.NewRecorder()
	tw := &translogWarningFilterWriterR63{ResponseWriter: innerRec, suppressTranslogWarning: true}
	tw.Header().Add("Warning", `299 Elasticsearch-8.15.5 "Translog retention settings [index.translog.retention.age] are deprecated"`)
	tw.Header().Add("Warning", `299 Elasticsearch-8.15.5 "Keep me"`)
	tw.Flush()
	if gotW := innerRec.Header().Values("Warning"); len(gotW) != 1 || !strings.Contains(gotW[0], "Keep me") {
		t.Fatalf("expected translog warning stripped on Flush, got %v", gotW)
	}

	// 5. F28 P1-5: bounded s.pits and s.scrollContexts eviction
	now := time.Now()
	srv.mu.Lock()
	srv.ensurePITStoreLocked()
	for i := 0; i < maxPITEntriesR64+25; i++ {
		srv.sweepPITStoreLockedR64(now)
		srv.pits[fmt.Sprintf("pit-%d", i)] = &pitContextEntry{
			ID:        fmt.Sprintf("pit-%d", i),
			ExpiresAt: now.Add(time.Duration(i+1) * time.Second),
		}
	}
	srv.sweepPITStoreLockedR64(now)
	pitLen := len(srv.pits)

	if srv.scrollContexts == nil {
		srv.scrollContexts = make(map[string]*scrollContextEntry)
	}
	for i := 0; i < maxScrollContextEntriesR64+25; i++ {
		srv.sweepScrollStoreLockedR62Admin(now)
		srv.scrollContexts[fmt.Sprintf("scr-%d", i)] = &scrollContextEntry{
			Token:     fmt.Sprintf("scr-%d", i),
			ExpiresAt: now.Add(time.Duration(i+1) * time.Second),
		}
	}
	srv.sweepScrollStoreLockedR62Admin(now)
	scrollLen := len(srv.scrollContexts)
	srv.mu.Unlock()
	if pitLen > maxPITEntriesR64 {
		t.Fatalf("expected bounded PIT store <= %d, got %d", maxPITEntriesR64, pitLen)
	}
	if scrollLen > maxScrollContextEntriesR64 {
		t.Fatalf("expected bounded scroll store <= %d, got %d", maxScrollContextEntriesR64, scrollLen)
	}
}
