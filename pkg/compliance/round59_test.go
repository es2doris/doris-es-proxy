package compliance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestRound59_F0_OpenPITNoForcedKeepAliveAndPITScrollCleanup(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	// 1. open_point_in_time must NOT inject keep_alive when omitted
	reqNoKeepAlive, err := ctx.buildActionRequest("open_point_in_time", map[string]any{
		"index": "idx1",
	})
	if err != nil {
		t.Fatalf("buildActionRequest(open_point_in_time) failed: %v", err)
	}
	if reqNoKeepAlive.method != http.MethodPost || reqNoKeepAlive.path != "/idx1/_pit" {
		t.Fatalf("unexpected method/path: %s %s", reqNoKeepAlive.method, reqNoKeepAlive.path)
	}
	if reqNoKeepAlive.query.Has("keep_alive") {
		t.Fatalf("expected keep_alive to be omitted when not provided, got query=%v", reqNoKeepAlive.query)
	}

	// Explicit keep_alive is preserved
	reqWithKeepAlive, err := ctx.buildActionRequest("open_point_in_time", map[string]any{
		"index":      "idx1",
		"keep_alive": "2m",
	})
	if err != nil {
		t.Fatalf("buildActionRequest(open_point_in_time with keep_alive) failed: %v", err)
	}
	if got := reqWithKeepAlive.query.Get("keep_alive"); got != "2m" {
		t.Fatalf("expected keep_alive=2m, got %q", got)
	}

	// 2. End-to-end negative keep_alive validation + PIT & scroll cleanup before index deletion
	type recordedCall struct {
		method string
		path   string
		query  string
		body   string
	}
	var mu sync.Mutex
	var calls []recordedCall
	pitSeq := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, recordedCall{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			body:   string(bodyBytes),
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_pit"):
			if r.URL.Query().Get("keep_alive") == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"type":"action_request_validation_exception","reason":"Validation Failed: 1: keep_alive is missing;"},"status":400}`))
				return
			}
			mu.Lock()
			pitSeq++
			id := "pit-" + string(rune('0'+pitSeq))
			mu.Unlock()
			_, _ = w.Write([]byte(`{"id":"` + id + `"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_search"):
			_, _ = w.Write([]byte(`{"_scroll_id":"scroll-1","hits":{"hits":[]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/_search/scroll":
			_, _ = w.Write([]byte(`{"_scroll_id":"scroll-2","hits":{"hits":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"acknowledged":true,"succeeded":true,"num_freed":1}`))
		}
	}))
	defer ts.Close()

	specYAML := `
---
"Negative open_point_in_time missing keep_alive":
  - do:
      indices.create:
        index: test_pit_idx
  - do:
      catch: bad_request
      open_point_in_time:
        index: test_pit_idx
  - do:
      open_point_in_time:
        index: test_pit_idx
        keep_alive: 1m
  - set: { id: pit1 }
  - do:
      open_point_in_time:
        index: test_pit_idx
        keep_alive: 1m
  - set: { id: pit2 }
  - do:
      close_point_in_time:
        body:
          id: $pit1
  - do:
      search:
        index: test_pit_idx
        scroll: 1m
  - set: { _scroll_id: sid1 }
  - do:
      scroll:
        scroll_id: $sid1
        scroll: 1m
  - do:
      clear_scroll:
        scroll_id: $sid1
`
	RunSpecFile(t, "pit_scroll_cleanup.yml", specYAML, ts.URL)

	mu.Lock()
	snapshotCalls := append([]recordedCall(nil), calls...)
	mu.Unlock()

	pitCleanupIdx := -1
	scrollCleanupIdx := -1
	indexDeleteIdx := -1
	for i, c := range snapshotCalls {
		if c.method == http.MethodDelete && c.path == "/_pit" && strings.Contains(c.body, `"pit-2"`) {
			pitCleanupIdx = i
		}
		if c.method == http.MethodDelete && c.path == "/_search/scroll" && strings.Contains(c.body, `"scroll-2"`) {
			scrollCleanupIdx = i
		}
		if c.method == http.MethodDelete && c.path == "/test_pit_idx" {
			indexDeleteIdx = i
		}
		if c.method == http.MethodDelete && c.path == "/_pit" && strings.Contains(c.body, `"pit-1"`) && i > 5 {
			t.Fatalf("pit-1 was already closed explicitly and should not be deleted again in cleanupAll: %+v", snapshotCalls)
		}
		if c.method == http.MethodDelete && c.path == "/_search/scroll" && strings.Contains(c.body, `"scroll-1"`) && i > 8 {
			t.Fatalf("scroll-1 was already cleared explicitly and should not be deleted again in cleanupAll: %+v", snapshotCalls)
		}
	}
	if pitCleanupIdx < 0 {
		t.Fatalf("expected cleanupAll to send DELETE /_pit for pit-2, calls=%+v", snapshotCalls)
	}
	if scrollCleanupIdx < 0 {
		t.Fatalf("expected cleanupAll to send DELETE /_search/scroll for scroll-2, calls=%+v", snapshotCalls)
	}
	if indexDeleteIdx < 0 {
		t.Fatalf("expected cleanupAll to send DELETE /test_pit_idx, calls=%+v", snapshotCalls)
	}
	if pitCleanupIdx > indexDeleteIdx || scrollCleanupIdx > indexDeleteIdx {
		t.Fatalf("expected PIT (%d) and scroll (%d) cleanup before index delete (%d)", pitCleanupIdx, scrollCleanupIdx, indexDeleteIdx)
	}

	// 3. Direct trackCreatedResources coverage for _all, comma-separated, slice, and body variants
	rc := newRunnerContext(http.DefaultClient, ts.URL)
	rc.trackCreatedResources("open_point_in_time", nil, map[string]any{"id": "pA"})
	rc.trackCreatedResources("open_point_in_time", nil, map[string]any{"id": "pB"})
	rc.trackCreatedResources("close_point_in_time", map[string]any{"id": "pA"}, nil)
	if rc.createdPITs["pA"] || !rc.createdPITs["pB"] {
		t.Fatalf("unexpected createdPITs after single close: %v", rc.createdPITs)
	}
	rc.trackCreatedResources("close_point_in_time", map[string]any{"id": "_all"}, nil)
	if len(rc.createdPITs) != 0 {
		t.Fatalf("expected _all to clear createdPITs, got %v", rc.createdPITs)
	}

	rc.trackCreatedResources("search", nil, map[string]any{"_scroll_id": "s1"})
	rc.trackCreatedResources("scroll", nil, map[string]any{"_scroll_id": "s2"})
	rc.trackCreatedResources("scroll", nil, map[string]any{"_scroll_id": "s3"})
	rc.trackCreatedResources("scroll", nil, map[string]any{"_scroll_id": "s4"})
	rc.trackCreatedResources("clear_scroll", map[string]any{"scroll_id": "s1, s2"}, nil)
	rc.trackCreatedResources("clear_scroll", map[string]any{"body": map[string]any{"scroll_id": []any{"s3"}}}, nil)
	if rc.createdScrolls["s1"] || rc.createdScrolls["s2"] || rc.createdScrolls["s3"] || !rc.createdScrolls["s4"] {
		t.Fatalf("unexpected createdScrolls after partial clear: %v", rc.createdScrolls)
	}
	rc.trackCreatedResources("clear_scroll", map[string]any{"scroll_id": "_all"}, nil)
	if len(rc.createdScrolls) != 0 {
		t.Fatalf("expected _all to clear createdScrolls, got %v", rc.createdScrolls)
	}
}

func TestRound59_F0_ActionBuilderPathsAndEscaping(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	// 1. transform.preview_transform with transform_id, id, and without ID
	prevNoID, err := ctx.buildActionRequest("transform.preview_transform", map[string]any{
		"timeout": "30s",
	})
	if err != nil {
		t.Fatalf("transform.preview_transform no ID failed: %v", err)
	}
	if prevNoID.method != http.MethodPost || prevNoID.path != "/_transform/_preview" || prevNoID.query.Get("timeout") != "30s" {
		t.Fatalf("unexpected preview_transform no-id spec: %+v", prevNoID)
	}

	prevTransformID, err := ctx.buildActionRequest("transform.preview_transform", map[string]any{
		"transform_id": "tr/1#a?b",
		"timeout":      "10s",
	})
	if err != nil {
		t.Fatalf("transform.preview_transform with transform_id failed: %v", err)
	}
	if prevTransformID.path != "/_transform/tr%2F1%23a%3Fb/_preview" {
		t.Fatalf("unexpected preview_transform path: %s", prevTransformID.path)
	}
	if prevTransformID.query.Has("transform_id") || prevTransformID.query.Has("id") {
		t.Fatalf("transform_id/id leaked into query: %v", prevTransformID.query)
	}

	prevID, err := ctx.buildActionRequest("transform.preview_transform", map[string]any{
		"id": "tr 2",
	})
	if err != nil {
		t.Fatalf("transform.preview_transform with id failed: %v", err)
	}
	if prevID.path != "/_transform/tr%202/_preview" || prevID.query.Has("id") {
		t.Fatalf("unexpected preview_transform id spec: %+v", prevID)
	}

	// 2. indices.get_settings strips and escapes prefix while preserving *
	gs1, err := ctx.buildActionRequest("indices.get_settings", map[string]any{
		"index":         "idx1",
		"prefix":        "index.blocks/read,index.routing.*",
		"flat_settings": true,
	})
	if err != nil {
		t.Fatalf("indices.get_settings failed: %v", err)
	}
	if gs1.path != "/idx1/_settings/index.blocks%2Fread,index.routing.*" {
		t.Fatalf("unexpected indices.get_settings path: %s", gs1.path)
	}
	if gs1.query.Has("prefix") {
		t.Fatalf("expected prefix to be deleted from query params, got %v", gs1.query)
	}
	if gs1.query.Get("flat_settings") != "true" {
		t.Fatalf("expected flat_settings=true, got %v", gs1.query)
	}

	// 3. Comprehensive ID escaping across resource-ID builders
	const rawID = "a/b#c?d e*"
	const escID = "a%2Fb%23c%3Fd%20e*"
	const rawList = "a/b,c#d*"
	const escList = "a%2Fb,c%23d*"

	cases := []struct {
		action   string
		params   map[string]any
		wantPath string
	}{
		{"indices.get_field_mapping", map[string]any{"index": "idx1", "fields": rawList}, "/idx1/_mapping/field/" + escList},
		{"indices.put_index_template", map[string]any{"name": rawID}, "/_index_template/" + escID},
		{"indices.get_index_template", map[string]any{"name": rawList}, "/_index_template/" + escList},
		{"indices.delete_index_template", map[string]any{"name": rawList}, "/_index_template/" + escList},
		{"indices.exists_index_template", map[string]any{"name": rawID}, "/_index_template/" + escID},
		{"indices.simulate_template", map[string]any{"name": rawID}, "/_index_template/_simulate/" + escID},
		{"indices.simulate_index_template", map[string]any{"name": rawID}, "/_index_template/_simulate_index/" + escID},
		{"indices.put_template", map[string]any{"name": rawID}, "/_template/" + escID},
		{"indices.get_template", map[string]any{"name": rawList}, "/_template/" + escList},
		{"indices.delete_template", map[string]any{"name": rawList}, "/_template/" + escList},
		{"indices.exists_template", map[string]any{"name": rawID}, "/_template/" + escID},
		{"cluster.put_component_template", map[string]any{"name": rawID}, "/_component_template/" + escID},
		{"cluster.get_component_template", map[string]any{"name": rawList}, "/_component_template/" + escList},
		{"cluster.delete_component_template", map[string]any{"name": rawList}, "/_component_template/" + escList},
		{"cluster.exists_component_template", map[string]any{"name": rawID}, "/_component_template/" + escID},
		{"cat.component_templates", map[string]any{"name": rawList}, "/_cat/component_templates/" + escList},
		{"ilm.put_lifecycle", map[string]any{"policy": rawID}, "/_ilm/policy/" + escID},
		{"ilm.get_lifecycle", map[string]any{"policy": rawList}, "/_ilm/policy/" + escList},
		{"ilm.delete_lifecycle", map[string]any{"policy": rawID}, "/_ilm/policy/" + escID},
		{"slm.put_lifecycle", map[string]any{"policy_id": rawID}, "/_slm/policy/" + escID},
		{"slm.get_lifecycle", map[string]any{"policy_id": rawList}, "/_slm/policy/" + escList},
		{"slm.delete_lifecycle", map[string]any{"policy_id": rawID}, "/_slm/policy/" + escID},
		{"slm.execute_lifecycle", map[string]any{"policy_id": rawID}, "/_slm/policy/" + escID + "/_execute"},
		{"enrich.put_policy", map[string]any{"name": rawID}, "/_enrich/policy/" + escID},
		{"enrich.get_policy", map[string]any{"name": rawList}, "/_enrich/policy/" + escList},
		{"enrich.delete_policy", map[string]any{"name": rawList}, "/_enrich/policy/" + escList},
		{"enrich.execute_policy", map[string]any{"name": rawID}, "/_enrich/policy/" + escID + "/_execute"},
		{"snapshot.create_repository", map[string]any{"repository": rawID}, "/_snapshot/" + escID},
		{"snapshot.get_repository", map[string]any{"repository": rawList}, "/_snapshot/" + escList},
		{"snapshot.delete_repository", map[string]any{"repository": rawList}, "/_snapshot/" + escList},
		{"snapshot.verify_repository", map[string]any{"repository": rawID}, "/_snapshot/" + escID + "/_verify"},
		{"snapshot.repository_analyze", map[string]any{"repository": rawID}, "/_snapshot/" + escID + "/_analyze"},
		{"snapshot.create", map[string]any{"repository": rawID, "snapshot": rawID}, "/_snapshot/" + escID + "/" + escID},
		{"snapshot.get", map[string]any{"repository": rawList, "snapshot": rawList}, "/_snapshot/" + escList + "/" + escList},
		{"snapshot.delete", map[string]any{"repository": rawID, "snapshot": rawList}, "/_snapshot/" + escID + "/" + escList},
		{"snapshot.status", map[string]any{"repository": rawList, "snapshot": rawList}, "/_snapshot/" + escList + "/" + escList + "/_status"},
		{"snapshot.status", map[string]any{"repository": rawList}, "/_snapshot/" + escList + "/_status"},
		{"snapshot.restore", map[string]any{"repository": rawID, "snapshot": rawID}, "/_snapshot/" + escID + "/" + escID + "/_restore"},
		{"snapshot.clone", map[string]any{"repository": rawID, "snapshot": rawID, "target_snapshot": rawID}, "/_snapshot/" + escID + "/" + escID + "/_clone/" + escID},
		{"snapshot.cleanup_repository", map[string]any{"repository": rawID}, "/_snapshot/" + escID + "/_cleanup"},
		{"searchable_snapshots.mount", map[string]any{"repository": rawID, "snapshot": rawID}, "/_snapshot/" + escID + "/" + escID + "/_mount"},
		{"cat.snapshots", map[string]any{"repository": rawList}, "/_cat/snapshots/" + escList},
		{"watcher.put_watch", map[string]any{"id": rawID}, "/_watcher/watch/" + escID},
		{"watcher.get_watch", map[string]any{"id": rawID}, "/_watcher/watch/" + escID},
		{"watcher.delete_watch", map[string]any{"id": rawID}, "/_watcher/watch/" + escID},
		{"watcher.execute_watch", map[string]any{"id": rawID}, "/_watcher/watch/" + escID + "/_execute"},
		{"watcher.ack_watch", map[string]any{"watch_id": rawID, "action_id": rawList}, "/_watcher/watch/" + escID + "/_ack/" + escList},
		{"watcher.ack_watch", map[string]any{"watch_id": rawID}, "/_watcher/watch/" + escID + "/_ack"},
		{"watcher.activate_watch", map[string]any{"watch_id": rawID}, "/_watcher/watch/" + escID + "/_activate"},
		{"watcher.deactivate_watch", map[string]any{"watch_id": rawID}, "/_watcher/watch/" + escID + "/_deactivate"},
		{"watcher.stats", map[string]any{"metric": rawList}, "/_watcher/stats/" + escList},
		{"transform.put_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID},
		{"transform.get_transform", map[string]any{"transform_id": rawList}, "/_transform/" + escList},
		{"transform.delete_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID},
		{"transform.start_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID + "/_start"},
		{"transform.stop_transform", map[string]any{"transform_id": rawList}, "/_transform/" + escList + "/_stop"},
		{"transform.get_transform_stats", map[string]any{"transform_id": rawList}, "/_transform/" + escList + "/_stats"},
		{"transform.update_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID + "/_update"},
		{"transform.reset_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID + "/_reset"},
		{"transform.schedule_now_transform", map[string]any{"transform_id": rawID}, "/_transform/" + escID + "/_schedule_now"},
		{"cat.transforms", map[string]any{"transform_id": rawList}, "/_cat/transforms/" + escList},
		{"dangling_indices.import_dangling_index", map[string]any{"index_uuid": rawID}, "/_dangling/" + escID},
		{"dangling_indices.delete_dangling_index", map[string]any{"index_uuid": rawID}, "/_dangling/" + escID},
		{"autoscaling.put_autoscaling_policy", map[string]any{"name": rawID}, "/_autoscaling/policy/" + escID},
		{"autoscaling.get_autoscaling_policy", map[string]any{"name": rawList}, "/_autoscaling/policy/" + escList},
		{"autoscaling.delete_autoscaling_policy", map[string]any{"name": rawID}, "/_autoscaling/policy/" + escID},
		{"shutdown.put_node", map[string]any{"node_id": rawID}, "/_nodes/" + escID + "/shutdown"},
		{"shutdown.get_node", map[string]any{"node_id": rawList}, "/_nodes/" + escList + "/shutdown"},
		{"shutdown.delete_node", map[string]any{"node_id": rawID}, "/_nodes/" + escID + "/shutdown"},
		{"rollup.put_job", map[string]any{"id": rawID}, "/_rollup/job/" + escID},
		{"rollup.get_jobs", map[string]any{"id": rawList}, "/_rollup/job/" + escList},
		{"rollup.delete_job", map[string]any{"id": rawID}, "/_rollup/job/" + escID},
		{"rollup.start_job", map[string]any{"id": rawID}, "/_rollup/job/" + escID + "/_start"},
		{"rollup.stop_job", map[string]any{"id": rawID}, "/_rollup/job/" + escID + "/_stop"},
		{"security.put_role", map[string]any{"name": rawID}, "/_security/role/" + escID},
		{"security.get_role", map[string]any{"name": rawList}, "/_security/role/" + escList},
		{"security.delete_role", map[string]any{"name": rawID}, "/_security/role/" + escID},
		{"security.clear_cached_roles", map[string]any{"name": rawList}, "/_security/role/" + escList + "/_clear_cache"},
		{"security.put_api_key", map[string]any{"id": rawID}, "/_security/api_key/" + escID},
		{"security.update_cross_cluster_api_key", map[string]any{"id": rawID}, "/_security/cross_cluster/api_key/" + escID},
		{"security.clear_cached_privileges", map[string]any{"application": rawList}, "/_security/privilege/" + escList + "/_clear_cache"},
		{"security.get_privileges", map[string]any{"application": rawList, "name": rawList}, "/_security/privilege/" + escList + "/" + escList},
		{"security.get_privileges", map[string]any{"application": rawList}, "/_security/privilege/" + escList},
		{"security.delete_privileges", map[string]any{"application": rawID, "name": rawList}, "/_security/privilege/" + escID + "/" + escList},
		{"security.create_service_token", map[string]any{"namespace": rawID, "service": rawID, "token_name": rawID}, "/_security/service/" + escID + "/" + escID + "/credential/token/" + escID},
		{"security.create_service_token", map[string]any{"namespace": rawID, "service": rawID}, "/_security/service/" + escID + "/" + escID + "/credential/token"},
		{"security.delete_service_token", map[string]any{"namespace": rawID, "service": rawID, "token_name": rawID}, "/_security/service/" + escID + "/" + escID + "/credential/token/" + escID},
		{"security.list_service_tokens", map[string]any{"namespace": rawID, "service": rawID}, "/_security/service/" + escID + "/" + escID + "/credential/token"},
		{"security.get_service_accounts", map[string]any{"namespace": rawID, "service": rawID}, "/_security/service/" + escID + "/" + escID},
		{"security.get_service_accounts", map[string]any{"namespace": rawID}, "/_security/service/" + escID},
		{"security.get_service_credentials", map[string]any{"namespace": rawID, "service": rawID}, "/_security/service/" + escID + "/" + escID + "/credential"},
		{"security.clear_cached_service_tokens", map[string]any{"namespace": rawID, "service": rawID, "token_name": rawList}, "/_security/service/" + escID + "/" + escID + "/credential/token/" + escList + "/_clear_cache"},
		{"security.put_role_mapping", map[string]any{"name": rawID}, "/_security/role_mapping/" + escID},
		{"security.get_role_mapping", map[string]any{"name": rawList}, "/_security/role_mapping/" + escList},
		{"security.delete_role_mapping", map[string]any{"name": rawID}, "/_security/role_mapping/" + escID},
		{"logstash.put_pipeline", map[string]any{"id": rawID}, "/_logstash/pipeline/" + escID},
		{"logstash.get_pipeline", map[string]any{"id": rawList}, "/_logstash/pipeline/" + escList},
		{"logstash.delete_pipeline", map[string]any{"id": rawList}, "/_logstash/pipeline/" + escList},
		{"logstash.exists_pipeline", map[string]any{"id": rawID}, "/_logstash/pipeline/" + escID},
		{"connector.put", map[string]any{"connector_id": rawID}, "/_connector/" + escID},
		{"connector.get", map[string]any{"connector_id": rawID}, "/_connector/" + escID},
		{"connector.delete", map[string]any{"connector_id": rawID}, "/_connector/" + escID},
		{"connector.update_name", map[string]any{"connector_id": rawID}, "/_connector/" + escID + "/_name"},
		{"connector.update_active_filtering", map[string]any{"connector_id": rawID, "filtering_validation_state": rawID}, "/_connector/" + escID + "/_filtering/" + escID},
		{"connector.sync_job_get", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID},
		{"connector.sync_job_delete", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID},
		{"connector.sync_job_cancel", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID + "/_cancel"},
		{"connector.sync_job_check_in", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID + "/_check_in"},
		{"connector.sync_job_error", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID + "/_error"},
		{"connector.sync_job_update_stats", map[string]any{"connector_sync_job_id": rawID}, "/_connector/_sync_job/" + escID + "/_stats"},
		{"search_application.put", map[string]any{"name": rawID}, "/_application/search_application/" + escID},
		{"search_application.get", map[string]any{"name": rawID}, "/_application/search_application/" + escID},
		{"search_application.delete", map[string]any{"name": rawID}, "/_application/search_application/" + escID},
		{"search_application.search", map[string]any{"name": rawID}, "/_application/search_application/" + escID + "/_search"},
		{"search_application.render_query", map[string]any{"name": rawID}, "/_application/search_application/" + escID + "/_render_query"},
		{"behavioral_analytics.put_collection", map[string]any{"collection_name": rawID}, "/_application/analytics/" + escID},
		{"behavioral_analytics.get_collections", map[string]any{"collection_name": rawList}, "/_application/analytics/" + escList},
		{"behavioral_analytics.delete_collection", map[string]any{"collection_name": rawID}, "/_application/analytics/" + escID},
		{"behavioral_analytics.post_event", map[string]any{"collection_name": rawID, "event_type": rawID}, "/_application/analytics/" + escID + "/event/" + escID},
		{"ml.put_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID},
		{"ml.get_jobs", map[string]any{"job_id": rawList}, "/_ml/anomaly_detectors/" + escList},
		{"ml.get_job_stats", map[string]any{"job_id": rawList}, "/_ml/anomaly_detectors/" + escList + "/_stats"},
		{"ml.update_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_update"},
		{"ml.delete_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID},
		{"ml.open_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_open"},
		{"ml.close_job", map[string]any{"job_id": rawList}, "/_ml/anomaly_detectors/" + escList + "/_close"},
		{"ml.put_datafeed", map[string]any{"datafeed_id": rawID}, "/_ml/datafeeds/" + escID},
		{"ml.get_datafeeds", map[string]any{"datafeed_id": rawList}, "/_ml/datafeeds/" + escList},
		{"ml.get_datafeed_stats", map[string]any{"datafeed_id": rawList}, "/_ml/datafeeds/" + escList + "/_stats"},
		{"ml.update_datafeed", map[string]any{"datafeed_id": rawID}, "/_ml/datafeeds/" + escID + "/_update"},
		{"ml.delete_datafeed", map[string]any{"datafeed_id": rawID}, "/_ml/datafeeds/" + escID},
		{"ml.start_datafeed", map[string]any{"datafeed_id": rawID}, "/_ml/datafeeds/" + escID + "/_start"},
		{"ml.stop_datafeed", map[string]any{"datafeed_id": rawList}, "/_ml/datafeeds/" + escList + "/_stop"},
		{"ml.put_trained_model", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID},
		{"ml.get_trained_models", map[string]any{"model_id": rawList}, "/_ml/trained_models/" + escList},
		{"ml.get_trained_models_stats", map[string]any{"model_id": rawList}, "/_ml/trained_models/" + escList + "/_stats"},
		{"ml.delete_trained_model", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID},
		{"ml.put_calendar", map[string]any{"calendar_id": rawID}, "/_ml/calendars/" + escID},
		{"ml.get_calendars", map[string]any{"calendar_id": rawList}, "/_ml/calendars/" + escList},
		{"ml.delete_calendar", map[string]any{"calendar_id": rawID}, "/_ml/calendars/" + escID},
		{"ml.put_calendar_job", map[string]any{"calendar_id": rawID, "job_id": rawList}, "/_ml/calendars/" + escID + "/jobs/" + escList},
		{"ml.delete_calendar_job", map[string]any{"calendar_id": rawID, "job_id": rawList}, "/_ml/calendars/" + escID + "/jobs/" + escList},
		{"ml.put_calendar_event", map[string]any{"calendar_id": rawID}, "/_ml/calendars/" + escID + "/events"},
		{"ml.get_calendar_events", map[string]any{"calendar_id": rawID}, "/_ml/calendars/" + escID + "/events"},
		{"ml.delete_calendar_event", map[string]any{"calendar_id": rawID, "event_id": rawID}, "/_ml/calendars/" + escID + "/events/" + escID},
		{"ml.put_filter", map[string]any{"filter_id": rawID}, "/_ml/filters/" + escID},
		{"ml.get_filters", map[string]any{"filter_id": rawList}, "/_ml/filters/" + escList},
		{"ml.update_filter", map[string]any{"filter_id": rawID}, "/_ml/filters/" + escID + "/_update"},
		{"ml.delete_filter", map[string]any{"filter_id": rawID}, "/_ml/filters/" + escID},
		{"cat.ml_anomaly_detectors", map[string]any{"job_id": rawList}, "/_cat/ml_anomaly_detectors/" + escList},
		{"cat.ml_datafeeds", map[string]any{"datafeed_id": rawList}, "/_cat/ml_datafeeds/" + escList},
		{"cat.ml_trained_models", map[string]any{"model_id": rawList}, "/_cat/ml_trained_models/" + escList},
		{"cat.ml_data_frame_analytics", map[string]any{"id": rawList}, "/_cat/ml_data_frame_analytics/" + escList},
		{"ml.put_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID},
		{"ml.get_data_frame_analytics", map[string]any{"id": rawList}, "/_ml/data_frame/analytics/" + escList},
		{"ml.get_data_frame_analytics_stats", map[string]any{"id": rawList}, "/_ml/data_frame/analytics/" + escList + "/_stats"},
		{"ml.update_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID + "/_update"},
		{"ml.delete_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID},
		{"ml.start_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID + "/_start"},
		{"ml.stop_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID + "/_stop"},
		{"ml.preview_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID + "/_preview"},
		{"ml.explain_data_frame_analytics", map[string]any{"id": rawID}, "/_ml/data_frame/analytics/" + escID + "/_explain"},
		{"ml.start_trained_model_deployment", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/deployment/_start"},
		{"ml.stop_trained_model_deployment", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/deployment/_stop"},
		{"ml.update_trained_model_deployment", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/deployment/_update"},
		{"ml.infer_trained_model", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/_infer"},
		{"ml.infer_trained_model_deployment", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/deployment/_infer"},
		{"ml.put_trained_model_alias", map[string]any{"model_id": rawID, "model_alias": rawID}, "/_ml/trained_models/" + escID + "/model_aliases/" + escID},
		{"ml.delete_trained_model_alias", map[string]any{"model_id": rawID, "model_alias": rawID}, "/_ml/trained_models/" + escID + "/model_aliases/" + escID},
		{"ml.put_trained_model_definition_part", map[string]any{"model_id": rawID, "part": rawID}, "/_ml/trained_models/" + escID + "/definition/" + escID},
		{"ml.put_trained_model_vocabulary", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/vocabulary"},
		{"ml.get_trained_model_vocabulary", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/vocabulary"},
		{"ml.clear_trained_model_deployment_cache", map[string]any{"model_id": rawID}, "/_ml/trained_models/" + escID + "/deployment/_cache/_clear"},
		{"ml.flush_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_flush"},
		{"ml.post_data", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_data"},
		{"ml.reset_job", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_reset"},
		{"ml.forecast", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_forecast"},
		{"ml.delete_forecast", map[string]any{"job_id": rawID, "forecast_id": rawList}, "/_ml/anomaly_detectors/" + escID + "/_forecast/" + escList},
		{"ml.delete_forecast", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_forecast"},
		{"ml.delete_expired_data", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/_delete_expired_data"},
		{"ml.get_buckets", map[string]any{"job_id": rawID, "timestamp": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/buckets/" + escID},
		{"ml.get_buckets", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/buckets"},
		{"ml.get_overall_buckets", map[string]any{"job_id": rawList}, "/_ml/anomaly_detectors/" + escList + "/results/overall_buckets"},
		{"ml.get_records", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/records"},
		{"ml.get_categories", map[string]any{"job_id": rawID, "category_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/categories/" + escID},
		{"ml.get_categories", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/categories"},
		{"ml.get_influencers", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/results/influencers"},
		{"ml.get_model_snapshots", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID},
		{"ml.get_model_snapshots", map[string]any{"job_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots"},
		{"ml.update_model_snapshot", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID + "/_update"},
		{"ml.delete_model_snapshot", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID},
		{"ml.revert_model_snapshot", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID + "/_revert"},
		{"ml.upgrade_job_snapshot", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID + "/_upgrade"},
		{"ml.get_model_snapshot_upgrade_stats", map[string]any{"job_id": rawID, "snapshot_id": rawID}, "/_ml/anomaly_detectors/" + escID + "/model_snapshots/" + escID + "/_upgrade/_stats"},
	}

	for _, tc := range cases {
		spec, err := ctx.buildActionRequest(tc.action, tc.params)
		if err != nil {
			t.Fatalf("buildActionRequest(%s) error: %v", tc.action, err)
		}
		if spec.path != tc.wantPath {
			t.Errorf("action %s: got path %q, want %q", tc.action, spec.path, tc.wantPath)
		}
	}
}

func TestRound59_F0_NDJSONContentTypeCatchRequestAndYAMLResponse(t *testing.T) {
	var mu sync.Mutex
	gotContentTypes := make(map[string]string)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		mu.Lock()
		gotContentTypes[r.URL.Path] = ct
		mu.Unlock()

		if r.URL.Query().Get("format") == "yaml" {
			if r.URL.Query().Get("no_header") == "true" {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("---\ncluster_name: \"doris-yaml\"\nstatus: green\ntimed_out: false\nnumber_of_nodes: 3\n"))
				return
			}
			w.Header().Set("Content-Type", "application/yaml; charset=UTF-8")
			_, _ = w.Write([]byte("cluster_name: doris-yaml-ct\nacknowledged: true\nitems:\n  - one\n  - two\n"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if codeStr := r.URL.Query().Get("mock_status"); codeStr != "" {
			switch codeStr {
			case "400":
				w.WriteHeader(http.StatusBadRequest)
			case "404":
				w.WriteHeader(http.StatusNotFound)
			case "500":
				w.WriteHeader(http.StatusInternalServerError)
			}
			_, _ = w.Write([]byte(`{"error":{"type":"test_err","reason":"simulated failure"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"errors":false,"responses":[],"took":1}`))
	}))
	defer ts.Close()

	specYAML := `
---
"NDJSON Content-Type and header override":
  - do:
      bulk:
        body:
          - '{"index":{"_index":"b1","_id":"1"}}'
          - '{"f":"v"}'
  - do:
      msearch:
        body:
          - '{}'
          - '{"query":{"match_all":{}}}'
  - do:
      msearch_template:
        body:
          - '{}'
          - '{"inline":{"query":{"match_all":{}}}}'
  - do:
      mpercolate:
        body:
          - '{"percolate":{"index":"p1"}}'
          - '{"doc":{"msg":"hi"}}'
  - do:
      monitoring.bulk:
        body:
          - '{"index":{"_type":"cluster_stats"}}'
          - '{"cluster_uuid":"u1"}'
  - do:
      headers:
        Content-Type: text/plain
      bulk:
        index: custom_ct
        body:
          - '{"index":{"_id":"1"}}'
          - '{"f":"v"}'
  - do:
      search:
        index: json_ct
        body:
          query:
            match_all: {}

---
"catch request and YAML format responses":
  - do:
      catch: request
      info:
        mock_status: 400
  - do:
      catch: request
      info:
        mock_status: 404
  - do:
      catch: request
      info:
        mock_status: 500
  - do:
      cluster.health:
        format: yaml
        no_header: true
  - is_false: timed_out
  - match: { cluster_name: doris-yaml }
  - match: { status: green }
  - gt: { number_of_nodes: 2 }
  - match: { $body: "/---\\ncluster_name:/" }
  - do:
      info:
        format: yaml
  - is_true: acknowledged
  - match: { cluster_name: doris-yaml-ct }
  - length: { items: 2 }
`
	RunSpecFile(t, "ndjson_catch_yaml.yml", specYAML, ts.URL)

	mu.Lock()
	for _, p := range []string{"/_bulk", "/_msearch", "/_msearch/template", "/_mpercolate", "/_monitoring/bulk"} {
		if got := gotContentTypes[p]; got != "application/x-ndjson" {
			t.Errorf("expected path %s Content-Type=application/x-ndjson, got %q", p, got)
		}
	}
	if got := gotContentTypes["/custom_ct/_bulk"]; got != "text/plain" {
		t.Errorf("expected explicit header override text/plain on /custom_ct/_bulk, got %q", got)
	}
	if got := gotContentTypes["/json_ct/_search"]; got != "application/json" {
		t.Errorf("expected application/json on /json_ct/_search, got %q", got)
	}
	mu.Unlock()

	// Verify catch: request fails when status < 400
	ctx := newRunnerContext(ts.Client(), ts.URL)
	if err := ctx.verifyCatch("request", "info", http.StatusOK, `{"ok":true}`, map[string]any{"ok": true}); err == nil {
		t.Fatalf("expected verifyCatch(request) to fail on HTTP 200")
	}
	// Verify rawHTTP wrapper backward compatibility
	st, rawBody, err := ctx.rawHTTP(http.MethodPost, "/_search", nil, []byte(`{}`), nil)
	if err != nil || st != http.StatusOK || !strings.Contains(rawBody, `"took"`) {
		t.Fatalf("rawHTTP failed: status=%d err=%v body=%s", st, err, rawBody)
	}
	// Verify YAML null document parsing
	parsedNull, kindNull := parseResponsePayloadWithContentType("---\n~\n", "application/yaml")
	if parsedNull != nil || kindNull != bodyKindJSONNull {
		t.Fatalf("expected YAML null to return (nil, bodyKindJSONNull), got (%v, %v)", parsedNull, kindNull)
	}
}

func TestRound59_F1_DedicatedIsUnsetAndBodyRootPath(t *testing.T) {
	// 1. Direct is_unset semantics: pass iff !exists || val == nil
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	ctx.lastBodyRaw = `{"null_v":null,"false_v":false,"zero_v":0,"empty_s":"","empty_a":[],"empty_o":{},"nodes":{"n1":{"null_sub":null,"false_sub":false}}}`
	ctx.lastResponse = parseResponsePayload(ctx.lastBodyRaw)
	ctx.lastBodyKind = bodyKindParsed

	passPaths := []string{
		"missing_v",
		"nested.missing",
		"null_v",
		"nodes._arbitrary_key_.missing_sub",
		"nodes._arbitrary_key_.null_sub",
	}
	for _, p := range passPaths {
		if err := ctx.execStep(SpecStep{Op: "is_unset", Value: p}, false); err != nil {
			t.Errorf("expected is_unset(%q) to pass, got %v", p, err)
		}
	}

	failPaths := []string{
		"false_v",
		"zero_v",
		"empty_s",
		"empty_a",
		"empty_o",
		"nodes._arbitrary_key_.false_sub",
		"$body",
		"",
	}
	for _, p := range failPaths {
		if err := ctx.execStep(SpecStep{Op: "is_unset", Value: p}, false); err == nil {
			t.Errorf("expected is_unset(%q) to fail on non-nil value", p)
		}
	}

	// 2. HTTP server scenarios for HEAD (200 vs 404), 200 empty text "", 200 JSON null, 404 empty, and 204 No Content
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exists_idx":
			w.WriteHeader(http.StatusOK)
		case "/missing_idx":
			w.WriteHeader(http.StatusNotFound)
		case "/_cat/indices":
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
		case "/null_doc/_source/1":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
		case "/no_content/_doc/1":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	specYAML := `
---
"HEAD 200 and 404 with empty and $body":
  - do:
      indices.exists:
        index: exists_idx
  - is_true: ''
  - is_true: $body
  - do:
      indices.exists:
        index: missing_idx
  - is_false: ''
  - is_false: $body
  - is_unset: ''
  - is_unset: $body

---
"200 empty text body supports match and length on $body":
  - do:
      cat.indices: {}
  - match: { $body: "" }
  - length: { $body: 0 }
  - is_empty: $body
  - is_false: $body

---
"200 JSON null body supports is_unset and match null on $body":
  - do:
      get_source:
        index: null_doc
        id: "1"
  - is_unset: $body
  - is_unset: ''
  - match: { $body: ~ }
  - is_false: $body

---
"Non-HEAD 404 with ignore 404 and empty body passes is_unset $body":
  - do:
      ignore: 404
      get_source:
        index: missing_source_idx
        id: "404"
  - is_unset: $body
  - is_unset: ''
`
	RunSpecFile(t, "is_unset_and_body.yml", specYAML, ts.URL)

	// Negative checks on HEAD 200/404, 200 empty text, and 204 No Content
	hctx := newRunnerContext(ts.Client(), ts.URL)
	headExistsDoc, _ := ParseSpecFile("s:\n  - do:\n      indices.exists:\n        index: exists_idx\n")
	if err := hctx.execStep(headExistsDoc.Sections[0].Steps[0], false); err != nil {
		t.Fatalf("HEAD exists_idx failed: %v", err)
	}
	if err := hctx.execIsFalse("$body"); err == nil {
		t.Fatalf("expected is_false($body) to fail on HEAD 200")
	}
	if err := hctx.execIsUnset("$body"); err == nil {
		t.Fatalf("expected is_unset($body) to fail on HEAD 200")
	}

	headMissingDoc, _ := ParseSpecFile("s:\n  - do:\n      indices.exists:\n        index: missing_idx\n")
	if err := hctx.execStep(headMissingDoc.Sections[0].Steps[0], false); err != nil {
		t.Fatalf("HEAD missing_idx failed: %v", err)
	}
	if err := hctx.execIsTrue("$body"); err == nil {
		t.Fatalf("expected is_true($body) to fail on HEAD 404")
	}

	catEmptyDoc, _ := ParseSpecFile("s:\n  - do:\n      cat.indices: {}\n")
	if err := hctx.execStep(catEmptyDoc.Sections[0].Steps[0], false); err != nil {
		t.Fatalf("GET /_cat/indices failed: %v", err)
	}
	if err := hctx.execIsUnset("$body"); err == nil {
		t.Fatalf("expected is_unset($body) to fail on 200 empty string text body")
	}
	if err := hctx.execIsTrue("$body"); err == nil {
		t.Fatalf("expected is_true($body) to fail on 200 empty string text body")
	}

	noContentDoc, _ := ParseSpecFile("s:\n  - do:\n      delete:\n        index: no_content\n        id: '1'\n")
	if err := hctx.execStep(noContentDoc.Sections[0].Steps[0], false); err != nil {
		t.Fatalf("DELETE 204 failed: %v", err)
	}
	if err := hctx.execIsUnset("$body"); err == nil {
		t.Fatalf("expected is_unset($body) to fail on HTTP 204")
	}
}

func TestRound59_F1_CompileComplianceRegexDotallFlagsAndStash(t *testing.T) {
	// 1. DOTALL default + flags i, m, s
	reDotall, isRe, err := compileComplianceRegex("/header.*footer/")
	if !isRe || err != nil {
		t.Fatalf("compileComplianceRegex(/header.*footer/) failed: isRe=%v err=%v", isRe, err)
	}
	if !reDotall.MatchString("header\nmiddle line\nfooter") {
		t.Fatalf("expected DOTALL by default to match across newlines")
	}

	reIM, isRe, err := compileComplianceRegex(`/^idx_one\s+green$/im`)
	if !isRe || err != nil {
		t.Fatalf("compileComplianceRegex(/.../im) failed: isRe=%v err=%v", isRe, err)
	}
	if !reIM.MatchString("header\nIDX_ONE   GREEN\ntrailer") {
		t.Fatalf("expected /.../im to match case-insensitively at line boundaries")
	}

	reEscSlash, isRe, err := compileComplianceRegex(`/http:\/\/localhost:9200\/idx/i`)
	if !isRe || err != nil || !reEscSlash.MatchString("HTTP://LOCALHOST:9200/IDX") {
		t.Fatalf("expected escaped slashes with /i flag to match, isRe=%v err=%v", isRe, err)
	}

	reTrailingBackslash, isRe, err := compileComplianceRegex(`/foo\\/`)
	if !isRe || err != nil || !reTrailingBackslash.MatchString(`foo\`) {
		t.Fatalf("expected even trailing backslashes before closing / to compile, isRe=%v err=%v", isRe, err)
	}

	// 2. Non-regex strings must return isRegex == false
	nonRegexes := []string{
		"",
		"/",
		"plain_string",
		"/_cat/indices",
		"/_nodes/stats",
		"/single_leading_slash",
		`/escaped_end\/`,
		"/bad/flags_xyz",
	}
	for _, s := range nonRegexes {
		if _, ok, compErr := compileComplianceRegex(s); ok || compErr != nil {
			t.Errorf("expected %q not to be treated as regex, got ok=%v err=%v", s, ok, compErr)
		}
	}

	// 3. Invalid regex handling across matchValues, valuesEqual, verifyCatch, and warnings_regex
	if _, ok, compErr := compileComplianceRegex("/[unclosed/i"); !ok || compErr == nil {
		t.Fatalf("expected invalid regex error for /[unclosed/i, got ok=%v err=%v", ok, compErr)
	}
	if err := matchValues("f", "abc", "/[unclosed/i"); err == nil {
		t.Fatalf("expected matchValues error on invalid regex")
	}
	if err := matchValues("f", nil, "/.*/"); err == nil {
		t.Fatalf("expected matchValues on nil actual against regex to fail")
	}
	if valuesEqual("abc", "/[unclosed/i") {
		t.Fatalf("expected valuesEqual false on invalid regex")
	}
	if valuesEqual(nil, "/.*/") {
		t.Fatalf("expected valuesEqual false on nil actual against regex")
	}
	if !valuesEqual(map[string]any{"msg": "Hello\nWorld"}, map[string]any{"msg": "/^hello.*world$/i"}) {
		t.Fatalf("expected nested valuesEqual with /i and DOTALL to succeed")
	}

	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	ctx.stash["idx"] = "orders_2026"
	ctx.stash["expected_code"] = "index_not_found"

	// Stash expansion in verifyCatch with multiline trace + /i flag
	errBody := "{\n  \"error\": {\n    \"type\": \"INDEX_NOT_FOUND_EXCEPTION\",\n    \"reason\": \"no such index [ORDERS_2026]\"\n  },\n  \"status\": 404\n}"
	var parsedErr any
	_ = json.Unmarshal([]byte(errBody), &parsedErr)
	if err := ctx.verifyCatch(`/$expected_code.*\[$idx\]/i`, "get", http.StatusNotFound, errBody, parsedErr); err != nil {
		t.Fatalf("expected verifyCatch with stash + /i + DOTALL to pass, got %v", err)
	}
	if err := ctx.verifyCatch(`/[unclosed/i`, "get", http.StatusBadRequest, errBody, parsedErr); err == nil {
		t.Fatalf("expected verifyCatch error on invalid regex")
	}

	// Stash expansion in execMatch regex
	ctx.lastResponse = map[string]any{
		"cat_out": "health status index\nyellow open   ORDERS_2026\n",
	}
	ctx.lastBodyKind = bodyKindParsed
	matchStep := NewOrderedMap()
	matchStep.Set("cat_out", `/^yellow\s+open\s+${idx}$/im`)
	if err := ctx.execMatch(matchStep); err != nil {
		t.Fatalf("expected execMatch with ${idx} and /im to pass, got %v", err)
	}

	// Warnings regex with /i flag
	if err := validateResponseWarnings(
		"search",
		http.MethodPost,
		true,
		[]string{`299 Elasticsearch-7.10.2 "Deprecated field [FOO]\ndetails"`},
		nil,
		[]string{`/deprecated field \[foo\].*details/i`},
		nil,
		nil,
	); err != nil {
		t.Fatalf("expected warnings_regex with /i and DOTALL to pass, got %v", err)
	}
}

func TestRound59_F1_YAMLAnchorsAliasesMergeKeysMultilineEscapesAndFlowColons(t *testing.T) {
	// 1. Anchors, aliases, deep-clone isolation, merge keys (<<: *a and <<: [*a, *b]), and per-doc scope
	yamlSrc := `
---
setup:
  - do:
      indices.create:
        index: &idx_name anchor_idx
        body: &default_body
          settings: &base_settings
            number_of_shards: 1
            number_of_replicas: 0
          mappings:
            properties: &base_props
              title: { type: text }

"Merge key precedence and alias deep clone":
  - do:
      indices.create:
        index: *idx_name
        body:
          <<: *default_body
          settings:
            explicit_before: preserved
            <<: [*base_settings, { number_of_shards: 99, refresh_interval: 5s }]
            number_of_replicas: 2
  - match:
      endpoints:
        { http://localhost:9200: ok, https://node1:9300/path: ready, "quoted:key": 123, 'sq:key': 456 }
---
"Second document redefines same anchor cleanly":
  - do:
      index:
        index: &idx_name second_doc_idx
        id: "1"
        body:
          target: *idx_name
          items:
            - &first_elem
              k: v1
            - *first_elem
`
	docs, err := ParseYAMLDocuments(yamlSrc)
	if err != nil {
		t.Fatalf("ParseYAMLDocuments failed: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 YAML documents, got %d", len(docs))
	}

	doc0 := ToNative(docs[0]).(map[string]any)
	secSteps := doc0["Merge key precedence and alias deep clone"].([]any)
	doStep := secSteps[0].(map[string]any)["do"].(map[string]any)["indices.create"].(map[string]any)
	if doStep["index"] != "anchor_idx" {
		t.Fatalf("expected *idx_name='anchor_idx', got %v", doStep["index"])
	}
	bodyMap := doStep["body"].(map[string]any)
	settingsMap := bodyMap["settings"].(map[string]any)
	if settingsMap["explicit_before"] != "preserved" {
		t.Fatalf("explicit key before <<: must override merged map: %v", settingsMap)
	}
	// *base_settings is earlier in [*base_settings, {...}] so number_of_shards=1 wins over 99
	if settingsMap["number_of_shards"] != int64(1) {
		t.Fatalf("expected earlier merge list entry number_of_shards=1 to win, got %v", settingsMap["number_of_shards"])
	}
	// Explicit key after <<: overrides *base_settings number_of_replicas=0 -> 2
	if settingsMap["number_of_replicas"] != int64(2) {
		t.Fatalf("expected explicit key after <<: number_of_replicas=2 to win, got %v", settingsMap["number_of_replicas"])
	}
	// Later merge entry contributes non-conflicting key refresh_interval=5s
	if settingsMap["refresh_interval"] != "5s" {
		t.Fatalf("expected refresh_interval=5s from second merge entry, got %v", settingsMap["refresh_interval"])
	}

	// Verify deep-clone isolation: mutating doc0's merged mappings must not mutate setup's mappings
	setupBody := doc0["setup"].([]any)[0].(map[string]any)["do"].(map[string]any)["indices.create"].(map[string]any)["body"].(map[string]any)
	bodyMap["mappings"].(map[string]any)["mutated"] = true
	if _, leaked := setupBody["mappings"].(map[string]any)["mutated"]; leaked {
		t.Fatalf("expected *alias expansion to deep-clone maps without shared mutation")
	}

	// Flow-map unquoted URL/host:port colons vs quoted colons
	matchEndpoints := secSteps[1].(map[string]any)["match"].(map[string]any)["endpoints"].(map[string]any)
	if matchEndpoints["http://localhost:9200"] != "ok" {
		t.Fatalf("expected flow key http://localhost:9200='ok', got %v", matchEndpoints)
	}
	if matchEndpoints["https://node1:9300/path"] != "ready" {
		t.Fatalf("expected flow key https://node1:9300/path='ready', got %v", matchEndpoints)
	}
	if matchEndpoints["quoted:key"] != int64(123) || matchEndpoints["sq:key"] != int64(456) {
		t.Fatalf("expected quoted colon keys to split cleanly, got %v", matchEndpoints)
	}

	// Verify second document anchor scope and sequence item anchor
	doc1 := ToNative(docs[1]).(map[string]any)
	doc1Idx := doc1["Second document redefines same anchor cleanly"].([]any)[0].(map[string]any)["do"].(map[string]any)["index"].(map[string]any)
	if doc1Idx["index"] != "second_doc_idx" {
		t.Fatalf("expected doc1 *idx_name='second_doc_idx', got %v", doc1Idx["index"])
	}
	items := doc1Idx["body"].(map[string]any)["items"].([]any)
	if len(items) != 2 || items[1].(map[string]any)["k"] != "v1" {
		t.Fatalf("expected sequence item alias to clone map {k: v1}, got %v", items)
	}

	// Cross-document alias leak must fail
	if _, err := ParseYAMLDocuments("---\na: &doc1_only 1\n---\nb: *doc1_only\n"); err == nil {
		t.Fatalf("expected alias referencing previous YAML document anchor to fail")
	}
	// Invalid merge value must fail
	if _, err := ParseYAMLDocuments("---\na: &scalar_anc hello\nm:\n  <<: *scalar_anc\n"); err == nil {
		t.Fatalf("expected <<: non-mapping value to fail")
	}

	// 2. Multiline double-quoted and single-quoted scalars + YAML 1.2 escapes
	multilineYAML := "---\n" +
		"dq_folded: \"hello\n" +
		"  world # not a comment\n" +
		"\n" +
		"  second para\n" +
		"\n" +
		"\n" +
		"  --- still inside quotes\\\n" +
		"  _joined\"\n" +
		"sq_folded: 'it''s line one\n" +
		"  line two\n" +
		"\n" +
		"  line three'\n" +
		"plain_apostrophe: doesn't open multiline quote\n" +
		"escapes: \"\\0\\a\\b\\t\\n\\v\\f\\r\\e\\ \\/\\\"\\\\\\N\\_\\L\\P\\.\\x41\\u03B1\\U0001F600\"\n"

	mDocs, err := ParseYAMLDocuments(multilineYAML)
	if err != nil {
		t.Fatalf("ParseYAMLDocuments(multilineYAML) failed: %v", err)
	}
	if len(mDocs) != 1 {
		t.Fatalf("expected 1 document (--- inside quotes must not split), got %d", len(mDocs))
	}
	mm := ToNative(mDocs[0]).(map[string]any)

	wantDQ := "hello world # not a comment\nsecond para\n\n--- still inside quotes_joined"
	if mm["dq_folded"] != wantDQ {
		t.Fatalf("dq_folded mismatch:\ngot:  %q\nwant: %q", mm["dq_folded"], wantDQ)
	}
	wantSQ := "it's line one line two\nline three"
	if mm["sq_folded"] != wantSQ {
		t.Fatalf("sq_folded mismatch:\ngot:  %q\nwant: %q", mm["sq_folded"], wantSQ)
	}
	if mm["plain_apostrophe"] != "doesn't open multiline quote" {
		t.Fatalf("plain_apostrophe mismatch: %q", mm["plain_apostrophe"])
	}
	wantEscapes := "\x00\a\b\t\n\v\f\r\x1b /\"\\\u0085\u00a0\u2028\u2029\\.Aα😀"
	if mm["escapes"] != wantEscapes {
		t.Fatalf("escapes mismatch:\ngot:  %q\nwant: %q", mm["escapes"], wantEscapes)
	}

	// Error cases for unclosed multiline quotes and invalid YAML 1.2 escapes
	badYAMLs := []string{
		"a: \"unclosed multiline\n  still open\n",
		"a: 'unclosed single\n  still open\n",
		`a: "\x4"`,
		`a: "\xZZ"`,
		`a: "\U0001"`,
		`a: "\U00110000"`,
		`a: "\U0000D800"`,
		`a: "\q"`,
	}
	for _, bad := range badYAMLs {
		if _, err := ParseYAMLDocuments(bad); err == nil {
			t.Errorf("expected ParseYAMLDocuments to fail on %q", bad)
		}
	}
}
