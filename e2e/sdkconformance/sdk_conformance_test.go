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

package sdkconformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/elastic/go-elasticsearch/v8/typedapi/core/search"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/calendarinterval"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/refresh"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/sortorder"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func strPtr(v string) *string { return &v }
func intPtr(v int) *int       { return &v }

type sdkOrderItem struct {
	SKU   string  `json:"sku"`
	Qty   int64   `json:"qty"`
	Price float64 `json:"price"`
}

type sdkOrderDoc struct {
	Title     string         `json:"title"`
	Category  string         `json:"category"`
	Quantity  int64          `json:"quantity"`
	Amount    float64        `json:"amount"`
	Active    bool           `json:"active"`
	CreatedAt string         `json:"created_at"`
	Items     []sdkOrderItem `json:"items,omitempty"`
}

// --- elastic/elasticsearch-specification schema.json Wire Validator (via compliance.SpecSchemaValidator) ---

const minValidatedEndpointsTarget = 518

var targetValidatedEndpoints = []string{
	"_internal.delete_desired_balance",
	"_internal.delete_desired_nodes",
	"_internal.get_desired_balance",
	"_internal.get_desired_nodes",
	"_internal.prevalidate_node_removal",
	"_internal.update_desired_nodes",
	"info",
	"ping",
	"exists",
	"get_source",
	"search_shards",
	"search_mvt",
	"cluster.health",
	"cluster.stats",
	"cluster.state",
	"cluster.allocation_explain",
	"cluster.reroute",
	"cluster.pending_tasks",
	"cluster.put_settings",
	"cluster.get_settings",
	"cluster.put_component_template",
	"cluster.get_component_template",
	"cluster.exists_component_template",
	"cluster.delete_component_template",
	"nodes.info",
	"nodes.stats",
	"nodes.usage",
	"nodes.hot_threads",
	"tasks.list",
	"tasks.get",
	"tasks.cancel",
	"indices.create",
	"indices.get",
	"indices.exists",
	"indices.delete",
	"indices.refresh",
	"indices.flush",
	"indices.stats",
	"indices.recovery",
	"indices.shrink",
	"indices.split",
	"indices.clone",
	"indices.put_settings",
	"indices.get_settings",
	"indices.put_mapping",
	"indices.get_mapping",
	"indices.get_field_mapping",
	"indices.put_alias",
	"indices.get_alias",
	"indices.exists_alias",
	"indices.delete_alias",
	"indices.update_aliases",
	"indices.put_index_template",
	"indices.get_index_template",
	"indices.exists_index_template",
	"indices.delete_index_template",
	"indices.simulate_index_template",
	"indices.simulate_template",
	"indices.put_template",
	"indices.get_template",
	"indices.exists_template",
	"indices.delete_template",
	"indices.create_data_stream",
	"indices.get_data_stream",
	"indices.data_streams_stats",
	"indices.delete_data_stream",
	"indices.rollover",
	"indices.close",
	"indices.open",
	"indices.segments",
	"indices.forcemerge",
	"indices.clear_cache",
	"indices.analyze",
	"indices.validate_query",
	"indices.resolve_index",
	"index",
	"get",
	"search",
	"msearch",
	"mget",
	"bulk",
	"count",
	"update",
	"delete",
	"update_by_query",
	"delete_by_query",
	"field_caps",
	"termvectors",
	"mtermvectors",
	"rank_eval",
	"scripts_painless_execute",
	"render_search_template",
	"search_template",
	"msearch_template",
	"synonyms.put_synonym",
	"synonyms.get_synonym",
	"synonyms.get_synonyms_sets",
	"synonyms.put_synonym_rule",
	"synonyms.delete_synonym",
	"async_search.submit",
	"async_search.get",
	"async_search.delete",
	"sql.query",
	"esql.query",
	"eql.search",
	"open_point_in_time",
	"close_point_in_time",
	"scroll",
	"clear_scroll",
	"put_script",
	"get_script",
	"delete_script",
	"explain",
	"reindex",
	"ingest.put_pipeline",
	"ingest.get_pipeline",
	"ingest.delete_pipeline",
	"ingest.processor_grok",
	"ingest.simulate",
	"ilm.put_lifecycle",
	"ilm.get_lifecycle",
	"ilm.delete_lifecycle",
	"ilm.get_status",
	"ilm.explain_lifecycle",
	"snapshot.create_repository",
	"snapshot.get_repository",
	"snapshot.verify_repository",
	"snapshot.create",
	"snapshot.get",
	"snapshot.restore",
	"snapshot.delete",
	"snapshot.delete_repository",
	"cat.health",
	"cat.indices",
	"cat.aliases",
	"cat.count",
	"cat.segments",
	"cat.nodes",
	"cat.shards",
	"cat.fielddata",
	"cat.templates",
	"cat.thread_pool",
	"cat.tasks",
	"cat.recovery",
	"cat.master",
	"cat.plugins",
	"cat.repositories",
	"cat.pending_tasks",
	"cat.nodeattrs",
	"cat.component_templates",
	"create",
	"exists_source",
	"knn_search",
	"terms_enum",
	"capabilities",
	"health_report",
	"get_script_context",
	"get_script_languages",
	"features.get_features",
	"migration.deprecations",
	"dangling_indices.list_dangling_indices",
	"reindex_rethrottle",
	"update_by_query_rethrottle",
	"delete_by_query_rethrottle",
	"indices.disk_usage",
	"indices.field_usage_stats",
	"indices.shard_stores",
	"indices.reload_search_analyzers",
	"indices.resolve_cluster",
	"indices.add_block",
	"indices.migrate_to_data_stream",
	"indices.put_data_lifecycle",
	"indices.get_data_lifecycle",
	"indices.explain_data_lifecycle",
	"indices.delete_data_lifecycle",
	"indices.modify_data_stream",
	"cluster.info",
	"cluster.remote_info",
	"cluster.post_voting_config_exclusions",
	"cluster.delete_voting_config_exclusions",
	"license.get",
	"license.get_basic_status",
	"cat.help",
	"cat.allocation",
	"cat.snapshots",
	"cat.transforms",
	"cat.ml_jobs",
	"ilm.stop",
	"ilm.start",
	"ilm.remove_policy",
	"slm.put_lifecycle",
	"slm.get_lifecycle",
	"slm.execute_lifecycle",
	"slm.execute_retention",
	"slm.get_status",
	"slm.get_stats",
	"slm.stop",
	"slm.start",
	"slm.delete_lifecycle",
	"enrich.put_policy",
	"enrich.get_policy",
	"enrich.execute_policy",
	"enrich.stats",
	"enrich.delete_policy",
	"sql.translate",
	"sql.clear_cursor",
	"async_search.status",
	"eql.get_status",
	"eql.get",
	"eql.delete",
	"synonyms.get_synonym_rule",
	"synonyms.delete_synonym_rule",
	"query_rules.put_ruleset",
	"query_rules.get_ruleset",
	"query_rules.list_rulesets",
	"query_rules.put_rule",
	"query_rules.get_rule",
	"query_rules.delete_rule",
	"query_rules.delete_ruleset",
	"ssl.certificates",
	"dangling_indices.import_dangling_index",
	"dangling_indices.delete_dangling_index",
	"shutdown.put_node",
	"shutdown.delete_node",
	"nodes.reload_secure_settings",
	"license.post",
	"license.post_start_basic",
	"license.post_start_trial",
	"license.get_trial_status",
	"license.delete",
	"snapshot.status",
	"snapshot.clone",
	"snapshot.cleanup_repository",
	"snapshot.repository_analyze",
	"searchable_snapshots.clear_cache",
	"searchable_snapshots.mount",
	"indices.unfreeze",
	"indices.promote_data_stream",
	"ingest.put_geoip_database",
	"ingest.delete_geoip_database",
	"simulate.ingest",
	"graph.explore",
	"text_structure.find_field_structure",
	"text_structure.find_message_structure",
	"text_structure.test_grok_pattern",
	"profiling.status",
	"profiling.stacktraces",
	"profiling.flamegraph",
	"autoscaling.put_autoscaling_policy",
	"autoscaling.delete_autoscaling_policy",
	"sql.get_async",
	"sql.delete_async",
	"esql.async_query",
	"esql.async_query_get",
	"cat.ml_datafeeds",
	"cat.ml_trained_models",
	"cat.ml_data_frame_analytics",
	"inference.put",
	"inference.get",
	"inference.inference",
	"search_application.put",
	"search_application.get",
	"search_application.list",
	"search_application.search",
	"search_application.render_query",
	"search_application.delete",
	"search_application.get_behavioral_analytics",
	"transform.put_transform",
	"transform.get_transform",
	"transform.start_transform",
	"transform.stop_transform",
	"transform.preview_transform",
	"transform.reset_transform",
	"transform.schedule_now_transform",
	"transform.delete_transform",
	"rollup.put_job",
	"rollup.start_job",
	"rollup.stop_job",
	"rollup.delete_job",
	"rollup.get_rollup_caps",
	"rollup.get_rollup_index_caps",
	"rollup.rollup_search",
	"watcher.put_watch",
	"watcher.get_watch",
	"watcher.activate_watch",
	"watcher.deactivate_watch",
	"watcher.ack_watch",
	"watcher.delete_watch",
	"watcher.start",
	"watcher.stop",
	"watcher.stats",
	"watcher.get_settings",
	"watcher.update_settings",
	"indices.downsample",
	"ilm.move_to_step",
	"ilm.retry",
	"shutdown.get_node",
	"xpack.info",
	"migration.post_feature_upgrade",
	"searchable_snapshots.stats",
	"ingest.get_geoip_database",
	"ingest.geo_ip_stats",
	"profiling.topn_functions",
	"autoscaling.get_autoscaling_policy",
	"autoscaling.get_autoscaling_capacity",
	"sql.get_async_status",
	"ml.set_upgrade_mode",
	"ml.put_filter",
	"ml.get_filters",
	"ml.delete_filter",
	"ml.put_calendar",
	"ml.delete_calendar",
	"inference.delete",
	"search_application.put_behavioral_analytics",
	"search_application.post_behavioral_analytics_event",
	"search_application.delete_behavioral_analytics",
	"transform.update_transform",
	"transform.get_node_stats",
	"transform.upgrade_transforms",
	"rollup.get_jobs",
	"watcher.execute_watch",
	"ilm.migrate_to_data_tiers",
	"logstash.put_pipeline",
	"logstash.delete_pipeline",
	"ccr.put_auto_follow_pattern",
	"ccr.pause_auto_follow_pattern",
	"ccr.resume_auto_follow_pattern",
	"ccr.delete_auto_follow_pattern",
	"ccr.follow",
	"ccr.pause_follow",
	"ccr.resume_follow",
	"ccr.unfollow",
	"ccr.forget_follower",
	"ccr.follow_info",
	"ccr.follow_stats",
	"ccr.get_auto_follow_pattern",
	"ccr.stats",
	"connector.check_in",
	"connector.delete",
	"connector.get",
	"connector.last_sync",
	"connector.list",
	"connector.post",
	"connector.put",
	"connector.secret_delete",
	"connector.secret_get",
	"connector.secret_post",
	"connector.secret_put",
	"connector.sync_job_cancel",
	"connector.sync_job_check_in",
	"connector.sync_job_claim",
	"connector.sync_job_delete",
	"connector.sync_job_error",
	"connector.sync_job_get",
	"connector.sync_job_list",
	"connector.sync_job_post",
	"connector.sync_job_update_stats",
	"connector.update_active_filtering",
	"connector.update_api_key_id",
	"connector.update_configuration",
	"connector.update_error",
	"connector.update_features",
	"connector.update_filtering",
	"connector.update_filtering_validation",
	"connector.update_index_name",
	"connector.update_name",
	"connector.update_native",
	"connector.update_pipeline",
	"connector.update_scheduling",
	"connector.update_service_type",
	"connector.update_status",
	"features.reset_features",
	"fleet.delete_secret",
	"fleet.get_secret",
	"fleet.global_checkpoints",
	"fleet.msearch",
	"fleet.post_secret",
	"fleet.search",
	"logstash.get_pipeline",
	"migration.get_feature_upgrade_status",
	"ml.clear_trained_model_deployment_cache",
	"ml.close_job",
	"ml.delete_calendar_event",
	"ml.delete_calendar_job",
	"ml.delete_data_frame_analytics",
	"ml.delete_datafeed",
	"ml.delete_expired_data",
	"ml.delete_forecast",
	"ml.delete_job",
	"ml.delete_model_snapshot",
	"ml.delete_trained_model",
	"ml.delete_trained_model_alias",
	"ml.estimate_model_memory",
	"ml.evaluate_data_frame",
	"ml.explain_data_frame_analytics",
	"ml.flush_job",
	"ml.forecast",
	"ml.get_buckets",
	"ml.get_calendar_events",
	"ml.get_calendars",
	"ml.get_categories",
	"ml.get_data_frame_analytics",
	"ml.get_data_frame_analytics_stats",
	"ml.get_datafeed_stats",
	"ml.get_datafeeds",
	"ml.get_influencers",
	"ml.get_job_stats",
	"ml.get_jobs",
	"ml.get_memory_stats",
	"ml.get_model_snapshot_upgrade_stats",
	"ml.get_model_snapshots",
	"ml.get_overall_buckets",
	"ml.get_records",
	"ml.get_trained_models",
	"ml.get_trained_models_stats",
	"ml.infer_trained_model",
	"ml.info",
	"ml.open_job",
	"ml.post_calendar_events",
	"ml.post_data",
	"ml.preview_data_frame_analytics",
	"ml.preview_datafeed",
	"ml.put_calendar_job",
	"ml.put_data_frame_analytics",
	"ml.put_datafeed",
	"ml.put_job",
	"ml.put_trained_model",
	"ml.put_trained_model_alias",
	"ml.put_trained_model_definition_part",
	"ml.put_trained_model_vocabulary",
	"ml.reset_job",
	"ml.revert_model_snapshot",
	"ml.start_data_frame_analytics",
	"ml.start_datafeed",
	"ml.start_trained_model_deployment",
	"ml.stop_data_frame_analytics",
	"ml.stop_datafeed",
	"ml.stop_trained_model_deployment",
	"ml.update_data_frame_analytics",
	"ml.update_datafeed",
	"ml.update_filter",
	"ml.update_job",
	"ml.update_model_snapshot",
	"ml.update_trained_model_deployment",
	"ml.upgrade_job_snapshot",
	"ml.validate",
	"ml.validate_detector",
	"monitoring.bulk",
	"nodes.clear_repositories_metering_archive",
	"nodes.get_repositories_metering_info",
	"searchable_snapshots.cache_stats",
	"security.activate_user_profile",
	"security.authenticate",
	"security.bulk_delete_role",
	"security.bulk_put_role",
	"security.bulk_update_api_keys",
	"security.change_password",
	"security.clear_api_key_cache",
	"security.clear_cached_privileges",
	"security.clear_cached_realms",
	"security.clear_cached_roles",
	"security.clear_cached_service_tokens",
	"security.create_api_key",
	"security.create_cross_cluster_api_key",
	"security.create_service_token",
	"security.delete_privileges",
	"security.delete_role",
	"security.delete_role_mapping",
	"security.delete_service_token",
	"security.delete_user",
	"security.disable_user",
	"security.disable_user_profile",
	"security.enable_user",
	"security.enable_user_profile",
	"security.enroll_kibana",
	"security.enroll_node",
	"security.get_api_key",
	"security.get_builtin_privileges",
	"security.get_privileges",
	"security.get_role",
	"security.get_role_mapping",
	"security.get_service_accounts",
	"security.get_service_credentials",
	"security.get_settings",
	"security.get_token",
	"security.get_user",
	"security.get_user_privileges",
	"security.get_user_profile",
	"security.grant_api_key",
	"security.has_privileges",
	"security.has_privileges_user_profile",
	"security.invalidate_api_key",
	"security.invalidate_token",
	"security.oidc_authenticate",
	"security.oidc_logout",
	"security.oidc_prepare_authentication",
	"security.put_privileges",
	"security.put_role",
	"security.put_role_mapping",
	"security.put_user",
	"security.query_api_keys",
	"security.query_role",
	"security.query_user",
	"security.saml_authenticate",
	"security.saml_complete_logout",
	"security.saml_invalidate",
	"security.saml_logout",
	"security.saml_prepare_authentication",
	"security.saml_service_provider_metadata",
	"security.suggest_user_profiles",
	"security.update_api_key",
	"security.update_cross_cluster_api_key",
	"security.update_settings",
	"security.update_user_profile_data",
	"text_structure.find_structure",
	"transform.get_transform_stats",
	"watcher.query_watches",
	"xpack.usage",
}

// --- Wire-Conformance Recording Transport ---

type wireConformanceTransport struct {
	base            http.RoundTripper
	validator       *compliance.SpecSchemaValidator
	mu              sync.Mutex
	totalResponses  int
	validatedCounts map[string]int
	violations      []string
}

func newWireConformanceTransport(validator *compliance.SpecSchemaValidator) *wireConformanceTransport {
	return &wireConformanceTransport{
		base:            http.DefaultTransport,
		validator:       validator,
		validatedCounts: make(map[string]int),
	}
}

func (wt *wireConformanceTransport) recordViolationf(format string, args ...any) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	wt.violations = append(wt.violations, fmt.Sprintf(format, args...))
}

func (wt *wireConformanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := wt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	var bodyBytes []byte
	if resp.Body != nil && req.Method != http.MethodHead {
		bodyBytes, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	wt.mu.Lock()
	wt.totalResponses++
	wt.mu.Unlock()

	// 1. Mandatory Elastic v8 product-check header on EVERY HTTP response
	productHeader := resp.Header.Get("X-Elastic-Product")
	if productHeader != "Elasticsearch" {
		wt.recordViolationf("%s %s (HTTP %d): missing or invalid X-Elastic-Product=%q (want \"Elasticsearch\")",
			req.Method, req.URL.Path, resp.StatusCode, productHeader)
	}

	// 2. Media-type check on JSON responses
	trimmed := bytes.TrimSpace(bodyBytes)
	ct := resp.Header.Get("Content-Type")
	isJSONBody := len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
	if req.Method != http.MethodHead && (isJSONBody || strings.Contains(strings.ToLower(ct), "json")) {
		mediaType, params, parseErr := mime.ParseMediaType(ct)
		if parseErr != nil {
			wt.recordViolationf("%s %s (HTTP %d): invalid Content-Type %q: %v",
				req.Method, req.URL.Path, resp.StatusCode, ct, parseErr)
		} else {
			validMedia := mediaType == "application/json" ||
				(mediaType == "application/vnd.elasticsearch+json" && params["compatible-with"] == "8")
			if !validMedia {
				wt.recordViolationf("%s %s (HTTP %d): unexpected JSON Content-Type %q (mediaType=%q params=%v)",
					req.Method, req.URL.Path, resp.StatusCode, ct, mediaType, params)
			}
		}
	}

	// 3. Upstream elastic/elasticsearch-specification schema.json validation via compliance.SpecSchemaValidator
	// Covers JSON, HEAD (`exists`, `indices.exists`, `indices.exists_alias`, `ping`), text/plain (`nodes.hot_threads`, `cat.*`),
	// and binary (`application/vnd.mapbox-vector-tile` `search_mvt`) responses.
	if wt.validator != nil {
		if epName := wt.validator.MatchEndpoint(req.Method, req.URL.Path, targetValidatedEndpoints...); epName != "" {
			if err := wt.validator.ValidateHTTPResponse(epName, resp.StatusCode, trimmed); err != nil {
				wt.recordViolationf("%s %s -> endpoint %q (HTTP %d) failed schema.json validation: %v",
					req.Method, req.URL.Path, epName, resp.StatusCode, err)
			} else {
				wt.mu.Lock()
				wt.validatedCounts[epName]++
				wt.mu.Unlock()
			}
		}
	}

	return resp, nil
}

func (wt *wireConformanceTransport) assertNoViolations(t *testing.T, phase string) {
	t.Helper()
	wt.mu.Lock()
	defer wt.mu.Unlock()
	if len(wt.violations) > 0 {
		msgs := strings.Join(wt.violations, "\n  - ")
		wt.violations = nil
		t.Fatalf("wire conformance violations during %s:\n  - %s", phase, msgs)
	}
}

func TestOfficialElasticGoSDKv8_Conformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Load compiled upstream schema.json via unified compliance.SpecSchemaValidator when available on disk
	schemaPath := filepath.Join("..", "..", ".cache", "es-specification", "output", "schema", "schema.json")
	if cacheDir := strings.TrimSpace(os.Getenv("CONFORMANCE_CACHE_DIR")); cacheDir != "" {
		cand := filepath.Join(cacheDir, "es-specification", "output", "schema", "schema.json")
		if _, err := os.Stat(cand); err == nil {
			schemaPath = cand
		}
	}
	var validator *compliance.SpecSchemaValidator
	if _, statErr := os.Stat(schemaPath); statErr == nil {
		var err error
		validator, err = compliance.LoadSpecSchemaValidator(schemaPath)
		if err != nil {
			t.Fatalf("failed to load upstream schema.json from %s: %v", schemaPath, err)
		}
		t.Logf("Loaded elastic/elasticsearch-specification schema.json via compliance.SpecSchemaValidator (%d endpoints, %d types)",
			validator.EndpointCount(), validator.TypeCount())
	} else {
		t.Logf("Upstream schema.json not present at %s (skipping optional wire-schema AST checks; run `make conformance-fetch` to enable)", schemaPath)
	}

	targetURL := strings.TrimSpace(os.Getenv("DORIS_ES_PROXY_URL"))
	targetMode := "live-doris-proxy"
	isInProcess := targetURL == ""
	if isInProcess {
		targetMode = "in-process-memory-backend"
		srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
		if v, ok := any(srv).(interface{ SetTargetESVersion(string) }); ok {
			v.SetTargetESVersion("8.15.5")
		}
		srv.SetAuth("elastic", "sdk-conformance-pass", "")
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		targetURL = ts.URL
	}
	t.Logf("Running official elastic/go-elasticsearch/v8 conformance against %s (%s)", targetURL, targetMode)

	wireTransport := newWireConformanceTransport(validator)
	esCfg := elasticsearch.Config{
		Addresses: []string{targetURL},
		Transport: wireTransport,
	}
	if isInProcess {
		esCfg.Username = "elastic"
		esCfg.Password = "sdk-conformance-pass"
	} else {
		if u := strings.TrimSpace(os.Getenv("DORIS_ES_PROXY_USER")); u != "" {
			esCfg.Username = u
		}
		if p := os.Getenv("DORIS_ES_PROXY_PASS"); p != "" {
			esCfg.Password = p
		}
	}

	esClient, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		t.Fatalf("elasticsearch.NewClient failed: %v", err)
	}
	typedClient, err := elasticsearch.NewTypedClient(esCfg)
	if err != nil {
		t.Fatalf("elasticsearch.NewTypedClient failed: %v", err)
	}

	idx := fmt.Sprintf("sdk_v8_orders_%d", time.Now().UnixNano())
	aliasName := idx + "_alias"
	pipelineID := fmt.Sprintf("sdk_v8_pipe_%d", time.Now().UnixNano())
	indexDeleted := false
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		if !indexDeleted {
			_, _ = typedClient.Indices.Delete(idx).Do(cleanCtx)
		}
		if res, delErr := esClient.Ingest.DeletePipeline(pipelineID, esClient.Ingest.DeletePipeline.WithContext(cleanCtx)); delErr == nil && res != nil {
			_ = res.Body.Close()
		}
	})

	// 1. Cluster Info, Ping, and Health
	infoRes, err := typedClient.Info().Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Info() failed: %v", err)
	}
	if infoRes.ClusterName == "" || infoRes.Version.Int == "" {
		t.Fatalf("unexpected Info() response: %+v", infoRes)
	}

	pingOK, err := typedClient.Ping().IsSuccess(ctx)
	if err != nil || !pingOK {
		t.Fatalf("typedClient.Ping() failed: ok=%v err=%v", pingOK, err)
	}
	if _, err := typedClient.Ping().Do(ctx); err != nil {
		t.Fatalf("typedClient.Ping().Do(ctx) failed: %v", err)
	}

	healthRes, err := typedClient.Cluster.Health().Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Cluster.Health() failed: %v", err)
	}
	if healthRes.ClusterName == "" || healthRes.NumberOfNodes < 1 {
		t.Fatalf("unexpected Cluster.Health() response: %+v", healthRes)
	}
	wireTransport.assertNoViolations(t, "cluster info/ping/health")

	// 2. Strongly-typed Index Creation, Exists, GetMapping, PutAlias, GetAlias
	mapping := &types.TypeMapping{
		Properties: map[string]types.Property{
			"title":      types.NewTextProperty(),
			"category":   types.NewKeywordProperty(),
			"quantity":   types.NewLongNumberProperty(),
			"amount":     types.NewDoubleNumberProperty(),
			"active":     types.NewBooleanProperty(),
			"created_at": types.NewDateProperty(),
			"items": &types.NestedProperty{
				Type: "nested",
				Properties: map[string]types.Property{
					"sku":   types.NewKeywordProperty(),
					"qty":   types.NewLongNumberProperty(),
					"price": types.NewDoubleNumberProperty(),
				},
			},
		},
	}

	var createErr error
	for attempt := 1; attempt <= 10; attempt++ {
		createRes, cErr := typedClient.Indices.Create(idx).Mappings(mapping).Do(ctx)
		if cErr == nil && createRes != nil && createRes.Acknowledged {
			createErr = nil
			break
		}
		createErr = cErr
		if createErr != nil && strings.Contains(createErr.Error(), "Failed to find enough backend") && attempt < 10 {
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	if createErr != nil {
		t.Fatalf("typedClient.Indices.Create(%s) failed: %v", idx, createErr)
	}

	idxExists, err := typedClient.Indices.Exists(idx).IsSuccess(ctx)
	if err != nil || !idxExists {
		t.Fatalf("typedClient.Indices.Exists(%s) failed: exists=%v err=%v", idx, idxExists, err)
	}

	getMappingRes, err := typedClient.Indices.GetMapping().Index(idx).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Indices.GetMapping(%s) failed: %v", idx, err)
	}
	idxMapRecord, ok := getMappingRes[idx]
	if !ok || len(idxMapRecord.Mappings.Properties) < 7 {
		t.Fatalf("expected >= 7 mapped properties on %s, got: %+v", idx, getMappingRes)
	}

	putAliasRes, err := typedClient.Indices.PutAlias(idx, aliasName).Do(ctx)
	if err != nil || !putAliasRes.Acknowledged {
		t.Fatalf("typedClient.Indices.PutAlias(%s, %s) failed: res=%+v err=%v", idx, aliasName, putAliasRes, err)
	}

	getAliasRes, err := typedClient.Indices.GetAlias().Index(idx).Name(aliasName).Do(ctx)
	if err != nil || len(getAliasRes) == 0 {
		t.Fatalf("typedClient.Indices.GetAlias(%s, %s) failed: res=%+v err=%v", idx, aliasName, getAliasRes, err)
	}
	wireTransport.assertNoViolations(t, "indices lifecycle & aliases")

	// 3. Single-document CRUD (Index, Get, Exists, Update, Delete)
	doc1 := sdkOrderDoc{
		Title:     "Enterprise Analytics Subscription",
		Category:  "analytics",
		Quantity:  2,
		Amount:    120.50,
		Active:    true,
		CreatedAt: "2026-11-01T10:00:00Z",
		Items: []sdkOrderItem{
			{SKU: "SKU-AN-1", Qty: 2, Price: 60.25},
		},
	}
	idxDocRes, err := typedClient.Index(idx).Id("order-1").Document(doc1).Refresh(refresh.True).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Index(order-1) failed: %v", err)
	}
	if idxDocRes.Id_ != "order-1" {
		t.Fatalf("expected _id=order-1, got %q", idxDocRes.Id_)
	}

	getDocRes, err := typedClient.Get(idx, "order-1").Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Get(order-1) failed: %v", err)
	}
	if !getDocRes.Found {
		t.Fatalf("expected order-1 Found==true")
	}
	var gotOrder1 sdkOrderDoc
	if err := json.Unmarshal(getDocRes.Source_, &gotOrder1); err != nil {
		t.Fatalf("unmarshal order-1 _source failed: %v", err)
	}
	if gotOrder1.Category != "analytics" || gotOrder1.Quantity != 2 {
		t.Fatalf("unexpected order-1 _source: %+v", gotOrder1)
	}

	docExists, err := typedClient.Exists(idx, "order-1").IsSuccess(ctx)
	if err != nil || !docExists {
		t.Fatalf("typedClient.Exists(order-1) failed: exists=%v err=%v", docExists, err)
	}

	updPayload := map[string]any{"amount": 150.00, "quantity": 3}
	updDocRes, err := typedClient.Update(idx, "order-1").
		Doc(updPayload).
		Refresh(refresh.True).
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Update(order-1) failed: %v", err)
	}
	if updDocRes.Id_ != "order-1" {
		t.Fatalf("expected updated _id=order-1, got %q", updDocRes.Id_)
	}

	getAfterUpd, err := typedClient.Get(idx, "order-1").Do(ctx)
	if err != nil || !getAfterUpd.Found {
		t.Fatalf("typedClient.Get(order-1) after update failed: res=%+v err=%v", getAfterUpd, err)
	}
	if err := json.Unmarshal(getAfterUpd.Source_, &gotOrder1); err != nil {
		t.Fatalf("unmarshal updated order-1 failed: %v", err)
	}
	if gotOrder1.Amount != 150.00 || gotOrder1.Quantity != 3 {
		t.Fatalf("expected updated amount=150.00 quantity=3, got %+v", gotOrder1)
	}

	tempDoc := sdkOrderDoc{
		Title:     "Ephemeral Draft Order",
		Category:  "draft",
		Quantity:  1,
		Amount:    5.00,
		Active:    false,
		CreatedAt: "2026-11-01T12:00:00Z",
	}
	if _, err := typedClient.Index(idx).Id("order-ephemeral").Document(tempDoc).Refresh(refresh.True).Do(ctx); err != nil {
		t.Fatalf("index order-ephemeral failed: %v", err)
	}
	delDocRes, err := typedClient.Delete(idx, "order-ephemeral").Refresh(refresh.True).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Delete(order-ephemeral) failed: %v", err)
	}
	if delDocRes.Id_ != "order-ephemeral" {
		t.Fatalf("expected deleted _id=order-ephemeral, got %q", delDocRes.Id_)
	}
	ephemeralExists, err := typedClient.Exists(idx, "order-ephemeral").IsSuccess(ctx)
	if err != nil || ephemeralExists {
		t.Fatalf("expected order-ephemeral Exists==false after delete, got exists=%v err=%v", ephemeralExists, err)
	}
	wireTransport.assertNoViolations(t, "single-document CRUD")

	// 4. Streaming Bulk Ingestion via esutil.NewBulkIndexer + Indices.Refresh
	bulkDocs := []struct {
		id  string
		doc sdkOrderDoc
	}{
		{
			id: "order-2",
			doc: sdkOrderDoc{
				Title:     "Realtime Analytics Engine Pack",
				Category:  "analytics",
				Quantity:  5,
				Amount:    250.00,
				Active:    true,
				CreatedAt: "2026-11-01T15:30:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AN-1", Qty: 3, Price: 50.00},
					{SKU: "SKU-AN-2", Qty: 2, Price: 50.00},
				},
			},
		},
		{
			id: "order-3",
			doc: sdkOrderDoc{
				Title:     "Cloud Storage Analytics Connector",
				Category:  "storage",
				Quantity:  4,
				Amount:    80.00,
				Active:    true,
				CreatedAt: "2026-11-02T09:15:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AN-1", Qty: 4, Price: 20.00},
				},
			},
		},
		{
			id: "order-4",
			doc: sdkOrderDoc{
				Title:     "Legacy Archive Backup",
				Category:  "archive",
				Quantity:  1,
				Amount:    25.00,
				Active:    false,
				CreatedAt: "2026-11-02T18:00:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AR-9", Qty: 1, Price: 25.00},
				},
			},
		},
	}

	bulkIndexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:  esClient,
		Index:   idx,
		Refresh: "true",
	})
	if err != nil {
		t.Fatalf("esutil.NewBulkIndexer failed: %v", err)
	}
	for _, item := range bulkDocs {
		payload, mErr := json.Marshal(item.doc)
		if mErr != nil {
			t.Fatalf("marshal bulk doc %s: %v", item.id, mErr)
		}
		if addErr := bulkIndexer.Add(ctx, esutil.BulkIndexerItem{
			Action:     "index",
			DocumentID: item.id,
			Body:       bytes.NewReader(payload),
		}); addErr != nil {
			t.Fatalf("bulkIndexer.Add(%s) failed: %v", item.id, addErr)
		}
	}
	if err := bulkIndexer.Close(ctx); err != nil {
		t.Fatalf("bulkIndexer.Close failed: %v", err)
	}
	bulkStats := bulkIndexer.Stats()
	if bulkStats.NumFailed != 0 || bulkStats.NumFlushed != uint64(len(bulkDocs)) {
		t.Fatalf("unexpected BulkIndexer stats: flushed=%d failed=%d", bulkStats.NumFlushed, bulkStats.NumFailed)
	}

	if _, err := typedClient.Indices.Refresh().Index(idx).Do(ctx); err != nil {
		t.Fatalf("typedClient.Indices.Refresh(%s) failed: %v", idx, err)
	}
	wireTransport.assertNoViolations(t, "BulkIndexer & Refresh")

	// 5. Typed Multi-Get (Mget)
	mgetRes, err := typedClient.Mget().
		Index(idx).
		Ids("order-1", "order-2", "order-3", "nonexistent-order").
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Mget() failed: %v", err)
	}
	if len(mgetRes.Docs) != 4 {
		t.Fatalf("expected 4 Mget items, got %d", len(mgetRes.Docs))
	}
	foundMget := 0
	for _, item := range mgetRes.Docs {
		gr, ok := item.(*types.GetResult)
		if !ok {
			t.Fatalf("expected *types.GetResult in Mget response, got %T", item)
		}
		if gr.Found {
			foundMget++
			var decoded sdkOrderDoc
			if err := json.Unmarshal(gr.Source_, &decoded); err != nil {
				t.Fatalf("unmarshal Mget _source for %s: %v", gr.Id_, err)
			}
			if decoded.Title == "" {
				t.Fatalf("expected non-empty Title in Mget doc %s", gr.Id_)
			}
		}
	}
	if foundMget != 3 {
		t.Fatalf("expected 3 found documents in Mget, got %d", foundMget)
	}
	wireTransport.assertNoViolations(t, "typed Mget")

	// 6. Typed Count & Search (Bool + Match + Term + Range + Nested, Sort, Highlight, Typed Aggregations)
	countRes, err := typedClient.Count().
		Index(aliasName).
		Query(&types.Query{
			Term: map[string]types.TermQuery{
				"active": {Value: true},
			},
		}).
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Count() failed: %v", err)
	}
	if countRes.Count != 3 {
		t.Fatalf("expected Count == 3 for active orders, got %d", countRes.Count)
	}

	minAmt := types.Float64(50.0)
	minNestedQty := types.Float64(2.0)
	searchReq := &search.Request{
		Query: &types.Query{
			Bool: &types.BoolQuery{
				Must: []types.Query{
					{
						Match: map[string]types.MatchQuery{
							"title": {Query: "Analytics"},
						},
					},
				},
				Filter: []types.Query{
					{
						Term: map[string]types.TermQuery{
							"active": {Value: true},
						},
					},
					{
						Range: map[string]types.RangeQuery{
							"amount": types.NumberRangeQuery{
								Gte: &minAmt,
							},
						},
					},
					{
						Nested: &types.NestedQuery{
							Path: "items",
							Query: types.Query{
								Bool: &types.BoolQuery{
									Must: []types.Query{
										{
											Term: map[string]types.TermQuery{
												"items.sku": {Value: "SKU-AN-1"},
											},
										},
										{
											Range: map[string]types.RangeQuery{
												"items.qty": types.NumberRangeQuery{
													Gte: &minNestedQty,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Sort: []types.SortCombinations{
			types.SortOptions{
				SortOptions: map[string]types.FieldSort{
					"amount": {Order: &sortorder.Desc},
				},
			},
		},
		Highlight: &types.Highlight{
			Fields: map[string]types.HighlightField{
				"title": {},
			},
		},
		Aggregations: map[string]types.Aggregations{
			"by_category": {
				Terms: &types.TermsAggregation{
					Field: strPtr("category"),
				},
			},
			"amount_stats": {
				Stats: &types.StatsAggregation{
					Field: strPtr("amount"),
				},
			},
			"orders_by_day": {
				DateHistogram: &types.DateHistogramAggregation{
					Field:            strPtr("created_at"),
					CalendarInterval: &calendarinterval.Day,
				},
			},
			"avg_amount": {
				Avg: &types.AverageAggregation{
					Field: strPtr("amount"),
				},
			},
			"sum_quantity": {
				Sum: &types.SumAggregation{
					Field: strPtr("quantity"),
				},
			},
			"distinct_categories": {
				Cardinality: &types.CardinalityAggregation{
					Field: strPtr("category"),
				},
			},
		},
	}

	searchRes, err := typedClient.Search().Index(aliasName).Request(searchReq).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Search() failed (including strict union unmarshaling): %v", err)
	}
	if searchRes.Hits.Total == nil || searchRes.Hits.Total.Value != 3 {
		t.Fatalf("expected 3 matched hits in Search(), got %+v", searchRes.Hits.Total)
	}
	if len(searchRes.Hits.Hits) != 3 {
		t.Fatalf("expected 3 returned hits, got %d", len(searchRes.Hits.Hits))
	}
	// Verify descending amount sort (250.00 -> 150.00 -> 80.00) and highlight snippets
	var firstHitDoc sdkOrderDoc
	if err := json.Unmarshal(searchRes.Hits.Hits[0].Source_, &firstHitDoc); err != nil {
		t.Fatalf("unmarshal first search hit _source: %v", err)
	}
	if firstHitDoc.Amount != 250.00 {
		t.Fatalf("expected top sorted hit amount=250.00, got %+v", firstHitDoc)
	}
	if len(searchRes.Hits.Hits[0].Highlight["title"]) == 0 {
		t.Fatalf("expected highlight snippet on title, got %+v", searchRes.Hits.Hits[0].Highlight)
	}

	// Verify strict typed union decoding across all 6 aggregation types
	catTermsAgg, ok := searchRes.Aggregations["by_category"].(*types.StringTermsAggregate)
	if !ok {
		t.Fatalf("expected *types.StringTermsAggregate for by_category, got %T (%+v)",
			searchRes.Aggregations["by_category"], searchRes.Aggregations["by_category"])
	}
	catBuckets, ok := catTermsAgg.Buckets.([]types.StringTermsBucket)
	if !ok || len(catBuckets) != 2 {
		t.Fatalf("expected []types.StringTermsBucket with 2 buckets for by_category, got %T (%+v)",
			catTermsAgg.Buckets, catTermsAgg.Buckets)
	}
	statsAgg, ok := searchRes.Aggregations["amount_stats"].(*types.StatsAggregate)
	if !ok || statsAgg.Count != 3 || statsAgg.Sum != 480.0 {
		t.Fatalf("unexpected StatsAggregate for amount_stats: %T %+v",
			searchRes.Aggregations["amount_stats"], searchRes.Aggregations["amount_stats"])
	}
	dateHistAgg, ok := searchRes.Aggregations["orders_by_day"].(*types.DateHistogramAggregate)
	if !ok {
		t.Fatalf("expected *types.DateHistogramAggregate for orders_by_day, got %T %+v",
			searchRes.Aggregations["orders_by_day"], searchRes.Aggregations["orders_by_day"])
	}
	dayBuckets, ok := dateHistAgg.Buckets.([]types.DateHistogramBucket)
	if !ok || len(dayBuckets) != 2 {
		t.Fatalf("expected []types.DateHistogramBucket with 2 daily buckets, got %T %+v",
			dateHistAgg.Buckets, dateHistAgg.Buckets)
	}
	avgAgg, ok := searchRes.Aggregations["avg_amount"].(*types.AvgAggregate)
	if !ok || avgAgg.Value == nil || math.Abs(float64(*avgAgg.Value)-160.0) > 1e-6 {
		t.Fatalf("unexpected AvgAggregate for avg_amount: %T %+v",
			searchRes.Aggregations["avg_amount"], searchRes.Aggregations["avg_amount"])
	}
	sumAgg, ok := searchRes.Aggregations["sum_quantity"].(*types.SumAggregate)
	if !ok || sumAgg.Value == nil || float64(*sumAgg.Value) != 12.0 {
		t.Fatalf("unexpected SumAggregate for sum_quantity: %T %+v",
			searchRes.Aggregations["sum_quantity"], searchRes.Aggregations["sum_quantity"])
	}
	cardAgg, ok := searchRes.Aggregations["distinct_categories"].(*types.CardinalityAggregate)
	if !ok || cardAgg.Value != 2 {
		t.Fatalf("unexpected CardinalityAggregate for distinct_categories: %T %+v",
			searchRes.Aggregations["distinct_categories"], searchRes.Aggregations["distinct_categories"])
	}
	wireTransport.assertNoViolations(t, "typed Count & Search with Aggregations")

	// 7. Classic esapi: Cat.Indices, Cat.Health, Ingest.PutPipeline + Simulate, UpdateByQuery, DeleteByQuery, Indices.Delete
	catIdxRes, err := esClient.Cat.Indices(
		esClient.Cat.Indices.WithContext(ctx),
		esClient.Cat.Indices.WithIndex(idx),
		esClient.Cat.Indices.WithFormat("json"),
	)
	if err != nil {
		t.Fatalf("esClient.Cat.Indices failed: %v", err)
	}
	catIdxBody, _ := io.ReadAll(catIdxRes.Body)
	_ = catIdxRes.Body.Close()
	if catIdxRes.IsError() || !strings.Contains(string(catIdxBody), idx) {
		t.Fatalf("unexpected Cat.Indices response (status=%s): %s", catIdxRes.Status(), string(catIdxBody))
	}

	catHealthRes, err := esClient.Cat.Health(
		esClient.Cat.Health.WithContext(ctx),
		esClient.Cat.Health.WithFormat("json"),
	)
	if err != nil {
		t.Fatalf("esClient.Cat.Health failed: %v", err)
	}
	catHealthBody, _ := io.ReadAll(catHealthRes.Body)
	_ = catHealthRes.Body.Close()
	if catHealthRes.IsError() || len(bytes.TrimSpace(catHealthBody)) == 0 {
		t.Fatalf("unexpected Cat.Health response (status=%s): %s", catHealthRes.Status(), string(catHealthBody))
	}

	pipeDef := `{"description":"SDK v8 conformance pipeline","processors":[{"lowercase":{"field":"category"}},{"set":{"field":"ingested_by","value":"go-es-v8"}}]}`
	putPipeRes, err := esClient.Ingest.PutPipeline(
		pipelineID,
		strings.NewReader(pipeDef),
		esClient.Ingest.PutPipeline.WithContext(ctx),
	)
	if err != nil {
		t.Fatalf("esClient.Ingest.PutPipeline failed: %v", err)
	}
	_ = putPipeRes.Body.Close()
	if putPipeRes.IsError() {
		t.Fatalf("PutPipeline returned error status: %s", putPipeRes.Status())
	}

	simBody := `{"docs":[{"_source":{"category":"ANALYTICS_UPPER"}}]}`
	simRes, err := esClient.Ingest.Simulate(
		strings.NewReader(simBody),
		esClient.Ingest.Simulate.WithContext(ctx),
		esClient.Ingest.Simulate.WithPipelineID(pipelineID),
	)
	if err != nil {
		t.Fatalf("esClient.Ingest.Simulate failed: %v", err)
	}
	simRaw, _ := io.ReadAll(simRes.Body)
	_ = simRes.Body.Close()
	if simRes.IsError() || !strings.Contains(string(simRaw), `"analytics_upper"`) || !strings.Contains(string(simRaw), `"go-es-v8"`) {
		t.Fatalf("unexpected Ingest.Simulate response (status=%s): %s", simRes.Status(), string(simRaw))
	}

	// 8. Round 61: +12 Expanded Official Go SDK v8 Conformance Subtests (typedapi + esapi)
	t.Run("Round61_01_ClusterSettings_Stats_And_NodesTelemetry", func(t *testing.T) {
		putSetRes, err := esClient.Cluster.PutSettings(
			strings.NewReader(`{"transient":{"indices.recovery.max_bytes_per_sec":"50mb"}}`),
			esClient.Cluster.PutSettings.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Cluster.PutSettings failed: %v", err)
		}
		putSetRaw, _ := io.ReadAll(putSetRes.Body)
		_ = putSetRes.Body.Close()
		if putSetRes.IsError() || !strings.Contains(string(putSetRaw), `"acknowledged":true`) {
			t.Fatalf("unexpected Cluster.PutSettings response (%s): %s", putSetRes.Status(), string(putSetRaw))
		}
		t.Cleanup(func() {
			r, rErr := esClient.Cluster.PutSettings(
				strings.NewReader(`{"transient":{"indices.recovery.max_bytes_per_sec":null}}`),
				esClient.Cluster.PutSettings.WithContext(context.Background()),
			)
			if rErr == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		getSetRes, err := esClient.Cluster.GetSettings(
			esClient.Cluster.GetSettings.WithContext(ctx),
			esClient.Cluster.GetSettings.WithIncludeDefaults(true),
		)
		if err != nil {
			t.Fatalf("Cluster.GetSettings failed: %v", err)
		}
		getSetRaw, _ := io.ReadAll(getSetRes.Body)
		_ = getSetRes.Body.Close()
		if getSetRes.IsError() || !strings.Contains(string(getSetRaw), `"transient"`) {
			t.Fatalf("unexpected Cluster.GetSettings response (%s): %s", getSetRes.Status(), string(getSetRaw))
		}

		cStatsRes, err := esClient.Cluster.Stats(esClient.Cluster.Stats.WithContext(ctx))
		if err != nil {
			t.Fatalf("Cluster.Stats failed: %v", err)
		}
		cStatsRaw, _ := io.ReadAll(cStatsRes.Body)
		_ = cStatsRes.Body.Close()
		if cStatsRes.IsError() || !strings.Contains(string(cStatsRaw), `"cluster_name"`) {
			t.Fatalf("unexpected Cluster.Stats response (%s): %s", cStatsRes.Status(), string(cStatsRaw))
		}

		nStatsRes, err := esClient.Nodes.Stats(esClient.Nodes.Stats.WithContext(ctx))
		if err != nil {
			t.Fatalf("Nodes.Stats failed: %v", err)
		}
		nStatsRaw, _ := io.ReadAll(nStatsRes.Body)
		_ = nStatsRes.Body.Close()
		if nStatsRes.IsError() || !strings.Contains(string(nStatsRaw), `"nodes"`) {
			t.Fatalf("unexpected Nodes.Stats response (%s): %s", nStatsRes.Status(), string(nStatsRaw))
		}
		wireTransport.assertNoViolations(t, "Round61_01_ClusterSettings_Stats_And_NodesTelemetry")
	})

	t.Run("Round61_02_IndexSettings_PutMapping_And_GetFieldMapping", func(t *testing.T) {
		putIdxSetRes, err := esClient.Indices.PutSettings(
			strings.NewReader(`{"index":{"number_of_replicas":0}}`),
			esClient.Indices.PutSettings.WithIndex(idx),
			esClient.Indices.PutSettings.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.PutSettings failed: %v", err)
		}
		_ = putIdxSetRes.Body.Close()
		if putIdxSetRes.IsError() {
			t.Fatalf("Indices.PutSettings returned error: %s", putIdxSetRes.Status())
		}

		getIdxSetRes, err := typedClient.Indices.GetSettings().Index(idx).Do(ctx)
		if err != nil {
			t.Fatalf("typedClient.Indices.GetSettings failed: %v", err)
		}
		if _, ok := getIdxSetRes[idx]; !ok {
			t.Fatalf("expected index %q in GetSettings response: %+v", idx, getIdxSetRes)
		}

		putMapRes, err := typedClient.Indices.PutMapping(idx).
			Properties(map[string]types.Property{
				"region": types.NewKeywordProperty(),
			}).
			Do(ctx)
		if err != nil || !putMapRes.Acknowledged {
			t.Fatalf("typedClient.Indices.PutMapping failed: res=%+v err=%v", putMapRes, err)
		}

		fieldMapRes, err := typedClient.Indices.GetFieldMapping("region").Index(idx).Do(ctx)
		if err != nil {
			t.Fatalf("typedClient.Indices.GetFieldMapping failed: %v", err)
		}
		if rec, ok := fieldMapRes[idx]; !ok || len(rec.Mappings) == 0 {
			t.Fatalf("expected region mapping in GetFieldMapping response: %+v", fieldMapRes)
		}
		wireTransport.assertNoViolations(t, "Round61_02_IndexSettings_PutMapping_And_GetFieldMapping")
	})

	t.Run("Round61_03_ComponentAndComposableIndexTemplates", func(t *testing.T) {
		compName := fmt.Sprintf("sdk_v8_comp_%d", time.Now().UnixNano())
		tmplName := fmt.Sprintf("sdk_v8_it_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Indices.DeleteIndexTemplate(tmplName); e == nil && r != nil {
				_ = r.Body.Close()
			}
			if r, e := esClient.Cluster.DeleteComponentTemplate(compName); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		putCompRes, err := esClient.Cluster.PutComponentTemplate(
			compName,
			strings.NewReader(`{"template":{"settings":{"number_of_shards":1}}}`),
			esClient.Cluster.PutComponentTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("PutComponentTemplate failed: %v", err)
		}
		_ = putCompRes.Body.Close()
		if putCompRes.IsError() {
			t.Fatalf("PutComponentTemplate status: %s", putCompRes.Status())
		}

		tmplBody := fmt.Sprintf(`{"index_patterns":["%s_tmpl_*"],"composed_of":[%q],"priority":300,"template":{"mappings":{"properties":{"host":{"type":"keyword"}}}}}`, idx, compName)
		putTmplRes, err := esClient.Indices.PutIndexTemplate(
			tmplName,
			strings.NewReader(tmplBody),
			esClient.Indices.PutIndexTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("PutIndexTemplate failed: %v", err)
		}
		_ = putTmplRes.Body.Close()
		if putTmplRes.IsError() {
			t.Fatalf("PutIndexTemplate status: %s", putTmplRes.Status())
		}

		getTmplRes, err := esClient.Indices.GetIndexTemplate(
			esClient.Indices.GetIndexTemplate.WithName(tmplName),
			esClient.Indices.GetIndexTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("GetIndexTemplate failed: %v", err)
		}
		getTmplRaw, _ := io.ReadAll(getTmplRes.Body)
		_ = getTmplRes.Body.Close()
		if getTmplRes.IsError() || !strings.Contains(string(getTmplRaw), tmplName) {
			t.Fatalf("unexpected GetIndexTemplate (%s): %s", getTmplRes.Status(), string(getTmplRaw))
		}
		wireTransport.assertNoViolations(t, "Round61_03_ComponentAndComposableIndexTemplates")
	})

	t.Run("Round61_04_FieldCaps_TypedAPI", func(t *testing.T) {
		fcRes, err := typedClient.FieldCaps().
			Index(idx).
			Fields("title", "category", "amount").
			Do(ctx)
		if err != nil {
			t.Fatalf("typedClient.FieldCaps() failed: %v", err)
		}
		if len(fcRes.Fields) < 3 {
			t.Fatalf("expected >= 3 fields in FieldCaps response, got %+v", fcRes.Fields)
		}
		if _, ok := fcRes.Fields["category"]; !ok {
			t.Fatalf("expected category in FieldCaps response: %+v", fcRes.Fields)
		}
		wireTransport.assertNoViolations(t, "Round61_04_FieldCaps_TypedAPI")
	})

	t.Run("Round61_05_MultiSearch_Msearch", func(t *testing.T) {
		ndjson := "{}\n" +
			`{"query":{"term":{"category":"analytics"}}}` + "\n" +
			"{}\n" +
			`{"query":{"term":{"active":false}}}` + "\n"
		msRes, err := esClient.Msearch(
			strings.NewReader(ndjson),
			esClient.Msearch.WithIndex(idx),
			esClient.Msearch.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("esClient.Msearch failed: %v", err)
		}
		msRaw, _ := io.ReadAll(msRes.Body)
		_ = msRes.Body.Close()
		if msRes.IsError() {
			t.Fatalf("Msearch returned error (%s): %s", msRes.Status(), string(msRaw))
		}
		var parsed struct {
			Responses []struct {
				Hits struct {
					Total struct {
						Value int64 `json:"value"`
					} `json:"total"`
				} `json:"hits"`
			} `json:"responses"`
		}
		if err := json.Unmarshal(msRaw, &parsed); err != nil || len(parsed.Responses) != 2 {
			t.Fatalf("unexpected Msearch payload (err=%v): %s", err, string(msRaw))
		}
		if parsed.Responses[0].Hits.Total.Value != 2 || parsed.Responses[1].Hits.Total.Value != 1 {
			t.Fatalf("unexpected Msearch hit counts: %+v", parsed.Responses)
		}
		wireTransport.assertNoViolations(t, "Round61_05_MultiSearch_Msearch")
	})

	t.Run("Round61_06_PointInTime_And_SearchAfter_TypedAPI", func(t *testing.T) {
		pitRes, err := typedClient.OpenPointInTime(idx).KeepAlive("1m").Do(ctx)
		if err != nil || pitRes.Id == "" {
			t.Fatalf("OpenPointInTime failed: res=%+v err=%v", pitRes, err)
		}
		pitClosed := false
		t.Cleanup(func() {
			if !pitClosed {
				_, _ = typedClient.ClosePointInTime().Id(pitRes.Id).Do(context.Background())
			}
		})

		page1, err := typedClient.Search().Request(&search.Request{
			Size: intPtr(2),
			Pit:  &types.PointInTimeReference{Id: pitRes.Id},
			Sort: []types.SortCombinations{
				types.SortOptions{
					SortOptions: map[string]types.FieldSort{
						"amount": {Order: &sortorder.Desc},
					},
				},
			},
		}).Do(ctx)
		if err != nil || len(page1.Hits.Hits) != 2 {
			t.Fatalf("PIT page1 search failed: hits=%d err=%v", len(page1.Hits.Hits), err)
		}
		cursor := page1.Hits.Hits[len(page1.Hits.Hits)-1].Sort
		if len(cursor) == 0 {
			t.Fatalf("expected non-empty sort cursor on PIT page1 last hit")
		}

		page2, err := typedClient.Search().Request(&search.Request{
			Size:        intPtr(2),
			Pit:         &types.PointInTimeReference{Id: pitRes.Id},
			SearchAfter: cursor,
			Sort: []types.SortCombinations{
				types.SortOptions{
					SortOptions: map[string]types.FieldSort{
						"amount": {Order: &sortorder.Desc},
					},
				},
			},
		}).Do(ctx)
		if err != nil || len(page2.Hits.Hits) != 2 {
			t.Fatalf("PIT page2 search_after failed: hits=%d err=%v", len(page2.Hits.Hits), err)
		}

		closeRes, err := typedClient.ClosePointInTime().Id(pitRes.Id).Do(ctx)
		if err != nil || !closeRes.Succeeded {
			t.Fatalf("ClosePointInTime failed: res=%+v err=%v", closeRes, err)
		}
		pitClosed = true
		wireTransport.assertNoViolations(t, "Round61_06_PointInTime_And_SearchAfter_TypedAPI")
	})

	t.Run("Round61_07_Scroll_And_ClearScroll", func(t *testing.T) {
		initRes, err := esClient.Search(
			esClient.Search.WithIndex(idx),
			esClient.Search.WithScroll(time.Minute),
			esClient.Search.WithSize(2),
			esClient.Search.WithBody(strings.NewReader(`{"sort":[{"quantity":"asc"}]}`)),
			esClient.Search.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("initial Scroll Search failed: %v", err)
		}
		initRaw, _ := io.ReadAll(initRes.Body)
		_ = initRes.Body.Close()
		if initRes.IsError() {
			t.Fatalf("initial Scroll Search error (%s): %s", initRes.Status(), string(initRaw))
		}
		var page struct {
			ScrollID string `json:"_scroll_id"`
			Hits     struct {
				Hits []json.RawMessage `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(initRaw, &page); err != nil || page.ScrollID == "" || len(page.Hits.Hits) != 2 {
			t.Fatalf("unexpected initial scroll payload (err=%v): %s", err, string(initRaw))
		}

		nextRes, err := esClient.Scroll(
			esClient.Scroll.WithScrollID(page.ScrollID),
			esClient.Scroll.WithScroll(time.Minute),
			esClient.Scroll.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("esClient.Scroll failed: %v", err)
		}
		nextRaw, _ := io.ReadAll(nextRes.Body)
		_ = nextRes.Body.Close()
		if nextRes.IsError() {
			t.Fatalf("Scroll page2 error (%s): %s", nextRes.Status(), string(nextRaw))
		}

		clrRes, err := esClient.ClearScroll(
			esClient.ClearScroll.WithScrollID(page.ScrollID),
			esClient.ClearScroll.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("esClient.ClearScroll failed: %v", err)
		}
		_ = clrRes.Body.Close()
		if clrRes.IsError() {
			t.Fatalf("ClearScroll error: %s", clrRes.Status())
		}
		wireTransport.assertNoViolations(t, "Round61_07_Scroll_And_ClearScroll")
	})

	t.Run("Round61_08_StoredScripts_Lifecycle_TypedAPI", func(t *testing.T) {
		scriptID := fmt.Sprintf("sdk_v8_script_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			_, _ = typedClient.DeleteScript(scriptID).Do(context.Background())
		})

		putScrRes, err := typedClient.PutScript(scriptID).
			Raw(strings.NewReader(`{"script":{"lang":"painless","source":"doc['amount'].value * params.factor"}}`)).
			Do(ctx)
		if err != nil || !putScrRes.Acknowledged {
			t.Fatalf("typedClient.PutScript failed: res=%+v err=%v", putScrRes, err)
		}

		getScrRes, err := typedClient.GetScript(scriptID).Do(ctx)
		if err != nil || !getScrRes.Found || getScrRes.Id_ != scriptID {
			t.Fatalf("typedClient.GetScript failed: res=%+v err=%v", getScrRes, err)
		}

		delScrRes, err := typedClient.DeleteScript(scriptID).Do(ctx)
		if err != nil || !delScrRes.Acknowledged {
			t.Fatalf("typedClient.DeleteScript failed: res=%+v err=%v", delScrRes, err)
		}
		wireTransport.assertNoViolations(t, "Round61_08_StoredScripts_Lifecycle_TypedAPI")
	})

	t.Run("Round61_09_Analyze_And_ValidateQuery", func(t *testing.T) {
		anRes, err := typedClient.Indices.Analyze().
			Raw(strings.NewReader(`{"analyzer":"standard","text":"Apache Doris Search Proxy"}`)).
			Do(ctx)
		if err != nil || len(anRes.Tokens) != 4 {
			t.Fatalf("typedClient.Indices.Analyze failed: tokens=%d err=%v", len(anRes.Tokens), err)
		}
		if anRes.Tokens[0].Token != "apache" {
			t.Fatalf("expected first token \"apache\", got %q", anRes.Tokens[0].Token)
		}

		valRes, err := esClient.Indices.ValidateQuery(
			esClient.Indices.ValidateQuery.WithIndex(idx),
			esClient.Indices.ValidateQuery.WithExplain(true),
			esClient.Indices.ValidateQuery.WithBody(strings.NewReader(`{"query":{"term":{"category":"analytics"}}}`)),
			esClient.Indices.ValidateQuery.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.ValidateQuery failed: %v", err)
		}
		valRaw, _ := io.ReadAll(valRes.Body)
		_ = valRes.Body.Close()
		if valRes.IsError() || !strings.Contains(string(valRaw), `"valid":true`) {
			t.Fatalf("unexpected ValidateQuery response (%s): %s", valRes.Status(), string(valRaw))
		}
		wireTransport.assertNoViolations(t, "Round61_09_Analyze_And_ValidateQuery")
	})

	t.Run("Round61_10_Explain_DocumentMatch", func(t *testing.T) {
		expRes, err := esClient.Explain(
			idx,
			"order-1",
			esClient.Explain.WithBody(strings.NewReader(`{"query":{"term":{"category":"analytics"}}}`)),
			esClient.Explain.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("esClient.Explain failed: %v", err)
		}
		expRaw, _ := io.ReadAll(expRes.Body)
		_ = expRes.Body.Close()
		if expRes.IsError() || !strings.Contains(string(expRaw), `"matched":true`) {
			t.Fatalf("unexpected Explain response (%s): %s", expRes.Status(), string(expRaw))
		}
		wireTransport.assertNoViolations(t, "Round61_10_Explain_DocumentMatch")
	})

	t.Run("Round61_11_Reindex_CopyAndVerify_TypedAPI", func(t *testing.T) {
		destIdx := idx + "_reindexed"
		t.Cleanup(func() {
			_, _ = typedClient.Indices.Delete(destIdx).Do(context.Background())
		})

		reidxRes, err := typedClient.Reindex().
			Refresh(true).
			Raw(strings.NewReader(fmt.Sprintf(`{"source":{"index":%q},"dest":{"index":%q}}`, idx, destIdx))).
			Do(ctx)
		if err != nil || reidxRes.Created == nil || *reidxRes.Created != 4 {
			t.Fatalf("typedClient.Reindex() failed: res=%+v err=%v", reidxRes, err)
		}

		destCount, err := typedClient.Count().Index(destIdx).Do(ctx)
		if err != nil || destCount.Count != 4 {
			t.Fatalf("dest Count() after Reindex = %+v, err=%v (want 4)", destCount, err)
		}

		delDest, err := typedClient.Indices.Delete(destIdx).Do(ctx)
		if err != nil || !delDest.Acknowledged {
			t.Fatalf("Delete(%s) after Reindex failed: res=%+v err=%v", destIdx, delDest, err)
		}
		wireTransport.assertNoViolations(t, "Round61_11_Reindex_CopyAndVerify_TypedAPI")
	})

	t.Run("Round61_12_UpdateAliases_ResolveIndex_And_CatSuite", func(t *testing.T) {
		swapAlias := idx + "_atomic_swap"
		updAliasRes, err := esClient.Indices.UpdateAliases(
			strings.NewReader(fmt.Sprintf(`{"actions":[{"add":{"index":%q,"alias":%q}}]}`, idx, swapAlias)),
			esClient.Indices.UpdateAliases.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.UpdateAliases(add) failed: %v", err)
		}
		_ = updAliasRes.Body.Close()
		if updAliasRes.IsError() {
			t.Fatalf("UpdateAliases(add) error: %s", updAliasRes.Status())
		}

		resolveRes, err := esClient.Indices.ResolveIndex(
			[]string{idx + "*"},
			esClient.Indices.ResolveIndex.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.ResolveIndex failed: %v", err)
		}
		resolveRaw, _ := io.ReadAll(resolveRes.Body)
		_ = resolveRes.Body.Close()
		if resolveRes.IsError() || !strings.Contains(string(resolveRaw), idx) {
			t.Fatalf("unexpected ResolveIndex response (%s): %s", resolveRes.Status(), string(resolveRaw))
		}

		catAliasesRes, err := esClient.Cat.Aliases(
			esClient.Cat.Aliases.WithName(swapAlias),
			esClient.Cat.Aliases.WithFormat("json"),
			esClient.Cat.Aliases.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Cat.Aliases failed: %v", err)
		}
		catAliasesRaw, _ := io.ReadAll(catAliasesRes.Body)
		_ = catAliasesRes.Body.Close()
		if catAliasesRes.IsError() || !strings.Contains(string(catAliasesRaw), swapAlias) {
			t.Fatalf("unexpected Cat.Aliases (%s): %s", catAliasesRes.Status(), string(catAliasesRaw))
		}

		catCountRes, err := esClient.Cat.Count(
			esClient.Cat.Count.WithIndex(idx),
			esClient.Cat.Count.WithFormat("json"),
			esClient.Cat.Count.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Cat.Count failed: %v", err)
		}
		catCountRaw, _ := io.ReadAll(catCountRes.Body)
		_ = catCountRes.Body.Close()
		if catCountRes.IsError() || !strings.Contains(string(catCountRaw), `"4"`) {
			t.Fatalf("unexpected Cat.Count (%s): %s", catCountRes.Status(), string(catCountRaw))
		}

		remAliasRes, err := esClient.Indices.UpdateAliases(
			strings.NewReader(fmt.Sprintf(`{"actions":[{"remove":{"index":%q,"alias":%q}}]}`, idx, swapAlias)),
			esClient.Indices.UpdateAliases.WithContext(ctx),
		)
		if err == nil && remAliasRes != nil {
			_ = remAliasRes.Body.Close()
		}
		wireTransport.assertNoViolations(t, "Round61_12_UpdateAliases_ResolveIndex_And_CatSuite")
	})

	// 9. Round 62: Tier-2 Official Go SDK v8 & schema.json 80+ Endpoint Expansion (Round62_01 .. Round62_08)
	t.Run("Round62_01_DataStreams_Stats_And_Rollover", func(t *testing.T) {
		dsTmpl := fmt.Sprintf("sdk_v8_ds_tmpl_%d", time.Now().UnixNano())
		dsName := fmt.Sprintf("sdk_v8_ds_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Indices.DeleteDataStream([]string{dsName}); e == nil && r != nil {
				_ = r.Body.Close()
			}
			if r, e := esClient.Indices.DeleteIndexTemplate(dsTmpl); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		dsTmplBody := fmt.Sprintf(`{"index_patterns":[%q],"data_stream":{},"priority":400,"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}}`, dsName+"*")
		putTmplRes, err := esClient.Indices.PutIndexTemplate(
			dsTmpl,
			strings.NewReader(dsTmplBody),
			esClient.Indices.PutIndexTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("PutIndexTemplate(ds) failed: %v", err)
		}
		_ = putTmplRes.Body.Close()
		if putTmplRes.IsError() {
			t.Fatalf("PutIndexTemplate(ds) error: %s", putTmplRes.Status())
		}

		createDSRes, err := esClient.Indices.CreateDataStream(
			dsName,
			esClient.Indices.CreateDataStream.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("CreateDataStream failed: %v", err)
		}
		createDSRaw, _ := io.ReadAll(createDSRes.Body)
		_ = createDSRes.Body.Close()
		if createDSRes.IsError() {
			t.Fatalf("CreateDataStream error (%s): %s", createDSRes.Status(), string(createDSRaw))
		}

		getDSRes, err := esClient.Indices.GetDataStream(
			esClient.Indices.GetDataStream.WithName(dsName),
			esClient.Indices.GetDataStream.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("GetDataStream failed: %v", err)
		}
		getDSRaw, _ := io.ReadAll(getDSRes.Body)
		_ = getDSRes.Body.Close()
		if getDSRes.IsError() || !strings.Contains(string(getDSRaw), dsName) {
			t.Fatalf("unexpected GetDataStream (%s): %s", getDSRes.Status(), string(getDSRaw))
		}

		dsStatsRes, err := esClient.Indices.DataStreamsStats(
			esClient.Indices.DataStreamsStats.WithName(dsName),
			esClient.Indices.DataStreamsStats.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("DataStreamsStats failed: %v", err)
		}
		dsStatsRaw, _ := io.ReadAll(dsStatsRes.Body)
		_ = dsStatsRes.Body.Close()
		if dsStatsRes.IsError() || !strings.Contains(string(dsStatsRaw), dsName) {
			t.Fatalf("unexpected DataStreamsStats (%s): %s", dsStatsRes.Status(), string(dsStatsRaw))
		}

		rollRes, err := esClient.Indices.Rollover(
			dsName,
			esClient.Indices.Rollover.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.Rollover failed: %v", err)
		}
		rollRaw, _ := io.ReadAll(rollRes.Body)
		_ = rollRes.Body.Close()
		if rollRes.IsError() || !strings.Contains(string(rollRaw), `"rolled_over"`) {
			t.Fatalf("unexpected Indices.Rollover (%s): %s", rollRes.Status(), string(rollRaw))
		}

		delDSRes, err := esClient.Indices.DeleteDataStream(
			[]string{dsName},
			esClient.Indices.DeleteDataStream.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("DeleteDataStream failed: %v", err)
		}
		delDSRaw, _ := io.ReadAll(delDSRes.Body)
		_ = delDSRes.Body.Close()
		if delDSRes.IsError() {
			t.Fatalf("DeleteDataStream error (%s): %s", delDSRes.Status(), string(delDSRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_01_DataStreams_Stats_And_Rollover")
	})

	t.Run("Round62_02_TemplateSim_CloseOpen_Segments_Forcemerge_ClearCache", func(t *testing.T) {
		simTmpl := fmt.Sprintf("sdk_v8_sim_%d", time.Now().UnixNano())
		maintIdx := fmt.Sprintf("sdk_v8_maint_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			_, _ = typedClient.Indices.Delete(maintIdx).Do(context.Background())
			if r, e := esClient.Indices.DeleteIndexTemplate(simTmpl); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		putSimTmpl, err := esClient.Indices.PutIndexTemplate(
			simTmpl,
			strings.NewReader(fmt.Sprintf(`{"index_patterns":[%q],"priority":250,"template":{"mappings":{"properties":{"tag":{"type":"keyword"}}}}}`, maintIdx+"*")),
			esClient.Indices.PutIndexTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("PutIndexTemplate(sim) failed: %v", err)
		}
		_ = putSimTmpl.Body.Close()

		simIdxRes, err := esClient.Indices.SimulateIndexTemplate(
			maintIdx+"_probe",
			esClient.Indices.SimulateIndexTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SimulateIndexTemplate failed: %v", err)
		}
		simIdxRaw, _ := io.ReadAll(simIdxRes.Body)
		_ = simIdxRes.Body.Close()
		if simIdxRes.IsError() {
			t.Fatalf("SimulateIndexTemplate error (%s): %s", simIdxRes.Status(), string(simIdxRaw))
		}

		simTmplRes, err := esClient.Indices.SimulateTemplate(
			esClient.Indices.SimulateTemplate.WithName(simTmpl),
			esClient.Indices.SimulateTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SimulateTemplate failed: %v", err)
		}
		simTmplRaw, _ := io.ReadAll(simTmplRes.Body)
		_ = simTmplRes.Body.Close()
		if simTmplRes.IsError() {
			t.Fatalf("SimulateTemplate error (%s): %s", simTmplRes.Status(), string(simTmplRaw))
		}

		if _, err := typedClient.Indices.Create(maintIdx).Do(ctx); err != nil {
			t.Fatalf("Create(%s) failed: %v", maintIdx, err)
		}

		closeRes, err := esClient.Indices.Close(
			[]string{maintIdx},
			esClient.Indices.Close.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.Close failed: %v", err)
		}
		closeRaw, _ := io.ReadAll(closeRes.Body)
		_ = closeRes.Body.Close()
		if closeRes.IsError() {
			t.Fatalf("Indices.Close error (%s): %s", closeRes.Status(), string(closeRaw))
		}

		openRes, err := esClient.Indices.Open(
			[]string{maintIdx},
			esClient.Indices.Open.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.Open failed: %v", err)
		}
		openRaw, _ := io.ReadAll(openRes.Body)
		_ = openRes.Body.Close()
		if openRes.IsError() {
			t.Fatalf("Indices.Open error (%s): %s", openRes.Status(), string(openRaw))
		}

		segRes, err := esClient.Indices.Segments(
			esClient.Indices.Segments.WithIndex(idx),
			esClient.Indices.Segments.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.Segments failed: %v", err)
		}
		segRaw, _ := io.ReadAll(segRes.Body)
		_ = segRes.Body.Close()
		if segRes.IsError() {
			t.Fatalf("Indices.Segments error (%s): %s", segRes.Status(), string(segRaw))
		}

		fmRes, err := esClient.Indices.Forcemerge(
			esClient.Indices.Forcemerge.WithIndex(idx),
			esClient.Indices.Forcemerge.WithMaxNumSegments(1),
			esClient.Indices.Forcemerge.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.Forcemerge failed: %v", err)
		}
		fmRaw, _ := io.ReadAll(fmRes.Body)
		_ = fmRes.Body.Close()
		if fmRes.IsError() {
			t.Fatalf("Indices.Forcemerge error (%s): %s", fmRes.Status(), string(fmRaw))
		}

		ccRes, err := esClient.Indices.ClearCache(
			esClient.Indices.ClearCache.WithIndex(idx),
			esClient.Indices.ClearCache.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Indices.ClearCache failed: %v", err)
		}
		ccRaw, _ := io.ReadAll(ccRes.Body)
		_ = ccRes.Body.Close()
		if ccRes.IsError() {
			t.Fatalf("Indices.ClearCache error (%s): %s", ccRes.Status(), string(ccRaw))
		}

		catSegRes, err := esClient.Cat.Segments(
			esClient.Cat.Segments.WithIndex(idx),
			esClient.Cat.Segments.WithFormat("json"),
			esClient.Cat.Segments.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Cat.Segments failed: %v", err)
		}
		catSegRaw, _ := io.ReadAll(catSegRes.Body)
		_ = catSegRes.Body.Close()
		if catSegRes.IsError() {
			t.Fatalf("Cat.Segments error (%s): %s", catSegRes.Status(), string(catSegRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_02_TemplateSim_CloseOpen_Segments_Forcemerge_ClearCache")
	})

	t.Run("Round62_03_Termvectors_Mtermvectors_And_RankEval", func(t *testing.T) {
		tvRes, err := esClient.Termvectors(
			idx,
			esClient.Termvectors.WithDocumentID("order-1"),
			esClient.Termvectors.WithFields("title"),
			esClient.Termvectors.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Termvectors failed: %v", err)
		}
		tvRaw, _ := io.ReadAll(tvRes.Body)
		_ = tvRes.Body.Close()
		if tvRes.IsError() {
			t.Fatalf("Termvectors error (%s): %s", tvRes.Status(), string(tvRaw))
		}

		mtvRes, err := esClient.Mtermvectors(
			esClient.Mtermvectors.WithIndex(idx),
			esClient.Mtermvectors.WithBody(strings.NewReader(`{"ids":["order-1","order-2"]}`)),
			esClient.Mtermvectors.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Mtermvectors failed: %v", err)
		}
		mtvRaw, _ := io.ReadAll(mtvRes.Body)
		_ = mtvRes.Body.Close()
		if mtvRes.IsError() {
			t.Fatalf("Mtermvectors error (%s): %s", mtvRes.Status(), string(mtvRaw))
		}

		rankEvalBody := fmt.Sprintf(`{
			"requests": [
				{
					"id": "analytics_q1",
					"request": {"query": {"match": {"title": "Analytics"}}},
					"ratings": [{"_index": %q, "_id": "order-1", "rating": 3}]
				}
			],
			"metric": {"precision": {"k": 5}}
		}`, idx)
		reRes, err := esClient.RankEval(
			strings.NewReader(rankEvalBody),
			esClient.RankEval.WithIndex(idx),
			esClient.RankEval.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("RankEval failed: %v", err)
		}
		reRaw, _ := io.ReadAll(reRes.Body)
		_ = reRes.Body.Close()
		if reRes.IsError() {
			t.Fatalf("RankEval error (%s): %s", reRes.Status(), string(reRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_03_Termvectors_Mtermvectors_And_RankEval")
	})

	t.Run("Round62_04_PainlessExecute_And_SearchTemplates", func(t *testing.T) {
		painlessRes, err := esClient.ScriptsPainlessExecute(
			esClient.ScriptsPainlessExecute.WithBody(strings.NewReader(`{"script":{"source":"params.count / params.total","params":{"count":100.0,"total":1000.0}}}`)),
			esClient.ScriptsPainlessExecute.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("ScriptsPainlessExecute failed: %v", err)
		}
		painlessRaw, _ := io.ReadAll(painlessRes.Body)
		_ = painlessRes.Body.Close()
		if painlessRes.IsError() || !strings.Contains(string(painlessRaw), `"0.1"`) {
			t.Fatalf("unexpected ScriptsPainlessExecute (%s): %s", painlessRes.Status(), string(painlessRaw))
		}

		renderRes, err := esClient.RenderSearchTemplate(
			esClient.RenderSearchTemplate.WithBody(strings.NewReader(`{"source":{"query":{"term":{"category":"{{cat}}"}}},"params":{"cat":"analytics"}}`)),
			esClient.RenderSearchTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("RenderSearchTemplate failed: %v", err)
		}
		renderRaw, _ := io.ReadAll(renderRes.Body)
		_ = renderRes.Body.Close()
		if renderRes.IsError() || !strings.Contains(string(renderRaw), `"analytics"`) {
			t.Fatalf("unexpected RenderSearchTemplate (%s): %s", renderRes.Status(), string(renderRaw))
		}

		stRes, err := esClient.SearchTemplate(
			strings.NewReader(`{"source":{"query":{"term":{"category":"{{cat}}"}}},"params":{"cat":"analytics"}}`),
			esClient.SearchTemplate.WithIndex(idx),
			esClient.SearchTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SearchTemplate failed: %v", err)
		}
		stRaw, _ := io.ReadAll(stRes.Body)
		_ = stRes.Body.Close()
		if stRes.IsError() {
			t.Fatalf("SearchTemplate error (%s): %s", stRes.Status(), string(stRaw))
		}

		mstNDJSON := "{}\n" + `{"source":{"query":{"term":{"category":"{{cat}}"}}},"params":{"cat":"analytics"}}` + "\n"
		mstRes, err := esClient.MsearchTemplate(
			strings.NewReader(mstNDJSON),
			esClient.MsearchTemplate.WithIndex(idx),
			esClient.MsearchTemplate.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("MsearchTemplate failed: %v", err)
		}
		mstRaw, _ := io.ReadAll(mstRes.Body)
		_ = mstRes.Body.Close()
		if mstRes.IsError() {
			t.Fatalf("MsearchTemplate error (%s): %s", mstRes.Status(), string(mstRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_04_PainlessExecute_And_SearchTemplates")
	})

	t.Run("Round62_05_SynonymsManagement_Lifecycle", func(t *testing.T) {
		synID := fmt.Sprintf("sdk_v8_syn_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.SynonymsDeleteSynonym(synID); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		putSynRes, err := esClient.SynonymsPutSynonym(
			synID,
			strings.NewReader(`{"synonyms_set":[{"id":"rule1","synonyms":"analytics, telemetry"}]}`),
			esClient.SynonymsPutSynonym.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SynonymsPutSynonym failed: %v", err)
		}
		putSynRaw, _ := io.ReadAll(putSynRes.Body)
		_ = putSynRes.Body.Close()
		if putSynRes.IsError() {
			t.Fatalf("SynonymsPutSynonym error (%s): %s", putSynRes.Status(), string(putSynRaw))
		}

		getSynRes, err := esClient.SynonymsGetSynonym(
			synID,
			esClient.SynonymsGetSynonym.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SynonymsGetSynonym failed: %v", err)
		}
		getSynRaw, _ := io.ReadAll(getSynRes.Body)
		_ = getSynRes.Body.Close()
		if getSynRes.IsError() || !strings.Contains(string(getSynRaw), "telemetry") {
			t.Fatalf("unexpected SynonymsGetSynonym (%s): %s", getSynRes.Status(), string(getSynRaw))
		}

		listSynRes, err := esClient.SynonymsGetSynonymsSets(
			esClient.SynonymsGetSynonymsSets.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SynonymsGetSynonymsSets failed: %v", err)
		}
		listSynRaw, _ := io.ReadAll(listSynRes.Body)
		_ = listSynRes.Body.Close()
		if listSynRes.IsError() {
			t.Fatalf("SynonymsGetSynonymsSets error (%s): %s", listSynRes.Status(), string(listSynRaw))
		}

		putRuleRes, err := esClient.SynonymsPutSynonymRule(
			strings.NewReader(`{"synonyms":"storage, warehouse"}`),
			"rule2",
			synID,
			esClient.SynonymsPutSynonymRule.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SynonymsPutSynonymRule failed: %v", err)
		}
		putRuleRaw, _ := io.ReadAll(putRuleRes.Body)
		_ = putRuleRes.Body.Close()
		if putRuleRes.IsError() {
			t.Fatalf("SynonymsPutSynonymRule error (%s): %s", putRuleRes.Status(), string(putRuleRaw))
		}

		delSynRes, err := esClient.SynonymsDeleteSynonym(
			synID,
			esClient.SynonymsDeleteSynonym.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SynonymsDeleteSynonym failed: %v", err)
		}
		delSynRaw, _ := io.ReadAll(delSynRes.Body)
		_ = delSynRes.Body.Close()
		if delSynRes.IsError() {
			t.Fatalf("SynonymsDeleteSynonym error (%s): %s", delSynRes.Status(), string(delSynRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_05_SynonymsManagement_Lifecycle")
	})

	t.Run("Round62_06_AsyncSearch_Lifecycle", func(t *testing.T) {
		subRes, err := esClient.AsyncSearch.Submit(
			esClient.AsyncSearch.Submit.WithIndex(idx),
			esClient.AsyncSearch.Submit.WithWaitForCompletionTimeout(0),
			esClient.AsyncSearch.Submit.WithKeepOnCompletion(true),
			esClient.AsyncSearch.Submit.WithBody(strings.NewReader(`{"query":{"term":{"category":"analytics"}}}`)),
			esClient.AsyncSearch.Submit.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("AsyncSearch.Submit failed: %v", err)
		}
		subRaw, _ := io.ReadAll(subRes.Body)
		_ = subRes.Body.Close()
		if subRes.IsError() {
			t.Fatalf("AsyncSearch.Submit error (%s): %s", subRes.Status(), string(subRaw))
		}
		var subParsed struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(subRaw, &subParsed); err != nil || subParsed.ID == "" {
			t.Fatalf("expected non-empty async_search id, got err=%v raw=%s", err, string(subRaw))
		}

		getAsyncRes, err := esClient.AsyncSearch.Get(
			subParsed.ID,
			esClient.AsyncSearch.Get.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("AsyncSearch.Get failed: %v", err)
		}
		getAsyncRaw, _ := io.ReadAll(getAsyncRes.Body)
		_ = getAsyncRes.Body.Close()
		if getAsyncRes.IsError() {
			t.Fatalf("AsyncSearch.Get error (%s): %s", getAsyncRes.Status(), string(getAsyncRaw))
		}

		delAsyncRes, err := esClient.AsyncSearch.Delete(
			subParsed.ID,
			esClient.AsyncSearch.Delete.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("AsyncSearch.Delete failed: %v", err)
		}
		delAsyncRaw, _ := io.ReadAll(delAsyncRes.Body)
		_ = delAsyncRes.Body.Close()
		if delAsyncRes.IsError() {
			t.Fatalf("AsyncSearch.Delete error (%s): %s", delAsyncRes.Status(), string(delAsyncRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_06_AsyncSearch_Lifecycle")
	})

	t.Run("Round62_07_SQL_ESQL_And_EQL_Queries", func(t *testing.T) {
		sqlRes, err := esClient.SQL.Query(
			strings.NewReader(fmt.Sprintf(`{"query":"SELECT category, quantity FROM \"%s\" WHERE active = true"}`, idx)),
			esClient.SQL.Query.WithFormat("json"),
			esClient.SQL.Query.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("SQL.Query failed: %v", err)
		}
		sqlRaw, _ := io.ReadAll(sqlRes.Body)
		_ = sqlRes.Body.Close()
		if sqlRes.IsError() {
			t.Fatalf("SQL.Query error (%s): %s", sqlRes.Status(), string(sqlRaw))
		}

		esqlRes, err := esClient.EsqlQuery(
			strings.NewReader(fmt.Sprintf(`{"query":"FROM %s | LIMIT 3"}`, idx)),
			esClient.EsqlQuery.WithFormat("json"),
			esClient.EsqlQuery.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("EsqlQuery failed: %v", err)
		}
		esqlRaw, _ := io.ReadAll(esqlRes.Body)
		_ = esqlRes.Body.Close()
		if esqlRes.IsError() {
			t.Fatalf("EsqlQuery error (%s): %s", esqlRes.Status(), string(esqlRaw))
		}

		eqlIdx := fmt.Sprintf("sdk_v8_eql_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			_, _ = typedClient.Indices.Delete(eqlIdx).Do(context.Background())
		})
		if _, err := typedClient.Indices.Create(eqlIdx).Mappings(&types.TypeMapping{
			Properties: map[string]types.Property{
				"@timestamp":     types.NewDateProperty(),
				"event.category": types.NewKeywordProperty(),
			},
		}).Do(ctx); err != nil {
			t.Fatalf("Create(%s) failed: %v", eqlIdx, err)
		}
		_, _ = typedClient.Index(eqlIdx).Id("ev-1").Refresh(refresh.True).
			Document(map[string]any{"@timestamp": "2026-11-01T10:00:00Z", "event": map[string]any{"category": "process"}}).
			Do(ctx)

		eqlRes, err := esClient.EqlSearch(
			eqlIdx,
			strings.NewReader(`{"query":"process where true"}`),
			esClient.EqlSearch.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("EqlSearch failed: %v", err)
		}
		eqlRaw, _ := io.ReadAll(eqlRes.Body)
		_ = eqlRes.Body.Close()
		if eqlRes.IsError() {
			t.Fatalf("EqlSearch error (%s): %s", eqlRes.Status(), string(eqlRaw))
		}
		wireTransport.assertNoViolations(t, "Round62_07_SQL_ESQL_And_EQL_Queries")
	})

	t.Run("Round62_08_TypedKnn_IfSeqNo409_ErrorSchemas_And_BulkIndexerOnFailure", func(t *testing.T) {
		knnIdx := fmt.Sprintf("sdk_v8_knn_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			_, _ = typedClient.Indices.Delete(knnIdx).Do(context.Background())
		})

		dims := 3
		knnCreateRes, err := esClient.Indices.Create(
			knnIdx,
			esClient.Indices.Create.WithBody(strings.NewReader(fmt.Sprintf(`{"mappings":{"properties":{"label":{"type":"keyword"},"vec":{"type":"dense_vector","dims":%d,"index":true,"similarity":"cosine"}}}}`, dims))),
			esClient.Indices.Create.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Create(%s) failed: %v", knnIdx, err)
		}
		_ = knnCreateRes.Body.Close()
		if knnCreateRes.IsError() {
			t.Fatalf("Create(%s) status: %s", knnIdx, knnCreateRes.Status())
		}

		_, err = typedClient.Index(knnIdx).Id("v1").Refresh(refresh.True).
			Document(map[string]any{"label": "near", "vec": []float32{0.95, 0.05, 0.0}}).Do(ctx)
		if err != nil {
			t.Fatalf("index v1 failed: %v", err)
		}
		_, err = typedClient.Index(knnIdx).Id("v2").Refresh(refresh.True).
			Document(map[string]any{"label": "far", "vec": []float32{0.0, 0.95, 0.05}}).Do(ctx)
		if err != nil {
			t.Fatalf("index v2 failed: %v", err)
		}

		knnRes, err := typedClient.Search().
			Index(knnIdx).
			Knn(types.KnnSearch{
				Field:         "vec",
				QueryVector:   []float32{1.0, 0.0, 0.0},
				K:             intPtr(1),
				NumCandidates: intPtr(5),
			}).
			Do(ctx)
		if err != nil {
			t.Fatalf("typedClient.Search().Knn() failed: %v", err)
		}
		if len(knnRes.Hits.Hits) != 1 || knnRes.Hits.Hits[0].Id_ == nil || *knnRes.Hits.Hits[0].Id_ != "v1" {
			t.Fatalf("expected top-1 Knn hit v1, got %+v", knnRes.Hits.Hits)
		}

		// Exercise 404, 400, and 409 error envelopes through wireTransport schema.json validation
		missRes, err := esClient.Get(idx, "missing-order-404", esClient.Get.WithContext(ctx))
		if err != nil {
			t.Fatalf("Get(404) transport error: %v", err)
		}
		_ = missRes.Body.Close()
		if missRes.StatusCode != http.StatusNotFound {
			t.Fatalf("expected HTTP 404 on missing doc, got %d", missRes.StatusCode)
		}

		badSearchRes, err := esClient.Search(
			esClient.Search.WithIndex(idx),
			esClient.Search.WithBody(strings.NewReader(`{"query":{"unknown_query_clause_r62":{}}}`)),
			esClient.Search.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Search(400) transport error: %v", err)
		}
		_ = badSearchRes.Body.Close()
		if badSearchRes.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 on invalid query clause, got %d", badSearchRes.StatusCode)
		}

		conflictRes, err := esClient.Index(
			idx,
			strings.NewReader(`{"title":"stale-seq-write","category":"analytics","quantity":99,"amount":1.0,"active":true,"created_at":"2026-11-01T10:00:00Z"}`),
			esClient.Index.WithDocumentID("order-1"),
			esClient.Index.WithIfSeqNo(999999),
			esClient.Index.WithIfPrimaryTerm(999),
			esClient.Index.WithContext(ctx),
		)
		if err != nil {
			t.Fatalf("Index(if_seq_no conflict) transport error: %v", err)
		}
		_ = conflictRes.Body.Close()
		if conflictRes.StatusCode != http.StatusConflict {
			t.Fatalf("expected HTTP 409 on stale if_seq_no, got %d", conflictRes.StatusCode)
		}

		// BulkIndexer OnFailure callback on duplicate "create" action
		var failedDocIDs []string
		var failMu sync.Mutex
		failIndexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
			Client:  esClient,
			Index:   idx,
			Refresh: "true",
		})
		if err != nil {
			t.Fatalf("NewBulkIndexer(OnFailure) failed: %v", err)
		}
		if err := failIndexer.Add(ctx, esutil.BulkIndexerItem{
			Action:     "create",
			DocumentID: "order-1",
			Body:       strings.NewReader(`{"title":"dup","category":"analytics","quantity":1,"amount":10.0,"active":true,"created_at":"2026-11-01T10:00:00Z"}`),
			OnFailure: func(_ context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, _ error) {
				failMu.Lock()
				defer failMu.Unlock()
				if resp.Status == http.StatusConflict {
					failedDocIDs = append(failedDocIDs, item.DocumentID)
				}
			},
		}); err != nil {
			t.Fatalf("failIndexer.Add failed: %v", err)
		}
		if err := failIndexer.Close(ctx); err != nil {
			t.Fatalf("failIndexer.Close failed: %v", err)
		}
		failStats := failIndexer.Stats()
		if failStats.NumFailed != 1 || len(failedDocIDs) != 1 || failedDocIDs[0] != "order-1" {
			t.Fatalf("expected BulkIndexer OnFailure for duplicate create order-1 (409), stats=%+v failedDocIDs=%v",
				failStats, failedDocIDs)
		}

		wireTransport.assertNoViolations(t, "Round62_08_TypedKnn_IfSeqNo409_ErrorSchemas_And_BulkIndexerOnFailure")
	})

	runRound63SDKConformanceSubtests(t, ctx, esCfg, idx, aliasName, esClient, wireTransport)
	runRound64SDKConformanceSubtests(t, ctx, idx, aliasName, esClient, wireTransport)
	runRound65SDKConformanceSubtests(t, ctx, idx, aliasName, esClient, wireTransport)
	runRound66SDKConformanceSubtests(t, ctx, idx, aliasName, esClient, wireTransport)
	runRound67InternalEndpointsSubtest(t, ctx, esClient, wireTransport)

	ubqBody := `{"query":{"term":{"category":"storage"}},"script":{"source":"ctx._source.quantity = ctx._source.quantity + params.bump","lang":"painless","params":{"bump":6}}}`
	ubqRes, err := esClient.UpdateByQuery(
		[]string{idx},
		esClient.UpdateByQuery.WithContext(ctx),
		esClient.UpdateByQuery.WithBody(strings.NewReader(ubqBody)),
		esClient.UpdateByQuery.WithRefresh(true),
	)
	if err != nil {
		t.Fatalf("esClient.UpdateByQuery failed: %v", err)
	}
	ubqRaw, _ := io.ReadAll(ubqRes.Body)
	_ = ubqRes.Body.Close()
	if ubqRes.IsError() {
		t.Fatalf("UpdateByQuery returned error status %s: %s", ubqRes.Status(), string(ubqRaw))
	}
	var ubqParsed struct {
		Updated int64 `json:"updated"`
	}
	if err := json.Unmarshal(ubqRaw, &ubqParsed); err != nil || ubqParsed.Updated != 1 {
		t.Fatalf("expected UpdateByQuery updated==1, got %+v (err=%v, raw=%s)", ubqParsed, err, string(ubqRaw))
	}

	dbqBody := `{"query":{"term":{"active":false}}}`
	dbqRes, err := esClient.DeleteByQuery(
		[]string{idx},
		strings.NewReader(dbqBody),
		esClient.DeleteByQuery.WithContext(ctx),
		esClient.DeleteByQuery.WithRefresh(true),
	)
	if err != nil {
		t.Fatalf("esClient.DeleteByQuery failed: %v", err)
	}
	dbqRaw, _ := io.ReadAll(dbqRes.Body)
	_ = dbqRes.Body.Close()
	if dbqRes.IsError() {
		t.Fatalf("DeleteByQuery returned error status %s: %s", dbqRes.Status(), string(dbqRaw))
	}
	var dbqParsed struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(dbqRaw, &dbqParsed); err != nil || dbqParsed.Deleted != 1 {
		t.Fatalf("expected DeleteByQuery deleted==1, got %+v (err=%v, raw=%s)", dbqParsed, err, string(dbqRaw))
	}

	delIdxRes, err := typedClient.Indices.Delete(idx).Do(ctx)
	if err != nil || !delIdxRes.Acknowledged {
		t.Fatalf("typedClient.Indices.Delete(%s) failed: res=%+v err=%v", idx, delIdxRes, err)
	}
	indexDeleted = true

	wireTransport.assertNoViolations(t, "esapi Cat/Ingest/UBQ/DBQ/Delete cleanup")

	// Verify wire-conformance coverage summary
	wireTransport.mu.Lock()
	totalHTTP := wireTransport.totalResponses
	validatedSnapshot := make(map[string]int, len(wireTransport.validatedCounts))
	for k, c := range wireTransport.validatedCounts {
		validatedSnapshot[k] = c
	}
	wireTransport.mu.Unlock()

	if totalHTTP < 20 {
		t.Fatalf("expected >= 20 recorded SDK HTTP responses, got %d", totalHTTP)
	}
	if len(targetValidatedEndpoints) < minValidatedEndpointsTarget {
		t.Fatalf("expected targetValidatedEndpoints ratchet >= %d, got %d", minValidatedEndpointsTarget, len(targetValidatedEndpoints))
	}
	if validator != nil {
		for _, epName := range targetValidatedEndpoints {
			if validatedSnapshot[epName] < 1 {
				t.Fatalf("expected endpoint %q to be validated against schema.json at least once, counts=%v", epName, validatedSnapshot)
			}
		}
		if len(validatedSnapshot) < minValidatedEndpointsTarget {
			t.Fatalf("expected >= %d distinct schema.json-validated endpoints, got %d", minValidatedEndpointsTarget, len(validatedSnapshot))
		}
	}
	t.Logf("Official Go SDK v8 conformance passed (%d HTTP responses verified; %d distinct schema-validated endpoints=%v)",
		totalHTTP, len(validatedSnapshot), validatedSnapshot)
}
