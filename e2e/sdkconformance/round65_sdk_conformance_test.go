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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

func runRound65SDKConformanceSubtests(
	t *testing.T,
	ctx context.Context,
	idx string,
	aliasName string,
	esClient *elasticsearch.Client,
	wireTransport *wireConformanceTransport,
) {
	t.Helper()
	_ = aliasName

	t.Run("Round65_01_SSLCertificatesDanglingShutdownAndReloadSecureSettings", func(t *testing.T) {
		sslRaw := doRawR64(t, ctx, esClient, "ssl.certificates", esapi.SSLCertificatesRequest{}, http.StatusOK)
		if !strings.Contains(sslRaw, "doris-es-proxy") {
			t.Fatalf("unexpected ssl.certificates payload: %s", sslRaw)
		}

		doJSONR64(t, ctx, esClient, "dangling_indices.import_dangling_index", esapi.DanglingIndicesImportDanglingIndexRequest{
			IndexUUID:      "r65-missing-dangling-uuid",
			AcceptDataLoss: esapi.BoolPtr(true),
		}, http.StatusNotFound)

		doJSONR64(t, ctx, esClient, "dangling_indices.delete_dangling_index", esapi.DanglingIndicesDeleteDanglingIndexRequest{
			IndexUUID:      "r65-missing-dangling-uuid",
			AcceptDataLoss: esapi.BoolPtr(true),
		}, http.StatusNotFound)

		t.Cleanup(func() {
			if r, e := (esapi.ShutdownDeleteNodeRequest{NodeID: "doris-fe-1"}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})
		doJSONR64(t, ctx, esClient, "shutdown.put_node", esapi.ShutdownPutNodeRequest{
			NodeID: "doris-fe-1",
			Body:   strings.NewReader(`{"type":"restart","reason":"r65 conformance check"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "shutdown.get_node", esapi.ShutdownGetNodeRequest{
			NodeID: "doris-fe-1",
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "shutdown.delete_node", esapi.ShutdownDeleteNodeRequest{
			NodeID: "doris-fe-1",
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "nodes.reload_secure_settings", esapi.NodesReloadSecureSettingsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "xpack.info", esapi.XPackInfoRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "migration.post_feature_upgrade", esapi.MigrationPostFeatureUpgradeRequest{}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_01_SSLCertificatesDanglingShutdownAndReloadSecureSettings")
	})

	t.Run("Round65_02_LicenseLifecycle", func(t *testing.T) {
		doJSONR64(t, ctx, esClient, "license.post", esapi.LicensePostRequest{
			Acknowledge: esapi.BoolPtr(true),
			Body: strings.NewReader(`{
				"licenses": [{
					"uid":                   "r65-lic-1",
					"type":                  "platinum",
					"issue_date_in_millis":  1700000000000,
					"expiry_date_in_millis": 4102444800000,
					"max_nodes":             1,
					"issued_to": "doris-es-proxy",
					"issuer": "elasticsearch",
					"signature": "sig"
				}]
			}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "license.post_start_basic", esapi.LicensePostStartBasicRequest{
			Acknowledge: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "license.post_start_trial", esapi.LicensePostStartTrialRequest{
			Acknowledge: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "license.get_trial_status", esapi.LicenseGetTrialStatusRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "license.delete", esapi.LicenseDeleteRequest{}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_02_LicenseLifecycle")
	})

	t.Run("Round65_03_SnapshotExtendedSearchableSnapshotsFreezeAndPromote", func(t *testing.T) {
		snapRepo := "r65_snap_repo"
		snapIdx := "sdk_r65_snap_idx"
		mountedIdx := "sdk_r65_mounted_idx"
		snapName := "r65_snap_1"
		clonedSnap := "r65_snap_1_clone"
		tplPromote := "tpl_r65_promote"
		dsPromote := "ds-r65-promote-1"

		t.Cleanup(func() {
			for _, name := range []string{dsPromote} {
				if r, e := (esapi.IndicesDeleteDataStreamRequest{Name: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			for _, name := range []string{snapIdx, mountedIdx} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.IndicesDeleteIndexTemplateRequest{Name: tplPromote}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			for _, sn := range []string{clonedSnap, snapName} {
				if r, e := (esapi.SnapshotDeleteRequest{Repository: snapRepo, Snapshot: []string{sn}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.SnapshotDeleteRepositoryRequest{Repository: []string{snapRepo}}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "indices.create("+snapIdx+")", esapi.IndicesCreateRequest{
			Index: snapIdx,
			Body:  strings.NewReader(`{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"}}}}`),
		})
		doJSONR64(t, ctx, esClient, "create("+snapIdx+"/1)", esapi.CreateRequest{
			Index:      snapIdx,
			DocumentID: "1",
			Body:       strings.NewReader(`{"title":"r65 snapshot doc","tag":"snap"}`),
			Refresh:    "true",
		})
		doJSONR64(t, ctx, esClient, "snapshot.create_repository("+snapRepo+")", esapi.SnapshotCreateRepositoryRequest{
			Repository: snapRepo,
			Body:       strings.NewReader(fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, t.TempDir())),
		})
		doJSONR64(t, ctx, esClient, "snapshot.create("+snapName+")", esapi.SnapshotCreateRequest{
			Repository:        snapRepo,
			Snapshot:          snapName,
			WaitForCompletion: esapi.BoolPtr(true),
			Body:              strings.NewReader(fmt.Sprintf(`{"indices":%q,"include_global_state":false}`, snapIdx)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "snapshot.status", esapi.SnapshotStatusRequest{
			Repository: snapRepo,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "snapshot.clone", esapi.SnapshotCloneRequest{
			Repository:     snapRepo,
			Snapshot:       snapName,
			TargetSnapshot: clonedSnap,
			Body:           strings.NewReader(fmt.Sprintf(`{"indices":%q}`, snapIdx)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "snapshot.cleanup_repository", esapi.SnapshotCleanupRepositoryRequest{
			Repository: snapRepo,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "snapshot.repository_analyze", esapi.SnapshotRepositoryAnalyzeRequest{
			Repository: snapRepo,
			BlobCount:  esapi.IntPtr(2),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "searchable_snapshots.mount", esapi.SearchableSnapshotsMountRequest{
			Repository:        snapRepo,
			Snapshot:          snapName,
			Storage:           "shared_cache",
			WaitForCompletion: esapi.BoolPtr(true),
			Body:              strings.NewReader(fmt.Sprintf(`{"index":%q,"renamed_index":%q}`, snapIdx, mountedIdx)),
		}, http.StatusOK)

		// Pending Wave-2 F25 fix: searchable_snapshots.cache_stats omits shared_cache.writes in schema.json;
		// exercised here and excluded from targetValidatedEndpoints until proxy emits writes.
		doJSONR64(t, ctx, esClient, "searchable_snapshots.cache_stats", esapi.SearchableSnapshotsCacheStatsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "searchable_snapshots.stats", esapi.SearchableSnapshotsStatsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "searchable_snapshots.clear_cache", esapi.SearchableSnapshotsClearCacheRequest{
			Index: []string{mountedIdx},
		}, http.StatusOK)

		freezeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("/%s/_freeze", snapIdx), nil)
		if err != nil {
			t.Fatalf("build freeze request failed: %v", err)
		}
		freezeResp, err := esClient.Perform(freezeReq)
		if err != nil {
			t.Fatalf("POST /%s/_freeze failed: %v", snapIdx, err)
		}
		_, _ = io.ReadAll(freezeResp.Body)
		_ = freezeResp.Body.Close()
		if freezeResp.StatusCode != http.StatusOK {
			t.Fatalf("POST /%s/_freeze unexpected status %d", snapIdx, freezeResp.StatusCode)
		}

		doJSONR64(t, ctx, esClient, "indices.unfreeze", esapi.IndicesUnfreezeRequest{
			Index: snapIdx,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.put_index_template("+tplPromote+")", esapi.IndicesPutIndexTemplateRequest{
			Name: tplPromote,
			Body: strings.NewReader(`{
				"index_patterns": ["ds-r65-promote-*"],
				"data_stream": {},
				"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}}}}
			}`),
		})
		doJSONR64(t, ctx, esClient, "indices.create_data_stream("+dsPromote+")", esapi.IndicesCreateDataStreamRequest{
			Name: dsPromote,
		})
		doJSONR64(t, ctx, esClient, "indices.promote_data_stream", esapi.IndicesPromoteDataStreamRequest{
			Name: dsPromote,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_03_SnapshotExtendedSearchableSnapshotsFreezeAndPromote")
	})

	t.Run("Round65_04_IngestGeoIPGraphTextStructureProfilingAndAutoscaling", func(t *testing.T) {
		geoID := "r65-geoip-db"
		asPol := "r65_as_pol"
		t.Cleanup(func() {
			if r, e := (esapi.IngestDeleteGeoipDatabaseRequest{DocumentID: []string{geoID}}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.AutoscalingDeleteAutoscalingPolicyRequest{Name: asPol}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "ingest.put_geoip_database", esapi.IngestPutGeoipDatabaseRequest{
			DocumentID: geoID,
			Body:       strings.NewReader(`{"database_file":"GeoLite2-City.mmdb","name":"r65-geoip"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ingest.get_geoip_database", esapi.IngestGetGeoipDatabaseRequest{
			DocumentID: []string{geoID},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ingest.geo_ip_stats", esapi.IngestGeoIPStatsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ingest.delete_geoip_database", esapi.IngestDeleteGeoipDatabaseRequest{
			DocumentID: []string{geoID},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "simulate.ingest", esapi.SimulateIngestRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"docs":[{"_index":%q,"_source":{"title":"sim ingest doc"}}]}`, idx)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "graph.explore", esapi.GraphExploreRequest{
			Index: []string{idx},
			Body:  strings.NewReader(`{"query":{"match_all":{}}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "text_structure.find_field_structure", esapi.TextStructureFindFieldStructureRequest{
			Index: idx,
			Field: "title",
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "text_structure.find_message_structure", esapi.TextStructureFindMessageStructureRequest{
			Body: strings.NewReader(`{"messages":["2026-11-01 INFO service started","2026-11-01 INFO request completed"]}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "text_structure.test_grok_pattern", esapi.TextStructureTestGrokPatternRequest{
			Body: strings.NewReader(`{"grok_pattern":"%{WORD:level} %{GREEDYDATA:msg}","messages":["INFO started ok"]}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "profiling.status", esapi.ProfilingStatusRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "profiling.stacktraces", esapi.ProfilingStacktracesRequest{
			Body: strings.NewReader(`{}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "profiling.flamegraph", esapi.ProfilingFlamegraphRequest{
			Body: strings.NewReader(`{}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "profiling.topn_functions", esapi.ProfilingTopnFunctionsRequest{
			Body: strings.NewReader(`{}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "autoscaling.put_autoscaling_policy", esapi.AutoscalingPutAutoscalingPolicyRequest{
			Name: asPol,
			Body: strings.NewReader(`{"roles":["data_content"],"deciders":{"fixed":{}}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "autoscaling.get_autoscaling_policy", esapi.AutoscalingGetAutoscalingPolicyRequest{
			Name: asPol,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "autoscaling.get_autoscaling_capacity", esapi.AutoscalingGetAutoscalingCapacityRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "autoscaling.delete_autoscaling_policy", esapi.AutoscalingDeleteAutoscalingPolicyRequest{
			Name: asPol,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_04_IngestGeoIPGraphTextStructureProfilingAndAutoscaling")
	})

	t.Run("Round65_05_SQLAsyncESQLAsyncAndCatML", func(t *testing.T) {
		var sqlAsyncID, esqlAsyncID string
		mlFilterID := "r65_ml_flt"
		mlCalID := "r65_ml_cal"
		t.Cleanup(func() {
			if sqlAsyncID != "" {
				if r, e := (esapi.SQLDeleteAsyncRequest{DocumentID: sqlAsyncID}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if esqlAsyncID != "" {
				if r, e := (esapi.EsqlAsyncQueryDeleteRequest{DocumentID: esqlAsyncID}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.MLDeleteFilterRequest{FilterID: mlFilterID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteCalendarRequest{CalendarID: mlCalID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		sqlRes := doJSONR64(t, ctx, esClient, "sql.query(async)", esapi.SQLQueryRequest{
			Format: "json",
			Body:   strings.NewReader(fmt.Sprintf(`{"query":"SELECT title FROM \"%s\"","wait_for_completion_timeout":"10s"}`, idx)),
		}, http.StatusOK)
		sqlAsyncID, _ = sqlRes["id"].(string)
		if sqlAsyncID == "" {
			t.Fatalf("expected non-empty sql async id, got %v", sqlRes)
		}

		doJSONR64(t, ctx, esClient, "sql.get_async", esapi.SQLGetAsyncRequest{
			DocumentID: sqlAsyncID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "sql.get_async_status", esapi.SQLGetAsyncStatusRequest{
			DocumentID: sqlAsyncID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "sql.delete_async", esapi.SQLDeleteAsyncRequest{
			DocumentID: sqlAsyncID,
		}, http.StatusOK)
		sqlAsyncID = ""

		esqlRes := doJSONR64(t, ctx, esClient, "esql.async_query", esapi.EsqlAsyncQueryRequest{
			Format: "json",
			Body:   strings.NewReader(fmt.Sprintf(`{"query":"FROM %s | LIMIT 2"}`, idx)),
		}, http.StatusOK)
		esqlAsyncID, _ = esqlRes["id"].(string)
		if esqlAsyncID == "" {
			t.Fatalf("expected non-empty esql async id, got %v", esqlRes)
		}

		doJSONR64(t, ctx, esClient, "esql.async_query_get", esapi.EsqlAsyncQueryGetRequest{
			DocumentID: esqlAsyncID,
		}, http.StatusOK)

		doRawR64(t, ctx, esClient, "cat.ml_datafeeds", esapi.CatMLDatafeedsRequest{Format: "json"}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.ml_trained_models", esapi.CatMLTrainedModelsRequest{Format: "json"}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.ml_data_frame_analytics", esapi.CatMLDataFrameAnalyticsRequest{Format: "json"}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ml.set_upgrade_mode", esapi.MLSetUpgradeModeRequest{
			Enabled: esapi.BoolPtr(false),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_filter", esapi.MLPutFilterRequest{
			FilterID: mlFilterID,
			Body:     strings.NewReader(`{"items":["10.0.0.1"],"description":"r65 ml filter"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_filters", esapi.MLGetFiltersRequest{
			FilterID: mlFilterID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_filter", esapi.MLDeleteFilterRequest{
			FilterID: mlFilterID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_calendar", esapi.MLPutCalendarRequest{
			CalendarID: mlCalID,
			Body:       strings.NewReader(`{"description":"r65 ml calendar"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_calendar", esapi.MLDeleteCalendarRequest{
			CalendarID: mlCalID,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_05_SQLAsyncESQLAsyncAndCatML")
	})

	t.Run("Round65_06_InferenceAndSearchApplications", func(t *testing.T) {
		infID := "r65_inf_ep"
		saName := "r65_search_app"
		baName := "r65_ba_col"
		t.Cleanup(func() {
			if r, e := (esapi.InferenceDeleteRequest{InferenceID: infID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SearchApplicationDeleteBehavioralAnalyticsRequest{Name: baName}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SearchApplicationDeleteRequest{Name: saName}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "inference.put", esapi.InferencePutRequest{
			InferenceID: infID,
			TaskType:    "text_embedding",
			Body:        strings.NewReader(`{"service":"elasticsearch","service_settings":{"model_id":".elser_model_2"}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "inference.get", esapi.InferenceGetRequest{
			InferenceID: infID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "inference.inference", esapi.InferenceInferenceRequest{
			InferenceID: infID,
			TaskType:    "text_embedding",
			Body:        strings.NewReader(`{"input":"doris search proxy inference test"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "inference.delete", esapi.InferenceDeleteRequest{
			InferenceID: infID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.put", esapi.SearchApplicationPutRequest{
			Name: saName,
			Body: strings.NewReader(fmt.Sprintf(`{"indices":[%q],"template":{"script":{"source":"{\"query\":{\"match\":{\"title\":\"{{q}}\"}}}","params":{"q":"Analytics"}}}}`, idx)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.get", esapi.SearchApplicationGetRequest{
			Name: saName,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.list", esapi.SearchApplicationListRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.render_query", esapi.SearchApplicationRenderQueryRequest{
			Name: saName,
			Body: strings.NewReader(`{"params":{"q":"Analytics"}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.search", esapi.SearchApplicationSearchRequest{
			Name: saName,
			Body: strings.NewReader(`{"params":{"q":"Analytics"}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.put_behavioral_analytics", esapi.SearchApplicationPutBehavioralAnalyticsRequest{
			Name: baName,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.post_behavioral_analytics_event", esapi.SearchApplicationPostBehavioralAnalyticsEventRequest{
			CollectionName: baName,
			EventType:      "page_view",
			Body:           strings.NewReader(`{"event":{}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.get_behavioral_analytics", esapi.SearchApplicationGetBehavioralAnalyticsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.delete_behavioral_analytics", esapi.SearchApplicationDeleteBehavioralAnalyticsRequest{
			Name: baName,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "search_application.delete", esapi.SearchApplicationDeleteRequest{
			Name: saName,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_06_InferenceAndSearchApplications")
	})

	t.Run("Round65_07_TransformLifecycle", func(t *testing.T) {
		tfSrc := "sdk_r65_tf_src"
		tfDst := "sdk_r65_tf_dst"
		tfID := "r65_tf_1"
		t.Cleanup(func() {
			if r, e := (esapi.TransformDeleteTransformRequest{TransformID: tfID, Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			for _, name := range []string{tfSrc, tfDst} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
		})

		doJSONR64(t, ctx, esClient, "indices.create("+tfSrc+")", esapi.IndicesCreateRequest{
			Index: tfSrc,
			Body:  strings.NewReader(`{"mappings":{"properties":{"category":{"type":"keyword"},"amount":{"type":"double"}}}}`),
		})
		doJSONR64(t, ctx, esClient, "create("+tfSrc+"/1)", esapi.CreateRequest{
			Index:      tfSrc,
			DocumentID: "1",
			Body:       strings.NewReader(`{"category":"analytics","amount":42.5}`),
			Refresh:    "true",
		})

		tfBody := fmt.Sprintf(`{
			"description": "r65 transform",
			"source": {"index": [%q]},
			"dest": {"index": %q},
			"frequency": "1m",
			"settings": {"max_page_search_size": 500},
			"pivot": {
				"group_by": {"category": {"terms": {"field": "category"}}},
				"aggregations": {"total_amount": {"sum": {"field": "amount"}}}
			}
		}`, tfSrc, tfDst)

		doJSONR64(t, ctx, esClient, "transform.put_transform", esapi.TransformPutTransformRequest{
			TransformID: tfID,
			Body:        strings.NewReader(tfBody),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.get_transform", esapi.TransformGetTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.update_transform", esapi.TransformUpdateTransformRequest{
			TransformID: tfID,
			Body:        strings.NewReader(`{"description":"r65 transform updated"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.preview_transform", esapi.TransformPreviewTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.start_transform", esapi.TransformStartTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		// Pending Wave-2 F8 fix: transform.get_transform_stats omits node.attributes in schema.json;
		// exercised here and excluded from targetValidatedEndpoints until proxy emits attributes.
		doJSONR64(t, ctx, esClient, "transform.get_transform_stats", esapi.TransformGetTransformStatsRequest{
			TransformID: tfID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.get_node_stats", esapi.TransformGetNodeStatsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.upgrade_transforms", esapi.TransformUpgradeTransformsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.schedule_now_transform", esapi.TransformScheduleNowTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.stop_transform", esapi.TransformStopTransformRequest{
			TransformID:       tfID,
			WaitForCompletion: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.reset_transform", esapi.TransformResetTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "transform.delete_transform", esapi.TransformDeleteTransformRequest{
			TransformID: tfID,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_07_TransformLifecycle")
	})

	t.Run("Round65_08_RollupLifecycleAndSearch", func(t *testing.T) {
		ruSrc := "sdk_r65_ru_src"
		ruDst := "sdk_r65_ru_dst"
		ruID := "r65_ru_1"
		t.Cleanup(func() {
			if r, e := (esapi.RollupStopJobRequest{JobID: ruID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.RollupDeleteJobRequest{JobID: ruID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			for _, name := range []string{ruSrc, ruDst} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
		})

		doJSONR64(t, ctx, esClient, "indices.create("+ruSrc+")", esapi.IndicesCreateRequest{
			Index: ruSrc,
			Body:  strings.NewReader(`{"mappings":{"properties":{"@timestamp":{"type":"date"},"category":{"type":"keyword"},"amount":{"type":"double"}}}}`),
		})
		doJSONR64(t, ctx, esClient, "create("+ruSrc+"/1)", esapi.CreateRequest{
			Index:      ruSrc,
			DocumentID: "1",
			Body:       strings.NewReader(`{"@timestamp":"2026-11-01T10:15:00Z","category":"analytics","amount":100.0}`),
			Refresh:    "true",
		})
		doJSONR64(t, ctx, esClient, "create("+ruSrc+"/2)", esapi.CreateRequest{
			Index:      ruSrc,
			DocumentID: "2",
			Body:       strings.NewReader(`{"@timestamp":"2026-11-01T11:30:00Z","category":"storage","amount":50.0}`),
			Refresh:    "true",
		})

		ruBody := fmt.Sprintf(`{
			"index_pattern": %q,
			"rollup_index": %q,
			"cron": "0 */5 * * * ?",
			"page_size": 100,
			"groups": {
				"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"},
				"terms": {"fields": ["category"]}
			},
			"metrics": [{"field": "amount", "metrics": ["sum", "min", "max", "avg", "value_count"]}]
		}`, ruSrc, ruDst)

		doJSONR64(t, ctx, esClient, "rollup.put_job", esapi.RollupPutJobRequest{
			JobID: ruID,
			Body:  strings.NewReader(ruBody),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.get_jobs", esapi.RollupGetJobsRequest{
			JobID: ruID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.start_job", esapi.RollupStartJobRequest{
			JobID: ruID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.get_rollup_caps", esapi.RollupGetRollupCapsRequest{
			Index: ruSrc,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.get_rollup_index_caps", esapi.RollupGetRollupIndexCapsRequest{
			Index: ruDst,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.rollup_search", esapi.RollupRollupSearchRequest{
			Index: []string{ruDst},
			Body:  strings.NewReader(`{"size":0,"aggs":{"by_cat":{"terms":{"field":"category"}}}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.stop_job", esapi.RollupStopJobRequest{
			JobID:             ruID,
			WaitForCompletion: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "rollup.delete_job", esapi.RollupDeleteJobRequest{
			JobID: ruID,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_08_RollupLifecycleAndSearch")
	})

	t.Run("Round65_09_WatcherLifecycleAndSettings", func(t *testing.T) {
		watchID := "r65_watch_1"
		t.Cleanup(func() {
			if r, e := (esapi.WatcherDeleteWatchRequest{WatchID: watchID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.WatcherStartRequest{}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "watcher.put_watch", esapi.WatcherPutWatchRequest{
			WatchID: watchID,
			Body:    strings.NewReader(`{"trigger":{"schedule":{"interval":"10m"}},"input":{"simple":{"msg":"hi"}},"condition":{"always":{}},"actions":{"log_it":{"logging":{"text":"triggered"}}}}`),
		}, http.StatusCreated, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.get_watch", esapi.WatcherGetWatchRequest{
			WatchID: watchID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.deactivate_watch", esapi.WatcherDeactivateWatchRequest{
			WatchID: watchID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.activate_watch", esapi.WatcherActivateWatchRequest{
			WatchID: watchID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.execute_watch", esapi.WatcherExecuteWatchRequest{
			WatchID: watchID,
			Body:    strings.NewReader(`{}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.ack_watch", esapi.WatcherAckWatchRequest{
			WatchID:  watchID,
			ActionID: []string{"log_it"},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.stats", esapi.WatcherStatsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.get_settings", esapi.WatcherGetSettingsRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.update_settings", esapi.WatcherUpdateSettingsRequest{
			Body: strings.NewReader(`{"xpack.watcher.execution.scroll.size":100}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.stop", esapi.WatcherStopRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.start", esapi.WatcherStartRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.delete_watch", esapi.WatcherDeleteWatchRequest{
			WatchID: watchID,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_09_WatcherLifecycleAndSettings")
	})

	t.Run("Round65_10_DownsampleAndILMSteps", func(t *testing.T) {
		tsSrc := "sdk_r65_ts_src"
		tsDst := "sdk_r65_ts_dst"
		ilmPol := "r65_ilm_step_pol"
		ilmIdx := "sdk_r65_ilm_step_idx"
		lsPipe := "r65_logstash_pipe"
		ccrPattern := "r65_ccr_af"
		ccrFollowIdx := "sdk_r65_ccr_follow"

		t.Cleanup(func() {
			if r, e := (esapi.CCRUnfollowRequest{Index: ccrFollowIdx}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.CCRDeleteAutoFollowPatternRequest{Name: ccrPattern}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.LogstashDeletePipelineRequest{DocumentID: lsPipe}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			for _, name := range []string{tsSrc, tsDst, ilmIdx, ccrFollowIdx} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.ILMDeleteLifecycleRequest{Policy: ilmPol}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "indices.create("+tsSrc+")", esapi.IndicesCreateRequest{
			Index: tsSrc,
			Body: strings.NewReader(`{
				"settings": {
					"index.mode": "time_series",
					"index.routing_path": ["service"],
					"index.time_series.start_time": "2026-11-01T00:00:00Z",
					"index.time_series.end_time": "2026-11-02T00:00:00Z"
				},
				"mappings": {
					"properties": {
						"@timestamp": {"type": "date"},
						"service": {"type": "keyword", "time_series_dimension": true},
						"cpu": {"type": "double", "time_series_metric": "gauge"}
					}
				}
			}`),
		})
		doJSONR64(t, ctx, esClient, "index("+tsSrc+")", esapi.IndexRequest{
			Index:   tsSrc,
			Body:    strings.NewReader(`{"@timestamp":"2026-11-01T10:15:00Z","service":"api","cpu":42.5}`),
			Refresh: "true",
		}, http.StatusCreated, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.downsample", esapi.IndicesDownsampleRequest{
			Index:       tsSrc,
			TargetIndex: tsDst,
			Body:        strings.NewReader(`{"fixed_interval":"1h"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ilm.put_lifecycle("+ilmPol+")", esapi.ILMPutLifecycleRequest{
			Policy: ilmPol,
			Body:   strings.NewReader(`{"policy":{"phases":{"hot":{"actions":{}},"warm":{"min_age":"1d","actions":{}}}}}`),
		})
		doJSONR64(t, ctx, esClient, "indices.create("+ilmIdx+")", esapi.IndicesCreateRequest{
			Index: ilmIdx,
			Body:  strings.NewReader(fmt.Sprintf(`{"settings":{"index.lifecycle.name":%q}}`, ilmPol)),
		})

		doJSONR64(t, ctx, esClient, "ilm.move_to_step", esapi.ILMMoveToStepRequest{
			Index: ilmIdx,
			Body:  strings.NewReader(`{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"hot","action":"error","name":"ERROR"}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ilm.retry", esapi.ILMRetryRequest{
			Index: ilmIdx,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ilm.migrate_to_data_tiers", esapi.ILMMigrateToDataTiersRequest{
			DryRun: esapi.BoolPtr(true),
			Body:   strings.NewReader(`{}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "logstash.put_pipeline", esapi.LogstashPutPipelineRequest{
			DocumentID: lsPipe,
			Body:       strings.NewReader(`{"pipeline":"input { stdin {} } output { stdout {} }"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "logstash.delete_pipeline", esapi.LogstashDeletePipelineRequest{
			DocumentID: lsPipe,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.put_auto_follow_pattern", esapi.CCRPutAutoFollowPatternRequest{
			Name: ccrPattern,
			Body: strings.NewReader(`{"remote_cluster":"rc1","leader_index_patterns":["logs-*"]}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.pause_auto_follow_pattern", esapi.CCRPauseAutoFollowPatternRequest{
			Name: ccrPattern,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.resume_auto_follow_pattern", esapi.CCRResumeAutoFollowPatternRequest{
			Name: ccrPattern,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.delete_auto_follow_pattern", esapi.CCRDeleteAutoFollowPatternRequest{
			Name: ccrPattern,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.follow", esapi.CCRFollowRequest{
			Index: ccrFollowIdx,
			Body:  strings.NewReader(fmt.Sprintf(`{"remote_cluster":"rc1","leader_index":%q}`, idx)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.pause_follow", esapi.CCRPauseFollowRequest{
			Index: ccrFollowIdx,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.resume_follow", esapi.CCRResumeFollowRequest{
			Index: ccrFollowIdx,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.unfollow", esapi.CCRUnfollowRequest{
			Index: ccrFollowIdx,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.forget_follower", esapi.CCRForgetFollowerRequest{
			Index: ccrFollowIdx,
			Body:  strings.NewReader(fmt.Sprintf(`{"follower_index":%q,"follower_index_uuid":"r65-uuid-1","leader_remote_cluster":"rc1","leader_index":%q}`, ccrFollowIdx, idx)),
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round65_10_DownsampleAndILMSteps")
	})
}
