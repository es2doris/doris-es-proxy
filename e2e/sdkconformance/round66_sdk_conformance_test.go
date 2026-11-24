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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

func int64PtrR66(v int64) *int64 { return &v }

func runRound66SDKConformanceSubtests(
	t *testing.T,
	ctx context.Context,
	idx string,
	aliasName string,
	esClient *elasticsearch.Client,
	wireTransport *wireConformanceTransport,
) {
	t.Helper()
	_ = aliasName

	t.Run("Round66_01_RemainingNonMLSecConnEndpoints", func(t *testing.T) {
		tsSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
		ccrPattern := "r66_ccr_af_" + tsSuffix
		ccrFollowIdx := "sdk_r66_ccr_follow_" + tsSuffix
		lsPipe := "r66_ls_pipe_" + tsSuffix
		watchID := "r66_watch_" + tsSuffix

		t.Cleanup(func() {
			if r, e := (esapi.CCRUnfollowRequest{Index: ccrFollowIdx}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.CCRDeleteAutoFollowPatternRequest{Name: ccrPattern}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.IndicesDeleteRequest{Index: []string{ccrFollowIdx}}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.LogstashDeletePipelineRequest{DocumentID: lsPipe}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.WatcherDeleteWatchRequest{WatchID: watchID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		// 1. CCR remaining endpoints (get_auto_follow_pattern, follow_info, follow_stats, stats)
		doJSONR64(t, ctx, esClient, "ccr.put_auto_follow_pattern(r66)", esapi.CCRPutAutoFollowPatternRequest{
			Name: ccrPattern,
			Body: strings.NewReader(`{"remote_cluster":"rc1","leader_index_patterns":["logs-*"]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.get_auto_follow_pattern(name)", esapi.CCRGetAutoFollowPatternRequest{
			Name: ccrPattern,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.get_auto_follow_pattern(all)", esapi.CCRGetAutoFollowPatternRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.delete_auto_follow_pattern(r66)", esapi.CCRDeleteAutoFollowPatternRequest{
			Name: ccrPattern,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ccr.follow(r66)", esapi.CCRFollowRequest{
			Index: ccrFollowIdx,
			Body:  strings.NewReader(fmt.Sprintf(`{"remote_cluster":"rc1","leader_index":%q}`, idx)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.follow_info", esapi.CCRFollowInfoRequest{
			Index: []string{ccrFollowIdx},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.follow_stats", esapi.CCRFollowStatsRequest{
			Index: []string{ccrFollowIdx},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.stats", esapi.CCRStatsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ccr.unfollow(r66)", esapi.CCRUnfollowRequest{
			Index: ccrFollowIdx,
		}, http.StatusOK)

		// 2. Nodes repositories metering (get + clear archive)
		doJSONR64(t, ctx, esClient, "nodes.get_repositories_metering_info", esapi.NodesGetRepositoriesMeteringInfoRequest{
			NodeID: []string{"_all"},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "nodes.clear_repositories_metering_archive", esapi.NodesClearRepositoriesMeteringArchiveRequest{
			NodeID:            []string{"_all"},
			MaxArchiveVersion: int64PtrR66(5),
		}, http.StatusOK)

		// 3. Searchable snapshots cache_stats (Wave-2A fix)
		doJSONR64(t, ctx, esClient, "searchable_snapshots.cache_stats(r66)", esapi.SearchableSnapshotsCacheStatsRequest{}, http.StatusOK)

		// 4. Fleet secrets, search, msearch, global_checkpoints
		fleetSecRes := doJSONR64(t, ctx, esClient, "fleet.post_secret", esapi.FleetPostSecretRequest{
			Body: strings.NewReader(`{"value":"r66-fleet-secret-val"}`),
		}, http.StatusOK)
		fleetSecID, _ := fleetSecRes["id"].(string)
		if fleetSecID == "" {
			t.Fatalf("expected non-empty fleet secret id, got %v", fleetSecRes)
		}
		t.Cleanup(func() {
			if r, e := (esapi.FleetDeleteSecretRequest{DocumentID: fleetSecID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})
		doJSONR64(t, ctx, esClient, "fleet.get_secret", esapi.FleetGetSecretRequest{
			DocumentID: fleetSecID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "fleet.delete_secret", esapi.FleetDeleteSecretRequest{
			DocumentID: fleetSecID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "fleet.search", esapi.FleetSearchRequest{
			Index: idx,
			Body:  strings.NewReader(`{"query":{"match_all":{}}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "fleet.msearch", esapi.FleetMsearchRequest{
			Index: idx,
			Body:  strings.NewReader("{}\n{\"query\":{\"match_all\":{}}}\n"),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "fleet.global_checkpoints", esapi.FleetGlobalCheckpointsRequest{
			Index: idx,
		}, http.StatusOK)

		// 5. Singletons: logstash.get_pipeline, migration.get_feature_upgrade_status, monitoring.bulk,
		// text_structure.find_structure, watcher.query_watches, xpack.usage
		doRawR64(t, ctx, esClient, "logstash.put_pipeline(r66)", esapi.LogstashPutPipelineRequest{
			DocumentID: lsPipe,
			Body:       strings.NewReader(`{"pipeline":"input { stdin {} } output { stdout {} }"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "logstash.get_pipeline", esapi.LogstashGetPipelineRequest{
			DocumentID: lsPipe,
		}, http.StatusOK)
		doRawR64(t, ctx, esClient, "logstash.delete_pipeline(r66)", esapi.LogstashDeletePipelineRequest{
			DocumentID: lsPipe,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "migration.get_feature_upgrade_status", esapi.MigrationGetFeatureUpgradeStatusRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "monitoring.bulk", esapi.MonitoringBulkRequest{
			SystemID:         "beats",
			SystemAPIVersion: "8.15.5",
			Interval:         "10s",
			Body:             strings.NewReader("{\"index\":{\"_index\":\"_data\"}}\n{\"cluster_uuid\":\"r66-mon\"}\n"),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "text_structure.find_structure", esapi.TextStructureFindStructureRequest{
			Body: strings.NewReader("2026-11-01T10:00:00Z INFO started\n2026-11-01T10:01:00Z WARN done\n"),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "watcher.put_watch(r66)", esapi.WatcherPutWatchRequest{
			WatchID: watchID,
			Body:    strings.NewReader(`{"trigger":{"schedule":{"interval":"10m"}},"input":{"simple":{"msg":"r66"}},"condition":{"always":{}},"actions":{"log_it":{"logging":{"text":"ok"}}}}`),
		}, http.StatusCreated, http.StatusOK)
		doJSONR64(t, ctx, esClient, "watcher.query_watches", esapi.WatcherQueryWatchesRequest{
			Body: strings.NewReader(`{"query":{"match_all":{}}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "watcher.delete_watch(r66)", esapi.WatcherDeleteWatchRequest{
			WatchID: watchID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "xpack.usage", esapi.XPackUsageRequest{}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round66_01_RemainingNonMLSecConnEndpoints")
	})

	t.Run("Round66_02_MLFullSuite", func(t *testing.T) {
		tsSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
		jobID := "r66_ml_job_" + tsSuffix
		dfJobID := "r66_ml_df_job_" + tsSuffix
		dfID := "r66_ml_df_" + tsSuffix
		calID := "r66_ml_cal_" + tsSuffix
		fltID := "r66_ml_flt_" + tsSuffix
		mdlID := "r66_ml_mdl_" + tsSuffix
		mdlAlias := "r66_ml_alias_" + tsSuffix
		dfaID := "r66_ml_dfa_" + tsSuffix
		dfaSrcIdx := "sdk_r66_dfa_src_" + tsSuffix
		dfaDstIdx := "sdk_r66_dfa_dst_" + tsSuffix

		t.Cleanup(func() {
			if r, e := (esapi.MLStopDataFrameAnalyticsRequest{ID: dfaID, Force: esapi.BoolPtr(true), AllowNoMatch: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteDataFrameAnalyticsRequest{ID: dfaID, Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLStopTrainedModelDeploymentRequest{ModelID: mdlID, AllowNoMatch: esapi.BoolPtr(true), Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteTrainedModelAliasRequest{ModelID: mdlID, ModelAlias: mdlAlias}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteTrainedModelRequest{ModelID: mdlID, Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLStopDatafeedRequest{DatafeedID: dfID, AllowNoMatch: esapi.BoolPtr(true), Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteDatafeedRequest{DatafeedID: dfID, Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteCalendarRequest{CalendarID: calID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.MLDeleteFilterRequest{FilterID: fltID}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			for _, jid := range []string{jobID, dfJobID} {
				if r, e := (esapi.MLCloseJobRequest{JobID: jid, Force: esapi.BoolPtr(true), AllowNoMatch: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
				if r, e := (esapi.MLDeleteJobRequest{JobID: jid, Force: esapi.BoolPtr(true)}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			for _, name := range []string{dfaSrcIdx, dfaDstIdx} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
		})

		// 1. Info, Memory Stats, Estimate, Validate
		doJSONR64(t, ctx, esClient, "ml.info", esapi.MLInfoRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_memory_stats", esapi.MLGetMemoryStatsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.estimate_model_memory", esapi.MLEstimateModelMemoryRequest{
			Body: strings.NewReader(`{"analysis_config":{"detectors":[{"function":"count"}]}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.validate", esapi.MLValidateRequest{
			Body: strings.NewReader(`{"analysis_config":{"detectors":[{"function":"count"}]}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.validate_detector", esapi.MLValidateDetectorRequest{
			Body: strings.NewReader(`{"function":"count"}`),
		}, http.StatusOK)

		// 2. Anomaly Detector Job, Results, Forecasts, Model Snapshots lifecycle
		doJSONR64(t, ctx, esClient, "ml.put_job", esapi.MLPutJobRequest{
			JobID: jobID,
			Body:  strings.NewReader(`{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]},"data_description":{"time_field":"@timestamp","time_format":"epoch_ms"}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_jobs", esapi.MLGetJobsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_job_stats", esapi.MLGetJobStatsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_job", esapi.MLUpdateJobRequest{
			JobID: jobID,
			Body:  strings.NewReader(`{"description":"r66 updated ml job"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.open_job", esapi.MLOpenJobRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.post_data", esapi.MLPostDataRequest{
			JobID: jobID,
			Body:  strings.NewReader(`{"@timestamp":1700000000000,"value":42}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.flush_job", esapi.MLFlushJobRequest{JobID: jobID}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ml.get_buckets", esapi.MLGetBucketsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_overall_buckets", esapi.MLGetOverallBucketsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_records", esapi.MLGetRecordsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_categories", esapi.MLGetCategoriesRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_influencers", esapi.MLGetInfluencersRequest{JobID: jobID}, http.StatusOK)

		fcRes := doJSONR64(t, ctx, esClient, "ml.forecast", esapi.MLForecastRequest{
			JobID: jobID,
			Body:  strings.NewReader(`{}`),
		}, http.StatusOK)
		fcID, _ := fcRes["forecast_id"].(string)
		if fcID == "" {
			t.Fatalf("expected non-empty ml forecast_id, got %v", fcRes)
		}
		doJSONR64(t, ctx, esClient, "ml.delete_forecast", esapi.MLDeleteForecastRequest{
			JobID:      jobID,
			ForecastID: fcID,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ml.get_model_snapshots", esapi.MLGetModelSnapshotsRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_model_snapshot", esapi.MLUpdateModelSnapshotRequest{
			JobID:      jobID,
			SnapshotID: "1",
			Body:       strings.NewReader(`{"description":"r66 snap","retain":true}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.upgrade_job_snapshot", esapi.MLUpgradeJobSnapshotRequest{
			JobID:      jobID,
			SnapshotID: "1",
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_model_snapshot_upgrade_stats", esapi.MLGetModelSnapshotUpgradeStatsRequest{
			JobID:      jobID,
			SnapshotID: "1",
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.revert_model_snapshot", esapi.MLRevertModelSnapshotRequest{
			JobID:      jobID,
			SnapshotID: "1",
			Body:       strings.NewReader(`{}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_model_snapshot", esapi.MLDeleteModelSnapshotRequest{
			JobID:      jobID,
			SnapshotID: "1",
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ml.close_job", esapi.MLCloseJobRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.reset_job", esapi.MLResetJobRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_expired_data", esapi.MLDeleteExpiredDataRequest{JobID: jobID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_job", esapi.MLDeleteJobRequest{JobID: jobID}, http.StatusOK)

		// 3. Datafeeds lifecycle
		doJSONR64(t, ctx, esClient, "ml.put_job(df)", esapi.MLPutJobRequest{
			JobID: dfJobID,
			Body:  strings.NewReader(`{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]},"data_description":{"time_field":"created_at"}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_datafeed", esapi.MLPutDatafeedRequest{
			DatafeedID: dfID,
			Body:       strings.NewReader(fmt.Sprintf(`{"job_id":%q,"indices":[%q]}`, dfJobID, idx)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_datafeeds", esapi.MLGetDatafeedsRequest{DatafeedID: dfID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_datafeed_stats", esapi.MLGetDatafeedStatsRequest{DatafeedID: dfID}, http.StatusOK)
		doRawR64(t, ctx, esClient, "ml.preview_datafeed", esapi.MLPreviewDatafeedRequest{DatafeedID: dfID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.start_datafeed", esapi.MLStartDatafeedRequest{DatafeedID: dfID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_datafeed", esapi.MLUpdateDatafeedRequest{
			DatafeedID: dfID,
			Body:       strings.NewReader(`{"scroll_size":500}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.stop_datafeed", esapi.MLStopDatafeedRequest{DatafeedID: dfID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_datafeed", esapi.MLDeleteDatafeedRequest{DatafeedID: dfID}, http.StatusOK)

		// 4. Calendars & Filters lifecycle
		doJSONR64(t, ctx, esClient, "ml.put_calendar(r66)", esapi.MLPutCalendarRequest{
			CalendarID: calID,
			Body:       strings.NewReader(`{"description":"r66 calendar"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_calendars", esapi.MLGetCalendarsRequest{CalendarID: calID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_calendar_job", esapi.MLPutCalendarJobRequest{
			CalendarID: calID,
			JobID:      dfJobID,
		}, http.StatusOK)
		evPostRes := doJSONR64(t, ctx, esClient, "ml.post_calendar_events", esapi.MLPostCalendarEventsRequest{
			CalendarID: calID,
			Body:       strings.NewReader(`{"events":[{"description":"maint","start_time":1700000000000,"end_time":1700003600000}]}`),
		}, http.StatusOK)
		evID := ""
		if evs, ok := evPostRes["events"].([]any); ok && len(evs) > 0 {
			if ev0, ok0 := evs[0].(map[string]any); ok0 {
				evID, _ = ev0["event_id"].(string)
			}
		}
		if evID == "" {
			t.Fatalf("expected non-empty ml calendar event_id, got %v", evPostRes)
		}
		doJSONR64(t, ctx, esClient, "ml.get_calendar_events", esapi.MLGetCalendarEventsRequest{CalendarID: calID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_calendar_event", esapi.MLDeleteCalendarEventRequest{
			CalendarID: calID,
			EventID:    evID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_calendar_job", esapi.MLDeleteCalendarJobRequest{
			CalendarID: calID,
			JobID:      dfJobID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_calendar(r66)", esapi.MLDeleteCalendarRequest{CalendarID: calID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_job(df)", esapi.MLDeleteJobRequest{JobID: dfJobID}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ml.put_filter(r66)", esapi.MLPutFilterRequest{
			FilterID: fltID,
			Body:     strings.NewReader(`{"items":["10.0.0.1"],"description":"r66 flt"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_filter", esapi.MLUpdateFilterRequest{
			FilterID: fltID,
			Body:     strings.NewReader(`{"add_items":["10.0.0.2"],"description":"r66 flt updated"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_filter(r66)", esapi.MLDeleteFilterRequest{FilterID: fltID}, http.StatusOK)

		// 5. Trained Models, Definition Parts, Vocabulary, Aliases & Deployments
		doJSONR64(t, ctx, esClient, "ml.put_trained_model", esapi.MLPutTrainedModelRequest{
			ModelID: mdlID,
			Body:    strings.NewReader(`{"input":{"field_names":["title"]},"inference_config":{"text_embedding":{"vocabulary":{"index":".vocab"}}}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_trained_models", esapi.MLGetTrainedModelsRequest{ModelID: mdlID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_trained_model_definition_part", esapi.MLPutTrainedModelDefinitionPartRequest{
			ModelID: mdlID,
			Part:    intPtr(0),
			Body:    strings.NewReader(`{"definition":"part0"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_trained_model_vocabulary", esapi.MLPutTrainedModelVocabularyRequest{
			ModelID: mdlID,
			Body:    strings.NewReader(`{"vocabulary":["hello","world"]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.put_trained_model_alias", esapi.MLPutTrainedModelAliasRequest{
			ModelID:    mdlID,
			ModelAlias: mdlAlias,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.start_trained_model_deployment", esapi.MLStartTrainedModelDeploymentRequest{
			ModelID: mdlID,
			Body:    strings.NewReader(`{}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_trained_model_deployment", esapi.MLUpdateTrainedModelDeploymentRequest{
			ModelID: mdlID,
			Body:    strings.NewReader(`{"number_of_allocations":2}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_trained_models_stats", esapi.MLGetTrainedModelsStatsRequest{ModelID: mdlID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.infer_trained_model", esapi.MLInferTrainedModelRequest{
			ModelID: mdlID,
			Body:    strings.NewReader(`{"docs":[{"title":"doris search"}]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.clear_trained_model_deployment_cache", esapi.MLClearTrainedModelDeploymentCacheRequest{
			ModelID: mdlID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.stop_trained_model_deployment", esapi.MLStopTrainedModelDeploymentRequest{
			ModelID: mdlID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_trained_model_alias", esapi.MLDeleteTrainedModelAliasRequest{
			ModelID:    mdlID,
			ModelAlias: mdlAlias,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_trained_model", esapi.MLDeleteTrainedModelRequest{ModelID: mdlID}, http.StatusOK)

		// 6. Data Frame Analytics & Evaluate
		doJSONR64(t, ctx, esClient, "indices.create("+dfaSrcIdx+")", esapi.IndicesCreateRequest{
			Index: dfaSrcIdx,
			Body:  strings.NewReader(`{"mappings":{"properties":{"actual":{"type":"double"},"predicted":{"type":"double"},"feature":{"type":"double"}}}}`),
		})
		doJSONR64(t, ctx, esClient, "create("+dfaSrcIdx+"/1)", esapi.CreateRequest{
			Index:      dfaSrcIdx,
			DocumentID: "1",
			Body:       strings.NewReader(`{"actual":10.0,"predicted":9.5,"feature":1.0}`),
			Refresh:    "true",
		})
		doJSONR64(t, ctx, esClient, "ml.put_data_frame_analytics", esapi.MLPutDataFrameAnalyticsRequest{
			ID:   dfaID,
			Body: strings.NewReader(fmt.Sprintf(`{"source":{"index":[%q]},"dest":{"index":%q},"analysis":{"regression":{"dependent_variable":"actual"}}}`, dfaSrcIdx, dfaDstIdx)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_data_frame_analytics", esapi.MLGetDataFrameAnalyticsRequest{ID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.get_data_frame_analytics_stats", esapi.MLGetDataFrameAnalyticsStatsRequest{ID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.explain_data_frame_analytics", esapi.MLExplainDataFrameAnalyticsRequest{DocumentID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.preview_data_frame_analytics", esapi.MLPreviewDataFrameAnalyticsRequest{DocumentID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.update_data_frame_analytics", esapi.MLUpdateDataFrameAnalyticsRequest{
			DocumentID: dfaID,
			Body:       strings.NewReader(`{"description":"r66 updated dfa"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.start_data_frame_analytics", esapi.MLStartDataFrameAnalyticsRequest{ID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.stop_data_frame_analytics", esapi.MLStopDataFrameAnalyticsRequest{ID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.delete_data_frame_analytics", esapi.MLDeleteDataFrameAnalyticsRequest{ID: dfaID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ml.evaluate_data_frame", esapi.MLEvaluateDataFrameRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"index":%q,"evaluation":{"regression":{"actual_field":"actual","predicted_field":"predicted"}}}`, dfaSrcIdx)),
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round66_02_MLFullSuite")
	})

	t.Run("Round66_03_SecurityFullSuite", func(t *testing.T) {
		tsSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
		user1 := "r66_user_" + tsSuffix
		role1 := "r66_role_" + tsSuffix
		bulkRoleA := "r66_brole_a_" + tsSuffix
		bulkRoleB := "r66_brole_b_" + tsSuffix
		rm1 := "r66_rm_" + tsSuffix
		appPriv := "r66_app_" + tsSuffix
		svcTok := "r66_svctok_" + tsSuffix
		profUser := "r66_prof_" + tsSuffix

		var apiKeyID, grantedKeyID string
		t.Cleanup(func() {
			if apiKeyID != "" {
				if r, e := (esapi.SecurityInvalidateAPIKeyRequest{Body: strings.NewReader(fmt.Sprintf(`{"ids":[%q]}`, apiKeyID))}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if grantedKeyID != "" {
				if r, e := (esapi.SecurityInvalidateAPIKeyRequest{Body: strings.NewReader(fmt.Sprintf(`{"ids":[%q]}`, grantedKeyID))}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.SecurityDeleteServiceTokenRequest{Namespace: "elastic", Service: "fleet-server", Name: svcTok}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SecurityDeletePrivilegesRequest{Application: appPriv, Name: "read"}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SecurityDeleteRoleMappingRequest{Name: rm1}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SecurityDeleteRoleRequest{Name: role1}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SecurityBulkDeleteRoleRequest{Body: strings.NewReader(fmt.Sprintf(`{"names":[%q,%q]}`, bulkRoleA, bulkRoleB))}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SecurityDeleteUserRequest{Username: user1}).Do(ctx, esClient); r != nil {
				_ = r.Body.Close()
				_ = e
			}
		})

		// 1. Authenticate & User Privileges
		doJSONR64(t, ctx, esClient, "security.authenticate", esapi.SecurityAuthenticateRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_user_privileges", esapi.SecurityGetUserPrivilegesRequest{}, http.StatusOK)

		// 2. Users lifecycle (temp user only, never mutate built-in elastic)
		doJSONR64(t, ctx, esClient, "security.put_user", esapi.SecurityPutUserRequest{
			Username: user1,
			Body:     strings.NewReader(`{"password":"r66-password-1","roles":["viewer"],"full_name":"R66 User","email":"r66@example.com"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_user", esapi.SecurityGetUserRequest{
			Username: []string{user1},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.query_user", esapi.SecurityQueryUserRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"query":{"term":{"username":%q}}}`, user1)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.disable_user", esapi.SecurityDisableUserRequest{Username: user1}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.enable_user", esapi.SecurityEnableUserRequest{Username: user1}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.change_password", esapi.SecurityChangePasswordRequest{
			Username: user1,
			Body:     strings.NewReader(`{"password":"r66-password-2"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.has_privileges", esapi.SecurityHasPrivilegesRequest{
			User: user1,
			Body: strings.NewReader(`{"cluster":["monitor"],"index":[{"names":["*"],"privileges":["read"]}]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.clear_cached_realms", esapi.SecurityClearCachedRealmsRequest{
			Realms: []string{"default_native"},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.delete_user", esapi.SecurityDeleteUserRequest{Username: user1}, http.StatusOK)

		// 3. Roles, Bulk Roles, Role Mappings, Privileges
		doJSONR64(t, ctx, esClient, "security.put_role", esapi.SecurityPutRoleRequest{
			Name: role1,
			Body: strings.NewReader(`{"cluster":["monitor"],"indices":[{"names":["*"],"privileges":["read"]}]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_role", esapi.SecurityGetRoleRequest{Name: []string{role1}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.query_role", esapi.SecurityQueryRoleRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"query":{"term":{"name":%q}}}`, role1)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.clear_cached_roles", esapi.SecurityClearCachedRolesRequest{Name: []string{role1}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.delete_role", esapi.SecurityDeleteRoleRequest{Name: role1}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.bulk_put_role", esapi.SecurityBulkPutRoleRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"roles":{%q:{"cluster":["monitor"]},%q:{"cluster":["all"]}}}`, bulkRoleA, bulkRoleB)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.bulk_delete_role", esapi.SecurityBulkDeleteRoleRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"names":[%q,%q]}`, bulkRoleA, bulkRoleB)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.put_role_mapping", esapi.SecurityPutRoleMappingRequest{
			Name: rm1,
			Body: strings.NewReader(`{"roles":["viewer"],"rules":{"field":{"username":"r66*"}},"enabled":true}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_role_mapping", esapi.SecurityGetRoleMappingRequest{Name: []string{rm1}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.delete_role_mapping", esapi.SecurityDeleteRoleMappingRequest{Name: rm1}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.get_builtin_privileges", esapi.SecurityGetBuiltinPrivilegesRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.put_privileges", esapi.SecurityPutPrivilegesRequest{
			Body: strings.NewReader(fmt.Sprintf(`{%q:{"read":{"actions":["data:read/*"]}}}`, appPriv)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_privileges", esapi.SecurityGetPrivilegesRequest{
			Application: appPriv,
			Name:        "read",
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.clear_cached_privileges", esapi.SecurityClearCachedPrivilegesRequest{
			Application: []string{appPriv},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.delete_privileges", esapi.SecurityDeletePrivilegesRequest{
			Application: appPriv,
			Name:        "read",
		}, http.StatusOK)

		// 4. API Keys & Cross-Cluster API Keys
		akRes := doJSONR64(t, ctx, esClient, "security.create_api_key", esapi.SecurityCreateAPIKeyRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"name":"r66_ak_%s"}`, tsSuffix)),
		}, http.StatusOK)
		apiKeyID, _ = akRes["id"].(string)
		if apiKeyID == "" {
			t.Fatalf("expected non-empty api_key id, got %v", akRes)
		}
		doJSONR64(t, ctx, esClient, "security.get_api_key", esapi.SecurityGetAPIKeyRequest{ID: apiKeyID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.query_api_keys", esapi.SecurityQueryAPIKeysRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"query":{"term":{"id":%q}}}`, apiKeyID)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.update_api_key", esapi.SecurityUpdateAPIKeyRequest{
			DocumentID: apiKeyID,
			Body:       strings.NewReader(`{"metadata":{"env":"r66"}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.bulk_update_api_keys", esapi.SecurityBulkUpdateAPIKeysRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"ids":[%q],"metadata":{"env":"r66-bulk"}}`, apiKeyID)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.clear_api_key_cache", esapi.SecurityClearAPIKeyCacheRequest{Ids: []string{apiKeyID}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.invalidate_api_key", esapi.SecurityInvalidateAPIKeyRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"ids":[%q]}`, apiKeyID)),
		}, http.StatusOK)
		apiKeyID = ""

		grantRes := doJSONR64(t, ctx, esClient, "security.grant_api_key", esapi.SecurityGrantAPIKeyRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"grant_type":"password","username":"r66_grant_u","password":"secret","api_key":{"name":"r66_granted_%s"}}`, tsSuffix)),
		}, http.StatusOK)
		grantedKeyID, _ = grantRes["id"].(string)

		ccRes := doJSONR64(t, ctx, esClient, "security.create_cross_cluster_api_key", esapi.SecurityCreateCrossClusterAPIKeyRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"name":"r66_cck_%s","access":{"search":[{"names":["*"]}]}}`, tsSuffix)),
		}, http.StatusOK)
		ccKeyID, _ := ccRes["id"].(string)
		if ccKeyID == "" {
			t.Fatalf("expected non-empty cross_cluster api_key id, got %v", ccRes)
		}
		doJSONR64(t, ctx, esClient, "security.update_cross_cluster_api_key", esapi.SecurityUpdateCrossClusterAPIKeyRequest{
			DocumentID: ccKeyID,
			Body:       strings.NewReader(`{"metadata":{"env":"cc-upd"}}`),
		}, http.StatusOK)

		// 5. OAuth2 Tokens, Service Accounts/Tokens, Enroll
		tokRes := doJSONR64(t, ctx, esClient, "security.get_token", esapi.SecurityGetTokenRequest{
			Body: strings.NewReader(`{"grant_type":"client_credentials"}`),
		}, http.StatusOK)
		accessTok, _ := tokRes["access_token"].(string)
		doJSONR64(t, ctx, esClient, "security.invalidate_token", esapi.SecurityInvalidateTokenRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"token":%q}`, accessTok)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.get_service_accounts", esapi.SecurityGetServiceAccountsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.create_service_token", esapi.SecurityCreateServiceTokenRequest{
			Namespace: "elastic",
			Service:   "fleet-server",
			Name:      svcTok,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.get_service_credentials", esapi.SecurityGetServiceCredentialsRequest{
			Namespace: "elastic",
			Service:   "fleet-server",
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.clear_cached_service_tokens", esapi.SecurityClearCachedServiceTokensRequest{
			Namespace: "elastic",
			Service:   "fleet-server",
			Name:      []string{svcTok},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.delete_service_token", esapi.SecurityDeleteServiceTokenRequest{
			Namespace: "elastic",
			Service:   "fleet-server",
			Name:      svcTok,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.enroll_kibana", esapi.SecurityEnrollKibanaRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.enroll_node", esapi.SecurityEnrollNodeRequest{}, http.StatusOK)

		// 6. User Profiles, Security Settings, OIDC, SAML
		profRes := doJSONR64(t, ctx, esClient, "security.activate_user_profile", esapi.SecurityActivateUserProfileRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"grant":{"user":{"username":%q,"roles":["analyst"]}}}`, profUser)),
		}, http.StatusOK)
		profUID, _ := profRes["uid"].(string)
		if profUID == "" {
			t.Fatalf("expected non-empty profile uid, got %v", profRes)
		}
		doJSONR64(t, ctx, esClient, "security.get_user_profile", esapi.SecurityGetUserProfileRequest{
			UID: []string{profUID},
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.update_user_profile_data", esapi.SecurityUpdateUserProfileDataRequest{
			UID:  profUID,
			Body: strings.NewReader(`{"labels":{"team":"search"},"data":{"theme":"dark"}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.disable_user_profile", esapi.SecurityDisableUserProfileRequest{UID: profUID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.enable_user_profile", esapi.SecurityEnableUserProfileRequest{UID: profUID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.has_privileges_user_profile", esapi.SecurityHasPrivilegesUserProfileRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"uids":[%q],"privileges":{"cluster":["monitor"]}}`, profUID)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.suggest_user_profiles", esapi.SecuritySuggestUserProfilesRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"hint":{"text":%q,"labels":{"team":"search"}},"size":5}`, profUser)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.get_settings", esapi.SecurityGetSettingsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.update_settings", esapi.SecurityUpdateSettingsRequest{
			Body: strings.NewReader(`{"tokens.max_age":"1h"}`),
		}, http.StatusOK)

		oidcPrep := doJSONR64(t, ctx, esClient, "security.oidc_prepare_authentication", esapi.SecurityOidcPrepareAuthenticationRequest{
			Body: strings.NewReader(`{"realm":"oidc1"}`),
		}, http.StatusOK)
		oidcState, _ := oidcPrep["state"].(string)
		oidcAuth := doJSONR64(t, ctx, esClient, "security.oidc_authenticate", esapi.SecurityOidcAuthenticateRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"redirect_uri":"https://app.example/cb?code=abc","state":%q}`, oidcState)),
		}, http.StatusOK)
		oidcTok, _ := oidcAuth["access_token"].(string)
		doJSONR64(t, ctx, esClient, "security.oidc_logout", esapi.SecurityOidcLogoutRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"token":%q}`, oidcTok)),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "security.saml_prepare_authentication", esapi.SecuritySamlPrepareAuthenticationRequest{
			Body: strings.NewReader(`{"realm":"saml1"}`),
		}, http.StatusOK)
		samlAuth := doJSONR64(t, ctx, esClient, "security.saml_authenticate", esapi.SecuritySamlAuthenticateRequest{
			Body: strings.NewReader(`{"content":"PHNhbWw+","ids":["req1"]}`),
		}, http.StatusOK)
		samlTok, _ := samlAuth["access_token"].(string)
		doJSONR64(t, ctx, esClient, "security.saml_invalidate", esapi.SecuritySamlInvalidateRequest{
			Body: strings.NewReader(`{"query_string":"SAMLRequest=xyz"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "security.saml_logout", esapi.SecuritySamlLogoutRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"token":%q}`, samlTok)),
		}, http.StatusOK)
		doRawR64(t, ctx, esClient, "security.saml_complete_logout", esapi.SecuritySamlCompleteLogoutRequest{
			Body: strings.NewReader(`{}`),
		}, http.StatusOK)
		doRawR64(t, ctx, esClient, "security.saml_service_provider_metadata", esapi.SecuritySamlServiceProviderMetadataRequest{
			RealmName: "saml1",
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round66_03_SecurityFullSuite")
	})

	t.Run("Round66_04_ConnectorFullSuite", func(t *testing.T) {
		tsSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
		connID := "r66_conn_" + tsSuffix
		secNamedID := "r66_sec_" + tsSuffix
		var postConnID, secPostID, syncJobID string

		t.Cleanup(func() {
			if syncJobID != "" {
				if r, e := (esapi.ConnectorSyncJobDeleteRequest{ConnectorSyncJobID: syncJobID}).Do(ctx, esClient); r != nil {
					_ = r.Body.Close()
					_ = e
				}
			}
			for _, sid := range []string{secNamedID, secPostID} {
				if sid != "" {
					if r, e := (esapi.ConnectorSecretDeleteRequest{DocumentID: sid}).Do(ctx, esClient); r != nil {
						_ = r.Body.Close()
						_ = e
					}
				}
			}
			for _, cid := range []string{connID, postConnID} {
				if cid != "" {
					if r, e := (esapi.ConnectorDeleteRequest{ConnectorID: cid}).Do(ctx, esClient); r != nil {
						_ = r.Body.Close()
						_ = e
					}
				}
			}
		})

		// 1. Connector CRUD & Updates
		postConnRes := doJSONR64(t, ctx, esClient, "connector.post", esapi.ConnectorPostRequest{
			Body: strings.NewReader(`{"name":"R66 Post Conn","service_type":"s3","index_name":"r66_conn_post_idx"}`),
		}, http.StatusCreated, http.StatusOK)
		postConnID, _ = postConnRes["id"].(string)

		doJSONR64(t, ctx, esClient, "connector.put", esapi.ConnectorPutRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"name":"R66 Put Conn","service_type":"postgresql","index_name":"r66_conn_idx"}`),
		}, http.StatusCreated, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.get", esapi.ConnectorGetRequest{ConnectorID: connID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.list", esapi.ConnectorListRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.check_in", esapi.ConnectorCheckInRequest{ConnectorID: connID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.last_sync", esapi.ConnectorLastSyncRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"last_synced":"2026-11-01T00:00:00Z","last_sync_status":"completed"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_name", esapi.ConnectorUpdateNameRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"name":"R66 Conn Renamed","description":"updated desc"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_index_name", esapi.ConnectorUpdateIndexNameRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"index_name":"r66_conn_idx_v2"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_service_type", esapi.ConnectorUpdateServiceDocumentTypeRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"service_type":"mysql"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_native", esapi.ConnectorUpdateNativeRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"is_native":true}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_status", esapi.ConnectorUpdateStatusRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"status":"connected"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_error", esapi.ConnectorUpdateErrorRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"error":null}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_configuration", esapi.ConnectorUpdateConfigurationRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"configuration":{"host":{"default_value":"localhost","depends_on":[],"display":"textbox","label":"Host","options":[],"required":false,"sensitive":false,"value":"localhost"}}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_filtering", esapi.ConnectorUpdateFilteringRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"filtering":[{"active":{"advanced_snippet":{"value":""},"rules":[],"validation":{"errors":[],"state":"valid"}},"draft":{"advanced_snippet":{"value":""},"rules":[],"validation":{"errors":[],"state":"valid"}}}]}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_active_filtering", esapi.ConnectorUpdateActiveFilteringRequest{
			ConnectorID: connID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_filtering_validation", esapi.ConnectorUpdateFilteringValidationRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"state":"valid"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_scheduling", esapi.ConnectorUpdateSchedulingRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"scheduling":{"full":{"enabled":false}}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_pipeline", esapi.ConnectorUpdatePipelineRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"pipeline":{"name":"r66_pipe"}}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_api_key_id", esapi.ConnectorUpdateAPIKeyDocumentIDRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"api_key_id":"ak-r66","api_key_secret_id":"sec-r66"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.update_features", esapi.ConnectorUpdateFeaturesRequest{
			ConnectorID: connID,
			Body:        strings.NewReader(`{"features":{"document_level_security":{"enabled":true}}}`),
		}, http.StatusOK)

		// 2. Connector Secrets
		secPostRes := doJSONR64(t, ctx, esClient, "connector.secret_post", esapi.ConnectorSecretPostRequest{
			Body: strings.NewReader(`{"value":"r66-secret-post-val"}`),
		}, http.StatusCreated, http.StatusOK)
		secPostID, _ = secPostRes["id"].(string)
		doJSONR64(t, ctx, esClient, "connector.secret_put", esapi.ConnectorSecretPutRequest{
			DocumentID: secNamedID,
			Body:       strings.NewReader(`{"value":"r66-secret-put-val"}`),
		}, http.StatusCreated, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.secret_get", esapi.ConnectorSecretGetRequest{
			DocumentID: secNamedID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.secret_delete", esapi.ConnectorSecretDeleteRequest{
			DocumentID: secNamedID,
		}, http.StatusOK)
		secNamedID = ""

		// 3. Connector Sync Jobs lifecycle
		sjPostRes := doJSONR64(t, ctx, esClient, "connector.sync_job_post", esapi.ConnectorSyncJobPostRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"connector_id":%q,"job_type":"full"}`, connID)),
		}, http.StatusCreated, http.StatusOK)
		syncJobID, _ = sjPostRes["id"].(string)
		if syncJobID == "" {
			t.Fatalf("expected non-empty connector sync_job id, got %v", sjPostRes)
		}
		doJSONR64(t, ctx, esClient, "connector.sync_job_list", esapi.ConnectorSyncJobListRequest{
			ConnectorID: connID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_get", esapi.ConnectorSyncJobGetRequest{
			ConnectorSyncJobID: syncJobID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_claim", esapi.ConnectorSyncJobClaimRequest{
			ConnectorSyncJobID: syncJobID,
			Body:               strings.NewReader(`{"worker_hostname":"r66-worker"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_check_in", esapi.ConnectorSyncJobCheckInRequest{
			ConnectorSyncJobID: syncJobID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_update_stats", esapi.ConnectorSyncJobUpdateStatsRequest{
			ConnectorSyncJobID: syncJobID,
			Body:               strings.NewReader(`{"indexed_document_count":10,"indexed_document_volume":1024}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_error", esapi.ConnectorSyncJobErrorRequest{
			ConnectorSyncJobID: syncJobID,
			Body:               strings.NewReader(`{"error":"sample error"}`),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_cancel", esapi.ConnectorSyncJobCancelRequest{
			ConnectorSyncJobID: syncJobID,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "connector.sync_job_delete", esapi.ConnectorSyncJobDeleteRequest{
			ConnectorSyncJobID: syncJobID,
		}, http.StatusOK)
		syncJobID = ""

		// 4. Delete connectors
		doJSONR64(t, ctx, esClient, "connector.delete", esapi.ConnectorDeleteRequest{
			ConnectorID: connID,
		}, http.StatusOK)
		connID = ""

		wireTransport.assertNoViolations(t, "Round66_04_ConnectorFullSuite")
	})

	t.Run("Round66_05_FeaturesReset", func(t *testing.T) {
		doJSONR64(t, ctx, esClient, "features.reset_features", esapi.FeaturesResetFeaturesRequest{}, http.StatusOK)
		wireTransport.assertNoViolations(t, "Round66_05_FeaturesReset")
	})
}
