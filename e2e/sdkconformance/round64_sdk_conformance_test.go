package sdkconformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type esRequestR64 interface {
	Do(context.Context, esapi.Transport) (*esapi.Response, error)
}

func doRawR64(t *testing.T, ctx context.Context, tr esapi.Transport, label string, req esRequestR64, wantStatuses ...int) string {
	t.Helper()
	resp, err := req.Do(ctx, tr)
	if err != nil {
		t.Fatalf("%s request failed: %v", label, err)
	}
	if resp == nil {
		t.Fatalf("%s returned nil response", label)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("%s read body failed: %v", label, readErr)
	}
	matched := len(wantStatuses) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300
	for _, want := range wantStatuses {
		if resp.StatusCode == want {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("%s unexpected status %d (want %v): %s", label, resp.StatusCode, wantStatuses, string(raw))
	}
	return string(raw)
}

func doJSONR64(t *testing.T, ctx context.Context, tr esapi.Transport, label string, req esRequestR64, wantStatuses ...int) map[string]any {
	t.Helper()
	raw := doRawR64(t, ctx, tr, label, req, wantStatuses...)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var out map[string]any
	if decErr := json.Unmarshal([]byte(raw), &out); decErr != nil {
		t.Fatalf("%s invalid JSON response: %v (%s)", label, decErr, raw)
	}
	return out
}

func runRound64SDKConformanceSubtests(
	t *testing.T,
	ctx context.Context,
	idx string,
	aliasName string,
	esClient *elasticsearch.Client,
	wireTransport *wireConformanceTransport,
) {
	t.Helper()
	_ = aliasName

	t.Run("Round64_01_DocCreateExistsSourceKnnAndTermsEnum", func(t *testing.T) {
		idxDoc := "sdk_r64_doc_idx"
		t.Cleanup(func() {
			if r, e := (esapi.IndicesDeleteRequest{Index: []string{idxDoc}}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "indices.create("+idxDoc+")", esapi.IndicesCreateRequest{
			Index: idxDoc,
			Body: strings.NewReader(`{
				"mappings": {
					"properties": {
						"title": {"type": "text"},
						"category": {"type": "keyword"},
						"vec": {"type": "dense_vector", "dims": 3}
					}
				}
			}`),
		})

		createMap := doJSONR64(t, ctx, esClient, "create", esapi.CreateRequest{
			Index:      idxDoc,
			DocumentID: "doc-1",
			Body:       strings.NewReader(`{"title":"r64 compute node","category":"compute","vec":[1.0,0.0,0.0]}`),
			Refresh:    "true",
		}, http.StatusCreated, http.StatusOK)
		if createMap["result"] != "created" {
			t.Fatalf("expected create result=created, got %v", createMap)
		}

		doRawR64(t, ctx, esClient, "exists_source", esapi.ExistsSourceRequest{
			Index:      idxDoc,
			DocumentID: "doc-1",
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "knn_search", esapi.KnnSearchRequest{
			Index: []string{idxDoc},
			Body:  strings.NewReader(`{"knn":{"field":"vec","query_vector":[1.0,0.0,0.0],"k":1,"num_candidates":2}}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "terms_enum", esapi.TermsEnumRequest{
			Index: []string{idxDoc},
			Body:  strings.NewReader(`{"field":"category","string":"com"}`),
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_01_DocCreateExistsSourceKnnAndTermsEnum")
	})

	t.Run("Round64_02_CapabilitiesHealthReportAndScriptMeta", func(t *testing.T) {
		doJSONR64(t, ctx, esClient, "capabilities", esapi.CapabilitiesRequest{Method: "GET", Path: "/_search"}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "health_report", esapi.HealthReportRequest{Verbose: esapi.BoolPtr(true)}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "get_script_context", esapi.GetScriptContextRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "get_script_languages", esapi.GetScriptLanguagesRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "features.get_features", esapi.FeaturesGetFeaturesRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "migration.deprecations", esapi.MigrationDeprecationsRequest{Index: idx}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "dangling_indices.list_dangling_indices", esapi.DanglingIndicesListDanglingIndicesRequest{}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_02_CapabilitiesHealthReportAndScriptMeta")
	})

	t.Run("Round64_03_TasksRethrottle", func(t *testing.T) {
		idxSrc := "sdk_r64_re_src"
		idxDst := "sdk_r64_re_dst"
		t.Cleanup(func() {
			for _, name := range []string{idxSrc, idxDst} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
		})

		for _, name := range []string{idxSrc, idxDst} {
			doJSONR64(t, ctx, esClient, "indices.create("+name+")", esapi.IndicesCreateRequest{
				Index: name,
				Body:  strings.NewReader(`{"mappings":{"properties":{"name":{"type":"keyword"}}}}`),
			})
		}
		doJSONR64(t, ctx, esClient, "create("+idxSrc+"/1)", esapi.CreateRequest{
			Index:      idxSrc,
			DocumentID: "1",
			Body:       strings.NewReader(`{"name":"item1"}`),
			Refresh:    "true",
		})

		reMap := doJSONR64(t, ctx, esClient, "reindex.async", esapi.ReindexRequest{
			WaitForCompletion: esapi.BoolPtr(false),
			Body:              strings.NewReader(fmt.Sprintf(`{"source":{"index":%q},"dest":{"index":%q}}`, idxSrc, idxDst)),
		}, http.StatusOK)
		taskID, _ := reMap["task"].(string)
		if taskID == "" {
			t.Fatalf("expected non-empty async reindex task id, got %v", reMap)
		}

		rpsReindex := 250
		doJSONR64(t, ctx, esClient, "reindex_rethrottle", esapi.ReindexRethrottleRequest{
			TaskID:            taskID,
			RequestsPerSecond: &rpsReindex,
		}, http.StatusOK)

		rpsUBQ := 50
		doJSONR64(t, ctx, esClient, "update_by_query_rethrottle", esapi.UpdateByQueryRethrottleRequest{
			TaskID:            taskID,
			RequestsPerSecond: &rpsUBQ,
		}, http.StatusOK)

		rpsDBQ := -1
		doJSONR64(t, ctx, esClient, "delete_by_query_rethrottle", esapi.DeleteByQueryRethrottleRequest{
			TaskID:            taskID,
			RequestsPerSecond: &rpsDBQ,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_03_TasksRethrottle")
	})

	t.Run("Round64_04_IndicesOpsAndBlocks", func(t *testing.T) {
		idxOps := "sdk_r64_ind_ops"
		idxBlk := "sdk_r64_blk_ops"
		t.Cleanup(func() {
			if r, e := (esapi.IndicesPutSettingsRequest{
				Index: []string{idxBlk},
				Body:  strings.NewReader(`{"index.blocks.write":null}`),
			}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			for _, name := range []string{idxOps, idxBlk} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
		})

		for _, name := range []string{idxOps, idxBlk} {
			doJSONR64(t, ctx, esClient, "indices.create("+name+")", esapi.IndicesCreateRequest{
				Index: name,
				Body:  strings.NewReader(`{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"}}}}`),
			})
		}
		doJSONR64(t, ctx, esClient, "create("+idxOps+"/1)", esapi.CreateRequest{
			Index:      idxOps,
			DocumentID: "1",
			Body:       strings.NewReader(`{"title":"hello ops","tag":"alpha"}`),
			Refresh:    "true",
		})

		doJSONR64(t, ctx, esClient, "indices.disk_usage", esapi.IndicesDiskUsageRequest{
			Index:             idxOps,
			RunExpensiveTasks: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.field_usage_stats", esapi.IndicesFieldUsageStatsRequest{
			Index:  idxOps,
			Fields: []string{"title", "tag"},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.shard_stores", esapi.IndicesShardStoresRequest{
			Index: []string{idxOps},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.reload_search_analyzers", esapi.IndicesReloadSearchAnalyzersRequest{
			Index: []string{idxOps},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.resolve_cluster", esapi.IndicesResolveClusterRequest{
			Name: []string{idxOps},
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.add_block", esapi.IndicesAddBlockRequest{
			Index: []string{idxBlk},
			Block: "write",
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_04_IndicesOpsAndBlocks")
	})

	t.Run("Round64_05_DataStreamsLifecycleMigrateModify", func(t *testing.T) {
		migIdx1 := "r64_mig_idx_01"
		migIdx2 := "r64_mig_idx_02"
		migStream := "r64_mig_stream"
		tplMig := "tpl_r64_mig"
		tplDS := "tpl_r64_ds_lc"
		dsName := "logs-r64-sdk-lc"
		t.Cleanup(func() {
			for _, name := range []string{migStream, dsName} {
				if r, e := (esapi.IndicesDeleteDataStreamRequest{Name: []string{name}}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
			for _, name := range []string{migIdx1, migIdx2} {
				if r, e := (esapi.IndicesDeleteRequest{Index: []string{name}}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
			for _, tpl := range []string{tplMig, tplDS} {
				if r, e := (esapi.IndicesDeleteIndexTemplateRequest{Name: tpl}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
		})

		doJSONR64(t, ctx, esClient, "indices.put_index_template("+tplMig+")", esapi.IndicesPutIndexTemplateRequest{
			Name: tplMig,
			Body: strings.NewReader(`{
				"index_patterns": ["r64_mig_stream"],
				"data_stream": {},
				"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}}}}
			}`),
		})
		for _, name := range []string{migIdx1, migIdx2} {
			doJSONR64(t, ctx, esClient, "indices.create("+name+")", esapi.IndicesCreateRequest{
				Index: name,
				Body:  strings.NewReader(`{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`),
			})
		}
		doJSONR64(t, ctx, esClient, "indices.update_aliases", esapi.IndicesUpdateAliasesRequest{
			Body: strings.NewReader(fmt.Sprintf(`{
				"actions": [
					{"add": {"index": %q, "alias": %q, "is_write_index": false}},
					{"add": {"index": %q, "alias": %q, "is_write_index": true}}
				]
			}`, migIdx1, migStream, migIdx2, migStream)),
		})

		doJSONR64(t, ctx, esClient, "indices.migrate_to_data_stream", esapi.IndicesMigrateToDataStreamRequest{Name: migStream}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.put_index_template("+tplDS+")", esapi.IndicesPutIndexTemplateRequest{
			Name: tplDS,
			Body: strings.NewReader(`{
				"index_patterns": ["logs-r64-sdk-*"],
				"data_stream": {},
				"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "keyword"}}}}
			}`),
		})
		doJSONR64(t, ctx, esClient, "indices.create_data_stream("+dsName+")", esapi.IndicesCreateDataStreamRequest{Name: dsName})
		doJSONR64(t, ctx, esClient, "index("+dsName+")", esapi.IndexRequest{
			Index:   dsName,
			Body:    strings.NewReader(`{"@timestamp":"2026-01-01T00:00:00Z","msg":"hello"}`),
			Refresh: "true",
		})
		doJSONR64(t, ctx, esClient, "indices.rollover("+dsName+")", esapi.IndicesRolloverRequest{Alias: dsName})

		doJSONR64(t, ctx, esClient, "indices.put_data_lifecycle", esapi.IndicesPutDataLifecycleRequest{
			Name: []string{dsName},
			Body: strings.NewReader(`{"data_retention":"7d"}`),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.get_data_lifecycle", esapi.IndicesGetDataLifecycleRequest{
			Name:            []string{dsName},
			IncludeDefaults: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.explain_data_lifecycle", esapi.IndicesExplainDataLifecycleRequest{
			Index:           dsName,
			IncludeDefaults: esapi.BoolPtr(true),
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.delete_data_lifecycle", esapi.IndicesDeleteDataLifecycleRequest{
			Name: []string{dsName},
		}, http.StatusOK)

		dsGetMap := doJSONR64(t, ctx, esClient, "indices.get_data_stream", esapi.IndicesGetDataStreamRequest{Name: []string{dsName}})
		var firstBacking string
		if dsArr, ok := dsGetMap["data_streams"].([]any); ok && len(dsArr) > 0 {
			if dsObj, ok := dsArr[0].(map[string]any); ok {
				if idxArr, ok := dsObj["indices"].([]any); ok && len(idxArr) > 0 {
					if idxObj, ok := idxArr[0].(map[string]any); ok {
						firstBacking, _ = idxObj["index_name"].(string)
					}
				}
			}
		}
		if firstBacking == "" {
			t.Fatalf("expected backing index on %s after rollover, got %v", dsName, dsGetMap)
		}
		doJSONR64(t, ctx, esClient, "indices.modify_data_stream", esapi.IndicesModifyDataStreamRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"actions":[{"remove_backing_index":{"data_stream":%q,"index":%q}}]}`, dsName, firstBacking)),
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_05_DataStreamsLifecycleMigrateModify")
	})

	t.Run("Round64_06_ClusterAndLicense", func(t *testing.T) {
		doJSONR64(t, ctx, esClient, "cluster.info", esapi.ClusterInfoRequest{Target: []string{"http", "ingest"}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "cluster.remote_info", esapi.ClusterRemoteInfoRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "cluster.post_voting_config_exclusions", esapi.ClusterPostVotingConfigExclusionsRequest{NodeNames: "doris-fe-1"}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "cluster.delete_voting_config_exclusions", esapi.ClusterDeleteVotingConfigExclusionsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "license.get", esapi.LicenseGetRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "license.get_basic_status", esapi.LicenseGetBasicStatusRequest{}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_06_ClusterAndLicense")
	})

	t.Run("Round64_07_CatExtendedAndILMControl", func(t *testing.T) {
		catRepo := "r64_cat_repo"
		ilmPol := "r64_ilm_pol"
		ilmIdx := "sdk_r64_ilm_idx"
		t.Cleanup(func() {
			if r, e := (esapi.IndicesDeleteRequest{Index: []string{ilmIdx}}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			if r, e := (esapi.ILMDeleteLifecycleRequest{Policy: ilmPol}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SnapshotDeleteRepositoryRequest{Repository: []string{catRepo}}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "snapshot.create_repository("+catRepo+")", esapi.SnapshotCreateRepositoryRequest{
			Repository: catRepo,
			Body:       strings.NewReader(fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, t.TempDir())),
		})

		doRawR64(t, ctx, esClient, "cat.help", esapi.CatHelpRequest{}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.allocation", esapi.CatAllocationRequest{Format: "json"}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.snapshots", esapi.CatSnapshotsRequest{Repository: []string{catRepo}, Format: "json"}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.transforms", esapi.CatTransformsRequest{Format: "json"}, http.StatusOK)
		doRawR64(t, ctx, esClient, "cat.ml_jobs", esapi.CatMLJobsRequest{Format: "json"}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ilm.stop", esapi.ILMStopRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "ilm.start", esapi.ILMStartRequest{}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "ilm.put_lifecycle", esapi.ILMPutLifecycleRequest{
			Policy: ilmPol,
			Body:   strings.NewReader(`{"policy":{"phases":{"delete":{"min_age":"1d","actions":{"delete":{}}}}}}`),
		})
		doJSONR64(t, ctx, esClient, "indices.create("+ilmIdx+")", esapi.IndicesCreateRequest{
			Index: ilmIdx,
			Body:  strings.NewReader(fmt.Sprintf(`{"settings":{"index.lifecycle.name":%q}}`, ilmPol)),
		})
		doJSONR64(t, ctx, esClient, "ilm.remove_policy", esapi.ILMRemovePolicyRequest{Index: ilmIdx}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_07_CatExtendedAndILMControl")
	})

	t.Run("Round64_08_SLMLifecycle", func(t *testing.T) {
		slmRepo := "r64_slm_repo"
		slmPol := "r64_slm_pol"
		t.Cleanup(func() {
			if r, e := (esapi.SlmDeleteLifecycleRequest{PolicyID: slmPol}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			if r, e := (esapi.SnapshotDeleteRepositoryRequest{Repository: []string{slmRepo}}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "snapshot.create_repository("+slmRepo+")", esapi.SnapshotCreateRepositoryRequest{
			Repository: slmRepo,
			Body:       strings.NewReader(fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, t.TempDir())),
		})

		doJSONR64(t, ctx, esClient, "slm.get_stats", esapi.SlmGetStatsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.put_lifecycle", esapi.SlmPutLifecycleRequest{
			PolicyID: slmPol,
			Body:     strings.NewReader(fmt.Sprintf(`{"schedule":"0 30 1 * * ?","name":"<r64-snap-{now/d}>","repository":%q}`, slmRepo)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.get_lifecycle", esapi.SlmGetLifecycleRequest{PolicyID: []string{slmPol}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.execute_lifecycle", esapi.SlmExecuteLifecycleRequest{PolicyID: slmPol}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.execute_retention", esapi.SlmExecuteRetentionRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.get_status", esapi.SlmGetStatusRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.stop", esapi.SlmStopRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.start", esapi.SlmStartRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "slm.delete_lifecycle", esapi.SlmDeleteLifecycleRequest{PolicyID: slmPol}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_08_SLMLifecycle")
	})

	t.Run("Round64_09_EnrichSQLAsyncEQL", func(t *testing.T) {
		polName := "r64_enrich_pol"
		idxEql := "sdk_r64_eql_idx"
		var asyncID string
		t.Cleanup(func() {
			if r, e := (esapi.EnrichDeletePolicyRequest{Name: polName}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			if asyncID != "" {
				if r, e := (esapi.AsyncSearchDeleteRequest{DocumentID: asyncID}).Do(ctx, esClient); r != nil {
					r.Body.Close()
					_ = e
				}
			}
			if r, e := (esapi.IndicesDeleteRequest{Index: []string{idxEql}}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "enrich.put_policy", esapi.EnrichPutPolicyRequest{
			Name: polName,
			Body: strings.NewReader(fmt.Sprintf(`{"match":{"indices":%q,"match_field":"category","enrich_fields":["title"]}}`, idx)),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "enrich.get_policy", esapi.EnrichGetPolicyRequest{Name: []string{polName}}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "enrich.execute_policy", esapi.EnrichExecutePolicyRequest{
			Name:              polName,
			WaitForCompletion: esapi.BoolPtr(true),
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "enrich.stats", esapi.EnrichStatsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "enrich.delete_policy", esapi.EnrichDeletePolicyRequest{Name: polName}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "sql.translate", esapi.SQLTranslateRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"query":"SELECT category, price FROM %s WHERE in_stock = true"}`, idx)),
		}, http.StatusOK)

		sqMap := doJSONR64(t, ctx, esClient, "sql.query(cursor)", esapi.SQLQueryRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"query":"SELECT title FROM %s","fetch_size":1}`, idx)),
		})
		cursor, _ := sqMap["cursor"].(string)
		if cursor == "" {
			t.Fatalf("expected non-empty sql cursor, got %v", sqMap)
		}
		doJSONR64(t, ctx, esClient, "sql.clear_cursor", esapi.SQLClearCursorRequest{
			Body: strings.NewReader(fmt.Sprintf(`{"cursor":%q}`, cursor)),
		}, http.StatusOK)

		asSubMap := doJSONR64(t, ctx, esClient, "async_search.submit", esapi.AsyncSearchSubmitRequest{
			Index:            []string{idx},
			KeepOnCompletion: esapi.BoolPtr(true),
			Body:             strings.NewReader(`{"query":{"match_all":{}}}`),
		})
		asyncID, _ = asSubMap["id"].(string)
		if asyncID == "" {
			t.Fatalf("expected non-empty async_search id, got %v", asSubMap)
		}
		doJSONR64(t, ctx, esClient, "async_search.status", esapi.AsyncSearchStatusRequest{DocumentID: asyncID}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "indices.create("+idxEql+")", esapi.IndicesCreateRequest{
			Index: idxEql,
			Body:  strings.NewReader(`{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"category":{"type":"keyword"}}},"user":{"type":"keyword"}}}}`),
		})
		doJSONR64(t, ctx, esClient, "create("+idxEql+"/1)", esapi.CreateRequest{
			Index:      idxEql,
			DocumentID: "1",
			Body:       strings.NewReader(`{"@timestamp":"2026-01-01T00:00:00Z","event":{"category":"process"},"user":"alice"}`),
			Refresh:    "true",
		})
		eqlSubMap := doJSONR64(t, ctx, esClient, "eql.search(keep_on_completion)", esapi.EqlSearchRequest{
			Index:            idxEql,
			KeepOnCompletion: esapi.BoolPtr(true),
			Body:             strings.NewReader(`{"query":"any where true"}`),
		})
		eqlID, _ := eqlSubMap["id"].(string)
		if eqlID == "" {
			t.Fatalf("expected non-empty eql id with keep_on_completion=true, got %v", eqlSubMap)
		}
		doJSONR64(t, ctx, esClient, "eql.get_status", esapi.EqlGetStatusRequest{DocumentID: eqlID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "eql.get", esapi.EqlGetRequest{DocumentID: eqlID}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "eql.delete", esapi.EqlDeleteRequest{DocumentID: eqlID}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_09_EnrichSQLAsyncEQL")
	})

	t.Run("Round64_10_SynonymsAndQueryRules", func(t *testing.T) {
		synSet := "r64_syn_set"
		synRule := "r1"
		qrSet := "r64_qr_set"
		qrRule := "r2"
		t.Cleanup(func() {
			if r, e := (esapi.SynonymsDeleteSynonymRequest{DocumentID: synSet}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
			if r, e := (esapi.QueryRulesDeleteRulesetRequest{RulesetID: qrSet}).Do(ctx, esClient); r != nil {
				r.Body.Close()
				_ = e
			}
		})

		doJSONR64(t, ctx, esClient, "synonyms.put_synonym", esapi.SynonymsPutSynonymRequest{
			DocumentID: synSet,
			Body:       strings.NewReader(`{"synonyms_set":[{"id":"r0","synonyms":"fast, quick"}]}`),
		})
		doJSONR64(t, ctx, esClient, "synonyms.put_synonym_rule", esapi.SynonymsPutSynonymRuleRequest{
			SetID:  synSet,
			RuleID: synRule,
			Body:   strings.NewReader(`{"synonyms":"small, tiny"}`),
		})
		doJSONR64(t, ctx, esClient, "synonyms.get_synonym_rule", esapi.SynonymsGetSynonymRuleRequest{
			SetID:  synSet,
			RuleID: synRule,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "synonyms.delete_synonym_rule", esapi.SynonymsDeleteSynonymRuleRequest{
			SetID:  synSet,
			RuleID: synRule,
		}, http.StatusOK)

		doJSONR64(t, ctx, esClient, "query_rules.put_ruleset", esapi.QueryRulesPutRulesetRequest{
			RulesetID: qrSet,
			Body:      strings.NewReader(`{"rules":[{"rule_id":"r1","type":"pinned","criteria":[{"type":"always"}],"actions":{"ids":["doc-1"]}}]}`),
		}, http.StatusOK, http.StatusCreated)
		doJSONR64(t, ctx, esClient, "query_rules.get_ruleset", esapi.QueryRulesGetRulesetRequest{
			RulesetID: qrSet,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "query_rules.list_rulesets", esapi.QueryRulesListRulesetsRequest{}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "query_rules.put_rule", esapi.QueryRulesPutRuleRequest{
			RulesetID: qrSet,
			RuleID:    qrRule,
			Body:      strings.NewReader(`{"type":"pinned","criteria":[{"type":"exact","metadata":"q","values":["featured"]}],"actions":{"ids":["doc-2"]}}`),
		}, http.StatusOK, http.StatusCreated)
		doJSONR64(t, ctx, esClient, "query_rules.get_rule", esapi.QueryRulesGetRuleRequest{
			RulesetID: qrSet,
			RuleID:    qrRule,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "query_rules.delete_rule", esapi.QueryRulesDeleteRuleRequest{
			RulesetID: qrSet,
			RuleID:    qrRule,
		}, http.StatusOK)
		doJSONR64(t, ctx, esClient, "query_rules.delete_ruleset", esapi.QueryRulesDeleteRulesetRequest{
			RulesetID: qrSet,
		}, http.StatusOK)

		wireTransport.assertNoViolations(t, "Round64_10_SynonymsAndQueryRules")
	})
}
