package compliance

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestBuildActionRequest(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	cases := []struct {
		name          string
		action        string
		params        map[string]any
		wantMethod    string
		wantPath      string
		strippedParam []string
		wantQuery     map[string]string
	}{
		// cluster.state
		{
			name:       "cluster.state default",
			action:     "cluster.state",
			params:     map[string]any{"local": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_cluster/state",
			wantQuery:  map[string]string{"local": "true"},
		},
		{
			name:          "cluster.state metric only",
			action:        "cluster.state",
			params:        map[string]any{"metric": "metadata", "local": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cluster/state/metadata",
			strippedParam: []string{"metric"},
			wantQuery:     map[string]string{"local": "true"},
		},
		{
			name:          "cluster.state index only",
			action:        "cluster.state",
			params:        map[string]any{"index": "idx1", "local": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cluster/state/_all/idx1",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"local": "true"},
		},
		{
			name:          "cluster.state metric and index",
			action:        "cluster.state",
			params:        map[string]any{"metric": "metadata,routing_table", "index": "idx1,idx2", "wait_for_metadata_version": 1},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cluster/state/metadata,routing_table/idx1,idx2",
			strippedParam: []string{"metric", "index"},
			wantQuery:     map[string]string{"wait_for_metadata_version": "1"},
		},

		// nodes.info
		{
			name:       "nodes.info default",
			action:     "nodes.info",
			params:     map[string]any{"flat_settings": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_nodes",
			wantQuery:  map[string]string{"flat_settings": "true"},
		},
		{
			name:          "nodes.info node_id only",
			action:        "nodes.info",
			params:        map[string]any{"node_id": "node1", "flat_settings": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/node1",
			strippedParam: []string{"node_id"},
			wantQuery:     map[string]string{"flat_settings": "true"},
		},
		{
			name:          "nodes.info metric only",
			action:        "nodes.info",
			params:        map[string]any{"metric": "jvm,os", "flat_settings": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/_all/jvm,os",
			strippedParam: []string{"metric"},
			wantQuery:     map[string]string{"flat_settings": "true"},
		},
		{
			name:          "nodes.info node_id and metric",
			action:        "nodes.info",
			params:        map[string]any{"node_id": "node1", "metric": "http", "timeout": "5s"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/node1/http",
			strippedParam: []string{"node_id", "metric"},
			wantQuery:     map[string]string{"timeout": "5s"},
		},

		// nodes.stats
		{
			name:       "nodes.stats default",
			action:     "nodes.stats",
			params:     map[string]any{"level": "nodes"},
			wantMethod: http.MethodGet,
			wantPath:   "/_nodes/stats",
			wantQuery:  map[string]string{"level": "nodes"},
		},
		{
			name:          "nodes.stats node_id only",
			action:        "nodes.stats",
			params:        map[string]any{"node_id": "node1", "level": "nodes"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/node1/stats",
			strippedParam: []string{"node_id"},
			wantQuery:     map[string]string{"level": "nodes"},
		},
		{
			name:          "nodes.stats metric only",
			action:        "nodes.stats",
			params:        map[string]any{"metric": "indices,jvm", "level": "shards"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/stats/indices,jvm",
			strippedParam: []string{"metric"},
			wantQuery:     map[string]string{"level": "shards"},
		},
		{
			name:          "nodes.stats node_id and metric",
			action:        "nodes.stats",
			params:        map[string]any{"node_id": "node1", "metric": "process", "timeout": "10s"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/node1/stats/process",
			strippedParam: []string{"node_id", "metric"},
			wantQuery:     map[string]string{"timeout": "10s"},
		},

		// indices.get
		{
			name:          "indices.get index only",
			action:        "indices.get",
			params:        map[string]any{"index": "my_idx", "include_defaults": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/my_idx",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"include_defaults": "true"},
		},
		{
			name:          "indices.get index and feature",
			action:        "indices.get",
			params:        map[string]any{"index": "my_idx", "feature": "_settings,_mappings", "flat_settings": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/my_idx/_settings,_mappings",
			strippedParam: []string{"index", "feature"},
			wantQuery:     map[string]string{"flat_settings": "true"},
		},

		// indices.get_settings
		{
			name:       "indices.get_settings default",
			action:     "indices.get_settings",
			params:     map[string]any{"flat_settings": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_settings",
			wantQuery:  map[string]string{"flat_settings": "true"},
		},
		{
			name:          "indices.get_settings index only",
			action:        "indices.get_settings",
			params:        map[string]any{"index": "idx1", "include_defaults": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_settings",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"include_defaults": "true"},
		},
		{
			name:          "indices.get_settings name only",
			action:        "indices.get_settings",
			params:        map[string]any{"name": "index.number_of_*", "flat_settings": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_all/_settings/index.number_of_*",
			strippedParam: []string{"name"},
			wantQuery:     map[string]string{"flat_settings": "true"},
		},
		{
			name:          "indices.get_settings index and name",
			action:        "indices.get_settings",
			params:        map[string]any{"index": "idx1", "name": "index.number_of_shards", "flat_settings": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_settings/index.number_of_shards",
			strippedParam: []string{"index", "name"},
			wantQuery:     map[string]string{"flat_settings": "true"},
		},
		{
			name:          "indices.get_settings index and prefix fallback",
			action:        "indices.get_settings",
			params:        map[string]any{"index": "idx1", "prefix": "index.routing.*"},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_settings/index.routing.*",
			strippedParam: []string{"index"},
		},
		{
			name:       "indices.get_settings prefix only fallback",
			action:     "indices.get_settings",
			params:     map[string]any{"prefix": "index.routing.*"},
			wantMethod: http.MethodGet,
			wantPath:   "/_all/_settings/index.routing.*",
		},

		// indices.stats
		{
			name:       "indices.stats default",
			action:     "indices.stats",
			params:     map[string]any{"level": "shards"},
			wantMethod: http.MethodGet,
			wantPath:   "/_stats",
			wantQuery:  map[string]string{"level": "shards"},
		},
		{
			name:          "indices.stats index only",
			action:        "indices.stats",
			params:        map[string]any{"index": "idx1", "level": "indices"},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_stats",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"level": "indices"},
		},
		{
			name:          "indices.stats metric only",
			action:        "indices.stats",
			params:        map[string]any{"metric": "docs,store", "level": "cluster"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_stats/docs,store",
			strippedParam: []string{"metric"},
			wantQuery:     map[string]string{"level": "cluster"},
		},
		{
			name:          "indices.stats index and metric",
			action:        "indices.stats",
			params:        map[string]any{"index": "idx1", "metric": "search", "fields": "f1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_stats/search",
			strippedParam: []string{"index", "metric"},
			wantQuery:     map[string]string{"fields": "f1"},
		},

		// ilm.explain_lifecycle
		{
			name:       "ilm.explain_lifecycle empty index",
			action:     "ilm.explain_lifecycle",
			params:     map[string]any{"only_managed": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_ilm/explain",
			wantQuery:  map[string]string{"only_managed": "true"},
		},
		{
			name:          "ilm.explain_lifecycle with index",
			action:        "ilm.explain_lifecycle",
			params:        map[string]any{"index": "my_logs-*", "only_errors": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/my_logs-*/_ilm/explain",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"only_errors": "true"},
		},

		// F0: data stream actions
		{
			name:       "indices.data_stream_stats default",
			action:     "indices.data_stream_stats",
			params:     map[string]any{"human": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_data_stream/_stats",
			wantQuery:  map[string]string{"human": "true"},
		},
		{
			name:          "indices.data_stream_stats with name",
			action:        "indices.data_stream_stats",
			params:        map[string]any{"name": "ds-1", "human": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_data_stream/ds-1/_stats",
			strippedParam: []string{"name"},
			wantQuery:     map[string]string{"human": "true"},
		},
		{
			name:       "indices.data_streams_stats default",
			action:     "indices.data_streams_stats",
			params:     map[string]any{"human": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_data_stream/_stats",
			wantQuery:  map[string]string{"human": "true"},
		},
		{
			name:          "indices.data_streams_stats with name",
			action:        "indices.data_streams_stats",
			params:        map[string]any{"name": "ds-1,ds-2"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_data_stream/ds-1,ds-2/_stats",
			strippedParam: []string{"name"},
		},
		{
			name:          "indices.migrate_to_data_stream",
			action:        "indices.migrate_to_data_stream",
			params:        map[string]any{"name": "my-logs"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_data_stream/_migrate/my-logs",
			strippedParam: []string{"name"},
		},

		// F1: alias parameter variant
		{
			name:          "indices.put_alias with alias param",
			action:        "indices.put_alias",
			params:        map[string]any{"index": "idx1", "alias": "al1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/idx1/_alias/al1",
			strippedParam: []string{"index", "alias"},
		},
		{
			name:          "indices.get_alias with alias param",
			action:        "indices.get_alias",
			params:        map[string]any{"index": "idx1", "alias": "al1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/idx1/_alias/al1",
			strippedParam: []string{"index", "alias"},
		},
		{
			name:          "indices.delete_alias with alias param",
			action:        "indices.delete_alias",
			params:        map[string]any{"index": "idx1", "alias": "al1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/idx1/_alias/al1",
			strippedParam: []string{"index", "alias"},
		},
		{
			name:          "indices.exists_alias with alias param",
			action:        "indices.exists_alias",
			params:        map[string]any{"index": "idx1", "alias": "al1"},
			wantMethod:    http.MethodHead,
			wantPath:      "/idx1/_alias/al1",
			strippedParam: []string{"index", "alias"},
		},
		{
			name:          "cat.aliases with alias param",
			action:        "cat.aliases",
			params:        map[string]any{"alias": "al1", "v": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cat/aliases/al1",
			strippedParam: []string{"alias"},
			wantQuery:     map[string]string{"v": "true"},
		},

		// F2: ilm.retry and policy_id
		{
			name:          "ilm.retry",
			action:        "ilm.retry",
			params:        map[string]any{"index": "my_idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/my_idx/_ilm/retry",
			strippedParam: []string{"index"},
		},
		{
			name:          "ilm.put_lifecycle with policy_id",
			action:        "ilm.put_lifecycle",
			params:        map[string]any{"policy_id": "pol_1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_ilm/policy/pol_1",
			strippedParam: []string{"policy_id"},
		},

		// F3: cat.* optional path parameters
		{
			name:          "cat.allocation with node_id",
			action:        "cat.allocation",
			params:        map[string]any{"node_id": "node-1", "v": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cat/allocation/node-1",
			strippedParam: []string{"node_id"},
			wantQuery:     map[string]string{"v": "true"},
		},
		{
			name:          "cat.fielddata with fields",
			action:        "cat.fielddata",
			params:        map[string]any{"fields": "f1,f2", "v": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cat/fielddata/f1,f2",
			strippedParam: []string{"fields"},
			wantQuery:     map[string]string{"v": "true"},
		},
		{
			name:          "cat.segments with index",
			action:        "cat.segments",
			params:        map[string]any{"index": "idx1", "v": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cat/segments/idx1",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"v": "true"},
		},
		{
			name:          "cat.thread_pool with thread_pool_patterns",
			action:        "cat.thread_pool",
			params:        map[string]any{"thread_pool_patterns": "search,write", "v": true},
			wantMethod:    http.MethodGet,
			wantPath:      "/_cat/thread_pool/search,write",
			strippedParam: []string{"thread_pool_patterns"},
			wantQuery:     map[string]string{"v": "true"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ctx.buildActionRequest(tc.action, tc.params)
			if err != nil {
				t.Fatalf("buildActionRequest(%q, %v) unexpected error: %v", tc.action, tc.params, err)
			}
			if spec.method != tc.wantMethod {
				t.Errorf("method: got %q, want %q", spec.method, tc.wantMethod)
			}
			if spec.path != tc.wantPath {
				t.Errorf("path: got %q, want %q", spec.path, tc.wantPath)
			}
			for _, stripped := range tc.strippedParam {
				if spec.query.Has(stripped) {
					t.Errorf("expected param %q to be stripped from query, got query=%v", stripped, spec.query)
				}
			}
			for k, wantV := range tc.wantQuery {
				if gotV := spec.query.Get(k); gotV != wantV {
					t.Errorf("query[%q]: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

func TestTrackCreatedResourcesAndCleanup(t *testing.T) {
	var mu sync.Mutex
	var deletedPaths []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletedPaths = append(deletedPaths, r.URL.Path)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer ts.Close()

	ctx := newRunnerContext(ts.Client(), ts.URL)

	// 1. indices.clone, indices.split, indices.shrink target tracking
	ctx.trackCreatedResources("indices.clone", map[string]any{"index": "src_idx", "target": "cloned_target"}, nil)
	ctx.trackCreatedResources("indices.split", map[string]any{"index": "src_idx", "target": "split_target"}, nil)
	ctx.trackCreatedResources("indices.shrink", map[string]any{"index": "src_idx", "target": "shrink_target"}, nil)

	for _, target := range []string{"cloned_target", "split_target", "shrink_target"} {
		if !ctx.createdIndices[target] {
			t.Errorf("expected target %q to be tracked in createdIndices", target)
		}
	}

	// 2. indices.create aliases in body
	ctx.trackCreatedResources("indices.create", map[string]any{
		"index": "created_idx",
		"body": map[string]any{
			"aliases": map[string]any{
				"create_alias_1": map[string]any{},
				"create_alias_2": map[string]any{"is_write_index": true},
			},
		},
	}, nil)
	for _, al := range []string{"create_alias_1", "create_alias_2"} {
		if gotIdx := ctx.createdAliases[al]; gotIdx != "created_idx" {
			t.Errorf("expected createdAliases[%q] = %q, got %q", al, "created_idx", gotIdx)
		}
	}

	// 3. indices.update_aliases actions[].add with alias and aliases slice
	ctx.trackCreatedResources("indices.update_aliases", map[string]any{
		"body": map[string]any{
			"actions": []any{
				map[string]any{
					"add": map[string]any{
						"index": "idx_a",
						"alias": "upd_alias_single",
					},
				},
				map[string]any{
					"add": map[string]any{
						"indices": []any{"idx_a", "idx_b"},
						"aliases": []any{"upd_alias_multi_1", "upd_alias_multi_2"},
					},
				},
			},
		},
	}, nil)
	for _, al := range []string{"upd_alias_single", "upd_alias_multi_1", "upd_alias_multi_2"} {
		if _, exists := ctx.createdAliases[al]; !exists {
			t.Errorf("expected %q to be tracked in createdAliases", al)
		}
	}

	// 4. F0, F1, F2, F9 resource tracking (migrate_to_data_stream, bulk OrderedMap + NDJSON, reindex OrderedMap, put_alias alias, ilm.put_lifecycle, put_script, ingest.put_pipeline)
	ctx.trackCreatedResources("indices.migrate_to_data_stream", map[string]any{"name": "migrated_ds"}, nil)

	bulkOpMeta := NewOrderedMap()
	bulkOpMeta.Set("_index", "bulk_om_idx")
	bulkOp := NewOrderedMap()
	bulkOp.Set("index", bulkOpMeta)
	ctx.trackCreatedResources("bulk", map[string]any{
		"body": []any{bulkOp, map[string]any{"field": "val"}},
	}, nil)

	ctx.trackCreatedResources("bulk", map[string]any{
		"body": "{\"index\":{\"_index\":\"bulk_ndjson_idx1\"}}\n{\"a\":1}\n{\"create\":{\"_index\":\"bulk_ndjson_idx2\"}}\n{\"b\":2}\n",
	}, nil)

	reindexDest := NewOrderedMap()
	reindexDest.Set("index", "reindex_om_dest")
	reindexBody := NewOrderedMap()
	reindexBody.Set("dest", reindexDest)
	ctx.trackCreatedResources("reindex", map[string]any{"body": reindexBody}, nil)

	ctx.trackCreatedResources("indices.put_alias", map[string]any{"index": "alias_param_idx", "alias": "alias_param_name"}, nil)
	ctx.trackCreatedResources("ilm.put_lifecycle", map[string]any{"policy_id": "test_ilm_pol"}, nil)
	ctx.trackCreatedResources("put_script", map[string]any{"id": "test_script_id"}, nil)
	ctx.trackCreatedResources("ingest.put_pipeline", map[string]any{"id": "test_pipeline_id"}, nil)

	// 5. cleanupAll issues DELETE for all tracked resources
	ctx.cleanupAll()

	mu.Lock()
	defer mu.Unlock()
	seenDelete := make(map[string]bool, len(deletedPaths))
	for _, p := range deletedPaths {
		seenDelete[p] = true
	}

	expectedDeletes := []string{
		"/created_idx/_alias/create_alias_1",
		"/_all/_alias/create_alias_1",
		"/created_idx/_alias/create_alias_2",
		"/_all/_alias/create_alias_2",
		"/idx_a/_alias/upd_alias_single",
		"/_all/_alias/upd_alias_single",
		"/_all/_alias/upd_alias_multi_1",
		"/_all/_alias/upd_alias_multi_2",
		"/alias_param_idx/_alias/alias_param_name",
		"/_all/_alias/alias_param_name",
		"/_data_stream/migrated_ds",
		"/bulk_om_idx",
		"/bulk_ndjson_idx1",
		"/bulk_ndjson_idx2",
		"/reindex_om_dest",
		"/_ilm/policy/test_ilm_pol",
		"/_scripts/test_script_id",
		"/_ingest/pipeline/test_pipeline_id",
	}
	for _, exp := range expectedDeletes {
		if !seenDelete[exp] {
			t.Errorf("expected cleanupAll to issue DELETE %s, got deletedPaths=%v", exp, deletedPaths)
		}
	}
}

func TestRunnerCleanTextFeatureAndMatch(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	skipMap := NewOrderedMap()
	skipMap.Set("features", "clean_text")
	if err := ctx.execSkip(skipMap); err != nil {
		t.Fatalf("expected clean_text feature to be supported and not skipped, got: %v", err)
	}

	ctx.lastBodyRaw = "  idx1   green   open  \n  idx2   yellow  open  \n\n"
	ctx.lastResponse = ctx.lastBodyRaw

	matchMap := NewOrderedMap()
	matchMap.Set("$body", "\nidx1   green   open\nidx2   yellow  open\n")
	if err := ctx.execMatch(matchMap); err != nil {
		t.Fatalf("expected clean_text execMatch to succeed on line-trimmed text, got: %v", err)
	}
}

func TestRound52BuildActionRequestF0(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	cases := []struct {
		name          string
		action        string
		params        map[string]any
		wantMethod    string
		wantPath      string
		strippedParam []string
		wantQuery     map[string]string
	}{
		// indices.add_block, indices.modify_data_stream, indices.promote_data_stream, indices.downgrade
		{
			name:          "indices.add_block",
			action:        "indices.add_block",
			params:        map[string]any{"index": "my_idx", "block": "read_only", "allow_no_indices": true},
			wantMethod:    http.MethodPut,
			wantPath:      "/my_idx/_block/read_only",
			strippedParam: []string{"index", "block"},
			wantQuery:     map[string]string{"allow_no_indices": "true"},
		},
		{
			name:       "indices.modify_data_stream",
			action:     "indices.modify_data_stream",
			params:     map[string]any{"body": map[string]any{"actions": []any{}}},
			wantMethod: http.MethodPost,
			wantPath:   "/_data_stream/_modify",
		},
		{
			name:          "indices.promote_data_stream",
			action:        "indices.promote_data_stream",
			params:        map[string]any{"name": "ds-rep"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_data_stream/_promote/ds-rep",
			strippedParam: []string{"name"},
		},
		{
			name:          "data_stream.create_data_stream",
			action:        "data_stream.create_data_stream",
			params:        map[string]any{"name": "ds-alias"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_data_stream/ds-alias",
			strippedParam: []string{"name"},
		},
		{
			name:          "indices.downgrade",
			action:        "indices.downgrade",
			params:        map[string]any{"index": "old_idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/old_idx/_downgrade",
			strippedParam: []string{"index"},
		},

		// slm.*
		{
			name:          "slm.put_lifecycle with policy_id",
			action:        "slm.put_lifecycle",
			params:        map[string]any{"policy_id": "daily-snapshots"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_slm/policy/daily-snapshots",
			strippedParam: []string{"policy_id"},
		},
		{
			name:          "slm.put_lifecycle with policy",
			action:        "slm.put_lifecycle",
			params:        map[string]any{"policy": "nightly"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_slm/policy/nightly",
			strippedParam: []string{"policy"},
		},
		{
			name:          "slm.put_lifecycle with id",
			action:        "slm.put_lifecycle",
			params:        map[string]any{"id": "hourly"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_slm/policy/hourly",
			strippedParam: []string{"id"},
		},
		{
			name:          "slm.put_lifecycle with name",
			action:        "slm.put_lifecycle",
			params:        map[string]any{"name": "weekly"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_slm/policy/weekly",
			strippedParam: []string{"name"},
		},
		{
			name:          "slm.get_lifecycle with policy_id",
			action:        "slm.get_lifecycle",
			params:        map[string]any{"policy_id": "daily-snapshots"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_slm/policy/daily-snapshots",
			strippedParam: []string{"policy_id"},
		},
		{
			name:       "slm.get_lifecycle all",
			action:     "slm.get_lifecycle",
			params:     map[string]any{"human": true},
			wantMethod: http.MethodGet,
			wantPath:   "/_slm/policy",
			wantQuery:  map[string]string{"human": "true"},
		},
		{
			name:          "slm.delete_lifecycle",
			action:        "slm.delete_lifecycle",
			params:        map[string]any{"policy_id": "daily-snapshots"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_slm/policy/daily-snapshots",
			strippedParam: []string{"policy_id"},
		},
		{
			name:          "slm.execute_lifecycle",
			action:        "slm.execute_lifecycle",
			params:        map[string]any{"policy_id": "daily-snapshots"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_slm/policy/daily-snapshots/_execute",
			strippedParam: []string{"policy_id"},
		},
		{
			name:       "slm.execute_retention",
			action:     "slm.execute_retention",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_slm/_execute_retention",
		},
		{
			name:       "slm.get_stats",
			action:     "slm.get_stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_slm/stats",
		},
		{
			name:       "slm.get_status",
			action:     "slm.get_status",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_slm/status",
		},
		{
			name:       "slm.start",
			action:     "slm.start",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_slm/start",
		},
		{
			name:       "slm.stop",
			action:     "slm.stop",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_slm/stop",
		},

		// ingest metadata
		{
			name:       "ingest.processor_grok",
			action:     "ingest.processor_grok",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_ingest/processor/grok",
		},
		{
			name:       "ingest.geo_ip_stats",
			action:     "ingest.geo_ip_stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_ingest/geoip/stats",
		},

		// watcher.*
		{
			name:          "watcher.put_watch with id",
			action:        "watcher.put_watch",
			params:        map[string]any{"id": "my_watch", "active": false},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch",
			strippedParam: []string{"id"},
			wantQuery:     map[string]string{"active": "false"},
		},
		{
			name:          "watcher.put_watch with watch_id",
			action:        "watcher.put_watch",
			params:        map[string]any{"watch_id": "my_watch_2"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch_2",
			strippedParam: []string{"watch_id"},
		},
		{
			name:          "watcher.get_watch",
			action:        "watcher.get_watch",
			params:        map[string]any{"id": "my_watch"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_watcher/watch/my_watch",
			strippedParam: []string{"id"},
		},
		{
			name:          "watcher.delete_watch",
			action:        "watcher.delete_watch",
			params:        map[string]any{"id": "my_watch"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_watcher/watch/my_watch",
			strippedParam: []string{"id"},
		},
		{
			name:          "watcher.execute_watch with id",
			action:        "watcher.execute_watch",
			params:        map[string]any{"id": "my_watch"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_watcher/watch/my_watch/_execute",
			strippedParam: []string{"id"},
		},
		{
			name:       "watcher.execute_watch without id",
			action:     "watcher.execute_watch",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_watcher/watch/_execute",
		},
		{
			name:          "watcher.ack_watch without action_id",
			action:        "watcher.ack_watch",
			params:        map[string]any{"watch_id": "my_watch"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch/_ack",
			strippedParam: []string{"watch_id"},
		},
		{
			name:          "watcher.ack_watch with action_id",
			action:        "watcher.ack_watch",
			params:        map[string]any{"watch_id": "my_watch", "action_id": "act1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch/_ack/act1",
			strippedParam: []string{"watch_id", "action_id"},
		},
		{
			name:          "watcher.activate_watch",
			action:        "watcher.activate_watch",
			params:        map[string]any{"watch_id": "my_watch"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch/_activate",
			strippedParam: []string{"watch_id"},
		},
		{
			name:          "watcher.deactivate_watch",
			action:        "watcher.deactivate_watch",
			params:        map[string]any{"watch_id": "my_watch"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_watcher/watch/my_watch/_deactivate",
			strippedParam: []string{"watch_id"},
		},
		{
			name:       "watcher.stats without metric",
			action:     "watcher.stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_watcher/stats",
		},
		{
			name:          "watcher.stats with metric",
			action:        "watcher.stats",
			params:        map[string]any{"metric": "current_watches"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_watcher/stats/current_watches",
			strippedParam: []string{"metric"},
		},
		{
			name:       "watcher.start",
			action:     "watcher.start",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_watcher/_start",
		},
		{
			name:       "watcher.stop",
			action:     "watcher.stop",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_watcher/_stop",
		},

		// transform.*
		{
			name:          "transform.put_transform",
			action:        "transform.put_transform",
			params:        map[string]any{"transform_id": "t1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_transform/t1",
			strippedParam: []string{"transform_id"},
		},
		{
			name:          "transform.get_transform with id",
			action:        "transform.get_transform",
			params:        map[string]any{"transform_id": "t1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_transform/t1",
			strippedParam: []string{"transform_id"},
		},
		{
			name:       "transform.get_transform all",
			action:     "transform.get_transform",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_transform",
		},
		{
			name:          "transform.delete_transform",
			action:        "transform.delete_transform",
			params:        map[string]any{"transform_id": "t1", "force": true},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_transform/t1",
			strippedParam: []string{"transform_id"},
			wantQuery:     map[string]string{"force": "true"},
		},
		{
			name:          "transform.start_transform",
			action:        "transform.start_transform",
			params:        map[string]any{"transform_id": "t1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_transform/t1/_start",
			strippedParam: []string{"transform_id"},
		},
		{
			name:          "transform.stop_transform",
			action:        "transform.stop_transform",
			params:        map[string]any{"transform_id": "t1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_transform/t1/_stop",
			strippedParam: []string{"transform_id"},
		},
		{
			name:          "transform.get_transform_stats with id",
			action:        "transform.get_transform_stats",
			params:        map[string]any{"transform_id": "t1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_transform/t1/_stats",
			strippedParam: []string{"transform_id"},
		},
		{
			name:       "transform.get_transform_stats all",
			action:     "transform.get_transform_stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_transform/_stats",
		},
		{
			name:       "transform.preview_transform",
			action:     "transform.preview_transform",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_transform/_preview",
		},

		// dangling_indices.*
		{
			name:       "dangling_indices.list_dangling_indices",
			action:     "dangling_indices.list_dangling_indices",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_dangling",
		},
		{
			name:          "dangling_indices.import_dangling_index",
			action:        "dangling_indices.import_dangling_index",
			params:        map[string]any{"index_uuid": "uuid-123", "accept_data_loss": true},
			wantMethod:    http.MethodPost,
			wantPath:      "/_dangling/uuid-123",
			strippedParam: []string{"index_uuid"},
			wantQuery:     map[string]string{"accept_data_loss": "true"},
		},
		{
			name:          "dangling_indices.delete_dangling_index",
			action:        "dangling_indices.delete_dangling_index",
			params:        map[string]any{"index_uuid": "uuid-123", "accept_data_loss": true},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_dangling/uuid-123",
			strippedParam: []string{"index_uuid"},
			wantQuery:     map[string]string{"accept_data_loss": "true"},
		},

		// autoscaling.*
		{
			name:          "autoscaling.put_autoscaling_policy",
			action:        "autoscaling.put_autoscaling_policy",
			params:        map[string]any{"name": "my_auto_pol"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_autoscaling/policy/my_auto_pol",
			strippedParam: []string{"name"},
		},
		{
			name:          "autoscaling.get_autoscaling_policy with name",
			action:        "autoscaling.get_autoscaling_policy",
			params:        map[string]any{"name": "my_auto_pol"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_autoscaling/policy/my_auto_pol",
			strippedParam: []string{"name"},
		},
		{
			name:       "autoscaling.get_autoscaling_policy all",
			action:     "autoscaling.get_autoscaling_policy",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_autoscaling/policy",
		},
		{
			name:          "autoscaling.delete_autoscaling_policy",
			action:        "autoscaling.delete_autoscaling_policy",
			params:        map[string]any{"name": "my_auto_pol"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_autoscaling/policy/my_auto_pol",
			strippedParam: []string{"name"},
		},
		{
			name:       "autoscaling.get_autoscaling_capacity",
			action:     "autoscaling.get_autoscaling_capacity",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_autoscaling/capacity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ctx.buildActionRequest(tc.action, tc.params)
			if err != nil {
				t.Fatalf("buildActionRequest(%q, %v) unexpected error: %v", tc.action, tc.params, err)
			}
			if spec.method != tc.wantMethod {
				t.Errorf("method: got %q, want %q", spec.method, tc.wantMethod)
			}
			if spec.path != tc.wantPath {
				t.Errorf("path: got %q, want %q", spec.path, tc.wantPath)
			}
			for _, stripped := range tc.strippedParam {
				if spec.query.Has(stripped) {
					t.Errorf("expected param %q to be stripped from query, got query=%v", stripped, spec.query)
				}
			}
			for k, wantV := range tc.wantQuery {
				if gotV := spec.query.Get(k); gotV != wantV {
					t.Errorf("query[%q]: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

func TestRound52TrackResourcesAndBlockClearingCleanup(t *testing.T) {
	type reqRecord struct {
		method   string
		path     string
		rawQuery string
	}
	var mu sync.Mutex
	var recorded []reqRecord

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recorded = append(recorded, reqRecord{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer ts.Close()

	ctx := newRunnerContext(ts.Client(), ts.URL)

	ctx.trackCreatedResources("indices.add_block", map[string]any{"index": "blocked_idx", "block": "read_only"}, nil)
	ctx.trackCreatedResources("slm.put_lifecycle", map[string]any{"policy_id": "slm_pol_1"}, nil)
	ctx.trackCreatedResources("watcher.put_watch", map[string]any{"id": "watch_1"}, nil)
	ctx.trackCreatedResources("transform.put_transform", map[string]any{"transform_id": "tx_1"}, nil)
	ctx.trackCreatedResources("autoscaling.put_autoscaling_policy", map[string]any{"name": "auto_pol_1"}, nil)
	ctx.trackCreatedResources("indices.promote_data_stream", map[string]any{"name": "promoted_ds"}, nil)
	ctx.trackCreatedResources("data_stream.create_data_stream", map[string]any{"name": "created_ds_2"}, nil)
	ctx.trackCreatedResources("indices.modify_data_stream", map[string]any{
		"body": map[string]any{
			"actions": []any{
				map[string]any{
					"add_backing_index": map[string]any{
						"data_stream": "mod_ds",
						"index":       "backing_idx_1",
					},
				},
			},
		},
	}, nil)

	ctx.cleanupAll()

	mu.Lock()
	defer mu.Unlock()

	putSettingsIdx := -1
	deleteIdx := -1
	seenDelete := make(map[string]string)
	for i, rec := range recorded {
		if rec.method == http.MethodPut && rec.path == "/blocked_idx/_settings" {
			putSettingsIdx = i
		}
		if rec.method == http.MethodDelete && rec.path == "/blocked_idx" {
			deleteIdx = i
		}
		if rec.method == http.MethodDelete {
			key := rec.path
			if rec.rawQuery != "" {
				key += "?" + rec.rawQuery
			}
			seenDelete[key] = rec.method
		}
	}

	if putSettingsIdx == -1 || deleteIdx == -1 || putSettingsIdx > deleteIdx {
		t.Errorf("expected PUT /blocked_idx/_settings before DELETE /blocked_idx, got putSettingsIdx=%d deleteIdx=%d (recorded=%v)", putSettingsIdx, deleteIdx, recorded)
	}

	expectedDeletes := []string{
		"/_slm/policy/slm_pol_1",
		"/_watcher/watch/watch_1",
		"/_transform/tx_1?force=true",
		"/_autoscaling/policy/auto_pol_1",
		"/_data_stream/promoted_ds",
		"/_data_stream/created_ds_2",
		"/_data_stream/mod_ds",
		"/backing_idx_1",
	}
	for _, exp := range expectedDeletes {
		if _, ok := seenDelete[exp]; !ok {
			t.Errorf("expected cleanupAll to issue DELETE %s, got seenDelete=%v", exp, seenDelete)
		}
	}
}

func TestRound52F1Features(t *testing.T) {
	var gotCustomHeader string
	var gotQuery string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustomHeader = r.Header.Get("X-Custom-Header")
		gotQuery = r.URL.RawQuery
		w.Header().Add("Warning", `299 Elasticsearch-7.10.2 "first warning"`)
		w.Header().Add("Warning", `299 Elasticsearch-7.10.2 "second warning"`)
		w.Header().Add("X-Multi", "val1")
		w.Header().Add("X-Multi", "val2")
		w.Header().Set("X-Single", "only_one")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"str_field": "hello world compliance test",
			"map_field": {"a": 1, "b": {"nested": "ok", "extra": true}, "c": 3},
			"arr_field": [
				{"items": [{"k": "v1", "extra": 1}, {"k": "v2", "extra": 2}]},
				[10, 20, 30]
			]
		}`))
	}))
	defer ts.Close()

	ctx := newRunnerContext(ts.Client(), ts.URL)

	// 1. warning_headers feature is supported
	skipMap := NewOrderedMap()
	skipMap.Set("features", "warning_headers")
	if err := ctx.execSkip(skipMap); err != nil {
		t.Fatalf("expected warning_headers feature to be supported, got: %v", err)
	}

	// 2. execDo with warning_headers and action-level headers
	actionHeaders := NewOrderedMap()
	actionHeaders.Set("X-Custom-Header", "custom-val-123")
	searchParams := NewOrderedMap()
	searchParams.Set("headers", actionHeaders)
	searchParams.Set("index", "my_idx")

	doMap := NewOrderedMap()
	doMap.Set("warning_headers", []any{`299 Elasticsearch-7.10.2 "first warning"`})
	doMap.Set("search", searchParams)

	if err := ctx.execDo(doMap, false); err != nil {
		t.Fatalf("execDo failed: %v", err)
	}
	if gotCustomHeader != "custom-val-123" {
		t.Errorf("expected X-Custom-Header='custom-val-123', got %q", gotCustomHeader)
	}
	if gotQuery != "" {
		t.Errorf("expected action-level headers to be stripped from query string, got query %q", gotQuery)
	}

	// 3. Multi-value response headers joined with ", "
	if gotMulti, ok := ctx.lastHeaders["x-multi"].(string); !ok || gotMulti != "val1, val2" {
		t.Errorf("expected lastHeaders['x-multi'] = 'val1, val2', got %v", ctx.lastHeaders["x-multi"])
	}
	if gotSingle, ok := ctx.lastHeaders["x-single"].(string); !ok || gotSingle != "only_one" {
		t.Errorf("expected lastHeaders['x-single'] = 'only_one', got %v", ctx.lastHeaders["x-single"])
	}

	// 4. execContains on string (substring and regex), map[string]any, and nested []any
	containsStep := NewOrderedMap()
	containsStep.Set("str_field", "compliance")
	if err := ctx.execContains(containsStep); err != nil {
		t.Errorf("execContains on string substring failed: %v", err)
	}

	containsRegexStep := NewOrderedMap()
	containsRegexStep.Set("str_field", "/world\\s+compliance/")
	if err := ctx.execContains(containsRegexStep); err != nil {
		t.Errorf("execContains on string regex failed: %v", err)
	}

	containsMapStep := NewOrderedMap()
	containsMapStep.Set("map_field", map[string]any{
		"a": int64(1),
		"b": map[string]any{"nested": "ok"},
	})
	if err := ctx.execContains(containsMapStep); err != nil {
		t.Errorf("execContains on map subset failed: %v", err)
	}

	containsNestedSliceStep := NewOrderedMap()
	containsNestedSliceStep.Set("arr_field", map[string]any{
		"items": []any{
			map[string]any{"k": "v1"},
			map[string]any{"k": "v2"},
		},
	})
	if err := ctx.execContains(containsNestedSliceStep); err != nil {
		t.Errorf("execContains on nested slice of maps failed: %v", err)
	}

	containsDirectNestedSlice := NewOrderedMap()
	containsDirectNestedSlice.Set("arr_field", []any{int64(10), int64(20), int64(30)})
	if err := ctx.execContains(containsDirectNestedSlice); err != nil {
		t.Errorf("execContains on nested slice of ints failed: %v", err)
	}
}

func TestRound53BuildActionRequestF0(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")

	cases := []struct {
		name          string
		action        string
		params        map[string]any
		wantMethod    string
		wantPath      string
		strippedParam []string
		wantQuery     map[string]string
	}{
		// synonyms.*
		{
			name:          "synonyms.put_synonym with id",
			action:        "synonyms.put_synonym",
			params:        map[string]any{"id": "my-synonyms"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_synonyms/my-synonyms",
			strippedParam: []string{"id"},
		},
		{
			name:          "synonyms.put_synonym with synonyms_set",
			action:        "synonyms.put_synonym",
			params:        map[string]any{"synonyms_set": "my-synonyms-2"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_synonyms/my-synonyms-2",
			strippedParam: []string{"synonyms_set"},
		},
		{
			name:          "synonyms.get_synonym",
			action:        "synonyms.get_synonym",
			params:        map[string]any{"id": "my-synonyms", "size": 10},
			wantMethod:    http.MethodGet,
			wantPath:      "/_synonyms/my-synonyms",
			strippedParam: []string{"id"},
			wantQuery:     map[string]string{"size": "10"},
		},
		{
			name:       "synonyms.get_synonyms_sets",
			action:     "synonyms.get_synonyms_sets",
			params:     map[string]any{"from": 0, "size": 5},
			wantMethod: http.MethodGet,
			wantPath:   "/_synonyms",
			wantQuery:  map[string]string{"from": "0", "size": "5"},
		},
		{
			name:          "synonyms.delete_synonym",
			action:        "synonyms.delete_synonym",
			params:        map[string]any{"id": "my-synonyms"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_synonyms/my-synonyms",
			strippedParam: []string{"id"},
		},
		{
			name:          "synonyms.put_synonym_rule",
			action:        "synonyms.put_synonym_rule",
			params:        map[string]any{"set_id": "my-synonyms", "rule_id": "rule-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_synonyms/my-synonyms/rule-1",
			strippedParam: []string{"set_id", "rule_id"},
		},
		{
			name:          "synonyms.get_synonym_rule",
			action:        "synonyms.get_synonym_rule",
			params:        map[string]any{"synonyms_set": "my-synonyms", "rule_id": "rule-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_synonyms/my-synonyms/rule-1",
			strippedParam: []string{"synonyms_set", "rule_id"},
		},
		{
			name:          "synonyms.delete_synonym_rule",
			action:        "synonyms.delete_synonym_rule",
			params:        map[string]any{"id": "my-synonyms", "rule_id": "rule-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_synonyms/my-synonyms/rule-1",
			strippedParam: []string{"id", "rule_id"},
		},
		{
			name:          "synonyms.reload_synonym",
			action:        "synonyms.reload_synonym",
			params:        map[string]any{"id": "my-synonyms"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_synonyms/my-synonyms/_reload",
			strippedParam: []string{"id"},
		},

		// query_rules.*
		{
			name:          "query_rules.put_ruleset",
			action:        "query_rules.put_ruleset",
			params:        map[string]any{"ruleset_id": "rs-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_query_rules/rs-1",
			strippedParam: []string{"ruleset_id"},
		},
		{
			name:          "query_rules.get_ruleset",
			action:        "query_rules.get_ruleset",
			params:        map[string]any{"ruleset_id": "rs-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_query_rules/rs-1",
			strippedParam: []string{"ruleset_id"},
		},
		{
			name:       "query_rules.list_rulesets",
			action:     "query_rules.list_rulesets",
			params:     map[string]any{"from": 0},
			wantMethod: http.MethodGet,
			wantPath:   "/_query_rules",
			wantQuery:  map[string]string{"from": "0"},
		},
		{
			name:          "query_rules.delete_ruleset",
			action:        "query_rules.delete_ruleset",
			params:        map[string]any{"ruleset_id": "rs-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_query_rules/rs-1",
			strippedParam: []string{"ruleset_id"},
		},
		{
			name:          "query_rules.put_rule",
			action:        "query_rules.put_rule",
			params:        map[string]any{"ruleset_id": "rs-1", "rule_id": "r-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_query_rules/rs-1/_rule/r-1",
			strippedParam: []string{"ruleset_id", "rule_id"},
		},
		{
			name:          "query_rules.get_rule",
			action:        "query_rules.get_rule",
			params:        map[string]any{"ruleset_id": "rs-1", "rule_id": "r-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_query_rules/rs-1/_rule/r-1",
			strippedParam: []string{"ruleset_id", "rule_id"},
		},
		{
			name:          "query_rules.delete_rule",
			action:        "query_rules.delete_rule",
			params:        map[string]any{"ruleset_id": "rs-1", "rule_id": "r-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_query_rules/rs-1/_rule/r-1",
			strippedParam: []string{"ruleset_id", "rule_id"},
		},
		{
			name:          "query_rules.test",
			action:        "query_rules.test",
			params:        map[string]any{"ruleset_id": "rs-1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_query_rules/rs-1/_test",
			strippedParam: []string{"ruleset_id"},
		},

		// features.* and cluster.*_voting_config_exclusions
		{
			name:       "features.get_features",
			action:     "features.get_features",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_features",
		},
		{
			name:       "features.reset_features",
			action:     "features.reset_features",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_features/_reset",
		},
		{
			name:       "cluster.post_voting_config_exclusions",
			action:     "cluster.post_voting_config_exclusions",
			params:     map[string]any{"node_names": "node-1"},
			wantMethod: http.MethodPost,
			wantPath:   "/_cluster/voting_config_exclusions",
			wantQuery:  map[string]string{"node_names": "node-1"},
		},
		{
			name:       "cluster.delete_voting_config_exclusions",
			action:     "cluster.delete_voting_config_exclusions",
			params:     map[string]any{"wait_for_removal": false},
			wantMethod: http.MethodDelete,
			wantPath:   "/_cluster/voting_config_exclusions",
			wantQuery:  map[string]string{"wait_for_removal": "false"},
		},

		// migration.* and shutdown.*
		{
			name:       "migration.deprecations cluster",
			action:     "migration.deprecations",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_migration/deprecations",
		},
		{
			name:          "migration.deprecations with index",
			action:        "migration.deprecations",
			params:        map[string]any{"index": "my-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/my-idx/_migration/deprecations",
			strippedParam: []string{"index"},
		},
		{
			name:          "shutdown.put_node",
			action:        "shutdown.put_node",
			params:        map[string]any{"node_id": "node-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_nodes/node-1/shutdown",
			strippedParam: []string{"node_id"},
		},
		{
			name:       "shutdown.get_node all",
			action:     "shutdown.get_node",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_nodes/shutdown",
		},
		{
			name:          "shutdown.get_node with node_id",
			action:        "shutdown.get_node",
			params:        map[string]any{"node_id": "node-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_nodes/node-1/shutdown",
			strippedParam: []string{"node_id"},
		},
		{
			name:          "shutdown.delete_node",
			action:        "shutdown.delete_node",
			params:        map[string]any{"node_id": "node-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_nodes/node-1/shutdown",
			strippedParam: []string{"node_id"},
		},

		// rollup.*
		{
			name:          "rollup.put_job",
			action:        "rollup.put_job",
			params:        map[string]any{"id": "job-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_rollup/job/job-1",
			strippedParam: []string{"id"},
		},
		{
			name:       "rollup.get_jobs all",
			action:     "rollup.get_jobs",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_rollup/job",
		},
		{
			name:          "rollup.get_jobs with id",
			action:        "rollup.get_jobs",
			params:        map[string]any{"id": "job-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_rollup/job/job-1",
			strippedParam: []string{"id"},
		},
		{
			name:          "rollup.delete_job",
			action:        "rollup.delete_job",
			params:        map[string]any{"id": "job-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_rollup/job/job-1",
			strippedParam: []string{"id"},
		},
		{
			name:          "rollup.start_job",
			action:        "rollup.start_job",
			params:        map[string]any{"id": "job-1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_rollup/job/job-1/_start",
			strippedParam: []string{"id"},
		},
		{
			name:          "rollup.stop_job",
			action:        "rollup.stop_job",
			params:        map[string]any{"id": "job-1", "wait_for_completion": true},
			wantMethod:    http.MethodPost,
			wantPath:      "/_rollup/job/job-1/_stop",
			strippedParam: []string{"id"},
			wantQuery:     map[string]string{"wait_for_completion": "true"},
		},
		{
			name:       "rollup.get_rollup_caps all",
			action:     "rollup.get_rollup_caps",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_rollup/data/_all",
		},
		{
			name:          "rollup.get_rollup_caps with id",
			action:        "rollup.get_rollup_caps",
			params:        map[string]any{"id": "my-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_rollup/data/my-idx",
			strippedParam: []string{"id"},
		},
		{
			name:          "rollup.get_rollup_index_caps",
			action:        "rollup.get_rollup_index_caps",
			params:        map[string]any{"index": "rollup-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/rollup-idx/_rollup/data",
			strippedParam: []string{"index"},
		},
		{
			name:          "rollup.rollup_search GET",
			action:        "rollup.rollup_search",
			params:        map[string]any{"index": "rollup-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/rollup-idx/_rollup_search",
			strippedParam: []string{"index"},
		},
		{
			name:          "rollup.rollup_search POST",
			action:        "rollup.rollup_search",
			params:        map[string]any{"index": "rollup-idx", "body": map[string]any{"size": 0}},
			wantMethod:    http.MethodPost,
			wantPath:      "/rollup-idx/_rollup_search",
			strippedParam: []string{"index"},
		},

		// ccr.*
		{
			name:          "ccr.put_auto_follow_pattern",
			action:        "ccr.put_auto_follow_pattern",
			params:        map[string]any{"name": "pat-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_ccr/auto_follow/pat-1",
			strippedParam: []string{"name"},
		},
		{
			name:       "ccr.get_auto_follow_pattern all",
			action:     "ccr.get_auto_follow_pattern",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_ccr/auto_follow",
		},
		{
			name:          "ccr.get_auto_follow_pattern with name",
			action:        "ccr.get_auto_follow_pattern",
			params:        map[string]any{"name": "pat-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_ccr/auto_follow/pat-1",
			strippedParam: []string{"name"},
		},
		{
			name:          "ccr.delete_auto_follow_pattern",
			action:        "ccr.delete_auto_follow_pattern",
			params:        map[string]any{"name": "pat-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_ccr/auto_follow/pat-1",
			strippedParam: []string{"name"},
		},
		{
			name:          "ccr.pause_auto_follow_pattern",
			action:        "ccr.pause_auto_follow_pattern",
			params:        map[string]any{"name": "pat-1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_ccr/auto_follow/pat-1/_pause",
			strippedParam: []string{"name"},
		},
		{
			name:          "ccr.resume_auto_follow_pattern",
			action:        "ccr.resume_auto_follow_pattern",
			params:        map[string]any{"name": "pat-1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_ccr/auto_follow/pat-1/_resume",
			strippedParam: []string{"name"},
		},
		{
			name:          "ccr.follow",
			action:        "ccr.follow",
			params:        map[string]any{"index": "follower-idx", "wait_for_active_shards": "1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/follower-idx/_ccr/follow",
			strippedParam: []string{"index"},
			wantQuery:     map[string]string{"wait_for_active_shards": "1"},
		},
		{
			name:          "ccr.follow_info",
			action:        "ccr.follow_info",
			params:        map[string]any{"index": "follower-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/follower-idx/_ccr/info",
			strippedParam: []string{"index"},
		},
		{
			name:          "ccr.follow_stats",
			action:        "ccr.follow_stats",
			params:        map[string]any{"index": "follower-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/follower-idx/_ccr/stats",
			strippedParam: []string{"index"},
		},
		{
			name:          "ccr.pause_follow",
			action:        "ccr.pause_follow",
			params:        map[string]any{"index": "follower-idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/follower-idx/_ccr/pause_follow",
			strippedParam: []string{"index"},
		},
		{
			name:          "ccr.resume_follow",
			action:        "ccr.resume_follow",
			params:        map[string]any{"index": "follower-idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/follower-idx/_ccr/resume_follow",
			strippedParam: []string{"index"},
		},
		{
			name:          "ccr.unfollow",
			action:        "ccr.unfollow",
			params:        map[string]any{"index": "follower-idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/follower-idx/_ccr/unfollow",
			strippedParam: []string{"index"},
		},
		{
			name:          "ccr.forget_follower",
			action:        "ccr.forget_follower",
			params:        map[string]any{"index": "leader-idx"},
			wantMethod:    http.MethodPost,
			wantPath:      "/leader-idx/_ccr/forget_follower",
			strippedParam: []string{"index"},
		},
		{
			name:       "ccr.stats",
			action:     "ccr.stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_ccr/stats",
		},

		// searchable_snapshots.*
		{
			name:          "searchable_snapshots.mount",
			action:        "searchable_snapshots.mount",
			params:        map[string]any{"repository": "repo-1", "snapshot": "snap-1", "storage": "full_copy"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_snapshot/repo-1/snap-1/_mount",
			strippedParam: []string{"repository", "snapshot"},
			wantQuery:     map[string]string{"storage": "full_copy"},
		},
		{
			name:       "searchable_snapshots.stats all",
			action:     "searchable_snapshots.stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_searchable_snapshots/stats",
		},
		{
			name:          "searchable_snapshots.stats with index",
			action:        "searchable_snapshots.stats",
			params:        map[string]any{"index": "mounted-idx"},
			wantMethod:    http.MethodGet,
			wantPath:      "/mounted-idx/_searchable_snapshots/stats",
			strippedParam: []string{"index"},
		},
		{
			name:       "searchable_snapshots.cache_stats",
			action:     "searchable_snapshots.cache_stats",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_searchable_snapshots/cache/stats",
		},
		{
			name:       "searchable_snapshots.clear_cache",
			action:     "searchable_snapshots.clear_cache",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_searchable_snapshots/cache/clear",
		},

		// security.*
		{
			name:       "security.authenticate",
			action:     "security.authenticate",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/_authenticate",
		},
		{
			name:          "security.put_user",
			action:        "security.put_user",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_security/user/alice",
			strippedParam: []string{"username"},
		},
		{
			name:       "security.get_user all",
			action:     "security.get_user",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/user",
		},
		{
			name:          "security.get_user with username",
			action:        "security.get_user",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/user/alice",
			strippedParam: []string{"username"},
		},
		{
			name:          "security.delete_user",
			action:        "security.delete_user",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_security/user/alice",
			strippedParam: []string{"username"},
		},
		{
			name:          "security.enable_user",
			action:        "security.enable_user",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_security/user/alice/_enable",
			strippedParam: []string{"username"},
		},
		{
			name:          "security.disable_user",
			action:        "security.disable_user",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_security/user/alice/_disable",
			strippedParam: []string{"username"},
		},
		{
			name:       "security.change_password self",
			action:     "security.change_password",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/user/_password",
		},
		{
			name:          "security.change_password with username",
			action:        "security.change_password",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_security/user/alice/_password",
			strippedParam: []string{"username"},
		},
		{
			name:       "security.has_privileges self",
			action:     "security.has_privileges",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/user/_has_privileges",
		},
		{
			name:          "security.has_privileges with username",
			action:        "security.has_privileges",
			params:        map[string]any{"username": "alice"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_security/user/alice/_has_privileges",
			strippedParam: []string{"username"},
		},
		{
			name:          "security.put_role",
			action:        "security.put_role",
			params:        map[string]any{"name": "admin_role"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_security/role/admin_role",
			strippedParam: []string{"name"},
		},
		{
			name:       "security.get_role all",
			action:     "security.get_role",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/role",
		},
		{
			name:          "security.get_role with name",
			action:        "security.get_role",
			params:        map[string]any{"name": "admin_role"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/role/admin_role",
			strippedParam: []string{"name"},
		},
		{
			name:          "security.delete_role",
			action:        "security.delete_role",
			params:        map[string]any{"name": "admin_role"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_security/role/admin_role",
			strippedParam: []string{"name"},
		},
		{
			name:          "security.clear_cached_roles",
			action:        "security.clear_cached_roles",
			params:        map[string]any{"name": "admin_role"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_security/role/admin_role/_clear_cache",
			strippedParam: []string{"name"},
		},
		{
			name:       "security.create_api_key",
			action:     "security.create_api_key",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/api_key",
		},
		{
			name:       "security.get_api_key",
			action:     "security.get_api_key",
			params:     map[string]any{"id": "k1"},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/api_key",
			wantQuery:  map[string]string{"id": "k1"},
		},
		{
			name:       "security.invalidate_api_key",
			action:     "security.invalidate_api_key",
			params:     map[string]any{},
			wantMethod: http.MethodDelete,
			wantPath:   "/_security/api_key",
		},
		{
			name:       "security.grant_api_key",
			action:     "security.grant_api_key",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/api_key/_grant",
		},
		{
			name:       "security.query_api_keys",
			action:     "security.query_api_keys",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/_query/api_key",
		},
		{
			name:       "security.clear_api_key_cache",
			action:     "security.clear_api_key_cache",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/_clear_api_key_cache",
		},
		{
			name:       "security.get_builtin_privileges",
			action:     "security.get_builtin_privileges",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/privilege/_builtin",
		},
		{
			name:       "security.put_privileges",
			action:     "security.put_privileges",
			params:     map[string]any{},
			wantMethod: http.MethodPut,
			wantPath:   "/_security/privilege",
		},
		{
			name:       "security.get_privileges all",
			action:     "security.get_privileges",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/privilege",
		},
		{
			name:          "security.get_privileges app only",
			action:        "security.get_privileges",
			params:        map[string]any{"application": "myapp"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/privilege/myapp",
			strippedParam: []string{"application"},
		},
		{
			name:          "security.get_privileges app and name",
			action:        "security.get_privileges",
			params:        map[string]any{"application": "myapp", "name": "read"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/privilege/myapp/read",
			strippedParam: []string{"application", "name"},
		},
		{
			name:          "security.delete_privileges",
			action:        "security.delete_privileges",
			params:        map[string]any{"application": "myapp", "name": "read"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_security/privilege/myapp/read",
			strippedParam: []string{"application", "name"},
		},
		{
			name:          "security.create_service_token with token_name",
			action:        "security.create_service_token",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server", "token_name": "tok1"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_security/service/elastic/fleet-server/credential/token/tok1",
			strippedParam: []string{"namespace", "service", "token_name"},
		},
		{
			name:          "security.create_service_token without token_name",
			action:        "security.create_service_token",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server"},
			wantMethod:    http.MethodPost,
			wantPath:      "/_security/service/elastic/fleet-server/credential/token",
			strippedParam: []string{"namespace", "service"},
		},
		{
			name:          "security.delete_service_token",
			action:        "security.delete_service_token",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server", "token_name": "tok1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_security/service/elastic/fleet-server/credential/token/tok1",
			strippedParam: []string{"namespace", "service", "token_name"},
		},
		{
			name:          "security.list_service_tokens",
			action:        "security.list_service_tokens",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/service/elastic/fleet-server/credential/token",
			strippedParam: []string{"namespace", "service"},
		},
		{
			name:       "security.get_service_accounts all",
			action:     "security.get_service_accounts",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_security/service",
		},
		{
			name:          "security.get_service_accounts namespace only",
			action:        "security.get_service_accounts",
			params:        map[string]any{"namespace": "elastic"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/service/elastic",
			strippedParam: []string{"namespace"},
		},
		{
			name:          "security.get_service_accounts namespace and service",
			action:        "security.get_service_accounts",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/service/elastic/fleet-server",
			strippedParam: []string{"namespace", "service"},
		},
		{
			name:          "security.get_service_credentials",
			action:        "security.get_service_credentials",
			params:        map[string]any{"namespace": "elastic", "service": "fleet-server"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_security/service/elastic/fleet-server/credential",
			strippedParam: []string{"namespace", "service"},
		},
		{
			name:       "security.get_token",
			action:     "security.get_token",
			params:     map[string]any{},
			wantMethod: http.MethodPost,
			wantPath:   "/_security/oauth2/token",
		},
		{
			name:       "security.invalidate_token",
			action:     "security.invalidate_token",
			params:     map[string]any{},
			wantMethod: http.MethodDelete,
			wantPath:   "/_security/oauth2/token",
		},

		// logstash.* and transform.update_transform
		{
			name:          "logstash.put_pipeline",
			action:        "logstash.put_pipeline",
			params:        map[string]any{"id": "pipe-1"},
			wantMethod:    http.MethodPut,
			wantPath:      "/_logstash/pipeline/pipe-1",
			strippedParam: []string{"id"},
		},
		{
			name:       "logstash.get_pipeline all",
			action:     "logstash.get_pipeline",
			params:     map[string]any{},
			wantMethod: http.MethodGet,
			wantPath:   "/_logstash/pipeline",
		},
		{
			name:          "logstash.get_pipeline with id",
			action:        "logstash.get_pipeline",
			params:        map[string]any{"id": "pipe-1"},
			wantMethod:    http.MethodGet,
			wantPath:      "/_logstash/pipeline/pipe-1",
			strippedParam: []string{"id"},
		},
		{
			name:          "logstash.delete_pipeline",
			action:        "logstash.delete_pipeline",
			params:        map[string]any{"id": "pipe-1"},
			wantMethod:    http.MethodDelete,
			wantPath:      "/_logstash/pipeline/pipe-1",
			strippedParam: []string{"id"},
		},
		{
			name:          "transform.update_transform",
			action:        "transform.update_transform",
			params:        map[string]any{"transform_id": "tx-1", "defer_validation": true},
			wantMethod:    http.MethodPost,
			wantPath:      "/_transform/tx-1/_update",
			strippedParam: []string{"transform_id"},
			wantQuery:     map[string]string{"defer_validation": "true"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ctx.buildActionRequest(tc.action, tc.params)
			if err != nil {
				t.Fatalf("buildActionRequest(%q, %v) unexpected error: %v", tc.action, tc.params, err)
			}
			if spec.method != tc.wantMethod {
				t.Errorf("method: got %q, want %q", spec.method, tc.wantMethod)
			}
			if spec.path != tc.wantPath {
				t.Errorf("path: got %q, want %q", spec.path, tc.wantPath)
			}
			for _, stripped := range tc.strippedParam {
				if spec.query.Has(stripped) {
					t.Errorf("expected param %q to be stripped from query, got query=%v", stripped, spec.query)
				}
			}
			for k, wantV := range tc.wantQuery {
				if gotV := spec.query.Get(k); gotV != wantV {
					t.Errorf("query[%q]: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}

	missingParamActions := []string{
		"synonyms.put_synonym",
		"synonyms.get_synonym",
		"synonyms.delete_synonym",
		"synonyms.put_synonym_rule",
		"synonyms.get_synonym_rule",
		"synonyms.delete_synonym_rule",
		"synonyms.reload_synonym",
		"query_rules.put_ruleset",
		"query_rules.get_ruleset",
		"query_rules.delete_ruleset",
		"query_rules.put_rule",
		"query_rules.get_rule",
		"query_rules.delete_rule",
		"query_rules.test",
		"shutdown.put_node",
		"shutdown.delete_node",
		"rollup.put_job",
		"rollup.delete_job",
		"rollup.start_job",
		"rollup.stop_job",
		"rollup.get_rollup_index_caps",
		"rollup.rollup_search",
		"ccr.put_auto_follow_pattern",
		"ccr.delete_auto_follow_pattern",
		"ccr.pause_auto_follow_pattern",
		"ccr.resume_auto_follow_pattern",
		"ccr.follow",
		"ccr.follow_info",
		"ccr.follow_stats",
		"ccr.pause_follow",
		"ccr.resume_follow",
		"ccr.unfollow",
		"ccr.forget_follower",
		"searchable_snapshots.mount",
		"security.put_user",
		"security.delete_user",
		"security.enable_user",
		"security.disable_user",
		"security.put_role",
		"security.delete_role",
		"security.clear_cached_roles",
		"security.delete_privileges",
		"security.create_service_token",
		"security.delete_service_token",
		"security.list_service_tokens",
		"security.get_service_credentials",
		"logstash.put_pipeline",
		"logstash.delete_pipeline",
		"transform.update_transform",
	}
	for _, act := range missingParamActions {
		if _, err := ctx.buildActionRequest(act, map[string]any{}); err == nil {
			t.Errorf("expected error for %s with empty params", act)
		}
	}
}

func TestRound53TrackResourcesAndCleanupF0(t *testing.T) {
	var mu sync.Mutex
	seenReqs := make(map[string]bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenReqs[r.Method+" "+r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer ts.Close()

	ctx := newRunnerContext(ts.Client(), ts.URL)

	ctx.trackCreatedResources("synonyms.put_synonym", map[string]any{"id": "syn-set-1"}, nil)
	ctx.trackCreatedResources("synonyms.put_synonym_rule", map[string]any{"set_id": "syn-set-2", "rule_id": "r1"}, nil)
	ctx.trackCreatedResources("query_rules.put_ruleset", map[string]any{"ruleset_id": "qr-1"}, nil)
	ctx.trackCreatedResources("query_rules.put_rule", map[string]any{"ruleset_id": "qr-2", "rule_id": "r1"}, nil)
	ctx.trackCreatedResources("rollup.put_job", map[string]any{
		"id":   "rollup-job-1",
		"body": map[string]any{"rollup_index": "rollup-target-idx"},
	}, nil)
	ctx.trackCreatedResources("ccr.put_auto_follow_pattern", map[string]any{"name": "af-pat-1"}, nil)
	ctx.trackCreatedResources("ccr.follow", map[string]any{"index": "ccr-follower-idx"}, nil)
	ctx.trackCreatedResources("searchable_snapshots.mount", map[string]any{
		"repository": "repo1",
		"snapshot":   "snap1",
		"body":       map[string]any{"renamed_index": "mounted-snap-idx"},
	}, nil)
	ctx.trackCreatedResources("logstash.put_pipeline", map[string]any{"id": "ls-pipe-1"}, nil)
	ctx.trackCreatedResources("security.put_user", map[string]any{"username": "sec_user_1"}, nil)
	ctx.trackCreatedResources("security.put_role", map[string]any{"name": "sec_role_1"}, nil)
	ctx.trackCreatedResources("security.put_privileges", map[string]any{
		"body": map[string]any{
			"app_one": map[string]any{
				"priv_read": map[string]any{"actions": []any{"data:read/*"}},
			},
		},
	}, nil)
	ctx.trackCreatedResources("security.create_service_token", map[string]any{
		"namespace":  "elastic",
		"service":    "fleet-server",
		"token_name": "tok_explicit",
	}, nil)
	ctx.trackCreatedResources("security.create_service_token", map[string]any{
		"namespace": "elastic",
		"service":   "kibana",
	}, map[string]any{
		"token": map[string]any{"name": "tok_from_resp"},
	})
	ctx.trackCreatedResources("shutdown.put_node", map[string]any{"node_id": "shut-node-1"}, nil)
	ctx.trackCreatedResources("cluster.post_voting_config_exclusions", map[string]any{"node_names": "shut-node-1"}, nil)

	ctx.cleanupAll()

	mu.Lock()
	defer mu.Unlock()

	expectedReqs := []string{
		"DELETE /_synonyms/syn-set-1",
		"DELETE /_synonyms/syn-set-2",
		"DELETE /_query_rules/qr-1",
		"DELETE /_query_rules/qr-2",
		"POST /_rollup/job/rollup-job-1/_stop",
		"DELETE /_rollup/job/rollup-job-1",
		"DELETE /rollup-target-idx",
		"DELETE /_ccr/auto_follow/af-pat-1",
		"DELETE /ccr-follower-idx",
		"DELETE /mounted-snap-idx",
		"DELETE /_logstash/pipeline/ls-pipe-1",
		"DELETE /_security/user/sec_user_1",
		"DELETE /_security/role/sec_role_1",
		"DELETE /_security/privilege/app_one/priv_read",
		"DELETE /_security/service/elastic/fleet-server/credential/token/tok_explicit",
		"DELETE /_security/service/elastic/kibana/credential/token/tok_from_resp",
		"DELETE /_nodes/shut-node-1/shutdown",
		"DELETE /_cluster/voting_config_exclusions",
	}
	for _, exp := range expectedReqs {
		if !seenReqs[exp] {
			t.Errorf("expected cleanupAll to send %q, got seenReqs=%v", exp, seenReqs)
		}
	}
}

func TestRound53StashInPathAndExecLengthF1(t *testing.T) {
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	ctx.lastMethod = http.MethodGet
	ctx.lastStatus = http.StatusOK
	ctx.lastResponse = map[string]any{
		"indices": map[string]any{
			".ds-logs-2026.01.01-000001": map[string]any{
				"state":     "open",
				"active":    true,
				"corrupted": false,
				"doc_count": int64(42),
				"tags":      []any{"hot", "logs"},
				"settings": map[string]any{
					"index.number_of_shards": "1",
				},
			},
		},
		".ds-logs-2026.01.01-000001": map[string]any{
			"top_level": "found_literal",
		},
		"nested": map[string]any{
			"arr": []any{
				map[string]any{"val": "found_subpath"},
			},
		},
		"unicode_jp":    "日本語テスト",
		"unicode_emoji": "🚀🔥✨",
	}
	ctx.stash["idx"] = ".ds-logs-2026.01.01-000001"
	ctx.stash["setting_key"] = "index.number_of_shards"
	ctx.stash["subpath"] = "nested.arr.0.val"
	ctx.stash["expected_tag_len"] = int64(2)
	ctx.stash["expected_jp_len"] = "6"
	ctx.stash["expected_emoji_len"] = 3

	// 1. execSet with dotted stashed variables in path
	if err := ctx.execSet(map[string]any{
		"indices.$idx.state":                 "stashed_state",
		"indices.$idx.settings.$setting_key": "stashed_shards",
	}); err != nil {
		t.Fatalf("execSet with dotted stash in path failed: %v", err)
	}
	if ctx.stash["stashed_state"] != "open" || ctx.stash["stashed_shards"] != "1" {
		t.Fatalf("unexpected stash after execSet: %#v", ctx.stash)
	}

	// 2. execTransformAndSet with dotted stashed variable in source path
	if err := ctx.execTransformAndSet(map[string]any{
		"upper_state": "upper(indices.$idx.state)",
	}); err != nil {
		t.Fatalf("execTransformAndSet with dotted stash in path failed: %v", err)
	}
	if ctx.stash["upper_state"] != "OPEN" {
		t.Fatalf("expected upper_state=OPEN, got %v", ctx.stash["upper_state"])
	}

	// 3. execMatch with multi-segment dotted stash, top-level literal dotted key, and top-level dotted subpath fallback
	if err := ctx.execMatch(map[string]any{
		"indices.$idx.state":                 "open",
		"indices.$idx.settings.$setting_key": "1",
		"$idx.top_level":                     "found_literal",
		"$subpath":                           "found_subpath",
	}); err != nil {
		t.Fatalf("execMatch with dotted stash in path failed: %v", err)
	}

	// 4. execContains, execIsTrue, execIsFalse, execCompare with dotted stash in path
	if err := ctx.execContains(map[string]any{
		"indices.$idx.tags": "logs",
	}); err != nil {
		t.Fatalf("execContains with dotted stash in path failed: %v", err)
	}
	if err := ctx.execIsTrue("indices.$idx.active"); err != nil {
		t.Fatalf("execIsTrue with dotted stash in path failed: %v", err)
	}
	if err := ctx.execIsFalse("indices.$idx.corrupted"); err != nil {
		t.Fatalf("execIsFalse with dotted stash in path failed: %v", err)
	}
	if err := ctx.execCompare("gt", map[string]any{"indices.$idx.doc_count": 40}); err != nil {
		t.Fatalf("execCompare with dotted stash in path failed: %v", err)
	}

	// 5. execLength with dotted stash in path, stashed expected length, and Unicode rune counting
	if err := ctx.execLength(map[string]any{
		"indices.$idx.tags": "$expected_tag_len",
		"unicode_jp":        "$expected_jp_len",
		"unicode_emoji":     "$expected_emoji_len",
	}); err != nil {
		t.Fatalf("execLength with stashed length and Unicode strings failed: %v", err)
	}
}
