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
