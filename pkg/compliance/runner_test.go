package compliance

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRound54ActionBuildersAndRunnerFeatures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		action     string
		params     map[string]any
		wantMethod string
		wantPath   string
	}{
		{"inference.put with task_type", "inference.put", map[string]any{"task_type": "text_embedding", "inference_id": "m1"}, http.MethodPut, "/_inference/text_embedding/m1"},
		{"inference.put_model without task_type", "inference.put_model", map[string]any{"inference_id": "m1"}, http.MethodPut, "/_inference/m1"},
		{"inference.get with task_type and id", "inference.get", map[string]any{"task_type": "rerank", "inference_id": "m2"}, http.MethodGet, "/_inference/rerank/m2"},
		{"inference.get_model with id only", "inference.get_model", map[string]any{"inference_id": "m2"}, http.MethodGet, "/_inference/m2"},
		{"inference.get with task_type only", "inference.get", map[string]any{"task_type": "rerank"}, http.MethodGet, "/_inference/rerank"},
		{"inference.get all", "inference.get", map[string]any{}, http.MethodGet, "/_inference"},
		{"inference.delete with task_type", "inference.delete", map[string]any{"task_type": "rerank", "inference_id": "m2"}, http.MethodDelete, "/_inference/rerank/m2"},
		{"inference.delete_model id only", "inference.delete_model", map[string]any{"inference_id": "m2"}, http.MethodDelete, "/_inference/m2"},
		{"inference.inference with task_type", "inference.inference", map[string]any{"task_type": "text_embedding", "inference_id": "m1"}, http.MethodPost, "/_inference/text_embedding/m1"},
		{"inference.post without task_type", "inference.post", map[string]any{"inference_id": "m1"}, http.MethodPost, "/_inference/m1"},
		{"connector.put", "connector.put", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1"},
		{"connector.post", "connector.post", map[string]any{}, http.MethodPost, "/_connector"},
		{"connector.get", "connector.get", map[string]any{"connector_id": "c1"}, http.MethodGet, "/_connector/c1"},
		{"connector.list", "connector.list", map[string]any{}, http.MethodGet, "/_connector"},
		{"connector.delete", "connector.delete", map[string]any{"connector_id": "c1"}, http.MethodDelete, "/_connector/c1"},
		{"connector.update_name", "connector.update_name", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_name"},
		{"connector.update_native", "connector.update_native", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_native"},
		{"connector.update_service_type", "connector.update_service_type", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_service_type"},
		{"connector.update_status", "connector.update_status", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_status"},
		{"connector.update_error", "connector.update_error", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_error"},
		{"connector.update_filtering", "connector.update_filtering", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_filtering"},
		{"connector.update_configuration", "connector.update_configuration", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_configuration"},
		{"connector.update_pipeline", "connector.update_pipeline", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_pipeline"},
		{"connector.last_sync", "connector.last_sync", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_last_sync"},
		{"connector.sync_job_post", "connector.sync_job_post", map[string]any{}, http.MethodPost, "/_connector/_sync_job"},
		{"connector.sync_job_get", "connector.sync_job_get", map[string]any{"connector_sync_job_id": "j1"}, http.MethodGet, "/_connector/_sync_job/j1"},
		{"connector.sync_job_list", "connector.sync_job_list", map[string]any{}, http.MethodGet, "/_connector/_sync_job"},
		{"connector.sync_job_delete", "connector.sync_job_delete", map[string]any{"connector_sync_job_id": "j1"}, http.MethodDelete, "/_connector/_sync_job/j1"},
		{"connector.sync_job_cancel", "connector.sync_job_cancel", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPost, "/_connector/_sync_job/j1/_cancel"},
		{"connector.sync_job_check_in", "connector.sync_job_check_in", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPost, "/_connector/_sync_job/j1/_check_in"},
		{"connector.sync_job_error", "connector.sync_job_error", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPut, "/_connector/_sync_job/j1/_error"},
		{"connector.sync_job_update_stats", "connector.sync_job_update_stats", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPut, "/_connector/_sync_job/j1/_stats"},
		{"search_application.put", "search_application.put", map[string]any{"name": "app1"}, http.MethodPut, "/_application/search_application/app1"},
		{"search_application.get", "search_application.get", map[string]any{"name": "app1"}, http.MethodGet, "/_application/search_application/app1"},
		{"search_application.delete", "search_application.delete", map[string]any{"name": "app1"}, http.MethodDelete, "/_application/search_application/app1"},
		{"search_application.list", "search_application.list", map[string]any{}, http.MethodGet, "/_application/search_application"},
		{"search_application.search", "search_application.search", map[string]any{"name": "app1"}, http.MethodPost, "/_application/search_application/app1/_search"},
		{"search_application.render_query", "search_application.render_query", map[string]any{"name": "app1"}, http.MethodPost, "/_application/search_application/app1/_render_query"},
		{"behavioral_analytics.put_collection", "behavioral_analytics.put_collection", map[string]any{"collection_name": "col1"}, http.MethodPut, "/_application/analytics/col1"},
		{"behavioral_analytics.get_collections specific", "behavioral_analytics.get_collections", map[string]any{"collection_name": "col1"}, http.MethodGet, "/_application/analytics/col1"},
		{"behavioral_analytics.get_collections all", "behavioral_analytics.get_collections", map[string]any{}, http.MethodGet, "/_application/analytics"},
		{"behavioral_analytics.delete_collection", "behavioral_analytics.delete_collection", map[string]any{"collection_name": "col1"}, http.MethodDelete, "/_application/analytics/col1"},
		{"behavioral_analytics.post_event", "behavioral_analytics.post_event", map[string]any{"collection_name": "col1", "event_type": "click"}, http.MethodPost, "/_application/analytics/col1/event/click"},
		{"text_structure.find_structure", "text_structure.find_structure", map[string]any{}, http.MethodPost, "/_text_structure/find_structure"},
		{"text_structure.find_field_structure", "text_structure.find_field_structure", map[string]any{}, http.MethodPost, "/_text_structure/find_field_structure"},
		{"text_structure.find_message_structure", "text_structure.find_message_structure", map[string]any{}, http.MethodPost, "/_text_structure/find_message_structure"},
		{"text_structure.test_grok_pattern", "text_structure.test_grok_pattern", map[string]any{}, http.MethodPost, "/_text_structure/test_grok_pattern"},
		{"profiling.status", "profiling.status", map[string]any{}, http.MethodGet, "/_profiling/status"},
		{"profiling.flamegraph", "profiling.flamegraph", map[string]any{}, http.MethodPost, "/_profiling/flamegraph"},
		{"profiling.stacktraces", "profiling.stacktraces", map[string]any{}, http.MethodPost, "/_profiling/stacktraces"},
		{"profiling.topn_functions", "profiling.topn_functions", map[string]any{}, http.MethodPost, "/_profiling/topn_functions"},
		{"async_search.submit index", "async_search.submit", map[string]any{"index": "idx1"}, http.MethodPost, "/idx1/_async_search"},
		{"async_search.submit cluster", "async_search.submit", map[string]any{}, http.MethodPost, "/_async_search"},
		{"async_search.get", "async_search.get", map[string]any{"id": "as1"}, http.MethodGet, "/_async_search/as1"},
		{"async_search.status", "async_search.status", map[string]any{"id": "as1"}, http.MethodGet, "/_async_search/status/as1"},
		{"async_search.delete", "async_search.delete", map[string]any{"id": "as1"}, http.MethodDelete, "/_async_search/as1"},
		{"esql.query", "esql.query", map[string]any{}, http.MethodPost, "/_query"},
		{"esql.async_query", "esql.async_query", map[string]any{}, http.MethodPost, "/_query/async"},
		{"esql.async_query_get", "esql.async_query_get", map[string]any{"id": "q1"}, http.MethodGet, "/_query/async/q1"},
		{"esql.async_query_stop", "esql.async_query_stop", map[string]any{"id": "q1"}, http.MethodPost, "/_query/async/q1/_stop"},
		{"esql.async_query_delete", "esql.async_query_delete", map[string]any{"id": "q1"}, http.MethodDelete, "/_query/async/q1"},
		{"watcher.query_watches", "watcher.query_watches", map[string]any{}, http.MethodPost, "/_watcher/_query/watches"},
		{"watcher.get_settings", "watcher.get_settings", map[string]any{}, http.MethodGet, "/_watcher/settings"},
		{"watcher.update_settings", "watcher.update_settings", map[string]any{}, http.MethodPut, "/_watcher/settings"},
		{"cat.transforms specific", "cat.transforms", map[string]any{"transform_id": "tr1"}, http.MethodGet, "/_cat/transforms/tr1"},
		{"cat.transforms all", "cat.transforms", map[string]any{}, http.MethodGet, "/_cat/transforms"},
		{"license.get", "license.get", map[string]any{}, http.MethodGet, "/_license"},
		{"license.delete", "license.delete", map[string]any{}, http.MethodDelete, "/_license"},
		{"license.post_start_basic", "license.post_start_basic", map[string]any{}, http.MethodPost, "/_license/start_basic"},
		{"license.get_basic_status", "license.get_basic_status", map[string]any{}, http.MethodGet, "/_license/basic_status"},
		{"license.post_start_trial", "license.post_start_trial", map[string]any{}, http.MethodPost, "/_license/start_trial"},
		{"license.get_trial_status", "license.get_trial_status", map[string]any{}, http.MethodGet, "/_license/trial_status"},
		{"xpack.info", "xpack.info", map[string]any{}, http.MethodGet, "/_xpack"},
		{"xpack.usage", "xpack.usage", map[string]any{}, http.MethodGet, "/_xpack/usage"},
		{"ssl.certificates", "ssl.certificates", map[string]any{}, http.MethodGet, "/_ssl/certificates"},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"created-id","acknowledged":true,"items":["first","second","last"],"raw_text":"hello+world/test"}`))
	}))
	defer ts.Close()
	ctx := newRunnerContext(ts.Client(), ts.URL)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ctx.buildActionRequest(tc.action, tc.params)
			if err != nil {
				t.Fatalf("buildActionRequest(%q) failed: %v", tc.action, err)
			}
			if spec.method != tc.wantMethod || spec.path != tc.wantPath {
				t.Fatalf("buildActionRequest(%q) = (%s, %s), want (%s, %s)", tc.action, spec.method, spec.path, tc.wantMethod, tc.wantPath)
			}
		})
	}

	// Test node_selector in execDo and resource tracking + cleanupAll
	for _, action := range []string{
		"inference.put",
		"connector.put",
		"connector.post",
		"connector.sync_job_post",
		"search_application.put",
		"behavioral_analytics.put_collection",
		"async_search.submit",
	} {
		step := &OrderedMap{
			Fields: []YAMLField{
				{Key: "node_selector", Value: map[string]any{"version": "8.0.0"}},
				{Key: action, Value: map[string]any{
					"inference_id":    "inf1",
					"connector_id":    "conn1",
					"name":            "app1",
					"collection_name": "coll1",
				}},
			},
		}
		if err := ctx.execDo(step, false); err != nil {
			t.Fatalf("execDo(%s) failed: %v", action, err)
		}
	}

	// Test lookupResponsePath with $body. prefix and negative array index
	if val, ok := ctx.lookupResponsePath("$body.items.-1"); !ok || val != "last" {
		t.Fatalf("expected $body.items.-1 = 'last', got (%v, %v)", val, ok)
	}
	if val, ok := ctx.lookupResponsePath("$body.items.-2"); !ok || val != "second" {
		t.Fatalf("expected $body.items.-2 = 'second', got (%v, %v)", val, ok)
	}
	if _, ok := ctx.lookupResponsePath("$body.items.-99"); ok {
		t.Fatalf("expected out-of-bounds negative index to return false")
	}

	// Test execTransformAndSet with base64UrlEncode, base64UrlDecode, and length/size
	if err := ctx.execTransformAndSet(map[string]any{
		"b64u":     "base64UrlEncode(raw_text)",
		"arr_len":  "length(items)",
		"str_size": "size(raw_text)",
	}); err != nil {
		t.Fatalf("execTransformAndSet failed: %v", err)
	}
	if err := ctx.execTransformAndSet(map[string]any{
		"decoded": "base64UrlDecode($b64u)",
	}); err != nil {
		t.Fatalf("execTransformAndSet base64UrlDecode failed: %v", err)
	}
	if ctx.stash["decoded"] != "hello+world/test" {
		t.Fatalf("expected decoded='hello+world/test', got %v", ctx.stash["decoded"])
	}
	if ctx.stash["arr_len"] != 3 || ctx.stash["str_size"] != 16 {
		t.Fatalf("unexpected lengths: arr_len=%v str_size=%v", ctx.stash["arr_len"], ctx.stash["str_size"])
	}

	ctx.cleanupAll()
}

func TestRound55BuildActionRequestAndOperatorsF0F1(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		params     map[string]any
		wantMethod string
		wantPath   string
		wantQuery  string
	}{
		{"health_report all", "health_report", map[string]any{}, http.MethodGet, "/_health_report", ""},
		{"health_report indicator", "health_report", map[string]any{"indicator": "shards_availability"}, http.MethodGet, "/_health_report/shards_availability", ""},
		{"sql.query", "sql.query", map[string]any{"format": "txt"}, http.MethodPost, "/_sql", "format=txt"},
		{"sql.translate", "sql.translate", map[string]any{}, http.MethodPost, "/_sql/translate", ""},
		{"sql.clear_cursor", "sql.clear_cursor", map[string]any{}, http.MethodPost, "/_sql/close", ""},
		{"sql.close", "sql.close", map[string]any{}, http.MethodPost, "/_sql/close", ""},
		{"sql.get_async", "sql.get_async", map[string]any{"id": "sq1"}, http.MethodGet, "/_sql/async/sq1", ""},
		{"sql.get_async_status", "sql.get_async_status", map[string]any{"id": "sq1"}, http.MethodGet, "/_sql/async/status/sq1", ""},
		{"sql.delete_async", "sql.delete_async", map[string]any{"id": "sq1"}, http.MethodDelete, "/_sql/async/sq1", ""},
		{"eql.search with index", "eql.search", map[string]any{"index": "logs-1"}, http.MethodPost, "/logs-1/_eql/search", ""},
		{"eql.search without index", "eql.search", map[string]any{}, http.MethodPost, "/_eql/search", ""},
		{"eql.get", "eql.get", map[string]any{"id": "eq1"}, http.MethodGet, "/_eql/search/eq1", ""},
		{"eql.get_status", "eql.get_status", map[string]any{"id": "eq1"}, http.MethodGet, "/_eql/search/status/eq1", ""},
		{"eql.delete", "eql.delete", map[string]any{"id": "eq1"}, http.MethodDelete, "/_eql/search/eq1", ""},
		{"fleet.msearch with index", "fleet.msearch", map[string]any{"index": "fl-idx"}, http.MethodPost, "/fl-idx/_fleet/msearch", ""},
		{"fleet.msearch without index", "fleet.msearch", map[string]any{}, http.MethodPost, "/_fleet/msearch", ""},
		{"fleet.search with index", "fleet.search", map[string]any{"index": "fl-idx"}, http.MethodPost, "/fl-idx/_fleet/search", ""},
		{"fleet.search without index", "fleet.search", map[string]any{}, http.MethodPost, "/_fleet/search", ""},
		{"fleet.global_checkpoints", "fleet.global_checkpoints", map[string]any{"index": "fl-idx"}, http.MethodGet, "/fl-idx/_fleet/global_checkpoints", ""},
		{"graph.explore with index", "graph.explore", map[string]any{"index": "gr-idx"}, http.MethodPost, "/gr-idx/_graph/explore", ""},
		{"graph.explore without index", "graph.explore", map[string]any{}, http.MethodPost, "/_graph/explore", ""},
		{"ml.info", "ml.info", map[string]any{}, http.MethodGet, "/_ml/info", ""},
		{"ml.get_memory_stats", "ml.get_memory_stats", map[string]any{}, http.MethodGet, "/_ml/memory_stats", ""},
		{"ml.set_upgrade_mode", "ml.set_upgrade_mode", map[string]any{"enabled": true}, http.MethodPost, "/_ml/set_upgrade_mode", "enabled=true"},
		{"ml.put_job", "ml.put_job", map[string]any{"job_id": "j1"}, http.MethodPut, "/_ml/anomaly_detectors/j1", ""},
		{"ml.get_jobs specific", "ml.get_jobs", map[string]any{"job_id": "j1"}, http.MethodGet, "/_ml/anomaly_detectors/j1", ""},
		{"ml.get_jobs all", "ml.get_jobs", map[string]any{}, http.MethodGet, "/_ml/anomaly_detectors", ""},
		{"ml.get_job_stats specific", "ml.get_job_stats", map[string]any{"job_id": "j1"}, http.MethodGet, "/_ml/anomaly_detectors/j1/_stats", ""},
		{"ml.get_job_stats all", "ml.get_job_stats", map[string]any{}, http.MethodGet, "/_ml/anomaly_detectors/_stats", ""},
		{"ml.update_job", "ml.update_job", map[string]any{"job_id": "j1"}, http.MethodPost, "/_ml/anomaly_detectors/j1/_update", ""},
		{"ml.delete_job", "ml.delete_job", map[string]any{"job_id": "j1"}, http.MethodDelete, "/_ml/anomaly_detectors/j1", ""},
		{"ml.open_job", "ml.open_job", map[string]any{"job_id": "j1"}, http.MethodPost, "/_ml/anomaly_detectors/j1/_open", ""},
		{"ml.close_job", "ml.close_job", map[string]any{"job_id": "j1"}, http.MethodPost, "/_ml/anomaly_detectors/j1/_close", ""},
		{"ml.put_datafeed", "ml.put_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodPut, "/_ml/datafeeds/df1", ""},
		{"ml.get_datafeeds specific", "ml.get_datafeeds", map[string]any{"datafeed_id": "df1"}, http.MethodGet, "/_ml/datafeeds/df1", ""},
		{"ml.get_datafeeds all", "ml.get_datafeeds", map[string]any{}, http.MethodGet, "/_ml/datafeeds", ""},
		{"ml.get_datafeed_stats specific", "ml.get_datafeed_stats", map[string]any{"datafeed_id": "df1"}, http.MethodGet, "/_ml/datafeeds/df1/_stats", ""},
		{"ml.get_datafeed_stats all", "ml.get_datafeed_stats", map[string]any{}, http.MethodGet, "/_ml/datafeeds/_stats", ""},
		{"ml.update_datafeed", "ml.update_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodPost, "/_ml/datafeeds/df1/_update", ""},
		{"ml.delete_datafeed", "ml.delete_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodDelete, "/_ml/datafeeds/df1", ""},
		{"ml.start_datafeed", "ml.start_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodPost, "/_ml/datafeeds/df1/_start", ""},
		{"ml.stop_datafeed", "ml.stop_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodPost, "/_ml/datafeeds/df1/_stop", ""},
		{"ml.preview_datafeed", "ml.preview_datafeed", map[string]any{"datafeed_id": "df1"}, http.MethodGet, "/_ml/datafeeds/df1/_preview", ""},
		{"ml.put_trained_model", "ml.put_trained_model", map[string]any{"model_id": "tm1"}, http.MethodPut, "/_ml/trained_models/tm1", ""},
		{"ml.get_trained_models specific", "ml.get_trained_models", map[string]any{"model_id": "tm1"}, http.MethodGet, "/_ml/trained_models/tm1", ""},
		{"ml.get_trained_models all", "ml.get_trained_models", map[string]any{}, http.MethodGet, "/_ml/trained_models", ""},
		{"ml.get_trained_models_stats specific", "ml.get_trained_models_stats", map[string]any{"model_id": "tm1"}, http.MethodGet, "/_ml/trained_models/tm1/_stats", ""},
		{"ml.get_trained_models_stats all", "ml.get_trained_models_stats", map[string]any{}, http.MethodGet, "/_ml/trained_models/_stats", ""},
		{"ml.delete_trained_model", "ml.delete_trained_model", map[string]any{"model_id": "tm1"}, http.MethodDelete, "/_ml/trained_models/tm1", ""},
		{"ml.put_calendar", "ml.put_calendar", map[string]any{"calendar_id": "cal1"}, http.MethodPut, "/_ml/calendars/cal1", ""},
		{"ml.get_calendars specific", "ml.get_calendars", map[string]any{"calendar_id": "cal1"}, http.MethodGet, "/_ml/calendars/cal1", ""},
		{"ml.get_calendars all", "ml.get_calendars", map[string]any{}, http.MethodGet, "/_ml/calendars", ""},
		{"ml.delete_calendar", "ml.delete_calendar", map[string]any{"calendar_id": "cal1"}, http.MethodDelete, "/_ml/calendars/cal1", ""},
		{"ml.put_calendar_job", "ml.put_calendar_job", map[string]any{"calendar_id": "cal1", "job_id": "j1"}, http.MethodPut, "/_ml/calendars/cal1/jobs/j1", ""},
		{"ml.delete_calendar_job", "ml.delete_calendar_job", map[string]any{"calendar_id": "cal1", "job_id": "j1"}, http.MethodDelete, "/_ml/calendars/cal1/jobs/j1", ""},
		{"ml.put_calendar_event", "ml.put_calendar_event", map[string]any{"calendar_id": "cal1"}, http.MethodPost, "/_ml/calendars/cal1/events", ""},
		{"ml.post_calendar_events", "ml.post_calendar_events", map[string]any{"calendar_id": "cal1"}, http.MethodPost, "/_ml/calendars/cal1/events", ""},
		{"ml.get_calendar_events", "ml.get_calendar_events", map[string]any{"calendar_id": "cal1"}, http.MethodGet, "/_ml/calendars/cal1/events", ""},
		{"ml.delete_calendar_event", "ml.delete_calendar_event", map[string]any{"calendar_id": "cal1", "event_id": "ev1"}, http.MethodDelete, "/_ml/calendars/cal1/events/ev1", ""},
		{"ml.put_filter", "ml.put_filter", map[string]any{"filter_id": "f1"}, http.MethodPut, "/_ml/filters/f1", ""},
		{"ml.get_filters specific", "ml.get_filters", map[string]any{"filter_id": "f1"}, http.MethodGet, "/_ml/filters/f1", ""},
		{"ml.get_filters all", "ml.get_filters", map[string]any{}, http.MethodGet, "/_ml/filters", ""},
		{"ml.update_filter", "ml.update_filter", map[string]any{"filter_id": "f1"}, http.MethodPost, "/_ml/filters/f1/_update", ""},
		{"ml.delete_filter", "ml.delete_filter", map[string]any{"filter_id": "f1"}, http.MethodDelete, "/_ml/filters/f1", ""},
		{"security.put_role_mapping", "security.put_role_mapping", map[string]any{"name": "rm1"}, http.MethodPut, "/_security/role_mapping/rm1", ""},
		{"security.get_role_mapping specific", "security.get_role_mapping", map[string]any{"name": "rm1"}, http.MethodGet, "/_security/role_mapping/rm1", ""},
		{"security.get_role_mapping all", "security.get_role_mapping", map[string]any{}, http.MethodGet, "/_security/role_mapping", ""},
		{"security.delete_role_mapping", "security.delete_role_mapping", map[string]any{"name": "rm1"}, http.MethodDelete, "/_security/role_mapping/rm1", ""},
		{"security.get_builtin_privileges", "security.get_builtin_privileges", map[string]any{}, http.MethodGet, "/_security/privilege/_builtin", ""},
		{"security.enroll_kibana", "security.enroll_kibana", map[string]any{}, http.MethodPost, "/_security/enroll/kibana", ""},
		{"security.enroll_node", "security.enroll_node", map[string]any{}, http.MethodPost, "/_security/enroll/node", ""},
		{"security.clear_cached_roles", "security.clear_cached_roles", map[string]any{"name": "admin"}, http.MethodPost, "/_security/role/admin/_clear_cache", ""},
		{"security.clear_cached_realms with username", "security.clear_cached_realms", map[string]any{"username": "u1"}, http.MethodPost, "/_security/user/u1/_clear_cache", ""},
		{"security.clear_cached_realms with realms", "security.clear_cached_realms", map[string]any{"realms": "native1"}, http.MethodPost, "/_security/realm/native1/_clear_cache", ""},
		{"security.clear_cached_realms empty", "security.clear_cached_realms", map[string]any{}, http.MethodPost, "/_security/user/_clear_cache", ""},
		{"indices.reload_search_analyzers with index", "indices.reload_search_analyzers", map[string]any{"index": "idx1"}, http.MethodPost, "/idx1/_reload_search_analyzers", ""},
		{"indices.reload_search_analyzers all", "indices.reload_search_analyzers", map[string]any{}, http.MethodPost, "/_reload_search_analyzers", ""},
		{"indices.disk_usage with index", "indices.disk_usage", map[string]any{"index": "idx1"}, http.MethodPost, "/idx1/_disk_usage", ""},
		{"indices.disk_usage all", "indices.disk_usage", map[string]any{}, http.MethodPost, "/_disk_usage", ""},
		{"indices.field_usage_stats with index", "indices.field_usage_stats", map[string]any{"index": "idx1"}, http.MethodGet, "/idx1/_field_usage_stats", ""},
		{"indices.field_usage_stats all", "indices.field_usage_stats", map[string]any{}, http.MethodGet, "/_field_usage_stats", ""},
		{"snapshot.clone", "snapshot.clone", map[string]any{"repository": "repo1", "snapshot": "snap1", "target_snapshot": "snap2"}, http.MethodPut, "/_snapshot/repo1/snap1/_clone/snap2", ""},
		{"snapshot.cleanup_repository", "snapshot.cleanup_repository", map[string]any{"repository": "repo1"}, http.MethodPost, "/_snapshot/repo1/_cleanup", ""},
		{"cat.component_templates specific", "cat.component_templates", map[string]any{"name": "ct1"}, http.MethodGet, "/_cat/component_templates/ct1", ""},
		{"cat.component_templates all", "cat.component_templates", map[string]any{}, http.MethodGet, "/_cat/component_templates", ""},
		{"cat.ml_anomaly_detectors specific", "cat.ml_anomaly_detectors", map[string]any{"job_id": "j1"}, http.MethodGet, "/_cat/ml_anomaly_detectors/j1", ""},
		{"cat.ml_jobs all", "cat.ml_jobs", map[string]any{}, http.MethodGet, "/_cat/ml_anomaly_detectors", ""},
		{"cat.ml_datafeeds specific", "cat.ml_datafeeds", map[string]any{"datafeed_id": "df1"}, http.MethodGet, "/_cat/ml_datafeeds/df1", ""},
		{"cat.ml_datafeeds all", "cat.ml_datafeeds", map[string]any{}, http.MethodGet, "/_cat/ml_datafeeds", ""},
		{"cat.ml_trained_models specific", "cat.ml_trained_models", map[string]any{"model_id": "tm1"}, http.MethodGet, "/_cat/ml_trained_models/tm1", ""},
		{"cat.ml_trained_models all", "cat.ml_trained_models", map[string]any{}, http.MethodGet, "/_cat/ml_trained_models", ""},
		{"cat.ml_data_frame_analytics specific", "cat.ml_data_frame_analytics", map[string]any{"id": "dfa1"}, http.MethodGet, "/_cat/ml_data_frame_analytics/dfa1", ""},
		{"cat.ml_data_frame_analytics all", "cat.ml_data_frame_analytics", map[string]any{}, http.MethodGet, "/_cat/ml_data_frame_analytics", ""},
		{"cluster.info specific", "cluster.info", map[string]any{"target": "settings,http"}, http.MethodGet, "/_cluster/info/settings,http", ""},
		{"cluster.info all", "cluster.info", map[string]any{}, http.MethodGet, "/_cluster/info", ""},
		{"cluster.exists_component_template", "cluster.exists_component_template", map[string]any{"name": "ct1"}, http.MethodHead, "/_component_template/ct1", ""},
		{"nodes.reload_secure_settings specific", "nodes.reload_secure_settings", map[string]any{"node_id": "n1"}, http.MethodPost, "/_nodes/n1/reload_secure_settings", ""},
		{"nodes.reload_secure_settings all", "nodes.reload_secure_settings", map[string]any{}, http.MethodPost, "/_nodes/reload_secure_settings", ""},
		{"nodes.get_repositories_metering_info specific", "nodes.get_repositories_metering_info", map[string]any{"node_id": "n1"}, http.MethodGet, "/_nodes/n1/repositories_metering", ""},
		{"nodes.get_repositories_metering_info all", "nodes.get_repositories_metering_info", map[string]any{}, http.MethodGet, "/_nodes/repositories_metering", ""},
		{"nodes.clear_repositories_metering_archive specific", "nodes.clear_repositories_metering_archive", map[string]any{"node_id": "n1", "max_archive_version": 5}, http.MethodDelete, "/_nodes/n1/clear_repositories_metering_archive/5", ""},
		{"nodes.clear_repositories_metering_archive all", "nodes.clear_repositories_metering_archive", map[string]any{"max_archive_version": 5}, http.MethodDelete, "/_nodes/clear_repositories_metering_archive/5", ""},
	}

	var deletedPaths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedPaths = append(deletedPaths, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"acknowledged": true,
			"ts_early": "2024-01-01T00:00:00Z",
			"ts_late": "2024-06-15T12:30:45.123Z",
			"date_only_early": "2024-01-01",
			"date_only_late": "2024-12-31",
			"ver_old": "8.9.2",
			"ver_new": "8.11.0",
			"str_a": "alpha",
			"str_b": "beta",
			"empty_str": "",
			"empty_arr": [],
			"empty_map": {},
			"null_val": null,
			"non_empty_arr": ["a", "b", "c"],
			"non_empty_str": "hello-world-2026",
			"num_str": "42",
			"num_val": 99
		}`))
	}))
	defer ts.Close()
	ctx := newRunnerContext(ts.Client(), ts.URL)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ctx.buildActionRequest(tc.action, tc.params)
			if err != nil {
				t.Fatalf("buildActionRequest(%q) failed: %v", tc.action, err)
			}
			if spec.method != tc.wantMethod || spec.path != tc.wantPath {
				t.Fatalf("buildActionRequest(%q) = (%s, %s), want (%s, %s)", tc.action, spec.method, spec.path, tc.wantMethod, tc.wantPath)
			}
			if tc.wantQuery != "" && spec.query.Encode() != tc.wantQuery {
				t.Fatalf("buildActionRequest(%q) query = %q, want %q", tc.action, spec.query.Encode(), tc.wantQuery)
			}
		})
	}

	// Test resource tracking and cleanup for Round 55 ML and security actions
	for _, item := range []struct {
		action string
		params map[string]any
	}{
		{"ml.put_job", map[string]any{"job_id": "job-r55"}},
		{"ml.put_datafeed", map[string]any{"datafeed_id": "df-r55"}},
		{"ml.put_trained_model", map[string]any{"model_id": "tm-r55"}},
		{"ml.put_calendar", map[string]any{"calendar_id": "cal-r55"}},
		{"ml.put_filter", map[string]any{"filter_id": "flt-r55"}},
		{"security.put_role_mapping", map[string]any{"name": "rm-r55"}},
	} {
		step := &OrderedMap{
			Fields: []YAMLField{
				{Key: item.action, Value: item.params},
			},
		}
		if err := ctx.execDo(step, false); err != nil {
			t.Fatalf("execDo(%s) failed: %v", item.action, err)
		}
	}

	// F1: Compare timestamps, semvers, and lexicographical strings
	for _, opTest := range []struct {
		op      string
		payload map[string]any
		wantErr bool
	}{
		{"gt", map[string]any{"ts_late": "2024-01-01T00:00:00Z"}, false},
		{"lt", map[string]any{"ts_early": "2024-06-15T12:30:45.123Z"}, false},
		{"gte", map[string]any{"date_only_late": "2024-01-01"}, false},
		{"lte", map[string]any{"date_only_early": "2024-01-01"}, false},
		{"gt", map[string]any{"ver_new": "8.9.2"}, false},
		{"lt", map[string]any{"ver_old": "8.11.0"}, false},
		{"gt", map[string]any{"str_b": "alpha"}, false},
		{"lt", map[string]any{"str_a": "beta"}, false},
		{"gt", map[string]any{"ts_early": "2025-01-01T00:00:00Z"}, true},
	} {
		err := ctx.execCompare(opTest.op, opTest.payload)
		if (err != nil) != opTest.wantErr {
			t.Fatalf("execCompare(%s, %v) err=%v, wantErr=%v", opTest.op, opTest.payload, err, opTest.wantErr)
		}
	}

	// F1: is_empty operator
	for _, emptyField := range []string{"empty_str", "empty_arr", "empty_map", "null_val", "non_existent_path"} {
		if err := ctx.execStep(SpecStep{Op: "is_empty", Value: emptyField}, false); err != nil {
			t.Fatalf("is_empty(%q) failed: %v", emptyField, err)
		}
	}
	if err := ctx.execStep(SpecStep{Op: "is_empty", Value: "non_empty_arr"}, false); err == nil {
		t.Fatalf("expected is_empty(non_empty_arr) to fail")
	}

	// F1: not_contains operator
	if err := ctx.execStep(SpecStep{Op: "not_contains", Value: map[string]any{
		"non_empty_arr": "z",
		"non_empty_str": "missing",
	}}, false); err != nil {
		t.Fatalf("not_contains failed: %v", err)
	}
	if err := ctx.execStep(SpecStep{Op: "not_contains", Value: map[string]any{
		"non_empty_arr": "b",
	}}, false); err == nil {
		t.Fatalf("expected not_contains to fail when element is present")
	}

	// F1: transform_and_set with concat, split, replace, toString, toInt + negative slice indices
	if err := ctx.execTransformAndSet(map[string]any{
		"joined":   `concat(str_a, "-", str_b)`,
		"parts":    `split(non_empty_str, "-")`,
		"replaced": `replace(non_empty_str, "-", "_")`,
		"str_num":  `toString(num_val)`,
		"int_num":  `toInt(num_str)`,
	}); err != nil {
		t.Fatalf("execTransformAndSet F1 failed: %v", err)
	}
	if ctx.stash["joined"] != "alpha-beta" {
		t.Fatalf("expected joined='alpha-beta', got %v", ctx.stash["joined"])
	}
	if ctx.stash["replaced"] != "hello_world_2026" {
		t.Fatalf("expected replaced='hello_world_2026', got %v", ctx.stash["replaced"])
	}
	if ctx.stash["str_num"] != "99" {
		t.Fatalf("expected str_num='99', got %v (%T)", ctx.stash["str_num"], ctx.stash["str_num"])
	}
	if ctx.stash["int_num"] != 42 {
		t.Fatalf("expected int_num=42, got %v (%T)", ctx.stash["int_num"], ctx.stash["int_num"])
	}
	if val, ok := ctx.lookupResponsePath("$parts.-1"); !ok || val != "2026" {
		t.Fatalf("expected $parts.-1='2026', got (%v, %v)", val, ok)
	}
	if val, ok := ctx.lookupResponsePath("non_empty_arr.-1"); !ok || val != "c" {
		t.Fatalf("expected non_empty_arr.-1='c', got (%v, %v)", val, ok)
	}

	ctx.cleanupAll()
	wantDeletes := []string{
		"/_ml/datafeeds/df-r55",
		"/_ml/anomaly_detectors/job-r55",
		"/_ml/trained_models/tm-r55",
		"/_ml/calendars/cal-r55",
		"/_ml/filters/flt-r55",
		"/_security/role_mapping/rm-r55",
	}
	for _, wd := range wantDeletes {
		found := false
		for _, dp := range deletedPaths {
			if dp == wd {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected cleanupAll to DELETE %s, got %v", wd, deletedPaths)
		}
	}
}

func TestRound56_ActionBuildersAndCleanup(t *testing.T) {
	t.Parallel()

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
		// Data Stream Lifecycle & Downsampling
		{"indices.put_data_lifecycle", "indices.put_data_lifecycle", map[string]any{"name": "ds-1"}, http.MethodPut, "/_data_stream/ds-1/_lifecycle", []string{"name"}, nil},
		{"indices.get_data_lifecycle", "indices.get_data_lifecycle", map[string]any{"name": "ds-1", "include_defaults": true}, http.MethodGet, "/_data_stream/ds-1/_lifecycle", []string{"name"}, map[string]string{"include_defaults": "true"}},
		{"indices.delete_data_lifecycle", "indices.delete_data_lifecycle", map[string]any{"name": "ds-1"}, http.MethodDelete, "/_data_stream/ds-1/_lifecycle", []string{"name"}, nil},
		{"indices.explain_data_lifecycle", "indices.explain_data_lifecycle", map[string]any{"index": "ds-1"}, http.MethodGet, "/ds-1/_lifecycle/explain", []string{"index"}, nil},
		{"indices.downsample", "indices.downsample", map[string]any{"index": "src-idx", "target_index": "dst-idx"}, http.MethodPost, "/src-idx/_downsample/dst-idx", []string{"index", "target_index"}, nil},

		// ML Data Frame Analytics & Evaluation
		{"ml.put_data_frame_analytics", "ml.put_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodPut, "/_ml/data_frame/analytics/dfa-1", []string{"id"}, nil},
		{"ml.get_data_frame_analytics specific", "ml.get_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodGet, "/_ml/data_frame/analytics/dfa-1", []string{"id"}, nil},
		{"ml.get_data_frame_analytics all", "ml.get_data_frame_analytics", map[string]any{}, http.MethodGet, "/_ml/data_frame/analytics", nil, nil},
		{"ml.get_data_frame_analytics_stats specific", "ml.get_data_frame_analytics_stats", map[string]any{"id": "dfa-1"}, http.MethodGet, "/_ml/data_frame/analytics/dfa-1/_stats", []string{"id"}, nil},
		{"ml.get_data_frame_analytics_stats all", "ml.get_data_frame_analytics_stats", map[string]any{}, http.MethodGet, "/_ml/data_frame/analytics/_stats", nil, nil},
		{"ml.update_data_frame_analytics", "ml.update_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodPost, "/_ml/data_frame/analytics/dfa-1/_update", []string{"id"}, nil},
		{"ml.delete_data_frame_analytics", "ml.delete_data_frame_analytics", map[string]any{"id": "dfa-1", "force": true}, http.MethodDelete, "/_ml/data_frame/analytics/dfa-1", []string{"id"}, map[string]string{"force": "true"}},
		{"ml.start_data_frame_analytics", "ml.start_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodPost, "/_ml/data_frame/analytics/dfa-1/_start", []string{"id"}, nil},
		{"ml.stop_data_frame_analytics", "ml.stop_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodPost, "/_ml/data_frame/analytics/dfa-1/_stop", []string{"id"}, nil},
		{"ml.preview_data_frame_analytics GET", "ml.preview_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodGet, "/_ml/data_frame/analytics/dfa-1/_preview", []string{"id"}, nil},
		{"ml.preview_data_frame_analytics POST adhoc", "ml.preview_data_frame_analytics", map[string]any{"body": map[string]any{"config": map[string]any{}}}, http.MethodPost, "/_ml/data_frame/analytics/_preview", nil, nil},
		{"ml.explain_data_frame_analytics GET", "ml.explain_data_frame_analytics", map[string]any{"id": "dfa-1"}, http.MethodGet, "/_ml/data_frame/analytics/dfa-1/_explain", []string{"id"}, nil},
		{"ml.explain_data_frame_analytics POST adhoc", "ml.explain_data_frame_analytics", map[string]any{"body": map[string]any{"source": map[string]any{}}}, http.MethodPost, "/_ml/data_frame/analytics/_explain", nil, nil},
		{"ml.evaluate_data_frame", "ml.evaluate_data_frame", map[string]any{}, http.MethodPost, "/_ml/data_frame/_evaluate", nil, nil},

		// ML Trained Models
		{"ml.start_trained_model_deployment", "ml.start_trained_model_deployment", map[string]any{"model_id": "tm-1", "wait_for": "started"}, http.MethodPost, "/_ml/trained_models/tm-1/deployment/_start", []string{"model_id"}, map[string]string{"wait_for": "started"}},
		{"ml.stop_trained_model_deployment", "ml.stop_trained_model_deployment", map[string]any{"model_id": "tm-1", "force": true}, http.MethodPost, "/_ml/trained_models/tm-1/deployment/_stop", []string{"model_id"}, map[string]string{"force": "true"}},
		{"ml.update_trained_model_deployment", "ml.update_trained_model_deployment", map[string]any{"model_id": "tm-1"}, http.MethodPost, "/_ml/trained_models/tm-1/deployment/_update", []string{"model_id"}, nil},
		{"ml.infer_trained_model", "ml.infer_trained_model", map[string]any{"model_id": "tm-1"}, http.MethodPost, "/_ml/trained_models/tm-1/_infer", []string{"model_id"}, nil},
		{"ml.infer_trained_model_deployment", "ml.infer_trained_model_deployment", map[string]any{"id": "tm-1"}, http.MethodPost, "/_ml/trained_models/tm-1/deployment/_infer", []string{"id"}, nil},
		{"ml.put_trained_model_alias", "ml.put_trained_model_alias", map[string]any{"model_id": "tm-1", "model_alias": "prod"}, http.MethodPut, "/_ml/trained_models/tm-1/model_aliases/prod", []string{"model_id", "model_alias"}, nil},
		{"ml.delete_trained_model_alias", "ml.delete_trained_model_alias", map[string]any{"model_id": "tm-1", "model_alias": "prod"}, http.MethodDelete, "/_ml/trained_models/tm-1/model_aliases/prod", []string{"model_id", "model_alias"}, nil},
		{"ml.put_trained_model_definition_part", "ml.put_trained_model_definition_part", map[string]any{"model_id": "tm-1", "part": 0}, http.MethodPut, "/_ml/trained_models/tm-1/definition/0", []string{"model_id", "part"}, nil},
		{"ml.put_trained_model_vocabulary", "ml.put_trained_model_vocabulary", map[string]any{"model_id": "tm-1"}, http.MethodPut, "/_ml/trained_models/tm-1/vocabulary", []string{"model_id"}, nil},

		// ML Anomaly Detection
		{"ml.flush_job", "ml.flush_job", map[string]any{"job_id": "j-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/_flush", []string{"job_id"}, nil},
		{"ml.post_data", "ml.post_data", map[string]any{"job_id": "j-1", "body": []any{map[string]any{"v": 1}}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/_data", []string{"job_id"}, nil},
		{"ml.reset_job", "ml.reset_job", map[string]any{"job_id": "j-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/_reset", []string{"job_id"}, nil},
		{"ml.forecast", "ml.forecast", map[string]any{"job_id": "j-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/_forecast", []string{"job_id"}, nil},
		{"ml.delete_forecast specific", "ml.delete_forecast", map[string]any{"job_id": "j-1", "forecast_id": "fc-1"}, http.MethodDelete, "/_ml/anomaly_detectors/j-1/_forecast/fc-1", []string{"job_id", "forecast_id"}, nil},
		{"ml.delete_forecast all", "ml.delete_forecast", map[string]any{"job_id": "j-1"}, http.MethodDelete, "/_ml/anomaly_detectors/j-1/_forecast", []string{"job_id"}, nil},
		{"ml.delete_expired_data", "ml.delete_expired_data", map[string]any{"job_id": "j-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/_delete_expired_data", []string{"job_id"}, nil},
		{"ml.validate", "ml.validate", map[string]any{}, http.MethodPost, "/_ml/anomaly_detectors/_validate", nil, nil},
		{"ml.validate_detector", "ml.validate_detector", map[string]any{}, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", nil, nil},
		{"ml.estimate_model_memory", "ml.estimate_model_memory", map[string]any{}, http.MethodPost, "/_ml/anomaly_detectors/_estimate_model_memory", nil, nil},
		{"ml.get_buckets GET all", "ml.get_buckets", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/results/buckets", []string{"job_id"}, nil},
		{"ml.get_buckets POST ts", "ml.get_buckets", map[string]any{"job_id": "j-1", "timestamp": "1700000000", "body": map[string]any{"expand": true}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/results/buckets/1700000000", []string{"job_id", "timestamp"}, nil},
		{"ml.get_overall_buckets GET", "ml.get_overall_buckets", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/results/overall_buckets", []string{"job_id"}, nil},
		{"ml.get_overall_buckets POST", "ml.get_overall_buckets", map[string]any{"job_id": "j-1", "body": map[string]any{"top_n": 2}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/results/overall_buckets", []string{"job_id"}, nil},
		{"ml.get_records GET", "ml.get_records", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/results/records", []string{"job_id"}, nil},
		{"ml.get_records POST", "ml.get_records", map[string]any{"job_id": "j-1", "body": map[string]any{"record_score": 50}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/results/records", []string{"job_id"}, nil},
		{"ml.get_categories all", "ml.get_categories", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/results/categories", []string{"job_id"}, nil},
		{"ml.get_categories specific POST", "ml.get_categories", map[string]any{"job_id": "j-1", "category_id": 3, "body": map[string]any{}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/results/categories/3", []string{"job_id", "category_id"}, nil},
		{"ml.get_influencers GET", "ml.get_influencers", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/results/influencers", []string{"job_id"}, nil},
		{"ml.get_influencers POST", "ml.get_influencers", map[string]any{"job_id": "j-1", "body": map[string]any{}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/results/influencers", []string{"job_id"}, nil},
		{"ml.get_model_snapshots all", "ml.get_model_snapshots", map[string]any{"job_id": "j-1"}, http.MethodGet, "/_ml/anomaly_detectors/j-1/model_snapshots", []string{"job_id"}, nil},
		{"ml.get_model_snapshots specific POST", "ml.get_model_snapshots", map[string]any{"job_id": "j-1", "snapshot_id": "s-1", "body": map[string]any{}}, http.MethodPost, "/_ml/anomaly_detectors/j-1/model_snapshots/s-1", []string{"job_id", "snapshot_id"}, nil},
		{"ml.update_model_snapshot", "ml.update_model_snapshot", map[string]any{"job_id": "j-1", "snapshot_id": "s-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/model_snapshots/s-1/_update", []string{"job_id", "snapshot_id"}, nil},
		{"ml.delete_model_snapshot", "ml.delete_model_snapshot", map[string]any{"job_id": "j-1", "snapshot_id": "s-1"}, http.MethodDelete, "/_ml/anomaly_detectors/j-1/model_snapshots/s-1", []string{"job_id", "snapshot_id"}, nil},
		{"ml.revert_model_snapshot", "ml.revert_model_snapshot", map[string]any{"job_id": "j-1", "snapshot_id": "s-1"}, http.MethodPost, "/_ml/anomaly_detectors/j-1/model_snapshots/s-1/_revert", []string{"job_id", "snapshot_id"}, nil},

		// Security Profiles, Settings & Cross-Cluster API Keys
		{"security.activate_profile", "security.activate_profile", map[string]any{}, http.MethodPost, "/_security/profile/_activate", nil, nil},
		{"security.get_profile", "security.get_profile", map[string]any{"uid": "u_1", "data": "*"}, http.MethodGet, "/_security/profile/u_1", []string{"uid"}, map[string]string{"data": "*"}},
		{"security.update_profile_data", "security.update_profile_data", map[string]any{"uid": "u_1"}, http.MethodPost, "/_security/profile/u_1/_data", []string{"uid"}, nil},
		{"security.enable_profile", "security.enable_profile", map[string]any{"uid": "u_1"}, http.MethodPut, "/_security/profile/u_1/_enable", []string{"uid"}, nil},
		{"security.disable_profile", "security.disable_profile", map[string]any{"uid": "u_1"}, http.MethodPut, "/_security/profile/u_1/_disable", []string{"uid"}, nil},
		{"security.suggest_profiles", "security.suggest_profiles", map[string]any{}, http.MethodPost, "/_security/_suggest_profiles", nil, nil},
		{"security.has_privileges_profile GET", "security.has_privileges_profile", map[string]any{"uid": "u_1"}, http.MethodGet, "/_security/profile/u_1/_has_privileges", []string{"uid"}, nil},
		{"security.has_privileges_profile POST", "security.has_privileges_profile", map[string]any{"uid": "u_1", "body": map[string]any{"cluster": []any{"all"}}}, http.MethodPost, "/_security/profile/u_1/_has_privileges", []string{"uid"}, nil},
		{"security.get_settings", "security.get_settings", map[string]any{}, http.MethodGet, "/_security/settings", nil, nil},
		{"security.update_settings", "security.update_settings", map[string]any{}, http.MethodPut, "/_security/settings", nil, nil},
		{"security.create_cross_cluster_api_key", "security.create_cross_cluster_api_key", map[string]any{}, http.MethodPost, "/_security/cross_cluster/api_key", nil, nil},
		{"security.update_cross_cluster_api_key", "security.update_cross_cluster_api_key", map[string]any{"id": "cck-1"}, http.MethodPut, "/_security/cross_cluster/api_key/cck-1", []string{"id"}, nil},

		// Transform, GeoIP, ILM, Cross-Cluster Resolve & Cat
		{"transform.reset_transform", "transform.reset_transform", map[string]any{"transform_id": "tx-1", "force": true}, http.MethodPost, "/_transform/tx-1/_reset", []string{"transform_id"}, map[string]string{"force": "true"}},
		{"transform.upgrade_transforms", "transform.upgrade_transforms", map[string]any{"dry_run": true}, http.MethodPost, "/_transform/_upgrade", nil, map[string]string{"dry_run": "true"}},
		{"transform.schedule_now_transform", "transform.schedule_now_transform", map[string]any{"transform_id": "tx-1"}, http.MethodPost, "/_transform/tx-1/_schedule_now", []string{"transform_id"}, nil},
		{"ingest.put_geoip_database", "ingest.put_geoip_database", map[string]any{"id": "db-1"}, http.MethodPut, "/_ingest/geoip/database/db-1", []string{"id"}, nil},
		{"ingest.get_geoip_database specific", "ingest.get_geoip_database", map[string]any{"id": "db-1"}, http.MethodGet, "/_ingest/geoip/database/db-1", []string{"id"}, nil},
		{"ingest.get_geoip_database all", "ingest.get_geoip_database", map[string]any{}, http.MethodGet, "/_ingest/geoip/database", nil, nil},
		{"ingest.delete_geoip_database", "ingest.delete_geoip_database", map[string]any{"id": "db-1"}, http.MethodDelete, "/_ingest/geoip/database/db-1", []string{"id"}, nil},
		{"ilm.migrate_to_data_tiers", "ilm.migrate_to_data_tiers", map[string]any{"dry_run": true}, http.MethodPost, "/_ilm/migrate_to_data_tiers", nil, map[string]string{"dry_run": "true"}},
		{"cluster.resolve_cluster all", "cluster.resolve_cluster", map[string]any{}, http.MethodGet, "/_resolve/cluster", nil, nil},
		{"indices.resolve_cluster named", "indices.resolve_cluster", map[string]any{"name": "remote*"}, http.MethodGet, "/_resolve/cluster/remote*", []string{"name"}, nil},
		{"cat.help", "cat.help", map[string]any{}, http.MethodGet, "/_cat", nil, map[string]string{"help": ""}},
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
					t.Errorf("expected param %q stripped from query, got %v", stripped, spec.query)
				}
			}
			for k, wantV := range tc.wantQuery {
				if !spec.query.Has(k) || spec.query.Get(k) != wantV {
					t.Errorf("query[%q]: got %q (has=%v), want %q", k, spec.query.Get(k), spec.query.Has(k), wantV)
				}
			}
			if tc.action == "ml.post_data" && !strings.HasSuffix(string(spec.body), "\n") {
				t.Errorf("expected ml.post_data NDJSON body to end with newline, got %q", string(spec.body))
			}
		})
	}

	missingParamActions := []string{
		"indices.put_data_lifecycle",
		"indices.get_data_lifecycle",
		"indices.delete_data_lifecycle",
		"indices.explain_data_lifecycle",
		"indices.downsample",
		"ml.put_data_frame_analytics",
		"ml.update_data_frame_analytics",
		"ml.delete_data_frame_analytics",
		"ml.start_data_frame_analytics",
		"ml.stop_data_frame_analytics",
		"ml.start_trained_model_deployment",
		"ml.stop_trained_model_deployment",
		"ml.update_trained_model_deployment",
		"ml.infer_trained_model",
		"ml.infer_trained_model_deployment",
		"ml.put_trained_model_alias",
		"ml.delete_trained_model_alias",
		"ml.put_trained_model_definition_part",
		"ml.put_trained_model_vocabulary",
		"ml.flush_job",
		"ml.post_data",
		"ml.reset_job",
		"ml.forecast",
		"ml.delete_forecast",
		"ml.delete_expired_data",
		"ml.get_buckets",
		"ml.get_overall_buckets",
		"ml.get_records",
		"ml.get_categories",
		"ml.get_influencers",
		"ml.get_model_snapshots",
		"ml.update_model_snapshot",
		"ml.delete_model_snapshot",
		"ml.revert_model_snapshot",
		"security.get_profile",
		"security.update_profile_data",
		"security.enable_profile",
		"security.disable_profile",
		"security.has_privileges_profile",
		"security.update_cross_cluster_api_key",
		"transform.reset_transform",
		"transform.schedule_now_transform",
		"ingest.put_geoip_database",
		"ingest.delete_geoip_database",
	}
	for _, act := range missingParamActions {
		if _, err := ctx.buildActionRequest(act, map[string]any{}); err == nil {
			t.Errorf("expected error for %s with empty params", act)
		}
	}

	// Test dependency-ordered cleanupAll via httptest.Server
	type recordedCall struct {
		method string
		path   string
		query  string
		body   string
	}
	var mu sync.Mutex
	var calls []recordedCall
	keySeq := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, recordedCall{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			body:   string(bodyBytes),
		})
		var resp string
		switch r.URL.Path {
		case "/_security/api_key", "/_security/api_key/_grant", "/_security/cross_cluster/api_key":
			if r.Method == http.MethodPost {
				keySeq++
				resp = fmt.Sprintf(`{"id":"ak-%d","api_key":"secret"}`, keySeq)
			}
		}
		mu.Unlock()
		if resp == "" {
			resp = `{"acknowledged":true}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	defer ts.Close()

	cleanCtx := newRunnerContext(ts.Client(), ts.URL)
	setupActions := []struct {
		action string
		params map[string]any
	}{
		{"ml.put_data_frame_analytics", map[string]any{
			"id":   "dfa-job-1",
			"body": map[string]any{"dest": map[string]any{"index": "dfa-dest-idx"}},
		}},
		{"ml.put_trained_model", map[string]any{"model_id": "tm-order-1"}},
		{"ml.start_trained_model_deployment", map[string]any{"model_id": "tm-order-1"}},
		{"ml.put_trained_model_alias", map[string]any{"model_id": "tm-order-1", "model_alias": "tm-alias-1"}},
		{"indices.downsample", map[string]any{"index": "ds-src-idx", "target_index": "ds-target-idx"}},
		{"ingest.put_geoip_database", map[string]any{"id": "geo-db-1"}},
		{"security.create_api_key", map[string]any{"body": map[string]any{"name": "k1"}}},
		{"security.grant_api_key", map[string]any{"body": map[string]any{"grant_type": "password"}}},
		{"security.create_cross_cluster_api_key", map[string]any{"body": map[string]any{"name": "k3"}}},
		{"security.update_settings", map[string]any{"body": map[string]any{"index.number_of_replicas": "0"}}},
	}
	for _, sa := range setupActions {
		step := &OrderedMap{
			Fields: []YAMLField{
				{Key: sa.action, Value: sa.params},
			},
		}
		if err := cleanCtx.execDo(step, false); err != nil {
			t.Fatalf("execDo(%s) failed: %v", sa.action, err)
		}
	}

	mu.Lock()
	calls = nil
	mu.Unlock()

	cleanCtx.cleanupAll()

	mu.Lock()
	recorded := append([]recordedCall(nil), calls...)
	mu.Unlock()

	indexOfCall := func(method, path string) int {
		for i, rc := range recorded {
			if rc.method == method && rc.path == path {
				return i
			}
		}
		return -1
	}

	dfaStopIdx := indexOfCall(http.MethodPost, "/_ml/data_frame/analytics/dfa-job-1/_stop")
	dfaDelIdx := indexOfCall(http.MethodDelete, "/_ml/data_frame/analytics/dfa-job-1")
	dfaDestDelIdx := indexOfCall(http.MethodDelete, "/dfa-dest-idx")
	if dfaStopIdx < 0 || dfaDelIdx < 0 || dfaStopIdx >= dfaDelIdx {
		t.Fatalf("expected DFA stop before DFA delete, got stop=%d del=%d calls=%+v", dfaStopIdx, dfaDelIdx, recorded)
	}
	if dfaDelIdx >= dfaDestDelIdx {
		t.Fatalf("expected DFA delete before dest.index delete, got dfaDel=%d destDel=%d", dfaDelIdx, dfaDestDelIdx)
	}

	depStopIdx := indexOfCall(http.MethodPost, "/_ml/trained_models/tm-order-1/deployment/_stop")
	aliasDelIdx := indexOfCall(http.MethodDelete, "/_ml/trained_models/tm-order-1/model_aliases/tm-alias-1")
	modelDelIdx := indexOfCall(http.MethodDelete, "/_ml/trained_models/tm-order-1")
	if depStopIdx < 0 || aliasDelIdx < 0 || modelDelIdx < 0 {
		t.Fatalf("missing trained model teardown calls: depStop=%d aliasDel=%d modelDel=%d", depStopIdx, aliasDelIdx, modelDelIdx)
	}
	if depStopIdx >= modelDelIdx || aliasDelIdx >= modelDelIdx {
		t.Fatalf("expected deployment stop (%d) and alias delete (%d) strictly before model delete (%d)", depStopIdx, aliasDelIdx, modelDelIdx)
	}

	if indexOfCall(http.MethodDelete, "/ds-target-idx") < 0 {
		t.Fatalf("expected downsampled target_index to be deleted in cleanupAll")
	}
	if indexOfCall(http.MethodDelete, "/_ingest/geoip/database/geo-db-1") < 0 {
		t.Fatalf("expected geoip database to be deleted in cleanupAll")
	}
	apiKeyDelIdx := indexOfCall(http.MethodDelete, "/_security/api_key")
	if apiKeyDelIdx < 0 || !strings.Contains(recorded[apiKeyDelIdx].body, `"ak-1"`) || !strings.Contains(recorded[apiKeyDelIdx].body, `"ak-2"`) || !strings.Contains(recorded[apiKeyDelIdx].body, `"ak-3"`) {
		t.Fatalf("expected DELETE /_security/api_key with ak-1..ak-3, got idx=%d calls=%+v", apiKeyDelIdx, recorded)
	}
	if indexOfCall(http.MethodPut, "/_security/settings") < 0 {
		t.Fatalf("expected PUT /_security/settings reset in cleanupAll")
	}

	// Verify embedded Round 56 YAML specs parse cleanly and every Round 56 `do` action builds without errors
	dryCtx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	dryCtx.stash["src_idx"] = "r56_ts_src"
	dryCtx.stash["special_doc_id"] = "doc#1?tag=alpha 2"
	dryCtx.stash["fc_id"] = "fc-1"
	dryCtx.stash["prof_uid"] = "u_elastic"
	dryCtx.stash["cc_key_id"] = "cck-1"

	for _, specPath := range []string{"specs/90_ingest_pipelines.yml", "specs/98_advanced_features.yml"} {
		rawBytes, readErr := EmbeddedSpecsFS.ReadFile(specPath)
		if readErr != nil {
			t.Fatalf("failed reading embedded %s: %v", specPath, readErr)
		}
		doc, parseErr := ParseSpecFile(string(rawBytes))
		if parseErr != nil {
			t.Fatalf("failed parsing embedded %s: %v", specPath, parseErr)
		}
		if len(doc.Sections) == 0 {
			t.Fatalf("expected non-empty sections in %s", specPath)
		}
		for _, sec := range doc.Sections {
			if !strings.Contains(sec.Name, "Round 56") {
				continue
			}
			for si, st := range sec.Steps {
				if st.Op != "do" {
					continue
				}
				om, ok := st.Value.(*OrderedMap)
				if !ok {
					t.Fatalf("%s [%s] step %d: expected OrderedMap for do step", specPath, sec.Name, si+1)
				}
				var actName string
				var actParams any
				for _, f := range om.Fields {
					switch f.Key {
					case "catch", "headers", "ignore", "warnings", "warning_headers", "warnings_regex", "allowed_warnings", "allowed_warnings_regex", "node_selector":
					default:
						actName = f.Key
						actParams = f.Value
					}
				}
				pm, _ := ToNative(dryCtx.expandStash(actParams)).(map[string]any)
				if pm == nil {
					pm = map[string]any{}
				}
				if _, bErr := dryCtx.buildActionRequest(actName, pm); bErr != nil {
					t.Fatalf("%s [%s] step %d (%s): buildActionRequest failed: %v", specPath, sec.Name, si+1, actName, bErr)
				}
			}
		}
	}
}

func TestRound56_RunnerFeaturesArbitraryKeyBracedStashVersionCatchAndEscaping(t *testing.T) {
	t.Parallel()

	// 1. Verify _arbitrary_key_ in lookupResponsePath, set, match, contains, and not_contains
	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	ctx.lastMethod = http.MethodGet
	ctx.lastStatus = http.StatusOK
	ctx.lastResponse = map[string]any{
		"nodes": map[string]any{
			"node-alpha": map[string]any{
				"name": "es-alpha",
				"role": "master",
			},
			"node-beta": map[string]any{
				"name": "es-beta",
				"role": "data",
			},
		},
		"single_wrap": map[string]any{
			"explicit": "fixed",
			"dyn_uuid": map[string]any{
				"status": "green",
			},
		},
		"bucket_list": []any{
			map[string]any{
				"by_host": map[string]any{
					"host-99": map[string]any{"count": int64(42)},
				},
			},
		},
		"empty_obj":  map[string]any{},
		"false_bool": false,
		"null_field": nil,
		"true_bool":  true,
	}

	if err := ctx.execSet(map[string]any{
		"nodes._arbitrary_key_.name": "${first_node_name}",
	}); err != nil {
		t.Fatalf("execSet with _arbitrary_key_ and braced target failed: %v", err)
	}
	if ctx.stash["first_node_name"] != "es-alpha" {
		t.Fatalf("expected deterministic sorted first key 'es-alpha', got %v", ctx.stash["first_node_name"])
	}

	// Multi-entry _arbitrary_key_ match should succeed even when matching the second sorted key ("data")
	if err := ctx.execMatch(map[string]any{
		"nodes._arbitrary_key_.role": "data",
		"single_wrap": map[string]any{
			"explicit":        "fixed",
			"_arbitrary_key_": map[string]any{"status": "green"},
		},
	}); err != nil {
		t.Fatalf("execMatch with _arbitrary_key_ failed: %v", err)
	}
	if err := ctx.execMatch(map[string]any{
		"empty_obj": map[string]any{"_arbitrary_key_": "anything"},
	}); err == nil {
		t.Fatalf("expected _arbitrary_key_ match against empty map to fail")
	}

	if err := ctx.execContains(map[string]any{
		"bucket_list": map[string]any{
			"by_host": map[string]any{
				"_arbitrary_key_": map[string]any{"count": int64(42)},
			},
		},
	}); err != nil {
		t.Fatalf("execContains with _arbitrary_key_ failed: %v", err)
	}
	if err := ctx.execNotContains(map[string]any{
		"bucket_list": map[string]any{
			"by_host": map[string]any{
				"_arbitrary_key_": map[string]any{"count": int64(999)},
			},
		},
	}); err != nil {
		t.Fatalf("execNotContains with _arbitrary_key_ failed: %v", err)
	}

	// 2. Braced ${var} stash preservation, string interpolation, dotted stash, and transform_and_set
	ctx.stash["num_val"] = int64(77)
	ctx.stash["bool_val"] = true
	ctx.stash["idx"] = "r56.logs"
	ctx.stash["nested_cfg"] = map[string]any{"env": "staging"}
	ctx.stash["arr_items"] = []any{"x", "y", "z"}

	if got := ctx.expandStash("${num_val}"); got != int64(77) {
		t.Fatalf("expected whole-string ${num_val} to preserve int64(77), got %v (%T)", got, got)
	}
	if got := ctx.expandStash("${bool_val}"); got != true {
		t.Fatalf("expected whole-string ${bool_val} to preserve bool(true), got %v (%T)", got, got)
	}
	if got := ctx.expandStash("${idx}_downsampled_${nested_cfg.env}"); got != "r56.logs_downsampled_staging" {
		t.Fatalf("unexpected braced string interpolation: %v", got)
	}
	if val, ok := ctx.lookupResponsePath("${arr_items}.-1"); !ok || val != "z" {
		t.Fatalf("expected ${arr_items}.-1 = 'z', got (%v, %v)", val, ok)
	}
	if err := ctx.execTransformAndSet(map[string]any{
		"${upper_env}": "upper(${nested_cfg.env})",
		"${joined_id}": `concat("${idx}", "-", "${upper_env}")`,
	}); err != nil {
		t.Fatalf("execTransformAndSet with braced vars failed: %v", err)
	}
	if ctx.stash["upper_env"] != "STAGING" {
		t.Fatalf("expected upper_env='STAGING', got %v", ctx.stash["upper_env"])
	}

	// 3. Multi-range and exact single-version skip.version
	if !versionInRange("7.10.2", "6.0.0 - 6.8.99, 7.10.0 - 7.10.99, 8.0.0 - 8.3.0") {
		t.Fatalf("expected multi-range versionInRange to match middle range")
	}
	if !versionInRange("7.10.2", "8.0.0 - 8.2.0, 7.10.2") {
		t.Fatalf("expected multi-range versionInRange to match exact single version")
	}
	if versionInRange("7.10.2", " - 7.9.99, 7.11.0 - 8.5.0") {
		t.Fatalf("expected multi-range versionInRange not to match disjoint ranges")
	}
	skipErr := ctx.execStep(SpecStep{
		Op: "skip",
		Value: map[string]any{
			"version":  "6.0.0 - 6.8.99, 7.10.2",
			"reason":   "skip exact target",
			"features": "is_unset",
		},
	}, false)
	if skipErr == nil {
		t.Fatalf("expected skip step to skip when comma-separated version matches proxyTargetVersion")
	}

	// 4. is_unset step
	for _, p := range []string{"missing_path", "null_field", "false_bool"} {
		if err := ctx.execStep(SpecStep{Op: "is_unset", Value: p}, false); err != nil {
			t.Fatalf("expected is_unset(%q) to pass, got %v", p, err)
		}
	}
	if err := ctx.execStep(SpecStep{Op: "is_unset", Value: "true_bool"}, false); err == nil {
		t.Fatalf("expected is_unset(true_bool) to fail")
	}

	// 5. Named catch HTTP status tokens + URL path escaping for '#', '?', '%', space, and '/' in document IDs
	var mu sync.Mutex
	var gotPath, gotRawPath, gotRawQuery string
	statusOverride := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotRawPath = r.URL.RawPath
		gotRawQuery = r.URL.RawQuery
		code := statusOverride
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if code != 0 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"type":"test_err","reason":"forced"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"_id":"ok","found":true}`))
	}))
	defer ts.Close()

	httpCtx := newRunnerContext(ts.Client(), ts.URL)

	catchCases := []struct {
		token string
		code  int
	}{
		{"not_acceptable", http.StatusNotAcceptable},
		{"request_entity_too_large", http.StatusRequestEntityTooLarge},
		{"payload_too_large", http.StatusRequestEntityTooLarge},
		{"unsupported_media_type", http.StatusUnsupportedMediaType},
		{"unprocessable_entity", http.StatusUnprocessableEntity},
		{"too_many_requests", http.StatusTooManyRequests},
		{"not_implemented", http.StatusNotImplemented},
	}
	for _, cc := range catchCases {
		mu.Lock()
		statusOverride = cc.code
		mu.Unlock()
		step := &OrderedMap{
			Fields: []YAMLField{
				{Key: "catch", Value: cc.token},
				{Key: "info", Value: map[string]any{}},
			},
		}
		if err := httpCtx.execDo(step, false); err != nil {
			t.Fatalf("catch %q (HTTP %d) unexpectedly failed: %v", cc.token, cc.code, err)
		}
		mu.Lock()
		statusOverride = http.StatusInternalServerError
		mu.Unlock()
		if err := httpCtx.execDo(step, false); err == nil {
			t.Fatalf("expected catch %q to fail when server returns 500", cc.token)
		}
	}

	mu.Lock()
	statusOverride = 0
	mu.Unlock()

	trickyID := "doc#1?a=b 2%z/sub"
	for _, docAction := range []string{"index", "get", "delete", "update", "explain", "termvectors"} {
		step := &OrderedMap{
			Fields: []YAMLField{
				{Key: docAction, Value: map[string]any{
					"index":   "r56_esc_idx",
					"id":      trickyID,
					"refresh": "true",
					"body":    map[string]any{"x": 1},
				}},
			},
		}
		if err := httpCtx.execDo(step, false); err != nil {
			t.Fatalf("execDo(%s) with tricky ID failed: %v", docAction, err)
		}
		mu.Lock()
		p, rp, rq := gotPath, gotRawPath, gotRawQuery
		mu.Unlock()
		if !strings.HasSuffix(p, "/"+trickyID) {
			t.Fatalf("%s decoded URL.Path = %q, expected suffix /%s", docAction, p, trickyID)
		}
		if !strings.Contains(rp, "doc%231%3Fa=b%202%25z%2Fsub") {
			t.Fatalf("%s RawPath = %q, expected percent-encoded tricky ID", docAction, rp)
		}
		if rq != "refresh=true" {
			t.Fatalf("%s RawQuery = %q, expected 'refresh=true' without leaked ID query", docAction, rq)
		}
	}

	// Ensure multi-index commas and wildcards stay unescaped in path
	multiStep := &OrderedMap{
		Fields: []YAMLField{
			{Key: "search", Value: map[string]any{"index": "idx1,logs-*"}},
		},
	}
	if err := httpCtx.execDo(multiStep, false); err != nil {
		t.Fatalf("search with multi-index wildcard failed: %v", err)
	}
	mu.Lock()
	finalPath := gotPath
	mu.Unlock()
	if finalPath != "/idx1,logs-*/_search" {
		t.Fatalf("expected /idx1,logs-*/_search, got %q", finalPath)
	}

	// Exercise _arbitrary_key_ across is_empty, not_contains, is_false, and array index traversal
	ctx.lastResponse = map[string]any{
		"nodes": map[string]any{
			"nodeA": map[string]any{
				"roles":   []any{"data", "ingest"},
				"empty_a": []any{},
				"empty_m": map[string]any{},
				"empty_s": "",
				"flag":    false,
			},
			"nodeB": map[string]any{
				"roles":   []any{"master"},
				"empty_a": []any{},
				"empty_m": map[string]any{},
				"empty_s": "",
				"flag":    false,
			},
		},
		"dotted.key": "dval",
	}
	for _, k := range []string{"nodes._arbitrary_key_.empty_a", "nodes._arbitrary_key_.empty_m", "nodes._arbitrary_key_.empty_s", "nodes._arbitrary_key_.missing_field"} {
		if err := ctx.execIsEmpty(k); err != nil {
			t.Fatalf("execIsEmpty(%s) failed: %v", k, err)
		}
	}
	if err := ctx.execIsFalse("nodes._arbitrary_key_.flag"); err != nil {
		t.Fatalf("execIsFalse wildcard failed: %v", err)
	}
	ncStep := NewOrderedMap()
	ncStep.Set("nodes._arbitrary_key_.roles", "ml")
	if err := ctx.execNotContains(ncStep); err != nil {
		t.Fatalf("execNotContains wildcard failed: %v", err)
	}
	matchDotted := NewOrderedMap()
	matchDotted.Set(`dotted\.key`, "dval")
	if err := ctx.execMatch(matchDotted); err != nil {
		t.Fatalf("execMatch dotted fallback failed: %v", err)
	}
}
