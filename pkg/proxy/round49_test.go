package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRound49KnnSearchCatDataStreamsAndAdminEndpoints(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Create index with dense_vector and index docs for _knn_search
	code, _, _ := doRound48Req(t, handler, http.MethodPut, "/knn_r49", `{
		"mappings": {
			"properties": {
				"vec": {"type": "dense_vector", "dims": 3},
				"category": {"type": "keyword"}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /knn_r49 failed: %d", code)
	}
	doRound48Req(t, handler, http.MethodPut, "/knn_r49/_doc/1?refresh=true", `{"vec":[1.0, 0.0, 0.0], "category":"tech"}`)
	doRound48Req(t, handler, http.MethodPut, "/knn_r49/_doc/2?refresh=true", `{"vec":[0.0, 1.0, 0.0], "category":"food"}`)

	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/knn_r49/_knn_search", `{
		"knn": {
			"field": "vec",
			"query_vector": [1.0, 0.0, 0.0],
			"k": 1,
			"num_candidates": 2
		},
		"filter": {
			"term": {"category": "tech"}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /knn_r49/_knn_search failed: %d %v", code, resp)
	}
	hitsObj, _ := resp["hits"].(map[string]any)
	hitsArr, _ := hitsObj["hits"].([]any)
	if len(hitsArr) != 1 {
		t.Fatalf("expected 1 hit from _knn_search, got %d (%v)", len(hitsArr), resp)
	}

	// 2. Data stream + _cat/data_streams + _data_stream/_stats
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_data_stream/ds_r49_metrics", "")
	if code != http.StatusOK {
		t.Fatalf("PUT /_data_stream/ds_r49_metrics failed: %d", code)
	}
	code, _, rawCatDS := doRound48Req(t, handler, http.MethodGet, "/_cat/data_streams/ds_r49_metrics?v=true", "")
	if code != http.StatusOK || !strings.Contains(rawCatDS, "ds_r49_metrics") {
		t.Fatalf("GET /_cat/data_streams/ds_r49_metrics failed: %d %s", code, rawCatDS)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/_cat/data_streams/nonexistent_ds", "")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent data stream in _cat/data_streams, got %d", code)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_data_stream/ds_r49_metrics/_stats", "")
	if code != http.StatusOK || resp["data_stream_count"] != float64(1) {
		t.Fatalf("GET /_data_stream/ds_r49_metrics/_stats failed: %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_data_stream/_stats", "")
	if code != http.StatusOK || resp["data_stream_count"] != float64(1) {
		t.Fatalf("GET /_data_stream/_stats failed: %d %v", code, resp)
	}

	// 3. _remote/info and _nodes/reload_secure_settings
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/_remote/info", "")
	if code != http.StatusOK {
		t.Fatalf("GET /_remote/info failed: %d", code)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_nodes/reload_secure_settings", "{}")
	if code != http.StatusOK {
		t.Fatalf("POST /_nodes/reload_secure_settings failed: %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_nodes/node-1/reload_secure_settings", "{}")
	if code != http.StatusOK {
		t.Fatalf("POST /_nodes/node-1/reload_secure_settings failed: %d %v", code, resp)
	}
}

func TestRound49SnapshotLifecycleAndSimulateTemplates(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Snapshot repository & snapshot lifecycle
	code, resp, _ := doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_backup", `{
		"type": "fs",
		"settings": {"location": "/tmp/r49_backup"}
	}`)
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("PUT /_snapshot/r49_backup failed: %d %v", code, resp)
	}

	code, _, rawRepos := doRound48Req(t, handler, http.MethodGet, "/_cat/repositories?format=json", "")
	if code != http.StatusOK || !strings.Contains(rawRepos, "r49_backup") {
		t.Fatalf("GET /_cat/repositories failed: %d %s", code, rawRepos)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_snapshot/r49_backup/_verify", "")
	if code != http.StatusOK || resp["nodes"] == nil {
		t.Fatalf("POST /_snapshot/r49_backup/_verify failed: %d %v", code, resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_backup/snap_01", `{"indices": ["idx_a"]}`)
	if code != http.StatusOK || resp["accepted"] != true {
		t.Fatalf("PUT /_snapshot/r49_backup/snap_01 failed: %d %v", code, resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_backup/snap_01", "")
	if code != http.StatusOK {
		t.Fatalf("GET /_snapshot/r49_backup/snap_01 failed: %d %v", code, resp)
	}
	snaps, _ := resp["snapshots"].([]any)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %v", resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_backup/snap_01/_status", "")
	if code != http.StatusOK {
		t.Fatalf("GET /_snapshot/r49_backup/snap_01/_status failed: %d %v", code, resp)
	}

	code, _, rawCatSnaps := doRound48Req(t, handler, http.MethodGet, "/_cat/snapshots/r49_backup?format=json", "")
	if code != http.StatusOK || !strings.Contains(rawCatSnaps, "snap_01") {
		t.Fatalf("GET /_cat/snapshots/r49_backup failed: %d %s", code, rawCatSnaps)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_snapshot/r49_backup/snap_01/_restore", `{}`)
	if code != http.StatusOK || resp["accepted"] != true {
		t.Fatalf("POST /_snapshot/r49_backup/snap_01/_restore failed: %d %v", code, resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodDelete, "/_snapshot/r49_backup/snap_01", "")
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("DELETE /_snapshot/r49_backup/snap_01 failed: %d %v", code, resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodDelete, "/_snapshot/r49_backup", "")
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("DELETE /_snapshot/r49_backup failed: %d %v", code, resp)
	}

	// 2. Simulate index templates (`_simulate`, `_simulate/{name}`, `_simulate_index/{name}`)
	doRound48Req(t, handler, http.MethodPut, "/_component_template/ct_r49", `{
		"template": {
			"settings": {"number_of_shards": 1},
			"mappings": {"properties": {"service": {"type": "keyword"}}}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/_index_template/it_r49", `{
		"index_patterns": ["r49-logs-*"],
		"composed_of": ["ct_r49"],
		"priority": 50,
		"template": {
			"mappings": {"properties": {"msg": {"type": "text"}}}
		}
	}`)

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate/it_r49", "")
	if code != http.StatusOK || resp["template"] == nil {
		t.Fatalf("POST /_index_template/_simulate/it_r49 failed: %d %v", code, resp)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate", `{
		"index_patterns": ["r49-logs-*"],
		"composed_of": ["ct_r49"],
		"priority": 10
	}`)
	if code != http.StatusOK || resp["template"] == nil {
		t.Fatalf("POST /_index_template/_simulate failed: %d %v", code, resp)
	}
	// Ensure "_simulate" was NOT stored as an index template
	code, _, rawTpls := doRound48Req(t, handler, http.MethodGet, "/_index_template", "")
	if code != http.StatusOK || strings.Contains(rawTpls, `"_simulate"`) {
		t.Fatalf("expected _simulate not to be stored as template, got %d %s", code, rawTpls)
	}

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate_index/r49-logs-0001", "")
	if code != http.StatusOK || resp["template"] == nil {
		t.Fatalf("POST /_index_template/_simulate_index/r49-logs-0001 failed: %d %v", code, resp)
	}
}

func TestRound49JoinScoreModeInnerHitsAndRankEvalMetrics(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Join family: has_child score_mode + inner_hits + min_children, has_parent score + inner_hits, ignore_unmapped
	doRound48Req(t, handler, http.MethodPut, "/r49_join", `{
		"mappings": {
			"properties": {
				"rel": {
					"type": "join",
					"relations": {"dept": "emp"}
				},
				"name": {"type": "text"},
				"rating": {"type": "integer"}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r49_join/_doc/d1?refresh=true", `{"name":"Engineering","rel":"dept"}`)
	doRound48Req(t, handler, http.MethodPut, "/r49_join/_doc/e1?routing=d1&refresh=true", `{"name":"Alice","rating":5,"rel":{"name":"emp","parent":"d1"}}`)
	doRound48Req(t, handler, http.MethodPut, "/r49_join/_doc/e2?routing=d1&refresh=true", `{"name":"Bob","rating":4,"rel":{"name":"emp","parent":"d1"}}`)

	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/r49_join/_search", `{
		"query": {
			"has_child": {
				"type": "emp",
				"score_mode": "sum",
				"min_children": 2,
				"inner_hits": {"name": "employees"},
				"query": {"match_all": {}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("has_child search failed: %d %v", code, resp)
	}
	hitsWrapper, _ := resp["hits"].(map[string]any)
	hitsList, _ := hitsWrapper["hits"].([]any)
	if len(hitsList) != 1 {
		t.Fatalf("expected 1 parent hit, got %d: %v", len(hitsList), resp)
	}
	hit0, _ := hitsList[0].(map[string]any)
	if sc, _ := hit0["_score"].(float64); sc <= 1.0 {
		t.Fatalf("expected summed child score > 1.0, got %v", hit0["_score"])
	}
	ih, _ := hit0["inner_hits"].(map[string]any)
	if ih["employees"] == nil {
		t.Fatalf("expected inner_hits.employees to be populated, got %v", ih)
	}

	// Unmapped child type without ignore_unmapped -> 400
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/r49_join/_search", `{
		"query": {
			"has_child": {
				"type": "unknown_rel",
				"query": {"match_all": {}}
			}
		}
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unmapped child type without ignore_unmapped, got %d", code)
	}

	// Unmapped child type with ignore_unmapped: true -> 200 with 0 hits
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r49_join/_search", `{
		"query": {
			"has_child": {
				"type": "unknown_rel",
				"ignore_unmapped": true,
				"query": {"match_all": {}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 with ignore_unmapped:true, got %d %v", code, resp)
	}

	// 2. RankEval NDCG linear discount + per_field_analyzer in termvectors
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r49_join/_termvectors", `{
		"doc": {"name": "Foo_Bar Baz"},
		"per_field_analyzer": {"name": "whitespace"},
		"filter": {"min_word_length": 5}
	}`)
	if code != http.StatusOK || resp["found"] != true {
		t.Fatalf("POST /r49_join/_termvectors failed: %d %v", code, resp)
	}
	tv, _ := resp["term_vectors"].(map[string]any)
	nameTV, _ := tv["name"].(map[string]any)
	terms, _ := nameTV["terms"].(map[string]any)
	if terms["Foo_Bar"] == nil || terms["Baz"] != nil {
		t.Fatalf("expected whitespace analyzer + min_word_length=5 to keep Foo_Bar and filter Baz, got %v", terms)
	}
}

func TestRound49DeepCoverageEndpointsScriptsNamedAndPercolate(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Snapshot root, wildcards, comma lists, _status, error paths, method checks
	doRound48Req(t, handler, http.MethodPost, "/_snapshot", "{}")
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_a", `{"type":"fs","settings":{"location":"/tmp/a"}}`)
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_b", `{"type":"fs","settings":{"location":"/tmp/b"}}`)
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_a", `{invalid`)
	doRound48Req(t, handler, http.MethodPatch, "/_snapshot/r49_repo_a", `{}`)

	code, resp, _ := doRound48Req(t, handler, http.MethodGet, "/_snapshot", "")
	if code != http.StatusOK || resp["r49_repo_a"] == nil {
		t.Fatalf("GET /_snapshot failed: %d %v", code, resp)
	}
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/_all", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/_status", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_*", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a,r49_repo_b", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/missing_repo", "")
	doRound48Req(t, handler, http.MethodDelete, "/_snapshot/missing_repo", "")

	// Snapshot item actions & edge cases
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/missing_repo/snap1", "")
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_a/snap_a1", `{"indices":"idx1,idx2","include_global_state":false}`)
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_a/snap_a2", `{}`)
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r49_repo_a/snap_bad", `{invalid`)
	doRound48Req(t, handler, http.MethodPatch, "/_snapshot/r49_repo_a/snap_a1", `{}`)
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/_status", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/_all", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/snap_*", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/snap_a1,snap_a2", "")
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/missing_snap", "")
	doRound48Req(t, handler, http.MethodDelete, "/_snapshot/r49_repo_a/missing_snap", "")

	doRound48Req(t, handler, http.MethodPost, "/_snapshot/missing_repo/snap_a1/_restore", `{}`)
	doRound48Req(t, handler, http.MethodPost, "/_snapshot/r49_repo_a/missing_snap/_restore", `{}`)
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/snap_a1/_restore", `{}`)
	doRound48Req(t, handler, http.MethodPost, "/_snapshot/r49_repo_a/snap_a1/_status", `{}`)
	doRound48Req(t, handler, http.MethodGet, "/_snapshot/r49_repo_a/snap_a1/_unknown", `{}`)

	// _cat/snapshots variations
	doRound48Req(t, handler, http.MethodPost, "/_cat/snapshots", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/snapshots?v=true", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/snapshots/_all?v=true", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/snapshots/r49_repo_*?v=true", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/snapshots/missing_repo", "")

	// 2. _knn_search variations (flat fields, array knn, invalid JSON, method check)
	doRound48Req(t, handler, http.MethodPut, "/knn_r49_deep", `{
		"mappings": {"properties": {"vec": {"type": "dense_vector", "dims": 2}, "tag": {"type": "keyword"}}}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/knn_r49_deep/_doc/1?refresh=true", `{"vec":[1.0, 0.0],"tag":"a"}`)
	doRound48Req(t, handler, http.MethodPost, "/knn_r49_deep/_knn_search", `{
		"field": "vec",
		"query_vector": [1.0, 0.0],
		"k": 1,
		"num_candidates": 2,
		"filter": {"term": {"tag": "a"}}
	}`)
	doRound48Req(t, handler, http.MethodPost, "/knn_r49_deep/_knn_search", `{
		"knn": [{"field": "vec", "query_vector": [1.0, 0.0], "k": 1}],
		"filter": {"term": {"tag": "a"}}
	}`)
	doRound48Req(t, handler, http.MethodPost, "/knn_r49_deep/_knn_search", `{invalid`)
	doRound48Req(t, handler, http.MethodDelete, "/knn_r49_deep/_knn_search", "")

	// 3. _index_template/_simulate and _simulate_index edge cases
	doRound48Req(t, handler, http.MethodGet, "/_index_template/_simulate", "")
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate", `{invalid`)
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate/nonexistent_tpl", "")
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate/nonexistent_tpl", `{}`)
	doRound48Req(t, handler, http.MethodPut, "/_component_template/ct_r49_deep", `{
		"template": {
			"settings": {"index.number_of_replicas": 0},
			"aliases": {"r49_alias": {}},
			"mappings": {"properties": {"host": {"type": "keyword"}}}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/_index_template/it_r49_low", `{
		"index_patterns": ["r49-sim-*"],
		"priority": 10,
		"template": {"settings": {"number_of_shards": 1}}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/_index_template/it_r49_high", `{
		"index_patterns": ["r49-sim-*"],
		"composed_of": ["ct_r49_deep"],
		"priority": 100,
		"template": {
			"settings": {"number_of_shards": 2},
			"aliases": {"r49_high_alias": {}},
			"mappings": {"properties": {"msg": {"type": "text"}}}
		}
	}`)
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate/it_r49_high", `{}`)
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate_index/r49-sim-0001", "")
	doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate_index/no-matching-template-idx", "")
	doRound48Req(t, handler, http.MethodGet, "/_index_template/_simulate_index/r49-sim-0001", "")

	// 4. Missing stored script validation across query/sort/script_fields/runtime_mappings/rescore/aggs
	for _, body := range []string{
		`{"post_filter": {"script": {"script": {"id": "missing_sc"}}}}`,
		`{"sort": [{"_script": {"type": "number", "script": {"id": "missing_sc"}}}]}`,
		`{"script_fields": {"sf": {"script": {"id": "missing_sc"}}}}`,
		`{"runtime_mappings": {"rm": {"type": "keyword", "script": {"id": "missing_sc"}}}}`,
		`{"rescore": [{"query": {"rescore_query": {"script": {"script": {"id": "missing_sc"}}}}}]}`,
		`{"query": {"script_score": {"query": {"match_all": {}}, "script": {"id": "missing_sc"}}}}`,
		`{"query": {"function_score": {"query": {"match_all": {}}, "script_score": {"script": {"id": "missing_sc"}}}}}`,
		`{"query": {"function_score": {"query": {"match_all": {}}, "functions": [{"script_score": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"bool": {"must": [{"script": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"bool": {"should": [{"script": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"bool": {"filter": [{"script": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"bool": {"must_not": [{"script": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"constant_score": {"filter": {"script": {"script": {"id": "missing_sc"}}}}}}`,
		`{"query": {"boosting": {"positive": {"match_all": {}}, "negative": {"script": {"script": {"id": "missing_sc"}}}, "negative_boost": 0.5}}}`,
		`{"query": {"dis_max": {"queries": [{"script": {"script": {"id": "missing_sc"}}}]}}}`,
		`{"query": {"nested": {"path": "items", "query": {"script": {"script": {"id": "missing_sc"}}}}}}`,
		`{"query": {"pinned": {"ids": ["1"], "organic": {"script": {"script": {"id": "missing_sc"}}}}}}`,
		`{"query": {"terms_set": {"tag": {"terms": ["a"], "minimum_should_match_script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"t": {"terms": {"field": "tag", "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"h": {"histogram": {"field": "v", "interval": 10, "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"dh": {"date_histogram": {"field": "ts", "fixed_interval": "1d", "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"r": {"range": {"field": "v", "ranges": [{"to": 10}], "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"f": {"filter": {"script": {"script": {"id": "missing_sc"}}}}}}`,
		`{"aggs": {"fs": {"filters": {"filters": {"a": {"script": {"script": {"id": "missing_sc"}}}}}}}}`,
		`{"aggs": {"avg_v": {"avg": {"script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"pct": {"percentiles": {"field": "v", "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"pr": {"percentile_ranks": {"field": "v", "values": [10], "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"ss": {"string_stats": {"field": "tag", "script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"rt": {"rate": {"script": {"id": "missing_sc"}}}}}`,
		`{"aggs": {"sm": {"scripted_metric": {"map_script": {"id": "missing_sc"}}}}}`,
	} {
		c, _, _ := doRound48Req(t, handler, http.MethodPost, "/knn_r49_deep/_search", body)
		if c != http.StatusNotFound {
			t.Fatalf("expected 404 for missing stored script in %s, got %d", body, c)
		}
	}

	// 5. Named queries (`_name`) across compound/span/nested/knn/post_filter queries
	doRound48Req(t, handler, http.MethodPut, "/r49_named", `{
		"mappings": {
			"properties": {
				"text": {"type": "text"},
				"tag": {"type": "keyword"},
				"vec": {"type": "dense_vector", "dims": 2},
				"items": {"type": "nested", "properties": {"k": {"type": "keyword"}}}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r49_named/_doc/1?refresh=true", `{
		"text": "quick brown fox",
		"tag": "alpha",
		"vec": [1.0, 0.0],
		"items": [{"k": "v1"}]
	}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r49_named/_search", `{
		"query": {
			"bool": {
				"must": [
					{"constant_score": {"_name": "cs_q", "filter": {"term": {"tag": {"value": "alpha", "_name": "term_q"}}}}},
					{"dis_max": {"_name": "dm_q", "queries": [{"term": {"tag": "alpha"}}]}},
					{"boosting": {"positive": {"term": {"tag": {"value": "alpha", "_name": "boost_pos"}}}, "negative": {"term": {"tag": "beta"}}, "negative_boost": 0.5}},
					{"function_score": {"query": {"term": {"tag": "alpha"}}, "functions": [{"filter": {"term": {"tag": {"value": "alpha", "_name": "fs_fn_filter"}}}, "weight": 2}]}},
					{"script_score": {"query": {"term": {"tag": {"value": "alpha", "_name": "ss_inner"}}}, "script": {"source": "1.0"}}},
					{"nested": {"path": "items", "_name": "nested_outer", "query": {"term": {"items.k": {"value": "v1", "_name": "nested_inner"}}}}},
					{"pinned": {"ids": ["1"], "organic": {"term": {"tag": {"value": "alpha", "_name": "pinned_org"}}}}},
					{"span_near": {"clauses": [{"span_term": {"text": {"value": "quick", "_name": "sn_t1"}}}], "slop": 2, "in_order": true}},
					{"span_or": {"clauses": [{"span_term": {"text": {"value": "quick", "_name": "so_t1"}}}]}},
					{"span_not": {"include": {"span_term": {"text": {"value": "quick", "_name": "snot_inc"}}}, "exclude": {"span_term": {"text": "lazy"}}}},
					{"span_first": {"match": {"span_term": {"text": {"value": "quick", "_name": "sf_m"}}}, "end": 3}}
				]
			}
		},
		"post_filter": {"term": {"tag": {"value": "alpha", "_name": "pf_q"}}},
		"knn": [{"field": "vec", "query_vector": [1.0, 0.0], "k": 1, "num_candidates": 1, "_name": "knn_top", "filter": [{"term": {"tag": {"value": "alpha", "_name": "knn_flt"}}}]}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("named query search failed: %d %v", code, resp)
	}

	// 6. Percolate multi-docs inside compound queries & Painless execute contexts
	doRound48Req(t, handler, http.MethodPut, "/r49_perc", `{
		"mappings": {"properties": {"query": {"type": "percolator"}, "title": {"type": "text"}}}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r49_perc/_doc/p1?refresh=true", `{"query": {"match": {"title": "doris"}}}`)
	for _, wrapperQ := range []string{
		`{"constant_score": {"filter": {"percolate": {"field": "query", "documents": [{"title": "doris"}, {"title": "other"}]}}}}`,
		`{"function_score": {"query": {"percolate": {"field": "query", "documents": [{"title": "other"}, {"title": "doris"}]}}}}`,
		`{"dis_max": {"queries": [{"percolate": {"field": "query", "documents": [{"title": "doris"}]}}]}}`,
		`{"boosting": {"positive": {"percolate": {"field": "query", "documents": [{"title": "doris"}]}}, "negative": {"term": {"title": "none"}}, "negative_boost": 0.5}}`,
	} {
		c, rMap, _ := doRound48Req(t, handler, http.MethodPost, "/r49_perc/_search", `{"query": `+wrapperQ+`}`)
		if c != http.StatusOK {
			t.Fatalf("percolate compound query failed: %d %v", c, rMap)
		}
	}

	// Painless _execute contexts (ingest, update, StringBuilder, Period)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "ctx.added = ctx.x + 5"},
		"context": "ingest",
		"context_setup": {"document": {"x": 10}}
	}`)
	if code != http.StatusOK {
		t.Fatalf("_scripts/painless/_execute ingest context failed: %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "new StringBuilder('clean_str')"}
	}`)
	if code != http.StatusOK || resp["result"] != "clean_str" {
		t.Fatalf("expected unquoted clean_str from StringBuilder execute, got %d %v", code, resp)
	}

	// _msearch/template with blank lines and missing template 404 item
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r49_named/_msearch/template",
		"{}\n{\"id\":\"missing_tpl_id\",\"params\":{}}\n\n{}\n{\"source\":{\"query\":{\"match_all\":{}}},\"params\":{}}\n")
	if code != http.StatusOK {
		t.Fatalf("_msearch/template failed: %d %v", code, resp)
	}
	resps, _ := resp["responses"].([]any)
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses from _msearch/template, got %d (%v)", len(resps), resp)
	}
}

func TestRound50ProxyAndIngestFindings(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// F1: _termvectors & _mtermvectors method validation and _index preservation with ids
	doRound48Req(t, handler, http.MethodPut, "/r50_tv/_doc/1?refresh=true", `{"title": "hello world"}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/r50_tv/_termvectors/1", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for DELETE _termvectors, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/r50_tv/_mtermvectors", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for DELETE _mtermvectors, got %d", c)
	}
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/_mtermvectors", `{"index": "r50_tv", "ids": ["1"]}`)
	if code != http.StatusOK {
		t.Fatalf("_mtermvectors failed: %d %v", code, resp)
	}
	if tvDocs, ok := resp["docs"].([]any); !ok || len(tvDocs) != 1 || tvDocs[0].(map[string]any)["_index"] != "r50_tv" {
		t.Fatalf("expected _mtermvectors docs[0]._index == r50_tv, got %v", resp)
	}

	// F2: Snapshot HEAD, duplicate snapshot name 400, and _restore with rename_pattern/rename_replacement
	if c, _, raw := doRound48Req(t, handler, http.MethodHead, "/_snapshot/missing_repo", ""); c != http.StatusNotFound || raw != "" {
		t.Fatalf("expected 404 empty body for HEAD missing repo, got %d %q", c, raw)
	}
	doRound48Req(t, handler, http.MethodPut, "/_snapshot/r50_repo", `{"type": "fs", "settings": {"location": "/tmp/r50_repo"}}`)
	if c, _, raw := doRound48Req(t, handler, http.MethodHead, "/_snapshot/r50_repo", ""); c != http.StatusOK || raw != "" {
		t.Fatalf("expected 200 empty body for HEAD repo, got %d %q", c, raw)
	}
	doRound48Req(t, handler, http.MethodPut, "/r50_snap_src", `{"mappings": {"properties": {" custom_k ": {"type": "keyword"}}}}`)
	if c, rMap, _ := doRound48Req(t, handler, http.MethodPut, "/_snapshot/r50_repo/snap1", `{"indices": "r50_snap_src"}`); c != http.StatusOK {
		t.Fatalf("create snapshot failed: %d %v", c, rMap)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_snapshot/r50_repo/snap1", `{"indices": "r50_snap_src"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate snapshot name, got %d", c)
	}
	if c, _, raw := doRound48Req(t, handler, http.MethodHead, "/_snapshot/r50_repo/snap1", ""); c != http.StatusOK || raw != "" {
		t.Fatalf("expected 200 empty body for HEAD snapshot, got %d %q", c, raw)
	}
	if c, _, raw := doRound48Req(t, handler, http.MethodHead, "/_snapshot/r50_repo/missing_snap", ""); c != http.StatusNotFound || raw != "" {
		t.Fatalf("expected 404 empty body for HEAD missing snapshot, got %d %q", c, raw)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_snapshot/r50_repo/snap1/_restore", `{
		"indices": "r50_snap_src",
		"rename_pattern": "r50_snap_(.+)",
		"rename_replacement": "r50_restored_$1"
	}`)
	if code != http.StatusOK {
		t.Fatalf("restore snapshot failed: %d %v", code, resp)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r50_restored_src", ""); c != http.StatusOK {
		t.Fatalf("expected restored index r50_restored_src to exist, got %d", c)
	}

	// F3: Index & Component template validation
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_index_template/r50_no_pat", `{"template": {}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for index template missing index_patterns, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_index_template/r50_bad_comp", `{"index_patterns": ["r50-*"], "composed_of": ["no_such_comp"]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for index template with missing component template, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_index_template/_simulate", `{"index_patterns": ["r50-*"], "composed_of": ["no_such_comp"]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for simulate index template with missing component template, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPut, "/_component_template/r50_comp_in_use", `{"template": {"settings": {"number_of_shards": 1}}}`)
	doRound48Req(t, handler, http.MethodPut, "/_index_template/r50_using_comp", `{"index_patterns": ["r50-use-*"], "composed_of": ["r50_comp_in_use"]}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_component_template/r50_comp_in_use", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when deleting component template in use, got %d", c)
	}

	// F4: Stateful index close/open
	doRound48Req(t, handler, http.MethodPut, "/r50_close_idx/_doc/1?refresh=true", `{"v": 1}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r50_close_idx/_close", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET _close, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_missing_close/_close", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for closing missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_close_idx/_close", ""); c != http.StatusOK {
		t.Fatalf("expected 200 for POST _close, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_close_idx/_search", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception on search of closed index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r50_close_idx/_doc/2", `{"v": 2}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception on write to closed index, got %d", c)
	}
	_, resIdxResp, _ := doRound48Req(t, handler, http.MethodGet, "/_resolve/index/r50_close_idx", "")
	if idxArr, ok := resIdxResp["indices"].([]any); !ok || len(idxArr) != 1 || idxArr[0].(map[string]any)["open"] != false {
		t.Fatalf("expected _resolve/index to report open:false for closed index, got %v", resIdxResp)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_close_idx/_open", ""); c != http.StatusOK {
		t.Fatalf("expected 200 for POST _open, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_close_idx/_search", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on search after _open, got %d", c)
	}

	// F5: Cluster & Index settings
	code, resp, _ = doRound48Req(t, handler, http.MethodPut, "/_cluster/settings?flat_settings=true", `{
		"persistent": {"cluster.routing.allocation.enable": "primaries"},
		"transient": {"indices.recovery.max_bytes_per_sec": "100mb"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("PUT _cluster/settings failed: %d %v", code, resp)
	}
	if pMap, _ := resp["persistent"].(map[string]any); pMap["cluster.routing.allocation.enable"] != "primaries" {
		t.Fatalf("expected flat persistent cluster setting, got %v", resp)
	}
	doRound48Req(t, handler, http.MethodPut, "/r50_close_idx/_settings", `{"index.refresh_interval": "5s"}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/r50_close_idx/_settings/index.refresh_*?flat_settings=true", "")
	if code != http.StatusOK {
		t.Fatalf("GET /{index}/_settings/{name} failed: %d %v", code, resp)
	}
	if idxObj, _ := resp["r50_close_idx"].(map[string]any); idxObj == nil || idxObj["settings"].(map[string]any)["index.refresh_interval"] != "5s" {
		t.Fatalf("expected filtered index.refresh_interval=5s, got %v", resp)
	}

	// F6, F7, F8, F9: _rank_eval, _field_caps, _mapping/field, _terms_enum validation
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_no_such_idx/_rank_eval", `{"requests": [], "metric": {"precision": {"k": 1}}}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _rank_eval on missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r50_no_such_idx/_field_caps?fields=*", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _field_caps on missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_close_idx/_field_caps?fields=*", "{bad_json"); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for _field_caps with malformed JSON, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r50_no_such_idx/_mapping/field/v", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _mapping/field on missing index, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPut, "/r50_te_idx", `{"mappings": {"properties": {"kw": {"type": "keyword"}, "txt": {"type": "text"}}}}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_no_such_idx/_terms_enum", `{"field": "kw"}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _terms_enum on missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_te_idx/_terms_enum", `{"field": "kw", "unknown_param": 1}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for _terms_enum unknown field, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_te_idx/_terms_enum", `{"field": "kw", "size": 0}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for _terms_enum size<=0, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r50_te_idx/_terms_enum", `{"field": "txt"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for _terms_enum on text field, got %d", c)
	}

	// F24: Painless _execute in ingest context returns mutated document map when no explicit return
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "ctx.tag = 'mutated'"},
		"context": "ingest",
		"context_setup": {"document": {"x": 1}}
	}`)
	if code != http.StatusOK {
		t.Fatalf("painless _execute ingest failed: %d %v", code, resp)
	}
	if resDoc, ok := resp["result"].(map[string]any); !ok || resDoc["tag"] != "mutated" || resDoc["x"] == nil {
		t.Fatalf("expected mutated document map from ingest _execute, got %v", resp)
	}

	// F26: _reindex conflicts=abort & pipeline execution
	doRound48Req(t, handler, http.MethodPut, "/_ingest/pipeline/r50_reidx_pipe", `{
		"processors": [{"set": {"field": "piped", "value": true}}]
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r50_reidx_dst/_doc/1?refresh=true", `{"v": 100}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r50_close_idx"},
		"dest": {"index": "r50_reidx_dst", "op_type": "create", "pipeline": "r50_reidx_pipe"}
	}`)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on _reindex op_type=create with conflicts=abort, got %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_reindex?refresh=true", `{
		"conflicts": "proceed",
		"source": {"index": "r50_close_idx"},
		"dest": {"index": "r50_reidx_dst2", "pipeline": "r50_reidx_pipe"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _reindex to r50_reidx_dst2, got %d %v", code, resp)
	}
	_, dstDoc, _ := doRound48Req(t, handler, http.MethodGet, "/r50_reidx_dst2/_doc/1", "")
	if srcMap, _ := dstDoc["_source"].(map[string]any); srcMap["piped"] != true {
		t.Fatalf("expected reindexed doc to have piped:true, got %v", dstDoc)
	}

	// F27, F28, F29: Ingest processors (set ignore_empty_value, url_encode, html_strip escaped_tags, date array, csv empty/strict quote, foreach on_failure)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"set": {"field": "skip_empty", "value": "", "ignore_empty_value": true}},
				{"url_encode": {"field": "raw_q", "target_field": "{{enc_target}}"}},
				{"html_strip": {"field": "html_in", "escaped_tags": ["b"]}},
				{"date": {"field": "dates", "target_field": "parsed_dates", "formats": ["EEE yyyy-MM-dd hh:mm:ss.SSSSSS a"], "output_format": "yyyy-MM-dd"}},
				{"csv": {"field": "empty_csv", "target_fields": ["c1", "c2"]}},
				{
					"foreach": {
						"field": "nums",
						"processor": {"convert": {"field": "_ingest._value", "type": "integer"}},
						"on_failure": [{"set": {"field": "failed_elem", "value": "{{_ingest._value}}"}}]
					}
				}
			]
		},
		"docs": [{
			"_source": {
				"raw_q": "a b",
				"enc_target": "encoded_q",
				"html_in": "<p>hello <b>bold</b></p>",
				"dates": ["Wed 2026-07-01 02:30:00.123456 PM"],
				"empty_csv": "",
				"nums": ["10", "bad_int", "30"]
			}
		}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("ingest simulate failed: %d %v", code, resp)
	}
	simDoc := resp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	simSrc := simDoc["_source"].(map[string]any)
	if _, hasSkip := simSrc["skip_empty"]; hasSkip {
		t.Fatalf("expected skip_empty to be omitted by ignore_empty_value, got %v", simSrc)
	}
	if simSrc["encoded_q"] != "a+b" {
		t.Fatalf("expected encoded_q='a+b', got %v", simSrc["encoded_q"])
	}
	if !strings.Contains(fmt.Sprintf("%v", simSrc["html_in"]), "<b>bold</b>") || strings.Contains(fmt.Sprintf("%v", simSrc["html_in"]), "<p>") {
		t.Fatalf("expected html_strip escaped_tags to preserve <b> and strip <p>, got %v", simSrc["html_in"])
	}
	if pDates, ok := simSrc["parsed_dates"].([]any); !ok || len(pDates) != 1 || pDates[0] != "2026-07-01" {
		t.Fatalf("expected parsed_dates=['2026-07-01'], got %v", simSrc["parsed_dates"])
	}
	if simSrc["failed_elem"] != "bad_int" {
		t.Fatalf("expected foreach on_failure to capture _ingest._value='bad_int', got %v", simSrc["failed_elem"])
	}
	if numsArr, ok := simSrc["nums"].([]any); !ok || numsArr[0] != float64(10) {
		t.Fatalf("expected foreach partial array progress nums[0]==10, got %v", simSrc["nums"])
	}
	if ingMeta, ok := simDoc["_ingest"].(map[string]any); ok {
		if _, hasVal := ingMeta["_value"]; hasVal {
			t.Fatalf("expected _ingest._value to be cleaned up after foreach on_failure, got %v", ingMeta)
		}
	}

	// F25 & F26: Guarded missing doc value ref in metric agg script & params._source raw nested array access
	doRound48Req(t, handler, http.MethodPut, "/r50_script_idx", `{
		"mappings": {
			"properties": {
				"a": {"type": "integer"},
				"b": {"type": "integer"},
				"items": {
					"type": "nested",
					"properties": {
						"price": {"type": "integer"},
						"qty": {"type": "integer"}
					}
				}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r50_script_idx/_doc/1?refresh=true", `{
		"a": 10,
		"items": [
			{"price": 5, "qty": 2},
			{"price": 3, "qty": 4}
		]
	}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r50_script_idx/_search", `{
		"script_fields": {
			"nested_total": {
				"script": {
					"source": "int s = 0; for (def it : params._source.items) { s += it.price * it.qty; } return s;"
				}
			}
		},
		"aggs": {
			"guarded_sum": {
				"sum": {
					"script": {
						"source": "doc['b'].size() == 0 ? doc['a'].value : doc['a'].value + doc['b'].value"
					}
				}
			},
			"missing_sum": {
				"sum": {
					"missing": 5,
					"script": {
						"source": "doc['a'].value + doc['b'].value"
					}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("r50_script_idx search failed: %d %v", code, resp)
	}
	aggsMap := resp["aggregations"].(map[string]any)
	if aggsMap["guarded_sum"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected guarded_sum=10, got %v", aggsMap["guarded_sum"])
	}
	if aggsMap["missing_sum"].(map[string]any)["value"] != float64(15) {
		t.Fatalf("expected missing_sum=15, got %v", aggsMap["missing_sum"])
	}
	hit0Fields := resp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	if hit0Fields["nested_total"].([]any)[0] != float64(22) {
		t.Fatalf("expected nested_total=[22], got %v", hit0Fields["nested_total"])
	}

	// Extended coverage for cluster/index settings, _cat endpoints, and _rank_eval metrics
	doRound48Req(t, handler, http.MethodGet, "/_cluster/settings?include_defaults=true", "")
	doRound48Req(t, handler, http.MethodGet, "/_cluster/settings?include_defaults=true&flat_settings=true", "")
	doRound48Req(t, handler, http.MethodPut, "/_cluster/settings", `{"persistent": {"cluster.routing.allocation.enable": null}}`)
	doRound48Req(t, handler, http.MethodGet, "/r50_close_idx/_settings?include_defaults=true", "")
	doRound48Req(t, handler, http.MethodGet, "/r50_close_idx/_settings?include_defaults=true&flat_settings=true", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/indices/r50_*?v=true&h=index,status,health&s=index:desc&format=json", "")
	doRound48Req(t, handler, http.MethodGet, "/_cat/templates/r50_*?v=true&h=name,index_patterns&s=name&format=json", "")
	doRound48Req(t, handler, http.MethodPost, "/r50_script_idx/_rank_eval", `{
		"requests": [{
			"id": "q1",
			"request": {"query": {"match_all": {}}},
			"ratings": [{"_index": "r50_script_idx", "_id": "1", "rating": 3}]
		}],
		"metric": {
			"dcg": {"k": 5, "normalize": true, "discount_factor": 2.0}
		}
	}`)
	doRound48Req(t, handler, http.MethodPost, "/r50_tv/_search", `{
		"query": {
			"intervals": {
				"title": {
					"all_of": {
						"intervals": [
							{"match": {"query": "hello"}},
							{"any_of": {"intervals": [
								{"prefix": {"prefix": "wor"}},
								{"wildcard": {"pattern": "w*d"}},
								{"fuzzy": {"term": "world"}}
							]}}
						]
					}
				}
			}
		},
		"highlight": {
			"fields": {"title": {}}
		}
	}`)
}

func TestRound51_ProxyAndComplianceFeatures(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// F0: Data stream migration & GET /_data_stream/{name} 404
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_data_stream/no_such_ds", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for GET /_data_stream/no_such_ds, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_data_stream/_migrate/no_such_alias", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /_data_stream/_migrate/{name}, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_data_stream/_migrate/no_such_alias", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for POST /_data_stream/_migrate/no_such_alias, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPut, "/r51_mig_idx_1", `{}`)
	doRound48Req(t, handler, http.MethodPut, "/r51_mig_idx_2", `{}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_data_stream/_migrate/r51_mig_idx_1", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when migrating concrete index name, got %d", c)
	}
	// Multi-index alias without write index -> 400
	doRound48Req(t, handler, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "r51_mig_idx_1", "alias": "r51_multi_no_write"}},
			{"add": {"index": "r51_mig_idx_2", "alias": "r51_multi_no_write"}}
		]
	}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_data_stream/_migrate/r51_multi_no_write", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when migrating multi-index alias without write index, got %d", c)
	}
	// Valid migration of alias with write index
	doRound48Req(t, handler, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "r51_mig_idx_1", "alias": "r51_mig_stream", "is_write_index": false}},
			{"add": {"index": "r51_mig_idx_2", "alias": "r51_mig_stream", "is_write_index": true}}
		]
	}`)
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/_data_stream/_migrate/r51_mig_stream", "")
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("expected 200 acknowledged for _data_stream/_migrate, got %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_data_stream/r51_mig_stream", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for GET /_data_stream/r51_mig_stream after migrate, got %d %v", code, resp)
	}

	// F2: ILM endpoints (/start, /stop, /status, /move, /remove, /retry, /explain 404)
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_ilm/status", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /_ilm/status, got %d", c)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_ilm/status", "")
	if code != http.StatusOK || resp["operation_mode"] != "RUNNING" {
		t.Fatalf("expected operation_mode=RUNNING, got %d %v", code, resp)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_ilm/stop", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /_ilm/stop, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPost, "/_ilm/stop", "")
	_, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_ilm/status", "")
	if resp["operation_mode"] != "STOPPED" {
		t.Fatalf("expected operation_mode=STOPPED after _ilm/stop, got %v", resp)
	}
	doRound48Req(t, handler, http.MethodPost, "/_ilm/start", "")
	_, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_ilm/status", "")
	if resp["operation_mode"] != "RUNNING" {
		t.Fatalf("expected operation_mode=RUNNING after _ilm/start, got %v", resp)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_ilm/move/no_such_idx", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _ilm/move on missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_mig_idx_1/_ilm/remove", ""); c != http.StatusOK {
		t.Fatalf("expected 200 for /{index}/_ilm/remove, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_mig_idx_1/_ilm/retry", ""); c != http.StatusOK {
		t.Fatalf("expected 200 for /{index}/_ilm/retry, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/no_such_ilm_idx/_ilm/explain", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 for /{index}/_ilm/explain on missing index, got %d", c)
	}

	// F3: _cat/* 405, _cat/allocation/{node_id}, _cat/templates version
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_cat/indices", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /_cat/indices, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_cat/allocation", ""); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for DELETE /_cat/allocation, got %d", c)
	}
	_, _, rawCatAlloc := doRound48Req(t, handler, http.MethodGet, "/_cat/allocation/non_existent_node?format=json", "")
	if strings.TrimSpace(rawCatAlloc) != "[]" {
		t.Fatalf("expected empty array for non-matching node_id on _cat/allocation, got %s", rawCatAlloc)
	}
	doRound48Req(t, handler, http.MethodPut, "/_index_template/r51_ver_tpl", `{
		"index_patterns": ["r51_ver_*"],
		"version": 42,
		"template": {"mappings": {"properties": {"x": {"type": "keyword"}}}}
	}`)
	_, _, rawCatTpl := doRound48Req(t, handler, http.MethodGet, "/_cat/templates/r51_ver_tpl?format=json", "")
	if !strings.Contains(rawCatTpl, `"version":"42"`) {
		t.Fatalf("expected _cat/templates to report version 42, got %s", rawCatTpl)
	}

	// F4: _tasks, _cluster/allocation/explain, _segments, _cache/clear validation
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_tasks/bad_task_id", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed task_id in _tasks/{task_id}, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_tasks/node-1:notanumber", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-numeric task number in _tasks/{task_id}, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_cluster/allocation/explain", `{"index": "no_such_alloc_idx", "shard": 0, "primary": true}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _cluster/allocation/explain on missing index, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPost, "/r51_mig_idx_1/_close", "")
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r51_mig_idx_1/_segments", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception for _segments on closed index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_mig_idx_1/_cache/clear", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception for _cache/clear on closed index, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPost, "/r51_mig_idx_1/_open", "")

	// F5: _aliases & /{index}/_alias/{name} conflicts and 404s
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r51_multi_no_write", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_index_name_exception when creating index with existing alias name, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r51_mig_idx_1/_alias/r51_mig_idx_2", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_alias_name_exception when alias name collides with index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/no_such_idx/_alias/r51_some_alias", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 index_not_found_exception when adding alias to missing index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_aliases", `{
		"actions": [{"remove": {"index": "r51_mig_idx_1", "alias": "non_existent_alias*"}}]
	}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 aliases_not_found_exception when removing non-existent wildcard alias, got %d", c)
	}

	// F6: _rollover validation & conditions map
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/no_such_rollover_target/_rollover", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _rollover on missing alias, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_multi_no_write/_rollover", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for _rollover on multi-index alias without write index, got %d", c)
	}
	doRound48Req(t, handler, http.MethodPut, "/r51_ro_000001", `{}`)
	doRound48Req(t, handler, http.MethodPut, "/r51_ro_000001/_alias/r51_ro_alias", `{}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r51_ro_alias/_rollover", `{
		"conditions": {"max_docs": 100}
	}`)
	if code != http.StatusOK || resp["rolled_over"] != false {
		t.Fatalf("expected rolled_over=false when max_docs=100 not met on empty index, got %d %v", code, resp)
	}
	condMap, _ := resp["conditions"].(map[string]any)
	if condMap["[max_docs: 100]"] != false {
		t.Fatalf("expected conditions['[max_docs: 100]']==false, got %v", condMap)
	}

	// F7: _count, _explain, _validate/query validation
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_ro_000001/_count", `{"unknown_top_key": 1}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown top-level key in _count, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r51_ro_000001/_explain/missing_doc_id", `{"query": {"match_all": {}}}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 for _explain on non-existent document, got %d", c)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r51_ro_000001/_validate/query?explain=true", `{"query": {" bogus_clause ": {}}}`)
	if code != http.StatusOK || resp["valid"] != false {
		t.Fatalf("expected 200 valid=false for unknown query clause in _validate/query, got %d %v", code, resp)
	}

	// F8: _resolve/index state & _search_shards closed index check
	_, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_resolve/index/r51_ro_000001", "")
	if idxList, ok := resp["indices"].([]any); !ok || len(idxList) != 1 || idxList[0].(map[string]any)["state"] != "open" {
		t.Fatalf("expected state='open' in _resolve/index response, got %v", resp)
	}

	// F9: _scripts & _ingest/pipeline validation
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_scripts/bad_ctx/s1", `{"script": {"lang": "painless", "source": "1"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown script context, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_scripts/s_bad_lang", `{"script": {"lang": "python", "source": "1"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported script lang, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_ingest/pipeline/bad_pipe", `{"processors": [{"not_a_processor": {}}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown ingest processor, got %d", c)
	}

	// F15-proxy: Alias field cycle/missing/chained validation in handleCreateIndex & handlePutMapping
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r51_bad_alias_idx", `{
		"mappings": {"properties": {"a": {"type": "alias", "path": "missing_target"}}}
	}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 mapper_parsing_exception for alias targeting missing field, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r51_bad_alias_cycle", `{
		"mappings": {"properties": {
			"a": {"type": "alias", "path": "b"},
			"b": {"type": "alias", "path": "a"}
		}}
	}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 mapper_parsing_exception for alias cycle, got %d", c)
	}

	// F27 & F28: grok nested brackets, dissect --->, kv strip_brackets {}, convert int32/short/byte bounds & yes/no/on/off, join non-array error
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"grok": {"field": "line", "patterns": ["%{WORD:[http][request][method]} %{NUMBER:[http][response][status]:int}"]}},
				{"dissect": {"field": "dline", "pattern": "%{a--->}%{b}"}},
				{"kv": {"field": "kvline", "field_split": " ", "value_split": "=", "strip_brackets": true, "target_field": "kvout"}},
				{"convert": {"field": "flag_yes", "type": "boolean"}},
				{"convert": {"field": "flag_off", "type": "boolean"}},
				{"convert": {"field": "overflow_byte", "type": "byte", "on_failure": [{"set": {"field": "byte_overflow_caught", "value": true}}]}},
				{"join": {"field": "not_an_array", "separator": ",", "on_failure": [{"set": {"field": "join_error_caught", "value": true}}]}}
			]
		},
		"docs": [{
			"_source": {
				"line": "GET 200",
				"dline": "hello     world",
				"kvline": "(k1={v1}) [k2=<v2>]",
				"flag_yes": "yes",
				"flag_off": "off",
				"overflow_byte": "200",
				"not_an_array": "scalar_str"
			}
		}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("F27/F28 ingest simulate failed: %d %v", code, resp)
	}
	simSrc := resp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	httpMap, _ := simSrc["http"].(map[string]any)
	if reqMap, _ := httpMap["request"].(map[string]any); reqMap["method"] != "GET" {
		t.Fatalf("expected grok nested http.request.method='GET', got %v", simSrc["http"])
	}
	if simSrc["a"] != "hello" || simSrc["b"] != "world" {
		t.Fatalf("expected dissect multi-arrow a='hello' b='world', got a=%v b=%v", simSrc["a"], simSrc["b"])
	}
	if kvOut, _ := simSrc["kvout"].(map[string]any); kvOut["k1"] != "v1" || kvOut["k2"] != "v2" {
		t.Fatalf("expected kv strip_brackets k1=v1 k2=v2, got %v", simSrc["kvout"])
	}
	if simSrc["flag_yes"] != true || simSrc["flag_off"] != false {
		t.Fatalf("expected boolean convert yes->true, off->false, got yes=%v off=%v", simSrc["flag_yes"], simSrc["flag_off"])
	}
	if simSrc["byte_overflow_caught"] != true {
		t.Fatalf("expected byte overflow to trigger on_failure, got %v", simSrc)
	}
	if simSrc["join_error_caught"] != true {
		t.Fatalf("expected join on scalar to trigger on_failure, got %v", simSrc)
	}

	// F29: bucket_script & bucket_selector multi-metric map binding & painless _execute __raw_source cleanup
	doRound48Req(t, handler, http.MethodPut, "/r51_bs_idx", `{
		"mappings": {"properties": {"grp": {"type": "keyword"}, "val": {"type": "double"}}}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r51_bs_idx/_doc/1?refresh=true", `{"grp": "g1", "val": 10}`)
	doRound48Req(t, handler, http.MethodPut, "/r51_bs_idx/_doc/2?refresh=true", `{"grp": "g1", "val": 30}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r51_bs_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"st": {"stats": {"field": "val"}},
					"spread": {
						"bucket_script": {
							"buckets_path": {"s": "st"},
							"script": "params.s.max - params.s.min"
						}
					},
					"keep": {
						"bucket_selector": {
							"buckets_path": {"avg_val": "st.avg"},
							"script": "params['avg_val'] >= 15"
						}
					}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("F29 bucket_script search failed: %d %v", code, resp)
	}
	buckets := resp["aggregations"].(map[string]any)["by_grp"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 1 || buckets[0].(map[string]any)["spread"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected 1 bucket with spread=20, got %v", buckets)
	}

	// Additional branch coverage for extractBucketMetricMapByPath, bindNestedPainlessParam, ILM/DataStream/Alias validation
	params := map[string]any{}
	bindNestedPainlessParam(params, "a.b.c", 42.0)
	bindNestedPainlessParam(params, "a.b.d", 99.0)
	if params["a.b.c"] != 42.0 {
		t.Fatalf("expected flat a.b.c=42")
	}
	sampleBucket := map[string]any{
		"doc_count": 5,
		"pct_f":     map[string]any{"values": map[string]float64{"50.0": 12.5, "95.0": 40.0}},
		"pct_a":     map[string]any{"values": map[string]any{"50.0": 12.5, "95.0": 40.0}},
		"sm":        map[string]any{"value": map[string]any{"total": 100.0}},
		"scalar":    map[string]any{"value": 10.0},
		"empty_st":  map[string]any{"count": 0, "avg": nil},
		"by_key": map[string]any{
			"buckets": map[string]any{
				"k1": map[string]any{"st": map[string]any{"min": 1.0, "max": 9.0}},
			},
		},
		"by_slice": map[string]any{
			"buckets": []map[string]any{
				{"key": "s1", "st": map[string]any{"min": 2.0, "max": 8.0}},
			},
		},
	}
	if m, ok := extractBucketMetricMapByPath(sampleBucket, "pct_f"); !ok || m["95"] != 40.0 {
		t.Fatalf("expected pct_f map with 95=40, got %v %v", m, ok)
	}
	if m, ok := extractBucketMetricMapByPath(sampleBucket, "pct_a"); !ok || m["50"] != 12.5 {
		t.Fatalf("expected pct_a map with 50=12.5, got %v %v", m, ok)
	}
	if m, ok := extractBucketMetricMapByPath(sampleBucket, "sm"); !ok || m["total"] != 100.0 {
		t.Fatalf("expected sm map with total=100, got %v %v", m, ok)
	}
	if _, ok := extractBucketMetricMapByPath(sampleBucket, "scalar"); ok {
		t.Fatalf("expected scalar metric not to match extractBucketMetricMapByPath")
	}
	if _, ok := extractBucketMetricMapByPath(sampleBucket, "empty_st"); ok {
		t.Fatalf("expected empty_st not to match extractBucketMetricMapByPath")
	}
	if m, ok := extractBucketMetricMapByPath(sampleBucket, "by_key['k1']>st"); !ok || m["max"] != 9.0 {
		t.Fatalf("expected keyed bucket path match, got %v %v", m, ok)
	}
	if m, ok := extractBucketMetricMapByPath(sampleBucket, "by_slice['s1']>st"); !ok || m["max"] != 8.0 {
		t.Fatalf("expected slice bucket path match, got %v %v", m, ok)
	}

	// Alias mapping validation branches (missing path, cycle, relative path, object target)
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r51_alias_no_path", `{"mappings":{"properties":{"a":{"type":"alias"}}}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on alias with missing path, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r51_alias_cycle", `{"mappings":{"properties":{"a":{"type":"alias","path":"b"},"b":{"type":"alias","path":"a"}}}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on alias cycle, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r51_alias_obj", `{"mappings":{"properties":{"obj":{"type":"object","properties":{"x":{"type":"keyword"}}},"a":{"type":"alias","path":"obj"}}}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on alias targeting object, got %d", code)
	}
}

func TestRound52_ProxyAndIngestFeatures(t *testing.T) {
	srv, handler := newTestServerWithMock(t)

	// --- F2: Index Blocks API & Stateful Read/Write/Metadata Block Enforcement ---
	code, _, _ := doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx", `{}`)
	if code != http.StatusOK {
		t.Fatalf("create r52_blk_idx failed: %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_doc/1", `{"title":"doc1","count":10}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc failed: %d", code)
	}
	// Invalid block type -> 400
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_block/invalid_block", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid block, got %d", code)
	}
	// Missing index -> 404
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_missing_idx/_block/write", `{}`)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 on missing index block, got %d", code)
	}
	// Add write block
	code, resp, _ := doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_block/write", `{}`)
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("expected 200 on write block, got %d %v", code, resp)
	}
	// Write operations must return 403 cluster_block_exception
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPut, "/r52_blk_idx/_doc/2", `{"title":"doc2"}`},
		{http.MethodDelete, "/r52_blk_idx/_doc/1", ``},
		{http.MethodPost, "/r52_blk_idx/_update/1", `{"doc":{"count":20}}`},
		{http.MethodPost, "/r52_blk_idx/_update_by_query", `{"query":{"match_all":{}}}`},
		{http.MethodPost, "/r52_blk_idx/_delete_by_query", `{"query":{"match_all":{}}}`},
	} {
		c, rMap, _ := doRound48Req(t, handler, tc.method, tc.path, tc.body)
		if c != http.StatusForbidden {
			t.Fatalf("expected 403 on %s %s under write block, got %d (%v)", tc.method, tc.path, c, rMap)
		}
	}
	// Bulk write to write-blocked index returns per-item 403
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_bulk", "{\"index\":{\"_index\":\"r52_blk_idx\",\"_id\":\"2\"}}\n{\"title\":\"b\"}\n")
	if code != http.StatusOK || resp["errors"] != true {
		t.Fatalf("expected bulk errors=true on write-blocked index, got %d %v", code, resp)
	}
	// Unblock write via _settings
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_settings", `{"index":{"blocks":{"write":false}}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 unblocking write, got %d", code)
	}
	// Add read block
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_block/read", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on read block, got %d", code)
	}
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/r52_blk_idx/_doc/1", ``},
		{http.MethodHead, "/r52_blk_idx/_doc/1", ``},
		{http.MethodGet, "/r52_blk_idx/_source/1", ``},
		{http.MethodPost, "/r52_blk_idx/_search", `{}`},
		{http.MethodPost, "/r52_blk_idx/_count", `{}`},
		{http.MethodPost, "/r52_blk_idx/_explain/1", `{"query":{"match_all":{}}}`},
	} {
		c, _, _ := doRound48Req(t, handler, tc.method, tc.path, tc.body)
		if c != http.StatusForbidden {
			t.Fatalf("expected 403 on %s %s under read block, got %d", tc.method, tc.path, c)
		}
	}
	// Unblock read, add metadata block
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_settings", `{"index":{"blocks":{"read":false}}}`)
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_block/metadata", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on metadata block, got %d", code)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_mapping", `{"properties":{"extra":{"type":"keyword"}}}`); c != http.StatusForbidden {
		t.Fatalf("expected 403 on _mapping under metadata block, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_alias/r52_al", `{}`); c != http.StatusForbidden {
		t.Fatalf("expected 403 on _alias under metadata block, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/r52_blk_idx", ``); c != http.StatusForbidden {
		t.Fatalf("expected 403 on DELETE index under metadata block, got %d", c)
	}
	// Unblock metadata, test read_only_allow_delete allows DELETE index
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_settings", `{"index":{"blocks":{"metadata":false}}}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_blk_idx/_block/read_only_allow_delete", `{}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/r52_blk_idx", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE index under read_only_allow_delete, got %d", c)
	}

	// --- F3: Data Stream Lifecycle (_modify, _promote, name validation, op_type=create) & _downgrade ---
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_data_stream/.invalid_ds", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on hidden data stream name, got %d", c)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_data_stream/r52_ds", `{}`)
	if code != http.StatusOK {
		t.Fatalf("create data stream r52_ds failed: %d", code)
	}
	// PUT /{ds}/_doc/{id} without op_type=create must fail with 400
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r52_ds/_doc/1", `{"@timestamp":"2026-01-01T00:00:00Z"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on PUT /{ds}/_doc/{id} without op_type=create, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/r52_ds/_create/1", `{"@timestamp":"2026-01-01T00:00:00Z"}`); c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("expected 201 on PUT /{ds}/_create/{id}, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_extra_backing", `{}`)
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"add_backing_index":{"data_stream":"r52_ds","index":"r52_extra_backing"}}]}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _data_stream/_modify add_backing_index, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_data_stream/_modify", `{"actions":[{"remove_backing_index":{"data_stream":"r52_ds","index":"r52_extra_backing"}}]}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _data_stream/_modify remove_backing_index, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_data_stream/_promote/r52_ds", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _data_stream/_promote/r52_ds, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/r52_extra_backing/_downgrade", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _downgrade, got %d", code)
	}

	// --- F4: Snapshot Lifecycle Management (/_slm/*) ---
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/r52_repo", `{"type":"fs"}`)
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_slm/policy/daily-snapshots", `{"schedule":"0 30 1 * * ?","name":"<daily-snap-{now/d}>","repository":"r52_repo"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_slm/policy, got %d", code)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_slm/policy/daily-snapshots/_execute", `{}`)
	if code != http.StatusOK || resp["snapshot_name"] == "" {
		t.Fatalf("expected 200 on POST /_slm/policy/_execute, got %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_slm/policy/daily-snapshots", ``)
	if code != http.StatusOK || resp["daily-snapshots"] == nil {
		t.Fatalf("expected 200 on GET /_slm/policy/daily-snapshots, got %d %v", code, resp)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_slm/_execute_retention", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _slm/_execute_retention, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_slm/stop", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _slm/stop, got %d", code)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_slm/status", ``)
	if code != http.StatusOK || resp["operation_mode"] != "STOPPED" {
		t.Fatalf("expected STOPPED on _slm/status, got %d %v", code, resp)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_slm/start", `{}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_slm/stats", ``)
	if code != http.StatusOK || resp["total_snapshots_taken"] != float64(1) {
		t.Fatalf("expected total_snapshots_taken=1 on _slm/stats, got %d %v", code, resp)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_slm/policy/daily-snapshots", ``)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_slm/policy, got %d", code)
	}

	// --- F5 & F29: Enrich Policy Validation, Immutability, Snapshot & Exact Match ---
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_enrich_src", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_enrich_src/_doc/1", `{"code":"US-EAST-1","region_name":"N. Virginia"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_enrich_src/_doc/2", `{"code":"US-EAST-1-EXTRA","region_name":"Extra"}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_enrich/policy/r52_pol", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty enrich policy, got %d", c)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_enrich/policy/r52_pol", `{"match":{"indices":"r52_enrich_src","match_field":"code","enrich_fields":["region_name"]}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_enrich/policy/r52_pol, got %d", code)
	}
	// Immutability check -> 400
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_enrich/policy/r52_pol", `{"match":{"indices":"r52_enrich_src","match_field":"code","enrich_fields":["region_name"]}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on duplicate PUT /_enrich/policy/r52_pol, got %d", c)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_enrich/policy/r52_pol/_execute", `{}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _enrich/policy/r52_pol/_execute, got %d", code)
	}
	// Invalid max_matches -> 400
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{"pipeline":{"processors":[{"enrich":{"policy_name":"r52_pol","field":"code","target_field":"enriched","max_matches":200}}]},"docs":[{"_source":{"code":"US-EAST-1"}}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on enrich max_matches=200, got %d", c)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{"pipeline":{"processors":[{"enrich":{"policy_name":"r52_pol","field":"code","target_field":"enriched"}}]},"docs":[{"_source":{"code":"US-EAST-1"}}]}`)
	if code != http.StatusOK {
		t.Fatalf("enrich simulate failed: %d %v", code, resp)
	}
	simDoc := resp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	enrichedMap, _ := simDoc["enriched"].(map[string]any)
	if enrichedMap == nil || enrichedMap["region_name"] != "N. Virginia" {
		t.Fatalf("expected exact enrich match region_name='N. Virginia', got %v", simDoc)
	}

	// --- F6: Ingest Metadata Endpoints ---
	if c, rMap, _ := doRound48Req(t, handler, http.MethodGet, "/_ingest/processor/grok", ``); c != http.StatusOK || rMap["patterns"] == nil {
		t.Fatalf("expected 200 on GET /_ingest/processor/grok, got %d %v", c, rMap)
	}
	if c, rMap, _ := doRound48Req(t, handler, http.MethodGet, "/_ingest/geoip/stats", ``); c != http.StatusOK || rMap["stats"] == nil {
		t.Fatalf("expected 200 on GET /_ingest/geoip/stats, got %d %v", c, rMap)
	}

	// --- F7: Watcher, Transform, Dangling Indices, Autoscaling ---
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_watcher/watch/w1", `{"trigger":{"schedule":{"interval":"10m"}},"input":{"simple":{}},"actions":{"log":{"logging":{"text":"hi"}}}}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("expected 201/200 on PUT /_watcher/watch/w1, got %d", code)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_watcher/watch/w1/_execute", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _watcher/watch/w1/_execute, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_watcher/watch/w1/_ack/log", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _watcher/watch/w1/_ack/log, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_watcher/watch/w1/_deactivate", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _watcher/watch/w1/_deactivate, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_watcher/watch/w1/_activate", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _watcher/watch/w1/_activate, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on _watcher/stats, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_watcher/watch/w1", ``)

	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_transform/t1", `{"source":{"index":["r52_enrich_src"]},"dest":{"index":"r52_tf_dest"},"pivot":{"group_by":{"code":{"terms":{"field":"code"}}},"aggregations":{"cnt":{"value_count":{"field":"code"}}}}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_transform/t1, got %d", code)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/t1/_start", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _transform/t1/_start, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_transform/t1/_stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on _transform/t1/_stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/t1/_stop", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _transform/t1/_stop, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/_preview", `{"source":{"index":["r52_enrich_src"]},"pivot":{"group_by":{"code":{"terms":{"field":"code"}}}}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _transform/_preview, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_transform/t1", ``)

	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_dangling", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_dangling, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_dangling/u1", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on DELETE /_dangling/u1 without accept_data_loss=true, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_autoscaling/policy/a1", `{"roles":["data_hot"],"deciders":{"fixed":{}}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_autoscaling/policy/a1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_autoscaling/capacity", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_autoscaling/capacity, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_autoscaling/policy/a1", ``)

	// --- F8: Closed Index Enforcement & _msearch Blank-Line / Missing-Body Validation ---
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_closed_idx", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_closed_idx/_doc/1", `{"x":1}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/r52_closed_idx/_close", `{}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r52_closed_idx/_doc/1", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception on GET /_doc of closed index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r52_closed_idx/_update_by_query", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception on _update_by_query of closed index, got %d", c)
	}
	// _msearch with trailing header and no body -> 400
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_msearch", "{\"index\":\"r52_enrich_src\"}\n"); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _msearch with header and no body line, got %d", c)
	}

	// --- F9: Mustache JSON String Escaping & Top-Level Search Options ---
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r52_enrich_src/_search/template", `{
		"source": "{\"query\":{\"match\":{\"code\":\"{{q}}\"}},\"explain\":\"{{exp}}\"}",
		"params": {"q": "US-\"EAST\"-1\nline2", "exp": true},
		"rest_total_hits_as_int": true
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _search/template with quotes/newlines in param, got %d %v", code, resp)
	}
	if _, isNum := resp["hits"].(map[string]any)["total"].(float64); !isNum {
		t.Fatalf("expected numeric hits.total when rest_total_hits_as_int=true on _search/template, got %T (%v)", resp["hits"].(map[string]any)["total"], resp["hits"])
	}

	// --- F26: Runtime Painless Invalid ctx.op -> 400 illegal_argument_exception ---
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r52_upd_idx/_doc/1", `{"v":1}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r52_upd_idx/_update/1", `{"script":{"source":"ctx.op = 'bogus'"}}`)
	if code != http.StatusBadRequest || resp["error"].(map[string]any)["type"] != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception on invalid ctx.op, got %d %v", code, resp)
	}

	// --- F27 & F28: Ingest date_index_name, user_agent, uri_parts, registered_domain ---
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"date_index_name": {"field": "ts", "index_name_prefix": "logs-", "date_rounding": "d", "index_name_format": "UNIX"}},
				{"user_agent": {"field": "ua"}},
				{"uri_parts": {"field": "uri"}},
				{"registered_domain": {"field": "fqdn"}}
			]
		},
		"docs": [{
			"_source": {
				"ts": 1704067200000,
				"ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
				"uri": "alice:secret@example.com:8080/home/.bashrc",
				"fqdn": "api.sub.example.co.jp."
			}
		}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("F27/F28 simulate failed: %d %v", code, resp)
	}
	simOut := resp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if simOut["_index"] != "logs-1704067200" {
		t.Fatalf("expected _index='logs-1704067200', got %v", simOut["_index"])
	}
	srcOut := simOut["_source"].(map[string]any)
	uaOut := srcOut["user_agent"].(map[string]any)["os"].(map[string]any)
	if uaOut["name"] != "iOS" || uaOut["version"] != "17.2" {
		t.Fatalf("expected iOS 17.2 from user_agent, got %v", uaOut)
	}
	uriOut := srcOut["url"].(map[string]any)
	if uriOut["username"] != "alice" || uriOut["domain"] != "example.com" || uriOut["extension"] != nil {
		t.Fatalf("expected schemeless user:pass@host and nil extension for /.bashrc, got %v", uriOut)
	}
	rdOut := srcOut["fqdn"].(map[string]any)
	if rdOut["registered_domain"] != "example.co.jp" || rdOut["top_level_domain"] != "co.jp" || rdOut["subdomain"] != "api.sub" {
		t.Fatalf("expected registered_domain='example.co.jp', got %v", rdOut)
	}

	// --- Additional F7 Watcher / Transform / Dangling / Autoscaling Edge Cases ---
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/stats/_all,queued_watches,current_watches,pending_watches", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_watcher/stats/{metrics}, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/stats/bad_metric", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on GET /_watcher/stats/bad_metric, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_watcher/stats", ``); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /_watcher/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_watcher/_stop", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_watcher/_stop, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/_stop", ``); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /_watcher/_stop, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_watcher/_start", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_watcher/_start, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/_start", ``); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /_watcher/_start, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_watcher/unknown_act", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_watcher/unknown_act, got %d", c)
	}

	// Transform validation & action branches
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_transform/t_bad", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty transform body, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_transform/t_bad", `{"dest":{"index":"d"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing transform source.index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_transform/t_bad", `{"source":{"index":"s"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing transform dest.index, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_transform/t_bad", `{"source":{"index":"s"},"dest":{"index":"d"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing transform pivot/latest, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_transform/t_cov", `{"source":{"index":"r52_enrich_src"},"dest":{"index":"r52_t_dest"},"latest":{"unique_key":["code"],"sort":"code"}}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_transform/t_cov", `{"source":{"index":"r52_enrich_src"},"dest":{"index":"r52_t_dest"},"latest":{"unique_key":["code"],"sort":"code"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 resource_already_exists_exception on duplicate transform, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_transform/_stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_transform/_stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/_preview", `{"source":{"index":"r52_enrich_src"},"latest":{"unique_key":["code"],"sort":"code"}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_transform/_preview, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/t_cov/_preview", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_transform/t_cov/_preview, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/missing_t/_preview", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 on POST /_transform/missing_t/_preview, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_transform/missing_t", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_transform/missing_t, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_transform/missing_t", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on HEAD /_transform/missing_t, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_transform/missing_*?allow_no_match=false", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_transform/missing_*?allow_no_match=false, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_transform/t_cov/_start", `{}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_transform/t_cov", ``); c != http.StatusConflict {
		t.Fatalf("expected 409 status_exception deleting started transform without force, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_transform/t_cov?force=true", ``); c != http.StatusOK {
		t.Fatalf("expected 200 deleting started transform with force=true, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_transform/t_cov", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 deleting non-existent transform, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/missing_t/_start", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 starting non-existent transform, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/missing_t/_stop", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 stopping non-existent transform, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/missing_t/_stop?allow_no_match=true", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 stopping non-existent transform with allow_no_match=true, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_transform/missing_t/_stats", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on stats for non-existent transform, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/t_cov/_bogus", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 on unknown transform action, got %d", c)
	}

	// Dangling indices import & delete
	srv.mu.Lock()
	if srv.danglingIndices == nil {
		srv.danglingIndices = make(map[string]map[string]any)
	}
	srv.danglingIndices["u_import"] = map[string]any{"index_name": "dangling_imp_idx", "index_uuid": "u_import"}
	srv.danglingIndices["u_del"] = map[string]any{"index_name": "dangling_del_idx", "index_uuid": "u_del"}
	srv.mu.Unlock()
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_dangling", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_dangling, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_dangling/u_import?accept_data_loss=true", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_dangling/u_import?accept_data_loss=true, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_dangling/u_del?accept_data_loss=true", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_dangling/u_del?accept_data_loss=true, got %d", c)
	}

	// Autoscaling validation & listing
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_autoscaling/policy/a_bad", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty autoscaling policy body, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_autoscaling/policy/a_bad", `{"roles":[]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty autoscaling roles, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_autoscaling/policy/a_bad", `{"roles":["data_hot"]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing autoscaling deciders, got %d", c)
	}
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_autoscaling/policy/a_cov", `{"roles":["data_hot"],"deciders":{}}`)
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_autoscaling/policy", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_autoscaling/policy, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_autoscaling/policy/missing_pol", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_autoscaling/policy/missing_pol, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_autoscaling/policy/missing_pol", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on HEAD /_autoscaling/policy/missing_pol, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_autoscaling/policy/missing_pol", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on DELETE /_autoscaling/policy/missing_pol, got %d", c)
	}
}

func TestRound53_ProxyAndIngestFeatures(t *testing.T) {
	srv, handler := newTestServerWithMock(t)

	// 1. F2: Synonyms Management API (/_synonyms & /_synonyms/{id}/*)
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_synonyms", `{}`); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /_synonyms, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty synonyms_set, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1", `{"synonyms_set":[{"synonyms":""}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty synonyms string, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1", `{"synonyms_set":[{"id":"r1","synonyms":"a, b"},{"id":"r1","synonyms":"c, d"}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on duplicate synonym rule id, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1", `{"synonyms_set":[{"id":"r1","synonyms":" laptop, notebook "},{"synonyms":"phone, mobile"}]}`); c != http.StatusOK || m["result"] != "created" {
		t.Fatalf("expected 200 created on PUT /_synonyms/syn1, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1", `{"synonyms_set":[{"id":"r1","synonyms":"laptop, notebook"},{"id":"r2","synonyms":"phone, mobile"}]}`); c != http.StatusOK || m["result"] != "updated" {
		t.Fatalf("expected 200 updated on PUT /_synonyms/syn1, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_synonyms?from=0&size=10", ``); c != http.StatusOK || m["count"] != float64(1) {
		t.Fatalf("expected count=1 on GET /_synonyms, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_synonyms", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on HEAD /_synonyms, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_synonyms/syn1?from=0&size=1", ``); c != http.StatusOK || m["count"] != float64(2) {
		t.Fatalf("expected count=2 on GET /_synonyms/syn1, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_synonyms/syn1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on HEAD /_synonyms/syn1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_synonyms/missing_syn", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_synonyms/missing_syn, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_synonyms/missing_syn", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on HEAD /_synonyms/missing_syn, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1/r3", `{"synonyms":"tv, television"}`); c != http.StatusOK || m["result"] != "created" {
		t.Fatalf("expected 200 created on PUT /_synonyms/syn1/r3, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_synonyms/syn1/r3", `{"synonyms":"tv, television, telly"}`); c != http.StatusOK || m["result"] != "updated" {
		t.Fatalf("expected 200 updated on PUT /_synonyms/syn1/r3, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_synonyms/syn1/r3", ``); c != http.StatusOK || m["id"] != "r3" {
		t.Fatalf("expected 200 on GET /_synonyms/syn1/r3, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodHead, "/_synonyms/syn1/r3", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on HEAD /_synonyms/syn1/r3, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_synonyms/syn1/missing_rule", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /_synonyms/syn1/missing_rule, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodDelete, "/_synonyms/syn1/r3", ``); c != http.StatusOK || m["result"] != "deleted" {
		t.Fatalf("expected 200 deleted on DELETE /_synonyms/syn1/r3, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_synonyms/syn1/_reload", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_synonyms/syn1/_reload, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_synonyms/missing_syn/_reload", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on POST /_synonyms/missing_syn/_reload, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_synonyms/syn1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_synonyms/syn1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_synonyms/syn1", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on second DELETE /_synonyms/syn1, got %d", c)
	}

	// 2. F3: Query Rules Management API (/_query_rules & /_query_rules/{ruleset_id}/*) + Search Rule Resolution
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1", `{"rules":[]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty ruleset, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1", `{"rules":[{"rule_id":"r1","type":"invalid"}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid rule type, got %d", c)
	}
	rsBody := `{
		"rules": [
			{
				"rule_id": "pin_rule",
				"type": "pinned",
				"criteria": [
					{"type": "contains", "metadata": "q", "values": ["pugs"]},
					{"type": "gte", "metadata": "tier", "values": [2]}
				],
				"actions": {"ids": ["doc-2"]}
			},
			{
				"rule_id": "excl_rule",
				"type": "exclude",
				"criteria": [
					{"type": "fuzzy", "metadata": "q", "values": ["pugs"]},
					{"type": "prefix", "metadata": "cat", "values": ["dog"]},
					{"type": "suffix", "metadata": "region", "values": ["us"]},
					{"type": "exact", "metadata": "env", "values": ["prod"]},
					{"type": "lt", "metadata": "age", "values": [10]},
					{"type": "lte", "metadata": "age", "values": [5]},
					{"type": "gt", "metadata": "score", "values": [1]},
					{"type": "always"}
				],
				"actions": {"docs": [{"_index": "qr_idx", "_id": "doc-1"}]}
			}
		]
	}`
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1", rsBody); c != http.StatusCreated || m["result"] != "created" {
		t.Fatalf("expected 201 created on PUT /_query_rules/rs1, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1", rsBody); c != http.StatusOK || m["result"] != "updated" {
		t.Fatalf("expected 200 updated on second PUT /_query_rules/rs1, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_query_rules", ``); c != http.StatusOK || m["count"] != float64(1) {
		t.Fatalf("expected count=1 on GET /_query_rules, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_query_rules/rs1", ``); c != http.StatusOK || m["ruleset_id"] != "rs1" {
		t.Fatalf("expected 200 on GET /_query_rules/rs1, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_query_rules/rs1/_test", `{"match_criteria":{"q":"cute pugs","tier":3,"cat":"dogs","region":"east-us","env":"prod","age":5,"score":2}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_query_rules/rs1/_test, got %d (%v)", c, m)
	} else if mr, _ := m["matched_rules"].([]any); len(mr) != 2 {
		t.Fatalf("expected 2 matched rules, got %v", m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1/_rule/r_extra", `{"type":"pinned","criteria":[{"type":"exact","metadata":"k","values":["v"]}],"actions":{"ids":["doc-3"]}}`); c != http.StatusCreated || m["result"] != "created" {
		t.Fatalf("expected 201 on PUT /_query_rules/rs1/_rule/r_extra, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs1/_rule/r_extra", `{"type":"pinned","criteria":[{"type":"exact","metadata":"k","values":["v2"]}],"actions":{"ids":["doc-3"]}}`); c != http.StatusOK || m["result"] != "updated" {
		t.Fatalf("expected 200 on update PUT /_query_rules/rs1/_rule/r_extra, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_query_rules/rs1/_rule/r_extra", ``); c != http.StatusOK || m["rule_id"] != "r_extra" {
		t.Fatalf("expected 200 on GET /_query_rules/rs1/_rule/r_extra, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodDelete, "/_query_rules/rs1/_rule/r_extra", ``); c != http.StatusOK || m["result"] != "deleted" {
		t.Fatalf("expected 200 on DELETE /_query_rules/rs1/_rule/r_extra, got %d (%v)", c, m)
	}
	// Test rewriteSearchBodyQueryRules
	rewritten := srv.rewriteSearchBodyQueryRules([]byte(`{"query":{"rule":{"organic":{"match_all":{}},"ruleset_ids":["rs1"],"match_criteria":{"q":"cute pugs","tier":3,"cat":"dogs","region":"east-us","env":"prod","age":5,"score":2}}}}`))
	if !strings.Contains(string(rewritten), `"pinned"`) || !strings.Contains(string(rewritten), `"must_not"`) {
		t.Fatalf("expected rewritten rule query to contain pinned and must_not, got %s", string(rewritten))
	}
	rewrittenRetr := srv.rewriteSearchBodyQueryRules([]byte(`{"retriever":{"rule":{"organic":{"match_all":{}},"ruleset_id":"rs1","match_criteria":{"q":"cute pugs","tier":3}}}}`))
	if !strings.Contains(string(rewrittenRetr), `"pinned"`) {
		t.Fatalf("expected rewritten retriever.rule to contain pinned, got %s", string(rewrittenRetr))
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_query_rules/rs1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_query_rules/rs1, got %d", c)
	}

	// 3. F4: Features API & Cluster Voting Config Exclusions
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_features", ``); c != http.StatusOK || len(m["features"].([]any)) < 8 {
		t.Fatalf("expected >=8 features on GET /_features, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_features/_reset", ``); c != http.StatusOK || len(m["features"].([]any)) < 8 {
		t.Fatalf("expected 200 on POST /_features/_reset, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_cluster/voting_config_exclusions", ``); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on POST /_cluster/voting_config_exclusions without params, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_cluster/voting_config_exclusions?node_names=node-a&node_ids=n1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_cluster/voting_config_exclusions, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_cluster/state", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_cluster/state, got %d", c)
	} else if cc, ok := m["cluster_coordination"].(map[string]any); !ok || len(cc["voting_config_exclusions"].([]any)) != 2 {
		t.Fatalf("expected 2 voting_config_exclusions in cluster state, got %v", m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_cluster/voting_config_exclusions", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_cluster/voting_config_exclusions, got %d", c)
	}

	// 4. F5: Migration Deprecations & Nodes Shutdown
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/r53_idx", `{}`)
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_migration/deprecations", ``); c != http.StatusOK || m["cluster_settings"] == nil {
		t.Fatalf("expected 200 on GET /_migration/deprecations, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r53_idx/_migration/deprecations", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /r53_idx/_migration/deprecations, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/nonexistent_r53/_migration/deprecations", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET /nonexistent_r53/_migration/deprecations, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_nodes/node-1/shutdown", `{"type":"invalid"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid shutdown type, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_nodes/node-1/shutdown", `{"type":"restart","reason":"upgrade"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_nodes/node-1/shutdown, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_nodes/shutdown", ``); c != http.StatusOK || len(m["nodes"].([]any)) != 1 {
		t.Fatalf("expected 1 node on GET /_nodes/shutdown, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_nodes/node-1/shutdown", ``); c != http.StatusOK || len(m["nodes"].([]any)) != 1 {
		t.Fatalf("expected 1 node on GET /_nodes/node-1/shutdown, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_nodes/node-1/shutdown", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_nodes/node-1/shutdown, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_nodes/node-1/shutdown", ``); c != http.StatusNotFound {
		t.Fatalf("expected 404 on second DELETE /_nodes/node-1/shutdown, got %d", c)
	}

	// 5. F6: Rollup API
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_rollup/job/rj1", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid rollup job, got %d", c)
	}
	rjBody := `{"index_pattern":"r53_*","rollup_index":"r53_rollup","cron":"0 * * * * ?","page_size":100,"groups":{"date_histogram":{"field":"@timestamp","fixed_interval":"1h"}}}`
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_rollup/job/rj1", rjBody); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_rollup/job/rj1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_rollup/job/rj1", rjBody); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on duplicate PUT /_rollup/job/rj1, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_rollup/job/rj1/_start", ``); c != http.StatusOK || m["started"] != true {
		t.Fatalf("expected started:true on POST /_rollup/job/rj1/_start, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_rollup/job/rj1/_stop", ``); c != http.StatusOK || m["stopped"] != true {
		t.Fatalf("expected stopped:true on POST /_rollup/job/rj1/_stop, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_rollup/job/rj1", ``); c != http.StatusOK || len(m["jobs"].([]any)) != 1 {
		t.Fatalf("expected 1 job on GET /_rollup/job/rj1, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_rollup/data/rj1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_rollup/data/rj1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/r53_idx/_rollup/data", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /r53_idx/_rollup/data, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r53_idx/_rollup_search", `{"from":10}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _rollup_search with from>0, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/r53_idx/_rollup_search", `{"size":0}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _rollup_search with size:0, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_rollup/job/rj1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_rollup/job/rj1, got %d", c)
	}

	// 6. F7 & F9: Snapshots (_mount, wildcard DELETE, multi-repo _status), Searchable Snapshots, CCR, Transform _update
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/repo_a", `{"type":"fs"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/repo_b", `{"type":"fs"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/repo_a/snap_1", `{"indices":"r53_idx"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/repo_a/snap_2", `{"indices":"r53_idx"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_snapshot/repo_b/snap_b1", `{"indices":"r53_idx"}`)
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_snapshot/_all/_status", ``); c != http.StatusOK || len(m["snapshots"].([]any)) != 3 {
		t.Fatalf("expected 3 snapshots on GET /_snapshot/_all/_status, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodGet, "/_snapshot/repo_*/snap_*/_status", ``); c != http.StatusOK || len(m["snapshots"].([]any)) != 3 {
		t.Fatalf("expected 3 snapshots on GET /_snapshot/repo_*/snap_*/_status, got %d (%v)", c, m)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_snapshot/repo_a/snap_1/_mount", `{"index":"r53_idx","renamed_index":"mounted_r53"}`); c != http.StatusOK || m["accepted"] != true {
		t.Fatalf("expected 200 accepted on _mount, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_searchable_snapshots/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_searchable_snapshots/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/mounted_r53/_searchable_snapshots/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /mounted_r53/_searchable_snapshots/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_searchable_snapshots/cache/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_searchable_snapshots/cache/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_searchable_snapshots/cache/clear", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_searchable_snapshots/cache/clear, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_snapshot/repo_a/snap_*", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on wildcard DELETE /_snapshot/repo_a/snap_*, got %d", c)
	}
	// CCR
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_ccr/auto_follow/af1", `{"remote_cluster":"rc1","leader_index_patterns":["leader_*"]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_ccr/auto_follow/af1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_ccr/auto_follow/af1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_ccr/auto_follow/af1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_ccr/auto_follow", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_ccr/auto_follow, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_ccr/auto_follow/af1/_pause", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_ccr/auto_follow/af1/_pause, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_ccr/auto_follow/af1/_resume", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_ccr/auto_follow/af1/_resume, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_ccr/auto_follow/af1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_ccr/auto_follow/af1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_ccr/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_ccr/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/follower_idx/_ccr/follow", `{"remote_cluster":"rc1","leader_index":"leader_idx"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /follower_idx/_ccr/follow, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/follower_idx/_ccr/info", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /follower_idx/_ccr/info, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/follower_idx/_ccr/stats", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /follower_idx/_ccr/stats, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/follower_idx/_ccr/pause_follow", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /follower_idx/_ccr/pause_follow, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/follower_idx/_ccr/resume_follow", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /follower_idx/_ccr/resume_follow, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/follower_idx/_ccr/unfollow", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /follower_idx/_ccr/unfollow, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/leader_idx/_ccr/forget_follower", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /leader_idx/_ccr/forget_follower, got %d", c)
	}
	// Transform _update
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_transform/tf_r53", `{"source":{"index":["r53_idx"]},"dest":{"index":"r53_tf_dest"},"pivot":{"group_by":{},"aggregations":{}}}`)
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/tf_r53/_update", `{"description":"updated desc","frequency":"5m"}`); c != http.StatusOK || m["description"] != "updated desc" {
		t.Fatalf("expected 200 on POST /_transform/tf_r53/_update, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_transform/tf_r53/_update", `{"pivot":{}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 updating immutable transform pivot, got %d", c)
	}

	// 7. F8: Security Management API & Logstash Pipeline API
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_security/user/alice", `{"password":"secret","roles":["admin"]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/user/alice, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/user/alice", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/user/alice, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/user", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/user, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_security/user/alice/_disable", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/user/alice/_disable, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_security/user/alice/_enable", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/user/alice/_enable, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_security/user/alice/_password", `{"password":"newsecret"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_security/user/alice/_password, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_security/user/_has_privileges", `{"cluster":["monitor"],"index":[{"names":["r53_idx"],"privileges":["read"]}]}`); c != http.StatusOK || m["has_all_requested"] != true {
		t.Fatalf("expected 200 on _has_privileges, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/user/alice", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_security/user/alice, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_security/role/analyst", `{"cluster":["monitor"],"indices":[{"names":["*"],"privileges":["read"]}]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/role/analyst, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/role/analyst", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/role/analyst, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/role", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/role, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_security/role/analyst/_clear_cache", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_security/role/analyst/_clear_cache, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/role/analyst", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_security/role/analyst, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/privilege/_builtin", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/privilege/_builtin, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_security/privilege", `{"myapp":{"read":{"actions":["data:read/*"]}}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/privilege, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/privilege/myapp/read", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/privilege/myapp/read, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/privilege/myapp/read", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_security/privilege/myapp/read, got %d", c)
	}
	if c, m, _ := doRound48Req(t, handler, http.MethodPost, "/_security/api_key", `{"name":"my-key"}`); c != http.StatusOK || m["id"] == nil {
		t.Fatalf("expected 200 on POST /_security/api_key, got %d (%v)", c, m)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/api_key?name=my-key", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/api_key, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_security/_query/api_key", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_security/_query/api_key, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/api_key", `{"name":"my-key"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_security/api_key, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"client_credentials"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on POST /_security/oauth2/token, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/oauth2/token", `{"token":"doris-oauth2-access-token"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_security/oauth2/token, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/service", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_security/service, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodPost, "/_security/service/elastic/kibana/credential/token/t1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on POST service token, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_security/service/elastic/kibana/credential/token", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET service tokens, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_security/service/elastic/kibana/credential/token/t1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE service token, got %d", c)
	}
	// Logstash
	if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_logstash/pipeline/ls1", `{"pipeline":"input { beats { port => 5044 } }","description":"beats pipeline"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_logstash/pipeline/ls1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_logstash/pipeline/ls1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_logstash/pipeline/ls1, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodGet, "/_logstash/pipeline", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_logstash/pipeline, got %d", c)
	}
	if c, _, _ := doRound48Req(t, handler, http.MethodDelete, "/_logstash/pipeline/ls1", ``); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /_logstash/pipeline/ls1, got %d", c)
	}

	// 8. F26–F29: Ingest processor validation, ctx map methods, date, fingerprint, attachment, user_agent, kv
	for _, badPipe := range []string{
		`{}`,
		`{"processors":"not_a_list"}`,
		`{"processors":["not_a_map"]}`,
		`{"processors":[{"tag":"only_tag"}]}`,
		`{"processors":[{"set":{"field":"a","value":1},"lowercase":{"field":"a"}}]}`,
		`{"processors":[{"unknown_proc_r53":{}}]}`,
		`{"processors":[{"set":null}]}`,
		`{"processors":[{"set":{"value":1}}]}`,
		`{"processors":[{"set":{"field":"a"}}]}`,
		`{"processors":[{"default":{}}]}`,
		`{"processors":[{"default":{"field":"a"}}]}`,
		`{"processors":[{"append":{"field":"a"}}]}`,
		`{"processors":[{"remove":{}}]}`,
		`{"processors":[{"remove":{"field":""}}]}`,
		`{"processors":[{"remove":{"field":[]}}]}`,
		`{"processors":[{"remove":{"field":[""]}}]}`,
		`{"processors":[{"remove":{"field":123}}]}`,
		`{"processors":[{"remove":{"keep":[]}}]}`,
		`{"processors":[{"rename":{}}]}`,
		`{"processors":[{"rename":{"field":"a"}}]}`,
		`{"processors":[{"rename":{"field":"a","target_field":"a"}}]}`,
		`{"processors":[{"copy":{"field":"a","target_field":"a"}}]}`,
		`{"processors":[{"lowercase":{}}]}`,
		`{"processors":[{"split":{}}]}`,
		`{"processors":[{"split":{"field":"a"}}]}`,
		`{"processors":[{"join":{}}]}`,
		`{"processors":[{"join":{"field":"a"}}]}`,
		`{"processors":[{"convert":{}}]}`,
		`{"processors":[{"convert":{"field":"a"}}]}`,
		`{"processors":[{"convert":{"field":"a","type":"bogus"}}]}`,
		`{"processors":[{"gsub":{}}]}`,
		`{"processors":[{"gsub":{"field":"a"}}]}`,
		`{"processors":[{"gsub":{"field":"a","pattern":"b"}}]}`,
		`{"processors":[{"gsub":{"field":"a","pattern":"[unclosed","replacement":"x"}}]}`,
		`{"processors":[{"kv":{}}]}`,
		`{"processors":[{"kv":{"field":"a"}}]}`,
		`{"processors":[{"kv":{"field":"a","field_split":"&"}}]}`,
		`{"processors":[{"kv":{"field":"a","field_split":"[unclosed","value_split":"="}}]}`,
		`{"processors":[{"kv":{"field":"a","field_split":"&","value_split":"[unclosed"}}]}`,
		`{"processors":[{"csv":{}}]}`,
		`{"processors":[{"csv":{"field":"a"}}]}`,
		`{"processors":[{"csv":{"field":"a","target_fields":["c1"],"separator":"::"}}]}`,
		`{"processors":[{"csv":{"field":"a","target_fields":["c1"],"quote":"''"}}]}`,
		`{"processors":[{"date":{}}]}`,
		`{"processors":[{"date":{"field":"a"}}]}`,
		`{"processors":[{"date":{"field":"a","formats":["ISO8601"],"timezone":"Invalid/Zone"}}]}`,
		`{"processors":[{"date_index_name":{}}]}`,
		`{"processors":[{"date_index_name":{"field":"a"}}]}`,
		`{"processors":[{"date_index_name":{"field":"a","date_rounding":"bogus"}}]}`,
		`{"processors":[{"date_index_name":{"field":"a","date_rounding":"d","timezone":"Invalid/Zone"}}]}`,
		`{"processors":[{"dissect":{}}]}`,
		`{"processors":[{"dissect":{"field":"a"}}]}`,
		`{"processors":[{"grok":{}}]}`,
		`{"processors":[{"grok":{"field":"a"}}]}`,
		`{"processors":[{"grok":{"field":"a","patterns":[""]}}]}`,
		`{"processors":[{"grok":{"field":"a","patterns":["%{NONEXISTENT_GROK_PAT_R53:x}"]}}]}`,
		`{"processors":[{"fingerprint":{"fields":["a"],"exclude_fields":["b"]}}]}`,
		`{"processors":[{"fingerprint":{"method":"BOGUS"}}]}`,
		`{"processors":[{"fail":{}}]}`,
		`{"processors":[{"pipeline":{}}]}`,
		`{"processors":[{"script":{}}]}`,
		`{"processors":[{"enrich":{}}]}`,
		`{"processors":[{"enrich":{"policy_name":"p"}}]}`,
		`{"processors":[{"enrich":{"policy_name":"p","field":"f"}}]}`,
		`{"processors":[{"enrich":{"policy_name":"p","field":"f","target_field":"t","max_matches":200}}]}`,
		`{"processors":[{"foreach":{}}]}`,
		`{"processors":[{"foreach":{"field":"a"}}]}`,
		`{"processors":[{"foreach":{"field":"a","processor":{"set":null}}}]}`,
		`{"processors":[{"foreach":{"field":"a","processors":[{"set":null}]}}]}`,
		`{"processors":[{"inference":{}}]}`,
		`{"processors":[{"set":{"field":"a","value":1,"on_failure":"not_a_list"}}]}`,
		`{"processors":[{"set":{"field":"a","value":1},"on_failure":"not_a_list"}]}`,
		`{"processors":[{"set":{"field":"a","value":1}}],"on_failure":"not_a_list"}`,
	} {
		if c, _, _ := doRound48Req(t, handler, http.MethodPut, "/_ingest/pipeline/bad_pipe", badPipe); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on invalid pipeline %s, got %d", badPipe, c)
		}
	}

	// Additional error/method branches on Round 53 endpoints
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_query_rules", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_query_rules", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_query_rules/nonexistent_rs", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_query_rules/nonexistent_rs", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_query_rules/nonexistent_rs", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_query_rules/nonexistent_rs/_test", `{"match_criteria":{"q":"a"}}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_query_rules/nonexistent_rs/_test", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs_err", `{"rules":[{"rule_id":"r1","type":"pinned","criteria":[{"type":"exact"}],"actions":{"ids":["1"]}}]}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs_err", `{"rules":[{"rule_id":"r1","type":"pinned","criteria":[{"type":"exact","metadata":"q"}],"actions":{"ids":["1"]}}]}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_query_rules/rs_err", `{"rules":[{"rule_id":"r1","type":"pinned","criteria":[{"type":"always"}],"actions":{}}]}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_features", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_features/_reset", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_features/unknown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_cluster/voting_config_exclusions", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_cluster/voting_config_exclusions", `{"node_ids":"n1","node_names":"nm1"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_migration/deprecations", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_migration/deprecations", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_nodes/missing_node/shutdown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_rollup/job/missing_rj/_start", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_rollup/data/_all", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_rollup/data/nonexistent_rj", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/_authenticate", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/user/elastic", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/user/missing_u", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/role/missing_r", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/privilege", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/privilege/missing_app", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/_clear_api_key_cache", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/service/elastic/kibana", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_logstash/pipeline", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_logstash/pipeline/missing_ls", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_logstash/pipeline/missing_ls", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_logstash/pipeline/missing_ls", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_logstash/pipeline/ls_w", `{"pipeline":"input {}"}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_logstash/pipeline/ls_*", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_logstash/pipeline", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_logstash/pipeline/ls_empty", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPatch, "/_logstash/pipeline", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_logstash/unknown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_rollup/job/missing_rj", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodHead, "/_rollup/job/missing_rj", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_rollup/job/missing_rj", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_rollup/job/missing_rj?allow_no_match=true", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/r53_idx/_rollup_search?from=5", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/r53_idx/_rollup_search", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_searchable_snapshots/unknown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_searchable_snapshots/cache/clear", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_searchable_snapshots/cache/stats", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_searchable_snapshots/stats", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/follower_err/_ccr/follow", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/missing_f/_ccr/info", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/missing_f/_ccr/stats", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/missing_f/_ccr/pause_follow", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/missing_f/_ccr/resume_follow", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/missing_f/_ccr/unfollow", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/missing_f/_ccr/unknown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_ccr/auto_follow/af_err", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_ccr/auto_follow/missing_af", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_ccr/auto_follow/missing_af", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_ccr/auto_follow/missing_af/_pause", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_ccr/unknown", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_security/user/no_roles", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/user/missing_u/_enable", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/user/elastic/_password", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPut, "/_security/role/empty_role", ``)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/api_key/_grant", `{"api_key":{"name":"granted-key"}}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/api_key", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodDelete, "/_security/api_key", `{"ids":["key-1"]}`)
	_, _, _ = doRound48Req(t, handler, http.MethodPost, "/_security/oauth2/token", `{}`)
	_, _, _ = doRound48Req(t, handler, http.MethodGet, "/_security/unknown", ``)

	simBody := `{
		"pipeline": {
			"processors": [
				{"date": {"field": "num_epoch", "formats": ["epoch_millis"], "target_field": "ts_epoch"}},
				{"date": {"field": "str_date", "formats": ["uuuu-MM-dd'T'HH:mm:ss,SSSZ"], "target_field": "ts_uuuu"}},
				{"fingerprint": {"fields": ["msg"], "method": "Murmur3@2.0", "target_field": "fp_murmur"}},
				{"fingerprint": {"fields": ["msg"], "method": "SHA-256@2.0", "target_field": "fp_sha256"}},
				{"attachment": {"field": "b64", "indexed_chars_field": "max_chars", "properties": ["content", "content_length"]}},
				{"user_agent": {"field": "ua", "properties": ["name", "major", "minor", "os"]}},
				{"kv": {"field": "kv_raw", "field_split": " ", "value_split": "=", "strip_brackets": true}},
				{"script": {"source": "ctx.replace('msg', 'updated_msg')"}}
			]
		},
		"docs": [
			{
				"_source": {
					"num_epoch": 1704067200000,
					"str_date": "2026-01-02T03:04:05,678+0000",
					"msg": "hello world",
					"b64": "aGVsbG8gd29ybGQ=",
					"max_chars": 5,
					"ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.1.2",
					"kv_raw": "[k1]=\"val\\\"1\" (k2)=[val2]"
				}
			}
		]
	}`
	if c, m, raw := doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", simBody); c != http.StatusOK {
		t.Fatalf("expected 200 on _simulate, got %d: %s", c, raw)
	} else {
		docs, _ := m["docs"].([]any)
		doc0, _ := docs[0].(map[string]any)["doc"].(map[string]any)
		src, _ := doc0["_source"].(map[string]any)
		if src["ts_epoch"] != "2024-01-01T00:00:00Z" {
			t.Fatalf("expected ts_epoch 2024-01-01T00:00:00Z, got %v", src["ts_epoch"])
		}
		if src["fp_murmur"] == nil || len(fmt.Sprintf("%v", src["fp_murmur"])) != 32 {
			t.Fatalf("expected 32-char murmur3 hex digest, got %v", src["fp_murmur"])
		}
		if src["k1"] != `val"1` || src["k2"] != "val2" {
			t.Fatalf("unexpected kv output: k1=%v k2=%v", src["k1"], src["k2"])
		}
		att, _ := src["attachment"].(map[string]any)
		if att["content"] != "hello" || att["content_type"] != nil {
			t.Fatalf("expected truncated attachment content='hello' and filtered content_type=nil, got %v", att)
		}
		ua, _ := src["user_agent"].(map[string]any)
		if ua["name"] != "Chrome" || ua["major"] != "120" || ua["minor"] != "1" || ua["original"] != nil {
			t.Fatalf("unexpected user_agent output: %v", ua)
		}
	}
}
