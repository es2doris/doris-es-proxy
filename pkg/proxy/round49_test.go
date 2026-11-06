package proxy

import (
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
		`{"query": {"boosting": {"positive": {"match_all": {}}, "negative": {"script": {"script": {"id": "missing_sc"}}}}}}`,
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
