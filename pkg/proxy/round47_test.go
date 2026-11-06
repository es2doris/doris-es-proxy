package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound47Raw(t *testing.T, srv *Server, method, path, body string) (int, string, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, raw, parsed
}

func TestRound47RootRoutesTemplatesILMAndAliases(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F16: Root routes /_settings, /_forcemerge, /_cat, /_resolve/index
	doRound47Raw(t, srv, http.MethodPut, "/idx_r47_a", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`)
	code, _, settingsRes := doRound47Raw(t, srv, http.MethodGet, "/_settings", "")
	if code != http.StatusOK || settingsRes["idx_r47_a"] == nil {
		t.Fatalf("F16 expected 200 on GET /_settings with idx_r47_a, got %d: %+v", code, settingsRes)
	}
	code, _, putSetRes := doRound47Raw(t, srv, http.MethodPut, "/_settings", `{"index":{"number_of_replicas":0}}`)
	if code != http.StatusOK || putSetRes["acknowledged"] != true {
		t.Fatalf("F16 expected 200 acknowledged=true on PUT /_settings, got %d: %+v", code, putSetRes)
	}
	code, _, fmRes := doRound47Raw(t, srv, http.MethodPost, "/_forcemerge", "")
	if code != http.StatusOK || fmRes["_shards"] == nil {
		t.Fatalf("F16 expected 200 on POST /_forcemerge, got %d: %+v", code, fmRes)
	}
	code, rawCat, _ := doRound47Raw(t, srv, http.MethodGet, "/_cat", "")
	if code != http.StatusOK || !strings.Contains(rawCat, "/_cat/indices") {
		t.Fatalf("F16 expected 200 banner on GET /_cat, got %d: %s", code, rawCat)
	}
	code, _, resIdx := doRound47Raw(t, srv, http.MethodGet, "/_resolve/index", "")
	if code != http.StatusOK || resIdx["indices"] == nil {
		t.Fatalf("F16 expected 200 on GET /_resolve/index, got %d: %+v", code, resIdx)
	}

	// F17: ILM policy & index templates 404/400/wildcard semantics
	code, _, _ = doRound47Raw(t, srv, http.MethodGet, "/_ilm/policy/nonexistent_policy", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on GET missing ILM policy, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodDelete, "/_ilm/policy/nonexistent_policy", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on DELETE missing ILM policy, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPut, "/_ilm/policy/pol_a", `{"policy":{"phases":{"hot":{"actions":{}}}}}`)
	if code != http.StatusOK {
		t.Fatalf("F17 expected 200 on PUT ILM policy pol_a, got %d", code)
	}
	code, _, polWild := doRound47Raw(t, srv, http.MethodGet, "/_ilm/policy/pol_*", "")
	if code != http.StatusOK || polWild["pol_a"] == nil {
		t.Fatalf("F17 expected 200 on GET /_ilm/policy/pol_*, got %d: %+v", code, polWild)
	}

	// Index templates (_template & _index_template)
	code, _, _ = doRound47Raw(t, srv, http.MethodGet, "/_template/missing_tpl", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on GET missing legacy template, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodHead, "/_template/missing_tpl", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on HEAD missing legacy template, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodGet, "/_index_template/missing_v2_tpl", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on GET missing composable template, got %d", code)
	}
	doRound47Raw(t, srv, http.MethodPut, "/_index_template/tpl_r47_1", `{"index_patterns":["r47-1-*"],"template":{}}`)
	doRound47Raw(t, srv, http.MethodPut, "/_index_template/tpl_r47_2", `{"index_patterns":["r47-2-*"],"template":{}}`)
	code, _, tplGet := doRound47Raw(t, srv, http.MethodGet, "/_index_template/tpl_r47_*,-tpl_r47_2", "")
	if code != http.StatusOK {
		t.Fatalf("F17 expected 200 on wildcard+exclusion GET /_index_template, got %d: %+v", code, tplGet)
	}
	tplArr, _ := tplGet["index_templates"].([]any)
	if len(tplArr) != 1 {
		t.Fatalf("F17 expected 1 template after exclusion, got %+v", tplArr)
	}

	// F19: _aliases validation, multi-write-index guard, and remove non-existent alias 404
	doRound47Raw(t, srv, http.MethodPut, "/idx_r47_b", `{}`)
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{" bogus_op ":{"index":"idx_r47_a","alias":"a1"}}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F19 expected 400 on unknown action in _aliases, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"idx_r47_a"}}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F19 expected 400 on missing alias in _aliases add, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"indices":["idx_r47_a","idx_r47_b"],"alias":"shared_w","is_write_index":true}}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F19 expected 400 when marking multiple indices as is_write_index=true in one action, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"remove":{"index":"idx_r47_a","alias":"nonexistent_alias"}}]}`)
	if code != http.StatusNotFound {
		t.Fatalf("F19 expected 404 when removing non-existent concrete alias, got %d", code)
	}
	// Promoting a second index to is_write_index=true clears the previous write index
	doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"idx_r47_a","alias":"flip_w","is_write_index":true}},{"add":{"index":"idx_r47_b","alias":"flip_w","is_write_index":false}}]}`)
	doRound47Raw(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"idx_r47_b","alias":"flip_w","is_write_index":true}}]}`)
	code, _, aliasRes := doRound47Raw(t, srv, http.MethodGet, "/_alias/flip_w", "")
	if code != http.StatusOK {
		t.Fatalf("F19 expected 200 on GET /_alias/flip_w, got %d", code)
	}
	aMeta, _ := aliasRes["idx_r47_a"].(map[string]any)["aliases"].(map[string]any)["flip_w"].(map[string]any)
	bMeta, _ := aliasRes["idx_r47_b"].(map[string]any)["aliases"].(map[string]any)["flip_w"].(map[string]any)
	if aMeta["is_write_index"] != false || bMeta["is_write_index"] != true {
		t.Fatalf("F19 expected idx_r47_a is_write_index=false and idx_r47_b is_write_index=true, got a=%+v b=%+v", aMeta, bMeta)
	}
}

func TestRound47RolloverIndexValidationAndReadTargets(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F21: Index name validation
	for _, invalidName := range []string{"UPPERCASE", "_underscore", "-dashstart", "+plusstart", "bad*star", "bad#hash"} {
		code, _, res := doRound47Raw(t, srv, http.MethodPut, "/"+invalidName, `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("F21 expected 400 invalid_index_name_exception for %q, got %d: %+v", invalidName, code, res)
		}
	}

	// F18: Rollover target validation
	doRound47Raw(t, srv, http.MethodPut, "/concrete_idx_r47", `{}`)
	code, _, _ := doRound47Raw(t, srv, http.MethodPost, "/concrete_idx_r47/_rollover", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F18 expected 400 when rolling over a concrete index, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/missing_rollover_alias/_rollover", `{}`)
	if code != http.StatusNotFound {
		t.Fatalf("F18 expected 404 when rolling over a non-existent alias, got %d", code)
	}
	doRound47Raw(t, srv, http.MethodPut, "/roll-000001", `{"aliases":{"roll_alias":{"is_write_index":true}}}`)
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/roll_alias/_rollover/concrete_idx_r47", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F18 expected 400 resource_already_exists_exception when new_index already exists, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/roll_alias/_rollover/INVALID_UPPER", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F18 expected 400 invalid_index_name_exception when new_index is invalid, got %d", code)
	}

	// F20: Multi-index read endpoints honor ignore_unavailable and allow_no_indices
	for _, ep := range []string{
		"/missing_r47_idx/_settings",
		"/missing_r47_idx/_mapping",
		"/missing_r47_idx/_alias",
		"/missing_r47_idx/_refresh",
		"/missing_r47_idx/_stats",
		"/missing_r47_idx/_search_shards",
	} {
		c404, _, _ := doRound47Raw(t, srv, http.MethodGet, ep, "")
		if c404 != http.StatusNotFound {
			t.Fatalf("F20 expected 404 on %s, got %d", ep, c404)
		}
		c200, _, _ := doRound47Raw(t, srv, http.MethodGet, ep+"?ignore_unavailable=true", "")
		if c200 != http.StatusOK {
			t.Fatalf("F20 expected 200 on %s?ignore_unavailable=true, got %d", ep, c200)
		}
	}
	cWild404, _, _ := doRound47Raw(t, srv, http.MethodGet, "/missing_wild_r47_*/_settings?allow_no_indices=false", "")
	if cWild404 != http.StatusNotFound {
		t.Fatalf("F20 expected 404 on wildcard with allow_no_indices=false, got %d", cWild404)
	}
}

func TestRound47TermsFormatMultiTermsKeyedAggsAndCollapseInnerHits(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound47Raw(t, srv, http.MethodPut, "/aggs_r47", `{
		"mappings": {
			"properties": {
				"flag": {"type": "boolean"},
				"num":  {"type": "long"},
				"host": {"type": "keyword"},
				"loc":  {"type": "geo_point"}
			}
		}
	}`)
	doRound47Raw(t, srv, http.MethodPost, "/aggs_r47/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_id":"1"}}`,
		`{"flag":true,"num":7,"host":"h1","loc":{"lat":40.0,"lon":-70.0}}`,
		`{"index":{"_id":"2"}}`,
		`{"flag":false,"num":7,"host":"h1","loc":{"lat":40.01,"lon":-70.01}}`,
		`{"index":{"_id":"3"}}`,
		`{"flag":true,"num":12,"host":"h2","loc":{"lat":41.0,"lon":-71.0}}`,
	}, "\n")+"\n")

	// F22 & F23: terms key_as_string on boolean & numeric format, multi_terms, keyed geo_distance & adjacency_matrix
	code, _, searchRes := doRound47Raw(t, srv, http.MethodPost, "/aggs_r47/_search", `{
		"size": 0,
		"aggs": {
			"by_flag": {
				"terms": {"field": "flag"}
			},
			"by_num_fmt": {
				"terms": {"field": "num", "format": "000.0"}
			},
			"by_multi": {
				"multi_terms": {
					"terms": [{"field": "host"}, {"field": "num"}]
				}
			},
			"adj_unkeyed": {
				"adjacency_matrix": {
					"keyed": false,
					"filters": {
						"f1": {"term": {"host": "h1"}},
						"f2": {"term": {"flag": true}}
					}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("F22/F23 search failed: %d %+v", code, searchRes)
	}
	aggs := searchRes["aggregations"].(map[string]any)
	flagBuckets := aggs["by_flag"].(map[string]any)["buckets"].([]any)
	if len(flagBuckets) == 0 || flagBuckets[0].(map[string]any)["key_as_string"] == nil {
		t.Fatalf("F22 expected key_as_string on boolean terms bucket, got %+v", flagBuckets)
	}
	numBuckets := aggs["by_num_fmt"].(map[string]any)["buckets"].([]any)
	if len(numBuckets) == 0 || numBuckets[0].(map[string]any)["key_as_string"] != "007.0" {
		t.Fatalf("F22 expected key_as_string='007.0' on formatted numeric terms bucket, got %+v", numBuckets)
	}
	multiBuckets := aggs["by_multi"].(map[string]any)["buckets"].([]any)
	if len(multiBuckets) == 0 {
		t.Fatalf("F22 expected non-empty multi_terms buckets, got %+v", aggs["by_multi"])
	}
	mb0 := multiBuckets[0].(map[string]any)
	if _, isArr := mb0["key"].([]any); !isArr || mb0["key_as_string"] == nil {
		t.Fatalf("F22 expected array key and pipe-joined key_as_string on multi_terms bucket, got %+v", mb0)
	}
	adjBuckets := aggs["adj_unkeyed"].(map[string]any)["buckets"]
	if _, isArr := adjBuckets.([]any); !isArr {
		t.Fatalf("F23 expected array buckets when adjacency_matrix keyed=false, got %T: %+v", adjBuckets, adjBuckets)
	}

	// F24: Second-level collapse inside inner_hits
	code, _, colRes := doRound47Raw(t, srv, http.MethodPost, "/aggs_r47/_search", `{
		"collapse": {
			"field": "host",
			"inner_hits": {
				"name": "by_num",
				"collapse": {"field": "num"},
				"size": 10
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("F24 search failed: %d %+v", code, colRes)
	}
	topHits := colRes["hits"].(map[string]any)["hits"].([]any)
	for _, th := range topHits {
		thm := th.(map[string]any)
		if thm["fields"].(map[string]any)["host"].([]any)[0] == "h1" {
			ihHits := thm["inner_hits"].(map[string]any)["by_num"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
			if len(ihHits) != 1 {
				t.Fatalf("F24 expected 2 docs with host=h1 and same num=7 to collapse to 1 inner hit, got %d: %+v", len(ihHits), ihHits)
			}
			ih0 := ihHits[0].(map[string]any)
			if ih0["fields"] == nil {
				t.Fatalf("F24 expected fields on second-level collapsed inner hit, got %+v", ih0)
			}
		}
	}
}

func TestRound47IngestRerouteDissectGrokPipelinesAndSlicedMutations(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F31 & F34: reroute processor, dissect array support & non-string error, grok trace_match
	code, _, simRes := doRound47Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"dissect": {"field": "lines", "pattern": "%{k}=%{v}"}},
				{"grok": {"field": "msg", "patterns": ["^NOMATCH$", "%{WORD:word}"], "trace_match": true}},
				{"reroute": {"dataset": "nginx", "namespace": "prod"}}
			]
		},
		"docs": [
			{"_index": "raw_in", "_id": "1", "_source": {"lines": ["a=1", "b=2"], "msg": "hello", "data_stream": {"type": "logs"}}}
		]
	}`)
	if code != http.StatusOK {
		t.Fatalf("F31/F34 simulate failed: %d %+v", code, simRes)
	}
	doc0 := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if doc0["_index"] != "logs-nginx-prod" {
		t.Fatalf("F31 expected reroute _index='logs-nginx-prod', got %v", doc0["_index"])
	}
	src0 := doc0["_source"].(map[string]any)
	if len(src0["k"].([]any)) != 2 || src0["word"] != "hello" {
		t.Fatalf("F34 expected dissect array k=[a,b] and grok word=hello, got %+v", src0)
	}
	ingestMeta := doc0["_ingest"].(map[string]any)
	if ingestMeta["_grok_match_index"] != float64(1) || ingestMeta["_grok_match_pattern"] != "%{WORD:word}" {
		t.Fatalf("F34 expected _grok_match_index=1 and _grok_match_pattern='%%{WORD:word}', got %+v", ingestMeta)
	}

	// F32: Ingest script ctx.put / ctx.remove / ctx.containsKey
	code, _, simCtx := doRound47Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"script": {"source": "if (ctx.containsKey('old')) { ctx.put('copied', ctx.get('old')); ctx.remove('old'); }"}}
			]
		},
		"docs": [
			{"_source": {"old": "val47"}}
		]
	}`)
	if code != http.StatusOK {
		t.Fatalf("F32 simulate failed: %d %+v", code, simCtx)
	}
	ctxSrc := simCtx["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if ctxSrc["copied"] != "val47" || ctxSrc["old"] != nil {
		t.Fatalf("F32 expected copied='val47' and old removed, got %+v", ctxSrc)
	}

	// F33: Reroute destination index's default_pipeline and final_pipeline execution
	doRound47Raw(t, srv, http.MethodPut, "/_ingest/pipeline/reroute_to_dest", `{
		"processors": [{"reroute": {"destination": "dest_r47"}}]
	}`)
	doRound47Raw(t, srv, http.MethodPut, "/_ingest/pipeline/dest_def_pipe", `{
		"processors": [{"set": {"field": "from_dest_default", "value": true}}]
	}`)
	doRound47Raw(t, srv, http.MethodPut, "/_ingest/pipeline/dest_fin_pipe", `{
		"processors": [{"set": {"field": "from_dest_final", "value": true}}]
	}`)
	doRound47Raw(t, srv, http.MethodPut, "/dest_r47", `{
		"settings": {
			"index.default_pipeline": "dest_def_pipe",
			"index.final_pipeline": "dest_fin_pipe"
		}
	}`)
	doRound47Raw(t, srv, http.MethodPut, "/src_r47/_doc/1?pipeline=reroute_to_dest&refresh=true", `{"msg":"hi"}`)
	code, _, gotDest := doRound47Raw(t, srv, http.MethodGet, "/dest_r47/_doc/1", "")
	if code != http.StatusOK {
		t.Fatalf("F33 expected doc 1 in dest_r47, got %d: %+v", code, gotDest)
	}
	destSrc := gotDest["_source"].(map[string]any)
	if destSrc["from_dest_default"] != true || destSrc["from_dest_final"] != true {
		t.Fatalf("F33 expected both dest default_pipeline and final_pipeline to run, got %+v", destSrc)
	}

	// F35: Slice validation and sliced _update_by_query / _delete_by_query / _reindex
	doRound47Raw(t, srv, http.MethodPut, "/slice_src", `{}`)
	for _, id := range []string{"1", "2", "3", "4"} {
		doRound47Raw(t, srv, http.MethodPut, "/slice_src/_doc/"+id+"?refresh=true", `{"v":1}`)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/slice_src/_update_by_query?slices=0", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F35 expected 400 for slices=0, got %d", code)
	}
	code, _, _ = doRound47Raw(t, srv, http.MethodPost, "/slice_src/_update_by_query", `{"slice":{"id":2,"max":2}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F35 expected 400 for slice.id >= slice.max, got %d", code)
	}
	_, _, s0 := doRound47Raw(t, srv, http.MethodPost, "/slice_src/_update_by_query?refresh=true", `{"slice":{"id":0,"max":2},"script":{"source":"ctx._source.v = 2"}}`)
	_, _, s1 := doRound47Raw(t, srv, http.MethodPost, "/slice_src/_update_by_query?refresh=true", `{"slice":{"id":1,"max":2},"script":{"source":"ctx._source.v = 2"}}`)
	u0, _ := s0["updated"].(float64)
	u1, _ := s1["updated"].(float64)
	if int(u0+u1) != 4 {
		t.Fatalf("F35 expected disjoint slices 0 and 1 of 2 to update 4 total docs, got %v + %v", u0, u1)
	}
}
