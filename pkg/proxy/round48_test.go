package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newTestServerWithMock(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	return srv, srv.Handler()
}

func doRound48Req(t *testing.T, srv http.Handler, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	var reqBody *strings.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	} else {
		reqBody = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, parsed, raw
}

func TestRound48StoredScriptsAndPainlessExecute(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. PUT stored script
	code, resp, _ := doRound48Req(t, handler, http.MethodPut, "/_scripts/calc_bonus", `{
		"script": {
			"lang": "painless",
			"source": "doc['salary'].value * params.factor"
		}
	}`)
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("PUT /_scripts/calc_bonus failed: %d %v", code, resp)
	}

	// 2. GET stored script
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_scripts/calc_bonus", "")
	if code != http.StatusOK || resp["found"] != true || resp["_id"] != "calc_bonus" {
		t.Fatalf("GET /_scripts/calc_bonus failed: %d %v", code, resp)
	}

	// 3. POST /_scripts/painless/_execute with inline script and context_setup.document
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {
			"source": "doc['price'].value * params.tax",
			"params": {"tax": 1.5}
		},
		"context": "score",
		"context_setup": {
			"index": "test",
			"document": {"price": 20}
		}
	}`)
	if code != http.StatusOK || resp["result"] != float64(30) {
		t.Fatalf("POST /_scripts/painless/_execute score failed: %d %v", code, resp)
	}

	// 4. POST /_scripts/painless/_execute with stored script id in filter context
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_scripts/high_earner", `{
		"script": {
			"lang": "painless",
			"source": "doc['salary'].value >= params.min_sal"
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /_scripts/high_earner failed: %d", code)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {
			"id": "high_earner",
			"params": {"min_sal": 100}
		},
		"context": "filter",
		"context_setup": {
			"document": {"salary": 150}
		}
	}`)
	if code != http.StatusOK || resp["result"] != true {
		t.Fatalf("POST /_scripts/painless/_execute filter failed: %d %v", code, resp)
	}

	// 5. Index docs and search using stored script id in script query & script_fields
	doRound48Req(t, handler, http.MethodPut, "/emp/_doc/1?refresh=true", `{"name":"alice","salary":120}`)
	doRound48Req(t, handler, http.MethodPut, "/emp/_doc/2?refresh=true", `{"name":"bob","salary":80}`)

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/emp/_search", `{
		"query": {
			"script": {
				"script": {
					"id": "high_earner",
					"params": {"min_sal": 100}
				}
			}
		},
		"script_fields": {
			"bonus": {
				"script": {
					"id": "calc_bonus",
					"params": {"factor": 0.5}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("search with stored script failed: %d %v", code, resp)
	}
	hitsObj, _ := resp["hits"].(map[string]any)
	hitsArr, _ := hitsObj["hits"].([]any)
	if len(hitsArr) != 1 {
		t.Fatalf("expected 1 hit from stored script query, got %d: %v", len(hitsArr), resp)
	}
	hit0, _ := hitsArr[0].(map[string]any)
	fields0, _ := hit0["fields"].(map[string]any)
	bonusArr, _ := fields0["bonus"].([]any)
	if len(bonusArr) != 1 || bonusArr[0] != float64(60) {
		t.Fatalf("expected bonus=[60], got %v", fields0)
	}

	// 6. DELETE stored script
	code, resp, _ = doRound48Req(t, handler, http.MethodDelete, "/_scripts/calc_bonus", "")
	if code != http.StatusOK || resp["acknowledged"] != true {
		t.Fatalf("DELETE /_scripts/calc_bonus failed: %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/_scripts/calc_bonus", "")
	if code != http.StatusNotFound || resp["found"] != false {
		t.Fatalf("GET deleted script expected 404 found=false, got %d %v", code, resp)
	}
}

func TestRound48MustacheSearchTemplates(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// Store a Mustache template
	code, _, _ := doRound48Req(t, handler, http.MethodPut, "/_scripts/my_search_tpl", `{
		"script": {
			"lang": "mustache",
			"source": "{\"size\":{{size}}{{^size}}5{{/size}},\"query\":{\"terms\":{\"tag\":{{#toJson}}tags{{/toJson}}}}}"
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("failed storing mustache template: %d", code)
	}

	// 1. Render template with default size and #toJson
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/_render/template", `{
		"id": "my_search_tpl",
		"params": {
			"tags": ["go", "doris"]
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /_render/template failed: %d %v", code, resp)
	}
	tplOut, _ := resp["template_output"].(map[string]any)
	if tplOut["size"] != float64(5) {
		t.Fatalf("expected default size 5 in template_output, got %v", tplOut)
	}

	// 2. Render inline template with #join and #url
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_render/template", `{
		"source": "{\"joined\":\"{{#join delimiter='|'}}items{{/join}}\",\"encoded\":\"{{#url}}a b/c{{/url}}\"}",
		"params": {
			"items": ["x", "y", "z"]
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /_render/template inline failed: %d %v", code, resp)
	}
	tplOut, _ = resp["template_output"].(map[string]any)
	if tplOut["joined"] != "x|y|z" || tplOut["encoded"] != "a%20b%2Fc" {
		t.Fatalf("unexpected #join/#url output: %v", tplOut)
	}

	// 3. Execute /_search/template and /_msearch/template
	doRound48Req(t, handler, http.MethodPut, "/tpl_idx/_doc/1?refresh=true", `{"tag":"go"}`)
	doRound48Req(t, handler, http.MethodPut, "/tpl_idx/_doc/2?refresh=true", `{"tag":"rust"}`)

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/tpl_idx/_search/template", `{
		"id": "my_search_tpl",
		"params": {
			"tags": ["go"]
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /tpl_idx/_search/template failed: %d %v", code, resp)
	}
	hitsObj, _ := resp["hits"].(map[string]any)
	hitsArr, _ := hitsObj["hits"].([]any)
	if len(hitsArr) != 1 {
		t.Fatalf("expected 1 hit from _search/template, got %d", len(hitsArr))
	}

	ndjson := "{\"index\":\"tpl_idx\"}\n{\"id\":\"my_search_tpl\",\"params\":{\"tags\":[\"rust\"]}}\n"
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/_msearch/template", ndjson)
	if code != http.StatusOK {
		t.Fatalf("POST /_msearch/template failed: %d %v", code, resp)
	}
	resps, _ := resp["responses"].([]any)
	if len(resps) != 1 {
		t.Fatalf("expected 1 response in _msearch/template, got %v", resp)
	}
}

func TestRound48TermVectorsRankEvalMVT(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	doRound48Req(t, handler, http.MethodPut, "/tv_idx/_doc/1?refresh=true", `{"title":"Quick brown fox jumps over lazy fox"}`)
	doRound48Req(t, handler, http.MethodPut, "/tv_idx/_doc/2?refresh=true", `{"title":"Fast brown dog"}`)

	// 1. Term vectors on indexed doc
	code, resp, _ := doRound48Req(t, handler, http.MethodGet, "/tv_idx/_termvectors/1?term_statistics=true", "")
	if code != http.StatusOK || resp["found"] != true {
		t.Fatalf("GET /tv_idx/_termvectors/1 failed: %d %v", code, resp)
	}
	tvMap, _ := resp["term_vectors"].(map[string]any)
	titleTV, _ := tvMap["title"].(map[string]any)
	termsMap, _ := titleTV["terms"].(map[string]any)
	foxStats, _ := termsMap["fox"].(map[string]any)
	if foxStats["term_freq"] != float64(2) {
		t.Fatalf("expected term_freq=2 for 'fox', got %v", foxStats)
	}

	// 2. Multi term vectors
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/tv_idx/_mtermvectors", `{"ids":["1","2"]}`)
	if code != http.StatusOK {
		t.Fatalf("POST /tv_idx/_mtermvectors failed: %d %v", code, resp)
	}
	docsArr, _ := resp["docs"].([]any)
	if len(docsArr) != 2 {
		t.Fatalf("expected 2 docs in _mtermvectors, got %d", len(docsArr))
	}

	// 3. Rank eval (precision@k and mrr)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/tv_idx/_rank_eval", `{
		"requests": [
			{
				"id": "q1",
				"request": {"query": {"match": {"title": "fox"}}},
				"ratings": [{"_index": "tv_idx", "_id": "1", "rating": 3}]
			}
		],
		"metric": {
			"mean_reciprocal_rank": {"k": 5, "relevant_rating_threshold": 1}
		}
	}`)
	if code != http.StatusOK || resp["metric_score"] != float64(1) {
		t.Fatalf("POST /tv_idx/_rank_eval failed: %d %v", code, resp)
	}

	// 4. Vector tile _mvt
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/tv_idx/_mvt/location/2/1/1", "")
	if code != http.StatusOK {
		t.Fatalf("GET /tv_idx/_mvt/location/2/1/1 expected 200, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/tv_idx/_mvt/location/2/99/1", "")
	if code != http.StatusBadRequest {
		t.Fatalf("GET /tv_idx/_mvt/location/2/99/1 expected 400 out of range, got %d", code)
	}
}

func TestRound48CatTasksClusterAdminEndpoints(t *testing.T) {
	_, handler := newTestServerWithMock(t)
	doRound48Req(t, handler, http.MethodPut, "/admin_idx", `{}`)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/_cat/allocation?format=json"},
		{http.MethodGet, "/_cat/fielddata?format=json"},
		{http.MethodGet, "/_cat/master?format=json"},
		{http.MethodGet, "/_cat/nodeattrs?format=json"},
		{http.MethodGet, "/_cat/pending_tasks?format=json"},
		{http.MethodGet, "/_cat/plugins?format=json"},
		{http.MethodGet, "/_cat/recovery?format=json"},
		{http.MethodGet, "/_cat/repositories?format=json"},
		{http.MethodGet, "/_cat/segments?format=json"},
		{http.MethodGet, "/_cat/tasks?format=json"},
		{http.MethodGet, "/_cat/thread_pool?format=json"},
		{http.MethodGet, "/_cat/templates?format=json"},
		{http.MethodGet, "/_tasks"},
		{http.MethodGet, "/_tasks/doris-node-1:1"},
		{http.MethodPost, "/_tasks/doris-node-1:1/_cancel"},
		{http.MethodGet, "/_cluster/allocation/explain"},
		{http.MethodGet, "/_cluster/pending_tasks"},
		{http.MethodPost, "/_cluster/reroute"},
		{http.MethodGet, "/_nodes/hot_threads"},
		{http.MethodGet, "/_nodes/usage"},
		{http.MethodGet, "/admin_idx/_recovery"},
		{http.MethodGet, "/admin_idx/_segments"},
		{http.MethodGet, "/admin_idx/_shard_stores"},
		{http.MethodPost, "/admin_idx/_cache/clear"},
		{http.MethodPost, "/admin_idx/_close"},
		{http.MethodPost, "/admin_idx/_open"},
	}
	for _, ep := range endpoints {
		code, _, raw := doRound48Req(t, handler, ep.method, ep.path, "")
		if code != http.StatusOK {
			t.Fatalf("%s %s returned %d: %s", ep.method, ep.path, code, raw)
		}
	}
}

func TestRound48QueriesAndSearchFeatures(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Wrapper, Pinned, matched_queries, and Search Slice
	doRound48Req(t, handler, http.MethodPut, "/q48/_doc/1?refresh=true", `{"title":"elasticsearch guide","tag":"search","part":1}`)
	doRound48Req(t, handler, http.MethodPut, "/q48/_doc/2?refresh=true", `{"title":"apache doris guide","tag":"analytics","part":2}`)
	doRound48Req(t, handler, http.MethodPut, "/q48/_doc/3?refresh=true", `{"title":"elasticsearch doris proxy","tag":"bridge","part":3}`)

	b64Query := base64.StdEncoding.EncodeToString([]byte(`{"term":{"tag":{"value":"search","_name":"tag_search"}}}`))
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/q48/_search", `{
		"query": {
			"bool": {
				"should": [
					{"wrapper": {"query": "`+b64Query+`"}},
					{"term": {"tag": {"value": "bridge", "_name": "tag_bridge"}}}
				]
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("wrapper + matched_queries search failed: %d %v", code, resp)
	}
	hitsObj, _ := resp["hits"].(map[string]any)
	hitsArr, _ := hitsObj["hits"].([]any)
	if len(hitsArr) != 2 {
		t.Fatalf("expected 2 hits for wrapper + should, got %d: %v", len(hitsArr), resp)
	}
	for _, hRaw := range hitsArr {
		hm, _ := hRaw.(map[string]any)
		mq, _ := hm["matched_queries"].([]any)
		if len(mq) != 1 {
			t.Fatalf("expected matched_queries on hit %v", hm)
		}
	}

	// Pinned query promotes doc 2 to the top
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/q48/_search", `{
		"query": {
			"pinned": {
				"ids": ["2"],
				"organic": {"match_all": {}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("pinned query failed: %d %v", code, resp)
	}
	hitsArr, _ = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hitsArr) != 3 || hitsArr[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected pinned doc 2 first, got %v", hitsArr)
	}

	// Search slice partitioning covers all 3 docs across 2 slices
	code1, resp1, _ := doRound48Req(t, handler, http.MethodPost, "/q48/_search", `{"slice":{"id":0,"max":2}}`)
	code2, resp2, _ := doRound48Req(t, handler, http.MethodPost, "/q48/_search", `{"slice":{"id":1,"max":2}}`)
	if code1 != http.StatusOK || code2 != http.StatusOK {
		t.Fatalf("slice search failed: %d %d", code1, code2)
	}
	h1 := len(resp1["hits"].(map[string]any)["hits"].([]any))
	h2 := len(resp2["hits"].(map[string]any)["hits"].([]any))
	if h1+h2 != 3 {
		t.Fatalf("expected slice 0 (%d) + slice 1 (%d) == 3", h1, h2)
	}

	// 2. MoreLikeThis query (text and doc _id lookup)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/q48/_search", `{
		"query": {
			"more_like_this": {
				"fields": ["title"],
				"like": [{"_index": "q48", "_id": "1"}],
				"min_term_freq": 1,
				"min_doc_freq": 1
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("more_like_this failed: %d %v", code, resp)
	}
	mltHits, _ := resp["hits"].(map[string]any)["hits"].([]any)
	// Doc 1 is excluded because it was in `like` by _id; docs 2 ("guide") and 3 ("elasticsearch") match!
	if len(mltHits) != 2 {
		t.Fatalf("expected 2 hits for more_like_this (excluding seed doc 1), got %d: %v", len(mltHits), mltHits)
	}

	// 3. Join queries: parent_id, has_child, has_parent
	doRound48Req(t, handler, http.MethodPut, "/join_idx", `{
		"mappings": {
			"properties": {
				"my_join": {
					"type": "join",
					"relations": {"question": "answer"}
				}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/join_idx/_doc/q1?refresh=true", `{"title":"What is Doris?","my_join":"question"}`)
	doRound48Req(t, handler, http.MethodPut, "/join_idx/_doc/q2?refresh=true", `{"title":"What is Lucene?","my_join":"question"}`)
	doRound48Req(t, handler, http.MethodPut, "/join_idx/_doc/a1?routing=q1&refresh=true", `{"body":"MPP analytical database","my_join":{"name":"answer","parent":"q1"}}`)

	// parent_id
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/join_idx/_search", `{
		"query": {"parent_id": {"type": "answer", "id": "q1"}}
	}`)
	if code != http.StatusOK || len(resp["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("parent_id query failed: %d %v", code, resp)
	}

	// has_child
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/join_idx/_search", `{
		"query": {
			"has_child": {
				"type": "answer",
				"query": {"match": {"body": "analytical"}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("has_child query failed: %d %v", code, resp)
	}
	hcHits, _ := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hcHits) != 1 || hcHits[0].(map[string]any)["_id"] != "q1" {
		t.Fatalf("expected parent q1 from has_child, got %v", hcHits)
	}

	// has_parent
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/join_idx/_search", `{
		"query": {
			"has_parent": {
				"parent_type": "question",
				"query": {"match": {"title": "Doris"}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("has_parent query failed: %d %v", code, resp)
	}
	hpHits, _ := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hpHits) != 1 || hpHits[0].(map[string]any)["_id"] != "a1" {
		t.Fatalf("expected child a1 from has_parent, got %v", hpHits)
	}

	// 4. Percolate query (single & multi documents with _percolator_document_slot)
	doRound48Req(t, handler, http.MethodPut, "/perc_idx", `{
		"mappings": {
			"properties": {
				"query": {"type": "percolator"},
				"alert": {"type": "keyword"}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/perc_idx/_doc/r1?refresh=true", `{"alert":"error","query":{"term":{"level":"error"}}}`)
	doRound48Req(t, handler, http.MethodPut, "/perc_idx/_doc/r2?refresh=true", `{"alert":"warn","query":{"term":{"level":"warn"}}}`)

	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/perc_idx/_search", `{
		"query": {
			"percolate": {
				"field": "query",
				"documents": [
					{"level": "info"},
					{"level": "error"}
				]
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("percolate query failed: %d %v", code, resp)
	}
	pHits, _ := resp["hits"].(map[string]any)["hits"].([]any)
	if len(pHits) != 1 || pHits[0].(map[string]any)["_id"] != "r1" {
		t.Fatalf("expected r1 from percolate, got %v", pHits)
	}
	pFields, _ := pHits[0].(map[string]any)["fields"].(map[string]any)
	slots, _ := pFields["_percolator_document_slot"].([]any)
	if len(slots) != 1 || slots[0] != float64(1) {
		t.Fatalf("expected _percolator_document_slot=[1], got %v", pFields)
	}
}

func TestRound48IngestAndMappingEdgeCases(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. F24: ctx.get('a')?.b and ctx?.get('arr')[0] in ingest script processor
	// 2. F27: grok ECS bracket field %{IP:[host][ip]} and integer coercion rejection
	// 3. F28: dissect %{+&msg} and %{&+msg}
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"script": {
						"source": "if (ctx.get('nested')?.val != null) { ctx.extracted = ctx.get('nested')?.val + '-' + ctx?.get('items')[0]; }"
					}
				},
				{
					"grok": {
						"field": "log",
						"patterns": ["%{IP:[host][ip]}"]
					}
				},
				{
					"dissect": {
						"field": "dis",
						"pattern": "%{?target} %{+&target} %{+&target}",
						"append_separator": ":"
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"nested": {"val": "ok"},
					"items": ["first"],
					"log": "10.0.0.1",
					"dis": "greeting hello world",
					"greeting": "start"
				}
			}
		]
	}`)
	if code != http.StatusOK {
		t.Fatalf("ingest simulate failed: %d %v", code, resp)
	}
	simDocs, _ := resp["docs"].([]any)
	doc0, _ := simDocs[0].(map[string]any)["doc"].(map[string]any)
	src0, _ := doc0["_source"].(map[string]any)
	if src0["extracted"] != "ok-first" {
		t.Fatalf("F24 ctx.get()?.val failed: %v", src0)
	}
	hostObj, _ := src0["host"].(map[string]any)
	if hostObj["ip"] != "10.0.0.1" {
		t.Fatalf("F27 grok ECS bracket field failed: %v", src0)
	}
	if src0["greeting"] != "hello:world" {
		t.Fatalf("F28 dissect combined +& failed, got greeting=%v (src=%v)", src0["greeting"], src0)
	}

	// 4. F25: Bulk create without _id where ingest pipeline sets ctx._id
	doRound48Req(t, handler, http.MethodPut, "/_ingest/pipeline/set_fixed_id", `{
		"processors": [
			{"set": {"field": "_id", "value": "fixed-1"}}
		]
	}`)
	bulkBody := bytes.NewBufferString(
		"{\"create\":{\"_index\":\"f25_idx\"}}\n{\"x\":1}\n" +
			"{\"create\":{\"_index\":\"f25_idx\"}}\n{\"x\":2}\n",
	)
	req := httptest.NewRequest(http.MethodPost, "/_bulk?pipeline=set_fixed_id&refresh=true", bulkBody)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var bulkResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &bulkResp)
	if bulkResp["errors"] != true {
		t.Fatalf("expected bulk conflict error when second create gets same pipeline-assigned _id: %v", bulkResp)
	}
	items, _ := bulkResp["items"].([]any)
	secondCreate, _ := items[1].(map[string]any)["create"].(map[string]any)
	if secondCreate["status"] != float64(409) {
		t.Fatalf("expected second create status 409, got %v", secondCreate)
	}

	// 5. F16: Dynamic mapping numeric_detection and dynamic_templates path_match
	doRound48Req(t, handler, http.MethodPut, "/f16_idx", `{
		"mappings": {
			"numeric_detection": true,
			"dynamic_templates": [
				{
					"codes_as_keyword": {
						"path_match": "meta.code_*",
						"mapping": {"type": "keyword"}
					}
				}
			]
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/f16_idx/_doc/1?refresh=true", `{"num_str":"42","meta":{"code_1":"99"}}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/f16_idx/_mapping", "")
	if code != http.StatusOK {
		t.Fatalf("GET /f16_idx/_mapping failed: %d %v", code, resp)
	}
	props, _ := resp["f16_idx"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["num_str"].(map[string]any)["type"] != "long" {
		t.Fatalf("expected num_str inferred as long with numeric_detection=true, got %v", props["num_str"])
	}
	metaProps, _ := props["meta"].(map[string]any)["properties"].(map[string]any)
	if metaProps["code_1"].(map[string]any)["type"] != "keyword" {
		t.Fatalf("expected meta.code_1 inferred as keyword via path_match template, got %v", metaProps["code_1"])
	}
}

func TestRound48DeepCoverage_TemplatesStoredScriptsQueriesAndAdmin(t *testing.T) {
	srv, handler := newTestServerWithMock(t)

	// Store scripts for queries, sorts, script_fields, runtime_mappings, and aggs
	doRound48Req(t, handler, http.MethodPut, "/_scripts/painless/legacy_filter", `{
		"script": {
			"lang": "painless",
			"source": "doc['price'].value >= params.min_p",
			"params": {"min_p": 10},
			"options": {"content_type": "application/json"}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/_scripts/score_boost", `{
		"script": {
			"inline": "doc['price'].value * params.factor",
			"params": {"factor": 2}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/_scripts/val_script", `{
		"script": {
			"source": "doc['price'].value + 5"
		}
	}`)

	// Legacy GET & DELETE on /_scripts/{lang}/{id} and error paths
	code, _, _ := doRound48Req(t, handler, http.MethodGet, "/_scripts/painless/legacy_filter", "")
	if code != http.StatusOK {
		t.Fatalf("GET legacy script failed: %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_scripts/bad1", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing script object, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPut, "/_scripts/bad2", `{"script":{"source":"   "}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for blank script.source, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "[1, 2, 3]"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for non-primitive painless _execute, got %d", code)
	}

	// Create index and seed docs for stored script resolution in queries & aggs
	doRound48Req(t, handler, http.MethodPut, "/r48_deep", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"tag": {"type": "keyword"},
				"price": {"type": "double"},
				"ts": {"type": "date"},
				"my_join": {
					"type": "join",
					"relations": {"question": "answer"}
				}
			}
		}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r48_deep/_doc/1?refresh=true", `{"title":"quick brown fox","tag":"alpha","price":20,"ts":"2025-01-01T00:00:00Z","my_join":"question"}`)
	doRound48Req(t, handler, http.MethodPut, "/r48_deep/_doc/2?routing=1&refresh=true", `{"title":"quick blue dog","tag":"beta","price":40,"ts":"2025-01-02T00:00:00Z","my_join":{"name":"answer","parent":"1"}}`)

	// Exercise resolveStoredScriptsInSearchRequest across nested query structures and aggs
	searchReq := &esast.SearchRequest{}
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"script": {"script": {"id": "legacy_filter", "params": {"min_p": 15}}}},
					{"script_score": {"query": {"match_all": {"_name": "m_all"}}, "script": {"id": "score_boost"}}}
				],
				"should": [
					{"function_score": {
						"query": {"term": {"tag": {"value": "alpha", "_name": "t_alpha"}}},
						"script_score": {"script": {"id": "score_boost"}}
					}},
					{"function_score": {
						"query": {"match_all": {}},
						"functions": [
							{"filter": {"script": {"script": {"id": "legacy_filter"}}}, "script_score": {"script": {"id": "score_boost"}}}
						]
					}},
					{"constant_score": {"filter": {"script": {"script": {"id": "legacy_filter"}}}, "_name": "cs_named"}},
					{"boosting": {
						"positive": {"script": {"script": {"id": "legacy_filter"}}},
						"negative": {"script": {"script": {"id": "legacy_filter"}}},
						"negative_boost": 0.2
					}},
					{"dis_max": {"queries": [{"script": {"script": {"id": "legacy_filter"}}}], "_name": "dm_named"}},
					{"pinned": {"ids": ["1"], "organic": {"script": {"script": {"id": "legacy_filter"}}}}}
				],
				"filter": [
					{"has_child": {"type": "answer", "query": {"match_all": {}}, "_name": "hc_named"}}
				],
				"must_not": [
					{"has_parent": {"parent_type": "question", "query": {"term": {"tag": "none"}}, "score": true, "boost": 1.5, "_name": "hp_named"}}
				]
			}
		},
		"post_filter": {"script": {"script": {"id": "legacy_filter"}}},
		"sort": [{"_script": {"type": "number", "script": {"id": "val_script"}, "order": "desc"}}],
		"script_fields": {"sf1": {"script": {"id": "val_script"}}},
		"runtime_mappings": {"rm1": {"type": "double", "script": {"id": "val_script"}}},
		"rescore": [{"window_size": 10, "query": {"rescore_query": {"script": {"script": {"id": "legacy_filter"}}}}}],
		"aggs": {
			"by_tag": {"terms": {"field": "tag", "script": {"id": "val_script"}}},
			"hist": {"histogram": {"field": "price", "interval": 10, "script": {"id": "val_script"}}},
			"dhist": {"date_histogram": {"field": "ts", "fixed_interval": "1d", "script": {"id": "val_script"}}},
			"rng": {"range": {"field": "price", "script": {"id": "val_script"}, "ranges": [{"to": 50}]}},
			"flt": {"filter": {"script": {"script": {"id": "legacy_filter"}}}, "aggs": {"avg_p": {"avg": {"field": "price", "script": {"id": "val_script"}}}}},
			"flts": {"filters": {"filters": {"f1": {"script": {"script": {"id": "legacy_filter"}}}}}},
			"p95": {"percentiles": {"field": "price", "script": {"id": "val_script"}}},
			"prank": {"percentile_ranks": {"field": "price", "values": [20], "script": {"id": "val_script"}}},
			"sstats": {"string_stats": {"field": "tag", "script": {"id": "val_script"}}},
			"rt": {"rate": {"field": "price", "script": {"id": "val_script"}}},
			"sm": {"scripted_metric": {
				"init_script": {"id": "val_script"},
				"map_script": {"id": "val_script"},
				"combine_script": {"id": "val_script"},
				"reduce_script": {"id": "val_script"}
			}}
		}
	}`), searchReq); err != nil {
		t.Fatalf("unmarshal searchReq failed: %v", err)
	}
	srv.resolveStoredScriptsInSearchRequest(searchReq)
	_ = srv.preResolveSpecialQueriesInSearchRequest(r48Ctx(), []string{"r48_deep"}, searchReq)
	if !queryHasNamedClauses(searchReq.Query) {
		t.Fatalf("expected queryHasNamedClauses=true")
	}

	// Mustache template advanced features: triple braces, &, !, #toJson, #join, #url, nested sections, string numeric coercion
	doRound48Req(t, handler, http.MethodPut, "/_scripts/adv_tpl", `{
		"script": {
			"lang": "mustache",
			"source": "{\"from\":\"{{from}}\",\"size\":\"{{size}}\",\"min_score\":\"{{min_score}}\",\"terminate_after\":\"{{term_after}}\",\"query\":{\"bool\":{\"must\":[{{#cond}}{\"term\":{\"tag\":\"{{{raw_tag}}}\"}}{{/cond}}{{^cond}}{\"match_all\":{}}{{/cond}}],\"filter\":[{\"terms\":{\"tag\":{{#toJson}}tags{{/toJson}}}}]}}}",
			"params": {"from": "0", "size": "5", "min_score": "0.1", "term_after": "100", "cond": true, "raw_tag": "alpha", "tags": ["alpha", "beta"]}
		}
	}`)
	code, resp, _ := doRound48Req(t, handler, http.MethodPost, "/_render/template/adv_tpl", `{
		"params": {"raw_tag": "alpha"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /_render/template/adv_tpl failed: %d %v", code, resp)
	}
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r48_deep/_search/template", `{
		"id": "adv_tpl",
		"params": {"raw_tag": "alpha"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("POST /r48_deep/_search/template failed: %d %v", code, resp)
	}

	// Direct evalMustacheBlock test for #join, #url, map section, []string section, nested sections, &
	renderedMustache := evalMustacheBlock(
		`{{! comment }}{{#join delimiter='|'}}arr{{/join}} {{#url}}{{q}}{{/url}} {{#obj}}{{&sub}}{{/obj}} {{#str_arr}}{{.}},{{/str_arr}} {{#outer}}{{#outer}}in{{/outer}}{{/outer}}`,
		map[string]any{
			"arr":     []any{"a", 2, true},
			"q":       "hello world",
			"obj":     map[string]any{"sub": "val"},
			"str_arr": []string{"x", "y"},
			"outer":   true,
		},
		nil,
	)
	if !strings.Contains(renderedMustache, "a|2|true") || !strings.Contains(renderedMustache, "hello%20world") {
		t.Fatalf("unexpected renderedMustache: %q", renderedMustache)
	}

	// _mtermvectors with ?ids=1,2 and query params
	code, resp, _ = doRound48Req(t, handler, http.MethodGet, "/r48_deep/_mtermvectors?ids=1,2&fields=title&term_statistics=true&field_statistics=true&positions=true&offsets=true", "")
	if code != http.StatusOK {
		t.Fatalf("GET /r48_deep/_mtermvectors?ids=1,2 failed: %d %v", code, resp)
	}

	// _rank_eval with recall, dcg (normalize: true), err, and template_id
	for _, metricPayload := range []string{
		`{"requests":[{"id":"q1","template_id":"adv_tpl","params":{"raw_tag":"alpha"},"ratings":[{"_index":"r48_deep","_id":"1","rating":3}]}],"metric":{"recall":{"k":5,"relevant_rating_threshold":1}}}`,
		`{"requests":[{"id":"q1","request":{"query":{"match_all":{}}},"ratings":[{"_index":"r48_deep","_id":"1","rating":3},{"_index":"r48_deep","_id":"2","rating":1}]}],"metric":{"dcg":{"k":5,"normalize":true}}}`,
		`{"requests":[{"id":"q1","request":{"query":{"match_all":{}}},"ratings":[{"_index":"r48_deep","_id":"1","rating":2}]}],"metric":{"expected_reciprocal_rank":{"k":5,"maximum_relevance":3}}}`,
		`{"requests":[{"id":"q_inline","template_id":"inl1","params":{},"ratings":[{"_index":"r48_deep","_id":"1","rating":1}]},{"id":"q_miss","template_id":"missing_tpl","ratings":[]}],"templates":[{"id":"inl1","template":{"source":{"query":{"match_all":{}}}}}],"metric":{"precision":{"k":5}}}`,
	} {
		code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r48_deep/_rank_eval", metricPayload)
		if code != http.StatusOK {
			t.Fatalf("_rank_eval failed for payload %s: %d %v", metricPayload, code, resp)
		}
	}

	// _mvt error cases
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/r48_deep/_mvt/loc/-1/0/0", "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative zoom, got %d", code)
	}
	code, _, _ = doRound48Req(t, handler, http.MethodGet, "/r48_deep/_mvt/loc/1/5/0", "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range x tile, got %d", code)
	}

	// _cat/thread_pool/{name}, _cat/templates/{name}, index-level _recovery, _segments, _shard_stores, _cache/clear, _open, _close
	doRound48Req(t, handler, http.MethodPut, "/_index_template/r48_tpl", `{"index_patterns":["r48_*"],"priority":10}`)
	for _, ep := range []string{
		"/_cat/thread_pool/search*?format=json",
		"/_cat/templates/r48*?format=json",
		"/r48_deep/_recovery",
		"/r48_deep/_segments",
		"/r48_deep/_shard_stores",
		"/r48_deep/_cache/clear",
	} {
		code, _, _ = doRound48Req(t, handler, http.MethodGet, ep, "")
		if code != http.StatusOK {
			t.Fatalf("GET %s failed: %d", ep, code)
		}
	}
	code, _, _ = doRound48Req(t, handler, http.MethodPost, "/_cluster/allocation/explain", `{"index":"r48_deep","shard":0,"primary":true}`)
	if code != http.StatusOK {
		t.Fatalf("POST /_cluster/allocation/explain with body failed: %d", code)
	}

	// MoreLikeThis with unlike, stop_words, minimum_should_match, and Percolate by doc _id
	doRound48Req(t, handler, http.MethodPut, "/r48_perc", `{
		"mappings": {"properties": {"query": {"type": "percolator"}, "title": {"type": "text"}}}
	}`)
	doRound48Req(t, handler, http.MethodPut, "/r48_perc/_doc/q1?refresh=true", `{"query":{"match":{"title":"quick"}},"title":"quick brown fox"}`)
	code, resp, _ = doRound48Req(t, handler, http.MethodPost, "/r48_perc/_search", `{
		"query": {
			"bool": {
				"must": [
					{"percolate": {"field": "query", "index": "r48_perc", "id": "q1", "_name": "perc_by_id"}}
				],
				"should": [
					{"more_like_this": {
						"fields": ["title"],
						"like": [{"_index": "r48_deep", "_id": "1"}, "quick fox"],
						"unlike": ["lazy"],
						"stop_words": ["the"],
						"min_term_freq": 1,
						"min_word_length": 2,
						"max_word_length": 20,
						"minimum_should_match": "50%",
						"_name": "mlt_named"
					}}
				]
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("percolate by id + mlt search failed: %d %v", code, resp)
	}
}

func r48Ctx() context.Context {
	return context.Background()
}
