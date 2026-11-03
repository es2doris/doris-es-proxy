package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound39JSON(t *testing.T, srv *Server, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var m map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &m)
	}
	return w, m
}

func TestRound39_F1_F18_IndexFalseSearchErrorAndFieldMappingEndpoints(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	w, _ := doRound39JSON(t, srv, http.MethodPut, "/r39_f1", `{
		"mappings": {
			"properties": {
				"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"secret": {"type": "keyword", "index": false},
				"title_alias": {"type": "alias", "path": "title"},
				"payload": {"type": "object", "enabled": false}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", w.Code, w.Body.String())
	}

	doRound39JSON(t, srv, http.MethodPut, "/r39_f1/_doc/1", `{"title":"hello","secret":"s1","payload":{"x":"y"}}`)

	// Searching on secret (index: false) -> 400 search_phase_execution_exception
	wSearch, mSearch := doRound39JSON(t, srv, http.MethodPost, "/r39_f1/_search", `{"query":{"term":{"secret":"s1"}}}`)
	if wSearch.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for searching index:false field, got %d: %s", wSearch.Code, wSearch.Body.String())
	}
	errObj, _ := mSearch["error"].(map[string]any)
	if errObj["type"] != "search_phase_execution_exception" {
		t.Fatalf("expected search_phase_execution_exception, got %+v", errObj)
	}

	// F18: GET /r39_f1/_mapping/field/title.keyword,title_alias returns both companion .keyword and alias path
	wFM, mFM := doRound39JSON(t, srv, http.MethodGet, "/r39_f1/_mapping/field/title.keyword,title_alias", "")
	if wFM.Code != http.StatusOK {
		t.Fatalf("expected 200 from _mapping/field, got %d: %s", wFM.Code, wFM.Body.String())
	}
	idxEntry, _ := mFM["r39_f1"].(map[string]any)
	mappingsMap, _ := idxEntry["mappings"].(map[string]any)
	if _, ok := mappingsMap["title.keyword"]; !ok {
		t.Fatalf("expected title.keyword in _mapping/field response, got %+v", mappingsMap)
	}
	aliasEntry, _ := mappingsMap["title_alias"].(map[string]any)
	aliasMap, _ := aliasEntry["mapping"].(map[string]any)
	aliasProp, _ := aliasMap["title_alias"].(map[string]any)
	if aliasProp["path"] != "title" {
		t.Fatalf("expected alias path='title' in _mapping/field response, got %+v", aliasProp)
	}
}

func TestRound39_F9_F14_GeoDistanceSortAndUnaryMinusCaseEval(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r39_geo", `{
		"mappings": {
			"properties": {
				"name": {"type": "keyword"},
				"loc": {"type": "geo_point"},
				"views": {"type": "integer"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_geo/_doc/1", `{"name":"far","loc":{"lat":34.0522,"lon":-118.2437},"views":10}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_geo/_doc/2", `{"name":"near","loc":{"lat":40.7306,"lon":-73.9352}}`)

	// F9: _geo_distance sort orders "near" before "far" and populates sort values
	wSort, mSort := doRound39JSON(t, srv, http.MethodPost, "/r39_geo/_search", `{
		"sort": [{"_geo_distance": {"loc": {"lat": 40.7128, "lon": -74.0060}, "order": "asc"}, "unit": "km"}]
	}`)
	if wSort.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", wSort.Code, wSort.Body.String())
	}
	hits := mSort["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 || hits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 (near) first in _geo_distance sort, got %+v", hits)
	}

	// F14: evalNumericExpr handles CASE ... THEN -5 ELSE 0 END and POW(...)
	row := map[string]any{"a": float64(10)}
	if got := evalNumericExpr(row, "(CASE WHEN `a` > 5 THEN -5 ELSE 0 END) + POW(2, 3)"); got != 3 {
		t.Fatalf("expected -5 + 8 = 3 from evalNumericExpr, got %v", got)
	}
}

func TestRound39_F12_DeleteTombstoneVersionAndUpdateByQueryReindexVersions(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r39_ver", `{"mappings":{"properties":{"v":{"type":"integer"}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_ver/_doc/1?version=5&version_type=external", `{"v":1}`)

	// Delete with lower external version (3 <= 5) -> 409 conflict
	wDelLow, _ := doRound39JSON(t, srv, http.MethodDelete, "/r39_ver/_doc/1?version=3&version_type=external", "")
	if wDelLow.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on delete with lower external version, got %d", wDelLow.Code)
	}

	// Delete with higher external version (10 > 5) -> 200 OK
	wDelOk, _ := doRound39JSON(t, srv, http.MethodDelete, "/r39_ver/_doc/1?version=10&version_type=external", "")
	if wDelOk.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete with version 10, got %d", wDelOk.Code)
	}

	// Second delete on tombstone with version 8 (<= 10) -> 409 conflict!
	wDelTomb, _ := doRound39JSON(t, srv, http.MethodDelete, "/r39_ver/_doc/1?version=8&version_type=external", "")
	if wDelTomb.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on tombstone with version 8 <= 10, got %d: %s", wDelTomb.Code, wDelTomb.Body.String())
	}

	// Update by query increments version and syncs s.docVersions
	doRound39JSON(t, srv, http.MethodPut, "/r39_ver/_doc/2", `{"v":10}`)
	verBefore := srv.getDocVersion("r39_ver", "2")
	doRound39JSON(t, srv, http.MethodPost, "/r39_ver/_update_by_query", `{
		"script": {"source": "ctx._source.v = 20"}
	}`)
	if gotVer := srv.getDocVersion("r39_ver", "2"); gotVer <= verBefore {
		t.Fatalf("expected s.getDocVersion > %d after _update_by_query, got %d", verBefore, gotVer)
	}

	// Reindex with version_type=external preserves external version 7 in s.docVersions of dest
	doRound39JSON(t, srv, http.MethodPut, "/r39_ver/_doc/3?version=7&version_type=external", `{"v":30}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_ver_dst", `{"mappings":{"properties":{"v":{"type":"integer"}}}}`)
	doRound39JSON(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": "r39_ver", "query": {"ids": {"values": ["3"]}}},
		"dest": {"index": "r39_ver_dst", "version_type": "external"}
	}`)
	if gotDstVer := srv.getDocVersion("r39_ver_dst", "3"); gotDstVer != 7 {
		t.Fatalf("expected dest doc 3 version=7 after external reindex, got %d", gotDstVer)
	}
}

func TestRound39_F15_F16_F19_PostScriptSearchAndSuggestAndNestedDocID(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r39_post", `{
		"mappings": {
			"properties": {
				"name": {"type": "completion"},
				"tag": {"type": "keyword"},
				"val": {"type": "double"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_post/_doc/docA", `{"name":"apple","tag":"keep","val":10,"items":[{"sku":"s1"}]}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_post/_doc/docB", `{"name":"apricot","tag":"drop","val":20,"items":[{"sku":"s2"}]}`)

	// F15: function_score with random_score + runtime script filter (complex script that runs post-SQL)
	w15, m15 := doRound39JSON(t, srv, http.MethodPost, "/r39_post/_search", `{
		"query": {
			"function_score": {
				"query": {
					"script": {
						"script": "doc['tag'].value.substring(0, 1) == 'k'"
					}
				},
				"random_score": {"seed": 42, "field": "_id"}
			}
		}
	}`)
	if w15.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w15.Code, w15.Body.String())
	}
	hits15 := m15["hits"].(map[string]any)["hits"].([]any)
	if len(hits15) != 1 || hits15[0].(map[string]any)["_id"] != "docA" {
		t.Fatalf("expected only docA to match inner script query in function_score, got %+v", hits15)
	}
	score15, _ := hits15[0].(map[string]any)["_score"].(float64)
	if score15 <= 0 || score15 >= 1 {
		t.Fatalf("expected random_score in (0, 1), got %v", score15)
	}

	// F16: completion suggest with regex and alias filter
	doRound39JSON(t, srv, http.MethodPost, "/_aliases", `{
		"actions": [{
			"add": {
				"index": "r39_post",
				"alias": "r39_keep_alias",
				"filter": {"script": {"script": "doc['tag'].value.substring(0, 1) == 'k'"}}
			}
		}]
	}`)
	w16, m16 := doRound39JSON(t, srv, http.MethodPost, "/r39_keep_alias/_search", `{
		"suggest": {
			"s": {
				"regex": "ap.*",
				"completion": {"field": "name"}
			}
		}
	}`)
	if w16.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w16.Code, w16.Body.String())
	}
	suggEntries := m16["suggest"].(map[string]any)["s"].([]any)
	opts := suggEntries[0].(map[string]any)["options"].([]any)
	if len(opts) != 1 || opts[0].(map[string]any)["_id"] != "docA" {
		t.Fatalf("expected completion regex suggest on alias to return only docA, got %+v", opts)
	}

	// F19: nested inner_hits script_fields accesses doc['_id'].value
	w19, m19 := doRound39JSON(t, srv, http.MethodPost, "/r39_post/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.sku": "s1"}},
				"inner_hits": {
					"script_fields": {
						"parent_id": {"script": "doc['_id'].value"}
					}
				}
			}
		}
	}`)
	if w19.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w19.Code, w19.Body.String())
	}
	hit0 := m19["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	ihHit0 := hit0["inner_hits"].(map[string]any)["items"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fields19 := ihHit0["fields"].(map[string]any)["parent_id"].([]any)
	if len(fields19) != 1 || fields19[0] != "docA" {
		t.Fatalf("expected nested inner_hits doc['_id'].value == 'docA', got %+v", fields19)
	}
}

func TestRound39_F17_F20_EmptyPercentilesNullAndChainedSiblingPipelineAggs(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r39_aggs", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"val": {"type": "double"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_aggs/_doc/1", `{"grp":"a","val":10}`)
	doRound39JSON(t, srv, http.MethodPut, "/r39_aggs/_doc/2", `{"grp":"b","val":30}`)

	// F17: percentiles and percentile_ranks on empty result set return null per key
	w17, m17 := doRound39JSON(t, srv, http.MethodPost, "/r39_aggs/_search", `{
		"size": 0,
		"query": {"term": {"grp": "nonexistent"}},
		"aggs": {
			"p": {"percentiles": {"field": "val", "percents": [50, 95]}},
			"pr": {"percentile_ranks": {"field": "val", "values": [10, 20]}}
		}
	}`)
	if w17.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w17.Code, w17.Body.String())
	}
	pVals := m17["aggregations"].(map[string]any)["p"].(map[string]any)["values"].(map[string]any)
	if v50, exists := pVals["50.0"]; !exists || v50 != nil {
		t.Fatalf("expected p.values['50.0'] == nil on empty set, got exists=%v val=%v", exists, v50)
	}
	prVals := m17["aggregations"].(map[string]any)["pr"].(map[string]any)["values"].(map[string]any)
	if r10, exists := prVals["10.0"]; !exists || r10 != nil {
		t.Fatalf("expected pr.values['10.0'] == nil on empty set, got exists=%v val=%v", exists, r10)
	}

	// F20: chained sibling pipeline aggs (terms -> sum, then avg_bucket -> max_bucket)
	w20, m20 := doRound39JSON(t, srv, http.MethodPost, "/r39_aggs/_search", `{
		"size": 0,
		"aggs": {
			"by_grp": {
				"terms": {"field": "grp", "order": {"_key": "asc"}},
				"aggs": {
					"s": {"sum": {"field": "val"}},
					"d": {"derivative": {"buckets_path": "s"}}
				}
			},
			"max_d": {
				"max_bucket": {"buckets_path": "by_grp>d"}
			}
		}
	}`)
	if w20.Code != http.StatusOK {
		t.Fatalf("expected 200 for chained sibling pipeline agg, got %d: %s", w20.Code, w20.Body.String())
	}
	maxD := m20["aggregations"].(map[string]any)["max_d"].(map[string]any)
	if maxD["value"] != float64(20) {
		t.Fatalf("expected max_d.value=20, got %+v", maxD)
	}
}

func TestRound39_F25_F26_F27_DataStreamRolloverDeleteAndAliasCollisions(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Create data stream logs-app
	wDS, _ := doRound39JSON(t, srv, http.MethodPut, "/_data_stream/logs-app", "")
	if wDS.Code != http.StatusOK {
		t.Fatalf("create data stream failed: %d %s", wDS.Code, wDS.Body.String())
	}
	doRound39JSON(t, srv, http.MethodPost, "/logs-app/_doc", `{"@timestamp":"2026-01-01T00:00:00Z","msg":"first"}`)

	// F25: Rollover data stream
	wRoll, mRoll := doRound39JSON(t, srv, http.MethodPost, "/logs-app/_rollover", `{"conditions":{"max_docs":1}}`)
	if wRoll.Code != http.StatusOK || mRoll["rolled_over"] != true {
		t.Fatalf("expected data stream rollover to succeed, got %d %+v", wRoll.Code, mRoll)
	}
	if mRoll["new_index"] != ".ds-logs-app-000002" {
		t.Fatalf("expected new_index='.ds-logs-app-000002', got %v", mRoll["new_index"])
	}

	// F27: Creating an index with the same name as a data stream or alias fails with 400
	wColl, _ := doRound39JSON(t, srv, http.MethodPut, "/logs-app", `{}`)
	if wColl.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when creating index colliding with data stream, got %d", wColl.Code)
	}

	// F26: Persisted data stream survives cold restart (NewServer on same backend)
	srv2 := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	wGetDS, mGetDS := doRound39JSON(t, srv2, http.MethodGet, "/_data_stream/logs-app", "")
	if wGetDS.Code != http.StatusOK {
		t.Fatalf("expected persisted data stream to be restored on restart, got %d %s", wGetDS.Code, wGetDS.Body.String())
	}
	dsList, _ := mGetDS["data_streams"].([]any)
	if len(dsList) != 1 {
		t.Fatalf("expected 1 restored data stream, got %+v", mGetDS)
	}

	// F26: DELETE /_data_stream/logs-* deletes backing indices and cleans up
	wDelDS, _ := doRound39JSON(t, srv2, http.MethodDelete, "/_data_stream/logs-*", "")
	if wDelDS.Code != http.StatusOK {
		t.Fatalf("expected 200 on wildcard data stream delete, got %d %s", wDelDS.Code, wDelDS.Body.String())
	}
	wAfter, _ := doRound39JSON(t, srv2, http.MethodGet, "/.ds-logs-app-000002", "")
	if wAfter.Code != http.StatusNotFound {
		t.Fatalf("expected backing index .ds-logs-app-000002 to be deleted, got %d", wAfter.Code)
	}
}

func TestRound39_F28_F29_F30_EnrichQueryAndRangePolicyAndAnalyzeUnicodeOffsets(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F28: match enrich policy with query filter
	doRound39JSON(t, srv, http.MethodPut, "/users_src", `{
		"mappings": {"properties": {"email": {"type": "keyword"}, "active": {"type": "boolean"}, "role": {"type": "keyword"}}}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/users_src/_doc/1", `{"email":"a@example.com","active":false,"role":"expired"}`)
	doRound39JSON(t, srv, http.MethodPut, "/users_src/_doc/2", `{"email":"a@example.com","active":true,"role":"admin"}`)

	doRound39JSON(t, srv, http.MethodPut, "/_enrich/policy/active_users_pol", `{
		"match": {
			"indices": "users_src",
			"match_field": "email",
			"enrich_fields": ["role"],
			"query": {"term": {"active": true}}
		}
	}`)

	// F29: range enrich policy with numeric range
	doRound39JSON(t, srv, http.MethodPut, "/tiers_src", `{
		"mappings": {"properties": {"score_range": {"type": "object"}, "tier": {"type": "keyword"}}}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/tiers_src/_doc/1", `{"score_range":{"gte":0,"lte":50},"tier":"bronze"}`)
	doRound39JSON(t, srv, http.MethodPut, "/tiers_src/_doc/2", `{"score_range":{"gte":51,"lte":100},"tier":"gold"}`)

	doRound39JSON(t, srv, http.MethodPut, "/_enrich/policy/tier_range_pol", `{
		"range": {
			"indices": "tiers_src",
			"match_field": "score_range",
			"enrich_fields": ["tier"]
		}
	}`)

	wSim, mSim := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"enrich": {"policy_name": "active_users_pol", "field": "user_email", "target_field": "user_info"}},
				{"enrich": {"policy_name": "tier_range_pol", "field": "score", "target_field": "tier_info"}}
			]
		},
		"docs": [
			{"_source": {"user_email": "a@example.com", "score": 75}}
		]
	}`)
	if wSim.Code != http.StatusOK {
		t.Fatalf("simulate failed: %d %s", wSim.Code, wSim.Body.String())
	}
	simDoc := mSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	userInfo, _ := simDoc["user_info"].(map[string]any)
	if userInfo["role"] != "admin" {
		t.Fatalf("expected active_users_pol with query filter to match role=admin, got %+v", userInfo)
	}
	tierInfo, _ := simDoc["tier_info"].(map[string]any)
	if tierInfo["tier"] != "gold" {
		t.Fatalf("expected tier_range_pol to match tier=gold for score=75, got %+v", tierInfo)
	}

	// F30: _analyze char_filter and tokenizer return Unicode code point offsets
	wAn, mAn := doRound39JSON(t, srv, http.MethodPost, "/_analyze", `{
		"tokenizer": "standard",
		"text": "日本 test"
	}`)
	if wAn.Code != http.StatusOK {
		t.Fatalf("analyze failed: %d %s", wAn.Code, wAn.Body.String())
	}
	tokens := mAn["tokens"].([]any)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %+v", tokens)
	}
	tok0 := tokens[0].(map[string]any)
	tok1 := tokens[1].(map[string]any)
	if tok0["start_offset"] != float64(0) || tok0["end_offset"] != float64(2) {
		t.Fatalf("expected '日本' rune offsets [0, 2], got %+v", tok0)
	}
	if tok1["start_offset"] != float64(3) || tok1["end_offset"] != float64(7) {
		t.Fatalf("expected 'test' rune offsets [3, 7], got %+v", tok1)
	}

	_ = bytes.NewReader(nil)
	_ = context.Background()
}
