package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound40_F2_InnerHitsAndTopHitsStoredFields(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_f2", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"title": {"type": "keyword"},
				"items": {
					"type": "nested",
					"properties": {
						"name": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f2/_doc/1?refresh=true", `{
		"dept": "eng",
		"title": "backend",
		"items": [{"name": "go"}]
	}`)

	// 1. inner_hits with stored_fields: "_none_" suppresses _source and fields
	w, m := doRound39JSON(t, srv, http.MethodPost, "/r40_f2/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.name": "go"}},
				"inner_hits": {"stored_fields": "_none_"}
			}
		},
		"aggs": {
			"by_dept": {
				"terms": {"field": "dept"},
				"aggs": {
					"top": {
						"top_hits": {"stored_fields": ["title"]}
					}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("search failed: %d %s", w.Code, w.Body.String())
	}
	hits := m["hits"].(map[string]any)["hits"].([]any)
	ihHit := hits[0].(map[string]any)["inner_hits"].(map[string]any)["items"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if _, hasSrc := ihHit["_source"]; hasSrc {
		t.Fatalf("expected inner_hits with stored_fields:_none_ to omit _source, got %+v", ihHit)
	}
	buckets := m["aggregations"].(map[string]any)["by_dept"].(map[string]any)["buckets"].([]any)
	topHit := buckets[0].(map[string]any)["top"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fieldsMap, _ := topHit["fields"].(map[string]any)
	if fieldsMap == nil || fieldsMap["title"] == nil {
		t.Fatalf("expected top_hits with stored_fields:[\"title\"] to populate fields.title, got %+v", topHit)
	}
}

func TestRound40_F9_F17_F18_MemoryBackendRandomScoreNotInAndCaseWithoutElse(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_f9", `{
		"mappings": {
			"properties": {
				"tag": {"type": "keyword"},
				"val": {"type": "long"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f9/_doc/1?refresh=true", `{"tag": "a", "val": 10}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f9/_doc/2?refresh=true", `{"tag": "b", "val": 20}`)

	// 1. Seeded random_score produces deterministic score in (0, 1]
	w1, m1 := doRound39JSON(t, srv, http.MethodPost, "/r40_f9/_search", `{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"random_score": {"seed": 123, "field": "_id"}
			}
		}
	}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("seeded random_score failed: %d %s", w1.Code, w1.Body.String())
	}
	w2, m2 := doRound39JSON(t, srv, http.MethodPost, "/r40_f9/_search", `{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"random_score": {"seed": 123, "field": "_id"}
			}
		}
	}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("second seeded random_score failed: %d", w2.Code)
	}
	hit1 := m1["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	hit2 := m2["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if hit1["_id"] != hit2["_id"] || hit1["_score"] != hit2["_score"] {
		t.Fatalf("expected deterministic seeded random_score order and score, got %+v vs %+v", hit1, hit2)
	}

	// 2. F17: Direct SQL with NOT IN (...) on MemoryBackend
	rows, err := mb.QueryHits(context.Background(), "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_db`.`r40_f9` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `f__tag` NOT IN ('a') ORDER BY `_score` DESC, `_id` ASC LIMIT 10 OFFSET 0")
	if err != nil {
		t.Fatalf("QueryHits NOT IN failed: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "2" {
		t.Fatalf("expected 1 row with ID=2 for NOT IN ('a'), got %+v", rows)
	}

	// 3. F18: Direct SQL with CASE WHEN ... END without ELSE on MemoryBackend
	if val := evalNumericExpr(map[string]any{"f__val": float64(10)}, "CASE WHEN `f__val` > 100 THEN 50 END"); val != float64(0) {
		t.Fatalf("expected unmatched CASE without ELSE to return 0, got %v", val)
	}
	if strVal := evalBucketKeyExpr(map[string]any{"f__val": float64(10)}, "CASE WHEN `f__val` > 100 THEN 'big' END"); strVal != "" {
		t.Fatalf("expected unmatched string CASE without ELSE to return \"\", got %q", strVal)
	}
}

func TestRound40_F11_FieldCapsHonorsNotIndexedAndDocValuesFalse(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_caps_1", `{
		"mappings": {
			"properties": {
				"secret": {"type": "keyword", "index": false},
				"no_dv": {"type": "keyword", "doc_values": false},
				"payload": {"type": "object", "enabled": false},
				"shared": {"type": "keyword", "index": true, "doc_values": true}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_caps_2", `{
		"mappings": {
			"properties": {
				"shared": {"type": "keyword", "index": false, "doc_values": false}
			}
		}
	}`)

	w, m := doRound39JSON(t, srv, http.MethodGet, "/r40_caps_1,r40_caps_2/_field_caps?fields=secret,no_dv,payload,shared", "")
	if w.Code != http.StatusOK {
		t.Fatalf("_field_caps failed: %d %s", w.Code, w.Body.String())
	}
	fields := m["fields"].(map[string]any)
	secretKw := fields["secret"].(map[string]any)["keyword"].(map[string]any)
	if secretKw["searchable"] != false || secretKw["aggregatable"] != true {
		t.Fatalf("expected secret searchable=false aggregatable=true, got %+v", secretKw)
	}
	noDvKw := fields["no_dv"].(map[string]any)["keyword"].(map[string]any)
	if noDvKw["searchable"] != true || noDvKw["aggregatable"] != false {
		t.Fatalf("expected no_dv searchable=true aggregatable=false, got %+v", noDvKw)
	}
	payloadObj := fields["payload"].(map[string]any)["object"].(map[string]any)
	if payloadObj["searchable"] != false || payloadObj["aggregatable"] != false {
		t.Fatalf("expected payload searchable=false aggregatable=false, got %+v", payloadObj)
	}
	sharedKw := fields["shared"].(map[string]any)["keyword"].(map[string]any)
	if sharedKw["searchable"] != true || sharedKw["aggregatable"] != true {
		t.Fatalf("expected shared searchable=true aggregatable=true across mixed indices, got %+v", sharedKw)
	}
	if nonSearch, ok := sharedKw["non_searchable_indices"].([]any); !ok || len(nonSearch) != 1 || nonSearch[0] != "r40_caps_2" {
		t.Fatalf("expected non_searchable_indices=[\"r40_caps_2\"], got %+v", sharedKw["non_searchable_indices"])
	}
	if nonAgg, ok := sharedKw["non_aggregatable_indices"].([]any); !ok || len(nonAgg) != 1 || nonAgg[0] != "r40_caps_2" {
		t.Fatalf("expected non_aggregatable_indices=[\"r40_caps_2\"], got %+v", sharedKw["non_aggregatable_indices"])
	}
}

func TestRound40_F12_F13_RescoreIdsAndUnicodeSuggester(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_f12", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f12/_doc/doc-alpha?refresh=true", `{"title": "café naïve"}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f12/_doc/doc-beta?refresh=true", `{"title": "other text"}`)

	// 1. F12: rescore with ids query boosts doc-beta above doc-alpha
	w, m := doRound39JSON(t, srv, http.MethodPost, "/r40_f12/_search", `{
		"query": {"match_all": {}},
		"rescore": {
			"window_size": 10,
			"query": {
				"rescore_query": {
					"ids": {"values": ["doc-beta"]}
				},
				"query_weight": 1.0,
				"rescore_query_weight": 10.0
			}
		},
		"suggest": {
			"s1": {
				"text": "caffé",
				"term": {"field": "title"}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("search failed: %d %s", w.Code, w.Body.String())
	}
	hits := m["hits"].(map[string]any)["hits"].([]any)
	if hits[0].(map[string]any)["_id"] != "doc-beta" {
		t.Fatalf("expected rescore ids query to boost doc-beta to top hit, got %+v", hits[0])
	}

	// 2. F13: Unicode suggester suggests "café" with rune length 5
	s1 := m["suggest"].(map[string]any)["s1"].([]any)[0].(map[string]any)
	if s1["length"] != float64(5) {
		t.Fatalf("expected rune length 5 for 'caffé', got %v", s1["length"])
	}
	opts := s1["options"].([]any)
	if len(opts) == 0 || opts[0].(map[string]any)["text"] != "café" {
		t.Fatalf("expected suggestion 'café', got %+v", opts)
	}
}

func TestRound40_F14_F15_DataStreamWriteAndSearchAndTemplateWildcards(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// 1. F15: Component and index templates with wildcards and exclusions
	doRound39JSON(t, srv, http.MethodPut, "/_component_template/ct_logs", `{"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/_component_template/ct_metrics", `{"template":{"mappings":{"properties":{"val":{"type":"double"}}}}}`)
	wCT, mCT := doRound39JSON(t, srv, http.MethodGet, "/_component_template/ct_*,-ct_metrics", "")
	if wCT.Code != http.StatusOK {
		t.Fatalf("GET _component_template failed: %d", wCT.Code)
	}
	cts := mCT["component_templates"].([]any)
	if len(cts) != 1 || cts[0].(map[string]any)["name"] != "ct_logs" {
		t.Fatalf("expected only ct_logs from wildcard+exclusion, got %+v", cts)
	}

	doRound39JSON(t, srv, http.MethodPut, "/_index_template/it_logs", `{"index_patterns":["logs-*"],"composed_of":["ct_logs"],"data_stream":{}}`)
	doRound39JSON(t, srv, http.MethodPut, "/_index_template/it_metrics", `{"index_patterns":["metrics-*"]}`)
	wIT, mIT := doRound39JSON(t, srv, http.MethodGet, "/_index_template/it_*,-it_metrics", "")
	if wIT.Code != http.StatusOK {
		t.Fatalf("GET _index_template failed: %d", wIT.Code)
	}
	its := mIT["index_templates"].([]any)
	if len(its) != 1 || its[0].(map[string]any)["name"] != "it_logs" {
		t.Fatalf("expected only it_logs from wildcard+exclusion, got %+v", its)
	}

	// 2. F14: Create data stream, reject duplicate, index and search via data stream name
	wDS, _ := doRound39JSON(t, srv, http.MethodPut, "/_data_stream/logs-app", "")
	if wDS.Code != http.StatusOK {
		t.Fatalf("PUT _data_stream/logs-app failed: %d %s", wDS.Code, wDS.Body.String())
	}
	wDup, mDup := doRound39JSON(t, srv, http.MethodPut, "/_data_stream/logs-app", "")
	if wDup.Code != http.StatusBadRequest || mDup["error"].(map[string]any)["type"] != "resource_already_exists_exception" {
		t.Fatalf("expected 400 resource_already_exists_exception on duplicate data stream, got %d %+v", wDup.Code, mDup)
	}

	// Index into data stream and search via data stream name
	wIdx, _ := doRound39JSON(t, srv, http.MethodPost, "/logs-app/_doc?refresh=true", `{"@timestamp":"2026-11-02T00:00:00Z","msg":"hello ds"}`)
	if wIdx.Code != http.StatusCreated {
		t.Fatalf("POST /logs-app/_doc failed: %d %s", wIdx.Code, wIdx.Body.String())
	}
	wSearch, mSearch := doRound39JSON(t, srv, http.MethodPost, "/logs-app/_search", `{"query":{"match_all":{}}}`)
	if wSearch.Code != http.StatusOK {
		t.Fatalf("search on data stream failed: %d %s", wSearch.Code, wSearch.Body.String())
	}
	total := mSearch["hits"].(map[string]any)["total"].(map[string]any)["value"]
	if total != float64(1) {
		t.Fatalf("expected 1 hit when searching data stream logs-app, got %v", total)
	}
}

func TestRound40_F16_F19_F20_DeletedDocVersionAndScrollAndHitFieldsMeta(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_f16/_doc/1?routing=r1&version=1&version_type=external&refresh=true", `{"v": 1}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_f16/_doc/1?routing=r1&version=2&version_type=external&refresh=true", `{"v": 2}`)

	// 1. F20: fields: ["_routing", "_version", "_seq_no", "_primary_term"]
	wFields, mFields := doRound39JSON(t, srv, http.MethodPost, "/r40_f16/_search", `{
		"fields": ["_routing", "_version", "_seq_no", "_primary_term"]
	}`)
	if wFields.Code != http.StatusOK {
		t.Fatalf("search with meta fields failed: %d", wFields.Code)
	}
	hit0 := mFields["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fMap := hit0["fields"].(map[string]any)
	if fMap["_routing"].([]any)[0] != "r1" || fMap["_version"] == nil || fMap["_seq_no"] == nil || fMap["_primary_term"].([]any)[0] != float64(1) {
		t.Fatalf("expected _routing, _version, _seq_no, _primary_term in fields, got %+v", fMap)
	}

	// 2. F19: Scroll invalid ID returns 404 search_context_missing_exception; exhausted scroll preserves hits.total.value
	wBadScroll, mBadScroll := doRound39JSON(t, srv, http.MethodPost, "/_search/scroll", `{"scroll_id": "invalid-scroll-id"}`)
	if wBadScroll.Code != http.StatusNotFound || mBadScroll["error"].(map[string]any)["type"] != "search_context_missing_exception" {
		t.Fatalf("expected 404 search_context_missing_exception for invalid scroll_id, got %d %+v", wBadScroll.Code, mBadScroll)
	}

	_, mInitScroll := doRound39JSON(t, srv, http.MethodPost, "/r40_f16/_search?scroll=1m", `{"size": 1}`)
	scrollID := mInitScroll["_scroll_id"].(string)
	_, mExhausted := doRound39JSON(t, srv, http.MethodPost, "/_search/scroll", `{"scroll": "1m", "scroll_id": "`+scrollID+`"}`)
	if mExhausted["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected exhausted scroll page to preserve hits.total.value=1, got %+v", mExhausted["hits"])
	}

	// 3. F16: Delete doc 1 with external version=20, clear in-memory docVersion cache, and verify external version <= deleted version is rejected with 409 Conflict via tombstones in MemoryBackend
	wDel, mDel := doRound39JSON(t, srv, http.MethodDelete, "/r40_f16/_doc/1?routing=r1&version=20&version_type=external&refresh=true", "")
	if wDel.Code != http.StatusOK {
		t.Fatalf("delete failed: %d", wDel.Code)
	}
	delVer := int64(mDel["_version"].(float64))
	// Clear in-memory docVersion cache to simulate proxy restart so GetDocByID tombstone is consulted
	srv.mu.Lock()
	srv.docVersions = make(map[string]map[string]int64)
	srv.mu.Unlock()

	wStale, _ := doRound39JSON(t, srv, http.MethodPut, "/r40_f16/_doc/1?routing=r1&version=10&version_type=external&refresh=true", `{"v": 3}`)
	if wStale.Code != http.StatusConflict {
		t.Fatalf("expected stale external version=10 <= deleted version=%d after restart to return 409 Conflict, got %d %s", delVer, wStale.Code, wStale.Body.String())
	}
}

func TestRound40_F24_F25_IngestRedactTargetFieldAndForeachMap(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	w, m := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"redact": {
						"field": "msg",
						"target_field": "redacted_msg",
						"patterns": ["%{EMAILADDRESS:EMAIL}"]
					}
				},
				{
					"foreach": {
						"field": "labels",
						"processor": {
							"set": {
								"field": "norm_labels.{{_ingest._key}}",
								"value": "{{_ingest._value}}"
							}
						}
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"msg": "contact user@example.com today",
					"labels": {"env": "prod", "tier": "backend"}
				}
			}
		]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("simulate failed: %d %s", w.Code, w.Body.String())
	}
	src := m["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if src["msg"] != "contact user@example.com today" {
		t.Fatalf("expected original msg to be preserved when target_field is set, got %v", src["msg"])
	}
	if src["redacted_msg"] != "contact <EMAIL> today" {
		t.Fatalf("expected redacted_msg='contact <EMAIL> today', got %v", src["redacted_msg"])
	}
	norm, _ := src["norm_labels"].(map[string]any)
	if norm["env"] != "prod" || norm["tier"] != "backend" {
		t.Fatalf("expected foreach over map to populate norm_labels, got %+v", norm)
	}
}

func TestRound40_F23_F26_F28_F29_RoutingEnforcementAndReindexRoutingAndOpCreate(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r40_routed", `{
		"mappings": {
			"_routing": {"required": true},
			"properties": {"v": {"type": "long"}}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_routed/_doc/1?routing=r1&refresh=true", `{"v": 1}`)
	doRound39JSON(t, srv, http.MethodPut, "/r40_routed/_doc/2?routing=r2&refresh=true", `{"v": 2}`)

	// 1. F29: GET / HEAD / _source without routing on _routing.required index returns 400; wrong routing returns 404
	if w, _ := doRound39JSON(t, srv, http.MethodGet, "/r40_routed/_doc/1", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("expected GET without routing on _routing.required index to return 400, got %d", w.Code)
	}
	if w, _ := doRound39JSON(t, srv, http.MethodGet, "/r40_routed/_doc/1?routing=r2", ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected GET with mismatched routing=r2 to return 404, got %d", w.Code)
	}
	if w, _ := doRound39JSON(t, srv, http.MethodGet, "/r40_routed/_source/1?routing=r2", ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected GET _source with mismatched routing=r2 to return 404, got %d", w.Code)
	}
	if w, _ := doRound39JSON(t, srv, http.MethodDelete, "/r40_routed/_doc/1?routing=r2", ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected DELETE with mismatched routing=r2 to return 404, got %d", w.Code)
	}

	// 2. F23: _update script mutating ctx._routing persists new routing
	wUpd, mUpd := doRound39JSON(t, srv, http.MethodPost, "/r40_routed/_update/1?routing=r1&refresh=true", `{
		"script": {"source": "ctx._routing = 'r1-new'; ctx._source.v = 10"}
	}`)
	if wUpd.Code != http.StatusOK || mUpd["_routing"] != "r1-new" {
		t.Fatalf("expected _update to persist ctx._routing='r1-new', got %d %+v", wUpd.Code, mUpd)
	}
	if wOld, _ := doRound39JSON(t, srv, http.MethodGet, "/r40_routed/_doc/1?routing=r1", ""); wOld.Code != http.StatusNotFound {
		t.Fatalf("expected old routing=r1 to return 404 after ctx._routing update, got %d", wOld.Code)
	}
	if wNew, _ := doRound39JSON(t, srv, http.MethodGet, "/r40_routed/_doc/1?routing=r1-new", ""); wNew.Code != http.StatusOK {
		t.Fatalf("expected new routing=r1-new to return 200, got %d", wNew.Code)
	}

	// 3. F28: _update_by_query and _delete_by_query honor ?routing= filter
	_, mUBQ := doRound39JSON(t, srv, http.MethodPost, "/r40_routed/_update_by_query?routing=r2&refresh=true", `{
		"script": {"source": "ctx._source.v = 200"}
	}`)
	if mUBQ["updated"] != float64(1) {
		t.Fatalf("expected _update_by_query?routing=r2 to update only 1 doc, got %+v", mUBQ)
	}

	// 4. F26: _reindex with source.routing, dest.routing="=custom-r", and ctx.op = "create"
	wReidx, mReidx := doRound39JSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r40_routed", "routing": "r2"},
		"dest": {"index": "r40_dest", "routing": "=custom-r"},
		"script": {"source": "ctx.op = 'create'"}
	}`)
	if wReidx.Code != http.StatusOK || mReidx["created"] != float64(1) {
		t.Fatalf("expected _reindex with source.routing=r2 and ctx.op='create' to create 1 doc, got %d %+v", wReidx.Code, mReidx)
	}
	_, mDestDoc := doRound39JSON(t, srv, http.MethodGet, "/r40_dest/_doc/2?routing=custom-r", "")
	if mDestDoc["found"] != true || mDestDoc["_routing"] != "custom-r" {
		t.Fatalf("expected reindexed doc 2 to have _routing='custom-r', got %+v", mDestDoc)
	}
	// Second _reindex with ctx.op = 'create' and conflicts=proceed counts version_conflicts=1
	_, mReidxConflict := doRound39JSON(t, srv, http.MethodPost, "/_reindex?conflicts=proceed&refresh=true", `{
		"source": {"index": "r40_routed", "routing": "r2"},
		"dest": {"index": "r40_dest", "routing": "=custom-r"},
		"script": {"source": "ctx.op = 'create'"}
	}`)
	if mReidxConflict["version_conflicts"] != float64(1) {
		t.Fatalf("expected version_conflicts=1 when ctx.op='create' targets existing doc, got %+v", mReidxConflict)
	}
}
