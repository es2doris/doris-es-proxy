package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound43_F1_F2_F8_F9_F15_F16_F17_F18_F19_F20_SearchSortGeoAggsAndCollapse(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r43_idx", `{
		"mappings": {
			"properties": {
				"items": {
					"type": "nested",
					"properties": {
						"active": {"type": "boolean"},
						"price": {"type": "double"}
					}
				},
				"loc": {"type": "geo_point"},
				"env": {"type": "keyword"},
				"tags": {"type": "keyword"},
				"price": {"type": "scaled_float", "scaling_factor": 100},
				"ts": {"type": "date"},
				"val": {"type": "double"}
			}
		}
	}`)

	doRound39JSON(t, srv, http.MethodPut, "/r43_idx/_doc/1?refresh=true", `{
		"items": [
			{"active": true, "price": 10},
			{"active": false, "price": 999}
		],
		"loc": "u4pruydqqvj",
		"env": "prod",
		"tags": ["alpha", "beta"],
		"price": 12.34,
		"ts": "2026-01-01T00:00:00Z",
		"val": 10,
		"unmapped_tags": ["foo_bar", "baz_qux"]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r43_idx/_doc/2?refresh=true", `{
		"items": [
			{"active": true, "price": 50}
		],
		"loc": {"lat": 37.7749, "lon": -122.4194},
		"tags": ["alpha", "gamma"],
		"price": 56.78,
		"ts": "2026-01-01T01:00:00Z",
		"val": 30,
		"unmapped_tags": ["other_item"]
	}`)

	// F1: _script sort with nested filter and mode (Painless post-processing path)
	wSort, resSort := doRound39JSON(t, srv, http.MethodPost, "/r43_idx/_search", `{
		"sort": [
			{
				"_script": {
					"type": "number",
					"order": "desc",
					"mode": "max",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}}
					},
					"script": {
						"source": "Math.round(doc['items.price'].value * 2)"
					}
				}
			}
		]
	}`)
	if wSort.Code != http.StatusOK {
		t.Fatalf("F1 _script nested sort failed: %d %s", wSort.Code, wSort.Body.String())
	}
	hitsSort := resSort["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSort) != 2 || hitsSort[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("F1 expected doc 2 (active price 50*2=100) before doc 1 (active price 10*2=20, inactive 999 filtered out), got %+v", hitsSort)
	}

	// F8: _geo_distance sort with geohash origin in both SQL and post-processing sortvalue computation
	wGeo, resGeo := doRound39JSON(t, srv, http.MethodPost, "/r43_idx/_search", `{
		"sort": [
			{
				"_geo_distance": {
					"loc": "u4pruydqqvj",
					"order": "asc",
					"unit": "km"
				}
			}
		]
	}`)
	if wGeo.Code != http.StatusOK {
		t.Fatalf("F8 _geo_distance sort failed: %d %s", wGeo.Code, wGeo.Body.String())
	}
	hitsGeo := resGeo["hits"].(map[string]any)["hits"].([]any)
	if len(hitsGeo) != 2 || hitsGeo[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F8 expected doc 1 (distance ~0) first for geohash origin 'u4pruydqqvj', got %+v", hitsGeo)
	}
	sortValsGeo, _ := hitsGeo[0].(map[string]any)["sort"].([]any)
	if len(sortValsGeo) != 1 || sortValsGeo[0].(float64) > 0.01 {
		t.Fatalf("F8 expected doc 1 sort distance ~0, got %+v", sortValsGeo)
	}

	// F9, F15, F16, F17, F18, F19:
	// - F9: terms agg with missing_bucket: true
	// - F15: terms agg on numeric field ("val") with order: {"_key": "asc"} (no value_type) sorts numerically
	// - F16: terms agg ordered by runtime-scripted stats.avg sub-agg
	// - F17: range sub-agg inside terms with string numeric bounds ("5", "20") normalizes from/to to float64
	// - F18: date_histogram with format "YYYY-MM-dd" and rate sub-agg in value_count mode with script
	// - F19: rate sub-agg nested under date_histogram -> filter scales by rateScaleFactor (24x for 1h -> 1d)
	wAgg, resAgg := doRound39JSON(t, srv, http.MethodPost, "/r43_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_env": {
				"terms": {
					"field": "env",
					"missing_bucket": true
				}
			},
			"by_val_key": {
				"terms": {
					"field": "val",
					"order": {"_key": "asc"}
				},
				"aggs": {
					"rng": {
						"range": {
							"field": "val",
							"ranges": [{"from": "5", "to": "20"}]
						}
					}
				}
			},
			"by_val_script_order": {
				"terms": {
					"field": "val",
					"order": {"st.avg": "desc"}
				},
				"aggs": {
					"st": {
						"stats": {
							"script": "doc['val'].value * 2"
						}
					}
				}
			},
			"by_hour": {
				"date_histogram": {
					"field": "ts",
					"fixed_interval": "1h",
					"format": "YYYY-MM-dd"
				},
				"aggs": {
					"r": {
						"rate": {
							"mode": "value_count",
							"unit": "1h",
							"script": "doc['val'].value"
						}
					},
					"flt": {
						"filter": {"match_all": {}},
						"aggs": {
							"r_day": {
								"rate": {
									"mode": "value_count",
									"unit": "1d",
									"script": "doc['val'].value"
								}
							}
						}
					}
				}
			}
		}
	}`)
	if wAgg.Code != http.StatusOK {
		t.Fatalf("F9/F15/F16/F17/F18/F19 search aggs failed: %d %s", wAgg.Code, wAgg.Body.String())
	}
	aggsMap := resAgg["aggregations"].(map[string]any)
	envBuckets := aggsMap["by_env"].(map[string]any)["buckets"].([]any)
	foundMissingBucket := false
	for _, b := range envBuckets {
		bm := b.(map[string]any)
		if bm["key"] == nil && bm["doc_count"] == float64(1) {
			foundMissingBucket = true
		}
	}
	if !foundMissingBucket {
		t.Fatalf("F9 expected missing_bucket with key=nil and doc_count=1, got %+v", envBuckets)
	}
	valKeyBuckets := aggsMap["by_val_key"].(map[string]any)["buckets"].([]any)
	if len(valKeyBuckets) != 2 || valKeyBuckets[0].(map[string]any)["key"] != "10" {
		t.Fatalf("F15 expected numeric _key asc order (10 then 30), got %+v", valKeyBuckets)
	}
	rngBuckets := valKeyBuckets[0].(map[string]any)["rng"].(map[string]any)["buckets"].([]any)
	if len(rngBuckets) != 1 || rngBuckets[0].(map[string]any)["from"] != float64(5) || rngBuckets[0].(map[string]any)["to"] != float64(20) {
		t.Fatalf("F17 expected range sub-agg string bounds normalized to float64(5)/float64(20), got %+v", rngBuckets)
	}
	scriptOrderBuckets := aggsMap["by_val_script_order"].(map[string]any)["buckets"].([]any)
	if len(scriptOrderBuckets) != 2 || scriptOrderBuckets[0].(map[string]any)["key"] != "30" {
		t.Fatalf("F16 expected terms ordered by scripted stats.avg desc (30 first), got %+v", scriptOrderBuckets)
	}
	hourBuckets := aggsMap["by_hour"].(map[string]any)["buckets"].([]any)
	if len(hourBuckets) != 2 || hourBuckets[0].(map[string]any)["key_as_string"] != "2026-01-01" {
		t.Fatalf("F18 expected date_histogram format YYYY-MM-dd -> '2026-01-01', got %+v", hourBuckets)
	}
	if hourBuckets[0].(map[string]any)["r"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("F18 expected rate value_count with script == 1, got %+v", hourBuckets[0])
	}
	fltRate := hourBuckets[0].(map[string]any)["flt"].(map[string]any)["r_day"].(map[string]any)["value"]
	if fltRate != float64(24) {
		t.Fatalf("F19 expected nested filter -> rate (1h bucket, 1d unit) == 24, got %v", fltRate)
	}

	// F20: Collapse on array field and wildcard/regexp on unmapped array field in MemoryBackend
	wCol, resCol := doRound39JSON(t, srv, http.MethodPost, "/r43_idx/_search", `{
		"collapse": {"field": "tags"},
		"sort": [{"val": "desc"}]
	}`)
	if wCol.Code != http.StatusOK {
		t.Fatalf("F20 collapse on array field failed: %d %s", wCol.Code, wCol.Body.String())
	}
	colHits := resCol["hits"].(map[string]any)["hits"].([]any)
	if len(colHits) != 1 || colHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("F20 expected collapse on tags (both docs have first tag 'alpha') to deduplicate to doc 2, got %+v", colHits)
	}
	wWildArr, resWildArr := doRound39JSON(t, srv, http.MethodPost, "/r43_idx/_search", `{
		"query": {
			"bool": {
				"must": [
					{"wildcard": {"unmapped_tags": "foo_*"}},
					{"regexp": {"unmapped_tags": "baz_.*"}}
				]
			}
		}
	}`)
	if wWildArr.Code != http.StatusOK {
		t.Fatalf("F20 wildcard/regexp on unmapped array failed: %d %s", wWildArr.Code, wWildArr.Body.String())
	}
	wildHits := resWildArr["hits"].(map[string]any)["hits"].([]any)
	if len(wildHits) != 1 || wildHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F20 expected doc 1 to match wildcard/regexp on unmapped_tags array elements, got %+v", wildHits)
	}
}

func TestRound43_F11_F12_F13_F14_DorisArrayExistsRewriteCacheKeyCatHealthAndMultiTargetCount(t *testing.T) {
	// F11: rewriteDorisArrayExists rewrites multiple and nested array_exists calls without corrupting string literals
	inSQL := `SELECT * FROM t WHERE array_exists(x -> x = 'array_exists(y -> y, a)', col1) AND NOT array_exists(z -> array_exists(w -> w > 0, z), col2)`
	outSQL := rewriteDorisArrayExists(inSQL)
	if !strings.Contains(outSQL, "array_contains(array_exists(x -> x = 'array_exists(y -> y, a)', IFNULL(col1, CAST([] AS ARRAY<STRING>))), true)") {
		t.Fatalf("F11 expected first array_exists rewritten and string literal preserved, got:\n%s", outSQL)
	}
	if !strings.Contains(outSQL, "array_contains(array_exists(z -> array_contains(array_exists(w -> w > 0, IFNULL(z, CAST([] AS ARRAY<STRING>))), true), IFNULL(col2, CAST([] AS ARRAY<STRING>))), true)") {
		t.Fatalf("F11 expected nested and second array_exists rewritten, got:\n%s", outSQL)
	}

	// F12: buildQueryCacheKey differentiates requests with different routing
	req1 := &esast.SearchRequest{Routing: "tenant_a"}
	req2 := &esast.SearchRequest{Routing: "tenant_b"}
	k1, ok1 := buildQueryCacheKey([]string{"idx"}, req1)
	k2, ok2 := buildQueryCacheKey([]string{"idx"}, req2)
	if !ok1 || !ok2 || k1 == k2 {
		t.Fatalf("F12 expected buildQueryCacheKey to differ when req.Routing differs: k1=%q k2=%q", k1, k2)
	}

	// F13 & F14: /_cat/health endpoint and deduplicated multi-target /_count & /_search
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	doRound39JSON(t, srv, http.MethodPut, "/logs-2026-01", `{
		"aliases": {
			"logs-all": {},
			"logs-jan": {}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/logs-2026-01/_doc/1?refresh=true", `{"msg": "hello"}`)

	reqCat := httptest.NewRequest(http.MethodGet, "/_cat/health?v=true&format=json", nil)
	wCat := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wCat, reqCat)
	if wCat.Code != http.StatusOK || !strings.Contains(wCat.Body.String(), `"status":"green"`) {
		t.Fatalf("F13 expected 200 OK with status:green from /_cat/health, got %d %s", wCat.Code, wCat.Body.String())
	}

	// F14: Overlapping multi-target pattern "logs-*,logs-all,logs-jan" must not double-count doc 1
	wCnt, resCnt := doRound39JSON(t, srv, http.MethodPost, "/logs-*,logs-all,logs-jan/_count", `{}`)
	if wCnt.Code != http.StatusOK || resCnt["count"] != float64(1) {
		t.Fatalf("F14 expected deduplicated count=1 across overlapping patterns/aliases, got %d %+v", wCnt.Code, resCnt)
	}
	wSrch, resSrch := doRound39JSON(t, srv, http.MethodPost, "/logs-*,logs-all,logs-jan/_search", `{}`)
	if wSrch.Code != http.StatusOK {
		t.Fatalf("F14 multi-target _search failed: %d %s", wSrch.Code, wSrch.Body.String())
	}
	hitsSrch := resSrch["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSrch) != 1 {
		t.Fatalf("F14 expected 1 deduplicated hit across overlapping patterns/aliases, got %d", len(hitsSrch))
	}
}

func TestRound43_F24_F25_F26_F27_F28_F29_F30_MutationPathsIngestAndReindex(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r43_mut", `{
		"mappings": {
			"properties": {
				"count": {"type": "integer"},
				"tag": {"type": "keyword"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r43_mut/_doc/1?routing=r-init&refresh=true", `{"count": 10, "tag": "v1"}`)

	// F24: ctx.op = "create" on existing doc returns 409 Conflict, and invalid ctx.op returns 400
	wConflict, _ := doRound39JSON(t, srv, http.MethodPost, "/r43_mut/_update/1", `{
		"script": {"source": "ctx.op = 'create'; ctx._source.count = 20;"}
	}`)
	if wConflict.Code != http.StatusConflict {
		t.Fatalf("F24 expected 409 Conflict when ctx.op='create' on existing document, got %d %s", wConflict.Code, wConflict.Body.String())
	}
	wBadOp, _ := doRound39JSON(t, srv, http.MethodPost, "/r43_mut/_update/1", `{
		"script": {"source": "ctx.op = 'invalid_op';"}
	}`)
	if wBadOp.Code != http.StatusBadRequest {
		t.Fatalf("F24 expected 400 Bad Request for invalid ctx.op, got %d %s", wBadOp.Code, wBadOp.Body.String())
	}

	// F25, F26, F27, F28:
	// - F25: multi-line / block-statement `if` condition in ingest processor
	// - F26: reading `ctx.op` returns "index", and user doc with `"op": "delete"` is not dropped
	// - F27: `fingerprint` with `exclude_fields` and omitted `fields`
	// - F28: `json` processor with `add_to_root: true` strips reserved metadata keys (`_id`, `_index`, `_ingest`) and rejects `add_to_root` + `target_field`
	wSim, resSim := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"set": {
						"if": "if (ctx.a != null) {\n  return ctx.a > 0;\n}\nreturn false;",
						"field": "cond_passed",
						"value": true
					}
				},
				{
					"script": {
						"source": "ctx.tag_done = true;"
					}
				},
				{
					"json": {
						"field": "raw_json",
						"add_to_root": true
					}
				},
				{
					"fingerprint": {
						"exclude_fields": ["raw_json", "op"],
						"target_field": "fp"
					}
				}
			]
		},
		"docs": [
			{
				"_index": "safe_idx",
				"_id": "safe_id",
				"_source": {
					"a": 5,
					"op": "delete",
					"raw_json": "{\"parsed_k\":\"parsed_v\",\"_id\":\"hijack_id\",\"_index\":\"hijack_idx\"}"
				}
			}
		]
	}`)
	if wSim.Code != http.StatusOK {
		t.Fatalf("F25-F28 simulate failed: %d %s", wSim.Code, wSim.Body.String())
	}
	simDoc := resSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if simDoc["_id"] != "safe_id" || simDoc["_index"] != "safe_idx" {
		t.Fatalf("F28 expected _id='safe_id' and _index='safe_idx' not hijacked by json add_to_root, got %+v", simDoc)
	}
	simSrc := simDoc["_source"].(map[string]any)
	if simSrc["cond_passed"] != true || simSrc["op"] != "delete" || simSrc["parsed_k"] != "parsed_v" || simSrc["fp"] == nil {
		t.Fatalf("F25/F26/F27/F28 unexpected simulated _source: %+v", simSrc)
	}

	// F29: Ingest pipeline clearing ctx._routing removes routing instead of falling back to request routing
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/clear_routing_pipe", `{
		"processors": [
			{
				"script": {
					"source": "ctx._routing = null; ctx.cleared = true;"
				}
			}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r43_mut/_doc/2?routing=temp-route&pipeline=clear_routing_pipe&refresh=true", `{"count": 1}`)
	wGet2, resGet2 := doRound39JSON(t, srv, http.MethodGet, "/r43_mut/_doc/2", "")
	if wGet2.Code != http.StatusOK || resGet2["_routing"] != nil {
		t.Fatalf("F29 expected _routing to be cleared by pipeline, got %+v", resGet2)
	}

	// F30: Reindex preserves small explicit versions (< 1e12) with version_type: external and supports _score in query script filter
	doRound39JSON(t, srv, http.MethodPut, "/r43_reidx_src", `{}`)
	doRound39JSON(t, srv, http.MethodPut, "/r43_reidx_dst", `{}`)
	doRound39JSON(t, srv, http.MethodPut, "/r43_reidx_src/_doc/1?version=7&version_type=external&refresh=true", `{"count": 42}`)
	wReidx, resReidx := doRound39JSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {
			"index": "r43_reidx_src",
			"query": {
				"function_score": {
					"query": {"match_all": {}},
					"boost_mode": "replace",
					"script_score": {"script": "15.0"}
				}
			}
		},
		"dest": {
			"index": "r43_reidx_dst",
			"version_type": "external"
		}
	}`)
	if wReidx.Code != http.StatusOK || resReidx["created"] != float64(1) {
		t.Fatalf("F30 reindex failed: %d %+v", wReidx.Code, resReidx)
	}
	_, resDstDoc := doRound39JSON(t, srv, http.MethodGet, "/r43_reidx_dst/_doc/1", "")
	if resDstDoc["_version"] != float64(7) {
		t.Fatalf("F30 expected reindex with version_type=external to preserve small version 7, got %v", resDstDoc["_version"])
	}
}
