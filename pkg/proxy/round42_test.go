package proxy

import (
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound42_F11_F12_F13_MemBackendPhraseCaseConcatUnquotedAndHavingSubAgg(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r42_mb", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"dept": {"type": "keyword"},
				"sub": {"type": "keyword"},
				"val": {"type": "double"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r42_mb/_doc/1?refresh=true", `{"title": "Quick Brown Fox", "dept": "eng,core", "sub": "a", "val": 10}`)
	doRound39JSON(t, srv, http.MethodPut, "/r42_mb/_doc/2?refresh=true", `{"title": "slow turtle", "dept": "sales", "sub": "b"}`)

	// F11: Case-insensitive MATCH_PHRASE and MATCH_PHRASE_PREFIX on standard-analyzed text
	wPhrase, resPhrase := doRound39JSON(t, srv, http.MethodPost, "/r42_mb/_search", `{
		"query": {
			"match_phrase": {
				"title": "quick brown"
			}
		}
	}`)
	if wPhrase.Code != http.StatusOK {
		t.Fatalf("F11 match_phrase failed: %d %s", wPhrase.Code, wPhrase.Body.String())
	}
	hits := resPhrase["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F11 expected doc 1 from case-insensitive match_phrase, got %+v", hits)
	}

	wPrefix, resPrefix := doRound39JSON(t, srv, http.MethodPost, "/r42_mb/_search", `{
		"query": {
			"match_phrase_prefix": {
				"title": "quick bro"
			}
		}
	}`)
	if wPrefix.Code != http.StatusOK {
		t.Fatalf("F11 match_phrase_prefix failed: %d %s", wPrefix.Code, wPrefix.Body.String())
	}
	hitsPrefix := resPrefix["hits"].(map[string]any)["hits"].([]any)
	if len(hitsPrefix) != 1 || hitsPrefix[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F11 expected doc 1 from case-insensitive match_phrase_prefix, got %+v", hitsPrefix)
	}

	// F12 & F13: Multi-level bucket agg (CONCAT with comma in dept) + sub-agg min/max on bucket with all-null metric values
	wAgg, resAgg := doRound39JSON(t, srv, http.MethodPost, "/r42_mb/_search", `{
		"size": 0,
		"aggs": {
			"by_dept": {
				"terms": {"field": "dept"},
				"aggs": {
					"by_sub": {
						"terms": {"field": "sub"},
						"aggs": {
							"min_val": {"min": {"field": "val"}}
						}
					}
				}
			}
		}
	}`)
	if wAgg.Code != http.StatusOK {
		t.Fatalf("F12/F13 agg search failed: %d %s", wAgg.Code, wAgg.Body.String())
	}
	buckets := resAgg["aggregations"].(map[string]any)["by_dept"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("F12 expected 2 dept buckets, got %+v", buckets)
	}
	for _, bRaw := range buckets {
		b := bRaw.(map[string]any)
		subBuckets := b["by_sub"].(map[string]any)["buckets"].([]any)
		if len(subBuckets) != 1 {
			t.Fatalf("F12 expected 1 sub-bucket for dept %v, got %+v", b["key"], subBuckets)
		}
		sb := subBuckets[0].(map[string]any)
		minVal := sb["min_val"].(map[string]any)["value"]
		if b["key"] == "sales" && minVal != nil {
			t.Fatalf("F13 expected min_val == nil for sales bucket with null val, got %v", minVal)
		}
		if b["key"] == "eng,core" && minVal != float64(10) {
			t.Fatalf("F12 expected min_val == 10 for eng,core bucket, got %v", minVal)
		}
	}
}

func TestRound42_F14_F15_F16_MappingDynamicPersistenceAndDataStreamHeadReadDoc(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F14: dynamic: "strict" persisted and returned in GET /{index}, GET /{index}/_mapping, GET /_mapping, GET /_cluster/state
	doRound39JSON(t, srv, http.MethodPut, "/r42_dyn", `{
		"mappings": {
			"dynamic": "strict",
			"properties": {
				"host": {"type": "keyword"}
			}
		}
	}`)
	_, resIdx := doRound39JSON(t, srv, http.MethodGet, "/r42_dyn", "")
	idxMappings := resIdx["r42_dyn"].(map[string]any)["mappings"].(map[string]any)
	if idxMappings["dynamic"] != "strict" {
		t.Fatalf("F14 expected GET /r42_dyn mappings.dynamic == 'strict', got %+v", idxMappings)
	}
	_, resMap := doRound39JSON(t, srv, http.MethodGet, "/r42_dyn/_mapping", "")
	mapMappings := resMap["r42_dyn"].(map[string]any)["mappings"].(map[string]any)
	if mapMappings["dynamic"] != "strict" {
		t.Fatalf("F14 expected GET /r42_dyn/_mapping mappings.dynamic == 'strict', got %+v", mapMappings)
	}
	_, resState := doRound39JSON(t, srv, http.MethodGet, "/_cluster/state", "")
	stateMappings := resState["metadata"].(map[string]any)["indices"].(map[string]any)["r42_dyn"].(map[string]any)["mappings"].(map[string]any)["_doc"].(map[string]any)
	if stateMappings["dynamic"] != "strict" {
		t.Fatalf("F14 expected GET /_cluster/state mappings._doc.dynamic == 'strict', got %+v", stateMappings)
	}

	// F15 & F16: Data stream HEAD /{index}, Wildcard HEAD /r42_*, and GET /{ds}/_doc/{id}
	doRound39JSON(t, srv, http.MethodPut, "/_index_template/r42_ds_tpl", `{
		"index_patterns": ["r42-logs-*"],
		"data_stream": {},
		"template": {
			"mappings": {
				"properties": {
					"@timestamp": {"type": "date"},
					"msg": {"type": "keyword"}
				}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/_data_stream/r42-logs-app", "")
	doRound39JSON(t, srv, http.MethodPut, "/r42-logs-app/_doc/doc-1?refresh=true", `{"@timestamp": "2025-01-01T00:00:00Z", "msg": "boot"}`)

	wHeadDS, _ := doRound39JSON(t, srv, http.MethodHead, "/r42-logs-app", "")
	if wHeadDS.Code != http.StatusOK {
		t.Fatalf("F15 expected HEAD /r42-logs-app 200, got %d", wHeadDS.Code)
	}
	wHeadWild, _ := doRound39JSON(t, srv, http.MethodHead, "/r42*", "")
	if wHeadWild.Code != http.StatusOK {
		t.Fatalf("F15 expected HEAD /r42* 200, got %d", wHeadWild.Code)
	}
	wGetDSDoc, resDSDoc := doRound39JSON(t, srv, http.MethodGet, "/r42-logs-app/_doc/doc-1", "")
	if wGetDSDoc.Code != http.StatusOK || resDSDoc["found"] != true {
		t.Fatalf("F16 expected GET /r42-logs-app/_doc/doc-1 200 found:true, got %d %+v", wGetDSDoc.Code, resDSDoc)
	}
	wHeadDSDoc, _ := doRound39JSON(t, srv, http.MethodHead, "/r42-logs-app/_doc/doc-1", "")
	if wHeadDSDoc.Code != http.StatusOK {
		t.Fatalf("F16 expected HEAD /r42-logs-app/_doc/doc-1 200, got %d", wHeadDSDoc.Code)
	}
}

func TestRound42_F17_F18_F19_ScriptScoreWithRangeFilterStdDevSigmaAndFieldValueFactorMissing(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r42_score", `{
		"mappings": {
			"properties": {
				"category": {"type": "keyword"},
				"price": {"type": "double"},
				"factor": {"type": "double"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r42_score/_doc/1?refresh=true", `{"category": "books", "price": 20, "factor": 2}`)
	doRound39JSON(t, srv, http.MethodPut, "/r42_score/_doc/2?refresh=true", `{"category": "books", "price": 40}`)

	// F17: script_score wrapping a range query with min_score does not drop docs by re-shredding
	wSS, resSS := doRound39JSON(t, srv, http.MethodPost, "/r42_score/_search", `{
		"query": {
			"script_score": {
				"query": {
					"range": {"price": {"gte": 10}}
				},
				"script": {
					"source": "doc['price'].value * 2"
				},
				"min_score": 50
			}
		}
	}`)
	if wSS.Code != http.StatusOK {
		t.Fatalf("F17 script_score failed: %d %s", wSS.Code, wSS.Body.String())
	}
	ssHits := resSS["hits"].(map[string]any)["hits"].([]any)
	if len(ssHits) != 1 || ssHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("F17 expected doc 2 (score 80 >= 50), got %+v", ssHits)
	}

	// F18: terms ordered by extended_stats.std_deviation_bounds.upper_sampling with sigma: 3
	wTerms, resTerms := doRound39JSON(t, srv, http.MethodPost, "/r42_score/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {
					"field": "category",
					"order": {"stats.std_deviation_bounds.upper_sampling": "desc"}
				},
				"aggs": {
					"stats": {
						"extended_stats": {
							"field": "price",
							"sigma": 3
						}
					}
				}
			}
		}
	}`)
	if wTerms.Code != http.StatusOK {
		t.Fatalf("F18 terms order by upper_sampling failed: %d %s", wTerms.Code, wTerms.Body.String())
	}
	catBuckets := resTerms["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(catBuckets) != 1 {
		t.Fatalf("F18 expected 1 category bucket, got %+v", catBuckets)
	}

	// F19: field_value_factor on missing field without "missing" fallback produces score 0 (not 1)
	wFVF, resFVF := doRound39JSON(t, srv, http.MethodPost, "/r42_score/_search", `{
		"query": {
			"function_score": {
				"query": {"term": {"_id": "2"}},
				"field_value_factor": {
					"field": "factor",
					"modifier": "none"
				},
				"boost_mode": "replace"
			}
		}
	}`)
	if wFVF.Code != http.StatusOK {
		t.Fatalf("F19 function_score failed: %d %s", wFVF.Code, wFVF.Body.String())
	}
	fvfHits := resFVF["hits"].(map[string]any)["hits"].([]any)
	if len(fvfHits) != 1 || math.Abs(fvfHits[0].(map[string]any)["_score"].(float64)) > 1e-9 {
		t.Fatalf("F19 expected score 0 for missing field_value_factor field, got %+v", fvfHits)
	}
}

func TestRound42_F20_F26_F27_F28_IngestRemoveKeepWildcardScriptMetaForeachMapConvertAndJsonStrict(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F20: remove processor with keep wildcard on nested map and array index deletion
	wSim1, resSim1 := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"remove": {"field": "arr.1"}},
				{"remove": {"keep": ["user.name*", "arr"]}}
			]
		},
		"docs": [
			{
				"_index": "idx",
				"_id": "1",
				"_source": {
					"user": {"name_first": "Alice", "secret": "drop"},
					"arr": ["a", "b", "c"],
					"other": "drop"
				}
			}
		]
	}`)
	if wSim1.Code != http.StatusOK {
		t.Fatalf("F20 simulate failed: %d %s", wSim1.Code, wSim1.Body.String())
	}
	simDoc1 := resSim1["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	userMap, _ := simDoc1["user"].(map[string]any)
	arrOut, _ := simDoc1["arr"].([]any)
	if userMap["name_first"] != "Alice" || userMap["secret"] != nil || len(arrOut) != 2 || arrOut[1] != "c" || simDoc1["other"] != nil {
		t.Fatalf("F20 unexpected simulated source: %+v", simDoc1)
	}

	// F26: ingest script processor does not pollute ctx.size() with _index/_id/_routing and preserves metadata on ctx.op = 'noop'
	wSim2, resSim2 := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"script": {
						"source": "ctx.key_count = ctx.size(); ctx._routing = 'r-new'; ctx.op = 'noop';"
					}
				}
			]
		},
		"docs": [
			{
				"_index": "idx",
				"_id": "1",
				"_source": {"a": 1, "b": 2}
			}
		]
	}`)
	if wSim2.Code != http.StatusOK {
		t.Fatalf("F26 simulate failed: %d %s", wSim2.Code, wSim2.Body.String())
	}
	simDocWrap2 := resSim2["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if simDocWrap2["_routing"] != "r-new" {
		t.Fatalf("F26 expected _routing='r-new' even on ctx.op='noop', got %+v", simDocWrap2)
	}

	// F27: foreach on map supports _ingest._value removal and _ingest._key rename, and ignore_failure cleans on_failure_*
	wSim3, resSim3 := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"foreach": {
						"field": "labels",
						"processor": {
							"script": {
								"source": "if (ctx._ingest._key == 'drop') { ctx._ingest.remove('_value'); } else { ctx._ingest._key = 'k_' + ctx._ingest._key; }"
							}
						}
					}
				},
				{
					"foreach": {
						"field": "bad_nums",
						"ignore_failure": true,
						"processor": {
							"convert": {"field": "_ingest._value", "type": "integer"}
						}
					}
				}
			]
		},
		"docs": [
			{
				"_index": "idx",
				"_id": "1",
				"_source": {
					"labels": {"env": "prod", "drop": "x"},
					"bad_nums": ["not_an_int"]
				}
			}
		]
	}`)
	if wSim3.Code != http.StatusOK {
		t.Fatalf("F27 simulate failed: %d %s", wSim3.Code, wSim3.Body.String())
	}
	simDoc3 := resSim3["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	src3 := simDoc3["_source"].(map[string]any)
	labels3 := src3["labels"].(map[string]any)
	if labels3["k_env"] != "prod" || labels3["drop"] != nil || labels3["env"] != nil {
		t.Fatalf("F27 expected renamed k_env and removed drop key, got %+v", labels3)
	}
	ing3 := simDoc3["_ingest"].(map[string]any)
	if ing3["on_failure_message"] != nil || ing3["on_failure_processor_type"] != nil {
		t.Fatalf("F27 expected on_failure_* cleaned when ignore_failure:true, got %+v", ing3)
	}

	// F28: convert preserves nil elements in arrays and json processor rejects trailing garbage
	wSim4, resSim4 := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"convert": {"field": "vals", "type": "integer"}}
			]
		},
		"docs": [
			{"_index": "idx", "_id": "1", "_source": {"vals": ["10", null, "20"]}}
		]
	}`)
	if wSim4.Code != http.StatusOK {
		t.Fatalf("F28 convert array with nil failed: %d %s", wSim4.Code, wSim4.Body.String())
	}
	vals4 := resSim4["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)["vals"].([]any)
	if len(vals4) != 3 || vals4[0] != float64(10) || vals4[1] != nil || vals4[2] != float64(20) {
		t.Fatalf("F28 expected [10, nil, 20], got %+v", vals4)
	}

	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r42_bad_json", `{
		"processors": [
			{"json": {"field": "raw"}}
		]
	}`)
	wBadJSON, _ := doRound39JSON(t, srv, http.MethodPut, "/r42_json/_doc/1?pipeline=r42_bad_json", `{"raw": "{\"a\": 1} trailing_garbage"}`)
	if wBadJSON.Code != http.StatusBadRequest {
		t.Fatalf("F28 expected 400 for trailing garbage in json processor, got %d %s", wBadJSON.Code, wBadJSON.Body.String())
	}
}

func TestRound42_F24_F25_F29_F30_UpdateReadOnlyMetaUpdateByQueryPipelineScriptFieldsIsolationAndScriptedMetricNull(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r42_stamp", `{
		"processors": [
			{"set": {"field": "stamped", "value": true}}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r42_upd/_doc/1?refresh=true", `{"val": 10}`)

	// F24: _update rejects read-only ctx._id mutation with 400 script_exception
	wUpdMeta, _ := doRound39JSON(t, srv, http.MethodPost, "/r42_upd/_update/1", `{
		"script": {"source": "ctx._id = 'other-id'"}
	}`)
	if wUpdMeta.Code != http.StatusBadRequest || !strings.Contains(wUpdMeta.Body.String(), "script_exception") {
		t.Fatalf("F24 expected 400 script_exception for ctx._id mutation in _update, got %d %s", wUpdMeta.Code, wUpdMeta.Body.String())
	}

	// F25: _update_by_query with ?pipeline=r42_stamp (and no script) runs ingest pipeline and updates doc
	wUBQ, resUBQ := doRound39JSON(t, srv, http.MethodPost, "/r42_upd/_update_by_query?pipeline=r42_stamp&refresh=true", `{}`)
	if wUBQ.Code != http.StatusOK || resUBQ["updated"] != float64(1) {
		t.Fatalf("F25 expected _update_by_query with pipeline to update 1 doc, got %d %+v", wUBQ.Code, resUBQ)
	}

	// F29 & F30: script_fields isolation, params._source without polluted _id, doc['_id'].value, metric _score, and scripted_metric combine_script returning null
	wSearch, resSearch := doRound39JSON(t, srv, http.MethodPost, "/r42_upd/_search", `{
		"script_fields": {
			"f1": {
				"script": {
					"source": "params._source.injected = 'leaked'; return params._source.containsKey('_id') ? 'bad' : doc['_id'].value;"
				}
			},
			"f2": {
				"script": {
					"source": "return params._source.containsKey('injected') ? 'leaked' : 'clean';"
				}
			}
		},
		"aggs": {
			"score_sum": {
				"sum": {
					"script": {"source": "_score * 10"}
				}
			},
			"sm_null": {
				"scripted_metric": {
					"init_script": "params._agg.items = [3, 1, 2]",
					"map_script": "params._agg.items.add(doc['val'].value)",
					"combine_script": "return null;",
					"reduce_script": "return states[0];"
				}
			}
		}
	}`)
	if wSearch.Code != http.StatusOK {
		t.Fatalf("F29/F30 search failed: %d %s", wSearch.Code, wSearch.Body.String())
	}
	hit0 := resSearch["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fields := hit0["fields"].(map[string]any)
	if fields["f1"].([]any)[0] != "1" {
		t.Fatalf("F29 expected f1 == '1' (doc['_id'].value without _id in _source), got %+v", fields["f1"])
	}
	if fields["f2"].([]any)[0] != "clean" {
		t.Fatalf("F29 expected f2 == 'clean' (isolated evalDoc per script_field), got %+v", fields["f2"])
	}
	aggs := resSearch["aggregations"].(map[string]any)
	if aggs["score_sum"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("F29 expected score_sum == 10 (_score=1.0 * 10), got %+v", aggs["score_sum"])
	}
	if aggs["sm_null"].(map[string]any)["value"] != nil {
		t.Fatalf("F30 expected sm_null.value == nil when combine_script returns null, got %+v", aggs["sm_null"])
	}
}
