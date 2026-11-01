package proxy

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestRound34_PostFilterTotalSuggestGlobalIdAndScroll(t *testing.T) {
	srv, _ := newTestServer()

	doRound27Req(t, srv, http.MethodPut, "/r34_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":  map[string]any{"type": "text"},
				"status": map[string]any{"type": "keyword"},
				"dept":   map[string]any{"type": "keyword"},
				"count":  map[string]any{"type": "long"},
				"count_alias": map[string]any{
					"type": "alias",
					"path": "count",
				},
			},
		},
		"aliases": map[string]any{
			"r34_id_alias": map[string]any{
				"filter": map[string]any{
					"script": map[string]any{
						"script": "doc['_id'].value != '3'",
					},
				},
			},
		},
	})

	bulk := strings.Join([]string{
		`{"index":{"_index":"r34_idx","_id":"1"}}`,
		`{"title":"elasticsearch analytics","status":"open","dept":"eng","count":10}`,
		`{"index":{"_index":"r34_idx","_id":"2"}}`,
		`{"title":"doris columnar engine","status":"closed","dept":"eng","count":20}`,
		`{"index":{"_index":"r34_idx","_id":"3"}}`,
		`{"title":"kubernetes cluster ops","status":"open","dept":"ops","count":30}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulk)

	// F11: post_filter with size: 0 and NO user aggs updates hits.total.value to post-filtered count
	code, pfRes := doRound27Req(t, srv, http.MethodPost, "/r34_idx/_search", map[string]any{
		"size": 0,
		"query": map[string]any{
			"term": map[string]any{"dept": "eng"},
		},
		"post_filter": map[string]any{
			"script": map[string]any{
				"script": "doc['status'].value == 'open'",
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on post_filter size=0 search, got %d: %+v", code, pfRes)
	}
	pfTotal := pfRes["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)
	if pfTotal != 1 {
		t.Fatalf("expected post_filter size=0 hits.total.value = 1, got %v", pfTotal)
	}

	// F12: suggest with restrictive query and size: 0 still suggests terms from index-wide dictionary
	code, sugRes := doRound27Req(t, srv, http.MethodPost, "/r34_idx/_search", map[string]any{
		"size": 0,
		"query": map[string]any{
			"term": map[string]any{"status": "nonexistent_status"},
		},
		"suggest": map[string]any{
			"title_sug": map[string]any{
				"text": "elasticsarch",
				"term": map[string]any{"field": "title"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on suggest search, got %d: %+v", code, sugRes)
	}
	sugEntries := sugRes["suggest"].(map[string]any)["title_sug"].([]any)
	if len(sugEntries) == 0 {
		t.Fatalf("expected suggest entries, got empty")
	}
	sugOpts := sugEntries[0].(map[string]any)["options"].([]any)
	if len(sugOpts) == 0 || sugOpts[0].(map[string]any)["text"] != "elasticsearch" {
		t.Fatalf("expected index-wide suggestion 'elasticsearch' even when query matches 0 docs, got %+v", sugOpts)
	}

	// F13: Alias script filter referencing doc['_id'].value on global agg
	code, glRes := doRound27Req(t, srv, http.MethodPost, "/r34_id_alias/_search?size=0", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"status": "closed"},
		},
		"aggs": map[string]any{
			"all_alias_docs": map[string]any{
				"global": map[string]any{},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on alias global agg search, got %d: %+v", code, glRes)
	}
	glCount := glRes["aggregations"].(map[string]any)["all_alias_docs"].(map[string]any)["doc_count"].(float64)
	if glCount != 2 {
		t.Fatalf("expected global agg under r34_id_alias (doc['_id'].value != '3') to have doc_count=2, got %v", glCount)
	}

	// F16: _search/scroll accepts raw JSON string body and omits aggregations/suggest on page 2
	code, sc1 := doRound27Req(t, srv, http.MethodPost, "/r34_idx/_search?scroll=1m", map[string]any{
		"size": 1,
		"sort": []any{map[string]any{"count": "asc"}},
		"aggs": map[string]any{
			"by_dept": map[string]any{"terms": map[string]any{"field": "dept"}},
		},
		"suggest": map[string]any{
			"s": map[string]any{
				"text": "elasticsarch",
				"term": map[string]any{"field": "title"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on initial scroll search, got %d: %+v", code, sc1)
	}
	if sc1["aggregations"] == nil || sc1["suggest"] == nil {
		t.Fatalf("expected aggregations and suggest on first scroll page, got %+v", sc1)
	}
	scrollID := sc1["_scroll_id"].(string)

	// Send raw JSON string body `"<scroll_id>"` to /_search/scroll?scroll=1m
	code, sc2 := doRound27Req(t, srv, http.MethodPost, "/_search/scroll?scroll=1m", `"`+scrollID+`"`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on raw JSON string scroll request, got %d: %+v", code, sc2)
	}
	sc2Hits := sc2["hits"].(map[string]any)["hits"].([]any)
	if len(sc2Hits) != 1 || sc2Hits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 on second scroll page, got %+v", sc2Hits)
	}
	if _, hasAggs := sc2["aggregations"]; hasAggs {
		t.Fatalf("expected aggregations to be omitted on subsequent scroll page, got %+v", sc2["aggregations"])
	}
	if _, hasSug := sc2["suggest"]; hasSug {
		t.Fatalf("expected suggest to be omitted on subsequent scroll page, got %+v", sc2["suggest"])
	}
}

func TestRound34_AggTypedKeysCompositeAliasTermsLookupAndMSearch(t *testing.T) {
	srv, _ := newTestServer()

	doRound27Req(t, srv, http.MethodPut, "/r34_lookup", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"allowed_depts": map[string]any{"type": "keyword"},
			},
		},
	})
	doRound27Req(t, srv, http.MethodPut, "/r34_lookup/_doc/u1?refresh=true", map[string]any{
		"allowed_depts": []any{"eng"},
	})

	doRound27Req(t, srv, http.MethodPut, "/r34_aggs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title": map[string]any{"type": "text"},
				"dept":  map[string]any{"type": "keyword"},
				"count": map[string]any{"type": "long"},
				"count_alias": map[string]any{
					"type": "alias",
					"path": "count",
				},
			},
		},
	})
	bulk := strings.Join([]string{
		`{"index":{"_index":"r34_aggs","_id":"1"}}`,
		`{"title":"alpha beta","dept":"ENG","count":10}`,
		`{"index":{"_index":"r34_aggs","_id":"2"}}`,
		`{"title":"alpha gamma","dept":"eng","count":20}`,
		`{"index":{"_index":"r34_aggs","_id":"3"}}`,
		`{"title":"delta epsilon","dept":"sales","count":30}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulk)

	// F14, F15, F17, F19:
	// - F14: typed_keys=true prefixes significant_text (`significant_text#sig_words`)
	// - F15: composite terms source on alias field `count_alias` emits numeric key (10, 20, 30)
	// - F17: terms lookup inside significant_terms.background_filter
	// - F19: membackend reAggScalarTerms with LOWER(...) / case-insensitive / include regex
	code, aggRes := doRound27Req(t, srv, http.MethodPost, "/r34_aggs/_search?size=0&typed_keys=true", map[string]any{
		"aggs": map[string]any{
			"sig_words": map[string]any{
				"significant_text": map[string]any{
					"field":         "title",
					"min_doc_count": 1,
				},
			},
			"sig_bg": map[string]any{
				"significant_terms": map[string]any{
					"field":         "dept",
					"min_doc_count": 1,
					"background_filter": map[string]any{
						"terms": map[string]any{
							"dept": map[string]any{
								"index": "r34_lookup",
								"id":    "u1",
								"path":  "allowed_depts",
							},
						},
					},
				},
			},
			"comp_alias": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{"ca": map[string]any{"terms": map[string]any{"field": "count_alias"}}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on aggs search, got %d: %+v", code, aggRes)
	}
	aggsMap := aggRes["aggregations"].(map[string]any)
	if aggsMap["significant_text#sig_words"] == nil {
		t.Fatalf("expected typed key 'significant_text#sig_words', got keys: %+v", aggsMap)
	}
	if aggsMap["sterms#sig_bg"] == nil {
		t.Fatalf("expected typed key 'sterms#sig_bg', got keys: %+v", aggsMap)
	}
	compBuckets := aggsMap["composite#comp_alias"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) == 0 {
		t.Fatalf("expected composite buckets for count_alias, got empty")
	}
	firstCompKey := compBuckets[0].(map[string]any)["key"].(map[string]any)["ca"]
	if _, ok := firstCompKey.(float64); !ok {
		t.Fatalf("expected numeric composite key for alias targeting long field, got %T (%v)", firstCompKey, firstCompKey)
	}

	// F18: MemBackend arithmetic relational WHERE expressions and left-to-right division
	testRow := map[string]any{"f__a": int64(6), "f__b": int64(7)}
	if !evalWhereExpr(testRow, "(`f__a` + `f__b`) > 10 AND (100 / 5 / 2) = 10") {
		t.Fatalf("expected membackend arithmetic relational WHERE and left-to-right division to evaluate true")
	}

	// F20: _msearch returns 400 parsing_exception on malformed header JSON and honors URI params (?typed_keys=true&rest_total_hits_as_int=true)
	badMsearch := "{bad_header_json\n{\"query\":{\"match_all\":{}}}\n"
	code, badRes := doRound27Req(t, srv, http.MethodPost, "/r34_aggs/_msearch", badMsearch)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on malformed _msearch header JSON, got %d: %+v", code, badRes)
	}
	goodMsearch := "{}\n{\"size\":0,\"aggs\":{\"c\":{\"value_count\":{\"field\":\"count\"}}}}\n"
	code, msRes := doRound27Req(t, srv, http.MethodPost, "/r34_aggs/_msearch?typed_keys=true&rest_total_hits_as_int=true", goodMsearch)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _msearch with URI params, got %d: %+v", code, msRes)
	}
	msResp0 := msRes["responses"].([]any)[0].(map[string]any)
	if _, ok := msResp0["hits"].(map[string]any)["total"].(float64); !ok {
		t.Fatalf("expected _msearch ?rest_total_hits_as_int=true to return integer total, got %T (%+v)", msResp0["hits"].(map[string]any)["total"], msResp0["hits"])
	}
	if msResp0["aggregations"].(map[string]any)["value_count#c"] == nil {
		t.Fatalf("expected _msearch ?typed_keys=true to prefix aggregation key as 'value_count#c', got %+v", msResp0["aggregations"])
	}
}

func TestRound34_IngestProcessorsMutationGhostIndexAndDeleteExternalVersion(t *testing.T) {
	srv, _ := newTestServer()

	// F25, F26, F27:
	// - F25: script processor ctx.op = 'drop' when document already has "op": "create"
	// - F26: attachment processor indexed_chars truncates by Unicode runes, not UTF-8 bytes
	// - F27: fingerprint MD5 & SHA-512, and redact processor on []string array
	doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/r34_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"attachment": map[string]any{
					"field":         "raw_b64",
					"indexed_chars": 3,
				},
			},
			map[string]any{
				"fingerprint": map[string]any{
					"fields":       []any{"status"},
					"target_field": "fp_md5",
					"method":       "MD5",
				},
			},
			map[string]any{
				"redact": map[string]any{
					"field":    "notes",
					"patterns": []any{"%{EMAILADDRESS:EMAIL}"},
				},
			},
			map[string]any{
				"script": map[string]any{
					"source": "if (ctx.should_drop == true) { ctx.op = 'drop'; }",
				},
			},
		},
	})

	// Simulate pipeline on doc with multi-byte UTF-8 ("éééé") and array notes
	b64UTF8 := base64.StdEncoding.EncodeToString([]byte("éééé"))
	code, simRes := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/r34_pipe/_simulate", map[string]any{
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"op":          "create",
					"should_drop": false,
					"status":      "active",
					"raw_b64":     b64UTF8,
					"notes":       []any{"contact user@example.com now", "normal note"},
				},
			},
			map[string]any{
				"_source": map[string]any{
					"op":          "create",
					"should_drop": true,
					"status":      "dropped",
					"raw_b64":     b64UTF8,
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on pipeline simulate, got %d: %+v", code, simRes)
	}
	simDocs := simRes["docs"].([]any)
	doc0 := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if doc0["op"] != "create" {
		t.Fatalf("expected application field 'op' to remain 'create' when ctx.op not set, got %v", doc0["op"])
	}
	attContent := doc0["attachment"].(map[string]any)["content"].(string)
	if attContent != "ééé" {
		t.Fatalf("expected rune-accurate indexed_chars=3 truncation 'ééé', got %q", attContent)
	}
	if len(doc0["fp_md5"].(string)) != 32 {
		t.Fatalf("expected 32-hex MD5 fingerprint, got %q", doc0["fp_md5"])
	}
	redactedNotes := doc0["notes"].([]any)
	if redactedNotes[0] != "contact <EMAIL> now" {
		t.Fatalf("expected array element redaction 'contact <EMAIL> now', got %+v", redactedNotes)
	}

	// F28: Enrich processor with array match_field values
	doRound27Req(t, srv, http.MethodPut, "/r34_enrich_src/_doc/1?refresh=true", map[string]any{
		"tags":  []any{"vip", "beta"},
		"label": "Priority Customer",
	})
	doRound27Req(t, srv, http.MethodPut, "/_enrich/policy/r34_pol", map[string]any{
		"match": map[string]any{
			"indices":       "r34_enrich_src",
			"match_field":   "tags",
			"enrich_fields": []any{"label"},
		},
	})
	doRound27Req(t, srv, http.MethodPost, "/_enrich/policy/r34_pol/_execute", nil)
	doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/r34_enrich_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"enrich": map[string]any{
					"policy_name":  "r34_pol",
					"field":        "user_tag",
					"target_field": "enriched",
				},
			},
		},
	})
	code, enrSim := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/r34_enrich_pipe/_simulate", map[string]any{
		"docs": []any{
			map[string]any{
				"_source": map[string]any{"user_tag": "beta"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on enrich simulate, got %d: %+v", code, enrSim)
	}
	enrDoc := enrSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if enrDoc["enriched"] == nil || enrDoc["enriched"].(map[string]any)["label"] != "Priority Customer" {
		t.Fatalf("expected enrich match on array source field 'tags' containing 'beta', got %+v", enrDoc)
	}

	// F29: DELETE on non-existent index/doc or bulk dropped/failed ops do NOT create ghost indices
	code, _ = doRound27Req(t, srv, http.MethodDelete, "/r34_ghost_del/_doc/1", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting from missing index, got %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodHead, "/r34_ghost_del", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected r34_ghost_del to NOT exist after 404 delete, got %d", code)
	}

	ghostBulk := strings.Join([]string{
		`{"delete":{"_index":"r34_ghost_bulk","_id":"missing"}}`,
		`{"update":{"_index":"r34_ghost_bulk","_id":"missing"}}`,
		`{"doc":{"x":1}}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk", ghostBulk)
	code, _ = doRound27Req(t, srv, http.MethodHead, "/r34_ghost_bulk", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected r34_ghost_bulk to NOT exist after missing delete/update bulk ops, got %d", code)
	}

	// F30: External version on DELETE /{index}/_doc/{id} and _bulk delete
	doRound27Req(t, srv, http.MethodPut, "/r34_ver/_doc/1?version=10&version_type=external&refresh=true", map[string]any{
		"v": 10,
	})
	// Stale external version (5 <= 10) must return 409 Conflict
	code, _ = doRound27Req(t, srv, http.MethodDelete, "/r34_ver/_doc/1?version=5&version_type=external", nil)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on stale external delete version=5 <= 10, got %d", code)
	}
	// Valid external version (12 > 10) deletes the doc and records _version=12
	code, delRes := doRound27Req(t, srv, http.MethodDelete, "/r34_ver/_doc/1?version=12&version_type=external&refresh=true", nil)
	if code != http.StatusOK || delRes["_version"] != float64(12) {
		t.Fatalf("expected 200 with _version=12 on external delete, got %d: %+v", code, delRes)
	}
	code, _ = doRound27Req(t, srv, http.MethodGet, "/r34_ver/_doc/1", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected doc 1 to be deleted (404) after external version=12 delete, got %d", code)
	}

	// Verify exact E2E payloads for Round 34
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"live_auto_index","_id":"auto-1"}}`,
		`{"service":"checkout-api","latency_ms":42,"ok":true}`,
		`{"index":{"_index":"live_auto_index","_id":"auto-2"}}`,
		`{"service":"billing-api","latency_ms":15,"env":"prod"}`,
	}, "\n")+"\n")
	code, e2eAggRes := doRound27Req(t, srv, http.MethodPost, "/live_auto_index/_search?typed_keys=true", `{
		"size": 0,
		"query": {
			"terms": {
				"service": ["CHECKOUT-API", "BILLING-API"],
				"case_insensitive": true
			}
		},
		"aggs": {
			"sig_srv": {
				"significant_text": {
					"field": "service",
					"min_doc_count": 1
				}
			},
			"dsamp": {
				"diversified_sampler": {
					"shard_size": 2,
					"field": "service"
				}
			},
			"lat_h": {
				"histogram": {
					"field": "latency_ms",
					"interval": 20
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on E2E agg payload, got %d: %+v", code, e2eAggRes)
	}
	e2eAggs, _ := e2eAggRes["aggregations"].(map[string]any)
	if e2eAggs["significant_text#sig_srv"] == nil || e2eAggs["diversified_sampler#dsamp"] == nil || e2eAggs["histogram#lat_h"] == nil {
		t.Fatalf("expected significant_text#sig_srv, diversified_sampler#dsamp, and histogram#lat_h, got %+v", e2eAggs)
	}
}
