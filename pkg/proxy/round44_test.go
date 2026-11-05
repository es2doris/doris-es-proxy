package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound44ProxySearchTermsLookupMembackendInnerHitsCollapseScrollAndAggOrder(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Create lookup index and main index
	doRound39JSON(t, srv, http.MethodPut, "/r44_users", `{
		"mappings": {"properties": {"allowed_depts": {"type": "keyword"}}}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r44_users/_doc/u1?routing=rt_u1&refresh=true", `{"allowed_depts": ["eng"]}`)

	doRound39JSON(t, srv, http.MethodPut, "/r44_docs", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"tags": {"type": "keyword"},
				"scores": {"type": "long", "multi_valued": true},
				"salary": {"type": "long"},
				"comments": {
					"type": "nested",
					"properties": {
						"author": {"type": "keyword"},
						"likes": {"type": "long"}
					}
				}
			}
		}
	}`)

	doRound39JSON(t, srv, http.MethodPut, "/r44_docs/_doc/1?routing=rt_a&refresh=true", `{
		"dept": "eng",
		"tags": ["Alpha", "Beta"],
		"scores": [10, 25],
		"salary": 100,
		"comments": [
			{"author": "alice", "likes": 10},
			{"author": "bob", "likes": 30}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r44_docs/_doc/2?routing=rt_b&refresh=true", `{
		"dept": "eng",
		"tags": ["Gamma"],
		"scores": [5],
		"salary": 100,
		"comments": [
			{"author": "alice", "likes": 5}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r44_docs/_doc/3?routing=rt_a&refresh=true", `{
		"dept": "sales",
		"tags": ["Delta"],
		"scores": [50],
		"salary": 200,
		"comments": [
			{"author": "carol", "likes": 40}
		]
	}`)

	// F13: min_score on nested scoring query (score_mode: "sum") does not prematurely filter on SQL 1.0 placeholder
	_, resF13 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search", `{
		"min_score": 1.5,
		"query": {
			"nested": {
				"path": "comments",
				"score_mode": "sum",
				"query": {"range": {"comments.likes": {"gte": 5}}}
			}
		}
	}`)
	hitsF13 := resF13["hits"].(map[string]any)["hits"].([]any)
	if len(hitsF13) != 1 || hitsF13[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F13 expected doc 1 (2 matching nested comments -> sum score 2.0 >= 1.5) to match, got %+v", hitsF13)
	}

	// F14: Terms lookup preserves req.Routing (?routing=rt_a) AND enforces lookup.Routing
	_, resF14OK := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search?routing=rt_a", `{
		"query": {
			"terms": {
				"dept": {
					"index": "r44_users",
					"id": "u1",
					"path": "allowed_depts",
					"routing": "rt_u1"
				}
			}
		}
	}`)
	hitsF14OK := resF14OK["hits"].(map[string]any)["hits"].([]any)
	if len(hitsF14OK) != 1 || hitsF14OK[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F14 expected only doc 1 (dept=eng, routing=rt_a) to match when lookup routing=rt_u1, got %+v", hitsF14OK)
	}

	_, resF14WrongRouting := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search", `{
		"query": {
			"terms": {
				"dept": {
					"index": "r44_users",
					"id": "u1",
					"path": "allowed_depts",
					"routing": "wrong_routing"
				}
			}
		}
	}`)
	hitsF14Wrong := resF14WrongRouting["hits"].(map[string]any)["hits"].([]any)
	if len(hitsF14Wrong) != 0 {
		t.Fatalf("F14 expected 0 hits when terms lookup routing mismatches stored doc routing, got %+v", hitsF14Wrong)
	}

	// F15: MemoryBackend evalArrayExistsExpr supports numeric range on multi-valued array, two-sided string range, prefix, regexp, and case-insensitive term
	_, resF15 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search", `{
		"query": {
			"bool": {
				"must": [
					{"range": {"scores": {"gte": 20, "lte": 30}}},
					{"range": {"tags": {"gte": "A", "lte": "C"}}},
					{"prefix": {"tags": "Alp"}},
					{"regexp": {"tags": "Bet.*"}},
					{"term": {"tags": {"value": "alpha", "case_insensitive": true}}}
				]
			}
		}
	}`)
	hitsF15 := resF15["hits"].(map[string]any)["hits"].([]any)
	if len(hitsF15) != 1 || hitsF15[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F15 expected doc 1 to match array_exists predicates in MemoryBackend, got %+v", hitsF15)
	}

	// F16: Merged nested inner_hits across multiple same-path clauses pre-merges sort and _source filtering and keeps _score null when sorted
	_, resF16 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search", `{
		"query": {
			"bool": {
				"must": [
					{"term": {"_id": "1"}},
					{
						"bool": {
							"should": [
								{
									"nested": {
										"path": "comments",
										"query": {"term": {"comments.author": "alice"}},
										"inner_hits": {"name": "merged_comm"}
									}
								},
								{
									"nested": {
										"path": "comments",
										"query": {"range": {"comments.likes": {"gte": 5}}},
										"inner_hits": {
											"name": "merged_comm",
											"sort": [{"comments.likes": "desc"}],
											"_source": ["author"]
										}
									}
								}
							]
						}
					}
				]
			}
		}
	}`)
	ihF16 := resF16["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["inner_hits"].(map[string]any)["merged_comm"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(ihF16) != 2 {
		t.Fatalf("F16 expected 2 merged inner_hits for doc 1, got %+v", ihF16)
	}
	ih0 := ihF16[0].(map[string]any)
	ih0Src := ih0["_source"].(map[string]any)
	if ih0Src["author"] != "bob" || ih0["_score"] != nil {
		t.Fatalf("F16 expected bob first with _score=nil when sorted by comments.likes desc, got %+v", ih0)
	}
	if _, hasLikes := ih0Src["likes"]; hasLikes {
		t.Fatalf("F16 expected _source=['author'] filter preserved on merged inner_hits, got %+v", ih0Src)
	}

	// F17: Collapse inner_hits enforces request routing in needsScript mode and decodes _source
	_, resF17 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search?routing=rt_a", `{
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['salary'].value * 1.0"}
			}
		},
		"collapse": {
			"field": "dept",
			"inner_hits": {
				"name": "dept_docs",
				"size": 5
			}
		},
		"sort": [{"dept": "asc"}]
	}`)
	engCollapseHit := resF17["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	engCollapseIH := engCollapseHit["inner_hits"].(map[string]any)["dept_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(engCollapseIH) != 1 || engCollapseIH[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F17 expected collapse inner_hits with ?routing=rt_a to only include doc 1 (excluding doc 2 with rt_b), got %+v", engCollapseIH)
	}

	// F18: Scroll page 2+ preserves track_total_hits relation: "gte" and supports GET/POST /_search/scroll/{scroll_id}
	_, sc1 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search?scroll=1m", `{
		"size": 1,
		"track_total_hits": 2,
		"sort": [{"_id": "asc"}]
	}`)
	scrollID := sc1["_scroll_id"].(string)
	wSc2, sc2 := doRound39JSON(t, srv, http.MethodGet, "/_search/scroll/"+scrollID+"?scroll=1m", "")
	if wSc2.Code != http.StatusOK {
		t.Fatalf("F18 expected GET /_search/scroll/{scroll_id} to succeed, got %d: %v", wSc2.Code, sc2)
	}
	sc2Total := sc2["hits"].(map[string]any)["total"].(map[string]any)
	if sc2Total["value"] != float64(2) || sc2Total["relation"] != "gte" {
		t.Fatalf("F18 expected scroll page 2 total={value:2, relation:'gte'}, got %+v", sc2Total)
	}

	// F20: Deterministic multi-key map order in terms and histogram aggregations
	_, resF20 := doRound39JSON(t, srv, http.MethodPost, "/r44_docs/_search", `{
		"size": 0,
		"aggs": {
			"by_dept": {
				"terms": {
					"field": "dept",
					"order": {"avg_sal": "desc", "_key": "asc"}
				},
				"aggs": {
					"avg_sal": {"avg": {"field": "salary"}}
				}
			},
			"by_sal_hist": {
				"histogram": {
					"field": "salary",
					"interval": 100,
					"order": {"max_sal": "desc", "_key": "asc"}
				},
				"aggs": {
					"max_sal": {"max": {"field": "salary"}}
				}
			}
		}
	}`)
	deptBuckets := resF20["aggregations"].(map[string]any)["by_dept"].(map[string]any)["buckets"].([]any)
	if len(deptBuckets) != 2 || deptBuckets[0].(map[string]any)["key"] != "sales" || deptBuckets[1].(map[string]any)["key"] != "eng" {
		t.Fatalf("F20 expected terms buckets ordered by avg_sal desc (sales=200, eng=100), got %+v", deptBuckets)
	}
	histBuckets := resF20["aggregations"].(map[string]any)["by_sal_hist"].(map[string]any)["buckets"].([]any)
	if len(histBuckets) != 2 || histBuckets[0].(map[string]any)["key"] != float64(200) {
		t.Fatalf("F20 expected histogram buckets ordered by max_sal desc (200 first), got %+v", histBuckets)
	}

	// F21: applyURISearchParams supports repeated sort, fields, _source_include, and clears Source.Disabled
	_, resF21 := doRound39JSON(t, srv, http.MethodGet, "/r44_docs/_search?sort=salary:asc&sort=_id:desc&fields=dept&fields=salary&_source=false&_source_include=dept&_source_include=salary", "")
	hitsF21 := resF21["hits"].(map[string]any)["hits"].([]any)
	firstF21 := hitsF21[0].(map[string]any)
	if firstF21["_id"] != "2" {
		t.Fatalf("F21 expected repeated sort=salary:asc&sort=_id:desc to rank doc 2 (salary=100, id=2) before doc 1 (salary=100, id=1), got %v", firstF21["_id"])
	}
	fieldsF21 := firstF21["fields"].(map[string]any)
	if len(fieldsF21["dept"].([]any)) == 0 || len(fieldsF21["salary"].([]any)) == 0 {
		t.Fatalf("F21 expected both repeated fields=dept and fields=salary, got %+v", fieldsF21)
	}
	srcF21 := firstF21["_source"].(map[string]any)
	if srcF21["dept"] != "eng" || srcF21["salary"] != float64(100) {
		t.Fatalf("F21 expected _source_include to re-enable _source and include dept+salary, got %+v", srcF21)
	}
}

func TestRound44StreamLoadRedirectAuthAndRetry(t *testing.T) {
	// F19: StreamLoadClient preserves Authorization header across 307 redirect from FE to BE and retries transient failure
	var beCalls atomic.Int32
	var seenAuth atomic.Value
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		callNum := beCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if callNum == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"Status":"Fail","Message":"SERVICE_UNAVAILABLE"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`))
	}))
	defer beSrv.Close()

	feSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, beSrv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer feSrv.Close()

	client := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		Database:       "es_db",
		User:           "root",
		Password:       "secret123",
	})
	if err := client.LoadNDJSON(context.Background(), "r44_tbl", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("F19 expected LoadNDJSON to succeed after 307 redirect + transient retry, got %v", err)
	}
	authHdr, _ := seenAuth.Load().(string)
	if !strings.HasPrefix(authHdr, "Basic ") {
		t.Fatalf("F19 expected Basic Authorization header preserved on BE after 307 redirect, got %q", authHdr)
	}
	if beCalls.Load() < 2 {
		t.Fatalf("F19 expected at least 2 BE attempts, got %d", beCalls.Load())
	}
}

func TestRound44IndexSettingsCatSyncSiblingPipelineIngestAndMutations(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r44_mut", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"role": {"type": "keyword"},
				"val": {"type": "long"},
				"title": {"type": "text"}
			}
		}
	}`)

	// F22: handleIndexSettings rejects malformed JSON and nonexistent default_pipeline, and accepts "index.default_pipeline"
	wBadJSON, _ := doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_settings", `{bad_json`)
	if wBadJSON.Code != http.StatusBadRequest {
		t.Fatalf("F22 expected 400 for malformed settings JSON, got %d", wBadJSON.Code)
	}
	wBadPipe, _ := doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_settings", `{"index.default_pipeline": "missing_pipe"}`)
	if wBadPipe.Code != http.StatusBadRequest {
		t.Fatalf("F22 expected 400 for nonexistent default_pipeline, got %d", wBadPipe.Code)
	}
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/valid_pipe", `{
		"processors": [{"set": {"field": "ingested", "value": true}}]
	}`)
	wGoodPipe, _ := doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_settings", `{"settings": {"index.default_pipeline": "valid_pipe"}}`)
	if wGoodPipe.Code != http.StatusOK {
		t.Fatalf("F22 expected 200 for valid index.default_pipeline, got %d", wGoodPipe.Code)
	}

	// F23: handleCatIndices / handleCatAliases sync catalog and 3-segment sibling pipeline agg dependency ordering
	wCatIdx, _ := doRound39JSON(t, srv, http.MethodGet, "/_cat/indices?format=json", "")
	if wCatIdx.Code != http.StatusOK || !strings.Contains(wCatIdx.Body.String(), "r44_mut") {
		t.Fatalf("F23 expected /_cat/indices to list r44_mut, got %s", wCatIdx.Body.String())
	}
	doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_alias/r44_mut_alias", "")
	wCatAlias, _ := doRound39JSON(t, srv, http.MethodGet, "/_cat/aliases?format=json", "")
	if wCatAlias.Code != http.StatusOK || !strings.Contains(wCatAlias.Body.String(), "r44_mut_alias") {
		t.Fatalf("F23 expected /_cat/aliases to list r44_mut_alias, got %s", wCatAlias.Body.String())
	}

	// F27, F28, F29, F30, F31, F32: Ingest processors (_version cleanup, inference, date quoted literals + M/d/H, kv quoted values, bytes validation, copy validation)
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r44_ingest_suite", `{
		"processors": [
			{"script": {"source": "ctx._version = 99; ctx._source.script_ran = true;"}},
			{"inference": {
				"model_id": "sentiment_model",
				"field_map": {"text": "input_text"},
				"target_field": "ml.sentiment",
				"inference_config": {"classification": {"num_top_classes": 2}}
			}},
			{"date": {
				"field": "ts_quoted",
				"formats": ["yyyy-M-d'T'H:mm:ss'Z'"],
				"target_field": "parsed_ts",
				"timezone": "UTC"
			}},
			{"kv": {
				"field": "kv_line",
				"field_split": " ",
				"value_split": "=",
				"target_field": "kv_out"
			}},
			{"bytes": {
				"field": "mem_size",
				"target_field": "mem_bytes"
			}},
			{"copy": {
				"field": "src_val",
				"target_field": "copied_val"
			}}
		]
	}`)
	_, simRes := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/r44_ingest_suite/_simulate", `{
		"docs": [
			{
				"_source": {
					"text": "great service",
					"ts_quoted": "2026-1-5T07:08:09Z",
					"kv_line": "user=\"Alice Smith\" role='admin user' code=42",
					"mem_size": "2kb",
					"src_val": "hello"
				}
			}
		]
	}`)
	firstSimEntry := simRes["docs"].([]any)[0].(map[string]any)
	if firstSimEntry["doc"] == nil {
		t.Fatalf("F27-F32 simulate returned error instead of doc: %+v", firstSimEntry)
	}
	simDoc := firstSimEntry["doc"].(map[string]any)
	simSrc := simDoc["_source"].(map[string]any)
	if _, leakedVersion := simSrc["_version"]; leakedVersion {
		t.Fatalf("F27 expected _version metadata not to leak into _source, got %+v", simSrc)
	}
	mlMap, _ := simSrc["ml"].(map[string]any)
	sentMap, _ := mlMap["sentiment"].(map[string]any)
	if sentMap == nil || sentMap["model_id"] != "sentiment_model" || sentMap["predicted_value"] == nil {
		t.Fatalf("F28 expected inference processor output in ml.sentiment, got %+v", simSrc["ml"])
	}
	if simSrc["parsed_ts"] != "2026-01-05T07:08:09Z" {
		t.Fatalf("F29 expected date processor to parse '2026-1-5T07:08:09Z' to '2026-01-05T07:08:09Z', got %v", simSrc["parsed_ts"])
	}
	kvOut, _ := simSrc["kv_out"].(map[string]any)
	if kvOut["user"] != "Alice Smith" || kvOut["role"] != "admin user" || kvOut["code"] != "42" {
		t.Fatalf("F30 expected quote-aware kv splitting and unquoting, got %+v", kvOut)
	}
	if simSrc["mem_bytes"] != float64(2048) || simSrc["copied_val"] != "hello" {
		t.Fatalf("F31/F32 expected mem_bytes=2048 and copied_val='hello', got %+v", simSrc)
	}

	// F31 & F32 error cases: bytes NaN/negative/non-string rejection and copy same-field / scalar-ancestor rejection
	_, simErrs := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"bytes": {"field": "b"}}
			]
		},
		"docs": [
			{"_source": {"b": "NaN"}},
			{"_source": {"b": "-5kb"}},
			{"_source": {"b": true}}
		]
	}`)
	for i, d := range simErrs["docs"].([]any) {
		if d.(map[string]any)["error"] == nil {
			t.Fatalf("F31 expected bytes processor error on doc %d, got %+v", i, d)
		}
	}
	_, simCopyErr := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"copy": {"field": "a", "target_field": "a.sub"}}
			]
		},
		"docs": [
			{"_source": {"a": "scalar_val"}}
		]
	}`)
	if simCopyErr["docs"].([]any)[0].(map[string]any)["error"] == nil {
		t.Fatalf("F32 expected copy processor error when target_field has scalar ancestor, got %+v", simCopyErr)
	}

	// F26 & F35: _update, _bulk update, and _update_by_query preserve stored _routing under multi-value ?routing=r1,r2 and persist script ctx._routing
	// Reset default_pipeline on r44_mut first
	doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_settings", `{"index.default_pipeline": "_none"}`)
	doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_doc/d1?routing=r1&refresh=true", `{"dept": "eng", "val": 10, "title": "hello world"}`)
	doRound39JSON(t, srv, http.MethodPut, "/r44_mut/_doc/d2?routing=r2&refresh=true", `{"dept": "sales", "val": 20, "title": "hello there"}`)

	// _update_by_query with multi-value ?routing=r1,r2 filter must keep d1's routing as r1 (not "r1,r2") and honor ctx._routing on d2
	doRound39JSON(t, srv, http.MethodPost, "/r44_mut/_update_by_query?routing=r1,r2&refresh=true", `{
		"script": {
			"source": "if (ctx._id == 'd2') { ctx._routing = 'r2_new'; } ctx._source.val = ctx._source.val + 5;"
		}
	}`)
	_, getD1 := doRound39JSON(t, srv, http.MethodGet, "/r44_mut/_doc/d1", "")
	if getD1["_routing"] != "r1" {
		t.Fatalf("F26 expected d1 _routing preserved as 'r1' after _update_by_query?routing=r1,r2, got %v", getD1["_routing"])
	}
	_, getD2 := doRound39JSON(t, srv, http.MethodGet, "/r44_mut/_doc/d2", "")
	if getD2["_routing"] != "r2_new" {
		t.Fatalf("F26 expected d2 _routing updated to 'r2_new' by _update_by_query script, got %v", getD2["_routing"])
	}

	// F35: Single _update and _bulk update persist ctx._routing mutation
	doRound39JSON(t, srv, http.MethodPost, "/r44_mut/_update/d1?refresh=true", `{
		"script": {"source": "ctx._routing = 'r1_updated'; ctx._source.val = 50;"}
	}`)
	_, getD1AfterUpd := doRound39JSON(t, srv, http.MethodGet, "/r44_mut/_doc/d1", "")
	if getD1AfterUpd["_routing"] != "r1_updated" {
		t.Fatalf("F35 expected _update script ctx._routing='r1_updated' persisted, got %v", getD1AfterUpd["_routing"])
	}
	doRound39JSON(t, srv, http.MethodPost, "/r44_mut/_bulk?refresh=true", strings.Join([]string{
		`{"update":{"_id":"d1"}}`,
		`{"script":{"source":"ctx._routing = 'r1_bulk'; ctx._source.val = 60;"}}`,
		"",
	}, "\n"))
	_, getD1AfterBulk := doRound39JSON(t, srv, http.MethodGet, "/r44_mut/_doc/d1", "")
	if getD1AfterBulk["_routing"] != "r1_bulk" {
		t.Fatalf("F35 expected _bulk update script ctx._routing='r1_bulk' persisted, got %v", getD1AfterBulk["_routing"])
	}

	// F33 & F34: Script filter query binding _score and doc['_index'].value / doc['_version'].value in search
	_, resF33F34 := doRound39JSON(t, srv, http.MethodPost, "/r44_mut/_search", `{
		"query": {
			"bool": {
				"must": [
					{"match": {"title": {"query": "hello", "boost": 3.0}}}
				],
				"filter": [
					{"script": {"script": "_score >= 1.0 && doc['_index'].value == 'r44_mut' && doc['_version'].value >= 1"}}
				]
			}
		},
		"script_fields": {
			"meta_check": {
				"script": {"source": "doc['_index'].value + ':' + doc['_id'].value"}
			}
		}
	}`)
	hitsF33F34 := resF33F34["hits"].(map[string]any)["hits"].([]any)
	if len(hitsF33F34) != 2 {
		t.Fatalf("F33/F34 expected both docs to match script filter using _score, doc['_index'].value, and doc['_version'].value, got %+v", hitsF33F34)
	}
}
