package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound41_F9_F11_F12_SortUnmappedMappingConflictAndDynamicStrict(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r41_idx", `{
		"mappings": {
			"dynamic": "strict",
			"properties": {
				"status": {"type": "keyword"},
				"count": {"type": "long"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_idx/_doc/1?refresh=true", `{"status": "ok", "count": 10}`)

	// F9: Sort on unmapped field without unmapped_type or ignore_unmapped -> HTTP 400
	wSort, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_idx/_search", `{
		"sort": [{"unknown_sort": {"order": "asc"}}]
	}`)
	if wSort.Code != http.StatusBadRequest || !strings.Contains(wSort.Body.String(), "search_phase_execution_exception") {
		t.Fatalf("F9 expected HTTP 400 search_phase_execution_exception for unmapped sort, got %d %s", wSort.Code, wSort.Body.String())
	}

	// F9: Sort with ignore_unmapped: true succeeds
	wSortOK, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_idx/_search", `{
		"sort": [{"unknown_sort": {"order": "asc", "ignore_unmapped": true}}]
	}`)
	if wSortOK.Code != http.StatusOK {
		t.Fatalf("F9 expected HTTP 200 with ignore_unmapped:true, got %d %s", wSortOK.Code, wSortOK.Body.String())
	}

	// F11: PUT /{index}/_mapping with conflicting field type -> HTTP 400 illegal_argument_exception
	wMap, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_idx/_mapping", `{
		"properties": {
			"status": {"type": "long"}
		}
	}`)
	if wMap.Code != http.StatusBadRequest || !strings.Contains(wMap.Body.String(), "cannot be changed from type") {
		t.Fatalf("F11 expected HTTP 400 type conflict on PutMapping, got %d %s", wMap.Code, wMap.Body.String())
	}

	// F12: Indexing unmapped field into dynamic:strict index -> HTTP 400 strict_dynamic_mapping_exception
	wStrict, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_idx/_doc/2", `{"status": "ok", "extra_unmapped": 1}`)
	if wStrict.Code != http.StatusBadRequest || !strings.Contains(wStrict.Body.String(), "strict_dynamic_mapping_exception") {
		t.Fatalf("F12 expected HTTP 400 strict_dynamic_mapping_exception on PutDoc, got %d %s", wStrict.Code, wStrict.Body.String())
	}

	// F2/F12: Indexing malformed long value -> HTTP 400 mapper_parsing_exception
	wMalformed, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_idx/_doc/3", `{"status": "ok", "count": "not_a_long"}`)
	if wMalformed.Code != http.StatusBadRequest || !strings.Contains(wMalformed.Body.String(), "mapper_parsing_exception") {
		t.Fatalf("F2/F12 expected HTTP 400 mapper_parsing_exception on malformed long, got %d %s", wMalformed.Code, wMalformed.Body.String())
	}
}

func TestRound41_F13_F14_F15_F16_F17_UpdateRetryNestedSortSearchAfterTermsPartitionAndHaving(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F14: Multi-level nested sort with relative field name
	doRound39JSON(t, srv, http.MethodPut, "/r41_nested", `{
		"mappings": {
			"properties": {
				"tag": {"type": "keyword"},
				"val": {"type": "long"},
				"comments": {
					"type": "nested",
					"properties": {
						"replies": {
							"type": "nested",
							"properties": {
								"likes": {"type": "long"}
							}
						}
					}
				}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_nested/_doc/1?refresh=true", `{
		"tag": "alpha",
		"val": 10,
		"comments": [{"replies": [{"likes": 5}]}]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_nested/_doc/2?refresh=true", `{
		"tag": "beta",
		"comments": [{"replies": [{"likes": 50}]}]
	}`)

	wNestedSort, mNestedSort := doRound39JSON(t, srv, http.MethodPost, "/r41_nested/_search", `{
		"sort": [
			{
				"likes": {
					"order": "desc",
					"nested": {
						"path": "comments",
						"nested": {
							"path": "comments.replies"
						}
					}
				}
			}
		]
	}`)
	if wNestedSort.Code != http.StatusOK {
		t.Fatalf("F14 multi-level nested sort failed: %d %s", wNestedSort.Code, wNestedSort.Body.String())
	}
	hits := mNestedSort["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 || hits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("F14 expected doc 2 first in multi-level nested sort, got %+v", hits)
	}

	// F15: search_after with fewer elements than sort -> HTTP 400 illegal_argument_exception
	wSA, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_nested/_search", `{
		"sort": [
			{"tag": {"order": "asc"}},
			{"_id": {"order": "asc"}}
		],
		"search_after": ["alpha"]
	}`)
	if wSA.Code != http.StatusBadRequest || !strings.Contains(wSA.Body.String(), "illegal_argument_exception") {
		t.Fatalf("F15 expected HTTP 400 illegal_argument_exception when search_after has fewer elements than sort, got %d %s", wSA.Code, wSA.Body.String())
	}

	// F16: terms aggregation include partition with num_partitions=2
	wPart0, mPart0 := doRound39JSON(t, srv, http.MethodPost, "/r41_nested/_search", `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {
					"field": "tag",
					"include": {"partition": 0, "num_partitions": 2}
				}
			}
		}
	}`)
	wPart1, mPart1 := doRound39JSON(t, srv, http.MethodPost, "/r41_nested/_search", `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {
					"field": "tag",
					"include": {"partition": 1, "num_partitions": 2}
				}
			}
		}
	}`)
	if wPart0.Code != http.StatusOK || wPart1.Code != http.StatusOK {
		t.Fatalf("F16 partition terms search failed: %d / %d", wPart0.Code, wPart1.Code)
	}
	b0 := mPart0["aggregations"].(map[string]any)["by_tag"].(map[string]any)["buckets"].([]any)
	b1 := mPart1["aggregations"].(map[string]any)["by_tag"].(map[string]any)["buckets"].([]any)
	if len(b0)+len(b1) != 2 {
		t.Fatalf("F16 expected partitions 0 and 1 to partition the 2 tags disjointly, got %d + %d", len(b0), len(b1))
	}

	// F17: MemBackend HAVING on GROUP BY sub-aggregation rows filters out groups where COUNT(f__val) == 0
	aggRows, err := mb.QueryAggs(context.Background(), "WITH `base_matched` AS (SELECT * FROM `es_db`.`r41_nested` WHERE `__DORIS_DELETE_SIGN__` = 0)\nSELECT 'by_tag.avg_val' AS `_agg_name`, CAST(`f__tag` AS STRING) AS `_bucket_key`, CAST(COALESCE(AVG(`f__val`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__tag` IS NOT NULL GROUP BY `_bucket_key` HAVING COUNT(`f__val`) > 0")
	if err != nil {
		t.Fatalf("F17 QueryAggs failed: %v", err)
	}
	if len(aggRows) != 1 || aggRows[0].BucketKey != "alpha" {
		t.Fatalf("F17 expected only bucket 'alpha' (where f__val is non-null) to pass HAVING COUNT(f__val) > 0, got %+v", aggRows)
	}

	// F13: _update with retry_on_conflict
	wUpd, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_nested/_update/1?retry_on_conflict=2&refresh=true", `{
		"doc": {"val": 99}
	}`)
	if wUpd.Code != http.StatusOK {
		t.Fatalf("F13 update with retry_on_conflict=2 failed: %d %s", wUpd.Code, wUpd.Body.String())
	}
}

func TestRound41_F18_F19_F20_StreamLoadBatchingRedirectAndDataStreamTemplate(t *testing.T) {
	// F18 + F19: StreamLoad redirect from FE to BE preserves Authorization and Stream Load headers, and BulkStreamLoad splits oversized batches
	var beAuthHeader, beFormatHeader string
	var batchCount int32
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&batchCount, 1)
		beAuthHeader = r.Header.Get("Authorization")
		beFormatHeader = r.Header.Get("format")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`))
	}))
	defer beSrv.Close()

	feSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, beSrv.URL+"/api/es_db/r41_tbl/_stream_load", http.StatusTemporaryRedirect)
	}))
	defer feSrv.Close()

	slClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		User:           "root",
		Password:       "secret",
		Database:       "es_db",
		MaxBatchBytes:  50,
	})
	sqlBackend := NewDorisSQLBackend(nil, slClient)
	err := sqlBackend.StreamLoad(context.Background(), "r41_tbl", []byte("{\"_id\":\"1\",\"payload\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n{\"_id\":\"2\",\"payload\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}\n"), false)
	if err != nil {
		t.Fatalf("F18/F19 StreamLoad failed: %v", err)
	}
	if atomic.LoadInt32(&batchCount) != 2 {
		t.Fatalf("F18 expected 2 sub-batches across Stream Load, got %d", atomic.LoadInt32(&batchCount))
	}
	if beAuthHeader == "" || beFormatHeader != "json" {
		t.Fatalf("F19 expected Authorization and format=json preserved across FE->BE redirect, got auth=%q format=%q", beAuthHeader, beFormatHeader)
	}

	// F20: CreateDataStream applies matching index template mappings to .ds-<name>-000001
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	doRound39JSON(t, srv, http.MethodPut, "/_index_template/logs_tpl", `{
		"index_patterns": ["logs-*"],
		"data_stream": {},
		"template": {
			"mappings": {
				"properties": {
					"host": {"type": "keyword"}
				}
			}
		}
	}`)
	wDS, _ := doRound39JSON(t, srv, http.MethodPut, "/_data_stream/logs-app", `{}`)
	if wDS.Code != http.StatusOK {
		t.Fatalf("F20 create data stream failed: %d %s", wDS.Code, wDS.Body.String())
	}
	wMap, mMap := doRound39JSON(t, srv, http.MethodGet, "/.ds-logs-app-000001/_mapping", "")
	if wMap.Code != http.StatusOK {
		t.Fatalf("F20 get backing index mapping failed: %d %s", wMap.Code, wMap.Body.String())
	}
	props := mMap[".ds-logs-app-000001"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if _, hasHost := props["host"]; !hasHost {
		t.Fatalf("F20 expected backing index .ds-logs-app-000001 to inherit template mapping 'host', got %+v", props)
	}
}

func TestRound41_F25_F26_F27_F28_F29_F30_PipelinesUpdateReindexAndValidation(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Register default_pipe, final_pipe, and id_pipe
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/def_pipe", `{
		"processors": [
			{"set": {"field": "from_default", "value": true}},
			{"convert": {"field": "b_one", "type": "boolean", "ignore_missing": true}}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/fin_pipe", `{
		"processors": [
			{"set": {"field": "from_final", "value": true}}
		]
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/id_pipe", `{
		"processors": [
			{"script": {"source": "ctx._id = 'custom-post-id'; ctx.tagged = 'yes';"}}
		]
	}`)

	// F30: Creating an index or template referencing a non-existent pipeline when pipelines are registered -> HTTP 400
	wBadPipe, _ := doRound39JSON(t, srv, http.MethodPut, "/bad_pipe_idx", `{
		"settings": {
			"index.default_pipeline": "missing_pipeline"
		}
	}`)
	if wBadPipe.Code != http.StatusBadRequest || !strings.Contains(wBadPipe.Body.String(), "illegal_argument_exception") {
		t.Fatalf("F30 expected HTTP 400 illegal_argument_exception for unknown default_pipeline, got %d %s", wBadPipe.Code, wBadPipe.Body.String())
	}

	// Create index with default_pipeline and final_pipeline
	doRound39JSON(t, srv, http.MethodPut, "/r41_pipe_idx", `{
		"settings": {
			"index.default_pipeline": "def_pipe",
			"index.final_pipeline": "fin_pipe"
		},
		"mappings": {
			"properties": {
				"title": {"type": "keyword"}
			}
		}
	}`)

	// F28: _bulk with pipeline=_none skips default_pipeline but still runs final_pipeline
	wBulk, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_pipe_idx/_bulk?pipeline=_none&refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"doc1"}`+"\n")
	if wBulk.Code != http.StatusOK {
		t.Fatalf("F28 bulk failed: %d %s", wBulk.Code, wBulk.Body.String())
	}
	_, mDoc1 := doRound39JSON(t, srv, http.MethodGet, "/r41_pipe_idx/_doc/1", "")
	src1 := mDoc1["_source"].(map[string]any)
	if src1["from_default"] != nil || src1["from_final"] != true {
		t.Fatalf("F28 expected pipeline=_none to skip default_pipeline and run final_pipeline, got %+v", src1)
	}

	// F25: _update executes default_pipeline and final_pipeline on the resulting document (including convert boolean "1" -> true)
	doRound39JSON(t, srv, http.MethodPost, "/r41_pipe_idx/_update/1?refresh=true", `{
		"doc": {"title": "doc1_updated", "b_one": "1"}
	}`)
	_, mDoc1Upd := doRound39JSON(t, srv, http.MethodGet, "/r41_pipe_idx/_doc/1", "")
	src1Upd := mDoc1Upd["_source"].(map[string]any)
	if src1Upd["from_default"] != true || src1Upd["from_final"] != true || src1Upd["title"] != "doc1_updated" || src1Upd["b_one"] != true {
		t.Fatalf("F25 expected _update to execute default_pipeline and final_pipeline, got %+v", src1Upd)
	}

	// F29: POST /{index}/_doc with ?pipeline=id_pipe applies pipeline and honors ctx._id override
	wPost, mPost := doRound39JSON(t, srv, http.MethodPost, "/r41_pipe_idx/_doc?pipeline=id_pipe&refresh=true", `{"title":"auto_doc"}`)
	if wPost.Code != http.StatusCreated || mPost["_id"] != "custom-post-id" {
		t.Fatalf("F29 expected POST /_doc with pipeline=id_pipe to set _id='custom-post-id', got %d %+v", wPost.Code, mPost)
	}

	// F26 + F27: _reindex with script changing ctx._id and ctx._index routes to new _index and _id
	wReidx, _ := doRound39JSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r41_pipe_idx"},
		"dest": {"index": "r41_static_dest"},
		"script": {
			"source": "if (ctx._id == '1') { ctx._id = 'reindexed-1'; ctx._index = 'r41_dynamic_dest'; }"
		}
	}`)
	if wReidx.Code != http.StatusOK {
		t.Fatalf("F26/F27 reindex failed: %d %s", wReidx.Code, wReidx.Body.String())
	}
	wDynGet, mDynGet := doRound39JSON(t, srv, http.MethodGet, "/r41_dynamic_dest/_doc/reindexed-1", "")
	if wDynGet.Code != http.StatusOK || mDynGet["found"] != true {
		t.Fatalf("F26/F27 expected doc at /r41_dynamic_dest/_doc/reindexed-1, got %d %+v", wDynGet.Code, mDynGet)
	}

	// F25: foreach processor preserves direct in-place doc mutations made by inner processors
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r41_foreach_uri_remove", `{
		"processors": [
			{
				"foreach": {
					"field": "labels",
					"processor": {
						"set": {
							"field": "labels.{{_ingest._key}}.tier",
							"value": "api"
						}
					}
				}
			},
			{
				"uri_parts": {
					"field": "url.original",
					"target_field": "url",
					"keep_original": true,
					"remove_if_successful": true
				}
			},
			{
				"remove": {
					"field": ["drop_me"],
					"keep": ["title", "labels", "url", "from_default", "from_final"]
				}
			}
		]
	}`)
	wProc, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_pipe_idx/_doc/proc-1?pipeline=r41_foreach_uri_remove&refresh=true", `{
		"title": "ecs_doc",
		"drop_me": "bye",
		"unlisted": "gone",
		"labels": {"svc": {"name": "auth"}},
		"url": {"original": "https://example.com:8443/v1/login?user=alice#top", " existing": "kept"}
	}`)
	if wProc.Code != http.StatusCreated {
		t.Fatalf("F25/F26/F27 pipeline doc index failed: %d %s", wProc.Code, wProc.Body.String())
	}
	_, mProcGet := doRound39JSON(t, srv, http.MethodGet, "/r41_pipe_idx/_doc/proc-1", "")
	procSrc := mProcGet["_source"].(map[string]any)
	svcMap := procSrc["labels"].(map[string]any)["svc"].(map[string]any)
	if svcMap["tier"] != "api" || svcMap["name"] != "auth" {
		t.Fatalf("F25 expected foreach inner set mutation preserved, got %+v", svcMap)
	}
	urlMap := procSrc["url"].(map[string]any)
	if urlMap["original"] != "https://example.com:8443/v1/login?user=alice#top" || urlMap["domain"] != "example.com" || urlMap[" existing"] != "kept" {
		t.Fatalf("F26 expected uri_parts to preserve url.original and sibling keys, got %+v", urlMap)
	}
	if _, hasDrop := procSrc["drop_me"]; hasDrop {
		t.Fatalf("F27 expected drop_me removed, got %+v", procSrc)
	}

	// F28: Explicitly requesting a non-existent pipeline on write returns 400 illegal_argument_exception
	wMissingPipe, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_pipe_idx/_doc/bad?pipeline=does_not_exist", `{"title":"x"}`)
	if wMissingPipe.Code != http.StatusBadRequest || !strings.Contains(wMissingPipe.Body.String(), "illegal_argument_exception") {
		t.Fatalf("F28 expected 400 illegal_argument_exception for missing pipeline, got %d %s", wMissingPipe.Code, wMissingPipe.Body.String())
	}

	// F29: _reindex with default internal versioning starts new destination docs at _version: 1
	if mDynGet["_version"] != float64(1) {
		t.Fatalf("F29 expected new destination doc _version=1 under internal versioning, got %v", mDynGet["_version"])
	}

	// _update_by_query with pipeline changing ctx._id deletes old _id and writes new _id
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/rename_id_pipe", `{
		"processors": [
			{"script": {"source": "ctx._id = 'renamed-post-id'; ctx.title = 'renamed';"}}
		]
	}`)
	rawUBQ, _ := json.Marshal(map[string]any{
		"query": map[string]any{"term": map[string]any{"_id": "custom-post-id"}},
	})
	wUBQ, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_pipe_idx/_update_by_query?pipeline=rename_id_pipe&refresh=true", string(rawUBQ))
	if wUBQ.Code != http.StatusOK {
		t.Fatalf("F26 _update_by_query failed: %d %s", wUBQ.Code, wUBQ.Body.String())
	}
	wOldGet, _ := doRound39JSON(t, srv, http.MethodGet, "/r41_pipe_idx/_doc/custom-post-id", "")
	wNewGet, mNewGet := doRound39JSON(t, srv, http.MethodGet, "/r41_pipe_idx/_doc/renamed-post-id", "")
	if wOldGet.Code != http.StatusNotFound || wNewGet.Code != http.StatusOK || mNewGet["found"] != true {
		t.Fatalf("expected old _id deleted (404) and new _id found (200), got old=%d new=%d", wOldGet.Code, wNewGet.Code)
	}

	// Additional coverage for Round 41 proxy/backend paths:
	// 1. handlePutMapping on non-existent index -> 404, and on multi-index alias -> updates all backing indices
	wNoIdxMap, _ := doRound39JSON(t, srv, http.MethodPut, "/no_such_r41_idx/_mapping", `{"properties":{"a":{"type":"keyword"}}}`)
	if wNoIdxMap.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on PutMapping for missing index, got %d", wNoIdxMap.Code)
	}
	doRound39JSON(t, srv, http.MethodPut, "/r41_m1", `{"mappings":{"properties":{"k":{"type":"keyword"},"v":{"type":"long"}}},"aliases":{"r41_both":{}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_m2", `{"mappings":{"properties":{"k":{"type":"keyword"},"v":{"type":"long"}}},"aliases":{"r41_both":{}}}`)
	wAliasMap, _ := doRound39JSON(t, srv, http.MethodPut, "/r41_both/_mapping", `{"properties":{"shared_extra":{"type":"keyword"}}}`)
	if wAliasMap.Code != http.StatusOK {
		t.Fatalf("expected 200 on PutMapping via multi-index alias, got %d %s", wAliasMap.Code, wAliasMap.Body.String())
	}

	// 2. Cross-index top_hits and top_metrics with identical _id across indices, plus terms order by child bucket_script
	doRound39JSON(t, srv, http.MethodPut, "/r41_m1/_doc/same-id?routing=rt1&refresh=true", `{"k":"g1","v":10}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_m2/_doc/same-id?routing=rt2&refresh=true", `{"k":"g1","v":20}`)
	doRound39JSON(t, srv, http.MethodPut, "/r41_m1/_doc/other-id?routing=rt1&refresh=true", `{"k":"g2","v":5}`)

	// Search & Count with ?routing=rt1
	wCntRt, mCntRt := doRound39JSON(t, srv, http.MethodPost, "/r41_both/_count?routing=rt1", `{}`)
	if wCntRt.Code != http.StatusOK || mCntRt["count"] != float64(2) {
		t.Fatalf("expected count=2 for routing=rt1, got %d %+v", wCntRt.Code, mCntRt)
	}
	wSrchRt, mSrchRt := doRound39JSON(t, srv, http.MethodPost, "/r41_both/_search?routing=rt2", `{}`)
	if wSrchRt.Code != http.StatusOK || len(mSrchRt["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit for routing=rt2, got %d %+v", wSrchRt.Code, mSrchRt)
	}

	// Cross-index top_hits, top_metrics, and terms ordered by bucket_script (with sub-top_hits and sub-top_metrics)
	wCross, mCross := doRound39JSON(t, srv, http.MethodPost, "/r41_both/_search", `{
		"size": 0,
		"aggs": {
			"top_docs": {
				"top_hits": {"size": 10, "sort": [{"v": "desc"}]}
			},
			"top_m": {
				"top_metrics": {"metrics": {"field": "v"}, "sort": {"v": "desc"}, "size": 10}
			},
			"by_k": {
				"terms": {
					"field": "k",
					"order": {"doubled": "asc"}
				},
				"aggs": {
					"sum_v": {"sum": {"field": "v"}},
					"doubled": {
						"bucket_script": {
							"buckets_path": {"sv": "sum_v"},
							"script": "params.sv * 2"
						}
					},
					"sub_top": {
						"top_hits": {"size": 5, "sort": [{"v": "desc"}]}
					},
					"sub_tm": {
						"top_metrics": {"metrics": {"field": "v"}, "sort": {"v": "desc"}, "size": 5}
					}
				}
			}
		}
	}`)
	if wCross.Code != http.StatusOK {
		t.Fatalf("cross-index aggs failed: %d %s", wCross.Code, wCross.Body.String())
	}
	thHits := mCross["aggregations"].(map[string]any)["top_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(thHits) != 3 {
		t.Fatalf("expected 3 top_hits across r41_m1 and r41_m2 (preserving both 'same-id' docs), got %d", len(thHits))
	}
	byKBuckets := mCross["aggregations"].(map[string]any)["by_k"].(map[string]any)["buckets"].([]any)
	if len(byKBuckets) != 2 || byKBuckets[0].(map[string]any)["key"] != "g2" {
		t.Fatalf("expected terms ordered by bucket_script asc (g2 first), got %+v", byKBuckets)
	}
	g1SubTopHits := byKBuckets[1].(map[string]any)["sub_top"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(g1SubTopHits) != 2 {
		t.Fatalf("expected 2 sub_top hits in bucket g1 across r41_m1 and r41_m2, got %d", len(g1SubTopHits))
	}

	// 3. Bulk _routing.required on create/delete/update and external version on bulk delete
	doRound39JSON(t, srv, http.MethodPut, "/r41_rt_req", `{"mappings":{"_routing":{"required":true},"properties":{"x":{"type":"keyword"}}}}`)
	wBulkRt, mBulkRt := doRound39JSON(t, srv, http.MethodPost, "/r41_rt_req/_bulk?refresh=true",
		`{"create":{"_id":"1"}}`+"\n"+`{"x":"a"}`+"\n"+
			`{"delete":{"_id":"1"}}`+"\n"+
			`{"index":{"_id":"1","routing":"r1"}}`+"\n"+`{"x":"a"}`+"\n"+
			`{"update":{"_id":"1","routing":"r2"}}`+"\n"+`{"doc":{"x":"b"}}`+"\n"+
			`{"delete":{"_id":"1","routing":"r2"}}`+"\n"+
			`{"delete":{"_id":"missing-ext","routing":"r1","version":7,"version_type":"external"}}`+"\n"+
			`{"index":{"_id":"missing-ext","routing":"r1","version":5,"version_type":"external"}}`+"\n"+`{"x":"old"}`+"\n")
	if wBulkRt.Code != http.StatusOK || mBulkRt["errors"] != true {
		t.Fatalf("expected bulk routing/version errors=true, got %d %+v", wBulkRt.Code, mBulkRt)
	}

	// 4. NormalizeDorisSQL, rewriteDorisArrayExists, ApplyDSNAuth, TraceMeta, and nil DorisSQLBackend helpers
	rewritten := NormalizeDorisSQL("SELECT * FROM `t` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `msg` = 'array_exists(x -> x > 1, arr)''s' AND array_exists(_x -> _x = 'a', `f__tags`)")
	if !strings.Contains(rewritten, "'array_exists(x -> x > 1, arr)''s'") || !strings.Contains(rewritten, "array_contains(array_exists(") {
		t.Fatalf("unexpected NormalizeDorisSQL result: %s", rewritten)
	}
	if dsn := ApplyDSNAuth("root:$(DORIS_PASSWORD)@tcp(127.0.0.1:9030)/default", "admin", "secret"); !strings.Contains(dsn, "admin:secret@") {
		t.Fatalf("expected ApplyDSNAuth to inject user/password, got %s", dsn)
	}
	traceCtx := WithTraceMeta(reqCtx(t), TraceMeta{Traceparent: "00-abc-def-01", OpaqueID: "opq1", RequestID: "req1"})
	if tm, ok := TraceMetaFromContext(traceCtx); !ok || tm.OpaqueID != "opq1" {
		t.Fatalf("expected TraceMetaFromContext to return opq1, got %+v %v", tm, ok)
	}
	sqlCommented := prependSQLTraceComment(traceCtx, "SELECT 1")
	if !strings.HasPrefix(sqlCommented, "/* traceparent=00-abc-def-01, opaque_id=opq1, request_id=req1 */") {
		t.Fatalf("unexpected prependSQLTraceComment: %s", sqlCommented)
	}
	nilBackend := NewDorisSQLBackend(nil, nil)
	nilBackend.SetLogSQL(true)
	_ = nilBackend.Ping(traceCtx)
	_ = nilBackend.ExecDDL(traceCtx, "CREATE TABLE t (id INT)")
	_, _ = nilBackend.QueryHits(traceCtx, "SELECT 1")
	_, _ = nilBackend.QueryAggs(traceCtx, "SELECT 1")
	_, _, _ = nilBackend.GetDocByID(traceCtx, "db", "tbl", "1")
	_, _ = nilBackend.GetDocsByIDs(traceCtx, "db", "tbl", []string{"1"})
	_ = nilBackend.StreamLoad(traceCtx, "tbl", []byte("{}"), true)
	_ = nilBackend.InitCatalog(traceCtx, "db")
	_ = nilBackend.UpsertCatalogEntry(traceCtx, "db", CatalogEntry{EntityType: "index", EntityKey: "idx"})
	_ = nilBackend.DeleteCatalogEntry(traceCtx, "db", "index", "idx")
	_, _ = nilBackend.LoadCatalogEntries(traceCtx, "db")

	// 5. _doris/explain, _doris/ddl, _field_caps with index_filter, and suggest (term, phrase, completion)
	wExp, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_m1/_doris/explain", `{"query":{"term":{"k":"g1"}},"aggs":{"c":{"value_count":{"field":"v"}}}}`)
	if wExp.Code != http.StatusOK {
		t.Fatalf("expected 200 on _doris/explain, got %d", wExp.Code)
	}
	wDDL, _ := doRound39JSON(t, srv, http.MethodGet, "/r41_m1/_doris/ddl", "")
	if wDDL.Code != http.StatusOK {
		t.Fatalf("expected 200 on _doris/ddl, got %d", wDDL.Code)
	}
	reqSQLDDL := httptest.NewRequest(http.MethodGet, "/r41_m1/_doris/ddl?format=sql", nil)
	wSQLDDL := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wSQLDDL, reqSQLDDL)
	if wSQLDDL.Code != http.StatusOK || !strings.Contains(wSQLDDL.Body.String(), "CREATE TABLE") {
		t.Fatalf("expected 200 SQL DDL on _doris/ddl?format=sql, got %d %s", wSQLDDL.Code, wSQLDDL.Body.String())
	}
	wFC, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_both/_field_caps?fields=k,v&include_unmapped=true", `{"index_filter":{"term":{"k":"g1"}}}`)
	if wFC.Code != http.StatusOK {
		t.Fatalf("expected 200 on _field_caps, got %d", wFC.Code)
	}
	wSug, mSug := doRound39JSON(t, srv, http.MethodPost, "/r41_both/_search?doris_explain=true&typed_keys=true&rest_total_hits_as_int=true&scroll=1m", `{
		"query": {"match_all": {}},
		"suggest": {
			"text": "g1",
			"s_term": {"term": {"field": "k", "suggest_mode": "always"}},
			"s_phrase": {"phrase": {"field": "k", "highlight": {"pre_tag": "<em>", "post_tag": "</em>"}}},
			"s_comp": {"prefix": "g", "completion": {"field": "k", "fuzzy": {"fuzziness": 1}}},
			"s_comp_rx": {"regex": "g.*", "completion": {"field": "k"}}
		}
	}`)
	if wSug.Code != http.StatusOK || mSug["_doris_explain"] == nil || mSug["suggest"] == nil {
		t.Fatalf("expected 200 with _doris_explain and suggest, got %d %+v", wSug.Code, mSug)
	}

	// 6. Runtime script bucket sub-aggregations (composite, filters, missing, sampler, histogram, range, filter)
	wRtSub, _ := doRound39JSON(t, srv, http.MethodPost, "/r41_m1/_search", `{
		"size": 0,
		"aggs": {
			"script_terms": {
				"terms": {"script": {"source": "doc['k'].value"}},
				"aggs": {
					"sub_comp": {
						"composite": {
							"sources": [
								{"s_k": {"terms": {"field": "k"}}},
								{"s_v": {"histogram": {"field": "v", "interval": 10}}}
							]
						},
						"aggs": {
							"sc_script": {"sum": {"script": {"source": "doc['v'].value"}}}
						}
					},
					"sub_filters": {
						"filters": {
							"other_bucket": true,
							"filters": {"f1": {"term": {"k": "g1"}}}
						},
						"aggs": {"sf_sum": {"sum": {"field": "v"}}}
					},
					"sub_anon_filters": {
						"filters": {
							"other_bucket": true,
							"filters": [{"term": {"k": "g1"}}]
						}
					},
					"sub_missing": {
						"missing": {"field": "missing_f"},
						"aggs": {"sm_sum": {"sum": {"field": "v"}}}
					},
					"sub_sampler": {
						"sampler": {"shard_size": 10},
						"aggs": {"ss_sum": {"sum": {"field": "v"}}}
					},
					"sub_filter": {
						"filter": {"term": {"k": "g1"}},
						"aggs": {"sfi_sum": {"sum": {"field": "v"}}}
					},
					"sub_hist": {"histogram": {"field": "v", "interval": 10}},
					"sub_dh": {"date_histogram": {"field": "v", "fixed_interval": "1000ms"}},
					"sub_range": {"range": {"field": "v", "ranges": [{"to": 100}]}}
				}
			},
			"top_comp": {
				"composite": {
					"sources": [
						{"s_k": {"terms": {"field": "k"}}},
						{"s_v": {"histogram": {"field": "v", "interval": 10}}}
					]
				},
				"aggs": {
					"tc_script": {"sum": {"script": {"source": "doc['v'].value"}}}
				}
			},
			"top_hist": {
				"histogram": {"field": "v", "interval": 10},
				"aggs": {
					"th_script": {"avg": {"script": {"source": "doc['v'].value"}}}
				}
			},
			"top_range": {
				"range": {"field": "v", "ranges": [{"key": "low", "to": 100}]},
				"aggs": {
					"tr_script": {"max": {"script": {"source": "doc['v'].value"}}}
				}
			},
			"script_hist": {
				"histogram": {"script": {"source": "doc['v'].value"}, "interval": 10},
				"aggs": {"sh_sum": {"sum": {"field": "v"}}}
			},
			"script_dh": {
				"date_histogram": {"script": {"source": "doc['v'].value"}, "fixed_interval": "1000ms"},
				"aggs": {"sdh_sum": {"sum": {"field": "v"}}}
			},
			"script_range": {
				"range": {"script": {"source": "doc['v'].value"}, "ranges": [{"to": 100}]},
				"aggs": {"sr_sum": {"sum": {"field": "v"}}}
			},
			"top_filters": {
				"filters": {"other_bucket": true, "filters": {"f1": {"term": {"k": "g1"}}}},
				"aggs": {"tf_script": {"sum": {"script": {"source": "doc['v'].value"}}}}
			},
			"top_anon_filters": {
				"filters": {"other_bucket": true, "filters": [{"term": {"k": "g1"}}]},
				"aggs": {"taf_script": {"sum": {"script": {"source": "doc['v'].value"}}}}
			},
			"top_global": {
				"global": {},
				"aggs": {"tg_script": {"sum": {"script": {"source": "doc['v'].value"}}}}
			},
			"top_missing": {
				"missing": {"field": "missing_f"},
				"aggs": {"tm_script": {"sum": {"script": {"source": "doc['v'].value"}}}}
			}
		}
	}`)
	if wRtSub.Code != http.StatusOK {
		t.Fatalf("expected 200 on runtime script sub-aggs, got %d %s", wRtSub.Code, wRtSub.Body.String())
	}
	doRound39JSON(t, srv, http.MethodGet, "/r41_m1/_doris/slowlog", "")
	doRound39JSON(t, srv, http.MethodGet, "/_doris/shadow_stats", "")
	doRound39JSON(t, srv, http.MethodPost, "/r41_m1/_terms_enum", `{"field":"k","string":"g"}`)
	doRound39JSON(t, srv, http.MethodPost, "/_analyze", `{"analyzer":"standard","text":"Hello World"}`)
	doRound39JSON(t, srv, http.MethodPut, "/_ilm/policy/my_pol", `{"policy":{"phases":{"hot":{"actions":{}}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/_ilm/policy/my_pol", `{"policy":{"phases":{"hot":{"actions":{}}}}}`)
	doRound39JSON(t, srv, http.MethodGet, "/_ilm/policy/my_pol", "")
	doRound39JSON(t, srv, http.MethodGet, "/_ilm/policy/my_*", "")
	doRound39JSON(t, srv, http.MethodGet, "/_ilm/policy/fallback_pol", "")
	doRound39JSON(t, srv, http.MethodGet, "/_ilm/policy", "")
	doRound39JSON(t, srv, http.MethodHead, "/_ilm/policy/my_pol", "")
	doRound39JSON(t, srv, http.MethodDelete, "/_ilm/policy/my_pol", "")
	doRound39JSON(t, srv, http.MethodDelete, "/_ilm/policy/my_pol", "")
	doRound39JSON(t, srv, http.MethodHead, "/_ilm/policy/my_pol", "")
	doRound39JSON(t, srv, http.MethodGet, "/r41_m1/_ilm/explain", "")
	doRound39JSON(t, srv, http.MethodGet, "/_cluster/state", "")
	doRound39JSON(t, srv, http.MethodGet, "/_cluster/stats", "")
	doRound39JSON(t, srv, http.MethodGet, "/_security/_authenticate", "")
	doRound39JSON(t, srv, http.MethodPut, "/_data_stream/ds_r41", "")
	doRound39JSON(t, srv, http.MethodPut, "/_data_stream/ds_r41", "")
	doRound39JSON(t, srv, http.MethodGet, "/_data_stream/ds_r41", "")
	doRound39JSON(t, srv, http.MethodGet, "/_data_stream", "")
	doRound39JSON(t, srv, http.MethodDelete, "/_data_stream/ds_r41", "")
	doRound39JSON(t, srv, http.MethodDelete, "/_data_stream/ds_r41", "")
	doRound39JSON(t, srv, http.MethodGet, "/_cat/indices?format=json", "")
	doRound39JSON(t, srv, http.MethodGet, "/_cat/aliases?format=json", "")
	if scrollID, ok := mSug["_scroll_id"].(string); ok && scrollID != "" {
		doRound39JSON(t, srv, http.MethodPost, "/_search/scroll", `{"scroll":"1m","scroll_id":"`+scrollID+`"}`)
		doRound39JSON(t, srv, http.MethodDelete, "/_search/scroll", `{"scroll_id":["`+scrollID+`"]}`)
	}
	doRound39JSON(t, srv, http.MethodPost, "/r41_m1/_clone/r41_m1_cloned", `{"settings":{"default_pipeline":"p_def","final_pipeline":"p_fin"},"aliases":{"r41_clone_alias":{}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/_enrich/policy/r41_pol", `{"match":{"indices":"r41_m1","match_field":"k","enrich_fields":["v"]}}`)
	doRound39JSON(t, srv, http.MethodPost, "/_enrich/policy/r41_pol/_execute", "")
	doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"enrich": {"policy_name": "r41_pol", "field": "k", "target_field": "enriched", "max_matches": 2}}
			]
		},
		"docs": [{"_source": {"k": "g1"}}]
	}`)
}

func reqCtx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
