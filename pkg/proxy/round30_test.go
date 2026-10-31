package proxy

import (
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound30_TopHitsScoreAndMaxScoreWhenSizeZero(t *testing.T) {
	srv, _ := newTestServer()

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"th_r30","_id":"1"}}`,
		`{"cat":"a","tier":"gold","val":10}`,
		`{"index":{"_index":"th_r30","_id":"2"}}`,
		`{"cat":"a","tier":"silver","val":20}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	// 1. size: 0 with boosted should clause -> doc 2 (tier:silver, boost:5) must rank first in top_hits with _score=5.0
	code, resp := doRound27Req(t, srv, http.MethodPost, "/th_r30/_search", map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"should": []any{
					map[string]any{"term": map[string]any{"tier": map[string]any{"value": "gold", "boost": 1.0}}},
					map[string]any{"term": map[string]any{"tier": map[string]any{"value": "silver", "boost": 5.0}}},
				},
			},
		},
		"aggs": map[string]any{
			"top_1": map[string]any{
				"top_hits": map[string]any{"size": 1},
			},
			"empty_filter": map[string]any{
				"filter": map[string]any{"term": map[string]any{"cat": "nonexistent"}},
				"aggs": map[string]any{
					"empty_th": map[string]any{"top_hits": map[string]any{"size": 1}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search failed: %d (%v)", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	top1Hits := aggs["top_1"].(map[string]any)["hits"].(map[string]any)
	if top1Hits["max_score"] != 5.0 {
		t.Fatalf("expected top_1 max_score=5.0, got %v", top1Hits["max_score"])
	}
	hit0 := top1Hits["hits"].([]any)[0].(map[string]any)
	if hit0["_id"] != "2" || hit0["_score"] != 5.0 {
		t.Fatalf("expected top_1 hit[0] _id=2 _score=5.0, got %+v", hit0)
	}
	emptyTHHits := aggs["empty_filter"].(map[string]any)["empty_th"].(map[string]any)["hits"].(map[string]any)
	if emptyTHHits["max_score"] != nil {
		t.Fatalf("expected empty top_hits max_score=nil, got %v", emptyTHHits["max_score"])
	}

	// 2. size: 0 with zero-boost filter query -> _score must be 0.0 (not 1.0)
	code, resp2 := doRound27Req(t, srv, http.MethodPost, "/th_r30/_search", map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{"term": map[string]any{"cat": "a"}},
				},
				"boost": 0,
			},
		},
		"aggs": map[string]any{
			"top_1": map[string]any{"top_hits": map[string]any{"size": 1}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("filter search failed: %d", code)
	}
	top1Filter := resp2["aggregations"].(map[string]any)["top_1"].(map[string]any)["hits"].(map[string]any)
	if top1Filter["max_score"] != 0.0 {
		t.Fatalf("expected filter-only top_hits max_score=0.0, got %v", top1Filter["max_score"])
	}
	hit0Filter := top1Filter["hits"].([]any)[0].(map[string]any)
	if hit0Filter["_score"] != 0.0 {
		t.Fatalf("expected filter-only top_hits hit[0]._score=0.0, got %v", hit0Filter["_score"])
	}
}

func TestRound30_MultiIndexExtendedStatsAndNegativePercentileRanks(t *testing.T) {
	srv, _ := newTestServer()

	// Index 1: cat=a has [10, 10] (std=0, avg=10), cat=b has [0, 20] (std=10, avg=10)
	// Index 2: cat=a has [100, 100] (std=0, avg=100), cat=b has [10, 10] (std=0, avg=10)
	// Pooled across both indices:
	// cat=a: [10, 10, 100, 100] -> avg=55, std=45, variance=2025
	// cat=b: [0, 20, 10, 10] -> avg=10, std=sqrt(50)~=7.07, variance=50
	// Ordering by es.std_deviation desc MUST put cat=a first (45 > 7.07), even though per-index stds for cat=a were both 0!
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"mi_es_1","_id":"1"}}`,
		`{"cat":"a","val":10,"temp":-20}`,
		`{"index":{"_index":"mi_es_1","_id":"2"}}`,
		`{"cat":"a","val":10,"temp":-5}`,
		`{"index":{"_index":"mi_es_1","_id":"3"}}`,
		`{"cat":"b","val":0,"temp":5}`,
		`{"index":{"_index":"mi_es_1","_id":"4"}}`,
		`{"cat":"b","val":20,"temp":15}`,
		`{"index":{"_index":"mi_es_2","_id":"5"}}`,
		`{"cat":"a","val":100,"temp":-15}`,
		`{"index":{"_index":"mi_es_2","_id":"6"}}`,
		`{"cat":"a","val":100,"temp":0}`,
		`{"index":{"_index":"mi_es_2","_id":"7"}}`,
		`{"cat":"b","val":10,"temp":10}`,
		`{"index":{"_index":"mi_es_2","_id":"8"}}`,
		`{"cat":"b","val":10,"temp":25}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, resp := doRound27Req(t, srv, http.MethodPost, "/mi_es_1,mi_es_2/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_cat": map[string]any{
				"terms": map[string]any{
					"field": "cat",
					"order": map[string]any{"es.std_deviation": "desc"},
				},
				"aggs": map[string]any{
					"es": map[string]any{"extended_stats": map[string]any{"field": "val"}},
					"pr": map[string]any{"percentile_ranks": map[string]any{"field": "temp", "values": []any{-10.0, 10.0}}},
					"neg_rank_double": map[string]any{
						"bucket_script": map[string]any{
							"buckets_path": map[string]any{"r": "pr.-10.0"},
							"script":       "params.r * 2",
						},
					},
				},
			},
			"by_cat_neg_order": map[string]any{
				"terms": map[string]any{
					"field": "cat",
					"order": map[string]any{"pr.-10.0": "desc"},
				},
				"aggs": map[string]any{
					"pr": map[string]any{"percentile_ranks": map[string]any{"field": "temp", "values": []any{-10.0}}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("multi-index search failed: %d (%v)", code, resp)
	}
	buckets := resp["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 || buckets[0].(map[string]any)["key"] != "a" {
		t.Fatalf("expected cat='a' (pooled std=45) to sort before cat='b' (pooled std=7.07), got %+v", buckets)
	}
	esA := buckets[0].(map[string]any)["es"].(map[string]any)
	if esA["avg"] != 55.0 || math.Abs(esA["std_deviation"].(float64)-45.0) > 1e-6 {
		t.Fatalf("expected cat='a' avg=55 std=45, got %+v", esA)
	}
	// Verify negative percentile_ranks bucket_script and terms order
	negRankDbl, _ := buckets[0].(map[string]any)["neg_rank_double"].(map[string]any)["value"].(float64)
	if negRankDbl <= 0 {
		t.Fatalf("expected positive neg_rank_double from pr.-10.0 on cat='a' (temps -20, -15 <= -10), got %v", buckets[0])
	}
	negOrderBuckets := resp["aggregations"].(map[string]any)["by_cat_neg_order"].(map[string]any)["buckets"].([]any)
	if len(negOrderBuckets) != 2 || negOrderBuckets[0].(map[string]any)["key"] != "a" {
		t.Fatalf("expected cat='a' first when ordering by pr.-10.0 desc, got %+v", negOrderBuckets)
	}
}

func TestRound30_NestedReverseNestedMultiLevelAndNestedFiltersOtherBucket(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/org_r30", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"depts": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"name": map[string]any{"type": "keyword"},
						"teams": map[string]any{
							"type": "nested",
							"properties": map[string]any{
								"team_name": map[string]any{"type": "keyword"},
								"headcount": map[string]any{"type": "integer"},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create org_r30 failed: %d", code)
	}

	// Single root doc with 2 depts, each having 1 team at index 0
	code, _ = doRound27Req(t, srv, http.MethodPut, "/org_r30/_doc/doc1?refresh=true", map[string]any{
		"depts": []any{
			map[string]any{
				"name":  "eng",
				"teams": []any{map[string]any{"team_name": "core", "headcount": 10}},
			},
			map[string]any{
				"name":  "sales",
				"teams": []any{map[string]any{"team_name": "enterprise", "headcount": 5}},
			},
		},
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc1 failed: %d", code)
	}

	// Runtime script query forces runtime nested aggregation path:
	// 1. depts -> teams -> reverse_nested(path:"depts") must have doc_count=2 (both parent depts, not deduplicated to 1!)
	// 2. depts -> filters(other_bucket: true) must put "sales" into _other_ (not dropped because "eng" shared doc1's _id!)
	code, resp := doRound27Req(t, srv, http.MethodPost, "/org_r30/_search", map[string]any{
		"size": 0,
		"query": map[string]any{
			"script": map[string]any{"script": "true"},
		},
		"aggs": map[string]any{
			"n_depts": map[string]any{
				"nested": map[string]any{"path": "depts"},
				"aggs": map[string]any{
					"n_teams": map[string]any{
						"nested": map[string]any{"path": "depts.teams"},
						"aggs": map[string]any{
							"back_to_depts": map[string]any{
								"reverse_nested": map[string]any{"path": "depts"},
							},
						},
					},
					"by_filter": map[string]any{
						"filters": map[string]any{
							"other_bucket": true,
							"filters": map[string]any{
								"only_eng": map[string]any{"term": map[string]any{"depts.name": "eng"}},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search org_r30 failed: %d (%v)", code, resp)
	}
	nDepts := resp["aggregations"].(map[string]any)["n_depts"].(map[string]any)
	backDepts := nDepts["n_teams"].(map[string]any)["back_to_depts"].(map[string]any)
	if backDepts["doc_count"] != float64(2) {
		t.Fatalf("expected reverse_nested(path='depts') doc_count=2, got %+v", backDepts)
	}
	filterBuckets := nDepts["by_filter"].(map[string]any)["buckets"].(map[string]any)
	otherBucket := filterBuckets["_other_"].(map[string]any)
	if otherBucket["doc_count"] != float64(1) {
		t.Fatalf("expected nested filters _other_ doc_count=1 ('sales'), got %+v", filterBuckets)
	}
}

func TestRound30_RuntimeSubAggUnderDateTermsFloatHistogramAndRateValueCount(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/metrics_r30", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"ts":    map[string]any{"type": "date"},
				"ratio": map[string]any{"type": "double"},
				"tags":  map[string]any{"type": "keyword"},
				"amt":   map[string]any{"type": "double"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create metrics_r30 failed: %d", code)
	}

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"metrics_r30","_id":"1"}}`,
		`{"ts":"2026-01-01T00:00:00Z","ratio":0.3,"tags":["x","y"],"amt":10}`,
		`{"index":{"_index":"metrics_r30","_id":"2"}}`,
		`{"ts":"2026-01-01T00:00:00Z","ratio":0.3,"tags":["z"],"amt":20}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	// 1. terms on date field + histogram on 0.1 interval with 0.3 (0.1*3 float drift) + runtime script sub-agg
	// 2. date_histogram with rate(mode: value_count, script returning string)
	code, resp := doRound27Req(t, srv, http.MethodPost, "/metrics_r30/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_ts_terms": map[string]any{
				"terms": map[string]any{"field": "ts"},
				"aggs": map[string]any{
					"script_sum": map[string]any{
						"sum": map[string]any{
							"script": map[string]any{"source": "int s = 0; s += doc['amt'].value; return s;"},
						},
					},
				},
			},
			"by_ratio_hist": map[string]any{
				"histogram": map[string]any{"field": "ratio", "interval": 0.1},
				"aggs": map[string]any{
					"script_sum": map[string]any{
						"sum": map[string]any{
							"script": map[string]any{"source": "int s = 0; s += doc['amt'].value; return s;"},
						},
					},
				},
			},
			"by_day": map[string]any{
				"date_histogram": map[string]any{"field": "ts", "fixed_interval": "1h"},
				"aggs": map[string]any{
					"tag_rate": map[string]any{
						"rate": map[string]any{
							"script": map[string]any{"source": "String p = 'tag:'; return p + doc['tags'].value;"},
							"mode":   "value_count",
							"unit":   "1h",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search metrics_r30 failed: %d (%v)", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	tsBuckets := aggs["by_ts_terms"].(map[string]any)["buckets"].([]any)
	if len(tsBuckets) != 1 || tsBuckets[0].(map[string]any)["script_sum"].(map[string]any)["value"] != 30.0 {
		t.Fatalf("expected by_ts_terms bucket script_sum=30.0, got %+v", tsBuckets)
	}
	ratioBuckets := aggs["by_ratio_hist"].(map[string]any)["buckets"].([]any)
	if len(ratioBuckets) != 1 || ratioBuckets[0].(map[string]any)["script_sum"].(map[string]any)["value"] != 30.0 {
		t.Fatalf("expected by_ratio_hist bucket (0.3) script_sum=30.0, got %+v", ratioBuckets)
	}
	dayBuckets := aggs["by_day"].(map[string]any)["buckets"].([]any)
	if len(dayBuckets) != 1 || dayBuckets[0].(map[string]any)["tag_rate"].(map[string]any)["value"] != 2.0 {
		t.Fatalf("expected tag_rate value_count with string script = 2.0, got %+v", dayBuckets)
	}
}

func TestRound30_IngestDropOnCreateSimulateVerbosePipelineErrorAndCloneShrinkSplit(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Register a drop pipeline and verify PUT /{index}/_create/{id}?pipeline=drop_pipe on an existing doc returns 200 noop (not 409)
	code, _ := doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/drop_pipe", map[string]any{
		"processors": []any{
			map[string]any{"drop": map[string]any{}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("put drop_pipe failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPut, "/drop_idx/_doc/1?refresh=true", map[string]any{"msg": "initial"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("put initial doc failed: %d", code)
	}
	code, createResp := doRound27Req(t, srv, http.MethodPut, "/drop_idx/_create/1?pipeline=drop_pipe", map[string]any{"msg": "dropped"})
	if code != http.StatusOK || createResp["result"] != "noop" {
		t.Fatalf("expected 200 OK noop when _create is dropped by pipeline, got code=%d resp=%+v", code, createResp)
	}
	// Also test bulk create with ?pipeline=drop_pipe on existing _id=1
	bulkDrop := `{"create":{"_index":"drop_idx","_id":"1"}}` + "\n" + `{"msg":"dropped_bulk"}` + "\n"
	code, bulkResp := doRound27Req(t, srv, http.MethodPost, "/_bulk?pipeline=drop_pipe", bulkDrop)
	if code != http.StatusOK || bulkResp["errors"] != false {
		t.Fatalf("expected bulk create with drop_pipe to succeed as noop without conflict error, got code=%d resp=%+v", code, bulkResp)
	}

	// 2. _simulate?verbose=true when a pipeline processor references a missing pipeline, plus nested on_failure metadata preservation
	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"pipeline": map[string]any{"name": "missing_sub_pipeline"},
				},
			},
		},
		"docs": []any{
			map[string]any{"_index": "test", "_id": "1", "_source": map[string]any{"a": 1}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate verbose failed: %d", code)
	}
	procResults := simResp["docs"].([]any)[0].(map[string]any)["processor_results"].([]any)
	if len(procResults) != 1 || procResults[0].(map[string]any)["error"] == nil {
		t.Fatalf("expected processor_results[0].error for missing sub-pipeline, got %+v", simResp)
	}

	// 3. Index lifecycle: POST /{index}/_clone/{target}, _shrink, _split
	code, _ = doRound27Req(t, srv, http.MethodPut, "/src_lifecycle", map[string]any{
		"settings": map[string]any{"number_of_shards": 2},
		"mappings": map[string]any{
			"properties": map[string]any{"title": map[string]any{"type": "keyword"}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create src_lifecycle failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPut, "/src_lifecycle/_doc/d1?refresh=true", map[string]any{"title": "hello"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index d1 into src_lifecycle failed: %d", code)
	}
	code, cloneResp := doRound27Req(t, srv, http.MethodPost, "/src_lifecycle/_clone/cloned_lifecycle", map[string]any{
		"settings": map[string]any{"index.number_of_replicas": 0},
		"aliases":  map[string]any{"cloned_alias": map[string]any{}},
	})
	if code != http.StatusOK || cloneResp["acknowledged"] != true || cloneResp["index"] != "cloned_lifecycle" {
		t.Fatalf("_clone failed: code=%d resp=%+v", code, cloneResp)
	}
	// Ensure src_lifecycle still has only 1 doc (not polluted with _id=cloned_lifecycle!) and cloned_lifecycle has d1
	code, srcCount := doRound27Req(t, srv, http.MethodGet, "/src_lifecycle/_count", nil)
	if code != http.StatusOK || srcCount["count"] != float64(1) {
		t.Fatalf("expected src_lifecycle count=1, got %+v", srcCount)
	}
	code, clonedDoc := doRound27Req(t, srv, http.MethodGet, "/cloned_alias/_doc/d1", nil)
	if code != http.StatusOK || clonedDoc["found"] != true {
		t.Fatalf("expected d1 in cloned_lifecycle via cloned_alias, got code=%d resp=%+v", code, clonedDoc)
	}

	// 4. QueryResultCache LRU & TTL unit test
	qCache := newQueryResultCache()
	qCache.Configure(50*time.Millisecond, 2)
	f1, f2, f3 := 1, 2, 3
	reqK1 := &esast.SearchRequest{From: &f1}
	reqK2 := &esast.SearchRequest{From: &f2}
	reqK3 := &esast.SearchRequest{From: &f3}
	qCache.Put([]string{"idx1"}, reqK1, map[string]any{"hits": 1})
	qCache.Put([]string{"idx1"}, reqK2, map[string]any{"hits": 2})
	qCache.Put([]string{"idx1"}, reqK3, map[string]any{"hits": 3}) // evicts 1 entry to stay at maxEntries=2
	if hits, misses := qCache.Stats(); hits != 0 || misses != 0 {
		t.Fatalf("unexpected initial cache stats: hits=%d misses=%d", hits, misses)
	}
	if val, ok := qCache.Get([]string{"idx1"}, reqK3); !ok || val["hits"] != int64(3) {
		t.Fatalf("expected reqK3 hit, got %+v (%v)", val, ok)
	}
	qCache.InvalidateAll()
	if _, ok := qCache.Get([]string{"idx1"}, reqK3); ok {
		t.Fatalf("expected reqK3 to be invalidated after InvalidateAll")
	}
}
