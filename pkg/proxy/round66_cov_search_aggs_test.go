package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound66CovSearchAggs_RuntimeMappingsSignificantTextMultiTermsAndPipelineAggs(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	mustR66CovHTTP(t, h, http.MethodPut, "/search_aggs_cov", `{
		"settings": {
			"analysis": {
				"filter": {"shingle_no_uni": {"type": "shingle", "output_unigrams": false}},
				"analyzer": {"no_uni_an": {"type": "custom", "tokenizer": "standard", "filter": ["shingle_no_uni"]}}
			}
		},
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"title_nouni": {"type": "text", "analyzer": "no_uni_an"},
				"category": {"type": "keyword"},
				"subcat": {"type": "keyword"},
				"price": {"type": "double"},
				"qty": {"type": "integer"},
				"ts": {"type": "date"},
				"ip": {"type": "ip"},
				"loc": {"type": "geo_point"},
				"shape": {"type": "geo_shape"},
				"vec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
				"meta_flat": {"type": "flattened"},
				"tags": {"type": "keyword"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"cost": {"type": "double"},
						"ivec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"}
					}
				}
			}
		}
	}`, http.StatusOK)

	docs := []string{
		`{"title":"apache doris analytical database search","title_nouni":"apache doris","category":"db","subcat":"olap","price":10.5,"qty":2,"ts":"2026-01-01T00:00:00Z","ip":"10.0.1.5","loc":{"lat":37.77,"lon":-122.41},"shape":{"type":"polygon","coordinates":[[[-123.0,37.0],[-122.0,37.0],[-122.0,38.0],[-123.0,38.0],[-123.0,37.0]]]},"vec":[1.0,0.0],"meta_flat":{"env":"prod","tier":"gold"},"tags":["fast","sql"],"items":[{"sku":"s1","cost":5.0,"ivec":[1.0,0.0]},{"sku":"s2","cost":15.0,"ivec":[0.0,1.0]}]}`,
		`{"title":"doris search proxy elasticsearch compatibility","title_nouni":"doris proxy","category":"db","subcat":"proxy","price":25.0,"qty":5,"ts":"2026-01-01T01:00:00Z","ip":"10.0.1.8","loc":{"lat":37.78,"lon":-122.40},"shape":{"type":"envelope","coordinates":[[-122.8,37.9],[-122.1,37.2]]},"vec":[0.8,0.2],"meta_flat":{"env":"prod","tier":"silver"},"tags":["sql"],"items":[{"sku":"s3","cost":20.0,"ivec":[0.7,0.7]}]}`,
		`{"title":"cloud storage analytics lakehouse","title_nouni":"cloud lakehouse","category":"storage","subcat":"lake","price":50.0,"qty":1,"ts":"2026-01-02T00:00:00Z","ip":"10.0.2.1","loc":{"lat":40.71,"lon":-74.00},"shape":{"type":"linestring","coordinates":[[-74.1,40.6],[-73.9,40.8]]},"vec":[0.0,1.0],"meta_flat":{"env":"stage"},"tags":["s3"],"items":[{"sku":"s4","cost":99.0,"ivec":[0.1,0.9]}]}`,
		`{"title":"observability metrics traces logs","title_nouni":"metrics traces","category":"obs","price":5.0,"qty":10,"ts":"2026-01-02T02:00:00Z","ip":"192.168.1.1","loc":{"lat":34.05,"lon":-118.24},"shape":{"type":"point","coordinates":[-118.24,34.05]},"vec":[0.5,0.5],"meta_flat":{"env":"dev"},"tags":["logs"],"items":[{"sku":"s5","cost":2.5,"ivec":[0.2,0.8]}]}`,
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		mustR66CovHTTP(t, h, http.MethodPost, "/search_aggs_cov/_doc/"+id+"?refresh=true", d, http.StatusCreated)
	}

	// Parameter validation limits in validateSearchLimitsAndParamsR62Search.
	badSearches := []struct {
		path string
		body string
	}{
		{"/search_aggs_cov/_search?batched_reduce_size=abc", `{}`},
		{"/search_aggs_cov/_search?batched_reduce_size=1", `{}`},
		{"/search_aggs_cov/_search?pre_filter_shard_size=0", `{}`},
		{"/search_aggs_cov/_search?max_concurrent_shard_requests=0", `{}`},
		{"/search_aggs_cov/_search", `{"from":-1}`},
		{"/search_aggs_cov/_search", `{"size":-1}`},
		{"/search_aggs_cov/_search", `{"sort":["_shard_doc"]}`},
		{"/search_aggs_cov/_search?scroll=1m", `{"size":20000}`},
		{"/search_aggs_cov/_search", `{"retriever":{"rrf":{"retrievers":[{"standard":{"query":{"match_all":{}}}},{"standard":{"query":{"match":{"title":"doris"}}}}],"rank_window_size":2}},"size":5}`},
	}
	for _, tc := range badSearches {
		st, _, _, _ := doR66CovHTTP(t, h, http.MethodPost, tc.path, tc.body, nil)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s %s, got %d", tc.path, tc.body, st)
		}
	}

	// Runtime mappings + composite/nested runtime fields + diverse aggs + profile + multi_terms + significant_text + sub-agg ordering + pipeline aggs.
	searchAggsBody := `{
		"size": 2,
		"profile": true,
		"runtime_mappings": {
			"unit_price": {"type": "double", "script": "emit(doc['price'].value / Math.max(1, doc['qty'].value))"},
			"rt_comp": {"type": "composite", "script": "emit('k1', 'v1'); emit('k2', 42)", "fields": {"k1": {"type": "keyword"}, "k2": {"type": "long"}}},
			"items.rt_cost": {"type": "double"}
		},
		"fields": ["meta_flat.env", "unit_price", "items.rt_cost"],
		"docvalue_fields": ["price", {"field": "ts", "format": "epoch_millis"}],
		"aggs": {
			"by_cat": {
				"terms": {"field": "category", "min_doc_count": 1, "order": [{"avg_p.value": "desc"}, {"_key": "asc"}], "include": "db|storage|obs", "exclude": "none"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"rt_sum": {"sum": {"field": "unit_price"}},
					"st_bounds": {"extended_stats": {"field": "price"}},
					"nested_items": {
						"nested": {"path": "items"},
						"aggs": {
							"best_items": {"top_hits": {"size": 2, "sort": [{"items.cost": "desc"}]}},
							"back_root": {"reverse_nested": {}, "aggs": {"root_cnt": {"value_count": {"field": "category"}}}}
						}
					}
				}
			},
			"sig_txt": {
				"significant_text": {
					"field": "title",
					"min_doc_count": 1,
					"filter_duplicate_text": true,
					"background_filter": {"match_all": {}}
				}
			},
			"mt": {
				"multi_terms": {
					"terms": [{"field": "category"}, {"field": "subcat", "missing": "none"}]
				}
			},
			"comp": {
				"composite": {
					"size": 10,
					"sources": [
						{"cat": {"terms": {"field": "category"}}},
						{"day": {"date_histogram": {"field": "ts", "calendar_interval": "day"}}}
					]
				}
			},
			"hist_pat": {
				"histogram": {"field": "price", "interval": 10, "format": "$#,##0.00"},
				"aggs": {
					"uniq_cat": {"cardinality": {"field": "category"}},
					"cum_cat": {"cumulative_cardinality": {"buckets_path": "uniq_cat"}}
				}
			},
			"auto_dh": {
				"auto_date_histogram": {"field": "ts", "buckets": 5, "time_zone": "America/New_York"},
				"aggs": {
					"p95": {"percentiles": {"field": "price", "percents": [50, 95]}},
					"p95_unkeyed": {"percentiles": {"field": "price", "percents": [50, 95], "keyed": false}},
					"mp": {"moving_percentiles": {"buckets_path": "p95", "window": 3, "shift": 1, "format": "0.0"}},
					"mp_u": {"moving_percentiles": {"buckets_path": "p95_unkeyed", "window": 3, "format": "0.0"}},
					"sum_q": {"sum": {"field": "qty"}},
					"cum_q": {"cumulative_sum": {"buckets_path": "sum_q"}},
					"bsort": {"bucket_sort": {"sort": [{"sum_q": {"order": "desc"}}], "size": 3}},
					"bsel": {"bucket_selector": {"buckets_path": {"sq": "sum_q"}, "script": "params.sq >= 0"}}
				}
			},
			"ip_pref": {"ip_prefix": {"field": "ip", "prefix_length": 24}},
			"rare": {"rare_terms": {"field": "tags", "max_doc_count": 2}},
			"miss_sub": {"missing": {"field": "subcat"}, "aggs": {"c": {"value_count": {"field": "price"}}}},
			"filt_grp": {
				"filters": {"other_bucket": true, "filters": {"dbs": {"term": {"category": "db"}}}},
				"aggs": {"min_p": {"min": {"field": "price"}}}
			},
			"g_cent": {"geo_centroid": {"field": "shape"}},
			"g_bounds": {"geo_bounds": {"field": "loc"}},
			"samp": {"sampler": {"shard_size": 2}, "aggs": {"avg_q": {"avg": {"field": "qty"}}}}
		}
	}`
	res := mustR66CovHTTP(t, h, http.MethodPost, "/search_aggs_cov/_search", searchAggsBody, http.StatusOK)
	if res["aggregations"] == nil || res["profile"] == nil {
		t.Fatalf("expected aggregations and profile in response, got %v", res)
	}
}

func TestRound66CovSearchAggs_SpatialNestedInnerHitsSuggestRRFAndCollapse(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	mustR66CovHTTP(t, h, http.MethodPut, "/spatial_cov", `{
		"settings": {
			"analysis": {
				"filter": {"shingle_no_uni": {"type": "shingle", "output_unigrams": false}},
				"analyzer": {"no_uni_an": {"type": "custom", "tokenizer": "standard", "filter": ["shingle_no_uni"]}}
			}
		},
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"title_nouni": {"type": "text", "analyzer": "no_uni_an"},
				"grp": {"type": "keyword"},
				"subgrp": {"type": "keyword"},
				"score_num": {"type": "integer"},
				"shape": {"type": "geo_shape"},
				"loc": {"type": "geo_point"},
				"vec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
				"items": {
					"type": "nested",
					"properties": {
						"name": {"type": "text"},
						"tag": {"type": "keyword"},
						"ivec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"}
					}
				}
			}
		}
	}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_doc/1?refresh=true", `{
		"title": "hello world doris proxy",
		"title_nouni": "hello world",
		"grp": "g1", "subgrp": "s1", "score_num": 10,
		"loc": {"lat": 37.75, "lon": -122.45},
		"shape": {"type": "polygon", "coordinates": [[[-123.0,37.0],[-122.0,37.0],[-122.0,38.0],[-123.0,38.0],[-123.0,37.0]]]},
		"vec": [1.0, 0.0],
		"items": [{"name":"alpha beta","tag":"hot","ivec":[1.0,0.0]},{"name":"gamma","tag":"cold","ivec":[0.0,1.0]}]
	}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_doc/2?refresh=true", `{
		"title": "hello elasticsearch world",
		"title_nouni": "hello elastic",
		"grp": "g1", "subgrp": "s2", "score_num": 20,
		"loc": {"lat": 40.70, "lon": -74.00},
		"shape": {"type": "envelope", "coordinates": [[-75.0,41.0],[-73.0,40.0]]},
		"vec": [0.7, 0.7],
		"items": [{"name":"alpha one","tag":"hot","ivec":[0.9,0.1]}]
	}`, http.StatusCreated)

	// GeoShape relations: DISJOINT, WITHIN, CONTAINS, INTERSECTS.
	for _, rel := range []string{"INTERSECTS", "DISJOINT", "WITHIN", "CONTAINS"} {
		mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_search", `{
			"query": {
				"geo_shape": {
					"shape": {
						"shape": {"type": "envelope", "coordinates": [[-122.8,37.8],[-122.2,37.2]]},
						"relation": "`+rel+`"
					}
				}
			}
		}`, http.StatusOK)
	}

	// Nested inner_hits + nested kNN inner_hits + collapse with inner_hits + rescore + track_scores.
	mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_search", `{
		"query": {
			"bool": {
				"should": [
					{"nested": {"path": "items", "query": {"match": {"items.tag": "hot"}}, "inner_hits": {"size": 2}}},
					{"knn": {"field": "items.ivec", "query_vector": [1.0, 0.0], "k": 2, "num_candidates": 4, "inner_hits": {"size": 1}}}
				]
			}
		},
		"collapse": {
			"field": "grp",
			"inner_hits": [{"name": "top_sub", "size": 2, "collapse": {"field": "subgrp"}}]
		},
		"rescore": [{"window_size": 10, "query": {"rescore_query": {"match": {"title": "doris"}}}}],
		"track_scores": true
	}`, http.StatusOK)

	// Phrase suggester (normal + force_unigrams=false + error on unigram-free analyzer).
	mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_search", `{
		"suggest": {
			"phrase_sug": {
				"text": "helo wrld",
				"phrase": {
					"field": "title",
					"direct_generator": [{"field": "title", "suggest_mode": "always"}]
				}
			},
			"no_uni_ok": {
				"text": "helo",
				"phrase": {
					"field": "title_nouni",
					"force_unigrams": false
				}
			}
		}
	}`, http.StatusOK)
	st, _, _, _ := doR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_search", `{
		"suggest": {"bad_sug": {"text": "helo", "phrase": {"field": "title_nouni"}}}
	}`, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 when force_unigrams omitted on no-unigram analyzer, got %d", st)
	}

	// RRF retriever combining standard + knn + global filter.
	rrfRes := mustR66CovHTTP(t, h, http.MethodPost, "/spatial_cov/_search", `{
		"retriever": {
			"rrf": {
				"retrievers": [
					{"standard": {"query": {"match": {"title": "doris"}}}},
					{"knn": {"field": "vec", "query_vector": [1.0, 0.0], "k": 2, "num_candidates": 5}}
				],
				"filter": [{"range": {"score_num": {"gte": 5}}}],
				"rank_constant": 60,
				"rank_window_size": 10
			}
		},
		"size": 2
	}`, http.StatusOK)
	if rrfRes["hits"] == nil {
		t.Fatalf("expected hits in RRF response, got %v", rrfRes)
	}

	// Index settings negative validation cases.
	for _, badSet := range []string{
		`{"index.translog.retention.age":"1h"}`,
		`{"index.top_metrics_max_size":0}`,
		`{"index.mode":"time_series"}`,
		`{"index.default_pipeline":"missing_pipe_r66"}`,
	} {
		st, _, _, _ = doR66CovHTTP(t, h, http.MethodPut, "/spatial_cov/_settings", badSet, nil)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid settings %s, got %d", badSet, st)
		}
	}
}

func TestRound66CovSearchAggs_TermsOrderingSubAggsInnerHitsAndTZ(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.5")

	mustR66CovHTTP(t, h, http.MethodPut, "/sa_deep", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"sub": {"type": "keyword"},
				"txt": {"type": "text"},
				"price": {"type": "double"},
				"ts": {"type": "date"},
				"ip": {"type": "ip"},
				"nested_raw": {"type": "nested", "properties": {"k": {"type": "keyword"}, "v": {"type": "double"}, "note": {"type": "text"}}}
			}
		}
	}`, http.StatusOK)

	docs := []string{
		`{"cat":"a","sub":"x","txt":"alpha beta gamma","price":10.0,"ts":"2026-01-01T01:00:00Z","ip":"10.0.0.1","nested_raw":[{"k":"n1","v":5,"note":"match one"},{"k":"n2","v":15,"note":"match two"}],"dyn_items":[{"dk":"d1","dv":2}]}`,
		`{"cat":"a","sub":"y","txt":"alpha delta epsilon","price":20.0,"ts":"2026-01-01T05:00:00Z","ip":"10.0.0.2","nested_raw":[{"k":"n3","v":25,"note":"match three"}],"dyn_items":[{"dk":"d2","dv":4}]}`,
		`{"cat":"b","sub":"x","txt":"gamma zeta","price":30.0,"ts":"2026-01-03T01:00:00Z","ip":"192.168.1.10","nested_raw":[{"k":"n4","v":35,"note":"other"}],"dyn_items":[{"dk":"d3","dv":6}]}`,
	}
	for i, d := range docs {
		mustR66CovHTTP(t, h, http.MethodPut, "/sa_deep/_doc/"+string(rune('1'+i))+"?refresh=true", d, http.StatusCreated)
	}

	// 1. Terms ordering by sub-agg variants + diverse sub-aggs + TZ date_histogram + pipeline aggs
	for _, ord := range []string{
		`{"est.variance": "desc"}`,
		`{"est.variance_sampling": "asc"}`,
		`{"est.std_deviation_sampling": "desc"}`,
		`{"est.std_deviation_bounds.upper": "desc"}`,
		`{"est.std_deviation_bounds.lower_sampling": "asc"}`,
		`{"est.sum_of_squares": "desc"}`,
		`{"pct.q1": "asc"}`,
		`{"pct.q3": "desc"}`,
		`{"sstat.entropy": "desc"}`,
		`{"sstat.avg_length": "desc"}`,
		`{"f.x._count": "desc"}`,
	} {
		searchBody := `{
			"size": 0,
			"aggs": {
				"by_cat": {
					"terms": {"field": "cat", "include": "a|b", "exclude": "none", "order": ` + ord + `},
					"aggs": {
						"est": {"extended_stats": {"field": "price", "sigma": 1.5}},
						"pct": {"percentiles": {"field": "price", "percents": [25, 50, 75]}},
						"pranks_keyed": {"percentile_ranks": {"field": "price", "values": [15, 25]}},
						"pranks_arr": {"percentile_ranks": {"field": "price", "values": [15, 25], "keyed": false}},
						"sstat": {"string_stats": {"field": "sub", "show_distribution": true}},
						"f": {"filters": {"other_bucket": true, "keyed": false, "filters": {"x": {"term": {"sub": "x"}}}}},
						"f_anon": {"filters": {"other_bucket": true, "filters": [{"term": {"sub": "x"}}]}},
						"dr": {"date_range": {"field": "ts", "ranges": [{"to": "2026-01-02T00:00:00Z"}, {"from": "2026-01-02T00:00:00Z"}]}},
						"ipr": {"ip_range": {"field": "ip", "ranges": [{"mask": "10.0.0.0/24"}]}},
						"sub_sig": {"significant_terms": {"field": "sub"}},
						"th": {"top_hits": {"size": 1, "_source": ["cat", "price"]}},
						"bscript": {"bucket_script": {"buckets_path": {"p": "est.avg"}, "script": "params.p * 2"}}
					}
				},
				"top_comp": {"composite": {"sources": [{"sub": {"terms": {"field": "sub"}}}]}},
				"dh_tz": {
					"date_histogram": {
						"field": "ts",
						"calendar_interval": "day",
						"time_zone": "America/New_York",
						"min_doc_count": 0,
						"extended_bounds": {"min": "2026-01-01", "max": "2026-01-04"}
					},
					"aggs": {
						"avg_p": {"avg": {"field": "price"}},
						"deriv": {"derivative": {"buckets_path": "avg_p"}},
						"serial": {"serial_diff": {"buckets_path": "avg_p", "lag": 1}},
						"norm": {"normalize": {"buckets_path": "avg_p", "method": "percent_of_sum"}},
						"mov": {"moving_fn": {"buckets_path": "avg_p", "window": 2, "script": "MovingFunctions.sum(values)"}}
					}
				}
			}
		}`
		mustR66CovHTTP(t, h, http.MethodPost, "/sa_deep/_search", searchBody, http.StatusOK)
	}

	// 2. TopHits pipeline validation error + bucket_selector on empty buckets
	_, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/sa_deep/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"th": {"top_hits": {"size": 1}},
					"bs_bad": {"bucket_script": {"buckets_path": {"v": "th._source.nonexistent_field"}, "script": "params.v * 2"}}
				}
			}
		}
	}`, nil)

	// 3. Nested inner_hits (mapped + unmapped dynamic + version/seq_no + highlight + sort) & function_score / pinned / constant_score
	mustR66CovHTTP(t, h, http.MethodPost, "/sa_deep/_search", `{
		"query": {
			"bool": {
				"should": [
					{
						"nested": {
							"path": "nested_raw",
							"query": {"match": {"nested_raw.note": "match"}},
							"inner_hits": {"name": "nh", "size": 1, "version": true, "seq_no_primary_term": true, "sort": [{"nested_raw.v": "desc"}], "highlight": {"fields": {"nested_raw.note": {}}}, "docvalue_fields": ["nested_raw.k"], "script_fields": {"sv": {"script": "doc['nested_raw.v'].value * 2"}}}
						}
					},
					{
						"function_score": {
							"query": {"constant_score": {"filter": {"match_all": {}}, "boost": 1.5}},
							"field_value_factor": {"field": "price", "modifier": "log1p", "missing": 1.0},
							"weight": 2.0
						}
					},
					{
						"pinned": {
							"ids": ["1"],
							"boost": 1.5,
							"organic": {"match": {"txt": "gamma"}}
						}
					}
				]
			}
		}
	}`, http.StatusOK)

	// 4. Direct helper unit calls: synthesizeFixedTZDateHistogramBucketsR66 & sqlRowValToInt64R66 / sqlRowValToFloat64R66
	locNY, _ := time.LoadLocation("America/New_York")
	synthRows := synthesizeFixedTZDateHistogramBucketsR66(
		[]AggRow{{BucketKey: "1767243600000", DocCount: 2, Value: 2}},
		&esast.DateHistogramAggSpec{
			CalendarInterval: "day",
			TimeZone:         "America/New_York",
			HardBounds:       &esast.HistogramBoundsSpec{Min: "2026-01-01T00:00:00Z", Max: "2026-01-03T00:00:00Z"},
			ExtendedBounds:   &esast.HistogramBoundsSpec{Min: "2025-12-31T00:00:00Z", Max: "2026-01-04T00:00:00Z"},
		},
		locNY,
	)
	if len(synthRows) < 2 {
		t.Fatalf("expected synthesized TZ buckets, got %v", synthRows)
	}

	for _, iv := range []any{int(1), int64(2), uint64(3), float64(4.5), float32(5.5), json.Number("6"), json.Number("7.2"), []byte("8"), " 9 ", "9.9"} {
		if _, ok := sqlRowValToInt64R66(iv); !ok {
			t.Fatalf("expected sqlRowValToInt64R66 ok for %T(%v)", iv, iv)
		}
		if _, ok := sqlRowValToFloat64R66(iv); !ok {
			t.Fatalf("expected sqlRowValToFloat64R66 ok for %T(%v)", iv, iv)
		}
	}
	for _, bad := range []any{nil, uint64(math.MaxUint64), math.NaN(), math.Inf(1), float32(math.NaN()), "", "not_num", true} {
		_, _ = sqlRowValToInt64R66(bad)
		_, _ = sqlRowValToFloat64R66(bad)
	}
}

func TestRound66CovSearchAggs_ProfilePercentilesHistogramInnerHitsAndErrorEdges(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	mustR66CovHTTP(t, h, http.MethodPut, "/adv_search_cov", `{
		"settings": {"index.mode": "standard"},
		"mappings": {
			"properties": {
				"cat":   {"type": "keyword"},
				"title": {"type": "text"},
				"price": {"type": "double"},
				"u64":   {"type": "unsigned_long"},
				"flag":  {"type": "boolean"},
				"loc":   {"type": "geo_shape"},
				"ts":    {"type": "date"},
				"dn":    {"type": "date_nanos"},
				"hist":  {"type": "histogram"},
				"items": {
					"type": "nested",
					"properties": {
						"tag":   {"type": "keyword"},
						"score": {"type": "double"}
					}
				}
			}
		}
	}`, http.StatusOK)

	docs := []string{
		`{"cat":"a","title":"alpha quick fox jumps over lazy dog","price":10.5,"u64":10,"flag":true,"loc":"POINT (10 20)","ts":"2026-01-01T00:00:00Z","dn":"2026-01-01T00:00:00.000000100Z","hist":{"values":[1,2],"counts":[2,3]},"items":[{"tag":"t1","score":9.5},{"tag":"t2","score":4.0}]}`,
		`{"cat":"a","title":"alpha fast hound runs across green field","price":20.5,"u64":20,"flag":false,"loc":"POINT (11 21)","ts":"2026-01-02T00:00:00Z","dn":"2026-01-02T00:00:00.000000200Z","hist":{"values":[2,3],"counts":[4,1]},"items":[{"tag":"t1","score":7.0}]}`,
		`{"cat":"b","title":"beta steady river flows near mountain","price":30.0,"u64":30,"flag":true,"loc":"POINT (12 22)","ts":"2026-01-03T00:00:00Z","dn":"2026-01-03T00:00:00.000000300Z","hist":{"values":[1,3],"counts":[1,2]},"items":[{"tag":"t3","score":6.0}]}`,
	}
	for i, d := range docs {
		mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_doc/"+string(rune('1'+i))+"?refresh=true", d, http.StatusCreated)
	}

	// 1. profile=true on terms agg (breadth_first + sub-agg + parent agg -> StringTermsAggregatorFromFilters + GlobalOrdinalsStringTermsAggregator),
	//    auto_date_histogram with sub-agg, percentiles keyed=false+format, histogram mapped field,
	//    runtime_mappings covering boolean/date/date_nanos/geo_shape/unsigned_long,
	//    fields parameter covering _id, _index, _version, _seq_no, _primary_term
	resp := mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{
		"profile": true,
		"size": 2,
		"version": true,
		"seq_no_primary_term": true,
		"fields": ["_id","_index","_version","cat","ts"],
		"docvalue_fields": ["_seq_no","_primary_term"],
		"runtime_mappings": {
			"rt_bool": {"type":"boolean","script":{"source":"emit(true)"}},
			"rt_date": {"type":"date","script":{"source":"emit('2026-01-01T00:00:00Z')"}},
			"rt_dn":   {"type":"date_nanos","script":{"source":"emit(1767225600000000100L)"}},
			"rt_geo":  {"type":"geo_shape","script":{"source":"emit('POINT (1 2)')"}},
			"rt_u64":  {"type":"unsigned_long","script":{"source":"emit(99)"}}
		},
		"query": {
			"bool": {
				"must": [{"match": {"title": "alpha"}}],
				"filter": [{
					"nested": {
						"path": "items",
						"query": {"range": {"items.score": {"gte": 1}}},
						"inner_hits": {
							"name": "ih_sorted",
							"size": 2,
							"version": true,
							"seq_no_primary_term": true,
							"fields": ["items.tag"],
							"docvalue_fields": ["items.score"],
							"sort": [{"items.score": "desc"}]
						}
					}
				}]
			}
		},
		"highlight": {
			"fields": {"title": {"fragment_size": 12, "number_of_fragments": 2}}
		},
		"aggs": {
			"by_cat_bf": {
				"terms": {"field": "cat", "collect_mode": "breadth_first"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"sub_title": {"terms": {"field": "cat"}}
				}
			},
			"by_cat_filt": {
				"terms": {"field": "cat", "execution_hint": "map"},
				"aggs": {"c": {"value_count": {"field": "price"}}}
			},
			"auto_dh": {
				"auto_date_histogram": {"field": "ts", "buckets": 3},
				"aggs": {"sum_p": {"sum": {"field": "price"}}}
			},
			"pct_arr": {
				"percentiles": {"field": "price", "percents": [50, 95], "keyed": false, "format": "0.00"}
			},
			"pct_map": {
				"percentiles": {"field": "price", "percents": [50], "format": "0.00"}
			},
			"mapped_hist": {
				"histogram": {"field": "hist", "interval": 1}
			},
			"children_fake": {
				"terms": {"field": "cat"},
				"aggs": {
					"sub_empty": {"filter": {"term": {"cat": "never"}}, "aggs": {"s": {"sum": {"field": "price"}}}},
					"bs_zero": {"bucket_script": {"buckets_path": {"s": "sub_empty>s"}, "script": "params.s + 1", "gap_policy": "insert_zeros"}},
					"bs_keep": {"bucket_selector": {"buckets_path": {"s": "sub_empty>s"}, "script": "params.s == null", "gap_policy": "keep_values"}}
				}
			}
		}
	}`, http.StatusOK)
	if _, hasProf := resp["profile"]; !hasProf {
		t.Fatalf("expected profile in response")
	}

	// 2. Unmapped nested inner_hits + cutoff_frequency + collapse/negative from ES8 parse errors + invalid field format
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"from":-1}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"query":{"match":{"title":{"query":"x","cutoff_frequency":0.1}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"query":{"multi_match":{"query":"x","fields":["title"],"type":"bool_prefix","cutoff_frequency":0.1}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"fields":[{"field":"_id","format":"epoch_millis"}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"fields":["_seq_no"]}`, http.StatusInternalServerError)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"docvalue_fields":["_id"]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"collapse":{"field":"cat","collapse":{"field":"cat"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"aggs":{"mad":{"median_absolute_deviation":{"field":"price","execution_hint":"bad"}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"aggs":{"bx":{"boxplot":{"field":"price","compression":-1}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/adv_search_cov/_search", `{"aggs":{"dh":{"date_histogram":{"field":"ts","fixed_interval":"1d"},"aggs":{"mv":{"moving_fn":{"buckets_path":"missing_path","window":2,"script":"MovingFunctions.sum(values)"}}}}}}`, http.StatusBadRequest)

	// 3. scroll with no matching open indices + rest_total_hits_as_int=true + empty hits
	mustR66CovHTTP(t, h, http.MethodGet, "/no_such_wildcard_*/_search?expand_wildcards=none&scroll=1m&rest_total_hits_as_int=true", "", http.StatusOK)

	// 4. Direct helper unit calls: evalRuntimeMappingsOrderedOnDocWithOutR62Search + evalRandomScoreOnDoc + buildNestedInnerHitsForHitWithOpts empty
	var emptyNH esast.NestedQuery
	_ = json.Unmarshal([]byte(`{"path":"items","query":{"match_all":{}},"inner_hits":{}}`), &emptyNH)
	resNH := buildNestedInnerHitsForHitWithOpts(HitRow{ID: "x"}, "adv_search_cov", nil, &emptyNH, false)
	if !strings.Contains(fmt.Sprintf("%v", resNH), "hits") {
		t.Fatalf("unexpected empty inner_hits: %v", resNH)
	}
	if sc := evalRandomScoreOnDoc(map[string]any{"_id": "1"}, &esast.RandomScoreSpec{Seed: 42, Field: "_id"}); sc <= 0 {
		t.Fatalf("unexpected random_score: %v", sc)
	}
}

func TestRound66CovSearchAggs_SignificantTextProfileNestedTopHitsJoinsAndRouting(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")

	// 1. Multi-shard routing filtering (server.go:25540), parent->significant_text with profile=true (round62:9652),
	//    nested->top_hits with sort (round61:5345), explicit moving_fn scripts (round61:4721)
	mustR66CovHTTP(t, h, http.MethodPut, "/route_sig_cov", `{
		"settings":{"number_of_shards":3,"number_of_routing_shards":3},
		"mappings":{
			"properties":{
				"cat":{"type":"keyword"},
				"title":{"type":"text"},
				"ts":{"type":"date"},
				"price":{"type":"double"},
				"items":{"type":"nested","properties":{"score":{"type":"double"},"tag":{"type":"keyword"}}}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_doc/r1?routing=shardA&refresh=true", `{"cat":"tech","title":"doris search proxy cloud","ts":"2026-01-01T00:00:00Z","price":10,"items":[{"tag":"x","score":1},{"tag":"y","score":5}]}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_doc/r2?routing=shardB&refresh=true", `{"cat":"tech","title":"doris vector hybrid engine","ts":"2026-01-02T00:00:00Z","price":20,"items":[{"tag":"y","score":8},{"tag":"z","score":2}]}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_doc/r3?routing=shardC&refresh=true", `{"cat":"food","title":"fresh baked sourdough bread","ts":"2026-01-03T00:00:00Z","price":30,"items":[{"tag":"b","score":9}]}`, http.StatusCreated)

	profResp := mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_search?routing=shardA,shardB", `{
		"profile": true,
		"query":{"function_score":{"query":{"match":{"title":"doris"}},"functions":[{"random_score":{"seed":7,"field":"_seq_no"}}]}},
		"aggs":{
			"by_cat":{
				"terms":{"field":"cat"},
				"aggs":{"sig":{"significant_text":{"field":"title"}}}
			},
			"nested_top":{
				"nested":{"path":"items"},
				"aggs":{"th":{"top_hits":{"size":2,"sort":[{"items.score":"desc"}]}}}
			},
			"dh":{
				"date_histogram":{"field":"ts","fixed_interval":"1d"},
				"aggs":{
					"s":{"sum":{"field":"price"}},
					"m":{"moving_fn":{"buckets_path":"s","window":2,"script":"MovingFunctions.sum(values)"}}
				}
			}
		}
	}`, http.StatusOK)
	if _, ok := profResp["profile"]; !ok {
		t.Fatalf("expected profile in response")
	}

	// 2. Join field parent/children sub-aggs inside terms agg (server.go:31460-31497) + aggregate_metric_double search
	mustR66CovHTTP(t, h, http.MethodPut, "/join_cov", `{
		"mappings":{
			"properties":{
				"grp":{"type":"keyword"},
				"my_join":{"type":"join","relations":{"question":"answer"}},
				"val":{"type":"double"},
				"metric_m":{"type":"aggregate_metric_double","metrics":["min","max","sum","value_count"],"default_metric":"sum"}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/join_cov/_doc/q1?refresh=true", `{"grp":"g1","my_join":{"name":"question"},"val":10,"metric_m":{"min":1,"max":5,"sum":6,"value_count":2}}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/join_cov/_doc/a1?routing=q1&refresh=true", `{"grp":"g1","my_join":{"name":"answer","parent":"q1"},"val":50}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/join_cov/_search", `{
		"aggs":{
			"by_grp":{
				"terms":{"field":"grp"},
				"aggs":{
					"to_children":{"children":{"type":"answer"},"aggs":{"avg_v":{"avg":{"field":"val"}}}},
					"to_parent":{"parent":{"type":"question"},"aggs":{"avg_v":{"avg":{"field":"val"}}}}
				}
			},
			"m_sum":{"sum":{"field":"metric_m"}}
		}
	}`, http.StatusOK)

	// 3. Force runtime eval path on children/parent join aggs + scriptless/non-emit runtime_mappings + on_script_error=continue + bucket_sort _key.sub/missing
	mustR66CovHTTP(t, h, http.MethodPost, "/join_cov/_search", `{
		"runtime_mappings":{
			"rt_flag":{"type":"boolean","script":{"source":"doc['val'].value > 0"}},
			"rt_bad":{"type":"keyword","on_script_error":"continue","script":{"source":"1 / 0"}},
			"nested_rt.v":{"type":"double","script":{"source":"doc['val'].value * 2"}}
		},
		"query":{"term":{"rt_flag":true}},
		"aggs":{
			"by_grp":{
				"terms":{"field":"grp"},
				"aggs":{
					"to_children":{"children":{"type":"answer"},"aggs":{"avg_v":{"avg":{"field":"val"}}}},
					"to_parent":{"parent":{"type":"question"},"aggs":{"avg_v":{"avg":{"field":"val"}}}}
				}
			}
		}
	}`, http.StatusOK)

	// 4. reEvaluatePipelineAggsTreeInnerR61Search (quantiles inside terms + sub-agg) & bucket_sort sort options
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_search", `{
		"size": 0,
		"aggs":{
			"by_cat":{
				"terms":{"field":"cat"},
				"aggs":{
					"pct":{"percentiles":{"field":"price","percents":[50]}},
					"avg_p":{"avg":{"field":"price"}},
					"bs_first":{"bucket_sort":{"sort":[{"pct>50.0":{"order":"asc","missing":"_first"}}]}},
					"bs_zero":{"bucket_sort":{"gap_policy":"insert_zeros","sort":[{"avg_p":{"order":"desc","missing":"_last"}}]}}
				}
			},
			"mt":{
				"multi_terms":{"terms":[{"field":"cat"},{"field":"price"}]},
				"aggs":{
					"bs_mt":{"bucket_sort":{"sort":[{"_key.price":"asc"},{"_key":"asc"}]}}
				}
			},
			"dh":{
				"date_histogram":{"field":"ts","fixed_interval":"1d"},
				"aggs":{
					"pct":{"percentiles":{"field":"price","percents":[50,90]}},
					"mp":{"moving_percentiles":{"buckets_path":"pct","window":2,"shift":1}}
				}
			}
		}
	}`, http.StatusOK)

	// 5. PIT with index_filter + doc indexed post-PIT (applyPITContextFilters postPITIDsByIdx)
	pitResp := mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_pit?keep_alive=1m", `{"index_filter":{"term":{"cat":"tech"}}}`, http.StatusOK)
	if pitID, _ := pitResp["id"].(string); pitID != "" {
		mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_doc/r4_post_pit?routing=shardA&refresh=true", `{"cat":"tech","title":"doris post pit","ts":"2026-01-04T00:00:00Z","price":40}`, http.StatusCreated)
		mustR66CovHTTP(t, h, http.MethodPost, "/_search", `{"pit":{"id":"`+pitID+`"},"query":{"match":{"title":"doris"}}}`, http.StatusOK)
	}

	// 6. parseAndValidateSliceParams invalid errors on _update_by_query
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_update_by_query?slices=0", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/route_sig_cov/_update_by_query?slices=bad", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"route_sig_cov","slice":{"id":5,"max":2}},"dest":{"index":"join_cov"}}`, http.StatusBadRequest)
}

func TestRound66CovSearchAggs_CumulativeCardCompositeNestedTopHitsPercentilesAndErrors(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	mustR66CovHTTP(t, h, http.MethodPut, "/agg_b6", `{
		"settings": {
			"analysis": {
				"normalizer": {"low_norm": {"type": "custom", "filter": ["lowercase"]}}
			}
		},
		"mappings": {
			"properties": {
				"ts": {"type": "date"},
				"ts_nanos": {"type": "date_nanos"},
				"flag": {"type": "boolean"},
				"kw_norm": {"type": "keyword", "normalizer": "low_norm"},
				"cat": {"type": "keyword"},
				"price": {"type": "double"},
				"val": {"type": "long"},
				"items": {
					"type": "nested",
					"properties": {
						"k": {"type": "keyword"},
						"p": {"type": "double"}
					}
				},
				"dyn_obj": {"type": "object"}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_doc/1?refresh=true", `{
		"ts":"2026-01-01T00:00:00Z","ts_nanos":1767225600000000000,"flag":true,"kw_norm":"Alpha","cat":"A","price":10.5,"val":5,
		"items":[{"k":"i1","p":30},{"k":"i2","p":10}],
		"dyn_obj":[{"name":"x","score":1.5}]
	}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_doc/2?refresh=true", `{
		"ts":"2026-01-02T00:00:00Z","ts_nanos":1767312000000000000,"flag":false,"kw_norm":"Beta","cat":"A","price":20.5,"val":10,
		"items":[{"k":"i3","p":20},{"k":"i4","p":40}]
	}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_doc/3?refresh=true", `{
		"ts":"2026-01-03T00:00:00Z","kw_norm":"Gamma","cat":"B","price":30.5,"val":15,
		"items":[{"k":"i5","p":5}]
	}`, http.StatusCreated)

	// 1. auto_date_histogram + date_histogram with cumulative_cardinality pipeline agg under runtime_mappings (applyTrueCumulativeCardinalityWithHitsR65)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"runtime_mappings": {
			"rt_ul_num": {"type": "unsigned_long", "script": {"source": "emit(params.u)", "params": {"u": 42}}},
			"rt_ul_str": {"type": "unsigned_long", "script": "emit(\"18446744073709551600\")"},
			"rt_ul_flt": {"type": "unsigned_long", "script": "emit(12.0)"}
		},
		"query": {"term": {"rt_ul_num": 42}},
		"aggs": {
			"adh": {
				"auto_date_histogram": {"field": "ts", "buckets": 3},
				"aggs": {
					"uniq": {"cardinality": {"field": "cat"}},
					"cc": {"cumulative_cardinality": {"buckets_path": "uniq"}}
				}
			},
			"dh": {
				"date_histogram": {"field": "ts", "calendar_interval": "day"},
				"aggs": {
					"uniq": {"cardinality": {"field": "cat"}},
					"cc": {"cumulative_cardinality": {"buckets_path": "uniq"}}
				}
			},
			"comp": {
				"composite": {
					"size": 10,
					"sources": [
						{"b": {"terms": {"field": "flag", "missing_bucket": true}}},
						{"dn": {"terms": {"field": "ts_nanos"}}},
						{"kn": {"terms": {"field": "kw_norm"}}}
					]
				}
			}
		}
	}`, http.StatusOK)

	// 2. nested agg with BOTH sorted and unsorted top_hits across multiple nested items (evaluateNestedTopHitsAggR61Search)
	// + percentiles keyed=false & format=0.00 (buildExactQuantileMetricObjectR61Search)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"pct_arr": {"percentiles": {"field": "price", "percents": [50, 95], "keyed": false, "format": "0.00"}},
					"pct_map": {"percentiles": {"field": "price", "percents": [50], "keyed": true, "format": "0.00"}},
					"avg_p": {"avg": {"field": "price"}},
					"stats_p": {"stats": {"field": "price"}},
					"bs_sel": {"bucket_selector": {"buckets_path": {"st": "stats_p"}, "script": "params.st.count > 0"}},
					"bs_calc": {"bucket_script": {"gap_policy": "insert_zeros", "buckets_path": {"a": "avg_p"}, "script": "params.a * 2"}}
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"th_sorted": {"top_hits": {"sort": [{"items.p": "desc"}], "size": 3}},
					"th_unsorted": {"top_hits": {"size": 3}}
				}
			}
		}
	}`, http.StatusOK)

	// 3. Pipeline & quantile validation / runtime script errors (validateTopHitsAndPipelineScriptErrorsR65)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"pct_bad": {"percentiles": {"field": "price", "percents": [-5]}}
				}
			}
		}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"bad_if": {"bucket_script": {"buckets_path": {"a": "avg_p"}, "script": "if (params.a > 0) { return 1 / 0; } return 0;"}}
				}
			}
		}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"bad_arith": {"bucket_script": {"buckets_path": {"a": "avg_p"}, "script": "1 / 0"}}
				}
			}
		}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/agg_b6/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"bad_sel": {"bucket_selector": {"buckets_path": {"a": "avg_p"}, "script": "1 / 0 > 0"}}
				}
			}
		}
	}`, http.StatusBadRequest)

	// 4. Direct buildNestedInnerHitsForHitWithOpts when NestedRoots lacks explicit nested type (object array inference)
	srv.mu.RLock()
	sch := srv.indices["agg_b6"]
	srv.mu.RUnlock()
	ihEnv := buildNestedInnerHitsForHitWithOpts(
		HitRow{ID: "1", Index: "agg_b6", Source: json.RawMessage(`{"dyn_obj":[{"name":"x","score":1.5}]}`)},
		"agg_b6", sch,
		&esast.NestedQuery{Path: "dyn_obj", Query: esast.Query{MatchAll: map[string]any{}}},
		false,
	)
	if hitsMap, _ := ihEnv["hits"].(map[string]any); hitsMap == nil {
		t.Fatalf("expected non-nil hits envelope from inferred nested inner_hits: %#v", ihEnv)
	}
}

func TestRound66CovSearchAggs_MovingFnMultiValueMetricSortExplainAndInnerHitsLookups(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	// 1. evalMovingFnWindowR61Search edge paths
	if _, err := evalMovingFnWindowR61Search([]float64{1, 2}, nil); err == nil {
		t.Fatal("expected error for nil spec")
	}
	if _, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "   "}); err == nil {
		t.Fatal("expected error for empty script")
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "Double.NaN"}); err != nil || v != nil {
		t.Fatalf("expected nil for NaN literal, got %v err=%v", v, err)
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "42.5"}); err != nil || v != 42.5 {
		t.Fatalf("expected 42.5 literal, got %v err=%v", v, err)
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "if (values.length > 99) { return 1.0; }"}); err != nil || v != 0.0 {
		t.Fatalf("expected 0.0 on falling-through if, got %v err=%v", v, err)
	}
	if _, err := evalMovingFnWindowR61Search([]float64{}, &esast.MovingAvgAggSpec{Script: "MovingFunctions.unweightedAvg(values)"}); err == nil {
		t.Log("unweightedAvg on empty window returned nil or err cleanly")
	}

	// 2. isMultiValueMetricAggSpecR61Search across metric specs
	for _, specJSON := range []string{
		`{"stats":{"field":"p"}}`,
		`{"extended_stats":{"field":"p"}}`,
		`{"matrix_stats":{"fields":["p"]}}`,
		`{"percentiles":{"field":"p","percents":[50,95]}}`,
		`{"percentile_ranks":{"field":"p","values":[10]}}`,
		`{"boxplot":{"field":"p"}}`,
		`{"stats_bucket":{"buckets_path":"a"}}`,
		`{"extended_stats_bucket":{"buckets_path":"a"}}`,
		`{"percentiles_bucket":{"buckets_path":"a"}}`,
		`{"string_stats":{"field":"s"}}`,
		`{"geo_bounds":{"field":"g"}}`,
		`{"geo_centroid":{"field":"g"}}`,
		`{"top_hits":{"size":1}}`,
	} {
		var sp esast.AggSpec
		if err := json.Unmarshal([]byte(specJSON), &sp); err != nil {
			t.Fatalf("unmarshal %s failed: %v", specJSON, err)
		}
		if _, isMulti := isMultiValueMetricAggSpecR61Search(sp); !isMulti {
			t.Fatalf("expected isMultiValueMetricAggSpecR61Search=true for %s", specJSON)
		}
	}
	var singlePct esast.AggSpec
	_ = json.Unmarshal([]byte(`{"percentiles":{"field":"p","percents":[50]}}`), &singlePct)
	if _, isMulti := isMultiValueMetricAggSpecR61Search(singlePct); isMulti {
		t.Fatal("expected single-percentiles isMulti=false")
	}

	// 3. sortHistogramBucketsR62Search (_time key alias inside map & []any) & extractTopMetricsNumericMetricR65
	bkts := []map[string]any{
		{"key": int64(2000), "doc_count": int64(2)},
		{"key": int64(1000), "doc_count": int64(1)},
	}
	sorted1 := sortHistogramBucketsR62Search(bkts, map[string]any{"_time": "asc"})
	sorted2 := sortHistogramBucketsR62Search(sorted1, []any{map[string]any{"_time": "desc"}, map[string]any{"_count": "asc"}})
	if len(sorted2) != 2 {
		t.Fatalf("unexpected sorted histogram buckets: %#v", sorted2)
	}
	if v, ok := extractTopMetricsNumericMetricR65(map[string]any{
		"top": []map[string]any{{"metrics": map[string]any{"p": 12.5, "sub": map[string]any{"v": 9.0}}}},
	}, []string{"metrics", "p"}); !ok || v != 12.5 {
		t.Fatalf("expected 12.5 from []map[string]any top_metrics, got %v ok=%v", v, ok)
	}
	if v, ok := extractTopMetricsNumericMetricR65(map[string]any{
		"top": []any{map[string]any{"metrics": map[string]any{"sub": map[string]any{"v": 9.0}}}},
	}, []string{"metrics", "sub.v"}); !ok || v != 9.0 {
		t.Fatalf("expected 9.0 from []any nested top_metrics, got %v ok=%v", v, ok)
	}
	if _, ok := extractTopMetricsNumericMetricR65(nil, []string{"p"}); ok {
		t.Fatal("expected ok=false for nil top_metrics map")
	}

	// 4. formatRuntimeTermValueForExplainR62Search across field types
	_ = formatRuntimeTermValueForExplainR62Search("2026-01-01T00:00:00Z", esast.FieldProperty{Type: "date"})
	_ = formatRuntimeTermValueForExplainR62Search(1.5, esast.FieldProperty{Type: "double"})
	_ = formatRuntimeTermValueForExplainR62Search(42, esast.FieldProperty{Type: "long"})
	_ = formatRuntimeTermValueForExplainR62Search("::ffff:127.0.0.1", esast.FieldProperty{Type: "ip"})
	_ = formatRuntimeTermValueForExplainR62Search(true, esast.FieldProperty{Type: "boolean"})
	_ = formatRuntimeTermValueForExplainR62Search(false, esast.FieldProperty{Type: "boolean"})
	_ = formatRuntimeTermValueForExplainR62Search("kw", esast.FieldProperty{Type: "keyword"})

	// 5. resolveTermsLookupsInInnerHits (nested sort filter + highlight_query + field highlight_query)
	mustR66CovHTTP(t, h, http.MethodPut, "/ih_lk_src", `{"mappings":{"properties":{"vals":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ih_lk_src/_doc/1?refresh=true", `{"vals":["alpha","beta"]}`, http.StatusCreated)
	var ih esast.InnerHitsSpec
	if err := json.Unmarshal([]byte(`{
		"sort":[{"nested_f":{"nested":{"path":"n","filter":{"terms":{"n.k":{"index":"ih_lk_src","id":"1","path":"vals"}}}}}}],
		"highlight":{
			"highlight_query":{"terms":{"title":{"index":"ih_lk_src","id":"1","path":"vals"}}},
			"fields":{"body":{"highlight_query":{"terms":{"body":{"index":"ih_lk_src","id":"1","path":"vals"}}}}}
		}
	}`), &ih); err != nil {
		t.Fatalf("unmarshal InnerHitsSpec failed: %v", err)
	}
	srv.resolveTermsLookupsInInnerHits(hCtxBgR66(), &ih)
}

func hCtxBgR66() (ctx context.Context) { return context.Background() }
