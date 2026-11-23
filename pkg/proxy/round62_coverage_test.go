// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func doStatusR62Cov(t *testing.T, srv *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRound62_Coverage_RRF_Profile_SAYT_And_SignificantText(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Create hybrid text + SAYT + vector + range + numeric index
	st, res := doStatusR62Cov(t, srv, http.MethodPut, "/r62_hybrid", `{
		"settings": {
			"number_of_shards": 2,
			"index.sort.field": ["rank", "cat"],
			"index.sort.order": ["desc", "asc"]
		},
		"mappings": {
			"_routing": {"required": false},
			"dynamic_templates": [
				{"as_int": {"match": "dyn_i*", "mapping": {"type": "integer"}}},
				{"as_kw_default": {"match": "dyn_k*", "mapping": {"type": "keyword"}}}
			],
			"properties": {
				"title": {"type": "text"},
				"sayt": {"type": "search_as_you_type", "max_shingle_size": 3},
				"cat": {"type": "keyword"},
				"tags": {"type": "keyword"},
				"rank": {"type": "long"},
				"price": {"type": "double"},
				"weight": {"type": "long"},
				"ip_addr": {"type": "ip"},
				"ts": {"type": "date"},
				"int_rng": {"type": "integer_range"},
				"dt_rng": {"type": "date_range"},
				"vec": {"type": "dense_vector", "dims": 3, "index": true, "similarity": "cosine"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"qty": {"type": "long"},
						"loc": {"type": "geo_point"}
					}
				},
				"doubled_rank": {
					"type": "long",
					"script": {"source": "if (doc['rank'].size() > 0) { emit(doc['rank'].value * 2); }"}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r62_hybrid failed (%d): %v", st, res)
	}

	bulkPayload := strings.Join([]string{
		`{"index":{"_id":"1","routing":"r1","dynamic_templates":{"dyn_i1":"as_int","nested_dyn.sub_k":"as_kw_default"}}}`,
		`{"title":"quick brown fox jumps","sayt":"quick brown fox & <dogs>","cat":"alpha","tags":["t1","t2"],"rank":10,"price":12.5,"weight":2,"ip_addr":"10.0.0.1","ts":"2026-11-01T00:00:00Z","int_rng":{"gte":1,"lte":10},"dt_rng":{"gte":"2026-11-01T00:00:00Z","lte":"2026-11-02T00:00:00Z"},"vec":[1.0,0.0,0.0],"_doc_count":2,"dyn_i1":42,"nested_dyn":{"sub_k":"v1"},"items":[{"sku":"s1","qty":3,"loc":{"lat":40.7,"lon":-74.0}}]}`,
		`{"index":{"_id":"2","routing":"r2"}}`,
		`{"title":"quick brown bear runs","sayt":"quick brown bear runs fast","cat":"alpha","tags":["t2","t3"],"rank":20,"price":25.0,"weight":4,"ip_addr":"10.0.0.2","ts":"2026-11-02T00:00:00Z","int_rng":{"gte":5,"lte":15},"vec":[0.8,0.6,0.0],"items":[{"sku":"s2","qty":5,"loc":"41.0,-73.5"}]}`,
		`{"index":{"_id":"3"}}`,
		`{"title":"lazy dog sleeps","sayt":"lazy dog sleeps all day","cat":"beta","tags":["t1"],"rank":30,"price":50.0,"weight":1,"ip_addr":"192.168.1.1","ts":"2026-11-03T00:00:00Z","vec":[0.0,1.0,0.0],"items":[{"sku":"s3","qty":1,"loc":[-73.9,40.8]}]}`,
		`{"index":{"_id":"4"}}`,
		`{"title":"quick brown fox jumps","sayt":"quick brown fox duplicate","cat":"beta","tags":["t3"],"rank":40,"price":75.0,"weight":3,"ip_addr":"192.168.1.2","ts":"2026-11-04T00:00:00Z","vec":[0.0,0.0,1.0]}`,
	}, "\n") + "\n"
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_bulk?refresh=true", bulkPayload)
	if st != http.StatusOK || res["errors"] != false {
		t.Fatalf("bulk r62_hybrid failed (%d): %v", st, res)
	}

	// Bulk dynamic_templates negative paths (unknown template + object into scalar template)
	badBulk := strings.Join([]string{
		`{"index":{"_id":"bad1","dynamic_templates":{"new_f":"missing_tpl"}}}`,
		`{"new_f":"abc"}`,
		`{"index":{"_id":"bad2","dynamic_templates":{"obj_f":"as_int"}}}`,
		`{"obj_f":{"nested":"bad"}}`,
	}, "\n") + "\n"
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_bulk", badBulk)
	if st != http.StatusOK || res["errors"] != true {
		t.Fatalf("expected per-item dynamic_templates errors in bulk, got (%d): %v", st, res)
	}

	// Both top-level `retriever` and top-level `rank` must be rejected in ES 8.15.
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"retriever": {"standard": {"query": {"match_all": {}}}},
		"rank": {"rrf": {"window_size": 10, "rank_constant": 20}}
	}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 when specifying both [retriever] and [rank], got (%d): %v", st, res)
	}

	// 2. RRF via `retriever.rrf` (with standard, knn, nested rule/text_similarity_reranker, filter, explain, profile, aggs)
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"from": 0,
		"size": 3,
		"explain": true,
		"profile": true,
		"retriever": {
			"text_similarity_reranker": {
				"retriever": {
					"rule": {
						"ruleset_ids": ["rs1"],
						"retriever": {
							"rrf": {
								"rank_window_size": 10,
								"rank_constant": 20,
								"filter": [
									{"range": {"rank": {"gte": 10}}},
									{"exists": {"field": "cat"}}
								],
								"retrievers": [
									{"standard": {"query": {"match": {"title": {"query": "quick", "_name": "q_std"}}}, "filter": [{"term": {"cat": "alpha"}}]}},
									{"knn": {"field": "vec", "query_vector": [1.0, 0.0, 0.0], "k": 3, "num_candidates": 5, "_name": "q_knn"}},
									{"rrf": {"retrievers": [{"standard": {"query": {"term": {"cat": "beta"}}}}]}}
								]
							}
						}
					}
				},
				"field": "title",
				"inference_id": "rerank-1",
				"inference_text": "quick"
			}
		},
		"aggs": {
			"by_cat": {"meta": {"env": "test"}, "terms": {"field": "cat"}}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("RRF retriever search failed (%d): %v", st, res)
	}
	hitsRRF, _ := res["hits"].(map[string]any)["hits"].([]any)
	if len(hitsRRF) == 0 || res["profile"] == nil || res["aggregations"] == nil {
		t.Fatalf("expected RRF hits, profile, and aggregations, got %v", res)
	}

	// RRF via `sub_searches` + top-level `knn` + `track_total_hits: false`, plus `query` + `knn` RRF, plus window_size < size error
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"size": 2,
		"track_total_hits": false,
		"sub_searches": [
			{"query": {"match": {"title": "quick"}}},
			{"query": {"term": {"cat": "beta"}}}
		],
		"knn": [{"field": "vec", "query_vector": [0.0, 1.0, 0.0], "k": 2, "num_candidates": 4}],
		"rank": {"rrf": {"window_size": 5, "rank_constant": 60, "filter": {"range": {"rank": {"gte": 1}}}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("RRF sub_searches failed (%d): %v", st, res)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"size": 2,
		"query": {"match": {"title": "quick"}},
		"knn": [{"field": "vec", "query_vector": [1.0, 0.0, 0.0], "k": 2, "num_candidates": 4}],
		"rank": {"rrf": {}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("RRF query+knn failed: %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"size": 20,
		"query": {"match_all": {}},
		"rank": {"rrf": {"window_size": 5}}
	}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 when RRF window_size < size, got %d", st)
	}

	// 3. Profile + dfs_query_then_fetch across broad aggregator classes
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search?search_type=dfs_query_then_fetch&request_cache=true", `{
		"size": 0,
		"profile": true,
		"query": {"match_all": {}},
		"aggs": {
			"t_fbyf": {"terms": {"field": "cat"}},
			"t_go": {"terms": {"field": "tags", "include": "t.*"}},
			"t_map": {"terms": {"field": "cat", "execution_hint": "map", "collect_mode": "breadth_first"}, "aggs": {"mx": {"max": {"field": "price"}}}},
			"t_num": {"terms": {"field": "price"}},
			"f_one": {"filters": {"filters": {"only": {"term": {"cat": "alpha"}}}}},
			"f_compat": {"filters": {"filters": {"a": {"term": {"cat": "alpha"}}, "b": {"term": {"cat": "beta"}}}}},
			"c_num": {"cardinality": {"field": "rank"}},
			"c_dir": {"cardinality": {"field": "cat", "execution_hint": "direct"}},
			"c_go": {"cardinality": {"field": "cat"}},
			"rare": {"rare_terms": {"field": "cat", "max_doc_count": 2}},
			"mterms": {"multi_terms": {"terms": [{"field": "cat"}, {"field": "rank"}]}},
			"hist": {"histogram": {"field": "rank", "interval": 10}},
			"vwh": {"variable_width_histogram": {"field": "price", "buckets": 2}},
			"dhist": {"date_histogram": {"field": "ts", "calendar_interval": "1d"}},
			"adhist": {"auto_date_histogram": {"field": "ts", "buckets": 3}},
			"ip_pfx": {"ip_prefix": {"field": "ip_addr", "prefix_length": 24}},
			"ip_rng": {"ip_range": {"field": "ip_addr", "ranges": [{"mask": "10.0.0.0/8"}]}},
			"rng": {"range": {"field": "price", "ranges": [{"to": 30}, {"from": 30}]}},
			"comp": {"composite": {"sources": [{"c": {"terms": {"field": "cat"}}}]}},
			"flt": {"filter": {"term": {"cat": "alpha"}}, "aggs": {"av": {"avg": {"field": "price"}}}},
			"glb": {"global": {}, "aggs": {"sm": {"sum": {"field": "price"}}}},
			"mis": {"missing": {"field": "int_rng"}},
			"nst": {"nested": {"path": "items"}, "aggs": {"rn": {"reverse_nested": {}}}},
			"rsmp": {"random_sampler": {"probability": 0.5}, "aggs": {"mn": {"min": {"field": "price"}}}},
			"dsmp": {"diversified_sampler": {"field": "cat", "shard_size": 10}, "aggs": {"vc": {"value_count": {"field": "rank"}}}},
			"smp": {"sampler": {"shard_size": 10}, "aggs": {"st": {"stats": {"field": "price"}}}},
			"est": {"extended_stats": {"field": "price"}},
			"wavg": {"weighted_avg": {"value": {"field": "price"}, "weight": {"field": "weight"}}},
			"pct": {"percentiles": {"field": "price"}},
			"prank": {"percentile_ranks": {"field": "price", "values": [20, 60]}},
			"box": {"boxplot": {"field": "price"}},
			"mad": {"median_absolute_deviation": {"field": "price"}},
			"sstats": {"string_stats": {"field": "cat"}},
			"th": {"top_hits": {"size": 1}}
		}
	}`)
	if st != http.StatusOK || res["profile"] == nil {
		t.Fatalf("DFS profile mega-agg search failed (%d): %v", st, res)
	}
	// Repeat identical request_cache=true query to record cache hit as well!
	_, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search?request_cache=true", `{"size":0,"query":{"term":{"cat":"alpha"}}}`)
	_, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search?request_cache=true", `{"size":0,"query":{"term":{"cat":"alpha"}}}`)

	// 4. SAYT bool_prefix highlight (`sayt`, `sayt._2gram`, `sayt._3gram`) + index default `_doc` sort + sliced search
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"query": {"match_bool_prefix": {"sayt": "quick brown f"}},
		"sort": ["_doc"],
		"highlight": {
			"encoder": "html",
			"fields": {
				"sayt": {},
				"sayt._2gram": {},
				"sayt._3gram": {}
			}
		},
		"fields": ["int_rng", "dt_rng", "doubled_rank"],
		"docvalue_fields": ["dt_rng"]
	}`)
	if st != http.StatusOK {
		t.Fatalf("SAYT highlight search failed (%d): %v", st, res)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"slice": {"field": "rank", "id": 0, "max": 2},
		"query": {"multi_match": {"type": "bool_prefix", "query": "quick brown bear r", "fields": ["sayt", "sayt._2gram", "sayt._3gram"]}},
		"highlight": {"fields": {"sayt._2gram": {}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("SAYT multi_match slice search failed: %d", st)
	}

	// 5. Significant text heuristics (`percentage`, `gnd`, `mutual_information`, `chi_square`, `jlh`) + typo suggestion
	for _, heurJSON := range []string{
		`"percentage": {}`,
		`"gnd": {"background_is_superset": true}`,
		`"gnd": {"background_is_superset": false}`,
		`"mutual_information": {"include_negatives": true, "background_is_superset": false}`,
		`"chi_square": {"include_negatives": true}`,
		`"jlh": {}`,
	} {
		st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
			"size": 0,
			"query": {"term": {"cat": "alpha"}},
			"aggs": {
				"sig": {
					"significant_text": {
						"field": "title",
						"min_doc_count": 1,
						"filter_duplicate_text": true,
						"include": ".*",
						"exclude": "zzz.*",
						"background_filter": {"exists": {"field": "title"}},
						`+heurJSON+`
					},
					"aggs": {"avg_p": {"avg": {"field": "price"}}}
				}
			}
		}`)
		if st != http.StatusOK {
			t.Fatalf("significant_text (%s) failed (%d): %v", heurJSON, st, res)
		}
	}
	// Heuristic typo error & invalid non-text field error
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"aggs": {"sig": {"significant_text": {"field": "title", "chi_sqaure": {}}}}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(stringifyAnyR62Cov(res), "did you mean [chi_square]") {
		t.Fatalf("expected chi_square typo suggestion, got (%d): %v", st, res)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_hybrid/_search", `{
		"aggs": {"sig": {"significant_text": {"field": ""}}}
	}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for significant_text with empty field, got %d", st)
	}
	var sigBadSR esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"aggs":{"sig":{"significant_text":{"field":"rank"}}}}`), &sigBadSR)
	if stSig, _, _ := validateSignificantTextSpecsInAggsR62Search(
		sigBadSR.Aggs,
		[]*schema.IndexSchema{srv.indices["r62_hybrid"]},
	); stSig != http.StatusBadRequest {
		t.Fatalf("expected validateSignificantTextSpecsInAggsR62Search 400 on long field, got %d", stSig)
	}
}

func TestRound62_Coverage_Runtime_Lookup_Explain_TSDB_Join_And_DataStreams(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Lookup runtime field (`target_field` = regular field and `_id`) + negative query/sort/agg checks
	doJSON(t, srv, http.MethodPut, "/r62_users", `{"mappings":{"properties":{"uid":{"type":"keyword"},"dept":{"type":"keyword"},"role":{"type":"keyword"}}}}`)
	doJSON(t, srv, http.MethodPost, "/r62_users/_bulk?refresh=true",
		`{"index":{"_id":"u1"}}`+"\n"+`{"uid":"u1","dept":"eng","role":"sre"}`+"\n"+
			`{"index":{"_id":"u2"}}`+"\n"+`{"uid":"u2","dept":"sec","role":"admin"}`+"\n")

	doJSON(t, srv, http.MethodPut, "/r62_events", `{
		"mappings": {
			"properties": {
				"uid": {"type": "keyword"},
				"val": {"type": "long"},
				"items": {"type": "nested", "properties": {"n": {"type": "long"}}}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_events/_bulk?refresh=true",
		`{"index":{"_id":"e1"}}`+"\n"+`{"uid":"u1","val":10,"loc_raw":"40.7,-74.0","items":[{"n":5,"pt":"40.1,-73.9"}]}`+"\n"+
			`{"index":{"_id":"e2"}}`+"\n"+`{"uid":"u2","val":20,"loc_raw":{"lat":41.0,"lon":-73.5},"items":[{"n":8,"pt":{"lat":41.2,"lon":-73.1}}]}`+"\n")

	st, res := doStatusR62Cov(t, srv, http.MethodPost, "/r62_events/_search", `{
		"explain": true,
		"runtime_mappings": {
			"u_by_field": {
				"type": "lookup",
				"target_index": "r62_users",
				"input_field": "uid",
				"target_field": "uid",
				"fetch_fields": ["dept", "role"]
			},
			"u_by_id": {
				"type": "lookup",
				"target_index": "r62_users",
				"input_field": "uid",
				"target_field": "_id",
				"fetch_fields": ["dept"]
			},
			"comp_rt": {
				"type": "composite",
				"script": {"source": "Map m = new HashMap(); m.put('tag', 'k_' + doc['uid'].value); m.put('num', doc['val'].value * 3); emit(m);"},
				"fields": {
					"tag": {"type": "keyword"},
					"num": {"type": "long"}
				}
			},
			"items.rt_n": {
				"type": "long",
				"script": {"source": "emit(params._source.n * 10)"}
			},
			"items.pt": {
				"type": "geo_point"
			},
			"loc_raw": {
				"type": "geo_point"
			},
			"rt_ip": {
				"type": "ip",
				"script": {"source": "emit('10.1.2.3')"}
			},
			"rt_bool": {
				"type": "boolean",
				"script": {"source": "emit(true)"}
			},
			"rt_double": {
				"type": "double",
				"script": {"source": "emit(3.5)"}
			},
			"rt_date": {
				"type": "date",
				"script": {"source": "emit(1760000000000L)"}
			}
		},
		"query": {
			"script_score": {
				"boost": 2.0,
				"query": {"term": {"rt_ip": {"value": "10.1.2.3", "boost": 1.5}}},
				"script": {"source": "_score + doc['comp_rt.num'].value"}
			}
		},
		"fields": ["u_by_field", "u_by_id", "comp_rt.tag", "comp_rt.num", "items.rt_n", "items.pt", "loc_raw", "rt_bool", "rt_double", "rt_date"]
	}`)
	if st != http.StatusOK {
		t.Fatalf("runtime lookup + composite + nested search failed (%d): %v", st, res)
	}

	// Explain on script query with params and runtime match query
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_events/_search", `{
		"explain": true,
		"runtime_mappings": {"rt_kw": {"type": "keyword", "script": {"source": "emit('hello')"}}},
		"query": {"script": {"script": {"source": "doc['val'].value >= params.min_v", "params": {"min_v": 5}}, "boost": 1.5}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("script explain search failed: %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_events/_search", `{
		"explain": true,
		"runtime_mappings": {"rt_kw": {"type": "keyword", "script": {"source": "emit('hello')"}}},
		"query": {"match": {"rt_kw": {"query": "hello", "boost": 2.0}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("runtime match explain search failed: %d", st)
	}

	// Lookup negative validations (`match`, `term`, `terms`, `range`, `prefix`, `wildcard`, `sort`)
	for _, badLookup := range []string{
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"match":{"lkp":"eng"}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"term":{"lkp":"eng"}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"terms":{"lkp":["eng"]}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"range":{"lkp":{"gte":"a"}}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"prefix":{"lkp":"e"}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"query":{"wildcard":{"lkp":"e*"}}}`,
		`{"runtime_mappings":{"lkp":{"type":"lookup","target_index":"r62_users","input_field":"uid","target_field":"uid","fetch_fields":["dept"]}},"sort":[{"lkp":"asc"}]}`,
	} {
		st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_events/_search", badLookup)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 on lookup field query/sort %s, got %d", badLookup, st)
		}
	}

	// 2. TSDB `time_series` index & agg (`buildTimeSeriesAggObjectR62Search` + `_ts_top_1` join in membackend)
	st, res = doStatusR62Cov(t, srv, http.MethodPut, "/r62_tsdb", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"cpu": {"type": "double", "time_series_metric": "gauge"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r62_tsdb failed (%d): %v", st, res)
	}
	doJSON(t, srv, http.MethodPost, "/r62_tsdb/_bulk?refresh=true",
		`{"index":{}}`+"\n"+`{"@timestamp":"2026-11-17T01:00:00Z","host":"h1","cpu":0.4}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2026-11-17T01:05:00Z","host":"h1","cpu":0.6}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2026-11-17T01:00:00Z","host":"h2","cpu":0.8}`+"\n")
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_tsdb/_search", `{
		"size": 0,
		"aggs": {
			"ts": {
				"time_series": {"size": 10},
				"aggs": {
					"avg_cpu": {"avg": {"field": "cpu"}}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("TSDB time_series agg failed (%d): %v", st, res)
	}

	// 3. Parent-child `join` index (`children`, `parent`, `terms -> children`, `terms -> parent`, `docvalue_fields` on join)
	doJSON(t, srv, http.MethodPut, "/r62_join", `{
		"mappings": {
			"properties": {
				"rel": {"type": "join", "relations": {"question": "answer"}},
				"tag": {"type": "keyword"},
				"votes": {"type": "long"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_join/_bulk?refresh=true",
		`{"index":{"_id":"q1","routing":"q1"}}`+"\n"+`{"rel":"question","tag":"go","votes":10}`+"\n"+
			`{"index":{"_id":"a1","routing":"q1"}}`+"\n"+`{"rel":{"name":"answer","parent":"q1"},"tag":"ans","votes":5}`+"\n"+
			`{"index":{"_id":"a2","routing":"q1"}}`+"\n"+`{"rel":{"name":"answer","parent":"q1"},"tag":"ans2","votes":7}`+"\n")
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_join/_search", `{
		"docvalue_fields": ["rel"],
		"fields": ["rel"],
		"aggs": {
			"to_ans": {"children": {"type": "answer"}, "aggs": {"sum_v": {"sum": {"field": "votes"}}}},
			"to_q": {"parent": {"type": "answer"}, "aggs": {"max_v": {"max": {"field": "votes"}}}},
			"by_q_tag": {"terms": {"field": "tag"}, "aggs": {"kids": {"children": {"type": "answer"}}}},
			"by_a_tag": {"terms": {"field": "tag"}, "aggs": {"pars": {"parent": {"type": "answer"}}}}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("join aggs search failed (%d): %v", st, res)
	}

	// 4. Data streams, failure store rollover, migrate, modify, resolve index, analyze, tasks, and stats
	doJSON(t, srv, http.MethodPut, "/_index_template/r62_ds_tpl", `{
		"index_patterns": ["r62-ds-*"],
		"data_stream": {},
		"template": {
			"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "text"}}}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/_data_stream/r62-ds-logs", `{}`)
	doJSON(t, srv, http.MethodPost, "/r62-ds-logs/_doc?refresh=true", `{"@timestamp":"2026-11-17T02:00:00Z","msg":"hello world"}`)

	// Failure store lazy, dry_run, and live rollover + regular rollover
	for _, roPath := range []string{
		"/r62-ds-logs/_rollover?target_failure_store=true&lazy=true",
		"/r62-ds-logs/_rollover?target_failure_store=true&dry_run=true",
		"/r62-ds-logs/_rollover?target_failure_store=true",
		"/r62-ds-logs/_rollover",
	} {
		st, res = doStatusR62Cov(t, srv, http.MethodPost, roPath, `{}`)
		if st != http.StatusOK {
			t.Fatalf("rollover %s failed (%d): %v", roPath, st, res)
		}
	}
	// Negative rollover checks
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_users/_rollover?target_failure_store=true", `{}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on target_failure_store for non-data-stream, got %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62-ds-logs/_rollover", `{"mappings":{}}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsupported mappings in data stream rollover, got %d", st)
	}

	// Direct handler coverage for Round 48 / 49 / 58 data stream & resolve index endpoints
	doJSON(t, srv, http.MethodPut, "/r62_extra_backing", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r62_mig_idx", `{"settings":{"index.hidden":true},"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`)
	doJSON(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"r62_mig_idx","alias":"r62_mig_alias","is_write_index":true}}]}`)
	doJSON(t, srv, http.MethodPut, "/r62_closed_idx", `{}`)
	doJSON(t, srv, http.MethodPost, "/r62_closed_idx/_close", `{}`)

	callDirect := func(fn func(http.ResponseWriter, *http.Request), method, target string, pathVals map[string]string, body string) int {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range pathVals {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		fn(rec, req)
		return rec.Code
	}

	if code := callDirect(srv.handleResolveIndexRound58, http.MethodGet, "/_resolve/index/*?expand_wildcards=open,closed,hidden", map[string]string{"name": "*"}, ""); code != http.StatusOK {
		t.Fatalf("handleResolveIndexRound58 all failed: %d", code)
	}
	if code := callDirect(srv.handleResolveIndexRound58, http.MethodGet, "/_resolve/index/*?expand_wildcards=none", map[string]string{"name": "*"}, ""); code != http.StatusOK {
		t.Fatalf("handleResolveIndexRound58 none failed: %d", code)
	}
	_ = callDirect(srv.handleResolveIndexRound58, http.MethodPost, "/_resolve/index/*", nil, "")
	_ = callDirect(srv.handleResolveIndexRound58, http.MethodGet, "/_resolve/index/*?expand_wildcards=invalid", nil, "")

	if code := callDirect(srv.handleDataStreamsStats, http.MethodGet, "/_data_stream/_stats", nil, ""); code != http.StatusOK {
		t.Fatalf("handleDataStreamsStats failed: %d", code)
	}
	if code := callDirect(srv.handleMigrateToDataStream, http.MethodPost, "/_data_stream/_migrate/r62_mig_alias", map[string]string{"name": "r62_mig_alias"}, ""); code != http.StatusOK {
		t.Fatalf("handleMigrateToDataStream failed: %d", code)
	}
	_ = callDirect(srv.handleMigrateToDataStream, http.MethodPost, "/_data_stream/_migrate/r62_users", map[string]string{"name": "r62_users"}, "")
	_ = callDirect(srv.handleMigrateToDataStream, http.MethodPost, "/_data_stream/_migrate/r62-ds-logs", map[string]string{"name": "r62-ds-logs"}, "")
	_ = callDirect(srv.handleMigrateToDataStream, http.MethodPost, "/_data_stream/_migrate/missing_al", map[string]string{"name": "missing_al"}, "")

	if code := callDirect(srv.handleModifyDataStream, http.MethodPost, "/_data_stream/_modify", nil,
		`{"actions":[{"add_backing_index":{"data_stream":"r62-ds-logs","index":"r62_extra_backing"}}]}`); code != http.StatusOK {
		t.Fatalf("handleModifyDataStream add_backing_index failed: %d", code)
	}
	if code := callDirect(srv.handleModifyDataStream, http.MethodPost, "/_data_stream/_modify", nil,
		`{"actions":[{"remove_backing_index":{"data_stream":"r62-ds-logs","index":"r62_extra_backing"}}]}`); code != http.StatusOK {
		t.Fatalf("handleModifyDataStream remove_backing_index failed: %d", code)
	}
	_ = callDirect(srv.handleModifyDataStream, http.MethodPost, "/_data_stream/_modify", nil, `{"actions":[]}`)
	_ = callDirect(srv.handleModifyDataStream, http.MethodPost, "/_data_stream/_modify", nil,
		`{"actions":[{"add_backing_index":{"data_stream":"missing","index":"r62_extra_backing"}}]}`)

	// Analyze endpoint (`explain: true`, `attributes`, field target on alias/normalizer/SAYT, query params)
	doJSON(t, srv, http.MethodPut, "/r62_an", `{
		"settings": {"analysis": {"normalizer": {"my_norm": {"type": "custom", "filter": ["lowercase"]}}}},
		"mappings": {
			"properties": {
				"kw": {"type": "keyword", "normalizer": "my_norm"},
				"kw_alias": {"type": "alias", "path": "kw"},
				"sayt": {"type": "search_as_you_type"}
			}
		}
	}`)
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_an/_analyze", `{"field":"kw_alias","text":["Hello","World"],"explain":true}`)
	if st != http.StatusOK {
		t.Fatalf("analyze kw_alias failed: %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_an/_analyze", `{"field":"sayt","text":"Quick Fox","explain":true,"attributes":["keyword"]}`)
	if st != http.StatusOK {
		t.Fatalf("analyze sayt explain failed: %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodGet, "/_analyze?text=<b>Hi</b>&text=There&tokenizer=standard&filter=lowercase&char_filter=html_strip", "")
	if st != http.StatusOK {
		t.Fatalf("analyze query-params failed: %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_closed_idx/_analyze", `{"text":"hi"}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on closed index analyze, got %d", st)
	}

	// Ingest pipeline with on_failure + async task + /.tasks/_search + /_nodes/stats + /_stats
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r62_pip", `{
		"processors": [
			{"convert": {"field": "num_s", "type": "integer", "on_failure": [{"set": {"field": "err_flag", "value": true}}]}}
		]
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_users/_doc/p1?pipeline=r62_pip&refresh=true", `{"uid":"p1","num_s":"not_int"}`)
	doJSON(t, srv, http.MethodPost, "/r62_users/_update_by_query?wait_for_completion=false", `{"query":{"match_all":{}}}`)
	// Allow background UBQ goroutine to finish so synthesizeTasksIndexHitsR62Search emits `.tasks` hits
	for attempt := 0; attempt < 20; attempt++ {
		hits := srv.synthesizeTasksIndexHitsR62Search()
		if len(hits) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, _ = doStatusR62Cov(t, srv, http.MethodPost, "/.tasks/_search", `{"query":{"match_all":{}}}`)
	_, _ = doStatusR62Cov(t, srv, http.MethodGet, "/_nodes/stats", "")
	_, _ = doStatusR62Cov(t, srv, http.MethodGet, "/_stats", "")
}

func TestRound62_Coverage_DirectHelpers_MemBackend_DateMath_QueryRefs_And_Painless(t *testing.T) {
	// 1. Direct `evalColumnFuncR62Mem` + `murmurHash3x8632R62Mem`
	hexIPv6 := hex.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	b64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	row := map[string]any{
		"_id":                  "doc1",
		"f__s":                 "abcdef",
		"f__hex":               hexIPv6,
		"f__b64":               b64,
		"f__ip4":               int64(0x0a000001),
		"f__ip6":               "::1",
		"_doc":                 `{"nested":{"k":"val1"}}`,
		"`_jp_1`.`_jp_bkey_1`": "joined_val",
	}
	exprs := []string{
		"`base_matched`.`f__s`",
		"CAST(`base_matched`.`_doc`['nested']['k'] AS STRING)",
		"`_jp_1`.`_jp_bkey_1`",
		"`_doc`['nested']['k']",
		"[NULL]",
		"[`f__s`]",
		"RIGHT(`f__s`, 3)",
		"RIGHT(`f__s`, 0)",
		"RPAD(`f__s`, 10, 'xy')",
		"RPAD(`f__s`, 3, 'x')",
		"REPLACE(`f__s`, 'cd', 'CD')",
		"CONV('ff', 16, 10)",
		"CONV('255', 10, 16)",
		"UNHEX(`f__hex`)",
		"FROM_BASE64(`f__b64`)",
		"IPV4_NUM_TO_STRING(`f__ip4`)",
		"IPV6_NUM_TO_STRING(UNHEX(`f__hex`))",
		"IPV6_STRING_TO_NUM_OR_NULL(`f__ip6`)",
		"MURMUR_HASH3_32('a')",
		"MURMUR_HASH3_32('ab')",
		"MURMUR_HASH3_32('abc')",
		"MURMUR_HASH3_32('abcd')",
		"MURMUR_HASH3_32('abcdefg')",
	}
	for _, ex := range exprs {
		if _, ok := evalColumnFuncR62Mem(row, ex); !ok {
			t.Fatalf("expected evalColumnFuncR62Mem(%q) to match", ex)
		}
	}

	// 2. Date-math index resolution (`resolveESIndexDateMathR62Search`, `parseESDateMathBaseAndOpsR62Search`, `parseFixedOffsetTZR62Search`)
	dateMathCases := []string{
		`<logs-{2026-11-17||+1y-2M+1w-3d+4h-5m+6s/d{yyyy.MM.dd|+05:30}}>`,
		`<logs-{2026-11-17||/y{yyyy|UTC}}>`,
		`<logs-{2026-11-17||/M{yyyy.MM|-0800}}>`,
		`<logs-{2026-11-17||/w{yyyy.MM.dd|+02}}>`,
		`<logs-{2026-11-17||/h{yyyy.MM.dd-HH|Z}}>`,
		`<logs-{now/m{yyyy.MM.dd-HHmm}}>`,
		`<logs-{now/s}>`,
	}
	for _, dm := range dateMathCases {
		got := resolveESIndexDateMathR62Search(dm)
		if strings.HasPrefix(got, "<") {
			t.Fatalf("expected date-math %q to resolve, got %q", dm, got)
		}
	}

	// 3. `collectQueryFieldRefsR62Search` across diverse query AST nodes
	var q esast.Query
	if err := json.Unmarshal([]byte(`{
		"bool": {
			"must": [
				{"terms_set": {"tags": {"terms": ["a"], "minimum_should_match_field": "req_cnt"}}},
				{"terms_set": {"tags": {"terms": ["a"], "minimum_should_match_script": {"source": "doc['rt_a'].value"}}}},
				{"common": {"body": {"query": "the quick"}}},
				{"intervals": {"body": {"match": {"query": "quick fox"}}}},
				{"multi_match": {"query": "fox"}},
				{"multi_match": {"query": "fox", "fields": ["title^2"]}},
				{"query_string": {"query": "rt_a:foo"}},
				{"query_string": {"query": "foo", "fields": ["title^3"]}},
				{"simple_query_string": {"query": "bar"}},
				{"simple_query_string": {"query": "bar", "fields": ["body^2"]}},
				{"geo_bounding_box": {"loc": {"top_left": [-75, 41], "bottom_right": [-73, 40]}}},
				{"geo_distance": {"distance": "10km", "loc": [-74.0, 40.7]}},
				{"distance_feature": {"field": "ts", "pivot": "7d", "origin": "now"}}
			],
			"should": [
				{
					"function_score": {
						"query": {"match_phrase": {"title": "quick"}},
						"field_value_factor": {"field": "rank"}
					}
				},
				{
					"function_score": {
						"query": {"match_all": {}},
						"script_score": {"script": {"source": "doc['rt_b'].value"}}
					}
				},
				{
					"function_score": {
						"query": {"match_all": {}},
						"functions": [
							{"filter": {"match_phrase_prefix": {"title": "qu"}}, "field_value_factor": {"field": "weight"}},
							{"filter": {"match_bool_prefix": {"title": "qu"}}, "script_score": {"script": {"source": "doc['rt_a'].value"}}}
						]
					}
				}
			]
		}
	}`), &q); err != nil {
		t.Fatalf("unmarshal complex query failed: %v", err)
	}
	seenRefs := make(map[string]bool)
	collectQueryFieldRefsR62Search(&q, map[string]bool{"rt_a": true, "rt_b": true}, func(f string) {
		seenRefs[f] = true
	})
	if !seenRefs["rt_a"] || !seenRefs["rt_b"] || !seenRefs["loc"] || !seenRefs["ts"] {
		t.Fatalf("missing collected field refs: %v", seenRefs)
	}

	// 4. Painless ISO-8601 Duration/Period, end-anchor `$` regex, `field(...)` getValue/getValues, `instanceof`, and synthetic semver
	painlessScripts := []string{
		`Duration.parse("P2DT3H4M5.5S").toSeconds() + Duration.parse("-PT15M").toMinutes()`,
		`Period.parse("P1Y2M3W4D").getDays() + Period.parse("-P2M").getMonths()`,
		`Pattern.compile("foo$").matcher("bar\nfoo").find() && !Pattern.compile("foo\\z").matcher("foo\n").find()`,
		`def s = "hi"; def n = 42L; def d = 1.5; def b = true; def l = [1, 2]; def m = ['a': 1]; (s instanceof String) && (n instanceof Number) && (n instanceof Long) && (d instanceof Double) && (b instanceof Boolean) && (l instanceof List) && (m instanceof Map)`,
		`field('u').getValue(0) != null && field('u').getValues().size() == 2 && field('missing_f').getValue(99) == 99`,
	}
	evalDoc := map[string]any{
		"u":             []any{uint64(10), uint64(20)},
		"__field_types": map[string]string{"u": "unsigned_long"},
	}
	for _, src := range painlessScripts {
		res, err := painless.Eval(evalDoc, src, nil)
		if err != nil || res == nil {
			t.Fatalf("Painless script %q failed: res=%v err=%v", src, res, err)
		}
	}

	// 5. Schema LockAutoDims & Synthetic `_source` with `version` array sorting
	var verSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"ver": {"type": "version"},
			"auto_v": {"type": "dense_vector"}
		}
	}`), &verSpec)
	verSchema := schema.CompileIndexSchema("db", "ver_idx", &verSpec)
	_ = verSchema.LockAutoDims("auto_v", 4)
	synth := schema.ReconstructSyntheticSource(verSchema, map[string]any{"ver": []any{"1.10.0", "1.2.0", "1.0.0-alpha"}}, nil)
	if synth == nil {
		t.Fatalf("expected synthetic source reconstruction for version field")
	}
}

func TestRound62_Coverage_Batch2_MovingWindow_Highlight_Ingest_ESQL_And_Wrappers(t *testing.T) {
	srv, _ := newTestServer()

	// 1. `evalMovingWindow` across all MovingFunctions.* and custom Painless script
	windowSlice := []float64{10, 20, 30, 40}
	for _, scriptSrc := range []string{
		"MovingFunctions.max(values)",
		"MovingFunctions.min(values)",
		"MovingFunctions.sum(values)",
		"MovingFunctions.stdDev(values, MovingFunctions.unweightedAvg(values))",
		"MovingFunctions.linearWeightedAvg(values)",
		"MovingFunctions.ewma(values, 0.5)",
		"MovingFunctions.ewma(values, params.a)",
		"MovingFunctions.unweightedAvg(values)",
		"values.size() * 2.5",
	} {
		rawSpec := `{"buckets_path":"c","window":4,"settings":{"alpha":0.4},"script":{"source":"` + scriptSrc + `","params":{"a":0.6}}}`
		var maSpec esast.MovingAvgAggSpec
		if err := json.Unmarshal([]byte(rawSpec), &maSpec); err != nil {
			t.Fatalf("unmarshal MovingAvgAggSpec(%s) failed: %v", scriptSrc, err)
		}
		if got := evalMovingWindow(windowSlice, &maSpec); got <= 0 {
			t.Fatalf("expected positive moving window result for %s, got %v", scriptSrc, got)
		}
	}

	// 2. `collectTermsFromQueryForFields` across all 16 query clauses
	var hlQ esast.Query
	if err := json.Unmarshal([]byte(`{
		"bool": {
			"must": [
				{"term": {"title": "t_one"}},
				{"terms": {"title": ["t_two", "t_three"]}},
				{"match": {"title": "m_one m_two"}},
				{"match_phrase": {"title": "exact phrase"}},
				{"match_phrase": {"title": {"query": "slop phrase", "slop": 2}}},
				{"match_phrase_prefix": {"title": "pre one two"}},
				{"match_bool_prefix": {"title": "bool one two"}},
				{"combined_fields": {"query": "comb tok", "fields": ["title"]}},
				{"multi_match": {"type": "phrase", "query": "mm exact", "fields": ["title"]}},
				{"multi_match": {"type": "phrase", "query": "mm slop", "slop": 1, "fields": ["title"]}},
				{"multi_match": {"type": "phrase_prefix", "query": "mm pfx", "fields": ["title"]}},
				{"multi_match": {"type": "best_fields", "query": "mm best", "fields": ["title"]}},
				{"query_string": {"query": "qs_tok", "default_field": "title"}},
				{"simple_query_string": {"query": "sqs_tok~2 +req", "fields": ["title"]}},
				{"wildcard": {"title": "wild*"}},
				{"prefix": {"title": "pfx"}},
				{"terms_set": {"title": {"terms": ["ts1"], "minimum_should_match_field": "c"}}},
				{"fuzzy": {"title": "fuz"}},
				{"regexp": {"title": ".*reg.*"}}
			]
		}
	}`), &hlQ); err != nil {
		t.Fatalf("unmarshal highlight query failed: %v", err)
	}
	var hlTerms []string
	collectTermsFromQueryForFields(&hlQ, map[string]bool{"title": true}, &hlTerms)
	if len(hlTerms) < 15 {
		t.Fatalf("expected >= 15 extracted highlight terms, got %d: %v", len(hlTerms), hlTerms)
	}

	// 3. `convertSingleIngestValue` across numeric widths, unsigned_long, float, and error cases
	convCases := []struct {
		val  any
		kind string
		ok   bool
	}{
		{"42", "integer", true},
		{int(12), "short", true},
		{int64(7), "byte", true},
		{int32(99), "long", true},
		{int16(15), "short", true},
		{int8(3), "byte", true},
		{uint(25), "integer", true},
		{uint64(50), "long", true},
		{float64(100), "integer", true},
		{float32(12), "short", true},
		{json.Number("77"), "integer", true},
		{json.Number("88.0"), "integer", true},
		{"999999", "byte", false},
		{map[string]any{"a": 1}, "integer", false},
		{"18446744073709551615", "unsigned_long", true},
		{uint64(123), "unsigned_long", true},
		{uint(45), "unsigned_long", true},
		{int(9), "unsigned_long", true},
		{int64(99), "unsigned_long", true},
		{float64(256), "unsigned_long", true},
		{float32(64), "unsigned_long", true},
		{json.Number("1024"), "unsigned_long", true},
		{"-5", "unsigned_long", false},
		{"3.14", "double", true},
	}
	for _, tc := range convCases {
		_, err := convertSingleIngestValue(tc.val, tc.kind)
		if tc.ok && err != nil {
			t.Fatalf("convertSingleIngestValue(%#v, %q) unexpected error: %v", tc.val, tc.kind, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("convertSingleIngestValue(%#v, %q) expected error", tc.val, tc.kind)
		}
	}

	// 4. `executeGeoIPProcessor` across City/Country/ASN, Linköping, unallocated, loopback, array first_only=false, properties
	geoCases := []struct {
		doc  map[string]any
		spec map[string]any
	}{
		{map[string]any{"ip": "89.160.20.128"}, map[string]any{"field": "ip"}},
		{map[string]any{"ip": "8.8.8.8"}, map[string]any{"field": "ip", "database_file": "GeoLite2-Country.mmdb"}},
		{map[string]any{"ip": "8.8.8.8"}, map[string]any{"field": "ip", "database_file": "GeoLite2-ASN.mmdb"}},
		{map[string]any{"ip": "89.160.20.128"}, map[string]any{"field": "ip", "properties": []any{"city_name", "country_iso_code"}}},
		{map[string]any{"ip": []any{"127.0.0.1", "80.231.5.0", "89.160.20.128", "8.8.8.8"}}, map[string]any{"field": "ip", "first_only": false}},
	}
	for _, gc := range geoCases {
		if _, err := executeGeoIPProcessor(gc.doc, gc.spec); err != nil {
			t.Fatalf("executeGeoIPProcessor(%v) failed: %v", gc.spec, err)
		}
	}
	if _, err := executeGeoIPProcessor(map[string]any{}, map[string]any{"field": "ip", "ignore_missing": false}); err == nil {
		t.Fatalf("expected error on missing geoip field with ignore_missing=false")
	}

	// 5. `evalESQLFuncRound57` & `evalSQLScalarFunc`
	esqlCalls := []struct {
		fn   string
		args []any
	}{
		{"REPLACE", []any{"hello 123", "[0-9]+", "N"}},
		{"SUBSTRING", []any{"abcdef", int64(2), int64(3)}},
		{"SUBSTRING", []any{"abcdef", int64(-2)}},
		{"SUBSTRING", []any{"abcdef", int64(0), int64(2)}},
		{"SPLIT", []any{"a,b,c", ","}},
		{"STARTS_WITH", []any{"foobar", "foo"}},
		{"ENDS_WITH", []any{"foobar", "bar"}},
		{"LOCATE", []any{"hello world", "world", int64(2)}},
		{"LTRIM", []any{"  hi"}},
		{"RTRIM", []any{"hi  "}},
		{"LEFT", []any{"abcdef", int64(3)}},
		{"RIGHT", []any{"abcdef", int64(3)}},
		{"FLOOR", []any{float64(3.9)}},
		{"CEIL", []any{float64(3.1)}},
		{"POW", []any{float64(2), float64(4)}},
		{"SQRT", []any{float64(16)}},
		{"MOD", []any{int64(10), int64(3)}},
		{"MOD", []any{float64(10.5), float64(3.0)}},
		{"GREATEST", []any{int64(2), int64(9), int64(5)}},
		{"LEAST", []any{int64(2), int64(9), int64(5)}},
		{"CASE", []any{false, "no", true, "yes", "dflt"}},
		{"TO_DATETIME", []any{"2026-11-17T00:00:00Z"}},
		{"MV_COUNT", []any{[]any{1, 2, 3}}},
		{"MV_MIN", []any{[]any{int64(5), int64(2), int64(8)}}},
		{"MV_MAX", []any{[]any{int64(5), int64(2), int64(8)}}},
		{"MV_SUM", []any{[]any{int64(2), int64(3)}}},
		{"MV_SUM", []any{[]any{int64(2), float64(3.5)}}},
		{"MV_AVG", []any{[]any{float64(2), float64(4)}}},
		{"MV_CONCAT", []any{[]any{"a", "b"}, "-"}},
		{"MV_DEDUPE", []any{[]any{"x", "x", "y"}}},
	}
	for _, c := range esqlCalls {
		if v, ok := evalESQLFuncRound57(c.fn, c.args); !ok || v == nil {
			t.Fatalf("evalESQLFuncRound57(%s) returned (%v, %v)", c.fn, v, ok)
		}
	}
	sqlCalls := []struct {
		fn   string
		args []any
	}{
		{"LOWER", []any{"ABC"}},
		{"UPPER", []any{"abc"}},
		{"LENGTH", []any{"hello"}},
		{"CONCAT", []any{"a", "b", "c"}},
		{"SUBSTRING", []any{"abcdef", int64(2), int64(3)}},
		{"SUBSTRING", []any{"abcdef", int64(3)}},
		{"TRIM", []any{"  x  "}},
		{"LTRIM", []any{"  x"}},
		{"RTRIM", []any{"x  "}},
		{"COALESCE", []any{nil, "ok"}},
		{"ROUND", []any{float64(3.6)}},
		{"ABS", []any{float64(-5)}},
		{"FLOOR", []any{float64(4.8)}},
	}
	for _, c := range sqlCalls {
		if v := evalSQLScalarFunc(c.fn, c.args); v == nil {
			t.Fatalf("evalSQLScalarFunc(%s) returned nil", c.fn)
		}
	}

	// 6. `?require_data_stream=true` & multi-index `auto_date_histogram`
	doJSON(t, srv, http.MethodPut, "/_index_template/r62_b2_tpl", `{
		"index_patterns": ["r62-b2-ds-*"],
		"data_stream": {},
		"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}}}}
	}`)
	st, _ := doStatusR62Cov(t, srv, http.MethodPost, "/r62-b2-ds-auto/_doc?require_data_stream=true&refresh=true", `{"@timestamp":"2026-11-17T01:00:00Z"}`)
	if st != http.StatusCreated {
		t.Fatalf("expected 201 auto-creating data stream with require_data_stream=true, got %d", st)
	}
	doJSON(t, srv, http.MethodPut, "/r62_ad1", `{"mappings":{"properties":{"ts":{"type":"date"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r62_ad2", `{"mappings":{"properties":{"ts":{"type":"date"}}}}`)
	doJSON(t, srv, http.MethodPost, "/r62_ad1/_doc/1?refresh=true", `{"ts":"2026-11-01T00:00:00Z"}`)
	doJSON(t, srv, http.MethodPost, "/r62_ad2/_doc/2?refresh=true", `{"ts":"2026-11-05T00:00:00Z"}`)
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r62_ad1/_doc?require_data_stream=true", `{"ts":"2026-11-01T00:00:00Z"}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on require_data_stream=true against regular index, got %d", st)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/no_such_ds_no_tpl/_doc?require_data_stream=true", `{"ts":"2026-11-01T00:00:00Z"}`)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 on require_data_stream=true with no template, got %d", st)
	}
	st, res := doStatusR62Cov(t, srv, http.MethodPost, "/r62_ad1,r62_ad2/_search", `{
		"size": 0,
		"aggs": {"ad": {"auto_date_histogram": {"field": "ts", "buckets": 2}}}
	}`)
	if st != http.StatusOK || res["aggregations"] == nil {
		t.Fatalf("multi-index auto_date_histogram failed (%d): %v", st, res)
	}

	// 7. Painless doc-value wrapper properties (`GeoPointVal`, `IPAddressVal`, `DenseVectorFieldVal`, `ZonedDateTimeVal`) & multiline end-anchors
	doJSON(t, srv, http.MethodPut, "/r62_wrap", `{
		"mappings": {
			"properties": {
				"pt": {"type": "geo_point"},
				"ip": {"type": "ip"},
				"vec": {"type": "dense_vector", "dims": 2},
				"ts": {"type": "date"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_wrap/_doc/1?refresh=true", `{"pt":{"lat":40.7,"lon":-74.0},"ip":"10.0.0.1","vec":[3.0,4.0],"ts":"2026-11-17T12:30:00Z"}`)
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_wrap/_search", `{
		"script_fields": {
			"info": {
				"script": {
					"source": "def g = doc['pt'].value; def ip = doc['ip'].value; def vf = doc['vec']; def v = vf.value; def d = doc['ts'].value; def rx = ('a\\nend' =~ /(?m)(foo\\z|end$)/); return g.lat + ':' + g.lon + ':' + ip.hostAddress + ':' + ip.IPv4 + ':' + ip.IPv6 + ':' + ip.private + ':' + ip.loopbackAddress + ':' + vf.dims + ':' + vf.empty + ':' + vf.magnitude + ':' + v.length + ':' + v[0] + ':' + d.year + ':' + d.monthValue + ':' + rx;"
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("wrapper properties script_fields search failed (%d): %v", st, res)
	}
}

func TestRound62_Coverage_Batch3_PainlessMathOptional_GlobalSortReindex_SubComposite_And_MemAggs(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Painless `Math.*` static calls (`eval.go:15733-15958`) + `Optional.*` methods (`eval.go:10876-10994`)
	mathScript := strings.Join([]string{
		"def a = Math.abs(-5.5) + Math.min(2.0, 4.0) + Math.max(2.0, 4.0) + Math.round(3.6) + Math.floor(3.9) + Math.ceil(3.1);",
		"def b = Math.pow(2.0, 3.0) + Math.sqrt(9.0) + Math.hypot(3.0, 4.0) + Math.log(Math.E) + Math.log10(100.0) + Math.exp(1.0);",
		"def c = Math.signum(5.0) + Math.signum(-5.0) + Math.signum(0.0) + Math.clamp(15.0, 0.0, 10.0);",
		"def d = Math.sin(0.5) + Math.cos(0.5) + Math.tan(0.5) + Math.asin(0.5) + Math.acos(0.5) + Math.atan(0.5) + Math.atan2(1.0, 2.0);",
		"def e = Math.sinh(0.5) + Math.cosh(0.5) + Math.tanh(0.5) + Math.cbrt(27.0) + Math.expm1(0.5) + Math.log1p(0.5);",
		"def f = Math.toRadians(180.0) + Math.toDegrees(3.14159) + Math.ulp(1.0) + Math.ulp(0.0);",
		"def g = Math.nextAfter(1.0, 2.0) + Math.nextUp(1.0) + Math.nextDown(1.0) + Math.IEEEremainder(5.0, 2.0) + Math.copySign(3.0, -1.0) + Math.scalb(1.5, 2) + Math.getExponent(8.0) + Math.getExponent(0.0);",
		"return a + b + c + d + e + f + g;",
	}, " ")
	if res, err := painless.Eval(map[string]any{}, mathScript, nil); err != nil || res == nil {
		t.Fatalf("Painless Math.* script failed: res=%v err=%v", res, err)
	}

	optScript := strings.Join([]string{
		"List acc = new ArrayList();",
		"def v1 = Optional.of('hello').filter(x -> x.length() > 2).map(x -> x + '!').orElseGet(() -> 'fallback');",
		"def v2 = Optional.empty().filter(x -> true).map(x -> x).orElseGet(() -> 'empty_fb');",
		"def v3 = Optional.of('ok').orElseThrow(() -> new IllegalArgumentException('boom'));",
		"Optional.of('p').ifPresent(x -> acc.add(x));",
		"Optional.of('q').ifPresentOrElse(x -> acc.add(x), () -> acc.add('none'));",
		"Optional.empty().ifPresentOrElse(x -> acc.add(x), () -> acc.add('was_empty'));",
		"return v1 + ':' + v2 + ':' + v3 + ':' + acc.size();",
	}, " ")
	if res, err := painless.Eval(map[string]any{}, optScript, nil); err != nil || res != "hello!:empty_fb:ok:3" {
		t.Fatalf("Painless Optional.* script failed: res=%v err=%v", res, err)
	}

	// 2. Multi-index `_reindex` with `source.sort` + runtime `script` query (`features.go:10977-11076`)
	doJSON(t, srv, http.MethodPut, "/r62_rx1", `{"mappings":{"properties":{"rank":{"type":"long"},"tag":{"type":"keyword"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r62_rx2", `{"mappings":{"properties":{"rank":{"type":"long"},"tag":{"type":"keyword"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r62_rx_dst", `{"mappings":{"properties":{"rank":{"type":"long"},"tag":{"type":"keyword"}}}}`)
	doJSON(t, srv, http.MethodPost, "/r62_rx1/_doc/1?refresh=true", `{"rank":10,"tag":"a"}`)
	doJSON(t, srv, http.MethodPost, "/r62_rx2/_doc/2?refresh=true", `{"rank":30,"tag":"b"}`)
	st, res := doStatusR62Cov(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {
			"index": ["r62_rx1", "r62_rx2"],
			"sort": [{"rank": "desc"}],
			"query": {"script": {"script": {"source": "doc['rank'].value >= 5"}}}
		},
		"dest": {"index": "r62_rx_dst"}
	}`)
	if st != http.StatusOK || res["created"] != float64(2) {
		t.Fatalf("multi-index sorted script _reindex failed (%d): %v", st, res)
	}

	// 3. Sub-composite agg (`date_histogram`, `histogram`, `geotile_grid`), array `terms` `missing`, `nested` `terms` `missing`, & `multi_terms` date `format`
	doJSON(t, srv, http.MethodPut, "/r62_subc", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"tags": {"type": "keyword", "multi_valued": true},
				"ts": {"type": "date"},
				"val": {"type": "double"},
				"loc": {"type": "geo_point"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"qty": {"type": "long"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_subc/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"grp":"g1","tags":["x","y"],"ts":"2026-11-17T10:15:30Z","val":12.5,"loc":{"lat":40.7,"lon":-74.0},"items":[{"sku":"s1","qty":2},{"qty":4}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"grp":"g1","items":[{"sku":"s2","qty":1}]}`+"\n")
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r62_subc/_search", `{
		"size": 0,
		"aggs": {
			"top_comp": {
				"composite": {
					"sources": [
						{"dh": {"date_histogram": {"field": "ts", "calendar_interval": "1h", "missing_bucket": true, "script": {"source": "_value"}}}},
						{"hg": {"histogram": {"field": "val", "interval": 5, "missing_bucket": true, "script": {"source": "_value"}}}},
						{"gt": {"geotile_grid": {"field": "loc", "precision": 6, "missing_bucket": true}}}
					]
				}
			},
			"arr_miss": {"terms": {"field": "tags", "missing": "NO_TAG"}},
			"nst": {
				"nested": {"path": "items"},
				"aggs": {
					"sku_plain": {"terms": {"field": "items.sku"}},
					"sku_miss": {"terms": {"field": "items.sku", "missing": "NO_SKU"}}
				}
			},
			"mt_date": {
				"multi_terms": {
					"terms": [
						{"field": "grp"},
						{"field": "ts", "format": "yyyy-MM-dd HH:mm:ss"}
					]
				}
			}
		}
	}`)
	if st != http.StatusOK || res["aggregations"] == nil {
		t.Fatalf("sub-composite + array/nested missing + multi_terms date search failed (%d): %v", st, res)
	}

	// 4. Ingest `json` processor on string array + `findMissingStaticSubPipelineForES7SimulateRound60`
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"json": {"field": "raw_arr", "target_field": "parsed_arr", "strict_json_parsing": true}}
			]
		},
		"docs": [{"_source": {"raw_arr": ["{\"a\":1}", "{\"b\":2}"]}}]
	}`)
	if st != http.StatusOK {
		t.Fatalf("ingest json array simulate failed (%d): %v", st, res)
	}
	missingPipe := findMissingStaticSubPipelineForES7SimulateRound60(srv, map[string]any{
		"processors": []any{
			map[string]any{
				"foreach": map[string]any{
					"field": "items",
					"processor": map[string]any{
						"set": map[string]any{
							"field": "x",
							"value": 1,
							"on_failure": []any{
								map[string]any{"pipeline": map[string]any{"name": "missing_sub_pipe"}},
							},
						},
					},
				},
			},
		},
	}, nil)
	if missingPipe != "missing_sub_pipe" {
		t.Fatalf("expected missing_sub_pipe, got %q", missingPipe)
	}
}

func TestRound62_Coverage_Batch4_SigScore_Temporal_Rollup_HistSubAgg_And_TSDBBulk(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Direct `computeSignificantScoreR62Search` across all heuristic formulas
	heurCases := []sigHeuristicSpecR62Search{
		{kind: "percentage"},
		{kind: "gnd", params: map[string]any{"background_is_superset": true}},
		{kind: "gnd", params: map[string]any{"background_is_superset": false}},
		{kind: "mutual_information", params: map[string]any{"include_negatives": true, "background_is_superset": true}},
		{kind: "mutual_information", params: map[string]any{"include_negatives": true, "background_is_superset": false}},
		{kind: "chi_square", params: map[string]any{"include_negatives": true}},
		{kind: "chi_square", params: map[string]any{"include_negatives": false}},
		{kind: "jlh"},
	}
	for _, hc := range heurCases {
		if sc := computeSignificantScoreR62Search(hc, 5, 10, 8, 100); sc <= 0 {
			t.Fatalf("expected positive significance score for %+v, got %v", hc, sc)
		}
	}

	// 2. Painless Java Time factories (`ZonedDateTime.of`, `ofInstant`, `LocalDate.of`, `ofEpochDay`, `LocalTime.of*`, `LocalDateTime.of`),
	//    `Comparator.comparing*`, 2-arg `Map.remove(k, v)`, and `Year` arithmetic
	timeAndCmpScript := strings.Join([]string{
		"def z1 = ZonedDateTime.of(2026, 11, 17, 10, 20, 30, 0, 'UTC');",
		"def z2 = ZonedDateTime.ofInstant(Instant.parse('2026-11-17T00:00:00Z'), 'UTC');",
		"def ld1 = LocalDate.of(2026, 11, 17);",
		"def ld2 = LocalDate.ofEpochDay(20000);",
		"def lt1 = LocalTime.of(12, 30, 45, 100);",
		"def lt2 = LocalTime.ofSecondOfDay(3661);",
		"def lt3 = LocalTime.ofNanoOfDay(5000000000L);",
		"def ldt1 = LocalDateTime.of(2026, 11, 17, 8, 9, 10, 500);",
		"def ldt2 = LocalDateTime.of(ld1, lt1);",
		"def z3 = ZonedDateTime.of(ldt1, 'UTC');",
		"List words = ['ccc', 'a', 'bb'];",
		"words.sort(Comparator.comparingInt(x -> x.length()));",
		"words.sort(Comparator.comparing(x -> x).reversed());",
		"Map mp = ['k1': 'v1', 'k2': 'v2'];",
		"def r1 = mp.remove('k1', 'wrong');",
		"def r2 = mp.remove('k1', 'v1');",
		"def yr = Year.of(2026).plusYears(2).minusYears(1).withYear(2030).plus(1, 'YEARS').plus(1, 'DECADES').plus(1, 'CENTURIES').plus(1, 'MILLENNIA');",
		"return z1 + '|' + z2 + '|' + z3 + '|' + ld2 + '|' + lt2 + '|' + lt3 + '|' + ldt2 + '|' + words[0] + '|' + r1 + '|' + r2 + '|' + yr;",
	}, " ")
	if res, err := painless.Eval(map[string]any{}, timeAndCmpScript, nil); err != nil || res == nil {
		t.Fatalf("Painless temporal/comparator/map/year script failed: res=%v err=%v", res, err)
	}

	// 3. `evalRollupAggMap` with `histogram` + sub-agg
	var rollupSearch esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"aggs":{"h":{"histogram":{"field":"lat","interval":10},"aggs":{"c":{"value_count":{"field":"lat"}}}}}}`), &rollupSearch)
	rollupDocs := []map[string]any{
		{"lat.histogram._count": int64(3), "lat.histogram.value": float64(15)},
		{"lat.histogram._count": int64(2), "lat.histogram.value": float64(25)},
	}
	rollupOut := evalRollupAggMap(rollupDocs, rollupSearch.Aggs)
	if rollupOut["h"] == nil {
		t.Fatalf("expected rollup histogram output, got %v", rollupOut)
	}

	// 4. `histogram` field (`terms -> percentiles` & `percentile_ranks`), `composite` on multi-valued `tags`, & `diversified_sampler` (`max_docs_per_value`)
	doJSON(t, srv, http.MethodPut, "/r62_histf", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"tags": {"type": "keyword", "multi_valued": true},
				"price": {"type": "double"},
				"h": {"type": "histogram"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_histf/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"grp":"a","tags":["t1","t2"],"price":10,"h":{"values":[10,20],"counts":[3,7]}}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"grp":"a","tags":["t2","t3"],"price":20,"h":{"values":[30],"counts":[5]}}`+"\n")
	st, res := doStatusR62Cov(t, srv, http.MethodPost, "/r62_histf/_search", `{
		"size": 0,
		"aggs": {
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"hp": {"percentiles": {"field": "h", "percents": [50, 90]}},
					"hpr": {"percentile_ranks": {"field": "h", "values": [15, 25]}}
				}
			},
			"mv_comp": {
				"composite": {
					"sources": [{"tg": {"terms": {"field": "tags"}}}]
				}
			},
			"div": {
				"diversified_sampler": {"field": "grp", "shard_size": 10, "max_docs_per_value": 1},
				"aggs": {"avg_p": {"avg": {"field": "price"}}}
			}
		}
	}`)
	if st != http.StatusOK || res["aggregations"] == nil {
		t.Fatalf("histogram/composite/diversified_sampler search failed (%d): %v", st, res)
	}

	// 5. Auto-created TSDB data stream via `_bulk` (`server.go:9190-9229`) including duplicate TSID 409 conflict
	doJSON(t, srv, http.MethodPut, "/_index_template/r62_tsdb_ds_tpl", `{
		"index_patterns": ["metrics-r62-*"],
		"data_stream": {},
		"template": {
			"settings": {"index.mode": "time_series", "index.routing_path": ["host"]},
			"mappings": {
				"properties": {
					"@timestamp": {"type": "date"},
					"host": {"type": "keyword", "time_series_dimension": true},
					"val": {"type": "double", "time_series_metric": "gauge"}
				}
			}
		}
	}`)
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/metrics-r62-cpu/_bulk?refresh=true",
		`{"create":{}}`+"\n"+`{"@timestamp":"2026-11-17T05:00:00Z","host":"n1","val":1.0}`+"\n")
	if st != http.StatusOK {
		t.Fatalf("TSDB data stream first bulk create failed: %d", st)
	}
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/metrics-r62-cpu/_bulk?refresh=true",
		`{"create":{}}`+"\n"+`{"@timestamp":"2026-11-17T05:00:00Z","host":"n1","val":2.0}`+"\n")
	if st != http.StatusOK || res["errors"] != true {
		t.Fatalf("expected duplicate TSDB create conflict in bulk, got (%d): %v", st, res)
	}

	// 6. Painless ISO-8601 `.plus(String)` Period/Duration parsing + `extractBucketMetricBySegs` + sub-pipeline `on_failure` + `copy_to` multi-fields
	isoScript := `LocalDate.parse('2026-11-17').plus('+P1Y2M3W4D').toString() + '|' + LocalDate.parse('2026-11-17').plus('-P1Y2M').toString() + '|' + Instant.parse('2026-11-17T00:00:00Z').plus('-P2DT3H4M5,5S').toString()`
	if resISO, err := painless.Eval(map[string]any{}, isoScript, nil); err != nil || resISO == nil {
		t.Fatalf("Painless ISO-8601 plus(String) failed: res=%v err=%v", resISO, err)
	}

	bucketCases := []struct {
		b    map[string]any
		segs []string
		want float64
	}{
		{map[string]any{"doc_count": int64(7), "p": map[string]any{"values": []map[string]any{{"key": 50.0, "value": 12.5}}}}, []string{"p"}, 12.5},
		{map[string]any{"doc_count": int64(7), "p": map[string]any{"values": []any{map[string]any{"key": 50.0, "value": 15.0}}}}, []string{"p"}, 15.0},
		{map[string]any{"doc_count": int64(7), "p": map[string]any{"values": map[string]any{"50.0": 18.0, "50.0_as_string": "18"}}}, []string{"p"}, 18.0},
		{map[string]any{"buckets": map[string]any{"a.b": map[string]any{"doc_count": int64(4), "m": map[string]any{"value": 9.0}}}}, []string{"a", "b", "m"}, 9.0},
		{map[string]any{"buckets": []map[string]any{{"key": "x.y", "doc_count": int64(3), "m": map[string]any{"value": 6.0}}}}, []string{"x", "y", "m"}, 6.0},
		{map[string]any{"f": map[string]any{"buckets": map[string]any{"k.1": map[string]any{"doc_count": int64(5)}}}}, []string{"f", "k", "1"}, 5.0},
		{map[string]any{"f": map[string]any{"buckets": []map[string]any{{"key": "k.2", "doc_count": int64(8)}}}}, []string{"f", "k", "2"}, 8.0},
	}
	for _, bc := range bucketCases {
		if v, ok := extractBucketMetricBySegs(bc.b, bc.segs); !ok || v != bc.want {
			t.Fatalf("extractBucketMetricBySegs(%v) = (%v, %v), want %v", bc.segs, v, ok, bc.want)
		}
	}

	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r62_sub_fail", `{
		"processors": [{"fail": {"message": "sub_boom"}}],
		"on_failure": [{"set": {"field": "sub_recovered", "value": "{{_ingest.on_failure_pipeline}}"}}]
	}`)
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r62_outer_pipe", `{
		"processors": [{"pipeline": {"name": "r62_sub_fail"}}]
	}`)
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/_ingest/pipeline/r62_outer_pipe/_simulate", `{"docs":[{"_source":{"x":1}}]}`)
	if st != http.StatusOK {
		t.Fatalf("sub-pipeline on_failure simulate failed (%d): %v", st, res)
	}

	doJSON(t, srv, http.MethodPut, "/r62_copy_mf", `{
		"mappings": {
			"properties": {
				"src": {"type": "keyword", "copy_to": "dst"},
				"dst": {
					"type": "text",
					"fields": {
						"num": {"type": "long", "ignore_malformed": true},
						"sub_txt": {"type": "text"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r62_copy_mf/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"src":["42","not_a_num"]}`+"\n")
}

func stringifyAnyR62Cov(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
