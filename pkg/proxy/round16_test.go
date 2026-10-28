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
	"math"
	"net/http"
	"testing"
)

func TestRound16_RuntimeScriptQueryWrapperAndMutationPaths(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_scripts", `{
		"mappings": {
			"properties": {
				"status": {"type": "keyword"},
				"category": {"type": "keyword"},
				"price": {"type": "double"},
				"qty": {"type": "long"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"cost": {"type": "double"}
					}
				}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_scripts/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"status":"active","category":"books","price":10,"qty":5,"items":[{"sku":"A","cost":15}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"status":"active","category":"games","price":30,"qty":1,"items":[{"sku":"B","cost":5}]}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"status":"archived","category":"books","price":50,"qty":2,"items":[{"sku":"C","cost":25}]}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"status":"active","category":"movies","price":5,"qty":2,"items":[{"sku":"D","cost":3}]}`+"\n")

	// 1. Top-level script_score with boost & min_score + aggregations restricted to script-matched docs
	res := doJSON(t, srv, http.MethodPost, "/r16_scripts/_search", `{
		"query": {
			"script_score": {
				"query": {
					"bool": {
						"must": [{"term": {"status": "active"}}],
						"must_not": [
							{
								"bool": {
									"must": [
										{"term": {"category": "movies"}},
										{"script": {"script": "doc['price'].value < 10"}}
									]
								}
							}
						],
						"should": [
							{"term": {"category": "books"}},
							{"script": {"script": "doc['price'].value >= 30"}}
						],
						"minimum_should_match": 1
					}
				},
				"script": {
					"source": "doc['price'].value * doc['qty'].value"
				},
				"min_score": 40,
				"boost": 2.0
			}
		},
		"aggs": {
			"by_cat": {"terms": {"field": "category"}},
			"sum_price": {"sum": {"field": "price"}}
		}
	}`)

	hitsObj := res["hits"].(map[string]any)
	if total := hitsObj["total"].(map[string]any)["value"].(float64); total != 2 {
		t.Fatalf("expected 2 hits after script_score min_score=40 and boost=2, got %v", total)
	}
	hitsList := hitsObj["hits"].([]any)
	// doc 1: (10*5)*2 = 100, doc 2: (30*1)*2 = 60, doc 4 excluded by must_not
	if hitsList[0].(map[string]any)["_id"] != "1" || hitsList[0].(map[string]any)["_score"].(float64) != 100 {
		t.Fatalf("unexpected top hit: %+v", hitsList[0])
	}
	aggs := res["aggregations"].(map[string]any)
	if sumPrice := aggs["sum_price"].(map[string]any)["value"].(float64); sumPrice != 40 {
		t.Fatalf("expected sum_price=40 over script-matched docs (10+30), got %v", sumPrice)
	}

	// 2. function_score with per-function filter + weight + script_score + score_mode + max_boost + min_score
	fsRes := doJSON(t, srv, http.MethodPost, "/r16_scripts/_search", `{
		"query": {
			"function_score": {
				"query": {"term": {"status": "active"}},
				"score_mode": "sum",
				"boost_mode": "replace",
				"max_boost": 80,
				"min_score": 25,
				"functions": [
					{
						"filter": {"term": {"category": "books"}},
						"weight": 50
					},
					{
						"filter": {"script": {"script": "doc['price'].value >= 10"}},
						"script_score": {"script": "doc['price'].value"}
					}
				]
			}
		}
	}`)
	fsHits := fsRes["hits"].(map[string]any)["hits"].([]any)
	if len(fsHits) != 2 {
		t.Fatalf("expected 2 hits from function_score, got %d", len(fsHits))
	}
	if fsHits[0].(map[string]any)["_score"].(float64) != 60 {
		t.Fatalf("expected doc 1 function_score=60 (50+10), got %v", fsHits[0].(map[string]any)["_score"])
	}

	// 3. Nested query containing runtime script
	nestedRes := doJSON(t, srv, http.MethodPost, "/r16_scripts/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"script": {"script": "doc['cost'].value >= 15"}
				}
			}
		}
	}`)
	if nTotal := nestedRes["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64); nTotal != 2 {
		t.Fatalf("expected 2 nested script matches (docs 1 and 3), got %v", nTotal)
	}

	// 4. _explain with script_score
	expRes := doJSON(t, srv, http.MethodPost, "/r16_scripts/_explain/1", `{
		"query": {
			"script_score": {
				"query": {"term": {"status": "active"}},
				"script": {"source": "doc['price'].value * 3"}
			}
		}
	}`)
	if expRes["matched"] != true || expRes["explanation"].(map[string]any)["value"].(float64) != 30 {
		t.Fatalf("unexpected _explain result: %+v", expRes)
	}

	// 5. _update_by_query and _delete_by_query with runtime script query and size cap
	ubqRes := doJSON(t, srv, http.MethodPost, "/r16_scripts/_update_by_query?refresh=true", `{
		"size": 1,
		"query": {
			"script": {"script": "doc['price'].value >= 30"}
		},
		"script": {
			"source": "ctx._source.qty = ctx._source.qty + 10"
		}
	}`)
	if ubqRes["updated"].(float64) != 1 {
		t.Fatalf("expected 1 updated doc with size=1 and script query, got %+v", ubqRes)
	}

	dbqRes := doJSON(t, srv, http.MethodPost, "/r16_scripts/_delete_by_query?refresh=true", `{
		"size": 1,
		"query": {
			"script": {"script": "doc['price'].value == 5"}
		}
	}`)
	if dbqRes["deleted"].(float64) != 1 {
		t.Fatalf("expected 1 deleted doc (id=4) with script query, got %+v", dbqRes)
	}
}

func TestRound16_UpgradedArrayColumnAndDateNanosFidelity(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_upgraded", `{
		"mappings": {
			"properties": {
				"group": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"val": {"type": "double"},
				"tag": {"type": "keyword"},
				"ts_ns": {"type": "date_nanos"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPut, "/r16_upgraded/_doc/1?refresh=true", `{
		"group": "alpha",
		"val": 10.0,
		"tag": "one",
		"ts_ns": 1700000000000000000
	}`)

	// Second document triggers UpgradedArray on `val` and `tag`
	doJSON(t, srv, http.MethodPut, "/r16_upgraded/_doc/2?refresh=true", `{
		"group": "beta",
		"val": [20.0, 30.0],
		"tag": ["two", "three"],
		"ts_ns": 1700000005000000000
	}`)

	// Verify range, term, exists, stats, percentiles, histogram, and sub-aggs on UpgradedArray + group.keyword
	res := doJSON(t, srv, http.MethodPost, "/r16_upgraded/_search", `{
		"query": {
			"bool": {
				"must": [
					{"exists": {"field": "tag"}},
					{"range": {"ts_ns": {"gte": 1700000000000000000, "lte": 1700000006000000000}}}
				]
			}
		},
		"sort": [{"ts_ns": "asc"}],
		"aggs": {
			"val_stats": {"stats": {"field": "val"}},
			"val_pct": {"percentiles": {"field": "val", "percents": [50]}},
			"val_hist": {"histogram": {"field": "val", "interval": 10}},
			"tag_sstats": {"string_stats": {"field": "tag"}},
			"by_group": {
				"terms": {"field": "group.keyword"},
				"aggs": {
					"sub_stats": {"stats": {"field": "val"}},
					"sub_box": {"boxplot": {"field": "val"}}
				}
			}
		}
	}`)

	aggs := res["aggregations"].(map[string]any)
	valStats := aggs["val_stats"].(map[string]any)
	if valStats["count"].(float64) != 3 || valStats["sum"].(float64) != 60 {
		t.Fatalf("expected val_stats count=3 sum=60 on UpgradedArray, got %+v", valStats)
	}
	tagSStats := aggs["tag_sstats"].(map[string]any)
	if tagSStats["count"].(float64) != 3 {
		t.Fatalf("expected tag_sstats count=3 on UpgradedArray, got %+v", tagSStats)
	}
	byGroup := aggs["by_group"].(map[string]any)["buckets"].([]any)
	if len(byGroup) != 2 {
		t.Fatalf("expected 2 group.keyword buckets, got %d", len(byGroup))
	}

	// Verify search_after with nanosecond epoch on date_nanos
	saRes := doJSON(t, srv, http.MethodPost, "/r16_upgraded/_search", `{
		"sort": [{"ts_ns": "asc"}],
		"search_after": [1700000000000000000]
	}`)
	saHits := saRes["hits"].(map[string]any)["hits"].([]any)
	if len(saHits) != 1 || saHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 after date_nanos search_after, got %+v", saHits)
	}
}

func TestRound16_SortAscNullsLastAndSearchAfterTerminalNull(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_sort_nulls", `{
		"mappings": {
			"properties": {
				"rank": {"type": "integer"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_sort_nulls/_bulk?refresh=true",
		`{"index":{"_id":"a"}}`+"\n"+`{"rank":20}`+"\n"+
			`{"index":{"_id":"b"}}`+"\n"+`{"rank":10}`+"\n"+
			`{"index":{"_id":"c"}}`+"\n"+`{}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r16_sort_nulls/_search", `{
		"sort": [
			{"rank": {"order": "asc"}},
			{"_id": "asc"}
		]
	}`)

	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}
	// Default missing="_last" for ASC: b (10), a (20), c (null)
	if hits[0].(map[string]any)["_id"] != "b" || hits[1].(map[string]any)["_id"] != "a" || hits[2].(map[string]any)["_id"] != "c" {
		t.Fatalf("expected order [b, a, c] with NULLS LAST, got [%v, %v, %v]",
			hits[0].(map[string]any)["_id"], hits[1].(map[string]any)["_id"], hits[2].(map[string]any)["_id"])
	}

	// search_after past the null doc (c) should return 0 hits, NOT resurface non-null docs
	afterNull := doJSON(t, srv, http.MethodPost, "/r16_sort_nulls/_search", `{
		"sort": [
			{"rank": {"order": "asc"}},
			{"_id": "asc"}
		],
		"search_after": [null, "c"]
	}`)
	afterHits := afterNull["hits"].(map[string]any)["hits"].([]any)
	if len(afterHits) != 0 {
		t.Fatalf("expected 0 hits after terminal null sort value, got %+v", afterHits)
	}
}

func TestRound16_CollapseSearchAfterRuntimeScriptAndGeoDistanceSort(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_collapse", `{
		"mappings": {
			"properties": {
				"brand": {"type": "keyword"},
				"price": {"type": "double"},
				"loc": {"type": "geo_point"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_collapse/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"brand":"acme","price":10,"loc":{"lat":40.7128,"lon":-74.0060}}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"brand":"acme","price":50,"loc":{"lat":34.0522,"lon":-118.2437}}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"brand":"globex","price":30,"loc":{"lat":41.8781,"lon":-87.6298}}`+"\n")

	// 1. Collapse + script query (filters out id=1 where price=10, so acme collapses to id=2!) + inner_hits
	cRes := doJSON(t, srv, http.MethodPost, "/r16_collapse/_search", `{
		"query": {
			"script": {"script": "doc['price'].value >= 20"}
		},
		"collapse": {
			"field": "brand",
			"inner_hits": {
				"name": "brand_docs",
				"size": 5
			}
		},
		"sort": [{"price": "desc"}]
	}`)
	cHits := cRes["hits"].(map[string]any)["hits"].([]any)
	if len(cHits) != 2 || cHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected 2 collapsed hits with id=2 first, got %+v", cHits)
	}
	ihHits := cHits[0].(map[string]any)["inner_hits"].(map[string]any)["brand_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(ihHits) != 1 || ihHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected collapse inner_hits to exclude script-filtered doc 1, got %+v", ihHits)
	}

	// 2. _geo_distance sort (from NYC: 40.7128, -74.0060) + search_after
	geoRes := doJSON(t, srv, http.MethodPost, "/r16_collapse/_search", `{
		"sort": [
			{
				"_geo_distance": {
					"loc": {"lat": 40.7128, "lon": -74.0060},
					"order": "asc",
					"unit": "km"
				}
			}
		]
	}`)
	gHits := geoRes["hits"].(map[string]any)["hits"].([]any)
	if len(gHits) != 3 || gHits[0].(map[string]any)["_id"] != "1" || gHits[1].(map[string]any)["_id"] != "3" || gHits[2].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected geo_distance order [1 (NYC), 3 (Chicago), 2 (LA)], got %+v", gHits)
	}
	sortVals0 := gHits[0].(map[string]any)["sort"].([]any)
	if sortVals0[0].(float64) != 0 {
		t.Fatalf("expected 0km distance for NYC origin, got %v", sortVals0[0])
	}
}

func TestRound16_PainlessAssignmentRegexAndReturnExpression(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_painless_eq/_doc/1?refresh=true", `{
		"status": "ok",
		"code": "ERR-404",
		"a": 10,
		"b": 10
	}`)

	res := doJSON(t, srv, http.MethodPost, "/r16_painless_eq/_search", `{
		"script_fields": {
			"eq_ternary": {
				"script": "def x = doc['a'].value; def y = doc['b'].value; x == y ? 'same' : 'diff'"
			},
			"regex_find": {
				"script": "def c = doc['code'].value; c =~ /^ERR-[0-9]+$/"
			},
			"regex_match": {
				"script": "def s = doc['status'].value; s ==~ /ok|ready/"
			}
		}
	}`)

	fields := res["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	if fields["eq_ternary"].([]any)[0] != "same" {
		t.Fatalf("expected eq_ternary='same', got %v", fields["eq_ternary"])
	}
	if fields["regex_find"].([]any)[0] != true {
		t.Fatalf("expected regex_find=true, got %v", fields["regex_find"])
	}
	if fields["regex_match"].([]any)[0] != true {
		t.Fatalf("expected regex_match=true, got %v", fields["regex_match"])
	}
}

func TestRound16_PainlessDocValuesAndNestedArrayProjection(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_painless_dv/_doc/1?refresh=true", `{
		"title": "hello",
		"tags": ["go", "doris", "es"],
		"items": [
			{"name": "p1", "price": 12.5},
			{"name": "p2", "price": 7.5}
		]
	}`)

	res := doJSON(t, srv, http.MethodPost, "/r16_painless_dv/_search", `{
		"script_fields": {
			"str_len": {"script": "doc['title'].value.length()"},
			"tags_count": {"script": "doc['tags'].size()"},
			"missing_empty": {"script": "doc['nonexistent'].empty"},
			"has_title": {"script": "doc.containsKey('title')"},
			"has_doris": {"script": "doc['tags'].contains('doris')"},
			"doris_idx": {"script": "doc['tags'].indexOf('doris')"},
			"second_tag": {"script": "doc['tags'][1]"},
			"loop_tags": {"script": "def out = ''; for (t in doc['tags']) { out = out + t + ','; } return out;"},
			"items_sum": {"script": "def s = 0; for (p in doc['items.price'].values) { s += p; } return s;"}
		}
	}`)

	fields := res["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	if fields["str_len"].([]any)[0].(float64) != 5 {
		t.Fatalf("expected str_len=5, got %v", fields["str_len"])
	}
	if fields["tags_count"].([]any)[0].(float64) != 3 {
		t.Fatalf("expected tags_count=3, got %v", fields["tags_count"])
	}
	if fields["missing_empty"].([]any)[0] != true {
		t.Fatalf("expected missing_empty=true, got %v", fields["missing_empty"])
	}
	if fields["has_title"].([]any)[0] != true || fields["has_doris"].([]any)[0] != true {
		t.Fatalf("expected has_title=true and has_doris=true, got %+v", fields)
	}
	if fields["doris_idx"].([]any)[0].(float64) != 1 || fields["second_tag"].([]any)[0] != "doris" {
		t.Fatalf("expected doris_idx=1 and second_tag='doris', got %+v", fields)
	}
	if fields["loop_tags"].([]any)[0] != "go,doris,es," {
		t.Fatalf("expected loop_tags='go,doris,es,', got %v", fields["loop_tags"])
	}
	if fields["items_sum"].([]any)[0].(float64) != 20.0 {
		t.Fatalf("expected items_sum=20.0, got %v", fields["items_sum"])
	}
}

func TestRound16_PainlessWhileLoopMathStaticAndBuiltins(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_painless_math/_doc/1?refresh=true", `{
		"price": 19.75,
		"raw_num": "42",
		"text": "foo-123-bar-456"
	}`)

	res := doJSON(t, srv, http.MethodPost, "/r16_painless_math/_search", `{
		"script_fields": {
			"while_sum": {
				"script": "def i = 1; def s = 0; while (i <= 4) { s += i; i++; } return s;"
			},
			"math_ops": {
				"script": "Math.round(doc['price'].value) + Math.abs(-5) + Integer.parseInt(doc['raw_num'].value)"
			},
			"str_ops": {
				"script": "doc['text'].value.replaceAll('[0-9]+', '#') + ':' + doc['text'].value.charAt(0)"
			}
		},
		"aggs": {
			"floor_sum": {
				"sum": {
					"script": {"source": "Math.floor(doc['price'].value)"}
				}
			}
		}
	}`)

	fields := res["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	if fields["while_sum"].([]any)[0].(float64) != 10 {
		t.Fatalf("expected while_sum=10, got %v", fields["while_sum"])
	}
	if fields["math_ops"].([]any)[0].(float64) != 67 {
		t.Fatalf("expected math_ops=67 (20+5+42), got %v", fields["math_ops"])
	}
	if fields["str_ops"].([]any)[0] != "foo-#-bar-#:f" {
		t.Fatalf("expected str_ops='foo-#-bar-#:f', got %v", fields["str_ops"])
	}
	if floorSum := res["aggregations"].(map[string]any)["floor_sum"].(map[string]any)["value"].(float64); floorSum != 19 {
		t.Fatalf("expected floor_sum=19, got %v", floorSum)
	}
}

func TestRound16_IngestMetadataIndexAndIDRouting(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/route_pipe", `{
		"processors": [
			{
				"set": {
					"field": "_index",
					"value": "r16_routed_{{env}}"
				}
			},
			{
				"script": {
					"source": "ctx._id = 'custom-' + ctx.code"
				}
			}
		]
	}`)

	// 1. Simulate
	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/route_pipe/_simulate", `{
		"docs": [
			{"_index": "orig_idx", "_id": "1", "_source": {"env": "prod", "code": "abc"}}
		]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if simDoc["_index"] != "r16_routed_prod" || simDoc["_id"] != "custom-abc" {
		t.Fatalf("expected simulated _index='r16_routed_prod' and _id='custom-abc', got %+v", simDoc)
	}
	simSrc := simDoc["_source"].(map[string]any)
	if _, leakedIdx := simSrc["_index"]; leakedIdx {
		t.Fatalf("_index leaked into _source: %+v", simSrc)
	}
	if _, leakedID := simSrc["_id"]; leakedID {
		t.Fatalf("_id leaked into _source: %+v", simSrc)
	}

	// 2. Single doc PUT with pipeline
	putRes := doJSON(t, srv, http.MethodPut, "/r16_orig/_doc/temp?pipeline=route_pipe&refresh=true", `{
		"env": "prod",
		"code": "xyz"
	}`)
	if putRes["_index"] != "r16_routed_prod" || putRes["_id"] != "custom-xyz" {
		t.Fatalf("expected PUT routed to r16_routed_prod/custom-xyz, got %+v", putRes)
	}

	getRes := doJSON(t, srv, http.MethodGet, "/r16_routed_prod/_doc/custom-xyz", "")
	getSrc := getRes["_source"].(map[string]any)
	if getSrc["code"] != "xyz" || getSrc["_index"] != nil || getSrc["_id"] != nil {
		t.Fatalf("unexpected routed document _source: %+v", getSrc)
	}
}

func TestRound16_IngestGrokApacheLogsAndMultiGroupRedact(t *testing.T) {
	srv, _ := newTestServer()

	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"grok": {
						"field": "log",
						"patterns": ["%{COMBINEDAPACHELOG}"]
					}
				},
				{
					"redact": {
						"field": "msg",
						"patterns": ["%{EMAILADDRESS:EMAIL}", "%{IPV4:IP}"]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"log": "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326 \"http://www.example.com/start.html\" \"Mozilla/4.08\"",
					"msg": "Contact alice@example.com from 10.20.30.40 immediately"
				}
			}
		]
	}`)

	doc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if doc["clientip"] != "127.0.0.1" || doc["verb"] != "GET" || doc["response"] != "200" {
		t.Fatalf("expected COMBINEDAPACHELOG grok extraction, got %+v", doc)
	}
	if doc["msg"] != "Contact <EMAIL> from <IP> immediately" {
		t.Fatalf("expected distinct <EMAIL> and <IP> redaction tokens, got %q", doc["msg"])
	}
}

func TestRound16_TermsScriptSubAggsAndTopHitsEnrichment(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_terms_script", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"title": {"type": "text"},
				"salary": {"type": "double"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_terms_script/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"dept":"eng","title":"senior golang engineer","salary":200}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"dept":"eng","title":"staff golang architect","salary":300}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"dept":"sales","title":"account executive","salary":150}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r16_terms_script/_search", `{
		"query": {"match": {"title": "golang"}},
		"aggs": {
			"script_depts": {
				"terms": {
					"script": {"source": "doc['dept'].value.toUpperCase()"},
					"order": {"avg_sal": "desc"}
				},
				"aggs": {
					"avg_sal": {"avg": {"field": "salary"}},
					"top_emp": {
						"top_hits": {
							"size": 1,
							"sort": [{"_script": {"type": "number", "script": "doc['salary'].value", "order": "desc"}}],
							"fields": ["dept"],
							"script_fields": {
								"bonus": {"script": "doc['salary'].value * 0.1"}
							},
							"highlight": {
								"fields": {"title": {}}
							}
						}
					}
				}
			}
		}
	}`)

	buckets := res["aggregations"].(map[string]any)["script_depts"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 1 || buckets[0].(map[string]any)["key"] != "ENG" {
		t.Fatalf("expected 1 bucket 'ENG', got %+v", buckets)
	}
	b0 := buckets[0].(map[string]any)
	if b0["avg_sal"].(map[string]any)["value"].(float64) != 250 {
		t.Fatalf("expected avg_sal=250 under terms.script, got %v", b0["avg_sal"])
	}
	topHit := b0["top_emp"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if topHit["_id"] != "2" {
		t.Fatalf("expected top_hits sorted by _script to pick doc 2, got %+v", topHit)
	}
	thFields := topHit["fields"].(map[string]any)
	if thFields["dept"].([]any)[0] != "eng" || thFields["bonus"].([]any)[0].(float64) != 30 {
		t.Fatalf("expected top_hits fields & script_fields populated, got %+v", thFields)
	}
	if _, hasHL := topHit["highlight"].(map[string]any)["title"]; !hasHL {
		t.Fatalf("expected top_hits highlight populated, got %+v", topHit["highlight"])
	}
}

func TestRound16_PipelineAggsFractionalPercentileOrderAndBucketsPath(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPost, "/r16_pct_order/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"service":"api","latency":100}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"service":"web","latency":500}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r16_pct_order/_search", `{
		"size": 0,
		"aggs": {
			"by_svc": {
				"terms": {
					"field": "service",
					"order": {"lat_pct.99.9": "desc"}
				},
				"aggs": {
					"lat_pct": {
						"percentiles": {
							"field": "latency",
							"percents": [50, 99.9]
						}
					}
				}
			},
			"max_p99_9": {
				"max_bucket": {
					"buckets_path": "by_svc>lat_pct.99.9"
				}
			}
		}
	}`)

	aggs := res["aggregations"].(map[string]any)
	buckets := aggs["by_svc"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 || buckets[0].(map[string]any)["key"] != "web" {
		t.Fatalf("expected 'web' first when ordered by lat_pct.99.9 desc, got %+v", buckets)
	}
	if maxP99 := aggs["max_p99_9"].(map[string]any)["value"].(float64); math.Abs(maxP99-500) > 1e-6 {
		t.Fatalf("expected max_p99_9=500, got %v", maxP99)
	}
}

func TestRound16_IngestURIPartsCSVBytesAndDateUnixMs(t *testing.T) {
	srv, _ := newTestServer()

	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"uri_parts": {
						"field": "url",
						"target_field": "parsed_url",
						"keep_original": false,
						"remove_if_successful": true
					}
				},
				{
					"csv": {
						"field": "csv_line",
						"target_fields": ["a", "b", "c"],
						"trim": true
					}
				},
				{
					"bytes": {
						"field": "mem",
						"target_field": "mem_bytes"
					}
				},
				{
					"date": {
						"field": "epoch_ms",
						"target_field": "@timestamp",
						"formats": ["UNIX_MS"]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"url": "https://example.com:8443/api/v1/items?limit=10#top",
					"csv_line": "  foo , \"bar\" , baz ",
					"mem": "2mib",
					"epoch_ms": 1700000000123
				}
			}
		]
	}`)

	doc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if _, hasOrigURL := doc["url"]; hasOrigURL {
		t.Fatalf("expected remove_if_successful=true to remove original url field, got %+v", doc)
	}
	parsedURL := doc["parsed_url"].(map[string]any)
	if _, hasOrigInTarget := parsedURL["original"]; hasOrigInTarget {
		t.Fatalf("expected keep_original=false to omit parsed_url.original, got %+v", parsedURL)
	}
	if doc["a"] != "foo" || doc["b"] != "bar" || doc["c"] != "baz" {
		t.Fatalf("expected trimmed CSV fields [foo, bar, baz], got [%v, %v, %v]", doc["a"], doc["b"], doc["c"])
	}
	if doc["mem_bytes"].(float64) != 2*1024*1024 {
		t.Fatalf("expected 2mib = 2097152, got %v", doc["mem_bytes"])
	}
	if doc["@timestamp"] != "2023-11-14T22:13:20.123Z" {
		t.Fatalf("expected @timestamp='2023-11-14T22:13:20.123Z', got %v", doc["@timestamp"])
	}
}

func TestRound16_ExtendedRuntimeScriptsGeoFormatsAndPainlessBuiltins(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r16_ext", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"salary": {"type": "double"},
				"loc": {"type": "geo_point"},
				"items": {
					"type": "nested",
					"properties": {
						"val": {"type": "double"}
					}
				}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_ext/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"dept":"eng","salary":100,"loc":"40.7128, -74.0060","items":[{"val":10},{"val":20}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"dept":"eng","salary":200,"loc":[-118.2437, 34.0522],"items":[{"val":30}]}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"dept":"sales","salary":150,"loc":["POINT(-87.6298 41.8781)", {"lat":37.7749,"lon":-122.4194}],"items":[{"val":40}]}`+"\n")

	// 1. Geo distance sort with array/string/WKT points and mi/yd/ft units
	for _, unit := range []string{"mi", "yd", "ft", "nmi"} {
		gRes := doJSON(t, srv, http.MethodPost, "/r16_ext/_search", `{
			"sort": [
				{
					"_geo_distance": {
						"loc": "40.7128, -74.0060",
						"order": "asc",
						"unit": "`+unit+`",
						"mode": "min"
					}
				}
			]
		}`)
		if len(gRes["hits"].(map[string]any)["hits"].([]any)) != 3 {
			t.Fatalf("expected 3 geo sorted hits for unit=%s", unit)
		}
	}

	// 2. DisMax, Boosting, FunctionScore score_mode/boost_mode variants, Nested score_mode variants, and minimum_should_match percentage
	for _, sm := range []string{"avg", "first", "max", "min", "multiply"} {
		for _, bm := range []string{"sum", "avg", "max", "min", "multiply"} {
			_ = doJSON(t, srv, http.MethodPost, "/r16_ext/_search", `{
				"query": {
					"function_score": {
						"query": {
							"dis_max": {
								"tie_breaker": 0.3,
								"boost": 1.2,
								"queries": [
									{"script": {"script": "doc['salary'].value >= 100"}},
									{
										"boosting": {
											"positive": {"script": {"script": "doc['salary'].value >= 100"}},
											"negative": {"script": {"script": "doc['salary'].value >= 180"}},
											"negative_boost": 0.5
										}
									}
								]
							}
						},
						"score_mode": "`+sm+`",
						"boost_mode": "`+bm+`",
						"functions": [
							{"script_score": {"script": "doc['salary'].value / 100.0"}, "weight": 2.0}
						]
					}
				}
			}`)
		}
	}

	for _, nsm := range []string{"sum", "max", "min", "none", "avg"} {
		_ = doJSON(t, srv, http.MethodPost, "/r16_ext/_search", `{
			"query": {
				"bool": {
					"should": [
						{
							"nested": {
								"path": "items",
								"score_mode": "`+nsm+`",
								"query": {"script": {"script": "doc['val'].value >= 10"}}
							}
						},
						{"script": {"script": "doc['salary'].value > 50"}}
					],
					"minimum_should_match": "50%"
				}
			}
		}`)
	}

	// 3. Runtime terms.script with sum, min, max, value_count, cardinality, stats, extended_stats, and nested terms sub-agg + filter parent agg
	aggRes := doJSON(t, srv, http.MethodPost, "/r16_ext/_search", `{
		"query": {"script": {"script": "doc['salary'].value >= 100"}},
		"aggs": {
			"by_dept_script": {
				"terms": {"script": "doc['dept'].value.toUpperCase()"},
				"aggs": {
					"s_sum": {"sum": {"field": "salary"}},
					"s_min": {"min": {"field": "salary"}},
					"s_max": {"max": {"field": "salary"}},
					"s_vc": {"value_count": {"field": "salary"}},
					"s_card": {"cardinality": {"field": "dept"}},
					"s_stats": {"stats": {"field": "salary"}},
					"s_estats": {"extended_stats": {"field": "salary"}},
					"sub_script": {"terms": {"script": "doc['dept'].value"}}
				}
			},
			"filtered_parent": {
				"filter": {"term": {"dept": "eng"}},
				"aggs": {
					"inner_script": {"terms": {"script": "doc['dept'].value"}}
				}
			}
		}
	}`)
	if len(aggRes["aggregations"].(map[string]any)["by_dept_script"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 buckets in by_dept_script")
	}

	// 4. Painless static Math.*, parseLong/Double/Float, String.valueOf/join, clear, replaceFirst, matches, getOrDefault, keySet, values, lastIndexOf
	pRes := doJSON(t, srv, http.MethodPost, "/r16_ext/_search", `{
		"size": 1,
		"script_fields": {
			"all_builtins": {
				"script": "def m = ['a': 1, 'b': 2]; def l = [1, 2, 3]; l.clear(); def v1 = Math.min(2, 5) + Math.max(2, 5) + Math.ceil(1.2) + Math.pow(2, 3) + Math.sqrt(9) + Math.log(1) + Math.log10(10) + Math.clamp(15, 0, 10); def v2 = Long.parseLong('10') + Double.parseDouble('2.5') + Float.parseFloat('1.5'); def s = String.valueOf(v1) + ':' + String.join('-', ['x', 'y']); def r = 'abc-123-456'.replaceFirst('[0-9]+', '#'); def ok = r.matches('abc-#-456') && m.getOrDefault('c', 9) == 9 && m.keySet().size() == 2 && m.values().size() == 2 && r.lastIndexOf('456') > 0 && l.size() == 0; return ok ? v2 : 0;"
			}
		}
	}`)
	pHit := pRes["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if pHit["fields"].(map[string]any)["all_builtins"].([]any)[0].(float64) != 14 {
		t.Fatalf("expected all_builtins=14, got %+v", pHit["fields"])
	}
}

func TestRound16_ReindexWithRuntimeScriptAndIngestMetaRouting(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r16_reindex_pipe", `{
		"processors": [
			{
				"set": {
					"field": "_index",
					"value": "r16_reindex_dest_{{tier}}"
				}
			}
		]
	}`)

	doJSON(t, srv, http.MethodPost, "/r16_reindex_src/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"tier":"gold","amount":100}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"tier":"silver","amount":20}`+"\n")

	reRes := doJSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {
			"index": "r16_reindex_src",
			"query": {
				"script": {"script": "doc['amount'].value >= 50"}
			}
		},
		"dest": {
			"index": "r16_reindex_dest_default",
			"pipeline": "r16_reindex_pipe"
		}
	}`)
	if reRes["created"].(float64) != 1 {
		t.Fatalf("expected 1 document reindexed by script query, got %+v", reRes)
	}

	goldGet := doJSON(t, srv, http.MethodGet, "/r16_reindex_dest_gold/_doc/1", "")
	if goldGet["found"] != true {
		t.Fatalf("expected doc 1 routed to r16_reindex_dest_gold via pipeline _index override, got %+v", goldGet)
	}
}

func TestRound16_MultiIndexPostFilterScriptSearchAfter(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPost, "/r16_mi_1/_bulk?refresh=true",
		`{"index":{"_id":"a"}}`+"\n"+`{"score_val":10,"keep":true}`+"\n"+
			`{"index":{"_id":"b"}}`+"\n"+`{"score_val":20,"keep":false}`+"\n")
	doJSON(t, srv, http.MethodPost, "/r16_mi_2/_bulk?refresh=true",
		`{"index":{"_id":"c"}}`+"\n"+`{"score_val":30,"keep":true}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r16_mi_1,r16_mi_2/_search", `{
		"post_filter": {
			"script": {"script": "doc['keep'].value == true"}
		},
		"sort": [{"score_val": "asc"}],
		"search_after": [10]
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "c" {
		t.Fatalf("expected only doc 'c' after multi-index post_filter script + search_after, got %+v", hits)
	}
}
