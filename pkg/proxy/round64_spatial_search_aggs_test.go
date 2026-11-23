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
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
)

func doRawHTTPReqR64(t *testing.T, srv *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = strings.NewReader("")
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRound64_Spatial_GeoLine_Cartesian_GeoHexGrid_And_TimeSeries(t *testing.T) {
	srv, _ := newTestServer()
	defer func() { _ = srv.Close(context.Background()) }()

	st, res := doStatusR62Cov(t, srv, http.MethodPut, "/r64_spatial_idx", `{
		"mappings": {
			"properties": {
				"loc": {"type": "geo_point"},
				"shape": {"type": "geo_shape"},
				"pt": {"type": "point"},
				"cart_shape": {"type": "shape"},
				"no_dv_no_idx": {"type": "geo_shape", "doc_values": false, "index": false},
				"grp": {"type": "keyword"},
				"seq": {"type": "integer"},
				"ts": {"type": "date"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create spatial index failed (%d): %v", st, res)
	}

	bulk := strings.Join([]string{
		`{"index":{"_id":"1"}}`,
		`{"loc":{"lat":48.8566,"lon":2.3522},"shape":{"type":"polygon","coordinates":[[[2.0,48.0],[3.0,48.0],[3.0,49.0],[2.0,49.0],[2.0,48.0]]]},"pt":{"x":10.0,"y":20.0},"cart_shape":{"type":"polygon","coordinates":[[[0.0,0.0],[10.0,0.0],[10.0,10.0],[0.0,10.0],[0.0,0.0]]]},"grp":"eu","seq":2,"ts":"2026-01-02T00:00:00Z"}`,
		`{"index":{"_id":"2"}}`,
		`{"loc":{"lat":51.5074,"lon":-0.1278},"shape":{"type":"point","coordinates":[-0.1278,51.5074]},"pt":{"x":30.0,"y":40.0},"cart_shape":{"type":"point","coordinates":[25.0,35.0]},"grp":"eu","seq":1,"ts":"2026-01-01T00:00:00Z"}`,
		`{"index":{"_id":"3"}}`,
		`{"loc":{"lat":35.6762,"lon":139.6503},"shape":{"type":"linestring","coordinates":[[139.0,35.0],[140.0,36.0]]},"pt":{"x":100.0,"y":200.0},"grp":"asia","seq":3,"ts":"2026-01-03T00:00:00Z"}`,
		"",
	}, "\n")
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_spatial_idx/_bulk?refresh=true", bulk)
	if st != http.StatusOK {
		t.Fatalf("bulk index failed (%d): %v", st, res)
	}

	// 1. geo_line (with sort + include_sort + empty filter bucket), cartesian_bounds, cartesian_centroid, geohex_grid, geo_bounds(shape), geo_centroid(shape), geotile_grid(shape)
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_spatial_idx/_search", `{
		"size": 0,
		"aggs": {
			"eu_line": {
				"filter": {"term": {"grp": "eu"}},
				"aggs": {
					"path": {
						"geo_line": {
							"point": {"field": "loc"},
							"sort": {"field": "seq"},
							"include_sort": true
						}
					}
				}
			},
			"empty_line": {
				"filter": {"term": {"grp": "none"}},
				"aggs": {
					"path": {
						"geo_line": {
							"point": {"field": "loc"},
							"sort": {"field": "seq"},
							"include_sort": true
						}
					}
				}
			},
			"c_bounds": {"cartesian_bounds": {"field": "pt"}},
			"c_cent": {"cartesian_centroid": {"field": "pt"}},
			"c_shape_bounds": {"cartesian_bounds": {"field": "cart_shape"}},
			"s_bounds": {"geo_bounds": {"field": "shape"}},
			"s_cent": {"geo_centroid": {"field": "shape"}},
			"hex_grid": {"geohex_grid": {"field": "loc", "precision": 3}},
			"shape_tile": {"geotile_grid": {"field": "shape", "precision": 3}}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("spatial aggs search failed (%d): %v", st, res)
	}
	aggs := res["aggregations"].(map[string]any)

	euLine := aggs["eu_line"].(map[string]any)["path"].(map[string]any)
	geom := euLine["geometry"].(map[string]any)
	coords := geom["coordinates"].([]any)
	if geom["type"] != "LineString" || len(coords) != 2 {
		t.Fatalf("expected 2-point geo_line, got %+v", euLine)
	}
	firstPt := coords[0].([]any)
	if firstPt[0].(float64) > 0 {
		t.Fatalf("expected seq=1 London (-0.1278) first in sorted geo_line, got %+v", coords)
	}
	if props, ok := euLine["properties"].(map[string]any); !ok || props["complete"] != true || len(props["sort_values"].([]any)) != 2 {
		t.Fatalf("unexpected geo_line properties: %+v", euLine["properties"])
	}

	emptyLine := aggs["empty_line"].(map[string]any)["path"].(map[string]any)
	if len(emptyLine["geometry"].(map[string]any)["coordinates"].([]any)) != 0 {
		t.Fatalf("expected empty geo_line coordinates, got %+v", emptyLine)
	}

	cBounds := aggs["c_bounds"].(map[string]any)["bounds"].(map[string]any)
	tl := cBounds["top_left"].(map[string]any)
	br := cBounds["bottom_right"].(map[string]any)
	if tl["x"].(float64) != 10 || tl["y"].(float64) != 200 || br["x"].(float64) != 100 || br["y"].(float64) != 20 {
		t.Fatalf("unexpected cartesian_bounds on point: %+v", cBounds)
	}
	cCent := aggs["c_cent"].(map[string]any)
	if int(cCent["count"].(float64)) != 3 {
		t.Fatalf("expected cartesian_centroid count=3, got %+v", cCent)
	}
	csBounds := aggs["c_shape_bounds"].(map[string]any)["bounds"].(map[string]any)
	if csBounds["top_left"].(map[string]any)["x"].(float64) != 0 || csBounds["bottom_right"].(map[string]any)["x"].(float64) != 25 {
		t.Fatalf("unexpected cartesian_bounds on cart_shape: %+v", csBounds)
	}

	if _, hasBounds := aggs["s_bounds"].(map[string]any)["bounds"]; !hasBounds {
		t.Fatalf("expected geo_bounds on geo_shape, got %+v", aggs["s_bounds"])
	}
	if int(aggs["s_cent"].(map[string]any)["count"].(float64)) == 0 {
		t.Fatalf("expected non-zero geo_centroid on geo_shape, got %+v", aggs["s_cent"])
	}
	hexBuckets := aggs["hex_grid"].(map[string]any)["buckets"].([]any)
	if len(hexBuckets) != 3 {
		t.Fatalf("expected 3 geohex_grid buckets, got %+v", hexBuckets)
	}
	for _, hb := range hexBuckets {
		key := hb.(map[string]any)["key"].(string)
		if _, err := spatial.StringToCell(key); err != nil {
			t.Fatalf("invalid H3 cell key %q: %v", key, err)
		}
	}
	tileBuckets := aggs["shape_tile"].(map[string]any)["buckets"].([]any)
	if len(tileBuckets) == 0 {
		t.Fatalf("expected non-empty geotile_grid buckets for geo_shape")
	}

	// 2. geo_grid query (geohex cell for Paris) + geo_shape CONTAINS query + doc_values:false/index:false 400 rejection
	parisCell, err := spatial.LatLonToCell(48.8566, 2.3522, 3)
	if err != nil {
		t.Fatalf("LatLonToCell failed: %v", err)
	}
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_spatial_idx/_search", `{
		"query": {"geo_grid": {"loc": {"geohex": "`+spatial.CellToString(parisCell)+`"}}},
		"aggs": {"c": {"cartesian_centroid": {"field": "pt"}}}
	}`)
	if st != http.StatusOK || int(res["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)) != 1 {
		t.Fatalf("expected 1 hit for geohex geo_grid query, got (%d): %v", st, res)
	}

	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_spatial_idx/_search", `{
		"query": {
			"geo_shape": {
				"shape": {
					"shape": {"type": "point", "coordinates": [2.5, 48.5]},
					"relation": "contains"
				}
			}
		}
	}`)
	if st != http.StatusOK || int(res["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)) != 1 {
		t.Fatalf("expected 1 hit for geo_shape contains query, got (%d): %v", st, res)
	}

	for _, badQ := range []string{
		`{"query": {"geo_grid": {"no_dv_no_idx": {"geohash": "u09t"}}}}`,
		`{"query": {"geo_shape": {"no_dv_no_idx": {"shape": {"type": "point", "coordinates": [2.5, 48.5]}}}}}`,
	} {
		if stBad, resBad := doStatusR62Cov(t, srv, http.MethodPost, "/r64_spatial_idx/_search", badQ); stBad != http.StatusBadRequest {
			t.Fatalf("expected 400 on doc_values:false/index:false query %s, got (%d): %v", badQ, stBad, resBad)
		}
	}

	// 3. time_series + geo_line position agg with Java Map.toString keyed bucket key
	st, res = doStatusR62Cov(t, srv, http.MethodPut, "/r64_ts_pos", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["city"],
			"index.time_series.start_time": "2026-01-01T00:00:00Z",
			"index.time_series.end_time": "2026-01-10T00:00:00Z"
		},
		"mappings": {
			"properties": {
				"city": {"type": "keyword", "time_series_dimension": true},
				"loc": {"type": "geo_point", "time_series_metric": "position"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create TSDB index failed (%d): %v", st, res)
	}
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ts_pos/_bulk?refresh=true",
		`{"index":{}}`+"\n"+`{"@timestamp":"2026-01-02T01:00:00Z","city":"Paris","loc":{"lat":48.85,"lon":2.35}}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2026-01-02T02:00:00Z","city":"Paris","loc":{"lat":48.86,"lon":2.36}}`+"\n")
	if st != http.StatusOK {
		t.Fatalf("bulk TSDB index failed (%d): %v", st, res)
	}
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ts_pos/_search", `{
		"size": 0,
		"aggs": {
			"by_city": {
				"time_series": {"keyed": true},
				"aggs": {
					"track": {"geo_line": {"point": {"field": "loc"}}}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("TSDB geo_line search failed (%d): %v", st, res)
	}
	tsBuckets := res["aggregations"].(map[string]any)["by_city"].(map[string]any)["buckets"].(map[string]any)
	parisBucket, okParis := tsBuckets["{city=Paris}"].(map[string]any)
	if !okParis {
		t.Fatalf("expected keyed bucket {city=Paris}, got %+v", tsBuckets)
	}
	trackCoords := parisBucket["track"].(map[string]any)["geometry"].(map[string]any)["coordinates"].([]any)
	if len(trackCoords) != 2 {
		t.Fatalf("expected 2 coordinates in TSDB geo_line, got %+v", parisBucket)
	}
}

func TestRound64_Spatial_RuntimeGeoShape_And_GeoShapeDocValues(t *testing.T) {
	srv, _ := newTestServer()
	defer func() { _ = srv.Close(context.Background()) }()

	st, res := doStatusR62Cov(t, srv, http.MethodPut, "/r64_rt_shape", `{
		"mappings": {
			"properties": {
				"shape": {"type": "geo_shape"},
				"name": {"type": "keyword"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create runtime shape index failed (%d): %v", st, res)
	}
	st, _ = doStatusR62Cov(t, srv, http.MethodPost, "/r64_rt_shape/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"name":"box","shape":{"type":"polygon","coordinates":[[[2.0,48.0],[3.0,48.0],[3.0,49.0],[2.0,49.0],[2.0,48.0]]]}}`+"\n")
	if st != http.StatusOK {
		t.Fatalf("bulk index failed (%d)", st)
	}

	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_rt_shape/_search", `{
		"runtime_mappings": {
			"dyn_shape": {
				"type": "geo_shape",
				"script": {"source": "emit('POINT (2.35 48.86)')"}
			},
			"bbox_min_lat": {
				"type": "double",
				"script": {"source": "emit(doc['shape'].getBoundingBox().minLat)"}
			}
		},
		"fields": ["dyn_shape", "bbox_min_lat"],
		"query": {
			"geo_shape": {
				"dyn_shape": {
					"shape": {"type": "polygon", "coordinates": [[[2.0,48.0],[3.0,48.0],[3.0,49.0],[2.0,49.0],[2.0,48.0]]]},
					"relation": "within"
				}
			}
		},
		"aggs": {
			"rt_bounds": {"geo_bounds": {"field": "dyn_shape"}}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("runtime geo_shape search failed (%d): %v", st, res)
	}
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for runtime geo_shape within query, got %+v", hits)
	}
	fields := hits[0].(map[string]any)["fields"].(map[string]any)
	if _, ok := fields["dyn_shape"]; !ok {
		t.Fatalf("expected dyn_shape in hit fields, got %+v", fields)
	}
	if gotMinLat := fields["bbox_min_lat"].([]any)[0].(float64); gotMinLat < 47.99 || gotMinLat > 48.01 {
		t.Fatalf("expected bbox minLat ~48.0 from doc['shape'].getBoundingBox(), got %v", gotMinLat)
	}
	if _, ok := res["aggregations"].(map[string]any)["rt_bounds"].(map[string]any)["bounds"]; !ok {
		t.Fatalf("expected geo_bounds on runtime geo_shape, got %+v", res["aggregations"])
	}
}

func TestRound64_CountedTerms_Murmur3_AggregateMetricDouble_UnsignedLong_And_ConstantKeyword(t *testing.T) {
	srv, _ := newTestServer()
	defer func() { _ = srv.Close(context.Background()) }()
	srv.SetTargetESVersion("8.15.5")

	// 1. counted_terms + murmur3 + aggregate_metric_double + unsigned_long + constant_keyword multifield warning
	recWarn := doRawHTTPReqR64(t, srv, http.MethodPut, "/r64_ck_a", `{
		"mappings": {
			"properties": {
				"foo": {"type": "constant_keyword", "value": "bar", "fields": {"raw": {"type": "keyword"}}},
				"tags": {"type": "counted_keyword"},
				"word": {"type": "keyword", "fields": {"hash": {"type": "murmur3"}}},
				"metrics": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count"], "default_metric": "sum"},
				"ul": {"type": "unsigned_long", "store": true}
			}
		}
	}`, nil)
	if recWarn.Code != http.StatusOK {
		t.Fatalf("create r64_ck_a failed (%d): %s", recWarn.Code, recWarn.Body.String())
	}
	if !strings.Contains(strings.Join(recWarn.Header().Values("Warning"), ","), "constant_keyword") {
		t.Fatalf("expected deprecation warning for constant_keyword multifield, got headers: %+v", recWarn.Header())
	}

	st, res := doStatusR62Cov(t, srv, http.MethodPut, "/r64_ck_b", `{
		"mappings": {
			"properties": {
				"foo": {"type": "constant_keyword", "value": "baz"},
				"ul": {"type": "long"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r64_ck_b failed (%d): %v", st, res)
	}

	bulkA := strings.Join([]string{
		`{"index":{"_id":"1"}}`,
		`{"tags":["a","a","b"],"word":"hello","metrics":{"min":1.0,"max":10.0,"sum":15.0,"value_count":3},"ul":18446744073709551615}`,
		`{"index":{"_id":"2"}}`,
		`{"tags":["a","c"],"word":"world","metrics":{"min":2.0,"max":4.0,"sum":6.0,"value_count":2},"ul":0}`,
		"",
	}, "\n")
	if st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_a/_bulk?refresh=true", bulkA); st != http.StatusOK {
		t.Fatalf("bulk r64_ck_a failed (%d): %v", st, res)
	}
	if st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_b/_doc/1?refresh=true", `{"ul":42}`); st != http.StatusOK && st != http.StatusCreated {
		t.Fatalf("index r64_ck_b failed (%d): %v", st, res)
	}

	// constant_keyword shard-skip
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_*/_search?pre_filter_shard_size=1", `{
		"size": 0,
		"query": {"term": {"foo": "bar"}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("constant_keyword search failed (%d): %v", st, res)
	}
	shards := res["_shards"].(map[string]any)
	if int(shards["total"].(float64)) != 2 || int(shards["skipped"].(float64)) != 1 || int(shards["successful"].(float64)) != 2 {
		t.Fatalf("expected _shards total=2, skipped=1, successful=2, got %+v", shards)
	}

	// counted_terms + murmur3 + aggregate_metric_double fields + unsigned_long stored_fields & sort & mixed terms
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_a/_search", `{
		"stored_fields": ["ul"],
		"fields": ["word.hash", "metrics"],
		"docvalue_fields": ["word.hash"],
		"script_fields": {"h": {"script": "doc['word.hash'].value"}},
		"sort": [{"ul": {"order": "desc"}}],
		"aggs": {
			"ct": {"counted_terms": {"field": "tags", "size": 5}}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("r64_ck_a feature search failed (%d): %v", st, res)
	}
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	h0 := hits[0].(map[string]any)
	if h0["_id"] != "1" {
		t.Fatalf("expected uint64 max doc _id=1 first on desc sort, got %+v", hits)
	}
	sf0 := h0["fields"].(map[string]any)
	if ulVals, ok := sf0["ul"].([]any); !ok || len(ulVals) == 0 || ulVals[0] != "18446744073709551615" {
		t.Fatalf("expected stringified stored unsigned_long 18446744073709551615, got %+v", sf0["ul"])
	}
	expectedHash := painless.ComputePainlessMurmur3Hash("hello")
	recHash := httptest.NewRecorder()
	reqHash := httptest.NewRequest(http.MethodPost, "/r64_ck_a/_search", strings.NewReader(`{
		"stored_fields": ["ul"],
		"fields": ["word.hash", "metrics"],
		"docvalue_fields": ["word.hash"],
		"script_fields": {"h": {"script": "doc['word.hash'].value"}},
		"sort": [{"ul": {"order": "desc"}}],
		"aggs": {"ct": {"counted_terms": {"field": "tags", "size": 5}}}
	}`))
	reqHash.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(recHash, reqHash)
	var numRes map[string]any
	decHash := json.NewDecoder(bytes.NewReader(recHash.Body.Bytes()))
	decHash.UseNumber()
	if err := decHash.Decode(&numRes); err != nil {
		t.Fatalf("decode murmur3 response failed: %v", err)
	}
	numHits := numRes["hits"].(map[string]any)["hits"].([]any)
	numSF0 := numHits[0].(map[string]any)["fields"].(map[string]any)
	dvHash, errHash := numSF0["word.hash"].([]any)[0].(json.Number).Int64()
	if errHash != nil || dvHash != expectedHash {
		t.Fatalf("expected murmur3 hash %d, got %d (err=%v, raw=%+v)", expectedHash, dvHash, errHash, numSF0["word.hash"])
	}
	if _, ok := sf0["metrics"].([]any)[0].(map[string]any); !ok {
		t.Fatalf("expected aggregate_metric_double object in fields, got %+v", sf0["metrics"])
	}
	ctBuckets := res["aggregations"].(map[string]any)["ct"].(map[string]any)["buckets"].([]any)
	if len(ctBuckets) != 3 || ctBuckets[0].(map[string]any)["key"] != "a" || int(ctBuckets[0].(map[string]any)["doc_count"].(float64)) != 3 {
		t.Fatalf("expected counted_terms bucket 'a' with doc_count=3, got %+v", ctBuckets)
	}

	// aggregate_metric_double in docvalue_fields rejected
	if stDV, resDV := doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_a/_search", `{"docvalue_fields":["metrics"]}`); stDV != http.StatusBadRequest {
		t.Fatalf("expected 400 for aggregate_metric_double docvalue_fields, got (%d): %v", stDV, resDV)
	}

	// Cross-index mixed numeric (unsigned_long + long) terms agg widening
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ck_*/_search", `{
		"size": 0,
		"aggs": {"ul_terms": {"terms": {"field": "ul"}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("mixed unsigned_long+long terms agg failed (%d): %v", st, res)
	}
	ulBuckets := res["aggregations"].(map[string]any)["ul_terms"].(map[string]any)["buckets"].([]any)
	if len(ulBuckets) != 3 {
		t.Fatalf("expected 3 buckets in mixed unsigned_long+long terms agg, got %+v", ulBuckets)
	}
}

func TestRound64_HEAD_FilterPath_Scripts_ILM_Rescore_Collapse_And_F28(t *testing.T) {
	srv, _ := newTestServer()
	defer func() { _ = srv.Close(context.Background()) }()

	// F7: /_script_context & /_script_language
	for _, path := range []string{"/_script_context", "/_script_language", "/_script_languages"} {
		st, res := doStatusR62Cov(t, srv, http.MethodGet, path, "")
		if st != http.StatusOK || len(res) == 0 {
			t.Fatalf("expected 200 non-empty on %s, got (%d): %v", path, st, res)
		}
	}

	// F3: ILM policy validation, delete-in-use, multi-wildcard get, and _ilm/explain filtering
	if st, res := doStatusR62Cov(t, srv, http.MethodPut, "/_ilm/policy/r64_bad_age", `{
		"policy": {
			"phases": {
				"hot": {"min_age": "10d"},
				"warm": {"min_age": "5d"}
			}
		}
	}`); st != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-monotonic ILM min_age, got (%d): %v", st, res)
	}
	if st, res := doStatusR62Cov(t, srv, http.MethodPut, "/_ilm/policy/r64_good_pol", `{
		"policy": {"phases": {"hot": {"min_age": "0ms"}}}
	}`); st != http.StatusOK {
		t.Fatalf("expected 200 for valid ILM policy, got (%d): %v", st, res)
	}
	if st, res := doStatusR62Cov(t, srv, http.MethodGet, "/_ilm/policy/r64_*,other_*", ""); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on multi-wildcard GET _ilm/policy, got (%d): %v", st, res)
	}
	if st, res := doStatusR62Cov(t, srv, http.MethodPut, "/r64_ilm_idx", `{
		"settings": {"index.lifecycle.name": "r64_good_pol"},
		"mappings": {"properties": {"cat": {"type": "keyword"}, "sub": {"type": "keyword"}, "city": {"type": "keyword"}, "txt": {"type": "text"}}}
	}`); st != http.StatusOK {
		t.Fatalf("create ILM index failed (%d): %v", st, res)
	}
	if st, res := doStatusR62Cov(t, srv, http.MethodDelete, "/_ilm/policy/r64_good_pol", ""); st != http.StatusBadRequest {
		t.Fatalf("expected 400 when deleting ILM policy in use, got (%d): %v", st, res)
	}
	if st, res := doStatusR62Cov(t, srv, http.MethodGet, "/r64_ilm_idx/_ilm/explain?only_managed=true", ""); st != http.StatusOK {
		t.Fatalf("expected 200 for _ilm/explain?only_managed=true, got (%d): %v", st, res)
	} else if _, ok := res["indices"].(map[string]any)["r64_ilm_idx"]; !ok {
		t.Fatalf("expected r64_ilm_idx in managed _ilm/explain, got %+v", res)
	}

	// Bulk docs for collapse _doc tie-break, rescore window_size, HEAD, filter_path+gzip, HTML escaping
	bulk := strings.Join([]string{
		`{"index":{"_id":"5"}}`,
		`{"cat":"a","sub":"s1","city":"London","txt":"alpha beta <tag>"}`,
		`{"index":{"_id":"8"}}`,
		`{"cat":"a","sub":"s2","city":"London","txt":"alpha"}`,
		`{"index":{"_id":"9"}}`,
		`{"cat":"b","sub":"s3","city":"Paris","txt":"gamma"}`,
		"",
	}, "\n")
	if st, res := doStatusR62Cov(t, srv, http.MethodPost, "/r64_ilm_idx/_bulk?refresh=true", bulk); st != http.StatusOK {
		t.Fatalf("bulk r64_ilm_idx failed (%d): %v", st, res)
	}

	// F6: HEAD body suppression + Content-Length + SetEscapeHTML(false) + multi-filter_path + gzip
	recHeadIdx := doRawHTTPReqR64(t, srv, http.MethodHead, "/r64_ilm_idx", "", nil)
	if recHeadIdx.Code != http.StatusOK || recHeadIdx.Body.Len() != 0 {
		t.Fatalf("expected 200 empty HEAD /r64_ilm_idx body, got code=%d len=%d", recHeadIdx.Code, recHeadIdx.Body.Len())
	}
	recHeadRoot := doRawHTTPReqR64(t, srv, http.MethodHead, "/", "", nil)
	if recHeadRoot.Code != http.StatusOK || recHeadRoot.Body.Len() != 0 || recHeadRoot.Header().Get("Content-Length") == "" {
		t.Fatalf("expected empty HEAD / body with Content-Length, got code=%d len=%d cl=%q", recHeadRoot.Code, recHeadRoot.Body.Len(), recHeadRoot.Header().Get("Content-Length"))
	}
	recPlain := doRawHTTPReqR64(t, srv, http.MethodPost, "/r64_ilm_idx/_search", `{"query":{"term":{"_id":"5"}}}`, nil)
	if strings.Contains(recPlain.Body.String(), `\u003c`) {
		t.Fatalf("expected unescaped HTML in JSON response (SetEscapeHTML(false)), got: %s", recPlain.Body.String())
	}
	recGzip := doRawHTTPReqR64(t, srv, http.MethodPost, "/r64_ilm_idx/_search?filter_path=hits.total&filter_path=took", `{"size":1}`, map[string]string{"Accept-Encoding": "gzip"})
	if recGzip.Code != http.StatusOK {
		t.Fatalf("filter_path + gzip failed (%d): %s", recGzip.Code, recGzip.Body.String())
	}
	zr, err := gzip.NewReader(bytes.NewReader(recGzip.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader failed: %v", err)
	}
	rawGzipBody, _ := io.ReadAll(zr)
	_ = zr.Close()
	var fpOut map[string]any
	if err := json.Unmarshal(rawGzipBody, &fpOut); err != nil {
		t.Fatalf("invalid gzipped filter_path JSON %q: %v", string(rawGzipBody), err)
	}
	if _, ok := fpOut["took"]; !ok {
		t.Fatalf("expected 'took' from multi-filter_path, got %+v", fpOut)
	}
	if _, ok := fpOut["hits"]; !ok {
		t.Fatalf("expected 'hits' from multi-filter_path, got %+v", fpOut)
	}

	// F15: rescore window_size=1 + query_weight=0.5 + explain
	st, res := doStatusR62Cov(t, srv, http.MethodPost, "/r64_ilm_idx/_search", `{
		"explain": true,
		"query": {"match": {"txt": "alpha"}},
		"rescore": {
			"window_size": 1,
			"query": {
				"rescore_query": {"match": {"txt": "beta"}},
				"query_weight": 0.5,
				"rescore_query_weight": 2.0
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("rescore explain search failed (%d): %v", st, res)
	}
	rHits := res["hits"].(map[string]any)["hits"].([]any)
	if len(rHits) != 2 {
		t.Fatalf("expected 2 rescore hits, got %+v", rHits)
	}
	outOfWindowExpl := rHits[1].(map[string]any)["_explanation"].(map[string]any)["description"].(string)
	if strings.Contains(outOfWindowExpl, "rescore") {
		t.Fatalf("expected hit outside window_size=1 not to include rescore breakdown, got %q", outOfWindowExpl)
	}

	// F15: two-level collapse with inner_hits _doc tie-breaking ("5" before "8")
	st, res = doStatusR62Cov(t, srv, http.MethodPost, "/r64_ilm_idx/_search", `{
		"collapse": {
			"field": "cat",
			"inner_hits": {
				"name": "by_sub",
				"size": 5,
				"sort": [{"city": "desc"}],
				"collapse": {"field": "sub"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("collapse _doc tiebreak failed (%d): %v", st, res)
	}
	var catAHits []any
	for _, hAny := range res["hits"].(map[string]any)["hits"].([]any) {
		hm := hAny.(map[string]any)
		if hm["_source"].(map[string]any)["cat"] == "a" {
			catAHits = hm["inner_hits"].(map[string]any)["by_sub"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
		}
	}
	if len(catAHits) != 2 || catAHits[0].(map[string]any)["_id"] != "5" || catAHits[1].(map[string]any)["_id"] != "8" {
		t.Fatalf("expected _doc tiebreak 5 before 8, got %+v", catAHits)
	}

	// F28: UTF-16 offset mapping for supplementary emoji + vwhMergeHeapR64 min-heap + Close() cleanup
	u16 := utf16OffsetsToByteOffsetsR64("a😀b")
	if bStart, bEnd, ok := resolveUTF16HighlightSpanBytesR64(u16, 3, 4); !ok || "a😀b"[bStart:bEnd] != "b" {
		t.Fatalf("expected UTF-16 offset 3..4 to slice 'b', got (%d,%d,%v) on %v", bStart, bEnd, ok, u16)
	}
	pq := &vwhMergeHeapR64{}
	heap.Init(pq)
	heap.Push(pq, vwhMergeCandidateR64{dist: 10.0, leftPos: 0})
	heap.Push(pq, vwhMergeCandidateR64{dist: 2.0, leftPos: 1})
	top := heap.Pop(pq).(vwhMergeCandidateR64)
	if top.dist != 2.0 || top.leftPos != 1 {
		t.Fatalf("expected min-heap pop dist=2.0, got %+v", top)
	}

	// TSDB tombstone cleanup on Close()
	tsSrv, _ := newTestServer()
	tsSrv.indices["ts_clean"] = &schema.IndexSchema{IndexMode: "time_series"}
	tsSrv.recordTSDBTombstoneVersionR63("ts_clean", "doc1", 2)
	_ = tsSrv.Close(context.Background())
	tsdbTombstoneMuR63.RLock()
	_, stillPresent := tsdbTombstonesBySrvR63[tsSrv]
	tsdbTombstoneMuR63.RUnlock()
	if stillPresent {
		t.Fatalf("expected Close() to remove tsdbTombstonesBySrvR63 entry")
	}
}
