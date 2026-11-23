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
	"container/heap"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
)

type r65UnwrapResponseWriter struct {
	http.ResponseWriter
}

func (rw *r65UnwrapResponseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

type r65SelfUnwrapResponseWriter struct {
	http.ResponseWriter
}

func (rw *r65SelfUnwrapResponseWriter) Unwrap() http.ResponseWriter {
	return rw
}

func doR65HTTPJSON(t *testing.T, srv *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader = strings.NewReader("")
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func TestRound65_F2_F5_Spatial_HardeningHeadUnwrapAndGridConformance(t *testing.T) {
	t.Parallel()

	// 1. F5-head: headResponseWriterR64.Unwrap() + unwrapResponseFormatAndHeadR64 + refreshFormatOptionsMultiFilterPathR64
	rec := httptest.NewRecorder()
	fmtW := &esFormatResponseWriter{
		ResponseWriter: rec,
		opts:           esResponseFormatOptions{filterPaths: []string{"hits.total"}},
	}
	customOuter := &r65UnwrapResponseWriter{ResponseWriter: fmtW}
	headW := &headResponseWriterR64{ResponseWriter: customOuter}
	if headW.Unwrap() != customOuter {
		t.Fatalf("expected headResponseWriterR64.Unwrap() to return customOuter")
	}
	if n, err := headW.Write([]byte("suppressed")); err != nil || n != len("suppressed") || rec.Body.Len() != 0 {
		t.Fatalf("expected HEAD body suppressed cleanly, got n=%d err=%v body=%d", n, err, rec.Body.Len())
	}
	headW.Flush()

	opts, hasOpts, isHead := unwrapResponseFormatAndHeadR64(headW)
	if !hasOpts || !isHead || len(opts.filterPaths) != 1 || opts.filterPaths[0] != "hits.total" {
		t.Fatalf("unwrapResponseFormatAndHeadR64 through custom Unwrap() failed: opts=%+v hasOpts=%v isHead=%v", opts, hasOpts, isHead)
	}
	exOpts, okEx := extractESResponseFormatOptionsR64(headW)
	if !okEx || len(exOpts.filterPaths) != 1 {
		t.Fatalf("extractESResponseFormatOptionsR64 failed: %+v %v", exOpts, okEx)
	}

	reqMulti := httptest.NewRequest(http.MethodHead, "/_search?filter_path=hits.hits,took", nil)
	refW := refreshFormatOptionsMultiFilterPathR64(headW, reqMulti)
	if refW != headW || len(fmtW.opts.filterPaths) != 2 {
		t.Fatalf("expected refreshFormatOptionsMultiFilterPathR64 to update in place via Unwrap, got paths=%+v", fmtW.opts.filterPaths)
	}

	// Self-referential / nil Unwrap guard must terminate without looping.
	selfW := &r65SelfUnwrapResponseWriter{ResponseWriter: rec}
	if _, hasO, isH := unwrapResponseFormatAndHeadR64(selfW); hasO || isH {
		t.Fatalf("expected self-unwrap writer to return false/false, got %v/%v", hasO, isH)
	}
	if wr := refreshFormatOptionsMultiFilterPathR64(selfW, reqMulti); wr == selfW {
		t.Fatalf("expected refreshFormatOptionsMultiFilterPathR64 to wrap when no inner esFormatResponseWriter exists")
	}

	// 2. F2c: Non-finite (NaN / +Inf / -Inf) coordinates rejected across WKT, GeoJSON, []float64, GeoPointVal, GeoBoundingBoxVal, and x/y maps
	badCoordInputs := []any{
		"POINT (NaN 10)",
		"POINT (Inf 10)",
		"POINT (10 -Inf)",
		"LINESTRING (0 0, Inf 1)",
		"POLYGON ((0 0, 1 0, 1 NaN, 0 0))",
		map[string]any{"type": "point", "coordinates": []any{math.NaN(), 10.0}},
		map[string]any{"type": "point", "coordinates": []float64{math.Inf(1), 10.0}},
		map[string]any{"type": "linestring", "coordinates": [][]float64{{0, 0}, {1, math.Inf(-1)}}},
		map[string]any{"type": "envelope", "coordinates": []any{[]float64{0, math.NaN()}, []float64{1, 1}}},
		map[string]any{"lat": math.Inf(1), "lon": 2.0},
		map[string]any{"x": math.NaN(), "y": 2.0},
		map[string]any{"x": 1.0, "y": math.Inf(1)},
		[]float64{math.Inf(1), 0.0},
		&painless.GeoPointVal{Lat: math.NaN(), Lon: 1.0},
		&painless.GeoPointVal{Lat: 1.0, Lon: math.Inf(-1)},
		&painless.GeoBoundingBoxVal{
			TopLeft:     &painless.GeoPointVal{Lat: 2.0, Lon: 1.0},
			BottomRight: &painless.GeoPointVal{Lat: math.Inf(-1), Lon: 2.0},
		},
		&painless.GeoBoundingBoxVal{
			TopLeft:     &painless.GeoPointVal{Lat: math.NaN(), Lon: 1.0},
			BottomRight: &painless.GeoPointVal{Lat: 0.0, Lon: 2.0},
		},
	}
	for i, bad := range badCoordInputs {
		if shapes, ok := parseRawShapesR64(bad, false); ok && len(shapes) > 0 {
			t.Fatalf("case %d: expected non-finite input %#v to be rejected, got %+v", i, bad, shapes)
		}
	}

	// 3. F2c: validateSpatialAndTimeSeriesAggTreeR64 precision checks (geohash 1..12, geotile 0..29, geohex 0..spatial.MaxRes)
	for _, tc := range []struct {
		name string
		spec esast.AggSpec
	}{
		{"geohash_0", esast.AggSpec{GeohashGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(0)}}},
		{"geohash_13", esast.AggSpec{GeohashGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(13)}}},
		{"geotile_neg", esast.AggSpec{GeotileGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(-1)}}},
		{"geotile_30", esast.AggSpec{GeotileGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(30)}}},
		{"geohex_neg", esast.AggSpec{GeoHexGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(-1)}}},
		{"geohex_gt_max", esast.AggSpec{GeoHexGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(spatial.MaxRes + 1)}}},
	} {
		st, et, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{"g": tc.spec}, false)
		if st != http.StatusBadRequest || et != "illegal_argument_exception" {
			t.Fatalf("%s: expected 400 illegal_argument_exception, got st=%d et=%q", tc.name, st, et)
		}
	}
	if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{
		"ts": {
			TimeSeries: &esast.TimeSeriesAggSpec{},
			Aggs: map[string]esast.AggSpec{
				"line": {GeoLine: &esast.GeoLineAggSpec{Sort: &esast.GeoLinePointSpec{Field: "seq"}}},
			},
		},
	}, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 for geo_line sort != @timestamp under time_series, got %d", st)
	}

	// 4. F2c: Zoom/precision clamping, overflow guards, poles, and antimeridian bounds intersection
	globalEnv := parsedGeomR64{kind: geomEnvelopeR64, topLat: 85.0, leftLon: -180.0, botLat: -85.0, rightLon: 180.0}
	if cells := enumerateGeotileCellsForGeomR64(globalEnv, -5, false, 0, 0, 0, 0); len(cells) != 1 || cells[0] != "0/0/0" {
		t.Fatalf("expected zoom=-5 clamped to 0/0/0, got %v", cells)
	}
	if cells := enumerateGeotileCellsForGeomR64(globalEnv, 999, false, 0, 0, 0, 0); len(cells) > 4096 {
		t.Fatalf("expected fallback cap <= 4096 for zoom=999, got %d", len(cells))
	}
	// Ensure huge prec=12 span cannot integer-overflow stepsLat*stepsLon <= 4096
	if cells := enumerateGeohashCellsForGeomR64(globalEnv, 99, false, 0, 0, 0, 0); len(cells) > 4096 {
		t.Fatalf("expected fallback cap <= 4096 for prec=99, got %d", len(cells))
	}
	polePt := parsedGeomR64{kind: geomPointR64, pt: [2]float64{90.0, 180.0}}
	if cells := enumerateGeotileCellsForGeomR64(polePt, 5, false, 0, 0, 0, 0); len(cells) != 1 || !strings.HasPrefix(cells[0], "5/") {
		t.Fatalf("expected safe pole clamping on geotile, got %v", cells)
	}
	if !geoBoxIntersectsBoxR64(10, 170, -10, 179, 5, 175, -5, -175) {
		t.Fatalf("expected dateline-wrapping bounds intersection to return true")
	}

	// 5. C14b: geotile_grid cell-intersects-bounds for points + geohash_grid DESC tie-breaking + geo_point null_value
	antwerpPt := parsedGeomR64{kind: geomPointR64, pt: [2]float64{51.2229, 4.4052}}
	if cells := enumerateGeotileCellsForGeomR64(antwerpPt, 7, true, 52.4, 4.9, 52.3, 5.0); len(cells) != 1 || cells[0] != "7/65/42" {
		t.Fatalf("expected Antwerp point in tile 7/65/42 intersecting Amsterdam bounds, got %v", cells)
	}
	var tieRows []AggRow
	emitRuntimeGeoGridAggRowsR64("grid", "", esast.AggSpec{
		GeohashGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(5)},
	}, []runtimeMatchedDoc{
		{hit: HitRow{ID: "1"}, doc: map[string]any{"loc": "POINT (4.91235 52.374081)"}}, // u173z (doc 1)
		{hit: HitRow{ID: "2"}, doc: map[string]any{"loc": "POINT (4.90161 52.369219)"}}, // u173z (doc 2)
		{hit: HitRow{ID: "3"}, doc: map[string]any{"loc": "POINT (4.40520 51.222900)"}}, // u155k
		{hit: HitRow{ID: "4"}, doc: map[string]any{"loc": "POINT (2.33638 48.861111)"}}, // u09tv
		{hit: HitRow{ID: "5"}, doc: map[string]any{"loc": "POINT (2.32700 48.860000)"}}, // u09tu
	}, &tieRows, nil)
	if len(tieRows) != 4 || tieRows[0].BucketKey != "u173z" || tieRows[1].BucketKey != "u155k" || tieRows[2].BucketKey != "u09tv" || tieRows[3].BucketKey != "u09tu" {
		t.Fatalf("expected geohash_grid tie-break DESC order [u173z u155k u09tv u09tu], got %+v", tieRows)
	}

	// geo_point null_value substitution on explicit null and array containing null (omitted stays nil)
	var gpNullSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"pt":{"type":"geo_point","null_value":{"lat":28.41951122705923,"lon":-81.58118930548268}}}}`), &gpNullSpec)
	gpIdx := schema.CompileIndexSchema("es_db", "r65_gp_null", &gpNullSpec)
	if sh, _ := parseDocShapesR64(map[string]any{"pt": nil}, "pt", gpIdx, true); len(sh) != 1 {
		t.Fatalf("expected 1 shape from explicit null geo_point null_value, got %+v", sh)
	}
	if sh, _ := parseDocShapesR64(map[string]any{"pt": []any{nil, map[string]any{"lat": -54.48, "lon": -37.07}}}, "pt", gpIdx, true); len(sh) != 2 {
		t.Fatalf("expected 2 shapes from array [null, pt], got %+v", sh)
	}
	if sh, _ := parseDocShapesR64(map[string]any{"other": 1}, "pt", gpIdx, true); len(sh) != 0 {
		t.Fatalf("expected 0 shapes when field omitted, got %+v", sh)
	}

	// 6. End-to-end HTTP spatial validation & HEAD suppression
	srv, _ := newTestServer()
	defer func() { _ = srv.Close(context.Background()) }()
	if st, res := doR65HTTPJSON(t, srv, http.MethodPut, "/r65_spatial_e2e", `{"mappings":{"properties":{"loc":{"type":"geo_point"}}}}`); st != http.StatusOK {
		t.Fatalf("create index failed: %d %+v", st, res)
	}
	if st, _ := doR65HTTPJSON(t, srv, http.MethodPost, "/r65_spatial_e2e/_doc/1?refresh=true", `{"loc":{"lat":52.374,"lon":4.912}}`); st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("index doc failed: %d", st)
	}
	if st, _ := doR65HTTPJSON(t, srv, http.MethodPost, "/r65_spatial_e2e/_search", `{"size":0,"aggs":{"g":{"geotile_grid":{"field":"loc","precision":30}}}}`); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on geotile_grid precision=30, got %d", st)
	}
	reqHead := httptest.NewRequest(http.MethodHead, "/r65_spatial_e2e/_search?filter_path=hits.total,took", nil)
	recHead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK || recHead.Body.Len() != 0 {
		t.Fatalf("expected HEAD 200 with empty body, got status=%d len=%d", recHead.Code, recHead.Body.Len())
	}
}

func TestRound65_F27_Spatial_ParsersPredicatesQueriesAndAggsCoverage(t *testing.T) {
	t.Parallel()

	// 1. WKT & GeoJSON normalizers, formatters, dims, bbox, dateline checks
	polyWKT := "POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0), (2 2, 2 4, 4 4, 4 2, 2 2))"
	mpWKT := "MULTIPOINT ((1 2), (3 4))"
	mlsWKT := "MULTILINESTRING ((0 0, 2 2), (3 3, 5 5))"
	mpolyWKT := "MULTIPOLYGON (((0 0, 2 0, 2 2, 0 2, 0 0)), ((10 10, 12 10, 12 12, 10 12, 10 10)))"
	gcWKT := "GEOMETRYCOLLECTION (POINT (1 2), LINESTRING (0 0, 2 2), BBOX (-5, 5, 10, 0))"
	for _, raw := range []any{
		polyWKT, mpWKT, mlsWKT, mpolyWKT, gcWKT,
		"ENVELOPE (-10, 10, 50, 40)",
		&painless.GeoPointVal{Lat: 10.5, Lon: 20.5},
		&painless.GeoBoundingBoxVal{
			TopLeft:     &painless.GeoPointVal{Lat: 50, Lon: -10},
			BottomRight: &painless.GeoPointVal{Lat: 40, Lon: 10},
		},
		map[string]any{"type": "multipoint", "coordinates": []any{[]any{1.0, 2.0}, []any{3.0, 4.0}}},
		map[string]any{"type": "multilinestring", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{1.0, 1.0}}}},
		map[string]any{"type": "multipolygon", "coordinates": []any{[]any{[]any{[]any{0.0, 0.0}, []any{4.0, 0.0}, []any{4.0, 4.0}, []any{0.0, 4.0}, []any{0.0, 0.0}}}}},
		map[string]any{"type": "geometrycollection", "geometries": []any{map[string]any{"type": "point", "coordinates": []any{1.0, 2.0}}}},
	} {
		shapes, ok := parseRawShapesR64(raw, false)
		if !ok || len(shapes) == 0 {
			t.Fatalf("expected parseRawShapesR64(%#v) ok", raw)
		}
		for _, sh := range shapes {
			_ = sh.dim()
			_ = sh.toWKT()
			_ = sh.vertices()
			_, _, _, _ = sh.bbox()
		}
		if w := formatParsedShapesToWKTR64(shapes); w == "" {
			t.Fatalf("expected non-empty WKT for %#v", raw)
		}
		_, _ = normalizeGeoShapeValueToGeoJSONR64(raw, true)
		_, _ = formatGeoShapeSingleWKTR64(raw)
	}
	if outWKT := formatGeoShapeValuesForFieldsR64([]any{"POINT (1 2)", "LINESTRING (0 0, 2 2)"}, true); len(outWKT) != 1 {
		t.Fatalf("expected single GEOMETRYCOLLECTION WKT, got %+v", outWKT)
	}
	if outGJ := formatGeoShapeValuesForFieldsR64([]any{"BBOX (-10, 10, 50, 40)", "POINT (1 2)"}, false); len(outGJ) != 2 {
		t.Fatalf("expected 2 GeoJSON items, got %+v", outGJ)
	}
	if !checkSeqDatelineR64([][2]float64{{10, 179}, {10, -179}}, true) {
		t.Fatalf("expected dateline crossing detected")
	}

	// 2. Geometry predicates & centroids & minDistance
	outerPoly := parsedGeomR64{
		kind:  geomPolygonR64,
		outer: [][2]float64{{0, 0}, {0, 10}, {10, 10}, {10, 0}, {0, 0}},
		holes: [][][2]float64{{{3, 3}, {3, 6}, {6, 6}, {6, 3}, {3, 3}}},
	}
	insideOuterPt := parsedGeomR64{kind: geomPointR64, pt: [2]float64{1, 1}}
	insideHolePt := parsedGeomR64{kind: geomPointR64, pt: [2]float64{4, 4}}
	crossingLine := parsedGeomR64{kind: geomLineR64, line: [][2]float64{{-1, 1}, {11, 1}}}
	smallEnv := parsedGeomR64{kind: geomEnvelopeR64, topLat: 2, leftLon: 1, botLat: 1, rightLon: 2}
	if pointInPolygonR64(4, 4, outerPoly.outer, outerPoly.holes) {
		t.Fatalf("expected point inside hole NOT in polygon")
	}
	if !pointInPolygonR64(1, 1, outerPoly.outer, outerPoly.holes) {
		t.Fatalf("expected point outside hole IN polygon")
	}
	if !onSegment2DR64(1, 1, 0, 0, 2, 2) || !segmentsIntersect2DR64(0, 0, 2, 2, 0, 2, 2, 0) {
		t.Fatalf("expected 2D segment helpers true")
	}
	if !geomIntersectsQueryShapeR64(outerPoly, crossingLine) || !geomIntersectsQueryShapeR64(outerPoly, smallEnv) {
		t.Fatalf("expected polygon to intersect crossing line and small envelope")
	}
	if geomIntersectsQueryShapeR64(insideHolePt, outerPoly) {
		t.Fatalf("expected point inside hole NOT to intersect polygon")
	}
	if !geomBoxContainsGeomR64(insideOuterPt, 10, 0, 0, 10) {
		t.Fatalf("expected point contained in outer box")
	}
	if d := minDistanceMetersFromGeomR64(outerPoly, 12, 12); d <= 0 {
		t.Fatalf("expected positive distance outside polygon, got %v", d)
	}
	var centAccum centroidAccumR64
	centAccum.addGeom(outerPoly)
	centAccum.addGeom(crossingLine)
	centAccum.addGeom(smallEnv)
	centAccum.addGeom(insideOuterPt)
	if centAccum.sumW <= 0 || centAccum.maxDim != 2 {
		t.Fatalf("expected positive centroid accum sumW and maxDim=2, got %+v", centAccum)
	}

	// 3. Spatial queries: geo_bounding_box, geo_distance, geo_polygon, geo_shape (intersects, disjoint, within, contains), validateGeoGridQueryFieldsR64
	docMap := map[string]any{
		"loc":   map[string]any{"lat": 48.8566, "lon": 2.3522},
		"shape": "POLYGON ((2 48, 3 48, 3 49, 2 49, 2 48))",
	}
	if !evalDocGeoBoundingBoxQueryR64(nil, docMap, &esast.GeoBoundingBoxQuery{Field: "loc", Top: 49, Left: 2, Bottom: 48, Right: 3}) {
		t.Fatalf("expected geo_bounding_box match")
	}
	if !evalDocGeoDistanceQueryR64(nil, docMap, &esast.GeoDistanceQuery{Field: "loc", Lat: 48.85, Lon: 2.35, DistanceMeters: 5000}) {
		t.Fatalf("expected geo_distance match")
	}
	if !evalDocGeoPolygonQueryR64(nil, docMap, &esast.GeoPolygonQuery{Field: "loc", Points: [][2]float64{{48, 2}, {48, 3}, {49, 3}, {49, 2}}}) {
		t.Fatalf("expected geo_polygon match")
	}
	for _, tc := range []struct {
		rel  string
		want bool
	}{
		{"intersects", true},
		{"contains", true},
		{"disjoint", false},
		{"within", false},
	} {
		got := evalDocGeoShapeQueryR64(nil, docMap, &esast.GeoShapeQuery{
			Field:    "shape",
			Relation: tc.rel,
			Shape:    map[string]any{"type": "point", "coordinates": []any{2.5, 48.5}},
		})
		if got != tc.want {
			t.Fatalf("geo_shape relation=%s got=%v want=%v", tc.rel, got, tc.want)
		}
	}
	if !queryHasSpatialLeafR64(&esast.Query{Bool: &esast.BoolQuery{Must: []esast.Query{{GeoGrid: &esast.GeoGridQuery{Field: "loc", Geohash: "u09t"}}}}}) {
		t.Fatalf("expected queryHasSpatialLeafR64 true for nested bool geo_grid")
	}
	if st, _, _ := validateGeoGridQueryFieldsR64(nil, &esast.Query{GeoGrid: &esast.GeoGridQuery{Field: "", Geohash: "u09t"}}); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing geo_grid field, got %d", st)
	}
	if st, _, _ := validateGeoGridQueryFieldsR64(nil, &esast.Query{GeoGrid: &esast.GeoGridQuery{Field: "loc"}}); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing geo_grid grid cell token, got %d", st)
	}
	if evalDocGeoGridQueryR64(nil, docMap, &esast.GeoGridQuery{Field: "loc", Geohash: "bad!"}) ||
		evalDocGeoGridQueryR64(nil, docMap, &esast.GeoGridQuery{Field: "loc", Geotile: "30/0/0"}) ||
		evalDocGeoGridQueryR64(nil, docMap, &esast.GeoGridQuery{Field: "loc", Geohex: "not_hex"}) {
		t.Fatalf("expected invalid geo_grid cell tokens to match false at runtime")
	}

	// 4. Spatial aggs: geo_bounds (dateline), geo_centroid, cartesian_bounds, cartesian_centroid, geo_line (date sort), multi-index recompute, unindexed & min_doc_count:0
	mdDocs := []runtimeMatchedDoc{
		{hit: HitRow{ID: "1", Index: "idx1"}, doc: map[string]any{"loc": map[string]any{"lat": 10.0, "lon": 179.0}, "pt": map[string]any{"x": 1.0, "y": 2.0}, "ts": "2026-01-01T00:00:00Z", "tags": []any{"a", "a", "b"}}},
		{hit: HitRow{ID: "2", Index: "idx1"}, doc: map[string]any{"loc": map[string]any{"lat": 12.0, "lon": -179.0}, "pt": map[string]any{"x": 3.0, "y": 4.0}, "ts": int64(1767312000000), "tags": []any{"a"}}},
	}
	var aggRows []AggRow
	wrapTrue := true
	emitRuntimeGeoBoundsAggRowsR64("gb", "", &esast.GeoBoundsAggSpec{Field: "loc", WrapLongitude: &wrapTrue}, mdDocs, &aggRows)
	emitRuntimeGeoCentroidAggRowsR64("gc", "", &esast.MetricAggSpec{Field: "loc"}, mdDocs, &aggRows)
	emitRuntimeCartesianBoundsAggRowsR64("cb", "", &esast.CartesianBoundsAggSpec{Field: "pt"}, mdDocs, &aggRows)
	emitRuntimeCartesianCentroidAggRowsR64("cc", "", &esast.CartesianCentroidAggSpec{Field: "pt"}, mdDocs, &aggRows)
	emitRuntimeGeoLineAggRowsR64("gl", "", &esast.GeoLineAggSpec{
		Point: esast.GeoLinePointSpec{Field: "loc"},
		Sort:  &esast.GeoLinePointSpec{Field: "ts"},
	}, mdDocs, nil, &aggRows)
	var ctSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"tags":{"type":"counted_keyword"},"no_idx":{"type":"keyword","index":false,"doc_values":false}}}`), &ctSpec)
	ctIdx := schema.CompileIndexSchema("es_db", "idx1", &ctSpec)
	emitRuntimeCountedTermsAggRowsR64("ct", "", esast.AggSpec{CountedTerms: &esast.TermsAggSpec{Field: "tags"}}, mdDocs, &aggRows, ctIdx)
	if len(aggRows) < 6 {
		t.Fatalf("expected all runtime spatial & counted_terms agg rows emitted, got %d", len(aggRows))
	}
	if !isPureMatchAllQueryR64(&esast.Query{MatchAll: map[string]any{}}) || isPureMatchAllQueryR64(&esast.Query{Term: map[string]esast.TermEntry{"a": {Value: 1}}}) {
		t.Fatalf("unexpected isPureMatchAllQueryR64 results")
	}
	aggsMap := map[string]esast.AggSpec{
		"gb":  {GeoBounds: &esast.GeoBoundsAggSpec{Field: "loc"}},
		"idx": {Terms: &esast.TermsAggSpec{Field: "_index", MinDocCount: intPtr(0)}},
	}
	if !aggsHaveMinDocCountZeroR64(aggsMap) || !aggsHaveIndexTermsMinDocCountZeroR64(aggsMap) {
		t.Fatalf("expected min_doc_count:0 helpers true")
	}
	recomp := recomputeMultiIndexSpatialAggsR64(aggsMap, []HitRow{{ID: "1", Index: "idx1", Source: json.RawMessage(`{"loc":{"lat":1,"lon":2}}`)}}, map[string]*schema.IndexSchema{"idx1": ctIdx}, ctIdx, aggRows)
	recomp = injectZeroIndexTermsAggRowsR64("", aggsMap, []string{"idx1", "idx2"}, map[string]bool{"idx1": true}, recomp)
	if len(recomp) == 0 {
		t.Fatalf("expected injected zero index terms rows")
	}
	if !queryUsesUnindexedFieldR64(&esast.Query{Term: map[string]esast.TermEntry{"no_idx": {Value: "x"}}}, map[string]*schema.IndexSchema{"idx1": ctIdx}, ctIdx) {
		t.Fatalf("expected queryUsesUnindexedFieldR64 true for index:false/doc_values:false")
	}

	// 5. Top-of-file helpers (UTF-16 offsets, ILM durations & validators, VWH merge heap, runtime emit ctx)
	u16 := utf16OffsetsToByteOffsetsR64("a😀b")
	if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16, 1, 3); !okSpan || bStart != 1 || bEnd != 5 {
		t.Fatalf("expected UTF-16 surrogate pair byte span [1,5), got [%d,%d) ok=%v", bStart, bEnd, okSpan)
	}
	if ms, err := parseILMDurationMillisR64("2d", true); err != nil || ms != 2*86400000 {
		t.Fatalf("parseILMDurationMillisR64(2d) = (%v, %v)", ms, err)
	}
	if _, err := parseILMDurationMillisR64("bad_unit", false); err == nil {
		t.Fatalf("expected error on invalid ILM duration")
	}
	if _, okILM := validateILMPolicyBodyR64(map[string]any{"phases": map[string]any{"hot": map[string]any{"min_age": "invalid"}}}); okILM {
		t.Fatalf("expected validateILMPolicyBodyR64 to reject invalid min_age")
	}
	if !hasMultiWildcardPatternListR64("logs-*,metrics-*") || hasMultiWildcardPatternListR64("logs-*") {
		t.Fatalf("unexpected hasMultiWildcardPatternListR64 result")
	}
	if pol := extractIndexILMPolicyNameR64(map[string]any{"index.lifecycle.name": "my-ilm"}, nil); pol != "my-ilm" {
		t.Fatalf("expected my-ilm, got %q", pol)
	}
	var mh vwhMergeHeapR64
	heap.Push(&mh, vwhMergeCandidateR64{dist: 2.0, leftPos: 1})
	heap.Push(&mh, vwhMergeCandidateR64{dist: 1.0, leftPos: 0})
	if pop := heap.Pop(&mh).(vwhMergeCandidateR64); pop.dist != 1.0 {
		t.Fatalf("expected min-heap pop dist=1.0, got %+v", pop)
	}
	for _, rt := range []string{"geo_point", "geo_shape", "ip", "keyword", "long"} {
		if ctxName, okRT := runtimeFieldTypeToEmitContextR64(rt); !okRT || ctxName == "" {
			t.Fatalf("expected valid emit context for %s", rt)
		}
	}
}

func TestRound65_F4_F6_MemBackend_StrictNereidsAndPercolatorMerge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. F4b: checkStrictNereidsSQLTypesR63Mem rejections vs valid queries
	badQueries := []struct {
		name string
		sql  string
	}{
		{"match_in_cast_coalesce", "SELECT `_id` FROM `es`.`t` WHERE CAST(COALESCE(`f__msg` MATCH_ANY 'hello', FALSE) AS INT) > 0"},
		{"match_in_select_proj", "SELECT MATCH_PHRASE_PREFIX(`f__msg`, 'foo') AS `_m` FROM `es`.`t` WHERE 1=1"},
		{"match_in_base_matched", "WITH `base_matched` AS (SELECT * FROM `es`.`t` WHERE 1=1) SELECT COUNT(*) FROM `base_matched` WHERE `f__msg` MATCH_ALL 'bar'"},
		{"score_in_base_matched", "WITH `base_matched` AS (SELECT * FROM `es`.`t` WHERE `f__msg` MATCH_ALL 'a') SELECT MAX(score()) AS `_s` FROM `base_matched`"},
		{"union_unparen_order_by_first", "SELECT 'a' AS `_agg_name`, `k` AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched` ORDER BY `_doc_count` DESC LIMIT 5 UNION ALL (SELECT 'b' AS `_agg_name`, 'x' AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched`)"},
		{"union_unparen_order_by_second", "(SELECT 'a' AS `_agg_name`, 'x' AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched`) UNION ALL SELECT 'b' AS `_agg_name`, `k` AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched` ORDER BY `_doc_count` DESC LIMIT 5"},
		{"static_cast_bad_double", "SELECT `_id` FROM `es`.`t` WHERE CAST('not_num' AS DOUBLE) > 0"},
		{"static_cast_bad_largeint", "SELECT `_id` FROM `es`.`t` WHERE CAST('2026-01-01' AS LARGEINT) > 0"},
		{"static_cast_bad_bigint", "SELECT `_id` FROM `es`.`t` WHERE CAST('abc' AS BIGINT) = 1"},
		{"static_cast_empty_int", "SELECT `_id` FROM `es`.`t` WHERE CAST('' AS INT) = 0"},
	}
	for _, tc := range badQueries {
		if err := checkStrictNereidsSQLTypesR63Mem(tc.sql); err == nil {
			t.Fatalf("%s: expected checkStrictNereidsSQLTypesR63Mem error for %s", tc.name, tc.sql)
		}
	}

	goodQueries := []string{
		"WITH `base_matched` AS (SELECT *, score() AS `_s` FROM `es`.`t` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (`f__msg` MATCH_ALL 'hello')) SELECT `_id` FROM `base_matched`",
		"(SELECT 'a' AS `_agg_name`, `k` AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched` GROUP BY `k` ORDER BY `_doc_count` DESC LIMIT 5) UNION ALL (SELECT 'b' AS `_agg_name`, 'x' AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched`)",
		"(SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t1` WHERE 1=1) UNION ALL (SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t2` WHERE 1=1) ORDER BY `_score` DESC LIMIT 10",
		"SELECT `_id` FROM `es`.`t` WHERE `f__note` = 'MATCH_ALL(foo) score() ORDER BY' AND TRY_CAST('not_num' AS DOUBLE) IS NULL",
	}
	for _, q := range goodQueries {
		if err := checkStrictNereidsSQLTypesR63Mem(q); err != nil {
			t.Fatalf("expected valid SQL to pass checkStrictNereidsSQLTypesR63Mem, got err=%v for %s", err, q)
		}
	}

	// 2. F4b: MemoryBackend row-level DATA_QUALITY_ERROR for strict CAST vs clean TRY_CAST
	mb := NewMemoryBackend(false)
	if err := mb.ExecDDL(ctx, "CREATE TABLE `es`.`t_strict` (`_id` VARCHAR(64), `_version` BIGINT, `__DORIS_DELETE_SIGN__` TINYINT, `_source` STRING, `_doc` VARIANT, `f__raw` VARCHAR(64), `f__arr` ARRAY<STRING>)"); err != nil {
		t.Fatal(err)
	}
	ndjson := strings.Join([]string{
		`{"_id":"1","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"raw\":\"bad_num\"}","_doc":{"raw":"bad_num"},"f__raw":"bad_num","f__arr":["12.5","oops"]}`,
		`{"_id":"2","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"raw\":null}","_doc":{},"f__raw":null,"f__arr":null}`,
	}, "\n")
	if err := mb.StreamLoad(ctx, "t_strict", []byte(ndjson), true); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_strict` WHERE `__DORIS_DELETE_SIGN__` = 0 AND CAST(`f__raw` AS DOUBLE) > 0 ORDER BY `_score` DESC LIMIT 10 OFFSET 0"); err == nil || !strings.Contains(err.Error(), "DATA_QUALITY_ERROR") {
		t.Fatalf("expected DATA_QUALITY_ERROR on strict row CAST(f__raw AS DOUBLE), got %v", err)
	}
	if _, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_strict` WHERE `__DORIS_DELETE_SIGN__` = 0 AND array_exists(_x -> CAST(_x AS DOUBLE) > 10, `f__arr`) ORDER BY `_score` DESC LIMIT 10 OFFSET 0"); err == nil || !strings.Contains(err.Error(), "DATA_QUALITY_ERROR") {
		t.Fatalf("expected DATA_QUALITY_ERROR on strict array_map CAST(_x AS DOUBLE), got %v", err)
	}
	if hits, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_strict` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (TRY_CAST(`f__raw` AS DOUBLE) IS NULL) ORDER BY `_score` DESC LIMIT 10 OFFSET 0"); err != nil || len(hits) != 2 {
		t.Fatalf("expected TRY_CAST to succeed cleanly returning 2 hits, got hits=%d err=%v", len(hits), err)
	}

	// 3. F6-L2b: mergeSourceWithDocVariantJSON must NOT pollute percolator `query` or dotted keys while merging genuine dynamic _doc keys
	percSrc := json.RawMessage(`{"query":{"term":{"foo.bar":"value"}},"obj.products":["a"],"extra_existing":true}`)
	percDoc := json.RawMessage(`{"query":{"term":{"foo":{"bar":"value"}}},"obj":{"products":["a"],"dyn_added":42},"dyn_top":"ok"}`)
	merged := mergeSourceWithDocVariantJSON(percSrc, percDoc)
	var dec map[string]any
	if err := json.Unmarshal(merged, &dec); err != nil {
		t.Fatalf("unmarshal merged failed: %v", err)
	}
	termObj := dec["query"].(map[string]any)["term"].(map[string]any)
	if _, polluted := termObj["foo"]; polluted || termObj["foo.bar"] != "value" {
		t.Fatalf("expected percolator query term untouched without nested foo injection, got %#v", termObj)
	}
	if _, hasNestedDup := dec["obj"].(map[string]any)["products"]; hasNestedDup {
		t.Fatalf("expected dotted obj.products not duplicated into obj.products, got %#v", dec)
	}
	if dec["obj"].(map[string]any)["dyn_added"] != float64(42) || dec["dyn_top"] != "ok" {
		t.Fatalf("expected genuine dynamic keys merged cleanly, got %#v", dec)
	}
	// Empty percolator `query: {}` must also remain intact
	emptyPercSrc := json.RawMessage(`{"query":{}}`)
	emptyPercDoc := json.RawMessage(`{"query":{"match_all":{}}}`)
	if got := string(mergeSourceWithDocVariantJSON(emptyPercSrc, emptyPercDoc)); got != string(emptyPercSrc) {
		t.Fatalf("expected empty percolator query preserved verbatim, got %s", got)
	}
	// Nested in dst must prevent injecting dotted key from src
	nestedDst := json.RawMessage(`{"a":{"b":1}}`)
	dottedSrc := json.RawMessage(`{"a.b":1}`)
	if got := string(mergeSourceWithDocVariantJSON(nestedDst, dottedSrc)); got != string(nestedDst) {
		t.Fatalf("expected nested path to block duplicate dotted injection, got %s", got)
	}
}

func TestRound65_F27_MemBackend_ColumnFuncsVectorAndAggsCoverage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. round63_membackend.go: evalCastDateTimeV2R63Mem (0% hotspot), evalColumnFuncR63Mem, evalTryCastBodyR63Mem
	row := map[string]any{
		"_id":        "doc-1",
		"_source":    `{"dt":"2026-03-15 12:34:56.789","tags":["a","b"],"s":"abc-123","b64":"aGVsbG8="}`,
		"f__num_str": "42",
		"f__flt_str": "3.25",
		"f__arr_str": `["1.5","2.5"]`,
		"f__nums":    []any{"1.5", "bad", "2.5"},
		"f__b64":     base64.StdEncoding.EncodeToString([]byte("doris-es")),
	}
	for _, dtCase := range []struct {
		expr    string
		wantNil bool
	}{
		{"CAST('2026-03-15T12:34:56.789Z' AS DATETIMEV2(3))", false},
		{"TRY_CAST('2026-03-15' AS DATETIMEV2(6))", false},
		{"CAST('2026-03-15 12:34:56' AS DATETIME)", false},
		{"CAST('1700000000123' AS DATETIMEV2(3))", false},
		{"CAST('not-a-date' AS DATETIMEV2(3))", true},
		{"CAST('   ' AS DATETIMEV2(3))", true},
		{"CAST(`f__missing` AS DATETIMEV2(3))", true},
	} {
		v := resolveColumnValue(row, dtCase.expr)
		if (v == nil) != dtCase.wantNil {
			t.Fatalf("dt %s = %#v (wantNil=%v)", dtCase.expr, v, dtCase.wantNil)
		}
	}

	if v := resolveColumnValue(row, "TRANSLATE('aabbcc', 'ac', 'x')"); v != "xxbb" {
		t.Fatalf("unexpected TRANSLATE result: %#v", v)
	}
	if v := resolveColumnValue(row, "FROM_BASE64_BINARY(`f__b64`)"); !reflect.DeepEqual(v, []byte("doris-es")) {
		t.Fatalf("unexpected FROM_BASE64_BINARY result: %#v", v)
	}
	if v := resolveColumnValue(row, "REGEXP_EXTRACT('abc-123', '([a-z]+)-([0-9]+)', 2)"); v != "123" {
		t.Fatalf("unexpected REGEXP_EXTRACT result: %#v", v)
	}
	if v := resolveColumnValue(row, "TRY_CAST('[1.5, 2.5]' AS ARRAY<STRING>)"); v == nil {
		t.Fatalf("expected JSON array string decode in TRY_CAST(... AS ARRAY<STRING>)")
	}
	if v := resolveColumnValue(row, "TRY_CAST('[1.5, 2.5]' AS DOUBLE)"); v != nil {
		t.Fatalf("expected nil on non-numeric scalar string in TRY_CAST(... AS DOUBLE), got %#v", v)
	}
	if v, ok := resolveColumnValue(row, "TRY_CAST(`f__nums` AS DOUBLE)").([]any); !ok || len(v) != 2 {
		t.Fatalf("expected 2 valid floats from slice TRY_CAST(f__nums AS DOUBLE), got %#v", v)
	}
	if v := resolveColumnValue(row, "TRY_CAST('9223372036854775808' AS LARGEINT)"); v == nil {
		t.Fatalf("expected LARGEINT parse for 2^63")
	}
	if !hasNullScalarCallOperandR64Mem(row, "ROUND(`f__missing`, 2)") || !hasNullScalarCallOperandR64Mem(row, "COALESCE(`f__missing`, NULL)") {
		t.Fatalf("expected hasNullScalarCallOperandR64Mem true on missing ROUND/COALESCE arg")
	}
	if !hasNullArithmeticOperandR63Mem(row, "`f__missing` + 1") {
		t.Fatalf("expected hasNullArithmeticOperandR63Mem true")
	}

	// 2. membackend.go: vector distances, temporal functions, DDL string coercion, QueryTermDocFreqs, DeleteDocsByIDs
	mb := NewMemoryBackend(false)
	_ = mb.ExecDDL(ctx, "CREATE TABLE `es`.`t_vecs` (`_id` VARCHAR(64), `_version` BIGINT, `__DORIS_DELETE_SIGN__` TINYINT, `_source` STRING, `_doc` VARIANT, `f__tag` VARCHAR(64), `f__vec` ARRAY<FLOAT>, `f__ts` BIGINT, `f__w` DOUBLE, `f__val` DOUBLE)")
	_ = mb.StreamLoad(ctx, "t_vecs", []byte(strings.Join([]string{
		`{"_id":"1","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"tag\":\"alpha\",\"ts\":1700000000000}","_doc":{"tag":"alpha","ts":1700000000000},"f__tag":123,"f__vec":[1.0,0.0,0.0],"f__ts":1700000000000,"f__w":2,"f__val":10.0}`,
		`{"_id":"2","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"tag\":\"beta\",\"ts\":1700003600000}","_doc":{"tag":"beta","ts":1700003600000},"f__tag":"beta","f__vec":[0.0,1.0,0.0],"f__ts":1700003600000,"f__w":4,"f__val":20.0}`,
		`{"_id":"3","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"tag\":\"del\"}","_doc":{},"f__tag":"del","f__vec":[0.0,0.0,1.0],"f__ts":1700007200000,"f__w":1,"f__val":30.0}`,
	}, "\n")), true)

	if err := mb.DeleteDocsByIDs(ctx, "es", "t_vecs", []string{"3"}); err != nil {
		t.Fatal(err)
	}
	if total, dfs := mb.QueryTermDocFreqs("t_vecs", "`f__tag`", []string{"123", "beta", "del"}, true); total != 2 || dfs["123"] != 1 || dfs["beta"] != 1 || dfs["del"] != 0 {
		t.Fatalf("unexpected QueryTermDocFreqs: total=%d dfs=%+v", total, dfs)
	}

	if d := computeCosineDistance([]float64{1, 0}, []float64{0, 1}); math.Abs(d-1.0) > 1e-9 {
		t.Fatalf("cosine distance = %v, want 1.0", d)
	}
	if d := computeL2Distance([]float64{1, 2}, []float64{4, 6}); math.Abs(d-5.0) > 1e-9 {
		t.Fatalf("l2 distance = %v, want 5.0", d)
	}
	if ip := computeInnerProduct([]float64{2, 3}, []float64{4, 5}); math.Abs(ip-23.0) > 1e-9 {
		t.Fatalf("inner product = %v, want 23.0", ip)
	}

	vRow := map[string]any{"f__vec": []any{1.0, 2.0}, "f__ts": int64(1700000000)}
	if vec := resolveVectorValue(vRow, "`f__vec`"); !reflect.DeepEqual(vec, []float64{1, 2}) {
		t.Fatalf("resolveVectorValue = %v", vec)
	}
	if s := memEvalFromUnixtime(vRow, "`f__ts`"); s == nil {
		t.Fatalf("memEvalFromUnixtime returned nil")
	}
	if dt := memEvalDateTrunc(map[string]any{"d": "2026-03-15 12:34:56"}, "`d`", "'hour'"); dt == nil {
		t.Fatalf("memEvalDateTrunc returned nil")
	}
	if sAdd := memEvalSecondsAdd(map[string]any{"d": "2026-03-15 12:34:56"}, "`d`", "60"); sAdd == nil {
		t.Fatalf("memEvalSecondsAdd returned nil")
	}
	if tDiff := memEvalTimestampDiff(map[string]any{}, "'SECOND'", "'2026-03-15 12:00:00'", "'2026-03-15 12:01:00'"); tDiff != int64(60) {
		t.Fatalf("memEvalTimestampDiff = %#v, want 60", tDiff)
	}
	if tz := memEvalConvertTZ(map[string]any{"d": "2026-03-15 12:00:00"}, "`d`", "'UTC'", "'America/New_York'"); tz == nil {
		t.Fatalf("memEvalConvertTZ returned nil")
	}

	// Numeric expr & agg branches in MemoryBackend
	if n := evalNumericExpr(row, "CAST(TRY_CAST('3.5' AS DOUBLE) AS DOUBLE)"); math.Abs(n-3.5) > 1e-9 {
		t.Fatalf("evalNumericExpr CAST(TRY_CAST) = %v", n)
	}
	aggs, err := mb.QueryAggs(ctx, "WITH `base_matched` AS (SELECT * FROM `es`.`t_vecs` WHERE `__DORIS_DELETE_SIGN__` = 0)\nSELECT 'mavg' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(SUM(`f__val`) / NULLIF(SUM(CAST(`f__w` AS DOUBLE)), 0), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`")
	if err != nil || len(aggs) != 1 || math.Abs(aggs[0].Value-5.0) > 1e-9 {
		t.Fatalf("expected metric double avg 5.0, got aggs=%+v err=%v", aggs, err)
	}
}

type r65SQLMockSpec struct {
	cols    []string
	rows    [][]driver.Value
	queryEr error
	execEr  error
}

type r65SQLMockDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(kind, query string, args []driver.NamedValue) r65SQLMockSpec
}

var (
	r65SQLDriverOnce sync.Once
	r65SQLDriverInst = &r65SQLMockDriver{
		handlers: make(map[string]func(kind, query string, args []driver.NamedValue) r65SQLMockSpec),
	}
)

func openR65MockDB(t *testing.T, fn func(kind, query string, args []driver.NamedValue) r65SQLMockSpec) *sql.DB {
	t.Helper()
	r65SQLDriverOnce.Do(func() {
		sql.Register("round65_sqlbackend_mock", r65SQLDriverInst)
	})
	dsn := fmt.Sprintf("%s_%d", t.Name(), time.Now().UnixNano())
	r65SQLDriverInst.mu.Lock()
	r65SQLDriverInst.handlers[dsn] = fn
	r65SQLDriverInst.mu.Unlock()
	t.Cleanup(func() {
		r65SQLDriverInst.mu.Lock()
		delete(r65SQLDriverInst.handlers, dsn)
		r65SQLDriverInst.mu.Unlock()
	})
	db, err := sql.Open("round65_sqlbackend_mock", dsn)
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (d *r65SQLMockDriver) Open(name string) (driver.Conn, error) {
	return &r65SQLMockConn{dsn: name, drv: d}, nil
}

type r65SQLMockConn struct {
	dsn string
	drv *r65SQLMockDriver
}

func (c *r65SQLMockConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *r65SQLMockConn) Close() error                        { return nil }
func (c *r65SQLMockConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c *r65SQLMockConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("missing mock SQL handler")
	}
	res := fn("exec", query, args)
	if res.execEr != nil {
		return nil, res.execEr
	}
	return driver.RowsAffected(1), nil
}

func (c *r65SQLMockConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("missing mock SQL handler")
	}
	res := fn("query", query, args)
	if res.queryEr != nil {
		return nil, res.queryEr
	}
	return &r65SQLMockRows{cols: res.cols, rows: res.rows}, nil
}

type r65SQLMockRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *r65SQLMockRows) Columns() []string { return r.cols }
func (r *r65SQLMockRows) Close() error      { return nil }
func (r *r65SQLMockRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	r.idx++
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		} else {
			dest[i] = nil
		}
	}
	return nil
}

func TestRound65_F27_SQLBackend_DeleteCatalogNormalizeAndTelemetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. ApplyDSNAuth + stripRawDSNMultiStatements (including malformed unparseable raw DSN)
	if got := ApplyDSNAuth("not::a::dsn?multiStatements=true&charset=utf8mb4", "u", "p"); strings.Contains(got, "multiStatements") || !strings.Contains(got, "charset=utf8mb4") {
		t.Fatalf("expected raw unparseable DSN multiStatements stripped, got %q", got)
	}
	if got := ApplyDSNAuth("root:$(DORIS_PASSWORD)@tcp(127.0.0.1:9030)/es?multiStatements=true", "es_user", "secret_pw"); !strings.Contains(got, "es_user:secret_pw@") || strings.Contains(got, "multiStatements=true") || !strings.Contains(got, "time_zone=") {
		t.Fatalf("unexpected ApplyDSNAuth output: %q", got)
	}

	// 2. stripOuterSQLParensR64 (F27-W5 6.4% hotspot)
	for _, tc := range []struct {
		in, want string
	}{
		{"(((`f__arr`)))", "`f__arr`"},
		{"('hello (world)')", "'hello (world)'"},
		{"(SELECT 1) UNION (SELECT 2)", "(SELECT 1) UNION (SELECT 2)"},
		{"((`col``name`))", "`col``name`"},
	} {
		if got := stripOuterSQLParensR64(tc.in); got != tc.want {
			t.Fatalf("stripOuterSQLParensR64(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// 3. detectDorisArrayFallbackType / detectDorisLambdaCastArrayType / NormalizeDorisSQL
	for _, expr := range []string{
		"SELECT * FROM t WHERE array_exists(_x -> CAST(_x AS LARGEINT) > 10, `f__nums`)",
		"SELECT * FROM t WHERE array_exists(( _x ) -> TRY_CAST(_x AS DOUBLE) > 1.5, `f__floats`)",
		"SELECT * FROM t WHERE array_exists(_x -> CAST(_x AS BOOLEAN) = true, `f__flags`)",
		"SELECT * FROM t WHERE array_exists(_x -> CAST(_x AS DATETIMEV2(3)) > '2026-01-01', `f__dates`)",
		"SELECT * FROM t WHERE array_exists(_x -> lower(_x) = 'ok', `f__kws`)",
	} {
		norm := NormalizeDorisSQL(expr)
		if !strings.Contains(norm, "CAST([] AS ARRAY<") {
			t.Fatalf("NormalizeDorisSQL(%s) = %s missing typed empty array fallback", expr, norm)
		}
	}
	for raw, want := range map[string]string{
		"FLOAT":      "ARRAY<FLOAT>",
		"DOUBLE":     "ARRAY<DOUBLE>",
		"BIGINT":     "ARRAY<BIGINT>",
		"LARGEINT":   "ARRAY<LARGEINT>",
		"INT":        "ARRAY<INT>",
		"BOOLEAN":    "ARRAY<BOOLEAN>",
		"DATETIME":   "ARRAY<DATETIME>",
		"DATETIMEV2": "ARRAY<DATETIMEV2>",
		"STRING":     "ARRAY<STRING>",
		"UNKNOWN_T":  "",
	} {
		arrT, ok := mapSQLScalarTypeToDorisArrayR64(raw)
		if (ok && arrT != want) || (!ok && want != "") {
			t.Fatalf("mapSQLScalarTypeToDorisArrayR64(%q) = (%q,%v), want %q", raw, arrT, ok, want)
		}
	}

	// 4. ParseDorisCapacityBytes & ParseDorisPercent
	for raw, want := range map[string]int64{
		"":         0,
		"N/A":      0,
		"-10":      0,
		"1048576":  1048576,
		"4.000KB":  4096,
		"2.00 MB":  2 * 1024 * 1024,
		"1.5 GB":   int64(1.5 * 1024 * 1024 * 1024),
		"1 TB":     1024 * 1024 * 1024 * 1024,
		"1 PiB":    1024 * 1024 * 1024 * 1024 * 1024,
		"bad UNIT": 0,
	} {
		if got := ParseDorisCapacityBytes(raw); got != want {
			t.Fatalf("ParseDorisCapacityBytes(%q) = %d, want %d", raw, got, want)
		}
	}
	if p := ParseDorisPercent("12.34 %"); math.Abs(p-12.34) > 1e-6 {
		t.Fatalf("ParseDorisPercent = %v", p)
	}
	if p := ParseDorisPercent("-5%"); p != 0 {
		t.Fatalf("expected negative percent 0, got %v", p)
	}

	// 5. DeleteDocsByIDs (F27-W5 0% hotspot), InitCatalog, Upsert/Delete/Load Catalog, ExecDDL, ShowDataTelemetry, CollectClusterTelemetry, QueryAggs
	var execQueries []string
	var execArgs [][]driver.NamedValue
	var mu sync.Mutex
	failNextExec := atomic.Bool{}
	db := openR65MockDB(t, func(kind, query string, args []driver.NamedValue) r65SQLMockSpec {
		if kind == "exec" {
			mu.Lock()
			execQueries = append(execQueries, query)
			execArgs = append(execArgs, args)
			mu.Unlock()
			if failNextExec.Swap(false) {
				return r65SQLMockSpec{execEr: errors.New("simulated doris exec error")}
			}
			return r65SQLMockSpec{}
		}
		switch {
		case strings.Contains(query, "FROM `es_db`.`_es_catalog`"):
			return r65SQLMockSpec{
				cols: []string{"entity_type", "entity_key", "payload_json", "updated_epoch_ms"},
				rows: [][]driver.Value{{"index", "orders", `{"properties":{"k":{"type":"keyword"}}}`, int64(42)}},
			}
		case strings.Contains(query, "SHOW BACKENDS"):
			return r65SQLMockSpec{
				cols: []string{"BackendId", "Host", "HttpPort", "Alive", "TabletNum", "DataUsedCapacity", "TrashUsedCapacity", "AvailCapacity", "TotalCapacity", "UsedPct", "CpuCores", "MemLimit", "Version"},
				rows: [][]driver.Value{
					{"1", "10.0.0.1", "8040", "true", "16", "1.00 GB", "0.00 B", "9.00 GB", "10.00 GB", "10.00%", "8", "16.00 GB", "4.1.3"},
				},
			}
		case strings.Contains(query, "SHOW DATA FROM"):
			return r65SQLMockSpec{
				cols: []string{"TableName", "Size", "ReplicaCount", "RowCount", "RemoteSize"},
				rows: [][]driver.Value{
					{"orders", "2.00 MB", "1", "100", "0.00 B"},
					{"Total", "2.00 MB", "1", "100", "0.00 B"},
				},
			}
		case strings.Contains(query, "AS `_agg_name`"):
			return r65SQLMockSpec{
				cols: []string{"_agg_name", "_bucket_key", "_doc_count"},
				rows: [][]driver.Value{
					{"total_hits", "_metric", float64(7)},
					{"by_tag", "a", float64(3)},
				},
			}
		default:
			// Test hitsRowScan7RoutingAndRawDoc with percolator dotted query preservation!
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_routing", "_raw_doc", "_score", "_total_hits"},
				rows: [][]driver.Value{
					{"p-1", int64(2), `{"query":{"term":{"foo.bar":"value"}}}`, "r1", `{"query":{"term":{"foo":{"bar":"value"}}},"dyn":true}`, nil, int64(1)},
				},
			}
		}
	})

	b := NewDorisSQLBackend(db, nil)
	b.SetLogSQL(true)
	if err := b.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.StreamLoad(ctx, "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatal(err)
	}
	if err := b.ExecDDL(ctx, "CREATE TABLE `es_db`.`orders` (`_id` VARCHAR(64))"); err != nil {
		t.Fatal(err)
	}
	if err := b.InitCatalog(ctx, "es_db"); err != nil {
		t.Fatal(err)
	}
	if err := b.UpsertCatalogEntry(ctx, "es_db", CatalogEntry{EntityType: "index", EntityKey: "orders", PayloadJSON: `{}`, UpdatedEpochMs: 1}); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteCatalogEntry(ctx, "es_db", "index", "orders"); err != nil {
		t.Fatal(err)
	}
	entries, err := b.LoadCatalogEntries(ctx, "es_db")
	if err != nil || len(entries) != 1 || entries[0].EntityKey != "orders" {
		t.Fatalf("LoadCatalogEntries = (%+v, %v)", entries, err)
	}

	// Single DeleteDocsByIDs + multi-chunk DeleteDocsByIDs (>256 IDs -> 3 batched IN queries) + error propagation
	if err := b.DeleteDocsByIDs(ctx, "es_db", "orders", nil); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteDocsByIDs(ctx, "es_db", "orders", []string{"only-one"}); err != nil {
		t.Fatal(err)
	}
	manyIDs := make([]string, 520)
	for i := range manyIDs {
		manyIDs[i] = "id-" + strconv.Itoa(i)
	}
	if err := b.DeleteDocsByIDs(ctx, "es_db", "orders", manyIDs); err != nil {
		t.Fatal(err)
	}
	failNextExec.Store(true)
	if err := b.DeleteDocsByIDs(ctx, "es_db", "orders", []string{"fail-id"}); err == nil {
		t.Fatalf("expected DeleteDocsByIDs error propagation")
	}

	mu.Lock()
	execCount := len(execQueries)
	mu.Unlock()
	if execCount < 8 {
		t.Fatalf("expected DDL/catalog/chunked DeleteDocsByIDs exec statements >= 8, got %d", execCount)
	}

	// QueryHits layout hitsRowScan7RoutingAndRawDoc + nullScore NaN + percolator merge exclusion
	hits, err := b.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_db`.`orders` WHERE 1=1 ORDER BY `_score` DESC LIMIT 10 OFFSET 0")
	if err != nil || len(hits) != 1 || !math.IsNaN(hits[0].Score) || !strings.Contains(string(hits[0].RawSource), `"dyn":true`) || strings.Contains(string(hits[0].RawSource), `"foo":{"bar"`) {
		t.Fatalf("unexpected QueryHits result: hits=%+v rawSrc=%s err=%v", hits, string(hits[0].RawSource), err)
	}

	aggRows, err := b.QueryAggs(ctx, "SELECT 'total_hits' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(7 AS DOUBLE) AS `_doc_count`")
	if err != nil || len(aggRows) != 2 || aggRows[0].Value != 7 || aggRows[1].DocCount != 3 {
		t.Fatalf("unexpected QueryAggs result: rows=%+v err=%v", aggRows, err)
	}

	tel := b.CollectClusterTelemetry(ctx, "es_db")
	if tel == nil || tel.TotalNodes != 1 || tel.AliveNodes != 1 || tel.Tables["orders"].RowCount != 100 {
		t.Fatalf("unexpected CollectClusterTelemetry: %+v", tel)
	}

	// Nil-db graceful behavior coverage
	nilB := NewDorisSQLBackend(nil, nil)
	_ = nilB.Ping(ctx)
	_ = nilB.ExecDDL(ctx, "DDL")
	_ = nilB.InitCatalog(ctx, "es_db")
	_ = nilB.UpsertCatalogEntry(ctx, "es_db", CatalogEntry{})
	_ = nilB.DeleteCatalogEntry(ctx, "es_db", "index", "k")
	_, _ = nilB.LoadCatalogEntries(ctx, "es_db")
	_ = nilB.DeleteDocsByIDs(ctx, "es_db", "t", []string{"1"})
	_, _ = nilB.ShowBackendsTelemetry(ctx)
	_, _ = nilB.ShowDataTelemetry(ctx, "es_db")
	_ = nilB.CollectClusterTelemetry(ctx, "es_db")
}

func intPtr(v int) *int {
	return &v
}

func TestRound65_F27_Spatial_DeepCoveragePart2(t *testing.T) {
	t.Parallel()

	// 1. UTF-16 offset conversion (surrogate pairs) + runtimeFieldTypeToEmitContextR64 + vwhMergeHeapR64
	s := "a😀b"
	u16Map := utf16OffsetsToByteOffsetsR64(s)
	if len(u16Map) != 5 {
		t.Fatalf("expected 5 UTF-16 entries for 'a😀b', got %d", len(u16Map))
	}
	if bStart, bEnd, ok := resolveUTF16HighlightSpanBytesR64(u16Map, 1, 3); !ok || s[bStart:bEnd] != "😀" {
		t.Fatalf("unexpected UTF-16 surrogate highlight slice: (%d,%d,%v)", bStart, bEnd, ok)
	}
	if _, _, ok := resolveUTF16HighlightSpanBytesR64(u16Map, -1, 100); ok {
		t.Fatalf("expected invalid UTF-16 span to return false")
	}
	if ctxName, ok := runtimeFieldTypeToEmitContextR64("geo_point"); !ok || ctxName != "geo_point_field" {
		t.Fatalf("unexpected runtimeFieldTypeToEmitContextR64 geo_point: %q %v", ctxName, ok)
	}
	if _, ok := runtimeFieldTypeToEmitContextR64("unknown_x"); ok {
		t.Fatalf("expected false for unknown runtime field type")
	}
	h := &vwhMergeHeapR64{
		{left: 1, right: 2, leftVer: 1, rightVer: 1, dist: 5.0, leftPos: 2},
		{left: 0, right: 1, leftVer: 1, rightVer: 1, dist: 2.0, leftPos: 1},
	}
	heap.Init(h)
	heap.Push(h, vwhMergeCandidateR64{left: 2, right: 3, dist: 1.0, leftPos: 0})
	first := heap.Pop(h).(vwhMergeCandidateR64)
	if first.dist != 1.0 {
		t.Fatalf("expected min-heap pop dist=1.0, got %+v", first)
	}

	// 2. ILM duration & policy validation & index ILM explain entry
	for raw, allowCal := range map[string]bool{
		"150ms": true, "30s": true, "5m": true, "2h": true, "3d": true, "1M": true, "1w": false, "1q": false, "1y": false,
	} {
		ms, err := parseILMDurationMillisR64(raw, allowCal)
		if allowCal && (err != nil || ms <= 0) {
			t.Fatalf("parseILMDurationMillisR64(%q) failed: ms=%v err=%v", raw, ms, err)
		}
		if !allowCal && err == nil {
			t.Fatalf("expected calendar duration %q rejected when allowCalendar=false", raw)
		}
	}
	if _, err := parseILMDurationMillisR64("-5d", true); err == nil {
		t.Fatalf("expected negative ILM duration rejected")
	}
	validPol := map[string]any{
		"phases": map[string]any{
			"hot": map[string]any{
				"min_age": "0ms",
				"actions": map[string]any{
					"rollover": map[string]any{"max_age": "7d", "max_primary_shard_size": "50gb"},
				},
			},
			"warm": map[string]any{
				"min_age": "7d",
				"actions": map[string]any{
					"forcemerge": map[string]any{"max_num_segments": 1},
					"shrink":     map[string]any{"number_of_shards": 1},
					"readonly":   map[string]any{},
				},
			},
			"cold": map[string]any{
				"min_age": "30d",
				"actions": map[string]any{
					"searchable_snapshot": map[string]any{"snapshot_repository": "my_repo"},
				},
			},
			"delete": map[string]any{
				"min_age": "90d",
				"actions": map[string]any{"delete": map[string]any{}},
			},
		},
	}
	if msg, ok := validateILMPolicyBodyR64(validPol); !ok {
		t.Fatalf("expected valid ILM policy accepted, got %s", msg)
	}
	if _, ok := validateILMPolicyBodyR64(map[string]any{"phases": map[string]any{"bogus_phase": map[string]any{}}}); ok {
		t.Fatalf("expected unknown ILM phase rejected")
	}
	if !hasMultiWildcardPatternListR64("a*,b*") || hasMultiWildcardPatternListR64("single") {
		t.Fatalf("unexpected hasMultiWildcardPatternListR64 behavior")
	}
	idxEntry, managed, errPol := buildILMExplainIndexEntryR64(
		"logs-000001",
		map[string]any{"index.lifecycle.name": "my_pol", "index.lifecycle.rollover_alias": "logs"},
		map[string]any{"name": "logs_ds"},
		nil,
		map[string]map[string]any{"my_pol": validPol},
	)
	if !managed || errPol || idxEntry["policy"] != "my_pol" {
		t.Fatalf("unexpected buildILMExplainIndexEntryR64 result: entry=%+v managed=%v err=%v", idxEntry, managed, errPol)
	}
	unmanaged, managed2, _ := buildILMExplainIndexEntryR64("plain", map[string]any{}, nil, nil, nil)
	if managed2 || unmanaged["managed"] != false {
		t.Fatalf("expected unmanaged ILM entry, got %+v", unmanaged)
	}

	// 3. Multi-geometry normalization, WKT roundtrip, holes, distance, containment
	geoInputs := []any{
		map[string]any{"type": "MultiPoint", "coordinates": []any{[]any{1.0, 2.0}, []any{3.0, 4.0}}},
		map[string]any{"type": "MultiLineString", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{1.0, 1.0}}, []any{[]any{2.0, 2.0}, []any{3.0, 3.0}}}},
		map[string]any{"type": "MultiPolygon", "coordinates": []any{[]any{[]any{[]any{0.0, 0.0}, []any{10.0, 0.0}, []any{10.0, 10.0}, []any{0.0, 10.0}, []any{0.0, 0.0}}, []any{[]any{2.0, 2.0}, []any{4.0, 2.0}, []any{4.0, 4.0}, []any{2.0, 4.0}, []any{2.0, 2.0}}}}},
		map[string]any{"type": "GeometryCollection", "geometries": []any{map[string]any{"type": "Point", "coordinates": []any{5.0, 5.0}}}},
		map[string]any{"type": "circle", "coordinates": []any{2.35, 48.85}, "radius": "500m"},
		"BBOX (-10, 10, 20, -5)",
	}
	for _, gi := range geoInputs {
		if norm, ok := normalizeGeoShapeValueToGeoJSONR64(gi, false); !ok || norm == nil {
			t.Fatalf("expected normalizeGeoShapeValueToGeoJSONR64 success for %#v", gi)
		}
	}
	wktVals := formatGeoShapeValuesForFieldsR64(geoInputs[:4], true)
	if len(wktVals) != 1 || !strings.Contains(fmt.Sprintf("%v", wktVals[0]), "GEOMETRYCOLLECTION") {
		t.Fatalf("expected 1 formatted WKT GEOMETRYCOLLECTION value, got %+v", wktVals)
	}
	if gjVals := formatGeoShapeValuesForFieldsR64(geoInputs[:4], false); len(gjVals) != 4 {
		t.Fatalf("expected 4 normalized GeoJSON values, got %d", len(gjVals))
	}
	polyWithHole := parsedGeomR64{
		kind:  geomPolygonR64,
		outer: [][2]float64{{0, 0}, {0, 10}, {10, 10}, {10, 0}, {0, 0}},
		holes: [][][2]float64{{{2, 2}, {2, 4}, {4, 4}, {4, 2}, {2, 2}}},
	}
	if polyWithHole.dim() != 2 || !strings.Contains(polyWithHole.toWKT(), "POLYGON") || len(polyWithHole.vertices()) < 5 {
		t.Fatalf("unexpected polyWithHole methods")
	}
	ptInHole := parsedGeomR64{kind: geomPointR64, pt: [2]float64{3, 3}}
	if geomIntersectsQueryShapeR64(ptInHole, polyWithHole) {
		t.Fatalf("point inside hole must NOT intersect polygon")
	}
	ptInsideRing := parsedGeomR64{kind: geomPointR64, pt: [2]float64{8, 8}}
	if !geomIntersectsQueryShapeR64(ptInsideRing, polyWithHole) {
		t.Fatalf("point inside polygon ring must intersect")
	}
	lineGeom := parsedGeomR64{kind: geomLineR64, line: [][2]float64{{-1, 5}, {11, 5}}}
	if !geomIntersectsQueryShapeR64(lineGeom, polyWithHole) {
		t.Fatalf("crossing line must intersect polygon")
	}
	if !geomBoxContainsGeomR64(parsedGeomR64{kind: geomEnvelopeR64, topLat: 9, leftLon: 1, botLat: 1, rightLon: 9}, 10, 0, 0, 10) {
		t.Fatalf("expected outer box contains inner envelope")
	}
	if d := minDistanceMetersFromGeomR64(lineGeom, 7.0, 9.0); d <= 0 {
		t.Fatalf("expected positive distance from off-line point to line, got %v", d)
	}
	if d := minDistanceMetersFromGeomR64(parsedGeomR64{kind: geomEnvelopeR64, topLat: 2, leftLon: 2, botLat: 0, rightLon: 0}, 5, 5); d <= 0 {
		t.Fatalf("expected positive distance from outside point to envelope, got %v", d)
	}

	// 4. TimeSeries aggs & validation, Multi-index & unindexed spatial queries, fallback evaluator
	var tsSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties":{
			"k8s.pod":{"type":"keyword","time_series_dimension":true},
			"@timestamp":{"type":"date"},
			"cpu":{"type":"double","time_series_metric":"gauge"},
			"raw_only":{"type":"keyword","index":false,"doc_values":false},
			"loc":{"type":"geo_point"}
		}
	}`), &tsSpec)
	tsIdx := schema.CompileIndexSchema("es_db", "metrics-1", &tsSpec)
	tsDocs := []runtimeMatchedDoc{
		{hit: HitRow{ID: "m1", Index: "metrics-1"}, doc: map[string]any{"k8s": map[string]any{"pod": "p1"}, "@timestamp": int64(1700000000000), "cpu": 0.4, "loc": map[string]any{"lat": 10.0, "lon": 20.0}}},
		{hit: HitRow{ID: "m2", Index: "metrics-1"}, doc: map[string]any{"k8s": map[string]any{"pod": "p2"}, "@timestamp": int64(1700000060000), "cpu": 0.8, "loc": map[string]any{"lat": 11.0, "lon": 21.0}}},
	}
	tsAggSpec := esast.AggSpec{
		TimeSeries: &esast.TimeSeriesAggSpec{Size: intPtr(10)},
		Aggs: map[string]esast.AggSpec{
			"ts_dh": {
				DateHistogram: &esast.DateHistogramAggSpec{Field: "@timestamp", CalendarInterval: "1h"},
				Aggs: map[string]esast.AggSpec{
					"avg_cpu": {Avg: &esast.MetricAggSpec{Field: "cpu"}},
				},
			},
		},
	}
	var tsRows []AggRow
	emitRuntimeTimeSeriesAggRowsR64("ts", "", tsAggSpec, tsDocs, &tsRows, tsIdx)
	if len(tsRows) == 0 {
		t.Fatalf("expected time_series agg rows emitted")
	}
	keyStr, dims := extractTimeSeriesDimsForDocR64(tsDocs[0], tsIdx)
	if keyStr == "" || dims["k8s.pod"] != "p1" || formatTimeSeriesJavaKeyR64(dims) == "" {
		t.Fatalf("unexpected time_series dims: key=%q dims=%+v", keyStr, dims)
	}
	// GeoLine invalid sort field under time_series + invalid grid precisions
	if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{
		"outer": {TimeSeries: &esast.TimeSeriesAggSpec{}, Aggs: map[string]esast.AggSpec{
			"inner": {GeoLine: &esast.GeoLineAggSpec{Point: esast.GeoLinePointSpec{Field: "loc"}, Sort: &esast.GeoLinePointSpec{Field: "bad_sort"}}},
		}},
	}, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on geo_line non-@timestamp sort under time_series, got %d", st)
	}
	if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{
		"bad_tile": {GeotileGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(31)}},
	}, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on geotile zoom=31, got %d", st)
	}
	if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{
		"bad_hash": {GeohashGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: intPtr(13)}},
	}, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on geohash precision=13, got %d", st)
	}

	schemasMap := map[string]*schema.IndexSchema{"metrics-1": tsIdx}
	qUnindexed := &esast.Query{Bool: &esast.BoolQuery{
		Should: []esast.Query{{Term: map[string]esast.TermEntry{"raw_only": {Value: "v"}}}},
	}}
	if !queryUsesUnindexedFieldR64(qUnindexed, schemasMap, tsIdx) {
		t.Fatalf("expected queryUsesUnindexedFieldR64 true for unindexed raw_only")
	}
	qNested := &esast.Query{
		Bool: &esast.BoolQuery{
			Filter: []esast.Query{{
				ConstantScore: &esast.ConstantScoreQuery{
					Filter: esast.Query{GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "loc", Top: 12, Left: 19, Bottom: 9, Right: 22}},
				},
			}},
		},
	}
	if queryNeedsRuntimeSpatialEvalR64(qNested, tsIdx) {
		t.Fatalf("expected geo_bounding_box on indexed geo_point to not require runtime spatial eval")
	}
	if !queryNeedsRuntimeSpatialEvalR64(&esast.Query{GeoShape: &esast.GeoShapeQuery{Field: "loc"}}, tsIdx) {
		t.Fatalf("expected queryNeedsRuntimeSpatialEvalR64 true for geo_shape")
	}
	if !evalDocWithSpatialFallbackR64(tsIdx, tsDocs[0].doc, qNested) {
		t.Fatalf("expected evalDocWithSpatialFallbackR64 match for m1")
	}
	if evalDocWithSpatialFallbackR64(tsIdx, tsDocs[0].doc, &esast.Query{Bool: &esast.BoolQuery{MustNot: []esast.Query{*qNested}}}) {
		t.Fatalf("expected must_not spatial fallback false")
	}

	zeroAggs := map[string]esast.AggSpec{
		"by_idx": {Terms: &esast.TermsAggSpec{Field: "_index", MinDocCount: intPtr(0)}},
		"gb":     {GeoBounds: &esast.GeoBoundsAggSpec{Field: "loc"}},
	}
	if !aggsHaveIndexTermsMinDocCountZeroR64(zeroAggs) {
		t.Fatalf("expected aggsHaveIndexTermsMinDocCountZeroR64 true")
	}
	injected := injectZeroIndexTermsAggRowsR64("", zeroAggs, []string{"metrics-1", "metrics-2"}, map[string]bool{"metrics-1": true, "metrics-2": true}, []AggRow{{AggName: "by_idx", BucketKey: "metrics-1", DocCount: 2}})
	if len(injected) != 2 {
		t.Fatalf("expected zero _index bucket injected for metrics-2, got %+v", injected)
	}
	hits := []HitRow{{ID: "m1", Index: "metrics-1", Source: json.RawMessage(`{"loc":{"lat":10,"lon":20}}`)}}
	recomp := recomputeMultiIndexSpatialAggsR64(zeroAggs, hits, schemasMap, tsIdx, injected)
	if len(recomp) < 3 {
		t.Fatalf("expected recomputeMultiIndexSpatialAggsR64 to append gb agg row, got %+v", recomp)
	}
}

func TestRound65_F27_Round63MemBackend_DeepCoveragePart2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	row := map[string]any{
		"_id":      "1",
		"_source":  `{"nested":{"n":7,"arr":["x","y"],"ok":true},"tags":["go","doris"],"body":"Quick brown fox jumps quick"}`,
		"_doc":     `{"nested":{"n":7,"arr":["x","y"],"ok":true}}`,
		"f__num":   int64(7),
		"f__flt":   2.5,
		"f__body":  "Quick brown fox jumps quick",
		"f__tags":  []any{"go", "doris"},
		"f__title": "quick fox",
	}

	// 1. evalBitwiseAndStrictR63Mem + evalNumericExpr bitwise `&`
	if v := evalNumericExpr(row, "`f__num` & 3"); v != 3.0 {
		t.Fatalf("7 & 3 = %v, want 3", v)
	}
	if v := evalNumericExpr(map[string]any{"x": "bad"}, "`x` & 1"); !math.IsNaN(v) {
		t.Fatalf("expected NaN on string bitwise AND, got %v", v)
	}

	// 2. evalDorisJSONTypeTwoArgR63Mem + evalColumnFuncR63Mem (JSON_TYPE, BIT_LENGTH, CARDINALITY)
	for path, want := range map[string]any{
		"$.nested":     "OBJECT",
		"$.nested.arr": "ARRAY",
		"$.nested.n":   "INTEGER",
		"$.nested.ok":  "BOOLEAN",
		"$.missing":    nil,
	} {
		got := evalDorisJSONTypeTwoArgR63Mem(row, "`_doc`", "'"+path+"'")
		if got != want {
			t.Fatalf("JSON_TYPE(%s) = %#v, want %#v", path, got, want)
		}
	}
	if bl := resolveColumnValue(row, "OCTET_LENGTH(`f__title`)"); bl != int64(len("quick fox")) {
		t.Fatalf("unexpected OCTET_LENGTH: %#v", bl)
	}
	if blNull := resolveColumnValue(row, "OCTET_LENGTH(`f__missing`)"); blNull != nil {
		t.Fatalf("expected nil OCTET_LENGTH on missing col, got %#v", blNull)
	}
	if aj := resolveColumnValue(row, "ARRAY_JOIN(`f__tags`, ',')"); aj != "go,doris" {
		t.Fatalf("unexpected ARRAY_JOIN: %#v", aj)
	}
	if tr := resolveColumnValue(row, "TRUNCATE(3.789, 1)"); tr != 3.7 {
		t.Fatalf("unexpected TRUNCATE: %#v", tr)
	}
	if rr := resolveColumnValue(row, "REGEXP_REPLACE('foo-123', '[0-9]+', 'X')"); rr != "foo-X" {
		t.Fatalf("unexpected REGEXP_REPLACE: %#v", rr)
	}

	// 3. evalTryCastBodyR63Mem scalars & slices
	for expr, want := range map[string]any{
		"TRY_CAST('42' AS BIGINT)":         int64(42),
		"TRY_CAST('2026-01-01' AS BIGINT)": nil,
		"TRY_CAST('true' AS BOOLEAN)":      true,
		"TRY_CAST('false' AS BOOLEAN)":     false,
		"TRY_CAST('bad_bool' AS BOOLEAN)":  nil,
		"TRY_CAST(123 AS STRING)":          "123",
	} {
		got := resolveColumnValue(row, expr)
		if got != want {
			t.Fatalf("%s = %#v, want %#v", expr, got, want)
		}
	}

	// 4. BM25 prepareScoreEvaluatorR63Mem + prepareScoreEvaluatorFromRowSliceR63Mem
	bm25Expr := "(CASE WHEN `f__body` MATCH_ALL 'quick' THEN 2.0 * (GREATEST(CAST(CHAR_LENGTH(CONCAT(' ', REGEXP_REPLACE(LOWER(COALESCE(CAST(`f__body` AS STRING), '')), '[^[:alnum:]_]+', '  '), ' ')) - CHAR_LENGTH(REPLACE(CONCAT(' ', REGEXP_REPLACE(LOWER(COALESCE(CAST(`f__body` AS STRING), '')), '[^[:alnum:]_]+', '  '), ' '), '  quick  ', '')) AS DOUBLE) / 9.0, 0.0) * (1.2 + 1.0)) / (GREATEST(0.0, 1.0) + 1.2 * (1.0 - 0.75 + 0.75 * 1.0)) ELSE 0.0 END)"
	tbl := map[string]map[string]any{
		"1": row,
		"2": {"_id": "2", "__DORIS_DELETE_SIGN__": int64(0), "f__body": "slow turtle only"},
	}
	scoreFn := prepareScoreEvaluatorR63Mem(ctx, tbl, bm25Expr)
	if s1, s2 := scoreFn(row), scoreFn(tbl["2"]); s1 <= 0 || s2 != 0 {
		t.Fatalf("expected BM25 s1>0 and s2==0, got s1=%v s2=%v", s1, s2)
	}
	sliceFn := prepareScoreEvaluatorFromRowSliceR63Mem([]map[string]any{row, tbl["2"]}, bm25Expr)
	if sliceFn(row) <= 0 {
		t.Fatalf("expected positive BM25 score from row slice evaluator")
	}

	// 5. evalRound63AggBranchR63Mem: sub weighted metric_double + counted_terms top & sub
	baseRows := []map[string]any{
		{"_id": "1", "f__cat": "ops", "f__sum": 30.0, "f__cnt": int64(3), "f__ck": []any{"err", "warn"}},
		{"_id": "2", "f__cat": "ops", "f__sum": 10.0, "f__cnt": int64(1), "f__ck": []any{"err"}},
	}
	subRows, okSub := evalRound63AggBranchR63Mem(baseRows, "SELECT 'avg_lat' AS `_agg_name`, COALESCE(CAST(`f__cat` AS STRING), '') AS `_bucket_key`, CAST(COALESCE(SUM(`f__sum`) / NULLIF(SUM(CAST(`f__cnt` AS DOUBLE)), 0), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__cat` IS NOT NULL GROUP BY `_bucket_key`", func(r []AggRow) []AggRow { return r })
	if !okSub || len(subRows) != 1 || math.Abs(subRows[0].Value-10.0) > 1e-9 {
		t.Fatalf("unexpected reR63AggMetricDoubleAvgSub: ok=%v rows=%+v", okSub, subRows)
	}
	ckTop, okTop := evalRound63AggBranchR63Mem(baseRows, "SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (SELECT 'ck' AS `_agg_name`, CAST(`_elem` AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__ck`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5) `_agg_sub_1`", func(r []AggRow) []AggRow { return r })
	if !okTop || len(ckTop) != 2 {
		t.Fatalf("unexpected reR63CountedTermsExprTop: ok=%v rows=%+v", okTop, ckTop)
	}
	ckSub, okCkSub := evalRound63AggBranchR63Mem(baseRows, "SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (SELECT 'ck_sub' AS `_agg_name`, CONCAT_WS('\\x1f', CAST(COALESCE(CAST(`f__cat` AS STRING), '') AS STRING), CAST(`_sub_elem_1` AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__ck`) `_sub_t_1` AS `_sub_elem_1` WHERE (`f__cat` IS NOT NULL) AND `_sub_elem_1` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5) `_agg_sub_2`", func(r []AggRow) []AggRow { return r })
	if !okCkSub || len(ckSub) != 2 {
		t.Fatalf("unexpected reR63CountedTermsExprSub: ok=%v rows=%+v", okCkSub, ckSub)
	}
}

func TestRound65_F27_MemBackend_DeepCoveragePart2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mb := NewMemoryBackend(false)
	_ = mb.ExecDDL(ctx, "CREATE TABLE `es`.`t_deep` (`_id` VARCHAR(64), `_version` BIGINT, `__DORIS_DELETE_SIGN__` TINYINT, `_source` STRING, `_doc` VARIANT, `f__cat` VARCHAR(64), `f__price` DOUBLE, `f__qty` BIGINT, `f__tags` ARRAY<STRING>, `f__body` VARCHAR(256), `f__ts` BIGINT, `f__vec` ARRAY<FLOAT>, `f__nested` ARRAY<STRING>, `f__tsid` VARCHAR(64), `__tsid` VARCHAR(64))")
	ndjson := strings.Join([]string{
		`{"_id":"1","_version":2,"__DORIS_DELETE_SIGN__":0,"_source":"{\"cat\":\"books\",\"price\":10,\"tags\":[\"go\",\"db\"]}","_doc":{"cat":"books","price":10,"nested":{"x":"v1"}},"f__cat":"books","f__price":10.0,"f__qty":2,"f__tags":["go","db"],"f__body":"fast search engine","f__ts":1700000000000,"f__vec":[1.0,0.0],"f__nested":["{\"name\":\"n1\",\"val\":5}"],"__tsid":"ts1"}`,
		`{"_id":"2","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"cat\":\"books\",\"price\":20,\"tags\":[\"db\"]}","_doc":{"cat":"books","price":20,"nested":{"x":"v2"}},"f__cat":"books","f__price":20.0,"f__qty":4,"f__tags":["db"],"f__body":"vector search guide","f__ts":1700003600000,"f__vec":[0.9,0.1],"f__nested":["{\"name\":\"n2\",\"val\":15}"],"__tsid":"ts1"}`,
		`{"_id":"3","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"cat\":\"games\",\"price\":30}"," _doc":{},"f__cat":"games","f__price":30.0,"f__qty":6,"f__tags":[],"f__body":"legacy tombstone","f__ts":1700086400000,"f__vec":[0.0,1.0],"f__nested":[],"__tsid":"ts2"}`,
	}, "\n")
	if err := mb.StreamLoad(ctx, "t_deep", []byte(ndjson), true); err != nil {
		t.Fatal(err)
	}
	if err := mb.DeleteDocsByIDs(ctx, "es", "t_deep", []string{"3"}); err != nil {
		t.Fatal(err)
	}

	// 1. GetDocByID / GetDocsByIDs (live, tombstoned, missing)
	if h, found, err := mb.GetDocByID(ctx, "es", "t_deep", "1"); err != nil || !found || h.ID != "1" {
		t.Fatalf("GetDocByID live = (%+v, %v, %v)", h, found, err)
	}
	if _, found, err := mb.GetDocByID(ctx, "es", "t_deep", "3"); err != nil || found {
		t.Fatalf("expected deleted doc 3 found=false, got found=%v err=%v", found, err)
	}
	batch, err := mb.GetDocsByIDs(ctx, "es", "t_deep", []string{"1", "2", "3", "missing"})
	if err != nil || len(batch) != 2 {
		t.Fatalf("GetDocsByIDs got %d err=%v", len(batch), err)
	}

	// 2. QueryHits: reHitsSQL + search_after + collapse + kNN TopK + WHERE operators
	hits1, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(`f__price` AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (`f__cat` = 'books' AND `f__price` >= 5 AND `f__price` <= 25 AND `f__tags` IS NOT NULL AND array_contains(`f__tags`, 'db')) ORDER BY `_score` DESC NULLS LAST, `_id` ASC LIMIT 10 OFFSET 0")
	if err != nil || len(hits1) != 2 || hits1[0].ID != "2" {
		t.Fatalf("reHitsSQL = %+v err=%v", hits1, err)
	}
	hitsSA, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM (SELECT *, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `f__cat` IN ('books', 'other')) `_scored` WHERE `f__price` > 10 ORDER BY `_score` DESC, `_id` ASC LIMIT 5 OFFSET 0")
	if err != nil || len(hitsSA) != 1 || hitsSA[0].ID != "2" {
		t.Fatalf("reSearchAfterHitsSQL = %+v err=%v", hitsSA, err)
	}
	hitsCol, err := mb.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY `f__cat` ORDER BY `f__price` DESC) AS `_collapse_rn` FROM (SELECT *, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `f__cat` = 'books') `_scored`) `_collapsed` WHERE `_collapse_rn` = 1 ORDER BY `_score` DESC, `_id` ASC LIMIT 5 OFFSET 0")
	if err != nil || len(hitsCol) != 1 {
		t.Fatalf("reCollapsedHitsSQL = %+v err=%v", hitsCol, err)
	}

	// 3. evalWhereExpr + evalNumericExpr + resolveColumnValue + evalColumnFuncR62Mem
	r1 := map[string]any{
		"_id":      "1",
		"_doc":     `{"nested":{"x":"v1"},"tags":["go","db"],"nums":[1,2]}`,
		"_source":  `{"cat":"books"}`,
		"f__cat":   "books",
		"f__price": 10.0,
		"f__body":  "fast search engine",
		"f__tags":  []any{"go", "db"},
		"f__vec":   []any{1.0, 0.0},
		"f__hex":   "68656c6c6f",
		"f__b64":   "aGVsbG8=",
		"f__ip4":   int64(2130706433),
		"f__ip6":   "::1",
	}
	for _, wExpr := range []string{
		"`f__cat` LIKE 'boo%'",
		"`f__body` REGEXP 'search'",
		"`f__body` MATCH_ALL 'fast'",
		"`f__body` MATCH_PHRASE 'fast search'",
		"`f__body` MATCH_PHRASE_PREFIX 'fast sea'",
		"`f__cat` NOT IN ('games', 'music')",
		"NOT (`f__cat` = 'games')",
		"arrays_overlap(`f__tags`, ['db', 'sql'])",
		"array_exists(_x -> _x = 'go', `f__tags`)",
	} {
		if !evalWhereExpr(r1, wExpr) {
			t.Fatalf("expected evalWhereExpr true for %s", wExpr)
		}
	}
	if evalNumericExpr(r1, "(10 + 5 - 3) * 2 / 4 % 5 + POW(2, 3) + ABS(-1) + FLOOR(2.9) + CEIL(1.1) + ROUND(2.4)") <= 0 {
		t.Fatalf("unexpected evalNumericExpr math result")
	}
	if math.Abs(evalNumericExpr(r1, "CASE WHEN `f__price` > 5 THEN 10 ELSE 1 END")-10) > 1e-9 {
		t.Fatalf("expected CASE WHEN numeric result 10")
	}
	if v := resolveColumnValue(r1, "CAST('true' AS BOOLEAN)"); v != true {
		t.Fatalf("CAST BOOLEAN = %#v", v)
	}
	if v := resolveColumnValue(r1, "CAST(123 AS STRING)"); v != "123" {
		t.Fatalf("CAST STRING = %#v", v)
	}
	if v := resolveColumnValue(r1, "CAST('[1.0, 2.0]' AS ARRAY<FLOAT>)"); v == nil {
		t.Fatalf("CAST ARRAY<FLOAT> returned nil")
	}
	if v := resolveColumnValue(r1, "RIGHT('abcdef', 3)"); v != "def" {
		t.Fatalf("RIGHT = %#v", v)
	}
	if v := resolveColumnValue(r1, "RPAD('ab', 5, 'x')"); v != "abxxx" {
		t.Fatalf("RPAD = %#v", v)
	}
	if v := resolveColumnValue(r1, "REPLACE('foo-bar', '-', '_')"); v != "foo_bar" {
		t.Fatalf("REPLACE = %#v", v)
	}
	if v := resolveColumnValue(r1, "CONV('10', 16, 10)"); v != "16" {
		t.Fatalf("CONV = %#v", v)
	}
	if v := resolveColumnValue(r1, "UNHEX(`f__hex`)"); string(v.([]byte)) != "hello" {
		t.Fatalf("UNHEX = %#v", v)
	}
	if v := resolveColumnValue(r1, "FROM_BASE64(`f__b64`)"); string(v.([]byte)) != "hello" {
		t.Fatalf("FROM_BASE64 = %#v", v)
	}
	if v := resolveColumnValue(r1, "IPV4_NUM_TO_STRING(`f__ip4`)"); v != "127.0.0.1" {
		t.Fatalf("IPV4_NUM_TO_STRING = %#v", v)
	}
	ip6Bytes := resolveColumnValue(r1, "IPV6_STRING_TO_NUM_OR_NULL(`f__ip6`)")
	if str := resolveColumnValue(map[string]any{"b": ip6Bytes}, "IPV6_NUM_TO_STRING(`b`)"); str != "::1" {
		t.Fatalf("IPV6 roundtrip = %#v", str)
	}
	if h := resolveColumnValue(r1, "MURMUR_HASH3_32('hello', 'world')"); h == nil {
		t.Fatalf("MURMUR_HASH3_32 returned nil")
	}
	if v := resolveColumnValue(r1, "`_doc`['nested']['x']"); v != "v1" {
		t.Fatalf("_doc bracket path = %#v", v)
	}

	// 4. QueryAggs multi-branch UNION ALL + KNN TopK + sampler subquery
	aggBranches := []string{
		"SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'flt' AS `_agg_name`, '_filter' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__price` >= 15",
		"SELECT 'mis' AS `_agg_name`, '_missing' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE NOT (`f__missing` IS NOT NULL)",
		"SELECT 'card_s' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `f__cat`) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'card_a' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL",
		"SELECT 'vc_s' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`f__cat`) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'vc_a' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL",
		"SELECT 'avg_p' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(AVG(`f__price`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'std_p' AS `_agg_name`, '_stats_std_deviation' AS `_bucket_key`, CAST(COALESCE(STDDEV_POP(`f__price`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'pct' AS `_agg_name`, '50.0' AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(`f__price`, 0.5), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"SELECT 'prank' AS `_agg_name`, '15' AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN `f__price` <= 15 THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
		"(SELECT 'terms_a' AS `_agg_name`, CAST(`_elem` AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5)",
		"(SELECT 'nested_t' AS `_agg_name`, json_extract_string(`_nel`, '$.name') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__nested`) `_nt` AS `_nel` WHERE json_extract_string(`_nel`, '$.name') IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5)",
		"SELECT 'rng' AS `_agg_name`, 'cheap' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__price` < 15",
		"(SELECT 'dh' AS `_agg_name`, CAST(CAST(FLOOR(`f__ts` / 3600000) * 3600000 AS BIGINT) AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__ts` IS NOT NULL GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS BIGINT) ASC)",
	}
	cteSQL := "WITH `base_matched` AS (SELECT * FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0)\n" + strings.Join(aggBranches, "\nUNION ALL\n")
	aggsOut, err := mb.QueryAggs(ctx, cteSQL)
	if err != nil || len(aggsOut) < 12 {
		t.Fatalf("QueryAggs multi-branch got len=%d err=%v", len(aggsOut), err)
	}
	if _, err := mb.QueryAggs(ctx, "WITH `base_matched` AS (SELECT * FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (ORDER BY (1.0 / (1.0 + l2_distance(`f__vec`, [1.0, 0.0]))) DESC, `_id` ASC) AS `_rn` FROM `es`.`t_deep` WHERE `__DORIS_DELETE_SIGN__` = 0 AND TRUE) `_knn` WHERE `_rn` <= 1)))\nSELECT 'k' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`"); err != nil {
		t.Fatalf("kNN subquery in QueryAggs failed: %v", err)
	}
	smpOut := resolveRound62AggSubqueriesR62Mem([]map[string]any{r1}, "`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE TRUE ORDER BY CAST(`f__price` AS DOUBLE) DESC, `_id` ASC LIMIT 1) `_smp`)")
	if !strings.Contains(smpOut, "'1'") {
		t.Fatalf("expected sampler subquery resolved to id '1', got %s", smpOut)
	}
}

func TestRound65_F27_SQLBackend_DeepCoveragePart2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. QueryHits across all hitsRowScanLayout variants (7RawDocAndRouting, 6Routing, 6RawDoc, 5Base) + GetDocByID/GetDocsByIDs fallback layouts & tombstones
	var callIdx atomic.Int32
	db := openR65MockDB(t, func(kind, query string, args []driver.NamedValue) r65SQLMockSpec {
		if kind == "exec" {
			return r65SQLMockSpec{}
		}
		if strings.Contains(query, "FROM `es_db`.`docs` WHERE `_id` = ?") {
			if len(args) > 0 && args[0].Value == "fallback_deleted" {
				if strings.Contains(query, "`_raw_doc`") {
					return r65SQLMockSpec{queryEr: errors.New("Unknown column '_doc'")}
				}
				return r65SQLMockSpec{
					cols: []string{"_id", "_version", "_source"},
					rows: [][]driver.Value{{"fallback_deleted", int64(3), ""}},
				}
			}
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_routing", "__DORIS_DELETE_SIGN__"},
				rows: [][]driver.Value{{"doc1", int64(2), `{"a":1}`, `{"a":1,"b":2}`, "r-1", int64(0)}},
			}
		}
		if strings.Contains(query, "FROM `es_db`.`docs` WHERE `_id` IN") {
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_routing", "__DORIS_DELETE_SIGN__"},
				rows: [][]driver.Value{
					{"doc1", int64(2), `{"a":1}`, "r-1", int64(0)},
					{"doc_del", int64(3), `{"a":9}`, "r-2", int64(1)},
				},
			}
		}
		switch callIdx.Add(1) {
		case 1:
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_routing", "_score", "_total_hits"},
				rows: [][]driver.Value{{"h1", int64(1), `{"k":1}`, `{"k":1,"x":2}`, "rt", 1.5, int64(10)}},
			}
		case 2:
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_routing", "_score", "_total_hits"},
				rows: [][]driver.Value{{"h2", int64(1), `{"k":2}`, "rt2", 2.5, int64(10)}},
			}
		case 3:
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_score", "_total_hits"},
				rows: [][]driver.Value{{"h3", int64(1), `{"k":3}`, `{"k":3}`, 3.5, int64(10)}},
			}
		default:
			return r65SQLMockSpec{
				cols: []string{"_id", "_version", "_source", "_score", "_total_hits"},
				rows: [][]driver.Value{{"h4", int64(1), `{"k":4}`, 4.5, int64(10)}},
			}
		}
	})

	b := NewDorisSQLBackend(db, nil)
	for i := 0; i < 4; i++ {
		hits, err := b.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_db`.`docs` WHERE 1=1")
		if err != nil || len(hits) != 1 || hits[0].TotalHits != 10 {
			t.Fatalf("QueryHits layout #%d = (%+v, %v)", i+1, hits, err)
		}
	}
	if hit, found, err := b.GetDocByID(ctx, "es_db", "docs", "doc1"); err != nil || !found || hit.Routing != "r-1" {
		t.Fatalf("GetDocByID live = (%+v, %v, %v)", hit, found, err)
	}
	if _, found, err := b.GetDocByID(ctx, "es_db", "docs", "fallback_deleted"); err != nil || found {
		t.Fatalf("expected fallback_deleted found=false, got found=%v err=%v", found, err)
	}
	docsMap, err := b.GetDocsByIDs(ctx, "es_db", "docs", []string{"doc1", "doc_del", "absent"})
	if err != nil || len(docsMap) != 1 || docsMap["doc1"].Routing != "r-1" {
		t.Fatalf("GetDocsByIDs = (%+v, %v)", docsMap, err)
	}

	// 2. injectRawDocSelectIntoHitsSQL & rewriteDorisUnitSepLiterals & rewriteDorisArrayExists edge cases
	if out, ok := injectRawDocSelectIntoHitsSQL("SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score` FROM `es`.`t`"); !ok || !strings.Contains(out, "`_raw_doc`") {
		t.Fatalf("injectRawDocSelectIntoHitsSQL failed: %q %v", out, ok)
	}
	if _, ok := injectRawDocSelectIntoHitsSQL("SELECT `_id` FROM `es`.`t` WHERE `msg` = 'SELECT `_id`, `_version`, `_source`,'"); ok {
		t.Fatalf("should not inject inside quoted SQL string literal")
	}
	if norm := NormalizeDorisSQL("SELECT * FROM t WHERE `k` = 'a\\x1fb' AND array_exists(_el -> TRY_CAST(json_extract_string(_el, '$.p') AS INT) > 1, `arr`)"); !strings.Contains(norm, "CHAR(31)") || !strings.Contains(norm, "CAST([] AS ARRAY<STRING>)") {
		t.Fatalf("unexpected NormalizeDorisSQL output: %s", norm)
	}
}
