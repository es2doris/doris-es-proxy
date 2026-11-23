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
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
)

func FuzzSpatialWKTGeoJSONAndGrid(f *testing.F) {
	type seed struct {
		shape  string
		bounds string
		prec   int
		lat    float64
		lon    float64
	}
	seeds := []seed{
		{"POINT (4.91235 52.374081)", "BBOX (4.9, 5.0, 52.4, 52.3)", 5, 52.374081, 4.91235},
		{"POINT (-0.1278 51.5074)", "ENVELOPE (-1.0, 1.0, 52.0, 51.0)", 7, 51.5074, -0.1278},
		{"MULTIPOINT ((2.35 48.86), (-0.12 51.50))", "", 3, 48.86, 2.35},
		{"LINESTRING (139.0 35.0, 140.0 36.0)", "BBOX (138.0, 141.0, 37.0, 34.0)", 4, 35.5, 139.5},
		{"MULTILINESTRING ((0 0, 1 1), (2 2, 3 3))", "", 6, 1.0, 1.0},
		{"POLYGON ((2 48, 3 48, 3 49, 2 49, 2 48))", "BBOX (2.2, 2.8, 48.8, 48.2)", 5, 48.5, 2.5},
		{"POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0), (2 2, 2 8, 8 8, 8 2, 2 2))", "", 2, 1.0, 1.0},
		{"MULTIPOLYGON (((0 0, 4 0, 4 4, 0 4, 0 0)), ((10 10, 14 10, 14 14, 10 14, 10 10)))", "", 3, 2.0, 2.0},
		{"BBOX (-10, 10, 50, 40)", "BBOX (-20, 20, 60, 30)", 4, 45.0, 0.0},
		{"ENVELOPE (-180, 180, 85, -85)", "", 0, 0.0, 0.0},
		{"GEOMETRYCOLLECTION (POINT (1 2), LINESTRING (0 0, 2 2), POLYGON ((0 0, 2 0, 2 2, 0 2, 0 0)))", "", 4, 1.0, 1.0},
		{"GEOMETRYCOLLECTION (GEOMETRYCOLLECTION (POINT (4.9 52.37)))", "", 5, 52.37, 4.9},
		{`{"type":"point","coordinates":[4.9,52.3]}`, "", 5, 52.3, 4.9},
		{`{"type":"multipoint","coordinates":[[0,0],[1,1]]}`, "", 4, 0.0, 0.0},
		{`{"type":"linestring","coordinates":[[179.5,10],[-179.5,10]]}`, "", 3, 10.0, 179.5},
		{`{"type":"polygon","coordinates":[[[2,48],[3,48],[3,49],[2,49],[2,48]]]}`, "", 5, 48.5, 2.5},
		{`{"type":"envelope","coordinates":[[-10,50],[10,40]]}`, "", 4, 45.0, 0.0},
		{`{"type":"geometrycollection","geometries":[{"type":"point","coordinates":[1,2]},{"type":"polygon","coordinates":[[[0,0],[2,0],[2,2],[0,2],[0,0]]]}]}`, "", 3, 1.0, 1.0},
		{`{"lat":52.37,"lon":4.90}`, "", 7, 52.37, 4.90},
		{`{"x":10.5,"y":-20.25}`, "", 4, -20.25, 10.5},
		// Adversarial / malformed / extreme / non-finite seeds
		{"POINT (NaN 10)", "", 5, math.NaN(), 10},
		{"POINT (Inf -Inf)", "BBOX (Inf, 1, 2, -Inf)", 29, math.Inf(1), math.Inf(-1)},
		{"LINESTRING (0 0, 1e308 1e308)", "", 64, 90.0, 180.0},
		{"POLYGON ((((((((1 2, 3 4))))", "", -999, -90.0, -180.0},
		{"POLYGON ((1 1))", "", 999999, 0.0, 0.0},
		{"7/65/42", "", 7, 52.37, 4.91},
		{"u173z", "", 5, 52.37, 4.91},
		{"85196953fffffff", "", 5, 52.37, 4.91},
		{"", "", 15, 0.0, 0.0},
	}
	for _, s := range seeds {
		f.Add(s.shape, s.bounds, s.prec, s.lat, s.lon)
	}

	f.Fuzz(func(t *testing.T, rawShape, rawBounds string, prec int, lat, lon float64) {
		if len(rawShape) > 8192 {
			rawShape = rawShape[:8192]
		}
		if len(rawBounds) > 1024 {
			rawBounds = rawBounds[:1024]
		}

		// 1. WKT / GeoJSON parsing & normalization must never panic or yield non-finite coords.
		for _, quantize := range []bool{true, false} {
			shapes, ok := parseRawShapesR64(rawShape, quantize)
			if ok {
				for _, sh := range shapes {
					for _, v := range sh.vertices() {
						if !isFiniteCoordR64(v[0]) || !isFiniteCoordR64(v[1]) {
							t.Fatalf("parseRawShapesR64(%q, quantize=%v) produced non-finite vertex %v", rawShape, quantize, v)
						}
					}
					_ = sh.dim()
					_ = sh.toWKT()
					top, left, bot, right := sh.bbox()
					if !isFiniteCoordR64(top) || !isFiniteCoordR64(left) || !isFiniteCoordR64(bot) || !isFiniteCoordR64(right) {
						t.Fatalf("non-finite bbox on %q: (%v,%v,%v,%v)", rawShape, top, left, bot, right)
					}
				}
				_ = formatParsedShapesToWKTR64(shapes)
			}
			_, _ = normalizeGeoShapeValueToGeoJSONR64(rawShape, quantize)
			_, _ = parseSingleWKTEnvelopeOrShapeToGeoJSONR64(rawShape, quantize)
		}
		_, _ = formatGeoShapeSingleWKTR64(rawShape)
		_, _, _, _, _, _, _, _ = decodeGeotileBoundsR64(rawShape)

		// 2. Float slice / [][]float64 non-finite coordinate rejection invariant.
		if !isFiniteCoordR64(lat) || !isFiniteCoordR64(lon) {
			if _, ok := parseJSONCoordPairR64([]float64{lon, lat}, false); ok {
				t.Fatalf("parseJSONCoordPairR64([]float64) accepted non-finite (%v,%v)", lon, lat)
			}
			if _, ok := parseJSONCoordSeqR64([][]float64{{lon, lat}}, false); ok {
				t.Fatalf("parseJSONCoordSeqR64([][]float64) accepted non-finite (%v,%v)", lon, lat)
			}
			if _, ok := parseRawShapesR64([]any{lon, lat}, false); ok {
				t.Fatalf("parseRawShapesR64([]any) accepted non-finite (%v,%v)", lon, lat)
			}
		}

		// 3. Bounding box parsing must never return non-finite bounds.
		bTop, bLeft, bBot, bRight, hasBounds := parseWKTBBoxCoordsR64(rawBounds)
		if hasBounds && (!isFiniteCoordR64(bTop) || !isFiniteCoordR64(bLeft) || !isFiniteCoordR64(bBot) || !isFiniteCoordR64(bRight)) {
			t.Fatalf("parseWKTBBoxCoordsR64(%q) returned non-finite coords", rawBounds)
		}

		// 4. Spatial grid cell enumerators & validation must handle arbitrary precisions safely.
		shapes, ok := parseRawShapesR64(rawShape, true)
		if !ok && isFiniteCoordR64(lat) && isFiniteCoordR64(lon) {
			shapes = []parsedGeomR64{{kind: geomPointR64, pt: [2]float64{lat, lon}}}
		}
		if len(shapes) > 8 {
			shapes = shapes[:8]
		}
		for _, sh := range shapes {
			gt := enumerateGeotileCellsForGeomR64(sh, prec, hasBounds, bTop, bLeft, bBot, bRight)
			if len(gt) > 4096 {
				t.Fatalf("enumerateGeotileCellsForGeomR64 exceeded 4096 cells: %d", len(gt))
			}
			gh := enumerateGeohashCellsForGeomR64(sh, prec, hasBounds, bTop, bLeft, bBot, bRight)
			if len(gh) > 4096 {
				t.Fatalf("enumerateGeohashCellsForGeomR64 exceeded 4096 cells: %d", len(gh))
			}
			// Keep geohex cell-polyfill quick at high res only when geometry bbox isn't huge.
			gTop, gLeft, gBot, gRight := sh.bbox()
			effHexRes := clampGeoGridPrecisionR65("geohex", prec)
			if effHexRes <= 6 || (math.Abs(gTop-gBot) < 1.0 && math.Abs(gRight-gLeft) < 1.0) {
				gx := enumerateGeohexCellsForGeomR64(sh, prec, hasBounds, bTop, bLeft, bBot, bRight, nil)
				if len(gx) > 1000000 {
					t.Fatalf("enumerateGeohexCellsForGeomR64 exceeded H3 cell limit: %d", len(gx))
				}
			}
		}

		// 5. Validation & aggregation helpers must reject out-of-range precision and never panic.
		pVal := prec
		specGH := esast.AggSpec{GeohashGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: &pVal}}
		specGT := esast.AggSpec{GeotileGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: &pVal}}
		specGX := esast.AggSpec{GeoHexGrid: &esast.GeoGridAggSpec{Field: "loc", Precision: &pVal}}
		if prec < 1 || prec > 12 {
			if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{"g": specGH}, false); st == 0 {
				t.Fatalf("expected 400 validation error for geohash_grid precision=%d", prec)
			}
		}
		if prec < 0 || prec > 29 {
			if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{"g": specGT}, false); st == 0 {
				t.Fatalf("expected 400 validation error for geotile_grid precision=%d", prec)
			}
		}
		if prec < 0 || prec > spatial.MaxRes {
			if st, _, _ := validateSpatialAndTimeSeriesAggTreeR64(map[string]esast.AggSpec{"g": specGX}, false); st == 0 {
				t.Fatalf("expected 400 validation error for geohex_grid precision=%d", prec)
			}
		}

		var rows []AggRow
		docs := []runtimeMatchedDoc{{hit: HitRow{ID: "1"}, doc: map[string]any{"loc": rawShape}}}
		emitRuntimeGeoGridAggRowsR64("gh", "", specGH, docs, &rows, nil)
		emitRuntimeGeoGridAggRowsR64("gt", "", specGT, docs, &rows, nil)
		if effHexRes := clampGeoGridPrecisionR65("geohex", prec); effHexRes <= 6 {
			emitRuntimeGeoGridAggRowsR64("gx", "", specGX, docs, &rows, nil)
		}

		// 6. Query evaluation helpers must handle arbitrary grid tokens safely.
		doc := map[string]any{"loc": rawShape}
		_ = evalDocGeoGridQueryR64(nil, doc, &esast.GeoGridQuery{Field: "loc", Geohash: rawShape})
		_ = evalDocGeoGridQueryR64(nil, doc, &esast.GeoGridQuery{Field: "loc", Geotile: rawShape})
		_ = evalDocGeoGridQueryR64(nil, doc, &esast.GeoGridQuery{Field: "loc", Geohex: rawShape})
	})
}
