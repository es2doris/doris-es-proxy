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

package spatial

import (
	"errors"
	"math"
	"testing"
)

func TestRound67UnwrapAndAngleHelpers(t *testing.T) {
	if got := unwrapDegLon(math.NaN(), 0); !math.IsNaN(got) {
		t.Fatalf("expected NaN for NaN lon, got %v", got)
	}
	if got := unwrapDegLon(10.0, math.Inf(1)); got != 10.0 {
		t.Fatalf("expected unchanged lon when refLon is Inf, got %v", got)
	}
	if got := unwrapDegLon(1000.0, 0.0); math.Abs(got-(-80.0)) > 1e-9 {
		t.Fatalf("expected 1000 unwrapped near 0 to -80, got %v", got)
	}
	if got := unwrapDegLon(-1000.0, 0.0); math.Abs(got-80.0) > 1e-9 {
		t.Fatalf("expected -1000 unwrapped near 0 to 80, got %v", got)
	}
	if got := unwrapDegLon(800.0, 0.0); math.Abs(got-80.0) > 1e-9 {
		t.Fatalf("expected 800 unwrapped near 0 to 80, got %v", got)
	}
	if got := unwrapDegLon(-800.0, 0.0); math.Abs(got-(-80.0)) > 1e-9 {
		t.Fatalf("expected -800 unwrapped near 0 to -80, got %v", got)
	}
	if got := unwrapDegLon(350.0, 0.0); math.Abs(got-(-10.0)) > 1e-9 {
		t.Fatalf("expected 350 unwrapped near 0 to -10, got %v", got)
	}
	if got := unwrapDegLon(-350.0, 0.0); math.Abs(got-10.0) > 1e-9 {
		t.Fatalf("expected -350 unwrapped near 0 to 10, got %v", got)
	}

	if got := posAngleRads(math.NaN()); !math.IsNaN(got) {
		t.Fatalf("expected NaN from posAngleRads(NaN), got %v", got)
	}
	if got := posAngleRads(math.Inf(-1)); !math.IsInf(got, -1) {
		t.Fatalf("expected -Inf from posAngleRads(-Inf), got %v", got)
	}
	if got := posAngleRads(-math.Pi / 2); math.Abs(got-1.5*math.Pi) > 1e-12 {
		t.Fatalf("expected 1.5*pi, got %v", got)
	}
	if got := posAngleRads(5 * math.Pi); math.Abs(got-math.Pi) > 1e-12 {
		t.Fatalf("expected pi, got %v", got)
	}
}

func TestRound67GeoAzDistanceAndGreatCircle(t *testing.T) {
	origin := latLng{lat: 0, lng: 0}
	if same := geoAzDistanceRads(origin, 0.5, 1e-18); same != origin {
		t.Fatalf("expected tiny distance < h3Epsilon to return origin, got %+v", same)
	}

	northPole := geoAzDistanceRads(origin, 0, pi2)
	if math.Abs(northPole.lat-pi2) > 1e-9 || northPole.lng != 0 {
		t.Fatalf("expected north pole, got %+v", northPole)
	}
	southPole := geoAzDistanceRads(origin, pi, pi2)
	if math.Abs(southPole.lat+pi2) > 1e-9 || southPole.lng != 0 {
		t.Fatalf("expected south pole, got %+v", southPole)
	}
	midNorth := geoAzDistanceRads(origin, 0, 0.5)
	if math.Abs(midNorth.lat-0.5) > 1e-9 {
		t.Fatalf("expected lat 0.5, got %+v", midNorth)
	}

	// Oblique azimuth directly toward north/south poles (hitting polar clamp branches).
	lat45 := latLng{lat: math.Pi / 4, lng: 0.2}
	obliqueNorth := geoAzDistanceRads(lat45, 0.0000000001, math.Pi/4)
	if math.Abs(obliqueNorth.lat-pi2) > 1e-4 {
		t.Fatalf("expected near-pole lat, got %+v", obliqueNorth)
	}
	latNeg45 := latLng{lat: -math.Pi / 4, lng: 0.2}
	obliqueSouth := geoAzDistanceRads(latNeg45, math.Pi-0.0000000001, math.Pi/4)
	if math.Abs(obliqueSouth.lat+pi2) > 1e-4 {
		t.Fatalf("expected near-south-pole lat, got %+v", obliqueSouth)
	}
	obliqueEast := geoAzDistanceRads(lat45, math.Pi/2, 0.7)
	if math.IsNaN(obliqueEast.lat) || math.IsNaN(obliqueEast.lng) {
		t.Fatalf("expected valid obliqueEast, got %+v", obliqueEast)
	}

	antipodalDist := greatCircleDistanceRads(latLng{lat: 0, lng: 0}, latLng{lat: 0, lng: math.Pi})
	if math.Abs(antipodalDist-math.Pi) > 1e-9 {
		t.Fatalf("expected pi antipodal distance, got %v", antipodalDist)
	}
}

func TestRound67ValidationDiskAndHierarchyEdgeCases(t *testing.T) {
	if isBaseCellPentagon(-1) || isBaseCellPentagon(numBaseCells) {
		t.Fatalf("expected out-of-range base cells not to be pentagons")
	}

	// Test invalid bitmasks in IsValidCell and StringToCell.
	valid, err := LatLonToCell(37.7749, -122.4194, 5)
	if err != nil {
		t.Fatalf("LatLonToCell failed: %v", err)
	}
	validStr := CellToString(valid)
	if parsed, err := StringToCell("  " + validStr + " "); err != nil || parsed != valid {
		t.Fatalf("StringToCell roundtrip failed: parsed=%x err=%v", parsed, err)
	}
	for _, bad := range []string{"", "1234567890abcdef0", "not-hex", "0"} {
		if _, err := StringToCell(bad); err == nil {
			t.Fatalf("expected StringToCell(%q) error", bad)
		}
	}

	if IsValidCell(valid | h3HighBitMask) {
		t.Fatalf("expected high-bit cell invalid")
	}
	if IsValidCell(h3SetMode(valid, 2)) {
		t.Fatalf("expected non-cell mode invalid")
	}
	if IsValidCell(valid | (1 << h3ReservedOffset)) {
		t.Fatalf("expected reserved bits set invalid")
	}
	if IsValidCell(h3SetBaseCell(valid, numBaseCells)) {
		t.Fatalf("expected base cell >= 122 invalid")
	}
	// Trailing non-7 unused digit invalid.
	if IsValidCell(h3SetIndexDigit(valid, 6, 1)) {
		t.Fatalf("expected trailing non-invalid digit invalid")
	}
	// Pentagon with kAxesDigit (1) invalid.
	pents := getPentagons(2)
	if IsValidCell(h3SetIndexDigit(pents[0], 1, kAxesDigit)) {
		t.Fatalf("expected pentagon with k-axis leading digit invalid")
	}

	// gridDiskMaxSize edge cases
	if n, ok := gridDiskMaxSize(-1); ok || n != 0 {
		t.Fatalf("expected negative k rejected")
	}
	if n, ok := gridDiskMaxSize(0); !ok || n != 1 {
		t.Fatalf("expected k=0 -> 1, got %d %v", n, ok)
	}
	if _, ok := gridDiskMaxSize(maxGridCellsLimit); ok {
		t.Fatalf("expected huge k rejected")
	}
	if _, ok := gridDiskMaxSize(600); ok {
		t.Fatalf("expected k=600 > limit rejected")
	}

	if got := GridDisk(0, 1); got != nil {
		t.Fatalf("expected invalid cell GridDisk nil, got %v", got)
	}
	if got := GridDisk(valid, -1); got != nil {
		t.Fatalf("expected k<0 GridDisk nil, got %v", got)
	}
	if got := GridDisk(valid, 0); len(got) != 1 || got[0] != valid {
		t.Fatalf("expected k=0 GridDisk singleton, got %v", got)
	}
	if got := GridDisk(valid, 600); got != nil {
		t.Fatalf("expected excessive GridDisk nil, got len=%d", len(got))
	}
	// Pentagon triggers BFS disk path cleanly.
	if got := GridDisk(pents[0], 2); len(got) != 1+5+10 {
		t.Fatalf("expected res-2 pentagon 2-disk size 16, got %d", len(got))
	}

	// CellToParent and CellNonChildren error / boundary branches.
	if _, err := CellToParent(0, 1); !errors.Is(err, ErrInvalidCell) {
		t.Fatalf("expected ErrInvalidCell for CellToParent(0,1), got %v", err)
	}
	if _, err := CellToParent(valid, -1); !errors.Is(err, ErrInvalidResolution) {
		t.Fatalf("expected ErrInvalidResolution, got %v", err)
	}
	if _, err := CellToParent(valid, 6); !errors.Is(err, ErrResolutionMismatch) {
		t.Fatalf("expected ErrResolutionMismatch for finer child res, got %v", err)
	}
	if parent, err := CellToParent(valid, 5); err != nil || parent != valid {
		t.Fatalf("expected same-res parent identity, got %x err=%v", parent, err)
	}

	res15Cell, err := LatLonToCell(0, 0, MaxRes)
	if err != nil {
		t.Fatalf("LatLonToCell max res failed: %v", err)
	}
	if nonCh, err := CellNonChildren(res15Cell); err != nil || nonCh != nil {
		t.Fatalf("expected nil nonChildren at MaxRes, got %v err=%v", nonCh, err)
	}
	if _, err := CellNonChildren(0); !errors.Is(err, ErrInvalidCell) {
		t.Fatalf("expected ErrInvalidCell for CellNonChildren(0), got %v", err)
	}
	if nonCh, err := CellNonChildren(pents[0]); err != nil || len(nonCh) == 0 {
		t.Fatalf("expected pentagon nonChildren, got len=%d err=%v", len(nonCh), err)
	}
}

func TestRound67LoopSegmentAndPolygonEdgeCases(t *testing.T) {
	if loop := loopToRads(nil); loop != nil {
		t.Fatalf("expected nil for empty loopToRads")
	}
	closed := [][2]float64{{0, 0}, {0, 1}, {1, 0}, {0, 0}}
	if loop := loopToRads(closed); len(loop) != 3 {
		t.Fatalf("expected closing duplicate vertex stripped, got %d", len(loop))
	}

	// segmentsIntersectDeg branches: disjoint, crossing, collinear overlapping, endpoint touch, parallel
	if segmentsIntersectDeg(0, 0, 1, 1, 2, 2, 3, 3) {
		t.Fatalf("expected disjoint segments false")
	}
	if !segmentsIntersectDeg(0, 0, 2, 2, 0, 2, 2, 0) {
		t.Fatalf("expected crossing segments true")
	}
	if !segmentsIntersectDeg(0, 0, 2, 0, 1, 0, 3, 0) {
		t.Fatalf("expected collinear overlapping segments true")
	}
	if !segmentsIntersectDeg(0, 0, 2, 0, 2, 0, 4, 0) {
		t.Fatalf("expected touching endpoint true")
	}
	if !segmentsIntersectDeg(0, 0, 2, 2, 1, 1, 1, 3) {
		t.Fatalf("expected endpoint-on-segment o3==0 true")
	}
	if !segmentsIntersectDeg(1, 1, 1, 3, 0, 0, 2, 2) {
		t.Fatalf("expected o1/o2 endpoint-on-segment true")
	}

	// lineHexEstimateCount branches
	o := latLng{lat: 0, lng: 0}
	d := latLng{lat: 0.1, lng: 0.1}
	if cnt := lineHexEstimateCount(o, d, 0); cnt != 1 {
		t.Fatalf("expected 1 for non-positive pentRadiusKm, got %d", cnt)
	}
	if cnt := lineHexEstimateCount(latLng{lat: math.NaN(), lng: 0}, d, 1.0); cnt != maxGridCellsLimit+1 {
		t.Fatalf("expected limit+1 for NaN coordinate, got %d", cnt)
	}
	if cnt := lineHexEstimateCount(o, latLng{lat: 0, lng: math.Pi / 2}, 0.001); cnt != maxGridCellsLimit+1 {
		t.Fatalf("expected limit+1 when ratio exceeds maxGridCellsLimit, got %d", cnt)
	}
	if cnt := lineHexEstimateCount(o, o, 100); cnt != 1 {
		t.Fatalf("expected min estimate 1, got %d", cnt)
	}

	// PolygonIntersectingCells validation & holes & antimeridian & sliver edge-intersection cases
	validPoly := [][2]float64{{37.7, -122.5}, {37.7, -122.3}, {37.85, -122.3}, {37.85, -122.5}}
	if _, err := PolygonIntersectingCells(validPoly, nil, -1); !errors.Is(err, ErrInvalidResolution) {
		t.Fatalf("expected ErrInvalidResolution, got %v", err)
	}
	if _, err := PolygonIntersectingCells([][2]float64{{math.NaN(), 0}, {0, 1}, {1, 0}}, nil, 3); !errors.Is(err, ErrInvalidCoordinate) {
		t.Fatalf("expected ErrInvalidCoordinate on outer, got %v", err)
	}
	if _, err := PolygonIntersectingCells(validPoly, [][][2]float64{{{0, math.Inf(1)}, {0, 1}, {1, 0}}}, 3); !errors.Is(err, ErrInvalidCoordinate) {
		t.Fatalf("expected ErrInvalidCoordinate on hole, got %v", err)
	}
	if cells, err := PolygonIntersectingCells([][2]float64{{0, 0}, {0, 1}}, nil, 3); err != nil || len(cells) != 0 {
		t.Fatalf("expected <3 vertex polygon to return empty nil err, got %v %v", cells, err)
	}

	hole := [][2]float64{{37.74, -122.44}, {37.74, -122.36}, {37.81, -122.36}, {37.81, -122.44}}
	withHole, err := PolygonIntersectingCells(validPoly, [][][2]float64{hole}, 6)
	if err != nil || len(withHole) == 0 {
		t.Fatalf("PolygonIntersectingCells with hole failed: len=%d err=%v", len(withHole), err)
	}

	// Tiny thin sliver across SF cell boundary at res 4: center & vertices fall outside sliver,
	// exercising cellEdgesIntersectLoops.
	sliver := [][2]float64{{37.7500, -122.55}, {37.7505, -122.25}, {37.7510, -122.25}, {37.7505, -122.55}}
	sliverCells, err := PolygonIntersectingCells(sliver, nil, 4)
	if err != nil || len(sliverCells) == 0 {
		t.Fatalf("expected sliver polygon to intersect res-4 cells, got len=%d err=%v", len(sliverCells), err)
	}

	// Antimeridian crossing polygon at low res.
	antiOuter := [][2]float64{{-2.0, 179.0}, {-2.0, -179.0}, {2.0, -179.0}, {2.0, 179.0}}
	antiCells, err := PolygonIntersectingCells(antiOuter, nil, 2)
	if err != nil || len(antiCells) == 0 {
		t.Fatalf("antimeridian PolygonIntersectingCells failed: len=%d err=%v", len(antiCells), err)
	}

	// Excessive boundary steps triggering ErrCellLimitExceeded.
	if _, err := PolygonIntersectingCells([][2]float64{{-50, -50}, {-50, 50}, {50, 50}, {50, -50}}, nil, 15); !errors.Is(err, ErrCellLimitExceeded) {
		t.Fatalf("expected ErrCellLimitExceeded for massive res-15 polygon, got %v", err)
	}

	// BBoxToCells transmeridian + invalid checks
	if _, err := BBoxToCells(10, 170, -10, -170, 1); err != nil {
		t.Fatalf("transmeridian BBoxToCells failed: %v", err)
	}
	if _, err := BBoxToCells(10, 20, -10, 10, 99); !errors.Is(err, ErrInvalidResolution) {
		t.Fatalf("expected ErrInvalidResolution on BBoxToCells, got %v", err)
	}
	if _, err := BBoxToCells(math.NaN(), 0, 0, 1, 2); !errors.Is(err, ErrInvalidCoordinate) {
		t.Fatalf("expected ErrInvalidCoordinate on BBoxToCells, got %v", err)
	}
}
