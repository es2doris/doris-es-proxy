package spatial

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func parseWKTPolygonRing(t *testing.T, wkt string) [][2]float64 {
	t.Helper()
	trimmed := strings.TrimSpace(wkt)
	const prefix = "POLYGON (("
	const suffix = "))"
	if !strings.HasPrefix(trimmed, prefix) || !strings.HasSuffix(trimmed, suffix) {
		t.Fatalf("unexpected WKT polygon %q", wkt)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefix), suffix)
	parts := strings.Split(inner, ",")
	pts := make([][2]float64, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) != 2 {
			t.Fatalf("unexpected coordinate pair %q in %q", p, wkt)
		}
		lon, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			t.Fatalf("parse lon %q: %v", fields[0], err)
		}
		lat, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("parse lat %q: %v", fields[1], err)
		}
		pts = append(pts, [2]float64{lat, lon})
	}
	// Strip closing point if it matches first point.
	if len(pts) > 1 && pts[0] == pts[len(pts)-1] {
		pts = pts[:len(pts)-1]
	}
	return pts
}

// assertRingMatches checks that got (open vertex loop [lat, lon]) matches want
// up to cyclic shift and optional reversal within tol degrees.
func assertRingMatches(t *testing.T, label string, got, want [][2]float64, tol float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s vertex count mismatch: got %d (%v), want %d (%v)", label, len(got), got, len(want), want)
	}
	n := len(got)
	matchOrder := func(reverse bool) bool {
		for shift := 0; shift < n; shift++ {
			ok := true
			for i := 0; i < n; i++ {
				wi := (i + shift) % n
				if reverse {
					wi = (n - 1 - i + shift) % n
				}
				if math.Abs(got[i][0]-want[wi][0]) > tol || math.Abs(got[i][1]-want[wi][1]) > tol {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
	if !matchOrder(false) && !matchOrder(true) {
		t.Fatalf("%s boundary vertices mismatch (tol=%g):\n  got:  %v\n  want: %v", label, tol, got, want)
	}
}

func TestUpstreamSpatialLocationsAndResolutions(t *testing.T) {
	// Points from 80_geohex_grid.yml, 80_geohex_grid_geo_shape.yml, and 90_geo_grid_query.yml
	cases := []struct {
		name     string
		lat, lon float64
		res5     string
		res0     string
		res15    string
	}{
		{"Amsterdam NEMO", 52.374081, 4.912350, "85196953fffffff", "801ffffffffffff", ""},
		{"Amsterdam Rembrandthuis", 52.369219, 4.901618, "85196953fffffff", "801ffffffffffff", "8f1969c9b261656"},
		{"Amsterdam Scheepvaart", 52.371667, 4.914722, "85196953fffffff", "801ffffffffffff", ""},
		{"Antwerp Letterenhuis", 51.222900, 4.405200, "851fa4c7fffffff", "801ffffffffffff", ""},
		{"Paris Louvre", 48.861111, 2.336389, "851fb467fffffff", "8019fffffffffff", ""},
		{"Paris dOrsay", 48.860000, 2.327000, "851fb467fffffff", "8019fffffffffff", ""},
	}

	for _, tc := range cases {
		h5, err := LatLonToCell(tc.lat, tc.lon, 5)
		if err != nil {
			t.Fatalf("%s res5 err: %v", tc.name, err)
		}
		if got := CellToString(h5); got != tc.res5 {
			t.Fatalf("%s res5: got %s, want %s", tc.name, got, tc.res5)
		}
		if Resolution(h5) != 5 || !IsValidCell(h5) || IsPentagon(h5) || !IsResClassIII(h5) {
			t.Fatalf("%s res5 metadata unexpected: %#x", tc.name, h5)
		}

		h0, err := LatLonToCell(tc.lat, tc.lon, 0)
		if err != nil {
			t.Fatalf("%s res0 err: %v", tc.name, err)
		}
		if got := CellToString(h0); got != tc.res0 {
			t.Fatalf("%s res0: got %s, want %s", tc.name, got, tc.res0)
		}
		// Note: due to H3 aperture-7 fractal boundaries, topological parent of a child cell
		// near a base-cell edge may be an adjacent res-0 base cell (base cell 12 vs 15 here).
		p0, err := CellToParent(h5, 0)
		if err != nil || !IsValidCell(p0) || Resolution(p0) != 0 {
			t.Fatalf("%s CellToParent(h5, 0): got %s (%v)", tc.name, CellToString(p0), err)
		}

		if tc.res15 != "" {
			h15, err := LatLonToCell(tc.lat, tc.lon, 15)
			if err != nil {
				t.Fatalf("%s res15 err: %v", tc.name, err)
			}
			if got := CellToString(h15); got != tc.res15 {
				t.Fatalf("%s res15: got %s, want %s", tc.name, got, tc.res15)
			}
			// Round-trip parent at res 5 & check Res15 center inverse.
			// Note Rembrandthuis is right near the edge of 85196953fffffff and adjacent 851969cbfffffff.
			p5, err := CellToParent(h15, 5)
			if err != nil {
				t.Fatalf("%s CellToParent(h15, 5) err: %v", tc.name, err)
			}
			inNeighborDisk := false
			for _, d := range GridDisk(h5, 1) {
				if d == p5 {
					inNeighborDisk = true
					break
				}
			}
			if !inNeighborDisk {
				t.Fatalf("%s CellToParent(h15, 5) = %s not within 1-disk of %s", tc.name, CellToString(p5), tc.res5)
			}
			cLat, cLon := CellToLatLon(h15)
			if math.Abs(cLat-tc.lat) > 1e-4 || math.Abs(cLon-tc.lon) > 1e-4 {
				t.Fatalf("%s CellToLatLon(h15)=(%v,%v) too far from (%v,%v)", tc.name, cLat, cLon, tc.lat, tc.lon)
			}
			rt15, err := LatLonToCell(cLat, cLon, 15)
			if err != nil || rt15 != h15 {
				t.Fatalf("%s LatLonToCell(CellToLatLon(h15)) = %s (%v), want %s", tc.name, CellToString(rt15), err, tc.res15)
			}
		}
	}

	// Verify 811f3ffffffffff validity & round-trip.
	h811f3, err := StringToCell("811f3ffffffffff")
	if err != nil || !IsValidCell(h811f3) || Resolution(h811f3) != 1 {
		t.Fatalf("811f3ffffffffff validation failed: %v", err)
	}
	lat3, lon3 := CellToLatLon(h811f3)
	rt3, err := LatLonToCell(lat3, lon3, 1)
	if err != nil || rt3 != h811f3 {
		t.Fatalf("811f3ffffffffff round-trip failed: %s (%v)", CellToString(rt3), err)
	}
}

func TestUpstream100GeoGridIngestBoundariesAndHierarchy(t *testing.T) {
	// Concrete hierarchy and exact 14 polygon boundaries from 100_geo_grid_ingest.yml
	cellHex := "811fbffffffffff"
	wantParent := "801ffffffffffff"
	wantChildren := []string{
		"821f87fffffffff",
		"821f8ffffffffff",
		"821f97fffffffff",
		"821f9ffffffffff",
		"821fa7fffffffff",
		"821faffffffffff",
		"821fb7fffffffff",
	}
	wantNonChildren := []string{
		"821ea7fffffffff",
		"82186ffffffffff",
		"82396ffffffffff",
		"821f17fffffffff",
		"821e37fffffffff",
		"82194ffffffffff",
	}

	h, err := StringToCell(cellHex)
	if err != nil {
		t.Fatalf("StringToCell(%s): %v", cellHex, err)
	}
	if Resolution(h) != 1 {
		t.Fatalf("Resolution(%s) = %d, want 1", cellHex, Resolution(h))
	}
	p, err := CellToParent(h, 0)
	if err != nil || CellToString(p) != wantParent {
		t.Fatalf("CellToParent(%s, 0) = %s (%v), want %s", cellHex, CellToString(p), err, wantParent)
	}
	children, err := CellToChildren(h, 2)
	if err != nil {
		t.Fatalf("CellToChildren(%s, 2): %v", cellHex, err)
	}
	if len(children) != len(wantChildren) {
		t.Fatalf("children count = %d, want %d", len(children), len(wantChildren))
	}
	for i, c := range children {
		if CellToString(c) != wantChildren[i] {
			t.Fatalf("child[%d] = %s, want %s", i, CellToString(c), wantChildren[i])
		}
	}

	// Exact WKT boundaries from 100_geo_grid_ingest.yml (stored by ES with 32-bit Lucene geo quantization: step ~4.19e-8 lat / ~8.38e-8 lon).
	cellWKT := "POLYGON ((1.1885095294564962 49.470279179513454, 2.0265689212828875 45.18424864858389, 7.509948452934623 43.786609335802495, 12.6773177459836 46.40695743262768, 12.345747342333198 50.55427505169064, 6.259687012061477 51.964770150370896, 3.6300085578113794 50.610463307239115, 1.1885095294564962 49.470279179513454))"
	wantCellVerts := parseWKTPolygonRing(t, cellWKT)
	gotCellVerts := CellToBoundary(h)
	assertRingMatches(t, cellHex, gotCellVerts, wantCellVerts, 1e-7)

	childrenWKTs := []string{
		"POLYGON ((5.163510935381055 48.943763938732445, 4.6524353697896 47.393027362413704, 6.371338488534093 46.417016638442874, 8.645314201712608 46.97706841863692, 9.251571390777826 48.53467794600874, 7.489805733785033 49.52621237374842, 5.163510935381055 48.943763938732445))",
		"POLYGON ((9.251571390777826 48.53467794600874, 8.645314201712608 46.97706841863692, 10.343212774023414 45.92192775104195, 12.6773177459836 46.40695743262768, 13.37434759363532 47.96593840699643, 11.648396300151944 49.039345127530396, 9.251571390777826 48.53467794600874))",
		"POLYGON ((2.4589017033576965 46.76373050082475, 2.0265689212828875 45.18424864858389, 3.696701768785715 44.22123494558036, 5.848476877436042 44.82546979095787, 6.371338488534093 46.417016638442874, 4.6524353697896 47.393027362413704, 2.4589017033576965 46.76373050082475))",
		"POLYGON ((6.371338488534093 46.417016638442874, 5.848476877436042 44.82546979095787, 7.509948452934623 43.786609335802495, 9.731941111385822 44.323804839514196, 10.343212774023414 45.92192775104195, 8.645314201712608 46.97706841863692, 6.371338488534093 46.417016638442874))",
		"POLYGON ((3.8811334781348705 51.36037617456168, 3.384771505370736 49.85377031844109, 5.163510935381055 48.943763938732445, 7.489805733785033 49.52621237374842, 8.08863085694611 51.039695707149804, 6.259687012061477 51.964770150370896, 3.8811334781348705 51.36037617456168))",
		"POLYGON ((8.08863085694611 51.039695707149804, 7.489805733785033 49.52621237374842, 9.251571390777826 48.53467794600874, 11.648396300151944 49.039345127530396, 12.345747342333198 50.55427505169064, 10.549622755497694 51.56398999504745, 8.08863085694611 51.039695707149804))",
		"POLYGON ((1.1885095294564962 49.470279179513454, 0.7640258967876434 47.907450324855745, 2.4589017033576965 46.76373050082475, 4.6524353697896 47.393027362413704, 5.163510935381055 48.943763938732445, 3.384771505370736 49.85377031844109, 1.1885095294564962 49.470279179513454))",
	}
	for i, chHex := range wantChildren {
		assertRingMatches(t, chHex, CellToBoundary(children[i]), parseWKTPolygonRing(t, childrenWKTs[i]), 1e-7)
	}

	nonChildrenWKTs := []string{
		"POLYGON ((10.343212774023414 45.92192775104195, 9.731941111385822 44.323804839514196, 11.369192842394114 43.20897659752518, 13.642238667234778 43.67433743085712, 14.337206231430173 45.273432224057615, 12.6773177459836 46.40695743262768, 10.343212774023414 45.92192775104195))",
		"POLYGON ((0.7640258967876434 47.907450324855745, -1.3966082129627466 47.44351194240153, -1.7527981102466583 45.828917124308646, -0.028004944324493408 44.71297777723521, 2.0265689212828875 45.18424864858389, 2.4589017033576965 46.76373050082475, 0.7640258967876434 47.907450324855745))",
		"POLYGON ((3.696701768785715 44.22123494558036, 3.2493495382368565 42.60479216929525, 4.868332073092461 41.58031489234418, 6.977840261533856 42.158615668304265, 7.509948452934623 43.786609335802495, 5.848476877436042 44.82546979095787, 3.696701768785715 44.22123494558036))",
		"POLYGON ((6.848228881135583 53.43156033195555, 6.259687012061477 51.964770150370896, 8.08863085694611 51.039695707149804, 10.549622755497694 51.56398999504745, 11.24517043121159 53.03203972522169, 9.374530809000134 53.975513661280274, 6.848228881135583 53.43156033195555))",
		"POLYGON ((12.345747342333198 50.55427505169064, 11.648396300151944 49.039345127530396, 13.37434759363532 47.96593840699643, 15.817383527755737 48.38812246453017, 16.606046771630645 49.899182128719985, 14.863026738166809 50.99274770356715, 12.345747342333198 50.55427505169064))",
		"POLYGON ((2.101313956081867 52.51713396515697, -0.21913748234510422 52.14168077800423, -0.6310947798192501 50.60191108379513, 1.1885095294564962 49.470279179513454, 3.384771505370736 49.85377031844109, 3.8811334781348705 51.36037617456168, 2.101313956081867 52.51713396515697))",
	}
	for i, ncHex := range wantNonChildren {
		nc, err := StringToCell(ncHex)
		if err != nil {
			t.Fatalf("StringToCell(%s): %v", ncHex, err)
		}
		assertRingMatches(t, ncHex, CellToBoundary(nc), parseWKTPolygonRing(t, nonChildrenWKTs[i]), 1e-7)
	}

	// Verify PolygonIntersectingCells over 811fbffffffffff boundary at res 2 returns
	// the 7 children AND the 6 overlapping nonChildren (13 cells total), whereas PolygonToCells
	// matches centers inside!
	polyCells, err := PolygonToCells(wantCellVerts, nil, 2)
	if err != nil {
		t.Fatalf("PolygonToCells res 2 err: %v", err)
	}
	polySet := make(map[string]bool)
	for _, c := range polyCells {
		polySet[CellToString(c)] = true
	}
	for _, ch := range wantChildren {
		if !polySet[ch] {
			t.Fatalf("PolygonToCells missing child %s; got %v", ch, polySet)
		}
	}

	interCells, err := PolygonIntersectingCells(wantCellVerts, nil, 2)
	if err != nil {
		t.Fatalf("PolygonIntersectingCells res 2 err: %v", err)
	}
	interSet := make(map[string]bool)
	for _, c := range interCells {
		interSet[CellToString(c)] = true
	}
	for _, ch := range wantChildren {
		if !interSet[ch] {
			t.Fatalf("PolygonIntersectingCells missing child %s", ch)
		}
	}
	for _, nch := range wantNonChildren {
		if !interSet[nch] {
			t.Fatalf("PolygonIntersectingCells missing adjacent nonChild %s", nch)
		}
	}
}

func TestBBoxGridDiskPentagonsAndValidation(t *testing.T) {
	// Bounds from 80_geohex_grid.yml: top_left POINT(4.9 52.4), bottom_right POINT(5.0 52.3)
	cells, err := BBoxToCells(52.4, 4.9, 52.3, 5.0, 5)
	if err != nil {
		t.Fatalf("BBoxToCells err: %v", err)
	}
	cellSet := make(map[string]bool)
	for _, c := range cells {
		cellSet[CellToString(c)] = true
	}
	if !cellSet["85196953fffffff"] {
		t.Fatalf("expected BBoxToCells to contain 85196953fffffff, got %v", cellSet)
	}
	if cellSet["851fb467fffffff"] || cellSet["851fa4c7fffffff"] {
		t.Fatalf("unexpected distant city cells in Amsterdam bbox: %v", cellSet)
	}

	// GridDisk hexagon k=0,1,2
	h5, _ := StringToCell("85196953fffffff")
	if d0 := GridDisk(h5, 0); len(d0) != 1 || d0[0] != h5 {
		t.Fatalf("GridDisk k=0: %v", d0)
	}
	if d1 := GridDisk(h5, 1); len(d1) != 7 {
		t.Fatalf("GridDisk k=1 hex len=%d, want 7", len(d1))
	}
	if d2 := GridDisk(h5, 2); len(d2) != 19 {
		t.Fatalf("GridDisk k=2 hex len=%d, want 19", len(d2))
	}

	// Pentagon at res 0 (base cell 4 is North Pole polar pentagon, base cell 14 is Class II pentagon).
	pent0 := getPentagons(0)[0] // base cell 4
	if !IsPentagon(pent0) {
		t.Fatalf("expected pentagon for %s", CellToString(pent0))
	}
	if pDisk := GridDisk(pent0, 1); len(pDisk) != 6 {
		t.Fatalf("pentagon GridDisk k=1 len=%d, want 6", len(pDisk))
	}
	if pChildren, err := CellToChildren(pent0, 1); err != nil || len(pChildren) != 6 {
		t.Fatalf("pentagon CellToChildren res 1 len=%d (%v), want 6", len(pChildren), err)
	}
	// Class III pentagon boundary includes icosahedron face edge intersection vertices (10 verts at res 1).
	pent1, err := CellToCenterChild(pent0, 1)
	if err != nil {
		t.Fatalf("CellToCenterChild pent0 res 1: %v", err)
	}
	if !IsPentagon(pent1) {
		t.Fatalf("expected center child %s to be pentagon", CellToString(pent1))
	}
	if pb := CellToBoundary(pent1); len(pb) != 10 {
		t.Fatalf("Class III pentagon boundary len=%d, want 10", len(pb))
	}

	// Polygon with hole excludes interior hole cells.
	outer := [][2]float64{{52.2, 4.7}, {52.2, 5.1}, {52.5, 5.1}, {52.5, 4.7}}
	hole := [][2]float64{{52.3, 4.85}, {52.3, 4.95}, {52.4, 4.95}, {52.4, 4.85}}
	withoutHole, err := PolygonToCells(outer, nil, 7)
	if err != nil {
		t.Fatalf("PolygonToCells outer res 7: %v", err)
	}
	withHole, err := PolygonToCells(outer, [][][2]float64{hole}, 7)
	if err != nil {
		t.Fatalf("PolygonToCells with hole res 7: %v", err)
	}
	if len(withHole) >= len(withoutHole) || len(withHole) == 0 {
		t.Fatalf("expected hole to remove cells: withHole=%d withoutHole=%d", len(withHole), len(withoutHole))
	}

	// Small polygon strictly inside a single res 1 cell.
	tinyPoly := [][2]float64{{48.0, 7.0}, {48.0, 7.01}, {48.01, 7.01}, {48.01, 7.0}}
	tinyInter, err := PolygonIntersectingCells(tinyPoly, nil, 1)
	if err != nil || len(tinyInter) != 1 || CellToString(tinyInter[0]) != "811fbffffffffff" {
		t.Fatalf("PolygonIntersectingCells tinyPoly res 1 = %v (%v), want [811fbffffffffff]", tinyInter, err)
	}

	// Validation & error checks.
	if _, err := LatLonToCell(0, 0, -1); err == nil {
		t.Fatal("expected error for negative res")
	}
	if _, err := LatLonToCell(0, 0, 16); err == nil {
		t.Fatal("expected error for res > 15")
	}
	if _, err := LatLonToCell(math.NaN(), 0, 5); err == nil {
		t.Fatal("expected error for NaN lat")
	}
	if _, err := StringToCell("not_hex"); err == nil {
		t.Fatal("expected error for invalid hex string")
	}
	if IsValidCell(0) || Resolution(0) != -1 {
		t.Fatal("expected zero H3 index to be invalid")
	}
	// Pentagon deleted k-direction digit 1 at first nonzero digit is invalid.
	badPentChild := (pent0 &^ h3ResMask) | (uint64(1) << h3ResOffset)
	badPentChild = h3SetIndexDigit(badPentChild, 1, 1)
	if IsValidCell(badPentChild) {
		t.Fatalf("expected pentagon child with leading digit 1 (%s) to be invalid", CellToString(badPentChild))
	}
	if _, err := BBoxToCells(10, 0, 20, 1, 5); err == nil {
		t.Fatal("expected error when bottomLat > topLat")
	}
	// Antimeridian bbox [-10..10] x [179..-179].
	antiCells, err := BBoxToCells(1.0, 179.5, -1.0, -179.5, 3)
	if err != nil || len(antiCells) == 0 {
		t.Fatalf("antimeridian BBoxToCells failed: len=%d err=%v", len(antiCells), err)
	}
	_ = fmt.Sprintf("validated %d antimeridian cells", len(antiCells))
}

func TestRound65H3RotationsAzimuthAndSafetyCaps(t *testing.T) {
	// 1. getRes0Cells: 122 unique valid resolution-0 base cells (12 pentagons, 110 hexagons).
	res0 := getRes0Cells()
	if len(res0) != numBaseCells {
		t.Fatalf("getRes0Cells len = %d, want %d", len(res0), numBaseCells)
	}
	seen := make(map[uint64]bool, len(res0))
	pentCount := 0
	for _, h := range res0 {
		if !IsValidCell(h) || Resolution(h) != 0 || seen[h] {
			t.Fatalf("invalid or duplicate res-0 cell %#x", h)
		}
		seen[h] = true
		if IsPentagon(h) {
			pentCount++
		}
	}
	if pentCount != numPentagons {
		t.Fatalf("res-0 pentagon count = %d, want %d", pentCount, numPentagons)
	}

	// 2. ijkRotate60cw: 6 CW rotations return original coordinate; CW+CCW is identity.
	for _, orig := range []coordIJK{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}, {2, 1, 0}, {0, 0, 0}} {
		c := orig
		for i := 0; i < 6; i++ {
			ijkRotate60cw(&c)
		}
		if c != orig {
			t.Fatalf("ijkRotate60cw*6(%v) = %v, want %v", orig, c, orig)
		}
		c2 := orig
		ijkRotate60cw(&c2)
		ijkRotate60ccw(&c2)
		if c2 != orig {
			t.Fatalf("ijkRotate60ccw(ijkRotate60cw(%v)) = %v, want %v", orig, c2, orig)
		}
	}

	// 3. rotate60cw: all digits 0..7, 6 rotations and inverse of rotate60ccw.
	for d := centerDigit; d <= invalidDigit; d++ {
		cur := d
		for i := 0; i < 6; i++ {
			cur = rotate60cw(cur)
		}
		if cur != d {
			t.Fatalf("rotate60cw*6(%d) = %d, want %d", d, cur, d)
		}
		if got := rotate60ccw(rotate60cw(d)); got != d {
			t.Fatalf("rotate60ccw(rotate60cw(%d)) = %d, want %d", d, got, d)
		}
	}

	// 4. geoAzDistanceRads across zero distance, due north/south, polar clamping, and general azimuth.
	pOrig := latLng{lat: degsToRads(10), lng: degsToRads(20)}
	if pSame := geoAzDistanceRads(pOrig, 1.0, 0); pSame != pOrig {
		t.Fatalf("zero distance geoAzDistanceRads = %v, want %v", pSame, pOrig)
	}
	pNorth := geoAzDistanceRads(pOrig, 0.0, degsToRads(5))
	if math.Abs(radsToDegs(pNorth.lat)-15.0) > 1e-9 || math.Abs(radsToDegs(pNorth.lng)-20.0) > 1e-9 {
		t.Fatalf("due north geoAzDistanceRads = (%v, %v)", radsToDegs(pNorth.lat), radsToDegs(pNorth.lng))
	}
	pNorthPole := geoAzDistanceRads(latLng{lat: degsToRads(80), lng: degsToRads(20)}, 0.0, degsToRads(10))
	if pNorthPole.lat != pi2 || pNorthPole.lng != 0 {
		t.Fatalf("expected North Pole clamping, got %v", pNorthPole)
	}
	pSouthPole := geoAzDistanceRads(latLng{lat: degsToRads(-80), lng: degsToRads(20)}, pi, degsToRads(10))
	if pSouthPole.lat != -pi2 || pSouthPole.lng != 0 {
		t.Fatalf("expected South Pole clamping, got %v", pSouthPole)
	}
	pSouth := geoAzDistanceRads(pOrig, pi, degsToRads(5))
	if math.Abs(radsToDegs(pSouth.lat)-5.0) > 1e-9 {
		t.Fatalf("due south geoAzDistanceRads lat = %v, want 5", radsToDegs(pSouth.lat))
	}
	pDiag := geoAzDistanceRads(pOrig, pi/3, degsToRads(4))
	if dist := greatCircleDistanceRads(pOrig, pDiag); math.Abs(dist-degsToRads(4)) > 1e-9 {
		t.Fatalf("greatCircleDistanceRads round-trip = %v, want %v", dist, degsToRads(4))
	}
	// Trigger polar branch inside general-azimuth path (lat ~ +-pi2)
	pPolarGen := geoAzDistanceRads(latLng{lat: degsToRads(89.9999), lng: 0}, 0.1, degsToRads(0.0001))
	if math.IsNaN(pPolarGen.lat) || math.IsNaN(pPolarGen.lng) {
		t.Fatalf("polar general-azimuth returned NaN: %v", pPolarGen)
	}
	// Antipodal and +/-pi longitude distance checks
	if d := greatCircleDistanceRads(latLng{lat: 0, lng: 0}, latLng{lat: 0, lng: pi}); math.Abs(d-pi) > 1e-12 {
		t.Fatalf("antipodal distance = %v, want pi", d)
	}
	if d := greatCircleDistanceRads(latLng{lat: 0, lng: -pi}, latLng{lat: 0, lng: pi}); d > 1e-12 {
		t.Fatalf("same meridian (-pi vs +pi) greatCircleDistanceRads = %v, want 0", d)
	}

	// 5. GridDisk caps: negative k, maxSize > maxGridCellsLimit, integer overflow, pentagon fallback cap.
	h5, _ := StringToCell("85196953fffffff")
	pent10 := getPentagons(10)[0]
	for _, badK := range []int{-1, -100, 577, 578, 1 << 30, math.MaxInt} {
		if got := GridDisk(h5, badK); got != nil {
			t.Fatalf("GridDisk(hex, %d) expected nil, got len=%d", badK, len(got))
		}
		if got := GridDisk(pent10, badK); got != nil {
			t.Fatalf("GridDisk(pent10, %d) expected nil, got len=%d", badK, len(got))
		}
	}
	if got := GridDisk(0, 1); got != nil {
		t.Fatalf("GridDisk(0, 1) expected nil, got %v", got)
	}
	if sz, ok := gridDiskMaxSize(576); !ok || sz != 997057 {
		t.Fatalf("gridDiskMaxSize(576) = (%d, %v), want (997057, true)", sz, ok)
	}
	if got := gridDiskBFS(pent10, 5, 10); got != nil {
		t.Fatalf("gridDiskBFS capped at 10 expected nil, got len=%d", len(got))
	}
	if got := gridDiskBFS(pent10, 1, 0); got != nil {
		t.Fatalf("gridDiskBFS limit=0 expected nil, got %v", got)
	}
	if got := gridDiskBFS(getPentagons(0)[0], 1, 100); len(got) != 6 {
		t.Fatalf("gridDiskBFS pent0 k=1 len=%d, want 6", len(got))
	}

	// 6. Cumulative polygon edge cap across outer + hole edges (each edge < 1M, sum > 1M).
	// At res 15, pentRadiusKm ~ 0.000509 km => 4 deg ~ 445 km => ~437k steps per edge (< 1M), 4 edges ~ 1.75M (> 1M).
	cumPoly := [][2]float64{{0, 0}, {0, 4}, {4, 4}, {4, 0}}
	if _, err := PolygonToCells(cumPoly, nil, 15); err != ErrCellLimitExceeded {
		t.Fatalf("PolygonToCells cumulative cap err = %v, want ErrCellLimitExceeded", err)
	}
	if _, err := PolygonIntersectingCells(cumPoly, nil, 15); err != ErrCellLimitExceeded {
		t.Fatalf("PolygonIntersectingCells cumulative cap err = %v, want ErrCellLimitExceeded", err)
	}
	// Outer triangle under cap (~550k steps), hole pushes cumulative sum over 1M.
	smallOuter := [][2]float64{{0, 0}, {0, 1.5}, {1.5, 0}}
	bigHole := [][2]float64{{0.1, 0.1}, {0.1, 2.5}, {2.5, 0.1}}
	if _, err := PolygonToCells(smallOuter, [][][2]float64{bigHole}, 15); err != ErrCellLimitExceeded {
		t.Fatalf("PolygonToCells outer+hole cumulative cap err = %v, want ErrCellLimitExceeded", err)
	}
	// Invalid coordinates & antimeridian polygon interpolation
	if _, err := PolygonToCells([][2]float64{{math.NaN(), 0}, {0, 1}, {1, 0}}, nil, 3); err != ErrInvalidCoordinate {
		t.Fatalf("PolygonToCells NaN err = %v, want ErrInvalidCoordinate", err)
	}
	if _, err := PolygonIntersectingCells([][2]float64{{0, 0}, {0, 1}, {1, 0}}, [][][2]float64{{{0, math.Inf(1)}, {0, 1}, {1, 0}}}, 3); err != ErrInvalidCoordinate {
		t.Fatalf("PolygonIntersectingCells Inf hole err = %v, want ErrInvalidCoordinate", err)
	}
	antiPoly := [][2]float64{{0.0, 179.5}, {0.0, -179.5}, {0.5, -179.5}, {0.5, 179.5}}
	antiPolyCells, err := PolygonIntersectingCells(antiPoly, nil, 3)
	if err != nil || len(antiPolyCells) == 0 {
		t.Fatalf("antimeridian PolygonIntersectingCells failed: len=%d err=%v", len(antiPolyCells), err)
	}
	for _, c := range antiPolyCells {
		_, cLon := CellToLatLon(c)
		if math.Abs(cLon) < 170.0 {
			t.Fatalf("antimeridian PolygonIntersectingCells emitted non-antimeridian cell at lon=%v", cLon)
		}
	}

	// 7. -180..+180 and wide-span BBoxToCells sampling (res <= 4 strips, res >= 5 belts & cap).
	res1All, err := BBoxToCells(90, -180, -90, 180, 1)
	if err != nil || len(res1All) != 842 {
		t.Fatalf("BBoxToCells global res=1 len=%d err=%v, want 842", len(res1All), err)
	}
	if _, err := BBoxToCells(90, -180, -90, 180, 5); err != ErrCellLimitExceeded {
		t.Fatalf("BBoxToCells global res=5 err=%v, want ErrCellLimitExceeded", err)
	}
	// Near-global strip at res=2 (-30..30 x -180..180) must cover all 4 longitude quadrants.
	stripRes2, err := BBoxToCells(30, -180, -30, 180, 2)
	if err != nil || len(stripRes2) < 100 {
		t.Fatalf("BBoxToCells res=2 strip failed: len=%d err=%v", len(stripRes2), err)
	}
	var seenQ1, seenQ2, seenQ3, seenQ4 bool
	for _, c := range stripRes2 {
		_, lon := CellToLatLon(c)
		switch {
		case lon >= 0 && lon < 90:
			seenQ1 = true
		case lon >= 90:
			seenQ2 = true
		case lon < 0 && lon > -90:
			seenQ3 = true
		case lon <= -90:
			seenQ4 = true
		}
	}
	if !seenQ1 || !seenQ2 || !seenQ3 || !seenQ4 {
		t.Fatalf("BBoxToCells res=2 -180..+180 undersampled longitudes: q1=%v q2=%v q3=%v q4=%v", seenQ1, seenQ2, seenQ3, seenQ4)
	}
	// Narrow equatorial -180..+180 strip at res >= 5.
	eqRes5, err := BBoxToCells(0.05, -180, -0.05, 180, 5)
	if err != nil || len(eqRes5) < 1000 {
		t.Fatalf("BBoxToCells equatorial res=5 -180..+180 failed: len=%d err=%v", len(eqRes5), err)
	}
	// Wide-span [-179, +179] box at res=5 and transmeridian [10, -10] at res=2.
	wideRes5, err := BBoxToCells(0.05, -179.0, -0.05, 179.0, 5)
	if err != nil || len(wideRes5) < 1000 {
		t.Fatalf("BBoxToCells wide-span [-179..179] res=5 failed: len=%d err=%v", len(wideRes5), err)
	}
	transWide, err := BBoxToCells(1.0, 10.0, -1.0, -10.0, 2)
	if err != nil || len(transWide) < 50 {
		t.Fatalf("BBoxToCells wide transmeridian [10..-10] res=2 failed: len=%d err=%v", len(transWide), err)
	}
	// Single point bbox, clamped latitudes > 90 / < -90, huge finite lon (1e300), invalid res/NaN.
	if ptCells, err := BBoxToCells(52.37, 4.91, 52.37, 4.91, 5); err != nil || len(ptCells) != 1 {
		t.Fatalf("single point BBoxToCells = (%v, %v)", ptCells, err)
	}
	if _, err := BBoxToCells(95, 1e300, -95, 1e300+10, 1); err != nil {
		t.Fatalf("huge finite lon BBoxToCells unexpected error: %v", err)
	}
	if _, err := BBoxToCells(1, 0, -1, 1, -1); err == nil {
		t.Fatal("expected invalid res error")
	}
	if _, err := BBoxToCells(math.NaN(), 0, -1, 1, 2); err == nil {
		t.Fatal("expected NaN coordinate error")
	}

	// 8. Additional validation / error branches across CellTo*, IsValidCell, StringToCell.
	if cLat, cLon := CellToLatLon(0); cLat != 0 || cLon != 0 {
		t.Fatalf("CellToLatLon(0) = (%v, %v), want (0, 0)", cLat, cLon)
	}
	if b := CellToBoundary(0); b != nil {
		t.Fatalf("CellToBoundary(0) = %v, want nil", b)
	}
	if _, err := CellToParent(0, 0); err == nil {
		t.Fatal("expected CellToParent(0, 0) error")
	}
	if _, err := CellToParent(h5, 6); err == nil {
		t.Fatal("expected CellToParent(h5, 6) resolution mismatch error")
	}
	if _, err := CellToCenterChild(0, 1); err == nil {
		t.Fatal("expected CellToCenterChild(0, 1) error")
	}
	if _, err := CellToCenterChild(h5, 4); err == nil {
		t.Fatal("expected CellToCenterChild(h5, 4) resolution mismatch error")
	}
	if _, err := CellToChildren(0, 1); err == nil {
		t.Fatal("expected CellToChildren(0, 1) error")
	}
	if _, err := CellToChildren(h5, 16); err == nil {
		t.Fatal("expected CellToChildren(h5, 16) error")
	}
	if IsPentagon(0) {
		t.Fatal("expected IsPentagon(0) == false")
	}
	if IsValidCell(h3SetBaseCell(h3SetMode(h3Init, h3CellMode), 125)) {
		t.Fatal("expected baseCell=125 to be invalid")
	}
	if IsValidCell(h3SetMode(h5, 2)) || IsValidCell(h5|h3HighBitMask) || IsValidCell(h5|h3ReservedMask) {
		t.Fatal("expected invalid mode/highbit/reserved cell to fail IsValidCell")
	}
}
