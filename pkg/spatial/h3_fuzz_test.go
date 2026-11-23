package spatial

import (
	"math"
	"testing"
)

func FuzzSpatialH3PolyfillAndGridDisk(f *testing.F) {
	// Normal polygon / bbox & valid res/k
	f.Add(52.4, 4.9, 52.3, 5.0, 5, 2, uint64(0x85196953fffffff))
	// Antimeridian crossing
	f.Add(1.0, 179.5, -1.0, -179.5, 3, 1, uint64(0x8009fffffffffff))
	// Global -180..+180 at res <= 4 and narrow equatorial strip at res >= 5
	f.Add(30.0, -180.0, -30.0, 180.0, 2, 0, uint64(0x821f87fffffffff))
	f.Add(0.05, -180.0, -0.05, 180.0, 5, 3, uint64(0x85196953fffffff))
	// Wide-span non-global box and transmeridian box
	f.Add(0.1, -179.0, -0.1, 179.0, 5, 576, uint64(0))
	f.Add(1.0, 10.0, -1.0, -10.0, 2, 577, uint64(0xffffffffffffffff))
	// Huge res exceeding cell limit quickly via cumulative edge steps
	f.Add(5.0, 0.0, 0.0, 5.0, 15, 578, uint64(0x8a09fffffffffff))
	// Adversarial coordinates: NaN, ±Inf, huge finite, negative/overflow k, invalid res
	f.Add(math.NaN(), 0.0, 1.0, 2.0, 5, -1, uint64(0x85196953fffffff))
	f.Add(math.Inf(1), math.Inf(-1), -10.0, 10.0, 4, math.MaxInt, uint64(0x8009fffffffffff))
	f.Add(1e300, -1e300, -1e300, 1e300, 16, 1<<30, uint64(0x85196953fffffff))
	f.Add(10.0, 0.0, 20.0, 1.0, -1, -999, uint64(12345))

	f.Fuzz(func(t *testing.T, lat1, lon1, lat2, lon2 float64, res int, k int, cell uint64) {
		hasBadCoord := math.IsNaN(lat1) || math.IsInf(lat1, 0) ||
			math.IsNaN(lon1) || math.IsInf(lon1, 0) ||
			math.IsNaN(lat2) || math.IsInf(lat2, 0) ||
			math.IsNaN(lon2) || math.IsInf(lon2, 0)

		h, err := LatLonToCell(lat1, lon1, res)
		if res < 0 || res > MaxRes || math.IsNaN(lat1) || math.IsInf(lat1, 0) || math.IsNaN(lon1) || math.IsInf(lon1, 0) {
			if err == nil {
				t.Fatalf("LatLonToCell(%v, %v, %d) expected error, got cell %#x", lat1, lon1, res, h)
			}
		} else if err == nil {
			if disk := GridDisk(h, k); len(disk) > maxGridCellsLimit {
				t.Fatalf("GridDisk(%#x, %d) exceeded limit: len=%d", h, k, len(disk))
			}
		}

		if disk := GridDisk(cell, k); len(disk) > maxGridCellsLimit {
			t.Fatalf("GridDisk(%#x, %d) exceeded limit: len=%d", cell, k, len(disk))
		} else if (k < 0 || !IsValidCell(cell)) && disk != nil {
			t.Fatalf("GridDisk(%#x, %d) expected nil for invalid/negative input, got len=%d", cell, k, len(disk))
		}

		// Test GridDisk against a pentagon at valid resolution.
		normRes := res
		if normRes < 0 {
			normRes = -normRes
		}
		normRes = normRes % (MaxRes + 1)
		pent := getPentagons(normRes)[0]
		if pd := GridDisk(pent, k); len(pd) > maxGridCellsLimit {
			t.Fatalf("GridDisk(pent %#x, %d) exceeded limit: len=%d", pent, k, len(pd))
		}

		// BBoxToCells with raw coords (covers inverted bottomLat > topLat, NaN/Inf, invalid res).
		if cells, bErr := BBoxToCells(lat1, lon1, lat2, lon2, res); bErr != nil {
			_ = bErr
		} else if len(cells) > maxGridCellsLimit {
			t.Fatalf("BBoxToCells exceeded limit: len=%d", len(cells))
		}
		if res < 0 || res > MaxRes || hasBadCoord {
			if _, bErr := BBoxToCells(lat1, lon1, lat2, lon2, res); bErr == nil {
				t.Fatalf("BBoxToCells(%v,%v,%v,%v,%d) expected error", lat1, lon1, lat2, lon2, res)
			}
		}

		// Normalized top/bottom box & polygon polyfill checks.
		topLat, botLat := lat1, lat2
		if !math.IsNaN(lat1) && !math.IsNaN(lat2) && botLat > topLat {
			topLat, botLat = botLat, topLat
		}
		outer := [][2]float64{
			{botLat, lon1},
			{botLat, lon2},
			{topLat, lon2},
			{topLat, lon1},
		}
		hole := [][2]float64{
			{botLat*0.75 + topLat*0.25, lon1*0.75 + lon2*0.25},
			{botLat*0.75 + topLat*0.25, lon1*0.25 + lon2*0.75},
			{botLat*0.25 + topLat*0.75, lon1*0.25 + lon2*0.75},
			{botLat*0.25 + topLat*0.75, lon1*0.75 + lon2*0.25},
		}

		pCells, pErr := PolygonToCells(outer, [][][2]float64{hole}, res)
		if (res < 0 || res > MaxRes || hasBadCoord) && pErr == nil {
			t.Fatalf("PolygonToCells expected error for bad res=%d or coords", res)
		}
		if len(pCells) > maxGridCellsLimit {
			t.Fatalf("PolygonToCells exceeded limit: len=%d", len(pCells))
		}

		iCells, iErr := PolygonIntersectingCells(outer, [][][2]float64{hole}, res)
		if (res < 0 || res > MaxRes || hasBadCoord) && iErr == nil {
			t.Fatalf("PolygonIntersectingCells expected error for bad res=%d or coords", res)
		}
		if len(iCells) > maxGridCellsLimit {
			t.Fatalf("PolygonIntersectingCells exceeded limit: len=%d", len(iCells))
		}
	})
}
