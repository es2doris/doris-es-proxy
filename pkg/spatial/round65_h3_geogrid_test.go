package spatial

import (
	"reflect"
	"testing"
)

func TestRound65CellNonChildren(t *testing.T) {
	h, err := StringToCell("811fbffffffffff")
	if err != nil {
		t.Fatalf("StringToCell failed: %v", err)
	}
	nc, err := CellNonChildren(h)
	if err != nil {
		t.Fatalf("CellNonChildren failed: %v", err)
	}
	wantOrder := []string{
		"821ea7fffffffff",
		"82186ffffffffff",
		"82396ffffffffff",
		"821f17fffffffff",
		"821e37fffffffff",
		"82194ffffffffff",
	}
	gotStrs := make([]string, len(nc))
	for i, c := range nc {
		gotStrs[i] = CellToString(c)
	}
	if !reflect.DeepEqual(gotStrs, wantOrder) {
		t.Fatalf("CellNonChildren(%s) order mismatch:\ngot:  %v\nwant: %v", CellToString(h), gotStrs, wantOrder)
	}

	// Class II hexagon (res=2) and pentagon (res=0) invariants: exact expected counts, no children, no duplicates.
	for _, tc := range []struct {
		hex     string
		wantLen int
	}{
		{"821f87fffffffff", 6},
		{"831f80fffffffff", 6},
		{"8009fffffffffff", 5},
	} {
		cell, cErr := StringToCell(tc.hex)
		if cErr != nil {
			t.Fatalf("StringToCell(%s): %v", tc.hex, cErr)
		}
		res := Resolution(cell)
		children, chErr := CellToChildren(cell, res+1)
		if chErr != nil {
			t.Fatalf("CellToChildren(%s): %v", tc.hex, chErr)
		}
		chSet := make(map[uint64]bool, len(children))
		for _, c := range children {
			chSet[c] = true
		}
		gotNC, ncErr := CellNonChildren(cell)
		if ncErr != nil {
			t.Fatalf("CellNonChildren(%s): %v", tc.hex, ncErr)
		}
		if len(gotNC) != tc.wantLen {
			t.Fatalf("CellNonChildren(%s) len=%d, want %d", tc.hex, len(gotNC), tc.wantLen)
		}
		seen := make(map[uint64]bool, len(gotNC))
		for _, c := range gotNC {
			if chSet[c] {
				t.Fatalf("CellNonChildren(%s) returned child %s", tc.hex, CellToString(c))
			}
			if seen[c] {
				t.Fatalf("CellNonChildren(%s) returned duplicate %s", tc.hex, CellToString(c))
			}
			seen[c] = true
		}
	}

	// Max resolution has no children / nonChildren
	maxCell, err := LatLonToCell(48.8566, 2.3522, MaxRes)
	if err != nil {
		t.Fatalf("LatLonToCell MaxRes failed: %v", err)
	}
	maxNC, err := CellNonChildren(maxCell)
	if err != nil || len(maxNC) != 0 {
		t.Fatalf("expected nil/empty nonChildren at MaxRes, got %v err=%v", maxNC, err)
	}

	// Invalid cell returns ErrInvalidCell
	if _, err := CellNonChildren(0); err == nil {
		t.Fatalf("expected error for invalid H3 cell 0")
	}
}

func BenchmarkCellNonChildren(b *testing.B) {
	hex, err := StringToCell("811fbffffffffff")
	if err != nil {
		b.Fatal(err)
	}
	pent, err := StringToCell("8009fffffffffff")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Hexagon", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			out, cErr := CellNonChildren(hex)
			if cErr != nil || len(out) != 6 {
				b.Fatalf("unexpected result: len=%d err=%v", len(out), cErr)
			}
		}
	})
	b.Run("Pentagon", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			out, cErr := CellNonChildren(pent)
			if cErr != nil || len(out) != 5 {
				b.Fatalf("unexpected result: len=%d err=%v", len(out), cErr)
			}
		}
	})
}
