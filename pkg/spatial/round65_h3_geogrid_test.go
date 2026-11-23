package spatial

import (
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
	wantSix := map[string]bool{
		"821ea7fffffffff": true,
		"82186ffffffffff": true,
		"82396ffffffffff": true,
		"821f17fffffffff": true,
		"821e37fffffffff": true,
		"82194ffffffffff": true,
	}
	if len(nc) != len(wantSix) {
		gotStrs := make([]string, len(nc))
		for i, c := range nc {
			gotStrs[i] = CellToString(c)
		}
		t.Fatalf("expected 6 interior-overlapping nonChildren, got %d: %v", len(nc), gotStrs)
	}
	for _, c := range nc {
		cs := CellToString(c)
		if !wantSix[cs] {
			t.Fatalf("unexpected boundary-only nonChild cell %s", cs)
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
