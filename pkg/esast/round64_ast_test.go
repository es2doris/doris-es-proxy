package esast

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestRound64_SpatialAndCountedASTExtensions(t *testing.T) {
	// 1. geo_line, cartesian_bounds, cartesian_centroid, geohex_grid, counted_terms
	reqJSON := `{
		"size": 0,
		"aggs": {
			"line": {
				"geo_line": {
					"point": {"field": "location"},
					"sort": {"field": "@timestamp"},
					"include_sort": true,
					"sort_order": "DESC",
					"size": 100
				}
			},
			"cb": {
				"cartesian_bounds": {"field": "point_f", "wrap_longitude": false}
			},
			"cc": {
				"cartesian_centroid": {"field": "shape_f"}
			},
			"hex": {
				"geohex_grid": {
					"field": "location",
					"precision": 5,
					"size": 10,
					"shard_size": 20,
					"bounds": {
						"top_left": "POINT (4.9 52.4)",
						"bottom_right": "POINT (5.0 52.3)"
					}
				}
			},
			"ct": {
				"counted_terms": {"field": "events"}
			}
		}
	}`
	var req SearchRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("unexpected agg unmarshal error: %v", err)
	}
	if req.Aggs["line"].GeoLine == nil || req.Aggs["line"].GeoLine.Point.Field != "location" ||
		req.Aggs["line"].GeoLine.Sort == nil || req.Aggs["line"].GeoLine.Sort.Field != "@timestamp" ||
		req.Aggs["line"].GeoLine.IncludeSort == nil || !*req.Aggs["line"].GeoLine.IncludeSort ||
		req.Aggs["line"].GeoLine.SortOrder != "DESC" || req.Aggs["line"].GeoLine.Size == nil || *req.Aggs["line"].GeoLine.Size != 100 {
		t.Fatalf("unexpected GeoLine: %+v", req.Aggs["line"].GeoLine)
	}
	cbTyped := req.Aggs["cb"].CartesianBounds
	if cbTyped == nil || cbTyped.Field != "point_f" || cbTyped.WrapLongitude == nil || *cbTyped.WrapLongitude {
		t.Fatalf("unexpected CartesianBounds: %+v", cbTyped)
	}
	ccTyped := req.Aggs["cc"].CartesianCentroid
	if ccTyped == nil || ccTyped.Field != "shape_f" {
		t.Fatalf("unexpected CartesianCentroid: %+v", ccTyped)
	}
	hexTyped := req.Aggs["hex"].GeoHexGrid
	if hexTyped == nil || hexTyped.Field != "location" || hexTyped.Precision == nil || *hexTyped.Precision != 5 ||
		hexTyped.Size != 10 || hexTyped.ShardSize != 20 || hexTyped.Bounds == nil {
		t.Fatalf("unexpected GeoHexGrid: %+v", hexTyped)
	}
	ctTyped := req.Aggs["ct"].CountedTerms
	if ctTyped == nil || ctTyped.Field != "events" {
		t.Fatalf("unexpected CountedTerms: %+v", ctTyped)
	}

	// Precision validation on geohex_grid
	for _, badHex := range []string{
		`{"aggs": {"g": {"geohex_grid": {"field": "loc", "precision": 16}}}}`,
		`{"aggs": {"g": {"geohex_grid": {"field": "loc", "precision": -1}}}}`,
		`{"aggs": {"g": {"geohex_grid": {"field": "loc", "precision": "1km"}}}}`,
	} {
		var badReq SearchRequest
		if err := json.Unmarshal([]byte(badHex), &badReq); err == nil {
			t.Fatalf("expected geohex_grid precision error for %s", badHex)
		}
	}

	// 2. geo_grid query: geohash, geotile, geohex
	for _, tc := range []struct {
		raw      string
		gridType string
		gridVal  string
	}{
		{`{"query": {"geo_grid": {"location": {"geohash": "u173zt90zc"}}}}`, "geohash", "u173zt90zc"},
		{`{"query": {"geo_grid": {"location": {"geotile": "22/2154259/1378425"}}}}`, "geotile", "22/2154259/1378425"},
		{`{"query": {"geo_grid": {"location": {"geohex": "8f1969c9b261656"}, "_name": "g1", "ignore_unmapped": true, "boost": 2.0}}}`, "geohex", "8f1969c9b261656"},
	} {
		var qReq SearchRequest
		if err := json.Unmarshal([]byte(tc.raw), &qReq); err != nil {
			t.Fatalf("unexpected geo_grid error for %s: %v", tc.raw, err)
		}
		gg := qReq.Query.GeoGrid
		if gg == nil || gg.Field != "location" || gg.GridType() != tc.gridType || gg.GridValue() != tc.gridVal {
			t.Fatalf("unexpected GeoGrid for %s: %+v", tc.raw, gg)
		}
		b, err := json.Marshal(gg)
		if err != nil || !strings.Contains(string(b), tc.gridVal) {
			t.Fatalf("GeoGrid MarshalJSON failed: %s (%v)", string(b), err)
		}
	}
	for _, badGrid := range []string{
		`{"query": {"geo_grid": {"location": {}}}}`,
		`{"query": {"geo_grid": {"location": {"geohash": "u1", "geohex": "85196953fffffff"}}}}`,
		`{"query": {"geo_grid": {"location": {"unknown": "x"}}}}`,
	} {
		var badReq SearchRequest
		if err := json.Unmarshal([]byte(badGrid), &badReq); err == nil {
			t.Fatalf("expected geo_grid error for %s", badGrid)
		}
	}
}

func TestRound64_PercolateLegacyTypesAndRangeBoundFormatting(t *testing.T) {
	// PercolateQuery with ES 7 document_type & type keys (percolator/11_basic_with_types.yml)
	var rDoc SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"percolate": {
				"field": "query",
				"document_type": "queries_type",
				"document": {"foo": "bar"}
			}
		}
	}`), &rDoc); err != nil {
		t.Fatalf("expected document_type on percolate with document to succeed: %v", err)
	}
	if rDoc.Query.Percolate.DocumentType != "queries_type" {
		t.Fatalf("expected DocumentType=queries_type, got %q", rDoc.Query.Percolate.DocumentType)
	}

	var rRef SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"percolate": {
				"field": "query",
				"index": "documents_index",
				"type": "documents_type",
				"id": "some_id"
			}
		}
	}`), &rRef); err != nil {
		t.Fatalf("expected type on percolate with index/id to succeed: %v", err)
	}
	if rRef.Query.Percolate.Type != "documents_type" {
		t.Fatalf("expected Type=documents_type, got %q", rRef.Query.Percolate.Type)
	}

	// formatRangeBoundKey Java Double.toString() scientific notation
	cases := []struct {
		in   any
		want string
	}{
		{float64(50), "50.0"},
		{float64(100), "100.0"},
		{float64(0), "0.0"},
		{float64(1.25), "1.25"},
		{float64(0.001), "0.001"},
		{float64(0.0005), "5.0E-4"},
		{float64(1e7), "1.0E7"},
		{float64(-9223372036854775808), "-9.223372036854776E18"},
		{json.Number("-9223372036854775808"), "-9.223372036854776E18"},
		{json.Number("50"), "50.0"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
	}
	for _, tc := range cases {
		if got := formatRangeBoundKey(tc.in); got != tc.want {
			t.Fatalf("formatRangeBoundKey(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
