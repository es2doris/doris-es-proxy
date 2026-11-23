package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRound65Wave3B_ESQLSubfieldsGeoPointAndTokenCount(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	h := srv.Handler()

	// 1. Subfields (explicit keyword/normalizer/ignore_above + synthetic _source), [lon, lat] geo_point, and token_count
	rec := doRound63ModulesReq(t, h, http.MethodPut, "/esql_w3b_idx", `{
		"mappings": {
			"_source": {"mode": "synthetic"},
			"properties": {
				"emp_no": {"type": "integer"},
				"card": {
					"type": "keyword",
					"fields": {
						"text": {"type": "text"},
						"lower": {"type": "keyword", "normalizer": "lowercase"}
					}
				},
				"loc": {"type": "geo_point"},
				"loc_multi": {"type": "geo_point"},
				"tc": {"type": "token_count", "analyzer": "standard"}
			}
		}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRound63ModulesReq(t, h, http.MethodPut, "/esql_w3b_idx/_doc/1?refresh=true", `{
		"emp_no": 1,
		"card": "Jack of Diamonds",
		"loc": [10, 12],
		"loc_multi": [[20, 22], [10, 12]],
		"tc": "foo bar baz"
	}`)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("index doc failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{
		"query": "FROM esql_w3b_idx | KEEP emp_no, card, card.lower, loc, loc_multi, tc"
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ES|QL query failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Columns []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"columns"`
		Values [][]any `json:"values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal ES|QL response: %v", err)
	}
	if len(resp.Values) != 1 || len(resp.Values[0]) != 6 {
		t.Fatalf("unexpected ES|QL rows: %s", rec.Body.String())
	}
	row := resp.Values[0]
	if row[1] != "Jack of Diamonds" {
		t.Fatalf("expected card='Jack of Diamonds', got %#v", row[1])
	}
	if row[2] != "jack of diamonds" {
		t.Fatalf("expected card.lower='jack of diamonds', got %#v", row[2])
	}
	if row[3] != "POINT (10.0 12.0)" {
		t.Fatalf("expected loc='POINT (10.0 12.0)', got %#v", row[3])
	}
	if arr, ok := row[4].([]any); !ok || len(arr) != 2 || arr[0] != "POINT (10.0 12.0)" || arr[1] != "POINT (20.0 22.0)" {
		t.Fatalf("expected multi-valued geo_point sorted WKT, got %#v", row[4])
	}
	if tcNum, ok := row[5].(float64); !ok || tcNum != 3 {
		t.Fatalf("expected token_count=3, got %#v", row[5])
	}
}

func TestRound65Wave3B_EQLColumnSuggestionScope(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	h := srv.Handler()

	// Dynamic string field (`text` + `.keyword` subfield) should only suggest `user`
	// when `user` is validly referenced in the query, while explicit `keyword` always suggests it.
	rec := doRound63ModulesReq(t, h, http.MethodPut, "/eql_dyn_idx/_doc/1?refresh=true", `{
		"@timestamp": "2020-02-06T12:34:56Z",
		"event": [{"category": "network"}],
		"user": "ADMIN",
		"id": 123
	}`)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("index dyn eql doc failed: %d %s", rec.Code, rec.Body.String())
	}

	noSugg := doRound63ModulesReq(t, h, http.MethodPost, "/eql_dyn_idx/_eql/search", `{
		"query": "sequence with maxspan=10d [network where used == \"ADMIN\"] [network where id == 123]"
	}`)
	if noSugg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown column, got %d %s", noSugg.Code, noSugg.Body.String())
	}
	var errNoSugg struct {
		Error struct {
			Reason string `json:"reason"`
		} `json:"error"`
	}
	_ = json.Unmarshal(noSugg.Body.Bytes(), &errNoSugg)
	wantNoSugg := "Found 1 problem\nline 1:42: Unknown column [used]"
	if errNoSugg.Error.Reason != wantNoSugg {
		t.Fatalf("expected exact error %q, got %q", wantNoSugg, errNoSugg.Error.Reason)
	}

	withSugg := doRound63ModulesReq(t, h, http.MethodPost, "/eql_dyn_idx/_eql/search", `{
		"query": "sequence with maxspan=10d [network where user == \"ADMIN\"] ![network where used == \"SYSTEM\"]"
	}`)
	if withSugg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown column with suggestion, got %d %s", withSugg.Code, withSugg.Body.String())
	}
	var errWithSugg struct {
		Error struct {
			Reason string `json:"reason"`
		} `json:"error"`
	}
	_ = json.Unmarshal(withSugg.Body.Bytes(), &errWithSugg)
	wantWithSugg := "Found 1 problem\nline 1:75: Unknown column [used], did you mean [user]?"
	if errWithSugg.Error.Reason != wantWithSugg {
		t.Fatalf("expected exact error %q, got %q", wantWithSugg, errWithSugg.Error.Reason)
	}
}

func TestRound65Wave3B_IngestCombinedApacheECSv1(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	h := srv.Handler()

	rec := doRound63ModulesReq(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"grok": {
						"field": "log",
						"ecs_compatibility": "v1",
						"patterns": ["%{COMBINEDAPACHELOG}"]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"log": "89.160.20.128 - - [08/Sep/2014:02:54:42 +0000] \"GET /index.html HTTP/1.1\" 200 175208 \"http://example.com/ref\" \"Mozilla/5.0\""
				}
			}
		]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate failed: %d %s", rec.Code, rec.Body.String())
	}
	var simResp struct {
		Docs []struct {
			Doc struct {
				Source map[string]any `json:"_source"`
			} `json:"doc"`
		} `json:"docs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &simResp); err != nil {
		t.Fatalf("unmarshal simulate response: %v", err)
	}
	if len(simResp.Docs) != 1 {
		t.Fatalf("expected 1 doc, got %s", rec.Body.String())
	}
	src := simResp.Docs[0].Doc.Source
	srcObj, _ := src["source"].(map[string]any)
	if srcObj["address"] != "89.160.20.128" {
		t.Fatalf("expected source.address=89.160.20.128, got %+v", src)
	}
	if _, hasUser := src["user"]; hasUser {
		t.Fatalf("expected '-' ident/auth not to populate user, got %+v", src["user"])
	}
	if _, hasClient := src["client"]; hasClient {
		t.Fatalf("expected COMBINEDAPACHELOG ECS v1 not to populate client, got %+v", src["client"])
	}
}

func TestRound65Wave3B_GeoGridQuantizedGeoHexAndGeoTile(t *testing.T) {
	// 1. GeoHex WKT must be Lucene 32-bit quantized and nonChildren must exclude boundary-only corner cells
	hxDoc := map[string]any{"geocell": "811fbffffffffff"}
	if err := ApplyGeoGridProcessorR64(hxDoc, map[string]any{
		"field":              "geocell",
		"tile_type":          "geohex",
		"target_format":      "wkt",
		"target_field":       "shape",
		"non_children_field": "nonChildren",
	}); err != nil {
		t.Fatalf("ApplyGeoGridProcessorR64 geohex failed: %v", err)
	}
	wantPrefix := "POLYGON ((1.1885095294564962 49.470279179513454,"
	if shapeStr, _ := hxDoc["shape"].(string); !strings.HasPrefix(shapeStr, wantPrefix) {
		t.Fatalf("expected quantized geohex WKT starting with %q, got %q", wantPrefix, shapeStr)
	}
	nc, _ := hxDoc["nonChildren"].([]any)
	if len(nc) != 6 {
		t.Fatalf("expected 6 interior-overlapping nonChildren, got %d (%v)", len(nc), nc)
	}

	// 2. GeoTile 4/8/5 top latitude matches Mercator formula without ULP drift
	gtDoc := map[string]any{"geocell": "4/8/5"}
	if err := ApplyGeoGridProcessorR64(gtDoc, map[string]any{
		"field":         "geocell",
		"tile_type":     "geotile",
		"target_format": "wkt",
		"target_field":  "shape",
	}); err != nil {
		t.Fatalf("ApplyGeoGridProcessorR64 geotile failed: %v", err)
	}
	if shapeStr, _ := gtDoc["shape"].(string); !strings.Contains(shapeStr, "55.77657301866769,") {
		t.Fatalf("expected geotile WKT containing 55.77657301866769, got %q", shapeStr)
	}
}
