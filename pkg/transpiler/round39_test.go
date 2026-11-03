package transpiler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound39_F1_TranspilerRejectsIndexFalseAndReturnsFalseOnEnabledFalse(t *testing.T) {
	f := false
	s := schema.CompileIndexSchema("es_db", "idx_r39_f1", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":   {Type: "text"},
			"secret":  {Type: "keyword", Index: &f},
			"payload": {Type: "object", Enabled: &f},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. Term query on index: false returns search_phase_execution_exception error
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"term":{"secret":"abc"}}}`), &req1); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.BuildSearchPlan(&req1); err == nil || !strings.Contains(err.Error(), "cannot search on field [secret] since it is not indexed") {
		t.Fatalf("expected not-indexed error on secret, got %v", err)
	}

	// 2. Term or exists query on enabled: false object compiles to FALSE without error
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"bool":{"should":[{"term":{"payload.inner":"val"}},{"exists":{"field":"payload.inner"}}]}}}`), &req2); err != nil {
		t.Fatal(err)
	}
	res2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatalf("unexpected error on enabled:false query: %v", err)
	}
	if !strings.Contains(res2.HitsSQL, "FALSE") {
		t.Fatalf("expected FALSE in HitsSQL for enabled:false field, got %s", res2.HitsSQL)
	}
}

func TestRound39_F4_BulkNDJSONNumericIDAndUnderscoreMetadata(t *testing.T) {
	ndjson := `{"index":{"_index":"test","_id":12345,"_routing":"r1","_version":7,"_version_type":"external"}}` + "\n" +
		`{"title":"doc1"}` + "\n" +
		`{"delete":{"_index":"test","_id":99,"_routing":"r2","_version":8,"_version_type":"external_gte"}}` + "\n"
	items, err := esast.ParseBulkNDJSON(strings.NewReader(ndjson), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].ID != "12345" || items[0].Routing != "r1" || items[0].Version == nil || *items[0].Version != 7 || items[0].VersionType != "external" {
		t.Fatalf("unexpected item[0]: %+v", items[0])
	}
	if items[1].ID != "99" || items[1].Routing != "r2" || items[1].Version == nil || *items[1].Version != 8 || items[1].VersionType != "external_gte" {
		t.Fatalf("unexpected item[1]: %+v", items[1])
	}
}

func TestRound39_F5_F6_BoostAndTermsCaretAndGeoDistanceSortOptions(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r39_f5", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"status":   {Type: "keyword"},
			"tags":     {Type: "keyword"},
			"required": {Type: "integer"},
			"location": {Type: "geo_point"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. match_all boost and exists boost
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"bool":{"should":[{"match_all":{"boost":2.5}},{"exists":{"field":"status","boost":3.5}}]}}}`), &req1); err != nil {
		t.Fatal(err)
	}
	res1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res1.HitsSQL, "2.5") || !strings.Contains(res1.HitsSQL, "3.5") {
		t.Fatalf("expected match_all boost 2.5 and exists boost 3.5 in SQL, got %s", res1.HitsSQL)
	}

	// 2. terms and terms_set with field^boost caret suffix
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"bool":{"must":[{"terms":{"status^2.0":["active","pending"],"boost":1.5}},{"terms_set":{"tags^3.0":{"terms":["a","b"],"minimum_should_match_field":"required","boost":2.0}}}]}}}`), &req2); err != nil {
		t.Fatal(err)
	}
	res2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res2.HitsSQL, "status^") || strings.Contains(res2.HitsSQL, "tags^") {
		t.Fatalf("expected caret suffix to be stripped from column name, got %s", res2.HitsSQL)
	}
	if !strings.Contains(res2.HitsSQL, "`f__status` IN ('active', 'pending')") {
		t.Fatalf("expected f__status IN clause, got %s", res2.HitsSQL)
	}

	// 3. _geo_distance sort preserves sibling options and compiles to ST_Distance_Sphere
	var req3 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"sort":[{"_geo_distance":{"location":{"lat":40.7128,"lon":-74.0060},"order":"asc"},"unit":"km","distance_type":"arc","ignore_unmapped":true}]}`), &req3); err != nil {
		t.Fatal(err)
	}
	geoOpts, _ := req3.Sort[0].Entry.Script.(map[string]any)
	if geoOpts["unit"] != "km" || geoOpts["distance_type"] != "arc" {
		t.Fatalf("expected _geo_distance sibling options to be preserved, got %+v", geoOpts)
	}
	res3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res3.HitsSQL, "ST_Distance_Sphere(") {
		t.Fatalf("expected ST_Distance_Sphere in ORDER BY SQL, got %s", res3.HitsSQL)
	}
}

func TestRound39_F7_F8_F10_F13_Doris4SearchAndFiltersOtherBucketAndScriptPushdownAndZeroBoost(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r39_f7", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":  {Type: "text"},
			"status": {Type: "keyword", Normalizer: "lowercase"},
			"price":  {Type: "double"},
			"qty":    {Type: "integer"},
		},
	})
	tr4 := NewTranspiler(s, TranspilerOptions{UseDoris4SearchFunc: true})

	// F7: Doris 4 SEARCH() fallback on backslash, dangling operator, and uppercase keyword query
	for _, qStr := range []string{`title:foo\+bar`, `title:(foo AND)`, `status:ACTIVE`} {
		var req esast.SearchRequest
		_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":`+strconvQuote(qStr)+`}}}`), &req)
		res, err := tr4.BuildSearchPlan(&req)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", qStr, err)
		}
		if strings.Contains(res.HitsSQL, "SEARCH(") {
			t.Fatalf("expected %q to fall back from Doris 4 SEARCH(), got %s", qStr, res.HitsSQL)
		}
	}

	// F8: filters sub-agg with empty filters: {} and other_bucket: true emits _other_ bucket SQL
	tr := NewTranspiler(s, TranspilerOptions{})
	var req8 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"size":0,"aggs":{"by_status":{"terms":{"field":"status"},"aggs":{"f":{"filters":{"other_bucket":true,"filters":{}}}}}}}`), &req8); err != nil {
		t.Fatal(err)
	}
	res8, err := tr.BuildSearchPlan(&req8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res8.AggsSQL, "_other_") {
		t.Fatalf("expected _other_ in AggsSQL for empty filters with other_bucket:true, got %s", res8.AggsSQL)
	}

	// F10: boolean script query comparison pushdown to SQL WHERE
	var req10 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"script":{"script":{"source":"doc['price'].value > params.min_p && doc['qty'].size() > 0","params":{"min_p":25}}}}}`), &req10); err != nil {
		t.Fatal(err)
	}
	res10, err := tr.BuildSearchPlan(&req10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res10.HitsSQL, "(`f__price` > 25)") || !strings.Contains(res10.HitsSQL, "`f__qty` IS NOT NULL") {
		t.Fatalf("expected script comparison pushdown in SQL WHERE, got %s", res10.HitsSQL)
	}

	// F13: boost: 0 survives JSON round-trip on TermEntry, MatchEntry, PrefixEntry, WildcardEntry, RegexpEntry, FuzzyEntry, PhraseEntry
	rawJSON := `{"query":{"bool":{"should":[{"term":{"status":{"value":"ok","boost":0}}},{"match":{"title":{"query":"hi","boost":0}}},{"prefix":{"status":{"value":"o","boost":0}}},{"wildcard":{"status":{"value":"o*","boost":0}}},{"regexp":{"status":{"value":"o.*","boost":0}}},{"fuzzy":{"status":{"value":"ok","boost":0}}},{"match_phrase":{"title":{"query":"hi","boost":0}}}]}}}`
	var origReq esast.SearchRequest
	if err := json.Unmarshal([]byte(rawJSON), &origReq); err != nil {
		t.Fatal(err)
	}
	marshaled, err := json.Marshal(&origReq)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripReq esast.SearchRequest
	if err := json.Unmarshal(marshaled, &roundTripReq); err != nil {
		t.Fatal(err)
	}
	res13, err := tr.BuildSearchPlan(&roundTripReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res13.HitsSQL, "THEN 1.0000") || strings.Count(res13.HitsSQL, "THEN 0.0000") != 7 {
		t.Fatalf("expected boost:0 to be preserved across round-trip, got %s", res13.HitsSQL)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
