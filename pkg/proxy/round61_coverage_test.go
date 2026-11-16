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
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound61Coverage_AdminHealthMetadataStatsAndFieldCaps(t *testing.T) {
	// 1. evalWaitForNodesCondR61Admin all operators + invalid
	for _, tc := range []struct {
		expr    string
		actual  int
		want    bool
		wantErr bool
	}{
		{"", 1, true, false},
		{">=1", 1, true, false},
		{"<=2", 1, true, false},
		{">0", 1, true, false},
		{"<2", 1, true, false},
		{"ge(1)", 1, true, false},
		{"le(1)", 1, true, false},
		{"gt(1)", 1, false, false},
		{"lt(1)", 1, false, false},
		{"eq(1)", 1, true, false},
		{"1", 1, true, false},
		{"-5", 1, false, true},
		{"bogus", 1, false, true},
	} {
		got, err := evalWaitForNodesCondR61Admin(tc.expr, tc.actual)
		if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
			t.Fatalf("evalWaitForNodesCondR61Admin(%q, %d) = (%v, %v), want (%v, err=%v)", tc.expr, tc.actual, got, err, tc.want, tc.wantErr)
		}
	}

	// 2. formatBytesHuman across <=0, b, kb, mb, gb, tb
	if formatBytesHuman(0) != "0b" ||
		formatBytesHuman(512) != "512b" ||
		formatBytesHuman(2048) != "2.0kb" ||
		formatBytesHuman(2*1024*1024) != "2.0mb" ||
		formatBytesHuman(2*1024*1024*1024) != "2.0gb" ||
		formatBytesHuman(2*1024*1024*1024*1024) != "2.0tb" {
		t.Fatalf("unexpected formatBytesHuman outputs")
	}

	// 3. HTTP endpoints: /_cluster/health params, /_mapping/field metadata with include_defaults=true, /_field_caps numeric year index_filter, /_nodes/stats/ingest?human=true, /_cat/snapshots?time=ms
	_, h := newServerR61CRUDTest(t, "8.15.5")

	code, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPut, "/cov_idx", `{
		"mappings": {
			"_routing": {"required": false},
			"properties": {
				"year": {"type": "date", "format": "uuuu"},
				"title": {"type": "text"},
				"tag": {"type": "keyword"},
				"price": {"type": "double"},
				"loc": {"type": "geo_point"},
				"flat": {"type": "flattened"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create cov_idx failed: %d", code)
	}
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/cov_idx/_doc/1?refresh=true", `{"year":"2023","title":"quick brown fox","tag":"news","price":12.345,"loc":"52.37,4.91","flat":{"k":"v"}}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc failed: %d", code)
	}

	// Cluster health levels, wait_for_status, wait_for_nodes, wait_for_events, error cases
	for _, path := range []string{
		"/_cluster/health?level=shards&wait_for_status=green&wait_for_nodes=ge(1)&wait_for_events=normal&local=true",
		"/_cluster/health/cov_idx?level=indices",
	} {
		c, _, _, raw := doReqR61CRUDTest(t, h, http.MethodGet, path, "", nil)
		if c != http.StatusOK {
			t.Fatalf("GET %s expected 200, got %d: %s", path, c, raw)
		}
	}
	for _, badPath := range []string{
		"/_cluster/health?bogus_param=1",
		"/_cluster/health?level=bogus",
		"/_cluster/health?wait_for_status=purple",
		"/_cluster/health?wait_for_events=bogus",
		"/_cluster/health?local=notabool",
	} {
		c, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, badPath, "", nil)
		if c != http.StatusBadRequest {
			t.Fatalf("GET %s expected 400, got %d", badPath, c)
		}
	}

	// Metadata field mappings with include_defaults=true
	cMeta, _, _, rawMeta := doReqR61CRUDTest(t, h, http.MethodGet, "/cov_idx/_mapping/field/_id,_index,_source,_routing,_field_names,_ignored?include_defaults=true", "", nil)
	if cMeta != http.StatusOK || !strings.Contains(rawMeta, `"_field_names"`) || !strings.Contains(rawMeta, `"_ignored"`) {
		t.Fatalf("unexpected metadata field mapping (%d): %s", cMeta, rawMeta)
	}

	// POST /_field_caps with numeric year bounds inside bool (Must/Filter/Should/MustNot)
	cFC, _, _, rawFC := doReqR61CRUDTest(t, h, http.MethodPost, "/cov_idx/_field_caps?fields=*", `{
		"index_filter": {
			"bool": {
				"must": [{"range": {"year": {"gte": 2020, "lte": 2025}}}],
				"filter": [{"range": {"year": {"gt": 2019}}}],
				"should": [{"range": {"year": {"lt": 2030}}}],
				"must_not": [{"range": {"year": {"gte": 2099}}}]
			}
		}
	}`, nil)
	if cFC != http.StatusOK || !strings.Contains(rawFC, `"title"`) {
		t.Fatalf("POST /cov_idx/_field_caps failed (%d): %s", cFC, rawFC)
	}

	// Create + run ingest pipeline & query /_nodes/stats/ingest,indices?human=true
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ingest/pipeline/p_cov", `{"processors":[{"set":{"field":"ingested","value":true}}]}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/cov_idx/_doc/2?pipeline=p_cov&refresh=true", `{"year":"2024","title":"second doc","tag":"tech","price":5.0}`, nil)
	cStats, _, _, rawStats := doReqR61CRUDTest(t, h, http.MethodGet, "/_nodes/stats/ingest,indices?human=true", "", nil)
	if cStats != http.StatusOK || !strings.Contains(rawStats, `"p_cov"`) {
		t.Fatalf("GET /_nodes/stats/ingest,indices?human=true failed (%d): %s", cStats, rawStats)
	}

	// Snapshot repo + snapshot + /_cat/snapshots?time=ms&v=true
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_snapshot/repo_cov", `{"type":"fs","settings":{"location":"/tmp/repo_cov"}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_snapshot/repo_cov/snap_1?wait_for_completion=true", `{"indices":"cov_idx"}`, nil)
	cSnap, _, _, rawSnap := doReqR61CRUDTest(t, h, http.MethodGet, "/_cat/snapshots/repo_*?time=ms&v=true", "", nil)
	if cSnap != http.StatusOK || !strings.Contains(rawSnap, "snap_1") {
		t.Fatalf("GET /_cat/snapshots failed (%d): %s", cSnap, rawSnap)
	}
}

func TestRound61Coverage_SearchProfileNamedScoresFormatsSuggestAndPercolate(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	// 1. Direct search formatters, spatial extractors, fuzzy edits, geo distance helpers, flattened scalars
	if !isValidESDecimalFetchFormatR61Search("000.00#;-000.00#") ||
		isValidESDecimalFetchFormatR61Search("a;b;c") ||
		isValidESDecimalFetchFormatR61Search("") ||
		isValidESDecimalFetchFormatR61Search("0.0.0") ||
		isValidESDecimalFetchFormatR61Search("'unclosed0") ||
		isValidESDecimalFetchFormatR61Search("abc") ||
		isValidESDecimalFetchFormatR61Search("0[1]") {
		t.Fatalf("unexpected isValidESDecimalFetchFormatR61Search validation result")
	}
	if got := formatNumericWithDecimalPatternR61Search(-5.2, "000.00#"); got != "-005.20" {
		t.Fatalf("expected -005.20, got %q", got)
	}
	if got := formatNumericWithDecimalPatternR61Search(0.256, "00.0%"); got != "25.6%" {
		t.Fatalf("expected 25.6%%, got %q", got)
	}
	if got := formatNumericWithDecimalPatternR61Search(-7.4, "000"); got != "-007" {
		t.Fatalf("expected -007, got %q", got)
	}

	flatVals := collectAllFlattenedScalarStringsR61Search(map[string]any{
		"b": []any{"z", 10},
		"a": map[string]any{"inner": true, "nil": nil},
	})
	if len(flatVals) != 3 {
		t.Fatalf("unexpected collectAllFlattenedScalarStringsR61Search: %v", flatVals)
	}
	if collectAllFlattenedScalarStringsR61Search(nil) != nil {
		t.Fatalf("expected nil on empty flattened node")
	}

	gpBind := schema.FieldBinding{ESType: "geo_point", SourceJSONPath: []string{"loc"}}
	spatialDoc := map[string]any{
		"loc": []any{[]any{4.9, 52.3}, "51.5,-0.1"},
		"shp": map[string]any{"type": "Point", "coordinates": []any{4.9, 52.3}},
	}
	if wktOut, st, _, _ := extractFormattedSpatialFieldValuesR61Search(spatialDoc, "loc", "loc", gpBind, "wkt", false); st != 0 || len(wktOut) != 2 {
		t.Fatalf("unexpected WKT spatial output: st=%d out=%v", st, wktOut)
	}
	if gjOut, st, _, _ := extractFormattedSpatialFieldValuesR61Search(spatialDoc, "loc", "loc", gpBind, "geojson", false); st != 0 || len(gjOut) != 2 {
		t.Fatalf("unexpected GeoJSON spatial output: st=%d out=%v", st, gjOut)
	}
	if _, st, _, _ := extractFormattedSpatialFieldValuesR61Search(spatialDoc, "loc", "loc", gpBind, "bad_fmt", false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid spatial format, got %d", st)
	}
	gsBind := schema.FieldBinding{ESType: "geo_shape", SourceJSONPath: []string{"shp"}}
	if shpOut, st, _, _ := extractFormattedSpatialFieldValuesR61Search(spatialDoc, "shp", "shp", gsBind, "", false); st != 0 || len(shpOut) != 1 {
		t.Fatalf("unexpected geo_shape spatial output: st=%d out=%v", st, shpOut)
	}

	for _, unitStr := range []string{"2kilometers", "500meters", "1miles", "10yards", "10feet", "12inch", "1nmi", "3km", "50cm", "100mm", "2mi", "5yd", "6ft", "4in", "25m"} {
		m, ok := parseDistanceStringToMetersR61Search(unitStr)
		if !ok || m <= 0 {
			t.Fatalf("parseDistanceStringToMetersR61Search(%q) failed", unitStr)
		}
		_ = distanceMetersToGeohashPrecisionR61Search(m)
	}
	_ = distanceMetersToGeohashPrecisionR61Search(0.01)
	_ = distanceMetersToGeohashPrecisionR61Search(5_000_000)

	if resolveCompletionFuzzyEditsR61Search(nil, 2) != 0 ||
		resolveCompletionFuzzyEditsR61Search(nil, 4) != 1 ||
		resolveCompletionFuzzyEditsR61Search(nil, 7) != 2 ||
		resolveCompletionFuzzyEditsR61Search(int64(2), 3) != 2 ||
		resolveCompletionFuzzyEditsR61Search(float64(1), 3) != 1 ||
		resolveCompletionFuzzyEditsR61Search("0", 8) != 0 ||
		resolveCompletionFuzzyEditsR61Search("1", 8) != 1 ||
		resolveCompletionFuzzyEditsR61Search("2", 2) != 2 ||
		resolveCompletionFuzzyEditsR61Search("AUTO:2,5", 1) != 0 ||
		resolveCompletionFuzzyEditsR61Search("AUTO:2,5", 3) != 1 ||
		resolveCompletionFuzzyEditsR61Search("AUTO:2,5", 6) != 2 {
		t.Fatalf("unexpected resolveCompletionFuzzyEditsR61Search outputs")
	}

	// 2. Profile query & agg describers + HTTP search with profile:true, fields formats, and include_named_queries_score=true
	for _, rawReq := range []string{
		`{"query":{"match_none":{}}}`,
		`{"query":{"term":{"tag":"news"}}}`,
		`{"query":{"match":{"title":"fox"}}}`,
		`{"query":{"bool":{"must":[{"term":{"tag":"news"}}]}}}`,
		`{"query":{"constant_score":{"filter":{"term":{"tag":"news"}}}}}`,
		`{"query":{"range":{"price":{"gte":1}}}}`,
		`{"query":{"intervals":{"title":{"match":{"query":"fox"}}}}}`,
		`{"query":{"knn":{"field":"vec","query_vector":[1,0],"k":1}}}`,
	} {
		var sr esast.SearchRequest
		if err := json.Unmarshal([]byte(rawReq), &sr); err != nil {
			t.Fatalf("unmarshal %s: %v", rawReq, err)
		}
		qType, qDesc := describeProfileQueryNodeR61Search(&sr)
		if qType == "" || qDesc == "" {
			t.Fatalf("empty profile query description for %s", rawReq)
		}
	}
	for _, rawAgg := range []string{
		`{"terms":{"field":"tag"}}`,
		`{"histogram":{"field":"price","interval":10}}`,
		`{"date_histogram":{"field":"ts","calendar_interval":"day"}}`,
		`{"avg":{"field":"price"}}`,
		`{"sum":{"field":"price"}}`,
		`{"min":{"field":"price"}}`,
		`{"max":{"field":"price"}}`,
		`{"cardinality":{"field":"tag"}}`,
		`{"percentiles":{"field":"price"}}`,
		`{"boxplot":{"field":"price"}}`,
	} {
		var spec esast.AggSpec
		if err := json.Unmarshal([]byte(rawAgg), &spec); err != nil {
			t.Fatalf("unmarshal agg %s: %v", rawAgg, err)
		}
		if profileAggFactoryTypeR61Search(spec) == "" {
			t.Fatalf("empty profileAggFactoryTypeR61Search for %s", rawAgg)
		}
	}
	if profileAggFactoryTypeR61Search(esast.AggSpec{}) != "Aggregator" {
		t.Fatalf("expected Aggregator fallback")
	}

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/srch_cov", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"tag": {"type": "keyword"},
				"price": {"type": "double"},
				"loc": {"type": "geo_point"}
			}
		}
	}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/srch_cov/_doc/1?refresh=true", `{"title":"quick brown fox","tag":"news","price":42.5,"loc":"52.37,4.91"}`, nil)

	cProf, _, _, rawProf := doReqR61CRUDTest(t, h, http.MethodPost, "/srch_cov/_search?include_named_queries_score=true", `{
		"profile": true,
		"fields": [
			{"field": "price", "format": "000.00"},
			{"field": "loc", "format": "wkt"}
		],
		"query": {
			"bool": {
				"must": [{"match": {"title": {"query": "fox", "_name": "m_fox"}}}],
				"filter": [{"term": {"tag": {"value": "news", "_name": "f_news"}}}]
			}
		},
		"aggs": {
			"by_tag": {"terms": {"field": "tag"}},
			"bp": {"boxplot": {"field": "price"}}
		}
	}`, nil)
	if cProf != http.StatusOK || !strings.Contains(rawProf, `"profile"`) || !strings.Contains(rawProf, `"m_fox"`) {
		t.Fatalf("profile + named_queries_score search failed (%d): %s", cProf, rawProf)
	}

	// 3. evalMultiDocPercolateR61Search
	var percSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"title":{"type":"text"},"query":{"type":"percolator"}}}`), &percSpec)
	percSchema := schema.CompileIndexSchema("es_db", "perc_cov", &percSpec)
	var pq esast.PercolateQuery
	_ = json.Unmarshal([]byte(`{"field":"query","documents":[{"title":"hello world"},{"title":"goodbye"},{"title":"hello again"}]}`), &pq)
	matched, bestScore, slots, slotScores := evalMultiDocPercolateR61Search(
		percSchema,
		map[string]any{"query": map[string]any{"match": map[string]any{"title": "hello"}}},
		&pq,
	)
	if !matched || bestScore <= 0 || len(slots) != 2 || len(slotScores) != 2 {
		t.Fatalf("unexpected multi-doc percolate result: matched=%v best=%v slots=%v scores=%v", matched, bestScore, slots, slotScores)
	}
}

func TestRound61Coverage_TasksIngestAndPainlessProxyHelpers(t *testing.T) {
	srv, _ := newServerR61CRUDTest(t, "8.15.5")

	// 1. toFloat64Round61 & formatCatDurationNanosRound61
	for _, v := range []any{float64(1.5), float32(2.5), int(3), int64(4), int32(5), json.Number("6.5"), "7.5"} {
		if f, ok := toFloat64Round61(v); !ok || f <= 0 {
			t.Fatalf("toFloat64Round61(%T %v) failed", v, v)
		}
	}
	if _, ok := toFloat64Round61(struct{}{}); ok {
		t.Fatalf("expected struct to fail toFloat64Round61")
	}
	if formatCatDurationNanosRound61(5_000_000, "", 0, "5ms") != "5ms" ||
		formatCatDurationNanosRound61(5_000_000, "", 0, "") == "" ||
		formatCatDurationNanosRound61(5_000_000, "ms", 1_000_000, "") != "5" {
		t.Fatalf("unexpected formatCatDurationNanosRound61")
	}

	// 2. scoreDocAgainstESQueryRound61 across match_all, match_none, term, match (and/or), range, exists, bool, constant_score
	doc := map[string]any{
		"title": []any{"Quick Brown", "Fox Jumps"},
		"tag":   "News",
		"num":   25,
		"code":  "M50",
	}
	for _, tc := range []struct {
		raw       string
		wantMatch bool
	}{
		{`{"match_all":{"boost":2.0}}`, true},
		{`{"match_none":{}}`, false},
		{`{"term":{"tag":{"value":"news","case_insensitive":true,"boost":1.5}}}`, true},
		{`{"match":{"title":{"query":"quick fox","operator":"and","boost":2.0}}}`, true},
		{`{"match":{"title":{"query":"quick missing","operator":"and"}}}`, false},
		{`{"range":{"num":{"gt":10,"lte":30}}}`, true},
		{`{"range":{"code":{"gte":"M10","lte":"M90"}}}`, true},
		{`{"exists":{"field":"tag"}}`, true},
		{`{"bool":{"must":[{"term":{"tag":"News"}}],"filter":[{"range":{"num":{"gte":20}}}],"should":[{"match":{"title":"fox"}}],"must_not":[{"term":{"tag":"other"}}],"boost":1.5}}`, true},
		{`{"constant_score":{"filter":{"exists":{"field":"tag"}},"boost":3.0}}`, true},
	} {
		sc, err := evalTransientDocQueryScoreRound61(doc, json.RawMessage(tc.raw))
		if err != nil {
			t.Fatalf("evalTransientDocQueryScoreRound61(%s) err: %v", tc.raw, err)
		}
		if tc.wantMatch && sc <= 0 {
			t.Fatalf("expected positive score for %s, got %v", tc.raw, sc)
		}
		if !tc.wantMatch && sc != 0 {
			t.Fatalf("expected 0 score for %s, got %v", tc.raw, sc)
		}
	}

	// 3. formatIngestDateWithWeekYearRound61
	tm := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC) // ISO week 2022-W52-7
	if out, ok := formatIngestDateWithWeekYearRound61(tm, "YYYY-'W'ww-e"); !ok || out != "2022-W52-7" {
		t.Fatalf("expected 2022-W52-7, got %q (ok=%v)", out, ok)
	}
	if out, ok := formatIngestDateWithWeekYearRound61(tm, "YY-w||epoch_millis"); !ok || out != "22-52" {
		t.Fatalf("expected 22-52, got %q (ok=%v)", out, ok)
	}
	if _, ok := formatIngestDateWithWeekYearRound61(tm, "epoch_millis"); ok {
		t.Fatalf("expected builtin format to return false")
	}
	if _, ok := formatIngestDateWithWeekYearRound61(tm, "yyyy-MM-dd"); ok {
		t.Fatalf("expected non-week-year pattern to return false")
	}

	// 4. PrepareDocForRuntimeScriptWithRequestRound61, extractStoredScriptIDRound61, coerceEmittedRuntimeValuesRound61
	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"x":{"type":"long"}}}`), &spec)
	idxSchema := schema.CompileIndexSchema("es_db", "rt_cov", &spec)
	req := httptest.NewRequest(http.MethodPost, "/rt_cov/_search", nil)
	prep := srv.PrepareDocForRuntimeScriptWithRequestRound61(req, idxSchema, map[string]any{"x": 10})
	if prep["x"] == nil {
		t.Fatalf("expected prepared doc to retain x")
	}

	if id, ok := extractStoredScriptIDRound61(&esast.ScriptSpec{ID: "s1"}); !ok || id != "s1" {
		t.Fatalf("unexpected *ScriptSpec ID: %q %v", id, ok)
	}
	if id, ok := extractStoredScriptIDRound61(esast.ScriptSpec{ID: "s2"}); !ok || id != "s2" {
		t.Fatalf("unexpected ScriptSpec ID: %q %v", id, ok)
	}
	if id, ok := extractStoredScriptIDRound61(map[string]any{"script": map[string]any{"id": "s3"}}); !ok || id != "s3" {
		t.Fatalf("unexpected nested map script ID: %q %v", id, ok)
	}
	if _, ok := extractStoredScriptIDRound61("inline"); ok {
		t.Fatalf("expected string script to return ok=false")
	}

	now := time.Now().UTC()
	ipVal, _ := painless.ParseIPAddressVal("10.1.2.3")
	zdt := &painless.ZonedDateTimeVal{Time: now}
	if g := coerceEmittedRuntimeValuesRound61("geo_point", "", []any{&painless.GeoPointVal{Lat: 52.3, Lon: 4.9}, "51.5,-0.1", nil}, now); len(g) != 2 {
		t.Fatalf("unexpected geo_point coercion: %v", g)
	}
	if ipOut := coerceEmittedRuntimeValuesRound61("ip", "", []any{ipVal, "::ffff:192.168.0.1"}, now); len(ipOut) != 2 {
		t.Fatalf("unexpected ip coercion: %v", ipOut)
	}
	if uOut := coerceEmittedRuntimeValuesRound61("unsigned_long", "", []any{uint64(10), int(5), int64(6), json.Number("18446744073709551610"), "18446744073709551611", float64(42)}, now); len(uOut) != 6 {
		t.Fatalf("unexpected unsigned_long coercion: %v", uOut)
	}
	if lOut := coerceEmittedRuntimeValuesRound61("long", "", []any{int64(1), json.Number("2"), float64(3.9)}, now); len(lOut) != 3 {
		t.Fatalf("unexpected long coercion: %v", lOut)
	}
	if hfOut := coerceEmittedRuntimeValuesRound61("half_float", "", []any{3.14159}, now); len(hfOut) != 1 || math.IsNaN(hfOut[0].(float64)) {
		t.Fatalf("unexpected half_float coercion: %v", hfOut)
	}
	if flOut := coerceEmittedRuntimeValuesRound61("float", "", []any{1.25}, now); len(flOut) != 1 {
		t.Fatalf("unexpected float coercion: %v", flOut)
	}
	if dbOut := coerceEmittedRuntimeValuesRound61("double", "", []any{1.25}, now); len(dbOut) != 1 {
		t.Fatalf("unexpected double coercion: %v", dbOut)
	}
	if bOut := coerceEmittedRuntimeValuesRound61("boolean", "", []any{true, "true", "0"}, now); len(bOut) != 3 {
		t.Fatalf("unexpected boolean coercion: %v", bOut)
	}
	if dnOut := coerceEmittedRuntimeValuesRound61("date_nanos", "", []any{"2023-01-01T00:00:00.123456789Z"}, now); len(dnOut) != 1 {
		t.Fatalf("unexpected date_nanos coercion: %v", dnOut)
	}
	if dOut := coerceEmittedRuntimeValuesRound61("date", "", []any{zdt, int64(1000), json.Number("2000"), float64(3000), "2023-01-01T00:00:00Z"}, now); len(dOut) != 5 {
		t.Fatalf("unexpected date coercion: %v", dOut)
	}
	if kwOut := coerceEmittedRuntimeValuesRound61("keyword", "", []any{"hello", 123}, now); len(kwOut) != 2 {
		t.Fatalf("unexpected keyword coercion: %v", kwOut)
	}
}

func TestRound61Coverage_DiskUsageSuggestHighlightRuntimeTasksAndParsers(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	// 1. Create index with diverse types + completion contexts + index doc + run _disk_usage, _field_usage_stats, _capabilities, _scripts/painless/_context
	code, _, _, rawCreate := doReqR61CRUDTest(t, h, http.MethodPut, "/du_cov", `{
		"settings": {
			"index.highlight.max_analyzed_offset": 500
		},
		"mappings": {
			"properties": {
				"title": {"type": "text", "store": true},
				"tag": {"type": "keyword"},
				"cnt": {"type": "long"},
				"ul": {"type": "unsigned_long"},
				"flag": {"type": "boolean"},
				"ts": {"type": "date"},
				"ts_ns": {"type": "date_nanos"},
				"ip_addr": {"type": "ip"},
				"vec": {"type": "dense_vector", "dims": 2},
				"flat": {"type": "flattened"},
				"sug": {
					"type": "completion",
					"contexts": [
						{"name": "cat", "type": "category"},
						{"name": "loc", "type": "geo", "precision": "1km"}
					]
				}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create du_cov failed (%d): %s", code, rawCreate)
	}
	code, _, _, rawIdx := doReqR61CRUDTest(t, h, http.MethodPost, "/du_cov/_doc/1?routing=r1&refresh=true", `{
		"title": "alpha beta gamma",
		"tag": ["t2", "t1"],
		"cnt": 42,
		"ul": 100,
		"flag": true,
		"ts": "2024-01-02T03:04:05Z",
		"ts_ns": "2024-01-02T03:04:05.123456789Z",
		"ip_addr": "10.0.0.1",
		"vec": [0.5, 0.5],
		"flat": {"env": "prod", "ports": [80, 443]},
		"unmapped_dyn": "extra",
		"sug": {
			"input": ["starbucks", "starlight"],
			"weight": 10,
			"contexts": {
				"cat": ["coffee"],
				"loc": [{"lat": 52.37, "lon": 4.91}]
			}
		}
	}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index du_cov failed (%d): %s", code, rawIdx)
	}

	// _disk_usage & _field_usage_stats (both normal & synthetic _source)
	cDU, _, _, rawDU := doReqR61CRUDTest(t, h, http.MethodPost, "/du_cov/_disk_usage?run_expensive_tasks=true&human=true", "", nil)
	if cDU != http.StatusOK || !strings.Contains(rawDU, `"store_size"`) {
		t.Fatalf("POST /du_cov/_disk_usage failed (%d): %s", cDU, rawDU)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/du_synth", `{"mappings":{"_source":{"mode":"synthetic"},"properties":{"k":{"type":"keyword"}}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/du_synth/_doc/1?refresh=true", `{"k":"v"}`, nil)
	cDUS, _, _, rawDUS := doReqR61CRUDTest(t, h, http.MethodPost, "/du_synth/_disk_usage?run_expensive_tasks=true&human=true", "", nil)
	if cDUS != http.StatusOK || !strings.Contains(rawDUS, `"_recovery_source"`) {
		t.Fatalf("POST /du_synth/_disk_usage failed (%d): %s", cDUS, rawDUS)
	}
	if cNoExp, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/du_cov/_field_usage_stats", "", nil); cNoExp != http.StatusBadRequest {
		t.Fatalf("expected 400 without run_expensive_tasks, got %d", cNoExp)
	}
	cFUS, _, _, rawFUS := doReqR61CRUDTest(t, h, http.MethodGet, "/du_cov/_field_usage_stats?run_expensive_tasks=true", "", nil)
	if cFUS != http.StatusOK || !strings.Contains(rawFUS, `"shards"`) {
		t.Fatalf("GET /du_cov/_field_usage_stats failed (%d): %s", cFUS, rawFUS)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/du_synth/_field_usage_stats?run_expensive_tasks=true", "", nil)

	// _capabilities & Painless _context API
	if cCap, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/_capabilities", "", nil); cCap != http.StatusOK {
		t.Fatalf("GET /_capabilities failed: %d", cCap)
	}
	if cCtx, _, _, rawCtx := doReqR61CRUDTest(t, h, http.MethodGet, "/_scripts/painless/_context", "", nil); cCtx != http.StatusOK || !strings.Contains(rawCtx, "aggregation_selector") {
		t.Fatalf("GET /_scripts/painless/_context failed (%d): %s", cCtx, rawCtx)
	}
	if cSc, _, _, rawSc := doReqR61CRUDTest(t, h, http.MethodGet, "/_scripts/painless/_context/score", "", nil); cSc != http.StatusOK || !strings.Contains(rawSc, "saturation") {
		t.Fatalf("GET /_scripts/painless/_context/score failed (%d): %s", cSc, rawSc)
	}
	if cBadCtx, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/_scripts/painless/_context/unknown_ctx", "", nil); cBadCtx != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown painless context, got %d", cBadCtx)
	}

	// 2. Search with unified fields (* + metadata), docvalue_fields, topological runtime_mappings, completion suggest (fuzzy + geo + category), highlight
	cSrch, _, _, rawSrch := doReqR61CRUDTest(t, h, http.MethodPost, "/du_cov/_search", `{
		"runtime_mappings": {
			"rt_step2": {
				"type": "long",
				"script": "emit(doc['rt_step1'].value + 5)"
			},
			"rt_step1": {
				"type": "long",
				"script": "emit(doc['cnt'].value * 2)"
			}
		},
		"fields": ["*", "_id", "_index", "_routing", "_version", "_seq_no", "_primary_term", "_ignored"],
		"docvalue_fields": ["tag", "cnt", "ul", "flag", "ts", "ts_ns", "ip_addr"],
		"query": {
			"intervals": {
				"title": {
					"all_of": {
						"ordered": true,
						"intervals": [
							{"match": {"query": "alpha"}},
							{"match": {"query": "gamma"}}
						]
					}
				}
			}
		},
		"highlight": {
			"pre_tags": ["<em>"],
			"post_tags": ["</em>"],
			"max_analyzed_offset": 100,
			"fields": {
				"title": {}
			}
		},
		"suggest": {
			"coffee_sug": {
				"prefix": "starb",
				"completion": {
					"field": "sug",
					"skip_duplicates": true,
					"fuzzy": {"fuzziness": "AUTO"},
					"contexts": {
						"cat": [{"context": "coffee", "boost": 2}],
						"loc": [{"context": {"lat": 52.37, "lon": 4.91}, "precision": "5km", "neighbours": ["10km"]}]
					}
				}
			}
		}
	}`, nil)
	if cSrch != http.StatusOK || !strings.Contains(rawSrch, `"rt_step2"`) || !strings.Contains(rawSrch, `"starbucks"`) {
		t.Fatalf("unified search failed (%d): %s", cSrch, rawSrch)
	}

	// Highlight validation error paths (mismatched tags, max_analyzed_offset > index limit, fvh without term_vector)
	for _, badHL := range []string{
		`{"highlight":{"pre_tags":[],"fields":{"title":{}}}}`,
		`{"highlight":{"pre_tags":["<a>","<b>"],"post_tags":["</a>"],"fields":{"title":{}}}}`,
		`{"highlight":{"max_analyzed_offset":9999,"fields":{"title":{}}}}`,
		`{"highlight":{"type":"fvh","fields":{"tit*":{}}}}`,
	} {
		cBad, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPost, "/du_cov/_search", badHL, nil)
		if cBad != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad highlight %s, got %d", badHL, cBad)
		}
	}

	// 3. Direct parser/helper sweeps for remaining Round-61 branches
	vals := []any{int64(9), int64(2), uint64(8), uint64(1), float64(3.5), float64(1.2), true, false, "b", "a"}
	sortFetchedScalarSliceR61Search(vals)
	for _, v := range []any{int(1), int64(2), uint64(3), json.Number("4"), json.Number("4.9"), float64(5.0), float64(5.9), "6", "6.9"} {
		_, _ = parseExactInt64R61Search(v, true)
		_, _ = parseExactInt64R61Search(v, false)
		_, _, _ = parseExactUint64R61Search(v, true)
		_, _, _ = parseExactUint64R61Search(v, false)
	}
	for _, nsFmt := range []string{"", "epoch_nanos", "epoch_millis", "epoch_second", "strict_date_optional_time", "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"} {
		_, _ = parseEpochNanosExactR61Search(int64(1700000000), nsFmt)
		_, _ = parseEpochNanosExactR61Search(json.Number("1700000000123456789"), nsFmt)
		_, _ = parseEpochNanosExactR61Search("2023-11-14T22:13:20.123456789Z", nsFmt)
		_, _ = parseEpochNanosExactR61Search(float64(1700000000), nsFmt)
		_ = formatDateNanosExactR61Search(0, nsFmt)
		_ = formatDateNanosExactR61Search(-123456789, nsFmt)
		_, _ = parseEpochMillisExactR61Search(int64(1700000000), nsFmt)
		_, _ = parseEpochMillisExactR61Search(json.Number("1700000000"), nsFmt)
		_, _ = parseEpochMillisExactR61Search(float64(1700000000), nsFmt)
	}
	for _, esT := range []string{"integer", "unsigned_long", "double", "boolean", "ip", "date", "date_nanos"} {
		_ = isMalformedValueForBindingR61Search("not_valid_scalar", schema.FieldBinding{ESType: esT})
	}
	for _, msm := range []any{nil, -1, int64(-1), float64(-1), "50%", "-25%", "2", "-1"} {
		_ = resolveBoolMinShouldMatchR61Search(&esast.BoolQuery{MinimumShouldMatch: msm}, 4)
	}
	_, _ = parseMaxAnalyzedOffsetFromSettingsMapR61Search(map[string]any{"index": map[string]any{"highlight": map[string]any{"max_analyzed_offset": 250}}})
	_, _ = parseMaxAnalyzedOffsetFromSettingsMapR61Search(map[string]any{"highlight": map[string]any{"max_analyzed_offset": 300}})

	for _, rawTpl := range []string{``, `{`, `{"query":`, `{"query":{"bogus_query":{}}}`, `{"size":10`} {
		eType, _ := classifyInvalidRenderedTemplateJSONRound61([]byte(rawTpl))
		if eType == "" {
			t.Fatalf("expected error type for %q", rawTpl)
		}
	}
	for _, sl := range []any{"auto", "4", "0", "2000", json.Number("3"), json.Number("0"), json.Number("2000"), float64(2), float64(0), float64(2000)} {
		_, _, _ = parseSlicesSpecRound61(nil, sl)
	}

	// Runtime mapping cycle detection + stored script runtime context guard
	if _, err := TopoSortRuntimeMappingsRound61(map[string]esast.FieldProperty{
		"a": {Type: "long", Script: map[string]any{"source": "emit(doc['b'].value)"}},
		"b": {Type: "long", Script: map[string]any{"source": "emit(doc['a'].value)"}},
	}); err == nil || !strings.Contains(err.Error(), "Cycle detected") {
		t.Fatalf("expected runtime_mappings cycle error, got %v", err)
	}
	if st, _, rejected := CheckStoredScriptRuntimeFieldContextRound61("long_field"); !rejected || st != http.StatusBadRequest {
		t.Fatalf("expected long_field stored script context to be rejected")
	}
}

func TestRound61Coverage_IntervalsCompoundScriptScoreRuntimeRowsResolveAndIngest(t *testing.T) {
	srv, h := newServerR61CRUDTest(t, "8.15.5")

	// 1. evalRuntimeMappingsOnHitRows across all runtime field types
	var rtBaseSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"base":{"type":"long"},"txt":{"type":"text"}}}`), &rtBaseSpec); err != nil {
		t.Fatal(err)
	}
	rtSchema := schema.CompileIndexSchema("es_db", "rt_rows", &rtBaseSpec)
	rtReqMap := map[string]esast.FieldProperty{
		"rt_ul":   {Type: "unsigned_long", Script: map[string]any{"source": "emit(100)"}},
		"rt_long": {Type: "long", Script: map[string]any{"source": "emit(doc['base'].value + 1)"}},
		"rt_dbl":  {Type: "double", Script: map[string]any{"source": "emit(3.5)"}},
		"rt_flt":  {Type: "float", Script: map[string]any{"source": "emit(2.5)"}},
		"rt_hf":   {Type: "half_float", Script: map[string]any{"source": "emit(1.5)"}},
		"rt_bool": {Type: "boolean", Script: map[string]any{"source": "emit(true)"}},
		"rt_dt":   {Type: "date", Script: map[string]any{"source": "emit(1700000000000L)"}},
		"rt_dtns": {Type: "date_nanos", Script: map[string]any{"source": "emit(1700000000123456789L)"}},
		"rt_gp":   {Type: "geo_point", Script: map[string]any{"source": "emit(52.37, 4.91)"}},
		"rt_ip":   {Type: "ip", Script: map[string]any{"source": "emit('10.0.0.1')"}},
		"rt_kw":   {Type: "keyword", Script: map[string]any{"source": "return 'hello';"}},
	}
	rows := []HitRow{
		{ID: "1", Index: "rt_rows", Version: 2, Source: json.RawMessage(`{"base":10,"txt":"hello"}`)},
	}
	srv.evalRuntimeMappingsOnHitRows(rtSchema, rtReqMap, rows)

	// 2. evalIntervalsCompoundQueryR61Search across bool, constant_score, boosting, dis_max, nested (sum/max/min/avg/none), function_score, script
	var ivSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"tag": {"type": "keyword"},
			"items": {
				"type": "nested",
				"properties": {
					"body": {"type": "text"}
				}
			}
		}
	}`), &ivSpec); err != nil {
		t.Fatal(err)
	}
	ivSchema := schema.CompileIndexSchema("es_db", "iv_cov", &ivSpec)
	ivDoc := map[string]any{
		"title": "alpha beta gamma delta",
		"tag":   "news",
		"items": []any{
			map[string]any{"body": "one two three"},
			map[string]any{"body": "one four three"},
		},
	}
	for _, qJSON := range []string{
		`{"bool":{"must":[{"intervals":{"title":{"match":{"query":"alpha"},"boost":2.0}}}],"should":[{"intervals":{"title":{"match":{"query":"gamma"}}}}],"filter":[{"term":{"tag":"news"}}],"must_not":[{"intervals":{"title":{"match":{"query":"zzz"}}}}],"boost":1.5}}`,
		`{"constant_score":{"filter":{"intervals":{"title":{"match":{"query":"alpha"}}}},"boost":2.0}}`,
		`{"boosting":{"positive":{"intervals":{"title":{"match":{"query":"alpha"}}}},"negative":{"intervals":{"title":{"match":{"query":"beta"}}}},"negative_boost":0.5,"boost":1.2}}`,
		`{"dis_max":{"tie_breaker":0.3,"boost":1.5,"queries":[{"intervals":{"title":{"match":{"query":"alpha"}}}},{"intervals":{"title":{"match":{"query":"gamma"}}}}]}}`,
		`{"nested":{"path":"items","score_mode":"sum","boost":1.5,"query":{"intervals":{"items.body":{"all_of":{"intervals":[{"match":{"query":"one"}},{"match":{"query":"three"}}]}} }}}}`,
		`{"nested":{"path":"items","score_mode":"max","query":{"intervals":{"items.body":{"match":{"query":"one"}}}}}}`,
		`{"nested":{"path":"items","score_mode":"min","query":{"intervals":{"items.body":{"match":{"query":"one"}}}}}}`,
		`{"nested":{"path":"items","score_mode":"avg","query":{"intervals":{"items.body":{"match":{"query":"one"}}}}}}`,
		`{"nested":{"path":"items","score_mode":"none","query":{"intervals":{"items.body":{"match":{"query":"one"}}}}}}`,
		`{"function_score":{"query":{"intervals":{"title":{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}],"filter":{"script":{"source":"interval.gaps >= 0"}}}}}},"boost":2.0}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("unmarshal intervals compound %s: %v", qJSON, err)
		}
		matched, _, err := evalIntervalsCompoundQueryR61Search(ivSchema, ivDoc, &q, true, true)
		if err != nil || !matched {
			t.Fatalf("expected intervals compound match for %s: matched=%v err=%v", qJSON, matched, err)
		}
	}

	// 3. evalAndValidateSearchScriptScoreR61Search: valid, min_score filter, compile error, non-numeric error, negative score error, nested function_score
	for _, tc := range []struct {
		raw        string
		wantStatus int
		wantMatch  bool
	}{
		{`{"script_score":{"query":{"term":{"tag":"news"}},"script":{"source":"_score * 2.0 + 1.0"},"boost":1.5,"min_score":1.0}}`, 0, true},
		{`{"script_score":{"query":{"term":{"tag":"news"}},"script":{"source":"0.5"},"min_score":5.0}}`, 0, false},
		{`{"script_score":{"query":{"intervals":{"title":{"match":{"query":"alpha"}}}},"script":{"source":"_score + 1.0"}}}`, 0, true},
		{`{"script_score":{"query":{"match_all":{}},"script":{"source":"return 'not_a_number';"}}}`, http.StatusBadRequest, false},
		{`{"script_score":{"query":{"match_all":{}},"script":{"source":"return -5.0;"}}}`, http.StatusBadRequest, false},
		{`{"function_score":{"query":{"intervals":{"title":{"match":{"query":"alpha"}}}},"script_score":{"script":{"source":"_score + 2.0"}}}}`, 0, true},
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(tc.raw), &q); err != nil {
			t.Fatalf("unmarshal script_score %s: %v", tc.raw, err)
		}
		_, m, st, _ := evalAndValidateSearchScriptScoreR61Search(ivSchema, ivDoc, &q, 1.0, true)
		if st != tc.wantStatus || (st == 0 && m != tc.wantMatch) {
			t.Fatalf("script_score %s: got status=%d matched=%v, want status=%d matched=%v", tc.raw, st, m, tc.wantStatus, tc.wantMatch)
		}
	}

	// 4. Cluster remote settings + /_resolve/cluster/* + ingest convert processor simulate + _reindex / _update_by_query / _delete_by_query / _explain / _aliases
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_cluster/settings", `{
		"persistent": {
			"cluster.remote.rc_one.seeds": ["127.0.0.1:9300"],
			"cluster.remote.rc_one.skip_unavailable": true
		},
		"transient": {
			"cluster": {
				"remote": {
					"rc_two": {
						"seeds": ["127.0.0.1:9301"],
						"skip_unavailable": "false"
					}
				}
			}
		}
	}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/res_local_idx", `{"mappings":{"properties":{"msg":{"type":"text"},"n":{"type":"long"}}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_doc/1?refresh=true", `{"msg":"hello world","n":10}`, nil)

	cRes, _, _, rawRes := doReqR61CRUDTest(t, h, http.MethodGet, "/_resolve/cluster/*,rc_*:res_*?ignore_throttled=false&ignore_unavailable=true&allow_no_indices=true&expand_wildcards=open,closed", "", nil)
	if cRes != http.StatusOK || !strings.Contains(rawRes, "rc_one") {
		t.Fatalf("GET /_resolve/cluster failed (%d): %s", cRes, rawRes)
	}
	if cBadEW, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/_resolve/cluster/*?expand_wildcards=bogus", "", nil); cBadEW != http.StatusBadRequest {
		t.Fatalf("expected 400 on bogus expand_wildcards, got %d", cBadEW)
	}

	// Ingest convert processor across all target types
	cSim, _, _, rawSim := doReqR61CRUDTest(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"convert": {"field": "s_int", "type": "integer"}},
				{"convert": {"field": "s_long", "type": "long"}},
				{"convert": {"field": "s_flt", "type": "float"}},
				{"convert": {"field": "s_dbl", "type": "double"}},
				{"convert": {"field": "s_bool", "type": "boolean"}},
				{"convert": {"field": "s_str", "type": "string"}},
				{"convert": {"field": "s_ip", "type": "ip"}},
				{"convert": {"field": "s_auto_i", "type": "auto"}},
				{"convert": {"field": "s_auto_f", "type": "auto"}},
				{"convert": {"field": "s_auto_b", "type": "auto"}}
			]
		},
		"docs": [{
			"_source": {
				"s_int": "42",
				"s_long": "9000",
				"s_flt": "3.5",
				"s_dbl": "7.25",
				"s_bool": "true",
				"s_str": 12345,
				"s_ip": "192.168.1.1",
				"s_auto_i": "77",
				"s_auto_f": "88.5",
				"s_auto_b": "false"
			}
		}]
	}`, nil)
	if cSim != http.StatusOK || !strings.Contains(rawSim, `"12345"`) {
		t.Fatalf("ingest convert _simulate failed (%d): %s", cSim, rawSim)
	}

	// Aliases, _explain, _update_by_query, _reindex, _delete_by_query
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"res_local_idx","alias":"res_alias","routing":"r1","filter":{"term":{"n":10}}}}]}`, nil)
	if cExp, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_explain/1", `{"query":{"match":{"msg":"hello"}}}`, nil); cExp != http.StatusOK {
		t.Fatalf("_explain failed: %d", cExp)
	}
	if cUBQ, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_update_by_query?refresh=true&slices=2", `{"script":{"source":"ctx._source.n = ctx._source.n + 5"}}`, nil); cUBQ != http.StatusOK {
		t.Fatalf("_update_by_query failed: %d", cUBQ)
	}
	if cReidx, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPost, "/_reindex?refresh=true", `{"source":{"index":"res_local_idx"},"dest":{"index":"res_dest_idx"}}`, nil); cReidx != http.StatusOK {
		t.Fatalf("_reindex failed: %d", cReidx)
	}
	if cDBQ, _, _, _ := doReqR61CRUDTest(t, h, http.MethodPost, "/res_dest_idx/_delete_by_query?refresh=true", `{"query":{"match_all":{}}}`, nil); cDBQ != http.StatusOK {
		t.Fatalf("_delete_by_query failed: %d", cDBQ)
	}

	// 5. Remote reindex scroll execution via httptest.NewServer + composable template flat_settings & alias normalization + resolveWriteIndex
	remoteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/_search") && r.URL.Path != "/_search/scroll":
			_, _ = w.Write([]byte(`{"_scroll_id":"scr-1","hits":{"hits":[
				{"_id":"r1","_version":2,"_routing":"rtA","_source":{"msg":"from_remote_1","n":1}},
				{"_id":"r2","_version":1,"_source":{"msg":"from_remote_2","n":2}},
				{"_id":"r3","_version":1,"_source":{"msg":"skip_me","n":3}}
			]}}`))
		case r.URL.Path == "/_search/scroll" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"_scroll_id":"scr-1","hits":{"hits":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"succeeded":true}`))
		}
	}))
	defer remoteSrv.Close()

	remBody := []byte(`{
		"source": {
			"remote": {"host": "` + remoteSrv.URL + `", "username": "u", "password": "p", "socket_timeout": "5s", "connect_timeout": "5s"},
			"index": ["rem_idx"],
			"size": 10,
			"query": {"match_all": {}}
		},
		"dest": {
			"index": "rem_dest_idx",
			"routing": "=fixed_r"
		},
		"script": {
			"source": "if (ctx._source.n == 3) { ctx.op = 'noop'; } else { ctx._source.n = ctx._source.n + 10; }"
		}
	}`)
	remRec := httptest.NewRecorder()
	remReq := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=true&refresh=true", strings.NewReader(string(remBody)))
	srv.executeRemoteReindexRound61(remRec, remReq, time.Now(), remBody, map[string]any{
		"host":            remoteSrv.URL,
		"username":        "u",
		"password":        "p",
		"socket_timeout":  "5s",
		"connect_timeout": "5s",
		"headers":         map[string]any{"X-Test": "1"},
	}, -1, true, 0)
	if remRec.Code != http.StatusOK || !strings.Contains(remRec.Body.String(), `"created":2`) {
		t.Fatalf("executeRemoteReindexRound61 failed (%d): %s", remRec.Code, remRec.Body.String())
	}

	// Composable index template flat_settings & alias normalization
	flatCfg := formatCanonicalTemplateSettings(map[string]any{
		"number_of_shards": 1,
		"analysis": map[string]any{
			"analyzer": map[string]any{"my_an": map[string]any{"type": "standard", "stopwords": []any{"a", "the"}}},
		},
		"flag_true":  true,
		"flag_false": false,
		"ratio":      1.5,
		"whole_f":    2.0,
		"jnum":       json.Number("7"),
	}, true)
	nestedCfg := formatCanonicalTemplateSettings(map[string]any{"index": map[string]any{"number_of_replicas": int64(0)}, "refresh_interval": "1s"}, false)
	normAl := normalizeTemplateAliasesOutput(map[string]map[string]any{
		"a1": {"routing": "r1"},
		"a2": {"index_routing": 10, "search_routing": "s1"},
		"a3": nil,
	})
	if len(flatCfg) == 0 || len(nestedCfg) == 0 || normAl["a1"]["index_routing"] != "r1" {
		t.Fatalf("unexpected template settings/aliases normalization: %+v / %+v / %+v", flatCfg, nestedCfg, normAl)
	}
	if wIdx, err := srv.resolveWriteIndex("res_alias"); err != nil || wIdx != "res_local_idx" {
		t.Fatalf("resolveWriteIndex(res_alias) = %q, %v", wIdx, err)
	}

	// 6. Direct helpers: trimRespHitsToMax, collectAllLeafScalarPaths, renderMustacheSearchTemplate errors, normalizeIndexFilterQueryNumbersRound61, fieldIsStoredInSchemaR61Search, fieldIsMultiValuedInSchemaR61Search, /_sql & /_query
	r1 := map[string]any{"hits": map[string]any{"hits": []map[string]any{{"_id": "1"}, {"_id": "2"}}}}
	trimRespHitsToMax(r1, 1)
	r2 := map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"_id": "1"}, map[string]any{"_id": "2"}}}}
	trimRespHitsToMax(r2, 1)
	leafOut := make(map[string][]any)
	collectAllLeafScalarPaths(map[string]any{"a": map[string]any{"b": []any{1, "x", nil}}}, "", leafOut)
	if len(leafOut["a.b"]) != 2 {
		t.Fatalf("unexpected collectAllLeafScalarPaths: %+v", leafOut)
	}
	for _, badMustache := range []string{`{"query":{"unknown_q":{"x":1`, `{"query":{"match_all":{`, `{invalid`} {
		_, mErr := renderMustacheSearchTemplate(badMustache, map[string]any{})
		et, _ := mustacheErrTypeAndReason(mErr)
		if et == "" {
			t.Fatalf("expected mustache error type for %q", badMustache)
		}
	}

	var fltQ esast.Query
	_ = json.Unmarshal([]byte(`{"bool":{"must":[{"range":{"y":{"gte":2020,"lte":2024}}}],"filter":[{"range":{"y":{"gt":2019}}}],"should":[{"range":{"y":{"lt":2025}}}],"must_not":[{"range":{"y":{"gte":2099}}}]}}`), &fltQ)
	normalizeIndexFilterQueryNumbersRound61(&fltQ)
	_ = fieldIsStoredInSchemaR61Search(ivSchema, "title")
	_ = fieldIsMultiValuedInSchemaR61Search(ivSchema, "title")

	// /_search/template, /_sql, and /_query (ES|QL)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_search/template", `{"source":"{\"query\":{\"match\":{\"msg\":\"{{q}}\"}}}","params":{"q":"hello"}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/_sql?format=json", `{"query":"SELECT msg, n, n + 1 AS n2 FROM res_local_idx WHERE n >= 5 ORDER BY n DESC LIMIT 5"}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/_query?format=json", `{"query":"FROM res_local_idx | WHERE n >= 5 | EVAL n2 = n * 2 | STATS mx = MAX(n2) BY msg | LIMIT 5"}`, nil)

	// 7. Ecosystem / _cat / ILM / SLM / EQL / Termvectors / TermsEnum endpoint sweep
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ilm/policy/pol_cov", `{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"30d"}}}}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/_ilm/policy/pol_cov", "", nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/res_local_idx/_ilm/explain", "", nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_slm/policy/slm_cov", `{"schedule":"0 30 1 * * ?","name":"<daily-snap-{now/d}>","repository":"repo_cov"}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/_slm/policy/slm_cov", "", nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/_slm/status", "", nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_terms_enum", `{"field":"msg","string":"h"}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/res_local_idx/_termvectors/1", `{"fields":["msg"],"term_statistics":true,"field_statistics":true}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/_mtermvectors", `{"docs":[{"_index":"res_local_idx","_id":"1","fields":["msg"]}]}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/res_local_idx/_validate/query?explain=true&all_shards=true", `{"query":{"match":{"msg":"hello"}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/res_local_idx/_search_shards", "", nil)
	for _, catPath := range []string{
		"/_cat/health?v=true",
		"/_cat/nodes?v=true&h=ip,name,heap.percent,ram.percent,cpu,node.role,master",
		"/_cat/indices?v=true&bytes=b",
		"/_cat/shards?v=true",
		"/_cat/aliases?v=true",
		"/_cat/count?v=true",
		"/_cat/segments?v=true",
		"/_cat/fielddata?v=true",
		"/_cat/recovery?v=true",
		"/_cat/tasks?v=true",
		"/_cat/templates?v=true",
	} {
		cCat, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, catPath, "", nil)
		if cCat != http.StatusOK {
			t.Fatalf("GET %s expected 200, got %d", catPath, cCat)
		}
	}

	// 8. Rich ingest _simulate?verbose=true processor suite + writePainlessScriptErrorRound60 + isASCIIAlphaNotERound61
	cRichSim, _, _, rawRichSim := doReqR61CRUDTest(t, h, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", `{
		"pipeline": {
			"processors": [
				{"pipeline": {"name": "missing_sub_pipe", "ignore_missing_pipeline": true, "tag": "t_miss", "description": "desc"}},
				{"dissect": {"field": "line", "pattern": "%{client_ip} %{verb} %{url_enc}"}},
				{"kv": {"field": "kv_raw", "field_split": "&", "value_split": "="}},
				{"split": {"field": "csv_tags", "separator": ","}},
				{"sort": {"field": "csv_tags", "order": "asc"}},
				{"join": {"field": "csv_tags", "separator": "|", "target_field": "joined_tags"}},
				{"uppercase": {"field": "verb"}},
				{"lowercase": {"field": "mixed"}},
				{"trim": {"field": "padded"}},
				{"gsub": {"field": "padded", "pattern": "-", "replacement": "_"}},
				{"bytes": {"field": "mem_str", "target_field": "mem_bytes"}},
				{"urldecode": {"field": "url_enc", "target_field": "url_dec"}},
				{"html_strip": {"field": "html_raw"}},
				{"csv": {"field": "csv_row", "target_fields": ["col1", "col2"]}},
				{"json": {"field": "json_raw", "target_field": "json_obj"}},
				{"dot_expander": {"field": "dotted.leaf"}},
				{"append": {"field": "arr", "value": ["x", "y"]}},
				{"compact": {"field": "arr_nulls"}},
				{"fingerprint": {"fields": ["verb", "client_ip"], "target_field": "fp"}},
				{"uri_parts": {"field": "full_uri", "target_field": "uri_info"}},
				{"community_id": {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "source_port": 12345, "destination_port": 80, "transport": "tcp"}},
				{"rename": {"field": "old_k", "target_field": "new_k"}},
				{"remove": {"field": "drop_k"}}
			]
		},
		"docs": [{
			"_source": {
				"line": "10.0.0.1 get hello%20world",
				"kv_raw": "k1=v1&k2=v2",
				"csv_tags": "c,a,b",
				"mixed": "HeLLo",
				"padded": "  a-b  ",
				"mem_str": "2kb",
				"html_raw": "<p>clean</p>",
				"csv_row": "val1,val2",
				"json_raw": "{\"nested\":true}",
				"dotted.leaf": 99,
				"arr": ["z"],
				"arr_nulls": ["keep", null],
				"full_uri": "https://example.com:8443/api/v1?foo=bar#frag",
				"old_k": "renamed",
				"drop_k": "gone"
			}
		}]
	}`, nil)
	if cRichSim != http.StatusOK || !strings.Contains(rawRichSim, `"hello world"`) {
		t.Fatalf("rich ingest _simulate?verbose=true failed (%d): %s", cRichSim, rawRichSim)
	}

	_, _ = formatIngestDateWithWeekYearRound61(time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC), "year-ww")
	wErr1 := httptest.NewRecorder()
	writePainlessScriptErrorRound60(wErr1, http.StatusBadRequest, painless.ErrSelfReferencingIterable)
	wErr2 := httptest.NewRecorder()
	writePainlessScriptErrorRound60(wErr2, http.StatusBadRequest, &painless.ScriptCompileError{
		Message:  "compile failure",
		Position: &painless.ScriptErrorPosition{Offset: 1, Start: 0, End: 5},
	})
	wErr3 := httptest.NewRecorder()
	writePainlessScriptErrorRound60(wErr3, http.StatusBadRequest, json.Unmarshal([]byte("bad"), &struct{}{}))
}
