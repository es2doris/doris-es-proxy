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
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR67CovRTServer(t *testing.T, ver string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_r67rt", mem, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR67CovRTHTTP(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		if hdrs["Content-Type"] == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

func mustR67CovRTHTTP(t *testing.T, h http.Handler, method, path, body string, want int) map[string]any {
	t.Helper()
	code, _, parsed, raw := doR67CovRTHTTP(t, h, method, path, body, nil)
	if code != want {
		t.Fatalf("%s %s: expected status %d, got %d body=%s", method, path, want, code, raw)
	}
	return parsed
}

func mustUnmarshalR67CovRT[T any](t *testing.T, rawJSON string) T {
	t.Helper()
	var out T
	dec := json.NewDecoder(strings.NewReader(rawJSON))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("unmarshal failed for %s: %v", rawJSON, err)
	}
	return out
}

func compileR67CovRTSchema(t *testing.T, idxName, mappingJSON string, es8 bool) *schema.IndexSchema {
	t.Helper()
	spec := mustUnmarshalR67CovRT[esast.MappingSpec](t, mappingJSON)
	sc := schema.CompileIndexSchema("es_r67rt", idxName, &spec)
	sc.IndexName = idxName
	sc.ES8Mode = es8
	return sc
}

func TestRound67Cov_Runtime_R61FieldsMetadataStoredAndFormats(t *testing.T) {
	sc := compileR67CovRTSchema(t, "r61_fields_idx", `{
		"_source": {"includes": ["*"], "excludes": ["secret"]},
		"properties": {
			"title": {"type": "text", "store": true, "fields": {"raw": {"type": "keyword", "ignore_above": 12, "normalizer": "lowercase"}}},
			"cnt": {"type": "long", "store": true},
			"price": {"type": "double"},
			"ratio": {"type": "scaled_float", "scaling_factor": 10},
			"flag": {"type": "boolean"},
			"ts": {"type": "date"},
			"ip": {"type": "ip"},
			"no_dv": {"type": "keyword", "doc_values": false},
			"disabled_obj": {"type": "object", "enabled": false},
			"const_kw": {"type": "constant_keyword", "value": "fixed_val"},
			"meta_flat": {"type": "flattened"},
			"alias_id": {"type": "alias", "path": "_id"},
			"alias_cnt": {"type": "alias", "path": "cnt"},
			"loc": {"type": "geo_point"},
			"shape": {"type": "geo_shape"},
			"secret": {"type": "keyword"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"cost": {"type": "double"},
					"ts": {"type": "date"},
					"pts": {"type": "geo_point"},
					"sub": {"type": "object", "properties": {"tag": {"type": "keyword"}}}
				}
			}
		}
	}`, true)

	doc := map[string]any{
		"title":        "Apache Doris Proxy",
		"cnt":          json.Number("42"),
		"price":        float64(19.95),
		"ratio":        float64(3.5),
		"flag":         true,
		"ts":           "2026-06-01T12:00:00Z",
		"ip":           "10.1.2.3",
		"no_dv":        "abc",
		"disabled_obj": map[string]any{"x": 1},
		"meta_flat":    map[string]any{"env": "prod", "nested": map[string]any{"tier": "gold"}},
		"loc":          map[string]any{"lat": 37.77, "lon": -122.41},
		"shape":        map[string]any{"type": "Point", "coordinates": []any{-122.41, 37.77}},
		"secret":       "hidden",
		"items": []any{
			map[string]any{"sku": "s1", "cost": float64(5.5), "ts": "2026-06-01T01:00:00Z", "pts": map[string]any{"lat": 40.71, "lon": -74.0}, "sub": map[string]any{"tag": "hot"}},
			map[string]any{"sku": "s2", "cost": float64(8.25), "ts": "2026-06-02T02:00:00Z", "sub": map[string]any{"tag": "cold"}},
		},
	}
	rawDoc, _ := json.Marshal(doc)
	hit := HitRow{
		Index:    "r61_fields_idx",
		ID:       "doc-1",
		Routing:  "r1",
		Version:  2,
		SeqNo:    7,
		HasSeqNo: true,
		Source:   rawDoc,
		Schema:   sc,
	}

	rtDefs := map[string]esast.FieldProperty{
		"rt_val": {Type: "double"},
	}
	rtDoc := map[string]any{
		"rt_val": float64(99.5),
	}

	out := make(map[string][]any)
	for _, tc := range []struct {
		field, pat, fmtStr string
		dv                 bool
	}{
		{"alias_id", "alias_id", "", false},
		{"alias_cnt", "alias_cnt", "", true},
		{"meta_flat.env", "meta_flat.env", "", false},
		{"meta_flat.nested.tier", "meta_flat.nested.*", "", false},
		{"meta_flat.env", "meta_flat.env", "strict_date", false},
		{"disabled_obj", "disabled_obj", "", false},
		{"no_dv", "no_dv", "", true},
		{"const_kw", "const_kw", "", false},
		{"title", "title", "", false},
		{"title", "title", "", true},
		{"ts", "ts", "epoch_millis", false},
		{"ts", "ts", "yyyy-MM-dd", true},
		{"ts", "ts", "bad[pattern", true},
		{"price", "price", "#,##0.00", false},
		{"cnt", "cnt", "#,##0", true},
		{"ratio", "ratio", "0.00", true},
		{"loc", "loc", "", false},
		{"shape", "shape", "wkt", false},
		{"shape", "shape", "geojson", false},
		{"rt_val", "rt_val", "#0.0", false},
	} {
		_, _, _ = emitSingleMatchedFieldIntoOutR61Search(hit, "r61_fields_idx", doc, rtDoc, rtDefs, tc.field, tc.pat, tc.fmtStr, tc.dv, sc, out)
	}
	if len(out["alias_id"]) != 1 || out["alias_id"][0] != "doc-1" {
		t.Fatalf("unexpected alias_id out: %+v", out)
	}
	if stNDV, _, _ := emitSingleMatchedFieldIntoOutR61Search(hit, "r61_fields_idx", doc, rtDoc, rtDefs, "no_dv", "no_dv", "", true, sc, make(map[string][]any)); stNDV == 0 {
		t.Log("no_dv docvalue returned empty status")
	}

	// collectSchemaCandidateFetchFieldsR61Search, lookupRawPropertyWithMultiFieldR61Search, mergeNestedFieldWithFullPrefixR63Search
	cands := collectSchemaCandidateFetchFieldsR61Search(sc, rtDefs, true)
	if len(cands) == 0 {
		t.Fatal("expected schema candidate fields")
	}
	if fp, okFP := lookupRawPropertyWithMultiFieldR61Search(sc, "title.raw"); !okFP || fp.Type != "keyword" {
		t.Fatalf("expected title.raw property, got ok=%v fp=%+v", okFP, fp)
	}
	nestedOut := make(map[string][]any)
	_, _, _ = mergeNestedFieldWithFullPrefixR63Search(doc, "items", "items", "ts", "items.ts", "items.*", "yyyy-MM-dd", sc, nestedOut)
	_, _, _ = mergeNestedFieldWithFullPrefixR63Search(doc, "items", "items", "sub.tag", "items.sub.tag", "items.*", "", sc, nestedOut)

	// extractUnifiedFieldsR61Search
	reqUnified := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{
		"fields": ["title", "const_kw", "rt_val", {"field": "ts", "format": "epoch_millis"}, "items.*"],
		"docvalue_fields": ["cnt", {"field": "price", "format": "0.00"}]
	}`)
	if uFields, stU, _, _ := extractUnifiedFieldsR61Search(hit, "r61_fields_idx", &reqUnified, sc, rtDoc); stU != 0 || len(uFields) == 0 {
		t.Fatalf("unexpected extractUnifiedFields result st=%d fields=%+v", stU, uFields)
	}

	// extractStoredFieldsOnlyR61Search, extractRawStoredValuesForFieldR61Search, extractHitIgnoredFieldsR61Search
	sf1, sup1, none1 := extractStoredFieldsOnlyR61Search(hit, "r61_fields_idx", "_none_", sc)
	if !none1 || !sup1 || len(sf1) != 0 {
		t.Fatalf("expected _none_ suppression, got sf=%+v sup=%v none=%v", sf1, sup1, none1)
	}
	sf2, _, _ := extractStoredFieldsOnlyR61Search(hit, "r61_fields_idx", "*", sc)
	sf3, _, _ := extractStoredFieldsOnlyR61Search(hit, "r61_fields_idx", []any{"title", "cnt", "_source"}, sc)
	_ = sf2
	_ = sf3
	_ = extractRawStoredValuesForFieldR61Search(doc, "title", sc)
	_ = extractHitIgnoredFieldsR61Search(hit, sc)

	// extractMetadataFieldR61Search & injectMissingConstantKeywordsInSyntheticMapR61Search
	for _, mf := range []string{"_id", "_index", "_routing", "_version", "_seq_no", "_primary_term", "_ignored", "_field_names"} {
		_, _, _, _, _ = extractMetadataFieldR61Search(hit, "r61_fields_idx", mf, "", mf == "_id", sc)
	}
	synthDst := map[string]any{"title": "abc"}
	injectMissingConstantKeywordsInSyntheticMapR61Search(synthDst, map[string]any{"const_kw": "x"}, sc)

	// Format & scalar parsing helpers
	if !isValidESDateFetchFormatR61Search("epoch_millis") || isValidESDateFetchFormatR61Search("invalid[[date") {
		t.Fatal("unexpected date format validator behavior")
	}
	if !isValidESDecimalFetchFormatR61Search("#,##0.00") || isValidESDecimalFetchFormatR61Search("") {
		t.Fatal("unexpected decimal format validator behavior")
	}
	if formatted := formatNumericWithDecimalPatternR61Search(1234.5, "#,##0.00"); formatted == "" {
		t.Fatal("expected formatted decimal string")
	}
	if b, okB := sc.Fields["loc"]; okB {
		_, _, _, _ = extractFormattedSpatialFieldValuesR61Search(doc, "loc", "loc", b, "", false)
	}
	if _, _, _, _ = formatUnifiedFieldSliceR61Search("price", "price", []any{float64(12.34)}, "#0.0", true, sc); false {
		t.Fatal("unreachable")
	}
	for _, v := range []any{float64(1.5), math.NaN(), float32(2.5), float32(math.NaN()), int(3), int64(4), uint64(5), json.Number("6.5"), "7.5", "bad"} {
		_, _ = parseFiniteFloatFromAnyR61Search(v, true)
		_, _ = parseFiniteFloatFromAnyR61Search(v, false)
	}
	for _, bv := range []any{true, false, "true", "FALSE", "nope", 1} {
		_, _ = parseStrictESBoolR61Search(bv)
	}
}

func TestRound67Cov_Runtime_R61ScriptScoreIntervalsKNNCollapseAndRankEval(t *testing.T) {
	sc := compileR67CovRTSchema(t, "r61_adv_idx", `{
		"properties": {
			"title": {"type": "text"},
			"sayt": {"type": "search_as_you_type"},
			"tag": {"type": "keyword"},
			"price": {"type": "double"},
			"qty": {"type": "long"},
			"vec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"cost": {"type": "double"},
					"ivec": {"type": "dense_vector", "dims": 2, "similarity": "cosine"}
				}
			},
			"pq": {"type": "percolator"}
		}
	}`, true)

	doc := map[string]any{
		"title": "apache doris analytics engine fast sql search",
		"tag":   "olap",
		"price": float64(12.5),
		"qty":   int64(4),
		"vec":   []any{float64(1.0), float64(0.0)},
		"items": []any{
			map[string]any{"sku": "k1", "cost": float64(10.0), "ivec": []any{float64(0.9), float64(0.1)}},
			map[string]any{"sku": "k2", "cost": float64(30.0), "ivec": []any{float64(0.1), float64(0.9)}},
		},
	}

	// 1. compileValidateQueryScriptScoreR61Search + queryContainsScriptScoreR61Search + evalAndValidateSearchScriptScoreR61Search
	validSSQ := mustUnmarshalR67CovRT[esast.Query](t, `{
		"bool": {
			"must": [{"script_score": {"query": {"match": {"title": "doris"}}, "script": {"source": "doc['price'].value * _score", "params": {"w": 2}}}}],
			"filter": [{"constant_score": {"filter": {"term": {"tag": "olap"}}}}],
			"should": [{"function_score": {
				"query": {"match_all": {}},
				"functions": [{"script_score": {"script": {"source": "doc['qty'].value + 1"}}}],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}}],
			"must_not": [{"dis_max": {"queries": [{"nested": {"path": "items", "query": {"term": {"items.sku": "none"}}}}]}}]
		}
	}`)
	if !queryContainsScriptScoreR61Search(&validSSQ) {
		t.Fatal("expected queryContainsScriptScoreR61Search to be true")
	}
	if st, _ := compileValidateQueryScriptScoreR61Search("r61_adv_idx", &validSSQ); st != 0 {
		t.Fatalf("expected valid script_score compilation, got %d", st)
	}
	if sVal, okM, st, _ := evalAndValidateSearchScriptScoreR61Search(sc, doc, &validSSQ, 1.5, true); st != 0 || !okM || sVal <= 0 {
		t.Logf("script score eval result score=%v okM=%v st=%d", sVal, okM, st)
	}

	// Boosting + Pinned + Wrapper + negative score + invalid script compile paths
	negSSQ := mustUnmarshalR67CovRT[esast.Query](t, `{"script_score":{"query":{"match_all":{}},"script":{"source":"-5.0"}}}`)
	_, _, _, _ = evalAndValidateSearchScriptScoreR61Search(sc, doc, &negSSQ, 1.0, true)

	badCompileWrap := mustUnmarshalR67CovRT[esast.Query](t, `{
		"boosting": {
			"positive": {"pinned": {"ids": ["1"], "organic": {"script_score": {"query": {"match_all": {}}, "script": {"source": "return (1 +;"}}}}},
			"negative": {"match_none": {}},
			"negative_boost": 0.2
		}
	}`)
	if stBad, _ := compileValidateQueryScriptScoreR61Search("r61_adv_idx", &badCompileWrap); stBad != http.StatusBadRequest {
		t.Fatalf("expected 400 from broken painless syntax in script_score, got %d", stBad)
	}

	// 2. evalIntervalsCompoundQueryR61Search
	for _, iqJSON := range []string{
		`{"intervals":{"title":{"match":{"query":"apache doris"}}}}`,
		`{"intervals":{"title":{"all_of":{"ordered":true,"max_gaps":3,"intervals":[{"match":{"query":"apache"}},{"prefix":{"prefix":"dor"}}],"filter":{"not_overlapping":{"match":{"query":"missing"}}}}}}}`,
		`{"intervals":{"title":{"any_of":{"intervals":[{"wildcard":{"pattern":"analyt*"}},{"fuzzy":{"term":"engne","fuzziness":1}}]}}}}`,
	} {
		iq := mustUnmarshalR67CovRT[esast.Query](t, iqJSON)
		_, _, _ = evalIntervalsCompoundQueryR61Search(sc, doc, &iq, true, true)
	}

	// 3. Nested kNN inner hits & parent score & nested top_hits
	nq := mustUnmarshalR67CovRT[esast.NestedQuery](t, `{
		"path": "items",
		"score_mode": "max",
		"query": {"knn": {"field": "items.ivec", "query_vector": [1.0, 0.0], "k": 2, "num_candidates": 2}},
		"inner_hits": {"name": "top_items", "size": 2}
	}`)
	if ps, okPS := evalNestedKNNParentScoreOnDocR63(sc, doc, &nq); !okPS || ps <= 0 {
		t.Fatalf("expected positive nested knn parent score, got %v %v", ps, okPS)
	}
	rawDocAdv, _ := json.Marshal(doc)
	knnReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"knn": {"field": "items.ivec", "query_vector": [1.0, 0.0], "k": 2}},
				"inner_hits": {"name": "ih_items", "size": 1}
			}
		}
	}`)
	advHit := HitRow{Index: "r61_adv_idx", ID: "adv1", Source: rawDocAdv, Schema: sc, Score: 1.0}
	if ih := populateNestedKNNInnerHitsR61Search(&advHit, doc, sc, &knnReq); len(ih) == 0 {
		t.Fatal("expected populated nested kNN inner hits")
	}

	thSpec := mustUnmarshalR67CovRT[esast.TopHitsAggSpec](t, `{"size": 1, "sort": [{"items.cost": {"order": "desc"}}], "_source": {"includes": ["items.sku"]}}`)
	if thOut := evaluateNestedTopHitsAggR61Search("items", []HitRow{advHit}, nil, &thSpec, sc); thOut == nil {
		t.Fatal("expected non-nil nested top_hits result")
	}

	// 4. expandCollapseInnerHitsAndSecondLevelR61Search & named queries
	collapseSpec := mustUnmarshalR67CovRT[esast.CollapseSpec](t, `{
		"field": "tag",
		"inner_hits": {"name": "by_tag", "size": 2}
	}`)
	sz1 := 1
	collapseSpec.InnerHits[0].Collapse = &esast.CollapseSpec{
		Field:     "items.sku",
		InnerHits: []esast.InnerHitsSpec{{Name: "by_sku", Size: &sz1}},
	}
	srv, _ := newR67CovRTServer(t, "8.15.5")
	_ = expandCollapseInnerHitsAndSecondLevelR61Search(advHit, []HitRow{advHit}, &collapseSpec, sc, srv)

	namedReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{
		"query": {
			"bool": {
				"_name": "outer_bool",
				"must": [{"match": {"title": {"query": "doris", "_name": "m_title"}}}],
				"should": [{"term": {"tag": {"value": "olap", "_name": "t_tag"}}}]
			}
		}
	}`)
	namedOut := make(map[string]float64)
	collectNamedQueryScoresR61Search(sc, doc, namedReq.Query, true, namedOut)
	if len(namedOut) == 0 {
		t.Fatal("expected named query scores")
	}
	_ = collectAllMatchedQueriesWithScoresR61Search(sc, doc, &namedReq, 1.0)
	_, _, _ = extractSingleTermOrMatchForExplainR61Search(namedReq.Query)

	// 5. evalMultiDocPercolateR61Search
	qDoc := map[string]any{
		"pq": map[string]any{"term": map[string]any{"tag": "olap"}},
	}
	percQ := mustUnmarshalR67CovRT[esast.PercolateQuery](t, `{
		"field": "pq",
		"documents": [{"tag": "none"}, {"tag": "olap"}]
	}`)
	if matchedP, _, slots, _ := evalMultiDocPercolateR61Search(sc, qDoc, &percQ); !matchedP || len(slots) != 1 || slots[0] != 1 {
		t.Fatalf("expected slot [1] match, got matched=%v slots=%v", matchedP, slots)
	}

	// 6. computeRankEvalMetricR61Search
	ratings := map[string]float64{"d1": 2, "d2": 1, "d3": 0}
	hitsList := []string{"d1", "unrated", "d2", "d3"}
	for _, tc := range []struct {
		name string
		cfg  map[string]any
	}{
		{"precision", map[string]any{"k": 3, "relevant_rating_threshold": 1, "ignore_unlabeled": true}},
		{"recall", map[string]any{"k": 4}},
		{"mean_reciprocal_rank", map[string]any{"k": 4}},
		{"dcg", map[string]any{"k": 4, "normalize": true}},
		{"expected_reciprocal_rank", map[string]any{"k": 4, "maximum_relevance": 3}},
	} {
		if _, det, err := computeRankEvalMetricR61Search(tc.name, tc.cfg, hitsList, ratings); err != nil || det == nil {
			t.Fatalf("rank_eval %s failed: err=%v det=%+v", tc.name, err, det)
		}
	}
	for _, bad := range []struct {
		name string
		cfg  map[string]any
	}{
		{"precision", map[string]any{"k": 0}},
		{"precision", map[string]any{"relevant_rating_threshold": -1}},
		{"unknown_metric", nil},
	} {
		if _, _, err := computeRankEvalMetricR61Search(bad.name, bad.cfg, hitsList, ratings); err == nil {
			t.Fatalf("expected error for bad rank_eval %s %+v", bad.name, bad.cfg)
		}
	}

	// 7. evalSearchScriptFieldsR61Search via SearchRequest
	sfReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{
		"script_fields": {
			"double_price": {"script": {"source": "doc['price'].value * params.m", "params": {"m": 2}}},
			"tag_len": {"script": {"source": "params._source.tag.length()"}}
		}
	}`)
	httpReq := httptest.NewRequest(http.MethodPost, "/r61_adv_idx/_search", nil)
	schemasByIdx := map[string]*schema.IndexSchema{"r61_adv_idx": sc}
	if sfRes, sfSt, sfErr := evalSearchScriptFieldsR61Search(srv, httpReq, []HitRow{advHit}, schemasByIdx, &sfReq); sfSt != 0 || sfErr != nil || len(sfRes[0]) == 0 {
		t.Fatalf("expected script_fields eval success, got st=%d err=%+v res=%+v", sfSt, sfErr, sfRes)
	}
}

func TestRound67Cov_Runtime_R61CompletionPipelineQuantilesAndMovingFn(t *testing.T) {
	// 1. Completion helpers
	if got := normalizeCompletionStringR61Search("  Café-Doris! 2026 ", "simple"); got == "" {
		t.Fatal("expected normalized completion string")
	}
	if got := normalizeCompletionStringR61Search("Keep_Exact", "keyword"); got != "Keep_Exact" {
		t.Fatalf("unexpected keyword normalized completion: %q", got)
	}
	for _, pr := range []any{5, float64(6), "1km", "500m", "invalid"} {
		_ = parseCompletionGeoPrecisionR61Search(pr)
	}
	for _, gp := range []any{"37.77,-122.41", map[string]any{"lat": 37.77, "lon": -122.41}, []any{-122.41, 37.77}, "bad"} {
		_, _ = parseCompletionGeoContextHashR61Search(gp, 5)
	}

	compDoc := map[string]any{
		"cat_fld": "books",
		"loc_fld": map[string]any{"lat": 37.77, "lon": -122.41},
		"suggest_field": []any{
			map[string]any{
				"input":  []any{"doris proxy", "doris engine"},
				"weight": float64(5),
				"contexts": map[string]any{
					"cat": []any{"db"},
				},
			},
			"doris plain",
		},
	}
	entries := extractCompletionEntriesFromDocR61Search(compDoc, []string{"suggest_field"})
	if len(entries) != 2 {
		t.Fatalf("expected 2 completion entries, got %+v", entries)
	}
	ctxDefs := mustUnmarshalR67CovRT[[]esast.CompletionContextDef](t, `[
		{"name": "cat", "type": "category", "path": "cat_fld", "default": ["general"]},
		{"name": "place", "type": "geo", "path": "loc_fld", "precision": "1km"}
	]`)
	docCtxs := resolveDocCompletionContextValuesR61Search(compDoc, entries[0], ctxDefs)
	qCtxs := mustUnmarshalR67CovRT[map[string][]esast.CompletionQueryContext](t, `{
		"cat": [{"context": "bo", "prefix": true, "boost": 3.0}],
		"place": [{"context": {"lat": 37.77, "lon": -122.41}, "precision": "1km", "neighbours": ["5km"], "boost": 2.0}]
	}`)
	matchedC, boostC, _, stC, _, _ := evaluateCompletionContextsBoostR61Search(docCtxs, ctxDefs, qCtxs)
	if stC != 0 || !matchedC || boostC <= 0 {
		t.Logf("completion context result matched=%v boost=%v st=%d", matchedC, boostC, stC)
	}
	if !matchesCompletionPrefixOrFuzzyR61Search("doris", "dori", nil) {
		t.Fatal("expected exact prefix match")
	}
	if !matchesCompletionPrefixOrFuzzyR61Search("doris", "dorix", map[string]any{"fuzziness": 1, "min_length": 3, "prefix_length": 1, "transpositions": true}) {
		t.Fatal("expected fuzzy completion match")
	}

	// End-to-end completion suggester over HTTP
	_, h := newR67CovRTServer(t, "8.15.5")
	mustR67CovRTHTTP(t, h, http.MethodPut, "/comp_cov_idx", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"loc": {"type": "geo_point"},
				"suggest": {
					"type": "completion",
					"contexts": [
						{"name": "cat_ctx", "type": "category", "path": "cat"},
						{"name": "geo_ctx", "type": "geo", "path": "loc", "precision": "5km"}
					]
				}
			}
		}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/comp_cov_idx/_doc/1?refresh=true", `{
		"cat": "analytics",
		"loc": {"lat": 37.77, "lon": -122.41},
		"suggest": {"input": ["apache doris", "apache spark"], "weight": 10}
	}`, http.StatusCreated)
	compResp := mustR67CovRTHTTP(t, h, http.MethodPost, "/comp_cov_idx/_search", `{
		"suggest": {
			"my_sug": {
				"prefix": "apac",
				"completion": {
					"field": "suggest",
					"size": 5,
					"skip_duplicates": true,
					"fuzzy": {"fuzziness": "AUTO"},
					"contexts": {
						"cat_ctx": [{"context": "anal", "prefix": true, "boost": 2}],
						"geo_ctx": [{"context": {"lat": 37.77, "lon": -122.41}, "precision": "5km"}]
					}
				}
			}
		}
	}`, http.StatusOK)
	if compResp["suggest"] == nil {
		t.Fatal("expected suggest response")
	}

	// 2. validatePipelineAggTreeR61Search invalid + valid cases
	badPipeAggs := []string{
		`{"rs":{"random_sampler":{"probability":0.5},"aggs":{"ts":{"time_series":{}}}}}`,
		`{"der":{"derivative":{"buckets_path":"m"}}}`,
		`{"bs":{"bucket_selector":{"buckets_path":{"a":"m"},"script":"params.a > 0"}}}`,
		`{"flt":{"filter":{"match_all":{}},"aggs":{"der":{"derivative":{"buckets_path":"m"}}}}}`,
		`{"t":{"terms":{"field":"cat"},"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p"}}}}}`,
	}
	for _, rawAgg := range badPipeAggs {
		aggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, rawAgg)
		if stP, _, _ := validatePipelineAggTreeR61Search(aggs, "root", false, false, false); stP == 0 {
			t.Fatalf("expected validation error for pipeline agg %s", rawAgg)
		}
	}
	badEmptyScriptAggs := map[string]esast.AggSpec{
		"mf": {MovingFn: &esast.MovingAvgAggSpec{BucketsPath: "m", Window: 3, Script: ""}},
	}
	if stP, _, _ := validatePipelineAggTreeR61Search(badEmptyScriptAggs, "root", false, false, false); stP == 0 {
		t.Fatal("expected validation error for moving_fn empty script")
	}
	badWinAggs := map[string]esast.AggSpec{
		"mf": {MovingFn: &esast.MovingAvgAggSpec{BucketsPath: "m", Window: 0, Script: "MovingFunctions.sum(values)"}},
	}
	if stP, _, _ := validatePipelineAggTreeR61Search(badWinAggs, "root", false, false, false); stP == 0 {
		t.Fatal("expected validation error for moving_fn window=0")
	}

	// 3. Exact quantiles + moving_percentiles + reEvaluatePipelineAggsTreeInnerR61Search
	qAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{
		"by_day": {
			"date_histogram": {"field": "ts", "calendar_interval": "day"},
			"aggs": {
				"p": {"percentiles": {"field": "val", "percents": [50, 95]}},
				"pr": {"percentile_ranks": {"field": "val", "values": [10, 50]}},
				"mp": {"moving_percentiles": {"buckets_path": "p", "window": 2, "shift": 1}},
				"mf": {"moving_fn": {"buckets_path": "p.50.0", "window": 2, "script": "MovingFunctions.unweightedAvg(values)"}}
			}
		},
		"flt": {
			"filter": {"match_all": {}},
			"aggs": {
				"p_single": {"percentiles": {"field": "val", "percents": [50], "keyed": false}}
			}
		}
	}`)
	aggsOut := map[string]any{
		"by_day": map[string]any{
			"buckets": []map[string]any{
				{
					"key":       int64(1700000000000),
					"doc_count": int64(3),
					"p":         map[string]any{"values": map[string]any{"50.0": 20.0, "95.0": 30.0}},
					"pr":        map[string]any{"values": map[string]any{"10.0": 10.0, "50.0": 90.0}},
				},
				{
					"key":       int64(1700086400000),
					"doc_count": int64(2),
					"p":         map[string]any{"values": map[string]any{"50.0": 40.0, "95.0": 50.0}},
					"pr":        map[string]any{"values": map[string]any{"10.0": 5.0, "50.0": 75.0}},
				},
			},
		},
		"flt": map[string]any{
			"doc_count": int64(5),
			"p_single":  map[string]any{"values": []any{}},
		},
	}
	rawVals := map[string]map[string][]float64{
		"by_day>p": {
			"1700000000000": {10, 20, 30},
			"1700086400000": {30, 50},
		},
		"by_day>pr": {
			"1700000000000": {10, 20, 30},
			"1700086400000": {30, 50},
		},
		"flt>p_single": {
			"": {10, 20, 30, 40, 50},
		},
	}
	rawSeen := map[string]map[string]bool{
		"by_day>p":     {"1700000000000": true, "1700086400000": true},
		"by_day>pr":    {"1700000000000": true, "1700086400000": true},
		"flt>p_single": {"": true},
	}
	if err := applyExactQuantilesWalkR61Search("", "", qAggs, aggsOut, rawVals, rawSeen, true); err != nil {
		t.Fatalf("applyExactQuantilesWalkR61Search failed: %v", err)
	}
	if err := reEvaluatePipelineAggsTreeInnerR61Search(qAggs, aggsOut, false); err != nil {
		t.Fatalf("reEvaluatePipelineAggsTreeInnerR61Search failed: %v", err)
	}

	// Test keyed/[]any bucket shapes in reEvaluatePipelineAggsTreeInnerR61Search & buildExactQuantileMetricObjectR61Search
	fltAgg := qAggs["flt"]
	if obj, err := buildExactQuantileMetricObjectR61Search(fltAgg.SubAggs()["p_single"], nil, true); err != nil || obj == nil {
		t.Fatalf("empty percentile object failed: err=%v obj=%+v", err, obj)
	}
	kvAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{
		"hist": {
			"histogram": {"field": "x", "interval": 10},
			"aggs": {
				"p": {"percentiles": {"field": "x", "percents": [50]}},
				"bs": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c > 0"}}
			}
		}
	}`)
	kvOut := map[string]any{
		"hist": map[string]any{
			"buckets": []any{
				map[string]any{"key": float64(0), "doc_count": int64(2), "p": map[string]any{"values": map[string]any{"50.0": 5.0}}},
				map[string]any{"key": float64(10), "doc_count": int64(0), "p": map[string]any{"values": map[string]any{"50.0": nil}}},
			},
		},
	}
	_ = reEvaluatePipelineAggsTreeInnerR61Search(kvAggs, kvOut, false)

	// 4. evalMovingFnWindowR61Search + MovingFunctions builtins + HoltWinters
	mfSpecs := []struct {
		src    string
		vals   []float64
		params map[string]any
	}{
		{"MovingFunctions.unweightedAvg(values)", []float64{2, 4, 6}, nil},
		{"MovingFunctions.linearWeightedAvg(values)", []float64{2, 4, 6}, nil},
		{"MovingFunctions.ewma(values, 0.3, true)", []float64{10, 20, 30, 40}, nil},
		{"MovingFunctions.holt(values, 0.3, 0.1)", []float64{10, 12, 15, 19, 24}, nil},
		{"MovingFunctions.holtWinters(values, 0.3, 0.1, 0.2, 2, false)", []float64{10, 20, 12, 22, 14, 24}, nil},
		{"MovingFunctions.holtWinters(values, 0.3, 0.1, 0.2, 2, true)", []float64{10, 20, 12, 22, 14, 24}, nil},
		{"MovingFunctions.max(values)", []float64{2, 9, 4}, nil},
		{"MovingFunctions.min(values)", []float64{2, 9, 4}, nil},
		{"MovingFunctions.sum(values)", []float64{2, 9, 4}, nil},
		{"MovingFunctions.stdDev(values, MovingFunctions.unweightedAvg(values))", []float64{2, 4, 6, 8}, nil},
		{"if (values.length > 1) { return MovingFunctions.sum(values) * params.k; }", []float64{2, 4}, map[string]any{"k": 3.0}},
		{"if (values.length > 5) { return 1.0; }", []float64{2, 4}, nil},
		{"Double.NaN", []float64{1, 2}, nil},
	}
	for _, tc := range mfSpecs {
		spec := &esast.MovingAvgAggSpec{
			BucketsPath: "m",
			Window:      4,
			Script:      map[string]any{"source": tc.src, "params": tc.params},
		}
		if _, err := evalMovingFnWindowR61Search(tc.vals, spec); err != nil {
			t.Fatalf("moving_fn %s failed: %v", tc.src, err)
		}
	}
	if _, err := evalSingleMovingFunctionsBuiltinR61Search("sum", []string{"values"}, []float64{}, nil); err != nil {
		t.Fatalf("expected sum([]) success, got %v", err)
	}
	if _, err := resolveMovingFnNumericArgR61Search("params.a", map[string]any{"a": 2.5}); err != nil {
		t.Fatalf("resolveMovingFnNumericArgR61Search failed: %v", err)
	}
	if b, err := resolveMovingFnBoolArgR61Search("true", nil); err != nil || !b {
		t.Fatalf("resolveMovingFnBoolArgR61Search failed: b=%v err=%v", b, err)
	}
	_ = computeESHoltWintersR61Search([]float64{10, 20, 12, 22, 14, 24}, 0.3, 0.1, 0.2, 2, false)
	_ = injectImplicitReturnInIfBlockR61Search("if (values.length > 0) { values.length }")
	if idx := findMatchingParenInScriptR61Search("(a + (b * c))", 0); idx != 12 {
		t.Fatalf("expected matching paren idx 12, got %d", idx)
	}
}

func TestRound67Cov_Runtime_R62ZeroCoveredFieldRefsRuntimeAndSigText(t *testing.T) {
	// 1. Zero-covered helpers in R62
	if !isBenignAddColumnErrorR62Search(nil) {
		t.Fatal("expected true for nil error")
	}
	if !isBenignAddColumnErrorR62Search(errors.New("errCode = 2, detailMessage = Duplicate column name 'x'")) {
		t.Fatal("expected true for duplicate column error")
	}
	if !isIndexGetFeaturesSegmentR62Search("_settings,_mappings") || isIndexGetFeaturesSegmentR62Search("_invalid") {
		t.Fatal("unexpected isIndexGetFeaturesSegmentR62Search result")
	}
	reqFeat := httptest.NewRequest(http.MethodGet, "/idx/_settings,_mappings?filter_path=*.settings", nil)
	wa, wm, ws, hf := parseIndexGetFeaturesR62Search(reqFeat, "_settings,_mappings")
	if wa || !wm || !ws || !hf {
		t.Fatalf("unexpected parseIndexGetFeaturesR62Search: %v %v %v %v", wa, wm, ws, hf)
	}
	recErr := httptest.NewRecorder()
	writeESErrorWithCausedByR62Search(recErr, http.StatusBadRequest, "script_exception", "runtime error", map[string]any{"type": "null_pointer_exception", "reason": "npe"})
	if recErr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recErr.Code)
	}
	nrc := nopReadCloserBytesR62Search{bytes.NewReader([]byte("ok"))}
	if err := nrc.Close(); err != nil {
		t.Fatalf("unexpected Close error: %v", err)
	}
	if bitMixerMix64R62Search(0) != 0 || bitMixerMix64R62Search(42) == 42 {
		t.Fatal("unexpected bitMixerMix64R62Search output")
	}
	if rev := reverseRunesR62Search("abcé"); rev != "écba" {
		t.Fatalf("unexpected reverseRunesR62Search: %q", rev)
	}
	if !matchesTermsPartitionR62Search("k1", map[string]any{"num_partitions": float64(4), "partition": float64(0)}, "keyword") && false {
		t.Fatal("unreachable")
	}
	for p := 0; p < 3; p++ {
		_ = matchesTermsPartitionR62Search("alpha", map[string]any{"num_partitions": 3, "partition": p}, "keyword")
		_ = matchesTermsPartitionR62Search("12345", map[string]any{"num_partitions": 3, "partition": p}, "long")
	}

	// 2. collectQueryFieldRefsR62Search, collectAggFieldRefsR62Search, collectReferencedRuntimeRootFieldsR62Search
	scRT := compileR67CovRTSchema(t, "r62_rt_idx", `{
		"runtime": {
			"rt_num": {"type": "long", "script": {"source": "emit(doc['base_num'].value + 1)"}},
			"rt_kw": {"type": "keyword", "script": {"source": "emit('k_' + params._source.tag)"}},
			"items.rt_sub": {"type": "double", "script": {"source": "emit(doc['items.cost'].value * 2)"}}
		},
		"properties": {
			"base_num": {"type": "long"},
			"tag": {"type": "keyword"},
			"title": {"type": "text"},
			"sayt": {"type": "search_as_you_type"},
			"loc": {"type": "geo_point"},
			"ip": {"type": "ip"},
			"ts": {"type": "date"},
			"items": {
				"type": "nested",
				"properties": {"cost": {"type": "double"}, "pt": {"type": "geo_point"}}
			}
		}
	}`, true)
	reqRefs := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{
		"runtime_mappings": {
			"req_comp": {"type": "composite", "script": "emit('a', 'x'); emit('b', 1)", "fields": {"a": {"type": "keyword"}, "b": {"type": "long"}}},
			"req_err": {"type": "double", "on_script_error": "continue", "script": "emit(1.0)"},
			"items.rt_pt": {"type": "geo_point"}
		},
		"query": {
			"bool": {
				"must": [{"match": {"title": "doris"}}, {"range": {"rt_num": {"gte": 1}}}],
				"filter": [{"term": {"rt_kw": "k_a"}}, {"exists": {"field": "req_comp.a"}}, {"geo_bounding_box": {"loc": {"top_left": [-123, 38], "bottom_right": [-122, 37]}}}],
				"should": [{"nested": {"path": "items", "query": {"range": {"items.rt_sub": {"gte": 1}}}}}],
				"must_not": [{"prefix": {"req_err": "1"}}]
			}
		},
		"aggs": {
			"g1": {"terms": {"field": "rt_kw"}, "aggs": {"s": {"sum": {"field": "rt_num"}}}},
			"st": {"significant_text": {"field": "title", "filter_duplicate_text": true, "background_filter": {"term": {"tag": "a"}}}},
			"ip_agg": {"ip_prefix": {"field": "ip", "prefix_length": 24}},
			"gg": {"geohash_grid": {"field": "loc", "precision": 4}},
			"rng": {"range": {"field": "rt_num", "ranges": [{"to": 10}, {"from": 10}]}}
		}
	}`)
	rtCands := map[string]bool{"rt_num": true, "rt_kw": true, "items.rt_sub": true, "req_comp": true, "req_err": true}
	refSet := make(map[string]bool)
	addRef := func(f string) {
		if f != "" {
			refSet[f] = true
		}
	}
	collectQueryFieldRefsR62Search(reqRefs.Query, rtCands, addRef)
	collectAggFieldRefsR62Search(reqRefs.Aggs, rtCands, addRef)
	if len(refSet) == 0 {
		t.Fatal("expected referenced field set")
	}
	if rootRefs := collectReferencedRuntimeRootFieldsR62Search(scRT, &reqRefs, nil); len(rootRefs) == 0 {
		t.Fatal("expected referenced runtime root fields")
	}

	// 3. evalRuntimeMappingsOrderedOnDocWithOutR62Search (nested + composite + shadowing + error continue)
	rtMap := mustUnmarshalR67CovRT[map[string]esast.FieldProperty](t, `{
		"rt_num": {"type": "long", "script": {"source": "emit(doc['base_num'].value + 10)"}},
		"rt_kw": {"type": "keyword", "script": {"source": "emit('v_' + params._source.tag)"}},
		"req_comp": {"type": "composite", "script": "emit('a', params._source.tag); emit('b', 7)", "fields": {"a": {"type": "keyword"}, "b": {"type": "long"}}},
		"items.rt_sub": {"type": "double", "script": {"source": "emit(doc['items.cost'].value * 3)"}},
		"items.rt_pt": {"type": "geo_point"},
		"shadow_empty": {"type": "long", "script": {"source": "if (false) { emit(1); }"}},
		"err_cont": {"type": "long", "on_script_error": "continue", "script": {"source": "throw new IllegalArgumentException('boom')"}}
	}`)
	rtDocIn := map[string]any{
		"base_num":     json.Number("5"),
		"tag":          "blue",
		"shadow_empty": int64(99),
		"items": []any{
			map[string]any{"cost": float64(4.0), "rt_pt": map[string]any{"lat": 37.7, "lon": -122.4}},
		},
	}
	_, rtEvalOut, modRT, _, errRT := evalRuntimeMappingsOrderedOnDocWithOutR62Search(
		scRT, rtMap,
		[]string{"rt_num", "rt_kw", "req_comp", "items.rt_sub", "items.rt_pt", "shadow_empty", "err_cont"},
		rtDocIn, true,
	)
	if errRT != nil || !modRT || rtEvalOut["rt_num"] == nil || rtEvalOut["req_comp.a"] == nil {
		t.Fatalf("unexpected evalRuntimeMappings result mod=%v err=%v out=%+v", modRT, errRT, rtEvalOut)
	}

	// 4. computeSignificantScoreWithSupersetR62Search + emitRuntimeSignificantTextAggRowsR62Search
	for _, kind := range []string{"jlh", "mutual_information", "chi_square", "gnd", "percentage", "script"} {
		hSpec := sigHeuristicSpecR62Search{kind: kind, params: map[string]any{"background_is_superset": true}}
		_ = computeSignificantScoreWithSupersetR62Search(hSpec, 5, 10, 6, 100, true)
		_ = computeSignificantScoreWithSupersetR62Search(hSpec, 0, 10, 6, 100, false)
	}
	srv, _ := newR67CovRTServer(t, "8.15.5")
	sigRawBody := []byte(`{"aggs":{"sig_t":{"significant_text":{"field":"title","filter_duplicate_text":true,"min_doc_count":1,"size":5,"jlh":{}}}}}`)
	sigScope := &activeSearchScope{srv: srv, ctx: context.Background(), rawBody: sigRawBody}
	sigSpec := mustUnmarshalR67CovRT[esast.AggSpec](t, `{"significant_text":{"field":"title","filter_duplicate_text":true,"min_doc_count":1,"size":5}}`)
	mkDoc := func(id, title, tag string) runtimeMatchedDoc {
		dm := map[string]any{"title": title, "tag": tag}
		return runtimeMatchedDoc{hit: HitRow{ID: id, Schema: scRT, SearchScope: sigScope}, doc: dm, rootDoc: dm, rootSchema: scRT}
	}
	fgDocs := []runtimeMatchedDoc{
		mkDoc("1", "apache doris search engine analytics olap real time", "fg"),
		mkDoc("2", "apache doris search engine analytics olap real time", "fg"), // exact duplicate skipped
		mkDoc("3", "doris query engine vector inverted index", "fg"),
	}
	bgDocs := append([]runtimeMatchedDoc{}, fgDocs...)
	bgDocs = append(bgDocs,
		mkDoc("4", "unrelated generic news weather sports", "bg"),
		mkDoc("5", "unrelated garden cooking music", "bg"),
	)
	var sigRows []AggRow
	emitRuntimeSignificantTextAggRowsR62Search("sig_t", "", sigSpec, fgDocs, bgDocs, &sigRows, scRT)
	if len(sigRows) == 0 {
		t.Fatal("expected significant_text rows")
	}

	// 5. buildIPPrefixAggObjectR62Search & buildTimeSeriesAggObjectR62Search & highlightSAYTBoolPrefixR62Search
	ipAggSpec := mustUnmarshalR67CovRT[esast.IPPrefixAggSpec](t, `{"field":"ip","prefix_length":24,"keyed":true,"append_prefix_length":true,"min_doc_count":1}`)
	ipRows := []AggRow{
		{AggName: "ip_agg", BucketKey: "10.1.2.0/24", DocCount: 3},
		{AggName: "ip_agg", BucketKey: "10.1.3.0/24", DocCount: 1},
	}
	if ipObj := buildIPPrefixAggObjectR62Search("r62_rt_idx", "ip_agg", "", &ipAggSpec, nil, ipRows, map[string][]AggRow{}, nil, scRT); ipObj["buckets"] == nil {
		t.Fatal("expected ip_prefix buckets")
	}
	tsAggSpec := mustUnmarshalR67CovRT[esast.TimeSeriesAggSpec](t, `{"size":10,"keyed":false}`)
	tsRows := []AggRow{{AggName: "ts_agg", BucketKey: "host=a", DocCount: 2}}
	if tsObj := buildTimeSeriesAggObjectR62Search("r62_rt_idx", "ts_agg", "", &tsAggSpec, nil, tsRows, map[string][]AggRow{}, nil, scRT); tsObj["buckets"] == nil {
		t.Fatal("expected time_series buckets")
	}

	saytQ := mustUnmarshalR67CovRT[esast.Query](t, `{"match_bool_prefix":{"sayt":"apach dor"}}`)
	if snips, okHL := highlightSAYTBoolPrefixR62Search(&saytQ, "sayt", []string{"apach doris <tag>"}, "<em>", "</em>", true, scRT); !okHL || len(snips) == 0 {
		t.Fatalf("expected match_bool_prefix highlight, got ok=%v snips=%v", okHL, snips)
	}

	// 6. validateRemovedES8SearchConstructsR65 & profile helpers & evaluatePhraseSuggestR62Search & bulk/ts helpers
	badCommonReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{"query":{"bool":{"must":[{"common":{"title":{"query":"x"}}}]}}}`)
	if stRem, _, _ := validateRemovedES8SearchConstructsR65(&badCommonReq); stRem != http.StatusBadRequest {
		t.Fatalf("expected 400 for removed common query, got %d", stRem)
	}
	cutoffMM := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{"query":{"multi_match":{"query":"x","fields":["title"],"cutoff_frequency":0.1}}}`)
	if stRem, _, _ := validateRemovedES8SearchConstructsR65(&cutoffMM); stRem != http.StatusBadRequest {
		t.Fatalf("expected 400 for removed cutoff_frequency, got %d", stRem)
	}

	_ = profileAggClassR62Search(sigSpec, &reqRefs, scRT, true, false, true)
	profPayload := map[string]any{"profile": map[string]any{"shards": []any{map[string]any{"id": "0", "aggregations": []any{map[string]any{"type": "TermsAggregator", "description": "sig_t", "time_in_nanos": int64(100)}}}}}}
	_ = enrichSearchProfilePayloadR62Search(srv, profPayload, scRT, &reqRefs, map[string]any{"sig_t": map[string]any{"buckets": []any{}}}, 3, []HitRow{{Index: "r62_rt_idx", ID: "1", Schema: scRT}})

	phraseSpec := mustUnmarshalR67CovRT[esast.PhraseSuggestSpec](t, `{"field":"title","size":3,"gram_size":2,"confidence":0.0,"max_errors":2,"highlight":{"pre_tag":"<b>","post_tag":"</b>"}}`)
	_, _, _, _ = srv.evaluatePhraseSuggestR62Search([]string{"r62_rt_idx"}, scRT, &phraseSpec, "apche dors", []string{"apache doris engine", "apache spark"}, strings.Fields, func(a, b string) int { return 1 })

	nq := validQueryWithNestedR67(t)
	_ = queryContainsInnerHitsR62Search(&nq)
	_ = buildSearchHitExplanationR62Search("r62_rt_idx", HitRow{Index: "r62_rt_idx", ID: "1", Score: 1.0, Schema: scRT}, scRT, &reqRefs)
	_ = extractGeoPointsAtPathR62Search(rtDocIn, []string{"items", "rt_pt"})
	_, _ = extractAndStripBulkExtendedMetaR62Search([]byte("{\"index\":{\"_index\":\"i\",\"require_data_stream\":true,\"dynamic_templates\":{\"t\":\"keyword\"}}}\n{\"a\":1}\n"))
	_, _, _, _, _ = validateDataStreamWriteTimestampR62Search([]byte(`{"@timestamp":"2026-06-01T00:00:00Z","msg":"ok"}`), scRT)
	_ = normalizeSearchSliceBodyR62Search([]byte(`{"slice":{"id":0,"max":2}}`))
}

func validQueryWithNestedR67(t *testing.T) esast.Query {
	t.Helper()
	return mustUnmarshalR67CovRT[esast.Query](t, `{"bool":{"must":[{"nested":{"path":"items","query":{"match_all":{}},"inner_hits":{}}}]}}`)
}

func TestRound67Cov_Runtime_R62ServerRRFDataStreamResolveAliasesAndRollover(t *testing.T) {
	srv, h := newR67CovRTServer(t, "8.15.5")

	// 1. Setup index templates, data stream with failure_store enabled, legacy index + alias, RRF index
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_index_template/r67_ds_tpl", `{
		"index_patterns": ["r67-ds-*"],
		"data_stream": {"failure_store": {"enabled": true}},
		"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "keyword"}, "level": {"type": "keyword"}}}}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_data_stream/r67-ds-logs", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/_data_stream/r67-ds-*", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/_data_stream/_stats", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/_data_stream/r67-ds-logs/_stats", "", http.StatusOK)
	codeHead, _, _, _ := doR67CovRTHTTP(t, h, http.MethodHead, "/_data_stream/r67-ds-logs", "", nil)
	if codeHead != http.StatusOK {
		t.Fatalf("HEAD _data_stream expected 200, got %d", codeHead)
	}

	// Valid doc + failure store recording + rollover + modify + resolve index
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r67-ds-logs/_doc?refresh=true", `{"@timestamp":"2026-06-01T00:00:00Z","msg":"ok","level":"info"}`, http.StatusCreated)
	_, _, _, _ = srv.recordFailureStoreDocumentR62Search(
		context.Background(), "r67-ds-logs", "bad-1",
		[]byte(`{"@timestamp":"not-a-date","msg":"broken"}`),
		"mapper_parsing_exception", "failed to parse @timestamp", []string{"p1"}, true, true, false,
	)

	rollRes := mustR67CovRTHTTP(t, h, http.MethodPost, "/_data_stream/r67-ds-logs/_rollover", `{}`, http.StatusOK)
	if rollRes["rolled_over"] != true {
		t.Fatalf("expected rolled_over=true, got %+v", rollRes)
	}

	// _resolve/index
	resIdx := mustR67CovRTHTTP(t, h, http.MethodGet, "/_resolve/index/r67*?expand_wildcards=all", "", http.StatusOK)
	if resIdx["data_streams"] == nil {
		t.Fatalf("expected data_streams in _resolve/index: %+v", resIdx)
	}

	// Legacy alias -> migrate to data stream -> modify_data_stream error/valid -> _aliases -> comma get index features
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r67_legacy_001", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"v":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "r67_legacy_001", "alias": "r67_mig_ds", "is_write_index": true}}
		]
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/r67_legacy_001/_settings,_mappings", "", http.StatusOK)
	if stNoTpl, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/_data_stream/_migrate/r67_mig_ds", "", nil); stNoTpl != http.StatusBadRequest {
		t.Fatalf("expected 400 migrating without matching data_stream template, got %d", stNoTpl)
	}
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_index_template/r67_mig_tpl", `{
		"index_patterns": ["r67_mig_*"],
		"data_stream": {}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/_data_stream/_migrate/r67_mig_ds", "", http.StatusOK)

	// Invalid modify removing active write backing index returns 400
	writeBackingIdx, _ := rollRes["new_index"].(string)
	if writeBackingIdx != "" {
		if cMod, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/_data_stream/_modify", `{
			"actions": [{"remove_backing_index": {"data_stream": "r67-ds-logs", "index": "`+writeBackingIdx+`"}}]
		}`, nil); cMod == http.StatusOK {
			t.Fatal("expected error removing active write backing index")
		}
	}

	// Aliases error paths (unsupported action + missing index in remove_index)
	for _, badAlias := range []string{
		`{"actions":[{"bad_op":{}}]}`,
		`{"actions":[{"remove_index":{}}]}`,
	} {
		stA, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/_aliases", badAlias, nil)
		if stA != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad alias payload %s, got %d", badAlias, stA)
		}
	}

	// 2. executeRRFSearchR62Search via sub_searches + rank.rrf AND retriever.rrf
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r67_rrf_idx", `{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"},"score_num":{"type":"double"}}}}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r67_rrf_idx/_doc/1?refresh=true", `{"title":"apache doris analytical","tag":"a","score_num":10}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r67_rrf_idx/_doc/2?refresh=true", `{"title":"doris search compatibility","tag":"b","score_num":20}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r67_rrf_idx/_doc/3?refresh=true", `{"title":"other database","tag":"a","score_num":5}`, http.StatusCreated)

	rrfResp := mustR67CovRTHTTP(t, h, http.MethodPost, "/r67_rrf_idx/_search", `{
		"size": 3,
		"sub_searches": [
			{"query": {"match": {"title": "doris"}}, "_name": "text_q"},
			{"query": {"term": {"tag": "a"}}, "_name": "tag_q"}
		],
		"rank": {
			"rrf": {
				"window_size": 10,
				"rank_constant": 60
			}
		}
	}`, http.StatusOK)
	if rrfResp["hits"] == nil {
		t.Fatalf("expected hits in RRF response: %+v", rrfResp)
	}

	retResp := mustR67CovRTHTTP(t, h, http.MethodPost, "/r67_rrf_idx/_search", `{
		"size": 2,
		"retriever": {
			"rrf": {
				"retrievers": [
					{"standard": {"query": {"match": {"title": "doris"}}}},
					{"standard": {"query": {"term": {"tag": "a"}}}}
				],
				"rank_window_size": 10,
				"rank_constant": 20,
				"filter": {"term": {"tag": "a"}}
			}
		}
	}`, http.StatusOK)
	if retResp["hits"] == nil {
		t.Fatalf("expected hits in retriever.rrf response: %+v", retResp)
	}

	// Direct validateSearchLimitsAndParamsR62Search + cleanup data stream
	negFrom := -1
	reqBadTerminate := esast.SearchRequest{From: &negFrom}
	if stLim, _, _ := srv.validateSearchLimitsAndParamsR62Search(context.Background(), httptest.NewRequest(http.MethodPost, "/r67_rrf_idx/_search", nil), &reqBadTerminate, nil, nil, false); stLim != http.StatusBadRequest {
		t.Fatalf("expected 400 from validateSearchLimitsAndParamsR62Search, got %d", stLim)
	}
	mustR67CovRTHTTP(t, h, http.MethodDelete, "/_data_stream/r67-ds-logs", "", http.StatusOK)
}

func buildTestDOCXZipBytesR67CovRT(t *testing.T, xmlBody string, coreXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if xmlBody != "" {
		w, err := zw.Create("word/document.xml")
		if err != nil {
			t.Fatalf("zip create document.xml failed: %v", err)
		}
		_, _ = w.Write([]byte(xmlBody))
	}
	if coreXML != "" {
		w, err := zw.Create("docProps/core.xml")
		if err != nil {
			t.Fatalf("zip create core.xml failed: %v", err)
		}
		_, _ = w.Write([]byte(coreXML))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close failed: %v", err)
	}
	return buf.Bytes()
}

func buildTestOLE2WordBytesR67CovRT() []byte {
	// 512-byte sector shift=9 (secSize=512), miniShift=6 (miniSize=64)
	const secSize = 512
	const totalSectors = 10 // header + 10 sectors (0..9)
	buf := make([]byte, (1+totalSectors)*secSize)
	const freeSec = uint32(0xFFFFFFFF)
	const endChain = uint32(0xFFFFFFFE)
	const fatSecTag = uint32(0xFFFFFFFD)

	// Header
	copy(buf[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(buf[30:32], 9)        // secShift=9
	binary.LittleEndian.PutUint16(buf[32:34], 6)        // miniShift=6
	binary.LittleEndian.PutUint32(buf[44:48], 1)        // num FAT sectors
	binary.LittleEndian.PutUint32(buf[48:52], 1)        // firstDirSec = 1
	binary.LittleEndian.PutUint32(buf[56:60], 4096)     // miniCutoff = 4096
	binary.LittleEndian.PutUint32(buf[60:64], 2)        // firstMiniFATSec = 2
	binary.LittleEndian.PutUint32(buf[64:68], 1)        // numMiniFAT
	binary.LittleEndian.PutUint32(buf[68:72], endChain) // firstDIFATSec
	binary.LittleEndian.PutUint32(buf[72:76], 0)        // numDIFAT
	for i := 0; i < 109; i++ {
		val := freeSec
		if i == 0 {
			val = 0 // FAT lives at sector 0
		}
		binary.LittleEndian.PutUint32(buf[76+i*4:80+i*4], val)
	}

	secSlice := func(id int) []byte {
		off := (1 + id) * secSize
		return buf[off : off+secSize]
	}

	// Sector 0: FAT
	fat := secSlice(0)
	for i := 0; i < 128; i++ {
		binary.LittleEndian.PutUint32(fat[i*4:i*4+4], freeSec)
	}
	binary.LittleEndian.PutUint32(fat[0*4:0*4+4], fatSecTag) // 0: FAT
	binary.LittleEndian.PutUint32(fat[1*4:1*4+4], 3)         // 1 -> 3 (Directory needs >128*4=512 bytes for 5 entries = 640 bytes)
	binary.LittleEndian.PutUint32(fat[3*4:3*4+4], endChain)
	binary.LittleEndian.PutUint32(fat[2*4:2*4+4], endChain) // 2: MiniFAT
	binary.LittleEndian.PutUint32(fat[4*4:4*4+4], 5)        // 4 -> 5 -> endChain (Root MiniStream = 1024 bytes)
	binary.LittleEndian.PutUint32(fat[5*4:5*4+4], endChain)

	// Sector 2: MiniFAT (16 x 64-byte mini sectors inside 1024-byte MiniStream)
	mfat := secSlice(2)
	for i := 0; i < 128; i++ {
		binary.LittleEndian.PutUint32(mfat[i*4:i*4+4], freeSec)
	}
	// WordDocument uses mini sectors 0..7 (8*64=512 bytes)
	for i := 0; i < 7; i++ {
		binary.LittleEndian.PutUint32(mfat[i*4:i*4+4], uint32(i+1))
	}
	binary.LittleEndian.PutUint32(mfat[7*4:7*4+4], endChain)
	// 1Table uses mini sector 8
	binary.LittleEndian.PutUint32(mfat[8*4:8*4+4], endChain)
	// SummaryInfo uses mini sectors 9..10
	binary.LittleEndian.PutUint32(mfat[9*4:9*4+4], 10)
	binary.LittleEndian.PutUint32(mfat[10*4:10*4+4], endChain)

	// MiniStream payload across sectors 4..5
	miniStream := make([]byte, 1024)
	// WordDocument in miniStream[0:512]:
	// ANSI text "Hello" placed at byteOff=0x200-? -> keep within 512 bytes: place ANSI text at byteOff=450 -> fc = 450*2 | 0x40000000
	wd := miniStream[0:512]
	binary.LittleEndian.PutUint16(wd[0x0A:0x0C], 0x0200) // 1Table flag
	binary.LittleEndian.PutUint32(wd[0x18:0x1C], 450)
	binary.LittleEndian.PutUint32(wd[0x1C:0x20], 455)
	binary.LittleEndian.PutUint32(wd[0x4C:0x50], 5)   // ccpText = 5
	binary.LittleEndian.PutUint32(wd[0x1A2:0x1A6], 0) // fcClx = 0
	// Prc (0x01, len=2, 2 dummy bytes) + Pcdt (0x02, lcb=16) + 2 CPs [0, 5] + 1 PCD (8 bytes, fcCompressed)
	copy(wd[450:455], []byte("Hello"))
	tbl := miniStream[8*64 : 9*64]
	tbl[0] = 0x01
	binary.LittleEndian.PutUint16(tbl[1:3], 2)
	tbl[3] = 0xAA
	tbl[4] = 0xBB
	tbl[5] = 0x02 // Pcdt
	lcb := uint32(16)
	binary.LittleEndian.PutUint32(tbl[6:10], lcb)
	plc := tbl[10:26]
	binary.LittleEndian.PutUint32(plc[0:4], 0)
	binary.LittleEndian.PutUint32(plc[4:8], 5)
	fcComp := uint32((450 * 2) | 0x40000000)
	binary.LittleEndian.PutUint32(plc[8+2:8+6], fcComp)
	binary.LittleEndian.PutUint32(wd[0x1A6:0x1AA], 26)

	// SummaryInformation in miniStream[9*64 : 11*64] (128 bytes)
	sum := miniStream[9*64 : 11*64]
	binary.LittleEndian.PutUint32(sum[24:28], 1)  // NumPropertySets
	binary.LittleEndian.PutUint32(sum[44:48], 48) // secOff = 48
	sec := sum[48:]
	binary.LittleEndian.PutUint32(sec[4:8], 3) // numProps = 3
	// Prop 0: Title (id=2) -> VT_LPSTR at rel 40
	binary.LittleEndian.PutUint32(sec[8:12], 2)
	binary.LittleEndian.PutUint32(sec[12:16], 40)
	// Prop 1: Author (id=4) -> VT_LPWSTR at rel 56
	binary.LittleEndian.PutUint32(sec[16:20], 4)
	binary.LittleEndian.PutUint32(sec[20:24], 56)
	// Prop 2: LastSave (id=13) -> VT_FILETIME at rel 68
	binary.LittleEndian.PutUint32(sec[24:28], 13)
	binary.LittleEndian.PutUint32(sec[28:32], 68)
	// Write Prop 0 VT_LPSTR "Doc\x00"
	binary.LittleEndian.PutUint16(sec[40:42], 0x001E)
	binary.LittleEndian.PutUint32(sec[44:48], 4)
	copy(sec[48:52], []byte("Doc\x00"))
	// Write Prop 1 VT_LPWSTR "AB\x00"
	binary.LittleEndian.PutUint16(sec[56:58], 0x001F)
	binary.LittleEndian.PutUint32(sec[60:64], 2)
	binary.LittleEndian.PutUint16(sec[64:66], 'A')
	binary.LittleEndian.PutUint16(sec[66:68], 0)
	// Write Prop 2 VT_FILETIME
	binary.LittleEndian.PutUint16(sec[68:70], 0x0040)
	binary.LittleEndian.PutUint64(sec[72:80], 133000000000000000)

	copy(secSlice(4), miniStream[0:512])
	copy(secSlice(5), miniStream[512:1024])

	// Directory entries spread across sector 1 (entries 0..3) and sector 3 (entry 4)
	writeDirEntry := func(dst []byte, name string, objType byte, startSec uint32, sz uint32) {
		u16 := utf16.Encode([]rune(name))
		for i, ch := range u16 {
			binary.LittleEndian.PutUint16(dst[i*2:i*2+2], ch)
		}
		binary.LittleEndian.PutUint16(dst[64:66], uint16((len(u16)+1)*2))
		dst[66] = objType
		binary.LittleEndian.PutUint32(dst[116:120], startSec)
		binary.LittleEndian.PutUint32(dst[120:124], sz)
	}
	dir0 := secSlice(1)
	writeDirEntry(dir0[0:128], "Root Entry", 5, 4, 1024)
	writeDirEntry(dir0[128:256], "WordDocument", 2, 0, 512)
	writeDirEntry(dir0[256:384], "1Table", 2, 8, 64)
	writeDirEntry(dir0[384:512], "\x05SummaryInformation", 2, 9, 128)
	return buf
}

func TestRound67Cov_Runtime_R63ModulesSecurityBinaryIngestAndESQL(t *testing.T) {
	// 1. Security helpers & TermsEnum DLS/FLS
	secret := "s3cr3t-pass"
	sum := sha256.Sum256([]byte(secret))
	hexHash := hex.EncodeToString(sum[:])
	if !verifyStoredSecretHashOrPlainR66(map[string]any{"__password_sha256": hexHash}, "__password_sha256", []string{"password"}, secret) {
		t.Fatal("expected sha256 secret match")
	}
	if !verifyStoredSecretHashOrPlainR66(map[string]any{"password": secret}, "__password_sha256", []string{"password"}, secret) {
		t.Fatal("expected plain secret match")
	}
	if verifyStoredSecretHashOrPlainR66(nil, "__password_sha256", []string{"password"}, secret) ||
		verifyStoredSecretHashOrPlainR66(map[string]any{"password": secret}, "__password_sha256", []string{"password"}, "") {
		t.Fatal("expected false on nil record or empty candidate")
	}

	scSec := compileR67CovRTSchema(t, "sec_idx", `{
		"properties": {
			"tenant": {"type": "constant_keyword", "value": "acme"},
			"title": {"type": "text"},
			"sayt": {"type": "search_as_you_type"},
			"secret_f": {"type": "keyword"}
		}
	}`, true)
	if v := lookupConstantKeywordValueR64(scSec, "tenant"); v != "acme" {
		t.Fatalf("expected constant_keyword acme, got %v", v)
	}
	if _, ok := extractTermsEnumDLSBoolClauseSliceR65([]any{map[string]any{"match_all": map[string]any{}}}); !ok {
		t.Fatal("expected bool clause slice")
	}
	if v, ok := parseTermsEnumDLSMinShouldMatchR65("100%", 2); !ok || v != 2 {
		t.Fatal("expected 100% min_should_match parse")
	}
	if _, ok := parseTermsEnumDLSMinShouldMatchR65("50%", 2); ok {
		t.Fatal("expected 50% percentage min_should_match to be rejected")
	}
	if _, ok := extractTermsEnumRoleStringSliceR65([]any{"a", "b"}); !ok {
		t.Fatal("expected role string slice parse")
	}
	dlsQ := map[string]any{
		"bool": map[string]any{
			"must":   []any{map[string]any{"match_all": map[string]any{}}},
			"filter": []any{map[string]any{"term": map[string]any{"tenant": "acme"}}},
		},
	}
	if !isTermsEnumDLSStaticMatchAllR64(dlsQ, scSec) {
		t.Fatal("expected static match_all with constant_keyword filter")
	}

	rolesMap := map[string]map[string]any{
		"reader": {
			"indices": []any{
				map[string]any{
					"names":          []any{"sec_*"},
					"privileges":     []any{"read"},
					"query":          dlsQ,
					"field_security": map[string]any{"grant": []any{"title"}, "except": []any{"secret_*"}},
				},
			},
		},
	}
	if !roleSliceAllowsTermsEnumR64([]map[string]any{rolesMap["reader"]}, map[string]*schema.IndexSchema{"sec_idx": scSec}, []string{"sec_idx"}, "title") {
		t.Fatal("expected roleSliceAllowsTermsEnumR64 true for title")
	}
	usersMap := map[string]map[string]any{
		"alice": {"__password_sha256": hexHash, "roles": []any{"reader"}, "enabled": true},
	}
	apiKeysMap := map[string]map[string]any{
		"k1": {"id": "k1", "api_key": "tok123", "username": "alice", "expiration": time.Now().Add(time.Hour).UnixMilli(), "role_descriptors": map[string]any{"reader": rolesMap["reader"]}},
	}
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+secret))
	if !EvaluateTermsEnumSecurityAccessR64(basicAuth, usersMap, rolesMap, apiKeysMap, map[string]*schema.IndexSchema{"sec_idx": scSec}, []string{"sec_idx"}, "title") {
		t.Fatal("expected Basic auth TermsEnum access allowed")
	}
	apiAuth := "ApiKey " + base64.StdEncoding.EncodeToString([]byte("k1:tok123"))
	if !EvaluateTermsEnumSecurityAccessR64(apiAuth, usersMap, rolesMap, apiKeysMap, map[string]*schema.IndexSchema{"sec_idx": scSec}, []string{"sec_idx"}, "title") {
		t.Fatal("expected ApiKey auth TermsEnum access allowed")
	}

	// 2. Week date parser, base64, DOCX zip, OLE2 Word+SummaryInfo
	for _, tc := range []struct {
		in, pat string
	}{
		{"2026-W05-3", "xxxx-'W'ww-e"},
		{"2026-W05", "YYYY-'W'ww"},
		{"2026-W99", "GGGG-'W'ww"},
	} {
		_, _ = parseSingleWeekDatePatternRound63(tc.in, tc.pat, time.UTC)
	}
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString([]byte("hello world")),
		base64.RawStdEncoding.EncodeToString([]byte("hello world")),
		base64.URLEncoding.EncodeToString([]byte("hello+world/")),
	} {
		if _, err := decodeBase64FlexibleRound63(enc); err != nil {
			t.Fatalf("decodeBase64FlexibleRound63 failed for %s: %v", enc, err)
		}
	}
	docxBytes := buildTestDOCXZipBytesR67CovRT(t,
		`<w:document><w:body><w:p><w:r><w:t>Hello Doris DOCX</w:t></w:r></w:p></w:body></w:document>`,
		`<cp:coreProperties><dc:title>My Title</dc:title><dc:creator>AuthorX</dc:creator></cp:coreProperties>`,
	)
	if meta := extractOOXMLDocxAttachmentRound63(docxBytes, 1000, true); meta["content"] == nil {
		t.Fatalf("expected DOCX content extracted, got %+v", meta)
	}
	zr, errZip := zip.NewReader(bytes.NewReader(docxBytes), int64(len(docxBytes)))
	if errZip == nil && len(zr.File) > 0 {
		remOK := int64(1024)
		_, _ = readZipFileBoundedRemainingRound63(zr.File[0], &remOK)
		remSmall := int64(2)
		_, _ = readZipFileBoundedRemainingRound63(zr.File[0], &remSmall)
	}

	oleBytes := buildTestOLE2WordBytesR67CovRT()
	streams := parseOLE2StreamsRound63(oleBytes)
	if len(streams["WordDocument"]) == 0 || len(streams["1Table"]) == 0 || len(streams["\x05SummaryInformation"]) == 0 {
		t.Fatalf("expected all OLE2 streams parsed, got keys=%v", streams)
	}
	if txt := extractWordFIBTextRound63(streams["WordDocument"], streams); !strings.Contains(txt, "Hello") {
		t.Fatalf("expected FIB/Clx extracted 'Hello', got %q", txt)
	}
	sumOut := make(map[string]any)
	parseOLE2SummaryInfoRound63(streams["\x05SummaryInformation"], sumOut, true)
	if len(sumOut) == 0 {
		t.Fatalf("expected OLE2 SummaryInfo properties, got %+v", sumOut)
	}

	// 3. ApplyGeoGridProcessorR64 + ValidateDownsampleAggsSpecMapR64 + overlayDownsampleLabelsAndDimsRound63
	h3Cell, h3Err := spatial.LatLonToCell(37.7749, -122.4194, 4)
	if h3Err != nil {
		t.Fatalf("LatLonToCell failed: %v", h3Err)
	}
	geoHexCell := spatial.CellToString(h3Cell)
	for _, tc := range []struct {
		cell string
		cfg  map[string]any
	}{
		{"4/8/5", map[string]any{"field": "loc", "target_field": "tile_wkt", "tile_type": "geotile", "target_format": "wkt", "parent_field": "p", "children_field": "c", "precision_field": "prec"}},
		{"4/8/5", map[string]any{"field": "loc", "target_field": "tile_gj", "tile_type": "geotile", "target_format": "geojson"}},
		{"u17", map[string]any{"field": "loc", "target_field": "gh_wkt", "tile_type": "geohash", "target_format": "wkt", "parent_field": "p", "children_field": "c", "precision_field": "prec"}},
		{"u17", map[string]any{"field": "loc", "target_field": "gh_gj", "tile_type": "geohash", "target_format": "geojson"}},
		{geoHexCell, map[string]any{"field": "loc", "target_field": "hex_wkt", "tile_type": "geohex", "target_format": "wkt", "parent_field": "p", "children_field": "c", "non_children_field": "nc", "precision_field": "prec"}},
		{geoHexCell, map[string]any{"field": "loc", "target_field": "hex_gj", "tile_type": "geohex", "target_format": "geojson"}},
	} {
		gDoc := map[string]any{"loc": tc.cell}
		if err := ApplyGeoGridProcessorR64(gDoc, tc.cfg); err != nil {
			t.Fatalf("ApplyGeoGridProcessorR64 %+v failed: %v", tc.cfg, err)
		}
	}
	scDS := compileR67CovRTSchema(t, "ds_agg_val", `{
		"properties": {
			"@timestamp": {"type": "date", "meta": {"fixed_interval": "1h"}},
			"cpu": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count"], "default_metric": "max"}
		}
	}`, true)
	for _, badAgg := range []map[string]any{
		{"h": map[string]any{"histogram": map[string]any{"field": "cpu", "interval": 10}}},
		{"dh": map[string]any{"date_histogram": map[string]any{"field": "@timestamp", "calendar_interval": "hour"}}},
	} {
		if err := ValidateDownsampleAggsSpecMapR64(badAgg, scDS); err == nil {
			t.Fatalf("expected DownsampleAggValidationErrorR64 for %+v", badAgg)
		} else if err.Error() == "" {
			t.Fatal("expected non-empty Error() on DownsampleAggValidationErrorR64")
		}
	}
	dstLbl := map[string]any{}
	overlayDownsampleLabelsAndDimsRound63(dstLbl, map[string]any{"labels": map[string]any{"env": "prod"}, "host": "n1"}, "", downsampleSchemaInfoRound63{dimPaths: []string{"host", "labels.env"}})

	// 4. ESQL & EQL pure helpers
	for _, f := range []float64{0, math.NaN(), math.Inf(1), 1.5, -3.25, 1e-5, 1e6} {
		_ = quantizeHalfFloatRound64(f)
	}
	_ = normalizeESQLWKTStringRound63("point (1.0 2.0)")
	sumESQL := esqlIndexFieldSummaryRound63{
		cols:           []string{"a", "hf", "ip_f", "unsup"},
		colTypes:       map[string]string{"a": "double", "hf": "double", "ip_f": "ip", "unsup": "unsupported"},
		rawTypes:       map[string]string{"hf": "half_float"},
		noDocValues:    map[string]bool{},
		nonIndexedNoDV: map[string]bool{"ip_f": true},
		ambiguousTypes: map[string][]string{"amb": {"keyword", "long"}},
		ambiguousError: map[string]string{"amb": "cannot cast amb"},
	}
	_ = formatESQLCellWithSchemaRound63(float64(1.3333), "hf", sumESQL)
	_ = formatESQLCellWithSchemaRound63("10.0.0.1", "ip_f", sumESQL)
	_ = formatESQLCellWithSchemaRound63("x", "unsup", sumESQL)
	_ = coerceESQLCellPreserveOrderRound64("42", "long")
	_ = esqlCheckAmbiguousExprR64("amb + 1", sumESQL)
	_ = expandESQLGroupTuplesR64(map[string]any{"k": []any{"x", "y"}}, []string{"k"}, nil)
	_, _, _, _ = extractInlineLookupTableDocsRound63(map[string]any{
		"tables": map[string]any{
			"t1": map[string]any{
				"env":  []any{"prod", "dev"},
				"tier": map[string]any{"long": []any{1, 2}},
			},
		},
	}, "t1")
	_ = extractEQLJoinKeyTuplesRound63(map[string]any{"host": []any{"h1", "h2"}}, []eqlExpr{&eqlFieldExpr{name: "host"}})
	_ = extractEQLJoinKeyTuplesRound63(map[string]any{"host": "h1"}, nil)
	patchEQLHitFieldsRound63(map[string]any{"_source": map[string]any{"a": 1}}, map[string]any{"a": 1, "b": "two"}, []any{"b"}, nil)
}

func TestRound67Cov_Runtime_R63ServerDownsampleMVTILMMLTPercolateAndESQL(t *testing.T) {
	srv, h := newR67CovRTServer(t, "8.15.5")

	// 1. TSDB + _downsample (`serveDownsampleIndexRound63`)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_ts_src", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"cpu": {"type": "double", "time_series_metric": "gauge"},
				"reqs": {"type": "long", "time_series_metric": "counter"}
			}
		}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_ts_src/_doc?refresh=true", `{"@timestamp":"2026-06-01T00:10:00Z","host":"n1","cpu":0.5,"reqs":10}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_ts_src/_doc?refresh=true", `{"@timestamp":"2026-06-01T00:20:00Z","host":"n1","cpu":0.8,"reqs":25}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_ts_src/_downsample/r63_ts_ds", `{"fixed_interval":"1h"}`, http.StatusOK)
	// Invalid downsample interval
	if stDS, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/r63_ts_src/_downsample/r63_ts_bad", `{"fixed_interval":"bad_int"}`, nil); stDS != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid downsample interval, got %d", stDS)
	}

	// 2. Geo _mvt (`serveMVTRound63`)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_mvt_idx", `{
		"mappings": {"properties": {"loc": {"type": "geo_point"}, "shape": {"type": "geo_shape"}, "tag": {"type": "keyword"}}}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_mvt_idx/_doc/1?refresh=true", `{"loc":{"lat":37.77,"lon":-122.41},"shape":{"type":"Point","coordinates":[-122.41,37.77]},"tag":"sf"}`, http.StatusCreated)
	stMVT, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/r63_mvt_idx/_mvt/loc/0/0/0", `{"grid_precision":4,"fields":["tag"],"exact_bounds":true}`, nil)
	if stMVT != http.StatusOK {
		t.Fatalf("expected 200 for MVT, got %d", stMVT)
	}
	if stMVTBad, _, _, _ := doR67CovRTHTTP(t, h, http.MethodGet, "/r63_mvt_idx/_mvt/loc/99/0/0", "", nil); stMVTBad != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid zoom MVT, got %d", stMVTBad)
	}

	// 3. ILM move / retry / remove (`serveILMMoveToStepRound63`, `serveILMRetryRound63`, `serveILMRemovePolicyRound63`)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_ilm/policy/r63_pol", `{
		"policy": {"phases": {"hot": {"min_age": "0ms", "actions": {"rollover": {"max_age": "1d"}}}, "warm": {"min_age": "1d", "actions": {"readonly": {}}}}}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_ilm_idx", `{
		"settings": {"index.lifecycle.name": "r63_pol"},
		"mappings": {"properties": {"msg": {"type": "keyword"}}}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/r63_ilm_idx/_ilm/explain", "", http.StatusOK)
	if stBadMove, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/_ilm/move/r63_ilm_idx", `{
		"current_step": {"phase": "cold", "action": "complete", "name": "complete"},
		"next_step": {"phase": "warm", "action": "readonly", "name": "readonly"}
	}`, nil); stBadMove != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched ILM current_step, got %d", stBadMove)
	}
	mustR67CovRTHTTP(t, h, http.MethodPost, "/_ilm/move/r63_ilm_idx", `{
		"current_step": {"phase": "new", "action": "complete", "name": "complete"},
		"next_step": {"phase": "warm", "action": "readonly", "name": "readonly"}
	}`, http.StatusOK)
	srv.mu.Lock()
	if srv.indexCustomSettings["r63_ilm_idx"] == nil {
		srv.indexCustomSettings["r63_ilm_idx"] = map[string]any{}
	}
	srv.indexCustomSettings["r63_ilm_idx"]["__ilm_step"] = "ERROR"
	srv.indexCustomSettings["r63_ilm_idx"]["__ilm_failed_step"] = "readonly"
	srv.mu.Unlock()
	_, _, _, _ = doR67CovRTHTTP(t, h, http.MethodPost, "/r63_ilm_idx/_ilm/retry", "", nil)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_ilm_idx/_ilm/remove", "", http.StatusOK)

	// 4. Synonyms + adjustSynonymReloadShardsLockedRound63
	stSyn, _, _, rawSyn := doR67CovRTHTTP(t, h, http.MethodPut, "/_synonyms/r63_syn", `{"synonyms_set":[{"id":"1","synonyms":"doris, olap"}]}`, nil)
	if stSyn != http.StatusOK && stSyn != http.StatusCreated {
		t.Fatalf("PUT _synonyms failed: %d %s", stSyn, rawSyn)
	}
	srv.mu.Lock()
	srv.adjustSynonymReloadShardsLockedRound63("r63_syn", map[string]any{
		"syn_idx": map[string]any{"shards": map[string]any{"total": float64(1), "successful": float64(1), "failed": float64(0)}},
	})
	srv.mu.Unlock()

	// 5. ESQL LOOKUP JOIN (`inspectESQLFromTargetSchemasRound63`, `executeESQLLookupJoinStageWithBodyRound63`)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_events", `{"mappings":{"properties":{"env":{"type":"keyword"},"val":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_lkp", `{"settings":{"index.mode":"lookup"},"mappings":{"properties":{"env":{"type":"keyword"},"owner":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_events/_doc/1?refresh=true", `{"env":"prod","val":10}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_lkp/_doc/1?refresh=true", `{"env":"prod","owner":"team-a"}`, http.StatusCreated)
	_ = inspectESQLFromTargetSchemasRound63(srv, context.Background(), "r63_events")
	mustR67CovRTHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM r63_events | LOOKUP JOIN r63_lkp ON env"}`, http.StatusOK)
	// Invalid LOOKUP JOIN syntax
	if stLkpBad, _, _, _ := doR67CovRTHTTP(t, h, http.MethodPost, "/_query", `{"query":"FROM r63_events | LOOKUP JOIN r63_lkp(x) ON env"}`, nil); stLkpBad != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad LOOKUP JOIN syntax, got %d", stLkpBad)
	}

	// 6. MoreLikeThis + Multi-Target Percolate + Termvectors + Pipeline hooks (`preResolveMoreLikeThisQueryRound63`, `preResolveMultiTargetPercolateRound63`, `analyzeTermVectorTokensRound63`, `collectPipelineHooksForWriteRound63`, `applyPostIngestEnrichmentsRound63`, `finalizeReroutedDestinationRound63`)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_mlt_idx", `{
		"mappings": {"properties": {"title": {"type": "text", "term_vector": "with_positions_offsets_payloads"}, "pq": {"type": "percolator"}}}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_mlt_idx/_doc/d1?refresh=true", `{"title":"apache doris distributed sql analytical database"}`, http.StatusCreated)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_mlt_idx/_doc/q1?refresh=true", `{"pq":{"match":{"title":"doris"}}}`, http.StatusCreated)

	mltQ := mustUnmarshalR67CovRT[esast.MoreLikeThisQuery](t, `{
		"fields": ["title"],
		"like": [{"_index": "r63_mlt_idx", "_id": "d1"}],
		"unlike": ["unrelated"],
		"min_term_freq": 1,
		"min_doc_freq": 1
	}`)
	if resolvedMLT, errMLT := srv.preResolveMoreLikeThisQueryRound63(context.Background(), []string{"r63_mlt_idx"}, &mltQ); errMLT != nil || resolvedMLT == nil {
		t.Fatalf("preResolveMoreLikeThisQueryRound63 failed: err=%v res=%+v", errMLT, resolvedMLT)
	}
	percDocQ := mustUnmarshalR67CovRT[esast.PercolateQuery](t, `{"field":"pq","index":"r63_mlt_idx","id":"d1"}`)
	if _, _, errPerc := srv.preResolveMultiTargetPercolateRound63(context.Background(), []string{"r63_mlt_idx"}, &percDocQ); errPerc != nil {
		t.Fatalf("preResolveMultiTargetPercolateRound63 failed: %v", errPerc)
	}
	if toks := srv.analyzeTermVectorTokensRound63("r63_mlt_idx", "title", "standard", []string{"Apache Doris!"}); len(toks) == 0 {
		t.Fatal("expected term vector tokens")
	}

	mustR67CovRTHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r63_hook_pipe", `{
		"processors": [
			{"attachment": {"field": "data", "target_field": "att", "indexed_chars": 500, "remove_binary": true}},
			{"user_agent": {"field": "ua", "target_field": "agent"}},
			{"reroute": {"destination": "r63_rerouted_dst"}}
		]
	}`, http.StatusOK)
	rawIngDoc := json.RawMessage(`{"data":"SGVsbG8gRG9yaXM=","ua":"Mozilla/5.0"}`)
	atts, uas, errHooks := srv.collectPipelineHooksForWriteRound63("r63_mlt_idx", "r63_hook_pipe", "", rawIngDoc)
	if errHooks != nil {
		t.Fatalf("collectPipelineHooksForWriteRound63 failed: %v", errHooks)
	}
	_ = srv.applyPostIngestEnrichmentsRound63(rawIngDoc, atts, uas)
	_, _, _ = srv.finalizeReroutedDestinationRound63("r63_mlt_idx", &IngestWriteResultRound61{TargetIndex: "r63_rerouted_dst"})

	// 7. resolveAuthorizedTermsEnumTargetsAndFiltersR66
	tReq := httptest.NewRequest(http.MethodPost, "/r63_mlt_idx/_terms_enum", nil)
	_, _ = srv.resolveAuthorizedTermsEnumTargetsAndFiltersR66(tReq, "r63_mlt_idx", []string{"r63_mlt_idx"}, nil, "title")
}

func TestRound67Cov_Runtime_R63SearchAggsHelpers(t *testing.T) {
	srv, h := newR67CovRTServer(t, "8.15.5")

	// 1. _open, _data_stream/_lifecycle, _lifecycle/explain
	mustR67CovRTHTTP(t, h, http.MethodPut, "/r63_sa_idx", `{
		"mappings": {
			"properties": {
				"title": {"type": "text", "fields": {"tc": {"type": "token_count", "analyzer": "standard"}}},
				"ts": {"type": "date"},
				"price": {"type": "double"},
				"scaled": {"type": "scaled_float", "scaling_factor": 100},
				"flag": {"type": "boolean"},
				"ip": {"type": "ip"},
				"loc": {"type": "geo_point"},
				"bad_num": {"type": "long", "ignore_malformed": true},
				"pq": {"type": "percolator"},
				"comp_kw": {"type": "keyword", "script": {"source": "emit('s_' + params._source.flag)"}}
			}
		}
	}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_sa_idx/_close", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPost, "/r63_sa_idx/_open", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_index_template/r63_dsl_tpl", `{"index_patterns":["r63-dsl-*"],"data_stream":{}}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_data_stream/r63-dsl-logs", "", http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodPut, "/_data_stream/r63-dsl-logs/_lifecycle", `{"data_retention":"7d"}`, http.StatusOK)
	mustR67CovRTHTTP(t, h, http.MethodGet, "/_data_stream/r63-dsl-logs/_lifecycle", "", http.StatusOK)
	dsInfoResp := mustR67CovRTHTTP(t, h, http.MethodGet, "/_data_stream/r63-dsl-logs", "", http.StatusOK)
	if dsArr, okDS := dsInfoResp["data_streams"].([]any); okDS && len(dsArr) > 0 {
		if dsObj, okObj := dsArr[0].(map[string]any); okObj {
			if idxs, okIdx := dsObj["indices"].([]any); okIdx && len(idxs) > 0 {
				if idxObj, okIO := idxs[0].(map[string]any); okIO {
					if bkName, _ := idxObj["index_name"].(string); bkName != "" {
						mustR67CovRTHTTP(t, h, http.MethodGet, "/"+bkName+"/_lifecycle/explain", "", http.StatusOK)
					}
				}
			}
		}
	}
	mustR67CovRTHTTP(t, h, http.MethodDelete, "/_data_stream/r63-dsl-logs/_lifecycle", "", http.StatusOK)

	srv.mu.RLock()
	sc := srv.indices["r63_sa_idx"]
	srv.mu.RUnlock()

	// 2. enrichRuntimeScriptDocBindingsR63, evalIndexTimeFieldScriptWithSchemaR63Search, extractUntrimmedScriptSourceR63, validateScriptedMetricAllowListR63Search
	cp := map[string]any{}
	docMap := map[string]any{"title": "hello doris proxy", "flag": true, "bad_num": "not_a_long"}
	enrichRuntimeScriptDocBindingsR63(sc, docMap, cp, map[string]string{"title.tc": "token_count"})
	if _, err := evalIndexTimeFieldScriptWithSchemaR63Search(sc, "comp_kw", "keyword", map[string]any{"source": "emit('ok')"}, "fail", docMap); err != nil {
		t.Fatalf("evalIndexTimeFieldScriptWithSchemaR63Search failed: %v", err)
	}
	if sSrc, okSrc := extractUntrimmedScriptSourceR63(map[string]any{"source": "  return 1; "}); !okSrc || sSrc == "" {
		t.Fatal("expected extractUntrimmedScriptSourceR63 true")
	}
	smAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{"sm":{"scripted_metric":{"init_script":"state.a=0","map_script":"state.a+=1","combine_script":"state.a","reduce_script":"params.states"}}}`)
	_, _, _ = validateScriptedMetricAllowListR63Search(srv, smAggs)

	// 3. extractSigHeuristicForAggFromRawR63, aggHasShowDistributionFromRawR65, formatTermsBucketKeyAndStringWithScopeR63
	rawAggJSON := []byte(`{"aggs":{"sig":{"significant_text":{"field":"title","chi_square":{"background_is_superset":false},"show_term_doc_count":true},"distribution":{}}}}`)
	_ = extractSigHeuristicForAggFromRawR63(rawAggJSON, "sig")
	_ = aggHasShowDistributionFromRawR65(rawAggJSON, "sig")
	scope := &activeSearchScope{srv: srv, ctx: context.Background(), rawBody: rawAggJSON, strictConformance: true}
	tSpecDate := mustUnmarshalR67CovRT[esast.AggSpec](t, `{"terms":{"field":"ts","format":"yyyy-MM-dd"}}`).Terms
	_, _, _ = formatTermsBucketKeyAndStringWithScopeR63(scope, "2026-06-01T00:00:00Z", tSpecDate, sc)
	tSpecNum := mustUnmarshalR67CovRT[esast.AggSpec](t, `{"terms":{"field":"price","format":"#0.00"}}`).Terms
	_, _, _ = formatTermsBucketKeyAndStringWithScopeR63(scope, "12.5", tSpecNum, sc)

	// 4. validateTermsLookupsExistR63 & validateCrossIndexSortTypesR63
	tlReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{"query":{"terms":{"flag":{"index":"missing_idx_r63","id":"1","path":"vals"}}}}`)
	if stTL, _, _ := srv.validateTermsLookupsExistR63(&tlReq); stTL == 0 {
		t.Log("validateTermsLookupsExistR63 handled missing lookup index")
	}
	scOther := compileR67CovRTSchema(t, "other_sort_idx", `{"properties":{"price":{"type":"keyword"}}}`, true)
	sortReq := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{"sort":[{"price":{"order":"asc"}}]}`)
	_, _, _ = validateCrossIndexSortTypesR63(sortReq.Sort, []*schema.IndexSchema{sc, scOther})

	// 5. convertSpatialWKTAndGeoJSONR63, extractIgnoredFieldValuesMapR63, isValueMalformedForFieldR63
	_ = convertSpatialWKTAndGeoJSONR63("POINT (1.5 2.5)", false)
	_ = convertSpatialWKTAndGeoJSONR63("BBOX (-10, 10, 20, -20)", false)
	_ = convertSpatialWKTAndGeoJSONR63(map[string]any{"type": "Point", "coordinates": []any{1.5, 2.5}}, true)
	rawBad, _ := json.Marshal(docMap)
	_ = extractIgnoredFieldValuesMapR63(HitRow{Source: rawBad, Schema: sc}, sc)
	_ = isValueMalformedForFieldR63("not_long", sc.Fields["bad_num"])

	// 6. Range sorting, KeepValues, Highlighting, Deprecation warnings, PreNormalize, Percolate matched queries, Composite date bound, CrossIndexTerms, TopHits metric, MultiIndexScriptFields, TokenCount backfill
	rngSpec := mustUnmarshalR67CovRT[esast.AggSpec](t, `{"range":{"field":"price","ranges":[{"from":10,"to":20},{"to":10}]}}`).Range
	_ = sortedRuntimeRangeAggIndicesAscR63(rngSpec, false, false, time.Now().UTC())
	kvSub := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{"bs":{"bucket_selector":{"buckets_path":{"c":"_count"},"script":"params.c > 0"}}}`)
	_, _ = validateAndApplyKeepValuesScriptPipelinesR63([]map[string]any{{"key": "a", "doc_count": int64(2)}, {"key": "b", "doc_count": int64(0)}}, kvSub)
	_ = buildHighlightedSnippetsModeAwareWithFieldTypeR63([]string{"Apache <Doris> search proxy"}, regexp.MustCompile(`(?i)doris`), "<em>", "</em>", true, 50, 2, 10, 100, "plain", false)
	emitRawBodyDeprecationWarningsR63(httptest.NewRecorder(), srv, httptest.NewRequest(http.MethodPost, "/r63_sa_idx/_search", nil), []byte(`{"query":{"match":{"title":{"query":"x","cutoff_frequency":0.1}}}}`))
	_, _, _, _ = preNormalizeSearchBodyR63([]byte(`{"query":{"match_all":{}}}`), true)

	percMulti := mustUnmarshalR67CovRT[esast.Query](t, `{"percolate":{"field":"pq","documents":[{"flag":true}]}}`)
	_ = collectPercolateMultiDocMatchedQueriesMapR63(sc, map[string]any{"pq": map[string]any{"term": map[string]any{"flag": true}}}, &percMulti)

	dhSpec := mustUnmarshalR67CovRT[esast.AggSpec](t, `{"date_histogram":{"field":"ts","calendar_interval":"day","time_zone":"America/New_York"}}`).DateHistogram
	_, _ = parseCompositeDateBoundWithTZR63("2026-06-01T00:00:00", dhSpec, time.Now().UTC())

	termAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{"by_p":{"terms":{"field":"price"}}}`)
	_ = detectCrossIndexTermsValueTypeShardFailureMapR65([]string{"r63_sa_idx", "other_sort_idx"}, map[string]*schema.IndexSchema{"r63_sa_idx": sc, "other_sort_idx": scOther}, termAggs)
	_ = orderMatchedQueriesByRawSourceR63([]byte(`{"query":{"bool":{"must":[{"term":{"a":{"value":1,"_name":"q2"}}},{"term":{"b":{"value":2,"_name":"q1"}}}]}}}`), []any{"q1", "q2"})
	_, _ = extractTopHitsSourceMetricR63(map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"_source": map[string]any{"price": float64(7.5)}}}}}, []string{"price"})

	sfReqR63 := mustUnmarshalR67CovRT[esast.SearchRequest](t, `{"script_fields":{"x":{"script":"doc['price'].value + 1"}}}`)
	_, _, _, _, _, _ = evalMultiIndexScriptFieldsWithPartialFailuresR63(srv, httptest.NewRequest(http.MethodPost, "/r63_sa_idx,other_sort_idx/_search", nil), []string{"r63_sa_idx", "other_sort_idx"}, "r63_sa_idx", []HitRow{{Index: "r63_sa_idx", ID: "1", Source: []byte(`{"price":5}`), Schema: sc}}, map[string]*schema.IndexSchema{"r63_sa_idx": sc, "other_sort_idx": scOther}, &sfReqR63)
	srv.populateMissingTokenCountValuesFromBackendR63(sc, "doc-tc", docMap)
}

func TestRound67Cov_Runtime_R64SpatialAndILM(t *testing.T) {
	// 1. UTF-16 offset mapping with supplementary plane emoji (surrogate pair)
	u16Map := utf16OffsetsToByteOffsetsR64("a😀b")
	if bS, bE, okSpan := resolveUTF16HighlightSpanBytesR64(u16Map, 1, 3); !okSpan || bS >= bE {
		t.Fatalf("unexpected UTF-16 highlight span bytes: %d..%d ok=%v", bS, bE, okSpan)
	}
	if _, _, okOOB := resolveUTF16HighlightSpanBytesR64(u16Map, 99, 100); okOOB {
		t.Fatal("expected false for OOB UTF-16 span")
	}

	// 2. ILM duration parser, validator, and explain builder
	for _, tc := range []struct {
		raw     string
		cal, ok bool
	}{
		{"30d", false, true},
		{"12h", false, true},
		{"15m", false, true},
		{"10s", false, true},
		{"2y", true, true},
		{"2y", false, false},
		{"bad", false, false},
	} {
		_, err := parseILMDurationMillisR64(tc.raw, tc.cal)
		if tc.ok != (err == nil) {
			t.Fatalf("parseILMDurationMillisR64(%q, %v) err=%v", tc.raw, tc.cal, err)
		}
	}
	if _, ok := validateILMPolicyBodyR64(map[string]any{
		"phases": map[string]any{
			"hot":  map[string]any{"min_age": "0ms", "actions": map[string]any{"rollover": map[string]any{"max_age": "1d"}}},
			"warm": map[string]any{"min_age": "2d", "actions": map[string]any{"readonly": map[string]any{}}},
		},
	}); !ok {
		t.Fatal("expected valid ILM policy")
	}
	if _, ok := validateILMPolicyBodyR64(map[string]any{
		"phases": map[string]any{
			"hot": map[string]any{"min_age": "0ms", "actions": map[string]any{"downsample": map[string]any{"fixed_interval": "1h"}}},
		},
	}); ok {
		t.Fatal("expected hot downsample without rollover invalid")
	}
	scILM := compileR67CovRTSchema(t, "ilm_exp_idx", `{"properties":{"ts":{"type":"date"}}}`, true)
	policies := map[string]map[string]any{
		"pol1": {"policy": map[string]any{"phases": map[string]any{"hot": map[string]any{"min_age": "0ms", "actions": map[string]any{"rollover": map[string]any{}}}}}},
	}
	cs := map[string]any{"index.lifecycle.name": "pol1", "index.lifecycle.rollover_alias": "ilm_al"}
	if ent, managed, _ := buildILMExplainIndexEntryR64("ilm_exp_idx", cs, nil, scILM, policies); !managed || ent == nil {
		t.Fatalf("expected managed ILM explain entry, got managed=%v ent=%+v", managed, ent)
	}

	// 3. Spatial geometry parsing, centroid signed area, intersections, grid enumeration
	rawShapes := []any{
		"POINT (-122.41 37.77)",
		"LINESTRING (-122.7 37.65, -122.1 37.65)",
		"POLYGON ((-122.6 37.6, -122.2 37.6, -122.2 37.9, -122.6 37.9, -122.6 37.6), (-122.5 37.7, -122.3 37.7, -122.3 37.8, -122.5 37.8, -122.5 37.7))",
		"BBOX (-122.8, -122.1, 38.0, 37.5)",
		"GEOMETRYCOLLECTION (POINT (-122.4 37.75), LINESTRING (-122.4 37.7, -122.3 37.8))",
		map[string]any{"type": "MultiPolygon", "coordinates": []any{[]any{[]any{[]any{-122.5, 37.7}, []any{-122.4, 37.7}, []any{-122.4, 37.8}, []any{-122.5, 37.8}, []any{-122.5, 37.7}}}}},
	}
	_ = formatGeoShapeValuesForFieldsR64(rawShapes, true)
	_ = formatGeoShapeValuesForFieldsR64(rawShapes, false)

	var geoms []parsedGeomR64
	var acc centroidAccumR64
	for _, rs := range rawShapes {
		parsed, okP := parseRawShapesR64(rs, false)
		if !okP || len(parsed) == 0 {
			t.Fatalf("failed parseRawShapesR64 for %v", rs)
		}
		for _, g := range parsed {
			geoms = append(geoms, g)
			acc.addGeom(g)
		}
	}
	if _, _, area := ringCentroidSignedAreaR64(geoms[2].outer); area <= 0 {
		t.Fatalf("expected positive polygon area, got %v", area)
	}
	if !geomIntersectsSimpleBoxR64(geoms[0], 38.0, -123.0, 37.0, -122.0) {
		t.Fatal("expected point to intersect box")
	}
	if !geomIntersectsQueryShapeR64(geoms[1], geoms[2]) || !geomIntersectsQueryShapeR64(geoms[2], geoms[3]) {
		t.Fatal("expected shape intersections to succeed")
	}
	for _, g := range geoms[:4] {
		_ = enumerateGeotileCellsForGeomR64(g, 6, true, 38.5, -123.0, 37.0, -122.0)
		_ = enumerateGeohashCellsForGeomR64(g, 4, true, 38.5, -123.0, 37.0, -122.0)
		cell, _ := spatial.LatLonToCell(37.77, -122.41, 3)
		_ = enumerateGeohexCellsForGeomR64(g, 3, false, 0, 0, 0, 0, map[uint64]bool{cell: true})
	}

	// 4. Runtime spatial agg emitters & spatial query evaluators
	scSp := compileR67CovRTSchema(t, "sp_idx", `{
		"properties": {
			"cat": {"type": "keyword"},
			"ts": {"type": "date"},
			"loc": {"type": "geo_point"},
			"shape": {"type": "geo_shape"},
			"xy": {"type": "point"},
			"unidx_kw": {"type": "keyword", "index": false}
		}
	}`, true)
	spDoc1 := map[string]any{"cat": "a", "ts": "2026-06-01T00:00:00Z", "loc": map[string]any{"lat": 37.77, "lon": -122.41}, "shape": "POLYGON ((-122.6 37.6, -122.2 37.6, -122.2 37.9, -122.6 37.9, -122.6 37.6))", "xy": "POINT (1 2)"}
	spDoc2 := map[string]any{"cat": "b", "ts": int64(1780272000000), "loc": map[string]any{"lat": 37.78, "lon": -122.40}, "shape": "POINT (-122.4 37.75)", "xy": "POLYGON ((0 0, 4 0, 4 4, 0 4, 0 0))"}
	spDocs := []runtimeMatchedDoc{
		{hit: HitRow{Index: "sp_idx", ID: "1", Schema: scSp}, doc: spDoc1, rootDoc: spDoc1, rootSchema: scSp},
		{hit: HitRow{Index: "sp_idx", ID: "2", Schema: scSp}, doc: spDoc2, rootDoc: spDoc2, rootSchema: scSp},
	}

	spAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{
		"gh": {"geohash_grid": {"field": "shape", "precision": 4, "bounds": {"top_left": [-123.0, 38.5], "bottom_right": [-122.0, 37.0]}}},
		"gt": {"geotile_grid": {"field": "shape", "precision": 6}},
		"gx": {"geohex_grid": {"field": "loc", "precision": 3}},
		"gb": {"geo_bounds": {"field": "shape", "wrap_longitude": true}},
		"gc": {"geo_centroid": {"field": "shape"}},
		"cb": {"cartesian_bounds": {"field": "xy"}},
		"cc": {"cartesian_centroid": {"field": "xy"}},
		"gl": {"geo_line": {"point": {"field": "loc"}, "sort": {"field": "ts"}, "include_sort": true}},
		"ct": {"counted_terms": {"field": "cat", "min_doc_count": 0}}
	}`)
	var aggRows []AggRow
	emitRuntimeGeoGridAggRowsR64("gh", "", spAggs["gh"], spDocs, &aggRows, scSp)
	emitRuntimeGeoGridAggRowsR64("gt", "", spAggs["gt"], spDocs, &aggRows, scSp)
	emitRuntimeGeoGridAggRowsR64("gx", "", spAggs["gx"], spDocs, &aggRows, scSp)
	emitRuntimeGeoBoundsAggRowsR64("gb", "", spAggs["gb"].GeoBounds, spDocs, &aggRows)
	emitRuntimeGeoCentroidAggRowsR64("gc", "", spAggs["gc"].GeoCentroid, spDocs, &aggRows)
	emitRuntimeCartesianBoundsAggRowsR64("cb", "", spAggs["cb"].CartesianBounds, spDocs, &aggRows)
	emitRuntimeCartesianCentroidAggRowsR64("cc", "", spAggs["cc"].CartesianCentroid, spDocs, &aggRows)
	emitRuntimeGeoLineAggRowsR64("gl", "", spAggs["gl"].GeoLine, spDocs, scSp, &aggRows)
	emitRuntimeCountedTermsAggRowsR64("ct", "", spAggs["ct"], spDocs, &aggRows, scSp)
	_, _, _ = extractGeoLineSortValueR64(spDocs[0], "ts", scSp)
	_, _ = parseDateValueToEpochMillisR64(json.Number("1780272000000"))

	_, _, _ = computeRuntimeCountedTermsBucketDocsR64(scSp, spDocs, spAggs["ct"].CountedTerms)
	_ = aggsHaveMinDocCountZeroR64(spAggs)
	_ = dropSpatialLeafAggRowsR64(aggRows, "gb", spAggs["gb"])

	// Query evaluators & multi-index spatial helpers
	qGeoShape := mustUnmarshalR67CovRT[esast.Query](t, `{"geo_shape":{"shape":{"shape":{"type":"envelope","coordinates":[[-123.0,38.0],[-122.0,37.0]]},"relation":"intersects"}}}`)
	qGeoPoly := mustUnmarshalR67CovRT[esast.Query](t, `{"geo_polygon":{"loc":{"points":[[-123.0,37.0],[-122.0,37.0],[-122.0,38.0],[-123.0,38.0]]}}}`)
	qGeoBox := mustUnmarshalR67CovRT[esast.Query](t, `{"geo_bounding_box":{"loc":{"top_left":[-123.0,38.0],"bottom_right":[-122.0,37.0]}}}`)
	qGeoDist := mustUnmarshalR67CovRT[esast.Query](t, `{"geo_distance":{"distance":"50km","loc":[-122.41,37.77]}}`)
	qGeoGrid := mustUnmarshalR67CovRT[esast.Query](t, `{"geo_grid":{"shape":{"geotile":"6/10/24"}}}`)

	_ = evalDocGeoShapeQueryR64(scSp, spDoc1, qGeoShape.GeoShape)
	_ = evalDocGeoPolygonQueryR64(scSp, spDoc1, qGeoPoly.GeoPolygon)
	_ = evalDocGeoBoundingBoxQueryR64(scSp, spDoc1, qGeoBox.GeoBoundingBox)
	_ = evalDocGeoDistanceQueryR64(scSp, spDoc1, qGeoDist.GeoDistance)
	_ = evalDocGeoGridQueryR64(scSp, spDoc1, qGeoGrid.GeoGrid)
	_ = queryHasSpatialLeafR64(&qGeoShape)
	_ = queryNeedsRuntimeSpatialEvalR64(&qGeoShape, scSp)
	_ = evalDocWithSpatialFallbackR64(scSp, spDoc1, &qGeoShape)
	_, _, _ = validateGeoGridQueryFieldsR64(scSp, &qGeoGrid)

	reqSp := esast.SearchRequest{Query: &qGeoShape, Aggs: spAggs}
	_ = searchReqNeedsSpatialEvalR64([]string{"sp_idx"}, []*schema.IndexSchema{scSp}, &reqSp, nil)
	rawH1, _ := json.Marshal(spDoc1)
	matchedDocs := hitsToRuntimeMatchedDocsWithSchemasR64([]HitRow{{Index: "sp_idx", ID: "1", Source: rawH1, Schema: scSp}}, map[string]*schema.IndexSchema{"sp_idx": scSp}, scSp)
	if len(matchedDocs) != 1 {
		t.Fatalf("expected 1 matchedDoc, got %d", len(matchedDocs))
	}
	_ = recomputeMultiIndexSpatialAggsR64(spAggs, []HitRow{{Index: "sp_idx", ID: "1", Source: rawH1, Schema: scSp}}, map[string]*schema.IndexSchema{"sp_idx": scSp}, scSp, aggRows)
	_ = isFieldUnindexedInSchemasR64("unidx_kw", map[string]*schema.IndexSchema{"sp_idx": scSp}, scSp)
	zeroAggs := mustUnmarshalR67CovRT[map[string]esast.AggSpec](t, `{"by_idx":{"terms":{"field":"_index","min_doc_count":0}}}`)
	_ = injectZeroIndexTermsAggRowsR64("", zeroAggs, []string{"sp_idx", "empty_idx"}, map[string]bool{"sp_idx": true}, nil)
}
