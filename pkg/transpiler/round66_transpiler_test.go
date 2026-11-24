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

package transpiler

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"testing/quick"
	"unicode"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound66Schema(t *testing.T) (*schema.IndexSchema, *analysis.IndexAnalysisConfig) {
	t.Helper()
	anCfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"syns": map[string]any{
					"type":     "synonym",
					"synonyms": []any{"quick,fast"},
				},
			},
			"analyzer": map[string]any{
				"syns": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "syns"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}
	sch := mustCompileSchemaR63(t, "r66_idx", `{
		"properties": {
			"title": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword"},
					"english": {"type": "text", "analyzer": "english"}
				}
			},
			"field1": {"type": "text", "analyzer": "syns"},
			"field2": {"type": "text", "analyzer": "syns"},
			"status": {"type": "keyword"},
			"cnt": {"type": "long"},
			"uid": {"type": "unsigned_long"},
			"price": {"type": "double"},
			"sf": {"type": "scaled_float", "scaling_factor": 100},
			"ts": {"type": "date"},
			"@timestamp": {"type": "date"},
			"fr_date": {"type": "date", "format": "E, d MMM yyyy HH:mm:ss Z", "locale": "fr"},
			"lrng": {"type": "long_range"},
			"drng": {"type": "date_range", "format": "E, d MMM yyyy HH:mm:ss Z", "locale": "fr"},
			"loc": {"type": "geo_point"},
			"vec": {"type": "dense_vector", "dims": 4, "index": true, "similarity": "l2_norm"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"qty": {"type": "long"},
					"price": {"type": "double"}
				}
			},
			"labels": {"type": "flattened"}
		}
	}`)
	return sch, anCfg
}

// findRawNumericFieldCastR66 scans SQL with balanced parenthesis tracking to detect
// any raw `CAST(<expr> AS BIGINT|DOUBLE|LARGEINT)` whose argument references a field/
// offset/floor/truncate/bucket expression (while allowing outer `CAST(... AS STRING)`
// that wraps inner `TRY_CAST(...)` and metadata casts like `CAST(MAX(_score) AS DOUBLE)`).
func findRawNumericFieldCastR66(sql string) string {
	upper := strings.ToUpper(sql)
	for i := 0; i < len(sql); i++ {
		switch sql[i] {
		case '\'':
			i++
			for i < len(sql) {
				if sql[i] == '\'' {
					if i+1 < len(sql) && sql[i+1] == '\'' {
						i += 2
						continue
					}
					break
				}
				i++
			}
			continue
		case '`':
			i++
			for i < len(sql) && sql[i] != '`' {
				i++
			}
			continue
		}
		if !strings.HasPrefix(upper[i:], "CAST(") {
			continue
		}
		if i > 0 {
			prev := rune(sql[i-1])
			if unicode.IsLetter(prev) || unicode.IsDigit(prev) || prev == '_' {
				continue
			}
		}
		depth := 0
		end := -1
		for j := i + 4; j < len(sql); j++ {
			switch sql[j] {
			case '\'':
				j++
				for j < len(sql) {
					if sql[j] == '\'' {
						if j+1 < len(sql) && sql[j+1] == '\'' {
							j += 2
							continue
						}
						break
					}
					j++
				}
			case '`':
				j++
				for j < len(sql) && sql[j] != '`' {
					j++
				}
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			continue
		}
		inner := sql[i+5 : end]
		innerUp := strings.ToUpper(inner)
		asIdx := strings.LastIndex(innerUp, " AS ")
		if asIdx < 0 {
			continue
		}
		targetType := strings.TrimSpace(innerUp[asIdx+4:])
		if targetType != "BIGINT" && targetType != "DOUBLE" && targetType != "LARGEINT" {
			continue
		}
		arg := inner[:asIdx]
		argUp := strings.ToUpper(arg)
		if strings.Contains(arg, "`f__") ||
			strings.Contains(arg, "`_off`") ||
			strings.Contains(argUp, "FLOOR(") ||
			strings.Contains(argUp, "TRUNCATE(") ||
			strings.Contains(arg, "`_bucket_key`") {
			return sql[i : end+1]
		}
	}
	return ""
}

func TestRound66_PropertyNoRawNumericCastSQL(t *testing.T) {
	sch, anCfg := buildRound66Schema(t)
	tr := NewTranspiler(sch, TranspilerOptions{
		AnalysisConfig: anCfg,
		RawHistBounds: map[string]RawHistParamStrings{
			"h_ul":   {Interval: "9223372036854775807", Offset: "0"},
			"h_long": {Interval: "9223372036854775807", Offset: "0"},
		},
	})

	cfg := &quick.Config{MaxCount: 40}
	sortFields := []string{"cnt", "price", "sf", "uid", "ts", "items.price"}
	numericTypes := []string{"", "long", "double"}
	orders := []string{"asc", "desc"}
	histIntervals := []float64{10, 25, 1000, 9223372036854775807}
	histOffsets := []float64{0, 5, -5}
	geotilePrecs := []int{1, 4, 7, 12}

	prop := func(sfIdx, ntIdx, ordIdx, hiIdx, hoIdx, gpIdx uint8) bool {
		sf := sortFields[int(sfIdx)%len(sortFields)]
		nt := numericTypes[int(ntIdx)%len(numericTypes)]
		ord := orders[int(ordIdx)%len(orders)]
		iv := histIntervals[int(hiIdx)%len(histIntervals)]
		off := histOffsets[int(hoIdx)%len(histOffsets)]
		prec := geotilePrecs[int(gpIdx)%len(geotilePrecs)]

		var afterJSON string
		switch sf {
		case "items.price":
			afterJSON = `,"search_after":[12.5,"doc1"]`
		case "cnt", "sf":
			afterJSON = `,"search_after":[42,"doc1"]`
		case "uid":
			afterJSON = `,"search_after":["18446744073709551615","doc1"]`
		case "ts":
			afterJSON = `,"search_after":["2025-01-01T00:00:00Z","doc1"]`
		default:
			afterJSON = `,"search_after":[3.14,"doc1"]`
		}
		ntPart := ""
		if nt != "" {
			ntPart = `,"numeric_type":"` + nt + `"`
		}
		nestedPart := ""
		if strings.HasPrefix(sf, "items.") {
			nestedPart = `,"nested":{"path":"items"}`
		}
		reqObj := map[string]any{
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						map[string]any{"range": map[string]any{"lrng": map[string]any{"gte": 1, "lte": 100}}},
					},
				},
			},
			"aggs": map[string]any{
				"h_ul":   map[string]any{"histogram": map[string]any{"field": "uid", "interval": iv, "offset": off}},
				"h_long": map[string]any{"histogram": map[string]any{"field": "cnt", "interval": iv, "offset": off}},
				"h_rng":  map[string]any{"histogram": map[string]any{"field": "lrng", "interval": 10, "offset": off}},
				"dh":     map[string]any{"date_histogram": map[string]any{"field": "ts", "fixed_interval": "1h", "time_zone": "America/New_York"}},
				"vwh":    map[string]any{"variable_width_histogram": map[string]any{"field": "price", "buckets": 5}},
				"gt":     map[string]any{"geotile_grid": map[string]any{"field": "loc", "precision": prec}},
			},
		}
		rawBase, _ := json.Marshal(reqObj)
		rawStr := strings.TrimSuffix(string(rawBase), "}") +
			`,"sort":[{"` + sf + `":{"order":"` + ord + `"` + ntPart + nestedPart + `}}]` + afterJSON + `}`
		var req esast.SearchRequest
		dec := json.NewDecoder(strings.NewReader(rawStr))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			t.Logf("decode error: %v (%s)", err, rawStr)
			return false
		}
		plan, err := tr.BuildSearchPlan(&req)
		if err != nil {
			t.Logf("plan error: %v", err)
			return false
		}
		if bad := findRawNumericFieldCastR66(plan.HitsSQL); bad != "" {
			t.Logf("raw numeric CAST in HitsSQL: %s", bad)
			return false
		}
		if bad := findRawNumericFieldCastR66(plan.AggsSQL); bad != "" {
			t.Logf("raw numeric CAST in AggsSQL: %s", bad)
			return false
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("property check failed: %v", err)
	}
}

func TestRound66_Task1_LargeIntBoundsAndRangeClamp(t *testing.T) {
	// 1. 128-bit Doris LARGEINT bounds [-2^127, 2^127-1]
	valid := []string{
		"0", "1", "-5", "+42", "9223372036854775807",
		"170141183460469231731687303715884105727",
		"-170141183460469231731687303715884105728",
	}
	for _, s := range valid {
		if !isExactSignedIntLiteralR65(s) {
			t.Fatalf("expected valid LARGEINT %q", s)
		}
	}
	invalid := []string{
		"", "-", "+", "12.5", "1e20", "abc",
		"170141183460469231731687303715884105728",
		"-170141183460469231731687303715884105729",
		"9999999999999999999999999999999999999999",
	}
	for _, s := range invalid {
		if isExactSignedIntLiteralR65(s) {
			t.Fatalf("expected invalid LARGEINT %q", s)
		}
	}

	// 2. interval <= 0 rejected / safely normalized without division by <= 0 or raw CAST
	ulB := schema.FieldBinding{ESType: "unsigned_long", DorisType: schema.DorisLargeInt}
	sZero := formatHistogramBucketKeySQLWithRawParamsR65("`f__uid`", 0, 0, RawHistParamStrings{Interval: "0"}, ulB)
	if strings.Contains(sZero, "/ 0") || findRawNumericFieldCastR66(sZero) != "" {
		t.Fatalf("unexpected SQL for zero interval: %s", sZero)
	}
	sNeg := formatHistogramBucketKeySQLWithRawParamsR65("`f__uid`", 0, -5, RawHistParamStrings{Interval: "-5"}, ulB)
	if strings.Contains(sNeg, "/ -5") || findRawNumericFieldCastR66(sNeg) != "" {
		t.Fatalf("unexpected SQL for negative interval: %s", sNeg)
	}
	sOverflowRaw := formatHistogramBucketKeySQLWithRawParamsR65("`f__uid`", 0, 10, RawHistParamStrings{Interval: "170141183460469231731687303715884105728"}, ulB)
	if strings.Contains(sOverflowRaw, "170141183460469231731687303715884105728") {
		t.Fatalf("expected overflow LARGEINT interval literal to be rejected, got: %s", sOverflowRaw)
	}

	// 3. P2 fix: parseExactInt64RangeBoundR65 clamps 1e30 and -1e30 on json.Number, string, float64
	for _, bound := range []any{json.Number("1e30"), "1e30", float64(1e30)} {
		for _, isUp := range []bool{false, true} {
			got, ok := parseExactInt64RangeBoundR65(bound, isUp)
			if !ok || got != math.MaxInt64 {
				t.Fatalf("parseExactInt64RangeBoundR65(%T=%v, %v) = (%d, %v), want (%d, true)", bound, bound, isUp, got, ok, math.MaxInt64)
			}
		}
	}
	for _, bound := range []any{json.Number("-1e30"), "-1e30", float64(-1e30)} {
		for _, isUp := range []bool{false, true} {
			got, ok := parseExactInt64RangeBoundR65(bound, isUp)
			if !ok || got != math.MinInt64 {
				t.Fatalf("parseExactInt64RangeBoundR65(%T=%v, %v) = (%d, %v), want (%d, true)", bound, bound, isUp, got, ok, math.MinInt64)
			}
		}
	}
}

func TestRound66_Task2_BM25CorpusStatsAndVariantExists(t *testing.T) {
	sch, anCfg := buildRound66Schema(t)

	// 1. CollectBM25QueryRequirements collects match / multi_match / phrase / rescore terms
	var synReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {"multi_match": {"query": "the fast brown", "fields": ["field1", "field2"], "operator": "and"}},
		"rescore": [{"window_size": 5, "query": {"rescore_query": {"match_phrase": {"title": "Weird Al's"}}}}]
	}`), &synReq)
	reqs := CollectBM25QueryRequirements(&synReq, sch, TranspilerOptions{AnalysisConfig: anCfg})
	if len(reqs) < 2 {
		t.Fatalf("expected >= 2 BM25 requirements for field1/field2/title, got %+v", reqs)
	}

	// 2. Nil CorpusBM25Stats preserves MemoryBackend signature `'[^[:alnum:]_]+', '  '`
	nilPlan, err := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg}).BuildSearchPlan(&synReq)
	if err != nil || !strings.Contains(nilPlan.HitsSQL, "'[^[:alnum:]_]+', '  '") {
		t.Fatalf("expected legacy BM25 signature when CorpusBM25Stats is nil: err=%v sql=%s", err, nilPlan.HitsSQL)
	}

	// 3. Populated CorpusBM25Stats computes (k1+1), exact IDF, real AvgDL, and preserves Al's apostrophe
	stats := map[string]*BM25FieldTermStats{
		"`f__field1`": {TotalDocs: 3, AvgDL: 6.3333, TermDocFreq: map[string]int64{"quick": 3, "fast": 3, "brown": 3}},
		"field2":      {TotalDocs: 1, AvgDL: 9.0, TermDocFreq: map[string]int64{"quick": 1, "fast": 1, "brown": 1}},
		"title":       {TotalDocs: 0, AvgDL: 0, TermDocFreq: nil},
	}
	statsPlan, err := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg, CorpusBM25Stats: stats}).BuildSearchPlan(&synReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan with CorpusBM25Stats failed: %v", err)
	}
	if !strings.Contains(statsPlan.HitsSQL, "[^[:alnum:]_'']+") || !strings.Contains(statsPlan.HitsSQL, "/ 9)") {
		t.Fatalf("expected apostrophe-preserving regex and AvgDL=9 in BM25 SQL:\n%s", statsPlan.HitsSQL)
	}
	// N=1, df=1 -> idf = ln(1 + 0.5/1.5) = 0.287682..., * (1.2+1) = 0.632900...
	if !strings.Contains(statsPlan.HitsSQL, "0.6329") {
		t.Fatalf("expected Lucene IDF*(k1+1) factor (~0.6329) for field2, got:\n%s", statsPlan.HitsSQL)
	}

	// 4. Phrase sums per-term IDF
	var phrReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"match_phrase":{"field1":"quick brown"}}}`), &phrReq)
	phrStats := map[string]*BM25FieldTermStats{
		"field1": {TotalDocs: 3, AvgDL: 4.0, TermDocFreq: map[string]int64{"quick": 3, "brown": 1}},
	}
	phrPlan, err := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg, CorpusBM25Stats: phrStats}).BuildSearchPlan(&phrReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan phrase BM25 failed: %v", err)
	}
	// field1 uses the synonym analyzer, expanding "quick brown" into 2 graph branches (boost 0.5 each).
	// Compute exact (boost * idfSum) * (k1 + 1.0): branch 1 has quick(df=3)+brown(df=1), branch 2 has fast(clamped df=1)+brown(df=1).
	expectedSumIDF := math.Log(1.0+0.5/3.5) + math.Log(1.0+2.5/1.5)
	expectedFastSumIDF := 2.0 * math.Log(1.0+2.5/1.5)
	_ = expectedSumIDF
	_ = expectedFastSumIDF
	if !strings.Contains(phrPlan.HitsSQL, "1.22579671019987") || !strings.Contains(phrPlan.HitsSQL, "2.15782435662579") {
		t.Fatalf("expected summed phrase IDF*(k1+1) scales (~1.22579671019987 and ~2.15782435662579), got:\n%s", phrPlan.HitsSQL)
	}

	// 5. Dynamic VARIANT exists emits 2-arg JSON_TYPE(... != 'NULL') while preserving flattened/promoted/nested
	tr := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg})
	var dynQ, knnFiltQ, flatQ, nestedQ esast.Query
	_ = json.Unmarshal([]byte(`{"exists":{"field":"dyn.extra"}}`), &dynQ)
	wDyn := tr.CompileQuery(&dynQ, false, nil).WhereSQL
	if !strings.Contains(wDyn, "JSON_TYPE(TRY_CAST(`_source` AS JSON), '$.\"dyn\".\"extra\"') IS NOT NULL") ||
		!strings.Contains(wDyn, "JSON_TYPE(TRY_CAST(`_source` AS JSON), '$.\"dyn\".\"extra\"') != 'NULL'") {
		t.Fatalf("unexpected dynamic VARIANT exists SQL: %s", wDyn)
	}
	_ = json.Unmarshal([]byte(`{"knn":{"field":"vec","query_vector":[1,0,0,0],"k":2,"filter":[{"exists":{"field":"dyn_root"}}]}}`), &knnFiltQ)
	wKnn := tr.CompileQuery(&knnFiltQ, true, nil).WhereSQL
	if !strings.Contains(wKnn, "JSON_TYPE(TRY_CAST(`_source` AS JSON), '$.\"dyn_root\"') != 'NULL'") {
		t.Fatalf("unexpected knn.filter dynamic VARIANT exists SQL: %s", wKnn)
	}
	_ = json.Unmarshal([]byte(`{"exists":{"field":"labels"}}`), &flatQ)
	if wFlat := tr.CompileQuery(&flatQ, false, nil).WhereSQL; !strings.Contains(wFlat, "!= '{}'") {
		t.Fatalf("expected flattened exists to keep != '{}', got %s", wFlat)
	}
	_ = json.Unmarshal([]byte(`{"nested":{"path":"items","query":{"exists":{"field":"items.sku"}}}}`), &nestedQ)
	if wNest := tr.CompileQuery(&nestedQ, false, nil).WhereSQL; strings.Contains(wNest, "JSON_TYPE(") {
		t.Fatalf("did not expect JSON_TYPE for nested promoted column exists, got %s", wNest)
	}
}

func TestRound66_Clusters5_6_9_11_13_15(t *testing.T) {
	sch, anCfg := buildRound66Schema(t)

	// Cluster 5: fixed_interval + non-fixed IANA timezone uses CONVERT_TZ back to UTC on floored local time
	dhPlan, err := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg}).BuildSearchPlan(&esast.SearchRequest{
		Size: intPtrR66(0),
		Aggs: map[string]esast.AggSpec{
			"dst_1d": {DateHistogram: &esast.DateHistogramAggSpec{
				Field: "@timestamp", FixedInterval: "1d", TimeZone: "America/New_York",
			}},
			"dst_1h": {DateHistogram: &esast.DateHistogramAggSpec{
				Field: "@timestamp", FixedInterval: "1h", TimeZone: "America/New_York", Offset: "+15m",
			}},
		},
	})
	if err != nil {
		t.Fatalf("Cluster 5 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(dhPlan.AggsSQL, "CONVERT_TZ(SECONDS_ADD(") || !strings.Contains(dhPlan.AggsSQL, ", 'America/New_York', '+00:00')") {
		t.Fatalf("expected CONVERT_TZ(..., 'America/New_York', '+00:00') on floored local boundary, got:\n%s", dhPlan.AggsSQL)
	}

	// Cluster 6: ImplicitTimestampSort
	trImp := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg, ImplicitTimestampSort: true})
	pScoreless, err := trImp.BuildSearchPlan(&esast.SearchRequest{})
	if err != nil {
		t.Fatalf("Cluster 6 scoreless plan failed: %v", err)
	}
	if !strings.Contains(pScoreless.HitsSQL, "ORDER BY `f___40_timestamp` DESC NULLS LAST, `_id` ASC") {
		t.Fatalf("expected implicit @timestamp DESC NULLS LAST sort, got:\n%s", pScoreless.HitsSQL)
	}
	var matchReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"match":{"title":"stars"}}}`), &matchReq)
	pScored, err := trImp.BuildSearchPlan(&matchReq)
	if err != nil || !strings.Contains(pScored.HitsSQL, "ORDER BY `_score` DESC, `f___40_timestamp` DESC NULLS LAST, `_id` ASC") {
		t.Fatalf("expected _score DESC before implicit @timestamp DESC NULLS LAST, err=%v sql=%s", err, pScored.HitsSQL)
	}
	schNoTS := mustCompileSchemaR63(t, "no_ts", `{"properties":{"name":{"type":"keyword"}}}`)
	pNoTS, _ := NewTranspiler(schNoTS, TranspilerOptions{ImplicitTimestampSort: true}).BuildSearchPlan(&esast.SearchRequest{})
	if strings.Contains(pNoTS.HitsSQL, "@timestamp") || !strings.Contains(pNoTS.HitsSQL, "ORDER BY `_score` DESC, `_id` ASC") {
		t.Fatalf("did not expect @timestamp sort when not mapped, got:\n%s", pNoTS.HitsSQL)
	}

	// Cluster 9: nested agg unmapped path returns empty plan; mapped non-nested path returns 400
	tr := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: anCfg})
	var nestAggUnmapped, nestAggMappedNonNested esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"unm":{"nested":{"path":"foo"},"aggs":{"h":{"date_histogram":{"field":"foo.date","calendar_interval":"day"}}}}}}`), &nestAggUnmapped)
	pUnm, err := tr.BuildSearchPlan(&nestAggUnmapped)
	if err != nil || !strings.Contains(pUnm.AggsSQL, "EXPLODE(CAST([] AS ARRAY<STRING>))") || strings.Contains(pUnm.AggsSQL, "n__foo") {
		t.Fatalf("expected unmapped nested agg empty plan without n__foo, err=%v sql=%v", err, pUnm)
	}
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"bad":{"nested":{"path":"status"}}}}`), &nestAggMappedNonNested)
	if _, err := tr.BuildSearchPlan(&nestAggMappedNonNested); err == nil {
		t.Fatalf("expected error on nested agg targeting mapped non-nested field [status]")
	}

	// Cluster 11: English analyzer phrase & query_string stemmed matching
	var qsPhraseReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "\"dancing with the stars\"",
				"fields": ["title^5", "title.english"],
				"phrase_slop": 2
			}
		}
	}`), &qsPhraseReq)
	pEng, err := tr.BuildSearchPlan(&qsPhraseReq)
	if err != nil {
		t.Fatalf("Cluster 11 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(pEng.HitsSQL, "danc[[:alpha:]]*") || !strings.Contains(pEng.HitsSQL, "star[[:alpha:]]*") {
		t.Fatalf("expected stemmed english token regexes (danc[[:alpha:]]*, star[[:alpha:]]*), got:\n%s", pEng.HitsSQL)
	}
	// Exact English phrase (slop=0) on stopwords should allow stopword gap
	cqEngExact := tr.CompileQuery(&esast.Query{
		MatchPhrase: map[string]esast.PhraseEntry{"title.english": {Query: "dancing with the stars"}},
	}, false, nil)
	if !strings.Contains(cqEngExact.WhereSQL, "danc[[:alpha:]]*") || !strings.Contains(cqEngExact.WhereSQL, "{0,2}") {
		t.Fatalf("expected stemmed stopword-gap phrase regex, got: %s", cqEngExact.WhereSQL)
	}

	// Cluster 13: kNN query scales candidate fetch by NumberOfShards when k omitted
	var knnShardReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":2,"query":{"knn":{"field":"vec","query_vector":[1,1,1,1],"num_candidates":3}}}`), &knnShardReq)
	pKNN2, err := NewTranspiler(sch, TranspilerOptions{NumberOfShards: 2}).BuildSearchPlan(&knnShardReq)
	if err != nil || !strings.Contains(pKNN2.HitsSQL, "`_rn` <= 6") {
		t.Fatalf("expected NumberOfShards=2 to scale query.knn limit 3 -> 6, err=%v sql=%v", err, pKNN2)
	}

	// Cluster 15: collapse CollapseMaxScoreSQL, French locale range date, long vs unsigned_long histogram alignment
	var colReq, frReq, histAlignReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":1,"query":{"match":{"title":"stars"}},"collapse":{"field":"status"}}`), &colReq)
	pCol, err := tr.BuildSearchPlan(&colReq)
	if err != nil || !strings.Contains(pCol.CollapseMaxScoreSQL, "MAX(`_score`)") || !strings.Contains(pCol.CollapseMaxScoreSQL, "_overall_max_score") {
		t.Fatalf("expected pre-collapse CollapseMaxScoreSQL, err=%v colMax=%q", err, pCol.CollapseMaxScoreSQL)
	}
	if !strings.HasPrefix(pCol.HitsSQL, "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM") {
		t.Fatalf("expected non-breaking 5-column HitsSQL projection, got:\n%s", pCol.HitsSQL)
	}

	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"range": {"fr_date": {"gte": "mar., 5 déc. 2000 02:55:00 -0800", "lte": "ven., 8 déc. 2000 00:00:00 -0800"}}},
					{"term": {"fr_date": "mer., 6 déc. 2000 02:55:00 -0800"}},
					{"range": {"drng": {"gte": "mar., 5 déc. 2000 02:55:00 -0800"}}}
				]
			}
		}
	}`), &frReq)
	pFR, err := tr.BuildSearchPlan(&frReq)
	if err != nil || strings.Contains(pFR.HitsSQL, "AND FALSE") {
		t.Fatalf("expected French locale date bounds to parse cleanly, err=%v sql=%s", err, pFR.HitsSQL)
	}

	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"h_long": {"histogram": {"field": "cnt", "interval": 9223372036854775807}},
			"h_ul":   {"histogram": {"field": "uid", "interval": 9223372036854775807}}
		}
	}`), &histAlignReq)
	trHist := NewTranspiler(sch, TranspilerOptions{
		RawHistBounds: map[string]RawHistParamStrings{
			"h_long": {Interval: "9223372036854775807"},
			"h_ul":   {Interval: "9223372036854775807"},
		},
	})
	pHistAlign, err := trHist.BuildSearchPlan(&histAlignReq)
	if err != nil {
		t.Fatalf("Cluster 15 hist align failed: %v", err)
	}
	if strings.Count(pHistAlign.AggsSQL, "AS LARGEINT) * 9223372036854775807") != 2 {
		t.Fatalf("expected both long and unsigned_long histograms to align on LARGEINT * 9223372036854775807, got:\n%s", pHistAlign.AggsSQL)
	}

	// Wave 2.5: long_range term uses exact int64 range compilation & dynamic/sparse_vector exists rejects empty JSON array []
	var lrTermQ, svExistsQ esast.Query
	if err := json.Unmarshal([]byte(`{"term":{"lrng":{"value":-9223372036854775808}}}`), &lrTermQ); err != nil {
		t.Fatalf("unmarshal long_range term query: %v", err)
	}
	lrTermSQL := tr.CompileQuery(&lrTermQ, false, nil).WhereSQL
	if !strings.Contains(lrTermSQL, "-9223372036854775808") || strings.Contains(lrTermSQL, "-9223372036854775808.0") || !strings.Contains(lrTermSQL, `"gt":null`) {
		t.Fatalf("expected exact int64 null-aware SQL for long_range MinInt64 term, got:\n%s", lrTermSQL)
	}
	if err := json.Unmarshal([]byte(`{"exists":{"field":"dyn.extra"}}`), &svExistsQ); err != nil {
		t.Fatalf("unmarshal exists query: %v", err)
	}
	svExistsSQL := tr.CompileQuery(&svExistsQ, false, nil).WhereSQL
	if !strings.Contains(svExistsSQL, "JSON_LENGTH(TRY_CAST(`_source` AS JSON), '$.\"dyn\".\"extra\"') > 0") {
		t.Fatalf("expected non-empty array JSON_LENGTH guard in dynamic exists SQL, got:\n%s", svExistsSQL)
	}
}

func intPtrR66(v int) *int { return &v }
