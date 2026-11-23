package esast

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRound65ES8RRFAndPinnedDocsAST(t *testing.T) {
	// 1. retriever.rrf with rank_window_size=2 and omitted body size (e.g. URL ?size=1) must unmarshal cleanly,
	// preserving RankWindowSize and deferring default size check to ValidateRRFWindowSize.
	var srRetRRF SearchRequest
	retRRFJSON := `{
		"retriever": {
			"rrf": {
				"retrievers": [
					{"standard": {"query": {"term": {"text": "term"}}}},
					{"knn": {"field": "vec", "query_vector": [0.1], "k": 3, "num_candidates": 3}}
				],
				"rank_window_size": 2,
				"rank_constant": 1
			}
		}
	}`
	if err := json.Unmarshal([]byte(retRRFJSON), &srRetRRF); err != nil {
		t.Fatalf("expected retriever.rrf without body size to unmarshal cleanly, got %v", err)
	}
	if srRetRRF.Rank == nil || srRetRRF.Rank.RRF == nil || srRetRRF.Rank.RRF.RankWindowSize == nil || *srRetRRF.Rank.RRF.RankWindowSize != 2 {
		t.Fatalf("expected lowered Rank.RRF.RankWindowSize=2, got %+v", srRetRRF.Rank)
	}
	if err := srRetRRF.ValidateRRFWindowSize(1); err != nil {
		t.Fatalf("ValidateRRFWindowSize(1) expected nil, got %v", err)
	}
	if err := srRetRRF.ValidateRRFWindowSize(10); err == nil || !strings.Contains(err.Error(), "[rank_window_size: 2]") {
		t.Fatalf("ValidateRRFWindowSize(10) expected error, got %v", err)
	}

	// Specifying both retriever and rank must fail cleanly.
	var srBoth SearchRequest
	if err := json.Unmarshal([]byte(`{"retriever":{"standard":{"query":{"match_all":{}}}},"rank":{"rrf":{"rank_window_size":5}}}`), &srBoth); err == nil {
		t.Fatal("expected error when both retriever and rank are specified")
	}

	// Explicit body size > rank_window_size still fails at UnmarshalJSON.
	var srTooSmall SearchRequest
	if err := json.Unmarshal([]byte(`{"size":10,"rank":{"rrf":{"rank_window_size":2}}}`), &srTooSmall); err == nil || !strings.Contains(err.Error(), "[rank_window_size: 2]") {
		t.Fatalf("expected rank_window_size < size error, got %v", err)
	}

	// 2. pinned.docs with omitted _index (ES 8.11+) vs explicit blank/null/non-string _index.
	var qPinnedOpt Query
	if err := json.Unmarshal([]byte(`{"pinned":{"docs":[{"_id":"a"},{"_id":"c","_index":"test2"}],"organic":{"match_all":{}}}}`), &qPinnedOpt); err != nil {
		t.Fatalf("expected pinned.docs with omitted _index to unmarshal cleanly, got %v", err)
	}
	if qPinnedOpt.Pinned == nil || !qPinnedOpt.Pinned.HasDocsMissingIndex || len(qPinnedOpt.Pinned.EffectiveIDs()) != 2 {
		t.Fatalf("unexpected PinnedQuery state: %+v", qPinnedOpt.Pinned)
	}

	var qPinnedNumID Query
	if err := json.Unmarshal([]byte(`{"pinned":{"docs":[{"_id":1}],"organic":{"match_all":{}}}}`), &qPinnedNumID); err != nil {
		t.Fatalf("expected pinned.docs with numeric _id and omitted _index to unmarshal cleanly, got %v", err)
	}
	if !qPinnedNumID.Pinned.HasDocsMissingIndex || qPinnedNumID.Pinned.EffectiveIDs()[0] != "1" {
		t.Fatalf("unexpected PinnedQuery numeric _id state: %+v", qPinnedNumID.Pinned)
	}

	var qPinnedWithIdx Query
	if err := json.Unmarshal([]byte(`{"pinned":{"docs":[{"_id":"a","_index":"test1"}],"organic":{"match_all":{}}}}`), &qPinnedWithIdx); err != nil {
		t.Fatalf("expected pinned.docs with explicit _index to unmarshal cleanly, got %v", err)
	}
	if qPinnedWithIdx.Pinned.HasDocsMissingIndex {
		t.Fatalf("expected HasDocsMissingIndex=false when all docs specify _index")
	}

	for _, badPinned := range []string{
		`{"pinned":{"docs":[{"_id":"a","_index":""}],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[{"_id":"a","_index":"   "}],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[{"_id":"a","_index":null}],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[{"_id":"a","_index":123}],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[null],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[{"_id":true,"_index":"idx"}],"organic":{"match_all":{}}}}`,
		`{"pinned":{"docs":[{"_id":"   ","_index":"idx"}],"organic":{"match_all":{}}}}`,
	} {
		var q Query
		if err := json.Unmarshal([]byte(badPinned), &q); err == nil {
			t.Fatalf("expected pinned error for %s", badPinned)
		}
	}
}

func TestRound65CumulativeCardinalityMovingPercentilesAndSortNestedFlags(t *testing.T) {
	// 1. cumulative_cardinality vs cumulative_sum helpers & strict validation.
	var srCum SearchRequest
	cumJSON := `{
		"size": 0,
		"aggs": {
			"h": {
				"date_histogram": {"field": "@timestamp", "calendar_interval": "day"},
				"aggs": {
					"u": {"cardinality": {"field": "user"}},
					"cc": {"cumulative_cardinality": {"buckets_path": "u", "format": "00", "gap_policy": "skip", "meta": {"tag": "cc"}}},
					"cs": {"cumulative_sum": {"buckets_path": "u", "format": "0.0"}}
				}
			}
		}
	}`
	if err := json.Unmarshal([]byte(cumJSON), &srCum); err != nil {
		t.Fatalf("unmarshal cumulative aggs failed: %v", err)
	}
	hCum := srCum.EffectiveAggs()["h"]
	sub := hCum.SubAggs()
	ccAgg := sub["cc"]
	csAgg := sub["cs"]
	if !ccAgg.IsCumulativeCardinality() || ccAgg.EffectiveCumulativeCardinality() == nil || ccAgg.EffectiveCumulativeSum() != nil {
		t.Fatalf("expected ccAgg to distinguish cumulative_cardinality, got %+v", ccAgg)
	}
	if csAgg.IsCumulativeCardinality() || csAgg.EffectiveCumulativeSum() == nil || csAgg.EffectiveCumulativeCardinality() != nil {
		t.Fatalf("expected csAgg to distinguish cumulative_sum, got %+v", csAgg)
	}
	for _, badCum := range []string{
		`{"aggs":{"cc":{"cumulative_cardinality":{"buckets_path":"u","sigma":2.0}}}}`,
		`{"aggs":{"cc":{"cumulative_cardinality":{"buckets_path":["u"]}}}}`,
		`{"aggs":{"cs":{"cumulative_sum":{"buckets_path":"u","unit":"day"}}}}`,
		`{"aggs":{"cs":{"cumulative_sum":{"buckets_path":{"a":"u"}}}}}`,
	} {
		var sr SearchRequest
		if err := json.Unmarshal([]byte(badCum), &sr); err == nil {
			t.Fatalf("expected error for invalid cumulative agg %s", badCum)
		}
	}

	// 2. moving_percentiles full ES 8 fields and error paths.
	var srMP SearchRequest
	mpJSON := `{
		"size": 0,
		"aggs": {
			"h": {
				"date_histogram": {"field": "ts", "calendar_interval": "day"},
				"aggs": {
					"p": {"percentiles": {"field": "lat"}},
					"mp": {
						"moving_percentiles": {
							"buckets_path": "p",
							"window": 4,
							"shift": 1,
							"keyed": false,
							"percentiles": [50, 95],
							"script": {"source": "params.values"},
							"format": "0.00",
							"gap_policy": "insert_zeros",
							"meta": {"k": "v"}
						}
					},
					"mp_def": {
						"moving_percentiles": {
							"buckets_path": "p"
						}
					}
				}
			}
		}
	}`
	if err := json.Unmarshal([]byte(mpJSON), &srMP); err != nil {
		t.Fatalf("moving_percentiles ES8 fields failed: %v", err)
	}
	hMP := srMP.EffectiveAggs()["h"]
	subMP := hMP.SubAggs()
	mp := subMP["mp"].MovingPercentiles
	if mp.EffectivePath() != "p" || mp.EffectiveWindow() != 4 || mp.EffectiveShift() != 1 || mp.Format != "0.00" || mp.GapPolicy != "insert_zeros" || len(mp.EffectivePercents()) != 2 {
		t.Fatalf("unexpected MovingPercentilesAggSpec: %+v", mp)
	}
	mpDef := subMP["mp_def"].MovingPercentiles
	if mpDef.EffectiveWindow() != 10 || mpDef.EffectiveShift() != 0 || len(mpDef.EffectivePercents()) != 0 {
		t.Fatalf("unexpected default MovingPercentilesAggSpec helpers: %+v", mpDef)
	}
	var srMPBadWin SearchRequest
	if err := json.Unmarshal([]byte(`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","window":-1}}}}`), &srMPBadWin); err == nil || !strings.Contains(err.Error(), "[window] must be a positive, non-zero integer.") {
		t.Fatalf("expected ES8 moving_percentiles window error, got %v", err)
	}
	for _, badMP := range []string{
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","shift":-1}}}}`,
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","gap_policy":"bogus"}}}}`,
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","percents":[150]}}}}`,
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","percentiles":[]}}}}`,
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","script":{"unknown":1}}}}}`,
		`{"aggs":{"mp":{"moving_percentiles":{"buckets_path":"p","unknown":1}}}}`,
	} {
		var sr SearchRequest
		if err := json.Unmarshal([]byte(badMP), &sr); err == nil {
			t.Fatalf("expected moving_percentiles error for %s", badMP)
		}
	}

	// 3. Sort nested_path / nested_filter legacy tracking across field, _script, and _geo_distance sorts.
	sortJSON := `{
		"sort": [
			{"offer.price": {"mode": "avg", "order": "asc", "nested_path": "offer"}},
			{"offer.price": {"mode": "avg", "order": "asc", "nested_filter": {"term": {"offer.color": "blue"}}}},
			{"offer.price": {"order": "asc", "nested": {"path": "offer", "filter": {"term": {"offer.color": "blue"}}}}},
			{"offer.price": "asc", "nested_path": "offer"},
			{"_geo_distance": {"pin.location": [-70, 40], "nested_path": "offer"}},
			{"_geo_distance": {"pin.location": [-70, 40], "nested_filter": {"term": {"offer.color": "blue"}}}},
			{"_script": {"type": "number", "script": "1", "nested_path": "offer", "nested_filter": {"term": {"offer.color": "blue"}}}}
		]
	}`
	var srSort SearchRequest
	if err := json.Unmarshal([]byte(sortJSON), &srSort); err != nil {
		t.Fatalf("sort legacy nested_path/nested_filter unmarshal failed: %v", err)
	}
	if len(srSort.Sort) != 7 {
		t.Fatalf("expected 7 sort entries, got %d", len(srSort.Sort))
	}
	if !srSort.Sort[0].Entry.WasLegacyNestedPath || srSort.Sort[0].Entry.WasLegacyNestedFilter {
		t.Fatalf("sort[0] flags unexpected: %+v", srSort.Sort[0].Entry)
	}
	if srSort.Sort[1].Entry.WasLegacyNestedPath || !srSort.Sort[1].Entry.WasLegacyNestedFilter || srSort.Sort[1].Entry.Nested == nil || srSort.Sort[1].Entry.Nested.Filter == nil {
		t.Fatalf("sort[1] (nested_filter without nested_path) flags unexpected: %+v", srSort.Sort[1].Entry)
	}
	if srSort.Sort[2].Entry.WasLegacyNestedPath || srSort.Sort[2].Entry.WasLegacyNestedFilter {
		t.Fatalf("sort[2] (modern nested) should not set legacy flags: %+v", srSort.Sort[2].Entry)
	}
	if !srSort.Sort[3].Entry.WasLegacyNestedPath {
		t.Fatalf("sort[3] (outer sibling nested_path) expected WasLegacyNestedPath=true")
	}
	if !srSort.Sort[4].Entry.WasLegacyNestedPath || srSort.Sort[4].Entry.WasLegacyNestedFilter {
		t.Fatalf("sort[4] (_geo_distance nested_path) flags unexpected: %+v", srSort.Sort[4].Entry)
	}
	if srSort.Sort[5].Entry.WasLegacyNestedPath || !srSort.Sort[5].Entry.WasLegacyNestedFilter {
		t.Fatalf("sort[5] (_geo_distance nested_filter) flags unexpected: %+v", srSort.Sort[5].Entry)
	}
	if !srSort.Sort[6].Entry.WasLegacyNestedPath || !srSort.Sort[6].Entry.WasLegacyNestedFilter {
		t.Fatalf("sort[6] (_script nested_path+nested_filter) flags unexpected: %+v", srSort.Sort[6].Entry)
	}
}

func TestRound65ESASTUncoveredValidationAndHelperCoverage(t *testing.T) {
	// InnerHitsSpec validation & helpers
	var ihValid InnerHitsSpec
	if err := json.Unmarshal([]byte(`{"name":"hits1","from":0,"size":5,"stored_fields":["_none_","title"],"fields":["f1"],"docvalue_fields":["d1"],"version":"true","seq_no_primary_term":"false","explain":true,"ignore_unmapped":"true","script_fields":{"s1":{"script":"1"}},"collapse":{"field":"cat"}}`), &ihValid); err != nil {
		t.Fatalf("InnerHitsSpec valid failed: %v", err)
	}
	if !ihValid.HasStoredFieldsNone() || ihValid.EffectiveSize() != 5 || len(ihValid.EffectiveFieldSpecs()) != 3 {
		t.Fatalf("unexpected InnerHitsSpec helpers: %+v", ihValid)
	}
	var ihNil *InnerHitsSpec
	if ihNil.HasStoredFieldsNone() || ihNil.EffectiveSize() != 3 || ihNil.EffectiveFieldSpecs() != nil {
		t.Fatal("unexpected nil InnerHitsSpec helper results")
	}
	for _, badIH := range []string{
		`{"unknown":1}`,
		`{"version":"notabool"}`,
		`{"seq_no_primary_term":"notabool"}`,
		`{"explain":"notabool"}`,
		`{"ignore_unmapped":"notabool"}`,
		`{"from":-1}`,
		`{"size":-1}`,
		`{"script_fields":{"s1":{}}}`,
		`{"collapse":{"field":"c","inner_hits":{"name":"nested"}}}`,
	} {
		var ih InnerHitsSpec
		if err := json.Unmarshal([]byte(badIH), &ih); err == nil {
			t.Fatalf("InnerHitsSpec expected error for %s", badIH)
		}
	}

	// HighlightFieldSpec matched_fields, tags_schema, error paths
	var hfs HighlightFieldSpec
	if err := json.Unmarshal([]byte(`{"tags_schema":"styled","pre_tags":"<b>","post_tags":"</b>","matched_fields":["title","title.en"]}`), &hfs); err != nil {
		t.Fatalf("HighlightFieldSpec valid failed: %v", err)
	}
	if hfs.TagSchema != "styled" || len(hfs.MatchedFields) != 2 {
		t.Fatalf("unexpected HighlightFieldSpec: %+v", hfs)
	}
	for _, badHFS := range []string{
		`{"pre_tags":123}`,
		`{"post_tags":123}`,
		`{"matched_fields":123}`,
		`{"unknown":1}`,
	} {
		var h HighlightFieldSpec
		if err := json.Unmarshal([]byte(badHFS), &h); err == nil {
			t.Fatalf("HighlightFieldSpec expected error for %s", badHFS)
		}
	}

	// SparseVectorQuerySpec EffectiveTokens & EffectiveQueryText
	sv1 := &SparseVectorQuerySpec{Tokens: map[string]float64{"a": 1.0}, QueryText: "hello"}
	if len(sv1.EffectiveTokens()) != 1 || sv1.EffectiveQueryText() != "hello" {
		t.Fatalf("unexpected SparseVector helpers: %+v", sv1)
	}
	sv2 := &SparseVectorQuerySpec{QueryVector: map[string]float64{"b": 2.0}, Query: "world", ModelText: "m"}
	if sv2.EffectiveTokens()["b"] != 2.0 || sv2.EffectiveQueryText() != "world" {
		t.Fatalf("unexpected SparseVector helpers 2: %+v", sv2)
	}
	sv3 := &SparseVectorQuerySpec{ModelText: "mt"}
	if sv3.EffectiveQueryText() != "mt" {
		t.Fatalf("unexpected SparseVector ModelText fallback: %q", sv3.EffectiveQueryText())
	}
	var svNil *SparseVectorQuerySpec
	if svNil.EffectiveTokens() != nil || svNil.EffectiveQueryText() != "" {
		t.Fatal("unexpected nil SparseVector helper results")
	}

	// TermsIncludeExclude error and partition branches
	for _, okTIE := range []string{
		`null`,
		`"foo.*"`,
		`["a", 1, true]`,
		`{"partition":0,"num_partitions":4}`,
	} {
		var tie TermsIncludeExclude
		if err := json.Unmarshal([]byte(okTIE), &tie); err != nil {
			t.Fatalf("TermsIncludeExclude %s failed: %v", okTIE, err)
		}
	}
	for _, badTIE := range []string{
		`[{"nested":1}]`,
		`{"partition":0,"num_partitions":4,"extra":1}`,
		`{"partition":0}`,
		`{"partition":"x","num_partitions":4}`,
		`{"partition":4,"num_partitions":4}`,
		`123`,
	} {
		var tie TermsIncludeExclude
		if err := json.Unmarshal([]byte(badTIE), &tie); err == nil {
			t.Fatalf("TermsIncludeExclude expected error for %s", badTIE)
		}
	}

	// parseGeoCoordAny branches
	for _, okCoord := range []any{float64(12.5), int(3), int64(4), json.Number("5.5"), " -74.0 "} {
		if _, err := parseGeoCoordAny(okCoord); err != nil {
			t.Fatalf("parseGeoCoordAny(%v) failed: %v", okCoord, err)
		}
	}
	for _, badCoord := range []any{json.Number("bad"), "notnum", true, []any{1}} {
		if _, err := parseGeoCoordAny(badCoord); err == nil {
			t.Fatalf("parseGeoCoordAny(%v) expected error", badCoord)
		}
	}

	// DateHistogramAggSpec.EffectiveCalendarUnit
	for _, tc := range []struct {
		dh   DateHistogramAggSpec
		want string
	}{
		{DateHistogramAggSpec{CalendarInterval: "1m"}, "minute"},
		{DateHistogramAggSpec{CalendarInterval: "1h"}, "hour"},
		{DateHistogramAggSpec{CalendarInterval: "1d"}, "day"},
		{DateHistogramAggSpec{CalendarInterval: "1w"}, "week"},
		{DateHistogramAggSpec{CalendarInterval: "1M"}, "month"},
		{DateHistogramAggSpec{CalendarInterval: "1q"}, "quarter"},
		{DateHistogramAggSpec{Interval: "year"}, "year"},
		{DateHistogramAggSpec{CalendarInterval: "1d", FixedInterval: "10s"}, ""},
		{DateHistogramAggSpec{CalendarInterval: "5m"}, ""},
	} {
		if got := tc.dh.EffectiveCalendarUnit(); got != tc.want {
			t.Fatalf("EffectiveCalendarUnit(%+v) = %q, want %q", tc.dh, got, tc.want)
		}
	}

	// FieldProperty.CopyToSlice variants & TermEntry/MatchEntry/CommonTermsEntry MarshalJSON
	if got := (FieldProperty{CopyTo: "all"}).CopyToSlice(); len(got) != 1 || got[0] != "all" {
		t.Fatalf("CopyToSlice string = %v", got)
	}
	if got := (FieldProperty{CopyTo: []string{"a", "b"}}).CopyToSlice(); len(got) != 2 {
		t.Fatalf("CopyToSlice []string = %v", got)
	}
	if got := (FieldProperty{CopyTo: []any{"a", "", 123}}).CopyToSlice(); len(got) != 1 {
		t.Fatalf("CopyToSlice []any = %v", got)
	}
	if got := (FieldProperty{}).CopyToSlice(); got != nil {
		t.Fatalf("CopyToSlice nil = %v", got)
	}
	if b, err := json.Marshal(TermEntry{Value: "v", Boost: 2.0, HasBoost: true, CaseInsensitive: true, Name: "t1"}); err != nil || !strings.Contains(string(b), `"boost":2`) {
		t.Fatalf("TermEntry MarshalJSON = %s (%v)", string(b), err)
	}
	if b, err := json.Marshal(MatchEntry{Query: "q", Boost: 1.5, HasBoost: true, CutoffFrequency: 0.01}); err != nil || !strings.Contains(string(b), `"cutoff_frequency":0.01`) {
		t.Fatalf("MatchEntry MarshalJSON = %s (%v)", string(b), err)
	}
	if b, err := json.Marshal(CommonTermsEntry{Query: "q", Boost: 1.2, HasBoost: true, CutoffFrequency: 0.02}); err != nil || !strings.Contains(string(b), `"cutoff_frequency":0.02`) {
		t.Fatalf("CommonTermsEntry MarshalJSON = %s (%v)", string(b), err)
	}

	// Pipeline EffectivePath / AggSpec EffectiveRange & EffectiveTerms & validateSearchRequestAggMap
	if (&MovingAvgAggSpec{BucketsPath: []string{"a"}}).EffectivePath() == "" ||
		(&SerialDiffAggSpec{BucketsPath: []string{"a"}}).EffectivePath() == "" ||
		(&NormalizeAggSpec{BucketsPath: []string{"a"}}).EffectivePath() == "" ||
		(&PercentilesBucketAggSpec{BucketsPath: []string{"a"}}).EffectivePath() == "" ||
		(&PipelineAggSpec{BucketsPath: []string{"a"}}).EffectivePath() == "" {
		t.Fatal("expected non-empty EffectivePath for slice buckets_path")
	}
	if (&AggSpec{IPRange: &RangeAggSpec{Field: "ip"}}).EffectiveRange() == nil ||
		(&AggSpec{DateRange: &RangeAggSpec{Field: "ts"}}).EffectiveRange() == nil ||
		(&AggSpec{SignificantText: &TermsAggSpec{Field: "txt"}}).EffectiveTerms() == nil ||
		(&AggSpec{SignificantTerms: &TermsAggSpec{Field: "kw"}}).EffectiveTerms() == nil {
		t.Fatal("expected non-nil EffectiveRange/EffectiveTerms")
	}
	if err := validateSearchRequestAggMap(map[string]AggSpec{"f": {Filters: &FiltersAggSpec{}}}); err == nil {
		t.Fatal("expected empty filters error")
	}
	if err := validateSearchRequestAggMap(map[string]AggSpec{"sm": {ScriptedMetric: &ScriptedMetricAggSpec{}}}); err == nil {
		t.Fatal("expected scripted_metric missing map_script error")
	}
	if err := validateSearchRequestAggMap(map[string]AggSpec{"t": {Terms: &TermsAggSpec{Field: "a"}, Aggs: map[string]AggSpec{"f": {Filters: &FiltersAggSpec{}}}}}); err == nil {
		t.Fatal("expected recursive sub-agg error")
	}

	// MultiMatchQuery validation errors & ValidateQueryStringDepth regex context
	for _, badMM := range []string{
		`{"query":{"multi_match":{"fields":["a"]}}}`,
		`{"query":{"multi_match":{"query":{"bad":1}}}}`,
		`{"query":{"multi_match":{"query":"a","fuzzy_transpositions":"bad"}}}`,
		`{"query":{"multi_match":{"query":"a","lenient":"bad"}}}`,
		`{"query":{"multi_match":{"query":"a","auto_generate_synonyms_phrase_query":"bad"}}}`,
		`{"query":{"multi_match":{"query":"a","boost":-1}}}`,
		`{"query":{"multi_match":{"query":"a","type":"bogus"}}}`,
		`{"query":{"multi_match":{"query":"a","type":"bool_prefix","slop":1}}}`,
		`{"query":{"multi_match":{"query":"a","type":"bool_prefix","cutoff_frequency":0.1}}}`,
		`{"query":{"multi_match":{"query":"a","slop":-1}}}`,
		`{"query":{"multi_match":{"query":"a","prefix_length":-1}}}`,
		`{"query":{"multi_match":{"query":"a","max_expansions":0}}}`,
	} {
		var q Query
		if err := json.Unmarshal([]byte(badMM), &q); err == nil {
			t.Fatalf("MultiMatchQuery expected error for %s", badMM)
		}
	}
	if err := ValidateQueryStringDepth(`field:/a\/b/ AND (c OR d)`); err != nil {
		t.Fatalf("ValidateQueryStringDepth valid regex failed: %v", err)
	}
}

func TestRound65FieldPropertyPassthroughPriority(t *testing.T) {
	var tmpl IndexTemplateRequest
	raw := `{
		"index_patterns": ["k9s*"],
		"data_stream": {},
		"template": {
			"mappings": {
				"properties": {
					"attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 0},
					"resource.attributes": {"type": "passthrough", "priority": 1},
					"scope": {
						"properties": {
							"attributes": {"type": "passthrough", "priority": 2}
						}
					},
					"no_priority": {"type": "passthrough"}
				}
			}
		}
	}`
	if err := json.Unmarshal([]byte(raw), &tmpl); err != nil {
		t.Fatalf("unmarshal IndexTemplateRequest with passthrough priority failed: %v", err)
	}
	props := tmpl.EffectiveMappings().Properties
	if props["attributes"].Priority == nil || *props["attributes"].Priority != 0 {
		t.Fatalf("expected attributes priority=0 (non-nil), got %+v", props["attributes"].Priority)
	}
	if props["resource.attributes"].Priority == nil || *props["resource.attributes"].Priority != 1 {
		t.Fatalf("expected resource.attributes priority=1, got %+v", props["resource.attributes"].Priority)
	}
	scopeAttr := props["scope"].Properties["attributes"]
	if scopeAttr.Priority == nil || *scopeAttr.Priority != 2 {
		t.Fatalf("expected scope.attributes priority=2, got %+v", scopeAttr.Priority)
	}
	if props["no_priority"].Priority != nil {
		t.Fatalf("expected omitted priority to remain nil, got %v", *props["no_priority"].Priority)
	}

	strictFP, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"passthrough","priority":0}`))
	if err != nil {
		t.Fatalf("UnmarshalFieldPropertyStrict with priority failed: %v", err)
	}
	if strictFP.Priority == nil || *strictFP.Priority != 0 {
		t.Fatalf("expected strict FieldProperty priority=0, got %+v", strictFP.Priority)
	}
	b, err := json.Marshal(strictFP)
	if err != nil || !strings.Contains(string(b), `"priority":0`) {
		t.Fatalf("expected marshaled FieldProperty to preserve priority:0, got %s (err=%v)", string(b), err)
	}
	if _, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"passthrough","priority":"not_an_int"}`)); err == nil {
		t.Fatal("expected non-integer priority to fail FieldProperty unmarshal")
	}
}

func TestRound65Wave3CESASTKNNTypeAndCutoffQueries(t *testing.T) {
	// KNN errors preserve caused_by marker for k <= 0 and num_candidates < k.
	var knnZero Query
	err := json.Unmarshal([]byte(`{"knn":{"field":"vec","query_vector":[1,2],"k":0,"num_candidates":5}}`), &knnZero)
	if err == nil || !strings.Contains(err.Error(), "illegal_argument_exception: [k] must be greater than 0") {
		t.Fatalf("expected k<=0 illegal_argument_exception, got %v", err)
	}
	var knnLess Query
	err = json.Unmarshal([]byte(`{"knn":{"field":"vec","query_vector":[1,2],"k":5,"num_candidates":2}}`), &knnLess)
	if err == nil || !strings.Contains(err.Error(), "illegal_argument_exception: [num_candidates] cannot be less than [k]") {
		t.Fatalf("expected num_candidates<k illegal_argument_exception, got %v", err)
	}

	// TypeQuery parses type clause cleanly so handler compat checks can deprecate/reject in ES8.
	var tq Query
	if err := json.Unmarshal([]byte(`{"type":{"value":"doc"}}`), &tq); err != nil {
		t.Fatalf("unmarshal type query failed: %v", err)
	}
	if tq.Type == nil || tq.Type.Value != "doc" {
		t.Fatalf("expected Type.Value=doc, got %+v", tq.Type)
	}

	// Match with cutoff_frequency and optional type parses cleanly for handler ES8/ES7 branching.
	var mq Query
	if err := json.Unmarshal([]byte(`{"match":{"title":{"query":"hello","cutoff_frequency":0.01,"type":"boolean"}}}`), &mq); err != nil {
		t.Fatalf("unmarshal match with cutoff_frequency+type failed: %v", err)
	}
	if mq.Match["title"].CutoffFrequency != 0.01 || mq.Match["title"].Type != "boolean" {
		t.Fatalf("unexpected MatchEntry fields: %+v", mq.Match["title"])
	}

	// Common terms query with type parses cleanly for handler ES8/ES7 branching.
	var cq Query
	if err := json.Unmarshal([]byte(`{"common":{"body":{"query":"hello","cutoff_frequency":0.001,"type":"low_freq"}}}`), &cq); err != nil {
		t.Fatalf("unmarshal common query with type failed: %v", err)
	}
	if cq.Common["body"].Type != "low_freq" {
		t.Fatalf("unexpected CommonTermsEntry fields: %+v", cq.Common["body"])
	}
}
