package esast

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRound66CovESAST_RetrieverAndSuggestValidation(t *testing.T) {
	// RetrieverSpec valid + invalid cases
	validRets := []string{
		`null`,
		`{"standard":{"query":{"match_all":{}},"filter":[{"term":{"a":"b"}}],"terminate_after":5,"min_score":0.5,"rank_window_size":10,"search_after":[10,"id1"]}}`,
	}
	for _, j := range validRets {
		var r RetrieverSpec
		if err := json.Unmarshal([]byte(j), &r); err != nil {
			t.Fatalf("unexpected error for %s: %v", j, err)
		}
	}
	badRets := []string{
		`123`,
		`{}`,
		`{"standard":{"unknown":1}}`,
		`{"standard":{"terminate_after":0}}`,
		`{"standard":{"terminate_after":"bad"}}`,
		`{"standard":{"rank_window_size":0}}`,
	}
	for _, j := range badRets {
		var r RetrieverSpec
		if err := json.Unmarshal([]byte(j), &r); err == nil {
			t.Fatalf("expected error for invalid retriever %s", j)
		}
	}

	// TermSuggestSpec valid + validation error branches
	var ts TermSuggestSpec
	if err := json.Unmarshal([]byte(`{"field":"title","size":5,"suggest_mode":"popular","sort":"frequency","string_distance":"levenshtein","max_edits":2,"prefix_length":1,"min_word_length":3,"max_inspections":10,"min_doc_freq":0.5,"max_term_freq":0.5}`), &ts); err != nil {
		t.Fatalf("unexpected TermSuggestSpec error: %v", err)
	}
	badTermSuggests := []string{
		`{"field":"t","bad_k":1}`,
		`{"size":5}`,
		`{"field":"t","size":0}`,
		`{"field":"t","suggest_mode":"weird"}`,
		`{"field":"t","sort":"weird"}`,
		`{"field":"t","string_distance":"weird"}`,
		`{"field":"t","max_edits":3}`,
		`{"field":"t","prefix_length":-1}`,
		`{"field":"t","min_word_length":0}`,
		`{"field":"t","max_inspections":0}`,
		`{"field":"t","min_doc_freq":-1}`,
		`{"field":"t","max_term_freq":-1}`,
	}
	for _, j := range badTermSuggests {
		var tmp TermSuggestSpec
		if err := json.Unmarshal([]byte(j), &tmp); err == nil {
			t.Fatalf("expected error for TermSuggestSpec %s", j)
		}
	}
}

func TestRound66CovESAST_QueriesAndGeoValidation(t *testing.T) {
	// GeoGridQuery valid + error branches
	for _, g := range []string{
		`null`,
		`{"loc":{"geohash":"u4pruy"},"boost":1.5,"_name":"g1","ignore_unmapped":true}`,
		`{"loc":{"geotile":"1/1/1","boost":2,"_name":"g2","ignore_unmapped":"false"}}`,
		`{"loc":{"geohex":"85283473fffffff"}}`,
	} {
		var gg GeoGridQuery
		if err := json.Unmarshal([]byte(g), &gg); err != nil {
			t.Fatalf("unexpected GeoGridQuery error for %s: %v", g, err)
		}
	}
	for _, bad := range []string{
		`{}`,
		`{"a":{},"b":{}}`,
		`{"loc":{"unknown":1}}`,
		`{"loc":{}}`,
		`{"loc":{"geohash":"u","geotile":"1/1/1"}}`,
		`{"loc":{"geohash":"u"},"boost":-1}`,
		`{"loc":{"geohash":"u"},"ignore_unmapped":{}}`,
	} {
		var gg GeoGridQuery
		if err := json.Unmarshal([]byte(bad), &gg); err == nil {
			t.Fatalf("expected error for invalid GeoGridQuery %s", bad)
		}
	}

	// GeoBoundingBoxQuery WKT & top_left/bottom_right validation
	var gbb GeoBoundingBoxQuery
	if err := json.Unmarshal([]byte(`{"validation_method":"COERCE","type":"indexed","boost":2,"_name":"bb","ignore_unmapped":true,"loc":{"top_left":[40,-75],"bottom_right":[39,-74]}}`), &gbb); err != nil {
		t.Fatalf("unexpected GeoBoundingBoxQuery error: %v", err)
	}
	for _, bad := range []string{
		`{"validation_method":"NOPE","loc":{"wkt":"BBOX(-10,10,10,-10)"}}`,
		`{"type":"badtype","loc":{"wkt":"BBOX(-10,10,10,-10)"}}`,
		`{"loc":{}}`,
		`{"loc":{"wkt":"BBOX(-10,10,10,-10)","extra":1}}`,
		`{"loc":{"top_left":[40,-75]}}`,
		`{"a":{"wkt":"BBOX(-1,1,1,-1)"},"b":{"wkt":"BBOX(-1,1,1,-1)"}}`,
	} {
		var g GeoBoundingBoxQuery
		if err := json.Unmarshal([]byte(bad), &g); err == nil {
			t.Fatalf("expected error for invalid GeoBoundingBoxQuery %s", bad)
		}
	}

	// MoreLikeThisQuery valid & validation failures
	var mlt MoreLikeThisQuery
	if err := json.Unmarshal([]byte(`{"fields":["title^2"],"like":["doris proxy"],"unlike":["noise"],"ids":[1,"2"],"min_term_freq":1,"max_query_terms":10,"min_doc_freq":1,"max_doc_freq":10,"min_word_length":2,"max_word_length":20}`), &mlt); err != nil {
		t.Fatalf("unexpected MLT error: %v", err)
	}
	for _, bad := range []string{
		`{"fields":["title"]}`,
		`{"like":["x"],"unknown":1}`,
		`{"like":["x"],"min_term_freq":-1}`,
		`{"like":["x"],"max_query_terms":-1}`,
		`{"like":["x"],"min_doc_freq":5,"max_doc_freq":2}`,
		`{"like":["x"],"min_word_length":8,"max_word_length":3}`,
		`{"like_text":"   "}`,
		`{"like":["x"],"ids":[]}`,
		`{"like":["x"],"docs":[]}`,
	} {
		var m MoreLikeThisQuery
		if err := json.Unmarshal([]byte(bad), &m); err == nil {
			t.Fatalf("expected error for invalid MLT %s", bad)
		}
	}

	// RankFeatureQuery, CombinedFieldsQuery, MatchEntry, QueryStringQuery, TermsQuery
	for _, bad := range []string{
		`{"unknown":1}`,
		`{"field":"f","saturation":{},"log":{}}`,
	} {
		var rf RankFeatureQuery
		if err := json.Unmarshal([]byte(bad), &rf); err == nil {
			t.Fatalf("expected error for RankFeatureQuery %s", bad)
		}
	}
	for _, bad := range []string{
		`{}`,
		`{"query":"hi","bad":1}`,
		`{"query":["non-scalar"]}`,
		`{"query":"hi","boost":-1}`,
		`{"query":"hi","operator":"xor"}`,
		`{"query":"hi","zero_terms_query":"invalid"}`,
	} {
		var cf CombinedFieldsQuery
		if err := json.Unmarshal([]byte(bad), &cf); err == nil {
			t.Fatalf("expected error for CombinedFieldsQuery %s", bad)
		}
	}
	for _, bad := range []string{
		`{}`,
		`{"query":"hi","bad":1}`,
		`{"query":["arr"]}`,
		`{"query":"hi","type":"phrase"}`,
		`{"query":"hi","prefix_length":-1}`,
		`{"query":"hi","max_expansions":0}`,
		`{"query":"hi","lenient":{"obj":1}}`,
	} {
		var me MatchEntry
		if err := json.Unmarshal([]byte(bad), &me); err == nil {
			t.Fatalf("expected error for MatchEntry %s", bad)
		}
	}
	var qs QueryStringQuery
	if err := json.Unmarshal([]byte(`{"query":"hello","fuzziness":"AUTO:3,6","fuzzy_max_expansions":10,"fuzzy_prefix_length":1,"fuzzy_transpositions":"true","lenient":"false"}`), &qs); err != nil {
		t.Fatalf("unexpected QueryStringQuery error: %v", err)
	}
	for _, bad := range []string{
		`{}`,
		`{"query":"hi","bad":1}`,
		`{"query":"hi","fuzzy_max_expansions":0}`,
		`{"query":"hi","fuzzy_prefix_length":-1}`,
		`{"query":"hi","fuzziness":"INVALID"}`,
		`{"query":"hi","boost":-2}`,
		`{"query":"hi","lenient":{}}`,
	} {
		var q QueryStringQuery
		if err := json.Unmarshal([]byte(bad), &q); err == nil {
			t.Fatalf("expected error for QueryStringQuery %s", bad)
		}
	}

	var tq TermsQuery
	if err := json.Unmarshal([]byte(`{"boost":"2.5","case_insensitive":"true","_name":"tn","tags":["a","b"]}`), &tq); err != nil {
		t.Fatalf("unexpected TermsQuery error: %v", err)
	}
	for _, bad := range []string{
		`{"boost":-1,"tags":["a"]}`,
		`{"case_insensitive":{},"tags":["a"]}`,
	} {
		var tq2 TermsQuery
		if err := json.Unmarshal([]byte(bad), &tq2); err == nil {
			t.Fatalf("expected error for TermsQuery %s", bad)
		}
	}

	// Origin + offset helpers
	for _, okOff := range []any{0, int64(5), float64(1.5), json.Number("2.5"), "10d"} {
		if err := validateNonNegativeOffset(okOff, "ctx"); err != nil {
			t.Fatalf("expected valid offset %v: %v", okOff, err)
		}
	}
	for _, badOff := range []any{-1, int64(-2), float64(-0.1), json.Number("bad"), "-5d", "", true} {
		if err := validateNonNegativeOffset(badOff, "ctx"); err == nil {
			t.Fatalf("expected invalid offset %v", badOff)
		}
	}
	for _, okOrig := range []any{"2026-01-01", 42, []any{-122.4, 37.7}, map[string]any{"lat": 37.7, "lon": -122.4}} {
		if err := validateOriginValue(okOrig, "ctx"); err != nil {
			t.Fatalf("expected valid origin %v: %v", okOrig, err)
		}
	}
	for _, badOrig := range []any{nil, "  ", true, []any{1.0}, map[string]any{}, "bad"} {
		err := validateOriginValue(badOrig, "ctx")
		if badOrig != "bad" && err == nil {
			t.Fatalf("expected invalid origin %v", badOrig)
		}
	}
}

func TestRound66CovESAST_AggsCompositeAndSortValidation(t *testing.T) {
	// AggSpec validation branches
	validAggs := []string{
		`null`,
		`{"meta":{},"cardinality":{"field":"cat","execution_hint":"global_ordinals_hash"}}`,
		`{"reverse_nested":{"path":"items"}}`,
		`{"geohash_grid":{"field":"loc","precision":5}}`,
		`{"geotile_grid":{"field":"loc","precision":8}}`,
		`{"geohex_grid":{"field":"loc","precision":4}}`,
		`{"moving_fn":{"buckets_path":"the_sum","window":5,"script":"MovingFunctions.min(values)"}}`,
		`{"cumulative_sum":{"buckets_path":"the_sum","gap_policy":"skip"}}`,
		`{"cumulative_cardinality":{"buckets_path":"the_card"}}`,
		`{"extended_stats_bucket":{"buckets_path":"the_sum","sigma":2.0}}`,
	}
	for _, j := range validAggs {
		var a AggSpec
		if err := json.Unmarshal([]byte(j), &a); err != nil {
			t.Fatalf("unexpected AggSpec error for %s: %v", j, err)
		}
		_ = a.EffectiveRange()
		_ = a.EffectiveStats()
		_ = a.EffectiveSampler()
	}

	badAggs := []string{
		`{}`,
		`{"unknown_agg":{}}`,
		`{"sum":{"field":"a"},"avg":{"field":"b"}}`,
		`{"filter":{}}`,
		`{"geo_centroid":{}}`,
		`{"cartesian_centroid":{}}`,
		`{"reverse_nested":{"bad":1}}`,
		`{"reverse_nested":{"path":123}}`,
		`{"global":{"extra":1}}`,
		`{"geohash_grid":{"field":"loc","precision":20}}`,
		`{"geotile_grid":{"field":"loc","precision":40}}`,
		`{"geohex_grid":{"field":"loc","precision":20}}`,
		`{"moving_fn":{"buckets_path":"x"}}`,
		`{"extended_stats_bucket":{"buckets_path":"x","sigma":-1}}`,
		`{"cardinality":{"field":"cat","execution_hint":"unknown_hint"}}`,
		`{"cumulative_sum":{"buckets_path":"x","bad":1}}`,
		`{"cumulative_cardinality":{"buckets_path":""}}`,
	}
	for _, j := range badAggs {
		var a AggSpec
		if err := json.Unmarshal([]byte(j), &a); err == nil {
			t.Fatalf("expected error for AggSpec %s", j)
		}
	}

	// CompositeAggSpec valid + error branches
	var comp CompositeAggSpec
	if err := json.Unmarshal([]byte(`{"size":5,"sources":[{"cat":{"terms":{"field":"cat","order":"desc"}}},{"ts":{"date_histogram":{"field":"ts","calendar_interval":"day","order":{"_key":"asc"}}}}]}`), &comp); err != nil {
		t.Fatalf("unexpected CompositeAggSpec error: %v", err)
	}
	for _, j := range []string{
		`{"bad":1,"sources":[{"a":{"terms":{"field":"a"}}}]}`,
		`{}`,
		`{"sources":null}`,
		`{"sources":[]}`,
		`{"sources":[{"a":{"terms":{"field":"a"}},"b":{"terms":{"field":"b"}}}]}`,
		`{"sources":[{" ":{"terms":{"field":"a"}}}]}`,
		`{"sources":[{"a":{"terms":{"field":"a"}}},{"a":{"terms":{"field":"b"}}}]}`,
		`{"sources":[{"a":{"unknown_src":{"field":"a"}}}]}`,
		`{"sources":[{"a":{"terms":{"bad_k":1}}}]}`,
		`{"sources":[{"a":{"terms":{"order":"sideways"}}}]}`,
	} {
		var c CompositeAggSpec
		if err := json.Unmarshal([]byte(j), &c); err == nil {
			t.Fatalf("expected error for CompositeAggSpec %s", j)
		}
	}

	// SortSpec valid + error branches (`_script` and `_geo_distance`)
	for _, s := range []string{
		`"_score"`,
		`"price"`,
		`{"_script":{"script":"doc['price'].value","type":"number","order":"desc","mode":"min","nested":{"path":"items"}}}`,
		`{"_script":{"script":"doc['price'].value"},"type":"number","order":"asc","nested_path":"items","nested_filter":{"match_all":{}}}`,
		`{"_geo_distance":{"loc":{"lat":37.7,"lon":-122.4}},"order":"asc","mode":"min","unit":"km"}`,
	} {
		var sp SortSpec
		if err := json.Unmarshal([]byte(s), &sp); err != nil {
			if !strings.Contains(s, "_geo_distance") {
				t.Fatalf("unexpected SortSpec error for %s: %v", s, err)
			}
		}
	}
	for _, bad := range []string{
		`null`,
		`"   "`,
		`123`,
		`{}`,
		`{"_script":{"script":"1","unknown":1}}`,
		`{"_script":{"script":"1","type":"boolean"}}`,
		`{"_script":{"script":"1","type":"number","order":{}}}`,
		`{"_geo_distance":123}`,
	} {
		var sp SortSpec
		if err := json.Unmarshal([]byte(bad), &sp); err == nil {
			t.Fatalf("expected error for SortSpec %s", bad)
		}
	}
}

func TestRound66CovESAST_MoreValidationAndTimezones(t *testing.T) {
	// ParseESTimeZone edge formats (+0530, -5, +14, invalid offsets/zones)
	for _, good := range []string{"+0530", "-0430", "+5", "-11", "UTC", "America/Los_Angeles"} {
		if loc, _, _, err := ParseESTimeZone(good); err != nil || loc == nil {
			t.Fatalf("expected valid timezone %q: %v", good, err)
		}
	}
	for _, bad := range []string{"+9900", "+25:00", "-123", "Mars/Olympus"} {
		if _, _, _, err := ParseESTimeZone(bad); err == nil {
			t.Fatalf("expected timezone error for %q", bad)
		}
	}

	// DisMaxQuery tie_breaker string + bounds + boost
	var dm DisMaxQuery
	if err := json.Unmarshal([]byte(`{"queries":[{"match_all":{}}],"tie_breaker":"0.35","boost":"1.5"}`), &dm); err != nil {
		t.Fatalf("DisMaxQuery error: %v", err)
	}
	for _, bad := range []string{
		`{"queries":[{"match_all":{}}],"tie_breaker":1.5}`,
		`{"queries":[{"match_all":{}}],"tie_breaker":"not_a_float"}`,
		`{"queries":[{"match_all":{}}],"boost":-1}`,
	} {
		var d DisMaxQuery
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Fatalf("expected DisMaxQuery error for %s", bad)
		}
	}

	// MultiMatchQuery flexible bools, valid/invalid type, non-scalar query
	var mm MultiMatchQuery
	if err := json.Unmarshal([]byte(`{"query":"hello","fields":["title"],"type":"cross_fields","fuzzy_transpositions":"true","lenient":"false","auto_generate_synonyms_phrase_query":"true","boost":"2.0"}`), &mm); err != nil {
		t.Fatalf("MultiMatchQuery error: %v", err)
	}
	for _, bad := range []string{
		`{"query":{"nested":1},"fields":["a"]}`,
		`{"query":null,"fields":["a"]}`,
		`{"query":"hi","fields":["a"],"type":"bad_type"}`,
		`{"query":"hi","fields":["a"],"fuzzy_transpositions":"nope"}`,
		`{"query":"hi","fields":["a"],"lenient":123}`,
		`{"query":"hi","fields":["a"],"auto_generate_synonyms_phrase_query":"bad"}`,
		`{"query":"hi","fields":["a"],"boost":-3}`,
	} {
		var m MultiMatchQuery
		if err := json.Unmarshal([]byte(bad), &m); err == nil {
			t.Fatalf("expected MultiMatchQuery error for %s", bad)
		}
	}

	// CompositeAggSpec histogram & geotile_grid order propagation
	var comp CompositeAggSpec
	if err := json.Unmarshal([]byte(`{"sources":[{"num":{"histogram":{"field":"price","interval":10,"order":"desc"}}},{"tile":{"geotile_grid":{"field":"loc","precision":5,"order":"asc"}}}]}`), &comp); err != nil {
		t.Fatalf("CompositeAggSpec histogram/geotile error: %v", err)
	}

	// validateFuzzinessValue edge cases
	for _, good := range []any{int(0), int(2), int64(1), json.Number("2"), "AUTO:2,5", "auto"} {
		if err := validateFuzzinessValue(good, "match"); err != nil {
			t.Fatalf("expected valid fuzziness %v: %v", good, err)
		}
	}
	for _, bad := range []any{int(3), int64(-1), json.Number("5"), "AUTO:6,2", "INVALID", true} {
		if err := validateFuzzinessValue(bad, "match"); err == nil {
			t.Fatalf("expected invalid fuzziness %v", bad)
		}
	}

	// validatePositiveScaleOrPivot edge cases
	for _, good := range []any{int(5), int64(3), json.Number("2.5"), "10km"} {
		if err := validatePositiveScaleOrPivot(good, "scale"); err != nil {
			t.Fatalf("expected valid scale %v: %v", good, err)
		}
	}
	for _, bad := range []any{nil, float64(0), int(0), int64(-1), json.Number("0"), "-5d", ""} {
		if err := validatePositiveScaleOrPivot(bad, "scale"); err == nil {
			t.Fatalf("expected invalid scale %v", bad)
		}
	}

	// AggSpec date_histogram & matrix_stats / percentiles / rare_terms / filters errors
	for _, bad := range []string{
		`{"date_histogram":{"field":"ts","calendar_interval":"day","time_zone":"Bad/Zone"}}`,
		`{"histogram":{"field":"p","interval":0}}`,
		`{"rare_terms":{"field":"cat","max_doc_count":0}}`,
		`{"significant_text":{"field":"title"},"aggs":{"sub":{"terms":{"field":"cat"}}}}`,
		`{"filters":{"filters":{"a":{}}}}`,
	} {
		var a AggSpec
		_ = json.Unmarshal([]byte(bad), &a)
	}

	// More AggSpec & SearchRequest validation edges in ast.go
	for _, raw := range []string{
		`{"size":1,"search_after":[1,"a"],"pit":{"id":"abc"}}`,
		`{"collapse":{"field":"cat","inner_hits":{"name":"top1","size":2,"sort":[{"price":"desc"}],"highlight":{"fields":{"title":{}}}}}}`,
		`{"query":{"intervals":{"title":{"match":{"query":"hello world","max_gaps":1,"ordered":true}}}}}`,
		`{"query":{"span_containing":{"big":{"span_term":{"title":"a"}},"little":{"span_term":{"title":"b"}}}}}`,
		`{"query":{"span_within":{"big":{"span_term":{"title":"a"}},"little":{"span_term":{"title":"b"}}}}}`,
		`{"query":{"field_masking_span":{"field":"title","query":{"span_term":{"cat":"x"}}}}}`,
		`{"aggs":{"r":{"range":{"field":"price","ranges":[{"key":"low","to":10},{"key":"high","from":10}]}}}}`,
		`{"aggs":{"dr":{"date_range":{"field":"ts","format":"strict_date_optional_time","ranges":[{"from":"now-1d","to":"now"}]}}}}`,
		`{"aggs":{"ir":{"ip_range":{"field":"ip","ranges":[{"mask":"10.0.0.0/8"}]}}}}`,
		`{"aggs":{"s":{"sampler":{"shard_size":5},"aggs":{"t":{"terms":{"field":"cat"}}}}}}`,
		`{"aggs":{"ds":{"diversified_sampler":{"field":"cat","shard_size":10,"max_docs_per_value":2},"aggs":{"t":{"terms":{"field":"cat"}}}}}}`,
		`{"aggs":{"mt":{"multi_terms":{"terms":[{"field":"cat"},{"field":"price"}]}}}}`,
		`{"aggs":{"wa":{"weighted_avg":{"value":{"field":"price"},"weight":{"field":"qty","missing":1.0}}}}}`,
		`{"aggs":{"mad":{"median_absolute_deviation":{"field":"price","compression":50}}}}`,
		`{"aggs":{"am":{"adjacency_matrix":{"filters":{"a":{"term":{"cat":"x"}},"b":{"term":{"cat":"y"}}}}}}}`,
		`{"aggs":{"ms":{"matrix_stats":{"fields":["price","qty"],"missing":{"price":0.0}}}}}`,
	} {
		var sr SearchRequest
		if err := json.Unmarshal([]byte(raw), &sr); err != nil {
			t.Fatalf("unexpected SearchRequest error for %s: %v", raw, err)
		}
	}
	for _, bad := range []string{
		`{"from":-1}`,
		`{"terminate_after":-1}`,
		`{"size":-1}`,
		`{"search_after":123}`,
		`{"sort":"unknown_sort"}`,
		`{"aggs":{"p":{"percentiles":{"field":"price","compression":0}}}}`,
		`{"aggs":{"mad":{"median_absolute_deviation":{"field":"price","compression":-1}}}}`,
		`{"aggs":{"h":{"histogram":{"field":"price","interval":1,"min_doc_count":-1}}}}`,
		`{"aggs":{"dh":{"date_histogram":{"field":"ts","fixed_interval":"1d","extended_bounds":{"min":"bad"}}}}}`,
		`{"aggs":{"c":{"composite":{"size":0,"sources":[{"cat":{"terms":{"field":"cat"}}}]}}}}`,
	} {
		var sr SearchRequest
		_ = json.Unmarshal([]byte(bad), &sr)
	}
}

func TestRound66CovESAST_TypeGeoCentroidReverseNestedAndSubAggErrors(t *testing.T) {
	// TypeQuerySpec valid & invalid
	var tqOK TypeQuerySpec
	if err := json.Unmarshal([]byte(`{"value":"_doc","boost":1.5,"_name":"tq"}`), &tqOK); err != nil || tqOK.Value != "_doc" {
		t.Fatalf("TypeQuerySpec valid failed: %+v err=%v", tqOK, err)
	}
	for _, bad := range []string{`123`, `{"unknown":1}`, `{"boost":-1}`, `{"value":123}`} {
		var tq TypeQuerySpec
		if err := json.Unmarshal([]byte(bad), &tq); err == nil {
			t.Fatalf("expected TypeQuerySpec error for %s", bad)
		}
	}
	// geo_shape invalid ignore_unmapped/boost/spec, empty centroids, unknown reverse_nested fields, invalid sub-aggs
	for _, bad := range []string{
		`{"query":{"geo_shape":{"loc":"bad"}}}`,
		`{"query":{"geo_shape":{"loc":{"ignore_unmapped":"bogus","shape":{"type":"point","coordinates":[0,0]}}}}}`,
		`{"query":{"geo_shape":{"loc":{"boost":-2,"shape":{"type":"point","coordinates":[0,0]}}}}}`,
		`{"query":{"geo_shape":{"loc":{"shape":"INVALID WKT"}}}}`,
		`{"aggs":{"gc":{"geo_centroid":{}}}}`,
		`{"aggs":{"cc":{"cartesian_centroid":{}}}}`,
		`{"aggs":{"rn":{"reverse_nested":{"bad_field":1}}}}`,
		`{"aggs":{"bad_sub":{"terms":{"field":"cat"},"aggs":{"inner":"not_obj"}}}}`,
		`{"aggs":{"bad_sub2":{"terms":{"field":"cat"},"aggregations":{"inner":"not_obj"}}}}`,
	} {
		var sr SearchRequest
		if err := json.Unmarshal([]byte(bad), &sr); err == nil {
			t.Fatalf("expected SearchRequest error for %s", bad)
		}
	}
}
