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

package esast

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func r67T2EMustUnmarshalErr(t *testing.T, name string, target any, raw string) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), target); err == nil {
		t.Fatalf("%s: expected unmarshal error for %s, got nil", name, raw)
	}
}

func r67T2EMustUnmarshalOK(t *testing.T, name string, target any, raw string) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		t.Fatalf("%s: unexpected unmarshal error for %s: %v", name, raw, err)
	}
}

func TestRound67TopUp2ESAST_SearchRequestAndHelpers(t *testing.T) {
	// SearchRequest: pre_filter_shard_size, batched_reduce_size, min_score, track_total_hits, search_after
	var sr SearchRequest
	r67T2EMustUnmarshalOK(t, "sr_valid_pf", &sr, `{"pre_filter_shard_size": 4, "batched_reduce_size": 2, "min_score": 0.5, "track_total_hits": true}`)
	if sr.BatchedReduceSize == nil || *sr.BatchedReduceSize != 2 {
		t.Fatalf("unexpected batched_reduce_size: %v", sr.BatchedReduceSize)
	}

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"pf_bad_str", `{"pre_filter_shard_size": "abc"}`},
		{"pf_zero", `{"pre_filter_shard_size": 0}`},
		{"brs_bad", `{"batched_reduce_size": "abc"}`},
		{"brs_one", `{"batched_reduce_size": 1}`},
		{"min_score_bad", `{"min_score": "bad"}`},
		{"tth_bad", `{"track_total_hits": "bad"}`},
		{"sa_bad", `{"search_after": "not_array"}`},
	} {
		var dst SearchRequest
		r67T2EMustUnmarshalErr(t, tc.name, &dst, tc.raw)
	}

	// parseBoundFloat variants
	for _, tc := range []struct {
		name   string
		in     any
		want   float64
		wantOK bool
	}{
		{"int", int(7), 7, true},
		{"int64", int64(19), 19, true},
		{"json_num", json.Number("3.25"), 3.25, true},
		{"json_num_bad", json.Number("bad"), 0, false},
		{"str", " 12.5 ", 12.5, true},
		{"str_bad", "nope", 0, false},
		{"bool", true, 0, false},
	} {
		got, ok := parseBoundFloat(tc.in)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Fatalf("parseBoundFloat(%s) = (%v, %v), want (%v, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}

	// parsePositiveDuration
	for _, raw := range []string{"", "-5s", "s", "0s", "abc", "5x"} {
		if err := parsePositiveDuration(raw); err == nil {
			t.Fatalf("parsePositiveDuration(%q): expected error", raw)
		}
	}
	if err := parsePositiveDuration("10m"); err != nil {
		t.Fatalf("parsePositiveDuration(10m) unexpected err: %v", err)
	}

	// PITSpec, SliceSpec, InnerHitsSpec error paths
	var pit PITSpec
	r67T2EMustUnmarshalErr(t, "pit_invalid_json", &pit, `{`)
	r67T2EMustUnmarshalErr(t, "pit_unknown", &pit, `{"id":"x","extra":1}`)
	r67T2EMustUnmarshalErr(t, "pit_empty_id", &pit, `{"id":""}`)
	r67T2EMustUnmarshalErr(t, "pit_bad_ka", &pit, `{"id":"x","keep_alive":"-1m"}`)

	var sl SliceSpec
	r67T2EMustUnmarshalErr(t, "slice_invalid_json", &sl, `{`)
	r67T2EMustUnmarshalErr(t, "slice_unknown", &sl, `{"id":0,"max":2,"x":1}`)
	r67T2EMustUnmarshalErr(t, "slice_no_id", &sl, `{"max":2}`)
	r67T2EMustUnmarshalErr(t, "slice_no_max", &sl, `{"id":0}`)
	r67T2EMustUnmarshalErr(t, "slice_bad_id", &sl, `{"id":"bad","max":2}`)
	r67T2EMustUnmarshalErr(t, "slice_bad_max", &sl, `{"id":0,"max":"bad"}`)
	r67T2EMustUnmarshalErr(t, "slice_bad_field", &sl, `{"id":0,"max":2,"field":123}`)
	r67T2EMustUnmarshalErr(t, "slice_max_one", &sl, `{"id":0,"max":1}`)
	r67T2EMustUnmarshalErr(t, "slice_id_oob", &sl, `{"id":2,"max":2}`)
	if err := sl.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("slice null err: %v", err)
	}

	var ih InnerHitsSpec
	if err := ih.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("inner_hits null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "ih_invalid_json", &ih, `{`)
	r67T2EMustUnmarshalErr(t, "ih_unknown", &ih, `{"foo":1}`)
}

func TestRound67TopUp2ESAST_GeoAndSpatialQueries(t *testing.T) {
	// GeoShapeQuery null/empty/errors
	var gs GeoShapeQuery
	if err := gs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("gs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "gs_bad_json", &gs, `{`)
	r67T2EMustUnmarshalErr(t, "gs_bad_boost", &gs, `{"boost":-1,"loc":{"shape":{"type":"point","coordinates":[0,0]}}}`)
	r67T2EMustUnmarshalErr(t, "gs_bad_name", &gs, `{"_name":123,"loc":{"shape":{"type":"point","coordinates":[0,0]}}}`)
	r67T2EMustUnmarshalErr(t, "gs_bad_iu_json", &gs, `{"ignore_unmapped":"not_bool","loc":{"shape":{"type":"point","coordinates":[0,0]}}}`)
	r67T2EMustUnmarshalErr(t, "gs_bad_iu_arr", &gs, `{"ignore_unmapped":[],"loc":{"shape":{"type":"point","coordinates":[0,0]}}}`)

	// GeoDistanceQuery null/empty/errors
	var gd GeoDistanceQuery
	if err := gd.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("gd null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "gd_bad_json", &gd, `{`)
	r67T2EMustUnmarshalErr(t, "gd_bad_dist", &gd, `{"distance":, "loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_unit_type", &gd, `{"distance":10,"unit":123,"loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_unit_val", &gd, `{"distance":10,"unit":"lightyears","loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_dt_type", &gd, `{"distance":"1km","distance_type":1,"loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_vm_type", &gd, `{"distance":"1km","validation_method":1,"loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_vm_val", &gd, `{"distance":"1km","validation_method":"BAD","loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_name", &gd, `{"distance":"1km","_name":123,"loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_iu", &gd, `{"distance":"1km","ignore_unmapped":"nope","loc":{"lat":1,"lon":2}}`)
	r67T2EMustUnmarshalErr(t, "gd_bad_iu_type", &gd, `{"distance":"1km","ignore_unmapped":{},"loc":{"lat":1,"lon":2}}`)

	// GeoBoundingBoxQuery null/empty/errors/coerce
	var gb GeoBoundingBoxQuery
	if err := gb.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("gb null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "gb_bad_vm_type", &gb, `{"validation_method":123,"loc":{"top_left":[40,-74],"bottom_right":[39,-73]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_boost", &gb, `{"boost":-2,"loc":{"top_left":[40,-74],"bottom_right":[39,-73]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_name", &gb, `{"_name":123,"loc":{"top_left":[40,-74],"bottom_right":[39,-73]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_iu", &gb, `{"ignore_unmapped":"nope","loc":{"top_left":[40,-74],"bottom_right":[39,-73]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_tl", &gb, `{"loc":{"top_left":"bad","bottom_right":[39,-73]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_br", &gb, `{"loc":{"top_left":[40,-74],"bottom_right":"bad"}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_tr", &gb, `{"loc":{"top_right":"bad","bottom_left":[39,-74]}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_bl", &gb, `{"loc":{"top_right":[40,-73],"bottom_left":"bad"}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_top", &gb, `{"loc":{"top":"x","left":1,"bottom":0,"right":2}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_left", &gb, `{"loc":{"top":1,"left":"x","bottom":0,"right":2}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_bottom", &gb, `{"loc":{"top":1,"left":1,"bottom":"x","right":2}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_right", &gb, `{"loc":{"top":1,"left":1,"bottom":0,"right":"x"}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_tl_lat", &gb, `{"loc":{"top_left":{"lat":95,"lon":0},"bottom_right":{"lat":0,"lon":1}}}`)
	r67T2EMustUnmarshalErr(t, "gb_bad_br_lat", &gb, `{"loc":{"top_left":{"lat":10,"lon":0},"bottom_right":{"lat":-95,"lon":1}}}`)
	r67T2EMustUnmarshalOK(t, "gb_coerce_swap", &gb, `{"validation_method":"COERCE","loc":{"top_left":{"lat":10,"lon":0},"bottom_right":{"lat":20,"lon":1}}}`)
	if gb.Top != 20 || gb.Bottom != 10 {
		t.Fatalf("expected coerced top=20 bottom=10, got %v %v", gb.Top, gb.Bottom)
	}

	// GeoPolygonQuery null/empty/errors
	var gp GeoPolygonQuery
	if err := gp.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("gp null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "gp_bad_json", &gp, `{`)
	r67T2EMustUnmarshalErr(t, "gp_bad_vm_type", &gp, `{"validation_method":1,"loc":{"points":[[0,0],[1,0],[1,1]]}}`)
	r67T2EMustUnmarshalErr(t, "gp_bad_boost", &gp, `{"boost":-1,"loc":{"points":[[0,0],[1,0],[1,1]]}}`)
	r67T2EMustUnmarshalErr(t, "gp_bad_name", &gp, `{"_name":1,"loc":{"points":[[0,0],[1,0],[1,1]]}}`)
	r67T2EMustUnmarshalErr(t, "gp_bad_iu", &gp, `{"ignore_unmapped":"nope","loc":{"points":[[0,0],[1,0],[1,1]]}}`)
	r67T2EMustUnmarshalErr(t, "gp_two_fields", &gp, `{"loc1":{"points":[[0,0],[1,0],[1,1]]},"loc2":{"points":[[0,0],[1,0],[1,1]]}}`)
	r67T2EMustUnmarshalErr(t, "gp_bad_pt", &gp, `{"loc":{"points":["bad",[1,0],[1,1]]}}`)

	// parseGeoWKTBBox & validateAndNormalizeGeoPoint
	for _, wkt := range []string{"POINT(1 2)", "BBOX 1,2,3,4", "BBOX(1,2,3)", "BBOX(a,2,3,4)"} {
		if _, _, _, _, err := parseGeoWKTBBox(wkt); err == nil {
			t.Fatalf("parseGeoWKTBBox(%q): expected error", wkt)
		}
	}
	if lat, lon, err := validateAndNormalizeGeoPoint(120, 380, "COERCE"); err != nil || lat != 90 || lon != 20 {
		t.Fatalf("validateAndNormalizeGeoPoint coerce got (%v, %v, %v)", lat, lon, err)
	}
	if lat, lon, err := validateAndNormalizeGeoPoint(-120, -380, "IGNORE_MALFORMED"); err != nil || lat != -90 || lon != -20 {
		t.Fatalf("validateAndNormalizeGeoPoint ignore_malformed got (%v, %v, %v)", lat, lon, err)
	}
}

func TestRound67TopUp2ESAST_QueriesAndValidation(t *testing.T) {
	// QueryStringQuery flexible bool error paths and unknown type
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"ft", `{"query":"a","fuzzy_transpositions":"bad"}`},
		{"lenient", `{"query":"a","lenient":"bad"}`},
		{"aw", `{"query":"a","analyze_wildcard":"bad"}`},
		{"alw", `{"query":"a","allow_leading_wildcard":"bad"}`},
		{"agspq", `{"query":"a","auto_generate_synonyms_phrase_query":"bad"}`},
		{"esc", `{"query":"a","escape":"bad"}`},
		{"sow", `{"query":"a","split_on_whitespace":"bad"}`},
		{"epi", `{"query":"a","enable_position_increments":"bad"}`},
		{"type", `{"query":"a","type":"nonexistent"}`},
	} {
		var qsq QueryStringQuery
		r67T2EMustUnmarshalErr(t, tc.name, &qsq, tc.raw)
	}

	// KNNQuery OpenSearch syntax + KNNSlice
	var ks KNNSlice
	if err := ks.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("ks null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "ks_bad_arr", &ks, `[{"k":0}]`)
	r67T2EMustUnmarshalErr(t, "ks_bad_single", &ks, `{"k":0}`)
	for _, raw := range []string{
		`{"vec":{"vector":[1,2],"k":5,"num_candidates":10001}}`,
		`{"vec":{"vector":[1,2],"k":5,"num_candidates":0}}`,
		`{"vec":{"vector":[1,2],"k":5,"num_candidates":3}}`,
		`{"vec":"not_obj"}`,
		`{"vec":{"vector":[1,2],"k":2,"unknown_k":1}}`,
		`{"vec":{"vector":[1,2],"k":2,"boost":-1}}`,
		`{" ":{"vector":[1,2],"k":2}}`,
		`{"vec":{"k":2}}`,
	} {
		var kq KNNQuery
		r67T2EMustUnmarshalErr(t, "knn_"+raw, &kq, raw)
	}
	var kqBoost KNNQuery
	r67T2EMustUnmarshalErr(t, "knn_bad_outer_boost", &kqBoost, `{"boost":-1,"vec":{"vector":[1,2],"k":2}}`)

	// Query.UnmarshalJSON _name propagation from subqueries
	wrappedB64 := base64.StdEncoding.EncodeToString([]byte(`{"match_all":{"_name":"wn"}}`))
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"percolate", `{"percolate":{"field":"q","document":{"a":1},"_name":"pn"}}`, "pn"},
		{"boosting", `{"boosting":{"positive":{"match_all":{}},"negative":{"match_all":{}},"negative_boost":0.2,"_name":"bn"}}`, "bn"},
		{"wrapper", `{"wrapper":{"query":"` + wrappedB64 + `"}}`, "wn"},
		{"sparse_vec", `{"sparse_vector":{"field":"sv","tokens":{"a":1.0},"_name":"svn"}}`, "svn"},
		{"geo_grid", `{"geo_grid":{"loc":{"geohash":"u4"},"_name":"ggn"}}`, "ggn"},
	} {
		var q Query
		r67T2EMustUnmarshalOK(t, tc.name, &q, tc.raw)
		if q.Name != tc.want {
			t.Fatalf("%s: expected Query.Name=%q, got %q", tc.name, tc.want, q.Name)
		}
	}

	// DisMaxQuery, IdsQuery, TermEntry, PrefixEntry, WildcardEntry, RegexpEntry, MatchEntry, MatchPhraseEntry, MultiMatchQuery
	var dm DisMaxQuery
	if err := dm.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("dm null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "dm_bad_json", &dm, `{`)
	r67T2EMustUnmarshalErr(t, "dm_unknown", &dm, `{"queries":[],"bad":1}`)

	var iq IdsQuery
	if err := iq.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("iq null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "iq_bad_json", &iq, `{`)
	r67T2EMustUnmarshalErr(t, "iq_unknown", &iq, `{"values":["1"],"bad":1}`)

	var te TermEntry
	r67T2EMustUnmarshalErr(t, "te_bad_json", &te, `{`)
	r67T2EMustUnmarshalErr(t, "te_bad_val", &te, `{"value":[1,2]}`)
	r67T2EMustUnmarshalErr(t, "te_bad_ci", &te, `{"value":"a","case_insensitive":"nope"}`)
	r67T2EMustUnmarshalErr(t, "te_bad_boost", &te, `{"value":"a","boost":-1}`)

	var pe PrefixEntry
	r67T2EMustUnmarshalErr(t, "pe_missing", &pe, `{}`)
	r67T2EMustUnmarshalErr(t, "pe_bad_json", &pe, `{"value":}`)
	r67T2EMustUnmarshalErr(t, "pe_bad_ci", &pe, `{"value":"a","case_insensitive":"nope"}`)
	r67T2EMustUnmarshalErr(t, "pe_nonscalar", &pe, `{"value":{"a":1}}`)
	r67T2EMustUnmarshalErr(t, "pe_bad_boost", &pe, `{"value":"a","boost":-1}`)
	r67T2EMustUnmarshalErr(t, "pe_scalar_nonscalar", &pe, `[1,2]`)

	var we WildcardEntry
	r67T2EMustUnmarshalErr(t, "we_missing", &we, `{}`)
	r67T2EMustUnmarshalErr(t, "we_bad_ci", &we, `{"value":"a*","case_insensitive":"nope"}`)
	r67T2EMustUnmarshalErr(t, "we_nonscalar", &we, `{"value":[1]}`)
	r67T2EMustUnmarshalErr(t, "we_bad_boost", &we, `{"value":"a*","boost":-1}`)

	var re RegexpEntry
	r67T2EMustUnmarshalErr(t, "re_bad_flags", &re, `{"value":"a.*","flags":"BADFLAG"}`)
	r67T2EMustUnmarshalErr(t, "re_bad_ci", &re, `{"value":"a.*","case_insensitive":"nope"}`)
	r67T2EMustUnmarshalErr(t, "re_nonscalar", &re, `{"value":[1]}`)
	r67T2EMustUnmarshalErr(t, "re_bad_boost", &re, `{"value":"a.*","boost":-1}`)

	var me MatchEntry
	r67T2EMustUnmarshalErr(t, "me_bad_agspq", &me, `{"query":"hi","auto_generate_synonyms_phrase_query":"nope"}`)
	r67T2EMustUnmarshalErr(t, "me_nonscalar", &me, `[1]`)

	var mpe PhraseEntry
	r67T2EMustUnmarshalErr(t, "mpe_neg_slop", &mpe, `{"query":"hi","slop":-1}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_fuzz", &mpe, `{"query":"hi","fuzziness":-1}`)
	r67T2EMustUnmarshalErr(t, "mpe_zero_maxexp", &mpe, `{"query":"hi","max_expansions":0}`)
	r67T2EMustUnmarshalErr(t, "mpe_neg_pfx", &mpe, `{"query":"hi","prefix_length":-1}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_ft", &mpe, `{"query":"hi","fuzzy_transpositions":"nope"}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_lenient", &mpe, `{"query":"hi","lenient":"nope"}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_op", &mpe, `{"query":"hi","operator":"xor"}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_ztq", &mpe, `{"query":"hi","zero_terms_query":"bad"}`)
	r67T2EMustUnmarshalErr(t, "mpe_bad_boost", &mpe, `{"query":"hi","boost":-1}`)

	var mmq MultiMatchQuery
	r67T2EMustUnmarshalErr(t, "mmq_bad_type", &mmq, `{"query":"hi","fields":["t"],"type":"bogus"}`)
	r67T2EMustUnmarshalErr(t, "mmq_bp_slop", &mmq, `{"query":"hi","fields":["t"],"type":"bool_prefix","slop":1}`)
	r67T2EMustUnmarshalErr(t, "mmq_bp_cf", &mmq, `{"query":"hi","fields":["t"],"type":"bool_prefix","cutoff_frequency":0.1}`)
	r67T2EMustUnmarshalErr(t, "mmq_bad_op", &mmq, `{"query":"hi","fields":["t"],"operator":"xor"}`)
	r67T2EMustUnmarshalErr(t, "mmq_bad_ztq", &mmq, `{"query":"hi","fields":["t"],"zero_terms_query":"bad"}`)
	r67T2EMustUnmarshalErr(t, "mmq_neg_slop", &mmq, `{"query":"hi","fields":["t"],"slop":-1}`)
	r67T2EMustUnmarshalErr(t, "mmq_bad_fuzz", &mmq, `{"query":"hi","fields":["t"],"fuzziness":-1}`)
	r67T2EMustUnmarshalErr(t, "mmq_neg_pfx", &mmq, `{"query":"hi","fields":["t"],"prefix_length":-1}`)
	r67T2EMustUnmarshalErr(t, "mmq_zero_maxexp", &mmq, `{"query":"hi","fields":["t"],"max_expansions":0}`)
	r67T2EMustUnmarshalErr(t, "mmq_bad_tb", &mmq, `{"query":"hi","fields":["t"],"tie_breaker":1.5}`)

	// DecayFunctionSpec & ScoreFunctionSpec
	var df DecayFunctionSpec
	if err := df.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("df null err: %v", err)
	}
	for _, raw := range []string{
		`{"multi_value_mode":123,"f":{"origin":0,"scale":1}}`,
		`{"multi_value_mode":"bad","f":{"origin":0,"scale":1}}`,
		`{"a":{"origin":0,"scale":1},"b":{"origin":0,"scale":1}}`,
		`{"f":"not_obj"}`,
		`{"f":{"origin":0,"scale":1,"bad":1}}`,
		`{"f":{"scale":1}}`,
		`{"f":{"origin":0}}`,
		`{"f":{"origin":null,"scale":1}}`,
		`{"f":{"origin":{},"scale":1}}`,
		`{"f":{"origin":0,"scale":0}}`,
		`{"f":{"origin":0,"scale":1,"offset":-1}}`,
		`{"f":{"origin":0,"scale":1,"multi_value_mode":"bad"}}`,
		`{"f":{"origin":0,"scale":1,"decay":-1}}`,
	} {
		var dst DecayFunctionSpec
		r67T2EMustUnmarshalErr(t, "df", &dst, raw)
	}

	var sfs ScoreFunctionSpec
	if err := sfs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("sfs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "sfs_bad_json", &sfs, `{`)
	r67T2EMustUnmarshalErr(t, "sfs_unknown", &sfs, `{"unknown_fn":{}}`)
	r67T2EMustUnmarshalErr(t, "sfs_bad_weight", &sfs, `{"weight":-1}`)

	// PinnedQuery & MoreLikeThisQuery & HasParentQuery
	var pq PinnedQuery
	if err := pq.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("pq null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "pq_bad_json", &pq, `{`)
	r67T2EMustUnmarshalErr(t, "pq_unknown", &pq, `{"ids":["1"],"organic":{"match_all":{}},"x":1}`)
	r67T2EMustUnmarshalErr(t, "pq_both", &pq, `{"ids":["1"],"docs":[{"_id":"1"}],"organic":{"match_all":{}}}`)
	r67T2EMustUnmarshalErr(t, "pq_bad_docs", &pq, `{"docs":[{"_id":""}],"organic":{"match_all":{}}}`)
	r67T2EMustUnmarshalErr(t, "pq_bad_doc_type", &pq, `{"docs":[{"_id":[]}],"organic":{"match_all":{}}}`)

	for _, raw := range []string{
		`{"like":"abc","min_doc_freq":-1}`,
		`{"like":"abc","max_doc_freq":-1}`,
		`{"like":"abc","min_doc_freq":5,"max_doc_freq":2}`,
		`{"like":"abc","min_word_length":-1}`,
		`{"like":"abc","max_word_length":-1}`,
		`{"like":"abc","min_word_length":5,"max_word_length":2}`,
		`{"like":[]}`,
		`{"like_text":"   "}`,
		`{"like":"abc","unlike":[]}`,
		`{"like":"abc","fields":{}}`,
		`{"like":"abc","ids":{}}`,
		`{"like":"abc","ids":[]}`,
		`{"like":"abc","ids":[""]}`,
		`{"like":"abc","docs":[]}`,
		`{"like":"abc","docs":[{}]}`,
		`{"like":"abc","stop_words":{}}`,
		`{"like":"abc","fail_on_unsupported_field":"bad"}`,
		`{"like":"abc","boost":-1}`,
	} {
		var dst MoreLikeThisQuery
		r67T2EMustUnmarshalErr(t, "mlt", &dst, raw)
	}

	var hp HasParentQuery
	r67T2EMustUnmarshalErr(t, "hp_bad_score", &hp, `{"parent_type":"p","query":{"match_all":{}},"score":"nope"}`)
	r67T2EMustUnmarshalErr(t, "hp_bad_iu", &hp, `{"parent_type":"p","query":{"match_all":{}},"ignore_unmapped":"nope"}`)
	r67T2EMustUnmarshalErr(t, "hp_bad_boost", &hp, `{"parent_type":"p","query":{"match_all":{}},"boost":-1}`)
}

func TestRound67TopUp2ESAST_AggsSortHighlightAndSuggest(t *testing.T) {
	// RandomSamplerAggSpec, RareTermsAggSpec, AutoDateHistogramAggSpec, VariableWidthHistogramAggSpec
	var rs RandomSamplerAggSpec
	if err := rs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("rs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "rs_unknown", &rs, `{"probability":0.2,"bad":1}`)
	r67T2EMustUnmarshalErr(t, "rs_bad_prob", &rs, `{"probability":1.0}`)
	r67T2EMustUnmarshalOK(t, "rs_default_prob", &rs, `{}`)
	if rs.Probability == nil || *rs.Probability != 0.1 {
		t.Fatalf("expected default probability 0.1, got %v", rs.Probability)
	}

	var rt RareTermsAggSpec
	if err := rt.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("rt null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "rt_unknown", &rt, `{"field":"k","bad":1}`)
	r67T2EMustUnmarshalErr(t, "rt_empty_field", &rt, `{}`)
	r67T2EMustUnmarshalErr(t, "rt_bad_mdc", &rt, `{"field":"k","max_doc_count":101}`)
	if rt.EffectiveMaxDocCount() != 1 {
		t.Fatalf("expected default max_doc_count 1")
	}

	var adh AutoDateHistogramAggSpec
	r67T2EMustUnmarshalErr(t, "adh_unknown", &adh, `{"field":"ts","bad":1}`)
	r67T2EMustUnmarshalErr(t, "adh_missing_field", &adh, `{}`)
	r67T2EMustUnmarshalErr(t, "adh_bad_script", &adh, `{"script":{"source":""}}`)
	r67T2EMustUnmarshalErr(t, "adh_bad_buckets", &adh, `{"field":"ts","buckets":0}`)
	r67T2EMustUnmarshalErr(t, "adh_bad_min_int", &adh, `{"field":"ts","minimum_interval":"decade"}`)

	var vwh VariableWidthHistogramAggSpec
	r67T2EMustUnmarshalErr(t, "vwh_unknown", &vwh, `{"field":"n","bad":1}`)
	r67T2EMustUnmarshalErr(t, "vwh_missing_field", &vwh, `{}`)
	r67T2EMustUnmarshalErr(t, "vwh_bad_script", &vwh, `{"script":{"source":""}}`)
	r67T2EMustUnmarshalErr(t, "vwh_bad_buckets", &vwh, `{"field":"n","buckets":0}`)
	r67T2EMustUnmarshalErr(t, "vwh_bad_ib", &vwh, `{"field":"n","initial_buffer":0}`)
	r67T2EMustUnmarshalErr(t, "vwh_bad_ss", &vwh, `{"field":"n","shard_size":0}`)

	// TTestSampleSpec, TTestAggSpec, AggSpec, HistogramBoundsSpec
	var tts TTestSampleSpec
	r67T2EMustUnmarshalErr(t, "tts_unknown", &tts, `{"field":"a","bad":1}`)
	r67T2EMustUnmarshalErr(t, "tts_empty", &tts, `{}`)
	r67T2EMustUnmarshalErr(t, "tts_bad_script", &tts, `{"script":{"source":""}}`)

	var tta TTestAggSpec
	r67T2EMustUnmarshalErr(t, "tta_unknown", &tta, `{"a":{"field":"x"},"b":{"field":"y"},"bad":1}`)
	r67T2EMustUnmarshalErr(t, "tta_missing_ab", &tta, `{"a":{"field":"x"}}`)
	r67T2EMustUnmarshalErr(t, "tta_bad_type", &tta, `{"a":{"field":"x"},"b":{"field":"y"},"type":"bogus"}`)

	var agg AggSpec
	r67T2EMustUnmarshalErr(t, "agg_empty", &agg, `{}`)
	r67T2EMustUnmarshalErr(t, "agg_two_types", &agg, `{"avg":{"field":"x"},"sum":{"field":"x"}}`)
	r67T2EMustUnmarshalErr(t, "agg_empty_filter", &agg, `{"filter":{},"aggs":{"c":{"value_count":{"field":"x"}}}}`)
	r67T2EMustUnmarshalErr(t, "agg_bad_subaggs", &agg, `{"terms":{"field":"k"},"aggs":"not_map"}`)
	r67T2EMustUnmarshalErr(t, "agg_bad_subaggs2", &agg, `{"terms":{"field":"k"},"aggregations":"not_map"}`)
	r67T2EMustUnmarshalErr(t, "agg_geocentroid_empty", &agg, `{"geo_centroid":{}}`)
	r67T2EMustUnmarshalErr(t, "agg_cartcentroid_empty", &agg, `{"cartesian_centroid":{}}`)
	r67T2EMustUnmarshalErr(t, "agg_revnested_unknown", &agg, `{"reverse_nested":{"bad":1}}`)
	r67T2EMustUnmarshalErr(t, "agg_revnested_bad_path", &agg, `{"reverse_nested":{"path":123}}`)

	var hb HistogramBoundsSpec
	if err := hb.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("hb null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "hb_unknown", &hb, `{"min":0,"max":10,"bad":1}`)
	r67T2EMustUnmarshalErr(t, "hb_no_min", &hb, `{"max":10}`)
	r67T2EMustUnmarshalErr(t, "hb_no_max", &hb, `{"min":0}`)

	// validateBucketAggOrderSpec & parseFlexibleRangesArrayOrMap
	for _, ord := range []any{
		map[string]any{"_key": "sideways"},
		map[string]any{"_key": map[string]any{"a": "asc", "b": "desc"}},
		map[string]any{"_key": map[string]any{"dir": "asc"}},
		map[string]any{"_key": map[string]any{"order": 123}},
		map[string]any{"_key": map[string]any{"order": "sideways"}},
		map[string]any{"_key": 123},
		[]any{},
	} {
		if err := validateBucketAggOrderSpec(ord, "terms"); err == nil {
			t.Fatalf("validateBucketAggOrderSpec(%v): expected error", ord)
		}
	}
	if _, _, err := parseFlexibleRangesArrayOrMap(json.RawMessage(`123`)); err == nil {
		t.Fatalf("parseFlexibleRangesArrayOrMap(123): expected error")
	}
	if _, _, err := parseFlexibleRangesArrayOrMap(json.RawMessage(`{"k1":{"from":"bad"`)); err == nil {
		t.Fatalf("parseFlexibleRangesArrayOrMap malformed keyed object: expected error")
	}
	if _, _, err := parseFlexibleRangesArrayOrMap(json.RawMessage(`{"k1":{"from":1},"k2":"not_an_object"}`)); err == nil {
		t.Fatalf("parseFlexibleRangesArrayOrMap invalid bucket: expected error")
	}

	// SortSpec: order fallback, nested/nested_path/nested_filter on _script and _geo_distance, error paths
	for _, raw := range []string{
		`{}`,
		`{" ": "asc"}`,
		`{"f": {"order": 123}}`,
		`{"f": {"mode": 123}}`,
		`{"f": {"numeric_type": 123}}`,
		`{"f": {"numeric_type": "bogus"}}`,
		`{"f": {"ignore_unmapped": "nope"}}`,
		`{"f": {"nested": "bad"}}`,
		`{"f": {"nested_path": 123}}`,
		`{"f": {"nested_filter": "bad"}}`,
		`{"f": null}`,
		`{"_script": {"script": {"source": "1"}, "type": "number", "nested": "bad"}}`,
		`{"_script": {"script": {"source": "1"}, "type": "number", "nested_path": 123}}`,
		`{"_script": {"script": {"source": "1"}, "type": "number", "nested_filter": "bad"}}`,
		`{"_geo_distance": "bad"}`,
		`{"_geo_distance": {"loc": [0, 0]}, "order": 123}`,
		`{"_geo_distance": {"loc": [0, 0]}, "mode": 123}`,
		`{"_geo_distance": {"loc": [0, 0]}, "nested": "bad"}`,
		`{"_geo_distance": {"loc": [0, 0]}, "nested_path": 123}`,
	} {
		var ss SortSpec
		r67T2EMustUnmarshalErr(t, "sort", &ss, raw)
	}
	var ssOrd SortSpec
	r67T2EMustUnmarshalOK(t, "sort_order_field", &ssOrd, `{"order": "desc"}`)
	if ssOrd.Entry.Field != "order" || ssOrd.Entry.Order != "desc" {
		t.Fatalf("unexpected sort order field result: %+v", ssOrd.Entry)
	}
	var ssOrdMulti SortSpec
	r67T2EMustUnmarshalOK(t, "sort_order_with_meta", &ssOrdMulti, `{"order": "desc", "missing": "_last"}`)
	if ssOrdMulti.Entry.Field != "order" {
		t.Fatalf("unexpected sort order+meta result: %+v", ssOrdMulti.Entry)
	}

	// HighlightFieldSpec & HighlightSpec & parseFlexibleHighlightFields
	var hfs HighlightFieldSpec
	if err := hfs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("hfs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "hfs_bad_json", &hfs, `{`)
	r67T2EMustUnmarshalErr(t, "hfs_bad_pre", &hfs, `{"pre_tags":123}`)
	r67T2EMustUnmarshalErr(t, "hfs_bad_post", &hfs, `{"post_tags":123}`)
	r67T2EMustUnmarshalErr(t, "hfs_bad_mf", &hfs, `{"matched_fields":123}`)

	var hs HighlightSpec
	if err := hs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("hs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "hs_bad_json", &hs, `{`)
	if _, _, err := parseFlexibleHighlightFields(json.RawMessage(`{"": {}}`)); err == nil {
		t.Fatalf("expected error on empty highlight field name")
	}
	if _, _, err := parseFlexibleHighlightFields(json.RawMessage(`{"title": {"pre_tags": 123}}`)); err == nil {
		t.Fatalf("expected error on invalid HighlightFieldSpec")
	}

	// CollapseInnerHits, CollapseSpec, RescoreQuerySpec, RescoreSpec, RescoreSlice
	var cih CollapseInnerHits
	if err := cih.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("cih null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "cih_bad_arr", &cih, `[{"bad":1}]`)
	r67T2EMustUnmarshalErr(t, "cih_bad_single", &cih, `{"bad":1}`)

	var cs CollapseSpec
	if err := cs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("cs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "cs_unknown", &cs, `{"field":"f","bad":1}`)
	r67T2EMustUnmarshalErr(t, "cs_empty", &cs, `{"field":""}`)
	r67T2EMustUnmarshalErr(t, "cs_bad_mcgs", &cs, `{"field":"f","max_concurrent_group_searches":0}`)

	var rqs RescoreQuerySpec
	if err := rqs.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("rqs null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "rqs_unknown", &rqs, `{"rescore_query":{"match_all":{}},"bad":1}`)
	r67T2EMustUnmarshalErr(t, "rqs_no_rq", &rqs, `{}`)
	r67T2EMustUnmarshalErr(t, "rqs_bad_sm", &rqs, `{"rescore_query":{"match_all":{}},"score_mode":"bogus"}`)

	var rspec RescoreSpec
	if err := rspec.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("rspec null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "rspec_unknown", &rspec, `{"bad":1}`)
	r67T2EMustUnmarshalErr(t, "rspec_neg_ws", &rspec, `{"window_size":-1,"query":{"rescore_query":{"match_all":{}}}}`)
	r67T2EMustUnmarshalErr(t, "rspec_no_q", &rspec, `{"window_size":10}`)

	var rslice RescoreSlice
	if err := rslice.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("rslice null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "rslice_bad_arr", &rslice, `[{}]`)
	r67T2EMustUnmarshalErr(t, "rslice_bad_single", &rslice, `{}`)

	// SuggestSpec, TermSuggestSpec, CompletionQueryContext
	var sug SuggestSpec
	if err := sug.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("sug null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "sug_unknown", &sug, `{"bad":1}`)
	r67T2EMustUnmarshalErr(t, "sug_none", &sug, `{"text":"hi"}`)
	r67T2EMustUnmarshalErr(t, "sug_two", &sug, `{"term":{"field":"t"},"phrase":{"field":"t"}}`)

	var ts TermSuggestSpec
	if err := ts.UnmarshalJSON([]byte(`null`)); err != nil {
		t.Fatalf("ts null err: %v", err)
	}
	r67T2EMustUnmarshalErr(t, "ts_bad_json", &ts, `{`)
	r67T2EMustUnmarshalErr(t, "ts_unknown", &ts, `{"field":"t","bad":1}`)
	r67T2EMustUnmarshalErr(t, "ts_no_field", &ts, `{}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_size", &ts, `{"field":"t","size":0}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_mode", &ts, `{"field":"t","suggest_mode":"bogus"}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_sort", &ts, `{"field":"t","sort":"bogus"}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_dist", &ts, `{"field":"t","string_distance":"bogus"}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_edits", &ts, `{"field":"t","max_edits":3}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_pfx", &ts, `{"field":"t","prefix_length":-1}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_mwl", &ts, `{"field":"t","min_word_length":0}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_mi", &ts, `{"field":"t","max_inspections":0}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_mdf", &ts, `{"field":"t","min_doc_freq":-1}`)
	r67T2EMustUnmarshalErr(t, "ts_bad_mtf", &ts, `{"field":"t","max_term_freq":-1}`)

	var cqc CompletionQueryContext
	r67T2EMustUnmarshalErr(t, "cqc_null", &cqc, `null`)
	r67T2EMustUnmarshalOK(t, "cqc_scalar", &cqc, `"cat_a"`)
	if cqc.Context != "cat_a" || cqc.Boost != 1.0 {
		t.Fatalf("unexpected scalar CompletionQueryContext: %+v", cqc)
	}
	r67T2EMustUnmarshalOK(t, "cqc_geo", &cqc, `{"lat": 43.66, "lon": -79.38}`)
	if _, ok := cqc.Context.(map[string]any); !ok {
		t.Fatalf("expected geo map context, got %T", cqc.Context)
	}
	r67T2EMustUnmarshalErr(t, "cqc_missing_ctx", &cqc, `{"boost":2}`)
}
