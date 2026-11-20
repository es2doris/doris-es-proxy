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
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRound63_HighlightFieldsObjectAndOrderedArray(t *testing.T) {
	// 1. JSON array form (`30_ngram_highligthing.yml`)
	var srArr SearchRequest
	err := json.Unmarshal([]byte(`{
		"query": {"match_all": {}},
		"highlight": {
			"pre_tags": ["<em>"],
			"post_tags": ["</em>"],
			"fields": [
				{"field_b": {"fragment_size": 50, "number_of_fragments": 2}},
				{"field_a": {}}
			]
		}
	}`), &srArr)
	if err != nil {
		t.Fatalf("expected array highlight.fields to unmarshal cleanly, got: %v", err)
	}
	if srArr.Highlight == nil {
		t.Fatal("expected non-nil HighlightSpec")
	}
	wantOrder := []string{"field_b", "field_a"}
	if !reflect.DeepEqual(srArr.Highlight.OrderedFieldNames, wantOrder) {
		t.Fatalf("expected OrderedFieldNames=%v, got %v", wantOrder, srArr.Highlight.OrderedFieldNames)
	}
	fbSpec := srArr.Highlight.FieldSpec("field_b")
	if fbSpec.FragmentSize == nil || *fbSpec.FragmentSize != 50 || fbSpec.NumberOfFragments == nil || *fbSpec.NumberOfFragments != 2 {
		t.Fatalf("unexpected field_b HighlightFieldSpec: %+v", fbSpec)
	}
	if _, ok := srArr.Highlight.Fields["field_a"]; !ok {
		t.Fatalf("expected field_a in Highlight.Fields, got %+v", srArr.Highlight.Fields)
	}

	// 2. JSON object form preserves key order and fields map
	var srObj SearchRequest
	err = json.Unmarshal([]byte(`{
		"highlight": {
			"fields": {
				"title": {"type": "fvh"},
				"body": {"no_match_size": 100}
			}
		}
	}`), &srObj)
	if err != nil {
		t.Fatalf("expected object highlight.fields to unmarshal cleanly, got: %v", err)
	}
	if !reflect.DeepEqual(srObj.Highlight.OrderedFieldNames, []string{"title", "body"}) {
		t.Fatalf("unexpected OrderedFieldNames for object form: %v", srObj.Highlight.OrderedFieldNames)
	}
	if srObj.Highlight.FieldSpec("title").Type != "fvh" {
		t.Fatalf("unexpected title HighlightFieldSpec: %+v", srObj.Highlight.FieldSpec("title"))
	}

	// 3. Invalid highlight.fields forms rejected
	for _, bad := range []string{
		`{"highlight": {"fields": "not_obj_or_arr"}}`,
		`{"highlight": {"fields": ["not_an_object"]}}`,
		`{"highlight": {"fields": [{"a": {}, "b": {}}]}}`,
		`{"highlight": {"fields": [{"": {}}]}}`,
		`{"highlight": {"fields": {"": {}}}}`,
	} {
		var badSR SearchRequest
		if err := json.Unmarshal([]byte(bad), &badSR); err == nil {
			t.Fatalf("expected error for invalid highlight payload %s", bad)
		}
	}
}

func TestRound63_IPRangeSingleMapAndArrayRanges(t *testing.T) {
	// 1. Single-map `ranges` (`{"to": "10.0.0.5"}` -> 1-element slice, Keyed=false)
	var srSingle SearchRequest
	err := json.Unmarshal([]byte(`{
		"aggs": {
			"ip_buckets": {
				"ip_range": {
					"field": "ip",
					"ranges": {"from": "10.0.0.1", "to": "10.0.0.5"}
				}
			}
		}
	}`), &srSingle)
	if err != nil {
		t.Fatalf("expected single-map ip_range.ranges to unmarshal, got: %v", err)
	}
	ipAgg := srSingle.Aggs["ip_buckets"].IPRange
	if ipAgg == nil || len(ipAgg.Ranges) != 1 || ipAgg.Keyed {
		t.Fatalf("expected 1 unkeyed bucket on IPRange, got %+v", ipAgg)
	}
	if ipAgg.Ranges[0].From != "10.0.0.1" || ipAgg.Ranges[0].To != "10.0.0.5" {
		t.Fatalf("unexpected single-map bucket bounds: %+v", ipAgg.Ranges[0])
	}

	// Verify IPRangeAggSpec alias
	var directSpec IPRangeAggSpec
	if err := json.Unmarshal([]byte(`{"field":"ip","ranges":{"mask":"10.0.0.0/25"}}`), &directSpec); err != nil {
		t.Fatalf("IPRangeAggSpec direct unmarshal failed: %v", err)
	}
	if len(directSpec.Ranges) != 1 || directSpec.Ranges[0].Mask != "10.0.0.0/25" {
		t.Fatalf("unexpected directSpec: %+v", directSpec)
	}

	// 2. Keyed map of buckets (`{"to": {"from": ...}}` -> Keyed=true)
	var srKeyed SearchRequest
	err = json.Unmarshal([]byte(`{
		"aggs": {
			"ip_buckets": {
				"ip_range": {
					"field": "ip",
					"ranges": {
						"local": {"mask": "10.0.0.0/8"}
					}
				}
			}
		}
	}`), &srKeyed)
	if err != nil {
		t.Fatalf("expected keyed-map ip_range.ranges to unmarshal, got: %v", err)
	}
	if !srKeyed.Aggs["ip_buckets"].IPRange.Keyed || len(srKeyed.Aggs["ip_buckets"].IPRange.Ranges) != 1 || srKeyed.Aggs["ip_buckets"].IPRange.Ranges[0].Key != "local" {
		t.Fatalf("unexpected keyed IPRange: %+v", srKeyed.Aggs["ip_buckets"].IPRange)
	}

	// 3. Array form
	var srArr SearchRequest
	if err := json.Unmarshal([]byte(`{"aggs":{"r":{"ip_range":{"field":"ip","ranges":[{"to":"10.0.0.5"},{"from":"10.0.0.5"}]}}}}`), &srArr); err != nil {
		t.Fatalf("expected array ip_range.ranges to unmarshal, got: %v", err)
	}
	if len(srArr.Aggs["r"].IPRange.Ranges) != 2 || srArr.Aggs["r"].IPRange.Keyed {
		t.Fatalf("unexpected array IPRange: %+v", srArr.Aggs["r"].IPRange)
	}
}

func TestRound63_LookupRuntimeFieldsSizeMetaAggregateMetricsAndUint64NullValue(t *testing.T) {
	// 1. Lookup runtime field with object-array & string-array fetch_fields + _size + aggregate_metric_double + uint64 null_value + counted_terms
	var ms MappingSpec
	err := json.Unmarshal([]byte(`{
		"_size": {"enabled": true},
		"runtime": {
			"user_lookup_obj": {
				"type": "lookup",
				"target_index": "users",
				"input_field": "uid",
				"target_field": "id",
				"fetch_fields": [{"field": "city"}, {"field": "created_at", "format": "yyyy-MM-dd"}]
			},
			"user_lookup_str": {
				"type": "lookup",
				"target_index": "users",
				"input_field": "uid",
				"key_field": "id",
				"fetch_fields": ["country", "zip"]
			}
		},
		"properties": {
			"ul": {"type": "unsigned_long", "null_value": 17446744073709551615},
			"lat_metrics": {
				"type": "aggregate_metric_double",
				"metrics": ["min", "max", "sum", "value_count", "avg"],
				"default_metric": "avg"
			}
		}
	}`), &ms)
	if err != nil {
		t.Fatalf("MappingSpec unmarshal failed: %v", err)
	}
	if ms.Size["enabled"] != true {
		t.Fatalf("expected _size.enabled=true, got %+v", ms.Size)
	}
	lkObj := ms.Runtime["user_lookup_obj"]
	if !lkObj.IsLookupRuntime() || lkObj.TargetIndex != "users" || lkObj.InputField != "uid" || lkObj.EffectiveLookupTargetField() != "id" {
		t.Fatalf("unexpected user_lookup_obj: %+v", lkObj)
	}
	if !reflect.DeepEqual(lkObj.LookupFetchFieldNames(), []string{"city", "created_at"}) {
		t.Fatalf("unexpected LookupFetchFieldNames: %v", lkObj.LookupFetchFieldNames())
	}
	lkStr := ms.Runtime["user_lookup_str"]
	if lkStr.EffectiveLookupTargetField() != "id" || !reflect.DeepEqual(lkStr.LookupFetchFieldNames(), []string{"country", "zip"}) {
		t.Fatalf("unexpected user_lookup_str: %+v", lkStr)
	}
	ulProp := ms.Properties["ul"]
	if num, ok := ulProp.NullValue.(json.Number); !ok || num.String() != "17446744073709551615" {
		t.Fatalf("expected exact json.Number(17446744073709551615) for unsigned_long null_value, got %T(%v)", ulProp.NullValue, ulProp.NullValue)
	}
	amProp := ms.Properties["lat_metrics"]
	if amProp.DefaultMetric != "avg" || len(amProp.Metrics) != 5 {
		t.Fatalf("unexpected aggregate_metric_double FieldProperty: %+v", amProp)
	}

	// Strict unmarshal & invalid fetch_fields
	if _, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"lookup","target_index":"u","input_field":"k","target_field":"id","fetch_fields":["a"]}`)); err != nil {
		t.Fatalf("strict lookup FieldProperty unmarshal failed: %v", err)
	}
	for _, badFF := range []string{
		`{"type":"lookup","fetch_fields":"not_array"}`,
		`{"type":"lookup","fetch_fields":[""]}`,
		`{"type":"lookup","fetch_fields":[{}]}`,
		`{"type":"lookup","fetch_fields":[123]}`,
	} {
		var fp FieldProperty
		if err := json.Unmarshal([]byte(badFF), &fp); err == nil {
			t.Fatalf("expected error for invalid fetch_fields %s", badFF)
		}
	}

	// rank_feature positive normal float validation
	var badRF FieldProperty
	_ = json.Unmarshal([]byte(`{"type":"rank_feature","null_value":-3}`), &badRF)
	if _, err := badRF.RankFeatureNullValue(); err == nil || !strings.Contains(err.Error(), "[null_value] must be a positive normal float for field of type [rank_feature]") {
		t.Fatalf("expected exact ES positive normal float error for rank_feature null_value=-3, got %v", err)
	}

	// counted_terms agg unmarshaling
	var ctSR SearchRequest
	if err := json.Unmarshal([]byte(`{"aggs":{"ev":{"counted_terms":{"field":"events"}}}}`), &ctSR); err != nil {
		t.Fatalf("expected counted_terms agg to unmarshal cleanly, got: %v", err)
	}
	if ctSR.Aggs["ev"].CountedTerms == nil || ctSR.Aggs["ev"].CountedTerms.Field != "events" {
		t.Fatalf("unexpected CountedTerms spec: %+v", ctSR.Aggs["ev"].CountedTerms)
	}
}

func TestRound63_ASTHelperAndSerializationCoverage(t *testing.T) {
	// 1. MarshalJSON round-trip for FuzzyEntry, PrefixEntry, WildcardEntry, RegexpEntry, MatchEntry, PhraseEntry
	tBool := true
	entries := []any{
		FuzzyEntry{Value: "quikc", Fuzziness: "AUTO", Boost: 2.5, HasBoost: true, Transpositions: &tBool},
		PrefixEntry{Value: " err", CaseInsensitive: true, Boost: 1.5, HasBoost: true},
		WildcardEntry{Value: "ki*y", CaseInsensitive: true, Boost: 2.0, HasBoost: true},
		RegexpEntry{Value: "s.*y", Flags: "ALL", CaseInsensitive: true, Boost: 3.0, HasBoost: true},
		MatchEntry{Query: "quick fox", Operator: "and", Boost: 1.2, HasBoost: true, Lenient: &tBool},
		PhraseEntry{Query: "quick brown", Slop: 2, Boost: 1.8, HasBoost: true, Lenient: &tBool},
	}
	for i, e := range entries {
		b, err := json.Marshal(e)
		if err != nil || len(b) == 0 {
			t.Fatalf("entry[%d] MarshalJSON failed: %v (%s)", i, err, string(b))
		}
	}

	// 2. AggSpec / TopHits / InnerHits / Pipeline Effective* helpers
	var sr SearchRequest
	err := json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "comments",
				"query": {"query_string": {"query": "/ab\\/cd/ AND (x:1 OR y:2)"}},
				"inner_hits": {
					"stored_fields": "_none_",
					"fields": ["comments.author"],
					"docvalue_fields": ["comments.ts"]
				}
			}
		},
		"aggs": {
			"rt": {"rare_terms": {"field": "tag", "max_doc_count": 2}},
			"adh": {"auto_date_histogram": {"field": "ts", "buckets": 5}},
			"vwh": {"variable_width_histogram": {"field": "price", "buckets": 4}},
			"adj": {"adjacency_matrix": {"filters": {"a": {"term": {"k": "v"}}}, "separator": "|"}},
			"sig": {"significant_terms": {"field": "tag"}},
			"rng": {"date_range": {"field": "ts", "ranges": {"a": {"from": "2024-01-01", "to": 1704153600000}}}},
			"st": {"extended_stats": {"field": "price", "sigma": 3.0}},
			"smp": {"diversified_sampler": {"field": "uid", "shard_size": 50}},
			"ma": {"moving_avg": {"buckets_path": "the_sum", "window": 7}},
			"sd": {"serial_diff": {"buckets_path": "the_sum", "lag": 2}},
			"nm": {"normalize": {"buckets_path": "the_sum", "method": "rescale_0_1"}},
			"pb": {"percentiles_bucket": {"buckets_path": "the_sum", "percents": [50, 95]}},
			"cs": {"cumulative_sum": {"buckets_path": "the_sum"}},
			"esb": {"extended_stats_bucket": {"buckets_path": "h>s", "sigma": 1.5}},
			"miss": {"missing": {"field": "opt"}},
			"th": {
				"top_hits": {
					"from": 2,
					"size": 5,
					"stored_fields": ["_none_", "f1"],
					"fields": ["f2"],
					"docvalue_fields": ["f3"]
				}
			}
		}
	}`), &sr)
	if err != nil {
		t.Fatalf("rich SearchRequest unmarshal failed: %v", err)
	}
	if err := ValidateQueryStringDepth(`/foo\/bar/ + (a:1 AND (b:2))`); err != nil {
		t.Fatalf("ValidateQueryStringDepth with regex failed: %v", err)
	}
	ih := sr.Query.Nested.InnerHits
	if !ih.HasStoredFieldsNone() || len(ih.EffectiveFieldSpecs()) != 2 {
		t.Fatalf("unexpected InnerHits helpers: none=%v specs=%+v", ih.HasStoredFieldsNone(), ih.EffectiveFieldSpecs())
	}
	if sr.Aggs["rt"].RareTerms.EffectiveMaxDocCount() != 2 ||
		sr.Aggs["adh"].AutoDateHistogram.EffectiveBuckets() != 5 ||
		sr.Aggs["vwh"].VariableWidthHistogram.EffectiveBuckets() != 4 ||
		sr.Aggs["adj"].AdjacencyMatrix.EffectiveSeparator() != "|" {
		t.Fatal("unexpected bucket agg Effective* values")
	}
	sigAgg := sr.Aggs["sig"]
	if !sigAgg.IsSignificantTerms() || sigAgg.EffectiveTerms().Field != "tag" {
		t.Fatalf("unexpected sig agg helpers: %+v", sigAgg)
	}
	rngAgg := sr.Aggs["rng"]
	if rngAgg.EffectiveRange() == nil {
		t.Fatal("expected non-nil EffectiveRange")
	}
	stAgg := sr.Aggs["st"]
	if stAgg.EffectiveStats() == nil || stAgg.ExtendedStats.EffectiveSigma() != 3.0 {
		t.Fatal("expected EffectiveStats & EffectiveSigma=3.0")
	}
	smpAgg := sr.Aggs["smp"]
	if smpAgg.EffectiveSampler() == nil {
		t.Fatal("expected EffectiveSampler")
	}
	maAgg := sr.Aggs["ma"]
	if maAgg.EffectiveMovingAvg().EffectivePath() != "the_sum" || maAgg.MovingAvg.EffectiveWindow() != 7 {
		t.Fatal("unexpected MovingAvg EffectivePath/EffectiveWindow")
	}
	if sr.Aggs["sd"].SerialDiff.EffectivePath() != "the_sum" || sr.Aggs["sd"].SerialDiff.EffectiveLag() != 2 {
		t.Fatal("unexpected SerialDiff helpers")
	}
	if sr.Aggs["nm"].Normalize.EffectivePath() != "the_sum" {
		t.Fatal("unexpected Normalize EffectivePath")
	}
	if sr.Aggs["pb"].PercentilesBucket.EffectivePath() != "the_sum" || len(sr.Aggs["pb"].PercentilesBucket.EffectivePercents()) != 2 {
		t.Fatal("unexpected PercentilesBucket helpers")
	}
	csAgg := sr.Aggs["cs"]
	if csAgg.EffectiveCumulative().EffectivePath() != "the_sum" {
		t.Fatal("unexpected CumulativeSum EffectiveCumulative")
	}
	if sr.Aggs["esb"].ExtendedStatsBucket.EffectiveSigma() != 1.5 {
		t.Fatal("unexpected ExtendedStatsBucket EffectiveSigma")
	}
	th := sr.Aggs["th"].TopHits
	if !th.HasStoredFieldsNone() || len(th.EffectiveFieldSpecs()) != 3 || th.EffectiveFrom() != 2 || th.EffectiveSize() != 5 || th.EffectiveFetchLimit() != 7 {
		t.Fatalf("unexpected TopHits helpers: %+v", th)
	}

	// 3. IndexTemplateRequest & FieldProperty helpers + extractExactLargeIntNumber edge cases
	var tmpl IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{
		"index_patterns": ["logs-*"],
		"priority": 100,
		"template": {
			"settings": {"number_of_shards": 1},
			"mappings": {"properties": {"v": {"type": "dense_vector", "dims": 4, "copy_to": ["all_v"]}}},
			"aliases": {"logs_current": {}}
		}
	}`), &tmpl); err != nil {
		t.Fatalf("IndexTemplateRequest unmarshal failed: %v", err)
	}
	if len(tmpl.EffectivePatterns()) != 1 || tmpl.EffectivePriority() != 100 || tmpl.EffectiveMappings() == nil || len(tmpl.EffectiveSettings()) == 0 || len(tmpl.EffectiveAliases()) != 1 {
		t.Fatalf("unexpected IndexTemplateRequest Effective* results: %+v", tmpl)
	}
	vp := tmpl.EffectiveMappings().Properties["v"]
	if vp.EffectiveDims() != 4 || !reflect.DeepEqual(vp.CopyToSlice(), []string{"all_v"}) {
		t.Fatalf("unexpected FieldProperty EffectiveDims/CopyToSlice: %+v", vp)
	}
	if _, ok := extractExactLargeIntNumber(json.RawMessage(`"12345678901234567890"`)); ok {
		t.Fatal("did not expect string literal to match extractExactLargeIntNumber")
	}
	if _, ok := extractExactLargeIntNumber(json.RawMessage(`12345678901234567890abc`)); ok {
		t.Fatal("did not expect invalid digits to match extractExactLargeIntNumber")
	}
}
