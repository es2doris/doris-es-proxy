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
	"strings"
	"testing"
)

func TestSearchRequestUnmarshal_OpenMetadataPayload(t *testing.T) {
	payload := `{
		"from": 0,
		"size": 20,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": {
							"multi_match": {
								"query": "customer_orders",
								"fields": ["name^10", "displayName^8", "description^2"],
								"operator": "and"
							}
						},
						"filter": [
							{"term": {"deleted": false}},
							{"term": {"serviceType": {"value": "BigQuery", "case_insensitive": true}}}
						]
					}
				},
				"functions": [
					{
						"filter": {"term": {"tier.tagFQN": "Tier.Tier1"}},
						"weight": 3.0
					},
					{
						"field_value_factor": {
							"field": "usageSummary.weeklyStats.count",
							"factor": 0.05,
							"modifier": "log1p",
							"missing": 0
						}
					}
				],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}
		},
		"aggs": {
			"serviceType": {"terms": {"field": "serviceType.keyword", "size": 10}},
			"columns_type": {
				"nested": {"path": "columns"},
				"aggs": {
					"by_type": {"terms": {"field": "columns.dataType", "size": 15}}
				}
			}
		},
		"sort": ["_score", {"updatedAt": {"order": "desc"}}]
	}`

	var req SearchRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("failed to unmarshal OpenMetadata search payload: %v", err)
	}
	if req.Size == nil || *req.Size != 20 {
		t.Fatalf("expected size 20, got %+v", req.Size)
	}
	if req.Query == nil || req.Query.FunctionScore == nil {
		t.Fatalf("expected function_score query")
	}
	boolQ := req.Query.FunctionScore.Query.Bool
	if len(boolQ.Must) != 1 || len(boolQ.Filter) != 2 {
		t.Fatalf("unexpected bool clauses: must=%d filter=%d", len(boolQ.Must), len(boolQ.Filter))
	}
	if len(req.EffectiveAggs()) != 2 {
		t.Fatalf("expected 2 aggs, got %d", len(req.EffectiveAggs()))
	}
	if len(req.Sort) != 2 || req.Sort[1].Entry.Field != "updatedAt" || req.Sort[1].Entry.Order != "desc" {
		t.Fatalf("unexpected sort spec: %+v", req.Sort)
	}
}

func TestParseBulkNDJSON(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"index":{"_index":"table_search_index","_id":"doc-1"}}`,
		`{"name":"orders","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}]}`,
		`{"delete":{"_index":"table_search_index","_id":"doc-2"}}`,
		"",
	}, "\n")

	ops, err := ParseBulkNDJSON(strings.NewReader(ndjson), "default_idx")
	if err != nil {
		t.Fatalf("ParseBulkNDJSON failed: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 bulk ops, got %d", len(ops))
	}
	if ops[0].Action != "index" || ops[0].ID != "doc-1" || string(ops[0].Source) != `{"name":"orders","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}]}` {
		t.Fatalf("unexpected first op: %+v", ops[0])
	}
	if ops[1].Action != "delete" || ops[1].ID != "doc-2" {
		t.Fatalf("unexpected second op: %+v", ops[1])
	}
}

func TestASTQueryAndAggVariants(t *testing.T) {
	id1 := NextAutoID()
	id2 := NextAutoID()
	if id1 == "" || id1 == id2 || !strings.HasPrefix(id1, "auto-") {
		t.Fatalf("expected distinct auto- IDs, got %q and %q", id1, id2)
	}

	// Test RangeCond.NormalizedBounds with From/To and IncludeLower/IncludeUpper
	fFalse := false
	fTrue := true
	rc := RangeCond{From: 10, To: 20, IncludeLower: &fFalse, IncludeUpper: &fTrue}
	gt, gte, lt, lte := rc.NormalizedBounds()
	if gt != 10 || gte != nil || lt != nil || lte != 20 {
		t.Fatalf("unexpected NormalizedBounds: gt=%v gte=%v lt=%v lte=%v", gt, gte, lt, lte)
	}
	rc2 := RangeCond{From: 5, To: 15, IncludeLower: &fTrue, IncludeUpper: &fFalse}
	gt2, gte2, lt2, lte2 := rc2.NormalizedBounds()
	if gt2 != nil || gte2 != 5 || lt2 != 15 || lte2 != nil {
		t.Fatalf("unexpected NormalizedBounds rc2: gt=%v gte=%v lt=%v lte=%v", gt2, gte2, lt2, lte2)
	}

	// Test PrefixEntry, WildcardEntry, RegexpEntry, MatchEntry, PhraseEntry (both shorthand and object forms)
	clausesJSON := `{
		"query": {
			"bool": {
				"must": [
					{"prefix": {"svc": "pay"}},
					{"prefix": {"env": {"value": "prod", "case_insensitive": true}}},
					{"wildcard": {"host": "web-*"}},
					{"wildcard": {"region": {"wildcard": "us-*", "case_insensitive": true}}},
					{"wildcard": {"zone": {"value": "az-*", "case_insensitive": false}}},
					{"regexp": {"path": "/api/v[0-9]+/.*"}},
					{"regexp": {"code": {"value": "ERR_[0-9]+"}}},
					{"match": {"title": "quick fox"}},
					{"match": {"subtitle": {"query": "brown dog", "operator": "AND", "boost": 2.5}}},
					{"match_phrase": {"body": "exact phrase"}},
					{"match_phrase": {"summary": {"query": "near phrase", "slop": 2, "boost": 1.5}}},
					{"terms": {"status": ["open", "pending"], "boost": 2.0}}
				]
			}
		},
		"knn": [
			{"field": "vec1", "query_vector": [0.1, 0.2], "k": 5, "filter": {"term": {"ok": true}}},
			{"vec2": {"vector": [0.3, 0.4], "k": 3, "filter": [{"term": {"ok": false}}]}}
		],
		"sort": {"created_at": "desc"},
		"_source": false
	}`
	var sr SearchRequest
	if err := json.Unmarshal([]byte(clausesJSON), &sr); err != nil {
		t.Fatalf("failed to unmarshal clausesJSON: %v", err)
	}
	if len(sr.Query.Bool.Must) != 12 {
		t.Fatalf("expected 12 must clauses, got %d", len(sr.Query.Bool.Must))
	}
	if len(sr.KNN) != 2 || sr.KNN[0].Field != "vec1" || sr.KNN[1].Field != "vec2" || sr.KNN[1].K != 3 {
		t.Fatalf("unexpected KNN slice: %+v", sr.KNN)
	}
	if len(sr.Sort) != 1 || sr.Sort[0].Entry.Field != "created_at" || sr.Sort[0].Entry.Order != "desc" {
		t.Fatalf("unexpected single-object SortSlice: %+v", sr.Sort)
	}
	if sr.Source == nil || !sr.Source.Disabled || sr.Source.Fetch {
		t.Fatalf("expected _source=false to set Disabled=true, got %+v", sr.Source)
	}

	// Test SourceFilter variations ("field", ["f1","f2"], {"includes":..., "excludes":...}, true)
	for _, tc := range []string{`true`, `"only_field"`, `["f1","f2"]`, `{"includes":["a"],"excludes":["b"],"include":["c"],"exclude":["d"]}`} {
		var sf SourceFilter
		if err := json.Unmarshal([]byte(tc), &sf); err != nil {
			t.Fatalf("SourceFilter unmarshal %s failed: %v", tc, err)
		}
	}

	// Test SortSpec variations and MarshalJSON
	for _, sTC := range []string{`"_score"`, `"_doc"`, `{"age":"asc"}`, `{"age":{"order":"desc"}}`} {
		var sp SortSpec
		if err := json.Unmarshal([]byte(sTC), &sp); err != nil {
			t.Fatalf("SortSpec unmarshal %s failed: %v", sTC, err)
		}
		if _, err := json.Marshal(sp); err != nil {
			t.Fatalf("SortSpec marshal failed: %v", err)
		}
	}

	// Test DateHistogramAggSpec.EffectiveIntervalMs across all units
	intervals := map[string]int64{
		"second":  1000,
		"minute":  60 * 1000,
		"hour":    3600 * 1000,
		"day":     86400 * 1000,
		"week":    7 * 86400 * 1000,
		"month":   30 * 86400 * 1000,
		"quarter": 90 * 86400 * 1000,
		"year":    365 * 86400 * 1000,
		"500ms":   500,
		"10s":     10 * 1000,
		"5m":      5 * 60 * 1000,
		"2h":      2 * 3600 * 1000,
		"3d":      3 * 86400 * 1000,
		"2w":      2 * 7 * 86400 * 1000,
		"6M":      6 * 30 * 86400 * 1000,
		"2y":      2 * 365 * 86400 * 1000,
		"unknown": 86400 * 1000,
	}
	for unit, wantMs := range intervals {
		dh := &DateHistogramAggSpec{Interval: unit}
		if got := dh.EffectiveIntervalMs(); got != wantMs {
			t.Fatalf("EffectiveIntervalMs(%q) = %d, want %d", unit, got, wantMs)
		}
	}

	// Test RangeAggBucket.EffectiveKey, PercentilesAggSpec.EffectivePercents, TopHitsAggSpec.EffectiveSize, FieldProperty.EffectiveDims
	if got := (RangeAggBucket{Key: "custom"}).EffectiveKey(); got != "custom" {
		t.Fatalf("expected custom, got %q", got)
	}
	if got := (RangeAggBucket{From: 10, To: 20}).EffectiveKey(); got != "10-20" {
		t.Fatalf("expected 10-20, got %q", got)
	}
	if got := (RangeAggBucket{}).EffectiveKey(); got != "*-*" {
		t.Fatalf("expected *-*, got %q", got)
	}
	if len((&PercentilesAggSpec{}).EffectivePercents()) != 7 {
		t.Fatalf("expected 7 default percentiles")
	}
	bigSize := 500
	if (&TopHitsAggSpec{Size: &bigSize}).EffectiveSize() != 100 {
		t.Fatalf("expected TopHits EffectiveSize capped at 100")
	}
	if (&FieldProperty{Dimension: 768}).EffectiveDims() != 768 {
		t.Fatalf("expected EffectiveDims=768")
	}

	// Test IndexTemplateRequest helpers
	tpl := &IndexTemplateRequest{
		Patterns: []string{"logs-*"},
		Mappings: &MappingSpec{Properties: map[string]FieldProperty{"msg": {Type: "text"}}},
	}
	if len(tpl.EffectivePatterns()) != 1 || tpl.EffectiveMappings() == nil {
		t.Fatalf("unexpected IndexTemplateRequest helpers: %+v", tpl)
	}

	// Unknown query clause must return error
	var badQ Query
	if err := json.Unmarshal([]byte(`{"not_a_real_es_clause": {}}`), &badQ); err == nil {
		t.Fatalf("expected error for unknown query clause")
	}
}

func TestASTRound28ComprehensiveCoverage(t *testing.T) {
	// 1. SearchRequest helpers: EffectiveFieldSpecs, HasStoredFieldsNone, ShouldTrackTotalHits, StoredFieldsSlice
	var nilReq *SearchRequest
	if nilReq.HasStoredFieldsNone() || nilReq.EffectiveFieldSpecs() != nil || !nilReq.ShouldTrackTotalHits() {
		t.Fatalf("unexpected nil SearchRequest helper behavior")
	}
	if StoredFieldsSlice(nil) != nil || len(StoredFieldsSlice("_none_")) != 1 || len(StoredFieldsSlice([]any{"a", "b"})) != 2 || len(StoredFieldsSlice([]string{"x"})) != 1 {
		t.Fatalf("unexpected StoredFieldsSlice results")
	}
	req := &SearchRequest{
		StoredFields:   []any{"_none_", "title"},
		Fields:         []FieldRequestSpec{{Field: "status"}},
		DocvalueFields: []FieldRequestSpec{{Field: "@timestamp", Format: "epoch_millis"}},
	}
	if !req.HasStoredFieldsNone() {
		t.Fatalf("expected HasStoredFieldsNone=true")
	}
	if specs := req.EffectiveFieldSpecs(); len(specs) != 3 {
		t.Fatalf("expected 3 EffectiveFieldSpecs, got %d", len(specs))
	}
	for _, tc := range []struct {
		val  any
		want bool
	}{
		{nil, true},
		{true, true},
		{false, false},
		{"true", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"0.0", false},
		{"-1", false},
		{"100", true},
		{0, false},
		{-5, false},
		{10, true},
		{int64(0), false},
		{int64(50), true},
		{float64(0), false},
		{float64(-1.5), false},
		{float64(25.0), true},
		{json.Number("0"), false},
		{json.Number("0.0"), false},
		{json.Number("-2.5"), false},
		{json.Number("1000"), true},
		{json.Number("10.5"), true},
	} {
		r := &SearchRequest{TrackTotalHits: tc.val}
		if got := r.ShouldTrackTotalHits(); got != tc.want {
			t.Fatalf("ShouldTrackTotalHits(%#v) = %v, want %v", tc.val, got, tc.want)
		}
	}

	// 2. FieldRequestSpec & KNNQuery UnmarshalJSON
	var frs1, frs2 FieldRequestSpec
	if err := json.Unmarshal([]byte(`"host.name"`), &frs1); err != nil || frs1.Field != "host.name" {
		t.Fatalf("FieldRequestSpec string unmarshal failed: %+v (%v)", frs1, err)
	}
	if err := json.Unmarshal([]byte(`{"field":"@timestamp","format":"strict_date"}`), &frs2); err != nil || frs2.Field != "@timestamp" || frs2.Format != "strict_date" {
		t.Fatalf("FieldRequestSpec object unmarshal failed: %+v (%v)", frs2, err)
	}
	var knn1, knn2 KNNQuery
	if err := json.Unmarshal([]byte(`{"field":"vec","query_vector":[0.1,0.2],"k":5,"num_candidates":10}`), &knn1); err != nil || knn1.Field != "vec" || knn1.K != 5 {
		t.Fatalf("KNNQuery standard unmarshal failed: %+v (%v)", knn1, err)
	}
	if err := json.Unmarshal([]byte(`{"embedding":{"vector":[0.5,0.6],"k":3}}`), &knn2); err != nil || knn2.Field != "embedding" || len(knn2.QueryVector) != 2 {
		t.Fatalf("KNNQuery OpenSearch unmarshal failed: %+v (%v)", knn2, err)
	}

	// 3. CollapseSpec, CollapseInnerHits, InnerHitsSpec, RescoreList
	var srCollapse SearchRequest
	collapseJSON := `{
		"collapse": {
			"field": "category",
			"inner_hits": {"name": "top_in_cat", "size": 2, "fields": ["title"], "docvalue_fields": [{"field": "price"}]}
		},
		"rescore": {
			"window_size": 50,
			"query": {"rescore_query": {"match": {"title": "laptop"}}, "query_weight": 1.2, "rescore_query_weight": 2.0, "score_mode": "multiply"}
		}
	}`
	if err := json.Unmarshal([]byte(collapseJSON), &srCollapse); err != nil {
		t.Fatalf("collapse/rescore unmarshal failed: %v", err)
	}
	if srCollapse.Collapse == nil || len(srCollapse.Collapse.InnerHits) != 1 {
		t.Fatalf("expected 1 collapse inner_hits, got %+v", srCollapse.Collapse)
	}
	ih := srCollapse.Collapse.InnerHits[0]
	if ih.EffectiveSize() != 2 || len(ih.EffectiveFieldSpecs()) != 2 {
		t.Fatalf("unexpected InnerHitsSpec helpers: size=%d specs=%v", ih.EffectiveSize(), ih.EffectiveFieldSpecs())
	}
	negSize := -1
	if (&InnerHitsSpec{Size: &negSize}).EffectiveSize() != 0 || (&InnerHitsSpec{}).EffectiveSize() != 3 {
		t.Fatalf("unexpected InnerHitsSpec default/negative EffectiveSize")
	}
	if len(srCollapse.Rescore) != 1 || srCollapse.Rescore[0].WindowSize == nil || *srCollapse.Rescore[0].WindowSize != 50 {
		t.Fatalf("unexpected RescoreList single-object unmarshal: %+v", srCollapse.Rescore)
	}
	var srRescoreArr SearchRequest
	if err := json.Unmarshal([]byte(`{"collapse":{"field":"f","inner_hits":[{"name":"a"},{"name":"b"}]},"rescore":[{"window_size":10,"query":{"rescore_query":{"match_all":{}}}}]}`), &srRescoreArr); err != nil || len(srRescoreArr.Collapse.InnerHits) != 2 || len(srRescoreArr.Rescore) != 1 {
		t.Fatalf("array collapse/rescore unmarshal failed: %v", err)
	}

	// 4. KNNQuery (ES 8/9 standard & OpenSearch field-keyed syntax) and KNNSlice
	var knnStd, knnOS KNNQuery
	if err := json.Unmarshal([]byte(`{"field":"vec","query_vector":[0.1,0.2],"k":5,"num_candidates":10}`), &knnStd); err != nil || knnStd.Field != "vec" || knnStd.K != 5 {
		t.Fatalf("KNNQuery standard unmarshal failed: %+v (%v)", knnStd, err)
	}
	if err := json.Unmarshal([]byte(`{"vec_os":{"vector":[0.3,0.4],"k":3,"num_candidates":8}}`), &knnOS); err != nil || knnOS.Field != "vec_os" || knnOS.K != 3 || len(knnOS.QueryVector) != 2 {
		t.Fatalf("KNNQuery OpenSearch unmarshal failed: %+v (%v)", knnOS, err)
	}
	var srKNN SearchRequest
	if err := json.Unmarshal([]byte(`{"knn":{"field":"vec","query_vector":[1,2],"k":2},"aggs":{"a":{"terms":{"field":"f"}}}}`), &srKNN); err != nil || len(srKNN.KNN) != 1 || len(srKNN.EffectiveAggs()) != 1 {
		t.Fatalf("KNNSlice single-object & EffectiveAggs failed: %v", err)
	}

	// 5. RangeCond NormalizedBounds, ScriptQuery, FuzzyEntry, PrefixEntry, WildcardEntry, RegexpEntry, MatchEntry, PhraseEntry
	var rcQ, sqStrQ, sqObjQ, fzShortQ, fzFullQ, pfShortQ, pfFullQ, wcFullQ, rxFullQ, mShortQ, mFullQ, mpShortQ, mpFullQ Query
	if err := json.Unmarshal([]byte(`{"range":{"age":{"from":18,"to":65,"include_lower":false,"include_upper":true}}}`), &rcQ); err != nil {
		t.Fatalf("RangeCond from/to unmarshal failed: %v", err)
	}
	gt, gte, lt, lte := rcQ.Range["age"].NormalizedBounds()
	if gt == nil || gte != nil || lt != nil || lte == nil {
		t.Fatalf("unexpected NormalizedBounds: gt=%v gte=%v lt=%v lte=%v", gt, gte, lt, lte)
	}
	if err := json.Unmarshal([]byte(`{"script":"doc['a'].value > 1"}`), &sqStrQ); err != nil || sqStrQ.Script == nil {
		t.Fatalf("ScriptQuery string unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"script":{"script":{"source":"doc['a'].value > 1"},"boost":1.5}}`), &sqObjQ); err != nil || sqObjQ.Script == nil || sqObjQ.Script.Boost == nil {
		t.Fatalf("ScriptQuery object unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"fuzzy":{"name":"alice"}}`), &fzShortQ); err != nil || fzShortQ.Fuzzy["name"].Value != "alice" {
		t.Fatalf("FuzzyEntry short unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"fuzzy":{"name":{"value":"alice","fuzziness":"AUTO","boost":2.0}}}`), &fzFullQ); err != nil || fzFullQ.Fuzzy["name"].Boost != 2.0 {
		t.Fatalf("FuzzyEntry full unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"prefix":{"name":"al"}}`), &pfShortQ); err != nil || pfShortQ.Prefix["name"].Value != "al" {
		t.Fatalf("PrefixEntry short unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"prefix":{"name":{"value":"al","case_insensitive":true,"boost":1.5}}}`), &pfFullQ); err != nil || !pfFullQ.Prefix["name"].CaseInsensitive {
		t.Fatalf("PrefixEntry full unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"wildcard":{"name":{"wildcard":"al*","case_insensitive":true,"boost":1.2}}}`), &wcFullQ); err != nil || wcFullQ.Wildcard["name"].Value != "al*" {
		t.Fatalf("WildcardEntry full unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"regexp":{"name":{"value":"al.*","case_insensitive":true,"boost":1.2}}}`), &rxFullQ); err != nil || !rxFullQ.Regexp["name"].CaseInsensitive {
		t.Fatalf("RegexpEntry full unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"match":{"title":"hello world"}}`), &mShortQ); err != nil || mShortQ.Match["title"].Query != "hello world" {
		t.Fatalf("MatchEntry short unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"match":{"title":{"query":"hello world","operator":"AND","boost":2.0,"fuzziness":1}}}`), &mFullQ); err != nil || mFullQ.Match["title"].Operator != "and" {
		t.Fatalf("MatchEntry full unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"match_phrase":{"title":"hello world"}}`), &mpShortQ); err != nil || mpShortQ.MatchPhrase["title"].Query != "hello world" {
		t.Fatalf("PhraseEntry short unmarshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"match_phrase":{"title":{"query":"hello world","slop":2,"boost":1.5}}}`), &mpFullQ); err != nil || mpFullQ.MatchPhrase["title"].Slop != 2 {
		t.Fatalf("PhraseEntry full unmarshal failed: %v", err)
	}

	// 6. CombinedFieldsQuery, QueryString, SimpleQueryString, MultiMatch, TermsQuery (with lookup)
	var cfQ, qsQ, sqsQ, mmQ, tLookupQ Query
	if err := json.Unmarshal([]byte(`{"combined_fields":{"query":"database error","fields":["title^2","body"],"operator":"and","minimum_should_match":2}}`), &cfQ); err != nil || cfQ.CombinedFields == nil {
		t.Fatalf("CombinedFieldsQuery failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"query_string":{"query":"status:active","fields":["title","body"],"default_operator":"AND","fuzziness":"AUTO","minimum_should_match":"75%"}}`), &qsQ); err != nil || qsQ.QueryString == nil {
		t.Fatalf("QueryStringQuery failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"simple_query_string":{"query":"foo + bar","fields":["title"],"flags":"ALL","minimum_should_match":1}}`), &sqsQ); err != nil || sqsQ.SimpleQueryString == nil {
		t.Fatalf("SimpleQueryStringQuery failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"multi_match":{"query":"quick fox","fields":["title^3","body"],"type":"cross_fields","operator":"and","fuzziness":1,"minimum_should_match":"2<-25%"}}`), &mmQ); err != nil || mmQ.MultiMatch == nil {
		t.Fatalf("MultiMatchQuery failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"terms":{"role":{"index":"users","id":"u1","path":"roles"},"boost":1.5}}`), &tLookupQ); err != nil || tLookupQ.Terms == nil || len(tLookupQ.Terms.Lookups) != 1 {
		t.Fatalf("TermsQuery lookup unmarshal failed: %+v (%v)", tLookupQ.Terms, err)
	}
	if _, err := json.Marshal(tLookupQ.Terms); err != nil {
		t.Fatalf("TermsQuery MarshalJSON failed: %v", err)
	}

	// 7. SortSpec legacy multi-key options, _script sort, _geo_distance sort, and round-trip MarshalJSON
	sortCases := []struct {
		raw         string
		wantField   string
		wantOrder   string
		wantMode    string
		wantMissing string
		wantType    string
	}{
		{`{"price": "desc", "mode": "avg", "missing": "_last", "unmapped_type": "long"}`, "price", "desc", "avg", "_last", "long"},
		{`{"rating": {"order": "asc"}, "mode": "max", "missing": 0, "numeric_type": "double"}`, "rating", "asc", "max", "0", "double"},
		{`{"_script": {"type": "number", "order": "desc", "missing": -1, "script": {"source": "doc['a'].value"}}}`, "_script", "desc", "", "-1", "number"},
		{`{"_geo_distance": {"pin.location": [-70, 40], "order": "asc", "unit": "km", "mode": "min"}}`, "_geo_distance", "asc", "min", "", ""},
		{`"_score"`, "_score", "desc", "", "", ""},
		{`"created_at"`, "created_at", "asc", "", "", ""},
	}
	for _, sc := range sortCases {
		var sp SortSpec
		if err := json.Unmarshal([]byte(sc.raw), &sp); err != nil {
			t.Fatalf("SortSpec(%s) unmarshal failed: %v", sc.raw, err)
		}
		if sp.Entry.Field != sc.wantField || sp.Entry.Order != sc.wantOrder || sp.Entry.Mode != sc.wantMode || sp.Entry.Missing != sc.wantMissing || sp.Entry.Type != sc.wantType {
			t.Fatalf("SortSpec(%s) = %+v, want field=%q order=%q mode=%q missing=%q type=%q", sc.raw, sp.Entry, sc.wantField, sc.wantOrder, sc.wantMode, sc.wantMissing, sc.wantType)
		}
		if _, err := json.Marshal(sp); err != nil {
			t.Fatalf("SortSpec(%s) marshal failed: %v", sc.raw, err)
		}
	}
	// Also test scriptless _geo_distance MarshalJSON
	geoNoScript := SortSpec{Entry: SortFieldSpec{Field: "_geo_distance", Order: "desc", Mode: "min", Missing: "_last"}}
	if b, err := json.Marshal(geoNoScript); err != nil || !strings.Contains(string(b), `"order":"desc"`) {
		t.Fatalf("scriptless _geo_distance MarshalJSON failed: %s (%v)", string(b), err)
	}

	// 8. TopMetricsAggSpec, FiltersAggSpec, TopHitsAggSpec, DateHistogramAggSpec (Offset + TimeZone)
	var tmSingle, tmMulti TopMetricsAggSpec
	if err := json.Unmarshal([]byte(`{"metric":{"field":"m1"},"sort":{"ts":"desc"}}`), &tmSingle); err != nil || len(tmSingle.EffectiveMetricFields()) != 1 || tmSingle.EffectiveSize() != 1 {
		t.Fatalf("TopMetricsAggSpec single failed: %+v (%v)", tmSingle, err)
	}
	if err := json.Unmarshal([]byte(`{"metrics":[{"field":"m1"},{"field":"m2"}],"size":5,"sort":[{"ts":"desc"}]}`), &tmMulti); err != nil || len(tmMulti.EffectiveMetricFields()) != 2 || tmMulti.EffectiveSize() != 5 {
		t.Fatalf("TopMetricsAggSpec multi failed: %+v (%v)", tmMulti, err)
	}
	if _, err := json.Marshal(tmMulti); err != nil {
		t.Fatalf("TopMetricsAggSpec MarshalJSON failed: %v", err)
	}
	var fAnon, fNamed FiltersAggSpec
	if err := json.Unmarshal([]byte(`{"filters":[{"term":{"a":"1"}},{"term":{"b":"2"}}],"other_bucket":true}`), &fAnon); err != nil || !fAnon.IsAnonymous || fAnon.EffectiveKeyed() || fAnon.EffectiveOtherBucketKey() != "_other_" {
		t.Fatalf("FiltersAggSpec anonymous failed: %+v (%v)", fAnon, err)
	}
	if _, err := json.Marshal(fAnon); err != nil {
		t.Fatalf("FiltersAggSpec anonymous marshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"filters":{"errors":{"term":{"level":"error"}}},"other_bucket_key":"rest","keyed":true}`), &fNamed); err != nil || fNamed.IsAnonymous || !fNamed.EffectiveKeyed() || fNamed.EffectiveOtherBucketKey() != "rest" {
		t.Fatalf("FiltersAggSpec named failed: %+v (%v)", fNamed, err)
	}
	if _, err := json.Marshal(fNamed); err != nil {
		t.Fatalf("FiltersAggSpec named marshal failed: %v", err)
	}
	dhTz := &DateHistogramAggSpec{FixedInterval: "1h", Offset: "+30m", TimeZone: "-05:00"}
	if dhTz.EffectiveOffsetMs() != 30*60*1000 || dhTz.EffectiveTimeZoneOffsetMs() != -5*3600*1000 {
		t.Fatalf("unexpected DateHistogram offset/timezone: offset=%d tz=%d", dhTz.EffectiveOffsetMs(), dhTz.EffectiveTimeZoneOffsetMs())
	}
	if ParseTimeZoneOffsetMs("+0530") != (5*3600+30*60)*1000 || ParseTimeZoneOffsetMs("+2") != 2*3600*1000 || ParseTimeZoneOffsetMs("America/New_York") == 0 {
		t.Fatalf("unexpected ParseTimeZoneOffsetMs results")
	}

	// 9. SourceFilter & HighlightSpec
	var sfBoolFalse, sfBoolTrue, sfStr, sfArr, sfObj SourceFilter
	_ = json.Unmarshal([]byte(`false`), &sfBoolFalse)
	_ = json.Unmarshal([]byte(`true`), &sfBoolTrue)
	_ = json.Unmarshal([]byte(`"obj.*"`), &sfStr)
	_ = json.Unmarshal([]byte(`["a","b"]`), &sfArr)
	_ = json.Unmarshal([]byte(`{"includes":["a"],"excludes":["b"]}`), &sfObj)
	if !sfBoolFalse.Disabled || sfBoolTrue.Disabled || len(sfStr.Includes) != 1 || len(sfArr.Includes) != 2 || len(sfObj.Excludes) != 1 {
		t.Fatalf("unexpected SourceFilter unmarshal results")
	}
	_, _ = json.Marshal(sfBoolFalse)
	_, _ = json.Marshal(sfBoolTrue)
	_, _ = json.Marshal(sfObj)
}

func TestRound29ASTIdsQueryNumericScalarBoostPhraseFuzzinessAndAggSpecs(t *testing.T) {
	// 1. IdsQuery with numeric array, scalar value, and boost
	var iqArr, iqScalar IdsQuery
	if err := json.Unmarshal([]byte(`{"values":[101, 202, "303"],"boost":2.5}`), &iqArr); err != nil {
		t.Fatalf("IdsQuery numeric array unmarshal failed: %v", err)
	}
	if len(iqArr.Values) != 3 || iqArr.Values[0] != "101" || iqArr.Values[1] != "202" || iqArr.Values[2] != "303" || iqArr.Boost == nil || *iqArr.Boost != 2.5 {
		t.Fatalf("unexpected IdsQuery numeric array: %+v", iqArr)
	}
	if err := json.Unmarshal([]byte(`{"values":42}`), &iqScalar); err != nil || len(iqScalar.Values) != 1 || iqScalar.Values[0] != "42" {
		t.Fatalf("IdsQuery scalar unmarshal failed: %+v (%v)", iqScalar, err)
	}

	// 2. PhraseEntry with Fuzziness
	var pe PhraseEntry
	if err := json.Unmarshal([]byte(`{"query":"quick brown","fuzziness":"AUTO","operator":"AND","boost":1.5}`), &pe); err != nil {
		t.Fatalf("PhraseEntry unmarshal failed: %v", err)
	}
	if pe.Query != "quick brown" || pe.Fuzziness != "AUTO" || pe.Operator != "and" || pe.Boost != 1.5 {
		t.Fatalf("unexpected PhraseEntry: %+v", pe)
	}

	// 3. KNNSlice, IndexTemplateRequest, FieldProperty helpers
	var ksSingle, ksArr KNNSlice
	if err := json.Unmarshal([]byte(`{"field":"vec","query_vector":[1.0,2.0],"k":5}`), &ksSingle); err != nil || len(ksSingle) != 1 {
		t.Fatalf("KNNSlice single unmarshal failed: %+v (%v)", ksSingle, err)
	}
	if err := json.Unmarshal([]byte(`[{"field":"vec","query_vector":[1.0,2.0],"k":5}]`), &ksArr); err != nil || len(ksArr) != 1 {
		t.Fatalf("KNNSlice array unmarshal failed: %+v (%v)", ksArr, err)
	}
	var tmpl IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{"patterns":["logs-*"],"mappings":{"properties":{"vec":{"type":"dense_vector","dimension":128,"copy_to":["all_vecs"]}}}}`), &tmpl); err != nil {
		t.Fatalf("IndexTemplateRequest unmarshal failed: %v", err)
	}
	if len(tmpl.EffectivePatterns()) != 1 || tmpl.EffectiveMappings() == nil || tmpl.EffectiveMappings().Properties["vec"].EffectiveDims() != 128 || len(tmpl.EffectiveMappings().Properties["vec"].CopyToSlice()) != 1 {
		t.Fatalf("unexpected IndexTemplateRequest helpers: %+v", tmpl)
	}

	// 4. FieldRequestSpec, StoredFieldsSlice, RescoreSlice, CollapseInnerHits
	var frs []FieldRequestSpec
	if err := json.Unmarshal([]byte(`["f1", {"field":"f2","format":"epoch_millis"}]`), &frs); err != nil || len(frs) != 2 || frs[1].Format != "epoch_millis" {
		t.Fatalf("[]FieldRequestSpec unmarshal failed: %+v (%v)", frs, err)
	}
	sfsSingle := StoredFieldsSlice("_none_")
	sfsArr := StoredFieldsSlice([]any{"a", "b"})
	if len(sfsSingle) != 1 || len(sfsArr) != 2 {
		t.Fatalf("StoredFieldsSlice failed: %v / %v", sfsSingle, sfsArr)
	}
	var rSlice RescoreSlice
	if err := json.Unmarshal([]byte(`{"window_size":50,"query":{"rescore_query":{"match_all":{}}}}`), &rSlice); err != nil || len(rSlice) != 1 || *rSlice[0].WindowSize != 50 {
		t.Fatalf("RescoreSlice single unmarshal failed: %+v (%v)", rSlice, err)
	}
	var cihSlice CollapseInnerHits
	if err := json.Unmarshal([]byte(`{"name":"top_1","size":1}`), &cihSlice); err != nil || len(cihSlice) != 1 || cihSlice[0].Name != "top_1" {
		t.Fatalf("CollapseInnerHits single unmarshal failed: %+v (%v)", cihSlice, err)
	}

	// 5. RangeCond Java from/to/include_lower/include_upper
	var rc RangeCond
	if err := json.Unmarshal([]byte(`{"from":10,"to":20,"include_lower":true,"include_upper":false}`), &rc); err != nil {
		t.Fatalf("RangeCond from/to unmarshal failed: %v", err)
	}
	_, gte, lt, _ := rc.NormalizedBounds()
	if gte == nil || lt == nil {
		t.Fatalf("expected RangeCond NormalizedBounds GTE=10, LT=20, got %+v", rc)
	}
}

func TestRound30PrefixWildcardRegexpFuzzySortAndPipelineHelpers(t *testing.T) {
	// 1. PrefixEntry: "prefix" key, scalar number/bool, and explicit "boost": 0
	var pfxKey, pfxNum, pfxBool PrefixEntry
	if err := json.Unmarshal([]byte(`{"prefix":"err_","case_insensitive":true,"boost":0}`), &pfxKey); err != nil {
		t.Fatalf("PrefixEntry 'prefix' key unmarshal failed: %v", err)
	}
	if pfxKey.Value != "err_" || !pfxKey.CaseInsensitive || !pfxKey.HasBoost || pfxKey.Boost != 0 {
		t.Fatalf("unexpected PrefixEntry from 'prefix' key: %+v", pfxKey)
	}
	if err := json.Unmarshal([]byte(`123`), &pfxNum); err != nil || pfxNum.Value != "123" || pfxNum.HasBoost {
		t.Fatalf("PrefixEntry scalar number unmarshal failed: %+v (%v)", pfxNum, err)
	}
	if err := json.Unmarshal([]byte(`{"value":true,"boost":2.0}`), &pfxBool); err != nil || pfxBool.Value != "true" || !pfxBool.HasBoost || pfxBool.Boost != 2.0 {
		t.Fatalf("PrefixEntry scalar bool unmarshal failed: %+v (%v)", pfxBool, err)
	}

	// 2. WildcardEntry: scalar number/bool and explicit "boost": 0
	var wcObj, wcScalar WildcardEntry
	if err := json.Unmarshal([]byte(`{"wildcard":"*warn*","case_insensitive":true,"boost":0}`), &wcObj); err != nil {
		t.Fatalf("WildcardEntry unmarshal failed: %v", err)
	}
	if wcObj.Value != "*warn*" || !wcObj.CaseInsensitive || !wcObj.HasBoost || wcObj.Boost != 0 {
		t.Fatalf("unexpected WildcardEntry: %+v", wcObj)
	}
	if err := json.Unmarshal([]byte(`404`), &wcScalar); err != nil || wcScalar.Value != "404" || wcScalar.HasBoost {
		t.Fatalf("WildcardEntry scalar unmarshal failed: %+v (%v)", wcScalar, err)
	}

	// 3. RegexpEntry: "regexp" key, scalar number, and explicit "boost": 0
	var reObj, reScalar RegexpEntry
	if err := json.Unmarshal([]byte(`{"regexp":"err-[0-9]+","case_insensitive":true,"flags":"ALL","boost":0}`), &reObj); err != nil {
		t.Fatalf("RegexpEntry 'regexp' key unmarshal failed: %v", err)
	}
	if reObj.Value != "err-[0-9]+" || !reObj.CaseInsensitive || !reObj.HasBoost || reObj.Boost != 0 {
		t.Fatalf("unexpected RegexpEntry: %+v", reObj)
	}
	if err := json.Unmarshal([]byte(`500`), &reScalar); err != nil || reScalar.Value != "500" || reScalar.HasBoost {
		t.Fatalf("RegexpEntry scalar unmarshal failed: %+v (%v)", reScalar, err)
	}

	// 4. FuzzyEntry: CaseInsensitive
	var fz FuzzyEntry
	if err := json.Unmarshal([]byte(`{"value":"Quick","fuzziness":1,"case_insensitive":true,"boost":1.5}`), &fz); err != nil {
		t.Fatalf("FuzzyEntry unmarshal failed: %v", err)
	}
	if fz.Value != "Quick" || !fz.CaseInsensitive || fz.Boost != 1.5 {
		t.Fatalf("unexpected FuzzyEntry: %+v", fz)
	}

	// 5. DateHistogramAggSpec signed offsets and intervals
	for _, tc := range []struct {
		offset string
		wantMs int64
	}{
		{"-30s", -30000},
		{"+500ms", 500},
		{"-2h", -7200000},
		{"+3d", 259200000},
		{"+1w", 604800000},
	} {
		dh := DateHistogramAggSpec{Offset: tc.offset}
		if got := dh.EffectiveOffsetMs(); got != tc.wantMs {
			t.Fatalf("EffectiveOffsetMs(%q) = %d, want %d", tc.offset, got, tc.wantMs)
		}
	}

	// 6. SortSpec unmarshal/marshal round-trip (_geo_distance, flat options, nested_path/nested_filter)
	var geoSort, nestedSort SortSpec
	if err := json.Unmarshal([]byte(`{"_geo_distance":{"pin.location":{"lat":40.7,"lon":-74.0},"order":"asc","unit":"km"}}`), &geoSort); err != nil {
		t.Fatalf("SortSpec _geo_distance unmarshal failed: %v", err)
	}
	if geoSort.Entry.Field != "_geo_distance" || geoSort.Entry.Script == nil || geoSort.Entry.Order != "asc" {
		t.Fatalf("unexpected geoSort: %+v", geoSort)
	}
	if b, err := json.Marshal(geoSort); err != nil || len(b) == 0 {
		t.Fatalf("SortSpec _geo_distance marshal failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"items.price":{"order":"desc","mode":"max","numeric_type":"double","nested_path":"items","nested_filter":{"term":{"items.active":true}}}}`), &nestedSort); err != nil {
		t.Fatalf("SortSpec nested_path/nested_filter unmarshal failed: %v", err)
	}
	if nestedSort.Entry.Nested == nil || nestedSort.Entry.Nested.Path != "items" || nestedSort.Entry.Nested.Filter == nil || nestedSort.Entry.Type != "double" {
		t.Fatalf("unexpected nestedSort: %+v", nestedSort)
	}
	if b, err := json.Marshal(nestedSort); err != nil || len(b) == 0 {
		t.Fatalf("SortSpec nested marshal failed: %v", err)
	}
}

func TestRound31IndexTemplatePriorityAndEffectiveHelpers(t *testing.T) {
	// 1. Legacy template using "order" and top-level "aliases"
	var legacyTpl IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{
		"index_patterns": ["logs-*"],
		"order": 15,
		"settings": {"number_of_shards": 2},
		"mappings": {"properties": {"host": {"type": "keyword"}}},
		"aliases": {"logs-read": {}}
	}`), &legacyTpl); err != nil {
		t.Fatalf("unmarshal legacyTpl failed: %v", err)
	}
	if legacyTpl.EffectivePriority() != 15 {
		t.Fatalf("expected EffectivePriority() == 15 from legacy order, got %d", legacyTpl.EffectivePriority())
	}
	if len(legacyTpl.EffectiveAliases()) != 1 || legacyTpl.EffectiveSettings()["number_of_shards"] == nil {
		t.Fatalf("unexpected EffectiveAliases/EffectiveSettings on legacyTpl: %+v", legacyTpl)
	}

	// 2. Composable _index_template using "priority", "composed_of", and "template.aliases"
	var compTpl IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{
		"index_patterns": ["logs-prod-*"],
		"priority": 100,
		"composed_of": ["ct-base", "ct-mappings"],
		"template": {
			"settings": {"index.refresh_interval": "5s"},
			"mappings": {"properties": {"service": {"type": "keyword"}}},
			"aliases": {"logs-prod-all": {"is_write_index": true}}
		}
	}`), &compTpl); err != nil {
		t.Fatalf("unmarshal compTpl failed: %v", err)
	}
	if compTpl.EffectivePriority() != 100 || len(compTpl.ComposedOf) != 2 || len(compTpl.EffectiveAliases()) != 1 {
		t.Fatalf("unexpected composable template fields: %+v", compTpl)
	}
}

func TestRound32QueryStringAndFieldPropertyOptions(t *testing.T) {
	var q Query
	if err := json.Unmarshal([]byte(`{
		"query_string": {
			"query": "status:ok",
			"default_field": "status",
			"time_zone": "+09:00",
			"type": "cross_fields",
			"tie_breaker": 0.3,
			"phrase_slop": 2,
			"fuzziness": "AUTO",
			"lenient": true,
			"zero_terms_query": "all",
			"analyze_wildcard": true
		}
	}`), &q); err != nil {
		t.Fatalf("unmarshal QueryStringQuery failed: %v", err)
	}
	if q.QueryString == nil || q.QueryString.TimeZone != "+09:00" || q.QueryString.Type != "cross_fields" || q.QueryString.TieBreaker == nil || *q.QueryString.TieBreaker != 0.3 || q.QueryString.PhraseSlop != 2 || q.QueryString.Fuzziness != "AUTO" || q.QueryString.Lenient == nil || !*q.QueryString.Lenient || q.QueryString.ZeroTermsQuery != "all" {
		t.Fatalf("unexpected QueryStringQuery fields: %+v", q.QueryString)
	}

	var sq Query
	if err := json.Unmarshal([]byte(`{
		"simple_query_string": {
			"query": "alpha beta",
			"fields": ["title^2", "body"],
			"lenient": true,
			"zero_terms_query": "all",
			"analyze_wildcard": true,
			"auto_generate_synonyms_phrase_query": true
		}
	}`), &sq); err != nil {
		t.Fatalf("unmarshal SimpleQueryStringQuery failed: %v", err)
	}
	if sq.SimpleQueryString == nil || sq.SimpleQueryString.Lenient == nil || !*sq.SimpleQueryString.Lenient || sq.SimpleQueryString.ZeroTermsQuery != "all" || sq.SimpleQueryString.AnalyzeWildcard == nil || !*sq.SimpleQueryString.AnalyzeWildcard {
		t.Fatalf("unexpected SimpleQueryStringQuery fields: %+v", sq.SimpleQueryString)
	}

	var mapping MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"price": {
				"type": "scaled_float",
				"scaling_factor": 100,
				"ignore_malformed": true,
				"coerce": false
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal MappingSpec failed: %v", err)
	}
	priceProp := mapping.Properties["price"]
	if priceProp.ScalingFactor != 100 || priceProp.IgnoreMalformed == nil || !*priceProp.IgnoreMalformed || priceProp.Coerce == nil || *priceProp.Coerce {
		t.Fatalf("unexpected FieldProperty options: %+v", priceProp)
	}
}

func TestRound33QueryStringOperatorAndSuggestRequest(t *testing.T) {
	var sr SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "alpha beta",
				"operator": "AND"
			}
		},
		"suggest": {
			"text": "golng",
			"term_sug": {
				"text": "golng",
				"term": {"field": "title", "size": 3, "suggest_mode": "always"}
			},
			"phrase_sug": {
				"phrase": {"field": "title", "size": 2, "highlight": {"pre_tag": "<em>", "post_tag": "</em>"}}
			},
			"comp_sug": {
				"prefix": "go",
				"completion": {"field": "suggest_title", "size": 5, "skip_duplicates": true}
			}
		}
	}`), &sr); err != nil {
		t.Fatalf("unmarshal SearchRequest with suggest failed: %v", err)
	}
	if sr.Query == nil || sr.Query.QueryString == nil || sr.Query.QueryString.Operator != "AND" {
		t.Fatalf("expected QueryString.Operator == 'AND', got %+v", sr.Query)
	}
	if len(sr.Suggest) != 4 || sr.Suggest["text"].Text != "golng" {
		t.Fatalf("expected global suggest text 'golng' and 4 entries, got %+v", sr.Suggest)
	}
	if sr.Suggest["term_sug"].Term == nil || sr.Suggest["term_sug"].Term.Field != "title" || sr.Suggest["term_sug"].Term.Size != 3 {
		t.Fatalf("unexpected term suggest spec: %+v", sr.Suggest["term_sug"])
	}
	if sr.Suggest["phrase_sug"].Phrase == nil || sr.Suggest["phrase_sug"].Phrase.Highlight == nil || sr.Suggest["phrase_sug"].Phrase.Highlight.PreTag != "<em>" {
		t.Fatalf("unexpected phrase suggest spec: %+v", sr.Suggest["phrase_sug"])
	}
	if sr.Suggest["comp_sug"].Completion == nil || !sr.Suggest["comp_sug"].Completion.SkipDuplicates {
		t.Fatalf("unexpected completion suggest spec: %+v", sr.Suggest["comp_sug"])
	}
}

func TestRound34SortSpecTermsCaseInsensitiveAndKNN(t *testing.T) {
	// F3: SortSpec with flat "type" and reserved field names ("mode", "format")
	var sr SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{"weight": "asc", "type": "double", "format": "strict_date"},
			{"mode": {"order": "desc", "missing": "_last"}, "ignore_unmapped": true},
			{"mode": "desc", "missing": "_last"}
		],
		"query": {
			"terms": {
				"status": ["ACTIVE", "Pending"],
				"case_insensitive": true,
				"boost": 1.5
			}
		},
		"knn": [
			{"field": "emb", "vector": [0.1, 0.2, 0.3], "k": 5}
		]
	}`), &sr); err != nil {
		t.Fatalf("unmarshal Round34 SearchRequest failed: %v", err)
	}
	if len(sr.Sort) != 3 {
		t.Fatalf("expected 3 sort specs, got %d", len(sr.Sort))
	}
	if sr.Sort[0].Entry.Field != "weight" || sr.Sort[0].Entry.Order != "asc" || sr.Sort[0].Entry.Type != "double" || sr.Sort[0].Entry.Format != "strict_date" {
		t.Fatalf("unexpected sort[0]: %+v", sr.Sort[0].Entry)
	}
	if sr.Sort[1].Entry.Field != "mode" || sr.Sort[1].Entry.Order != "desc" || sr.Sort[1].Entry.Missing != "_last" {
		t.Fatalf("unexpected sort[1]: %+v", sr.Sort[1].Entry)
	}
	if sr.Sort[2].Entry.Field != "mode" || sr.Sort[2].Entry.Order != "desc" || sr.Sort[2].Entry.Missing != "_last" {
		t.Fatalf("unexpected sort[2]: %+v", sr.Sort[2].Entry)
	}
	// F4: TermsQuery case_insensitive
	if sr.Query == nil || sr.Query.Terms == nil || !sr.Query.Terms.CaseInsensitive || len(sr.Query.Terms.Fields["status"]) != 2 {
		t.Fatalf("unexpected TermsQuery: %+v", sr.Query)
	}
	// F5: KNNQuery flat vector and filter error propagation
	if len(sr.KNN) != 1 || sr.KNN[0].Field != "emb" || len(sr.KNN[0].QueryVector) != 3 {
		t.Fatalf("unexpected KNNQuery: %+v", sr.KNN)
	}
	var badKNN KNNQuery
	err := json.Unmarshal([]byte(`{"field": "emb", "query_vector": [0.1, 0.2], "k": 5, "filter": {"unknown_query_clause": {"x": 1}}}`), &badKNN)
	if err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("expected parsing_exception for invalid KNN filter, got %v", err)
	}
}

func TestRound41FunctionScoreCompositeAndMultiLevelNestedSort(t *testing.T) {
	// F1a: FunctionScoreSpec rejects invalid inner query
	var badFS SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"function_score": {
				"query": {"not_a_real_query": {"x": 1}}
			}
		}
	}`), &badFS); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("expected parsing_exception for invalid function_score.query, got %v", err)
	}

	// F1b: CompositeAggSpec rejects invalid sources and empty sources
	var badCompEmpty SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"comp": {
				"composite": {
					"sources": []
				}
			}
		}
	}`), &badCompEmpty); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("expected parsing_exception for empty composite.sources, got %v", err)
	}
	var badCompType SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"comp": {
				"composite": {
					"sources": "not-an-array"
				}
			}
		}
	}`), &badCompType); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("expected parsing_exception for malformed composite.sources, got %v", err)
	}

	// F14: Multi-level nested sort spec preserves nested.nested chain and DeepestNestedPath
	var sr SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{
				"comments.replies.likes": {
					"order": "desc",
					"nested": {
						"path": "comments",
						"nested": {
							"path": "comments.replies"
						}
					}
				}
			}
		]
	}`), &sr); err != nil {
		t.Fatalf("unmarshal multi-level nested sort failed: %v", err)
	}
	if len(sr.Sort) != 1 || sr.Sort[0].Entry.Nested == nil || sr.Sort[0].Entry.Nested.Nested == nil {
		t.Fatalf("expected nested.nested sort chain, got %+v", sr.Sort)
	}
	if got := sr.Sort[0].Entry.Nested.Nested.Path; got != "comments.replies" {
		t.Fatalf("expected nested.nested.path == 'comments.replies', got %q", got)
	}
}

func TestRound42BoolQueryUnknownKeyAndClauseSliceParsingException(t *testing.T) {
	// F5a: BoolQuery rejects unknown keys inside "bool"
	var badBool SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"filtre": [{"term": {"status": "ok"}}]
			}
		}
	}`), &badBool); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("F5a expected parsing_exception for unknown bool key 'filtre', got %v", err)
	}

	// F5b: unmarshalClauseSlice preserves parsing_exception when a single-object clause is invalid
	var badSingleClause SearchRequest
	err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": {"not_a_real_query": {"x": 1}}
			}
		}
	}`), &badSingleClause)
	if err == nil || !strings.Contains(err.Error(), "parsing_exception") {
		t.Fatalf("F5b expected parsing_exception for invalid single-object bool.must clause, got %v", err)
	}
}

func TestRound43ScriptSortNestedModeStringScriptShorthandsAndTermsBoostValidation(t *testing.T) {
	// F1: _script sort parses mode, nested, and legacy nested_path / nested_filter
	var sr SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{
				"_script": {
					"type": "number",
					"order": "desc",
					"mode": "max",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}}
					},
					"script": {"source": "doc['items.price'].value"}
				}
			},
			{
				"_script": {
					"type": "number",
					"order": "asc",
					"nested_path": "comments",
					"nested_filter": {"term": {"comments.flagged": false}},
					"script": "doc['comments.votes'].value"
				}
			}
		]
	}`), &sr); err != nil {
		t.Fatalf("F1 unmarshal _script sort failed: %v", err)
	}
	if len(sr.Sort) != 2 || sr.Sort[0].Entry.Mode != "max" || sr.Sort[0].Entry.Nested == nil || sr.Sort[0].Entry.Nested.Path != "items" || sr.Sort[0].Entry.Nested.Filter == nil {
		t.Fatalf("F1 unexpected first _script sort entry: %+v", sr.Sort)
	}
	if sr.Sort[1].Entry.Nested == nil || sr.Sort[1].Entry.Nested.Path != "comments" || sr.Sort[1].Entry.Nested.Filter == nil {
		t.Fatalf("F1 unexpected second _script sort legacy nested entry: %+v", sr.Sort[1].Entry)
	}

	// F2: String script shorthands in terms_set.minimum_should_match_script, script_score.script, and script query
	var qReq SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"terms_set": {
							"tags": {
								"terms": ["a", "b", "c"],
								"minimum_should_match_script": "Math.min(params.num_terms, 2)"
							}
						}
					},
					{
						"script_score": {
							"query": {"match_all": {}},
							"script": "_score * 2"
						}
					},
					{
						"script": "doc['x'].value > 5"
					}
				]
			}
		}
	}`), &qReq); err != nil {
		t.Fatalf("F2 unmarshal string script shorthands failed: %v", err)
	}
	must := qReq.Query.Bool.Must
	if len(must) != 3 || must[0].TermsSet["tags"].MinimumShouldMatchScript != "Math.min(params.num_terms, 2)" {
		t.Fatalf("F2 unexpected terms_set minimum_should_match_script: %+v", must)
	}
	if must[1].ScriptScore.Script != "_score * 2" {
		t.Fatalf("F2 unexpected script_score script: %+v", must[1].ScriptScore)
	}
	if must[2].Script.Script != "doc['x'].value > 5" {
		t.Fatalf("F2 unexpected script query shorthand: %+v", must[2].Script)
	}

	// F3: TermsQuery validates boost (rejects negative and non-numeric boost)
	for _, rawTerms := range []string{
		`{"query": {"terms": {"tags": ["a", "b"], "boost": -1}}}`,
		`{"query": {"terms": {"tags": ["a", "b"], "boost": "not_a_number"}}}`,
		`{"query": {"terms": {"tags": ["a", "b"], "boost": true}}}`,
	} {
		var bad SearchRequest
		if err := json.Unmarshal([]byte(rawTerms), &bad); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
			t.Fatalf("F3 expected parsing_exception for %s, got %v", rawTerms, err)
		}
	}
}

func TestRound44ASTBoostValidationAggSpecAndLeafUnknownKeys(t *testing.T) {
	// F1: Negative boost rejected across all query types, map-level boost, and BoostingQuery.NegativeBoost
	for _, badBoostJSON := range []string{
		`{"query": {"term": {"status": "ok", "boost": -1.0}}}`,
		`{"query": {"term": {"status": {"value": "ok", "boost": -1}}}}`,
		`{"query": {"prefix": {"status": {"value": "ok", "boost": -0.5}}}}`,
		`{"query": {"wildcard": {"status": {"value": "ok*", "boost": -2}}}}`,
		`{"query": {"regexp": {"status": {"value": "ok.*", "boost": -1}}}}`,
		`{"query": {"fuzzy": {"status": {"value": "ok", "boost": -1}}}}`,
		`{"query": {"match": {"title": {"query": "hello", "boost": -1}}}}`,
		`{"query": {"match_phrase": {"title": {"query": "hello", "boost": -1}}}}`,
		`{"query": {"range": {"age": {"gte": 1, "boost": -1}}}}`,
		`{"query": {"terms_set": {"tags": {"terms": ["a"], "boost": -1}}}}`,
		`{"query": {"bool": {"must": [{"match_all": {}}], "boost": -1}}}`,
		`{"query": {"dis_max": {"queries": [{"match_all": {}}], "boost": -1}}}`,
		`{"query": {"boosting": {"positive": {"match_all": {}}, "negative": {"match_none": {}}, "negative_boost": -0.5}}}`,
		`{"query": {"boosting": {"positive": {"match_all": {}}, "negative": {"match_none": {}}, "boost": -1}}}`,
		`{"query": {"constant_score": {"filter": {"match_all": {}}, "boost": -1}}}`,
		`{"query": {"exists": {"field": "a", "boost": -1}}}`,
		`{"query": {"ids": {"values": ["1"], "boost": -1}}}`,
		`{"query": {"multi_match": {"query": "x", "boost": -1}}}`,
		`{"query": {"query_string": {"query": "x", "boost": -1}}}`,
		`{"query": {"simple_query_string": {"query": "x", "boost": -1}}}`,
		`{"query": {"nested": {"path": "items", "query": {"match_all": {}}, "boost": -1}}}`,
		`{"query": {"function_score": {"query": {"match_all": {}}, "boost": -1}}}`,
		`{"query": {"script_score": {"query": {"match_all": {}}, "script": "1", "boost": -1}}}`,
		`{"query": {"script": {"script": "true", "boost": -1}}}`,
		`{"query": {"match_all": {"boost": -1}}}`,
	} {
		var bad SearchRequest
		if err := json.Unmarshal([]byte(badBoostJSON), &bad); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
			t.Fatalf("F1 expected parsing_exception for negative boost %s, got %v", badBoostJSON, err)
		}
	}

	// F1: String-encoded float boosts ("boost": "1.5") accepted on RangeCond, FuzzyEntry, TermsSetEntry
	var strBoostReq SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"range": {"age": {"gte": 10, "boost": "1.5"}}},
					{"fuzzy": {"name": {"value": "alice", "boost": "2.5"}}},
					{"terms_set": {"tags": {"terms": ["a"], "minimum_should_match": 1, "boost": "3.5"}}}
				]
			}
		}
	}`), &strBoostReq); err != nil {
		t.Fatalf("F1 expected string-encoded boost to unmarshal cleanly: %v", err)
	}
	mustClauses := strBoostReq.Query.Bool.Must
	if mustClauses[0].Range["age"].Boost == nil || *mustClauses[0].Range["age"].Boost != 1.5 ||
		mustClauses[1].Fuzzy["name"].Boost != 2.5 ||
		mustClauses[2].TermsSet["tags"].Boost == nil || *mustClauses[2].TermsSet["tags"].Boost != 3.5 {
		t.Fatalf("F1 unexpected parsed string boosts: %+v", mustClauses)
	}

	// F2: AggSpec rejects unknown agg types, empty agg types, and multiple agg types
	for _, badAggJSON := range []string{
		`{"aggs": {"a": {"unknown_agg_type": {"field": "x"}}}}`,
		`{"aggs": {"a": {}}}`,
		`{"aggs": {"a": {"aggs": {"sub": {"avg": {"field": "x"}}}}}}`,
		`{"aggs": {"a": {"avg": {"field": "x"}, "sum": {"field": "x"}}}}`,
	} {
		var bad SearchRequest
		if err := json.Unmarshal([]byte(badAggJSON), &bad); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
			t.Fatalf("F2 expected parsing_exception for invalid agg %s, got %v", badAggJSON, err)
		}
	}

	// F3: Unknown keys and missing required value/query rejected inside leaf queries
	for _, badLeafJSON := range []string{
		`{"query": {"term": {"status": {"value": "ok", "bogus": 1}}}}`,
		`{"query": {"term": {"status": {"query": "ok"}}}}`,
		`{"query": {"prefix": {"status": {"value": "ok", "bogus": 1}}}}`,
		`{"query": {"wildcard": {"status": {"value": "ok*", "bogus": 1}}}}`,
		`{"query": {"regexp": {"status": {"value": "ok.*", "bogus": 1}}}}`,
		`{"query": {"fuzzy": {"status": {"value": "ok", "bogus": 1}}}}`,
		`{"query": {"match": {"title": {"query": "hi", "bogus": 1}}}}`,
		`{"query": {"match": {"title": {"value": "hi"}}}}`,
		`{"query": {"match_phrase": {"title": {"query": "hi", "bogus": 1}}}}`,
		`{"query": {"range": {"age": {"greater_than": 18}}}}`,
		`{"query": {"terms_set": {"tags": {"terms": ["a"], "bogus": 1}}}}`,
	} {
		var bad SearchRequest
		if err := json.Unmarshal([]byte(badLeafJSON), &bad); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
			t.Fatalf("F3 expected parsing_exception for invalid leaf query %s, got %v", badLeafJSON, err)
		}
	}

	// F11: BoostingQuery preserves explicit negative_boost: 0
	var bqZero SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"boosting": {"positive": {"match_all": {}}, "negative": {"match_all": {}}, "negative_boost": 0}}}`), &bqZero); err != nil {
		t.Fatalf("F11 unmarshal boosting negative_boost:0 failed: %v", err)
	}
	if bqZero.Query.Boosting.EffectiveNegativeBoost() != 0 {
		t.Fatalf("F11 expected EffectiveNegativeBoost() == 0, got %v", bqZero.Query.Boosting.EffectiveNegativeBoost())
	}
}

func TestRound45ASTValidationSortSuggestAndRuntimeAggs(t *testing.T) {
	// F1: Query-DSL leaf validation rejects unknown keys & invalid values
	for _, badLeaf := range []string{
		`{"query": {"multi_match": {"query": "hi", "fields": ["title"], "bogus": 1}}}`,
		`{"query": {"query_string": {"query": "hi", "bogus": 1}}}`,
		`{"query": {"simple_query_string": {"query": "hi", "bogus": 1}}}`,
		`{"query": {"combined_fields": {"query": "hi", "fields": ["title"], "bogus": 1}}}`,
		`{"query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "1"}, "bogus": 1}}}`,
		`{"query": {"script_score": {"query": {"match_all": {}}}}}`,
		`{"query": {"match_phrase_prefix": {"title": {"query": "hi", "bogus": 1}}}}`,
		`{"query": {"match_bool_prefix": {"title": {"query": "hi", "bogus": 1}}}}`,
		`{"query": {"bool": {"must": [{"match_all": {}}], "bogus": 1}}}`,
		`{"query": {"script": {"script": {"source": "1"}, "bogus": 1}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(badLeaf), &req); err == nil || !strings.Contains(err.Error(), "parsing_exception") {
			t.Fatalf("F1 expected parsing_exception for %s, got %v", badLeaf, err)
		}
	}

	// F2: Aggregation validation rejects unknown agg types, empty agg definitions, and multiple agg types
	for _, badAgg := range []string{
		`{"aggs": {"a": {"unknown_agg_type": {"field": "status"}}}}`,
		`{"aggs": {"a": {}}}`,
		`{"aggs": {"a": {"terms": {"field": "status"}, "avg": {"field": "age"}}}}`,
		`{"aggs": {"a": {"composite": {"sources": []}}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(badAgg), &req); err == nil {
			t.Fatalf("F2 expected error for %s, got nil", badAgg)
		}
	}

	// Valid _geo_distance sort and nested filter/max_children parse cleanly
	var validSortReq SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{"_geo_distance": {"pin.location": {"lat": 40, "lon": -70}, "order": "asc", "unit": "km"}},
			{"items.price": {"order": "desc", "mode": "avg", "nested": {"path": "items", "max_children": 3, "filter": {"term": {"items.active": true}}}}}
		]
	}`), &validSortReq); err != nil {
		t.Fatalf("F3/F14 valid sort failed: %v", err)
	}
	if len(validSortReq.Sort) != 2 || validSortReq.Sort[0].Entry.Field != "_geo_distance" || validSortReq.Sort[1].Entry.Nested == nil || validSortReq.Sort[1].Entry.Nested.MaxChildren == nil || *validSortReq.Sort[1].Entry.Nested.MaxChildren != 3 {
		t.Fatalf("F3/F14 unexpected parsed sort: %+v", validSortReq.Sort)
	}

	// F5 & F18 & F20: Suggest, RareTerms, AutoDateHistogram, VariableWidthHistogram, WeightedAvg, MAD, Geo, Matrix, TTest aggs parse cleanly
	var fullAggReq SearchRequest
	if err := json.Unmarshal([]byte(`{
		"suggest": {
			"text": "devloper",
			"my_term": {"term": {"field": "title", "size": 3}},
			"my_phrase": {"phrase": {"field": "title"}},
			"my_comp": {"prefix": "dev", "completion": {"field": "suggest"}}
		},
		"aggs": {
			"rt": {"rare_terms": {"field": "tag", "max_doc_count": 2}},
			"adh": {"auto_date_histogram": {"field": "ts", "buckets": 5}},
			"vwh": {"variable_width_histogram": {"field": "price", "buckets": 3}},
			"wavg": {"weighted_avg": {"value": {"field": "grade"}, "weight": {"field": "credits"}}},
			"mad": {"median_absolute_deviation": {"field": "latency"}},
			"gb": {"geo_bounds": {"field": "loc"}},
			"gc": {"geo_centroid": {"field": "loc"}},
			"gd": {"geo_distance": {"field": "loc", "origin": "40,-70", "ranges": [{"to": 100}]}},
			"gh": {"geohash_grid": {"field": "loc", "precision": 4}},
			"gt": {"geotile_grid": {"field": "loc", "precision": 6}},
			"am": {"adjacency_matrix": {"filters": {"a": {"term": {"tag": "a"}}, "b": {"term": {"tag": "b"}}}}},
			"ms": {"matrix_stats": {"fields": ["price", "latency"]}},
			"tt": {"t_test": {"a": {"field": "price"}, "b": {"field": "latency"}, "type": "paired"}}
		}
	}`), &fullAggReq); err != nil {
		t.Fatalf("F5/F18/F20 unmarshal failed: %v", err)
	}
	if len(fullAggReq.Suggest) != 4 || fullAggReq.Suggest["text"].Text != "devloper" || fullAggReq.Suggest["my_term"].Term == nil {
		t.Fatalf("F5 unexpected suggest parsed: %+v", fullAggReq.Suggest)
	}
	if len(fullAggReq.Aggs) != 13 {
		t.Fatalf("F18/F20 expected 13 aggs, got %d", len(fullAggReq.Aggs))
	}
}

func TestRound46GeoQueriesBoolMatchDisMaxAndBulkMeta(t *testing.T) {
	// F1: geo_distance query parsing (map, array [lon,lat], string "lat,lon", WKT, geohash) and error validation
	for _, validGD := range []string{
		`{"query": {"geo_distance": {"distance": "15km", "loc": {"lat": 40.7128, "lon": -74.0060}}}}`,
		`{"query": {"geo_distance": {"distance": "500m", "loc": [-74.0060, 40.7128], "distance_type": "arc", "validation_method": "STRICT", "_name": "gd1", "boost": 2.0}}}`,
		`{"query": {"geo_distance": {"distance": 1000, "unit": "m", "loc": "40.7128,-74.0060"}}}`,
		`{"query": {"geo_distance": {"distance": "2mi", "loc": "POINT (-74.0060 40.7128)"}}}`,
		`{"query": {"geo_distance": {"distance": "10km", "loc": "dr5regw3pg6f"}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(validGD), &req); err != nil {
			t.Fatalf("F1 expected valid geo_distance for %s, got %v", validGD, err)
		}
		if req.Query == nil || req.Query.GeoDistance == nil || req.Query.GeoDistance.DistanceMeters <= 0 {
			t.Fatalf("F1 unexpected parsed GeoDistance: %+v", req.Query)
		}
		if _, err := json.Marshal(req.Query.GeoDistance); err != nil {
			t.Fatalf("F1 GeoDistance.MarshalJSON failed: %v", err)
		}
	}
	for _, u := range []any{10, int64(20), float64(30.5), json.Number("40"), "5yd", "10ft", "12in", "2nmi", "100cm", "1000mm"} {
		if _, m, err := ParseGeoDistanceMeters(u); err != nil || m <= 0 {
			t.Fatalf("F1 ParseGeoDistanceMeters(%v) failed: m=%v err=%v", u, m, err)
		}
	}
	for _, badGD := range []string{
		`{"query": {"geo_distance": {"loc": {"lat": 40, "lon": -74}}}}`,
		`{"query": {"geo_distance": {"distance": "-5km", "loc": {"lat": 40, "lon": -74}}}}`,
		`{"query": {"geo_distance": {"distance": "5lightyears", "loc": {"lat": 40, "lon": -74}}}}`,
		`{"query": {"geo_distance": {"distance": "5km"}}}`,
		`{"query": {"geo_distance": {"distance": "5km", "loc": {"lat": 95, "lon": -74}}}}`,
		`{"query": {"geo_distance": {"distance": "5km", "loc": {"lat": 40, "lon": -74}, "distance_type": "bogus"}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(badGD), &req); err == nil {
			t.Fatalf("F1 expected error for invalid geo_distance %s", badGD)
		}
	}

	// F2: geo_bounding_box query parsing (top_left/bottom_right, top_right/bottom_left, wkt, top/left/bottom/right)
	for _, validBB := range []string{
		`{"query": {"geo_bounding_box": {"loc": {"top_left": {"lat": 42.0, "lon": -75.0}, "bottom_right": {"lat": 40.0, "lon": -72.0}}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top_right": [-72.0, 42.0], "bottom_left": [-75.0, 40.0]}, "type": "indexed"}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top": 42.0, "left": -75.0, "bottom": 40.0, "right": -72.0}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"wkt": "BBOX (-75.0, -72.0, 42.0, 40.0)"}}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(validBB), &req); err != nil {
			t.Fatalf("F2 expected valid geo_bounding_box for %s, got %v", validBB, err)
		}
		if req.Query == nil || req.Query.GeoBoundingBox == nil || req.Query.GeoBoundingBox.Top != 42.0 {
			t.Fatalf("F2 unexpected parsed GeoBoundingBox: %+v", req.Query)
		}
		if _, err := json.Marshal(req.Query.GeoBoundingBox); err != nil {
			t.Fatalf("F2 GeoBoundingBox.MarshalJSON failed: %v", err)
		}
	}
	for _, badBB := range []string{
		`{"query": {"geo_bounding_box": {"loc": {"top_left": {"lat": 40.0, "lon": -75.0}, "bottom_right": {"lat": 42.0, "lon": -72.0}}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top_left": {"lat": 42.0, "lon": -75.0}}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top_right": {"lat": 42.0, "lon": -72.0}}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"wkt": "INVALID"}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top": 42.0, "left": -75.0, "bottom": 40.0, "extra": 1}}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top_left": {"lat": 42.0, "lon": -75.0}, "bottom_right": {"lat": 40.0, "lon": -72.0}}, "type": "bogus"}}}`,
		`{"query": {"geo_bounding_box": {"loc": {"top_left": {"lat": 42.0, "lon": -75.0}, "bottom_right": {"lat": 40.0, "lon": -72.0}}, "validation_method": "bogus"}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(badBB), &req); err == nil {
			t.Fatalf("F2 expected error for invalid geo_bounding_box %s", badBB)
		}
	}
	var coerceBB SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"geo_bounding_box": {"type": {"top_left": {"lat": 40.0, "lon": -75.0}, "bottom_right": {"lat": 42.0, "lon": -72.0}}, "validation_method": "COERCE", "boost": 1.5, "_name": "bb1", "ignore_unmapped": true}}}`), &coerceBB); err != nil {
		t.Fatalf("F2 coerce geo_bounding_box failed: %v", err)
	}
	if _, err := json.Marshal(coerceBB.Query.GeoBoundingBox); err != nil {
		t.Fatalf("F2 MarshalJSON failed: %v", err)
	}

	// F3: boolean & numeric query values in match, multi_match, combined_fields, and decay functions
	var reqF3 SearchRequest
	if err := json.Unmarshal([]byte(`{
		"version": "true",
		"seq_no_primary_term": true,
		"explain": true,
		"indices_boost": [{"idx_a": 2.5}, {"idx_b": 0.5}],
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [
							{"match": {"active": true}},
							{"match": {"flag": {"query": false}}},
							{"multi_match": {"query": true, "fields": ["active"]}},
							{"combined_fields": {"query": 42, "fields": ["title"]}}
						]
					}
				},
				"gauss": {
					"loc": {"origin": "40.7,-74.0", "scale": "5km", "offset": "1km", "decay": 0.5},
					"multi_value_mode": "min"
				}
			}
		}
	}`), &reqF3); err != nil {
		t.Fatalf("F3/F22 unmarshal failed: %v", err)
	}
	if !reqF3.Version || !reqF3.SeqNoPrimaryTerm || !reqF3.Explain || reqF3.IndicesBoost["idx_a"] != 2.5 {
		t.Fatalf("F22 unexpected SearchRequest flags/indices_boost: %+v", reqF3)
	}
	if reqF3.Query.FunctionScore.Gauss == nil || reqF3.Query.FunctionScore.Gauss.Field != "loc" || reqF3.Query.FunctionScore.Gauss.MultiValueMode != "min" {
		t.Fatalf("F3/F10 unexpected DecayFunctionSpec: %+v", reqF3.Query.FunctionScore.Gauss)
	}

	// F4: dis_max validation rejects empty queries and negative/ >1.0 tie_breaker
	for _, badDM := range []string{
		`{"query": {"dis_max": {"queries": []}}}`,
		`{"query": {"dis_max": {"queries": [{"match_all": {}}], "tie_breaker": -0.1}}}`,
		`{"query": {"dis_max": {"queries": [{"match_all": {}}], "tie_breaker": 1.5}}}`,
	} {
		var req SearchRequest
		if err := json.Unmarshal([]byte(badDM), &req); err == nil {
			t.Fatalf("F4 expected error for invalid dis_max %s", badDM)
		}
	}

	// F33 & F34: ParseBulkNDJSON with require_alias, doc_as_upsert, detect_noop, _source, and auto-generated ID
	ops, err := ParseBulkNDJSON(strings.NewReader(
		"{\"index\":{\"_index\":\"my_alias\",\"require_alias\":true}}\n"+
			"{\"title\":\"auto id doc\"}\n"+
			"{\"update\":{\"_index\":\"my_alias\",\"_id\":\"1\",\"require_alias\":\"true\",\"doc_as_upsert\":true,\"detect_noop\":false,\"_source\":[\"title\"]}}\n"+
			"{\"doc\":{\"title\":\"updated\"}}\n",
	), "")
	if err != nil || len(ops) != 2 {
		t.Fatalf("F33/F34 ParseBulkNDJSON failed: len=%d err=%v", len(ops), err)
	}
	if ops[0].RequireAlias == nil || !*ops[0].RequireAlias || !ops[0].AutoGeneratedID || ops[0].ID == "" {
		t.Fatalf("F34 expected RequireAlias=true and AutoGeneratedID=true on ops[0], got %+v", ops[0])
	}
	if ops[1].RequireAlias == nil || !*ops[1].RequireAlias || ops[1].DocAsUpsert == nil || !*ops[1].DocAsUpsert || ops[1].DetectNoop == nil || *ops[1].DetectNoop || ops[1].SourceFilter == nil || len(ops[1].SourceFilter.Includes) != 1 {
		t.Fatalf("F33 expected action-level update options parsed on ops[1], got %+v", ops[1])
	}
}

func TestRound47ASTSpecCompliance(t *testing.T) {
	// F5: RangeCond.Relation parsing and validation
	for _, rel := range []string{"intersects", "CONTAINS", "Within"} {
		var q Query
		raw := `{"range": {"age_range": {"gte": 10, "lte": 20, "relation": "` + rel + `"}}}`
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F5 expected valid range relation %q, got err: %v", rel, err)
		}
		if q.Range["age_range"].Relation != strings.ToUpper(rel) {
			t.Fatalf("F5 expected normalized relation %s, got %s", strings.ToUpper(rel), q.Range["age_range"].Relation)
		}
	}
	var badRel Query
	if err := json.Unmarshal([]byte(`{"range": {"age_range": {"gte": 10, "lte": 20, "relation": "INVALID_REL"}}}`), &badRel); err == nil {
		t.Fatalf("F5 expected parsing_exception for invalid range relation")
	}

	// F7: MappingSpec and FieldProperty metadata & dynamic detection settings
	var ms MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_meta": {"version": "1.0"},
		"_source": {"enabled": true},
		"date_detection": false,
		"numeric_detection": true,
		"dynamic_date_formats": ["yyyy/MM/dd"],
		"dynamic_templates": [{"strings_as_kw": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
		"properties": {
			"title": {
				"type": "text",
				"meta": {"unit": "words"},
				"index_prefixes": {"min_chars": 2, "max_chars": 5},
				"index_phrases": true,
				"store": true,
				"time_zone": "+02:00",
				"split_queries_on_whitespace": true
			}
		}
	}`), &ms); err != nil {
		t.Fatalf("F7 MappingSpec unmarshal failed: %v", err)
	}
	if ms.Meta["version"] != "1.0" || ms.DateDetection == nil || *ms.DateDetection || ms.NumericDetection == nil || !*ms.NumericDetection || len(ms.DynamicTemplates) != 1 || len(ms.DynamicDateFormats) != 1 {
		t.Fatalf("F7 MappingSpec fields not preserved: %+v", ms)
	}
	tp := ms.Properties["title"]
	if tp.Meta["unit"] != "words" || tp.IndexPrefixes["min_chars"] != float64(2) || tp.IndexPhrases == nil || !*tp.IndexPhrases || tp.Store == nil || !*tp.Store || tp.TimeZone != "+02:00" || tp.SplitQueriesOnWhitespace == nil || !*tp.SplitQueriesOnWhitespace {
		t.Fatalf("F7 FieldProperty fields not preserved: %+v", tp)
	}

	// F10 & F11: PhraseEntry and FuzzyEntry parameters
	var qPhraseFuzzy Query
	if err := json.Unmarshal([]byte(`{
		"bool": {
			"must": [
				{"match_phrase": {"title": {"query": "quick fox", "slop": 2, "zero_terms_query": "all", "auto_generate_synonyms_phrase_query": true}}},
				{"match_bool_prefix": {"title": {"query": "quick f", "fuzziness": "AUTO", "prefix_length": 1, "max_expansions": 25, "fuzzy_transpositions": false, "fuzzy_rewrite": "constant_score", "lenient": true}}},
				{"fuzzy": {"title": {"value": "quikc", "fuzziness": 2, "prefix_length": 2, "max_expansions": 30, "transpositions": false, "rewrite": "constant_score"}}}
			]
		}
	}`), &qPhraseFuzzy); err != nil {
		t.Fatalf("F10/F11 unmarshal failed: %v", err)
	}
	mbp := qPhraseFuzzy.Bool.Must[1].MatchBoolPrefix["title"]
	if mbp.PrefixLength != 1 || mbp.MaxExpansions != 25 || mbp.FuzzyTranspositions == nil || *mbp.FuzzyTranspositions || mbp.FuzzyRewrite != "constant_score" || mbp.Lenient == nil || !*mbp.Lenient {
		t.Fatalf("F10 PhraseEntry fields not preserved: %+v", mbp)
	}
	fe := qPhraseFuzzy.Bool.Must[2].Fuzzy["title"]
	if fe.PrefixLength != 2 || fe.MaxExpansions != 30 || fe.Transpositions == nil || *fe.Transpositions || fe.Rewrite != "constant_score" {
		t.Fatalf("F11 FuzzyEntry fields not preserved: %+v", fe)
	}

	// F12: Additional Query DSL clauses
	f12Clauses := []string{
		`{"geo_polygon": {"loc": {"points": [{"lat": 40, "lon": -70}, {"lat": 41, "lon": -71}, {"lat": 39, "lon": -72}]}}}`,
		`{"geo_shape": {"loc": {"shape": {"type": "envelope", "coordinates": [[-75.0, 41.0], [-73.0, 40.0]]}, "relation": "WITHIN"}}}`,
		`{"wrapper": {"query": "eyJtYXRjaF9hbGwiOnt9fQ=="}}`,
		`{"pinned": {"ids": ["1", "2"], "organic": {"match_all": {}}}}`,
		`{"more_like_this": {"fields": ["title"], "like": "quick brown fox", "min_term_freq": 1}}`,
		`{"intervals": {"title": {"all_of": {"ordered": true, "intervals": [{"match": {"query": "quick"}}, {"prefix": {"prefix": "fo"}}]}}}}`,
		`{"span_term": {"title": {"value": "quick", "boost": 2.0}}}`,
		`{"span_near": {"clauses": [{"span_term": {"title": "quick"}}, {"span_term": {"title": "fox"}}], "slop": 2, "in_order": true}}`,
		`{"span_or": {"clauses": [{"span_term": {"title": "quick"}}, {"span_term": {"title": "lazy"}}]}}`,
		`{"span_not": {"include": {"span_term": {"title": "quick"}}, "exclude": {"span_term": {"title": "brown"}}}}`,
		`{"span_first": {"match": {"span_term": {"title": "quick"}}, "end": 3}}`,
		`{"span_multi": {"match": {"prefix": {"title": {"value": "qu"}}}}}`,
		`{"span_containing": {"little": {"span_term": {"title": "fox"}}, "big": {"span_near": {"clauses": [{"span_term": {"title": "quick"}}, {"span_term": {"title": "brown"}}], "slop": 5}}}}`,
		`{"span_within": {"little": {"span_term": {"title": "fox"}}, "big": {"span_near": {"clauses": [{"span_term": {"title": "quick"}}, {"span_term": {"title": "brown"}}], "slop": 5}}}}`,
		`{"field_masking_span": {"query": {"span_term": {"title": "quick"}}, "field": "body"}}`,
		`{"rank_feature": {"field": "pagerank", "saturation": {"pivot": 8}}}`,
		`{"distance_feature": {"field": "created_at", "origin": "now", "pivot": "7d"}}`,
		`{"has_child": {"type": "child_doc", "query": {"match_all": {}}, "score_mode": "max"}}`,
		`{"has_parent": {"parent_type": "parent_doc", "query": {"match_all": {}}, "score": true}}`,
		`{"parent_id": {"type": "child_doc", "id": "parent-1"}}`,
		`{"percolate": {"field": "query", "document": {"title": "quick fox"}}}`,
	}
	for _, raw := range f12Clauses {
		var q Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F12 failed to unmarshal %s: %v", raw, err)
		}
	}

	// Additional F12 options and error-branch coverage
	f12ExtendedValid := []string{
		`{"geo_polygon": {"validation_method": "COERCE", "boost": 1.5, "_name": "gp", "ignore_unmapped": true, "loc": {"points": [{"lat": 40, "lon": -70}, {"lat": 41, "lon": -71}, {"lat": 39, "lon": -72}]}}}`,
		`{"geo_shape": {"boost": 1.2, "_name": "gs", "ignore_unmapped": true, "loc": {"indexed_shape": {"id": "1", "index": "shapes"}}}}`,
		`{"wrapper": {"query": "eyJtYXRjaF9hbGwiOnt9fQ==", "boost": 2.0, "_name": "w"}}`,
		`{"pinned": {"docs": [{"_index": "idx", "_id": "1"}], "organic": {"match_all": {}}, "boost": 1.5, "_name": "p"}}`,
		`{"more_like_this": {"fields": ["title"], "like": ["text", {"_id": "1"}], "unlike": "bad", "stop_words": ["the"], "boost": 1.5, "_name": "m"}}`,
		`{"intervals": {"title": {"any_of": {"intervals": [{"wildcard": {"pattern": "qu*"}}, {"fuzzy": {"term": "fox"}}]}, "boost": 1.5, "_name": "iv"}}}`,
		`{"rank_feature": {"field": "pagerank", "log": {"scaling_factor": 2.0}, "boost": 1.5, "_name": "rf"}}`,
		`{"rank_feature": {"field": "pagerank", "sigmoid": {"pivot": 5.0, "exponent": 0.6}}}`,
		`{"rank_feature": {"field": "pagerank", "linear": {}}}`,
		`{"distance_feature": {"field": "loc", "origin": [40.0, -70.0], "pivot": "1000m", "boost": 1.5, "_name": "df"}}`,
		`{"has_child": {"type": "c", "query": {"match_all": {}}, "min_children": 1, "max_children": 5, "ignore_unmapped": true, "boost": 1.2, "_name": "hc"}}`,
		`{"has_parent": {"parent_type": "p", "query": {"match_all": {}}, "ignore_unmapped": true, "boost": 1.2, "_name": "hp"}}`,
		`{"parent_id": {"type": "c", "id": 42, "ignore_unmapped": true, "boost": 1.2, "_name": "pi"}}`,
		`{"percolate": {"field": "query", "documents": [{"title": "a"}], "boost": 1.2, "_name": "pc"}}`,
	}
	for _, raw := range f12ExtendedValid {
		var q Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F12 extended valid failed for %s: %v", raw, err)
		}
	}
	f12Invalid := []string{
		`{"geo_polygon": {"validation_method": "BAD", "loc": {"points": [{"lat": 40, "lon": -70}, {"lat": 41, "lon": -71}, {"lat": 39, "lon": -72}]}}}`,
		`{"geo_polygon": {"loc": {"points": [{"lat": 40, "lon": -70}]}}}`,
		`{"geo_shape": {"loc": {"shape": {"type": "point"}, "relation": "BAD_REL"}}}`,
		`{"geo_shape": {"loc": {}}}`,
		`{"wrapper": {"query": "!!!not_base64!!!"}}`,
		`{"wrapper": {"unknown": 1}}`,
		`{"pinned": {"ids": ["1"]}}`,
		`{"pinned": {"organic": {"match_all": {}}}}`,
		`{"more_like_this": {"fields": ["title"]}}`,
		`{"intervals": {"title": {}}}`,
		`{"rank_feature": {}}`,
		`{"rank_feature": {"field": "f", "unknown": 1}}`,
		`{"distance_feature": {"field": "f", "origin": "now"}}`,
		`{"has_child": {"type": "c"}}`,
		`{"has_parent": {"parent_type": "p"}}`,
		`{"parent_id": {"type": "c"}}`,
		`{"percolate": {}}`,
	}
	for _, raw := range f12Invalid {
		var q Query
		if err := json.Unmarshal([]byte(raw), &q); err == nil {
			t.Fatalf("F12 expected error for %s, got nil", raw)
		}
	}
	bulkActions, err := ParseBulkNDJSON(strings.NewReader(
		`{"update":{"_index":"idx","_id":"1","_source_includes":["a","b"],"_source_excludes":"c"}}`+"\n"+
			`{"doc":{"a":1},"_source":{"includes":["x"],"excludes":["y"]}}`+"\n",
	), "idx")
	if err != nil || len(bulkActions) != 1 || bulkActions[0].SourceFilter == nil || len(bulkActions[0].SourceFilter.Includes) != 2 {
		t.Fatalf("ParseBulkNDJSON _source_includes failed: err=%v actions=%+v", err, bulkActions)
	}
}

func TestRound48ASTSpecCompliance(t *testing.T) {
	// F29: SearchRequest.Slice
	var req SearchRequest
	if err := json.Unmarshal([]byte(`{"slice": {"id": 1, "max": 4, "field": "uid"}, "query": {"match_all": {"_name": "all_q"}}}`), &req); err != nil {
		t.Fatalf("F29 SearchRequest.Slice unmarshal failed: %v", err)
	}
	if req.Slice == nil || req.Slice.ID != 1 || req.Slice.Max != 4 || req.Slice.Field != "uid" {
		t.Fatalf("F29 unexpected Slice: %+v", req.Slice)
	}
	if req.Query == nil || req.Query.Name != "all_q" {
		t.Fatalf("F8 expected Query.Name='all_q', got %+v", req.Query)
	}

	// F8: Named queries (_name) extraction across query types
	namedQueries := map[string]string{
		`{"term": {"status": {"value": "active", "_name": "term_q"}}}`:       "term_q",
		`{"range": {"age": {"gte": 10, "_name": "range_q"}}}`:                "range_q",
		`{"match": {"title": {"query": "hello", "_name": "match_q"}}}`:       "match_q",
		`{"bool": {"must": [{"match_all": {}}], "_name": "bool_q"}}`:         "bool_q",
		`{"constant_score": {"filter": {"match_all": {}}, "_name": "cs_q"}}`: "cs_q",
		`{"exists": {"field": "tags", "_name": "exists_q"}}`:                 "exists_q",
	}
	for raw, wantName := range namedQueries {
		var q Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F8 failed to unmarshal %s: %v", raw, err)
		}
		if q.Name != wantName {
			t.Fatalf("F8 for %s expected q.Name=%q, got %q", raw, wantName, q.Name)
		}
	}

	// F8: WrapperQuery.Decoded populated and invalid inner query rejected
	var wq Query
	if err := json.Unmarshal([]byte(`{"wrapper": {"query": "eyJ0ZXJtIjp7InN0YXR1cyI6ImFjdGl2ZSJ9fQ=="}}`), &wq); err != nil {
		t.Fatalf("F8 WrapperQuery unmarshal failed: %v", err)
	}
	if wq.Wrapper == nil || wq.Wrapper.Decoded == nil || len(wq.Wrapper.Decoded.Term) != 1 {
		t.Fatalf("F8 expected WrapperQuery.Decoded to contain inner Term query, got %+v", wq.Wrapper)
	}
	var badWQ Query
	if err := json.Unmarshal([]byte(`{"wrapper": {"query": "eyJ1bmtub3duX3F1ZXJ5Ijp7fX0="}}`), &badWQ); err == nil {
		t.Fatalf("F8 expected error for wrapper query with invalid inner query JSON")
	}

	// F12: WKT string parsing in GeoShapeQuery
	wktCases := map[string]string{
		`{"geo_shape": {"loc": {"shape": "POINT (-74.0 40.7)"}}}`:                                               "point",
		`{"geo_shape": {"loc": {"shape": "BBOX (-75.0, -73.0, 41.0, 40.0)"}}}`:                                  "envelope",
		`{"geo_shape": {"loc": {"shape": "ENVELOPE (-75.0, -73.0, 41.0, 40.0)"}}}`:                              "envelope",
		`{"geo_shape": {"loc": {"shape": "LINESTRING (-74.0 40.7, -73.9 40.8)"}}}`:                              "linestring",
		`{"geo_shape": {"loc": {"shape": "POLYGON ((-75 40, -73 40, -73 42, -75 42, -75 40))"}}}`:               "polygon",
		`{"geo_shape": {"loc": {"shape": "MULTIPOINT ((-74 40), (-73 41))"}}}`:                                  "multipoint",
		`{"geo_shape": {"loc": {"shape": "GEOMETRYCOLLECTION (POINT (-74 40), LINESTRING (-74 40, -73 41))"}}}`: "geometrycollection",
	}
	for raw, wantType := range wktCases {
		var q Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F12 WKT GeoShapeQuery unmarshal failed for %s: %v", raw, err)
		}
		if q.GeoShape == nil || q.GeoShape.Shape == nil || q.GeoShape.Shape["type"] != wantType {
			t.Fatalf("F12 for %s expected shape type %q, got %+v", raw, wantType, q.GeoShape)
		}
	}
}
