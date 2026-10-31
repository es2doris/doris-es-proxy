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
	if err := json.Unmarshal([]byte(`{"collapse":{"field":"f","inner_hits":[{"name":"a"},{"name":"b"}]},"rescore":[{"window_size":10}]}`), &srRescoreArr); err != nil || len(srRescoreArr.Collapse.InnerHits) != 2 || len(srRescoreArr.Rescore) != 1 {
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
