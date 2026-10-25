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
