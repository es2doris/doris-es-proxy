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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound36_F1_FieldNamedUnderscoreNamePreservedInQueryUnmarshal(t *testing.T) {
	cases := []string{
		`{"term": {"_name": "alice"}}`,
		`{"terms": {"_name": ["alice", "bob"]}}`,
		`{"range": {"_name": {"gte": "a", "lte": "z"}}}`,
		`{"prefix": {"_name": "ali"}}`,
		`{"wildcard": {"_name": "al*e"}}`,
		`{"regexp": {"_name": "al.*"}}`,
		`{"fuzzy": {"_name": "alcie"}}`,
		`{"match": {"_name": "alice"}}`,
		`{"match_phrase": {"_name": "alice smith"}}`,
		`{"match_phrase_prefix": {"_name": "alice sm"}}`,
		`{"match_bool_prefix": {"_name": "alice sm"}}`,
		`{"terms_set": {"_name": {"terms": ["a", "b"], "minimum_should_match_field": "req"}}}`,
	}
	for _, raw := range cases {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("failed to unmarshal %s: %v", raw, err)
		}
		switch {
		case q.Term != nil && q.Term["_name"].Value != nil:
		case q.Terms != nil && len(q.Terms.Fields["_name"]) > 0:
		case q.Range != nil && q.Range["_name"].GTE != nil:
		case q.Prefix != nil && q.Prefix["_name"].Value != "":
		case q.Wildcard != nil && q.Wildcard["_name"].Value != "":
		case q.Regexp != nil && q.Regexp["_name"].Value != "":
		case q.Fuzzy != nil && q.Fuzzy["_name"].Value != nil:
		case q.Match != nil && q.Match["_name"].Query != nil:
		case q.MatchPhrase != nil && q.MatchPhrase["_name"].Query != "":
		case q.MatchPhrasePrefix != nil && q.MatchPhrasePrefix["_name"].Query != "":
		case q.MatchBoolPrefix != nil && q.MatchBoolPrefix["_name"].Query != "":
		case q.TermsSet != nil && len(q.TermsSet["_name"].Terms) > 0:
		default:
			t.Fatalf("expected _name target field to be preserved in %s, got %+v", raw, q)
		}
	}

	// Sibling "_name" alongside a real field must still be stripped as query name.
	var namedQ esast.Query
	if err := json.Unmarshal([]byte(`{"term": {"status": "ok", "_name": "status_tag"}}`), &namedQ); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if namedQ.Term["status"].Value != "ok" {
		t.Fatalf("expected status='ok', got Term=%+v", namedQ.Term)
	}
	if _, hasNameField := namedQ.Term["_name"]; hasNameField {
		t.Fatalf("expected sibling _name to be stripped from Term map")
	}
}

func TestRound36_F2_InferMappingDeduplicatesFieldBudgetAcrossSamplesAndObjectArrays(t *testing.T) {
	var docs []json.RawMessage
	for i := 0; i < 60; i++ {
		docs = append(docs, json.RawMessage(`{
			"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5",
			"items": [
				{"a": 1, "b": "x", "c": true},
				{"a": 2, "b": "y", "c": false},
				{"a": 3, "b": "z", "c": true}
			],
			"late_unique": 42
		}`))
	}
	inferred := schema.InferMappingFromSampleDocs(docs)
	if _, ok := inferred.Properties["late_unique"]; !ok {
		t.Fatalf("expected late_unique to be inferred within field budget, got properties: %+v", inferred.Properties)
	}
	itemsProp, ok := inferred.Properties["items"]
	if !ok || len(itemsProp.Properties) != 3 {
		t.Fatalf("expected items object properties a,b,c to be inferred, got %+v", itemsProp)
	}
}

func TestRound36_F3_F4_ShredderCopyToCoercionAndNestedKeywordScalarCoercion(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"raw_price": {"type": "keyword", "copy_to": ["prices", "scaled_prices"]},
			"prices": {"type": "long", "ignore_malformed": true},
			"scaled_prices": {"type": "scaled_float", "scaling_factor": 100, "ignore_malformed": true},
			"items": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword"},
					"const_code": {"type": "constant_keyword"}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("failed to unmarshal mapping: %v", err)
	}
	s := schema.CompileIndexSchema("idx_f3_f4", "doris_es", &mapping)
	// Make prices and scaled_prices multi-valued arrays.
	pb := s.Fields["prices"]
	pb.Kind = schema.StoragePromotedArray
	pb.IsMultiValued = true
	pb.ColumnName = "f__arr__prices"
	s.Fields["prices"] = pb

	spb := s.Fields["scaled_prices"]
	spb.Kind = schema.StoragePromotedArray
	spb.IsMultiValued = true
	spb.ColumnName = "f__arr__scaled_prices"
	s.Fields["scaled_prices"] = spb

	shredded, err := schema.ShredDocument(s, "1", 1, false, []byte(`{
		"raw_price": ["12.346", "not_a_number"],
		"items": [{"code": 404, "const_code": true}]
	}`))
	if err != nil {
		t.Fatalf("unexpected shred error: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil {
		t.Fatalf("unmarshal shredded row: %v", err)
	}
	ignored, _ := row["_ignored"].([]any)
	if len(ignored) != 2 || ignored[0] != "prices" || ignored[1] != "scaled_prices" {
		t.Fatalf("expected _ignored=['prices', 'scaled_prices'] from malformed copy_to element, got %+v", row["_ignored"])
	}
	scaledArr, _ := row["f__arr__scaled_prices"].([]any)
	if len(scaledArr) != 1 || scaledArr[0] != "12.35" {
		t.Fatalf("expected scaled_prices array ['12.35'], got %+v", row["f__arr__scaled_prices"])
	}
	nestedArr, _ := row["n__items"].([]any)
	if len(nestedArr) != 1 {
		t.Fatalf("expected 1 nested element, got %+v", row["n__items"])
	}
	var nestedElem map[string]any
	_ = json.Unmarshal([]byte(nestedArr[0].(string)), &nestedElem)
	if nestedElem["code"] != "404" || nestedElem["const_code"] != "true" {
		t.Fatalf("expected nested keyword/constant_keyword scalars to be coerced to strings, got %+v", nestedElem)
	}
}

func TestRound36_F5_F6_F7_F8_F9_F10_TranspilerAndLuceneHardening(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"active": {"type": "boolean"},
			"price": {"type": "double", "null_value": 0},
			"items": {
				"type": "nested",
				"properties": {
					"tag": {"type": "keyword"},
					"price": {"type": "scaled_float", "scaling_factor": 100},
					"weights": {"type": "double"},
					"score": {"type": "double"}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("failed to unmarshal mapping: %v", err)
	}
	s := schema.CompileIndexSchema("idx_f5_f10", "doris_es", &mapping)
	wb := s.Fields["items.weights"]
	wb.IsMultiValued = true
	s.Fields["items.weights"] = wb

	tr := transpiler.NewTranspiler(s, transpiler.TranspilerOptions{})

	// F5 & F6: +a b AND c under default_operator OR keeps (b AND c) optional in Should, and +/ab.*/ parses as regex.
	var qsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "+/ab.*/ b AND c",
				"default_field": "active",
				"default_operator": "OR"
			}
		}
	}`), &qsReq)
	plan, err := tr.BuildSearchPlan(&qsReq)
	if err != nil {
		t.Fatalf("unexpected transpile error for F5/F6: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "REGEXP") {
		t.Fatalf("expected +/ab.*/ to compile as REGEXP, got SQL: %s", plan.HitsSQL)
	}

	// F7: nested prefilter skips case_insensitive terms when normalizer is not lowercase, and rounds scaled_float.
	var nestedReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"terms": {"items.tag": ["ABC"], "case_insensitive": true}},
							{"term": {"items.price": 12.346}},
							{"term": {"items.weights": "10.5"}},
							{"term": {"items.score": "10.5"}}
						]
					}
				}
			}
		}
	}`), &nestedReq)
	nPlan, err := tr.BuildSearchPlan(&nestedReq)
	if err != nil {
		t.Fatalf("unexpected transpile error for F7/F8: %v", err)
	}
	if strings.Contains(nPlan.HitsSQL, "array_contains(`f__nested_arr__items__tag`, 'ABC')") {
		t.Fatalf("expected case_insensitive nested terms to skip exact prefilter array_contains, got: %s", nPlan.HitsSQL)
	}
	if !strings.Contains(nPlan.HitsSQL, "12.35") {
		t.Fatalf("expected scaled_float nested prefilter/predicate to round 12.346 to 12.35, got: %s", nPlan.HitsSQL)
	}
	if !strings.Contains(nPlan.HitsSQL, "CAST(json_extract_string(_el, '$.score') AS DOUBLE) = 10.5") {
		t.Fatalf("expected single-valued double nested subfield to cast to DOUBLE for numeric string term, got: %s", nPlan.HitsSQL)
	}

	// F9: invalid boolean term returns FALSE, and invalid boolean in terms is skipped.
	var boolReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"active": "not_a_bool"}},
					{"terms": {"active": ["true", "invalid_bool"]}}
				]
			}
		}
	}`), &boolReq)
	bPlan, err := tr.BuildSearchPlan(&boolReq)
	if err != nil {
		t.Fatalf("unexpected transpile error for F9: %v", err)
	}
	if !strings.Contains(bPlan.HitsSQL, "FALSE") || strings.Contains(bPlan.HitsSQL, "invalid_bool") {
		t.Fatalf("expected invalid boolean term to compile to FALSE and invalid terms element to be skipped, got: %s", bPlan.HitsSQL)
	}

	// F10: terms [1, 1.5] on double field with integer null_value: 0 casts COALESCE to DOUBLE instead of BIGINT.
	var termsFloatReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"terms": {"price": [1, 1.5]}
		}
	}`), &termsFloatReq)
	fPlan, err := tr.BuildSearchPlan(&termsFloatReq)
	if err != nil {
		t.Fatalf("unexpected transpile error for F10: %v", err)
	}
	if strings.Contains(fPlan.HitsSQL, "AS BIGINT") || !strings.Contains(fPlan.HitsSQL, "1.5") {
		t.Fatalf("expected price terms [1, 1.5] not to truncate via BIGINT cast, got: %s", fPlan.HitsSQL)
	}
}

func TestRound36_F11_F12_F14_MultiIndexMetricNullAndStringStatsAndMinDocCount(t *testing.T) {
	srv, _ := newTestServer()

	// Create idx_empty (no docs with score/title) and idx_populated
	doJSON(t, srv, http.MethodPut, "/idx_r36_empty", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"val": {"type": "double"},
				"title": {"type": "keyword"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_pop", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"val": {"type": "double"},
				"title": {"type": "keyword"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_empty/_doc/1?refresh=true", `{"group": "g1"}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_pop/_doc/2?refresh=true", `{"group": "g1"}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_pop/_doc/3?refresh=true", `{"group": "g2", "val": 20, "title": "éé"}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_pop/_doc/4?refresh=true", `{"group": "g2", "val": 40, "title": "éééé"}`)

	// 1. Multi-index search where all matching docs have null `val`: avg/min/max must be nil, not 0.
	res := doJSON(t, srv, http.MethodPost, "/idx_r36_empty,idx_r36_pop/_search", `{
		"size": 0,
		"query": {"term": {"group": "g1"}},
		"aggs": {
			"avg_val": {"avg": {"field": "val"}},
			"min_val": {"min": {"field": "val"}},
			"max_val": {"max": {"field": "val"}},
			"by_group": {
				"terms": {"field": "group"},
				"aggs": {
					"sub_avg": {"avg": {"field": "val"}}
				}
			}
		}
	}`)
	aggs := res["aggregations"].(map[string]any)
	for _, k := range []string{"avg_val", "min_val", "max_val"} {
		if aggs[k].(map[string]any)["value"] != nil {
			t.Fatalf("expected %s.value to be nil when all docs have null val across indices, got %+v", k, aggs[k])
		}
	}
	buckets := aggs["by_group"].(map[string]any)["buckets"].([]any)
	if buckets[0].(map[string]any)["sub_avg"].(map[string]any)["value"] != nil {
		t.Fatalf("expected sub_avg.value to be nil in g1 bucket across indices, got %+v", buckets[0])
	}

	// 2. Multi-index string_stats where idx_r36_empty has 0 string values and idx_r36_pop has UTF-8 strings ("éé" = 2 runes, "éééé" = 4 runes).
	res2 := doJSON(t, srv, http.MethodPost, "/idx_r36_empty,idx_r36_pop/_search", `{
		"size": 0,
		"aggs": {
			"sstats": {"string_stats": {"field": "title"}}
		}
	}`)
	aggs2 := res2["aggregations"].(map[string]any)
	ss := aggs2["sstats"].(map[string]any)
	if ss["count"].(float64) != 2 || ss["min_length"].(float64) != 2 || ss["max_length"].(float64) != 4 || ss["avg_length"].(float64) != 3 {
		t.Fatalf("expected string_stats count=2, min_length=2, max_length=4, avg_length=3 (rune count unaffected by empty index), got %+v", ss)
	}
	res3 := doJSON(t, srv, http.MethodPost, "/idx_r36_pop/_search", `{
		"size": 0,
		"aggs": {
			"filtered_groups": {
				"terms": {"field": "group", "min_doc_count": 2, "size": 1, "order": {"_key": "asc"}}
			}
		}
	}`)
	fgBuckets := res3["aggregations"].(map[string]any)["filtered_groups"].(map[string]any)["buckets"].([]any)
	if len(fgBuckets) != 1 || fgBuckets[0].(map[string]any)["key"] != "g2" {
		t.Fatalf("expected min_doc_count=2 with size=1 to return g2, got %+v", fgBuckets)
	}
}

func TestRound36_F13_CoalescerPropagatesInflightErrorsOnFlushTableAndFlushAll(t *testing.T) {
	expectedErr := errors.New("simulated stream load failure")
	coal := newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		time.Sleep(25 * time.Millisecond)
		return expectedErr
	})
	coal.Configure(5*time.Millisecond, 1024*1024)
	defer func() { _ = coal.Close(context.Background()) }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- coal.Submit(context.Background(), "tbl_a", []byte(`{"_id":"1"}`), false)
	}()
	time.Sleep(10 * time.Millisecond) // timer has fired; batch is now in-flight
	if flushErr := coal.FlushTable(context.Background(), "tbl_a"); !errors.Is(flushErr, expectedErr) {
		t.Fatalf("expected FlushTable to propagate in-flight error %v, got %v", expectedErr, flushErr)
	}
	if addErr := <-errCh; !errors.Is(addErr, expectedErr) {
		t.Fatalf("expected Add to return %v, got %v", expectedErr, addErr)
	}
}

func TestRound36_F15_F16_F18_F19_F20_ProxySearchMGetFieldCapsUBQAndHighlight(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/idx_r36_main", `{
		"mappings": {
			"properties": {
				"suggest_col": {"type": "completion"},
				"secret": {"type": "keyword"},
				"title": {"type": "text"},
				"env": {"type": "keyword"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_main/_doc/1?refresh=true", `{
		"suggest_col": "café latte",
		"secret": "top-secret",
		"title": "über café guide",
		"env": "prod"
	}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_main/_doc/2?refresh=true", `{
		"suggest_col": "tea",
		"secret": "public",
		"title": "green tea",
		"env": "dev"
	}`)
	doJSON(t, srv, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "idx_r36_main", "alias": "alias_r36_prod", "filter": {"term": {"env": "prod"}}}}
		]
	}`)

	// F15: Completion suggester with UTF-8 fuzzy prefix and _source: false
	sugRes := doJSON(t, srv, http.MethodPost, "/idx_r36_main/_search", `{
		"_source": false,
		"suggest": {
			"coffee_sug": {
				"prefix": "café",
				"completion": {
					"field": "suggest_col",
					"fuzzy": {"fuzziness": 1}
				}
			}
		}
	}`)
	sugArr := sugRes["suggest"].(map[string]any)["coffee_sug"].([]any)
	sugEntry := sugArr[0].(map[string]any)
	if sugEntry["length"].(float64) != 4 {
		t.Fatalf("expected UTF-8 rune length 4 for 'café', got %v", sugEntry["length"])
	}
	opts := sugEntry["options"].([]any)
	if len(opts) != 1 {
		t.Fatalf("expected 1 completion option, got %+v", opts)
	}
	if _, hasSrc := opts[0].(map[string]any)["_source"]; hasSrc {
		t.Fatalf("expected _source to be omitted when _source: false in completion suggest, got %+v", opts[0])
	}

	// F16: _mget with URL ?_source_excludes=secret and body {"_source": true, "ids": ["1"]}
	mgetRes := doJSON(t, srv, http.MethodPost, "/idx_r36_main/_mget?_source_excludes=secret", `{
		"_source": true,
		"ids": ["1"]
	}`)
	mgetDoc := mgetRes["docs"].([]any)[0].(map[string]any)["_source"].(map[string]any)
	if _, hasSecret := mgetDoc["secret"]; hasSecret {
		t.Fatalf("expected URL _source_excludes=secret to be honored when body has _source:true, got %+v", mgetDoc)
	}

	// F18: _field_caps on filtered alias with index_filter matching only excluded docs prunes the index
	fcRes := doJSON(t, srv, http.MethodPost, "/alias_r36_prod/_field_caps?fields=title", `{
		"index_filter": {"term": {"env": "dev"}}
	}`)
	fieldsMap, _ := fcRes["fields"].(map[string]any)
	if len(fieldsMap) != 0 {
		t.Fatalf("expected alias_r36_prod to be pruned when index_filter matches only dev docs, got %+v", fcRes)
	}

	// F20: Highlight wildcard on non-ASCII UTF-8 token ("üb*r*") and rune-based fragment_size
	hlRes := doJSON(t, srv, http.MethodPost, "/idx_r36_main/_search", `{
		"query": {"wildcard": {"title": "üb*r*"}},
		"highlight": {
			"fields": {
				"title": {"fragment_size": 15, "number_of_fragments": 1}
			}
		}
	}`)
	hlHits := hlRes["hits"].(map[string]any)["hits"].([]any)
	if len(hlHits) != 1 {
		t.Fatalf("expected 1 hit for wildcard 'üb*r', got %+v", hlHits)
	}
	hlSnippets := hlHits[0].(map[string]any)["highlight"].(map[string]any)["title"].([]any)
	if len(hlSnippets) == 0 || !strings.Contains(hlSnippets[0].(string), "<em>über</em>") {
		t.Fatalf("expected highlight snippet to contain <em>über</em>, got %+v", hlSnippets)
	}

	// F19: _update_by_query and _delete_by_query with ?q=env:dev and no body query
	ubqRes := doJSON(t, srv, http.MethodPost, "/idx_r36_main/_update_by_query?q=env:dev&refresh=true", `{
		"script": {"source": "ctx._source.secret = 'updated-dev'"}
	}`)
	if ubqRes["updated"].(float64) != 1 {
		t.Fatalf("expected ?q=env:dev on _update_by_query to update 1 doc, got %+v", ubqRes)
	}
	dbqRes := doJSON(t, srv, http.MethodPost, "/idx_r36_main/_delete_by_query?q=env:dev&refresh=true", `{}`)
	if dbqRes["deleted"].(float64) != 1 {
		t.Fatalf("expected ?q=env:dev on _delete_by_query to delete 1 doc, got %+v", dbqRes)
	}
}

func TestRound36_F21_F22_F23_F24_F25_PainlessHardening(t *testing.T) {
	// F21: ctx.op = 'delete' inside a .forEach(...) lambda propagates out of EvalPainlessWithOp
	doc := map[string]any{"tags": []any{"keep", "drop_me"}}
	op, err := painless.EvalPainlessWithOp(doc, `ctx._source.tags.forEach(t -> { if (t == 'drop_me') { ctx.op = 'delete'; } });`, nil)
	if err != nil || op != "delete" {
		t.Fatalf("expected ctx.op='delete' inside forEach lambda to propagate, got op=%q err=%v", op, err)
	}

	// F22 & F24: unary +x, leading-decimal float .5 / -.5, and Elvis ?: in boolean condition
	doc2 := map[string]any{"a": int64(4), "flag": nil, "backup": true}
	err = painless.EvalPainless(doc2, `
		def pos = +ctx._source.a;
		def half = .5;
		def negHalf = -.5;
		if (ctx._source.flag ?: ctx._source.backup) {
			ctx._source.res = pos + half + negHalf;
		}
	`, nil)
	if err != nil {
		t.Fatalf("unexpected painless error for F22/F24: %v", err)
	}
	if doc2["res"] != float64(4) && doc2["res"] != int64(4) {
		t.Fatalf("expected res=4, got %+v (%T)", doc2["res"], doc2["res"])
	}

	// F23 & F25: List.remove(Object) returns false when not found, and chained local alias def sub = root.items mutates ctx._source
	doc3 := map[string]any{
		"nested": map[string]any{
			"items": []any{"a", "b"},
		},
	}
	err = painless.EvalPainless(doc3, `
		def n = ctx._source.nested;
		def items = n.items;
		boolean removedMissing = items.remove('nonexistent');
		boolean removedA = items.remove('a');
		items.add('c');
		ctx._source.removed_missing = removedMissing;
		ctx._source.removed_a = removedA;
	`, nil)
	if err != nil {
		t.Fatalf("unexpected painless error for F23/F25: %v", err)
	}
	if doc3["removed_missing"] != false || doc3["removed_a"] != true {
		t.Fatalf("expected removed_missing=false and removed_a=true, got %+v", doc3)
	}
	nestedItems := doc3["nested"].(map[string]any)["items"].([]any)
	if len(nestedItems) != 2 || nestedItems[0] != "b" || nestedItems[1] != "c" {
		t.Fatalf("expected chained alias mutation to update ctx._source.nested.items to [b, c], got %+v", nestedItems)
	}
}

func TestRound36_F26_F27_F28_F29_F30_IngestAndMutationHardening(t *testing.T) {
	srv, _ := newTestServer()

	// F26 & F27: split and kv on array of strings, kv overwriting scalar target_field, grok rejecting non-string and merging duplicate captures
	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"split": {"field": "lines", "separator": ","}},
				{"kv": {"field": "kv_arr", "field_split": " ", "value_split": "=", "target_field": "parsed"}},
				{"grok": {"field": "log", "patterns": ["%{WORD:tok}-%{WORD:tok}"]}}
			]
		},
		"docs": [
			{
				"_source": {
					"lines": ["a,b", "c"],
					"kv_arr": ["k1=v1 k2=v2", "k1=v3"],
					"parsed": "scalar_to_overwrite",
					"log": "hello-world"
				}
			}
		]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if len(simDoc["lines"].([]any)) != 3 {
		t.Fatalf("expected split on string array to produce [a, b, c], got %+v", simDoc["lines"])
	}
	parsedMap, ok := simDoc["parsed"].(map[string]any)
	if !ok || len(parsedMap["k1"].([]any)) != 2 || parsedMap["k2"] != "v2" {
		t.Fatalf("expected kv to overwrite scalar target_field with map and merge k1=[v1, v3], got %+v", simDoc["parsed"])
	}
	tokArr, ok := simDoc["tok"].([]any)
	if !ok || len(tokArr) != 2 || tokArr[0] != "hello" || tokArr[1] != "world" {
		t.Fatalf("expected duplicate named grok captures to merge into [hello, world], got %+v", simDoc["tok"])
	}

	// Grok on non-string field must fail with error
	simErrRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"grok": {"field": "num_field", "patterns": ["%{NUMBER:n}"]}}
			]
		},
		"docs": [{"_source": {"num_field": 12345}}]
	}`)
	if _, hasErr := simErrRes["docs"].([]any)[0].(map[string]any)["error"]; !hasErr {
		t.Fatalf("expected grok on integer field to return processor error, got %+v", simErrRes)
	}

	// F28: Chained same-batch _bulk update reroute via ingest pipeline: 1 -> 2, then 2 -> 3 (where 2 did not exist before batch)
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/pipe_next_id", `{
		"processors": [
			{"script": {"source": "ctx._id = ctx.next_id"}}
		]
	}`)
	doJSON(t, srv, http.MethodPut, "/idx_r36_bulk/_doc/1?refresh=true", `{"step": 0}`)
	bulkBody := strings.Join([]string{
		`{"update": {"_index": "idx_r36_bulk", "_id": "1", "pipeline": "pipe_next_id"}}`,
		`{"doc": {"step": 1, "next_id": "2"}}`,
		`{"update": {"_index": "idx_r36_bulk", "_id": "2", "pipeline": "pipe_next_id"}}`,
		`{"doc": {"step": 2, "next_id": "3"}}`,
		"",
	}, "\n")
	req := httptest.NewRequest(http.MethodPost, "/_bulk?refresh=true", strings.NewReader(bulkBody))
	req.Header.Set("Content-Type", "application/x-ndjson")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected bulk status %d: %s", rec.Code, rec.Body.String())
	}
	// Verify only doc "3" exists in idx_r36_bulk ("1" and intermediate "2" are tombstoned)
	searchBulk := doJSON(t, srv, http.MethodPost, "/idx_r36_bulk/_search", `{"query": {"match_all": {}}}`)
	bulkHits := searchBulk["hits"].(map[string]any)["hits"].([]any)
	if len(bulkHits) != 1 || bulkHits[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected only doc 3 to remain after chained bulk reroute 1->2->3, got %+v", bulkHits)
	}

	// F29 & F30: Pipeline/script setting ctx._id = null auto-generates a new ID in PUT /_doc and _reindex
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/pipe_clear_id", `{
		"processors": [
			{"script": {"source": "ctx._id = null"}}
		]
	}`)
	putRes := doJSON(t, srv, http.MethodPut, "/idx_r36_auto/_doc/explicit-id?pipeline=pipe_clear_id&refresh=true", `{"k": "v"}`)
	genID, _ := putRes["_id"].(string)
	if genID == "" || genID == "explicit-id" {
		t.Fatalf("expected ctx._id = null in pipeline to auto-generate a new _id, got %q", genID)
	}

	doJSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "idx_r36_auto"},
		"dest": {"index": "idx_r36_reindexed"},
		"script": {"source": "ctx._id = null"}
	}`)
	reidxSearch := doJSON(t, srv, http.MethodPost, "/idx_r36_reindexed/_search", `{"query": {"match_all": {}}}`)
	reidxHits := reidxSearch["hits"].(map[string]any)["hits"].([]any)
	if len(reidxHits) != 1 || reidxHits[0].(map[string]any)["_id"] == genID {
		t.Fatalf("expected _reindex with ctx._id = null to auto-generate a new destination _id, got %+v", reidxHits)
	}
}
