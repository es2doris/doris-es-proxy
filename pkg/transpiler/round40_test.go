package transpiler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound40_F1_FieldNamedBoostOrNameInTermAndTerms(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r40_f1", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"boost": {Type: "keyword"},
			"_name": {Type: "keyword"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. term query on field named "boost"
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"term":{"boost":"high"}}}`), &req1); err != nil {
		t.Fatalf("unmarshal term on boost failed: %v", err)
	}
	res1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatalf("compile term on boost failed: %v", err)
	}
	if !strings.Contains(res1.HitsSQL, "`f__boost` = 'high'") {
		t.Fatalf("expected `f__boost` = 'high' in SQL, got %s", res1.HitsSQL)
	}

	// 2. term query on field named "_name"
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"term":{"_name":"alice"}}}`), &req2); err != nil {
		t.Fatalf("unmarshal term on _name failed: %v", err)
	}
	res2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatalf("compile term on _name failed: %v", err)
	}
	if !strings.Contains(res2.HitsSQL, "`f___name` = 'alice'") {
		t.Fatalf("expected `f___name` = 'alice' in SQL, got %s", res2.HitsSQL)
	}

	// 3. terms query on field named "boost" and "_name"
	var req3 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"bool":{"must":[{"terms":{"boost":["low","high"]}},{"terms":{"_name":["alice","bob"],"boost":2.0}}]}}}`), &req3); err != nil {
		t.Fatalf("unmarshal terms on boost/_name failed: %v", err)
	}
	res3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatalf("compile terms on boost/_name failed: %v", err)
	}
	if !strings.Contains(res3.HitsSQL, "`f__boost` IN ('low', 'high')") {
		t.Fatalf("expected `f__boost` IN ('low', 'high') in SQL, got %s", res3.HitsSQL)
	}
	if !strings.Contains(res3.HitsSQL, "`f___name` IN ('alice', 'bob')") {
		t.Fatalf("expected `f___name` IN ('alice', 'bob') in SQL, got %s", res3.HitsSQL)
	}
}

func TestRound40_F2_SortMultiKeyAndFieldNamedOrderAndInnerHitsStoredFields(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r40_f2", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"order":    {Type: "long"},
			"priority": {Type: "long"},
			"name":     {Type: "keyword"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. Sort by field named "order" with sibling options, and multi-key sort object {"priority": "desc", "name": "asc"}
	var req esast.SearchRequest
	raw := `{
		"sort": [
			{"order": {"order": "desc", "missing": "_last"}},
			{"priority": "desc", "name": "asc"}
		]
	}`
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal sort failed: %v", err)
	}
	if len(req.Sort) != 3 {
		t.Fatalf("expected 3 expanded sort specs, got %d: %+v", len(req.Sort), req.Sort)
	}
	if req.Sort[0].Entry.Field != "order" || req.Sort[1].Entry.Field != "priority" || req.Sort[2].Entry.Field != "name" {
		t.Fatalf("unexpected sort fields: %+v", req.Sort)
	}
	res, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(res.HitsSQL, "`f__order` DESC NULLS LAST") || !strings.Contains(res.HitsSQL, "`f__priority` DESC") || !strings.Contains(res.HitsSQL, "`f__name` ASC") {
		t.Fatalf("unexpected ORDER BY in HitsSQL: %s", res.HitsSQL)
	}

	// 2. InnerHitsSpec and TopHitsAggSpec StoredFields / HasStoredFieldsNone
	var ih esast.InnerHitsSpec
	if err := json.Unmarshal([]byte(`{"stored_fields": "_none_"}`), &ih); err != nil {
		t.Fatal(err)
	}
	if !ih.HasStoredFieldsNone() {
		t.Fatalf("expected ih.HasStoredFieldsNone() = true")
	}
	var th esast.TopHitsAggSpec
	if err := json.Unmarshal([]byte(`{"stored_fields": ["order", "name"]}`), &th); err != nil {
		t.Fatal(err)
	}
	if th.HasStoredFieldsNone() || len(th.EffectiveFieldSpecs()) != 2 {
		t.Fatalf("expected 2 EffectiveFieldSpecs on TopHitsAggSpec, got %+v", th.EffectiveFieldSpecs())
	}
}

func TestRound40_F7_RoutingMetadataFieldInQueriesSortAndAggs(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r40_f7", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"req": {Type: "integer"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	var req esast.SearchRequest
	raw := `{
		"query": {
			"bool": {
				"must": [
					{"term": {"_routing": "shard-1"}},
					{"terms": {"_routing": ["shard-1", "shard-2"]}},
					{"prefix": {"_routing": "shard-"}},
					{"exists": {"field": "_routing"}},
					{"terms_set": {"_routing": {"terms": ["shard-1"], "minimum_should_match_field": "req"}}}
				]
			}
		},
		"sort": [{"_routing": "asc"}],
		"aggs": {
			"by_routing": {"terms": {"field": "_routing"}}
		}
	}`
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	res, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(res.HitsSQL, "_doc['") {
		t.Fatalf("expected `_routing` column ref instead of _doc['_routing'], got %s", res.HitsSQL)
	}
	if !strings.Contains(res.HitsSQL, "`_routing` = 'shard-1'") {
		t.Fatalf("expected `_routing` = 'shard-1' in HitsSQL, got %s", res.HitsSQL)
	}
	if !strings.Contains(res.AggsSQL, "`_routing`") {
		t.Fatalf("expected `_routing` in AggsSQL, got %s", res.AggsSQL)
	}
}

func TestRound40_F8_TermsSetNestedAndEnabledFalse(t *testing.T) {
	f := false
	s := schema.CompileIndexSchema("es_db", "idx_r40_f8", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"payload": {Type: "object", Enabled: &f},
			"secret":  {Type: "keyword", Index: &f},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"codes": {Type: "keyword"},
					"min":   {Type: "integer"},
				},
			},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. terms_set on index:false field errors
	var reqIdxFalse esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"terms_set":{"secret":{"terms":["a"],"minimum_should_match_script":{"source":"1"}}}}}`), &reqIdxFalse)
	if _, err := tr.BuildSearchPlan(&reqIdxFalse); err == nil || !strings.Contains(err.Error(), "cannot search on field [secret] since it is not indexed") {
		t.Fatalf("expected not-indexed error for terms_set on secret, got %v", err)
	}

	// 2. terms_set on enabled:false field compiles to FALSE (not 0 >= 1)
	var reqEnabledFalse esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"terms_set":{"payload.tags":{"terms":["a","b"],"minimum_should_match_script":{"source":"1"}}}}}`), &reqEnabledFalse)
	resEF, err := tr.BuildSearchPlan(&reqEnabledFalse)
	if err != nil {
		t.Fatalf("unexpected error on enabled:false terms_set: %v", err)
	}
	if strings.Contains(resEF.HitsSQL, "THEN 1 ELSE 0 END") || !strings.Contains(resEF.HitsSQL, "WHERE `__DORIS_DELETE_SIGN__` = 0 AND (FALSE)") {
		t.Fatalf("expected enabled:false terms_set to short-circuit to FALSE, got %s", resEF.HitsSQL)
	}

	// 3. terms_set inside nested query resolves nested subfield
	var reqNested esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"terms_set": {
						"items.codes": {
							"terms": ["c1", "c2"],
							"minimum_should_match_field": "items.min"
						}
					}
				}
			}
		}
	}`), &reqNested)
	resNested, err := tr.BuildSearchPlan(&reqNested)
	if err != nil {
		t.Fatalf("unexpected error on nested terms_set: %v", err)
	}
	if !strings.Contains(resNested.HitsSQL, "array_exists") {
		t.Fatalf("expected array_exists for nested terms_set, got %s", resNested.HitsSQL)
	}
}

func TestRound40_F9_FunctionScoreRandomScore(t *testing.T) {
	s := schema.CompileIndexSchema("es_db", "idx_r40_f9", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"uid": {Type: "keyword"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{})

	// 1. Seeded random_score
	var reqSeeded esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"random_score": {"seed": 42, "field": "uid"}
			}
		}
	}`), &reqSeeded)
	res1, err := tr.BuildSearchPlan(&reqSeeded)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(res1.HitsSQL, "MD5(CONCAT('42'") || !strings.Contains(res1.HitsSQL, "`f__uid`") {
		t.Fatalf("expected deterministic MD5 random_score SQL using f__uid, got %s", res1.HitsSQL)
	}

	// 2. Unseeded random_score
	var reqUnseeded esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"random_score": {}
			}
		}
	}`), &reqUnseeded)
	res2, err := tr.BuildSearchPlan(&reqUnseeded)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(res2.HitsSQL, "RAND()") {
		t.Fatalf("expected RAND() in unseeded random_score SQL, got %s", res2.HitsSQL)
	}
}

func TestRound40_F10_Doris4SearchPushdownGuardsAndSymbolicOperators(t *testing.T) {
	f := false
	s := schema.CompileIndexSchema("es_db", "idx_r40_f10", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":   {Type: "text"},
			"secret":  {Type: "keyword", Index: &f},
			"payload": {Type: "object", Enabled: &f},
			"ip_addr": {Type: "ip"},
		},
	})
	tr := NewTranspiler(s, TranspilerOptions{UseDoris4SearchFunc: true})

	// 1. query_string on index:false field must NOT use SEARCH() pushdown and must return not-indexed error
	var req1 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"default_field":"secret","query":"abc"}}}`), &req1)
	if _, err := tr.BuildSearchPlan(&req1); err == nil || !strings.Contains(err.Error(), "cannot search on field [secret] since it is not indexed") {
		t.Fatalf("expected not-indexed error on secret with Doris4Search enabled, got %v", err)
	}

	// 2. query_string with prefix + and - on field:val rewrites column names for SEARCH() pushdown
	var req2 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"default_field":"title","query":"+title:foo -title:bar"}}}`), &req2)
	res2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatalf("unexpected error on prefixed query_string: %v", err)
	}
	if !strings.Contains(res2.HitsSQL, "SEARCH('+f__title:foo -f__title:bar'") {
		t.Fatalf("expected SEARCH() with rewritten +f__title:foo -f__title:bar, got %s", res2.HitsSQL)
	}

	// 3. query_string with symbolic operators &&, ||, ! falls back to AST SQL without corrupting SEARCH()
	var req3 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"default_field":"title","query":"title:foo && !title:bar || title:baz"}}}`), &req3)
	res3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatalf("unexpected error on symbolic query_string: %v", err)
	}
	if strings.Contains(res3.HitsSQL, "SEARCH(") || !strings.Contains(res3.HitsSQL, "MATCH_ANY") {
		t.Fatalf("expected symbolic operators to fall back to AST SQL without corrupting SEARCH(), got %s", res3.HitsSQL)
	}
}
