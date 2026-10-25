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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestSQLInjectionEscapingAndSubAggregations(t *testing.T) {
	mappingJSON := []byte(`{
		"properties": {
			"serviceType": {"type": "keyword"},
			"updatedAt": {"type": "date"},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"}
				}
			}
		}
	}`)
	var spec esast.MappingSpec
	if err := json.Unmarshal(mappingJSON, &spec); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// 1. Verify backslash + single-quote in dynamic VARIANT field path cannot break out of string literal
	maliciousPayload := []byte(`{
		"size": 5,
		"collapse": {"field": "a\\'.b"},
		"query": {
			"term": {"x\\'.y": "val' OR 1=1 --"}
		},
		"aggs": {
			"nested_cols": {
				"nested": {"path": "columns"},
				"aggs": {
					"bad_key": {
						"terms": {"field": "columns.x') FROM mysql.user --"}
					}
				}
			},
			"by_service": {
				"terms": {"field": "serviceType", "size": 5},
				"aggs": {
					"avg_updated": {"avg": {"field": "updatedAt"}},
					"col_count": {"value_count": {"field": "serviceType"}}
				}
			}
		}
	}`)
	var req esast.SearchRequest
	if err := json.Unmarshal(maliciousPayload, &req); err != nil {
		t.Fatalf("unmarshal search request: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, `['a\\''']['b']`) {
		t.Fatalf("expected escaped backslash and quote in collapse variant path, got:\n%s", plan.HitsSQL)
	}
	if !strings.Contains(plan.AggsSQL, `'$.x'') FROM mysql.user --'`) {
		t.Fatalf("expected escaped nested terms relKey in AggsSQL, got:\n%s", plan.AggsSQL)
	}
	if !strings.Contains(plan.AggsSQL, `'by_service.avg_updated'`) {
		t.Fatalf("expected bucket sub-aggregation 'by_service.avg_updated' in AggsSQL, got:\n%s", plan.AggsSQL)
	}
}

func FuzzParseLuceneQueryString(f *testing.F) {
	seeds := []string{
		"+orders -deleted:true (tier:Tier1 OR tags:PII*)",
		`name:"customer\"orders" AND status:active`,
		strings.Repeat("(", 120) + "field:val" + strings.Repeat(")", 120),
		"field:(' OR 1=1 --)",
		"*:*",
		"a\\'.b:test*",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", nil)
	f.Fuzz(func(t *testing.T, expr string) {
		tr := NewTranspiler(idxSchema, TranspilerOptions{})
		q := &esast.Query{
			QueryString: &esast.QueryStringQuery{
				Query:        expr,
				DefaultField: "_all_text",
			},
		}
		compiled := tr.CompileQuery(q, true, nil)
		if compiled.WhereSQL == "" || compiled.ScoreSQL == "" {
			t.Fatalf("empty SQL output for expr=%q", expr)
		}
	})
}

func FuzzBuildSearchPlan(f *testing.F) {
	f.Add([]byte(`{"query":{"match_all":{}},"size":10}`))
	f.Add([]byte(`{"query":{"bool":{"must":[{"query_string":{"query":"+fact -staging"}}]}},"aggs":{"by_svc":{"terms":{"field":"serviceType"},"aggs":{"avg_u":{"avg":{"field":"updatedAt"}}}}}}`))
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", nil)
	f.Fuzz(func(t *testing.T, raw []byte) {
		var req esast.SearchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return
		}
		tr := NewTranspiler(idxSchema, TranspilerOptions{})
		_, _ = tr.BuildSearchPlan(&req)
	})
}

func BenchmarkBuildSearchPlan(b *testing.B) {
	mappingJSON := []byte(`{
		"properties": {
			"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"serviceType": {"type": "keyword"},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "date"},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"}
				}
			}
		}
	}`)
	var spec esast.MappingSpec
	_ = json.Unmarshal(mappingJSON, &spec)
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", &spec)

	searchJSON := []byte(`{
		"size": 25,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [{"query_string": {"query": "+orders -staging"}}],
						"filter": [
							{"term": {"deleted": false}},
							{"nested": {"path": "columns", "query": {"term": {"columns.dataType": "BIGINT"}}}}
						]
					}
				},
				"functions": [{"field_value_factor": {"field": "updatedAt", "modifier": "log1p", "factor": 0.1}}]
			}
		},
		"aggs": {
			"by_service": {
				"terms": {"field": "serviceType", "size": 10},
				"aggs": {"avg_updated": {"avg": {"field": "updatedAt"}}}
			},
			"nested_cols": {
				"nested": {"path": "columns"},
				"aggs": {"by_type": {"terms": {"field": "columns.dataType", "size": 10}}}
			}
		}
	}`)
	var req esast.SearchRequest
	_ = json.Unmarshal(searchJSON, &req)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := NewTranspiler(idxSchema, TranspilerOptions{})
		if _, err := tr.BuildSearchPlan(&req); err != nil {
			b.Fatal(err)
		}
	}
}
