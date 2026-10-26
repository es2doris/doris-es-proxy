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
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func FuzzLuceneQueryStringBalancedSQL(f *testing.F) {
	seeds := []string{
		`status:200 AND service:checkout`,
		`title:"apache doris"^2.5 OR (host:web-* AND NOT env:dev)`,
		`latency:[100 TO 500] AND created_at:{2026-01-01 TO *}`,
		`_exists_:user.id AND *.keyword:admin*`,
		`message:"error: connection refused (timeout)"`,
		`+must_term -excluded_termoptional_term~2`,
		`((unbalanced:paren OR "unterminated quote`,
		`'::' OR '''' OR "\"\\"`,
		`*:*`,
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"status": {"type": "integer"},
			"service": {"type": "keyword", "normalizer": "lowercase"},
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lowercase"}}},
			"host": {"type": "keyword"},
			"latency": {"type": "double"},
			"created_at": {"type": "date"}
		}
	}`), &spec)
	idxSchema := schema.CompileIndexSchema("fuzz_db", "fuzz_idx", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	f.Fuzz(func(t *testing.T, luceneQuery string) {
		req := &esast.SearchRequest{
			Query: &esast.Query{
				QueryString: &esast.QueryStringQuery{
					Query:  luceneQuery,
					Fields: []string{"title^2", "*.keyword", "service"},
				},
			},
		}
		plan, err := tr.BuildSearchPlan(req)
		if err != nil {
			return
		}
		assertBalancedSQLQuotesAndParens(t, luceneQuery, plan.HitsSQL)
		assertBalancedSQLQuotesAndParens(t, luceneQuery, plan.AggsSQL)
	})
}

func FuzzBuildSearchPlanBalancedSQL(f *testing.F) {
	seeds := []string{
		`{"query":{"bool":{"must":[{"match":{"title":"doris''s sql"}},{"range":{"latency":{"gte":10,"lte":100}}}],"should":[{"term":{"service":"Checkout"}}],"minimum_should_match":"50%"}}}`,
		`{"query":{"simple_query_string":{"query":"\"fast analytics\" +doris -legacy","fields":["title","*"]}}}`,
		`{"size":0,"aggs":{"by_svc":{"terms":{"field":"service","missing":"N/A"},"aggs":{"top_docs":{"top_hits":{"size":2,"sort":[{"latency":"desc"}]}}}}}}`,
		`{"post_filter":{"term":{"service":"api"}},"aggs":{"missing_svc":{"missing":{"field":"service"},"aggs":{"avg_lat":{"avg":{"field":"latency"}}}}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"service": {"type": "keyword", "normalizer": "lowercase"},
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lowercase"}}},
			"latency": {"type": "double"},
			"created_at": {"type": "date"}
		}
	}`), &spec)
	idxSchema := schema.CompileIndexSchema("fuzz_db", "fuzz_idx", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	f.Fuzz(func(t *testing.T, rawJSON []byte) {
		var req esast.SearchRequest
		if err := json.Unmarshal(rawJSON, &req); err != nil {
			return
		}
		plan, err := tr.BuildSearchPlan(&req)
		if err != nil {
			return
		}
		assertBalancedSQLQuotesAndParens(t, string(rawJSON), plan.HitsSQL)
		assertBalancedSQLQuotesAndParens(t, string(rawJSON), plan.AggsSQL)
	})
}

func assertBalancedSQLQuotesAndParens(t *testing.T, input, sqlStr string) {
	t.Helper()
	if sqlStr == "" {
		return
	}
	inSingleQuote := false
	inBacktick := false
	parenDepth := 0
	for i := 0; i < len(sqlStr); i++ {
		ch := sqlStr[i]
		if inSingleQuote {
			if ch == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inSingleQuote = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingleQuote = true
		case '`':
			inBacktick = true
		case '(':
			parenDepth++
		case ')':
			parenDepth--
			if parenDepth < 0 {
				t.Fatalf("negative parenthesis depth in SQL for input %q:\n%s", input, sqlStr)
			}
		}
	}
	if inSingleQuote {
		t.Fatalf("unbalanced single quote in SQL for input %q:\n%s", input, sqlStr)
	}
	if inBacktick {
		t.Fatalf("unbalanced backtick in SQL for input %q:\n%s", input, sqlStr)
	}
	if parenDepth != 0 {
		t.Fatalf("unbalanced parentheses (depth=%d) in SQL for input %q:\n%s", parenDepth, input, sqlStr)
	}
}
