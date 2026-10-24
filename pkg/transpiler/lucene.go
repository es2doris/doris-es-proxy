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
	"fmt"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// compileQueryString compiles an ES `query_string` or `simple_query_string` query.
// When `Opts.UseDoris4SearchFunc` is enabled, it emits Apache Doris 4.0's native `SEARCH(...)`
// function; otherwise, it parses common Lucene `field:value`, `AND`/`OR`/`NOT`, and wildcard
// clauses into standard Doris `MATCH_ANY` / `LIKE` / `=` predicates.
func (t *Transpiler) compileQueryString(qsq *esast.QueryStringQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	raw := strings.TrimSpace(qsq.Query)
	if raw == "" || raw == "*" || raw == "*:*" {
		return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	}

	defaultField := qsq.DefaultField
	if defaultField == "" {
		if len(qsq.Fields) > 0 {
			defaultField = strings.Split(qsq.Fields[0], "^")[0]
		} else {
			defaultField = "_all_text"
		}
	}
	defaultOp := strings.ToUpper(qsq.DefaultOperator)
	if defaultOp != "AND" {
		defaultOp = "OR"
	}

	if t.Opts.UseDoris4SearchFunc {
		col := strings.Trim(t.sqlColumnRef(defaultField, false, nctx), "`")
		pred := fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(raw), quoteStr(col), quoteStr(defaultOp))
		return CompiledQuery{
			WhereSQL:          pred,
			ScoreSQL:          "1.0",
			UsesFulltextMatch: true,
		}
	}

	// Parse field:term tokens and boolean operators into a structured Query AST
	parsedAST := parseSimpleLuceneToAST(raw, defaultField, qsq.Fields, defaultOp)
	return t.CompileQuery(&parsedAST, scoring, nctx)
}

func parseSimpleLuceneToAST(expr, defaultField string, fields []string, defaultOp string) esast.Query {
	tokens := tokenizeLucene(expr)
	boolQ := &esast.BoolQuery{}

	negateNext := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		upper := strings.ToUpper(tok)
		if upper == "AND" || upper == "OR" {
			continue
		}
		if upper == "NOT" {
			negateNext = true
			continue
		}
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negateNext = true
			tok = tok[1:]
		} else if strings.HasPrefix(tok, "+") && len(tok) > 1 {
			tok = tok[1:]
		}

		clause := buildLuceneAtomQuery(tok, defaultField, fields)
		if negateNext {
			boolQ.MustNot = append(boolQ.MustNot, clause)
			negateNext = false
		} else if defaultOp == "AND" {
			boolQ.Must = append(boolQ.Must, clause)
		} else {
			boolQ.Should = append(boolQ.Should, clause)
		}
	}
	return esast.Query{Bool: boolQ}
}

func buildLuceneAtomQuery(token, defaultField string, fields []string) esast.Query {
	token = strings.Trim(token, "()")
	if idx := strings.IndexByte(token, ':'); idx > 0 {
		field := token[:idx]
		val := strings.Trim(token[idx+1:], `"`)
		if strings.EqualFold(val, "true") || strings.EqualFold(val, "false") {
			boolVal := strings.EqualFold(val, "true")
			return esast.Query{
				Term: map[string]esast.TermEntry{
					field: {Value: boolVal, Boost: 1.0},
				},
			}
		}
		if strings.ContainsAny(val, "*?") {
			return esast.Query{
				Wildcard: map[string]esast.WildcardEntry{
					field: {Value: val, CaseInsensitive: true},
				},
			}
		}
		return esast.Query{
			Match: map[string]esast.MatchEntry{
				field: {Query: val, Operator: "or", Boost: 1.0},
			},
		}
	}

	cleanVal := strings.Trim(token, `"`)
	if len(fields) > 0 {
		return esast.Query{
			MultiMatch: &esast.MultiMatchQuery{
				Query:  cleanVal,
				Fields: fields,
			},
		}
	}
	return esast.Query{
		Match: map[string]esast.MatchEntry{
			defaultField: {Query: cleanVal, Operator: "or", Boost: 1.0},
		},
	}
}

func tokenizeLucene(s string) []string {
	var out []string
	var curr strings.Builder
	inQuotes := false
	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
			curr.WriteRune(r)
		case ' ', '\t', '\n':
			if inQuotes {
				curr.WriteRune(r)
			} else if curr.Len() > 0 {
				out = append(out, curr.String())
				curr.Reset()
			}
		default:
			curr.WriteRune(r)
		}
	}
	if curr.Len() > 0 {
		out = append(out, curr.String())
	}
	return out
}
