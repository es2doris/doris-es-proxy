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
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// compileQueryString compiles an ES `query_string` or `simple_query_string` query.
// When `Opts.UseDoris4SearchFunc` is enabled, it emits Apache Doris 4.0's native `SEARCH(...)`
// function; otherwise, it parses Lucene `field:value`, `AND`/`OR`/`NOT`, `+`/`-`, parenthesized
// groups, and wildcard clauses into standard Doris `MATCH_ANY` / `LIKE` / `=` predicates.
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

	parsedAST := parseSimpleLuceneToAST(raw, defaultField, qsq.Fields, defaultOp)
	compiled := t.CompileQuery(&parsedAST, scoring, nctx)
	if t.Opts.UseDoris4SearchFunc {
		col := strings.Trim(t.sqlColumnRef(defaultField, false, nctx), "`")
		pred := fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(raw), quoteStr(col), quoteStr(defaultOp))
		return CompiledQuery{
			WhereSQL:          pred,
			ScoreSQL:          compiled.ScoreSQL,
			UsesFulltextMatch: true,
		}
	}
	return compiled
}

const maxLuceneDepth = 32

func parseSimpleLuceneToAST(expr, defaultField string, fields []string, defaultOp string) esast.Query {
	return parseSimpleLuceneToASTWithDepth(expr, defaultField, fields, defaultOp, 0)
}

func parseSimpleLuceneToASTWithDepth(expr, defaultField string, fields []string, defaultOp string, depth int) esast.Query {
	if depth > maxLuceneDepth {
		return esast.Query{MatchAll: map[string]any{}}
	}
	tokens := tokenizeLucene(expr)
	if len(tokens) == 0 {
		return esast.Query{MatchAll: map[string]any{}}
	}

	// Determine effective boolean operator for this group if explicit AND / OR tokens exist
	groupOp := defaultOp
	for _, tok := range tokens {
		switch strings.ToUpper(tok) {
		case "AND":
			groupOp = "AND"
		case "OR":
			groupOp = "OR"
		}
	}

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

		mustClause := false
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negateNext = true
			tok = tok[1:]
		} else if strings.HasPrefix(tok, "+") && len(tok) > 1 {
			mustClause = true
			tok = tok[1:]
		}

		var clause esast.Query
		if strings.HasPrefix(tok, "(") && strings.HasSuffix(tok, ")") && len(tok) > 2 {
			inner := tok[1 : len(tok)-1]
			clause = parseSimpleLuceneToASTWithDepth(inner, defaultField, fields, defaultOp, depth+1)
		} else {
			clause = buildLuceneAtomQueryWithDepth(tok, defaultField, fields, depth+1)
		}

		if negateNext {
			boolQ.MustNot = append(boolQ.MustNot, clause)
			negateNext = false
		} else if mustClause || groupOp == "AND" {
			boolQ.Must = append(boolQ.Must, clause)
		} else {
			boolQ.Should = append(boolQ.Should, clause)
		}
	}
	return esast.Query{Bool: boolQ}
}

func buildLuceneAtomQueryWithDepth(token, defaultField string, fields []string, depth int) esast.Query {
	token = strings.TrimSpace(token)
	if idx := strings.IndexByte(token, ':'); idx > 0 {
		field := token[:idx]
		val := strings.TrimSpace(token[idx+1:])
		if field == "_exists_" && val != "" {
			return esast.Query{
				Exists: &esast.ExistsQuery{Field: strings.Trim(val, `"`)},
			}
		}
		if (strings.HasPrefix(val, "[") || strings.HasPrefix(val, "{")) &&
			(strings.HasSuffix(val, "]") || strings.HasSuffix(val, "}")) && len(val) > 2 {
			incLower := strings.HasPrefix(val, "[")
			incUpper := strings.HasSuffix(val, "]")
			inner := strings.TrimSpace(val[1 : len(val)-1])
			parts := strings.Split(inner, " TO ")
			if len(parts) != 2 {
				parts = strings.Split(inner, " to ")
			}
			if len(parts) == 2 {
				lowerStr := strings.Trim(strings.TrimSpace(parts[0]), `"`)
				upperStr := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				var rc esast.RangeCond
				if lowerStr != "" && lowerStr != "*" {
					bound := parseLuceneRangeBound(lowerStr)
					if incLower {
						rc.GTE = bound
					} else {
						rc.GT = bound
					}
				}
				if upperStr != "" && upperStr != "*" {
					bound := parseLuceneRangeBound(upperStr)
					if incUpper {
						rc.LTE = bound
					} else {
						rc.LT = bound
					}
				}
				return esast.Query{
					Range: map[string]esast.RangeCond{field: rc},
				}
			}
		}
		if strings.HasPrefix(val, "(") && strings.HasSuffix(val, ")") && len(val) > 2 {
			return parseSimpleLuceneToASTWithDepth(val[1:len(val)-1], field, nil, "OR", depth+1)
		}
		isQuoted := strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) && len(val) >= 2
		val = strings.Trim(val, `"`)
		if strings.EqualFold(val, "true") || strings.EqualFold(val, "false") {
			boolVal := strings.EqualFold(val, "true")
			return esast.Query{
				Term: map[string]esast.TermEntry{
					field: {Value: boolVal, Boost: 1.0},
				},
			}
		}
		if !isQuoted && strings.ContainsAny(val, "*?") {
			return esast.Query{
				Wildcard: map[string]esast.WildcardEntry{
					field: {Value: val, CaseInsensitive: true},
				},
			}
		}
		if isQuoted && strings.Contains(val, " ") {
			return esast.Query{
				MatchPhrase: map[string]esast.PhraseEntry{
					field: {Query: val, Boost: 1.0},
				},
			}
		}
		return esast.Query{
			Match: map[string]esast.MatchEntry{
				field: {Query: val, Operator: "or", Boost: 1.0},
			},
		}
	}

	isQuoted := strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`) && len(token) >= 2
	cleanVal := strings.Trim(token, `"`)
	if !isQuoted && strings.ContainsAny(cleanVal, "*?") {
		if len(fields) > 0 {
			var shoulds []esast.Query
			for _, fpat := range fields {
				fname := strings.Split(fpat, "^")[0]
				if !strings.Contains(fname, "*") {
					shoulds = append(shoulds, esast.Query{
						Wildcard: map[string]esast.WildcardEntry{
							fname: {Value: cleanVal, CaseInsensitive: true},
						},
					})
				}
			}
			if len(shoulds) > 0 {
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
		}
		return esast.Query{
			Wildcard: map[string]esast.WildcardEntry{
				defaultField: {Value: cleanVal, CaseInsensitive: true},
			},
		}
	}

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

func parseLuceneRangeBound(s string) any {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func tokenizeLucene(s string) []string {
	var out []string
	var curr strings.Builder
	inQuotes := false
	escaped := false
	parenDepth := 0
	bracketDepth := 0
	for _, r := range s {
		if escaped {
			curr.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
			curr.WriteRune(r)
		case '"':
			inQuotes = !inQuotes
			curr.WriteRune(r)
		case '(':
			if !inQuotes {
				parenDepth++
			}
			curr.WriteRune(r)
		case ')':
			if !inQuotes && parenDepth > 0 {
				parenDepth--
			}
			curr.WriteRune(r)
		case '[', '{':
			if !inQuotes {
				bracketDepth++
			}
			curr.WriteRune(r)
		case ']', '}':
			if !inQuotes && bracketDepth > 0 {
				bracketDepth--
			}
			curr.WriteRune(r)
		case ' ', '\t', '\n':
			if inQuotes || parenDepth > 0 || bracketDepth > 0 {
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
