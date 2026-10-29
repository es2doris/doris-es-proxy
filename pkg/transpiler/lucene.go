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
	"math"
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// compileQueryString compiles an ES `query_string` or `simple_query_string` query.
// When `Opts.UseDoris4SearchFunc` is enabled, it emits Apache Doris 4.0's native `SEARCH(...)`
// function; otherwise, it parses Lucene `field:value`, `AND`/`OR`/`NOT`, `+`/`-`, parenthesized
// groups, and wildcard clauses into standard Doris `MATCH_ANY` / `LIKE` / `=` predicates.
func (t *Transpiler) compileQueryString(qsq *esast.QueryStringQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	return t.compileQueryStringWithMode(qsq, scoring, nctx, false)
}

func (t *Transpiler) compileQueryStringWithMode(qsq *esast.QueryStringQuery, scoring bool, nctx *nestedCtx, isSimple bool) CompiledQuery {
	raw := strings.TrimSpace(qsq.Query)
	if raw == "" || raw == "*" || raw == "*:*" {
		return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	}

	var expandedFields []string
	hadExplicitWildcardFields := false
	for _, fpat := range qsq.Fields {
		basePat := strings.Split(fpat, "^")[0]
		if strings.ContainsAny(basePat, "*?") && t.Schema != nil {
			exp := t.Schema.ExpandFieldPattern(fpat)
			if len(exp) == 0 && basePat == "*" {
				expandedFields = append(expandedFields, "_all_text")
				continue
			}
			hadExplicitWildcardFields = true
			for _, bf := range exp {
				if bf.Boost != 1.0 {
					expandedFields = append(expandedFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
				} else {
					expandedFields = append(expandedFields, bf.Field)
				}
			}
		} else {
			expandedFields = append(expandedFields, fpat)
		}
	}

	defaultField := qsq.DefaultField
	if defaultField == "" {
		if len(expandedFields) > 0 {
			defaultField = strings.Split(expandedFields[0], "^")[0]
		} else if hadExplicitWildcardFields {
			defaultField = "__unmatched_wildcard__"
		} else {
			defaultField = "_all_text"
		}
	} else if strings.ContainsAny(defaultField, "*?") && t.Schema != nil {
		baseDef := strings.Split(defaultField, "^")[0]
		if exp := t.Schema.ExpandFieldPattern(defaultField); len(exp) > 0 {
			defaultField = exp[0].Field
			if len(expandedFields) == 0 {
				for _, bf := range exp {
					if bf.Boost != 1.0 {
						expandedFields = append(expandedFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
					} else {
						expandedFields = append(expandedFields, bf.Field)
					}
				}
			}
		} else if baseDef == "*" {
			defaultField = "_all_text"
		} else {
			defaultField = "__unmatched_wildcard__"
		}
	}
	defaultOp := strings.ToUpper(qsq.DefaultOperator)
	if defaultOp != "AND" {
		defaultOp = "OR"
	}

	parsedAST := parseSimpleLuceneToASTWithFlags(raw, defaultField, expandedFields, defaultOp, 0, isSimple, parseSimpleQueryFlags(qsq.Flags, isSimple))
	if qsq.MinimumShouldMatch != nil && parsedAST.Bool != nil && len(parsedAST.Bool.Should) > 0 {
		parsedAST.Bool.MinimumShouldMatch = qsq.MinimumShouldMatch
	}
	compiled := t.CompileQuery(&parsedAST, scoring, nctx)
	if scoring && qsq.Boost != nil && *qsq.Boost != 1.0 && compiled.ScoreSQL != "" && compiled.ScoreSQL != "0.0" {
		compiled.ScoreSQL = fmt.Sprintf("((%s) * %.4f)", compiled.ScoreSQL, *qsq.Boost)
	}
	if !isSimple {
		if rewrittenRaw, ok := t.rewriteDoris4SearchQuery(raw); ok && t.Opts.UseDoris4SearchFunc && nctx == nil && qsq.MinimumShouldMatch == nil && defaultField != "__unmatched_wildcard__" && !strings.ContainsAny(raw, "[{><~/^") && !strings.Contains(compiled.WhereSQL, "`_doc`[") && !strings.Contains(compiled.WhereSQL, "array_exists(") && !strings.Contains(compiled.EffectiveSafeWhere(), "array_exists(") && !strings.Contains(compiled.WhereSQL, "array_contains(") && !strings.Contains(compiled.WhereSQL, " LIKE ") && !strings.Contains(compiled.WhereSQL, "`n__") {
			if len(expandedFields) > 1 {
				if canEmitMultiFieldDoris4SearchDisjunction(rewrittenRaw, defaultOp) {
					var searchPreds []string
					allSupported := true
					for _, ef := range expandedFields {
						fname := strings.Split(ef, "^")[0]
						if t.isDoris4SearchableField(fname) {
							col := strings.Trim(t.sqlColumnRef(fname, false, nctx), "`")
							searchPreds = append(searchPreds, fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(rewrittenRaw), quoteStr(col), quoteStr(defaultOp)))
						} else {
							allSupported = false
							break
						}
					}
					if allSupported && len(searchPreds) > 0 {
						pred := strings.Join(searchPreds, " OR ")
						if len(searchPreds) > 1 {
							pred = "(" + pred + ")"
						}
						return CompiledQuery{
							WhereSQL:          pred,
							SafeWhereSQL:      compiled.EffectiveSafeWhere(),
							ScoreSQL:          compiled.ScoreSQL,
							UsesFulltextMatch: true,
						}
					}
				}
			} else if t.isDoris4SearchableField(defaultField) {
				col := strings.Trim(t.sqlColumnRef(defaultField, false, nctx), "`")
				pred := fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(rewrittenRaw), quoteStr(col), quoteStr(defaultOp))
				return CompiledQuery{
					WhereSQL:          pred,
					SafeWhereSQL:      compiled.EffectiveSafeWhere(),
					ScoreSQL:          compiled.ScoreSQL,
					UsesFulltextMatch: true,
				}
			}
		}
	}
	return compiled
}

func (t *Transpiler) rewriteDoris4SearchQuery(raw string) (string, bool) {
	if strings.Contains(raw, "_exists_:") || strings.Contains(raw, "&&") || strings.Contains(raw, "||") || strings.Contains(raw, "|") || strings.Contains(raw, "!") {
		return "", false
	}
	if !strings.Contains(raw, ":") {
		return raw, true
	}
	tokens := tokenizeLucene(raw)
	if len(tokens) == 0 {
		return raw, true
	}
	var out []string
	for _, tok := range tokens {
		prefix := ""
		rest := tok
		if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
			prefix = rest[:1]
			rest = rest[1:]
		}
		if hasMatchingOuterParens(rest) {
			innerRewritten, ok := t.rewriteDoris4SearchQuery(rest[1 : len(rest)-1])
			if !ok {
				return "", false
			}
			out = append(out, prefix+"("+innerRewritten+")")
			continue
		}
		if idx := findLuceneFieldColon(rest); idx > 0 {
			field := unescapeLuceneToken(rest[:idx])
			val := rest[idx+1:]
			if !t.isDoris4SearchableField(field) {
				return "", false
			}
			if hasMatchingOuterParens(val) && strings.Contains(val, ":") {
				return "", false
			}
			col := strings.Trim(t.sqlColumnRef(field, false, nil), "`")
			out = append(out, prefix+col+":"+val)
		} else {
			out = append(out, tok)
		}
	}
	return strings.Join(out, " "), true
}

func canEmitMultiFieldDoris4SearchDisjunction(rewrittenRaw string, defaultOp string) bool {
	tokens := tokenizeLucene(rewrittenRaw)
	clauseCount := 0
	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if upper == "AND" || tok == "&&" || upper == "NOT" || tok == "!" || tok == "+" || tok == "-" {
			return false
		}
		if upper == "OR" || tok == "||" || tok == "|" {
			continue
		}
		if strings.HasPrefix(tok, "+") || strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "!") {
			return false
		}
		if hasMatchingOuterParens(tok) && !canEmitMultiFieldDoris4SearchDisjunction(tok[1:len(tok)-1], defaultOp) {
			return false
		}
		clauseCount++
	}
	if defaultOp == "AND" && clauseCount > 1 {
		return false
	}
	return true
}

func (t *Transpiler) isDoris4SearchableField(fname string) bool {
	if fname == "_all_text" {
		return true
	}
	if t.Schema == nil {
		return false
	}
	b := t.Schema.ResolveField(fname)
	if b.LowercaseNormalizer {
		return false
	}
	return b.Kind == schema.StoragePromotedScalar && (b.DorisType == schema.DorisString || b.DorisType == schema.DorisVarchar)
}

const maxLuceneDepth = 32

type simpleQueryFlags struct {
	and        bool
	or         bool
	not        bool
	phrase     bool
	prefix     bool
	precedence bool
	fuzzy      bool
	slop       bool
}

func allSimpleQueryFlags() simpleQueryFlags {
	return simpleQueryFlags{
		and:        true,
		or:         true,
		not:        true,
		phrase:     true,
		prefix:     true,
		precedence: true,
		fuzzy:      true,
		slop:       true,
	}
}

func parseSimpleQueryFlags(raw string, isSimple bool) simpleQueryFlags {
	if !isSimple {
		return allSimpleQueryFlags()
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "ALL") {
		return allSimpleQueryFlags()
	}
	if strings.EqualFold(trimmed, "NONE") {
		return simpleQueryFlags{}
	}
	var f simpleQueryFlags
	for _, part := range strings.Split(trimmed, "|") {
		switch strings.ToUpper(strings.TrimSpace(part)) {
		case "AND":
			f.and = true
		case "OR":
			f.or = true
		case "NOT":
			f.not = true
		case "PHRASE":
			f.phrase = true
		case "PREFIX":
			f.prefix = true
		case "PRECEDENCE":
			f.precedence = true
		case "FUZZY":
			f.fuzzy = true
		case "SLOP", "NEAR":
			f.slop = true
		case "ALL":
			return allSimpleQueryFlags()
		}
	}
	return f
}

func isLuceneBinaryAnd(tok string, prevWasClause bool, isSimple bool, flags simpleQueryFlags) bool {
	if isSimple {
		if !flags.and {
			return false
		}
		return tok == "&&" || (tok == "+" && prevWasClause)
	}
	return strings.EqualFold(tok, "AND") || tok == "&&" || (tok == "+" && prevWasClause)
}

func isLuceneBinaryOr(tok string, isSimple bool, flags simpleQueryFlags) bool {
	if isSimple {
		if !flags.or {
			return false
		}
		return tok == "|" || tok == "||"
	}
	return strings.EqualFold(tok, "OR") || tok == "||" || tok == "|"
}

func isLuceneStandaloneNot(tok string, isSimple bool, flags simpleQueryFlags) bool {
	if isSimple {
		return flags.not && tok == "-"
	}
	return strings.EqualFold(tok, "NOT") || tok == "!" || tok == "-"
}

func isLuceneUnaryPrefixed(tok string, isSimple bool, flags simpleQueryFlags) bool {
	if len(tok) <= 1 {
		return false
	}
	if strings.HasPrefix(tok, "+") {
		return !isSimple || flags.and
	}
	if strings.HasPrefix(tok, "-") {
		return !isSimple || flags.not
	}
	if strings.HasPrefix(tok, "!") {
		return !isSimple
	}
	return false
}

func parseSimpleLuceneToASTWithDepth(expr, defaultField string, fields []string, defaultOp string, depth int) esast.Query {
	return parseSimpleLuceneToASTWithFlags(expr, defaultField, fields, defaultOp, depth, false, allSimpleQueryFlags())
}

func parseSimpleLuceneToASTWithFlags(expr, defaultField string, fields []string, defaultOp string, depth int, isSimple bool, flags simpleQueryFlags) esast.Query {
	if depth > maxLuceneDepth {
		return esast.Query{MatchAll: map[string]any{}}
	}
	tokens := tokenizeLuceneWithFlags(expr, isSimple, flags)
	if len(tokens) == 0 {
		return esast.Query{MatchAll: map[string]any{}}
	}
	return parseLuceneTokensToASTWithFlags(tokens, defaultField, fields, defaultOp, depth, isSimple, flags)
}

func parseLuceneTokensToASTWithFlags(tokens []string, defaultField string, fields []string, defaultOp string, depth int, isSimple bool, flags simpleQueryFlags) esast.Query {
	if depth > maxLuceneDepth || len(tokens) == 0 {
		return esast.Query{MatchAll: map[string]any{}}
	}

	// Pre-merge standalone unary prefix tokens ('+', '-', '!', 'NOT') with their operand token
	// before inserting synthetic 'OR' tokens so unattached unary clauses can be cleanly separated.
	var merged []string
	prevWasClause := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if isLuceneBinaryAnd(tok, prevWasClause, isSimple, flags) || isLuceneBinaryOr(tok, isSimple, flags) {
			merged = append(merged, tok)
			prevWasClause = false
			continue
		}
		if tok == "+" && !prevWasClause && (!isSimple || flags.and) && i+1 < len(tokens) {
			merged = append(merged, "+"+tokens[i+1])
			i++
			prevWasClause = true
			continue
		}
		if isLuceneStandaloneNot(tok, isSimple, flags) && i+1 < len(tokens) {
			merged = append(merged, "-"+tokens[i+1])
			i++
			prevWasClause = true
			continue
		}
		merged = append(merged, tok)
		prevWasClause = true
	}

	// Separate unattached unary tokens (+term, -term, !term not adjacent to explicit binary AND/OR)
	// from the remaining tokens BEFORE inserting synthetic ORs.
	var unattachedUnary []string
	var remaining []string
	for i, tok := range merged {
		isUnary := isLuceneUnaryPrefixed(tok, isSimple, flags)
		prevIsBin := i > 0 && (isLuceneBinaryAnd(merged[i-1], true, isSimple, flags) || isLuceneBinaryOr(merged[i-1], isSimple, flags))
		nextIsBin := i+1 < len(merged) && (isLuceneBinaryAnd(merged[i+1], true, isSimple, flags) || isLuceneBinaryOr(merged[i+1], isSimple, flags))
		if isUnary && !prevIsBin && !nextIsBin {
			unattachedUnary = append(unattachedUnary, tok)
		} else {
			remaining = append(remaining, tok)
		}
	}

	if len(unattachedUnary) > 0 && len(remaining) > 0 {
		uQ := parseLuceneTokenSliceWithFlags(unattachedUnary, defaultField, fields, defaultOp, defaultOp, depth+1, isSimple, flags)
		remQ := parseLuceneTokensToASTWithFlags(remaining, defaultField, fields, defaultOp, depth+1, isSimple, flags)
		outBool := &esast.BoolQuery{}
		if uQ.Bool != nil {
			outBool.Must = append(outBool.Must, uQ.Bool.Must...)
			outBool.MustNot = append(outBool.MustNot, uQ.Bool.MustNot...)
		}
		if remQ.Bool != nil {
			if defaultOp == "AND" && len(remQ.Bool.Must) == 0 && len(remQ.Bool.Filter) == 0 && len(remQ.Bool.MustNot) == 0 && len(remQ.Bool.Should) > 0 {
				remQ.Bool.MinimumShouldMatch = 1
				outBool.Must = append(outBool.Must, remQ)
			} else if defaultOp == "OR" && len(outBool.Must) > 0 && (len(remQ.Bool.Must) > 0 || len(remQ.Bool.MustNot) > 0 || len(remQ.Bool.Filter) > 0) {
				outBool.Should = append(outBool.Should, remQ)
			} else {
				outBool.Must = append(outBool.Must, remQ.Bool.Must...)
				outBool.MustNot = append(outBool.MustNot, remQ.Bool.MustNot...)
				outBool.Should = append(outBool.Should, remQ.Bool.Should...)
				outBool.Filter = append(outBool.Filter, remQ.Bool.Filter...)
			}
		}
		if len(outBool.Should) > 0 && len(outBool.Must) == 0 && len(outBool.Filter) == 0 {
			outBool.MinimumShouldMatch = 1
		}
		return esast.Query{Bool: outBool}
	}

	tokens = merged
	hasAND, hasOR, hasExplicitOR, hasUnary := false, false, false, false
	var normalizedTokens []string
	prevWasClause = false
	for _, tok := range tokens {
		if isLuceneBinaryAnd(tok, prevWasClause, isSimple, flags) {
			hasAND = true
			prevWasClause = false
			tok = "\x00AND"
		} else if isLuceneBinaryOr(tok, isSimple, flags) {
			hasOR = true
			hasExplicitOR = true
			prevWasClause = false
			tok = "\x00OR"
		} else if isLuceneStandaloneNot(tok, isSimple, flags) {
			hasUnary = true
			prevWasClause = false
			tok = "\x00NOT"
		} else {
			isUnaryPrefix := isLuceneUnaryPrefixed(tok, isSimple, flags)
			if isUnaryPrefix {
				hasUnary = true
			}
			if prevWasClause && defaultOp == "OR" && !isUnaryPrefix {
				normalizedTokens = append(normalizedTokens, "\x00OR")
				hasOR = true
			}
			prevWasClause = true
		}
		normalizedTokens = append(normalizedTokens, tok)
	}
	tokens = normalizedTokens

	// In Lucene grammar, `AND` (and unary `NOT`/`+`/`-`) binds tighter than `OR` (e.g., `a:1 AND b:2 OR c:3` -> `(a:1 AND b:2) OR c:3`).
	if (hasAND || defaultOp == "AND" || (hasExplicitOR && hasUnary)) && hasOR {
		var orGroups [][]string
		var curGroup []string
		for _, tok := range tokens {
			if tok == "\x00OR" {
				if len(curGroup) > 0 {
					orGroups = append(orGroups, curGroup)
					curGroup = nil
				}
			} else {
				curGroup = append(curGroup, tok)
			}
		}
		if len(curGroup) > 0 {
			orGroups = append(orGroups, curGroup)
		}
		if len(orGroups) > 1 {
			var shoulds []esast.Query
			for _, grp := range orGroups {
				shoulds = append(shoulds, parseLuceneTokenSliceWithFlags(grp, defaultField, fields, "AND", defaultOp, depth+1, isSimple, flags))
			}
			outBool := &esast.BoolQuery{Should: shoulds, MinimumShouldMatch: 1}
			return esast.Query{Bool: outBool}
		}
	}

	groupOp := defaultOp
	if hasAND {
		groupOp = "AND"
	} else if hasOR {
		groupOp = "OR"
	}
	return parseLuceneTokenSliceWithFlags(tokens, defaultField, fields, groupOp, defaultOp, depth, isSimple, flags)
}

func parseLuceneTokenSliceWithFlags(tokens []string, defaultField string, fields []string, groupOp string, defaultOp string, depth int, isSimple bool, flags simpleQueryFlags) esast.Query {
	boolQ := &esast.BoolQuery{}
	negateNext := false
	forceMustNext := false

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "\x00AND" || tok == "\x00OR" || isLuceneBinaryAnd(tok, true, isSimple, flags) || isLuceneBinaryOr(tok, isSimple, flags) {
			continue
		}
		if tok == "\x00NOT" || isLuceneStandaloneNot(tok, isSimple, flags) {
			negateNext = true
			continue
		}
		if tok == "+" && (!isSimple || flags.and) {
			forceMustNext = true
			continue
		}

		mustClause := forceMustNext
		forceMustNext = false
		if ((strings.HasPrefix(tok, "-") && (!isSimple || flags.not)) || (strings.HasPrefix(tok, "!") && !isSimple)) && len(tok) > 1 {
			negateNext = true
			tok = tok[1:]
		} else if strings.HasPrefix(tok, "+") && (!isSimple || flags.and) && len(tok) > 1 {
			mustClause = true
			tok = tok[1:]
		}
		if strings.TrimSpace(tok) == "" {
			continue
		}

		var clause esast.Query
		if (!isSimple || flags.precedence) && hasMatchingOuterParens(tok) {
			inner := tok[1 : len(tok)-1]
			clause = parseSimpleLuceneToASTWithFlags(inner, defaultField, fields, defaultOp, depth+1, isSimple, flags)
		} else {
			clause = buildLuceneAtomQueryWithFlags(tok, defaultField, fields, defaultOp, depth+1, isSimple, flags)
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
	if len(boolQ.Must) == 0 && len(boolQ.Should) == 0 && len(boolQ.Filter) == 0 && len(boolQ.MustNot) == 0 {
		return esast.Query{MatchAll: map[string]any{}}
	}
	if len(boolQ.Should) > 0 && len(boolQ.Must) == 0 && len(boolQ.Filter) == 0 && len(boolQ.MustNot) > 0 {
		boolQ.MinimumShouldMatch = 1
	}
	return esast.Query{Bool: boolQ}
}

func hasMatchingOuterParens(s string) bool {
	if len(s) <= 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	inQuotes := false
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		ch := s[i]
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i < len(s)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !inQuotes
}

func splitLuceneBoost(s string) (string, float64) {
	if idx := strings.LastIndexByte(s, '^'); idx > 0 && idx < len(s)-1 && s[idx-1] != '\\' {
		if b, err := strconv.ParseFloat(s[idx+1:], 64); err == nil && !math.IsNaN(b) && !math.IsInf(b, 0) && b > 0 {
			return s[:idx], b
		}
	}
	return s, 1.0
}

func unescapeLuceneToken(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func hasUnescapedLuceneWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

func parseLuceneQuotedOrFuzzy(raw string) (clean string, rawWildcard string, isQuoted bool, slop int) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, `"`) && len(s) >= 2 {
		if strings.HasSuffix(s, `"`) {
			inner := s[1 : len(s)-1]
			return unescapeLuceneToken(inner), inner, true, 0
		}
		if tildeIdx := strings.LastIndex(s, `"~`); tildeIdx > 0 {
			slopStr := s[tildeIdx+2:]
			if n, err := strconv.Atoi(slopStr); err == nil && n >= 0 {
				inner := s[1:tildeIdx]
				return unescapeLuceneToken(inner), inner, true, n
			}
		}
	}
	if tildeIdx := strings.LastIndexByte(s, '~'); tildeIdx > 0 && s[tildeIdx-1] != '\\' {
		suffix := s[tildeIdx+1:]
		if suffix == "" || strings.EqualFold(suffix, "auto") {
			s = s[:tildeIdx]
		} else if _, err := strconv.Atoi(suffix); err == nil {
			s = s[:tildeIdx]
		}
	}
	return unescapeLuceneToken(s), s, false, 0
}

func findLuceneFieldColon(s string) int {
	if len(s) == 0 || s[0] == '"' || s[0] == '(' || s[0] == '[' || s[0] == '{' || s[0] == '/' {
		return -1
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			i++
			continue
		}
		if c == '"' || c == '(' || c == '[' || c == '{' {
			return -1
		}
		if c == ':' && i > 0 && i < len(s)-1 {
			return i
		}
	}
	return -1
}

func parseLuceneRangeToken(val string, boost float64) *esast.RangeCond {
	for _, op := range []string{">=", "<=", ">", "<"} {
		if strings.HasPrefix(val, op) && len(val) > len(op) {
			boundStr := unescapeLuceneToken(strings.Trim(strings.TrimSpace(val[len(op):]), `"`))
			bound := parseLuceneRangeBound(boundStr)
			rc := &esast.RangeCond{}
			if boost != 1.0 {
				b := boost
				rc.Boost = &b
			}
			switch op {
			case ">=":
				rc.GTE = bound
			case "<=":
				rc.LTE = bound
			case ">":
				rc.GT = bound
			case "<":
				rc.LT = bound
			}
			return rc
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
			rc := &esast.RangeCond{}
			if boost != 1.0 {
				b := boost
				rc.Boost = &b
			}
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
			return rc
		}
	}
	return nil
}

func buildLuceneAtomQueryWithFlags(token, defaultField string, fields []string, defaultOp string, depth int, isSimple bool, flags simpleQueryFlags) esast.Query {
	token = strings.TrimSpace(token)
	token, boost := splitLuceneBoost(token)
	if (!isSimple || flags.precedence) && hasMatchingOuterParens(token) {
		inner := parseSimpleLuceneToASTWithFlags(token[1:len(token)-1], defaultField, fields, defaultOp, depth+1, isSimple, flags)
		if boost != 1.0 && inner.Bool != nil {
			inner.Bool.Boost = &boost
		}
		return inner
	}
	idx := -1
	if !isSimple {
		idx = findLuceneFieldColon(token)
	}
	if idx > 0 {
		field := unescapeLuceneToken(token[:idx])
		val := strings.TrimSpace(token[idx+1:])
		if field == "_exists_" && val != "" {
			return esast.Query{
				Exists: &esast.ExistsQuery{Field: unescapeLuceneToken(strings.Trim(val, `"`))},
			}
		}
		if rc := parseLuceneRangeToken(val, boost); rc != nil {
			return esast.Query{
				Range: map[string]esast.RangeCond{field: *rc},
			}
		}
		if strings.HasPrefix(val, "/") && strings.HasSuffix(val, "/") && len(val) > 2 {
			return esast.Query{
				Regexp: map[string]esast.RegexpEntry{
					field: {Value: strings.ReplaceAll(val[1:len(val)-1], `\/`, `/`), Boost: boost},
				},
			}
		}
		if hasMatchingOuterParens(val) {
			var subFields []string
			subDefault := field
			if strings.ContainsAny(field, "*?") {
				subFields = []string{field}
				subDefault = defaultField
			}
			inner := parseSimpleLuceneToASTWithDepth(val[1:len(val)-1], subDefault, subFields, defaultOp, depth+1)
			if boost != 1.0 && inner.Bool != nil {
				b := boost
				inner.Bool.Boost = &b
			}
			return inner
		}
		val, rawWild, isQuoted, slop := parseLuceneQuotedOrFuzzy(val)
		if !isQuoted && (strings.EqualFold(val, "true") || strings.EqualFold(val, "false")) {
			boolVal := strings.EqualFold(val, "true")
			return esast.Query{
				Term: map[string]esast.TermEntry{
					field: {Value: boolVal, Boost: boost},
				},
			}
		}
		if !isQuoted && hasUnescapedLuceneWildcard(rawWild) {
			return esast.Query{
				Wildcard: map[string]esast.WildcardEntry{
					field: {Value: rawWild, CaseInsensitive: true, Boost: boost},
				},
			}
		}
		if strings.ContainsAny(field, "*?") {
			b := boost
			qType := "best_fields"
			if isQuoted && (strings.Contains(val, " ") || slop > 0) {
				qType = "phrase"
			}
			return esast.Query{
				MultiMatch: &esast.MultiMatchQuery{
					Query:    val,
					Fields:   []string{field},
					Type:     qType,
					Operator: strings.ToLower(defaultOp),
					Slop:     slop,
					Boost:    &b,
				},
			}
		}
		if isQuoted && (strings.Contains(val, " ") || slop > 0) {
			return esast.Query{
				MatchPhrase: map[string]esast.PhraseEntry{
					field: {Query: val, Slop: slop, Boost: boost},
				},
			}
		}
		return esast.Query{
			Match: map[string]esast.MatchEntry{
				field: {Query: val, Operator: strings.ToLower(defaultOp), Boost: boost},
			},
		}
	}

	if len(fields) == 0 && defaultField == "__unmatched_wildcard__" {
		return esast.Query{MatchNone: map[string]any{}}
	}

	if !isSimple {
		if rc := parseLuceneRangeToken(token, boost); rc != nil {
			if len(fields) > 0 {
				var shoulds []esast.Query
				for _, fpat := range fields {
					fname, fBoost := splitLuceneBoost(fpat)
					rcCopy := *rc
					effBoost := boost * fBoost
					if effBoost != 1.0 {
						rcCopy.Boost = &effBoost
					}
					shoulds = append(shoulds, esast.Query{
						Range: map[string]esast.RangeCond{fname: rcCopy},
					})
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				if len(shoulds) > 1 {
					return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
				}
			}
			return esast.Query{
				Range: map[string]esast.RangeCond{defaultField: *rc},
			}
		}
		if strings.HasPrefix(token, "/") && strings.HasSuffix(token, "/") && len(token) > 2 {
			pat := strings.ReplaceAll(token[1:len(token)-1], `\/`, `/`)
			if len(fields) > 0 {
				var shoulds []esast.Query
				for _, fpat := range fields {
					fname, fBoost := splitLuceneBoost(fpat)
					shoulds = append(shoulds, esast.Query{
						Regexp: map[string]esast.RegexpEntry{
							fname: {Value: pat, Boost: boost * fBoost},
						},
					})
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				if len(shoulds) > 1 {
					return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
				}
			}
			return esast.Query{
				Regexp: map[string]esast.RegexpEntry{
					defaultField: {Value: pat, Boost: boost},
				},
			}
		}
	}
	cleanVal, rawWild, isQuoted, slop := parseLuceneQuotedOrFuzzy(token)
	if isSimple {
		if !flags.phrase {
			isQuoted = false
			slop = 0
		} else if !flags.slop {
			slop = 0
		}
		if !flags.fuzzy && !isQuoted {
			cleanVal = unescapeLuceneToken(strings.TrimSpace(token))
			rawWild = strings.TrimSpace(token)
		}
	}
	if !isQuoted && (!isSimple || flags.prefix) && hasUnescapedLuceneWildcard(rawWild) {
		if len(fields) > 0 {
			var shoulds []esast.Query
			for _, fpat := range fields {
				fname, fBoost := splitLuceneBoost(fpat)
				shoulds = append(shoulds, esast.Query{
					Wildcard: map[string]esast.WildcardEntry{
						fname: {Value: rawWild, CaseInsensitive: true, Boost: boost * fBoost},
					},
				})
			}
			if len(shoulds) == 1 {
				return shoulds[0]
			}
			if len(shoulds) > 1 {
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
		}
		return esast.Query{
			Wildcard: map[string]esast.WildcardEntry{
				defaultField: {Value: rawWild, CaseInsensitive: true, Boost: boost},
			},
		}
	}

	if isQuoted && (strings.Contains(cleanVal, " ") || slop > 0) {
		if len(fields) > 0 {
			return esast.Query{
				MultiMatch: &esast.MultiMatchQuery{
					Query:  cleanVal,
					Fields: fields,
					Type:   "phrase",
					Slop:   slop,
					Boost:  &boost,
				},
			}
		}
		return esast.Query{
			MatchPhrase: map[string]esast.PhraseEntry{
				defaultField: {Query: cleanVal, Slop: slop, Boost: boost},
			},
		}
	}

	if len(fields) > 0 {
		return esast.Query{
			MultiMatch: &esast.MultiMatchQuery{
				Query:    cleanVal,
				Fields:   fields,
				Operator: strings.ToLower(defaultOp),
				Boost:    &boost,
			},
		}
	}
	return esast.Query{
		Match: map[string]esast.MatchEntry{
			defaultField: {Query: cleanVal, Operator: strings.ToLower(defaultOp), Boost: boost},
		},
	}
}

func parseLuceneRangeBound(s string) any {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return f
	}
	return s
}

// sanitizeSimpleQueryInput strips unmatched quotes and unmatched parentheses in
// fault-tolerant `simple_query_string` mode so stray '"' or '(' never swallow tokens to EOF.
func sanitizeSimpleQueryInput(s string, flags simpleQueryFlags) string {
	var quoteIndices []int
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == '"' {
			quoteIndices = append(quoteIndices, i)
		}
	}
	dropIdx := make(map[int]bool)
	if !flags.phrase {
		for _, idx := range quoteIndices {
			dropIdx[idx] = true
		}
	} else if len(quoteIndices)%2 == 1 {
		dropIdx[quoteIndices[len(quoteIndices)-1]] = true
	}

	var openParens []int
	inQuotes := false
	escaped = false
	for i := 0; i < len(s); i++ {
		if dropIdx[i] {
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == '"' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch s[i] {
		case '(':
			if !flags.precedence {
				dropIdx[i] = true
			} else {
				openParens = append(openParens, i)
			}
		case ')':
			if !flags.precedence || len(openParens) == 0 {
				dropIdx[i] = true
			} else {
				openParens = openParens[:len(openParens)-1]
			}
		}
	}
	for _, idx := range openParens {
		dropIdx[idx] = true
	}
	if len(dropIdx) == 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if dropIdx[i] {
			if s[i] == '(' || s[i] == ')' {
				sb.WriteByte(' ')
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func tokenizeLucene(s string) []string {
	return tokenizeLuceneWithFlags(s, false, allSimpleQueryFlags())
}

func tokenizeLuceneWithFlags(s string, isSimple bool, flags simpleQueryFlags) []string {
	if isSimple {
		s = sanitizeSimpleQueryInput(s, flags)
	}
	var out []string
	var curr strings.Builder
	inQuotes := false
	inRegex := false
	escaped := false
	parenDepth := 0
	bracketDepth := 0
	for i, r := range s {
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
			if !inRegex && (!isSimple || flags.phrase) {
				inQuotes = !inQuotes
			}
			curr.WriteRune(r)
		case '/':
			if !isSimple && !inQuotes && bracketDepth == 0 {
				if inRegex {
					inRegex = false
				} else if (curr.Len() == 0 || strings.HasSuffix(curr.String(), ":")) && strings.ContainsRune(s[i+1:], '/') {
					inRegex = true
				}
			}
			curr.WriteRune(r)
		case '(':
			if !inQuotes && !inRegex && (!isSimple || flags.precedence) {
				if parenDepth == 0 && bracketDepth == 0 && curr.Len() > 0 {
					prefix := curr.String()
					if prefix != "+" && prefix != "-" && prefix != "!" && !strings.HasSuffix(prefix, ":") {
						out = append(out, prefix)
						curr.Reset()
					}
				}
				parenDepth++
			}
			curr.WriteRune(r)
		case ')':
			if !inQuotes && !inRegex && (!isSimple || flags.precedence) && parenDepth > 0 {
				parenDepth--
				curr.WriteRune(r)
				if parenDepth == 0 && bracketDepth == 0 && (i+1 >= len(s) || s[i+1] != '^') {
					tokStr := curr.String()
					trimmedTok := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(tokStr, "+"), "-"), "!")
					colonIdx := findLuceneFieldColon(trimmedTok)
					if hasMatchingOuterParens(trimmedTok) || (colonIdx > 0 && hasMatchingOuterParens(trimmedTok[colonIdx+1:])) {
						out = append(out, tokStr)
						curr.Reset()
					}
				}
				continue
			}
			curr.WriteRune(r)
		case '[', '{':
			if !isSimple && !inQuotes && !inRegex {
				bracketDepth++
			}
			curr.WriteRune(r)
		case ']', '}':
			if !isSimple && !inQuotes && !inRegex && bracketDepth > 0 {
				bracketDepth--
			}
			curr.WriteRune(r)
		case ' ', '\t', '\n':
			if inQuotes || inRegex || parenDepth > 0 || bracketDepth > 0 {
				curr.WriteRune(r)
			} else if curr.Len() > 0 {
				out = append(out, curr.String())
				curr.Reset()
			}
		case '|':
			if inQuotes || inRegex || parenDepth > 0 || bracketDepth > 0 || (isSimple && !flags.or) {
				curr.WriteRune(r)
			} else {
				if curr.String() == "|" {
					out = append(out, "||")
					curr.Reset()
				} else {
					if curr.Len() > 0 {
						out = append(out, curr.String())
						curr.Reset()
					}
					if i+1 < len(s) && s[i+1] == '|' {
						curr.WriteRune('|')
					} else {
						out = append(out, "|")
					}
				}
			}
		case '&':
			if inQuotes || inRegex || parenDepth > 0 || bracketDepth > 0 || (isSimple && !flags.and) {
				curr.WriteRune(r)
			} else if curr.String() == "&" {
				out = append(out, "&&")
				curr.Reset()
			} else if i+1 < len(s) && s[i+1] == '&' {
				if curr.Len() > 0 {
					out = append(out, curr.String())
					curr.Reset()
				}
				curr.WriteRune('&')
			} else {
				curr.WriteRune(r)
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
