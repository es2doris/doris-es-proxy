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
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// compileQueryStringWithMode compiles an ES `query_string` or `simple_query_string` query.
// When `Opts.UseDoris4SearchFunc` is enabled, it emits Apache Doris 4.0's native `SEARCH(...)`
// function; otherwise, it parses Lucene `field:value`, `AND`/`OR`/`NOT`, `+`/`-`, parenthesized
// groups, and wildcard clauses into standard Doris `MATCH_ANY` / `LIKE` / `=` predicates.
func (t *Transpiler) compileQueryStringWithMode(qsq *esast.QueryStringQuery, scoring bool, nctx *nestedCtx, isSimple bool) CompiledQuery {
	raw := strings.TrimSpace(qsq.Query)
	allowLeading := isSimple || qsq.AllowLeadingWildcard == nil || *qsq.AllowLeadingWildcard
	if raw == "" || raw == "*:*" || (allowLeading && raw == "*" && (qsq.DefaultField == "" || qsq.DefaultField == "*" || qsq.DefaultField == "_all_text") && len(qsq.Fields) == 0) {
		if raw == "" && strings.EqualFold(strings.TrimSpace(qsq.ZeroTermsQuery), "none") {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		score := "1.0"
		if scoring && qsq.Boost != nil {
			score = fmt.Sprintf("%.4f", *qsq.Boost)
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: score}
	}

	var expandedFields []string
	hadExplicitWildcardFields := false
	for _, fpat := range qsq.Fields {
		basePat := strings.Split(fpat, "^")[0]
		if strings.ContainsAny(basePat, "*?") && t.Schema != nil {
			exp := t.expandFieldPatternForContext(fpat, nctx)
			if len(exp) == 0 && basePat == "*" && nctx == nil {
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
		} else if nctx != nil && t.Schema != nil {
			if exp := t.expandFieldPatternForContext("*", nctx); len(exp) > 0 {
				defaultField = exp[0].Field
				for _, bf := range exp {
					if bf.Boost != 1.0 {
						expandedFields = append(expandedFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
					} else {
						expandedFields = append(expandedFields, bf.Field)
					}
				}
			} else {
				defaultField = "_all_text"
			}
		} else {
			defaultField = "_all_text"
		}
	} else if strings.ContainsAny(defaultField, "*?") && t.Schema != nil {
		baseDef := strings.Split(defaultField, "^")[0]
		if exp := t.expandFieldPatternForContext(defaultField, nctx); len(exp) > 0 {
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
		} else if baseDef == "*" && nctx == nil {
			defaultField = "_all_text"
		} else {
			defaultField = "__unmatched_wildcard__"
		}
	}
	defaultOp := strings.ToUpper(qsq.DefaultOperator)
	if defaultOp == "" {
		defaultOp = strings.ToUpper(qsq.Operator)
	}
	if defaultOp != "AND" {
		defaultOp = "OR"
	}

	flags := parseSimpleQueryFlags(qsq.Flags, isSimple)
	if !isSimple && qsq.SplitOnWhitespace != nil && !*qsq.SplitOnWhitespace {
		flags.whitespace = false
	}
	if !isSimple && qsq.Escape != nil && *qsq.Escape {
		raw = escapeAllLuceneSpecialChars(raw)
	}
	flags.quoteFieldSuffix = strings.TrimSpace(qsq.QuoteFieldSuffix)
	flags.timeZone = strings.TrimSpace(qsq.TimeZone)
	flags.queryType = strings.TrimSpace(qsq.Type)
	flags.tieBreaker = qsq.TieBreaker
	flags.phraseSlop = qsq.PhraseSlop
	flags.fuzziness = qsq.Fuzziness
	flags.fuzzyPrefixLength = qsq.FuzzyPrefixLength
	flags.fuzzyMaxExpansions = qsq.FuzzyMaxExpansions
	flags.fuzzyTranspositions = qsq.FuzzyTranspositions
	flags.allowLeadingWildcard = qsq.AllowLeadingWildcard
	flags.analyzer = strings.TrimSpace(qsq.Analyzer)
	flags.quoteAnalyzer = strings.TrimSpace(qsq.QuoteAnalyzer)
	flags.zeroTermsQuery = strings.TrimSpace(qsq.ZeroTermsQuery)
	flags.lenient = qsq.Lenient
	if t.Schema != nil {
		flags.isTextField = func(fname string) bool {
			if fname == "_all_text" {
				return true
			}
			_, b := t.resolveFieldInNestedCtx(fname, false, nctx)
			return schema.IsTextLikeESType(b.ESType)
		}
		flags.expandFields = func(pat string) []string {
			exp := t.expandFieldPatternForContext(pat, nctx)
			out := make([]string, 0, len(exp))
			for _, bf := range exp {
				if bf.Boost != 1.0 {
					out = append(out, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
				} else {
					out = append(out, bf.Field)
				}
			}
			return out
		}
	}
	if !isSimple && qsq.AllowLeadingWildcard != nil && !*qsq.AllowLeadingWildcard && hasLeadingLuceneWildcard(raw, flags) {
		if qsq.Lenient == nil || !*qsq.Lenient {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("query_shard_exception: Leading wildcard is not allowed in query_string when allow_leading_wildcard is false")
			}
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if !isSimple && (qsq.Lenient == nil || !*qsq.Lenient) && hasUnclosedLuceneRange(raw) {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("parse_exception: failed to parse query [%s]: unclosed range query", qsq.Query)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if !isSimple && (qsq.Lenient == nil || !*qsq.Lenient) && (qsq.Escape == nil || !*qsq.Escape) {
		if syntaxErr := validateStrictLuceneQuery(raw); syntaxErr != nil {
			if t.searchErr == nil {
				t.searchErr = syntaxErr
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}
	parsedAST := parseSimpleLuceneToASTWithFlags(raw, defaultField, expandedFields, defaultOp, 0, isSimple, flags)
	if qsq.MinimumShouldMatch != nil && parsedAST.Bool != nil {
		if len(parsedAST.Bool.Should) > 0 {
			if len(parsedAST.Bool.Should) == 1 && parsedAST.Bool.Should[0].Bool != nil && len(parsedAST.Bool.Should[0].Bool.Should) > 0 && len(parsedAST.Bool.Must) == 0 && len(parsedAST.Bool.Filter) == 0 {
				parsedAST.Bool.Should[0].Bool.MinimumShouldMatch = qsq.MinimumShouldMatch
			} else {
				parsedAST.Bool.MinimumShouldMatch = qsq.MinimumShouldMatch
			}
		} else if len(parsedAST.Bool.Must) == 1 && parsedAST.Bool.Must[0].Bool != nil && len(parsedAST.Bool.Must[0].Bool.Should) > 0 && len(parsedAST.Bool.Filter) == 0 {
			parsedAST.Bool.Must[0].Bool.MinimumShouldMatch = qsq.MinimumShouldMatch
		}
	}
	prevLenient := t.inLenientQuery
	if qsq.Lenient != nil && *qsq.Lenient {
		t.inLenientQuery = true
	}
	compiled := t.CompileQuery(&parsedAST, scoring, nctx)
	t.inLenientQuery = prevLenient
	if scoring && qsq.Boost != nil && *qsq.Boost != 1.0 && compiled.ScoreSQL != "" && compiled.ScoreSQL != "0.0" {
		compiled.ScoreSQL = fmt.Sprintf("((%s) * %.4f)", compiled.ScoreSQL, *qsq.Boost)
	}
	if !isSimple && flags.whitespace && (flags.queryType == "" || flags.queryType == "best_fields" || flags.queryType == "most_fields") && flags.quoteFieldSuffix == "" && flags.timeZone == "" && flags.phraseSlop == 0 && flags.fuzziness == nil && flags.fuzzyPrefixLength == 0 && flags.fuzzyMaxExpansions == 0 && flags.analyzer == "" && flags.quoteAnalyzer == "" && flags.zeroTermsQuery == "" && flags.escape && (flags.lenient == nil || !*flags.lenient) && compiled.WhereSQL != "FALSE" {
		if rewrittenRaw, ok := t.rewriteDoris4SearchQuery(raw); ok && t.Opts.UseDoris4SearchFunc && nctx == nil && qsq.MinimumShouldMatch == nil && defaultField != "__unmatched_wildcard__" && !strings.ContainsAny(raw, "[{><~/^\\") && !strings.Contains(compiled.WhereSQL, "`_doc`[") && !strings.Contains(compiled.WhereSQL, "array_exists(") && !strings.Contains(compiled.EffectiveSafeWhere(), "array_exists(") && !strings.Contains(compiled.WhereSQL, "array_contains(") && !strings.Contains(compiled.WhereSQL, " LIKE ") && !strings.Contains(compiled.WhereSQL, "`n__") && !strings.Contains(compiled.WhereSQL, " IS NOT NULL") && !strings.Contains(compiled.WhereSQL, "array_size(") {
			if len(expandedFields) > 1 {
				if canEmitMultiFieldDoris4SearchDisjunction(rewrittenRaw, defaultOp) {
					var searchPreds []string
					allSupported := true
					for _, ef := range expandedFields {
						fname := strings.Split(ef, "^")[0]
						fb := schema.FieldBinding{}
						if t.Schema != nil {
							fb = t.Schema.ResolveEffectiveField(fname, false)
						}
						if t.isDoris4SearchableField(fname) && (t.Schema == nil || !isExactKeywordField(fname, fb) || (!strings.Contains(raw, `"`) && !strings.ContainsAny(raw, "+-") && (!fb.EffectiveLowercase(true) || strings.ToLower(raw) == raw) && (strings.Contains(raw, ":") || !strings.ContainsAny(strings.TrimSpace(raw), " \t\n\r")))) {
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
				} else if hasOnlyFieldedDoris4Clauses(rewrittenRaw) {
					col := "_all_text"
					for _, ef := range expandedFields {
						fname := strings.Split(ef, "^")[0]
						if t.isDoris4SearchableField(fname) {
							col = strings.Trim(t.sqlColumnRef(fname, false, nctx), "`")
							break
						}
					}
					pred := fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(rewrittenRaw), quoteStr(col), quoteStr(defaultOp))
					return CompiledQuery{
						WhereSQL:          pred,
						SafeWhereSQL:      compiled.EffectiveSafeWhere(),
						ScoreSQL:          compiled.ScoreSQL,
						UsesFulltextMatch: true,
					}
				}
			} else if hasOnlyFieldedDoris4Clauses(rewrittenRaw) {
				col := "_all_text"
				if t.isDoris4SearchableField(defaultField) {
					col = strings.Trim(t.sqlColumnRef(defaultField, false, nctx), "`")
				}
				pred := fmt.Sprintf("SEARCH(%s, %s, %s)", quoteStr(rewrittenRaw), quoteStr(col), quoteStr(defaultOp))
				return CompiledQuery{
					WhereSQL:          pred,
					SafeWhereSQL:      compiled.EffectiveSafeWhere(),
					ScoreSQL:          compiled.ScoreSQL,
					UsesFulltextMatch: true,
				}
			} else if t.isDoris4SearchableField(defaultField) &&
				(t.Schema == nil || t.Schema.ResolveEffectiveField(defaultField, false).IgnoreAbove <= 0 || len([]rune(strings.TrimSpace(raw))) <= t.Schema.ResolveEffectiveField(defaultField, false).IgnoreAbove) &&
				(t.Schema == nil || !isExactKeywordField(defaultField, t.Schema.ResolveEffectiveField(defaultField, false)) || (!strings.Contains(raw, `"`) && !strings.ContainsAny(raw, "+-") && (strings.Contains(raw, ":") || ((!t.Schema.ResolveEffectiveField(defaultField, false).EffectiveLowercase(true) || strings.ToLower(raw) == raw) && !strings.ContainsAny(strings.TrimSpace(raw), " \t\n\r"))))) {
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
	if strings.Contains(raw, "_exists_:") || strings.Contains(raw, "&&") || strings.Contains(raw, "||") || strings.Contains(raw, "|") || strings.Contains(raw, "!") || strings.Contains(raw, `\`) {
		return "", false
	}
	tokens := tokenizeLucene(raw)
	if len(tokens) == 0 {
		return raw, true
	}
	isBoolBinOp := func(tok string) bool {
		u := strings.ToUpper(tok)
		return u == "AND" || u == "OR"
	}
	isBoolUnaryOrBinOp := func(tok string) bool {
		u := strings.ToUpper(tok)
		return u == "AND" || u == "OR" || u == "NOT" || tok == "+" || tok == "-"
	}
	if isBoolBinOp(tokens[0]) || isBoolUnaryOrBinOp(tokens[len(tokens)-1]) {
		return "", false
	}
	for i := range tokens {
		if tokens[i] == "+" || tokens[i] == "-" {
			return "", false
		}
		rest := strings.TrimLeft(tokens[i], "+-")
		if len(tokens[i])-len(rest) > 1 || (len(tokens[i]) > len(rest) && isBoolUnaryOrBinOp(rest)) {
			return "", false
		}
		if i < len(tokens)-1 {
			if isBoolBinOp(tokens[i]) && isBoolBinOp(tokens[i+1]) {
				return "", false
			}
			if strings.EqualFold(tokens[i], "NOT") && isBoolUnaryOrBinOp(tokens[i+1]) {
				return "", false
			}
		}
	}
	if !strings.Contains(raw, ":") {
		for _, tok := range tokens {
			rest := strings.TrimLeft(tok, "+-")
			if hasMatchingOuterParens(rest) {
				if _, ok := t.rewriteDoris4SearchQuery(rest[1 : len(rest)-1]); !ok {
					return "", false
				}
			}
		}
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
			if val == "" || hasMatchingOuterParens(val) || strings.HasPrefix(val, "+") || strings.HasPrefix(val, "-") || strings.HasPrefix(val, "!") {
				return "", false
			}
			if !t.isDoris4SearchableField(field) {
				return "", false
			}
			if t.Schema != nil {
				fb := t.Schema.ResolveEffectiveField(field, false)
				if isExactKeywordField(field, fb) && (prefix != "" || strings.Contains(val, `"`) || (fb.EffectiveLowercase(true) && strings.ToLower(val) != val)) {
					return "", false
				}
				if fb.IgnoreAbove > 0 && len([]rune(strings.Trim(val, `"`))) > fb.IgnoreAbove {
					return "", false
				}
			}
			col := strings.Trim(t.sqlColumnRef(field, false, nil), "`")
			out = append(out, prefix+col+":"+val)
		} else {
			out = append(out, tok)
		}
	}
	return strings.Join(out, " "), true
}

func hasOnlyFieldedDoris4Clauses(rewrittenRaw string) bool {
	tokens := tokenizeLucene(rewrittenRaw)
	hasClause := false
	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if upper == "AND" || upper == "OR" || upper == "NOT" {
			continue
		}
		rest := strings.TrimLeft(tok, "+-")
		if hasMatchingOuterParens(rest) {
			if !hasOnlyFieldedDoris4Clauses(rest[1 : len(rest)-1]) {
				return false
			}
			hasClause = true
			continue
		}
		if findLuceneFieldColon(rest) <= 0 {
			return false
		}
		hasClause = true
	}
	return hasClause
}

func canEmitMultiFieldDoris4SearchDisjunction(rewrittenRaw string, defaultOp string) bool {
	if strings.Contains(rewrittenRaw, ":") {
		return false
	}
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
	b := t.Schema.ResolveEffectiveField(fname, false)
	if b.NotIndexed || b.EnabledFalse || b.LowercaseNormalizer || b.ESType == "ip" || b.ESType == "binary" || b.ESType == "constant_keyword" || b.NullValue != nil {
		return false
	}
	return b.Kind == schema.StoragePromotedScalar && (b.DorisType == schema.DorisString || b.DorisType == schema.DorisVarchar)
}

const maxLuceneDepth = 32

type simpleQueryFlags struct {
	and                  bool
	or                   bool
	not                  bool
	phrase               bool
	prefix               bool
	precedence           bool
	fuzzy                bool
	slop                 bool
	escape               bool
	whitespace           bool
	quoteFieldSuffix     string
	timeZone             string
	queryType            string
	tieBreaker           *float64
	phraseSlop           int
	fuzziness            any
	fuzzyPrefixLength    int
	fuzzyMaxExpansions   int
	fuzzyTranspositions  *bool
	allowLeadingWildcard *bool
	analyzer             string
	quoteAnalyzer        string
	zeroTermsQuery       string
	lenient              *bool
	expandFields         func(string) []string
	isTextField          func(string) bool
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
		escape:     true,
		whitespace: true,
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
		case "ESCAPE":
			f.escape = true
		case "WHITESPACE":
			f.whitespace = true
		case "ALL":
			return allSimpleQueryFlags()
		}
	}
	return f
}

func escapeAllLuceneSpecialChars(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '+', '-', '=', '&', '|', '>', '<', '!', '(', ')', '{', '}', '[', ']', '^', '"', '~', '*', '?', ':', '\\', '/':
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hasLeadingLuceneWildcard(s string, flags simpleQueryFlags) bool {
	tokens := tokenizeLuceneWithFlags(s, false, flags)
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.EqualFold(tok, "AND") || strings.EqualFold(tok, "OR") || strings.EqualFold(tok, "NOT") || tok == "&&" || tok == "||" || tok == "|" || tok == "+" || tok == "-" || tok == "!" {
			continue
		}
		tok = strings.TrimLeft(tok, "+-!")
		tok, _ = splitLuceneBoost(tok)
		if hasMatchingOuterParens(tok) {
			if hasLeadingLuceneWildcard(tok[1:len(tok)-1], flags) {
				return true
			}
			continue
		}
		if idx := findLuceneFieldColon(tok); idx > 0 {
			field := tok[:idx]
			val := strings.TrimSpace(tok[idx+1:])
			val = strings.TrimLeft(val, "+-!")
			val, _ = splitLuceneBoost(val)
			if hasMatchingOuterParens(val) {
				if hasLeadingLuceneWildcard(val[1:len(val)-1], flags) {
					return true
				}
				continue
			}
			if field == "*" && val == "*" {
				continue
			}
			if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, "[") && !strings.HasPrefix(val, "{") && !strings.HasPrefix(val, "/") && (strings.HasPrefix(val, "*") || strings.HasPrefix(val, "?")) {
				return true
			}
			continue
		}
		if !strings.HasPrefix(tok, `"`) && !strings.HasPrefix(tok, "[") && !strings.HasPrefix(tok, "{") && !strings.HasPrefix(tok, "/") && (strings.HasPrefix(tok, "*") || strings.HasPrefix(tok, "?")) {
			return true
		}
	}
	return false
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

func extractLuceneTokenUnary(tok string, isSimple bool, flags simpleQueryFlags) (byte, string) {
	if len(tok) <= 1 {
		return 0, tok
	}
	if strings.HasPrefix(tok, "+") && (!isSimple || flags.and) {
		return '+', tok[1:]
	}
	if strings.HasPrefix(tok, "-") && (!isSimple || flags.not) {
		return '-', tok[1:]
	}
	if strings.HasPrefix(tok, "!") && !isSimple {
		return '-', tok[1:]
	}
	if !isSimple {
		if idx := findLuceneFieldColon(tok); idx > 0 && idx+2 <= len(tok) {
			val := strings.TrimSpace(tok[idx+1:])
			if len(val) > 1 && (val[0] == '+' || val[0] == '-' || val[0] == '!') {
				valNoBoost, _ := splitLuceneBoost(val)
				isNegNum := false
				if val[0] == '-' {
					if _, err := strconv.ParseFloat(valNoBoost, 64); err == nil {
						isNegNum = true
					}
				}
				afterOp := strings.TrimSpace(val[1:])
				if !isNegNum && afterOp != "" {
					if val[0] == '+' {
						return '+', tok[:idx+1] + afterOp
					}
					return '-', tok[:idx+1] + afterOp
				}
			}
		}
	}
	return 0, tok
}

func isLuceneUnaryPrefixed(tok string, isSimple bool, flags simpleQueryFlags) bool {
	uOp, _ := extractLuceneTokenUnary(tok, isSimple, flags)
	return uOp != 0
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
			remHasUnary := false
			for _, rt := range remaining {
				if isLuceneUnaryPrefixed(rt, isSimple, flags) || isLuceneStandaloneNot(rt, isSimple, flags) {
					remHasUnary = true
					break
				}
			}
			if defaultOp == "AND" && len(remQ.Bool.Must) == 0 && len(remQ.Bool.Filter) == 0 && len(remQ.Bool.MustNot) == 0 && len(remQ.Bool.Should) > 0 {
				remQ.Bool.MinimumShouldMatch = 1
				outBool.Must = append(outBool.Must, remQ)
			} else if defaultOp == "OR" && len(outBool.Must) > 0 && !remHasUnary && len(remQ.Bool.MustNot) == 0 && (len(remQ.Bool.Must) > 0 || len(remQ.Bool.Filter) > 0) {
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
	hasAND, hasOR, hasExplicitOR, hasNegUnary, hasPlusUnary := false, false, false, false, false
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
			hasNegUnary = true
			prevWasClause = false
			tok = "\x00NOT"
		} else {
			uOp, _ := extractLuceneTokenUnary(tok, isSimple, flags)
			isUnaryPrefix := uOp != 0
			if isUnaryPrefix {
				if uOp == '+' {
					hasPlusUnary = true
				} else {
					hasNegUnary = true
				}
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

	// In Lucene grammar, `AND` binds tighter than `OR` (e.g., `a:1 AND b:2 OR c:3` -> `(a:1 AND b:2) OR c:3`).
	if (hasAND || (defaultOp == "AND" && (!hasExplicitOR || !hasPlusUnary)) || (hasExplicitOR && hasNegUnary)) && hasOR {
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
		for len(tok) > 0 {
			if (tok == "-" && (!isSimple || flags.not)) || (tok == "!" && !isSimple) || (tok == "+" && (!isSimple || flags.and)) {
				tok = ""
				break
			}
			uOp, stripped := extractLuceneTokenUnary(tok, isSimple, flags)
			switch uOp {
			case '-':
				negateNext = true
				tok = stripped
			case '+':
				mustClause = true
				tok = stripped
			default:
				tok = stripped
			}
			if uOp == 0 {
				break
			}
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
		if len(tokens) > 0 {
			return esast.Query{MatchNone: map[string]any{}}
		}
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
		if b, err := strconv.ParseFloat(s[idx+1:], 64); err == nil && !math.IsNaN(b) && !math.IsInf(b, 0) && b >= 0 {
			return s[:idx], b
		}
	}
	return s, 1.0
}

func unescapeLuceneToken(s string) string {
	return unescapeLuceneTokenWithFlags(s, true)
}

func unescapeLuceneTokenWithFlags(s string, escape bool) string {
	if !escape || !strings.ContainsRune(s, '\\') {
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

func hasUnescapedLuceneWildcardWithFlags(s string, escape bool) bool {
	for i := 0; i < len(s); i++ {
		if escape && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

func isSimplePrefixTokenWithFlags(s string, escape bool) bool {
	if len(s) < 2 || s[len(s)-1] != '*' {
		return false
	}
	if hasUnescapedLuceneWildcardWithFlags(s[:len(s)-1], escape) {
		return false
	}
	if !escape {
		return true
	}
	backslashes := 0
	for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func parseLuceneQuotedOrFuzzyExWithFlags(raw string, escape bool) (clean string, rawWildcard string, isQuoted bool, slop int, isFuzzy bool, explicitZeroFuzzy bool, fuzzyDist any) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, `"`) && len(s) >= 2 {
		if strings.HasSuffix(s, `"`) {
			inner := s[1 : len(s)-1]
			return unescapeLuceneTokenWithFlags(inner, escape), inner, true, 0, false, false, nil
		}
		if tildeIdx := strings.LastIndex(s, `"~`); tildeIdx > 0 {
			slopStr := s[tildeIdx+2:]
			if n, err := strconv.Atoi(slopStr); err == nil && n >= 0 {
				inner := s[1:tildeIdx]
				return unescapeLuceneTokenWithFlags(inner, escape), inner, true, n, false, false, nil
			}
		}
	}
	if tildeIdx := strings.LastIndexByte(s, '~'); tildeIdx > 0 && (!escape || s[tildeIdx-1] != '\\') {
		suffix := s[tildeIdx+1:]
		if suffix == "" || strings.EqualFold(suffix, "auto") {
			s = s[:tildeIdx]
			isFuzzy = true
			fuzzyDist = "AUTO"
		} else if strings.HasPrefix(strings.ToLower(suffix), "auto:") && isValidLuceneFuzzySuffix(suffix) {
			s = s[:tildeIdx]
			isFuzzy = true
			fuzzyDist = strings.ToUpper(suffix)
		} else if n, err := strconv.Atoi(suffix); err == nil && n >= 0 {
			s = s[:tildeIdx]
			isFuzzy = n > 0
			explicitZeroFuzzy = n == 0
			fuzzyDist = n
		} else if f, err := strconv.ParseFloat(suffix, 64); err == nil && f >= 0 && f <= 2.0 {
			s = s[:tildeIdx]
			isFuzzy = f > 0
			explicitZeroFuzzy = f == 0
			fuzzyDist = int(math.Round(f))
		}
	}
	return unescapeLuceneTokenWithFlags(s, escape), s, false, 0, isFuzzy, explicitZeroFuzzy, fuzzyDist
}

func findLuceneFieldColon(s string) int {
	if len(s) == 0 || s[0] == '"' || s[0] == '(' || s[0] == '[' || s[0] == '{' || s[0] == '/' || s[0] == '~' {
		return -1
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			i++
			continue
		}
		if c == '"' || c == '(' || c == '[' || c == '{' || c == '~' {
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
			rawBound := strings.TrimSpace(val[len(op):])
			wasQuoted := strings.HasPrefix(rawBound, `"`) && strings.HasSuffix(rawBound, `"`)
			boundStr := unescapeLuceneToken(strings.Trim(rawBound, `"`))
			var bound any = boundStr
			if !wasQuoted {
				bound = parseLuceneRangeBound(boundStr)
			}
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
		if rawLower, rawUpper, ok := splitLuceneRangeBounds(inner); ok {
			rc := &esast.RangeCond{}
			if boost != 1.0 {
				b := boost
				rc.Boost = &b
			}
			if rawLower != "" && rawLower != "*" {
				wasQuoted := strings.HasPrefix(rawLower, `"`) && strings.HasSuffix(rawLower, `"`)
				lowerStr := unescapeLuceneToken(strings.Trim(rawLower, `"`))
				var bound any = lowerStr
				if !wasQuoted {
					bound = parseLuceneRangeBound(lowerStr)
				}
				if incLower {
					rc.GTE = bound
				} else {
					rc.GT = bound
				}
			}
			if rawUpper != "" && rawUpper != "*" {
				wasQuoted := strings.HasPrefix(rawUpper, `"`) && strings.HasSuffix(rawUpper, `"`)
				upperStr := unescapeLuceneToken(strings.Trim(rawUpper, `"`))
				var bound any = upperStr
				if !wasQuoted {
					bound = parseLuceneRangeBound(upperStr)
				}
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

func splitLuceneRangeBounds(inner string) (string, string, bool) {
	inQuotes := false
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && i > 0 && (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
			j := i
			for j < len(inner) && (inner[j] == ' ' || inner[j] == '\t' || inner[j] == '\n' || inner[j] == '\r') {
				j++
			}
			if j+2 < len(inner) && strings.EqualFold(inner[j:j+2], "TO") &&
				(inner[j+2] == ' ' || inner[j+2] == '\t' || inner[j+2] == '\n' || inner[j+2] == '\r') {
				k := j + 2
				for k < len(inner) && (inner[k] == ' ' || inner[k] == '\t' || inner[k] == '\n' || inner[k] == '\r') {
					k++
				}
				return strings.TrimSpace(inner[:i]), strings.TrimSpace(inner[k:]), true
			}
		}
	}
	return "", "", false
}

func applyLuceneQueryBoost(q *esast.Query, boost float64) {
	if q == nil || boost == 1.0 {
		return
	}
	b := boost
	if q.Bool != nil {
		if q.Bool.Boost != nil {
			b = *q.Bool.Boost * boost
		}
		q.Bool.Boost = &b
		return
	}
	inner := *q
	*q = esast.Query{Bool: &esast.BoolQuery{Must: []esast.Query{inner}, Boost: &b}}
}

func buildLuceneAtomQueryWithFlags(token, defaultField string, fields []string, defaultOp string, depth int, isSimple bool, flags simpleQueryFlags) esast.Query {
	token = strings.TrimSpace(token)
	boost := 1.0
	if !isSimple {
		token, boost = splitLuceneBoost(token)
	}
	if (!isSimple || flags.precedence) && hasMatchingOuterParens(token) {
		inner := parseSimpleLuceneToASTWithFlags(token[1:len(token)-1], defaultField, fields, defaultOp, depth+1, isSimple, flags)
		applyLuceneQueryBoost(&inner, boost)
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
			eq := &esast.ExistsQuery{Field: unescapeLuceneToken(strings.Trim(val, `"`))}
			if boost != 1.0 {
				b := boost
				eq.Boost = &b
			}
			return esast.Query{
				Exists: eq,
			}
		}
		if rc := parseLuceneRangeToken(val, boost); rc != nil {
			if rc.GTE == nil && rc.GT == nil && rc.LTE == nil && rc.LT == nil {
				if field == "*" {
					if boost != 1.0 {
						b := boost
						return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{MatchAll: map[string]any{}}, Boost: &b}}
					}
					return esast.Query{MatchAll: map[string]any{}}
				}
				if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
					expFields := flags.expandFields(field)
					if len(expFields) == 0 {
						return esast.Query{MatchNone: map[string]any{}}
					}
					var shoulds []esast.Query
					for _, ef := range expFields {
						fname, fBoost := splitLuceneBoost(ef)
						effB := boost * fBoost
						if effB != 1.0 {
							shoulds = append(shoulds, esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: fname}}, Boost: &effB}})
						} else {
							shoulds = append(shoulds, esast.Query{Exists: &esast.ExistsQuery{Field: fname}})
						}
					}
					if len(shoulds) == 1 {
						return shoulds[0]
					}
					return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
				}
				if boost != 1.0 {
					b := boost
					return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: field}}, Boost: &b}}
				}
				return esast.Query{Exists: &esast.ExistsQuery{Field: field}}
			}
			if flags.timeZone != "" && rc.TimeZone == "" {
				rc.TimeZone = flags.timeZone
			}
			if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
				expFields := flags.expandFields(field)
				if len(expFields) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				var shoulds []esast.Query
				for _, ef := range expFields {
					fname, fBoost := splitLuceneBoost(ef)
					rcCopy := *rc
					effB := boost * fBoost
					if effB != 1.0 {
						rcCopy.Boost = &effB
					}
					shoulds = append(shoulds, esast.Query{Range: map[string]esast.RangeCond{fname: rcCopy}})
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
			return esast.Query{
				Range: map[string]esast.RangeCond{field: *rc},
			}
		}
		if len(val) > 1 && (val[0] == '+' || val[0] == '-' || val[0] == '!') {
			trimmedAfterOp := strings.TrimSpace(val[1:])
			isNegNumber := false
			if val[0] == '-' {
				if _, numErr := strconv.ParseFloat(val, 64); numErr == nil {
					isNegNumber = true
				}
			}
			if trimmedAfterOp != "" && !isNegNumber && !hasMatchingOuterParens(trimmedAfterOp) {
				inner := buildLuceneAtomQueryWithFlags(field+":"+trimmedAfterOp, defaultField, fields, defaultOp, depth+1, isSimple, flags)
				if val[0] == '-' || val[0] == '!' {
					neg := esast.Query{Bool: &esast.BoolQuery{MustNot: []esast.Query{inner}}}
					if boost != 1.0 {
						b := boost
						neg.Bool.Boost = &b
					}
					return neg
				}
				if boost != 1.0 {
					applyLuceneQueryBoost(&inner, boost)
				}
				return inner
			}
		}
		if strings.HasPrefix(val, "/") && strings.HasSuffix(val, "/") && len(val) > 2 {
			pat := strings.ReplaceAll(val[1:len(val)-1], `\/`, `/`)
			if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
				expFields := flags.expandFields(field)
				if len(expFields) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				var shoulds []esast.Query
				for _, ef := range expFields {
					fname, fBoost := splitLuceneBoost(ef)
					shoulds = append(shoulds, esast.Query{
						Regexp: map[string]esast.RegexpEntry{
							fname: {Value: pat, Flags: "ALL", Boost: boost * fBoost, HasBoost: true},
						},
					})
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
			return esast.Query{
				Regexp: map[string]esast.RegexpEntry{
					field: {Value: pat, Flags: "ALL", Boost: boost, HasBoost: true},
				},
			}
		}
		valUnary := byte(0)
		valRest := val
		if len(val) > 2 && (val[0] == '+' || val[0] == '-' || val[0] == '!') {
			trimmedAfterOp := strings.TrimSpace(val[1:])
			if hasMatchingOuterParens(trimmedAfterOp) {
				valUnary = val[0]
				valRest = trimmedAfterOp
			}
		}
		if hasMatchingOuterParens(valRest) {
			var subFields []string
			subDefault := field
			if strings.ContainsAny(field, "*?") {
				if flags.expandFields != nil {
					subFields = flags.expandFields(field)
					if len(subFields) > 0 {
						subDefault = strings.Split(subFields[0], "^")[0]
					} else {
						subDefault = "__unmatched_wildcard__"
					}
				} else {
					subFields = []string{field}
					subDefault = defaultField
				}
			}
			inner := parseSimpleLuceneToASTWithFlags(valRest[1:len(valRest)-1], subDefault, subFields, defaultOp, depth+1, isSimple, flags)
			if valUnary == '-' || valUnary == '!' {
				neg := esast.Query{Bool: &esast.BoolQuery{MustNot: []esast.Query{inner}}}
				if boost != 1.0 {
					b := boost
					neg.Bool.Boost = &b
				}
				return neg
			}
			applyLuceneQueryBoost(&inner, boost)
			return inner
		}
		val, rawWild, isQuoted, slop, isFuzzy, explicitZeroFuzzy, fuzzyDist := parseLuceneQuotedOrFuzzyExWithFlags(val, flags.escape)
		if isQuoted && slop == 0 && flags.phraseSlop > 0 {
			slop = flags.phraseSlop
		}
		if isQuoted && flags.quoteFieldSuffix != "" && field != "_all_text" && !strings.HasSuffix(field, flags.quoteFieldSuffix) {
			field += flags.quoteFieldSuffix
		}
		var fuzzAny any
		if isFuzzy && !isQuoted {
			fuzzAny = fuzzyDist
		} else if explicitZeroFuzzy && !isQuoted {
			fuzzAny = 0
		} else if !isQuoted && !explicitZeroFuzzy && flags.fuzziness != nil {
			fuzzAny = flags.fuzziness
		}
		if !isQuoted && !isFuzzy && (strings.EqualFold(val, "true") || strings.EqualFold(val, "false")) && (flags.isTextField == nil || !flags.isTextField(field)) {
			boolVal := strings.EqualFold(val, "true")
			if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
				expFields := flags.expandFields(field)
				if len(expFields) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				var shoulds []esast.Query
				for _, ef := range expFields {
					fname, fBoost := splitLuceneBoost(ef)
					if flags.isTextField != nil && flags.isTextField(fname) {
						shoulds = append(shoulds, esast.Query{
							Match: map[string]esast.MatchEntry{
								fname: {
									Query:               val,
									Operator:            strings.ToLower(defaultOp),
									Analyzer:            flags.analyzer,
									ZeroTermsQuery:      flags.zeroTermsQuery,
									Fuzziness:           fuzzAny,
									PrefixLength:        flags.fuzzyPrefixLength,
									MaxExpansions:       flags.fuzzyMaxExpansions,
									FuzzyTranspositions: flags.fuzzyTranspositions,
									Lenient:             flags.lenient,
									Boost:               boost * fBoost,
									HasBoost:            true,
								},
							},
						})
					} else {
						shoulds = append(shoulds, esast.Query{
							Term: map[string]esast.TermEntry{
								fname: {Value: boolVal, Boost: boost * fBoost, HasBoost: true},
							},
						})
					}
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
			return esast.Query{
				Term: map[string]esast.TermEntry{
					field: {Value: boolVal, Boost: boost, HasBoost: true},
				},
			}
		}
		if !isQuoted && hasUnescapedLuceneWildcardWithFlags(rawWild, flags.escape) {
			if rawWild == "*" {
				if field == "*" {
					if boost != 1.0 {
						b := boost
						return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{MatchAll: map[string]any{}}, Boost: &b}}
					}
					return esast.Query{MatchAll: map[string]any{}}
				}
				if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
					expFields := flags.expandFields(field)
					if len(expFields) == 0 {
						return esast.Query{MatchNone: map[string]any{}}
					}
					var shoulds []esast.Query
					for _, ef := range expFields {
						fname, fBoost := splitLuceneBoost(ef)
						effB := boost * fBoost
						if effB != 1.0 {
							shoulds = append(shoulds, esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: fname}}, Boost: &effB}})
						} else {
							shoulds = append(shoulds, esast.Query{Exists: &esast.ExistsQuery{Field: fname}})
						}
					}
					if len(shoulds) == 1 {
						return shoulds[0]
					}
					return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
				}
				if boost != 1.0 {
					b := boost
					return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: field}}, Boost: &b}}
				}
				return esast.Query{Exists: &esast.ExistsQuery{Field: field}}
			}
			if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
				expFields := flags.expandFields(field)
				if len(expFields) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				var shoulds []esast.Query
				for _, ef := range expFields {
					fname, fBoost := splitLuceneBoost(ef)
					shoulds = append(shoulds, esast.Query{
						Wildcard: map[string]esast.WildcardEntry{
							fname: {Value: rawWild, CaseInsensitive: true, Boost: boost * fBoost, HasBoost: true},
						},
					})
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
			return esast.Query{
				Wildcard: map[string]esast.WildcardEntry{
					field: {Value: rawWild, CaseInsensitive: true, Boost: boost, HasBoost: true},
				},
			}
		}
		effAnalyzer := flags.analyzer
		if isQuoted && flags.quoteAnalyzer != "" {
			effAnalyzer = flags.quoteAnalyzer
		}
		if isQuoted && val == "" {
			if strings.ContainsAny(field, "*?") && flags.expandFields != nil {
				expFields := flags.expandFields(field)
				if len(expFields) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				var shoulds []esast.Query
				for _, ef := range expFields {
					fname, fBoost := splitLuceneBoost(ef)
					q := buildEmptyQuotedFieldQuery(fname, boost*fBoost, flags)
					if q.MatchNone == nil {
						shoulds = append(shoulds, q)
					}
				}
				if len(shoulds) == 0 {
					return esast.Query{MatchNone: map[string]any{}}
				}
				if len(shoulds) == 1 {
					return shoulds[0]
				}
				return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
			}
			return buildEmptyQuotedFieldQuery(field, boost, flags)
		}
		if strings.ContainsAny(field, "*?") {
			b := boost
			qType := "best_fields"
			if flags.queryType != "" {
				qType = flags.queryType
			}
			if isQuoted && val != "" {
				qType = "phrase"
			}
			return esast.Query{
				MultiMatch: &esast.MultiMatchQuery{
					Query:               val,
					Fields:              []string{field},
					Type:                qType,
					Operator:            strings.ToLower(defaultOp),
					Analyzer:            effAnalyzer,
					ZeroTermsQuery:      flags.zeroTermsQuery,
					Slop:                slop,
					Fuzziness:           fuzzAny,
					PrefixLength:        flags.fuzzyPrefixLength,
					MaxExpansions:       flags.fuzzyMaxExpansions,
					FuzzyTranspositions: flags.fuzzyTranspositions,
					TieBreaker:          flags.tieBreaker,
					Lenient:             flags.lenient,
					Boost:               &b,
				},
			}
		}
		if isQuoted && val != "" {
			return esast.Query{
				MatchPhrase: map[string]esast.PhraseEntry{
					field: {Query: val, Analyzer: effAnalyzer, ZeroTermsQuery: flags.zeroTermsQuery, Slop: slop, Lenient: flags.lenient, Boost: boost, HasBoost: true},
				},
			}
		}
		return esast.Query{
			Match: map[string]esast.MatchEntry{
				field: {
					Query:               val,
					Operator:            strings.ToLower(defaultOp),
					Analyzer:            effAnalyzer,
					ZeroTermsQuery:      flags.zeroTermsQuery,
					Fuzziness:           fuzzAny,
					PrefixLength:        flags.fuzzyPrefixLength,
					MaxExpansions:       flags.fuzzyMaxExpansions,
					FuzzyTranspositions: flags.fuzzyTranspositions,
					Lenient:             flags.lenient,
					Boost:               boost,
					HasBoost:            true,
				},
			},
		}
	}

	if len(fields) == 0 && defaultField == "__unmatched_wildcard__" {
		return esast.Query{MatchNone: map[string]any{}}
	}

	if !isSimple {
		if rc := parseLuceneRangeToken(token, boost); rc != nil {
			if rc.GTE == nil && rc.GT == nil && rc.LTE == nil && rc.LT == nil {
				if len(fields) > 0 {
					var shoulds []esast.Query
					for _, fpat := range fields {
						fname, fBoost := splitLuceneBoost(fpat)
						effBoost := boost * fBoost
						if fname == "*" || fname == "_all_text" {
							if effBoost != 1.0 {
								b := effBoost
								shoulds = append(shoulds, esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{MatchAll: map[string]any{}}, Boost: &b}})
							} else {
								shoulds = append(shoulds, esast.Query{MatchAll: map[string]any{}})
							}
						} else if effBoost != 1.0 {
							b := effBoost
							shoulds = append(shoulds, esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: fname}}, Boost: &b}})
						} else {
							shoulds = append(shoulds, esast.Query{Exists: &esast.ExistsQuery{Field: fname}})
						}
					}
					if len(shoulds) == 1 {
						return shoulds[0]
					}
					if len(shoulds) > 1 {
						return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
					}
				}
				if defaultField == "" || defaultField == "*" || defaultField == "_all_text" {
					if boost != 1.0 {
						b := boost
						return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{MatchAll: map[string]any{}}, Boost: &b}}
					}
					return esast.Query{MatchAll: map[string]any{}}
				}
				if boost != 1.0 {
					b := boost
					return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: defaultField}}, Boost: &b}}
				}
				return esast.Query{Exists: &esast.ExistsQuery{Field: defaultField}}
			}
			if flags.timeZone != "" && rc.TimeZone == "" {
				rc.TimeZone = flags.timeZone
			}
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
							fname: {Value: pat, Flags: "ALL", Boost: boost * fBoost, HasBoost: true},
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
					defaultField: {Value: pat, Flags: "ALL", Boost: boost, HasBoost: true},
				},
			}
		}
	}
	cleanVal, rawWild, isQuoted, slop, isFuzzy, explicitZeroFuzzy, fuzzyDist := parseLuceneQuotedOrFuzzyExWithFlags(token, flags.escape)
	if isQuoted && slop == 0 && flags.phraseSlop > 0 {
		slop = flags.phraseSlop
	}
	if isSimple {
		if !flags.phrase {
			isQuoted = false
			slop = 0
		} else if !flags.slop && flags.phraseSlop == 0 {
			slop = 0
		}
		if !flags.fuzzy && !isQuoted {
			cleanVal = unescapeLuceneTokenWithFlags(strings.TrimSpace(token), flags.escape)
			rawWild = strings.TrimSpace(token)
			isFuzzy = false
			explicitZeroFuzzy = false
		}
	}
	var fuzzAny any
	if isFuzzy && !isQuoted {
		fuzzAny = fuzzyDist
	} else if explicitZeroFuzzy && !isQuoted {
		fuzzAny = 0
	} else if !isQuoted && !explicitZeroFuzzy && flags.fuzziness != nil {
		fuzzAny = flags.fuzziness
	}
	targetDefaultField := defaultField
	targetFields := fields
	if isQuoted && flags.quoteFieldSuffix != "" {
		if targetDefaultField != "_all_text" && targetDefaultField != "__unmatched_wildcard__" && !strings.HasSuffix(targetDefaultField, flags.quoteFieldSuffix) {
			targetDefaultField += flags.quoteFieldSuffix
		}
		if len(fields) > 0 {
			targetFields = make([]string, len(fields))
			for i, fpat := range fields {
				fname, fBoost := splitLuceneBoost(fpat)
				if fname != "_all_text" && !strings.HasSuffix(fname, flags.quoteFieldSuffix) {
					fname += flags.quoteFieldSuffix
				}
				if fBoost != 1.0 {
					targetFields[i] = fmt.Sprintf("%s^%g", fname, fBoost)
				} else {
					targetFields[i] = fname
				}
			}
		}
	}
	if !isQuoted && ((!isSimple && hasUnescapedLuceneWildcardWithFlags(rawWild, flags.escape)) || (isSimple && flags.prefix && isSimplePrefixTokenWithFlags(rawWild, flags.escape))) {
		if len(fields) > 0 {
			var shoulds []esast.Query
			for _, fpat := range fields {
				fname, fBoost := splitLuceneBoost(fpat)
				if rawWild == "*" && fname != "*" && fname != "_all_text" {
					effB := boost * fBoost
					if effB != 1.0 {
						shoulds = append(shoulds, esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: fname}}, Boost: &effB}})
					} else {
						shoulds = append(shoulds, esast.Query{Exists: &esast.ExistsQuery{Field: fname}})
					}
					continue
				}
				shoulds = append(shoulds, esast.Query{
					Wildcard: map[string]esast.WildcardEntry{
						fname: {Value: rawWild, CaseInsensitive: true, Boost: boost * fBoost, HasBoost: true},
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
		if rawWild == "*" && defaultField != "*" && defaultField != "_all_text" && defaultField != "" {
			if boost != 1.0 {
				b := boost
				return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Exists: &esast.ExistsQuery{Field: defaultField}}, Boost: &b}}
			}
			return esast.Query{Exists: &esast.ExistsQuery{Field: defaultField}}
		}
		return esast.Query{
			Wildcard: map[string]esast.WildcardEntry{
				defaultField: {Value: rawWild, CaseInsensitive: true, Boost: boost, HasBoost: true},
			},
		}
	}

	effAnalyzer := flags.analyzer
	if isQuoted && flags.quoteAnalyzer != "" {
		effAnalyzer = flags.quoteAnalyzer
	}
	if isQuoted && cleanVal == "" {
		if len(targetFields) > 0 {
			var shoulds []esast.Query
			for _, fpat := range targetFields {
				fname, fBoost := splitLuceneBoost(fpat)
				q := buildEmptyQuotedFieldQuery(fname, boost*fBoost, flags)
				if q.MatchNone == nil {
					shoulds = append(shoulds, q)
				}
			}
			if len(shoulds) == 0 {
				return esast.Query{MatchNone: map[string]any{}}
			}
			if len(shoulds) == 1 {
				return shoulds[0]
			}
			return esast.Query{Bool: &esast.BoolQuery{Should: shoulds}}
		}
		return buildEmptyQuotedFieldQuery(targetDefaultField, boost, flags)
	}
	if isQuoted && cleanVal != "" {
		if len(targetFields) > 0 {
			return esast.Query{
				MultiMatch: &esast.MultiMatchQuery{
					Query:          cleanVal,
					Fields:         targetFields,
					Type:           "phrase",
					Analyzer:       effAnalyzer,
					ZeroTermsQuery: flags.zeroTermsQuery,
					Slop:           slop,
					TieBreaker:     flags.tieBreaker,
					Lenient:        flags.lenient,
					Boost:          &boost,
				},
			}
		}
		return esast.Query{
			MatchPhrase: map[string]esast.PhraseEntry{
				targetDefaultField: {Query: cleanVal, Analyzer: effAnalyzer, ZeroTermsQuery: flags.zeroTermsQuery, Slop: slop, Lenient: flags.lenient, Boost: boost, HasBoost: true},
			},
		}
	}

	if len(targetFields) > 0 {
		return esast.Query{
			MultiMatch: &esast.MultiMatchQuery{
				Query:               cleanVal,
				Fields:              targetFields,
				Type:                flags.queryType,
				Operator:            strings.ToLower(defaultOp),
				Analyzer:            effAnalyzer,
				ZeroTermsQuery:      flags.zeroTermsQuery,
				Fuzziness:           fuzzAny,
				PrefixLength:        flags.fuzzyPrefixLength,
				MaxExpansions:       flags.fuzzyMaxExpansions,
				FuzzyTranspositions: flags.fuzzyTranspositions,
				TieBreaker:          flags.tieBreaker,
				Lenient:             flags.lenient,
				Boost:               &boost,
			},
		}
	}
	return esast.Query{
		Match: map[string]esast.MatchEntry{
			targetDefaultField: {
				Query:               cleanVal,
				Operator:            strings.ToLower(defaultOp),
				Analyzer:            effAnalyzer,
				ZeroTermsQuery:      flags.zeroTermsQuery,
				Fuzziness:           fuzzAny,
				PrefixLength:        flags.fuzzyPrefixLength,
				MaxExpansions:       flags.fuzzyMaxExpansions,
				FuzzyTranspositions: flags.fuzzyTranspositions,
				Lenient:             flags.lenient,
				Boost:               boost,
				HasBoost:            true,
			},
		},
	}
}

func parseLuceneRangeBound(s string) any {
	if len(s) > 1 && ((s[0] == '0' && s[1] >= '0' && s[1] <= '9') || (s[0] == '-' && len(s) > 2 && s[1] == '0' && s[2] >= '0' && s[2] <= '9')) {
		return s
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if strings.Contains(s, ".") && strings.HasSuffix(s, "0") {
		return s
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
		if flags.escape && s[i] == '\\' {
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
		if flags.escape && s[i] == '\\' {
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

func hasUnclosedLuceneRange(s string) bool {
	inQuotes := false
	inRegex := false
	escaped := false
	bracketDepth := 0
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '"':
			if !inRegex {
				inQuotes = !inQuotes
			}
		case '/':
			if !inQuotes && bracketDepth == 0 {
				if inRegex {
					inRegex = false
				} else if strings.ContainsRune(s[i+1:], '/') {
					if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n' || s[i-1] == ':' || s[i-1] == '(' || s[i-1] == '+' || s[i-1] == '-' || s[i-1] == '!' {
						inRegex = true
					}
				}
			}
		case '[', '{':
			if !inQuotes && !inRegex {
				bracketDepth++
			}
		case ']', '}':
			if !inQuotes && !inRegex && bracketDepth > 0 {
				bracketDepth--
			}
		case ')':
			if !inQuotes && !inRegex && bracketDepth > 0 {
				return true
			}
		}
	}
	return bracketDepth > 0
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
			if flags.escape {
				escaped = true
			}
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
				} else if strings.ContainsRune(s[i+1:], '/') {
					currStr := curr.String()
					if currStr == "" || currStr == "+" || currStr == "-" || currStr == "!" ||
						strings.HasSuffix(currStr, ":") || strings.HasSuffix(currStr, ":+") ||
						strings.HasSuffix(currStr, ":-") || strings.HasSuffix(currStr, ":!") {
						inRegex = true
					}
				}
			}
			curr.WriteRune(r)
		case '(':
			if !inQuotes && !inRegex && (!isSimple || flags.precedence) {
				if parenDepth == 0 && bracketDepth == 0 && curr.Len() > 0 {
					prefix := curr.String()
					isFieldUnaryPrefix := strings.HasSuffix(prefix, ":+") || strings.HasSuffix(prefix, ":-") || strings.HasSuffix(prefix, ":!")
					if prefix != "+" && prefix != "-" && prefix != "!" && !strings.HasSuffix(prefix, ":") && !isFieldUnaryPrefix {
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
					afterColon := ""
					if colonIdx > 0 {
						afterColon = strings.TrimLeft(trimmedTok[colonIdx+1:], "+-!")
					}
					if hasMatchingOuterParens(trimmedTok) || (colonIdx > 0 && hasMatchingOuterParens(afterColon)) {
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
			if inQuotes || inRegex || parenDepth > 0 || bracketDepth > 0 || (isSimple && !flags.whitespace) {
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
	if !isSimple && !flags.whitespace && len(out) > 1 {
		out = mergeQueryStringUnquotedWhitespaceTokens(out)
	}
	return out
}

func buildEmptyQuotedFieldQuery(fname string, effBoost float64, flags simpleQueryFlags) esast.Query {
	if flags.isTextField != nil && fname != "_all_text" && fname != "*" && fname != "__unmatched_wildcard__" && !flags.isTextField(fname) {
		return esast.Query{
			Term: map[string]esast.TermEntry{
				fname: {Value: "", Boost: effBoost, HasBoost: true},
			},
		}
	}
	if strings.EqualFold(flags.zeroTermsQuery, "all") && fname != "__unmatched_wildcard__" {
		if effBoost != 1.0 {
			b := effBoost
			return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{MatchAll: map[string]any{}}, Boost: &b}}
		}
		return esast.Query{MatchAll: map[string]any{}}
	}
	return esast.Query{MatchNone: map[string]any{}}
}

func isExplicitLuceneBoolToken(tok string) bool {
	return tok == "AND" || tok == "OR" || tok == "NOT" || tok == "&&" || tok == "||" || tok == "|"
}

func canAcceptTrailingWSChunk(prev string) bool {
	if prev == "" || isExplicitLuceneBoolToken(prev) {
		return false
	}
	trimmed := strings.TrimLeft(prev, "+-!")
	if trimmed == "" || strings.HasPrefix(trimmed, "(") || strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, ">") || strings.HasPrefix(trimmed, "<") {
		return false
	}
	if colonIdx := findLuceneFieldColon(trimmed); colonIdx > 0 {
		rhs := strings.TrimLeft(trimmed[colonIdx+1:], "+-!")
		if rhs == "" || strings.HasPrefix(rhs, "(") || strings.HasPrefix(rhs, `"`) || strings.HasPrefix(rhs, "/") || strings.HasPrefix(rhs, "[") || strings.HasPrefix(rhs, "{") || strings.HasPrefix(rhs, ">") || strings.HasPrefix(rhs, "<") {
			return false
		}
	}
	last := prev[len(prev)-1]
	if last == ')' || last == '"' || last == ']' || last == '}' || last == '/' {
		return false
	}
	for i := 0; i < len(prev); i++ {
		if prev[i] == '\\' {
			i++
			continue
		}
		if prev[i] == '~' || prev[i] == '^' {
			return false
		}
	}
	return true
}

func canMergeAsTrailingWSChunk(tok string) bool {
	if tok == "" || isExplicitLuceneBoolToken(tok) {
		return false
	}
	c := tok[0]
	if c == '+' || c == '-' || c == '!' || c == '(' || c == ')' || c == '"' || c == '/' || c == '[' || c == '{' || c == '>' || c == '<' {
		return false
	}
	if findLuceneFieldColon(tok) >= 0 {
		return false
	}
	return true
}

func mergeQueryStringUnquotedWhitespaceTokens(tokens []string) []string {
	merged := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if len(merged) > 0 && canAcceptTrailingWSChunk(merged[len(merged)-1]) && canMergeAsTrailingWSChunk(tok) {
			merged[len(merged)-1] = merged[len(merged)-1] + " " + tok
		} else {
			merged = append(merged, tok)
		}
	}
	return merged
}

func isValidLuceneFuzzySuffix(sub string) bool {
	if sub == "" || strings.EqualFold(sub, "auto") {
		return true
	}
	lower := strings.ToLower(sub)
	if strings.HasPrefix(lower, "auto:") {
		parts := strings.Split(lower[len("auto:"):], ",")
		if len(parts) != 2 || !isPureDigitsASCII(parts[0]) || !isPureDigitsASCII(parts[1]) {
			return false
		}
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		return err1 == nil && err2 == nil && lo >= 0 && hi >= lo
	}
	if sub == "0" || sub == "1" || sub == "2" {
		return true
	}
	if sub[0] == '+' || sub[0] == '-' {
		return false
	}
	f, err := strconv.ParseFloat(sub, 64)
	return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0.0 && f <= 2.0
}

func validateStrictLuceneQuery(s string) error {
	inQuotes := false
	inRegex := false
	escaped := false
	bracketDepth := 0
	bracketStart := -1
	parenDepth := 0
	justClosedQuoteIdx := -2

	isSuffixStop := func(b byte) bool {
		switch b {
		case ' ', '\t', '\n', '\r', '(', ')', '^', '|', '&':
			return true
		default:
			return false
		}
	}
	isBoostStop := func(b byte) bool {
		switch b {
		case ' ', '\t', '\n', '\r', '(', ')', ':', '|', '&', '~':
			return true
		default:
			return false
		}
	}
	isTermBreak := func(b byte) bool {
		switch b {
		case ' ', '\t', '\n', '\r', '(', ')', ':', '+', '-', '!', '|', '&', '^', '~':
			return true
		default:
			return false
		}
	}

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' && !inRegex {
			if inQuotes {
				inQuotes = false
				justClosedQuoteIdx = i
			} else {
				inQuotes = true
			}
			continue
		}
		if inQuotes {
			continue
		}
		if ch == '/' && bracketDepth == 0 {
			if inRegex {
				inRegex = false
				continue
			}
			if strings.ContainsRune(s[i+1:], '/') {
				if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n' || s[i-1] == '\r' ||
					s[i-1] == ':' || s[i-1] == '(' || s[i-1] == '+' || s[i-1] == '-' || s[i-1] == '!' {
					inRegex = true
					continue
				}
			}
		}
		if inRegex {
			continue
		}
		if ch == '[' || ch == '{' {
			if bracketDepth > 0 {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: nested range bracket", s)
			}
			bracketDepth++
			bracketStart = i
			continue
		}
		if ch == ']' || ch == '}' {
			if bracketDepth == 0 {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: unmatched closing range bracket", s)
			}
			bracketDepth--
			if bracketDepth == 0 && bracketStart >= 0 {
				inner := strings.TrimSpace(s[bracketStart+1 : i])
				rawLo, rawHi, ok := splitLuceneRangeBounds(inner)
				if !ok || rawLo == "" || rawHi == "" {
					return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid range query [%s]", s, s[bracketStart:i+1])
				}
				bracketStart = -1
			}
			continue
		}
		if bracketDepth > 0 {
			continue
		}
		switch ch {
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: unbalanced parentheses", s)
			}
			parenDepth--
		case '~':
			isSlop := justClosedQuoteIdx == i-1
			if !isSlop && (i == 0 || isTermBreak(s[i-1])) {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid fuzzy operator", s)
			}
			j := i + 1
			for j < len(s) && !isSuffixStop(s[j]) {
				j++
			}
			sub := s[i+1 : j]
			if isSlop {
				if sub != "" && !isPureDigitsASCII(sub) {
					return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid phrase slop [%s]", s, sub)
				}
			} else if !isValidLuceneFuzzySuffix(sub) {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid fuzzy edit distance [%s]", s, sub)
			}
			i = j - 1
		case '^':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n' || s[i-1] == '\r' ||
				s[i-1] == '(' || s[i-1] == ':' || s[i-1] == '|' || s[i-1] == '&' {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid boost operator", s)
			}
			j := i + 1
			for j < len(s) && !isBoostStop(s[j]) {
				j++
			}
			sub := s[i+1 : j]
			if sub == "" || sub[0] == '-' || sub[0] == '+' {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid or negative boost [%s]", s, sub)
			}
			f, err := strconv.ParseFloat(sub, 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
				return fmt.Errorf("parse_exception: cannot parse query [%s]: invalid boost [%s]", s, sub)
			}
			i = j - 1
		}
	}
	if inQuotes {
		return fmt.Errorf("parse_exception: cannot parse query [%s]: unclosed double quote", s)
	}
	if parenDepth != 0 {
		return fmt.Errorf("parse_exception: cannot parse query [%s]: unbalanced parentheses", s)
	}
	if bracketDepth != 0 {
		return fmt.Errorf("parse_exception: cannot parse query [%s]: unclosed range bracket", s)
	}
	return nil
}

type luceneRegexpFlags struct {
	intersection bool
	complement   bool
	empty        bool
	anystring    bool
	automaton    bool
	interval     bool
}

func parseLuceneRegexpFlags(flags string) (luceneRegexpFlags, error) {
	trimmed := strings.TrimSpace(flags)
	if trimmed == "" {
		return luceneRegexpFlags{
			intersection: true,
			complement:   true,
			empty:        true,
			anystring:    true,
			automaton:    true,
			interval:     true,
		}, nil
	}
	var out luceneRegexpFlags
	for _, rawTok := range strings.Split(trimmed, "|") {
		tok := strings.ToUpper(strings.TrimSpace(rawTok))
		if tok == "" {
			continue
		}
		switch tok {
		case "ALL":
			out.intersection = true
			out.complement = true
			out.empty = true
			out.anystring = true
			out.automaton = true
			out.interval = true
		case "NONE":
			// Enables no optional syntax flags.
		case "INTERSECTION":
			out.intersection = true
		case "COMPLEMENT", "DEPRECATED_COMPLEMENT":
			out.complement = true
		case "EMPTY":
			out.empty = true
		case "ANYSTRING":
			out.anystring = true
		case "AUTOMATON":
			out.automaton = true
		case "INTERVAL":
			out.interval = true
		default:
			return luceneRegexpFlags{}, fmt.Errorf("illegal_argument_exception: Unknown regexp flag [%s]", strings.TrimSpace(rawTok))
		}
	}
	return out, nil
}

type luceneAutoNodeKind int

const (
	luceneNodeRE2 luceneAutoNodeKind = iota
	luceneNodeEmpty
	luceneNodeUnion
	luceneNodeInter
	luceneNodeCompl
)

type luceneAutoNode struct {
	kind       luceneAutoNodeKind
	re2        string
	hasLiteral bool
	literal    string
	isAnyStr   bool
	children   []*luceneAutoNode
	child      *luceneAutoNode
	complRE2   string // optional pure-RE2 lowering for complement of finite literal / single char class
}

// LuceneRegexpCompiled holds a compiled Lucene automaton regular expression ready to render
// full-term anchored SQL predicates (`^(?:...)$`) for both scalar columns and array elements.
type LuceneRegexpCompiled struct {
	IsEmpty      bool
	NeedsNotNull bool
	root         *luceneAutoNode
	caseInsens   bool
}

func complementOfLiteralRE2(lit string) string {
	runes := []rune(lit)
	k := len(runes)
	if k == 0 {
		return "(?s:.+)"
	}
	var alts []string
	if k == 1 {
		alts = append(alts, "")
	} else {
		alts = append(alts, fmt.Sprintf("(?s:.){0,%d}", k-1))
	}
	var prefix strings.Builder
	for i, r := range runes {
		notR := fmt.Sprintf("[^%s]", escapeRE2CharClassMember(r))
		rem := k - 1 - i
		switch rem {
		case 0:
			alts = append(alts, prefix.String()+notR)
		case 1:
			alts = append(alts, prefix.String()+notR+"(?s:.)")
		default:
			alts = append(alts, fmt.Sprintf("%s%s(?s:.){%d}", prefix.String(), notR, rem))
		}
		prefix.WriteString(regexp.QuoteMeta(string(r)))
	}
	alts = append(alts, fmt.Sprintf("(?s:.){%d,}", k+1))
	return "(?:" + strings.Join(alts, "|") + ")"
}

func escapeRE2CharClassMember(r rune) string {
	switch r {
	case '\\', ']', '-', '^':
		return `\` + string(r)
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	default:
		return string(r)
	}
}

func buildNumericIntervalRE2(minVal, maxVal uint64, fixedWidth int) string {
	var rangeFixed func(a, b string) string
	charRange := func(lo, hi byte) string {
		if lo == hi {
			return string(lo)
		}
		if lo == '0' && hi == '9' {
			return "[0-9]"
		}
		return fmt.Sprintf("[%c-%c]", lo, hi)
	}
	repeatDigits := func(n int) string {
		if n <= 0 {
			return ""
		}
		if n == 1 {
			return "[0-9]"
		}
		return fmt.Sprintf("[0-9]{%d}", n)
	}
	allZeros := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] != '0' {
				return false
			}
		}
		return true
	}
	allNines := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] != '9' {
				return false
			}
		}
		return true
	}
	rangeFixed = func(a, b string) string {
		if a == b {
			return a
		}
		w := len(a)
		if allZeros(a) && allNines(b) {
			return repeatDigits(w)
		}
		cp := 0
		for cp < w && a[cp] == b[cp] {
			cp++
		}
		if cp > 0 {
			return a[:cp] + rangeFixed(a[cp:], b[cp:])
		}
		if w == 1 {
			return charRange(a[0], b[0])
		}
		var parts []string
		midLo := a[0]
		midHi := b[0]
		if !allZeros(a[1:]) {
			parts = append(parts, string(a[0])+rangeFixed(a[1:], strings.Repeat("9", w-1)))
			midLo++
		}
		var rightPart string
		if !allNines(b[1:]) {
			rightPart = string(b[0]) + rangeFixed(strings.Repeat("0", w-1), b[1:])
			midHi--
		}
		if midLo <= midHi {
			parts = append(parts, charRange(midLo, midHi)+repeatDigits(w-1))
		}
		if rightPart != "" {
			parts = append(parts, rightPart)
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(?:" + strings.Join(parts, "|") + ")"
	}

	minStr := strconv.FormatUint(minVal, 10)
	maxStr := strconv.FormatUint(maxVal, 10)
	if fixedWidth > 0 {
		if len(minStr) < fixedWidth {
			minStr = strings.Repeat("0", fixedWidth-len(minStr)) + minStr
		}
		if len(maxStr) < fixedWidth {
			maxStr = strings.Repeat("0", fixedWidth-len(maxStr)) + maxStr
		}
		if len(minStr) == len(maxStr) {
			return rangeFixed(minStr, maxStr)
		}
	}
	var branches []string
	curLo := minStr
	for w := len(minStr); w <= len(maxStr); w++ {
		if w < len(maxStr) {
			hiW := strings.Repeat("9", w)
			branches = append(branches, rangeFixed(curLo, hiW))
			curLo = "1" + strings.Repeat("0", w)
		} else {
			branches = append(branches, rangeFixed(curLo, maxStr))
		}
	}
	if len(branches) == 1 {
		return branches[0]
	}
	return "(?:" + strings.Join(branches, "|") + ")"
}

type luceneRegexpParser struct {
	runes []rune
	pos   int
	flags luceneRegexpFlags
	raw   string
}

func (p *luceneRegexpParser) parseUnion() (*luceneAutoNode, error) {
	first, err := p.parseIntersection()
	if err != nil {
		return nil, err
	}
	branches := []*luceneAutoNode{first}
	for p.pos < len(p.runes) && p.runes[p.pos] == '|' {
		p.pos++
		next, err := p.parseIntersection()
		if err != nil {
			return nil, err
		}
		branches = append(branches, next)
	}
	if len(branches) == 1 {
		return branches[0], nil
	}
	var nonEmpty []*luceneAutoNode
	allPureRE2 := true
	for _, br := range branches {
		if br.kind == luceneNodeEmpty {
			continue
		}
		if br.kind != luceneNodeRE2 {
			allPureRE2 = false
		}
		nonEmpty = append(nonEmpty, br)
	}
	if len(nonEmpty) == 0 {
		return &luceneAutoNode{kind: luceneNodeEmpty}, nil
	}
	if len(nonEmpty) == 1 {
		return nonEmpty[0], nil
	}
	if allPureRE2 {
		parts := make([]string, len(nonEmpty))
		for i, br := range nonEmpty {
			parts[i] = br.re2
		}
		return &luceneAutoNode{
			kind: luceneNodeRE2,
			re2:  "(?:" + strings.Join(parts, "|") + ")",
		}, nil
	}
	return &luceneAutoNode{
		kind:     luceneNodeUnion,
		children: nonEmpty,
	}, nil
}

func (p *luceneRegexpParser) parseIntersection() (*luceneAutoNode, error) {
	first, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	if !p.flags.intersection {
		return first, nil
	}
	conjuncts := []*luceneAutoNode{first}
	for p.pos < len(p.runes) && p.runes[p.pos] == '&' {
		p.pos++
		next, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		conjuncts = append(conjuncts, next)
	}
	if len(conjuncts) == 1 {
		return conjuncts[0], nil
	}
	var filtered []*luceneAutoNode
	for _, c := range conjuncts {
		if c.kind == luceneNodeEmpty {
			return &luceneAutoNode{kind: luceneNodeEmpty}, nil
		}
		if c.kind == luceneNodeRE2 && c.isAnyStr {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return &luceneAutoNode{kind: luceneNodeRE2, re2: "(?s:.*)", isAnyStr: true}, nil
	}
	if len(filtered) == 1 {
		return filtered[0], nil
	}
	return &luceneAutoNode{
		kind:     luceneNodeInter,
		children: filtered,
	}, nil
}

func (p *luceneRegexpParser) isConcatStop(r rune) bool {
	if r == ')' || r == '|' {
		return true
	}
	if p.flags.intersection && r == '&' {
		return true
	}
	return false
}

func (p *luceneRegexpParser) parseConcat() (*luceneAutoNode, error) {
	var items []*luceneAutoNode
	for p.pos < len(p.runes) && !p.isConcatStop(p.runes[p.pos]) {
		rep, err := p.parseRepeat()
		if err != nil {
			return nil, err
		}
		items = append(items, rep)
	}
	if len(items) == 0 {
		return &luceneAutoNode{kind: luceneNodeRE2, re2: "", hasLiteral: true, literal: ""}, nil
	}
	if len(items) == 1 {
		return items[0], nil
	}
	var re2Builder strings.Builder
	var litBuilder strings.Builder
	allLit := true
	for _, it := range items {
		if it.kind == luceneNodeEmpty {
			return &luceneAutoNode{kind: luceneNodeEmpty}, nil
		}
		subRE2, ok := it.asSubRE2()
		if !ok {
			return nil, fmt.Errorf("regexp_syntax_exception: unsupported nested automaton operator inside concatenation in [%s]", p.raw)
		}
		re2Builder.WriteString(subRE2)
		if it.kind == luceneNodeRE2 && it.hasLiteral {
			litBuilder.WriteString(it.literal)
		} else {
			allLit = false
		}
	}
	out := &luceneAutoNode{
		kind: luceneNodeRE2,
		re2:  re2Builder.String(),
	}
	if allLit {
		out.hasLiteral = true
		out.literal = litBuilder.String()
	}
	return out, nil
}

func (n *luceneAutoNode) asSubRE2() (string, bool) {
	switch n.kind {
	case luceneNodeRE2:
		return n.re2, true
	case luceneNodeCompl:
		if n.complRE2 != "" {
			return n.complRE2, true
		}
		return "", false
	case luceneNodeUnion:
		var parts []string
		for _, ch := range n.children {
			s, ok := ch.asSubRE2()
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return "(?:" + strings.Join(parts, "|") + ")", true
	default:
		return "", false
	}
}

func isAtomicRE2Unit(s string) bool {
	if s == "" {
		return false
	}
	if len(s) == 2 && s[0] == '\\' {
		return true
	}
	if utf8.RuneCountInString(s) == 1 {
		switch s {
		case "|", "*", "+", "?", "(", ")", "[", "]", "{", "}", "^", "$", `\`:
			return false
		default:
			return true
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		depth := 0
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '[' {
				if depth == 0 && i > 0 {
					return false
				}
				if i+1 < len(s) && s[i+1] == ':' {
					depth++
					continue
				}
				if i == 0 {
					depth = 1
				}
			} else if s[i] == ']' {
				if i == 1 || (i == 2 && s[1] == '^') {
					continue
				}
				depth--
				if depth == 0 && i < len(s)-1 {
					return false
				}
			}
		}
		return depth == 0
	}
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		depth := 0
		inClass := false
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if inClass {
				if s[i] == ']' {
					inClass = false
				}
				continue
			}
			switch s[i] {
			case '[':
				inClass = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i < len(s)-1 {
					return false
				}
			}
		}
		return depth == 0
	}
	return false
}

func (p *luceneRegexpParser) parseRepeat() (*luceneAutoNode, error) {
	base, err := p.parseCompl()
	if err != nil {
		return nil, err
	}
	for p.pos < len(p.runes) {
		r := p.runes[p.pos]
		if r != '?' && r != '*' && r != '+' && r != '{' {
			break
		}
		var qStr string
		minRep := 0
		maxRep := -1
		switch r {
		case '?':
			p.pos++
			qStr = "?"
			minRep, maxRep = 0, 1
		case '*':
			p.pos++
			qStr = "*"
			minRep, maxRep = 0, -1
		case '+':
			p.pos++
			qStr = "+"
			minRep, maxRep = 1, -1
		case '{':
			qParsed, lo, hi, errQ := p.parseBracedQuantifier()
			if errQ != nil {
				return nil, errQ
			}
			qStr = qParsed
			minRep, maxRep = lo, hi
		}
		if base.kind == luceneNodeEmpty {
			if minRep == 0 {
				base = &luceneAutoNode{kind: luceneNodeRE2, re2: "", hasLiteral: true, literal: ""}
			}
			continue
		}
		subRE2, ok := base.asSubRE2()
		if !ok {
			return nil, fmt.Errorf("regexp_syntax_exception: unsupported quantifier over complex automaton expression in [%s]", p.raw)
		}
		_ = maxRep
		wrapped := subRE2
		if !isAtomicRE2Unit(subRE2) {
			wrapped = "(?:" + subRE2 + ")"
		}
		base = &luceneAutoNode{
			kind: luceneNodeRE2,
			re2:  wrapped + qStr,
		}
	}
	return base, nil
}

func (p *luceneRegexpParser) parseBracedQuantifier() (string, int, int, error) {
	start := p.pos
	p.pos++ // consume '{'
	closeIdx := -1
	for i := p.pos; i < len(p.runes); i++ {
		if p.runes[i] == '}' {
			closeIdx = i
			break
		}
	}
	if closeIdx < 0 {
		return "", 0, 0, fmt.Errorf("regexp_syntax_exception: expected '}' in quantifier in [%s]", p.raw)
	}
	body := string(p.runes[p.pos:closeIdx])
	p.pos = closeIdx + 1
	if body == "" {
		return "", 0, 0, fmt.Errorf("regexp_syntax_exception: empty quantifier '{}' in [%s]", p.raw)
	}
	if comma := strings.IndexByte(body, ','); comma >= 0 {
		loPart := body[:comma]
		hiPart := body[comma+1:]
		if !isPureDigitsASCII(loPart) {
			return "", 0, 0, fmt.Errorf("regexp_syntax_exception: invalid quantifier '{%s}' in [%s]", body, p.raw)
		}
		lo, errLo := strconv.Atoi(loPart)
		if errLo != nil || lo < 0 {
			return "", 0, 0, fmt.Errorf("regexp_syntax_exception: invalid quantifier '{%s}' in [%s]", body, p.raw)
		}
		if hiPart == "" {
			return "{" + body + "}", lo, -1, nil
		}
		if !isPureDigitsASCII(hiPart) {
			return "", 0, 0, fmt.Errorf("regexp_syntax_exception: invalid quantifier '{%s}' in [%s]", body, p.raw)
		}
		hi, errHi := strconv.Atoi(hiPart)
		if errHi != nil || hi < lo {
			return "", 0, 0, fmt.Errorf("regexp_syntax_exception: out-of-order quantifier '{%s}' in [%s]", body, p.raw)
		}
		return "{" + body + "}", lo, hi, nil
	}
	if !isPureDigitsASCII(body) {
		_ = start
		return "", 0, 0, fmt.Errorf("regexp_syntax_exception: invalid quantifier '{%s}' in [%s]", body, p.raw)
	}
	n, errN := strconv.Atoi(body)
	if errN != nil || n < 0 {
		return "", 0, 0, fmt.Errorf("regexp_syntax_exception: invalid quantifier '{%s}' in [%s]", body, p.raw)
	}
	return "{" + body + "}", n, n, nil
}

func (p *luceneRegexpParser) parseCompl() (*luceneAutoNode, error) {
	if p.flags.complement && p.pos < len(p.runes) && p.runes[p.pos] == '~' {
		p.pos++
		inner, err := p.parseCompl()
		if err != nil {
			return nil, err
		}
		switch inner.kind {
		case luceneNodeEmpty:
			return &luceneAutoNode{kind: luceneNodeRE2, re2: "(?s:.*)", isAnyStr: true}, nil
		case luceneNodeCompl:
			return inner.child, nil
		case luceneNodeRE2:
			if inner.isAnyStr {
				return &luceneAutoNode{kind: luceneNodeEmpty}, nil
			}
			cNode := &luceneAutoNode{
				kind:  luceneNodeCompl,
				child: inner,
			}
			if inner.hasLiteral {
				cNode.complRE2 = complementOfLiteralRE2(inner.literal)
			}
			return cNode, nil
		default:
			return &luceneAutoNode{
				kind:  luceneNodeCompl,
				child: inner,
			}, nil
		}
	}
	return p.parseAtom()
}

func (p *luceneRegexpParser) parseAtom() (*luceneAutoNode, error) {
	if p.pos >= len(p.runes) {
		return &luceneAutoNode{kind: luceneNodeRE2, re2: "", hasLiteral: true, literal: ""}, nil
	}
	r := p.runes[p.pos]
	switch r {
	case '?', '*', '+', '{', ')':
		return nil, fmt.Errorf("regexp_syntax_exception: unexpected '%c' at position %d in [%s]", r, p.pos, p.raw)
	case '.':
		p.pos++
		return &luceneAutoNode{kind: luceneNodeRE2, re2: "(?s:.)"}, nil
	case '^':
		p.pos++
		return &luceneAutoNode{kind: luceneNodeRE2, re2: `\^`, hasLiteral: true, literal: "^"}, nil
	case '$':
		p.pos++
		return &luceneAutoNode{kind: luceneNodeRE2, re2: `\$`, hasLiteral: true, literal: "$"}, nil
	case '#':
		p.pos++
		if p.flags.empty {
			return &luceneAutoNode{kind: luceneNodeEmpty}, nil
		}
		return &luceneAutoNode{kind: luceneNodeRE2, re2: `#`, hasLiteral: true, literal: "#"}, nil
	case '@':
		p.pos++
		if p.flags.anystring {
			return &luceneAutoNode{kind: luceneNodeRE2, re2: "(?s:.*)", isAnyStr: true}, nil
		}
		return &luceneAutoNode{kind: luceneNodeRE2, re2: `@`, hasLiteral: true, literal: "@"}, nil
	case '"':
		p.pos++
		var lit strings.Builder
		var re2 strings.Builder
		closed := false
		for p.pos < len(p.runes) {
			ch := p.runes[p.pos]
			p.pos++
			if ch == '"' {
				closed = true
				break
			}
			lit.WriteRune(ch)
			re2.WriteString(regexp.QuoteMeta(string(ch)))
		}
		if !closed {
			return nil, fmt.Errorf("regexp_syntax_exception: unclosed double quote in [%s]", p.raw)
		}
		return &luceneAutoNode{
			kind:       luceneNodeRE2,
			re2:        re2.String(),
			hasLiteral: true,
			literal:    lit.String(),
		}, nil
	case '(':
		p.pos++
		if p.pos+1 < len(p.runes) && p.runes[p.pos] == '?' && p.runes[p.pos+1] == ':' {
			p.pos += 2
		}
		inner, err := p.parseUnion()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.runes) || p.runes[p.pos] != ')' {
			return nil, fmt.Errorf("regexp_syntax_exception: expected ')' at position %d in [%s]", p.pos, p.raw)
		}
		p.pos++
		if inner.kind == luceneNodeRE2 && !inner.hasLiteral && !inner.isAnyStr {
			return &luceneAutoNode{
				kind: luceneNodeRE2,
				re2:  "(?:" + inner.re2 + ")",
			}, nil
		}
		return inner, nil
	case '[':
		return p.parseCharClass()
	case '<':
		if p.flags.interval || p.flags.automaton {
			if node, consumed, err := p.tryParseAngleBracket(); consumed || err != nil {
				return node, err
			}
		}
		p.pos++
		return &luceneAutoNode{kind: luceneNodeRE2, re2: "<", hasLiteral: true, literal: "<"}, nil
	case '\\':
		p.pos++
		if p.pos >= len(p.runes) {
			return nil, fmt.Errorf("regexp_syntax_exception: trailing backslash in [%s]", p.raw)
		}
		esc := p.runes[p.pos]
		p.pos++
		switch esc {
		case 'd', 'D', 's', 'S', 'w', 'W':
			return &luceneAutoNode{kind: luceneNodeRE2, re2: `\` + string(esc)}, nil
		case 'n':
			return &luceneAutoNode{kind: luceneNodeRE2, re2: `\n`, hasLiteral: true, literal: "\n"}, nil
		case 'r':
			return &luceneAutoNode{kind: luceneNodeRE2, re2: `\r`, hasLiteral: true, literal: "\r"}, nil
		case 't':
			return &luceneAutoNode{kind: luceneNodeRE2, re2: `\t`, hasLiteral: true, literal: "\t"}, nil
		default:
			return &luceneAutoNode{
				kind:       luceneNodeRE2,
				re2:        regexp.QuoteMeta(string(esc)),
				hasLiteral: true,
				literal:    string(esc),
			}, nil
		}
	default:
		p.pos++
		return &luceneAutoNode{
			kind:       luceneNodeRE2,
			re2:        regexp.QuoteMeta(string(r)),
			hasLiteral: true,
			literal:    string(r),
		}, nil
	}
}

func (p *luceneRegexpParser) parseCharClass() (*luceneAutoNode, error) {
	p.pos++ // consume '['
	var sb strings.Builder
	sb.WriteByte('[')
	if p.pos < len(p.runes) && p.runes[p.pos] == '^' {
		sb.WriteByte('^')
		p.pos++
	}
	first := true
	closed := false
	for p.pos < len(p.runes) {
		r := p.runes[p.pos]
		if r == ']' && !first {
			sb.WriteByte(']')
			p.pos++
			closed = true
			break
		}
		first = false
		if r == '[' && p.pos+1 < len(p.runes) && p.runes[p.pos+1] == ':' {
			endPos := -1
			for k := p.pos + 2; k+1 < len(p.runes); k++ {
				if p.runes[k] == ':' && p.runes[k+1] == ']' {
					endPos = k + 2
					break
				}
			}
			if endPos > 0 {
				sb.WriteString(string(p.runes[p.pos:endPos]))
				p.pos = endPos
				continue
			}
		}
		if r == '\\' {
			p.pos++
			if p.pos >= len(p.runes) {
				return nil, fmt.Errorf("regexp_syntax_exception: trailing backslash in character class in [%s]", p.raw)
			}
			esc := p.runes[p.pos]
			p.pos++
			switch esc {
			case 'd', 'D', 's', 'S', 'w', 'W', 'n', 'r', 't', '\\', '-', ']', '[', '^':
				sb.WriteByte('\\')
				sb.WriteRune(esc)
			default:
				sb.WriteString(escapeRE2CharClassMember(esc))
			}
			continue
		}
		if r == ']' {
			sb.WriteString(`\]`)
			p.pos++
			continue
		}
		sb.WriteRune(r)
		p.pos++
	}
	if !closed {
		return nil, fmt.Errorf("regexp_syntax_exception: unclosed character class '[' in [%s]", p.raw)
	}
	cls := sb.String()
	if _, err := regexp.Compile(cls); err != nil {
		return nil, fmt.Errorf("regexp_syntax_exception: invalid character class %s in [%s]: %w", cls, p.raw, err)
	}
	return &luceneAutoNode{kind: luceneNodeRE2, re2: cls}, nil
}

func (p *luceneRegexpParser) tryParseAngleBracket() (*luceneAutoNode, bool, error) {
	closeIdx := -1
	for i := p.pos + 1; i < len(p.runes); i++ {
		if p.runes[i] == '>' {
			closeIdx = i
			break
		}
		if p.runes[i] == '<' || p.runes[i] == '\\' {
			break
		}
	}
	if closeIdx < 0 {
		return nil, false, nil
	}
	inner := string(p.runes[p.pos+1 : closeIdx])
	if p.flags.interval {
		if dash := strings.IndexByte(inner, '-'); dash > 0 && dash < len(inner)-1 {
			loStr := inner[:dash]
			hiStr := inner[dash+1:]
			if isPureDigitsASCII(loStr) && isPureDigitsASCII(hiStr) {
				loVal, errLo := strconv.ParseUint(loStr, 10, 64)
				hiVal, errHi := strconv.ParseUint(hiStr, 10, 64)
				if errLo != nil || errHi != nil {
					return nil, true, fmt.Errorf("illegal_argument_exception: numeric interval out of range [<%s>] in [%s]", inner, p.raw)
				}
				if loVal > hiVal {
					return nil, true, fmt.Errorf("illegal_argument_exception: invalid numeric interval [<%s>]: min > max in [%s]", inner, p.raw)
				}
				fixedWidth := 0
				if len(loStr) == len(hiStr) {
					fixedWidth = len(loStr)
				}
				p.pos = closeIdx + 1
				return &luceneAutoNode{
					kind: luceneNodeRE2,
					re2:  buildNumericIntervalRE2(loVal, hiVal, fixedWidth),
				}, true, nil
			}
		}
	}
	return nil, false, nil
}

func nodeContainsCompl(n *luceneAutoNode) bool {
	if n == nil {
		return false
	}
	if n.kind == luceneNodeCompl {
		return true
	}
	for _, ch := range n.children {
		if nodeContainsCompl(ch) {
			return true
		}
	}
	return nodeContainsCompl(n.child)
}

func validateNodeRE2(n *luceneAutoNode, ci bool, raw string) error {
	if n == nil {
		return nil
	}
	switch n.kind {
	case luceneNodeRE2:
		anchored := fullTermAnchorRE2(n.re2, ci)
		if _, err := regexp.Compile(anchored); err != nil {
			return fmt.Errorf("regexp_syntax_exception: invalid regular expression [%s]: %w", raw, err)
		}
	case luceneNodeCompl:
		return validateNodeRE2(n.child, ci, raw)
	case luceneNodeUnion, luceneNodeInter:
		for _, ch := range n.children {
			if err := validateNodeRE2(ch, ci, raw); err != nil {
				return err
			}
		}
	}
	return nil
}

func fullTermAnchorRE2(re2Body string, caseInsensitive bool) string {
	if caseInsensitive {
		return "(?i)^(?:" + re2Body + ")$"
	}
	return "^(?:" + re2Body + ")$"
}

// CompileLuceneRegexpToSQLPredicates parses a Lucene automaton regular expression with the
// specified ES `flags` (`ALL`, `NONE`, `INTERSECTION`, `COMPLEMENT`, `EMPTY`, `ANYSTRING`,
// `INTERVAL`, `AUTOMATON`) and builds full-term anchored RE2 / SQL predicates.
func CompileLuceneRegexpToSQLPredicates(pattern, flags string, caseInsensitive bool) (*LuceneRegexpCompiled, error) {
	parsedFlags, err := parseLuceneRegexpFlags(flags)
	if err != nil {
		return nil, err
	}
	raw := pattern
	if strings.HasPrefix(pattern, "(?i)") {
		caseInsensitive = true
		pattern = pattern[4:]
	}
	parser := &luceneRegexpParser{
		runes: []rune(pattern),
		flags: parsedFlags,
		raw:   raw,
	}
	root, err := parser.parseUnion()
	if err != nil {
		return nil, err
	}
	if parser.pos < len(parser.runes) {
		return nil, fmt.Errorf("regexp_syntax_exception: unexpected '%c' at position %d in [%s]", parser.runes[parser.pos], parser.pos, raw)
	}
	if err := validateNodeRE2(root, caseInsensitive, raw); err != nil {
		return nil, err
	}
	return &LuceneRegexpCompiled{
		IsEmpty:      root.kind == luceneNodeEmpty,
		NeedsNotNull: nodeContainsCompl(root),
		root:         root,
		caseInsens:   caseInsensitive,
	}, nil
}

func renderLuceneAutoNodeSQL(n *luceneAutoNode, targetExpr string, ci bool) string {
	switch n.kind {
	case luceneNodeEmpty:
		return "FALSE"
	case luceneNodeRE2:
		pat := fullTermAnchorRE2(n.re2, ci)
		return fmt.Sprintf("%s REGEXP %s", targetExpr, quoteStr(pat))
	case luceneNodeCompl:
		innerSQL := renderLuceneAutoNodeSQL(n.child, targetExpr, ci)
		return fmt.Sprintf("NOT (%s)", innerSQL)
	case luceneNodeInter:
		parts := make([]string, 0, len(n.children))
		for _, ch := range n.children {
			sub := renderLuceneAutoNodeSQL(ch, targetExpr, ci)
			parts = append(parts, "("+sub+")")
		}
		return "(" + strings.Join(parts, " AND ") + ")"
	case luceneNodeUnion:
		parts := make([]string, 0, len(n.children))
		for _, ch := range n.children {
			sub := renderLuceneAutoNodeSQL(ch, targetExpr, ci)
			parts = append(parts, "("+sub+")")
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	default:
		return "FALSE"
	}
}

func tokenAnchorRE2(re2Body string) string {
	return "(?i)(?:^|[^[:alnum:]_])(?:" + re2Body + ")(?:$|[^[:alnum:]_])"
}

func renderLuceneAutoNodeTokenSQL(n *luceneAutoNode, targetExpr string) string {
	switch n.kind {
	case luceneNodeEmpty:
		return "FALSE"
	case luceneNodeRE2:
		if n.isAnyStr {
			return fmt.Sprintf("%s REGEXP '(?i)[[:alnum:]_]'", targetExpr)
		}
		pat := tokenAnchorRE2(n.re2)
		return fmt.Sprintf("%s REGEXP %s", targetExpr, quoteStr(pat))
	case luceneNodeCompl:
		innerSQL := renderLuceneAutoNodeTokenSQL(n.child, targetExpr)
		return fmt.Sprintf("NOT (%s)", innerSQL)
	case luceneNodeInter:
		parts := make([]string, 0, len(n.children))
		for _, ch := range n.children {
			parts = append(parts, "("+renderLuceneAutoNodeTokenSQL(ch, targetExpr)+")")
		}
		return "(" + strings.Join(parts, " AND ") + ")"
	case luceneNodeUnion:
		parts := make([]string, 0, len(n.children))
		for _, ch := range n.children {
			parts = append(parts, "("+renderLuceneAutoNodeTokenSQL(ch, targetExpr)+")")
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	default:
		return "FALSE"
	}
}

// ScalarSQL renders `(whereSQL, safeWhereSQL, usesFulltext)` for a scalar SQL column expression.
// RE2 predicates always use Apache Doris's `REGEXP` (Google RE2) rather than `MATCH_REGEXP`
// (CLucene Automaton, which rejects `(?:...)` / `(?i)` / `(?s:.)` and treats `^` / `$` literally).
func (c *LuceneRegexpCompiled) ScalarSQL(colExpr string, _ bool, isTokenizedText bool) (string, string, bool) {
	if c == nil || c.IsEmpty {
		return "FALSE", "FALSE", false
	}
	if isTokenizedText {
		tokCore := renderLuceneAutoNodeTokenSQL(c.root, colExpr)
		safePred := fmt.Sprintf("(%s IS NOT NULL AND %s)", colExpr, tokCore)
		if c.NeedsNotNull {
			return safePred, safePred, false
		}
		return tokCore, safePred, false
	}
	safeCore := renderLuceneAutoNodeSQL(c.root, colExpr, c.caseInsens)
	safePred := fmt.Sprintf("(%s IS NOT NULL AND %s)", colExpr, safeCore)
	if c.NeedsNotNull {
		return safePred, safePred, false
	}
	return safeCore, safePred, false
}

// ArrayElemSQL renders the predicate body for an array element variable (e.g., `_x`) inside `array_exists`.
func (c *LuceneRegexpCompiled) ArrayElemSQL(elemVar string) string {
	if c == nil || c.IsEmpty {
		return "FALSE"
	}
	core := renderLuceneAutoNodeSQL(c.root, elemVar, c.caseInsens)
	if c.NeedsNotNull {
		return fmt.Sprintf("(%s IS NOT NULL AND %s)", elemVar, core)
	}
	return core
}
