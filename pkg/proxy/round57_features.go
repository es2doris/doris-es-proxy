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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// Round 57 F2: SQL Engine Compliance (/_sql, /_sql/translate)
// ============================================================================

type sqlTokKind int

const (
	sqlTokEOF sqlTokKind = iota
	sqlTokIdent
	sqlTokQuotedIdent
	sqlTokString
	sqlTokNumber
	sqlTokOp
	sqlTokLParen
	sqlTokRParen
	sqlTokComma
	sqlTokStar
)

type sqlToken struct {
	kind sqlTokKind
	val  string
	raw  string
}

func tokenizeRound57SQL(input string) ([]sqlToken, error) {
	var toks []sqlToken
	n := len(input)
	for i := 0; i < n; {
		ch := input[i]
		if unicode.IsSpace(rune(ch)) {
			i++
			continue
		}
		if ch == '-' && i+1 < n && input[i+1] == '-' {
			for i < n && input[i] != '\n' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < n && input[i+1] == '*' {
			end := strings.Index(input[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unclosed block comment")
			}
			i += 2 + end + 2
			continue
		}
		if ch == ';' {
			i++
			continue
		}
		if ch == '\'' {
			start := i
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				if input[i] == '\'' {
					if i+1 < n && input[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if input[i] == '\\' && i+1 < n {
					i++
					sb.WriteByte(input[i])
					i++
					continue
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed string literal")
			}
			toks = append(toks, sqlToken{kind: sqlTokString, val: sb.String(), raw: input[start:i]})
			continue
		}
		if ch == '"' || ch == '`' {
			quote := ch
			start := i
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				if input[i] == quote {
					if i+1 < n && input[i+1] == quote {
						sb.WriteByte(quote)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed quoted identifier")
			}
			toks = append(toks, sqlToken{kind: sqlTokQuotedIdent, val: sb.String(), raw: input[start:i]})
			continue
		}
		if ch >= '0' && ch <= '9' || (ch == '.' && i+1 < n && input[i+1] >= '0' && input[i+1] <= '9') {
			start := i
			for i < n && input[i] >= '0' && input[i] <= '9' {
				i++
			}
			if i < n && input[i] == '.' {
				i++
				for i < n && input[i] >= '0' && input[i] <= '9' {
					i++
				}
			}
			if i < n && (input[i] == 'e' || input[i] == 'E') {
				i++
				if i < n && (input[i] == '+' || input[i] == '-') {
					i++
				}
				for i < n && input[i] >= '0' && input[i] <= '9' {
					i++
				}
			}
			lit := input[start:i]
			toks = append(toks, sqlToken{kind: sqlTokNumber, val: lit, raw: lit})
			continue
		}
		switch ch {
		case '(':
			toks = append(toks, sqlToken{kind: sqlTokLParen, val: "(", raw: "("})
			i++
			continue
		case ')':
			toks = append(toks, sqlToken{kind: sqlTokRParen, val: ")", raw: ")"})
			i++
			continue
		case ',':
			toks = append(toks, sqlToken{kind: sqlTokComma, val: ",", raw: ","})
			i++
			continue
		case '*':
			toks = append(toks, sqlToken{kind: sqlTokStar, val: "*", raw: "*"})
			i++
			continue
		case '+', '-', '/', '%':
			s := string(ch)
			toks = append(toks, sqlToken{kind: sqlTokOp, val: s, raw: s})
			i++
			continue
		case '=':
			toks = append(toks, sqlToken{kind: sqlTokOp, val: "=", raw: "="})
			i++
			continue
		case '!':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, sqlToken{kind: sqlTokOp, val: "!=", raw: "!="})
				i += 2
				continue
			}
			return nil, fmt.Errorf("unexpected character '!'")
		case '<':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, sqlToken{kind: sqlTokOp, val: "<=", raw: "<="})
				i += 2
				continue
			}
			if i+1 < n && input[i+1] == '>' {
				toks = append(toks, sqlToken{kind: sqlTokOp, val: "!=", raw: "<>"})
				i += 2
				continue
			}
			toks = append(toks, sqlToken{kind: sqlTokOp, val: "<", raw: "<"})
			i++
			continue
		case '>':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, sqlToken{kind: sqlTokOp, val: ">=", raw: ">="})
				i += 2
				continue
			}
			toks = append(toks, sqlToken{kind: sqlTokOp, val: ">", raw: ">"})
			i++
			continue
		}
		if unicode.IsLetter(rune(ch)) || ch == '_' || ch == '@' {
			start := i
			for i < n {
				r := rune(input[i])
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '@' || r == '-' {
					// Stop at '-' if followed by space or digit outside identifier context unless part of index name
					if r == '-' {
						// Allow '-' inside table/field identifiers only when immediately followed by letter/digit without spaces
						if i+1 >= n || (!unicode.IsLetter(rune(input[i+1])) && !unicode.IsDigit(rune(input[i+1]))) {
							break
						}
					}
					i++
				} else {
					break
				}
			}
			ident := input[start:i]
			toks = append(toks, sqlToken{kind: sqlTokIdent, val: ident, raw: ident})
			continue
		}
		return nil, fmt.Errorf("unexpected character %q", ch)
	}
	toks = append(toks, sqlToken{kind: sqlTokEOF})
	return toks, nil
}

func substituteSQLParams(query string, params []any) (string, error) {
	if !strings.Contains(query, "?") {
		return query, nil
	}
	var out strings.Builder
	paramIdx := 0
	inSingle, inDouble, inBacktick := false, false, false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if inSingle {
			out.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
					out.WriteByte(query[i])
				} else {
					inSingle = false
				}
			} else if ch == '\\' && i+1 < len(query) {
				i++
				out.WriteByte(query[i])
			}
			continue
		}
		if inDouble {
			out.WriteByte(ch)
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			out.WriteByte(ch)
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			out.WriteByte(ch)
		case '"':
			inDouble = true
			out.WriteByte(ch)
		case '`':
			inBacktick = true
			out.WriteByte(ch)
		case '?':
			if paramIdx >= len(params) {
				return "", fmt.Errorf("missing value for parameter [%d]", paramIdx+1)
			}
			pv := params[paramIdx]
			paramIdx++
			if m, ok := pv.(map[string]any); ok {
				if v, hasVal := m["value"]; hasVal {
					pv = v
				}
			}
			switch v := pv.(type) {
			case nil:
				out.WriteString("NULL")
			case bool:
				if v {
					out.WriteString("TRUE")
				} else {
					out.WriteString("FALSE")
				}
			case int, int64, int32, float64, float32, json.Number:
				_, _ = fmt.Fprintf(&out, "%v", v)
			default:
				escaped := strings.ReplaceAll(fmt.Sprintf("%v", v), "'", "''")
				out.WriteByte('\'')
				out.WriteString(escaped)
				out.WriteByte('\'')
			}
		default:
			out.WriteByte(ch)
		}
	}
	return out.String(), nil
}

type sqlExpr interface {
	sqlExprLabel() string
}

type sqlColExpr struct {
	name string
}

func (e *sqlColExpr) sqlExprLabel() string { return e.name }

type sqlLitExpr struct {
	val any
	raw string
}

func (e *sqlLitExpr) sqlExprLabel() string { return e.raw }

type sqlStarExpr struct{}

func (e *sqlStarExpr) sqlExprLabel() string { return "*" }

type sqlUnaryExpr struct {
	op  string
	sub sqlExpr
}

func (e *sqlUnaryExpr) sqlExprLabel() string { return e.op + e.sub.sqlExprLabel() }

type sqlBinaryExpr struct {
	op    string
	left  sqlExpr
	right sqlExpr
}

func (e *sqlBinaryExpr) sqlExprLabel() string {
	return fmt.Sprintf("%s %s %s", e.left.sqlExprLabel(), e.op, e.right.sqlExprLabel())
}

type sqlIsNullExpr struct {
	sub    sqlExpr
	negate bool
}

func (e *sqlIsNullExpr) sqlExprLabel() string {
	if e.negate {
		return e.sub.sqlExprLabel() + " IS NOT NULL"
	}
	return e.sub.sqlExprLabel() + " IS NULL"
}

type sqlInExpr struct {
	left   sqlExpr
	list   []sqlExpr
	negate bool
}

func (e *sqlInExpr) sqlExprLabel() string { return e.left.sqlExprLabel() + " IN (...)" }

type sqlBetweenExpr struct {
	val    sqlExpr
	low    sqlExpr
	high   sqlExpr
	negate bool
}

func (e *sqlBetweenExpr) sqlExprLabel() string { return e.val.sqlExprLabel() + " BETWEEN ..." }

type sqlLikeExpr struct {
	left    sqlExpr
	pattern sqlExpr
	negate  bool
}

func (e *sqlLikeExpr) sqlExprLabel() string { return e.left.sqlExprLabel() + " LIKE ..." }

type sqlFuncExpr struct {
	name     string
	args     []sqlExpr
	distinct bool
	starArg  bool
}

func (e *sqlFuncExpr) sqlExprLabel() string {
	if e.starArg {
		return fmt.Sprintf("%s(*)", strings.ToUpper(e.name))
	}
	parts := make([]string, len(e.args))
	for i, a := range e.args {
		parts[i] = a.sqlExprLabel()
	}
	prefix := ""
	if e.distinct {
		prefix = "DISTINCT "
	}
	return fmt.Sprintf("%s(%s%s)", strings.ToUpper(e.name), prefix, strings.Join(parts, ", "))
}

type sqlSelectItem struct {
	expr  sqlExpr
	alias string
	star  bool
}

type sqlOrderItem struct {
	expr       sqlExpr
	desc       bool
	nullsFirst *bool
}

type sqlSelectStmt struct {
	distinct bool
	top      int
	items    []sqlSelectItem
	from     string
	where    sqlExpr
	groupBy  []sqlExpr
	having   sqlExpr
	orderBy  []sqlOrderItem
	limit    int
}

type sqlParser struct {
	toks []sqlToken
	pos  int
}

func (p *sqlParser) cur() sqlToken {
	if p.pos >= len(p.toks) {
		return sqlToken{kind: sqlTokEOF}
	}
	return p.toks[p.pos]
}

func (p *sqlParser) matchKw(kw string) bool {
	t := p.cur()
	if t.kind == sqlTokIdent && strings.EqualFold(t.val, kw) {
		p.pos++
		return true
	}
	return false
}

func (p *sqlParser) peekKw(kw string) bool {
	t := p.cur()
	return t.kind == sqlTokIdent && strings.EqualFold(t.val, kw)
}

func (p *sqlParser) parseSelect() (*sqlSelectStmt, error) {
	if !p.matchKw("SELECT") {
		return nil, fmt.Errorf("expected SELECT")
	}
	stmt := &sqlSelectStmt{top: -1, limit: -1}
	if p.matchKw("DISTINCT") {
		stmt.distinct = true
	} else {
		p.matchKw("ALL")
	}
	if p.matchKw("TOP") {
		nt := p.cur()
		if nt.kind != sqlTokNumber {
			return nil, fmt.Errorf("expected integer after TOP")
		}
		p.pos++
		tv, err := strconv.Atoi(nt.val)
		if err != nil || tv < 0 {
			return nil, fmt.Errorf("invalid TOP value [%s]", nt.val)
		}
		stmt.top = tv
	}
	for {
		if p.cur().kind == sqlTokStar {
			p.pos++
			stmt.items = append(stmt.items, sqlSelectItem{expr: &sqlStarExpr{}, star: true})
		} else {
			ex, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			alias := ""
			if p.matchKw("AS") {
				at := p.cur()
				if at.kind != sqlTokIdent && at.kind != sqlTokQuotedIdent && at.kind != sqlTokString {
					return nil, fmt.Errorf("expected alias after AS")
				}
				p.pos++
				alias = at.val
			} else if (p.cur().kind == sqlTokIdent || p.cur().kind == sqlTokQuotedIdent) && !isSQLClauseKeyword(p.cur().val) {
				alias = p.cur().val
				p.pos++
			}
			stmt.items = append(stmt.items, sqlSelectItem{expr: ex, alias: alias})
		}
		if p.cur().kind == sqlTokComma {
			p.pos++
			continue
		}
		break
	}
	if len(stmt.items) == 0 {
		return nil, fmt.Errorf("SELECT list cannot be empty")
	}
	if p.matchKw("FROM") {
		tbl, err := p.parseTableName()
		if err != nil {
			return nil, err
		}
		stmt.from = tbl
		// Optional table alias
		if p.matchKw("AS") {
			if p.cur().kind == sqlTokIdent || p.cur().kind == sqlTokQuotedIdent {
				p.pos++
			}
		} else if (p.cur().kind == sqlTokIdent || p.cur().kind == sqlTokQuotedIdent) && !isSQLClauseKeyword(p.cur().val) {
			p.pos++
		}
	}
	if p.matchKw("WHERE") {
		we, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		stmt.where = we
	}
	if p.matchKw("GROUP") {
		if !p.matchKw("BY") {
			return nil, fmt.Errorf("expected BY after GROUP")
		}
		for {
			ge, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			stmt.groupBy = append(stmt.groupBy, ge)
			if p.cur().kind == sqlTokComma {
				p.pos++
				continue
			}
			break
		}
	}
	if p.matchKw("HAVING") {
		he, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		stmt.having = he
	}
	if p.matchKw("ORDER") {
		if !p.matchKw("BY") {
			return nil, fmt.Errorf("expected BY after ORDER")
		}
		for {
			oe, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			desc := false
			if p.matchKw("DESC") {
				desc = true
			} else {
				p.matchKw("ASC")
			}
			var nf *bool
			if p.matchKw("NULLS") {
				if p.matchKw("FIRST") {
					b := true
					nf = &b
				} else if p.matchKw("LAST") {
					b := false
					nf = &b
				} else {
					return nil, fmt.Errorf("expected FIRST or LAST after NULLS")
				}
			}
			stmt.orderBy = append(stmt.orderBy, sqlOrderItem{expr: oe, desc: desc, nullsFirst: nf})
			if p.cur().kind == sqlTokComma {
				p.pos++
				continue
			}
			break
		}
	}
	if p.matchKw("LIMIT") {
		nt := p.cur()
		if nt.kind != sqlTokNumber {
			return nil, fmt.Errorf("expected integer after LIMIT")
		}
		p.pos++
		lv, err := strconv.Atoi(nt.val)
		if err != nil || lv < 0 {
			return nil, fmt.Errorf("invalid LIMIT value [%s]", nt.val)
		}
		stmt.limit = lv
	}
	if p.cur().kind != sqlTokEOF {
		return nil, fmt.Errorf("unexpected token [%s]", p.cur().raw)
	}
	return stmt, nil
}

func isSQLClauseKeyword(s string) bool {
	switch strings.ToUpper(s) {
	case "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "UNION", "JOIN", "INNER", "LEFT", "RIGHT":
		return true
	}
	return false
}

func (p *sqlParser) parseTableName() (string, error) {
	t := p.cur()
	if t.kind == sqlTokQuotedIdent || t.kind == sqlTokString {
		p.pos++
		return t.val, nil
	}
	if t.kind == sqlTokIdent || t.kind == sqlTokStar {
		var sb strings.Builder
		sb.WriteString(t.val)
		p.pos++
		for p.cur().kind == sqlTokStar || (p.cur().kind == sqlTokOp && p.cur().val == "-") {
			sb.WriteString(p.cur().val)
			p.pos++
			if p.cur().kind == sqlTokIdent || p.cur().kind == sqlTokNumber || p.cur().kind == sqlTokStar {
				sb.WriteString(p.cur().val)
				p.pos++
			}
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("expected table name, got [%s]", t.raw)
}

func (p *sqlParser) parseExpr() (sqlExpr, error) {
	return p.parseOr()
}

func (p *sqlParser) parseOr() (sqlExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.matchKw("OR") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &sqlBinaryExpr{op: "OR", left: left, right: right}
	}
	return left, nil
}

func (p *sqlParser) parseAnd() (sqlExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.matchKw("AND") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &sqlBinaryExpr{op: "AND", left: left, right: right}
	}
	return left, nil
}

func (p *sqlParser) parseNot() (sqlExpr, error) {
	if p.matchKw("NOT") {
		sub, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &sqlUnaryExpr{op: "NOT ", sub: sub}, nil
	}
	return p.parsePredicate()
}

func (p *sqlParser) parsePredicate() (sqlExpr, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	if p.matchKw("IS") {
		neg := p.matchKw("NOT")
		if !p.matchKw("NULL") {
			return nil, fmt.Errorf("expected NULL after IS")
		}
		return &sqlIsNullExpr{sub: left, negate: neg}, nil
	}
	negPred := false
	if p.peekKw("NOT") {
		save := p.pos
		p.pos++
		if p.peekKw("IN") || p.peekKw("BETWEEN") || p.peekKw("LIKE") || p.peekKw("ILIKE") {
			negPred = true
		} else {
			p.pos = save
		}
	}
	if p.matchKw("IN") {
		if p.cur().kind != sqlTokLParen {
			return nil, fmt.Errorf("expected '(' after IN")
		}
		p.pos++
		var list []sqlExpr
		for p.cur().kind != sqlTokRParen && p.cur().kind != sqlTokEOF {
			item, err := p.parseAdditive()
			if err != nil {
				return nil, err
			}
			list = append(list, item)
			if p.cur().kind == sqlTokComma {
				p.pos++
				continue
			}
			break
		}
		if p.cur().kind != sqlTokRParen {
			return nil, fmt.Errorf("expected ')' after IN list")
		}
		p.pos++
		return &sqlInExpr{left: left, list: list, negate: negPred}, nil
	}
	if p.matchKw("BETWEEN") {
		low, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		if !p.matchKw("AND") {
			return nil, fmt.Errorf("expected AND in BETWEEN predicate")
		}
		high, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		return &sqlBetweenExpr{val: left, low: low, high: high, negate: negPred}, nil
	}
	if p.matchKw("LIKE") || p.matchKw("ILIKE") {
		pat, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		return &sqlLikeExpr{left: left, pattern: pat, negate: negPred}, nil
	}
	t := p.cur()
	if t.kind == sqlTokOp && (t.val == "=" || t.val == "!=" || t.val == "<" || t.val == "<=" || t.val == ">" || t.val == ">=") {
		p.pos++
		right, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		return &sqlBinaryExpr{op: t.val, left: left, right: right}, nil
	}
	return left, nil
}

func (p *sqlParser) parseAdditive() (sqlExpr, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == sqlTokOp && (p.cur().val == "+" || p.cur().val == "-") {
		op := p.cur().val
		p.pos++
		right, err := p.parseMultiplicative()
		if err != nil {
			return nil, err
		}
		left = &sqlBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *sqlParser) parseMultiplicative() (sqlExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for (p.cur().kind == sqlTokOp && (p.cur().val == "/" || p.cur().val == "%")) || p.cur().kind == sqlTokStar {
		op := p.cur().val
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &sqlBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *sqlParser) parseUnary() (sqlExpr, error) {
	if p.cur().kind == sqlTokOp && (p.cur().val == "-" || p.cur().val == "+") {
		op := p.cur().val
		p.pos++
		sub, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &sqlUnaryExpr{op: op, sub: sub}, nil
	}
	return p.parsePrimary()
}

func (p *sqlParser) parsePrimary() (sqlExpr, error) {
	t := p.cur()
	switch t.kind {
	case sqlTokLParen:
		p.pos++
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.cur().kind != sqlTokRParen {
			return nil, fmt.Errorf("unbalanced '('")
		}
		p.pos++
		return inner, nil
	case sqlTokString:
		p.pos++
		return &sqlLitExpr{val: t.val, raw: t.raw}, nil
	case sqlTokNumber:
		p.pos++
		if iv, err := strconv.ParseInt(t.val, 10, 64); err == nil {
			return &sqlLitExpr{val: iv, raw: t.raw}, nil
		}
		fv, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number [%s]", t.val)
		}
		return &sqlLitExpr{val: fv, raw: t.raw}, nil
	case sqlTokQuotedIdent:
		p.pos++
		return &sqlColExpr{name: t.val}, nil
	case sqlTokIdent:
		upper := strings.ToUpper(t.val)
		if upper == "NULL" {
			p.pos++
			return &sqlLitExpr{val: nil, raw: "NULL"}, nil
		}
		if upper == "TRUE" {
			p.pos++
			return &sqlLitExpr{val: true, raw: "TRUE"}, nil
		}
		if upper == "FALSE" {
			p.pos++
			return &sqlLitExpr{val: false, raw: "FALSE"}, nil
		}
		p.pos++
		if p.cur().kind == sqlTokLParen {
			p.pos++
			fn := &sqlFuncExpr{name: upper}
			if p.cur().kind == sqlTokStar {
				p.pos++
				fn.starArg = true
			} else if p.cur().kind != sqlTokRParen {
				if p.matchKw("DISTINCT") {
					fn.distinct = true
				}
				for {
					arg, err := p.parseExpr()
					if err != nil {
						return nil, err
					}
					fn.args = append(fn.args, arg)
					if p.cur().kind == sqlTokComma {
						p.pos++
						continue
					}
					break
				}
			}
			if p.cur().kind != sqlTokRParen {
				return nil, fmt.Errorf("expected ')' in call to %s", upper)
			}
			p.pos++
			return fn, nil
		}
		return &sqlColExpr{name: t.val}, nil
	default:
		return nil, fmt.Errorf("unexpected token [%s]", t.raw)
	}
}

func sqlExprHasAggregate(ex sqlExpr) bool {
	if ex == nil {
		return false
	}
	switch e := ex.(type) {
	case *sqlFuncExpr:
		switch strings.ToUpper(e.name) {
		case "COUNT", "SUM", "AVG", "MIN", "MAX":
			return true
		}
		for _, a := range e.args {
			if sqlExprHasAggregate(a) {
				return true
			}
		}
	case *sqlUnaryExpr:
		return sqlExprHasAggregate(e.sub)
	case *sqlBinaryExpr:
		return sqlExprHasAggregate(e.left) || sqlExprHasAggregate(e.right)
	case *sqlIsNullExpr:
		return sqlExprHasAggregate(e.sub)
	case *sqlInExpr:
		if sqlExprHasAggregate(e.left) {
			return true
		}
		for _, it := range e.list {
			if sqlExprHasAggregate(it) {
				return true
			}
		}
	case *sqlBetweenExpr:
		return sqlExprHasAggregate(e.val) || sqlExprHasAggregate(e.low) || sqlExprHasAggregate(e.high)
	case *sqlLikeExpr:
		return sqlExprHasAggregate(e.left) || sqlExprHasAggregate(e.pattern)
	}
	return false
}

func getNestedDocVal(doc map[string]any, field string) any {
	if doc == nil {
		return nil
	}
	if v, exists := doc[field]; exists {
		return normalizeESQLNumber(v)
	}
	parts := strings.Split(field, ".")
	var cur any = doc
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return normalizeESQLNumber(cur)
}

func evalSQLExprOnRow(ex sqlExpr, row map[string]any, grpRows []map[string]any) any {
	if ex == nil {
		return nil
	}
	switch e := ex.(type) {
	case *sqlLitExpr:
		return e.val
	case *sqlColExpr:
		return getNestedDocVal(row, e.name)
	case *sqlUnaryExpr:
		op := strings.TrimSpace(strings.ToUpper(e.op))
		v := evalSQLExprOnRow(e.sub, row, grpRows)
		if op == "NOT" {
			if v == nil {
				return nil
			}
			b, ok := toSQLBool(v)
			if !ok {
				return nil
			}
			return !b
		}
		if op == "-" {
			if iv, ok := esqlAsInt64Exact(v); ok {
				return -iv
			}
			if fv, ok := toESQLNumber(v); ok {
				return -fv
			}
			return nil
		}
		return v
	case *sqlIsNullExpr:
		v := evalSQLExprOnRow(e.sub, row, grpRows)
		if e.negate {
			return v != nil
		}
		return v == nil
	case *sqlInExpr:
		lv := evalSQLExprOnRow(e.left, row, grpRows)
		if lv == nil {
			return false
		}
		matched := false
		for _, it := range e.list {
			rv := evalSQLExprOnRow(it, row, grpRows)
			if rv != nil && sqlValuesEqual(lv, rv) {
				matched = true
				break
			}
		}
		if e.negate {
			return !matched
		}
		return matched
	case *sqlBetweenExpr:
		vv := evalSQLExprOnRow(e.val, row, grpRows)
		lo := evalSQLExprOnRow(e.low, row, grpRows)
		hi := evalSQLExprOnRow(e.high, row, grpRows)
		if vv == nil || lo == nil || hi == nil {
			return false
		}
		inRange := compareESQLValues(vv, lo) >= 0 && compareESQLValues(vv, hi) <= 0
		if e.negate {
			return !inRange
		}
		return inRange
	case *sqlLikeExpr:
		lv := evalSQLExprOnRow(e.left, row, grpRows)
		pv := evalSQLExprOnRow(e.pattern, row, grpRows)
		if lv == nil || pv == nil {
			return false
		}
		matched := matchSQLLikeExact(fmt.Sprintf("%v", lv), fmt.Sprintf("%v", pv))
		if e.negate {
			return !matched
		}
		return matched
	case *sqlBinaryExpr:
		switch e.op {
		case "AND":
			lb, lok := toSQLBool(evalSQLExprOnRow(e.left, row, grpRows))
			rb, rok := toSQLBool(evalSQLExprOnRow(e.right, row, grpRows))
			if (!lok || !lb) && (lok && !lb) {
				return false
			}
			if rok && !rb {
				return false
			}
			return lok && rok && lb && rb
		case "OR":
			lb, lok := toSQLBool(evalSQLExprOnRow(e.left, row, grpRows))
			if lok && lb {
				return true
			}
			rb, rok := toSQLBool(evalSQLExprOnRow(e.right, row, grpRows))
			return rok && rb
		case "=", "!=", "<", "<=", ">", ">=":
			lv := evalSQLExprOnRow(e.left, row, grpRows)
			rv := evalSQLExprOnRow(e.right, row, grpRows)
			if lv == nil || rv == nil {
				return false
			}
			switch e.op {
			case "=":
				return sqlValuesEqual(lv, rv)
			case "!=":
				return !sqlValuesEqual(lv, rv)
			case "<":
				return compareESQLValues(lv, rv) < 0
			case "<=":
				return compareESQLValues(lv, rv) <= 0
			case ">":
				return compareESQLValues(lv, rv) > 0
			case ">=":
				return compareESQLValues(lv, rv) >= 0
			}
		case "+", "-", "*", "/", "%":
			lv := evalSQLExprOnRow(e.left, row, grpRows)
			rv := evalSQLExprOnRow(e.right, row, grpRows)
			if lv == nil || rv == nil {
				return nil
			}
			li, lInt := esqlAsInt64Exact(lv)
			ri, rInt := esqlAsInt64Exact(rv)
			if lInt && rInt && e.op != "/" {
				switch e.op {
				case "+":
					return li + ri
				case "-":
					return li - ri
				case "*":
					return li * ri
				case "%":
					if ri == 0 {
						return nil
					}
					return li % ri
				}
			}
			lf, lok := toESQLNumber(lv)
			rf, rok := toESQLNumber(rv)
			if !lok || !rok {
				return nil
			}
			switch e.op {
			case "+":
				return lf + rf
			case "-":
				return lf - rf
			case "*":
				return lf * rf
			case "/":
				if rf == 0 {
					return nil
				}
				if lInt && rInt && li%ri == 0 {
					return li / ri
				}
				return lf / rf
			case "%":
				if rf == 0 {
					return nil
				}
				return math.Mod(lf, rf)
			}
		}
	case *sqlFuncExpr:
		fn := strings.ToUpper(e.name)
		switch fn {
		case "COUNT":
			if e.starArg {
				return int64(len(grpRows))
			}
			if len(e.args) == 0 {
				return int64(0)
			}
			if e.distinct {
				seen := make(map[string]bool)
				for _, gr := range grpRows {
					v := evalSQLExprOnRow(e.args[0], gr, nil)
					if v != nil {
						seen[fmt.Sprintf("%T:%v", v, v)] = true
					}
				}
				return int64(len(seen))
			}
			var c int64
			for _, gr := range grpRows {
				if evalSQLExprOnRow(e.args[0], gr, nil) != nil {
					c++
				}
			}
			return c
		case "SUM":
			if len(e.args) == 0 {
				return nil
			}
			hasVal := false
			allInt := true
			var sumI int64
			var sumF float64
			for _, gr := range grpRows {
				v := evalSQLExprOnRow(e.args[0], gr, nil)
				if v == nil {
					continue
				}
				if iv, ok := esqlAsInt64Exact(v); ok {
					hasVal = true
					sumI += iv
					sumF += float64(iv)
				} else if fv, ok := toESQLNumber(v); ok {
					hasVal = true
					allInt = false
					sumF += fv
				}
			}
			if !hasVal {
				return nil
			}
			if allInt {
				return sumI
			}
			return sumF
		case "AVG":
			if len(e.args) == 0 {
				return nil
			}
			var cnt int
			var sumF float64
			for _, gr := range grpRows {
				v := evalSQLExprOnRow(e.args[0], gr, nil)
				if fv, ok := toESQLNumber(v); ok {
					sumF += fv
					cnt++
				}
			}
			if cnt == 0 {
				return nil
			}
			return sumF / float64(cnt)
		case "MIN", "MAX":
			if len(e.args) == 0 {
				return nil
			}
			var best any
			for _, gr := range grpRows {
				v := evalSQLExprOnRow(e.args[0], gr, nil)
				if v == nil {
					continue
				}
				if best == nil {
					best = v
					continue
				}
				cmp := compareESQLValues(v, best)
				if (fn == "MIN" && cmp < 0) || (fn == "MAX" && cmp > 0) {
					best = v
				}
			}
			return best
		default:
			evalArgs := make([]any, len(e.args))
			for i, a := range e.args {
				evalArgs[i] = evalSQLExprOnRow(a, row, grpRows)
			}
			return evalSQLScalarFunc(fn, evalArgs)
		}
	}
	return nil
}

func evalSQLScalarFunc(fn string, args []any) any {
	switch fn {
	case "LOWER", "LCASE":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.ToLower(fmt.Sprintf("%v", args[0]))
	case "UPPER", "UCASE":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.ToUpper(fmt.Sprintf("%v", args[0]))
	case "LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return int64(utf8.RuneCountInString(fmt.Sprintf("%v", args[0])))
	case "CONCAT":
		var sb strings.Builder
		for _, a := range args {
			if a == nil {
				return nil
			}
			_, _ = fmt.Fprintf(&sb, "%v", a)
		}
		return sb.String()
	case "SUBSTRING", "SUBSTR":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil
		}
		runes := []rune(fmt.Sprintf("%v", args[0]))
		start, ok := toInt64(args[1])
		if !ok {
			return nil
		}
		// SQL SUBSTRING is 1-based
		idx := int(start) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(runes) {
			return ""
		}
		if len(args) >= 3 && args[2] != nil {
			ln, okL := toInt64(args[2])
			if !okL || ln <= 0 {
				return ""
			}
			end := idx + int(ln)
			if end > len(runes) {
				end = len(runes)
			}
			return string(runes[idx:end])
		}
		return string(runes[idx:])
	case "TRIM":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.TrimSpace(fmt.Sprintf("%v", args[0]))
	case "LTRIM":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.TrimLeftFunc(fmt.Sprintf("%v", args[0]), unicode.IsSpace)
	case "RTRIM":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		return strings.TrimRightFunc(fmt.Sprintf("%v", args[0]), unicode.IsSpace)
	case "COALESCE", "IFNULL":
		for _, a := range args {
			if a != nil {
				return a
			}
		}
		return nil
	case "ROUND":
		return evalESQLFunc("ROUND", args)
	case "ABS":
		return evalESQLFunc("ABS", args)
	case "FLOOR":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		if fv, ok := toESQLNumber(args[0]); ok {
			return int64(math.Floor(fv))
		}
		return nil
	case "CEIL", "CEILING":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		if fv, ok := toESQLNumber(args[0]); ok {
			return int64(math.Ceil(fv))
		}
		return nil
	case "SQRT":
		if len(args) == 0 || args[0] == nil {
			return nil
		}
		if fv, ok := toESQLNumber(args[0]); ok && fv >= 0 {
			return math.Sqrt(fv)
		}
		return nil
	case "MOD":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil
		}
		if li, ok1 := esqlAsInt64Exact(args[0]); ok1 {
			if ri, ok2 := esqlAsInt64Exact(args[1]); ok2 && ri != 0 {
				return li % ri
			}
		}
		if lf, ok1 := toESQLNumber(args[0]); ok1 {
			if rf, ok2 := toESQLNumber(args[1]); ok2 && rf != 0 {
				return math.Mod(lf, rf)
			}
		}
		return nil
	}
	return evalESQLFunc(fn, args)
}

func sqlValuesEqual(a, b any) bool {
	if af, okA := toESQLNumber(a); okA {
		if bf, okB := toESQLNumber(b); okB {
			return af == bf
		}
	}
	if ab, okA := a.(bool); okA {
		if bb, okB := b.(bool); okB {
			return ab == bb
		}
	}
	// Multi-valued doc field equality: match if any element matches
	if arr, ok := a.([]any); ok {
		for _, el := range arr {
			if sqlValuesEqual(el, b) {
				return true
			}
		}
		return false
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func toSQLBool(v any) (bool, bool) {
	if v == nil {
		return false, false
	}
	if b, ok := v.(bool); ok {
		return b, true
	}
	return false, false
}

func matchSQLLikeExact(val, pattern string) bool {
	var rb strings.Builder
	rb.WriteString("^(?s)")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '\\' && i+1 < len(pattern) {
			i++
			rb.WriteString(regexp.QuoteMeta(string(pattern[i])))
			continue
		}
		switch ch {
		case '%':
			rb.WriteString(".*")
		case '_':
			rb.WriteString(".")
		default:
			rb.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	rb.WriteString("$")
	re, err := regexp.Compile(rb.String())
	return err == nil && re.MatchString(val)
}

func mapESFieldTypeToSQLAndMapping(esType string) (string, string) {
	s := strings.ToLower(strings.TrimSpace(esType))
	switch s {
	case "keyword", "constant_keyword", "wildcard":
		return "VARCHAR", s
	case "text", "match_only_text", "search_as_you_type":
		return "VARCHAR", s
	case "long", "unsigned_long":
		return "BIGINT", s
	case "integer", "int":
		return "INTEGER", "integer"
	case "short":
		return "SMALLINT", "short"
	case "byte":
		return "TINYINT", "byte"
	case "double":
		return "DOUBLE", "double"
	case "float", "half_float", "scaled_float":
		return "REAL", s
	case "boolean", "bool":
		return "BOOLEAN", "boolean"
	case "date", "date_nanos":
		return "TIMESTAMP", s
	case "ip":
		return "VARCHAR", "ip"
	case "geo_point":
		return "GEOMETRY", "geo_point"
	case "geo_shape":
		return "GEOMETRY", "geo_shape"
	default:
		if s == "" {
			return "VARCHAR", "keyword"
		}
		return "VARCHAR", s
	}
}

var supportedSQLFunctionsCatalog = []struct {
	name string
	kind string
}{
	{"ABS", "SCALAR"},
	{"AVG", "AGGREGATE"},
	{"CEIL", "SCALAR"},
	{"CEILING", "SCALAR"},
	{"CHAR_LENGTH", "SCALAR"},
	{"COALESCE", "SCALAR"},
	{"CONCAT", "SCALAR"},
	{"COUNT", "AGGREGATE"},
	{"FLOOR", "SCALAR"},
	{"IFNULL", "SCALAR"},
	{"LCASE", "SCALAR"},
	{"LENGTH", "SCALAR"},
	{"LOWER", "SCALAR"},
	{"LTRIM", "SCALAR"},
	{"MAX", "AGGREGATE"},
	{"MIN", "AGGREGATE"},
	{"MOD", "SCALAR"},
	{"ROUND", "SCALAR"},
	{"RTRIM", "SCALAR"},
	{"SQRT", "SCALAR"},
	{"SUBSTR", "SCALAR"},
	{"SUBSTRING", "SCALAR"},
	{"SUM", "AGGREGATE"},
	{"TRIM", "SCALAR"},
	{"UCASE", "SCALAR"},
	{"UPPER", "SCALAR"},
}

func translateSQLWhereToDSL(ex sqlExpr) map[string]any {
	if ex == nil {
		return map[string]any{"match_all": map[string]any{}}
	}
	switch e := ex.(type) {
	case *sqlBinaryExpr:
		switch e.op {
		case "AND":
			return map[string]any{
				"bool": map[string]any{
					"must": []any{translateSQLWhereToDSL(e.left), translateSQLWhereToDSL(e.right)},
				},
			}
		case "OR":
			return map[string]any{
				"bool": map[string]any{
					"should":               []any{translateSQLWhereToDSL(e.left), translateSQLWhereToDSL(e.right)},
					"minimum_should_match": 1,
				},
			}
		case "=", "!=", "<", "<=", ">", ">=":
			if col, okC := e.left.(*sqlColExpr); okC {
				if lit, okL := e.right.(*sqlLitExpr); okL && lit.val != nil {
					switch e.op {
					case "=":
						return map[string]any{"term": map[string]any{col.name: map[string]any{"value": lit.val}}}
					case "!=":
						return map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"term": map[string]any{col.name: map[string]any{"value": lit.val}}}}}}
					case "<":
						return map[string]any{"range": map[string]any{col.name: map[string]any{"lt": lit.val}}}
					case "<=":
						return map[string]any{"range": map[string]any{col.name: map[string]any{"lte": lit.val}}}
					case ">":
						return map[string]any{"range": map[string]any{col.name: map[string]any{"gt": lit.val}}}
					case ">=":
						return map[string]any{"range": map[string]any{col.name: map[string]any{"gte": lit.val}}}
					}
				}
			}
		}
	case *sqlUnaryExpr:
		if strings.TrimSpace(strings.ToUpper(e.op)) == "NOT" {
			return map[string]any{
				"bool": map[string]any{
					"must_not": []any{translateSQLWhereToDSL(e.sub)},
				},
			}
		}
	case *sqlIsNullExpr:
		if col, okC := e.sub.(*sqlColExpr); okC {
			existsQ := map[string]any{"exists": map[string]any{"field": col.name}}
			if e.negate {
				return existsQ
			}
			return map[string]any{"bool": map[string]any{"must_not": []any{existsQ}}}
		}
	case *sqlInExpr:
		if col, okC := e.left.(*sqlColExpr); okC {
			var vals []any
			for _, it := range e.list {
				if lit, okL := it.(*sqlLitExpr); okL && lit.val != nil {
					vals = append(vals, lit.val)
				}
			}
			termsQ := map[string]any{"terms": map[string]any{col.name: vals}}
			if e.negate {
				return map[string]any{"bool": map[string]any{"must_not": []any{termsQ}}}
			}
			return termsQ
		}
	case *sqlBetweenExpr:
		if col, okC := e.val.(*sqlColExpr); okC {
			lo, ok1 := e.low.(*sqlLitExpr)
			hi, ok2 := e.high.(*sqlLitExpr)
			if ok1 && ok2 {
				rq := map[string]any{"range": map[string]any{col.name: map[string]any{"gte": lo.val, "lte": hi.val}}}
				if e.negate {
					return map[string]any{"bool": map[string]any{"must_not": []any{rq}}}
				}
				return rq
			}
		}
	case *sqlLikeExpr:
		if col, okC := e.left.(*sqlColExpr); okC {
			if pat, okP := e.pattern.(*sqlLitExpr); okP && pat.val != nil {
				wc := strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%v", pat.val), "%", "*"), "_", "?")
				wq := map[string]any{"wildcard": map[string]any{col.name: map[string]any{"wildcard": wc}}}
				if e.negate {
					return map[string]any{"bool": map[string]any{"must_not": []any{wq}}}
				}
				return wq
			}
		}
	}
	return map[string]any{"match_all": map[string]any{}}
}

func (s *Server) handleSQLTranslateRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	queryStr, _ := body["query"].(string)
	queryStr = strings.TrimSpace(queryStr)
	if queryStr == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
		return
	}
	params, _ := body["params"].([]any)
	boundQ, err := substituteSQLParams(queryStr, params)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "verification_exception", err.Error())
		return
	}
	toks, err := tokenizeRound57SQL(boundQ)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	p := &sqlParser{toks: toks}
	stmt, err := p.parseSelect()
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	fetchSize := 1000
	if fs, okF := toInt64(body["fetch_size"]); okF && fs > 0 {
		fetchSize = int(fs)
	}
	sizeVal := fetchSize
	if stmt.top >= 0 && stmt.top < sizeVal {
		sizeVal = stmt.top
	}
	if stmt.limit >= 0 && stmt.limit < sizeVal {
		sizeVal = stmt.limit
	}
	whereDSL := translateSQLWhereToDSL(stmt.where)
	if filterMap, okF := body["filter"].(map[string]any); okF && len(filterMap) > 0 {
		if stmt.where == nil {
			whereDSL = filterMap
		} else {
			whereDSL = map[string]any{
				"bool": map[string]any{
					"must":   []any{whereDSL},
					"filter": []any{filterMap},
				},
			}
		}
	}
	hasAgg := len(stmt.groupBy) > 0
	var selectFields []any
	hasStar := false
	for _, it := range stmt.items {
		if it.star {
			hasStar = true
		} else if sqlExprHasAggregate(it.expr) {
			hasAgg = true
		} else if col, okC := it.expr.(*sqlColExpr); okC {
			selectFields = append(selectFields, map[string]any{"field": col.name})
		}
	}
	out := map[string]any{
		"size":  sizeVal,
		"query": whereDSL,
	}
	if hasAgg {
		out["size"] = 0
		subAggs := make(map[string]any)
		for idx, it := range stmt.items {
			fn, okFn := it.expr.(*sqlFuncExpr)
			if !okFn {
				continue
			}
			aggKey := it.alias
			if aggKey == "" {
				aggKey = fmt.Sprintf("agg_%d", idx+1)
			}
			colName := "_id"
			if len(fn.args) > 0 {
				if c, okC := fn.args[0].(*sqlColExpr); okC {
					colName = c.name
				}
			}
			switch strings.ToUpper(fn.name) {
			case "COUNT":
				if fn.distinct {
					subAggs[aggKey] = map[string]any{"cardinality": map[string]any{"field": colName}}
				} else if !fn.starArg {
					subAggs[aggKey] = map[string]any{"value_count": map[string]any{"field": colName}}
				}
			case "SUM":
				subAggs[aggKey] = map[string]any{"sum": map[string]any{"field": colName}}
			case "AVG":
				subAggs[aggKey] = map[string]any{"avg": map[string]any{"field": colName}}
			case "MIN":
				subAggs[aggKey] = map[string]any{"min": map[string]any{"field": colName}}
			case "MAX":
				subAggs[aggKey] = map[string]any{"max": map[string]any{"field": colName}}
			}
		}
		if len(stmt.groupBy) > 0 {
			sources := make([]any, 0, len(stmt.groupBy))
			for gi, g := range stmt.groupBy {
				gField := g.sqlExprLabel()
				if c, okC := g.(*sqlColExpr); okC {
					gField = c.name
				}
				sources = append(sources, map[string]any{
					fmt.Sprintf("groupby_%d", gi): map[string]any{
						"terms": map[string]any{"field": gField, "missing_bucket": true},
					},
				})
			}
			comp := map[string]any{
				"composite": map[string]any{
					"size":    fetchSize,
					"sources": sources,
				},
			}
			if len(subAggs) > 0 {
				comp["aggregations"] = subAggs
			}
			out["aggs"] = map[string]any{"groupby": comp}
		} else if len(subAggs) > 0 {
			out["aggs"] = subAggs
		}
	} else {
		if !hasStar && len(selectFields) > 0 {
			out["_source"] = false
			out["fields"] = selectFields
		} else {
			out["_source"] = true
		}
		var sortList []any
		for _, ord := range stmt.orderBy {
			dir := "asc"
			if ord.desc {
				dir = "desc"
			}
			field := ord.expr.sqlExprLabel()
			if c, okC := ord.expr.(*sqlColExpr); okC {
				field = c.name
			}
			sortList = append(sortList, map[string]any{
				field: map[string]any{"order": dir},
			})
		}
		if len(sortList) > 0 {
			out["sort"] = sortList
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSQLQueryRound57(w http.ResponseWriter, r *http.Request, body map[string]any) {
	queryStr, _ := body["query"].(string)
	queryStr = strings.TrimSpace(queryStr)
	if queryStr == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
		return
	}
	params, _ := body["params"].([]any)
	boundQ, err := substituteSQLParams(queryStr, params)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "verification_exception", err.Error())
		return
	}
	boundQ = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(boundQ), ";"))

	fetchSize := 1000
	if fs, ok := toInt64(body["fetch_size"]); ok && fs > 0 {
		fetchSize = int(fs)
	}
	columnar, _ := body["columnar"].(bool)
	if !columnar && r.URL.Query().Has("columnar") {
		columnar = isTruthyBoolQueryParam(r, "columnar")
	}

	var columns []any
	var rows []any

	toks, tokErr := tokenizeRound57SQL(boundQ)
	if tokErr != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", tokErr.Error())
		return
	}
	p0 := &sqlParser{toks: toks}
	firstKw := strings.ToUpper(p0.cur().val)
	if p0.cur().kind != sqlTokIdent {
		firstKw = ""
	}
	secondKw := ""
	if len(toks) > 1 && toks[1].kind == sqlTokIdent {
		secondKw = strings.ToUpper(toks[1].val)
	}

	switch {
	case firstKw == "DESCRIBE" || firstKw == "DESC" || (firstKw == "SHOW" && secondKw == "COLUMNS"):
		var targetTbl string
		p := &sqlParser{toks: toks}
		if p.matchKw("DESCRIBE") || p.matchKw("DESC") {
			p.matchKw("TABLE")
			targetTbl, tokErr = p.parseTableName()
		} else if p.matchKw("SHOW") && p.matchKw("COLUMNS") {
			if !p.matchKw("IN") && !p.matchKw("FROM") {
				tokErr = fmt.Errorf("expected IN or FROM after SHOW COLUMNS")
			} else {
				targetTbl, tokErr = p.parseTableName()
			}
		}
		if tokErr != nil || strings.TrimSpace(targetTbl) == "" {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "invalid DESCRIBE / SHOW COLUMNS syntax")
			return
		}
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.RLock()
		var matchedSchemas []*schema.IndexSchema
		if sch, ok := s.indices[targetTbl]; ok && sch != nil {
			matchedSchemas = append(matchedSchemas, sch)
		} else if aliasTargets, okA := s.aliases[targetTbl]; okA && len(aliasTargets) > 0 {
			for _, at := range aliasTargets {
				if sch, okS := s.indices[at]; okS && sch != nil {
					matchedSchemas = append(matchedSchemas, sch)
				}
			}
		} else if strings.ContainsAny(targetTbl, "*?") {
			for idx, sch := range s.indices {
				if matchSimpleWildcard(targetTbl, idx) && sch != nil {
					matchedSchemas = append(matchedSchemas, sch)
				}
			}
		}
		fieldTypes := make(map[string]string)
		for _, sch := range matchedSchemas {
			for fname, fmeta := range sch.Fields {
				if strings.HasSuffix(fname, ".keyword") {
					continue
				}
				fieldTypes[fname] = fmeta.ESType
			}
		}
		s.mu.RUnlock()
		if len(matchedSchemas) == 0 {
			writeESError(w, http.StatusBadRequest, "verification_exception", fmt.Sprintf("Found 1 problem\nline 1:1: Unknown index [%s]", targetTbl))
			return
		}
		columns = []any{
			map[string]any{"name": "column", "type": "keyword"},
			map[string]any{"name": "type", "type": "keyword"},
			map[string]any{"name": "mapping", "type": "keyword"},
		}
		fnames := make([]string, 0, len(fieldTypes))
		for fn := range fieldTypes {
			fnames = append(fnames, fn)
		}
		sort.Strings(fnames)
		for _, fn := range fnames {
			sqlT, esT := mapESFieldTypeToSQLAndMapping(fieldTypes[fn])
			rows = append(rows, []any{fn, sqlT, esT})
		}

	case firstKw == "SHOW" && secondKw == "TABLES":
		p := &sqlParser{toks: toks}
		p.matchKw("SHOW")
		p.matchKw("TABLES")
		likePat := ""
		hasLike := false
		if p.matchKw("LIKE") {
			if p.cur().kind != sqlTokString {
				writeESError(w, http.StatusBadRequest, "parsing_exception", "expected string pattern after LIKE")
				return
			}
			likePat = p.cur().val
			hasLike = true
			p.pos++
		} else if p.cur().kind == sqlTokString {
			likePat = p.cur().val
			hasLike = true
			p.pos++
		}
		if p.cur().kind != sqlTokEOF {
			writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("unexpected token [%s] in SHOW TABLES", p.cur().raw))
			return
		}
		_ = s.syncCatalogFromBackend(r.Context())
		type tblEntry struct {
			name string
			kind string
		}
		var entries []tblEntry
		s.mu.RLock()
		for idx := range s.indices {
			if hasLike && !matchSQLLikeExact(idx, likePat) {
				continue
			}
			entries = append(entries, tblEntry{name: idx, kind: "BASE TABLE"})
		}
		for al, targets := range s.aliases {
			if len(targets) == 0 {
				continue
			}
			if _, isIdx := s.indices[al]; isIdx {
				continue
			}
			if hasLike && !matchSQLLikeExact(al, likePat) {
				continue
			}
			entries = append(entries, tblEntry{name: al, kind: "VIEW"})
		}
		s.mu.RUnlock()
		sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
		columns = []any{
			map[string]any{"name": "name", "type": "keyword"},
			map[string]any{"name": "type", "type": "keyword"},
		}
		for _, e := range entries {
			rows = append(rows, []any{e.name, e.kind})
		}

	case firstKw == "SHOW" && secondKw == "FUNCTIONS":
		p := &sqlParser{toks: toks}
		p.matchKw("SHOW")
		p.matchKw("FUNCTIONS")
		likePat := ""
		hasLike := false
		if p.matchKw("LIKE") {
			if p.cur().kind != sqlTokString {
				writeESError(w, http.StatusBadRequest, "parsing_exception", "expected string pattern after LIKE")
				return
			}
			likePat = p.cur().val
			hasLike = true
			p.pos++
		}
		if p.cur().kind != sqlTokEOF {
			writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("unexpected token [%s] in SHOW FUNCTIONS", p.cur().raw))
			return
		}
		columns = []any{
			map[string]any{"name": "name", "type": "keyword"},
			map[string]any{"name": "type", "type": "keyword"},
		}
		for _, fn := range supportedSQLFunctionsCatalog {
			if hasLike && !matchSQLLikeExact(fn.name, strings.ToUpper(likePat)) && !matchSQLLikeExact(fn.name, likePat) {
				continue
			}
			rows = append(rows, []any{fn.name, fn.kind})
		}

	case firstKw == "SELECT":
		p := &sqlParser{toks: toks}
		stmt, parseErr := p.parseSelect()
		if parseErr != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", parseErr.Error())
			return
		}
		if stmt.from == "" {
			// Constant SELECT without FROM
			outRow := make([]any, 0, len(stmt.items))
			for _, it := range stmt.items {
				val := evalSQLExprOnRow(it.expr, nil, nil)
				cName := it.alias
				if cName == "" {
					cName = it.expr.sqlExprLabel()
				}
				columns = append(columns, map[string]any{"name": cName, "type": inferSQLResultType(val)})
				outRow = append(outRow, val)
			}
			rows = []any{outRow}
			break
		}

		// Fetch candidate documents via internal search (applying request filter if provided)
		searchDSL := map[string]any{"size": 10000}
		if filterMap, okF := body["filter"].(map[string]any); okF && len(filterMap) > 0 {
			searchDSL["query"] = filterMap
		} else {
			searchDSL["query"] = map[string]any{"match_all": map[string]any{}}
		}
		dslBytes, _ := json.Marshal(searchDSL)
		subReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
		if reqErr != nil {
			writeESError(w, http.StatusInternalServerError, "internal_server_error", reqErr.Error())
			return
		}
		subReq.SetPathValue("index", stmt.from)
		capW := &asyncCaptureResponseWriter{}
		s.handleSearch(capW, subReq)
		if capW.code >= 400 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(capW.code)
			_, _ = w.Write(capW.body.Bytes())
			return
		}
		var searchResp map[string]any
		dec := json.NewDecoder(bytes.NewReader(capW.body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&searchResp)
		hitsWrapper, _ := searchResp["hits"].(map[string]any)
		rawHits, _ := hitsWrapper["hits"].([]any)
		docs := make([]map[string]any, 0, len(rawHits))
		for _, h := range rawHits {
			hm, okM := h.(map[string]any)
			if !okM {
				continue
			}
			src, okS := hm["_source"].(map[string]any)
			if !okS {
				continue
			}
			normDoc := make(map[string]any, len(src))
			for k, v := range src {
				normDoc[k] = normalizeESQLNumber(v)
			}
			if stmt.where != nil {
				condVal := evalSQLExprOnRow(stmt.where, normDoc, nil)
				if b, okB := toSQLBool(condVal); !okB || !b {
					continue
				}
			}
			docs = append(docs, normDoc)
		}

		isGrouped := len(stmt.groupBy) > 0
		if !isGrouped {
			for _, it := range stmt.items {
				if sqlExprHasAggregate(it.expr) {
					isGrouped = true
					break
				}
			}
		}

		// Expand SELECT * if needed
		expandedItems := stmt.items
		hasStar := false
		for _, it := range stmt.items {
			if it.star {
				hasStar = true
				break
			}
		}
		if hasStar {
			colSet := make(map[string]bool)
			for _, d := range docs {
				for k := range d {
					colSet[k] = true
				}
			}
			if len(colSet) == 0 {
				s.mu.RLock()
				if sch, exists := s.indices[stmt.from]; exists && sch != nil {
					for k := range sch.Fields {
						if !strings.HasSuffix(k, ".keyword") {
							colSet[k] = true
						}
					}
				}
				s.mu.RUnlock()
			}
			starCols := make([]string, 0, len(colSet))
			for k := range colSet {
				starCols = append(starCols, k)
			}
			sort.Strings(starCols)
			var nextItems []sqlSelectItem
			for _, it := range stmt.items {
				if it.star {
					for _, sc := range starCols {
						nextItems = append(nextItems, sqlSelectItem{expr: &sqlColExpr{name: sc}, alias: sc})
					}
				} else {
					nextItems = append(nextItems, it)
				}
			}
			expandedItems = nextItems
		}

		type evalRecord struct {
			cells   []any
			baseRow map[string]any
			grpRows []map[string]any
		}
		var records []evalRecord

		if isGrouped {
			type grpBucket struct {
				rep  map[string]any
				rows []map[string]any
			}
			var order []string
			buckets := make(map[string]*grpBucket)
			if len(stmt.groupBy) == 0 {
				order = []string{""}
				var rep map[string]any
				if len(docs) > 0 {
					rep = docs[0]
				}
				buckets[""] = &grpBucket{rep: rep, rows: docs}
			} else {
				for _, d := range docs {
					var kb strings.Builder
					rep := make(map[string]any, len(d)+len(stmt.groupBy))
					for k, v := range d {
						rep[k] = v
					}
					for _, ge := range stmt.groupBy {
						gv := evalSQLExprOnRow(ge, d, nil)
						_, _ = fmt.Fprintf(&kb, "%T:%v|", gv, gv)
						rep[ge.sqlExprLabel()] = gv
					}
					kStr := kb.String()
					b, exists := buckets[kStr]
					if !exists {
						b = &grpBucket{rep: rep}
						buckets[kStr] = b
						order = append(order, kStr)
					}
					b.rows = append(b.rows, d)
				}
			}
			for _, bk := range order {
				b := buckets[bk]
				if stmt.having != nil {
					hv := evalSQLExprOnRow(stmt.having, b.rep, b.rows)
					if hb, okB := toSQLBool(hv); !okB || !hb {
						continue
					}
				}
				cells := make([]any, len(expandedItems))
				rowWithAliases := make(map[string]any)
				for k, v := range b.rep {
					rowWithAliases[k] = v
				}
				for ci, it := range expandedItems {
					val := evalSQLExprOnRow(it.expr, b.rep, b.rows)
					cells[ci] = val
					if it.alias != "" {
						rowWithAliases[it.alias] = val
					}
					rowWithAliases[it.expr.sqlExprLabel()] = val
				}
				records = append(records, evalRecord{cells: cells, baseRow: rowWithAliases, grpRows: b.rows})
			}
		} else {
			for _, d := range docs {
				cells := make([]any, len(expandedItems))
				rowWithAliases := make(map[string]any, len(d)+len(expandedItems))
				for k, v := range d {
					rowWithAliases[k] = v
				}
				for ci, it := range expandedItems {
					val := evalSQLExprOnRow(it.expr, d, nil)
					cells[ci] = val
					if it.alias != "" {
						rowWithAliases[it.alias] = val
					}
				}
				records = append(records, evalRecord{cells: cells, baseRow: rowWithAliases})
			}
		}

		if stmt.distinct {
			var deduped []evalRecord
			seen := make(map[string]bool)
			for _, rec := range records {
				var kb strings.Builder
				for _, c := range rec.cells {
					_, _ = fmt.Fprintf(&kb, "%T:%v|", c, c)
				}
				k := kb.String()
				if !seen[k] {
					seen[k] = true
					deduped = append(deduped, rec)
				}
			}
			records = deduped
		}

		if len(stmt.orderBy) > 0 {
			sort.SliceStable(records, func(i, j int) bool {
				for _, ord := range stmt.orderBy {
					vi := evalSQLExprOnRow(ord.expr, records[i].baseRow, records[i].grpRows)
					vj := evalSQLExprOnRow(ord.expr, records[j].baseRow, records[j].grpRows)
					if vi == nil && vj == nil {
						continue
					}
					nf := ord.desc
					if ord.nullsFirst != nil {
						nf = *ord.nullsFirst
					}
					if vi == nil {
						return nf
					}
					if vj == nil {
						return !nf
					}
					cmp := compareESQLValues(vi, vj)
					if cmp == 0 {
						continue
					}
					if ord.desc {
						return cmp > 0
					}
					return cmp < 0
				}
				return false
			})
		}

		effLimit := -1
		if stmt.top >= 0 {
			effLimit = stmt.top
		}
		if stmt.limit >= 0 && (effLimit < 0 || stmt.limit < effLimit) {
			effLimit = stmt.limit
		}
		if effLimit >= 0 && effLimit < len(records) {
			records = records[:effLimit]
		}

		for ci, it := range expandedItems {
			colName := it.alias
			if colName == "" {
				colName = it.expr.sqlExprLabel()
			}
			colType := "keyword"
			for _, rec := range records {
				if rec.cells[ci] != nil {
					colType = inferSQLResultType(rec.cells[ci])
					break
				}
			}
			columns = append(columns, map[string]any{"name": colName, "type": colType})
		}
		for _, rec := range records {
			rows = append(rows, rec.cells)
		}

	default:
		writeESError(w, http.StatusBadRequest, "parsing_exception", "line 1:1: mismatched input; expected SELECT, SHOW, or DESCRIBE")
		return
	}

	if columns == nil {
		columns = []any{}
	}
	if rows == nil {
		rows = []any{}
	}

	s.mu.Lock()
	if s.sqlAsyncSearches == nil {
		s.sqlAsyncSearches = make(map[string]map[string]any)
	}
	sqlID := fmt.Sprintf("sql_%d", len(s.sqlAsyncSearches)+1)
	var cursorID string
	if fetchSize > 0 && len(rows) > fetchSize {
		cursorID = sqlID + "_cur"
		remRows := rows[fetchSize:]
		rows = rows[:fetchSize]
		curObj := map[string]any{
			"columns": columns,
		}
		if columnar {
			curObj["values"] = transposeRowsToColumnar(columns, remRows)
		} else {
			curObj["rows"] = remRows
		}
		s.sqlAsyncSearches[cursorID+"_cursor"] = curObj
	}
	resp := map[string]any{
		"id":         sqlID,
		"is_partial": false,
		"is_running": false,
		"columns":    columns,
	}
	if columnar {
		resp["values"] = transposeRowsToColumnar(columns, rows)
	} else {
		resp["rows"] = rows
	}
	if cursorID != "" {
		resp["cursor"] = cursorID
	}
	s.sqlAsyncSearches[sqlID] = resp
	s.mu.Unlock()

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "csv" || format == "tsv" || format == "txt" {
		sep := ","
		contentType := "text/csv; charset=UTF-8"
		switch format {
		case "tsv":
			sep = "\t"
			contentType = "text/tab-separated-values; charset=UTF-8"
		case "txt":
			sep = " | "
			contentType = "text/plain; charset=UTF-8"
		}
		var sb strings.Builder
		colHeaders := make([]string, len(columns))
		for i, c := range columns {
			cm, _ := c.(map[string]any)
			colHeaders[i] = fmt.Sprintf("%v", cm["name"])
		}
		sb.WriteString(strings.Join(colHeaders, sep) + "\n")
		if format == "txt" && len(colHeaders) > 0 {
			seps := make([]string, len(colHeaders))
			for i, h := range colHeaders {
				wLen := len(h)
				if wLen < 3 {
					wLen = 3
				}
				seps[i] = strings.Repeat("-", wLen)
			}
			sb.WriteString(strings.Join(seps, "-+-") + "\n")
		}
		for _, rAny := range rows {
			rSlice, _ := rAny.([]any)
			cells := make([]string, len(rSlice))
			for i, v := range rSlice {
				if v == nil {
					cells[i] = ""
				} else {
					cells[i] = fmt.Sprintf("%v", v)
				}
			}
			sb.WriteString(strings.Join(cells, sep) + "\n")
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func inferSQLResultType(v any) string {
	switch v.(type) {
	case int, int64, int32:
		return "long"
	case float64, float32:
		return "double"
	case bool:
		return "boolean"
	default:
		return "keyword"
	}
}

func transposeRowsToColumnar(columns, rows []any) []any {
	numCols := len(columns)
	cols := make([]any, numCols)
	for ci := 0; ci < numCols; ci++ {
		colVals := make([]any, len(rows))
		for ri, rAny := range rows {
			if rSlice, ok := rAny.([]any); ok && ci < len(rSlice) {
				colVals[ri] = rSlice[ci]
			}
		}
		cols[ci] = colVals
	}
	return cols
}

// ============================================================================
// Round 57 F3: ES|QL Engine Extensions (Stages, Functions, Aggregations, Async)
// ============================================================================

func evalESQLFuncRound57(name string, args []any) (any, bool) {
	switch strings.ToUpper(name) {
	// --- String functions ---
	case "REPLACE":
		if len(args) < 3 || args[0] == nil || args[1] == nil || args[2] == nil {
			return nil, true
		}
		src := fmt.Sprintf("%v", args[0])
		pat := fmt.Sprintf("%v", args[1])
		repl := fmt.Sprintf("%v", args[2])
		if re, err := compileIngestJavaRegex(pat); err == nil {
			if out, rErr := applyIngestGsubReplacement(re, src, repl); rErr == nil {
				return out, true
			}
			return re.ReplaceAllString(src, repl), true
		}
		return strings.ReplaceAll(src, pat, repl), true

	case "SUBSTRING":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		runes := []rune(fmt.Sprintf("%v", args[0]))
		start, okS := toInt64(args[1])
		if !okS {
			return nil, true
		}
		var idx int
		if start > 0 {
			idx = int(start) - 1
		} else if start == 0 {
			idx = 0
		} else {
			idx = len(runes) + int(start)
			if idx < 0 {
				idx = 0
			}
		}
		if idx >= len(runes) {
			return "", true
		}
		if len(args) >= 3 && args[2] != nil {
			ln, okL := toInt64(args[2])
			if !okL || ln < 0 {
				return nil, true
			}
			end := idx + int(ln)
			if end > len(runes) {
				end = len(runes)
			}
			return string(runes[idx:end]), true
		}
		return string(runes[idx:]), true

	case "SPLIT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		parts := strings.Split(fmt.Sprintf("%v", args[0]), fmt.Sprintf("%v", args[1]))
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = p
		}
		return out, true

	case "STARTS_WITH":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		return strings.HasPrefix(fmt.Sprintf("%v", args[0]), fmt.Sprintf("%v", args[1])), true

	case "ENDS_WITH":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		return strings.HasSuffix(fmt.Sprintf("%v", args[0]), fmt.Sprintf("%v", args[1])), true

	case "LOCATE":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		hay := []rune(fmt.Sprintf("%v", args[0]))
		needle := []rune(fmt.Sprintf("%v", args[1]))
		startPos := 1
		if len(args) >= 3 && args[2] != nil {
			if sp, okP := toInt64(args[2]); okP {
				startPos = int(sp)
			}
		}
		if startPos < 1 {
			return int64(0), true
		}
		if len(needle) == 0 {
			if startPos <= len(hay)+1 {
				return int64(startPos), true
			}
			return int64(0), true
		}
		for i := startPos - 1; i+len(needle) <= len(hay); i++ {
			match := true
			for j := range needle {
				if hay[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return int64(i + 1), true
			}
		}
		return int64(0), true

	case "LTRIM":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		return strings.TrimLeftFunc(fmt.Sprintf("%v", args[0]), unicode.IsSpace), true

	case "RTRIM":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		return strings.TrimRightFunc(fmt.Sprintf("%v", args[0]), unicode.IsSpace), true

	case "LEFT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		ln, okL := toInt64(args[1])
		if !okL || ln < 0 {
			return nil, true
		}
		runes := []rune(fmt.Sprintf("%v", args[0]))
		if int(ln) >= len(runes) {
			return string(runes), true
		}
		return string(runes[:int(ln)]), true

	case "RIGHT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		ln, okL := toInt64(args[1])
		if !okL || ln < 0 {
			return nil, true
		}
		runes := []rune(fmt.Sprintf("%v", args[0]))
		if int(ln) >= len(runes) {
			return string(runes), true
		}
		return string(runes[len(runes)-int(ln):]), true

	// --- Math, Conditional & Conversion functions ---
	case "FLOOR":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		if fv, ok := toESQLNumber(args[0]); ok {
			return int64(math.Floor(fv)), true
		}
		return nil, true

	case "CEIL", "CEILING":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		if fv, ok := toESQLNumber(args[0]); ok {
			return int64(math.Ceil(fv)), true
		}
		return nil, true

	case "POW", "POWER":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		b, ok1 := toESQLNumber(args[0])
		e, ok2 := toESQLNumber(args[1])
		if !ok1 || !ok2 {
			return nil, true
		}
		res := math.Pow(b, e)
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return nil, true
		}
		return res, true

	case "SQRT":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		if fv, ok := toESQLNumber(args[0]); ok && fv >= 0 {
			return math.Sqrt(fv), true
		}
		return nil, true

	case "MOD":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		if li, ok1 := esqlAsInt64Exact(args[0]); ok1 {
			if ri, ok2 := esqlAsInt64Exact(args[1]); ok2 {
				if ri == 0 {
					return nil, true
				}
				return li % ri, true
			}
		}
		lf, ok1 := toESQLNumber(args[0])
		rf, ok2 := toESQLNumber(args[1])
		if !ok1 || !ok2 || rf == 0 {
			return nil, true
		}
		return math.Mod(lf, rf), true

	case "GREATEST":
		var best any
		for _, a := range args {
			if a == nil {
				continue
			}
			if best == nil || compareESQLValues(a, best) > 0 {
				best = a
			}
		}
		return best, true

	case "LEAST":
		var best any
		for _, a := range args {
			if a == nil {
				continue
			}
			if best == nil || compareESQLValues(a, best) < 0 {
				best = a
			}
		}
		return best, true

	case "CASE":
		for i := 0; i+1 < len(args); i += 2 {
			if b, ok := args[i].(bool); ok && b {
				return args[i+1], true
			}
		}
		if len(args)%2 == 1 {
			return args[len(args)-1], true
		}
		return nil, true

	case "TO_DATETIME":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		if t, ok := parseESQLDateTime(args[0]); ok {
			return t.UTC().Format("2006-01-02T15:04:05.000Z"), true
		}
		return nil, true

	// --- Multivalue (MV_*) functions ---
	case "MV_COUNT":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		return int64(len(vals)), true

	case "MV_MIN", "MV_MAX":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		var best any
		wantMax := strings.EqualFold(name, "MV_MAX")
		for _, el := range vals {
			if el == nil {
				continue
			}
			if best == nil {
				best = el
				continue
			}
			cmp := compareESQLValues(el, best)
			if (wantMax && cmp > 0) || (!wantMax && cmp < 0) {
				best = el
			}
		}
		return best, true

	case "MV_SUM":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		hasVal := false
		allInt := true
		var sumI int64
		var sumF float64
		for _, el := range vals {
			if iv, ok := esqlAsInt64Exact(el); ok {
				hasVal = true
				sumI += iv
				sumF += float64(iv)
			} else if fv, ok := toESQLNumber(el); ok {
				hasVal = true
				allInt = false
				sumF += fv
			}
		}
		if !hasVal {
			return nil, true
		}
		if allInt {
			return sumI, true
		}
		return sumF, true

	case "MV_AVG":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		var cnt int
		var sumF float64
		for _, el := range vals {
			if fv, ok := toESQLNumber(el); ok {
				sumF += fv
				cnt++
			}
		}
		if cnt == 0 {
			return nil, true
		}
		return sumF / float64(cnt), true

	case "MV_CONCAT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		if len(vals) == 0 {
			return nil, true
		}
		sep := fmt.Sprintf("%v", args[1])
		strs := make([]string, 0, len(vals))
		for _, el := range vals {
			if el != nil {
				strs = append(strs, fmt.Sprintf("%v", el))
			}
		}
		return strings.Join(strs, sep), true

	case "MV_DEDUPE":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		seen := make(map[string]bool)
		var out []any
		for _, el := range vals {
			if el == nil {
				continue
			}
			k := fmt.Sprintf("%T:%v", el, el)
			if !seen[k] {
				seen[k] = true
				out = append(out, el)
			}
		}
		if len(out) == 1 {
			return out[0], true
		}
		return out, true

	case "MV_SORT":
		if len(args) == 0 || args[0] == nil {
			return nil, true
		}
		vals := append([]any(nil), toESQLMultiValueSlice(args[0])...)
		desc := false
		if len(args) >= 2 && args[1] != nil {
			desc = strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", args[1])), "DESC")
		}
		sort.SliceStable(vals, func(i, j int) bool {
			cmp := compareESQLValues(vals[i], vals[j])
			if desc {
				return cmp > 0
			}
			return cmp < 0
		})
		return vals, true

	case "MV_SLICE":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		vals := toESQLMultiValueSlice(args[0])
		n := len(vals)
		if n == 0 {
			return []any{}, true
		}
		sIdx, okS := toInt64(args[1])
		if !okS {
			return nil, true
		}
		start := int(sIdx)
		if start < 0 {
			start = n + start
		}
		if start < 0 {
			start = 0
		}
		end := n - 1
		if len(args) >= 3 && args[2] != nil {
			eIdx, okE := toInt64(args[2])
			if !okE {
				return nil, true
			}
			end = int(eIdx)
			if end < 0 {
				end = n + end
			}
		}
		if end >= n {
			end = n - 1
		}
		if start > end || start >= n {
			return []any{}, true
		}
		out := append([]any(nil), vals[start:end+1]...)
		if len(out) == 1 {
			return out[0], true
		}
		return out, true

	// --- Date (DATE_*) functions ---
	case "DATE_EXTRACT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		part := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", args[0])))
		t, ok := parseESQLDateTime(args[1])
		if !ok {
			return nil, true
		}
		t = t.UTC()
		switch part {
		case "year", "years":
			return int64(t.Year()), true
		case "month", "months", "month_of_year":
			return int64(t.Month()), true
		case "day", "days", "day_of_month", "date":
			return int64(t.Day()), true
		case "day_of_year":
			return int64(t.YearDay()), true
		case "day_of_week", "dow":
			dow := int64(t.Weekday())
			if dow == 0 {
				dow = 7
			}
			return dow, true
		case "hour", "hours", "hour_of_day":
			return int64(t.Hour()), true
		case "minute", "minutes", "minute_of_hour":
			return int64(t.Minute()), true
		case "second", "seconds", "second_of_minute":
			return int64(t.Second()), true
		case "milli", "millis", "millisecond", "milliseconds":
			return int64(t.Nanosecond() / 1_000_000), true
		}
		return nil, true

	case "DATE_TRUNC":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		unitStr := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", args[0])))
		t, ok := parseESQLDateTime(args[1])
		if !ok {
			return nil, true
		}
		t = t.UTC()
		var tr time.Time
		switch {
		case strings.Contains(unitStr, "year") || strings.HasSuffix(unitStr, "y"):
			tr = time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		case strings.Contains(unitStr, "month") || unitStr == "1M":
			tr = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		case strings.Contains(unitStr, "day") || strings.HasSuffix(unitStr, "d"):
			tr = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		case strings.Contains(unitStr, "hour") || strings.HasSuffix(unitStr, "h"):
			tr = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC)
		case strings.Contains(unitStr, "minute") || strings.HasSuffix(unitStr, "m"):
			if durMS, valid := parsePositiveESDurationMillis(unitStr); valid && durMS > 0 {
				tr = time.UnixMilli((t.UnixMilli() / durMS) * durMS).UTC()
			} else {
				tr = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
			}
		case strings.Contains(unitStr, "second") || strings.HasSuffix(unitStr, "s"):
			tr = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		default:
			if durMS, valid := parsePositiveESDurationMillis(unitStr); valid && durMS > 0 {
				tr = time.UnixMilli((t.UnixMilli() / durMS) * durMS).UTC()
			} else {
				return nil, true
			}
		}
		return tr.Format("2006-01-02T15:04:05.000Z"), true

	case "DATE_PARSE":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		fmtPattern := fmt.Sprintf("%v", args[0])
		dateStr := fmt.Sprintf("%v", args[1])
		if t, err := parseIngestDateValue(dateStr, []any{fmtPattern}, "UTC"); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000Z"), true
		}
		return nil, true

	case "DATE_FORMAT":
		if len(args) < 2 || args[0] == nil || args[1] == nil {
			return nil, true
		}
		// ES|QL DATE_FORMAT(format, date) or single-arg DATE_FORMAT(date)
		fmtPattern := fmt.Sprintf("%v", args[0])
		t, ok := parseESQLDateTime(args[1])
		if !ok {
			// Also tolerate DATE_FORMAT(date, format) if user reversed args
			if tAlt, okAlt := parseESQLDateTime(args[0]); okAlt {
				t = tAlt
				fmtPattern = fmt.Sprintf("%v", args[1])
			} else {
				return nil, true
			}
		}
		layouts := convertESDateFormatToGoLayouts(fmtPattern)
		if len(layouts) > 0 && layouts[0] != "UNIX" && layouts[0] != "UNIX_MS" && layouts[0] != "TAI64N" {
			return t.UTC().Format(layouts[0]), true
		}
		return t.UTC().Format("2006-01-02T15:04:05.000Z"), true

	case "DATE_DIFF":
		if len(args) < 3 || args[0] == nil || args[1] == nil || args[2] == nil {
			return nil, true
		}
		unit := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", args[0])))
		tStart, ok1 := parseESQLDateTime(args[1])
		tEnd, ok2 := parseESQLDateTime(args[2])
		if !ok1 || !ok2 {
			return nil, true
		}
		diff := tEnd.Sub(tStart)
		switch unit {
		case "year", "years", "y":
			return int64(tEnd.UTC().Year() - tStart.UTC().Year()), true
		case "month", "months", "M":
			return int64((tEnd.UTC().Year()-tStart.UTC().Year())*12 + int(tEnd.UTC().Month()-tStart.UTC().Month())), true
		case "week", "weeks", "w":
			return int64(diff / (7 * 24 * time.Hour)), true
		case "day", "days", "d":
			return int64(diff / (24 * time.Hour)), true
		case "hour", "hours", "h":
			return int64(diff / time.Hour), true
		case "minute", "minutes", "m":
			return int64(diff / time.Minute), true
		case "second", "seconds", "s":
			return int64(diff / time.Second), true
		case "millisecond", "milliseconds", "ms":
			return diff.Milliseconds(), true
		}
		return nil, true
	}
	return nil, false
}

func toESQLMultiValueSlice(v any) []any {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		out := make([]any, 0, len(arr))
		for _, el := range arr {
			if el != nil {
				out = append(out, normalizeESQLNumber(el))
			}
		}
		return out
	}
	return []any{normalizeESQLNumber(v)}
}

func parseESQLDateTime(v any) (time.Time, bool) {
	switch tv := v.(type) {
	case time.Time:
		return tv, true
	case int64:
		return time.UnixMilli(tv).UTC(), true
	case int:
		return time.UnixMilli(int64(tv)).UTC(), true
	case float64:
		if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
			return time.UnixMilli(int64(tv)).UTC(), true
		}
	case string:
		s := strings.TrimSpace(tv)
		if s == "" {
			return time.Time{}, false
		}
		if t, err := parseIngestDateValue(s, []any{"ISO8601", "UNIX_MS"}, "UTC"); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func computeESQLMedianOrPercentile(fn, arg string, grpRows []map[string]any) (any, string, bool) {
	switch fn {
	case "MEDIAN":
		val := computeESQLPercentileValue(arg, 50.0, grpRows)
		return val, "double", true
	case "PERCENTILE":
		parts := splitESQLTopLevel(arg, ',')
		if len(parts) < 2 {
			return nil, "double", true
		}
		fieldExpr := strings.TrimSpace(parts[0])
		pctVal := evalESQLExpr(strings.TrimSpace(parts[1]), nil)
		pct, ok := toESQLNumber(pctVal)
		if !ok || pct < 0 || pct > 100 {
			return nil, "double", true
		}
		val := computeESQLPercentileValue(fieldExpr, pct, grpRows)
		return val, "double", true
	}
	return nil, "", false
}

func computeESQLPercentileValue(fieldExpr string, pct float64, grpRows []map[string]any) any {
	var nums []float64
	for _, r := range grpRows {
		v := evalESQLExpr(fieldExpr, r)
		if fv, ok := toESQLNumber(v); ok {
			nums = append(nums, fv)
		} else if arr, okA := v.([]any); okA {
			for _, el := range arr {
				if ef, okE := toESQLNumber(el); okE {
					nums = append(nums, ef)
				}
			}
		}
	}
	if len(nums) == 0 {
		return nil
	}
	sort.Float64s(nums)
	if len(nums) == 1 {
		return nums[0]
	}
	pos := (pct / 100.0) * float64(len(nums)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return nums[lo]
	}
	frac := pos - float64(lo)
	return nums[lo] + frac*(nums[hi]-nums[lo])
}

func executeESQLShowInfo() ([]map[string]any, []string, map[string]string) {
	colOrder := []string{"version", "build_date", "build_hash", "lucene_version"}
	colTypes := map[string]string{
		"version":        "keyword",
		"build_date":     "datetime",
		"build_hash":     "keyword",
		"lucene_version": "keyword",
	}
	row := map[string]any{
		"version":        "8.15.0",
		"build_date":     "2026-01-01T00:00:00.000Z",
		"build_hash":     "doris-es-proxy",
		"lucene_version": "9.11.1",
	}
	return []map[string]any{row}, colOrder, colTypes
}

func parseESQLStageTokens(s string) ([]string, error) {
	var out []string
	n := len(s)
	for i := 0; i < n; {
		for i < n && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= n {
			break
		}
		ch := s[i]
		if ch == '"' || ch == '\'' || ch == '`' {
			quote := ch
			start := i
			i++
			closed := false
			for i < n {
				if s[i] == '\\' && quote != '`' && i+1 < n {
					i += 2
					continue
				}
				if s[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed quote in ES|QL stage [%s]", s)
			}
			out = append(out, s[start:i])
			continue
		}
		if ch == '=' || ch == ',' {
			out = append(out, string(ch))
			i++
			continue
		}
		start := i
		for i < n && !unicode.IsSpace(rune(s[i])) && s[i] != '=' && s[i] != ',' && s[i] != '"' && s[i] != '\'' && s[i] != '`' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out, nil
}

func unquoteESQLStringToken(tok string) string {
	t := strings.TrimSpace(tok)
	if len(t) >= 2 && ((t[0] == '"' && t[len(t)-1] == '"') || (t[0] == '\'' && t[len(t)-1] == '\'') || (t[0] == '`' && t[len(t)-1] == '`')) {
		quote := t[0]
		inner := t[1 : len(t)-1]
		if quote == '`' {
			return inner
		}
		var sb strings.Builder
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				i++
				switch inner[i] {
				case 'n':
					sb.WriteByte('\n')
				case 't':
					sb.WriteByte('\t')
				case 'r':
					sb.WriteByte('\r')
				default:
					sb.WriteByte(inner[i])
				}
				continue
			}
			sb.WriteByte(inner[i])
		}
		return sb.String()
	}
	return t
}

func appendUniqueESQLCol(colOrder []string, col string) []string {
	for _, c := range colOrder {
		if c == col {
			return colOrder
		}
	}
	return append(colOrder, col)
}

func esqlStageHasKeyword(upper, kw string) bool {
	if upper == kw {
		return true
	}
	return strings.HasPrefix(upper, kw) && len(upper) > len(kw) && unicode.IsSpace(rune(upper[len(kw)]))
}

func (s *Server) executeESQLExtraStage(
	w http.ResponseWriter,
	r *http.Request,
	st string,
	upper string,
	rows []map[string]any,
	colOrder []string,
	colTypes map[string]string,
) ([]map[string]any, []string, map[string]string, bool, bool) {
	switch {
	case esqlStageHasKeyword(upper, "DISSECT"):
		rest := strings.TrimSpace(st[len("DISSECT"):])
		toks, err := parseESQLStageTokens(rest)
		if err != nil || len(toks) < 2 {
			writeESError(w, http.StatusBadRequest, "verification_exception", "DISSECT requires <field> and \"<pattern>\"")
			return nil, nil, nil, true, false
		}
		field := unquoteESQLStringToken(toks[0])
		pattern := unquoteESQLStringToken(toks[1])
		appendSep := " "
		for i := 2; i < len(toks); i++ {
			if strings.EqualFold(toks[i], "APPEND_SEPARATOR") && i+2 < len(toks) && toks[i+1] == "=" {
				appendSep = unquoteESQLStringToken(toks[i+2])
				i += 2
			}
		}
		// Validate pattern syntax upfront
		if strings.Contains(pattern, "%{") && !strings.Contains(pattern, "}") {
			writeESError(w, http.StatusBadRequest, "verification_exception", fmt.Sprintf("invalid DISSECT pattern [%s]", pattern))
			return nil, nil, nil, true, false
		}
		var newCols []string
		seenNew := make(map[string]bool)
		for _, row := range rows {
			rawVal := getESQLFieldVal(row, field)
			if rawVal == nil {
				continue
			}
			extracted, dErr := evalDissectPattern(pattern, fmt.Sprintf("%v", rawVal), appendSep)
			if dErr != nil {
				continue
			}
			for k, v := range extracted {
				row[k] = v
				if !seenNew[k] {
					seenNew[k] = true
					newCols = append(newCols, k)
				}
				if colTypes[k] == "" {
					colTypes[k] = "keyword"
				}
			}
		}
		sort.Strings(newCols)
		for _, nc := range newCols {
			colOrder = appendUniqueESQLCol(colOrder, nc)
		}
		return rows, colOrder, colTypes, true, true

	case esqlStageHasKeyword(upper, "GROK"):
		rest := strings.TrimSpace(st[len("GROK"):])
		toks, err := parseESQLStageTokens(rest)
		if err != nil || len(toks) < 2 {
			writeESError(w, http.StatusBadRequest, "verification_exception", "GROK requires <field> and \"<pattern>\"")
			return nil, nil, nil, true, false
		}
		field := unquoteESQLStringToken(toks[0])
		pattern := unquoteESQLStringToken(toks[1])
		re, grpMap, grpTypes, gErr := compileGrokRegex(pattern, nil)
		if gErr != nil {
			writeESError(w, http.StatusBadRequest, "verification_exception", fmt.Sprintf("invalid GROK pattern [%s]: %v", pattern, gErr))
			return nil, nil, nil, true, false
		}
		var grokCols []string
		seenGrok := make(map[string]bool)
		for grpID, fn := range grpMap {
			if fn != "" && !seenGrok[fn] {
				seenGrok[fn] = true
				grokCols = append(grokCols, fn)
				switch strings.ToLower(grpTypes[grpID]) {
				case "int", "integer", "long":
					colTypes[fn] = "long"
				case "float", "double":
					colTypes[fn] = "double"
				case "boolean", "bool":
					colTypes[fn] = "boolean"
				default:
					if colTypes[fn] == "" {
						colTypes[fn] = "keyword"
					}
				}
			}
		}
		sort.Strings(grokCols)
		for _, gc := range grokCols {
			colOrder = appendUniqueESQLCol(colOrder, gc)
		}
		for _, row := range rows {
			rawVal := getESQLFieldVal(row, field)
			if rawVal == nil {
				continue
			}
			msg := fmt.Sprintf("%v", rawVal)
			sub := re.FindStringSubmatch(msg)
			loc := re.FindStringSubmatchIndex(msg)
			if sub == nil || loc == nil {
				continue
			}
			for i, grpID := range re.SubexpNames() {
				if i == 0 || grpID == "" || i >= len(sub) || 2*i >= len(loc) || loc[2*i] < 0 {
					continue
				}
				fn := grpMap[grpID]
				if fn == "" {
					continue
				}
				var val any = sub[i]
				if ct := grpTypes[grpID]; ct != "" {
					if cv, cErr := convertSingleIngestValue(sub[i], ct); cErr == nil {
						val = cv
					}
				}
				row[fn] = val
			}
		}
		return rows, colOrder, colTypes, true, true

	case esqlStageHasKeyword(upper, "ENRICH"):
		rest := strings.TrimSpace(st[len("ENRICH"):])
		toks, err := parseESQLStageTokens(rest)
		if err != nil || len(toks) == 0 {
			writeESError(w, http.StatusBadRequest, "verification_exception", "ENRICH requires <policy_name>")
			return nil, nil, nil, true, false
		}
		policyName := unquoteESQLStringToken(toks[0])
		s.mu.RLock()
		polEntry, polExists := s.enrichPolicies[policyName]
		var polCopy map[string]any
		if polExists && polEntry != nil {
			polCopy = deepCloneDocMap(polEntry)
		}
		s.mu.RUnlock()
		if !polExists || polCopy == nil {
			writeESError(w, http.StatusBadRequest, "verification_exception", fmt.Sprintf("enrich policy [%s] not found", policyName))
			return nil, nil, nil, true, false
		}
		var cfg map[string]any
		for _, pt := range []string{"match", "range", "geo_match"} {
			if m, okM := polCopy[pt].(map[string]any); okM {
				cfg = m
				break
			}
		}
		if cfg == nil {
			if cSub, okC := polCopy["config"].(map[string]any); okC {
				for _, pt := range []string{"match", "range", "geo_match"} {
					if m, okM := cSub[pt].(map[string]any); okM {
						cfg = m
						break
					}
				}
			}
		}
		if cfg == nil {
			cfg = polCopy
		}
		policyMatchField, _ := cfg["match_field"].(string)
		onField := policyMatchField
		type enrichOutSpec struct {
			outCol   string
			srcField string
		}
		var withSpecs []enrichOutSpec
		i := 1
		for i < len(toks) {
			if strings.EqualFold(toks[i], "ON") && i+1 < len(toks) {
				onField = unquoteESQLStringToken(toks[i+1])
				i += 2
				continue
			}
			if strings.EqualFold(toks[i], "WITH") {
				i++
				for i < len(toks) {
					if toks[i] == "," {
						i++
						continue
					}
					col1 := unquoteESQLStringToken(toks[i])
					if i+2 < len(toks) && toks[i+1] == "=" {
						srcF := unquoteESQLStringToken(toks[i+2])
						withSpecs = append(withSpecs, enrichOutSpec{outCol: col1, srcField: srcF})
						i += 3
					} else {
						withSpecs = append(withSpecs, enrichOutSpec{outCol: col1, srcField: col1})
						i++
					}
				}
				break
			}
			i++
		}
		if len(withSpecs) == 0 {
			if efSlice, okE := cfg["enrich_fields"].([]any); okE {
				for _, ef := range efSlice {
					fStr := fmt.Sprintf("%v", ef)
					withSpecs = append(withSpecs, enrichOutSpec{outCol: fStr, srcField: fStr})
				}
			}
		}
		var srcIndices []string
		switch iv := cfg["indices"].(type) {
		case string:
			if strings.TrimSpace(iv) != "" {
				srcIndices = append(srcIndices, strings.TrimSpace(iv))
			}
		case []any:
			for _, el := range iv {
				if sIdx := strings.TrimSpace(fmt.Sprintf("%v", el)); sIdx != "" {
					srcIndices = append(srcIndices, sIdx)
				}
			}
		case []string:
			srcIndices = append(srcIndices, iv...)
		}

		lookup := make(map[string]map[string]any)
		// Also check cached _docs on policy if `_execute` captured them
		if cachedDocs, okCD := polCopy["_docs"].([]any); okCD {
			for _, dAny := range cachedDocs {
				if dm, okM := dAny.(map[string]any); okM {
					mv := getNestedDocVal(dm, policyMatchField)
					if mv != nil {
						lookup[fmt.Sprintf("%v", mv)] = dm
					}
				}
			}
		}
		if len(srcIndices) > 0 {
			dslBytes := []byte(`{"size":10000,"query":{"match_all":{}}}`)
			r2, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
			if reqErr == nil {
				r2.SetPathValue("index", strings.Join(srcIndices, ","))
				rec := &asyncCaptureResponseWriter{}
				s.handleSearch(rec, r2)
				if rec.code == http.StatusOK {
					var sr map[string]any
					dec := json.NewDecoder(bytes.NewReader(rec.body.Bytes()))
					dec.UseNumber()
					_ = dec.Decode(&sr)
					if hm, okH := sr["hits"].(map[string]any); okH {
						if hList, okL := hm["hits"].([]any); okL {
							for _, hAny := range hList {
								if hObj, okO := hAny.(map[string]any); okO {
									if srcMap, okS := hObj["_source"].(map[string]any); okS {
										mv := getNestedDocVal(srcMap, policyMatchField)
										if mv != nil {
											lookup[fmt.Sprintf("%v", mv)] = srcMap
										}
									}
								}
							}
						}
					}
				}
			}
		}

		for _, ws := range withSpecs {
			colOrder = appendUniqueESQLCol(colOrder, ws.outCol)
			if colTypes[ws.outCol] == "" {
				colTypes[ws.outCol] = "keyword"
			}
		}
		for _, row := range rows {
			mv := getESQLFieldVal(row, onField)
			if mv == nil {
				continue
			}
			matchedDoc, found := lookup[fmt.Sprintf("%v", mv)]
			if !found {
				continue
			}
			for _, ws := range withSpecs {
				ev := getNestedDocVal(matchedDoc, ws.srcField)
				row[ws.outCol] = ev
				if ev != nil {
					colTypes[ws.outCol] = inferESQLValueType(ev)
				}
			}
		}
		return rows, colOrder, colTypes, true, true

	case esqlStageHasKeyword(upper, "MV_EXPAND"):
		field := unquoteESQLIdent(strings.TrimSpace(st[len("MV_EXPAND"):]))
		if field == "" {
			writeESError(w, http.StatusBadRequest, "verification_exception", "MV_EXPAND requires a field name")
			return nil, nil, nil, true, false
		}
		var expanded []map[string]any
		for _, row := range rows {
			val := getESQLFieldVal(row, field)
			if val == nil {
				continue
			}
			if arr, ok := val.([]any); ok {
				if len(arr) == 0 {
					continue
				}
				for _, el := range arr {
					if el == nil {
						continue
					}
					cp := make(map[string]any, len(row))
					for k, v := range row {
						cp[k] = v
					}
					normEl := normalizeESQLNumber(el)
					cp[field] = normEl
					colTypes[field] = inferESQLValueType(normEl)
					expanded = append(expanded, cp)
				}
			} else {
				cp := make(map[string]any, len(row))
				for k, v := range row {
					cp[k] = v
				}
				expanded = append(expanded, cp)
			}
		}
		return expanded, colOrder, colTypes, true, true
	}
	return rows, colOrder, colTypes, false, true
}

// ============================================================================
// Round 57 F4: EQL Event & Multi-Stage Sequence Engine
// ============================================================================

type eqlTokKind int

const (
	eqlTokEOF eqlTokKind = iota
	eqlTokIdent
	eqlTokString
	eqlTokNumber
	eqlTokLBracket
	eqlTokRBracket
	eqlTokLParen
	eqlTokRParen
	eqlTokComma
	eqlTokOp
)

type eqlToken struct {
	kind eqlTokKind
	val  string
	raw  string
}

func tokenizeEQL(input string) ([]eqlToken, error) {
	var toks []eqlToken
	n := len(input)
	bracketDepth := 0
	parenDepth := 0
	for i := 0; i < n; {
		ch := input[i]
		if unicode.IsSpace(rune(ch)) {
			i++
			continue
		}
		if ch == '/' && i+1 < n && input[i+1] == '/' {
			for i < n && input[i] != '\n' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < n && input[i+1] == '*' {
			i += 2
			end := strings.Index(input[i:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unclosed block comment in EQL query")
			}
			i += end + 2
			continue
		}
		if ch == '"' || ch == '\'' {
			quote := ch
			start := i
			i++
			var sb strings.Builder
			// Check raw triple quotes """..."""
			if quote == '"' && i+1 < n && input[i] == '"' && input[i+1] == '"' {
				i += 2
				end := strings.Index(input[i:], `"""`)
				if end < 0 {
					return nil, fmt.Errorf("unclosed raw string literal")
				}
				sb.WriteString(input[i : i+end])
				i += end + 3
				toks = append(toks, eqlToken{kind: eqlTokString, val: sb.String(), raw: input[start:i]})
				continue
			}
			closed := false
			for i < n {
				if input[i] == '\\' && i+1 < n {
					i++
					switch input[i] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					default:
						sb.WriteByte(input[i])
					}
					i++
					continue
				}
				if input[i] == quote {
					if i+1 < n && input[i+1] == quote {
						sb.WriteByte(quote)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed string literal")
			}
			toks = append(toks, eqlToken{kind: eqlTokString, val: sb.String(), raw: input[start:i]})
			continue
		}
		switch ch {
		case '[':
			bracketDepth++
			toks = append(toks, eqlToken{kind: eqlTokLBracket, val: "[", raw: "["})
			i++
			continue
		case ']':
			bracketDepth--
			if bracketDepth < 0 {
				return nil, fmt.Errorf("unbalanced ']'")
			}
			toks = append(toks, eqlToken{kind: eqlTokRBracket, val: "]", raw: "]"})
			i++
			continue
		case '(':
			parenDepth++
			toks = append(toks, eqlToken{kind: eqlTokLParen, val: "(", raw: "("})
			i++
			continue
		case ')':
			parenDepth--
			if parenDepth < 0 {
				return nil, fmt.Errorf("unbalanced ')'")
			}
			toks = append(toks, eqlToken{kind: eqlTokRParen, val: ")", raw: ")"})
			i++
			continue
		case ',':
			toks = append(toks, eqlToken{kind: eqlTokComma, val: ",", raw: ","})
			i++
			continue
		case ':':
			toks = append(toks, eqlToken{kind: eqlTokOp, val: ":", raw: ":"})
			i++
			continue
		case '~':
			toks = append(toks, eqlToken{kind: eqlTokOp, val: "~", raw: "~"})
			i++
			continue
		case '=':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, eqlToken{kind: eqlTokOp, val: "==", raw: "=="})
				i += 2
				continue
			}
			toks = append(toks, eqlToken{kind: eqlTokOp, val: "=", raw: "="})
			i++
			continue
		case '!':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, eqlToken{kind: eqlTokOp, val: "!=", raw: "!="})
				i += 2
				continue
			}
			if bracketDepth == 0 {
				j := i + 1
				for j < n && unicode.IsSpace(rune(input[j])) {
					j++
				}
				if j < n && input[j] == '[' {
					toks = append(toks, eqlToken{kind: eqlTokOp, val: "!", raw: "!"})
					i++
					continue
				}
			}
			return nil, fmt.Errorf("invalid operator '!' (use 'not' or '!=')")
		case '<':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, eqlToken{kind: eqlTokOp, val: "<=", raw: "<="})
				i += 2
				continue
			}
			if i+1 < n && input[i+1] == '>' {
				toks = append(toks, eqlToken{kind: eqlTokOp, val: "!=", raw: "<>"})
				i += 2
				continue
			}
			toks = append(toks, eqlToken{kind: eqlTokOp, val: "<", raw: "<"})
			i++
			continue
		case '>':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, eqlToken{kind: eqlTokOp, val: ">=", raw: ">="})
				i += 2
				continue
			}
			toks = append(toks, eqlToken{kind: eqlTokOp, val: ">", raw: ">"})
			i++
			continue
		}
		if (ch >= '0' && ch <= '9') || (ch == '-' && i+1 < n && input[i+1] >= '0' && input[i+1] <= '9') {
			start := i
			if ch == '-' {
				i++
			}
			for i < n && input[i] >= '0' && input[i] <= '9' {
				i++
			}
			if i < n && input[i] == '.' {
				i++
				for i < n && input[i] >= '0' && input[i] <= '9' {
					i++
				}
			}
			// Check duration suffix like 5m, 30s, 100ms
			numEnd := i
			for i < n && unicode.IsLetter(rune(input[i])) {
				i++
			}
			if i > numEnd {
				toks = append(toks, eqlToken{kind: eqlTokIdent, val: input[start:i], raw: input[start:i]})
			} else {
				toks = append(toks, eqlToken{kind: eqlTokNumber, val: input[start:i], raw: input[start:i]})
			}
			continue
		}
		if unicode.IsLetter(rune(ch)) || ch == '_' || ch == '@' {
			start := i
			for i < n {
				r := rune(input[i])
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '@' || r == '-' {
					i++
				} else {
					break
				}
			}
			toks = append(toks, eqlToken{kind: eqlTokIdent, val: input[start:i], raw: input[start:i]})
			continue
		}
		return nil, fmt.Errorf("unexpected character %q in EQL query", ch)
	}
	if bracketDepth != 0 {
		return nil, fmt.Errorf("unbalanced '[' in EQL query")
	}
	if parenDepth != 0 {
		return nil, fmt.Errorf("unbalanced '(' in EQL query")
	}
	toks = append(toks, eqlToken{kind: eqlTokEOF})
	return toks, nil
}

type eqlExpr interface {
	isEQLExpr()
}

type eqlLitExpr struct{ val any }
type eqlFieldExpr struct{ name string }
type eqlNotExpr struct{ sub eqlExpr }
type eqlBinExpr struct {
	op          string
	left, right eqlExpr
}
type eqlInExpr struct {
	left   eqlExpr
	list   []eqlExpr
	negate bool
}
type eqlFuncExpr struct {
	name string
	args []eqlExpr
}

func (*eqlLitExpr) isEQLExpr()   {}
func (*eqlFieldExpr) isEQLExpr() {}
func (*eqlNotExpr) isEQLExpr()   {}
func (*eqlBinExpr) isEQLExpr()   {}
func (*eqlInExpr) isEQLExpr()    {}
func (*eqlFuncExpr) isEQLExpr()  {}

type eqlStageSpec struct {
	category string
	where    eqlExpr
	byKeys   []eqlExpr
}

type eqlQueryAST struct {
	isSequence  bool
	single      eqlStageSpec
	byKeys      []eqlExpr
	maxspanMS   int64
	hasMaxspan  bool
	stages      []eqlStageSpec
	absentAfter map[int][]eqlStageSpec
	untilStage  *eqlStageSpec
}

type eqlParser struct {
	toks []eqlToken
	pos  int
}

func (p *eqlParser) cur() eqlToken {
	if p.pos >= len(p.toks) {
		return eqlToken{kind: eqlTokEOF}
	}
	return p.toks[p.pos]
}

func (p *eqlParser) matchKw(kw string) bool {
	if p.cur().kind == eqlTokIdent && strings.EqualFold(p.cur().val, kw) {
		p.pos++
		return true
	}
	return false
}

func (p *eqlParser) peekKw(kw string) bool {
	return p.cur().kind == eqlTokIdent && strings.EqualFold(p.cur().val, kw)
}

func (p *eqlParser) parseQuery() (*eqlQueryAST, error) {
	if p.matchKw("sequence") {
		ast := &eqlQueryAST{isSequence: true}
		for p.peekKw("by") || p.peekKw("with") {
			if p.matchKw("by") {
				keys, err := p.parseByKeyList()
				if err != nil {
					return nil, err
				}
				ast.byKeys = append(ast.byKeys, keys...)
			} else if p.matchKw("with") {
				for p.cur().kind == eqlTokIdent {
					opt := strings.ToLower(p.cur().val)
					p.pos++
					if opt == "maxspan" {
						if p.cur().kind != eqlTokOp || p.cur().val != "=" {
							return nil, fmt.Errorf("expected '=' after maxspan")
						}
						p.pos++
						durTok := p.cur()
						if durTok.kind != eqlTokIdent && durTok.kind != eqlTokString {
							return nil, fmt.Errorf("invalid maxspan duration [%s]", durTok.raw)
						}
						p.pos++
						ms, ok := parsePositiveESDurationMillis(durTok.val)
						if !ok {
							return nil, fmt.Errorf("invalid maxspan duration [%s]", durTok.val)
						}
						ast.maxspanMS = ms
						ast.hasMaxspan = true
					} else if p.cur().kind == eqlTokOp && p.cur().val == "=" {
						p.pos++
						p.pos++
					}
					if p.cur().kind == eqlTokComma {
						p.pos++
					}
				}
			}
		}
		for p.cur().kind == eqlTokLBracket || (p.cur().kind == eqlTokOp && p.cur().val == "!") {
			isAbsent := false
			if p.cur().kind == eqlTokOp && p.cur().val == "!" {
				isAbsent = true
				p.pos++
				if p.cur().kind != eqlTokLBracket {
					return nil, fmt.Errorf("expected '[' after '!'")
				}
			}
			p.pos++
			st, err := p.parseStage(true)
			if err != nil {
				return nil, err
			}
			if p.cur().kind != eqlTokRBracket {
				return nil, fmt.Errorf("expected ']' at end of sequence stage")
			}
			p.pos++
			if isAbsent {
				if len(ast.stages) == 0 {
					return nil, fmt.Errorf("EQL missing stage '![...]' cannot be the first stage")
				}
				if ast.absentAfter == nil {
					ast.absentAfter = make(map[int][]eqlStageSpec)
				}
				ast.absentAfter[len(ast.stages)] = append(ast.absentAfter[len(ast.stages)], st)
			} else {
				ast.stages = append(ast.stages, st)
			}
		}
		if len(ast.stages) < 2 {
			return nil, fmt.Errorf("EQL sequence requires at least 2 stages")
		}
		if p.matchKw("until") {
			if p.cur().kind != eqlTokLBracket {
				return nil, fmt.Errorf("expected '[' after until")
			}
			p.pos++
			ust, err := p.parseStage(true)
			if err != nil {
				return nil, err
			}
			if p.cur().kind != eqlTokRBracket {
				return nil, fmt.Errorf("expected ']' after until stage")
			}
			p.pos++
			ast.untilStage = &ust
		}
		if p.cur().kind != eqlTokEOF {
			return nil, fmt.Errorf("unexpected token [%s] after sequence", p.cur().raw)
		}
		return ast, nil
	}

	st, err := p.parseStage(false)
	if err != nil {
		return nil, err
	}
	if p.cur().kind != eqlTokEOF {
		return nil, fmt.Errorf("unexpected token [%s] in EQL query", p.cur().raw)
	}
	return &eqlQueryAST{isSequence: false, single: st}, nil
}

func (p *eqlParser) parseByKeyList() ([]eqlExpr, error) {
	var keys []eqlExpr
	for {
		ex, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		keys = append(keys, ex)
		if p.cur().kind == eqlTokComma {
			p.pos++
			continue
		}
		break
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("expected at least one join key after 'by'")
	}
	return keys, nil
}

func (p *eqlParser) parseStage(allowBy bool) (eqlStageSpec, error) {
	catTok := p.cur()
	if catTok.kind != eqlTokIdent && catTok.kind != eqlTokString {
		return eqlStageSpec{}, fmt.Errorf("expected event category in EQL query, got [%s]", catTok.raw)
	}
	p.pos++
	if !p.matchKw("where") {
		return eqlStageSpec{}, fmt.Errorf("missing 'where' clause after category [%s]", catTok.val)
	}
	expr, err := p.parseOr()
	if err != nil {
		return eqlStageSpec{}, err
	}
	st := eqlStageSpec{category: catTok.val, where: expr}
	if allowBy && p.matchKw("by") {
		keys, bErr := p.parseByKeyList()
		if bErr != nil {
			return eqlStageSpec{}, bErr
		}
		st.byKeys = keys
	}
	return st, nil
}

func (p *eqlParser) parseOr() (eqlExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.matchKw("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &eqlBinExpr{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *eqlParser) parseAnd() (eqlExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.matchKw("and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &eqlBinExpr{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *eqlParser) parseNot() (eqlExpr, error) {
	if p.matchKw("not") {
		sub, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &eqlNotExpr{sub: sub}, nil
	}
	return p.parseComparison()
}

func (p *eqlParser) parseComparison() (eqlExpr, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	negate := false
	if p.peekKw("not") {
		save := p.pos
		p.pos++
		if p.peekKw("in") || p.peekKw("like") || p.peekKw("like~") || p.peekKw("regex") || p.peekKw("regex~") {
			negate = true
		} else {
			p.pos = save
		}
	}
	if p.matchKw("in") {
		if p.cur().kind != eqlTokLParen {
			return nil, fmt.Errorf("expected '(' after 'in'")
		}
		p.pos++
		var list []eqlExpr
		for p.cur().kind != eqlTokRParen && p.cur().kind != eqlTokEOF {
			it, lErr := p.parsePrimary()
			if lErr != nil {
				return nil, lErr
			}
			list = append(list, it)
			if p.cur().kind == eqlTokComma {
				p.pos++
				continue
			}
			break
		}
		if len(list) == 0 || p.cur().kind != eqlTokRParen {
			return nil, fmt.Errorf("invalid 'in (...)' list in EQL")
		}
		p.pos++
		return &eqlInExpr{left: left, list: list, negate: negate}, nil
	}
	if p.matchKw("like") || p.matchKw("like~") {
		pat, pErr := p.parsePrimary()
		if pErr != nil {
			return nil, pErr
		}
		var ex eqlExpr = &eqlBinExpr{op: "like", left: left, right: pat}
		if negate {
			ex = &eqlNotExpr{sub: ex}
		}
		return ex, nil
	}
	if p.matchKw("regex") || p.matchKw("regex~") {
		pat, pErr := p.parsePrimary()
		if pErr != nil {
			return nil, pErr
		}
		var ex eqlExpr = &eqlBinExpr{op: "regex", left: left, right: pat}
		if negate {
			ex = &eqlNotExpr{sub: ex}
		}
		return ex, nil
	}
	t := p.cur()
	if t.kind == eqlTokOp {
		if t.val == "=" {
			return nil, fmt.Errorf("invalid operator '=' in EQL; use '==' or ':'")
		}
		op := t.val
		p.pos++
		right, rErr := p.parsePrimary()
		if rErr != nil {
			return nil, rErr
		}
		return &eqlBinExpr{op: op, left: left, right: right}, nil
	}
	return left, nil
}

func (p *eqlParser) parsePrimary() (eqlExpr, error) {
	t := p.cur()
	switch t.kind {
	case eqlTokLParen:
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.cur().kind != eqlTokRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.pos++
		return inner, nil
	case eqlTokString:
		p.pos++
		return &eqlLitExpr{val: t.val}, nil
	case eqlTokNumber:
		p.pos++
		if iv, err := strconv.ParseInt(t.val, 10, 64); err == nil {
			return &eqlLitExpr{val: iv}, nil
		}
		fv, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number [%s]", t.val)
		}
		return &eqlLitExpr{val: fv}, nil
	case eqlTokIdent:
		low := strings.ToLower(t.val)
		if low == "true" {
			p.pos++
			return &eqlLitExpr{val: true}, nil
		}
		if low == "false" {
			p.pos++
			return &eqlLitExpr{val: false}, nil
		}
		if low == "null" {
			p.pos++
			return &eqlLitExpr{val: nil}, nil
		}
		p.pos++
		if p.cur().kind == eqlTokLParen {
			p.pos++
			var args []eqlExpr
			for p.cur().kind != eqlTokRParen && p.cur().kind != eqlTokEOF {
				a, aErr := p.parseOr()
				if aErr != nil {
					return nil, aErr
				}
				args = append(args, a)
				if p.cur().kind == eqlTokComma {
					p.pos++
					continue
				}
				break
			}
			if p.cur().kind != eqlTokRParen {
				return nil, fmt.Errorf("expected ')' in EQL function %s", t.val)
			}
			p.pos++
			return &eqlFuncExpr{name: t.val, args: args}, nil
		}
		return &eqlFieldExpr{name: t.val}, nil
	default:
		return nil, fmt.Errorf("unexpected token [%s] in EQL expression", t.raw)
	}
}

func evalEQLExpr(ex eqlExpr, doc map[string]any) (any, error) {
	switch e := ex.(type) {
	case *eqlLitExpr:
		return e.val, nil
	case *eqlFieldExpr:
		return getNestedDocVal(doc, e.name), nil
	case *eqlNotExpr:
		v, err := evalEQLExpr(e.sub, doc)
		if err != nil {
			return nil, err
		}
		b, ok := v.(bool)
		if !ok {
			return false, nil
		}
		return !b, nil
	case *eqlInExpr:
		lv, err := evalEQLExpr(e.left, doc)
		if err != nil {
			return nil, err
		}
		if lv == nil {
			return false, nil
		}
		matched := false
		for _, item := range e.list {
			rv, rErr := evalEQLExpr(item, doc)
			if rErr != nil {
				return nil, rErr
			}
			if eqlCompareAny(lv, rv, "==") {
				matched = true
				break
			}
		}
		if e.negate {
			return !matched, nil
		}
		return matched, nil
	case *eqlBinExpr:
		if e.op == "and" {
			lv, err := evalEQLExpr(e.left, doc)
			if err != nil {
				return nil, err
			}
			if b, ok := lv.(bool); !ok || !b {
				return false, nil
			}
			rv, err := evalEQLExpr(e.right, doc)
			if err != nil {
				return nil, err
			}
			b2, ok2 := rv.(bool)
			return ok2 && b2, nil
		}
		if e.op == "or" {
			lv, err := evalEQLExpr(e.left, doc)
			if err != nil {
				return nil, err
			}
			if b, ok := lv.(bool); ok && b {
				return true, nil
			}
			rv, err := evalEQLExpr(e.right, doc)
			if err != nil {
				return nil, err
			}
			b2, ok2 := rv.(bool)
			return ok2 && b2, nil
		}
		lv, err := evalEQLExpr(e.left, doc)
		if err != nil {
			return nil, err
		}
		rv, err := evalEQLExpr(e.right, doc)
		if err != nil {
			return nil, err
		}
		if e.op == "==" && rv == nil {
			return lv == nil, nil
		}
		if e.op == "!=" && rv == nil {
			return lv != nil, nil
		}
		if lv == nil || rv == nil {
			return false, nil
		}
		if e.op == "regex" || e.op == "~" {
			re, rErr := regexp.Compile(fmt.Sprintf("%v", rv))
			if rErr != nil {
				return nil, fmt.Errorf("invalid regex [%v]: %v", rv, rErr)
			}
			for _, s := range eqlCandidateStrings(lv) {
				if re.MatchString(s) {
					return true, nil
				}
			}
			return false, nil
		}
		return eqlCompareAny(lv, rv, e.op), nil

	case *eqlFuncExpr:
		fn := strings.ToLower(e.name)
		vals := make([]any, len(e.args))
		for i, a := range e.args {
			v, err := evalEQLExpr(a, doc)
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
		switch fn {
		case "length":
			if len(vals) < 1 || vals[0] == nil {
				return nil, nil
			}
			if arr, ok := vals[0].([]any); ok {
				return int64(len(arr)), nil
			}
			return int64(utf8.RuneCountInString(fmt.Sprintf("%v", vals[0]))), nil
		case "startswith":
			if len(vals) < 2 || vals[0] == nil || vals[1] == nil {
				return false, nil
			}
			pref := fmt.Sprintf("%v", vals[1])
			for _, s := range eqlCandidateStrings(vals[0]) {
				if strings.HasPrefix(s, pref) {
					return true, nil
				}
			}
			return false, nil
		case "endswith":
			if len(vals) < 2 || vals[0] == nil || vals[1] == nil {
				return false, nil
			}
			sfx := fmt.Sprintf("%v", vals[1])
			for _, s := range eqlCandidateStrings(vals[0]) {
				if strings.HasSuffix(s, sfx) {
					return true, nil
				}
			}
			return false, nil
		case "stringcontains":
			if len(vals) < 2 || vals[0] == nil || vals[1] == nil {
				return false, nil
			}
			sub := fmt.Sprintf("%v", vals[1])
			for _, s := range eqlCandidateStrings(vals[0]) {
				if strings.Contains(s, sub) {
					return true, nil
				}
			}
			return false, nil
		case "cidrmatch":
			if len(vals) < 2 || vals[0] == nil {
				return false, nil
			}
			var nets []*net.IPNet
			for _, cidrArg := range vals[1:] {
				if cidrArg == nil {
					continue
				}
				_, ipNet, cErr := net.ParseCIDR(fmt.Sprintf("%v", cidrArg))
				if cErr != nil {
					return nil, fmt.Errorf("invalid CIDR [%v]: %v", cidrArg, cErr)
				}
				nets = append(nets, ipNet)
			}
			for _, ipStr := range eqlCandidateStrings(vals[0]) {
				ip := net.ParseIP(strings.TrimSpace(ipStr))
				if ip == nil {
					continue
				}
				for _, n := range nets {
					if n.Contains(ip) {
						return true, nil
					}
				}
			}
			return false, nil
		case "regex":
			if len(vals) < 2 || vals[0] == nil || vals[1] == nil {
				return false, nil
			}
			re, rErr := regexp.Compile(fmt.Sprintf("%v", vals[1]))
			if rErr != nil {
				return nil, fmt.Errorf("invalid regex [%v]: %v", vals[1], rErr)
			}
			for _, s := range eqlCandidateStrings(vals[0]) {
				if re.MatchString(s) {
					return true, nil
				}
			}
			return false, nil
		default:
			return nil, fmt.Errorf("unknown EQL function [%s]", e.name)
		}
	}
	return false, nil
}

func eqlCandidateStrings(v any) []string {
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, el := range arr {
			if el != nil {
				out = append(out, fmt.Sprintf("%v", el))
			}
		}
		return out
	}
	return []string{fmt.Sprintf("%v", v)}
}

func eqlCompareAny(lv, rv any, op string) bool {
	if arr, ok := lv.([]any); ok {
		if op == "!=" {
			for _, el := range arr {
				if eqlCompareAny(el, rv, "==") {
					return false
				}
			}
			return len(arr) > 0
		}
		for _, el := range arr {
			if eqlCompareAny(el, rv, op) {
				return true
			}
		}
		return false
	}
	switch op {
	case "==":
		return sqlValuesEqual(lv, rv)
	case "!=":
		return !sqlValuesEqual(lv, rv)
	case "<":
		return compareESQLValues(lv, rv) < 0
	case "<=":
		return compareESQLValues(lv, rv) <= 0
	case ">":
		return compareESQLValues(lv, rv) > 0
	case ">=":
		return compareESQLValues(lv, rv) >= 0
	case ":", "like":
		pat := fmt.Sprintf("%v", rv)
		return matchESQLLike(strings.ToLower(fmt.Sprintf("%v", lv)), strings.ToLower(pat))
	}
	return false
}

func eqlMatchesStage(st eqlStageSpec, doc map[string]any, catField string) (bool, error) {
	if !strings.EqualFold(st.category, "any") {
		catVal := getNestedDocVal(doc, catField)
		if catVal == nil || !eqlCompareAny(catVal, st.category, "==") {
			return false, nil
		}
	}
	res, err := evalEQLExpr(st.where, doc)
	if err != nil {
		return false, err
	}
	b, ok := res.(bool)
	return ok && b, nil
}

func extractEQLTimestampMillis(doc map[string]any, tsField string) int64 {
	raw := getNestedDocVal(doc, tsField)
	if raw == nil {
		return 0
	}
	if t, ok := parseESQLDateTime(raw); ok {
		return t.UnixMilli()
	}
	if iv, ok := toInt64(raw); ok {
		return iv
	}
	return 0
}

func extractEQLJoinKeys(doc map[string]any, keyExprs []eqlExpr) ([]any, string, bool) {
	if len(keyExprs) == 0 {
		return []any{}, "__global__", true
	}
	vals := make([]any, len(keyExprs))
	var sb strings.Builder
	for i, ke := range keyExprs {
		v, err := evalEQLExpr(ke, doc)
		if err != nil || v == nil {
			return nil, "", false
		}
		if arr, ok := v.([]any); ok {
			if len(arr) == 0 || arr[0] == nil {
				return nil, "", false
			}
			v = arr[0]
		}
		vals[i] = v
		_, _ = fmt.Fprintf(&sb, "%T:%v|", v, v)
	}
	return vals, sb.String(), true
}

func (s *Server) handleEQLSearchAPIRound57(w http.ResponseWriter, r *http.Request, segs []string) {
	if segs[0] == "_eql" && len(segs) >= 3 && segs[1] == "search" {
		if segs[2] == "status" && len(segs) >= 4 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return
			}
			id := strings.TrimSpace(segs[3])
			s.mu.RLock()
			_, exists := s.eqlSearches[id]
			s.mu.RUnlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id":                id,
				"is_running":        false,
				"is_partial":        false,
				"completion_status": 200,
			})
			return
		}
		id := strings.TrimSpace(segs[2])
		if len(segs) == 4 && segs[2] == "delete" {
			id = strings.TrimSpace(segs[3])
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.Lock()
			entry, exists := s.eqlSearches[id]
			var respCopy map[string]any
			if exists {
				respCopy = deepCloneDocMap(entry)
				if r.Method == http.MethodGet {
					if dropAfterGet, _ := entry["__delete_on_get"].(bool); dropAfterGet {
						delete(s.eqlSearches, id)
					}
				}
				delete(respCopy, "__delete_on_get")
			}
			s.mu.Unlock()
			if !exists {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, respCopy)
		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.eqlSearches[id]
			delete(s.eqlSearches, id)
			s.mu.Unlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("eql search [%s] not found", id))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	targetIndex := "_all"
	if len(segs) == 3 && segs[1] == "_eql" && segs[2] == "search" {
		targetIndex = strings.TrimSpace(segs[0])
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	queryStr, _ := body["query"].(string)
	if strings.TrimSpace(queryStr) == "" {
		writeESError(w, http.StatusBadRequest, "verification_exception", "Found 1 problem\nline 1:1: [query] cannot be empty")
		return
	}
	toks, err := tokenizeEQL(queryStr)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "verification_exception", err.Error())
		return
	}
	parser := &eqlParser{toks: toks}
	ast, err := parser.parseQuery()
	if err != nil {
		writeESError(w, http.StatusBadRequest, "verification_exception", err.Error())
		return
	}

	sizeVal := 10
	if sz, okSz := toInt64(body["size"]); okSz && sz >= 0 {
		sizeVal = int(sz)
	}
	tsField := "@timestamp"
	if tf, okTF := body["timestamp_field"].(string); okTF && strings.TrimSpace(tf) != "" {
		tsField = strings.TrimSpace(tf)
	}
	catField := "event.category"
	if cf, okCF := body["event_category_field"].(string); okCF && strings.TrimSpace(cf) != "" {
		catField = strings.TrimSpace(cf)
	}

	searchDSL := map[string]any{"size": 10000}
	if filterMap, okF := body["filter"].(map[string]any); okF && len(filterMap) > 0 {
		searchDSL["query"] = filterMap
	} else {
		searchDSL["query"] = map[string]any{"match_all": map[string]any{}}
	}
	dslBytes, _ := json.Marshal(searchDSL)
	subReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, "/_search", bytes.NewReader(dslBytes))
	if reqErr != nil {
		writeESError(w, http.StatusInternalServerError, "internal_server_error", reqErr.Error())
		return
	}
	if targetIndex != "" && targetIndex != "_all" {
		subReq.SetPathValue("index", targetIndex)
	}
	capW := &asyncCaptureResponseWriter{}
	s.handleSearch(capW, subReq)
	if capW.code >= 400 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(capW.code)
		_, _ = w.Write(capW.body.Bytes())
		return
	}
	var searchResp map[string]any
	dec := json.NewDecoder(bytes.NewReader(capW.body.Bytes()))
	dec.UseNumber()
	_ = dec.Decode(&searchResp)
	hitsWrapper, _ := searchResp["hits"].(map[string]any)
	rawHits, _ := hitsWrapper["hits"].([]any)

	type candidateEvent struct {
		hit map[string]any
		doc map[string]any
		ts  int64
	}
	candidates := make([]candidateEvent, 0, len(rawHits))
	for _, hAny := range rawHits {
		hm, okM := hAny.(map[string]any)
		if !okM {
			continue
		}
		src, _ := hm["_source"].(map[string]any)
		normDoc := make(map[string]any, len(src))
		for k, v := range src {
			normDoc[k] = normalizeESQLNumber(v)
		}
		candidates = append(candidates, candidateEvent{
			hit: hm,
			doc: normDoc,
			ts:  extractEQLTimestampMillis(normDoc, tsField),
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].ts < candidates[j].ts
	})

	eventsOut := []any{}
	sequencesOut := []any{}
	totalMatched := 0

	if !ast.isSequence {
		for _, cand := range candidates {
			matched, evalErr := eqlMatchesStage(ast.single, cand.doc, catField)
			if evalErr != nil {
				writeESError(w, http.StatusBadRequest, "verification_exception", evalErr.Error())
				return
			}
			if matched {
				totalMatched++
				if len(eventsOut) < sizeVal {
					eventsOut = append(eventsOut, cand.hit)
				}
			}
		}
	} else {
		type seqProgress struct {
			joinKeys []any
			events   []any
			startTS  int64
		}
		active := make(map[string]*seqProgress)
		stageKeysFor := func(stageIdx int) []eqlExpr {
			if len(ast.stages[stageIdx].byKeys) > 0 {
				return ast.stages[stageIdx].byKeys
			}
			return ast.byKeys
		}

		for _, cand := range candidates {
			// Check `until` abort stage and `![...]` absent stages against in-flight sequences
			if ast.untilStage != nil {
				uMatched, uErr := eqlMatchesStage(*ast.untilStage, cand.doc, catField)
				if uErr != nil {
					writeESError(w, http.StatusBadRequest, "verification_exception", uErr.Error())
					return
				}
				if uMatched {
					uKeyExprs := ast.untilStage.byKeys
					if len(uKeyExprs) == 0 {
						uKeyExprs = stageKeysFor(0)
					}
					if _, jk, okK := extractEQLJoinKeys(cand.doc, uKeyExprs); okK {
						delete(active, jk)
					}
				}
			}
			for afterPos, absList := range ast.absentAfter {
				for _, absSt := range absList {
					aMatched, aErr := eqlMatchesStage(absSt, cand.doc, catField)
					if aErr != nil {
						writeESError(w, http.StatusBadRequest, "verification_exception", aErr.Error())
						return
					}
					if aMatched {
						aKeyExprs := absSt.byKeys
						if len(aKeyExprs) == 0 {
							aKeyExprs = stageKeysFor(0)
						}
						if _, jk, okK := extractEQLJoinKeys(cand.doc, aKeyExprs); okK {
							if prog, hasProg := active[jk]; hasProg && len(prog.events) == afterPos {
								delete(active, jk)
							}
						}
					}
				}
			}

			// Evaluate stages from highest partial stage down to stage 0 so a single event advances at most one step per partial sequence
			advanced := false
			for stIdx := len(ast.stages) - 1; stIdx >= 1; stIdx-- {
				keyExprs := stageKeysFor(stIdx)
				_, jk, okK := extractEQLJoinKeys(cand.doc, keyExprs)
				if !okK {
					continue
				}
				prog, hasProg := active[jk]
				if !hasProg || len(prog.events) != stIdx {
					continue
				}
				if ast.hasMaxspan && cand.ts-prog.startTS > ast.maxspanMS {
					delete(active, jk)
					continue
				}
				stMatched, sErr := eqlMatchesStage(ast.stages[stIdx], cand.doc, catField)
				if sErr != nil {
					writeESError(w, http.StatusBadRequest, "verification_exception", sErr.Error())
					return
				}
				if stMatched {
					prog.events = append(prog.events, cand.hit)
					advanced = true
					if len(prog.events) == len(ast.stages) {
						totalMatched++
						if len(sequencesOut) < sizeVal {
							sequencesOut = append(sequencesOut, map[string]any{
								"join_keys": prog.joinKeys,
								"events":    prog.events,
							})
						}
						delete(active, jk)
					}
					break
				}
			}
			if !advanced {
				keyExprs0 := stageKeysFor(0)
				jVals, jk, okK := extractEQLJoinKeys(cand.doc, keyExprs0)
				if !okK {
					continue
				}
				st0Matched, sErr := eqlMatchesStage(ast.stages[0], cand.doc, catField)
				if sErr != nil {
					writeESError(w, http.StatusBadRequest, "verification_exception", sErr.Error())
					return
				}
				if st0Matched {
					if existing, hasProg := active[jk]; !hasProg || (ast.hasMaxspan && cand.ts-existing.startTS > ast.maxspanMS) {
						active[jk] = &seqProgress{
							joinKeys: jVals,
							events:   []any{cand.hit},
							startTS:  cand.ts,
						}
					}
				}
			}
		}
	}

	keepOnCompletion := true
	hasExplicitKeepFalse := false
	if koc, hasK := body["keep_on_completion"].(bool); hasK {
		keepOnCompletion = koc
		hasExplicitKeepFalse = !koc
	}
	if r.URL.Query().Has("keep_on_completion") {
		keepOnCompletion = isTruthyBoolQueryParam(r, "keep_on_completion")
		hasExplicitKeepFalse = !keepOnCompletion
	}
	hasWaitTimeout := body["wait_for_completion_timeout"] != nil || r.URL.Query().Has("wait_for_completion_timeout")

	s.mu.Lock()
	if s.eqlSearches == nil {
		s.eqlSearches = make(map[string]map[string]any)
	}
	eqlID := fmt.Sprintf("eql_%d", len(s.eqlSearches)+1)
	resp := map[string]any{
		"id":         eqlID,
		"is_partial": false,
		"is_running": false,
		"took":       1,
		"timed_out":  false,
		"hits": map[string]any{
			"total": map[string]any{
				"value":    totalMatched,
				"relation": "eq",
			},
			"events":    eventsOut,
			"sequences": sequencesOut,
		},
	}
	if keepOnCompletion || hasWaitTimeout {
		stored := deepCloneDocMap(resp)
		if hasExplicitKeepFalse {
			stored["__delete_on_get"] = true
		}
		s.eqlSearches[eqlID] = stored
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

// ============================================================================
// Round 57 F5: Stateful Snapshot/Restore, _mount, Cache Clear, Repo _analyze & SLM
// ============================================================================

// applyJavaRegexSimpleReplacement applies simple Java regex replacement ($1 -> ${1}, \$ -> $$)
// used by snapshot restore rename_replacement.
func applyJavaRegexSimpleReplacement(re *regexp.Regexp, src, repl string) string {
	if re == nil {
		return src
	}
	res, err := applyIngestGsubReplacement(re, src, repl)
	if err != nil {
		return re.ReplaceAllString(src, repl)
	}
	return res
}

// exportSnapshotIndexData exports schemas, shredded documents, custom settings, and aliases
// for the given snapshot indices in a backend-agnostic manner.
// Caller MUST NOT hold s.mu while calling this helper (it flushes & queries backend).
func (s *Server) exportSnapshotIndexData(ctx context.Context, indices []string) (
	savedSchemas map[string]*schema.IndexSchema,
	savedDocs map[string]any,
	savedSettings map[string]any,
	savedAliases map[string]any,
) {
	savedSchemas = make(map[string]*schema.IndexSchema, len(indices))
	savedDocs = make(map[string]any, len(indices))
	savedSettings = make(map[string]any, len(indices))
	savedAliases = make(map[string]any, len(indices))

	s.mu.RLock()
	type idxExportMeta struct {
		name    string
		sch     *schema.IndexSchema
		routing map[string]string
	}
	metas := make([]idxExportMeta, 0, len(indices))
	for _, idxName := range indices {
		sch := s.indices[idxName]
		if sch != nil {
			savedSchemas[idxName] = sch
			var rtCopy map[string]string
			if rm := s.docRouting[idxName]; len(rm) > 0 {
				rtCopy = make(map[string]string, len(rm))
				for k, v := range rm {
					rtCopy[k] = v
				}
			}
			metas = append(metas, idxExportMeta{name: idxName, sch: sch, routing: rtCopy})
		}
		if cs := s.indexCustomSettings[idxName]; len(cs) > 0 {
			savedSettings[idxName] = deepCloneDocMap(cs)
		}
		idxAliasMap := make(map[string]any)
		for aliasName, targets := range s.aliases {
			hasIdx := false
			for _, t := range targets {
				if t == idxName {
					hasIdx = true
					break
				}
			}
			if !hasIdx {
				continue
			}
			amObj := map[string]any{}
			if byIdx, okM := s.aliasMeta[aliasName]; okM {
				if meta, okIdx := byIdx[idxName]; okIdx {
					if meta.Filter != nil {
						if fb, err := json.Marshal(meta.Filter); err == nil {
							var fm map[string]any
							if json.Unmarshal(fb, &fm) == nil && fm != nil {
								amObj["filter"] = fm
							}
						}
					}
					if meta.IndexRouting != "" {
						amObj["index_routing"] = meta.IndexRouting
					}
					if meta.SearchRouting != "" {
						amObj["search_routing"] = meta.SearchRouting
					}
					if meta.Routing != "" {
						amObj["routing"] = meta.Routing
					}
					if meta.IsWriteIndex != nil {
						amObj["is_write_index"] = *meta.IsWriteIndex
					}
				}
			}
			idxAliasMap[aliasName] = amObj
		}
		if len(idxAliasMap) > 0 {
			savedAliases[idxName] = idxAliasMap
		}
	}
	opts := s.transpileOpts
	s.mu.RUnlock()

	opts.MaxResultWindow = 0
	for _, m := range metas {
		if s.coalescer != nil {
			_ = s.coalescer.FlushTable(ctx, m.sch.DorisTable)
		}
		if s.backend == nil {
			continue
		}
		tr := transpiler.NewTranspiler(m.sch, opts)
		batchSize := 1000
		var searchAfter []any
		var docList []any
		for {
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Size:           &batchSize,
				TrackTotalHits: false,
				Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter:    searchAfter,
			})
			if err != nil {
				break
			}
			hits, err := s.backend.QueryHits(ctx, plan.HitsSQL)
			if err != nil || len(hits) == 0 {
				break
			}
			for _, h := range hits {
				srcBytes := h.EffectiveSource()
				if len(srcBytes) == 0 {
					srcBytes = h.Source
				}
				rec := map[string]any{
					"id":      h.ID,
					"version": h.Version,
					"source":  string(srcBytes),
				}
				if m.routing != nil {
					if rv := m.routing[h.ID]; rv != "" {
						rec["routing"] = rv
					}
				}
				docList = append(docList, rec)
			}
			searchAfter = []any{hits[len(hits)-1].ID}
			if len(hits) < batchSize {
				break
			}
		}
		savedDocs[m.name] = docList
	}
	return savedSchemas, savedDocs, savedSettings, savedAliases
}

// restoreSnapshotIndexArtifacts restores documents, custom settings, and aliases from rawSnap
// for srcIdx into targetIdx (restoredSchema). Caller MUST NOT hold s.mu.
func (s *Server) restoreSnapshotIndexArtifacts(
	ctx context.Context,
	rawSnap map[string]any,
	srcIdx, targetIdx string,
	restoredSchema *schema.IndexSchema,
	reqMap map[string]any,
	isMount bool,
) {
	if rawSnap == nil {
		return
	}
	// 1. Restore custom settings (respecting ignore_index_settings & index_settings overrides)
	ignoredSettings := make(map[string]bool)
	if rawIgnore, hasIgn := reqMap["ignore_index_settings"]; hasIgn && rawIgnore != nil {
		switch iv := rawIgnore.(type) {
		case []any:
			for _, it := range iv {
				k := strings.TrimPrefix(strings.TrimSpace(fmt.Sprintf("%v", it)), "index.")
				if k != "" {
					ignoredSettings[k] = true
				}
			}
		case string:
			for _, p := range strings.Split(iv, ",") {
				k := strings.TrimPrefix(strings.TrimSpace(p), "index.")
				if k != "" {
					ignoredSettings[k] = true
				}
			}
		}
	}

	s.mu.Lock()
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	if s.indexCustomSettings[targetIdx] == nil {
		s.indexCustomSettings[targetIdx] = make(map[string]any)
	}
	if allSavedSettings, okS := rawSnap["__settings"].(map[string]any); okS {
		if idxSaved, okI := allSavedSettings[srcIdx].(map[string]any); okI {
			for k, v := range idxSaved {
				cleanK := strings.TrimPrefix(k, "index.")
				if ignoredSettings[cleanK] || ignoredSettings[k] {
					continue
				}
				// Also check prefix wildcards in ignore_index_settings
				skipWildcard := false
				for pat := range ignoredSettings {
					if strings.ContainsAny(pat, "*?") && matchSimpleWildcard(pat, cleanK) {
						skipWildcard = true
						break
					}
				}
				if skipWildcard {
					continue
				}
				s.indexCustomSettings[targetIdx][cleanK] = deepCloneIngestValue(v)
			}
		}
	}
	if isMount {
		s.indexCustomSettings[targetIdx]["store.type"] = "snapshot"
	}
	if idxOverrides, okO := reqMap["index_settings"].(map[string]any); okO {
		for k, v := range idxOverrides {
			if subMap, isMap := v.(map[string]any); isMap && k == "index" {
				for sk, sv := range subMap {
					cleanSK := strings.TrimPrefix(sk, "index.")
					s.indexCustomSettings[targetIdx][cleanSK] = deepCloneIngestValue(sv)
				}
			} else {
				cleanK := strings.TrimPrefix(k, "index.")
				s.indexCustomSettings[targetIdx][cleanK] = deepCloneIngestValue(v)
			}
		}
	}
	if !ignoredSettings["default_pipeline"] && !ignoredSettings["index.default_pipeline"] {
		var savedDP string
		switch dpMap := rawSnap["__default_pipelines"].(type) {
		case map[string]string:
			savedDP = dpMap[srcIdx]
		case map[string]any:
			savedDP, _ = dpMap[srcIdx].(string)
		}
		if savedDP != "" {
			if s.indexDefaultPipelines == nil {
				s.indexDefaultPipelines = make(map[string]string)
			}
			s.indexDefaultPipelines[targetIdx] = savedDP
		}
	}
	if !ignoredSettings["final_pipeline"] && !ignoredSettings["index.final_pipeline"] {
		var savedFP string
		switch fpMap := rawSnap["__final_pipelines"].(type) {
		case map[string]string:
			savedFP = fpMap[srcIdx]
		case map[string]any:
			savedFP, _ = fpMap[srcIdx].(string)
		}
		if savedFP != "" {
			if s.indexFinalPipelines == nil {
				s.indexFinalPipelines = make(map[string]string)
			}
			s.indexFinalPipelines[targetIdx] = savedFP
		}
	}
	if dpOver, okDP := s.indexCustomSettings[targetIdx]["default_pipeline"].(string); okDP {
		if s.indexDefaultPipelines == nil {
			s.indexDefaultPipelines = make(map[string]string)
		}
		if dpOver == "" || dpOver == "_none" {
			delete(s.indexDefaultPipelines, targetIdx)
		} else {
			s.indexDefaultPipelines[targetIdx] = dpOver
		}
	}
	if fpOver, okFP := s.indexCustomSettings[targetIdx]["final_pipeline"].(string); okFP {
		if s.indexFinalPipelines == nil {
			s.indexFinalPipelines = make(map[string]string)
		}
		if fpOver == "" || fpOver == "_none" {
			delete(s.indexFinalPipelines, targetIdx)
		} else {
			s.indexFinalPipelines[targetIdx] = fpOver
		}
	}
	s.setFreshIndexCreationDateLocked(targetIdx)

	// 2. Restore aliases when include_aliases != false (default true for _restore, default false for _mount unless include_aliases: true)
	aliasesToPersist := make(map[string][]string)
	includeAliases := !isMount
	if ia, hasIA := reqMap["include_aliases"].(bool); hasIA {
		includeAliases = ia
	}
	if includeAliases {
		if allSavedAliases, okA := rawSnap["__aliases"].(map[string]any); okA {
			if idxAliases, okIA := allSavedAliases[srcIdx].(map[string]any); okIA {
				if s.aliases == nil {
					s.aliases = make(map[string][]string)
				}
				if s.aliasMeta == nil {
					s.aliasMeta = make(map[string]map[string]AliasMetadata)
				}
				for aliasName, rawMeta := range idxAliases {
					alreadyLinked := false
					for _, existingTgt := range s.aliases[aliasName] {
						if existingTgt == targetIdx {
							alreadyLinked = true
							break
						}
					}
					if !alreadyLinked {
						s.aliases[aliasName] = append(s.aliases[aliasName], targetIdx)
					}
					if metaMap, okMM := rawMeta.(map[string]any); okMM && len(metaMap) > 0 {
						var am AliasMetadata
						if fm, okF := metaMap["filter"]; okF && fm != nil {
							var q esast.Query
							if fb, err := json.Marshal(fm); err == nil && json.Unmarshal(fb, &q) == nil {
								am.Filter = &q
							}
						}
						if v, okV := metaMap["index_routing"].(string); okV {
							am.IndexRouting = v
						}
						if v, okV := metaMap["search_routing"].(string); okV {
							am.SearchRouting = v
						}
						if v, okV := metaMap["routing"].(string); okV {
							am.Routing = v
						}
						if v, okV := metaMap["is_write_index"].(bool); okV {
							vb := v
							am.IsWriteIndex = &vb
						}
						if s.aliasMeta[aliasName] == nil {
							s.aliasMeta[aliasName] = make(map[string]AliasMetadata)
						}
						s.aliasMeta[aliasName][targetIdx] = am
					}
					aliasesToPersist[aliasName] = append([]string(nil), s.aliases[aliasName]...)
				}
			}
		}
	}
	if restoredSchema == nil {
		restoredSchema = s.indices[targetIdx]
	}
	s.mu.Unlock()

	if restoredSchema != nil {
		s.persistIndex(ctx, targetIdx, restoredSchema)
	}
	for aName, aTargets := range aliasesToPersist {
		s.persistAlias(ctx, aName, aTargets)
	}

	if restoredSchema == nil {
		return
	}

	// 3. Shred and insert snapshotted documents into targetIdx
	allSavedDocs, okD := rawSnap["__docs"].(map[string]any)
	if !okD {
		return
	}
	rawDocSlice, okS := allSavedDocs[srcIdx].([]any)
	if !okS || len(rawDocSlice) == 0 {
		return
	}

	var buf bytes.Buffer
	type docMetaTrack struct {
		id      string
		ver     int64
		routing string
	}
	var tracked []docMetaTrack
	for _, item := range rawDocSlice {
		rec, okR := item.(map[string]any)
		if !okR {
			continue
		}
		docID, _ := rec["id"].(string)
		if docID == "" {
			continue
		}
		ver, okV := toInt64(rec["version"])
		if !okV || ver <= 0 {
			ver = 1
		}
		srcStr, _ := rec["source"].(string)
		routing, _ := rec["routing"].(string)
		shredded, err := schema.ShredDocument(restoredSchema, docID, ver, false, []byte(srcStr))
		if err != nil {
			continue
		}
		buf.Write(shredded)
		buf.WriteByte('\n')
		tracked = append(tracked, docMetaTrack{id: docID, ver: ver, routing: routing})
	}
	if buf.Len() > 0 {
		_ = s.streamLoad(ctx, restoredSchema.DorisTable, buf.Bytes(), true)
		if s.coalescer != nil {
			_ = s.coalescer.FlushTable(ctx, restoredSchema.DorisTable)
		}
		s.mu.Lock()
		if s.docVersions == nil {
			s.docVersions = make(map[string]map[string]int64)
		}
		if s.docVersions[targetIdx] == nil {
			s.docVersions[targetIdx] = make(map[string]int64)
		}
		if s.docRouting == nil {
			s.docRouting = make(map[string]map[string]string)
		}
		for _, tr := range tracked {
			s.docVersions[targetIdx][tr.id] = tr.ver
			if tr.routing != "" {
				if s.docRouting[targetIdx] == nil {
					s.docRouting[targetIdx] = make(map[string]string)
				}
				s.docRouting[targetIdx][tr.id] = tr.routing
			}
		}
		s.mu.Unlock()
		if s.queryCache != nil {
			s.queryCache.InvalidateAll()
		}
	}
}

// handleSnapshotRepoAnalyzeRound57 implements `POST /_snapshot/{repository}/_analyze` (F5.2).
func (s *Server) handleSnapshotRepoAnalyzeRound57(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.ContentLength != 0 {
		if _, ok := parseJSONBody(w, r); !ok {
			return
		}
	}
	blobCount := 10
	if rawBC := strings.TrimSpace(r.URL.Query().Get("blob_count")); rawBC != "" {
		n, err := strconv.Atoi(rawBC)
		if err != nil || n < 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "invalid [blob_count] value ["+rawBC+"]")
			return
		}
		blobCount = n
	}
	s.mu.RLock()
	_, exists := s.snapshotRepos[repo]
	snapCount := 0
	if exists && s.snapshots != nil && s.snapshots[repo] != nil {
		snapCount = len(s.snapshots[repo])
	}
	s.mu.RUnlock()
	if !exists {
		writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
		return
	}
	if snapCount > blobCount {
		blobCount = snapCount
	}
	totalBytes := int64(blobCount) * 4096
	details := make([]any, 0, blobCount)
	for i := 0; i < blobCount; i++ {
		details = append(details, map[string]any{
			"blob": map[string]any{
				"name": fmt.Sprintf("analyze-blob-%d", i),
				"size": int64(4096),
			},
			"writer_node": map[string]any{
				"id":   "doris-fe-1",
				"name": "doris-fe-1",
			},
			"write_elapsed_nanos":           int64(100000),
			"overwrite_elapsed_nanos":       int64(50000),
			"read_elapsed_nanos":            int64(80000),
			"first_byte_time_to_read_nanos": int64(20000),
			"list_before_delete_nanos":      int64(30000),
			"delete_elapsed_nanos":          int64(40000),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"coordinating_node": map[string]any{
			"id":   "doris-fe-1",
			"name": "doris-fe-1",
		},
		"repository":               repo,
		"Repository":               repo,
		"blob_count":               blobCount,
		"total_blob_size":          fmt.Sprintf("%db", totalBytes),
		"total_blob_size_in_bytes": totalBytes,
		"total_elapsed":            "1ms",
		"total_elapsed_nanos":      int64(1000000),
		"issues_detected":          []any{},
		"details":                  details,
	})
}

// handleSLMExecutePolicyRound57 implements real SLM policy execution with repo check, index filtering,
// full snapshot doc/schema export, metadata stamping, and per-policy stats (F5.3).
func (s *Server) handleSLMExecutePolicyRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	policyID := strings.TrimSpace(r.PathValue("policy_id"))
	s.mu.Lock()
	entry, exists := s.slmPolicies[policyID]
	if !exists || entry == nil {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("missing snapshot lifecycle policy [%s]", policyID))
		return
	}
	pol, _ := entry["policy"].(map[string]any)
	repo, _ := pol["repository"].(string)
	rawName, _ := pol["name"].(string)
	cleanBase := strings.ToLower(strings.NewReplacer("<", "", ">", "", "{", "", "}", "", "/", "-", ":", "-", " ", "-").Replace(rawName))
	if cleanBase == "" {
		cleanBase = strings.ToLower(policyID)
	}
	if s.slmStats == nil {
		s.slmStats = make(map[string]int64)
	}
	if s.slmPolicyStats == nil {
		s.slmPolicyStats = make(map[string]map[string]int64)
	}
	if s.slmPolicyStats[policyID] == nil {
		s.slmPolicyStats[policyID] = make(map[string]int64)
	}

	nowMs := time.Now().UTC().UnixMilli()
	nowISO := time.UnixMilli(nowMs).UTC().Format("2006-01-02T15:04:05.000Z")

	// Validate repository exists
	if _, repoExists := s.snapshotRepos[repo]; !repoExists {
		failSnapName := fmt.Sprintf("%s-failed-%d", cleanBase, nowMs)
		s.slmStats["total_snapshots_failed"]++
		s.slmPolicyStats[policyID]["snapshots_failed"]++
		entry["last_failure"] = map[string]any{
			"snapshot_name": failSnapName,
			"time":          nowMs,
			"time_string":   nowISO,
			"details":       fmt.Sprintf("repository_missing_exception: [%s] missing", repo),
		}
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", repo))
		return
	}

	// Filter indices by policy.config.indices when present
	var indexPatterns []string
	includeGlobalState := true
	if cfgMap, okC := pol["config"].(map[string]any); okC && cfgMap != nil {
		if igs, okIGS := cfgMap["include_global_state"].(bool); okIGS {
			includeGlobalState = igs
		}
		switch iv := cfgMap["indices"].(type) {
		case string:
			for _, p := range strings.Split(iv, ",") {
				if p = strings.TrimSpace(p); p != "" {
					indexPatterns = append(indexPatterns, p)
				}
			}
		case []any:
			for _, item := range iv {
				if p := strings.TrimSpace(fmt.Sprintf("%v", item)); p != "" {
					indexPatterns = append(indexPatterns, p)
				}
			}
		}
	}

	var selectedIndices []string
	joinedPat := strings.Join(indexPatterns, ",")
	for idxName := range s.indices {
		if len(indexPatterns) == 0 || joinedPat == "*" || joinedPat == "_all" {
			selectedIndices = append(selectedIndices, idxName)
		} else if matchMultiWildcardWithExclusions(joinedPat, idxName) {
			selectedIndices = append(selectedIndices, idxName)
		}
	}
	sort.Strings(selectedIndices)

	s.slmStats["total_snapshots_taken"]++
	s.slmPolicyStats[policyID]["snapshots_taken"]++
	snapSeq := s.slmStats["total_snapshots_taken"]
	snapName := fmt.Sprintf("%s-%06d", cleanBase, snapSeq)
	s.mu.Unlock()

	savedSchemas, savedDocs, savedSettings, savedAliases := s.exportSnapshotIndexData(r.Context(), selectedIndices)

	s.mu.Lock()
	if s.snapshots == nil {
		s.snapshots = make(map[string]map[string]map[string]any)
	}
	if s.snapshots[repo] == nil {
		s.snapshots[repo] = make(map[string]map[string]any)
	}
	s.snapshots[repo][snapName] = map[string]any{
		"snapshot":             snapName,
		"uuid":                 snapName,
		"repository":           repo,
		"version_id":           8120099,
		"version":              "8.12.0",
		"indices":              selectedIndices,
		"data_streams":         []any{},
		"include_global_state": includeGlobalState,
		"metadata": map[string]any{
			"policy":   policyID,
			"taken_by": "slm",
		},
		"state":                "SUCCESS",
		"start_time":           nowISO,
		"start_time_in_millis": nowMs,
		"end_time":             nowISO,
		"end_time_in_millis":   nowMs,
		"duration_in_millis":   int64(1),
		"failures":             []any{},
		"shards":               map[string]any{"total": len(selectedIndices), "failed": 0, "successful": len(selectedIndices)},
		"__schemas":            savedSchemas,
		"__docs":               savedDocs,
		"__settings":           savedSettings,
		"__aliases":            savedAliases,
	}
	if curEntry := s.slmPolicies[policyID]; curEntry != nil {
		curEntry["last_success"] = map[string]any{
			"snapshot_name": snapName,
			"time":          nowMs,
			"time_string":   nowISO,
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_name": snapName})
}

// handleSLMActionRound57 implements `_execute_retention` pruning & `stats` with `policy_stats` (F5.3).
func (s *Server) handleSLMActionRound57(w http.ResponseWriter, r *http.Request, action string) bool {
	switch action {
	case "_execute_retention":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		nowMs := time.Now().UTC().UnixMilli()
		s.mu.Lock()
		if s.slmStats == nil {
			s.slmStats = make(map[string]int64)
		}
		if s.slmPolicyStats == nil {
			s.slmPolicyStats = make(map[string]map[string]int64)
		}
		s.slmStats["retention_runs"]++

		for policyID, entry := range s.slmPolicies {
			if entry == nil {
				continue
			}
			pol, _ := entry["policy"].(map[string]any)
			if pol == nil {
				continue
			}
			retMap, _ := pol["retention"].(map[string]any)
			if len(retMap) == 0 {
				continue
			}
			repo, _ := pol["repository"].(string)
			repoSnaps := s.snapshots[repo]
			if len(repoSnaps) == 0 {
				continue
			}

			var maxCount int64 = -1
			if mc, okMC := toInt64(retMap["max_count"]); okMC && mc >= 0 {
				maxCount = mc
			}
			var minCount int64 = 0
			if mnc, okMNC := toInt64(retMap["min_count"]); okMNC && mnc >= 0 {
				minCount = mnc
			}
			var expireAfterMs int64 = -1
			if eaStr, okEA := retMap["expire_after"].(string); okEA && strings.TrimSpace(eaStr) != "" {
				if durMs, valid := parsePositiveESDurationMillis(eaStr); valid {
					expireAfterMs = durMs
				} else if strings.TrimSpace(eaStr) == "0s" || strings.TrimSpace(eaStr) == "0ms" {
					expireAfterMs = 0
				}
			}

			type polSnap struct {
				name    string
				startMs int64
			}
			var candidates []polSnap
			for snapName, snapObj := range repoSnaps {
				if snapObj == nil {
					continue
				}
				meta, _ := snapObj["metadata"].(map[string]any)
				if meta == nil || fmt.Sprintf("%v", meta["policy"]) != policyID {
					continue
				}
				stMs, _ := toInt64(snapObj["start_time_in_millis"])
				candidates = append(candidates, polSnap{name: snapName, startMs: stMs})
			}
			// Sort oldest first (by startMs, then name)
			sort.Slice(candidates, func(i, j int) bool {
				if candidates[i].startMs != candidates[j].startMs {
					return candidates[i].startMs < candidates[j].startMs
				}
				return candidates[i].name < candidates[j].name
			})

			remaining := int64(len(candidates))
			if s.slmPolicyStats[policyID] == nil {
				s.slmPolicyStats[policyID] = make(map[string]int64)
			}
			for _, cand := range candidates {
				if remaining <= minCount {
					break
				}
				shouldDelete := false
				if maxCount >= 0 && remaining > maxCount {
					shouldDelete = true
				}
				if !shouldDelete && expireAfterMs >= 0 && (nowMs-cand.startMs) >= expireAfterMs {
					shouldDelete = true
				}
				if shouldDelete {
					delete(repoSnaps, cand.name)
					remaining--
					s.slmStats["total_snapshots_deleted"]++
					s.slmPolicyStats[policyID]["snapshots_deleted"]++
				}
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return true

	case "stats":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return true
		}
		s.mu.RLock()
		retRuns := s.slmStats["retention_runs"]
		snapsTaken := s.slmStats["total_snapshots_taken"]
		snapsFailed := s.slmStats["total_snapshots_failed"]
		snapsDeleted := s.slmStats["total_snapshots_deleted"]
		polIDs := make([]string, 0, len(s.slmPolicies))
		seenPol := make(map[string]bool)
		for pid := range s.slmPolicies {
			polIDs = append(polIDs, pid)
			seenPol[pid] = true
		}
		for pid := range s.slmPolicyStats {
			if !seenPol[pid] {
				polIDs = append(polIDs, pid)
			}
		}
		sort.Strings(polIDs)
		policyStats := make([]any, 0, len(polIDs))
		for _, pid := range polIDs {
			ps := s.slmPolicyStats[pid]
			policyStats = append(policyStats, map[string]any{
				"policy":                     pid,
				"snapshots_taken":            ps["snapshots_taken"],
				"snapshots_failed":           ps["snapshots_failed"],
				"snapshots_deleted":          ps["snapshots_deleted"],
				"snapshot_deletion_failures": ps["snapshot_deletion_failures"],
			})
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"retention_runs":                   retRuns,
			"retention_failed":                 int64(0),
			"retention_timed_out":              int64(0),
			"retention_deletion_time":          "0s",
			"retention_deletion_time_millis":   int64(0),
			"total_snapshots_taken":            snapsTaken,
			"total_snapshots_failed":           snapsFailed,
			"total_snapshots_deleted":          snapsDeleted,
			"total_snapshot_deletion_failures": int64(0),
			"policy_stats":                     policyStats,
		})
		return true
	}
	return false
}

// ============================================================================
// Round 57 F6: Synonyms Analyzer Integration & Inference Streaming / Tasks
// ============================================================================

// validateSynonymRuleString validates Solr/ES synonym rule syntax.
func validateSynonymRuleString(synStr string) error {
	trimmed := strings.TrimSpace(synStr)
	if trimmed == "" {
		return fmt.Errorf("synonym rule [synonyms] cannot be empty")
	}
	if strings.Contains(trimmed, "=>") {
		parts := strings.Split(trimmed, "=>")
		if len(parts) != 2 {
			return fmt.Errorf("invalid synonym rule [%s]: more than one explicit mapping (=>) specified", synStr)
		}
		lhsRaw := strings.Split(parts[0], ",")
		rhsRaw := strings.Split(parts[1], ",")
		lhsCount := 0
		for _, item := range lhsRaw {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("invalid synonym rule [%s]: empty left-hand term in explicit mapping", synStr)
			}
			lhsCount++
		}
		rhsCount := 0
		for _, item := range rhsRaw {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("invalid synonym rule [%s]: empty right-hand term in explicit mapping", synStr)
			}
			rhsCount++
		}
		if lhsCount == 0 || rhsCount == 0 {
			return fmt.Errorf("invalid synonym rule [%s]: explicit mapping requires non-empty left and right sides", synStr)
		}
		return nil
	}
	terms := strings.Split(trimmed, ",")
	if len(terms) < 2 {
		return fmt.Errorf("invalid synonym rule [%s]: equivalent synonyms require at least 2 comma-separated terms", synStr)
	}
	for _, item := range terms {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("invalid synonym rule [%s]: empty term in synonym list", synStr)
		}
	}
	return nil
}

// extractIndexAnalysisMaps extracts normalized filter and analyzer definition maps from index custom settings.
func extractIndexAnalysisMaps(custom map[string]any) (analyzers map[string]map[string]any, filters map[string]map[string]any) {
	analyzers = make(map[string]map[string]any)
	filters = make(map[string]map[string]any)
	if len(custom) == 0 {
		return analyzers, filters
	}

	// Support both nested {"analysis": {"analyzer": ..., "filter": ...}} and flat dotted keys
	// like "analysis.filter.my_syn.synonyms_set" or "index.analysis.analyzer.my_an.filter".
	if rawAnObj, ok := custom["analysis"].(map[string]any); ok {
		if anMap, okA := rawAnObj["analyzer"].(map[string]any); okA {
			for k, v := range anMap {
				if vm, okM := v.(map[string]any); okM {
					analyzers[k] = deepCloneDocMap(vm)
				}
			}
		}
		if flMap, okF := rawAnObj["filter"].(map[string]any); okF {
			for k, v := range flMap {
				if vm, okM := v.(map[string]any); okM {
					filters[k] = deepCloneDocMap(vm)
				}
			}
		}
	}
	if rawIdxObj, ok := custom["index"].(map[string]any); ok {
		if rawAnObj, ok2 := rawIdxObj["analysis"].(map[string]any); ok2 {
			if anMap, okA := rawAnObj["analyzer"].(map[string]any); okA {
				for k, v := range anMap {
					if vm, okM := v.(map[string]any); okM {
						analyzers[k] = deepCloneDocMap(vm)
					}
				}
			}
			if flMap, okF := rawAnObj["filter"].(map[string]any); okF {
				for k, v := range flMap {
					if vm, okM := v.(map[string]any); okM {
						filters[k] = deepCloneDocMap(vm)
					}
				}
			}
		}
	}

	for rawKey, val := range custom {
		clean := strings.TrimPrefix(rawKey, "index.")
		if strings.HasPrefix(clean, "analysis.analyzer.") {
			rest := strings.TrimPrefix(clean, "analysis.analyzer.")
			dot := strings.IndexByte(rest, '.')
			if dot > 0 {
				name, prop := rest[:dot], rest[dot+1:]
				if analyzers[name] == nil {
					analyzers[name] = make(map[string]any)
				}
				analyzers[name][prop] = val
			} else if vm, okM := val.(map[string]any); okM {
				analyzers[rest] = deepCloneDocMap(vm)
			}
		} else if strings.HasPrefix(clean, "analysis.filter.") {
			rest := strings.TrimPrefix(clean, "analysis.filter.")
			dot := strings.IndexByte(rest, '.')
			if dot > 0 {
				name, prop := rest[:dot], rest[dot+1:]
				if filters[name] == nil {
					filters[name] = make(map[string]any)
				}
				filters[name][prop] = val
			} else if vm, okM := val.(map[string]any); okM {
				filters[rest] = deepCloneDocMap(vm)
			}
		}
	}
	return analyzers, filters
}

func normalizeCustomSettingValue(v any) any {
	switch tv := v.(type) {
	case []string:
		return append([]string(nil), tv...)
	case []any:
		out := make([]string, 0, len(tv))
		for _, elem := range tv {
			out = append(out, fmt.Sprintf("%v", elem))
		}
		return out
	default:
		return fmt.Sprintf("%v", v)
	}
}

func extractStringSliceAny(v any) []string {
	switch tv := v.(type) {
	case string:
		trimmed := strings.TrimSpace(tv)
		if trimmed == "" {
			return nil
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if inner == "" {
				return nil
			}
			if strings.Contains(inner, ",") {
				var out []string
				for _, p := range strings.Split(inner, ",") {
					if p = strings.Trim(strings.TrimSpace(p), `"'`); p != "" {
						out = append(out, p)
					}
				}
				return out
			}
			return strings.Fields(inner)
		}
		return []string{trimmed}
	case []string:
		return append([]string(nil), tv...)
	case []any:
		out := make([]string, 0, len(tv))
		for _, it := range tv {
			if s := strings.TrimSpace(fmt.Sprintf("%v", it)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// findIndicesUsingSynonymSetLocked finds existing indices whose custom filters/analyzers reference setID.
// Caller MUST hold s.mu.RLock() or s.mu.Lock().
func (s *Server) findIndicesUsingSynonymSetLocked(setID string) []map[string]any {
	if setID == "" {
		return nil
	}
	var idxNames []string
	for idxName := range s.indices {
		idxNames = append(idxNames, idxName)
	}
	sort.Strings(idxNames)

	var details []map[string]any
	for _, idxName := range idxNames {
		analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
		matchingFilters := make(map[string]bool)
		for fName, fDef := range filters {
			if fmt.Sprintf("%v", fDef["synonyms_set"]) == setID {
				matchingFilters[fName] = true
			}
		}
		if len(matchingFilters) == 0 {
			continue
		}
		var reloadedAnalyzers []string
		for aName, aDef := range analyzers {
			for _, fRef := range extractStringSliceAny(aDef["filter"]) {
				if matchingFilters[fRef] {
					reloadedAnalyzers = append(reloadedAnalyzers, aName)
					break
				}
			}
		}
		if len(reloadedAnalyzers) == 0 {
			for fName := range matchingFilters {
				reloadedAnalyzers = append(reloadedAnalyzers, fName)
			}
		}
		sort.Strings(reloadedAnalyzers)
		details = append(details, map[string]any{
			"index":              idxName,
			"reloaded_analyzers": reloadedAnalyzers,
			"reloaded_node_ids":  []string{"doris-fe-1"},
		})
	}
	return details
}

func (s *Server) buildSynonymReloadPayloadLocked(setID string) map[string]any {
	matched := s.findIndicesUsingSynonymSetLocked(setID)
	totalShards := len(matched)
	if totalShards == 0 {
		totalShards = 1
	}
	reloadDetails := make([]any, 0, len(matched))
	for _, m := range matched {
		reloadDetails = append(reloadDetails, m)
	}
	return map[string]any{
		"_shards": map[string]any{
			"total":      totalShards,
			"successful": totalShards,
			"failed":     0,
		},
		"reload_details": reloadDetails,
	}
}

func (s *Server) buildIndexReloadAnalyzersDetailsLocked(targets []string) []any {
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	reloadDetails := make([]any, 0, len(sorted))
	for _, idxName := range sorted {
		analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
		updateableFilters := make(map[string]bool)
		for fName, fDef := range filters {
			fType := fmt.Sprintf("%v", fDef["type"])
			upd, _ := fDef["updateable"].(bool)
			if upd || fmt.Sprintf("%v", fDef["updateable"]) == "true" || fDef["synonyms_set"] != nil || fType == "synonym" || fType == "synonym_graph" {
				updateableFilters[fName] = true
			}
		}
		var reloaded []string
		for aName, aDef := range analyzers {
			for _, fRef := range extractStringSliceAny(aDef["filter"]) {
				if updateableFilters[fRef] {
					reloaded = append(reloaded, aName)
					break
				}
			}
		}
		sort.Strings(reloaded)
		if reloaded == nil {
			reloaded = []string{}
		}
		reloadDetails = append(reloadDetails, map[string]any{
			"index":              idxName,
			"reloaded_analyzers": reloaded,
			"reloaded_node_ids":  []string{"doris-fe-1"},
		})
	}
	return reloadDetails
}

type parsedSynonymRule struct {
	explicit bool
	lhs      []string // lowercased single/multi-word phrases
	rhs      []string // lowercased phrases
	equiv    []string // lowercased equivalent terms/phrases
}

func parseSynonymRuleStrings(ruleStrs []string) []parsedSynonymRule {
	var out []parsedSynonymRule
	for _, raw := range ruleStrs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "=>") {
			parts := strings.SplitN(trimmed, "=>", 2)
			var lhs, rhs []string
			for _, p := range strings.Split(parts[0], ",") {
				if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
					lhs = append(lhs, p)
				}
			}
			for _, p := range strings.Split(parts[1], ",") {
				if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
					rhs = append(rhs, p)
				}
			}
			if len(lhs) > 0 && len(rhs) > 0 {
				out = append(out, parsedSynonymRule{explicit: true, lhs: lhs, rhs: rhs})
			}
		} else {
			var eq []string
			for _, p := range strings.Split(trimmed, ",") {
				if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
					eq = append(eq, p)
				}
			}
			if len(eq) >= 2 {
				out = append(out, parsedSynonymRule{explicit: false, equiv: eq})
			}
		}
	}
	return out
}

func (s *Server) collectSynonymRulesFromFilterDefLocked(fDef map[string]any) []parsedSynonymRule {
	var rawRules []string
	if setID, okS := fDef["synonyms_set"].(string); okS && strings.TrimSpace(setID) != "" {
		for _, rm := range s.synonymSets[strings.TrimSpace(setID)] {
			if syn, ok := rm["synonyms"].(string); ok {
				rawRules = append(rawRules, syn)
			}
		}
	}
	rawRules = append(rawRules, extractStringSliceAny(fDef["synonyms"])...)
	return parseSynonymRuleStrings(rawRules)
}

type analyzedToken struct {
	token       string
	startOffset int
	endOffset   int
	tokenType   string
	position    int
}

func applySynonymFilterToTokens(tokens []analyzedToken, rules []parsedSynonymRule) []analyzedToken {
	if len(tokens) == 0 || len(rules) == 0 {
		return tokens
	}
	out := make([]analyzedToken, 0, len(tokens)*2)
	for _, tok := range tokens {
		tl := strings.ToLower(tok.token)
		matchedExplicit := false
		var explicitReplacements []string
		var equivAdditions []string
		seen := map[string]bool{tl: true}

		for _, r := range rules {
			if r.explicit {
				for _, l := range r.lhs {
					if l == tl {
						matchedExplicit = true
						for _, rhs := range r.rhs {
							if !seen[rhs] || rhs != tl {
								explicitReplacements = append(explicitReplacements, rhs)
							}
						}
					}
				}
			} else {
				inGroup := false
				for _, eq := range r.equiv {
					if eq == tl {
						inGroup = true
						break
					}
				}
				if inGroup {
					for _, eq := range r.equiv {
						if !seen[eq] {
							seen[eq] = true
							equivAdditions = append(equivAdditions, eq)
						}
					}
				}
			}
		}

		if matchedExplicit {
			dedup := make(map[string]bool)
			for _, rep := range explicitReplacements {
				if dedup[rep] {
					continue
				}
				dedup[rep] = true
				out = append(out, analyzedToken{
					token:       rep,
					startOffset: tok.startOffset,
					endOffset:   tok.endOffset,
					tokenType:   "SYNONYM",
					position:    tok.position,
				})
			}
		} else {
			out = append(out, tok)
			for _, syn := range equivAdditions {
				out = append(out, analyzedToken{
					token:       syn,
					startOffset: tok.startOffset,
					endOffset:   tok.endOffset,
					tokenType:   "SYNONYM",
					position:    tok.position,
				})
			}
		}
	}
	return out
}

// tryHandleCustomIndexAnalyze evaluates custom index analyzers & synonym/synonym_graph filters in /{index}/_analyze (F6.1).
func (s *Server) tryHandleCustomIndexAnalyze(w http.ResponseWriter, r *http.Request, bodyBytes []byte) bool {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var req map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			return false // let standard handler emit parse_exception
		}
	}

	// Check inline filter objects for synonym / synonym_graph even without an index
	hasInlineSynFilter := false
	if rawFilters, okF := req["filter"].([]any); okF {
		for _, rf := range rawFilters {
			if fm, okM := rf.(map[string]any); okM {
				ft := strings.ToLower(fmt.Sprintf("%v", fm["type"]))
				if ft == "synonym" || ft == "synonym_graph" {
					hasInlineSynFilter = true
					break
				}
			}
		}
	}

	if rawIndex == "" && !hasInlineSynFilter {
		return false
	}

	var analyzers, filters map[string]map[string]any
	var idxSchema *schema.IndexSchema
	s.mu.RLock()
	if rawIndex != "" {
		resolvedIdx := rawIndex
		if s.indices[resolvedIdx] == nil {
			if tgts := s.aliases[resolvedIdx]; len(tgts) > 0 {
				resolvedIdx = tgts[0]
			}
		}
		idxSchema = s.indices[resolvedIdx]
		if idxSchema == nil {
			s.mu.RUnlock()
			return false // let standard handleAnalyze return 404 index_not_found_exception
		}
		analyzers, filters = extractIndexAnalysisMaps(s.indexCustomSettings[resolvedIdx])
	}

	analyzerName, _ := req["analyzer"].(string)
	if analyzerName == "" {
		analyzerName = strings.TrimSpace(r.URL.Query().Get("analyzer"))
	}
	fieldName, _ := req["field"].(string)
	if fieldName == "" && analyzerName == "" && idxSchema != nil && idxSchema.RawMapping != nil {
		fieldName = strings.TrimSpace(r.URL.Query().Get("field"))
	}
	if analyzerName == "" && fieldName != "" && idxSchema != nil && idxSchema.RawMapping != nil {
		analyzerName = lookupFieldSearchAnalyzerFromMappingSpec(idxSchema.RawMapping, fieldName)
	}

	customAnDef := analyzers[analyzerName]
	var reqFilterList []any
	if rf, okF := req["filter"].([]any); okF {
		reqFilterList = rf
	}
	usesCustomFilter := hasInlineSynFilter
	if !usesCustomFilter {
		for _, rf := range reqFilterList {
			if fn, okS := rf.(string); okS && filters[fn] != nil {
				usesCustomFilter = true
				break
			}
		}
	}
	if customAnDef == nil && !usesCustomFilter {
		s.mu.RUnlock()
		return false
	}

	// Extract input text(s)
	var texts []string
	switch tv := req["text"].(type) {
	case string:
		texts = []string{tv}
	case []any:
		for _, item := range tv {
			if str, ok := item.(string); ok {
				texts = append(texts, str)
			}
		}
	}
	if len(texts) == 0 {
		if qt := r.URL.Query().Get("text"); qt != "" {
			texts = []string{qt}
		}
	}
	if len(texts) == 0 {
		s.mu.RUnlock()
		return false
	}

	tokName := "standard"
	var filterSteps []any
	if customAnDef != nil {
		if tn, okT := customAnDef["tokenizer"].(string); okT && tn != "" {
			tokName = tn
		}
		for _, fn := range extractStringSliceAny(customAnDef["filter"]) {
			filterSteps = append(filterSteps, fn)
		}
	} else {
		if tn, okT := req["tokenizer"].(string); okT && tn != "" {
			tokName = tn
		}
		filterSteps = reqFilterList
	}

	// Tokenize input texts
	var toks []analyzedToken
	pos := 0
	baseOffset := 0
	for tIdx, text := range texts {
		if tIdx > 0 {
			baseOffset++
		}
		switch strings.ToLower(tokName) {
		case "keyword", "noop":
			toks = append(toks, analyzedToken{
				token:       text,
				startOffset: baseOffset,
				endOffset:   baseOffset + len(text),
				tokenType:   "word",
				position:    pos,
			})
			pos++
		case "whitespace":
			idx := 0
			for idx < len(text) {
				for idx < len(text) && unicode.IsSpace(rune(text[idx])) {
					idx++
				}
				if idx >= len(text) {
					break
				}
				start := idx
				for idx < len(text) && !unicode.IsSpace(rune(text[idx])) {
					idx++
				}
				toks = append(toks, analyzedToken{
					token:       text[start:idx],
					startOffset: baseOffset + start,
					endOffset:   baseOffset + idx,
					tokenType:   "word",
					position:    pos,
				})
				pos++
			}
		default: // standard / letter
			idx := 0
			for idx < len(text) {
				rn, sz := utf8.DecodeRuneInString(text[idx:])
				if !unicode.IsLetter(rn) && !unicode.IsDigit(rn) {
					idx += sz
					continue
				}
				start := idx
				for idx < len(text) {
					r2, s2 := utf8.DecodeRuneInString(text[idx:])
					if !unicode.IsLetter(r2) && !unicode.IsDigit(r2) {
						break
					}
					idx += s2
				}
				toks = append(toks, analyzedToken{
					token:       text[start:idx],
					startOffset: baseOffset + start,
					endOffset:   baseOffset + idx,
					tokenType:   "<ALPHANUM>",
					position:    pos,
				})
				pos++
			}
		}
		baseOffset += len(text)
	}

	// Apply filters sequentially while holding RLock so synonymSets read is consistent
	for _, step := range filterSteps {
		var fType string
		var fDef map[string]any
		switch sv := step.(type) {
		case string:
			if def, okD := filters[sv]; okD {
				fDef = def
				fType = strings.ToLower(fmt.Sprintf("%v", def["type"]))
			} else {
				fType = strings.ToLower(sv)
			}
		case map[string]any:
			fDef = sv
			fType = strings.ToLower(fmt.Sprintf("%v", sv["type"]))
		}
		switch fType {
		case "lowercase":
			for i := range toks {
				toks[i].token = strings.ToLower(toks[i].token)
			}
		case "uppercase":
			for i := range toks {
				toks[i].token = strings.ToUpper(toks[i].token)
			}
		case "trim":
			for i := range toks {
				toks[i].token = strings.TrimSpace(toks[i].token)
			}
		case "stop":
			stopSet := map[string]bool{"a": true, "an": true, "and": true, "are": true, "as": true, "at": true, "be": true, "but": true, "by": true, "for": true, "if": true, "in": true, "into": true, "is": true, "it": true, "no": true, "not": true, "of": true, "on": true, "or": true, "such": true, "that": true, "the": true, "their": true, "then": true, "there": true, "these": true, "they": true, "this": true, "to": true, "was": true, "will": true, "with": true}
			if fDef != nil {
				customStops := extractStringSliceAny(fDef["stopwords"])
				if len(customStops) > 0 {
					stopSet = make(map[string]bool, len(customStops))
					for _, sw := range customStops {
						stopSet[strings.ToLower(sw)] = true
					}
				}
			}
			filtered := make([]analyzedToken, 0, len(toks))
			for _, tk := range toks {
				if !stopSet[strings.ToLower(tk.token)] {
					filtered = append(filtered, tk)
				}
			}
			toks = filtered
		case "synonym", "synonym_graph":
			if fDef != nil {
				rules := s.collectSynonymRulesFromFilterDefLocked(fDef)
				toks = applySynonymFilterToTokens(toks, rules)
			}
		}
	}
	s.mu.RUnlock()

	respTokens := make([]any, 0, len(toks))
	for _, tk := range toks {
		respTokens = append(respTokens, map[string]any{
			"token":        tk.token,
			"start_offset": tk.startOffset,
			"end_offset":   tk.endOffset,
			"type":         tk.tokenType,
			"position":     tk.position,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": respTokens})
	return true
}

func lookupFieldSearchAnalyzerFromMappingSpec(ms *esast.MappingSpec, fieldPath string) string {
	if ms == nil || fieldPath == "" {
		return ""
	}
	parts := strings.Split(fieldPath, ".")
	curProps := ms.Properties
	for i, part := range parts {
		if curProps == nil {
			return ""
		}
		fp, ok := curProps[part]
		if !ok {
			return ""
		}
		if i == len(parts)-1 {
			if fp.SearchAnalyzer != "" {
				return fp.SearchAnalyzer
			}
			return fp.Analyzer
		}
		if fp.Properties != nil {
			curProps = fp.Properties
		} else {
			curProps = fp.Fields
		}
	}
	return ""
}

// collectIndexSynonymRulesForFieldLocked collects active synonym rules for a field (or index default search analyzer).
func (s *Server) collectIndexSynonymRulesForFieldLocked(idxName, fieldName string, explicitAnalyzer string) []parsedSynonymRule {
	analyzers, filters := extractIndexAnalysisMaps(s.indexCustomSettings[idxName])
	if len(filters) == 0 {
		return nil
	}
	targetAnalyzer := explicitAnalyzer
	if targetAnalyzer == "" {
		if sch := s.indices[idxName]; sch != nil && sch.RawMapping != nil && fieldName != "" {
			targetAnalyzer = lookupFieldSearchAnalyzerFromMappingSpec(sch.RawMapping, fieldName)
		}
	}
	if targetAnalyzer == "" {
		if defSearch, okDS := s.indexCustomSettings[idxName]["analysis.analyzer.default_search.type"].(string); okDS && defSearch != "" {
			targetAnalyzer = "default_search"
		} else if analyzers["default_search"] != nil {
			targetAnalyzer = "default_search"
		} else if analyzers["default"] != nil {
			targetAnalyzer = "default"
		}
	}

	var rules []parsedSynonymRule
	if targetAnalyzer != "" && analyzers[targetAnalyzer] != nil {
		for _, fName := range extractStringSliceAny(analyzers[targetAnalyzer]["filter"]) {
			if fDef := filters[fName]; fDef != nil {
				ft := strings.ToLower(fmt.Sprintf("%v", fDef["type"]))
				if ft == "synonym" || ft == "synonym_graph" || fDef["synonyms_set"] != nil || fDef["synonyms"] != nil {
					rules = append(rules, s.collectSynonymRulesFromFilterDefLocked(fDef)...)
				}
			}
		}
	}
	return rules
}

func expandQueryTermsWithSynonyms(queryText string, rules []parsedSynonymRule) []string {
	if len(rules) == 0 || strings.TrimSpace(queryText) == "" {
		return nil
	}
	words := strings.Fields(strings.ToLower(queryText))
	if len(words) == 0 {
		return nil
	}
	var initToks []analyzedToken
	for i, w := range words {
		clean := strings.Trim(w, ".,!?;:\"'()[]{}")
		if clean == "" {
			continue
		}
		initToks = append(initToks, analyzedToken{token: clean, position: i})
	}
	expanded := applySynonymFilterToTokens(initToks, rules)
	seen := make(map[string]bool)
	var terms []string
	for _, tk := range expanded {
		if !seen[tk.token] {
			seen[tk.token] = true
			terms = append(terms, tk.token)
		}
	}
	if len(terms) <= 1 && (len(terms) == 0 || terms[0] == strings.ToLower(strings.TrimSpace(queryText))) {
		return nil
	}
	return terms
}

// resolveTextEmbeddingFromEndpoint resolves model_id against s.inferenceEndpoints / built-in models.
func (s *Server) resolveTextEmbeddingFromEndpointLocked(modelID, modelText string) ([]float64, int, string, string) {
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return nil, http.StatusBadRequest, "illegal_argument_exception", "[query_vector_builder.text_embedding.model_id] is required"
	}
	if ep, exists := s.inferenceEndpoints[modelID]; exists && ep != nil {
		epTask, _ := ep["task_type"].(string)
		if epTask != "" && epTask != "text_embedding" {
			return nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Inference endpoint [%s] is for task [%s], expected [text_embedding]", modelID, epTask)
		}
		return computeDeterministicEmbedding(modelText), 0, "", ""
	}
	if realModelID, okAlias := s.mlModelAliases[modelID]; okAlias && s.mlTrainedModels[realModelID] != nil {
		return computeDeterministicEmbedding(modelText), 0, "", ""
	}
	if s.mlTrainedModels[modelID] != nil || strings.HasPrefix(modelID, ".") {
		return computeDeterministicEmbedding(modelText), 0, "", ""
	}
	return nil, http.StatusBadRequest, "illegal_argument_exception",
		fmt.Sprintf("Inference endpoint or trained model [%s] not found", modelID)
}

func (s *Server) resolveSparseEmbeddingFromEndpointLocked(infID, queryText string) (map[string]float64, int, string, string) {
	infID = strings.TrimSpace(infID)
	if infID == "" {
		return nil, http.StatusBadRequest, "illegal_argument_exception", "[sparse_vector.inference_id] is required"
	}
	if ep, exists := s.inferenceEndpoints[infID]; exists && ep != nil {
		epTask, _ := ep["task_type"].(string)
		if epTask != "" && epTask != "sparse_embedding" {
			return nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Inference endpoint [%s] is for task [%s], expected [sparse_embedding]", infID, epTask)
		}
		return computeDeterministicSparseEmbedding(queryText), 0, "", ""
	}
	if realModelID, okAlias := s.mlModelAliases[infID]; okAlias && s.mlTrainedModels[realModelID] != nil {
		return computeDeterministicSparseEmbedding(queryText), 0, "", ""
	}
	if s.mlTrainedModels[infID] != nil || strings.HasPrefix(infID, ".") {
		return computeDeterministicSparseEmbedding(queryText), 0, "", ""
	}
	return nil, http.StatusBadRequest, "illegal_argument_exception",
		fmt.Sprintf("Inference endpoint [%s] not found", infID)
}

// preprocessSearchBodyRound57 pre-rewrites search JSON bodies when needed for:
// 1) knn query_vector_builder.text_embedding -> query_vector via _inference
// 2) sparse_vector inference_id + query -> query_vector via _inference
// 3) match / multi_match synonym expansion when target index uses custom synonym search analyzers
// Returns (possiblyUpdatedBodyBytes, true) on success, or writes an ES error and returns (nil, false).
func (s *Server) preprocessSearchBodyRound57(w http.ResponseWriter, rawIndex string, bodyBytes []byte) ([]byte, bool) {
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return bodyBytes, true
	}
	needsInferenceRewrite := bytes.Contains(bodyBytes, []byte("query_vector_builder")) ||
		(bytes.Contains(bodyBytes, []byte("sparse_vector")) && (bytes.Contains(bodyBytes, []byte("inference_id")) || bytes.Contains(bodyBytes, []byte("model_id"))))

	hasActiveSynonyms := false
	var targetIndices []string
	s.mu.RLock()
	if rawIndex != "" && rawIndex != "*" && rawIndex != "_all" {
		for _, part := range strings.Split(rawIndex, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if s.indices[part] != nil {
				targetIndices = append(targetIndices, part)
			} else if tgts := s.aliases[part]; len(tgts) > 0 {
				targetIndices = append(targetIndices, tgts...)
			}
		}
	} else {
		for idxName := range s.indices {
			targetIndices = append(targetIndices, idxName)
		}
	}
	for _, idxName := range targetIndices {
		if cs := s.indexCustomSettings[idxName]; len(cs) > 0 {
			_, fls := extractIndexAnalysisMaps(cs)
			for _, fd := range fls {
				ft := strings.ToLower(fmt.Sprintf("%v", fd["type"]))
				if ft == "synonym" || ft == "synonym_graph" || fd["synonyms_set"] != nil || fd["synonyms"] != nil {
					hasActiveSynonyms = true
					break
				}
			}
		}
		if hasActiveSynonyms {
			break
		}
	}
	s.mu.RUnlock()

	if !needsInferenceRewrite && !hasActiveSynonyms {
		return bodyBytes, true
	}

	var doc map[string]any
	if err := json.Unmarshal(bodyBytes, &doc); err != nil || doc == nil {
		return bodyBytes, true // let standard parser handle syntax errors
	}

	mutated := false
	var errCode int
	var errType, errMsg string

	s.mu.RLock()
	var walkValue func(v any) any
	rewriteKNNMap := func(km map[string]any) {
		qvb, hasQVB := km["query_vector_builder"].(map[string]any)
		if !hasQVB || qvb == nil {
			return
		}
		te, hasTE := qvb["text_embedding"].(map[string]any)
		if !hasTE || te == nil {
			errCode = http.StatusBadRequest
			errType = "parsing_exception"
			errMsg = "[query_vector_builder] requires [text_embedding] configuration"
			return
		}
		modelID, _ := te["model_id"].(string)
		modelText, _ := te["model_text"].(string)
		vec, c, t, m := s.resolveTextEmbeddingFromEndpointLocked(modelID, modelText)
		if c != 0 {
			errCode, errType, errMsg = c, t, m
			return
		}
		vecAny := make([]any, len(vec))
		for i, fv := range vec {
			vecAny[i] = fv
		}
		km["query_vector"] = vecAny
		delete(km, "query_vector_builder")
		mutated = true
	}

	walkValue = func(v any) any {
		if errCode != 0 {
			return v
		}
		switch tv := v.(type) {
		case map[string]any:
			if knnRaw, hasK := tv["knn"]; hasK {
				switch kv := knnRaw.(type) {
				case map[string]any:
					if _, hasField := kv["field"]; hasField || kv["query_vector_builder"] != nil {
						rewriteKNNMap(kv)
					} else {
						for _, fieldSub := range kv {
							if fsm, okM := fieldSub.(map[string]any); okM {
								rewriteKNNMap(fsm)
							}
						}
					}
				case []any:
					for _, item := range kv {
						if km, okM := item.(map[string]any); okM {
							rewriteKNNMap(km)
						}
					}
				}
			}
			if svMap, hasSV := tv["sparse_vector"].(map[string]any); hasSV && svMap != nil {
				infID, _ := svMap["inference_id"].(string)
				if infID == "" {
					infID, _ = svMap["model_id"].(string)
				}
				if infID != "" && svMap["query_vector"] == nil {
					qText, _ := svMap["query"].(string)
					if qText == "" {
						qText, _ = svMap["model_text"].(string)
					}
					sVec, c, t, m := s.resolveSparseEmbeddingFromEndpointLocked(infID, qText)
					if c != 0 {
						errCode, errType, errMsg = c, t, m
						return tv
					}
					qvMap := make(map[string]any, len(sVec))
					for k, wVal := range sVec {
						qvMap[k] = wVal
					}
					svMap["query_vector"] = qvMap
					delete(svMap, "inference_id")
					delete(svMap, "model_id")
					delete(svMap, "query")
					delete(svMap, "model_text")
					mutated = true
				}
			}

			// Synonym expansion for match / multi_match queries
			if hasActiveSynonyms && len(tv) == 1 {
				if matchBody, isMatch := tv["match"].(map[string]any); isMatch && len(matchBody) == 1 {
					for fieldName, rawSpec := range matchBody {
						var qText, explicitAn string
						switch sp := rawSpec.(type) {
						case string:
							qText = sp
						case map[string]any:
							qText, _ = sp["query"].(string)
							explicitAn, _ = sp["analyzer"].(string)
						}
						if qText != "" {
							var rules []parsedSynonymRule
							for _, idxName := range targetIndices {
								rules = append(rules, s.collectIndexSynonymRulesForFieldLocked(idxName, fieldName, explicitAn)...)
							}
							if synTerms := expandQueryTermsWithSynonyms(qText, rules); len(synTerms) > 0 {
								shouldClauses := make([]any, 0, len(synTerms))
								for _, termStr := range synTerms {
									shouldClauses = append(shouldClauses, map[string]any{
										"match": map[string]any{fieldName: termStr},
									})
								}
								mutated = true
								return map[string]any{
									"bool": map[string]any{
										"should":               shouldClauses,
										"minimum_should_match": 1,
									},
								}
							}
						}
					}
				}
				if mmBody, isMM := tv["multi_match"].(map[string]any); isMM {
					qText, _ := mmBody["query"].(string)
					explicitAn, _ := mmBody["analyzer"].(string)
					fields := extractStringSliceAny(mmBody["fields"])
					if qText != "" && len(fields) > 0 {
						var rules []parsedSynonymRule
						for _, idxName := range targetIndices {
							for _, fn := range fields {
								cleanField := strings.Split(fn, "^")[0]
								rules = append(rules, s.collectIndexSynonymRulesForFieldLocked(idxName, cleanField, explicitAn)...)
							}
						}
						if synTerms := expandQueryTermsWithSynonyms(qText, rules); len(synTerms) > 0 {
							shouldClauses := make([]any, 0, len(synTerms))
							for _, termStr := range synTerms {
								cpMM := deepCloneDocMap(mmBody)
								cpMM["query"] = termStr
								shouldClauses = append(shouldClauses, map[string]any{"multi_match": cpMM})
							}
							mutated = true
							return map[string]any{
								"bool": map[string]any{
									"should":               shouldClauses,
									"minimum_should_match": 1,
								},
							}
						}
					}
				}
			}

			for k, sub := range tv {
				tv[k] = walkValue(sub)
				if errCode != 0 {
					return tv
				}
			}
			return tv
		case []any:
			for i, item := range tv {
				tv[i] = walkValue(item)
				if errCode != 0 {
					return tv
				}
			}
			return tv
		}
		return v
	}

	walkValue(doc)
	s.mu.RUnlock()

	if errCode != 0 {
		writeESError(w, errCode, errType, errMsg)
		return nil, false
	}
	if !mutated {
		return bodyBytes, true
	}
	reEncoded, err := json.Marshal(doc)
	if err != nil {
		return bodyBytes, true
	}
	return reEncoded, true
}

// handleInferenceStreamOrPostRound57 handles SSE `_stream` endpoints and `chat_completion` (messages),
// `classification`, and `ner` task payloads on `/_inference/*` (F6.2).
func (s *Server) handleInferenceStreamOrPostRound57(w http.ResponseWriter, r *http.Request, segs []string) bool {
	if r.Method != http.MethodPost {
		return false
	}
	isStream := (len(segs) == 3 && segs[2] == "_stream") || (len(segs) == 4 && segs[3] == "_stream")
	if isStream {
		var taskType, inferenceID string
		if len(segs) == 3 {
			inferenceID = strings.TrimSpace(segs[1])
		} else {
			taskType = strings.TrimSpace(segs[1])
			inferenceID = strings.TrimSpace(segs[2])
		}
		if inferenceID == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: inference_id is missing;")
			return true
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return true
		}
		s.mu.RLock()
		ep, exists := s.inferenceEndpoints[inferenceID]
		s.mu.RUnlock()
		if !exists || ep == nil {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("Inference endpoint [%s] not found", inferenceID))
			return true
		}
		epTaskType, _ := ep["task_type"].(string)
		if taskType != "" && taskType != epTaskType {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Inference endpoint [%s] is for task [%s], not [%s]", inferenceID, epTaskType, taskType))
			return true
		}
		if epTaskType != "completion" && epTaskType != "chat_completion" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Streaming is only supported for [completion, chat_completion], got [%s]", epTaskType))
			return true
		}
		prompt := extractInferencePromptOrInput(body)
		if prompt == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: input or messages is missing;")
			return true
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		tokens := strings.Fields("completed: " + prompt)
		for idx, tok := range tokens {
			delta := tok
			if idx < len(tokens)-1 {
				delta += " "
			}
			var chunk map[string]any
			if epTaskType == "chat_completion" {
				chunk = map[string]any{
					"inference_id": inferenceID,
					"task_type":    "chat_completion",
					"chat_completion": map[string]any{
						"choices": []any{
							map[string]any{
								"index": 0,
								"delta": map[string]any{
									"role":    "assistant",
									"content": delta,
								},
							},
						},
					},
				}
			} else {
				chunk = map[string]any{
					"inference_id": inferenceID,
					"task_type":    "completion",
					"completion": []any{
						map[string]any{"result": delta},
					},
				}
			}
			b, _ := json.Marshal(chunk)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(b))
		}
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		if flusher, okF := w.(http.Flusher); okF {
			flusher.Flush()
		}
		return true
	}

	// Non-stream POST: intercept when endpoint is chat_completion (with messages), classification, or ner
	var taskType, inferenceID string
	if len(segs) == 2 {
		inferenceID = strings.TrimSpace(segs[1])
	} else if len(segs) == 3 {
		taskType = strings.TrimSpace(segs[1])
		inferenceID = strings.TrimSpace(segs[2])
	} else {
		return false
	}
	if inferenceID == "" {
		return false
	}
	s.mu.RLock()
	ep, exists := s.inferenceEndpoints[inferenceID]
	s.mu.RUnlock()
	if !exists || ep == nil {
		return false
	}
	epTaskType, _ := ep["task_type"].(string)
	if taskType != "" && taskType != "_inference" && taskType != epTaskType {
		return false // let existing handler emit task mismatch 400
	}
	if epTaskType != "chat_completion" && epTaskType != "classification" && epTaskType != "ner" {
		return false
	}

	body, ok := parseJSONBody(w, r)
	if !ok {
		return true
	}

	switch epTaskType {
	case "chat_completion":
		prompt := extractInferencePromptOrInput(body)
		if prompt == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: input or messages is missing;")
			return true
		}
		reply := "completed: " + prompt
		writeJSON(w, http.StatusOK, map[string]any{
			"inference_id": inferenceID,
			"task_type":    "chat_completion",
			"completion": []any{
				map[string]any{"result": reply},
			},
			"chat_completion": map[string]any{
				"choices": []any{
					map[string]any{
						"index":         0,
						"finish_reason": "stop",
						"message": map[string]any{
							"role":    "assistant",
							"content": reply,
						},
					},
				},
			},
		})
		return true

	case "classification":
		inputs, okInp := extractInferenceInputStrings(body)
		if !okInp {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: input is missing;")
			return true
		}
		results := make([]any, 0, len(inputs))
		for _, inp := range inputs {
			lower := strings.ToLower(inp)
			pred := "NEUTRAL"
			prob := 0.85
			alt := "POSITIVE"
			if strings.Contains(lower, "good") || strings.Contains(lower, "great") || strings.Contains(lower, "love") || strings.Contains(lower, "excellent") {
				pred = "POSITIVE"
				prob = 0.94
				alt = "NEGATIVE"
			} else if strings.Contains(lower, "bad") || strings.Contains(lower, "fail") || strings.Contains(lower, "error") || strings.Contains(lower, "hate") {
				pred = "NEGATIVE"
				prob = 0.92
				alt = "POSITIVE"
			}
			results = append(results, map[string]any{
				"predicted_value":        pred,
				"prediction_probability": prob,
				"top_classes": []any{
					map[string]any{"class_name": pred, "score": prob},
					map[string]any{"class_name": alt, "score": math.Round((1.0-prob)*100) / 100},
				},
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"inference_id":   inferenceID,
			"task_type":      "classification",
			"classification": results,
		})
		return true

	case "ner":
		inputs, okInp := extractInferenceInputStrings(body)
		if !okInp {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: input is missing;")
			return true
		}
		results := make([]any, 0, len(inputs))
		for _, inp := range inputs {
			entities := extractSimpleNEREntities(inp)
			results = append(results, map[string]any{
				"entities": entities,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"inference_id": inferenceID,
			"task_type":    "ner",
			"ner":          results,
			"entities":     results,
		})
		return true
	}
	return false
}

func extractInferencePromptOrInput(body map[string]any) string {
	if body == nil {
		return ""
	}
	if rawInput, has := body["input"]; has && rawInput != nil {
		switch iv := rawInput.(type) {
		case string:
			return strings.TrimSpace(iv)
		case []any:
			var parts []string
			for _, it := range iv {
				parts = append(parts, fmt.Sprintf("%v", it))
			}
			return strings.TrimSpace(strings.Join(parts, "\n"))
		default:
			return strings.TrimSpace(fmt.Sprintf("%v", iv))
		}
	}
	if msgs, okM := body["messages"].([]any); okM && len(msgs) > 0 {
		var parts []string
		for _, m := range msgs {
			if mm, okMap := m.(map[string]any); okMap {
				if cStr, okC := mm["content"].(string); okC && strings.TrimSpace(cStr) != "" {
					parts = append(parts, strings.TrimSpace(cStr))
				}
			}
		}
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}
	return ""
}

func extractInferenceInputStrings(body map[string]any) ([]string, bool) {
	if body == nil {
		return nil, false
	}
	rawInput, has := body["input"]
	if !has || rawInput == nil {
		return nil, false
	}
	switch iv := rawInput.(type) {
	case string:
		return []string{iv}, true
	case []any:
		if len(iv) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(iv))
		for _, it := range iv {
			out = append(out, fmt.Sprintf("%v", it))
		}
		return out, true
	default:
		return []string{fmt.Sprintf("%v", iv)}, true
	}
}

func extractSimpleNEREntities(text string) []any {
	entities := make([]any, 0)
	idx := 0
	for idx < len(text) {
		rn, sz := utf8.DecodeRuneInString(text[idx:])
		if !unicode.IsLetter(rn) {
			idx += sz
			continue
		}
		start := idx
		for idx < len(text) {
			r2, s2 := utf8.DecodeRuneInString(text[idx:])
			if !unicode.IsLetter(r2) && r2 != '-' {
				break
			}
			idx += s2
		}
		word := text[start:idx]
		firstRune, _ := utf8.DecodeRuneInString(word)
		if unicode.IsUpper(firstRune) && len(word) > 1 {
			cls := "PER"
			switch strings.ToLower(word) {
			case "paris", "london", "tokyo", "berlin", "california", "france", "america", "seattle":
				cls = "LOC"
			case "google", "elastic", "apache", "microsoft", "openai", "inc", "corp":
				cls = "ORG"
			}
			entities = append(entities, map[string]any{
				"entity":            word,
				"class_name":        cls,
				"class_probability": 0.95,
				"start_pos":         start,
				"end_pos":           idx,
			})
		}
	}
	return entities
}

// ============================================================================
// Round 57 F7: Connectors Sync Job _claim & Search Application Dictionary
// ============================================================================

// handleConnectorSyncJobClaimRound57 implements `POST /_connector/_sync_job/_claim` (F7.1).
func (s *Server) handleConnectorSyncJobClaimRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}
	connFilter, _ := body["connector_id"].(string)
	connFilter = strings.TrimSpace(connFilter)
	workerHost, _ := body["worker_hostname"].(string)
	if strings.TrimSpace(workerHost) == "" {
		workerHost = "doris-connector-worker-1"
	}
	allowedTypes := make(map[string]bool)
	for _, jt := range extractStringSliceAny(body["job_types"]) {
		allowedTypes[jt] = true
	}

	nowISO := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	var pendingIDs []string
	for id, job := range s.connectorSyncJobs {
		if job == nil || job["status"] != "pending" {
			continue
		}
		if connFilter != "" && fmt.Sprintf("%v", job["connector_id"]) != connFilter {
			continue
		}
		if len(allowedTypes) > 0 && !allowedTypes[fmt.Sprintf("%v", job["job_type"])] {
			continue
		}
		pendingIDs = append(pendingIDs, id)
	}
	sort.Slice(pendingIDs, func(i, j int) bool {
		ci := fmt.Sprintf("%v", s.connectorSyncJobs[pendingIDs[i]]["created_at"])
		cj := fmt.Sprintf("%v", s.connectorSyncJobs[pendingIDs[j]]["created_at"])
		if ci != cj {
			return ci < cj
		}
		return pendingIDs[i] < pendingIDs[j]
	})
	if len(pendingIDs) == 0 {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	chosen := s.connectorSyncJobs[pendingIDs[0]]
	chosen["status"] = "in_progress"
	chosen["worker_hostname"] = workerHost
	chosen["claimed_at"] = nowISO
	chosen["started_at"] = nowISO
	chosen["last_seen"] = nowISO
	claimedCopy := deepCloneDocMap(chosen)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, claimedCopy)
}

// validateSearchApplicationParams validates merged template parameters against template.dictionary JSON Schema (F7.2).
func validateSearchApplicationParams(tmplMap map[string]any, mergedParams map[string]any) error {
	if tmplMap == nil {
		return nil
	}
	dictMap, ok := tmplMap["dictionary"].(map[string]any)
	if !ok || len(dictMap) == 0 {
		return nil
	}
	// 1. Check required properties
	for _, reqField := range extractStringSliceAny(dictMap["required"]) {
		val, exists := mergedParams[reqField]
		if !exists || val == nil {
			return fmt.Errorf("missing required parameter [%s] according to template dictionary", reqField)
		}
	}
	// 2. Check properties.<k>.type and enum
	if props, okP := dictMap["properties"].(map[string]any); okP {
		for k, rawSchema := range props {
			val, exists := mergedParams[k]
			if !exists || val == nil {
				continue
			}
			propSchema, okPS := rawSchema.(map[string]any)
			if !okPS {
				continue
			}
			if expectedType, okT := propSchema["type"].(string); okT && expectedType != "" {
				if !matchesJSONSchemaType(val, expectedType) {
					return fmt.Errorf("parameter [%s] expected type [%s], got %T", k, expectedType, val)
				}
			}
			if enumSlice, okE := propSchema["enum"].([]any); okE && len(enumSlice) > 0 {
				matchedEnum := false
				for _, ev := range enumSlice {
					if fmt.Sprintf("%v", ev) == fmt.Sprintf("%v", val) && reflectSameJSONKind(ev, val) {
						matchedEnum = true
						break
					}
				}
				if !matchedEnum {
					return fmt.Errorf("parameter [%s] value [%v] is not one of allowed enum values", k, val)
				}
			}
		}
	}
	// 3. Check additionalProperties == false
	if addProps, hasAP := dictMap["additionalProperties"].(bool); hasAP && !addProps {
		props, _ := dictMap["properties"].(map[string]any)
		for k := range mergedParams {
			if props == nil || props[k] == nil {
				return fmt.Errorf("unknown parameter [%s] is not allowed by template dictionary (additionalProperties: false)", k)
			}
		}
	}
	return nil
}

func matchesJSONSchemaType(val any, expected string) bool {
	switch strings.ToLower(expected) {
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "number":
		switch val.(type) {
		case float64, float32, int, int64, int32, uint64, json.Number:
			return true
		}
		return false
	case "integer":
		switch tv := val.(type) {
		case int, int64, int32, uint64:
			return true
		case float64:
			return !math.IsNaN(tv) && !math.IsInf(tv, 0) && tv == math.Trunc(tv)
		case json.Number:
			_, err := tv.Int64()
			return err == nil
		}
		return false
	case "array":
		_, ok := val.([]any)
		return ok
	case "object":
		_, ok := val.(map[string]any)
		return ok
	}
	return true
}

func reflectSameJSONKind(a, b any) bool {
	_, aStr := a.(string)
	_, bStr := b.(string)
	if aStr != bStr {
		return false
	}
	_, aBool := a.(bool)
	_, bBool := b.(bool)
	return aBool == bBool
}

// ============================================================================
// Round 57 F8: Security API Key Update/Bulk-Update, _query DSL, _privileges,
// Cache-Clear Fixes, and OIDC / SAML / Delegate-PKI / SSL
// ============================================================================

func securityNodesCacheClearResponse() map[string]any {
	return map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "apache-doris-search-cluster",
		"nodes":        map[string]any{"doris-fe-1": map[string]any{"name": "doris-fe-1"}},
	}
}

// handleSecurityRound57 intercepts Round 57 `/_security/*` endpoints before Round 56 / Round 49 handlers.
func (s *Server) handleSecurityRound57(w http.ResponseWriter, r *http.Request, segs []string) bool {
	if len(segs) < 2 {
		return false
	}

	switch segs[1] {
	case "user":
		// GET /_security/user/_privileges (must run before target username lookup!)
		if len(segs) == 3 && segs[2] == "_privileges" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return true
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"cluster": []string{"all"},
				"global":  []any{},
				"indices": []any{
					map[string]any{
						"names":                    []string{"*"},
						"privileges":               []string{"all"},
						"allow_restricted_indices": false,
					},
				},
				"applications": []any{},
				"run_as":       []string{"*"},
			})
			return true
		}

	case "privilege":
		// POST /_security/privilege/{app}/_clear_cache (must run BEFORE privilege creation!)
		if len(segs) == 4 && segs[3] == "_clear_cache" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			writeJSON(w, http.StatusOK, securityNodesCacheClearResponse())
			return true
		}

	case "service":
		// POST /_security/service/{ns}/{svc}/credential/token/{name}/_clear_cache
		// or POST /_security/service/{ns}/{svc}/_clear_cache
		if (len(segs) == 8 && segs[4] == "credential" && segs[5] == "token" && segs[7] == "_clear_cache") ||
			(len(segs) == 5 && segs[4] == "_clear_cache") {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			writeJSON(w, http.StatusOK, securityNodesCacheClearResponse())
			return true
		}

	case "api_key":
		// POST /_security/api_key/_bulk_update
		if len(segs) == 3 && segs[2] == "_bulk_update" {
			if r.Method != http.MethodPost && r.Method != http.MethodPut {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			body, ok := parseJSONBody(w, r)
			if !ok {
				return true
			}
			rawIDs, hasIDs := body["ids"].([]any)
			if !hasIDs || len(rawIDs) == 0 {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [ids] must not be empty;")
				return true
			}
			hasRD := false
			var newRD any
			if rd, exists := body["role_descriptors"]; exists {
				hasRD = true
				newRD = rd
			}
			hasMeta := false
			var newMeta any
			if md, exists := body["metadata"]; exists {
				hasMeta = true
				newMeta = md
			}

			updatedIDs := make([]string, 0)
			noopIDs := make([]string, 0)
			errDetails := make([]any, 0)

			s.mu.Lock()
			for _, rawID := range rawIDs {
				idStr := strings.TrimSpace(fmt.Sprintf("%v", rawID))
				if idStr == "" {
					continue
				}
				kObj, exists := s.securityAPIKeys[idStr]
				if !exists || kObj == nil {
					errDetails = append(errDetails, map[string]any{
						"type":   "resource_not_found_exception",
						"reason": fmt.Sprintf("api_key [%s] not found", idStr),
					})
					continue
				}
				if inv, _ := kObj["invalidated"].(bool); inv {
					errDetails = append(errDetails, map[string]any{
						"type":   "illegal_argument_exception",
						"reason": fmt.Sprintf("Cannot update invalidated API key [%s]", idStr),
					})
					continue
				}
				if !hasRD && !hasMeta {
					noopIDs = append(noopIDs, idStr)
					continue
				}
				if hasRD {
					kObj["role_descriptors"] = deepCloneIngestValue(newRD)
				}
				if hasMeta {
					kObj["metadata"] = deepCloneIngestValue(newMeta)
				}
				updatedIDs = append(updatedIDs, idStr)
			}
			s.mu.Unlock()

			writeJSON(w, http.StatusOK, map[string]any{
				"updated":       updatedIDs,
				"noop":          noopIDs,
				"error_count":   len(errDetails),
				"error_details": errDetails,
				"errors":        errDetails,
			})
			return true
		}

		if len(segs) == 3 && segs[2] == "_query" {
			s.handleSecurityQueryDSL(w, r, "api_key")
			return true
		}

		// PUT/POST /_security/api_key/{id}
		if len(segs) == 3 && segs[2] != "_grant" {
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
				return true
			}
			keyID := strings.TrimSpace(segs[2])
			body, ok := parseJSONBody(w, r)
			if !ok {
				return true
			}
			s.mu.Lock()
			kObj, exists := s.securityAPIKeys[keyID]
			if !exists || kObj == nil {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("api_key [%s] not found", keyID))
				return true
			}
			if inv, _ := kObj["invalidated"].(bool); inv {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Cannot update invalidated API key [%s]", keyID))
				return true
			}
			if rd, hasRD := body["role_descriptors"]; hasRD {
				kObj["role_descriptors"] = deepCloneIngestValue(rd)
			}
			if md, hasMeta := body["metadata"]; hasMeta {
				kObj["metadata"] = deepCloneIngestValue(md)
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"updated": true})
			return true
		}

	case "_query":
		if len(segs) == 3 && (segs[2] == "api_key" || segs[2] == "user" || segs[2] == "role") {
			s.handleSecurityQueryDSL(w, r, segs[2])
			return true
		}

	case "oidc":
		s.handleSecurityOIDC(w, r, segs)
		return true

	case "saml":
		s.handleSecuritySAML(w, r, segs)
		return true

	case "delegate_pki":
		s.handleSecurityDelegatePKI(w, r, segs)
		return true

	case "ssl":
		if len(segs) == 3 && segs[2] == "certificates" {
			s.handleSSLCertificates(w, r)
			return true
		}
	}

	return false
}

// handleSecurityQueryDSL implements `POST/GET /_security/_query/{api_key,user,role}` with Query DSL, sort, from, size (F8.2).
func (s *Server) handleSecurityQueryDSL(w http.ResponseWriter, r *http.Request, entity string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}

	from, size := parseFromSizePagination(r, 100)
	if body != nil {
		if fv, okF := toInt64(body["from"]); okF && fv >= 0 {
			from = int(fv)
		}
		if sv, okS := toInt64(body["size"]); okS && sv >= 0 {
			size = int(sv)
		}
	}
	withProfileUID := isTruthyBoolQueryParam(r, "with_profile_uid")
	if bwp, okB := body["with_profile_uid"].(bool); okB {
		withProfileUID = bwp
	}

	var candidates []map[string]any
	var defaultSortKey, outKey string

	s.mu.RLock()
	switch entity {
	case "api_key":
		defaultSortKey = "id"
		outKey = "api_keys"
		for _, kObj := range s.securityAPIKeys {
			if kObj != nil {
				candidates = append(candidates, deepCloneDocMap(kObj))
			}
		}
	case "user":
		defaultSortKey = "username"
		outKey = "users"
		userMap := make(map[string]map[string]any, len(s.securityUsers)+1)
		userMap["elastic"] = map[string]any{
			"username":  "elastic",
			"roles":     []any{"superuser"},
			"full_name": "Built-in Superuser",
			"email":     "",
			"metadata":  map[string]any{},
			"enabled":   true,
		}
		for uName, uObj := range s.securityUsers {
			if uObj != nil {
				cp := deepCloneDocMap(uObj)
				cp["username"] = uName
				userMap[uName] = cp
			}
		}
		for uName, cp := range userMap {
			if withProfileUID {
				uid := "u_" + uName
				cp["profile_uid"] = uid
			}
			candidates = append(candidates, cp)
		}
	case "role":
		defaultSortKey = "name"
		outKey = "roles"
		roleMap := make(map[string]map[string]any, len(s.securityRoles)+1)
		roleMap["superuser"] = map[string]any{
			"name":         "superuser",
			"cluster":      []any{"all"},
			"indices":      []any{map[string]any{"names": []any{"*"}, "privileges": []any{"all"}}},
			"applications": []any{},
			"run_as":       []any{"*"},
			"metadata":     map[string]any{"_reserved": true},
		}
		for rName, rObj := range s.securityRoles {
			if rObj != nil {
				cp := deepCloneDocMap(rObj)
				cp["name"] = rName
				roleMap[rName] = cp
			}
		}
		for _, cp := range roleMap {
			candidates = append(candidates, cp)
		}
	}
	s.mu.RUnlock()

	var queryDSL map[string]any
	if body != nil {
		if qm, okQ := body["query"].(map[string]any); okQ {
			queryDSL = qm
		} else if body["query"] != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "[query] must be an object")
			return
		}
	}

	matched := make([]map[string]any, 0, len(candidates))
	for _, item := range candidates {
		okMatch, qErr := evalSecurityDocQueryDSL(item, queryDSL)
		if qErr != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", qErr.Error())
			return
		}
		if okMatch {
			matched = append(matched, item)
		}
	}

	sortSpecs := parseSecuritySortSpecs(body["sort"], defaultSortKey)
	sort.SliceStable(matched, func(i, j int) bool {
		for _, sp := range sortSpecs {
			vi := lookupSecurityDocField(matched[i], sp.field)
			vj := lookupSecurityDocField(matched[j], sp.field)
			cmp := compareESQLValues(vi, vj)
			if cmp == 0 {
				continue
			}
			if sp.desc {
				return cmp > 0
			}
			return cmp < 0
		}
		return false
	})

	total := len(matched)
	page := make([]any, 0)
	for i := from; i < total && len(page) < size; i++ {
		page = append(page, matched[i])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total": total,
		"count": len(page),
		outKey:  page,
	})
}

type securitySortSpec struct {
	field string
	desc  bool
}

func parseSecuritySortSpecs(raw any, defaultField string) []securitySortSpec {
	var specs []securitySortSpec
	parseOne := func(item any) {
		switch tv := item.(type) {
		case string:
			if strings.TrimSpace(tv) != "" {
				specs = append(specs, securitySortSpec{field: strings.TrimSpace(tv), desc: false})
			}
		case map[string]any:
			for k, v := range tv {
				desc := false
				switch ov := v.(type) {
				case string:
					desc = strings.EqualFold(strings.TrimSpace(ov), "desc")
				case map[string]any:
					if ord, ok := ov["order"].(string); ok {
						desc = strings.EqualFold(strings.TrimSpace(ord), "desc")
					}
				}
				specs = append(specs, securitySortSpec{field: k, desc: desc})
			}
		}
	}
	switch rv := raw.(type) {
	case []any:
		for _, it := range rv {
			parseOne(it)
		}
	case string, map[string]any:
		parseOne(rv)
	}
	if len(specs) == 0 && defaultField != "" {
		specs = append(specs, securitySortSpec{field: defaultField, desc: false})
	}
	return specs
}

func lookupSecurityDocField(doc map[string]any, field string) any {
	clean := strings.TrimSuffix(field, ".keyword")
	if v, ok := doc[clean]; ok {
		return v
	}
	parts := strings.Split(clean, ".")
	var cur any = doc
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok || m == nil {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func extractSecurityFieldValues(doc map[string]any, field string) []any {
	val := lookupSecurityDocField(doc, field)
	if val == nil {
		return nil
	}
	switch tv := val.(type) {
	case []any:
		return tv
	case []string:
		out := make([]any, len(tv))
		for i, s := range tv {
			out[i] = s
		}
		return out
	default:
		return []any{val}
	}
}

func evalSecurityDocQueryDSL(doc map[string]any, q map[string]any) (bool, error) {
	if len(q) == 0 {
		return true, nil
	}
	for clause, rawSpec := range q {
		switch clause {
		case "match_all":
			continue
		case "match_none":
			return false, nil
		case "exists":
			em, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[exists] query malformed")
			}
			f, _ := em["field"].(string)
			vals := extractSecurityFieldValues(doc, f)
			if len(vals) == 0 {
				return false, nil
			}
		case "term":
			tm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[term] query malformed")
			}
			for field, target := range tm {
				expected := target
				caseInsensitive := false
				if sub, okM := target.(map[string]any); okM {
					expected = sub["value"]
					caseInsensitive, _ = sub["case_insensitive"].(bool)
				}
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					if caseInsensitive {
						if strings.EqualFold(fmt.Sprintf("%v", dv), fmt.Sprintf("%v", expected)) {
							matched = true
							break
						}
					} else if fmt.Sprintf("%v", dv) == fmt.Sprintf("%v", expected) {
						matched = true
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "terms":
			tm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[terms] query malformed")
			}
			for field, rawList := range tm {
				if field == "boost" {
					continue
				}
				list, okL := rawList.([]any)
				if !okL {
					return false, fmt.Errorf("[terms] field [%s] requires an array", field)
				}
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					for _, tv := range list {
						if fmt.Sprintf("%v", dv) == fmt.Sprintf("%v", tv) {
							matched = true
							break
						}
					}
					if matched {
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "prefix":
			pm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[prefix] query malformed")
			}
			for field, target := range pm {
				pfx := ""
				ci := false
				switch tv := target.(type) {
				case string:
					pfx = tv
				case map[string]any:
					pfx, _ = tv["value"].(string)
					ci, _ = tv["case_insensitive"].(bool)
				}
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					ds := fmt.Sprintf("%v", dv)
					if ci {
						if strings.HasPrefix(strings.ToLower(ds), strings.ToLower(pfx)) {
							matched = true
							break
						}
					} else if strings.HasPrefix(ds, pfx) {
						matched = true
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "wildcard":
			wm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[wildcard] query malformed")
			}
			for field, target := range wm {
				pat := ""
				ci := false
				switch tv := target.(type) {
				case string:
					pat = tv
				case map[string]any:
					pat, _ = tv["value"].(string)
					if pat == "" {
						pat, _ = tv["wildcard"].(string)
					}
					ci, _ = tv["case_insensitive"].(bool)
				}
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					ds := fmt.Sprintf("%v", dv)
					if ci {
						if matchSimpleWildcard(strings.ToLower(pat), strings.ToLower(ds)) {
							matched = true
							break
						}
					} else if matchSimpleWildcard(pat, ds) {
						matched = true
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "match":
			mm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[match] query malformed")
			}
			for field, target := range mm {
				qStr := ""
				switch tv := target.(type) {
				case string:
					qStr = tv
				case map[string]any:
					qStr = fmt.Sprintf("%v", tv["query"])
				default:
					qStr = fmt.Sprintf("%v", tv)
				}
				tokens := strings.Fields(strings.ToLower(qStr))
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					dl := strings.ToLower(fmt.Sprintf("%v", dv))
					for _, tk := range tokens {
						if strings.Contains(dl, tk) {
							matched = true
							break
						}
					}
					if matched {
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "range":
			rm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[range] query malformed")
			}
			for field, rawBounds := range rm {
				bm, okB := rawBounds.(map[string]any)
				if !okB {
					return false, fmt.Errorf("[range] bounds must be an object")
				}
				vals := extractSecurityFieldValues(doc, field)
				matched := false
				for _, dv := range vals {
					okVal := true
					if b, has := bm["gt"]; has && compareESQLValues(dv, b) <= 0 {
						okVal = false
					}
					if b, has := bm["gte"]; has && compareESQLValues(dv, b) < 0 {
						okVal = false
					}
					if b, has := bm["lt"]; has && compareESQLValues(dv, b) >= 0 {
						okVal = false
					}
					if b, has := bm["lte"]; has && compareESQLValues(dv, b) > 0 {
						okVal = false
					}
					if okVal {
						matched = true
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
		case "bool":
			bm, ok := rawSpec.(map[string]any)
			if !ok {
				return false, fmt.Errorf("[bool] query malformed")
			}
			extractClauseList := func(v any) ([]map[string]any, error) {
				if v == nil {
					return nil, nil
				}
				switch tv := v.(type) {
				case map[string]any:
					return []map[string]any{tv}, nil
				case []any:
					out := make([]map[string]any, 0, len(tv))
					for _, it := range tv {
						m, okM := it.(map[string]any)
						if !okM {
							return nil, fmt.Errorf("bool sub-clause must be an object")
						}
						out = append(out, m)
					}
					return out, nil
				default:
					return nil, fmt.Errorf("bool clause must be an object or array")
				}
			}
			for _, reqKey := range []string{"must", "filter"} {
				list, err := extractClauseList(bm[reqKey])
				if err != nil {
					return false, err
				}
				for _, subQ := range list {
					okSub, err := evalSecurityDocQueryDSL(doc, subQ)
					if err != nil || !okSub {
						return false, err
					}
				}
			}
			mustNotList, err := extractClauseList(bm["must_not"])
			if err != nil {
				return false, err
			}
			for _, subQ := range mustNotList {
				okSub, err := evalSecurityDocQueryDSL(doc, subQ)
				if err != nil {
					return false, err
				}
				if okSub {
					return false, nil
				}
			}
			shouldList, err := extractClauseList(bm["should"])
			if err != nil {
				return false, err
			}
			if len(shouldList) > 0 {
				minShould := 1
				if bm["must"] != nil || bm["filter"] != nil {
					minShould = 0
				}
				if msm, okMSM := toInt64(bm["minimum_should_match"]); okMSM {
					minShould = int(msm)
				}
				matchedShould := 0
				for _, subQ := range shouldList {
					okSub, err := evalSecurityDocQueryDSL(doc, subQ)
					if err != nil {
						return false, err
					}
					if okSub {
						matchedShould++
					}
				}
				if matchedShould < minShould {
					return false, nil
				}
			}
		default:
			return false, fmt.Errorf("unknown query [%s]", clause)
		}
	}
	return true, nil
}

func (s *Server) handleSecurityOIDC(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) != 3 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}
	realm, _ := body["realm"].(string)
	if strings.TrimSpace(realm) == "" {
		realm = "oidc1"
	}

	switch segs[2] {
	case "prepare":
		nowNs := time.Now().UTC().UnixNano()
		state := fmt.Sprintf("oidc_state_%d", nowNs)
		nonce := fmt.Sprintf("oidc_nonce_%d", nowNs)
		if st, okS := body["state"].(string); okS && strings.TrimSpace(st) != "" {
			state = strings.TrimSpace(st)
		}
		if nc, okN := body["nonce"].(string); okN && strings.TrimSpace(nc) != "" {
			nonce = strings.TrimSpace(nc)
		}
		s.mu.Lock()
		if s.securitySessions == nil {
			s.securitySessions = make(map[string]map[string]any)
		}
		s.securitySessions[state] = map[string]any{
			"type":  "oidc",
			"state": state,
			"nonce": nonce,
			"realm": realm,
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": fmt.Sprintf("https://oidc.example.com/authorize?response_type=code&state=%s&nonce=%s", state, nonce),
			"state":    state,
			"nonce":    nonce,
			"realm":    realm,
		})

	case "authenticate":
		redirectURI, _ := body["redirect_uri"].(string)
		code, _ := body["code"].(string)
		if strings.TrimSpace(redirectURI) == "" && strings.TrimSpace(code) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [redirect_uri] is required;")
			return
		}
		state, _ := body["state"].(string)
		tok := fmt.Sprintf("doris-oidc-token-%d", time.Now().UTC().UnixNano())
		ref := fmt.Sprintf("doris-oidc-refresh-%d", time.Now().UTC().UnixNano())
		s.mu.Lock()
		if s.securitySessions == nil {
			s.securitySessions = make(map[string]map[string]any)
		}
		s.securitySessions[tok] = map[string]any{
			"type":     "oidc_token",
			"state":    state,
			"realm":    realm,
			"username": "elastic",
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  tok,
			"type":          "Bearer",
			"expires_in":    1200,
			"refresh_token": ref,
			"username":      "elastic",
		})

	case "logout":
		tok, _ := body["token"].(string)
		if strings.TrimSpace(tok) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [token] is required;")
			return
		}
		s.mu.Lock()
		delete(s.securitySessions, strings.TrimSpace(tok))
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": "https://oidc.example.com/end_session",
		})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func (s *Server) handleSecuritySAML(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) < 3 || len(segs) > 4 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	action := segs[2]
	if action == "metadata" {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		var body map[string]any
		if r.ContentLength != 0 {
			var ok bool
			body, ok = parseJSONBody(w, r)
			if !ok {
				return
			}
		}
		realmName := ""
		if len(segs) == 4 {
			realmName = strings.TrimSpace(segs[3])
		}
		if realmName == "" {
			realmName, _ = body["realm_name"].(string)
		}
		if realmName == "" {
			realmName = strings.TrimSpace(r.URL.Query().Get("realm_name"))
		}
		if strings.TrimSpace(realmName) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [realm_name] is required;")
			return
		}
		xmlStr := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://doris-es-proxy/%s"/>`, html.EscapeString(realmName))
		w.Header().Set("Content-Type", "application/xml; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		// #nosec G705 -- SAML EntityDescriptor XML response with html.EscapeString-escaped entityID and application/xml Content-Type
		_, _ = w.Write([]byte(xmlStr))
		return
	}

	if len(segs) != 3 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}
	realm, _ := body["realm"].(string)
	if strings.TrimSpace(realm) == "" {
		realm = "saml1"
	}

	switch action {
	case "prepare":
		reqID := fmt.Sprintf("saml_req_%d", time.Now().UTC().UnixNano())
		s.mu.Lock()
		if s.securitySessions == nil {
			s.securitySessions = make(map[string]map[string]any)
		}
		s.securitySessions[reqID] = map[string]any{
			"type":  "saml",
			"id":    reqID,
			"realm": realm,
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": fmt.Sprintf("https://idp.example.com/sso/saml?SAMLRequest=%s", reqID),
			"id":       reqID,
			"realm":    realm,
		})

	case "authenticate":
		content, _ := body["content"].(string)
		if strings.TrimSpace(content) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [content] is required;")
			return
		}
		tok := fmt.Sprintf("doris-saml-token-%d", time.Now().UTC().UnixNano())
		ref := fmt.Sprintf("doris-saml-refresh-%d", time.Now().UTC().UnixNano())
		s.mu.Lock()
		if s.securitySessions == nil {
			s.securitySessions = make(map[string]map[string]any)
		}
		s.securitySessions[tok] = map[string]any{
			"type":     "saml_token",
			"realm":    realm,
			"username": "elastic",
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  tok,
			"type":          "Bearer",
			"expires_in":    1200,
			"refresh_token": ref,
			"username":      "elastic",
			"roles":         []string{"superuser"},
			"realm":         realm,
		})

	case "logout":
		tok, _ := body["token"].(string)
		if strings.TrimSpace(tok) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [token] is required;")
			return
		}
		s.mu.Lock()
		delete(s.securitySessions, strings.TrimSpace(tok))
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": "https://idp.example.com/sso/slo",
		})

	case "invalidate":
		content, _ := body["content"].(string)
		qs, _ := body["query_string"].(string)
		if strings.TrimSpace(content) == "" && strings.TrimSpace(qs) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: either [content] or [query_string] must be specified;")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect":    "https://idp.example.com/sso/slo_response",
			"invalidated": 1,
			"realm":       realm,
		})

	case "complete_logout":
		writeJSON(w, http.StatusOK, map[string]any{})

	default:
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
	}
}

func (s *Server) handleSecurityDelegatePKI(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) != 2 {
		writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	subjectDN, _ := body["subject_dn"].(string)
	hasChain := body["x509_certificate_chain"] != nil
	if strings.TrimSpace(subjectDN) == "" && !hasChain {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: [subject_dn] or [x509_certificate_chain] is required;")
		return
	}
	username := "pki-user"
	for _, part := range strings.Split(subjectDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			if cn := strings.TrimSpace(part[3:]); cn != "" {
				username = cn
			}
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": fmt.Sprintf("doris-pki-token-%d", time.Now().UTC().UnixNano()),
		"type":         "Bearer",
		"expires_in":   1200,
		"username":     username,
	})
}

// ============================================================================
// Round 57 F9: Fleet Secrets, /_capabilities, /_ingest/_simulate,
// /_scripts/{_context,_languages}, Rethrottle, Freeze/Unfreeze, Synced Flush & Migration
// ============================================================================

// handleFleetSecretsRound57 implements `POST /_fleet/secrets`, `GET /_fleet/secrets/{id}`, `DELETE /_fleet/secrets/{id}` (F9.1).
func (s *Server) handleFleetSecretsRound57(w http.ResponseWriter, r *http.Request, segs []string) {
	// segs: ["_fleet", "secrets"] or ["_fleet", "secrets", "{id}"]
	if len(segs) == 2 {
		if r.Method != http.MethodPost {
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
			return
		}
		body, ok := parseJSONBody(w, r)
		if !ok {
			return
		}
		valStr, hasVal := body["value"].(string)
		if !hasVal || valStr == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "secret [value] is required")
			return
		}
		nowISO := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		s.mu.Lock()
		if s.fleetSecrets == nil {
			s.fleetSecrets = make(map[string]map[string]any)
		}
		secID := fmt.Sprintf("fleet-secret-%d", len(s.fleetSecrets)+1)
		if reqID, okID := body["id"].(string); okID && strings.TrimSpace(reqID) != "" {
			secID = strings.TrimSpace(reqID)
		}
		for s.fleetSecrets[secID] != nil {
			secID = fmt.Sprintf("fleet-secret-%d-%d", len(s.fleetSecrets)+1, time.Now().UTC().UnixNano()%10000)
		}
		entry := map[string]any{
			"id":         secID,
			"created_at": nowISO,
			"__value":    valStr,
		}
		if ns, okNS := body["namespace"].(string); okNS && ns != "" {
			entry["namespace"] = ns
		}
		s.fleetSecrets[secID] = entry
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"id":         secID,
			"created_at": nowISO,
		})
		return
	}

	if len(segs) == 3 {
		secID := strings.TrimSpace(segs[2])
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.mu.RLock()
			entry, exists := s.fleetSecrets[secID]
			var cp map[string]any
			if exists && entry != nil {
				cp = deepCloneDocMap(entry)
				delete(cp, "__value")
			}
			s.mu.RUnlock()
			if cp == nil {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("fleet secret [%s] not found", secID))
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, cp)

		case http.MethodDelete:
			s.mu.Lock()
			_, exists := s.fleetSecrets[secID]
			delete(s.fleetSecrets, secID)
			s.mu.Unlock()
			if !exists {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("fleet secret [%s] not found", secID))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		}
		return
	}

	writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
}

// handleCapabilitiesRound57 implements `GET/POST /_capabilities` (F9.2).
func (s *Server) handleCapabilitiesRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	var body map[string]any
	if r.ContentLength != 0 {
		var ok bool
		body, ok = parseJSONBody(w, r)
		if !ok {
			return
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	defaultCapSpec := func() map[string]any {
		return map[string]any{
			"parameters": []string{},
		}
	}
	allCaps := map[string]any{
		"create_pit":             defaultCapSpec(),
		"search":                 map[string]any{"parameters": []string{"allow_no_indices", "ccs_minimize_roundtrips", "expand_wildcards", "ignore_throttled", "ignore_unavailable", "preference", "request_cache", "routing", "scroll", "search_type", "track_total_hits", "typed_keys"}},
		"knn":                    defaultCapSpec(),
		"sub_searches":           defaultCapSpec(),
		"retriever":              defaultCapSpec(),
		"esql":                   defaultCapSpec(),
		"eql":                    defaultCapSpec(),
		"sql":                    defaultCapSpec(),
		"ingest":                 defaultCapSpec(),
		"synonyms":               defaultCapSpec(),
		"query_rules":            defaultCapSpec(),
		"inference":              defaultCapSpec(),
		"connectors":             defaultCapSpec(),
		"search_application":     defaultCapSpec(),
		"security":               defaultCapSpec(),
		"fleet":                  defaultCapSpec(),
		"ml":                     defaultCapSpec(),
		"slm":                    defaultCapSpec(),
		"searchable_snapshots":   defaultCapSpec(),
		"rest_capabilities_api":  defaultCapSpec(),
		"field_capabilities_api": defaultCapSpec(),
	}

	var requested []string
	if qCaps := strings.TrimSpace(r.URL.Query().Get("capabilities")); qCaps != "" {
		for _, c := range strings.Split(qCaps, ",") {
			if c = strings.TrimSpace(c); c != "" {
				requested = append(requested, c)
			}
		}
	}
	if body != nil {
		requested = append(requested, extractStringSliceAny(body["capabilities"])...)
	}

	outCaps := make(map[string]any)
	if len(requested) == 0 {
		outCaps = allCaps
	} else {
		for _, capName := range requested {
			if spec, ok := allCaps[capName]; ok {
				outCaps[capName] = spec
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"capabilities": outCaps,
	})
}

// handleSimulateIndexIngestRound57 implements `POST /_ingest/_simulate` (`simulate.ingest`) (F9.3).
func (s *Server) handleSimulateIndexIngestRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	body, ok := parseJSONBody(w, r)
	if !ok {
		return
	}
	indexName, _ := body["index"].(string)
	indexName = strings.TrimSpace(indexName)
	if indexName == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
		return
	}
	rawDocs, okDocs := body["docs"].([]any)
	if !okDocs || len(rawDocs) == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: docs is missing;")
		return
	}

	verbose := isTruthyBoolQueryParam(r, "verbose")
	reqPipeline := strings.TrimSpace(r.URL.Query().Get("pipeline"))
	if reqPipeline == "" {
		if bp, okBP := body["pipeline"].(string); okBP {
			reqPipeline = strings.TrimSpace(bp)
		}
	}

	// Validate optional pipeline_substitutions upfront
	substPipes := make(map[string]map[string]any)
	if rawSubs, okSub := body["pipeline_substitutions"].(map[string]any); okSub {
		for pName, pRaw := range rawSubs {
			pm, okM := pRaw.(map[string]any)
			if !okM || pm == nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", fmt.Sprintf("pipeline_substitution [%s] must be an object", pName))
				return
			}
			if vErr := validateIngestPipelineSpec(pm); vErr != nil {
				writeESError(w, http.StatusBadRequest, ingestSpecValidationErrorType(vErr), vErr.Error())
				return
			}
			substPipes[pName] = pm
		}
	}

	// Resolve effective base mapping, default_pipeline, and final_pipeline from index or matching templates
	s.mu.RLock()
	var baseMapping *esast.MappingSpec
	var defaultPipe, finalPipe string
	if idxSchema := s.indices[indexName]; idxSchema != nil {
		baseMapping = idxSchema.RawMapping
		defaultPipe = s.indexDefaultPipelines[indexName]
		finalPipe = s.indexFinalPipelines[indexName]
	} else {
		tplMap, tplDef, hasDef, tplFin, hasFin, _ := s.matchingTemplateConfigLocked(indexName)
		baseMapping = tplMap
		if hasDef {
			defaultPipe = tplDef
		}
		if hasFin {
			finalPipe = tplFin
		}
	}
	s.mu.RUnlock()

	lookupPipe := func(pipeID string) (map[string]any, bool) {
		if sub, ok := substPipes[pipeID]; ok {
			return sub, true
		}
		s.mu.RLock()
		p, ok := s.pipelines[pipeID]
		s.mu.RUnlock()
		return p, ok
	}

	compiledSchema := schema.CompileIndexSchema(s.dorisDB, indexName, baseMapping)
	existingDeclaredProps := make(map[string]esast.FieldProperty)
	if baseMapping != nil && baseMapping.Properties != nil {
		for k, v := range baseMapping.Properties {
			existingDeclaredProps[k] = v
		}
	}

	mappingAdditions := make(map[string]any)
	simResults := make([]any, 0, len(rawDocs))

	for idx, rawDocItem := range rawDocs {
		docMap, okM := rawDocItem.(map[string]any)
		if !okM || docMap == nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", "each entry in [docs] must be an object")
			return
		}
		docID := fmt.Sprintf("auto-sim-%d", idx+1)
		docIndex := indexName
		docRouting := ""
		docPipeOverride := reqPipeline
		var sourceMap map[string]any

		if srcSub, hasSrc := docMap["_source"].(map[string]any); hasSrc {
			sourceMap = deepCloneDocMap(srcSub)
			if idStr, okI := docMap["_id"].(string); okI && idStr != "" {
				docID = idStr
			}
			if idxStr, okIx := docMap["_index"].(string); okIx && idxStr != "" {
				docIndex = idxStr
			}
			if rtStr, okRt := docMap["_routing"].(string); okRt {
				docRouting = rtStr
			}
			if dpStr, okDP := docMap["_pipeline"].(string); okDP && dpStr != "" {
				docPipeOverride = dpStr
			}
		} else {
			sourceMap = deepCloneDocMap(docMap)
		}

		curBytes, _ := json.Marshal(sourceMap)
		var executedPipelines []string
		var allProcResults []map[string]any
		var ingestMeta map[string]any
		var docErr error
		dropped := false

		effPipe := defaultPipe
		if docPipeOverride == "_none" {
			effPipe = ""
		} else if docPipeOverride != "" {
			effPipe = docPipeOverride
		}

		if effPipe != "" && effPipe != "_none" {
			pipeSpec, exists := lookupPipe(effPipe)
			if !exists {
				docErr = fmt.Errorf("pipeline with id [%s] does not exist", effPipe)
			} else {
				executedPipelines = append(executedPipelines, effPipe)
				out, outIdx, outID, _, outRt, isDrop, trace, nextMeta, pErr := applyIngestPipelineSpecWithNameAndRoutingAndIngestMeta(
					s, pipeSpec, effPipe, docIndex, docID, docRouting, curBytes, verbose, ingestMeta,
				)
				if pErr != nil {
					docErr = pErr
				} else {
					curBytes = out
					if outIdx != "" {
						docIndex = outIdx
					}
					if outID != "" {
						docID = outID
					}
					docRouting = outRt
					dropped = isDrop
					ingestMeta = nextMeta
					allProcResults = append(allProcResults, trace...)
				}
			}
		}

		if docErr == nil && !dropped && finalPipe != "" && finalPipe != "_none" {
			pipeSpec, exists := lookupPipe(finalPipe)
			if !exists {
				docErr = fmt.Errorf("pipeline with id [%s] does not exist", finalPipe)
			} else {
				executedPipelines = append(executedPipelines, finalPipe)
				out, outIdx, outID, _, outRt, isDrop, trace, _, pErr := applyIngestPipelineSpecWithNameAndRoutingAndIngestMeta(
					s, pipeSpec, finalPipe, docIndex, docID, docRouting, curBytes, verbose, ingestMeta,
				)
				if pErr != nil {
					docErr = pErr
				} else {
					curBytes = out
					if outIdx != "" {
						docIndex = outIdx
					}
					if outID != "" {
						docID = outID
					}
					docRouting = outRt
					dropped = isDrop
					allProcResults = append(allProcResults, trace...)
				}
			}
		}

		if docErr == nil && !dropped && compiledSchema != nil {
			if _, sErr := schema.ShredDocument(compiledSchema, docID, 1, false, curBytes); sErr != nil {
				docErr = sErr
			}
		}

		if docErr != nil {
			simResults = append(simResults, map[string]any{
				"pipelines": executedPipelines,
				"error": map[string]any{
					"type":   ingestSpecValidationErrorType(docErr),
					"reason": docErr.Error(),
				},
			})
			continue
		}
		if dropped {
			simResults = append(simResults, map[string]any{
				"pipelines": executedPipelines,
				"doc":       nil,
			})
			continue
		}

		var finalSource map[string]any
		_ = json.Unmarshal(curBytes, &finalSource)
		if finalSource == nil {
			finalSource = map[string]any{}
		}

		// Accumulate dynamic mapping additions for fields not in existingDeclaredProps
		inferSimulateMappingAdditions(finalSource, existingDeclaredProps, mappingAdditions)

		if executedPipelines == nil {
			executedPipelines = []string{}
		}
		docOut := map[string]any{
			"_index":   docIndex,
			"_id":      docID,
			"_version": "-3",
			"_source":  finalSource,
			"_ingest": map[string]any{
				"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			},
		}
		if docRouting != "" {
			docOut["_routing"] = docRouting
		}
		entry := map[string]any{
			"pipelines": executedPipelines,
			"doc":       docOut,
		}
		if verbose {
			entry["processor_results"] = allProcResults
		}
		simResults = append(simResults, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"pipeline_simulation": simResults,
		"mapping_addition": map[string]any{
			"properties": mappingAdditions,
		},
	})
}

func inferSimulateMappingAdditions(doc map[string]any, declared map[string]esast.FieldProperty, additions map[string]any) {
	for k, v := range doc {
		if v == nil {
			continue
		}
		if existingFP, isDeclared := declared[k]; isDeclared {
			if subMap, okM := v.(map[string]any); okM && (existingFP.Type == "" || existingFP.Type == "object" || existingFP.Type == "nested") {
				subAdd, _ := additions[k].(map[string]any)
				var subProps map[string]any
				if subAdd != nil {
					subProps, _ = subAdd["properties"].(map[string]any)
				}
				if subProps == nil {
					subProps = make(map[string]any)
				}
				inferSimulateMappingAdditions(subMap, existingFP.Properties, subProps)
				if len(subProps) > 0 {
					additions[k] = map[string]any{"properties": subProps}
				}
			}
			continue
		}
		if additions[k] != nil {
			continue
		}
		additions[k] = inferDynamicESFieldMapping(v)
	}
}

func inferDynamicESFieldMapping(v any) map[string]any {
	switch tv := v.(type) {
	case bool:
		return map[string]any{"type": "boolean"}
	case int, int64, int32, uint64:
		return map[string]any{"type": "long"}
	case float64:
		if !math.IsNaN(tv) && !math.IsInf(tv, 0) && tv == math.Trunc(tv) {
			return map[string]any{"type": "long"}
		}
		return map[string]any{"type": "float"}
	case string:
		if _, err := time.Parse(time.RFC3339, tv); err == nil {
			return map[string]any{"type": "date"}
		}
		return map[string]any{
			"type": "text",
			"fields": map[string]any{
				"keyword": map[string]any{
					"type":         "keyword",
					"ignore_above": 256,
				},
			},
		}
	case []any:
		for _, elem := range tv {
			if elem != nil {
				return inferDynamicESFieldMapping(elem)
			}
		}
		return map[string]any{"type": "keyword"}
	case map[string]any:
		subProps := make(map[string]any)
		inferSimulateMappingAdditions(tv, nil, subProps)
		return map[string]any{"properties": subProps}
	default:
		return map[string]any{"type": "keyword"}
	}
}

// handleScriptsContextRound57 implements `GET /_scripts/_context` (F9.4).
func (s *Server) handleScriptsContextRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	makeCtx := func(name, retType string) map[string]any {
		return map[string]any{
			"name": name,
			"methods": []any{
				map[string]any{
					"name":        "execute",
					"return_type": retType,
					"params":      []any{},
				},
			},
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"contexts": []any{
			makeCtx("score", "double"),
			makeCtx("filter", "boolean"),
			makeCtx("update", "void"),
			makeCtx("ingest", "void"),
			makeCtx("field", "void"),
			makeCtx("boolean_field", "boolean"),
			makeCtx("double_field", "double"),
			makeCtx("long_field", "long"),
			makeCtx("string_field", "String"),
			makeCtx("number_sort", "double"),
			makeCtx("string_sort", "String"),
			makeCtx("bucket_aggregation", "Object"),
			makeCtx("aggs_combine", "Object"),
			makeCtx("template", "BytesReference"),
		},
	})
}

// handleScriptsLanguagesRound57 implements `GET /_scripts/_languages` (F9.4).
func (s *Server) handleScriptsLanguagesRound57(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"types_allowed": []string{"inline", "stored"},
		"language_contexts": []any{
			map[string]any{
				"language": "painless",
				"contexts": []string{"score", "filter", "update", "ingest", "field", "boolean_field", "double_field", "long_field", "string_field", "number_sort", "string_sort", "bucket_aggregation", "aggs_combine"},
			},
			map[string]any{
				"language": "expression",
				"contexts": []string{"score", "filter", "number_sort", "bucket_aggregation"},
			},
			map[string]any{
				"language": "mustache",
				"contexts": []string{"template"},
			},
		},
	})
}

// handleFlushSyncedRound57 implements `POST/GET /_flush/synced` and `/{index}/_flush/synced` (F9.5).
func (s *Server) handleFlushSyncedRound57(w http.ResponseWriter, r *http.Request, rawIndex string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	if !s.ensureNoExplicitClosedTargetRound59(w, r, rawIndex) {
		return
	}
	var targets []string
	if rawIndex != "" && rawIndex != "*" && rawIndex != "_all" {
		var ok bool
		targets, ok = s.resolveMaintenanceTargetIndices(w, rawIndex)
		if !ok {
			return
		}
	} else {
		s.mu.RLock()
		for idx := range s.indices {
			targets = append(targets, idx)
		}
		s.mu.RUnlock()
		sort.Strings(targets)
	}
	if s.coalescer != nil {
		s.mu.RLock()
		tables := make([]string, 0, len(targets))
		for _, idx := range targets {
			if sch := s.indices[idx]; sch != nil {
				tables = append(tables, sch.DorisTable)
			}
		}
		s.mu.RUnlock()
		for _, tbl := range tables {
			_ = s.coalescer.FlushTable(r.Context(), tbl)
		}
	}
	resp := map[string]any{
		"_shards": map[string]any{
			"total":      len(targets),
			"successful": len(targets),
			"failed":     0,
		},
	}
	for _, idx := range targets {
		resp[idx] = map[string]any{
			"total":      1,
			"successful": 1,
			"failed":     0,
			"failures":   []any{},
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleFreezeIndexRound57 implements `POST /{index}/_freeze` and `POST /{index}/_unfreeze` (F9.5).
func (s *Server) handleFreezeIndexRound57(w http.ResponseWriter, r *http.Request, rawIndex string, freeze bool) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	targets, ok := s.resolveMaintenanceTargetIndices(w, rawIndex)
	if !ok {
		return
	}
	s.mu.Lock()
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	for _, idx := range targets {
		if s.indexCustomSettings[idx] == nil {
			s.indexCustomSettings[idx] = make(map[string]any)
		}
		if freeze {
			s.indexCustomSettings[idx]["frozen"] = "true"
		} else {
			delete(s.indexCustomSettings[idx], "frozen")
		}
	}
	s.mu.Unlock()
	s.persistIndexBatchRound59(r.Context(), targets)
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
	})
}

// handleTaskRethrottleRound57 implements `POST /_reindex/{task_id}/_rethrottle`,
// `POST /[index/]_update_by_query/{task_id}/_rethrottle`, and `POST /[index/]_delete_by_query/{task_id}/_rethrottle` (F9.5).
func (s *Server) handleTaskRethrottleRound57(w http.ResponseWriter, r *http.Request, rawIndex, taskID string) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" || !strings.Contains(taskID, ":") {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("malformed task id [%s]", taskID))
		return
	}
	if rawIndex != "" && rawIndex != "*" && rawIndex != "_all" {
		if _, ok := s.resolveMaintenanceTargetIndices(w, rawIndex); !ok {
			return
		}
	}
	rps := float64(-1)
	if rawRPS := strings.TrimSpace(r.URL.Query().Get("requests_per_second")); rawRPS != "" && rawRPS != "unlimited" {
		parsed, err := strconv.ParseFloat(rawRPS, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || (parsed <= 0 && parsed != -1) {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid [requests_per_second] value [%s]", rawRPS))
			return
		}
		rps = parsed
	}
	parts := strings.SplitN(taskID, ":", 2)
	nodeID := parts[0]
	idNum, _ := strconv.ParseInt(parts[1], 10, 64)
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": map[string]any{
			nodeID: map[string]any{
				"name":              nodeID,
				"transport_address": "127.0.0.1:9300",
				"host":              "127.0.0.1",
				"ip":                "127.0.0.1:9300",
				"roles":             []string{"data", "ingest", "master"},
				"tasks": map[string]any{
					taskID: map[string]any{
						"node":   nodeID,
						"id":     idNum,
						"type":   "transport",
						"action": "indices:data/write/bulk[s]",
						"status": map[string]any{
							"requests_per_second": rps,
						},
					},
				},
			},
		},
	})
}

// handleMigrationSystemFeaturesRound57 implements `GET/POST /_migration/system_features` (F9.5).
func (s *Server) handleMigrationSystemFeaturesRound57(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.mu.RLock()
		kibanaState := "MIGRATION_NEEDED"
		securityState := "NONE"
		if s.migrationSystemFeatures != nil {
			if s.migrationSystemFeatures["kibana"] {
				kibanaState = "NONE"
			}
			if s.migrationSystemFeatures["security"] {
				securityState = "NONE"
			}
		} else {
			kibanaState = "NONE"
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"features": []any{
				map[string]any{
					"feature_name":          "kibana",
					"minimum_index_version": "8.0.0",
					"migration_status":      kibanaState,
					"indices":               []any{},
				},
				map[string]any{
					"feature_name":          "security",
					"minimum_index_version": "8.0.0",
					"migration_status":      securityState,
					"indices":               []any{},
				},
			},
		})
	case http.MethodPost:
		var body map[string]any
		if r.ContentLength != 0 {
			var ok bool
			body, ok = parseJSONBody(w, r)
			if !ok {
				return
			}
		}
		s.mu.Lock()
		if s.migrationSystemFeatures == nil {
			s.migrationSystemFeatures = make(map[string]bool)
		}
		s.migrationSystemFeatures["kibana"] = true
		s.migrationSystemFeatures["security"] = true
		if fn, okF := body["feature_name"].(string); okF && fn != "" {
			s.migrationSystemFeatures[fn] = true
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"acknowledged": true,
			"features":     []string{"kibana", "security"},
		})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
	}
}
