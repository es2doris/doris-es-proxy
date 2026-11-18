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

package analysis

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultEvalPredicateScript evaluates Painless boolean predicates over `token.*`
// when Options.EvalPredicateScript is not provided by the caller.
// It supports boolean operators (`&&`, `||`, `!`), parentheses, comparisons
// (`==`, `!=`, `<`, `<=`, `>`, `>=`), `params.*`, `token.term` (including `.length()`,
// `.isEmpty()`, `.startsWith(...)`, `.endsWith(...)`, `.contains(...)`, and assignment
// `token.term = ...`), `token.position`, `token.positionIncrement`, `token.positionLength`,
// `token.startOffset`, `token.endOffset`, `token.type`, and `token.keyword`.
func DefaultEvalPredicateScript(script map[string]any, tok *TokenContext) (bool, error) {
	if tok == nil {
		return false, newIllegalArgError("token context is required for analysis script")
	}
	if script == nil {
		return false, newIllegalArgError("script is required")
	}
	src, _ := script["source"].(string)
	if src == "" {
		src, _ = script["inline"].(string)
	}
	src = strings.TrimSpace(src)
	if src == "" {
		return false, newIllegalArgError("script [source] is required")
	}
	var params map[string]any
	if pm, ok := script["params"].(map[string]any); ok {
		params = pm
	}

	// Support multi-statement scripts separated by ';' (e.g. `token.term += "x"; return true;`).
	stmts := splitScriptStatements(src)
	var lastVal any = false
	for _, rawStmt := range stmts {
		stmt := strings.TrimSpace(rawStmt)
		if stmt == "" {
			continue
		}
		if strings.HasPrefix(stmt, "return ") || stmt == "return" {
			expr := strings.TrimSpace(strings.TrimPrefix(stmt, "return"))
			p := &predParser{src: expr, tok: tok, params: params}
			val, err := p.parseExpr()
			if err != nil {
				return false, err
			}
			b, ok := val.(bool)
			if !ok {
				return false, newIllegalArgError(fmt.Sprintf("predicate script must return boolean, got [%T]", val))
			}
			return b, nil
		}
		if handled, err := tryExecTokenAssignment(stmt, tok, params); err != nil {
			return false, err
		} else if handled {
			lastVal = true
			continue
		}
		p := &predParser{src: stmt, tok: tok, params: params}
		val, err := p.parseExpr()
		if err != nil {
			return false, err
		}
		p.skipWS()
		if p.pos < len(p.src) {
			return false, newIllegalArgError(fmt.Sprintf("unexpected token in script at [%s]", p.src[p.pos:]))
		}
		lastVal = val
	}
	b, ok := lastVal.(bool)
	if !ok {
		return false, newIllegalArgError(fmt.Sprintf("predicate script must evaluate to boolean, got [%T]", lastVal))
	}
	return b, nil
}

func splitScriptStatements(src string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	escaped := false
	for _, r := range src {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if quote != 0 {
			cur.WriteRune(r)
			switch r {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			cur.WriteRune(r)
			continue
		}
		if r == ';' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func tryExecTokenAssignment(stmt string, tok *TokenContext, params map[string]any) (bool, error) {
	if strings.HasPrefix(stmt, "token.term") {
		rest := strings.TrimSpace(strings.TrimPrefix(stmt, "token.term"))
		if strings.HasPrefix(rest, "+=") {
			rhs := strings.TrimSpace(strings.TrimPrefix(rest, "+="))
			p := &predParser{src: rhs, tok: tok, params: params}
			val, err := p.parseExpr()
			if err != nil {
				return false, err
			}
			tok.Term += fmt.Sprintf("%v", val)
			return true, nil
		}
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
			rhs := strings.TrimSpace(strings.TrimPrefix(rest, "="))
			p := &predParser{src: rhs, tok: tok, params: params}
			val, err := p.parseExpr()
			if err != nil {
				return false, err
			}
			tok.Term = fmt.Sprintf("%v", val)
			return true, nil
		}
	}
	return false, nil
}

type predParser struct {
	src    string
	pos    int
	tok    *TokenContext
	params map[string]any
}

func (p *predParser) skipWS() {
	for p.pos < len(p.src) {
		r, sz := utf8.DecodeRuneInString(p.src[p.pos:])
		if !unicode.IsSpace(r) {
			break
		}
		p.pos += sz
	}
}

func (p *predParser) matchOp(op string) bool {
	p.skipWS()
	if strings.HasPrefix(p.src[p.pos:], op) {
		p.pos += len(op)
		return true
	}
	return false
}

func (p *predParser) parseExpr() (any, error) {
	return p.parseOr()
}

func (p *predParser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if !strings.HasPrefix(p.src[p.pos:], "||") {
			break
		}
		p.pos += 2
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		lb, ok1 := left.(bool)
		rb, ok2 := right.(bool)
		if !ok1 || !ok2 {
			return nil, newIllegalArgError("logical || requires boolean operands")
		}
		left = lb || rb
	}
	return left, nil
}

func (p *predParser) parseAnd() (any, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if !strings.HasPrefix(p.src[p.pos:], "&&") {
			break
		}
		p.pos += 2
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		lb, ok1 := left.(bool)
		rb, ok2 := right.(bool)
		if !ok1 || !ok2 {
			return nil, newIllegalArgError("logical && requires boolean operands")
		}
		left = lb && rb
	}
	return left, nil
}

func (p *predParser) parseComparison() (any, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if strings.HasPrefix(p.src[p.pos:], op) {
			p.pos += len(op)
			right, err := p.parseAdditive()
			if err != nil {
				return nil, err
			}
			return evalComparisonOp(op, left, right)
		}
	}
	return left, nil
}

func (p *predParser) parseAdditive() (any, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if p.pos >= len(p.src) {
			break
		}
		ch := p.src[p.pos]
		if ch != '+' && ch != '-' {
			break
		}
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if ch == '+' {
			if ls, ok := left.(string); ok {
				left = ls + fmt.Sprintf("%v", right)
				continue
			}
			if rs, ok := right.(string); ok {
				left = fmt.Sprintf("%v", left) + rs
				continue
			}
			li, ok1 := toFloat64Script(left)
			ri, ok2 := toFloat64Script(right)
			if !ok1 || !ok2 {
				return nil, newIllegalArgError("invalid operands to +")
			}
			left = li + ri
		} else {
			li, ok1 := toFloat64Script(left)
			ri, ok2 := toFloat64Script(right)
			if !ok1 || !ok2 {
				return nil, newIllegalArgError("invalid operands to -")
			}
			left = li - ri
		}
	}
	return left, nil
}

func (p *predParser) parseUnary() (any, error) {
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == '!' && !strings.HasPrefix(p.src[p.pos:], "!=") {
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		b, ok := v.(bool)
		if !ok {
			return nil, newIllegalArgError("logical ! requires boolean operand")
		}
		return !b, nil
	}
	if p.pos < len(p.src) && p.src[p.pos] == '-' {
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		f, ok := toFloat64Script(v)
		if !ok {
			return nil, newIllegalArgError("unary - requires numeric operand")
		}
		return -f, nil
	}
	return p.parsePrimary()
}

func (p *predParser) parsePrimary() (any, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, newIllegalArgError("unexpected end of script expression")
	}
	ch := p.src[p.pos]
	if ch == '(' {
		p.pos++
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if !p.matchOp(")") {
			return nil, newIllegalArgError("missing closing ')' in script expression")
		}
		return p.parsePostfix(val)
	}
	if ch == '"' || ch == '\'' {
		s, err := p.parseStringLiteral()
		if err != nil {
			return nil, err
		}
		return p.parsePostfix(s)
	}
	if ch >= '0' && ch <= '9' {
		start := p.pos
		hasDot := false
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if c >= '0' && c <= '9' {
				p.pos++
			} else if c == '.' && !hasDot {
				hasDot = true
				p.pos++
			} else {
				break
			}
		}
		raw := p.src[start:p.pos]
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, newIllegalArgError("invalid numeric literal: " + raw)
		}
		return f, nil
	}

	ident := p.readIdent()
	if ident == "" {
		return nil, newIllegalArgError("unexpected character in script: " + p.src[p.pos:])
	}
	switch ident {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "token":
		if !p.matchOp(".") {
			return nil, newIllegalArgError("expected '.' after token")
		}
		prop := p.readIdent()
		var val any
		switch prop {
		case "term":
			val = p.tok.Term
		case "position":
			val = float64(p.tok.Position)
		case "positionIncrement":
			val = float64(p.tok.PositionIncrement)
		case "positionLength":
			val = float64(p.tok.PositionLength)
		case "startOffset":
			val = float64(p.tok.StartOffset)
		case "endOffset":
			val = float64(p.tok.EndOffset)
		case "type":
			val = p.tok.Type
		case "keyword":
			val = p.tok.Keyword
		case "getTerm":
			if !p.matchOp("(") || !p.matchOp(")") {
				return nil, newIllegalArgError("expected () after token.getTerm")
			}
			val = p.tok.Term
		default:
			return nil, newIllegalArgError("unknown token property [" + prop + "]")
		}
		return p.parsePostfix(val)
	case "params":
		if p.matchOp(".") {
			key := p.readIdent()
			return p.parsePostfix(p.params[key])
		}
		if p.matchOp("[") {
			keyVal, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if !p.matchOp("]") {
				return nil, newIllegalArgError("missing ']' after params index")
			}
			return p.parsePostfix(p.params[fmt.Sprintf("%v", keyVal)])
		}
		return nil, newIllegalArgError("expected '.' or '[' after params")
	default:
		return nil, newIllegalArgError("unknown identifier [" + ident + "] in analysis script")
	}
}

func (p *predParser) parsePostfix(base any) (any, error) {
	cur := base
	for {
		p.skipWS()
		if !strings.HasPrefix(p.src[p.pos:], ".") {
			break
		}
		p.pos++
		method := p.readIdent()
		s, isStr := cur.(string)
		if !isStr {
			return nil, newIllegalArgError("method [" + method + "] called on non-string value")
		}
		if !p.matchOp("(") {
			if method == "length" {
				cur = float64(utf16RuneUnitLen(s))
				continue
			}
			return nil, newIllegalArgError("expected '(' after ." + method)
		}
		var args []any
		p.skipWS()
		if !strings.HasPrefix(p.src[p.pos:], ")") {
			for {
				arg, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, arg)
				if !p.matchOp(",") {
					break
				}
			}
		}
		if !p.matchOp(")") {
			return nil, newIllegalArgError("missing ')' in method call ." + method)
		}
		switch method {
		case "length":
			cur = float64(utf16RuneUnitLen(s))
		case "isEmpty":
			cur = len(s) == 0
		case "toLowerCase":
			cur = strings.ToLower(s)
		case "toUpperCase":
			cur = strings.ToUpper(s)
		case "startsWith":
			if len(args) != 1 {
				return nil, newIllegalArgError("startsWith expects 1 argument")
			}
			cur = strings.HasPrefix(s, fmt.Sprintf("%v", args[0]))
		case "endsWith":
			if len(args) != 1 {
				return nil, newIllegalArgError("endsWith expects 1 argument")
			}
			cur = strings.HasSuffix(s, fmt.Sprintf("%v", args[0]))
		case "contains":
			if len(args) != 1 {
				return nil, newIllegalArgError("contains expects 1 argument")
			}
			cur = strings.Contains(s, fmt.Sprintf("%v", args[0]))
		case "equals":
			if len(args) != 1 {
				return nil, newIllegalArgError("equals expects 1 argument")
			}
			cur = s == fmt.Sprintf("%v", args[0])
		default:
			return nil, newIllegalArgError("unsupported string method [" + method + "]")
		}
	}
	return cur, nil
}

func (p *predParser) parseStringLiteral() (string, error) {
	quote := p.src[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		r, sz := utf8.DecodeRuneInString(p.src[p.pos:])
		p.pos += sz
		if r == '\\' {
			if p.pos >= len(p.src) {
				return "", newIllegalArgError("unterminated escape in string literal")
			}
			nr, nsz := utf8.DecodeRuneInString(p.src[p.pos:])
			p.pos += nsz
			switch nr {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '"', '\'':
				b.WriteRune(nr)
			default:
				b.WriteRune(nr)
			}
			continue
		}
		if sz == 1 && p.src[p.pos-1] == quote {
			return b.String(), nil
		}
		b.WriteRune(r)
	}
	return "", newIllegalArgError("unterminated string literal in script")
}

func (p *predParser) readIdent() string {
	p.skipWS()
	start := p.pos
	for p.pos < len(p.src) {
		r, sz := utf8.DecodeRuneInString(p.src[p.pos:])
		if r == '_' || unicode.IsLetter(r) || (p.pos > start && unicode.IsDigit(r)) {
			p.pos += sz
		} else {
			break
		}
	}
	return p.src[start:p.pos]
}

func toFloat64Script(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	default:
		return 0, false
	}
}

func evalComparisonOp(op string, left, right any) (bool, error) {
	if lf, ok1 := toFloat64Script(left); ok1 {
		if rf, ok2 := toFloat64Script(right); ok2 {
			switch op {
			case "==":
				return lf == rf, nil
			case "!=":
				return lf != rf, nil
			case "<":
				return lf < rf, nil
			case "<=":
				return lf <= rf, nil
			case ">":
				return lf > rf, nil
			case ">=":
				return lf >= rf, nil
			}
		}
	}
	if ls, ok1 := left.(string); ok1 {
		if rs, ok2 := right.(string); ok2 {
			switch op {
			case "==":
				return ls == rs, nil
			case "!=":
				return ls != rs, nil
			case "<":
				return ls < rs, nil
			case "<=":
				return ls <= rs, nil
			case ">":
				return ls > rs, nil
			case ">=":
				return ls >= rs, nil
			}
		}
	}
	if lb, ok1 := left.(bool); ok1 {
		if rb, ok2 := right.(bool); ok2 {
			switch op {
			case "==":
				return lb == rb, nil
			case "!=":
				return lb != rb, nil
			}
		}
	}
	return false, newIllegalArgError(fmt.Sprintf("incompatible operand types for %s", op))
}

func utf16RuneUnitLen(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}
