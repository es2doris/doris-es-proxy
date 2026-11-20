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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ----------------------------------------------------------------------------
// Round 63 F10: Apache Doris 4.1.3 Strict-Cast & Nereids Typing in MemoryBackend
// ----------------------------------------------------------------------------

// checkStrictNereidsSQLTypesR63Mem rejects SQL expressions that Apache Doris 4.1.3 Nereids
// rejects at analysis time (`C-07`: `CONV(...) & mask` or `'literal' & mask` without an
// explicit `CAST(... AS BIGINT/INT/LARGEINT)` around the `VARCHAR` operand).
func checkStrictNereidsSQLTypesR63Mem(sqlStr string) error {
	// Scan outside SQL string literals and backticks for top-level `CONV(...)` directly
	// participating in `&` without an enclosing `CAST(` / `TRY_CAST(`.
	upper := strings.ToUpper(sqlStr)
	searchFrom := 0
	for {
		idx := strings.Index(upper[searchFrom:], "CONV(")
		if idx < 0 {
			break
		}
		absIdx := searchFrom + idx
		searchFrom = absIdx + len("CONV(")
		if absIdx > 0 && isIdentByteR63Mem(upper[absIdx-1]) {
			continue
		}
		if isOffsetInsideQuotesOrBackticksR63Mem(sqlStr, absIdx) {
			continue
		}
		closeParen := memFindMatchingParen(sqlStr, absIdx+len("CONV"))
		if closeParen < 0 {
			continue
		}
		// Check immediate non-space token after `CONV(...)` (skipping closing parens ONLY if
		// those parens were not preceded by `AS BIGINT)` / `AS LARGEINT)` / `AS INT)`).
		after := strings.TrimSpace(sqlStr[closeParen+1:])
		if strings.HasPrefix(after, "&") {
			return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: cannot resolve bitand(VARCHAR, BIGINT) in Doris 4.1.3 Nereids; wrap CONV(...) in CAST(... AS BIGINT)")
		}
		// Also check `mask & CONV(...)` before `absIdx`.
		before := strings.TrimSpace(sqlStr[:absIdx])
		for strings.HasSuffix(before, "(") {
			before = strings.TrimSpace(before[:len(before)-1])
		}
		if strings.HasSuffix(before, "&") {
			return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: cannot resolve bitand(BIGINT, VARCHAR) in Doris 4.1.3 Nereids; wrap CONV(...) in CAST(... AS BIGINT)")
		}
	}
	return nil
}

func isIdentByteR63Mem(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

func isOffsetInsideQuotesOrBackticksR63Mem(s string, target int) bool {
	inSingle := false
	inBacktick := false
	for i := 0; i < target && i < len(s); i++ {
		c := s[i]
		if inSingle {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inBacktick {
			if c == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '`':
			inBacktick = true
		}
	}
	return inSingle || inBacktick
}

// evalBitwiseAndStrictR63Mem evaluates `a & b [& c ...]` in `MemoryBackend`, rejecting raw
// `string` (`VARCHAR`) operands unless explicitly cast to an integer type (`C-07`).
func evalBitwiseAndStrictR63Mem(row map[string]any, parts []string) (float64, bool) {
	var acc int64
	for i, rawPart := range parts {
		p := trimOuterParens(strings.TrimSpace(rawPart))
		val, ok := evalStrictBitwiseOperandInt64R63Mem(row, p)
		if !ok {
			return math.NaN(), false
		}
		if i == 0 {
			acc = val
		} else {
			acc &= val
		}
	}
	return float64(acc), true
}

func evalStrictBitwiseOperandInt64R63Mem(row map[string]any, p string) (int64, bool) {
	p = trimOuterParens(strings.TrimSpace(p))
	if p == "" {
		return 0, false
	}
	if strings.HasPrefix(p, "'") && strings.HasSuffix(p, "'") {
		// Raw string literal in bitwise `&` is a Nereids type error!
		return 0, false
	}
	if iv, err := strconv.ParseInt(p, 10, 64); err == nil {
		return iv, true
	}
	if u, err := strconv.ParseUint(p, 10, 64); err == nil && u <= math.MaxInt64 {
		return int64(u), true
	}
	// Resolve as column/function expression first so `CONV(...)` returns `string` and gets rejected!
	v := resolveColumnValue(row, p)
	if v != nil {
		switch tv := v.(type) {
		case string:
			// Doris 4.1.3 Nereids rejects `VARCHAR & BIGINT` unless explicitly CAST!
			return 0, false
		case int:
			return int64(tv), true
		case int32:
			return int64(tv), true
		case int64:
			return tv, true
		case uint64:
			if tv <= math.MaxInt64 {
				return int64(tv), true
			}
			return 0, false
		case float64:
			if math.IsNaN(tv) || math.IsInf(tv, 0) {
				return 0, false
			}
			return int64(math.Trunc(tv)), true
		case json.Number:
			if iv, err := tv.Int64(); err == nil {
				return iv, true
			}
			return 0, false
		}
	}
	if isArithmeticSQLExpr(p) && !strings.HasPrefix(strings.ToUpper(p), "CONV(") {
		fv := evalNumericExpr(row, p)
		if math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, false
		}
		return int64(math.Trunc(fv)), true
	}
	return 0, false
}

// parseDorisJSONPathSegmentsR63Mem parses a Doris JSONPath (`$."a"."b"`, `$."a\"b\\c"`, `$.a.b`)
// into unescaped path segments (`C-13`).
func parseDorisJSONPathSegmentsR63Mem(rawPath string) []string {
	s := strings.TrimSpace(rawPath)
	if !strings.HasPrefix(s, "$") {
		if s == "" {
			return nil
		}
		return strings.Split(s, ".")
	}
	s = s[1:]
	if s == "" {
		return nil
	}
	var segs []string
	i := 0
	for i < len(s) {
		if s[i] == '.' {
			i++
			if i >= len(s) {
				break
			}
		}
		if s[i] == '"' {
			i++
			var sb strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					sb.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				sb.WriteByte(s[i])
				i++
			}
			segs = append(segs, sb.String())
		} else {
			start := i
			for i < len(s) && s[i] != '.' {
				i++
			}
			segs = append(segs, s[start:i])
		}
	}
	return segs
}

// extractJSONTypedValueFromStrR63Mem extracts the raw JSON-typed Go value (`[]any`, `map[string]any`,
// `string`, `json.Number`, `bool`, or `nil`) at `segs` WITHOUT flattening parent arrays, matching
// Doris 4.1.3 `json_extract(doc, path)` + `JSON_TYPE(...)` (`C-08`, `C-13`).
func extractJSONTypedValueFromStrR63Mem(rawJSON string, segs []string) (any, bool) {
	if strings.TrimSpace(rawJSON) == "" {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(rawJSON))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, false
	}
	curr := root
	for _, seg := range segs {
		m, ok := curr.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[seg]
		if !exists {
			return nil, false
		}
		curr = next
	}
	return curr, true
}

// dorisJSONTypeNameR63Mem returns Doris 4.1.3 `JSON_TYPE(val)` string (`'ARRAY'`, `'OBJECT'`,
// `'STRING'`, `'INTEGER'`, `'DOUBLE'`, `'BOOLEAN'`, `'NULL'`), or `nil` when SQL input is `NULL`.
func dorisJSONTypeNameR63Mem(v any, exists bool) any {
	if !exists {
		return nil
	}
	if v == nil {
		return "NULL"
	}
	switch tv := v.(type) {
	case []any, []string, []float64:
		return "ARRAY"
	case map[string]any:
		return "OBJECT"
	case bool:
		return "BOOLEAN"
	case int, int32, int64, uint64:
		return "INTEGER"
	case float64:
		return "DOUBLE"
	case json.Number:
		raw := tv.String()
		if strings.ContainsAny(raw, ".eE") {
			return "DOUBLE"
		}
		return "INTEGER"
	case string:
		return "STRING"
	default:
		return "STRING"
	}
}

// evalColumnFuncR63Mem evaluates Round-63 Doris 4.1.3 SQL scalar functions in `MemoryBackend`
// (`TRY_CAST`, `CAST(... AS DATETIMEV2(...))`, `JSON_TYPE`, `MICROSECOND`, `TRANSLATE`,
// `FROM_BASE64_BINARY`, `REGEXP_EXTRACT`).
func evalColumnFuncR63Mem(row map[string]any, colExpr string) (any, bool) {
	upper := strings.ToUpper(colExpr)

	// 1. `TRY_CAST(expr AS TYPE)` & `CAST(expr AS DATETIMEV2(p))`
	if strings.HasPrefix(upper, "TRY_CAST(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("TRY_CAST")) {
		innerAll := colExpr[len("TRY_CAST(") : len(colExpr)-1]
		return evalTryCastBodyR63Mem(row, innerAll), true
	}
	if strings.HasPrefix(upper, "CAST(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("CAST")) {
		innerAll := colExpr[len("CAST(") : len(colExpr)-1]
		asIdx := findTopLevelLastAsR63Mem(innerAll)
		if asIdx > 0 {
			targetType := strings.ToUpper(strings.TrimSpace(innerAll[asIdx+4:]))
			if strings.HasPrefix(targetType, "DATETIMEV2") || targetType == "DATETIME" {
				return evalCastDateTimeV2R63Mem(row, strings.TrimSpace(innerAll[:asIdx]), targetType), true
			}
		}
	}

	// 2. `JSON_TYPE(expr)`
	if strings.HasPrefix(upper, "JSON_TYPE(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("JSON_TYPE")) {
		arg := strings.TrimSpace(colExpr[len("JSON_TYPE(") : len(colExpr)-1])
		return evalDorisJSONTypeExprR63Mem(row, arg), true
	}

	// 3. `MICROSECOND(dt)`
	if strings.HasPrefix(upper, "MICROSECOND(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("MICROSECOND")) {
		arg := strings.TrimSpace(colExpr[len("MICROSECOND(") : len(colExpr)-1])
		dtVal := resolveColumnValue(row, arg)
		if dtVal == nil {
			return nil, true
		}
		_, _, _, _, _, _, ns, ok := memParseDateTimeWallClock(dtVal)
		if !ok {
			return nil, true
		}
		return int64(ns / 1000), true
	}

	// 4. `TRANSLATE(src, fromChars, toChars)`
	if strings.HasPrefix(upper, "TRANSLATE(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("TRANSLATE")) {
		args := splitTopLevelArgs(colExpr[len("TRANSLATE(") : len(colExpr)-1])
		if len(args) == 3 {
			sv := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if sv == nil {
				return nil, true
			}
			fromRunes := []rune(unquoteSQLLiteral(strings.TrimSpace(args[1])))
			toRunes := []rune(unquoteSQLLiteral(strings.TrimSpace(args[2])))
			srcStr := fmt.Sprintf("%v", sv)
			var sb strings.Builder
			sb.Grow(len(srcStr))
			for _, r := range srcStr {
				mapped := false
				replaced := rune(0)
				for idx, fr := range fromRunes {
					if fr == r {
						mapped = true
						if idx < len(toRunes) {
							replaced = toRunes[idx]
						}
						break
					}
				}
				if !mapped {
					sb.WriteRune(r)
				} else if replaced != 0 {
					sb.WriteRune(replaced)
				}
			}
			return sb.String(), true
		}
		return nil, true
	}

	// 5. `FROM_BASE64_BINARY(b64Str)`
	if strings.HasPrefix(upper, "FROM_BASE64_BINARY(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("FROM_BASE64_BINARY")) {
		inner := strings.TrimSpace(colExpr[len("FROM_BASE64_BINARY(") : len(colExpr)-1])
		sv := resolveColumnValue(row, inner)
		if sv == nil {
			return nil, true
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(fmt.Sprintf("%v", sv)))
		if err != nil {
			return nil, true
		}
		return b, true
	}

	// 6. `REGEXP_EXTRACT(str, pat, idx)`
	if strings.HasPrefix(upper, "REGEXP_EXTRACT(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("REGEXP_EXTRACT")) {
		args := splitTopLevelArgs(colExpr[len("REGEXP_EXTRACT(") : len(colExpr)-1])
		if len(args) == 3 {
			sv := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if sv == nil {
				return nil, true
			}
			pat := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			grpIdx := int(evalNumericExpr(row, strings.TrimSpace(args[2])))
			re, err := regexp.Compile(pat)
			if err != nil {
				return "", true
			}
			sub := re.FindStringSubmatch(fmt.Sprintf("%v", sv))
			if grpIdx >= 0 && grpIdx < len(sub) {
				return sub[grpIdx], true
			}
			return "", true
		}
		return nil, true
	}

	// 7. `REGEXP_REPLACE(str, pat, repl)`
	if strings.HasPrefix(upper, "REGEXP_REPLACE(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("REGEXP_REPLACE")) {
		args := splitTopLevelArgs(colExpr[len("REGEXP_REPLACE(") : len(colExpr)-1])
		if len(args) == 3 {
			sv := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if sv == nil {
				return nil, true
			}
			pat := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			repl := unquoteSQLLiteral(strings.TrimSpace(args[2]))
			re, err := regexp.Compile(pat)
			if err != nil {
				return fmt.Sprintf("%v", sv), true
			}
			return re.ReplaceAllString(fmt.Sprintf("%v", sv), repl), true
		}
		return nil, true
	}

	// 8. `ARRAY_JOIN(arrExpr, sepLit)`
	if strings.HasPrefix(upper, "ARRAY_JOIN(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("ARRAY_JOIN")) {
		args := splitTopLevelArgs(colExpr[len("ARRAY_JOIN(") : len(colExpr)-1])
		if len(args) >= 2 {
			av := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if av == nil {
				return nil, true
			}
			sep := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			return strings.Join(toStringSlice(av), sep), true
		}
		return nil, true
	}

	// 9. `OCTET_LENGTH(strExpr)` (byte length for `_size` metadata mapper)
	if strings.HasPrefix(upper, "OCTET_LENGTH(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("OCTET_LENGTH")) {
		arg := strings.TrimSpace(colExpr[len("OCTET_LENGTH(") : len(colExpr)-1])
		sv := resolveColumnValue(row, arg)
		if sv == nil {
			return nil, true
		}
		return int64(len(fmt.Sprintf("%v", sv))), true
	}

	// 10. `TRUNCATE(numExpr, scaleExpr)` (used by `scaled_float` sort `numeric_type: "long"`)
	if strings.HasPrefix(upper, "TRUNCATE(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("TRUNCATE")) {
		args := splitTopLevelArgs(colExpr[len("TRUNCATE(") : len(colExpr)-1])
		if len(args) == 2 {
			nv := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if nv == nil && isArithmeticSQLExpr(strings.TrimSpace(args[0])) {
				if !hasUnwrappedNullColumnRef(row, strings.TrimSpace(args[0])) {
					nv = evalNumericExpr(row, strings.TrimSpace(args[0]))
				}
			}
			if nv == nil {
				return nil, true
			}
			fv, ok := toFloat(nv)
			if !ok || math.IsNaN(fv) || math.IsInf(fv, 0) {
				return nil, true
			}
			scale := int(evalNumericExpr(row, strings.TrimSpace(args[1])))
			if scale == 0 {
				return math.Trunc(fv), true
			}
			pow := math.Pow(10, float64(scale))
			return math.Trunc(fv*pow) / pow, true
		}
		return nil, true
	}

	return nil, false
}

func findTopLevelLastAsR63Mem(s string) int {
	depth := 0
	inSingle := false
	inBacktick := false
	lastIdx := -1
	for i := 0; i <= len(s)-4; i++ {
		c := s[i]
		if inSingle {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inBacktick {
			if c == '`' {
				inBacktick = false
			}
			continue
		}
		if c == '\'' {
			inSingle = true
			continue
		}
		if c == '`' {
			inBacktick = true
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && strings.EqualFold(s[i:i+4], " AS ") {
			lastIdx = i
		}
	}
	return lastIdx
}

func evalTryCastBodyR63Mem(row map[string]any, innerAll string) any {
	asIdx := findTopLevelLastAsR63Mem(innerAll)
	if asIdx <= 0 {
		return nil
	}
	srcExpr := strings.TrimSpace(innerAll[:asIdx])
	targetType := strings.ToUpper(strings.TrimSpace(innerAll[asIdx+4:]))

	if strings.HasPrefix(targetType, "DATETIMEV2") || targetType == "DATETIME" {
		return evalCastDateTimeV2R63Mem(row, srcExpr, targetType)
	}

	v := resolveColumnValue(row, srcExpr)
	if v == nil {
		if strings.HasPrefix(srcExpr, "'") && strings.HasSuffix(srcExpr, "'") {
			v = unquoteSQLLiteral(srcExpr)
		} else if f, err := strconv.ParseFloat(srcExpr, 64); err == nil {
			v = f
		} else {
			return nil
		}
	}

	switch targetType {
	case "BIGINT", "INT":
		// Strict Doris `TRY_CAST(str AS BIGINT)`: ONLY valid signed integers (or exact integral numbers) succeed;
		// ISO-8601 date strings like `"2026-05-01T12:00:00Z"` return `NULL` cleanly without error!
		switch tv := v.(type) {
		case int:
			return int64(tv)
		case int32:
			return int64(tv)
		case int64:
			return tv
		case uint64:
			if tv <= math.MaxInt64 {
				return int64(tv)
			}
			return nil
		case float64:
			if math.IsNaN(tv) || math.IsInf(tv, 0) || tv < float64(math.MinInt64) || tv >= 9223372036854775808.0 {
				return nil
			}
			return int64(math.Trunc(tv))
		case json.Number:
			if iv, err := tv.Int64(); err == nil {
				return iv
			}
			return nil
		case string:
			trimmed := strings.TrimSpace(tv)
			if trimmed == "" {
				return nil
			}
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return iv
			}
			return nil
		default:
			return nil
		}
	case "LARGEINT":
		return memCoerceSQLLargeInt(v)
	case "DOUBLE", "FLOAT":
		switch tv := v.(type) {
		case string:
			trimmed := strings.TrimSpace(tv)
			if trimmed == "" {
				return nil
			}
			f, err := strconv.ParseFloat(trimmed, 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return nil
			}
			return f
		default:
			if f, ok := toFloat(tv); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
			return nil
		}
	case "BOOLEAN":
		if bv, ok := coerceSQLBool(v); ok {
			return bv
		}
		return nil
	case "STRING", "VARCHAR":
		return fmt.Sprintf("%v", v)
	case "ARRAY<STRING>":
		if s, ok := v.(string); ok {
			trimmed := strings.TrimSpace(s)
			if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
				return nil
			}
			var arr []any
			dec := json.NewDecoder(strings.NewReader(trimmed))
			dec.UseNumber()
			if err := dec.Decode(&arr); err != nil {
				return nil
			}
			return toStringSlice(arr)
		}
		return coerceCastArrayOfStringR62Mem(v)
	case "ARRAY<FLOAT>", "ARRAY<DOUBLE>":
		switch tv := v.(type) {
		case []float64:
			if len(tv) == 0 {
				return nil
			}
			return tv
		case []any:
			out := make([]float64, 0, len(tv))
			for _, el := range tv {
				switch ev := el.(type) {
				case float64:
					if math.IsNaN(ev) || math.IsInf(ev, 0) {
						return nil
					}
					out = append(out, ev)
				case int:
					out = append(out, float64(ev))
				case int64:
					out = append(out, float64(ev))
				case uint64:
					out = append(out, float64(ev))
				case json.Number:
					fv, err := ev.Float64()
					if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
						return nil
					}
					out = append(out, fv)
				default:
					return nil
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		case string:
			trimmed := strings.TrimSpace(tv)
			if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
				return nil
			}
			var arr []any
			dec := json.NewDecoder(strings.NewReader(trimmed))
			dec.UseNumber()
			if err := dec.Decode(&arr); err != nil || len(arr) == 0 {
				return nil
			}
			out := make([]float64, 0, len(arr))
			for _, el := range arr {
				switch ev := el.(type) {
				case float64:
					if math.IsNaN(ev) || math.IsInf(ev, 0) {
						return nil
					}
					out = append(out, ev)
				case json.Number:
					fv, err := ev.Float64()
					if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
						return nil
					}
					out = append(out, fv)
				default:
					return nil
				}
			}
			return out
		default:
			return nil
		}
	default:
		return resolveColumnValue(row, "CAST("+innerAll+")")
	}
}

func evalCastDateTimeV2R63Mem(row map[string]any, srcExpr, targetType string) any {
	v := resolveColumnValue(row, srcExpr)
	if v == nil {
		if strings.HasPrefix(srcExpr, "'") && strings.HasSuffix(srcExpr, "'") {
			v = unquoteSQLLiteral(srcExpr)
		} else {
			return nil
		}
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" {
		return nil
	}
	// Reject pure integer strings like `"1700000000123"` when casting to `DATETIMEV2` if > 8 digits without separators
	// unless valid `YYYY-MM-DD[ HH:MM:SS[.ffffff]]`.
	var parsed time.Time
	matched := false
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			parsed = t
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}
	scale := 6
	if strings.Contains(targetType, "(3)") {
		scale = 3
	} else if targetType == "DATETIME" || strings.Contains(targetType, "(0)") {
		scale = 0
	}
	switch scale {
	case 0:
		return parsed.UTC().Truncate(time.Second).Format("2006-01-02 15:04:05")
	case 3:
		return parsed.UTC().Truncate(time.Millisecond).Format("2006-01-02 15:04:05.000")
	default:
		return parsed.UTC().Truncate(time.Microsecond).Format("2006-01-02 15:04:05.000000")
	}
}

func evalDorisJSONTypeExprR63Mem(row map[string]any, arg string) any {
	arg = trimOuterParens(strings.TrimSpace(arg))
	if strings.HasPrefix(strings.ToLower(arg), "coalesce(") && strings.HasSuffix(arg, ")") && hasMatchingOuterParens(arg, len("coalesce")) {
		subArgs := splitTopLevelArgs(arg[len("coalesce(") : len(arg)-1])
		for _, sa := range subArgs {
			if jt := evalDorisJSONTypeExprR63Mem(row, sa); jt != nil {
				return jt
			}
		}
		return nil
	}
	if strings.HasPrefix(strings.ToLower(arg), "json_extract(") && strings.HasSuffix(arg, ")") && hasMatchingOuterParens(arg, len("json_extract")) {
		subArgs := splitTopLevelArgs(arg[len("json_extract(") : len(arg)-1])
		if len(subArgs) == 2 {
			varExpr := strings.TrimSpace(subArgs[0])
			varName := strings.Trim(varExpr, "`")
			rawPath := unquoteSQLLiteral(strings.TrimSpace(subArgs[1]))
			rawJSON := extractRowJSONStringR62Mem(row, varName)
			if rawJSON == "" {
				if rv := resolveColumnValue(row, varExpr); rv != nil {
					if s, ok := rv.(string); ok {
						rawJSON = s
					} else if jb, err := json.Marshal(rv); err == nil {
						rawJSON = string(jb)
					}
				}
			}
			segs := parseDorisJSONPathSegmentsR63Mem(rawPath)
			val, exists := extractJSONTypedValueFromStrR63Mem(rawJSON, segs)
			return dorisJSONTypeNameR63Mem(val, exists)
		}
	}
	v := resolveColumnValue(row, arg)
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		trimmed := strings.TrimSpace(s)
		var decoded any
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err == nil {
			return dorisJSONTypeNameR63Mem(decoded, true)
		}
	}
	return dorisJSONTypeNameR63Mem(v, true)
}

// hasNullArithmeticOperandR63Mem ensures SQL `NULL` propagates through arithmetic (`+`, `-`, `*`, `/`)
// when nested function calls such as `TRY_CAST(...)` or `UNIX_TIMESTAMP(DATE_TRUNC(NULL, ...))` evaluate to `nil`.
func hasNullArithmeticOperandR63Mem(row map[string]any, expr string) bool {
	trimmed := trimOuterParens(strings.TrimSpace(expr))
	if trimmed == "" || strings.Contains(trimmed, "CASE ") {
		return false
	}
	for _, op := range []byte{'+', '-', '*', '/', '%', '&'} {
		if parts := splitTopLevelBinaryMath(trimmed, op); len(parts) > 1 {
			for _, p := range parts {
				pt := trimOuterParens(strings.TrimSpace(p))
				if pt == "" {
					continue
				}
				if _, err := strconv.ParseFloat(pt, 64); err == nil {
					continue
				}
				if isArithmeticSQLExpr(pt) {
					if hasNullArithmeticOperandR63Mem(row, pt) {
						return true
					}
					// For function-rooted arithmetic expressions (`UNIX_TIMESTAMP(...)`, `FLOOR(...)`, etc.),
					// verify `resolveColumnValue` is non-nil when handled as a column function.
					if !hasTopLevelBinaryOpR63Mem(pt) {
						if resolveColumnValue(row, pt) == nil {
							return true
						}
					}
				} else if resolveColumnValue(row, pt) == nil {
					return true
				}
			}
			return false
		}
	}
	return false
}

func hasTopLevelBinaryOpR63Mem(s string) bool {
	trimmed := trimOuterParens(strings.TrimSpace(s))
	for _, op := range []byte{'+', '-', '*', '/', '%', '&'} {
		if len(splitTopLevelBinaryMath(trimmed, op)) > 1 {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// Round 63 F12: Corpus-Wide Lucene BM25 (`k1 = 1.2`, `b = 0.75`) in MemoryBackend
// ----------------------------------------------------------------------------

type bm25ClauseSpecR63Mem struct {
	placeholder   string
	safePred      string
	colExpr       string
	terms         []string
	caseSensitive bool
	boost         float64
	k1            float64
	bParam        float64
	idf           float64
	avgdl         float64
	docCount      int
}

var reBM25TailParamsR63Mem = regexp.MustCompile(`\+\s*([0-9.]+)\s*\*\s*\(([0-9.]+)\s*\+\s*([0-9.]+)\s*\*\s*\(GREATEST\(`)

// luceneSmallFloatLengthR63Mem implements Lucene 8+ `SmallFloat.intToByte4` -> `byte4ToInt`
// document length quantization used by `BM25Similarity.LENGTH_TABLE` (`0..40` are exact!).
func luceneSmallFloatLengthR63Mem(length int) int {
	if length <= 0 {
		return 0
	}
	if length < 40 {
		return length
	}
	if length > math.MaxInt32 {
		length = math.MaxInt32
	}
	// Lucene SmallFloat.intToByte4(i): shift = i - 32; 3 mantissa bits.
	// #nosec G115 -- length is bounded in [40, MaxInt32]
	shifted := uint32(length - 32)
	bitsLen := 32
	for tmp := shifted; tmp == 0; {
		break
	}
	msb := 0
	for tmp := shifted; tmp > 0; tmp >>= 1 {
		msb++
	}
	_ = bitsLen
	if msb <= 4 {
		return length
	}
	shift := uint(msb - 4)
	mantissa := (shifted >> shift) & 0x07
	decoded := ((mantissa | 0x08) << shift) + 24
	return int(decoded)
}

func tokenizeBM25TextStringR63Mem(s string, caseSensitive bool) []string {
	if !caseSensitive {
		s = strings.ToLower(s)
	}
	var out []string
	var cur strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func tokenizeBM25FieldTokensR63Mem(row map[string]any, colExpr string, caseSensitive bool) []string {
	v := resolveColumnValue(row, colExpr)
	if v == nil {
		return nil
	}
	var out []string
	for _, elem := range asSliceOrSingle(v) {
		if elem == nil {
			continue
		}
		s := fmt.Sprintf("%v", elem)
		if s == "" {
			continue
		}
		out = append(out, tokenizeBM25TextStringR63Mem(s, caseSensitive)...)
	}
	return out
}

func countBM25TermOrPhraseFreqR63Mem(docTokens, queryTerms []string) float64 {
	if len(docTokens) == 0 || len(queryTerms) == 0 {
		return 0
	}
	if len(queryTerms) == 1 {
		target := queryTerms[0]
		var cnt int
		for _, dt := range docTokens {
			if dt == target {
				cnt++
			}
		}
		return float64(cnt)
	}
	m := len(queryTerms)
	if len(docTokens) < m {
		return 0
	}
	var cnt int
	for i := 0; i <= len(docTokens)-m; i++ {
		match := true
		for j := 0; j < m; j++ {
			if docTokens[i+j] != queryTerms[j] {
				match = false
				break
			}
		}
		if match {
			cnt++
		}
	}
	return float64(cnt)
}

func extractBM25ClauseSpecR63Mem(clause string) (bm25ClauseSpecR63Mem, bool) {
	if !strings.Contains(clause, "'[^[:alnum:]_]+', '  '") {
		return bm25ClauseSpecR63Mem{}, false
	}
	trimmed := strings.TrimSpace(clause)
	if !strings.HasPrefix(trimmed, "(CASE WHEN ") || !strings.HasSuffix(trimmed, " ELSE 0.0 END)") {
		return bm25ClauseSpecR63Mem{}, false
	}
	inner := trimmed[len("(CASE WHEN ") : len(trimmed)-len(" ELSE 0.0 END)")]
	thenIdx := findTopLevelOp(inner, " THEN ")
	if thenIdx <= 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	safePred := strings.TrimSpace(inner[:thenIdx])
	thenBody := trimOuterParens(strings.TrimSpace(inner[thenIdx+len(" THEN "):]))

	// Leading `<boost> * (...)`
	mulIdx := strings.Index(thenBody, " * (GREATEST(CAST(CHAR_LENGTH(CONCAT(' ', REGEXP_REPLACE(")
	if mulIdx <= 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	boost, errB := strconv.ParseFloat(strings.TrimSpace(thenBody[:mulIdx]), 64)
	if errB != nil {
		return bm25ClauseSpecR63Mem{}, false
	}

	rrMarker := "REGEXP_REPLACE("
	rrIdx := strings.Index(thenBody[mulIdx:], rrMarker)
	if rrIdx < 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	rrOpen := mulIdx + rrIdx + len("REGEXP_REPLACE")
	rrClose := memFindMatchingParen(thenBody, rrOpen)
	if rrClose < 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	rrArgs := splitTopLevelArgs(thenBody[rrOpen+1 : rrClose])
	if len(rrArgs) != 3 {
		return bm25ClauseSpecR63Mem{}, false
	}
	strCol := strings.TrimSpace(rrArgs[0])
	caseSensitive := true
	if strings.HasPrefix(strCol, "LOWER(") && strings.HasSuffix(strCol, ")") && hasMatchingOuterParens(strCol, len("LOWER")) {
		caseSensitive = false
		strCol = strings.TrimSpace(strCol[len("LOWER(") : len(strCol)-1])
	}
	const coalPrefix = "COALESCE(CAST("
	const coalSuffix = " AS STRING), '')"
	if !strings.HasPrefix(strCol, coalPrefix) || !strings.HasSuffix(strCol, coalSuffix) {
		return bm25ClauseSpecR63Mem{}, false
	}
	colExpr := strings.TrimSpace(strCol[len(coalPrefix) : len(strCol)-len(coalSuffix)])

	// Extract `<patLit>` from `REPLACE(CONCAT(' ', REGEXP_REPLACE(...), ' '), <patLit>, '')`
	replMarker := "CHAR_LENGTH(REPLACE("
	replIdx := strings.Index(thenBody[rrClose:], replMarker)
	if replIdx < 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	replOpen := rrClose + replIdx + len("CHAR_LENGTH(REPLACE")
	replClose := memFindMatchingParen(thenBody, replOpen)
	if replClose < 0 {
		return bm25ClauseSpecR63Mem{}, false
	}
	replArgs := splitTopLevelArgs(thenBody[replOpen+1 : replClose])
	if len(replArgs) != 3 {
		return bm25ClauseSpecR63Mem{}, false
	}
	rawPat := unquoteSQLLiteral(strings.TrimSpace(replArgs[1]))
	var terms []string
	for _, tk := range strings.Split(strings.TrimSpace(rawPat), "  ") {
		if tk != "" {
			terms = append(terms, tk)
		}
	}
	if len(terms) == 0 {
		return bm25ClauseSpecR63Mem{}, false
	}

	k1 := 1.2
	bParam := 0.75
	if m := reBM25TailParamsR63Mem.FindStringSubmatch(thenBody[replClose:]); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			k1 = v
		}
		if v, err := strconv.ParseFloat(m[3], 64); err == nil {
			bParam = v
		}
	}

	return bm25ClauseSpecR63Mem{
		safePred:      safePred,
		colExpr:       colExpr,
		terms:         terms,
		caseSensitive: caseSensitive,
		boost:         boost,
		k1:            k1,
		bParam:        bParam,
	}, true
}

type legacySimpleScoreCtxKeyR63 struct{}

// prepareScoreEvaluatorR63Mem precomputes corpus-wide `(N, df, avgdl)` over `tbl` for all
// BM25 text clauses inside `scoreExpr`, returning a fast per-row evaluator (`F12`).
func prepareScoreEvaluatorR63Mem(ctx context.Context, tbl map[string]map[string]any, scoreExpr string) func(row map[string]any) float64 {
	if (ctx != nil && ctx.Value(legacySimpleScoreCtxKeyR63{}) != nil) || !strings.Contains(scoreExpr, "'[^[:alnum:]_]+', '  '") || len(tbl) == 0 {
		return func(row map[string]any) float64 {
			return evalNumericExpr(row, scoreExpr)
		}
	}

	var specs []bm25ClauseSpecR63Mem
	rewritten := scoreExpr
	searchPos := 0
	for searchPos < len(rewritten) {
		relIdx := strings.Index(rewritten[searchPos:], "(CASE WHEN ")
		if relIdx < 0 {
			break
		}
		openIdx := searchPos + relIdx
		closeIdx := memFindMatchingParen(rewritten, openIdx)
		if closeIdx < 0 {
			break
		}
		cand := rewritten[openIdx : closeIdx+1]
		if spec, ok := extractBM25ClauseSpecR63Mem(cand); ok {
			ph := fmt.Sprintf("__bm25_%d", len(specs))
			spec.placeholder = ph
			specs = append(specs, spec)
			ref := "`" + ph + "`"
			rewritten = rewritten[:openIdx] + ref + rewritten[closeIdx+1:]
			searchPos = openIdx + len(ref)
			continue
		}
		searchPos = openIdx + len("(CASE WHEN ")
	}

	if len(specs) == 0 {
		return func(row map[string]any) float64 {
			return evalNumericExpr(row, scoreExpr)
		}
	}

	// Precompute corpus `(N, avgdl, idf)` per BM25 clause across all live rows in `tbl`.
	liveRows := make([]map[string]any, 0, len(tbl))
	for _, r := range tbl {
		if !isTombstoneRow(r) {
			liveRows = append(liveRows, r)
		}
	}

	for idx := range specs {
		sp := &specs[idx]
		var docCount int
		var sumDL int
		dfs := make([]int, len(sp.terms))

		for _, r := range liveRows {
			toks := tokenizeBM25FieldTokensR63Mem(r, sp.colExpr, sp.caseSensitive)
			predMatched := len(sp.terms) == 1 && evalWhereExpr(r, sp.safePred)
			if len(toks) == 0 && !predMatched {
				continue
			}
			docCount++
			dl := len(toks)
			if dl == 0 {
				dl = 1
			}
			sumDL += luceneSmallFloatLengthR63Mem(dl)
			for ti, qTok := range sp.terms {
				found := false
				for _, dt := range toks {
					if dt == qTok {
						found = true
						break
					}
				}
				if !found && len(sp.terms) == 1 && predMatched {
					found = true
				}
				if found {
					dfs[ti]++
				}
			}
		}

		sp.docCount = docCount
		if docCount > 0 {
			sp.avgdl = float64(sumDL) / float64(docCount)
			if sp.avgdl <= 0 {
				sp.avgdl = 1.0
			}
			var idfSum float64
			for _, df := range dfs {
				if df <= 0 {
					df = 1
				}
				idfSum += math.Log(1.0 + (float64(docCount)-float64(df)+0.5)/(float64(df)+0.5))
			}
			sp.idf = idfSum
		}
	}

	singleDirect := len(specs) == 1 && strings.TrimSpace(rewritten) == "`"+specs[0].placeholder+"`"
	evalClauseOnRow := func(sp *bm25ClauseSpecR63Mem, row map[string]any) float64 {
		if sp.docCount == 0 || sp.boost == 0 || !evalWhereExpr(row, sp.safePred) {
			return 0.0
		}
		docToks := tokenizeBM25FieldTokensR63Mem(row, sp.colExpr, sp.caseSensitive)
		tf := countBM25TermOrPhraseFreqR63Mem(docToks, sp.terms)
		if tf < 1.0 {
			tf = 1.0
		}
		dl := len(docToks)
		if dl < 1 {
			dl = 1
		}
		dlNorm := float64(luceneSmallFloatLengthR63Mem(dl))
		tfNorm := tf / (tf + sp.k1*(1.0-sp.bParam+sp.bParam*(dlNorm/sp.avgdl)))
		return sp.boost * sp.idf * tfNorm
	}

	if singleDirect {
		sp0 := specs[0]
		return func(row map[string]any) float64 {
			return evalClauseOnRow(&sp0, row)
		}
	}

	return func(row map[string]any) float64 {
		cp := make(map[string]any, len(row)+len(specs))
		for k, v := range row {
			cp[k] = v
		}
		for i := range specs {
			cp[specs[i].placeholder] = evalClauseOnRow(&specs[i], row)
		}
		return evalNumericExpr(cp, rewritten)
	}
}

func prepareScoreEvaluatorFromRowSliceR63Mem(rows []map[string]any, scoreExpr string) func(row map[string]any) float64 {
	if !strings.Contains(scoreExpr, "'[^[:alnum:]_]+', '  '") || len(rows) == 0 {
		return func(row map[string]any) float64 {
			return evalNumericExpr(row, scoreExpr)
		}
	}
	syntheticTbl := make(map[string]map[string]any, len(rows))
	for i, r := range rows {
		id := fmt.Sprintf("%v", r["_id"])
		if id == "" || id == "<nil>" {
			id = strconv.Itoa(i)
		}
		syntheticTbl[id] = r
	}
	return prepareScoreEvaluatorR63Mem(context.Background(), syntheticTbl, scoreExpr)
}

// ----------------------------------------------------------------------------
// Round 63 F11: `aggregate_metric_double` & `counted_terms` Aggregation Branches
// ----------------------------------------------------------------------------

var (
	reR63AggMetricDoubleAvgTop = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_metric|_stats_avg)' AS `_bucket_key`, CAST\\(COALESCE\\(SUM\\((`[^`]+`)\\) / NULLIF\\(SUM\\(CAST\\((`[^`]+`) AS DOUBLE\\)\\), 0\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reR63AggMetricDoubleAvgSub = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\(COALESCE\\(SUM\\((`[^`]+`)\\) / NULLIF\\(SUM\\(CAST\\((`[^`]+`) AS DOUBLE\\)\\), 0\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?) GROUP BY `_bucket_key`$")
	reR63CountedTermsExprTop   = regexp.MustCompile(`^SELECT ` + "`_agg_name`, `_bucket_key`, `_doc_count` FROM \\(SELECT '([^']+)' AS `_agg_name`, CAST\\((.+?) AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\((.+?)\\) `_t` AS `_elem` WHERE (?:\\((.+)\\) AND )?`_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)\\) `_agg_sub_\\d+`$")
	reR63CountedTermsExprSub   = regexp.MustCompile(`^SELECT ` + "`_agg_name`, `_bucket_key`, `_doc_count` FROM \\(SELECT '([^']+)' AS `_agg_name`, CONCAT_WS\\('\\\\x1f', CAST\\((.+?) AS STRING\\), CAST\\((.+?) AS STRING\\)\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM (.+?) LATERAL VIEW EXPLODE\\((.+?)\\) `_sub_t[^`]*` AS (`_sub_elem[^`]*`) WHERE \\((.+)\\) AND `_sub_elem[^`]*` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)\\) `_agg_sub_\\d+`$")
)

func evalRound63AggBranchR63Mem(
	baseRows []map[string]any,
	branch string,
	filterHaving func([]AggRow) []AggRow,
) ([]AggRow, bool) {
	if m := reR63AggMetricDoubleAvgTop.FindStringSubmatch(branch); m != nil {
		aggName, bKey, sumCol, cntCol, extraWhere := m[1], m[2], m[3], m[4], m[5]
		var sumVal float64
		var cntVal int64
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			sv := resolveColumnValue(row, sumCol)
			cv := resolveColumnValue(row, cntCol)
			if sv == nil || cv == nil {
				continue
			}
			sf, okS := toFloat(sv)
			ci, okC := toInt64(cv)
			if okS && okC && ci > 0 {
				sumVal += sf
				cntVal += ci
			}
		}
		if cntVal <= 0 {
			if bKey == "_metric" {
				return nil, true
			}
			return []AggRow{{AggName: aggName, BucketKey: bKey, Weight: -1}}, true
		}
		avgVal := sumVal / float64(cntVal)
		return filterHaving([]AggRow{{
			AggName:   aggName,
			BucketKey: bKey,
			DocCount:  int64(avgVal),
			Value:     avgVal,
			Weight:    cntVal,
		}}), true
	}

	if m := reR63AggMetricDoubleAvgSub.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr, sumCol, cntCol, fromClause, whereClause := m[1], m[2], m[3], m[4], m[5], m[6]
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		type sumCnt struct {
			sum float64
			cnt int64
		}
		byBucket := make(map[string]*sumCnt)
		var keys []string
		for _, row := range expanded {
			sv := resolveColumnValue(row, sumCol)
			cv := resolveColumnValue(row, cntCol)
			if sv == nil || cv == nil {
				continue
			}
			sf, okS := toFloat(sv)
			ci, okC := toInt64(cv)
			if !okS || !okC || ci <= 0 {
				continue
			}
			for _, bk := range evalBucketKeyExprs(row, parentBucketExpr) {
				if bk == "" {
					continue
				}
				entry, exists := byBucket[bk]
				if !exists {
					entry = &sumCnt{}
					byBucket[bk] = entry
					keys = append(keys, bk)
				}
				entry.sum += sf
				entry.cnt += ci
			}
		}
		sort.Strings(keys)
		rows := make([]AggRow, 0, len(keys))
		for _, bk := range keys {
			sc := byBucket[bk]
			if sc.cnt <= 0 {
				continue
			}
			avgVal := sc.sum / float64(sc.cnt)
			rows = append(rows, AggRow{
				AggName:   aggName,
				BucketKey: bk,
				DocCount:  int64(avgVal),
				Value:     avgVal,
				Weight:    sc.cnt,
			})
		}
		return filterHaving(rows), true
	}

	if m := reR63CountedTermsExprTop.FindStringSubmatch(branch); m != nil {
		aggName, elemExpr, explodeExpr, extraWhere := m[1], m[2], m[3], m[4]
		limit, _ := strconv.Atoi(m[5])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			var elems []string
			if strings.HasPrefix(explodeExpr, "`") && strings.HasSuffix(explodeExpr, "`") {
				elems = toStringSlice(row[strings.Trim(explodeExpr, "`")])
			} else {
				elems = toStringSlice(resolveColumnValue(row, explodeExpr))
			}
			for _, elem := range elems {
				if elem == "" {
					continue
				}
				valStr := elem
				if elemExpr != "`_elem`" {
					cp := make(map[string]any, len(row)+1)
					for k, v := range row {
						cp[k] = v
					}
					cp["_elem"] = elem
					if v := resolveColumnValue(cp, elemExpr); v != nil {
						valStr = fmt.Sprintf("%v", v)
					} else {
						valStr = ""
					}
				}
				if valStr != "" {
					counts[valStr]++
				}
			}
		}
		rows := filterHaving(topBuckets(aggName, counts, 0))
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		return rows, true
	}

	if m := reR63CountedTermsExprSub.FindStringSubmatch(branch); m != nil {
		aggName, parentExpr, elemExpr, fromClause, explodeExpr, elemAlias, whereClause := m[1], m[2], m[3], m[4], m[5], m[6], m[7]
		limit, _ := strconv.Atoi(m[8])
		elemKey := strings.Trim(elemAlias, "`")
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		counts := make(map[string]int64)
		for _, row := range expanded {
			var elems []string
			if strings.HasPrefix(explodeExpr, "`") && strings.HasSuffix(explodeExpr, "`") {
				elems = toStringSlice(row[strings.Trim(explodeExpr, "`")])
			} else {
				elems = toStringSlice(resolveColumnValue(row, explodeExpr))
			}
			parentKeys := evalBucketKeyExprs(row, parentExpr)
			for _, pk := range parentKeys {
				if pk == "" {
					continue
				}
				for _, elem := range elems {
					if elem == "" {
						continue
					}
					valStr := elem
					if elemExpr != elemAlias {
						cp := make(map[string]any, len(row)+1)
						for k, v := range row {
							cp[k] = v
						}
						cp[elemKey] = elem
						if v := resolveColumnValue(cp, elemExpr); v != nil {
							valStr = fmt.Sprintf("%v", v)
						} else {
							valStr = ""
						}
					}
					if valStr != "" {
						counts[pk+"\x1f"+valStr]++
					}
				}
			}
		}
		rows := filterHaving(topBuckets(aggName, counts, 0))
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		return rows, true
	}

	return nil, false
}

var reDDLStringColumnR63Mem = regexp.MustCompile("(?i)`([a-zA-Z0-9_]+)`\\s+(?:VARCHAR\\s*\\(\\s*\\d+\\s*\\)|STRING\\b)")

// recordDDLStringColumnsR63Mem records `VARCHAR(...)` and `STRING` column definitions from
// `CREATE TABLE` and `ALTER TABLE ... ADD COLUMN` DDL statements so `StreamLoad` coerces
// scalar `json.Number` / `bool` values into `string` matching Doris 4.1.3 `VARCHAR` storage (`30_multi_fields.yml`).
func recordDDLStringColumnsR63Mem(stringCols map[string]map[string]bool, ddl string) {
	if stringCols == nil {
		return
	}
	upper := strings.ToUpper(strings.TrimSpace(ddl))
	tbl := extractTableNameFromDDL(ddl)
	if tbl == "" {
		return
	}
	if strings.HasPrefix(upper, "DROP TABLE") {
		delete(stringCols, tbl)
		return
	}
	if !strings.HasPrefix(upper, "CREATE TABLE") && !strings.HasPrefix(upper, "ALTER TABLE") {
		return
	}
	if stringCols[tbl] == nil {
		stringCols[tbl] = make(map[string]bool)
	}
	for _, m := range reDDLStringColumnR63Mem.FindAllStringSubmatch(ddl, -1) {
		col := m[1]
		if col == "_doc" {
			continue
		}
		stringCols[tbl][col] = true
	}
}

func coerceRowStringColumnsR63Mem(row map[string]any, strCols map[string]bool) {
	if len(row) == 0 || len(strCols) == 0 {
		return
	}
	for col := range strCols {
		v, exists := row[col]
		if !exists || v == nil {
			continue
		}
		switch tv := v.(type) {
		case string, []any, []string, map[string]any:
			continue
		case json.Number:
			row[col] = tv.String()
		default:
			row[col] = fmt.Sprintf("%v", tv)
		}
	}
}
