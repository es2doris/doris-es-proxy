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

var (
	reNereidsFromBaseMatchedR65 = regexp.MustCompile("(?i)\\bFROM\\s+`?base_matched`?(?:\\s|$|\\)|,|;)")
	reNereidsMatchFuncR65       = regexp.MustCompile(`(?i)\bMATCH_(?:ALL|ANY|PHRASE|PHRASE_PREFIX|REGEXP|BOOL_PREFIX)\b`)
	reNereidsScoreCallR65       = regexp.MustCompile(`(?i)\bscore\s*\(\s*\)`)
	reNereidsOrderByR65         = regexp.MustCompile(`(?i)\bORDER\s+BY\b`)
	reNereidsCastCoalesceR65    = regexp.MustCompile(`(?i)\bCAST\s*\(\s*COALESCE\s*\(`)
)

// checkStrictNereidsSQLTypesR63Mem rejects SQL expressions that Apache Doris 4.1.3 Nereids
// rejects at analysis time (`C-07`: `CONV(...) & mask` or `'literal' & mask` without an
// explicit `CAST(... AS BIGINT/INT/LARGEINT)` around the `VARCHAR` operand), 1-arg `JSON_TYPE`,
// `MATCH_*` in projections/`CAST(COALESCE(...))`/`FROM base_matched`, `score()` in `base_matched`
// consumers, unparenthesized `ORDER BY` inside `UNION ALL` branches, and invalid strict scalar casts.
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
	// Enforce Doris 4.1.3 2-argument `JSON_TYPE(doc, path)` signature across all SQL expressions.
	searchFrom = 0
	for {
		idx := strings.Index(upper[searchFrom:], "JSON_TYPE(")
		if idx < 0 {
			break
		}
		absIdx := searchFrom + idx
		searchFrom = absIdx + len("JSON_TYPE(")
		if absIdx > 0 && isIdentByteR63Mem(upper[absIdx-1]) {
			continue
		}
		if isOffsetInsideQuotesOrBackticksR63Mem(sqlStr, absIdx) {
			continue
		}
		argCount := countTopLevelSQLCallArgsR64Mem(sqlStr, absIdx+len("JSON_TYPE"))
		if argCount >= 0 && argCount != 2 {
			return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: Can not found function 'json_type' with %d arguments in Doris 4.1.3 Nereids; use JSON_TYPE(doc, path)", argCount)
		}
	}
	// Reject `MATCH_*` inside `CAST(COALESCE(...))` and `SELECT` projections.
	if hasMatchInCastCoalesceR65Mem(sqlStr) {
		return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: MATCH predicate cannot appear inside CAST(COALESCE(...)) in Doris 4.1.3 Nereids")
	}
	if hasMatchInSelectProjectionR65Mem(sqlStr) {
		return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: MATCH predicate is not allowed in SELECT projection list in Doris 4.1.3 Nereids")
	}
	// Reject `MATCH_*` and `score()` inside `FROM base_matched` consumers.
	for _, seg := range extractFromBaseMatchedSegmentsR65Mem(sqlStr) {
		if reNereidsMatchFuncR65.MatchString(seg) {
			return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: MATCH predicate cannot reference CTE base_matched in Doris 4.1.3 Nereids")
		}
		if reNereidsScoreCallR65.MatchString(seg) {
			return fmt.Errorf("errCode = 2, detailMessage = Unexpected exception: score() cannot reference CTE base_matched in Doris 4.1.3 Nereids")
		}
	}
	// Reject unparenthesized `ORDER BY` inside `UNION ALL` branches.
	if hasUnparenthesizedOrderByInUnionAllR65Mem(sqlStr) {
		return fmt.Errorf("errCode = 2, detailMessage = Syntax error: unparenthesized ORDER BY inside UNION ALL branch in Doris 4.1.3 Nereids")
	}
	// Reject invalid string literals inside strict scalar `CAST('<lit>' AS DOUBLE|FLOAT|LARGEINT|BIGINT|INT)`.
	if err := checkStaticStrictCastLiteralsR65Mem(sqlStr); err != nil {
		return err
	}
	return nil
}

func blankQuotedAndBacktickedR65Mem(s string, keepBackticks bool) string {
	var b strings.Builder
	b.Grow(len(s))
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inS {
			b.WriteByte(' ')
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(' ')
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte(' ')
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			b.WriteByte(' ')
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(' ')
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if keepBackticks {
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
			if c == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					if keepBackticks {
						b.WriteByte('`')
					} else {
						b.WriteByte(' ')
					}
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
			b.WriteByte(' ')
		case '"':
			inD = true
			b.WriteByte(' ')
		case '`':
			inB = true
			if keepBackticks {
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func findSelectStartBackwardR65Mem(masked string, fromPos int) int {
	depth := 0
	for i := fromPos - 1; i >= 0; i-- {
		switch masked[i] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				return i + 1
			}
			depth--
		default:
			if depth == 0 && i+6 <= fromPos && strings.EqualFold(masked[i:i+6], "SELECT") {
				prevOK := i == 0 || !isIdentByteR63Mem(masked[i-1])
				nextOK := i+6 == fromPos || !isIdentByteR63Mem(masked[i+6])
				if prevOK && nextOK {
					return i
				}
			}
		}
	}
	return 0
}

func extractFromBaseMatchedSegmentsR65Mem(sqlStr string) []string {
	maskedNoStrings := blankQuotedAndBacktickedR65Mem(sqlStr, true)
	locs := reNereidsFromBaseMatchedR65.FindAllStringIndex(maskedNoStrings, -1)
	if len(locs) == 0 {
		return nil
	}
	maskedAll := blankQuotedAndBacktickedR65Mem(sqlStr, false)
	segs := make([]string, 0, len(locs))
	for _, loc := range locs {
		startIdx := findSelectStartBackwardR65Mem(maskedAll, loc[0])
		depth := 0
		endIdx := len(maskedAll)
		for i := loc[1]; i < len(maskedAll); i++ {
			switch maskedAll[i] {
			case '(':
				depth++
			case ')':
				if depth == 0 {
					endIdx = i
					goto doneSeg
				}
				depth--
			}
		}
	doneSeg:
		segs = append(segs, maskedAll[startIdx:loc[0]]+" "+maskedAll[loc[1]:endIdx])
	}
	return segs
}

func hasMatchInCastCoalesceR65Mem(sqlStr string) bool {
	if !reNereidsMatchFuncR65.MatchString(sqlStr) {
		return false
	}
	masked := blankQuotedAndBacktickedR65Mem(sqlStr, false)
	searchFrom := 0
	for searchFrom < len(masked) {
		loc := reNereidsCastCoalesceR65.FindStringIndex(masked[searchFrom:])
		if loc == nil {
			return false
		}
		castStart := searchFrom + loc[0]
		openIdx := strings.IndexByte(masked[castStart:], '(')
		if openIdx < 0 {
			return false
		}
		closeIdx := memFindMatchingParen(sqlStr, castStart+openIdx)
		if closeIdx < 0 {
			searchFrom = castStart + openIdx + 1
			continue
		}
		if reNereidsMatchFuncR65.MatchString(masked[castStart : closeIdx+1]) {
			return true
		}
		searchFrom = castStart + openIdx + 1
	}
	return false
}

func hasMatchInSelectProjectionR65Mem(sqlStr string) bool {
	if !reNereidsMatchFuncR65.MatchString(sqlStr) {
		return false
	}
	masked := blankQuotedAndBacktickedR65Mem(sqlStr, false)
	inProjByDepth := make(map[int]bool)
	depth := 0
	for i := 0; i < len(masked); {
		c := masked[i]
		switch c {
		case '(':
			depth++
			i++
		case ')':
			delete(inProjByDepth, depth)
			if depth > 0 {
				depth--
			}
			i++
		default:
			if isIdentByteR63Mem(c) {
				j := i + 1
				for j < len(masked) && isIdentByteR63Mem(masked[j]) {
					j++
				}
				tok := masked[i:j]
				switch {
				case strings.EqualFold(tok, "SELECT"):
					inProjByDepth[depth] = true
				case strings.EqualFold(tok, "FROM"):
					inProjByDepth[depth] = false
				case strings.EqualFold(tok, "WHERE") || strings.EqualFold(tok, "GROUP") || strings.EqualFold(tok, "HAVING") || strings.EqualFold(tok, "UNION"):
					inProjByDepth[depth] = false
				case reNereidsMatchFuncR65.MatchString(tok):
					if inProjByDepth[depth] {
						return true
					}
				}
				i = j
			} else {
				i++
			}
		}
	}
	return false
}

func hasUnparenthesizedOrderByInUnionAllR65Mem(sqlStr string) bool {
	if !strings.Contains(strings.ToUpper(sqlStr), "UNION ALL") {
		return false
	}
	masked := blankQuotedAndBacktickedR65Mem(sqlStr, false)
	body := skipLeadingWithCTEsForUnionR65Mem(masked)
	branches := splitTopLevelUnionAllR65Mem(body)
	if len(branches) <= 1 {
		return false
	}
	for idx, br := range branches {
		trimmed := strings.TrimSpace(br)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "(") {
			closeIdx := memFindMatchingParen(trimmed, 0)
			if closeIdx == len(trimmed)-1 {
				continue
			}
			// Allow a trailing union-wide `ORDER BY` only after a closing `)` on the final branch.
			if idx == len(branches)-1 && closeIdx > 0 {
				afterClose := strings.TrimSpace(trimmed[closeIdx+1:])
				if strings.HasPrefix(strings.ToUpper(afterClose), "ORDER ") {
					continue
				}
			}
			if closeIdx > 0 && hasTopLevelOrderByR65Mem(trimmed[closeIdx+1:]) {
				return true
			}
			continue
		}
		if hasTopLevelOrderByR65Mem(trimmed) {
			return true
		}
	}
	return false
}

func skipLeadingWithCTEsForUnionR65Mem(masked string) string {
	trimmed := strings.TrimSpace(masked)
	if len(trimmed) < 5 || !strings.EqualFold(trimmed[:4], "WITH") || isIdentByteR63Mem(trimmed[4]) {
		return trimmed
	}
	depth := 0
	sawParen := false
	for i := 4; i < len(trimmed); i++ {
		switch trimmed[i] {
		case '(':
			depth++
			sawParen = true
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if sawParen && depth == 0 {
				rest := strings.TrimSpace(trimmed[i:])
				if strings.HasPrefix(rest, ",") {
					continue
				}
				if strings.HasPrefix(rest, "(") || (len(rest) >= 6 && strings.EqualFold(rest[:6], "SELECT") && (len(rest) == 6 || !isIdentByteR63Mem(rest[6]))) {
					return rest
				}
			}
		}
	}
	return trimmed
}

func splitTopLevelUnionAllR65Mem(masked string) []string {
	var branches []string
	depth := 0
	start := 0
	for i := 0; i < len(masked); i++ {
		switch masked[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+len("UNION ALL") <= len(masked) && strings.EqualFold(masked[i:i+len("UNION ALL")], "UNION ALL") {
				prevOK := i == 0 || !isIdentByteR63Mem(masked[i-1])
				nextPos := i + len("UNION ALL")
				nextOK := nextPos == len(masked) || !isIdentByteR63Mem(masked[nextPos])
				if prevOK && nextOK {
					branches = append(branches, masked[start:i])
					start = nextPos
					i = nextPos - 1
				}
			}
		}
	}
	if start < len(masked) {
		branches = append(branches, masked[start:])
	}
	return branches
}

func hasTopLevelOrderByR65Mem(masked string) bool {
	var top strings.Builder
	top.Grow(len(masked))
	depth := 0
	for i := 0; i < len(masked); i++ {
		switch masked[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				top.WriteByte(masked[i])
			}
		}
	}
	return reNereidsOrderByR65.MatchString(top.String())
}

func validateStrictCastValueR65Mem(val any, targetType string) error {
	if val == nil {
		return nil
	}
	switch targetType {
	case "DOUBLE", "FLOAT":
		if _, ok := toFloat(val); !ok {
			return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Can not parse value %v as %s in strict cast mode", val, targetType)
		}
	case "LARGEINT":
		if memCoerceSQLLargeInt(val) == nil {
			return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Can not parse value %v as LARGEINT in strict cast mode", val)
		}
	case "BIGINT", "INT":
		switch tv := val.(type) {
		case int, int32, int64:
			return nil
		case uint64:
			if targetType == "BIGINT" && tv > math.MaxInt64 {
				return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Out of range value %v for %s in strict cast mode", val, targetType)
			}
			return nil
		case float64:
			if math.IsNaN(tv) || math.IsInf(tv, 0) {
				return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Invalid float value %v for %s in strict cast mode", val, targetType)
			}
		case json.Number:
			if _, err := tv.Int64(); err != nil {
				return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Can not parse value %q as %s in strict cast mode", tv.String(), targetType)
			}
		case string:
			trimmed := strings.TrimSpace(tv)
			if trimmed == "" {
				return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Can not parse empty string as %s in strict cast mode", targetType)
			}
			bitSize := 64
			if targetType == "INT" {
				bitSize = 32
			}
			if _, err := strconv.ParseInt(trimmed, 10, bitSize); err != nil {
				return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Can not parse value %q as %s in strict cast mode", trimmed, targetType)
			}
		default:
			return fmt.Errorf("errCode = 2, detailMessage = [DATA_QUALITY_ERROR] Unsupported value %T for CAST AS %s in strict cast mode", val, targetType)
		}
	}
	return nil
}

type strictCastSiteR65Mem struct {
	absStart   int
	inner      string
	targetType string
}

func extractStrictNumericCastSitesR65Mem(sqlStr string) []strictCastSiteR65Mem {
	upper := strings.ToUpper(sqlStr)
	if !strings.Contains(upper, "CAST(") {
		return nil
	}
	var sites []strictCastSiteR65Mem
	searchFrom := 0
	for {
		idx := strings.Index(upper[searchFrom:], "CAST(")
		if idx < 0 {
			break
		}
		absIdx := searchFrom + idx
		searchFrom = absIdx + len("CAST(")
		if absIdx > 0 && isIdentByteR63Mem(upper[absIdx-1]) {
			continue
		}
		if isOffsetInsideQuotesOrBackticksR63Mem(sqlStr, absIdx) {
			continue
		}
		closeParen := memFindMatchingParen(sqlStr, absIdx+len("CAST"))
		if closeParen < 0 {
			continue
		}
		body := sqlStr[absIdx+len("CAST(") : closeParen]
		asIdx := findTopLevelLastAsR63Mem(body)
		if asIdx <= 0 {
			continue
		}
		inner := strings.TrimSpace(body[:asIdx])
		targetType := strings.ToUpper(strings.TrimSpace(body[asIdx+4:]))
		switch targetType {
		case "DOUBLE", "FLOAT", "LARGEINT", "BIGINT", "INT":
		default:
			continue
		}
		innerUpper := strings.ToUpper(inner)
		if strings.HasPrefix(innerUpper, "`_DOC`") || strings.HasPrefix(innerUpper, "_DOC") ||
			strings.HasPrefix(innerUpper, "`BASE_MATCHED`.`_DOC`") {
			continue
		}
		if targetType == "INT" && strings.HasPrefix(innerUpper, "COALESCE(") &&
			(strings.HasSuffix(innerUpper, ", FALSE)") || strings.HasSuffix(innerUpper, ", TRUE)")) {
			continue
		}
		sites = append(sites, strictCastSiteR65Mem{
			absStart:   absIdx,
			inner:      inner,
			targetType: targetType,
		})
	}
	return sites
}

func checkStaticStrictCastLiteralsR65Mem(sqlStr string) error {
	for _, site := range extractStrictNumericCastSitesR65Mem(sqlStr) {
		if strings.HasPrefix(site.inner, "'") && strings.HasSuffix(site.inner, "'") && len(site.inner) >= 2 {
			if err := validateStrictCastValueR65Mem(unquoteSQLLiteral(site.inner), site.targetType); err != nil {
				return err
			}
		}
	}
	return nil
}

func isStrictCastRowExprCandidateR65Mem(inner string) bool {
	u := strings.ToUpper(strings.TrimSpace(inner))
	if strings.Contains(u, "JSON_EXTRACT_STRING(") || strings.Contains(u, "SPLIT_PART(") || strings.Contains(u, "REGEXP_EXTRACT(") {
		return true
	}
	if strings.HasPrefix(inner, "`") && strings.HasSuffix(inner, "`") && strings.Count(inner, "`") == 2 {
		col := inner[1 : len(inner)-1]
		return col != "_id" && col != "_version" && col != "_score" && col != "_total_hits" && col != "_doc" && col != "_source"
	}
	return false
}

func extractEnclosingArrayMapColForCastR65Mem(sqlStr string, castPos int) (string, string, bool) {
	upperPfx := strings.ToUpper(sqlStr[:castPos])
	bestStart := -1
	bestLen := 0
	for _, kw := range []string{"ARRAY_MAP(", "ARRAY_EXISTS(", "ARRAY_FILTER("} {
		if idx := strings.LastIndex(upperPfx, kw); idx > bestStart && !isOffsetInsideQuotesOrBackticksR63Mem(sqlStr, idx) {
			bestStart = idx
			bestLen = len(kw)
		}
	}
	if bestStart < 0 {
		return "", "", false
	}
	closeAM := memFindMatchingParen(sqlStr, bestStart+bestLen-1)
	if closeAM <= castPos {
		return "", "", false
	}
	amBody := sqlStr[bestStart+bestLen : closeAM]
	parts := splitTopLevelArgs(amBody)
	if len(parts) != 2 {
		return "", "", false
	}
	paramName := "_x"
	if arrow := strings.Index(parts[0], "->"); arrow > 0 {
		if p := strings.TrimSpace(parts[0][:arrow]); p != "" {
			paramName = p
		}
	}
	return strings.TrimSpace(parts[1]), paramName, true
}

// checkStrictCastRowsR65Mem enforces Doris 4.1.3 strict cast semantics (`enable_strict_cast=true`)
// on row-level `CAST(... AS DOUBLE|FLOAT|LARGEINT|BIGINT|INT)` expressions when executing against MemoryBackend.
func checkStrictCastRowsR65Mem(tbl map[string]map[string]any, sqlStr string) error {
	if len(tbl) == 0 {
		return nil
	}
	sites := extractStrictNumericCastSitesR65Mem(sqlStr)
	if len(sites) == 0 {
		return nil
	}
	for _, site := range sites {
		if arrExpr, paramName, okAM := extractEnclosingArrayMapColForCastR65Mem(sqlStr, site.absStart); okAM {
			innerTrim := strings.Trim(strings.TrimSpace(site.inner), "`")
			if innerTrim == strings.Trim(paramName, "`") || innerTrim == "_x" || innerTrim == "_el" {
				for _, row := range tbl {
					if isTombstoneRow(row) {
						continue
					}
					arrVal := resolveColumnValue(row, arrExpr)
					if arrVal == nil {
						continue
					}
					for _, elem := range asSliceOrSingle(arrVal) {
						if err := validateStrictCastValueR65Mem(elem, site.targetType); err != nil {
							return err
						}
					}
				}
				continue
			}
		}
		if !isStrictCastRowExprCandidateR65Mem(site.inner) {
			continue
		}
		for _, row := range tbl {
			if isTombstoneRow(row) {
				continue
			}
			val := resolveColumnValue(row, site.inner)
			if err := validateStrictCastValueR65Mem(val, site.targetType); err != nil {
				return err
			}
		}
	}
	return nil
}

func countTopLevelSQLCallArgsR64Mem(s string, openParenIdx int) int {
	if openParenIdx < 0 || openParenIdx >= len(s) || s[openParenIdx] != '(' {
		return -1
	}
	depth := 1
	topCommas := 0
	hasContent := false
	inSingle, inDouble, inBacktick := false, false, false
	for i := openParenIdx + 1; i < len(s); i++ {
		c := s[i]
		if inSingle {
			hasContent = true
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
		if inDouble {
			hasContent = true
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			hasContent = true
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
			hasContent = true
		case '"':
			inDouble = true
			hasContent = true
		case '`':
			inBacktick = true
			hasContent = true
		case '(':
			depth++
			hasContent = true
		case ')':
			depth--
			if depth == 0 {
				if !hasContent {
					return 0
				}
				return topCommas + 1
			}
		case ',':
			if depth == 1 {
				topCommas++
			}
			hasContent = true
		default:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				hasContent = true
			}
		}
	}
	return -1
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

	// 2. `JSON_TYPE(doc, path)` (strict 2-arg Doris 4.1.3 signature; 1-arg returns nil)
	if strings.HasPrefix(upper, "JSON_TYPE(") && strings.HasSuffix(colExpr, ")") && hasMatchingOuterParens(colExpr, len("JSON_TYPE")) {
		args := splitTopLevelArgs(colExpr[len("JSON_TYPE(") : len(colExpr)-1])
		if len(args) != 2 {
			return nil, true
		}
		return evalDorisJSONTypeTwoArgR63Mem(row, args[0], args[1]), true
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
		if raw := extractRowJSONStringR62Mem(row, strings.Trim(srcExpr, "`")); raw != "" {
			v = raw
		} else if strings.HasPrefix(srcExpr, "'") && strings.HasSuffix(srcExpr, "'") {
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
		tryBigIntScalar := func(val any) (int64, bool) {
			switch tv := val.(type) {
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
				if math.IsNaN(tv) || math.IsInf(tv, 0) || tv < float64(math.MinInt64) || tv >= 9223372036854775808.0 {
					return 0, false
				}
				return int64(math.Trunc(tv)), true
			case json.Number:
				if iv, err := tv.Int64(); err == nil {
					return iv, true
				}
				return 0, false
			case string:
				trimmed := strings.TrimSpace(tv)
				if trimmed == "" {
					return 0, false
				}
				if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
					return iv, true
				}
				return 0, false
			default:
				return 0, false
			}
		}
		switch v.(type) {
		case []any, []string:
			var out []any
			for _, elem := range asSliceOrSingle(v) {
				if iv, ok := tryBigIntScalar(elem); ok {
					out = append(out, iv)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		default:
			if iv, ok := tryBigIntScalar(v); ok {
				return iv
			}
			return nil
		}
	case "LARGEINT":
		return memCoerceSQLLargeInt(v)
	case "DOUBLE", "FLOAT":
		tryDoubleScalar := func(val any) (float64, bool) {
			switch tv := val.(type) {
			case string:
				trimmed := strings.TrimSpace(tv)
				if trimmed == "" {
					return 0, false
				}
				f, err := strconv.ParseFloat(trimmed, 64)
				if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
					return 0, false
				}
				return f, true
			default:
				if f, ok := toFloat(tv); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
					return f, true
				}
				return 0, false
			}
		}
		switch v.(type) {
		case []any, []string:
			var out []any
			for _, elem := range asSliceOrSingle(v) {
				if f, ok := tryDoubleScalar(elem); ok {
					out = append(out, f)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		default:
			if f, ok := tryDoubleScalar(v); ok {
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
			if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") || !json.Valid([]byte(trimmed)) {
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
		if _, isMap := v.(map[string]any); isMap {
			return nil
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
			if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") || !json.Valid([]byte(trimmed)) {
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
	case "JSON":
		switch tv := v.(type) {
		case string:
			trimmed := strings.TrimSpace(tv)
			if trimmed == "" || !json.Valid([]byte(trimmed)) {
				return nil
			}
			var decoded any
			dec := json.NewDecoder(strings.NewReader(trimmed))
			dec.UseNumber()
			if err := dec.Decode(&decoded); err != nil {
				return nil
			}
			return decoded
		default:
			return tv
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

func evalDorisJSONTypeTwoArgR63Mem(row map[string]any, docArg, pathArg string) any {
	pathTrim := strings.TrimSpace(pathArg)
	var rawPath string
	if strings.HasPrefix(pathTrim, "'") && strings.HasSuffix(pathTrim, "'") {
		rawPath = unquoteSQLLiteral(pathTrim)
	} else if pv := resolveColumnValue(row, pathTrim); pv != nil {
		rawPath = fmt.Sprintf("%v", pv)
	}
	if rawPath == "" {
		return nil
	}
	segs := parseDorisJSONPathSegmentsR63Mem(rawPath)
	docTrim := trimOuterParens(strings.TrimSpace(docArg))
	if docName := strings.Trim(docTrim, "`"); docName != "" {
		if rawJSON := extractRowJSONStringR62Mem(row, docName); rawJSON != "" {
			val, exists := extractJSONTypedValueFromStrR63Mem(rawJSON, segs)
			return dorisJSONTypeNameR63Mem(val, exists)
		}
	}
	v := resolveColumnValue(row, docTrim)
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return nil
		}
		val, exists := extractJSONTypedValueFromStrR63Mem(trimmed, segs)
		return dorisJSONTypeNameR63Mem(val, exists)
	}
	jb, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	val, exists := extractJSONTypedValueFromStrR63Mem(string(jb), segs)
	return dorisJSONTypeNameR63Mem(val, exists)
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
				if hasUnwrappedNullColumnRef(row, pt) {
					return true
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
	return hasNullScalarCallOperandR64Mem(row, trimmed)
}

func hasNullScalarCallOperandR64Mem(row map[string]any, trimmed string) bool {
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "CAST(COALESCE(") && (strings.HasSuffix(upper, ", FALSE) AS INT)") || strings.HasSuffix(upper, ", TRUE) AS INT)")) {
		return false
	}
	for _, pfx := range []string{"TRY_CAST(", "CAST("} {
		if strings.HasPrefix(upper, pfx) && strings.HasSuffix(trimmed, ")") && hasMatchingOuterParens(trimmed, len(pfx)-1) {
			innerAll := strings.TrimSpace(trimmed[len(pfx) : len(trimmed)-1])
			if asIdx := findTopLevelLastAsR63Mem(innerAll); asIdx > 0 {
				inner := trimOuterParens(strings.TrimSpace(innerAll[:asIdx]))
				if inner == "" {
					return false
				}
				if _, err := strconv.ParseFloat(inner, 64); err == nil {
					return false
				}
				if hasUnwrappedNullColumnRef(row, inner) || hasNullArithmeticOperandR63Mem(row, inner) {
					return true
				}
				if !isArithmeticSQLExpr(inner) && resolveColumnValue(row, inner) == nil {
					return true
				}
				return false
			}
		}
	}
	for _, fn := range []string{"UNIX_TIMESTAMP", "TIMESTAMPDIFF", "MICROSECOND", "DATE_TRUNC", "SECONDS_ADD"} {
		if strings.HasPrefix(upper, fn+"(") && strings.HasSuffix(trimmed, ")") && hasMatchingOuterParens(trimmed, len(fn)) {
			return resolveColumnValue(row, trimmed) == nil
		}
	}
	if strings.HasPrefix(upper, "COALESCE(") && strings.HasSuffix(trimmed, ")") && hasMatchingOuterParens(trimmed, len("COALESCE")) {
		args := splitTopLevelArgs(trimmed[len("COALESCE(") : len(trimmed)-1])
		for _, a := range args {
			arg := trimOuterParens(strings.TrimSpace(a))
			if arg == "" {
				continue
			}
			if strings.EqualFold(arg, "NULL") {
				continue
			}
			if strings.EqualFold(arg, "TRUE") || strings.EqualFold(arg, "FALSE") || (len(arg) >= 2 && arg[0] == '\'' && arg[len(arg)-1] == '\'') {
				return false
			}
			if _, err := strconv.ParseFloat(arg, 64); err == nil {
				return false
			}
			if hasUnwrappedNullColumnRef(row, arg) || hasNullArithmeticOperandR63Mem(row, arg) {
				continue
			}
			if !isArithmeticSQLExpr(arg) && resolveColumnValue(row, arg) == nil {
				continue
			}
			return false
		}
		return len(args) > 0
	}
	for _, fn := range []string{"FLOOR", "CEIL", "ROUND", "TRUNCATE", "ABS", "SQRT", "LN", "LOG10", "EXP", "SIN", "COS", "TAN", "ASIN", "ACOS", "ATAN", "ATAN2", "POW"} {
		if strings.HasPrefix(upper, fn+"(") && strings.HasSuffix(trimmed, ")") && hasMatchingOuterParens(trimmed, len(fn)) {
			args := splitTopLevelArgs(trimmed[len(fn)+1 : len(trimmed)-1])
			for _, a := range args {
				arg := trimOuterParens(strings.TrimSpace(a))
				if arg == "" {
					continue
				}
				if _, err := strconv.ParseFloat(arg, 64); err == nil {
					continue
				}
				if hasUnwrappedNullColumnRef(row, arg) || hasNullArithmeticOperandR63Mem(row, arg) {
					return true
				}
				if !isArithmeticSQLExpr(arg) && resolveColumnValue(row, arg) == nil {
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
	runes := []rune(s)
	for i, r := range runes {
		isApostrophe := (r == '\'' || r == '\u2019') && cur.Len() > 0 && i+1 < len(runes) && (unicode.IsLetter(runes[i+1]) || unicode.IsNumber(runes[i+1]))
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || isApostrophe {
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
		isTrailingPrefix := strings.Contains(sp.safePred, " REGEXP ") && !strings.Contains(sp.safePred, "($|[^[:alnum:]_])")
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
				allowPfx := isTrailingPrefix && ti == len(sp.terms)-1
				for _, dt := range toks {
					if dt == qTok || (allowPfx && strings.HasPrefix(dt, qTok)) {
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
		tfNorm := (tf * (sp.k1 + 1.0)) / (tf + sp.k1*(1.0-sp.bParam+sp.bParam*(dlNorm/sp.avgdl)))
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

// QueryTermDocFreqs counts live rows having non-empty tokens in `colExpr` and per-term
// document frequencies across `m.tables[table]`, supporting exact `cutoff_frequency` splitting.
func (m *MemoryBackend) QueryTermDocFreqs(table, colExpr string, terms []string, caseSensitive bool) (int, map[string]int) {
	dfs := make(map[string]int, len(terms))
	if m == nil || len(terms) == 0 {
		return 0, dfs
	}
	need := make(map[string]bool, len(terms))
	for _, tk := range terms {
		k := tk
		if !caseSensitive {
			k = strings.ToLower(k)
		}
		need[k] = true
	}
	m.mu.RLock()
	tbl := m.tables[table]
	liveRows := make([]map[string]any, 0, len(tbl))
	for _, r := range tbl {
		if !isTombstoneRow(r) {
			liveRows = append(liveRows, r)
		}
	}
	m.mu.RUnlock()

	docCount := 0
	for _, r := range liveRows {
		toks := tokenizeBM25FieldTokensR63Mem(r, colExpr, caseSensitive)
		if len(toks) == 0 {
			continue
		}
		docCount++
		seen := make(map[string]bool, len(toks))
		for _, dt := range toks {
			if need[dt] && !seen[dt] {
				seen[dt] = true
				dfs[dt]++
			}
		}
	}
	return docCount, dfs
}
