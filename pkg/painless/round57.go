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

package painless

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	painlessNullMapKey    = "\x00__painless_null_key__"
	painlessBigDecKeyPref = "$__painless_bd_key__:"
	painlessBigIntKeyPref = "$__painless_bi_key__:"
)

// ---------------------------------------------------------------------------
// F20: JLS §15.19 / §15.22.1 / §15.15.5 Exact Bitwise & Shift Semantics
// ---------------------------------------------------------------------------

// extractExactIntegralPainless extracts an exact 64-bit two's-complement integer
// without converting exact int64 values through float64.
func extractExactIntegralPainless(val any, allowCharString bool) (int64, bool) {
	if val == nil || val == painlessEmptyOptional {
		return 0, false
	}
	if opt, ok := val.(*painlessOptional); ok {
		if !opt.present {
			return 0, false
		}
		val = opt.val
	}
	switch tv := val.(type) {
	case int64:
		return tv, true
	case int:
		return int64(tv), true
	case int32:
		return int64(tv), true
	case int16:
		return int64(tv), true
	case int8:
		return int64(tv), true
	case uint:
		return int64(tv), true // #nosec G115 -- intentional two's-complement bit preservation
	case uint64:
		return int64(tv), true // #nosec G115 -- intentional two's-complement bit preservation
	case uint32:
		return int64(tv), true
	case uint16:
		return int64(tv), true
	case uint8:
		return int64(tv), true
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv, true
		}
		if fv, err := tv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
			return int64(fv), true
		}
		return 0, false
	case *painlessBigInteger:
		if tv == nil || tv.val == nil {
			return 0, false
		}
		return tv.longValue(), true
	case float64:
		if !math.IsNaN(tv) && !math.IsInf(tv, 0) && tv == math.Trunc(tv) && tv >= -9223372036854775808.0 && tv < 9223372036854775808.0 {
			return int64(tv), true
		}
		return 0, false
	case float32:
		fv := float64(tv)
		if !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
			return int64(fv), true
		}
		return 0, false
	case string:
		if allowCharString {
			if u, ok := parseSurrogateCharStringRound59(tv); ok {
				return int64(u), true
			}
			if utf8.RuneCountInString(tv) == 1 {
				r, _ := utf8.DecodeRuneInString(tv)
				return int64(uint16(r)), true // #nosec G115 -- Java 16-bit unsigned char promotion
			}
		}
		return 0, false
	}
	return 0, false
}

func stripBalancedOuterParensRound57(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && findMatchingDelimiter(s, 0, '(', ')') == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func classifyNumericLiteralLongRound57(s string) (isLong bool, isNumLit bool) {
	clean := stripNumericUnderscoresPainless(strings.TrimSpace(s))
	if clean == "" {
		return false, false
	}
	neg := false
	switch clean[0] {
	case '+':
		clean = strings.TrimSpace(clean[1:])
	case '-':
		neg = true
		clean = strings.TrimSpace(clean[1:])
	}
	if clean == "" {
		return false, false
	}
	last := clean[len(clean)-1]
	if last == 'L' || last == 'l' {
		core := clean[:len(clean)-1]
		if core == "" {
			return false, false
		}
		if strings.HasPrefix(core, "0x") || strings.HasPrefix(core, "0X") {
			if len(core) > 2 {
				for i := 2; i < len(core); i++ {
					if !isHexDigitBytePainless(core[i]) {
						return false, false
					}
				}
				return true, true
			}
			return false, false
		}
		if strings.HasPrefix(core, "0b") || strings.HasPrefix(core, "0B") {
			if len(core) > 2 {
				for i := 2; i < len(core); i++ {
					if core[i] != '0' && core[i] != '1' {
						return false, false
					}
				}
				return true, true
			}
			return false, false
		}
		for i := 0; i < len(core); i++ {
			if core[i] < '0' || core[i] > '9' {
				return false, false
			}
		}
		return true, true
	}
	if strings.HasPrefix(clean, "0x") || strings.HasPrefix(clean, "0X") {
		if len(clean) <= 2 || strings.ContainsAny(clean, ".pP") {
			return false, false
		}
		for i := 2; i < len(clean); i++ {
			if !isHexDigitBytePainless(clean[i]) {
				return false, false
			}
		}
		uv, err := strconv.ParseUint(clean[2:], 16, 64)
		if err != nil {
			return true, true
		}
		if neg {
			if uv <= uint64(-int64(math.MinInt32)) {
				return false, true
			}
			return true, true
		}
		return uv > math.MaxUint32, true
	}
	if strings.HasPrefix(clean, "0b") || strings.HasPrefix(clean, "0B") {
		if len(clean) <= 2 {
			return false, false
		}
		for i := 2; i < len(clean); i++ {
			if clean[i] != '0' && clean[i] != '1' {
				return false, false
			}
		}
		uv, err := strconv.ParseUint(clean[2:], 2, 64)
		if err != nil {
			return true, true
		}
		if neg {
			return uv > uint64(-int64(math.MinInt32)), true
		}
		return uv > math.MaxUint32, true
	}
	if strings.ContainsAny(clean, ".eEfFdD") {
		return false, false
	}
	for i := 0; i < len(clean); i++ {
		if clean[i] < '0' || clean[i] > '9' {
			return false, false
		}
	}
	full := clean
	if neg {
		full = "-" + clean
	}
	iv, err := strconv.ParseInt(full, 10, 64)
	if err != nil {
		return true, true
	}
	return iv < math.MinInt32 || iv > math.MaxInt32, true
}

func findLastTopLevelBinaryArithRound57(s string) (int, byte) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastAddIdx := -1
	var lastAddOp byte
	lastMulIdx := -1
	var lastMulOp byte
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		ch := s[i]
		switch ch {
		case '(', '[', '{':
			depth++
			continue
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if ch == '+' || ch == '-' {
			if i+1 < len(s) && (s[i+1] == ch || s[i+1] == '=' || (ch == '-' && s[i+1] == '>')) {
				i++
				continue
			}
			if i > 0 && (s[i-1] == 'e' || s[i-1] == 'E') {
				prev := i - 2
				if prev >= 0 && ((s[prev] >= '0' && s[prev] <= '9') || s[prev] == '.') {
					continue
				}
			}
			// Check unary vs binary by inspecting previous non-space character.
			j := i - 1
			for j >= 0 && (s[j] == ' ' || s[j] == '\t') {
				j--
			}
			if j < 0 {
				continue
			}
			prevCh := s[j]
			isPostfixIncDec := (prevCh == '+' && j > 0 && s[j-1] == '+') || (prevCh == '-' && j > 0 && s[j-1] == '-')
			if !isPostfixIncDec && strings.IndexByte("+-*/%&|^~=<>?:,(", prevCh) >= 0 {
				continue
			}
			lastAddIdx = i
			lastAddOp = ch
		} else if ch == '*' || ch == '/' || ch == '%' {
			if i+1 < len(s) && s[i+1] == '=' {
				i++
				continue
			}
			if i > 0 {
				lastMulIdx = i
				lastMulOp = ch
			}
		}
	}
	if lastAddIdx > 0 {
		return lastAddIdx, lastAddOp
	}
	if lastMulIdx > 0 {
		return lastMulIdx, lastMulOp
	}
	return -1, 0
}

func findUserFieldDeclaredTypeRound57(cls *painlessUserClass, fieldName string) string {
	for cur := cls; cur != nil; cur = cur.parent {
		for _, f := range cur.fields {
			if f.name == fieldName {
				return f.typeName
			}
		}
	}
	return ""
}

// isLongExprPainless determines whether an integral Painless expression promotes
// to 64-bit Java `long` (true) or 32-bit Java `int` (false) per JLS §5.6 / §15.19.
func isLongExprPainless(expr string, val any, params map[string]any) bool {
	s := stripBalancedOuterParensRound57(expr)
	if s == "" {
		if iv, ok := extractExactIntegralPainless(val, false); ok {
			return iv < math.MinInt32 || iv > math.MaxInt32
		}
		return false
	}

	if isLong, isLit := classifyNumericLiteralLongRound57(s); isLit {
		return isLong
	}

	if castType, castRest, ok := splitLeadingTypeCastPainless(s); ok {
		switch castType {
		case "long", "Long":
			return true
		case "int", "Integer", "short", "Short", "byte", "Byte", "char", "Character":
			return false
		case "def", "Object", "Number":
			return isLongExprPainless(castRest, val, params)
		}
	}

	if strings.HasPrefix(s, "++") || strings.HasPrefix(s, "--") {
		return isLongExprPainless(s[2:], nil, params)
	}
	if (strings.HasSuffix(s, "++") || strings.HasSuffix(s, "--")) && len(s) > 2 {
		return isLongExprPainless(s[:len(s)-2], nil, params)
	}
	if (strings.HasPrefix(s, "~") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-")) && len(s) > 1 {
		return isLongExprPainless(s[1:], nil, params)
	}

	// Ternary conditional `cond ? a : b`
	if qIdx := findTopLevelOpPainless(s, "?"); qIdx > 0 {
		rest := s[qIdx+1:]
		if cIdx := findTopLevelOpPainless(rest, ":"); cIdx > 0 {
			return isLongExprPainless(rest[:cIdx], nil, params) || isLongExprPainless(rest[cIdx+1:], nil, params)
		}
	}

	// Binary bitwise OR / XOR / AND
	for _, op := range []string{"|", "^", "&"} {
		if idx, matchedOp := findLastTopLevelOpPainless(s, op); idx > 0 {
			return isLongExprPainless(s[:idx], nil, params) || isLongExprPainless(s[idx+len(matchedOp):], nil, params)
		}
	}
	// Shifts: JLS §15.19 — shift type is unary-promoted type of LHS ONLY!
	if idx, _ := findLastTopLevelOpPainless(s, ">>>", "<<", ">>"); idx > 0 {
		return isLongExprPainless(s[:idx], nil, params)
	}
	// Binary arithmetic +, -, *, /, %
	if idx, _ := findLastTopLevelBinaryArithRound57(s); idx > 0 {
		return isLongExprPainless(s[:idx], nil, params) || isLongExprPainless(s[idx+1:], nil, params)
	}

	// Constants
	constExpr := s
	for _, pkgPfx := range []string{"java.lang.", "java.math.", "java.time.", "java.util."} {
		if strings.HasPrefix(constExpr, pkgPfx) {
			constExpr = strings.TrimPrefix(constExpr, pkgPfx)
			break
		}
	}
	switch constExpr {
	case "Long.MAX_VALUE", "Long.MIN_VALUE":
		return true
	case "Integer.MAX_VALUE", "Integer.MIN_VALUE", "Integer.SIZE", "Integer.BYTES",
		"Long.SIZE", "Long.BYTES", "Short.MAX_VALUE", "Short.MIN_VALUE", "Short.SIZE", "Short.BYTES",
		"Byte.MAX_VALUE", "Byte.MIN_VALUE", "Byte.SIZE", "Byte.BYTES",
		"Character.MAX_VALUE", "Character.MIN_VALUE", "Character.SIZE", "Character.BYTES",
		"Character.MIN_RADIX", "Character.MAX_RADIX", "Character.MIN_CODE_POINT", "Character.MAX_CODE_POINT":
		return false
	}

	// Simple identifier variable
	if reIdentOnly.MatchString(s) {
		if params != nil {
			if vt, ok := params["__var_type_"+s].(string); ok {
				switch vt {
				case "long", "Long":
					return true
				case "int", "Integer", "short", "Short", "byte", "Byte", "char", "Character":
					return false
				}
			}
			if uo, isThis := params["this"].(*painlessUserObject); isThis && uo != nil && uo.class != nil {
				switch findUserFieldDeclaredTypeRound57(uo.class, s) {
				case "long", "Long":
					return true
				case "int", "Integer", "short", "Short", "byte", "Byte", "char", "Character":
					return false
				}
			}
			if val == nil {
				val = params[s]
			}
		}
		if iv, ok := extractExactIntegralPainless(val, false); ok {
			return iv < math.MinInt32 || iv > math.MaxInt32
		}
		return false
	}

	// Static / user function call
	if openParen := strings.IndexByte(s, '('); openParen > 0 && strings.HasSuffix(s, ")") && findMatchingDelimiter(s, openParen, '(', ')') == len(s)-1 {
		fnName := strings.TrimSpace(s[:openParen])
		for _, pfx := range []string{"java.lang.", "java.math.", "java.util."} {
			if strings.HasPrefix(fnName, pfx) {
				fnName = strings.TrimPrefix(fnName, pfx)
				break
			}
		}
		if strings.HasPrefix(fnName, "StrictMath.") {
			fnName = "Math." + strings.TrimPrefix(fnName, "StrictMath.")
		}
		argStr := strings.TrimSpace(s[openParen+1 : len(s)-1])
		callArgs := splitTopLevelCommaPainless(argStr)
		switch fnName {
		case "Long.bitCount", "Long.numberOfLeadingZeros", "Long.numberOfTrailingZeros",
			"Long.signum", "Long.hashCode", "Long.compare", "Long.compareUnsigned":
			return false
		case "Integer.toUnsignedLong", "Short.toUnsignedLong", "Byte.toUnsignedLong":
			return true
		case "Math.toIntExact":
			return false
		case "Math.addExact", "Math.subtractExact", "Math.multiplyExact", "Math.floorDiv", "Math.floorMod", "Math.min", "Math.max":
			for _, a := range callArgs {
				if isLongExprPainless(a, nil, params) {
					return true
				}
			}
			return false
		case "Math.incrementExact", "Math.decrementExact", "Math.negateExact", "Math.abs":
			if len(callArgs) >= 1 {
				return isLongExprPainless(callArgs[0], nil, params)
			}
			return false
		}
		if strings.HasPrefix(fnName, "Long.") {
			return true
		}
		if strings.HasPrefix(fnName, "Integer.") || strings.HasPrefix(fnName, "Short.") || strings.HasPrefix(fnName, "Byte.") || strings.HasPrefix(fnName, "Character.") {
			return false
		}
		if b := getOrInitEvalBudget(params); b != nil {
			arity := 0
			if argStr != "" {
				arity = len(callArgs)
			}
			uFn := lookupUserFuncRound59(b, fnName, arity)
			if uFn == nil && b.userFuncs != nil && len(b.userFuncOverloads[fnName]) == 0 {
				uFn = b.userFuncs[fnName]
			}
			if uFn != nil {
				switch uFn.returnType {
				case "long", "Long":
					return true
				case "int", "Integer", "short", "Short", "byte", "Byte", "char", "Character":
					return false
				}
			}
		}
	}

	// Trailing zero-arg / parameterized methods
	for _, longSuf := range []string{
		".longValue()", ".longValueExact()", ".getAsLong()", ".toEpochMilli()", ".getMillis()", ".getEpochSecond()",
		".toEpochDay()", ".toTotalMonths()", ".toDays()", ".toHours()", ".toMinutes()", ".toSeconds()", ".toMillis()", ".toNanos()", ".getSeconds()",
		".getMostSignificantBits()", ".getLeastSignificantBits()", ".count()",
	} {
		if strings.HasSuffix(s, longSuf) {
			return true
		}
	}
	for _, intSuf := range []string{
		".intValue()", ".intValueExact()", ".shortValue()", ".shortValueExact()", ".byteValue()", ".byteValueExact()",
		".getAsInt()", ".length()", ".size()", ".hashCode()", ".signum()", ".precision()", ".scale()", ".bitLength()", ".bitCount()", ".cardinality()",
	} {
		if strings.HasSuffix(s, intSuf) {
			return false
		}
	}
	if _, _, ok := matchTrailingMethodCallPainless(s, ".getLong("); ok {
		return true
	}
	if _, _, ok := matchTrailingMethodCallPainless(s, ".toEpochSecond("); ok {
		return true
	}
	if _, _, ok := matchTrailingMethodCallPainless(s, ".fromHexDigitsToLong("); ok {
		return true
	}
	for _, intM := range []string{".compareTo(", ".compareToIgnoreCase(", ".indexOf(", ".lastIndexOf(", ".codePointAt("} {
		if _, _, ok := matchTrailingMethodCallPainless(s, intM); ok {
			return false
		}
	}

	if iv, ok := extractExactIntegralPainless(val, false); ok {
		return iv < math.MinInt32 || iv > math.MaxInt32
	}
	return false
}

func evalBitwiseNotRound57(operandExpr string, innerVal any, params map[string]any) any {
	iv, ok := extractExactIntegralPainless(innerVal, true)
	if !ok {
		return int64(-1)
	}
	if isLongExprPainless(operandExpr, innerVal, params) {
		return ^iv
	}
	return int64(^int32(iv)) // #nosec G115 -- intentional JLS §15.15.5 32-bit int bitwise complement
}

func evalBitwiseOrShiftOpRound57(leftExpr, rightExpr string, leftVal, rightVal any, op string, params map[string]any) (any, error) {
	if lb, ok1 := leftVal.(bool); ok1 {
		if rb, ok2 := rightVal.(bool); ok2 {
			switch op {
			case "|":
				return lb || rb, nil
			case "^":
				return lb != rb, nil
			case "&":
				return lb && rb, nil
			}
		}
	}
	li, ok1 := extractExactIntegralPainless(leftVal, true)
	ri, ok2 := extractExactIntegralPainless(rightVal, true)
	if !ok1 || !ok2 {
		return int64(0), nil
	}
	leftLong := isLongExprPainless(leftExpr, leftVal, params)
	switch op {
	case "<<", ">>", ">>>":
		if leftLong {
			s := uint(ri) & 0x3f // #nosec G115 -- masked to 0..63 per JLS §15.19
			switch op {
			case "<<":
				return li << s, nil
			case ">>":
				return li >> s, nil
			default:
				return int64(uint64(li) >> s), nil // #nosec G115 -- JLS §15.19 unsigned 64-bit right shift
			}
		}
		s := uint(ri) & 0x1f // #nosec G115 -- masked to 0..31 per JLS §15.19
		li32 := int32(li)    // #nosec G115 -- JLS §5.6.1 32-bit unary numeric promotion
		switch op {
		case "<<":
			return int64(li32 << s), nil
		case ">>":
			return int64(li32 >> s), nil
		default:
			return int64(int32(uint32(li32) >> s)), nil // #nosec G115 -- JLS §15.19 32-bit unsigned right shift
		}
	case "|", "^", "&":
		rightLong := isLongExprPainless(rightExpr, rightVal, params)
		if leftLong || rightLong {
			switch op {
			case "|":
				return li | ri, nil
			case "^":
				return li ^ ri, nil
			default:
				return li & ri, nil
			}
		}
		li32 := int32(li) // #nosec G115 -- JLS §5.6.2 32-bit binary numeric promotion
		ri32 := int32(ri) // #nosec G115 -- JLS §5.6.2 32-bit binary numeric promotion
		switch op {
		case "|":
			return int64(li32 | ri32), nil
		case "^":
			return int64(li32 ^ ri32), nil
		default:
			return int64(li32 & ri32), nil
		}
	}
	return li, nil
}

func applyBitwiseAssignRound57(curVal, rhsVal any, op, lhsExpr, rhsExpr string, params map[string]any) any {
	baseOp := strings.TrimSuffix(op, "=")
	res, err := evalBitwiseOrShiftOpRound57(lhsExpr, rhsExpr, curVal, rhsVal, baseOp, params)
	if err != nil {
		return int64(0)
	}
	return res
}

// ---------------------------------------------------------------------------
// F21: JLS §5.1.3 Primitive Narrowing Casts & Typed Local Variable Coercion
// ---------------------------------------------------------------------------

func doubleToInt32JLS(f float64) int32 {
	if math.IsNaN(f) {
		return 0
	}
	if f >= 2147483647.0 {
		return math.MaxInt32
	}
	if f <= -2147483648.0 {
		return math.MinInt32
	}
	return int32(math.Trunc(f))
}

func doubleToInt64JLS(f float64) int64 {
	if math.IsNaN(f) {
		return 0
	}
	if f >= 9223372036854775808.0 {
		return math.MaxInt64
	}
	if f <= -9223372036854775808.0 {
		return math.MinInt64
	}
	return int64(math.Trunc(f))
}

func extractExactIntOrFloatForNarrowRound57(val any) (iv int64, fv float64, kind byte) {
	if val == nil || val == painlessEmptyOptional {
		return 0, 0, 0
	}
	if opt, ok := val.(*painlessOptional); ok {
		if !opt.present {
			return 0, 0, 0
		}
		val = opt.val
	}
	switch tv := val.(type) {
	case int64:
		return tv, 0, 'i'
	case int:
		return int64(tv), 0, 'i'
	case int32:
		return int64(tv), 0, 'i'
	case int16:
		return int64(tv), 0, 'i'
	case int8:
		return int64(tv), 0, 'i'
	case uint:
		return int64(tv), 0, 'i' // #nosec G115 -- intentional two's-complement bit preservation
	case uint64:
		return int64(tv), 0, 'i' // #nosec G115 -- intentional two's-complement bit preservation
	case uint32:
		return int64(tv), 0, 'i'
	case uint16:
		return int64(tv), 0, 'i'
	case uint8:
		return int64(tv), 0, 'i'
	case *painlessBigInteger:
		if tv != nil && tv.val != nil {
			return tv.longValue(), 0, 'i'
		}
		return 0, 0, 0
	case *painlessBigDecimal:
		if tv != nil && tv.unscaled != nil {
			return tv.longValue(), 0, 'i'
		}
		return 0, 0, 0
	case json.Number:
		if parsed, err := tv.Int64(); err == nil {
			return parsed, 0, 'i'
		}
		if parsedF, err := tv.Float64(); err == nil {
			return 0, parsedF, 'f'
		}
		return 0, 0, 0
	case float64:
		return 0, tv, 'f'
	case float32:
		return 0, float64(tv), 'f'
	case string:
		if u, ok := parseSurrogateCharStringRound59(tv); ok {
			return int64(u), 0, 'i'
		}
		if utf8.RuneCountInString(tv) == 1 {
			r, _ := utf8.DecodeRuneInString(tv)
			return int64(uint16(r)), 0, 'i' // #nosec G115 -- Java 16-bit char code unit
		}
		return 0, 0, 0
	}
	if f, ok := toFloat64WithRawPainless(val); ok {
		return 0, f, 'f'
	}
	return 0, 0, 0
}

func evalPrimitiveCastRound57Painless(castType string, innerVal any) (any, bool) {
	switch castType {
	case "byte", "Byte":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return int64(int8(iv)), true // #nosec G115 -- JLS §5.1.3 narrowing to byte
		case 'f':
			return int64(int8(doubleToInt32JLS(fv))), true // #nosec G115 -- JLS §5.1.3 two-step float->int->byte
		default:
			return int64(0), true
		}
	case "short", "Short":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return int64(int16(iv)), true // #nosec G115 -- JLS §5.1.3 narrowing to short
		case 'f':
			return int64(int16(doubleToInt32JLS(fv))), true // #nosec G115 -- JLS §5.1.3 two-step float->int->short
		default:
			return int64(0), true
		}
	case "char", "Character":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return formatJavaCharUnitRound59(uint16(iv)), true // #nosec G115 -- JLS §5.1.3 narrowing to 16-bit char
		case 'f':
			return formatJavaCharUnitRound59(uint16(doubleToInt32JLS(fv))), true // #nosec G115 -- JLS §5.1.3 two-step float->int->char
		default:
			if s, ok := innerVal.(string); ok && len(s) > 0 {
				if u, okS := parseSurrogateCharStringRound59(s); okS {
					return formatJavaCharUnitRound59(u), true
				}
				r, _ := utf8.DecodeRuneInString(s)
				return string(r), true
			}
			return "", true
		}
	case "int", "Integer":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return int64(int32(iv)), true // #nosec G115 -- JLS §5.1.3 narrowing to 32-bit int
		case 'f':
			return int64(doubleToInt32JLS(fv)), true
		default:
			return int64(0), true
		}
	case "long", "Long":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return iv, true
		case 'f':
			return doubleToInt64JLS(fv), true
		default:
			return int64(0), true
		}
	case "float", "Float":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return float64(float32(iv)), true
		case 'f':
			return float64(float32(fv)), true
		default:
			return float64(0), true
		}
	case "double", "Double":
		iv, fv, kind := extractExactIntOrFloatForNarrowRound57(innerVal)
		switch kind {
		case 'i':
			return float64(iv), true
		case 'f':
			return fv, true
		default:
			return float64(0), true
		}
	}
	return nil, false
}

func evalNumberNarrowMethodRound57Painless(mSuffix string, recVal any) any {
	if bd, isBD := recVal.(*painlessBigDecimal); isBD && bd != nil {
		switch mSuffix {
		case ".intValue()":
			return bd.intValue()
		case ".shortValue()":
			return bd.shortValue()
		case ".byteValue()":
			return bd.byteValue()
		default:
			return bd.longValue()
		}
	}
	if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
		switch mSuffix {
		case ".intValue()":
			return bi.intValue()
		case ".shortValue()":
			return bi.shortValue()
		case ".byteValue()":
			return bi.byteValue()
		default:
			return bi.longValue()
		}
	}
	var castType string
	switch mSuffix {
	case ".byteValue()":
		castType = "byte"
	case ".shortValue()":
		castType = "short"
	case ".intValue()":
		castType = "int"
	default:
		castType = "long"
	}
	res, _ := evalPrimitiveCastRound57Painless(castType, recVal)
	return res
}

func extractExplicitPrimitiveVarTypeRound57(stmt string) string {
	tm := reVarTypeDeclPrefix.FindStringSubmatch(strings.TrimSpace(stmt))
	if tm == nil {
		return ""
	}
	tp := strings.TrimSpace(tm[1])
	if strings.Contains(tp, "[") || strings.Contains(tp, "<") {
		return ""
	}
	switch tp {
	case "byte", "short", "char", "int", "long", "float", "double", "boolean":
		return tp
	}
	return ""
}

func extractDeclaredUserClassTypeRound57(rawStmt string, budget *evalBudget) string {
	if budget == nil || len(budget.userClasses) == 0 {
		return ""
	}
	t := strings.TrimSpace(rawStmt)
	endIdent := 0
	for endIdent < len(t) && isIdentByte(t[endIdent]) {
		endIdent++
	}
	if endIdent == 0 {
		return ""
	}
	clsName := t[:endIdent]
	if _, exists := budget.userClasses[clsName]; !exists {
		return ""
	}
	rest := strings.TrimSpace(t[endIdent:])
	if rest == "" || rest[0] == '[' || !isIdentByte(rest[0]) {
		return ""
	}
	return clsName
}

func defaultZeroForPrimitiveTypeRound57(declType string) any {
	switch declType {
	case "byte", "short", "int", "long":
		return int64(0)
	case "char":
		return string(rune(0))
	case "float", "double":
		return float64(0)
	case "boolean":
		return false
	default:
		return nil
	}
}

func coerceTypedVarRound57Painless(declType string, val any) any {
	if declType == "" {
		return val
	}
	if val == nil || val == painlessEmptyOptional {
		return defaultZeroForPrimitiveTypeRound57(declType)
	}
	switch declType {
	case "byte", "short", "char", "int", "long", "float", "double":
		if coerced, ok := evalPrimitiveCastRound57Painless(declType, val); ok {
			return coerced
		}
	case "boolean":
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return val
}

func getLocalVarPrimitiveTypeRound57(params map[string]any, varName string) string {
	if params == nil || varName == "" {
		return ""
	}
	if vt, ok := params["__var_type_"+varName].(string); ok {
		return vt
	}
	return ""
}

func resolveUnshadowedThisFieldTypeRound57(params map[string]any, varName string) (*painlessUserObject, string) {
	uo, isThis := params["this"].(*painlessUserObject)
	if !isThis || uo == nil || uo.fields == nil || varName == "this" {
		return nil, ""
	}
	if mp, okMP := params["__method_params"].(map[string]bool); okMP && mp[varName] {
		return nil, ""
	}
	if sl, okSL := params["__script_locals"].(map[string]bool); okSL && sl[varName] {
		return nil, ""
	}
	if _, hasField := uo.fields[varName]; !hasField {
		return nil, ""
	}
	return uo, findUserFieldDeclaredTypeRound57(uo.class, varName)
}

func applyIncDecRound57Painless(curVal any, isInc bool, declType string) (nextVal any, prevVal any) {
	delta := int64(-1)
	if isInc {
		delta = 1
	}
	switch declType {
	case "byte":
		iv, _ := extractExactIntegralPainless(curVal, true)
		prev := int64(int8(iv))           // #nosec G115 -- Java 8-bit signed byte
		next := int64(int8(prev + delta)) // #nosec G115 -- Java 8-bit signed byte wraparound
		return next, prev
	case "short":
		iv, _ := extractExactIntegralPainless(curVal, true)
		prev := int64(int16(iv))           // #nosec G115 -- Java 16-bit signed short
		next := int64(int16(prev + delta)) // #nosec G115 -- Java 16-bit signed short wraparound
		return next, prev
	case "char":
		iv, _ := extractExactIntegralPainless(curVal, true)
		prevU := uint16(iv)                   // #nosec G115 -- Java 16-bit unsigned char
		nextU := uint16(int64(prevU) + delta) // #nosec G115 -- Java 16-bit unsigned char wraparound
		return string(rune(nextU)), string(rune(prevU))
	case "int":
		iv, _ := extractExactIntegralPainless(curVal, true)
		prev := int64(int32(iv))           // #nosec G115 -- Java 32-bit signed int
		next := int64(int32(prev + delta)) // #nosec G115 -- Java 32-bit signed int wraparound
		return next, prev
	case "long":
		iv, _ := extractExactIntegralPainless(curVal, true)
		return iv + delta, iv
	case "float":
		f, _ := toFloat64WithRawPainless(curVal)
		prevF := float32(f)
		nextF := prevF + float32(delta)
		return float64(nextF), float64(prevF)
	case "double":
		f, _ := toFloat64WithRawPainless(curVal)
		return f + float64(delta), f
	}
	// Untyped variable/field: preserve exact int64 without float64 precision loss!
	switch tv := curVal.(type) {
	case int64:
		return tv + delta, tv
	case int:
		iv := int64(tv)
		return iv + delta, iv
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv + delta, iv
		}
	}
	return applyArithmetic(curVal, int64(1), isInc), normalizeIncDecPrevVal(curVal)
}

func evalCompoundAssignRound57Painless(curVal, rhsVal any, op, lhsExpr, rhsExpr, declType string, params map[string]any) (any, error) {
	switch op {
	case "&=", "|=", "^=", "<<=", ">>=", ">>>=":
		raw := applyBitwiseAssignRound57(curVal, rhsVal, op, lhsExpr, rhsExpr, params)
		if declType != "" {
			return coerceTypedVarRound57Painless(declType, raw), nil
		}
		return raw, nil
	}
	if declType != "" && declType != "float" && declType != "double" {
		_, rhsIsFloat := isRawFloatingValPainless(rhsVal)
		if !rhsIsFloat {
			li, okL := extractExactIntegralPainless(curVal, true)
			ri, okR := extractExactIntegralPainless(rhsVal, true)
			if okL && okR {
				if (op == "/=" || op == "%=") && ri == 0 {
					return nil, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
				}
				var raw int64
				switch op {
				case "+=":
					raw = li + ri
				case "-=":
					raw = li - ri
				case "*=":
					raw = li * ri
				case "/=":
					if li == math.MinInt64 && ri == -1 {
						raw = math.MinInt64
					} else {
						raw = li / ri
					}
				case "%=":
					if li == math.MinInt64 && ri == -1 {
						raw = 0
					} else {
						raw = li % ri
					}
				}
				return coerceTypedVarRound57Painless(declType, raw), nil
			}
		}
		// Floating RHS with integral LHS: JLS §15.26.2 E1 = (T)(E1 op E2)
		curForOp := curVal
		if declType == "char" {
			if iv, ok := extractExactIntegralPainless(curVal, true); ok {
				curForOp = iv
			}
		}
		var raw any
		switch op {
		case "+=":
			raw = applyArithmetic(curForOp, rhsVal, true)
		case "-=":
			raw = applyArithmetic(curForOp, rhsVal, false)
		case "*=":
			raw = applyMulDiv(curForOp, rhsVal, '*')
		case "/=":
			raw = applyMulDiv(curForOp, rhsVal, '/')
		case "%=":
			raw = applyMulDiv(curForOp, rhsVal, '%')
		}
		return coerceTypedVarRound57Painless(declType, raw), nil
	}

	var nextVal any
	switch op {
	case "+=":
		nextVal = applyArithmetic(curVal, rhsVal, true)
	case "-=":
		nextVal = applyArithmetic(curVal, rhsVal, false)
	case "*=":
		nextVal = applyMulDiv(curVal, rhsVal, '*')
	case "/=":
		nextVal = applyMulDiv(curVal, rhsVal, '/')
	case "%=":
		nextVal = applyMulDiv(curVal, rhsVal, '%')
	}
	if declType != "" {
		nextVal = coerceTypedVarRound57Painless(declType, nextVal)
	}
	return nextVal, nil
}

func snapshotBlockVarMetaRound57(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	snap := make(map[string]any)
	for k, v := range params {
		if strings.HasPrefix(k, "__var_type_") || strings.HasPrefix(k, "__user_var_class_") {
			snap[k] = v
		}
	}
	return snap
}

func restoreBlockVarMetaRound57(params, snap map[string]any) {
	if params == nil {
		return
	}
	for k := range params {
		if strings.HasPrefix(k, "__var_type_") || strings.HasPrefix(k, "__user_var_class_") {
			if prev, existed := snap[k]; existed {
				params[k] = prev
			} else {
				delete(params, k)
			}
		}
	}
	for k, v := range snap {
		params[k] = v
	}
}

func execScopedSubBlockRound57(sourceMap map[string]any, body string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	snap := snapshotBlockVarMetaRound57(params)
	err := execBlock(sourceMap, body, params, ctxOp, budget)
	restoreBlockVarMetaRound57(params, snap)
	return err
}

// ---------------------------------------------------------------------------
// F22: Math & StrictMath *Exact 32-Bit/64-Bit Overloads & floorDiv/floorMod
// ---------------------------------------------------------------------------

func evalMathExactOrFloorRound57Painless(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	evalIntArg := func(idx int) (int64, bool, error) {
		if idx >= len(args) {
			return 0, false, nil
		}
		rawExpr := strings.TrimSpace(args[idx])
		v, err := evalRHSExprDepth(sourceMap, rawExpr, params, depth+1)
		if err != nil {
			return 0, false, err
		}
		iv, ok := extractExactIntegralPainless(v, true)
		if !ok {
			return 0, false, nil
		}
		return iv, isLongExprPainless(rawExpr, v, params), nil
	}

	switch fnName {
	case "Math.addExact":
		x, longX, err1 := evalIntArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		y, longY, err2 := evalIntArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if len(args) < 2 {
			return int64(0), true, nil
		}
		if !longX && !longY {
			xi, yi := int64(int32(x)), int64(int32(y)) // #nosec G115 -- 32-bit int overload
			r := xi + yi
			if r < math.MinInt32 || r > math.MaxInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		r := x + y
		if ((x ^ r) & (y ^ r)) < 0 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return r, true, nil

	case "Math.subtractExact":
		x, longX, err1 := evalIntArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		y, longY, err2 := evalIntArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if len(args) < 2 {
			return int64(0), true, nil
		}
		if !longX && !longY {
			xi, yi := int64(int32(x)), int64(int32(y)) // #nosec G115 -- 32-bit int overload
			r := xi - yi
			if r < math.MinInt32 || r > math.MaxInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		r := x - y
		if ((x ^ y) & (x ^ r)) < 0 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return r, true, nil

	case "Math.multiplyExact":
		x, longX, err1 := evalIntArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		y, longY, err2 := evalIntArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if len(args) < 2 {
			return int64(0), true, nil
		}
		if !longX && !longY {
			xi, yi := int64(int32(x)), int64(int32(y)) // #nosec G115 -- 32-bit int overload
			r := xi * yi
			if r < math.MinInt32 || r > math.MaxInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		prod := new(big.Int).Mul(big.NewInt(x), big.NewInt(y))
		if !prod.IsInt64() {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return prod.Int64(), true, nil

	case "Math.incrementExact":
		x, longX, err := evalIntArg(0)
		if err != nil {
			return nil, true, err
		}
		if len(args) < 1 {
			return int64(0), true, nil
		}
		if !longX {
			xi := int64(int32(x)) // #nosec G115 -- 32-bit int overload
			if xi == math.MaxInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return xi + 1, true, nil
		}
		if x == math.MaxInt64 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return x + 1, true, nil

	case "Math.decrementExact":
		x, longX, err := evalIntArg(0)
		if err != nil {
			return nil, true, err
		}
		if len(args) < 1 {
			return int64(0), true, nil
		}
		if !longX {
			xi := int64(int32(x)) // #nosec G115 -- 32-bit int overload
			if xi == math.MinInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return xi - 1, true, nil
		}
		if x == math.MinInt64 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return x - 1, true, nil

	case "Math.negateExact":
		x, longX, err := evalIntArg(0)
		if err != nil {
			return nil, true, err
		}
		if len(args) < 1 {
			return int64(0), true, nil
		}
		if !longX {
			xi := int64(int32(x)) // #nosec G115 -- 32-bit int overload
			if xi == math.MinInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return -xi, true, nil
		}
		if x == math.MinInt64 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "long overflow"}
		}
		return -x, true, nil

	case "Math.toIntExact":
		x, _, err := evalIntArg(0)
		if err != nil {
			return nil, true, err
		}
		if len(args) < 1 {
			return int64(0), true, nil
		}
		if x < math.MinInt32 || x > math.MaxInt32 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
		}
		return int64(int32(x)), true, nil // #nosec G115 -- bounds checked in MinInt32..MaxInt32

	case "Math.floorDiv":
		x, longX, err1 := evalIntArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		y, longY, err2 := evalIntArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if len(args) < 2 {
			return int64(0), true, nil
		}
		if !longX && !longY {
			xi, yi := int32(x), int32(y) // #nosec G115 -- 32-bit int overload
			if yi == 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
			}
			if xi == math.MinInt32 && yi == -1 {
				return int64(math.MinInt32), true, nil
			}
			q := xi / yi
			if (xi^yi) < 0 && q*yi != xi {
				q--
			}
			return int64(q), true, nil
		}
		if y == 0 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
		}
		if x == math.MinInt64 && y == -1 {
			return int64(math.MinInt64), true, nil
		}
		q := x / y
		if (x^y) < 0 && q*y != x {
			q--
		}
		return q, true, nil

	case "Math.floorMod":
		x, longX, err1 := evalIntArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		y, longY, err2 := evalIntArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if len(args) < 2 {
			return int64(0), true, nil
		}
		if !longX && !longY {
			xi, yi := int32(x), int32(y) // #nosec G115 -- 32-bit int overload
			if yi == 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
			}
			if xi == math.MinInt32 && yi == -1 {
				return int64(0), true, nil
			}
			r := xi % yi
			if r != 0 && (r^yi) < 0 {
				r += yi
			}
			return int64(r), true, nil
		}
		if y == 0 {
			return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
		}
		if x == math.MinInt64 && y == -1 {
			return int64(0), true, nil
		}
		r := x % y
		if r != 0 && (r^y) < 0 {
			r += y
		}
		return r, true, nil
	}
	return nil, false, nil
}

// ---------------------------------------------------------------------------
// F23: BigDecimal.divide Exact Terminating Quotient & Strict .equals()
// ---------------------------------------------------------------------------

func divideExactBigDecimalPainless(a, b *painlessBigDecimal) (*painlessBigDecimal, error) {
	if b == nil || b.unscaled == nil || b.unscaled.Sign() == 0 {
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Division by zero"}
	}
	var prefScale64 int64
	if a != nil {
		prefScale64 = int64(a.scale) - int64(b.scale)
	}
	if prefScale64 > math.MaxInt32 || prefScale64 < math.MinInt32 {
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	prefScale := int(prefScale64)
	if a == nil || a.unscaled == nil || a.unscaled.Sign() == 0 {
		return newPainlessBigDecimal(big.NewInt(0), prefScale), nil
	}

	absA := new(big.Int).Abs(a.unscaled)
	absB := new(big.Int).Abs(b.unscaled)
	g := new(big.Int).GCD(nil, nil, absA, absB)
	num := new(big.Int).Quo(absA, g)
	den := new(big.Int).Quo(absB, g)

	c2 := den.TrailingZeroBits()
	if c2 > 0 {
		den.Rsh(den, c2)
	}
	var c5 uint
	five := big.NewInt(5)
	rem := new(big.Int)
	for den.Sign() > 0 {
		q, r := new(big.Int).QuoRem(den, five, rem)
		if r.Sign() != 0 {
			break
		}
		den = q
		c5++
	}
	if den.Cmp(big.NewInt(1)) != 0 {
		return nil, &painlessExceptionError{
			exType:  "ArithmeticException",
			message: "Non-terminating decimal expansion; no exact representable decimal result.",
		}
	}

	if c2 > c5 {
		fivePow := new(big.Int).Exp(five, big.NewInt(int64(c2-c5)), nil) // #nosec G115 -- factor count fits in int64
		num.Mul(num, fivePow)
	} else if c5 > c2 {
		num.Lsh(num, c5-c2)
	}
	if (a.unscaled.Sign() < 0) != (b.unscaled.Sign() < 0) {
		num.Neg(num)
	}

	maxFactor := int64(c2)     // #nosec G115 -- factor count fits in int64
	if int64(c5) > maxFactor { // #nosec G115 -- factor count fits in int64
		maxFactor = int64(c5) // #nosec G115 -- factor count fits in int64
	}
	exactScale64 := prefScale64 + maxFactor
	if exactScale64 > math.MaxInt32 || exactScale64 < math.MinInt32 {
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	exactScale := int(exactScale64)

	if exactScale < prefScale {
		num.Mul(num, bigTenPowPainless(prefScale-exactScale))
		exactScale = prefScale
	} else if exactScale > prefScale {
		ten := big.NewInt(10)
		for exactScale > prefScale && num.Sign() != 0 {
			qTen, rTen := new(big.Int).QuoRem(num, ten, rem)
			if rTen.Sign() != 0 {
				break
			}
			num = qTen
			exactScale--
		}
	}
	return &painlessBigDecimal{unscaled: num, scale: exactScale}, nil
}

// painlessJavaObjectEquals implements Java Object.equals / Objects.equals semantics:
// BigDecimal.equals requires identical value AND scale (and BigDecimal runtime type),
// BigInteger.equals requires BigInteger runtime type, while delegating other types
// to painlessValuesEqual so existing Painless equality semantics remain intact.
func painlessJavaObjectEquals(a, b any) bool {
	if optA, okA := a.(*painlessOptional); okA {
		return optA.equals(b)
	}
	if optB, okB := b.(*painlessOptional); okB {
		return optB.equals(a)
	}
	if a == painlessEmptyOptional || b == painlessEmptyOptional {
		return a == painlessEmptyOptional && b == painlessEmptyOptional
	}
	if bda, okA := a.(*painlessBigDecimal); okA {
		bdb, okB := b.(*painlessBigDecimal)
		if !okB || bda == nil || bdb == nil || bda.unscaled == nil || bdb.unscaled == nil {
			return bda == nil && okB && bdb == nil
		}
		return bda.scale == bdb.scale && bda.unscaled.Cmp(bdb.unscaled) == 0
	}
	if _, okB := b.(*painlessBigDecimal); okB {
		return false
	}
	if bia, okA := a.(*painlessBigInteger); okA {
		bib, okB := b.(*painlessBigInteger)
		if !okB || bia == nil || bib == nil || bia.val == nil || bib.val == nil {
			return bia == nil && okB && bib == nil
		}
		return bia.val.Cmp(bib.val) == 0
	}
	if _, okB := b.(*painlessBigInteger); okB {
		return false
	}
	if sa, okA := a.([]any); okA {
		sb, okB := b.([]any)
		if !okB || len(sa) != len(sb) {
			return false
		}
		for i := range sa {
			if !painlessJavaObjectEquals(sa[i], sb[i]) {
				return false
			}
		}
		return true
	}
	if ma, okA := a.(map[string]any); okA {
		mb, okB := b.(map[string]any)
		if !okB {
			return false
		}
		if visiblePainlessMapLen(ma) != visiblePainlessMapLen(mb) {
			return false
		}
		for k, va := range ma {
			if isInternalPainlessMapKey(ma, k) {
				continue
			}
			vb, exists := mb[k]
			if !exists || !painlessJavaObjectEquals(va, vb) {
				return false
			}
		}
		return true
	}
	return painlessValuesEqual(a, b)
}

// ---------------------------------------------------------------------------
// F24: Java 8+ String/Pattern.split & Matcher.appendReplacement Semantics
// ---------------------------------------------------------------------------

func javaSplitEmptyPatternRound57(s string, limit int) []any {
	if s == "" {
		return []any{""}
	}
	if limit == 1 {
		return []any{s}
	}
	runes := []rune(s)
	n := len(runes)
	if limit > 1 {
		if limit <= n {
			out := make([]any, limit)
			for i := 0; i < limit-1; i++ {
				out[i] = string(runes[i])
			}
			out[limit-1] = string(runes[limit-1:])
			return out
		}
		out := make([]any, n+1)
		for i := 0; i < n; i++ {
			out[i] = string(runes[i])
		}
		out[n] = ""
		return out
	}
	if limit < 0 {
		out := make([]any, n+1)
		for i := 0; i < n; i++ {
			out[i] = string(runes[i])
		}
		out[n] = ""
		return out
	}
	// limit == 0: trailing empty string stripped
	out := make([]any, n)
	for i := 0; i < n; i++ {
		out[i] = string(runes[i])
	}
	return out
}

func javaRegexSplitRound57(re *regexp.Regexp, s string, limit int) []any {
	if re == nil || limit == 1 {
		return []any{s}
	}
	if re.String() == "" {
		return javaSplitEmptyPatternRound57(s, limit)
	}
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return []any{s}
	}
	index := 0
	matchLimited := limit > 0
	var matchList []string
	matchedNonLeadingEmpty := false
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if index == 0 && start == 0 && end == 0 {
			// Java 8+ Pattern.split ignores a zero-width match at the start of input.
			continue
		}
		matchedNonLeadingEmpty = true
		if !matchLimited || len(matchList) < limit-1 {
			matchList = append(matchList, s[index:start])
			index = end
		} else if len(matchList) == limit-1 {
			matchList = append(matchList, s[index:])
			index = len(s)
			break
		}
	}
	if !matchedNonLeadingEmpty {
		return []any{s}
	}
	if !matchLimited || len(matchList) < limit {
		matchList = append(matchList, s[index:])
	}
	if limit == 0 {
		for len(matchList) > 0 && matchList[len(matchList)-1] == "" {
			matchList = matchList[:len(matchList)-1]
		}
	}
	out := make([]any, len(matchList))
	for i, part := range matchList {
		out[i] = part
	}
	return out
}

func compileJavaSplitOrReplaceRegexRound57(patStr string) (*regexp.Regexp, error) {
	norm := normalizeJavaNamedGroupsPainless(patStr)
	re, err := compilePainlessRegexp(norm)
	if err != nil {
		return nil, &painlessExceptionError{
			exType:  "PatternSyntaxException",
			message: err.Error(),
		}
	}
	return re, nil
}

func expandJavaReplacementForMatchRound57(re *regexp.Regexp, input string, loc []int, repl string) (string, error) {
	var sb strings.Builder
	sb.Grow(len(repl) + 8)
	numSubexp := 0
	var subexpNames []string
	if re != nil {
		numSubexp = re.NumSubexp()
		subexpNames = re.SubexpNames()
	}

	cursor := 0
	for cursor < len(repl) {
		ch := repl[cursor]
		if ch == '\\' {
			cursor++
			if cursor >= len(repl) {
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: "character to be escaped is missing",
				}
			}
			r, w := utf8.DecodeRuneInString(repl[cursor:])
			sb.WriteRune(r)
			cursor += w
			continue
		}
		if ch == '$' {
			cursor++
			if cursor >= len(repl) {
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: "Illegal group reference: group index is missing",
				}
			}
			if repl[cursor] == '{' {
				cursor++
				nameStart := cursor
				for cursor < len(repl) && repl[cursor] != '}' {
					c := repl[cursor]
					valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (cursor > nameStart && c >= '0' && c <= '9')
					if !valid {
						return "", &painlessExceptionError{
							exType:  "IllegalArgumentException",
							message: "Illegal group reference",
						}
					}
					cursor++
				}
				if cursor >= len(repl) || cursor == nameStart {
					return "", &painlessExceptionError{
						exType:  "IllegalArgumentException",
						message: "Illegal group reference",
					}
				}
				gName := repl[nameStart:cursor]
				cursor++ // consume '}'
				gIdx := -1
				for i := 1; i < len(subexpNames); i++ {
					if subexpNames[i] == gName {
						gIdx = i
						break
					}
				}
				if gIdx < 0 {
					return "", &painlessExceptionError{
						exType:  "IllegalArgumentException",
						message: fmt.Sprintf("No group with name {%s}", gName),
					}
				}
				if 2*gIdx+1 < len(loc) && loc[2*gIdx] >= 0 && loc[2*gIdx+1] >= 0 {
					sb.WriteString(input[loc[2*gIdx]:loc[2*gIdx+1]])
				}
				continue
			}
			if repl[cursor] < '0' || repl[cursor] > '9' {
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: "Illegal group reference",
				}
			}
			refNum := int(repl[cursor] - '0')
			cursor++
			if refNum > numSubexp {
				return "", &painlessExceptionError{
					exType:  "IndexOutOfBoundsException",
					message: fmt.Sprintf("No group %d", refNum),
				}
			}
			for cursor < len(repl) && repl[cursor] >= '0' && repl[cursor] <= '9' {
				nextNum := refNum*10 + int(repl[cursor]-'0')
				if numSubexp < nextNum {
					break
				}
				refNum = nextNum
				cursor++
			}
			if 2*refNum+1 < len(loc) && loc[2*refNum] >= 0 && loc[2*refNum+1] >= 0 {
				sb.WriteString(input[loc[2*refNum]:loc[2*refNum+1]])
			}
			continue
		}
		r, w := utf8.DecodeRuneInString(repl[cursor:])
		sb.WriteRune(r)
		cursor += w
	}
	return sb.String(), nil
}

func applyJavaMatcherReplacement(re *regexp.Regexp, s, repl string, firstOnly bool) (string, error) {
	if re == nil {
		return s, nil
	}
	if firstOnly {
		loc := re.FindStringSubmatchIndex(s)
		if loc == nil {
			return s, nil
		}
		expanded, err := expandJavaReplacementForMatchRound57(re, s, loc, repl)
		if err != nil {
			return "", err
		}
		return s[:loc[0]] + expanded + s[loc[1]:], nil
	}
	locs := re.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s, nil
	}
	var out strings.Builder
	out.Grow(len(s) + len(repl))
	lastEnd := 0
	for _, loc := range locs {
		out.WriteString(s[lastEnd:loc[0]])
		expanded, err := expandJavaReplacementForMatchRound57(re, s, loc, repl)
		if err != nil {
			return "", err
		}
		out.WriteString(expanded)
		lastEnd = loc[1]
	}
	out.WriteString(s[lastEnd:])
	return out.String(), nil
}

// ---------------------------------------------------------------------------
// F25: Exception Hierarchy, Abrupt Jump Propagation & Post-super Field Init
// ---------------------------------------------------------------------------

func stripJavaExceptionPkgPrefixRound57(name string) string {
	t := strings.TrimSpace(name)
	for _, pfx := range []string{
		"java.lang.", "java.time.format.", "java.time.temporal.", "java.time.",
		"java.util.regex.", "java.util.concurrent.", "java.util.", "java.math.",
		"java.io.", "java.net.", "java.nio.charset.", "java.text.",
	} {
		if strings.HasPrefix(t, pfx) {
			return strings.TrimPrefix(t, pfx)
		}
	}
	return t
}

func parentJavaExceptionTypeRound57(exType string, budget *evalBudget) string {
	if budget != nil && len(budget.userClasses) > 0 {
		if uCls := budget.userClasses[exType]; uCls != nil && uCls.parentName != "" {
			return stripJavaExceptionPkgPrefixRound57(uCls.parentName)
		}
	}
	switch exType {
	case "NumberFormatException", "PatternSyntaxException", "IllegalFormatException":
		return "IllegalArgumentException"
	case "ArrayIndexOutOfBoundsException", "StringIndexOutOfBoundsException":
		return "IndexOutOfBoundsException"
	case "DateTimeParseException", "UnsupportedTemporalTypeException", "ZoneRulesException":
		return "DateTimeException"
	case "InputMismatchException":
		return "NoSuchElementException"
	case "IllegalArgumentException", "IndexOutOfBoundsException", "DateTimeException",
		"NullPointerException", "ArithmeticException", "IllegalStateException",
		"ClassCastException", "UnsupportedOperationException", "NoSuchElementException",
		"NegativeArraySizeException", "ArrayStoreException", "SecurityException",
		"ConcurrentModificationException", "UncheckedIOException":
		return "RuntimeException"
	case "MalformedURLException":
		return "IOException"
	case "RuntimeException", "IOException", "URISyntaxException", "ParseException":
		return "Exception"
	case "AssertionError", "StackOverflowError", "OutOfMemoryError":
		return "Error"
	case "Exception", "Error":
		return "Throwable"
	case "Throwable":
		return "Object"
	case "Object":
		return ""
	}
	if strings.HasSuffix(exType, "Error") {
		return "Error"
	}
	if strings.HasSuffix(exType, "Exception") {
		return "RuntimeException"
	}
	return ""
}

func painlessExceptionIsAssignableTo(actualType, catchType string, budget *evalBudget) bool {
	actual := stripJavaExceptionPkgPrefixRound57(actualType)
	target := stripJavaExceptionPkgPrefixRound57(catchType)
	if target == "" || target == "def" || target == "Object" || target == "Throwable" {
		return true
	}
	if actual == "" {
		actual = "RuntimeException"
	}
	visited := 0
	for cur := actual; cur != "" && visited < 32; visited++ {
		if cur == target {
			return true
		}
		cur = parentJavaExceptionTypeRound57(cur, budget)
	}
	return false
}

func extractThrownExceptionTypeAndMsgRound57(err error) (exType string, msg string) {
	if err == nil {
		return "", ""
	}
	var pEx *painlessExceptionError
	if errors.As(err, &pEx) {
		t := strings.TrimSpace(pEx.exType)
		if t == "" {
			t = "RuntimeException"
		}
		return stripJavaExceptionPkgPrefixRound57(t), pEx.message
	}
	raw := err.Error()
	if colonIdx := strings.IndexByte(raw, ':'); colonIdx > 0 {
		cand := strings.TrimSpace(raw[:colonIdx])
		candSimple := stripJavaExceptionPkgPrefixRound57(cand)
		if reIdentOnly.MatchString(candSimple) && (strings.HasSuffix(candSimple, "Exception") || strings.HasSuffix(candSimple, "Error") || candSimple == "Throwable") {
			return candSimple, strings.TrimSpace(raw[colonIdx+1:])
		}
	}
	return "RuntimeException", raw
}

func matchesCatchExceptionRound57(err error, excTypes []string, budget *evalBudget) bool {
	if len(excTypes) == 0 {
		return true
	}
	actualType, _ := extractThrownExceptionTypeAndMsgRound57(err)
	for _, t := range excTypes {
		if painlessExceptionIsAssignableTo(actualType, t, budget) {
			return true
		}
	}
	return false
}

func isAbruptControlFlowPainless(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errPainlessReturn) || errors.Is(err, errPainlessBreak) || errors.Is(err, errPainlessContinue) || errors.Is(err, errPainlessYield) {
		return true
	}
	var lblJump *painlessLabeledJumpError
	return errors.As(err, &lblJump)
}

func shouldPropagateReceiverEvalErrorRound57(err error) bool {
	if err == nil {
		return false
	}
	if isAbruptControlFlowPainless(err) || isUnrecoverableSandboxError(err) {
		return true
	}
	var pEx *painlessExceptionError
	return errors.As(err, &pEx)
}

func anyUserClassDefinesMethodRound57(budget *evalBudget, methodName string) bool {
	if budget == nil || len(budget.userClasses) == 0 {
		return false
	}
	for _, cls := range budget.userClasses {
		if cls != nil && len(cls.findMethod(methodName)) > 0 {
			return true
		}
	}
	return false
}

func isNullUserMethodReceiverRound57(recExpr string, methodName string, params map[string]any, budget *evalBudget) bool {
	clean := stripBalancedOuterParensRound57(recExpr)
	if clean == "null" {
		return anyUserClassDefinesMethodRound57(budget, methodName)
	}
	if castType, _, ok := splitLeadingTypeCastPainless(clean); ok {
		if budget != nil && budget.userClasses[castType] != nil {
			return true
		}
	}
	if reIdentOnly.MatchString(clean) && params != nil {
		if _, isUserVar := params["__user_var_class_"+clean]; isUserVar {
			return true
		}
	}
	if strings.HasPrefix(clean, "ctx") || strings.HasPrefix(clean, "doc") || strings.HasPrefix(clean, "params") {
		return false
	}
	return anyUserClassDefinesMethodRound57(budget, methodName)
}

func initDeclaredClassFieldsRound57Painless(uo *painlessUserObject, cls *painlessUserClass, sourceMap, params map[string]any, depth int) error {
	if uo == nil || cls == nil {
		return nil
	}
	localScope := make(map[string]any, len(params)+len(cls.fields)+4)
	for k, v := range params {
		if strings.HasPrefix(k, "__var_type_") || strings.HasPrefix(k, "__user_var_class_") {
			continue
		}
		localScope[k] = v
	}
	localScope["this"] = uo
	localScope["__current_class"] = cls
	for _, f := range cls.fields {
		if f.initExpr == "" {
			continue
		}
		val, err := evalRHSExprDepth(sourceMap, f.initExpr, localScope, depth+1)
		if err != nil {
			return err
		}
		switch f.typeName {
		case "byte", "short", "char", "int", "long", "float", "double", "boolean":
			val = coerceTypedVarRound57Painless(f.typeName, val)
		}
		uo.fields[f.name] = val
	}
	return nil
}

// ---------------------------------------------------------------------------
// F26: Map Key Encoding & Map.merge / compute* NullPointerException Contracts
// ---------------------------------------------------------------------------

func encodePainlessMapKeyRound57(kVal any) string {
	if kVal == nil || kVal == painlessEmptyOptional {
		return painlessNullMapKey
	}
	if opt, ok := kVal.(*painlessOptional); ok && !opt.present {
		return painlessNullMapKey
	}
	if bd, ok := kVal.(*painlessBigDecimal); ok && bd != nil && bd.unscaled != nil {
		return painlessBigDecKeyPref + bd.unscaled.String() + ":" + strconv.Itoa(bd.scale)
	}
	if bi, ok := kVal.(*painlessBigInteger); ok && bi != nil && bi.val != nil {
		return painlessBigIntKeyPref + bi.val.String()
	}
	return fmt.Sprintf("%v", kVal)
}

func decodePainlessMapKeyRound57(kStr string) any {
	if kStr == painlessNullMapKey {
		return nil
	}
	if strings.HasPrefix(kStr, painlessBigDecKeyPref) {
		rest := strings.TrimPrefix(kStr, painlessBigDecKeyPref)
		if sep := strings.LastIndexByte(rest, ':'); sep > 0 {
			if bi, ok := new(big.Int).SetString(rest[:sep], 10); ok {
				if sc, err := strconv.Atoi(rest[sep+1:]); err == nil {
					return newPainlessBigDecimal(bi, sc)
				}
			}
		}
	}
	if strings.HasPrefix(kStr, painlessBigIntKeyPref) {
		raw := strings.TrimPrefix(kStr, painlessBigIntKeyPref)
		if bi, ok := new(big.Int).SetString(raw, 10); ok {
			return newPainlessBigInteger(bi)
		}
	}
	return kStr
}

func validateAndNormalizeMapLambdaRound57(rawFnExpr string, arity int, fnLabel string, sourceMap, params map[string]any, depth int) (string, int, error) {
	trimmed := strings.TrimSpace(rawFnExpr)
	if trimmed == "" || trimmed == "null" {
		return "", -1, &painlessExceptionError{
			exType:  "NullPointerException",
			message: fnLabel + " is null",
		}
	}
	fnExpr := normalizeMethodReferenceToLambdaPainless(trimmed, arity)
	arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
	if arrowIdx <= 0 {
		fnVal, err := evalRHSExprDepth(sourceMap, trimmed, params, depth+1)
		if err != nil {
			return "", -1, err
		}
		if isEmptyOptionalOrNilPainless(fnVal) {
			return "", -1, &painlessExceptionError{
				exType:  "NullPointerException",
				message: fnLabel + " is null",
			}
		}
		return fnExpr, -1, nil
	}
	return fnExpr, arrowIdx, nil
}
