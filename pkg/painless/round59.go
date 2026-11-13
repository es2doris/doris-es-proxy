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
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ============================================================================
// Round 59: Painless Engine Spec Compliance (F20-F26)
//   F20: Right-associative assignment expressions & left-associative equality/relational chaining
//   F21: Reference, collection, array & user-class casts (ClassCastException / primitive NPE)
//   F22: switch null NPE, strict non-coercive case matching & block scoping
//   F23: User-defined function overloading by arity, arg/return type validation & static scope isolation
//   F24: java.util.Arrays exact JDK range bounds & null receiver NPE
//   F25: List / Collection / Map method bounds & null collection/map argument NPE
//   F26: Lazy Stream pipeline short-circuiting, unbounded IntStream/LongStream.range & flatMap validation
// ============================================================================

// ----------------------------------------------------------------------------
// Runtime Slice Tagging Helpers (Set vs List vs Java Typed Arrays)
// ----------------------------------------------------------------------------

func ensureUniqueBackingSliceRound59(s []any) []any {
	if s == nil {
		return make([]any, 0, 1)
	}
	if cap(s) == 0 {
		return make([]any, 0, 1)
	}
	return s
}

func markSetSliceRound59(budget *evalBudget, s []any) []any {
	out := ensureUniqueBackingSliceRound59(s)
	if budget != nil {
		if budget.setSlices == nil {
			budget.setSlices = make(map[uintptr]bool)
		}
		budget.setSlices[reflect.ValueOf(out).Pointer()] = true
	}
	return out
}

func isSetSliceRound59(budget *evalBudget, v any) bool {
	s, ok := v.([]any)
	if !ok || budget == nil || len(budget.setSlices) == 0 || cap(s) == 0 {
		return false
	}
	return budget.setSlices[reflect.ValueOf(s).Pointer()]
}

func markTypedArraySliceRound59(budget *evalBudget, s []any, arrType string) []any {
	out := ensureUniqueBackingSliceRound59(s)
	if budget != nil && arrType != "" {
		if budget.arrayTypes == nil {
			budget.arrayTypes = make(map[uintptr]string)
		}
		budget.arrayTypes[reflect.ValueOf(out).Pointer()] = arrType
	}
	return out
}

func tagMultiDimArraySliceRound59(budget *evalBudget, s []any, baseCls string, dims int) []any {
	if budget == nil || dims <= 0 {
		return s
	}
	normBase := normalizeDeclaredSignatureTypeRound59(baseCls)
	if normBase == "def" {
		normBase = "Object"
	}
	if dims > 1 {
		for i, el := range s {
			if sub, ok := el.([]any); ok {
				s[i] = tagMultiDimArraySliceRound59(budget, sub, normBase, dims-1)
			}
		}
	}
	return markTypedArraySliceRound59(budget, s, normBase+strings.Repeat("[]", dims))
}

func getTypedArraySliceRound59(budget *evalBudget, v any) (string, bool) {
	s, ok := v.([]any)
	if !ok || budget == nil || len(budget.arrayTypes) == 0 || cap(s) == 0 {
		return "", false
	}
	t, exists := budget.arrayTypes[reflect.ValueOf(s).Pointer()]
	return t, exists && t != ""
}

func propagateSliceTagsRound59(budget *evalBudget, oldSlice, newSlice []any) []any {
	if budget == nil || cap(oldSlice) == 0 {
		return newSlice
	}
	oldPtr := reflect.ValueOf(oldSlice).Pointer()
	isSet := len(budget.setSlices) > 0 && budget.setSlices[oldPtr]
	arrType, isArr := "", false
	if len(budget.arrayTypes) > 0 {
		arrType, isArr = budget.arrayTypes[oldPtr]
	}
	if !isSet && !isArr {
		return newSlice
	}
	newSlice = ensureUniqueBackingSliceRound59(newSlice)
	if isSet {
		markSetSliceRound59(budget, newSlice)
	}
	if isArr {
		markTypedArraySliceRound59(budget, newSlice, arrType)
	}
	return newSlice
}

// ----------------------------------------------------------------------------
// F20: Left-Associative Equality/Relational Scanner & Right-Associative Assignments
// ----------------------------------------------------------------------------

// findLastTopLevelAnyOpPainless returns the rightmost top-level index and operator
// among ops, preserving left-associative evaluation when splitting at the returned index.
func findLastTopLevelAnyOpPainless(expr string, ops []string) (int, string) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastIdx := -1
	lastOp := ""
	for i := 0; i < len(expr); i++ {
		if stepQuoteState(expr, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch expr[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth != 0 {
				continue
			}
			for _, op := range ops {
				if i+len(op) > len(expr) || expr[i:i+len(op)] != op {
					continue
				}
				if !isStandaloneComparisonOpAtRound59(expr, i, op) {
					continue
				}
				lastIdx = i
				lastOp = op
				i += len(op) - 1
				break
			}
		}
	}
	return lastIdx, lastOp
}

func isStandaloneComparisonOpAtRound59(s string, i int, op string) bool {
	switch op {
	case "!==":
		return true
	case "===":
		if i > 0 && s[i-1] == '!' {
			return false
		}
		return true
	case "!=":
		if i+2 < len(s) && s[i+2] == '=' {
			return false
		}
		return true
	case "==":
		if i+2 < len(s) && (s[i+2] == '=' || s[i+2] == '~') {
			return false
		}
		if i > 0 && (s[i-1] == '=' || s[i-1] == '!') {
			return false
		}
		return true
	case ">=":
		if i > 0 && s[i-1] == '>' {
			return false
		}
		return true
	case "<=":
		if i > 0 && s[i-1] == '<' {
			return false
		}
		return true
	case ">":
		if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>') {
			return false
		}
		if i > 0 && (s[i-1] == '>' || s[i-1] == '-') {
			return false
		}
		return true
	case "<":
		if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '<') {
			return false
		}
		if i > 0 && s[i-1] == '<' {
			return false
		}
		return true
	}
	return true
}

var assignOpsOrderedRound59 = []string{
	">>>=", "<<=", ">>=",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
	"=",
}

// findFirstTopLevelAssignOpRound59 scans left-to-right for the first top-level
// assignment operator at depth 0 (enabling right-associative recursion on RHS).
func findFirstTopLevelAssignOpRound59(expr string) (lhs string, op string, rhs string, ok bool) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(expr); i++ {
		if stepQuoteState(expr, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := expr[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth != 0 {
				continue
			}
			// Lambda arrow at depth 0 means outer expression is a lambda, not an assignment.
			if c == '-' && i+1 < len(expr) && expr[i+1] == '>' {
				return "", "", "", false
			}
			// Ternary/Elvis `?` at depth 0 before `=` means outer expression is ternary/Elvis.
			if c == '?' && (i+1 >= len(expr) || expr[i+1] != '.') {
				return "", "", "", false
			}
			for _, cand := range assignOpsOrderedRound59 {
				if i+len(cand) > len(expr) || expr[i:i+len(cand)] != cand {
					continue
				}
				if cand == "=" {
					if i+1 < len(expr) && (expr[i+1] == '=' || expr[i+1] == '~') {
						continue
					}
					if i > 0 {
						prev := expr[i-1]
						if prev == '=' || prev == '!' || prev == '<' || prev == '>' ||
							prev == '+' || prev == '-' || prev == '*' || prev == '/' ||
							prev == '%' || prev == '&' || prev == '|' || prev == '^' {
							continue
						}
					}
				} else if cand == ">>=" && i > 0 && expr[i-1] == '>' {
					continue
				}
				rawLHS := strings.TrimSpace(expr[:i])
				rawRHS := strings.TrimSpace(expr[i+len(cand):])
				if rawLHS == "" || rawRHS == "" || !isValidAssignmentLHSRound59(rawLHS) {
					return "", "", "", false
				}
				return rawLHS, cand, rawRHS, true
			}
		}
	}
	return "", "", "", false
}

func isValidAssignmentLHSRound59(lhs string) bool {
	t := trimBalancedParens(lhs)
	if t == "" || t == "null" || t == "true" || t == "false" || t == "this" || t == "super" || isPainlessReservedKeyword(t) {
		return false
	}
	if t[0] == '\'' || t[0] == '"' || (t[0] >= '0' && t[0] <= '9') {
		return false
	}
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(t); i++ {
		if stepQuoteState(t, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := t[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth != 0 {
				continue
			}
			switch c {
			case '+', '-', '*', '/', '%', '&', '|', '^', '!', '<', '>', '=', ':', ';', ',':
				return false
			case '?':
				if i+1 >= len(t) || t[i+1] != '.' {
					return false
				}
			}
		}
	}
	return !strings.HasSuffix(t, ")")
}

func validateUserClassVarValueRound59(varName string, val any, params map[string]any, budget *evalBudget) error {
	if params == nil || val == nil {
		return nil
	}
	uClsName, ok := params["__user_var_class_"+varName].(string)
	if !ok || uClsName == "" {
		return nil
	}
	uo, isUO := val.(*painlessUserObject)
	if !isUO || uo == nil || uo.class == nil || !uo.class.isInstanceOf(uClsName) {
		return &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("Cannot cast %T to %s", val, uClsName),
		}
	}
	return nil
}

func coerceAndValidateLocalAssignRound59(declType, rhsExpr string, val any, params map[string]any) (any, error) {
	if declType == "" {
		return val, nil
	}
	if val == nil {
		if isJavaPrimitiveCastTypeRound59(declType) {
			return nil, &painlessExceptionError{
				exType:  "NullPointerException",
				message: fmt.Sprintf("Cannot unbox null to %s", declType),
			}
		}
		return nil, nil
	}
	return evalExplicitCastRound59Painless(declType, rhsExpr, val, params)
}

func evalAssignExprRound59Painless(sourceMap map[string]any, lhsRaw, op, rhsRaw string, params map[string]any, depth int) (any, error) {
	budget := getOrInitEvalBudget(params)
	lhs := trimBalancedParens(lhsRaw)
	if lhs == "" {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid assignment target"}
	}
	if lhs == "doc" || strings.HasPrefix(lhs, "doc.") || strings.HasPrefix(lhs, "doc?.") || strings.HasPrefix(lhs, "doc[") {
		return nil, &painlessExceptionError{exType: "UnsupportedOperationException", message: "doc fields are read-only"}
	}

	// Post-call property/index target: e.g. `getObj().field = 5`
	if callExpr, tailPath, ok := splitPostCallPropertyAccess(lhs); ok {
		callVal, err := evalRHSExprDepth(sourceMap, callExpr, params, depth+1)
		if err != nil {
			return nil, err
		}
		if callVal == nil {
			return nil, &painlessExceptionError{exType: "NullPointerException", message: "Cannot assign property on null target"}
		}
		wrapRoot := map[string]any{"_v": callVal}
		expTail := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expandDynamicBrackets(tailPath+" =", sourceMap, params, depth+1)), "="))
		wrapPath := append([]string{"_v"}, strings.Split(expTail, ".")...)
		if err := checkMutableParentAtPathPainless(budget, wrapRoot, wrapPath); err != nil {
			return nil, err
		}
		var curVal any
		if op != "=" {
			curVal = resolveParamPath(wrapRoot, wrapPath)
		}
		rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return nil, err
		}
		finalVal := rhsVal
		if op != "=" {
			finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, lhs, rhsRaw, "", params)
			if err != nil {
				return nil, err
			}
		}
		setValueAtPath(wrapRoot, wrapPath, finalVal)
		return finalVal, nil
	}

	expLHS := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expandDynamicBrackets(lhs+" =", sourceMap, params, depth+1)), "="))
	_, hasRawSrc := rawSourceFromSourceMapPainless(sourceMap)
	if !hasRawSrc {
		for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
			if strings.HasPrefix(expLHS, pfx) {
				expLHS = "ctx._source." + strings.TrimPrefix(expLHS, pfx)
				break
			}
		}
	}

	// 1. `ctx.op = ...`
	if (expLHS == "ctx.op" || expLHS == "ctx?.op") && (params == nil || params["ctx"] == nil) {
		var curVal any
		if op != "=" && params != nil {
			curVal = params["_ctx_op"]
		}
		rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return nil, err
		}
		finalVal := rhsVal
		if op != "=" {
			finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, expLHS, rhsRaw, "", params)
			if err != nil {
				return nil, err
			}
		}
		opStr := ""
		if finalVal != nil {
			opStr = fmt.Sprintf("%v", finalVal)
		}
		if params != nil {
			params["_ctx_op"] = opStr
		}
		if budget != nil {
			budget.ctxOp = opStr
			budget.hasCtxOp = true
		}
		return finalVal, nil
	}

	// 2. `ctx._source.<path> = ...` or `_source.<path> = ...`
	for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
		if strings.HasPrefix(expLHS, pfx) && (params == nil || params["ctx"] == nil) {
			relPath := strings.TrimSuffix(strings.TrimPrefix(expLHS, pfx), "?")
			lhsPath := strings.Split(relPath, ".")
			if err := checkMutableParentAtPathPainless(budget, sourceMap, lhsPath); err != nil {
				return nil, err
			}
			var curVal any
			if op != "=" {
				curVal = resolveParamPath(sourceMap, lhsPath)
			}
			rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
			if err != nil {
				return nil, err
			}
			finalVal := rhsVal
			if op != "=" {
				finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, "ctx._source."+relPath, rhsRaw, "", params)
				if err != nil {
					return nil, err
				}
			}
			setValueAtPath(sourceMap, lhsPath, finalVal)
			syncSourceAliasToLocalVars(sourceMap, params, relPath)
			return finalVal, nil
		}
	}
	for _, pfx := range []string{"_source?.", "_source."} {
		if strings.HasPrefix(expLHS, pfx) && !hasRawSrc && (params == nil || params["_source"] == nil) {
			relPath := strings.TrimSuffix(strings.TrimPrefix(expLHS, pfx), "?")
			lhsPath := strings.Split(relPath, ".")
			if err := checkMutableParentAtPathPainless(budget, sourceMap, lhsPath); err != nil {
				return nil, err
			}
			var curVal any
			if op != "=" {
				curVal = resolveParamPath(sourceMap, lhsPath)
			}
			rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
			if err != nil {
				return nil, err
			}
			finalVal := rhsVal
			if op != "=" {
				finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, "ctx._source."+relPath, rhsRaw, "", params)
				if err != nil {
					return nil, err
				}
			}
			setValueAtPath(sourceMap, lhsPath, finalVal)
			syncSourceAliasToLocalVars(sourceMap, params, relPath)
			return finalVal, nil
		}
	}

	// 3. `ctx._source = ...`
	if (expLHS == "ctx._source" || expLHS == "ctx?._source") && (params == nil || params["ctx"] == nil) {
		rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return nil, err
		}
		if _, err := mutateCtxDirectMapKey("_source", rhsVal, false, false, sourceMap, params); err != nil {
			return nil, err
		}
		return rhsVal, nil
	}

	// 4. Dotted or bracketed local/object/static/meta path
	if strings.Contains(expLHS, ".") {
		cleanParts := strings.Split(strings.ReplaceAll(expLHS, "?.", "."), ".")
		varName := strings.TrimSuffix(cleanParts[0], "?")
		propPath := cleanParts[1:]
		if varName == "doc" {
			return nil, &painlessExceptionError{exType: "UnsupportedOperationException", message: "doc fields are read-only"}
		}
		if _, err := checkCtxMetaLHS(append([]string{varName}, propPath...), sourceMap, params); err != nil {
			return nil, err
		}
		if varName == "super" && len(propPath) == 1 {
			if uo, isThis := params["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil {
				curVal := uo.fields[propPath[0]]
				rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
				if err != nil {
					return nil, err
				}
				ft := findUserFieldDeclaredTypeRound57(uo.class, propPath[0])
				finalVal := rhsVal
				if op != "=" {
					finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, expLHS, rhsRaw, ft, params)
					if err != nil {
						return nil, err
					}
				} else if ft != "" {
					finalVal = coerceTypedVarRound57Painless(ft, finalVal)
				}
				uo.fields[propPath[0]] = finalVal
				return finalVal, nil
			}
		}
		if budget != nil && len(budget.userClasses) > 0 && len(propPath) == 1 {
			if uCls := budget.userClasses[varName]; uCls != nil {
				curVal, hasStatic := uCls.getStaticField(propPath[0])
				if hasStatic {
					rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
					if err != nil {
						return nil, err
					}
					finalVal := rhsVal
					if op != "=" {
						finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, expLHS, rhsRaw, "", params)
						if err != nil {
							return nil, err
						}
					}
					uCls.setStaticField(propPath[0], finalVal)
					return finalVal, nil
				}
			}
		}

		fullPath := normalizeLocalLHSPath(append([]string{varName}, propPath...), params)
		if len(fullPath) > 1 {
			if err := checkMutableParentAtPathPainless(budget, params, fullPath); err != nil {
				return nil, err
			}
			parentVal := resolveParamPath(params, fullPath[:len(fullPath)-1])
			if parentVal == nil && !strings.Contains(expLHS, "?.") {
				return nil, &painlessExceptionError{exType: "NullPointerException", message: "Cannot assign on null target"}
			}
		}
		declType := ""
		if len(fullPath) == 2 {
			if uo, isUO := params[decodeBracketSeg(fullPath[0])].(*painlessUserObject); isUO && uo != nil {
				declType = findUserFieldDeclaredTypeRound57(uo.class, decodeBracketSeg(fullPath[1]))
			}
		}
		var curVal any
		if op != "=" {
			curVal = resolveParamPath(params, fullPath)
		}
		rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return nil, err
		}
		finalVal := rhsVal
		if op != "=" {
			finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, expLHS, rhsRaw, declType, params)
			if err != nil {
				return nil, err
			}
		} else if declType != "" {
			finalVal = coerceTypedVarRound57Painless(declType, finalVal)
		}
		if len(fullPath) > 0 {
			setValueAtPath(params, fullPath, finalVal)
			if decodeBracketSeg(varName) == "params" && len(fullPath) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(fullPath[0]))
			}
			latchCtxMetaOnBudget(budget, fullPath, finalVal)
			if len(propPath) == 1 && propPath[0] == "value" {
				if entryMap, ok := params[varName].(map[string]any); ok {
					if pm, ok := entryMap["__parent_map"].(map[string]any); ok {
						pm[encodePainlessMapKeyRound57(entryMap["key"])] = finalVal
					}
				}
			}
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(fullPath[0]))
		}
		return finalVal, nil
	}

	// 5. Simple identifier assignment (`a = ...`, `a += ...`)
	varName := decodeBracketSeg(expLHS)
	if !reIdentOnly.MatchString(varName) {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Invalid assignment target [%s]", lhs)}
	}
	if params == nil {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Variable [%s] is not defined", varName)}
	}

	declType := getLocalVarPrimitiveTypeRound57(params, varName)
	var fieldOwner *painlessUserObject
	if declType == "" {
		fieldOwner, declType = resolveUnshadowedThisFieldTypeRound57(params, varName)
	}
	if fieldOwner == nil {
		if uo, isThis := params["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil {
			_, isLocal := params[varName]
			if !isLocal {
				if _, hasF := uo.fields[varName]; hasF {
					fieldOwner = uo
				}
			}
		}
	}

	var curStaticCls *painlessUserClass
	if fieldOwner == nil {
		if _, exists := params[varName]; !exists {
			if cc, isCC := params["__current_class"].(*painlessUserClass); isCC && cc != nil {
				if _, hasS := cc.getStaticField(varName); hasS {
					curStaticCls = cc
				}
			}
		}
	}

	_, existed := params[varName]
	if !existed && fieldOwner == nil && curStaticCls == nil {
		if op != "=" || params["__in_user_func"] == true {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Variable [%s] is not defined", varName)}
		}
	}
	if oos, ok := params["__out_of_scope_vars"].(map[string]bool); ok && oos[varName] {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Variable [%s] is not defined", varName)}
	}

	var curVal any
	if op != "=" {
		switch {
		case fieldOwner != nil:
			curVal = fieldOwner.fields[varName]
		case curStaticCls != nil:
			curVal, _ = curStaticCls.getStaticField(varName)
		default:
			curVal = params[varName]
		}
	}

	rhsVal, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
	if err != nil {
		return nil, err
	}

	var finalVal any
	if op != "=" {
		finalVal, err = evalCompoundAssignRound57Painless(curVal, rhsVal, op, varName, rhsRaw, declType, params)
		if err != nil {
			return nil, err
		}
	} else {
		if err := validateUserClassVarValueRound59(varName, rhsVal, params, budget); err != nil {
			return nil, err
		}
		finalVal, err = coerceAndValidateLocalAssignRound59(declType, rhsRaw, rhsVal, params)
		if err != nil {
			return nil, err
		}
	}

	if curStaticCls != nil {
		curStaticCls.setStaticField(varName, finalVal)
		return finalVal, nil
	}
	if !existed && fieldOwner == nil {
		if sl, ok := params["__script_locals"].(map[string]bool); ok {
			sl[varName] = true
		}
	}
	params[varName] = finalVal
	if fieldOwner != nil {
		fieldOwner.fields[varName] = finalVal
	}
	if rv, ok := params["__reassigned_vars"].(map[string]bool); ok {
		rv[varName] = true
	}
	delete(params, "__alias_"+varName)
	return finalVal, nil
}

// ----------------------------------------------------------------------------
// F21: Reference, Collection, Array & User-Class Type Casts
// ----------------------------------------------------------------------------

func isJavaPrimitiveCastTypeRound59(t string) bool {
	switch t {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return true
	}
	return false
}

func isBuiltInScalarOrColCastBaseRound59(base string) bool {
	switch base {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean",
		"Byte", "Short", "Integer", "Long", "Float", "Double", "Character", "Boolean",
		"Number", "BigDecimal", "BigInteger",
		"String", "CharSequence", "Object", "def",
		"List", "ArrayList", "LinkedList",
		"Map", "HashMap", "LinkedHashMap", "TreeMap",
		"Set", "HashSet", "LinkedHashSet", "TreeSet",
		"Collection":
		return true
	}
	return false
}

// normalizeCastTypeCandidateRound59 parses a cast type inside `(...)` such as
// `Set`, `Collection`, `Number`, `int[]`, `String[][]`, `List<String>`, or a declared user class.
func normalizeCastTypeCandidateRound59(cand string, budget *evalBudget) (string, bool) {
	s := strings.TrimSpace(cand)
	if s == "" {
		return "", false
	}
	// Count trailing `[]` dimensions (allowing whitespace inside `[ ]`).
	dims := 0
	for strings.HasSuffix(s, "]") {
		openBr := strings.LastIndexByte(s, '[')
		if openBr <= 0 || strings.TrimSpace(s[openBr+1:len(s)-1]) != "" {
			return "", false
		}
		dims++
		s = strings.TrimSpace(s[:openBr])
	}
	// Strip optional generic suffix `<...>`, e.g. `List<String>` or `Map<String, Object>`.
	if strings.HasSuffix(s, ">") {
		openAng := strings.IndexByte(s, '<')
		if openAng <= 0 || findMatchingDelimiter(s, openAng, '<', '>') != len(s)-1 {
			return "", false
		}
		s = strings.TrimSpace(s[:openAng])
	}
	for _, pfx := range []string{"java.math.", "java.lang.", "java.util."} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimPrefix(s, pfx)
			break
		}
	}
	if !reIdentOnly.MatchString(s) {
		return "", false
	}
	isKnown := isBuiltInScalarOrColCastBaseRound59(s)
	if !isKnown && budget != nil && len(budget.userClasses) > 0 {
		_, isKnown = budget.userClasses[s]
	}
	if !isKnown {
		return "", false
	}
	if s == "def" && dims > 0 {
		s = "Object"
	}
	return s + strings.Repeat("[]", dims), true
}

func isInvalidCastFollowerRound59(rest string) bool {
	if rest == "" {
		return true
	}
	switch rest[0] {
	case '.', '*', '/', '%', '&', '|', '^', '=', '<', '>', '?', ':', ',', ';', ')', ']':
		return true
	}
	if strings.HasPrefix(rest, "instanceof ") || strings.HasPrefix(rest, "->") {
		return true
	}
	return false
}

func splitLeadingTypeCastRound59(s string, params map[string]any) (castType, rest string, ok bool) {
	if !strings.HasPrefix(s, "(") {
		return "", "", false
	}
	closeP := findMatchingDelimiter(s, 0, '(', ')')
	if closeP <= 1 || closeP >= len(s)-1 {
		return "", "", false
	}
	tail := strings.TrimSpace(s[closeP+1:])
	if isInvalidCastFollowerRound59(tail) {
		return "", "", false
	}
	var budget *evalBudget
	if params != nil {
		budget = getOrInitEvalBudget(params)
	}
	normType, valid := normalizeCastTypeCandidateRound59(s[1:closeP], budget)
	if !valid {
		return "", "", false
	}
	return normType, tail, true
}

func isSingleQuotedCharExprRound59(expr string) bool {
	t := trimBalancedParens(expr)
	return len(t) >= 2 && t[0] == '\'' && t[len(t)-1] == '\''
}

func isDoubleQuotedStringLiteralRound59(expr string) bool {
	t := trimBalancedParens(expr)
	return len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"'
}

func isCharExprRound59(expr string, params map[string]any) bool {
	t := trimBalancedParens(expr)
	if isSingleQuotedCharExprRound59(t) {
		return true
	}
	if strings.HasPrefix(t, "(char)") || strings.HasPrefix(t, "(Character)") {
		return true
	}
	for _, pfx := range []string{
		"Character.forDigit(", "Character.highSurrogate(",
		"Character.lowSurrogate(", "Character.reverseBytes(", "Character.valueOf(",
	} {
		if strings.HasPrefix(t, pfx) {
			return true
		}
	}
	if strings.Contains(t, ".charAt(") && strings.HasSuffix(t, ")") {
		return true
	}
	if params != nil && reIdentOnly.MatchString(t) {
		vt, _ := params["__var_type_"+t].(string)
		if vt == "char" || vt == "Character" {
			return true
		}
	}
	return false
}

func isSetValueRound59(val any, expr string, params map[string]any, budget *evalBudget) bool {
	if isSetSliceRound59(budget, val) {
		return true
	}
	t := trimBalancedParens(expr)
	if params != nil && reIdentOnly.MatchString(t) {
		if ck, _ := params["__col_kind_"+t].(string); ck == "Set" || ck == "TreeSet" {
			return true
		}
	}
	for _, pfx := range []string{
		"Set.of(", "Set.copyOf(", "Collections.emptySet(", "Collections.singleton(",
		"Collections.unmodifiableSet(", "EnumSet.", "new HashSet(", "new LinkedHashSet(", "new TreeSet(",
	} {
		if strings.HasPrefix(t, pfx) {
			return true
		}
	}
	return false
}

func splitArrayBaseAndDimsRound59(arrType string) (string, int) {
	dims := 0
	base := arrType
	for strings.HasSuffix(base, "[]") {
		dims++
		base = strings.TrimSuffix(base, "[]")
	}
	return base, dims
}

func isReferenceComponentAssignableRound59(srcBase, dstBase string, budget *evalBudget) bool {
	if srcBase == dstBase {
		return true
	}
	if isJavaPrimitiveCastTypeRound59(srcBase) || isJavaPrimitiveCastTypeRound59(dstBase) {
		return false
	}
	if dstBase == "Object" || dstBase == "def" {
		return true
	}
	if dstBase == "CharSequence" && srcBase == "String" {
		return true
	}
	if dstBase == "Number" {
		switch srcBase {
		case "Byte", "Short", "Integer", "Long", "Float", "Double", "BigDecimal", "BigInteger":
			return true
		}
	}
	if dstBase == "Collection" {
		switch srcBase {
		case "List", "ArrayList", "LinkedList", "Set", "HashSet", "LinkedHashSet", "TreeSet":
			return true
		}
	}
	if dstBase == "List" && (srcBase == "ArrayList" || srcBase == "LinkedList") {
		return true
	}
	if dstBase == "Set" && (srcBase == "HashSet" || srcBase == "LinkedHashSet" || srcBase == "TreeSet") {
		return true
	}
	if dstBase == "Map" && (srcBase == "HashMap" || srcBase == "LinkedHashMap" || srcBase == "TreeMap") {
		return true
	}
	if budget != nil && len(budget.userClasses) > 0 {
		if srcCls := budget.userClasses[srcBase]; srcCls != nil {
			return srcCls.isInstanceOf(dstBase)
		}
	}
	return false
}

func isJavaArrayTypeAssignableRound59(srcArrType, dstArrType string, budget *evalBudget) bool {
	if srcArrType == dstArrType {
		return true
	}
	srcBase, srcDims := splitArrayBaseAndDimsRound59(srcArrType)
	dstBase, dstDims := splitArrayBaseAndDimsRound59(dstArrType)
	if srcDims == 0 || dstDims == 0 {
		return false
	}
	if srcDims == dstDims {
		return isReferenceComponentAssignableRound59(srcBase, dstBase, budget)
	}
	// Higher-dimensional array (e.g. `int[][]` or `String[][]`) is assignable to `Object[]` when `srcDims > dstDims` and `dstBase == "Object"`.
	if srcDims > dstDims && (dstBase == "Object" || dstBase == "def") {
		return true
	}
	return false
}

func validateArrayCastRound59(castType string, innerExpr string, innerVal any, params map[string]any, budget *evalBudget) (any, error) {
	arr, ok := innerVal.([]any)
	if !ok || isSetValueRound59(innerVal, innerExpr, params, budget) {
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType),
		}
	}
	if srcArrType, isTagged := getTypedArraySliceRound59(budget, arr); isTagged {
		if isJavaArrayTypeAssignableRound59(srcArrType, castType, budget) {
			return arr, nil
		}
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("Cannot cast %s to %s", srcArrType, castType),
		}
	}
	// Untagged `[]any` in Painless is a `List` (`ArrayList`), NOT a Java array `T[]`.
	return nil, &painlessExceptionError{
		exType:  "ClassCastException",
		message: fmt.Sprintf("Cannot cast List to %s", castType),
	}
}

func evalExplicitCastRound59Painless(castType string, innerExpr string, innerVal any, params map[string]any) (any, error) {
	var budget *evalBudget
	if params != nil {
		budget = getOrInitEvalBudget(params)
	}
	if innerVal == nil {
		if isJavaPrimitiveCastTypeRound59(castType) {
			return nil, &painlessExceptionError{
				exType:  "NullPointerException",
				message: fmt.Sprintf("Cannot unbox null to %s", castType),
			}
		}
		return nil, nil
	}

	if castType == "Object" || castType == "def" {
		return innerVal, nil
	}

	if strings.HasSuffix(castType, "[]") {
		return validateArrayCastRound59(castType, innerExpr, innerVal, params, budget)
	}

	switch castType {
	case "String":
		s, ok := innerVal.(string)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to String", innerVal)}
		}
		return s, nil
	case "CharSequence":
		if s, ok := innerVal.(string); ok {
			return s, nil
		}
		if sb, ok := innerVal.(*painlessStringBuilder); ok && sb != nil {
			return sb, nil
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to CharSequence", innerVal)}
	case "List", "ArrayList", "LinkedList":
		s, ok := innerVal.([]any)
		if !ok || isSetValueRound59(innerVal, innerExpr, params, budget) {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType)}
		}
		if _, isArr := getTypedArraySliceRound59(budget, s); isArr {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast array to %s", castType)}
		}
		return s, nil
	case "Set", "HashSet", "LinkedHashSet", "TreeSet":
		s, ok := innerVal.([]any)
		if !ok || !isSetValueRound59(innerVal, innerExpr, params, budget) {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType)}
		}
		return s, nil
	case "Collection":
		s, ok := innerVal.([]any)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to Collection", innerVal)}
		}
		if _, isArr := getTypedArraySliceRound59(budget, s); isArr {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: "Cannot cast array to Collection"}
		}
		return s, nil
	case "Map", "HashMap", "LinkedHashMap", "TreeMap":
		m, ok := innerVal.(map[string]any)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType)}
		}
		if _, isStats := isSummaryStatisticsMapPainless(m); isStats {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast SummaryStatistics to %s", castType)}
		}
		return m, nil
	case "Number":
		if !isNumericValuePainless(innerVal) {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to Number", innerVal)}
		}
		return innerVal, nil
	case "BigDecimal":
		bd, ok := innerVal.(*painlessBigDecimal)
		if !ok || bd == nil {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to BigDecimal", innerVal)}
		}
		return bd, nil
	case "BigInteger":
		bi, ok := innerVal.(*painlessBigInteger)
		if !ok || bi == nil {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to BigInteger", innerVal)}
		}
		return bi, nil
	case "boolean":
		if b, ok := innerVal.(bool); ok {
			return b, nil
		}
		// Preserve Painless numeric-to-boolean cast `(boolean) 1 == true` (`eval_test.go:522`).
		if isNumericValuePainless(innerVal) {
			if f, ok := toFloat64(innerVal); ok {
				return f != 0 && !math.IsNaN(f), nil
			}
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to boolean", innerVal)}
	case "Boolean":
		b, ok := innerVal.(bool)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to Boolean", innerVal)}
		}
		return b, nil
	case "char":
		if s, isStr := innerVal.(string); isStr {
			if u, ok := parseSurrogateCharStringRound59(s); ok && !isDoubleQuotedStringLiteralRound59(innerExpr) {
				return formatJavaCharUnitRound59(u), nil
			}
			u16 := utf16.Encode([]rune(s))
			if len(u16) == 1 {
				return formatJavaCharUnitRound59(u16[0]), nil
			}
			return nil, &painlessExceptionError{exType: "ClassCastException", message: "Cannot cast multi-character or empty String to char"}
		}
		if !isNumericValuePainless(innerVal) {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to char", innerVal)}
		}
		v, _ := evalPrimitiveCastRound57Painless("char", innerVal)
		return v, nil
	case "Character":
		if s, isStr := innerVal.(string); isStr {
			if u, ok := parseSurrogateCharStringRound59(s); ok && (innerExpr == "" || isCharExprRound59(innerExpr, params)) {
				return formatJavaCharUnitRound59(u), nil
			}
			u16 := utf16.Encode([]rune(s))
			if len(u16) == 1 && (innerExpr == "" || isCharExprRound59(innerExpr, params)) {
				return formatJavaCharUnitRound59(u16[0]), nil
			}
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to Character", innerVal)}
	case "byte", "short", "int", "long", "float", "double",
		"Byte", "Short", "Integer", "Long", "Float", "Double":
		if s, isStr := innerVal.(string); isStr {
			if isJavaPrimitiveCastTypeRound59(castType) && isCharExprRound59(innerExpr, params) {
				if u, ok := parseSurrogateCharStringRound59(s); ok {
					v, _ := evalPrimitiveCastRound57Painless(castType, int64(u))
					return v, nil
				}
				u16 := utf16.Encode([]rune(s))
				if len(u16) == 1 {
					v, _ := evalPrimitiveCastRound57Painless(castType, int64(u16[0]))
					return v, nil
				}
			}
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast String to %s", castType)}
		}
		if !isNumericValuePainless(innerVal) {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType)}
		}
		v, ok := evalPrimitiveCastRound57Painless(castType, innerVal)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType)}
		}
		return v, nil
	}

	// Declared user-defined class cast `(TargetClass) expr`
	if budget != nil && len(budget.userClasses) > 0 {
		if _, exists := budget.userClasses[castType]; exists {
			uo, isUO := innerVal.(*painlessUserObject)
			if !isUO || uo == nil || uo.class == nil || !uo.class.isInstanceOf(castType) {
				return nil, &painlessExceptionError{
					exType:  "ClassCastException",
					message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType),
				}
			}
			return uo, nil
		}
	}

	return nil, &painlessExceptionError{
		exType:  "ClassCastException",
		message: fmt.Sprintf("Cannot cast %T to %s", innerVal, castType),
	}
}

func defaultZeroForJavaArrayElemTypeRound59(arrType string) any {
	base, dims := splitArrayBaseAndDimsRound59(arrType)
	if dims > 1 {
		return nil
	}
	return defaultZeroForJavaArrayTypePainless(base)
}

// ----------------------------------------------------------------------------
// F22: switch NullPointerException, Non-Coercive Case Matching & Block Scoping
// ----------------------------------------------------------------------------

func valuesEqualSwitchCaseRound59(switchVal any, switchExpr string, cVal any, caseExpr string, params map[string]any) bool {
	if valuesEqualRound58(switchVal, cVal) {
		return true
	}
	// Allow Java `char` <-> integral constant switch matching ONLY when one side is integral and the other is `char`.
	if isNumericValuePainless(switchVal) && !isFloatingPointPainlessValueRound59(switchVal) {
		if cs, ok := cVal.(string); ok && isCharExprRound59(caseExpr, params) {
			u16 := utf16.Encode([]rune(cs))
			if len(u16) == 1 {
				if iv, okI := toInt64Painless(switchVal); okI && iv == int64(u16[0]) {
					return true
				}
			}
		}
	}
	if ss, ok := switchVal.(string); ok && isCharExprRound59(switchExpr, params) {
		u16 := utf16.Encode([]rune(ss))
		if len(u16) == 1 && isNumericValuePainless(cVal) && !isFloatingPointPainlessValueRound59(cVal) {
			if iv, okI := toInt64Painless(cVal); okI && iv == int64(u16[0]) {
				return true
			}
		}
	}
	return false
}

func isFloatingPointPainlessValueRound59(v any) bool {
	switch v.(type) {
	case float64, float32, *painlessBigDecimal:
		return true
	}
	return false
}

func matchSwitchClauseIndexRound59(sourceMap map[string]any, switchVal any, switchExpr string, clauses []painlessSwitchClause, params map[string]any, depth int) (int, error) {
	matchIdx := -1
	defaultIdx := -1
	for idx, cl := range clauses {
		if cl.isDefault {
			if defaultIdx < 0 {
				defaultIdx = idx
			}
			continue
		}
		for _, ce := range cl.caseExprs {
			cVal, cErr := evalRHSExprDepth(sourceMap, ce, params, depth+1)
			if cErr != nil {
				return -1, cErr
			}
			if valuesEqualSwitchCaseRound59(switchVal, switchExpr, cVal, ce, params) {
				matchIdx = idx
				break
			}
		}
		if matchIdx >= 0 {
			break
		}
	}
	if matchIdx < 0 {
		matchIdx = defaultIdx
	}
	return matchIdx, nil
}

type switchScopeSnapshotRound59 struct {
	preKeys      map[string]bool
	preLocals    map[string]bool
	preOOS       map[string]bool
	savedMeta    map[string]any
	hadSavedMeta map[string]bool
}

func captureSwitchScopeRound59(params map[string]any) *switchScopeSnapshotRound59 {
	if params == nil {
		return nil
	}
	snap := &switchScopeSnapshotRound59{
		preKeys:      make(map[string]bool, len(params)),
		preLocals:    make(map[string]bool),
		preOOS:       make(map[string]bool),
		savedMeta:    make(map[string]any),
		hadSavedMeta: make(map[string]bool),
	}
	for k, v := range params {
		snap.preKeys[k] = true
		if strings.HasPrefix(k, "__var_type_") || strings.HasPrefix(k, "__user_var_class_") ||
			strings.HasPrefix(k, "__col_kind_") || strings.HasPrefix(k, "__temporal_kind_") ||
			strings.HasPrefix(k, "__alias_") || strings.HasPrefix(k, "__wb_") {
			snap.savedMeta[k] = v
			snap.hadSavedMeta[k] = true
		}
	}
	if sl, ok := params["__script_locals"].(map[string]bool); ok {
		for k, v := range sl {
			if v {
				snap.preLocals[k] = true
			}
		}
	}
	if oos, ok := params["__out_of_scope_vars"].(map[string]bool); ok {
		for k, v := range oos {
			if v {
				snap.preOOS[k] = true
			}
		}
	}
	return snap
}

func restoreSwitchScopeRound59(params map[string]any, snap *switchScopeSnapshotRound59) {
	if params == nil || snap == nil {
		return
	}
	ep, _ := params["__explicit_params_keys"].(map[string]bool)
	sl, _ := params["__script_locals"].(map[string]bool)
	oos, hasOOS := params["__out_of_scope_vars"].(map[string]bool)
	if !hasOOS || oos == nil {
		oos = make(map[string]bool)
		params["__out_of_scope_vars"] = oos
	}
	var cleanedVars []string
	for k := range params {
		if snap.preKeys[k] {
			continue
		}
		if k == "_return_val" || k == "_last_expr_val" || k == "__switch_yield_val" ||
			k == "__out_of_scope_vars" || k == "__eval_budget" || strings.HasPrefix(k, "_ctx_") {
			continue
		}
		if ep != nil && ep[k] {
			continue
		}
		if !strings.HasPrefix(k, "__") {
			cleanedVars = append(cleanedVars, k)
		}
		delete(params, k)
	}
	// Also clean up variables that previously went out of scope and were re-declared inside switch.
	for k := range snap.preOOS {
		if _, existsNow := params[k]; existsNow {
			delete(params, k)
			cleanedVars = append(cleanedVars, k)
		}
		oos[k] = true
	}
	for _, vName := range cleanedVars {
		if sl != nil && !snap.preLocals[vName] {
			delete(sl, vName)
		}
		if !snap.preKeys[vName] {
			oos[vName] = true
		}
		for _, metaPfx := range []string{"__var_type_", "__user_var_class_", "__col_kind_", "__temporal_kind_", "__alias_", "__wb_"} {
			mk := metaPfx + vName
			if snap.hadSavedMeta[mk] {
				params[mk] = snap.savedMeta[mk]
			} else {
				delete(params, mk)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// F23: User-Defined Functions Overloading, Validation & Static Scope Isolation
// ----------------------------------------------------------------------------

func parseParamListTypesAndNamesRound59(paramStr string) ([]string, []string) {
	paramStr = strings.TrimSpace(paramStr)
	if paramStr == "" {
		return nil, nil
	}
	parts := splitTopLevelCommaPainless(paramStr)
	paramTypes := make([]string, 0, len(parts))
	paramNames := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		nameStart := len(p)
		for nameStart > 0 && isIdentByte(p[nameStart-1]) {
			nameStart--
		}
		pName := strings.TrimSpace(p[nameStart:])
		pTypeRaw := strings.TrimSpace(p[:nameStart])
		if pTypeRaw == "" {
			pTypeRaw = "def"
		}
		paramTypes = append(paramTypes, normalizeDeclaredSignatureTypeRound59(pTypeRaw))
		paramNames = append(paramNames, pName)
	}
	return paramTypes, paramNames
}

func normalizeDeclaredSignatureTypeRound59(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "def"
	}
	dims := 0
	for strings.HasSuffix(s, "]") {
		openBr := strings.LastIndexByte(s, '[')
		if openBr <= 0 {
			break
		}
		dims++
		s = strings.TrimSpace(s[:openBr])
	}
	if strings.HasSuffix(s, ">") {
		if openAng := strings.IndexByte(s, '<'); openAng > 0 {
			s = strings.TrimSpace(s[:openAng])
		}
	}
	for _, pfx := range []string{"java.time.temporal.", "java.time.", "java.math.", "java.lang.", "java.util.regex.", "java.util.function.", "java.util.", "java.net."} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimPrefix(s, pfx)
			break
		}
	}
	if s == "def" && dims > 0 {
		s = "Object"
	}
	return s + strings.Repeat("[]", dims)
}

func registerUserFuncRound59(budget *evalBudget, fn *painlessUserFunc) error {
	if budget == nil || fn == nil {
		return nil
	}
	arity := len(fn.paramNames)
	if budget.userFuncOverloads == nil {
		budget.userFuncOverloads = make(map[string]map[int]*painlessUserFunc)
	}
	byArity := budget.userFuncOverloads[fn.name]
	if byArity == nil {
		byArity = make(map[int]*painlessUserFunc)
		budget.userFuncOverloads[fn.name] = byArity
	}
	if _, dup := byArity[arity]; dup {
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Duplicate function [%s/%d] definition", fn.name, arity),
		}
	}
	byArity[arity] = fn
	if budget.userFuncs == nil {
		budget.userFuncs = make(map[string]*painlessUserFunc)
	}
	budget.userFuncs[fn.name] = fn
	return nil
}

func lookupUserFuncRound59(budget *evalBudget, name string, arity int) *painlessUserFunc {
	if budget == nil {
		return nil
	}
	if len(budget.userFuncOverloads) > 0 {
		if byArity := budget.userFuncOverloads[name]; byArity != nil {
			return byArity[arity]
		}
	}
	if len(budget.userFuncs) > 0 {
		if fn := budget.userFuncs[name]; fn != nil && len(fn.paramNames) == arity {
			return fn
		}
	}
	return nil
}

func validateAndCoerceSignatureValueRound59(sigType string, val any, rawExpr string, params map[string]any, budget *evalBudget) (any, error) {
	norm := normalizeDeclaredSignatureTypeRound59(sigType)
	if norm == "" || norm == "def" || norm == "Object" {
		return val, nil
	}
	if val == nil {
		if isJavaPrimitiveCastTypeRound59(norm) {
			return nil, &painlessExceptionError{
				exType:  "NullPointerException",
				message: fmt.Sprintf("Cannot pass/return null for primitive type %s", norm),
			}
		}
		return nil, nil
	}
	// Reject floating-point values (e.g. `3.5`) passed to integral parameter/return types without an explicit cast,
	// while still permitting integer-valued float64 from JSON `_source` (when rawExpr is not an explicit float literal).
	switch norm {
	case "byte", "short", "int", "long", "Byte", "Short", "Integer", "Long":
		if fv, isF := val.(float64); isF {
			if math.IsNaN(fv) || math.IsInf(fv, 0) || fv != math.Trunc(fv) || isExplicitFloatLiteralRound59(rawExpr) {
				return nil, &painlessExceptionError{
					exType:  "ClassCastException",
					message: fmt.Sprintf("Cannot convert floating-point value %v to %s", fv, norm),
				}
			}
		}
		if _, isBD := val.(*painlessBigDecimal); isBD {
			return nil, &painlessExceptionError{
				exType:  "ClassCastException",
				message: fmt.Sprintf("Cannot convert BigDecimal to %s", norm),
			}
		}
	case "boolean", "Boolean":
		b, ok := val.(bool)
		if !ok {
			return nil, &painlessExceptionError{
				exType:  "ClassCastException",
				message: fmt.Sprintf("Cannot convert %T to %s", val, norm),
			}
		}
		return b, nil
	}

	// Built-in castable or user-class / array types
	if _, isCastType := normalizeCastTypeCandidateRound59(norm, budget); isCastType {
		return evalExplicitCastRound59Painless(norm, rawExpr, val, params)
	}
	// Fallback to instanceof check for other JDK types (e.g. Pattern, Matcher, Optional, LocalDate, UUID, etc.)
	if !evalInstanceOfPainless(val, norm) {
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("Cannot convert %T to %s", val, norm),
		}
	}
	return val, nil
}

func isExplicitFloatLiteralRound59(expr string) bool {
	t := strings.TrimSpace(expr)
	if t == "" {
		return false
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "+"), "-")
	if len(t) == 0 || ((t[0] < '0' || t[0] > '9') && t[0] != '.') {
		return false
	}
	return strings.ContainsAny(t, ".eEfFdD") && !strings.HasPrefix(t, "0x") && !strings.HasPrefix(t, "0X")
}

func evalUserFuncCallRound59(fnName, argStr string, args []string, sourceMap, params map[string]any, budget *evalBudget, depth int) (any, bool, error) {
	if budget == nil {
		return nil, false, nil
	}
	hasOverloads := len(budget.userFuncOverloads) > 0 && budget.userFuncOverloads[fnName] != nil
	_, hasLegacy := budget.userFuncs[fnName]
	if !hasOverloads && !hasLegacy {
		return nil, false, nil
	}

	arity := 0
	if strings.TrimSpace(argStr) != "" {
		arity = len(args)
	}
	fn := lookupUserFuncRound59(budget, fnName, arity)
	if fn == nil {
		return nil, true, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("No overload of function [%s] accepts %d argument(s)", fnName, arity),
		}
	}

	if err := budget.step(); err != nil {
		return nil, true, err
	}

	var argVals []any
	if arity > 0 {
		argVals = make([]any, arity)
		for i := 0; i < arity; i++ {
			av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if i < len(fn.paramTypes) {
				av, err = validateAndCoerceSignatureValueRound59(fn.paramTypes[i], av, args[i], params, budget)
				if err != nil {
					return nil, true, err
				}
			}
			argVals[i] = av
		}
	}

	// Build isolated static function scope: preserve explicit `params`, `_source`, `doc`, `_ctx_*`, and `__eval_budget`,
	// while excluding caller local variables (`__script_locals`, `__loop_declared`, `__method_params`, `this`).
	fnParams := make(map[string]any, len(fn.paramNames)+12)
	preCallEp := make(map[string]bool)
	fnEp := make(map[string]bool)
	if params != nil {
		if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
			for k, v := range ep {
				if v {
					preCallEp[k] = true
					fnEp[k] = true
					if pv, exists := params[k]; exists {
						fnParams[k] = pv
					}
				}
			}
		}
		for _, ctxKey := range []string{
			"_source", "__raw_source", "_ingest", "doc",
			"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_version_mutated",
			"_ctx_op", "_ctx_now", "_now", "__readonly_ctx_meta",
		} {
			if cv, exists := params[ctxKey]; exists {
				fnParams[ctxKey] = cv
			}
		}
	}
	fnLocals := make(map[string]bool, len(fn.paramNames))
	reassignedVars := make(map[string]bool)
	fnParams["__explicit_params_keys"] = fnEp
	fnParams["__script_locals"] = fnLocals
	fnParams["__reassigned_vars"] = reassignedVars
	fnParams["__eval_budget"] = budget
	fnParams["__in_user_func"] = true

	paramNamesSet := make(map[string]bool, len(fn.paramNames))
	callerVarBindings := make(map[string]string, len(fn.paramNames))
	for i, pName := range fn.paramNames {
		paramNamesSet[pName] = true
		fnParams[pName] = argVals[i]
		fnLocals[pName] = true
		if i < len(fn.paramTypes) {
			pNorm := normalizeDeclaredSignatureTypeRound59(fn.paramTypes[i])
			if isJavaPrimitiveCastTypeRound59(pNorm) {
				fnParams["__var_type_"+pName] = pNorm
			} else if budget.userClasses != nil && budget.userClasses[pNorm] != nil {
				fnParams["__user_var_class_"+pName] = pNorm
			}
		}
		if i < arity && params != nil {
			argExpr := strings.TrimSpace(expandDynamicBrackets(strings.TrimSpace(args[i]), sourceMap, params, depth+1))
			matchedAlias := false
			for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
				if strings.HasPrefix(argExpr, pfx) {
					tail := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(argExpr, pfx)), "?")
					if reSimpleFieldPath.MatchString(tail) && !strings.HasSuffix(tail, ".size()") && !strings.HasSuffix(tail, ".length()") {
						switch argVals[i].(type) {
						case []any, map[string]any:
							fnParams["__alias_"+pName] = tail
							matchedAlias = true
						}
					}
					break
				}
			}
			if !matchedAlias && reSimpleFieldPath.MatchString(argExpr) && !strings.Contains(argExpr, ".") {
				callerVar := decodeBracketSeg(argExpr)
				if _, exists := params[callerVar]; exists {
					if _, isSlice := argVals[i].([]any); isSlice {
						callerVarBindings[pName] = callerVar
					}
					if aliasPath, ok := params["__alias_"+callerVar].(string); ok && aliasPath != "" {
						fnParams["__alias_"+pName] = aliasPath
					}
					if ck, ok := params["__col_kind_"+callerVar].(string); ok && ck != "" {
						fnParams["__col_kind_"+pName] = ck
					}
				}
			} else if !matchedAlias && reSimpleFieldPath.MatchString(argExpr) && !strings.HasSuffix(argExpr, ".size()") && !strings.HasSuffix(argExpr, ".length()") {
				rhsParts := normalizeLocalLHSPath(strings.Split(argExpr, "."), params)
				if len(rhsParts) > 0 {
					rootVar := decodeBracketSeg(rhsParts[0])
					if baseAlias, ok := params["__alias_"+rootVar].(string); ok && baseAlias != "" {
						switch argVals[i].(type) {
						case []any, map[string]any:
							fnParams["__alias_"+pName] = strings.Join(append([]string{baseAlias}, rhsParts[1:]...), ".")
						}
					}
				}
			}
		}
	}

	fnCtxOp := ""
	err := execBlock(sourceMap, fn.body, fnParams, &fnCtxOp, budget)
	for _, pName := range fn.paramNames {
		if !reassignedVars[pName] {
			syncLocalVarAlias(sourceMap, fnParams, pName)
			if callerVar, bound := callerVarBindings[pName]; bound && params != nil {
				params[callerVar] = fnParams[pName]
				syncLocalVarAlias(sourceMap, params, callerVar)
			}
		}
	}
	if params != nil {
		if ep, ok := fnParams["__explicit_params_keys"].(map[string]bool); ok {
			callerEp, _ := params["__explicit_params_keys"].(map[string]bool)
			for k := range ep {
				if paramNamesSet[k] {
					continue
				}
				if v, exists := fnParams[k]; exists {
					params[k] = v
					if callerEp != nil {
						callerEp[k] = true
					}
				}
			}
			for k := range preCallEp {
				if !ep[k] && !paramNamesSet[k] {
					delete(params, k)
					unmarkExplicitParamsKey(params, k)
				}
			}
		}
		for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_version_mutated", "_ctx_op"} {
			if v, exists := fnParams[metaKey]; exists {
				params[metaKey] = v
			}
		}
	}
	if err != nil && !errors.Is(err, errPainlessReturn) {
		return nil, true, err
	}

	normRet := normalizeDeclaredSignatureTypeRound59(fn.returnType)
	if normRet == "void" {
		if fnParams["__has_value_return"] == true {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("Void function [%s] cannot return a value", fn.name),
			}
		}
		return nil, true, nil
	}

	var rawRet any
	if retVal, hasRet := fnParams["_return_val"]; hasRet {
		if fnParams["__has_empty_return"] == true {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("Non-void function [%s] must return a value", fn.name),
			}
		}
		rawRet = retVal
	} else {
		rawRet = fnParams["_last_expr_val"]
	}
	coercedRet, retErr := validateAndCoerceSignatureValueRound59(normRet, rawRet, "", fnParams, budget)
	if retErr != nil {
		return nil, true, retErr
	}
	return coercedRet, true, nil
}

// ----------------------------------------------------------------------------
// F24: java.util.Arrays Null Receiver NPE & Exact JDK Range Checks
// ----------------------------------------------------------------------------

func requireNonNullArrayArgRound59(val any, method string) ([]any, error) {
	if val == nil || val == painlessEmptyOptional {
		return nil, &painlessExceptionError{
			exType:  "NullPointerException",
			message: fmt.Sprintf("Arrays.%s: array is null", method),
		}
	}
	arr, ok := val.([]any)
	if !ok {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Arrays.%s: expected array, got %T", method, val),
		}
	}
	return arr, nil
}

func checkArraysRangeBoundsRound59(arrayLen, fromIndex, toIndex int) error {
	if fromIndex > toIndex {
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("fromIndex(%d) > toIndex(%d)", fromIndex, toIndex),
		}
	}
	if fromIndex < 0 {
		return &painlessExceptionError{
			exType:  "ArrayIndexOutOfBoundsException",
			message: fmt.Sprintf("Array index out of range: %d", fromIndex),
		}
	}
	if toIndex > arrayLen {
		return &painlessExceptionError{
			exType:  "ArrayIndexOutOfBoundsException",
			message: fmt.Sprintf("Array index out of range: %d", toIndex),
		}
	}
	return nil
}

func evalArraysCopyOfRound59(arrVal any, newLen int, budget *evalBudget) ([]any, error) {
	arr, err := requireNonNullArrayArgRound59(arrVal, "copyOf")
	if err != nil {
		return nil, err
	}
	if newLen < 0 {
		return nil, &painlessExceptionError{
			exType:  "NegativeArraySizeException",
			message: strconv.Itoa(newLen),
		}
	}
	if newLen > MaxPainlessSliceItems {
		return nil, fmt.Errorf("painless array size %d exceeds maximum (%d)", newLen, MaxPainlessSliceItems)
	}
	out := make([]any, newLen, max(1, newLen))
	copy(out, arr)
	srcArrType, isTagged := getTypedArraySliceRound59(budget, arr)
	if newLen > len(arr) && isTagged {
		padVal := defaultZeroForJavaArrayElemTypeRound59(srcArrType)
		for i := len(arr); i < newLen; i++ {
			out[i] = padVal
		}
	}
	if isTagged {
		out = markTypedArraySliceRound59(budget, out, srcArrType)
	} else {
		out = markTypedArraySliceRound59(budget, out, "Object[]")
	}
	return out, nil
}

func evalArraysCopyOfRangeRound59(arrVal any, fromIdx, toIdx int, budget *evalBudget) ([]any, error) {
	arr, err := requireNonNullArrayArgRound59(arrVal, "copyOfRange")
	if err != nil {
		return nil, err
	}
	if fromIdx > toIdx {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("%d > %d", fromIdx, toIdx),
		}
	}
	if fromIdx < 0 || fromIdx > len(arr) {
		return nil, &painlessExceptionError{
			exType:  "ArrayIndexOutOfBoundsException",
			message: strconv.Itoa(fromIdx),
		}
	}
	newLen := toIdx - fromIdx
	if newLen > MaxPainlessSliceItems {
		return nil, fmt.Errorf("painless array size %d exceeds maximum (%d)", newLen, MaxPainlessSliceItems)
	}
	out := make([]any, newLen, max(1, newLen))
	copied := 0
	if fromIdx < len(arr) {
		copied = copy(out, arr[fromIdx:])
	}
	srcArrType, isTagged := getTypedArraySliceRound59(budget, arr)
	if copied < newLen && isTagged {
		padVal := defaultZeroForJavaArrayElemTypeRound59(srcArrType)
		for i := copied; i < newLen; i++ {
			out[i] = padVal
		}
	}
	if isTagged {
		out = markTypedArraySliceRound59(budget, out, srcArrType)
	} else {
		out = markTypedArraySliceRound59(budget, out, "Object[]")
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// F25: List / Collection / Map Method Bounds & Null Argument NPE
// ----------------------------------------------------------------------------

func parseStrictListIndexRound59(idxVal any, size int, allowEnd bool) (int, error) {
	if idxVal == nil || idxVal == painlessEmptyOptional {
		return 0, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "Cannot unbox null index",
		}
	}
	iv, ok := toInt64Painless(idxVal)
	if !ok {
		return 0, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("List index must be an integer, got %T", idxVal),
		}
	}
	upper := int64(size)
	if allowEnd {
		if iv < 0 || iv > upper {
			return 0, &painlessExceptionError{
				exType:  "IndexOutOfBoundsException",
				message: fmt.Sprintf("Index: %d, Size: %d", iv, size),
			}
		}
	} else {
		if iv < 0 || iv >= upper {
			return 0, &painlessExceptionError{
				exType:  "IndexOutOfBoundsException",
				message: fmt.Sprintf("Index: %d, Size: %d", iv, size),
			}
		}
	}
	return int(iv), nil
}

func requireNonNullCollectionArgRound59(val any, method string) ([]any, error) {
	if val == nil || val == painlessEmptyOptional {
		return nil, &painlessExceptionError{
			exType:  "NullPointerException",
			message: fmt.Sprintf("%s: collection is null", method),
		}
	}
	items, ok := val.([]any)
	if !ok {
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("%s: expected Collection, got %T", method, val),
		}
	}
	return items, nil
}

func requireNonNullMapArgRound59(val any, method string) (map[string]any, error) {
	if val == nil || val == painlessEmptyOptional {
		return nil, &painlessExceptionError{
			exType:  "NullPointerException",
			message: fmt.Sprintf("%s: map is null", method),
		}
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("%s: expected Map, got %T", method, val),
		}
	}
	return m, nil
}

func isJavaIntRemoveOverloadRound59(argVal any, argExpr string, params map[string]any) bool {
	if argVal == nil {
		return false
	}
	t := trimBalancedParens(argExpr)
	// Explicit `(Object)` or boxed `Long` / `long` calls `remove(Object)` rather than `remove(int)`.
	if strings.HasPrefix(t, "(Object)") || strings.HasPrefix(t, "(Number)") || strings.HasPrefix(t, "(Long)") || strings.HasPrefix(t, "(long)") {
		return false
	}
	if strings.HasPrefix(t, "Integer.valueOf(") || strings.HasPrefix(t, "Long.valueOf(") {
		return false
	}
	if isLongExprPainless(t, argVal, params) {
		return false
	}
	switch v := argVal.(type) {
	case int, int64, int32, int16, int8:
		return true
	case float64:
		if isExplicitFloatLiteralRound59(t) || math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) {
			return false
		}
		return true
	case json.Number:
		_, err := v.Int64()
		return err == nil
	}
	return false
}

func isTargetSetAtPathRound59(root map[string]any, path []string, target []any, params map[string]any, budget *evalBudget) bool {
	if isSetSliceRound59(budget, target) {
		return true
	}
	if len(path) == 1 {
		seg := decodeBracketSeg(path[0])
		if root != nil {
			if ck, _ := root["__col_kind_"+seg].(string); ck == "Set" || ck == "TreeSet" {
				return true
			}
		}
		if params != nil {
			if ck, _ := params["__col_kind_"+seg].(string); ck == "Set" || ck == "TreeSet" {
				return true
			}
		}
	}
	return false
}

func removeKeyOrIndexAtPathRound59(root map[string]any, parentPath []string, keyOrIdx any, rawArgExpr string, params map[string]any, budget *evalBudget) (any, error) {
	if len(parentPath) == 0 {
		return removeKeyOrIndexAtPath(root, parentPath, keyOrIdx), nil
	}
	switch target := resolveParamPath(root, parentPath).(type) {
	case map[string]any:
		return removeKeyOrIndexAtPath(root, parentPath, keyOrIdx), nil
	case []any:
		removeAt := func(idx int) any {
			old := target[idx]
			next := make([]any, 0, max(1, len(target)-1))
			next = append(next, target[:idx]...)
			next = append(next, target[idx+1:]...)
			next = propagateSliceTagsRound59(budget, target, next)
			setValueAtPath(root, parentPath, next)
			return old
		}
		isSet := isTargetSetAtPathRound59(root, parentPath, target, params, budget)
		if !isSet && isJavaIntRemoveOverloadRound59(keyOrIdx, rawArgExpr, params) {
			idx, err := parseStrictListIndexRound59(keyOrIdx, len(target), false)
			if err != nil {
				return nil, err
			}
			return removeAt(idx), nil
		}
		for idx, elem := range target {
			if painlessJavaObjectEquals(elem, keyOrIdx) {
				_ = removeAt(idx)
				return true, nil
			}
		}
		return false, nil
	}
	return nil, nil
}

func setSliceElementAtPathRound59(root map[string]any, arrPath []string, idxVal any, newVal any, budget *evalBudget) (any, error) {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return nil, nil
	}
	idx, err := parseStrictListIndexRound59(idxVal, len(existing), false)
	if err != nil {
		return nil, err
	}
	prev := existing[idx]
	next := make([]any, len(existing), max(1, len(existing)))
	copy(next, existing)
	next[idx] = newVal
	next = propagateSliceTagsRound59(budget, existing, next)
	setValueAtPath(root, arrPath, next)
	return prev, nil
}

func insertIntoSliceAtPathRound59(root map[string]any, path []string, idxVal any, val any, budget *evalBudget) error {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	idx, err := parseStrictListIndexRound59(idxVal, len(existing), true)
	if err != nil {
		return err
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	next := make([]any, 0, len(existing)+1)
	next = append(next, existing[:idx]...)
	next = append(next, val)
	next = append(next, existing[idx:]...)
	next = propagateSliceTagsRound59(budget, existing, next)
	setValueAtPath(root, path, next)
	return nil
}

func insertAllIntoSliceAtPathRound59(root map[string]any, path []string, idxVal any, rawCol any, budget *evalBudget) (bool, error) {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	// JDK ArrayList.addAll(index, c): rangeCheckForAdd(index) runs FIRST, then c.toArray() throws NPE if c == null.
	idx, err := parseStrictListIndexRound59(idxVal, len(existing), true)
	if err != nil {
		return false, err
	}
	items, err := requireNonNullCollectionArgRound59(rawCol, "addAll")
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	if len(existing)+len(items) > MaxPainlessSliceItems {
		return false, fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	if budget != nil {
		for range items {
			if err := budget.step(); err != nil {
				return false, err
			}
		}
	}
	itemsCopy := make([]any, len(items))
	copy(itemsCopy, items)
	next := make([]any, 0, len(existing)+len(itemsCopy))
	next = append(next, existing[:idx]...)
	next = append(next, itemsCopy...)
	next = append(next, existing[idx:]...)
	next = propagateSliceTagsRound59(budget, existing, next)
	setValueAtPath(root, path, next)
	return true, nil
}

func mutateSliceRemoveOrRetainAtPathRound59(root map[string]any, path []string, argVal any, isRetain bool, budget *evalBudget) (bool, error) {
	mName := "removeAll"
	if isRetain {
		mName = "retainAll"
	}
	needles, err := requireNonNullCollectionArgRound59(argVal, mName)
	if err != nil {
		return false, err
	}
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		return false, nil
	}
	out := make([]any, 0, max(1, len(existing)))
	for _, item := range existing {
		inNeedles := false
		for _, needle := range needles {
			if painlessJavaObjectEquals(item, needle) {
				inNeedles = true
				break
			}
		}
		if (isRetain && inNeedles) || (!isRetain && !inNeedles) {
			out = append(out, item)
		}
	}
	changed := len(out) != len(existing)
	if changed {
		out = propagateSliceTagsRound59(budget, existing, out)
		setValueAtPath(root, path, out)
	}
	return changed, nil
}

// ----------------------------------------------------------------------------
// F26: Lazy Stream Pipeline, Unbounded IntStream/LongStream.range & flatMap
// ----------------------------------------------------------------------------

type painlessRangeStream struct {
	kind      string // "IntStream" or "LongStream"
	cur       int64
	end       int64
	inclusive bool
	done      bool
}

func newPainlessRangeStreamRound59(fnName string, start, end int64) *painlessRangeStream {
	kind := "IntStream"
	if strings.HasPrefix(fnName, "LongStream.") {
		kind = "LongStream"
	}
	inclusive := strings.HasSuffix(fnName, "Closed")
	done := false
	if inclusive {
		if start > end {
			done = true
		}
	} else {
		if start >= end {
			done = true
		}
	}
	return &painlessRangeStream{
		kind:      kind,
		cur:       start,
		end:       end,
		inclusive: inclusive,
		done:      done,
	}
}

type streamIterRound59 func() (any, bool, error)

func sliceStreamIterRound59(items []any, budget *evalBudget) streamIterRound59 {
	cp := make([]any, len(items))
	copy(cp, items)
	idx := 0
	return func() (any, bool, error) {
		if idx >= len(cp) {
			return nil, false, nil
		}
		if budget != nil && (idx&63) == 0 {
			if err := budget.step(); err != nil {
				return nil, false, err
			}
		}
		v := cp[idx]
		idx++
		return v, true, nil
	}
}

func rangeStreamIterRound59(rs *painlessRangeStream, budget *evalBudget) streamIterRound59 {
	if rs == nil || rs.done {
		return func() (any, bool, error) { return nil, false, nil }
	}
	cur := rs.cur
	end := rs.end
	inclusive := rs.inclusive
	done := rs.done
	var pulled uint64
	return func() (any, bool, error) {
		if done {
			return nil, false, nil
		}
		if budget != nil && (pulled&63) == 0 {
			if err := budget.step(); err != nil {
				return nil, false, err
			}
		}
		pulled++
		val := cur
		if inclusive {
			if cur == end {
				done = true
			} else {
				cur++
			}
		} else {
			cur++
			if cur >= end {
				done = true
			}
		}
		return val, true, nil
	}
}

func concatStreamValueToIterRound59(v1, v2 any, budget *evalBudget) streamIterRound59 {
	it1, _ := streamSourceToIterRound59(v1, budget)
	it2, _ := streamSourceToIterRound59(v2, budget)
	firstDone := false
	return func() (any, bool, error) {
		if !firstDone {
			item, ok, err := it1()
			if err != nil || ok {
				return item, ok, err
			}
			firstDone = true
		}
		return it2()
	}
}

type painlessConcatStream struct {
	kind  string
	left  any
	right any
}

func streamSourceToIterRound59(src any, budget *evalBudget) (streamIterRound59, string) {
	switch tv := src.(type) {
	case *painlessRangeStream:
		return rangeStreamIterRound59(tv, budget), tv.kind
	case *painlessConcatStream:
		return concatStreamValueToIterRound59(tv.left, tv.right, budget), tv.kind
	case []any:
		return sliceStreamIterRound59(tv, budget), "Stream"
	default:
		return sliceStreamIterRound59(nil, budget), "Stream"
	}
}

func drainStreamIterBoundedRound59(iter streamIterRound59, maxItems int) ([]any, error) {
	out := make([]any, 0)
	for {
		it, ok, err := iter()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if maxItems > 0 && len(out) >= maxItems {
			return nil, fmt.Errorf("painless stream materialization exceeded maximum size (%d)", maxItems)
		}
		out = append(out, it)
	}
	return out, nil
}

func wrapFlatMapResultIterRound59(mv any, coerceElem func(any) any, budget *evalBudget) (streamIterRound59, error) {
	if mv == nil {
		return func() (any, bool, error) { return nil, false, nil }, nil
	}
	switch tv := mv.(type) {
	case *painlessRangeStream:
		base := rangeStreamIterRound59(tv, budget)
		return func() (any, bool, error) {
			v, ok, err := base()
			if !ok || err != nil {
				return nil, ok, err
			}
			return coerceElem(v), true, nil
		}, nil
	case *painlessConcatStream:
		base := concatStreamValueToIterRound59(tv.left, tv.right, budget)
		return func() (any, bool, error) {
			v, ok, err := base()
			if !ok || err != nil {
				return nil, ok, err
			}
			return coerceElem(v), true, nil
		}, nil
	case []any:
		base := sliceStreamIterRound59(tv, budget)
		return func() (any, bool, error) {
			v, ok, err := base()
			if !ok || err != nil {
				return nil, ok, err
			}
			return coerceElem(v), true, nil
		}, nil
	default:
		return nil, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("flatMap mapper must return a Stream, got %T", mv),
		}
	}
}

func applyLazyStreamIntermediateRound59(
	prevIter streamIterRound59,
	step painlessStreamStep,
	streamKind *string,
	sourceMap, params map[string]any,
	budget *evalBudget,
	depth int,
) (streamIterRound59, bool, error) {
	switch step.name {
	case "stream":
		return prevIter, true, nil
	case "boxed":
		*streamKind = "Stream"
		return prevIter, true, nil
	case "asLongStream":
		*streamKind = "LongStream"
		return prevIter, true, nil
	case "asDoubleStream":
		*streamKind = "DoubleStream"
		upstream := prevIter
		return func() (any, bool, error) {
			it, ok, err := upstream()
			if !ok || err != nil {
				return nil, ok, err
			}
			if f, fOk := toFloat64WithRawPainless(it); fOk {
				return f, true, nil
			}
			return it, true, nil
		}, true, nil
	case "filter":
		upstream := prevIter
		predArg := step.args
		predSteps := 0
		return func() (any, bool, error) {
			for {
				it, ok, err := upstream()
				if !ok || err != nil {
					return nil, ok, err
				}
				if budget != nil && (predSteps&63) == 0 {
					if err := budget.step(); err != nil {
						return nil, false, err
					}
				}
				predSteps++
				matched, mErr := evalPredicateArgOnItemPainless(predArg, it, sourceMap, params, depth+1)
				if mErr != nil {
					return nil, false, mErr
				}
				if matched {
					return it, true, nil
				}
			}
		}, true, nil
	case "takeWhile":
		upstream := prevIter
		predArg := step.args
		stopped := false
		predSteps := 0
		return func() (any, bool, error) {
			if stopped {
				return nil, false, nil
			}
			it, ok, err := upstream()
			if !ok || err != nil {
				stopped = true
				return nil, ok, err
			}
			if budget != nil && (predSteps&63) == 0 {
				if err := budget.step(); err != nil {
					return nil, false, err
				}
			}
			predSteps++
			matched, mErr := evalPredicateArgOnItemPainless(predArg, it, sourceMap, params, depth+1)
			if mErr != nil {
				stopped = true
				return nil, false, mErr
			}
			if !matched {
				stopped = true
				return nil, false, nil
			}
			return it, true, nil
		}, true, nil
	case "dropWhile":
		upstream := prevIter
		predArg := step.args
		dropping := true
		predSteps := 0
		return func() (any, bool, error) {
			for {
				it, ok, err := upstream()
				if !ok || err != nil {
					return nil, ok, err
				}
				if !dropping {
					return it, true, nil
				}
				if budget != nil && (predSteps&63) == 0 {
					if err := budget.step(); err != nil {
						return nil, false, err
					}
				}
				predSteps++
				matched, mErr := evalPredicateArgOnItemPainless(predArg, it, sourceMap, params, depth+1)
				if mErr != nil {
					return nil, false, mErr
				}
				if !matched {
					dropping = false
					return it, true, nil
				}
			}
		}, true, nil
	case "map", "mapToObj", "mapToInt", "mapToLong", "mapToDouble":
		switch step.name {
		case "map", "mapToObj":
			*streamKind = "Stream"
		case "mapToInt":
			*streamKind = "IntStream"
		case "mapToLong":
			*streamKind = "LongStream"
		case "mapToDouble":
			*streamKind = "DoubleStream"
		}
		normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
		arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
		if arrowIdx <= 0 {
			return prevIter, true, nil
		}
		pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
		if len(pNames) == 0 {
			return prevIter, true, nil
		}
		pName := pNames[0]
		body := normArg[arrowIdx+2:]
		stepName := step.name
		upstream := prevIter
		return func() (any, bool, error) {
			it, ok, err := upstream()
			if !ok || err != nil {
				return nil, ok, err
			}
			prev, hadPrev := params[pName]
			params[pName] = it
			mv, lErr := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			if lErr != nil {
				return nil, false, lErr
			}
			switch stepName {
			case "mapToInt", "mapToLong":
				if f, okF := toFloat64(mv); okF {
					mv = int64(f)
				}
			case "mapToDouble":
				if f, okF := toFloat64WithRawPainless(mv); okF {
					mv = f
				}
			}
			return mv, true, nil
		}, true, nil
	case "flatMap", "flatMapToInt", "flatMapToLong", "flatMapToDouble":
		switch step.name {
		case "flatMap":
			*streamKind = "Stream"
		case "flatMapToInt":
			*streamKind = "IntStream"
		case "flatMapToLong":
			*streamKind = "LongStream"
		case "flatMapToDouble":
			*streamKind = "DoubleStream"
		}
		normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
		arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
		if arrowIdx <= 0 {
			return prevIter, true, nil
		}
		pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
		if len(pNames) == 0 {
			return prevIter, true, nil
		}
		pName := pNames[0]
		body := strings.TrimSpace(normArg[arrowIdx+2:])
		stepName := step.name
		coerceElem := func(el any) any {
			switch stepName {
			case "flatMapToInt", "flatMapToLong":
				if f, okF := toFloat64(el); okF {
					return int64(f)
				}
			case "flatMapToDouble":
				if f, okF := toFloat64WithRawPainless(el); okF {
					return f
				}
			}
			return el
		}
		upstream := prevIter
		var curSubIter streamIterRound59
		return func() (any, bool, error) {
			for {
				if curSubIter != nil {
					sv, sOk, sErr := curSubIter()
					if sErr != nil {
						return nil, false, sErr
					}
					if sOk {
						return sv, true, nil
					}
					curSubIter = nil
				}
				it, ok, err := upstream()
				if !ok || err != nil {
					return nil, ok, err
				}
				prev, hadPrev := params[pName]
				params[pName] = it
				mv, lErr := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
				if hadPrev {
					params[pName] = prev
				} else {
					delete(params, pName)
				}
				if lErr != nil {
					return nil, false, lErr
				}
				subIt, wErr := wrapFlatMapResultIterRound59(mv, coerceElem, budget)
				if wErr != nil {
					return nil, false, wErr
				}
				curSubIter = subIt
			}
		}, true, nil
	case "peek":
		normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
		arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
		if arrowIdx <= 0 {
			return prevIter, true, nil
		}
		pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
		if len(pNames) == 0 {
			return prevIter, true, nil
		}
		pName := pNames[0]
		body := normArg[arrowIdx+2:]
		upstream := prevIter
		return func() (any, bool, error) {
			it, ok, err := upstream()
			if !ok || err != nil {
				return nil, ok, err
			}
			prev, hadPrev := params[pName]
			params[pName] = it
			_, lErr := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			if lErr != nil {
				return nil, false, lErr
			}
			return it, true, nil
		}, true, nil
	case "distinct":
		upstream := prevIter
		var seen []any
		return func() (any, bool, error) {
			for {
				it, ok, err := upstream()
				if !ok || err != nil {
					return nil, ok, err
				}
				dup := false
				for _, ex := range seen {
					if painlessValuesEqual(it, ex) {
						dup = true
						break
					}
				}
				if !dup {
					seen = append(seen, it)
					return it, true, nil
				}
			}
		}, true, nil
	case "limit":
		lv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		lim, ok := toInt64Painless(lv)
		if !ok {
			return prevIter, true, nil
		}
		if lim < 0 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: strconv.FormatInt(lim, 10)}
		}
		upstream := prevIter
		var emitted int64
		return func() (any, bool, error) {
			if emitted >= lim {
				return nil, false, nil
			}
			it, ok, err := upstream()
			if !ok || err != nil {
				return nil, ok, err
			}
			emitted++
			return it, true, nil
		}, true, nil
	case "skip":
		sv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		sk, ok := toInt64Painless(sv)
		if !ok {
			return prevIter, true, nil
		}
		if sk < 0 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: strconv.FormatInt(sk, 10)}
		}
		upstream := prevIter
		var skipped int64
		return func() (any, bool, error) {
			for skipped < sk {
				_, ok, err := upstream()
				if !ok || err != nil {
					return nil, ok, err
				}
				skipped++
			}
			return upstream()
		}, true, nil
	case "sorted":
		drained, err := drainStreamIterBoundedRound59(prevIter, MaxPainlessSliceItems)
		if err != nil {
			return nil, true, err
		}
		if err := sortPainlessSliceInPlace(drained, step.args, sourceMap, params, depth+1); err != nil {
			return nil, true, err
		}
		return sliceStreamIterRound59(drained, budget), true, nil
	}
	return nil, false, nil
}

func execStreamIterForEachRound59(
	iter streamIterRound59,
	argExpr string,
	sourceMap, params map[string]any,
	budget *evalBudget,
	depth int,
) error {
	argExpr = normalizeMethodReferenceToLambdaPainless(argExpr, 1)
	arrowIdx := findNextUnquotedSubstr(argExpr, "->", 0)
	if arrowIdx <= 0 {
		for {
			_, ok, err := iter()
			if err != nil || !ok {
				return err
			}
		}
	}
	pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
	if len(pNames) == 0 {
		return nil
	}
	body := strings.TrimSpace(argExpr[arrowIdx+2:])
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = strings.TrimSpace(body[1 : len(body)-1])
	}
	ctxOp := ""
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		if k == "_return_val" || k == "_last_expr_val" || k == "__has_value_return" || k == "__has_empty_return" {
			continue
		}
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	excludedVars := make(map[string]bool, len(pNames))
	loopDeclared := make(map[string]bool)
	for _, n := range pNames {
		excludedVars[n] = true
		if !preExistingKeys[n] {
			loopDeclared[n] = true
		}
	}
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for {
		item, ok, err := iter()
		if err != nil {
			loopErr = err
			break
		}
		if !ok {
			break
		}
		if budget != nil {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
		}
		loopParams[pNames[0]] = item
		if err := execBlock(sourceMap, body, loopParams, &ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessReturn) {
				delete(loopParams, "_return_val")
				delete(loopParams, "__has_value_return")
				delete(loopParams, "__has_empty_return")
				continue
			}
			loopErr = err
			break
		}
	}
	delete(loopParams, "_return_val")
	delete(loopParams, "_last_expr_val")
	delete(loopParams, "__has_value_return")
	delete(loopParams, "__has_empty_return")
	syncLoopScopeBack(params, loopParams, preExistingKeys, excludedVars, loopDeclared)
	if ctxOp != "" {
		params["_ctx_op"] = ctxOp
	}
	return loopErr
}

// ----------------------------------------------------------------------------
// Character UTF-16 Surrogate & JDK Helper Extensions + URL.sameFile
// ----------------------------------------------------------------------------

func formatJavaCharUnitRound59(u uint16) string {
	if u >= 0xD800 && u <= 0xDFFF {
		return fmt.Sprintf("\\u%04x", u)
	}
	return string(rune(u))
}

func parseSurrogateCharStringRound59(s string) (uint16, bool) {
	if len(s) == 6 && (strings.HasPrefix(s, "\\u") || strings.HasPrefix(s, "\\U")) {
		if parsed, err := strconv.ParseUint(s[2:], 16, 16); err == nil {
			u := uint16(parsed)
			if u >= 0xD800 && u <= 0xDFFF {
				return u, true
			}
		}
	}
	return 0, false
}

// tryDecodeUnicodeEscapeRound59 decodes a `\uXXXX` Java Unicode escape starting
// at `s[uIdx] == 'u'` (where `s[uIdx-1] == '\\'`). When a UTF-16 high surrogate
// `\uD800`..`\uDBFF` is immediately followed by a low surrogate `\uDC00`..`\uDFFF`,
// both units are combined into their supplementary Unicode code point; lone
// surrogates are preserved via `formatJavaCharUnitRound59`.
func tryDecodeUnicodeEscapeRound59(s string, uIdx int) (decoded string, newIdx int, ok bool) {
	if uIdx+4 >= len(s) ||
		!isHexDigitBytePainless(s[uIdx+1]) ||
		!isHexDigitBytePainless(s[uIdx+2]) ||
		!isHexDigitBytePainless(s[uIdx+3]) ||
		!isHexDigitBytePainless(s[uIdx+4]) {
		return "", uIdx, false
	}
	parsedHi, err := strconv.ParseUint(s[uIdx+1:uIdx+5], 16, 16)
	if err != nil {
		return "", uIdx, false
	}
	hi := uint16(parsedHi)
	endIdx := uIdx + 4
	if hi >= 0xD800 && hi <= 0xDBFF && endIdx+6 < len(s) && s[endIdx+1] == '\\' && s[endIdx+2] == 'u' &&
		isHexDigitBytePainless(s[endIdx+3]) &&
		isHexDigitBytePainless(s[endIdx+4]) &&
		isHexDigitBytePainless(s[endIdx+5]) &&
		isHexDigitBytePainless(s[endIdx+6]) {
		if parsedLo, errLo := strconv.ParseUint(s[endIdx+3:endIdx+7], 16, 16); errLo == nil {
			lo := uint16(parsedLo)
			if lo >= 0xDC00 && lo <= 0xDFFF {
				return string(utf16.DecodeRune(rune(hi), rune(lo))), endIdx + 6, true
			}
		}
	}
	return formatJavaCharUnitRound59(hi), endIdx, true
}

func isMirroredCodePointRound59(cp int32) bool {
	switch cp {
	case '(', ')', '[', ']', '{', '}', '<', '>',
		0x00AB, 0x00BB, 0x2039, 0x203A, 0x2045, 0x2046,
		0x2208, 0x2209, 0x220B, 0x220C, 0x2264, 0x2265,
		0x2282, 0x2283, 0x2286, 0x2287, 0x2308, 0x2309,
		0x230A, 0x230B, 0x27E6, 0x27E7, 0x27E8, 0x27E9,
		0x27EA, 0x27EB, 0x3008, 0x3009, 0x300A, 0x300B,
		0xFF08, 0xFF09, 0xFF3B, 0xFF3D, 0xFF5B, 0xFF5D:
		return true
	}
	return false
}

func evalCharacterExtraStaticRound59(fnName string, a0 any, toCodePoint func(any) (int32, bool)) (any, bool, error) {
	switch fnName {
	case "highSurrogate":
		cp, ok := toCodePoint(a0)
		if !ok {
			return "\x00", true, nil
		}
		hi := uint16((uint32(cp) >> 10) + 0xD7C0) // #nosec G115 -- UTF-16 high surrogate formula
		return formatJavaCharUnitRound59(hi), true, nil
	case "lowSurrogate":
		cp, ok := toCodePoint(a0)
		if !ok {
			return "\x00", true, nil
		}
		lo := uint16((uint32(cp) & 0x3FF) + 0xDC00) // #nosec G115 -- UTF-16 low surrogate formula
		return formatJavaCharUnitRound59(lo), true, nil
	case "isMirrored":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, true, nil
		}
		return isMirroredCodePointRound59(cp), true, nil
	case "hashCode":
		cp, ok := toCodePoint(a0)
		if !ok {
			return int64(0), true, nil
		}
		return int64(uint16(cp)), true, nil // #nosec G115 -- Java Character.hashCode(char) returns unsigned 16-bit code unit
	case "getName":
		cp, ok := toCodePoint(a0)
		if !ok {
			return nil, true, nil
		}
		if cp < 0 || cp > 0x10FFFF {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("Not a valid Unicode code point: 0x%X", cp),
			}
		}
		if cp >= 'A' && cp <= 'Z' {
			return "LATIN CAPITAL LETTER " + string(rune(cp)), true, nil
		}
		if cp >= 'a' && cp <= 'z' {
			return "LATIN SMALL LETTER " + string(rune(cp-'a'+'A')), true, nil
		}
		if cp == ' ' {
			return "SPACE", true, nil
		}
		return fmt.Sprintf("UNICODE CHARACTER U+%04X", cp), true, nil
	}
	return nil, false, nil
}

func evalURLSameFileRound59(recVal any, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth)
	if err != nil {
		return false, err
	}
	uVal, ok1 := recVal.(*painlessURL)
	oVal, ok2 := otherVal.(*painlessURL)
	if !ok1 || !ok2 || uVal == nil || oVal == nil || uVal.u == nil || oVal.u == nil {
		return false, nil
	}
	if !strings.EqualFold(uVal.u.Scheme, oVal.u.Scheme) {
		return false, nil
	}
	if !strings.EqualFold(uVal.u.Hostname(), oVal.u.Hostname()) {
		return false, nil
	}
	p1 := uVal.getPort()
	if p1 == -1 {
		p1 = uVal.getDefaultPort()
	}
	p2 := oVal.getPort()
	if p2 == -1 {
		p2 = oVal.getDefaultPort()
	}
	if p1 != p2 {
		return false, nil
	}
	return uVal.getFile() == oVal.getFile(), nil
}

func evalArraysHashCodeRound59(val any, deep bool, sourceMap, params map[string]any, depth int) int64 {
	if val == nil {
		return 0
	}
	arr, ok := val.([]any)
	if !ok {
		return evalValueHashCodePainless(val, sourceMap, params, depth+1)
	}
	var h int32 = 1
	for _, el := range arr {
		var eh int32
		if deep {
			if sub, isSub := el.([]any); isSub {
				eh = int32(evalArraysHashCodeRound59(sub, true, sourceMap, params, depth+1)) // #nosec G115 -- 32-bit Java hashCode
				h = 31*h + eh
				continue
			}
		}
		eh = int32(evalValueHashCodePainless(el, sourceMap, params, depth+1)) // #nosec G115 -- 32-bit Java hashCode
		h = 31*h + eh
	}
	return int64(h)
}
