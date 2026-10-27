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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// UpdateRequest models an Elasticsearch `/_update/<id>` or `/_update_by_query` mutation spec.
type UpdateRequest struct {
	Doc            map[string]any `json:"doc,omitempty"`
	DocAsUpsert    bool           `json:"doc_as_upsert,omitempty"`
	Upsert         map[string]any `json:"upsert,omitempty"`
	ScriptedUpsert bool           `json:"scripted_upsert,omitempty"`
	Script         *ScriptSpec    `json:"script,omitempty"`
}

type ScriptSpec struct {
	Source string         `json:"source"`
	Lang   string         `json:"lang,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

var (
	reCtxOp          = regexp.MustCompile(`^ctx\.op\s*=\s*['"]([^'"]+)['"]$`)
	reCompoundAssign = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\s*(\+=|-=|\*=|/=)\s*(.+)$`)
	reAssignParam    = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\s*=\s*(.+)$`)
	reRemoveField    = regexp.MustCompile(`^ctx\._source(?:\.([a-zA-Z0-9_.]+))?\.remove\(\s*(.+?)\s*\)$`)
	reArrayAdd       = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\.add\(\s*(.+?)\s*\)$`)
	reArrayAddAll    = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\.addAll\(\s*(.+?)\s*\)$`)
	reMapPut         = regexp.MustCompile(`^ctx\._source(?:\.([a-zA-Z0-9_.]+))?\.put\(\s*(.+?)\s*,\s*(.+?)\s*\)$`)
	reMapPutAll      = regexp.MustCompile(`^ctx\._source(?:\.([a-zA-Z0-9_.]+))?\.putAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveIf  = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\.removeIf\(\s*([a-zA-Z0-9_]+)\s*->\s*([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_.]+))?\s*==\s*(.+?)\s*\)$`)
)

// ApplyUpdate applies either a partial `doc` deep merge or an embedded Painless `script`
// against a raw `_source` JSON payload and returns the mutated `_source` JSON bytes.
func ApplyUpdate(rawSource json.RawMessage, req *UpdateRequest) (json.RawMessage, error) {
	updated, _, err := ApplyUpdateWithResult(rawSource, req, len(bytes.TrimSpace(rawSource)) > 0)
	return updated, err
}

// ApplyUpdateWithResult applies an `UpdateRequest` and returns `(updatedSource, opResult, error)`
// where `opResult` is `"updated"`, `"created"`, `"noop"`, or `"deleted"`.
func ApplyUpdateWithResult(rawSource json.RawMessage, req *UpdateRequest, docExisted bool) (json.RawMessage, string, error) {
	var doc map[string]any
	trimmed := bytes.TrimSpace(rawSource)
	if len(trimmed) > 0 {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal _source for update: %w", err)
		}
	}
	if doc == nil {
		doc = make(map[string]any)
	}

	if !docExisted {
		if req.Upsert != nil {
			deepMergeMap(doc, req.Upsert)
			if !req.ScriptedUpsert {
				out, err := json.Marshal(doc)
				return json.RawMessage(out), "created", err
			}
		} else if req.DocAsUpsert && len(req.Doc) > 0 {
			deepMergeMap(doc, req.Doc)
			out, err := json.Marshal(doc)
			return json.RawMessage(out), "created", err
		}
	}

	if len(req.Doc) > 0 {
		deepMergeMap(doc, req.Doc)
	}

	opResult := "updated"
	if !docExisted {
		opResult = "created"
	}

	if req.Script != nil && strings.TrimSpace(req.Script.Source) != "" {
		ctxOp, err := EvalPainlessWithOp(doc, req.Script.Source, req.Script.Params)
		if err != nil {
			return nil, "", err
		}
		switch strings.ToLower(ctxOp) {
		case "noop", "none":
			opResult = "noop"
		case "delete":
			opResult = "deleted"
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	return json.RawMessage(out), opResult, nil
}

const (
	MaxPainlessSteps      = 10_000
	MaxPainlessDepth      = 32
	MaxPainlessSliceItems = 10_000
)

type evalBudget struct {
	steps int
	depth int
}

func (b *evalBudget) step() error {
	b.steps++
	if b.steps > MaxPainlessSteps {
		return fmt.Errorf("painless script exceeded maximum step budget (%d)", MaxPainlessSteps)
	}
	return nil
}

// EvalPainless evaluates common Painless script statements used by OpenMetadata and DataHub
// against `sourceMap` (`ctx._source`) with `params`.
func EvalPainless(sourceMap map[string]any, scriptSource string, params map[string]any) error {
	_, err := EvalPainlessWithOp(sourceMap, scriptSource, params)
	return err
}

// EvalPainlessWithOp evaluates a Painless script and returns any `ctx.op` set by the script.
func EvalPainlessWithOp(sourceMap map[string]any, scriptSource string, params map[string]any) (string, error) {
	if params == nil {
		params = make(map[string]any)
	}
	ctxOp := ""
	budget := &evalBudget{}
	err := execBlock(sourceMap, scriptSource, params, &ctxOp, budget)
	return ctxOp, err
}

func execBlock(sourceMap map[string]any, block string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	budget.depth++
	defer func() { budget.depth-- }()
	if budget.depth > MaxPainlessDepth {
		return fmt.Errorf("painless script exceeded maximum recursion depth (%d)", MaxPainlessDepth)
	}

	stmts := splitTopLevelStatements(block)
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if err := budget.step(); err != nil {
			return err
		}
		if strings.HasPrefix(stmt, "if") && (len(stmt) == 2 || stmt[2] == ' ' || stmt[2] == '(') {
			if err := execIfStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "for") && (len(stmt) == 3 || stmt[3] == ' ' || stmt[3] == '(') {
			if err := execForStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if err := execSimpleStmt(sourceMap, stmt, params, ctxOp, budget); err != nil {
			return err
		}
	}
	return nil
}

func execIfStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	cond, thenBody, elseBody, ok := parseIfBlocks(stmt)
	if !ok {
		return nil
	}
	if evalCondition(sourceMap, cond, params) {
		return execBlock(sourceMap, thenBody, params, ctxOp, budget)
	}
	if strings.TrimSpace(elseBody) != "" {
		return execBlock(sourceMap, elseBody, params, ctxOp, budget)
	}
	return nil
}

func execForStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	header := strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	body := strings.TrimSpace(rest)
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = body[1 : len(body)-1]
	}

	var varName, iterExpr string
	if idx := strings.Index(header, " in "); idx >= 0 {
		varName = strings.TrimSpace(header[:idx])
		iterExpr = strings.TrimSpace(header[idx+4:])
	} else if idx := strings.IndexByte(header, ':'); idx >= 0 {
		varName = strings.TrimSpace(header[:idx])
		iterExpr = strings.TrimSpace(header[idx+1:])
	} else {
		return nil
	}
	fields := strings.Fields(varName)
	if len(fields) > 0 {
		varName = fields[len(fields)-1]
	}

	iterVal, err := evalRHSExpr(sourceMap, iterExpr, params)
	if err != nil {
		return err
	}
	slice, ok := iterVal.([]any)
	if !ok {
		return nil
	}
	// Copy slice header + elements so in-loop mutations do not mutate the iteration snapshot
	snapshot := make([]any, len(slice))
	copy(snapshot, slice)

	loopParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		loopParams[k] = v
	}
	for _, item := range snapshot {
		if err := budget.step(); err != nil {
			return err
		}
		loopParams[varName] = item
		if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
			return err
		}
	}
	return nil
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// normalizeBracketAccess rewrites bracket property accesses like `ctx._source['field']`
// or `params["key"]` into dot notation (`ctx._source.field`, `params.key`) outside string literals.
func normalizeBracketAccess(s string) string {
	if strings.IndexByte(s, '[') < 0 {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes != 0 {
			out.WriteByte(c)
			if c == inQuotes && (i == 0 || s[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuotes = c
			out.WriteByte(c)
			continue
		}
		if c == '[' && i > 0 && (isIdentByte(s[i-1]) || s[i-1] == ']') && i+3 < len(s) && (s[i+1] == '\'' || s[i+1] == '"') {
			q := s[i+1]
			j := i + 2
			valid := false
			for j < len(s) && isIdentByte(s[j]) {
				j++
				valid = true
			}
			if valid && j+1 < len(s) && s[j] == q && s[j+1] == ']' {
				out.WriteByte('.')
				out.WriteString(s[i+2 : j])
				i = j + 1
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

func execSimpleStmt(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	stmt = normalizeBracketAccess(stmt)
	if m := reCtxOp.FindStringSubmatch(stmt); m != nil {
		*ctxOp = m[1]
		return nil
	}

	// 1. Check `removeIf` on array of objects or scalars
	if m := reArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		var propPath []string
		if m[4] != "" {
			propPath = strings.Split(m[4], ".")
		}
		targetVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[5]), params)
		if err != nil {
			return err
		}
		removeIfFromSlice(sourceMap, arrPath, propPath, targetVal)
		return nil
	}

	// 2. Check `.addAll(...)` on array
	if m := reArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		if items, ok := valToAdd.([]any); ok {
			// Snapshot items before appending to prevent self-aliasing issues
			itemsCopy := make([]any, len(items))
			copy(itemsCopy, items)
			for _, item := range itemsCopy {
				if err := budget.step(); err != nil {
					return err
				}
				if err := appendToSlice(sourceMap, arrPath, item); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// 3. Check `.add(...)` on array
	if m := reArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		return appendToSlice(sourceMap, arrPath, valToAdd)
	}

	// 4. Check `.putAll(...)` on map
	if m := reMapPutAll.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		mapVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		if subMap, ok := mapVal.(map[string]any); ok {
			putAllAtPath(sourceMap, targetPath, subMap)
		}
		return nil
	}

	// 5. Check `.put(k, v)` on map
	if m := reMapPut.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		setValueAtPath(sourceMap, append(targetPath, keyStr), vVal)
		return nil
	}

	// 6. Check `.remove('field')` or `.remove(params.key)` or `.remove(0)`
	if m := reRemoveField.FindStringSubmatch(stmt); m != nil {
		var parentPath []string
		if m[1] != "" {
			parentPath = strings.Split(m[1], ".")
		}
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
		return nil
	}

	// 7. Check compound assignment `+=` / `-=` / `*=` / `/=`
	if m := reCompoundAssign.FindStringSubmatch(stmt); m != nil {
		lhsPath := strings.Split(m[1], ".")
		op := m[2]
		rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		curVal := resolveParamPath(sourceMap, lhsPath)
		switch op {
		case "+=":
			setValueAtPath(sourceMap, lhsPath, applyArithmetic(curVal, rhsVal, true))
		case "-=":
			setValueAtPath(sourceMap, lhsPath, applyArithmetic(curVal, rhsVal, false))
		case "*=":
			setValueAtPath(sourceMap, lhsPath, applyMulDiv(curVal, rhsVal, true))
		case "/=":
			setValueAtPath(sourceMap, lhsPath, applyMulDiv(curVal, rhsVal, false))
		}
		return nil
	}

	// 8. Check field assignment (`ctx._source.deleted = params.deleted`, arithmetic, or literal)
	if m := reAssignParam.FindStringSubmatch(stmt); m != nil {
		lhsPath := strings.Split(m[1], ".")
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		setValueAtPath(sourceMap, lhsPath, val)
		return nil
	}

	return nil
}

func trimBalancedParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		if findMatchingDelimiter(s, 0, '(', ')') == len(s)-1 {
			s = strings.TrimSpace(s[1 : len(s)-1])
		} else {
			break
		}
	}
	return s
}

func splitTopLevelCondOp(s, op string) []string {
	var parts []string
	depth := 0
	inQuotes := byte(0)
	lastStart := 0
	for i := 0; i <= len(s)-len(op); i++ {
		c := s[i]
		if inQuotes != 0 {
			if c == inQuotes && (i == 0 || s[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuotes = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(op)] == op {
				parts = append(parts, s[lastStart:i])
				lastStart = i + len(op)
				i += len(op) - 1
			}
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func evalCondition(sourceMap map[string]any, cond string, params map[string]any) bool {
	cond = trimBalancedParens(cond)
	if cond == "" {
		return false
	}
	if parts := splitTopLevelCondOp(cond, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalCondition(sourceMap, p, params) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelCondOp(cond, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalCondition(sourceMap, p, params) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(cond, "!") {
		return !evalCondition(sourceMap, cond[1:], params)
	}

	// Check `.contains(...)`
	if idx := strings.Index(cond, ".contains("); idx > 0 && strings.HasSuffix(cond, ")") {
		lhsExpr := strings.TrimSpace(cond[:idx])
		argExpr := strings.TrimSpace(cond[idx+len(".contains(") : len(cond)-1])
		lhsVal, _ := evalRHSExpr(sourceMap, lhsExpr, params)
		argVal, _ := evalRHSExpr(sourceMap, argExpr, params)
		if arr, ok := lhsVal.([]any); ok {
			for _, item := range arr {
				if valuesEqual(item, argVal) {
					return true
				}
			}
		}
		return false
	}

	// Check `.containsKey(...)`
	if idx := strings.Index(cond, ".containsKey("); idx > 0 && strings.HasSuffix(cond, ")") {
		lhsExpr := strings.TrimSpace(cond[:idx])
		argExpr := strings.TrimSpace(cond[idx+len(".containsKey(") : len(cond)-1])
		lhsVal, _ := evalRHSExpr(sourceMap, lhsExpr, params)
		argVal, _ := evalRHSExpr(sourceMap, argExpr, params)
		if m, ok := lhsVal.(map[string]any); ok {
			_, exists := m[fmt.Sprintf("%v", argVal)]
			return exists
		}
		return false
	}

	if idx := strings.Index(cond, "!="); idx > 0 {
		lhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[:idx]), params)
		rhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[idx+2:]), params)
		return !valuesEqual(lhs, rhs)
	}
	if idx := strings.Index(cond, "=="); idx > 0 {
		lhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[:idx]), params)
		rhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[idx+2:]), params)
		return valuesEqual(lhs, rhs)
	}
	for _, op := range []string{">=", "<=", ">", "<"} {
		if idx := strings.Index(cond, op); idx > 0 {
			lhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[:idx]), params)
			rhs, _ := evalRHSExpr(sourceMap, strings.TrimSpace(cond[idx+len(op):]), params)
			return compareOrderedValues(lhs, rhs, op)
		}
	}

	val, _ := evalRHSExpr(sourceMap, cond, params)
	if b, ok := val.(bool); ok {
		return b
	}
	return val != nil
}

func compareOrderedValues(a, b any, op string) bool {
	fa, oka := toFloat64(a)
	fb, okb := toFloat64(b)
	if oka && okb {
		switch op {
		case ">=":
			return fa >= fb
		case "<=":
			return fa <= fb
		case ">":
			return fa > fb
		case "<":
			return fa < fb
		}
	}
	sa, soka := a.(string)
	sb, sokb := b.(string)
	if soka && sokb {
		switch op {
		case ">=":
			return sa >= sb
		case "<=":
			return sa <= sb
		case ">":
			return sa > sb
		case "<":
			return sa < sb
		}
	}
	return false
}

func valuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if reflect.DeepEqual(a, b) {
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func evalRHSExpr(sourceMap map[string]any, rhs string, params map[string]any) (any, error) {
	rhs = trimBalancedParens(normalizeBracketAccess(rhs))
	// Check binary `+` or `-` outside quotes
	if opIdx, isAdd := findTopLevelAddSub(rhs); opIdx > 0 {
		leftVal, err := evalRHSExpr(sourceMap, rhs[:opIdx], params)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExpr(sourceMap, rhs[opIdx+1:], params)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(leftVal, rightVal, isAdd), nil
	}
	if opIdx, isMul := findTopLevelMulDiv(rhs); opIdx > 0 {
		leftVal, err := evalRHSExpr(sourceMap, rhs[:opIdx], params)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExpr(sourceMap, rhs[opIdx+1:], params)
		if err != nil {
			return nil, err
		}
		return applyMulDiv(leftVal, rightVal, isMul), nil
	}
	if strings.HasPrefix(rhs, "-") && len(rhs) > 1 && (rhs[1] < '0' || rhs[1] > '9') {
		innerVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(rhs[1:]), params)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, false), nil
	}

	if rhs == "ctx._source" {
		return sourceMap, nil
	}
	if strings.HasPrefix(rhs, "ctx._source.") {
		path := strings.Split(strings.TrimPrefix(rhs, "ctx._source."), ".")
		return resolveParamPath(sourceMap, path), nil
	}
	if rhs == "params" {
		return params, nil
	}
	if strings.HasPrefix(rhs, "params.") {
		paramPath := strings.Split(strings.TrimPrefix(rhs, "params."), ".")
		return resolveParamPath(params, paramPath), nil
	}
	if val, ok := params[rhs]; ok {
		return val, nil
	}
	if rhs == "null" {
		return nil, nil
	}
	if rhs == "[]" {
		return []any{}, nil
	}
	if rhs == "[:]" || rhs == "{}" {
		return map[string]any{}, nil
	}
	if (strings.HasPrefix(rhs, "'") && strings.HasSuffix(rhs, "'")) ||
		(strings.HasPrefix(rhs, `"`) && strings.HasSuffix(rhs, `"`)) {
		if len(rhs) >= 2 {
			return rhs[1 : len(rhs)-1], nil
		}
	}
	dec := json.NewDecoder(strings.NewReader(rhs))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err == nil {
		return parsed, nil
	}
	return rhs, nil
}

func findTopLevelAddSub(expr string) (int, bool) {
	inQuotes := byte(0)
	depth := 0
	lastIdx := -1
	lastIsAdd := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuotes != 0 {
			if c == inQuotes && (i == 0 || expr[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuotes = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '+', '-':
			if depth == 0 && i > 0 {
				if (expr[i-1] == 'e' || expr[i-1] == 'E') && i >= 2 && ((expr[i-2] >= '0' && expr[i-2] <= '9') || expr[i-2] == '.') {
					continue
				}
				prev := strings.TrimSpace(expr[:i])
				if len(prev) > 0 {
					lastChar := prev[len(prev)-1]
					if lastChar != '+' && lastChar != '-' && lastChar != '*' && lastChar != '/' && lastChar != '(' &&
						lastChar != ',' && lastChar != '?' && lastChar != ':' && lastChar != '=' && lastChar != '<' && lastChar != '>' && lastChar != '!' {
						lastIdx = i
						lastIsAdd = c == '+'
					}
				}
			}
		}
	}
	return lastIdx, lastIsAdd
}

func findTopLevelMulDiv(expr string) (int, bool) {
	inQuotes := byte(0)
	depth := 0
	lastIdx := -1
	lastIsMul := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuotes != 0 {
			if c == inQuotes && (i == 0 || expr[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuotes = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '*', '/':
			if depth == 0 && i > 0 {
				lastIdx = i
				lastIsMul = c == '*'
			}
		}
	}
	return lastIdx, lastIsMul
}

func applyMulDiv(a, b any, isMul bool) any {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		var res float64
		if isMul {
			res = af * bf
		} else if bf != 0 {
			res = af / bf
		}
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}
	return float64(0)
}

func applyArithmetic(a, b any, isAdd bool) any {
	if isAdd {
		_, aIsStr := a.(string)
		_, bIsStr := b.(string)
		if aIsStr || bIsStr {
			return fmt.Sprintf("%v%v", a, b)
		}
	}
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		res := af + bf
		if !isAdd {
			res = af - bf
		}
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}
	if isAdd {
		return fmt.Sprintf("%v%v", a, b)
	}
	return a
}

func toFloat64(v any) (float64, bool) {
	var f float64
	var ok bool
	switch val := v.(type) {
	case nil:
		return 0, true
	case int:
		f, ok = float64(val), true
	case int64:
		f, ok = float64(val), true
	case float64:
		f, ok = val, true
	case json.Number:
		parsed, err := val.Float64()
		f, ok = parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(val, 64)
		f, ok = parsed, err == nil
	default:
		return 0, false
	}
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func parseIfBlocks(stmt string) (cond, thenBody, elseBody string, ok bool) {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return "", "", "", false
	}
	cond = strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	if strings.HasPrefix(rest, "{") {
		closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
		if closeBrace < 0 {
			return "", "", "", false
		}
		thenBody = rest[1:closeBrace]
		afterThen := strings.TrimSpace(rest[closeBrace+1:])
		if strings.HasPrefix(afterThen, "else") {
			elseRest := strings.TrimSpace(afterThen[4:])
			if strings.HasPrefix(elseRest, "{") && strings.HasSuffix(elseRest, "}") {
				elseBody = elseRest[1 : len(elseRest)-1]
			} else {
				elseBody = elseRest
			}
		}
		return cond, thenBody, elseBody, true
	}
	return cond, rest, "", true
}

func findMatchingDelimiter(s string, openIdx int, openChar, closeChar byte) int {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != openChar {
		return -1
	}
	depth := 0
	inQuotes := byte(0)
	for i := openIdx; i < len(s); i++ {
		c := s[i]
		if inQuotes != 0 {
			if c == inQuotes && (i == 0 || s[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuotes = c
		case openChar:
			depth++
		case closeChar:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopLevelStatements(s string) []string {
	var out []string
	var curr strings.Builder
	braceDepth := 0
	parenDepth := 0
	inQuotes := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes != 0 {
			curr.WriteByte(c)
			if c == inQuotes && (i == 0 || s[i-1] != '\\') {
				inQuotes = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuotes = c
			curr.WriteByte(c)
		case '(':
			parenDepth++
			curr.WriteByte(c)
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			curr.WriteByte(c)
		case '{':
			braceDepth++
			curr.WriteByte(c)
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
			curr.WriteByte(c)
			if braceDepth == 0 && parenDepth == 0 {
				// Check if followed by `else`
				rem := strings.TrimSpace(s[i+1:])
				if !strings.HasPrefix(rem, "else") {
					out = append(out, curr.String())
					curr.Reset()
				}
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				if c == '\n' && strings.HasPrefix(strings.TrimSpace(s[i+1:]), "else") {
					curr.WriteByte(c)
					continue
				}
				if strings.TrimSpace(curr.String()) != "" {
					out = append(out, curr.String())
				}
				curr.Reset()
			} else {
				curr.WriteByte(c)
			}
		default:
			curr.WriteByte(c)
		}
	}
	if strings.TrimSpace(curr.String()) != "" {
		out = append(out, curr.String())
	}
	return out
}

func resolveParamPath(params map[string]any, path []string) any {
	var curr any = params
	for _, seg := range path {
		m, ok := curr.(map[string]any)
		if !ok {
			return nil
		}
		curr = m[seg]
	}
	return curr
}

func setValueAtPath(root map[string]any, path []string, val any) {
	curr := root
	for i := 0; i < len(path)-1; i++ {
		seg := path[i]
		next, ok := curr[seg].(map[string]any)
		if !ok {
			next = make(map[string]any)
			curr[seg] = next
		}
		curr = next
	}
	curr[path[len(path)-1]] = val
}

func putAllAtPath(root map[string]any, path []string, values map[string]any) {
	curr := root
	for _, seg := range path {
		next, ok := curr[seg].(map[string]any)
		if !ok {
			next = make(map[string]any)
			curr[seg] = next
		}
		curr = next
	}
	for k, v := range values {
		curr[k] = v
	}
}

func removeKeyOrIndexAtPath(root map[string]any, parentPath []string, keyOrIdx any) {
	if len(parentPath) == 0 {
		delete(root, fmt.Sprintf("%v", keyOrIdx))
		return
	}
	curr := root
	for i := 0; i < len(parentPath)-1; i++ {
		next, ok := curr[parentPath[i]].(map[string]any)
		if !ok {
			return
		}
		curr = next
	}
	lastSeg := parentPath[len(parentPath)-1]
	switch target := curr[lastSeg].(type) {
	case map[string]any:
		delete(target, fmt.Sprintf("%v", keyOrIdx))
	case []any:
		if f, ok := toFloat64(keyOrIdx); ok {
			idx := int(f)
			if idx >= 0 && idx < len(target) {
				curr[lastSeg] = append(target[:idx], target[idx+1:]...)
			}
		}
	}
}

func appendToSlice(root map[string]any, path []string, val any) error {
	curr := root
	for i := 0; i < len(path)-1; i++ {
		seg := path[i]
		next, ok := curr[seg].(map[string]any)
		if !ok {
			next = make(map[string]any)
			curr[seg] = next
		}
		curr = next
	}
	lastKey := path[len(path)-1]
	existing, ok := curr[lastKey].([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	curr[lastKey] = append(existing, val)
	return nil
}

func removeIfFromSlice(root map[string]any, arrPath []string, propPath []string, matchVal any) {
	curr := root
	for i := 0; i < len(arrPath)-1; i++ {
		next, ok := curr[arrPath[i]].(map[string]any)
		if !ok {
			return
		}
		curr = next
	}
	lastKey := arrPath[len(arrPath)-1]
	existing, ok := curr[lastKey].([]any)
	if !ok {
		return
	}
	filtered := make([]any, 0, len(existing))
	for _, item := range existing {
		if len(propPath) == 0 {
			if valuesEqual(item, matchVal) {
				continue
			}
		} else if itemMap, ok := item.(map[string]any); ok {
			if valuesEqual(resolveParamPath(itemMap, propPath), matchVal) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	curr[lastKey] = filtered
}

func deepMergeMap(dst, src map[string]any) {
	for k, v := range src {
		if srcSubMap, ok := v.(map[string]any); ok {
			if dstSubMap, ok := dst[k].(map[string]any); ok {
				deepMergeMap(dstSubMap, srcSubMap)
				continue
			}
		}
		dst[k] = v
	}
}
