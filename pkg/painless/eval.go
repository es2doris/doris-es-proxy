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
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var (
	errPainlessReturn   = errors.New("painless_return")
	errPainlessBreak    = errors.New("painless_break")
	errPainlessContinue = errors.New("painless_continue")
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
	reCtxOp               = regexp.MustCompile(`^ctx\.op\s*=\s*['"]([^'"]+)['"]$`)
	reCtxIncDec           = regexp.MustCompile(`^(?:(\+\+|--)\s*ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)|ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\s*(\+\+|--))$`)
	reCompoundAssign      = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\s*(\+=|-=|\*=|/=)\s*(.+)$`)
	reAssignParam         = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\s*=\s*(.+)$`)
	reRemoveField         = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_.@/:?\x00-\x04-]+))?\.remove\(\s*(.+?)\s*\)$`)
	reArrayAdd            = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\.add\(\s*(.+?)\s*\)$`)
	reArrayAddAll         = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\.addAll\(\s*(.+?)\s*\)$`)
	reMapPut              = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_.@/:?\x00-\x04-]+))?\.put\(\s*(.+?)\s*,\s*(.+?)\s*\)$`)
	reMapPutAll           = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_.@/:?\x00-\x04-]+))?\.putAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveIf       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\.removeIf\(\s*([a-zA-Z0-9_]+)\s*->\s*([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_.@/:?\x00-\x04-]+))?\s*==\s*(.+?)\s*\)$`)
	reLocalIncDec         = regexp.MustCompile(`^(?:(\+\+|--)\s*([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)|([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\s*(\+\+|--))$`)
	reLocalRemoveField    = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.remove\(\s*(.+?)\s*\)$`)
	reLocalArrayAdd       = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.add\(\s*(.+?)\s*\)$`)
	reLocalArrayAddAll    = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.addAll\(\s*(.+?)\s*\)$`)
	reLocalMapPut         = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.put\(\s*(.+?)\s*,\s*(.+?)\s*\)$`)
	reLocalMapPutAll      = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.putAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveIf  = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\.removeIf\(\s*([a-zA-Z0-9_]+)\s*->\s*([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_.@/:?\x00-\x04-]+))?\s*==\s*(.+?)\s*\)$`)
	reLocalCompoundAssign = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_.@/:?\x00-\x04-]+)*)\s*(\+=|-=|\*=|/=)\s*(.+)$`)
	reLocalPropAssign     = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_.@/:?\x00-\x04-]+)\s*=\s*(.+)$`)
	reLocalVarAssign      = regexp.MustCompile(`^(?:(?:def|boolean|int|long|double|float|String|Object|Map|List)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$`)
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
		case "delete", "drop":
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
	cleaned := stripPainlessComments(scriptSource)
	err := execBlock(sourceMap, cleaned, params, &ctxOp, budget)
	if errors.Is(err, errPainlessReturn) {
		err = nil
	}
	return ctxOp, err
}

func stripPainlessComments(s string) string {
	if !strings.Contains(s, "//") && !strings.Contains(s, "/*") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if inQuotes == 0 && s[i] == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				i += 2
				for i < len(s) && s[i] != '\n' {
					i++
				}
				if i < len(s) {
					out.WriteByte('\n')
				}
				continue
			}
			if s[i+1] == '*' {
				i += 2
				for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
					i++
				}
				i++
				continue
			}
		}
		_ = stepQuoteState(s, i, &inQuotes, &inRegexClass)
		out.WriteByte(s[i])
	}
	return out.String()
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
	} else if clauses := splitTopLevelSemicolonPainless(header); len(clauses) == 3 {
		loopParams := make(map[string]any, len(params)+2)
		for k, v := range params {
			loopParams[k] = v
		}
		if initStmt := strings.TrimSpace(clauses[0]); initStmt != "" {
			if err := execSimpleStmt(sourceMap, initStmt, loopParams, ctxOp, budget); err != nil {
				return err
			}
		}
		condExpr := strings.TrimSpace(clauses[1])
		postStmt := strings.TrimSpace(clauses[2])
		var loopErr error
		for {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			if condExpr != "" && !evalCondition(sourceMap, condExpr, loopParams) {
				break
			}
			if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessBreak) {
					break
				}
				if !errors.Is(err, errPainlessContinue) {
					loopErr = err
					break
				}
			}
			if postStmt != "" {
				if err := execSimpleStmt(sourceMap, postStmt, loopParams, ctxOp, budget); err != nil {
					loopErr = err
					break
				}
			}
		}
		for k := range params {
			params[k] = loopParams[k]
		}
		return loopErr
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
	var loopErr error
	for _, item := range snapshot {
		if err := budget.step(); err != nil {
			loopErr = err
			break
		}
		loopParams[varName] = item
		if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				break
			}
			if errors.Is(err, errPainlessContinue) {
				continue
			}
			loopErr = err
			break
		}
	}
	for k, v := range loopParams {
		if k != varName {
			params[k] = v
		}
	}
	return loopErr
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func isBracketReceiverByte(c byte) bool {
	return isIdentByte(c) || c == ']' || c == ')' || c == '?' || (c >= '\x00' && c <= '\x04')
}

func encodeBracketKey(key string) string {
	var out strings.Builder
	out.Grow(len(key))
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '.':
			out.WriteByte('\x00')
		case ' ':
			out.WriteByte('\x01')
		case '/':
			out.WriteByte('\x02')
		case ':':
			out.WriteByte('\x03')
		case '-':
			out.WriteByte('\x04')
		default:
			out.WriteByte(key[i])
		}
	}
	return out.String()
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func decodeBracketSeg(seg string) string {
	seg = strings.TrimSuffix(seg, "?")
	seg = strings.ReplaceAll(seg, "\x00", ".")
	seg = strings.ReplaceAll(seg, "\x01", " ")
	seg = strings.ReplaceAll(seg, "\x02", "/")
	seg = strings.ReplaceAll(seg, "\x03", ":")
	seg = strings.ReplaceAll(seg, "\x04", "-")
	return seg
}

func expandDynamicBrackets(s string, sourceMap map[string]any, params map[string]any, depth int) string {
	if strings.IndexByte(s, '[') < 0 || depth > 64 {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			out.WriteByte(c)
			continue
		}
		if c == '[' && i > 0 && isBracketReceiverByte(s[i-1]) {
			closeIdx := findMatchingDelimiter(s, i, '[', ']')
			if closeIdx > i+1 {
				inner := strings.TrimSpace(s[i+1 : closeIdx])
				if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
					q := inner[0]
					rawKey := inner[1 : len(inner)-1]
					validLiteral := !strings.ContainsRune(rawKey, rune(q))
					if validLiteral {
						out.WriteByte('.')
						out.WriteString(encodeBracketKey(rawKey))
						i = closeIdx
						continue
					}
				}
				if isIntegerLiteral(inner) {
					out.WriteByte('.')
					out.WriteString(encodeBracketKey(inner))
					i = closeIdx
					continue
				}
				if sourceMap != nil || params != nil {
					if idxVal, err := evalRHSExprDepth(sourceMap, inner, params, depth+1); err == nil && idxVal != nil {
						var keyStr string
						if strVal, isStr := idxVal.(string); isStr {
							keyStr = strVal
						} else if f, ok := toFloat64(idxVal); ok && f == float64(int64(f)) {
							keyStr = strconv.FormatInt(int64(f), 10)
						} else {
							keyStr = fmt.Sprintf("%v", idxVal)
						}
						if keyStr != "" {
							out.WriteByte('.')
							out.WriteString(encodeBracketKey(keyStr))
							i = closeIdx
							continue
						}
					}
				}
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

func execSimpleStmt(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	stmt = strings.TrimSpace(expandDynamicBrackets(stmt, sourceMap, params, 0))
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") {
		return errPainlessReturn
	}
	if stmt == "break" {
		return errPainlessBreak
	}
	if stmt == "continue" {
		return errPainlessContinue
	}
	if m := reCtxOp.FindStringSubmatch(stmt); m != nil {
		*ctxOp = m[1]
		return nil
	}
	if m := reCtxIncDec.FindStringSubmatch(stmt); m != nil {
		op := m[1]
		pathStr := m[2]
		if op == "" {
			pathStr = m[3]
			op = m[4]
		}
		lhsPath := strings.Split(pathStr, ".")
		curVal := resolveParamPath(sourceMap, lhsPath)
		setValueAtPath(sourceMap, lhsPath, applyArithmetic(curVal, int64(1), op == "++"))
		return nil
	}
	if m := reLocalIncDec.FindStringSubmatch(stmt); m != nil {
		op := m[1]
		lhs := m[2]
		if op == "" {
			lhs = m[3]
			op = m[4]
		}
		path := strings.Split(lhs, ".")
		curVal := resolveParamPath(params, path)
		nextVal := applyArithmetic(curVal, int64(1), op == "++")
		setValueAtPath(params, path, nextVal)
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

	// 6b. Check `.removeIf`, `.addAll`, `.add`, `.putAll`, `.put`, `.remove` on local/loop variables
	if m := reLocalArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(arrPath[0])]; ok {
			var propPath []string
			if m[4] != "" {
				propPath = strings.Split(m[4], ".")
			}
			targetVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[5]), params)
			if err != nil {
				return err
			}
			removeIfFromSlice(params, arrPath, propPath, targetVal)
			return nil
		}
	}
	if m := reLocalArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(arrPath[0])]; ok {
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			if items, ok := valToAdd.([]any); ok {
				itemsCopy := make([]any, len(items))
				copy(itemsCopy, items)
				for _, item := range itemsCopy {
					if err := budget.step(); err != nil {
						return err
					}
					if err := appendToSlice(params, arrPath, item); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}
	if m := reLocalArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(arrPath[0])]; ok {
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			return appendToSlice(params, arrPath, valToAdd)
		}
	}
	if m := reLocalMapPutAll.FindStringSubmatch(stmt); m != nil {
		targetPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(targetPath[0])]; ok {
			mapVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			if subMap, ok := mapVal.(map[string]any); ok {
				putAllAtPath(params, targetPath, subMap)
			}
			return nil
		}
	}
	if m := reLocalMapPut.FindStringSubmatch(stmt); m != nil {
		targetPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(targetPath[0])]; ok {
			kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
			if err != nil {
				return err
			}
			setValueAtPath(params, append(targetPath, fmt.Sprintf("%v", kVal)), vVal)
			return nil
		}
	}
	if m := reLocalRemoveField.FindStringSubmatch(stmt); m != nil {
		parentPath := strings.Split(m[1], ".")
		if _, ok := params[decodeBracketSeg(parentPath[0])]; ok {
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			removeKeyOrIndexAtPath(params, parentPath, argVal)
			return nil
		}
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
			setValueAtPath(sourceMap, lhsPath, applyMulDiv(curVal, rhsVal, '*'))
		case "/=":
			setValueAtPath(sourceMap, lhsPath, applyMulDiv(curVal, rhsVal, '/'))
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

	// 9. Check local/loop variable compound assignment (`sum += x`, `item.count += 1`, `items[0].qty += 2`)
	if m := reLocalCompoundAssign.FindStringSubmatch(stmt); m != nil {
		lhs := m[1]
		op := m[2]
		rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		path := strings.Split(lhs, ".")
		curVal := resolveParamPath(params, path)
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
		}
		setValueAtPath(params, path, nextVal)
		return nil
	}

	// 10. Check local/loop variable property/index assignment (`tag.status = 'active'`, `items[0] = 'x'`)
	if m := reLocalPropAssign.FindStringSubmatch(stmt); m != nil {
		varName := m[1]
		propPath := strings.Split(m[2], ".")
		rhsExpr := strings.TrimSpace(m[3])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		setValueAtPath(params, append([]string{varName}, propPath...), val)
		return nil
	}

	// 11. Check local variable declaration/assignment (`def x = ...`, `boolean ok = ...`, `x = ...`)
	if m := reLocalVarAssign.FindStringSubmatch(stmt); m != nil {
		varName := m[1]
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		params[varName] = val
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
	inRegexClass := false
	lastStart := 0
	for i := 0; i <= len(s)-len(op); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
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
	return evalConditionDepth(sourceMap, cond, params, 0)
}

func isEscapedAt(s string, idx int) bool {
	bs := 0
	for j := idx - 1; j >= 0 && s[j] == '\\'; j-- {
		bs++
	}
	return bs%2 == 1
}

func isRegexSlashAt(s string, idx int) bool {
	if idx < 0 || idx >= len(s) || s[idx] != '/' {
		return false
	}
	for j := idx - 1; j >= 0; j-- {
		if s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' {
			continue
		}
		return s[j] == '~'
	}
	return false
}

func stepQuoteState(s string, i int, inQuotes *byte, inRegexClass *bool) bool {
	c := s[i]
	if *inQuotes != 0 {
		if *inQuotes == '/' && !isEscapedAt(s, i) {
			if c == '[' && !*inRegexClass {
				*inRegexClass = true
				return true
			}
			if c == ']' && *inRegexClass {
				*inRegexClass = false
				return true
			}
			if *inRegexClass {
				return true
			}
		}
		if c == *inQuotes && !isEscapedAt(s, i) {
			*inQuotes = 0
			*inRegexClass = false
		}
		return true
	}
	if c == '/' && isRegexSlashAt(s, i) {
		*inQuotes = '/'
		*inRegexClass = false
		return true
	}
	if c == '\'' || c == '"' {
		*inQuotes = c
		return true
	}
	return false
}

func findTopLevelOpPainless(s, op string) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i <= len(s)-len(op); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(op)] == op {
				if op == "==" && ((i+2 < len(s) && (s[i+2] == '~' || s[i+2] == '=')) || (i > 0 && (s[i-1] == '=' || s[i-1] == '!'))) {
					continue
				}
				if op == "!=" && i+2 < len(s) && s[i+2] == '=' {
					continue
				}
				if op == ">" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == "<" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == "?" && i+1 < len(s) && (s[i+1] == '.' || s[i+1] == ':') {
					continue
				}
				if op == ":" && i > 0 && s[i-1] == '?' {
					continue
				}
				return i
			}
		}
	}
	return -1
}

func findMatchingTernaryColonPainless(s string) int {
	depth := 0
	ternaryDepth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '?':
			if depth == 0 && (i+1 >= len(s) || (s[i+1] != '.' && s[i+1] != ':')) {
				ternaryDepth++
			}
		case ':':
			if depth == 0 && (i == 0 || s[i-1] != '?') {
				if ternaryDepth == 0 {
					return i
				}
				ternaryDepth--
			}
		}
	}
	return -1
}

func evalRegexMatchPainless(lhsVal, rhsVal any, fullMatch bool) bool {
	if lhsVal == nil || rhsVal == nil {
		return false
	}
	lhsStr := fmt.Sprintf("%v", lhsVal)
	pat := strings.TrimSpace(fmt.Sprintf("%v", rhsVal))
	if len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
		pat = strings.ReplaceAll(pat[1:len(pat)-1], `\/`, `/`)
	}
	if fullMatch {
		pat = "^(?:" + pat + ")$"
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return false
	}
	return re.MatchString(lhsStr)
}

func evalConditionDepth(sourceMap map[string]any, cond string, params map[string]any, depth int) bool {
	if depth > 64 {
		return false
	}
	cond = trimBalancedParens(expandDynamicBrackets(cond, sourceMap, params, depth+1))
	if cond == "" || cond == "false" {
		return false
	}
	if cond == "true" {
		return true
	}
	if parts := splitTopLevelCondOp(cond, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalConditionDepth(sourceMap, p, params, depth+1) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelCondOp(cond, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalConditionDepth(sourceMap, p, params, depth+1) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(cond, "!") && !strings.HasPrefix(cond, "!=") {
		return !evalConditionDepth(sourceMap, cond[1:], params, depth+1)
	}

	if idx := findTopLevelOpPainless(cond, "==~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+3:])
		var rhs any = rhsRaw
		if len(rhsRaw) < 2 || rhsRaw[0] != '/' || rhsRaw[len(rhsRaw)-1] != '/' {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, true)
	}
	if idx := findTopLevelOpPainless(cond, "=~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		var rhs any = rhsRaw
		if len(rhsRaw) < 2 || rhsRaw[0] != '/' || rhsRaw[len(rhsRaw)-1] != '/' {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, false)
	}
	if idx := findTopLevelOpPainless(cond, "!=="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+3:]), params, depth+1)
		return !valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "==="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+3:]), params, depth+1)
		return valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "!="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+2:]), params, depth+1)
		return !valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "=="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+2:]), params, depth+1)
		return valuesEqual(lhs, rhs)
	}
	for _, op := range []string{">=", "<=", ">", "<"} {
		if idx := findTopLevelOpPainless(cond, op); idx > 0 {
			lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
			rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+len(op):]), params, depth+1)
			return compareOrderedValues(lhs, rhs, op)
		}
	}
	if idx := findTopLevelOpPainless(cond, " instanceof "); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		typeName := strings.TrimSpace(cond[idx+len(" instanceof "):])
		return evalInstanceOfPainless(lhs, typeName)
	}

	// Check `.contains(...)`
	if recExpr, argExpr, ok := matchTrailingMethodCallPainless(cond, ".contains("); ok {
		lhsVal, _ := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
		switch tv := lhsVal.(type) {
		case []any:
			for _, item := range tv {
				if valuesEqual(item, argVal) {
					return true
				}
			}
		case string:
			if argVal != nil {
				return strings.Contains(tv, fmt.Sprintf("%v", argVal))
			}
		}
		return false
	}

	// Check `.startsWith(...)` and `.endsWith(...)`
	for _, mSpec := range []struct {
		name   string
		prefix bool
	}{
		{".startsWith(", true},
		{".endsWith(", false},
	} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(cond, mSpec.name); ok {
			lhsVal, _ := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
			if s, ok := lhsVal.(string); ok && argVal != nil {
				sub := fmt.Sprintf("%v", argVal)
				if mSpec.prefix {
					return strings.HasPrefix(s, sub)
				}
				return strings.HasSuffix(s, sub)
			}
			return false
		}
	}

	// Check `.isEmpty()`
	if strings.HasSuffix(cond, ".isEmpty()") {
		lhsExpr := strings.TrimSpace(strings.TrimSuffix(cond[:len(cond)-len(".isEmpty()")], "?"))
		lhsVal, _ := evalRHSExprDepth(sourceMap, lhsExpr, params, depth+1)
		switch tv := lhsVal.(type) {
		case string:
			return len(tv) == 0
		case []any:
			return len(tv) == 0
		case map[string]any:
			return len(tv) == 0
		}
		return false
	}

	// Check `.containsKey(...)`
	if recExpr, argExpr, ok := matchTrailingMethodCallPainless(cond, ".containsKey("); ok {
		lhsVal, _ := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
		if m, ok := lhsVal.(map[string]any); ok {
			_, exists := m[fmt.Sprintf("%v", argVal)]
			return exists
		}
		return false
	}

	val, _ := evalRHSExprDepth(sourceMap, cond, params, depth+1)
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
	return evalRHSExprDepth(sourceMap, rhs, params, 0)
}

func evalRHSExprDepth(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("painless expression exceeded maximum recursion depth (64)")
	}
	rhs = trimBalancedParens(expandDynamicBrackets(rhs, sourceMap, params, depth+1))

	// Check Elvis operator `?:`
	if elvisIdx := findTopLevelOpPainless(rhs, "?:"); elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[:elvisIdx]), params, depth+1)
		if err != nil {
			return nil, err
		}
		if leftVal != nil && leftVal != false && leftVal != "" {
			return leftVal, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[elvisIdx+2:]), params, depth+1)
	}

	// Check ternary `cond ? trueExpr : falseExpr`
	if qIdx := findTopLevelOpPainless(rhs, "?"); qIdx > 0 {
		rest := rhs[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			condStr := strings.TrimSpace(rhs[:qIdx])
			if evalConditionDepth(sourceMap, condStr, params, depth+1) {
				return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}

	// Check boolean logical, relational, or regex operators on RHS (`||`, `&&`, `=~`, `==~`, `==`, `!=`, `>=`, `<=`, `>`, `<`, `!`)
	if hasTopLevelBooleanOrRegexOp(rhs) {
		return evalConditionDepth(sourceMap, rhs, params, depth+1), nil
	}

	// Check binary `+` or `-` outside quotes
	if opIdx, isAdd := findTopLevelAddSub(rhs); opIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, rhs[:opIdx], params, depth+1)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, rhs[opIdx+1:], params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(leftVal, rightVal, isAdd), nil
	}
	if opIdx, opCh := findTopLevelMulDiv(rhs); opIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, rhs[:opIdx], params, depth+1)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, rhs[opIdx+1:], params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyMulDiv(leftVal, rightVal, opCh), nil
	}
	if strings.HasPrefix(rhs, "-") && len(rhs) > 1 && (rhs[1] < '0' || rhs[1] > '9') {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, false), nil
	}

	// Check trailing zero-arg methods `.toLowerCase()`, `.toUpperCase()`, `.trim()`, `.length()`, `.size()`
	for _, mSuffix := range []string{".toLowerCase()", ".toUpperCase()", ".trim()", ".length()", ".size()"} {
		if strings.HasSuffix(rhs, mSuffix) {
			recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(mSuffix)], "?"))
			recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			if err != nil || recVal == nil {
				return nil, err
			}
			switch mSuffix {
			case ".toLowerCase()":
				return strings.ToLower(fmt.Sprintf("%v", recVal)), nil
			case ".toUpperCase()":
				return strings.ToUpper(fmt.Sprintf("%v", recVal)), nil
			case ".trim()":
				return strings.TrimSpace(fmt.Sprintf("%v", recVal)), nil
			case ".length()", ".size()":
				switch tv := recVal.(type) {
				case string:
					return int64(len(tv)), nil
				case []any:
					return int64(len(tv)), nil
				case map[string]any:
					return int64(len(tv)), nil
				}
			}
		}
	}

	if strings.HasSuffix(rhs, ".isEmpty()") {
		recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(".isEmpty()")], "?"))
		recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil || recVal == nil {
			return nil, err
		}
		switch tv := recVal.(type) {
		case string:
			return len(tv) == 0, nil
		case []any:
			return len(tv) == 0, nil
		case map[string]any:
			return len(tv) == 0, nil
		}
		return false, nil
	}

	for _, mName := range []string{".startsWith(", ".endsWith(", ".contains(", ".containsKey(", ".get(", ".indexOf(", ".split(", ".replace(", ".substring("} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(rhs, mName); ok {
			recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			if err != nil || recVal == nil {
				return nil, err
			}
			switch mName {
			case ".replace(":
				args := splitTopLevelCommaPainless(argExpr)
				if len(args) == 2 {
					oldVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					newVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if s, ok := recVal.(string); ok && oldVal != nil && newVal != nil {
						return strings.ReplaceAll(s, fmt.Sprintf("%v", oldVal), fmt.Sprintf("%v", newVal)), nil
					}
				}
				return recVal, nil
			case ".substring(":
				args := splitTopLevelCommaPainless(argExpr)
				if s, ok := recVal.(string); ok && len(args) >= 1 {
					startVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					sf, sOk := toFloat64(startVal)
					if !sOk {
						return s, nil
					}
					start := int(sf)
					if start < 0 {
						start = 0
					}
					if start > len(s) {
						start = len(s)
					}
					end := len(s)
					if len(args) >= 2 {
						endVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if ef, eOk := toFloat64(endVal); eOk {
							end = int(ef)
							if end < start {
								end = start
							}
							if end > len(s) {
								end = len(s)
							}
						}
					}
					return s[start:end], nil
				}
				return recVal, nil
			}
			argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
			switch mName {
			case ".startsWith(":
				if s, ok := recVal.(string); ok && argVal != nil {
					return strings.HasPrefix(s, fmt.Sprintf("%v", argVal)), nil
				}
				return false, nil
			case ".endsWith(":
				if s, ok := recVal.(string); ok && argVal != nil {
					return strings.HasSuffix(s, fmt.Sprintf("%v", argVal)), nil
				}
				return false, nil
			case ".contains(":
				switch tv := recVal.(type) {
				case []any:
					for _, item := range tv {
						if valuesEqual(item, argVal) {
							return true, nil
						}
					}
				case string:
					if argVal != nil {
						return strings.Contains(tv, fmt.Sprintf("%v", argVal)), nil
					}
				}
				return false, nil
			case ".containsKey(":
				if m, ok := recVal.(map[string]any); ok && argVal != nil {
					_, exists := m[fmt.Sprintf("%v", argVal)]
					return exists, nil
				}
				return false, nil
			case ".get(":
				switch tv := recVal.(type) {
				case map[string]any:
					if argVal != nil {
						return tv[fmt.Sprintf("%v", argVal)], nil
					}
				case []any:
					if f, ok := toFloat64(argVal); ok {
						if idx, okIdx := parseSliceIndex(strconv.Itoa(int(f)), len(tv)); okIdx {
							return tv[idx], nil
						}
					}
				}
				return nil, nil
			case ".indexOf(":
				switch tv := recVal.(type) {
				case string:
					if argVal != nil {
						return int64(strings.Index(tv, fmt.Sprintf("%v", argVal))), nil
					}
				case []any:
					for idx, item := range tv {
						if valuesEqual(item, argVal) {
							return int64(idx), nil
						}
					}
				}
				return int64(-1), nil
			case ".split(":
				if s, ok := recVal.(string); ok && argVal != nil {
					sepStr := fmt.Sprintf("%v", argVal)
					var parts []string
					if re, err := regexp.Compile(sepStr); err == nil && sepStr != "." && sepStr != "" {
						parts = re.Split(s, -1)
					} else {
						parts = strings.Split(s, sepStr)
					}
					out := make([]any, len(parts))
					for i, p := range parts {
						out[i] = p
					}
					return out, nil
				}
				return []any{}, nil
			}
		}
	}

	if callExpr, tailPath, ok := splitPostCallPropertyAccess(rhs); ok {
		callVal, err := evalRHSExprDepth(sourceMap, callExpr, params, depth+1)
		if err != nil || callVal == nil {
			return nil, err
		}
		return resolveParamPath(map[string]any{"_v": callVal}, append([]string{"_v"}, strings.Split(tailPath, ".")...)), nil
	}

	if rhs == "ctx._source" || rhs == "ctx?._source" {
		return sourceMap, nil
	}
	if strings.HasPrefix(rhs, "ctx._source.") || strings.HasPrefix(rhs, "ctx._source?.") ||
		strings.HasPrefix(rhs, "ctx?._source.") || strings.HasPrefix(rhs, "ctx?._source?.") {
		trimmed := rhs
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(trimmed, pfx) {
				trimmed = strings.TrimPrefix(trimmed, pfx)
				break
			}
		}
		path := strings.Split(trimmed, ".")
		return resolveParamPath(sourceMap, path), nil
	}
	if strings.HasPrefix(rhs, "doc.") || strings.HasPrefix(rhs, "doc?.") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "doc?."), "doc.")
		trimmed = strings.TrimSuffix(trimmed, ".value")
		path := strings.Split(trimmed, ".")
		val := resolveParamPath(sourceMap, path)
		if val == nil && (strings.HasSuffix(trimmed, ".keyword") || strings.HasSuffix(trimmed, "\x00keyword")) {
			kwTrimmed := strings.TrimSuffix(strings.TrimSuffix(trimmed, ".keyword"), "\x00keyword")
			val = resolveParamPath(sourceMap, strings.Split(kwTrimmed, "."))
		}
		return val, nil
	}
	if rhs == "params" {
		return params, nil
	}
	if strings.HasPrefix(rhs, "params.") || strings.HasPrefix(rhs, "params?.") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "params?."), "params.")
		paramPath := strings.Split(trimmed, ".")
		return resolveParamPath(params, paramPath), nil
	}
	if val, ok := params[decodeBracketSeg(rhs)]; ok {
		return val, nil
	}
	if dotIdx := strings.IndexByte(rhs, '.'); dotIdx > 0 {
		firstSeg := decodeBracketSeg(rhs[:dotIdx])
		if _, ok := params[firstSeg]; ok {
			return resolveParamPath(params, strings.Split(rhs, ".")), nil
		}
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
	if strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, "]") && findMatchingDelimiter(rhs, 0, '[', ']') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[1 : len(rhs)-1])
		if inner != "" {
			items := splitTopLevelCommaPainless(inner)
			if len(items) > 0 && findTopLevelOpPainless(items[0], ":") > 0 {
				mOut := make(map[string]any, len(items))
				for _, entry := range items {
					cIdx := findTopLevelOpPainless(entry, ":")
					if cIdx <= 0 {
						continue
					}
					kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(entry[:cIdx]), params, depth+1)
					if err != nil {
						return nil, err
					}
					vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(entry[cIdx+1:]), params, depth+1)
					if err != nil {
						return nil, err
					}
					mOut[fmt.Sprintf("%v", kVal)] = vVal
				}
				return mOut, nil
			}
			listOut := make([]any, 0, len(items))
			for _, itemExpr := range items {
				vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(itemExpr), params, depth+1)
				if err != nil {
					return nil, err
				}
				listOut = append(listOut, vVal)
			}
			return listOut, nil
		}
	}
	if (strings.HasPrefix(rhs, "'") && strings.HasSuffix(rhs, "'")) ||
		(strings.HasPrefix(rhs, `"`) && strings.HasSuffix(rhs, `"`)) {
		if len(rhs) >= 2 {
			return unescapePainlessString(rhs[1 : len(rhs)-1]), nil
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

func matchTrailingMethodCallPainless(s, mName string) (recExpr, argExpr string, ok bool) {
	if !strings.HasSuffix(s, ")") || len(s) <= len(mName) {
		return "", "", false
	}
	openParenIdx := -1
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == '(' || ch == '[' {
			if depth == 0 && ch == '(' {
				openParenIdx = i
			}
			depth++
			continue
		}
		if ch == ')' || ch == ']' {
			depth--
			if depth == 0 && i < len(s)-1 {
				openParenIdx = -1
			}
		}
	}
	if depth != 0 || openParenIdx <= 0 {
		return "", "", false
	}
	prefix := s[:openParenIdx+1]
	if !strings.HasSuffix(prefix, mName) {
		return "", "", false
	}
	idx := len(prefix) - len(mName)
	if idx <= 0 {
		return "", "", false
	}
	recExpr = strings.TrimSpace(strings.TrimSuffix(s[:idx], "?"))
	argExpr = strings.TrimSpace(s[openParenIdx+1 : len(s)-1])
	return recExpr, argExpr, recExpr != ""
}

func splitTopLevelCommaPainless(s string) []string {
	var parts []string
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[lastStart:i])
				lastStart = i + 1
			}
		}
	}
	if strings.TrimSpace(s[lastStart:]) != "" {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func unescapePainlessString(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case '\'':
				sb.WriteByte('\'')
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			default:
				sb.WriteByte('\\')
				sb.WriteByte(s[i])
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func hasTopLevelBooleanOrRegexOp(s string) bool {
	if strings.HasPrefix(s, "!") && !strings.HasPrefix(s, "!=") {
		return true
	}
	if len(splitTopLevelCondOp(s, "||")) > 1 || len(splitTopLevelCondOp(s, "&&")) > 1 {
		return true
	}
	for _, op := range []string{"==~", "=~", "===", "!==", "==", "!=", ">=", "<=", ">", "<", " instanceof "} {
		if findTopLevelOpPainless(s, op) > 0 {
			return true
		}
	}
	return false
}

func findTopLevelAddSub(expr string) (int, bool) {
	inQuotes := byte(0)
	inRegexClass := false
	depth := 0
	lastIdx := -1
	lastIsAdd := false
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
		case '+', '-':
			if depth == 0 && i > 0 {
				if (expr[i-1] == 'e' || expr[i-1] == 'E') && i >= 2 && ((expr[i-2] >= '0' && expr[i-2] <= '9') || expr[i-2] == '.') {
					continue
				}
				prev := strings.TrimSpace(expr[:i])
				if len(prev) > 0 {
					lastChar := prev[len(prev)-1]
					if lastChar != '+' && lastChar != '-' && lastChar != '*' && lastChar != '/' && lastChar != '(' &&
						lastChar != ',' && lastChar != '?' && lastChar != ':' && lastChar != '=' && lastChar != '<' && lastChar != '>' && lastChar != '!' && lastChar != '~' {
						lastIdx = i
						lastIsAdd = c == '+'
					}
				}
			}
		}
	}
	return lastIdx, lastIsAdd
}

func findTopLevelMulDiv(expr string) (int, byte) {
	inQuotes := byte(0)
	inRegexClass := false
	depth := 0
	lastIdx := -1
	lastOp := byte(0)
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
		case '*', '/', '%':
			if depth == 0 && i > 0 {
				lastIdx = i
				lastOp = c
			}
		}
	}
	return lastIdx, lastOp
}

func applyMulDiv(a, b any, op byte) any {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		var res float64
		switch op {
		case '*':
			res = af * bf
		case '/':
			if bf != 0 {
				res = af / bf
			}
		case '%':
			if bf != 0 {
				res = math.Mod(af, bf)
			}
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
	inRegexClass := false
	for i := openIdx; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
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
	inRegexClass := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			curr.WriteByte(c)
			continue
		}
		switch c {
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

func parseSliceIndex(seg string, length int) (int, bool) {
	idx, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	if idx < 0 {
		idx = length + idx
	}
	if idx < 0 || idx >= length {
		return 0, false
	}
	return idx, true
}

func resolveParamPath(params map[string]any, path []string) any {
	var curr any = params
	for i, rawSeg := range path {
		seg := decodeBracketSeg(rawSeg)
		if slice, isSlice := curr.([]any); isSlice {
			idx, ok := parseSliceIndex(seg, len(slice))
			if !ok {
				return nil
			}
			curr = slice[idx]
			continue
		}
		m, ok := curr.(map[string]any)
		if !ok {
			return nil
		}
		val, exists := m[seg]
		if !exists {
			if strings.Contains(seg, ".") {
				subCurr := any(m)
				for _, subSeg := range strings.Split(seg, ".") {
					sm, sok := subCurr.(map[string]any)
					if !sok {
						subCurr = nil
						break
					}
					subCurr = sm[subSeg]
				}
				val = subCurr
			} else if i < len(path)-1 {
				decodedRest := make([]string, len(path)-i)
				for j := i; j < len(path); j++ {
					decodedRest[j-i] = decodeBracketSeg(path[j])
				}
				if flatVal, flatOk := m[strings.Join(decodedRest, ".")]; flatOk {
					return flatVal
				}
			}
		}
		curr = val
	}
	return curr
}

func setValueAtPath(root map[string]any, path []string, val any) {
	if len(path) == 0 {
		return
	}
	if len(path) > 1 {
		decoded := make([]string, len(path))
		for i, p := range path {
			decoded[i] = decodeBracketSeg(p)
		}
		delete(root, strings.Join(decoded, "."))
	}
	var curr any = root
	for i := 0; i < len(path)-1; i++ {
		seg := decodeBracketSeg(path[i])
		switch node := curr.(type) {
		case map[string]any:
			next, exists := node[seg]
			if !exists || next == nil {
				nextMap := make(map[string]any)
				node[seg] = nextMap
				curr = nextMap
				continue
			}
			if _, isMap := next.(map[string]any); isMap {
				curr = next
				continue
			}
			if _, isSlice := next.([]any); isSlice {
				curr = next
				continue
			}
			nextMap := make(map[string]any)
			node[seg] = nextMap
			curr = nextMap
		case []any:
			idx, ok := parseSliceIndex(seg, len(node))
			if !ok {
				return
			}
			if node[idx] == nil {
				node[idx] = make(map[string]any)
			}
			curr = node[idx]
		default:
			return
		}
	}
	lastSeg := decodeBracketSeg(path[len(path)-1])
	switch node := curr.(type) {
	case map[string]any:
		node[lastSeg] = val
	case []any:
		if idx, ok := parseSliceIndex(lastSeg, len(node)); ok {
			node[idx] = val
		}
	}
}

func splitTopLevelSemicolonPainless(s string) []string {
	var parts []string
	depth := 0
	var quote byte
	last := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	parts = append(parts, s[last:])
	return parts
}

func evalInstanceOfPainless(val any, typeName string) bool {
	if val == nil {
		return false
	}
	switch typeName {
	case "List", "ArrayList":
		_, ok := val.([]any)
		return ok
	case "Map", "HashMap":
		_, ok := val.(map[string]any)
		return ok
	case "String":
		_, ok := val.(string)
		return ok
	case "Boolean", "boolean":
		_, ok := val.(bool)
		return ok
	case "Number", "Integer", "Long", "Double", "Float", "int", "long", "double", "float":
		switch val.(type) {
		case int, int64, float64, json.Number:
			return true
		default:
			return false
		}
	case "Object", "def":
		return true
	default:
		return false
	}
}

func splitPostCallPropertyAccess(s string) (callExpr, tailPath string, ok bool) {
	depth := 0
	var quote byte
	lastCallEnd := -1
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == '(' || ch == '[' {
			depth++
			continue
		}
		if ch == ')' || ch == ']' {
			if depth > 0 {
				depth--
			}
			if depth == 0 && ch == ')' && i+1 < len(s) {
				if s[i+1] == '.' || (i+2 < len(s) && s[i+1:i+3] == "?.") {
					lastCallEnd = i
				}
			}
		}
	}
	if depth != 0 || lastCallEnd <= 0 || lastCallEnd >= len(s)-1 {
		return "", "", false
	}
	rest := s[lastCallEnd+1:]
	rest = strings.TrimPrefix(rest, "?")
	rest = strings.TrimPrefix(rest, ".")
	if rest == "" || strings.ContainsAny(rest, "(),+-*/?:=!<>|& ") {
		return "", "", false
	}
	rest = strings.ReplaceAll(rest, "?.", ".")
	return strings.TrimSpace(s[:lastCallEnd+1]), rest, true
}

func putAllAtPath(root map[string]any, path []string, values map[string]any) {
	if len(path) == 0 {
		for k, v := range values {
			root[k] = v
		}
		return
	}
	if existing, ok := resolveParamPath(root, path).(map[string]any); ok && existing != nil {
		for k, v := range values {
			existing[k] = v
		}
		return
	}
	cp := make(map[string]any, len(values))
	for k, v := range values {
		cp[k] = v
	}
	setValueAtPath(root, path, cp)
}

func removeKeyOrIndexAtPath(root map[string]any, parentPath []string, keyOrIdx any) {
	if len(parentPath) == 0 {
		delete(root, fmt.Sprintf("%v", keyOrIdx))
		return
	}
	switch target := resolveParamPath(root, parentPath).(type) {
	case map[string]any:
		delete(target, fmt.Sprintf("%v", keyOrIdx))
	case []any:
		if _, isStr := keyOrIdx.(string); !isStr {
			if idx, ok := parseSliceIndex(fmt.Sprintf("%v", keyOrIdx), len(target)); ok {
				setValueAtPath(root, parentPath, append(target[:idx], target[idx+1:]...))
				return
			}
		}
		for idx, elem := range target {
			if valuesEqual(elem, keyOrIdx) {
				setValueAtPath(root, parentPath, append(target[:idx], target[idx+1:]...))
				break
			}
		}
	}
}

func appendToSlice(root map[string]any, path []string, val any) error {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	setValueAtPath(root, path, append(existing, val))
	return nil
}

func removeIfFromSlice(root map[string]any, arrPath []string, propPath []string, matchVal any) {
	existing, ok := resolveParamPath(root, arrPath).([]any)
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
	setValueAtPath(root, arrPath, filtered)
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
