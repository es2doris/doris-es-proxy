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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	DetectNoop     *bool          `json:"detect_noop,omitempty"`
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
	reCtxOp                = regexp.MustCompile(`(?s)^ctx\??\.op\s*=\s*(.+)$`)
	reCtxIncDec            = regexp.MustCompile(`^(?:(\+\+|--)\s*ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)|ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\s*(\+\+|--))$`)
	reCompoundAssign       = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reAssignParam          = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\s*=\s*(.+)$`)
	reRemoveField          = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+))?\.remove\(\s*(.+?)\s*\)$`)
	reClearField           = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+))?\.clear\(\s*\)$`)
	reArrayAdd             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.add\(\s*(.+?)\s*\)$`)
	reArraySet             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.set\(\s*(.+)\s*\)$`)
	reArrayAddAll          = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.addAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.removeAll\(\s*(.+?)\s*\)$`)
	reArrayRetainAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.retainAll\(\s*(.+?)\s*\)$`)
	reMapPut               = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+))?\.put\(\s*(.+)\s*\)$`)
	reMapPutAll            = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+))?\.putAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveIf        = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\.removeIf\(\s*\(?\s*([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalIncDec          = regexp.MustCompile(`^(?:(\+\+|--)\s*([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)|([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\s*(\+\+|--))$`)
	reLocalRemoveField     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.remove\(\s*(.+?)\s*\)$`)
	reLocalClearField      = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.clear\(\s*\)$`)
	reLocalArrayAdd        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.add\(\s*(.+?)\s*\)$`)
	reLocalArraySet        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.set\(\s*(.+)\s*\)$`)
	reLocalArrayAddAll     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.addAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.removeAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRetainAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.retainAll\(\s*(.+?)\s*\)$`)
	reLocalMapPut          = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.put\(\s*(.+)\s*\)$`)
	reLocalMapPutAll       = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.putAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveIf   = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\.removeIf\(\s*\(?\s*([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalCompoundAssign  = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)*)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reLocalPropAssign      = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+)\s*=\s*(.+)$`)
	reLocalVarAssign       = regexp.MustCompile(`(?s)^(?:(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)$`)
	reNullVarDecl          = regexp.MustCompile(`^(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)$`)
	reSimpleFieldPath      = regexp.MustCompile(`^[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x15-]+$`)
	reNumericLiteralSuffix = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[lLdDfF]$`)
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

	detectNoop := req.DetectNoop == nil || *req.DetectNoop
	var preMergeSnapshot []byte
	if docExisted && detectNoop && len(req.Doc) > 0 && (req.Script == nil || strings.TrimSpace(req.Script.Source) == "") {
		preMergeSnapshot, _ = json.Marshal(doc)
	}

	if len(req.Doc) > 0 && (docExisted || !req.ScriptedUpsert) {
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
			return rawSource, "noop", nil
		case "delete", "drop":
			opResult = "deleted"
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	if len(preMergeSnapshot) > 0 && bytes.Equal(preMergeSnapshot, out) {
		return rawSource, "noop", nil
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

// Eval evaluates a Painless script expression or multi-statement block and returns its result value.
func Eval(sourceMap map[string]any, scriptSource string, params map[string]any) (any, error) {
	evalParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		evalParams[k] = v
	}
	if sourceMap != nil && evalParams["_source"] == nil {
		evalParams["_source"] = sourceMap
	}
	cleaned := strings.TrimSpace(stripPainlessComments(scriptSource))
	if cleaned == "" {
		return nil, nil
	}
	ctxOp := ""
	budget := &evalBudget{}
	stmts := splitTopLevelStatements(cleaned)
	err := execBlock(sourceMap, cleaned, evalParams, &ctxOp, budget)
	if err != nil && !errors.Is(err, errPainlessReturn) {
		return nil, err
	}
	if retVal, hasRet := evalParams["_return_val"]; hasRet {
		return retVal, nil
	}
	if len(stmts) > 0 {
		lastStmt := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmts[len(stmts)-1]), ";"))
		if strings.HasPrefix(lastStmt, "return ") || strings.HasPrefix(lastStmt, "return(") {
			lastStmt = strings.TrimSpace(strings.TrimPrefix(lastStmt, "return"))
		}
		if lastStmt != "" && lastStmt != "return" && !strings.HasPrefix(lastStmt, "if ") && !strings.HasPrefix(lastStmt, "if(") && !strings.HasPrefix(lastStmt, "for ") && !strings.HasPrefix(lastStmt, "for(") && !strings.HasPrefix(lastStmt, "while ") && !strings.HasPrefix(lastStmt, "while(") && !isTopLevelAssignmentStmt(lastStmt) {
			if lastVal, hasLast := evalParams["_last_expr_val"]; hasLast {
				return lastVal, nil
			}
			val, evalErr := evalRHSExpr(sourceMap, lastStmt, evalParams)
			if evalErr == nil && (val != nil || findTopLevelOpPainless(lastStmt, "?") > 0 || findTopLevelOpPainless(lastStmt, "?:") > 0) {
				return val, nil
			}
			if strings.ContainsAny(lastStmt, "><=!&|") || strings.Contains(lastStmt, ".empty") || strings.Contains(lastStmt, ".contains(") || strings.Contains(lastStmt, ".startsWith(") || strings.Contains(lastStmt, ".endsWith(") || strings.Contains(lastStmt, ".isEmpty()") || strings.Contains(lastStmt, ".matches(") || strings.Contains(lastStmt, ".containsKey(") || strings.Contains(lastStmt, ".equals(") || strings.Contains(lastStmt, ".equalsIgnoreCase(") {
				return evalCondition(sourceMap, lastStmt, evalParams), nil
			}
		}
	}
	return nil, nil
}

func isTopLevelAssignmentStmt(s string) bool {
	depth := 0
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
		case '=':
			if depth == 0 {
				if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '~') {
					i++
					continue
				}
				if i > 0 && (s[i-1] == '=' || s[i-1] == '!') {
					continue
				}
				if i > 0 && s[i-1] == '<' && (i < 2 || s[i-2] != '<') {
					continue
				}
				if i > 0 && s[i-1] == '>' && (i < 2 || s[i-2] != '>') {
					continue
				}
				return true
			}
		}
	}
	return false
}

// EvalNumber evaluates a Painless script and coerces the result to float64.
func EvalNumber(sourceMap map[string]any, scriptSource string, params map[string]any) (float64, bool, error) {
	val, err := Eval(sourceMap, scriptSource, params)
	if err != nil || val == nil {
		return 0, false, err
	}
	f, ok := toFloat64(val)
	return f, ok, nil
}

// EvalFilter evaluates a boolean Painless filter script (`script` query or `bucket_selector`).
func EvalFilter(sourceMap map[string]any, scriptSource string, params map[string]any) (bool, error) {
	val, err := Eval(sourceMap, scriptSource, params)
	if err != nil {
		return false, err
	}
	switch v := val.(type) {
	case bool:
		return v, nil
	case nil:
		return false, nil
	default:
		if f, ok := toFloat64(v); ok {
			return f != 0, nil
		}
		return fmt.Sprintf("%v", v) == "true", nil
	}
}

// EvalPainless evaluates common Painless script statements used by OpenMetadata and DataHub
// against `sourceMap` (`ctx._source`) with `params`.
func EvalPainless(sourceMap map[string]any, scriptSource string, params map[string]any) error {
	_, err := EvalPainlessWithOp(sourceMap, scriptSource, params)
	return err
}

// EvalPainlessWithOp evaluates a Painless script and returns any `ctx.op` set by the script.
func EvalPainlessWithOp(sourceMap map[string]any, scriptSource string, params map[string]any) (string, error) {
	evalParams := make(map[string]any, len(params)+4)
	for k, v := range params {
		evalParams[k] = v
	}
	if sourceMap != nil {
		if _, exists := evalParams["_source"]; !exists {
			evalParams["_source"] = sourceMap
		}
	}
	ctxOp := ""
	budget := &evalBudget{}
	cleaned := stripPainlessComments(scriptSource)
	err := execBlock(sourceMap, cleaned, evalParams, &ctxOp, budget)
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
		if strings.HasPrefix(stmt, "while") && (len(stmt) == 5 || stmt[5] == ' ' || stmt[5] == '(') {
			if err := execWhileStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
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

func execWhileStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	cond := strings.TrimSpace(stmt[openParen+1 : closeParen])
	body := strings.TrimSpace(stmt[closeParen+1:])
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = body[1 : len(body)-1]
	}
	for {
		if err := budget.step(); err != nil {
			return err
		}
		if cond != "" && !evalCondition(sourceMap, cond, params) {
			break
		}
		if err := execBlock(sourceMap, body, params, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				break
			}
			if errors.Is(err, errPainlessContinue) {
				continue
			}
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
	if clauses := splitTopLevelSemicolonPainless(header); len(clauses) == 3 {
		preExistingKeys := make(map[string]bool, len(params))
		loopParams := make(map[string]any, len(params)+2)
		for k, v := range params {
			preExistingKeys[k] = true
			loopParams[k] = v
		}
		initVars := make(map[string]bool)
		if initStmt := strings.TrimSpace(clauses[0]); initStmt != "" {
			for _, subInit := range splitTopLevelCommaPainless(initStmt) {
				subInit = strings.TrimSpace(subInit)
				if subInit == "" {
					continue
				}
				if m := reLocalVarAssign.FindStringSubmatch(subInit); m != nil {
					if _, existed := params[m[1]]; !existed {
						initVars[m[1]] = true
					}
				}
				if err := execSimpleStmt(sourceMap, subInit, loopParams, ctxOp, budget); err != nil {
					return err
				}
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
				for _, subPost := range splitTopLevelCommaPainless(postStmt) {
					subPost = strings.TrimSpace(subPost)
					if subPost == "" {
						continue
					}
					if err := execSimpleStmt(sourceMap, subPost, loopParams, ctxOp, budget); err != nil {
						loopErr = err
						break
					}
				}
				if loopErr != nil {
					break
				}
			}
		}
		for k, v := range loopParams {
			if (preExistingKeys[k] && !initVars[k]) || k == "_return_val" || k == "_ctx_op" {
				params[k] = v
			} else if strings.HasPrefix(k, "__alias_") {
				baseVar := strings.TrimPrefix(k, "__alias_")
				if preExistingKeys[baseVar] && !initVars[baseVar] {
					params[k] = v
				}
			}
		}
		for k := range preExistingKeys {
			if strings.HasPrefix(k, "__alias_") {
				baseVar := strings.TrimPrefix(k, "__alias_")
				if !initVars[baseVar] {
					if _, stillExists := loopParams[k]; !stillExists {
						delete(params, k)
					}
				}
			}
		}
		return loopErr
	} else if idx, sepLen := findTopLevelForInOrColon(header); idx >= 0 {
		varName = strings.TrimSpace(header[:idx])
		iterExpr = strings.TrimSpace(header[idx+sepLen:])
	} else {
		return nil
	}
	if closeIdx := strings.LastIndexAny(varName, ">]"); closeIdx >= 0 && closeIdx+1 < len(varName) {
		varName = strings.TrimSpace(varName[closeIdx+1:])
	}
	fields := strings.Fields(varName)
	if len(fields) > 0 {
		varName = fields[len(fields)-1]
	}

	var iterVal any
	expIter := strings.TrimSpace(expandDynamicBrackets(iterExpr, sourceMap, params, 0))
	if (strings.HasPrefix(expIter, "doc.") || strings.HasPrefix(expIter, "doc?.")) &&
		!strings.HasSuffix(expIter, ".value") && !strings.Contains(expIter, ".value.") && !strings.Contains(expIter, ".values.") && !strings.Contains(expIter, "(") {
		docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expIter, "doc?."), "doc."), ".values")
		iterVal = resolveDocValuesSlice(sourceMap, docPath)
	} else {
		var err error
		iterVal, err = evalRHSExpr(sourceMap, iterExpr, params)
		if err != nil {
			return err
		}
	}
	slice, ok := iterVal.([]any)
	if !ok {
		if mVal, isMap := iterVal.(map[string]any); isMap {
			keys := make([]string, 0, len(mVal))
			for k := range mVal {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			slice = make([]any, len(keys))
			for i, k := range keys {
				slice[i] = map[string]any{"key": k, "value": mVal[k], "__parent_map": mVal}
			}
		} else {
			return nil
		}
	}
	// Copy slice header + elements so in-loop mutations do not mutate the iteration snapshot
	snapshot := make([]any, len(slice))
	copy(snapshot, slice)

	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		preExistingKeys[k] = true
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
		if (preExistingKeys[k] && k != varName) || k == "_return_val" || k == "_ctx_op" {
			params[k] = v
		} else if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if preExistingKeys[baseVar] && baseVar != varName {
				params[k] = v
			}
		}
	}
	for k := range preExistingKeys {
		if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if baseVar != varName {
				if _, stillExists := loopParams[k]; !stillExists {
					delete(params, k)
				}
			}
		}
	}
	return loopErr
}

func findTopLevelForInOrColon(header string) (int, int) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	colonIdx := -1
	for i := 0; i < len(header); i++ {
		if stepQuoteState(header, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch header[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				if strings.HasPrefix(header[i:], " in ") {
					return i, 4
				}
				if header[i] == ':' && colonIdx < 0 {
					colonIdx = i
				}
			}
		}
	}
	if colonIdx >= 0 {
		return colonIdx, 1
	}
	return -1, 0
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

func isBracketReceiverByte(c byte) bool {
	return isIdentByte(c) || c == ']' || c == ')' || c == '?' || (c >= '\x00' && c <= '\x08') || (c >= '\x10' && c <= '\x15')
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
		case '+':
			out.WriteByte('\x05')
		case '*':
			out.WriteByte('\x06')
		case '%':
			out.WriteByte('\x07')
		case '?':
			out.WriteByte('\x08')
		case '!':
			out.WriteByte('\x10')
		case '=':
			out.WriteByte('\x11')
		case '<':
			out.WriteByte('\x12')
		case '>':
			out.WriteByte('\x13')
		case '&':
			out.WriteByte('\x14')
		case '|':
			out.WriteByte('\x15')
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
	seg = strings.ReplaceAll(seg, "\x05", "+")
	seg = strings.ReplaceAll(seg, "\x06", "*")
	seg = strings.ReplaceAll(seg, "\x07", "%")
	seg = strings.ReplaceAll(seg, "\x08", "?")
	seg = strings.ReplaceAll(seg, "\x10", "!")
	seg = strings.ReplaceAll(seg, "\x11", "=")
	seg = strings.ReplaceAll(seg, "\x12", "<")
	seg = strings.ReplaceAll(seg, "\x13", ">")
	seg = strings.ReplaceAll(seg, "\x14", "&")
	seg = strings.ReplaceAll(seg, "\x15", "|")
	return seg
}

func findNextUnquotedSubstr(s, sub string, from int) int {
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		if i >= from && strings.HasPrefix(s[i:], sub) {
			return i
		}
	}
	return -1
}

func expandDynamicBrackets(s string, sourceMap map[string]any, params map[string]any, depth int) string {
	if (strings.IndexByte(s, '[') < 0 && !strings.Contains(s, ".get(")) || depth > 64 {
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
	res := out.String()
	searchFrom := 0
	for {
		getIdx := findNextUnquotedSubstr(res, ".get(", searchFrom)
		if getIdx < 0 {
			break
		}
		openParen := getIdx + 4
		closeParen := findMatchingDelimiter(res, openParen, '(', ')')
		if closeParen <= openParen {
			break
		}
		after := strings.TrimSpace(res[closeParen+1:])
		isChainedOrAssign := false
		if after != "" {
			if after[0] == '.' || strings.HasPrefix(after, "?.") ||
				strings.HasPrefix(after, "+=") || strings.HasPrefix(after, "-=") ||
				strings.HasPrefix(after, "*=") || strings.HasPrefix(after, "/=") || strings.HasPrefix(after, "%=") ||
				strings.HasPrefix(after, "&=") || strings.HasPrefix(after, "|=") || strings.HasPrefix(after, "^=") ||
				strings.HasPrefix(after, "<<=") || strings.HasPrefix(after, ">>>=") || strings.HasPrefix(after, ">>=") ||
				strings.HasPrefix(after, "++") || strings.HasPrefix(after, "--") ||
				(after[0] == '=' && !strings.HasPrefix(after, "==") && !strings.HasPrefix(after, "=~")) {
				isChainedOrAssign = true
			}
		}
		if !isChainedOrAssign {
			recvStart := getIdx
			for recvStart > 0 && (isBracketReceiverByte(res[recvStart-1]) || res[recvStart-1] == '.') {
				recvStart--
			}
			before := strings.TrimSpace(res[:recvStart])
			if strings.HasSuffix(before, "++") || strings.HasSuffix(before, "--") {
				isChainedOrAssign = true
			}
		}
		if !isChainedOrAssign {
			searchFrom = closeParen + 1
			continue
		}
		inner := strings.TrimSpace(res[openParen+1 : closeParen])
		idxVal, err := evalRHSExprDepth(sourceMap, inner, params, depth+1)
		if err != nil || idxVal == nil {
			searchFrom = closeParen + 1
			continue
		}
		var keyStr string
		if strVal, isStr := idxVal.(string); isStr {
			keyStr = strVal
		} else if f, ok := toFloat64(idxVal); ok && f == float64(int64(f)) {
			keyStr = strconv.FormatInt(int64(f), 10)
		} else {
			keyStr = fmt.Sprintf("%v", idxVal)
		}
		if keyStr == "" {
			searchFrom = closeParen + 1
			continue
		}
		repl := "." + encodeBracketKey(keyStr)
		res = res[:getIdx] + repl + res[closeParen+1:]
		searchFrom = getIdx
	}
	return res
}

func normalizeLocalLHSPath(path []string, params map[string]any) []string {
	if len(path) >= 1 && decodeBracketSeg(path[0]) == "params" {
		if _, hasExplicit := params["params"]; !hasExplicit {
			return path[1:]
		}
	}
	return path
}

func normalizeIncDecPrevVal(v any) any {
	if jn, ok := v.(json.Number); ok {
		if iv, err := jn.Int64(); err == nil {
			return iv
		}
		if fv, err := jn.Float64(); err == nil {
			return fv
		}
	}
	if f, ok := toFloat64(v); ok {
		if f >= float64(math.MinInt64) && f < float64(math.MaxInt64) && f == float64(int64(f)) {
			return int64(f)
		}
		return f
	}
	return int64(0)
}

func syncLocalVarAlias(sourceMap map[string]any, params map[string]any, varName string) {
	if sourceMap == nil || params == nil || varName == "" {
		return
	}
	if aliasPath, ok := params["__alias_"+varName].(string); ok && aliasPath != "" {
		val := params[varName]
		switch val.(type) {
		case []any, map[string]any:
			setValueAtPath(sourceMap, strings.Split(aliasPath, "."), val)
		}
	}
}

func syncSourceAliasToLocalVars(sourceMap map[string]any, params map[string]any, targetPath string) {
	if sourceMap == nil || params == nil || targetPath == "" {
		return
	}
	for k, v := range params {
		if strings.HasPrefix(k, "__alias_") {
			if aliasPath, ok := v.(string); ok && aliasPath == targetPath {
				varName := strings.TrimPrefix(k, "__alias_")
				params[varName] = resolveParamPath(sourceMap, strings.Split(aliasPath, "."))
			}
		}
	}
}

func execSimpleStmt(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	delete(params, "_last_expr_val")
	stmt = strings.TrimSpace(expandDynamicBrackets(stmt, sourceMap, params, 0))
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") || strings.HasPrefix(stmt, "return(") {
		retExpr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(stmt, "return")), ";"))
		if retExpr == "" {
			params["_return_val"] = nil
			return errPainlessReturn
		}
		val, err := evalRHSExpr(sourceMap, retExpr, params)
		if err != nil {
			return err
		}
		params["_return_val"] = val
		return errPainlessReturn
	}
	if stmt == "break" {
		return errPainlessBreak
	}
	if stmt == "continue" {
		return errPainlessContinue
	}
	if m := reCtxOp.FindStringSubmatch(stmt); m != nil {
		val, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[1]), params)
		if err != nil {
			return err
		}
		if val == nil {
			*ctxOp = ""
		} else {
			*ctxOp = fmt.Sprintf("%v", val)
		}
		params["_ctx_op"] = *ctxOp
		return nil
	}
	if m := reCtxIncDec.FindStringSubmatch(stmt); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		pathStr := m[2]
		if op == "" {
			pathStr = m[3]
			op = m[4]
		}
		lhsPath := strings.Split(pathStr, ".")
		curVal := resolveParamPath(sourceMap, lhsPath)
		nextVal := applyArithmetic(curVal, int64(1), op == "++")
		setValueAtPath(sourceMap, lhsPath, nextVal)
		if isPrefix {
			params["_last_expr_val"] = nextVal
		} else {
			params["_last_expr_val"] = normalizeIncDecPrevVal(curVal)
		}
		return nil
	}
	if m := reLocalIncDec.FindStringSubmatch(stmt); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		lhs := m[2]
		if op == "" {
			lhs = m[3]
			op = m[4]
		}
		path := normalizeLocalLHSPath(strings.Split(lhs, "."), params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if isPrefix {
				params["_last_expr_val"] = nextVal
			} else {
				params["_last_expr_val"] = normalizeIncDecPrevVal(curVal)
			}
			if len(path) > 1 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
			}
		}
		return nil
	}

	// 1. Check `removeIf` on array of objects or scalars
	if m := reArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		params["_last_expr_val"] = removeIfCondFromSlice(sourceMap, sourceMap, arrPath, m[2], strings.TrimSpace(m[3]), params)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}

	// 2. Check `.addAll(...)` on array
	if m := reArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		changed := false
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
				changed = true
			}
		}
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = changed
		return nil
	}

	if m := reArrayRemoveAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, false)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}
	if m := reArrayRetainAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, true)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}

	// 3. Check `.add(...)` / `.set(idx, val)` on array
	if m := reArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if addArgs := splitTopLevelCommaPainless(m[2]); len(addArgs) == 2 {
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[0]), params)
			if err != nil {
				return err
			}
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[1]), params)
			if err != nil {
				return err
			}
			if err := insertIntoSliceAtPath(sourceMap, arrPath, idxVal, valToAdd); err != nil {
				return err
			}
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
			params["_last_expr_val"] = true
			return nil
		}
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		if err := appendToSlice(sourceMap, arrPath, valToAdd); err != nil {
			return err
		}
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = true
		return nil
	}
	if m := reArraySet.FindStringSubmatch(stmt); m != nil {
		if setArgs := splitTopLevelCommaPainless(m[2]); len(setArgs) == 2 {
			arrPath := strings.Split(m[1], ".")
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[0]), params)
			if err != nil {
				return err
			}
			newVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[1]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = setSliceElementAtPath(sourceMap, arrPath, idxVal, newVal)
			return nil
		}
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
		params["_last_expr_val"] = nil
		return nil
	}

	// 5. Check `.put(k, v)` on map
	if m := reMapPut.FindStringSubmatch(stmt); m != nil {
		if putArgs := splitTopLevelCommaPainless(m[2]); len(putArgs) == 2 {
			var targetPath []string
			if m[1] != "" {
				targetPath = strings.Split(m[1], ".")
			}
			kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[0]), params)
			if err != nil {
				return err
			}
			vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[1]), params)
			if err != nil {
				return err
			}
			keyStr := fmt.Sprintf("%v", kVal)
			fullKeyPath := append(targetPath, keyStr)
			params["_last_expr_val"] = resolveParamPath(sourceMap, fullKeyPath)
			setValueAtPath(sourceMap, fullKeyPath, vVal)
			return nil
		}
	}

	// 6. Check `.remove('field')` or `.remove(params.key)` or `.remove(0)` or `.clear()`
	if m := reRemoveField.FindStringSubmatch(stmt); m != nil {
		var parentPath []string
		if m[1] != "" {
			parentPath = strings.Split(m[1], ".")
		}
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
		return nil
	}
	if m := reClearField.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		clearAtPath(sourceMap, targetPath)
		params["_last_expr_val"] = nil
		return nil
	}

	// 6b. Check `.removeIf`, `.addAll`, `.add`, `.putAll`, `.put`, `.remove`, `.clear` on local/loop variables
	if m := reLocalArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				params["_last_expr_val"] = removeIfCondFromSlice(sourceMap, params, arrPath, m[2], strings.TrimSpace(m[3]), params)
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				changed := false
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
						changed = true
					}
				}
				params["_last_expr_val"] = changed
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayRemoveAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, false)
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayRetainAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, true)
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				if addArgs := splitTopLevelCommaPainless(m[2]); len(addArgs) == 2 {
					idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[0]), params)
					if err != nil {
						return err
					}
					valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[1]), params)
					if err != nil {
						return err
					}
					if err := insertIntoSliceAtPath(params, arrPath, idxVal, valToAdd); err != nil {
						return err
					}
					params["_last_expr_val"] = true
					syncLocalVarAlias(sourceMap, params, rootVar)
					return nil
				}
				valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				if err := appendToSlice(params, arrPath, valToAdd); err != nil {
					return err
				}
				params["_last_expr_val"] = true
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArraySet.FindStringSubmatch(stmt); m != nil {
		if setArgs := splitTopLevelCommaPainless(m[2]); len(setArgs) == 2 {
			arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
			if len(arrPath) > 0 {
				rootVar := decodeBracketSeg(arrPath[0])
				if _, ok := params[rootVar]; ok {
					idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[0]), params)
					if err != nil {
						return err
					}
					newVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[1]), params)
					if err != nil {
						return err
					}
					params["_last_expr_val"] = setSliceElementAtPath(params, arrPath, idxVal, newVal)
					syncLocalVarAlias(sourceMap, params, rootVar)
					return nil
				}
			}
		}
	}
	if m := reLocalMapPutAll.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		targetPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(targetPath) > 0 {
			rootVar = decodeBracketSeg(targetPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			mapVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			if subMap, ok := mapVal.(map[string]any); ok {
				putAllAtPath(params, targetPath, subMap)
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
			}
			params["_last_expr_val"] = nil
			return nil
		}
	}
	if m := reLocalMapPut.FindStringSubmatch(stmt); m != nil {
		if putArgs := splitTopLevelCommaPainless(m[2]); len(putArgs) == 2 {
			rawPath := strings.Split(m[1], ".")
			targetPath := normalizeLocalLHSPath(rawPath, params)
			isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
			rootVar := ""
			hasRoot := isRootParams
			if len(targetPath) > 0 {
				rootVar = decodeBracketSeg(targetPath[0])
				_, hasRoot = params[rootVar]
			}
			if hasRoot {
				kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[0]), params)
				if err != nil {
					return err
				}
				vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[1]), params)
				if err != nil {
					return err
				}
				fullKeyPath := append(targetPath, fmt.Sprintf("%v", kVal))
				params["_last_expr_val"] = resolveParamPath(params, fullKeyPath)
				setValueAtPath(params, fullKeyPath, vVal)
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
				return nil
			}
		}
	}
	if m := reLocalRemoveField.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		parentPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(parentPath) > 0 {
			rootVar = decodeBracketSeg(parentPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = removeKeyOrIndexAtPath(params, parentPath, argVal)
			if rootVar != "" {
				syncLocalVarAlias(sourceMap, params, rootVar)
			}
			return nil
		}
	}
	if m := reLocalClearField.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		targetPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(targetPath) > 0 {
			rootVar = decodeBracketSeg(targetPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			if isRootParams {
				for k := range params {
					if !strings.HasPrefix(k, "__") && k != "_source" {
						delete(params, k)
					}
				}
			} else {
				clearAtPath(params, targetPath)
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
			}
			params["_last_expr_val"] = nil
			return nil
		}
	}
	if !isTopLevelAssignmentStmt(stmt) && !strings.HasPrefix(stmt, "return ") && !strings.HasPrefix(stmt, "return(") {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(stmt, ".setValue("); ok {
			recVal, err := evalRHSExpr(sourceMap, recExpr, params)
			if err != nil {
				return err
			}
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(argExpr), params)
			if err != nil {
				return err
			}
			if m, ok := recVal.(map[string]any); ok {
				oldVal := m["value"]
				m["value"] = argVal
				if pm, ok := m["__parent_map"].(map[string]any); ok {
					pm[fmt.Sprintf("%v", m["key"])] = argVal
				}
				params["_last_expr_val"] = oldVal
			}
			return nil
		}
	}

	// 7. Check compound assignment `+=` / `-=` / `*=` / `/=` / `%=` / `&=` / `|=` / `^=` / `<<=` / `>>=` / `>>>=`
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
		case "%=":
			setValueAtPath(sourceMap, lhsPath, applyMulDiv(curVal, rhsVal, '%'))
		case "&=", "|=", "^=", "<<=", ">>=", ">>>=":
			setValueAtPath(sourceMap, lhsPath, applyBitwiseAssign(curVal, rhsVal, op))
		}
		return nil
	}

	// 8. Check field assignment (`ctx._source.deleted = params.deleted`, arithmetic, or literal)
	if m := reAssignParam.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[2]), "=") && !strings.HasPrefix(strings.TrimSpace(m[2]), "~") {
		lhsPath := strings.Split(m[1], ".")
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		setValueAtPath(sourceMap, lhsPath, val)
		for k, v := range params {
			if strings.HasPrefix(k, "__alias_") {
				if aliasPath, ok := v.(string); ok && (aliasPath == m[1] || strings.HasPrefix(aliasPath, m[1]+".")) {
					delete(params, k)
				}
			}
		}
		if reSimpleFieldPath.MatchString(rhsExpr) && !strings.Contains(rhsExpr, ".") {
			if _, exists := params[rhsExpr]; exists {
				switch val.(type) {
				case []any, map[string]any:
					params["__alias_"+rhsExpr] = m[1]
				}
			}
		}
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
		path := normalizeLocalLHSPath(strings.Split(lhs, "."), params)
		if len(path) == 0 {
			return nil
		}
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
		case "%=":
			nextVal = applyMulDiv(curVal, rhsVal, '%')
		case "&=", "|=", "^=", "<<=", ">>=", ">>>=":
			nextVal = applyBitwiseAssign(curVal, rhsVal, op)
		}
		setValueAtPath(params, path, nextVal)
		if len(path) > 1 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
		}
		return nil
	}

	// 10. Check local/loop variable property/index assignment (`tag.status = 'active'`, `items[0] = 'x'`)
	if m := reLocalPropAssign.FindStringSubmatch(stmt); m != nil && m[1] != "doc" && !strings.HasPrefix(strings.TrimSpace(m[3]), "=") && !strings.HasPrefix(strings.TrimSpace(m[3]), "~") {
		varName := m[1]
		propPath := strings.Split(m[2], ".")
		if varName == "ctx" && len(propPath) == 1 {
			metaField := decodeBracketSeg(propPath[0])
			if metaField == "_id" || metaField == "_index" || metaField == "_version" {
				return fmt.Errorf("cannot modify read-only metadata field [ctx.%s]", metaField)
			}
		}
		rhsExpr := strings.TrimSpace(m[3])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		fullPath := normalizeLocalLHSPath(append([]string{varName}, propPath...), params)
		if len(fullPath) > 0 {
			setValueAtPath(params, fullPath, val)
			if len(propPath) == 1 && propPath[0] == "value" {
				if entryMap, ok := params[varName].(map[string]any); ok {
					if pm, ok := entryMap["__parent_map"].(map[string]any); ok {
						pm[fmt.Sprintf("%v", entryMap["key"])] = val
					}
				}
			}
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(fullPath[0]))
		}
		return nil
	}

	// 11. Check local variable declaration/assignment (`def x = ...`, `boolean ok = ...`, `x = ...`)
	if m := reLocalVarAssign.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[2]), "=") && !strings.HasPrefix(strings.TrimSpace(m[2]), "~") {
		varName := m[1]
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		params[varName] = val
		matchedAlias := false
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(rhsExpr, pfx) {
				tail := strings.TrimSpace(strings.TrimPrefix(rhsExpr, pfx))
				if reSimpleFieldPath.MatchString(tail) && !strings.HasSuffix(tail, ".size()") && !strings.HasSuffix(tail, ".length()") {
					switch val.(type) {
					case []any, map[string]any:
						params["__alias_"+varName] = tail
						matchedAlias = true
					}
				}
				break
			}
		}
		if !matchedAlias {
			delete(params, "__alias_"+varName)
		}
		return nil
	}
	if m := reNullVarDecl.FindStringSubmatch(stmt); m != nil {
		params[m[1]] = nil
		delete(params, "__alias_"+m[1])
		return nil
	}

	if strings.HasSuffix(stmt, ")") {
		val, err := evalRHSExpr(sourceMap, stmt, params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = val
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

func findMatchingRegexSlash(s string, openIdx int) int {
	if openIdx < 0 || openIdx >= len(s)-1 || s[openIdx] != '/' || s[openIdx+1] == '/' || s[openIdx+1] == '*' {
		return -1
	}
	inClass := false
	for k := openIdx + 1; k < len(s); k++ {
		if s[k] == '\n' || s[k] == '\r' {
			return -1
		}
		if isEscapedAt(s, k) {
			continue
		}
		if s[k] == '[' && !inClass {
			inClass = true
			continue
		}
		if s[k] == ']' && inClass {
			inClass = false
			continue
		}
		if s[k] == '/' && !inClass {
			if k > openIdx+1 {
				return k
			}
			return -1
		}
	}
	return -1
}

func isRegexSlashAt(s string, idx int) bool {
	if findMatchingRegexSlash(s, idx) <= idx+1 {
		return false
	}
	for j := idx - 1; j >= 0; j-- {
		if s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' {
			continue
		}
		switch s[j] {
		case '~', '(', ',', '=', ':', '?', '!', '&', '|', '[', '{', ';':
			return true
		default:
			return false
		}
	}
	return true
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
				if op == ">" && ((i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>')) || (i > 0 && (s[i-1] == '>' || s[i-1] == '-'))) {
					continue
				}
				if op == "<" && ((i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '<')) || (i > 0 && s[i-1] == '<')) {
					continue
				}
				if op == "|" && ((i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '=')) || (i > 0 && s[i-1] == '|')) {
					continue
				}
				if op == "&" && ((i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '=')) || (i > 0 && s[i-1] == '&')) {
					continue
				}
				if op == "^" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == ">>" && ((i+2 < len(s) && (s[i+2] == '>' || s[i+2] == '=')) || (i > 0 && s[i-1] == '>')) {
					continue
				}
				if (op == "<<" || op == ">>>") && i+len(op) < len(s) && s[i+len(op)] == '=' {
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

func findLastTopLevelOpPainless(s string, ops ...string) (int, string) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastIdx := -1
	lastOp := ""
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
		default:
			if depth != 0 {
				continue
			}
			for _, op := range ops {
				if i+len(op) > len(s) || s[i:i+len(op)] != op {
					continue
				}
				if op == "|" && ((i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '=')) || (i > 0 && s[i-1] == '|')) {
					continue
				}
				if op == "&" && ((i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '=')) || (i > 0 && s[i-1] == '&')) {
					continue
				}
				if op == "^" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == ">>" && ((i+2 < len(s) && (s[i+2] == '>' || s[i+2] == '=')) || (i > 0 && s[i-1] == '>')) {
					continue
				}
				if op == "<<" && ((i+2 < len(s) && s[i+2] == '=') || (i > 0 && s[i-1] == '<')) {
					continue
				}
				if op == ">>>" && ((i+3 < len(s) && s[i+3] == '=') || (i > 0 && s[i-1] == '>')) {
					continue
				}
				lastIdx = i
				lastOp = op
				if len(op) > 1 {
					i += len(op) - 1
				}
				break
			}
		}
	}
	return lastIdx, lastOp
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

func isRawRegexLiteralPainless(expr string) bool {
	expr = trimBalancedParens(strings.TrimSpace(expr))
	return len(expr) >= 3 && expr[0] == '/' && findMatchingRegexSlash(expr, 0) == len(expr)-1
}

func evalRegexMatchPainless(lhsVal, rhsVal any, isRegexLit, fullMatch bool) bool {
	if lhsVal == nil || rhsVal == nil {
		return false
	}
	lhsStr := fmt.Sprintf("%v", lhsVal)
	pat := strings.TrimSpace(fmt.Sprintf("%v", rhsVal))
	if isRegexLit && len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
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
	if strings.HasPrefix(cond, "!") && !strings.HasPrefix(cond, "!=") {
		return !evalConditionDepth(sourceMap, cond[1:], params, depth+1)
	}

	if idx := findTopLevelOpPainless(cond, "==~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+3:])
		isRegexLit := isRawRegexLiteralPainless(rhsRaw)
		var rhs any = rhsRaw
		if !isRegexLit {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, isRegexLit, true)
	}
	if idx := findTopLevelOpPainless(cond, "=~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		isRegexLit := isRawRegexLiteralPainless(rhsRaw)
		var rhs any = rhsRaw
		if !isRegexLit {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, isRegexLit, false)
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

	// Check `.isEmpty()`
	if strings.HasSuffix(cond, ".isEmpty()") {
		val, err := evalRHSExprDepth(sourceMap, cond, params, depth+1)
		if err == nil {
			if b, ok := val.(bool); ok {
				return b
			}
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
	if a == nil || b == nil {
		return false
	}
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
	if len(rhs) >= 3 && rhs[0] == '/' && findMatchingRegexSlash(rhs, 0) == len(rhs)-1 {
		return rhs, nil
	}

	// Check Elvis operator `?:` and ternary `cond ? trueExpr : falseExpr` in left-to-right order
	elvisIdx := findTopLevelOpPainless(rhs, "?:")
	qIdx := findTopLevelOpPainless(rhs, "?")
	if qIdx > 0 && (elvisIdx < 0 || qIdx < elvisIdx) {
		rest := rhs[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			condStr := strings.TrimSpace(rhs[:qIdx])
			if evalConditionDepth(sourceMap, condStr, params, depth+1) {
				return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}
	if elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[:elvisIdx]), params, depth+1)
		if err != nil {
			return nil, err
		}
		if leftVal != nil {
			return leftVal, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[elvisIdx+2:]), params, depth+1)
	}

	// Check boolean logical, relational, or regex operators on RHS (`||`, `&&`, `=~`, `==~`, `==`, `!=`, `>=`, `<=`, `>`, `<`, `!`)
	if hasTopLevelBooleanOrRegexOp(rhs) {
		return evalConditionDepth(sourceMap, rhs, params, depth+1), nil
	}

	// Check bitwise and shift operators (`|`, `^`, `&`, `<<`, `>>>`, `>>`)
	if bwVal, bwOk, bwErr := evalBitwiseOrShiftPainless(sourceMap, rhs, params, depth+1); bwOk || bwErr != nil {
		return bwVal, bwErr
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
	if castType, castRest, ok := splitLeadingTypeCastPainless(rhs); ok {
		innerVal, err := evalRHSExprDepth(sourceMap, castRest, params, depth+1)
		if err != nil || innerVal == nil {
			return nil, err
		}
		switch castType {
		case "int", "long", "Integer", "Long":
			if f, fOk := toFloat64(innerVal); fOk {
				return int64(f), nil
			}
			return int64(0), nil
		case "double", "float", "Double", "Float":
			if f, fOk := toFloat64(innerVal); fOk {
				return f, nil
			}
			return float64(0), nil
		case "String":
			return fmt.Sprintf("%v", innerVal), nil
		case "boolean", "Boolean":
			if b, bOk := innerVal.(bool); bOk {
				return b, nil
			}
			if f, fOk := toFloat64(innerVal); fOk {
				return f != 0, nil
			}
			return strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", innerVal)), "true"), nil
		}
	}
	if m := reCtxIncDec.FindStringSubmatch(rhs); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		pathStr := m[2]
		if op == "" {
			pathStr = m[3]
			op = m[4]
		}
		lhsPath := strings.Split(pathStr, ".")
		curVal := resolveParamPath(sourceMap, lhsPath)
		nextVal := applyArithmetic(curVal, int64(1), op == "++")
		setValueAtPath(sourceMap, lhsPath, nextVal)
		if isPrefix {
			return nextVal, nil
		}
		return normalizeIncDecPrevVal(curVal), nil
	}
	if m := reLocalIncDec.FindStringSubmatch(rhs); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		lhs := m[2]
		if op == "" {
			lhs = m[3]
			op = m[4]
		}
		path := normalizeLocalLHSPath(strings.Split(lhs, "."), params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if len(path) > 1 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
			}
			if isPrefix {
				return nextVal, nil
			}
			return normalizeIncDecPrevVal(curVal), nil
		}
	}
	if strings.HasPrefix(rhs, "-") && len(rhs) > 1 && (rhs[1] < '0' || rhs[1] > '9') {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, false), nil
	}
	if strings.HasPrefix(rhs, "~") && len(rhs) > 1 {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		if f, ok := toFloat64(innerVal); ok {
			return ^int64(f), nil
		}
		return int64(-1), nil
	}

	// Check trailing zero-arg methods `.toLowerCase()`, `.toUpperCase()`, `.trim()`, `.strip()`, `.stripLeading()`, `.stripTrailing()`, `.isBlank()`, `.length()`, `.size()`, `.keySet()`, `.values()`, `.entrySet()`, `.getKey()`, `.getValue()`, `.toString()`, and ZonedDateTime getters
	for _, mSuffix := range []string{
		".toLowerCase()", ".toUpperCase()", ".trim()", ".strip()", ".stripLeading()", ".stripTrailing()", ".isBlank()",
		".length()", ".size()", ".keySet()", ".values()", ".entrySet()", ".getKey()", ".getValue()", ".toString()",
		".getYear()", ".getMonthValue()", ".getDayOfMonth()", ".getDate()", ".getHour()", ".getMinute()", ".getSecond()",
		".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()", ".toInstant()",
	} {
		if strings.HasSuffix(rhs, mSuffix) {
			recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(mSuffix)], "?"))
			if (mSuffix == ".length()" || mSuffix == ".size()") && (strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
				!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".values.") {
				docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
				return int64(len(resolveDocValuesSlice(sourceMap, docPath))), nil
			}
			recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			if err != nil || recVal == nil {
				return nil, err
			}
			switch mSuffix {
			case ".toLowerCase()":
				return strings.ToLower(fmt.Sprintf("%v", recVal)), nil
			case ".toUpperCase()":
				return strings.ToUpper(fmt.Sprintf("%v", recVal)), nil
			case ".trim()", ".strip()":
				return strings.TrimSpace(fmt.Sprintf("%v", recVal)), nil
			case ".stripLeading()":
				return strings.TrimLeftFunc(fmt.Sprintf("%v", recVal), unicode.IsSpace), nil
			case ".stripTrailing()":
				return strings.TrimRightFunc(fmt.Sprintf("%v", recVal), unicode.IsSpace), nil
			case ".isBlank()":
				return strings.TrimSpace(fmt.Sprintf("%v", recVal)) == "", nil
			case ".toString()":
				return fmt.Sprintf("%v", recVal), nil
			case ".toInstant()":
				return recVal, nil
			case ".getYear()", ".getMonthValue()", ".getDayOfMonth()", ".getDate()", ".getHour()", ".getMinute()", ".getSecond()", ".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					switch mSuffix {
					case ".getYear()":
						return int64(tm.Year()), nil
					case ".getMonthValue()":
						return int64(tm.Month()), nil
					case ".getDayOfMonth()", ".getDate()":
						return int64(tm.Day()), nil
					case ".getHour()":
						return int64(tm.Hour()), nil
					case ".getMinute()":
						return int64(tm.Minute()), nil
					case ".getSecond()":
						return int64(tm.Second()), nil
					case ".getDayOfWeek()":
						dow := int64(tm.Weekday())
						if dow == 0 {
							dow = 7
						}
						return dow, nil
					case ".getDayOfWeekEnum()":
						return strings.ToUpper(tm.Weekday().String()), nil
					case ".getMillis()", ".toEpochMilli()":
						return tm.UnixMilli(), nil
					case ".getEpochSecond()":
						return tm.Unix(), nil
					}
				}
				return nil, nil
			case ".keySet()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := make([]string, 0, len(tv))
					for k := range tv {
						if k == "__parent_map" {
							continue
						}
						keys = append(keys, k)
					}
					sort.Strings(keys)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = k
					}
					return out, nil
				}
				return []any{}, nil
			case ".values()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := make([]string, 0, len(tv))
					for k := range tv {
						if k == "__parent_map" {
							continue
						}
						keys = append(keys, k)
					}
					sort.Strings(keys)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = tv[k]
					}
					return out, nil
				}
				if tv, ok := recVal.([]any); ok {
					return tv, nil
				}
				return []any{}, nil
			case ".entrySet()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := make([]string, 0, len(tv))
					for k := range tv {
						if k == "__parent_map" {
							continue
						}
						keys = append(keys, k)
					}
					sort.Strings(keys)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = map[string]any{"key": k, "value": tv[k], "__parent_map": tv}
					}
					return out, nil
				}
				return []any{}, nil
			case ".getKey()":
				if tv, ok := recVal.(map[string]any); ok {
					return tv["key"], nil
				}
				return nil, nil
			case ".getValue()":
				if tv, ok := recVal.(map[string]any); ok {
					return tv["value"], nil
				}
				if f, ok := toFloat64(recVal); ok {
					return int64(f), nil
				}
				if s, ok := recVal.(string); ok {
					switch strings.ToUpper(strings.TrimSpace(s)) {
					case "MONDAY":
						return int64(1), nil
					case "TUESDAY":
						return int64(2), nil
					case "WEDNESDAY":
						return int64(3), nil
					case "THURSDAY":
						return int64(4), nil
					case "FRIDAY":
						return int64(5), nil
					case "SATURDAY":
						return int64(6), nil
					case "SUNDAY":
						return int64(7), nil
					}
				}
				return nil, nil
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
		if (strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
			!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".values.") {
			docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
			return len(resolveDocValuesSlice(sourceMap, docPath)) == 0, nil
		}
		recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil || recVal == nil {
			return false, err
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

	for _, mName := range []string{
		".startsWith(", ".endsWith(", ".containsAll(", ".removeAll(", ".retainAll(", ".removeIf(", ".contains(", ".containsKey(", ".containsValue(", ".getOrDefault(", ".get(",
		".indexOf(", ".lastIndexOf(", ".charAt(", ".repeat(", ".matches(", ".replaceAll(", ".replaceFirst(",
		".splitOnToken(", ".split(", ".replace(", ".substring(", ".subList(", ".join(",
		".equals(", ".equalsIgnoreCase(", ".compareTo(", ".concat(", ".remove(", ".setValue(", ".set(", ".addAll(", ".add(", ".putAll(", ".putIfAbsent(", ".put(", ".sort(",
		".plusDays(", ".minusDays(", ".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(",
		".isAfter(", ".isBefore(", ".isEqual(",
	} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(rhs, mName); ok {
			if mName == ".removeIf(" {
				arrowIdx := strings.Index(argExpr, "->")
				if arrowIdx > 0 {
					paramName := strings.TrimSpace(argExpr[:arrowIdx])
					paramName = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(paramName, "("), ")"))
					condExpr := strings.TrimSpace(argExpr[arrowIdx+2:])
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							arrPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
							return removeIfCondFromSlice(sourceMap, sourceMap, arrPath, paramName, condExpr, params), nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							changed := removeIfCondFromSlice(sourceMap, params, arrPath, paramName, condExpr, params)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return changed, nil
						}
					}
				}
				return false, nil
			}
			if mName == ".removeAll(" || mName == ".retainAll(" {
				isRetain := mName == ".retainAll("
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						arrPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
						return mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, isRetain), nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
				if len(arrPath) > 0 {
					rootVar := decodeBracketSeg(arrPath[0])
					if _, exists := params[rootVar]; exists {
						changed := mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, isRetain)
						syncLocalVarAlias(sourceMap, params, rootVar)
						return changed, nil
					}
				}
			}
			if mName == ".remove(" {
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
					return removeKeyOrIndexAtPath(sourceMap, nil, argVal), nil
				}
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						parentPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
						return removeKeyOrIndexAtPath(sourceMap, parentPath, argVal), nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				rawPath := strings.Split(cleanRec, ".")
				parentPath := normalizeLocalLHSPath(rawPath, params)
				if len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
					return removeKeyOrIndexAtPath(params, nil, argVal), nil
				}
				if len(parentPath) > 0 {
					rootVar := decodeBracketSeg(parentPath[0])
					if _, exists := params[rootVar]; exists {
						removed := removeKeyOrIndexAtPath(params, parentPath, argVal)
						syncLocalVarAlias(sourceMap, params, rootVar)
						return removed, nil
					}
				}
			}
			if mName == ".set(" {
				setArgs := splitTopLevelCommaPainless(argExpr)
				if len(setArgs) == 2 {
					idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[0]), params, depth+1)
					newVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[1]), params, depth+1)
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							arrPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
							return setSliceElementAtPath(sourceMap, arrPath, idxVal, newVal), nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							prev := setSliceElementAtPath(params, arrPath, idxVal, newVal)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return prev, nil
						}
					}
				}
			}
			if mName == ".addAll(" {
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				items, _ := argVal.([]any)
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						arrPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
						changed := false
						for _, item := range append([]any(nil), items...) {
							if err := appendToSlice(sourceMap, arrPath, item); err != nil {
								return nil, err
							}
							changed = true
						}
						return changed, nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
				if len(arrPath) > 0 {
					rootVar := decodeBracketSeg(arrPath[0])
					if _, exists := params[rootVar]; exists {
						changed := false
						for _, item := range append([]any(nil), items...) {
							if err := appendToSlice(params, arrPath, item); err != nil {
								return nil, err
							}
							changed = true
						}
						syncLocalVarAlias(sourceMap, params, rootVar)
						return changed, nil
					}
				}
				return false, nil
			}
			if mName == ".add(" {
				addArgs := splitTopLevelCommaPainless(argExpr)
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						arrPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
						if len(addArgs) == 2 {
							idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
							if err := insertIntoSliceAtPath(sourceMap, arrPath, idxVal, valToAdd); err != nil {
								return nil, err
							}
							return true, nil
						}
						valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if err := appendToSlice(sourceMap, arrPath, valToAdd); err != nil {
							return nil, err
						}
						return true, nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
				if len(arrPath) > 0 {
					rootVar := decodeBracketSeg(arrPath[0])
					if _, exists := params[rootVar]; exists {
						if len(addArgs) == 2 {
							idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
							if err := insertIntoSliceAtPath(params, arrPath, idxVal, valToAdd); err != nil {
								return nil, err
							}
							syncLocalVarAlias(sourceMap, params, rootVar)
							return true, nil
						}
						valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if err := appendToSlice(params, arrPath, valToAdd); err != nil {
							return nil, err
						}
						syncLocalVarAlias(sourceMap, params, rootVar)
						return true, nil
					}
				}
				return true, nil
			}
			if mName == ".putAll(" {
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				subMap, isSubMap := argVal.(map[string]any)
				if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
					if isSubMap {
						putAllAtPath(sourceMap, nil, subMap)
					}
					return nil, nil
				}
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						targetPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
						if isSubMap {
							putAllAtPath(sourceMap, targetPath, subMap)
						}
						return nil, nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				rawPath := strings.Split(cleanRec, ".")
				targetPath := normalizeLocalLHSPath(rawPath, params)
				if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
					if isSubMap {
						putAllAtPath(params, nil, subMap)
					}
					return nil, nil
				}
				if len(targetPath) > 0 {
					rootVar := decodeBracketSeg(targetPath[0])
					if _, exists := params[rootVar]; exists {
						if isSubMap {
							putAllAtPath(params, targetPath, subMap)
							syncLocalVarAlias(sourceMap, params, rootVar)
						}
						return nil, nil
					}
				}
				return nil, nil
			}
			if mName == ".put(" {
				putArgs := splitTopLevelCommaPainless(argExpr)
				if len(putArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[1]), params, depth+1)
					keyStr := fmt.Sprintf("%v", kVal)
					if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
						prev := resolveParamPath(sourceMap, []string{keyStr})
						setValueAtPath(sourceMap, []string{keyStr}, vVal)
						return prev, nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							targetPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(sourceMap, fullKeyPath)
							setValueAtPath(sourceMap, fullKeyPath, vVal)
							return prev, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					targetPath := normalizeLocalLHSPath(rawPath, params)
					if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						prev := params[keyStr]
						params[keyStr] = vVal
						return prev, nil
					}
					if len(targetPath) > 0 {
						rootVar := decodeBracketSeg(targetPath[0])
						if _, exists := params[rootVar]; exists {
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(params, fullKeyPath)
							setValueAtPath(params, fullKeyPath, vVal)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return prev, nil
						}
					}
				}
				return nil, nil
			}
			if mName == ".putIfAbsent(" {
				putArgs := splitTopLevelCommaPainless(argExpr)
				if len(putArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[1]), params, depth+1)
					keyStr := fmt.Sprintf("%v", kVal)
					if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
						prev := resolveParamPath(sourceMap, []string{keyStr})
						if prev == nil {
							setValueAtPath(sourceMap, []string{keyStr}, vVal)
						}
						return prev, nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							targetPath := strings.Split(strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?"), ".")
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(sourceMap, fullKeyPath)
							if prev == nil {
								setValueAtPath(sourceMap, fullKeyPath, vVal)
							}
							return prev, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					targetPath := normalizeLocalLHSPath(rawPath, params)
					if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						prev := params[keyStr]
						if prev == nil {
							params[keyStr] = vVal
						}
						return prev, nil
					}
					if len(targetPath) > 0 {
						rootVar := decodeBracketSeg(targetPath[0])
						if _, exists := params[rootVar]; exists {
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(params, fullKeyPath)
							if prev == nil {
								setValueAtPath(params, fullKeyPath, vVal)
								syncLocalVarAlias(sourceMap, params, rootVar)
							}
							return prev, nil
						}
					}
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok {
							prev := m[keyStr]
							if prev == nil {
								m[keyStr] = vVal
							}
							return prev, nil
						}
					}
				}
				return nil, nil
			}
			if mName == ".sort(" {
				if recExpr == "Collections" {
					continue
				}
				if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
					if arr, ok := recVal.([]any); ok {
						sortPainlessSliceInPlace(arr, argExpr, sourceMap, params, depth+1)
						return arr, nil
					}
				}
				return nil, nil
			}
			if mName == ".containsKey(" && (recExpr == "doc" || recExpr == "doc?") {
				argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
				if argVal == nil {
					return false, nil
				}
				fieldPath := fmt.Sprintf("%v", argVal)
				if len(resolveDocValuesSlice(sourceMap, fieldPath)) > 0 {
					return true, nil
				}
				cleanPath := strings.TrimSuffix(fieldPath, ".keyword")
				return resolveParamPath(sourceMap, strings.Split(cleanPath, ".")) != nil, nil
			}
			var recVal any
			var err error
			if (mName == ".containsAll(" || mName == ".contains(" || mName == ".indexOf(" || mName == ".lastIndexOf(" || mName == ".get(" || mName == ".subList(" || mName == ".join(") &&
				(strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
				!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".value.") && !strings.Contains(recExpr, ".values.") && !strings.Contains(recExpr, "(") {
				docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
				recVal = resolveDocValuesSlice(sourceMap, docPath)
			} else {
				recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			}
			if err != nil || recVal == nil {
				if mName == ".startsWith(" || mName == ".endsWith(" || mName == ".containsAll(" || mName == ".removeAll(" || mName == ".retainAll(" || mName == ".contains(" || mName == ".containsKey(" || mName == ".containsValue(" || mName == ".matches(" || mName == ".equals(" || mName == ".equalsIgnoreCase(" || mName == ".isAfter(" || mName == ".isBefore(" || mName == ".isEqual(" {
					return false, err
				}
				return nil, err
			}
			switch mName {
			case ".subList(":
				args := splitTopLevelCommaPainless(argExpr)
				if tv, ok := recVal.([]any); ok && len(args) >= 2 {
					sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					sf, sOk := toFloat64(sVal)
					ef, eOk := toFloat64(eVal)
					if sOk && eOk {
						start, end := int(sf), int(ef)
						if start < 0 {
							start = 0
						}
						if start > len(tv) {
							start = len(tv)
						}
						if end < start {
							end = start
						}
						if end > len(tv) {
							end = len(tv)
						}
						sub := make([]any, end-start)
						copy(sub, tv[start:end])
						return sub, nil
					}
				}
				return []any{}, nil
			case ".getOrDefault(":
				args := splitTopLevelCommaPainless(argExpr)
				if tv, ok := recVal.(map[string]any); ok && len(args) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					defVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if kVal != nil {
						if v, exists := tv[fmt.Sprintf("%v", kVal)]; exists && v != nil {
							return v, nil
						}
					}
					return defVal, nil
				}
				return nil, nil
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
			case ".replaceAll(", ".replaceFirst(":
				args := splitTopLevelCommaPainless(argExpr)
				if len(args) == 2 {
					rawPatExpr := strings.TrimSpace(args[0])
					patVal, _ := evalRHSExprDepth(sourceMap, rawPatExpr, params, depth+1)
					replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if s, ok := recVal.(string); ok && patVal != nil && replVal != nil {
						patStr := fmt.Sprintf("%v", patVal)
						if isRawRegexLiteralPainless(rawPatExpr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
							patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
						}
						replStr := fmt.Sprintf("%v", replVal)
						if re, err := regexp.Compile(patStr); err == nil {
							goRepl := normalizeJavaRegexReplacement(replStr)
							if mName == ".replaceFirst(" {
								if loc := re.FindStringSubmatchIndex(s); loc != nil {
									expanded := re.ExpandString(nil, goRepl, s, loc)
									return s[:loc[0]] + string(expanded) + s[loc[1]:], nil
								}
								return s, nil
							}
							return re.ReplaceAllString(s, goRepl), nil
						}
						if mName == ".replaceFirst(" {
							return strings.Replace(s, patStr, replStr, 1), nil
						}
						return strings.ReplaceAll(s, patStr, replStr), nil
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
			case ".setValue(":
				if m, ok := recVal.(map[string]any); ok {
					oldVal := m["value"]
					m["value"] = argVal
					if pm, ok := m["__parent_map"].(map[string]any); ok {
						pm[fmt.Sprintf("%v", m["key"])] = argVal
					}
					return oldVal, nil
				}
				return nil, nil
			case ".endsWith(":
				if s, ok := recVal.(string); ok && argVal != nil {
					return strings.HasSuffix(s, fmt.Sprintf("%v", argVal)), nil
				}
				return false, nil
			case ".matches(":
				return evalRegexMatchPainless(recVal, argVal, isRawRegexLiteralPainless(argExpr), true), nil
			case ".charAt(":
				if s, ok := recVal.(string); ok && argVal != nil {
					if f, ok := toFloat64(argVal); ok {
						idx := int(f)
						if idx >= 0 && idx < len(s) {
							return string(s[idx]), nil
						}
					}
				}
				return nil, nil
			case ".repeat(":
				if s, ok := recVal.(string); ok && argVal != nil {
					if f, ok := toFloat64(argVal); ok {
						n := int(f)
						if n <= 0 || s == "" {
							return "", nil
						}
						if len(s)*n > MaxPainlessSliceItems*64 {
							n = (MaxPainlessSliceItems * 64) / len(s)
						}
						return strings.Repeat(s, n), nil
					}
				}
				return "", nil
			case ".containsAll(":
				if tv, ok := recVal.([]any); ok {
					if needles, ok2 := argVal.([]any); ok2 {
						for _, needle := range needles {
							found := false
							for _, item := range tv {
								if valuesEqual(item, needle) {
									found = true
									break
								}
							}
							if !found {
								return false, nil
							}
						}
						return true, nil
					}
				}
				return false, nil
			case ".removeAll(", ".retainAll(":
				if tv, ok := recVal.([]any); ok {
					if needles, ok2 := argVal.([]any); ok2 {
						isRetain := mName == ".retainAll("
						changed := false
						for _, item := range tv {
							inNeedles := false
							for _, needle := range needles {
								if valuesEqual(item, needle) {
									inNeedles = true
									break
								}
							}
							if (isRetain && !inNeedles) || (!isRetain && inNeedles) {
								changed = true
								break
							}
						}
						return changed, nil
					}
				}
				return false, nil
			case ".join(":
				if recExpr == "String" {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						delimVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						delim := fmt.Sprintf("%v", delimVal)
						if len(args) == 2 {
							secondVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
							if arr, ok := secondVal.([]any); ok {
								parts := make([]string, len(arr))
								for i, item := range arr {
									parts[i] = fmt.Sprintf("%v", item)
								}
								return strings.Join(parts, delim), nil
							}
						}
						parts := make([]string, 0, len(args)-1)
						for _, a := range args[1:] {
							v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
							parts = append(parts, fmt.Sprintf("%v", v))
						}
						return strings.Join(parts, delim), nil
					}
				}
				if tv, ok := recVal.([]any); ok {
					sep := ""
					if argVal != nil {
						sep = fmt.Sprintf("%v", argVal)
					}
					parts := make([]string, len(tv))
					for i, item := range tv {
						parts[i] = fmt.Sprintf("%v", item)
					}
					return strings.Join(parts, sep), nil
				}
				return fmt.Sprintf("%v", recVal), nil
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
			case ".containsValue(":
				if m, ok := recVal.(map[string]any); ok {
					for _, v := range m {
						if valuesEqual(v, argVal) {
							return true, nil
						}
					}
				}
				return false, nil
			case ".get(":
				switch tv := recVal.(type) {
				case map[string]any:
					if argVal != nil {
						return tv[fmt.Sprintf("%v", argVal)], nil
					}
				case []any:
					if argVal != nil {
						if f, ok := toFloat64(argVal); ok {
							if idx, okIdx := parseSliceIndex(strconv.Itoa(int(f)), len(tv)); okIdx {
								return tv[idx], nil
							}
						}
					}
				}
				return nil, nil
			case ".indexOf(":
				args := splitTopLevelCommaPainless(argExpr)
				switch tv := recVal.(type) {
				case string:
					if len(args) >= 2 {
						subVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						fromVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if subVal != nil {
							fromIdx := 0
							if ff, ok := toFloat64(fromVal); ok {
								fromIdx = int(ff)
							}
							if fromIdx < 0 {
								fromIdx = 0
							}
							if fromIdx > len(tv) {
								return int64(-1), nil
							}
							idx := strings.Index(tv[fromIdx:], fmt.Sprintf("%v", subVal))
							if idx < 0 {
								return int64(-1), nil
							}
							return int64(fromIdx + idx), nil
						}
					} else if argVal != nil {
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
			case ".lastIndexOf(":
				args := splitTopLevelCommaPainless(argExpr)
				switch tv := recVal.(type) {
				case string:
					if len(args) >= 2 {
						subVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						fromVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if subVal != nil {
							fromIdx := len(tv)
							if ff, ok := toFloat64(fromVal); ok {
								fromIdx = int(ff)
							}
							if fromIdx < 0 {
								return int64(-1), nil
							}
							subStr := fmt.Sprintf("%v", subVal)
							maxEnd := fromIdx + len(subStr)
							if maxEnd > len(tv) {
								maxEnd = len(tv)
							}
							return int64(strings.LastIndex(tv[:maxEnd], subStr)), nil
						}
					} else if argVal != nil {
						return int64(strings.LastIndex(tv, fmt.Sprintf("%v", argVal))), nil
					}
				case []any:
					for idx := len(tv) - 1; idx >= 0; idx-- {
						if valuesEqual(tv[idx], argVal) {
							return int64(idx), nil
						}
					}
				}
				return int64(-1), nil
			case ".splitOnToken(":
				if s, ok := recVal.(string); ok && argVal != nil {
					tokenStr := fmt.Sprintf("%v", argVal)
					if tokenStr == "" {
						return []any{}, nil
					}
					parts := strings.Split(s, tokenStr)
					out := make([]any, 0, len(parts))
					for _, p := range parts {
						out = append(out, p)
					}
					return out, nil
				}
				return []any{}, nil
			case ".split(":
				if s, ok := recVal.(string); ok {
					args := splitTopLevelCommaPainless(argExpr)
					rawSepExpr := argExpr
					sepVal := argVal
					limit := 0
					if len(args) >= 2 {
						rawSepExpr = strings.TrimSpace(args[0])
						sepVal, _ = evalRHSExprDepth(sourceMap, rawSepExpr, params, depth+1)
						limVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if lf, lOk := toFloat64(limVal); lOk {
							limit = int(lf)
						}
					}
					if sepVal != nil {
						if s == "" {
							return []any{""}, nil
						}
						sepStr := fmt.Sprintf("%v", sepVal)
						isRegexLit := isRawRegexLiteralPainless(rawSepExpr)
						if isRegexLit && len(sepStr) >= 3 && sepStr[0] == '/' && sepStr[len(sepStr)-1] == '/' {
							sepStr = strings.ReplaceAll(sepStr[1:len(sepStr)-1], `\/`, `/`)
						}
						splitLim := -1
						if limit > 0 {
							splitLim = limit
						}
						var parts []string
						if re, err := regexp.Compile(sepStr); err == nil && (isRegexLit || (sepStr != "." && sepStr != "|" && sepStr != "" && sepStr != "$" && sepStr != "^")) {
							parts = re.Split(s, splitLim)
						} else if splitLim > 0 {
							parts = strings.SplitN(s, sepStr, splitLim)
						} else {
							parts = strings.Split(s, sepStr)
						}
						if limit == 0 && len(parts) > 1 {
							for len(parts) > 0 && parts[len(parts)-1] == "" {
								parts = parts[:len(parts)-1]
							}
						}
						out := make([]any, len(parts))
						for i, p := range parts {
							out[i] = p
						}
						return out, nil
					}
				}
				return []any{}, nil
			case ".equals(":
				return valuesEqual(recVal, argVal), nil
			case ".equalsIgnoreCase(":
				if argVal == nil {
					return false, nil
				}
				return strings.EqualFold(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal)), nil
			case ".compareTo(":
				if fa, ok1 := toFloat64(recVal); ok1 {
					if fb, ok2 := toFloat64(argVal); ok2 {
						if fa < fb {
							return int64(-1), nil
						}
						if fa > fb {
							return int64(1), nil
						}
						return int64(0), nil
					}
				}
				return int64(strings.Compare(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal))), nil
			case ".concat(":
				if arr, ok := recVal.([]any); ok {
					if argArr, ok2 := argVal.([]any); ok2 {
						return append(append([]any(nil), arr...), argArr...), nil
					}
					return append(append([]any(nil), arr...), argVal), nil
				}
				if argVal == nil {
					return fmt.Sprintf("%v", recVal), nil
				}
				return fmt.Sprintf("%v%v", recVal, argVal), nil
			case ".remove(":
				if m, ok := recVal.(map[string]any); ok && argVal != nil {
					k := fmt.Sprintf("%v", argVal)
					old := m[k]
					delete(m, k)
					return old, nil
				}
				return nil, nil
			case ".plusDays(", ".minusDays(", ".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					f, fOk := toFloat64(argVal)
					if !fOk {
						return recVal, nil
					}
					n := int64(f)
					if strings.HasPrefix(mName, ".minus") {
						n = -n
					}
					switch mName {
					case ".plusDays(", ".minusDays(":
						tm = tm.AddDate(0, 0, int(n))
					case ".plusHours(", ".minusHours(":
						tm = tm.Add(time.Duration(n) * time.Hour)
					case ".plusMinutes(", ".minusMinutes(":
						tm = tm.Add(time.Duration(n) * time.Minute)
					case ".plusSeconds(", ".minusSeconds(":
						tm = tm.Add(time.Duration(n) * time.Second)
					case ".plusMillis(", ".minusMillis(":
						tm = tm.Add(time.Duration(n) * time.Millisecond)
					}
					return tm.Format(time.RFC3339Nano), nil
				}
				return nil, nil
			case ".isAfter(", ".isBefore(", ".isEqual(":
				if tm1, ok1 := parsePainlessDateTime(recVal); ok1 {
					if tm2, ok2 := parsePainlessDateTime(argVal); ok2 {
						switch mName {
						case ".isAfter(":
							return tm1.After(tm2), nil
						case ".isBefore(":
							return tm1.Before(tm2), nil
						case ".isEqual(":
							return tm1.Equal(tm2), nil
						}
					}
				}
				return false, nil
			}
		}
	}

	if staticVal, handled, err := evalStaticCallPainless(sourceMap, rhs, params, depth+1); handled {
		return staticVal, err
	}

	if callExpr, tailPath, ok := splitPostCallPropertyAccess(rhs); ok {
		callVal, err := evalRHSExprDepth(sourceMap, callExpr, params, depth+1)
		if err != nil || callVal == nil {
			return nil, err
		}
		return resolveParamPath(map[string]any{"_v": callVal}, append([]string{"_v"}, strings.Split(tailPath, ".")...)), nil
	}

	if rhs == "ctx.op" || rhs == "ctx?.op" {
		if v, ok := params["_ctx_op"]; ok {
			return v, nil
		}
		return "index", nil
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
		if strings.HasSuffix(trimmed, ".empty") {
			base := strings.TrimSuffix(trimmed, ".empty")
			if strings.HasSuffix(base, ".value") {
				val, err := evalRHSExprDepth(sourceMap, "doc."+base, params, depth+1)
				if err != nil || val == nil {
					return true, err
				}
				return fmt.Sprintf("%v", val) == "", nil
			}
			dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(base, ".values"))
			return len(dv) == 0, nil
		}
		if strings.HasSuffix(trimmed, ".length") {
			base := strings.TrimSuffix(trimmed, ".length")
			if strings.HasSuffix(base, ".value") {
				val, err := evalRHSExprDepth(sourceMap, "doc."+base, params, depth+1)
				if err != nil || val == nil {
					return int64(0), err
				}
				return int64(len(fmt.Sprintf("%v", val))), nil
			}
			dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(base, ".values"))
			return int64(len(dv)), nil
		}
		if strings.HasSuffix(trimmed, ".values") {
			return resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed, ".values")), nil
		}
		// Check `.values.<idx>` or `.<idx>` after bracket expansion (`doc['tags'].values[0]` or `doc['tags'][0]`)
		if idx := strings.LastIndex(trimmed, ".values."); idx > 0 {
			dv := resolveDocValuesSlice(sourceMap, trimmed[:idx])
			tailSeg := decodeBracketSeg(trimmed[idx+len(".values."):])
			if sIdx, ok := parseSliceIndex(tailSeg, len(dv)); ok {
				return dv[sIdx], nil
			}
			return nil, nil
		}
		if lastDot := strings.LastIndexByte(trimmed, '.'); lastDot > 0 {
			tailSeg := decodeBracketSeg(trimmed[lastDot+1:])
			if isIntegerLiteral(tailSeg) {
				dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed[:lastDot], ".values"))
				if sIdx, ok := parseSliceIndex(tailSeg, len(dv)); ok {
					return dv[sIdx], nil
				}
				return nil, nil
			}
		}
		dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed, ".value"))
		if len(dv) == 0 {
			return nil, nil
		}
		return dv[0], nil
	}
	if strings.HasSuffix(rhs, ".empty") || strings.HasSuffix(rhs, ".length") {
		isLen := strings.HasSuffix(rhs, ".length")
		suf := ".empty"
		if isLen {
			suf = ".length"
		}
		recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(suf)], "?"))
		if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil && recVal != nil {
			switch tv := recVal.(type) {
			case string:
				if isLen {
					return int64(len(tv)), nil
				}
				return len(tv) == 0, nil
			case []any:
				if isLen {
					return int64(len(tv)), nil
				}
				return len(tv) == 0, nil
			case map[string]any:
				if _, hasProp := tv[strings.TrimPrefix(suf, ".")]; !hasProp {
					if isLen {
						return int64(len(tv)), nil
					}
					return len(tv) == 0, nil
				}
			}
		}
	}
	if rhs == "params" {
		return params, nil
	}
	if rhs == "params._source" || rhs == "params?._source" {
		return sourceMap, nil
	}
	if strings.HasPrefix(rhs, "params._source.") || strings.HasPrefix(rhs, "params?._source.") ||
		strings.HasPrefix(rhs, "params._source?.") || strings.HasPrefix(rhs, "params?._source?.") {
		trimmed := rhs
		for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
			if strings.HasPrefix(trimmed, pfx) {
				trimmed = strings.TrimPrefix(trimmed, pfx)
				break
			}
		}
		return resolveParamPath(sourceMap, strings.Split(trimmed, ".")), nil
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
	switch rhs {
	case "[]", "new ArrayList()", "new LinkedList()", "new HashSet()":
		return []any{}, nil
	case "[:]", "{}", "new HashMap()", "new LinkedHashMap()", "new TreeMap()":
		return map[string]any{}, nil
	}
	if strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, "]") && findMatchingDelimiter(rhs, 0, '[', ']') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[1 : len(rhs)-1])
		if inner != "" {
			items := splitTopLevelCommaPainless(inner)
			firstColon := -1
			firstQ := -1
			if len(items) > 0 {
				firstColon = findTopLevelOpPainless(items[0], ":")
				firstQ = findTopLevelOpPainless(items[0], "?")
			}
			if firstColon > 0 && (firstQ < 0 || firstQ > firstColon) {
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
	numStr := rhs
	if reNumericLiteralSuffix.MatchString(numStr) {
		numStr = numStr[:len(numStr)-1]
	}
	dec := json.NewDecoder(strings.NewReader(numStr))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err == nil && strings.TrimSpace(numStr[dec.InputOffset():]) == "" {
		if jn, ok := parsed.(json.Number); ok {
			if iv, err := jn.Int64(); err == nil {
				return iv, nil
			}
			if fv, err := jn.Float64(); err == nil {
				return fv, nil
			}
		}
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
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		ch := s[i]
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

func isPrimitiveTypeCastKeyword(s string) bool {
	switch s {
	case "int", "long", "double", "float", "String", "boolean", "Integer", "Long", "Double", "Float", "Boolean":
		return true
	}
	return false
}

func splitLeadingTypeCastPainless(s string) (castType, rest string, ok bool) {
	if !strings.HasPrefix(s, "(") {
		return "", "", false
	}
	closeP := findMatchingDelimiter(s, 0, '(', ')')
	if closeP <= 1 || closeP >= len(s)-1 {
		return "", "", false
	}
	cand := strings.TrimSpace(s[1:closeP])
	if !isPrimitiveTypeCastKeyword(cand) {
		return "", "", false
	}
	tail := strings.TrimSpace(s[closeP+1:])
	if tail == "" {
		return "", "", false
	}
	return cand, tail, true
}

func isCastPrefixOnly(prev string) bool {
	cur := strings.TrimSpace(prev)
	strippedAny := false
	for strings.HasSuffix(cur, ")") {
		openIdx := -1
		for i := len(cur) - 2; i >= 0; i-- {
			if cur[i] == '(' && findMatchingDelimiter(cur, i, '(', ')') == len(cur)-1 {
				openIdx = i
				break
			}
		}
		if openIdx < 0 || !isPrimitiveTypeCastKeyword(strings.TrimSpace(cur[openIdx+1:len(cur)-1])) {
			break
		}
		strippedAny = true
		cur = strings.TrimSpace(cur[:openIdx])
	}
	if !strippedAny {
		return false
	}
	if cur == "" {
		return true
	}
	lastChar := cur[len(cur)-1]
	return lastChar == '+' || lastChar == '-' || lastChar == '*' || lastChar == '/' || lastChar == '%' ||
		lastChar == '(' || lastChar == ',' || lastChar == '?' || lastChar == ':' || lastChar == '=' ||
		lastChar == '<' || lastChar == '>' || lastChar == '!' || lastChar == '~' || lastChar == '&' || lastChar == '|' || lastChar == '^'
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
				if (i+1 < len(expr) && expr[i+1] == c) || expr[i-1] == c {
					continue
				}
				if (expr[i-1] == 'e' || expr[i-1] == 'E') && i >= 2 && ((expr[i-2] >= '0' && expr[i-2] <= '9') || expr[i-2] == '.') {
					continue
				}
				prev := strings.TrimSpace(expr[:i])
				if len(prev) > 0 && !isCastPrefixOnly(prev) {
					lastChar := prev[len(prev)-1]
					if lastChar != '+' && lastChar != '-' && lastChar != '*' && lastChar != '/' && lastChar != '%' && lastChar != '(' &&
						lastChar != ',' && lastChar != '?' && lastChar != ':' && lastChar != '=' && lastChar != '<' && lastChar != '>' && lastChar != '!' && lastChar != '~' &&
						lastChar != '&' && lastChar != '|' && lastChar != '^' {
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
		if aSlice, ok := a.([]any); ok {
			if bSlice, ok2 := b.([]any); ok2 {
				out := make([]any, 0, len(aSlice)+len(bSlice))
				out = append(out, aSlice...)
				out = append(out, bSlice...)
				return out
			}
			out := make([]any, 0, len(aSlice)+1)
			out = append(out, aSlice...)
			out = append(out, b)
			return out
		}
		if aMap, ok := a.(map[string]any); ok {
			if bMap, ok2 := b.(map[string]any); ok2 {
				out := make(map[string]any, len(aMap)+len(bMap))
				for k, v := range aMap {
					out[k] = v
				}
				for k, v := range bMap {
					out[k] = v
				}
				return out
			}
		}
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
		if err == nil {
			f, ok = parsed, true
		} else if len(val) >= 10 && val[4] == '-' && val[7] == '-' {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
				if t, tErr := time.Parse(layout, strings.TrimSpace(val)); tErr == nil {
					f, ok = float64(t.UTC().UnixMilli()), true
					break
				}
			}
		}
	default:
		return 0, false
	}
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func hasElseKeywordPrefix(s string) bool {
	return strings.HasPrefix(s, "else") && (len(s) == 4 || !isIdentByte(s[4]))
}

func hasTrailingContinuationOp(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	for _, sfx := range []string{"&&", "||", "?:", "==", "!=", ">=", "<=", "=~", "==~"} {
		if strings.HasSuffix(t, sfx) {
			return true
		}
	}
	if strings.HasSuffix(t, "++") || strings.HasSuffix(t, "--") {
		return false
	}
	last := t[len(t)-1]
	return last == '+' || last == '-' || last == '*' || last == ',' || last == '?' || last == ':' || last == '='
}

func isControlBlockStmt(s string) bool {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "{") {
		return true
	}
	for _, kw := range []string{"if", "for", "while"} {
		if strings.HasPrefix(t, kw) && (len(t) == len(kw) || t[len(kw)] == ' ' || t[len(kw)] == '\t' || t[len(kw)] == '(') {
			return true
		}
	}
	return false
}

func isIncompleteControlHeader(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || !isControlBlockStmt(t) || strings.HasPrefix(t, "{") {
		return false
	}
	openP := strings.IndexByte(t, '(')
	closeP := findMatchingDelimiter(t, openP, '(', ')')
	if openP > 0 && closeP == len(t)-1 {
		return true
	}
	if strings.HasSuffix(t, "else") && len(t) > 4 && !isIdentByte(t[len(t)-5]) {
		return true
	}
	if strings.HasSuffix(t, ")") {
		// Check trailing `else if (...)`
		if idx := strings.LastIndex(t, "else"); idx > 0 && !isIdentByte(t[idx-1]) {
			tail := strings.TrimSpace(t[idx+4:])
			if strings.HasPrefix(tail, "if") && (len(tail) == 2 || tail[2] == ' ' || tail[2] == '\t' || tail[2] == '(') {
				op := strings.IndexByte(tail, '(')
				cp := findMatchingDelimiter(tail, op, '(', ')')
				if op > 0 && cp == len(tail)-1 {
					return true
				}
			}
		}
	}
	return false
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
		if hasElseKeywordPrefix(afterThen) {
			elseRest := strings.TrimSpace(afterThen[4:])
			if strings.HasPrefix(elseRest, "{") && findMatchingDelimiter(elseRest, 0, '{', '}') == len(elseRest)-1 {
				elseBody = elseRest[1 : len(elseRest)-1]
			} else {
				elseBody = elseRest
			}
		}
		return cond, thenBody, elseBody, true
	}
	// Braceless `if (cond) thenStmt; else elseStmt`
	braceDepth := 0
	parenDepth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(rest); i++ {
		if stepQuoteState(rest, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch rest[i] {
		case '(', '[':
			parenDepth++
		case ')', ']':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				after := strings.TrimSpace(rest[i+1:])
				if hasElseKeywordPrefix(after) {
					thenBody = strings.TrimSpace(rest[:i])
					elseRest := strings.TrimSpace(after[4:])
					if strings.HasPrefix(elseRest, "{") && findMatchingDelimiter(elseRest, 0, '{', '}') == len(elseRest)-1 {
						elseBody = elseRest[1 : len(elseRest)-1]
					} else {
						elseBody = elseRest
					}
					return cond, thenBody, elseBody, true
				}
			}
		}
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
		case '(', '[':
			parenDepth++
			curr.WriteByte(c)
		case ')', ']':
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
			if braceDepth == 0 && parenDepth == 0 && isControlBlockStmt(curr.String()) {
				rem := strings.TrimSpace(s[i+1:])
				if !hasElseKeywordPrefix(rem) {
					out = append(out, curr.String())
					curr.Reset()
				}
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				rem := strings.TrimSpace(s[i+1:])
				if c == '\n' && (hasElseKeywordPrefix(rem) || isIncompleteControlHeader(curr.String()) || hasTrailingContinuationOp(curr.String())) {
					curr.WriteByte(c)
					continue
				}
				if c == ';' && isControlBlockStmt(curr.String()) && hasElseKeywordPrefix(rem) {
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

func resolveDocValuesSlice(sourceMap map[string]any, fieldPath string) []any {
	if sourceMap == nil || fieldPath == "" {
		return []any{}
	}
	val := resolveParamPath(sourceMap, strings.Split(fieldPath, "."))
	if val == nil && (strings.HasSuffix(fieldPath, ".keyword") || strings.HasSuffix(fieldPath, "\x00keyword")) {
		kwTrimmed := strings.TrimSuffix(strings.TrimSuffix(fieldPath, ".keyword"), "\x00keyword")
		val = resolveParamPath(sourceMap, strings.Split(kwTrimmed, "."))
	}
	if val == nil {
		return []any{}
	}
	if slice, ok := val.([]any); ok {
		out := make([]any, 0, len(slice))
		for _, item := range slice {
			if item != nil {
				out = append(out, item)
			}
		}
		return out
	}
	return []any{val}
}

func resolveParamPath(params map[string]any, path []string) any {
	var curr any = params
	for i, rawSeg := range path {
		seg := decodeBracketSeg(rawSeg)
		if slice, isSlice := curr.([]any); isSlice {
			if idx, ok := parseSliceIndex(seg, len(slice)); ok {
				curr = slice[idx]
				continue
			}
			if i == len(path)-1 {
				if seg == "length" {
					return int64(len(slice))
				}
				if seg == "empty" {
					return len(slice) == 0
				}
			}
			var projected []any
			for _, elem := range slice {
				if em, ok := elem.(map[string]any); ok {
					if v := resolveParamPath(em, path[i:]); v != nil {
						if subSlice, isSub := v.([]any); isSub {
							projected = append(projected, subSlice...)
						} else {
							projected = append(projected, v)
						}
					}
				}
			}
			if len(projected) == 0 {
				return nil
			}
			return projected
		}
		if strVal, isStr := curr.(string); isStr && i == len(path)-1 {
			if seg == "length" {
				return int64(len(strVal))
			}
			if seg == "empty" {
				return len(strVal) == 0
			}
		}
		m, ok := curr.(map[string]any)
		if !ok {
			return nil
		}
		val, exists := m[seg]
		if !exists {
			if strings.Contains(seg, ".") {
				return resolveParamPath(m, append(strings.Split(seg, "."), path[i+1:]...))
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
	inQuotes := byte(0)
	inRegexClass := false
	last := 0
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
	inQuotes := byte(0)
	inRegexClass := false
	lastCallEnd := -1
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		ch := s[i]
		if ch == '(' || ch == '[' {
			depth++
			continue
		}
		if ch == ')' || ch == ']' {
			if depth > 0 {
				depth--
			}
			if depth == 0 && i+1 < len(s) {
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

func removeKeyOrIndexAtPath(root map[string]any, parentPath []string, keyOrIdx any) any {
	if len(parentPath) == 0 {
		if root == nil || keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		old := root[k]
		delete(root, k)
		return old
	}
	switch target := resolveParamPath(root, parentPath).(type) {
	case map[string]any:
		if keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		old := target[k]
		delete(target, k)
		return old
	case []any:
		removeAt := func(idx int) any {
			old := target[idx]
			next := make([]any, 0, len(target)-1)
			next = append(next, target[:idx]...)
			next = append(next, target[idx+1:]...)
			setValueAtPath(root, parentPath, next)
			return old
		}
		if _, isStr := keyOrIdx.(string); !isStr {
			if idx, ok := parseSliceIndex(fmt.Sprintf("%v", keyOrIdx), len(target)); ok {
				return removeAt(idx)
			}
		}
		for idx, elem := range target {
			if valuesEqual(elem, keyOrIdx) {
				_ = removeAt(idx)
				return true
			}
		}
	}
	return nil
}

func setSliceElementAtPath(root map[string]any, arrPath []string, idxVal any, newVal any) any {
	if idxVal == nil {
		return nil
	}
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return nil
	}
	f, fOk := toFloat64(idxVal)
	if !fOk {
		return nil
	}
	idx, okIdx := parseSliceIndex(strconv.Itoa(int(f)), len(existing))
	if !okIdx {
		return nil
	}
	prev := existing[idx]
	next := make([]any, len(existing))
	copy(next, existing)
	next[idx] = newVal
	setValueAtPath(root, arrPath, next)
	return prev
}

func insertIntoSliceAtPath(root map[string]any, path []string, idxVal any, val any) error {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	f, fOk := toFloat64(idxVal)
	idx := len(existing)
	if fOk {
		idx = int(f)
		if idx < 0 {
			idx = 0
		} else if idx > len(existing) {
			idx = len(existing)
		}
	}
	next := make([]any, 0, len(existing)+1)
	next = append(next, existing[:idx]...)
	next = append(next, val)
	next = append(next, existing[idx:]...)
	setValueAtPath(root, path, next)
	return nil
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

func applyBitwiseAssign(curVal, rhsVal any, op string) any {
	lf, ok1 := toFloat64(curVal)
	rf, ok2 := toFloat64(rhsVal)
	if !ok1 || !ok2 {
		return int64(0)
	}
	li := int64(lf)
	ri := int64(rf)
	shift := ri & 63
	switch op {
	case "&=":
		return li & ri
	case "|=":
		return li | ri
	case "^=":
		return li ^ ri
	case "<<=":
		return li << shift
	case ">>=":
		return li >> shift
	case ">>>=":
		if shift == 0 {
			return li
		}
		return ((li >> 1) & math.MaxInt64) >> (shift - 1)
	}
	return li
}

func parsePainlessDateTime(v any) (time.Time, bool) {
	switch tv := v.(type) {
	case string:
		s := strings.TrimSpace(tv)
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999Z0700",
			"2006-01-02T15:04:05Z0700",
			"2006-01-02 15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05Z07:00",
			"2006-01-02 15:04:05.999999999Z0700",
			"2006-01-02 15:04:05Z0700",
			"2006-01-02T15:04:05.999999999",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		} {
			if tm, err := time.Parse(layout, s); err == nil {
				return tm, true
			}
		}
	case int, int64, float64, json.Number:
		if f, ok := toFloat64(tv); ok {
			return time.UnixMilli(int64(f)).UTC(), true
		}
	}
	return time.Time{}, false
}

func mutateSliceRemoveOrRetainAtPath(root map[string]any, arrPath []string, argVal any, isRetain bool) bool {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return false
	}
	needles, ok2 := argVal.([]any)
	if !ok2 {
		return false
	}
	filtered := make([]any, 0, len(existing))
	for _, elem := range existing {
		inNeedles := false
		for _, needle := range needles {
			if valuesEqual(elem, needle) {
				inNeedles = true
				break
			}
		}
		if (isRetain && inNeedles) || (!isRetain && !inNeedles) {
			filtered = append(filtered, elem)
		}
	}
	changed := len(filtered) != len(existing)
	setValueAtPath(root, arrPath, filtered)
	return changed
}

func evalBitwiseOrShiftPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	tiers := [][]string{
		{"|"},
		{"^"},
		{"&"},
		{">>>", "<<", ">>"},
	}
	for _, tier := range tiers {
		idx, op := findLastTopLevelOpPainless(rhs, tier...)
		if idx <= 0 {
			continue
		}
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[:idx]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[idx+len(op):]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		lf, ok1 := toFloat64(leftVal)
		rf, ok2 := toFloat64(rightVal)
		if !ok1 || !ok2 {
			return int64(0), true, nil
		}
		li := int64(lf)
		ri := int64(rf)
		shift := ri & 63
		switch op {
		case "|":
			return li | ri, true, nil
		case "^":
			return li ^ ri, true, nil
		case "&":
			return li & ri, true, nil
		case "<<":
			return li << shift, true, nil
		case ">>":
			return li >> shift, true, nil
		case ">>>":
			if shift == 0 {
				return li, true, nil
			}
			return ((li >> 1) & math.MaxInt64) >> (shift - 1), true, nil
		}
	}
	return nil, false, nil
}

func removeIfCondFromSlice(sourceMap, root map[string]any, arrPath []string, paramName, condExpr string, params map[string]any) bool {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return false
	}
	condExpr = strings.TrimSpace(condExpr)
	if strings.HasPrefix(condExpr, "{") && strings.HasSuffix(condExpr, "}") {
		condExpr = strings.TrimSpace(condExpr[1 : len(condExpr)-1])
	}
	condExpr = strings.TrimSpace(strings.TrimSuffix(condExpr, ";"))
	if strings.HasPrefix(condExpr, "return ") || strings.HasPrefix(condExpr, "return(") {
		condExpr = strings.TrimSpace(strings.TrimPrefix(condExpr, "return"))
	}
	itemParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		itemParams[k] = v
	}
	filtered := make([]any, 0, len(existing))
	for _, item := range existing {
		itemParams[paramName] = item
		if evalCondition(sourceMap, condExpr, itemParams) {
			continue
		}
		filtered = append(filtered, item)
	}
	changed := len(filtered) != len(existing)
	setValueAtPath(root, arrPath, filtered)
	return changed
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

func clearAtPath(root map[string]any, path []string) {
	if len(path) == 0 {
		for k := range root {
			delete(root, k)
		}
		return
	}
	switch target := resolveParamPath(root, path).(type) {
	case map[string]any:
		for k := range target {
			delete(target, k)
		}
	case []any:
		setValueAtPath(root, path, []any{})
	}
}

func evalStaticCallPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	openParen := strings.IndexByte(rhs, '(')
	if openParen <= 0 || !strings.HasSuffix(rhs, ")") || findMatchingDelimiter(rhs, openParen, '(', ')') != len(rhs)-1 {
		return nil, false, nil
	}
	fnName := strings.TrimSpace(rhs[:openParen])
	argStr := strings.TrimSpace(rhs[openParen+1 : len(rhs)-1])
	args := splitTopLevelCommaPainless(argStr)

	evalNumArg := func(idx int) (float64, bool) {
		if idx >= len(args) {
			return 0, false
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil || v == nil {
			return 0, false
		}
		return toFloat64(v)
	}
	formatMathResult := func(res float64) any {
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}

	switch fnName {
	case "Math.abs":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Abs(f)), true, nil
		}
		return int64(0), true, nil
	case "Math.min":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Min(f1, f2)), true, nil
		}
		return int64(0), true, nil
	case "Math.max":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Max(f1, f2)), true, nil
		}
		return int64(0), true, nil
	case "Math.round":
		if f, ok := evalNumArg(0); ok {
			return int64(math.Floor(f + 0.5)), true, nil
		}
		return int64(0), true, nil
	case "Math.floor":
		if f, ok := evalNumArg(0); ok {
			return math.Floor(f), true, nil
		}
		return float64(0), true, nil
	case "Math.ceil":
		if f, ok := evalNumArg(0); ok {
			return math.Ceil(f), true, nil
		}
		return float64(0), true, nil
	case "Math.pow":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Pow(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.sqrt":
		if f, ok := evalNumArg(0); ok && f >= 0 {
			return formatMathResult(math.Sqrt(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.hypot":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Hypot(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.log":
		if f, ok := evalNumArg(0); ok && f > 0 {
			return formatMathResult(math.Log(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.log10":
		if f, ok := evalNumArg(0); ok && f > 0 {
			return formatMathResult(math.Log10(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.exp":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Exp(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.signum":
		if f, ok := evalNumArg(0); ok {
			if f > 0 {
				return float64(1), true, nil
			}
			if f < 0 {
				return float64(-1), true, nil
			}
		}
		return float64(0), true, nil
	case "Math.clamp":
		v, ok1 := evalNumArg(0)
		lo, ok2 := evalNumArg(1)
		hi, ok3 := evalNumArg(2)
		if ok1 && ok2 && ok3 {
			return formatMathResult(math.Min(math.Max(v, lo), hi)), true, nil
		}
		return int64(0), true, nil
	case "Integer.parseInt", "Long.parseLong":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			base := 10
			if len(args) >= 2 {
				if bf, ok := evalNumArg(1); ok && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			if iv, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", v)), base, 64); err == nil {
				return iv, true, nil
			}
		}
		return int64(0), true, nil
	case "Double.parseDouble", "Float.parseFloat":
		if f, ok := evalNumArg(0); ok {
			return f, true, nil
		}
		return float64(0), true, nil
	case "String.valueOf":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			return fmt.Sprintf("%v", v), true, nil
		}
		return "", true, nil
	case "String.format":
		if len(args) >= 1 {
			fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			fmtStr := fmt.Sprintf("%v", fmtVal)
			fmtArgs := make([]any, 0, len(args)-1)
			for _, a := range args[1:] {
				av, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
				if jn, isJN := av.(json.Number); isJN {
					if iv, err := jn.Int64(); err == nil {
						av = iv
					} else if fv, err := jn.Float64(); err == nil {
						av = fv
					}
				}
				fmtArgs = append(fmtArgs, av)
			}
			return fmt.Sprintf(fmtStr, fmtArgs...), true, nil
		}
		return "", true, nil
	case "String.join":
		if len(args) >= 2 {
			sepVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			sepStr := fmt.Sprintf("%v", sepVal)
			if len(args) == 2 {
				colExpr := strings.TrimSpace(args[1])
				var colVal any
				if (strings.HasPrefix(colExpr, "doc.") || strings.HasPrefix(colExpr, "doc?.")) &&
					!strings.HasSuffix(colExpr, ".value") && !strings.Contains(colExpr, ".values.") {
					docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(colExpr, "doc?."), "doc."), ".values")
					colVal = resolveDocValuesSlice(sourceMap, docPath)
				} else {
					colVal, _ = evalRHSExprDepth(sourceMap, colExpr, params, depth+1)
				}
				if tv, ok := colVal.([]any); ok {
					parts := make([]string, len(tv))
					for i, item := range tv {
						parts[i] = fmt.Sprintf("%v", item)
					}
					return strings.Join(parts, sepStr), true, nil
				}
				if colVal != nil {
					return fmt.Sprintf("%v", colVal), true, nil
				}
				return "", true, nil
			}
			parts := make([]string, len(args)-1)
			for i := 1; i < len(args); i++ {
				itemVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i]), params, depth+1)
				parts[i-1] = fmt.Sprintf("%v", itemVal)
			}
			return strings.Join(parts, sepStr), true, nil
		}
		return "", true, nil
	case "Collections.sort":
		if len(args) >= 1 {
			listVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if arr, ok := listVal.([]any); ok {
				cmpExpr := ""
				if len(args) >= 2 {
					cmpExpr = strings.TrimSpace(args[1])
				}
				sortPainlessSliceInPlace(arr, cmpExpr, sourceMap, params, depth+1)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Collections.reverse":
		if len(args) >= 1 {
			listVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if arr, ok := listVal.([]any); ok {
				for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
					arr[i], arr[j] = arr[j], arr[i]
				}
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Instant.ofEpochMilli":
		if f, ok := evalNumArg(0); ok {
			return time.UnixMilli(int64(f)).UTC().Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	case "Instant.ofEpochSecond":
		if f, ok := evalNumArg(0); ok {
			return time.Unix(int64(f), 0).UTC().Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	case "Instant.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if tm, ok := parsePainlessDateTime(v); ok {
				return tm.UTC().Format(time.RFC3339Nano), true, nil
			}
		}
		return nil, true, nil
	case "ZonedDateTime.parse", "LocalDateTime.parse", "LocalDate.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if tm, ok := parsePainlessDateTime(v); ok {
				return tm.Format(time.RFC3339Nano), true, nil
			}
		}
		return nil, true, nil
	case "ChronoUnit.DAYS.between", "ChronoUnit.HOURS.between", "ChronoUnit.MINUTES.between", "ChronoUnit.SECONDS.between", "ChronoUnit.MILLIS.between":
		if len(args) >= 2 {
			v1, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			v2, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			t1, ok1 := parsePainlessDateTime(v1)
			t2, ok2 := parsePainlessDateTime(v2)
			if ok1 && ok2 {
				diffMs := t2.UnixMilli() - t1.UnixMilli()
				switch fnName {
				case "ChronoUnit.DAYS.between":
					return diffMs / 86400000, true, nil
				case "ChronoUnit.HOURS.between":
					return diffMs / 3600000, true, nil
				case "ChronoUnit.MINUTES.between":
					return diffMs / 60000, true, nil
				case "ChronoUnit.SECONDS.between":
					return diffMs / 1000, true, nil
				case "ChronoUnit.MILLIS.between":
					return diffMs, true, nil
				}
			}
		}
		return int64(0), true, nil
	}
	return nil, false, nil
}

func normalizeJavaRegexReplacement(repl string) string {
	var sb strings.Builder
	sb.Grow(len(repl) + 8)
	for i := 0; i < len(repl); i++ {
		if repl[i] == '\\' && i+1 < len(repl) {
			i++
			if repl[i] == '$' {
				sb.WriteString("$$")
			} else {
				sb.WriteByte(repl[i])
			}
			continue
		}
		if repl[i] == '$' && i+1 < len(repl) && repl[i+1] >= '0' && repl[i+1] <= '9' {
			j := i + 1
			for j < len(repl) && repl[j] >= '0' && repl[j] <= '9' {
				j++
			}
			sb.WriteString("${")
			sb.WriteString(repl[i+1 : j])
			sb.WriteByte('}')
			i = j - 1
			continue
		}
		sb.WriteByte(repl[i])
	}
	return sb.String()
}

func comparePainlessValues(a, b any) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	fa, okA := toFloat64(a)
	fb, okB := toFloat64(b)
	if okA && okB {
		if fa < fb {
			return -1
		}
		if fa > fb {
			return 1
		}
		return 0
	}
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

func sortPainlessSliceInPlace(arr []any, cmpExpr string, sourceMap, params map[string]any, depth int) {
	if len(arr) <= 1 {
		return
	}
	cmpExpr = strings.TrimSpace(cmpExpr)
	if strings.Contains(cmpExpr, "reverseOrder") {
		sort.SliceStable(arr, func(i, j int) bool {
			return comparePainlessValues(arr[i], arr[j]) > 0
		})
		return
	}
	if arrowIdx := strings.Index(cmpExpr, "->"); arrowIdx > 0 {
		lhs := strings.TrimSpace(cmpExpr[:arrowIdx])
		lhs = strings.TrimPrefix(strings.TrimSuffix(lhs, ")"), "(")
		paramParts := strings.Split(lhs, ",")
		if len(paramParts) == 2 {
			fA := strings.Fields(paramParts[0])
			fB := strings.Fields(paramParts[1])
			if len(fA) > 0 && len(fB) > 0 {
				pA := fA[len(fA)-1]
				pB := fB[len(fB)-1]
				body := strings.TrimSpace(cmpExpr[arrowIdx+2:])
				if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
					body = strings.TrimSpace(body[1 : len(body)-1])
				}
				body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
				if strings.HasPrefix(body, "return ") || strings.HasPrefix(body, "return(") {
					body = strings.TrimSpace(strings.TrimPrefix(body, "return"))
				}
				cmpParams := make(map[string]any, len(params)+2)
				for k, v := range params {
					cmpParams[k] = v
				}
				sort.SliceStable(arr, func(i, j int) bool {
					cmpParams[pA] = arr[i]
					cmpParams[pB] = arr[j]
					res, err := evalRHSExprDepth(sourceMap, body, cmpParams, depth+1)
					if err != nil || res == nil {
						return false
					}
					if f, ok := toFloat64(res); ok {
						return f < 0
					}
					if b, ok := res.(bool); ok {
						return b
					}
					return false
				})
				return
			}
		}
	}
	sort.SliceStable(arr, func(i, j int) bool {
		return comparePainlessValues(arr[i], arr[j]) < 0
	})
}
