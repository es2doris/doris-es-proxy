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
	"unicode/utf8"
)

var (
	errPainlessReturn   = errors.New("painless_return")
	errPainlessBreak    = errors.New("painless_break")
	errPainlessContinue = errors.New("painless_continue")
)

type painlessExceptionError struct {
	exType  string
	message string
}

func (e *painlessExceptionError) Error() string {
	if e.exType != "" && e.message != "" {
		return e.exType + ": " + e.message
	}
	if e.exType != "" {
		return e.exType
	}
	return e.message
}

// UpdateRequest models an Elasticsearch `/_update/<id>` or `/_update_by_query` mutation spec.
type UpdateRequest struct {
	Doc                map[string]any `json:"doc,omitempty"`
	DocAsUpsert        bool           `json:"doc_as_upsert,omitempty"`
	DetectNoop         *bool          `json:"detect_noop,omitempty"`
	Upsert             map[string]any `json:"upsert,omitempty"`
	ScriptedUpsert     bool           `json:"scripted_upsert,omitempty"`
	Script             *ScriptSpec    `json:"script,omitempty"`
	MetaID             string         `json:"-"`
	MetaIndex          string         `json:"-"`
	MetaRouting        string         `json:"-"`
	MetaVersion        int64          `json:"-"`
	MetaVersionNil     bool           `json:"-"`
	MetaVersionMutated bool           `json:"-"`
	MetaOp             string         `json:"-"`
	AllowMetaMutation  bool           `json:"-"`
}

type ScriptSpec struct {
	Source string         `json:"source"`
	Lang   string         `json:"lang,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

var (
	reCtxOp                = regexp.MustCompile(`(?s)^ctx\??\.op\s*=\s*(.+)$`)
	reCtxIncDec            = regexp.MustCompile(`^(?:(\+\+|--)\s*ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)|ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*(\+\+|--))$`)
	reCompoundAssign       = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reAssignParam          = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*=\s*(.+)$`)
	reRemoveField          = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.remove\(\s*(.+?)\s*\)$`)
	reClearField           = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.clear\(\s*\)$`)
	reArrayAdd             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.add\(\s*(.+?)\s*\)$`)
	reArraySet             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.set\(\s*(.+)\s*\)$`)
	reArrayAddAll          = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.addAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.removeAll\(\s*(.+?)\s*\)$`)
	reArrayRetainAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.retainAll\(\s*(.+?)\s*\)$`)
	reMapPut               = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.put\(\s*(.+)\s*\)$`)
	reMapPutAll            = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.putAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveIf        = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.removeIf\(\s*\(?\s*(?:[a-zA-Z_$][a-zA-Z0-9_$<>[\]]*\s+)?([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalIncDec          = regexp.MustCompile(`^(?:(\+\+|--)\s*([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)|([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\s*(\+\+|--))$`)
	reLocalRemoveField     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.remove\(\s*(.+?)\s*\)$`)
	reLocalClearField      = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.clear\(\s*\)$`)
	reLocalArrayAdd        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.add\(\s*(.+?)\s*\)$`)
	reLocalArraySet        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.set\(\s*(.+)\s*\)$`)
	reLocalArrayAddAll     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.addAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.removeAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRetainAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.retainAll\(\s*(.+?)\s*\)$`)
	reLocalMapPut          = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.put\(\s*(.+)\s*\)$`)
	reLocalMapPutAll       = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.putAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveIf   = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.removeIf\(\s*\(?\s*(?:[a-zA-Z_$][a-zA-Z0-9_$<>[\]]*\s+)?([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalCompoundAssign  = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reLocalPropAssign      = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*)\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*=\s*(.+)$`)
	reLocalVarAssign       = regexp.MustCompile(`(?s)^(?:(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate|Pattern|Matcher)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)$`)
	reNullVarDecl          = regexp.MustCompile(`^(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate|Pattern|Matcher)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)$`)
	reVarTypeDeclPrefix    = regexp.MustCompile(`(?s)^((?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate|Pattern|Matcher)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*)\s+(.+)$`)
	reUserFuncHeaderPrefix = regexp.MustCompile(`^(void|def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|Object|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|LinkedList|Set|HashSet|ZonedDateTime|Instant|LocalDateTime|LocalDate|Pattern|Matcher)(?:\s*<[^>]*>)?(?:\s*\[\s*\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)$`)
	reIdentAssign          = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)$`)
	reIdentOnly            = regexp.MustCompile(`^[a-zA-Z_$][a-zA-Z0-9_$]*$`)
	reSimpleFieldPath      = regexp.MustCompile(`^[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+$`)
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
		} else if req.DocAsUpsert && req.Doc != nil {
			deepMergeMap(doc, req.Doc)
			out, err := json.Marshal(doc)
			return json.RawMessage(out), "created", err
		}
	}

	detectNoop := req.DetectNoop == nil || *req.DetectNoop
	var preMergeSnapshot []byte
	if docExisted && detectNoop && req.Doc != nil && (req.Script == nil || strings.TrimSpace(req.Script.Source) == "") {
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
		scriptParams := make(map[string]any, len(req.Script.Params)+5)
		for k, v := range req.Script.Params {
			scriptParams[k] = v
		}
		if req.MetaID != "" {
			scriptParams["_ctx_id"] = req.MetaID
		}
		if req.MetaIndex != "" {
			scriptParams["_ctx_index"] = req.MetaIndex
		}
		if req.MetaRouting != "" {
			scriptParams["_ctx_routing"] = req.MetaRouting
		}
		if req.MetaVersion != 0 {
			scriptParams["_ctx_version"] = req.MetaVersion
		}
		if req.MetaOp != "" {
			scriptParams["_ctx_op"] = req.MetaOp
		}
		if !req.AllowMetaMutation {
			scriptParams["__readonly_ctx_meta"] = true
		}
		ctxOp, err := EvalPainlessWithOp(doc, req.Script.Source, scriptParams)
		if err != nil {
			return nil, "", err
		}
		if ctxOp != "" {
			req.MetaOp = ctxOp
		}
		if v, exists := scriptParams["_ctx_routing"]; exists {
			if v == nil {
				req.MetaRouting = ""
			} else {
				req.MetaRouting = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		if req.AllowMetaMutation {
			if v, exists := scriptParams["_ctx_id"]; exists {
				if v == nil {
					req.MetaID = ""
				} else if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
					req.MetaID = s
				}
			}
			if v, exists := scriptParams["_ctx_index"]; exists {
				if v == nil {
					req.MetaIndex = ""
				} else if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
					req.MetaIndex = s
				}
			}
			if v, exists := scriptParams["_ctx_version"]; exists {
				if v == nil {
					req.MetaVersion = 0
					req.MetaVersionNil = true
				} else if vf, ok := toFloat64(v); ok {
					req.MetaVersion = int64(vf)
					req.MetaVersionNil = false
				}
			}
			if mut, ok := scriptParams["_ctx_version_mutated"].(bool); ok && mut {
				req.MetaVersionMutated = true
			}
		}
		switch strings.ToLower(ctxOp) {
		case "noop", "none":
			return rawSource, "noop", nil
		case "delete", "drop":
			opResult = "deleted"
		case "create":
			opResult = "created"
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	if len(preMergeSnapshot) > 0 && jsonBytesSemanticallyEqual(preMergeSnapshot, out) {
		return rawSource, "noop", nil
	}
	return json.RawMessage(out), opResult, nil
}

func jsonBytesSemanticallyEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

const (
	MaxPainlessSteps       = 10_000
	MaxPainlessDepth       = 32
	MaxPainlessSliceItems  = 10_000
	MaxPainlessStringBytes = MaxPainlessSliceItems * 100
)

type painlessUserFunc struct {
	name       string
	returnType string
	paramNames []string
	body       string
}

type painlessMatcher struct {
	re        *regexp.Regexp
	input     string
	curPos    int
	lastMatch []int
}

type evalBudget struct {
	steps         int
	depth         int
	ctxOp         string
	hasCtxOp      bool
	ctxID         any
	hasCtxID      bool
	ctxIndex      any
	hasCtxIndex   bool
	ctxRouting    any
	hasCtxRouting bool
	ctxVersion    any
	hasCtxVersion bool
	userFuncs     map[string]*painlessUserFunc
}

func latchCtxMetaOnBudget(budget *evalBudget, path []string, val any) {
	if budget == nil || len(path) != 1 {
		return
	}
	switch path[0] {
	case "_ctx_id":
		budget.ctxID = val
		budget.hasCtxID = true
	case "_ctx_index":
		budget.ctxIndex = val
		budget.hasCtxIndex = true
	case "_ctx_routing":
		budget.ctxRouting = val
		budget.hasCtxRouting = true
	case "_ctx_version":
		budget.ctxVersion = val
		budget.hasCtxVersion = true
	case "_ctx_op":
		if val == nil {
			budget.ctxOp = ""
		} else {
			budget.ctxOp = fmt.Sprintf("%v", val)
		}
		budget.hasCtxOp = true
	}
}

func isInternalPainlessMapKey(m map[string]any, k string) bool {
	if strings.HasPrefix(k, "__") {
		return true
	}
	switch k {
	case "_source", "_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_version_mutated", "_ctx_op", "_return_val", "_last_expr_val":
		return true
	}
	if m != nil {
		if sl, ok := m["__script_locals"].(map[string]bool); ok && sl[k] {
			return true
		}
		if ld, ok := m["__loop_declared"].(map[string]bool); ok && ld[k] {
			return true
		}
	}
	return false
}

func visiblePainlessMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if isInternalPainlessMapKey(m, k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func visiblePainlessMapLen(m map[string]any) int {
	n := 0
	for k := range m {
		if !isInternalPainlessMapKey(m, k) {
			n++
		}
	}
	return n
}

func markExplicitParamsKey(params map[string]any, key string) {
	if params == nil || key == "" {
		return
	}
	if sl, ok := params["__script_locals"].(map[string]bool); ok {
		delete(sl, key)
	}
	if ld, ok := params["__loop_declared"].(map[string]bool); ok {
		delete(ld, key)
	}
	if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
		ep[key] = true
	} else {
		params["__explicit_params_keys"] = map[string]bool{key: true}
	}
}

func unmarkExplicitParamsKey(params map[string]any, key string) {
	if params == nil || key == "" {
		return
	}
	if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
		delete(ep, key)
	}
}

func parseUserFuncDecl(stmt string) (*painlessUserFunc, bool) {
	t := strings.TrimSpace(stmt)
	openP := strings.IndexByte(t, '(')
	if openP <= 0 {
		return nil, false
	}
	headerPrefix := strings.TrimSpace(t[:openP])
	m := reUserFuncHeaderPrefix.FindStringSubmatch(headerPrefix)
	if m == nil {
		return nil, false
	}
	closeP := findMatchingDelimiter(t, openP, '(', ')')
	if closeP < 0 {
		return nil, false
	}
	rest := strings.TrimSpace(t[closeP+1:])
	if !strings.HasPrefix(rest, "{") || findMatchingDelimiter(rest, 0, '{', '}') != len(rest)-1 {
		return nil, false
	}
	paramStr := strings.TrimSpace(t[openP+1 : closeP])
	var paramNames []string
	if paramStr != "" {
		for _, p := range splitTopLevelCommaPainless(paramStr) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if closeIdx := strings.LastIndexAny(p, ">]"); closeIdx >= 0 && closeIdx+1 < len(p) {
				p = strings.TrimSpace(p[closeIdx+1:])
			}
			fields := strings.Fields(p)
			if len(fields) > 0 {
				paramNames = append(paramNames, fields[len(fields)-1])
			}
		}
	}
	return &painlessUserFunc{
		name:       m[2],
		returnType: m[1],
		paramNames: paramNames,
		body:       strings.TrimSpace(rest[1 : len(rest)-1]),
	}, true
}

func (b *evalBudget) step() error {
	b.steps++
	if b.steps > MaxPainlessSteps {
		return fmt.Errorf("painless script exceeded maximum step budget (%d)", MaxPainlessSteps)
	}
	return nil
}

func getOrInitEvalBudget(params map[string]any) *evalBudget {
	if params != nil {
		if b, ok := params["__eval_budget"].(*evalBudget); ok && b != nil {
			return b
		}
		b := &evalBudget{}
		params["__eval_budget"] = b
		return b
	}
	return &evalBudget{}
}

// Eval evaluates a Painless script expression or multi-statement block and returns its result value.
func Eval(sourceMap map[string]any, scriptSource string, params map[string]any) (any, error) {
	evalParams := make(map[string]any, len(params)+4)
	explicitParams := make(map[string]bool, len(params))
	for k, v := range params {
		evalParams[k] = v
		if !isInternalPainlessMapKey(nil, k) {
			explicitParams[k] = true
		}
	}
	evalParams["__script_locals"] = make(map[string]bool)
	evalParams["__explicit_params_keys"] = explicitParams
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
	if budget.hasCtxOp {
		evalParams["_ctx_op"] = budget.ctxOp
	} else if ctxOp != "" {
		evalParams["_ctx_op"] = ctxOp
	}
	if budget.hasCtxID {
		evalParams["_ctx_id"] = budget.ctxID
	}
	if budget.hasCtxIndex {
		evalParams["_ctx_index"] = budget.ctxIndex
	}
	if budget.hasCtxRouting {
		evalParams["_ctx_routing"] = budget.ctxRouting
	}
	if budget.hasCtxVersion {
		evalParams["_ctx_version"] = budget.ctxVersion
	}
	if params != nil {
		for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_op"} {
			if v, exists := evalParams[metaKey]; exists {
				params[metaKey] = v
			}
		}
	}
	if err != nil && !errors.Is(err, errPainlessReturn) {
		return nil, err
	}
	if retVal, hasRet := evalParams["_return_val"]; hasRet {
		return retVal, nil
	}
	if len(stmts) > 0 {
		lastStmt := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmts[len(stmts)-1]), ";"))
		hasExplicitReturn := false
		if strings.HasPrefix(lastStmt, "return ") || strings.HasPrefix(lastStmt, "return(") {
			lastStmt = strings.TrimSpace(strings.TrimPrefix(lastStmt, "return"))
			hasExplicitReturn = true
		}
		if lastStmt != "" && lastStmt != "return" && !strings.HasPrefix(lastStmt, "if ") && !strings.HasPrefix(lastStmt, "if(") && !strings.HasPrefix(lastStmt, "for ") && !strings.HasPrefix(lastStmt, "for(") && !strings.HasPrefix(lastStmt, "while ") && !strings.HasPrefix(lastStmt, "while(") && !strings.HasPrefix(lastStmt, "switch ") && !strings.HasPrefix(lastStmt, "switch(") && !strings.HasPrefix(lastStmt, "try ") && !strings.HasPrefix(lastStmt, "try{") && !strings.HasPrefix(lastStmt, "do ") && !strings.HasPrefix(lastStmt, "do{") && !strings.HasPrefix(lastStmt, "throw ") {
			isAggStateMutation := !hasExplicitReturn && isTopLevelAssignmentStmt(lastStmt) &&
				(strings.HasPrefix(lastStmt, "_agg.") || strings.HasPrefix(lastStmt, "_agg[") ||
					strings.HasPrefix(lastStmt, "state.") || strings.HasPrefix(lastStmt, "state["))
			if !isAggStateMutation {
				if lastVal, hasLast := evalParams["_last_expr_val"]; hasLast {
					return lastVal, nil
				}
			}
			if !isTopLevelAssignmentStmt(lastStmt) {
				val, evalErr := evalRHSExpr(sourceMap, lastStmt, evalParams)
				if evalErr == nil && (val != nil || findTopLevelOpPainless(lastStmt, "?") > 0 || findTopLevelOpPainless(lastStmt, "?:") > 0) {
					return val, nil
				}
				if strings.ContainsAny(lastStmt, "><=!&|") || strings.Contains(lastStmt, ".empty") || strings.Contains(lastStmt, ".contains(") || strings.Contains(lastStmt, ".startsWith(") || strings.Contains(lastStmt, ".endsWith(") || strings.Contains(lastStmt, ".isEmpty()") || strings.Contains(lastStmt, ".matches(") || strings.Contains(lastStmt, ".containsKey(") || strings.Contains(lastStmt, ".equals(") || strings.Contains(lastStmt, ".equalsIgnoreCase(") {
					return evalCondition(sourceMap, lastStmt, evalParams), nil
				}
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
	origVer, hadOrigVer := params["_ctx_version"]
	evalParams := make(map[string]any, len(params)+6)
	explicitParams := make(map[string]bool, len(params))
	for k, v := range params {
		evalParams[k] = v
		if !isInternalPainlessMapKey(nil, k) {
			explicitParams[k] = true
		}
	}
	evalParams["__script_locals"] = make(map[string]bool)
	evalParams["__explicit_params_keys"] = explicitParams
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
	if budget.hasCtxOp {
		ctxOp = budget.ctxOp
	} else if ctxOp == "" {
		if opStr, ok := evalParams["_ctx_op"].(string); ok && opStr != "" {
			ctxOp = opStr
		}
	}
	if budget.hasCtxID {
		evalParams["_ctx_id"] = budget.ctxID
	}
	if budget.hasCtxIndex {
		evalParams["_ctx_index"] = budget.ctxIndex
	}
	if budget.hasCtxRouting {
		evalParams["_ctx_routing"] = budget.ctxRouting
	}
	if budget.hasCtxVersion {
		evalParams["_ctx_version"] = budget.ctxVersion
	}
	if params != nil {
		for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version"} {
			if v, exists := evalParams[metaKey]; exists {
				params[metaKey] = v
			}
		}
		if budget.hasCtxVersion {
			params["_ctx_version_mutated"] = true
		} else if curV, hasCur := evalParams["_ctx_version"]; hasCur && (!hadOrigVer || !reflect.DeepEqual(curV, origVer)) {
			params["_ctx_version_mutated"] = true
		}
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
	if params != nil && budget != nil {
		params["__eval_budget"] = budget
	}
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
		if strings.HasPrefix(stmt, "do") && (len(stmt) == 2 || stmt[2] == ' ' || stmt[2] == '\t' || stmt[2] == '\n' || stmt[2] == '{') {
			if err := execDoWhileStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "try") && (len(stmt) == 3 || stmt[3] == ' ' || stmt[3] == '\t' || stmt[3] == '\n' || stmt[3] == '{') {
			if err := execTryStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "switch") && (len(stmt) == 6 || stmt[6] == ' ' || stmt[6] == '\t' || stmt[6] == '\n' || stmt[6] == '(') {
			if err := execSwitchStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if fnDecl, ok := parseUserFuncDecl(stmt); ok {
			if budget.userFuncs == nil {
				budget.userFuncs = make(map[string]*painlessUserFunc)
			}
			budget.userFuncs[fnDecl.name] = fnDecl
			continue
		}
		if err := execSimpleStmt(sourceMap, stmt, params, ctxOp, budget); err != nil {
			return err
		}
	}
	return nil
}

type painlessSwitchClause struct {
	isDefault bool
	caseExpr  string
	body      string
}

func parseSwitchClauses(body string) []painlessSwitchClause {
	type labelSpan struct {
		isDefault  bool
		caseExpr   string
		labelStart int
		labelEnd   int
	}
	var spans []labelSpan
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(body); i++ {
		if stepQuoteState(body, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch body[i] {
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
		if i > 0 && (isIdentByte(body[i-1]) || body[i-1] == '.') {
			continue
		}
		if strings.HasPrefix(body[i:], "case") && len(body) > i+4 && !isIdentByte(body[i+4]) {
			rest := body[i+4:]
			cIdx := findMatchingTernaryColonPainless(rest)
			if cIdx >= 0 {
				spans = append(spans, labelSpan{
					isDefault:  false,
					caseExpr:   strings.TrimSpace(rest[:cIdx]),
					labelStart: i,
					labelEnd:   i + 4 + cIdx,
				})
				i = i + 4 + cIdx
				continue
			}
		}
		if strings.HasPrefix(body[i:], "default") && len(body) > i+7 && !isIdentByte(body[i+7]) {
			j := i + 7
			for j < len(body) && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r') {
				j++
			}
			if j < len(body) && body[j] == ':' {
				spans = append(spans, labelSpan{
					isDefault:  true,
					labelStart: i,
					labelEnd:   j,
				})
				i = j
				continue
			}
		}
	}
	clauses := make([]painlessSwitchClause, 0, len(spans))
	for idx, sp := range spans {
		endIdx := len(body)
		if idx+1 < len(spans) {
			endIdx = spans[idx+1].labelStart
		}
		cBody := strings.TrimSpace(body[sp.labelEnd+1 : endIdx])
		if strings.HasPrefix(cBody, "{") && findMatchingDelimiter(cBody, 0, '{', '}') == len(cBody)-1 {
			cBody = strings.TrimSpace(cBody[1 : len(cBody)-1])
		}
		clauses = append(clauses, painlessSwitchClause{
			isDefault: sp.isDefault,
			caseExpr:  sp.caseExpr,
			body:      cBody,
		})
	}
	return clauses
}

func execSwitchStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	switchExpr := strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	if !strings.HasPrefix(rest, "{") {
		return nil
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return nil
	}
	switchVal, err := evalRHSExpr(sourceMap, switchExpr, params)
	if err != nil {
		return err
	}
	clauses := parseSwitchClauses(rest[1:closeBrace])
	if len(clauses) == 0 {
		return nil
	}
	matchIdx := -1
	defaultIdx := -1
	for idx, cl := range clauses {
		if cl.isDefault {
			if defaultIdx < 0 {
				defaultIdx = idx
			}
			continue
		}
		cVal, cErr := evalRHSExpr(sourceMap, cl.caseExpr, params)
		if cErr != nil {
			return cErr
		}
		if valuesEqual(switchVal, cVal) {
			matchIdx = idx
			break
		}
		if f1, ok1 := toFloat64(switchVal); ok1 && switchVal != nil {
			if f2, ok2 := toFloat64(cVal); ok2 && cVal != nil && f1 == f2 {
				matchIdx = idx
				break
			}
		}
	}
	if matchIdx < 0 {
		matchIdx = defaultIdx
	}
	if matchIdx < 0 {
		return nil
	}
	for i := matchIdx; i < len(clauses); i++ {
		if clauses[i].body == "" {
			continue
		}
		if err := execBlock(sourceMap, clauses[i].body, params, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				return nil
			}
			return err
		}
	}
	return nil
}

func syncLoopScopeBack(params, loopParams map[string]any, preExistingKeys, excludedVars, loopDeclared map[string]bool) {
	ep, _ := loopParams["__explicit_params_keys"].(map[string]bool)
	for k, v := range loopParams {
		if k == "__loop_declared" {
			continue
		}
		if (ep != nil && ep[k]) || (preExistingKeys[k] && !excludedVars[k] && !loopDeclared[k]) || k == "_return_val" || k == "_ctx_op" || k == "_ctx_id" || k == "_ctx_index" || k == "_ctx_routing" || k == "_ctx_version" {
			params[k] = v
		} else if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if preExistingKeys[baseVar] && !excludedVars[baseVar] && !loopDeclared[baseVar] {
				params[k] = v
			}
		}
	}
	for k := range preExistingKeys {
		if k == "__loop_declared" || k == "__script_locals" || k == "__explicit_params_keys" || k == "__eval_budget" || k == "__user_funcs" || k == "__reassigned_vars" {
			continue
		}
		if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if !excludedVars[baseVar] && !loopDeclared[baseVar] {
				if _, stillExists := loopParams[k]; !stillExists {
					delete(params, k)
				}
			}
			continue
		}
		if !excludedVars[k] && !loopDeclared[k] {
			if _, stillExists := loopParams[k]; !stillExists {
				delete(params, k)
			}
		}
	}
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
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for {
		if err := budget.step(); err != nil {
			loopErr = err
			break
		}
		if cond != "" && !evalCondition(sourceMap, cond, loopParams) {
			break
		}
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
	syncLoopScopeBack(params, loopParams, preExistingKeys, nil, loopDeclared)
	return loopErr
}

func execDoWhileStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	rest := strings.TrimSpace(stmt[2:])
	if !strings.HasPrefix(rest, "{") {
		return nil
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return nil
	}
	body := rest[1:closeBrace]
	after := strings.TrimSpace(rest[closeBrace+1:])
	if !strings.HasPrefix(after, "while") {
		return nil
	}
	openParen := strings.IndexByte(after, '(')
	closeParen := findMatchingDelimiter(after, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	cond := strings.TrimSpace(after[openParen+1 : closeParen])
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for {
		if err := budget.step(); err != nil {
			loopErr = err
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
		if cond != "" && !evalCondition(sourceMap, cond, loopParams) {
			break
		}
	}
	syncLoopScopeBack(params, loopParams, preExistingKeys, nil, loopDeclared)
	return loopErr
}

type painlessCatchClause struct {
	excTypes []string
	varName  string
	body     string
}

func parseTryStatement(stmt string) (tryBody string, catches []painlessCatchClause, finallyBody string, hasFinally bool, ok bool) {
	rest := strings.TrimSpace(stmt[3:])
	if !strings.HasPrefix(rest, "{") {
		return "", nil, "", false, false
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return "", nil, "", false, false
	}
	tryBody = rest[1:closeBrace]
	rem := strings.TrimSpace(rest[closeBrace+1:])
	for rem != "" {
		if strings.HasPrefix(rem, "catch") && (len(rem) == 5 || rem[5] == ' ' || rem[5] == '\t' || rem[5] == '\n' || rem[5] == '(') {
			rem = strings.TrimSpace(rem[5:])
			if !strings.HasPrefix(rem, "(") {
				break
			}
			cp := findMatchingDelimiter(rem, 0, '(', ')')
			if cp < 0 {
				break
			}
			header := strings.TrimSpace(rem[1:cp])
			rem = strings.TrimSpace(rem[cp+1:])
			if !strings.HasPrefix(rem, "{") {
				break
			}
			cb := findMatchingDelimiter(rem, 0, '{', '}')
			if cb < 0 {
				break
			}
			cBody := rem[1:cb]
			rem = strings.TrimSpace(rem[cb+1:])
			var excTypes []string
			varName := "e"
			if header != "" {
				fields := strings.Fields(header)
				if len(fields) == 1 {
					varName = fields[0]
				} else if len(fields) >= 2 {
					varName = fields[len(fields)-1]
					typePart := strings.TrimSpace(header[:strings.LastIndex(header, varName)])
					for _, tp := range strings.Split(typePart, "|") {
						tp = strings.TrimSpace(tp)
						if tp != "" {
							excTypes = append(excTypes, tp)
						}
					}
				}
			}
			catches = append(catches, painlessCatchClause{
				excTypes: excTypes,
				varName:  varName,
				body:     cBody,
			})
			continue
		}
		if strings.HasPrefix(rem, "finally") && (len(rem) == 7 || rem[7] == ' ' || rem[7] == '\t' || rem[7] == '\n' || rem[7] == '{') {
			rem = strings.TrimSpace(rem[7:])
			if strings.HasPrefix(rem, "{") {
				cb := findMatchingDelimiter(rem, 0, '{', '}')
				if cb >= 0 {
					finallyBody = rem[1:cb]
					hasFinally = true
				}
			}
			break
		}
		break
	}
	return tryBody, catches, finallyBody, hasFinally, len(catches) > 0 || hasFinally
}

func matchesCatchException(err error, excTypes []string) bool {
	if len(excTypes) == 0 {
		return true
	}
	var pEx *painlessExceptionError
	errExType := "RuntimeException"
	errMsg := err.Error()
	if errors.As(err, &pEx) && pEx.exType != "" {
		errExType = pEx.exType
	}
	for _, t := range excTypes {
		switch t {
		case "Exception", "RuntimeException", "Throwable", "Object", "def":
			return true
		default:
			if t == errExType || strings.HasSuffix(errExType, "."+t) || strings.Contains(errMsg, t) {
				return true
			}
		}
	}
	return false
}

func isUnrecoverableSandboxError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "exceeded maximum step budget") ||
		strings.Contains(msg, "exceeded maximum recursion depth") ||
		strings.Contains(msg, "exceeded maximum size")
}

func execTryStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	tryBody, catches, finallyBody, hasFinally, ok := parseTryStatement(stmt)
	if !ok {
		return nil
	}
	tryErr := execBlock(sourceMap, tryBody, params, ctxOp, budget)
	if isUnrecoverableSandboxError(tryErr) {
		return tryErr
	}
	if tryErr != nil && !errors.Is(tryErr, errPainlessReturn) && !errors.Is(tryErr, errPainlessBreak) && !errors.Is(tryErr, errPainlessContinue) {
		for _, clause := range catches {
			if matchesCatchException(tryErr, clause.excTypes) {
				prevVal, hadPrev := params[clause.varName]
				sl, _ := params["__script_locals"].(map[string]bool)
				hadSL := sl != nil && sl[clause.varName]
				if sl != nil && !hadPrev {
					sl[clause.varName] = true
				}
				msg := tryErr.Error()
				exType := "RuntimeException"
				var pEx *painlessExceptionError
				if errors.As(tryErr, &pEx) {
					msg = pEx.message
					if pEx.exType != "" {
						exType = pEx.exType
					}
				}
				params[clause.varName] = map[string]any{
					"message":    msg,
					"type":       exType,
					"__exc_type": exType,
				}
				tryErr = execBlock(sourceMap, clause.body, params, ctxOp, budget)
				if hadPrev {
					params[clause.varName] = prevVal
				} else {
					delete(params, clause.varName)
					if sl != nil && !hadSL {
						delete(sl, clause.varName)
					}
				}
				if isUnrecoverableSandboxError(tryErr) {
					return tryErr
				}
				break
			}
		}
	}
	if hasFinally {
		savedRet, hadRet := params["_return_val"]
		savedLast, hadLast := params["_last_expr_val"]
		delete(params, "_return_val")
		delete(params, "_last_expr_val")
		finErr := execBlock(sourceMap, finallyBody, params, ctxOp, budget)
		if finErr != nil {
			tryErr = finErr
		} else {
			if hadRet {
				params["_return_val"] = savedRet
			}
			if hadLast {
				params["_last_expr_val"] = savedLast
			} else {
				delete(params, "_last_expr_val")
			}
		}
	}
	return tryErr
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
		loopParams := make(map[string]any, len(params)+3)
		for k, v := range params {
			preExistingKeys[k] = true
			loopParams[k] = v
		}
		loopDeclared := make(map[string]bool)
		loopParams["__loop_declared"] = loopDeclared
		initVars := make(map[string]bool)
		if initStmt := strings.TrimSpace(clauses[0]); initStmt != "" {
			var initTypePrefix string
			initRest := initStmt
			if tm := reVarTypeDeclPrefix.FindStringSubmatch(initStmt); tm != nil {
				initTypePrefix = tm[1]
				initRest = tm[2]
			}
			for _, subInit := range splitTopLevelCommaPainless(initRest) {
				subInit = strings.TrimSpace(subInit)
				if subInit == "" {
					continue
				}
				fullSubInit := subInit
				if initTypePrefix != "" && !reVarTypeDeclPrefix.MatchString(subInit) {
					fullSubInit = initTypePrefix + " " + subInit
				}
				if m := reLocalVarAssign.FindStringSubmatch(fullSubInit); m != nil {
					if initTypePrefix != "" || reVarTypeDeclPrefix.MatchString(fullSubInit) {
						initVars[m[1]] = true
						loopDeclared[m[1]] = true
					} else if _, existed := params[m[1]]; !existed {
						initVars[m[1]] = true
						loopDeclared[m[1]] = true
					}
				} else if m := reNullVarDecl.FindStringSubmatch(fullSubInit); m != nil {
					initVars[m[1]] = true
					loopDeclared[m[1]] = true
				}
				if err := execSimpleStmt(sourceMap, fullSubInit, loopParams, ctxOp, budget); err != nil {
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
		syncLoopScopeBack(params, loopParams, preExistingKeys, initVars, loopDeclared)
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
			keys := visiblePainlessMapKeys(mVal)
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
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	if !preExistingKeys[varName] || len(fields) > 1 {
		loopDeclared[varName] = true
	}
	loopParams["__loop_declared"] = loopDeclared
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
	syncLoopScopeBack(params, loopParams, preExistingKeys, map[string]bool{varName: true}, loopDeclared)
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
	return isIdentByte(c) || c == ']' || c == ')' || c == '?' || (c >= '\x00' && c <= '\x08') || (c >= '\x10' && c <= '\x1f') || c == '\x7f'
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
		case '(':
			out.WriteByte('\x16')
		case ')':
			out.WriteByte('\x17')
		case '[':
			out.WriteByte('\x18')
		case ']':
			out.WriteByte('\x19')
		case '{':
			out.WriteByte('\x1a')
		case '}':
			out.WriteByte('\x1b')
		case ',':
			out.WriteByte('\x1c')
		case ';':
			out.WriteByte('\x1d')
		case '^':
			out.WriteByte('\x1e')
		case '~':
			out.WriteByte('\x1f')
		case '#':
			out.WriteByte('\x7f')
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
	seg = strings.ReplaceAll(seg, "\x16", "(")
	seg = strings.ReplaceAll(seg, "\x17", ")")
	seg = strings.ReplaceAll(seg, "\x18", "[")
	seg = strings.ReplaceAll(seg, "\x19", "]")
	seg = strings.ReplaceAll(seg, "\x1a", "{")
	seg = strings.ReplaceAll(seg, "\x1b", "}")
	seg = strings.ReplaceAll(seg, "\x1c", ",")
	seg = strings.ReplaceAll(seg, "\x1d", ";")
	seg = strings.ReplaceAll(seg, "\x1e", "^")
	seg = strings.ReplaceAll(seg, "\x1f", "~")
	seg = strings.ReplaceAll(seg, "\x7f", "#")
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

func isBracketReceiverAt(s string, openBrackIdx int, closeBrackIdx int) (isReceiver bool, hasSafeDot bool) {
	if openBrackIdx <= 0 {
		return false, false
	}
	prev := s[openBrackIdx-1]
	if prev == '.' && openBrackIdx >= 2 && s[openBrackIdx-2] == '?' {
		return true, true
	}
	if prev == '?' {
		if openBrackIdx < 2 || (!isIdentByte(s[openBrackIdx-2]) && s[openBrackIdx-2] != ']' && s[openBrackIdx-2] != ')') {
			return false, false
		}
		if closeBrackIdx > openBrackIdx && findMatchingTernaryColonPainless(s[closeBrackIdx+1:]) >= 0 {
			return false, false
		}
		return true, false
	}
	if isIdentByte(prev) {
		j := openBrackIdx - 1
		for j > 0 && isIdentByte(s[j-1]) {
			j--
		}
		word := s[j:openBrackIdx]
		switch word {
		case "return", "case", "throw", "new", "in", "instanceof", "else":
			return false, false
		}
		return true, false
	}
	return prev == ']' || prev == ')' || (prev >= '\x00' && prev <= '\x08') || (prev >= '\x10' && prev <= '\x1f') || prev == '\x7f', false
}

func isUnboundIdentIndex(inner string, params map[string]any) bool {
	if !reSimpleFieldPath.MatchString(inner) || strings.Contains(inner, ".") {
		return false
	}
	if inner == "true" || inner == "false" || inner == "null" {
		return false
	}
	if params == nil {
		return true
	}
	_, exists := params[inner]
	return !exists
}

func findLambdaBodyEndPainless(s string, bodyStart int) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for j := bodyStart; j < len(s); j++ {
		if stepQuoteState(s, j, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[j] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return j
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return j
			}
		}
	}
	return len(s)
}

func isInsideCallArgsOrBrackets(s string, targetIdx int) bool {
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < targetIdx && i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		if s[i] == '(' && i > 0 && isIdentByte(s[i-1]) {
			closeP := findMatchingDelimiter(s, i, '(', ')')
			if closeP > targetIdx {
				return true
			}
			if closeP > i {
				i = closeP
				continue
			}
		}
		if s[i] == '[' {
			closeB := findMatchingDelimiter(s, i, '[', ']')
			if closeB > targetIdx {
				return true
			}
			if closeB > i {
				i = closeB
				continue
			}
		}
	}
	return false
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
		if c == '-' && i+1 < len(s) && s[i+1] == '>' {
			endIdx := findLambdaBodyEndPainless(s, i+2)
			out.WriteString(s[i:endIdx])
			i = endIdx - 1
			continue
		}
		if c == '(' && i > 0 && isIdentByte(s[i-1]) {
			closeParen := findMatchingDelimiter(s, i, '(', ')')
			if closeParen > i {
				out.WriteString(s[i : closeParen+1])
				i = closeParen
				continue
			}
		}
		if c == '[' {
			closeIdx := findMatchingDelimiter(s, i, '[', ']')
			if closeIdx > i+1 && i > 0 {
				if isRecv, hasSafeDot := isBracketReceiverAt(s, i, closeIdx); isRecv {
					inner := strings.TrimSpace(s[i+1 : closeIdx])
					if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
						q := inner[0]
						rawKey := inner[1 : len(inner)-1]
						validLiteral := !strings.ContainsRune(rawKey, rune(q))
						if validLiteral {
							if !hasSafeDot {
								out.WriteByte('.')
							}
							if rawKey == "_source" {
								out.WriteString("_source")
							} else {
								out.WriteString(encodeBracketKey(rawKey))
							}
							i = closeIdx
							continue
						}
					}
					if isIntegerLiteral(inner) {
						if !hasSafeDot {
							out.WriteByte('.')
						}
						out.WriteString(encodeBracketKey(inner))
						i = closeIdx
						continue
					}
					if (sourceMap != nil || params != nil) && !isUnboundIdentIndex(inner, params) {
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
								if !hasSafeDot {
									out.WriteByte('.')
								}
								if keyStr == "_source" {
									out.WriteString("_source")
								} else {
									out.WriteString(encodeBracketKey(keyStr))
								}
								i = closeIdx
								continue
							}
						}
					}
				}
			}
			if closeIdx > i && (i == 0 || func() bool { r, _ := isBracketReceiverAt(s, i, closeIdx); return !r }()) {
				out.WriteString(s[i : closeIdx+1])
				i = closeIdx
				continue
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
		arrowIdx := findNextUnquotedSubstr(res, "->", searchFrom)
		if arrowIdx >= 0 && arrowIdx < getIdx {
			lambdaEnd := findLambdaBodyEndPainless(res, arrowIdx+2)
			if getIdx < lambdaEnd {
				searchFrom = lambdaEnd
				continue
			}
		}
		openParen := getIdx + 4
		closeParen := findMatchingDelimiter(res, openParen, '(', ')')
		if closeParen <= openParen {
			break
		}
		if isInsideCallArgsOrBrackets(res, getIdx) {
			searchFrom = closeParen + 1
			continue
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
		if keyStr == "_source" {
			repl = "._source"
		}
		res = res[:getIdx] + repl + res[closeParen+1:]
		searchFrom = getIdx
	}
	return res
}

func checkCtxMetaLHS(rawPath []string, sourceMap, params map[string]any) (string, error) {
	if len(rawPath) == 2 && decodeBracketSeg(rawPath[0]) == "ctx" {
		metaField := decodeBracketSeg(rawPath[1])
		if metaField == "_id" || metaField == "_index" || metaField == "_routing" || metaField == "_version" {
			if readonly, ok := params["__readonly_ctx_meta"].(bool); ok && readonly && metaField != "_routing" {
				return "", fmt.Errorf("cannot modify read-only metadata field [ctx.%s]", metaField)
			}
			metaKey := "_ctx" + metaField
			if params != nil {
				if _, exists := params[metaKey]; !exists && sourceMap != nil {
					if v, ok := sourceMap[metaField]; ok {
						params[metaKey] = v
					}
				}
			}
			return metaKey, nil
		}
	}
	return "", nil
}

func normalizeLocalLHSPath(path []string, params map[string]any) []string {
	if len(path) == 2 && decodeBracketSeg(path[0]) == "ctx" {
		metaField := decodeBracketSeg(path[1])
		if metaField == "_id" || metaField == "_index" || metaField == "_routing" || metaField == "_version" {
			return []string{"_ctx" + metaField}
		}
		if metaField == "op" {
			return []string{"_ctx_op"}
		}
	}
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
		if aliasPath == "@root" {
			for k := range sourceMap {
				syncSourceAliasToLocalVars(sourceMap, params, k)
			}
			return
		}
		val := params[varName]
		switch val.(type) {
		case []any, map[string]any:
			setValueAtPath(sourceMap, strings.Split(aliasPath, "."), val)
		}
		syncSourceAliasToLocalVars(sourceMap, params, aliasPath)
	}
}

func syncSourceAliasToLocalVars(sourceMap map[string]any, params map[string]any, targetPath string) {
	if sourceMap == nil || params == nil || targetPath == "" {
		return
	}
	for k, v := range params {
		if strings.HasPrefix(k, "__alias_") {
			if aliasPath, ok := v.(string); ok && aliasPath != "@root" && (aliasPath == targetPath || strings.HasPrefix(aliasPath, targetPath+".") || strings.HasPrefix(targetPath, aliasPath+".")) {
				varName := strings.TrimPrefix(k, "__alias_")
				params[varName] = resolveParamPath(sourceMap, strings.Split(aliasPath, "."))
			}
		}
	}
}

func findTopLevelAssignOpStartPainless(s string) int {
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
				if i > 0 && (s[i-1] == '=' || s[i-1] == '!' || s[i-1] == '~') {
					continue
				}
				if i > 0 && s[i-1] == '<' && (i < 2 || s[i-2] != '<') {
					continue
				}
				if i > 0 && s[i-1] == '>' && (i < 2 || s[i-2] != '>') {
					continue
				}
				if i >= 3 && s[i-3:i] == ">>>" {
					return i - 3
				}
				if i >= 2 && (s[i-2:i] == "<<" || s[i-2:i] == ">>") {
					return i - 2
				}
				if i >= 1 && strings.IndexByte("+-*/%&|^", s[i-1]) >= 0 {
					return i - 1
				}
				return i
			}
		}
	}
	return -1
}

func expandStmtTargetsOnly(stmt string, sourceMap, params map[string]any) string {
	stmt = strings.TrimSpace(stmt)
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") ||
		strings.HasPrefix(stmt, "return(") || strings.HasPrefix(stmt, "return[") ||
		strings.HasPrefix(stmt, "return'") || strings.HasPrefix(stmt, "return\"") || strings.HasPrefix(stmt, "return/") ||
		stmt == "break" || stmt == "continue" ||
		stmt == "throw" || strings.HasPrefix(stmt, "throw ") || strings.HasPrefix(stmt, "throw(") ||
		reVarTypeDeclPrefix.MatchString(stmt) {
		return stmt
	}
	if opStart := findTopLevelAssignOpStartPainless(stmt); opStart > 0 {
		lhs := expandDynamicBrackets(stmt[:opStart], sourceMap, params, 0)
		return strings.TrimSpace(lhs + stmt[opStart:])
	}
	if strings.HasPrefix(stmt, "++") || strings.HasPrefix(stmt, "--") ||
		strings.HasSuffix(stmt, "++") || strings.HasSuffix(stmt, "--") ||
		(strings.HasSuffix(stmt, ")") && !strings.HasPrefix(stmt, "(")) {
		return strings.TrimSpace(expandDynamicBrackets(stmt, sourceMap, params, 0))
	}
	return stmt
}

func execSimpleStmt(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	delete(params, "_last_expr_val")
	stmt = expandStmtTargetsOnly(stmt, sourceMap, params)
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") || strings.HasPrefix(stmt, "return(") || strings.HasPrefix(stmt, "return[") || strings.HasPrefix(stmt, "return'") || strings.HasPrefix(stmt, "return\"") || strings.HasPrefix(stmt, "return/") {
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
	if stmt == "throw" || strings.HasPrefix(stmt, "throw ") || strings.HasPrefix(stmt, "throw(") {
		throwExpr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(stmt, "throw")), ";"))
		if strings.HasPrefix(throwExpr, "new ") {
			rest := strings.TrimSpace(throwExpr[4:])
			openP := strings.IndexByte(rest, '(')
			closeP := findMatchingDelimiter(rest, openP, '(', ')')
			if openP > 0 && closeP == len(rest)-1 {
				exType := strings.TrimSpace(rest[:openP])
				argExpr := strings.TrimSpace(rest[openP+1 : closeP])
				msg := ""
				if argExpr != "" {
					if v, err := evalRHSExpr(sourceMap, argExpr, params); err == nil && v != nil {
						msg = fmt.Sprintf("%v", v)
					} else {
						msg = argExpr
					}
				}
				return &painlessExceptionError{exType: exType, message: msg}
			}
		}
		if v, err := evalRHSExpr(sourceMap, throwExpr, params); err == nil && v != nil {
			if m, ok := v.(map[string]any); ok {
				exType, _ := m["__exc_type"].(string)
				msg, _ := m["message"].(string)
				return &painlessExceptionError{exType: exType, message: msg}
			}
			return &painlessExceptionError{exType: "RuntimeException", message: fmt.Sprintf("%v", v)}
		}
		return &painlessExceptionError{exType: "RuntimeException", message: throwExpr}
	}
	if m := reCtxOp.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[1]), "=") && !strings.HasPrefix(strings.TrimSpace(m[1]), "~") {
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
		if budget != nil {
			budget.ctxOp = *ctxOp
			budget.hasCtxOp = true
		}
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
		syncSourceAliasToLocalVars(sourceMap, params, pathStr)
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
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return err
		}
		path := normalizeLocalLHSPath(rawPath, params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(path[0]))
			}
			latchCtxMetaOnBudget(budget, path, nextVal)
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
		changed, err := removeIfCondFromSlice(sourceMap, sourceMap, arrPath, m[2], strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = changed
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}

	// 2. Check `.addAll(...)` on array
	if m := reArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if addAllArgs := splitTopLevelCommaPainless(m[2]); len(addAllArgs) == 2 {
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[0]), params)
			if err != nil {
				return err
			}
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[1]), params)
			if err != nil {
				return err
			}
			items, _ := valToAdd.([]any)
			changed, err := insertAllIntoSliceAtPath(sourceMap, arrPath, idxVal, items, budget)
			if err != nil {
				return err
			}
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
			params["_last_expr_val"] = changed
			return nil
		}
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
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
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
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
				for k := range subMap {
					syncSourceAliasToLocalVars(sourceMap, params, m[1]+"."+k)
				}
			} else {
				for k := range subMap {
					syncSourceAliasToLocalVars(sourceMap, params, k)
				}
			}
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
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
			}
			syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
			return nil
		}
	}

	// 6. Check `.remove('field')` or `.remove(params.key)` or `.remove(0)` or `.clear()`
	if m := reRemoveField.FindStringSubmatch(stmt); m != nil {
		var parentPath []string
		if m[1] != "" {
			parentPath = strings.Split(m[1], ".")
		}
		if remArgs := splitTopLevelCommaPainless(m[2]); len(remArgs) == 2 {
			kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[0]), params)
			if err != nil {
				return err
			}
			vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[1]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = removeKeyValueAtPath(sourceMap, parentPath, kVal, vVal)
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
			}
			return nil
		}
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
		if m[1] != "" {
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
		}
		return nil
	}
	if m := reClearField.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		clearAtPath(sourceMap, targetPath)
		if m[1] != "" {
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
		}
		params["_last_expr_val"] = nil
		return nil
	}

	// 6b. Check `.removeIf`, `.addAll`, `.add`, `.putAll`, `.put`, `.remove`, `.clear` on local/loop variables
	if m := reLocalArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				changed, err := removeIfCondFromSlice(sourceMap, params, arrPath, m[2], strings.TrimSpace(m[3]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = changed
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
				if addAllArgs := splitTopLevelCommaPainless(m[2]); len(addAllArgs) == 2 {
					idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[0]), params)
					if err != nil {
						return err
					}
					valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[1]), params)
					if err != nil {
						return err
					}
					items, _ := valToAdd.([]any)
					changed, err := insertAllIntoSliceAtPath(params, arrPath, idxVal, items, budget)
					if err != nil {
						return err
					}
					params["_last_expr_val"] = changed
					syncLocalVarAlias(sourceMap, params, rootVar)
					return nil
				}
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
				if isRootParams {
					for k := range subMap {
						markExplicitParamsKey(params, k)
					}
				}
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
				keyStr := fmt.Sprintf("%v", kVal)
				fullKeyPath := append(targetPath, keyStr)
				params["_last_expr_val"] = resolveParamPath(params, fullKeyPath)
				setValueAtPath(params, fullKeyPath, vVal)
				if isRootParams {
					markExplicitParamsKey(params, keyStr)
				}
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
			if remArgs := splitTopLevelCommaPainless(m[2]); len(remArgs) == 2 {
				kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[0]), params)
				if err != nil {
					return err
				}
				vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[1]), params)
				if err != nil {
					return err
				}
				removed := removeKeyValueAtPath(params, parentPath, kVal, vVal)
				if isRootParams && removed && kVal != nil {
					unmarkExplicitParamsKey(params, fmt.Sprintf("%v", kVal))
				}
				params["_last_expr_val"] = removed
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
				return nil
			}
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = removeKeyOrIndexAtPath(params, parentPath, argVal)
			if isRootParams && argVal != nil {
				unmarkExplicitParamsKey(params, fmt.Sprintf("%v", argVal))
			}
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
					if !isInternalPainlessMapKey(params, k) {
						delete(params, k)
						unmarkExplicitParamsKey(params, k)
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
		setValueAtPath(sourceMap, lhsPath, nextVal)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = nextVal
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
		params["_last_expr_val"] = val
		return nil
	}

	// 9. Check local/loop variable compound assignment (`sum += x`, `item.count += 1`, `items[0].qty += 2`)
	if m := reLocalCompoundAssign.FindStringSubmatch(stmt); m != nil {
		lhs := m[1]
		op := m[2]
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return err
		}
		rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		path := normalizeLocalLHSPath(rawPath, params)
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
		if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
			markExplicitParamsKey(params, decodeBracketSeg(path[0]))
		}
		latchCtxMetaOnBudget(budget, path, nextVal)
		params["_last_expr_val"] = nextVal
		if len(path) > 1 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
		}
		return nil
	}

	// 10. Check local/loop variable property/index assignment (`tag.status = 'active'`, `items[0] = 'x'`)
	if m := reLocalPropAssign.FindStringSubmatch(stmt); m != nil && m[1] != "doc" && !strings.HasPrefix(strings.TrimSpace(m[3]), "=") && !strings.HasPrefix(strings.TrimSpace(m[3]), "~") {
		varName := m[1]
		propPath := strings.Split(m[2], ".")
		if _, err := checkCtxMetaLHS(append([]string{varName}, propPath...), sourceMap, params); err != nil {
			return err
		}
		rhsExpr := strings.TrimSpace(m[3])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		fullPath := normalizeLocalLHSPath(append([]string{varName}, propPath...), params)
		if len(fullPath) > 0 {
			setValueAtPath(params, fullPath, val)
			if decodeBracketSeg(varName) == "params" && len(fullPath) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(fullPath[0]))
			}
			latchCtxMetaOnBudget(budget, fullPath, val)
			if len(propPath) == 1 && propPath[0] == "value" {
				if entryMap, ok := params[varName].(map[string]any); ok {
					if pm, ok := entryMap["__parent_map"].(map[string]any); ok {
						pm[fmt.Sprintf("%v", entryMap["key"])] = val
					}
				}
			}
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(fullPath[0]))
		}
		params["_last_expr_val"] = val
		return nil
	}
	if eqIdx := findTopLevelOpPainless(stmt, "="); eqIdx > 0 && (eqIdx+1 >= len(stmt) || (stmt[eqIdx+1] != '=' && stmt[eqIdx+1] != '~')) && stmt[eqIdx-1] != '!' && stmt[eqIdx-1] != '<' && stmt[eqIdx-1] != '>' {
		lhsExpr := strings.TrimSpace(stmt[:eqIdx])
		if callExpr, tailPath, ok := splitPostCallPropertyAccess(lhsExpr); ok {
			callVal, err := evalRHSExpr(sourceMap, callExpr, params)
			if err != nil {
				return err
			}
			rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(stmt[eqIdx+1:]), params)
			if err != nil {
				return err
			}
			if callVal != nil {
				setValueAtPath(map[string]any{"_v": callVal}, append([]string{"_v"}, strings.Split(tailPath, ".")...), rhsVal)
				params["_last_expr_val"] = rhsVal
			}
			return nil
		}
	}

	// 11. Check local variable declaration/assignment (`def x = ...`, `boolean ok = ...`, `int a = 1, b = 2`, `x = ...`)
	if tm := reVarTypeDeclPrefix.FindStringSubmatch(stmt); tm != nil {
		typePrefix := tm[1]
		decls := splitTopLevelCommaPainless(tm[2])
		if len(decls) > 1 {
			allValid := true
			for _, d := range decls {
				d = strings.TrimSpace(d)
				if !reIdentAssign.MatchString(d) && !reIdentOnly.MatchString(d) {
					allValid = false
					break
				}
			}
			if allValid {
				for _, d := range decls {
					d = strings.TrimSpace(d)
					if err := execSimpleStmt(sourceMap, typePrefix+" "+d, params, ctxOp, budget); err != nil {
						return err
					}
				}
				return nil
			}
		}
	}
	if m := reLocalVarAssign.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[2]), "=") && !strings.HasPrefix(strings.TrimSpace(m[2]), "~") {
		varName := m[1]
		_, existed := params[varName]
		if reVarTypeDeclPrefix.MatchString(stmt) {
			if ld, ok := params["__loop_declared"].(map[string]bool); ok {
				ld[varName] = true
			}
			if sl, ok := params["__script_locals"].(map[string]bool); ok && !existed {
				sl[varName] = true
			}
		} else if !existed {
			if sl, ok := params["__script_locals"].(map[string]bool); ok {
				sl[varName] = true
			}
		}
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		params[varName] = val
		if rv, ok := params["__reassigned_vars"].(map[string]bool); ok {
			rv[varName] = true
		}
		matchedAlias := false
		if rhsExpr == "ctx._source" || rhsExpr == "ctx?._source" || rhsExpr == "ctx._source?" || rhsExpr == "ctx?._source?" ||
			rhsExpr == "params._source" || rhsExpr == "params?._source" {
			params["__alias_"+varName] = "@root"
			matchedAlias = true
		}
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
		if !matchedAlias && reSimpleFieldPath.MatchString(rhsExpr) && !strings.HasSuffix(rhsExpr, ".size()") && !strings.HasSuffix(rhsExpr, ".length()") {
			rhsParts := normalizeLocalLHSPath(strings.Split(rhsExpr, "."), params)
			if len(rhsParts) > 0 {
				rootVar := decodeBracketSeg(rhsParts[0])
				if baseAlias, ok := params["__alias_"+rootVar].(string); ok && baseAlias != "" {
					switch val.(type) {
					case []any, map[string]any:
						if baseAlias == "@root" {
							if len(rhsParts) > 1 {
								params["__alias_"+varName] = strings.Join(rhsParts[1:], ".")
							} else {
								params["__alias_"+varName] = "@root"
							}
						} else {
							params["__alias_"+varName] = strings.Join(append([]string{baseAlias}, rhsParts[1:]...), ".")
						}
						matchedAlias = true
					}
				}
			}
		}
		if !matchedAlias {
			delete(params, "__alias_"+varName)
		}
		if !reVarTypeDeclPrefix.MatchString(stmt) {
			params["_last_expr_val"] = val
		}
		return nil
	}
	if m := reNullVarDecl.FindStringSubmatch(stmt); m != nil {
		if ld, ok := params["__loop_declared"].(map[string]bool); ok {
			ld[m[1]] = true
		}
		if _, existed := params[m[1]]; !existed {
			if sl, ok := params["__script_locals"].(map[string]bool); ok {
				sl[m[1]] = true
			}
		}
		params[m[1]] = nil
		if rv, ok := params["__reassigned_vars"].(map[string]bool); ok {
			rv[m[1]] = true
		}
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
	if stmt != "" && !isTopLevelAssignmentStmt(stmt) {
		val, err := evalRHSExpr(sourceMap, stmt, params)
		if err == nil && (val != nil || findTopLevelOpPainless(stmt, "?") > 0 || findTopLevelOpPainless(stmt, "?:") > 0) {
			params["_last_expr_val"] = val
			return nil
		}
		if strings.ContainsAny(stmt, "><=!&|") || strings.Contains(stmt, ".empty") || strings.Contains(stmt, ".contains(") || strings.Contains(stmt, ".startsWith(") || strings.Contains(stmt, ".endsWith(") || strings.Contains(stmt, ".isEmpty()") || strings.Contains(stmt, ".matches(") || strings.Contains(stmt, ".containsKey(") || strings.Contains(stmt, ".equals(") || strings.Contains(stmt, ".equalsIgnoreCase(") {
			params["_last_expr_val"] = evalCondition(sourceMap, stmt, params)
			return nil
		}
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
		if s[j] == '>' && j > 0 && s[j-1] == '-' {
			return true
		}
		if j >= 5 && s[j-5:j+1] == "return" && (j == 5 || !isIdentByte(s[j-6])) {
			return true
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

func isQuotedStringExprPainless(expr string) bool {
	s := trimBalancedParens(strings.TrimSpace(expr))
	return len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"'))
}

func evalRegexMatchPainless(lhsVal, rhsVal any, isRegexLit, fullMatch bool) bool {
	if lhsVal == nil || rhsVal == nil {
		return false
	}
	lhsStr := fmt.Sprintf("%v", lhsVal)
	pat := strings.TrimSpace(fmt.Sprintf("%v", rhsVal))
	if (isRegexLit || isRawRegexLiteralPainless(pat)) && len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
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
	cond = trimBalancedParens(cond)
	if cond == "" || cond == "false" {
		return false
	}
	if cond == "true" {
		return true
	}
	elvisIdx := findTopLevelOpPainless(cond, "?:")
	qIdx := findTopLevelOpPainless(cond, "?")
	if qIdx > 0 && (elvisIdx < 0 || qIdx < elvisIdx) {
		rest := cond[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			if evalConditionDepth(sourceMap, strings.TrimSpace(cond[:qIdx]), params, depth+1) {
				return evalConditionDepth(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalConditionDepth(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}
	if elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:elvisIdx]), params, depth+1)
		if err == nil && leftVal != nil {
			if b, ok := leftVal.(bool); ok {
				return b
			}
			if f, ok := toFloat64(leftVal); ok {
				return f != 0
			}
			return true
		}
		return evalConditionDepth(sourceMap, strings.TrimSpace(cond[elvisIdx+2:]), params, depth+1)
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
	for _, bwOp := range []string{"|", "^", "&"} {
		if idx, _ := findLastTopLevelOpPainless(cond, bwOp); idx > 0 {
			leftExpr := strings.TrimSpace(cond[:idx])
			rightExpr := strings.TrimSpace(cond[idx+1:])
			if hasTopLevelBooleanOrRegexOp(trimBalancedParens(leftExpr)) || hasTopLevelBooleanOrRegexOp(trimBalancedParens(rightExpr)) {
				lb := evalConditionDepth(sourceMap, leftExpr, params, depth+1)
				rb := evalConditionDepth(sourceMap, rightExpr, params, depth+1)
				switch bwOp {
				case "|":
					return lb || rb
				case "^":
					return lb != rb
				case "&":
					return lb && rb
				}
			}
		}
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
	cond = trimBalancedParens(expandDynamicBrackets(cond, sourceMap, params, depth+1))

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
	if val == nil {
		return false
	}
	if f, ok := toFloat64(val); ok {
		return f != 0
	}
	return true
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
	rhs = trimBalancedParens(rhs)
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

	if cVal, cOk, cErr := evalCollectionConstructorPainless(sourceMap, rhs, params, depth+1); cOk || cErr != nil {
		return cVal, cErr
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
		case "int", "long", "short", "byte", "Integer", "Long", "Short", "Byte":
			if f, fOk := toFloat64(innerVal); fOk {
				switch castType {
				case "short", "Short":
					v := int64(f) & 0xFFFF
					if v >= 0x8000 {
						v -= 0x10000
					}
					return v, nil
				case "byte", "Byte":
					v := int64(f) & 0xFF
					if v >= 0x80 {
						v -= 0x100
					}
					return v, nil
				default:
					return int64(f), nil
				}
			}
			if s, sOk := innerVal.(string); sOk && utf8.RuneCountInString(s) == 1 {
				r, _ := utf8.DecodeRuneInString(s)
				return int64(r), nil
			}
			return int64(0), nil
		case "char", "Character":
			if f, fOk := toFloat64(innerVal); fOk {
				return string(rune(int32(f))), nil
			}
			if s, sOk := innerVal.(string); sOk && len(s) > 0 {
				r, _ := utf8.DecodeRuneInString(s)
				return string(r), nil
			}
			return "", nil
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
		case "def", "Object", "List", "Map":
			return innerVal, nil
		}
	}
	rhs = trimBalancedParens(expandDynamicBrackets(rhs, sourceMap, params, depth+1))
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
		syncSourceAliasToLocalVars(sourceMap, params, pathStr)
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
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return nil, err
		}
		path := normalizeLocalLHSPath(rawPath, params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(path[0]))
			}
			latchCtxMetaOnBudget(getOrInitEvalBudget(params), path, nextVal)
			if len(path) > 1 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
			}
			if isPrefix {
				return nextVal, nil
			}
			return normalizeIncDecPrevVal(curVal), nil
		}
	}
	if strings.HasPrefix(rhs, "+") && len(rhs) > 1 && rhs[1] != '+' {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, true), nil
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

	if streamVal, handled, err := evalStreamPipelinePainless(sourceMap, rhs, params, depth+1); handled {
		return streamVal, err
	}

	// Check trailing zero-arg methods `.toLowerCase()`, `.toUpperCase()`, `.trim()`, `.strip()`, `.stripLeading()`, `.stripTrailing()`, `.isBlank()`, `.length()`, `.size()`, `.keySet()`, `.values()`, `.entrySet()`, `.getKey()`, `.getValue()`, `.getMessage()`, `.toString()`, and ZonedDateTime getters
	for _, mSuffix := range []string{
		".toLowerCase()", ".toUpperCase()", ".trim()", ".strip()", ".stripLeading()", ".stripTrailing()", ".isBlank()",
		".length()", ".size()", ".keySet()", ".values()", ".entrySet()", ".getKey()", ".getValue()", ".getMessage()", ".toString()",
		".getYear()", ".getMonthValue()", ".getMonth()", ".getDayOfMonth()", ".getDayOfYear()", ".getDate()", ".getHour()", ".getMinute()", ".getSecond()", ".getNano()",
		".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()", ".toInstant()",
		".find()", ".matches()", ".group()", ".groupCount()", ".start()", ".end()", ".reset()", ".pattern()",
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
			case ".getMessage()":
				if m, ok := recVal.(map[string]any); ok {
					if msg, hasMsg := m["message"]; hasMsg {
						return fmt.Sprintf("%v", msg), nil
					}
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".toString()":
				if m, ok := recVal.(map[string]any); ok {
					if excType, hasExc := m["__exc_type"].(string); hasExc && excType != "" {
						msg, _ := m["message"].(string)
						if msg != "" {
							return excType + ": " + msg, nil
						}
						return excType, nil
					}
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".toInstant()":
				return recVal, nil
			case ".getYear()", ".getMonthValue()", ".getMonth()", ".getDayOfMonth()", ".getDayOfYear()", ".getDate()", ".getHour()", ".getMinute()", ".getSecond()", ".getNano()", ".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					switch mSuffix {
					case ".getYear()":
						return int64(tm.Year()), nil
					case ".getMonthValue()":
						return int64(tm.Month()), nil
					case ".getMonth()":
						return strings.ToUpper(tm.Month().String()), nil
					case ".getDayOfMonth()", ".getDate()":
						return int64(tm.Day()), nil
					case ".getDayOfYear()":
						return int64(tm.YearDay()), nil
					case ".getHour()":
						return int64(tm.Hour()), nil
					case ".getMinute()":
						return int64(tm.Minute()), nil
					case ".getSecond()":
						return int64(tm.Second()), nil
					case ".getNano()":
						return int64(tm.Nanosecond()), nil
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
					keys := visiblePainlessMapKeys(tv)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = k
					}
					return out, nil
				}
				return []any{}, nil
			case ".values()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := visiblePainlessMapKeys(tv)
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
					keys := visiblePainlessMapKeys(tv)
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
					case "MONDAY", "JANUARY":
						return int64(1), nil
					case "TUESDAY", "FEBRUARY":
						return int64(2), nil
					case "WEDNESDAY", "MARCH":
						return int64(3), nil
					case "THURSDAY", "APRIL":
						return int64(4), nil
					case "FRIDAY", "MAY":
						return int64(5), nil
					case "SATURDAY", "JUNE":
						return int64(6), nil
					case "SUNDAY", "JULY":
						return int64(7), nil
					case "AUGUST":
						return int64(8), nil
					case "SEPTEMBER":
						return int64(9), nil
					case "OCTOBER":
						return int64(10), nil
					case "NOVEMBER":
						return int64(11), nil
					case "DECEMBER":
						return int64(12), nil
					}
				}
				return nil, nil
			case ".length()", ".size()":
				switch tv := recVal.(type) {
				case string:
					return int64(utf8.RuneCountInString(tv)), nil
				case []any:
					return int64(len(tv)), nil
				case map[string]any:
					return int64(visiblePainlessMapLen(tv)), nil
				}
			case ".pattern()":
				pat := fmt.Sprintf("%v", recVal)
				if isRawRegexLiteralPainless(pat) && len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
					pat = strings.ReplaceAll(pat[1:len(pat)-1], `\/`, `/`)
				}
				return pat, nil
			case ".find()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if pm.re == nil || pm.curPos > len(pm.input) {
						pm.lastMatch = nil
						return false, nil
					}
					loc := pm.re.FindStringSubmatchIndex(pm.input[pm.curPos:])
					if loc == nil {
						pm.lastMatch = nil
						pm.curPos = len(pm.input) + 1
						return false, nil
					}
					shifted := make([]int, len(loc))
					for i, idx := range loc {
						if idx >= 0 {
							shifted[i] = idx + pm.curPos
						} else {
							shifted[i] = -1
						}
					}
					pm.lastMatch = shifted
					if shifted[1] == pm.curPos {
						pm.curPos++
					} else {
						pm.curPos = shifted[1]
					}
					return true, nil
				}
				return false, nil
			case ".matches()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if pm.re == nil {
						return false, nil
					}
					fullRe, err := regexp.Compile("^(?:" + pm.re.String() + ")$")
					if err != nil {
						return false, nil
					}
					loc := fullRe.FindStringSubmatchIndex(pm.input)
					if loc == nil {
						pm.lastMatch = nil
						return false, nil
					}
					pm.lastMatch = loc
					pm.curPos = len(pm.input)
					return true, nil
				}
				return false, nil
			case ".group()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if len(pm.lastMatch) >= 2 && pm.lastMatch[0] >= 0 && pm.lastMatch[1] >= 0 {
						return pm.input[pm.lastMatch[0]:pm.lastMatch[1]], nil
					}
				}
				return nil, nil
			case ".groupCount()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && pm.re != nil {
					return int64(pm.re.NumSubexp()), nil
				}
				return int64(0), nil
			case ".start()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && len(pm.lastMatch) >= 2 && pm.lastMatch[0] >= 0 {
					return int64(utf8.RuneCountInString(pm.input[:pm.lastMatch[0]])), nil
				}
				return int64(-1), nil
			case ".end()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && len(pm.lastMatch) >= 2 && pm.lastMatch[1] >= 0 {
					return int64(utf8.RuneCountInString(pm.input[:pm.lastMatch[1]])), nil
				}
				return int64(-1), nil
			case ".reset()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					pm.curPos = 0
					pm.lastMatch = nil
					return pm, nil
				}
				return recVal, nil
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
			return visiblePainlessMapLen(tv) == 0, nil
		}
		return false, nil
	}

	for _, mName := range []string{
		".startsWith(", ".endsWith(", ".containsAll(", ".removeAll(", ".retainAll(", ".removeIf(", ".forEach(", ".compute(", ".computeIfAbsent(", ".computeIfPresent(", ".merge(", ".contains(", ".containsKey(", ".containsValue(", ".getOrDefault(", ".get(",
		".indexOf(", ".lastIndexOf(", ".charAt(", ".repeat(", ".matches(", ".matcher(", ".group(", ".start(", ".end(", ".replaceAll(", ".replaceFirst(",
		".splitOnToken(", ".split(", ".replace(", ".substring(", ".subList(", ".join(",
		".equals(", ".equalsIgnoreCase(", ".compareTo(", ".concat(", ".remove(", ".setValue(", ".set(", ".addAll(", ".add(", ".putAll(", ".putIfAbsent(", ".put(", ".sort(",
		".plusYears(", ".minusYears(", ".plusMonths(", ".minusMonths(", ".plusWeeks(", ".minusWeeks(", ".plusDays(", ".minusDays(",
		".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(", ".plusNanos(", ".minusNanos(",
		".withYear(", ".withMonth(", ".withDayOfMonth(", ".withHour(", ".withMinute(", ".withSecond(", ".withNano(", ".truncatedTo(",
		".isAfter(", ".isBefore(", ".isEqual(",
	} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(rhs, mName); ok {
			if mName == ".forEach(" {
				if err := execPainlessForEach(recExpr, argExpr, sourceMap, params, depth+1); err != nil {
					return nil, err
				}
				return nil, nil
			}
			if mName == ".replaceAll(" && findNextUnquotedSubstr(argExpr, "->", 0) > 0 && len(splitTopLevelCommaPainless(argExpr)) == 1 {
				if err := execPainlessListReplaceAll(recExpr, argExpr, sourceMap, params, depth+1); err != nil {
					return nil, err
				}
				return nil, nil
			}
			if mName == ".compute(" || mName == ".computeIfAbsent(" || mName == ".computeIfPresent(" || mName == ".merge(" {
				return evalPainlessMapCompute(mName, recExpr, argExpr, sourceMap, params, depth+1)
			}
			if mName == ".removeIf(" {
				arrowIdx := strings.Index(argExpr, "->")
				if arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
					if len(pNames) == 0 {
						return false, nil
					}
					paramName := pNames[0]
					condExpr := strings.TrimSpace(argExpr[arrowIdx+2:])
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							changed, err := removeIfCondFromSlice(sourceMap, sourceMap, arrPath, paramName, condExpr, params)
							if err != nil {
								return nil, err
							}
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return changed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							changed, err := removeIfCondFromSlice(sourceMap, params, arrPath, paramName, condExpr, params)
							if err != nil {
								return nil, err
							}
							syncLocalVarAlias(sourceMap, params, rootVar)
							return changed, nil
						}
					}
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if arr, ok := recVal.([]any); ok {
							tmpMap := map[string]any{"_arr": arr}
							changed, err := removeIfCondFromSlice(sourceMap, tmpMap, []string{"_arr"}, paramName, condExpr, params)
							if err != nil {
								return nil, err
							}
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
						relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
						arrPath := strings.Split(relPath, ".")
						changed := mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, isRetain)
						syncSourceAliasToLocalVars(sourceMap, params, relPath)
						return changed, nil
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
				if remArgs := splitTopLevelCommaPainless(argExpr); len(remArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[1]), params, depth+1)
					if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
						return removeKeyValueAtPath(sourceMap, nil, kVal, vVal), nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							parentPath := strings.Split(relPath, ".")
							removed := removeKeyValueAtPath(sourceMap, parentPath, kVal, vVal)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return removed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					parentPath := normalizeLocalLHSPath(rawPath, params)
					if len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						removed := removeKeyValueAtPath(params, nil, kVal, vVal)
						if removed && kVal != nil {
							unmarkExplicitParamsKey(params, fmt.Sprintf("%v", kVal))
						}
						return removed, nil
					}
					if len(parentPath) > 0 {
						rootVar := decodeBracketSeg(parentPath[0])
						if _, exists := params[rootVar]; exists {
							removed := removeKeyValueAtPath(params, parentPath, kVal, vVal)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return removed, nil
						}
					}
				}
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
					return removeKeyOrIndexAtPath(sourceMap, nil, argVal), nil
				}
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
						parentPath := strings.Split(relPath, ".")
						removed := removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
						syncSourceAliasToLocalVars(sourceMap, params, relPath)
						return removed, nil
					}
				}
				cleanRec := strings.TrimSuffix(recExpr, "?")
				rawPath := strings.Split(cleanRec, ".")
				parentPath := normalizeLocalLHSPath(rawPath, params)
				if len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
					removed := removeKeyOrIndexAtPath(params, nil, argVal)
					if argVal != nil {
						unmarkExplicitParamsKey(params, fmt.Sprintf("%v", argVal))
					}
					return removed, nil
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
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							prev := setSliceElementAtPath(sourceMap, arrPath, idxVal, newVal)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return prev, nil
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
				if addAllArgs := splitTopLevelCommaPainless(argExpr); len(addAllArgs) == 2 {
					idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addAllArgs[0]), params, depth+1)
					argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addAllArgs[1]), params, depth+1)
					items, _ := argVal.([]any)
					budget := getOrInitEvalBudget(params)
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							changed, err := insertAllIntoSliceAtPath(sourceMap, arrPath, idxVal, items, budget)
							if err != nil {
								return nil, err
							}
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return changed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							changed, err := insertAllIntoSliceAtPath(params, arrPath, idxVal, items, budget)
							if err != nil {
								return nil, err
							}
							syncLocalVarAlias(sourceMap, params, rootVar)
							return changed, nil
						}
					}
					return false, nil
				}
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				items, _ := argVal.([]any)
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
						arrPath := strings.Split(relPath, ".")
						changed := false
						for _, item := range append([]any(nil), items...) {
							if err := appendToSlice(sourceMap, arrPath, item); err != nil {
								return nil, err
							}
							changed = true
						}
						syncSourceAliasToLocalVars(sourceMap, params, relPath)
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
						relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
						arrPath := strings.Split(relPath, ".")
						if len(addArgs) == 2 {
							idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
							if err := insertIntoSliceAtPath(sourceMap, arrPath, idxVal, valToAdd); err != nil {
								return nil, err
							}
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return true, nil
						}
						valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if err := appendToSlice(sourceMap, arrPath, valToAdd); err != nil {
							return nil, err
						}
						syncSourceAliasToLocalVars(sourceMap, params, relPath)
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
						for k := range subMap {
							syncSourceAliasToLocalVars(sourceMap, params, k)
						}
					}
					return nil, nil
				}
				for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
					if strings.HasPrefix(recExpr, pfx) {
						relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
						targetPath := strings.Split(relPath, ".")
						if isSubMap {
							putAllAtPath(sourceMap, targetPath, subMap)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							for k := range subMap {
								syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+k)
							}
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
						for k := range subMap {
							markExplicitParamsKey(params, k)
						}
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
				if isSubMap {
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok && m != nil {
							putAllAtPath(m, nil, subMap)
						}
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
						syncSourceAliasToLocalVars(sourceMap, params, keyStr)
						return prev, nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							targetPath := strings.Split(relPath, ".")
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(sourceMap, fullKeyPath)
							setValueAtPath(sourceMap, fullKeyPath, vVal)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
							return prev, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					targetPath := normalizeLocalLHSPath(rawPath, params)
					if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						prev := params[keyStr]
						params[keyStr] = vVal
						markExplicitParamsKey(params, keyStr)
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
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok && m != nil {
							prev := m[keyStr]
							m[keyStr] = vVal
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
							syncSourceAliasToLocalVars(sourceMap, params, keyStr)
						}
						return prev, nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							targetPath := strings.Split(relPath, ".")
							fullKeyPath := append(targetPath, keyStr)
							prev := resolveParamPath(sourceMap, fullKeyPath)
							if prev == nil {
								setValueAtPath(sourceMap, fullKeyPath, vVal)
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
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
							markExplicitParamsKey(params, keyStr)
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
						kStr := fmt.Sprintf("%v", kVal)
						if !isInternalPainlessMapKey(tv, kStr) {
							if v, exists := tv[kStr]; exists && v != nil {
								return v, nil
							}
						}
					}
					return defVal, nil
				}
				return nil, nil
			case ".replace(":
				args := splitTopLevelCommaPainless(argExpr)
				if recMap, isMap := recVal.(map[string]any); isMap && recMap != nil {
					syncReplacedMap := func() {
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						rawPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(rawPath) > 0 {
							syncLocalVarAlias(sourceMap, params, decodeBracketSeg(rawPath[0]))
						}
					}
					if len(args) == 2 {
						kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						keyStr := fmt.Sprintf("%v", kVal)
						if cur, exists := recMap[keyStr]; exists {
							recMap[keyStr] = newVal
							syncReplacedMap()
							return cur, nil
						}
						return nil, nil
					}
					if len(args) == 3 {
						kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						oldVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
						if err != nil {
							return nil, err
						}
						keyStr := fmt.Sprintf("%v", kVal)
						if cur, exists := recMap[keyStr]; exists && valuesEqual(cur, oldVal) {
							recMap[keyStr] = newVal
							syncReplacedMap()
							return true, nil
						}
						return false, nil
					}
					return nil, nil
				}
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
				if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil && len(args) == 1 {
					replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					if replVal != nil && pm.re != nil {
						goRepl := normalizeJavaRegexReplacement(fmt.Sprintf("%v", replVal))
						if mName == ".replaceFirst(" {
							if loc := pm.re.FindStringSubmatchIndex(pm.input); loc != nil {
								expanded := pm.re.ExpandString(nil, goRepl, pm.input, loc)
								return pm.input[:loc[0]] + string(expanded) + pm.input[loc[1]:], nil
							}
							return pm.input, nil
						}
						return pm.re.ReplaceAllString(pm.input, goRepl), nil
					}
					return pm.input, nil
				}
				if len(args) == 2 {
					rawPatExpr := strings.TrimSpace(args[0])
					patVal, _ := evalRHSExprDepth(sourceMap, rawPatExpr, params, depth+1)
					replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if s, ok := recVal.(string); ok && patVal != nil && replVal != nil {
						patStr := fmt.Sprintf("%v", patVal)
						if !isQuotedStringExprPainless(rawPatExpr) && isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
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
					runes := []rune(s)
					start := int(sf)
					if start < 0 {
						start = 0
					}
					if start > len(runes) {
						start = len(runes)
					}
					end := len(runes)
					if len(args) >= 2 {
						endVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if ef, eOk := toFloat64(endVal); eOk {
							end = int(ef)
							if end < start {
								end = start
							}
							if end > len(runes) {
								end = len(runes)
							}
						}
					}
					return string(runes[start:end]), nil
				}
				return recVal, nil
			}
			argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
			switch mName {
			case ".matcher(":
				patStr := fmt.Sprintf("%v", recVal)
				if !isQuotedStringExprPainless(recExpr) && isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
					patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
				}
				inStr := ""
				if argVal != nil {
					inStr = fmt.Sprintf("%v", argVal)
				}
				re, _ := regexp.Compile(patStr)
				return &painlessMatcher{re: re, input: inStr}, nil
			case ".group(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && argVal != nil {
					if f, fOk := toFloat64(argVal); fOk {
						idx := int(f)
						if idx >= 0 && 2*idx+1 < len(pm.lastMatch) {
							sIdx, eIdx := pm.lastMatch[2*idx], pm.lastMatch[2*idx+1]
							if sIdx >= 0 && eIdx >= 0 {
								return pm.input[sIdx:eIdx], nil
							}
						}
						return nil, nil
					}
					if pm.re != nil {
						gName := fmt.Sprintf("%v", argVal)
						for i, name := range pm.re.SubexpNames() {
							if name != "" && name == gName && 2*i+1 < len(pm.lastMatch) {
								sIdx, eIdx := pm.lastMatch[2*i], pm.lastMatch[2*i+1]
								if sIdx >= 0 && eIdx >= 0 {
									return pm.input[sIdx:eIdx], nil
								}
							}
						}
					}
				}
				return nil, nil
			case ".start(", ".end(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && argVal != nil {
					if f, fOk := toFloat64(argVal); fOk {
						idx := int(f)
						if idx >= 0 && 2*idx+1 < len(pm.lastMatch) {
							pos := pm.lastMatch[2*idx]
							if mName == ".end(" {
								pos = pm.lastMatch[2*idx+1]
							}
							if pos >= 0 {
								return int64(utf8.RuneCountInString(pm.input[:pos])), nil
							}
						}
					}
				}
				return int64(-1), nil
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
						runes := []rune(s)
						if idx >= 0 && idx < len(runes) {
							return string(runes[idx]), nil
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
					k := fmt.Sprintf("%v", argVal)
					if isInternalPainlessMapKey(m, k) {
						return false, nil
					}
					_, exists := m[k]
					return exists, nil
				}
				return false, nil
			case ".containsValue(":
				if m, ok := recVal.(map[string]any); ok {
					for k, v := range m {
						if isInternalPainlessMapKey(m, k) {
							continue
						}
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
						kStr := fmt.Sprintf("%v", argVal)
						if isInternalPainlessMapKey(tv, kStr) {
							return nil, nil
						}
						return tv[kStr], nil
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
					runes := []rune(tv)
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
							if fromIdx > len(runes) {
								return int64(-1), nil
							}
							tailStr := string(runes[fromIdx:])
							byteIdx := strings.Index(tailStr, fmt.Sprintf("%v", subVal))
							if byteIdx < 0 {
								return int64(-1), nil
							}
							return int64(fromIdx + utf8.RuneCountInString(tailStr[:byteIdx])), nil
						}
					} else if argVal != nil {
						byteIdx := strings.Index(tv, fmt.Sprintf("%v", argVal))
						if byteIdx < 0 {
							return int64(-1), nil
						}
						return int64(utf8.RuneCountInString(tv[:byteIdx])), nil
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
					runes := []rune(tv)
					if len(args) >= 2 {
						subVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						fromVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if subVal != nil {
							fromIdx := len(runes)
							if ff, ok := toFloat64(fromVal); ok {
								fromIdx = int(ff)
							}
							if fromIdx < 0 {
								return int64(-1), nil
							}
							subRunes := []rune(fmt.Sprintf("%v", subVal))
							maxEnd := fromIdx + len(subRunes)
							if maxEnd > len(runes) {
								maxEnd = len(runes)
							}
							headStr := string(runes[:maxEnd])
							byteIdx := strings.LastIndex(headStr, string(subRunes))
							if byteIdx < 0 {
								return int64(-1), nil
							}
							return int64(utf8.RuneCountInString(headStr[:byteIdx])), nil
						}
					} else if argVal != nil {
						byteIdx := strings.LastIndex(tv, fmt.Sprintf("%v", argVal))
						if byteIdx < 0 {
							return int64(-1), nil
						}
						return int64(utf8.RuneCountInString(tv[:byteIdx])), nil
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
						isRegexLit := isRawRegexLiteralPainless(rawSepExpr) || (!isQuotedStringExprPainless(rawSepExpr) && isRawRegexLiteralPainless(sepStr))
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
					return applyArithmetic(arr, argVal, true), nil
				}
				if argVal == nil {
					return applyArithmetic(fmt.Sprintf("%v", recVal), "", true), nil
				}
				return applyArithmetic(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal), true), nil
			case ".remove(":
				if m, ok := recVal.(map[string]any); ok {
					if remArgs := splitTopLevelCommaPainless(argExpr); len(remArgs) == 2 {
						kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[0]), params, depth+1)
						vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[1]), params, depth+1)
						if kVal == nil {
							return false, nil
						}
						k := fmt.Sprintf("%v", kVal)
						cur, exists := m[k]
						if exists && valuesEqual(cur, vVal) {
							delete(m, k)
							return true, nil
						}
						return false, nil
					}
					if argVal != nil {
						k := fmt.Sprintf("%v", argVal)
						old := m[k]
						delete(m, k)
						return old, nil
					}
				}
				if arr, ok := recVal.([]any); ok {
					tmp := map[string]any{"_arr": arr}
					return removeKeyOrIndexAtPath(tmp, []string{"_arr"}, argVal), nil
				}
				return nil, nil
			case ".plusYears(", ".minusYears(", ".plusMonths(", ".minusMonths(", ".plusWeeks(", ".minusWeeks(", ".plusDays(", ".minusDays(",
				".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(", ".plusNanos(", ".minusNanos(",
				".withYear(", ".withMonth(", ".withDayOfMonth(", ".withHour(", ".withMinute(", ".withSecond(", ".withNano(", ".truncatedTo(":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					if mName == ".truncatedTo(" {
						unitStr := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", argVal)))
						unitStr = strings.TrimPrefix(unitStr, "CHRONOUNIT.")
						switch unitStr {
						case "DAYS", "DAY":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, tm.Location())
						case "HOURS", "HOUR":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), 0, 0, 0, tm.Location())
						case "MINUTES", "MINUTE":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), 0, 0, tm.Location())
						case "SECONDS", "SECOND":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), 0, tm.Location())
						case "MILLIS", "MILLISECONDS":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), (tm.Nanosecond()/1e6)*1e6, tm.Location())
						}
						return tm.Format(time.RFC3339Nano), nil
					}
					f, fOk := toFloat64(argVal)
					if !fOk {
						return recVal, nil
					}
					n := int64(f)
					if strings.HasPrefix(mName, ".minus") {
						n = -n
					}
					switch mName {
					case ".plusYears(", ".minusYears(":
						tm = tm.AddDate(int(n), 0, 0)
					case ".plusMonths(", ".minusMonths(":
						tm = tm.AddDate(0, int(n), 0)
					case ".plusWeeks(", ".minusWeeks(":
						tm = tm.AddDate(0, 0, int(n)*7)
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
					case ".plusNanos(", ".minusNanos(":
						tm = tm.Add(time.Duration(n) * time.Nanosecond)
					case ".withYear(":
						tm = time.Date(int(n), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withMonth(":
						tm = time.Date(tm.Year(), time.Month(int(n)), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withDayOfMonth(":
						tm = time.Date(tm.Year(), tm.Month(), int(n), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withHour(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), int(n), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withMinute(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), int(n), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withSecond(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), int(n), tm.Nanosecond(), tm.Location())
					case ".withNano(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), int(n), tm.Location())
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

	if strings.HasPrefix(rhs, "ctx.") || strings.HasPrefix(rhs, "ctx?.") {
		metaKey := decodeBracketSeg(strings.TrimPrefix(strings.TrimPrefix(rhs, "ctx?."), "ctx."))
		switch metaKey {
		case "op":
			if v, ok := params["_ctx_op"]; ok {
				return v, nil
			}
			return "index", nil
		case "_id":
			if v, ok := params["_ctx_id"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_id"]; ok {
				return v, nil
			}
			return nil, nil
		case "_index":
			if v, ok := params["_ctx_index"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_index"]; ok {
				return v, nil
			}
			return nil, nil
		case "_routing":
			if v, ok := params["_ctx_routing"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_routing"]; ok {
				return v, nil
			}
			return nil, nil
		case "_version":
			if v, ok := params["_ctx_version"]; ok {
				return v, nil
			}
			return nil, nil
		case "_now":
			return time.Now().UTC().UnixMilli(), nil
		}
	}
	if rhs == "ctx" {
		ctxMap := map[string]any{
			"_source": sourceMap,
			"op":      "index",
			"_now":    time.Now().UTC().UnixMilli(),
		}
		if v, ok := params["_ctx_op"]; ok {
			ctxMap["op"] = v
		}
		if v, ok := params["_ctx_id"]; ok {
			ctxMap["_id"] = v
		} else if v, ok := sourceMap["__reindex_id"]; ok {
			ctxMap["_id"] = v
		} else if v, ok := sourceMap["_id"]; ok {
			ctxMap["_id"] = v
		}
		if v, ok := params["_ctx_index"]; ok {
			ctxMap["_index"] = v
		} else if v, ok := sourceMap["__reindex_index"]; ok {
			ctxMap["_index"] = v
		} else if v, ok := sourceMap["_index"]; ok {
			ctxMap["_index"] = v
		}
		if v, ok := params["_ctx_version"]; ok {
			ctxMap["_version"] = v
		} else if v, ok := sourceMap["__reindex_version"]; ok {
			ctxMap["_version"] = v
		}
		if v, ok := params["_ctx_routing"]; ok {
			ctxMap["_routing"] = v
		} else if v, ok := sourceMap["_routing"]; ok {
			ctxMap["_routing"] = v
		}
		return ctxMap, nil
	}
	if rhs == "ctx._source" || rhs == "ctx?._source" || rhs == "ctx._source?" || rhs == "ctx?._source?" {
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
		if len(path) > 0 && strings.HasPrefix(decodeBracketSeg(path[0]), "__") {
			return nil, nil
		}
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
				return int64(utf8.RuneCountInString(fmt.Sprintf("%v", val))), nil
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
					return int64(utf8.RuneCountInString(tv)), nil
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
						return int64(visiblePainlessMapLen(tv)), nil
					}
					return visiblePainlessMapLen(tv) == 0, nil
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
		path := strings.Split(trimmed, ".")
		if len(path) > 0 && strings.HasPrefix(decodeBracketSeg(path[0]), "__") {
			return nil, nil
		}
		return resolveParamPath(sourceMap, path), nil
	}
	if strings.HasPrefix(rhs, "params.") || strings.HasPrefix(rhs, "params?.") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "params?."), "params.")
		paramPath := strings.Split(trimmed, ".")
		if len(paramPath) > 0 && isInternalPainlessMapKey(params, decodeBracketSeg(paramPath[0])) {
			return nil, nil
		}
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
	case "Math.PI":
		return math.Pi, nil
	case "Math.E":
		return math.E, nil
	case "Integer.MAX_VALUE":
		return int64(math.MaxInt32), nil
	case "Integer.MIN_VALUE":
		return int64(math.MinInt32), nil
	case "Long.MAX_VALUE":
		return int64(math.MaxInt64), nil
	case "Long.MIN_VALUE":
		return int64(math.MinInt64), nil
	case "Double.MAX_VALUE":
		return math.MaxFloat64, nil
	case "Double.MIN_VALUE":
		return math.SmallestNonzeroFloat64, nil
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
	if v, ok := parseHexOrBinaryIntLiteralPainless(numStr); ok {
		return v, nil
	}
	if reNumericLiteralSuffix.MatchString(numStr) {
		numStr = numStr[:len(numStr)-1]
	}
	if strings.HasPrefix(numStr, ".") && len(numStr) > 1 && numStr[1] >= '0' && numStr[1] <= '9' {
		numStr = "0" + numStr
	} else if strings.HasPrefix(numStr, "-.") && len(numStr) > 2 && numStr[2] >= '0' && numStr[2] <= '9' {
		numStr = "-0." + numStr[2:]
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

func stripConstructorGenericsPainless(s string) string {
	if !strings.Contains(s, "new ") || !strings.Contains(s, "<") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			out.WriteByte(s[i])
			continue
		}
		if strings.HasPrefix(s[i:], "new ") && (i == 0 || !isIdentByte(s[i-1])) {
			j := i + 4
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			clsStart := j
			for j < len(s) && (isIdentByte(s[j]) || s[j] == '.') {
				j++
			}
			if j > clsStart {
				k := j
				for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k < len(s) && s[k] == '<' {
					closeAngle := findMatchingDelimiter(s, k, '<', '>')
					if closeAngle > k {
						afterAngle := strings.TrimSpace(s[closeAngle+1:])
						if strings.HasPrefix(afterAngle, "(") {
							out.WriteString(s[i:j])
							i = closeAngle
							continue
						}
					}
				}
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func evalCollectionConstructorPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	if !strings.HasPrefix(rhs, "new ") {
		return nil, false, nil
	}
	rest := strings.TrimSpace(rhs[4:])
	idx := 0
	for idx < len(rest) && (isIdentByte(rest[idx]) || rest[idx] == '.') {
		idx++
	}
	if idx == 0 {
		return nil, false, nil
	}
	clsName := rest[:idx]
	if lastDot := strings.LastIndexByte(clsName, '.'); lastDot >= 0 {
		clsName = clsName[lastDot+1:]
	}
	isList := false
	isSet := false
	isMap := false
	switch clsName {
	case "ArrayList", "LinkedList":
		isList = true
	case "HashSet", "LinkedHashSet", "TreeSet":
		isSet = true
	case "HashMap", "LinkedHashMap", "TreeMap":
		isMap = true
	default:
		return nil, false, nil
	}
	rem := strings.TrimSpace(rest[idx:])
	if strings.HasPrefix(rem, "<") {
		closeAngle := findMatchingDelimiter(rem, 0, '<', '>')
		if closeAngle < 0 {
			return nil, false, nil
		}
		rem = strings.TrimSpace(rem[closeAngle+1:])
	}
	if !strings.HasPrefix(rem, "(") {
		return nil, false, nil
	}
	closeParen := findMatchingDelimiter(rem, 0, '(', ')')
	if closeParen < 0 {
		return nil, false, nil
	}
	argStr := strings.TrimSpace(rem[1:closeParen])
	tail := strings.TrimSpace(rem[closeParen+1:])
	if tail != "" && !strings.HasPrefix(tail, ".") && !strings.HasPrefix(tail, "?.") {
		return nil, false, nil
	}

	var ctorVal any
	if isList || isSet {
		outSlice := []any{}
		if argStr != "" {
			var argVal any
			expArg := strings.TrimSpace(expandDynamicBrackets(argStr, sourceMap, params, depth+1))
			if (strings.HasPrefix(expArg, "doc.") || strings.HasPrefix(expArg, "doc?.")) &&
				!strings.HasSuffix(expArg, ".value") && !strings.Contains(expArg, ".value.") && !strings.Contains(expArg, ".values.") && !strings.Contains(expArg, "(") {
				docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expArg, "doc?."), "doc."), ".values")
				argVal = resolveDocValuesSlice(sourceMap, docPath)
			} else {
				var err error
				argVal, err = evalRHSExprDepth(sourceMap, argStr, params, depth+1)
				if err != nil {
					return nil, true, err
				}
			}
			if srcSlice, ok := argVal.([]any); ok {
				if isSet {
					outSlice = make([]any, 0, len(srcSlice))
					for _, item := range srcSlice {
						seen := false
						for _, ex := range outSlice {
							if valuesEqual(item, ex) {
								seen = true
								break
							}
						}
						if !seen {
							outSlice = append(outSlice, item)
						}
					}
				} else {
					outSlice = make([]any, len(srcSlice))
					copy(outSlice, srcSlice)
				}
			}
		}
		ctorVal = outSlice
	} else if isMap {
		outMap := map[string]any{}
		if argStr != "" {
			argVal, err := evalRHSExprDepth(sourceMap, argStr, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if srcMap, ok := argVal.(map[string]any); ok {
				outMap = make(map[string]any, len(srcMap))
				for k, v := range srcMap {
					outMap[k] = v
				}
			}
		}
		ctorVal = outMap
	}

	if tail != "" {
		prevTmp, hadTmp := params["__ctor_res"]
		params["__ctor_res"] = ctorVal
		res, err := evalRHSExprDepth(sourceMap, "__ctor_res"+tail, params, depth+1)
		if hadTmp {
			params["__ctor_res"] = prevTmp
		} else {
			delete(params, "__ctor_res")
		}
		return res, true, err
	}
	return ctorVal, true, nil
}

func hasTopLevelBooleanOrRegexOp(s string) bool {
	s = stripConstructorGenericsPainless(s)
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
	case "int", "long", "double", "float", "short", "byte", "char", "String", "boolean",
		"Integer", "Long", "Double", "Float", "Short", "Byte", "Character", "Boolean",
		"def", "Object", "List", "Map":
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
					isPostfixIncDec := (lastChar == '+' || lastChar == '-') && len(prev) >= 3 && prev[len(prev)-2] == lastChar &&
						isBracketReceiverByte(prev[len(prev)-3])
					if (isPostfixIncDec || (lastChar != '+' && lastChar != '-')) && lastChar != '*' && lastChar != '/' && lastChar != '%' && lastChar != '(' &&
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
			if len(aSlice) >= MaxPainlessSliceItems {
				return aSlice[:MaxPainlessSliceItems]
			}
			if bSlice, ok2 := b.([]any); ok2 {
				rem := MaxPainlessSliceItems - len(aSlice)
				if len(bSlice) > rem {
					bSlice = bSlice[:rem]
				}
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
			as := fmt.Sprintf("%v", a)
			if len(as) >= MaxPainlessStringBytes {
				return as[:MaxPainlessStringBytes]
			}
			bs := fmt.Sprintf("%v", b)
			if len(as)+len(bs) > MaxPainlessStringBytes {
				bs = bs[:MaxPainlessStringBytes-len(as)]
			}
			return as + bs
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
		as := fmt.Sprintf("%v", a)
		if len(as) >= MaxPainlessStringBytes {
			return as[:MaxPainlessStringBytes]
		}
		bs := fmt.Sprintf("%v", b)
		if len(as)+len(bs) > MaxPainlessStringBytes {
			bs = bs[:MaxPainlessStringBytes-len(as)]
		}
		return as + bs
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

func hasCatchOrFinallyPrefix(s string) bool {
	if strings.HasPrefix(s, "catch") && (len(s) == 5 || !isIdentByte(s[5])) {
		return true
	}
	if strings.HasPrefix(s, "finally") && (len(s) == 7 || !isIdentByte(s[7])) {
		return true
	}
	return false
}

func hasDoWhileContinuation(curr, rem string) bool {
	t := strings.TrimSpace(curr)
	if strings.HasPrefix(t, "do") && (len(t) == 2 || !isIdentByte(t[2])) {
		return strings.HasPrefix(rem, "while") && (len(rem) == 5 || !isIdentByte(rem[5]))
	}
	return false
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
	for _, kw := range []string{"if", "for", "while", "try", "do", "switch"} {
		if strings.HasPrefix(t, kw) && (len(t) == len(kw) || t[len(kw)] == ' ' || t[len(kw)] == '\t' || t[len(kw)] == '\n' || t[len(kw)] == '(' || t[len(kw)] == '{') {
			return true
		}
	}
	if openP := strings.IndexByte(t, '('); openP > 0 && reUserFuncHeaderPrefix.MatchString(strings.TrimSpace(t[:openP])) {
		return true
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
				if !hasElseKeywordPrefix(rem) && !hasCatchOrFinallyPrefix(rem) && !hasDoWhileContinuation(curr.String(), rem) {
					out = append(out, curr.String())
					curr.Reset()
				}
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				rem := strings.TrimSpace(s[i+1:])
				if c == '\n' && (hasElseKeywordPrefix(rem) || hasCatchOrFinallyPrefix(rem) || hasDoWhileContinuation(curr.String(), rem) || isIncompleteControlHeader(curr.String()) || hasTrailingContinuationOp(curr.String())) {
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
				return int64(utf8.RuneCountInString(strVal))
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

func removeKeyValueAtPath(root map[string]any, parentPath []string, keyVal, expectedVal any) bool {
	if keyVal == nil {
		return false
	}
	var targetMap map[string]any
	if len(parentPath) == 0 {
		targetMap = root
	} else {
		targetMap, _ = resolveParamPath(root, parentPath).(map[string]any)
	}
	if targetMap == nil {
		return false
	}
	k := fmt.Sprintf("%v", keyVal)
	cur, exists := targetMap[k]
	if !exists || !valuesEqual(cur, expectedVal) {
		return false
	}
	delete(targetMap, k)
	return true
}

func insertAllIntoSliceAtPath(root map[string]any, path []string, idxVal any, items []any, budget *evalBudget) (bool, error) {
	if len(items) == 0 {
		return false, nil
	}
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
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
	itemsCopy := make([]any, len(items))
	copy(itemsCopy, items)
	next := make([]any, 0, len(existing)+len(itemsCopy))
	next = append(next, existing[:idx]...)
	next = append(next, itemsCopy...)
	next = append(next, existing[idx:]...)
	setValueAtPath(root, path, next)
	return true, nil
}

func removeKeyOrIndexAtPath(root map[string]any, parentPath []string, keyOrIdx any) any {
	if len(parentPath) == 0 {
		if root == nil || keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		if old, exists := root[k]; exists {
			delete(root, k)
			return old
		}
		if strings.Contains(k, ".") {
			segs := strings.Split(k, ".")
			return removeKeyOrIndexAtPath(root, segs[:len(segs)-1], segs[len(segs)-1])
		}
		return nil
	}
	switch target := resolveParamPath(root, parentPath).(type) {
	case map[string]any:
		if keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		if old, exists := target[k]; exists {
			delete(target, k)
			return old
		}
		if strings.Contains(k, ".") {
			segs := strings.Split(k, ".")
			subPath := append(append([]string(nil), parentPath...), segs[:len(segs)-1]...)
			return removeKeyOrIndexAtPath(root, subPath, segs[len(segs)-1])
		}
		return nil
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
		return false
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
		if lb, ok1 := leftVal.(bool); ok1 {
			if rb, ok2 := rightVal.(bool); ok2 {
				switch op {
				case "|":
					return lb || rb, true, nil
				case "^":
					return lb != rb, true, nil
				case "&":
					return lb && rb, true, nil
				}
			}
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

func removeIfCondFromSlice(sourceMap, root map[string]any, arrPath []string, paramName, condExpr string, params map[string]any) (bool, error) {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return false, nil
	}
	rawBody := strings.TrimSpace(condExpr)
	budget := getOrInitEvalBudget(params)
	preExistingKeys := make(map[string]bool, len(params))
	itemParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		itemParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	itemParams["__loop_declared"] = loopDeclared
	itemParams["__eval_budget"] = budget
	filtered := make([]any, 0, len(existing))
	var iterErr error
	for _, item := range existing {
		if err := budget.step(); err != nil {
			iterErr = err
			break
		}
		itemParams[paramName] = item
		matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, itemParams, 1)
		if err != nil {
			iterErr = err
			break
		}
		if matched {
			continue
		}
		filtered = append(filtered, item)
	}
	syncLoopScopeBack(params, itemParams, preExistingKeys, map[string]bool{paramName: true}, loopDeclared)
	if iterErr != nil {
		return false, iterErr
	}
	changed := len(filtered) != len(existing)
	setValueAtPath(root, arrPath, filtered)
	return changed, nil
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
	case "Math.sin":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Sin(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cos":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cos(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.tan":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Tan(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.asin":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Asin(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.acos":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Acos(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.atan":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Atan(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.atan2":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Atan2(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.sinh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Sinh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cosh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cosh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.tanh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Tanh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cbrt":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cbrt(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.expm1":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Expm1(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.log1p":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Log1p(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.toRadians":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(f * math.Pi / 180.0), true, nil
		}
		return float64(0), true, nil
	case "Math.toDegrees":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(f * 180.0 / math.Pi), true, nil
		}
		return float64(0), true, nil
	case "Math.floorDiv":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 && int64(f2) != 0 {
			x, y := int64(f1), int64(f2)
			q := x / y
			if (x^y) < 0 && q*y != x {
				q--
			}
			return q, true, nil
		}
		return int64(0), true, nil
	case "Math.floorMod":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 && int64(f2) != 0 {
			x, y := int64(f1), int64(f2)
			r := x % y
			if r != 0 && (r^y) < 0 {
				r += y
			}
			return r, true, nil
		}
		return int64(0), true, nil
	case "Integer.parseInt", "Long.parseLong":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			base := 10
			if len(args) >= 2 {
				if bf, ok := evalNumArg(1); ok && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if v != nil {
				if iv, pErr := strconv.ParseInt(s, base, 64); pErr == nil {
					return iv, true, nil
				}
			}
			return int64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", s),
			}
		}
		return int64(0), true, nil
	case "Double.parseDouble", "Float.parseFloat":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return float64(0), true, err
			}
			if v != nil {
				switch tv := v.(type) {
				case int, int64, float64, json.Number:
					if f, ok := toFloat64(tv); ok {
						return f, true, nil
					}
				case string:
					if fv, pErr := strconv.ParseFloat(strings.TrimSpace(tv), 64); pErr == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						return fv, true, nil
					}
				}
			}
			return float64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", v)),
			}
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
	case "ChronoUnit.YEARS.between", "ChronoUnit.MONTHS.between", "ChronoUnit.WEEKS.between", "ChronoUnit.DAYS.between", "ChronoUnit.HOURS.between", "ChronoUnit.MINUTES.between", "ChronoUnit.SECONDS.between", "ChronoUnit.MILLIS.between":
		if len(args) >= 2 {
			v1, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			v2, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			t1, ok1 := parsePainlessDateTime(v1)
			t2, ok2 := parsePainlessDateTime(v2)
			if ok1 && ok2 {
				diffMs := t2.UnixMilli() - t1.UnixMilli()
				switch fnName {
				case "ChronoUnit.YEARS.between", "ChronoUnit.MONTHS.between":
					months := int64(t2.Year()-t1.Year())*12 + int64(t2.Month()-t1.Month())
					if months > 0 && t1.AddDate(0, int(months), 0).After(t2) {
						months--
					} else if months < 0 && t1.AddDate(0, int(months), 0).Before(t2) {
						months++
					}
					if fnName == "ChronoUnit.YEARS.between" {
						return months / 12, true, nil
					}
					return months, true, nil
				case "ChronoUnit.WEEKS.between":
					return diffMs / (7 * 86400000), true, nil
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
	case "Pattern.compile":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if v != nil {
				patStr := fmt.Sprintf("%v", v)
				if isRawRegexLiteralPainless(patStr) {
					return patStr, true, nil
				}
				return "/" + strings.ReplaceAll(patStr, "/", `\/`) + "/", true, nil
			}
		}
		return nil, true, nil
	}
	budget := getOrInitEvalBudget(params)
	if budget != nil && budget.userFuncs != nil {
		if fn, ok := budget.userFuncs[fnName]; ok && fn != nil {
			if err := budget.step(); err != nil {
				return nil, true, err
			}
			var argVals []any
			if argStr != "" {
				argVals = make([]any, len(args))
				for i, a := range args {
					av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
					if err != nil {
						return nil, true, err
					}
					argVals[i] = av
				}
			}
			fnParams := make(map[string]any, len(params)+len(fn.paramNames)+4)
			for k, v := range params {
				if k == "_return_val" || k == "_last_expr_val" || k == "__loop_declared" || k == "__reassigned_vars" {
					continue
				}
				fnParams[k] = v
			}
			fnLocals := make(map[string]bool)
			if sl, ok := params["__script_locals"].(map[string]bool); ok {
				for k, v := range sl {
					fnLocals[k] = v
				}
			}
			fnParams["__script_locals"] = fnLocals
			reassignedVars := make(map[string]bool)
			fnParams["__reassigned_vars"] = reassignedVars
			fnParams["__eval_budget"] = budget
			callerVarBindings := make(map[string]string, len(fn.paramNames))
			for i, pName := range fn.paramNames {
				if i < len(argVals) {
					fnParams[pName] = argVals[i]
				} else {
					fnParams[pName] = nil
				}
				fnLocals[pName] = true
				delete(fnParams, "__alias_"+pName)
				if i < len(args) {
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
					for k := range ep {
						if v, exists := fnParams[k]; exists {
							params[k] = v
						}
					}
				}
			}
			if fnCtxOp != "" {
				budget.ctxOp = fnCtxOp
				budget.hasCtxOp = true
				if params != nil {
					params["_ctx_op"] = fnCtxOp
				}
			}
			if params != nil {
				for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version"} {
					if v, exists := fnParams[metaKey]; exists {
						params[metaKey] = v
					}
				}
			}
			if err != nil && !errors.Is(err, errPainlessReturn) {
				return nil, true, err
			}
			if fn.returnType == "void" {
				return nil, true, nil
			}
			if retVal, hasRet := fnParams["_return_val"]; hasRet {
				return retVal, true, nil
			}
			return fnParams["_last_expr_val"], true, nil
		}
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
				preExistingKeys := make(map[string]bool, len(params))
				cmpParams := make(map[string]any, len(params)+2)
				for k, v := range params {
					preExistingKeys[k] = true
					cmpParams[k] = v
				}
				loopDeclared := make(map[string]bool)
				cmpParams["__loop_declared"] = loopDeclared
				sort.SliceStable(arr, func(i, j int) bool {
					cmpParams[pA] = arr[i]
					cmpParams[pB] = arr[j]
					res, err := evalPainlessLambdaBody(body, sourceMap, cmpParams, depth+1)
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
				syncLoopScopeBack(params, cmpParams, preExistingKeys, map[string]bool{pA: true, pB: true}, loopDeclared)
				return
			}
		}
	}
	sort.SliceStable(arr, func(i, j int) bool {
		return comparePainlessValues(arr[i], arr[j]) < 0
	})
}

func parseHexOrBinaryIntLiteralPainless(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return 0, false
	}
	sign := int64(1)
	switch s[0] {
	case '-':
		sign = -1
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if len(s) < 3 || s[0] != '0' {
		return 0, false
	}
	base := 0
	switch s[1] {
	case 'x', 'X':
		base = 16
	case 'b', 'B':
		base = 2
	default:
		return 0, false
	}
	digits := s[2:]
	if strings.HasSuffix(digits, "L") || strings.HasSuffix(digits, "l") {
		digits = digits[:len(digits)-1]
	}
	digits = strings.ReplaceAll(digits, "_", "")
	if digits == "" {
		return 0, false
	}
	if sign < 0 {
		if iv, err := strconv.ParseInt("-"+digits, base, 64); err == nil {
			return iv, true
		}
		return 0, false
	}
	if iv, err := strconv.ParseInt(digits, base, 64); err == nil {
		return iv, true
	}
	return 0, false
}

func parsePainlessLambdaHeader(lhs string) []string {
	lhs = strings.TrimSpace(lhs)
	lhs = strings.TrimPrefix(strings.TrimSuffix(lhs, ")"), "(")
	if strings.TrimSpace(lhs) == "" {
		return nil
	}
	parts := strings.Split(lhs, ",")
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) > 0 {
			names = append(names, fields[len(fields)-1])
		}
	}
	return names
}

func evalPainlessLambdaBody(body string, sourceMap, params map[string]any, depth int) (any, error) {
	budget := getOrInitEvalBudget(params)
	if err := budget.step(); err != nil {
		return nil, err
	}
	body = strings.TrimSpace(body)
	if (strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}")) || isTopLevelAssignmentStmt(body) {
		inner := body
		if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
			inner = strings.TrimSpace(body[1 : len(body)-1])
		}
		preExistingKeys := make(map[string]bool, len(params))
		lambdaParams := make(map[string]any, len(params)+2)
		for k, v := range params {
			if k == "_return_val" || k == "_last_expr_val" {
				continue
			}
			preExistingKeys[k] = true
			lambdaParams[k] = v
		}
		loopDeclared := make(map[string]bool)
		lambdaParams["__loop_declared"] = loopDeclared
		ctxOp := ""
		err := execBlock(sourceMap, inner, lambdaParams, &ctxOp, budget)
		if err != nil && !errors.Is(err, errPainlessReturn) {
			return nil, err
		}
		var retVal any
		if rv, hasRet := lambdaParams["_return_val"]; hasRet {
			retVal = rv
		} else {
			retVal = lambdaParams["_last_expr_val"]
		}
		delete(lambdaParams, "_return_val")
		delete(lambdaParams, "_last_expr_val")
		syncLoopScopeBack(params, lambdaParams, preExistingKeys, nil, loopDeclared)
		if ctxOp != "" {
			params["_ctx_op"] = ctxOp
		}
		return retVal, nil
	}
	body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
	if strings.HasPrefix(body, "return ") || strings.HasPrefix(body, "return(") {
		body = strings.TrimSpace(strings.TrimPrefix(body, "return"))
	}
	return evalRHSExprDepth(sourceMap, body, params, depth+1)
}

func evalPainlessPredicateLambda(body string, sourceMap, params map[string]any, depth int) (bool, error) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		val, err := evalPainlessLambdaBody(body, sourceMap, params, depth)
		if err != nil {
			return false, err
		}
		if b, ok := val.(bool); ok {
			return b, nil
		}
		if val != nil {
			return strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", val)), "true"), nil
		}
		return false, nil
	}
	condBody := strings.TrimSpace(strings.TrimSuffix(body, ";"))
	if strings.HasPrefix(condBody, "return ") || strings.HasPrefix(condBody, "return(") {
		condBody = strings.TrimSpace(strings.TrimPrefix(condBody, "return"))
	}
	return evalConditionDepth(sourceMap, condBody, params, depth), nil
}

func execPainlessListReplaceAll(recExpr, argExpr string, sourceMap, params map[string]any, depth int) error {
	arrowIdx := findNextUnquotedSubstr(argExpr, "->", 0)
	if arrowIdx <= 0 {
		return nil
	}
	pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
	if len(pNames) == 0 {
		return nil
	}
	pName := pNames[0]
	body := strings.TrimSpace(argExpr[arrowIdx+2:])

	recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
	if err != nil {
		return err
	}
	if recMap, isMap := recVal.(map[string]any); isMap && recMap != nil && len(pNames) >= 2 {
		kName, vName := pNames[0], pNames[1]
		prevK, hadK := params[kName]
		prevV, hadV := params[vName]
		keys := visiblePainlessMapKeys(recMap)
		for _, k := range keys {
			params[kName] = k
			params[vName] = recMap[k]
			newVal, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if err != nil {
				if hadK {
					params[kName] = prevK
				} else {
					delete(params, kName)
				}
				if hadV {
					params[vName] = prevV
				} else {
					delete(params, vName)
				}
				return err
			}
			recMap[k] = newVal
		}
		if hadK {
			params[kName] = prevK
		} else {
			delete(params, kName)
		}
		if hadV {
			params[vName] = prevV
		} else {
			delete(params, vName)
		}
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(recExpr, pfx) {
				relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
				syncSourceAliasToLocalVars(sourceMap, params, relPath)
				return nil
			}
		}
		cleanRec := strings.TrimSuffix(recExpr, "?")
		mapPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
		if len(mapPath) > 0 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(mapPath[0]))
		}
		return nil
	}
	arr, ok := recVal.([]any)
	if !ok {
		return nil
	}
	prevVal, hadPrev := params[pName]
	for i, item := range arr {
		params[pName] = item
		newVal, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
		if err != nil {
			if hadPrev {
				params[pName] = prevVal
			} else {
				delete(params, pName)
			}
			return err
		}
		arr[i] = newVal
	}
	if hadPrev {
		params[pName] = prevVal
	} else {
		delete(params, pName)
	}
	for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
		if strings.HasPrefix(recExpr, pfx) {
			relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
			syncSourceAliasToLocalVars(sourceMap, params, relPath)
			return nil
		}
	}
	cleanRec := strings.TrimSuffix(recExpr, "?")
	arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
	if len(arrPath) > 0 {
		syncLocalVarAlias(sourceMap, params, decodeBracketSeg(arrPath[0]))
	}
	return nil
}

func execPainlessForEach(recExpr, argExpr string, sourceMap, params map[string]any, depth int) error {
	arrowIdx := findNextUnquotedSubstr(argExpr, "->", 0)
	if arrowIdx <= 0 {
		return nil
	}
	pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
	if len(pNames) == 0 {
		return nil
	}
	body := strings.TrimSpace(argExpr[arrowIdx+2:])
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = strings.TrimSpace(body[1 : len(body)-1])
	}

	var recVal any
	expRec := strings.TrimSpace(expandDynamicBrackets(recExpr, sourceMap, params, depth+1))
	if (strings.HasPrefix(expRec, "doc.") || strings.HasPrefix(expRec, "doc?.")) &&
		!strings.HasSuffix(expRec, ".value") && !strings.Contains(expRec, ".value.") && !strings.Contains(expRec, ".values.") && !strings.Contains(expRec, "(") {
		docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expRec, "doc?."), "doc."), ".values")
		recVal = resolveDocValuesSlice(sourceMap, docPath)
	} else {
		var err error
		recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil {
			return err
		}
	}

	ctxOp := ""
	budget := getOrInitEvalBudget(params)
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		if k == "_return_val" || k == "_last_expr_val" {
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

	switch tv := recVal.(type) {
	case []any:
		snapshot := make([]any, len(tv))
		copy(snapshot, tv)
		for _, item := range snapshot {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			loopParams[pNames[0]] = item
			if err := execBlock(sourceMap, body, loopParams, &ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessReturn) {
					delete(loopParams, "_return_val")
					continue
				}
				loopErr = err
				break
			}
		}
	case map[string]any:
		keys := visiblePainlessMapKeys(tv)
		for _, k := range keys {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			v := tv[k]
			if len(pNames) >= 2 {
				loopParams[pNames[0]] = k
				loopParams[pNames[1]] = v
			} else {
				loopParams[pNames[0]] = map[string]any{"key": k, "value": v, "__parent_map": tv}
			}
			if err := execBlock(sourceMap, body, loopParams, &ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessReturn) {
					delete(loopParams, "_return_val")
					continue
				}
				loopErr = err
				break
			}
		}
	}
	delete(loopParams, "_return_val")
	delete(loopParams, "_last_expr_val")
	syncLoopScopeBack(params, loopParams, preExistingKeys, excludedVars, loopDeclared)
	if ctxOp != "" {
		params["_ctx_op"] = ctxOp
	}
	return loopErr
}

func evalPainlessMapCompute(mName, recExpr, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	args := splitTopLevelCommaPainless(argExpr)
	recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
	if err != nil {
		return nil, err
	}
	m, ok := recVal.(map[string]any)
	if !ok || m == nil {
		return nil, nil
	}
	syncMutatedMap := func(mutatedKey string) {
		if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
			if mutatedKey != "" {
				syncSourceAliasToLocalVars(sourceMap, params, mutatedKey)
			}
			return
		}
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(recExpr, pfx) {
				relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
				syncSourceAliasToLocalVars(sourceMap, params, relPath)
				if mutatedKey != "" {
					syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+mutatedKey)
				}
				return
			}
		}
		cleanRec := strings.TrimSuffix(recExpr, "?")
		rawPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
		if len(rawPath) > 0 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(rawPath[0]))
		}
	}

	switch mName {
	case ".computeIfAbsent(":
		if len(args) != 2 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		if cur, exists := m[keyStr]; exists && cur != nil {
			return cur, nil
		}
		fnExpr := strings.TrimSpace(args[1])
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return nil, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		var pName string
		if len(pNames) > 0 {
			pName = pNames[0]
		}
		prev, hadPrev := params[pName]
		if pName != "" {
			params[pName] = keyStr
		}
		newVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if pName != "" {
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
		}
		if err != nil {
			return nil, err
		}
		if newVal != nil {
			m[keyStr] = newVal
			syncMutatedMap(keyStr)
		}
		return newVal, nil

	case ".compute(", ".computeIfPresent(":
		if len(args) != 2 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		cur, exists := m[keyStr]
		if mName == ".computeIfPresent(" && (!exists || cur == nil) {
			return nil, nil
		}
		fnExpr := strings.TrimSpace(args[1])
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return cur, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		if len(pNames) < 2 {
			return cur, nil
		}
		prevK, hadK := params[pNames[0]]
		prevV, hadV := params[pNames[1]]
		params[pNames[0]] = keyStr
		params[pNames[1]] = cur
		newVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if hadK {
			params[pNames[0]] = prevK
		} else {
			delete(params, pNames[0])
		}
		if hadV {
			params[pNames[1]] = prevV
		} else {
			delete(params, pNames[1])
		}
		if err != nil {
			return nil, err
		}
		if newVal == nil {
			delete(m, keyStr)
		} else {
			m[keyStr] = newVal
		}
		syncMutatedMap(keyStr)
		return newVal, nil

	case ".merge(":
		if len(args) != 3 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		cur, exists := m[keyStr]
		if !exists || cur == nil {
			if vVal != nil {
				m[keyStr] = vVal
				syncMutatedMap(keyStr)
			}
			return vVal, nil
		}
		fnExpr := strings.TrimSpace(args[2])
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return vVal, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		if len(pNames) < 2 {
			return vVal, nil
		}
		prev1, had1 := params[pNames[0]]
		prev2, had2 := params[pNames[1]]
		params[pNames[0]] = cur
		params[pNames[1]] = vVal
		mergedVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if had1 {
			params[pNames[0]] = prev1
		} else {
			delete(params, pNames[0])
		}
		if had2 {
			params[pNames[1]] = prev2
		} else {
			delete(params, pNames[1])
		}
		if err != nil {
			return nil, err
		}
		if mergedVal == nil {
			delete(m, keyStr)
		} else {
			m[keyStr] = mergedVal
		}
		syncMutatedMap(keyStr)
		return mergedVal, nil
	}
	return nil, nil
}

type painlessStreamStep struct {
	name string
	args string
}

func findTopLevelSubstrPainless(s, sub string) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i <= len(s)-len(sub); i++ {
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
		default:
			if depth == 0 && s[i:i+len(sub)] == sub {
				return i
			}
		}
	}
	return -1
}

func parseStreamChainStepsPainless(chain string) ([]painlessStreamStep, string, bool) {
	var steps []painlessStreamStep
	rem := strings.TrimSpace(chain)
	for strings.HasPrefix(rem, ".") || strings.HasPrefix(rem, "?.") {
		rem = strings.TrimPrefix(rem, "?")
		rem = strings.TrimPrefix(rem, ".")
		rem = strings.TrimSpace(rem)
		openP := strings.IndexByte(rem, '(')
		if openP <= 0 {
			return steps, "." + rem, len(steps) > 0
		}
		name := strings.TrimSpace(rem[:openP])
		for i := 0; i < len(name); i++ {
			if !isIdentByte(name[i]) {
				return nil, "", false
			}
		}
		closeP := findMatchingDelimiter(rem, openP, '(', ')')
		if closeP < 0 {
			return nil, "", false
		}
		argStr := strings.TrimSpace(rem[openP+1 : closeP])
		steps = append(steps, painlessStreamStep{name: name, args: argStr})
		rem = strings.TrimSpace(rem[closeP+1:])
	}
	if rem != "" {
		return steps, rem, len(steps) > 0
	}
	return steps, "", len(steps) > 0
}

func evalStreamPipelinePainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	streamIdx := findTopLevelSubstrPainless(rhs, ".stream()")
	if streamIdx <= 0 {
		return nil, false, nil
	}
	recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:streamIdx], "?"))
	chainRest := strings.TrimSpace(rhs[streamIdx+len(".stream()"):])
	if chainRest == "" {
		return nil, false, nil
	}
	steps, tailRest, ok := parseStreamChainStepsPainless(chainRest)
	if !ok || len(steps) == 0 {
		return nil, false, nil
	}

	var recVal any
	expRec := strings.TrimSpace(expandDynamicBrackets(recExpr, sourceMap, params, depth+1))
	if (strings.HasPrefix(expRec, "doc.") || strings.HasPrefix(expRec, "doc?.")) &&
		!strings.HasSuffix(expRec, ".value") && !strings.Contains(expRec, ".value.") && !strings.Contains(expRec, ".values.") && !strings.Contains(expRec, "(") {
		docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expRec, "doc?."), "doc."), ".values")
		recVal = resolveDocValuesSlice(sourceMap, docPath)
	} else {
		var err error
		recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil {
			return nil, true, err
		}
	}
	srcSlice, ok := recVal.([]any)
	if !ok {
		srcSlice = []any{}
	}
	items := make([]any, len(srcSlice))
	copy(items, srcSlice)

	var terminalVal any
	hasTerminal := false
	isOptional := false

	for idx, step := range steps {
		if hasTerminal {
			if isOptional {
				switch step.name {
				case "map", "flatMap":
					if terminalVal == nil {
						continue
					}
					if arrowIdx := findNextUnquotedSubstr(step.args, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = terminalVal
							mv, err := evalPainlessLambdaBody(step.args[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							if err != nil {
								return nil, true, err
							}
							terminalVal = mv
						}
					}
					continue
				case "filter":
					if terminalVal == nil {
						continue
					}
					if arrowIdx := findNextUnquotedSubstr(step.args, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = terminalVal
							matched, err := evalPainlessPredicateLambda(step.args[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							if err != nil {
								return nil, true, err
							}
							if !matched {
								terminalVal = nil
							}
						}
					}
					continue
				case "ifPresent":
					if terminalVal != nil {
						if arrowIdx := findNextUnquotedSubstr(step.args, "->", 0); arrowIdx > 0 {
							pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
							if len(pNames) > 0 {
								pName := pNames[0]
								prev, hadPrev := params[pName]
								params[pName] = terminalVal
								_, err := evalPainlessLambdaBody(step.args[arrowIdx+2:], sourceMap, params, depth+1)
								if hadPrev {
									params[pName] = prev
								} else {
									delete(params, pName)
								}
								if err != nil {
									return nil, true, err
								}
							}
						}
					}
					terminalVal = nil
					isOptional = false
					continue
				case "orElseThrow":
					if terminalVal == nil {
						return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
					}
					isOptional = false
					continue
				case "orElse":
					if terminalVal != nil {
						isOptional = false
						continue
					}
					defVal, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1)
					if err != nil {
						return nil, true, err
					}
					terminalVal = defVal
					isOptional = false
					continue
				case "orElseGet":
					if terminalVal != nil {
						isOptional = false
						continue
					}
					if arrowIdx := findNextUnquotedSubstr(step.args, "->", 0); arrowIdx >= 0 {
						defVal, err := evalPainlessLambdaBody(step.args[arrowIdx+2:], sourceMap, params, depth+1)
						if err != nil {
							return nil, true, err
						}
						terminalVal = defVal
					}
					isOptional = false
					continue
				case "get", "getAsInt", "getAsLong", "getAsDouble":
					isOptional = false
					continue
				case "isPresent":
					terminalVal = terminalVal != nil
					isOptional = false
					continue
				case "isEmpty":
					terminalVal = terminalVal == nil
					isOptional = false
					continue
				}
			}
			// Delegate remaining chained method calls on `terminalVal` via a temporary param
			var sb strings.Builder
			sb.WriteString("__stream_res")
			for _, remStep := range steps[idx:] {
				sb.WriteByte('.')
				sb.WriteString(remStep.name)
				sb.WriteByte('(')
				sb.WriteString(remStep.args)
				sb.WriteByte(')')
			}
			sb.WriteString(tailRest)
			prevTmp, hadTmp := params["__stream_res"]
			params["__stream_res"] = terminalVal
			res, err := evalRHSExprDepth(sourceMap, sb.String(), params, depth+1)
			if hadTmp {
				params["__stream_res"] = prevTmp
			} else {
				delete(params, "__stream_res")
			}
			return res, true, err
		}

		switch step.name {
		case "filter":
			arrowIdx := findNextUnquotedSubstr(step.args, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					rawBody := strings.TrimSpace(step.args[arrowIdx+2:])
					budget := getOrInitEvalBudget(params)
					prev, hadPrev := params[pName]
					filtered := make([]any, 0, len(items))
					for _, it := range items {
						if err := budget.step(); err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						params[pName] = it
						matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						if matched {
							filtered = append(filtered, it)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = filtered
				}
			}
		case "map", "mapToInt", "mapToLong", "mapToDouble":
			arrowIdx := findNextUnquotedSubstr(step.args, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := step.args[arrowIdx+2:]
					prev, hadPrev := params[pName]
					mapped := make([]any, 0, len(items))
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						switch step.name {
						case "mapToInt", "mapToLong":
							if f, ok := toFloat64(mv); ok {
								mv = int64(f)
							}
						case "mapToDouble":
							if f, ok := toFloat64(mv); ok {
								mv = f
							}
						}
						mapped = append(mapped, mv)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = mapped
				}
			}
		case "flatMap":
			arrowIdx := findNextUnquotedSubstr(step.args, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := strings.TrimSpace(step.args[arrowIdx+2:])
					body = strings.TrimSuffix(body, ".stream()")
					prev, hadPrev := params[pName]
					var flattened []any
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						if subArr, ok := mv.([]any); ok {
							if len(flattened) < MaxPainlessSliceItems {
								rem := MaxPainlessSliceItems - len(flattened)
								if len(subArr) > rem {
									subArr = subArr[:rem]
								}
								flattened = append(flattened, subArr...)
							}
						} else if mv != nil && len(flattened) < MaxPainlessSliceItems {
							flattened = append(flattened, mv)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = flattened
				}
			}
		case "distinct":
			dedup := make([]any, 0, len(items))
			for _, it := range items {
				seen := false
				for _, ex := range dedup {
					if valuesEqual(it, ex) {
						seen = true
						break
					}
				}
				if !seen {
					dedup = append(dedup, it)
				}
			}
			items = dedup
		case "sorted":
			sortPainlessSliceInPlace(items, step.args, sourceMap, params, depth+1)
		case "limit":
			if lv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1); err == nil {
				if f, ok := toFloat64(lv); ok {
					lim := int(f)
					if lim < 0 {
						lim = 0
					}
					if lim < len(items) {
						items = items[:lim]
					}
				}
			}
		case "skip":
			if sv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1); err == nil {
				if f, ok := toFloat64(sv); ok {
					sk := int(f)
					if sk < 0 {
						sk = 0
					}
					if sk >= len(items) {
						items = []any{}
					} else {
						items = items[sk:]
					}
				}
			}
		case "boxed", "asDoubleStream", "asLongStream":
			// No-op intermediate stream conversion
		case "peek":
			if arrowIdx := findNextUnquotedSubstr(step.args, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := step.args[arrowIdx+2:]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						if _, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1); err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		case "collect":
			hasTerminal = true
			cVal, cErr := evalStreamCollectorPainless(step.args, items, sourceMap, params, depth+1)
			if cErr != nil {
				return nil, true, cErr
			}
			terminalVal = cVal
		case "toList", "toArray":
			hasTerminal = true
			terminalVal = items
		case "count":
			hasTerminal = true
			terminalVal = int64(len(items))
		case "sum":
			hasTerminal = true
			sum := 0.0
			allInt := true
			for _, it := range items {
				if f, ok := toFloat64(it); ok {
					sum += f
					if f != float64(int64(f)) {
						allInt = false
					}
				}
			}
			if allInt {
				terminalVal = int64(sum)
			} else {
				terminalVal = sum
			}
		case "average":
			hasTerminal = true
			isOptional = true
			if len(items) == 0 {
				terminalVal = nil
			} else {
				sum := 0.0
				for _, it := range items {
					if f, ok := toFloat64(it); ok {
						sum += f
					}
				}
				terminalVal = sum / float64(len(items))
			}
		case "min", "max":
			hasTerminal = true
			isOptional = true
			if len(items) == 0 {
				terminalVal = nil
			} else {
				cp := make([]any, len(items))
				copy(cp, items)
				sortPainlessSliceInPlace(cp, step.args, sourceMap, params, depth+1)
				if step.name == "min" {
					terminalVal = cp[0]
				} else {
					terminalVal = cp[len(cp)-1]
				}
			}
		case "findFirst", "findAny":
			hasTerminal = true
			isOptional = true
			if len(items) > 0 {
				terminalVal = items[0]
			} else {
				terminalVal = nil
			}
		case "anyMatch", "allMatch", "noneMatch":
			hasTerminal = true
			arrowIdx := findNextUnquotedSubstr(step.args, "->", 0)
			if arrowIdx <= 0 {
				terminalVal = step.name != "anyMatch"
				continue
			}
			pNames := parsePainlessLambdaHeader(step.args[:arrowIdx])
			if len(pNames) == 0 {
				terminalVal = step.name != "anyMatch"
				continue
			}
			pName := pNames[0]
			rawBody := strings.TrimSpace(step.args[arrowIdx+2:])
			budget := getOrInitEvalBudget(params)
			prev, hadPrev := params[pName]
			resBool := step.name != "anyMatch"
			for _, it := range items {
				if err := budget.step(); err != nil {
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					return nil, true, err
				}
				params[pName] = it
				matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, params, depth+1)
				if err != nil {
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					return nil, true, err
				}
				if step.name == "anyMatch" && matched {
					resBool = true
					break
				}
				if step.name == "allMatch" && !matched {
					resBool = false
					break
				}
				if step.name == "noneMatch" && matched {
					resBool = false
					break
				}
			}
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			terminalVal = resBool
		case "reduce":
			hasTerminal = true
			rArgs := splitTopLevelCommaPainless(step.args)
			var acc any
			hasAcc := false
			fnExpr := step.args
			if len(rArgs) >= 2 {
				initVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rArgs[0]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				acc = initVal
				hasAcc = true
				fnExpr = strings.TrimSpace(rArgs[1])
			} else {
				isOptional = true
			}
			arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
				if len(pNames) >= 2 {
					p1, p2 := pNames[0], pNames[1]
					body := fnExpr[arrowIdx+2:]
					prev1, had1 := params[p1]
					prev2, had2 := params[p2]
					for _, it := range items {
						if !hasAcc {
							acc = it
							hasAcc = true
							continue
						}
						params[p1] = acc
						params[p2] = it
						nextAcc, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if had1 {
								params[p1] = prev1
							} else {
								delete(params, p1)
							}
							if had2 {
								params[p2] = prev2
							} else {
								delete(params, p2)
							}
							return nil, true, err
						}
						acc = nextAcc
					}
					if had1 {
						params[p1] = prev1
					} else {
						delete(params, p1)
					}
					if had2 {
						params[p2] = prev2
					} else {
						delete(params, p2)
					}
				}
			}
			terminalVal = acc
		case "forEach":
			hasTerminal = true
			prevTmp, hadTmp := params["__stream_items"]
			params["__stream_items"] = items
			err := execPainlessForEach("__stream_items", step.args, sourceMap, params, depth+1)
			if hadTmp {
				params["__stream_items"] = prevTmp
			} else {
				delete(params, "__stream_items")
			}
			if err != nil {
				return nil, true, err
			}
			terminalVal = nil
		}
	}

	if !hasTerminal {
		terminalVal = items
	}
	if tailRest != "" {
		prevTmp, hadTmp := params["__stream_res"]
		params["__stream_res"] = terminalVal
		res, err := evalRHSExprDepth(sourceMap, "__stream_res"+tailRest, params, depth+1)
		if hadTmp {
			params["__stream_res"] = prevTmp
		} else {
			delete(params, "__stream_res")
		}
		return res, true, err
	}
	return terminalVal, true, nil
}

func evalStreamCollectorPainless(collectorExpr string, items []any, sourceMap, params map[string]any, depth int) (any, error) {
	cExpr := strings.TrimSpace(collectorExpr)
	if strings.HasPrefix(cExpr, "Collectors.joining(") && strings.HasSuffix(cExpr, ")") {
		joinArgStr := strings.TrimSpace(cExpr[len("Collectors.joining(") : len(cExpr)-1])
		joinArgs := splitTopLevelCommaPainless(joinArgStr)
		delim, prefix, suffix := "", "", ""
		if len(joinArgs) >= 1 {
			if dv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[0]), params, depth+1); err == nil && dv != nil {
				delim = fmt.Sprintf("%v", dv)
			}
		}
		if len(joinArgs) >= 3 {
			if pv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[1]), params, depth+1); err == nil && pv != nil {
				prefix = fmt.Sprintf("%v", pv)
			}
			if sv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[2]), params, depth+1); err == nil && sv != nil {
				suffix = fmt.Sprintf("%v", sv)
			}
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = fmt.Sprintf("%v", it)
		}
		return prefix + strings.Join(parts, delim) + suffix, nil
	}
	if cExpr == "Collectors.toSet()" {
		dedup := make([]any, 0, len(items))
		for _, it := range items {
			seen := false
			for _, ex := range dedup {
				if valuesEqual(it, ex) {
					seen = true
					break
				}
			}
			if !seen {
				dedup = append(dedup, it)
			}
		}
		return dedup, nil
	}
	if cExpr == "Collectors.counting()" {
		return int64(len(items)), nil
	}
	for _, sumPfx := range []string{"Collectors.summingInt(", "Collectors.summingLong(", "Collectors.summingDouble(", "Collectors.averagingInt(", "Collectors.averagingLong(", "Collectors.averagingDouble("} {
		if strings.HasPrefix(cExpr, sumPfx) && strings.HasSuffix(cExpr, ")") {
			fnExpr := strings.TrimSpace(cExpr[len(sumPfx) : len(cExpr)-1])
			arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
			sum := 0.0
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := fnExpr[arrowIdx+2:]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						if f, ok := toFloat64(mv); ok {
							sum += f
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
			if strings.HasPrefix(sumPfx, "Collectors.averaging") {
				if len(items) == 0 {
					return float64(0), nil
				}
				return sum / float64(len(items)), nil
			}
			if sumPfx == "Collectors.summingDouble(" {
				return sum, nil
			}
			return int64(sum), nil
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.toMap(") && strings.HasSuffix(cExpr, ")") {
		mapArgStr := strings.TrimSpace(cExpr[len("Collectors.toMap(") : len(cExpr)-1])
		mapArgs := splitTopLevelCommaPainless(mapArgStr)
		resMap := make(map[string]any, len(items))
		if len(mapArgs) >= 2 {
			kFn := strings.TrimSpace(mapArgs[0])
			vFn := strings.TrimSpace(mapArgs[1])
			kArrow := findNextUnquotedSubstr(kFn, "->", 0)
			vArrow := findNextUnquotedSubstr(vFn, "->", 0)
			if kArrow > 0 && vArrow > 0 {
				kp := parsePainlessLambdaHeader(kFn[:kArrow])
				vp := parsePainlessLambdaHeader(vFn[:vArrow])
				if len(kp) > 0 && len(vp) > 0 {
					for _, it := range items {
						prevK, hadK := params[kp[0]]
						params[kp[0]] = it
						kVal, err := evalPainlessLambdaBody(kFn[kArrow+2:], sourceMap, params, depth+1)
						if hadK {
							params[kp[0]] = prevK
						} else {
							delete(params, kp[0])
						}
						if err != nil {
							return nil, err
						}
						prevV, hadV := params[vp[0]]
						params[vp[0]] = it
						vVal, err := evalPainlessLambdaBody(vFn[vArrow+2:], sourceMap, params, depth+1)
						if hadV {
							params[vp[0]] = prevV
						} else {
							delete(params, vp[0])
						}
						if err != nil {
							return nil, err
						}
						kStr := fmt.Sprintf("%v", kVal)
						if prevEntry, exists := resMap[kStr]; exists && len(mapArgs) >= 3 {
							mFn := strings.TrimSpace(mapArgs[2])
							if mArrow := findNextUnquotedSubstr(mFn, "->", 0); mArrow > 0 {
								mp := parsePainlessLambdaHeader(mFn[:mArrow])
								if len(mp) >= 2 {
									prev1, had1 := params[mp[0]]
									prev2, had2 := params[mp[1]]
									params[mp[0]] = prevEntry
									params[mp[1]] = vVal
									merged, mErr := evalPainlessLambdaBody(mFn[mArrow+2:], sourceMap, params, depth+1)
									if had1 {
										params[mp[0]] = prev1
									} else {
										delete(params, mp[0])
									}
									if had2 {
										params[mp[1]] = prev2
									} else {
										delete(params, mp[1])
									}
									if mErr != nil {
										return nil, mErr
									}
									vVal = merged
								}
							}
						}
						resMap[kStr] = vVal
					}
				}
			}
		}
		return resMap, nil
	}
	if strings.HasPrefix(cExpr, "Collectors.groupingBy(") && strings.HasSuffix(cExpr, ")") {
		grpArgStr := strings.TrimSpace(cExpr[len("Collectors.groupingBy(") : len(cExpr)-1])
		grpArgs := splitTopLevelCommaPainless(grpArgStr)
		groups := make(map[string][]any)
		var keyOrder []string
		if len(grpArgs) >= 1 {
			cFn := strings.TrimSpace(grpArgs[0])
			if cArrow := findNextUnquotedSubstr(cFn, "->", 0); cArrow > 0 {
				cp := parsePainlessLambdaHeader(cFn[:cArrow])
				if len(cp) > 0 {
					pName := cp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						kVal, err := evalPainlessLambdaBody(cFn[cArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						kStr := fmt.Sprintf("%v", kVal)
						if _, exists := groups[kStr]; !exists {
							keyOrder = append(keyOrder, kStr)
						}
						groups[kStr] = append(groups[kStr], it)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		}
		resMap := make(map[string]any, len(groups))
		downstream := "Collectors.toList()"
		if len(grpArgs) >= 2 {
			downstream = strings.TrimSpace(grpArgs[1])
		}
		for _, kStr := range keyOrder {
			dsVal, err := evalStreamCollectorPainless(downstream, groups[kStr], sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			resMap[kStr] = dsVal
		}
		return resMap, nil
	}
	if strings.HasPrefix(cExpr, "Collectors.partitioningBy(") && strings.HasSuffix(cExpr, ")") {
		partArgStr := strings.TrimSpace(cExpr[len("Collectors.partitioningBy(") : len(cExpr)-1])
		partArgs := splitTopLevelCommaPainless(partArgStr)
		trueSlice := []any{}
		falseSlice := []any{}
		if len(partArgs) >= 1 {
			pFn := strings.TrimSpace(partArgs[0])
			if pArrow := findNextUnquotedSubstr(pFn, "->", 0); pArrow > 0 {
				pp := parsePainlessLambdaHeader(pFn[:pArrow])
				if len(pp) > 0 {
					pName := pp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						matched, err := evalPainlessPredicateLambda(pFn[pArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						if matched {
							trueSlice = append(trueSlice, it)
						} else {
							falseSlice = append(falseSlice, it)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		}
		if len(partArgs) >= 2 {
			ds := strings.TrimSpace(partArgs[1])
			tv, err := evalStreamCollectorPainless(ds, trueSlice, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			fv, err := evalStreamCollectorPainless(ds, falseSlice, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			return map[string]any{"true": tv, "false": fv}, nil
		}
		return map[string]any{"true": trueSlice, "false": falseSlice}, nil
	}
	if strings.Contains(cExpr, "toSet") {
		return evalStreamCollectorPainless("Collectors.toSet()", items, sourceMap, params, depth)
	}
	return items, nil
}
