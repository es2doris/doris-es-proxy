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
	"fmt"
	"regexp"
	"strings"
)

// UpdateRequest models an Elasticsearch `/_update/<id>` or `/_update_by_query` mutation spec.
type UpdateRequest struct {
	Doc         map[string]any `json:"doc,omitempty"`
	DocAsUpsert bool           `json:"doc_as_upsert,omitempty"`
	Script      *ScriptSpec    `json:"script,omitempty"`
}

type ScriptSpec struct {
	Source string         `json:"source"`
	Lang   string         `json:"lang,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

var (
	// Matches `ctx._source.<path> = params.<param>` or literal assignment
	reAssignParam = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\s*=\s*(.+)$`)
	// Matches `ctx._source.remove('field')` or `ctx._source.<path>.remove('field')`
	reRemoveField = regexp.MustCompile(`^ctx\._source(?:\.([a-zA-Z0-9_.]+))?\.remove\(\s*['"]([^'"]+)['"]\s*\)$`)
	// Matches `ctx._source.<path>.add(params.<param>)`
	reArrayAdd = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\.add\(\s*params\.([a-zA-Z0-9_.]+)\s*\)$`)
	// Matches `ctx._source.<path>.removeIf(x -> x.<prop> == params.<param>)`
	reArrayRemoveIf = regexp.MustCompile(`^ctx\._source\.([a-zA-Z0-9_.]+)\.removeIf\(\s*([a-zA-Z0-9_]+)\s*->\s*([a-zA-Z0-9_]+)\.([a-zA-Z0-9_.]+)\s*==\s*params\.([a-zA-Z0-9_.]+)\s*\)$`)
)

// ApplyUpdate applies either a partial `doc` deep merge or an embedded Painless `script`
// against a raw `_source` JSON payload and returns the mutated `_source` JSON bytes.
func ApplyUpdate(rawSource json.RawMessage, req *UpdateRequest) (json.RawMessage, error) {
	var doc map[string]any
	if len(rawSource) > 0 {
		if err := json.Unmarshal(rawSource, &doc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal _source for update: %w", err)
		}
	}
	if doc == nil {
		doc = make(map[string]any)
	}

	if len(req.Doc) > 0 {
		deepMergeMap(doc, req.Doc)
	}
	if req.Script != nil && strings.TrimSpace(req.Script.Source) != "" {
		if err := EvalPainless(doc, req.Script.Source, req.Script.Params); err != nil {
			return nil, err
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// EvalPainless evaluates common Painless script statements used by OpenMetadata and DataHub
// against `sourceMap` (`ctx._source`) with `params`.
func EvalPainless(sourceMap map[string]any, scriptSource string, params map[string]any) error {
	// Strip simple null-initialization guards like `if (ctx._source.tags == null) { ctx._source.tags = []; }`
	normalized := normalizeNullInitGuards(scriptSource)
	stmts := splitStatements(normalized)

	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		// 1. Check `removeIf` on array of objects (`ctx._source.tags.removeIf(t -> t.tagFQN == params.tagFQN)`)
		if m := reArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
			arrPath := strings.Split(m[1], ".")
			propPath := strings.Split(m[4], ".")
			targetVal := resolveParamPath(params, strings.Split(m[5], "."))
			removeIfFromSlice(sourceMap, arrPath, propPath, targetVal)
			continue
		}

		// 2. Check `.add(params.x)` on array (`ctx._source.tags.add(params.tag)`)
		if m := reArrayAdd.FindStringSubmatch(stmt); m != nil {
			arrPath := strings.Split(m[1], ".")
			valToAdd := resolveParamPath(params, strings.Split(m[2], "."))
			appendToSlice(sourceMap, arrPath, valToAdd)
			continue
		}

		// 3. Check `.remove('field')` (`ctx._source.remove('tier')`)
		if m := reRemoveField.FindStringSubmatch(stmt); m != nil {
			var parentPath []string
			if m[1] != "" {
				parentPath = strings.Split(m[1], ".")
			}
			removeKeyAtPath(sourceMap, parentPath, m[2])
			continue
		}

		// 4. Check field assignment (`ctx._source.deleted = params.deleted` or literal)
		if m := reAssignParam.FindStringSubmatch(stmt); m != nil {
			lhsPath := strings.Split(m[1], ".")
			rhsExpr := strings.TrimSpace(m[2])
			val, err := evalRHSExpr(rhsExpr, params)
			if err != nil {
				return err
			}
			setValueAtPath(sourceMap, lhsPath, val)
			continue
		}
	}
	return nil
}

func evalRHSExpr(rhs string, params map[string]any) (any, error) {
	if strings.HasPrefix(rhs, "params.") {
		paramPath := strings.Split(strings.TrimPrefix(rhs, "params."), ".")
		return resolveParamPath(params, paramPath), nil
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
	if strings.HasPrefix(rhs, "'") && strings.HasSuffix(rhs, "'") && len(rhs) >= 2 {
		return rhs[1 : len(rhs)-1], nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(rhs), &parsed); err == nil {
		return parsed, nil
	}
	return rhs, nil
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

func removeKeyAtPath(root map[string]any, parentPath []string, key string) {
	curr := root
	for _, seg := range parentPath {
		next, ok := curr[seg].(map[string]any)
		if !ok {
			return
		}
		curr = next
	}
	delete(curr, key)
}

func appendToSlice(root map[string]any, path []string, val any) {
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
	curr[lastKey] = append(existing, val)
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
		if itemMap, ok := item.(map[string]any); ok {
			if fmt.Sprintf("%v", resolveParamPath(itemMap, propPath)) == fmt.Sprintf("%v", matchVal) {
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

func normalizeNullInitGuards(s string) string {
	// Replaces `if (ctx._source.foo == null) { ctx._source.foo = []; }` with a no-op since `appendToSlice` auto-initializes.
	reGuard := regexp.MustCompile(`if\s*\(\s*ctx\._source\.[a-zA-Z0-9_.]+\s*==\s*null\s*\)\s*\{\s*ctx\._source\.[a-zA-Z0-9_.]+\s*=\s*\[\s*\]\s*;?\s*\}`)
	return reGuard.ReplaceAllString(s, "")
}

func splitStatements(s string) []string {
	s = strings.ReplaceAll(s, "\n", ";")
	return strings.Split(s, ";")
}
