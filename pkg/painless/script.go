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
	"reflect"
	"strings"
)

// UnmarshalJSON parses both the standard Elasticsearch script object form
// (`{"source": "...", "lang": "painless", "params": {...}, "id": "..."}`)
// and the compact JSON string shorthand (`"ctx._source.f = 1"`).
func (s *ScriptSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*s = ScriptSpec{}
		return nil
	}
	if trimmed[0] == '"' {
		var shorthand string
		if err := json.Unmarshal(trimmed, &shorthand); err != nil {
			return fmt.Errorf("illegal_argument_exception: failed to parse script string shorthand: %w", err)
		}
		*s = ScriptSpec{
			Source: shorthand,
			Lang:   "painless",
		}
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("illegal_argument_exception: [script] must be an object or string")
	}

	var raw struct {
		Source *string        `json:"source"`
		Inline *string        `json:"inline"`
		Code   *string        `json:"code"`
		ID     string         `json:"id"`
		Lang   string         `json:"lang"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return fmt.Errorf("illegal_argument_exception: failed to parse script object: %w", err)
	}
	src := ""
	hasInline := false
	if raw.Source != nil {
		src = *raw.Source
		hasInline = true
	} else if raw.Inline != nil {
		src = *raw.Inline
		hasInline = true
	} else if raw.Code != nil {
		src = *raw.Code
		hasInline = true
	}
	if hasInline && raw.ID != "" {
		return fmt.Errorf("illegal_argument_exception: cannot specify both [source] and [id] in script")
	}
	*s = ScriptSpec{
		Source: src,
		ID:     raw.ID,
		Lang:   raw.Lang,
		Params: raw.Params,
	}
	return nil
}

// EffectiveSource returns the inline Painless script source string from ScriptSpec.
func (s ScriptSpec) EffectiveSource() string {
	return s.Source
}

// EvalScore evaluates a Painless `score` context script and returns the numeric float64 score.
func EvalScore(sourceMap map[string]any, scriptSource string, params map[string]any) (float64, error) {
	val, err := Eval(sourceMap, scriptSource, params)
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 0, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "score script returned null",
		}
	}
	fv, ok := toFloat64(val)
	if !ok {
		return 0, &painlessExceptionError{
			exType:  "ClassCastException",
			message: fmt.Sprintf("cannot cast [%T] to [double]", val),
		}
	}
	return fv, nil
}

// AllowedUpdateCtxKeys returns whether k is a recognized top-level key on `ctx`
// in `_update` and `_update_by_query` scripts.
func AllowedUpdateCtxKeys(k string) bool {
	switch k {
	case "_source", "_id", "_index", "_routing", "_version", "op", "_now", "_type",
		"_primary_term", "_seq_no":
		return true
	default:
		return false
	}
}

// FormatUnknownCtxKeyError returns Elasticsearch's version-appropriate
// illegal_argument_exception when an unknown top-level key is added to `ctx`
// in `_update` or `_update_by_query`.
func FormatUnknownCtxKeyError(key string, val any, isUBQ, isES8 bool) error {
	if isES8 {
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Cannot put key [%s] with value [%s] into ctx", key, FormatValueSafe(val)),
		}
	}
	if isUBQ {
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Invalid fields added to context [%s]", key),
		}
	}
	return &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("Operation [ctx.%s] is not supported, only [_source, op] are allowed", key),
	}
}

// FormatModifyCtxIDError returns Elasticsearch's illegal_argument_exception
// when `ctx._id` is modified in `_update_by_query` or `_update`.
func FormatModifyCtxIDError(isUBQ, isES8 bool) error {
	if isUBQ {
		if isES8 {
			return &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "_id cannot be updated",
			}
		}
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "Modifying [_id] not allowed",
		}
	}
	return &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: "Cannot modify _id in update script",
	}
}

// ValidateUBQCtxOp validates `ctx.op` values for `_update_by_query` (`index`, `noop`, `delete`).
func ValidateUBQCtxOp(op string, isES8 bool) error {
	switch op {
	case "", "index", "noop", "delete":
		return nil
	default:
		if isES8 {
			return fmt.Errorf("illegal_argument_exception: [op] must be one of delete, index, noop, not [%s]", op)
		}
		return fmt.Errorf("illegal_argument_exception: Operation type [%s] not allowed, only [noop, index, delete] are allowed", op)
	}
}

// ValidateUpdateCtxOp validates `ctx.op` values for single-document `_update`.
func ValidateUpdateCtxOp(op string) error {
	switch op {
	case "", "index", "noop", "none", "delete":
		return nil
	default:
		return fmt.Errorf("illegal_argument_exception: Invalidctx.op [%s]; must be one of [index, noop, none, delete]", op)
	}
}

// ValidateCtxVersion validates `ctx._version` after `_update` / `_update_by_query` script execution.
// In `_update_by_query`, `ctx._version` starts at `-1` when unmutated; if mutated to `< 0`,
// Elasticsearch rejects it with `illegal_argument_exception: version must be >= 0`.
func ValidateCtxVersion(version int64, mutated bool, isUBQ bool, isES8 bool) error {
	_ = isES8
	if !mutated {
		if isUBQ && version == -1 {
			return nil
		}
		if version >= 0 {
			return nil
		}
	}
	if version < 0 {
		return fmt.Errorf("illegal_argument_exception: version must be >= 0")
	}
	return nil
}

// CheckSelfReferencingContainer checks whether `val` contains a cyclic map or slice reference
// (e.g., `ctx._source.ctx = ctx` or `x.a = y; y.a = x`) and returns Elasticsearch's exact
// `illegal_argument_exception: Iterable object is self-referencing itself` message.
func CheckSelfReferencingContainer(val any, suffix string) error {
	msg := "Iterable object is self-referencing itself"
	if suffix != "" {
		msg = msg + " (" + suffix + ")"
	}
	ancestors := make(map[uintptr]bool)
	var walk func(v any, depth int) error
	walk = func(v any, depth int) error {
		if v == nil || depth > 256 {
			return nil
		}
		switch tv := v.(type) {
		case map[string]any:
			ptr := reflect.ValueOf(tv).Pointer()
			if ptr != 0 {
				if ancestors[ptr] {
					return fmt.Errorf("illegal_argument_exception: %s", msg)
				}
				ancestors[ptr] = true
				defer delete(ancestors, ptr)
			}
			for _, child := range tv {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			rv := reflect.ValueOf(tv)
			ptr := rv.Pointer()
			if ptr != 0 && len(tv) > 0 {
				if ancestors[ptr] {
					return fmt.Errorf("illegal_argument_exception: %s", msg)
				}
				ancestors[ptr] = true
				defer delete(ancestors, ptr)
			}
			for _, child := range tv {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(val, 0)
}

// ValidateUBQAndUpdateCtx validates a mutated `ctx` map (plus `_source` cycles, `_id` immutability,
// `ctx.op`, and `ctx._version`) for `_update` and `_update_by_query` callers in `pkg/proxy`.
func ValidateUBQAndUpdateCtx(ctxMap map[string]any, origID string, isUBQ bool, isES8 bool, versionMutated bool) error {
	if ctxMap == nil {
		return nil
	}
	for k, v := range ctxMap {
		if !AllowedUpdateCtxKeys(k) {
			pErr := FormatUnknownCtxKeyError(k, v, isUBQ, isES8)
			return fmt.Errorf("illegal_argument_exception: %s", strings.TrimPrefix(pErr.Error(), "illegal_argument_exception: "))
		}
	}
	if origID != "" {
		if curID, exists := ctxMap["_id"]; exists && curID != nil {
			if fmt.Sprintf("%v", curID) != origID {
				pErr := FormatModifyCtxIDError(isUBQ, isES8)
				return fmt.Errorf("illegal_argument_exception: %s", strings.TrimPrefix(pErr.Error(), "illegal_argument_exception: "))
			}
		}
	}
	if rawOp, exists := ctxMap["op"]; exists && rawOp != nil {
		opStr := fmt.Sprintf("%v", rawOp)
		if isUBQ {
			if err := ValidateUBQCtxOp(opStr, isES8); err != nil {
				return err
			}
		} else {
			if err := ValidateUpdateCtxOp(opStr); err != nil {
				return err
			}
		}
	}
	if rawVer, exists := ctxMap["_version"]; exists && rawVer != nil {
		if vi, ok := toInt64Painless(rawVer); ok {
			if err := ValidateCtxVersion(vi, versionMutated, isUBQ, isES8); err != nil {
				return err
			}
		} else if vf, ok := toFloat64(rawVer); ok {
			if err := ValidateCtxVersion(int64(vf), versionMutated, isUBQ, isES8); err != nil {
				return err
			}
		}
	}
	if src, exists := ctxMap["_source"]; exists && src != nil {
		if err := CheckSelfReferencingContainer(src, ""); err != nil {
			return err
		}
	}
	return nil
}
