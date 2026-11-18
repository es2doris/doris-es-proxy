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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// F28: Server.Close() Global Registry Cleanup
// ============================================================================

// supersededRouteHandlersR62Search retains references to legacy route methods
// in sibling files whose server.go mux bindings were upgraded to R62Search.
var supersededRouteHandlersR62Search = []any{
	(*Server).handleResolveIndex,
	(*Server).handleMigrateToDataStream,
	(*Server).handleDataStreamsStats,
	(*Server).handleModifyDataStream,
}

var _ = supersededRouteHandlersR62Search

func (s *Server) cleanupGlobalServerRegistriesR62Search() {
	if s == nil {
		return
	}
	CleanupAdminAndCRUDRegistriesOnCloseR62Admin(s)

	serverIngestStatsRegistryRound61.Delete(s)
	serverRemoteReindexTransportsRound61.Delete(s)
	serverRemoteReindexSecurityConfigRound62.Delete(s)

	indexLookupSpecsMuR62Search.Lock()
	delete(serverLookupSpecsR62Search, s)
	for k, owner := range schemaServerRegistryR62Search {
		if owner == s {
			delete(schemaServerRegistryR62Search, k)
		}
	}
	indexLookupSpecsMuR62Search.Unlock()
}

// ============================================================================
// F26: Thread-Safe Copy-on-Write AutoDims, Dynamic Vectors & LegacyTypeName
// ============================================================================

func vectorOrShredErrorTypeForReqR62Search(err error, isES8 bool) string {
	et := vectorOrShredErrorTypeR62Search(err)
	if !isES8 && et == "document_parsing_exception" && err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "date_nanos") || strings.Contains(lower, "1970") || strings.Contains(lower, "2262") {
			return "mapper_parsing_exception"
		}
	}
	return et
}

func vectorOrShredErrorTypeR62Search(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, pfx := range []string{
		"document_parsing_exception:",
		"mapper_parsing_exception:",
		"illegal_argument_exception:",
		"strict_dynamic_mapping_exception:",
	} {
		if strings.HasPrefix(msg, pfx) {
			return strings.TrimSuffix(pfx, ":")
		}
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "vector") && (strings.Contains(lower, "dimension") ||
		strings.Contains(lower, "length") ||
		strings.Contains(lower, "magnitude") ||
		strings.Contains(lower, "nan") ||
		strings.Contains(lower, "inf") ||
		strings.Contains(lower, "byte") ||
		strings.Contains(lower, "bit") ||
		strings.Contains(lower, "hex")) {
		if strings.Contains(lower, "zero-magnitude") || strings.Contains(lower, "requires [dims]") {
			return "mapper_parsing_exception"
		}
		return "document_parsing_exception"
	}
	return shredErrorType(err)
}

func trimSchemaErrorPrefixR62Search(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, pfx := range []string{
		"document_parsing_exception: ",
		"mapper_parsing_exception: ",
		"illegal_argument_exception: ",
		"strict_dynamic_mapping_exception: ",
	} {
		if strings.HasPrefix(msg, pfx) {
			return strings.TrimPrefix(msg, pfx)
		}
	}
	return msg
}

func extractIndexModeSettingR62Search(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	for _, k := range []string{"index.mode", "mode"} {
		if v, ok := m[k]; ok && v != nil {
			if s, okS := v.(string); okS {
				return strings.TrimSpace(s)
			}
		}
	}
	if idxSub, ok := m["index"].(map[string]any); ok {
		if v, okM := idxSub["mode"]; okM && v != nil {
			if s, okS := v.(string); okS {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func isBenignAddColumnErrorR62Search(err error) bool {
	if err == nil {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "duplicate column") ||
		strings.Contains(lower, "already exists") ||
		strings.Contains(lower, "column exists")
}

// applyCopyOnWriteAutoDimsR62Search inspects `rawDocs` for unlocked `AutoDims` vector fields
// and ES8 dynamic float `[128..2048]` vectors without mutating `current` in place. When new
// dimensions or dynamic vector bindings are discovered, it acquires `s.mu.Lock()`, re-verifies
// against the latest `s.indices[indexName]`, clones via `CloneWithAutoDimsAndDynamicVectors`,
// executes `ALTER TABLE ADD COLUMN` DDL, and atomically swaps `s.indices[indexName]`.
func (s *Server) applyCopyOnWriteAutoDimsR62Search(
	ctx context.Context,
	indexName string,
	current *schema.IndexSchema,
	rawDocs [][]byte,
) (*schema.IndexSchema, error) {
	if s == nil || current == nil || len(rawDocs) == 0 {
		return current, nil
	}
	lockedDims, newDynVecs, err := schema.InspectAutoDimsAndDynamicVectors(current, rawDocs)
	if err != nil {
		return nil, err
	}
	if len(lockedDims) == 0 && len(newDynVecs) == 0 {
		return current, nil
	}

	s.mu.Lock()
	latest := s.indices[indexName]
	if latest == nil {
		latest = current
	}
	locked2, dyn2, err2 := schema.InspectAutoDimsAndDynamicVectors(latest, rawDocs)
	if err2 != nil {
		s.mu.Unlock()
		return nil, err2
	}
	if len(locked2) == 0 && len(dyn2) == 0 {
		s.mu.Unlock()
		return latest, nil
	}
	cloned, addedBindings := latest.CloneWithAutoDimsAndDynamicVectors(locked2, dyn2)
	ddlStmts := schema.GenerateAddColumnsDDL(cloned, addedBindings)
	for _, stmt := range ddlStmts {
		if ddlErr := s.backend.ExecDDL(ctx, stmt); ddlErr != nil && !isBenignAddColumnErrorR62Search(ddlErr) {
			s.mu.Unlock()
			return nil, ddlErr
		}
	}
	s.indices[indexName] = cloned
	s.mu.Unlock()

	s.persistIndex(ctx, indexName, cloned)
	return cloned, nil
}

func (s *Server) persistLegacyTypeCopyOnWriteR62Search(
	ctx context.Context,
	indexName string,
	current *schema.IndexSchema,
	docType string,
) *schema.IndexSchema {
	docType = strings.TrimSpace(docType)
	if s == nil || current == nil || current.ES8Mode || docType == "" || docType == "_doc" {
		return current
	}
	if current.LegacyTypeName == docType {
		return current
	}
	s.mu.Lock()
	latest := s.indices[indexName]
	if latest == nil {
		latest = current
	}
	if latest.LegacyTypeName != "" {
		s.mu.Unlock()
		return latest
	}
	cloned := latest.CloneIndexSchema()
	cloned.LegacyTypeName = docType
	s.indices[indexName] = cloned
	s.mu.Unlock()

	s.persistIndex(ctx, indexName, cloned)
	return cloned
}

// ============================================================================
// Bulk Extended Action Metadata (`require_data_stream`, `dynamic_templates`, trailing action)
// ============================================================================

type bulkItemPreMetaR62Search struct {
	hasRequireDataStream bool
	requireDataStream    bool
	badRequireDSRaw      string
	dynamicTemplates     map[string]string
	rawAction            string
	explicitOpType       string
}

// extractAndStripBulkExtendedMetaR62Search extracts `require_data_stream` and `dynamic_templates`
// per bulk operation while also stripping a trailing dangling `{"index":{}}` line after >=1 valid
// pairs (`aggregations/date_histogram.yml` setup line 82) so downstream `validateBulkDeprecatedParams`
// and `preprocessBulkNDJSONRound60` succeed cleanly.
func extractAndStripBulkExtendedMetaR62Search(rawBulk []byte) ([]byte, []bulkItemPreMetaR62Search) {
	lines := bytes.Split(rawBulk, []byte{'\n'})
	// Trim trailing whitespace-only lines
	for len(lines) > 0 && len(bytes.TrimSpace(lines[len(lines)-1])) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return rawBulk, nil
	}

	var outBuf bytes.Buffer
	var metas []bulkItemPreMetaR62Search
	completedOps := 0

	for i := 0; i < len(lines); {
		rawLine := bytes.TrimRight(lines[i], "\r")
		trimmed := bytes.TrimSpace(rawLine)
		if len(trimmed) == 0 {
			i++
			continue
		}
		var actionObj map[string]any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&actionObj); err != nil || len(actionObj) != 1 {
			// Pass malformed line verbatim so preprocessBulkNDJSONRound60 produces exact error
			for j := i; j < len(lines); j++ {
				outBuf.Write(lines[j])
				outBuf.WriteByte('\n')
			}
			return outBuf.Bytes(), metas
		}
		var actName string
		var rawMeta any
		for k, v := range actionObj {
			actName = k
			rawMeta = v
		}
		metaMap, okM := rawMeta.(map[string]any)
		if !okM {
			for j := i; j < len(lines); j++ {
				outBuf.Write(lines[j])
				outBuf.WriteByte('\n')
			}
			return outBuf.Bytes(), metas
		}

		// Upstream ES BulkRequestParser silently breaks on a trailing empty-metadata `{"index":{}}`
		// at EOF after >= 1 complete action pairs (`date_histogram.yml:82`).
		if actName != "delete" && i+1 >= len(lines) && completedOps >= 1 && len(metaMap) == 0 {
			break
		}

		var itemMeta bulkItemPreMetaR62Search
		itemMeta.rawAction = actName
		rewroteMeta := false
		if ot, okOT := metaMap["op_type"].(string); okOT {
			itemMeta.explicitOpType = strings.ToLower(strings.TrimSpace(ot))
			if actName == "index" && itemMeta.explicitOpType == "create" {
				actName = "create"
				delete(metaMap, "op_type")
				rewroteMeta = true
			}
		}
		if rawRDS, hasRDS := metaMap["require_data_stream"]; hasRDS {
			itemMeta.hasRequireDataStream = true
			switch bv := rawRDS.(type) {
			case bool:
				itemMeta.requireDataStream = bv
			case string:
				parsed, okB := parseStrictESBoolR61Search(bv)
				if okB {
					itemMeta.requireDataStream = parsed
				} else {
					itemMeta.badRequireDSRaw = bv
				}
			default:
				itemMeta.badRequireDSRaw = fmt.Sprintf("%v", rawRDS)
			}
			delete(metaMap, "require_data_stream")
			rewroteMeta = true
		}
		if rawDT, hasDT := metaMap["dynamic_templates"]; hasDT && rawDT != nil {
			if dtMap, okDTM := rawDT.(map[string]any); okDTM && len(dtMap) > 0 {
				itemMeta.dynamicTemplates = make(map[string]string, len(dtMap))
				for fk, tv := range dtMap {
					itemMeta.dynamicTemplates[fk] = fmt.Sprintf("%v", tv)
				}
			}
			delete(metaMap, "dynamic_templates")
			rewroteMeta = true
		}

		if rewroteMeta {
			if b, mErr := json.Marshal(map[string]any{actName: metaMap}); mErr == nil {
				outBuf.Write(b)
				outBuf.WriteByte('\n')
			} else {
				outBuf.Write(rawLine)
				outBuf.WriteByte('\n')
			}
		} else {
			outBuf.Write(rawLine)
			outBuf.WriteByte('\n')
		}
		metas = append(metas, itemMeta)
		i++
		if actName != "delete" {
			for i < len(lines) && len(bytes.TrimSpace(lines[i])) == 0 {
				i++
			}
			if i < len(lines) {
				outBuf.Write(bytes.TrimRight(lines[i], "\r"))
				outBuf.WriteByte('\n')
				i++
				completedOps++
			}
		} else {
			completedOps++
		}
	}
	return outBuf.Bytes(), metas
}

func formatJavaMapPreviewR62Search(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := m[k]
		if sub, ok := v.(map[string]any); ok {
			parts = append(parts, k+"="+formatJavaMapPreviewR62Search(sub))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func expandDottedDocForPreviewR62Search(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := doc[k]
		if subM, okM := v.(map[string]any); okM {
			v = expandDottedDocForPreviewR62Search(subM)
		}
		if dot := strings.IndexByte(k, '.'); dot > 0 {
			head := k[:dot]
			tail := k[dot+1:]
			sub := expandDottedDocForPreviewR62Search(map[string]any{tail: v})
			if ex, okEx := out[head].(map[string]any); okEx {
				for sk, sv := range sub {
					ex[sk] = sv
				}
			} else {
				out[head] = sub
			}
			continue
		}
		out[k] = v
	}
	return out
}

func lookupDocPathExpandedR62Search(expanded map[string]any, fieldPath string) (any, bool) {
	curr := any(expanded)
	for _, seg := range strings.Split(fieldPath, ".") {
		m, ok := curr.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[seg]
		if !exists {
			return nil, false
		}
		curr = v
	}
	return curr, true
}

func isFieldAlreadyMappedInSchemaR62Search(sc *schema.IndexSchema, fieldPath string) bool {
	if sc == nil || fieldPath == "" {
		return false
	}
	if _, ok := sc.Fields[fieldPath]; ok {
		return true
	}
	pfx := fieldPath + "."
	for k := range sc.Fields {
		if strings.HasPrefix(k, pfx) {
			return true
		}
	}
	if sc.RawMapping != nil && len(sc.RawMapping.Properties) > 0 {
		curr := sc.RawMapping.Properties
		segs := strings.Split(fieldPath, ".")
		for i, seg := range segs {
			p, ok := curr[seg]
			if !ok {
				break
			}
			if i == len(segs)-1 {
				return true
			}
			curr = p.Properties
		}
	}
	return false
}

func findNamedDynamicTemplatePropR62Search(sc *schema.IndexSchema, tplName string) (esast.FieldProperty, bool) {
	if sc == nil || sc.RawMapping == nil {
		return esast.FieldProperty{}, false
	}
	for _, entry := range sc.RawMapping.DynamicTemplates {
		rawRule, ok := entry[tplName]
		if !ok {
			continue
		}
		ruleMap, okM := rawRule.(map[string]any)
		if !okM {
			continue
		}
		rawMapping, hasMap := ruleMap["mapping"]
		if !hasMap || rawMapping == nil {
			return esast.FieldProperty{Type: "keyword"}, true
		}
		b, err := json.Marshal(rawMapping)
		if err != nil {
			return esast.FieldProperty{}, false
		}
		var fp esast.FieldProperty
		if err := json.Unmarshal(b, &fp); err != nil {
			return esast.FieldProperty{}, false
		}
		return fp, true
	}
	return esast.FieldProperty{}, false
}

// applyBulkActionDynamicTemplatesR62Search applies per-item `dynamic_templates` from bulk action metadata
// (`bulk/11_dynamic_templates.yml`) using thread-safe copy-on-write on `s.indices[indexName]`.
func (s *Server) applyBulkActionDynamicTemplatesR62Search(
	ctx context.Context,
	indexName, docID string,
	current *schema.IndexSchema,
	dynTemplates map[string]string,
	rawDoc []byte,
) (*schema.IndexSchema, int, string, string) {
	if s == nil || current == nil || len(dynTemplates) == 0 || len(bytes.TrimSpace(rawDoc)) == 0 {
		return current, 0, "", ""
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return current, 0, "", ""
	}
	expanded := expandDottedDocForPreviewR62Search(doc)

	fieldPaths := make([]string, 0, len(dynTemplates))
	for fp := range dynTemplates {
		fieldPaths = append(fieldPaths, fp)
	}
	sort.Strings(fieldPaths)

	s.mu.Lock()
	latest := s.indices[indexName]
	if latest == nil {
		latest = current
	}

	var propsToAdd map[string]esast.FieldProperty
	for _, fieldPath := range fieldPaths {
		if isFieldAlreadyMappedInSchemaR62Search(latest, fieldPath) {
			continue
		}
		valAtPath, present := lookupDocPathExpandedR62Search(expanded, fieldPath)
		if !present || valAtPath == nil {
			continue
		}
		tplName := dynTemplates[fieldPath]
		tplProp, foundTpl := findNamedDynamicTemplatePropR62Search(latest, tplName)
		if !foundTpl {
			s.mu.Unlock()
			return latest, http.StatusBadRequest, "document_parsing_exception",
				fmt.Sprintf("[1:1] failed to parse: Can't find dynamic template for dynamic template name [%s] of field [%s]", tplName, fieldPath)
		}
		pType := strings.ToLower(strings.TrimSpace(tplProp.Type))
		if subObj, isObj := valAtPath.(map[string]any); isObj && pType != "" && pType != "object" && pType != "nested" && pType != "flattened" && pType != "geo_point" && pType != "geo_shape" {
			s.mu.Unlock()
			return latest, http.StatusBadRequest, "document_parsing_exception",
				fmt.Sprintf("[1:1] failed to parse field [%s] of type [%s] in document with id '%s'. Preview of field's value: '%s'",
					fieldPath, pType, docID, formatJavaMapPreviewR62Search(subObj))
		}
		if propsToAdd == nil {
			propsToAdd = make(map[string]esast.FieldProperty)
		}
		propsToAdd[fieldPath] = tplProp
	}
	if len(propsToAdd) == 0 {
		s.mu.Unlock()
		return latest, 0, "", ""
	}

	cloned := latest.CloneIndexSchema()
	addSpec := &esast.MappingSpec{Properties: make(map[string]esast.FieldProperty)}
	for fp, prop := range propsToAdd {
		segs := strings.Split(fp, ".")
		curr := addSpec.Properties
		for i := 0; i < len(segs)-1; i++ {
			sub, ok := curr[segs[i]]
			if !ok {
				sub = esast.FieldProperty{Properties: make(map[string]esast.FieldProperty)}
			} else if sub.Properties == nil {
				sub.Properties = make(map[string]esast.FieldProperty)
			}
			curr[segs[i]] = sub
			curr = sub.Properties
		}
		curr[segs[len(segs)-1]] = prop
	}
	mergedMap := schema.MergeMappingSpecs(cloned.RawMapping, addSpec)
	recompiled := schema.CompileIndexSchema(cloned.DorisDB, indexName, mergedMap)
	recompiled.DorisTable = cloned.DorisTable
	recompiled.ES8Mode = cloned.ES8Mode
	recompiled.LegacyTypeName = cloned.LegacyTypeName
	recompiled.IndexMode = cloned.IndexMode
	recompiled.RoutingPath = append([]string(nil), cloned.RoutingPath...)
	recompiled.TimeSeriesStartTime = cloned.TimeSeriesStartTime
	recompiled.TimeSeriesEndTime = cloned.TimeSeriesEndTime
	recompiled.SyntheticSource = cloned.SyntheticSource
	recompiled.SourceMode = cloned.SourceMode
	recompiled.MaxResultWindow = cloned.MaxResultWindow
	recompiled.DefaultCoerce = cloned.DefaultCoerce
	recompiled.DefaultIgnoreMalformed = cloned.DefaultIgnoreMalformed
	schema.ApplyIndexModeDefaults(recompiled)

	var addedBindings []schema.FieldBinding
	for fk, fb := range recompiled.Fields {
		if oldFB, existed := latest.Fields[fk]; !existed || (oldFB.ColumnName == "" && fb.ColumnName != "") {
			addedBindings = append(addedBindings, fb)
		}
	}
	for _, stmt := range schema.GenerateAddColumnsDDL(recompiled, addedBindings) {
		if ddlErr := s.backend.ExecDDL(ctx, stmt); ddlErr != nil && !isBenignAddColumnErrorR62Search(ddlErr) {
			s.mu.Unlock()
			return latest, http.StatusInternalServerError, "doris_ddl_exception", ddlErr.Error()
		}
	}
	s.indices[indexName] = recompiled
	s.mu.Unlock()

	s.persistIndex(ctx, indexName, recompiled)
	return recompiled, 0, "", ""
}

// ============================================================================
// Date-Math Index / Alias Name Resolution (`<logs_http_{2022-12-31||/d{yyyy-MM-dd}}>`)
// ============================================================================

func resolveESIndexDateMathR62Search(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "<") || !strings.HasSuffix(trimmed, ">") || len(trimmed) < 4 {
		return raw
	}
	inner := trimmed[1 : len(trimmed)-1]
	openBrace := strings.IndexByte(inner, '{')
	if openBrace < 0 {
		return inner
	}
	// Find matching closing '}' accounting for nested `{format|tz}`
	depth := 0
	closeBrace := -1
	for i := openBrace; i < len(inner); i++ {
		switch inner[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				closeBrace = i
			}
		}
		if closeBrace >= 0 {
			break
		}
	}
	if closeBrace < 0 {
		return raw
	}
	prefix := inner[:openBrace]
	suffix := inner[closeBrace+1:]
	expr := inner[openBrace+1 : closeBrace]

	fmtPattern := "yyyy.MM.dd"
	tzLoc := time.UTC
	if nestedOpen := strings.IndexByte(expr, '{'); nestedOpen >= 0 && strings.HasSuffix(expr, "}") {
		nestedInner := expr[nestedOpen+1 : len(expr)-1]
		expr = expr[:nestedOpen]
		if pipeIdx := strings.IndexByte(nestedInner, '|'); pipeIdx >= 0 {
			if strings.TrimSpace(nestedInner[:pipeIdx]) != "" {
				fmtPattern = strings.TrimSpace(nestedInner[:pipeIdx])
			}
			tzName := strings.TrimSpace(nestedInner[pipeIdx+1:])
			if tzName != "" {
				if loc, err := time.LoadLocation(tzName); err == nil {
					tzLoc = loc
				} else if off, okOff := parseFixedOffsetTZR62Search(tzName); okOff {
					tzLoc = off
				}
			}
		} else if strings.TrimSpace(nestedInner) != "" {
			fmtPattern = strings.TrimSpace(nestedInner)
		}
	}

	resolvedTime, ok := parseESDateMathBaseAndOpsR62Search(expr, fmtPattern, tzLoc)
	if !ok {
		return raw
	}
	formatted := formatESDateMathJavaPatternR62Search(resolvedTime.In(tzLoc), fmtPattern)
	return prefix + formatted + suffix
}

func parseFixedOffsetTZR62Search(tz string) (*time.Location, bool) {
	s := strings.TrimSpace(tz)
	if s == "Z" || strings.EqualFold(s, "UTC") {
		return time.UTC, true
	}
	if len(s) >= 3 && (s[0] == '+' || s[0] == '-') {
		sign := 1
		if s[0] == '-' {
			sign = -1
		}
		rest := s[1:]
		parts := strings.Split(rest, ":")
		var hh, mm int
		if len(parts) == 2 {
			h, err1 := strconv.Atoi(parts[0])
			m, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				hh, mm = h, m
				return time.FixedZone(s, sign*(hh*3600+mm*60)), true
			}
		} else if len(rest) == 4 {
			h, err1 := strconv.Atoi(rest[:2])
			m, err2 := strconv.Atoi(rest[2:])
			if err1 == nil && err2 == nil {
				hh, mm = h, m
				return time.FixedZone(s, sign*(hh*3600+mm*60)), true
			}
		} else if h, err := strconv.Atoi(rest); err == nil {
			return time.FixedZone(s, sign*h*3600), true
		}
	}
	return nil, false
}

func parseESDateMathBaseAndOpsR62Search(expr, fmtPattern string, loc *time.Location) (time.Time, bool) {
	expr = strings.TrimSpace(expr)
	var base time.Time
	var ops string
	if strings.HasPrefix(expr, "now") {
		base = time.Now().In(loc)
		ops = expr[3:]
	} else if idx := strings.Index(expr, "||"); idx >= 0 {
		dateStr := strings.TrimSpace(expr[:idx])
		ops = expr[idx+2:]
		goLayout := javaDatePatternToGoLayoutR62Search(fmtPattern)
		if t, err := time.ParseInLocation(goLayout, dateStr, loc); err == nil {
			base = t
		} else if ms, okMS := schema.ParseESDateWithFormatToEpochMillis(dateStr, "", time.Now().UTC()); okMS {
			base = time.UnixMilli(ms).In(loc)
		} else {
			return time.Time{}, false
		}
	} else {
		return time.Time{}, false
	}

	cur := base
	for i := 0; i < len(ops); {
		op := ops[i]
		if op == '/' {
			if i+1 >= len(ops) {
				return time.Time{}, false
			}
			unit := ops[i+1]
			cur = applyESDateMathRoundR62Search(cur, unit)
			i += 2
			continue
		}
		if op == '+' || op == '-' {
			sign := 1
			if op == '-' {
				sign = -1
			}
			i++
			j := i
			for j < len(ops) && ops[j] >= '0' && ops[j] <= '9' {
				j++
			}
			num := 1
			if j > i {
				n, err := strconv.Atoi(ops[i:j])
				if err != nil {
					return time.Time{}, false
				}
				num = n
			}
			if j >= len(ops) {
				return time.Time{}, false
			}
			unit := ops[j]
			i = j + 1
			switch unit {
			case 'y', 'Y':
				cur = cur.AddDate(sign*num, 0, 0)
			case 'M':
				cur = cur.AddDate(0, sign*num, 0)
			case 'w':
				cur = cur.AddDate(0, 0, sign*num*7)
			case 'd':
				cur = cur.AddDate(0, 0, sign*num)
			case 'h', 'H':
				cur = cur.Add(time.Duration(sign*num) * time.Hour)
			case 'm':
				cur = cur.Add(time.Duration(sign*num) * time.Minute)
			case 's':
				cur = cur.Add(time.Duration(sign*num) * time.Second)
			default:
				return time.Time{}, false
			}
			continue
		}
		i++
	}
	return cur, true
}

func applyESDateMathRoundR62Search(t time.Time, unit byte) time.Time {
	loc := t.Location()
	switch unit {
	case 'y', 'Y':
		return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, loc)
	case 'M':
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
	case 'w':
		wd := int(t.Weekday())
		if wd == 0 {
			wd = 7
		}
		d := t.AddDate(0, 0, -(wd - 1))
		return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
	case 'd':
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	case 'h', 'H':
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, loc)
	case 'm':
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, loc)
	case 's':
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
	default:
		return t
	}
}

func javaDatePatternToGoLayoutR62Search(pat string) string {
	r := strings.NewReplacer(
		"uuuu", "2006",
		"yyyy", "2006",
		"yy", "06",
		"MM", "01",
		"dd", "02",
		"HH", "15",
		"mm", "04",
		"ss", "05",
	)
	return r.Replace(pat)
}

func formatESDateMathJavaPatternR62Search(t time.Time, pat string) string {
	return t.Format(javaDatePatternToGoLayoutR62Search(pat))
}

func resolveCommaDateMathTokensR62Search(raw string) string {
	if !strings.Contains(raw, "<") {
		return raw
	}
	parts := strings.Split(raw, ",")
	for i, p := range parts {
		trimmed := strings.TrimSpace(p)
		neg := false
		if strings.HasPrefix(trimmed, "-") && strings.HasPrefix(trimmed[1:], "<") {
			neg = true
			trimmed = trimmed[1:]
		}
		res := resolveESIndexDateMathR62Search(trimmed)
		if neg {
			parts[i] = "-" + res
		} else {
			parts[i] = res
		}
	}
	return strings.Join(parts, ",")
}

// ============================================================================
// Wave-1 Server Hooks: Deprecated Index Settings, GET /{index}, _flush, _forcemerge, _stats
// ============================================================================

func (s *Server) validateIndexDeprecatedSettingsR62Search(w http.ResponseWriter, r *http.Request, indexName string, settings map[string]any) (int, string, string) {
	if len(settings) == 0 {
		return 0, "", ""
	}
	flat := make(map[string]any)
	flattenSettingsInput("", settings, flat)
	isES8 := s != nil && s.isES8Mode(r)

	for _, k := range []string{"soft_deletes.enabled", "index.soft_deletes.enabled", "settings.soft_deletes.enabled", "settings.index.soft_deletes.enabled"} {
		if raw, ok := flat[k]; ok && raw != nil {
			valStr := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", raw)))
			if valStr == "false" {
				if isES8 {
					return http.StatusBadRequest, "illegal_argument_exception",
						"Creating indices with soft-deletes disabled is not supported. Indices must have soft-deletes enabled in Elasticsearch 8.0 and later."
				}
				msg := "Creating indices with soft-deletes disabled is deprecated and will be removed in future Elasticsearch versions. Please do not specify value for setting [index.soft_deletes.enabled] of index."
				if strings.TrimSpace(indexName) != "" {
					msg = fmt.Sprintf("Creating indices with soft-deletes disabled is deprecated and will be removed in future Elasticsearch versions. Please do not specify value for setting [index.soft_deletes.enabled] of index [%s].", indexName)
				}
				emitESDeprecationWarningRound61(w, s, r, msg)
			}
		}
	}
	hasTranslogRetention := false
	hasHTMLStripDeprecated := false
	for k, raw := range flat {
		if raw == nil {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimPrefix(k, "settings."), "index.")
		if clean == "translog.retention.age" || clean == "translog.retention.size" {
			if isES8 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("index.translog.retention.* settings are removed; invalid setting [index.%s]", clean)
			}
			hasTranslogRetention = true
		}
		if strings.Contains(clean, "analysis.") && strings.Contains(fmt.Sprintf("%v", raw), "htmlStrip") {
			hasHTMLStripDeprecated = true
		}
	}
	if hasTranslogRetention && !isES8 {
		emitESDeprecationWarningRound61(w, s, r,
			"Translog retention settings [index.translog.retention.age] and [index.translog.retention.size] are deprecated and effectively ignored. They will be removed in a future version.")
	}
	if hasHTMLStripDeprecated && !isES8 {
		emitESDeprecationWarningRound61(w, s, r,
			"The [htmpStrip] char filter name is deprecated and will be removed in a future version. Please change the filter name to [html_strip] instead.")
	}
	return 0, "", ""
}

func isIndexGetFeaturesSegmentR62Search(seg string) bool {
	if !strings.Contains(seg, ",") {
		return false
	}
	for _, part := range strings.Split(seg, ",") {
		switch strings.TrimSpace(part) {
		case "_settings", "_mappings", "_mapping", "_aliases", "_alias":
		default:
			return false
		}
	}
	return true
}

func parseIndexGetFeaturesR62Search(r *http.Request, pathFeatureSeg string) (wantAliases, wantMappings, wantSettings, hasFilter bool) {
	raw := strings.TrimSpace(pathFeatureSeg)
	if raw == "" && r != nil && r.URL != nil {
		raw = strings.TrimSpace(r.URL.Query().Get("features"))
	}
	if raw == "" {
		return true, true, true, false
	}
	for _, part := range strings.Split(raw, ",") {
		switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(part)), "_") {
		case "alias", "aliases":
			wantAliases = true
		case "mapping", "mappings":
			wantMappings = true
		case "setting", "settings":
			wantSettings = true
		}
	}
	return wantAliases, wantMappings, wantSettings, true
}

func (s *Server) handleGetIndexR62Search(w http.ResponseWriter, r *http.Request, pathFeatureSeg string) {
	incType, _, okInc := checkIncludeTypeNameParamR61CRUD(w, s, r, "get index")
	if !okInc {
		return
	}
	rawIndex := resolveCommaDateMathTokensR62Search(strings.TrimSpace(r.PathValue("index")))
	if rawIndex != "" && rawIndex != "_all" {
		for _, part := range strings.Split(rawIndex, ",") {
			p := strings.TrimSpace(part)
			if strings.HasPrefix(p, "_") && p != "_all" {
				writeESError(w, http.StatusBadRequest, "invalid_index_name_exception",
					fmt.Sprintf("Invalid index name [%s], must not start with '_'", p))
				return
			}
		}
	}
	targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	wantAliases, wantMappings, wantSettings, hasFeatureFilter := parseIndexGetFeaturesR62Search(r, pathFeatureSeg)
	human := isTruthyBoolQueryParam(r, "human")
	flat := isTruthyBoolQueryParam(r, "flat_settings")
	verNum := s.effectiveClusterESVersionNumber(r)
	if s.isES8Mode(r) {
		verNum = "8.15.5"
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := make(map[string]any, len(targets))
	for _, indexName := range targets {
		idx, okIdx := s.indices[indexName]
		if !okIdx {
			continue
		}
		entry := make(map[string]any, 4)
		if dsOwner := s.findOwningDataStreamLockedR62Search(indexName); dsOwner != "" {
			entry["data_stream"] = dsOwner
		}
		if wantAliases {
			idxAliases := make(map[string]any)
			for alias, aliasTargets := range s.aliases {
				for _, t := range aliasTargets {
					if t == indexName {
						idxAliases[alias] = s.getAliasMetaMapLocked(alias, indexName)
					}
				}
			}
			entry["aliases"] = idxAliases
		} else if hasFeatureFilter {
			entry["aliases"] = map[string]any{}
		}
		if wantMappings {
			entry["mappings"] = wrapMappingsResponseForTypeR61CRUD(idx, buildMappingResponseMapRound59(idx), incType, "")
		} else if hasFeatureFilter {
			entry["mappings"] = map[string]any{}
		}
		if wantSettings {
			shortFlat := s.buildIndexSettingsMapLocked(indexName)
			if human {
				if cdRaw, okCD := shortFlat["creation_date"]; okCD {
					if ms, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", cdRaw)), 10, 64); err == nil {
						shortFlat["creation_date_string"] = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
					}
				}
				shortFlat["version.created_string"] = verNum
			}
			entry["settings"] = formatIndexSettingsOutput(shortFlat, flat)
		} else if hasFeatureFilter {
			entry["settings"] = map[string]any{}
		}
		resp[indexName] = entry
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) handleIndexStatsR62Search(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	s.handleIndexStatsRound60(rec, r)
	for k, vals := range rec.Header() {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil || payload == nil {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	// Preserve true `flush.total: 0` when an index has not been flushed since creation (`indices.flush/10_basic.yml`).
	indicesObj, _ := payload["indices"].(map[string]any)
	var sumFlush int64
	adjustedAny := false
	s.mu.RLock()
	for idxName, rawIdxVal := range indicesObj {
		idxMap, okM := rawIdxVal.(map[string]any)
		if !okM {
			continue
		}
		st := s.indexStats[idxName]
		actualFlush := int64(1)
		if st != nil {
			actualFlush = st.flushTotal.Load()
		}
		sumFlush += actualFlush
		if st != nil && actualFlush == 0 {
			for _, secKey := range []string{"primaries", "total"} {
				if secMap, okS := idxMap[secKey].(map[string]any); okS {
					if flMap, okF := secMap["flush"].(map[string]any); okF {
						flMap["total"] = int64(0)
						adjustedAny = true
					}
				}
			}
		}
	}
	s.mu.RUnlock()
	if adjustedAny {
		if allMap, okA := payload["_all"].(map[string]any); okA {
			for _, secKey := range []string{"primaries", "total"} {
				if secMap, okS := allMap[secKey].(map[string]any); okS {
					if flMap, okF := secMap["flush"].(map[string]any); okF {
						flMap["total"] = sumFlush
					}
				}
			}
		}
		writeJSONWithRequest(w, r, http.StatusOK, payload)
		return
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (s *Server) handleRefreshFlushForceMergeR62Search(w http.ResponseWriter, r *http.Request) {
	trimmedPath := strings.Trim(r.URL.Path, "/")
	isFlush := strings.HasSuffix(trimmedPath, "_flush") || strings.Contains(r.URL.Path, "/_flush/")
	isForceMerge := strings.HasSuffix(trimmedPath, "_forcemerge") || strings.Contains(r.URL.Path, "/_forcemerge/")

	if isFlush && r != nil && r.URL != nil {
		q := r.URL.Query()
		if isTruthyBoolQueryParam(r, "force") && q.Has("wait_if_ongoing") && !isTruthyBoolQueryParam(r, "wait_if_ongoing") {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: wait_if_ongoing must be true for a force flush;")
			return
		}
	}
	if isForceMerge && r != nil && r.URL != nil {
		q := r.URL.Query()
		if q.Has("only_expunge_deletes") && isTruthyBoolQueryParam(r, "only_expunge_deletes") && q.Has("max_num_segments") {
			if s.isES8Mode(r) {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
					"Validation Failed: 1: cannot set only_expunge_deletes and max_num_segments at the same time, those two parameters are mutually exclusive;")
				return
			}
			emitESDeprecationWarningRound61(w, s, r,
				"setting only_expunge_deletes and max_num_segments at the same time is deprecated and will be rejected in a future version")
		}
		if q.Has("wait_for_completion") && !isTruthyBoolQueryParam(r, "wait_for_completion") {
			reg := s.getTaskRegistry()
			entry := reg.register("indices:admin/forcemerge", "force-merge", -1, extractTaskHeadersFromRequest(r), func() {})
			entry.markDone(map[string]any{
				"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
			}, nil)
			writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"task": entry.fullID})
			return
		}
	}
	s.handleRefresh(w, r)
}

func (s *Server) handleFlushSyncedR62Search(w http.ResponseWriter, r *http.Request, rawIndex string) {
	if !s.isES8Mode(r) {
		emitESDeprecationWarningRound61(w, s, r,
			"Synced flush is deprecated and will be removed in 8.0; use flush at /_flush or /{index}/_flush instead.")
	}
	s.handleFlushSyncedRound57(w, r, rawIndex)
}

func (s *Server) handleClusterHealthR62Search(w http.ResponseWriter, r *http.Request) {
	// On a 1-node cluster, ES data-stream backing indices use `auto_expand_replicas: 0-1` (0 replicas on 1 node),
	// so `GET /_cluster/health?wait_for_status=green` succeeds immediately (`data_stream/10_basic.yml`, `150_tsdb.yml`)!
	if r != nil && r.URL != nil && strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("wait_for_status")), "green") {
		allReplicaIndicesAreDataStreamBacking := true
		hasAnyDSBacking := false
		s.mu.RLock()
		for idxName := range s.indices {
			if s.closedIndices[idxName] {
				continue
			}
			cs := s.indexCustomSettings[idxName]
			reps := 0
			if cs != nil {
				for _, k := range []string{"number_of_replicas", "index.number_of_replicas"} {
					if raw, ok := cs[k]; ok && raw != nil {
						if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil {
							reps = n
							break
						}
					}
				}
			}
			if reps > 0 {
				if strings.HasPrefix(idxName, ".ds-") || strings.HasPrefix(idxName, ".fs-") || s.findOwningDataStreamLockedR62Search(idxName) != "" {
					hasAnyDSBacking = true
				} else {
					allReplicaIndicesAreDataStreamBacking = false
					break
				}
			}
		}
		s.mu.RUnlock()
		if hasAnyDSBacking && allReplicaIndicesAreDataStreamBacking {
			rec := httptest.NewRecorder()
			rCopy := r.Clone(r.Context())
			q := rCopy.URL.Query()
			q.Set("wait_for_status", "yellow")
			rCopy.URL.RawQuery = q.Encode()
			s.handleClusterHealthR61Admin(rec, rCopy)
			for k, vals := range rec.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			var payload map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &payload) == nil && payload != nil {
				payload["status"] = "green"
				payload["unassigned_shards"] = 0
				payload["active_shards_percent_as_number"] = 100.0
				if indicesMap, okI := payload["indices"].(map[string]any); okI {
					for _, iv := range indicesMap {
						if im, okM := iv.(map[string]any); okM {
							im["status"] = "green"
							im["unassigned_shards"] = 0
							im["number_of_replicas"] = 0
						}
					}
				}
				writeJSONWithRequest(w, r, http.StatusOK, payload)
				return
			}
		}
	}
	s.handleClusterHealthR61Admin(w, r)
}

// ============================================================================
// Wave-1 Alias Enhancements: Date-Math, Data-Stream Aliases, `must_exist` & `action_results`
// ============================================================================

func (s *Server) handleUpdateAliasesR62Search(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	bodyBytes = normalizeAliasActionsBodyRound60(bodyBytes)
	type aliasActionItemR62Search struct {
		Index         string          `json:"index"`
		Indices       []string        `json:"indices"`
		Alias         string          `json:"alias"`
		Aliases       []string        `json:"aliases"`
		Filter        *esast.Query    `json:"filter,omitempty"`
		RawFilter     json.RawMessage `json:"-"`
		IsWriteIndex  *bool           `json:"is_write_index,omitempty"`
		IsHidden      *bool           `json:"is_hidden,omitempty"`
		MustExist     *bool           `json:"must_exist,omitempty"`
		Routing       string          `json:"routing,omitempty"`
		IndexRouting  string          `json:"index_routing,omitempty"`
		SearchRouting string          `json:"search_routing,omitempty"`
	}
	var rawPayload struct {
		Actions []map[string]json.RawMessage `json:"actions"`
	}
	if err := json.Unmarshal(bodyBytes, &rawPayload); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}

	parsedActions := make([]map[string]aliasActionItemR62Search, len(rawPayload.Actions))
	for i, rawActMap := range rawPayload.Actions {
		if len(rawActMap) == 0 {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "action object must specify one of [add, remove, remove_index]")
			return
		}
		parsedActions[i] = make(map[string]aliasActionItemR62Search, len(rawActMap))
		for actType, rawSpecBytes := range rawActMap {
			if actType != "add" && actType != "remove" && actType != "remove_index" {
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("unknown alias action [%s]", actType))
				return
			}
			var item aliasActionItemR62Search
			if err := json.Unmarshal(rawSpecBytes, &item); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
			var rawFields map[string]json.RawMessage
			if json.Unmarshal(rawSpecBytes, &rawFields) == nil {
				if rf, hasF := rawFields["filter"]; hasF && len(bytes.TrimSpace(rf)) > 0 && !bytes.Equal(bytes.TrimSpace(rf), []byte("null")) {
					item.RawFilter = rf
				}
			}
			parsedActions[i][actType] = item
		}
	}

	isES8 := s.isES8Mode(r)
	_ = s.syncCatalogFromBackend(r.Context())
	modifiedAliases := make(map[string][]string)
	var removedIndices []string
	var tablesToDrop []*schema.IndexSchema

	s.mu.Lock()
	expandTargetsFromSet := func(rawList []string, targetSet map[string]bool) []string {
		resolvedRaw := make([]string, 0, len(rawList))
		for _, tok := range rawList {
			resolvedRaw = append(resolvedRaw, resolveCommaDateMathTokensR62Search(tok))
		}
		universe := make([]string, 0, len(targetSet))
		for name := range targetSet {
			// Exclude hidden `.ds-*` / `.fs-*` backing indices from wildcard `*` unless explicitly matched by dot pattern!
			if strings.HasPrefix(name, ".ds-") || strings.HasPrefix(name, ".fs-") {
				hasExplicitDot := false
				for _, rt := range resolvedRaw {
					if strings.HasPrefix(strings.TrimSpace(rt), ".") {
						hasExplicitDot = true
						break
					}
				}
				if !hasExplicitDot {
					continue
				}
			}
			universe = append(universe, name)
		}
		expanded := expandNamesWithExclusions(resolvedRaw, universe)
		sort.Strings(expanded)
		return expanded
	}
	resolveAliasTokens := func(rawList []string) []string {
		out := make([]string, 0, len(rawList))
		for _, tok := range splitCommaTrimmedTokens(rawList) {
			out = append(out, resolveESIndexDateMathR62Search(tok))
		}
		return out
	}

	// Universe includes BOTH concrete indices AND data streams (`data_stream/140_data_stream_aliases.yml`)!
	simulatedTargets := make(map[string]bool, len(s.indices)+len(s.dataStreams))
	for k := range s.indices {
		simulatedTargets[k] = true
	}
	for dsName := range s.dataStreams {
		simulatedTargets[dsName] = true
	}
	simulatedAliases := make(map[string]map[string]bool, len(s.aliases))
	for al, tList := range s.aliases {
		m := make(map[string]bool, len(tList))
		for _, t := range tList {
			m[t] = true
		}
		simulatedAliases[al] = m
	}

	indicesRemovedInTx := make(map[string]bool)
	for _, action := range parsedActions {
		if remIdx, ok := action["remove_index"]; ok {
			if remIdx.MustExist != nil {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "parsing_exception", "Failed to parse [must_exist]: unsupported parameter for [remove_index]")
				return
			}
			rawIndices := append([]string(nil), remIdx.Indices...)
			if remIdx.Index != "" {
				rawIndices = append(rawIndices, remIdx.Index)
			}
			for _, idxName := range expandTargetsFromSet(splitCommaTrimmedTokens(rawIndices), simulatedTargets) {
				indicesRemovedInTx[idxName] = true
			}
		}
	}

	type actionExecResultR62Search struct {
		status    int
		actType   string
		indices   []string
		aliases   []string
		errType   string
		errReason string
		skipApply bool
	}
	actionResults := make([]actionExecResultR62Search, len(parsedActions))
	hasPartialActionError := false
	writeIndexSetForAlias := make(map[string]string)

	for actIdx, action := range parsedActions {
		if add, ok := action["add"]; ok {
			if add.MustExist != nil {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "parsing_exception", "Failed to parse [must_exist]: unsupported parameter for [add]")
				return
			}
			rawIndices := append([]string(nil), add.Indices...)
			if add.Index != "" {
				rawIndices = append(rawIndices, add.Index)
			}
			rawIndices = splitCommaTrimmedTokens(rawIndices)
			for i := range rawIndices {
				rawIndices[i] = resolveESIndexDateMathR62Search(rawIndices[i])
			}
			rawAliases := append([]string(nil), add.Aliases...)
			if add.Alias != "" {
				rawAliases = append(rawAliases, add.Alias)
			}
			rawAliases = resolveAliasTokens(rawAliases)
			if len(rawIndices) == 0 || len(rawAliases) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index and alias are required for [add];")
				return
			}
			for _, pat := range rawIndices {
				if pat != "" && !strings.HasPrefix(pat, "-") && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedTargets[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			targets := expandTargetsFromSet(rawIndices, simulatedTargets)
			if len(targets) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+strings.Join(rawIndices, ",")+"]")
				return
			}
			for _, tName := range targets {
				if blocked, reason := s.isIndexMetadataBlockedLocked(tName, false); blocked {
					s.mu.Unlock()
					writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
					return
				}
				if sc := s.indices[tName]; sc != nil && sc.IndexMode == "time_series" {
					if err := validateAliasNoRoutingOnTSDBR61CRUD(AliasMetadata{
						Filter:        add.Filter,
						IsWriteIndex:  add.IsWriteIndex,
						IsHidden:      add.IsHidden,
						Routing:       add.Routing,
						IndexRouting:  add.IndexRouting,
						SearchRouting: add.SearchRouting,
					}); err != nil {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
						return
					}
				}
			}
			var cleanAliases []string
			for _, al := range rawAliases {
				if strings.HasPrefix(al, "-") {
					continue
				}
				cleanAliases = append(cleanAliases, al)
				if reason, validName := validateESIndexName(al); !validName {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception",
						strings.Replace(reason, "Invalid index name", "Invalid alias name", 1))
					return
				}
				if s.indices[al] != nil && !indicesRemovedInTx[al] {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], an index exists with the same name as the alias", al))
					return
				}
				if _, isDS := s.dataStreams[al]; isDS {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], a data stream exists with the same name as the alias", al))
					return
				}
				if add.IsWriteIndex != nil && *add.IsWriteIndex {
					if len(targets) > 1 {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Alias [%s] has more than one write index", al))
						return
					}
					if prevIdx, hadPrev := writeIndexSetForAlias[al]; hadPrev && prevIdx != targets[0] {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Alias [%s] has more than one write index [%s, %s]", al, prevIdx, targets[0]))
						return
					}
					writeIndexSetForAlias[al] = targets[0]
				}
				if simulatedAliases[al] == nil {
					simulatedAliases[al] = make(map[string]bool)
				}
				for _, tName := range targets {
					simulatedAliases[al][tName] = true
				}
			}
			actionResults[actIdx] = actionExecResultR62Search{
				status:  http.StatusOK,
				actType: "add",
				indices: targets,
				aliases: cleanAliases,
			}
		}

		if rem, ok := action["remove"]; ok {
			rawIndices := append([]string(nil), rem.Indices...)
			if rem.Index != "" {
				rawIndices = append(rawIndices, rem.Index)
			}
			rawIndices = splitCommaTrimmedTokens(rawIndices)
			for i := range rawIndices {
				rawIndices[i] = resolveESIndexDateMathR62Search(rawIndices[i])
			}
			rawAliases := append([]string(nil), rem.Aliases...)
			if rem.Alias != "" {
				rawAliases = append(rawAliases, rem.Alias)
			}
			rawAliases = resolveAliasTokens(rawAliases)
			if len(rawIndices) == 0 || len(rawAliases) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index and alias are required for [remove];")
				return
			}
			strictMustExist := false
			if rem.MustExist != nil {
				strictMustExist = *rem.MustExist
			} else if !isES8 || len(parsedActions) == 1 {
				// In ES < 8.14 (and single-action requests), missing alias fails 404; in ES 8.14+ multi-action
				// requests with must_exist=null or must_exist=false, partial success records 404 in action_results!
				strictMustExist = !isES8
			}
			for _, pat := range rawIndices {
				if pat != "" && !strings.HasPrefix(pat, "-") && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedTargets[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			targets := expandTargetsFromSet(rawIndices, simulatedTargets)
			for _, tName := range targets {
				if blocked, reason := s.isIndexMetadataBlockedLocked(tName, false); blocked {
					s.mu.Unlock()
					writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
					return
				}
			}

			var missingAl string
			hasAliasExclusion := false
			for _, al := range rawAliases {
				if strings.HasPrefix(al, "-") && len(al) > 1 {
					hasAliasExclusion = true
					break
				}
			}
			if hasAliasExclusion {
				var simUniv []string
				for simAl, idxMap := range simulatedAliases {
					if len(idxMap) > 0 {
						simUniv = append(simUniv, simAl)
					}
				}
				for _, tok := range rawAliases {
					if !strings.HasPrefix(tok, "-") && !strings.ContainsAny(tok, "*?") && tok != "_all" {
						hasMatch := false
						if idxMap := simulatedAliases[tok]; idxMap != nil {
							for _, idx := range targets {
								if idxMap[idx] {
									hasMatch = true
									break
								}
							}
						}
						if !hasMatch && missingAl == "" {
							missingAl = tok
						}
					}
				}
				expandedAliases := expandNamesWithExclusions(rawAliases, simUniv)
				foundAny := false
				for _, simAl := range expandedAliases {
					if idxMap := simulatedAliases[simAl]; idxMap != nil {
						for _, idx := range targets {
							if idxMap[idx] {
								foundAny = true
								delete(idxMap, idx)
							}
						}
					}
				}
				if !foundAny && missingAl == "" {
					missingAl = strings.Join(rawAliases, ",")
				}
			} else {
				for _, al := range rawAliases {
					if al == "" {
						continue
					}
					foundOnTarget := false
					if strings.ContainsAny(al, "*?") || al == "_all" {
						for simAl, idxMap := range simulatedAliases {
							if al == "_all" || al == "*" || matchWildcardPattern(al, simAl) {
								for _, idx := range targets {
									if idxMap[idx] {
										foundOnTarget = true
										delete(idxMap, idx)
									}
								}
							}
						}
					} else if idxMap := simulatedAliases[al]; idxMap != nil {
						for _, idx := range targets {
							if idxMap[idx] {
								foundOnTarget = true
								delete(idxMap, idx)
							}
						}
					}
					if !foundOnTarget && missingAl == "" {
						missingAl = al
					}
				}
			}

			if missingAl != "" {
				if strictMustExist || (rem.MustExist == nil && len(parsedActions) == 1) {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "aliases_not_found_exception", fmt.Sprintf("aliases [%s] missing", missingAl))
					return
				}
				hasPartialActionError = true
				actionResults[actIdx] = actionExecResultR62Search{
					status:    http.StatusNotFound,
					actType:   "remove",
					indices:   targets,
					aliases:   rawAliases,
					errType:   "aliases_not_found_exception",
					errReason: fmt.Sprintf("aliases [%s] missing", missingAl),
					skipApply: true,
				}
			} else {
				actionResults[actIdx] = actionExecResultR62Search{
					status:  http.StatusOK,
					actType: "remove",
					indices: targets,
					aliases: rawAliases,
				}
			}
		}

		if remIdx, ok := action["remove_index"]; ok {
			rawIndices := append([]string(nil), remIdx.Indices...)
			if remIdx.Index != "" {
				rawIndices = append(rawIndices, remIdx.Index)
			}
			rawIndices = splitCommaTrimmedTokens(rawIndices)
			for i := range rawIndices {
				rawIndices[i] = resolveESIndexDateMathR62Search(rawIndices[i])
			}
			if len(rawIndices) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is required for [remove_index];")
				return
			}
			for _, pat := range rawIndices {
				if pat != "" && !strings.HasPrefix(pat, "-") && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedTargets[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			targets := expandTargetsFromSet(rawIndices, simulatedTargets)
			for _, indexName := range targets {
				if blocked, reason := s.isIndexMetadataBlockedLocked(indexName, true); blocked {
					s.mu.Unlock()
					writeESError(w, http.StatusForbidden, "cluster_block_exception", reason)
					return
				}
				delete(simulatedTargets, indexName)
				for _, idxMap := range simulatedAliases {
					delete(idxMap, indexName)
				}
			}
			actionResults[actIdx] = actionExecResultR62Search{
				status:  http.StatusOK,
				actType: "remove_index",
				indices: targets,
			}
		}
	}

	// If every single action failed (no action succeeded), return the first 404 error directly.
	if hasPartialActionError {
		anyOK := false
		for _, ar := range actionResults {
			if ar.status == http.StatusOK {
				anyOK = true
				break
			}
		}
		if !anyOK {
			s.mu.Unlock()
			writeESError(w, actionResults[0].status, actionResults[0].errType, actionResults[0].errReason)
			return
		}
	}

	liveTargetsSet := func() map[string]bool {
		m := make(map[string]bool, len(s.indices)+len(s.dataStreams))
		for k := range s.indices {
			m[k] = true
		}
		for dsName := range s.dataStreams {
			m[dsName] = true
		}
		return m
	}
	expandAliasListLocked := func(rawList []string) []string {
		universe := make([]string, 0, len(s.aliases))
		for alName := range s.aliases {
			universe = append(universe, alName)
		}
		return expandNamesWithExclusions(rawList, universe)
	}

	for actIdx, action := range parsedActions {
		if actionResults[actIdx].skipApply {
			continue
		}
		if add, ok := action["add"]; ok {
			targets := actionResults[actIdx].indices
			var rawFilterMap map[string]any
			if len(add.RawFilter) > 0 {
				dec := json.NewDecoder(bytes.NewReader(add.RawFilter))
				dec.UseNumber()
				_ = dec.Decode(&rawFilterMap)
			}
			meta := AliasMetadata{
				Filter:        add.Filter,
				RawFilter:     rawFilterMap,
				IsWriteIndex:  add.IsWriteIndex,
				IsHidden:      add.IsHidden,
				Routing:       add.Routing,
				IndexRouting:  add.IndexRouting,
				SearchRouting: add.SearchRouting,
			}
			for _, al := range actionResults[actIdx].aliases {
				for _, tName := range targets {
					s.addAliasWithMetaLocked(al, tName, meta)
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		}
		if rem, ok := action["remove"]; ok {
			rawIndices := append([]string(nil), rem.Indices...)
			if rem.Index != "" {
				rawIndices = append(rawIndices, rem.Index)
			}
			rawIndicesNorm := splitCommaTrimmedTokens(rawIndices)
			for i := range rawIndicesNorm {
				rawIndicesNorm[i] = resolveESIndexDateMathR62Search(rawIndicesNorm[i])
			}
			aliases := expandAliasListLocked(actionResults[actIdx].aliases)
			hasAllIdx := len(rawIndicesNorm) == 1 && (rawIndicesNorm[0] == "*" || rawIndicesNorm[0] == "_all")
			targets := expandTargetsFromSet(rawIndicesNorm, liveTargetsSet())
			for _, al := range aliases {
				if hasAllIdx {
					delete(s.aliases, al)
					delete(s.aliasMeta, al)
				} else {
					for _, tName := range targets {
						s.removeAliasTargetLocked(al, tName)
					}
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		}
		if _, ok := action["remove_index"]; ok {
			for _, indexName := range actionResults[actIdx].indices {
				if idx, exists := s.indices[indexName]; exists {
					tablesToDrop = append(tablesToDrop, idx)
				}
				delete(s.indices, indexName)
				delete(s.docRouting, indexName)
				delete(s.docVersions, indexName)
				delete(s.indexDefaultPipelines, indexName)
				delete(s.indexFinalPipelines, indexName)
				delete(s.closedIndices, indexName)
				delete(s.indexCustomSettings, indexName)
				delete(s.indexNextSeqNo, indexName)
				delete(s.docSeqNos, indexName)
				delete(s.docDeleted, indexName)
				delete(s.docExtTombstones, indexName)
				delete(s.unrefreshedDocs, indexName)
				delete(s.indexStats, indexName)
				removedIndices = append(removedIndices, indexName)
				for alias := range s.aliases {
					s.removeAliasTargetLocked(alias, indexName)
					modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
				}
			}
		}
	}
	s.mu.Unlock()

	for _, indexName := range removedIndices {
		s.deleteCatalogEntity(r.Context(), "index", indexName)
		s.deleteCatalogEntity(r.Context(), "index_seq_state", indexName)
	}
	for al, targets := range modifiedAliases {
		s.persistAlias(r.Context(), al, targets)
	}
	for _, idx := range tablesToDrop {
		ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
		_ = s.backend.ExecDDL(r.Context(), ddl)
	}
	s.queryCache.InvalidateAll()

	resp := map[string]any{"acknowledged": true}
	if isES8 && hasPartialActionError {
		resp["errors"] = true
		arOut := make([]any, 0, len(actionResults))
		for _, ar := range actionResults {
			actDesc := map[string]any{
				"type":    ar.actType,
				"indices": ar.indices,
			}
			if len(ar.aliases) > 0 {
				actDesc["aliases"] = ar.aliases
			}
			item := map[string]any{
				"status": ar.status,
				"action": actDesc,
				"error":  nil,
			}
			if ar.errType != "" {
				item["error"] = map[string]any{
					"type":   ar.errType,
					"reason": ar.errReason,
				}
			}
			arOut = append(arOut, item)
		}
		resp["action_results"] = arOut
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) handleGetAliasesR62Search(w http.ResponseWriter, r *http.Request) {
	if rawName := r.PathValue("name"); strings.Contains(rawName, "<") {
		r.SetPathValue("name", resolveCommaDateMathTokensR62Search(rawName))
	}
	if rawIdx := r.PathValue("index"); strings.Contains(rawIdx, "<") {
		r.SetPathValue("index", resolveCommaDateMathTokensR62Search(rawIdx))
	}
	if r != nil && r.Method == http.MethodHead {
		s.handleGetAliasesR61CRUD(w, r)
		return
	}
	rec := httptest.NewRecorder()
	s.handleGetAliasesR61CRUD(rec, r)
	for k, vals := range rec.Header() {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	// Augment GET /_alias response with data-stream alias entries (`data_stream/140_data_stream_aliases.yml`)!
	rawAliasPat := strings.TrimSpace(r.PathValue("name"))
	s.mu.RLock()
	hasDS := len(s.dataStreams) > 0
	dsAliasesOut := make(map[string]map[string]any)
	if hasDS {
		for dsName := range s.dataStreams {
			matchedAl := make(map[string]any)
			for al, targets := range s.aliases {
				if rawAliasPat != "" && rawAliasPat != "*" && rawAliasPat != "_all" && !matchMultiWildcardWithExclusions(rawAliasPat, al) {
					continue
				}
				for _, t := range targets {
					if t == dsName {
						matchedAl[al] = s.getAliasMetaMapLocked(al, dsName)
					}
				}
			}
			if len(matchedAl) > 0 {
				dsAliasesOut[dsName] = map[string]any{"aliases": matchedAl}
			}
		}
	}
	s.mu.RUnlock()

	if len(dsAliasesOut) > 0 {
		var payload map[string]any
		if rec.Code == http.StatusOK {
			dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
			dec.UseNumber()
			_ = dec.Decode(&payload)
		}
		if payload == nil {
			payload = make(map[string]any)
		}
		// Remove hidden `.ds-*` / `.fs-*` entries if not explicitly requested
		for k := range payload {
			if strings.HasPrefix(k, ".ds-") || strings.HasPrefix(k, ".fs-") {
				delete(payload, k)
			}
		}
		for dsName, v := range dsAliasesOut {
			payload[dsName] = v
		}
		writeJSONWithRequest(w, r, http.StatusOK, payload)
		return
	}
	if rec.Code == http.StatusOK {
		var payload map[string]any
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		if dec.Decode(&payload) == nil && payload != nil {
			removedHidden := false
			for k := range payload {
				if strings.HasPrefix(k, ".ds-") || strings.HasPrefix(k, ".fs-") {
					delete(payload, k)
					removedHidden = true
				}
			}
			if removedHidden {
				writeJSONWithRequest(w, r, http.StatusOK, payload)
				return
			}
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (s *Server) handleGetIndexAliasesR62Search(w http.ResponseWriter, r *http.Request) {
	if rawIdx := r.PathValue("index"); strings.Contains(rawIdx, "<") {
		r.SetPathValue("index", resolveCommaDateMathTokensR62Search(rawIdx))
	}
	s.handleGetIndexAliasesR61CRUD(w, r)
}

func (s *Server) handleIndexAliasByNameR62Search(w http.ResponseWriter, r *http.Request) {
	if rawIdx := r.PathValue("index"); strings.Contains(rawIdx, "<") {
		r.SetPathValue("index", resolveCommaDateMathTokensR62Search(rawIdx))
	}
	if rawName := r.PathValue("name"); strings.Contains(rawName, "<") {
		r.SetPathValue("name", resolveCommaDateMathTokensR62Search(rawName))
	}
	s.handleIndexAliasByNameR61CRUD(w, r)
}

// ============================================================================
// Wave-1 Search Slice (`scroll/12_slices.yml`), Index Default Sort & `.tasks` Search
// ============================================================================

func normalizeSearchSliceBodyR62Search(bodyBytes []byte) []byte {
	if !bytes.Contains(bodyBytes, []byte(`"slice"`)) {
		return bodyBytes
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil {
		return bodyBytes
	}
	sliceMap, ok := root["slice"].(map[string]any)
	if !ok {
		return bodyBytes
	}
	changed := false
	for _, k := range []string{"id", "max"} {
		if sv, isStr := sliceMap[k].(string); isStr {
			if iv, err := strconv.Atoi(strings.TrimSpace(sv)); err == nil {
				sliceMap[k] = iv
				changed = true
			}
		}
	}
	if !changed {
		return bodyBytes
	}
	out, err := json.Marshal(root)
	if err != nil {
		return bodyBytes
	}
	return out
}

func validateSearchSliceMaxPerScrollR62Search(req *esast.SearchRequest, customSettingsByIdx map[string]map[string]any) (int, string, string) {
	if req == nil || req.Slice == nil {
		return 0, "", ""
	}
	maxLimit := 1024
	for _, cs := range customSettingsByIdx {
		for _, k := range []string{"max_slices_per_scroll", "index.max_slices_per_scroll"} {
			if raw, ok := cs[k]; ok && raw != nil {
				if v, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", raw))); err == nil && v > 0 {
					maxLimit = v
				}
			}
		}
	}
	if req.Slice.Max > maxLimit {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("The number of slices [%d] is too large. It must be less than or equal to [%d]. This limit can be set by changing the [index.max_slices_per_scroll] index level setting.",
				req.Slice.Max, maxLimit)
	}
	return 0, "", ""
}

func bitMix64R62Search(z uint64) uint64 {
	z = (z ^ (z >> 32)) * 0x4cd6944c5cc20b6d
	z = (z ^ (z >> 29)) * 0xfc12c5b19d3259e9
	return z ^ (z >> 32)
}

func murmur3X86_32Seed0R62Search(data []byte) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	var h1 uint32
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data)) // #nosec G115 -- bounded byte slice length
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1) // #nosec G115 -- intentional signed 32-bit hash matching Lucene StringHelper
}

// docMatchesScrollSliceR62Search implements Elasticsearch's deterministic slice partitioning:
//   - When `sliceField == ""` (or `"_id"`) and `s != nil` with `numShards >= sliceMax`:
//     assigns shard `esMurmur3Shard(routingOrID, numShards, routingShards)` to slice `shard % sliceMax`
//     (matching `scroll/12_slices.yml`: `"2", "3", "4"` in slice 0 and `"1"` in slice 1 on 5 shards!).
//   - When `sliceField != ""` (or `sliceMax > numShards`):
//     uses `BitMixer.mix64` (numeric doc values) or `murmur3_x86_32` (`TermsSliceQuery`), partitioning
//     every document into `[0, sliceMax)` with zero overlap and 100% coverage!
func docMatchesScrollSliceR62Search(s *Server, indexName, docID, routing, sliceField string, docSource json.RawMessage, sliceID, sliceMax int) bool {
	if sliceMax <= 1 {
		return sliceID == 0
	}
	sf := strings.TrimSpace(sliceField)
	if s != nil && indexName != "" {
		numShards, _, routingShards := s.getIndexShardAndReplicaCounts(indexName)
		if numShards >= sliceMax {
			effRt := strings.TrimSpace(routing)
			if effRt == "" {
				effRt = docID
			}
			shard := esMurmur3Shard(effRt, numShards, routingShards)
			return shard%sliceMax == sliceID
		}
	}
	if sf != "" && sf != "_id" && len(docSource) > 0 {
		var docMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(docSource))
		dec.UseNumber()
		if dec.Decode(&docMap) == nil && docMap != nil {
			if v, ok := getIngestPath(docMap, sf); ok && v != nil {
				if iv, okI := toInt64(v); okI {
					mixed := int64(bitMix64R62Search(uint64(iv)) & 0x7fffffff) // #nosec G115 -- masked positive 31-bit integer
					return int(mixed)%sliceMax == sliceID
				}
				h := murmur3X86_32Seed0R62Search([]byte(fmt.Sprintf("%v", v)))
				return esFloorMod(int(h), sliceMax) == sliceID
			}
			return false
		}
	}
	h := murmur3X86_32Seed0R62Search([]byte(docID))
	return esFloorMod(int(h), sliceMax) == sliceID
}

// applyIndexDefaultSortR62Search rewrites `sort: ["_doc"]` (and scoreless searches on `logsdb` /
// `index.sort.field` indices) to sort by the configured index segment sort order (`indices.sort/10_basic.yml`,
// `380_sort_segments_on_timestamp.yml`, `logsdb`).
func (s *Server) applyIndexDefaultSortR62Search(indexName string, idxSchema *schema.IndexSchema, req *esast.SearchRequest) *esast.SearchRequest {
	if s == nil || req == nil {
		return req
	}
	hasExplicitDocSort := len(req.Sort) == 1 && req.Sort[0].Entry.Field == "_doc"
	isScorelessNoSort := len(req.Sort) == 0 && (req.Query == nil || req.Query.MatchAll != nil)
	if !hasExplicitDocSort && !isScorelessNoSort {
		return req
	}

	var sortFields []string
	var sortOrders []string
	s.mu.RLock()
	cs := s.indexCustomSettings[indexName]
	if cs != nil {
		for _, fk := range []string{"sort.field", "index.sort.field"} {
			if rawF, ok := cs[fk]; ok && rawF != nil {
				switch tv := rawF.(type) {
				case string:
					for _, p := range strings.Split(tv, ",") {
						if p = strings.TrimSpace(p); p != "" {
							sortFields = append(sortFields, p)
						}
					}
				case []any:
					for _, el := range tv {
						if p := strings.TrimSpace(fmt.Sprintf("%v", el)); p != "" {
							sortFields = append(sortFields, p)
						}
					}
				case []string:
					sortFields = append(sortFields, tv...)
				}
				break
			}
		}
		for _, okKey := range []string{"sort.order", "index.sort.order"} {
			if rawO, ok := cs[okKey]; ok && rawO != nil {
				switch tv := rawO.(type) {
				case string:
					for _, p := range strings.Split(tv, ",") {
						if p = strings.TrimSpace(p); p != "" {
							sortOrders = append(sortOrders, strings.ToLower(p))
						}
					}
				case []any:
					for _, el := range tv {
						if p := strings.TrimSpace(fmt.Sprintf("%v", el)); p != "" {
							sortOrders = append(sortOrders, strings.ToLower(p))
						}
					}
				case []string:
					for _, p := range tv {
						sortOrders = append(sortOrders, strings.ToLower(strings.TrimSpace(p)))
					}
				}
				break
			}
		}
	}
	s.mu.RUnlock()

	if len(sortFields) == 0 && idxSchema != nil {
		if strings.EqualFold(idxSchema.IndexMode, "logsdb") {
			for _, lf := range schema.LogsDBDefaultSortFields() {
				if _, ok := idxSchema.Fields[lf]; ok {
					sortFields = append(sortFields, lf)
					if lf == "@timestamp" {
						sortOrders = append(sortOrders, "desc")
					} else {
						sortOrders = append(sortOrders, "asc")
					}
				}
			}
		} else if hasExplicitDocSort && idxSchema.ES8Mode {
			if tsB, ok := idxSchema.Fields["@timestamp"]; ok && (tsB.ESType == "date" || tsB.ESType == "date_nanos") && !tsB.DocValuesFalse {
				sortFields = []string{"@timestamp"}
				sortOrders = []string{"desc"}
			}
		}
	}
	if len(sortFields) == 0 {
		return req
	}
	// Only apply index.sort automatically when `sort: _doc` is requested (segment order)!
	if !hasExplicitDocSort {
		return req
	}
	cp := *req
	newSorts := make(esast.SortSlice, 0, len(sortFields)+1)
	for i, sf := range sortFields {
		ord := "asc"
		if i < len(sortOrders) && (sortOrders[i] == "asc" || sortOrders[i] == "desc") {
			ord = sortOrders[i]
		}
		newSorts = append(newSorts, esast.SortSpec{
			Entry: esast.SortFieldSpec{
				Field: sf,
				Order: ord,
			},
		})
	}
	newSorts = append(newSorts, esast.SortSpec{
		Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"},
	})
	cp.Sort = newSorts
	return &cp
}

func (s *Server) synthesizeTasksIndexHitsR62Search() []HitRow {
	if s == nil {
		return nil
	}
	reg := s.getTaskRegistry()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	var ids []string
	for id := range reg.tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []HitRow
	for _, id := range ids {
		e := reg.tasks[id]
		if e == nil {
			continue
		}
		e.mu.Lock()
		done := e.completed
		resp := e.response
		act := e.action
		desc := e.description
		numID := e.id
		e.mu.Unlock()
		if !done {
			continue
		}
		docMap := map[string]any{
			"completed": true,
			"task": map[string]any{
				"node":        taskLocalNodeID,
				"id":          numID,
				"type":        "transport",
				"action":      act,
				"description": desc,
			},
		}
		if resp != nil {
			docMap["response"] = resp
		}
		srcBytes, _ := json.Marshal(docMap)
		out = append(out, HitRow{
			Index:     ".tasks",
			ID:        id,
			Score:     1.0,
			Version:   1,
			SeqNo:     int64(len(out)),
			HasSeqNo:  true,
			Source:    srcBytes,
			RawSource: srcBytes,
		})
	}
	return out
}

// ============================================================================
// F6: Data Streams `.ds-<stream>-YYYY.MM.DD-000001` & Failure Store `.fs-*`
// ============================================================================

func formatDataStreamBackingIndexNameR62Search(streamName string, gen int, useDatedFormat bool) string {
	if gen <= 0 {
		gen = 1
	}
	if !useDatedFormat {
		return fmt.Sprintf(".ds-%s-%06d", streamName, gen)
	}
	return fmt.Sprintf(".ds-%s-%s-%06d", streamName, time.Now().UTC().Format("2006.01.02"), gen)
}

func formatFailureStoreBackingIndexNameR62Search(streamName string, gen int) string {
	if gen <= 0 {
		gen = 1
	}
	return fmt.Sprintf(".fs-%s-%s-%06d", streamName, time.Now().UTC().Format("2006.01.02"), gen)
}

func (s *Server) findOwningDataStreamLockedR62Search(backingIndex string) string {
	if backingIndex == "" || len(s.dataStreams) == 0 {
		return ""
	}
	for dsName, ds := range s.dataStreams {
		if rawIndices, ok := ds["indices"].([]any); ok {
			for _, item := range rawIndices {
				if m, okM := item.(map[string]any); okM {
					if m["index_name"] == backingIndex {
						return dsName
					}
				}
			}
		}
		if fsObj, okFS := ds["failure_store"].(map[string]any); okFS {
			if fsIndices, okFI := fsObj["indices"].([]any); okFI {
				for _, item := range fsIndices {
					if m, okM := item.(map[string]any); okM {
						if m["index_name"] == backingIndex {
							return dsName
						}
					}
				}
			}
		}
	}
	return ""
}

func (s *Server) findWinningDataStreamTemplateLockedR62Search(streamName string) (string, esast.IndexTemplateRequest, bool) {
	bestName := ""
	var bestTpl esast.IndexTemplateRequest
	bestPrio := -1
	found := false
	for tplName, tpl := range s.templates {
		if tpl.DataStream == nil {
			continue
		}
		if !matchesTemplateIndexPatterns(streamName, tpl.EffectivePatterns()) {
			continue
		}
		prio := tpl.EffectivePriority()
		if !found || prio > bestPrio || (prio == bestPrio && tplName < bestName) {
			found = true
			bestName = tplName
			bestTpl = tpl
			bestPrio = prio
		}
	}
	return bestName, bestTpl, found
}

func extractTemplateDataStreamFlagsR62Search(dsBlock map[string]any) (hidden, allowCustomRouting, failureStoreEnabled bool) {
	if len(dsBlock) == 0 {
		return false, false, false
	}
	if h, ok := parseOptionalBoolAny(dsBlock["hidden"]); ok {
		hidden = h
	}
	if acr, ok := parseOptionalBoolAny(dsBlock["allow_custom_routing"]); ok {
		allowCustomRouting = acr
	}
	switch fs := dsBlock["failure_store"].(type) {
	case bool:
		failureStoreEnabled = fs
	case map[string]any:
		if en, ok := parseOptionalBoolAny(fs["enabled"]); ok {
			failureStoreEnabled = en
		}
	}
	return hidden, allowCustomRouting, failureStoreEnabled
}

func extractILMPolicyFromSettingsR62Search(st map[string]any) (policy string, preferILM bool, hasPreferILM bool) {
	if len(st) == 0 {
		return "", false, false
	}
	flat := make(map[string]any)
	flattenSettingsInput("", st, flat)
	for _, k := range []string{"lifecycle.name", "index.lifecycle.name", "settings.lifecycle.name", "settings.index.lifecycle.name"} {
		if v, ok := flat[k]; ok && v != nil {
			if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
				policy = s
				break
			}
		}
	}
	for _, k := range []string{"lifecycle.prefer_ilm", "index.lifecycle.prefer_ilm", "settings.lifecycle.prefer_ilm", "settings.index.lifecycle.prefer_ilm"} {
		if v, ok := flat[k]; ok && v != nil {
			if b, okB := parseOptionalBoolAny(v); okB {
				preferILM = b
				hasPreferILM = true
				break
			}
		}
	}
	return policy, preferILM, hasPreferILM
}

func (s *Server) createPhysicalBackingIndexR62Search(
	ctx context.Context,
	streamName, backingName string,
	isFailureStore bool,
	overrideSettings map[string]any,
	overrideMappings *esast.MappingSpec,
	isES8 bool,
) (*schema.IndexSchema, error) {
	s.mu.RLock()
	tplMappings, tplDefPipe, hasTplDefPipe, tplFinPipe, hasFinP, _, tplCustomSettings, _ := s.matchingTemplateFullConfigLocked(streamName)
	s.mu.RUnlock()

	var effMappings *esast.MappingSpec
	if isFailureStore {
		effMappings = &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"@timestamp": {Type: "date"},
			},
		}
	} else {
		tsMapping := &esast.MappingSpec{
			DataStreamTimestamp: map[string]any{"enabled": true},
			Properties: map[string]esast.FieldProperty{
				"@timestamp": {Type: "date"},
			},
		}
		effMappings = schema.MergeMappingSpecs(tsMapping, tplMappings)
		if overrideMappings != nil {
			effMappings = schema.MergeMappingSpecs(effMappings, overrideMappings)
		}
	}

	mergedSettings := make(map[string]any)
	if !isFailureStore {
		for k, v := range tplCustomSettings {
			mergedSettings[k] = v
		}
	}
	for k, v := range overrideSettings {
		mergedSettings[k] = v
	}
	mergedSettings["hidden"] = "true"
	if isFailureStore {
		delete(mergedSettings, "default_pipeline")
		delete(mergedSettings, "index.default_pipeline")
		delete(mergedSettings, "final_pipeline")
		delete(mergedSettings, "index.final_pipeline")
		mergedSettings["failure_store.version"] = "1"
	}

	compiled := schema.CompileIndexSchema(s.dorisDB, backingName, effMappings)
	compiled.ES8Mode = isES8
	_ = parseAndApplyIndexMappingSettingsRound59(mergedSettings, compiled)
	if !isFailureStore {
		if mode, routingPath, startTime, endTime, tsErr := schema.ExtractTSDBSettings(mergedSettings); tsErr == nil && mode == "time_series" {
			compiled.IndexMode = "time_series"
			compiled.RoutingPath = routingPath
			compiled.TimeSeriesStartTime = startTime
			compiled.TimeSeriesEndTime = endTime
			compiled.SyntheticSource = true
			if compiled.TimeSeriesStartTime == "" {
				compiled.TimeSeriesStartTime = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
			}
			if compiled.TimeSeriesEndTime == "" {
				compiled.TimeSeriesEndTime = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
			}
		}
	}
	schema.ApplyIndexModeDefaults(compiled)

	ddl := schema.GenerateCreateTableDDL(compiled)
	if err := s.backend.ExecDDL(ctx, ddl); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.indices[backingName] = compiled
	if !isFailureStore {
		if hasTplDefPipe && tplDefPipe != "" {
			s.indexDefaultPipelines[backingName] = tplDefPipe
		}
		if hasFinP && tplFinPipe != "" {
			s.indexFinalPipelines[backingName] = tplFinPipe
		}
		if p, okP := extractDefaultPipelineFromSettings(overrideSettings); okP && p != "" {
			s.indexDefaultPipelines[backingName] = p
		}
	}
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	if s.indexCustomSettings[backingName] == nil {
		s.indexCustomSettings[backingName] = make(map[string]any)
	}
	for k, v := range mergedSettings {
		if k == "default_pipeline" || k == "final_pipeline" || v == nil {
			continue
		}
		if isFailureStore && (strings.HasSuffix(k, "default_pipeline") || strings.HasSuffix(k, "final_pipeline")) {
			continue
		}
		s.indexCustomSettings[backingName][strings.TrimPrefix(k, "index.")] = normalizeCustomSettingValue(v)
	}
	s.ensureIndexCreationDateLocked(backingName)
	if s.indexStats == nil {
		s.indexStats = make(map[string]*indexLiveStats)
	}
	st := &indexLiveStats{}
	st.refreshTotal.Store(1)
	st.flushTotal.Store(0)
	s.indexStats[backingName] = st
	s.mu.Unlock()

	s.persistIndex(ctx, backingName, compiled)
	return compiled, nil
}

func validateDataStreamNameR62Search(name string, allowDotHidden bool) (int, string, string) {
	if name == "" {
		return http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;"
	}
	if strings.Contains(name, "#") {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("data_stream [%s] must not contain '#'", name)
	}
	if strings.HasPrefix(name, ".ds-") || strings.HasPrefix(name, ".fs-") {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("data_stream [%s] must not start with '.ds-' or '.fs-'", name)
	}
	if strings.HasPrefix(name, ".") {
		if !allowDotHidden {
			return http.StatusBadRequest, "invalid_index_name_exception", fmt.Sprintf("Invalid data stream name [%s], must not start with '.'", name)
		}
		rest := strings.TrimPrefix(name, ".")
		if reason, ok := validateESIndexName(rest); !ok {
			return http.StatusBadRequest, "invalid_index_name_exception", strings.Replace(reason, rest, name, 1)
		}
		return 0, "", ""
	}
	if reason, ok := validateESIndexName(name); !ok {
		return http.StatusBadRequest, "invalid_index_name_exception", reason
	}
	return 0, "", ""
}

func formatTSDBTemporalInstantMillisR62Search(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return s
}

func (s *Server) createOrAutoCreateDataStreamR62Search(
	ctx context.Context,
	streamName string,
	explicitLifecycle map[string]any,
	explicitFailureStore *bool,
	isES8 bool,
	initFailureStoreAtGen1 bool,
) (map[string]any, int, string, string) {
	s.mu.RLock()
	if existing, ok := s.dataStreams[streamName]; ok {
		cp := deepCloneDocMap(existing)
		s.mu.RUnlock()
		return cp, 0, "", ""
	}
	_, idxExists := s.indices[streamName]
	aliasExists := len(s.aliases[streamName]) > 0
	tplName, winTpl, hasDS := s.findWinningDataStreamTemplateLockedR62Search(streamName)
	tplLC := s.extractMatchingTemplateLifecycleLocked(streamName)
	_, _, _, _, _, _, tplCustomSettings, _ := s.matchingTemplateFullConfigLocked(streamName)
	s.mu.RUnlock()

	if idxExists || aliasExists {
		return nil, http.StatusBadRequest, "resource_already_exists_exception", "index or alias [" + streamName + "] already exists"
	}
	if strings.Contains(streamName, "#") || strings.HasPrefix(streamName, ".ds-") || strings.HasPrefix(streamName, ".fs-") {
		if st, et, er := validateDataStreamNameR62Search(streamName, true); st != 0 {
			return nil, st, et, er
		}
	}
	if !hasDS && s.hasExplicitTargetESVersion() {
		return nil, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("no matching index template found for data stream [%s]", streamName)
	}
	hidden, allowCustomRouting, fsEnabled := extractTemplateDataStreamFlagsR62Search(winTpl.DataStream)
	if st, et, er := validateDataStreamNameR62Search(streamName, hidden); st != 0 {
		return nil, st, et, er
	}
	if explicitFailureStore != nil {
		fsEnabled = *explicitFailureStore
	}

	backingName := formatDataStreamBackingIndexNameR62Search(streamName, 1, s.hasExplicitTargetESVersion())
	backingSchema, err := s.createPhysicalBackingIndexR62Search(ctx, streamName, backingName, false, nil, nil, isES8)
	if err != nil {
		return nil, http.StatusInternalServerError, "doris_ddl_exception", err.Error()
	}

	ilmPol, preferILM, hasPreferILM := extractILMPolicyFromSettingsR62Search(tplCustomSettings)
	if !hasPreferILM {
		preferILM = true
	}
	var effLC map[string]any
	if explicitLifecycle != nil {
		effLC = explicitLifecycle
	} else if len(tplLC) > 0 {
		effLC = tplLC
	}
	dslEnabled := true
	if effLC != nil {
		if en, okB := parseOptionalBoolAny(effLC["enabled"]); okB {
			dslEnabled = en
		}
	}

	managedBy := "Unmanaged"
	nextManagedBy := "Unmanaged"
	if ilmPol != "" && (preferILM || !dslEnabled) {
		managedBy = "Index Lifecycle Management"
		nextManagedBy = "Index Lifecycle Management"
	} else if effLC != nil && dslEnabled {
		managedBy = "Data stream lifecycle"
		nextManagedBy = "Data stream lifecycle"
	}

	idxEntry := map[string]any{
		"index_name": backingName,
		"index_uuid": indexUUIDForNameRound61(backingName),
		"prefer_ilm": preferILM,
		"managed_by": managedBy,
	}
	if ilmPol != "" {
		idxEntry["ilm_policy"] = ilmPol
	}

	fsIndices := []any{}
	if fsEnabled && initFailureStoreAtGen1 {
		fsBacking := formatFailureStoreBackingIndexNameR62Search(streamName, 1)
		if _, fsErr := s.createPhysicalBackingIndexR62Search(ctx, streamName, fsBacking, true, nil, nil, isES8); fsErr == nil {
			fsIndices = append(fsIndices, map[string]any{
				"index_name": fsBacking,
				"index_uuid": indexUUIDForNameRound61(fsBacking),
				"managed_by": "Data stream lifecycle",
			})
		}
	}

	dsObj := map[string]any{
		"name":                       streamName,
		"timestamp_field":            map[string]any{"name": "@timestamp"},
		"indices":                    []any{idxEntry},
		"generation":                 1,
		"status":                     "GREEN",
		"template":                   tplName,
		"hidden":                     hidden,
		"system":                     strings.HasPrefix(streamName, "."),
		"allow_custom_routing":       allowCustomRouting,
		"replicated":                 false,
		"prefer_ilm":                 preferILM,
		"next_generation_managed_by": nextManagedBy,
		"failure_store": map[string]any{
			"enabled": fsEnabled,
			"indices": fsIndices,
		},
	}
	if ilmPol != "" {
		dsObj["ilm_policy"] = ilmPol
	}
	if winTpl.Meta != nil {
		dsObj["_meta"] = deepCloneDocMap(winTpl.Meta)
	}
	if effLC != nil {
		if dslEnabled && effLC["rollover"] == nil {
			lcCopy := deepCloneDocMap(effLC)
			lcCopy["rollover"] = map[string]any{"max_age": "7d", "max_primary_shard_size": "50gb"}
			effLC = lcCopy
		}
		dsObj["lifecycle"] = effLC
	}
	if backingSchema != nil && backingSchema.IndexMode == "time_series" {
		dsObj["time_series"] = map[string]any{
			"temporal_ranges": []any{
				map[string]any{
					"start": formatTSDBTemporalInstantMillisR62Search(backingSchema.TimeSeriesStartTime),
					"end":   formatTSDBTemporalInstantMillisR62Search(backingSchema.TimeSeriesEndTime),
				},
			},
		}
	}

	s.mu.Lock()
	if s.dataStreams == nil {
		s.dataStreams = make(map[string]map[string]any)
	}
	s.dataStreams[streamName] = dsObj
	s.mu.Unlock()
	s.persistDataStream(ctx, streamName, dsObj)
	return deepCloneDocMap(dsObj), 0, "", ""
}

func (s *Server) enrichDataStreamResponseMapLockedR62Search(ds map[string]any) map[string]any {
	cp := deepCloneDocMap(ds)
	streamName, _ := cp["name"].(string)
	if _, hasFS := cp["failure_store"]; !hasFS {
		cp["failure_store"] = map[string]any{
			"enabled": false,
			"indices": []any{},
		}
	} else if fsMap, okFS := cp["failure_store"].(map[string]any); okFS {
		delete(fsMap, "__lazy_rollover")
		if fsMap["indices"] == nil {
			fsMap["indices"] = []any{}
		}
	}
	if _, hasACR := cp["allow_custom_routing"]; !hasACR {
		cp["allow_custom_routing"] = false
	}
	if _, hasTpl := cp["template"]; !hasTpl && streamName != "" {
		if tplName, winTpl, ok := s.findWinningDataStreamTemplateLockedR62Search(streamName); ok {
			cp["template"] = tplName
			if winTpl.Meta != nil && cp["_meta"] == nil {
				cp["_meta"] = deepCloneDocMap(winTpl.Meta)
			}
		}
	}
	// Refresh temporal_ranges from backing TSDB schemas if present
	if rawIndices, okI := cp["indices"].([]any); okI {
		var ranges []any
		for _, item := range rawIndices {
			if m, okM := item.(map[string]any); okM {
				bName, _ := m["index_name"].(string)
				if sc := s.indices[bName]; sc != nil && sc.IndexMode == "time_series" && sc.TimeSeriesStartTime != "" {
					ranges = append(ranges, map[string]any{
						"start": formatTSDBTemporalInstantMillisR62Search(sc.TimeSeriesStartTime),
						"end":   formatTSDBTemporalInstantMillisR62Search(sc.TimeSeriesEndTime),
					})
				}
			}
		}
		if len(ranges) > 0 {
			cp["time_series"] = map[string]any{"temporal_ranges": ranges}
		}
	}
	return cp
}

// validateDataStreamWriteTimestampR62Search enforces `@timestamp` presence, single-value scalar,
// and valid date format on writes targeting a data stream (`10_basic.yml`, `110_index_and_bulk_api.yml`, `150_tsdb.yml`).
func validateDataStreamWriteTimestampR62Search(rawDoc []byte, idxSchema *schema.IndexSchema) (int64, int, string, string, map[string]any) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return 0, http.StatusBadRequest, "mapper_parsing_exception", "failed to parse document body", nil
	}
	expanded := expandDottedDocForPreviewR62Search(doc)
	rawTS, exists := expanded["@timestamp"]
	if !exists || rawTS == nil {
		return 0, http.StatusBadRequest, "mapper_parsing_exception",
			"Error extracting data stream timestamp field: Failed to parse object: expecting token of type [VALUE_NUMBER, VALUE_STRING] but found [NULL]",
			map[string]any{
				"type":   "illegal_argument_exception",
				"reason": "data stream timestamp field [@timestamp] is missing",
			}
	}
	if arr, isArr := rawTS.([]any); isArr {
		if len(arr) == 0 {
			return 0, http.StatusBadRequest, "mapper_parsing_exception",
				"Error extracting data stream timestamp field: Failed to parse object: expecting token of type [VALUE_NUMBER, VALUE_STRING] but found [NULL]",
				map[string]any{
					"type":   "illegal_argument_exception",
					"reason": "data stream timestamp field [@timestamp] is missing",
				}
		}
		if len(arr) > 1 {
			return 0, http.StatusBadRequest, "mapper_parsing_exception",
				"Error extracting data stream timestamp field: data stream timestamp field [@timestamp] encountered multiple values",
				map[string]any{
					"type":   "illegal_argument_exception",
					"reason": "data stream timestamp field [@timestamp] encountered multiple values",
				}
		}
		rawTS = arr[0]
	}
	if _, isObj := rawTS.(map[string]any); isObj {
		return 0, http.StatusBadRequest, "mapper_parsing_exception",
			"Error extracting data stream timestamp field: Failed to parse object: expecting token of type [VALUE_NUMBER, VALUE_STRING] but found [START_OBJECT]",
			nil
	}
	var fmtSpec string
	if idxSchema != nil {
		if b, ok := idxSchema.Fields["@timestamp"]; ok {
			fmtSpec = b.Format
		}
	}
	valStr := strings.TrimSpace(fmt.Sprintf("%v", rawTS))
	ms, okTS := schema.ParseESDateWithFormatToEpochMillis(valStr, fmtSpec, time.Now().UTC())
	if !okTS {
		if fmtSpec == "" {
			fmtSpec = "strict_date_optional_time_nanos||strict_date_optional_time||epoch_millis"
		}
		return 0, http.StatusBadRequest, "mapper_parsing_exception",
			fmt.Sprintf("Error extracting data stream timestamp field: failed to parse date field [%s] with format [%s]", valStr, fmtSpec),
			nil
	}
	return ms, 0, "", "", nil
}

// validateDirectBackingIndexWriteR62Search blocks direct `op_type=create` or non-OCC `op_type=index`
// writes targeting `.ds-*` backing indices (`data_stream/10_basic.yml:917-925`).
func (s *Server) validateDirectBackingIndexWriteR62Search(rawTarget string, isCreate bool, hasIfSeqNoAndTerm bool) (int, string, string) {
	trimmed := strings.TrimSpace(rawTarget)
	if !strings.HasPrefix(trimmed, ".ds-") {
		return 0, "", ""
	}
	s.mu.RLock()
	owner := s.findOwningDataStreamLockedR62Search(trimmed)
	s.mu.RUnlock()
	if owner == "" {
		return 0, "", ""
	}
	if isCreate {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("index request with op_type=create targeting backing indices is disallowed, target corresponding data stream [%s] instead", owner)
	}
	if !hasIfSeqNoAndTerm {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("index request with op_type=index and no if_primary_term and if_seq_no set targeting backing indices is disallowed, target corresponding data stream [%s] instead", owner)
	}
	return 0, "", ""
}

// validateRequireDataStreamParamR62Search enforces `?require_data_stream=true` (and bulk metadata `require_data_stream`)
// per `data_stream/190_require_data_stream.yml`.
func (s *Server) validateRequireDataStreamParamR62Search(ctx context.Context, rawTarget string, isES8 bool) (bool, int, string, string) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return false, 0, "", ""
	}
	s.mu.RLock()
	_, isDS := s.dataStreams[target]
	_, isIdx := s.indices[target]
	aliasTargets := append([]string(nil), s.aliases[target]...)
	_, _, hasDSTpl := s.findWinningDataStreamTemplateLockedR62Search(target)
	s.mu.RUnlock()

	if isDS {
		return true, 0, "", ""
	}
	if len(aliasTargets) > 0 {
		s.mu.RLock()
		allDS := true
		for _, at := range aliasTargets {
			if s.dataStreams[at] == nil {
				allDS = false
				break
			}
		}
		s.mu.RUnlock()
		if allDS {
			return true, 0, "", ""
		}
		return false, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("[%s] is not a data stream", target)
	}
	if isIdx {
		return false, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("[%s] is not a data stream", target)
	}
	if !hasDSTpl {
		return false, http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such index [%s] and the index creation request requires a data stream, but no matching index template with data stream template was found for it", target)
	}
	if _, st, et, er := s.createOrAutoCreateDataStreamR62Search(ctx, target, nil, nil, isES8, false); st != 0 {
		return false, st, et, er
	}
	return true, 0, "", ""
}

func (s *Server) recordMaxDataStreamTimestampR62Search(streamName string, tsMillis int64) {
	if s == nil || streamName == "" || tsMillis <= 0 {
		return
	}
	s.mu.Lock()
	ds := s.dataStreams[streamName]
	if ds == nil {
		s.mu.Unlock()
		return
	}
	prev, _ := toInt64(ds["__max_timestamp_ms"])
	var snap map[string]any
	if tsMillis > prev {
		ds["__max_timestamp_ms"] = tsMillis
		snap = deepCloneDocMap(ds)
	}
	s.mu.Unlock()
	if snap != nil {
		s.persistDataStream(context.Background(), streamName, snap)
	}
}

// isDataStreamFailureStoreEnabledR62Search checks whether `target` is an existing data stream with
// `failure_store.enabled: true` OR a not-yet-created stream matching a data-stream template with `failure_store` enabled.
func (s *Server) isDataStreamFailureStoreEnabledR62Search(target string) (enabled bool, existed bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ds := s.dataStreams[target]; ds != nil {
		if fsObj, ok := ds["failure_store"].(map[string]any); ok {
			en, _ := parseOptionalBoolAny(fsObj["enabled"])
			return en, true
		}
		return false, true
	}
	if s.indices[target] != nil || len(s.aliases[target]) > 0 {
		return false, true
	}
	if _, winTpl, hasDS := s.findWinningDataStreamTemplateLockedR62Search(target); hasDS {
		_, _, fsEn := extractTemplateDataStreamFlagsR62Search(winTpl.DataStream)
		return fsEn, false
	}
	return false, false
}

// recordFailureStoreDocumentR62Search redirects a failed ingest or mapper/shard document into
// `.fs-<stream>-YYYY.MM.DD-00000X` when `failure_store` is enabled (`10_basic.yml`, `190_failure_store_redirection.yml`).
func (s *Server) recordFailureStoreDocumentR62Search(
	ctx context.Context,
	streamName, explicitDocID string,
	origDocBytes []byte,
	errType, errMessage string,
	executedPipelines []string,
	syncRefresh bool,
	isES8 bool,
	isIngestPreAutoCreate bool,
) (fsBackingIndex, fsDocID string, fsSeqNo int64, ok bool) {
	fsEnabled, streamExisted := s.isDataStreamFailureStoreEnabledR62Search(streamName)
	if !fsEnabled {
		return "", "", 0, false
	}
	if !streamExisted {
		if _, st, _, _ := s.createOrAutoCreateDataStreamR62Search(ctx, streamName, nil, nil, isES8, isIngestPreAutoCreate); st != 0 {
			return "", "", 0, false
		}
	}

	s.mu.Lock()
	ds := s.dataStreams[streamName]
	if ds == nil {
		s.mu.Unlock()
		return "", "", 0, false
	}
	fsObj, _ := ds["failure_store"].(map[string]any)
	if fsObj == nil {
		fsObj = map[string]any{"enabled": true, "indices": []any{}}
		ds["failure_store"] = fsObj
	}
	fsIndices, _ := fsObj["indices"].([]any)
	lazyRollover, _ := fsObj["__lazy_rollover"].(bool)
	needNewFS := len(fsIndices) == 0 || lazyRollover
	var targetFSName string
	var nextGen int
	if !needNewFS {
		if lastMap, okM := fsIndices[len(fsIndices)-1].(map[string]any); okM {
			targetFSName, _ = lastMap["index_name"].(string)
		}
		if targetFSName == "" {
			needNewFS = true
		}
	}
	if needNewFS {
		curGen, _ := toInt64(ds["generation"])
		if isIngestPreAutoCreate && len(fsIndices) == 0 && curGen <= 1 {
			nextGen = 1
		} else {
			nextGen = int(curGen) + 1
			if nextGen < 1 {
				nextGen = 1
			}
		}
		targetFSName = formatFailureStoreBackingIndexNameR62Search(streamName, nextGen)
		ds["generation"] = nextGen
		delete(fsObj, "__lazy_rollover")
		fsIndices = append(fsIndices, map[string]any{
			"index_name": targetFSName,
			"index_uuid": indexUUIDForNameRound61(targetFSName),
			"managed_by": "Data stream lifecycle",
		})
		fsObj["indices"] = fsIndices
	}
	dsSnap := deepCloneDocMap(ds)
	s.mu.Unlock()

	if needNewFS {
		if _, cErr := s.createPhysicalBackingIndexR62Search(ctx, streamName, targetFSName, true, nil, nil, isES8); cErr != nil {
			return "", "", 0, false
		}
		s.persistDataStream(ctx, streamName, dsSnap)
	}

	var srcVal any
	dec := json.NewDecoder(bytes.NewReader(origDocBytes))
	dec.UseNumber()
	if err := dec.Decode(&srcVal); err != nil || srcVal == nil {
		srcVal = string(origDocBytes)
	}
	docBlock := map[string]any{
		"index":  streamName,
		"source": srcVal,
	}
	if explicitDocID != "" {
		docBlock["id"] = explicitDocID
	}
	cleanMsg := trimSchemaErrorPrefixR62Search(fmt.Errorf("%s", errMessage))
	javaExc := "org.elasticsearch.index.mapper.DocumentParsingException"
	if errType == "fail_processor_exception" || strings.Contains(errType, "processor") {
		javaExc = "org.elasticsearch.ingest.common.FailProcessorException"
	} else if errType == "mapper_parsing_exception" {
		errType = "document_parsing_exception"
	}
	errBlock := map[string]any{
		"type":        errType,
		"message":     cleanMsg,
		"stack_trace": fmt.Sprintf("%s: %s", javaExc, cleanMsg),
	}
	if len(executedPipelines) > 0 {
		failPipe := executedPipelines[len(executedPipelines)-1]
		errBlock["pipeline"] = failPipe
		errBlock["pipeline_trace"] = executedPipelines
		s.mu.RLock()
		pipeDef := s.pipelines[failPipe]
		s.mu.RUnlock()
		procType, procTag := extractFailingProcessorTypeAndTagR62Search(pipeDef, errType)
		if procType != "" {
			errBlock["processor_type"] = procType
		}
		if procTag != "" {
			errBlock["processor_tag"] = procTag
		}
	}

	failDoc := map[string]any{
		"@timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"document":   docBlock,
		"error":      errBlock,
	}
	failBytes, mErr := json.Marshal(failDoc)
	if mErr != nil {
		return "", "", 0, false
	}
	fsSchema := s.getOrCompileReadOnlySchema(ctx, targetFSName)
	if fsSchema == nil {
		return "", "", 0, false
	}
	genID := esast.NextAutoID()
	shredded, sErr := schema.ShredDocument(fsSchema, genID, 1, false, failBytes)
	if sErr != nil {
		return "", "", 0, false
	}
	if lErr := s.streamLoad(ctx, fsSchema.DorisTable, append(shredded, '\n'), syncRefresh); lErr != nil {
		return "", "", 0, false
	}
	seqNo := s.allocIndexSeqNo(ctx, targetFSName)
	s.recordDocWriteMetaRound60(targetFSName, genID, 1, seqNo)
	if st := s.getOrCreateIndexLiveStats(targetFSName); st != nil {
		st.indexTotal.Add(1)
	}
	return targetFSName, genID, seqNo, true
}

func extractFailingProcessorTypeAndTagR62Search(pipe map[string]any, errType string) (string, string) {
	if pipe == nil {
		if errType == "fail_processor_exception" {
			return "fail", ""
		}
		return "", ""
	}
	procs, _ := pipe["processors"].([]any)
	for _, p := range procs {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		pType, pTag, _, _, _, _ := extractIngestProcessorSpecRound60(pm)
		if pType == "pipeline" {
			continue
		}
		if errType == "fail_processor_exception" && pType != "fail" {
			continue
		}
		return pType, pTag
	}
	if errType == "fail_processor_exception" {
		return "fail", ""
	}
	return "", ""
}

func (s *Server) handleDataStreamR62Search(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	name := resolveCommaDateMathTokensR62Search(strings.TrimSpace(r.PathValue("name")))
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		var explicitLifecycle map[string]any
		var explicitFS *bool
		if r.Body != nil && r.ContentLength != 0 {
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				var reqMap map[string]any
				if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
					writeESError(w, http.StatusBadRequest, "x_content_parse_exception", err.Error())
					return
				}
				if lcRaw, okLC := reqMap["lifecycle"].(map[string]any); okLC {
					lcNorm, err := normalizeAndValidateDataStreamLifecycle(lcRaw)
					if err != nil {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
						return
					}
					explicitLifecycle = lcNorm
				}
				if fsRaw, hasFS := reqMap["failure_store"]; hasFS && fsRaw != nil {
					if fsMap, okM := fsRaw.(map[string]any); okM {
						if en, okB := parseOptionalBoolAny(fsMap["enabled"]); okB {
							explicitFS = &en
						}
					} else if en, okB := parseOptionalBoolAny(fsRaw); okB {
						explicitFS = &en
					}
				}
			}
		}
		s.mu.RLock()
		_, dsExists := s.dataStreams[name]
		s.mu.RUnlock()
		if dsExists {
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "data_stream ["+name+"] already exists")
			return
		}
		if _, st, et, er := s.createOrAutoCreateDataStreamR62Search(r.Context(), name, explicitLifecycle, explicitFS, s.isES8Mode(r), false); st != 0 {
			writeESError(w, st, et, er)
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		_, _, ewHidden, _, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
		if ewErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
			return
		}
		// DELETE /_data_stream defaults expand_wildcards to open,hidden when explicit dot prefix or expand_wildcards includes hidden
		isWildcardOrAll := strings.ContainsAny(name, "*?") || name == "_all"
		s.mu.Lock()
		var matched []string
		var backingIndices []string
		seenBacking := make(map[string]bool)
		addBacking := func(idx string) {
			if idx != "" && !seenBacking[idx] {
				seenBacking[idx] = true
				backingIndices = append(backingIndices, idx)
			}
		}
		var missingConcrete string
		for _, tok := range strings.Split(name, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "*?") || tok == "_all" {
				continue
			}
			if _, ok := s.dataStreams[tok]; !ok && missingConcrete == "" {
				missingConcrete = tok
			}
		}
		if missingConcrete != "" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_streams ["+missingConcrete+"] missing")
			return
		}
		for k, ds := range s.dataStreams {
			isHid, _ := ds["hidden"].(bool)
			if isHid && !ewHidden && isWildcardOrAll && !strings.HasPrefix(name, ".") && k != name {
				// Hidden data streams excluded from wildcard delete unless expand_wildcards=open,hidden or pattern starts with '.'
				if !strings.HasPrefix(strings.TrimSpace(name), ".") {
					continue
				}
			}
			if matchMultiWildcardWithExclusions(name, k) {
				matched = append(matched, k)
				addBacking(k)
				if rawIndices, ok := ds["indices"].([]any); ok {
					for _, item := range rawIndices {
						if m, okM := item.(map[string]any); okM {
							if idxName, okS := m["index_name"].(string); okS {
								addBacking(idxName)
							}
						}
					}
				}
				if fsObj, okFS := ds["failure_store"].(map[string]any); okFS {
					if fsIndices, okFI := fsObj["indices"].([]any); okFI {
						for _, item := range fsIndices {
							if m, okM := item.(map[string]any); okM {
								if idxName, okS := m["index_name"].(string); okS {
									addBacking(idxName)
								}
							}
						}
					}
				}
			}
		}
		if len(matched) == 0 {
			s.mu.Unlock()
			if isWildcardOrAll || isTruthyBoolQueryParam(r, "ignore_unavailable") || isTruthyBoolQueryParam(r, "allow_no_indices") {
				writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_streams ["+name+"] missing")
			return
		}
		var tablesToDrop []*schema.IndexSchema
		modifiedAliases := make(map[string][]string)
		for _, k := range matched {
			delete(s.dataStreams, k)
			for alias := range s.aliases {
				s.removeAliasTargetLocked(alias, k)
				modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
			}
		}
		for _, idxName := range backingIndices {
			if idx, ok := s.indices[idxName]; ok {
				tablesToDrop = append(tablesToDrop, idx)
			}
			delete(s.indices, idxName)
			delete(s.docRouting, idxName)
			delete(s.docVersions, idxName)
			delete(s.indexDefaultPipelines, idxName)
			delete(s.indexFinalPipelines, idxName)
			delete(s.closedIndices, idxName)
			delete(s.indexCustomSettings, idxName)
			delete(s.indexNextSeqNo, idxName)
			delete(s.docSeqNos, idxName)
			delete(s.docDeleted, idxName)
			delete(s.docExtTombstones, idxName)
			delete(s.unrefreshedDocs, idxName)
			delete(s.indexStats, idxName)
			for alias := range s.aliases {
				s.removeAliasTargetLocked(alias, idxName)
				modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
			}
		}
		s.mu.Unlock()

		for _, k := range matched {
			s.deleteDataStreamCatalog(r.Context(), k)
		}
		for _, idxName := range backingIndices {
			s.deleteCatalogEntity(r.Context(), "index", idxName)
		}
		for alias, aliasTargets := range modifiedAliases {
			s.persistAlias(r.Context(), alias, aliasTargets)
		}
		for _, idx := range tablesToDrop {
			ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
			_ = s.backend.ExecDDL(r.Context(), ddl)
		}
		s.queryCache.InvalidateAll()
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodHead, http.MethodGet:
		_, _, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
		if ewErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
			return
		}
		includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")
		s.mu.RLock()
		var missingConcrete string
		concreteRequested := make(map[string]bool)
		if name != "" && name != "*" && name != "_all" {
			for _, part := range strings.Split(name, ",") {
				part = strings.TrimSpace(part)
				if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
					continue
				}
				concreteRequested[part] = true
				if _, exists := s.dataStreams[part]; !exists && missingConcrete == "" {
					missingConcrete = part
				}
			}
		}
		var list []any
		var names []string
		if !ewNone || len(concreteRequested) > 0 {
			for k, ds := range s.dataStreams {
				if ewNone && !concreteRequested[k] {
					continue
				}
				isHid, _ := ds["hidden"].(bool)
				if isHid && !ewHidden && !concreteRequested[k] {
					hasDotPat := false
					for _, p := range strings.Split(name, ",") {
						if strings.HasPrefix(strings.TrimSpace(p), ".") {
							hasDotPat = true
							break
						}
					}
					if !hasDotPat {
						continue
					}
				}
				if name == "" || matchMultiWildcardWithExclusions(name, k) {
					names = append(names, k)
				}
			}
		}
		sort.Strings(names)
		for _, k := range names {
			item := s.enrichDataStreamResponseMapLockedR62Search(s.dataStreams[k])
			delete(item, "__max_timestamp_ms")
			if includeDefaults && item["lifecycle"] == nil {
				item["lifecycle"] = map[string]any{"enabled": true}
			}
			list = append(list, item)
		}
		s.mu.RUnlock()

		if r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			if missingConcrete != "" || (name != "" && len(list) == 0) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if missingConcrete != "" {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "data_streams ["+missingConcrete+"] missing")
			return
		}
		if name != "" && !strings.ContainsAny(name, "*?") && !strings.HasPrefix(name, "-") && name != "_all" && len(list) == 0 {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "data_streams ["+name+"] missing")
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"data_streams": list})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) handleModifyDataStreamR62Search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var payload struct {
		Actions []map[string]map[string]any `json:"actions"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if len(payload.Actions) == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: actions are missing;")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())

	// Validate all actions up front so multi-action modify is atomic (`170_modify_data_stream.yml`).
	s.mu.Lock()
	for _, action := range payload.Actions {
		if len(action) != 1 {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "parsing_exception", "each action must specify exactly one operation")
			return
		}
		for op, spec := range action {
			dsName, _ := spec["data_stream"].(string)
			dsName = strings.TrimSpace(dsName)
			switch op {
			case "add_backing_index", "remove_backing_index":
				idxName, _ := spec["index"].(string)
				idxName = strings.TrimSpace(idxName)
				if dsName == "" || idxName == "" {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
						fmt.Sprintf("Validation Failed: 1: data_stream and index are required for [%s];", op))
					return
				}
				if op == "add_backing_index" {
					if _, exists := s.indices[idxName]; !exists {
						s.mu.Unlock()
						writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+idxName+"]")
						return
					}
					if owner := s.findOwningDataStreamLockedR62Search(idxName); owner != "" {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("index [%s] is already part of data stream [%s]", idxName, owner))
						return
					}
				} else {
					ds := s.dataStreams[dsName]
					if ds == nil {
						s.mu.Unlock()
						writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_stream ["+dsName+"] missing")
						return
					}
					rawIndices, _ := ds["indices"].([]any)
					if len(rawIndices) > 0 {
						if lastM, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM && lastM["index_name"] == idxName {
							s.mu.Unlock()
							writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
								fmt.Sprintf("cannot remove write index [%s] from data stream [%s]", idxName, dsName))
							return
						}
					}
				}
			case "data_stream_options":
				if dsName == "" {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: data_stream is required;")
					return
				}
				if s.dataStreams[dsName] == nil {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_stream ["+dsName+"] missing")
					return
				}
				for sk, sv := range spec {
					switch sk {
					case "data_stream":
					case "failure_store":
						if fsMap, okM := sv.(map[string]any); okM {
							for fk := range fsMap {
								if fk != "enabled" {
									s.mu.Unlock()
									writeESError(w, http.StatusBadRequest, "x_content_parse_exception", fmt.Sprintf("unknown field [%s] in failure_store", fk))
									return
								}
							}
							if _, okB := parseOptionalBoolAny(fsMap["enabled"]); !okB {
								s.mu.Unlock()
								writeESError(w, http.StatusBadRequest, "x_content_parse_exception", "failure_store.enabled must be a boolean")
								return
							}
						} else if _, okB := parseOptionalBoolAny(sv); !okB {
							s.mu.Unlock()
							writeESError(w, http.StatusBadRequest, "x_content_parse_exception", "failure_store must be a boolean or object")
							return
						}
					default:
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "x_content_parse_exception", fmt.Sprintf("[data_stream_options] unknown field [%s]", sk))
						return
					}
				}
			default:
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "x_content_parse_exception", fmt.Sprintf("unknown modify data stream action [%s]", op))
				return
			}
		}
	}

	modifiedDS := make(map[string]map[string]any)
	modifiedIdxHidden := make(map[string]bool)
	for _, action := range payload.Actions {
		for op, spec := range action {
			dsName := strings.TrimSpace(fmt.Sprintf("%v", spec["data_stream"]))
			switch op {
			case "add_backing_index":
				idxName := strings.TrimSpace(fmt.Sprintf("%v", spec["index"]))
				ds := s.dataStreams[dsName]
				if ds == nil {
					ds = map[string]any{
						"name":            dsName,
						"timestamp_field": map[string]any{"name": "@timestamp"},
						"indices":         []any{},
						"generation":      1,
						"status":          "GREEN",
						"hidden":          false,
						"system":          false,
						"replicated":      false,
						"failure_store":   map[string]any{"enabled": false, "indices": []any{}},
					}
					s.dataStreams[dsName] = ds
				}
				curIndices, _ := ds["indices"].([]any)
				// Insert before current write index if stream already has a `.ds-*` write index, or append if new!
				newEntry := map[string]any{
					"index_name": idxName,
					"index_uuid": indexUUIDForNameRound61(idxName),
					"prefer_ilm": true,
					"managed_by": "Unmanaged",
				}
				if len(curIndices) > 0 {
					updated := make([]any, 0, len(curIndices)+1)
					updated = append(updated, curIndices[:len(curIndices)-1]...)
					updated = append(updated, newEntry, curIndices[len(curIndices)-1])
					ds["indices"] = updated
				} else {
					ds["indices"] = []any{newEntry}
				}
				if s.indexCustomSettings == nil {
					s.indexCustomSettings = make(map[string]map[string]any)
				}
				if s.indexCustomSettings[idxName] == nil {
					s.indexCustomSettings[idxName] = make(map[string]any)
				}
				s.indexCustomSettings[idxName]["hidden"] = "true"
				modifiedIdxHidden[idxName] = true
				modifiedDS[dsName] = deepCloneDocMap(ds)

			case "remove_backing_index":
				idxName := strings.TrimSpace(fmt.Sprintf("%v", spec["index"]))
				ds := s.dataStreams[dsName]
				if rawIndices, okI := ds["indices"].([]any); okI {
					var kept []any
					for _, item := range rawIndices {
						if m, okM := item.(map[string]any); okM && m["index_name"] == idxName {
							continue
						}
						kept = append(kept, item)
					}
					ds["indices"] = kept
				}
				if s.indexCustomSettings[idxName] != nil {
					s.indexCustomSettings[idxName]["hidden"] = "false"
				}
				modifiedDS[dsName] = deepCloneDocMap(ds)

			case "data_stream_options":
				ds := s.dataStreams[dsName]
				var en bool
				if fsMap, okM := spec["failure_store"].(map[string]any); okM {
					en, _ = parseOptionalBoolAny(fsMap["enabled"])
				} else {
					en, _ = parseOptionalBoolAny(spec["failure_store"])
				}
				fsObj, _ := ds["failure_store"].(map[string]any)
				if fsObj == nil {
					fsObj = map[string]any{"indices": []any{}}
				}
				fsObj["enabled"] = en
				if fsObj["indices"] == nil {
					fsObj["indices"] = []any{}
				}
				ds["failure_store"] = fsObj
				modifiedDS[dsName] = deepCloneDocMap(ds)
			}
		}
	}
	s.mu.Unlock()

	for dsName, snap := range modifiedDS {
		s.persistDataStream(r.Context(), dsName, snap)
	}
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleRolloverR62Search(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	alias := resolveESIndexDateMathR62Search(strings.TrimSpace(r.PathValue("alias")))
	explicitNewIndex := resolveESIndexDateMathR62Search(strings.TrimSpace(r.PathValue("new_index")))
	targetFailureStore := isTruthyBoolQueryParam(r, "target_failure_store")
	lazyFlag := isTruthyBoolQueryParam(r, "lazy")
	dryRun, _, dryErr := parseStrictQueryBoolParamRound59(r, "dry_run")
	if dryErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", dryErr.Error())
		return
	}

	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	dsObj, isDS := s.dataStreams[alias]
	s.mu.RUnlock()

	if !isDS {
		if targetFailureStore {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("target_failure_store=true is only supported on data streams, but [%s] is not a data stream", alias))
			return
		}
		s.handleRollover(w, r)
		return
	}
	if explicitNewIndex != "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "rollover with new_index_name is not supported for data streams")
		return
	}

	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var reqBody struct {
		Conditions map[string]any `json:"conditions"`
		DryRun     *bool          `json:"dry_run,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var rawMap map[string]any
		if err := json.Unmarshal(bodyBytes, &rawMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
		for k := range rawMap {
			if k != "conditions" && k != "dry_run" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("data stream rollover does not support [%s]", k))
				return
			}
		}
		if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if reqBody.DryRun != nil && *reqBody.DryRun {
		dryRun = true
	}

	if targetFailureStore {
		s.mu.RLock()
		curDS := s.dataStreams[alias]
		var fsIndices []any
		if fsMap, okFS := curDS["failure_store"].(map[string]any); okFS {
			fsIndices, _ = fsMap["indices"].([]any)
		}
		curGen, _ := toInt64(curDS["generation"])
		s.mu.RUnlock()

		if len(fsIndices) == 0 && len(reqBody.Conditions) > 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				"Rolling over/initializing an empty failure store is only supported without conditions.")
			return
		}
		oldFS := "_none_"
		if len(fsIndices) > 0 {
			if m, okM := fsIndices[len(fsIndices)-1].(map[string]any); okM {
				oldFS, _ = m["index_name"].(string)
			}
		}
		if lazyFlag {
			if len(reqBody.Conditions) > 0 {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					"lazy rollover does not support conditions")
				return
			}
			if !dryRun {
				s.mu.Lock()
				if liveDS := s.dataStreams[alias]; liveDS != nil {
					fsMap, _ := liveDS["failure_store"].(map[string]any)
					if fsMap == nil {
						fsMap = map[string]any{"enabled": true, "indices": []any{}}
						liveDS["failure_store"] = fsMap
					}
					fsMap["__lazy_rollover"] = true
				}
				s.mu.Unlock()
			}
			writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
				"acknowledged":        true,
				"shards_acknowledged": false,
				"old_index":           oldFS,
				"new_index":           nil,
				"rolled_over":         false,
				"dry_run":             dryRun,
				"conditions":          map[string]bool{},
			})
			return
		}

		condResults := make(map[string]bool)
		shouldRoll := len(reqBody.Conditions) == 0
		if len(reqBody.Conditions) > 0 {
			evalIdx := oldFS
			if evalIdx == "_none_" {
				evalIdx = ""
			}
			var condErr error
			condResults, shouldRoll, condErr = s.evaluateRolloverConditionsRound59(r.Context(), evalIdx, reqBody.Conditions)
			if condErr != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", condErr.Error())
				return
			}
		}
		nextGen := int(curGen) + 1
		newFS := formatFailureStoreBackingIndexNameR62Search(alias, nextGen)
		if dryRun || !shouldRoll {
			ack := dryRun
			writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
				"acknowledged":        ack,
				"shards_acknowledged": false,
				"old_index":           oldFS,
				"new_index":           newFS,
				"rolled_over":         false,
				"dry_run":             dryRun,
				"conditions":          condResults,
			})
			return
		}
		if _, err := s.createPhysicalBackingIndexR62Search(r.Context(), alias, newFS, true, nil, nil, s.isES8Mode(r)); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
			return
		}
		s.mu.Lock()
		liveDS := s.dataStreams[alias]
		liveDS["generation"] = nextGen
		fsMap, _ := liveDS["failure_store"].(map[string]any)
		if fsMap == nil {
			fsMap = map[string]any{"enabled": false, "indices": []any{}}
			liveDS["failure_store"] = fsMap
		}
		delete(fsMap, "__lazy_rollover")
		curFSList, _ := fsMap["indices"].([]any)
		curFSList = append(curFSList, map[string]any{
			"index_name": newFS,
			"index_uuid": indexUUIDForNameRound61(newFS),
			"managed_by": "Data stream lifecycle",
		})
		fsMap["indices"] = curFSList
		snap := deepCloneDocMap(liveDS)
		s.mu.Unlock()
		s.persistDataStream(r.Context(), alias, snap)
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"acknowledged":        true,
			"shards_acknowledged": true,
			"old_index":           oldFS,
			"new_index":           newFS,
			"rolled_over":         true,
			"dry_run":             false,
			"conditions":          condResults,
		})
		return
	}

	// Normal data stream rollover (`.ds-<stream>-YYYY.MM.DD-00000X`)
	var oldIdx string
	if rawIndices, okI := dsObj["indices"].([]any); okI && len(rawIndices) > 0 {
		if m, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM {
			oldIdx, _ = m["index_name"].(string)
		}
	}
	if oldIdx == "" {
		oldIdx = alias
	}
	if lazyFlag {
		if len(reqBody.Conditions) > 0 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				"lazy rollover does not support conditions")
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"acknowledged":        true,
			"shards_acknowledged": false,
			"old_index":           oldIdx,
			"new_index":           nil,
			"rolled_over":         false,
			"dry_run":             dryRun,
			"conditions":          map[string]bool{},
		})
		return
	}

	condResults, shouldRoll, condErr := s.evaluateRolloverConditionsRound59(r.Context(), oldIdx, reqBody.Conditions)
	if condErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", condErr.Error())
		return
	}
	curGen, _ := toInt64(dsObj["generation"])
	nextGen := int(curGen) + 1
	if nextGen < 2 {
		nextGen = 2
	}
	newIdx := formatDataStreamBackingIndexNameR62Search(alias, nextGen, s.hasExplicitTargetESVersion())
	if dryRun || !shouldRoll {
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"acknowledged":        dryRun,
			"shards_acknowledged": false,
			"old_index":           oldIdx,
			"new_index":           newIdx,
			"rolled_over":         false,
			"dry_run":             dryRun,
			"conditions":          condResults,
		})
		return
	}

	newSchema, err := s.createPhysicalBackingIndexR62Search(r.Context(), alias, newIdx, false, nil, nil, s.isES8Mode(r))
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	s.mu.Lock()
	liveDS := s.dataStreams[alias]
	liveDS["generation"] = nextGen
	preferILM, _ := liveDS["prefer_ilm"].(bool)
	nextManagedBy, _ := liveDS["next_generation_managed_by"].(string)
	if nextManagedBy == "" {
		nextManagedBy = "Unmanaged"
	}
	newEntry := map[string]any{
		"index_name": newIdx,
		"index_uuid": indexUUIDForNameRound61(newIdx),
		"prefer_ilm": preferILM,
		"managed_by": nextManagedBy,
	}
	if ilmPol, okP := liveDS["ilm_policy"].(string); okP && ilmPol != "" {
		newEntry["ilm_policy"] = ilmPol
	}
	curIndices, _ := liveDS["indices"].([]any)
	liveDS["indices"] = append(curIndices, newEntry)
	if newSchema != nil && newSchema.IndexMode == "time_series" {
		liveDS["time_series"] = map[string]any{
			"temporal_ranges": []any{
				map[string]any{
					"start": newSchema.TimeSeriesStartTime,
					"end":   newSchema.TimeSeriesEndTime,
				},
			},
		}
	}
	snap := deepCloneDocMap(liveDS)
	s.mu.Unlock()

	s.persistDataStream(r.Context(), alias, snap)
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"old_index":           oldIdx,
		"new_index":           newIdx,
		"rolled_over":         true,
		"dry_run":             false,
		"conditions":          condResults,
	})
}

func (s *Server) handleMigrateToDataStreamR62Search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.Lock()
	if _, alreadyDS := s.dataStreams[name]; alreadyDS {
		s.mu.Unlock()
		writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "data_stream ["+name+"] already exists")
		return
	}
	if _, isConcreteIdx := s.indices[name]; isConcreteIdx {
		s.mu.Unlock()
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("[%s] is an index, not an alias", name))
		return
	}
	targets := append([]string(nil), s.aliases[name]...)
	if len(targets) == 0 {
		s.mu.Unlock()
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "alias ["+name+"] missing")
		return
	}
	tplName, winTpl, hasDSTpl := s.findWinningDataStreamTemplateLockedR62Search(name)
	if !hasDSTpl && s.explicitTargetESVersion {
		s.mu.Unlock()
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("no matching index template found for data stream [%s]", name))
		return
	}
	// Verify alias has a write index if multiple indices exist
	metaByIdx := s.aliasMeta[name]
	writeIdx := ""
	if len(targets) == 1 {
		if metaByIdx != nil && metaByIdx[targets[0]].IsWriteIndex != nil && !*metaByIdx[targets[0]].IsWriteIndex {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("no write index is defined for alias [%s]", name))
			return
		}
		writeIdx = targets[0]
	} else {
		for _, t := range targets {
			if metaByIdx != nil && metaByIdx[t].IsWriteIndex != nil && *metaByIdx[t].IsWriteIndex {
				writeIdx = t
				break
			}
		}
		if writeIdx == "" {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("no write index is defined for alias [%s]", name))
			return
		}
	}
	// Order targets with writeIdx last
	ordered := make([]string, 0, len(targets))
	for _, t := range targets {
		if t != writeIdx {
			ordered = append(ordered, t)
		}
	}
	sort.Strings(ordered)
	ordered = append(ordered, writeIdx)

	idxList := make([]any, 0, len(ordered))
	for _, t := range ordered {
		idxList = append(idxList, map[string]any{
			"index_name": t,
			"index_uuid": indexUUIDForNameRound61(t),
			"prefer_ilm": true,
			"managed_by": "Unmanaged",
		})
		if s.indexCustomSettings == nil {
			s.indexCustomSettings = make(map[string]map[string]any)
		}
		if s.indexCustomSettings[t] == nil {
			s.indexCustomSettings[t] = make(map[string]any)
		}
		s.indexCustomSettings[t]["hidden"] = "true"
	}
	hidden, allowCR, fsEn := extractTemplateDataStreamFlagsR62Search(winTpl.DataStream)
	dsObj := map[string]any{
		"name":                       name,
		"timestamp_field":            map[string]any{"name": "@timestamp"},
		"indices":                    idxList,
		"generation":                 len(ordered),
		"status":                     "GREEN",
		"template":                   tplName,
		"hidden":                     hidden,
		"system":                     false,
		"allow_custom_routing":       allowCR,
		"replicated":                 false,
		"prefer_ilm":                 true,
		"next_generation_managed_by": "Unmanaged",
		"failure_store": map[string]any{
			"enabled": fsEn,
			"indices": []any{},
		},
	}
	if s.dataStreams == nil {
		s.dataStreams = make(map[string]map[string]any)
	}
	s.dataStreams[name] = dsObj
	delete(s.aliases, name)
	delete(s.aliasMeta, name)
	s.mu.Unlock()

	s.persistDataStream(r.Context(), name, dsObj)
	s.persistAlias(r.Context(), name, nil)
	s.queryCache.InvalidateAll()
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleDataStreamsStatsR62Search(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	pattern := strings.TrimSpace(r.PathValue("name"))
	if pattern == "" {
		pattern = "*"
	}
	human := isTruthyBoolQueryParam(r, "human")

	s.mu.RLock()
	var missingConcrete string
	if pattern != "*" && pattern != "_all" {
		for _, p := range strings.Split(pattern, ",") {
			p = strings.TrimSpace(p)
			if p == "" || strings.HasPrefix(p, "-") || strings.ContainsAny(p, "*?") || p == "_all" {
				continue
			}
			if s.dataStreams[p] == nil && missingConcrete == "" {
				missingConcrete = p
			}
		}
	}
	if missingConcrete != "" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
		s.mu.RUnlock()
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "data_streams ["+missingConcrete+"] missing")
		return
	}
	var names []string
	for k := range s.dataStreams {
		if matchMultiWildcardWithExclusions(pattern, k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	dsSnapshots := make(map[string]map[string]any, len(names))
	for _, n := range names {
		dsSnapshots[n] = deepCloneDocMap(s.dataStreams[n])
	}
	s.mu.RUnlock()

	var totalBacking, totalShards, totalStoreBytes int64
	streamsOut := make([]any, 0, len(names))
	for _, n := range names {
		ds := dsSnapshots[n]
		rawIndices, _ := ds["indices"].([]any)
		var bCount int64
		var sBytes int64
		maxTS, _ := toInt64(ds["__max_timestamp_ms"])
		for _, item := range rawIndices {
			m, okM := item.(map[string]any)
			if !okM {
				continue
			}
			bIdx, _ := m["index_name"].(string)
			if bIdx == "" {
				continue
			}
			bCount++
			numShards, numReplicas, _ := s.getIndexShardAndReplicaCounts(bIdx)
			totalShards += int64(numShards * (1 + numReplicas))
			_, idxBytes := s.computeLiveIndexDocCountAndStoreBytesRound59(r.Context(), bIdx, true)
			sBytes += idxBytes
		}
		if fsObj, okFS := ds["failure_store"].(map[string]any); okFS {
			if fsIndices, okFI := fsObj["indices"].([]any); okFI {
				for _, item := range fsIndices {
					if m, okM := item.(map[string]any); okM {
						fIdx, _ := m["index_name"].(string)
						if fIdx != "" {
							numShards, numReplicas, _ := s.getIndexShardAndReplicaCounts(fIdx)
							totalShards += int64(numShards * (1 + numReplicas))
						}
					}
				}
			}
		}
		totalBacking += bCount
		totalStoreBytes += sBytes
		entry := map[string]any{
			"data_stream":        n,
			"backing_indices":    bCount,
			"store_size_bytes":   sBytes,
			"maximum_timestamp":  maxTS,
			"total_store_size":   fmt.Sprintf("%db", sBytes),
			"failure_store_size": int64(0),
		}
		if human {
			entry["store_size"] = fmt.Sprintf("%db", sBytes)
			if maxTS > 0 {
				entry["maximum_timestamp_string"] = time.UnixMilli(maxTS).UTC().Format("2006-01-02T15:04:05.000Z")
			}
		}
		if !human {
			delete(entry, "total_store_size")
		}
		streamsOut = append(streamsOut, entry)
	}
	if totalShards == 0 && len(names) > 0 {
		totalShards = int64(len(names))
	}
	resp := map[string]any{
		"_shards": map[string]any{
			"total":      totalShards,
			"successful": totalShards,
			"failed":     0,
		},
		"data_stream_count":      len(names),
		"backing_indices":        totalBacking,
		"total_store_size_bytes": totalStoreBytes,
		"data_streams":           streamsOut,
	}
	if human {
		resp["total_store_size"] = fmt.Sprintf("%db", totalStoreBytes)
	}
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}

func (s *Server) handleResolveIndexR62Search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawName := strings.TrimSpace(r.PathValue("name"))
	if rawName == "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
		return
	}
	rawName = resolveCommaDateMathTokensR62Search(rawName)
	rawEW := strings.TrimSpace(r.URL.Query().Get("expand_wildcards"))
	if rawEW == "" {
		rawEW = "open"
	}
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(rawEW)
	if ewErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", ewErr.Error())
		return
	}

	_ = s.syncCatalogFromBackend(r.Context())
	if strings.Contains(rawName, ":") {
		s.handleResolveIndexRound58(w, r)
		return
	}

	tokens := splitCommaTrimmedTokens([]string{rawName})
	var posPats, negPats []string
	concretePos := make(map[string]bool)
	hasExplicitDotPos := false
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negPats = append(negPats, tok[1:])
		} else {
			posPats = append(posPats, tok)
			if strings.HasPrefix(tok, ".") {
				hasExplicitDotPos = true
			}
			if !strings.ContainsAny(tok, "*?") && tok != "_all" {
				concretePos[tok] = true
			}
		}
	}
	matchesExpr := func(candidate string) bool {
		if ewNone {
			if !concretePos[candidate] {
				return false
			}
		} else {
			matched := false
			for _, p := range posPats {
				if p == "_all" || p == "*" || matchWildcardPattern(p, candidate) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		for _, np := range negPats {
			if np == "_all" || np == "*" || matchWildcardPattern(np, candidate) {
				return false
			}
		}
		return true
	}

	s.mu.RLock()
	indicesOut := make([]map[string]any, 0)
	aliasesOut := make([]map[string]any, 0)
	dataStreamsOut := make([]map[string]any, 0)

	var idxNames []string
	for k := range s.indices {
		idxNames = append(idxNames, k)
	}
	sort.Strings(idxNames)
	for _, idxName := range idxNames {
		if !matchesExpr(idxName) {
			continue
		}
		isClosed := s.closedIndices[idxName]
		dsOwner := s.findOwningDataStreamLockedR62Search(idxName)
		isHidden := s.isIndexExplicitlyHiddenLocked(idxName) ||
			strings.HasPrefix(idxName, ".") ||
			dsOwner != ""
		if !concretePos[idxName] {
			if isHidden && !ewHidden && !hasExplicitDotPos {
				continue
			}
			if isClosed && !ewClosed {
				continue
			}
			if !isClosed && !ewOpen {
				continue
			}
		}
		var attrs []string
		if isHidden {
			attrs = append(attrs, "hidden")
		}
		if isClosed {
			attrs = append(attrs, "closed")
		} else {
			attrs = append(attrs, "open")
		}
		sort.Strings(attrs)
		entry := map[string]any{
			"name":       idxName,
			"attributes": attrs,
			"open":       !isClosed,
		}
		if !s.explicitTargetESVersion {
			if isClosed {
				entry["state"] = "close"
			} else {
				entry["state"] = "open"
			}
			entry["hidden"] = isHidden
		}
		var matchingAliases []string
		for al, alTargets := range s.aliases {
			for _, t := range alTargets {
				if t == idxName {
					isAlHidden := false
					if metaByIdx := s.aliasMeta[al]; metaByIdx != nil && metaByIdx[idxName].IsHidden != nil && *metaByIdx[idxName].IsHidden {
						isAlHidden = true
					}
					if isAlHidden && !ewHidden && !hasExplicitDotPos && !concretePos[al] {
						continue
					}
					matchingAliases = append(matchingAliases, al)
				} else if dsOwner != "" && t == dsOwner {
					matchingAliases = append(matchingAliases, al)
				}
			}
		}
		if len(matchingAliases) > 0 {
			sort.Strings(matchingAliases)
			entry["aliases"] = matchingAliases
		}
		if dsOwner != "" {
			entry["data_stream"] = dsOwner
		}
		indicesOut = append(indicesOut, entry)
	}

	var aliasNames []string
	for al := range s.aliases {
		if len(s.aliases[al]) > 0 {
			aliasNames = append(aliasNames, al)
		}
	}
	sort.Strings(aliasNames)
	for _, al := range aliasNames {
		if !matchesExpr(al) {
			continue
		}
		targets := append([]string(nil), s.aliases[al]...)
		sort.Strings(targets)
		anyOpen, anyClosed := false, false
		allHidden := len(targets) > 0
		for _, t := range targets {
			if ds := s.dataStreams[t]; ds != nil {
				anyOpen = true
				if h, _ := ds["hidden"].(bool); !h {
					allHidden = false
				}
				continue
			}
			if s.closedIndices[t] {
				anyClosed = true
			} else {
				anyOpen = true
			}
			isTHidden := s.isIndexExplicitlyHiddenLocked(t) || strings.HasPrefix(t, ".")
			if metaByIdx := s.aliasMeta[al]; metaByIdx != nil && metaByIdx[t].IsHidden != nil && *metaByIdx[t].IsHidden {
				isTHidden = true
			}
			if !isTHidden {
				allHidden = false
			}
		}
		if !concretePos[al] {
			if allHidden && !ewHidden && !hasExplicitDotPos {
				continue
			}
			if (!anyOpen || !ewOpen) && (!anyClosed || !ewClosed) {
				continue
			}
		}
		aliasesOut = append(aliasesOut, map[string]any{
			"name":    al,
			"indices": targets,
		})
	}

	var dsNames []string
	for dsName := range s.dataStreams {
		dsNames = append(dsNames, dsName)
	}
	sort.Strings(dsNames)
	for _, dsName := range dsNames {
		if !matchesExpr(dsName) {
			continue
		}
		ds := s.dataStreams[dsName]
		isDSHidden, _ := ds["hidden"].(bool)
		if strings.HasPrefix(dsName, ".") {
			isDSHidden = true
		}
		if !concretePos[dsName] {
			if !ewOpen {
				continue
			}
			if isDSHidden && !ewHidden && !hasExplicitDotPos {
				continue
			}
		}
		backing := extractDataStreamBackingIndexNames(ds)
		if len(backing) == 0 {
			backing = []string{}
		}
		dsEntry := map[string]any{
			"name":            dsName,
			"backing_indices": backing,
			"timestamp_field": "@timestamp",
		}
		var dsAliases []string
		for al, targets := range s.aliases {
			for _, t := range targets {
				if t == dsName {
					dsAliases = append(dsAliases, al)
					break
				}
			}
		}
		if len(dsAliases) > 0 {
			sort.Strings(dsAliases)
			dsEntry["aliases"] = dsAliases
		}
		dataStreamsOut = append(dataStreamsOut, dsEntry)
	}
	s.mu.RUnlock()

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"indices":      indicesOut,
		"aliases":      aliasesOut,
		"data_streams": dataStreamsOut,
	})
}

func (s *Server) shredDocumentCopyOnWriteAutoDimsR62Search(
	ctx context.Context,
	indexName string,
	idxSchema *schema.IndexSchema,
	docID string,
	nextVer int64,
	isDelete bool,
	docPayload json.RawMessage,
) ([]byte, *schema.IndexSchema, error) {
	if !isDelete && len(docPayload) > 0 && idxSchema != nil {
		updated, err := s.applyCopyOnWriteAutoDimsR62Search(ctx, indexName, idxSchema, [][]byte{docPayload})
		if err != nil {
			return nil, idxSchema, err
		}
		idxSchema = updated
	}
	pushActiveScriptedSchemaR62Search(idxSchema)
	shredded, err := schema.ShredDocument(idxSchema, docID, nextVer, isDelete, docPayload)
	popActiveScriptedSchemaR62Search(idxSchema)
	if err != nil {
		return nil, idxSchema, err
	}
	return shredded, idxSchema, nil
}

func (s *Server) prepareAutoCreateTargetR62Search(
	ctx context.Context,
	r *http.Request,
	rawTarget string,
	isCreateOp bool,
) (int, string, string) {
	target := strings.TrimSpace(rawTarget)
	if target == "" || strings.ContainsAny(target, "*?,") || strings.HasPrefix(target, "<") {
		return 0, "", ""
	}
	_ = s.syncCatalogFromBackend(ctx)
	s.mu.RLock()
	_, isIdx := s.indices[target]
	isAlias := len(s.aliases[target]) > 0
	_, isDS := s.dataStreams[target]
	_, _, _, _, _, _, _, winComp := s.matchingTemplateFullConfigLocked(target)
	s.mu.RUnlock()

	if isDS {
		if !isCreateOp && s.isDataStream(target) {
			return http.StatusBadRequest, "illegal_argument_exception", "only write ops with an op_type of create are allowed in data streams"
		}
		return 0, "", ""
	}
	if !isIdx && !isAlias {
		if stCode, errType, errReason := s.checkAutoCreateIndexClusterSettingRound60(target); stCode != 0 {
			return stCode, errType, errReason
		}
	}
	if isIdx || isAlias || winComp == nil {
		return 0, "", ""
	}
	if winComp.AllowAutoCreate != nil && !*winComp.AllowAutoCreate {
		return http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such index [%s] and [allow_auto_create] is [false] on matching index template", target)
	}
	if winComp.DataStream != nil {
		if !isCreateOp {
			return http.StatusBadRequest, "illegal_argument_exception", "only write ops with an op_type of create are allowed in data streams"
		}
		if _, st, et, er := s.createOrAutoCreateDataStreamR62Search(ctx, target, nil, nil, s.isES8Mode(r), false); st != 0 {
			return st, et, er
		}
	}
	return 0, "", ""
}

func writeESErrorWithCausedByR62Search(w http.ResponseWriter, status int, errType, reason string, causedBy map[string]any) {
	if causedBy == nil {
		writeESError(w, status, errType, reason)
		return
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{
				{
					"type":   errType,
					"reason": reason,
				},
			},
			"type":      errType,
			"reason":    reason,
			"caused_by": causedBy,
		},
		"status": status,
	})
}

func validateMGetForceSyntheticSourceR62Search(idxSchema *schema.IndexSchema, forceSynth bool) (string, bool) {
	if !forceSynth || idxSchema == nil || idxSchema.RawMapping == nil {
		return "", true
	}
	cp := *idxSchema.RawMapping
	cp.Source = map[string]any{"mode": "synthetic"}
	if err := schema.ValidateSyntheticSourceMapping(&cp); err != nil {
		_, rsn := splitSchemaErrorPrefixR61CRUD(err, "illegal_argument_exception")
		return rsn, false
	}
	return "", true
}

// ============================================================================
// F21-F24: Runtime Fields Lazy DFS, `on_script_error`, Index-Time Scripts,
// Composite Runtime Fields, `scripted_metric` Allow-List & Explain Trees
// ============================================================================

var (
	activeScriptedSchemasMuR62Search sync.RWMutex
	activeScriptedSchemasR62Search   = make(map[*schema.IndexSchema]int)
	knownScriptedSchemasR62Search    = make(map[*schema.IndexSchema]struct{})
)

func init() {
	schema.RegisterIndexFieldScriptEvaluator(evalIndexTimeFieldScriptR62Search)
}

func hasMappedPropertyScriptsR62Search(props map[string]esast.FieldProperty) bool {
	for _, p := range props {
		if p.Script != nil {
			return true
		}
		if len(p.Fields) > 0 && hasMappedPropertyScriptsR62Search(p.Fields) {
			return true
		}
		if len(p.Properties) > 0 && hasMappedPropertyScriptsR62Search(p.Properties) {
			return true
		}
	}
	return false
}

func pushActiveScriptedSchemaR62Search(s *schema.IndexSchema) {
	if s == nil || s.RawMapping == nil || !hasMappedPropertyScriptsR62Search(s.RawMapping.Properties) {
		return
	}
	activeScriptedSchemasMuR62Search.Lock()
	activeScriptedSchemasR62Search[s]++
	knownScriptedSchemasR62Search[s] = struct{}{}
	activeScriptedSchemasMuR62Search.Unlock()
}

func popActiveScriptedSchemaR62Search(s *schema.IndexSchema) {
	if s == nil || s.RawMapping == nil || !hasMappedPropertyScriptsR62Search(s.RawMapping.Properties) {
		return
	}
	activeScriptedSchemasMuR62Search.Lock()
	if activeScriptedSchemasR62Search[s] <= 1 {
		delete(activeScriptedSchemasR62Search, s)
	} else {
		activeScriptedSchemasR62Search[s]--
	}
	activeScriptedSchemasMuR62Search.Unlock()
}

func registerKnownScriptedSchemaR62Search(s *schema.IndexSchema) {
	if s == nil || s.RawMapping == nil || !hasMappedPropertyScriptsR62Search(s.RawMapping.Properties) {
		return
	}
	activeScriptedSchemasMuR62Search.Lock()
	knownScriptedSchemasR62Search[s] = struct{}{}
	activeScriptedSchemasMuR62Search.Unlock()
}

func shredDocumentWithActiveSchemaR62Search(s *schema.IndexSchema, id string, version int64, deleted bool, rawSource []byte) ([]byte, error) {
	pushActiveScriptedSchemaR62Search(s)
	defer popActiveScriptedSchemaR62Search(s)
	return schema.ShredDocument(s, id, version, deleted, rawSource)
}

func collectMappedScriptPropsR62Search(props map[string]esast.FieldProperty, prefix string, out map[string]esast.FieldProperty) {
	for k, p := range props {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		if p.Script != nil && (p.Enabled == nil || *p.Enabled) {
			out[full] = p
		}
		if len(p.Properties) > 0 {
			collectMappedScriptPropsR62Search(p.Properties, full, out)
		}
	}
}

func matchActiveScriptedSchemaR62Search(fieldPath, esType string, scriptSpec any) *schema.IndexSchema {
	srcWanted, _ := extractScriptSourceAndParams(scriptSpec)
	activeScriptedSchemasMuR62Search.RLock()
	defer activeScriptedSchemasMuR62Search.RUnlock()

	checkCandidate := func(cand *schema.IndexSchema) bool {
		if cand == nil || cand.RawMapping == nil {
			return false
		}
		props := make(map[string]esast.FieldProperty)
		collectMappedScriptPropsR62Search(cand.RawMapping.Properties, "", props)
		prop, ok := props[fieldPath]
		if !ok {
			return false
		}
		if esType != "" && !strings.EqualFold(strings.TrimSpace(prop.Type), esType) {
			return false
		}
		candSrc, _ := extractScriptSourceAndParams(prop.Script)
		return candSrc == srcWanted
	}

	if len(activeScriptedSchemasR62Search) == 1 {
		for s := range activeScriptedSchemasR62Search {
			if checkCandidate(s) {
				return s
			}
		}
	}
	for s := range activeScriptedSchemasR62Search {
		if checkCandidate(s) {
			return s
		}
	}
	for s := range knownScriptedSchemasR62Search {
		if checkCandidate(s) {
			return s
		}
	}
	return nil
}

func buildStoredFieldsParamMapR62Search(idxSchema *schema.IndexSchema, doc map[string]any) map[string]any {
	if idxSchema == nil || doc == nil {
		return nil
	}
	storeTrue := collectExplicitStoreTrueFieldsR61Search(idxSchema)
	if len(storeTrue) == 0 {
		return nil
	}
	out := make(map[string]any, len(storeTrue))
	for fn := range storeTrue {
		vals := extractRawStoredValuesForFieldR61Search(doc, fn, idxSchema)
		if len(vals) == 0 {
			continue
		}
		out[fn] = map[string]any{
			"values": vals,
			"value":  vals[0],
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func evalSingleIndexTimeOrRuntimePropR62Search(
	idxSchema *schema.IndexSchema,
	fieldPath string,
	prop esast.FieldProperty,
	evalDoc map[string]any,
	sourceDoc map[string]any,
	fieldsParam map[string]any,
	ftMap map[string]string,
	isES8 bool,
	nowUTC time.Time,
) ([]any, error) {
	esType := strings.ToLower(strings.TrimSpace(prop.Type))
	if esType == "" {
		esType = "keyword"
	}
	scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
	if strings.TrimSpace(scriptSrc) == "" {
		return nil, nil
	}
	p := make(map[string]any, len(scriptParams)+6)
	for k, v := range scriptParams {
		p[k] = v
	}
	p["_source"] = sourceDoc
	p["__keep_boolean_dups"] = isES8
	p["__quantize_geo_point"] = true
	if strings.TrimSpace(prop.Format) != "" {
		p["__runtime_date_format"] = strings.TrimSpace(prop.Format)
	}
	if fieldsParam != nil {
		p["_fields"] = fieldsParam
	}

	var rawVals []any
	if emitCtx, okCtx := runtimeFieldTypeToEmitContextRound60(esType); okCtx && strings.Contains(scriptSrc, "emit(") {
		emitted, errEmit := painless.EvalEmitContext(scriptSrc, emitCtx, evalDoc, sourceDoc, p, ftMap)
		if errEmit != nil {
			return nil, errEmit
		}
		rawVals = emitted
	} else {
		res, evalErr := painless.Eval(evalDoc, scriptSrc, p)
		if evalErr != nil {
			return nil, evalErr
		}
		if emitted, ok := p["__emitted_vals"].([]any); ok && len(emitted) > 0 {
			rawVals = emitted
		} else if res != nil {
			if arr, ok := res.([]any); ok {
				rawVals = arr
			} else {
				rawVals = []any{res}
			}
		}
	}
	if len(rawVals) == 0 {
		return nil, nil
	}
	return coerceEmittedRuntimeValuesRound61(esType, prop.Format, rawVals, nowUTC), nil
}

func evalIndexTimeFieldScriptR62Search(
	fieldPath string,
	esType string,
	scriptSpec any,
	onScriptError string,
	sourceDoc map[string]any,
) ([]any, error) {
	idxSchema := matchActiveScriptedSchemaR62Search(fieldPath, esType, scriptSpec)
	isES8 := idxSchema == nil || idxSchema.ES8Mode
	workingDoc := deepCloneDocMap(sourceDoc)
	if workingDoc == nil {
		workingDoc = make(map[string]any)
	}
	nowUTC := time.Now().UTC()
	fieldsParam := buildStoredFieldsParamMapR62Search(idxSchema, sourceDoc)

	if idxSchema != nil && idxSchema.RawMapping != nil {
		scriptProps := make(map[string]esast.FieldProperty)
		collectMappedScriptPropsR62Search(idxSchema.RawMapping.Properties, "", scriptProps)
		if prop, ok := scriptProps[fieldPath]; ok {
			order, err := resolveLazyRuntimeMappingsOrderR62Search(scriptProps, []string{fieldPath})
			if err != nil {
				return nil, err
			}
			evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, workingDoc, isES8)
			ftMap, _ := evalDoc["__field_types"].(map[string]string)
			if ftMap == nil {
				ftMap = make(map[string]string)
				evalDoc["__field_types"] = ftMap
			}
			for fn, sp := range scriptProps {
				t := strings.ToLower(strings.TrimSpace(sp.Type))
				if t == "" {
					t = "keyword"
				}
				ftMap[fn] = t
			}
			for _, depName := range order {
				depProp := scriptProps[depName]
				coerced, depErr := evalSingleIndexTimeOrRuntimePropR62Search(
					idxSchema, depName, depProp, evalDoc, sourceDoc, fieldsParam, ftMap, isES8, nowUTC,
				)
				if depErr != nil {
					depOnErr := strings.ToLower(strings.TrimSpace(depProp.OnScriptError))
					if depName == fieldPath && strings.EqualFold(onScriptError, "continue") {
						return nil, nil
					}
					if depOnErr == "continue" {
						continue
					}
					return nil, fmt.Errorf("script_exception: runtime error: %w", depErr)
				}
				if depName == fieldPath {
					return coerced, nil
				}
				if len(coerced) > 0 {
					var val any = coerced
					if len(coerced) == 1 {
						val = coerced[0]
					}
					workingDoc[depName] = val
					if strings.Contains(depName, ".") {
						setIngestPath(workingDoc, depName, val)
					}
					evalDoc[depName] = val
					if strings.Contains(depName, ".") {
						setRuntimeScriptDocPath(evalDoc, strings.Split(depName, "."), val)
					}
				}
			}
			_ = prop
			return nil, nil
		}
	}

	evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, workingDoc, isES8)
	ftMap, _ := evalDoc["__field_types"].(map[string]string)
	if ftMap == nil {
		ftMap = make(map[string]string)
		evalDoc["__field_types"] = ftMap
	}
	if esType != "" {
		ftMap[fieldPath] = esType
	}
	coerced, err := evalSingleIndexTimeOrRuntimePropR62Search(
		idxSchema,
		fieldPath,
		esast.FieldProperty{Type: esType, Script: scriptSpec, OnScriptError: onScriptError},
		evalDoc,
		sourceDoc,
		fieldsParam,
		ftMap,
		isES8,
		nowUTC,
	)
	if err != nil {
		if strings.EqualFold(onScriptError, "continue") {
			return nil, nil
		}
		return nil, fmt.Errorf("script_exception: runtime error: %w", err)
	}
	return coerced, nil
}

// evalIndexTimeMappedFieldsForHitR62Search evaluates `mappings.properties.<f>.script` on a hit's
// `_source` when requested by `fields`, `docvalue_fields`, or `highlight` (`*_calculated_at_index.yml`).
func evalIndexTimeMappedFieldsForHitR62Search(idxSchema *schema.IndexSchema, sourceDoc map[string]any) map[string][]any {
	if idxSchema == nil || idxSchema.RawMapping == nil || !hasMappedPropertyScriptsR62Search(idxSchema.RawMapping.Properties) {
		return nil
	}
	scriptProps := make(map[string]esast.FieldProperty)
	collectMappedScriptPropsR62Search(idxSchema.RawMapping.Properties, "", scriptProps)
	if len(scriptProps) == 0 {
		return nil
	}
	roots := make([]string, 0, len(scriptProps))
	for k := range scriptProps {
		roots = append(roots, k)
	}
	sort.Strings(roots)
	order, err := resolveLazyRuntimeMappingsOrderR62Search(scriptProps, roots)
	if err != nil {
		order = roots
	}
	workingDoc := deepCloneDocMap(sourceDoc)
	if workingDoc == nil {
		workingDoc = make(map[string]any)
	}
	isES8 := idxSchema.ES8Mode
	evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, workingDoc, isES8)
	ftMap, _ := evalDoc["__field_types"].(map[string]string)
	if ftMap == nil {
		ftMap = make(map[string]string)
		evalDoc["__field_types"] = ftMap
	}
	for fn, sp := range scriptProps {
		t := strings.ToLower(strings.TrimSpace(sp.Type))
		if t == "" {
			t = "keyword"
		}
		ftMap[fn] = t
	}
	fieldsParam := buildStoredFieldsParamMapR62Search(idxSchema, sourceDoc)
	nowUTC := time.Now().UTC()
	out := make(map[string][]any, len(order))
	for _, fn := range order {
		sp := scriptProps[fn]
		coerced, evalErr := evalSingleIndexTimeOrRuntimePropR62Search(
			idxSchema, fn, sp, evalDoc, sourceDoc, fieldsParam, ftMap, isES8, nowUTC,
		)
		if evalErr != nil || len(coerced) == 0 {
			continue
		}
		out[fn] = coerced
		var val any = coerced
		if len(coerced) == 1 {
			val = coerced[0]
		}
		workingDoc[fn] = val
		if strings.Contains(fn, ".") {
			setIngestPath(workingDoc, fn, val)
		}
		evalDoc[fn] = val
		if strings.Contains(fn, ".") {
			setRuntimeScriptDocPath(evalDoc, strings.Split(fn, "."), val)
		}
	}
	return out
}

func normalizeSingleScriptSpecR62Search(raw any) any {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return map[string]any{
			"source": v,
			"lang":   "painless",
		}
	case map[string]any:
		cp := make(map[string]any, len(v)+1)
		for k, val := range v {
			cp[k] = val
		}
		if _, hasLang := cp["lang"]; !hasLang {
			if _, hasID := cp["id"]; !hasID {
				cp["lang"] = "painless"
			}
		}
		return cp
	case *esast.ScriptSpec:
		if v == nil {
			return nil
		}
		if v.ID != "" {
			out := map[string]any{"id": v.ID}
			if len(v.Params) > 0 {
				out["params"] = v.Params
			}
			return out
		}
		lang := v.Lang
		if lang == "" {
			lang = "painless"
		}
		out := map[string]any{
			"source": v.Source,
			"lang":   lang,
		}
		if len(v.Params) > 0 {
			out["params"] = v.Params
		}
		return out
	case esast.ScriptSpec:
		return normalizeSingleScriptSpecR62Search(&v)
	}
	return raw
}

func normalizeFieldPropsScriptsR62Search(props map[string]esast.FieldProperty) {
	for k, prop := range props {
		changed := false
		if prop.Script != nil {
			prop.Script = normalizeSingleScriptSpecR62Search(prop.Script)
			changed = true
		}
		if len(prop.Fields) > 0 {
			normalizeFieldPropsScriptsR62Search(prop.Fields)
			changed = true
		}
		if len(prop.Properties) > 0 {
			normalizeFieldPropsScriptsR62Search(prop.Properties)
			changed = true
		}
		if changed {
			props[k] = prop
		}
	}
}

func normalizeMappingScriptsInPlaceR62Search(m *esast.MappingSpec) {
	if m == nil {
		return
	}
	if len(m.Properties) > 0 {
		normalizeFieldPropsScriptsR62Search(m.Properties)
	}
	if len(m.Runtime) > 0 {
		normalizeFieldPropsScriptsR62Search(m.Runtime)
	}
}

func validateMappedPropertyScriptsR62Search(m *esast.MappingSpec) error {
	if m == nil || len(m.Properties) == 0 {
		return nil
	}
	var walk func(props map[string]esast.FieldProperty, prefix string) error
	walk = func(props map[string]esast.FieldProperty, prefix string) error {
		for k, prop := range props {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			if onErr := strings.ToLower(strings.TrimSpace(prop.OnScriptError)); onErr != "" && onErr != "fail" && onErr != "continue" {
				return fmt.Errorf("mapper_parsing_exception: Invalid [on_script_error] value [%s] on field [%s]: must be [fail] or [continue]", prop.OnScriptError, full)
			}
			if prop.Script != nil {
				if src, ok := extractPainlessSourceIfApplicableRound60(prop.Script); ok {
					if err := painless.CompileValidate(src); err != nil {
						return err
					}
				}
			}
			if len(prop.Fields) > 0 {
				if err := walk(prop.Fields, full); err != nil {
					return err
				}
			}
			if len(prop.Properties) > 0 {
				if err := walk(prop.Properties, full); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(m.Properties, "")
}

func resolveLazyRuntimeMappingsOrderR62Search(
	rtMap map[string]esast.FieldProperty,
	rootFields []string,
) ([]string, error) {
	if len(rtMap) == 0 || len(rootFields) == 0 {
		return nil, nil
	}
	candidates := make(map[string]bool, len(rtMap))
	for k := range rtMap {
		candidates[k] = true
	}

	resolvedSet := make(map[string]bool, len(rtMap))
	var postOrder []string

	var dfs func(cur string, stack []string) error
	dfs = func(cur string, stack []string) error {
		for idx, prev := range stack {
			if prev == cur {
				cycle := append(append([]string(nil), stack[idx:]...), cur)
				return fmt.Errorf("illegal_argument_exception: Cyclic dependency detected while resolving runtime fields: %s", strings.Join(cycle, " -> "))
			}
		}
		nextStack := append(append([]string(nil), stack...), cur)
		if len(nextStack) > 5 {
			return fmt.Errorf("illegal_argument_exception: Field requires resolving too many dependent fields: %s", strings.Join(nextStack, " -> "))
		}
		prop, exists := rtMap[cur]
		if !exists {
			return nil
		}
		if prop.Script != nil {
			scriptSrc, _ := extractScriptSourceAndParams(prop.Script)
			deps := ExtractRuntimeScriptFieldDepsRound61(scriptSrc, candidates)
			for _, dep := range deps {
				if err := dfs(dep, nextStack); err != nil {
					return err
				}
			}
		}
		if !resolvedSet[cur] {
			resolvedSet[cur] = true
			postOrder = append(postOrder, cur)
		}
		return nil
	}

	for _, root := range rootFields {
		if !candidates[root] {
			continue
		}
		if err := dfs(root, nil); err != nil {
			return nil, err
		}
	}
	return postOrder, nil
}

func collectQueryFieldRefsR62Search(q *esast.Query, rtCandidates map[string]bool, addField func(string)) {
	if q == nil {
		return
	}
	for f := range q.Term {
		addField(f)
	}
	if q.Terms != nil {
		for f := range q.Terms.Fields {
			addField(f)
		}
	}
	for f, entry := range q.TermsSet {
		addField(f)
		addField(entry.MinimumShouldMatchField)
		if entry.MinimumShouldMatchScript != nil {
			src, _ := extractScriptSourceAndParams(entry.MinimumShouldMatchScript)
			for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
				addField(dep)
			}
		}
	}
	for f := range q.Match {
		addField(f)
	}
	for f := range q.MatchPhrase {
		addField(f)
	}
	for f := range q.MatchPhrasePrefix {
		addField(f)
	}
	for f := range q.MatchBoolPrefix {
		addField(f)
	}
	for f := range q.Common {
		addField(f)
	}
	for f := range q.Range {
		addField(f)
	}
	for f := range q.Prefix {
		addField(f)
	}
	for f := range q.Wildcard {
		addField(f)
	}
	for f := range q.Regexp {
		addField(f)
	}
	for f := range q.Fuzzy {
		addField(f)
	}
	for f := range q.Intervals {
		addField(f)
	}
	if q.Exists != nil {
		addField(q.Exists.Field)
	}
	if q.MultiMatch != nil {
		if len(q.MultiMatch.Fields) == 0 {
			for rt := range rtCandidates {
				addField(rt)
			}
		} else {
			for _, f := range q.MultiMatch.Fields {
				if idx := strings.IndexByte(f, '^'); idx > 0 {
					f = f[:idx]
				}
				addField(f)
			}
		}
	}
	if q.QueryString != nil {
		if len(q.QueryString.Fields) > 0 {
			for _, f := range q.QueryString.Fields {
				if idx := strings.IndexByte(f, '^'); idx > 0 {
					f = f[:idx]
				}
				addField(f)
			}
		} else if q.QueryString.DefaultField != "" {
			addField(q.QueryString.DefaultField)
		} else {
			for rt := range rtCandidates {
				if strings.Contains(q.QueryString.Query, rt+":") || !strings.Contains(q.QueryString.Query, ":") {
					addField(rt)
				}
			}
		}
	}
	if q.SimpleQueryString != nil {
		if len(q.SimpleQueryString.Fields) > 0 {
			for _, f := range q.SimpleQueryString.Fields {
				if idx := strings.IndexByte(f, '^'); idx > 0 {
					f = f[:idx]
				}
				addField(f)
			}
		} else {
			for rt := range rtCandidates {
				addField(rt)
			}
		}
	}
	if q.GeoBoundingBox != nil {
		addField(q.GeoBoundingBox.Field)
	}
	if q.GeoDistance != nil {
		addField(q.GeoDistance.Field)
	}
	if q.GeoPolygon != nil {
		addField(q.GeoPolygon.Field)
	}
	if q.GeoShape != nil {
		addField(q.GeoShape.Field)
	}
	if q.DistanceFeature != nil {
		addField(q.DistanceFeature.Field)
	}
	if q.Script != nil && q.Script.Script != nil {
		src, _ := extractScriptSourceAndParams(q.Script.Script)
		for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
			addField(dep)
		}
	}
	if q.ScriptScore != nil {
		if q.ScriptScore.Script != nil {
			src, _ := extractScriptSourceAndParams(q.ScriptScore.Script)
			for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
				addField(dep)
			}
		}
		collectQueryFieldRefsR62Search(q.ScriptScore.Query, rtCandidates, addField)
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			src, _ := extractScriptSourceAndParams(q.FunctionScore.ScriptScore.Script)
			for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
				addField(dep)
			}
		}
		if q.FunctionScore.FieldValueFactor != nil {
			addField(q.FunctionScore.FieldValueFactor.Field)
		}
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			collectQueryFieldRefsR62Search(fn.Filter, rtCandidates, addField)
			if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
				src, _ := extractScriptSourceAndParams(fn.ScriptScore.Script)
				for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
					addField(dep)
				}
			}
			if fn.FieldValueFactor != nil {
				addField(fn.FieldValueFactor.Field)
			}
		}
		collectQueryFieldRefsR62Search(q.FunctionScore.Query, rtCandidates, addField)
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectQueryFieldRefsR62Search(&q.Bool.Must[i], rtCandidates, addField)
		}
		for i := range q.Bool.Filter {
			collectQueryFieldRefsR62Search(&q.Bool.Filter[i], rtCandidates, addField)
		}
		for i := range q.Bool.Should {
			collectQueryFieldRefsR62Search(&q.Bool.Should[i], rtCandidates, addField)
		}
		for i := range q.Bool.MustNot {
			collectQueryFieldRefsR62Search(&q.Bool.MustNot[i], rtCandidates, addField)
		}
	}
	if q.ConstantScore != nil {
		collectQueryFieldRefsR62Search(&q.ConstantScore.Filter, rtCandidates, addField)
	}
	if q.Boosting != nil {
		collectQueryFieldRefsR62Search(&q.Boosting.Positive, rtCandidates, addField)
		collectQueryFieldRefsR62Search(&q.Boosting.Negative, rtCandidates, addField)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectQueryFieldRefsR62Search(&q.DisMax.Queries[i], rtCandidates, addField)
		}
	}
	if q.Nested != nil {
		collectQueryFieldRefsR62Search(&q.Nested.Query, rtCandidates, addField)
		if q.Nested.InnerHits != nil {
			for _, fs := range q.Nested.InnerHits.Fields {
				addField(fs.Field)
			}
			for _, dv := range q.Nested.InnerHits.DocvalueFields {
				addField(dv.Field)
			}
			for _, s := range q.Nested.InnerHits.Sort {
				addField(s.Entry.Field)
			}
		}
	}
	if q.HasChild != nil {
		collectQueryFieldRefsR62Search(&q.HasChild.Query, rtCandidates, addField)
	}
	if q.HasParent != nil {
		collectQueryFieldRefsR62Search(&q.HasParent.Query, rtCandidates, addField)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		collectQueryFieldRefsR62Search(q.Wrapper.Decoded, rtCandidates, addField)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		collectQueryFieldRefsR62Search(q.Pinned.Organic, rtCandidates, addField)
	}
}

func collectAggFieldRefsR62Search(aggs map[string]esast.AggSpec, rtCandidates map[string]bool, addField func(string)) {
	addScript := func(raw any) {
		if raw == nil {
			return
		}
		src, _ := extractScriptSourceAndParams(raw)
		for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
			addField(dep)
		}
	}
	names := make([]string, 0, len(aggs))
	for k := range aggs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		spec := aggs[name]
		if t := spec.EffectiveTerms(); t != nil {
			addField(t.Field)
			addScript(t.Script)
		}
		if spec.RareTerms != nil {
			addField(spec.RareTerms.Field)
		}
		if spec.MultiTerms != nil {
			for _, mt := range spec.MultiTerms.Terms {
				addField(mt.Field)
				addScript(mt.Script)
			}
		}
		if spec.Histogram != nil {
			addField(spec.Histogram.Field)
			addScript(spec.Histogram.Script)
		}
		if spec.VariableWidthHistogram != nil {
			addField(spec.VariableWidthHistogram.Field)
		}
		if spec.DateHistogram != nil {
			addField(spec.DateHistogram.Field)
			addScript(spec.DateHistogram.Script)
		}
		if spec.AutoDateHistogram != nil {
			addField(spec.AutoDateHistogram.Field)
			addScript(spec.AutoDateHistogram.Script)
		}
		if r := spec.EffectiveRange(); r != nil {
			addField(r.Field)
			addScript(r.Script)
		}
		if spec.IPPrefix != nil {
			addField(spec.IPPrefix.Field)
		}
		if spec.Filter != nil {
			collectQueryFieldRefsR62Search(spec.Filter, rtCandidates, addField)
		}
		if spec.Filters != nil {
			for _, fq := range spec.Filters.Filters {
				qCopy := fq
				collectQueryFieldRefsR62Search(&qCopy, rtCandidates, addField)
			}
			for i := range spec.Filters.AnonymousFilters {
				collectQueryFieldRefsR62Search(&spec.Filters.AnonymousFilters[i], rtCandidates, addField)
			}
		}
		if spec.Missing != nil {
			addField(spec.Missing.Field)
		}
		if spec.Composite != nil {
			for _, srcMap := range spec.Composite.Sources {
				for _, cs := range srcMap {
					if cs.Terms != nil {
						addField(cs.Terms.Field)
						addScript(cs.Terms.Script)
					}
					if cs.Histogram != nil {
						addField(cs.Histogram.Field)
						addScript(cs.Histogram.Script)
					}
					if cs.DateHistogram != nil {
						addField(cs.DateHistogram.Field)
						addScript(cs.DateHistogram.Script)
					}
					if cs.GeotileGrid != nil {
						addField(cs.GeotileGrid.Field)
					}
				}
			}
		}
		for _, m := range []*esast.MetricAggSpec{
			spec.Avg, spec.Sum, spec.Min, spec.Max,
			spec.EffectiveStats(), spec.ValueCount, spec.Cardinality,
			spec.Boxplot, spec.MedianAbsoluteDeviation,
		} {
			if m != nil {
				addField(m.Field)
				addScript(m.Script)
			}
		}
		if spec.WeightedAvg != nil {
			addField(spec.WeightedAvg.Value.Field)
			addScript(spec.WeightedAvg.Value.Script)
			addField(spec.WeightedAvg.Weight.Field)
			addScript(spec.WeightedAvg.Weight.Script)
		}
		if spec.Percentiles != nil {
			addField(spec.Percentiles.Field)
			addScript(spec.Percentiles.Script)
		}
		if spec.PercentileRanks != nil {
			addField(spec.PercentileRanks.Field)
			addScript(spec.PercentileRanks.Script)
		}
		if spec.StringStats != nil {
			addField(spec.StringStats.Field)
			addScript(spec.StringStats.Script)
		}
		if spec.Rate != nil {
			addField(spec.Rate.Field)
			addScript(spec.Rate.Script)
		}
		if spec.GeoBounds != nil {
			addField(spec.GeoBounds.Field)
		}
		if spec.GeoCentroid != nil {
			addField(spec.GeoCentroid.Field)
		}
		if spec.GeoDistance != nil {
			addField(spec.GeoDistance.Field)
		}
		if spec.GeohashGrid != nil {
			addField(spec.GeohashGrid.Field)
		}
		if spec.GeotileGrid != nil {
			addField(spec.GeotileGrid.Field)
		}
		if spec.MatrixStats != nil {
			for _, f := range spec.MatrixStats.Fields {
				addField(f)
			}
		}
		if spec.TopHits != nil {
			for _, fs := range spec.TopHits.Fields {
				addField(fs.Field)
			}
			for _, dv := range spec.TopHits.DocvalueFields {
				addField(dv.Field)
			}
			for _, s := range spec.TopHits.Sort {
				addField(s.Entry.Field)
				if s.Entry.Field == "_script" {
					addScript(s.Entry.Script)
				}
			}
			for _, sf := range spec.TopHits.ScriptFields {
				addScript(sf)
			}
		}
		if spec.TopMetrics != nil {
			for _, m := range spec.TopMetrics.Metrics {
				addField(m.Field)
			}
			for _, s := range spec.TopMetrics.Sort {
				addField(s.Entry.Field)
			}
		}
		if spec.ScriptedMetric != nil {
			addScript(spec.ScriptedMetric.MapScript)
		}
		if sm := spec.EffectiveSampler(); sm != nil {
			addField(sm.Field)
			addScript(sm.Script)
		}
		if len(spec.SubAggs()) > 0 {
			collectAggFieldRefsR62Search(spec.SubAggs(), rtCandidates, addField)
		}
	}
}

func collectReferencedRuntimeRootFieldsR62Search(
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
	aliasFilter *esast.Query,
) []string {
	if req == nil {
		return nil
	}
	rtMap := effectiveRuntimeMappings(idxSchema, req.RuntimeMappings)
	if len(rtMap) == 0 {
		return nil
	}
	rtCandidates := make(map[string]bool, len(rtMap))
	rtNamesSorted := make([]string, 0, len(rtMap))
	for k := range rtMap {
		rtCandidates[k] = true
		rtNamesSorted = append(rtNamesSorted, k)
	}
	sort.Strings(rtNamesSorted)

	seen := make(map[string]bool)
	var roots []string
	recordRoot := func(rtName string) {
		if rtCandidates[rtName] && !seen[rtName] {
			seen[rtName] = true
			roots = append(roots, rtName)
		}
	}

	addFieldOrPattern := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if strings.ContainsAny(raw, "*?") {
			for _, rtName := range rtNamesSorted {
				if matchWildcardPattern(raw, rtName) {
					recordRoot(rtName)
					continue
				}
				prop := rtMap[rtName]
				if prop.IsCompositeRuntime() {
					for subName := range prop.Fields {
						if matchWildcardPattern(raw, rtName+"."+subName) {
							recordRoot(rtName)
							break
						}
					}
				}
			}
			return
		}
		if rtCandidates[raw] {
			recordRoot(raw)
			return
		}
		trimmed := strings.TrimSuffix(raw, ".keyword")
		if trimmed != raw && rtCandidates[trimmed] {
			recordRoot(trimmed)
			return
		}
		// Check composite runtime subfield `<rtName>.<subName>`
		for _, rtName := range rtNamesSorted {
			if strings.HasPrefix(raw, rtName+".") {
				prop := rtMap[rtName]
				if prop.IsCompositeRuntime() {
					sub := strings.TrimSuffix(strings.TrimPrefix(raw, rtName+"."), ".keyword")
					if _, ok := prop.Fields[sub]; ok {
						recordRoot(rtName)
						return
					}
				}
			}
		}
	}

	collectQueryFieldRefsR62Search(aliasFilter, rtCandidates, addFieldOrPattern)
	collectQueryFieldRefsR62Search(req.Query, rtCandidates, addFieldOrPattern)
	collectQueryFieldRefsR62Search(req.PostFilter, rtCandidates, addFieldOrPattern)
	for i := range req.KNN {
		for j := range req.KNN[i].Filter {
			collectQueryFieldRefsR62Search(&req.KNN[i].Filter[j], rtCandidates, addFieldOrPattern)
		}
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil {
			collectQueryFieldRefsR62Search(req.Rescore[i].Query.RescoreQuery, rtCandidates, addFieldOrPattern)
		}
	}
	collectAggFieldRefsR62Search(req.EffectiveAggs(), rtCandidates, addFieldOrPattern)
	for _, s := range req.Sort {
		if s.Entry.Field == "_script" && s.Entry.Script != nil {
			src, _ := extractScriptSourceAndParams(s.Entry.Script)
			for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
				recordRoot(dep)
			}
			continue
		}
		if s.Entry.Field == "_geo_distance" {
			if gm, ok := s.Entry.Script.(map[string]any); ok {
				for k := range gm {
					if k != "distance_type" && k != "mode" && k != "unit" && k != "validation_method" && k != "ignore_unmapped" && k != "order" {
						addFieldOrPattern(k)
					}
				}
			}
			continue
		}
		addFieldOrPattern(s.Entry.Field)
	}
	for _, fs := range req.Fields {
		addFieldOrPattern(fs.Field)
	}
	for _, dv := range req.DocvalueFields {
		addFieldOrPattern(dv.Field)
	}
	for _, sf := range req.ScriptFields {
		src, _ := extractScriptSourceAndParams(sf)
		for _, dep := range ExtractRuntimeScriptFieldDepsRound61(src, rtCandidates) {
			recordRoot(dep)
		}
	}
	if req.Collapse != nil && req.Collapse.Field != "" {
		addFieldOrPattern(req.Collapse.Field)
	}
	if req.Highlight != nil {
		for hf := range req.Highlight.Fields {
			addFieldOrPattern(hf)
		}
	}
	return roots
}

func augmentSchemaWithCompositeRuntimeR62Search(
	base *schema.IndexSchema,
	rtMap map[string]esast.FieldProperty,
) *schema.IndexSchema {
	if base == nil || len(rtMap) == 0 {
		return base
	}
	hasComposite := false
	for _, prop := range rtMap {
		if prop.IsCompositeRuntime() {
			hasComposite = true
			break
		}
	}
	if !hasComposite {
		return base
	}
	orderedSet := make(map[string]bool, len(base.OrderedFields))
	for _, ob := range base.OrderedFields {
		orderedSet[ob.ESFieldPath] = true
	}
	for fName, prop := range rtMap {
		if !prop.IsCompositeRuntime() {
			continue
		}
		subNames := make([]string, 0, len(prop.Fields))
		for sn := range prop.Fields {
			subNames = append(subNames, sn)
		}
		sort.Strings(subNames)
		for _, subName := range subNames {
			subProp := prop.Fields[subName]
			fullPath := fName + "." + subName
			subType := strings.ToLower(strings.TrimSpace(subProp.Type))
			if subType == "" {
				subType = "keyword"
			}
			dType := schema.DorisString
			switch subType {
			case "long", "integer", "short", "byte", "unsigned_long", "date", "date_nanos":
				dType = schema.DorisBigInt
			case "double", "float", "half_float", "scaled_float":
				dType = schema.DorisDouble
			case "boolean":
				dType = schema.DorisBoolean
			}
			binding := schema.FieldBinding{
				ESFieldPath:    fullPath,
				ESType:         subType,
				Format:         subProp.Format,
				Kind:           schema.StoragePromotedArray,
				ColumnName:     "f__" + schema.SanitizeDorisIdentifier(fullPath),
				DorisType:      dType,
				IsMultiValued:  true,
				FromRuntime:    true,
				FromScript:     prop.Script != nil,
				SourceJSONPath: []string{fullPath},
			}
			base.Fields[fullPath] = binding
			if !orderedSet[fullPath] {
				base.OrderedFields = append(base.OrderedFields, binding)
				orderedSet[fullPath] = true
			}
			if subType == "keyword" || subType == "text" {
				kwB := binding
				kwB.ESFieldPath = fullPath + ".keyword"
				kwB.ESType = "keyword"
				base.Fields[fullPath+".keyword"] = kwB
			}
		}
	}
	return base
}

func evalRuntimeMappingsOrderedOnDocR62Search(
	idxSchema *schema.IndexSchema,
	rtMap map[string]esast.FieldProperty,
	rtOrder []string,
	doc map[string]any,
	isES8 bool,
) (map[string]any, bool, string, error) {
	evalDoc, _, modified, scriptSrc, err := evalRuntimeMappingsOrderedOnDocWithOutR62Search(idxSchema, rtMap, rtOrder, doc, isES8)
	return evalDoc, modified, scriptSrc, err
}

func evalRuntimeMappingsOrderedOnDocWithOutR62Search(
	idxSchema *schema.IndexSchema,
	rtMap map[string]esast.FieldProperty,
	rtOrder []string,
	doc map[string]any,
	isES8 bool,
) (map[string]any, map[string]any, bool, string, error) {
	rtOut := make(map[string]any, len(rtOrder))
	evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8)
	if len(rtMap) == 0 || len(rtOrder) == 0 {
		return evalDoc, rtOut, false, "", nil
	}

	ftMap, _ := evalDoc["__field_types"].(map[string]string)
	if ftMap == nil {
		ftMap = make(map[string]string, len(rtMap))
		evalDoc["__field_types"] = ftMap
	}
	fmtMap, _ := evalDoc["__field_formats"].(map[string]string)
	if fmtMap == nil {
		fmtMap = make(map[string]string)
		evalDoc["__field_formats"] = fmtMap
	}
	strictSet, hasStrict := evalDoc["__strict_doc_fields"].(map[string]bool)

	for _, fName := range rtOrder {
		prop := rtMap[fName]
		esT := strings.ToLower(strings.TrimSpace(prop.Type))
		if esT == "" {
			esT = "keyword"
		}
		if prop.IsCompositeRuntime() {
			for subName, subProp := range prop.Fields {
				full := fName + "." + subName
				st := strings.ToLower(strings.TrimSpace(subProp.Type))
				if st == "" {
					st = "keyword"
				}
				ftMap[full] = st
				if strings.TrimSpace(subProp.Format) != "" {
					fmtMap[full] = strings.TrimSpace(subProp.Format)
				}
				if hasStrict && strictSet != nil {
					strictSet[full] = true
				}
			}
			continue
		}
		ftMap[fName] = esT
		if strings.TrimSpace(prop.Format) != "" {
			fmtMap[fName] = strings.TrimSpace(prop.Format)
		}
		if hasStrict && strictSet != nil {
			strictSet[fName] = true
		}
	}

	fieldsParam := buildStoredFieldsParamMapR62Search(idxSchema, doc)
	nowUTC := time.Now().UTC()
	modified := false

	for _, fName := range rtOrder {
		prop := rtMap[fName]
		esType := strings.ToLower(strings.TrimSpace(prop.Type))
		if esType == "" {
			esType = "keyword"
		}
		onErrContinue := strings.EqualFold(strings.TrimSpace(prop.OnScriptError), "continue")

		// Check if `<nestedRoot>.<subField>` targets a nested object array (`150_nested_runtime_fields.yml`, `20_long.yml:201`)
		if idxSchema != nil && len(idxSchema.NestedRoots) > 0 && strings.Contains(fName, ".") && !prop.IsCompositeRuntime() {
			var matchedNestedRoot, relSubField string
			parts := strings.Split(fName, ".")
			for k := len(parts) - 1; k >= 1; k-- {
				candRoot := strings.Join(parts[:k], ".")
				if idxSchema.NestedRoots[candRoot] != "" {
					matchedNestedRoot = candRoot
					relSubField = strings.Join(parts[k:], ".")
					break
				}
			}
			if matchedNestedRoot != "" && relSubField != "" {
				rootSegs := strings.Split(matchedNestedRoot, ".")
				cands := extractNestedElementsAtPath(doc, rootSegs)
				nestedSchema := deriveNestedEvalSchema(idxSchema, matchedNestedRoot)
				for _, cand := range cands {
					if cand.obj == nil {
						continue
					}
					elemDoc := buildSingleNestedElementDoc(rootSegs, cand.obj)
					elemEvalDoc := PrepareDocForRuntimeScriptRound61(nestedSchema, elemDoc, isES8)
					var rawNestedVals []any
					if prop.Script == nil {
						if esType == "geo_point" || esType == "point" {
							for _, pt := range extractGeoPointsAtPathR62Search(cand.obj, strings.Split(relSubField, ".")) {
								rawNestedVals = append(rawNestedVals, map[string]any{"lat": pt[1], "lon": pt[0]})
							}
						} else {
							rawNestedVals = collectScalarValuesAtPath(cand.obj, strings.Split(relSubField, "."))
							if len(rawNestedVals) == 0 {
								if sv, ok := cand.obj[relSubField]; ok && sv != nil {
									rawNestedVals = flattenAnyToSliceR61Search(sv)
								}
							}
						}
					} else {
						scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
						if strings.TrimSpace(scriptSrc) == "" {
							continue
						}
						p := make(map[string]any, len(scriptParams)+6)
						for pk, pv := range scriptParams {
							p[pk] = pv
						}
						p["_source"] = cand.obj
						p["__keep_boolean_dups"] = isES8
						p["__quantize_geo_point"] = true
						if strings.TrimSpace(prop.Format) != "" {
							p["__runtime_date_format"] = strings.TrimSpace(prop.Format)
						}
						if fieldsParam != nil {
							p["_fields"] = fieldsParam
						}
						elemFT, _ := elemEvalDoc["__field_types"].(map[string]string)
						if emitCtx, okCtx := runtimeFieldTypeToEmitContextRound60(esType); okCtx && strings.Contains(scriptSrc, "emit(") {
							emitted, errEmit := painless.EvalEmitContext(scriptSrc, emitCtx, elemEvalDoc, cand.obj, p, elemFT)
							if errEmit != nil {
								if onErrContinue {
									continue
								}
								return evalDoc, rtOut, modified, scriptSrc, errEmit
							}
							rawNestedVals = emitted
						} else {
							res, evalErr := painless.Eval(elemEvalDoc, scriptSrc, p)
							if evalErr != nil {
								if onErrContinue {
									continue
								}
								return evalDoc, rtOut, modified, scriptSrc, evalErr
							}
							if emitted, ok := p["__emitted_vals"].([]any); ok && len(emitted) > 0 {
								rawNestedVals = emitted
							} else if res != nil {
								rawNestedVals = flattenAnyToSliceR61Search(res)
							}
						}
					}
					coerced := coerceRuntimeValuesWithScriptFlagR62Search(esType, prop.Format, rawNestedVals, nowUTC, prop.Script != nil)
					if len(coerced) > 0 {
						var fv any = coerced
						if len(coerced) == 1 {
							fv = coerced[0]
						}
						setNestedMapPathR61Search(cand.obj, strings.Split(relSubField, "."), fv)
						prevNested := flattenAnyToSliceR61Search(rtOut[fName])
						rtOut[fName] = append(prevNested, coerced...)
						modified = true
					}
				}
				continue
			}
		}

		srcForScript := doc
		if idxSchema != nil && idxSchema.SyntheticSource && doc != nil {
			if synthMap := schema.ReconstructSyntheticSource(idxSchema, doc, nil); synthMap != nil {
				srcForScript = synthMap
			}
		}

		// Composite runtime field (`110_composite.yml`, `111_search_time_composite.yml`, `114_composite_errors.yml`)
		if prop.IsCompositeRuntime() {
			if prop.Script == nil {
				continue
			}
			scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
			if strings.TrimSpace(scriptSrc) == "" {
				continue
			}
			p := make(map[string]any, len(scriptParams)+6)
			for k, v := range scriptParams {
				p[k] = v
			}
			p["_source"] = srcForScript
			p["__keep_boolean_dups"] = isES8
			p["__quantize_geo_point"] = true
			if fieldsParam != nil {
				p["_fields"] = fieldsParam
			}
			emitted, errEmit := painless.EvalEmitContext(scriptSrc, "composite", evalDoc, srcForScript, p, ftMap)
			if errEmit != nil {
				if onErrContinue {
					continue
				}
				return evalDoc, rtOut, modified, scriptSrc, errEmit
			}
			mergedSubMap := painless.MergeCompositeEmittedMaps(emitted)
			for subName, subProp := range prop.Fields {
				rawSubVals := flattenAnyToSliceR61Search(mergedSubMap[subName])
				if len(rawSubVals) == 0 {
					continue
				}
				subType := strings.ToLower(strings.TrimSpace(subProp.Type))
				if subType == "" {
					subType = "keyword"
				}
				coerced := coerceRuntimeValuesWithScriptFlagR62Search(subType, subProp.Format, rawSubVals, nowUTC, true)
				if len(coerced) == 0 {
					continue
				}
				var finalSubVal any = coerced
				if len(coerced) == 1 {
					finalSubVal = coerced[0]
				}
				fullSub := fName + "." + subName
				if doc != nil {
					doc[fullSub] = finalSubVal
					setIngestPathIfNoScalarConflictR62Search(doc, fullSub, finalSubVal)
				}
				rtOut[fullSub] = finalSubVal
				evalDoc[fullSub] = finalSubVal
				setRuntimeScriptDocPath(evalDoc, strings.Split(fullSub, "."), finalSubVal)
				modified = true
			}
			continue
		}

		// Standard scalar / geo_point runtime field (scriptless or Painless `emit(...)`)
		var rawVals []any
		var activeScriptSrc string
		if prop.Script == nil {
			if doc != nil {
				if esType == "geo_point" || esType == "point" {
					var pts [][2]float64
					if v, ok := doc[fName]; ok && v != nil {
						pts = extractGeoPointsFromRawNodeR61Search(v)
					}
					if len(pts) == 0 {
						pts = extractGeoPointsAtPathR62Search(doc, strings.Split(fName, "."))
					}
					for _, pt := range pts {
						rawVals = append(rawVals, map[string]any{"lat": pt[1], "lon": pt[0]})
					}
				} else {
					if v, ok := doc[fName]; ok && v != nil {
						rawVals = flattenAnyToSliceR61Search(v)
					}
					if len(rawVals) == 0 {
						rawVals = collectScalarValuesAtPath(doc, strings.Split(fName, "."))
					}
				}
			}
			if len(rawVals) == 0 {
				continue
			}
		} else {
			scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
			activeScriptSrc = scriptSrc
			if strings.TrimSpace(scriptSrc) == "" {
				continue
			}
			p := make(map[string]any, len(scriptParams)+6)
			for k, v := range scriptParams {
				p[k] = v
			}
			p["_source"] = srcForScript
			p["__keep_boolean_dups"] = isES8
			p["__quantize_geo_point"] = true
			if strings.TrimSpace(prop.Format) != "" {
				p["__runtime_date_format"] = strings.TrimSpace(prop.Format)
			}
			if fieldsParam != nil {
				p["_fields"] = fieldsParam
			}

			if emitCtx, okCtx := runtimeFieldTypeToEmitContextRound60(prop.Type); okCtx && strings.Contains(scriptSrc, "emit(") {
				emitted, errEmit := painless.EvalEmitContext(scriptSrc, emitCtx, evalDoc, srcForScript, p, ftMap)
				if errEmit != nil {
					if onErrContinue {
						continue
					}
					return evalDoc, rtOut, modified, activeScriptSrc, errEmit
				}
				if len(emitted) > 0 {
					rawVals = emitted
				}
			} else {
				res, evalErr := painless.Eval(evalDoc, scriptSrc, p)
				if evalErr != nil {
					if onErrContinue {
						continue
					}
					return evalDoc, rtOut, modified, activeScriptSrc, evalErr
				}
				if emitted, ok := p["__emitted_vals"].([]any); ok && len(emitted) > 0 {
					rawVals = emitted
				} else if res != nil {
					if arr, ok := res.([]any); ok {
						rawVals = arr
					} else {
						rawVals = []any{res}
					}
				}
			}
		}
		if len(rawVals) == 0 {
			// When a scriptless runtime field shadows a _source field that fails coercion (or emits nothing),
			// ensure stale uncoerced _source values don't masquerade as valid runtime values if Script != nil.
			if prop.Script != nil && doc != nil {
				if _, had := doc[fName]; had {
					delete(doc, fName)
					modified = true
				}
			}
			continue
		}
		coercedVals := coerceRuntimeValuesWithScriptFlagR62Search(esType, prop.Format, rawVals, nowUTC, prop.Script != nil)
		if len(coercedVals) == 0 {
			if doc != nil {
				if _, had := doc[fName]; had {
					delete(doc, fName)
					modified = true
				}
			}
			continue
		}
		var finalVal any
		if len(coercedVals) == 1 {
			finalVal = coercedVals[0]
		} else {
			finalVal = coercedVals
		}
		if doc != nil {
			doc[fName] = finalVal
			if strings.Contains(fName, ".") {
				setIngestPathIfNoScalarConflictR62Search(doc, fName, finalVal)
			}
		}
		rtOut[fName] = finalVal
		evalDoc[fName] = finalVal
		if strings.Contains(fName, ".") {
			setRuntimeScriptDocPath(evalDoc, strings.Split(fName, "."), finalVal)
		}
		modified = true
	}
	return evalDoc, rtOut, modified, "", nil
}

func extractGeoPointsAtPathR62Search(node any, segs []string) [][2]float64 {
	if node == nil {
		return nil
	}
	if len(segs) == 0 {
		return extractGeoPointsFromRawNodeR61Search(node)
	}
	switch cur := node.(type) {
	case map[string]any:
		var out [][2]float64
		if next, ok := cur[segs[0]]; ok {
			out = append(out, extractGeoPointsAtPathR62Search(next, segs[1:])...)
		}
		for i := 2; i <= len(segs); i++ {
			if next, ok := cur[strings.Join(segs[:i], ".")]; ok {
				out = append(out, extractGeoPointsAtPathR62Search(next, segs[i:])...)
			}
		}
		return out
	case []any:
		var out [][2]float64
		for _, elem := range cur {
			out = append(out, extractGeoPointsAtPathR62Search(elem, segs)...)
		}
		return out
	}
	return nil
}

func setIngestPathIfNoScalarConflictR62Search(doc map[string]any, dottedPath string, val any) {
	if doc == nil || dottedPath == "" {
		return
	}
	segs := strings.Split(dottedPath, ".")
	if len(segs) <= 1 {
		doc[dottedPath] = val
		return
	}
	cur := doc
	for i := 0; i < len(segs)-1; i++ {
		seg := segs[i]
		existing, exists := cur[seg]
		if !exists || existing == nil {
			next := make(map[string]any)
			cur[seg] = next
			cur = next
			continue
		}
		nextMap, ok := existing.(map[string]any)
		if !ok {
			// Do not clobber an existing scalar or array field (e.g. `voltage: 5.2` when writing `voltage.rating`)!
			return
		}
		cur = nextMap
	}
	cur[segs[len(segs)-1]] = val
}

func evalRuntimeMappingsOnDocLazyForReqR62Search(
	idxSchema *schema.IndexSchema,
	reqMappings map[string]esast.FieldProperty,
	req *esast.SearchRequest,
	doc map[string]any,
	isES8 bool,
) (map[string]any, bool, error) {
	rtMap := effectiveRuntimeMappings(idxSchema, reqMappings)
	if len(rtMap) == 0 {
		return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8), false, nil
	}
	var roots []string
	if req != nil {
		roots = collectReferencedRuntimeRootFieldsR62Search(idxSchema, req, nil)
		if len(roots) == 0 {
			return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8), false, nil
		}
	} else {
		roots = make([]string, 0, len(rtMap))
		for k := range rtMap {
			roots = append(roots, k)
		}
		sort.Strings(roots)
	}
	rtOrder, err := resolveLazyRuntimeMappingsOrderR62Search(rtMap, roots)
	if err != nil {
		return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8), false, err
	}
	evalDoc, modified, _, rtErr := evalRuntimeMappingsOrderedOnDocR62Search(idxSchema, rtMap, rtOrder, doc, isES8)
	return evalDoc, modified, rtErr
}

// EvalRuntimeMappingsOnHitRowsLazyR62Search resolves ONLY the runtime fields referenced by `req`
// (or all runtime fields if `req == nil`) via lazy DFS (`90_loops.yml`), evaluates them on `hits`
// honoring `on_script_error: "continue" | "fail"` (`*_errors.yml`), and returns `(failedScriptSrc, err)`.
func (s *Server) EvalRuntimeMappingsOnHitRowsLazyR62Search(
	r *http.Request,
	idxSchema *schema.IndexSchema,
	reqMappings map[string]esast.FieldProperty,
	req *esast.SearchRequest,
	aliasFilter *esast.Query,
	hits []HitRow,
) (string, error) {
	rtMap := effectiveRuntimeMappings(idxSchema, reqMappings)
	if len(rtMap) == 0 {
		return "", nil
	}
	var roots []string
	if req != nil {
		roots = collectReferencedRuntimeRootFieldsR62Search(idxSchema, req, aliasFilter)
		if len(roots) == 0 {
			return "", nil
		}
	} else {
		roots = make([]string, 0, len(rtMap))
		for k := range rtMap {
			roots = append(roots, k)
		}
		sort.Strings(roots)
	}

	rtOrder, err := resolveLazyRuntimeMappingsOrderR62Search(rtMap, roots)
	if err != nil {
		return "", err
	}
	if len(hits) == 0 || len(rtOrder) == 0 {
		return "", nil
	}

	isES8 := s == nil || s.isES8Mode(r)
	for i := range hits {
		h := &hits[i]
		src := h.EffectiveSource()
		var doc map[string]any
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
		if doc == nil {
			doc = make(map[string]any)
		}
		doc["__meta_id"] = h.ID
		if h.Index != "" {
			doc["__meta_index"] = h.Index
		}
		if h.Version > 0 {
			doc["__meta_version"] = h.Version
		} else {
			doc["__meta_version"] = int64(1)
		}
		if h.HasSeqNo {
			doc["__meta_seq_no"] = h.SeqNo
		}
		effSch := idxSchema
		if h.Schema != nil {
			effSch = h.Schema
		}
		_, rtOut, modified, scriptSrc, rtErr := evalRuntimeMappingsOrderedOnDocWithOutR62Search(effSch, rtMap, rtOrder, doc, isES8)
		if rtErr != nil {
			return scriptSrc, rtErr
		}
		h.RuntimeFields = rtOut
		if modified {
			delete(doc, "__meta_id")
			delete(doc, "__meta_index")
			delete(doc, "__meta_version")
			delete(doc, "__meta_seq_no")
			delete(doc, "__meta_primary_term")
			if updatedBytes, mErr := json.Marshal(doc); mErr == nil {
				h.RawSource = updatedBytes
			}
		}
		h.Schema = effSch
	}
	return "", nil
}

// validateScriptedMetricAllowListR62Search enforces ES 8.15+ cluster settings:
//   - `search.aggs.only_allowed_metric_scripts`
//   - `search.aggs.allowed_inline_metric_scripts`
//   - `search.aggs.allowed_stored_metric_scripts`
//
// BEFORE `resolveStoredScriptsInSearchRequest` expands `{id: ...}` into `{source: ...}` (`scripted_metric_allow_list.yml`).
func validateScriptedMetricAllowListR62Search(s *Server, aggs map[string]esast.AggSpec) (int, string, string) {
	if s == nil || len(aggs) == 0 {
		return 0, "", ""
	}
	lookupClusterSetting := func(key string) (any, bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.clusterTransientSettings != nil {
			if v, ok := s.clusterTransientSettings[key]; ok && v != nil {
				return v, true
			}
		}
		if s.clusterPersistentSettings != nil {
			if v, ok := s.clusterPersistentSettings[key]; ok && v != nil {
				return v, true
			}
		}
		return nil, false
	}

	rawOnly, hasOnly := lookupClusterSetting("search.aggs.only_allowed_metric_scripts")
	if !hasOnly {
		return 0, "", ""
	}
	onlyAllowed, okB := parseOptionalBoolAny(rawOnly)
	if !okB || !onlyAllowed {
		return 0, "", ""
	}

	parseAllowedSet := func(key string) map[string]bool {
		out := make(map[string]bool)
		raw, ok := lookupClusterSetting(key)
		if !ok || raw == nil {
			return out
		}
		switch tv := raw.(type) {
		case []string:
			for _, item := range tv {
				out[item] = true
			}
		case []any:
			for _, item := range tv {
				out[fmt.Sprintf("%v", item)] = true
			}
		case string:
			if tv != "" {
				out[tv] = true
			}
		}
		return out
	}

	allowedInline := parseAllowedSet("search.aggs.allowed_inline_metric_scripts")
	allowedStored := parseAllowedSet("search.aggs.allowed_stored_metric_scripts")

	isScriptAllowed := func(rawScript any) bool {
		if rawScript == nil {
			return true
		}
		if id, hasID := extractStoredScriptIDRound61(rawScript); hasID {
			return allowedStored[id]
		}
		src, _ := extractScriptSourceAndParams(rawScript)
		return allowedInline[src]
	}

	var walk func(m map[string]esast.AggSpec) (int, string, string)
	walk = func(m map[string]esast.AggSpec) (int, string, string) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, aggName := range names {
			spec := m[aggName]
			if spec.ScriptedMetric != nil {
				for _, entry := range []struct {
					field string
					raw   any
				}{
					{"init_script", spec.ScriptedMetric.InitScript},
					{"map_script", spec.ScriptedMetric.MapScript},
					{"combine_script", spec.ScriptedMetric.CombineScript},
					{"reduce_script", spec.ScriptedMetric.ReduceScript},
				} {
					if entry.raw != nil && !isScriptAllowed(entry.raw) {
						return http.StatusBadRequest,
							"search_phase_execution_exception",
							fmt.Sprintf("all_shards_failed|illegal_argument_exception|[%s] contains not allowed script: [%s]", entry.field, aggName)
					}
				}
			}
			if sub := spec.SubAggs(); len(sub) > 0 {
				if st, et, er := walk(sub); st != 0 {
					return st, et, er
				}
			}
		}
		return 0, "", ""
	}
	return walk(aggs)
}

func compareTermsKeysSchemaAwareR62Search(a, b, esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "ip":
		addrA, errA := netip.ParseAddr(strings.TrimSpace(a))
		addrB, errB := netip.ParseAddr(strings.TrimSpace(b))
		if errA == nil && errB == nil {
			return addrA.Unmap().Compare(addrB.Unmap()) < 0
		}
	case "long", "integer", "short", "byte", "date", "date_nanos":
		ia, errA := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		ib, errB := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
		if errA == nil && errB == nil && ia != ib {
			return ia < ib
		}
	case "unsigned_long":
		ua, errA := strconv.ParseUint(strings.TrimSpace(a), 10, 64)
		ub, errB := strconv.ParseUint(strings.TrimSpace(b), 10, 64)
		if errA == nil && errB == nil && ua != ub {
			return ua < ub
		}
	case "double", "float", "half_float", "scaled_float":
		fa, okA := parseFiniteFloat(strings.TrimSpace(a))
		fb, okB := parseFiniteFloat(strings.TrimSpace(b))
		if okA && okB && fa != fb {
			return fa < fb
		}
	}
	return a < b
}

func formatRuntimeTermValueForExplainR62Search(val any, prop esast.FieldProperty) string {
	esT := strings.ToLower(strings.TrimSpace(prop.Type))
	switch esT {
	case "date":
		if ms, ok := parseEpochMillisExactR61Search(val, prop.Format); ok {
			return strconv.FormatInt(ms, 10)
		}
	case "double", "float", "half_float":
		if fv, ok := toFloat64(val); ok {
			return formatJavaDoubleRound60(fv)
		}
	case "long", "integer", "short", "byte":
		if iv, ok := parseExactInt64R61Search(val, true); ok {
			return strconv.FormatInt(iv, 10)
		}
	case "ip":
		if addr, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprintf("%v", val))); err == nil {
			return addr.Unmap().String()
		}
	case "boolean":
		if bv, ok := parseStrictESBoolR61Search(val); ok {
			if bv {
				return "true"
			}
			return "false"
		}
	}
	return fmt.Sprintf("%v", val)
}

func buildRuntimeTermExplainNodeR62Search(field string, val any, boost float64, prop esast.FieldProperty) map[string]any {
	if boost == 0 {
		boost = 1.0
	}
	valStr := formatRuntimeTermValueForExplainR62Search(val, prop)
	desc := field + ":" + valStr
	if boost != 1.0 {
		desc += "^" + formatJavaDoubleRound60(boost)
	}
	return map[string]any{
		"value":       boost,
		"description": desc,
		"details": []map[string]any{
			{
				"value":       boost,
				"description": "boost * runtime_field_score",
				"details": []map[string]any{
					{
						"value":       boost,
						"description": "boost",
						"details":     []map[string]any{},
					},
					{
						"value":       1.0,
						"description": "runtime_field_score is always 1",
						"details":     []map[string]any{},
					},
				},
			},
		},
	}
}

func buildSearchHitExplanationR62Search(
	hitIdx string,
	h HitRow,
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
) map[string]any {
	if req == nil || req.Query == nil {
		return map[string]any{
			"value":       h.Score,
			"description": "ConstantScore(*:*)^1.0",
			"details":     []map[string]any{},
		}
	}
	doc := decodeHitDocMapRound60(h)
	rtMap := effectiveRuntimeMappings(idxSchema, req.RuntimeMappings)

	var buildForQuery func(q *esast.Query, fallbackScore float64) map[string]any
	buildForQuery = func(q *esast.Query, fallbackScore float64) map[string]any {
		if q == nil {
			return map[string]any{
				"value":       fallbackScore,
				"description": "*:*",
				"details":     []map[string]any{},
			}
		}
		// 1. `script_score` (`110_script_score_boost.yml`)
		if q.ScriptScore != nil && q.ScriptScore.Script != nil {
			var subExp map[string]any
			if q.ScriptScore.Query != nil {
				subScore := scoreNonScriptClauseOnDoc(idxSchema, doc, q.ScriptScore.Query)
				subExp = buildForQuery(q.ScriptScore.Query, subScore)
			}
			src, params := extractScriptSourceAndParams(q.ScriptScore.Script)
			boost := 1.0
			if q.ScriptScore.Boost != nil {
				boost = *q.ScriptScore.Boost
			}
			unboosted := fallbackScore
			if boost != 0 && boost != 1.0 {
				unboosted = fallbackScore / boost
			}
			innerNode := BuildScriptScoreExplainNodeRound61(unboosted, src, params, subExp)
			if boost != 1.0 {
				return map[string]any{
					"value":       fallbackScore,
					"description": fmt.Sprintf("script score function, computed with script:\"%s\"", src),
					"details": []map[string]any{
						{
							"value":       boost,
							"description": "boost",
							"details":     []map[string]any{},
						},
						innerNode,
					},
				}
			}
			return innerNode
		}

		// 2. `script` filter/query (`10_keyword.yml` script explain)
		if q.Script != nil && q.Script.Script != nil {
			src, params := extractScriptSourceAndParams(q.Script.Script)
			boost := 1.0
			if q.Script.Boost != nil {
				boost = *q.Script.Boost
			}
			paramStr := "{}"
			if len(params) > 0 {
				keys := make([]string, 0, len(params))
				for k := range params {
					if !strings.HasPrefix(k, "__") && k != "_score" {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				if len(keys) > 0 {
					parts := make([]string, 0, len(keys))
					for _, k := range keys {
						parts = append(parts, fmt.Sprintf("%s=%v", k, params[k]))
					}
					paramStr = "{" + strings.Join(parts, ", ") + "}"
				}
			}
			return map[string]any{
				"value":       boost,
				"description": fmt.Sprintf("ScriptQuery(Script{type=inline, lang='painless', idOrCode='%s', options={}, params=%s})", src, paramStr),
				"details":     []map[string]any{},
			}
		}

		// 3. Single `term` or `match` on runtime field vs concrete BM25 field
		if len(q.Term) == 1 {
			for f, te := range q.Term {
				boost := 1.0
				if te.HasBoost || te.Boost != 0 {
					boost = te.Boost
				}
				if rtProp, isRT := rtMap[f]; isRT {
					return buildRuntimeTermExplainNodeR62Search(f, te.Value, boost, rtProp)
				}
				return map[string]any{
					"value":       fallbackScore,
					"description": formatTermWeightExplainDescriptionR61Search(f, fmt.Sprintf("%v", te.Value), 0),
					"details":     []map[string]any{},
				}
			}
		}
		if len(q.Match) == 1 {
			for f, me := range q.Match {
				boost := 1.0
				if me.HasBoost || me.Boost != 0 {
					boost = me.Boost
				}
				if rtProp, isRT := rtMap[f]; isRT {
					return buildRuntimeTermExplainNodeR62Search(f, me.Query, boost, rtProp)
				}
				return map[string]any{
					"value":       fallbackScore,
					"description": formatTermWeightExplainDescriptionR61Search(f, fmt.Sprintf("%v", me.Query), 0),
					"details":     []map[string]any{},
				}
			}
		}
		if f, termStr, okTM := extractSingleTermOrMatchForExplainR61Search(q); okTM {
			if rtProp, isRT := rtMap[f]; isRT {
				return buildRuntimeTermExplainNodeR62Search(f, termStr, fallbackScore, rtProp)
			}
			return map[string]any{
				"value":       fallbackScore,
				"description": formatTermWeightExplainDescriptionR61Search(f, termStr, 0),
				"details":     []map[string]any{},
			}
		}
		return map[string]any{
			"value":       fallbackScore,
			"description": "ConstantScore(*:*)",
			"details":     []map[string]any{},
		}
	}

	primaryExp := buildForQuery(req.Query, h.Score)
	if len(req.Rescore) > 0 {
		curExp := primaryExp
		for _, rs := range req.Rescore {
			if rs.Query == nil || rs.Query.RescoreQuery == nil {
				continue
			}
			qWeight := 1.0
			if rs.Query.QueryWeight != nil {
				qWeight = *rs.Query.QueryWeight
			}
			rWeight := 1.0
			if rs.Query.RescoreQueryWeight != nil {
				rWeight = *rs.Query.RescoreQueryWeight
			}
			mode := strings.ToLower(strings.TrimSpace(rs.Query.ScoreMode))
			if mode == "" {
				mode = "total"
			}
			rScore, matched := (*Server)(nil).evalHitRescoreQuery(h, rs.Query.RescoreQuery, idxSchema)
			primaryWeighted := map[string]any{
				"value":       toFloatOrDefaultR62Search(curExp["value"], h.Score) * qWeight,
				"description": "primaryWeight, product of:",
				"details": []map[string]any{
					curExp,
					{"value": qWeight, "description": "queryWeight", "details": []map[string]any{}},
				},
			}
			if !matched {
				curExp = primaryWeighted
				continue
			}
			rescoreSubExp := buildForQuery(rs.Query.RescoreQuery, rScore)
			secondaryWeighted := map[string]any{
				"value":       rScore * rWeight,
				"description": "rescoreWeight, product of:",
				"details": []map[string]any{
					rescoreSubExp,
					{"value": rWeight, "description": "rescoreQueryWeight", "details": []map[string]any{}},
				},
			}
			curExp = map[string]any{
				"value":       h.Score,
				"description": fmt.Sprintf("rescore(%s), result of:", mode),
				"details":     []map[string]any{primaryWeighted, secondaryWeighted},
			}
		}
		return curExp
	}
	return primaryExp
}

func toFloatOrDefaultR62Search(v any, def float64) float64 {
	if f, ok := toFloat64(v); ok {
		return f
	}
	return def
}

// effectiveTranspileOptsForIndexR62Search enriches `s.effectiveTranspileOptsR61CRUD(r)` with:
//   - `DisallowExpensiveQueries` (`search.allow_expensive_queries == false` in cluster or index settings)
//   - `AnalysisConfig` & `AnalysisOpts` (`pkg/analysis` per-index analyzers/normalizers + `_synonyms` resolver)
//   - `RuntimeMappings` (`effectiveRuntimeMappings(idxSchema, reqMappings)`)
//   - Dynamic cluster search limits (`search.max_buckets`, `indices.query.bool.max_clause_count`, etc.)
func (s *Server) effectiveTranspileOptsForIndexR62Search(
	r *http.Request,
	indexName string,
	idxSchema *schema.IndexSchema,
	reqMappings map[string]esast.FieldProperty,
) transpiler.TranspilerOptions {
	opts := s.effectiveTranspileOptsR61CRUD(r)
	opts.RuntimeMappings = effectiveRuntimeMappings(idxSchema, reqMappings)
	if s == nil {
		return opts
	}

	s.mu.RLock()
	var idxCustom map[string]any
	resolvedIdx := strings.TrimSpace(indexName)
	if commaIdx := strings.IndexByte(resolvedIdx, ','); commaIdx > 0 {
		resolvedIdx = strings.TrimSpace(resolvedIdx[:commaIdx])
	}
	if targets, ok := s.aliases[resolvedIdx]; ok && len(targets) > 0 {
		resolvedIdx = targets[0]
	}
	if resolvedIdx != "" && s.indexCustomSettings != nil {
		if cs := s.indexCustomSettings[resolvedIdx]; len(cs) > 0 {
			idxCustom = deepCloneDocMap(cs)
		}
	}
	lookupCluster := func(key string) (any, bool) {
		if v, ok := lookupNestedClusterSettingR62Admin(s.clusterTransientSettings, key); ok {
			return v, true
		}
		if v, ok := lookupNestedClusterSettingR62Admin(s.clusterPersistentSettings, key); ok {
			return v, true
		}
		return nil, false
	}
	if rawAllowExp, ok := lookupCluster("search.allow_expensive_queries"); ok {
		if b, okB := parseOptionalBoolAny(rawAllowExp); okB {
			opts.DisallowExpensiveQueries = !b
		}
	}
	if rawMaxBuckets, ok := lookupCluster("search.max_buckets"); ok {
		if iv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawMaxBuckets))); err == nil && iv > 0 {
			opts.MaxAggBuckets = iv
		}
	}
	s.mu.RUnlock()

	if idxCustom != nil {
		if rawV, ok := lookupRawIndexSettingPresenceR62Admin(idxCustom, "search.allow_expensive_queries"); ok && rawV != nil {
			if b, okB := parseOptionalBoolAny(rawV); okB {
				opts.DisallowExpensiveQueries = !b
			}
		}
		if rawV, ok := lookupRawIndexSettingPresenceR62Admin(idxCustom, "max_docvalue_fields_search"); ok && rawV != nil {
			if iv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawV))); err == nil && iv > 0 {
				opts.MaxDocvalueFieldsSearch = iv
			}
		}
		if rawV, ok := lookupRawIndexSettingPresenceR62Admin(idxCustom, "max_script_fields"); ok && rawV != nil {
			if iv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawV))); err == nil && iv > 0 {
				opts.MaxScriptFields = iv
			}
		}
		if rawV, ok := lookupRawIndexSettingPresenceR62Admin(idxCustom, "max_regex_length"); ok && rawV != nil {
			if iv, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", rawV))); err == nil && iv > 0 {
				opts.MaxRegexLength = iv
			}
		}
		if rawV, ok := lookupRawIndexSettingPresenceR62Admin(idxCustom, "search.synonyms_phrase_query"); ok && rawV != nil {
			if b, okB := parseOptionalBoolAny(rawV); okB && !b {
				opts.DisableSynonymsPhraseQuery = true
			}
		}
	}
	cfg, anOpts := s.buildIndexAnalysisConfigR62Admin(resolvedIdx)
	opts.AnalysisConfig = cfg
	opts.AnalysisOpts = anOpts
	return opts
}

func enrichSourceBytesWithMappedScriptsR62Search(idxSchema *schema.IndexSchema, rawSrc []byte) []byte {
	if idxSchema == nil || idxSchema.RawMapping == nil || !hasMappedPropertyScriptsR62Search(idxSchema.RawMapping.Properties) {
		return rawSrc
	}
	var doc map[string]any
	if len(rawSrc) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawSrc))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	computed := evalIndexTimeMappedFieldsForHitR62Search(idxSchema, doc)
	if len(computed) == 0 {
		return rawSrc
	}
	cp := deepCloneDocMap(doc)
	if cp == nil {
		cp = make(map[string]any)
	}
	for fn, vals := range computed {
		if len(vals) == 1 {
			setIngestPath(cp, fn, vals[0])
		} else if len(vals) > 1 {
			setIngestPath(cp, fn, vals)
		}
	}
	if b, err := json.Marshal(cp); err == nil {
		return b
	}
	return rawSrc
}

func (s *Server) handlePutMappingNormalizedR62Search(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Body != nil {
		bodyBytes, err := jsonReadAllBodyR62Search(r)
		if err == nil && len(bytes.TrimSpace(bodyBytes)) > 0 {
			var probe esast.MappingSpec
			if json.Unmarshal(bodyBytes, &probe) == nil {
				if vErr := validateMappedPropertyScriptsR62Search(&probe); vErr != nil {
					et, er := splitSchemaErrorPrefixR61CRUD(vErr, "illegal_argument_exception")
					writeESError(w, http.StatusBadRequest, et, er)
					return
				}
			}
		}
	}
	rec := httptest.NewRecorder()
	s.handlePutMappingR61CRUD(rec, r)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	respBytes := rec.Body.Bytes()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		s.mu.Lock()
		for _, sch := range s.indices {
			if sch != nil && sch.RawMapping != nil {
				normalizeMappingScriptsInPlaceR62Search(sch.RawMapping)
				registerKnownScriptedSchemaR62Search(sch)
			}
		}
		s.mu.Unlock()
	}
	for hk, hvs := range res.Header {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}
	w.WriteHeader(res.StatusCode)
	// #nosec G705 -- JSON response proxied from internal mapping handler with nosniff/JSON Content-Type
	_, _ = w.Write(respBytes)
}

func jsonReadAllBodyR62Search(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, err
	}
	data := buf.Bytes()
	r.Body = nopReadCloserBytesR62Search{Reader: bytes.NewReader(data)}
	return data, nil
}

type nopReadCloserBytesR62Search struct {
	*bytes.Reader
}

func (nopReadCloserBytesR62Search) Close() error { return nil }

// ============================================================================
// F11–F19: Aggregation Stitchers, Partitioning, AutoDateHistogram, Lookup & Profile
// ============================================================================

func buildIPPrefixAggObjectR62Search(
	indexName string,
	fullKey string,
	parentBucketKey string,
	spec *esast.IPPrefixAggSpec,
	subAggs map[string]esast.AggSpec,
	rows []AggRow,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) map[string]any {
	if spec == nil {
		return map[string]any{"buckets": []map[string]any{}}
	}
	var matchingRows []AggRow
	if parentBucketKey == "" {
		matchingRows = append(matchingRows, rows...)
	} else {
		for _, r := range rows {
			if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
				cp := r
				cp.BucketKey = childKey
				matchingRows = append(matchingRows, cp)
			}
		}
	}

	// Merge duplicate network keys (e.g. across multiple indices)
	mergedCounts := make(map[string]int64, len(matchingRows))
	var uniqueKeys []string
	for _, r := range matchingRows {
		if r.BucketKey == "" {
			continue
		}
		if _, exists := mergedCounts[r.BucketKey]; !exists {
			uniqueKeys = append(uniqueKeys, r.BucketKey)
		}
		mergedCounts[r.BucketKey] += r.effectiveCount()
	}

	minCnt := int64(spec.EffectiveMinDocCount())
	filteredKeys := make([]string, 0, len(uniqueKeys))
	for _, k := range uniqueKeys {
		if mergedCounts[k] >= minCnt {
			filteredKeys = append(filteredKeys, k)
		}
	}

	sort.SliceStable(filteredKeys, func(i, j int) bool {
		hi := transpiler.CanonicalIPPrefixSortHex(filteredKeys[i])
		hj := transpiler.CanonicalIPPrefixSortHex(filteredKeys[j])
		if hi != hj {
			return hi < hj
		}
		return filteredKeys[i] < filteredKeys[j]
	})

	var netmaskVal any
	if !spec.IsIPv6 {
		netmaskVal = transpiler.IPv4PrefixNetmask(spec.PrefixLength)
	}

	buckets := make([]map[string]any, 0, len(filteredKeys))
	for _, k := range filteredKeys {
		cnt := mergedCounts[k]
		bMap := map[string]any{
			"key":           k,
			"doc_count":     cnt,
			"is_ipv6":       spec.IsIPv6,
			"prefix_length": spec.PrefixLength,
			"netmask":       netmaskVal,
		}
		if len(subAggs) > 0 {
			childParentKey := k
			if parentBucketKey != "" {
				childParentKey = parentBucketKey + "\x1f" + k
			}
			attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, childParentKey, subAggs, bucketsByAgg, docLookup, idxSchema)
			evaluateSiblingPipelineAggs(subAggs, bMap)
		}
		buckets = append(buckets, bMap)
	}
	if len(subAggs) > 0 {
		buckets = evaluateChildPipelineAggs(buckets, subAggs)
	}
	return formatKeyedBuckets(buckets, spec.EffectiveKeyed(), "key")
}

func emitRuntimeIPPrefixAggRowsR62Search(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	spec := aggSpec.IPPrefix
	if spec == nil {
		return
	}
	appendLen := spec.EffectiveAppendPrefixLength()
	byBucket := make(map[string][]runtimeMatchedDoc)
	var keys []string
	clean := strings.TrimSuffix(strings.TrimSuffix(spec.Field, ".keyword"), ".ngram")
	for _, md := range docs {
		effSchema := md.EffectiveSchema(idxSchema)
		pathSegs := strings.Split(clean, ".")
		if effSchema != nil {
			if b := effSchema.ResolveField(spec.Field); len(b.SourceJSONPath) > 0 {
				pathSegs = b.SourceJSONPath
			}
		}
		seen := make(map[string]bool)
		for _, rv := range collectSchemaAwareScalarValues(md.doc, spec.Field, pathSegs, effSchema) {
			bk, ok := transpiler.FormatIPPrefixBucketKey(fmt.Sprintf("%v", rv), spec.PrefixLength, spec.IsIPv6, appendLen)
			if !ok || seen[bk] {
				continue
			}
			seen[bk] = true
			if _, exists := byBucket[bk]; !exists {
				keys = append(keys, bk)
			}
			byBucket[bk] = append(byBucket[bk], md)
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return transpiler.CanonicalIPPrefixSortHex(keys[i]) < transpiler.CanonicalIPPrefixSortHex(keys[j])
	})
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func canonicalTSKeyStringR62Search(keyMap map[string]any) string {
	if len(keyMap) == 0 {
		return "{}"
	}
	ks := make([]string, 0, len(keyMap))
	for k := range keyMap {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var sb strings.Builder
	for i, k := range ks {
		if i > 0 {
			sb.WriteByte('\x00')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		fmt.Fprintf(&sb, "%v", keyMap[k])
	}
	return sb.String()
}

func buildTimeSeriesAggObjectR62Search(
	indexName string,
	fullKey string,
	parentBucketKey string,
	spec *esast.TimeSeriesAggSpec,
	subAggs map[string]esast.AggSpec,
	rows []AggRow,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) map[string]any {
	if spec == nil {
		return map[string]any{"buckets": map[string]any{}}
	}
	type tsGroup struct {
		tsid       string
		rawSortHex string
		canonKey   string
		keyMap     map[string]any
		docCount   int64
		rawKeys    []string
	}
	byCanon := make(map[string]*tsGroup)
	var order []*tsGroup

	for _, r := range rows {
		childKey := r.BucketKey
		if parentBucketKey != "" {
			ck, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey)
			if !ok {
				continue
			}
			childKey = ck
		}
		if childKey == "" {
			continue
		}
		tsid, keyMap := transpiler.ParseTimeSeriesBucketKey(childKey)
		ckStr := canonicalTSKeyStringR62Search(keyMap)
		if ckStr == "{}" && tsid != "" {
			ckStr = "tsid:" + tsid
		}
		g, exists := byCanon[ckStr]
		if !exists {
			if tsid == "" {
				tsid = ckStr
			}
			g = &tsGroup{
				tsid:       tsid,
				rawSortHex: transpiler.DecodeTSIDRawHex(tsid),
				canonKey:   ckStr,
				keyMap:     keyMap,
			}
			byCanon[ckStr] = g
			order = append(order, g)
		}
		g.docCount += r.effectiveCount()
		g.rawKeys = append(g.rawKeys, childKey)
	}

	// Stage 1: Shard collection order is binary `_tsid` (including 4-byte routing hash prefix), capped at `size`.
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].rawSortHex != order[j].rawSortHex {
			return order[i].rawSortHex < order[j].rawSortHex
		}
		return order[i].canonKey < order[j].canonKey
	})
	limit := spec.EffectiveSize()
	if limit > 0 && len(order) > limit {
		order = order[:limit]
	}

	// Stage 2: Reduction sorts surviving series by canonical dimension key order (`bar`, `baz`, `foo`).
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].canonKey != order[j].canonKey {
			return order[i].canonKey < order[j].canonKey
		}
		return order[i].tsid < order[j].tsid
	})

	buckets := make([]map[string]any, 0, len(order))
	tsidForIdx := make([]string, 0, len(order))
	for _, g := range order {
		km := g.keyMap
		if km == nil {
			km = map[string]any{}
		}
		bMap := map[string]any{
			"key":       km,
			"doc_count": g.docCount,
		}
		if len(subAggs) > 0 && len(g.rawKeys) > 0 {
			childParentKey := g.rawKeys[0]
			if parentBucketKey != "" {
				childParentKey = parentBucketKey + "\x1f" + g.rawKeys[0]
			}
			attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, childParentKey, subAggs, bucketsByAgg, docLookup, idxSchema)
			evaluateSiblingPipelineAggs(subAggs, bMap)
		}
		buckets = append(buckets, bMap)
		tsidForIdx = append(tsidForIdx, g.tsid)
	}
	if len(subAggs) > 0 {
		buckets = evaluateChildPipelineAggs(buckets, subAggs)
	}
	if spec.EffectiveKeyed() {
		keyedMap := make(map[string]any, len(buckets))
		for i, bMap := range buckets {
			tk := fmt.Sprintf("ts_%d", i)
			if i < len(tsidForIdx) && tsidForIdx[i] != "" {
				tk = tsidForIdx[i]
			}
			keyedMap[tk] = bMap
		}
		return map[string]any{"buckets": keyedMap}
	}
	return map[string]any{"buckets": buckets}
}

// applyIPRangeCIDRMaskR62Search computes Elasticsearch `ip_range` CIDR `from` (inclusive masked start IP)
// and `to` (exclusive `lastIP + 1`, or omitted if `lastIP` is all-ones max IPv4/IPv6) for both IPv4 and IPv6!
func applyIPRangeCIDRMaskR62Search(maskStr string, entry map[string]any) (startAddr netip.Addr, endAddrInclusive netip.Addr, ok bool) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(maskStr))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	masked := pfx.Masked()
	addr := masked.Addr()
	bits := pfx.Bits()

	strictConformance := false
	if srv := currentActiveSearchServerR62Search(); srv != nil && srv.hasExplicitTargetESVersion() {
		strictConformance = true
	}

	if addr.Is4() {
		b4 := addr.As4()
		v := binary.BigEndian.Uint32(b4[:])
		var hostMask uint32
		if bits < 32 {
			hostMask = (uint32(1) << (32 - bits)) - 1
		}
		lastV := v | hostMask
		var endB4 [4]byte
		binary.BigEndian.PutUint32(endB4[:], lastV)
		endInclusive := netip.AddrFrom4(endB4)
		entry["from"] = addr.String()
		if !strictConformance {
			entry["to"] = endInclusive.String()
		} else if lastV < math.MaxUint32 {
			var exclB4 [4]byte
			binary.BigEndian.PutUint32(exclB4[:], lastV+1)
			entry["to"] = netip.AddrFrom4(exclB4).String()
		}
		return addr, endInclusive, true
	}

	b16 := addr.As16()
	startInt := new(big.Int).SetBytes(b16[:])
	hostBits := 128 - bits
	endInt := new(big.Int).Set(startInt)
	if hostBits > 0 {
		maskInt := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(hostBits)), big.NewInt(1))
		endInt.Or(endInt, maskInt)
	}
	var endB16 [16]byte
	endInt.FillBytes(endB16[:])
	endInclusive := netip.AddrFrom16(endB16)

	entry["from"] = addr.String()
	maxIPv6 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	if !strictConformance {
		entry["to"] = endInclusive.String()
	} else if endInt.Cmp(maxIPv6) < 0 {
		exclInt := new(big.Int).Add(endInt, big.NewInt(1))
		var exclB16 [16]byte
		exclInt.FillBytes(exclB16[:])
		entry["to"] = netip.AddrFrom16(exclB16).String()
	}
	return addr, endInclusive, true
}

func ipAddrTo16BytesR62Search(raw string) ([16]byte, bool) {
	var out [16]byte
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return out, false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return out, false
	}
	copy(out[:], ip16)
	return out, true
}

func ipInCIDRMaskOrBoundsR62Search(rawIP string, rng esast.RangeAggBucket) bool {
	cand, ok := ipAddrTo16BytesR62Search(rawIP)
	if !ok {
		return false
	}
	if strings.TrimSpace(rng.Mask) != "" {
		dummy := make(map[string]any, 2)
		startA, endInclA, okM := applyIPRangeCIDRMaskR62Search(rng.Mask, dummy)
		if !okM {
			return false
		}
		lo, _ := ipAddrTo16BytesR62Search(startA.String())
		hi, _ := ipAddrTo16BytesR62Search(endInclA.String())
		return bytes.Compare(cand[:], lo[:]) >= 0 && bytes.Compare(cand[:], hi[:]) <= 0
	}
	if s, okF := rng.From.(string); okF && strings.TrimSpace(s) != "" {
		if lo, okL := ipAddrTo16BytesR62Search(s); okL {
			if bytes.Compare(cand[:], lo[:]) < 0 {
				return false
			}
		}
	}
	if s, okT := rng.To.(string); okT && strings.TrimSpace(s) != "" {
		if hi, okH := ipAddrTo16BytesR62Search(s); okH {
			if bytes.Compare(cand[:], hi[:]) >= 0 {
				return false
			}
		}
	}
	return true
}

// murmurHash3X8632R62Search implements Apache Lucene `StringHelper.murmurhash3_x86_32(byte[], 0, len, seed)`.
func murmurHash3X8632R62Search(data []byte, seed uint32) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	h1 := seed
	roundedEnd := len(data) & ^0x3
	for i := 0; i < roundedEnd; i += 4 {
		k1 := binary.LittleEndian.Uint32(data[i : i+4])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	var k1 uint32
	switch len(data) & 0x03 {
	case 3:
		k1 = uint32(data[roundedEnd+2]) << 16
		fallthrough
	case 2:
		k1 |= uint32(data[roundedEnd+1]) << 8
		fallthrough
	case 1:
		k1 |= uint32(data[roundedEnd])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data)) // #nosec G115 -- intentional 32-bit MurmurHash3 length mix matching Lucene StringHelper
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1) // #nosec G115 -- intentional signed 32-bit two's-complement hash matching Java int
}

// bitMixerMix64R62Search implements CarrotSearch HPPC `BitMixer.mix64(long)` used by ES `IncludeExclude`.
func bitMixerMix64R62Search(z int64) int64 {
	u := uint64(z) // #nosec G115 -- intentional two's-complement bit reinterpretation matching HPPC BitMixer.mix64
	u = (u ^ (u >> 32)) * 0x4cd6944c5cc20b6d
	u = (u ^ (u >> 29)) * 0xfc12c5b19d3259e9
	u = u ^ (u >> 32)
	return int64(u) // #nosec G115 -- intentional signed 64-bit two's-complement return matching Java long
}

// bitMixerMix32R62Search implements CarrotSearch HPPC `BitMixer.mix32(int)` used by ES `IncludeExclude`.
func bitMixerMix32R62Search(k int32) int32 {
	u := uint32(k) // #nosec G115 -- intentional two's-complement bit reinterpretation matching HPPC BitMixer.mix32
	u = (u ^ (u >> 16)) * 0x85ebca6b
	u = (u ^ (u >> 13)) * 0xc2b2ae35
	u = u ^ (u >> 16)
	return int32(u) // #nosec G115 -- intentional signed 32-bit two's-complement return matching Java int
}

func javaFloorMod64R62Search(x, y int64) int64 {
	if y <= 0 {
		return 0
	}
	r := x % y
	if r < 0 {
		r += y
	}
	return r
}

// matchesTermsPartitionR62Search implements Elasticsearch `IncludeExclude` partition routing
// across numeric (HPPC `BitMixer.mix64`) and string (Lucene `murmurhash3_x86_32` + `BitMixer.mix32`) terms.
func matchesTermsPartitionR62Search(key string, fv map[string]any, fieldType string) bool {
	numPart, okNP := toInt64(fv["num_partitions"])
	part, okP := toInt64(fv["partition"])
	if !okNP || !okP || numPart <= 0 || part < 0 || part >= numPart {
		return false
	}
	var seed int64
	if rawSeed, hasS := fv["seed"]; hasS && rawSeed != nil {
		seed, _ = toInt64(rawSeed)
	}
	ft := strings.ToLower(strings.TrimSpace(fieldType))
	switch ft {
	case "long", "integer", "short", "byte", "date", "date_nanos", "unsigned_long":
		if iv, err := strconv.ParseInt(strings.TrimSpace(key), 10, 64); err == nil {
			h := bitMixerMix64R62Search(iv + seed)
			return javaFloorMod64R62Search(h, numPart) == part
		}
	case "double", "float", "half_float", "scaled_float":
		if fvNum, okF := parseFiniteFloat(strings.TrimSpace(key)); okF {
			bits := int64(math.Float64bits(fvNum)) // #nosec G115 -- intentional IEEE-754 doubleToRawLongBits reinterpretation
			h := bitMixerMix64R62Search(bits + seed)
			return javaFloorMod64R62Search(h, numPart) == part
		}
	}
	seedU32 := uint32(uint64(seed) & 0xffffffff) // #nosec G115 -- intentional low-32-bit Java `(int) seed` narrowing
	mh := murmurHash3X8632R62Search([]byte(key), seedU32)
	mixed := bitMixerMix32R62Search(mh)
	return javaFloorMod64R62Search(int64(mixed), numPart) == part
}

func matchesTermsFilterPrecompiledWithSchemaR62Search(key string, filter any, precompiled *regexp.Regexp, fieldType string) bool {
	if fv, isMap := filter.(map[string]any); isMap {
		return matchesTermsPartitionR62Search(key, fv, fieldType)
	}
	return matchesTermsFilterPrecompiledWithSchemaRound60(key, filter, precompiled, fieldType)
}

// formatHistogramKeyWithPatternR62Search formats a numeric `histogram` bucket key according to
// Java `DecimalFormat` patterns including literal prefixes/suffixes (e.g. `"Value is ##0.0"` -> `"Value is 50.0"`).
func formatHistogramKeyWithPatternR62Search(val float64, pattern string) string {
	if pattern == "" {
		return strconv.FormatFloat(val, 'f', -1, 64)
	}
	firstPat := -1
	lastPat := -1
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '0' || ch == '#' || ch == '.' || ch == ',' {
			if firstPat < 0 {
				firstPat = i
			}
			lastPat = i
		}
	}
	if firstPat < 0 {
		return pattern
	}
	prefix := strings.ReplaceAll(pattern[:firstPat], "'", "")
	core := pattern[firstPat : lastPat+1]
	suffix := strings.ReplaceAll(pattern[lastPat+1:], "'", "")
	return prefix + formatTermsNumericPattern(val, core) + suffix
}

func sortHistogramBucketsR62Search(buckets []map[string]any, order any) []map[string]any {
	if order == nil || len(buckets) <= 1 {
		return buckets
	}
	normalizeOrder := func(raw any) any {
		switch v := raw.(type) {
		case map[string]any:
			cp := make(map[string]any, len(v))
			for k, val := range v {
				if k == "_time" {
					cp["_key"] = val
				} else {
					cp[k] = val
				}
			}
			return cp
		case []any:
			out := make([]any, len(v))
			for i, el := range v {
				if m, ok := el.(map[string]any); ok {
					cp := make(map[string]any, len(m))
					for k, val := range m {
						if k == "_time" {
							cp["_key"] = val
						} else {
							cp[k] = val
						}
					}
					out[i] = cp
				} else {
					out[i] = el
				}
			}
			return out
		}
		return raw
	}
	return sortHistogramBuckets(buckets, normalizeOrder(order))
}

type autoDateIntervalR62Search struct {
	fixedMs        int64
	calDaysInMonth int
	calMonth       int
	calYear        int
	label          string
}

var autoDateCandidatesR62Search = []autoDateIntervalR62Search{
	{fixedMs: 1000, label: "1s"},
	{fixedMs: 5000, label: "5s"},
	{fixedMs: 10000, label: "10s"},
	{fixedMs: 30000, label: "30s"},
	{fixedMs: 60000, label: "1m"},
	{fixedMs: 300000, label: "5m"},
	{fixedMs: 600000, label: "10m"},
	{fixedMs: 1800000, label: "30m"},
	{fixedMs: 3600000, label: "1h"},
	{fixedMs: 10800000, label: "3h"},
	{fixedMs: 43200000, label: "12h"},
	{fixedMs: 86400000, label: "1d"},
	{calDaysInMonth: 7, label: "7d"},
	{calMonth: 1, label: "1M"},
	{calMonth: 3, label: "3M"},
	{calYear: 1, label: "1y"},
	{calYear: 5, label: "5y"},
	{calYear: 10, label: "10y"},
	{calYear: 20, label: "20y"},
	{calYear: 50, label: "50y"},
	{calYear: 100, label: "100y"},
}

func resolveAutoDateTimeZoneLocR62Search(tzRaw string) *time.Location {
	tzRaw = strings.TrimSpace(tzRaw)
	if tzRaw == "" || tzRaw == "Z" || strings.EqualFold(tzRaw, "UTC") {
		return time.UTC
	}
	if loc, _, _, err := esast.ParseESTimeZone(tzRaw); err == nil && loc != nil {
		return loc
	}
	return time.UTC
}

func floorAutoDateCandMillisR62Search(epochMs int64, cand autoDateIntervalR62Search, loc *time.Location) int64 {
	if loc == nil {
		loc = time.UTC
	}
	if cand.calYear > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		y := t.Year()
		if cand.calYear > 1 {
			rem := y % cand.calYear
			if rem < 0 {
				rem += cand.calYear
			}
			y -= rem
		}
		return time.Date(y, time.January, 1, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.calMonth > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		m0 := int(t.Month()) - 1
		mFloor := (m0 / cand.calMonth) * cand.calMonth
		return time.Date(t.Year(), time.Month(mFloor+1), 1, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.calDaysInMonth > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		dFloor := ((t.Day()-1)/cand.calDaysInMonth)*cand.calDaysInMonth + 1
		return time.Date(t.Year(), t.Month(), dFloor, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.fixedMs >= 86400000 && loc != time.UTC {
		_, offSec := time.UnixMilli(epochMs).In(loc).Zone()
		offMs := int64(offSec) * 1000
		shifted := epochMs + offMs
		b := int64(math.Floor(float64(shifted)/float64(cand.fixedMs))) * cand.fixedMs
		return b - offMs
	}
	if cand.fixedMs <= 0 {
		return epochMs
	}
	return int64(math.Floor(float64(epochMs)/float64(cand.fixedMs))) * cand.fixedMs
}

func stepAutoDateCandMillisR62Search(epochMs int64, cand autoDateIntervalR62Search, loc *time.Location) int64 {
	if loc == nil {
		loc = time.UTC
	}
	if cand.calYear > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		return time.Date(t.Year()+cand.calYear, time.January, 1, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.calMonth > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		return time.Date(t.Year(), t.Month()+time.Month(cand.calMonth), 1, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.calDaysInMonth > 0 {
		t := time.UnixMilli(epochMs).In(loc)
		lastDayOfMonth := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, loc).Day()
		nextDay := t.Day() + cand.calDaysInMonth
		if nextDay <= lastDayOfMonth {
			return time.Date(t.Year(), t.Month(), nextDay, 0, 0, 0, 0, loc).UnixMilli()
		}
		return time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc).UnixMilli()
	}
	if cand.fixedMs <= 0 {
		return epochMs + 1000
	}
	return epochMs + cand.fixedMs
}

func countAutoDateCandBucketsR62Search(minTS, maxTS int64, cand autoDateIntervalR62Search, loc *time.Location) int64 {
	firstB := floorAutoDateCandMillisR62Search(minTS, cand, loc)
	lastB := floorAutoDateCandMillisR62Search(maxTS, cand, loc)
	if lastB <= firstB {
		return 1
	}
	if cand.fixedMs > 0 {
		return (lastB-firstB)/cand.fixedMs + 1
	}
	t1 := time.UnixMilli(firstB).In(loc)
	t2 := time.UnixMilli(lastB).In(loc)
	if cand.calYear > 0 {
		return int64((t2.Year()-t1.Year())/cand.calYear) + 1
	}
	if cand.calDaysInMonth > 0 {
		months := (t2.Year()-t1.Year())*12 + int(t2.Month()-t1.Month())
		if months > 240 {
			return int64(months)*5 + 1
		}
		cnt := int64(1)
		for cur := firstB; cur < lastB; {
			nxt := stepAutoDateCandMillisR62Search(cur, cand, loc)
			if nxt <= cur {
				break
			}
			cnt++
			cur = nxt
		}
		return cnt
	}
	months := (t2.Year()-t1.Year())*12 + int(t2.Month()-t1.Month())
	return int64(months/cand.calMonth) + 1
}

func selectAutoDateCandR62Search(minTS, maxTS int64, targetBuckets int, minInterval string, loc *time.Location) autoDateIntervalR62Search {
	if targetBuckets <= 0 {
		targetBuckets = 10
	}
	minIdx := 0
	if trimmed := strings.TrimSpace(minInterval); trimmed != "" {
		switch trimmed {
		case "year", "1y":
			trimmed = "1y"
		case "month", "1M":
			trimmed = "1M"
		case "day", "1d":
			trimmed = "1d"
		case "hour", "1h":
			trimmed = "1h"
		case "minute", "1m":
			trimmed = "1m"
		case "second", "1s":
			trimmed = "1s"
		}
		for i, c := range autoDateCandidatesR62Search {
			if c.label == trimmed {
				minIdx = i
				break
			}
		}
	}
	if maxTS <= minTS {
		return autoDateCandidatesR62Search[minIdx]
	}
	for i := minIdx; i < len(autoDateCandidatesR62Search); i++ {
		c := autoDateCandidatesR62Search[i]
		if countAutoDateCandBucketsR62Search(minTS, maxTS, c, loc) <= int64(targetBuckets) {
			return c
		}
	}
	return autoDateCandidatesR62Search[len(autoDateCandidatesR62Search)-1]
}

func selectAutoDateHistogramIntervalR62Search(minTS, maxTS int64, targetBuckets int, minInterval, timeZone string) (int64, string) {
	loc := resolveAutoDateTimeZoneLocR62Search(timeZone)
	cand := selectAutoDateCandR62Search(minTS, maxTS, targetBuckets, minInterval, loc)
	approxMs := cand.fixedMs
	if cand.calDaysInMonth > 0 {
		approxMs = int64(cand.calDaysInMonth) * 86400 * 1000
	} else if cand.calMonth > 0 {
		approxMs = int64(cand.calMonth) * 30 * 86400 * 1000
	} else if cand.calYear > 0 {
		approxMs = int64(cand.calYear) * 365 * 86400 * 1000
	}
	return approxMs, cand.label
}

func emitRuntimeAutoDateHistogramAggRowsR62Search(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	adh := aggSpec.AutoDateHistogram
	if adh == nil {
		return
	}
	targetBuckets := adh.EffectiveBuckets()
	loc := resolveAutoDateTimeZoneLocR62Search(adh.TimeZone)
	nowUTC := time.Now().UTC()
	var minTS, maxTS int64
	hasTS := false
	type docTS struct {
		md     runtimeMatchedDoc
		tsList []int64
	}
	var allDocTS []docTS
	for _, md := range docs {
		tsList := extractDocDateMillisForBucket(idxSchema, md, adh.Field, adh.Missing, adh.Script, nowUTC)
		if len(tsList) == 0 {
			continue
		}
		allDocTS = append(allDocTS, docTS{md: md, tsList: tsList})
		for _, ts := range tsList {
			if !hasTS || ts < minTS {
				minTS = ts
			}
			if !hasTS || ts > maxTS {
				maxTS = ts
			}
			hasTS = true
		}
	}
	if !hasTS {
		return
	}
	cand := selectAutoDateCandR62Search(minTS, maxTS, targetBuckets, adh.MinimumInterval, loc)
	byBucket := make(map[string][]runtimeMatchedDoc)
	bucketTS := make(map[string]int64)
	for _, d := range allDocTS {
		seenDocB := make(map[string]bool, len(d.tsList))
		for _, ts := range d.tsList {
			b := floorAutoDateCandMillisR62Search(ts, cand, loc)
			k := strconv.FormatInt(b, 10)
			if !seenDocB[k] {
				seenDocB[k] = true
				bucketTS[k] = b
				byBucket[k] = append(byBucket[k], d.md)
			}
		}
	}
	keys := make([]string, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bucketTS[keys[i]] < bucketTS[keys[j]]
	})
	if len(keys) >= 2 {
		firstTS := bucketTS[keys[0]]
		lastTS := bucketTS[keys[len(keys)-1]]
		if countAutoDateCandBucketsR62Search(firstTS, lastTS, cand, loc) <= 10000 {
			for b := stepAutoDateCandMillisR62Search(firstTS, cand, loc); b < lastTS; {
				k := strconv.FormatInt(b, 10)
				if _, exists := byBucket[k]; !exists {
					byBucket[k] = nil
					bucketTS[k] = b
					keys = append(keys, k)
				}
				nextB := stepAutoDateCandMillisR62Search(b, cand, loc)
				if nextB <= b {
					break
				}
				b = nextB
			}
			sort.Slice(keys, func(i, j int) bool {
				return bucketTS[keys[i]] < bucketTS[keys[j]]
			})
		}
	}
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func aggsHaveAutoDateOrSignificantTextR62Search(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.AutoDateHistogram != nil || spec.SignificantText != nil {
			return true
		}
		if spec.Composite != nil {
			for _, sm := range spec.Composite.Sources {
				for _, cs := range sm {
					if cs.GeotileGrid != nil {
						return true
					}
				}
			}
		}
		if len(spec.SubAggs()) > 0 && aggsHaveAutoDateOrSignificantTextR62Search(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func parseGeotileTripleR62Search(s string) (z, x, y int64, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	zv, errZ := strconv.ParseInt(parts[0], 10, 64)
	xv, errX := strconv.ParseInt(parts[1], 10, 64)
	yv, errY := strconv.ParseInt(parts[2], 10, 64)
	if errZ != nil || errX != nil || errY != nil {
		return 0, 0, 0, false
	}
	return zv, xv, yv, true
}

func compareGeotileStringsR62Search(a, b string) int {
	za, xa, ya, okA := parseGeotileTripleR62Search(a)
	zb, xb, yb, okB := parseGeotileTripleR62Search(b)
	if okA && okB {
		if za != zb {
			if za < zb {
				return -1
			}
			return 1
		}
		if xa != xb {
			if xa < xb {
				return -1
			}
			return 1
		}
		if ya != yb {
			if ya < yb {
				return -1
			}
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}

func validateCompositeAggSourcesR62Search(aggs map[string]esast.AggSpec) (int, string, string) {
	for _, spec := range aggs {
		if spec.Composite != nil {
			for _, srcMap := range spec.Composite.Sources {
				for _, cs := range srcMap {
					if cs.Terms != nil && strings.TrimSpace(cs.Terms.MissingOrder) != "" && !cs.Terms.MissingBucket {
						return http.StatusBadRequest, "illegal_argument_exception",
							"missingOrder can only be set if missingBucket is true"
					}
					if cs.Histogram != nil && strings.TrimSpace(cs.Histogram.MissingOrder) != "" && !cs.Histogram.MissingBucket {
						return http.StatusBadRequest, "illegal_argument_exception",
							"missingOrder can only be set if missingBucket is true"
					}
					if cs.DateHistogram != nil {
						if strings.TrimSpace(cs.DateHistogram.MissingOrder) != "" && !cs.DateHistogram.MissingBucket {
							return http.StatusBadRequest, "illegal_argument_exception",
								"missingOrder can only be set if missingBucket is true"
						}
						if fmtStr := strings.TrimSpace(cs.DateHistogram.Format); fmtStr != "" {
							// Week-year `YYYY` without week-of-year `w` cannot round-trip calendar dates in ES `composite`!
							if strings.Contains(fmtStr, "Y") && !strings.Contains(fmtStr, "w") {
								return http.StatusBadRequest, "search_phase_execution_exception",
									fmt.Sprintf("all_shards_failed|illegal_argument_exception|date format [%s] created output it couldn't parse", fmtStr)
							}
							ivMs := cs.DateHistogram.EffectiveIntervalMs()
							isFullNamedFmt := fmtStr == "iso8601" || fmtStr == "epoch_millis" || fmtStr == "epoch_second" ||
								strings.HasPrefix(fmtStr, "strict_date") || strings.HasPrefix(fmtStr, "basic_date") ||
								fmtStr == "date" || fmtStr == "date_time" || fmtStr == "date_time_no_millis" || fmtStr == "date_optional_time"
							if ivMs > 0 && ivMs <= 86400000 && !strings.ContainsAny(fmtStr, "dD") && !isFullNamedFmt {
								return http.StatusBadRequest, "search_phase_execution_exception",
									fmt.Sprintf("all_shards_failed|illegal_argument_exception|date format [%s] created output it couldn't parse", fmtStr)
							}
						}
					}
				}
			}
		}
		if len(spec.SubAggs()) > 0 {
			if st, et, er := validateCompositeAggSourcesR62Search(spec.SubAggs()); st != 0 {
				return st, et, er
			}
		}
	}
	return 0, "", ""
}

var (
	activeSearchRawBodyMuR62Search sync.RWMutex
	activeSearchRawBodyR62Search   []byte
	activeSearchServerR62Search    *Server
	indexLookupSpecsMuR62Search    sync.RWMutex
	indexLookupSpecsR62Search      = make(map[string]map[string]lookupRuntimeSpecR62Search)
	serverLookupSpecsR62Search     = make(map[*Server]map[string]lookupRuntimeSpecR62Search)
	schemaServerRegistryR62Search  = make(map[string]*Server)
)

func pushActiveSearchContextR62Search(srv *Server, raw []byte, schemas []*schema.IndexSchema) (*Server, []byte) {
	if srv != nil {
		indexLookupSpecsMuR62Search.Lock()
		for _, sc := range schemas {
			if sc != nil {
				schemaServerRegistryR62Search[sc.DorisDB+"\x00"+sc.IndexName] = srv
			}
		}
		if len(bytes.TrimSpace(raw)) > 0 && bytes.Contains(raw, []byte("lookup")) {
			var root map[string]any
			if json.Unmarshal(raw, &root) == nil && root != nil {
				if rtm, ok := root["runtime_mappings"].(map[string]any); ok {
					if parsed := parseLookupSpecsFromRuntimeMapR62Search(rtm); len(parsed) > 0 {
						if serverLookupSpecsR62Search[srv] == nil {
							serverLookupSpecsR62Search[srv] = make(map[string]lookupRuntimeSpecR62Search, len(parsed))
						}
						for k, v := range parsed {
							serverLookupSpecsR62Search[srv][k] = v
						}
					}
				}
			}
		}
		indexLookupSpecsMuR62Search.Unlock()
	}
	activeSearchRawBodyMuR62Search.Lock()
	prevSrv := activeSearchServerR62Search
	prevRaw := activeSearchRawBodyR62Search
	activeSearchServerR62Search = srv
	activeSearchRawBodyR62Search = raw
	activeSearchRawBodyMuR62Search.Unlock()
	return prevSrv, prevRaw
}

func popActiveSearchContextR62Search(prevSrv *Server, prevRaw []byte) {
	activeSearchRawBodyMuR62Search.Lock()
	activeSearchServerR62Search = prevSrv
	activeSearchRawBodyR62Search = prevRaw
	activeSearchRawBodyMuR62Search.Unlock()
}

func resolveServerForSchemaOrActiveR62Search(sc *schema.IndexSchema) *Server {
	if sc != nil {
		indexLookupSpecsMuR62Search.RLock()
		srv := schemaServerRegistryR62Search[sc.DorisDB+"\x00"+sc.IndexName]
		indexLookupSpecsMuR62Search.RUnlock()
		if srv != nil {
			return srv
		}
	}
	return currentActiveSearchServerR62Search()
}

func currentActiveSearchServerR62Search() *Server {
	activeSearchRawBodyMuR62Search.RLock()
	srv := activeSearchServerR62Search
	activeSearchRawBodyMuR62Search.RUnlock()
	if srv != nil {
		return srv
	}
	activeStoredScriptsServerMu.RLock()
	srv = activeStoredScriptsServer
	activeStoredScriptsServerMu.RUnlock()
	return srv
}

type lookupRuntimeSpecR62Search struct {
	TargetIndex string   `json:"target_index"`
	InputField  string   `json:"input_field"`
	TargetField string   `json:"target_field"`
	KeyField    string   `json:"key_field"`
	FetchFields []string `json:"fetch_fields"`
}

func currentActiveSearchRawBodyR62Search() []byte {
	activeSearchRawBodyMuR62Search.RLock()
	raw := activeSearchRawBodyR62Search
	activeSearchRawBodyMuR62Search.RUnlock()
	return raw
}

func registerIndexLookupSpecsFromRawBodyR62Search(indexName string, rawBody []byte) {
	if indexName == "" || len(bytes.TrimSpace(rawBody)) == 0 {
		return
	}
	var root map[string]any
	if json.Unmarshal(rawBody, &root) != nil || root == nil {
		return
	}
	var rtMap map[string]any
	if m, ok := root["mappings"].(map[string]any); ok {
		rtMap, _ = m["runtime"].(map[string]any)
	}
	if rtMap == nil {
		rtMap, _ = root["runtime"].(map[string]any)
	}
	if len(rtMap) == 0 {
		return
	}
	parsed := parseLookupSpecsFromRuntimeMapR62Search(rtMap)
	if len(parsed) == 0 {
		return
	}
	indexLookupSpecsMuR62Search.Lock()
	if indexLookupSpecsR62Search[indexName] == nil {
		indexLookupSpecsR62Search[indexName] = make(map[string]lookupRuntimeSpecR62Search, len(parsed))
	}
	for k, v := range parsed {
		indexLookupSpecsR62Search[indexName][k] = v
	}
	indexLookupSpecsMuR62Search.Unlock()
}

func parseLookupSpecsFromRuntimeMapR62Search(rtMap map[string]any) map[string]lookupRuntimeSpecR62Search {
	out := make(map[string]lookupRuntimeSpecR62Search)
	for fName, rawSpec := range rtMap {
		sm, ok := rawSpec.(map[string]any)
		if !ok || sm == nil {
			continue
		}
		tp, _ := sm["type"].(string)
		if !strings.EqualFold(strings.TrimSpace(tp), "lookup") {
			continue
		}
		b, err := json.Marshal(sm)
		if err != nil {
			continue
		}
		var ls lookupRuntimeSpecR62Search
		if json.Unmarshal(b, &ls) == nil {
			if ls.TargetField == "" && ls.KeyField != "" {
				ls.TargetField = ls.KeyField
			}
			out[fName] = ls
		}
	}
	return out
}

func resolveLookupRuntimeSpecForFieldR62Search(srv *Server, idxSchema *schema.IndexSchema, fieldName string) (lookupRuntimeSpecR62Search, bool) {
	if srv != nil {
		indexLookupSpecsMuR62Search.RLock()
		sm := serverLookupSpecsR62Search[srv]
		ls, ok := sm[fieldName]
		indexLookupSpecsMuR62Search.RUnlock()
		if ok {
			return ls, true
		}
	}
	if raw := currentActiveSearchRawBodyR62Search(); len(bytes.TrimSpace(raw)) > 0 {
		var root map[string]any
		if json.Unmarshal(raw, &root) == nil && root != nil {
			if rtm, ok := root["runtime_mappings"].(map[string]any); ok {
				if parsed := parseLookupSpecsFromRuntimeMapR62Search(rtm); len(parsed) > 0 {
					if ls, okF := parsed[fieldName]; okF {
						return ls, true
					}
				}
			}
		}
	}
	if idxSchema != nil && idxSchema.IndexName != "" {
		indexLookupSpecsMuR62Search.RLock()
		idxMap := indexLookupSpecsR62Search[idxSchema.IndexName]
		ls, ok := idxMap[fieldName]
		indexLookupSpecsMuR62Search.RUnlock()
		if ok {
			return ls, true
		}
	}
	return lookupRuntimeSpecR62Search{}, false
}

// rewriteSignificantHeuristicParseErrorR62Search rewrites `[terms] unknown field [<hk>]` into
// ES's `x_content_parse_exception: Unknown significance heuristic [<hk>] did you mean [...]?`
// when the raw body contains `significant_text` or `significant_terms`.
func rewriteSignificantHeuristicParseErrorR62Search(rawBody []byte, errMsg string) (string, string, bool) {
	if !bytes.Contains(rawBody, []byte("significant_text")) && !bytes.Contains(rawBody, []byte("significant_terms")) {
		return "", "", false
	}
	const marker = "[terms] unknown field ["
	idx := strings.Index(errMsg, marker)
	if idx < 0 {
		return "", "", false
	}
	rest := errMsg[idx+len(marker):]
	end := strings.IndexByte(rest, ']')
	if end <= 0 {
		return "", "", false
	}
	hk := rest[:end]
	knownHeuristics := []string{"jlh", "mutual_information", "chi_square", "gnd", "percentage", "script_heuristic"}
	levDist := func(a, b string) int {
		dp := make([]int, len(b)+1)
		for j := range dp {
			dp[j] = j
		}
		for i := 1; i <= len(a); i++ {
			prev := dp[0]
			dp[0] = i
			for j := 1; j <= len(b); j++ {
				tmp := dp[j]
				cost := 0
				if a[i-1] != b[j-1] {
					cost = 1
				}
				v := dp[j] + 1
				if dp[j-1]+1 < v {
					v = dp[j-1] + 1
				}
				if prev+cost < v {
					v = prev + cost
				}
				dp[j] = v
				prev = tmp
			}
		}
		return dp[len(b)]
	}
	best := ""
	bestD := 99
	for _, kh := range knownHeuristics {
		if d := levDist(hk, kh); d < bestD {
			bestD = d
			best = kh
		}
	}
	if best != "" && bestD <= 3 {
		return "x_content_parse_exception", fmt.Sprintf("Unknown significance heuristic [%s] did you mean [%s]?", hk, best), true
	}
	return "x_content_parse_exception", fmt.Sprintf("Unknown significance heuristic [%s]", hk), true
}

// validateSignificantTextSpecsInAggsR62Search verifies `significant_text` field mapping compatibility.
func validateSignificantTextSpecsInAggsR62Search(aggs map[string]esast.AggSpec, schemas []*schema.IndexSchema) (int, string, string) {
	for _, spec := range aggs {
		if spec.SignificantText != nil {
			f := strings.TrimSpace(spec.SignificantText.Field)
			if f == "" {
				return http.StatusBadRequest, "parsing_exception", "[significant_text] requires [field] to be specified"
			}
			for _, sc := range schemas {
				if sc == nil {
					continue
				}
				if b, ok := sc.Fields[f]; ok && b.ESType != "" && b.ESType != "text" && b.ESType != "match_only_text" && b.ESType != "annotated-text" && b.ESType != "annotated_text" {
					return http.StatusBadRequest, "search_phase_execution_exception",
						fmt.Sprintf("all_shards_failed|illegal_argument_exception|Field [%s] of type [%s] is not supported for aggregation [significant_text]", f, b.ESType)
				}
			}
		}
		if len(spec.SubAggs()) > 0 {
			if st, et, er := validateSignificantTextSpecsInAggsR62Search(spec.SubAggs(), schemas); st != 0 {
				return st, et, er
			}
		}
	}
	return 0, "", ""
}

type sigHeuristicSpecR62Search struct {
	kind   string
	params map[string]any
}

func extractSigHeuristicForAggR62Search(fullAggName string) sigHeuristicSpecR62Search {
	raw := currentActiveSearchRawBodyR62Search()
	if len(bytes.TrimSpace(raw)) == 0 {
		return sigHeuristicSpecR62Search{kind: "jlh"}
	}
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return sigHeuristicSpecR62Search{kind: "jlh"}
	}
	segs := strings.Split(fullAggName, ".")
	cur := root
	for i, seg := range segs {
		aggsObj, _ := cur["aggs"].(map[string]any)
		if aggsObj == nil {
			aggsObj, _ = cur["aggregations"].(map[string]any)
		}
		if aggsObj == nil {
			return sigHeuristicSpecR62Search{kind: "jlh"}
		}
		next, ok := aggsObj[seg].(map[string]any)
		if !ok || next == nil {
			return sigHeuristicSpecR62Search{kind: "jlh"}
		}
		cur = next
		if i == len(segs)-1 {
			stMap, _ := cur["significant_text"].(map[string]any)
			if stMap == nil {
				stMap, _ = cur["significant_terms"].(map[string]any)
			}
			for _, hk := range []string{"percentage", "gnd", "mutual_information", "chi_square", "jlh"} {
				if rawH, hasH := stMap[hk]; hasH && rawH != nil {
					pm, _ := rawH.(map[string]any)
					if pm == nil {
						pm = map[string]any{}
					}
					return sigHeuristicSpecR62Search{kind: hk, params: pm}
				}
			}
		}
	}
	return sigHeuristicSpecR62Search{kind: "jlh"}
}

func computeSignificantScoreR62Search(heur sigHeuristicSpecR62Search, fgCount, fgTotal, bgCount, bgTotal int64) float64 {
	if fgCount <= 0 || fgTotal <= 0 || bgTotal <= 0 {
		return 0
	}
	if bgCount < fgCount {
		bgCount = fgCount
	}
	if bgTotal < fgTotal {
		bgTotal = fgTotal
	}
	fgFreq := float64(fgCount) / float64(fgTotal)
	bgFreq := float64(bgCount) / float64(bgTotal)
	if bgFreq <= 0 {
		return 0
	}
	switch heur.kind {
	case "percentage":
		return float64(fgCount) / float64(bgCount)
	case "gnd":
		bgIsSuperset := true
		if b, ok := heur.params["background_is_superset"].(bool); ok {
			bgIsSuperset = b
		}
		n11 := float64(fgCount)
		n10 := float64(fgTotal - fgCount)
		var n01, n00 float64
		if bgIsSuperset {
			n01 = float64(bgCount - fgCount)
			n00 = float64((bgTotal - fgTotal) - (bgCount - fgCount))
		} else {
			n01 = float64(bgCount)
			n00 = float64(bgTotal - bgCount)
		}
		if n01 < 0 {
			n01 = 0
		}
		if n00 < 0 {
			n00 = 0
		}
		total := n11 + n10 + n01 + n00
		if total <= 0 {
			return 0
		}
		dx := math.Max(n11*n00-n10*n01, 0)
		denom := (n11 + n10) * (n01 + n00)
		if denom <= 0 {
			return 0
		}
		return dx / (denom * math.Max(1.0, math.Sqrt(total)))
	case "mutual_information":
		includeNeg := false
		if b, ok := heur.params["include_negatives"].(bool); ok {
			includeNeg = b
		}
		if !includeNeg && fgFreq < bgFreq {
			return 0
		}
		bgIsSuperset := true
		if b, ok := heur.params["background_is_superset"].(bool); ok {
			bgIsSuperset = b
		}
		var allDocs, otherSubTotal, otherTermCount float64
		if bgIsSuperset {
			allDocs = float64(bgTotal)
			otherSubTotal = float64(bgTotal - fgTotal)
			otherTermCount = float64(bgCount - fgCount)
		} else {
			allDocs = float64(bgTotal + fgTotal)
			otherSubTotal = float64(bgTotal)
			otherTermCount = float64(bgCount)
		}
		if allDocs <= 0 {
			return 0
		}
		termWith := float64(fgCount)
		termWithout := float64(fgTotal - fgCount)
		otherWithout := otherSubTotal - otherTermCount
		miTerm := func(joint, rowSum, colSum float64) float64 {
			if joint <= 0 || rowSum <= 0 || colSum <= 0 {
				return 0
			}
			return (joint / allDocs) * math.Log2((allDocs*joint)/(rowSum*colSum))
		}
		tSum := termWith + otherTermCount
		noTSum := termWithout + otherWithout
		fgSum := float64(fgTotal)
		return miTerm(termWith, fgSum, tSum) +
			miTerm(otherTermCount, otherSubTotal, tSum) +
			miTerm(termWithout, fgSum, noTSum) +
			miTerm(otherWithout, otherSubTotal, noTSum)
	case "chi_square":
		includeNeg := false
		if b, ok := heur.params["include_negatives"].(bool); ok {
			includeNeg = b
		}
		if !includeNeg && fgFreq <= bgFreq {
			return 0
		}
		exp := float64(fgTotal) * bgFreq
		if exp <= 0 {
			return 0
		}
		diff := float64(fgCount) - exp
		return (diff * diff) / exp
	default:
		// Default JLH score: `(fgFreq - bgFreq) * (fgFreq / bgFreq)`
		if fgFreq <= bgFreq {
			return 0
		}
		return (fgFreq - bgFreq) * (fgFreq / bgFreq)
	}
}

func emitRuntimeSignificantTextAggRowsR62Search(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	fgDocs []runtimeMatchedDoc,
	allCorpusDocs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	stSpec := aggSpec.SignificantText
	if stSpec == nil {
		return
	}
	bgDocs := allCorpusDocs
	if len(bgDocs) == 0 {
		bgDocs = fgDocs
	}
	if stSpec.BackgroundFilter != nil {
		filteredBG := make([]runtimeMatchedDoc, 0, len(bgDocs))
		for _, md := range bgDocs {
			if evalBranchMatchesDoc(md.EffectiveSchema(idxSchema), md.doc, stSpec.BackgroundFilter) {
				filteredBG = append(filteredBG, md)
			}
		}
		bgDocs = filteredBG
	}

	analyzerName := "standard"
	if idxSchema != nil {
		if b := idxSchema.ResolveField(stSpec.Field); b.Analyzer != "" {
			analyzerName = b.Analyzer
		}
	}
	var anCfg *analysis.IndexAnalysisConfig
	if idxSchema != nil && idxSchema.IndexName != "" {
		if srv := currentActiveSearchServerR62Search(); srv != nil {
			srv.mu.RLock()
			cs := srv.indexCustomSettings[idxSchema.IndexName]
			srv.mu.RUnlock()
			if len(cs) > 0 {
				anCfg, _ = analysis.ParseIndexAnalysisConfig(cs, analysis.Options{})
			}
		}
	}
	if anCfg == nil {
		anCfg = analysis.DefaultIndexAnalysisConfig()
	}

	sourceFields := stSpec.SourceFields
	if len(sourceFields) == 0 {
		sourceFields = []string{stSpec.Field}
	}

	extractDocTokens := func(md runtimeMatchedDoc) ([]string, string) {
		var rawTexts []string
		for _, sf := range sourceFields {
			vals := collectStringValuesAtPath(md.doc, strings.Split(sf, "."))
			rawTexts = append(rawTexts, vals...)
		}
		joined := strings.Join(rawTexts, " ")
		if strings.TrimSpace(joined) == "" {
			return nil, ""
		}
		graph, err := analysis.AnalyzeForQuery(joined, analyzerName, anCfg, analysis.Options{})
		if err != nil || graph.IsEmpty() {
			return transpiler.TokenizeByAnalyzer(joined, analyzerName), joined
		}
		seen := make(map[string]bool)
		var toks []string
		for _, pos := range graph.Positions {
			for _, tk := range pos.Terms {
				if !seen[tk] {
					seen[tk] = true
					toks = append(toks, tk)
				}
			}
		}
		return toks, joined
	}

	filterDup := stSpec.FilterDuplicateText != nil && *stSpec.FilterDuplicateText
	fgDeduplicated := make([]runtimeMatchedDoc, 0, len(fgDocs))
	fgTokensByDoc := make([][]string, 0, len(fgDocs))
	seenTextHash := make(map[string]bool)
	for _, md := range fgDocs {
		toks, rawJoined := extractDocTokens(md)
		if filterDup && rawJoined != "" {
			normTxt := strings.TrimSpace(rawJoined)
			if seenTextHash[normTxt] {
				continue
			}
			seenTextHash[normTxt] = true
		}
		fgDeduplicated = append(fgDeduplicated, md)
		fgTokensByDoc = append(fgTokensByDoc, toks)
	}

	bgDocFreq := make(map[string]int64)
	for _, md := range bgDocs {
		toks, _ := extractDocTokens(md)
		seen := make(map[string]bool, len(toks))
		for _, tk := range toks {
			if !seen[tk] {
				seen[tk] = true
				bgDocFreq[tk]++
			}
		}
	}

	fgDocsByTerm := make(map[string][]runtimeMatchedDoc)
	for i, md := range fgDeduplicated {
		seen := make(map[string]bool, len(fgTokensByDoc[i]))
		for _, tk := range fgTokensByDoc[i] {
			if !seen[tk] {
				seen[tk] = true
				fgDocsByTerm[tk] = append(fgDocsByTerm[tk], md)
			}
		}
	}

	minCnt := int64(3)
	if stSpec.MinDocCount != nil {
		minCnt = int64(*stSpec.MinDocCount)
	}
	var incRe, excRe *regexp.Regexp
	if s, ok := stSpec.Include.(string); ok {
		incRe, _ = regexp.Compile("^(?:" + s + ")$")
	}
	if s, ok := stSpec.Exclude.(string); ok {
		excRe, _ = regexp.Compile("^(?:" + s + ")$")
	}

	heur := extractSigHeuristicForAggR62Search(fullAggName)
	type sigCand struct {
		term    string
		fgCount int64
		bgCount int64
		score   float64
		docs    []runtimeMatchedDoc
	}
	fgTotal := int64(len(fgDeduplicated))
	bgTotal := int64(len(bgDocs))
	var cands []sigCand
	for term, tDocs := range fgDocsByTerm {
		fgCnt := int64(len(tDocs))
		if fgCnt < minCnt {
			continue
		}
		if stSpec.Include != nil && !matchesTermsFilterPrecompiledWithSchemaR62Search(term, stSpec.Include, incRe, "keyword") {
			continue
		}
		if stSpec.Exclude != nil && matchesTermsFilterPrecompiledWithSchemaR62Search(term, stSpec.Exclude, excRe, "keyword") {
			continue
		}
		bgCnt := bgDocFreq[term]
		if bgCnt < fgCnt {
			bgCnt = fgCnt
		}
		sc := computeSignificantScoreR62Search(heur, fgCnt, fgTotal, bgCnt, bgTotal)
		if sc <= 0 && heur.kind != "mutual_information" && heur.kind != "percentage" && heur.kind != "gnd" {
			continue
		}
		cands = append(cands, sigCand{
			term:    term,
			fgCount: fgCnt,
			bgCount: bgCnt,
			score:   sc,
			docs:    tDocs,
		})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if cands[i].fgCount != cands[j].fgCount {
			return cands[i].fgCount > cands[j].fgCount
		}
		return cands[i].term < cands[j].term
	})
	limit := stSpec.Size
	if limit <= 0 {
		limit = 10
	}
	if len(cands) > limit {
		cands = cands[:limit]
	}

	// Store total bgCount in synthetic row `__SIG_BG_COUNT__` so stitcher emits `bg_count`!
	bgMetaKey := "__SIG_BG_COUNT__"
	if parentBucketKey != "" {
		bgMetaKey = parentBucketKey + "\x1f__SIG_BG_COUNT__"
	}
	*out = append(*out, AggRow{
		AggName:   fullAggName + ".__sig_bg",
		BucketKey: bgMetaKey,
		DocCount:  bgTotal,
		Value:     float64(bgTotal),
	})

	subAggs := aggSpec.SubAggs()
	for _, c := range cands {
		rowKey := c.term
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + c.term
		}
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  c.fgCount,
			Value:     c.score,
			Weight:    c.bgCount,
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, c.docs, out, idxSchema)
		}
	}
}

// resolveLookupRuntimeFieldFetchR62Search implements ES 8.15 `type: "lookup"` runtime fields
// (`search/390_lookup_fields.yml`), joining local `input_field` values against `target_index` `target_field`
// and extracting `fetch_fields` into `[{"<subField>": [...] }]`.
func (s *Server) resolveLookupRuntimeFieldFetchR62Search(
	ctx context.Context,
	doc map[string]any,
	runtimeDoc map[string]any,
	idxSchema *schema.IndexSchema,
	fieldName string,
	_ esast.FieldProperty,
) ([]any, int, string, string) {
	if s == nil {
		return nil, 0, "", ""
	}
	ls, ok := resolveLookupRuntimeSpecForFieldR62Search(s, idxSchema, fieldName)
	if !ok {
		return nil, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("lookup field [%s] requires [target_index], [input_field], [target_field], and [fetch_fields]", fieldName)
	}
	targetIdx := strings.TrimSpace(ls.TargetIndex)
	inputField := strings.TrimSpace(ls.InputField)
	targetField := strings.TrimSpace(ls.TargetField)
	if targetIdx == "" || inputField == "" || targetField == "" || len(ls.FetchFields) == 0 {
		return nil, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("lookup field [%s] requires [target_index], [input_field], [target_field], and [fetch_fields]", fieldName)
	}

	var inputVals []any
	if runtimeDoc != nil {
		if v, ok := runtimeDoc[inputField]; ok && v != nil {
			inputVals = flattenAnyToSliceR61Search(v)
		}
	}
	if len(inputVals) == 0 {
		segs := strings.Split(inputField, ".")
		if idxSchema != nil {
			if b := idxSchema.ResolveField(inputField); len(b.SourceJSONPath) > 0 {
				segs = b.SourceJSONPath
			}
		}
		inputVals = collectSchemaAwareScalarValues(doc, inputField, segs, idxSchema)
	}
	if len(inputVals) == 0 {
		return nil, 0, "", ""
	}

	targets, aliasFilters := s.resolveTargetIndicesWithFilters(targetIdx)
	if len(targets) == 0 {
		return nil, 0, "", ""
	}

	fetchSize := 100
	subReq := &esast.SearchRequest{
		Size: &fetchSize,
		Query: &esast.Query{
			Terms: &esast.TermsQuery{
				Fields: map[string][]any{targetField: inputVals},
			},
		},
	}
	for _, f := range ls.FetchFields {
		subReq.Fields = append(subReq.Fields, esast.FieldRequestSpec{Field: f})
	}

	var results []any
	for _, tName := range targets {
		if s.isIndexClosed(tName) {
			continue
		}
		tSchema := s.getOrCompileReadOnlySchema(ctx, tName)
		if tSchema == nil {
			continue
		}
		_ = s.coalescer.FlushTable(ctx, tSchema.DorisTable)
		var hits []HitRow
		if targetField == "_id" {
			seenIDs := make(map[string]bool, len(inputVals))
			for _, iv := range inputVals {
				idStr := strings.TrimSpace(fmt.Sprintf("%v", iv))
				if idStr == "" || seenIDs[idStr] {
					continue
				}
				seenIDs[idStr] = true
				if h, found, gErr := s.backend.GetDocByID(ctx, tSchema.DorisDB, tSchema.DorisTable, idStr); gErr == nil && found && h != nil {
					if af := aliasFilters[tName]; af != nil && !s.docMatchesAliasFilter(ctx, tName, idStr, h.Source, af) {
						continue
					}
					hits = append(hits, *h)
				}
			}
		} else {
			effSub := applyIndexAliasFilter(subReq, aliasFilters[tName])
			trOpts := s.effectiveTranspileOptsForIndexR62Search(nil, tName, tSchema, nil)
			plan, pErr := transpiler.NewTranspiler(tSchema, trOpts).BuildSearchPlan(effSub)
			if pErr != nil || plan.HitsSQL == "" {
				continue
			}
			qHits, hErr := s.backend.QueryHits(ctx, plan.HitsSQL)
			if hErr != nil {
				continue
			}
			hits = qHits
		}
		for _, h := range hits {
			fOut, st, _, _ := extractUnifiedFieldsR61Search(h, tName, subReq, tSchema, nil)
			if st != 0 || len(fOut) == 0 {
				continue
			}
			entry := make(map[string]any, len(fOut))
			for fk, fv := range fOut {
				entry[fk] = fv
			}
			if len(entry) > 0 {
				results = append(results, entry)
			}
		}
	}
	return results, 0, "", ""
}

func detectLookupQueryKindR62Search(q *esast.Query, lookupFields map[string]bool) (string, string) {
	if q == nil {
		return "", ""
	}
	for f := range q.Match {
		if lookupFields[f] {
			return f, "match"
		}
	}
	for f := range q.Term {
		if lookupFields[f] {
			return f, "term"
		}
	}
	if q.Terms != nil {
		for f := range q.Terms.Fields {
			if lookupFields[f] {
				return f, "terms"
			}
		}
	}
	for f := range q.Range {
		if lookupFields[f] {
			return f, "range"
		}
	}
	for f := range q.Prefix {
		if lookupFields[f] {
			return f, "prefix"
		}
	}
	for f := range q.Wildcard {
		if lookupFields[f] {
			return f, "wildcard"
		}
	}
	var badF string
	collectQueryFieldRefsR62Search(q, lookupFields, func(f string) {
		if lookupFields[strings.TrimSpace(f)] && badF == "" {
			badF = strings.TrimSpace(f)
		}
	})
	if badF != "" {
		return badF, "match"
	}
	return "", ""
}

func validateNoLookupFieldsInQueryOrAggsR62Search(
	idxSchemas []*schema.IndexSchema,
	req *esast.SearchRequest,
) (int, string, string) {
	if req == nil {
		return 0, "", ""
	}
	lookupFields := make(map[string]bool)
	for k, p := range req.RuntimeMappings {
		if strings.EqualFold(strings.TrimSpace(p.Type), "lookup") {
			lookupFields[k] = true
		}
	}
	for _, sc := range idxSchemas {
		if sc != nil && sc.RawMapping != nil {
			for k, p := range sc.RawMapping.Runtime {
				if strings.EqualFold(strings.TrimSpace(p.Type), "lookup") {
					lookupFields[k] = true
				}
			}
		}
	}
	if len(lookupFields) == 0 {
		return 0, "", ""
	}
	if badF, qKind := detectLookupQueryKindR62Search(req.Query, lookupFields); badF != "" {
		return http.StatusBadRequest, "search_phase_execution_exception",
			fmt.Sprintf("all_shards_failed|query_shard_exception|Field [%s] of type [lookup] does not support %s queries", badF, qKind)
	}
	if badF, qKind := detectLookupQueryKindR62Search(req.PostFilter, lookupFields); badF != "" {
		return http.StatusBadRequest, "search_phase_execution_exception",
			fmt.Sprintf("all_shards_failed|query_shard_exception|Field [%s] of type [lookup] does not support %s queries", badF, qKind)
	}
	var badField string
	check := func(f string) {
		clean := strings.TrimSpace(f)
		if lookupFields[clean] && badField == "" {
			badField = clean
		}
	}
	collectAggFieldRefsR62Search(req.EffectiveAggs(), lookupFields, check)
	for _, sSpec := range req.Sort {
		check(sSpec.Entry.Field)
	}
	for _, dv := range req.DocvalueFields {
		check(dv.Field)
	}
	if badField != "" {
		return http.StatusBadRequest, "search_phase_execution_exception",
			fmt.Sprintf("all_shards_failed|illegal_argument_exception|Fielddata is not supported on field [%s] of type [lookup]", badField)
	}
	return 0, "", ""
}

func extractRangeOrJoinFieldObjectsR62Search(
	doc map[string]any,
	fieldName string,
	b schema.FieldBinding,
	esType string,
	format string,
	isDocvalue bool,
) ([]any, bool, int, string, string) {
	switch esType {
	case "integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range":
		if isDocvalue && format != "" && esType != "date_range" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception",
				formatUnsupportedErrorMsgR61Search(fieldName, fieldName, esType)
		}
		segs := effectiveSourceSegsR61Search(fieldName, b)
		rawNode, ok := lookupNestedMapPathR61Search(doc, segs)
		if !ok || rawNode == nil {
			return nil, true, 0, "", ""
		}
		var out []any
		var collectMaps func(v any)
		collectMaps = func(v any) {
			switch tv := v.(type) {
			case map[string]any:
				cp := make(map[string]any, len(tv))
				for k, mv := range tv {
					if jn, okJ := mv.(json.Number); okJ {
						if iv, errI := jn.Int64(); errI == nil {
							cp[k] = iv
						} else if fv, errF := jn.Float64(); errF == nil {
							cp[k] = fv
						} else {
							cp[k] = jn.String()
						}
					} else {
						cp[k] = mv
					}
				}
				if len(cp) > 0 {
					out = append(out, cp)
				}
			case []any:
				for _, el := range tv {
					collectMaps(el)
				}
			}
		}
		collectMaps(rawNode)
		return out, true, 0, "", ""

	case "join":
		if isDocvalue {
			segs := effectiveSourceSegsR61Search(fieldName, b)
			rawNode, ok := lookupNestedMapPathR61Search(doc, segs)
			if !ok || rawNode == nil {
				return nil, true, 0, "", ""
			}
			switch tv := rawNode.(type) {
			case string:
				return []any{tv}, true, 0, "", ""
			case map[string]any:
				if nm, okN := tv["name"].(string); okN {
					return []any{nm}, true, 0, "", ""
				}
			}
			return nil, true, 0, "", ""
		}
		segs := effectiveSourceSegsR61Search(fieldName, b)
		rawNode, ok := lookupNestedMapPathR61Search(doc, segs)
		if !ok || rawNode == nil {
			return nil, true, 0, "", ""
		}
		switch tv := rawNode.(type) {
		case string:
			return []any{tv}, true, 0, "", ""
		case map[string]any:
			return []any{tv}, true, 0, "", ""
		}
		return nil, true, 0, "", ""
	}
	return nil, false, 0, "", ""
}

// validateSearchLimitsAndParamsR62Search enforces ES search request parameter limits (`30_limits.yml`,
// `40_indices_boost.yml`, `90_search_after.yml`, `120_batch_reduce_size.yml`, `140_pre_filter_search_shards.yml`).
func (s *Server) validateSearchLimitsAndParamsR62Search(
	ctx context.Context,
	r *http.Request,
	req *esast.SearchRequest,
	rawSchemas []*schema.IndexSchema,
	customSettings map[string]map[string]any,
	hasScroll bool,
) (int, string, string) {
	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if q.Has("batched_reduce_size") {
			raw := strings.TrimSpace(q.Get("batched_reduce_size"))
			n, err := strconv.Atoi(raw)
			if err != nil {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse int parameter [batched_reduce_size] with value [%s]", raw)
			}
			if n < 2 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("batched_reduce_size must be >= 2, got [%d]", n)
			}
		}
		if q.Has("pre_filter_shard_size") {
			raw := strings.TrimSpace(q.Get("pre_filter_shard_size"))
			n, err := strconv.Atoi(raw)
			if err != nil {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse int parameter [pre_filter_shard_size] with value [%s]", raw)
			}
			if n < 1 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("pre_filter_shard_size must be >= 1, got [%d]", n)
			}
		}
		if q.Has("max_concurrent_shard_requests") {
			raw := strings.TrimSpace(q.Get("max_concurrent_shard_requests"))
			n, err := strconv.Atoi(raw)
			if err != nil {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse int parameter [max_concurrent_shard_requests] with value [%s]", raw)
			}
			if n < 1 {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("max_concurrent_shard_requests must be >= 1, got [%d]", n)
			}
		}
	}

	if req == nil {
		return 0, "", ""
	}
	if req.From != nil && *req.From < 0 {
		return http.StatusBadRequest, "search_phase_execution_exception",
			fmt.Sprintf("all_shards_failed|illegal_argument_exception|[from] parameter cannot be negative, found [%d]", *req.From)
	}
	if req.Size != nil && *req.Size < 0 {
		return http.StatusBadRequest, "search_phase_execution_exception",
			fmt.Sprintf("all_shards_failed|illegal_argument_exception|[size] parameter cannot be negative, found [%d]", *req.Size)
	}
	if hasScroll && req.Size != nil {
		maxWin := transpiler.DefaultMaxResultWindow
		for _, sc := range rawSchemas {
			if sc != nil && sc.MaxResultWindow > 0 && sc.MaxResultWindow < maxWin {
				maxWin = sc.MaxResultWindow
			}
		}
		if *req.Size > maxWin {
			return http.StatusBadRequest, "search_phase_execution_exception",
				fmt.Sprintf("all_shards_failed|illegal_argument_exception|Batch size is too large, size must be less than or equal to: [%d] but was [%d]. Scroll batch sizes cost as much memory as result windows so they are controlled by the [index.max_result_window] index level setting.", maxWin, *req.Size)
		}
	}

	// Enforce `index.max_docvalue_fields_search` (default 100) and `index.max_script_fields` (default 32)
	maxDV := 100
	maxSF := 32
	for _, cs := range customSettings {
		if n, ok := extractIntSettingR62Search(cs, "index.max_docvalue_fields_search", "max_docvalue_fields_search"); ok && n >= 0 {
			maxDV = n
		}
		if n, ok := extractIntSettingR62Search(cs, "index.max_script_fields", "max_script_fields"); ok && n >= 0 {
			maxSF = n
		}
	}
	if len(req.DocvalueFields) > maxDV {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Trying to retrieve too many docvalue_fields. Must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_docvalue_fields_search] index level setting.", maxDV, len(req.DocvalueFields))
	}
	if len(req.ScriptFields) > maxSF {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Trying to retrieve too many script_fields. Must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_script_fields] index level setting.", maxSF, len(req.ScriptFields))
	}

	// Enforce `_shard_doc` sort requires `pit` (`90_search_after.yml`)
	if req.PIT == nil {
		for _, sSpec := range req.Sort {
			if sSpec.Entry.Field == "_shard_doc" {
				return http.StatusBadRequest, "search_phase_execution_exception",
					"all_shards_failed|illegal_argument_exception|_shard_doc can only be used for sorting with a point in time (pit)"
			}
		}
	}

	// Validate strict date `format` on `search_after` values when `Sort[i].Entry.Format != ""`
	if len(req.SearchAfter) > 0 && len(req.Sort) > 0 {
		nowUTC := time.Now().UTC()
		for i := 0; i < len(req.SearchAfter) && i < len(req.Sort); i++ {
			fmtStr := strings.TrimSpace(req.Sort[i].Entry.Format)
			if fmtStr == "" {
				continue
			}
			saStr, isStr := req.SearchAfter[i].(string)
			if !isStr {
				continue
			}
			if _, ok := schema.ParseESDateWithFormatToEpochMillis(saStr, fmtStr, nowUTC); !ok {
				return http.StatusBadRequest, "search_phase_execution_exception",
					fmt.Sprintf("all_shards_failed|parse_exception|failed to parse date field [%s] with format [%s]", saStr, fmtStr)
			}
		}
	}

	// Validate concrete `indices_boost` targets exist unless `ignore_unavailable=true` (`40_indices_boost.yml`)
	if len(req.IndicesBoost) > 0 && s != nil {
		ignoreUnavail := isTruthyBoolQueryParam(r, "ignore_unavailable")
		for _, boostMap := range parseOrderedIndicesBoostR62Search(req.IndicesBoost) {
			for pat := range boostMap {
				if missing := s.findMissingConcreteSearchIndexRound60(ctx, r, pat, &ignoreUnavail); missing != "" {
					return http.StatusNotFound, "index_not_found_exception", "no such index [" + missing + "]"
				}
			}
		}
	}

	if st, et, er := validateNoLookupFieldsInQueryOrAggsR62Search(rawSchemas, req); st != 0 {
		return st, et, er
	}
	if st, et, er := validateCompositeAggSourcesR62Search(req.EffectiveAggs()); st != 0 {
		return st, et, er
	}
	if s == nil || s.hasExplicitTargetESVersion() {
		if st, et, er := validateSignificantTextSpecsInAggsR62Search(req.EffectiveAggs(), rawSchemas); st != 0 {
			return st, et, er
		}
	}
	return 0, "", ""
}

func extractIntSettingR62Search(m map[string]any, keys ...string) (int, bool) {
	if len(m) == 0 {
		return 0, false
	}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if iv, okI := toInt64(v); okI {
				return int(iv), true
			}
			if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
				return n, true
			}
		}
	}
	if idxSub, ok := m["index"].(map[string]any); ok {
		return extractIntSettingR62Search(idxSub, keys...)
	}
	return 0, false
}

func parseOrderedIndicesBoostR62Search(fallback map[string]float64) []map[string]float64 {
	if raw := currentActiveSearchRawBodyR62Search(); len(bytes.TrimSpace(raw)) > 0 {
		var root struct {
			IndicesBoost json.RawMessage `json:"indices_boost"`
		}
		if json.Unmarshal(raw, &root) == nil && len(bytes.TrimSpace(root.IndicesBoost)) > 0 {
			trim := bytes.TrimSpace(root.IndicesBoost)
			if trim[0] == '[' {
				var arr []map[string]float64
				if json.Unmarshal(trim, &arr) == nil && len(arr) > 0 {
					return arr
				}
			}
		}
	}
	if len(fallback) == 0 {
		return nil
	}
	return []map[string]float64{fallback}
}

// resolveIndexBoostFirstMatchR62Search returns the boost factor from `req.IndicesBoost` using
// ES first-matching entry semantics (`40_indices_boost.yml`: first entry in array matching concrete
// index name, alias pointing to `indexName`, or wildcard pattern wins!).
func (s *Server) resolveIndexBoostFirstMatchR62Search(indexName string, indicesBoostMap map[string]float64) (float64, bool) {
	indicesBoost := parseOrderedIndicesBoostR62Search(indicesBoostMap)
	if len(indicesBoost) == 0 {
		return 1.0, false
	}
	var indexAliases []string
	if s != nil {
		s.mu.RLock()
		for aliasName, idxList := range s.aliases {
			for _, t := range idxList {
				if t == indexName {
					indexAliases = append(indexAliases, aliasName)
					break
				}
			}
		}
		s.mu.RUnlock()
	}
	for _, boostMap := range indicesBoost {
		for pat, boostVal := range boostMap {
			if pat == indexName || matchWildcardPattern(pat, indexName) {
				return boostVal, true
			}
			for _, al := range indexAliases {
				if pat == al || matchWildcardPattern(pat, al) {
					return boostVal, true
				}
			}
		}
	}
	return 1.0, false
}

// enrichSearchProfilePayloadR62Search upgrades `buildSearchProfilePayloadR61Search` with exact
// ES 8.15 aggregator class names (`StringTermsAggregatorFromFilters`, `GlobalOrdinalsStringTermsAggregator`,
// `MapStringTermsAggregator`, `NumericTermsAggregator`, `NumericHistogramAggregator`, `TimeSeriesAggregator`,
// `AutoDateHistogramAggregator.FromSingle`), `collect_count`, `debug` blocks, and `_routing` in `stored_fields`!
func enrichSearchProfilePayloadR62Search(
	profilePayload map[string]any,
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
	aggsOut map[string]any,
	matchedDocCount int64,
	allHits []HitRow,
) map[string]any {
	if profilePayload == nil || req == nil {
		return profilePayload
	}
	shards, ok := profilePayload["shards"].([]map[string]any)
	if !ok || len(shards) == 0 {
		return profilePayload
	}
	shard := shards[0]

	// Add `_routing` to `fetch.debug.stored_fields` when index requires routing or hits carry routing (`370_profile.yml`)
	if fetchProf, okF := shard["fetch"].(map[string]any); okF && !req.HasStoredFieldsNone() {
		hasRouting := idxSchema != nil && idxSchema.RawMapping != nil && idxSchema.RawMapping.Routing != nil && idxSchema.RawMapping.Routing.Required
		if !hasRouting {
			for _, h := range allHits {
				if h.Routing != "" {
					hasRouting = true
					break
				}
			}
		}
		if hasRouting {
			if dbg, okD := fetchProf["debug"].(map[string]any); okD {
				if sf, okS := dbg["stored_fields"].([]string); okS {
					foundR := false
					for _, s := range sf {
						if s == "_routing" {
							foundR = true
							break
						}
					}
					if !foundR {
						dbg["stored_fields"] = append(sf, "_routing")
					}
				}
			}
		}
	}

	multiValuedStringField := make(map[string]bool)
	allValuesPerField := make(map[string][]string)
	hasDocCountField := false
	for _, h := range allHits {
		doc := decodeHitDocMapRound60(h)
		if _, hasDC := doc["_doc_count"]; hasDC {
			hasDocCountField = true
		}
		for k, v := range doc {
			if arr, okA := v.([]any); okA && len(arr) > 1 {
				multiValuedStringField[k] = true
			}
			allValuesPerField[k] = append(allValuesPerField[k], collectStringValuesAtPath(doc, []string{k})...)
		}
	}
	rewriteToFilterByFilter := true
	if srv := currentActiveSearchServerR62Search(); srv != nil {
		srv.mu.RLock()
		for _, m := range []map[string]any{srv.clusterTransientSettings, srv.clusterPersistentSettings} {
			if m != nil {
				if rawOpt, ok := m["search.aggs.rewrite_to_filter_by_filter"]; ok && rawOpt != nil {
					if bv, okB := parseOptionalBoolAny(rawOpt); okB {
						rewriteToFilterByFilter = bv
						break
					}
				}
			}
		}
		srv.mu.RUnlock()
	}

	var buildAggNode func(aggName string, spec esast.AggSpec, outObj map[string]any, isTopLevel bool) map[string]any
	buildAggNode = func(aggName string, spec esast.AggSpec, outObj map[string]any, isTopLevel bool) map[string]any {
		aggType := profileAggClassR62Search(spec, req, idxSchema, isTopLevel, rewriteToFilterByFilter, hasDocCountField)
		collectCount := matchedDocCount
		debugMap := make(map[string]any)

		subAggs := spec.SubAggs()
		subNames := make([]string, 0, len(subAggs))
		for sn := range subAggs {
			subNames = append(subNames, sn)
		}
		sort.Strings(subNames)

		bucketCount := 0
		var bucketKeys []string
		if outObj != nil {
			switch bs := outObj["buckets"].(type) {
			case []map[string]any:
				bucketCount = len(bs)
				for _, b := range bs {
					bucketKeys = append(bucketKeys, fmt.Sprintf("%v", b["key"]))
				}
			case []any:
				bucketCount = len(bs)
				for _, el := range bs {
					if bm, ok := el.(map[string]any); ok {
						bucketKeys = append(bucketKeys, fmt.Sprintf("%v", bm["key"]))
					}
				}
			case map[string]any:
				bucketCount = len(bs)
				for k := range bs {
					bucketKeys = append(bucketKeys, k)
				}
				sort.Strings(bucketKeys)
			}
		}

		switch aggType {
		case "StringTermsAggregatorFromFilters":
			collectCount = 0
			sortedTerms := append([]string(nil), bucketKeys...)
			if len(sortedTerms) == 0 && spec.Terms != nil {
				seenT := make(map[string]bool)
				for _, tv := range allValuesPerField[spec.Terms.Field] {
					if !seenT[tv] {
						seenT[tv] = true
						sortedTerms = append(sortedTerms, tv)
					}
				}
			}
			sort.Strings(sortedTerms)
			filters := make([]map[string]any, 0, len(sortedTerms))
			field := ""
			if spec.Terms != nil {
				field = spec.Terms.Field
			}
			for _, tk := range sortedTerms {
				filters = append(filters, map[string]any{
					"query":               fmt.Sprintf("%s:%s", field, tk),
					"specialized_for":     "PointInSetQuery",
					"segments_counted_in": 0,
				})
			}
			debugMap["delegate"] = "FilterByFilterAggregator"
			debugMap["delegate_debug"] = map[string]any{
				"filters": filters,
			}
		case "GlobalOrdinalsStringTermsAggregator":
			if len(subNames) > 0 && spec.Terms != nil && strings.EqualFold(spec.Terms.CollectMode, "breadth_first") {
				debugMap["deferred_aggregators"] = subNames
			}
			debugMap["collection_strategy"] = "remap using many bucket ords"
			debugMap["result_strategy"] = "terms"
			isMV := spec.Terms != nil && multiValuedStringField[spec.Terms.Field]
			if isMV {
				debugMap["segments_with_single_valued_ords"] = 0
				debugMap["segments_with_multi_valued_ords"] = 1
			} else {
				debugMap["segments_with_single_valued_ords"] = 1
				debugMap["segments_with_multi_valued_ords"] = 0
			}
			debugMap["has_filter"] = spec.Terms != nil && (spec.Terms.Include != nil || spec.Terms.Exclude != nil)
			debugMap["total_buckets"] = bucketCount
		case "MapStringTermsAggregator":
			if spec.SignificantText != nil {
				debugMap["collection_strategy"] = "analyze text from _source"
				debugMap["total_buckets"] = bucketCount
			} else {
				if len(subNames) > 0 && spec.Terms != nil && strings.EqualFold(spec.Terms.CollectMode, "breadth_first") {
					debugMap["deferred_aggregators"] = subNames
				}
				debugMap["result_strategy"] = "terms"
				debugMap["total_buckets"] = bucketCount
			}
		case "NumericTermsAggregator":
			strategy := "long_terms"
			if spec.Terms != nil && idxSchema != nil {
				b := idxSchema.ResolveField(spec.Terms.Field)
				if b.ESType == "double" || b.ESType == "float" || b.ESType == "half_float" {
					strategy = "double_terms"
				}
			}
			debugMap["result_strategy"] = strategy
			debugMap["total_buckets"] = bucketCount
		case "AutoDateHistogramAggregator.FromSingle":
			surviving := bucketCount
			if spec.AutoDateHistogram != nil && spec.AutoDateHistogram.Field != "" && len(allHits) > 0 {
				distinctTS := make(map[int64]bool)
				nowUTC := time.Now().UTC()
				for _, h := range allHits {
					md := runtimeMatchedDoc{
						hit: h,
						doc: decodeHitDocMapRound60(h),
					}
					for _, ts := range extractDocDateMillisForBucket(idxSchema, md, spec.AutoDateHistogram.Field, spec.AutoDateHistogram.Missing, spec.AutoDateHistogram.Script, nowUTC) {
						distinctTS[ts] = true
					}
				}
				if len(distinctTS) > surviving {
					surviving = len(distinctTS)
				}
			}
			debugMap["surviving_buckets"] = surviving
			debugMap["total_buckets"] = bucketCount
		case "CardinalityAggregator":
			hintLower := ""
			esT := ""
			if spec.Cardinality != nil {
				hintLower = strings.ToLower(strings.TrimSpace(spec.Cardinality.ExecutionHint))
				if idxSchema != nil && spec.Cardinality.Field != "" {
					b := idxSchema.ResolveField(spec.Cardinality.Field)
					esT = b.ESType
					if esT == "" {
						switch b.DorisType {
						case schema.DorisBigInt, schema.DorisInt, schema.DorisLargeInt:
							esT = "long"
						case schema.DorisDouble:
							esT = "double"
						case schema.DorisVarchar, schema.DorisString:
							esT = "keyword"
						}
					}
				}
			}
			isNumericCard := false
			switch esT {
			case "long", "integer", "short", "byte", "unsigned_long", "double", "float", "half_float", "scaled_float", "date", "date_nanos", "boolean":
				isNumericCard = true
			}
			debugMap["empty_collectors_used"] = 0
			debugMap["ordinals_collectors_overhead_too_high"] = 0
			switch {
			case isNumericCard:
				debugMap["numeric_collectors_used"] = 1
				debugMap["ordinals_collectors_used"] = 0
				debugMap["string_hashing_collectors_used"] = 0
			case hintLower == "direct":
				debugMap["numeric_collectors_used"] = 0
				debugMap["ordinals_collectors_used"] = 0
				debugMap["string_hashing_collectors_used"] = 1
			default:
				debugMap["numeric_collectors_used"] = 0
				debugMap["ordinals_collectors_used"] = 1
				debugMap["string_hashing_collectors_used"] = 0
			}
		case "GlobalOrdCardinalityAggregator":
			debugMap["empty_collectors_used"] = 0
			debugMap["ordinals_collectors_used"] = 1
			debugMap["built_global_ordinals"] = 0
			debugMap["hash_collectors_used"] = 0
		default:
			if bucketCount > 0 {
				debugMap["total_buckets"] = bucketCount
			}
		}

		children := make([]map[string]any, 0, len(subNames))
		for _, sn := range subNames {
			subSpec := subAggs[sn]
			if isSiblingPipelineAggSpec(subSpec) || subSpec.EffectiveCumulative() != nil || subSpec.Derivative != nil ||
				subSpec.EffectiveMovingAvg() != nil || subSpec.SerialDiff != nil || subSpec.Normalize != nil ||
				subSpec.BucketScript != nil || subSpec.BucketSelector != nil || subSpec.BucketSort != nil {
				continue
			}
			var sampleSubOut map[string]any
			if outObj != nil {
				if bs, okB := outObj["buckets"].([]map[string]any); okB && len(bs) > 0 {
					sampleSubOut, _ = bs[0][sn].(map[string]any)
				} else if subM, okM := outObj[sn].(map[string]any); okM {
					sampleSubOut = subM
				}
			}
			children = append(children, buildAggNode(sn, subSpec, sampleSubOut, false))
		}

		node := map[string]any{
			"type":          aggType,
			"description":   aggName,
			"time_in_nanos": int64(100),
			"breakdown": map[string]any{
				"reduce":                     int64(10),
				"reduce_count":               int64(1),
				"build_aggregation":          int64(10),
				"build_aggregation_count":    int64(1),
				"build_leaf_collector":       int64(10),
				"build_leaf_collector_count": int64(1),
				"post_collection":            int64(5),
				"post_collection_count":      int64(1),
				"initialize":                 int64(5),
				"initialize_count":           int64(1),
				"collect":                    int64(10),
				"collect_count":              collectCount,
			},
			"children": children,
		}
		if len(debugMap) > 0 {
			node["debug"] = debugMap
		}
		return node
	}

	aggs := req.EffectiveAggs()
	if len(aggs) > 0 {
		aggNames := make([]string, 0, len(aggs))
		for k := range aggs {
			aggNames = append(aggNames, k)
		}
		sort.Strings(aggNames)
		aggProfiles := make([]map[string]any, 0, len(aggNames))
		for _, an := range aggNames {
			spec := aggs[an]
			if isSiblingPipelineAggSpec(spec) {
				continue
			}
			var subOut map[string]any
			if aggsOut != nil {
				subOut, _ = aggsOut[an].(map[string]any)
			}
			aggProfiles = append(aggProfiles, buildAggNode(an, spec, subOut, true))
		}
		shard["aggregations"] = aggProfiles
	}
	return profilePayload
}

func profileAggClassR62Search(
	spec esast.AggSpec,
	req *esast.SearchRequest,
	idxSchema *schema.IndexSchema,
	isTopLevel bool,
	rewriteToFilterByFilter bool,
	hasDocCountField bool,
) string {
	switch {
	case spec.SignificantText != nil:
		return "MapStringTermsAggregator"
	case spec.Terms != nil:
		tSpec := spec.Terms
		vt := strings.ToLower(strings.TrimSpace(tSpec.ValueType))
		esType := vt
		if esType == "" && idxSchema != nil && tSpec.Field != "" {
			b := idxSchema.ResolveField(tSpec.Field)
			esType = b.ESType
			if esType == "" {
				switch b.DorisType {
				case schema.DorisBigInt, schema.DorisInt, schema.DorisLargeInt:
					esType = "long"
				case schema.DorisDouble:
					esType = "double"
				case schema.DorisBoolean:
					esType = "boolean"
				}
			}
		}
		switch esType {
		case "long", "integer", "short", "byte", "unsigned_long", "double", "float", "half_float", "scaled_float", "date", "date_nanos", "boolean":
			return "NumericTermsAggregator"
		}
		if strings.EqualFold(tSpec.ExecutionHint, "map") || tSpec.Script != nil {
			return "MapStringTermsAggregator"
		}
		isMatchAll := req == nil || req.Query == nil || req.Query.MatchAll != nil
		if isTopLevel && strings.EqualFold(tSpec.CollectMode, "breadth_first") {
			return "StringTermsAggregatorFromFilters"
		}
		if isTopLevel && rewriteToFilterByFilter && isMatchAll && len(spec.SubAggs()) == 0 &&
			tSpec.ExecutionHint == "" && tSpec.Include == nil && tSpec.Exclude == nil &&
			(req != nil && req.Size != nil && *req.Size == 0) {
			return "StringTermsAggregatorFromFilters"
		}
		return "GlobalOrdinalsStringTermsAggregator"
	case spec.Filters != nil:
		totalF := len(spec.Filters.Filters) + len(spec.Filters.AnonymousFilters)
		if totalF == 1 {
			return "FilterByFilterAggregator"
		}
		if hasDocCountField && totalF > 1 {
			return "FiltersAggregator.Compatible"
		}
		return "FiltersAggregator"
	case spec.Cardinality != nil:
		if spec.Cardinality.Field != "" &&
			!strings.EqualFold(spec.Cardinality.ExecutionHint, "direct") &&
			!strings.EqualFold(spec.Cardinality.ExecutionHint, "segment_ordinals") {
			esT := ""
			if idxSchema != nil {
				b := idxSchema.ResolveField(spec.Cardinality.Field)
				esT = b.ESType
				if esT == "" && (b.DorisType == schema.DorisVarchar || b.DorisType == schema.DorisString) {
					esT = "keyword"
				}
			}
			if esT == "keyword" || esT == "constant_keyword" || esT == "wildcard" || esT == "ip" || strings.HasSuffix(spec.Cardinality.Field, ".keyword") {
				return "GlobalOrdCardinalityAggregator"
			}
		}
		return "CardinalityAggregator"
	case spec.RareTerms != nil:
		return "RareTermsAggregator"
	case spec.MultiTerms != nil:
		return "MultiTermsAggregator"
	case spec.Histogram != nil:
		return "NumericHistogramAggregator"
	case spec.VariableWidthHistogram != nil:
		return "VariableWidthHistogramAggregator"
	case spec.DateHistogram != nil:
		return "DateHistogramAggregator"
	case spec.AutoDateHistogram != nil:
		return "AutoDateHistogramAggregator.FromSingle"
	case spec.TimeSeries != nil:
		return "TimeSeriesAggregator"
	case spec.IPPrefix != nil:
		return "IpPrefixAggregator"
	case spec.IPRange != nil:
		return "BinaryRangeAggregator"
	case spec.DateRange != nil, spec.Range != nil:
		return "RangeAggregator"
	case spec.Composite != nil:
		return "CompositeAggregator"
	case spec.Filter != nil:
		return "FilterAggregator"
	case spec.Global != nil:
		return "GlobalAggregator"
	case spec.Missing != nil:
		return "MissingAggregator"
	case spec.Nested != nil:
		return "NestedAggregator"
	case spec.ReverseNested != nil:
		return "ReverseNestedAggregator"
	case spec.RandomSampler != nil:
		return "RandomSamplerAggregator"
	case spec.DiversifiedSampler != nil:
		return "DiversifiedSamplerAggregator"
	case spec.Sampler != nil:
		return "SamplerAggregator"
	case spec.Avg != nil:
		return "AvgAggregator"
	case spec.WeightedAvg != nil:
		return "WeightedAvgAggregator"
	case spec.Sum != nil:
		return "SumAggregator"
	case spec.Min != nil:
		return "MinAggregator"
	case spec.Max != nil:
		return "MaxAggregator"
	case spec.Stats != nil:
		return "StatsAggregator"
	case spec.ExtendedStats != nil:
		return "ExtendedStatsAggregator"
	case spec.ValueCount != nil:
		return "ValueCountAggregator"
	case spec.Percentiles != nil:
		return "TDigestPercentilesAggregator"
	case spec.PercentileRanks != nil:
		return "TDigestPercentileRanksAggregator"
	case spec.Boxplot != nil:
		return "BoxplotAggregator"
	case spec.MedianAbsoluteDeviation != nil:
		return "MedianAbsoluteDeviationAggregator"
	case spec.StringStats != nil:
		return "StringStatsAggregator"
	case spec.TopHits != nil:
		return "TopHitsAggregator"
	case spec.TopMetrics != nil:
		return "TopMetricsAggregator"
	case spec.ScriptedMetric != nil:
		return "ScriptedMetricAggregator"
	case spec.MatrixStats != nil:
		return "MatrixStatsAggregator"
	case spec.TTest != nil:
		return "TTestAggregator"
	default:
		return "Aggregator"
	}
}

// ============================================================================
// Wave-3 Batch A: Analysis Settings Validation, Phrase Suggester & SAYT Highlighting
// ============================================================================

func (s *Server) validateIndexAnalysisSettingsR62Search(settings map[string]any) (int, string, string) {
	if len(settings) == 0 {
		return 0, "", ""
	}
	flat := make(map[string]any)
	flattenSettingsInput("", settings, flat)
	hasAnalysis := false
	for k := range flat {
		clean := strings.TrimPrefix(strings.TrimPrefix(k, "settings."), "index.")
		if strings.HasPrefix(clean, "analysis.") || strings.HasPrefix(clean, "analyze.") {
			hasAnalysis = true
			break
		}
	}
	if !hasAnalysis {
		return 0, "", ""
	}
	var opts analysis.Options
	if s != nil {
		opts = s.analysisOptionsR62Admin()
	}
	if _, err := analysis.ParseIndexAnalysisConfig(settings, opts); err != nil {
		if aErr, isAE := analysis.AsAnalysisError(err); isAE {
			return aErr.Status, aErr.ErrType, aErr.Reason
		}
		return http.StatusBadRequest, "illegal_argument_exception", err.Error()
	}
	return 0, "", ""
}

func reverseRunesR62Search(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func (s *Server) evaluatePhraseSuggestR62Search(
	targets []string,
	primarySchema *schema.IndexSchema,
	ps *esast.PhraseSuggestSpec,
	text string,
	rawDocStrings []string,
	tokenizeWords func(string) []string,
	levenshtein func(string, string) int,
) ([]map[string]any, int, string, string) {
	textRuneLen := len([]rune(text))
	targetIdx := ""
	if len(targets) > 0 {
		targetIdx = targets[0]
	}
	var cfg *analysis.IndexAnalysisConfig
	if s != nil && targetIdx != "" {
		cfg, _ = s.buildIndexAnalysisConfigR62Admin(targetIdx)
	}
	anName := strings.TrimSpace(ps.Analyzer)
	if anName == "" && primarySchema != nil {
		b := primarySchema.ResolveField(ps.Field)
		anName = strings.TrimSpace(b.SearchAnalyzer)
		if anName == "" {
			anName = strings.TrimSpace(b.Analyzer)
		}
		if anName == "" {
			if rawProp, okP := lookupRawPropertyWithMultiFieldR61Search(primarySchema, ps.Field); okP {
				anName = strings.TrimSpace(rawProp.SearchAnalyzer)
				if anName == "" {
					anName = strings.TrimSpace(rawProp.Analyzer)
				}
			}
		}
	}

	hasBigrams := false
	emitsUnigrams := true
	if cfg != nil && anName != "" {
		if anDef, okA := cfg.AnalyzerDefs[anName]; okA && anDef != nil {
			var filterNames []string
			switch fv := anDef["filter"].(type) {
			case []any:
				for _, el := range fv {
					filterNames = append(filterNames, fmt.Sprintf("%v", el))
				}
			case []string:
				filterNames = append(filterNames, fv...)
			case string:
				filterNames = append(filterNames, fv)
			}
			for _, fn := range filterNames {
				if fDef, okF := cfg.FilterDefs[fn]; okF && fDef != nil {
					ft := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", fDef["type"])))
					if ft == "shingle" {
						if ou, hasOU := parseOptionalBoolAny(fDef["output_unigrams"]); hasOU && !ou {
							emitsUnigrams = false
						} else {
							hasBigrams = true
						}
					}
				}
			}
		}
	}

	if !emitsUnigrams {
		if ps.ForceUnigrams == nil || *ps.ForceUnigrams {
			return nil, http.StatusBadRequest, "search_phase_execution_exception",
				fmt.Sprintf("all_shards_failed|illegal_argument_exception|Analyzer [%s] cannot be used since it doesn't emit unigrams", anName)
		}
		return []map[string]any{
			{
				"text":    text,
				"offset":  0,
				"length":  textRuneLen,
				"options": []map[string]any{},
			},
		}, 0, "", ""
	}

	useReverse := false
	suggestAlways := false
	hasDirectGen := len(ps.DirectGenerator) > 0
	for _, dg := range ps.DirectGenerator {
		if strings.EqualFold(fmt.Sprintf("%v", dg["pre_filter"]), "reverse") &&
			strings.EqualFold(fmt.Sprintf("%v", dg["post_filter"]), "reverse") {
			useReverse = true
		}
		if strings.EqualFold(fmt.Sprintf("%v", dg["suggest_mode"]), "always") {
			suggestAlways = true
		}
	}

	limit := ps.Size
	if limit <= 0 {
		limit = 5
	}
	vocabFreq := make(map[string]int)
	bigramFreq := make(map[string]int)
	for _, str := range rawDocStrings {
		ws := tokenizeWords(str)
		for idx, w := range ws {
			vocabFreq[w]++
			if idx+1 < len(ws) {
				bigramFreq[w+" "+ws[idx+1]]++
			}
		}
	}

	words := tokenizeWords(text)
	if len(words) == 0 {
		return []map[string]any{
			{
				"text":    text,
				"offset":  0,
				"length":  textRuneLen,
				"options": []map[string]any{},
			},
		}, 0, "", ""
	}

	type wordCand struct {
		word string
		dist int
		freq int
	}
	perPos := make([][]wordCand, len(words))
	for i, w := range words {
		if !suggestAlways && vocabFreq[w] > 0 {
			perPos[i] = []wordCand{{word: w, dist: 0, freq: vocabFreq[w]}}
			continue
		}
		var cands []wordCand
		if vocabFreq[w] > 0 {
			cands = append(cands, wordCand{word: w, dist: 0, freq: vocabFreq[w]})
		}
		wCheck := w
		if useReverse {
			wCheck = reverseRunesR62Search(w)
		}
		wRunes := []rune(wCheck)
		for cand, freq := range vocabFreq {
			if cand == w {
				continue
			}
			cCheck := cand
			if useReverse {
				cCheck = reverseRunesR62Search(cand)
			}
			cRunes := []rune(cCheck)
			if hasDirectGen && len(wRunes) > 0 && len(cRunes) > 0 && wRunes[0] != cRunes[0] {
				continue
			}
			d := levenshtein(wCheck, cCheck)
			if d > 0 && d <= 2 {
				cands = append(cands, wordCand{word: cand, dist: d, freq: freq})
			}
		}
		sort.Slice(cands, func(a, b int) bool {
			if cands[a].dist != cands[b].dist {
				return cands[a].dist < cands[b].dist
			}
			if cands[a].freq != cands[b].freq {
				return cands[a].freq > cands[b].freq
			}
			return cands[a].word < cands[b].word
		})
		if len(cands) > 5 {
			cands = cands[:5]
		}
		if len(cands) == 0 {
			cands = []wordCand{{word: w, dist: 0, freq: 0}}
		}
		perPos[i] = cands
	}

	preTag, postTag := "<em>", "</em>"
	if ps.Highlight != nil {
		if ps.Highlight.PreTag != "" {
			preTag = ps.Highlight.PreTag
		}
		if ps.Highlight.PostTag != "" {
			postTag = ps.Highlight.PostTag
		}
	}

	type phraseOpt struct {
		text        string
		highlighted string
		score       float64
	}
	var phraseOpts []phraseOpt
	origJoined := strings.Join(words, " ")
	cur := make([]wordCand, len(words))
	var dfs func(pos int)
	dfs = func(pos int) {
		if len(phraseOpts) >= 256 {
			return
		}
		if pos == len(words) {
			parts := make([]string, len(words))
			hlParts := make([]string, len(words))
			var totalSim float64
			for idx, c := range cur {
				parts[idx] = c.word
				if c.word != words[idx] {
					hlParts[idx] = preTag + c.word + postTag
				} else {
					hlParts[idx] = c.word
				}
				maxL := len([]rune(words[idx]))
				if cl := len([]rune(c.word)); cl > maxL {
					maxL = cl
				}
				if maxL < 1 {
					maxL = 1
				}
				sim := 1.0 - float64(c.dist)/float64(maxL)
				totalSim += sim
			}
			joined := strings.Join(parts, " ")
			if joined == origJoined {
				return
			}
			sc := totalSim / float64(len(words))
			if hasBigrams {
				for idx := 0; idx+1 < len(parts); idx++ {
					if bf := bigramFreq[parts[idx]+" "+parts[idx+1]]; bf > 0 {
						sc += 0.1 * float64(bf)
					}
				}
			}
			sc = math.Round(sc*1e6) / 1e6
			phraseOpts = append(phraseOpts, phraseOpt{
				text:        joined,
				highlighted: strings.Join(hlParts, " "),
				score:       sc,
			})
			return
		}
		for _, c := range perPos[pos] {
			cur[pos] = c
			dfs(pos + 1)
		}
	}
	dfs(0)

	sort.Slice(phraseOpts, func(i, j int) bool {
		if math.Abs(phraseOpts[i].score-phraseOpts[j].score) > 1e-9 {
			return phraseOpts[i].score > phraseOpts[j].score
		}
		return phraseOpts[i].text < phraseOpts[j].text
	})
	if len(phraseOpts) > limit {
		phraseOpts = phraseOpts[:limit]
	}

	opts := make([]map[string]any, 0, len(phraseOpts))
	for _, po := range phraseOpts {
		opt := map[string]any{
			"text":  po.text,
			"score": po.score,
		}
		if ps.Highlight != nil {
			opt["highlighted"] = po.highlighted
		}
		opts = append(opts, opt)
	}
	return []map[string]any{
		{
			"text":    text,
			"offset":  0,
			"length":  textRuneLen,
			"options": opts,
		},
	}, 0, "", ""
}

func extractSAYTBoolPrefixQueryStringR62Search(q *esast.Query, baseField string) (string, bool) {
	if q == nil {
		return "", false
	}
	if len(q.MatchBoolPrefix) == 1 {
		for f, pe := range q.MatchBoolPrefix {
			clean := f
			if idx := strings.IndexByte(clean, '^'); idx >= 0 {
				clean = clean[:idx]
			}
			if clean == baseField {
				return pe.Query, true
			}
		}
	}
	if q.MultiMatch != nil && strings.EqualFold(strings.TrimSpace(q.MultiMatch.Type), "bool_prefix") && q.MultiMatch.Query != nil {
		matched := len(q.MultiMatch.Fields) == 0
		for _, f := range q.MultiMatch.Fields {
			clean := f
			if idx := strings.IndexByte(clean, '^'); idx >= 0 {
				clean = clean[:idx]
			}
			for _, sfx := range []string{"._2gram", "._3gram", "._4gram", "._index_prefix"} {
				clean = strings.TrimSuffix(clean, sfx)
			}
			if clean == baseField || matchWildcardPattern(clean, baseField) {
				matched = true
				break
			}
		}
		if matched {
			return fmt.Sprintf("%v", q.MultiMatch.Query), true
		}
	}
	return "", false
}

type wordSpanR62Search struct {
	lower string
	start int
	end   int
}

func scanWordSpansR62Search(s string) []wordSpanR62Search {
	var out []wordSpanR62Search
	inWord := false
	wordStart := 0
	for idx, r := range s {
		isWordChar := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r > 127
		if isWordChar {
			if !inWord {
				inWord = true
				wordStart = idx
			}
		} else if inWord {
			out = append(out, wordSpanR62Search{
				lower: strings.ToLower(s[wordStart:idx]),
				start: wordStart,
				end:   idx,
			})
			inWord = false
		}
	}
	if inWord {
		out = append(out, wordSpanR62Search{
			lower: strings.ToLower(s[wordStart:]),
			start: wordStart,
			end:   len(s),
		})
	}
	return out
}

func highlightSAYTBoolPrefixR62Search(
	q *esast.Query,
	field string,
	vals []string,
	preTag, postTag string,
	htmlEscape bool,
	hitSchema *schema.IndexSchema,
) ([]string, bool) {
	if hitSchema == nil || strings.HasSuffix(field, "._index_prefix") {
		return nil, false
	}
	b := hitSchema.ResolveField(field)
	if b.ESType != "search_as_you_type" {
		return nil, false
	}
	baseField := field
	gramN := 1
	switch {
	case strings.HasSuffix(field, "._2gram"):
		baseField = strings.TrimSuffix(field, "._2gram")
		gramN = 2
	case strings.HasSuffix(field, "._3gram"):
		baseField = strings.TrimSuffix(field, "._3gram")
		gramN = 3
	case strings.HasSuffix(field, "._4gram"):
		baseField = strings.TrimSuffix(field, "._4gram")
		gramN = 4
	}
	qStr, ok := extractSAYTBoolPrefixQueryStringR62Search(q, baseField)
	if !ok {
		return nil, false
	}
	qTokens := scanWordSpansR62Search(qStr)
	if len(qTokens) == 0 {
		return nil, true
	}
	complete := qTokens[:len(qTokens)-1]
	if len(complete) < gramN {
		return nil, true
	}

	var targetGrams [][]string
	if gramN == 1 {
		for _, w := range complete {
			targetGrams = append(targetGrams, []string{w.lower})
		}
	} else {
		for k := 0; k <= len(complete)-gramN; k++ {
			seq := make([]string, gramN)
			for j := 0; j < gramN; j++ {
				seq[j] = complete[k+j].lower
			}
			targetGrams = append(targetGrams, seq)
		}
	}

	type byteRange struct{ s, e int }
	var frags []string
	for _, val := range vals {
		docWords := scanWordSpansR62Search(val)
		if len(docWords) < gramN {
			continue
		}
		var spans []byteRange
		for i := 0; i <= len(docWords)-gramN; i++ {
			matched := false
			for _, tg := range targetGrams {
				eq := true
				for j := 0; j < gramN; j++ {
					if docWords[i+j].lower != tg[j] {
						eq = false
						break
					}
				}
				if eq {
					matched = true
					break
				}
			}
			if matched {
				spans = append(spans, byteRange{s: docWords[i].start, e: docWords[i+gramN-1].end})
			}
		}
		if len(spans) == 0 {
			continue
		}
		var merged []byteRange
		for _, sp := range spans {
			if len(merged) > 0 && ((gramN >= 2 && sp.s <= merged[len(merged)-1].e) || (gramN == 1 && sp.s < merged[len(merged)-1].e)) {
				if sp.e > merged[len(merged)-1].e {
					merged[len(merged)-1].e = sp.e
				}
			} else {
				merged = append(merged, sp)
			}
		}
		esc := func(part string) string {
			if !htmlEscape {
				return part
			}
			r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
			return r.Replace(part)
		}
		var sb strings.Builder
		pos := 0
		for _, sp := range merged {
			sb.WriteString(esc(val[pos:sp.s]))
			sb.WriteString(preTag)
			sb.WriteString(esc(val[sp.s:sp.e]))
			sb.WriteString(postTag)
			pos = sp.e
		}
		sb.WriteString(esc(val[pos:]))
		frags = append(frags, sb.String())
	}
	return frags, true
}

// ============================================================================
// Wave-3 Cluster 2: RRF Execution, Explain & Profile + DFS/Cardinality/Joining Polish
// ============================================================================

func hasJoiningQueryInSearchRequestR62Search(req *esast.SearchRequest) bool {
	if req == nil {
		return false
	}
	return queryContainsJoiningR62Search(req.Query) || queryContainsJoiningR62Search(req.PostFilter)
}

func queryContainsJoiningR62Search(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.HasChild != nil || q.HasParent != nil || q.ParentID != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsJoiningR62Search(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsJoiningR62Search(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsJoiningR62Search(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryContainsJoiningR62Search(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryContainsJoiningR62Search(&q.ConstantScore.Filter) {
		return true
	}
	if q.FunctionScore != nil && queryContainsJoiningR62Search(q.FunctionScore.Query) {
		return true
	}
	if q.ScriptScore != nil && queryContainsJoiningR62Search(q.ScriptScore.Query) {
		return true
	}
	if q.Boosting != nil && (queryContainsJoiningR62Search(&q.Boosting.Positive) || queryContainsJoiningR62Search(&q.Boosting.Negative)) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsJoiningR62Search(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	return false
}

func searchReqHasInnerHitsR62Search(req *esast.SearchRequest) bool {
	if req == nil {
		return false
	}
	if req.Collapse != nil && len(req.Collapse.InnerHits) > 0 {
		return true
	}
	for i := range req.KNN {
		if req.KNN[i].InnerHits != nil {
			return true
		}
	}
	return queryContainsInnerHitsR62Search(req.Query)
}

func queryContainsInnerHitsR62Search(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Nested != nil {
		if q.Nested.InnerHits != nil || queryContainsInnerHitsR62Search(&q.Nested.Query) {
			return true
		}
	}
	if q.HasChild != nil {
		if q.HasChild.InnerHits != nil || queryContainsInnerHitsR62Search(&q.HasChild.Query) {
			return true
		}
	}
	if q.HasParent != nil {
		if q.HasParent.InnerHits != nil || queryContainsInnerHitsR62Search(&q.HasParent.Query) {
			return true
		}
	}
	if q.KNN != nil && q.KNN.InnerHits != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsInnerHitsR62Search(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsInnerHitsR62Search(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsInnerHitsR62Search(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryContainsInnerHitsR62Search(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryContainsInnerHitsR62Search(&q.ConstantScore.Filter) {
		return true
	}
	if q.FunctionScore != nil && queryContainsInnerHitsR62Search(q.FunctionScore.Query) {
		return true
	}
	if q.ScriptScore != nil && queryContainsInnerHitsR62Search(q.ScriptScore.Query) {
		return true
	}
	return false
}

func attachEmptyAggMetasR62Search(aggsOut map[string]any, aggs map[string]esast.AggSpec) {
	if len(aggsOut) == 0 || len(aggs) == 0 {
		return
	}
	for aggName, spec := range aggs {
		obj, ok := aggsOut[aggName].(map[string]any)
		if !ok || obj == nil {
			continue
		}
		if spec.Meta != nil {
			if _, exists := obj["meta"]; !exists {
				obj["meta"] = spec.Meta
			}
		}
		subAggs := spec.SubAggs()
		if len(subAggs) == 0 {
			continue
		}
		attachEmptyAggMetasR62Search(obj, subAggs)
		switch bs := obj["buckets"].(type) {
		case []map[string]any:
			for _, bm := range bs {
				attachEmptyAggMetasR62Search(bm, subAggs)
			}
		case []any:
			for _, el := range bs {
				if bm, okM := el.(map[string]any); okM {
					attachEmptyAggMetasR62Search(bm, subAggs)
				}
			}
		case map[string]any:
			for _, v := range bs {
				if bm, okM := v.(map[string]any); okM {
					attachEmptyAggMetasR62Search(bm, subAggs)
				}
			}
		}
	}
}

func replaceAutoDateAggRowsAcrossIndicesR62Search(
	existing []AggRow,
	aggs map[string]esast.AggSpec,
	allHits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
) []AggRow {
	var autoNames map[string]esast.AggSpec
	for name, spec := range aggs {
		if spec.AutoDateHistogram != nil {
			if autoNames == nil {
				autoNames = make(map[string]esast.AggSpec)
			}
			autoNames[name] = spec
		}
	}
	if len(autoNames) == 0 {
		return existing
	}
	docs := make([]runtimeMatchedDoc, 0, len(allHits))
	for _, h := range allHits {
		hSc := schemasByIndex[h.Index]
		if hSc == nil {
			hSc = h.Schema
		}
		if hSc == nil {
			hSc = primarySchema
		}
		hCopy := h
		hCopy.Schema = hSc
		docs = append(docs, runtimeMatchedDoc{
			hit: hCopy,
			doc: decodeHitDocMapRound60(h),
		})
	}
	filtered := make([]AggRow, 0, len(existing))
	for _, r := range existing {
		drop := false
		for an := range autoNames {
			if r.AggName == an || strings.HasPrefix(r.AggName, an+".") || strings.HasPrefix(r.AggName, transpiler.RawValuesAggPrefix+an) {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, r)
		}
	}
	for an, spec := range autoNames {
		emitRuntimeAutoDateHistogramAggRowsR62Search(an, "", spec, docs, &filtered, primarySchema)
	}
	return filtered
}

func enrichSearchProfilePayloadWithReqR62Search(
	s *Server,
	httpReq *http.Request,
	targets []string,
	profilePayload map[string]any,
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
	aggsOut map[string]any,
	matchedDocCount int64,
	allHits []HitRow,
) map[string]any {
	out := enrichSearchProfilePayloadR62Search(profilePayload, idxSchema, req, aggsOut, matchedDocCount, allHits)
	if out == nil || httpReq == nil || httpReq.URL == nil {
		return out
	}
	if !strings.EqualFold(strings.TrimSpace(httpReq.URL.Query().Get("search_type")), "dfs_query_then_fetch") {
		return out
	}
	shards, ok := out["shards"].([]map[string]any)
	if !ok || len(shards) == 0 {
		return out
	}
	baseShard := shards[0]
	nodeID, _ := baseShard["node_id"].(string)
	if nodeID == "" {
		nodeID = "doris-es-proxy-node-01"
	}
	dfsStats := map[string]any{
		"type":          "statistics",
		"description":   "collect term statistics",
		"time_in_nanos": int64(50),
		"breakdown": map[string]any{
			"collect_term_stats":       int64(25),
			"collect_term_stats_count": int64(1),
		},
	}
	cloneShardForIdx := func(tIdx string, shardNum int) map[string]any {
		cp := make(map[string]any, len(baseShard)+1)
		for k, v := range baseShard {
			cp[k] = v
		}
		cp["index"] = tIdx
		cp["shard_id"] = shardNum
		cp["id"] = fmt.Sprintf("[%s][%s][%d]", nodeID, tIdx, shardNum)
		dfsMap := make(map[string]any)
		if existingDFS, okD := baseShard["dfs"].(map[string]any); okD {
			for k, v := range existingDFS {
				dfsMap[k] = v
			}
		}
		dfsMap["statistics"] = dfsStats
		cp["dfs"] = dfsMap
		return cp
	}
	var expanded []map[string]any
	effTargets := targets
	if len(effTargets) == 0 {
		if idxStr, _ := baseShard["index"].(string); idxStr != "" {
			effTargets = []string{idxStr}
		}
	}
	for _, tName := range effTargets {
		nShards := 1
		if s != nil {
			ns, _, _ := s.getIndexShardAndReplicaCounts(tName)
			if ns > 0 {
				nShards = ns
			}
		}
		for sh := 0; sh < nShards; sh++ {
			expanded = append(expanded, cloneShardForIdx(tName, sh))
		}
	}
	if len(expanded) > 0 {
		out["shards"] = expanded
	}
	return out
}

type rrfSubRetrieverSpecR62Search struct {
	isTopKNN bool
	query    *esast.Query
	knn      *esast.KNNQuery
	name     string
}

func unwrapRRFRetrieverR62Search(ret *esast.RetrieverSpec) *esast.RRFRetrieverSpec {
	if ret == nil {
		return nil
	}
	if ret.RRF != nil {
		return ret.RRF
	}
	if ret.Rule != nil {
		return unwrapRRFRetrieverR62Search(ret.Rule.Retriever)
	}
	if ret.TextSimilarityReranker != nil {
		return unwrapRRFRetrieverR62Search(ret.TextSimilarityReranker.Retriever)
	}
	return nil
}

func extractSubRetrieverQueryNameR62Search(q *esast.Query) string {
	if q == nil {
		return ""
	}
	if strings.TrimSpace(q.Name) != "" {
		return strings.TrimSpace(q.Name)
	}
	if q.KNN != nil && strings.TrimSpace(q.KNN.Name) != "" {
		return strings.TrimSpace(q.KNN.Name)
	}
	return ""
}

func applyRRFFilterToQueryR62Search(q *esast.Query, filter *esast.Query) *esast.Query {
	if filter == nil {
		return q
	}
	if q == nil {
		cp := *filter
		return &cp
	}
	return &esast.Query{
		Name: q.Name,
		Bool: &esast.BoolQuery{
			Must:   esast.QuerySlice{*q},
			Filter: esast.QuerySlice{*filter},
		},
	}
}

func (s *Server) executeRRFSearchR62Search(
	ctx context.Context,
	httpReq *http.Request,
	rawIndexPattern string,
	targets []string,
	req *esast.SearchRequest,
	start time.Time,
) (map[string]any, int, string, string) {
	rrfCfg := req.Rank.RRF
	size := 10
	if req.Size != nil {
		size = *req.Size
	}
	from := 0
	if req.From != nil && *req.From > 0 {
		from = *req.From
	}
	windowSize := 100
	if size > windowSize {
		windowSize = size
	}
	if rrfCfg.WindowSize != nil && *rrfCfg.WindowSize > 0 {
		windowSize = *rrfCfg.WindowSize
	}
	if windowSize < size {
		return nil, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("[rank] requires [rank_window_size: %d] be greater than or equal to [size: %d]", windowSize, size)
	}
	rankConstant := 60
	if rrfCfg.RankConstant != nil && *rrfCfg.RankConstant >= 1 {
		rankConstant = *rrfCfg.RankConstant
	}

	var subs []rrfSubRetrieverSpecR62Search
	var globalFilter *esast.Query
	if rrfCfg.Filter != nil {
		cpF := *rrfCfg.Filter
		globalFilter = &cpF
	}
	if rrfRet := unwrapRRFRetrieverR62Search(req.Retriever); rrfRet != nil {
		if len(rrfRet.Filter) == 1 {
			f0 := rrfRet.Filter[0]
			globalFilter = &f0
		} else if len(rrfRet.Filter) > 1 {
			cpSlice := append([]esast.Query(nil), rrfRet.Filter...)
			globalFilter = &esast.Query{Bool: &esast.BoolQuery{Filter: esast.QuerySlice(cpSlice)}}
		}
		var collectRet func(node *esast.RetrieverSpec)
		collectRet = func(node *esast.RetrieverSpec) {
			if node == nil {
				return
			}
			switch {
			case node.Standard != nil:
				var q *esast.Query
				std := node.Standard
				if len(std.Filter) == 0 {
					if std.Query != nil {
						cpQ := *std.Query
						q = &cpQ
					} else {
						q = &esast.Query{MatchAll: map[string]any{}}
					}
				} else {
					bq := &esast.BoolQuery{Filter: std.Filter}
					name := ""
					if std.Query != nil {
						bq.Must = esast.QuerySlice{*std.Query}
						name = extractSubRetrieverQueryNameR62Search(std.Query)
					}
					q = &esast.Query{Name: name, Bool: bq}
				}
				subs = append(subs, rrfSubRetrieverSpecR62Search{
					isTopKNN: false,
					query:    applyRRFFilterToQueryR62Search(q, globalFilter),
					name:     extractSubRetrieverQueryNameR62Search(std.Query),
				})
			case node.KNN != nil:
				k := node.KNN
				knnSpec := esast.KNNQuery{
					Field:              k.Field,
					QueryVector:        k.QueryVector,
					QueryVectorHex:     k.QueryVectorHex,
					QueryVectorFromHex: k.QueryVectorFromHex,
					QueryVectorBuilder: k.QueryVectorBuilder,
					K:                  k.K,
					HasK:               k.HasK,
					NumCandidates:      k.NumCandidates,
					HasNumCandidates:   k.HasNumCandidates,
					Filter:             append(esast.QuerySlice(nil), k.Filter...),
					Similarity:         k.Similarity,
					Boost:              k.Boost,
					InnerHits:          k.InnerHits,
					Name:               k.Name,
				}
				if globalFilter != nil {
					knnSpec.Filter = append(knnSpec.Filter, *globalFilter)
				}
				subs = append(subs, rrfSubRetrieverSpecR62Search{
					isTopKNN: true,
					knn:      &knnSpec,
					name:     strings.TrimSpace(k.Name),
				})
			case node.RRF != nil:
				for i := range node.RRF.Retrievers {
					collectRet(&node.RRF.Retrievers[i])
				}
			case node.Rule != nil:
				collectRet(node.Rule.Retriever)
			case node.TextSimilarityReranker != nil:
				collectRet(node.TextSimilarityReranker.Retriever)
			}
		}
		for i := range rrfRet.Retrievers {
			collectRet(&rrfRet.Retrievers[i])
		}
	} else if len(req.SubSearches) > 0 {
		for _, ss := range req.SubSearches {
			name := strings.TrimSpace(ss.Name)
			if name == "" {
				name = extractSubRetrieverQueryNameR62Search(ss.Query)
			}
			subs = append(subs, rrfSubRetrieverSpecR62Search{
				isTopKNN: false,
				query:    applyRRFFilterToQueryR62Search(ss.Query, globalFilter),
				name:     name,
			})
		}
		for i := range req.KNN {
			kq := req.KNN[i]
			kq.Filter = append(esast.QuerySlice(nil), kq.Filter...)
			if globalFilter != nil {
				kq.Filter = append(kq.Filter, *globalFilter)
			}
			subs = append(subs, rrfSubRetrieverSpecR62Search{
				isTopKNN: true,
				knn:      &kq,
				name:     strings.TrimSpace(kq.Name),
			})
		}
	} else {
		if req.Query != nil {
			subs = append(subs, rrfSubRetrieverSpecR62Search{
				isTopKNN: false,
				query:    applyRRFFilterToQueryR62Search(req.Query, globalFilter),
				name:     extractSubRetrieverQueryNameR62Search(req.Query),
			})
		}
		for i := range req.KNN {
			kq := req.KNN[i]
			kq.Filter = append(esast.QuerySlice(nil), kq.Filter...)
			if globalFilter != nil {
				kq.Filter = append(kq.Filter, *globalFilter)
			}
			subs = append(subs, rrfSubRetrieverSpecR62Search{
				isTopKNN: true,
				knn:      &kq,
				name:     strings.TrimSpace(kq.Name),
			})
		}
	}

	type rrfSubDocRank struct {
		rank1Based int
		contrib32  float32
		explain    map[string]any
	}
	type rrfDocEntry struct {
		key            string
		hitMap         map[string]any
		score32        float32
		firstSeenOrder int
		subRanks       map[int]rrfSubDocRank
	}

	docEntries := make(map[string]*rrfDocEntry)
	var orderedEntries []*rrfDocEntry
	allMatchedIDsByIndex := make(map[string][]string)
	seenGlobalDocKeys := make(map[string]bool)
	seenOrderSeq := 0

	var topDFSQueries []esast.KNNQuery
	for subIdx, sub := range subs {
		zero := 0
		subFetch := windowSize
		if !sub.isTopKNN {
			if sub.query != nil && sub.query.KNN != nil {
				if sub.query.KNN.HasK && sub.query.KNN.K > 0 {
					subFetch = sub.query.KNN.K
				} else if sub.query.KNN.NumCandidates > 0 && sub.query.KNN.NumCandidates < subFetch {
					subFetch = sub.query.KNN.NumCandidates
				}
			} else if subFetch < 10000 {
				subFetch = 10000
			}
		} else if sub.knn != nil {
			topDFSQueries = append(topDFSQueries, *sub.knn)
			if sub.knn.HasK && sub.knn.K > 0 {
				subFetch = sub.knn.K
			} else if sub.knn.NumCandidates > 0 {
				subFetch = sub.knn.NumCandidates
			}
		}
		subReq := *req
		subReq.Retriever = nil
		subReq.Rank = nil
		subReq.SubSearches = nil
		subReq.Aggs = nil
		subReq.Aggregations = nil
		subReq.Suggest = nil
		subReq.Profile = false
		subReq.From = &zero
		subReq.Size = &subFetch
		if sub.isTopKNN && sub.knn != nil {
			kqCopy := *sub.knn
			if !kqCopy.HasK || kqCopy.K <= 0 {
				kqCopy.K = subFetch
				kqCopy.HasK = true
			}
			if !kqCopy.HasNumCandidates || kqCopy.NumCandidates < kqCopy.K {
				kqCopy.NumCandidates = kqCopy.K
				kqCopy.HasNumCandidates = true
			}
			subReq.Query = nil
			subReq.KNN = esast.KNNSlice{kqCopy}
		} else {
			subReq.Query = sub.query
			subReq.KNN = nil
		}

		subResp, st, eType, eReason := s.executeSearchRequest(ctx, rawIndexPattern, &subReq)
		if st != http.StatusOK {
			return subResp, st, eType, eReason
		}
		hitsObj, _ := subResp["hits"].(map[string]any)
		var subHits []map[string]any
		if hitsObj != nil {
			if hs, okS := hitsObj["hits"].([]map[string]any); okS {
				subHits = hs
			} else if ha, okA := hitsObj["hits"].([]any); okA {
				for _, el := range ha {
					if m, okM := el.(map[string]any); okM {
						subHits = append(subHits, m)
					}
				}
			}
		}
		for idxInSub, hm := range subHits {
			hIdx, _ := hm["_index"].(string)
			hID, _ := hm["_id"].(string)
			dKey := hIdx + "\x00" + hID
			if !seenGlobalDocKeys[dKey] {
				seenGlobalDocKeys[dKey] = true
				allMatchedIDsByIndex[hIdx] = append(allMatchedIDsByIndex[hIdx], hID)
			}
			if idxInSub >= windowSize {
				continue
			}
			ent, exists := docEntries[dKey]
			if !exists {
				cpHit := make(map[string]any, len(hm)+2)
				for k, v := range hm {
					cpHit[k] = v
				}
				ent = &rrfDocEntry{
					key:            dKey,
					hitMap:         cpHit,
					firstSeenOrder: seenOrderSeq,
					subRanks:       make(map[int]rrfSubDocRank),
				}
				seenOrderSeq++
				docEntries[dKey] = ent
				orderedEntries = append(orderedEntries, ent)
			}
			r1 := idxInSub + 1
			c32 := float32(1.0 / float64(rankConstant+r1))
			ent.score32 += c32
			var subExp map[string]any
			if req.Explain {
				if rawExp, okE := hm["_explanation"].(map[string]any); okE && rawExp != nil {
					subExp = rawExp
				}
				isKNNSub := sub.isTopKNN || (sub.query != nil && sub.query.KNN != nil)
				if isKNNSub {
					effTopK := subFetch
					scVal := 0.0
					if sv, okF := toFloat64(hm["_score"]); okF {
						scVal = sv
					} else if subExp != nil {
						scVal, _ = toFloat64(subExp["value"])
					}
					subExp = map[string]any{
						"value":       scVal,
						"description": fmt.Sprintf("within top %d", effTopK),
						"details":     []map[string]any{},
					}
				} else if subExp == nil {
					scVal, _ := toFloat64(hm["_score"])
					subExp = map[string]any{
						"value":       scVal,
						"description": "match",
						"details":     []map[string]any{},
					}
				}
			}
			ent.subRanks[subIdx] = rrfSubDocRank{
				rank1Based: r1,
				contrib32:  c32,
				explain:    subExp,
			}
		}
	}

	sort.SliceStable(orderedEntries, func(i, j int) bool {
		if orderedEntries[i].score32 != orderedEntries[j].score32 {
			return orderedEntries[i].score32 > orderedEntries[j].score32
		}
		return orderedEntries[i].firstSeenOrder < orderedEntries[j].firstSeenOrder
	})
	if len(orderedEntries) > windowSize {
		orderedEntries = orderedEntries[:windowSize]
	}

	var pagedEntries []*rrfDocEntry
	if from < len(orderedEntries) && size > 0 {
		end := from + size
		if end > len(orderedEntries) {
			end = len(orderedEntries)
		}
		pagedEntries = orderedEntries[from:end]
	}

	outHits := make([]map[string]any, 0, len(pagedEntries))
	for i, ent := range pagedEntries {
		hm := ent.hitMap
		hm["_score"] = nil
		hm["_rank"] = from + i + 1
		if req.Explain {
			details := make([]map[string]any, 0, len(subs))
			for m, sub := range subs {
				label := sub.name
				if label == "" {
					label = fmt.Sprintf("at index [%d]", m)
				}
				if sr, okFound := ent.subRanks[m]; okFound {
					cStr := strconv.FormatFloat(float64(sr.contrib32), 'f', -1, 32)
					var detSlice []map[string]any
					if sr.explain != nil {
						detSlice = []map[string]any{sr.explain}
					} else {
						detSlice = []map[string]any{}
					}
					details = append(details, map[string]any{
						"value":       sr.rank1Based,
						"description": fmt.Sprintf("rrf score: [%s], rank [%d] from sub-retriever [%s]", cStr, sr.rank1Based, label),
						"details":     detSlice,
					})
				} else {
					details = append(details, map[string]any{
						"value":       0,
						"description": fmt.Sprintf("rrf score: [0], result not found in sub-retriever [%s]", label),
						"details":     []map[string]any{},
					})
				}
			}
			totStr := strconv.FormatFloat(float64(ent.score32), 'f', -1, 32)
			hm["_explanation"] = map[string]any{
				"value":       float64(ent.score32),
				"description": fmt.Sprintf("rrf score: [%s] with rank_constant [%d]", totStr, rankConstant),
				"details":     details,
			}
		} else {
			delete(hm, "_explanation")
		}
		outHits = append(outHits, hm)
	}

	totalMatched := int64(len(seenGlobalDocKeys))
	var aggsOut map[string]any
	if len(req.EffectiveAggs()) > 0 {
		var allIDs []string
		for _, ids := range allMatchedIDsByIndex {
			allIDs = append(allIDs, ids...)
		}
		zero := 0
		aggReq := *req
		aggReq.Retriever = nil
		aggReq.Rank = nil
		aggReq.SubSearches = nil
		aggReq.KNN = nil
		aggReq.Explain = false
		aggReq.Profile = false
		aggReq.From = &zero
		aggReq.Size = &zero
		if len(allIDs) == 0 {
			aggReq.Query = &esast.Query{MatchNone: map[string]any{}}
		} else {
			aggReq.Query = &esast.Query{Ids: &esast.IdsQuery{Values: allIDs}}
		}
		aggResp, st, eType, eReason := s.executeSearchRequest(ctx, rawIndexPattern, &aggReq)
		if st != http.StatusOK {
			return aggResp, st, eType, eReason
		}
		aggsOut, _ = aggResp["aggregations"].(map[string]any)
	}

	totalTargetShards := 0
	for _, tName := range targets {
		nShards, _, _ := s.getIndexShardAndReplicaCounts(tName)
		totalTargetShards += nShards
	}
	if totalTargetShards <= 0 {
		totalTargetShards = 1
	}
	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	var hitsTotalAny any = map[string]any{
		"value":    totalMatched,
		"relation": "eq",
	}
	if req.TrackTotalHits != nil {
		if b, okB := req.TrackTotalHits.(bool); okB && !b {
			hitsTotalAny = nil
		}
	}
	hitsEnv := map[string]any{
		"max_score": nil,
		"hits":      outHits,
	}
	if hitsTotalAny != nil {
		hitsEnv["total"] = hitsTotalAny
	}
	resp := map[string]any{
		"took":      tookMs,
		"timed_out": false,
		"_shards": map[string]any{
			"total":      totalTargetShards,
			"successful": totalTargetShards,
			"skipped":    0,
			"failed":     0,
		},
		"hits": hitsEnv,
	}
	if aggsOut != nil {
		resp["aggregations"] = aggsOut
	}
	if req.Profile {
		primaryIdx := rawIndexPattern
		if len(targets) > 0 && targets[0] != "" {
			primaryIdx = targets[0]
		}
		profReq := *req
		profReq.KNN = topDFSQueries
		prof := buildSearchProfilePayloadR61Search(primaryIdx, &profReq, time.Since(start).Nanoseconds())
		subProfileChildren := make([]map[string]any, 0, len(subs))
		mkBreakdown := func() map[string]any {
			return map[string]any{
				"set_min_competitive_score":       int64(0),
				"set_min_competitive_score_count": int64(0),
				"match":                           int64(0),
				"match_count":                     int64(0),
				"shallow_advance":                 int64(0),
				"shallow_advance_count":           int64(0),
				"compute_max_score":               int64(0),
				"compute_max_score_count":         int64(0),
				"advance":                         int64(0),
				"advance_count":                   int64(0),
				"create_weight":                   int64(10),
				"create_weight_count":             int64(1),
				"build_scorer":                    int64(10),
				"build_scorer_count":              int64(1),
				"next_doc":                        int64(10),
				"next_doc_count":                  int64(1),
				"score":                           int64(10),
				"score_count":                     int64(1),
			}
		}
		for _, sub := range subs {
			cType := "MatchAllDocsQuery"
			cDesc := "*:*"
			switch {
			case sub.isTopKNN && sub.knn != nil:
				cType = "KnnScoreDocQuery"
				cDesc = fmt.Sprintf("KnnScoreDocQuery[%s]", sub.knn.Field)
			case sub.query != nil && sub.query.KNN != nil:
				effC := sub.query.KNN.NumCandidates
				if effC <= 0 {
					effC = max(1, sub.query.KNN.K)
				}
				cType = "DocAndScoreQuery"
				cDesc = fmt.Sprintf("DocAndScore[%d]", effC)
			case sub.query != nil:
				cType, cDesc = describeProfileQueryNodeR61Search(&esast.SearchRequest{Query: sub.query})
			}
			subProfileChildren = append(subProfileChildren, map[string]any{
				"type":          cType,
				"description":   cDesc,
				"time_in_nanos": int64(50),
				"breakdown":     mkBreakdown(),
				"children":      []map[string]any{},
			})
		}
		rrfQueryNode := map[string]any{
			"type":          "ConstantScoreQuery",
			"description":   "ConstantScore(rrf)",
			"time_in_nanos": int64(120),
			"breakdown":     mkBreakdown(),
			"children": []map[string]any{
				{
					"type":          "BooleanQuery",
					"description":   "rrf_boolean",
					"time_in_nanos": int64(100),
					"breakdown":     mkBreakdown(),
					"children":      subProfileChildren,
				},
			},
		}
		if shards, okS := prof["shards"].([]map[string]any); okS && len(shards) > 0 {
			if searches, okSr := shards[0]["searches"].([]map[string]any); okSr && len(searches) > 0 {
				searches[0]["query"] = []map[string]any{rrfQueryNode}
			}
			if len(topDFSQueries) == 0 {
				delete(shards[0], "dfs")
			}
		}
		var pSchema *schema.IndexSchema
		if len(targets) > 0 {
			pSchema = s.getOrCompileReadOnlySchema(ctx, targets[0])
		}
		resp["profile"] = enrichSearchProfilePayloadWithReqR62Search(s, httpReq, targets, prof, pSchema, &profReq, aggsOut, totalMatched, nil)
	}
	return resp, http.StatusOK, "", ""
}
