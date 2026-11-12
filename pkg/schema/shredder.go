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

package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// ShredDocument transforms an Elasticsearch document (`rawSource`) into a flat Doris Stream Load
// JSON row containing `_id`, `_version`, `__DORIS_DELETE_SIGN__`, verbatim `_source`, `_doc` (VARIANT),
// `_all_text`, promoted `f__*` columns, and `n__*` correlated + pre-filter nested array columns.
func ShredDocument(
	s *IndexSchema,
	id string,
	version int64,
	deleted bool,
	rawSource json.RawMessage,
) ([]byte, error) {
	return ShredDocumentWithNow(s, id, version, deleted, rawSource, time.Time{})
}

// ShredDocumentWithNow transforms an Elasticsearch document (`rawSource`) into a flat Doris Stream Load
// JSON row using an explicit `now` timestamp for date math expressions.
func ShredDocumentWithNow(
	s *IndexSchema,
	id string,
	version int64,
	deleted bool,
	rawSource json.RawMessage,
	now time.Time,
) ([]byte, error) {
	if version <= 0 {
		version = 1
	}
	if deleted {
		tombstone := map[string]any{
			"_id":                   id,
			"_version":              version,
			"__DORIS_DELETE_SIGN__": 1,
			"_source":               "{}",
			"_doc":                  map[string]any{},
		}
		return json.Marshal(tombstone)
	}

	trimmed := bytes.TrimSpace(rawSource)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}

	var parsedDoc map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&parsedDoc); err != nil || parsedDoc == nil {
		if err == nil {
			err = fmt.Errorf("expected JSON object")
		}
		return nil, fmt.Errorf("invalid document JSON for _id=%q: %w", id, err)
	}
	prunedDynamic := false
	if s != nil {
		if s.MaxDepth > 0 || s.MaxFieldNameLength > 0 {
			if err := validateDocumentLimits(parsedDoc, 1, s.MaxDepth, s.MaxFieldNameLength); err != nil {
				return nil, err
			}
		}
		if s.MaxNestedObjects > 0 && (len(s.NestedRootSpecs) > 0 || len(s.NestedRoots) > 0) {
			nestedPaths := make(map[string][]string, len(s.NestedRootSpecs)+len(s.NestedRoots))
			for _, nr := range s.NestedRootSpecs {
				nestedPaths[nr.Path] = nr.PathParts
			}
			for np := range s.NestedRoots {
				if _, exists := nestedPaths[np]; !exists {
					nestedPaths[np] = strings.Split(np, ".")
				}
			}
			totalNestedObjs := 0
			for _, parts := range nestedPaths {
				totalNestedObjs += len(extractNestedElementMapsWithIDs(parsedDoc, parts, ""))
			}
			if totalNestedObjs > s.MaxNestedObjects {
				return nil, fmt.Errorf("illegal_argument_exception: The number of nested documents has exceeded the allowed limit of [%d]", s.MaxNestedObjects)
			}
		}
	}
	if s != nil && s.RawMapping != nil {
		var err error
		prunedDynamic, err = validateStrictDynamicObject(parsedDoc, s.RawMapping.Properties, s.RawMapping.Dynamic, s.RawMapping.Subobjects, "")
		if err != nil {
			return nil, err
		}
	}

	row := make(map[string]any, len(s.Fields)+len(s.NestedRoots)+8)
	row["_id"] = id
	row["_version"] = version
	row["__DORIS_DELETE_SIGN__"] = 0
	row["_source"] = string(trimmed)

	getNow := func() time.Time {
		if now.IsZero() {
			now = time.Now().UTC()
		}
		return now
	}

	// Populate promoted scalar, multi-valued array, and nested pre-filter columns
	fieldsToVisit := s.OrderedFields
	if len(fieldsToVisit) == 0 && len(s.Fields) > 0 {
		for _, b := range s.Fields {
			fieldsToVisit = append(fieldsToVisit, b)
		}
	}
	var ignoredFields []string
	ignoredSeen := make(map[string]bool)
	recordIgnored := func(fieldPath string) {
		base := strings.TrimSuffix(fieldPath, ".keyword")
		if base != "" && !ignoredSeen[base] {
			ignoredSeen[base] = true
			ignoredFields = append(ignoredFields, base)
		}
	}
	type deferredDocMutation struct {
		path         []string
		deletePath   bool
		validLeafs   []any
		cleanBinding *FieldBinding
	}
	var deferredMutations []deferredDocMutation
	deferReplacePath := func(path []string, validLeafs []any) {
		deferredMutations = append(deferredMutations, deferredDocMutation{
			path:       path,
			deletePath: false,
			validLeafs: validLeafs,
		})
	}
	deferDeletePath := func(path []string) {
		deferredMutations = append(deferredMutations, deferredDocMutation{
			path:       path,
			deletePath: true,
		})
	}
	deferCleanNestedPath := func(path []string, b FieldBinding) {
		bc := b
		deferredMutations = append(deferredMutations, deferredDocMutation{
			path:         path,
			cleanBinding: &bc,
		})
	}
	if s != nil && len(s.Fields) > 0 {
		aliasFieldKeys := make([]string, 0)
		for k, b := range s.Fields {
			if b.AliasTarget != "" && b.ESFieldPath != "" {
				aliasFieldKeys = append(aliasFieldKeys, k)
			}
		}
		if len(aliasFieldKeys) > 0 {
			sort.Strings(aliasFieldKeys)
			for _, k := range aliasFieldKeys {
				b := s.Fields[k]
				if docHasExplicitFieldPath(parsedDoc, strings.Split(b.ESFieldPath, ".")) {
					return nil, fmt.Errorf("mapper_parsing_exception: Cannot write to a field alias [%s]", b.ESFieldPath)
				}
			}
		}
		flattenedFieldKeys := make([]string, 0)
		for k, b := range s.Fields {
			if b.ESType == "flattened" && b.AliasTarget == "" && !b.EnabledFalse {
				flattenedFieldKeys = append(flattenedFieldKeys, k)
			}
		}
		sort.Strings(flattenedFieldKeys)
		for _, k := range flattenedFieldKeys {
			b := s.Fields[k]
			modified, err := validateAndNormalizeFlattenedFieldInDoc(parsedDoc, b.SourceJSONPath, b, recordIgnored)
			if err != nil {
				if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
					recordIgnored(b.ESFieldPath)
					if deletePathInMap(parsedDoc, b.SourceJSONPath) {
						prunedDynamic = true
					}
					continue
				}
				return nil, err
			}
			if modified {
				prunedDynamic = true
			}
		}
		sparseFieldKeys := make([]string, 0)
		for k, b := range s.Fields {
			if (b.ESType == "sparse_vector" || b.ESType == "rank_features") && b.AliasTarget == "" && !b.EnabledFalse {
				sparseFieldKeys = append(sparseFieldKeys, k)
			}
		}
		sort.Strings(sparseFieldKeys)
		for _, k := range sparseFieldKeys {
			b := s.Fields[k]
			modified, err := validateAndNormalizeSparseVectorFieldInDoc(parsedDoc, b.SourceJSONPath, b)
			if err != nil {
				if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
					recordIgnored(b.ESFieldPath)
					if deletePathInMap(parsedDoc, b.SourceJSONPath) {
						prunedDynamic = true
					}
					continue
				}
				return nil, err
			}
			if modified {
				prunedDynamic = true
			}
		}
	}

	for _, b := range fieldsToVisit {
		if b.EnabledFalse {
			continue
		}
		hasObjAtPath := false
		if isStrictLeafFieldWithoutSubprops(s, b) && hasObjectValueAtPath(parsedDoc, b.SourceJSONPath) {
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				recordIgnored(b.ESFieldPath)
				hasObjAtPath = true
			} else {
				return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", b.ESFieldPath, b.ESType)
			}
		}
		if b.ESType == "constant_keyword" && b.ConstantValue != nil {
			expectedStr := fmt.Sprintf("%v", b.ConstantValue)
			if b.LowercaseNormalizer {
				expectedStr = strings.ToLower(expectedStr)
			}
			rawLeafs := extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
			var validLeafs []any
			hadMalformed := hasObjAtPath
			for _, rv := range rawLeafs {
				if rv == nil {
					continue
				}
				sv := fmt.Sprintf("%v", rv)
				if b.LowercaseNormalizer {
					sv = strings.ToLower(sv)
				}
				if sv != expectedStr {
					if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
						recordIgnored(b.ESFieldPath)
						hadMalformed = true
						continue
					}
					return nil, fmt.Errorf("mapper_parsing_exception: [constant_keyword] field [%s] only accepts value [%s]", b.ESFieldPath, expectedStr)
				}
				validLeafs = append(validLeafs, rv)
			}
			if !hadMalformed || len(validLeafs) > 0 {
				if b.Kind == StoragePromotedArray {
					row[b.ColumnName] = []string{expectedStr}
				} else if b.Kind == StorageNestedSubfield {
					if len(extractNestedElementMapsWithIDs(parsedDoc, strings.Split(b.NestedPath, "."), "")) > 0 {
						row[b.ColumnName] = []string{expectedStr}
					}
				} else if b.ColumnName != "" {
					row[b.ColumnName] = expectedStr
				} else if b.Kind == StorageDynamicVariant && b.NestedPath == "" && len(b.SourceJSONPath) > 0 && len(rawLeafs) == 0 && !hadMalformed {
					deferReplacePath(b.SourceJSONPath, []any{expectedStr})
				}
			}
			if hadMalformed && isPrimaryFieldBinding(b) {
				if len(validLeafs) > 0 {
					if b.Kind == StorageNestedSubfield {
						deferCleanNestedPath(b.SourceJSONPath, b)
					} else {
						deferReplacePath(b.SourceJSONPath, validLeafs)
					}
				} else {
					deferDeletePath(b.SourceJSONPath)
				}
			}
			continue
		}
		switch b.Kind {
		case StoragePromotedScalar:
			if IsTextLikeESType(b.ESType) && b.DorisType == DorisString {
				var val any
				var strs []string
				if b.ESType == "completion" {
					var compErr error
					strs, compErr = extractCompletionStringsWithNull(parsedDoc, b.SourceJSONPath, b.LowercaseNormalizer, b.NullValue)
					if compErr != nil {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							recordIgnored(b.ESFieldPath)
							if isPrimaryFieldBinding(b) {
								deferDeletePath(b.SourceJSONPath)
							}
							continue
						}
						return nil, compErr
					}
				} else {
					strs = extractStringSliceValuesWithNull(parsedDoc, b.SourceJSONPath, b.LowercaseNormalizer, b.NullValue)
				}
				if b.IgnoreAbove > 0 && len(strs) > 0 {
					filtered := strs[:0]
					for _, sv := range strs {
						if len([]rune(sv)) <= b.IgnoreAbove {
							filtered = append(filtered, sv)
						} else if isPrimaryFieldBinding(b) {
							recordIgnored(b.ESFieldPath)
						}
					}
					strs = filtered
				}
				if len(strs) >= 1 {
					val = strings.Join(strs, " ")
				}
				if val == nil && b.NullValue != nil && hasExplicitNullAtPath(parsedDoc, b.SourceJSONPath) {
					nullStr := fmt.Sprintf("%v", b.NullValue)
					if b.IgnoreAbove <= 0 || len([]rune(nullStr)) <= b.IgnoreAbove {
						val = b.NullValue
					}
				}
				if val != nil {
					if coerced := coerceScalarBindingForDoris(val, b, getNow()); coerced != nil {
						row[b.ColumnName] = coerced
					}
				}
				if hasObjAtPath && isPrimaryFieldBinding(b) {
					if len(strs) > 0 {
						validLeafs := make([]any, 0, len(strs))
						for _, sv := range strs {
							validLeafs = append(validLeafs, sv)
						}
						deferReplacePath(b.SourceJSONPath, validLeafs)
					} else {
						deferDeletePath(b.SourceJSONPath)
					}
				}
				continue
			}
			var rawLeafs []any
			switch b.ESType {
			case "geo_point":
				rawLeafs = extractGeoPointCandidatesWithNull(parsedDoc, b.SourceJSONPath, nil)
				if len(rawLeafs) == 0 && b.NullValue != nil {
					rawLeafs = extractGeoPointCandidatesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
				}
			case "token_count":
				rawLeafs = extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
			default:
				rawLeafs = extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, nil)
				if len(rawLeafs) == 0 && b.NullValue != nil {
					rawLeafs = extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
				}
			}
			if len(rawLeafs) == 0 && b.NullValue != nil && hasExplicitNullAtPath(parsedDoc, b.SourceJSONPath) {
				rawLeafs = []any{b.NullValue}
			}
			if b.ESType == "token_count" && (len(rawLeafs) > 0 || hasObjAtPath) {
				var totalTokens int64
				var validLeafs []any
				hasTokenVal := false
				hadMalformed := hasObjAtPath
				for _, rv := range rawLeafs {
					if rv == nil {
						continue
					}
					if sv, isStr := rv.(string); isStr {
						totalTokens += countTokensForBinding(sv, b)
						hasTokenVal = true
						validLeafs = append(validLeafs, rv)
					} else if coerced := coerceScalarBindingForDoris(rv, b, getNow()); coerced != nil {
						switch iv := coerced.(type) {
						case int64:
							totalTokens += iv
							hasTokenVal = true
							validLeafs = append(validLeafs, rv)
						case int:
							totalTokens += int64(iv)
							hasTokenVal = true
							validLeafs = append(validLeafs, rv)
						}
					} else if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
						recordIgnored(b.ESFieldPath)
						hadMalformed = true
					} else {
						return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", b.ESFieldPath, b.ESType)
					}
				}
				if hasTokenVal {
					row[b.ColumnName] = totalTokens
				}
				if hadMalformed && isPrimaryFieldBinding(b) {
					if len(validLeafs) > 0 {
						deferReplacePath(b.SourceJSONPath, validLeafs)
					} else {
						deferDeletePath(b.SourceJSONPath)
					}
				}
				continue
			}
			if len(rawLeafs) > 0 || b.ESType == "geo_point" || hasObjAtPath {
				var firstVal any
				var validLeafs []any
				hadMalformed := hasObjAtPath
				for _, rv := range rawLeafs {
					if rv == nil {
						continue
					}
					if b.IgnoreAbove > 0 {
						str, ok := rv.(string)
						if !ok && (b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || b.DorisType == DorisVarchar) {
							str = fmt.Sprintf("%v", rv)
							ok = true
						}
						if ok && len([]rune(str)) > b.IgnoreAbove {
							if isPrimaryFieldBinding(b) {
								recordIgnored(b.ESFieldPath)
							}
							continue
						}
					}
					if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && b.ESType != "token_count" && (b.Coerce == nil || *b.Coerce) && (b.ESType == "ip" || b.ESType == "geo_point" || (b.DorisType != DorisString && b.DorisType != DorisVarchar)) {
						continue
					}
					coerced := coerceScalarBindingForDoris(rv, b, getNow())
					if coerced == nil {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							recordIgnored(b.ESFieldPath)
							hadMalformed = true
							continue
						}
						return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", b.ESFieldPath, b.ESType)
					}
					if b.ESType == "date_nanos" {
						if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
							coerced = iv / 1_000_000
						}
					}
					validLeafs = append(validLeafs, rv)
					if firstVal == nil {
						firstVal = coerced
					}
				}
				if firstVal == nil && b.NullValue != nil && hasExplicitNullAtPath(parsedDoc, b.SourceJSONPath) {
					nvAllowed := true
					if b.IgnoreAbove > 0 {
						str, ok := b.NullValue.(string)
						if !ok && (b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || b.DorisType == DorisVarchar) {
							str = fmt.Sprintf("%v", b.NullValue)
							ok = true
						}
						if ok && len([]rune(str)) > b.IgnoreAbove {
							nvAllowed = false
						}
					}
					if nvAllowed {
						firstVal = coerceScalarBindingForDoris(b.NullValue, b, getNow())
						if b.ESType == "date_nanos" {
							if iv, ok := firstVal.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
								firstVal = iv / 1_000_000
							}
						}
					}
				}
				if firstVal != nil {
					row[b.ColumnName] = firstVal
					if hadMalformed && isPrimaryFieldBinding(b) {
						deferReplacePath(b.SourceJSONPath, validLeafs)
					}
				} else if hadMalformed && isPrimaryFieldBinding(b) {
					deferDeletePath(b.SourceJSONPath)
				}
				continue
			}
			val := extractScalarValue(parsedDoc, b.SourceJSONPath)
			if b.IgnoreAbove > 0 && val != nil {
				str, ok := val.(string)
				if !ok && (b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || b.DorisType == DorisVarchar) {
					str = fmt.Sprintf("%v", val)
					ok = true
				}
				if ok && len([]rune(str)) > b.IgnoreAbove {
					if isPrimaryFieldBinding(b) {
						recordIgnored(b.ESFieldPath)
					}
					val = nil
				}
			}
			if val != nil {
				if strVal, isStr := val.(string); isStr && strings.TrimSpace(strVal) == "" && b.ESType != "token_count" && (b.Coerce == nil || *b.Coerce) && (b.ESType == "ip" || b.ESType == "geo_point" || (b.DorisType != DorisString && b.DorisType != DorisVarchar)) {
					val = nil
				} else {
					coerced := coerceScalarBindingForDoris(val, b, getNow())
					if coerced == nil {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							recordIgnored(b.ESFieldPath)
							if isPrimaryFieldBinding(b) {
								deferDeletePath(b.SourceJSONPath)
							}
						} else {
							return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", b.ESFieldPath, b.ESType)
						}
					}
					val = coerced
				}
			}
			if b.ESType == "date_nanos" {
				if iv, ok := val.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
					val = iv / 1_000_000
				}
			}
			if val != nil {
				row[b.ColumnName] = val
			}
		case StoragePromotedArray, StorageNestedSubfield:
			if isTypedNonStringBinding(b) {
				var rawLeafs []any
				if b.ESType == "geo_point" {
					rawLeafs = extractGeoPointCandidatesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
				} else {
					rawLeafs = extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
				}
				var vals []string
				var validLeafs []any
				hadMalformed := hasObjAtPath
				for _, rv := range rawLeafs {
					if rv == nil {
						continue
					}
					if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && b.ESType != "token_count" && b.ESType != "version" && (b.Coerce == nil || *b.Coerce) {
						continue
					}
					coerced := coerceScalarBindingForDoris(rv, b, getNow())
					if coerced == nil {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							recordIgnored(b.ESFieldPath)
							hadMalformed = true
							continue
						}
						return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", b.ESFieldPath, b.ESType)
					}
					if b.ESType == "date_nanos" {
						if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
							coerced = iv / 1_000_000
						}
					}
					validLeafs = append(validLeafs, rv)
					if b.ESType == "unsigned_long" {
						if u, okU := parseExactUint64(rv); okU && u > uint64(math.MaxInt64) {
							vals = append(vals, strconv.FormatUint(u, 10))
							continue
						}
					}
					vals = append(vals, formatCoercedArrayElement(coerced))
				}
				if len(vals) > 0 {
					row[b.ColumnName] = vals
					if hadMalformed && isPrimaryFieldBinding(b) {
						if b.Kind == StorageNestedSubfield {
							deferCleanNestedPath(b.SourceJSONPath, b)
						} else {
							deferReplacePath(b.SourceJSONPath, validLeafs)
						}
					}
				} else if hadMalformed && isPrimaryFieldBinding(b) {
					deferDeletePath(b.SourceJSONPath)
				}
				continue
			}
			vals := extractStringSliceValuesWithNull(parsedDoc, b.SourceJSONPath, b.LowercaseNormalizer, b.NullValue)
			if b.IgnoreAbove > 0 && len(vals) > 0 {
				filtered := vals[:0]
				for _, v := range vals {
					if len([]rune(v)) <= b.IgnoreAbove {
						filtered = append(filtered, v)
					} else if isPrimaryFieldBinding(b) {
						recordIgnored(b.ESFieldPath)
					}
				}
				vals = filtered
			}
			if len(vals) > 0 {
				row[b.ColumnName] = vals
			}
			if hasObjAtPath && isPrimaryFieldBinding(b) {
				if len(vals) > 0 {
					if b.Kind == StorageNestedSubfield {
						deferCleanNestedPath(b.SourceJSONPath, b)
					} else {
						validLeafs := make([]any, 0, len(vals))
						for _, sv := range vals {
							validLeafs = append(validLeafs, sv)
						}
						deferReplacePath(b.SourceJSONPath, validLeafs)
					}
				} else {
					deferDeletePath(b.SourceJSONPath)
				}
			}
		case StoragePromotedVector:
			vec, present, valid := extractAndValidateVectorValues(parsedDoc, b.SourceJSONPath, b.VectorDims)
			if present {
				if !valid {
					if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
						recordIgnored(b.ESFieldPath)
						if isPrimaryFieldBinding(b) {
							deferDeletePath(b.SourceJSONPath)
						}
						continue
					}
					return nil, fmt.Errorf("mapper_parsing_exception: failed to parse vector field [%s] of type [%s]", b.ESFieldPath, b.ESType)
				}
				if (b.ESType == "dense_vector" || b.ESType == "knn_vector") && (b.VectorMetric == "" || strings.EqualFold(b.VectorMetric, "cosine")) {
					var sumSq float64
					for _, fv := range vec {
						sumSq += fv * fv
					}
					if sumSq == 0 {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							recordIgnored(b.ESFieldPath)
							if isPrimaryFieldBinding(b) {
								deferDeletePath(b.SourceJSONPath)
							}
							continue
						}
						return nil, fmt.Errorf("mapper_parsing_exception: Zero-magnitude vectors are not supported when using [cosine] similarity on field [%s]", b.ESFieldPath)
					}
				}
				row[b.ColumnName] = vec
			}
		}
	}

	if s != nil && len(s.Fields) > 0 {
		rangeFieldKeys := make([]string, 0)
		for k, b := range s.Fields {
			if IsRangeFieldType(b.ESType) && b.AliasTarget == "" && !b.EnabledFalse {
				rangeFieldKeys = append(rangeFieldKeys, k)
			}
		}
		sort.Strings(rangeFieldKeys)
		for _, k := range rangeFieldKeys {
			b := s.Fields[k]
			modified, err := validateAndNormalizeRangeFieldInDoc(parsedDoc, b.SourceJSONPath, b, getNow)
			if err != nil {
				if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
					recordIgnored(b.ESFieldPath)
					if deletePathInMap(parsedDoc, b.SourceJSONPath) {
						prunedDynamic = true
					}
					continue
				}
				return nil, err
			}
			if modified {
				prunedDynamic = true
			}
		}
	}

	// Propagate `copy_to` field values to target bindings (supporting transitive A -> B -> C chains)
	copyToFields := fieldsToVisit
	if s != nil && len(s.Fields) > 0 {
		visitedPaths := make(map[string]bool, len(fieldsToVisit))
		for _, b := range fieldsToVisit {
			visitedPaths[b.ESFieldPath] = true
		}
		var extraCopyToKeys []string
		for k, b := range s.Fields {
			if !visitedPaths[k] && b.AliasTarget == "" && !b.EnabledFalse && len(b.CopyTo) > 0 {
				extraCopyToKeys = append(extraCopyToKeys, k)
			}
		}
		if len(extraCopyToKeys) > 0 {
			sort.Strings(extraCopyToKeys)
			copyToFields = make([]FieldBinding, 0, len(fieldsToVisit)+len(extraCopyToKeys))
			copyToFields = append(copyToFields, fieldsToVisit...)
			for _, k := range extraCopyToKeys {
				copyToFields = append(copyToFields, s.Fields[k])
			}
		}
	}
	copiedRawVals := make(map[string][]any)
	for _, b := range copyToFields {
		if len(b.CopyTo) > 0 {
			basePath := strings.TrimSuffix(b.ESFieldPath, ".keyword")
			srcDot := strings.Join(b.SourceJSONPath, ".")
			if ignoredSeen[b.ESFieldPath] || ignoredSeen[basePath] || (srcDot != "" && ignoredSeen[srcDot]) {
				continue
			}
			var vals []any
			if b.ESType == "flattened" {
				vals = extractFlattenedLeafValues(parsedDoc, b.SourceJSONPath)
			} else {
				vals = extractRawLeafValuesWithNull(parsedDoc, b.SourceJSONPath, b.NullValue)
			}
			if b.ESType == "constant_keyword" && len(vals) == 0 && b.ConstantValue != nil {
				vals = []any{b.ConstantValue}
			}
			if b.IgnoreAbove > 0 && len(vals) > 0 {
				filtered := make([]any, 0, len(vals))
				for _, v := range vals {
					if len([]rune(fmt.Sprintf("%v", v))) <= b.IgnoreAbove {
						filtered = append(filtered, v)
					}
				}
				vals = filtered
			}
			if len(vals) > 0 {
				copiedRawVals[b.ESFieldPath] = append(copiedRawVals[b.ESFieldPath], vals...)
			}
		}
	}
	forwardedCount := make(map[string]int)
	for pass := 0; pass < 4; pass++ {
		progressed := false
		for _, b := range copyToFields {
			if len(b.CopyTo) == 0 {
				continue
			}
			allSrc := copiedRawVals[b.ESFieldPath]
			if len(allSrc) == 0 {
				continue
			}
			for _, targetField := range b.CopyTo {
				edgeKey := b.ESFieldPath + "\x00" + targetField
				already := forwardedCount[edgeKey]
				if already >= len(allSrc) {
					continue
				}
				srcVals := allSrc[already:]
				forwardedCount[edgeKey] = len(allSrc)
				progressed = true

				tb, ok := s.Fields[targetField]
				if !ok && b.NestedPath != "" {
					if rtb, rOK := s.Fields[b.NestedPath+"."+targetField]; rOK {
						targetField = b.NestedPath + "." + targetField
						tb = rtb
						ok = true
					}
				}
				if ok && tb.AliasTarget != "" {
					if resolvedTB, rOK := s.Fields[tb.AliasTarget]; rOK {
						targetField = tb.AliasTarget
						tb = resolvedTB
					}
				}
				if ok && tb.EnabledFalse {
					continue
				}
				chainSrcVals := srcVals
				if ok && tb.IgnoreAbove > 0 {
					chainSrcVals = make([]any, 0, len(srcVals))
					for _, rv := range srcVals {
						if len([]rune(fmt.Sprintf("%v", rv))) <= tb.IgnoreAbove {
							chainSrcVals = append(chainSrcVals, rv)
						}
					}
				}
				if len(chainSrcVals) > 0 {
					copiedRawVals[targetField] = append(copiedRawVals[targetField], chainSrcVals...)
				}
				if !ok {
					continue
				}
				srcStrs := make([]string, 0, len(srcVals))
				for _, rv := range srcVals {
					srcStrs = append(srcStrs, fmt.Sprintf("%v", rv))
				}
				switch tb.Kind {
				case StoragePromotedScalar:
					if isTypedNonStringBinding(tb) {
						for _, rv := range srcVals {
							if rv == nil {
								continue
							}
							if tb.IgnoreAbove > 0 && len([]rune(fmt.Sprintf("%v", rv))) > tb.IgnoreAbove {
								continue
							}
							if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && tb.ESType != "version" && (tb.Coerce == nil || *tb.Coerce) {
								continue
							}
							coerced := coerceScalarBindingForDoris(rv, tb, getNow())
							if coerced == nil {
								if tb.IgnoreMalformed != nil && *tb.IgnoreMalformed {
									recordIgnored(targetField)
									continue
								}
								return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", targetField, tb.ESType)
							}
							if tb.ESType == "date_nanos" {
								if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
									coerced = iv / 1_000_000
								}
							}
							if existing, exists := row[tb.ColumnName]; !exists || existing == nil {
								row[tb.ColumnName] = coerced
							}
						}
					} else {
						filteredSrc := srcStrs
						if tb.IgnoreAbove > 0 {
							filteredSrc = make([]string, 0, len(srcStrs))
							for _, sv := range srcStrs {
								if len([]rune(sv)) <= tb.IgnoreAbove {
									filteredSrc = append(filteredSrc, sv)
								}
							}
						}
						if len(filteredSrc) > 0 {
							joined := strings.Join(filteredSrc, " ")
							coerced := coerceScalarBindingForDoris(joined, tb, getNow())
							if coerced != nil {
								if existing, exists := row[tb.ColumnName]; exists && existing != nil {
									if tb.DorisType == DorisString || tb.DorisType == DorisVarchar {
										row[tb.ColumnName] = fmt.Sprintf("%v %v", existing, coerced)
									}
								} else {
									row[tb.ColumnName] = coerced
								}
							}
						}
					}
					if tb.KeywordCompanion != "" {
						kwB, hasKw := s.Fields[targetField+".keyword"]
						if hasKw && kwB.Kind == StoragePromotedArray {
							var curKw []string
							if existing, ok := row[tb.KeywordCompanion].([]string); ok {
								curKw = append(curKw, existing...)
							}
							for _, sv := range srcStrs {
								if kwB.IgnoreAbove > 0 && len([]rune(sv)) > kwB.IgnoreAbove {
									continue
								}
								if tb.KeywordNormalizer || kwB.LowercaseNormalizer {
									sv = strings.ToLower(sv)
								}
								curKw = append(curKw, sv)
							}
							if len(curKw) > 0 {
								row[tb.KeywordCompanion] = curKw
							}
						} else {
							var filteredKw []string
							for _, sv := range srcStrs {
								if hasKw && kwB.IgnoreAbove > 0 && len([]rune(sv)) > kwB.IgnoreAbove {
									continue
								}
								if tb.KeywordNormalizer || (hasKw && kwB.LowercaseNormalizer) {
									sv = strings.ToLower(sv)
								}
								filteredKw = append(filteredKw, sv)
							}
							if len(filteredKw) > 0 {
								kwVal := strings.Join(filteredKw, " ")
								if existing, exists := row[tb.KeywordCompanion]; exists && existing != nil {
									row[tb.KeywordCompanion] = fmt.Sprintf("%v %s", existing, kwVal)
								} else {
									row[tb.KeywordCompanion] = kwVal
								}
							}
						}
					}
					if err := propagateCopyToCustomMultiFields(s, row, targetField, srcVals, getNow, recordIgnored); err != nil {
						return nil, err
					}
				case StoragePromotedArray, StorageNestedSubfield:
					var cur []string
					if existing, ok := row[tb.ColumnName].([]string); ok {
						cur = append(cur, existing...)
					}
					for _, rv := range srcVals {
						sv := fmt.Sprintf("%v", rv)
						if tb.IgnoreAbove > 0 && len([]rune(sv)) > tb.IgnoreAbove {
							continue
						}
						if isTypedNonStringBinding(tb) {
							if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && tb.ESType != "version" && (tb.Coerce == nil || *tb.Coerce) {
								continue
							}
							coerced := coerceScalarBindingForDoris(rv, tb, getNow())
							if coerced == nil {
								if tb.IgnoreMalformed != nil && *tb.IgnoreMalformed {
									recordIgnored(targetField)
									continue
								}
								return nil, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", targetField, tb.ESType)
							}
							if tb.ESType == "date_nanos" {
								if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
									coerced = iv / 1_000_000
								}
							}
							if tb.ESType == "unsigned_long" {
								if u, okU := parseExactUint64(rv); okU && u > uint64(math.MaxInt64) {
									cur = append(cur, strconv.FormatUint(u, 10))
									continue
								}
							}
							sv = formatCoercedArrayElement(coerced)
						} else if tb.LowercaseNormalizer {
							sv = strings.ToLower(sv)
						}
						cur = append(cur, sv)
					}
					if len(cur) > 0 {
						row[tb.ColumnName] = cur
					}
					if tb.KeywordCompanion != "" {
						kwB := s.Fields[targetField+".keyword"]
						var curKw []string
						if existing, ok := row[tb.KeywordCompanion].([]string); ok {
							curKw = append(curKw, existing...)
						}
						for _, sv := range srcStrs {
							if kwB.IgnoreAbove > 0 && len([]rune(sv)) > kwB.IgnoreAbove {
								continue
							}
							if tb.KeywordNormalizer || kwB.LowercaseNormalizer {
								sv = strings.ToLower(sv)
							}
							curKw = append(curKw, sv)
						}
						if len(curKw) > 0 {
							row[tb.KeywordCompanion] = curKw
						}
					}
					if err := propagateCopyToCustomMultiFields(s, row, targetField, srcVals, getNow, recordIgnored); err != nil {
						return nil, err
					}
				}
			}
		}
		if !progressed {
			break
		}
	}

	// Populate correlated nested JSON element arrays (`n__<nested_path>`)
	if len(s.NestedRootSpecs) > 0 {
		for _, nr := range s.NestedRootSpecs {
			rawElements := extractNestedElementMapsWithIDs(parsedDoc, nr.PathParts, "")
			if len(rawElements) > 0 {
				serializedElems := make([]string, 0, len(rawElements))
				for _, elem := range rawElements {
					normMap := normalizeNestedElementForStorage(s, nr.Path, nr.PathParts, elem.m, getNow)
					if normMap != nil {
						normMap["_nested_id"] = elem.nestedID
						if elem.parentID != "" {
							normMap["_parent_id"] = elem.parentID
						}
					}
					encoded, err := json.Marshal(normMap)
					if err == nil {
						serializedElems = append(serializedElems, string(encoded))
					}
				}
				row[nr.ColumnName] = serializedElems
			}
		}
	} else {
		for nestedPath, corrCol := range s.NestedRoots {
			pathParts := strings.Split(nestedPath, ".")
			rawElements := extractNestedElementMapsWithIDs(parsedDoc, pathParts, "")
			if len(rawElements) > 0 {
				serializedElems := make([]string, 0, len(rawElements))
				for _, elem := range rawElements {
					normMap := normalizeNestedElementForStorage(s, nestedPath, pathParts, elem.m, getNow)
					if normMap != nil {
						normMap["_nested_id"] = elem.nestedID
						if elem.parentID != "" {
							normMap["_parent_id"] = elem.parentID
						}
					}
					encoded, err := json.Marshal(normMap)
					if err == nil {
						serializedElems = append(serializedElems, string(encoded))
					}
				}
				row[corrCol] = serializedElems
			}
		}
	}

	if len(ignoredFields) > 0 {
		sort.Strings(ignoredFields)
		row["_ignored"] = ignoredFields
	}
	for _, mut := range deferredMutations {
		if mut.cleanBinding != nil {
			if cleanMalformedNestedLeafInMap(parsedDoc, mut.path, *mut.cleanBinding, getNow()) {
				prunedDynamic = true
			}
		} else if mut.deletePath {
			if deletePathInMap(parsedDoc, mut.path) {
				prunedDynamic = true
			}
		} else {
			if replacePathSliceInMap(parsedDoc, mut.path, mut.validLeafs) {
				prunedDynamic = true
			}
		}
	}
	var allTextBuilder strings.Builder
	allTextBuilder.Grow(len(trimmed) / 2)
	collectAllTextWithSchema(parsedDoc, s, nil, &allTextBuilder)
	row["_all_text"] = allTextBuilder.String()
	row["_doc"] = buildVariantDocPayload(trimmed, parsedDoc, prunedDynamic, s)

	return json.Marshal(row)
}

func isTypedNonStringBinding(b FieldBinding) bool {
	switch b.ESType {
	case "long", "unsigned_long", "integer", "short", "byte", "token_count", "double", "float", "half_float", "scaled_float", "date", "date_nanos", "boolean", "ip", "geo_point", "version":
		return true
	}
	switch b.DorisType {
	case DorisBigInt, DorisInt, DorisDouble, DorisBoolean:
		return true
	}
	return false
}

func isGeoNumericElem(v any) bool {
	switch v.(type) {
	case float64, int, int64, json.Number:
		return true
	default:
		return false
	}
}

func extractGeoPointCandidatesWithNull(node any, path []string, nullVal any) []any {
	var out []any
	collectGeoPointCandidatesWithNull(node, path, nullVal, &out)
	return out
}

func collectGeoPointCandidatesWithNull(node any, path []string, nullVal any, out *[]any) {
	if len(path) == 0 {
		if node == nil {
			if nullVal != nil {
				*out = append(*out, nullVal)
			}
			return
		}
		if arr, ok := node.([]any); ok {
			if len(arr) == 2 && isGeoNumericElem(arr[0]) && isGeoNumericElem(arr[1]) {
				*out = append(*out, arr)
				return
			}
			for _, item := range arr {
				collectGeoPointCandidatesWithNull(item, nil, nullVal, out)
			}
			return
		}
		*out = append(*out, node)
		return
	}
	if node == nil {
		return
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			collectGeoPointCandidatesWithNull(next, path[1:], nullVal, out)
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				collectGeoPointCandidatesWithNull(next, path[i:], nullVal, out)
			}
		}
	case []any:
		for _, elem := range curr {
			collectGeoPointCandidatesWithNull(elem, path, nullVal, out)
		}
	}
}

func parseGeoFloatElem(x any) (float64, bool) {
	switch nv := x.(type) {
	case float64:
		return nv, !math.IsNaN(nv) && !math.IsInf(nv, 0)
	case int:
		return float64(nv), true
	case int64:
		return float64(nv), true
	case json.Number:
		f, err := nv.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(nv), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

// DecodeGeohashLatLon decodes a geohash string into its center (lat, lon) coordinates.
func DecodeGeohashLatLon(hash string) (lat, lon float64, ok bool) {
	return decodeGeohashLatLon(hash)
}

func decodeGeohashLatLon(hash string) (lat, lon float64, ok bool) {
	if len(hash) == 0 || len(hash) > 12 {
		return 0, 0, false
	}
	const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0
	isEven := true
	for i := 0; i < len(hash); i++ {
		ch := hash[i]
		if ch >= 'A' && ch <= 'Z' {
			ch = ch - 'A' + 'a'
		}
		idx := strings.IndexByte(base32, ch)
		if idx < 0 {
			return 0, 0, false
		}
		for bit := 4; bit >= 0; bit-- {
			mask := (idx >> bit) & 1
			if isEven {
				mid := (minLon + maxLon) / 2
				if mask == 1 {
					minLon = mid
				} else {
					maxLon = mid
				}
			} else {
				mid := (minLat + maxLat) / 2
				if mask == 1 {
					minLat = mid
				} else {
					maxLat = mid
				}
			}
			isEven = !isEven
		}
	}
	return (minLat + maxLat) / 2, (minLon + maxLon) / 2, true
}

func parseAndFormatGeoPointValue(val any) (formatted string, lat, lon float64, ok bool) {
	checkBounds := func(la, lo float64) (string, float64, float64, bool) {
		if math.IsNaN(la) || math.IsInf(la, 0) || la < -90.0 || la > 90.0 ||
			math.IsNaN(lo) || math.IsInf(lo, 0) || lo < -180.0 || lo > 180.0 {
			return "", 0, 0, false
		}
		return fmt.Sprintf("%s,%s", strconv.FormatFloat(la, 'f', -1, 64), strconv.FormatFloat(lo, 'f', -1, 64)), la, lo, true
	}
	switch tv := val.(type) {
	case map[string]any:
		if coords, hasCoords := tv["coordinates"]; hasCoords {
			if tStr, _ := tv["type"].(string); strings.EqualFold(strings.TrimSpace(tStr), "Point") {
				if arr, okArr := coords.([]any); okArr && len(arr) == 2 {
					lo, okLon := parseGeoFloatElem(arr[0])
					la, okLat := parseGeoFloatElem(arr[1])
					if okLat && okLon {
						return checkBounds(la, lo)
					}
				}
			}
			return "", 0, 0, false
		}
		rawLat, hasLat := tv["lat"]
		rawLon, hasLon := tv["lon"]
		if !hasLat || !hasLon {
			return "", 0, 0, false
		}
		for k := range tv {
			if k != "lat" && k != "lon" {
				return "", 0, 0, false
			}
		}
		la, okLat := parseGeoFloatElem(rawLat)
		lo, okLon := parseGeoFloatElem(rawLon)
		if !okLat || !okLon {
			return "", 0, 0, false
		}
		return checkBounds(la, lo)
	case []any:
		if len(tv) != 2 || !isGeoNumericElem(tv[0]) || !isGeoNumericElem(tv[1]) {
			return "", 0, 0, false
		}
		lo, okLon := parseGeoFloatElem(tv[0])
		la, okLat := parseGeoFloatElem(tv[1])
		if !okLat || !okLon {
			return "", 0, 0, false
		}
		return checkBounds(la, lo)
	case string:
		str := strings.TrimSpace(tv)
		if str == "" {
			return "", 0, 0, false
		}
		if strings.HasPrefix(strings.ToUpper(str), "POINT") {
			openIdx := strings.IndexByte(str, '(')
			closeIdx := strings.LastIndexByte(str, ')')
			if openIdx > 0 && closeIdx > openIdx && strings.TrimSpace(str[closeIdx+1:]) == "" {
				fields := strings.Fields(str[openIdx+1 : closeIdx])
				if len(fields) == 2 {
					lo, err1 := strconv.ParseFloat(fields[0], 64)
					la, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil {
						return checkBounds(la, lo)
					}
				}
			}
			return "", 0, 0, false
		}
		if strings.Contains(str, ",") {
			parts := strings.Split(str, ",")
			if len(parts) != 2 {
				return "", 0, 0, false
			}
			la, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lo, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 != nil || err2 != nil {
				return "", 0, 0, false
			}
			return checkBounds(la, lo)
		}
		if la, lo, okHash := decodeGeohashLatLon(str); okHash {
			return checkBounds(la, lo)
		}
		return "", 0, 0, false
	default:
		return "", 0, 0, false
	}
}

func formatCoercedArrayElement(v any) string {
	switch tv := v.(type) {
	case int64:
		return strconv.FormatInt(tv, 10)
	case int:
		return strconv.Itoa(tv)
	case float64:
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case bool:
		if tv {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func extractRawLeafValuesWithNull(node any, path []string, nullVal any) []any {
	var out []any
	collectRawLeafsAtPathWithNull(node, path, nullVal, &out)
	return out
}

func extractFlattenedLeafValues(node any, path []string) []any {
	var out []any
	collectFlattenedLeafsAtPath(node, path, &out)
	return out
}

func collectFlattenedLeafsAtPath(node any, path []string, out *[]any) {
	if node == nil {
		return
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				collectFlattenedLeafsAtPath(v[k], nil, out)
			}
		case []any:
			for _, item := range v {
				collectFlattenedLeafsAtPath(item, nil, out)
			}
		default:
			*out = append(*out, v)
		}
		return
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			collectFlattenedLeafsAtPath(next, path[1:], out)
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				collectFlattenedLeafsAtPath(next, path[i:], out)
			}
		}
	case []any:
		for _, elem := range curr {
			collectFlattenedLeafsAtPath(elem, path, out)
		}
	}
}

func collectRawLeafsAtPathWithNull(node any, path []string, nullVal any, out *[]any) {
	if len(path) == 0 {
		if node == nil {
			if nullVal != nil {
				*out = append(*out, nullVal)
			}
			return
		}
		switch v := node.(type) {
		case []any:
			for _, item := range v {
				collectRawLeafsAtPathWithNull(item, nil, nullVal, out)
			}
		case map[string]any:
			return
		default:
			*out = append(*out, v)
		}
		return
	}
	if node == nil {
		return
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			collectRawLeafsAtPathWithNull(next, path[1:], nullVal, out)
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				collectRawLeafsAtPathWithNull(next, path[i:], nullVal, out)
			}
		}
	case []any:
		for _, elem := range curr {
			collectRawLeafsAtPathWithNull(elem, path, nullVal, out)
		}
	}
}

var standardEnglishStopwords = map[string]struct{}{
	"a": {}, "an": {}, "and": {}, "are": {}, "as": {}, "at": {}, "be": {}, "but": {}, "by": {},
	"for": {}, "if": {}, "in": {}, "into": {}, "is": {}, "it": {}, "no": {}, "not": {}, "of": {},
	"on": {}, "or": {}, "such": {}, "that": {}, "the": {}, "their": {}, "then": {}, "there": {},
	"these": {}, "they": {}, "this": {}, "to": {}, "was": {}, "will": {}, "with": {},
}

func countTokensForBinding(sv string, b FieldBinding) int64 {
	fields := strings.Fields(sv)
	if len(fields) == 0 {
		return 0
	}
	filterStops := false
	if b.EnablePositionIncrements != nil && !*b.EnablePositionIncrements {
		filterStops = true
	} else if (strings.EqualFold(b.Analyzer, "stop") || strings.EqualFold(b.Analyzer, "english")) && (b.EnablePositionIncrements == nil || !*b.EnablePositionIncrements) {
		filterStops = true
	}
	if !filterStops {
		return int64(len(fields))
	}
	var cnt int64
	for _, tok := range fields {
		cleaned := strings.ToLower(strings.Trim(tok, ".,!?;:\"'()[]{}"))
		if cleaned == "" {
			continue
		}
		if _, isStop := standardEnglishStopwords[cleaned]; !isStop {
			cnt++
		}
	}
	return cnt
}

func validateDocumentLimits(obj map[string]any, depth, maxDepth, maxFieldNameLength int) error {
	if obj == nil {
		return nil
	}
	if maxDepth > 0 && depth > maxDepth {
		return fmt.Errorf("illegal_argument_exception: Limit of mapping depth [%d] has been exceeded", maxDepth)
	}
	for k, v := range obj {
		if maxFieldNameLength > 0 {
			if len(k) > maxFieldNameLength {
				return fmt.Errorf("illegal_argument_exception: Field name [%s] is longer than the limit of [%d] characters", k, maxFieldNameLength)
			}
			for _, seg := range strings.Split(k, ".") {
				if len(seg) > maxFieldNameLength {
					return fmt.Errorf("illegal_argument_exception: Field name [%s] is longer than the limit of [%d] characters", seg, maxFieldNameLength)
				}
			}
		}
		effDepth := depth + strings.Count(k, ".")
		if maxDepth > 0 && effDepth > maxDepth {
			return fmt.Errorf("illegal_argument_exception: Limit of mapping depth [%d] has been exceeded", maxDepth)
		}
		switch tv := v.(type) {
		case map[string]any:
			if err := validateDocumentLimits(tv, effDepth+1, maxDepth, maxFieldNameLength); err != nil {
				return err
			}
		case []any:
			for _, elem := range tv {
				if em, ok := elem.(map[string]any); ok {
					if err := validateDocumentLimits(em, effDepth+1, maxDepth, maxFieldNameLength); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func dateFormatAllowsNumericWithNoCoerce(format string) bool {
	if strings.TrimSpace(format) == "" {
		return true
	}
	for _, part := range strings.Split(format, "||") {
		switch strings.TrimSpace(part) {
		case "epoch_millis", "epoch_second":
			return true
		}
	}
	return false
}

func parseUnsignedLongString(s string, allowCoerce bool) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") {
		return 0, false
	}
	if !allowCoerce && strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	if u, err := strconv.ParseUint(strings.TrimPrefix(s, "+"), 10, 64); err == nil {
		return u, true
	}
	if !strings.ContainsAny(s, "eE") && strings.Count(s, ".") == 1 {
		parts := strings.SplitN(s, ".", 2)
		intPart, fracPart := parts[0], parts[1]
		if len(fracPart) == 0 {
			return 0, false
		}
		for i := 0; i < len(fracPart); i++ {
			c := fracPart[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			if !allowCoerce && c != '0' {
				return 0, false
			}
		}
		intPart = strings.TrimPrefix(intPart, "+")
		if intPart == "" {
			intPart = "0"
		}
		u, err := strconv.ParseUint(intPart, 10, 64)
		return u, err == nil
	}
	if strings.ContainsAny(s, "eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f >= 18446744073709551616.0 {
			return 0, false
		}
		if !allowCoerce && math.Trunc(f) != f {
			return 0, false
		}
		return uint64(f), true
	}
	return 0, false
}

func parseExactUint64(val any) (uint64, bool) {
	switch v := val.(type) {
	case uint64:
		return v, true
	case json.Number:
		return parseUnsignedLongString(v.String(), true)
	case string:
		return parseUnsignedLongString(v, true)
	}
	return 0, false
}

func coerceScalarBindingForDoris(val any, b FieldBinding, now time.Time) any {
	if val == nil {
		return nil
	}
	if b.ESType == "token_count" {
		switch tv := val.(type) {
		case string:
			return countTokensForBinding(tv, b)
		case []string:
			var total int64
			for _, sv := range tv {
				total += countTokensForBinding(sv, b)
			}
			return total
		case []any:
			var total int64
			for _, elem := range tv {
				if sv, ok := elem.(string); ok {
					total += countTokensForBinding(sv, b)
				}
			}
			return total
		}
	}
	effDorisType := b.DorisType
	if (effDorisType == DorisString || effDorisType == "") && b.ESType != "" {
		effDorisType = mapESTypeToDoris(b.ESType)
	}
	if b.Coerce != nil && !*b.Coerce {
		switch effDorisType {
		case DorisBigInt, DorisInt:
			if b.ESType != "date" && b.ESType != "date_nanos" {
				switch v := val.(type) {
				case string, bool:
					return nil
				case float64:
					if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
						return nil
					}
				case json.Number:
					if strings.ContainsAny(v.String(), ".eE") {
						return nil
					}
					if _, err := v.Int64(); err != nil {
						if _, uerr := strconv.ParseUint(v.String(), 10, 64); uerr != nil {
							return nil
						}
					}
				}
			}
		case DorisDouble:
			switch val.(type) {
			case string, bool:
				return nil
			}
		case DorisBoolean:
			if _, ok := val.(bool); !ok {
				return nil
			}
		}
	}
	if b.ESType == "ip" {
		strVal, ok := val.(string)
		if !ok {
			return nil
		}
		trimmed := strings.TrimSpace(strVal)
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return nil
		}
		return ip.String()
	}
	if b.ESType == "version" {
		strVal, ok := val.(string)
		if !ok || !ValidateSemver(strVal) {
			return nil
		}
		return strVal
	}
	if b.ESType == "geo_point" {
		formatted, _, _, ok := parseAndFormatGeoPointValue(val)
		if !ok {
			return nil
		}
		return formatted
	}
	if b.ESType == "unsigned_long" {
		allowCoerce := b.Coerce == nil || *b.Coerce
		clampUintToInt64 := func(u uint64) int64 {
			if u > uint64(math.MaxInt64) {
				return int64(math.MaxInt64)
			}
			return int64(u)
		}
		checkFloatUint := func(f float64) any {
			if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f >= 18446744073709551616.0 {
				return nil
			}
			if !allowCoerce && math.Trunc(f) != f {
				return nil
			}
			if f >= float64(math.MaxInt64) {
				return int64(math.MaxInt64)
			}
			return int64(f)
		}
		switch v := val.(type) {
		case int64:
			if v < 0 {
				return nil
			}
			return v
		case int:
			if v < 0 {
				return nil
			}
			return int64(v)
		case uint64:
			return clampUintToInt64(v)
		case float64:
			return checkFloatUint(v)
		case json.Number:
			if u, ok := parseUnsignedLongString(v.String(), allowCoerce); ok {
				return clampUintToInt64(u)
			}
			return nil
		case string:
			if !allowCoerce {
				return nil
			}
			if u, ok := parseUnsignedLongString(v, allowCoerce); ok {
				return clampUintToInt64(u)
			}
			return nil
		default:
			return nil
		}
	}
	if b.ESType == "long" || b.ESType == "integer" || b.ESType == "short" || b.ESType == "byte" {
		minBound := int64(math.MinInt64)
		maxBound := int64(math.MaxInt64)
		switch b.ESType {
		case "integer":
			minBound, maxBound = int64(math.MinInt32), int64(math.MaxInt32)
		case "short":
			minBound, maxBound = int64(math.MinInt16), int64(math.MaxInt16)
		case "byte":
			minBound, maxBound = int64(math.MinInt8), int64(math.MaxInt8)
		}
		checkIntBounds := func(i int64) bool {
			return i >= minBound && i <= maxBound
		}
		checkFloatBounds := func(f float64) bool {
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return false
			}
			if b.ESType == "long" {
				return f >= -9223372036854775808.0 && f < 9223372036854775808.0
			}
			return f >= float64(minBound) && f <= float64(maxBound)
		}
		switch v := val.(type) {
		case int:
			if !checkIntBounds(int64(v)) {
				return nil
			}
		case int64:
			if !checkIntBounds(v) {
				return nil
			}
		case uint64:
			if b.ESType != "long" && (v > uint64(math.MaxInt64) || !checkIntBounds(int64(v))) {
				return nil
			}
		case float64:
			if !checkFloatBounds(v) {
				return nil
			}
		case json.Number:
			s := v.String()
			if i, err := v.Int64(); err == nil {
				if !checkIntBounds(i) {
					return nil
				}
			} else if b.ESType == "long" {
				if _, uerr := strconv.ParseUint(s, 10, 64); uerr != nil {
					if strings.ContainsAny(s, ".eE") {
						if f, ferr := v.Float64(); ferr != nil || !checkFloatBounds(f) {
							return nil
						}
					} else {
						return nil
					}
				}
			} else if strings.ContainsAny(s, ".eE") {
				if f, ferr := v.Float64(); ferr != nil || !checkFloatBounds(f) {
					return nil
				}
			} else {
				return nil
			}
		case string:
			trimmed := strings.TrimSpace(v)
			if i, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				if !checkIntBounds(i) {
					return nil
				}
			} else if b.ESType == "long" {
				if _, uerr := strconv.ParseUint(trimmed, 10, 64); uerr != nil {
					if strings.ContainsAny(trimmed, ".eE") {
						if f, ferr := strconv.ParseFloat(trimmed, 64); ferr != nil || !checkFloatBounds(f) {
							return nil
						}
					} else {
						return nil
					}
				}
			} else if strings.ContainsAny(trimmed, ".eE") {
				if f, ferr := strconv.ParseFloat(trimmed, 64); ferr != nil || !checkFloatBounds(f) {
					return nil
				}
			} else {
				return nil
			}
		default:
			return nil
		}
	}
	if (b.ESType == "date" || b.ESType == "date_nanos") && b.Format != "" {
		if b.Coerce != nil && !*b.Coerce && !dateFormatAllowsNumericWithNoCoerce(b.Format) {
			switch val.(type) {
			case int, int64, float64, json.Number:
				return nil
			}
		}
		normalizeNanos := func(ms int64) int64 {
			if b.ESType == "date_nanos" && (ms > 1_000_000_000_000_000 || ms < -1_000_000_000_000_000) {
				return ms / 1_000_000
			}
			return ms
		}
		switch v := val.(type) {
		case string:
			if ms, ok := ParseESDateWithFormatToEpochMillis(v, b.Format, now); ok {
				return normalizeNanos(ms)
			}
		case int64:
			if ms, ok := ParseESDateWithFormatToEpochMillis(strconv.FormatInt(v, 10), b.Format, now); ok {
				return normalizeNanos(ms)
			}
		case int:
			if ms, ok := ParseESDateWithFormatToEpochMillis(strconv.Itoa(v), b.Format, now); ok {
				return normalizeNanos(ms)
			}
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				if ms, ok := ParseESDateWithFormatToEpochMillis(strconv.FormatFloat(v, 'f', -1, 64), b.Format, now); ok {
					return normalizeNanos(ms)
				}
			}
		case json.Number:
			if ms, ok := ParseESDateWithFormatToEpochMillis(v.String(), b.Format, now); ok {
				return normalizeNanos(ms)
			}
		}
		return nil
	}
	coerced := coerceScalarForDoris(val, effDorisType, b.LowercaseNormalizer, now)
	switch b.ESType {
	case "short":
		if iv, ok := coerced.(int); ok && (iv < math.MinInt16 || iv > math.MaxInt16) {
			return nil
		}
	case "byte":
		if iv, ok := coerced.(int); ok && (iv < math.MinInt8 || iv > math.MaxInt8) {
			return nil
		}
	case "float":
		if fv, ok := coerced.(float64); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) && math.Abs(fv) > math.MaxFloat32 {
			return nil
		}
	case "half_float":
		if fv, ok := coerced.(float64); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) && math.Abs(fv) > 65504.0 {
			return nil
		}
	case "date_nanos":
		if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
			coerced = iv / 1_000_000
		}
	case "scaled_float":
		if b.ScalingFactor > 0 {
			if fv, ok := coerced.(float64); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				coerced = math.Round(fv*b.ScalingFactor) / b.ScalingFactor
			}
		}
	}
	return coerced
}

func coerceScalarForDoris(val any, dorisType DorisScalarType, lowercase bool, now time.Time) any {
	if val == nil {
		return nil
	}
	switch dorisType {
	case DorisBigInt:
		clamp64 := func(f float64) any {
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return nil
			}
			if f >= float64(math.MaxInt64) {
				return int64(math.MaxInt64)
			}
			if f <= float64(math.MinInt64) {
				return int64(math.MinInt64)
			}
			return int64(f)
		}
		switch v := val.(type) {
		case int64:
			return v
		case uint64:
			if v > uint64(math.MaxInt64) {
				return int64(math.MaxInt64)
			}
			return int64(v)
		case int:
			return int64(v)
		case float64:
			return clamp64(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return i
			}
			if u, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
				if u > uint64(math.MaxInt64) {
					return int64(math.MaxInt64)
				}
				return int64(u)
			}
			if f, err := v.Float64(); err == nil {
				return clamp64(f)
			}
			return nil
		case string:
			trimmed := strings.TrimSpace(v)
			if i, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return i
			}
			if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
				if u > uint64(math.MaxInt64) {
					return int64(math.MaxInt64)
				}
				return int64(u)
			}
			if ms, ok := ParseESDateToEpochMillis(v, now); ok {
				return ms
			}
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
				return clamp64(f)
			}
			return nil
		default:
			return nil
		}
	case DorisInt:
		clamp32 := func(i int64) int {
			if i > math.MaxInt32 {
				return math.MaxInt32
			}
			if i < math.MinInt32 {
				return math.MinInt32
			}
			return int(i)
		}
		switch v := val.(type) {
		case int:
			return clamp32(int64(v))
		case int64:
			return clamp32(v)
		case uint64:
			if v > uint64(math.MaxInt32) {
				return math.MaxInt32
			}
			return int(v)
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil
			}
			if v >= float64(math.MaxInt32) {
				return math.MaxInt32
			}
			if v <= float64(math.MinInt32) {
				return math.MinInt32
			}
			return int(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return clamp32(i)
			}
			if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				if f >= float64(math.MaxInt32) {
					return math.MaxInt32
				}
				if f <= float64(math.MinInt32) {
					return math.MinInt32
				}
				return int(f)
			}
			return nil
		case string:
			if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return clamp32(i)
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				if f >= float64(math.MaxInt32) {
					return math.MaxInt32
				}
				if f <= float64(math.MinInt32) {
					return math.MinInt32
				}
				return int(f)
			}
			return nil
		default:
			return nil
		}
	case DorisDouble:
		switch v := val.(type) {
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil
			}
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case json.Number:
			if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
			return nil
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
			return nil
		default:
			return nil
		}
	case DorisBoolean:
		switch v := val.(type) {
		case bool:
			return v
		case int:
			return v != 0
		case int64:
			return v != 0
		case float64:
			return v != 0 && !math.IsNaN(v)
		case json.Number:
			if f, err := v.Float64(); err == nil {
				return f != 0 && !math.IsNaN(f)
			}
			return v.String() != "0" && v.String() != ""
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1":
				return true
			case "false", "0":
				return false
			}
			return nil
		default:
			return nil
		}
	default:
		if strVal, ok := val.(string); ok {
			if lowercase {
				strVal = strings.ToLower(strVal)
			}
			if dorisType == DorisVarchar && len(strVal) > 1024 {
				strVal = truncateUTF8Bytes(strVal, 1024)
			}
			return strVal
		}
	}
	return val
}

func isNullOrNullSlice(v any) bool {
	if v == nil {
		return true
	}
	if arr, ok := v.([]any); ok {
		for _, elem := range arr {
			if isNullOrNullSlice(elem) {
				return true
			}
		}
	}
	return false
}

func normalizeDynamicMode(dyn any) string {
	switch v := dyn.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "strict":
			return "strict"
		case "false":
			return "false"
		case "runtime":
			return "runtime"
		default:
			return "true"
		}
	case bool:
		if !v {
			return "false"
		}
		return "true"
	default:
		return "true"
	}
}

func isObjectAcceptingLeafProperty(prop esast.FieldProperty) bool {
	if prop.Enabled != nil && !*prop.Enabled {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(prop.Type))
	if IsRangeFieldType(t) {
		return true
	}
	switch t {
	case "flattened", "geo_point", "geo_shape", "shape", "point", "percolator", "sparse_vector", "rank_features", "completion", "histogram", "aggregate_metric_double", "join":
		return true
	default:
		return false
	}
}

func validateStrictDynamicObject(obj map[string]any, props map[string]esast.FieldProperty, parentDynamic any, parentSubobjects *bool, pathPrefix string) (bool, error) {
	mode := normalizeDynamicMode(parentDynamic)
	currentSubobjects := parentSubobjects == nil || *parentSubobjects
	pruned := false
	scope := "_doc"
	if pathPrefix != "" {
		scope = pathPrefix
	}
	for k, v := range obj {
		switch k {
		case "_id", "_index", "_routing", "_version", "_ingest", "_ignored":
			continue
		}
		prop, exists := props[k]
		if exists && prop.Enabled != nil && !*prop.Enabled {
			delete(obj, k)
			pruned = true
			continue
		}
		if currentSubobjects && (!exists || prop.Type == "" || strings.EqualFold(prop.Type, "object")) && len(props) > 0 {
			prefix := k + "."
			var synthProps map[string]esast.FieldProperty
			for pk, pv := range props {
				if strings.HasPrefix(pk, prefix) {
					if synthProps == nil {
						synthProps = make(map[string]esast.FieldProperty)
						for ek, ev := range prop.Properties {
							synthProps[ek] = ev
						}
					}
					synthProps[strings.TrimPrefix(pk, prefix)] = pv
				}
			}
			if len(synthProps) > 0 {
				if !exists {
					prop = esast.FieldProperty{Type: "object", Properties: synthProps}
					exists = true
				} else {
					prop.Properties = synthProps
				}
			}
		}
		if !currentSubobjects {
			isAllowedObjectProp := exists && isObjectAcceptingLeafProperty(prop)
			if !isAllowedObjectProp && hasObjectValueAtPath(v, nil) {
				return false, fmt.Errorf("mapper_parsing_exception: object mapping for [%s] tried to parse field [%s] as object, but subobjects is set to false", scope, k)
			}
		}
		if currentSubobjects && !exists && strings.Contains(k, ".") {
			parts := strings.SplitN(k, ".", 2)
			if p0, ok := props[parts[0]]; ok {
				subObj := map[string]any{parts[1]: v}
				childMode := mode
				if p0.Dynamic != nil {
					childMode = normalizeDynamicMode(p0.Dynamic)
				}
				childSubobjects := parentSubobjects
				if p0.Subobjects != nil {
					childSubobjects = p0.Subobjects
				}
				fullPath := parts[0]
				if pathPrefix != "" {
					fullPath = pathPrefix + "." + parts[0]
				}
				if (p0.Enabled != nil && !*p0.Enabled) || strings.EqualFold(p0.Type, "flattened") || strings.EqualFold(p0.Type, "sparse_vector") || strings.EqualFold(p0.Type, "rank_features") || strings.EqualFold(p0.Type, "percolator") {
					continue
				}
				if isStrictLeafESType(p0.Type) && len(p0.Properties) == 0 && !DefaultMultiValuedPaths[fullPath] {
					if p0.IgnoreMalformed == nil || !*p0.IgnoreMalformed {
						return false, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", fullPath, strings.ToLower(strings.TrimSpace(p0.Type)))
					}
					continue
				}
				subPruned, err := validateStrictDynamicObject(subObj, p0.Properties, childMode, childSubobjects, fullPath)
				if err != nil {
					return false, err
				}
				if subPruned {
					if _, stillExists := subObj[parts[1]]; !stillExists {
						delete(obj, k)
					}
					pruned = true
				}
				continue
			}
		}
		if !exists {
			if mode == "strict" {
				return false, fmt.Errorf("strict_dynamic_mapping_exception: mapping set to strict, dynamic introduction of [%s] within [%s] is not allowed", k, scope)
			}
			if mode == "false" {
				delete(obj, k)
				pruned = true
			}
			continue
		}
		if strings.EqualFold(prop.Type, "flattened") || strings.EqualFold(prop.Type, "sparse_vector") || strings.EqualFold(prop.Type, "rank_features") || strings.EqualFold(prop.Type, "percolator") {
			continue
		}
		if prop.Enabled != nil && !*prop.Enabled {
			delete(obj, k)
			pruned = true
			continue
		}
		fullPath := k
		if pathPrefix != "" {
			fullPath = pathPrefix + "." + k
		}
		isObjOrNested := len(prop.Properties) > 0 || prop.Type == "" || strings.EqualFold(prop.Type, "object") || strings.EqualFold(prop.Type, "nested")
		if !isObjOrNested {
			if isStrictLeafESType(prop.Type) && !DefaultMultiValuedPaths[fullPath] && hasObjectValueAtPath(v, nil) {
				if prop.IgnoreMalformed == nil || !*prop.IgnoreMalformed {
					return false, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", fullPath, strings.ToLower(strings.TrimSpace(prop.Type)))
				}
			}
			continue
		}
		childMode := mode
		if prop.Dynamic != nil {
			childMode = normalizeDynamicMode(prop.Dynamic)
		}
		childSubobjects := parentSubobjects
		if prop.Subobjects != nil {
			childSubobjects = prop.Subobjects
		}
		if subMap, ok := v.(map[string]any); ok {
			subPruned, err := validateStrictDynamicObject(subMap, prop.Properties, childMode, childSubobjects, fullPath)
			if err != nil {
				return false, err
			}
			if subPruned {
				pruned = true
			}
		} else if slice, ok := v.([]any); ok {
			subPruned, err := validateStrictDynamicSlice(slice, prop.Properties, childMode, childSubobjects, fullPath)
			if err != nil {
				return false, err
			}
			if subPruned {
				pruned = true
			}
		}
	}
	return pruned, nil
}

func validateStrictDynamicSlice(slice []any, props map[string]esast.FieldProperty, childMode string, childSubobjects *bool, fullPath string) (bool, error) {
	pruned := false
	for _, elem := range slice {
		if elemMap, ok := elem.(map[string]any); ok {
			subPruned, err := validateStrictDynamicObject(elemMap, props, childMode, childSubobjects, fullPath)
			if err != nil {
				return false, err
			}
			if subPruned {
				pruned = true
			}
		} else if subSlice, ok := elem.([]any); ok {
			subPruned, err := validateStrictDynamicSlice(subSlice, props, childMode, childSubobjects, fullPath)
			if err != nil {
				return false, err
			}
			if subPruned {
				pruned = true
			}
		}
	}
	return pruned, nil
}

func hasExplicitNullAtPath(node any, path []string) bool {
	if len(path) == 0 {
		return false
	}
	if node == nil {
		return false
	}
	switch v := node.(type) {
	case map[string]any:
		if child, exists := v[path[0]]; exists {
			if len(path) == 1 {
				if isNullOrNullSlice(child) {
					return true
				}
			} else if hasExplicitNullAtPath(child, path[1:]) {
				return true
			}
		}
		for i := 2; i <= len(path); i++ {
			if c, ok := v[strings.Join(path[:i], ".")]; ok {
				if i == len(path) {
					if isNullOrNullSlice(c) {
						return true
					}
				} else if hasExplicitNullAtPath(c, path[i:]) {
					return true
				}
			}
		}
		return false
	case []any:
		for _, elem := range v {
			if hasExplicitNullAtPath(elem, path) {
				return true
			}
		}
	}
	return false
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	return b
}

// ParseESDateToEpochMillis parses ISO-8601 / RFC3339 date strings, epoch strings,
// and Elasticsearch date math expressions (`now`, `now-7d`, `now-1h/d`, `2024-01-01||+1d`)
// into Unix epoch milliseconds.
func ParseESDateToEpochMillis(input string, now time.Time) (int64, bool) {
	return ParseESDateBoundToEpochMillis(input, now, false)
}

// ESDateFormatToGoLayout converts an Elasticsearch / Java DateTimeFormatter pattern
// (such as "dd/MM/yyyy", "yyyy-MM-dd HH:mm:ss", "MM/dd/yyyy") into a Go time layout.
func ESDateFormatToGoLayout(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); {
		if pattern[i] == '\'' {
			i++
			for i < len(pattern) && pattern[i] != '\'' {
				b.WriteByte(pattern[i])
				i++
			}
			if i < len(pattern) {
				i++
			}
			continue
		}
		ch := pattern[i]
		j := i + 1
		for j < len(pattern) && pattern[j] == ch {
			j++
		}
		token := pattern[i:j]
		switch token {
		case "yyyy", "uuuu":
			b.WriteString("2006")
		case "yy", "uu":
			b.WriteString("06")
		case "MM":
			b.WriteString("01")
		case "M":
			b.WriteString("1")
		case "dd":
			b.WriteString("02")
		case "d":
			b.WriteString("2")
		case "HH":
			b.WriteString("15")
		case "hh":
			b.WriteString("03")
		case "h":
			b.WriteString("3")
		case "mm":
			b.WriteString("04")
		case "m":
			b.WriteString("4")
		case "ss":
			b.WriteString("05")
		case "s":
			b.WriteString("5")
		case "SSS":
			b.WriteString("000")
		case "Z":
			b.WriteString("-0700")
		case "X", "XX", "XXX":
			b.WriteString("Z07:00")
		default:
			b.WriteString(token)
		}
		i = j
	}
	return b.String()
}

// ParseESDateWithFormatToEpochMillis parses a date string or date math expression using an
// optional ES date format specification (e.g., "dd/MM/yyyy||epoch_millis") before falling back
// to standard ISO-8601 / epoch millis parsing.
func ParseESDateWithFormatToEpochMillis(input, format string, now time.Time) (int64, bool) {
	return ParseESDateBoundWithFormatToEpochMillis(input, format, now, false)
}

// ParseESDateBoundWithFormatToEpochMillis parses a date string or date math expression using an
// optional ES date format specification, rounding date-only or `/unit` expressions up when `roundUp` is true.
func ParseESDateBoundWithFormatToEpochMillis(input, format string, now time.Time, roundUp bool) (int64, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "now") {
		return ParseESDateBoundToEpochMillis(s, now, roundUp)
	}
	if strings.TrimSpace(format) != "" {
		prefix := s
		mathExpr := ""
		hasMath := false
		if idx := strings.Index(s, "||"); idx >= 0 {
			prefix = strings.TrimSpace(s[:idx])
			mathExpr = strings.TrimSpace(s[idx+2:])
			hasMath = true
		}
		finalizeFormatMatch := func(base time.Time, dateOnly bool) (int64, bool) {
			base = base.UTC()
			if !hasMath || mathExpr == "" {
				if roundUp && dateOnly {
					base = base.AddDate(0, 0, 1).Add(-time.Millisecond)
				}
				return base.UnixMilli(), true
			}
			mt, ok := applyESDateMathWithRound(base, mathExpr, roundUp)
			if !ok {
				return 0, false
			}
			if roundUp && dateOnly && !strings.Contains(mathExpr, "/") && hasOnlyCalendarDayOrLargerOffsets(mathExpr) {
				mt = mt.AddDate(0, 0, 1).Add(-time.Millisecond)
			}
			return mt.UnixMilli(), true
		}
		for _, rawFmt := range strings.Split(format, "||") {
			fmtPart := strings.TrimSpace(rawFmt)
			if fmtPart == "" {
				continue
			}
			switch fmtPart {
			case "epoch_second":
				if f, err := strconv.ParseFloat(prefix, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					base := time.UnixMilli(int64(math.Round(f * 1000))).UTC()
					return finalizeFormatMatch(base, false)
				}
			case "epoch_millis":
				if iv, err := strconv.ParseInt(prefix, 10, 64); err == nil {
					base := time.UnixMilli(iv).UTC()
					return finalizeFormatMatch(base, false)
				}
			case "epoch_nanos":
				if iv, err := strconv.ParseInt(prefix, 10, 64); err == nil {
					base := time.Unix(0, iv).UTC()
					return finalizeFormatMatch(base, false)
				}
			case "basic_date", "strict_basic_date":
				if len(prefix) == 8 {
					if t, err := time.Parse("20060102", prefix); err == nil {
						return finalizeFormatMatch(t, true)
					}
				}
			case "basic_date_time", "strict_basic_date_time":
				for _, l := range []string{"20060102T150405.000Z0700", "20060102T150405.000Z", "20060102T150405.999999999Z07:00"} {
					if t, err := time.Parse(l, prefix); err == nil {
						return finalizeFormatMatch(t, false)
					}
				}
			case "basic_date_time_no_millis", "strict_basic_date_time_no_millis":
				for _, l := range []string{"20060102T150405Z0700", "20060102T150405Z", "20060102T150405Z07:00"} {
					if t, err := time.Parse(l, prefix); err == nil {
						return finalizeFormatMatch(t, false)
					}
				}
			case "strict_date_optional_time", "date_optional_time", "strict_date", "date", "strict_date_hour_minute_second", "date_hour_minute_second":
				if t, ok := parseISODateString(prefix); ok {
					return finalizeFormatMatch(t, isDateOnlyString(prefix))
				}
			default:
				layout := ESDateFormatToGoLayout(fmtPart)
				if layout != "" {
					if t, err := time.Parse(layout, prefix); err == nil {
						dateOnly := !strings.ContainsAny(fmtPart, "HhmsS")
						return finalizeFormatMatch(t, dateOnly)
					}
				}
			}
		}
		return 0, false
	}
	return ParseESDateBoundToEpochMillis(s, now, roundUp)
}

// ParseESDateBoundToEpochMillis parses ISO-8601 / RFC3339 date strings, epoch strings,
// and Elasticsearch date math expressions into Unix epoch milliseconds.
// When `roundUp` is true (used for inclusive upper bounds like `lte`), rounding units (`/d`, `/h`, etc.)
// and date-only strings (`"2024-01-15"`) round to the end of the interval (`23:59:59.999` for `/d`).
func ParseESDateBoundToEpochMillis(input string, now time.Time, roundUp bool) (int64, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, false
	}
	if len(s) == 4 && (strings.HasPrefix(s, "19") || strings.HasPrefix(s, "20") || strings.HasPrefix(s, "21")) {
		if t, err := time.Parse("2006", s); err == nil {
			t = t.UTC()
			if roundUp {
				t = t.AddDate(1, 0, 0).Add(-time.Millisecond)
			}
			return t.UnixMilli(), true
		}
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}

	var baseTime time.Time
	var mathExpr string
	dateOnlyPrefix := false

	if strings.HasPrefix(s, "now") {
		mathExpr = s[3:]
		if mathExpr != "" && mathExpr[0] != '+' && mathExpr[0] != '-' && mathExpr[0] != '/' {
			return 0, false
		}
		baseTime = now.UTC()
	} else if idx := strings.Index(s, "||"); idx >= 0 {
		prefix := strings.TrimSpace(s[:idx])
		mathExpr = strings.TrimSpace(s[idx+2:])
		if ms, err := strconv.ParseInt(prefix, 10, 64); err == nil {
			if ms > 1_000_000_000_000_000 || ms < -1_000_000_000_000_000 {
				ms /= 1_000_000
			}
			baseTime = time.UnixMilli(ms).UTC()
		} else if t, ok := parseISODateString(prefix); ok {
			dateOnlyPrefix = isDateOnlyString(prefix)
			if roundUp && mathExpr == "" && dateOnlyPrefix {
				t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
			}
			baseTime = t
		} else {
			return 0, false
		}
	} else {
		t, ok := parseISODateString(s)
		if !ok {
			return 0, false
		}
		if roundUp && isDateOnlyString(s) {
			t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
		}
		return t.UnixMilli(), true
	}

	t, ok := applyESDateMathWithRound(baseTime, mathExpr, roundUp)
	if !ok {
		return 0, false
	}
	if roundUp && dateOnlyPrefix && mathExpr != "" && !strings.Contains(mathExpr, "/") && hasOnlyCalendarDayOrLargerOffsets(mathExpr) {
		t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
	}
	return t.UnixMilli(), true
}

func hasOnlyCalendarDayOrLargerOffsets(expr string) bool {
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '+' || c == '-' || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case 'y', 'Y', 'M', 'w', 'W', 'd', 'D':
		default:
			return false
		}
	}
	return true
}

func isDateOnlyString(s string) bool {
	return len(s) == 10 && (s[4] == '-' || s[4] == '/') && (s[7] == '-' || s[7] == '/')
}

func parseISODateString(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z0700",
		"2006-01-02T15:04:05.000Z0700",
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999Z0700",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006/01/02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func applyESDateMathWithRound(base time.Time, expr string, roundUp bool) (time.Time, bool) {
	t := base.UTC()
	i := 0
	for i < len(expr) {
		if expr[i] == '/' {
			i++
			if i >= len(expr) {
				return time.Time{}, false
			}
			switch expr[i] {
			case 'y', 'Y', 'M', 'w', 'W', 'd', 'D', 'h', 'H', 'm', 's':
				unit := expr[i]
				i++
				t = roundTimeToUnit(t, unit, roundUp && i == len(expr))
			default:
				return time.Time{}, false
			}
			continue
		}
		var sign int
		switch expr[i] {
		case '+':
			sign = 1
			i++
		case '-':
			sign = -1
			i++
		default:
			return time.Time{}, false
		}
		numStart := i
		for i < len(expr) && expr[i] >= '0' && expr[i] <= '9' {
			i++
		}
		if numStart == i || i >= len(expr) {
			return time.Time{}, false
		}
		n, err := strconv.Atoi(expr[numStart:i])
		if err != nil || n > 100000 {
			return time.Time{}, false
		}
		unit := expr[i]
		i++
		val := sign * n
		switch unit {
		case 'y', 'Y':
			t = t.AddDate(val, 0, 0)
		case 'M':
			t = t.AddDate(0, val, 0)
		case 'w', 'W':
			t = t.AddDate(0, 0, val*7)
		case 'd', 'D':
			t = t.AddDate(0, 0, val)
		case 'h', 'H':
			t = t.Add(time.Duration(val) * time.Hour)
		case 'm':
			t = t.Add(time.Duration(val) * time.Minute)
		case 's':
			t = t.Add(time.Duration(val) * time.Second)
		default:
			return time.Time{}, false
		}
	}
	return t, true
}

func roundTimeToUnit(t time.Time, roundUnit byte, roundUp bool) time.Time {
	switch roundUnit {
	case 'y', 'Y':
		t = time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(1, 0, 0).Add(-time.Millisecond)
		}
	case 'M':
		t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 1, 0).Add(-time.Millisecond)
		}
	case 'w', 'W':
		weekday := int(t.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		t = time.Date(t.Year(), t.Month(), t.Day()-(weekday-1), 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 0, 7).Add(-time.Millisecond)
		}
	case 'd', 'D':
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
		}
	case 'h', 'H':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC)
		if roundUp {
			t = t.Add(time.Hour - time.Millisecond)
		}
	case 'm':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
		if roundUp {
			t = t.Add(time.Minute - time.Millisecond)
		}
	case 's':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		if roundUp {
			t = t.Add(time.Second - time.Millisecond)
		}
	}
	return t
}

func extractScalarValue(node any, path []string) any {
	if len(path) == 0 {
		return normalizeScalar(node)
	}
	if node == nil {
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			if v := extractScalarValue(next, path[1:]); v != nil {
				return v
			}
		}
		for i := 2; i <= len(path); i++ {
			if next, exists := curr[strings.Join(path[:i], ".")]; exists {
				if v := extractScalarValue(next, path[i:]); v != nil {
					return v
				}
			}
		}
		return nil
	case []any:
		for _, elem := range curr {
			if v := extractScalarValue(elem, path); v != nil {
				return v
			}
		}
		return nil
	default:
		return nil
	}
}

func normalizeScalar(v any) any {
	switch val := v.(type) {
	case nil:
		return nil
	case []any:
		for _, elem := range val {
			if norm := normalizeScalar(elem); norm != nil {
				return norm
			}
		}
		return nil
	case map[string]any:
		if nameVal, ok := val["name"]; ok && nameVal != nil {
			return fmt.Sprintf("%v", nameVal)
		}
		b, _ := json.Marshal(val)
		return string(b)
	default:
		return val
	}
}

func extractStringSliceValuesWithNull(node any, path []string, lowercase bool, nullVal any) []string {
	var out []string
	collectStringsAtPathWithNull(node, path, lowercase, nullVal, &out)
	return out
}

func collectStringsAtPathWithNull(node any, path []string, lowercase bool, nullVal any, out *[]string) {
	if len(path) == 0 {
		if node == nil {
			if nullVal != nil {
				s := fmt.Sprintf("%v", nullVal)
				if lowercase {
					s = strings.ToLower(s)
				}
				*out = append(*out, s)
			}
			return
		}
		switch v := node.(type) {
		case string:
			if lowercase {
				v = strings.ToLower(v)
			}
			*out = append(*out, v)
		case []any:
			for _, item := range v {
				collectStringsAtPathWithNull(item, nil, lowercase, nullVal, out)
			}
		case map[string]any:
			return
		default:
			s := fmt.Sprintf("%v", v)
			if lowercase {
				s = strings.ToLower(s)
			}
			*out = append(*out, s)
		}
		return
	}
	if node == nil {
		return
	}

	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			collectStringsAtPathWithNull(next, path[1:], lowercase, nullVal, out)
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				collectStringsAtPathWithNull(next, path[i:], lowercase, nullVal, out)
			}
		}
	case []any:
		for _, elem := range curr {
			collectStringsAtPathWithNull(elem, path, lowercase, nullVal, out)
		}
	}
}

type nestedExtractedElem struct {
	m        map[string]any
	nestedID string
	parentID string
}

func joinNestedElemID(prefix string, idx int) string {
	s := strconv.Itoa(idx)
	if prefix == "" {
		return s
	}
	return prefix + "." + s
}

func splitNestedParentID(nestedID string) string {
	if dot := strings.LastIndexByte(nestedID, '.'); dot > 0 {
		return nestedID[:dot]
	}
	return ""
}

func extractNestedElementMapsWithIDs(node any, path []string, curPrefix string) []nestedExtractedElem {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case []any:
			var res []nestedExtractedElem
			for idx, item := range v {
				if m, ok := item.(map[string]any); ok {
					nid := joinNestedElemID(curPrefix, idx)
					res = append(res, nestedExtractedElem{
						m:        m,
						nestedID: nid,
						parentID: splitNestedParentID(nid),
					})
				}
			}
			return res
		case map[string]any:
			nid := joinNestedElemID(curPrefix, 0)
			return []nestedExtractedElem{{
				m:        v,
				nestedID: nid,
				parentID: splitNestedParentID(nid),
			}}
		}
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			return extractNestedElementMapsWithIDs(next, path[1:], curPrefix)
		}
		if len(path) > 1 {
			dotted := strings.Join(path, ".")
			if next, exists := curr[dotted]; exists {
				return extractNestedElementMapsWithIDs(next, nil, curPrefix)
			}
		}
		return nil
	case []any:
		var res []nestedExtractedElem
		for idx, elem := range curr {
			nextPrefix := joinNestedElemID(curPrefix, idx)
			res = append(res, extractNestedElementMapsWithIDs(elem, path, nextPrefix)...)
		}
		return res
	default:
		return nil
	}
}

func propagateCopyToCustomMultiFields(s *IndexSchema, row map[string]any, targetField string, srcVals []any, getNow func() time.Time, recordIgnored func(string)) error {
	if s == nil || len(s.Fields) == 0 || len(srcVals) == 0 {
		return nil
	}
	targetPrefix := targetField + "."
	for subK, subB := range s.Fields {
		if !strings.HasPrefix(subK, targetPrefix) || subK == targetField+".keyword" || subB.AliasTarget != "" {
			continue
		}
		if strings.Join(subB.SourceJSONPath, ".") != targetField || subB.ColumnName == "" {
			continue
		}
		switch subB.Kind {
		case StoragePromotedArray, StorageNestedSubfield:
			var cur []string
			if existing, ok := row[subB.ColumnName].([]string); ok {
				cur = append(cur, existing...)
			}
			for _, rv := range srcVals {
				if rv == nil {
					continue
				}
				sv := fmt.Sprintf("%v", rv)
				if subB.IgnoreAbove > 0 && len([]rune(sv)) > subB.IgnoreAbove {
					continue
				}
				if isTypedNonStringBinding(subB) {
					if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && subB.ESType != "version" && (subB.Coerce == nil || *subB.Coerce) {
						continue
					}
					coerced := coerceScalarBindingForDoris(rv, subB, getNow())
					if coerced == nil {
						if subB.IgnoreMalformed != nil && *subB.IgnoreMalformed {
							if recordIgnored != nil {
								recordIgnored(subK)
							}
							continue
						}
						return fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", subK, subB.ESType)
					}
					if subB.ESType == "date_nanos" {
						if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
							coerced = iv / 1_000_000
						}
					}
					if subB.ESType == "unsigned_long" {
						if u, okU := parseExactUint64(rv); okU && u > uint64(math.MaxInt64) {
							cur = append(cur, strconv.FormatUint(u, 10))
							continue
						}
					}
					sv = formatCoercedArrayElement(coerced)
				} else if subB.LowercaseNormalizer {
					sv = strings.ToLower(sv)
				}
				cur = append(cur, sv)
			}
			if len(cur) > 0 {
				row[subB.ColumnName] = cur
			}
		case StoragePromotedScalar:
			if isTypedNonStringBinding(subB) {
				for _, rv := range srcVals {
					if rv == nil {
						continue
					}
					if subB.IgnoreAbove > 0 && len([]rune(fmt.Sprintf("%v", rv))) > subB.IgnoreAbove {
						continue
					}
					if strVal, isStr := rv.(string); isStr && strings.TrimSpace(strVal) == "" && subB.ESType != "version" && (subB.Coerce == nil || *subB.Coerce) {
						continue
					}
					coerced := coerceScalarBindingForDoris(rv, subB, getNow())
					if coerced == nil {
						if subB.IgnoreMalformed != nil && *subB.IgnoreMalformed {
							if recordIgnored != nil {
								recordIgnored(subK)
							}
							continue
						}
						return fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]", subK, subB.ESType)
					}
					if subB.ESType == "date_nanos" {
						if iv, ok := coerced.(int64); ok && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
							coerced = iv / 1_000_000
						}
					}
					if existing, exists := row[subB.ColumnName]; !exists || existing == nil {
						row[subB.ColumnName] = coerced
					}
				}
			} else {
				var filtered []string
				for _, rv := range srcVals {
					if rv == nil {
						continue
					}
					sv := fmt.Sprintf("%v", rv)
					if subB.IgnoreAbove > 0 && len([]rune(sv)) > subB.IgnoreAbove {
						continue
					}
					if subB.LowercaseNormalizer {
						sv = strings.ToLower(sv)
					}
					filtered = append(filtered, sv)
				}
				if len(filtered) > 0 {
					joined := strings.Join(filtered, " ")
					if existing, exists := row[subB.ColumnName]; exists && existing != nil {
						row[subB.ColumnName] = fmt.Sprintf("%v %s", existing, joined)
					} else {
						row[subB.ColumnName] = joined
					}
				}
			}
		}
	}
	return nil
}

func buildVariantDocPayload(trimmed []byte, parsedDoc map[string]any, prunedDynamic bool, s *IndexSchema) json.RawMessage {
	if !prunedDynamic && (s == nil || len(s.Fields) == 0) {
		return json.RawMessage(trimmed)
	}
	var enabledFalsePaths [][]string
	if s != nil {
		for _, b := range s.Fields {
			if b.EnabledFalse && len(b.SourceJSONPath) > 0 {
				enabledFalsePaths = append(enabledFalsePaths, b.SourceJSONPath)
			}
		}
	}
	if !prunedDynamic && len(enabledFalsePaths) == 0 {
		return json.RawMessage(trimmed)
	}
	if prunedDynamic && parsedDoc != nil {
		for _, p := range enabledFalsePaths {
			deletePathInMap(parsedDoc, p)
		}
		b, err := json.Marshal(parsedDoc)
		if err != nil {
			return json.RawMessage(trimmed)
		}
		return json.RawMessage(b)
	}
	var docMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&docMap); err != nil || docMap == nil {
		return json.RawMessage(trimmed)
	}
	modified := false
	for _, p := range enabledFalsePaths {
		if deletePathInMap(docMap, p) {
			modified = true
		}
	}
	if !modified {
		return json.RawMessage(trimmed)
	}
	b, err := json.Marshal(docMap)
	if err != nil {
		return json.RawMessage(trimmed)
	}
	return json.RawMessage(b)
}

func isPrimaryFieldBinding(b FieldBinding) bool {
	return len(b.SourceJSONPath) > 0 && b.ESFieldPath == strings.Join(b.SourceJSONPath, ".")
}

func replacePathSliceInMap(curr map[string]any, path []string, validLeafs []any) bool {
	if len(path) == 0 || curr == nil {
		return false
	}
	dotFull := strings.Join(path, ".")
	if _, ok := curr[dotFull]; ok {
		curr[dotFull] = validLeafs
		return true
	}
	if len(path) == 1 {
		if _, ok := curr[path[0]]; ok {
			curr[path[0]] = validLeafs
			return true
		}
		return false
	}
	next, exists := curr[path[0]]
	if !exists {
		return false
	}
	switch tv := next.(type) {
	case map[string]any:
		return replacePathSliceInMap(tv, path[1:], validLeafs)
	case []any:
		replaced := false
		for _, elem := range tv {
			if em, ok := elem.(map[string]any); ok {
				if replacePathSliceInMap(em, path[1:], validLeafs) {
					replaced = true
				}
			}
		}
		return replaced
	}
	return false
}

func cleanMalformedNestedLeafInMap(curr map[string]any, path []string, b FieldBinding, now time.Time) bool {
	if len(path) == 0 || curr == nil {
		return false
	}
	dotFull := strings.Join(path, ".")
	if val, ok := curr[dotFull]; ok {
		cleaned, keep, changed := cleanMalformedNestedLeafValue(val, b, now)
		if !keep {
			delete(curr, dotFull)
			return true
		}
		if changed {
			curr[dotFull] = cleaned
			return true
		}
		return false
	}
	if len(path) == 1 {
		val, ok := curr[path[0]]
		if !ok {
			return false
		}
		cleaned, keep, changed := cleanMalformedNestedLeafValue(val, b, now)
		if !keep {
			delete(curr, path[0])
			return true
		}
		if changed {
			curr[path[0]] = cleaned
			return true
		}
		return false
	}
	next, exists := curr[path[0]]
	if !exists {
		return false
	}
	switch tv := next.(type) {
	case map[string]any:
		return cleanMalformedNestedLeafInMap(tv, path[1:], b, now)
	case []any:
		modified := false
		for _, elem := range tv {
			if em, ok := elem.(map[string]any); ok {
				if cleanMalformedNestedLeafInMap(em, path[1:], b, now) {
					modified = true
				}
			}
		}
		return modified
	}
	return false
}

func cleanMalformedNestedLeafValue(val any, b FieldBinding, now time.Time) (any, bool, bool) {
	if val == nil {
		return nil, true, false
	}
	if arr, isSlice := val.([]any); isSlice {
		if b.ESType == "geo_point" && len(arr) == 2 && isGeoNumericElem(arr[0]) && isGeoNumericElem(arr[1]) {
			if _, _, _, ok := parseAndFormatGeoPointValue(arr); !ok {
				return nil, false, true
			}
			return val, true, false
		}
		out := make([]any, 0, len(arr))
		changed := false
		for _, item := range arr {
			cItem, keep, itemChanged := cleanMalformedNestedLeafValue(item, b, now)
			if !keep {
				changed = true
				continue
			}
			if itemChanged {
				changed = true
			}
			out = append(out, cItem)
		}
		if len(out) == 0 {
			return nil, false, true
		}
		return out, true, changed
	}
	if m, isMap := val.(map[string]any); isMap {
		if b.ESType == "geo_point" {
			cands := extractGeoPointCandidatesWithNull(map[string]any{"v": m}, []string{"v"}, b.NullValue)
			if len(cands) == 0 || coerceScalarBindingForDoris(cands[0], b, now) == nil {
				return nil, false, true
			}
			return val, true, false
		}
		if b.ESType != "object" && b.ESType != "flattened" {
			return nil, false, true
		}
		return val, true, false
	}
	if isTypedNonStringBinding(b) {
		if b.ESType == "geo_point" {
			cands := extractGeoPointCandidatesWithNull(map[string]any{"v": val}, []string{"v"}, b.NullValue)
			if len(cands) == 0 || coerceScalarBindingForDoris(cands[0], b, now) == nil {
				return nil, false, true
			}
			return val, true, false
		}
		if strVal, isStr := val.(string); isStr && strings.TrimSpace(strVal) == "" && (b.Coerce == nil || *b.Coerce) {
			return nil, false, true
		}
		if coerceScalarBindingForDoris(val, b, now) == nil {
			return nil, false, true
		}
	}
	return val, true, false
}

func deletePathInMap(curr map[string]any, path []string) bool {
	if len(path) == 0 || curr == nil {
		return false
	}
	dotFull := strings.Join(path, ".")
	dotPrefix := dotFull + "."
	removed := false
	for k := range curr {
		if k == dotFull || strings.HasPrefix(k, dotPrefix) {
			delete(curr, k)
			removed = true
		}
	}
	if len(path) == 1 {
		return removed
	}
	next, exists := curr[path[0]]
	if !exists {
		return removed
	}
	switch tv := next.(type) {
	case map[string]any:
		if deletePathInMap(tv, path[1:]) {
			removed = true
		}
	case []any:
		for _, elem := range tv {
			if em, ok := elem.(map[string]any); ok {
				if deletePathInMap(em, path[1:]) {
					removed = true
				}
			}
		}
	}
	return removed
}

func isStrictLeafESType(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "text", "match_only_text", "keyword", "constant_keyword", "wildcard", "ip",
		"long", "unsigned_long", "integer", "short", "byte", "token_count",
		"double", "float", "half_float", "scaled_float", "boolean", "date", "date_nanos",
		"version", "search_as_you_type", "annotated-text", "annotated_text":
		return true
	default:
		return false
	}
}

func isStrictLeafFieldWithoutSubprops(s *IndexSchema, b FieldBinding) bool {
	if b.AliasTarget != "" || DefaultMultiValuedPaths[b.ESFieldPath] {
		return false
	}
	if !isStrictLeafESType(b.ESType) {
		return false
	}
	if s != nil {
		srcDot := strings.Join(b.SourceJSONPath, ".")
		prefix := srcDot + "."
		for _, other := range s.Fields {
			if len(other.SourceJSONPath) > len(b.SourceJSONPath) && strings.HasPrefix(strings.Join(other.SourceJSONPath, "."), prefix) {
				return false
			}
		}
	}
	return true
}

func hasObjectValueAtPath(node any, path []string) bool {
	if node == nil {
		return false
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case map[string]any:
			return true
		case []any:
			for _, elem := range v {
				if hasObjectValueAtPath(elem, nil) {
					return true
				}
			}
		}
		return false
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			if hasObjectValueAtPath(next, path[1:]) {
				return true
			}
		}
		for i := 2; i <= len(path); i++ {
			if next, exists := curr[strings.Join(path[:i], ".")]; exists {
				if hasObjectValueAtPath(next, path[i:]) {
					return true
				}
			}
		}
	case []any:
		for _, elem := range curr {
			if hasObjectValueAtPath(elem, path) {
				return true
			}
		}
	}
	return false
}

func collectAllTextWithSchema(node any, s *IndexSchema, curPath []string, sb *strings.Builder) {
	switch v := node.(type) {
	case string:
		if v != "" {
			if s != nil && len(s.Fields) > 0 && len(curPath) > 0 {
				dotPath := strings.Join(curPath, ".")
				b := s.ResolveField(dotPath)
				if b.IgnoreAbove > 0 && len([]rune(v)) > b.IgnoreAbove {
					return
				}
			}
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(v)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			nextPath := append(append([]string(nil), curPath...), k)
			var b FieldBinding
			if s != nil && len(s.Fields) > 0 {
				dotPath := strings.Join(nextPath, ".")
				b = s.ResolveField(dotPath)
				if b.EnabledFalse {
					continue
				}
				if b.NotIndexed {
					hasIndexedCopyOrSub := false
					if b.KeywordCompanion != "" {
						if kwB, ok := s.Fields[dotPath+".keyword"]; ok && !kwB.NotIndexed && !kwB.EnabledFalse {
							hasIndexedCopyOrSub = true
						}
					}
					if !hasIndexedCopyOrSub {
						for _, ct := range b.CopyTo {
							tb := s.ResolveField(ct)
							if !tb.NotIndexed && !tb.EnabledFalse {
								hasIndexedCopyOrSub = true
								break
							}
						}
					}
					if !hasIndexedCopyOrSub {
						continue
					}
				}
			}
			if v[k] == nil && b.NullValue != nil && !b.NotIndexed && !b.EnabledFalse {
				collectAllTextWithSchema(fmt.Sprintf("%v", b.NullValue), s, nextPath, sb)
				continue
			}
			collectAllTextWithSchema(v[k], s, nextPath, sb)
		}
	case []any:
		for _, child := range v {
			collectAllTextWithSchema(child, s, curPath, sb)
		}
	}
}

func docHasExplicitFieldPath(doc map[string]any, segs []string) bool {
	if len(doc) == 0 || len(segs) == 0 {
		return false
	}
	if val, exists := doc[segs[0]]; exists {
		if len(segs) == 1 {
			return true
		}
		if docValueHasExplicitFieldPath(val, segs[1:]) {
			return true
		}
	}
	if len(segs) > 1 {
		full := strings.Join(segs, ".")
		if _, exists := doc[full]; exists {
			return true
		}
		for k := 2; k < len(segs); k++ {
			prefix := strings.Join(segs[:k], ".")
			if val, exists := doc[prefix]; exists {
				if docValueHasExplicitFieldPath(val, segs[k:]) {
					return true
				}
			}
		}
	}
	return false
}

func docValueHasExplicitFieldPath(val any, segs []string) bool {
	if len(segs) == 0 {
		return true
	}
	switch v := val.(type) {
	case map[string]any:
		return docHasExplicitFieldPath(v, segs)
	case []any:
		for _, elem := range v {
			if docValueHasExplicitFieldPath(elem, segs) {
				return true
			}
		}
	}
	return false
}

func extractAndValidateVectorValues(node any, path []string, dims int) ([]float64, bool, bool) {
	if node == nil {
		return nil, false, true
	}
	if len(path) == 0 {
		arr, ok := node.([]any)
		if !ok || len(arr) == 0 {
			return nil, true, false
		}
		out := make([]float64, 0, len(arr))
		for _, elem := range arr {
			switch v := elem.(type) {
			case float64:
				if math.IsNaN(v) || math.IsInf(v, 0) {
					return nil, true, false
				}
				out = append(out, v)
			case int:
				out = append(out, float64(v))
			case int64:
				out = append(out, float64(v))
			case json.Number:
				f, err := v.Float64()
				if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
					return nil, true, false
				}
				out = append(out, f)
			default:
				return nil, true, false
			}
		}
		if dims > 0 && len(out) != dims {
			return out, true, false
		}
		return out, true, true
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil, false, true
	}
	if next, exists := m[path[0]]; exists {
		return extractAndValidateVectorValues(next, path[1:], dims)
	}
	for i := len(path); i > 1; i-- {
		if next, exists := m[strings.Join(path[:i], ".")]; exists {
			return extractAndValidateVectorValues(next, path[i:], dims)
		}
	}
	return nil, false, true
}

func cloneNestedMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch tv := v.(type) {
		case map[string]any:
			out[k] = cloneNestedMap(tv)
		case []any:
			s := make([]any, len(tv))
			for i, item := range tv {
				if subM, ok := item.(map[string]any); ok {
					s[i] = cloneNestedMap(subM)
				} else {
					s[i] = item
				}
			}
			out[k] = s
		default:
			out[k] = v
		}
	}
	return out
}

func expandFlatDottedKeysInMap(curr map[string]any) {
	if curr == nil {
		return
	}
	var dottedKeys []string
	for k := range curr {
		if strings.Contains(k, ".") && !strings.HasPrefix(k, "_") {
			dottedKeys = append(dottedKeys, k)
		}
	}
	sort.Strings(dottedKeys)
	for _, k := range dottedKeys {
		val := curr[k]
		delete(curr, k)
		parts := strings.SplitN(k, ".", 2)
		if existingSub, ok := curr[parts[0]].(map[string]any); ok {
			existingSub[parts[1]] = val
		} else {
			curr[parts[0]] = map[string]any{parts[1]: val}
		}
	}
	for _, v := range curr {
		switch tv := v.(type) {
		case map[string]any:
			expandFlatDottedKeysInMap(tv)
		case []any:
			for _, elem := range tv {
				if subM, ok := elem.(map[string]any); ok {
					expandFlatDottedKeysInMap(subM)
				}
			}
		}
	}
}

func normalizeNestedElementForStorage(s *IndexSchema, nestedPath string, rootParts []string, elemMap map[string]any, getNow func() time.Time) map[string]any {
	if s == nil || elemMap == nil {
		return elemMap
	}
	cloned := cloneNestedMap(elemMap)
	expandFlatDottedKeysInMap(cloned)
	fields := s.OrderedFields
	if len(fields) == 0 {
		for _, b := range s.Fields {
			fields = append(fields, b)
		}
	}

	copiedNestedVals := make(map[string][]string)
	for _, b := range fields {
		if b.Kind != StorageNestedSubfield || b.NestedPath != nestedPath || len(b.CopyTo) == 0 {
			continue
		}
		if len(b.SourceJSONPath) <= len(rootParts) {
			continue
		}
		relPath := b.SourceJSONPath[len(rootParts):]
		rawSrcVals := extractStringSliceValuesWithNull(cloned, relPath, false, b.NullValue)
		for _, sv := range rawSrcVals {
			if b.IgnoreAbove > 0 && len([]rune(sv)) > b.IgnoreAbove {
				continue
			}
			copiedNestedVals[b.ESFieldPath] = append(copiedNestedVals[b.ESFieldPath], sv)
		}
	}
	if len(copiedNestedVals) > 0 {
		forwardedNested := make(map[string]int)
		for pass := 0; pass < 4; pass++ {
			progressed := false
			for _, b := range fields {
				if b.Kind != StorageNestedSubfield || b.NestedPath != nestedPath || len(b.CopyTo) == 0 {
					continue
				}
				allSrc := copiedNestedVals[b.ESFieldPath]
				if len(allSrc) == 0 {
					continue
				}
				for _, targetField := range b.CopyTo {
					edgeKey := b.ESFieldPath + "\x00" + targetField
					already := forwardedNested[edgeKey]
					if already >= len(allSrc) {
						continue
					}
					srcVals := allSrc[already:]
					forwardedNested[edgeKey] = len(allSrc)
					progressed = true

					tb, ok := s.Fields[targetField]
					if !ok && b.NestedPath != "" {
						if rtb, rOK := s.Fields[b.NestedPath+"."+targetField]; rOK {
							targetField = b.NestedPath + "." + targetField
							tb = rtb
							ok = true
						}
					}
					if ok && tb.AliasTarget != "" {
						if rtb, rOK := s.Fields[tb.AliasTarget]; rOK {
							targetField = tb.AliasTarget
							tb = rtb
						}
					}
					var filteredSrc []string
					for _, sv := range srcVals {
						if ok && tb.IgnoreAbove > 0 && len([]rune(sv)) > tb.IgnoreAbove {
							continue
						}
						if ok && tb.LowercaseNormalizer {
							sv = strings.ToLower(sv)
						}
						filteredSrc = append(filteredSrc, sv)
					}
					if len(filteredSrc) > 0 {
						copiedNestedVals[targetField] = append(copiedNestedVals[targetField], filteredSrc...)
					}
					if !ok || tb.NestedPath != nestedPath || len(tb.SourceJSONPath) <= len(rootParts) || len(srcVals) == 0 {
						continue
					}
					tRelPath := tb.SourceJSONPath[len(rootParts):]
					if len(tRelPath) >= 1 {
						appendNestedCopyToAtPath(s, cloned, tRelPath, srcVals, tb)
					}
				}
			}
			if !progressed {
				break
			}
		}
	}

	// Run .keyword and custom multi-field companion normalization first so base field normalization does not clobber the raw value before companion keys are populated.
	for _, b := range fields {
		if b.Kind != StorageNestedSubfield || b.NestedPath != nestedPath {
			continue
		}
		if len(b.SourceJSONPath) <= len(rootParts) || b.AliasTarget != "" {
			continue
		}
		srcDotPath := strings.Join(b.SourceJSONPath, ".")
		if !strings.HasPrefix(b.ESFieldPath, srcDotPath+".") {
			continue
		}
		subKey := strings.TrimPrefix(b.ESFieldPath, srcDotPath+".")
		if subKey == "" || strings.Contains(subKey, ".") {
			continue
		}
		baseB, hasBase := s.Fields[srcDotPath]
		if !hasBase {
			continue
		}
		relPath := b.SourceJSONPath[len(rootParts):]
		if b.IgnoreAbove > 0 || b.LowercaseNormalizer || b.IsMultiValued || b.NullValue != nil ||
			baseB.IgnoreAbove > 0 || baseB.LowercaseNormalizer || baseB.NullValue != nil ||
			b.ESType != baseB.ESType || b.Format != baseB.Format || b.ScalingFactor != baseB.ScalingFactor {
			applyNestedCompanionNormalizationAtPath(cloned, relPath, "__"+subKey, b, getNow)
		}
	}
	for _, b := range fields {
		if b.Kind != StorageNestedSubfield || b.NestedPath != nestedPath {
			continue
		}
		if len(b.SourceJSONPath) <= len(rootParts) {
			continue
		}
		if strings.HasSuffix(b.ESFieldPath, ".keyword") {
			if _, hasBase := s.Fields[strings.TrimSuffix(b.ESFieldPath, ".keyword")]; hasBase {
				continue
			}
		}
		if b.AliasTarget == "" && strings.Join(b.SourceJSONPath, ".") != b.ESFieldPath {
			continue
		}
		relPath := b.SourceJSONPath[len(rootParts):]
		applyNestedBindingNormalizationAtPath(cloned, relPath, b, getNow)
	}
	return cloned
}

func appendNestedCopyToAtPath(s *IndexSchema, curr map[string]any, relPath []string, srcVals []string, tb FieldBinding) {
	if len(relPath) == 0 || curr == nil || len(srcVals) == 0 {
		return
	}
	key := relPath[0]
	if len(relPath) > 1 {
		nextVal, exists := curr[key]
		if !exists || nextVal == nil {
			nextMap := make(map[string]any)
			curr[key] = nextMap
			appendNestedCopyToAtPath(s, nextMap, relPath[1:], srcVals, tb)
			return
		}
		switch tv := nextVal.(type) {
		case map[string]any:
			appendNestedCopyToAtPath(s, tv, relPath[1:], srcVals, tb)
		case []any:
			for _, elem := range tv {
				if em, ok := elem.(map[string]any); ok {
					appendNestedCopyToAtPath(s, em, relPath[1:], srcVals, tb)
				}
			}
		}
		return
	}
	if !IsTextLikeESType(tb.ESType) {
		var arr []any
		if existing, exists := curr[key]; exists && existing != nil {
			if exSlice, okS := existing.([]any); okS {
				arr = append(arr, exSlice...)
			} else {
				arr = append(arr, existing)
			}
		}
		for _, sv := range srcVals {
			arr = append(arr, sv)
		}
		if len(arr) == 1 {
			curr[key] = arr[0]
		} else if len(arr) > 1 {
			curr[key] = arr
		}
	} else {
		var companionKeys []string
		if tb.KeywordCompanion != "" {
			companionKeys = append(companionKeys, key+"__keyword")
		}
		if s != nil && len(s.Fields) > 0 && tb.ESFieldPath != "" {
			prefix := tb.ESFieldPath + "."
			for fk, fb := range s.Fields {
				if !strings.HasPrefix(fk, prefix) || fb.AliasTarget != "" {
					continue
				}
				subKey := strings.TrimPrefix(fk, prefix)
				if subKey == "" || strings.Contains(subKey, ".") || subKey == "keyword" {
					continue
				}
				companionKeys = append(companionKeys, key+"__"+subKey)
			}
		}
		for _, kwKey := range companionKeys {
			var kwArr []any
			if exKw, hasKw := curr[kwKey]; hasKw && exKw != nil {
				if exSlice, okS := exKw.([]any); okS {
					kwArr = append(kwArr, exSlice...)
				} else {
					kwArr = append(kwArr, exKw)
				}
			} else if existing, exists := curr[key]; exists && existing != nil {
				if exSlice, okS := existing.([]any); okS {
					kwArr = append(kwArr, exSlice...)
				} else {
					kwArr = append(kwArr, existing)
				}
			}
			for _, sv := range srcVals {
				kwArr = append(kwArr, sv)
			}
			if len(kwArr) == 1 {
				curr[kwKey] = kwArr[0]
			} else if len(kwArr) > 1 {
				curr[kwKey] = kwArr
			}
		}
		joined := strings.Join(srcVals, " ")
		if existing, exists := curr[key]; exists && existing != nil {
			curr[key] = fmt.Sprintf("%v %s", existing, joined)
		} else {
			curr[key] = joined
		}
	}
}

func applyNestedCompanionNormalizationAtPath(curr map[string]any, relPath []string, suffix string, b FieldBinding, getNow func() time.Time) {
	if len(relPath) == 0 || curr == nil {
		return
	}
	expandFlatDottedKeysInMap(curr)
	key := relPath[0]
	val, exists := curr[key]
	if !exists {
		return
	}
	if len(relPath) > 1 {
		switch tv := val.(type) {
		case map[string]any:
			applyNestedCompanionNormalizationAtPath(tv, relPath[1:], suffix, b, getNow)
		case []any:
			for _, item := range tv {
				if subM, ok := item.(map[string]any); ok {
					applyNestedCompanionNormalizationAtPath(subM, relPath[1:], suffix, b, getNow)
				}
			}
		}
		return
	}
	compKey := key + suffix
	var norm any
	if compVal, hasComp := curr[compKey]; hasComp {
		norm = normalizeNestedLeafValue(compVal, b, getNow)
	} else {
		norm = normalizeNestedLeafValue(val, b, getNow)
	}
	if norm == nil {
		delete(curr, compKey)
	} else {
		curr[compKey] = norm
	}
}

func applyNestedBindingNormalizationAtPath(curr map[string]any, relPath []string, b FieldBinding, getNow func() time.Time) {
	if len(relPath) == 0 || curr == nil {
		return
	}
	expandFlatDottedKeysInMap(curr)
	key := relPath[0]
	val, exists := curr[key]
	if !exists {
		if b.ESType == "constant_keyword" && b.ConstantValue != nil {
			if len(relPath) == 1 {
				expectedStr := fmt.Sprintf("%v", b.ConstantValue)
				if b.LowercaseNormalizer {
					expectedStr = strings.ToLower(expectedStr)
				}
				curr[key] = expectedStr
			} else {
				nextMap := make(map[string]any)
				curr[key] = nextMap
				applyNestedBindingNormalizationAtPath(nextMap, relPath[1:], b, getNow)
			}
		}
		return
	}
	if len(relPath) > 1 {
		switch tv := val.(type) {
		case map[string]any:
			applyNestedBindingNormalizationAtPath(tv, relPath[1:], b, getNow)
		case []any:
			for _, item := range tv {
				if subM, ok := item.(map[string]any); ok {
					applyNestedBindingNormalizationAtPath(subM, relPath[1:], b, getNow)
				}
			}
		}
		return
	}
	norm := normalizeNestedLeafValue(val, b, getNow)
	if norm == nil && val != nil {
		delete(curr, key)
	} else {
		curr[key] = norm
	}
}

func normalizeNestedLeafValue(val any, b FieldBinding, getNow func() time.Time) any {
	if b.ESType == "constant_keyword" && b.ConstantValue != nil {
		expectedStr := fmt.Sprintf("%v", b.ConstantValue)
		if b.LowercaseNormalizer {
			expectedStr = strings.ToLower(expectedStr)
		}
		if val != nil {
			if arr, ok := val.([]any); ok {
				var out []any
				for _, item := range arr {
					if norm := normalizeNestedLeafValue(item, b, getNow); norm != nil {
						out = append(out, norm)
					}
				}
				if len(out) == 0 && len(arr) > 0 {
					return nil
				}
				return out
			}
			sv := fmt.Sprintf("%v", val)
			if b.LowercaseNormalizer {
				sv = strings.ToLower(sv)
			}
			if sv != expectedStr {
				return nil
			}
		}
		return expectedStr
	}
	if val == nil {
		if b.NullValue != nil {
			return normalizeNestedLeafValue(b.NullValue, b, getNow)
		}
		return nil
	}
	if b.ESType == "flattened" {
		norm, _, err := validateAndNormalizeFlattenedValue(val, b, nil)
		if err != nil {
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
			return val
		}
		return norm
	}
	if arr, ok := val.([]any); ok {
		if b.ESType == "geo_point" && len(arr) == 2 && isGeoNumericElem(arr[0]) && isGeoNumericElem(arr[1]) {
			if formatted, _, _, okGeo := parseAndFormatGeoPointValue(arr); okGeo {
				return formatted
			}
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
			return val
		}
		var out []any
		for _, item := range arr {
			norm := normalizeNestedLeafValue(item, b, getNow)
			if norm != nil {
				out = append(out, norm)
			}
		}
		if len(out) == 0 && len(arr) > 0 {
			return nil
		}
		return out
	}
	if IsRangeFieldType(b.ESType) {
		norm, _, err := validateAndNormalizeRangeValue(val, b, getNow)
		if err != nil {
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
			return val
		}
		return norm
	}
	if _, isMap := val.(map[string]any); isMap && b.ESType != "geo_point" && b.ESType != "object" && b.ESType != "flattened" && b.ESType != "sparse_vector" && b.ESType != "rank_features" {
		return nil
	}
	if b.IgnoreAbove > 0 {
		str, ok := val.(string)
		if !ok && (b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || b.DorisType == DorisVarchar) {
			str = fmt.Sprintf("%v", val)
			ok = true
		}
		if ok && len([]rune(str)) > b.IgnoreAbove {
			return nil
		}
	}
	if isTypedNonStringBinding(b) {
		if strVal, isStr := val.(string); isStr && strings.TrimSpace(strVal) == "" && (b.Coerce == nil || *b.Coerce) {
			return nil
		}
	}
	if b.ESType == "date" || b.ESType == "date_nanos" {
		if b.Coerce != nil && !*b.Coerce && b.Format != "" && !dateFormatAllowsNumericWithNoCoerce(b.Format) {
			switch val.(type) {
			case int, int64, float64, json.Number:
				return nil
			}
		}
		str := strings.TrimSpace(fmt.Sprintf("%v", val))
		if b.Format != "" {
			if ms, ok := ParseESDateWithFormatToEpochMillis(str, b.Format, getNow()); ok {
				if b.ESType == "date_nanos" && (ms > 1_000_000_000_000_000 || ms < -1_000_000_000_000_000) {
					return ms / 1_000_000
				}
				return ms
			}
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
		} else {
			if iv, err := strconv.ParseInt(str, 10, 64); err == nil {
				if b.ESType == "date_nanos" && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
					return iv / 1_000_000
				}
				return iv
			}
			if ms, ok := ParseESDateToEpochMillis(str, getNow()); ok {
				return ms
			}
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
		}
	} else if b.ESType == "boolean" || b.DorisType == DorisBoolean {
		if b.Coerce != nil && !*b.Coerce {
			if bv, ok := val.(bool); ok {
				return bv
			}
			if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
				return nil
			}
			return val
		}
		switch strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val))) {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
		if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
			return nil
		}
	} else if b.ESType == "scaled_float" && b.ScalingFactor > 0 {
		coerced := coerceScalarBindingForDoris(val, b, getNow())
		if coerced != nil {
			return coerced
		}
		if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
			return nil
		}
		if b.Coerce != nil && !*b.Coerce {
			return nil
		}
	} else if isTypedNonStringBinding(b) {
		coerced := coerceScalarBindingForDoris(val, b, getNow())
		if coerced != nil {
			if b.ESType == "unsigned_long" {
				if u, okU := parseExactUint64(val); okU && u > uint64(math.MaxInt64) {
					return json.Number(strconv.FormatUint(u, 10))
				}
			}
			return coerced
		}
		if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
			return nil
		}
		if (b.Coerce != nil && !*b.Coerce) || b.ESType == "float" || b.ESType == "half_float" || b.ESType == "version" || b.ESType == "ip" {
			return nil
		}
	} else if b.LowercaseNormalizer {
		if str, ok := val.(string); ok {
			return strings.ToLower(str)
		} else if b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || b.DorisType == DorisVarchar {
			return strings.ToLower(fmt.Sprintf("%v", val))
		}
	} else if b.ESType == "keyword" || b.ESType == "constant_keyword" || b.ESType == "wildcard" || IsTextLikeESType(b.ESType) || b.DorisType == DorisVarchar {
		if _, isStr := val.(string); !isStr {
			return fmt.Sprintf("%v", val)
		}
	}
	return val
}

func extractCompletionStringsWithNull(node any, path []string, lowercase bool, nullVal any) ([]string, error) {
	var out []string
	if err := collectCompletionStringsAtPath(node, path, lowercase, nullVal, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func collectCompletionStringsAtPath(node any, path []string, lowercase bool, nullVal any, out *[]string) error {
	if len(path) == 0 {
		if node == nil {
			if nullVal != nil {
				s := fmt.Sprintf("%v", nullVal)
				if lowercase {
					s = strings.ToLower(s)
				}
				*out = append(*out, s)
			}
			return nil
		}
		switch v := node.(type) {
		case string:
			if lowercase {
				v = strings.ToLower(v)
			}
			*out = append(*out, v)
		case []any:
			for _, item := range v {
				if err := collectCompletionStringsAtPath(item, nil, lowercase, nullVal, out); err != nil {
					return err
				}
			}
		case map[string]any:
			inp, hasInput := v["input"]
			if !hasInput || inp == nil {
				return fmt.Errorf("mapper_parsing_exception: [completion] field object missing required [input]")
			}
			for k := range v {
				switch k {
				case "input", "weight", "contexts":
				default:
					return fmt.Errorf("mapper_parsing_exception: [completion] unknown field [%s]", k)
				}
			}
			switch iv := inp.(type) {
			case string:
				if lowercase {
					iv = strings.ToLower(iv)
				}
				*out = append(*out, iv)
			case []any:
				for _, elem := range iv {
					if elem == nil {
						continue
					}
					if _, isMap := elem.(map[string]any); isMap {
						return fmt.Errorf("mapper_parsing_exception: [completion] input cannot contain objects")
					}
					s := fmt.Sprintf("%v", elem)
					if lowercase {
						s = strings.ToLower(s)
					}
					*out = append(*out, s)
				}
			default:
				return fmt.Errorf("mapper_parsing_exception: [completion] invalid input value")
			}
		default:
			s := fmt.Sprintf("%v", v)
			if lowercase {
				s = strings.ToLower(s)
			}
			*out = append(*out, s)
		}
		return nil
	}
	if node == nil {
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			if err := collectCompletionStringsAtPath(next, path[1:], lowercase, nullVal, out); err != nil {
				return err
			}
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				if err := collectCompletionStringsAtPath(next, path[i:], lowercase, nullVal, out); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, elem := range curr {
			if err := collectCompletionStringsAtPath(elem, path, lowercase, nullVal, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// IPToSortableFloat converts an IPv4 or IPv6 address string into an order-preserving float64.
func IPToSortableFloat(ipStr string) (float64, bool) {
	trimmed := strings.TrimSpace(ipStr)
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return 0, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		u := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		return float64(u), true
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false
	}
	var val float64
	for i := 0; i < 16; i++ {
		val = val*256.0 + float64(ip16[i])
	}
	return val, true
}

func traverseFieldInDocMap(curr map[string]any, path []string, leafFn func(m map[string]any, key string) (bool, error)) (bool, error) {
	if curr == nil {
		return false, nil
	}
	if len(path) == 0 {
		return false, nil
	}
	head := path[0] // #nosec G602 -- len(path) > 0 checked above
	if len(path) == 1 {
		return leafFn(curr, head)
	}
	rest := path[1:] // #nosec G602 -- len(path) >= 2 checked above
	if next, exists := curr[head]; exists {
		switch tv := next.(type) {
		case map[string]any:
			return traverseFieldInDocMap(tv, rest, leafFn)
		case []any:
			anyMod := false
			for _, elem := range tv {
				if em, ok := elem.(map[string]any); ok {
					mod, err := traverseFieldInDocMap(em, rest, leafFn)
					if err != nil {
						return false, err
					}
					if mod {
						anyMod = true
					}
				}
			}
			return anyMod, nil
		}
	}
	for i := len(path); i >= 2; i-- {
		if i > len(path) {
			continue
		}
		joined := strings.Join(path[:i], ".") // #nosec G602 -- 2 <= i <= len(path)
		if next, ok := curr[joined]; ok {
			if i == len(path) {
				return leafFn(curr, joined)
			}
			tail := path[i:] // #nosec G602 -- 2 <= i < len(path)
			switch tv := next.(type) {
			case map[string]any:
				return traverseFieldInDocMap(tv, tail, leafFn)
			case []any:
				anyMod := false
				for _, elem := range tv {
					if em, ok := elem.(map[string]any); ok {
						mod, err := traverseFieldInDocMap(em, tail, leafFn)
						if err != nil {
							return false, err
						}
						if mod {
							anyMod = true
						}
					}
				}
				return anyMod, nil
			}
		}
	}
	return false, nil
}

func validateAndNormalizeSparseVectorFieldInDoc(curr map[string]any, path []string, b FieldBinding) (bool, error) {
	return traverseFieldInDocMap(curr, path, func(m map[string]any, key string) (bool, error) {
		raw, exists := m[key]
		if !exists || raw == nil {
			return false, nil
		}
		tokMap, ok := raw.(map[string]any)
		if !ok {
			return false, fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [%s]: expected object mapping tokens to numeric weights", b.ESFieldPath, b.ESType)
		}
		modified := false
		for tk, tv := range tokMap {
			if strings.TrimSpace(tk) == "" {
				return false, fmt.Errorf("mapper_parsing_exception: [%s] token key in [%s] cannot be empty", b.ESType, b.ESFieldPath)
			}
			var fv float64
			var validNum bool
			switch val := tv.(type) {
			case float64:
				fv, validNum = val, !math.IsNaN(val) && !math.IsInf(val, 0)
			case json.Number:
				if f, err := val.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					fv, validNum = f, true
				}
			case int:
				fv, validNum = float64(val), true
			case int64:
				fv, validNum = float64(val), true
			case string:
				if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					fv, validNum = f, true
					tokMap[tk] = fv
					modified = true
				}
			}
			if !validNum {
				return false, fmt.Errorf("mapper_parsing_exception: [%s] token [%s.%s] weight must be a finite number", b.ESType, b.ESFieldPath, tk)
			}
			if b.ESType == "rank_features" && fv <= 0 {
				return false, fmt.Errorf("mapper_parsing_exception: [rank_features] feature [%s.%s] weight must be > 0, got [%v]", b.ESFieldPath, tk, fv)
			}
		}
		return modified, nil
	})
}

func validateAndNormalizeFlattenedFieldInDoc(curr map[string]any, path []string, b FieldBinding, recordIgnored func(string)) (bool, error) {
	return traverseFieldInDocMap(curr, path, func(m map[string]any, key string) (bool, error) {
		raw, exists := m[key]
		if !exists || raw == nil {
			if exists && raw == nil {
				delete(m, key)
				return true, nil
			}
			return false, nil
		}
		norm, modified, err := validateAndNormalizeFlattenedValue(raw, b, recordIgnored)
		if err != nil {
			return false, err
		}
		if norm == nil {
			delete(m, key)
			return true, nil
		}
		if modified {
			m[key] = norm
		}
		return modified, nil
	})
}

func validateAndNormalizeFlattenedValue(raw any, b FieldBinding, recordIgnored func(string)) (any, bool, error) {
	if raw == nil {
		return nil, true, nil
	}
	switch v := raw.(type) {
	case map[string]any:
		normMap, mod := normalizeFlattenedObjectMap(v, b, recordIgnored)
		if len(normMap) == 0 {
			return nil, true, nil
		}
		return normMap, mod, nil
	case []any:
		var merged map[string]any
		for _, elem := range v {
			if elem == nil {
				continue
			}
			em, ok := elem.(map[string]any)
			if !ok {
				return nil, false, fmt.Errorf("mapper_parsing_exception: object mapping for [%s] tried to parse field [%s] as object, but found a concrete value", b.ESFieldPath, b.ESFieldPath)
			}
			normMap, _ := normalizeFlattenedObjectMap(em, b, recordIgnored)
			if len(normMap) == 0 {
				continue
			}
			if merged == nil {
				merged = make(map[string]any)
			}
			mergeFlattenedObjectMaps(merged, normMap)
		}
		if len(merged) == 0 {
			return nil, true, nil
		}
		return merged, true, nil
	default:
		return nil, false, fmt.Errorf("mapper_parsing_exception: object mapping for [%s] tried to parse field [%s] as object, but found a concrete value", b.ESFieldPath, b.ESFieldPath)
	}
}

func normalizeFlattenedObjectMap(m map[string]any, b FieldBinding, recordIgnored func(string)) (map[string]any, bool) {
	out := make(map[string]any, len(m))
	modified := false
	for k, v := range m {
		normV, mod := normalizeFlattenedInnerValue(v, b, recordIgnored)
		if mod {
			modified = true
		}
		if normV == nil {
			modified = true
			continue
		}
		out[k] = normV
	}
	return out, modified
}

func normalizeFlattenedInnerValue(v any, b FieldBinding, recordIgnored func(string)) (any, bool) {
	if v == nil {
		if b.NullValue != nil {
			nv := fmt.Sprintf("%v", b.NullValue)
			if b.LowercaseNormalizer {
				nv = strings.ToLower(nv)
			}
			if b.IgnoreAbove > 0 && len([]rune(nv)) > b.IgnoreAbove {
				if recordIgnored != nil {
					recordIgnored(b.ESFieldPath)
				}
				return nil, true
			}
			return nv, true
		}
		return nil, true
	}
	switch tv := v.(type) {
	case map[string]any:
		normMap, mod := normalizeFlattenedObjectMap(tv, b, recordIgnored)
		if len(normMap) == 0 {
			return nil, true
		}
		return normMap, mod
	case []any:
		var scalarOut []any
		var mergedObj map[string]any
		modified := false
		for _, elem := range tv {
			normElem, mod := normalizeFlattenedInnerValue(elem, b, recordIgnored)
			if mod {
				modified = true
			}
			if normElem == nil {
				modified = true
				continue
			}
			if em, ok := normElem.(map[string]any); ok {
				if mergedObj == nil {
					mergedObj = make(map[string]any)
				}
				mergeFlattenedObjectMaps(mergedObj, em)
				modified = true
			} else {
				scalarOut = append(scalarOut, normElem)
			}
		}
		if len(mergedObj) > 0 && len(scalarOut) == 0 {
			return mergedObj, true
		}
		if len(scalarOut) == 0 {
			return nil, true
		}
		return scalarOut, modified
	case string:
		sv := tv
		mod := false
		if b.LowercaseNormalizer {
			if lower := strings.ToLower(sv); lower != sv {
				sv = lower
				mod = true
			}
		}
		if b.IgnoreAbove > 0 && len([]rune(sv)) > b.IgnoreAbove {
			if recordIgnored != nil {
				recordIgnored(b.ESFieldPath)
			}
			return nil, true
		}
		return sv, mod
	default:
		sv := fmt.Sprintf("%v", tv)
		if b.IgnoreAbove > 0 && len([]rune(sv)) > b.IgnoreAbove {
			if recordIgnored != nil {
				recordIgnored(b.ESFieldPath)
			}
			return nil, true
		}
		return tv, false
	}
}

func mergeFlattenedObjectMaps(dst, src map[string]any) {
	for k, sv := range src {
		dv, exists := dst[k]
		if !exists || dv == nil {
			dst[k] = sv
			continue
		}
		dm, dIsMap := dv.(map[string]any)
		sm, sIsMap := sv.(map[string]any)
		if dIsMap && sIsMap {
			mergeFlattenedObjectMaps(dm, sm)
			dst[k] = dm
			continue
		}
		var combined []any
		if dSlice, ok := dv.([]any); ok {
			combined = append(combined, dSlice...)
		} else {
			combined = append(combined, dv)
		}
		if sSlice, ok := sv.([]any); ok {
			combined = append(combined, sSlice...)
		} else {
			combined = append(combined, sv)
		}
		dst[k] = combined
	}
}

func validateAndNormalizeRangeFieldInDoc(curr map[string]any, path []string, b FieldBinding, getNow func() time.Time) (bool, error) {
	return traverseFieldInDocMap(curr, path, func(m map[string]any, key string) (bool, error) {
		raw, exists := m[key]
		if !exists || raw == nil {
			return false, nil
		}
		norm, modified, err := validateAndNormalizeRangeValue(raw, b, getNow)
		if err != nil {
			return false, err
		}
		if modified {
			m[key] = norm
		}
		return modified, nil
	})
}

func validateAndNormalizeRangeValue(raw any, b FieldBinding, getNow func() time.Time) (any, bool, error) {
	if raw == nil {
		return nil, false, nil
	}
	switch v := raw.(type) {
	case map[string]any:
		if err := validateAndPopulateSingleRangeMap(v, b, getNow); err != nil {
			return nil, false, err
		}
		return v, true, nil
	case []any:
		for i, elem := range v {
			if elem == nil {
				continue
			}
			em, ok := elem.(map[string]any)
			if !ok {
				if str, isStr := elem.(string); isStr && b.ESType == "ip_range" {
					cidrMap, err := parseCIDRRangeMap(str, b.ESFieldPath)
					if err != nil {
						return nil, false, err
					}
					v[i] = cidrMap
					continue
				}
				return nil, false, fmt.Errorf("mapper_parsing_exception: failed to parse range field [%s] of type [%s]: expected range object", b.ESFieldPath, b.ESType)
			}
			if err := validateAndPopulateSingleRangeMap(em, b, getNow); err != nil {
				return nil, false, err
			}
		}
		return v, true, nil
	case string:
		if b.ESType == "ip_range" {
			cidrMap, err := parseCIDRRangeMap(v, b.ESFieldPath)
			if err != nil {
				return nil, false, err
			}
			return cidrMap, true, nil
		}
		return nil, false, fmt.Errorf("mapper_parsing_exception: failed to parse range field [%s] of type [%s]: expected range object", b.ESFieldPath, b.ESType)
	default:
		return nil, false, fmt.Errorf("mapper_parsing_exception: failed to parse range field [%s] of type [%s]: expected range object", b.ESFieldPath, b.ESType)
	}
}

func parseCIDRRangeMap(cidrStr, fieldPath string) (map[string]any, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidrStr))
	if err != nil || ipNet == nil {
		return nil, fmt.Errorf("mapper_parsing_exception: failed to parse ip_range field [%s]: invalid CIDR [%s]", fieldPath, cidrStr)
	}
	startIP := make(net.IP, len(ipNet.IP))
	copy(startIP, ipNet.IP)
	endIP := make(net.IP, len(ipNet.IP))
	for i := range ipNet.IP {
		endIP[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	lo, ok1 := IPToSortableFloat(startIP.String())
	hi, ok2 := IPToSortableFloat(endIP.String())
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("mapper_parsing_exception: failed to parse ip_range field [%s]", fieldPath)
	}
	return map[string]any{
		"gte":  startIP.String(),
		"lte":  endIP.String(),
		"_gte": lo,
		"_lte": hi,
	}, nil
}

func parseRangeBoundValue(raw any, b FieldBinding, getNow func() time.Time, roundUp bool) (float64, int64, bool) {
	if raw == nil {
		return 0, 0, false
	}
	if _, isBool := raw.(bool); isBool {
		return 0, 0, false
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	switch esType {
	case "integer_range", "long_range":
		var iv int64
		var ok bool
		switch tv := raw.(type) {
		case json.Number:
			if parsed, err := tv.Int64(); err == nil {
				iv, ok = parsed, true
			}
		case float64:
			if !math.IsNaN(tv) && !math.IsInf(tv, 0) && math.Trunc(tv) == tv && tv >= -9223372036854775808.0 && tv < 9223372036854775808.0 {
				iv, ok = int64(tv), true
			}
		case string:
			if b.Coerce == nil || *b.Coerce {
				if parsed, err := strconv.ParseInt(strings.TrimSpace(tv), 10, 64); err == nil {
					iv, ok = parsed, true
				}
			}
		}
		if !ok || (esType == "integer_range" && (iv < math.MinInt32 || iv > math.MaxInt32)) {
			return 0, 0, false
		}
		return float64(iv), iv, true
	case "float_range", "double_range":
		var fv float64
		var ok bool
		switch tv := raw.(type) {
		case json.Number:
			if parsed, err := tv.Float64(); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
				fv, ok = parsed, true
			}
		case float64:
			if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
				fv, ok = tv, true
			}
		case string:
			if b.Coerce == nil || *b.Coerce {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(tv), 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
					fv, ok = parsed, true
				}
			}
		}
		if !ok || (esType == "float_range" && math.Abs(fv) > math.MaxFloat32) {
			return 0, 0, false
		}
		return fv, 0, true
	case "date_range":
		switch tv := raw.(type) {
		case string:
			if b.Format != "" {
				if ms, ok := ParseESDateBoundWithFormatToEpochMillis(tv, b.Format, getNow(), roundUp); ok {
					return float64(ms), ms, true
				}
				return 0, 0, false
			}
			if iv, err := strconv.ParseInt(strings.TrimSpace(tv), 10, 64); err == nil {
				return float64(iv), iv, true
			}
			if ms, ok := ParseESDateBoundToEpochMillis(tv, getNow(), roundUp); ok {
				return float64(ms), ms, true
			}
		case json.Number:
			if iv, err := tv.Int64(); err == nil {
				return float64(iv), iv, true
			}
			if fv, err := tv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return fv, int64(fv), true
			}
		case float64:
			if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
				return tv, int64(tv), true
			}
		}
		return 0, 0, false
	case "ip_range":
		str, ok := raw.(string)
		if !ok {
			return 0, 0, false
		}
		fv, okIP := IPToSortableFloat(str)
		return fv, int64(fv), okIP
	}
	return 0, 0, false
}

func validateAndPopulateSingleRangeMap(m map[string]any, b FieldBinding, getNow func() time.Time) error {
	hasGt, hasGte, hasLt, hasLte := false, false, false, false
	var rawLower, rawUpper any
	for k, v := range m {
		switch k {
		case "_gte", "_lte":
			continue
		case "gt":
			if v != nil {
				hasGt = true
				rawLower = v
			}
		case "gte":
			if v != nil {
				hasGte = true
				rawLower = v
			}
		case "lt":
			if v != nil {
				hasLt = true
				rawUpper = v
			}
		case "lte":
			if v != nil {
				hasLte = true
				rawUpper = v
			}
		default:
			return fmt.Errorf("mapper_parsing_exception: range field [%s] unknown bound key [%s]", b.ESFieldPath, k)
		}
	}
	if (hasGt && hasGte) || (hasLt && hasLte) || (!hasGt && !hasGte && !hasLt && !hasLte) {
		return fmt.Errorf("mapper_parsing_exception: invalid range bounds for field [%s]", b.ESFieldPath)
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	isIntRange := esType == "integer_range" || esType == "long_range" || esType == "date_range"
	hasLower := hasGt || hasGte
	hasUpper := hasLt || hasLte
	var lowerFloat, upperFloat float64
	var lowerInt, upperInt int64
	if hasLower {
		lf, li, ok := parseRangeBoundValue(rawLower, b, getNow, false)
		if !ok {
			return fmt.Errorf("mapper_parsing_exception: failed to parse lower bound of range field [%s] of type [%s]", b.ESFieldPath, b.ESType)
		}
		if hasGt {
			if isIntRange {
				if (esType == "integer_range" && li == math.MaxInt32) || li == math.MaxInt64 {
					return fmt.Errorf("mapper_parsing_exception: lower bound overflow in range field [%s]", b.ESFieldPath)
				}
				li++
				lf = float64(li)
			} else if esType == "ip_range" {
				lf += 1.0
			} else {
				lf = math.Nextafter(lf, math.Inf(1))
			}
		}
		lowerFloat, lowerInt = lf, li
	}
	if hasUpper {
		uf, ui, ok := parseRangeBoundValue(rawUpper, b, getNow, hasLte)
		if !ok {
			return fmt.Errorf("mapper_parsing_exception: failed to parse upper bound of range field [%s] of type [%s]", b.ESFieldPath, b.ESType)
		}
		if hasLt {
			if isIntRange {
				if (esType == "integer_range" && ui == math.MinInt32) || ui == math.MinInt64 {
					return fmt.Errorf("mapper_parsing_exception: upper bound underflow in range field [%s]", b.ESFieldPath)
				}
				ui--
				uf = float64(ui)
			} else if esType == "ip_range" {
				uf -= 1.0
			} else {
				uf = math.Nextafter(uf, math.Inf(-1))
			}
		}
		upperFloat, upperInt = uf, ui
	}
	if hasLower && hasUpper {
		if isIntRange {
			if lowerInt > upperInt {
				return fmt.Errorf("mapper_parsing_exception: lower bound cannot be greater than upper bound in range field [%s]", b.ESFieldPath)
			}
		} else {
			if lowerFloat > upperFloat {
				return fmt.Errorf("mapper_parsing_exception: lower bound cannot be greater than upper bound in range field [%s]", b.ESFieldPath)
			}
		}
	}
	if hasLower {
		if isIntRange {
			m["_gte"] = lowerInt
		} else {
			m["_gte"] = lowerFloat
		}
	} else {
		m["_gte"] = -1e100
	}
	if hasUpper {
		if isIntRange {
			m["_lte"] = upperInt
		} else {
			m["_lte"] = upperFloat
		}
	} else {
		m["_lte"] = 1e100
	}
	return nil
}
