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
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

type StorageKind int

const (
	StoragePromotedScalar StorageKind = iota
	StoragePromotedArray
	StorageNestedSubfield
	StorageDynamicVariant
)

type DorisScalarType string

const (
	DorisVarchar    DorisScalarType = "VARCHAR(1024)"
	DorisString     DorisScalarType = "STRING"
	DorisBigInt     DorisScalarType = "BIGINT"
	DorisInt        DorisScalarType = "INT"
	DorisDouble     DorisScalarType = "DOUBLE"
	DorisBoolean    DorisScalarType = "BOOLEAN"
	DorisDateTimeV2 DorisScalarType = "DATETIMEV2(3)"
)

// FieldBinding describes how an Elasticsearch field path (e.g. `name.keyword`,
// `tags.tagFQN`, `columns.dataType`) maps to physical Apache Doris column(s).
type FieldBinding struct {
	ESFieldPath         string
	SourceJSONPath      []string // JSON object keys from root `_source`
	Kind                StorageKind
	ColumnName          string
	DorisType           DorisScalarType
	Analyzer            string
	LowercaseNormalizer bool
	KeywordCompanion    string // Optional untokenized `.keyword` column for `text` fields

	// For `StorageNestedSubfield` (`nested` arrays of objects):
	NestedPath         string   // Root nested path, e.g. "columns"
	CorrelatedArrayCol string   // e.g. "n__columns" (`ARRAY<STRING>` holding per-element JSON)
	RelativeJSONPath   []string // Path inside each nested element, e.g. ["tags", "tagFQN"]
	PrefilterArrayCol  string   // e.g. "n__columns__tags__tagFQN" (`ARRAY<STRING>` with `USING INVERTED`)
	IsMultiValued      bool
}

// NestedRootSpec holds pre-split path metadata for a correlated nested array root.
type NestedRootSpec struct {
	Path       string
	ColumnName string
	PathParts  []string
}

// IndexSchema holds the compiled schema registry for an Elasticsearch index.
type IndexSchema struct {
	IndexName       string
	DorisDB         string
	DorisTable      string
	Buckets         int
	Fields          map[string]FieldBinding
	OrderedFields   []FieldBinding
	NestedRoots     map[string]string // Maps ES nested path (e.g. "columns") -> Doris column ("n__columns")
	NestedRootSpecs []NestedRootSpec
	RawMapping      *esast.MappingSpec
}

// DefaultMultiValuedPaths lists common OpenMetadata & DataHub paths that hold arrays of objects/strings
// even when declared as `"type": "keyword"` or `"type": "object"` (not `"nested"`) in ES mappings.
var DefaultMultiValuedPaths = map[string]bool{
	"tags.tagFQN":                true,
	"tags.name":                  true,
	"owners":                     true,
	"owners.id":                  true,
	"owners.name":                true,
	"owners.displayName":         true,
	"owners.displayName.keyword": true,
	"followers":                  true,
	"domains.id":                 true,
	"domains.name":               true,
	"glossaryTerms":              true,
	"customProperties":           true,
	"upstreams":                  true,
	"downstreams":                true,
	"browsePaths":                true,
	"browsePathsV2":              true,
}

// CompileIndexSchema translates an Elasticsearch `_mapping` specification into a Doris `IndexSchema`.
func CompileIndexSchema(dorisDB, indexName string, mapping *esast.MappingSpec) *IndexSchema {
	s := &IndexSchema{
		IndexName:   indexName,
		DorisDB:     SanitizeDorisIdentifier(dorisDB),
		DorisTable:  SanitizeDorisIdentifier(indexName),
		Buckets:     8,
		Fields:      make(map[string]FieldBinding),
		NestedRoots: make(map[string]string),
		RawMapping:  mapping,
	}
	if mapping != nil && len(mapping.Properties) > 0 {
		s.compileProperties(nil, nil, "", 0, mapping.Properties)
	}
	s.finalizeCompiledSlices()
	return s
}

func (s *IndexSchema) finalizeCompiledSlices() {
	fieldKeys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	seenCols := make(map[string]bool, len(fieldKeys))
	s.OrderedFields = make([]FieldBinding, 0, len(fieldKeys))
	for _, k := range fieldKeys {
		b := s.Fields[k]
		if b.ColumnName == "" || seenCols[b.ColumnName] {
			continue
		}
		seenCols[b.ColumnName] = true
		s.OrderedFields = append(s.OrderedFields, b)
	}

	nestedKeys := make([]string, 0, len(s.NestedRoots))
	for np := range s.NestedRoots {
		nestedKeys = append(nestedKeys, np)
	}
	sort.Strings(nestedKeys)
	s.NestedRootSpecs = make([]NestedRootSpec, 0, len(nestedKeys))
	for _, np := range nestedKeys {
		s.NestedRootSpecs = append(s.NestedRootSpecs, NestedRootSpec{
			Path:       np,
			ColumnName: s.NestedRoots[np],
			PathParts:  strings.Split(np, "."),
		})
	}
}

// MergeMappingSpecs deep-merges two Elasticsearch MappingSpecs without losing existing properties or sub-fields.
func MergeMappingSpecs(oldSpec, newSpec *esast.MappingSpec) *esast.MappingSpec {
	if oldSpec == nil && newSpec == nil {
		return &esast.MappingSpec{Properties: make(map[string]esast.FieldProperty)}
	}
	if oldSpec == nil {
		return &esast.MappingSpec{
			Dynamic:    newSpec.Dynamic,
			Properties: DeepMergeMappingProperties(nil, newSpec.Properties),
		}
	}
	if newSpec == nil {
		return &esast.MappingSpec{
			Dynamic:    oldSpec.Dynamic,
			Properties: DeepMergeMappingProperties(nil, oldSpec.Properties),
		}
	}
	dyn := oldSpec.Dynamic
	if newSpec.Dynamic != nil {
		dyn = newSpec.Dynamic
	}
	return &esast.MappingSpec{
		Dynamic:    dyn,
		Properties: DeepMergeMappingProperties(oldSpec.Properties, newSpec.Properties),
	}
}

// DeepMergeMappingProperties recursively merges `src` into a copy of `dst`.
func DeepMergeMappingProperties(
	dst, src map[string]esast.FieldProperty,
) map[string]esast.FieldProperty {
	out := make(map[string]esast.FieldProperty, len(dst)+len(src))
	for k, v := range dst {
		copied := v
		if len(v.Properties) > 0 {
			copied.Properties = DeepMergeMappingProperties(nil, v.Properties)
		}
		if len(v.Fields) > 0 {
			copied.Fields = DeepMergeMappingProperties(nil, v.Fields)
		}
		out[k] = copied
	}
	for k, v := range src {
		if existing, ok := out[k]; ok {
			merged := existing
			if v.Type != "" {
				merged.Type = v.Type
			}
			if v.Analyzer != "" {
				merged.Analyzer = v.Analyzer
			}
			if v.SearchAnalyzer != "" {
				merged.SearchAnalyzer = v.SearchAnalyzer
			}
			if v.Normalizer != "" {
				merged.Normalizer = v.Normalizer
			}
			if v.Format != "" {
				merged.Format = v.Format
			}
			if len(v.Properties) > 0 {
				merged.Properties = DeepMergeMappingProperties(existing.Properties, v.Properties)
			}
			if len(v.Fields) > 0 {
				merged.Fields = DeepMergeMappingProperties(existing.Fields, v.Fields)
			}
			out[k] = merged
		} else {
			copied := v
			if len(v.Properties) > 0 {
				copied.Properties = DeepMergeMappingProperties(nil, v.Properties)
			}
			if len(v.Fields) > 0 {
				copied.Fields = DeepMergeMappingProperties(nil, v.Fields)
			}
			out[k] = copied
		}
	}
	return out
}

func (s *IndexSchema) compileProperties(
	esPathPrefix []string,
	jsonPathPrefix []string,
	activeNestedRoot string,
	nestedRootDepth int,
	props map[string]esast.FieldProperty,
) {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, propName := range keys {
		prop := props[propName]
		currESPath := append(append([]string{}, esPathPrefix...), propName)
		currJSONPath := append(append([]string{}, jsonPathPrefix...), propName)
		dotPath := strings.Join(currESPath, ".")

		if strings.EqualFold(prop.Type, "nested") {
			corrCol := "n__" + SanitizeDorisIdentifier(dotPath)
			s.NestedRoots[dotPath] = corrCol
			if len(prop.Properties) > 0 {
				s.compileProperties(currESPath, currJSONPath, dotPath, len(currJSONPath), prop.Properties)
			}
			continue
		}

		// Recurse into sub-object properties if present
		if len(prop.Properties) > 0 {
			s.compileProperties(currESPath, currJSONPath, activeNestedRoot, nestedRootDepth, prop.Properties)
		}

		// If leaf type is declared, register the field binding
		if prop.Type != "" && !strings.EqualFold(prop.Type, "object") {
			s.registerLeafField(dotPath, currJSONPath, activeNestedRoot, nestedRootDepth, prop)
		}

		// Register multi-fields (e.g. `name.keyword`, `name.ngram`)
		if len(prop.Fields) > 0 {
			subKeys := make([]string, 0, len(prop.Fields))
			for sk := range prop.Fields {
				subKeys = append(subKeys, sk)
			}
			sort.Strings(subKeys)
			for _, subKey := range subKeys {
				subProp := prop.Fields[subKey]
				multiDotPath := dotPath + "." + subKey
				// Multi-fields read from the same `currJSONPath` in `_source`!
				s.registerLeafField(multiDotPath, currJSONPath, activeNestedRoot, nestedRootDepth, subProp)
				if subKey == "keyword" {
					if baseBinding, ok := s.Fields[dotPath]; ok && baseBinding.Kind == StoragePromotedScalar {
						baseBinding.KeywordCompanion = s.Fields[multiDotPath].ColumnName
						s.Fields[dotPath] = baseBinding
					}
				}
			}
		}
	}
}

func (s *IndexSchema) registerLeafField(
	dotPath string,
	sourceJSONPath []string,
	activeNestedRoot string,
	nestedRootDepth int,
	prop esast.FieldProperty,
) {
	dorisType := mapESTypeToDoris(prop.Type)
	lowerNorm := strings.Contains(strings.ToLower(prop.Normalizer), "lower")

	if activeNestedRoot != "" {
		corrCol := s.NestedRoots[activeNestedRoot]
		relPrefixLen := nestedRootDepth
		if relPrefixLen > len(sourceJSONPath) {
			relPrefixLen = len(sourceJSONPath)
		}
		relJSONPath := sourceJSONPath[relPrefixLen:]
		prefilterCol := "n__" + SanitizeDorisIdentifier(dotPath)
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:         dotPath,
			SourceJSONPath:      sourceJSONPath,
			Kind:                StorageNestedSubfield,
			ColumnName:          prefilterCol,
			DorisType:           DorisString,
			Analyzer:            prop.Analyzer,
			LowercaseNormalizer: lowerNorm,
			NestedPath:          activeNestedRoot,
			CorrelatedArrayCol:  corrCol,
			RelativeJSONPath:    relJSONPath,
			PrefilterArrayCol:   prefilterCol,
			IsMultiValued:       len(relJSONPath) > 1 || DefaultMultiValuedPaths[dotPath],
		}
		return
	}

	colName := "f__" + SanitizeDorisIdentifier(dotPath)
	if DefaultMultiValuedPaths[dotPath] {
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:         dotPath,
			SourceJSONPath:      sourceJSONPath,
			Kind:                StoragePromotedArray,
			ColumnName:          colName,
			DorisType:           DorisString,
			LowercaseNormalizer: lowerNorm,
			IsMultiValued:       true,
		}
		return
	}

	s.Fields[dotPath] = FieldBinding{
		ESFieldPath:         dotPath,
		SourceJSONPath:      sourceJSONPath,
		Kind:                StoragePromotedScalar,
		ColumnName:          colName,
		DorisType:           dorisType,
		Analyzer:            prop.Analyzer,
		LowercaseNormalizer: lowerNorm,
	}
}

// ResolveField returns the physical Doris storage binding for an ES field path,
// falling back to `_doc` (`VARIANT`) for dynamic/unmapped fields.
// If `esFieldPath` ends with `.keyword` and has no explicit `.keyword` sub-field,
// it checks the base field first and strips `.keyword` from the dynamic JSON path.
func (s *IndexSchema) ResolveField(esFieldPath string) FieldBinding {
	if b, ok := s.Fields[esFieldPath]; ok {
		return b
	}
	if strings.HasSuffix(esFieldPath, ".keyword") {
		basePath := strings.TrimSuffix(esFieldPath, ".keyword")
		if b, ok := s.Fields[basePath]; ok {
			return b
		}
		return FieldBinding{
			ESFieldPath:    esFieldPath,
			SourceJSONPath: strings.Split(basePath, "."),
			Kind:           StorageDynamicVariant,
			DorisType:      DorisString,
		}
	}
	return FieldBinding{
		ESFieldPath:    esFieldPath,
		SourceJSONPath: strings.Split(esFieldPath, "."),
		Kind:           StorageDynamicVariant,
		DorisType:      DorisString,
	}
}

type BoostedField struct {
	Field string
	Boost float64
}

// ExpandFieldPattern expands wildcard field patterns with optional boosts (e.g. `"*name*^5"`).
func (s *IndexSchema) ExpandFieldPattern(patternWithBoost string) []BoostedField {
	pattern := patternWithBoost
	boost := 1.0
	if idx := strings.IndexByte(patternWithBoost, '^'); idx >= 0 {
		pattern = patternWithBoost[:idx]
		if parsed, err := strconv.ParseFloat(patternWithBoost[idx+1:], 64); err == nil {
			boost = parsed
		}
	}
	if !strings.Contains(pattern, "*") {
		return []BoostedField{{Field: pattern, Boost: boost}}
	}
	reStr := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	re, err := regexp.Compile(reStr)
	if err != nil {
		return nil
	}
	var matched []BoostedField
	for k := range s.Fields {
		if re.MatchString(k) {
			matched = append(matched, BoostedField{Field: k, Boost: boost})
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Field < matched[j].Field
	})
	return matched
}

func mapESTypeToDoris(esType string) DorisScalarType {
	switch strings.ToLower(esType) {
	case "keyword", "constant_keyword", "wildcard", "ip":
		return DorisVarchar
	case "text", "match_only_text":
		return DorisString
	case "long", "unsigned_long":
		return DorisBigInt
	case "integer", "short", "byte":
		return DorisInt
	case "double", "float", "half_float", "scaled_float":
		return DorisDouble
	case "boolean":
		return DorisBoolean
	case "date", "date_nanos":
		return DorisBigInt
	default:
		return DorisString
	}
}

func SanitizeDorisIdentifier(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		} else if r == '.' || r == '-' {
			sb.WriteString("__")
		} else {
			_, _ = fmt.Fprintf(&sb, "_%x_", r)
		}
	}
	res := sb.String()
	if len(res) > 56 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(res))
		res = fmt.Sprintf("%s_%08x", res[:47], h.Sum32())
	}
	return res
}
