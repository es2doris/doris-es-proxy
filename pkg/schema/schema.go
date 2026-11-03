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
	"hash/fnv"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

type StorageKind int

const (
	StoragePromotedScalar StorageKind = iota
	StoragePromotedArray
	StorageNestedSubfield
	StorageDynamicVariant
	StoragePromotedVector
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
	DorisFloatArray DorisScalarType = "ARRAY<FLOAT>"
)

// FieldBinding describes how an Elasticsearch field path (e.g. `name.keyword`,
// `tags.tagFQN`, `columns.dataType`) maps to physical Apache Doris column(s).
type FieldBinding struct {
	ESFieldPath         string
	SourceJSONPath      []string // JSON object keys from root `_source`
	Kind                StorageKind
	ColumnName          string
	DorisType           DorisScalarType
	ESType              string // Declared Elasticsearch field type (e.g. "date", "long", "keyword")
	Format              string // Optional ES date/number format
	Analyzer            string
	LowercaseNormalizer bool
	KeywordCompanion    string // Optional untokenized `.keyword` column for `text` fields
	KeywordNormalizer   bool   // Whether `KeywordCompanion` has a lowercase normalizer
	VectorDims          int
	VectorMetric        string

	// For `StorageNestedSubfield` (`nested` arrays of objects):
	NestedPath         string   // Root nested path, e.g. "columns"
	CorrelatedArrayCol string   // e.g. "n__columns" (`ARRAY<STRING>` holding per-element JSON)
	RelativeJSONPath   []string // Path inside each nested element, e.g. ["tags", "tagFQN"]
	PrefilterArrayCol  string   // e.g. "n__columns__tags__tagFQN" (`ARRAY<STRING>` with `USING INVERTED`)
	IsMultiValued      bool
	CopyTo             []string
	NullValue          any
	IgnoreAbove        int
	AliasTarget        string
	ScalingFactor      float64
	Coerce             *bool
	IgnoreMalformed    *bool
	NotIndexed         bool
	EnabledFalse       bool
	DocValuesFalse     bool
}

// EffectiveLowercase returns true if this field (or its `.keyword` companion when `preferKeyword` is true)
// uses a lowercase normalizer.
func (b FieldBinding) EffectiveLowercase(preferKeyword bool) bool {
	if b.LowercaseNormalizer {
		return true
	}
	if b.KeywordCompanion != "" && b.KeywordNormalizer && (preferKeyword || b.Kind == StoragePromotedArray || b.Kind == StorageNestedSubfield) {
		return true
	}
	return false
}

// EffectiveArrayColumn returns the physical array column name for StoragePromotedArray
// or StorageNestedSubfield, preferring KeywordCompanion when preferKeyword is true.
func (b FieldBinding) EffectiveArrayColumn(preferKeyword bool) string {
	if b.KeywordCompanion != "" && preferKeyword {
		return b.KeywordCompanion
	}
	if b.Kind == StorageNestedSubfield && b.PrefilterArrayCol != "" {
		return b.PrefilterArrayCol
	}
	return b.ColumnName
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
	nestedRootPaths map[string][]string
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
		IndexName:       indexName,
		DorisDB:         SanitizeDorisIdentifier(dorisDB),
		DorisTable:      SanitizeDorisIdentifier(indexName),
		Buckets:         8,
		Fields:          make(map[string]FieldBinding),
		NestedRoots:     make(map[string]string),
		nestedRootPaths: make(map[string][]string),
		RawMapping:      mapping,
	}
	if mapping != nil && len(mapping.Properties) > 0 {
		s.compileProperties(nil, nil, "", 0, mapping.Properties)
	}
	s.finalizeCompiledSlices()
	return s
}

func (s *IndexSchema) finalizeCompiledSlices() {
	// First resolve alias chains (e.g. a1 -> a2 -> target) so copy_to targeting an alias resolves to the underlying field.
	for pass := 0; pass < 4; pass++ {
		changed := false
		for k, b := range s.Fields {
			if b.AliasTarget != "" {
				if _, ok := s.Fields[b.AliasTarget]; !ok && b.NestedPath != "" {
					if _, rOK := s.Fields[b.NestedPath+"."+b.AliasTarget]; rOK {
						b.AliasTarget = b.NestedPath + "." + b.AliasTarget
						s.Fields[k] = b
						changed = true
					}
				}
				if tb, ok := s.Fields[b.AliasTarget]; ok && tb.AliasTarget != "" && tb.AliasTarget != b.AliasTarget {
					b.AliasTarget = tb.AliasTarget
					s.Fields[k] = b
					changed = true
				} else if strings.HasSuffix(b.AliasTarget, ".keyword") {
					baseTarget := strings.TrimSuffix(b.AliasTarget, ".keyword")
					if tb, ok := s.Fields[baseTarget]; ok && tb.AliasTarget != "" {
						newTarget := strings.TrimSuffix(tb.AliasTarget, ".keyword") + ".keyword"
						if newTarget != b.AliasTarget {
							b.AliasTarget = newTarget
							s.Fields[k] = b
							changed = true
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	copyToTargets := make(map[string]bool)
	for k, b := range s.Fields {
		updatedCopyTo := false
		for i, target := range b.CopyTo {
			if _, ok := s.Fields[target]; !ok && b.NestedPath != "" {
				if _, rOK := s.Fields[b.NestedPath+"."+target]; rOK {
					target = b.NestedPath + "." + target
					b.CopyTo[i] = target
					updatedCopyTo = true
				}
			}
			if tb, ok := s.Fields[target]; ok && tb.AliasTarget != "" {
				target = tb.AliasTarget
				b.CopyTo[i] = target
				updatedCopyTo = true
			}
			copyToTargets[target] = true
		}
		if updatedCopyTo {
			s.Fields[k] = b
		}
	}
	for target := range copyToTargets {
		if tb, ok := s.Fields[target]; ok {
			if tb.Kind == StoragePromotedScalar && tb.ESType != "text" && tb.ESType != "match_only_text" {
				tb.Kind = StoragePromotedArray
				tb.IsMultiValued = true
				s.Fields[target] = tb
			} else if tb.Kind == StorageNestedSubfield && tb.ESType != "text" && tb.ESType != "match_only_text" {
				tb.IsMultiValued = true
				s.Fields[target] = tb
			}
			if tb.KeywordCompanion != "" {
				if kwB, hasKw := s.Fields[target+".keyword"]; hasKw {
					switch kwB.Kind {
					case StoragePromotedScalar:
						kwB.Kind = StoragePromotedArray
						kwB.IsMultiValued = true
						s.Fields[target+".keyword"] = kwB
					case StorageNestedSubfield:
						kwB.IsMultiValued = true
						s.Fields[target+".keyword"] = kwB
					}
				}
			}
			targetPrefix := target + "."
			for subK, subB := range s.Fields {
				if strings.HasPrefix(subK, targetPrefix) && subB.AliasTarget == "" && strings.Join(subB.SourceJSONPath, ".") == target {
					if subB.ESType != "text" && subB.ESType != "match_only_text" {
						switch subB.Kind {
						case StoragePromotedScalar:
							subB.Kind = StoragePromotedArray
							subB.IsMultiValued = true
							s.Fields[subK] = subB
						case StorageNestedSubfield:
							subB.IsMultiValued = true
							s.Fields[subK] = subB
						}
					}
				}
			}
		}
	}

	for pass := 0; pass < 4; pass++ {
		changed := false
		for k, b := range s.Fields {
			if b.AliasTarget != "" && b.ColumnName == "" {
				if tb, ok := s.Fields[b.AliasTarget]; ok && tb.ColumnName != "" {
					aliased := tb
					aliased.ESFieldPath = k
					aliased.AliasTarget = b.AliasTarget
					aliased.CopyTo = nil
					s.Fields[k] = aliased
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	// Any remaining unresolved alias (pointing to a dynamic/unmapped field or disabled object) falls back to StorageDynamicVariant on AliasTarget.
	for k, b := range s.Fields {
		if b.AliasTarget != "" && b.ColumnName == "" {
			cleanTarget := strings.TrimSuffix(b.AliasTarget, ".keyword")
			if tb, ok := s.Fields[cleanTarget]; ok && (tb.ColumnName != "" || tb.EnabledFalse || tb.NotIndexed) {
				aliased := tb
				aliased.ESFieldPath = k
				aliased.AliasTarget = b.AliasTarget
				aliased.CopyTo = nil
				s.Fields[k] = aliased
				continue
			}
			resolved := s.ResolveField(cleanTarget)
			b.Kind = StorageDynamicVariant
			b.DorisType = DorisString
			b.ESType = "keyword"
			b.SourceJSONPath = strings.Split(cleanTarget, ".")
			b.NotIndexed = resolved.NotIndexed
			b.EnabledFalse = resolved.EnabledFalse
			b.DocValuesFalse = resolved.DocValuesFalse
			s.Fields[k] = b
		}
	}

	fieldKeys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	seenCols := make(map[string]bool, len(fieldKeys))
	s.OrderedFields = make([]FieldBinding, 0, len(fieldKeys))
	for _, k := range fieldKeys {
		b := s.Fields[k]
		if b.AliasTarget != "" || b.ColumnName == "" || seenCols[b.ColumnName] {
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
		parts := s.nestedRootPaths[np]
		if len(parts) == 0 {
			parts = strings.Split(np, ".")
		}
		s.NestedRootSpecs = append(s.NestedRootSpecs, NestedRootSpec{
			Path:       np,
			ColumnName: s.NestedRoots[np],
			PathParts:  parts,
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
			Routing:    newSpec.Routing,
			Properties: DeepMergeMappingProperties(nil, newSpec.Properties),
		}
	}
	if newSpec == nil {
		return &esast.MappingSpec{
			Dynamic:    oldSpec.Dynamic,
			Routing:    oldSpec.Routing,
			Properties: DeepMergeMappingProperties(nil, oldSpec.Properties),
		}
	}
	dyn := oldSpec.Dynamic
	if newSpec.Dynamic != nil {
		dyn = newSpec.Dynamic
	}
	rt := oldSpec.Routing
	if newSpec.Routing != nil {
		rt = newSpec.Routing
	}
	return &esast.MappingSpec{
		Dynamic:    dyn,
		Routing:    rt,
		Properties: DeepMergeMappingProperties(oldSpec.Properties, newSpec.Properties),
	}
}

// ValidateMappingUpdateCompatibility checks whether `newSpec` attempts to change the type of any existing field in `oldSpec`.
func ValidateMappingUpdateCompatibility(oldSpec, newSpec *esast.MappingSpec) error {
	if oldSpec == nil || newSpec == nil {
		return nil
	}
	return validatePropertiesCompatibility(oldSpec.Properties, newSpec.Properties, "")
}

func validatePropertiesCompatibility(oldProps, newProps map[string]esast.FieldProperty, prefix string) error {
	for k, newProp := range newProps {
		fullPath := k
		if prefix != "" {
			fullPath = prefix + "." + k
		}
		oldProp, exists := oldProps[k]
		if !exists {
			continue
		}
		oldType := strings.ToLower(strings.TrimSpace(oldProp.Type))
		if oldType == "" && (len(oldProp.Properties) > 0 || oldProp.Enabled != nil) {
			oldType = "object"
		}
		newType := strings.ToLower(strings.TrimSpace(newProp.Type))
		if newType == "" && (len(newProp.Properties) > 0 || newProp.Enabled != nil) {
			newType = "object"
		}
		if oldType != "" && newType != "" && oldType != newType {
			return fmt.Errorf("mapper [%s] cannot be changed from type [%s] to [%s]", fullPath, oldType, newType)
		}
		if oldProp.Enabled != nil && newProp.Enabled != nil && *oldProp.Enabled != *newProp.Enabled {
			return fmt.Errorf("mapper [%s] enabled cannot be changed from [%v] to [%v]", fullPath, *oldProp.Enabled, *newProp.Enabled)
		}
		if oldProp.Path != "" && newProp.Path != "" && oldProp.Path != newProp.Path {
			return fmt.Errorf("cannot change path of alias [%s] from [%s] to [%s]", fullPath, oldProp.Path, newProp.Path)
		}
		oldDims := oldProp.Dims
		if oldDims == 0 {
			oldDims = oldProp.Dimension
		}
		newDims := newProp.Dims
		if newDims == 0 {
			newDims = newProp.Dimension
		}
		if oldDims > 0 && newDims > 0 && oldDims != newDims {
			return fmt.Errorf("cannot update parameter [dims] from [%d] to [%d] for field [%s]", oldDims, newDims, fullPath)
		}
		if oldProp.ScalingFactor > 0 && newProp.ScalingFactor > 0 && oldProp.ScalingFactor != newProp.ScalingFactor {
			return fmt.Errorf("cannot update parameter [scaling_factor] from [%v] to [%v] for field [%s]", oldProp.ScalingFactor, newProp.ScalingFactor, fullPath)
		}
		if len(oldProp.Fields) > 0 && len(newProp.Fields) > 0 {
			if err := validatePropertiesCompatibility(oldProp.Fields, newProp.Fields, fullPath); err != nil {
				return err
			}
		}
		if len(oldProp.Properties) > 0 && len(newProp.Properties) > 0 {
			if err := validatePropertiesCompatibility(oldProp.Properties, newProp.Properties, fullPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// IsDynamicFalseUnmappedField reports whether `esFieldPath` is an unmapped field under a `dynamic: false` mapping scope.
func (s *IndexSchema) IsDynamicFalseUnmappedField(esFieldPath string) bool {
	if s == nil || s.RawMapping == nil {
		return false
	}
	cleanPath := strings.TrimSuffix(strings.TrimSuffix(esFieldPath, ".keyword"), ".ngram")
	if cleanPath == "" || strings.HasPrefix(cleanPath, "_") {
		return false
	}
	if _, ok := s.Fields[esFieldPath]; ok {
		return false
	}
	if _, ok := s.Fields[cleanPath]; ok {
		return false
	}
	mode := normalizeDynamicMode(s.RawMapping.Dynamic)
	props := s.RawMapping.Properties
	for _, seg := range strings.Split(cleanPath, ".") {
		prop, ok := props[seg]
		if !ok {
			return mode == "false"
		}
		if strings.EqualFold(prop.Type, "flattened") {
			return false
		}
		if prop.Dynamic != nil {
			mode = normalizeDynamicMode(prop.Dynamic)
		}
		props = prop.Properties
	}
	return false
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
			if v.Path != "" {
				merged.Path = v.Path
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
			if v.Dims > 0 {
				merged.Dims = v.Dims
			}
			if v.Dimension > 0 {
				merged.Dimension = v.Dimension
			}
			if v.Similarity != "" {
				merged.Similarity = v.Similarity
			}
			if v.MultiValued {
				merged.MultiValued = true
			}
			if v.UpgradedArray {
				merged.UpgradedArray = true
			}
			if v.CopyTo != nil {
				merged.CopyTo = v.CopyTo
			}
			if v.NullValue != nil {
				merged.NullValue = v.NullValue
			}
			if v.IgnoreAbove > 0 {
				merged.IgnoreAbove = v.IgnoreAbove
			}
			if v.ScalingFactor > 0 {
				merged.ScalingFactor = v.ScalingFactor
			}
			if v.Coerce != nil {
				merged.Coerce = v.Coerce
			}
			if v.IgnoreMalformed != nil {
				merged.IgnoreMalformed = v.IgnoreMalformed
			}
			if v.Enabled != nil {
				merged.Enabled = v.Enabled
			}
			if v.Index != nil {
				merged.Index = v.Index
			}
			if v.DocValues != nil {
				merged.DocValues = v.DocValues
			}
			if v.Dynamic != nil {
				merged.Dynamic = v.Dynamic
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

		if prop.Enabled != nil && !*prop.Enabled {
			s.Fields[dotPath] = FieldBinding{
				ESFieldPath:    dotPath,
				SourceJSONPath: currJSONPath,
				ESType:         "object",
				NotIndexed:     true,
				EnabledFalse:   true,
				DocValuesFalse: true,
			}
			continue
		}

		if strings.EqualFold(prop.Type, "nested") {
			corrCol := "n__" + SanitizeDorisIdentifier(dotPath)
			s.NestedRoots[dotPath] = corrCol
			if s.nestedRootPaths == nil {
				s.nestedRootPaths = make(map[string][]string)
			}
			s.nestedRootPaths[dotPath] = currJSONPath
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
				if prop.MultiValued || DefaultMultiValuedPaths[dotPath] {
					subProp.MultiValued = true
					if prop.UpgradedArray {
						subProp.UpgradedArray = true
					}
				}
				multiDotPath := dotPath + "." + subKey
				// Multi-fields read from the same `currJSONPath` in `_source`!
				s.registerLeafField(multiDotPath, currJSONPath, activeNestedRoot, nestedRootDepth, subProp)
				if subKey == "keyword" {
					subBinding := s.Fields[multiDotPath]
					if baseBinding, ok := s.Fields[dotPath]; ok && (baseBinding.Kind == subBinding.Kind || (baseBinding.Kind == StoragePromotedScalar && subBinding.Kind == StoragePromotedArray)) && (baseBinding.Kind == StoragePromotedScalar || baseBinding.Kind == StoragePromotedArray || baseBinding.Kind == StorageNestedSubfield) {
						companionCol := subBinding.ColumnName
						if baseBinding.Kind == StorageNestedSubfield && subBinding.PrefilterArrayCol != "" {
							companionCol = subBinding.PrefilterArrayCol
						}
						if companionCol != "" {
							baseBinding.KeywordCompanion = companionCol
							baseBinding.KeywordNormalizer = subBinding.LowercaseNormalizer
							s.Fields[dotPath] = baseBinding
						}
					}
				}
			}
		}
	}
}

func parseCopyToTargets(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		var out []string
		for _, item := range v {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

func (s *IndexSchema) registerLeafField(
	dotPath string,
	sourceJSONPath []string,
	activeNestedRoot string,
	nestedRootDepth int,
	prop esast.FieldProperty,
) {
	dorisType := mapESTypeToDoris(prop.Type)
	esType := strings.ToLower(strings.TrimSpace(prop.Type))
	if esType == "alias" {
		if prop.Path != "" {
			s.Fields[dotPath] = FieldBinding{
				ESFieldPath: dotPath,
				ESType:      "alias",
				AliasTarget: prop.Path,
				NestedPath:  activeNestedRoot,
			}
		}
		return
	}
	lowerNorm := prop.Normalizer != "" && !strings.EqualFold(prop.Normalizer, "none")
	copyTo := parseCopyToTargets(prop.CopyTo)
	notIndexed := (prop.Index != nil && !*prop.Index) || (prop.Enabled != nil && !*prop.Enabled)
	docValuesFalse := (prop.DocValues != nil && !*prop.DocValues) || (prop.Enabled != nil && !*prop.Enabled)

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
			DorisType:           dorisType,
			ESType:              esType,
			Format:              prop.Format,
			Analyzer:            prop.Analyzer,
			LowercaseNormalizer: lowerNorm,
			NestedPath:          activeNestedRoot,
			CorrelatedArrayCol:  corrCol,
			RelativeJSONPath:    relJSONPath,
			PrefilterArrayCol:   prefilterCol,
			IsMultiValued:       prop.MultiValued || len(relJSONPath) > 1 || DefaultMultiValuedPaths[dotPath],
			CopyTo:              copyTo,
			NullValue:           prop.NullValue,
			IgnoreAbove:         prop.IgnoreAbove,
			ScalingFactor:       prop.ScalingFactor,
			Coerce:              prop.Coerce,
			IgnoreMalformed:     prop.IgnoreMalformed,
			NotIndexed:          notIndexed,
			DocValuesFalse:      docValuesFalse,
		}
		return
	}

	colName := "f__" + SanitizeDorisIdentifier(dotPath)
	if strings.EqualFold(prop.Type, "dense_vector") || strings.EqualFold(prop.Type, "knn_vector") {
		metric := prop.Similarity
		if metric == "" {
			metric = "cosine"
		}
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:    dotPath,
			SourceJSONPath: sourceJSONPath,
			Kind:           StoragePromotedVector,
			ColumnName:     colName,
			DorisType:      DorisFloatArray,
			ESType:         esType,
			VectorDims:     prop.EffectiveDims(),
			VectorMetric:   metric,
			NotIndexed:     notIndexed,
			DocValuesFalse: docValuesFalse,
		}
		return
	}
	if prop.MultiValued || DefaultMultiValuedPaths[dotPath] {
		arrColName := colName
		if prop.UpgradedArray {
			arrColName = "f__arr__" + SanitizeDorisIdentifier(dotPath)
		}
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:         dotPath,
			SourceJSONPath:      sourceJSONPath,
			Kind:                StoragePromotedArray,
			ColumnName:          arrColName,
			DorisType:           DorisString,
			ESType:              esType,
			Format:              prop.Format,
			LowercaseNormalizer: lowerNorm,
			IsMultiValued:       true,
			CopyTo:              copyTo,
			NullValue:           prop.NullValue,
			IgnoreAbove:         prop.IgnoreAbove,
			ScalingFactor:       prop.ScalingFactor,
			Coerce:              prop.Coerce,
			IgnoreMalformed:     prop.IgnoreMalformed,
			NotIndexed:          notIndexed,
			DocValuesFalse:      docValuesFalse,
		}
		return
	}

	s.Fields[dotPath] = FieldBinding{
		ESFieldPath:         dotPath,
		SourceJSONPath:      sourceJSONPath,
		Kind:                StoragePromotedScalar,
		ColumnName:          colName,
		DorisType:           dorisType,
		ESType:              esType,
		Format:              prop.Format,
		Analyzer:            prop.Analyzer,
		LowercaseNormalizer: lowerNorm,
		CopyTo:              copyTo,
		NullValue:           prop.NullValue,
		IgnoreAbove:         prop.IgnoreAbove,
		ScalingFactor:       prop.ScalingFactor,
		Coerce:              prop.Coerce,
		IgnoreMalformed:     prop.IgnoreMalformed,
		NotIndexed:          notIndexed,
		DocValuesFalse:      docValuesFalse,
	}
}

// ResolveField returns the physical Doris storage binding for an ES field path,
// falling back to `_doc` (`VARIANT`) for dynamic/unmapped fields.
// If `esFieldPath` ends with `.keyword` and has no explicit `.keyword` sub-field,
// it checks the base field first and strips `.keyword` from the dynamic JSON path.
func (s *IndexSchema) ResolveField(esFieldPath string) FieldBinding {
	if s == nil || s.Fields == nil {
		cleanPath := strings.TrimSuffix(esFieldPath, ".keyword")
		var segs []string
		if cleanPath != "" {
			segs = strings.Split(cleanPath, ".")
		}
		return FieldBinding{
			ESFieldPath:    esFieldPath,
			SourceJSONPath: segs,
			Kind:           StorageDynamicVariant,
			DorisType:      DorisString,
		}
	}
	if b, ok := s.Fields[esFieldPath]; ok {
		return b
	}
	for prefix := esFieldPath; ; {
		idx := strings.LastIndexByte(prefix, '.')
		if idx <= 0 {
			break
		}
		prefix = prefix[:idx]
		if pb, ok := s.Fields[prefix]; ok && pb.EnabledFalse {
			return FieldBinding{
				ESFieldPath:    esFieldPath,
				SourceJSONPath: strings.Split(strings.TrimSuffix(esFieldPath, ".keyword"), "."),
				Kind:           StorageDynamicVariant,
				DorisType:      DorisString,
				NotIndexed:     true,
				EnabledFalse:   true,
				DocValuesFalse: true,
			}
		}
	}
	if strings.HasSuffix(esFieldPath, ".keyword") {
		basePath := strings.TrimSuffix(esFieldPath, ".keyword")
		if b, ok := s.Fields[basePath]; ok {
			if b.AliasTarget != "" {
				if kwB, hasKw := s.Fields[b.AliasTarget+".keyword"]; hasKw {
					kwB.ESFieldPath = esFieldPath
					kwB.AliasTarget = b.AliasTarget
					return kwB
				}
			}
			b.ESFieldPath = esFieldPath
			if b.ESType == "text" {
				b.ESType = "keyword"
			}
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

// ResolveEffectiveField returns the FieldBinding for esFieldPath, promoting to the
// `.keyword` companion binding when preferKeyword is true and a `.keyword` companion exists.
func (s *IndexSchema) ResolveEffectiveField(esFieldPath string, preferKeyword bool) FieldBinding {
	b := s.ResolveField(esFieldPath)
	if preferKeyword && b.KeywordCompanion != "" && !strings.HasSuffix(esFieldPath, ".keyword") {
		lookupBase := esFieldPath
		if b.AliasTarget != "" {
			lookupBase = b.AliasTarget
		}
		if kwB, ok := s.Fields[lookupBase+".keyword"]; ok {
			kwB.ESFieldPath = esFieldPath
			if b.AliasTarget != "" {
				kwB.AliasTarget = b.AliasTarget
			}
			return kwB
		}
	}
	return b
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
		if parsed, err := strconv.ParseFloat(patternWithBoost[idx+1:], 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
			boost = parsed
		}
	}
	if s == nil || !strings.ContainsAny(pattern, "*?") {
		return []BoostedField{{Field: pattern, Boost: boost}}
	}
	reStr := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"), `\?`, ".") + "$"
	re, err := regexp.Compile(reStr)
	if err != nil {
		return nil
	}
	var matched []BoostedField
	matchedSet := make(map[string]bool)
	for k, b := range s.Fields {
		if b.Kind == StoragePromotedVector || b.NotIndexed || b.EnabledFalse {
			continue
		}
		if b.ESType == "alias" && b.ColumnName == "" && b.Kind != StorageDynamicVariant {
			continue
		}
		if re.MatchString(k) {
			matchedSet[k] = true
		}
	}
	for k := range matchedSet {
		b := s.Fields[k]
		if b.AliasTarget != "" && matchedSet[b.AliasTarget] {
			continue
		}
		matched = append(matched, BoostedField{Field: k, Boost: boost})
	}
	if len(matched) == 0 && (pattern == "*" || pattern == "*.keyword") {
		return []BoostedField{{Field: "_all_text", Boost: boost}}
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
			sb.WriteByte('_')
			sb.WriteString(strconv.FormatInt(int64(r), 16))
			sb.WriteByte('_')
		}
	}
	res := sb.String()
	if res == "" {
		return "_unnamed"
	}
	if len(res) > 56 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(res))
		res = res[:47] + "_" + strconv.FormatUint(uint64(h.Sum32()), 16)
	}
	return res
}

const (
	maxInferredSampleDocs = 16
	maxInferredProperties = 64
	maxInferredDepth      = 4
)

// InferMappingFromSampleDocs inspects up to 16 sample JSON documents on first write to an
// auto-created schemaless index (`dynamic: true`) and infers Elasticsearch field mappings
// (`keyword`, `text` + `.keyword`, `long`, `double`, `boolean`, `date`, and nested object properties).
func InferMappingFromSampleDocs(docs []json.RawMessage) *esast.MappingSpec {
	if len(docs) == 0 {
		return nil
	}
	props := make(map[string]esast.FieldProperty)
	totalFields := 0
	limit := len(docs)
	if limit > maxInferredSampleDocs {
		limit = maxInferredSampleDocs
	}
	for i := 0; i < limit; i++ {
		raw := bytes.TrimSpace(docs[i])
		if len(raw) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			continue
		}
		inferObjectProperties(obj, props, 0, &totalFields)
	}
	if len(props) == 0 {
		return nil
	}
	return &esast.MappingSpec{
		Properties: props,
	}
}

func inferObjectProperties(obj map[string]any, dst map[string]esast.FieldProperty, depth int, totalFields *int) {
	if depth >= maxInferredDepth || *totalFields >= maxInferredProperties {
		return
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if *totalFields >= maxInferredProperties {
			return
		}
		if k == "" || strings.HasPrefix(k, "_") {
			continue
		}
		val := obj[k]
		if val == nil {
			continue
		}
		if existing, exists := dst[k]; exists && len(existing.Properties) > 0 {
			if subMap, isMap := val.(map[string]any); isMap {
				if depth+1 < maxInferredDepth {
					inferObjectProperties(subMap, existing.Properties, depth+1, totalFields)
					if existing.MultiValued {
						markPropertyMultiValued(&existing)
					}
					dst[k] = existing
				}
				continue
			}
			if subSlice, isSlice := val.([]any); isSlice {
				if depth+1 < maxInferredDepth {
					hadAny := false
					for _, elem := range subSlice {
						if elemMap, ok := elem.(map[string]any); ok {
							inferObjectProperties(elemMap, existing.Properties, depth+1, totalFields)
							hadAny = true
						}
					}
					if hadAny {
						markPropertyMultiValued(&existing)
						dst[k] = existing
						continue
					}
				}
			}
		}
		inferred, ok := inferValueProperty(val, depth, totalFields)
		if !ok {
			continue
		}
		if existing, exists := dst[k]; exists {
			dst[k] = mergeFieldProperty(existing, inferred)
		} else {
			*totalFields++
			dst[k] = inferred
		}
	}
}

func inferValueProperty(val any, depth int, totalFields *int) (esast.FieldProperty, bool) {
	switch v := val.(type) {
	case bool:
		return esast.FieldProperty{Type: "boolean"}, true
	case json.Number:
		s := v.String()
		if strings.ContainsAny(s, ".eE") {
			return esast.FieldProperty{Type: "double"}, true
		}
		return esast.FieldProperty{Type: "long"}, true
	case float64:
		return esast.FieldProperty{Type: "double"}, true
	case string:
		if looksLikeISODateString(v) {
			if _, ok := ParseESDateToEpochMillis(v, time.Time{}); ok {
				return esast.FieldProperty{Type: "date"}, true
			}
		}
		if strings.ContainsAny(v, " \t\n") || len(v) > 128 {
			return esast.FieldProperty{
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"keyword": {Type: "keyword"},
				},
			}, true
		}
		return esast.FieldProperty{Type: "keyword"}, true
	case map[string]any:
		if depth+1 >= maxInferredDepth {
			return esast.FieldProperty{}, false
		}
		childProps := make(map[string]esast.FieldProperty)
		inferObjectProperties(v, childProps, depth+1, totalFields)
		if len(childProps) == 0 {
			return esast.FieldProperty{}, false
		}
		return esast.FieldProperty{Properties: childProps}, true
	case []any:
		var merged esast.FieldProperty
		hasElem := false
		allNumeric := len(v) >= 2
		hasFloat := false
		for _, elem := range v {
			if elem == nil {
				allNumeric = false
				continue
			}
			switch n := elem.(type) {
			case float64:
				hasFloat = true
			case json.Number:
				if strings.ContainsAny(n.String(), ".eE") {
					hasFloat = true
				}
			default:
				allNumeric = false
			}
			if elemMap, isMap := elem.(map[string]any); isMap {
				if depth+1 >= maxInferredDepth {
					continue
				}
				if merged.Properties == nil {
					merged.Properties = make(map[string]esast.FieldProperty)
				}
				inferObjectProperties(elemMap, merged.Properties, depth+1, totalFields)
				if len(merged.Properties) > 0 {
					hasElem = true
				}
				continue
			}
			elemProp, ok := inferValueProperty(elem, depth, totalFields)
			if !ok {
				continue
			}
			if !hasElem {
				merged = elemProp
				hasElem = true
			} else {
				merged = mergeFieldProperty(merged, elemProp)
			}
		}
		if !hasElem {
			return esast.FieldProperty{}, false
		}
		if allNumeric && hasFloat {
			return esast.FieldProperty{
				Type:       "dense_vector",
				Dims:       len(v),
				Similarity: "cosine",
			}, true
		}
		markPropertyMultiValued(&merged)
		return merged, true
	default:
		return esast.FieldProperty{}, false
	}
}

func markPropertyMultiValued(fp *esast.FieldProperty) {
	if len(fp.Properties) > 0 {
		fp.MultiValued = true
		for k, sub := range fp.Properties {
			markPropertyMultiValued(&sub)
			fp.Properties[k] = sub
		}
		return
	}
	if fp.Type != "" && fp.Type != "dense_vector" && fp.Type != "knn_vector" {
		fp.MultiValued = true
		fp.Fields = nil
	}
}

func mergeFieldProperty(existing, incoming esast.FieldProperty) esast.FieldProperty {
	mv := existing.MultiValued || incoming.MultiValued
	if len(existing.Properties) > 0 || len(incoming.Properties) > 0 {
		if existing.Properties == nil {
			existing.Properties = make(map[string]esast.FieldProperty)
		}
		for k, v := range incoming.Properties {
			if prev, ok := existing.Properties[k]; ok {
				existing.Properties[k] = mergeFieldProperty(prev, v)
			} else {
				existing.Properties[k] = v
			}
		}
		existing.MultiValued = mv
		if mv {
			markPropertyMultiValued(&existing)
		}
		return existing
	}
	if existing.Type == incoming.Type {
		if (existing.Type == "dense_vector" || existing.Type == "knn_vector") &&
			(existing.EffectiveDims() != incoming.EffectiveDims() || mv) {
			return esast.FieldProperty{Type: "double", MultiValued: true}
		}
		existing.MultiValued = mv
		if mv {
			existing.Fields = nil
		}
		return existing
	}
	if existing.Type == "" {
		incoming.MultiValued = mv
		return incoming
	}
	if incoming.Type == "" {
		existing.MultiValued = mv
		return existing
	}
	// Widening rules: long + double -> double; dense_vector + numeric -> multi-valued double; keyword + text -> text (with .keyword); incompatible scalars -> keyword/text
	isNumericOrVec := func(t string) bool {
		return t == "long" || t == "double" || t == "dense_vector" || t == "knn_vector"
	}
	if isNumericOrVec(existing.Type) && isNumericOrVec(incoming.Type) {
		if existing.Type == "dense_vector" || existing.Type == "knn_vector" || incoming.Type == "dense_vector" || incoming.Type == "knn_vector" {
			return esast.FieldProperty{Type: "double", MultiValued: true}
		}
		return esast.FieldProperty{Type: "double", MultiValued: mv}
	}
	isStringType := func(t string) bool {
		return t == "keyword" || t == "text"
	}
	if isStringType(existing.Type) || isStringType(incoming.Type) {
		hasText := existing.Type == "text" || incoming.Type == "text"
		if mv || !hasText {
			return esast.FieldProperty{Type: "keyword", MultiValued: mv}
		}
		return esast.FieldProperty{
			Type: "text",
			Fields: map[string]esast.FieldProperty{
				"keyword": {Type: "keyword"},
			},
		}
	}
	return esast.FieldProperty{Type: "keyword", MultiValued: mv}
}

func looksLikeISODateString(s string) bool {
	if len(s) < 10 || len(s) > 40 {
		return false
	}
	return s[4] == '-' && s[7] == '-' && (len(s) == 10 || s[10] == 'T' || s[10] == ' ')
}
