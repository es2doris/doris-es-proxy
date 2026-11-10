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
	DorisVariant    DorisScalarType = "VARIANT"
)

// IsRangeFieldType returns true if esType is one of the 6 Elasticsearch range field types.
func IsRangeFieldType(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range":
		return true
	default:
		return false
	}
}

// IsTextLikeESType returns true if esType is tokenized full-text or completion/search_as_you_type/annotated-text
// where multi-valued string arrays are joined with spaces in a single STRING column rather than promoted to ARRAY<STRING>.
func IsTextLikeESType(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "text", "match_only_text", "search_as_you_type", "completion", "annotated-text", "annotated_text":
		return true
	default:
		return false
	}
}

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
	NestedPath               string   // Root nested path, e.g. "columns"
	CorrelatedArrayCol       string   // e.g. "n__columns" (`ARRAY<STRING>` holding per-element JSON)
	RelativeJSONPath         []string // Path inside each nested element, e.g. ["tags", "tagFQN"]
	PrefilterArrayCol        string   // e.g. "n__columns__tags__tagFQN" (`ARRAY<STRING>` with `USING INVERTED`)
	IsMultiValued            bool
	CopyTo                   []string
	NullValue                any
	ConstantValue            any
	IgnoreAbove              int
	AliasTarget              string
	ScalingFactor            float64
	Coerce                   *bool
	IgnoreMalformed          *bool
	EnablePositionIncrements *bool
	Relations                map[string]any
	NotIndexed               bool
	EnabledFalse             bool
	DocValuesFalse           bool
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
	IndexName          string
	DorisDB            string
	DorisTable         string
	Buckets            int
	Fields             map[string]FieldBinding
	OrderedFields      []FieldBinding
	NestedRoots        map[string]string // Maps ES nested path (e.g. "columns") -> Doris column ("n__columns")
	nestedRootPaths    map[string][]string
	NestedRootSpecs    []NestedRootSpec
	RawMapping         *esast.MappingSpec
	MaxNestedObjects   int
	MaxDepth           int
	MaxFieldNameLength int
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
	// First resolve alias chains (e.g. a1 -> a2 -> target) with cycle detection so copy_to targeting an alias resolves to the underlying field.
	for k, b := range s.Fields {
		if b.AliasTarget == "" {
			continue
		}
		visited := map[string]bool{k: true}
		curr := b.AliasTarget
		cyclic := false
		for hop := 0; hop < 16 && curr != ""; hop++ {
			if _, ok := s.Fields[curr]; !ok && b.NestedPath != "" {
				if _, rOK := s.Fields[b.NestedPath+"."+curr]; rOK {
					curr = b.NestedPath + "." + curr
				}
			}
			if visited[curr] {
				cyclic = true
				break
			}
			visited[curr] = true
			if tb, ok := s.Fields[curr]; ok && tb.AliasTarget != "" && tb.AliasTarget != curr {
				curr = tb.AliasTarget
				continue
			}
			if strings.HasSuffix(curr, ".keyword") {
				baseTarget := strings.TrimSuffix(curr, ".keyword")
				if tb, ok := s.Fields[baseTarget]; ok && tb.AliasTarget != "" {
					nextTarget := strings.TrimSuffix(tb.AliasTarget, ".keyword") + ".keyword"
					if nextTarget != curr {
						curr = nextTarget
						continue
					}
				}
			}
			break
		}
		if cyclic {
			b.AliasTarget = ""
			b.Kind = StorageDynamicVariant
			b.DorisType = DorisString
			b.ESType = "keyword"
			b.SourceJSONPath = strings.Split(strings.TrimSuffix(k, ".keyword"), ".")
			s.Fields[k] = b
		} else if curr != b.AliasTarget {
			b.AliasTarget = curr
			s.Fields[k] = b
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
			if tb.Kind == StoragePromotedScalar && !IsTextLikeESType(tb.ESType) {
				tb.Kind = StoragePromotedArray
				tb.DorisType = DorisString
				tb.IsMultiValued = true
				s.Fields[target] = tb
			} else if tb.Kind == StorageNestedSubfield && !IsTextLikeESType(tb.ESType) {
				tb.IsMultiValued = true
				s.Fields[target] = tb
			}
			if tb.KeywordCompanion != "" {
				if kwB, hasKw := s.Fields[target+".keyword"]; hasKw {
					switch kwB.Kind {
					case StoragePromotedScalar:
						kwB.Kind = StoragePromotedArray
						kwB.DorisType = DorisString
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
					if !IsTextLikeESType(subB.ESType) {
						switch subB.Kind {
						case StoragePromotedScalar:
							subB.Kind = StoragePromotedArray
							subB.DorisType = DorisString
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
			if b.AliasTarget != "" && b.ColumnName == "" && (b.ESType == "" || b.ESType == "alias") {
				if tb, ok := s.Fields[b.AliasTarget]; ok && (tb.ColumnName != "" || (tb.ESType != "" && tb.ESType != "alias")) {
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
		if b.AliasTarget != "" && b.ColumnName == "" && (b.ESType == "" || b.ESType == "alias") {
			cleanTarget := strings.TrimSuffix(b.AliasTarget, ".keyword")
			if tb, ok := s.Fields[cleanTarget]; ok && (tb.ColumnName != "" || tb.EnabledFalse || tb.NotIndexed || (tb.ESType != "" && tb.ESType != "alias")) {
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
			Dynamic:            newSpec.Dynamic,
			Subobjects:         newSpec.Subobjects,
			Routing:            newSpec.Routing,
			Meta:               newSpec.Meta,
			Source:             newSpec.Source,
			DynamicTemplates:   newSpec.DynamicTemplates,
			DateDetection:      newSpec.DateDetection,
			NumericDetection:   newSpec.NumericDetection,
			DynamicDateFormats: newSpec.DynamicDateFormats,
			Runtime:            DeepMergeMappingProperties(nil, newSpec.Runtime),
			Properties:         DeepMergeMappingProperties(nil, newSpec.Properties),
		}
	}
	if newSpec == nil {
		return &esast.MappingSpec{
			Dynamic:            oldSpec.Dynamic,
			Subobjects:         oldSpec.Subobjects,
			Routing:            oldSpec.Routing,
			Meta:               oldSpec.Meta,
			Source:             oldSpec.Source,
			DynamicTemplates:   oldSpec.DynamicTemplates,
			DateDetection:      oldSpec.DateDetection,
			NumericDetection:   oldSpec.NumericDetection,
			DynamicDateFormats: oldSpec.DynamicDateFormats,
			Runtime:            DeepMergeMappingProperties(nil, oldSpec.Runtime),
			Properties:         DeepMergeMappingProperties(nil, oldSpec.Properties),
		}
	}
	dyn := oldSpec.Dynamic
	if newSpec.Dynamic != nil {
		dyn = newSpec.Dynamic
	}
	subobj := oldSpec.Subobjects
	if newSpec.Subobjects != nil {
		subobj = newSpec.Subobjects
	}
	rt := oldSpec.Routing
	if newSpec.Routing != nil {
		rt = newSpec.Routing
	}
	meta := oldSpec.Meta
	if newSpec.Meta != nil {
		meta = newSpec.Meta
	}
	source := oldSpec.Source
	if newSpec.Source != nil {
		source = newSpec.Source
	}
	dynTemplates := oldSpec.DynamicTemplates
	if newSpec.DynamicTemplates != nil {
		dynTemplates = newSpec.DynamicTemplates
	}
	dateDet := oldSpec.DateDetection
	if newSpec.DateDetection != nil {
		dateDet = newSpec.DateDetection
	}
	numDet := oldSpec.NumericDetection
	if newSpec.NumericDetection != nil {
		numDet = newSpec.NumericDetection
	}
	dynDateFormats := oldSpec.DynamicDateFormats
	if newSpec.DynamicDateFormats != nil {
		dynDateFormats = newSpec.DynamicDateFormats
	}
	return &esast.MappingSpec{
		Dynamic:            dyn,
		Subobjects:         subobj,
		Routing:            rt,
		Meta:               meta,
		Source:             source,
		DynamicTemplates:   dynTemplates,
		DateDetection:      dateDet,
		NumericDetection:   numDet,
		DynamicDateFormats: dynDateFormats,
		Runtime:            DeepMergeMappingProperties(oldSpec.Runtime, newSpec.Runtime),
		Properties:         DeepMergeMappingProperties(oldSpec.Properties, newSpec.Properties),
	}
}

var knownESFieldTypes = map[string]bool{
	"keyword":                 true,
	"constant_keyword":        true,
	"wildcard":                true,
	"text":                    true,
	"match_only_text":         true,
	"annotated-text":          true,
	"annotated_text":          true,
	"search_as_you_type":      true,
	"completion":              true,
	"token_count":             true,
	"murmur3":                 true,
	"long":                    true,
	"integer":                 true,
	"short":                   true,
	"byte":                    true,
	"double":                  true,
	"float":                   true,
	"half_float":              true,
	"scaled_float":            true,
	"unsigned_long":           true,
	"boolean":                 true,
	"date":                    true,
	"date_nanos":              true,
	"ip":                      true,
	"version":                 true,
	"binary":                  true,
	"object":                  true,
	"nested":                  true,
	"flattened":               true,
	"join":                    true,
	"percolator":              true,
	"geo_point":               true,
	"geo_shape":               true,
	"point":                   true,
	"shape":                   true,
	"dense_vector":            true,
	"knn_vector":              true,
	"sparse_vector":           true,
	"rank_feature":            true,
	"rank_features":           true,
	"rank_vector":             true,
	"histogram":               true,
	"aggregate_metric_double": true,
	"alias":                   true,
	"integer_range":           true,
	"float_range":             true,
	"long_range":              true,
	"double_range":            true,
	"date_range":              true,
	"ip_range":                true,
	"passthrough":             true,
}

func validateDynamicModeVal(dyn any, path string) error {
	if dyn == nil {
		return nil
	}
	switch v := dyn.(type) {
	case bool:
		return nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "false", "strict", "runtime":
			return nil
		default:
			return fmt.Errorf("mapper_parsing_exception: wrong value for [dynamic] setting on [%s]: [%s]", path, v)
		}
	default:
		return fmt.Errorf("mapper_parsing_exception: wrong value for [dynamic] setting on [%s]: [%v]", path, dyn)
	}
}

func parseIntOption(raw any, optName, fieldPath string) (int, error) {
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) {
			return 0, fmt.Errorf("mapper_parsing_exception: [%s] on field [%s] must be an integer", optName, fieldPath)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("mapper_parsing_exception: [%s] on field [%s] must be an integer", optName, fieldPath)
	}
}

func validateSingleFieldProperty(fullPath, fType string, prop esast.FieldProperty) error {
	if fType != "" && !knownESFieldTypes[fType] {
		return fmt.Errorf("mapper_parsing_exception: No handler for type [%s] declared on field [%s]", prop.Type, fullPath)
	}
	if err := validateDynamicModeVal(prop.Dynamic, fullPath); err != nil {
		return err
	}
	if fType == "scaled_float" {
		if prop.ScalingFactor <= 0.0 || math.IsNaN(prop.ScalingFactor) || math.IsInf(prop.ScalingFactor, 0) {
			return fmt.Errorf("mapper_parsing_exception: [scaling_factor] must be > 0.0 for [scaled_float] field [%s]", fullPath)
		}
	}
	if fType == "constant_keyword" && prop.Value != nil {
		switch prop.Value.(type) {
		case map[string]any, []any:
			return fmt.Errorf("mapper_parsing_exception: [constant_keyword] field [%s] [value] must be a scalar value", fullPath)
		}
	}
	if fType == "dense_vector" || fType == "knn_vector" {
		dims := prop.EffectiveDims()
		if prop.Dims < 0 || prop.Dimension < 0 || dims < 1 || dims > 4096 {
			return fmt.Errorf("mapper_parsing_exception: [%s] field [%s] requires [dims] in [1, 4096], got [%d]", fType, fullPath, dims)
		}
		switch strings.ToLower(strings.TrimSpace(prop.Similarity)) {
		case "", "l2_norm", "dot_product", "cosine", "max_inner_product":
		default:
			return fmt.Errorf("mapper_parsing_exception: unknown [similarity] [%s] on [%s] field [%s]", prop.Similarity, fType, fullPath)
		}
	}
	if prop.NullValue != nil {
		switch fType {
		case "text", "match_only_text", "annotated-text", "annotated_text", "search_as_you_type",
			"nested", "object", "flattened", "percolator", "join", "dense_vector", "knn_vector", "sparse_vector", "rank_feature", "rank_features":
			return fmt.Errorf("mapper_parsing_exception:Mapping definition for [%s] has unsupported parameters: [null_value] is not supported on [%s]", fullPath, fType)
		}
		switch prop.NullValue.(type) {
		case map[string]any, []any:
			return fmt.Errorf("mapper_parsing_exception: [null_value] on field [%s] must be a scalar value", fullPath)
		}
	}
	if prop.IgnoreAbove < 0 {
		return fmt.Errorf("mapper_parsing_exception: [ignore_above] must be >= 0 for field [%s]", fullPath)
	}
	if len(prop.IndexPrefixes) > 0 {
		minChars := 2
		maxChars := 5
		for k, v := range prop.IndexPrefixes {
			switch k {
			case "min_chars":
				iv, err := parseIntOption(v, "min_chars", fullPath)
				if err != nil {
					return err
				}
				minChars = iv
			case "max_chars":
				iv, err := parseIntOption(v, "max_chars", fullPath)
				if err != nil {
					return err
				}
				maxChars = iv
			default:
				return fmt.Errorf("mapper_parsing_exception: unknown parameter [%s] in [index_prefixes] on field [%s]", k, fullPath)
			}
		}
		if minChars < 1 {
			return fmt.Errorf("mapper_parsing_exception: [min_chars] in [index_prefixes] on field [%s] must be >= 1", fullPath)
		}
		if maxChars >= 20 {
			return fmt.Errorf("mapper_parsing_exception: [max_chars] in [index_prefixes] on field [%s] must be < 20", fullPath)
		}
		if minChars > maxChars {
			return fmt.Errorf("mapper_parsing_exception: [min_chars] (%d) must be <= [max_chars] (%d) in [index_prefixes] on field [%s]", minChars, maxChars, fullPath)
		}
	}
	if fType == "join" {
		if len(prop.Relations) == 0 {
			return fmt.Errorf("mapper_parsing_exception: [relations] is required for [join] field [%s]", fullPath)
		}
		childParent := make(map[string]string)
		for parent, rawChildren := range prop.Relations {
			pTrim := strings.TrimSpace(parent)
			if pTrim == "" {
				return fmt.Errorf("mapper_parsing_exception: [join] field [%s] parent relation name cannot be empty", fullPath)
			}
			var children []string
			switch cv := rawChildren.(type) {
			case string:
				children = []string{cv}
			case []string:
				children = cv
			case []any:
				for _, elem := range cv {
					s, ok := elem.(string)
					if !ok {
						return fmt.Errorf("mapper_parsing_exception: [join] field [%s] child relation must be a string", fullPath)
					}
					children = append(children, s)
				}
			default:
				return fmt.Errorf("mapper_parsing_exception: [join] field [%s] relation for [%s] must be a string or array of strings", fullPath, pTrim)
			}
			if len(children) == 0 {
				return fmt.Errorf("mapper_parsing_exception: [join] field [%s] parent [%s] must have at least one child", fullPath, pTrim)
			}
			for _, child := range children {
				cTrim := strings.TrimSpace(child)
				if cTrim == "" {
					return fmt.Errorf("mapper_parsing_exception: [join] field [%s] child relation name cannot be empty", fullPath)
				}
				if cTrim == pTrim {
					return fmt.Errorf("mapper_parsing_exception: [join] field [%s] child [%s] cannot be its own parent", fullPath, cTrim)
				}
				if prevParent, exists := childParent[cTrim]; exists && prevParent != pTrim {
					return fmt.Errorf("mapper_parsing_exception: [join] field [%s] child [%s] cannot have multiple parents ([%s] and [%s])", fullPath, cTrim, prevParent, pTrim)
				}
				childParent[cTrim] = pTrim
			}
		}
	}
	if prop.CopyTo != nil {
		switch fType {
		case "object", "nested", "alias", "join":
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [copy_to] is not supported on [%s]", fullPath, fType)
		}
		var targets []string
		switch cv := prop.CopyTo.(type) {
		case string:
			t := strings.TrimSpace(cv)
			if t == "" {
				return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] cannot be empty", fullPath)
			}
			targets = []string{t}
		case []string:
			if len(cv) == 0 {
				return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] cannot be empty", fullPath)
			}
			for _, elem := range cv {
				t := strings.TrimSpace(elem)
				if t == "" {
					return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] cannot contain empty strings", fullPath)
				}
				targets = append(targets, t)
			}
		case []any:
			if len(cv) == 0 {
				return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] cannot be empty", fullPath)
			}
			for _, elem := range cv {
				s, ok := elem.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] must be a string or array of non-empty strings", fullPath)
				}
				targets = append(targets, strings.TrimSpace(s))
			}
		default:
			return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] must be a string or array of strings", fullPath)
		}
		shortName := fullPath
		if dot := strings.LastIndex(fullPath, "."); dot >= 0 {
			shortName = fullPath[dot+1:]
		}
		for _, target := range targets {
			if target == fullPath || target == shortName {
				return fmt.Errorf("mapper_parsing_exception: Cannot copy field [%s] to itself", fullPath)
			}
		}
	}
	return nil
}

var validRuntimeFieldTypes = map[string]bool{
	"boolean":   true,
	"composite": true,
	"date":      true,
	"double":    true,
	"geo_point": true,
	"ip":        true,
	"keyword":   true,
	"long":      true,
	"lookup":    true,
}

var validDynamicMatchMappingTypes = map[string]bool{
	"*":       true,
	"boolean": true,
	"date":    true,
	"double":  true,
	"long":    true,
	"object":  true,
	"string":  true,
	"binary":  true,
}

func validateDynamicTemplatesSpec(templates []map[string]any) error {
	for i, tmplEntry := range templates {
		if len(tmplEntry) != 1 {
			return fmt.Errorf("mapper_parsing_exception: dynamic_templates[%d] must have exactly 1 named template entry, got %d", i, len(tmplEntry))
		}
		for tmplName, rawDef := range tmplEntry {
			if strings.TrimSpace(tmplName) == "" {
				return fmt.Errorf("mapper_parsing_exception: dynamic template name cannot be empty")
			}
			defMap, ok := rawDef.(map[string]any)
			if !ok || len(defMap) == 0 {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] definition must be an object", tmplName)
			}
			for k := range defMap {
				switch k {
				case "mapping", "match", "unmatch", "match_pattern", "path_match", "path_unmatch", "match_mapping_type":
				default:
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has unknown parameter [%s]", tmplName, k)
				}
			}
			if rawMMT, hasMMT := defMap["match_mapping_type"]; hasMMT && rawMMT != nil {
				validateMMT := func(s string) error {
					norm := strings.ToLower(strings.TrimSpace(s))
					if !validDynamicMatchMappingTypes[norm] {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid [match_mapping_type] [%s]", tmplName, s)
					}
					return nil
				}
				switch v := rawMMT.(type) {
				case string:
					if err := validateMMT(v); err != nil {
						return err
					}
				case []string:
					if len(v) == 0 {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [match_mapping_type] cannot be empty", tmplName)
					}
					for _, item := range v {
						if err := validateMMT(item); err != nil {
							return err
						}
					}
				case []any:
					if len(v) == 0 {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [match_mapping_type] cannot be empty", tmplName)
					}
					for _, item := range v {
						s, ok := item.(string)
						if !ok {
							return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [match_mapping_type] elements must be strings", tmplName)
						}
						if err := validateMMT(s); err != nil {
							return err
						}
					}
				default:
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [match_mapping_type] must be a string or array of strings", tmplName)
				}
			}
			isRegex := false
			if rawMP, hasMP := defMap["match_pattern"]; hasMP && rawMP != nil {
				mpStr, ok := rawMP.(string)
				if !ok {
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [match_pattern] must be a string", tmplName)
				}
				switch strings.ToLower(strings.TrimSpace(mpStr)) {
				case "simple":
				case "regex":
					isRegex = true
				default:
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid [match_pattern] [%s]", tmplName, mpStr)
				}
			}
			if isRegex {
				for _, patKey := range []string{"match", "unmatch"} {
					if rawPat, hasPat := defMap[patKey]; hasPat && rawPat != nil {
						patStr, ok := rawPat.(string)
						if !ok {
							return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [%s] must be a string", tmplName, patKey)
						}
						if _, err := regexp.Compile(patStr); err != nil {
							return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid regex in [%s]: %w", tmplName, patKey, err)
						}
					}
				}
			}
			rawMapping, hasMapping := defMap["mapping"]
			mappingMap, ok := rawMapping.(map[string]any)
			if !hasMapping || !ok {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] requires a [mapping] object", tmplName)
			}
			if rawType, hasType := mappingMap["type"]; hasType && rawType != nil {
				typeStr, ok := rawType.(string)
				if !ok || strings.TrimSpace(typeStr) == "" {
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [mapping.type] must be a non-empty string", tmplName)
				}
				if strings.TrimSpace(typeStr) != "{dynamic_type}" {
					b, err := json.Marshal(mappingMap)
					if err != nil {
						return err
					}
					var fp esast.FieldProperty
					if err := json.Unmarshal(b, &fp); err != nil {
						return err
					}
					// Replace `{name}` / `{dynamic_type}` placeholders in copy_to before single-field validation
					substituteDynamicTemplatePlaceholders(&fp, tmplName, "keyword")
					if err := validateSingleFieldProperty(tmplName, strings.ToLower(strings.TrimSpace(fp.Type)), fp); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// ValidateMappingSpec validates field definitions in a MappingSpec, including `alias` field `path` requirements,
// target existence, alias-to-alias chaining rejection, and cycle detection.
func ValidateMappingSpec(m *esast.MappingSpec) error {
	if m == nil {
		return nil
	}
	if err := validateDynamicModeVal(m.Dynamic, "_root"); err != nil {
		return err
	}
	for rtName, rtProp := range m.Runtime {
		if strings.TrimSpace(rtName) == "" {
			return fmt.Errorf("mapper_parsing_exception: runtime field name cannot be empty")
		}
		rtType := strings.ToLower(strings.TrimSpace(rtProp.Type))
		if !validRuntimeFieldTypes[rtType] {
			return fmt.Errorf("mapper_parsing_exception: No handler for runtime type [%s] declared on field [%s]", rtProp.Type, rtName)
		}
		if rtProp.Script != nil {
			switch sv := rtProp.Script.(type) {
			case string:
				if strings.TrimSpace(sv) == "" {
					return fmt.Errorf("mapper_parsing_exception: runtime field [%s] script cannot be empty", rtName)
				}
			case map[string]any:
				src, hasSrc := sv["source"]
				id, hasID := sv["id"]
				if (!hasSrc && !hasID) || (hasSrc && strings.TrimSpace(fmt.Sprintf("%v", src)) == "") || (hasID && strings.TrimSpace(fmt.Sprintf("%v", id)) == "") {
					return fmt.Errorf("mapper_parsing_exception: runtime field [%s] script requires non-empty [source] or [id]", rtName)
				}
			default:
				return fmt.Errorf("mapper_parsing_exception: runtime field [%s] invalid [script]", rtName)
			}
		}
	}
	if err := validateDynamicTemplatesSpec(m.DynamicTemplates); err != nil {
		return err
	}
	if len(m.Properties) == 0 {
		return nil
	}
	allTypes := make(map[string]string)
	aliasTargets := make(map[string]string)
	aliasPrefixes := make(map[string]string)
	type copyToRef struct {
		source string
		prefix string
		target string
	}
	var copyToRefs []copyToRef

	var collect func(props map[string]esast.FieldProperty, prefix string) error
	collect = func(props map[string]esast.FieldProperty, prefix string) error {
		for k, prop := range props {
			fullPath := k
			if prefix != "" {
				fullPath = prefix + "." + k
			}
			fType := strings.ToLower(strings.TrimSpace(prop.Type))
			if fType == "" && len(prop.Properties) > 0 {
				fType = "object"
			}
			allTypes[fullPath] = fType
			if err := validateSingleFieldProperty(fullPath, fType, prop); err != nil {
				return err
			}
			for _, ct := range prop.CopyToSlice() {
				copyToRefs = append(copyToRefs, copyToRef{source: fullPath, prefix: prefix, target: strings.TrimSpace(ct)})
			}
			if fType == "alias" {
				target := strings.TrimSpace(prop.Path)
				if target == "" {
					return fmt.Errorf("mapper_parsing_exception: [path] is required for [alias] field [%s]", fullPath)
				}
				if len(prop.Properties) > 0 || len(prop.Fields) > 0 {
					return fmt.Errorf("mapper_parsing_exception: [alias] field [%s] cannot have sub-properties or multi-fields", fullPath)
				}
				if target == fullPath {
					return fmt.Errorf("mapper_parsing_exception: alias field [%s] cannot point to itself", fullPath)
				}
				aliasTargets[fullPath] = target
				aliasPrefixes[fullPath] = prefix
			}
			if len(prop.Fields) > 0 {
				for fk, fprop := range prop.Fields {
					subFull := fullPath + "." + fk
					sfType := strings.ToLower(strings.TrimSpace(fprop.Type))
					allTypes[subFull] = sfType
					if err := validateSingleFieldProperty(subFull, sfType, fprop); err != nil {
						return err
					}
					for _, ct := range fprop.CopyToSlice() {
						copyToRefs = append(copyToRefs, copyToRef{source: subFull, prefix: prefix, target: strings.TrimSpace(ct)})
					}
					if sfType == "alias" {
						target := strings.TrimSpace(fprop.Path)
						if target == "" {
							return fmt.Errorf("mapper_parsing_exception: [path] is required for [alias] field [%s]", subFull)
						}
						if target == subFull {
							return fmt.Errorf("mapper_parsing_exception: alias field [%s] cannot point to itself", subFull)
						}
						aliasTargets[subFull] = target
						aliasPrefixes[subFull] = prefix
					}
				}
			}
			if len(prop.Properties) > 0 {
				if err := collect(prop.Properties, fullPath); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := collect(m.Properties, ""); err != nil {
		return err
	}

	for _, ref := range copyToRefs {
		targetType, exists := allTypes[ref.target]
		if !exists && ref.prefix != "" {
			targetType, exists = allTypes[ref.prefix+"."+ref.target]
		}
		if exists {
			switch targetType {
			case "object", "nested", "alias", "join":
				return fmt.Errorf("mapper_parsing_exception: [copy_to] on field [%s] cannot target [%s] field [%s]", ref.source, targetType, ref.target)
			}
		}
	}

	resolveTarget := func(aliasPath, target string) string {
		if _, ok := allTypes[target]; ok {
			return target
		}
		if pfx := aliasPrefixes[aliasPath]; pfx != "" {
			if _, ok := allTypes[pfx+"."+target]; ok {
				return pfx + "." + target
			}
		}
		return target
	}

	for aliasPath, rawTarget := range aliasTargets {
		target := resolveTarget(aliasPath, rawTarget)
		if target == aliasPath {
			return fmt.Errorf("mapper_parsing_exception: alias field [%s] cannot point to itself", aliasPath)
		}
		visited := map[string]bool{aliasPath: true}
		curr := target
		for curr != "" {
			if visited[curr] {
				return fmt.Errorf("mapper_parsing_exception: cycle detected for alias field [%s]", aliasPath)
			}
			visited[curr] = true
			nextRaw, isAlias := aliasTargets[curr]
			if !isAlias {
				break
			}
			curr = resolveTarget(curr, nextRaw)
		}
		if _, isTargetAlias := aliasTargets[target]; isTargetAlias || allTypes[target] == "alias" {
			return fmt.Errorf("mapper_parsing_exception: invalid [path] for alias [%s]: target [%s] cannot be another alias", aliasPath, rawTarget)
		}
		targetType, exists := allTypes[target]
		if !exists && strings.HasSuffix(target, ".keyword") {
			baseTarget := strings.TrimSuffix(target, ".keyword")
			if bt, ok := allTypes[baseTarget]; ok && bt == "text" {
				exists = true
				targetType = "keyword"
			}
		}
		if !exists || targetType == "" || targetType == "object" || targetType == "nested" {
			return fmt.Errorf("mapper_parsing_exception: invalid [path] for alias [%s]: target field [%s] does not exist", aliasPath, rawTarget)
		}
	}
	return nil
}

// ValidateMappingUpdateCompatibility checks whether `newSpec` attempts to change the type or immutable parameters of any existing field in `oldSpec`.
func ValidateMappingUpdateCompatibility(oldSpec, newSpec *esast.MappingSpec) error {
	if newSpec != nil && oldSpec == nil {
		return ValidateMappingSpec(newSpec)
	}
	if oldSpec == nil || newSpec == nil {
		return nil
	}
	if err := validatePropertiesCompatibility(oldSpec.Properties, newSpec.Properties, ""); err != nil {
		return err
	}
	return ValidateMappingSpec(&esast.MappingSpec{
		Properties: DeepMergeMappingProperties(oldSpec.Properties, newSpec.Properties),
	})
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
		if oldType == "" && (len(oldProp.Properties) > 0 || oldProp.Enabled != nil || oldProp.Dynamic != nil) {
			oldType = "object"
		}
		newType := strings.ToLower(strings.TrimSpace(newProp.Type))
		if newType == "" && (len(newProp.Properties) > 0 || newProp.Enabled != nil || newProp.Dynamic != nil) {
			if oldType == "nested" && newProp.Enabled == nil {
				newType = "nested"
			} else {
				newType = "object"
			}
		}
		if oldType != "" && newType != "" && oldType != newType {
			return fmt.Errorf("mapper [%s] cannot be changed from type [%s] to [%s]", fullPath, oldType, newType)
		}
		if newProp.Enabled != nil && (oldType == "object" || oldProp.Enabled != nil) {
			oldEnabled := true
			if oldProp.Enabled != nil {
				oldEnabled = *oldProp.Enabled
			}
			if oldEnabled != *newProp.Enabled {
				return fmt.Errorf("mapper [%s] enabled cannot be changed from [%v] to [%v]", fullPath, oldEnabled, *newProp.Enabled)
			}
		}
		if oldProp.Path != "" && newProp.Path != "" && oldProp.Path != newProp.Path {
			return fmt.Errorf("cannot change path of alias [%s] from [%s] to [%s]", fullPath, oldProp.Path, newProp.Path)
		}
		if newProp.Normalizer != "" && newProp.Normalizer != oldProp.Normalizer {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [normalizer] from [%s] to [%s]", fullPath, oldProp.Normalizer, newProp.Normalizer)
		}
		if newProp.Analyzer != "" && newProp.Analyzer != oldProp.Analyzer {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [analyzer] from [%s] to [%s]", fullPath, oldProp.Analyzer, newProp.Analyzer)
		}
		if newProp.ScalingFactor != 0 && newProp.ScalingFactor != oldProp.ScalingFactor {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [scaling_factor] from [%v] to [%v] for field [%s]", fullPath, oldProp.ScalingFactor, newProp.ScalingFactor, fullPath)
		}
		if (newProp.Index != nil && oldProp.Index != nil && *newProp.Index != *oldProp.Index) ||
			(newProp.Index != nil && oldProp.Index == nil && !*newProp.Index) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [index]", fullPath)
		}
		if (newProp.DocValues != nil && oldProp.DocValues != nil && *newProp.DocValues != *oldProp.DocValues) ||
			(newProp.DocValues != nil && oldProp.DocValues == nil && !*newProp.DocValues) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [doc_values]", fullPath)
		}
		oldDims := oldProp.EffectiveDims()
		newDims := newProp.EffectiveDims()
		if oldDims > 0 && newDims > 0 && oldDims != newDims {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [dims] from [%d] to [%d] for field [%s]", fullPath, oldDims, newDims, fullPath)
		}
		if newProp.Similarity != "" && oldProp.Similarity != "" && !strings.EqualFold(newProp.Similarity, oldProp.Similarity) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [similarity] from [%s] to [%s]", fullPath, oldProp.Similarity, newProp.Similarity)
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
	for _, saytSuffix := range []string{"._index_prefix", "._2gram", "._3gram"} {
		cleanPath = strings.TrimSuffix(cleanPath, saytSuffix)
	}
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
			if v.Value != nil {
				merged.Value = v.Value
			}
			if v.Subobjects != nil {
				merged.Subobjects = v.Subobjects
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
			if v.Script != nil {
				merged.Script = v.Script
			}
			if v.Meta != nil {
				merged.Meta = v.Meta
			}
			if v.IndexPrefixes != nil {
				merged.IndexPrefixes = v.IndexPrefixes
			}
			if v.IndexPhrases != nil {
				merged.IndexPhrases = v.IndexPhrases
			}
			if v.Store != nil {
				merged.Store = v.Store
			}
			if v.TimeZone != "" {
				merged.TimeZone = v.TimeZone
			}
			if v.SplitQueriesOnWhitespace != nil {
				merged.SplitQueriesOnWhitespace = v.SplitQueriesOnWhitespace
			}
			if v.EnablePositionIncrements != nil {
				merged.EnablePositionIncrements = v.EnablePositionIncrements
			}
			if v.Relations != nil {
				merged.Relations = v.Relations
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
		segments := strings.Split(propName, ".")
		currESPath := append(append([]string{}, esPathPrefix...), segments...)
		currJSONPath := append(append([]string{}, jsonPathPrefix...), segments...)
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

	if esType == "search_as_you_type" && prop.Analyzer == "" {
		prop.Analyzer = "standard"
	}

	if IsRangeFieldType(esType) || esType == "flattened" || esType == "sparse_vector" || esType == "rank_features" || esType == "percolator" || esType == "geo_shape" {
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:              dotPath,
			SourceJSONPath:           sourceJSONPath,
			Kind:                     StorageDynamicVariant,
			ColumnName:               "",
			DorisType:                DorisVariant,
			ESType:                   esType,
			Format:                   prop.Format,
			Analyzer:                 prop.Analyzer,
			LowercaseNormalizer:      lowerNorm,
			NestedPath:               activeNestedRoot,
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			IgnoreAbove:              prop.IgnoreAbove,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			Relations:                prop.Relations,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
		}
		return
	}

	if activeNestedRoot != "" {
		corrCol := s.NestedRoots[activeNestedRoot]
		relPrefixLen := nestedRootDepth
		if relPrefixLen > len(sourceJSONPath) {
			relPrefixLen = len(sourceJSONPath)
		}
		relJSONPath := sourceJSONPath[relPrefixLen:]
		prefilterCol := "n__" + SanitizeDorisIdentifier(dotPath)
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:              dotPath,
			SourceJSONPath:           sourceJSONPath,
			Kind:                     StorageNestedSubfield,
			ColumnName:               prefilterCol,
			DorisType:                dorisType,
			ESType:                   esType,
			Format:                   prop.Format,
			Analyzer:                 prop.Analyzer,
			LowercaseNormalizer:      lowerNorm,
			NestedPath:               activeNestedRoot,
			CorrelatedArrayCol:       corrCol,
			RelativeJSONPath:         relJSONPath,
			PrefilterArrayCol:        prefilterCol,
			IsMultiValued:            prop.MultiValued || len(relJSONPath) > 1 || DefaultMultiValuedPaths[dotPath],
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			ConstantValue:            prop.Value,
			IgnoreAbove:              prop.IgnoreAbove,
			ScalingFactor:            prop.ScalingFactor,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			Relations:                prop.Relations,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
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
			ESFieldPath:     dotPath,
			SourceJSONPath:  sourceJSONPath,
			Kind:            StoragePromotedVector,
			ColumnName:      colName,
			DorisType:       DorisFloatArray,
			ESType:          esType,
			VectorDims:      prop.EffectiveDims(),
			VectorMetric:    metric,
			IgnoreMalformed: prop.IgnoreMalformed,
			NotIndexed:      notIndexed,
			DocValuesFalse:  docValuesFalse,
		}
		return
	}
	if (prop.MultiValued || DefaultMultiValuedPaths[dotPath]) && !IsTextLikeESType(esType) {
		arrColName := colName
		if prop.UpgradedArray {
			arrColName = "f__arr__" + SanitizeDorisIdentifier(dotPath)
		}
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:              dotPath,
			SourceJSONPath:           sourceJSONPath,
			Kind:                     StoragePromotedArray,
			ColumnName:               arrColName,
			DorisType:                DorisString,
			ESType:                   esType,
			Format:                   prop.Format,
			Analyzer:                 prop.Analyzer,
			LowercaseNormalizer:      lowerNorm,
			IsMultiValued:            true,
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			ConstantValue:            prop.Value,
			IgnoreAbove:              prop.IgnoreAbove,
			ScalingFactor:            prop.ScalingFactor,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			Relations:                prop.Relations,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
		}
		return
	}

	s.Fields[dotPath] = FieldBinding{
		ESFieldPath:              dotPath,
		SourceJSONPath:           sourceJSONPath,
		Kind:                     StoragePromotedScalar,
		ColumnName:               colName,
		DorisType:                dorisType,
		ESType:                   esType,
		Format:                   prop.Format,
		Analyzer:                 prop.Analyzer,
		LowercaseNormalizer:      lowerNorm,
		CopyTo:                   copyTo,
		NullValue:                prop.NullValue,
		ConstantValue:            prop.Value,
		IgnoreAbove:              prop.IgnoreAbove,
		ScalingFactor:            prop.ScalingFactor,
		Coerce:                   prop.Coerce,
		IgnoreMalformed:          prop.IgnoreMalformed,
		EnablePositionIncrements: prop.EnablePositionIncrements,
		Relations:                prop.Relations,
		NotIndexed:               notIndexed,
		DocValuesFalse:           docValuesFalse,
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
		if b.ESType == "alias" && b.ColumnName == "" {
			cleanPath := strings.TrimSuffix(esFieldPath, ".keyword")
			return FieldBinding{
				ESFieldPath:    esFieldPath,
				SourceJSONPath: strings.Split(cleanPath, "."),
				Kind:           StorageDynamicVariant,
				DorisType:      DorisString,
				ESType:         "keyword",
			}
		}
		return b
	}
	for _, saytSuffix := range []string{"._index_prefix", "._2gram", "._3gram"} {
		if strings.HasSuffix(esFieldPath, saytSuffix) {
			basePath := strings.TrimSuffix(esFieldPath, saytSuffix)
			if b, ok := s.Fields[basePath]; ok && strings.EqualFold(b.ESType, "search_as_you_type") {
				b.ESFieldPath = esFieldPath
				return b
			}
		}
	}
	for prefix := esFieldPath; ; {
		idx := strings.LastIndexByte(prefix, '.')
		if idx <= 0 {
			break
		}
		prefix = prefix[:idx]
		if pb, ok := s.Fields[prefix]; ok {
			if pb.EnabledFalse {
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
			if pb.ESType == "flattened" || pb.ESType == "sparse_vector" || pb.ESType == "rank_features" {
				cleanPath := strings.TrimSuffix(esFieldPath, ".keyword")
				suffixSegs := strings.Split(strings.TrimPrefix(cleanPath, prefix+"."), ".")
				srcPath := append(append([]string{}, pb.SourceJSONPath...), suffixSegs...)
				dorisType := DorisString
				if pb.ESType == "sparse_vector" || pb.ESType == "rank_features" {
					dorisType = DorisDouble
				}
				return FieldBinding{
					ESFieldPath:         esFieldPath,
					SourceJSONPath:      srcPath,
					Kind:                StorageDynamicVariant,
					DorisType:           dorisType,
					ESType:              pb.ESType,
					NestedPath:          pb.NestedPath,
					LowercaseNormalizer: pb.LowercaseNormalizer,
					IgnoreAbove:         pb.IgnoreAbove,
					NotIndexed:          pb.NotIndexed,
					DocValuesFalse:      pb.DocValuesFalse,
				}
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
			if IsTextLikeESType(b.ESType) {
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
		if b.ESType == "search_as_you_type" && (strings.Contains(pattern, "_2gram") || strings.Contains(pattern, "_3gram") || strings.Contains(pattern, "_index_prefix") || strings.HasPrefix(pattern, k+".")) {
			for _, sub := range []string{"._2gram", "._3gram", "._index_prefix"} {
				cand := k + sub
				if re.MatchString(cand) {
					matchedSet[cand] = true
				}
			}
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
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range", "flattened", "percolator", "geo_shape":
		return DorisVariant
	case "keyword", "constant_keyword", "wildcard", "ip", "version":
		return DorisVarchar
	case "text", "match_only_text", "search_as_you_type", "completion", "annotated-text", "annotated_text":
		return DorisString
	case "long", "unsigned_long":
		return DorisBigInt
	case "integer", "short", "byte", "token_count":
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

type inferOptions struct {
	dateDetection      bool
	numericDetection   bool
	dynamicDateFormats []string
	dynamicTemplates   []map[string]any
	dynamicMode        string
}

func newInferOptions(existing *esast.MappingSpec) inferOptions {
	opts := inferOptions{
		dateDetection:    true,
		numericDetection: false,
		dynamicMode:      "true",
	}
	if existing != nil {
		if existing.DateDetection != nil {
			opts.dateDetection = *existing.DateDetection
		}
		if existing.NumericDetection != nil {
			opts.numericDetection = *existing.NumericDetection
		}
		opts.dynamicDateFormats = existing.DynamicDateFormats
		opts.dynamicTemplates = existing.DynamicTemplates
		opts.dynamicMode = normalizeDynamicMode(existing.Dynamic)
	}
	return opts
}

// InferMappingFromSampleDocs inspects up to 16 sample JSON documents on first write to an
// auto-created schemaless index (`dynamic: true`) and infers Elasticsearch field mappings
// (`keyword`, `text` + `.keyword`, `long`, `double`, `boolean`, `date`, and nested object properties).
func InferMappingFromSampleDocs(docs []json.RawMessage, existing ...*esast.MappingSpec) *esast.MappingSpec {
	var baseSpec *esast.MappingSpec
	if len(existing) > 0 {
		baseSpec = existing[0]
	}
	if len(docs) == 0 {
		return nil
	}
	opts := newInferOptions(baseSpec)
	props := make(map[string]esast.FieldProperty)
	if baseSpec != nil && len(baseSpec.Properties) > 0 {
		props = DeepMergeMappingProperties(nil, baseSpec.Properties)
	}
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
		inferObjectPropertiesWithOpts(obj, props, "", 0, &totalFields, opts)
	}
	if len(props) == 0 {
		if baseSpec != nil {
			out := *baseSpec
			return &out
		}
		return nil
	}
	inferredSpec := &esast.MappingSpec{
		Properties: props,
	}
	if baseSpec != nil {
		out := *baseSpec
		out.Properties = mergeInferredIntoExistingProps(baseSpec.Properties, inferredSpec.Properties)
		return &out
	}
	return inferredSpec
}

func mergeInferredIntoExistingProps(
	existingProps, inferredProps map[string]esast.FieldProperty,
) map[string]esast.FieldProperty {
	out := DeepMergeMappingProperties(nil, existingProps)
	for k, infProp := range inferredProps {
		exProp, exists := out[k]
		if !exists {
			copied := infProp
			if len(infProp.Properties) > 0 {
				copied.Properties = DeepMergeMappingProperties(nil, infProp.Properties)
			}
			if len(infProp.Fields) > 0 {
				copied.Fields = DeepMergeMappingProperties(nil, infProp.Fields)
			}
			out[k] = copied
			continue
		}
		if (exProp.Enabled != nil && !*exProp.Enabled) ||
			(exProp.Type != "" && !strings.EqualFold(exProp.Type, "object") && !strings.EqualFold(exProp.Type, "nested")) {
			continue
		}
		if len(infProp.Properties) > 0 {
			exProp.Properties = mergeInferredIntoExistingProps(exProp.Properties, infProp.Properties)
			out[k] = exProp
		}
	}
	return out
}

func inferObjectPropertiesWithOpts(obj map[string]any, dst map[string]esast.FieldProperty, pathPrefix string, depth int, totalFields *int, opts inferOptions) {
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
		fullPath := k
		if pathPrefix != "" {
			fullPath = pathPrefix + "." + k
		}
		existing, exists := dst[k]
		if exists && (len(existing.Properties) > 0 || strings.EqualFold(existing.Type, "object") || strings.EqualFold(existing.Type, "nested")) {
			if existing.Enabled != nil && !*existing.Enabled {
				continue
			}
			childOpts := opts
			if existing.Dynamic != nil {
				childOpts.dynamicMode = normalizeDynamicMode(existing.Dynamic)
			}
			if existing.Properties == nil {
				existing.Properties = make(map[string]esast.FieldProperty)
			}
			if subMap, isMap := val.(map[string]any); isMap {
				if depth+1 < maxInferredDepth {
					inferObjectPropertiesWithOpts(subMap, existing.Properties, fullPath, depth+1, totalFields, childOpts)
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
							inferObjectPropertiesWithOpts(elemMap, existing.Properties, fullPath, depth+1, totalFields, childOpts)
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
		if !exists && (opts.dynamicMode == "false" || opts.dynamicMode == "strict" || opts.dynamicMode == "runtime") {
			continue
		}
		inferred, ok := inferValuePropertyWithOpts(val, k, fullPath, depth, totalFields, opts)
		if !ok {
			continue
		}
		if exists {
			dst[k] = mergeFieldProperty(existing, inferred)
		} else {
			*totalFields++
			dst[k] = inferred
		}
	}
}

func detectDynamicMappingType(val any, opts inferOptions) string {
	switch v := val.(type) {
	case bool:
		return "boolean"
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return "double"
		}
		return "long"
	case float64:
		return "double"
	case string:
		trimmed := strings.TrimSpace(v)
		if opts.dateDetection && matchesInferredDate(trimmed, opts.dynamicDateFormats) {
			return "date"
		}
		if opts.numericDetection && trimmed != "" {
			if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return "long"
			}
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return "double"
			}
		}
		return "string"
	case map[string]any:
		return "object"
	case []any:
		for _, elem := range v {
			if elem != nil {
				return detectDynamicMappingType(elem, opts)
			}
		}
	}
	return ""
}

func matchesInferredDate(v string, dynamicDateFormats []string) bool {
	if len(dynamicDateFormats) > 0 {
		if _, err := strconv.ParseInt(v, 10, 64); err == nil {
			return false
		}
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return false
		}
		for _, fmtSpec := range dynamicDateFormats {
			for _, singleFmt := range strings.Split(fmtSpec, "||") {
				singleFmt = strings.TrimSpace(singleFmt)
				if singleFmt == "" || singleFmt == "epoch_millis" || singleFmt == "epoch_second" {
					continue
				}
				if _, ok := ParseESDateWithFormatToEpochMillis(v, singleFmt, time.Time{}); ok {
					return true
				}
			}
		}
		return false
	}
	if looksLikeISODateString(v) {
		if _, ok := ParseESDateToEpochMillis(v, time.Time{}); ok {
			return true
		}
	}
	return false
}

func matchDynamicTemplatePattern(pattern, candidate, matchPatternType string) bool {
	if pattern == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(matchPatternType), "regex") {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(candidate)
	}
	reStr := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"), `\?`, ".") + "$"
	re, err := regexp.Compile(reStr)
	if err != nil {
		return false
	}
	return re.MatchString(candidate)
}

func matchesDynamicMappingType(rawMMT any, detectedType string) bool {
	if rawMMT == nil {
		return true
	}
	matchSingle := func(s string) bool {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || s == "*" || s == detectedType {
			return true
		}
		return (s == "double" || s == "float") && (detectedType == "double" || detectedType == "float")
	}
	switch v := rawMMT.(type) {
	case string:
		return matchSingle(v)
	case []string:
		if len(v) == 0 {
			return true
		}
		for _, item := range v {
			if matchSingle(item) {
				return true
			}
		}
		return false
	case []any:
		if len(v) == 0 {
			return true
		}
		for _, item := range v {
			if s, ok := item.(string); ok && matchSingle(s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func substituteDynamicTemplatePlaceholders(fp *esast.FieldProperty, fieldName, detectedType string) {
	if fp == nil {
		return
	}
	dynTypeForFieldType := detectedType
	if dynTypeForFieldType == "string" {
		dynTypeForFieldType = "text"
	}
	replaceStr := func(s, dynVal string) string {
		s = strings.ReplaceAll(s, "{name}", fieldName)
		s = strings.ReplaceAll(s, "{dynamic_type}", dynVal)
		return s
	}
	if fp.Type != "" {
		fp.Type = replaceStr(fp.Type, dynTypeForFieldType)
	}
	if fp.Path != "" {
		fp.Path = replaceStr(fp.Path, detectedType)
	}
	switch ct := fp.CopyTo.(type) {
	case string:
		fp.CopyTo = replaceStr(ct, detectedType)
	case []string:
		out := make([]string, len(ct))
		for i, item := range ct {
			out[i] = replaceStr(item, detectedType)
		}
		fp.CopyTo = out
	case []any:
		out := make([]any, len(ct))
		for i, item := range ct {
			if s, ok := item.(string); ok {
				out[i] = replaceStr(s, detectedType)
			} else {
				out[i] = item
			}
		}
		fp.CopyTo = out
	}
	if len(fp.Fields) > 0 {
		newFields := make(map[string]esast.FieldProperty, len(fp.Fields))
		for subKey, subProp := range fp.Fields {
			newKey := replaceStr(subKey, detectedType)
			substituteDynamicTemplatePlaceholders(&subProp, fieldName, detectedType)
			newFields[newKey] = subProp
		}
		fp.Fields = newFields
	}
}

func applyMatchingDynamicTemplate(fieldName, fullPath, detectedType string, templates []map[string]any) (esast.FieldProperty, bool) {
	if len(templates) == 0 || detectedType == "" {
		return esast.FieldProperty{}, false
	}
	for _, entry := range templates {
		var rules []map[string]any
		if _, hasMapping := entry["mapping"]; hasMapping {
			rules = append(rules, entry)
		} else {
			for _, v := range entry {
				if rm, ok := v.(map[string]any); ok {
					rules = append(rules, rm)
				}
			}
		}
		for _, rule := range rules {
			if !matchesDynamicMappingType(rule["match_mapping_type"], detectedType) {
				continue
			}
			mpType, _ := rule["match_pattern"].(string)
			if matchPat, ok := rule["match"].(string); ok && matchPat != "" {
				if !matchDynamicTemplatePattern(matchPat, fieldName, mpType) {
					continue
				}
			}
			if unmatchPat, ok := rule["unmatch"].(string); ok && unmatchPat != "" {
				if matchDynamicTemplatePattern(unmatchPat, fieldName, mpType) {
					continue
				}
			}
			if pathMatchPat, ok := rule["path_match"].(string); ok && pathMatchPat != "" {
				if !matchDynamicTemplatePattern(pathMatchPat, fullPath, mpType) {
					continue
				}
			}
			if pathUnmatchPat, ok := rule["path_unmatch"].(string); ok && pathUnmatchPat != "" {
				if matchDynamicTemplatePattern(pathUnmatchPat, fullPath, mpType) {
					continue
				}
			}
			rawMapping, hasMap := rule["mapping"]
			if !hasMap || rawMapping == nil {
				continue
			}
			b, err := json.Marshal(rawMapping)
			if err != nil {
				continue
			}
			var fp esast.FieldProperty
			if err := json.Unmarshal(b, &fp); err != nil {
				continue
			}
			substituteDynamicTemplatePlaceholders(&fp, fieldName, detectedType)
			return fp, true
		}
	}
	return esast.FieldProperty{}, false
}

func inferValuePropertyWithOpts(val any, fieldName, fullPath string, depth int, totalFields *int, opts inferOptions) (esast.FieldProperty, bool) {
	if _, isSlice := val.([]any); !isSlice {
		if _, isMap := val.(map[string]any); !isMap && len(opts.dynamicTemplates) > 0 {
			detType := detectDynamicMappingType(val, opts)
			if tmplProp, matched := applyMatchingDynamicTemplate(fieldName, fullPath, detType, opts.dynamicTemplates); matched {
				return tmplProp, true
			}
		}
	}
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
		trimmed := strings.TrimSpace(v)
		if opts.dateDetection && matchesInferredDate(trimmed, opts.dynamicDateFormats) {
			return esast.FieldProperty{Type: "date"}, true
		}
		if opts.numericDetection && trimmed != "" {
			if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return esast.FieldProperty{Type: "long"}, true
			}
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return esast.FieldProperty{Type: "float"}, true
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
		if len(opts.dynamicTemplates) > 0 {
			if tmplProp, matched := applyMatchingDynamicTemplate(fieldName, fullPath, "object", opts.dynamicTemplates); matched {
				if (tmplProp.Enabled != nil && !*tmplProp.Enabled) ||
					(tmplProp.Type != "" && !strings.EqualFold(tmplProp.Type, "object") && !strings.EqualFold(tmplProp.Type, "nested")) {
					return tmplProp, true
				}
				if depth+1 < maxInferredDepth {
					childProps := make(map[string]esast.FieldProperty)
					inferObjectPropertiesWithOpts(v, childProps, fullPath, depth+1, totalFields, opts)
					if len(childProps) > 0 {
						tmplProp.Properties = DeepMergeMappingProperties(childProps, tmplProp.Properties)
					}
				}
				return tmplProp, true
			}
		}
		if depth+1 >= maxInferredDepth {
			return esast.FieldProperty{}, false
		}
		childProps := make(map[string]esast.FieldProperty)
		inferObjectPropertiesWithOpts(v, childProps, fullPath, depth+1, totalFields, opts)
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
				inferObjectPropertiesWithOpts(elemMap, merged.Properties, fullPath, depth+1, totalFields, opts)
				if len(merged.Properties) > 0 {
					hasElem = true
				}
				continue
			}
			elemProp, ok := inferValuePropertyWithOpts(elem, fieldName, fullPath, depth, totalFields, opts)
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
			matchedTmpl := false
			if len(opts.dynamicTemplates) > 0 {
				if _, ok := applyMatchingDynamicTemplate(fieldName, fullPath, "double", opts.dynamicTemplates); ok {
					matchedTmpl = true
				} else if _, ok := applyMatchingDynamicTemplate(fieldName, fullPath, "float", opts.dynamicTemplates); ok {
					matchedTmpl = true
				}
			}
			if !matchedTmpl {
				return esast.FieldProperty{
					Type:       "dense_vector",
					Dims:       len(v),
					Similarity: "cosine",
				}, true
			}
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
		if fp.Type == "text" {
			if fp.Fields == nil {
				fp.Fields = map[string]esast.FieldProperty{
					"keyword": {Type: "keyword"},
				}
			}
		}
	}
}

func mergeFieldProperty(existing, incoming esast.FieldProperty) esast.FieldProperty {
	mv := existing.MultiValued || incoming.MultiValued
	if len(existing.Properties) == 0 && existing.Type != "" && !strings.EqualFold(existing.Type, "object") && !strings.EqualFold(existing.Type, "nested") && len(incoming.Properties) > 0 {
		return existing
	}
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
		if len(incoming.Fields) > 0 {
			existing.Fields = DeepMergeMappingProperties(existing.Fields, incoming.Fields)
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
		mergedFields := DeepMergeMappingProperties(existing.Fields, incoming.Fields)
		if mv && len(mergedFields) == 0 || !hasText {
			return esast.FieldProperty{Type: "keyword", MultiValued: mv, Fields: mergedFields}
		}
		if mergedFields == nil {
			mergedFields = make(map[string]esast.FieldProperty)
		}
		if _, hasKw := mergedFields["keyword"]; !hasKw {
			mergedFields["keyword"] = esast.FieldProperty{Type: "keyword"}
		}
		return esast.FieldProperty{
			Type:        "text",
			MultiValued: mv,
			Fields:      mergedFields,
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
