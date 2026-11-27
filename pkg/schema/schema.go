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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
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
	DorisVarchar       DorisScalarType = "VARCHAR(1024)"
	DorisString        DorisScalarType = "STRING"
	DorisBigInt        DorisScalarType = "BIGINT"
	DorisLargeInt      DorisScalarType = "LARGEINT"
	DorisLargeIntArray DorisScalarType = "ARRAY<LARGEINT>"
	DorisInt           DorisScalarType = "INT"
	DorisDouble        DorisScalarType = "DOUBLE"
	DorisBoolean       DorisScalarType = "BOOLEAN"
	DorisDateTimeV2    DorisScalarType = "DATETIMEV2(3)"
	DorisFloatArray    DorisScalarType = "ARRAY<FLOAT>"
	DorisVariant       DorisScalarType = "VARIANT"
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
	Locale              string // Optional ES date locale (e.g. "fr")
	Analyzer            string
	SearchAnalyzer      string
	NormalizerName      string
	LowercaseNormalizer bool
	KeywordCompanion    string // Optional untokenized `.keyword` column for `text` fields
	KeywordNormalizer   bool   // Whether `KeywordCompanion` has a lowercase normalizer
	VectorDims          int
	AutoDims            bool
	VectorMetric        string
	VectorElementType   string
	VectorIndexOptions  map[string]any

	// For `StorageNestedSubfield` (`nested` arrays of objects):
	NestedPath               string   // Root nested path, e.g. "columns"
	CorrelatedArrayCol       string   // e.g. "n__columns" (`ARRAY<STRING>` holding per-element JSON)
	RelativeJSONPath         []string // Path inside each nested element, e.g. ["tags", "tagFQN"]
	PrefilterArrayCol        string   // e.g. "n__columns__tags__tagFQN" (`ARRAY<STRING>` with `USING INVERTED`)
	IsMultiValued            bool
	CopyTo                   []string
	NullValue                any
	ConstantValue            any
	HasConstantValue         bool
	AdoptedConstantValue     bool
	IgnoreAbove              int
	AliasTarget              string
	IsPassthroughAlias       bool
	ScalingFactor            float64
	Coerce                   *bool
	IgnoreMalformed          *bool
	EnablePositionIncrements *bool
	PositiveScoreImpact      *bool
	MaxShingleSize           int
	DepthLimit               int
	Relations                map[string]any
	Meta                     map[string]string
	Contexts                 []esast.CompletionContextDef
	NotIndexed               bool
	EnabledFalse             bool
	DocValuesFalse           bool
	StoreArraySource         *bool
	SyntheticSourceKeep      string
	TimeSeriesDimension      *bool
	TimeSeriesDimensions     []string
	TimeSeriesMetric         string
	IsVirtualSAYTSubfield    bool
	FromScript               bool
	FromRuntime              bool
	AggregateMetrics         []string
	DefaultMetric            string
	ES8Mode                  bool
}

// EffectivePositiveScoreImpact returns true unless `positive_score_impact` was explicitly set to false.
func (b FieldBinding) EffectivePositiveScoreImpact() bool {
	return b.PositiveScoreImpact == nil || *b.PositiveScoreImpact
}

// SearchAsYouTypeSubfields returns the active synthetic sub-field suffixes (e.g. `._2gram`, `._3gram`, `._index_prefix`)
// for a `search_as_you_type` field based on its `max_shingle_size` (default 3).
func (b FieldBinding) SearchAsYouTypeSubfields() []string {
	if b.IsVirtualSAYTSubfield {
		return nil
	}
	ms := b.MaxShingleSize
	if ms <= 0 {
		ms = 3
	}
	switch ms {
	case 2:
		return []string{"._2gram", "._index_prefix"}
	case 4:
		return []string{"._2gram", "._3gram", "._4gram", "._index_prefix"}
	default:
		return []string{"._2gram", "._3gram", "._index_prefix"}
	}
}

// EffectiveDepthLimit returns the maximum object nesting depth for a `flattened` field (default 20).
func (b FieldBinding) EffectiveDepthLimit() int {
	if b.DepthLimit > 0 {
		return b.DepthLimit
	}
	return 20
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
	IndexName                string
	DorisDB                  string
	DorisTable               string
	Buckets                  int
	Fields                   map[string]FieldBinding
	OrderedFields            []FieldBinding
	NestedRoots              map[string]string // Maps ES nested path (e.g. "columns") -> Doris column ("n__columns")
	nestedRootPaths          map[string][]string
	NestedRootSpecs          []NestedRootSpec
	RawMapping               *esast.MappingSpec
	MaxTotalFields           int
	MaxNestedFields          int
	HasExplicitNestedLimit   bool
	MaxNestedObjects         int
	MaxDepth                 int
	MaxFieldNameLength       int
	MaxTermsCount            int
	MaxResultWindow          int
	MaxDocvalueFieldsSearch  int
	MaxScriptFields          int
	MaxRegexLength           int
	DefaultCoerce            *bool
	DefaultIgnoreMalformed   *bool
	SourceMode               string
	SyntheticSource          bool
	SourceConfig             *SourceConfig
	LegacyTypeName           string
	FieldAddedAtSeqNo        map[string]int64
	ES8Mode                  bool
	IndexMode                string
	RoutingPath              []string
	TimeSeriesStartTime      string
	TimeSeriesEndTime        string
	IgnoreDynamicBeyondLimit bool
	IsRuntimeEvalSchema      bool
	NestedEvalRoot           string
	AnalysisConfig           *analysis.IndexAnalysisConfig
	MappingHash              string
	AliasFieldKeys           []string
	FlattenedFieldKeys       []string
	SparseFieldKeys          []string
	histogramFieldKeys       []string
	rangeFieldKeys           []string
	extraCopyToKeys          []string
	enabledFalsePaths        [][]string
	passthroughNodes         []passthroughNodeSpec
}

type passthroughNodeSpec struct {
	prefix      string
	priority    int
	hasPriority bool
}

// CopyIndexMappingSettingsFrom copies index-level mapping/search limits and defaults from src into s.
func (s *IndexSchema) CopyIndexMappingSettingsFrom(src *IndexSchema) {
	if s == nil || src == nil {
		return
	}
	if src.MaxTotalFields > 0 {
		s.MaxTotalFields = src.MaxTotalFields
	}
	if src.HasExplicitNestedLimit || src.MaxNestedFields > 0 {
		s.MaxNestedFields = src.MaxNestedFields
		s.HasExplicitNestedLimit = src.HasExplicitNestedLimit
	}
	if src.MaxNestedObjects > 0 {
		s.MaxNestedObjects = src.MaxNestedObjects
	}
	if src.MaxDepth > 0 {
		s.MaxDepth = src.MaxDepth
	}
	if src.MaxFieldNameLength > 0 {
		s.MaxFieldNameLength = src.MaxFieldNameLength
	}
	if src.MaxTermsCount > 0 {
		s.MaxTermsCount = src.MaxTermsCount
	}
	if src.MaxResultWindow > 0 {
		s.MaxResultWindow = src.MaxResultWindow
	}
	if src.MaxDocvalueFieldsSearch > 0 {
		s.MaxDocvalueFieldsSearch = src.MaxDocvalueFieldsSearch
	}
	if src.MaxScriptFields > 0 {
		s.MaxScriptFields = src.MaxScriptFields
	}
	if src.MaxRegexLength > 0 {
		s.MaxRegexLength = src.MaxRegexLength
	}
	if src.DefaultCoerce != nil {
		v := *src.DefaultCoerce
		s.DefaultCoerce = &v
	}
	if src.DefaultIgnoreMalformed != nil {
		v := *src.DefaultIgnoreMalformed
		s.DefaultIgnoreMalformed = &v
	}
	if src.SourceMode != "" && s.SourceMode == "" {
		s.SourceMode = src.SourceMode
	}
	if src.SyntheticSource {
		s.SyntheticSource = true
	}
	if src.SourceConfig != nil && s.SourceConfig == nil {
		cp := *src.SourceConfig
		if len(src.SourceConfig.Includes) > 0 {
			cp.Includes = append([]string(nil), src.SourceConfig.Includes...)
		}
		if len(src.SourceConfig.Excludes) > 0 {
			cp.Excludes = append([]string(nil), src.SourceConfig.Excludes...)
		}
		s.SourceConfig = &cp
	}
	if src.LegacyTypeName != "" && s.LegacyTypeName == "" {
		s.LegacyTypeName = src.LegacyTypeName
	}
	if len(src.FieldAddedAtSeqNo) > 0 {
		if s.FieldAddedAtSeqNo == nil {
			s.FieldAddedAtSeqNo = make(map[string]int64, len(src.FieldAddedAtSeqNo))
		}
		for k, v := range src.FieldAddedAtSeqNo {
			if _, exists := s.FieldAddedAtSeqNo[k]; !exists {
				s.FieldAddedAtSeqNo[k] = v
			}
		}
	}
	if src.ES8Mode {
		s.ES8Mode = true
	}
	if src.IndexMode != "" && s.IndexMode == "" {
		s.IndexMode = src.IndexMode
	}
	if len(src.RoutingPath) > 0 && len(s.RoutingPath) == 0 {
		s.RoutingPath = append([]string(nil), src.RoutingPath...)
	}
	if src.TimeSeriesStartTime != "" && s.TimeSeriesStartTime == "" {
		s.TimeSeriesStartTime = src.TimeSeriesStartTime
	}
	if src.TimeSeriesEndTime != "" && s.TimeSeriesEndTime == "" {
		s.TimeSeriesEndTime = src.TimeSeriesEndTime
	}
	if src.IgnoreDynamicBeyondLimit {
		s.IgnoreDynamicBeyondLimit = true
	}
	if src.IsRuntimeEvalSchema {
		s.IsRuntimeEvalSchema = true
	}
	if src.AnalysisConfig != nil && s.AnalysisConfig == nil {
		s.AnalysisConfig = src.AnalysisConfig
		s.refreshNormalizerFlags()
	}
	for fn, srcFB := range src.Fields {
		if srcFB.AdoptedConstantValue {
			if dstFB, ok := s.Fields[fn]; ok {
				dstFB.AdoptedConstantValue = true
				s.Fields[fn] = dstFB
			}
		}
	}
	s.recomputePrecomputedSlices()
}

// EffectiveCoerce returns the field-level `coerce` flag if explicitly set, otherwise the index-level default (true).
func (s *IndexSchema) EffectiveCoerce(b FieldBinding) bool {
	if b.Coerce != nil {
		return *b.Coerce
	}
	if s != nil && s.DefaultCoerce != nil {
		return *s.DefaultCoerce
	}
	return true
}

// EffectiveIgnoreMalformed returns the field-level `ignore_malformed` flag if explicitly set, otherwise the index-level default (false).
func (s *IndexSchema) EffectiveIgnoreMalformed(b FieldBinding) bool {
	if b.IgnoreMalformed != nil {
		return *b.IgnoreMalformed
	}
	if s != nil && s.DefaultIgnoreMalformed != nil {
		return *s.DefaultIgnoreMalformed
	}
	return false
}

func (s *IndexSchema) withEffectiveDefaults(b FieldBinding) FieldBinding {
	c := s.EffectiveCoerce(b)
	im := s.EffectiveIgnoreMalformed(b)
	b.Coerce = &c
	b.IgnoreMalformed = &im
	if s != nil && s.ES8Mode {
		b.ES8Mode = true
	}
	return b
}

// SourceDisabled reports whether the mapping `_source` meta-field explicitly disables `_source` (`"enabled": false` or `"mode": "disabled"`).
func (s *IndexSchema) SourceDisabled() bool {
	if s == nil {
		return false
	}
	if s.SourceMode == "disabled" {
		return true
	}
	if s.SourceConfig != nil && s.SourceConfig.Enabled != nil && !*s.SourceConfig.Enabled {
		return true
	}
	if s.RawMapping == nil || len(s.RawMapping.Source) == 0 {
		return false
	}
	if rawMode, ok := s.RawMapping.Source["mode"].(string); ok && strings.EqualFold(strings.TrimSpace(rawMode), "disabled") {
		return true
	}
	if rawEnabled, ok := s.RawMapping.Source["enabled"]; ok {
		if b, isBool := rawEnabled.(bool); isBool {
			return !b
		}
	}
	return false
}

// SourceIncludesExcludes returns the mapping-level `_source.includes` and `_source.excludes` patterns, if any.
func (s *IndexSchema) SourceIncludesExcludes() ([]string, []string) {
	if s == nil || s.RawMapping == nil || len(s.RawMapping.Source) == 0 {
		return nil, nil
	}
	inc, _ := parseMappingSourcePatternSlice(s.RawMapping.Source["includes"], "includes")
	exc, _ := parseMappingSourcePatternSlice(s.RawMapping.Source["excludes"], "excludes")
	return inc, exc
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
	defaultCoerce := true
	defaultIgnoreMalformed := false
	rawDB := strings.TrimSpace(dorisDB)
	if rawDB == "" {
		rawDB = "default"
	}
	s := &IndexSchema{
		IndexName:              indexName,
		DorisDB:                rawDB,
		DorisTable:             SanitizeDorisIdentifier(indexName),
		Buckets:                8,
		Fields:                 make(map[string]FieldBinding),
		NestedRoots:            make(map[string]string),
		nestedRootPaths:        make(map[string][]string),
		RawMapping:             mapping,
		MaxTotalFields:         1000,
		MaxNestedFields:        50,
		MaxNestedObjects:       10000,
		MaxDepth:               20,
		MaxTermsCount:          65536,
		DefaultCoerce:          &defaultCoerce,
		DefaultIgnoreMalformed: &defaultIgnoreMalformed,
	}
	if mapping != nil {
		if mapping.Source != nil {
			if cfg, err := ParseSourceConfig(mapping.Source); err == nil {
				s.SourceConfig = cfg
				s.SourceMode = cfg.Mode
				s.SyntheticSource = cfg.Mode == "synthetic"
			}
		}
		if IsSizeMetadataEnabled(mapping) {
			s.Fields["_size"] = FieldBinding{
				ESFieldPath: "_size",
				ColumnName:  "f___size",
				Kind:        StoragePromotedScalar,
				DorisType:   DorisBigInt,
				ESType:      "long",
			}
		}
		if len(mapping.Properties) > 0 {
			if expanded, err := ExpandDottedPropertiesWithSubobjects(mapping.Properties, mapping.Subobjects != nil && !*mapping.Subobjects); err == nil {
				mapping.Properties = expanded
			}
			s.compileProperties(nil, nil, "", 0, false, mapping.Properties)
		}
	}
	s.finalizeCompiledSlices()
	return s
}

// CompileIndexSchemaWithSettings compiles an IndexSchema with optional ES index settings (e.g. `analysis.normalizer`).
func CompileIndexSchemaWithSettings(dorisDB, indexName string, mapping *esast.MappingSpec, settings map[string]any) *IndexSchema {
	s := CompileIndexSchema(dorisDB, indexName, mapping)
	if len(settings) > 0 {
		_ = s.SetAnalysisSettings(settings)
	}
	return s
}

// SetAnalysisSettings parses and attaches ES index analysis settings to s and refreshes field normalizer flags.
func (s *IndexSchema) SetAnalysisSettings(settings map[string]any) error {
	if s == nil {
		return nil
	}
	cfg, err := analysis.ParseIndexAnalysisConfig(settings, analysis.Options{})
	if err != nil {
		return err
	}
	s.AnalysisConfig = cfg
	s.refreshNormalizerFlags()
	s.recomputePrecomputedSlices()
	return nil
}

func (s *IndexSchema) refreshNormalizerFlags() {
	if s == nil {
		return
	}
	for k, b := range s.Fields {
		if b.NormalizerName != "" {
			b.LowercaseNormalizer = normalizerUsesLowercaseFilter(b.NormalizerName, s.AnalysisConfig)
			s.Fields[k] = b
		}
	}
	for k, b := range s.Fields {
		if b.KeywordCompanion != "" {
			if kwB, ok := s.Fields[k+".keyword"]; ok {
				b.KeywordNormalizer = kwB.LowercaseNormalizer
				s.Fields[k] = b
			}
		}
	}
	for i, ob := range s.OrderedFields {
		if updated, ok := s.Fields[ob.ESFieldPath]; ok {
			s.OrderedFields[i] = updated
		}
	}
}

func normalizerUsesLowercaseFilter(normName string, cfg *analysis.IndexAnalysisConfig) bool {
	trimmed := strings.TrimSpace(normName)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return false
	}
	if strings.EqualFold(trimmed, "lowercase") {
		return true
	}
	if cfg == nil {
		return true
	}
	def, ok := cfg.NormalizerDefs[trimmed]
	if !ok {
		return false
	}
	var names []string
	switch fv := def["filter"].(type) {
	case string:
		names = []string{fv}
	case []string:
		names = fv
	case []any:
		for _, item := range fv {
			if sv, okS := item.(string); okS {
				names = append(names, sv)
			}
		}
	}
	for _, fn := range names {
		lf := strings.ToLower(strings.TrimSpace(fn))
		if lf == "lowercase" || lf == "icu_normalizer" || lf == "icu_folding" {
			return true
		}
		if fDef, hasF := cfg.FilterDefs[fn]; hasF {
			if ft, _ := fDef["type"].(string); strings.EqualFold(strings.TrimSpace(ft), "lowercase") {
				return true
			}
		}
	}
	return false
}

func (s *IndexSchema) registerPassthroughAliases() {
	if s == nil || len(s.passthroughNodes) == 0 || len(s.Fields) == 0 {
		return
	}
	fieldKeys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)

	hasConcreteConflict := func(rel string) bool {
		if existing, exists := s.Fields[rel]; exists && !existing.IsPassthroughAlias {
			return true
		}
		prefix := rel + "."
		for _, fk := range fieldKeys {
			if strings.HasPrefix(fk, prefix) {
				if fb := s.Fields[fk]; !fb.IsPassthroughAlias {
					return true
				}
			}
		}
		return false
	}

	type candidate struct {
		target      string
		priority    int
		hasPriority bool
	}
	winners := make(map[string]candidate)

	for _, k := range fieldKeys {
		b := s.Fields[k]
		if b.AliasTarget != "" || strings.EqualFold(b.ESType, "passthrough") || strings.EqualFold(b.ESType, "object") || strings.EqualFold(b.ESType, "nested") {
			continue
		}
		if strings.HasPrefix(k, "_") || strings.HasSuffix(k, ".keyword") {
			continue
		}
		var bestNode *passthroughNodeSpec
		for i := range s.passthroughNodes {
			pn := &s.passthroughNodes[i]
			if strings.HasPrefix(k, pn.prefix+".") {
				if bestNode == nil || len(pn.prefix) > len(bestNode.prefix) {
					bestNode = pn
				}
			}
		}
		if bestNode == nil {
			continue
		}
		rel := strings.TrimPrefix(k, bestNode.prefix+".")
		if rel == "" || hasConcreteConflict(rel) {
			continue
		}
		cand := candidate{
			target:      k,
			priority:    bestNode.priority,
			hasPriority: bestNode.hasPriority,
		}
		prev, hasPrev := winners[rel]
		if !hasPrev ||
			(cand.hasPriority && !prev.hasPriority) ||
			(cand.hasPriority == prev.hasPriority && cand.priority > prev.priority) ||
			(cand.hasPriority == prev.hasPriority && cand.priority == prev.priority && cand.target < prev.target) {
			winners[rel] = cand
		}
	}

	for rel, win := range winners {
		s.Fields[rel] = FieldBinding{
			ESFieldPath:        rel,
			ESType:             "alias",
			AliasTarget:        win.target,
			IsPassthroughAlias: true,
		}
	}
}

func (s *IndexSchema) finalizeCompiledSlices() {
	s.registerPassthroughAliases()
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
					aliased.IsPassthroughAlias = b.IsPassthroughAlias
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
				aliased.IsPassthroughAlias = b.IsPassthroughAlias
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
	s.recomputePrecomputedSlices()
}

func (s *IndexSchema) recomputePrecomputedSlices() {
	if s == nil {
		return
	}
	fieldKeys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)

	orderedPaths := make(map[string]bool, len(s.OrderedFields))
	for _, ob := range s.OrderedFields {
		orderedPaths[ob.ESFieldPath] = true
	}

	s.AliasFieldKeys = make([]string, 0)
	s.FlattenedFieldKeys = make([]string, 0)
	s.SparseFieldKeys = make([]string, 0)
	s.histogramFieldKeys = make([]string, 0)
	s.rangeFieldKeys = make([]string, 0)
	s.extraCopyToKeys = make([]string, 0)
	s.enabledFalsePaths = make([][]string, 0)

	for _, k := range fieldKeys {
		b := s.Fields[k]
		if b.EnabledFalse && len(b.SourceJSONPath) > 0 {
			s.enabledFalsePaths = append(s.enabledFalsePaths, b.SourceJSONPath)
		}
		if b.AliasTarget != "" {
			if !b.IsPassthroughAlias && b.ESFieldPath != "" {
				s.AliasFieldKeys = append(s.AliasFieldKeys, k)
			}
			continue
		}
		if !orderedPaths[k] && !orderedPaths[b.ESFieldPath] && !b.EnabledFalse && len(b.CopyTo) > 0 {
			s.extraCopyToKeys = append(s.extraCopyToKeys, k)
		}
		if b.EnabledFalse {
			continue
		}
		switch {
		case b.ESType == "flattened":
			s.FlattenedFieldKeys = append(s.FlattenedFieldKeys, k)
		case b.ESType == "sparse_vector" || b.ESType == "rank_features":
			s.SparseFieldKeys = append(s.SparseFieldKeys, k)
		case b.ESType == "histogram":
			s.histogramFieldKeys = append(s.histogramFieldKeys, k)
		case IsRangeFieldType(b.ESType):
			s.rangeFieldKeys = append(s.rangeFieldKeys, k)
		}
	}
	s.RefreshMappingHash()
}

// RefreshMappingHash computes a deterministic SHA-256 hex digest over the schema's
// canonical mapping, settings, mode, nested roots, and compiled fields.
func (s *IndexSchema) RefreshMappingHash() string {
	if s == nil {
		return ""
	}
	h := sha256.New()
	writeCanonicalValue := func(label string, v any) {
		_, _ = fmt.Fprintf(h, "%s:", label)
		if b, err := json.Marshal(v); err == nil {
			_, _ = h.Write(b)
		} else {
			_, _ = fmt.Fprintf(h, "%#v", v)
		}
		_, _ = h.Write([]byte{'\n'})
	}

	writeCanonicalValue("meta", struct {
		IndexName                string
		DorisDB                  string
		DorisTable               string
		Buckets                  int
		MaxTotalFields           int
		MaxNestedFields          int
		HasExplicitNestedLimit   bool
		MaxNestedObjects         int
		MaxDepth                 int
		MaxFieldNameLength       int
		MaxTermsCount            int
		MaxResultWindow          int
		MaxDocvalueFieldsSearch  int
		MaxScriptFields          int
		MaxRegexLength           int
		DefaultCoerce            *bool
		DefaultIgnoreMalformed   *bool
		SourceMode               string
		SyntheticSource          bool
		SourceConfig             *SourceConfig
		LegacyTypeName           string
		ES8Mode                  bool
		IndexMode                string
		RoutingPath              []string
		TimeSeriesStartTime      string
		TimeSeriesEndTime        string
		IgnoreDynamicBeyondLimit bool
		IsRuntimeEvalSchema      bool
		NestedEvalRoot           string
		AnalysisConfig           *analysis.IndexAnalysisConfig
	}{
		IndexName:                s.IndexName,
		DorisDB:                  s.DorisDB,
		DorisTable:               s.DorisTable,
		Buckets:                  s.Buckets,
		MaxTotalFields:           s.MaxTotalFields,
		MaxNestedFields:          s.MaxNestedFields,
		HasExplicitNestedLimit:   s.HasExplicitNestedLimit,
		MaxNestedObjects:         s.MaxNestedObjects,
		MaxDepth:                 s.MaxDepth,
		MaxFieldNameLength:       s.MaxFieldNameLength,
		MaxTermsCount:            s.MaxTermsCount,
		MaxResultWindow:          s.MaxResultWindow,
		MaxDocvalueFieldsSearch:  s.MaxDocvalueFieldsSearch,
		MaxScriptFields:          s.MaxScriptFields,
		MaxRegexLength:           s.MaxRegexLength,
		DefaultCoerce:            s.DefaultCoerce,
		DefaultIgnoreMalformed:   s.DefaultIgnoreMalformed,
		SourceMode:               s.SourceMode,
		SyntheticSource:          s.SyntheticSource,
		SourceConfig:             s.SourceConfig,
		LegacyTypeName:           s.LegacyTypeName,
		ES8Mode:                  s.ES8Mode,
		IndexMode:                s.IndexMode,
		RoutingPath:              s.RoutingPath,
		TimeSeriesStartTime:      s.TimeSeriesStartTime,
		TimeSeriesEndTime:        s.TimeSeriesEndTime,
		IgnoreDynamicBeyondLimit: s.IgnoreDynamicBeyondLimit,
		IsRuntimeEvalSchema:      s.IsRuntimeEvalSchema,
		NestedEvalRoot:           s.NestedEvalRoot,
		AnalysisConfig:           s.AnalysisConfig,
	})

	nestedKeys := make([]string, 0, len(s.NestedRoots))
	for k := range s.NestedRoots {
		nestedKeys = append(nestedKeys, k)
	}
	sort.Strings(nestedKeys)
	for _, k := range nestedKeys {
		writeCanonicalValue("nested:"+k, s.NestedRoots[k])
	}

	fieldKeys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	for _, k := range fieldKeys {
		writeCanonicalValue("field:"+k, s.Fields[k])
	}

	if s.RawMapping != nil {
		writeCanonicalValue("raw_mapping", s.RawMapping)
	}

	s.MappingHash = hex.EncodeToString(h.Sum(nil))
	return s.MappingHash
}

// MergeMappingSpecs deep-merges two Elasticsearch MappingSpecs without losing existing properties or sub-fields.
func MergeMappingSpecs(oldSpec, newSpec *esast.MappingSpec) *esast.MappingSpec {
	if oldSpec == nil && newSpec == nil {
		return &esast.MappingSpec{Properties: make(map[string]esast.FieldProperty)}
	}
	if oldSpec == nil {
		cp := deepCloneMappingSpec(newSpec)
		subFalse := cp.Subobjects != nil && !*cp.Subobjects
		cp.Properties = deepMergeMappingPropertiesWithSubobjects(nil, newSpec.Properties, subFalse)
		return cp
	}
	if newSpec == nil {
		cp := deepCloneMappingSpec(oldSpec)
		subFalse := cp.Subobjects != nil && !*cp.Subobjects
		cp.Properties = deepMergeMappingPropertiesWithSubobjects(nil, oldSpec.Properties, subFalse)
		return cp
	}
	en := oldSpec.Enabled
	if newSpec.Enabled != nil {
		v := *newSpec.Enabled
		en = &v
	} else if en != nil {
		v := *en
		en = &v
	}
	dyn := deepCloneAny(oldSpec.Dynamic)
	if newSpec.Dynamic != nil {
		dyn = deepCloneAny(newSpec.Dynamic)
	}
	subobj := oldSpec.Subobjects
	if newSpec.Subobjects != nil {
		v := *newSpec.Subobjects
		subobj = &v
	} else if subobj != nil {
		v := *subobj
		subobj = &v
	}
	var rt *esast.RoutingMetaSpec
	if newSpec.Routing != nil {
		r := *newSpec.Routing
		rt = &r
	} else if oldSpec.Routing != nil {
		r := *oldSpec.Routing
		rt = &r
	}
	size := deepCloneMapStringAny(oldSpec.Size)
	if newSpec.Size != nil {
		size = deepCloneMapStringAny(newSpec.Size)
	}
	meta := deepCloneMapStringAny(oldSpec.Meta)
	if newSpec.Meta != nil {
		meta = deepCloneMapStringAny(newSpec.Meta)
	}
	source := deepCloneMapStringAny(oldSpec.Source)
	if newSpec.Source != nil {
		source = deepCloneMapStringAny(newSpec.Source)
	}
	dsTS := deepCloneAny(oldSpec.DataStreamTimestamp)
	if newSpec.DataStreamTimestamp != nil {
		dsTS = deepCloneAny(newSpec.DataStreamTimestamp)
	}
	dynTemplates := deepCloneSliceMapStringAny(oldSpec.DynamicTemplates)
	if newSpec.DynamicTemplates != nil {
		dynTemplates = deepCloneSliceMapStringAny(newSpec.DynamicTemplates)
	}
	dateDet := oldSpec.DateDetection
	if newSpec.DateDetection != nil {
		v := *newSpec.DateDetection
		dateDet = &v
	} else if dateDet != nil {
		v := *dateDet
		dateDet = &v
	}
	numDet := oldSpec.NumericDetection
	if newSpec.NumericDetection != nil {
		v := *newSpec.NumericDetection
		numDet = &v
	} else if numDet != nil {
		v := *numDet
		numDet = &v
	}
	dynDateFormats := append([]string(nil), oldSpec.DynamicDateFormats...)
	if newSpec.DynamicDateFormats != nil {
		dynDateFormats = append([]string(nil), newSpec.DynamicDateFormats...)
	}
	subFalse := subobj != nil && !*subobj
	return &esast.MappingSpec{
		Enabled:             en,
		Dynamic:             dyn,
		Subobjects:          subobj,
		Routing:             rt,
		Size:                size,
		Meta:                meta,
		Source:              source,
		DataStreamTimestamp: dsTS,
		DynamicTemplates:    dynTemplates,
		DateDetection:       dateDet,
		NumericDetection:    numDet,
		DynamicDateFormats:  dynDateFormats,
		Runtime:             CloneFlatRuntimeMap(oldSpec.Runtime, newSpec.Runtime),
		Properties:          deepMergeMappingPropertiesWithSubobjects(oldSpec.Properties, newSpec.Properties, subFalse),
	}
}

// CloneFlatRuntimeMap clones and merges `runtime` mapping definitions without expanding dotted field names
// (such as `status.active`, `http.clientip`, or `users.first_script`) into nested object `Properties`.
func CloneFlatRuntimeMap(dst, src map[string]esast.FieldProperty) map[string]esast.FieldProperty {
	if len(dst) == 0 && len(src) == 0 {
		return nil
	}
	out := make(map[string]esast.FieldProperty, len(dst)+len(src))
	cloneEntry := func(fp esast.FieldProperty) esast.FieldProperty {
		cp := deepCloneFieldProperty(fp)
		if len(fp.Fields) > 0 {
			cp.Fields = make(map[string]esast.FieldProperty, len(fp.Fields))
			for fk, fv := range fp.Fields {
				cp.Fields[fk] = deepCloneFieldProperty(fv)
			}
		}
		return cp
	}
	for k, v := range dst {
		out[k] = cloneEntry(v)
	}
	for k, v := range src {
		out[k] = cloneEntry(v)
	}
	return out
}

var knownESFieldTypes = map[string]bool{
	"keyword":                 true,
	"constant_keyword":        true,
	"counted_keyword":         true,
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

// ValidateSemver reports whether s is a valid SemVer 2.0.0 version string
// (MAJOR.MINOR.PATCH[-prerelease][+build], with no leading zeros on multi-digit
// numeric core parts or purely-numeric pre-release identifiers).
func ValidateSemver(s string) bool {
	if len(s) == 0 {
		return false
	}
	isIdentChar := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-'
	}
	isAllDigits := func(part string) bool {
		if len(part) == 0 {
			return false
		}
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
		return true
	}
	if plusIdx := strings.IndexByte(s, '+'); plusIdx >= 0 {
		build := s[plusIdx+1:]
		s = s[:plusIdx]
		if len(build) == 0 {
			return false
		}
		for _, ident := range strings.Split(build, ".") {
			if len(ident) == 0 {
				return false
			}
			for i := 0; i < len(ident); i++ {
				if !isIdentChar(ident[i]) {
					return false
				}
			}
		}
	}
	if dashIdx := strings.IndexByte(s, '-'); dashIdx >= 0 {
		pre := s[dashIdx+1:]
		s = s[:dashIdx]
		if len(pre) == 0 {
			return false
		}
		for _, ident := range strings.Split(pre, ".") {
			if len(ident) == 0 {
				return false
			}
			for i := 0; i < len(ident); i++ {
				if !isIdentChar(ident[i]) {
					return false
				}
			}
			if isAllDigits(ident) && len(ident) > 1 && ident[0] == '0' {
				return false
			}
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !isAllDigits(part) {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		if n, err := strconv.ParseInt(part, 10, 64); err != nil || n < 0 {
			return false
		}
	}
	return true
}

func isValidCartesianPointValue(val any) bool {
	checkFinite := func(x, y float64) bool {
		return !math.IsNaN(x) && !math.IsInf(x, 0) && !math.IsNaN(y) && !math.IsInf(y, 0)
	}
	switch tv := val.(type) {
	case map[string]any:
		if coords, hasCoords := tv["coordinates"]; hasCoords {
			if tStr, _ := tv["type"].(string); strings.EqualFold(strings.TrimSpace(tStr), "Point") {
				if arr, okArr := coords.([]any); okArr && len(arr) == 2 {
					x, okX := parseGeoFloatElem(arr[0])
					y, okY := parseGeoFloatElem(arr[1])
					return okX && okY && checkFinite(x, y)
				}
			}
			return false
		}
		rawX, hasX := tv["x"]
		rawY, hasY := tv["y"]
		if !hasX || !hasY {
			return false
		}
		for k := range tv {
			if k != "x" && k != "y" {
				return false
			}
		}
		x, okX := parseGeoFloatElem(rawX)
		y, okY := parseGeoFloatElem(rawY)
		return okX && okY && checkFinite(x, y)
	case []any:
		if len(tv) != 2 {
			return false
		}
		if !isGeoNumericElem(tv[0]) || !isGeoNumericElem(tv[1]) {
			return false
		}
		x, okX := parseGeoFloatElem(tv[0])
		y, okY := parseGeoFloatElem(tv[1])
		return okX && okY && checkFinite(x, y)
	case string:
		str := strings.TrimSpace(tv)
		if str == "" {
			return false
		}
		if strings.HasPrefix(strings.ToUpper(str), "POINT") {
			openIdx := strings.IndexByte(str, '(')
			closeIdx := strings.LastIndexByte(str, ')')
			if openIdx > 0 && closeIdx > openIdx && strings.TrimSpace(str[closeIdx+1:]) == "" {
				fields := strings.Fields(str[openIdx+1 : closeIdx])
				if len(fields) == 2 {
					x, err1 := strconv.ParseFloat(fields[0], 64)
					y, err2 := strconv.ParseFloat(fields[1], 64)
					return err1 == nil && err2 == nil && checkFinite(x, y)
				}
			}
			return false
		}
		if strings.Contains(str, ",") {
			parts := strings.Split(str, ",")
			if len(parts) != 2 {
				return false
			}
			x, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			y, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			return err1 == nil && err2 == nil && checkFinite(x, y)
		}
		return false
	default:
		return false
	}
}

func validateNullValueForField(fullPath, fType string, prop esast.FieldProperty) error {
	switch fType {
	case "", "text", "match_only_text", "annotated-text", "annotated_text", "search_as_you_type",
		"nested", "object", "flattened", "percolator", "join", "dense_vector", "knn_vector", "sparse_vector",
		"rank_features", "rank_vector",
		"alias", "binary", "completion", "token_count", "murmur3",
		"histogram", "aggregate_metric_double", "geo_shape", "shape", "constant_keyword":
		return fmt.Errorf("mapper_parsing_exception:Mapping definition for [%s] has unsupported parameters: [null_value] is not supported on [%s]", fullPath, fType)
	}
	if fType == "rank_feature" {
		nv, err := prop.RankFeatureNullValue()
		if err != nil {
			return err
		}
		if nv != nil && *nv <= 0 {
			return esWireError(fmt.Sprintf("illegal_argument_exception: [null_value] must be a positive normal float for field of type [rank_feature], got [%v]", *nv))
		}
		return nil
	}
	if IsRangeFieldType(fType) {
		return fmt.Errorf("mapper_parsing_exception:Mapping definition for [%s] has unsupported parameters: [null_value] is not supported on [%s]", fullPath, fType)
	}
	if fType == "geo_point" {
		if _, _, _, ok := parseAndFormatGeoPointValue(prop.NullValue); !ok {
			return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [geo_point] field [%s]", fullPath)
		}
		return nil
	}
	if fType == "point" {
		if !isValidCartesianPointValue(prop.NullValue) {
			return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [point] field [%s]", fullPath)
		}
		return nil
	}
	switch prop.NullValue.(type) {
	case map[string]any, []any, []string:
		return fmt.Errorf("mapper_parsing_exception: [null_value] on field [%s] must be a scalar value", fullPath)
	}
	switch fType {
	case "keyword", "wildcard", "passthrough":
		return nil
	case "boolean":
		if prop.Coerce != nil && !*prop.Coerce {
			if _, ok := prop.NullValue.(bool); !ok {
				return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [boolean] field [%s]", fullPath)
			}
			return nil
		}
		switch v := prop.NullValue.(type) {
		case bool:
			return nil
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "false":
				return nil
			}
		}
		return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [boolean] field [%s]", fullPath)
	case "ip":
		s, ok := prop.NullValue.(string)
		if !ok || net.ParseIP(strings.TrimSpace(s)) == nil {
			return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [ip] field [%s]", fullPath)
		}
		return nil
	case "version":
		s, ok := prop.NullValue.(string)
		if !ok || !ValidateSemver(s) {
			return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [version] field [%s]", fullPath)
		}
		return nil
	case "date", "date_nanos":
		if _, isBool := prop.NullValue.(bool); isBool {
			return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [%s] field [%s]", fType, fullPath)
		}
		if s, isStr := prop.NullValue.(string); isStr {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [%s] field [%s]", fType, fullPath)
			}
			if strings.TrimSpace(prop.Format) == "" {
				if fType == "date_nanos" {
					if _, ok := ParseESDateWithFormatToEpochNanos(s, "", time.Now().UTC()); !ok {
						return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [%s] field [%s]", fType, fullPath)
					}
					return nil
				}
				if _, ok := ParseESDateToEpochMillis(s, time.Now().UTC()); !ok {
					return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [%s] field [%s]", fType, fullPath)
				}
				return nil
			}
		}
	case "long":
		if s, isStr := prop.NullValue.(string); isStr {
			trimmed := strings.TrimSpace(s)
			if trimmed == "" || (!strings.ContainsAny(trimmed, ".eE") && func() bool {
				_, err := strconv.ParseInt(trimmed, 10, 64)
				return err != nil
			}()) {
				return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [long] field [%s]", fullPath)
			}
		}
	}
	tmpB := FieldBinding{
		ESFieldPath:    fullPath,
		ESType:         fType,
		DorisType:      mapESTypeToDoris(fType),
		Format:         prop.Format,
		Locale:         prop.Locale,
		NormalizerName: prop.Normalizer,
		Coerce:         prop.Coerce,
		ScalingFactor:  prop.ScalingFactor,
	}
	if coerceScalarBindingForDoris(prop.NullValue, tmpB, time.Now().UTC()) == nil {
		return fmt.Errorf("mapper_parsing_exception: failed to parse [null_value] on [%s] field [%s]", fType, fullPath)
	}
	return nil
}

func validateSingleFieldProperty(fullPath, fType string, prop esast.FieldProperty) error {
	if fType != "" && !knownESFieldTypes[fType] {
		return fmt.Errorf("mapper_parsing_exception: No handler for type [%s] declared on field [%s]", prop.Type, fullPath)
	}
	if len(prop.Meta) > 0 {
		if err := esast.ValidateFieldMetaStringMap(prop.Meta); err != nil {
			return err
		}
	}
	if err := validateCompletionContextsMapping(fullPath, fType, prop.Contexts); err != nil {
		return err
	}
	if fType == "aggregate_metric_double" {
		if err := validateAggregateMetricDoubleProperty(fullPath, prop); err != nil {
			return err
		}
	}
	if fType == "alias" {
		if len(prop.Properties) > 0 || len(prop.Fields) > 0 {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters (cannot have sub-properties or multi-fields)", fullPath)
		}
		if prop.CopyTo != nil {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [copy_to] is not supported on [alias]", fullPath)
		}
		if prop.Dynamic != nil || prop.Subobjects != nil || prop.Enabled != nil ||
			prop.Index != nil || prop.DocValues != nil || prop.Store != nil ||
			prop.Value != nil || prop.Script != nil || prop.OnScriptError != "" ||
			prop.IncludeInParent != nil || prop.IncludeInRoot != nil ||
			prop.Analyzer != "" || prop.SearchAnalyzer != "" || prop.Normalizer != "" ||
			prop.Format != "" || prop.Locale != "" || prop.TimeZone != "" ||
			prop.Dims != 0 || prop.Dimension != 0 || prop.Similarity != "" || prop.ElementType != "" ||
			prop.MultiValued || prop.UpgradedArray ||
			prop.NullValue != nil || prop.IgnoreAbove != 0 ||
			prop.IgnoreMalformed != nil || prop.Coerce != nil || prop.ScalingFactor != 0 ||
			prop.Meta != nil || prop.IndexPrefixes != nil || prop.IndexPhrases != nil ||
			prop.IndexOptions != nil || prop.Norms != nil || prop.Boost != nil ||
			prop.EagerGlobalOrdinals != nil || prop.Fielddata != nil ||
			prop.SplitQueriesOnWhitespace != nil || prop.EnablePositionIncrements != nil ||
			prop.PositiveScoreImpact != nil || prop.MaxShingleSize != nil || prop.DepthLimit != nil ||
			prop.Relations != nil {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters", fullPath)
		}
	}
	if prop.IncludeInParent != nil && fType != "nested" {
		return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [include_in_parent : %v]", fullPath, *prop.IncludeInParent)
	}
	if prop.IncludeInRoot != nil && fType != "nested" {
		return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [include_in_root : %v]", fullPath, *prop.IncludeInRoot)
	}
	if _, err := esast.ValidateOnScriptError(prop.OnScriptError); err != nil {
		return err
	}
	if prop.OnScriptError != "" && prop.Script == nil {
		return fmt.Errorf("mapper_parsing_exception: [on_script_error] cannot be set without [script] on field [%s]", fullPath)
	}
	if prop.Script != nil {
		switch sv := prop.Script.(type) {
		case string:
			if strings.TrimSpace(sv) == "" {
				return fmt.Errorf("mapper_parsing_exception: field [%s] script cannot be empty", fullPath)
			}
		case map[string]any:
			src, hasSrc := sv["source"]
			id, hasID := sv["id"]
			if (!hasSrc && !hasID) || (hasSrc && strings.TrimSpace(fmt.Sprintf("%v", src)) == "") || (hasID && strings.TrimSpace(fmt.Sprintf("%v", id)) == "") {
				return fmt.Errorf("mapper_parsing_exception: field [%s] script requires non-empty [source] or [id]", fullPath)
			}
		default:
			return fmt.Errorf("mapper_parsing_exception: field [%s] invalid [script]", fullPath)
		}
	}
	if prop.PositiveScoreImpact != nil && fType != "rank_feature" && fType != "rank_features" {
		return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [positive_score_impact : %v]", fullPath, *prop.PositiveScoreImpact)
	}
	if prop.MaxShingleSize != nil {
		if fType != "search_as_you_type" {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [max_shingle_size : %d]", fullPath, *prop.MaxShingleSize)
		}
		if *prop.MaxShingleSize < 2 || *prop.MaxShingleSize > 4 {
			return fmt.Errorf("mapper_parsing_exception: [max_shingle_size] must be between 2 and 4 inclusive for field [%s], got [%d]", fullPath, *prop.MaxShingleSize)
		}
	}
	if prop.DepthLimit != nil {
		if fType != "flattened" {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [depth_limit : %d]", fullPath, *prop.DepthLimit)
		}
		if *prop.DepthLimit < 1 {
			return fmt.Errorf("mapper_parsing_exception: [depth_limit] must be >= 1 for field [%s], got [%d]", fullPath, *prop.DepthLimit)
		}
	}
	if prop.Subobjects != nil && fType != "" && fType != "object" {
		return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters:  [subobjects : %v]", fullPath, *prop.Subobjects)
	}
	if prop.Priority != nil {
		if fType != "passthrough" {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters:  [priority : %d]", fullPath, *prop.Priority)
		}
		if *prop.Priority < 0 {
			return fmt.Errorf("mapper_parsing_exception: [priority] must be >= 0 for field [%s], got [%d]", fullPath, *prop.Priority)
		}
	}
	if err := validateDynamicModeVal(prop.Dynamic, fullPath); err != nil {
		return err
	}
	if fType == "scaled_float" {
		if prop.ScalingFactor <= 0.0 || math.IsNaN(prop.ScalingFactor) || math.IsInf(prop.ScalingFactor, 0) {
			return fmt.Errorf("mapper_parsing_exception: [scaling_factor] must be > 0.0 for [scaled_float] field [%s]", fullPath)
		}
	} else if prop.ScalingFactor != 0 {
		if prop.ScalingFactor < 0 || math.IsNaN(prop.ScalingFactor) || math.IsInf(prop.ScalingFactor, 0) {
			return fmt.Errorf("mapper_parsing_exception: [scaling_factor] must be > 0.0 for field [%s]", fullPath)
		}
		if fType != "" {
			return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [scaling_factor : %v]", fullPath, prop.ScalingFactor)
		}
	}
	if fType == "constant_keyword" && prop.Value != nil {
		switch prop.Value.(type) {
		case map[string]any, []any:
			return fmt.Errorf("mapper_parsing_exception: [constant_keyword] field [%s] [value] must be a scalar value", fullPath)
		}
	}
	if fType == "dense_vector" || fType == "knn_vector" {
		if prop.Dims < 0 || prop.Dimension < 0 {
			return fmt.Errorf("mapper_parsing_exception: [%s] field [%s] [dims] cannot be negative", fType, fullPath)
		}
		if prop.ExplicitDims && prop.EffectiveDims() <= 0 {
			return fmt.Errorf("mapper_parsing_exception: [%s] field [%s] requires [dims] in [1, 4096], got [%d]", fType, fullPath, prop.EffectiveDims())
		}
		elemType := strings.ToLower(strings.TrimSpace(prop.ElementType))
		switch elemType {
		case "", "float", "byte", "bit":
		default:
			return fmt.Errorf("mapper_parsing_exception: unknown [element_type] [%s] on [%s] field [%s]", prop.ElementType, fType, fullPath)
		}
		effElemType := elemType
		if effElemType == "" {
			effElemType = "float"
		}
		isNotIndexed := prop.Index != nil && !*prop.Index
		dims := prop.EffectiveDims()
		sim := strings.ToLower(strings.TrimSpace(prop.Similarity))
		if isNotIndexed {
			if sim != "" {
				return fmt.Errorf("mapper_parsing_exception: Field [similarity] can only be specified for a field of type [%s] when it is indexed", fType)
			}
			if prop.IndexOptions != nil {
				return fmt.Errorf("mapper_parsing_exception: Field [index_options] can only be specified for a field of type [%s] when it is indexed", fType)
			}
			if dims != 0 && (dims < 1 || dims > 4096) {
				return fmt.Errorf("mapper_parsing_exception: [%s] field [%s] requires [dims] in [1, 4096], got [%d]", fType, fullPath, dims)
			}
			if effElemType == "bit" && dims != 0 && dims%8 != 0 {
				return fmt.Errorf("mapper_parsing_exception: [bit] vectors require [dims] to be a multiple of 8 on field [%s], got [%d]", fullPath, dims)
			}
		} else {
			if dims != 0 && (dims < 1 || dims > 4096) {
				return fmt.Errorf("mapper_parsing_exception: [%s] field [%s] requires [dims] in [1, 4096], got [%d]", fType, fullPath, dims)
			}
			if effElemType == "bit" && dims != 0 && dims%8 != 0 {
				return fmt.Errorf("mapper_parsing_exception: [bit] vectors require [dims] to be a multiple of 8 on field [%s], got [%d]", fullPath, dims)
			}
			switch sim {
			case "", "l2_norm", "dot_product", "cosine", "max_inner_product":
			default:
				return fmt.Errorf("mapper_parsing_exception: unknown [similarity] [%s] on [%s] field [%s]", prop.Similarity, fType, fullPath)
			}
			if sim == "dot_product" && effElemType == "bit" {
				return fmt.Errorf("mapper_parsing_exception: [dot_product] similarity cannot be used with [bit] element_type on field [%s]", fullPath)
			}
			if effElemType == "bit" && (sim == "cosine" || sim == "max_inner_product") {
				return fmt.Errorf("mapper_parsing_exception: [%s] similarity cannot be used with [bit] element_type on field [%s]", prop.Similarity, fullPath)
			}
			if _, err := ValidateDenseVectorIndexOptions(fullPath, fType, effElemType, dims, prop.IndexOptions); err != nil {
				return err
			}
		}
	}
	if err := ValidateTSDBFieldParams(fullPath, fType, prop); err != nil {
		return err
	}
	if prop.SyntheticSourceKeep != "" {
		switch prop.SyntheticSourceKeep {
		case "none", "all", "arrays":
		default:
			return fmt.Errorf("mapper_parsing_exception: Invalid [synthetic_source_keep] value [%s] for field [%s]", prop.SyntheticSourceKeep, fullPath)
		}
		if fType != "text" && fType != "annotated-text" && fType != "annotated_text" {
			return fmt.Errorf("mapper_parsing_exception: [synthetic_source_keep] is not supported for [%s] field [%s]", fType, fullPath)
		}
	}
	if prop.NullValue != nil {
		if err := validateNullValueForField(fullPath, fType, prop); err != nil {
			return err
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
		_ = targets
	}
	return nil
}

var validRuntimeFieldTypes = map[string]bool{
	"boolean":   true,
	"composite": true,
	"date":      true,
	"double":    true,
	"geo_point": true,
	"geo_shape": true,
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
				case "mapping", "match", "unmatch", "match_pattern", "path_match", "path_unmatch", "match_mapping_type", "unmatch_mapping_type":
				default:
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has unknown parameter [%s]", tmplName, k)
				}
			}
			mmtFirst := ""
			mmtIsObjectOrWildcard := false
			if rawMMT, hasMMT := defMap["match_mapping_type"]; hasMMT && rawMMT != nil {
				validateMMT := func(s string) error {
					norm := strings.ToLower(strings.TrimSpace(s))
					if !validDynamicMatchMappingTypes[norm] {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid [match_mapping_type] [%s]", tmplName, s)
					}
					if mmtFirst == "" {
						mmtFirst = norm
					}
					if norm == "object" || norm == "*" {
						mmtIsObjectOrWildcard = true
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
			if rawUMMT, hasUMMT := defMap["unmatch_mapping_type"]; hasUMMT && rawUMMT != nil {
				validateUMMT := func(s string) error {
					norm := strings.ToLower(strings.TrimSpace(s))
					if !validDynamicMatchMappingTypes[norm] {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid [unmatch_mapping_type] [%s]", tmplName, s)
					}
					return nil
				}
				switch v := rawUMMT.(type) {
				case string:
					if err := validateUMMT(v); err != nil {
						return err
					}
				case []string:
					if len(v) == 0 {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [unmatch_mapping_type] cannot be empty", tmplName)
					}
					for _, item := range v {
						if err := validateUMMT(item); err != nil {
							return err
						}
					}
				case []any:
					if len(v) == 0 {
						return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [unmatch_mapping_type] cannot be empty", tmplName)
					}
					for _, item := range v {
						s, ok := item.(string)
						if !ok {
							return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [unmatch_mapping_type] elements must be strings", tmplName)
						}
						if err := validateUMMT(s); err != nil {
							return err
						}
					}
				default:
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [unmatch_mapping_type] must be a string or array of strings", tmplName)
				}
			}
			for _, patKey := range []string{"match", "unmatch", "path_match", "path_unmatch"} {
				if rawPat, hasPat := defMap[patKey]; hasPat && rawPat != nil {
					if _, err := parseDynamicTemplatePatternList(rawPat, tmplName, patKey, isRegex); err != nil {
						return err
					}
				}
			}
			rawMapping, hasMapping := defMap["mapping"]
			mappingMap, ok := rawMapping.(map[string]any)
			if !hasMapping || !ok {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] requires a [mapping] object", tmplName)
			}
			repType := "keyword"
			switch mmtFirst {
			case "double":
				repType = "double"
			case "long":
				repType = "long"
			case "boolean":
				repType = "boolean"
			case "date":
				repType = "date"
			case "object":
				repType = "object"
			case "binary":
				repType = "binary"
			}
			clonedMapping := make(map[string]any, len(mappingMap))
			for mk, mv := range mappingMap {
				switch mk {
				case "match_mapping_type", "unmatch_mapping_type", "match", "unmatch", "path_match", "path_unmatch", "match_pattern":
					continue
				}
				clonedMapping[mk] = mv
			}
			if mmtFirst == "" {
				if rawMMT, hasMMT := mappingMap["match_mapping_type"]; hasMMT && rawMMT != nil {
					if mmtStr, okS := rawMMT.(string); okS {
						norm := strings.ToLower(strings.TrimSpace(mmtStr))
						if !validDynamicMatchMappingTypes[norm] {
							return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid [match_mapping_type] [%s]", tmplName, mmtStr)
						}
						mmtFirst = norm
						if norm == "object" || norm == "*" {
							mmtIsObjectOrWildcard = true
						}
					}
				}
			}
			rawType, hasType := clonedMapping["type"]
			if hasType && rawType != nil {
				typeStr, ok := rawType.(string)
				if !ok || strings.TrimSpace(typeStr) == "" {
					return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [mapping.type] must be a non-empty string", tmplName)
				}
				if strings.TrimSpace(typeStr) == "{dynamic_type}" {
					clonedMapping["type"] = repType
				}
			} else if clonedMapping["properties"] == nil && !mmtIsObjectOrWildcard {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [mapping] requires a [type]", tmplName)
			}
			b, err := json.Marshal(clonedMapping)
			if err != nil {
				return fmt.Errorf("mapper_parsing_exception: invalid mapping in dynamic template [%s]: %w", tmplName, err)
			}
			fp, err := esast.UnmarshalFieldPropertyStrict(b)
			if err != nil {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has unsupported or invalid mapping parameter: %w", tmplName, err)
			}
			substituteDynamicTemplatePlaceholders(&fp, tmplName, repType)
			if err := validateSingleFieldProperty(tmplName, strings.ToLower(strings.TrimSpace(fp.Type)), fp); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseMappingSourcePatternSlice(raw any, fieldName string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		return []string{v}, nil
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			s, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("mapper_parsing_exception: [_source.%s] must be an array of strings", fieldName)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("mapper_parsing_exception: [_source.%s] must be a string or array of strings", fieldName)
	}
}

type normalizedMappingSource struct {
	mode               string
	synthetic          bool
	hasExplicitMode    bool
	hasExplicitEnabled bool
	enabled            bool
	includes           []string
	excludes           []string
	hasCompress        bool
	compress           bool
	compressThreshold  string
}

func (n normalizedMappingSource) effectiveMode() string {
	if !n.enabled {
		return "disabled"
	}
	if n.mode != "" {
		return n.mode
	}
	return "stored"
}

func parseTSDBBoolOptionR61(v any) (bool, bool) {
	switch tv := v.(type) {
	case bool:
		return tv, true
	case string:
		s := strings.ToLower(strings.TrimSpace(tv))
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
	}
	return false, false
}

func validateDataStreamTimestampSpec(raw any) error {
	if raw == nil {
		return nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("mapper_parsing_exception: Failed to parse mapping: [_data_stream_timestamp] config must be an object")
	}
	for k, v := range obj {
		if k != "enabled" {
			return fmt.Errorf("mapper_parsing_exception: Failed to parse mapping: [_data_stream_timestamp] does not support parameter [%s]", k)
		}
		if _, ok := parseTSDBBoolOptionR61(v); !ok {
			return fmt.Errorf("mapper_parsing_exception: Failed to parse value [%v] as only [true] or [false] are allowed.", v) //nolint:staticcheck // Exact Elasticsearch error message
		}
	}
	return nil
}

func validateAndNormalizeMappingSourceSpec(src map[string]any) (normalizedMappingSource, error) {
	norm := normalizedMappingSource{mode: "stored", enabled: true}
	if src == nil {
		return norm, nil
	}
	for k, v := range src {
		switch k {
		case "mode":
			s, ok := v.(string)
			if !ok {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source.mode] must be a string, got %T", v)
			}
			modeLower := strings.ToLower(strings.TrimSpace(s))
			switch modeLower {
			case "synthetic", "stored", "disabled":
				norm.mode = modeLower
				norm.hasExplicitMode = true
			default:
				return norm, fmt.Errorf("mapper_parsing_exception: illegal [_source] mode [%s]; must be one of [disabled, stored, synthetic]", s)
			}
		case "enabled":
			b, ok := v.(bool)
			if !ok {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source.enabled] must be a boolean, got %T", v)
			}
			norm.enabled = b
			norm.hasExplicitEnabled = true
		case "includes":
			inc, err := parseMappingSourcePatternSlice(v, "includes")
			if err != nil {
				return norm, err
			}
			norm.includes = inc
		case "excludes":
			exc, err := parseMappingSourcePatternSlice(v, "excludes")
			if err != nil {
				return norm, err
			}
			norm.excludes = exc
		case "compress":
			b, ok := v.(bool)
			if !ok {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source.compress] must be a boolean, got %T", v)
			}
			norm.hasCompress = true
			norm.compress = b
		case "compress_threshold":
			s, ok := v.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source.compress_threshold] must be a non-empty byte-size string")
			}
			norm.compressThreshold = strings.TrimSpace(s)
		default:
			return norm, fmt.Errorf("mapper_parsing_exception: Root mapping definition has unsupported parameters in [_source]: [%s]", k)
		}
	}
	if norm.hasExplicitMode {
		if norm.mode == "disabled" {
			if norm.hasExplicitEnabled && norm.enabled {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source] cannot set [enabled: true] when [mode] is [disabled]")
			}
			norm.enabled = false
		} else {
			if norm.hasExplicitEnabled && !norm.enabled {
				return norm, fmt.Errorf("mapper_parsing_exception: [_source] cannot set [enabled: false] when [mode] is [%s]", norm.mode)
			}
			norm.enabled = true
			if norm.mode == "synthetic" {
				norm.synthetic = true
			}
		}
	} else if !norm.enabled {
		norm.mode = "disabled"
	}
	if !norm.enabled && (len(norm.includes) > 0 || len(norm.excludes) > 0) {
		return norm, fmt.Errorf("mapper_parsing_exception: [_source] cannot specify [includes] or [excludes] when [enabled] is false")
	}
	return norm, nil
}

func stringSlicesEqualExact(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ValidateMappingLimits enforces `index.mapping.total_fields.limit`, `nested_fields.limit`,
// `depth.limit`, and `field_name_length.limit` against `spec`.
func ValidateMappingLimits(s *IndexSchema, spec *esast.MappingSpec) error {
	if spec == nil {
		return nil
	}
	maxTotal := 1000
	maxNested := 50
	maxDepth := 20
	maxFieldNameLen := 0
	if s != nil {
		if s.MaxTotalFields > 0 {
			maxTotal = s.MaxTotalFields
		}
		if s.HasExplicitNestedLimit || s.MaxNestedFields > 0 {
			maxNested = s.MaxNestedFields
		}
		if s.MaxDepth > 0 {
			maxDepth = s.MaxDepth
		}
		if s.MaxFieldNameLength > 0 {
			maxFieldNameLen = s.MaxFieldNameLength
		}
	}
	totalFields := 0
	nestedFields := 0
	checkFieldName := func(name string) error {
		if name == "" || strings.TrimSpace(name) == "" {
			return fmt.Errorf("mapper_parsing_exception: Field name cannot be an empty string")
		}
		for _, seg := range strings.Split(name, ".") {
			if seg == "" {
				return fmt.Errorf("mapper_parsing_exception: Field name cannot be an empty string")
			}
			if maxFieldNameLen > 0 && len(seg) > maxFieldNameLen {
				return fmt.Errorf("illegal_argument_exception: Field name [%s] is longer than the limit of [%d] characters", seg, maxFieldNameLen)
			}
		}
		if maxFieldNameLen > 0 && len(name) > maxFieldNameLen {
			return fmt.Errorf("illegal_argument_exception: Field name [%s] is longer than the limit of [%d] characters", name, maxFieldNameLen)
		}
		return nil
	}
	for rtName := range spec.Runtime {
		if err := checkFieldName(rtName); err != nil {
			return err
		}
		effDepth := 1 + strings.Count(rtName, ".")
		if maxDepth > 0 && effDepth > maxDepth {
			return fmt.Errorf("illegal_argument_exception: Limit of mapping depth [%d] has been exceeded", maxDepth)
		}
		totalFields++
	}
	var walk func(props map[string]esast.FieldProperty, depth int) error
	walk = func(props map[string]esast.FieldProperty, depth int) error {
		for k, prop := range props {
			if err := checkFieldName(k); err != nil {
				return err
			}
			effDepth := depth + strings.Count(k, ".")
			if maxDepth > 0 && effDepth > maxDepth {
				return fmt.Errorf("illegal_argument_exception: Limit of mapping depth [%d] has been exceeded", maxDepth)
			}
			totalFields++
			if strings.EqualFold(strings.TrimSpace(prop.Type), "nested") {
				nestedFields++
				if nestedFields > maxNested {
					return fmt.Errorf("illegal_argument_exception: Limit of nested fields [%d] has been exceeded", maxNested)
				}
			}
			for fk := range prop.Fields {
				if err := checkFieldName(fk); err != nil {
					return err
				}
				totalFields++
			}
			if len(prop.Properties) > 0 {
				if err := walk(prop.Properties, effDepth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(spec.Properties, 1); err != nil {
		return err
	}
	if totalFields > maxTotal {
		if s != nil && s.IgnoreDynamicBeyondLimit && s.RawMapping != nil && s.RawMapping != spec && CountTotalMappingFields(s.RawMapping) <= maxTotal {
			capDynamicPropsInPlace(s.RawMapping, spec, maxTotal)
			totalFields = CountTotalMappingFields(spec)
		}
		if totalFields > maxTotal {
			return fmt.Errorf("illegal_argument_exception: Limit of total fields [%d] has been exceeded", maxTotal)
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
	if m.Source != nil {
		if _, err := validateAndNormalizeMappingSourceSpec(m.Source); err != nil {
			return err
		}
	}
	if err := validateDataStreamTimestampSpec(m.DataStreamTimestamp); err != nil {
		return err
	}
	if m.Size != nil {
		if _, _, err := ValidateSizeMetaSpec(m.Size); err != nil {
			return err
		}
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
		if rtProp.TimeSeriesDimension != nil {
			return fmt.Errorf("mapper_parsing_exception: unknown parameter [time_series_dimension] on runtime field [%s] of type [%s]", rtName, rtProp.Type)
		}
		if rtProp.TimeSeriesDimensions != nil {
			return fmt.Errorf("mapper_parsing_exception: unknown parameter [time_series_dimensions] on runtime field [%s] of type [%s]", rtName, rtProp.Type)
		}
		if rtProp.TimeSeriesMetric != "" {
			return fmt.Errorf("mapper_parsing_exception: unknown parameter [time_series_metric] on runtime field [%s] of type [%s]", rtName, rtProp.Type)
		}
		if _, err := esast.ValidateOnScriptError(rtProp.OnScriptError); err != nil {
			return err
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
		if rtType == "lookup" {
			if err := validateLookupRuntimeField(rtName, rtProp); err != nil {
				return err
			}
		}
		if rtType == "composite" {
			if len(rtProp.Fields) == 0 {
				return fmt.Errorf("mapper_parsing_exception: composite runtime field [%s] requires non-empty [fields]", rtName)
			}
			for subName, subProp := range rtProp.Fields {
				if strings.TrimSpace(subName) == "" {
					return fmt.Errorf("mapper_parsing_exception: composite runtime sub-field name in [%s] cannot be empty", rtName)
				}
				subType := strings.ToLower(strings.TrimSpace(subProp.Type))
				if !validRuntimeFieldTypes[subType] || subType == "composite" || subType == "lookup" {
					return fmt.Errorf("mapper_parsing_exception: unsupported sub-field type [%s] in composite runtime field [%s.%s]", subProp.Type, rtName, subName)
				}
				if subProp.Script != nil {
					return fmt.Errorf("mapper_parsing_exception: sub-field [%s.%s] of composite runtime field cannot define its own [script]", rtName, subName)
				}
			}
		}
	}
	if err := validateDynamicTemplatesSpec(m.DynamicTemplates); err != nil {
		return err
	}
	if len(m.Properties) == 0 {
		return ValidateSyntheticSourceMapping(m)
	}
	expandedProps, err := ExpandDottedPropertiesWithSubobjects(m.Properties, m.Subobjects != nil && !*m.Subobjects)
	if err != nil {
		return err
	}
	m.Properties = expandedProps
	if err := ValidateSyntheticSourceMapping(m); err != nil {
		return err
	}
	allTypes := make(map[string]string)
	for rtName, rtProp := range m.Runtime {
		rtType := strings.ToLower(strings.TrimSpace(rtProp.Type))
		allTypes[rtName] = rtType
		if rtType == "lookup" {
			if err := validateLookupRuntimeField(rtName, rtProp); err != nil {
				return err
			}
		}
		if rtType == "composite" {
			for subName, subProp := range rtProp.Fields {
				allTypes[rtName+"."+subName] = strings.ToLower(strings.TrimSpace(subProp.Type))
			}
		}
	}
	aliasTargets := make(map[string]string)
	aliasPrefixes := make(map[string]string)
	type copyToRef struct {
		source string
		prefix string
		target string
	}
	var copyToRefs []copyToRef

	var collect func(props map[string]esast.FieldProperty, prefix string, inSubobjectsFalse bool, inNested bool) error
	tsdbDims := make(map[string]bool)
	tsdbMetrics := make(map[string]bool)
	passthroughPriorities := make(map[int][]string)
	collect = func(props map[string]esast.FieldProperty, prefix string, inSubobjectsFalse bool, inNested bool) error {
		for k, prop := range props {
			fullPath := k
			if prefix != "" {
				fullPath = prefix + "." + k
			}
			fType := strings.ToLower(strings.TrimSpace(prop.Type))
			if fType == "" && (len(prop.Properties) > 0 || prop.Enabled != nil || prop.Dynamic != nil || prop.Subobjects != nil) {
				fType = "object"
			}
			childNested := inNested || fType == "nested"
			if childNested && prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension {
				return fmt.Errorf("mapper_parsing_exception: time_series_dimension can't be configured in nested field [%s]", fullPath)
			}
			if prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension {
				tsdbDims[fullPath] = true
			}
			if prop.TimeSeriesMetric != "" {
				tsdbMetrics[fullPath] = true
			}
			if fType == "passthrough" && prop.Priority != nil {
				passthroughPriorities[*prop.Priority] = append(passthroughPriorities[*prop.Priority], fullPath)
			}
			if inSubobjectsFalse {
				isDisabledObj := (fType == "" || fType == "object") && prop.Enabled != nil && !*prop.Enabled
				if len(prop.Properties) > 0 {
					return fmt.Errorf("mapper_parsing_exception: Field [%s] cannot have sub-properties because parent has [subobjects: false]", fullPath)
				}
				if fType == "nested" || ((fType == "" || fType == "object") && !isDisabledObj) {
					return fmt.Errorf("mapper_parsing_exception: Field [%s] of type [%s] is not allowed inside [subobjects: false]", fullPath, fType)
				}
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
				childSubobjectsFalse := inSubobjectsFalse || (prop.Subobjects != nil && !*prop.Subobjects)
				if err := collect(prop.Properties, fullPath, childSubobjectsFalse, childNested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	rootSubobjectsFalse := m.Subobjects != nil && !*m.Subobjects
	if err := collect(m.Properties, "", rootSubobjectsFalse, false); err != nil {
		return err
	}
	if len(passthroughPriorities) > 0 {
		prios := make([]int, 0, len(passthroughPriorities))
		for p := range passthroughPriorities {
			prios = append(prios, p)
		}
		sort.Ints(prios)
		for _, p := range prios {
			paths := passthroughPriorities[p]
			if len(paths) > 1 {
				sort.Strings(paths)
				return fmt.Errorf("mapper_parsing_exception: field [%s] has a conflicting param [priority: %d] with field [%s]", paths[1], p, paths[0])
			}
		}
	}
	for rtName := range m.Runtime {
		if tsdbDims[rtName] {
			return fmt.Errorf("illegal_argument_exception: Field [%s] attempted to shadow a time_series_dimension", rtName)
		}
		if tsdbMetrics[rtName] {
			return fmt.Errorf("illegal_argument_exception: Field [%s] attempted to shadow a time_series_metric", rtName)
		}
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
		if !exists {
			switch target {
			case "_id", "_index", "_routing", "_ignored":
				exists = true
				targetType = "keyword"
			case "_version", "_seq_no", "_primary_term":
				exists = true
				targetType = "long"
			case "_size":
				if IsSizeMetadataEnabled(m) {
					exists = true
					targetType = "long"
				}
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
	if newSpec.Source != nil {
		newSrcNorm, err := validateAndNormalizeMappingSourceSpec(newSpec.Source)
		if err != nil {
			return err
		}
		oldSrcNorm, _ := validateAndNormalizeMappingSourceSpec(oldSpec.Source)
		oldMode := oldSrcNorm.effectiveMode()
		newMode := newSrcNorm.effectiveMode()
		if oldMode == "synthetic" && newSrcNorm.hasExplicitMode && newMode == "stored" {
			return esWireError("illegal_argument_exception: Cannot update parameter [mode] from [synthetic] to [stored]")
		}
		allowedStoredToSynthetic := oldMode == "stored" && newMode == "synthetic"
		if newSrcNorm.enabled != oldSrcNorm.enabled ||
			(newMode != oldMode && !allowedStoredToSynthetic) ||
			!stringSlicesEqualExact(newSrcNorm.includes, oldSrcNorm.includes) ||
			!stringSlicesEqualExact(newSrcNorm.excludes, oldSrcNorm.excludes) ||
			(newSrcNorm.hasCompress && newSrcNorm.compress != oldSrcNorm.compress) ||
			(newSrcNorm.compressThreshold != "" && newSrcNorm.compressThreshold != oldSrcNorm.compressThreshold) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [_source] conflicts with existing mapper")
		}
	}
	if newSpec.Size != nil {
		newSizeEn, newSizeExplicit, err := ValidateSizeMetaSpec(newSpec.Size)
		if err != nil {
			return err
		}
		if oldSpec.Size != nil {
			oldSizeEn, oldSizeExplicit, _ := ValidateSizeMetaSpec(oldSpec.Size)
			if oldSizeExplicit && newSizeExplicit && oldSizeEn != newSizeEn {
				return fmt.Errorf("illegal_argument_exception: Mapper for [_size] conflicts with existing mapper")
			}
		}
	}
	if newSpec.Subobjects != nil {
		oldEffectiveSub := true
		if oldSpec.Subobjects != nil {
			oldEffectiveSub = *oldSpec.Subobjects
		}
		if *newSpec.Subobjects != oldEffectiveSub {
			return fmt.Errorf("illegal_argument_exception: Mapper for [_doc] conflicts with existing mapper: Cannot update parameter [subobjects] from [%v] to [%v]", oldEffectiveSub, *newSpec.Subobjects)
		}
	}
	mergedSubobjects := newSpec.Subobjects
	if mergedSubobjects == nil {
		mergedSubobjects = oldSpec.Subobjects
	}
	rootSubFalse := mergedSubobjects != nil && !*mergedSubobjects
	oldProps := oldSpec.Properties
	if len(oldProps) > 0 {
		if expOld, err := ExpandDottedPropertiesWithSubobjects(oldProps, rootSubFalse); err == nil {
			oldProps = expOld
		}
	}
	newProps := newSpec.Properties
	if len(newProps) > 0 {
		expNew, err := expandDottedPropertiesWithBase(newProps, oldProps, rootSubFalse)
		if err != nil {
			return err
		}
		newProps = expNew
	}
	if err := validatePropertiesCompatibility(oldProps, newProps, ""); err != nil {
		return err
	}
	mergedDynamic := newSpec.Dynamic
	if mergedDynamic == nil {
		mergedDynamic = oldSpec.Dynamic
	}
	mergedDynTemplates := newSpec.DynamicTemplates
	if mergedDynTemplates == nil {
		mergedDynTemplates = oldSpec.DynamicTemplates
	}
	mergedSource := newSpec.Source
	if mergedSource == nil {
		mergedSource = oldSpec.Source
	}
	mergedEnabled := newSpec.Enabled
	if mergedEnabled == nil {
		mergedEnabled = oldSpec.Enabled
	}
	mergedSize := newSpec.Size
	if mergedSize == nil {
		mergedSize = oldSpec.Size
	}
	merged := &esast.MappingSpec{
		Enabled:          mergedEnabled,
		Dynamic:          mergedDynamic,
		Subobjects:       mergedSubobjects,
		Size:             mergedSize,
		Source:           mergedSource,
		Runtime:          CloneFlatRuntimeMap(oldSpec.Runtime, newSpec.Runtime),
		DynamicTemplates: mergedDynTemplates,
		Properties:       deepMergeMappingPropertiesWithSubobjects(oldProps, newProps, rootSubFalse),
	}
	return ValidateMappingSpec(merged)
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
		if oldType == "" && (len(oldProp.Properties) > 0 || oldProp.Enabled != nil || oldProp.Dynamic != nil || oldProp.Subobjects != nil) {
			oldType = "object"
		}
		newType := strings.ToLower(strings.TrimSpace(newProp.Type))
		if newType == "" && (len(newProp.Properties) > 0 || newProp.Enabled != nil || newProp.Dynamic != nil || newProp.Subobjects != nil) {
			if oldType == "nested" && newProp.Enabled == nil {
				newType = "nested"
			} else {
				newType = "object"
			}
		}
		if oldType != "" && newType != "" && oldType != newType {
			return fmt.Errorf("mapper [%s] cannot be changed from type [%s] to [%s]", fullPath, oldType, newType)
		}
		if newProp.Subobjects != nil {
			oldEffectiveSub := true
			if oldProp.Subobjects != nil {
				oldEffectiveSub = *oldProp.Subobjects
			}
			if *newProp.Subobjects != oldEffectiveSub {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [subobjects] from [%v] to [%v]", fullPath, oldEffectiveSub, *newProp.Subobjects)
			}
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
		if newProp.Priority != nil && oldProp.Priority != nil && *newProp.Priority != *oldProp.Priority {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [priority] from [%d] to [%d]", fullPath, *oldProp.Priority, *newProp.Priority)
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
		if oldType == "constant_keyword" && newProp.Value != nil {
			if oldProp.Value == nil || fmt.Sprintf("%v", oldProp.Value) != fmt.Sprintf("%v", newProp.Value) {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [value]", fullPath)
			}
		}
		if newProp.Store != nil {
			oldStore := oldProp.Store != nil && *oldProp.Store
			if *newProp.Store != oldStore {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [store]", fullPath)
			}
		}
		if newProp.Format != "" && (oldType == "date" || oldType == "date_nanos" || oldType == "date_range") {
			oldFormat := oldProp.Format
			if oldFormat == "" {
				if oldType == "date_nanos" {
					oldFormat = "strict_date_optional_time_nanos||epoch_millis"
				} else {
					oldFormat = "strict_date_optional_time||epoch_millis"
				}
			}
			if newProp.Format != oldFormat {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [format]", fullPath)
			}
		}
		oldDims := oldProp.EffectiveDims()
		newDims := newProp.EffectiveDims()
		if newDims > 0 && oldDims > 0 && oldDims != newDims {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot update parameter [dims] from [%d] to [%d] for field [%s]", fullPath, oldDims, newDims, fullPath)
		}
		if oldType == "dense_vector" || oldType == "knn_vector" {
			if err := ValidateDenseVectorUpdate(fullPath, oldProp, newProp); err != nil {
				return err
			}
		}
		if newProp.TimeSeriesDimension != nil {
			oldTSD := oldProp.TimeSeriesDimension != nil && *oldProp.TimeSeriesDimension
			if *newProp.TimeSeriesDimension != oldTSD {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [time_series_dimension] from [%v] to [%v]", fullPath, oldTSD, *newProp.TimeSeriesDimension)
			}
		}
		if newProp.TimeSeriesMetric != "" && !strings.EqualFold(newProp.TimeSeriesMetric, oldProp.TimeSeriesMetric) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [time_series_metric] from [%s] to [%s]", fullPath, oldProp.TimeSeriesMetric, newProp.TimeSeriesMetric)
		}
		if newProp.ElementType != "" && (oldType == "dense_vector" || oldType == "knn_vector") {
			oldET := strings.ToLower(strings.TrimSpace(oldProp.ElementType))
			if oldET == "" {
				oldET = "float"
			}
			if !strings.EqualFold(strings.TrimSpace(newProp.ElementType), oldET) {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [element_type] from [%s] to [%s]", fullPath, oldET, newProp.ElementType)
			}
		}
		if newProp.Similarity != "" {
			oldSim := oldProp.Similarity
			oldNotIndexed := oldProp.Index != nil && !*oldProp.Index
			if oldSim == "" && !oldNotIndexed && (oldType == "dense_vector" || oldType == "knn_vector") {
				if strings.EqualFold(strings.TrimSpace(oldProp.ElementType), "bit") {
					oldSim = "l2_norm"
				} else {
					oldSim = "cosine"
				}
			}
			if !strings.EqualFold(newProp.Similarity, oldSim) {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [similarity] from [%s] to [%s]", fullPath, oldSim, newProp.Similarity)
			}
		}
		if newProp.PositiveScoreImpact != nil && (oldType == "rank_feature" || oldType == "rank_features") {
			oldPSI := oldProp.PositiveScoreImpact == nil || *oldProp.PositiveScoreImpact
			if *newProp.PositiveScoreImpact != oldPSI {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [positive_score_impact] from [%v] to [%v]", fullPath, oldPSI, *newProp.PositiveScoreImpact)
			}
		}
		if newProp.MaxShingleSize != nil && oldType == "search_as_you_type" {
			oldMSS := 3
			if oldProp.MaxShingleSize != nil {
				oldMSS = *oldProp.MaxShingleSize
			}
			if *newProp.MaxShingleSize != oldMSS {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [max_shingle_size] from [%d] to [%d]", fullPath, oldMSS, *newProp.MaxShingleSize)
			}
		}
		if newProp.DepthLimit != nil && oldType == "flattened" {
			oldDL := 20
			if oldProp.DepthLimit != nil {
				oldDL = *oldProp.DepthLimit
			}
			if *newProp.DepthLimit != oldDL {
				return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [depth_limit] from [%d] to [%d]", fullPath, oldDL, *newProp.DepthLimit)
			}
		}
		if oldType == "completion" && len(newProp.Contexts) > 0 && !completionContextsEqual(oldProp.Contexts, newProp.Contexts) {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [contexts]", fullPath)
		}
		if oldType == "aggregate_metric_double" {
			if err := validateAggregateMetricDoubleUpdate(fullPath, oldProp, newProp); err != nil {
				return err
			}
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
	for _, saytSuffix := range []string{"._index_prefix", "._2gram", "._3gram", "._4gram"} {
		if strings.HasSuffix(cleanPath, saytSuffix) {
			candBase := strings.TrimSuffix(cleanPath, saytSuffix)
			if b, ok := s.Fields[candBase]; ok && strings.EqualFold(b.ESType, "search_as_you_type") {
				for _, allowed := range b.SearchAsYouTypeSubfields() {
					if allowed == saytSuffix {
						cleanPath = candBase
						break
					}
				}
			}
			break
		}
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
	return deepMergeMappingPropertiesWithSubobjects(dst, src, false)
}

func deepMergeMappingPropertiesWithSubobjects(
	dst, src map[string]esast.FieldProperty,
	subobjectsFalse bool,
) map[string]esast.FieldProperty {
	if len(dst) > 0 {
		if expDst, err := expandDottedPropertiesWithBase(dst, nil, subobjectsFalse); err == nil {
			dst = expDst
		}
	}
	if len(src) > 0 {
		if expSrc, err := expandDottedPropertiesWithBase(src, dst, subobjectsFalse); err == nil {
			src = expSrc
		}
	}
	out := make(map[string]esast.FieldProperty, len(dst)+len(src))
	for k, v := range dst {
		copied := deepCloneFieldProperty(v)
		if len(v.Properties) > 0 {
			childSubFalse := subobjectsFalse || (v.Subobjects != nil && !*v.Subobjects)
			copied.Properties = deepMergeMappingPropertiesWithSubobjects(nil, v.Properties, childSubFalse)
		}
		if len(v.Fields) > 0 {
			copied.Fields = deepMergeMappingPropertiesWithSubobjects(nil, v.Fields, true)
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
			if v.Locale != "" {
				merged.Locale = v.Locale
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
			if v.ElementType != "" {
				merged.ElementType = v.ElementType
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
				b := *v.Enabled
				merged.Enabled = &b
			}
			if v.IncludeInParent != nil {
				b := *v.IncludeInParent
				merged.IncludeInParent = &b
			}
			if v.IncludeInRoot != nil {
				b := *v.IncludeInRoot
				merged.IncludeInRoot = &b
			}
			if v.Index != nil {
				b := *v.Index
				merged.Index = &b
			}
			if v.DocValues != nil {
				b := *v.DocValues
				merged.DocValues = &b
			}
			if v.Dynamic != nil {
				merged.Dynamic = v.Dynamic
			}
			if v.Subobjects != nil {
				b := *v.Subobjects
				merged.Subobjects = &b
			}
			if v.Script != nil {
				merged.Script = v.Script
			}
			if v.OnScriptError != "" {
				merged.OnScriptError = v.OnScriptError
			}
			if v.Meta != nil {
				merged.Meta = cloneStringMap(v.Meta)
			}
			if len(v.Contexts) > 0 {
				merged.Contexts = cloneCompletionContexts(v.Contexts)
			}
			if v.IndexPrefixes != nil {
				merged.IndexPrefixes = v.IndexPrefixes
			}
			if v.IndexPhrases != nil {
				merged.IndexPhrases = v.IndexPhrases
			}
			if v.Store != nil {
				b := *v.Store
				merged.Store = &b
			}
			if v.Value != nil {
				merged.Value = v.Value
			}
			if v.IndexOptions != nil {
				merged.IndexOptions = v.IndexOptions
			}
			if v.Norms != nil {
				b := *v.Norms
				merged.Norms = &b
			}
			if v.Boost != nil {
				merged.Boost = v.Boost
			}
			if v.EagerGlobalOrdinals != nil {
				b := *v.EagerGlobalOrdinals
				merged.EagerGlobalOrdinals = &b
			}
			if v.Fielddata != nil {
				merged.Fielddata = v.Fielddata
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
			if v.PositiveScoreImpact != nil {
				b := *v.PositiveScoreImpact
				merged.PositiveScoreImpact = &b
			}
			if v.MaxShingleSize != nil {
				ms := *v.MaxShingleSize
				merged.MaxShingleSize = &ms
			}
			if v.DepthLimit != nil {
				dl := *v.DepthLimit
				merged.DepthLimit = &dl
			}
			if v.Priority != nil {
				pr := *v.Priority
				merged.Priority = &pr
			}
			if v.Relations != nil {
				merged.Relations = v.Relations
			}
			if v.ExplicitDims {
				merged.ExplicitDims = true
			}
			if v.StoreArraySource != nil {
				b := *v.StoreArraySource
				merged.StoreArraySource = &b
			}
			if v.SyntheticSourceKeep != "" {
				merged.SyntheticSourceKeep = v.SyntheticSourceKeep
			}
			if v.TimeSeriesDimension != nil {
				b := *v.TimeSeriesDimension
				merged.TimeSeriesDimension = &b
			}
			if v.TimeSeriesDimensions != nil {
				merged.TimeSeriesDimensions = append([]string(nil), v.TimeSeriesDimensions...)
			}
			if v.TimeSeriesMetric != "" {
				merged.TimeSeriesMetric = v.TimeSeriesMetric
			}
			if v.TargetIndex != "" {
				merged.TargetIndex = v.TargetIndex
			}
			if v.InputField != "" {
				merged.InputField = v.InputField
			}
			if v.TargetField != "" {
				merged.TargetField = v.TargetField
			}
			if v.KeyField != "" {
				merged.KeyField = v.KeyField
			}
			if len(v.FetchFields) > 0 {
				merged.FetchFields = deepCloneSliceMapStringAny(v.FetchFields)
			}
			if len(v.Metrics) > 0 {
				merged.Metrics = append([]string(nil), v.Metrics...)
			}
			if v.DefaultMetric != "" {
				merged.DefaultMetric = v.DefaultMetric
			}
			if len(v.Properties) > 0 {
				mergedSubFalse := subobjectsFalse || (merged.Subobjects != nil && !*merged.Subobjects)
				merged.Properties = deepMergeMappingPropertiesWithSubobjects(existing.Properties, v.Properties, mergedSubFalse)
			}
			if len(v.Fields) > 0 {
				merged.Fields = deepMergeMappingPropertiesWithSubobjects(existing.Fields, v.Fields, true)
			}
			out[k] = merged
		} else {
			copied := deepCloneFieldProperty(v)
			if len(v.Properties) > 0 {
				childSubFalse := subobjectsFalse || (v.Subobjects != nil && !*v.Subobjects)
				copied.Properties = deepMergeMappingPropertiesWithSubobjects(nil, v.Properties, childSubFalse)
			}
			if len(v.Fields) > 0 {
				copied.Fields = deepMergeMappingPropertiesWithSubobjects(nil, v.Fields, true)
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
	inPassthroughTSDim bool,
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

		isPassthrough := strings.EqualFold(strings.TrimSpace(prop.Type), "passthrough")
		if isPassthrough {
			prio := -1
			hasPrio := false
			if prop.Priority != nil {
				prio = *prop.Priority
				hasPrio = true
			}
			s.passthroughNodes = append(s.passthroughNodes, passthroughNodeSpec{
				prefix:      dotPath,
				priority:    prio,
				hasPriority: hasPrio,
			})
		}
		propTSDim := prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension
		childPassthroughTSDim := inPassthroughTSDim || (isPassthrough && propTSDim)

		if strings.EqualFold(prop.Type, "nested") {
			corrCol := "n__" + SanitizeDorisIdentifier(dotPath)
			s.NestedRoots[dotPath] = corrCol
			if s.nestedRootPaths == nil {
				s.nestedRootPaths = make(map[string][]string)
			}
			s.nestedRootPaths[dotPath] = currJSONPath
			if len(prop.Properties) > 0 {
				s.compileProperties(currESPath, currJSONPath, dotPath, len(currJSONPath), childPassthroughTSDim, prop.Properties)
			}
			continue
		}

		// Recurse into sub-object properties if present
		if len(prop.Properties) > 0 {
			s.compileProperties(currESPath, currJSONPath, activeNestedRoot, nestedRootDepth, childPassthroughTSDim, prop.Properties)
		}

		// If leaf type is declared, register the field binding
		if prop.Type != "" && !strings.EqualFold(prop.Type, "object") {
			if inPassthroughTSDim && !isPassthrough && prop.TimeSeriesDimension == nil && prop.TimeSeriesMetric == "" && IsValidTSDBDimensionFieldType(prop.Type) {
				t := true
				prop.TimeSeriesDimension = &t
			}
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
	lowerNorm := normalizerUsesLowercaseFilter(prop.Normalizer, s.AnalysisConfig)
	copyTo := parseCopyToTargets(prop.CopyTo)
	notIndexed := (prop.Index != nil && !*prop.Index) || (prop.Enabled != nil && !*prop.Enabled)
	docValuesFalse := (prop.DocValues != nil && !*prop.DocValues) || (prop.Enabled != nil && !*prop.Enabled)

	if esType == "search_as_you_type" && prop.Analyzer == "" {
		prop.Analyzer = "standard"
	}
	maxShingle := 0
	if esType == "search_as_you_type" {
		maxShingle = 3
		if prop.MaxShingleSize != nil {
			maxShingle = *prop.MaxShingleSize
		}
	}
	depthLimit := 0
	if esType == "flattened" {
		depthLimit = 20
		if prop.DepthLimit != nil {
			depthLimit = *prop.DepthLimit
		}
	}

	metaMap := cloneStringMap(prop.Meta)
	ctxSlice := cloneCompletionContexts(prop.Contexts)
	var tsDimCopy *bool
	if prop.TimeSeriesDimension != nil {
		v := *prop.TimeSeriesDimension
		tsDimCopy = &v
	}
	var tsDimsCopy []string
	if len(prop.TimeSeriesDimensions) > 0 {
		tsDimsCopy = append([]string(nil), prop.TimeSeriesDimensions...)
	}
	var storeArrCopy *bool
	if prop.StoreArraySource != nil {
		v := *prop.StoreArraySource
		storeArrCopy = &v
	}
	var aggMetricsCopy []string
	if len(prop.Metrics) > 0 {
		aggMetricsCopy = append([]string(nil), prop.Metrics...)
	}

	if IsRangeFieldType(esType) || esType == "histogram" || esType == "flattened" || esType == "sparse_vector" || esType == "rank_features" || esType == "percolator" || esType == "geo_shape" || esType == "passthrough" {
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:              dotPath,
			SourceJSONPath:           sourceJSONPath,
			Kind:                     StorageDynamicVariant,
			ColumnName:               "",
			DorisType:                DorisVariant,
			ESType:                   esType,
			Format:                   prop.Format,
			Locale:                   prop.Locale,
			Analyzer:                 prop.Analyzer,
			SearchAnalyzer:           prop.SearchAnalyzer,
			NormalizerName:           prop.Normalizer,
			LowercaseNormalizer:      lowerNorm,
			NestedPath:               activeNestedRoot,
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			ConstantValue:            prop.Value,
			HasConstantValue:         prop.Value != nil,
			IgnoreAbove:              prop.IgnoreAbove,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			PositiveScoreImpact:      prop.PositiveScoreImpact,
			MaxShingleSize:           maxShingle,
			DepthLimit:               depthLimit,
			Relations:                prop.Relations,
			Meta:                     metaMap,
			Contexts:                 ctxSlice,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
			StoreArraySource:         storeArrCopy,
			SyntheticSourceKeep:      prop.SyntheticSourceKeep,
			TimeSeriesDimension:      tsDimCopy,
			TimeSeriesDimensions:     tsDimsCopy,
			TimeSeriesMetric:         prop.TimeSeriesMetric,
			FromScript:               prop.Script != nil,
			AggregateMetrics:         aggMetricsCopy,
			DefaultMetric:            prop.DefaultMetric,
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
		var nVecDims int
		var nAutoDims bool
		var nVecMetric string
		var nVecElemType string
		var nVecIdxOpts map[string]any
		if esType == "dense_vector" || esType == "knn_vector" {
			nVecElemType = strings.ToLower(strings.TrimSpace(prop.ElementType))
			if nVecElemType == "" {
				nVecElemType = "float"
			}
			nVecDims = prop.EffectiveDims()
			nAutoDims = nVecDims == 0
			nVecMetric = strings.ToLower(strings.TrimSpace(prop.Similarity))
			if nVecMetric == "" && !notIndexed {
				if nVecElemType == "bit" {
					nVecMetric = "l2_norm"
				} else {
					nVecMetric = "cosine"
				}
			}
			if !notIndexed {
				nVecIdxOpts = MaterializeDenseVectorIndexOptions(nVecElemType, prop.IndexOptions)
			}
		}
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:              dotPath,
			SourceJSONPath:           sourceJSONPath,
			Kind:                     StorageNestedSubfield,
			ColumnName:               prefilterCol,
			DorisType:                dorisType,
			ESType:                   esType,
			Format:                   prop.Format,
			Locale:                   prop.Locale,
			Analyzer:                 prop.Analyzer,
			SearchAnalyzer:           prop.SearchAnalyzer,
			NormalizerName:           prop.Normalizer,
			LowercaseNormalizer:      lowerNorm,
			VectorDims:               nVecDims,
			AutoDims:                 nAutoDims,
			VectorMetric:             nVecMetric,
			VectorElementType:        nVecElemType,
			VectorIndexOptions:       nVecIdxOpts,
			NestedPath:               activeNestedRoot,
			CorrelatedArrayCol:       corrCol,
			RelativeJSONPath:         relJSONPath,
			PrefilterArrayCol:        prefilterCol,
			IsMultiValued:            (prop.MultiValued || prop.Script != nil || len(relJSONPath) > 1 || DefaultMultiValuedPaths[dotPath]) && esType != "rank_feature" && esType != "dense_vector" && esType != "knn_vector",
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			ConstantValue:            prop.Value,
			HasConstantValue:         prop.Value != nil,
			IgnoreAbove:              prop.IgnoreAbove,
			ScalingFactor:            prop.ScalingFactor,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			PositiveScoreImpact:      prop.PositiveScoreImpact,
			MaxShingleSize:           maxShingle,
			DepthLimit:               depthLimit,
			Relations:                prop.Relations,
			Meta:                     metaMap,
			Contexts:                 ctxSlice,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
			StoreArraySource:         storeArrCopy,
			SyntheticSourceKeep:      prop.SyntheticSourceKeep,
			TimeSeriesDimension:      tsDimCopy,
			TimeSeriesDimensions:     tsDimsCopy,
			TimeSeriesMetric:         prop.TimeSeriesMetric,
			FromScript:               prop.Script != nil,
			AggregateMetrics:         aggMetricsCopy,
			DefaultMetric:            prop.DefaultMetric,
		}
		if esType == "search_as_you_type" {
			baseNestedB := s.Fields[dotPath]
			for _, sub := range baseNestedB.SearchAsYouTypeSubfields() {
				subPath := dotPath + sub
				subCol := "n__" + SanitizeDorisIdentifier(subPath)
				s.Fields[subPath] = FieldBinding{
					ESFieldPath:           subPath,
					SourceJSONPath:        sourceJSONPath,
					Kind:                  StorageNestedSubfield,
					ColumnName:            subCol,
					DorisType:             DorisString,
					ESType:                "search_as_you_type",
					Analyzer:              prop.Analyzer,
					SearchAnalyzer:        prop.SearchAnalyzer,
					NestedPath:            activeNestedRoot,
					CorrelatedArrayCol:    corrCol,
					RelativeJSONPath:      relJSONPath,
					PrefilterArrayCol:     subCol,
					IsMultiValued:         true,
					MaxShingleSize:        maxShingle,
					NotIndexed:            notIndexed,
					DocValuesFalse:        true,
					IsVirtualSAYTSubfield: true,
				}
			}
		}
		return
	}

	colName := "f__" + SanitizeDorisIdentifier(dotPath)
	if strings.EqualFold(prop.Type, "dense_vector") || strings.EqualFold(prop.Type, "knn_vector") {
		elemType := strings.ToLower(strings.TrimSpace(prop.ElementType))
		if elemType == "" {
			elemType = "float"
		}
		metric := strings.ToLower(strings.TrimSpace(prop.Similarity))
		if metric == "" && !notIndexed {
			if elemType == "bit" {
				metric = "l2_norm"
			} else {
				metric = "cosine"
			}
		}
		var vecIdxOpts map[string]any
		if !notIndexed {
			vecIdxOpts = MaterializeDenseVectorIndexOptions(elemType, prop.IndexOptions)
		}
		dims := prop.EffectiveDims()
		s.Fields[dotPath] = FieldBinding{
			ESFieldPath:        dotPath,
			SourceJSONPath:     sourceJSONPath,
			Kind:               StoragePromotedVector,
			ColumnName:         colName,
			DorisType:          DorisFloatArray,
			ESType:             esType,
			VectorDims:         dims,
			AutoDims:           dims == 0,
			VectorMetric:       metric,
			VectorElementType:  elemType,
			VectorIndexOptions: vecIdxOpts,
			IgnoreMalformed:    prop.IgnoreMalformed,
			Meta:               metaMap,
			NotIndexed:         notIndexed,
			DocValuesFalse:     docValuesFalse,
		}
		return
	}
	if (prop.MultiValued || prop.Script != nil || DefaultMultiValuedPaths[dotPath] || esType == "counted_keyword") && !IsTextLikeESType(esType) && esType != "rank_feature" && esType != "aggregate_metric_double" {
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
			Locale:                   prop.Locale,
			Analyzer:                 prop.Analyzer,
			SearchAnalyzer:           prop.SearchAnalyzer,
			NormalizerName:           prop.Normalizer,
			LowercaseNormalizer:      lowerNorm,
			IsMultiValued:            true,
			CopyTo:                   copyTo,
			NullValue:                prop.NullValue,
			ConstantValue:            prop.Value,
			HasConstantValue:         prop.Value != nil,
			IgnoreAbove:              prop.IgnoreAbove,
			ScalingFactor:            prop.ScalingFactor,
			Coerce:                   prop.Coerce,
			IgnoreMalformed:          prop.IgnoreMalformed,
			EnablePositionIncrements: prop.EnablePositionIncrements,
			PositiveScoreImpact:      prop.PositiveScoreImpact,
			MaxShingleSize:           maxShingle,
			DepthLimit:               depthLimit,
			Relations:                prop.Relations,
			Meta:                     metaMap,
			Contexts:                 ctxSlice,
			NotIndexed:               notIndexed,
			DocValuesFalse:           docValuesFalse,
			StoreArraySource:         storeArrCopy,
			SyntheticSourceKeep:      prop.SyntheticSourceKeep,
			TimeSeriesDimension:      tsDimCopy,
			TimeSeriesDimensions:     tsDimsCopy,
			TimeSeriesMetric:         prop.TimeSeriesMetric,
			FromScript:               prop.Script != nil,
			AggregateMetrics:         aggMetricsCopy,
			DefaultMetric:            prop.DefaultMetric,
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
		Locale:                   prop.Locale,
		Analyzer:                 prop.Analyzer,
		SearchAnalyzer:           prop.SearchAnalyzer,
		NormalizerName:           prop.Normalizer,
		LowercaseNormalizer:      lowerNorm,
		CopyTo:                   copyTo,
		NullValue:                prop.NullValue,
		ConstantValue:            prop.Value,
		HasConstantValue:         prop.Value != nil,
		IgnoreAbove:              prop.IgnoreAbove,
		ScalingFactor:            prop.ScalingFactor,
		Coerce:                   prop.Coerce,
		IgnoreMalformed:          prop.IgnoreMalformed,
		EnablePositionIncrements: prop.EnablePositionIncrements,
		PositiveScoreImpact:      prop.PositiveScoreImpact,
		MaxShingleSize:           maxShingle,
		DepthLimit:               depthLimit,
		Relations:                prop.Relations,
		Meta:                     metaMap,
		Contexts:                 ctxSlice,
		NotIndexed:               notIndexed,
		DocValuesFalse:           docValuesFalse,
		StoreArraySource:         storeArrCopy,
		SyntheticSourceKeep:      prop.SyntheticSourceKeep,
		TimeSeriesDimension:      tsDimCopy,
		TimeSeriesDimensions:     tsDimsCopy,
		TimeSeriesMetric:         prop.TimeSeriesMetric,
		FromScript:               prop.Script != nil,
		AggregateMetrics:         aggMetricsCopy,
		DefaultMetric:            prop.DefaultMetric,
	}
	if esType == "search_as_you_type" {
		baseB := s.Fields[dotPath]
		for _, sub := range baseB.SearchAsYouTypeSubfields() {
			subPath := dotPath + sub
			subCol := "f__" + SanitizeDorisIdentifier(subPath)
			s.Fields[subPath] = FieldBinding{
				ESFieldPath:           subPath,
				SourceJSONPath:        sourceJSONPath,
				Kind:                  StoragePromotedArray,
				ColumnName:            subCol,
				DorisType:             DorisString,
				ESType:                "search_as_you_type",
				Analyzer:              prop.Analyzer,
				SearchAnalyzer:        prop.SearchAnalyzer,
				IsMultiValued:         true,
				MaxShingleSize:        maxShingle,
				NotIndexed:            notIndexed,
				DocValuesFalse:        true,
				IsVirtualSAYTSubfield: true,
			}
		}
	}
}

// ResolveField returns the physical Doris storage binding for an ES field path,
// falling back to `_doc` (`VARIANT`) for dynamic/unmapped fields.
// If `esFieldPath` ends with `.keyword` and has no explicit `.keyword` sub-field,
// it checks the base field first and strips `.keyword` from the dynamic JSON path.
func (s *IndexSchema) ResolveField(esFieldPath string) FieldBinding {
	if esFieldPath == "_ignored" {
		return FieldBinding{
			ESFieldPath:   "_ignored",
			ColumnName:    "_ignored",
			Kind:          StoragePromotedArray,
			DorisType:     DorisString,
			ESType:        "keyword",
			IsMultiValued: true,
		}
	}
	if esFieldPath == "_tsid" && s != nil && strings.EqualFold(strings.TrimSpace(s.IndexMode), "time_series") {
		return tsidBindingForTSDB()
	}
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
	for _, saytSuffix := range []string{"._index_prefix", "._2gram", "._3gram", "._4gram"} {
		if strings.HasSuffix(esFieldPath, saytSuffix) {
			basePath := strings.TrimSuffix(esFieldPath, saytSuffix)
			if b, ok := s.Fields[basePath]; ok && strings.EqualFold(b.ESType, "search_as_you_type") {
				for _, allowed := range b.SearchAsYouTypeSubfields() {
					if allowed == saytSuffix {
						b.ESFieldPath = esFieldPath
						return b
					}
				}
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
					NormalizerName:      pb.NormalizerName,
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
	if !preferKeyword && b.IsVirtualSAYTSubfield && !strings.HasSuffix(esFieldPath, "._index_prefix") && s != nil {
		for _, sfx := range []string{"._2gram", "._3gram", "._4gram"} {
			if strings.HasSuffix(esFieldPath, sfx) {
				if baseB, ok := s.Fields[strings.TrimSuffix(esFieldPath, sfx)]; ok {
					baseB.ESFieldPath = esFieldPath
					return baseB
				}
			}
		}
	}
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
		if strings.HasPrefix(k, "_") || b.IsVirtualSAYTSubfield || b.Kind == StoragePromotedVector || b.EnabledFalse {
			continue
		}
		if b.NotIndexed && (!s.ES8Mode || !SupportsDocValuesQueriesInES8(b)) {
			continue
		}
		if b.ESType == "histogram" || b.ESType == "rank_feature" || b.ESType == "rank_features" || b.ESType == "sparse_vector" || b.ESType == "percolator" {
			continue
		}
		if b.ESType == "alias" && b.ColumnName == "" && b.Kind != StorageDynamicVariant {
			continue
		}
		if re.MatchString(k) {
			matchedSet[k] = true
		}
		if b.ESType == "search_as_you_type" && (strings.Contains(pattern, "_2gram") || strings.Contains(pattern, "_3gram") || strings.Contains(pattern, "_4gram") || strings.Contains(pattern, "_index_prefix") || strings.HasPrefix(pattern, k+".")) {
			for _, sub := range b.SearchAsYouTypeSubfields() {
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
	case "integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range", "histogram", "flattened", "percolator", "geo_shape":
		return DorisVariant
	case "keyword", "constant_keyword", "wildcard", "ip", "version":
		return DorisVarchar
	case "text", "match_only_text", "search_as_you_type", "completion", "annotated-text", "annotated_text":
		return DorisString
	case "long", "murmur3":
		return DorisBigInt
	case "unsigned_long":
		return DorisLargeInt
	case "integer", "short", "byte", "token_count":
		return DorisInt
	case "double", "float", "half_float", "scaled_float", "rank_feature", "aggregate_metric_double":
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
	subobjects         bool
	inPassthroughTSDim bool
	dynamicDateFormats []string
	dynamicTemplates   []map[string]any
	dynamicMode        string
	es8Mode            bool
	inArray            bool
	copyToTargets      map[string]bool
	declared           map[string]string
}

func seedDeclaredPropertyTypes(props map[string]esast.FieldProperty, prefix string, subobjects bool, dst map[string]string) {
	if len(props) == 0 || dst == nil {
		return
	}
	for k, prop := range props {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		if prop.Type != "" {
			dst[full] = prop.Type
		}
		if len(prop.Properties) > 0 {
			childSub := subobjects
			if prop.Subobjects != nil {
				childSub = *prop.Subobjects
			}
			seedDeclaredPropertyTypes(prop.Properties, full, childSub, dst)
		}
	}
}

func cloneDeclaredMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newInferOptions(existing *esast.MappingSpec) inferOptions {
	opts := inferOptions{
		dateDetection:    true,
		numericDetection: false,
		subobjects:       true,
		dynamicMode:      "true",
		declared:         make(map[string]string),
	}
	if existing != nil {
		if existing.DateDetection != nil {
			opts.dateDetection = *existing.DateDetection
		}
		if existing.NumericDetection != nil {
			opts.numericDetection = *existing.NumericDetection
		}
		if existing.Subobjects != nil {
			opts.subobjects = *existing.Subobjects
		}
		opts.dynamicDateFormats = existing.DynamicDateFormats
		opts.dynamicTemplates = existing.DynamicTemplates
		opts.dynamicMode = normalizeDynamicMode(existing.Dynamic)
		if len(existing.Properties) > 0 {
			seedDeclaredPropertyTypes(existing.Properties, "", opts.subobjects, opts.declared)
		}
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
		props = deepMergeMappingPropertiesWithSubobjects(nil, baseSpec.Properties, !opts.subobjects)
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
	var mergedRuntime map[string]esast.FieldProperty
	if baseSpec != nil {
		rtMap, addedRT := InferDynamicRuntimeFieldsFromDocs(docs, baseSpec)
		if addedRT {
			mergedRuntime = rtMap
		} else if len(baseSpec.Runtime) > 0 {
			mergedRuntime = CloneFlatRuntimeMap(nil, baseSpec.Runtime)
		}
	}
	if len(props) == 0 {
		if baseSpec != nil {
			out := *baseSpec
			if len(mergedRuntime) > 0 {
				out.Runtime = mergedRuntime
			}
			return &out
		}
		return nil
	}
	inferredSpec := &esast.MappingSpec{
		Properties: props,
	}
	if baseSpec != nil {
		out := *baseSpec
		if len(mergedRuntime) > 0 {
			out.Runtime = mergedRuntime
		}
		out.Properties = mergeInferredIntoExistingPropsWithSubobjects(baseSpec.Properties, inferredSpec.Properties, !opts.subobjects)
		return &out
	}
	return inferredSpec
}

// InferDynamicRuntimeFieldsFromDocs inspects sample documents against an existing MappingSpec
// and infers `runtime` field definitions (`long`, `double`, `boolean`, `date`, `ip`, `keyword`)
// for unmapped fields inside `dynamic: "runtime"` scopes.
func InferDynamicRuntimeFieldsFromDocs(docs []json.RawMessage, existing *esast.MappingSpec) (map[string]esast.FieldProperty, bool) {
	if existing == nil || len(docs) == 0 {
		return nil, false
	}
	opts := newInferOptions(existing)
	outRuntime := CloneFlatRuntimeMap(nil, existing.Runtime)
	if outRuntime == nil {
		outRuntime = make(map[string]esast.FieldProperty)
	}
	added := false
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
		if err := dec.Decode(&obj); err != nil || obj == nil {
			continue
		}
		if inferRuntimeFromObject(obj, existing.Properties, outRuntime, existing.Runtime, "", 0, opts) {
			added = true
		}
	}
	if !added && len(existing.Runtime) == 0 {
		return nil, false
	}
	return outRuntime, added
}

func inferRuntimeFromObject(
	obj map[string]any,
	mappedProps map[string]esast.FieldProperty,
	outRuntime map[string]esast.FieldProperty,
	origRuntime map[string]esast.FieldProperty,
	pathPrefix string,
	depth int,
	opts inferOptions,
) bool {
	if depth >= maxInferredDepth || obj == nil {
		return false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	addedAny := false
	for _, k := range keys {
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
		if existingProp, exists := mappedProps[k]; exists {
			if existingProp.Enabled != nil && !*existingProp.Enabled {
				continue
			}
			if len(existingProp.Properties) > 0 || strings.EqualFold(existingProp.Type, "object") || strings.EqualFold(existingProp.Type, "nested") || existingProp.Type == "" {
				childOpts := opts
				if existingProp.Dynamic != nil {
					childOpts.dynamicMode = normalizeDynamicMode(existingProp.Dynamic)
				}
				if existingProp.Subobjects != nil {
					childOpts.subobjects = *existingProp.Subobjects
				}
				switch tv := val.(type) {
				case map[string]any:
					if inferRuntimeFromObject(tv, existingProp.Properties, outRuntime, origRuntime, fullPath, depth+1, childOpts) {
						addedAny = true
					}
				case []any:
					for _, elem := range tv {
						if em, ok := elem.(map[string]any); ok {
							if inferRuntimeFromObject(em, existingProp.Properties, outRuntime, origRuntime, fullPath, depth+1, childOpts) {
								addedAny = true
							}
						}
					}
				}
			}
			continue
		}
		if opts.dynamicMode != "runtime" {
			continue
		}
		if _, inOrig := origRuntime[fullPath]; inOrig {
			continue
		}
		switch tv := val.(type) {
		case map[string]any:
			if opts.subobjects && depth+1 < maxInferredDepth {
				if inferRuntimeFromObject(tv, nil, outRuntime, origRuntime, fullPath, depth+1, opts) {
					addedAny = true
				}
			}
		case []any:
			hasMap := false
			for _, elem := range tv {
				if em, ok := elem.(map[string]any); ok {
					hasMap = true
					if opts.subobjects && depth+1 < maxInferredDepth {
						if inferRuntimeFromObject(em, nil, outRuntime, origRuntime, fullPath, depth+1, opts) {
							addedAny = true
						}
					}
				}
			}
			if !hasMap {
				for _, elem := range tv {
					if elem == nil {
						continue
					}
					if rtProp, ok := inferScalarRuntimeProperty(elem, opts); ok {
						if prev, had := outRuntime[fullPath]; had {
							outRuntime[fullPath] = mergeRuntimeProperty(prev, rtProp)
						} else {
							outRuntime[fullPath] = rtProp
							addedAny = true
						}
					}
				}
			}
		default:
			if rtProp, ok := inferScalarRuntimeProperty(val, opts); ok {
				if prev, had := outRuntime[fullPath]; had {
					outRuntime[fullPath] = mergeRuntimeProperty(prev, rtProp)
				} else {
					outRuntime[fullPath] = rtProp
					addedAny = true
				}
			}
		}
	}
	return addedAny
}

func inferScalarRuntimeProperty(val any, opts inferOptions) (esast.FieldProperty, bool) {
	switch v := val.(type) {
	case bool:
		return esast.FieldProperty{Type: "boolean"}, true
	case json.Number:
		s := v.String()
		if strings.ContainsAny(s, ".eE") {
			return esast.FieldProperty{Type: "double"}, true
		}
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			if _, errU := strconv.ParseUint(s, 10, 64); errU == nil {
				return esast.FieldProperty{Type: "unsigned_long"}, true
			}
			return esast.FieldProperty{Type: "double"}, true
		}
		return esast.FieldProperty{Type: "long"}, true
	case float64:
		return esast.FieldProperty{Type: "double"}, true
	case string:
		trimmed := strings.TrimSpace(v)
		if opts.dateDetection {
			if fmtStr, matched := matchInferredDateFormat(trimmed, opts.dynamicDateFormats); matched {
				return esast.FieldProperty{Type: "date", Format: fmtStr}, true
			}
		}
		if opts.numericDetection && trimmed != "" {
			if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return esast.FieldProperty{Type: "long"}, true
			}
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return esast.FieldProperty{Type: "double"}, true
			}
		}
		if trimmed != "" && (strings.Contains(trimmed, ".") || strings.Contains(trimmed, ":")) {
			if ip := net.ParseIP(trimmed); ip != nil {
				return esast.FieldProperty{Type: "ip"}, true
			}
		}
		return esast.FieldProperty{Type: "keyword"}, true
	default:
		return esast.FieldProperty{}, false
	}
}

func mergeRuntimeProperty(existing, incoming esast.FieldProperty) esast.FieldProperty {
	if existing.Type == incoming.Type {
		return existing
	}
	if (existing.Type == "long" && incoming.Type == "double") || (existing.Type == "double" && incoming.Type == "long") {
		return esast.FieldProperty{Type: "double"}
	}
	return esast.FieldProperty{Type: "keyword"}
}

func mergeInferredIntoExistingPropsWithSubobjects(
	existingProps, inferredProps map[string]esast.FieldProperty,
	subobjectsFalse bool,
) map[string]esast.FieldProperty {
	out := deepMergeMappingPropertiesWithSubobjects(nil, existingProps, subobjectsFalse)
	for k, infProp := range inferredProps {
		exProp, exists := out[k]
		if !exists {
			copied := deepCloneFieldProperty(infProp)
			childSubFalse := subobjectsFalse || (infProp.Subobjects != nil && !*infProp.Subobjects)
			if len(infProp.Properties) > 0 {
				copied.Properties = deepMergeMappingPropertiesWithSubobjects(nil, infProp.Properties, childSubFalse)
			}
			if len(infProp.Fields) > 0 {
				copied.Fields = deepMergeMappingPropertiesWithSubobjects(nil, infProp.Fields, true)
			}
			out[k] = copied
			continue
		}
		if (exProp.Enabled != nil && !*exProp.Enabled) ||
			(exProp.Type != "" && !strings.EqualFold(exProp.Type, "object") && !strings.EqualFold(exProp.Type, "nested") && !strings.EqualFold(exProp.Type, "passthrough")) {
			continue
		}
		if len(infProp.Properties) > 0 {
			childSubFalse := subobjectsFalse || strings.EqualFold(exProp.Type, "passthrough") || (exProp.Subobjects != nil && !*exProp.Subobjects) || (infProp.Subobjects != nil && !*infProp.Subobjects)
			exProp.Properties = mergeInferredIntoExistingPropsWithSubobjects(exProp.Properties, infProp.Properties, childSubFalse)
			out[k] = exProp
		}
	}
	return out
}

func inferObjectPropertiesWithOpts(obj map[string]any, dst map[string]esast.FieldProperty, pathPrefix string, depth int, totalFields *int, opts inferOptions) {
	if depth >= maxInferredDepth || *totalFields >= maxInferredProperties {
		return
	}
	if opts.subobjects {
		obj = expandInferDocKeysOneLevel(obj, dst)
	} else {
		obj = flattenSubmapsForNoSubobjects(obj)
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
		if exists && (len(existing.Properties) > 0 || strings.EqualFold(existing.Type, "object") || strings.EqualFold(existing.Type, "nested") || strings.EqualFold(existing.Type, "passthrough")) {
			if existing.Enabled != nil && !*existing.Enabled {
				continue
			}
			childOpts := opts
			if existing.Dynamic != nil {
				childOpts.dynamicMode = normalizeDynamicMode(existing.Dynamic)
			}
			if strings.EqualFold(existing.Type, "passthrough") {
				childOpts.subobjects = false
				if existing.TimeSeriesDimension != nil && *existing.TimeSeriesDimension {
					childOpts.inPassthroughTSDim = true
				}
			} else if existing.Subobjects != nil {
				childOpts.subobjects = *existing.Subobjects
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
		if opts.inPassthroughTSDim && inferred.TimeSeriesDimension == nil && inferred.TimeSeriesMetric == "" && IsValidTSDBDimensionFieldType(inferred.Type) {
			t := true
			inferred.TimeSeriesDimension = &t
		}
		if exists {
			if declType := opts.declared[fullPath]; declType != "" && !strings.EqualFold(declType, "object") && !strings.EqualFold(declType, "nested") {
				if _, isSlice := val.([]any); isSlice && !existing.MultiValued {
					markPropertyMultiValued(&existing)
					dst[k] = existing
				}
				continue
			}
			if opts.es8Mode && (existing.Type == "dense_vector" || existing.Type == "knn_vector" || existing.Type == "float") && len(existing.Properties) == 0 {
				continue
			}
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

func matchInferredDateFormat(v string, dynamicDateFormats []string) (string, bool) {
	if len(dynamicDateFormats) > 0 {
		if _, err := strconv.ParseInt(v, 10, 64); err == nil {
			return "", false
		}
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return "", false
		}
		for _, fmtSpec := range dynamicDateFormats {
			for _, singleFmt := range strings.Split(fmtSpec, "||") {
				singleFmt = strings.TrimSpace(singleFmt)
				if singleFmt == "" || singleFmt == "epoch_millis" || singleFmt == "epoch_second" {
					continue
				}
				if _, ok := ParseESDateWithFormatToEpochMillis(v, singleFmt, time.Time{}); ok {
					return fmtSpec, true
				}
			}
		}
		return "", false
	}
	if looksLikeISODateString(v) || looksLikeSlashDateString(v) {
		if _, ok := ParseESDateToEpochMillis(v, time.Time{}); ok {
			return "", true
		}
	}
	return "", false
}

func matchesInferredDate(v string, dynamicDateFormats []string) bool {
	_, ok := matchInferredDateFormat(v, dynamicDateFormats)
	return ok
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
			rawMapping, hasMap := rule["mapping"]
			if !hasMap || rawMapping == nil {
				continue
			}
			mappingMap, _ := rawMapping.(map[string]any)
			lookupMatcher := func(key string) any {
				if v, ok := rule[key]; ok && v != nil {
					return v
				}
				if mappingMap != nil {
					return mappingMap[key]
				}
				return nil
			}
			rawMMT := lookupMatcher("match_mapping_type")
			rawUMMT := lookupMatcher("unmatch_mapping_type")
			rawMatch := lookupMatcher("match")
			rawUnmatch := lookupMatcher("unmatch")
			rawPathMatch := lookupMatcher("path_match")
			rawPathUnmatch := lookupMatcher("path_unmatch")
			if rawMMT == nil && rawUMMT == nil && rawMatch == nil && rawUnmatch == nil && rawPathMatch == nil && rawPathUnmatch == nil {
				continue
			}
			if !matchesDynamicMappingType(rawMMT, detectedType) {
				continue
			}
			if rawUMMT != nil && matchesDynamicMappingType(rawUMMT, detectedType) {
				continue
			}
			mpType, _ := lookupMatcher("match_pattern").(string)
			if hasPats, matched := matchesAnyDynamicTemplatePattern(rawMatch, fieldName, mpType); hasPats && !matched {
				continue
			}
			if hasPats, matched := matchesAnyDynamicTemplatePattern(rawUnmatch, fieldName, mpType); hasPats && matched {
				continue
			}
			if hasPats, matched := matchesAnyDynamicTemplatePattern(rawPathMatch, fullPath, mpType); hasPats && !matched {
				continue
			}
			if hasPats, matched := matchesAnyDynamicTemplatePattern(rawPathUnmatch, fullPath, mpType); hasPats && matched {
				continue
			}
			toMarshal := rawMapping
			if mappingMap != nil {
				cleaned := make(map[string]any, len(mappingMap))
				for mk, mv := range mappingMap {
					switch mk {
					case "match_mapping_type", "unmatch_mapping_type", "match", "unmatch", "path_match", "path_unmatch", "match_pattern":
						continue
					}
					cleaned[mk] = mv
				}
				toMarshal = cleaned
			}
			b, err := json.Marshal(toMarshal)
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
			if opts.es8Mode {
				return esast.FieldProperty{Type: "float"}, true
			}
			return esast.FieldProperty{Type: "double"}, true
		}
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			if _, errU := strconv.ParseUint(s, 10, 64); errU == nil {
				return esast.FieldProperty{Type: "unsigned_long"}, true
			}
			if opts.es8Mode {
				return esast.FieldProperty{Type: "float"}, true
			}
			return esast.FieldProperty{Type: "double"}, true
		}
		return esast.FieldProperty{Type: "long"}, true
	case float64:
		if opts.es8Mode {
			return esast.FieldProperty{Type: "float"}, true
		}
		return esast.FieldProperty{Type: "double"}, true
	case string:
		trimmed := strings.TrimSpace(v)
		if opts.dateDetection {
			if fmtStr, matched := matchInferredDateFormat(trimmed, opts.dynamicDateFormats); matched {
				return esast.FieldProperty{Type: "date", Format: fmtStr}, true
			}
		}
		if opts.numericDetection && trimmed != "" {
			if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return esast.FieldProperty{Type: "long"}, true
			}
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return esast.FieldProperty{Type: "float"}, true
			}
		}
		if opts.es8Mode {
			if opts.inPassthroughTSDim {
				return esast.FieldProperty{Type: "keyword"}, true
			}
			return esast.FieldProperty{
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"keyword": {Type: "keyword", IgnoreAbove: 256},
				},
			}, true
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
				if !opts.subobjects {
					return esast.FieldProperty{}, false
				}
				if depth+1 < maxInferredDepth {
					childOpts := opts
					childOpts.declared = cloneDeclaredMap(opts.declared)
					if tmplProp.Dynamic != nil {
						childOpts.dynamicMode = normalizeDynamicMode(tmplProp.Dynamic)
					}
					if tmplProp.Subobjects != nil {
						childOpts.subobjects = *tmplProp.Subobjects
					}
					childProps := make(map[string]esast.FieldProperty)
					if len(tmplProp.Properties) > 0 {
						childProps = deepMergeMappingPropertiesWithSubobjects(nil, tmplProp.Properties, !childOpts.subobjects)
						seedDeclaredPropertyTypes(childProps, fullPath, childOpts.subobjects, childOpts.declared)
					}
					inferObjectPropertiesWithOpts(v, childProps, fullPath, depth+1, totalFields, childOpts)
					if len(childProps) > 0 {
						tmplProp.Properties = childProps
					}
				}
				return tmplProp, true
			}
		}
		if !opts.subobjects || depth+1 >= maxInferredDepth {
			return esast.FieldProperty{}, false
		}
		childProps := make(map[string]esast.FieldProperty)
		inferObjectPropertiesWithOpts(v, childProps, fullPath, depth+1, totalFields, opts)
		if len(childProps) == 0 {
			return esast.FieldProperty{}, false
		}
		return esast.FieldProperty{Properties: childProps}, true
	case []any:
		elemOpts := opts
		elemOpts.inArray = true
		var merged esast.FieldProperty
		hasElem := false
		allNumeric := len(v) >= 2 && !opts.inArray
		if opts.es8Mode {
			allNumeric = len(v) >= 128 && len(v) <= 2048 && !opts.inArray && !opts.copyToTargets[fullPath]
		}
		allStrings := len(v) >= 50 && !opts.inArray
		nonNilStrings := 0
		hasFloat := false
		for _, elem := range v {
			if elem == nil {
				allNumeric = false
				continue
			}
			if _, isStr := elem.(string); isStr {
				nonNilStrings++
			} else {
				allStrings = false
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
				objElemOpts := opts
				objElemOpts.inArray = false
				inferObjectPropertiesWithOpts(elemMap, merged.Properties, fullPath, depth+1, totalFields, objElemOpts)
				if len(merged.Properties) > 0 {
					hasElem = true
				}
				continue
			}
			elemProp, ok := inferValuePropertyWithOpts(elem, fieldName, fullPath, depth, totalFields, elemOpts)
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
		if (merged.Type == "dense_vector" || merged.Type == "knn_vector") && merged.EffectiveDims() == 0 && !opts.inArray && len(v) > 0 {
			merged.Dims = len(v)
		}
		if allStrings && nonNilStrings >= 50 && merged.Type == "keyword" {
			matchedTmpl := false
			if len(opts.dynamicTemplates) > 0 {
				if _, ok := applyMatchingDynamicTemplate(fieldName, fullPath, "string", opts.dynamicTemplates); ok {
					matchedTmpl = true
				}
			}
			if !matchedTmpl {
				merged = esast.FieldProperty{
					Type:        "text",
					MultiValued: true,
					Fields: map[string]esast.FieldProperty{
						"keyword": {Type: "keyword", IgnoreAbove: 256, MultiValued: true},
					},
				}
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
	// Widening rules: long + unsigned_long -> unsigned_long; long/unsigned_long + double -> double; dense_vector + numeric -> multi-valued double; keyword + text -> text (with .keyword); incompatible scalars -> keyword/text
	if (existing.Type == "long" && incoming.Type == "unsigned_long") || (existing.Type == "unsigned_long" && incoming.Type == "long") {
		return esast.FieldProperty{Type: "unsigned_long", MultiValued: mv}
	}
	isNumericOrVec := func(t string) bool {
		return t == "long" || t == "unsigned_long" || t == "double" || t == "float" || t == "dense_vector" || t == "knn_vector"
	}
	if isNumericOrVec(existing.Type) && isNumericOrVec(incoming.Type) {
		widenFloatType := "double"
		if existing.Type == "float" || incoming.Type == "float" {
			if existing.Type != "double" && incoming.Type != "double" {
				widenFloatType = "float"
			}
		}
		if existing.Type == "dense_vector" || existing.Type == "knn_vector" || incoming.Type == "dense_vector" || incoming.Type == "knn_vector" {
			return esast.FieldProperty{Type: widenFloatType, MultiValued: true}
		}
		return esast.FieldProperty{Type: widenFloatType, MultiValued: mv}
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

func looksLikeSlashDateString(s string) bool {
	if len(s) < 10 || len(s) > 40 {
		return false
	}
	if s[4] != '/' || s[7] != '/' || (len(s) > 10 && s[10] != ' ') {
		return false
	}
	for _, i := range [...]int{0, 1, 2, 3, 5, 6, 8, 9} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
