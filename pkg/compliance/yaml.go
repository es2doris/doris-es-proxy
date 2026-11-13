package compliance

import (
	"embed"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// EmbeddedSpecsFS contains the embedded Apache-2.0 rest-api-spec YAML compliance test corpus.
//
//go:embed specs/*.yml
var EmbeddedSpecsFS embed.FS

// YAMLField represents a single ordered key-value pair in a YAML mapping.
type YAMLField struct {
	Key   string
	Value any
}

// OrderedMap preserves the exact YAML key order of a mapping.
type OrderedMap struct {
	Fields []YAMLField
}

// NewOrderedMap creates an empty OrderedMap.
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{}
}

// Set sets or appends a key-value pair in the OrderedMap.
func (m *OrderedMap) Set(key string, val any) {
	for i := range m.Fields {
		if m.Fields[i].Key == key {
			m.Fields[i].Value = val
			return
		}
	}
	m.Fields = append(m.Fields, YAMLField{Key: key, Value: val})
}

// Get looks up a key in the OrderedMap.
func (m *OrderedMap) Get(key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	for _, f := range m.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

// ToNative recursively converts OrderedMap instances into standard map[string]any
// and slices into []any suitable for JSON marshaling and deep inspection.
func ToNative(v any) any {
	switch val := v.(type) {
	case *OrderedMap:
		if val == nil {
			return map[string]any{}
		}
		out := make(map[string]any, len(val.Fields))
		for _, f := range val.Fields {
			out[f.Key] = ToNative(f.Value)
		}
		return out
	case OrderedMap:
		out := make(map[string]any, len(val.Fields))
		for _, f := range val.Fields {
			out[f.Key] = ToNative(f.Value)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = ToNative(elem)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, elem := range val {
			out[k] = ToNative(elem)
		}
		return out
	default:
		return v
	}
}

// SpecStep represents a single operation in a rest-api-spec setup, teardown, or test section.
type SpecStep struct {
	Op    string
	Value any
}

// SpecSection represents a named rest-api-spec test section within a YAML file.
type SpecSection struct {
	Name  string
	Steps []SpecStep
}

// SkipSpec represents a rest-api-spec skip directive (file-level or section-level).
type SkipSpec struct {
	Version  string
	Reason   string
	Features []string
}

// SpecDocument represents a parsed multi-document rest-api-spec YAML file.
type SpecDocument struct {
	Skip     *SkipSpec
	Setup    []SpecStep
	Teardown []SpecStep
	Sections []SpecSection
}

// SpecFile is an alias for SpecDocument representing a parsed rest-api-spec YAML file.
type SpecFile = SpecDocument

// ParseSpecFile parses a rest-api-spec YAML file (potentially containing multiple
// YAML documents separated by `---`) into a SpecDocument with optional file-level skip,
// setup, teardown, and test sections.
func ParseSpecFile(content string) (*SpecDocument, error) {
	docs, err := ParseYAMLDocuments(content)
	if err != nil {
		return nil, err
	}
	spec := &SpecDocument{}
	for docIdx, doc := range docs {
		if doc == nil {
			continue
		}
		om, ok := doc.(*OrderedMap)
		if !ok {
			return nil, fmt.Errorf("expected top-level YAML mapping in spec document, got %T", doc)
		}
		for _, field := range om.Fields {
			if docIdx == 0 && field.Key == "skip" {
				if _, isSeq := field.Value.([]any); !isSeq {
					skipSpec, err := parseSkipSpec(field.Value)
					if err != nil {
						return nil, err
					}
					spec.Skip = skipSpec
					continue
				}
			}
			steps, err := extractSteps(field.Key, field.Value)
			if err != nil {
				return nil, err
			}
			switch field.Key {
			case "setup":
				spec.Setup = append(spec.Setup, steps...)
			case "teardown":
				spec.Teardown = append(spec.Teardown, steps...)
			default:
				spec.Sections = append(spec.Sections, SpecSection{
					Name:  field.Key,
					Steps: steps,
				})
			}
		}
	}
	return spec, nil
}

func parseSkipSpec(raw any) (*SkipSpec, error) {
	var fields []YAMLField
	switch val := raw.(type) {
	case *OrderedMap:
		if val == nil {
			return nil, fmt.Errorf("skip directive requires a non-empty mapping")
		}
		fields = val.Fields
	case OrderedMap:
		fields = val.Fields
	case map[string]any:
		for k, v := range val {
			fields = append(fields, YAMLField{Key: k, Value: v})
		}
	default:
		return nil, fmt.Errorf("skip directive requires a mapping, got %T", raw)
	}
	out := &SkipSpec{}
	for _, f := range fields {
		switch f.Key {
		case "version":
			if f.Value != nil {
				out.Version = strings.TrimSpace(fmt.Sprintf("%v", f.Value))
			}
		case "reason":
			if f.Value != nil {
				out.Reason = strings.TrimSpace(fmt.Sprintf("%v", f.Value))
			}
		case "features":
			for _, item := range extractStringSlice(f.Value) {
				for _, part := range strings.Split(item, ",") {
					if trimmed := strings.TrimSpace(part); trimmed != "" {
						out.Features = append(out.Features, trimmed)
					}
				}
			}
		}
	}
	return out, nil
}

func extractSteps(sectionName string, raw any) ([]SpecStep, error) {
	seq, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("section %q must be a sequence of steps, got %T", sectionName, raw)
	}
	var steps []SpecStep
	for i, item := range seq {
		om, ok := item.(*OrderedMap)
		if !ok {
			return nil, fmt.Errorf("section %q step %d must be a mapping, got %T", sectionName, i, item)
		}
		for _, f := range om.Fields {
			steps = append(steps, SpecStep{
				Op:    f.Key,
				Value: f.Value,
			})
		}
	}
	return steps, nil
}

// ParseYAMLDocuments parses a multi-document YAML string separated by `---` into a slice of values.
func ParseYAMLDocuments(content string) ([]any, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	rawLines := strings.Split(content, "\n")

	var docChunks [][]string
	var current []string
	inBlockScalar := false
	blockIndent := 0
	var openQuote byte
	flowDepth := 0

	for _, line := range rawLines {
		if openQuote != 0 {
			current = append(current, line)
			openQuote, flowDepth = advanceOpenQuoteOnLine(line, openQuote, flowDepth)
			continue
		}

		trimmed := strings.TrimSpace(line)
		indent := countLeadingSpaces(line)

		if inBlockScalar {
			if trimmed != "" && indent <= blockIndent {
				inBlockScalar = false
			} else {
				current = append(current, line)
				continue
			}
		}

		if (trimmed == "---" || strings.HasPrefix(trimmed, "--- ")) && indent == 0 {
			if len(current) > 0 {
				docChunks = append(docChunks, current)
				current = nil
			}
			flowDepth = 0
			continue
		}
		if trimmed == "..." && indent == 0 {
			if len(current) > 0 {
				docChunks = append(docChunks, current)
				current = nil
			}
			flowDepth = 0
			continue
		}

		// Detect if this line starts a block scalar (`|` or `>`)
		stripped := stripComment(line)
		trimmedStripped := strings.TrimSpace(stripped)
		if isBlockScalarHeaderLine(trimmedStripped) {
			inBlockScalar = true
			blockIndent = indent
			current = append(current, line)
			continue
		}

		openQuote, _, flowDepth = scanLineForUnclosedQuote(line, 0, true, false, flowDepth)
		current = append(current, line)
	}
	if len(current) > 0 {
		docChunks = append(docChunks, current)
	}

	var docs []any
	for _, chunk := range docChunks {
		processed, err := preprocessLines(chunk)
		if err != nil {
			return nil, err
		}
		p := &yamlParser{
			rawLines: processed,
			anchors:  make(map[string]any),
		}
		val, err := p.parseDocument()
		if err != nil {
			return nil, err
		}
		if val != nil {
			docs = append(docs, val)
		}
	}
	return docs, nil
}

func isBlockScalarHeaderLine(trimmed string) bool {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimSpace(trimmed[2:])
	}
	if _, afterAnc, hasAnc, err := extractLeadingAnchor(trimmed); err == nil && hasAnc {
		trimmed = afterAnc
	}
	if isBlockScalarIndicator(trimmed) {
		return true
	}
	_, valPart, ok := splitKeyValue(trimmed)
	if ok {
		vp := strings.TrimSpace(valPart)
		if _, afterAnc, hasAnc, err := extractLeadingAnchor(vp); err == nil && hasAnc {
			vp = afterAnc
		}
		if isBlockScalarIndicator(vp) {
			return true
		}
	}
	return false
}

func parseBlockScalarHeader(s string) (folded bool, chomp string, explicitIndent int, ok bool) {
	if len(s) == 0 || len(s) > 3 {
		return false, "", 0, false
	}
	switch s[0] {
	case '|':
		folded = false
	case '>':
		folded = true
	default:
		return false, "", 0, false
	}
	chomp = "clip"
	hasChomp := false
	hasIndent := false
	for i := 1; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '-' || ch == '+':
			if hasChomp {
				return false, "", 0, false
			}
			hasChomp = true
			if ch == '-' {
				chomp = "strip"
			} else {
				chomp = "keep"
			}
		case ch >= '1' && ch <= '9':
			if hasIndent {
				return false, "", 0, false
			}
			hasIndent = true
			explicitIndent = int(ch - '0')
		default:
			return false, "", 0, false
		}
	}
	return folded, chomp, explicitIndent, true
}

func isBlockScalarIndicator(s string) bool {
	_, _, _, ok := parseBlockScalarHeader(s)
	return ok
}

type yamlParser struct {
	rawLines []string
	pos      int
	anchors  map[string]any
}

func (p *yamlParser) setAnchor(name string, val any) {
	if name == "" {
		return
	}
	if p.anchors == nil {
		p.anchors = make(map[string]any)
	}
	p.anchors[name] = deepCloneYAMLValue(val)
}

func (p *yamlParser) resolveAlias(aliasName string) (any, error) {
	if aliasName == "" || strings.ContainsAny(aliasName, " \t\r\n") {
		return nil, fmt.Errorf("invalid YAML alias *%s", aliasName)
	}
	if p.anchors == nil {
		return nil, fmt.Errorf("undefined YAML alias *%s", aliasName)
	}
	val, ok := p.anchors[aliasName]
	if !ok {
		return nil, fmt.Errorf("undefined YAML alias *%s", aliasName)
	}
	return deepCloneYAMLValue(val), nil
}

func (p *yamlParser) parseScalarOrAlias(s string) (any, error) {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "*") {
		return p.resolveAlias(trimmed[1:])
	}
	return parseScalar(trimmed)
}

func deepCloneYAMLValue(v any) any {
	switch val := v.(type) {
	case *OrderedMap:
		if val == nil {
			return nil
		}
		cp := &OrderedMap{Fields: make([]YAMLField, len(val.Fields))}
		for i, f := range val.Fields {
			cp.Fields[i] = YAMLField{Key: f.Key, Value: deepCloneYAMLValue(f.Value)}
		}
		return cp
	case OrderedMap:
		cp := OrderedMap{Fields: make([]YAMLField, len(val.Fields))}
		for i, f := range val.Fields {
			cp.Fields[i] = YAMLField{Key: f.Key, Value: deepCloneYAMLValue(f.Value)}
		}
		return cp
	case []any:
		cp := make([]any, len(val))
		for i, elem := range val {
			cp[i] = deepCloneYAMLValue(elem)
		}
		return cp
	case map[string]any:
		cp := make(map[string]any, len(val))
		for k, elem := range val {
			cp[k] = deepCloneYAMLValue(elem)
		}
		return cp
	default:
		return v
	}
}

func isAnchorStopByte(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', ',', '[', ']', '{', '}':
		return true
	default:
		return false
	}
}

func extractLeadingAnchor(s string) (anchorName, rest string, hasAnchor bool, err error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "&") {
		return "", s, false, nil
	}
	i := 1
	for i < len(s) && !isAnchorStopByte(s[i]) {
		i++
	}
	anchorName = s[1:i]
	if anchorName == "" {
		return "", "", false, fmt.Errorf("empty YAML anchor name in %q", s)
	}
	rest = strings.TrimSpace(s[i:])
	return anchorName, rest, true, nil
}

type parsedMapEntry struct {
	isMerge bool
	key     string
	val     any
}

func extractMergeSourceMaps(v any) ([]*OrderedMap, error) {
	switch tv := v.(type) {
	case *OrderedMap:
		if tv == nil {
			return nil, fmt.Errorf("merge key '<<' requires a non-null mapping")
		}
		return []*OrderedMap{tv}, nil
	case OrderedMap:
		cp := tv
		return []*OrderedMap{&cp}, nil
	case []any:
		out := make([]*OrderedMap, 0, len(tv))
		for i, elem := range tv {
			switch em := elem.(type) {
			case *OrderedMap:
				if em == nil {
					return nil, fmt.Errorf("merge key '<<' sequence element %d is null", i)
				}
				out = append(out, em)
			case OrderedMap:
				cp := em
				out = append(out, &cp)
			default:
				return nil, fmt.Errorf("merge key '<<' sequence element %d must be a mapping, got %T", i, elem)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("merge key '<<' requires a mapping or sequence of mappings, got %T", v)
	}
}

func buildMergedOrderedMap(entries []parsedMapEntry) (*OrderedMap, error) {
	om := NewOrderedMap()
	explicitPlaced := make(map[string]bool, len(entries))
	mergedSeen := make(map[string]bool)

	for _, e := range entries {
		if !e.isMerge {
			om.Set(e.key, e.val)
			explicitPlaced[e.key] = true
			continue
		}
		srcs, err := extractMergeSourceMaps(e.val)
		if err != nil {
			return nil, err
		}
		for _, src := range srcs {
			for _, f := range src.Fields {
				if explicitPlaced[f.Key] || mergedSeen[f.Key] {
					continue
				}
				mergedSeen[f.Key] = true
				om.Set(f.Key, deepCloneYAMLValue(f.Value))
			}
		}
	}
	return om, nil
}

func (p *yamlParser) parseDocument() (any, error) {
	if p.anchors == nil {
		p.anchors = make(map[string]any)
	}
	p.skipBlankAndComments()
	if p.pos >= len(p.rawLines) {
		return nil, nil
	}
	indent := countLeadingSpaces(p.rawLines[p.pos])
	return p.parseNode(indent)
}

func (p *yamlParser) skipBlankAndComments() {
	for p.pos < len(p.rawLines) {
		stripped := strings.TrimSpace(stripComment(p.rawLines[p.pos]))
		if stripped == "" {
			p.pos++
			continue
		}
		break
	}
}

func (p *yamlParser) parseNode(minIndent int) (any, error) {
	p.skipBlankAndComments()
	if p.pos >= len(p.rawLines) {
		return nil, nil
	}
	line := p.rawLines[p.pos]
	indent := countLeadingSpaces(line)
	if indent < minIndent {
		return nil, nil
	}
	trimmed := strings.TrimSpace(stripComment(line))
	if strings.HasPrefix(trimmed, "&") {
		anchorName, afterAnc, hasAnc, err := extractLeadingAnchor(trimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos+1, err)
		}
		if hasAnc {
			if afterAnc == "" {
				p.pos++
				val, err := p.parseNode(minIndent)
				if err != nil {
					return nil, err
				}
				p.setAnchor(anchorName, val)
				return val, nil
			}
			lineIdx := p.pos
			orig := p.rawLines[lineIdx]
			p.rawLines[lineIdx] = strings.Repeat(" ", indent) + afterAnc
			val, err := p.parseNode(minIndent)
			p.rawLines[lineIdx] = orig
			if err != nil {
				return nil, err
			}
			p.setAnchor(anchorName, val)
			return val, nil
		}
	}
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		return p.parseSequence(indent)
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		flowStr, err := p.collectFlowLines()
		if err != nil {
			return nil, err
		}
		return p.parseFlowValue(flowStr)
	}
	if _, _, ok := splitKeyValue(trimmed); ok {
		return p.parseMapping(indent)
	}
	if isBlockScalarIndicator(trimmed) {
		p.pos++
		return p.parseBlockScalar(trimmed, indent-1)
	}
	p.pos++
	return p.parseScalarOrAlias(trimmed)
}

func (p *yamlParser) collectFlowLines() (string, error) {
	var sb strings.Builder
	depthBrace := 0
	depthBracket := 0
	inSingle := false
	inDouble := false
	escaped := false

	startLine := p.pos + 1
	for p.pos < len(p.rawLines) {
		line := stripComment(p.rawLines[p.pos])
		p.pos++
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(strings.TrimSpace(line))
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if escaped {
				escaped = false
				continue
			}
			if inDouble && ch == '\\' {
				escaped = true
				continue
			}
			if ch == '\'' && !inDouble {
				if inSingle && i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				inSingle = !inSingle
				continue
			}
			if ch == '"' && !inSingle {
				inDouble = !inDouble
				continue
			}
			if inSingle || inDouble {
				continue
			}
			switch ch {
			case '{':
				depthBrace++
			case '}':
				depthBrace--
			case '[':
				depthBracket++
			case ']':
				depthBracket--
			}
		}
		if depthBrace <= 0 && depthBracket <= 0 && !inSingle && !inDouble {
			return sb.String(), nil
		}
	}
	return "", fmt.Errorf("line %d: unclosed flow collection", startLine)
}

func (p *yamlParser) parseSequence(seqIndent int) ([]any, error) {
	var items []any
	for {
		p.skipBlankAndComments()
		if p.pos >= len(p.rawLines) {
			break
		}
		line := p.rawLines[p.pos]
		indent := countLeadingSpaces(line)
		if indent != seqIndent {
			break
		}
		trimmed := strings.TrimSpace(stripComment(line))
		if trimmed != "-" && !strings.HasPrefix(trimmed, "- ") {
			break
		}

		if trimmed == "-" {
			p.pos++
			p.skipBlankAndComments()
			if p.pos >= len(p.rawLines) || countLeadingSpaces(p.rawLines[p.pos]) <= seqIndent {
				items = append(items, nil)
				continue
			}
			childIndent := countLeadingSpaces(p.rawLines[p.pos])
			val, err := p.parseNode(childIndent)
			if err != nil {
				return nil, err
			}
			items = append(items, val)
			continue
		}

		// Line starts with "- "
		afterDash := trimmed[1:]
		leadingSpacesAfterDash := countLeadingSpaces(afterDash)
		if leadingSpacesAfterDash < 1 {
			leadingSpacesAfterDash = 1
		}
		rest := strings.TrimSpace(afterDash)
		itemIndent := seqIndent + 1 + leadingSpacesAfterDash

		anchorName, afterAnc, hasAnc, err := extractLeadingAnchor(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos+1, err)
		}
		if hasAnc {
			rest = afterAnc
			if rest == "" {
				p.pos++
				p.skipBlankAndComments()
				if p.pos >= len(p.rawLines) || countLeadingSpaces(p.rawLines[p.pos]) <= seqIndent {
					p.setAnchor(anchorName, nil)
					items = append(items, nil)
					continue
				}
				childIndent := countLeadingSpaces(p.rawLines[p.pos])
				val, err := p.parseNode(childIndent)
				if err != nil {
					return nil, err
				}
				p.setAnchor(anchorName, val)
				items = append(items, val)
				continue
			}
		}

		if isBlockScalarIndicator(rest) {
			p.pos++
			str, err := p.parseBlockScalar(rest, seqIndent)
			if err != nil {
				return nil, err
			}
			if hasAnc {
				p.setAnchor(anchorName, str)
			}
			items = append(items, str)
			continue
		}

		if strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[") {
			lineIdx := p.pos
			orig := p.rawLines[lineIdx]
			p.rawLines[lineIdx] = strings.Repeat(" ", itemIndent) + rest
			flowStr, err := p.collectFlowLines()
			p.rawLines[lineIdx] = orig
			if err != nil {
				return nil, err
			}
			val, err := p.parseFlowValue(flowStr)
			if err != nil {
				return nil, err
			}
			if hasAnc {
				p.setAnchor(anchorName, val)
			}
			items = append(items, val)
			continue
		}

		if _, _, ok := splitKeyValue(rest); ok {
			// Compact mapping inside sequence item: rewrite `- key: val` as `  key: val` at itemIndent
			lineIdx := p.pos
			orig := p.rawLines[lineIdx]
			p.rawLines[lineIdx] = strings.Repeat(" ", itemIndent) + rest
			val, err := p.parseMapping(itemIndent)
			p.rawLines[lineIdx] = orig
			if err != nil {
				return nil, err
			}
			if hasAnc {
				p.setAnchor(anchorName, val)
			}
			items = append(items, val)
			continue
		}

		p.pos++
		val, err := p.parseScalarOrAlias(rest)
		if err != nil {
			return nil, err
		}
		if hasAnc {
			p.setAnchor(anchorName, val)
		}
		items = append(items, val)
	}
	return items, nil
}

func (p *yamlParser) parseMapping(mapIndent int) (*OrderedMap, error) {
	var entries []parsedMapEntry
	for {
		p.skipBlankAndComments()
		if p.pos >= len(p.rawLines) {
			break
		}
		line := p.rawLines[p.pos]
		indent := countLeadingSpaces(line)
		if indent != mapIndent {
			if indent > mapIndent {
				return nil, fmt.Errorf("line %d: unexpected indentation %d (expected %d)", p.pos+1, indent, mapIndent)
			}
			break
		}
		trimmed := strings.TrimSpace(stripComment(line))
		if trimmed == "-" || strings.HasPrefix(trimmed, "- ") {
			break
		}
		rawKey, rawVal, ok := splitKeyValue(trimmed)
		if !ok {
			return nil, fmt.Errorf("line %d: expected mapping key: value, got %q", p.pos+1, trimmed)
		}
		isMerge := strings.TrimSpace(rawKey) == "<<"
		key, err := parseKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos+1, err)
		}
		valTrimmed := strings.TrimSpace(rawVal)

		anchorName, afterAnc, hasAnc, err := extractLeadingAnchor(valTrimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos+1, err)
		}
		if hasAnc {
			valTrimmed = afterAnc
		}

		recordEntry := func(v any) {
			if hasAnc {
				p.setAnchor(anchorName, v)
			}
			entries = append(entries, parsedMapEntry{isMerge: isMerge, key: key, val: v})
		}

		if valTrimmed == "" {
			p.pos++
			p.skipBlankAndComments()
			if p.pos >= len(p.rawLines) {
				recordEntry(nil)
				break
			}
			nextIndent := countLeadingSpaces(p.rawLines[p.pos])
			if nextIndent < mapIndent {
				recordEntry(nil)
				continue
			}
			if nextIndent == mapIndent {
				nextTrimmed := strings.TrimSpace(stripComment(p.rawLines[p.pos]))
				if nextTrimmed == "-" || strings.HasPrefix(nextTrimmed, "- ") {
					seqVal, err := p.parseSequence(nextIndent)
					if err != nil {
						return nil, err
					}
					recordEntry(seqVal)
					continue
				}
				recordEntry(nil)
				continue
			}
			childVal, err := p.parseNode(nextIndent)
			if err != nil {
				return nil, err
			}
			recordEntry(childVal)
			continue
		}

		if isBlockScalarIndicator(valTrimmed) {
			p.pos++
			str, err := p.parseBlockScalar(valTrimmed, mapIndent)
			if err != nil {
				return nil, err
			}
			recordEntry(str)
			continue
		}

		if strings.HasPrefix(valTrimmed, "{") || strings.HasPrefix(valTrimmed, "[") {
			lineIdx := p.pos
			orig := p.rawLines[lineIdx]
			p.rawLines[lineIdx] = strings.Repeat(" ", mapIndent) + valTrimmed
			flowStr, err := p.collectFlowLines()
			p.rawLines[lineIdx] = orig
			if err != nil {
				return nil, err
			}
			val, err := p.parseFlowValue(flowStr)
			if err != nil {
				return nil, err
			}
			recordEntry(val)
			continue
		}

		p.pos++
		val, err := p.parseScalarOrAlias(valTrimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos, err)
		}
		recordEntry(val)
	}
	return buildMergedOrderedMap(entries)
}

func (p *yamlParser) parseBlockScalar(indicator string, parentIndent int) (string, error) {
	folded, chomp, explicitIndent, ok := parseBlockScalarHeader(indicator)
	if !ok {
		return "", fmt.Errorf("invalid block scalar indicator %q", indicator)
	}

	var blockLines []string
	contentIndent := -1
	if explicitIndent > 0 {
		baseIndent := parentIndent
		if baseIndent < 0 {
			baseIndent = 0
		}
		contentIndent = baseIndent + explicitIndent
	}

	for p.pos < len(p.rawLines) {
		raw := p.rawLines[p.pos]
		trimmed := strings.TrimSpace(raw)
		indent := countLeadingSpaces(raw)

		if trimmed == "" {
			blockLines = append(blockLines, "")
			p.pos++
			continue
		}
		if indent <= parentIndent {
			break
		}
		if contentIndent == -1 {
			contentIndent = indent
		}
		if indent >= contentIndent {
			blockLines = append(blockLines, raw[contentIndent:])
		} else {
			blockLines = append(blockLines, strings.TrimLeft(raw, " "))
		}
		p.pos++
	}

	// Trim trailing empty lines for clip/strip
	trailingNewlines := 0
	for len(blockLines) > 0 && blockLines[len(blockLines)-1] == "" {
		blockLines = blockLines[:len(blockLines)-1]
		trailingNewlines++
	}

	isMoreIndented := func(s string) bool {
		return len(s) > 0 && (s[0] == ' ' || s[0] == '\t')
	}

	var result string
	if !folded {
		result = strings.Join(blockLines, "\n")
	} else {
		var sb strings.Builder
		for i, l := range blockLines {
			if i > 0 {
				if l == "" || blockLines[i-1] == "" || isMoreIndented(l) || isMoreIndented(blockLines[i-1]) {
					sb.WriteByte('\n')
				} else {
					sb.WriteByte(' ')
				}
			}
			sb.WriteString(l)
		}
		result = sb.String()
	}

	switch chomp {
	case "strip":
		return result, nil
	case "keep":
		return result + "\n" + strings.Repeat("\n", trailingNewlines), nil
	default: // clip
		if len(blockLines) == 0 {
			return "", nil
		}
		return result + "\n", nil
	}
}

func countLeadingSpaces(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			n++
		case '\t':
			n += 2
		default:
			return n
		}
	}
	return n
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			if inSingle && i+1 < len(line) && line[i+1] == '\'' {
				i++
				continue
			}
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && ch == '#' {
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

func splitKeyValue(s string) (string, string, bool) {
	trimmedStart := strings.TrimLeft(s, " \t")
	startsQuoted := len(trimmedStart) > 0 && (trimmedStart[0] == '"' || trimmedStart[0] == '\'')
	afterQuotedKey := false

	inSingle := false
	inDouble := false
	escaped := false
	depthBrace := 0
	depthBracket := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			if inSingle && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingle = !inSingle
			if !inSingle && startsQuoted && depthBrace == 0 && depthBracket == 0 {
				afterQuotedKey = true
				startsQuoted = false
			}
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			if !inDouble && startsQuoted && depthBrace == 0 && depthBracket == 0 {
				afterQuotedKey = true
				startsQuoted = false
			}
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if afterQuotedKey && ch != ' ' && ch != '\t' && ch != ':' {
			afterQuotedKey = false
		}
		switch ch {
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case '[':
			depthBracket++
		case ']':
			depthBracket--
		case ':':
			if depthBrace == 0 && depthBracket == 0 {
				if afterQuotedKey || i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
					return strings.TrimSpace(s[:i]), s[i+1:], true
				}
			}
		}
	}
	return "", "", false
}

func parseKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty mapping key")
	}
	if (strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"")) ||
		(strings.HasPrefix(raw, "'") && strings.HasSuffix(raw, "'")) {
		v, err := parseScalar(raw)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%v", v), nil
	}
	return raw, nil
}

func isBareInfOrNaN(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	return strings.EqualFold(s, "inf") || strings.EqualFold(s, "infinity") || strings.EqualFold(s, "nan")
}

func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "Null" || s == "NULL" || s == "~" {
		return nil, nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		inner := s[1 : len(s)-1]
		return strings.ReplaceAll(inner, "''", "'"), nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unquoteDouble(s[1 : len(s)-1])
	}
	switch s {
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	}
	if strings.ContainsRune(s, '_') || isBareInfOrNaN(s) {
		return s, nil
	}
	if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
		return iv, nil
	}
	if !strings.ContainsAny(s, ".eE") {
		unsignedCand := strings.TrimPrefix(s, "+")
		if unsignedCand != "" {
			if uv, err := strconv.ParseUint(unsignedCand, 10, 64); err == nil {
				return uv, nil
			}
		}
	}
	if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		return fv, nil
	}
	return s, nil
}

func unquoteDouble(inner string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		if ch != '\\' {
			sb.WriteByte(ch)
			continue
		}
		if i+1 >= len(inner) {
			return "", fmt.Errorf("trailing backslash in double-quoted string")
		}
		i++
		esc := inner[i]
		switch esc {
		case '"':
			sb.WriteByte('"')
		case '\\':
			sb.WriteByte('\\')
		case '/':
			sb.WriteByte('/')
		case '0':
			sb.WriteByte(0)
		case 'a':
			sb.WriteByte('\a')
		case 'b':
			sb.WriteByte('\b')
		case 't', '\t':
			sb.WriteByte('\t')
		case 'n':
			sb.WriteByte('\n')
		case 'v':
			sb.WriteByte('\v')
		case 'f':
			sb.WriteByte('\f')
		case 'r':
			sb.WriteByte('\r')
		case 'e':
			sb.WriteByte(0x1b)
		case ' ':
			sb.WriteByte(' ')
		case 'N':
			sb.WriteRune('\u0085')
		case '_':
			sb.WriteRune('\u00a0')
		case 'L':
			sb.WriteRune('\u2028')
		case 'P':
			sb.WriteRune('\u2029')
		case '.':
			// Support escaped dots inside rest-api-spec double-quoted paths (e.g. "indices.my\\.idx" or "indices.my\.idx")
			sb.WriteString(`\.`)
		case 'x':
			if i+2 >= len(inner) {
				return "", fmt.Errorf("invalid \\x escape in double-quoted string")
			}
			code, err := strconv.ParseUint(inner[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("invalid \\x escape in double-quoted string: %w", err)
			}
			// #nosec G115 -- 2-hex-digit escape fits in 8-bit Unicode code point (<= 0xFF)
			sb.WriteRune(rune(code))
			i += 2
		case 'u':
			if i+4 >= len(inner) {
				return "", fmt.Errorf("invalid unicode escape in double-quoted string")
			}
			code, err := strconv.ParseUint(inner[i+1:i+5], 16, 16)
			if err != nil {
				return "", err
			}
			// #nosec G115 -- 4-hex-digit unicode escape fits in 16-bit code point (<= 0xFFFF)
			sb.WriteRune(rune(code))
			i += 4
		case 'U':
			if i+8 >= len(inner) {
				return "", fmt.Errorf("invalid \\U escape in double-quoted string")
			}
			code, err := strconv.ParseUint(inner[i+1:i+9], 16, 32)
			if err != nil {
				return "", fmt.Errorf("invalid \\U escape in double-quoted string: %w", err)
			}
			if code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF) {
				return "", fmt.Errorf("unicode code point U+%X out of range in \\U escape", code)
			}
			// #nosec G115 -- validated <= 0x10FFFF (utf8.MaxRune)
			sb.WriteRune(rune(code))
			i += 8
		default:
			return "", fmt.Errorf("invalid escape sequence \\%c in double-quoted string", esc)
		}
	}
	return sb.String(), nil
}

func (p *yamlParser) parseFlowValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	anchorName, afterAnc, hasAnc, err := extractLeadingAnchor(s)
	if err != nil {
		return nil, err
	}
	if hasAnc {
		if afterAnc == "" {
			return nil, fmt.Errorf("anchor &%s without value in flow context", anchorName)
		}
		val, err := p.parseFlowValue(afterAnc)
		if err != nil {
			return nil, err
		}
		p.setAnchor(anchorName, val)
		return val, nil
	}

	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("unclosed flow mapping: %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return NewOrderedMap(), nil
		}
		parts, err := splitTopLevelFlow(inner, ',')
		if err != nil {
			return nil, err
		}
		var entries []parsedMapEntry
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			rawK, rawV, ok := splitFlowKeyValue(part)
			if !ok {
				return nil, fmt.Errorf("invalid flow mapping entry %q", part)
			}
			isMerge := strings.TrimSpace(rawK) == "<<"
			k, err := parseKey(rawK)
			if err != nil {
				return nil, err
			}
			v, err := p.parseFlowElement(strings.TrimSpace(rawV))
			if err != nil {
				return nil, err
			}
			entries = append(entries, parsedMapEntry{isMerge: isMerge, key: k, val: v})
		}
		return buildMergedOrderedMap(entries)
	}
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unclosed flow sequence: %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		parts, err := splitTopLevelFlow(inner, ',')
		if err != nil {
			return nil, err
		}
		var out []any
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			v, err := p.parseFlowElement(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return p.parseScalarOrAlias(s)
}

func (p *yamlParser) parseFlowElement(s string) (any, error) {
	s = strings.TrimSpace(s)
	anchorName, afterAnc, hasAnc, err := extractLeadingAnchor(s)
	if err != nil {
		return nil, err
	}
	if hasAnc {
		if afterAnc == "" {
			return nil, fmt.Errorf("anchor &%s without value in flow collection", anchorName)
		}
		val, err := p.parseFlowElement(afterAnc)
		if err != nil {
			return nil, err
		}
		p.setAnchor(anchorName, val)
		return val, nil
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return p.parseFlowValue(s)
	}
	return p.parseScalarOrAlias(s)
}

func splitTopLevelFlow(s string, sep byte) ([]string, error) {
	var parts []string
	start := 0
	inSingle := false
	inDouble := false
	escaped := false
	depthBrace := 0
	depthBracket := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			if inSingle && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		switch ch {
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case '[':
			depthBracket++
		case ']':
			depthBracket--
		default:
			if ch == sep && depthBrace == 0 && depthBracket == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if inSingle || inDouble || depthBrace != 0 || depthBracket != 0 {
		return nil, fmt.Errorf("unbalanced quotes or brackets in flow expression %q", s)
	}
	parts = append(parts, s[start:])
	return parts, nil
}

func splitFlowKeyValue(s string) (string, string, bool) {
	trimmedStart := strings.TrimLeft(s, " \t")
	startsQuoted := len(trimmedStart) > 0 && (trimmedStart[0] == '"' || trimmedStart[0] == '\'')
	afterQuotedKey := false

	inSingle := false
	inDouble := false
	escaped := false
	depthBrace := 0
	depthBracket := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			if inSingle && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingle = !inSingle
			if !inSingle && startsQuoted && depthBrace == 0 && depthBracket == 0 {
				afterQuotedKey = true
				startsQuoted = false
			}
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			if !inDouble && startsQuoted && depthBrace == 0 && depthBracket == 0 {
				afterQuotedKey = true
				startsQuoted = false
			}
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if afterQuotedKey && ch != ' ' && ch != '\t' && ch != ':' {
			afterQuotedKey = false
		}
		switch ch {
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case '[':
			depthBracket++
		case ']':
			depthBracket--
		case ':':
			if depthBrace == 0 && depthBracket == 0 {
				if afterQuotedKey || i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' || s[i+1] == ',' || s[i+1] == '}' {
					return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
				}
			}
		}
	}
	return "", "", false
}

// findClosingQuoteOnLine searches line from startIdx for the closing delimiter of openQuote ('"' or '\”).
// Returns the byte index of the closing quote, or -1 if the quote remains open past EOL.
func findClosingQuoteOnLine(line string, startIdx int, openQuote byte) int {
	if openQuote == '\'' {
		for i := startIdx; i < len(line); i++ {
			if line[i] == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				return i
			}
		}
		return -1
	}
	escaped := false
	for i := startIdx; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if line[i] == '\\' {
			escaped = true
			continue
		}
		if line[i] == '"' {
			return i
		}
	}
	return -1
}

// advanceOpenQuoteOnLine advances an open multiline quote across a continuation line during document chunking.
func advanceOpenQuoteOnLine(line string, openQuote byte, flowDepth int) (byte, int) {
	closeIdx := findClosingQuoteOnLine(line, 0, openQuote)
	if closeIdx < 0 {
		return openQuote, flowDepth
	}
	nextQuote, _, nextDepth := scanLineForUnclosedQuote(line, closeIdx+1, false, true, flowDepth)
	return nextQuote, nextDepth
}

// scanLineForUnclosedQuote scans line from startIdx outside block scalars and returns an unclosed quote
// character ('"' or '\”), its opening byte index on line, and the updated flow collection nesting depth.
// Quotes inside comments or mid-word inside plain scalars (e.g. `reason: doesn't match`) do not start quoted scalars.
func scanLineForUnclosedQuote(line string, startIdx int, nodeStart, justClosedQuote bool, flowDepth int) (byte, int, int) {
	for i := startIdx; i < len(line); i++ {
		ch := line[i]
		if ch == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return 0, -1, flowDepth
		}
		if ch == ' ' || ch == '\t' {
			continue
		}
		if nodeStart {
			if ch == '-' && flowDepth == 0 && i+1 < len(line) && (line[i+1] == ' ' || line[i+1] == '\t') {
				continue
			}
			if ch == '&' {
				j := i + 1
				for j < len(line) && !isAnchorStopByte(line[j]) {
					j++
				}
				i = j - 1
				continue
			}
			switch ch {
			case '{', '[':
				flowDepth++
				nodeStart = true
				justClosedQuote = false
				continue
			case '}', ']':
				if flowDepth > 0 {
					flowDepth--
				}
				nodeStart = false
				justClosedQuote = false
				continue
			case ',':
				if flowDepth > 0 {
					nodeStart = true
				}
				justClosedQuote = false
				continue
			case '"', '\'':
				closeIdx := findClosingQuoteOnLine(line, i+1, ch)
				if closeIdx < 0 {
					return ch, i, flowDepth
				}
				i = closeIdx
				nodeStart = false
				justClosedQuote = true
				continue
			default:
				nodeStart = false
				justClosedQuote = false
			}
		}

		switch ch {
		case '{', '[':
			flowDepth++
			nodeStart = true
			justClosedQuote = false
		case '}', ']':
			if flowDepth > 0 {
				flowDepth--
			}
			justClosedQuote = false
		case ',':
			if flowDepth > 0 {
				nodeStart = true
			}
			justClosedQuote = false
		case ':':
			isSep := justClosedQuote || i+1 == len(line) || line[i+1] == ' ' || line[i+1] == '\t' ||
				(flowDepth > 0 && (line[i+1] == ',' || line[i+1] == '}'))
			if isSep {
				nodeStart = true
			}
			justClosedQuote = false
		default:
			justClosedQuote = false
		}
	}
	return 0, -1, flowDepth
}

func hasTrailingUnescapedBackslash(s string) bool {
	backslashes := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func trimUnescapedTrailingHWS(s string) string {
	keepEnd := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			keepEnd = i + 1
			continue
		}
		if s[i] == '\\' {
			escaped = true
			keepEnd = i + 1
			continue
		}
		if s[i] != ' ' && s[i] != '\t' {
			keepEnd = i + 1
		}
	}
	return s[:keepEnd]
}

func foldSingleQuotedSegments(segs []string) string {
	var sb strings.Builder
	sb.WriteString(strings.TrimRight(segs[0], " \t"))
	emptyCount := 0
	for idx := 1; idx < len(segs); idx++ {
		seg := segs[idx]
		isLast := idx == len(segs)-1
		if !isLast && strings.Trim(seg, " \t") == "" {
			emptyCount++
			continue
		}
		if emptyCount > 0 {
			sb.WriteString(strings.Repeat("\n", emptyCount))
		} else {
			sb.WriteByte(' ')
		}
		emptyCount = 0
		trimmedLeft := strings.TrimLeft(seg, " \t")
		if !isLast {
			trimmedLeft = strings.TrimRight(trimmedLeft, " \t")
		}
		sb.WriteString(trimmedLeft)
	}
	return sb.String()
}

func foldDoubleQuotedSegments(segs []string) string {
	var sb strings.Builder
	escapedBreak := hasTrailingUnescapedBackslash(segs[0])
	if escapedBreak {
		sb.WriteString(segs[0][:len(segs[0])-1])
	} else {
		sb.WriteString(trimUnescapedTrailingHWS(segs[0]))
	}
	emptyCount := 0
	for idx := 1; idx < len(segs); idx++ {
		seg := segs[idx]
		isLast := idx == len(segs)-1
		trimmedLeft := strings.TrimLeft(seg, " \t")

		if escapedBreak {
			escapedBreak = false
			if !isLast && trimmedLeft == "" {
				// Escaped line break consumed the newline and leading HWS on this empty line;
				// this empty line's own trailing newline now folds normally.
				emptyCount = 0
				continue
			}
			if !isLast {
				if hasTrailingUnescapedBackslash(trimmedLeft) {
					escapedBreak = true
					sb.WriteString(trimmedLeft[:len(trimmedLeft)-1])
				} else {
					sb.WriteString(trimUnescapedTrailingHWS(trimmedLeft))
				}
			} else {
				sb.WriteString(trimmedLeft)
			}
			continue
		}

		if !isLast && trimmedLeft == "" {
			emptyCount++
			continue
		}
		if emptyCount > 0 {
			sb.WriteString(strings.Repeat(`\n`, emptyCount))
		} else {
			sb.WriteByte(' ')
		}
		emptyCount = 0
		if !isLast {
			if hasTrailingUnescapedBackslash(trimmedLeft) {
				escapedBreak = true
				sb.WriteString(trimmedLeft[:len(trimmedLeft)-1])
			} else {
				sb.WriteString(trimUnescapedTrailingHWS(trimmedLeft))
			}
		} else {
			sb.WriteString(trimmedLeft)
		}
	}
	return sb.String()
}

// preprocessLines joins multiline single- and double-quoted scalars across physical lines
// according to YAML 1.2 line-folding rules while leaving block scalars untouched.
func preprocessLines(rawLines []string) ([]string, error) {
	out := make([]string, 0, len(rawLines))
	inBlockScalar := false
	blockIndent := 0
	flowDepth := 0

	for idx := 0; idx < len(rawLines); idx++ {
		line := rawLines[idx]
		trimmed := strings.TrimSpace(line)
		indent := countLeadingSpaces(line)

		if inBlockScalar {
			if trimmed != "" && indent <= blockIndent {
				inBlockScalar = false
			} else {
				out = append(out, line)
				continue
			}
		}

		stripped := stripComment(line)
		if isBlockScalarHeaderLine(strings.TrimSpace(stripped)) {
			inBlockScalar = true
			blockIndent = indent
			out = append(out, line)
			continue
		}

		startLineNum := idx + 1
		scanOffset := 0
		nodeStart := true
		justClosedQuote := false

		for {
			openQuote, openIdx, nextDepth := scanLineForUnclosedQuote(line, scanOffset, nodeStart, justClosedQuote, flowDepth)
			flowDepth = nextDepth
			if openQuote == 0 {
				break
			}

			prefix := line[:openIdx]
			segs := []string{line[openIdx+1:]}
			closed := false
			var suffix string

			for idx+1 < len(rawLines) {
				idx++
				contLine := rawLines[idx]
				closeIdx := findClosingQuoteOnLine(contLine, 0, openQuote)
				if closeIdx >= 0 {
					segs = append(segs, contLine[:closeIdx])
					suffix = contLine[closeIdx+1:]
					closed = true
					break
				}
				segs = append(segs, contLine)
			}
			if !closed {
				return nil, fmt.Errorf("line %d: unclosed %c-quoted scalar", startLineNum, openQuote)
			}

			var folded string
			if openQuote == '\'' {
				folded = foldSingleQuotedSegments(segs)
			} else {
				folded = foldDoubleQuotedSegments(segs)
			}

			qStr := string(openQuote)
			line = prefix + qStr + folded + qStr + suffix
			scanOffset = len(prefix) + 1 + len(folded) + 1
			nodeStart = false
			justClosedQuote = true
		}

		out = append(out, line)
	}
	return out, nil
}
