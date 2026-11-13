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

	for _, line := range rawLines {
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
			continue
		}
		if trimmed == "..." && indent == 0 {
			if len(current) > 0 {
				docChunks = append(docChunks, current)
				current = nil
			}
			continue
		}

		// Detect if this line starts a block scalar (`|` or `>`)
		stripped := stripComment(line)
		trimmedStripped := strings.TrimSpace(stripped)
		if isBlockScalarHeaderLine(trimmedStripped) {
			inBlockScalar = true
			blockIndent = indent
		}

		current = append(current, line)
	}
	if len(current) > 0 {
		docChunks = append(docChunks, current)
	}

	var docs []any
	for _, chunk := range docChunks {
		p := &yamlParser{rawLines: chunk}
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
	if isBlockScalarIndicator(trimmed) {
		return true
	}
	_, valPart, ok := splitKeyValue(trimmed)
	if ok && isBlockScalarIndicator(strings.TrimSpace(valPart)) {
		return true
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
}

func (p *yamlParser) parseDocument() (any, error) {
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
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		return p.parseSequence(indent)
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		flowStr, err := p.collectFlowLines()
		if err != nil {
			return nil, err
		}
		return parseFlowValue(flowStr)
	}
	if _, _, ok := splitKeyValue(trimmed); ok {
		return p.parseMapping(indent)
	}
	if isBlockScalarIndicator(trimmed) {
		p.pos++
		return p.parseBlockScalar(trimmed, indent-1)
	}
	p.pos++
	return parseScalar(trimmed)
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

		if isBlockScalarIndicator(rest) {
			p.pos++
			str, err := p.parseBlockScalar(rest, seqIndent)
			if err != nil {
				return nil, err
			}
			items = append(items, str)
			continue
		}

		if strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[") {
			// Replace current line temporarily or parse inline flow if balanced
			lineIdx := p.pos
			orig := p.rawLines[lineIdx]
			p.rawLines[lineIdx] = strings.Repeat(" ", itemIndent) + rest
			flowStr, err := p.collectFlowLines()
			p.rawLines[lineIdx] = orig
			if err != nil {
				return nil, err
			}
			val, err := parseFlowValue(flowStr)
			if err != nil {
				return nil, err
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
			items = append(items, val)
			continue
		}

		p.pos++
		val, err := parseScalar(rest)
		if err != nil {
			return nil, err
		}
		items = append(items, val)
	}
	return items, nil
}

func (p *yamlParser) parseMapping(mapIndent int) (*OrderedMap, error) {
	om := NewOrderedMap()
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
		key, err := parseKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos+1, err)
		}
		valTrimmed := strings.TrimSpace(rawVal)

		if valTrimmed == "" {
			p.pos++
			p.skipBlankAndComments()
			if p.pos >= len(p.rawLines) {
				om.Set(key, nil)
				break
			}
			nextIndent := countLeadingSpaces(p.rawLines[p.pos])
			if nextIndent < mapIndent {
				om.Set(key, nil)
				continue
			}
			if nextIndent == mapIndent {
				nextTrimmed := strings.TrimSpace(stripComment(p.rawLines[p.pos]))
				if nextTrimmed == "-" || strings.HasPrefix(nextTrimmed, "- ") {
					seqVal, err := p.parseSequence(nextIndent)
					if err != nil {
						return nil, err
					}
					om.Set(key, seqVal)
					continue
				}
				om.Set(key, nil)
				continue
			}
			childVal, err := p.parseNode(nextIndent)
			if err != nil {
				return nil, err
			}
			om.Set(key, childVal)
			continue
		}

		if isBlockScalarIndicator(valTrimmed) {
			p.pos++
			str, err := p.parseBlockScalar(valTrimmed, mapIndent)
			if err != nil {
				return nil, err
			}
			om.Set(key, str)
			continue
		}

		if strings.HasPrefix(valTrimmed, "{") || strings.HasPrefix(valTrimmed, "[") {
			p.rawLines[p.pos] = strings.Repeat(" ", mapIndent) + valTrimmed
			flowStr, err := p.collectFlowLines()
			if err != nil {
				return nil, err
			}
			val, err := parseFlowValue(flowStr)
			if err != nil {
				return nil, err
			}
			om.Set(key, val)
			continue
		}

		p.pos++
		val, err := parseScalar(valTrimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.pos, err)
		}
		om.Set(key, val)
	}
	return om, nil
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
		case ':':
			if depthBrace == 0 && depthBracket == 0 {
				if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' || (i > 0 && (s[i-1] == '"' || s[i-1] == '\'')) {
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
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case 'b':
			sb.WriteByte('\b')
		case 'f':
			sb.WriteByte('\f')
		case '.':
			// Support escaped dots inside rest-api-spec double-quoted paths (e.g. "indices.my\\.idx" or "indices.my\.idx")
			sb.WriteString(`\.`)
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
		default:
			sb.WriteByte('\\')
			sb.WriteByte(esc)
		}
	}
	return sb.String(), nil
}

func parseFlowValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("unclosed flow mapping: %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		om := NewOrderedMap()
		if inner == "" {
			return om, nil
		}
		parts, err := splitTopLevelFlow(inner, ',')
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			rawK, rawV, ok := splitFlowKeyValue(part)
			if !ok {
				return nil, fmt.Errorf("invalid flow mapping entry %q", part)
			}
			k, err := parseKey(rawK)
			if err != nil {
				return nil, err
			}
			v, err := parseFlowElement(strings.TrimSpace(rawV))
			if err != nil {
				return nil, err
			}
			om.Set(k, v)
		}
		return om, nil
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
			v, err := parseFlowElement(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return parseScalar(s)
}

func parseFlowElement(s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return parseFlowValue(s)
	}
	return parseScalar(s)
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
		case ':':
			if depthBrace == 0 && depthBracket == 0 {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}
