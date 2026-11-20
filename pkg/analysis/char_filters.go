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

package analysis

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// charStream tracks filtered runes alongside exact start/end character offsets in the original text.
type charStream struct {
	runes      []rune
	starts     []int
	ends       []int
	baseOffset int
	origEnd    int
}

func newCharStream(text string, baseOffset int) charStream {
	runes := []rune(text)
	starts := make([]int, len(runes))
	ends := make([]int, len(runes))
	off := baseOffset
	for i, r := range runes {
		starts[i] = off
		if r > 0xFFFF {
			off += 2
		} else {
			off++
		}
		ends[i] = off
	}
	return charStream{
		runes:      runes,
		starts:     starts,
		ends:       ends,
		baseOffset: baseOffset,
		origEnd:    off,
	}
}

func (cs charStream) String() string {
	return string(cs.runes)
}

func (cs charStream) sliceOffsets(runeStartIdx, runeEndIdx int) (int, int) {
	if len(cs.runes) == 0 || runeStartIdx >= len(cs.runes) {
		return cs.baseOffset, cs.origEnd
	}
	if runeStartIdx < 0 {
		runeStartIdx = 0
	}
	if runeEndIdx <= runeStartIdx {
		return cs.starts[runeStartIdx], cs.starts[runeStartIdx]
	}
	if runeEndIdx > len(cs.runes) {
		runeEndIdx = len(cs.runes)
	}
	return cs.starts[runeStartIdx], cs.ends[runeEndIdx-1]
}

type charStreamBuilder struct {
	runes      []rune
	starts     []int
	ends       []int
	baseOffset int
	origEnd    int
	exceeded   bool
}

func newCharStreamBuilder(in charStream) *charStreamBuilder {
	initCap := len(in.runes)
	if initCap > MaxCharFilterOutputRunes {
		initCap = MaxCharFilterOutputRunes
	}
	return &charStreamBuilder{
		runes:      make([]rune, 0, initCap),
		starts:     make([]int, 0, initCap),
		ends:       make([]int, 0, initCap),
		baseOffset: in.baseOffset,
		origEnd:    in.origEnd,
	}
}

func (b *charStreamBuilder) appendUnchanged(in charStream, idx int) {
	if b.exceeded {
		return
	}
	if len(b.runes)+1 > MaxCharFilterOutputRunes {
		b.exceeded = true
		return
	}
	b.runes = append(b.runes, in.runes[idx])
	b.starts = append(b.starts, in.starts[idx])
	b.ends = append(b.ends, in.ends[idx])
}

func (b *charStreamBuilder) appendRangeUnchanged(in charStream, fromIdx, toIdx int) {
	if b.exceeded || toIdx <= fromIdx {
		return
	}
	if len(b.runes)+(toIdx-fromIdx) > MaxCharFilterOutputRunes {
		b.exceeded = true
		return
	}
	b.runes = append(b.runes, in.runes[fromIdx:toIdx]...)
	b.starts = append(b.starts, in.starts[fromIdx:toIdx]...)
	b.ends = append(b.ends, in.ends[fromIdx:toIdx]...)
}

func (b *charStreamBuilder) appendReplacement(rep []rune, origStart, origEnd int) {
	if b.exceeded || len(rep) == 0 {
		return
	}
	if len(b.runes)+len(rep) > MaxCharFilterOutputRunes {
		b.exceeded = true
		return
	}
	for k, r := range rep {
		s := origStart + k
		if s > origEnd {
			s = origEnd
		}
		if k == 0 {
			s = origStart
		}
		e := origStart + k + 1
		if e > origEnd || k == len(rep)-1 {
			e = origEnd
		}
		b.runes = append(b.runes, r)
		b.starts = append(b.starts, s)
		b.ends = append(b.ends, e)
	}
}

func (b *charStreamBuilder) build() (charStream, error) {
	if b.exceeded || len(b.runes) > MaxCharFilterOutputRunes {
		return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
	}
	return charStream{
		runes:      b.runes,
		starts:     b.starts,
		ends:       b.ends,
		baseOffset: b.baseOffset,
		origEnd:    b.origEnd,
	}, nil
}

type compiledCharFilter struct {
	name  string
	apply func(charStream) (charStream, error)
}

var htmlBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"body": true, "br": true, "dd": true, "details": true, "div": true,
	"dl": true, "dt": true, "fieldset": true, "figcaption": true, "figure": true,
	"footer": true, "form": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "head": true, "header": true,
	"hr": true, "html": true, "li": true, "main": true, "nav": true,
	"ol": true, "p": true, "pre": true, "section": true, "table": true,
	"tbody": true, "td": true, "tfoot": true, "th": true, "thead": true,
	"title": true, "tr": true, "ul": true,
}

func buildCharFilter(displayName string, typeName string, def map[string]any, opts Options) (*compiledCharFilter, error) {
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "html_strip", "htmlstrip":
		escaped := make(map[string]bool)
		if def != nil {
			for _, tag := range extractStringSlice(def["escaped_tags"]) {
				escaped[strings.ToLower(strings.TrimSpace(tag))] = true
			}
			if ra, hasRA := def["read_ahead"]; hasRA {
				n, ok := extractInt(ra)
				if !ok || n < 0 {
					return nil, newIllegalArgError("read_ahead in html_strip must be a non-negative integer")
				}
			}
		}
		return &compiledCharFilter{
			name: displayName,
			apply: func(in charStream) (charStream, error) {
				return applyHTMLStrip(in, escaped)
			},
		}, nil

	case "mapping":
		var rawRules []string
		if def != nil {
			if pathVal, ok := def["mappings_path"].(string); ok && pathVal != "" {
				lines, err := resolvePathSetting("mappings_path", pathVal, opts)
				if err != nil {
					return nil, err
				}
				rawRules = append(rawRules, lines...)
			}
			rawRules = append(rawRules, extractStringSlice(def["mappings"])...)
		}
		pairs, err := parseMappingRules(rawRules)
		if err != nil {
			return nil, err
		}
		return &compiledCharFilter{
			name: displayName,
			apply: func(in charStream) (charStream, error) {
				return applyMappingCharFilter(in, pairs)
			},
		}, nil

	case "pattern_replace":
		if def == nil {
			return nil, newIllegalArgError("pattern_replace char filter requires [pattern]")
		}
		pat, _ := def["pattern"].(string)
		if pat == "" {
			if _, exists := def["pattern"]; !exists {
				return nil, newIllegalArgError("pattern is missing for [pattern_replace] char filter")
			}
		}
		flags, _ := def["flags"].(string)
		repl, _ := def["replacement"].(string)
		re, err := compileJavaRegex(pat, flags)
		if err != nil {
			return nil, err
		}
		return &compiledCharFilter{
			name: displayName,
			apply: func(in charStream) (charStream, error) {
				return applyPatternReplaceCharFilter(in, re, repl)
			},
		}, nil

	case "zero_width_spaces":
		return &compiledCharFilter{
			name: displayName,
			apply: func(in charStream) (charStream, error) {
				if len(in.runes) > MaxCharFilterOutputRunes {
					return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
				}
				b := newCharStreamBuilder(in)
				for i, r := range in.runes {
					if r == '\u200C' || r == '\u200D' || r == '\u200B' {
						b.appendReplacement([]rune{' '}, in.starts[i], in.ends[i])
					} else {
						b.appendUnchanged(in, i)
					}
					if b.exceeded {
						break
					}
				}
				return b.build()
			},
		}, nil

	case "icu_normalizer":
		return buildICUNormalizerCharFilter(displayName, def)

	case "kuromoji_iteration_mark", "japanese_iteration_mark":
		return buildKuromojiIterationMarkCharFilter(displayName, def)

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown char_filter type [%s] for [%s]", typeName, displayName))
	}
}

func resolvePathSetting(settingKey, pathVal string, opts Options) ([]string, error) {
	clean := strings.TrimSpace(pathVal)
	if clean == "jvm.options" || strings.Contains(clean, "..") || strings.HasSuffix(clean, "/jvm.options") {
		return nil, newIllegalArgError(fmt.Sprintf("Access denied trying to read file %s [%s]", settingKey, pathVal))
	}
	if opts.ResolveResourcePath != nil {
		lines, err := opts.ResolveResourcePath(settingKey, pathVal)
		if err != nil {
			if _, ok := AsAnalysisError(err); ok {
				return nil, err
			}
			return nil, newIllegalArgError(err.Error())
		}
		return lines, nil
	}
	return nil, nil
}

type mappingPair struct {
	src []rune
	dst []rune
}

func parseMappingRules(rules []string) ([]mappingPair, error) {
	var pairs []mappingPair
	for _, raw := range rules {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(raw, "=>")
		if idx < 0 {
			return nil, newIllegalArgError(fmt.Sprintf("Invalid mapping rule [%s]", raw))
		}
		lhs := unescapeMappingStr(strings.TrimSpace(raw[:idx]))
		rhs := unescapeMappingStr(strings.TrimSpace(raw[idx+2:]))
		if lhs == "" {
			return nil, newIllegalArgError(fmt.Sprintf("Empty source in mapping rule [%s]", raw))
		}
		pairs = append(pairs, mappingPair{
			src: []rune(lhs),
			dst: []rune(rhs),
		})
	}
	// Sort longest source first so greedy longest match wins deterministically.
	sort.SliceStable(pairs, func(i, j int) bool {
		return len(pairs[i].src) > len(pairs[j].src)
	})
	return pairs, nil
}

func unescapeMappingStr(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if r == '\\' && i+sz < len(s) {
			nr, nsz := utf8.DecodeRuneInString(s[i+sz:])
			switch nr {
			case 'n':
				b.WriteByte('\n')
				i += sz + nsz
				continue
			case 't':
				b.WriteByte('\t')
				i += sz + nsz
				continue
			case 'r':
				b.WriteByte('\r')
				i += sz + nsz
				continue
			case 'b':
				b.WriteByte('\b')
				i += sz + nsz
				continue
			case 'f':
				b.WriteByte('\f')
				i += sz + nsz
				continue
			case 'u':
				if i+sz+nsz+4 <= len(s) {
					hexStr := s[i+sz+nsz : i+sz+nsz+4]
					if v, err := strconv.ParseUint(hexStr, 16, 16); err == nil {
						b.WriteRune(rune(v))
						i += sz + nsz + 4
						continue
					}
				}
			default:
				b.WriteRune(nr)
				i += sz + nsz
				continue
			}
		}
		b.WriteRune(r)
		i += sz
	}
	return b.String()
}

func applyMappingCharFilter(in charStream, pairs []mappingPair) (charStream, error) {
	if len(in.runes) > MaxCharFilterOutputRunes {
		return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
	}
	if len(pairs) == 0 || len(in.runes) == 0 {
		return in, nil
	}
	b := newCharStreamBuilder(in)
	n := len(in.runes)
	for i := 0; i < n; {
		matched := false
		for _, p := range pairs {
			m := len(p.src)
			if i+m <= n && runesEqual(in.runes[i:i+m], p.src) {
				b.appendReplacement(p.dst, in.starts[i], in.ends[i+m-1])
				i += m
				matched = true
				break
			}
		}
		if !matched {
			b.appendUnchanged(in, i)
			i++
		}
		if b.exceeded {
			return b.build()
		}
	}
	return b.build()
}

func runesEqual(a, b []rune) bool {
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

func applyHTMLStrip(in charStream, escapedTags map[string]bool) (charStream, error) {
	n := len(in.runes)
	if n > MaxCharFilterOutputRunes {
		return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
	}
	if n == 0 {
		return in, nil
	}
	b := newCharStreamBuilder(in)
	noMoreCommentClose := false
	nextCommentClose := -1
	noMoreCDATAClose := false
	nextCDATAClose := -1
	noMorePIEnd := false
	checkedAnyGT := false
	noMoreRawClose := make(map[string]bool)
	var visitedPICloseFail []uint8
	var visitedTagCloseFail []uint8

	for i := 0; i < n; {
		r := in.runes[i]
		if r == '<' {
			// HTML comment <!-- ... -->
			if hasRunePrefix(in.runes[i:], "<!--") {
				if !noMoreCommentClose {
					if nextCommentClose < i+4 {
						scanFrom := i + 4
						if nextCommentClose+1 > scanFrom {
							scanFrom = nextCommentClose + 1
						}
						rel := indexRunes(in.runes[scanFrom:], "-->")
						if rel < 0 {
							noMoreCommentClose = true
						} else {
							nextCommentClose = scanFrom + rel
						}
					}
					if !noMoreCommentClose && nextCommentClose >= i+4 {
						i = nextCommentClose + 3
						continue
					}
				}
				b.appendUnchanged(in, i)
				if b.exceeded {
					return b.build()
				}
				i++
				continue
			}
			// CDATA <![CDATA[ ... ]]>
			if hasRunePrefixFold(in.runes[i:], "<![cdata[") {
				if !noMoreCDATAClose {
					if nextCDATAClose < i+9 {
						scanFrom := i + 9
						if nextCDATAClose+1 > scanFrom {
							scanFrom = nextCDATAClose + 1
						}
						rel := indexRunes(in.runes[scanFrom:], "]]>")
						if rel < 0 {
							noMoreCDATAClose = true
						} else {
							nextCDATAClose = scanFrom + rel
						}
					}
					if !noMoreCDATAClose && nextCDATAClose >= i+9 {
						b.appendRangeUnchanged(in, i+9, nextCDATAClose)
						if b.exceeded {
							return b.build()
						}
						i = nextCDATAClose + 3
						continue
					}
				}
				b.appendUnchanged(in, i)
				if b.exceeded {
					return b.build()
				}
				i++
				continue
			}
			// <!DOCTYPE ...> or <?...?>
			if !noMorePIEnd && i+1 < n && (in.runes[i+1] == '!' || in.runes[i+1] == '?') {
				endTag := findTagCloseMemo(in.runes, i+2, &visitedPICloseFail)
				if endTag >= 0 {
					i = endTag + 1
					continue
				}
				if !checkedAnyGT {
					checkedAnyGT = true
					if indexRunes(in.runes[i+2:], ">") < 0 {
						noMorePIEnd = true
					}
				}
			}
			// Standard tag <tag ...> or </tag>
			tagName, isClosing, endTag, ok := parseHTMLTagAtMemo(in.runes, i, &visitedTagCloseFail)
			if ok {
				lowerTag := strings.ToLower(tagName)
				if escapedTags[lowerTag] {
					b.appendRangeUnchanged(in, i, endTag+1)
					if b.exceeded {
						return b.build()
					}
					i = endTag + 1
					continue
				}
				if !isClosing && (lowerTag == "script" || lowerTag == "style") && !noMoreRawClose[lowerTag] {
					closeEnd := findClosingRawElementMemo(in.runes, endTag+1, lowerTag, &visitedTagCloseFail)
					if closeEnd >= 0 {
						i = closeEnd
						continue
					}
					noMoreRawClose[lowerTag] = true
				}
				if htmlBlockTags[lowerTag] {
					b.appendReplacement([]rune{'\n'}, in.starts[i], in.ends[endTag])
					if b.exceeded {
						return b.build()
					}
				}
				i = endTag + 1
				continue
			}
		}

		if r == '&' {
			semi := -1
			maxScan := i + 32
			if maxScan > n {
				maxScan = n
			}
			for j := i + 1; j < maxScan; j++ {
				cj := in.runes[j]
				if cj == ';' {
					semi = j
					break
				}
				if unicode.IsSpace(cj) || cj == '<' || cj == '&' {
					break
				}
			}
			if semi > i+1 {
				rawEnt := string(in.runes[i : semi+1])
				decoded := html.UnescapeString(rawEnt)
				if decoded != rawEnt {
					b.appendReplacement([]rune(decoded), in.starts[i], in.ends[semi])
					if b.exceeded {
						return b.build()
					}
					i = semi + 1
					continue
				}
			}
		}

		b.appendUnchanged(in, i)
		if b.exceeded {
			return b.build()
		}
		i++
	}
	return b.build()
}

func hasRunePrefix(runes []rune, prefix string) bool {
	idx := 0
	for _, p := range prefix {
		if idx >= len(runes) || runes[idx] != p {
			return false
		}
		idx++
	}
	return true
}

func hasRunePrefixFold(runes []rune, prefixLower string) bool {
	idx := 0
	for _, p := range prefixLower {
		if idx >= len(runes) {
			return false
		}
		r := runes[idx]
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		} else if r >= utf8.RuneSelf {
			r = unicode.ToLower(r)
		}
		if r != p {
			return false
		}
		idx++
	}
	return true
}

func indexRunes(haystack []rune, needle string) int {
	nr := []rune(needle)
	if len(nr) == 0 || len(haystack) < len(nr) {
		return -1
	}
	limit := len(haystack) - len(nr)
	for i := 0; i <= limit; i++ {
		if runesEqual(haystack[i:i+len(nr)], nr) {
			return i
		}
	}
	return -1
}

func htmlQuoteMask(quote rune) uint8 {
	switch quote {
	case '"':
		return 1 << 1
	case '\'':
		return 1 << 2
	default:
		return 1 << 0
	}
}

func markHTMLQuotePathFailed(runes []rune, start, stopAt int, visited *[]uint8) {
	if *visited == nil {
		*visited = make([]uint8, len(runes))
	}
	var quote rune
	for k := start; k < stopAt && k < len(runes); k++ {
		(*visited)[k] |= htmlQuoteMask(quote)
		c := runes[k]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
		} else if c == '"' || c == '\'' {
			quote = c
		}
	}
}

func findTagCloseMemo(runes []rune, start int, visited *[]uint8) int {
	var quote rune
	for j := start; j < len(runes); j++ {
		if *visited != nil && ((*visited)[j]&htmlQuoteMask(quote)) != 0 {
			markHTMLQuotePathFailed(runes, start, j, visited)
			return -1
		}
		c := runes[j]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			return j
		}
	}
	markHTMLQuotePathFailed(runes, start, len(runes), visited)
	return -1
}

func parseHTMLTagAtMemo(runes []rune, pos int, visited *[]uint8) (tagName string, isClosing bool, endIdx int, ok bool) {
	n := len(runes)
	if pos+2 >= n || runes[pos] != '<' {
		return "", false, -1, false
	}
	j := pos + 1
	if runes[j] == '/' {
		isClosing = true
		j++
	}
	if j >= n || !isASCIILetter(runes[j]) {
		return "", false, -1, false
	}
	nameStart := j
	for j < n && (isASCIILetter(runes[j]) || (runes[j] >= '0' && runes[j] <= '9') || runes[j] == '-' || runes[j] == ':') {
		j++
	}
	tagName = string(runes[nameStart:j])
	attrStart := j
	var quote rune
	for ; j < n; j++ {
		if *visited != nil && ((*visited)[j]&htmlQuoteMask(quote)) != 0 {
			markHTMLQuotePathFailed(runes, attrStart, j, visited)
			return "", false, -1, false
		}
		c := runes[j]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '<' {
			markHTMLQuotePathFailed(runes, attrStart, j, visited)
			return "", false, -1, false
		}
		if c == '>' {
			return tagName, isClosing, j, true
		}
	}
	markHTMLQuotePathFailed(runes, attrStart, n, visited)
	return "", false, -1, false
}

func findClosingRawElementMemo(runes []rune, start int, lowerTag string, visited *[]uint8) int {
	for j := start; j < len(runes); j++ {
		if runes[j] == '<' {
			tName, isClose, endTag, ok := parseHTMLTagAtMemo(runes, j, visited)
			if ok && isClose && strings.ToLower(tName) == lowerTag {
				return endTag + 1
			}
		}
	}
	return -1
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func compileJavaRegex(pattern string, flagsStr string) (*regexp.Regexp, error) {
	if len(pattern) > MaxRegexPatternBytes {
		return nil, newIllegalArgError(fmt.Sprintf("Regex pattern length [%d] exceeds maximum allowed [%d]", len(pattern), MaxRegexPatternBytes))
	}
	upperFlags := strings.ToUpper(flagsStr)
	if strings.Contains(upperFlags, "CANON_EQ") && countConsecutiveCombiningMarks(pattern) >= 3 {
		return nil, newIllegalArgError("Too complex regex pattern")
	}
	literal := false
	var flagChars strings.Builder
	if strings.TrimSpace(flagsStr) != "" {
		for _, part := range strings.Split(flagsStr, "|") {
			f := strings.ToUpper(strings.TrimSpace(part))
			switch f {
			case "":
			case "CASE_INSENSITIVE", "UNICODE_CASE":
				if !strings.ContainsRune(flagChars.String(), 'i') {
					flagChars.WriteByte('i')
				}
			case "MULTILINE":
				if !strings.ContainsRune(flagChars.String(), 'm') {
					flagChars.WriteByte('m')
				}
			case "DOTALL":
				if !strings.ContainsRune(flagChars.String(), 's') {
					flagChars.WriteByte('s')
				}
			case "LITERAL":
				literal = true
			case "CANON_EQ", "UNIX_LINES", "COMMENTS", "UNICODE_CHARACTER_CLASS":
				// Accepted Java Pattern flags without extra RE2 mode modifier.
			default:
				return nil, newIllegalArgError(fmt.Sprintf("Unknown regex flag [%s]", part))
			}
		}
	}
	expr := pattern
	if literal {
		expr = regexp.QuoteMeta(expr)
	}
	if flagChars.Len() > 0 {
		expr = "(?" + flagChars.String() + ")" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		if countConsecutiveCombiningMarks(pattern) >= 3 {
			return nil, newIllegalArgError("Too complex regex pattern")
		}
		return nil, newIllegalArgError(fmt.Sprintf("Invalid regex pattern [%s]: %v", pattern, err))
	}
	return re, nil
}

func countConsecutiveCombiningMarks(s string) int {
	maxRun := 0
	curRun := 0
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r) {
			curRun++
			if curRun > maxRun {
				maxRun = curRun
			}
		} else {
			curRun = 0
		}
	}
	return maxRun
}

func applyPatternReplaceCharFilter(in charStream, re *regexp.Regexp, repl string) (charStream, error) {
	if len(in.runes) > MaxCharFilterOutputRunes {
		return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
	}
	s := in.String()
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return in, nil
	}
	// Map byte index in s -> rune index in in.runes
	byteToRune := make([]int, len(s)+1)
	byteOff := 0
	for rIdx, r := range in.runes {
		sz := utf8.RuneLen(r)
		for k := 0; k < sz; k++ {
			byteToRune[byteOff+k] = rIdx
		}
		byteOff += sz
	}
	byteToRune[len(s)] = len(in.runes)

	b := newCharStreamBuilder(in)
	prevRune := 0
	for _, loc := range matches {
		mStartByte, mEndByte := loc[0], loc[1]
		mStartRune := byteToRune[mStartByte]
		mEndRune := byteToRune[mEndByte]
		if mStartRune < prevRune {
			continue
		}
		b.appendRangeUnchanged(in, prevRune, mStartRune)
		if b.exceeded {
			return b.build()
		}
		expanded := expandJavaReplacement(s, loc, repl)
		var origStart, origEnd int
		if mStartRune < len(in.runes) {
			origStart = in.starts[mStartRune]
		} else {
			origStart = in.origEnd
		}
		if mEndRune > mStartRune && mEndRune-1 < len(in.runes) {
			origEnd = in.ends[mEndRune-1]
		} else {
			origEnd = origStart
		}
		b.appendReplacement([]rune(expanded), origStart, origEnd)
		if b.exceeded {
			return b.build()
		}
		if mEndRune == mStartRune {
			if mStartRune < len(in.runes) {
				b.appendUnchanged(in, mStartRune)
				if b.exceeded {
					return b.build()
				}
				prevRune = mStartRune + 1
			} else {
				prevRune = mStartRune
			}
		} else {
			prevRune = mEndRune
		}
	}
	b.appendRangeUnchanged(in, prevRune, len(in.runes))
	return b.build()
}

func expandJavaReplacement(src string, loc []int, repl string) string {
	var out strings.Builder
	for i := 0; i < len(repl); {
		r, sz := utf8.DecodeRuneInString(repl[i:])
		if r == '\\' && i+sz < len(repl) {
			nr, nsz := utf8.DecodeRuneInString(repl[i+sz:])
			out.WriteRune(nr)
			i += sz + nsz
			continue
		}
		if r == '$' && i+sz < len(repl) {
			j := i + sz
			if repl[j] >= '0' && repl[j] <= '9' {
				grp := 0
				for j < len(repl) && repl[j] >= '0' && repl[j] <= '9' {
					cand := grp*10 + int(repl[j]-'0')
					if cand*2+1 >= len(loc) && j > i+sz {
						break
					}
					grp = cand
					j++
				}
				if grp*2+1 < len(loc) && loc[grp*2] >= 0 && loc[grp*2+1] >= 0 {
					out.WriteString(src[loc[grp*2]:loc[grp*2+1]])
				}
				i = j
				continue
			}
		}
		out.WriteRune(r)
		i += sz
	}
	return out.String()
}
