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

package transpiler

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

var (
	reFuzzR64JSONType        = regexp.MustCompile(`(?i)\bJSON_TYPE\s*\(`)
	reFuzzR64MatchPredicate  = regexp.MustCompile(`(?i)\bMATCH_(ALL|ANY|PHRASE|PHRASE_PREFIX|REGEXP)\b`)
	reFuzzR64FromBaseMatched = regexp.MustCompile("(?i)\\bFROM\\s+`?base_matched`?")
	reFuzzR64OrderByLimit    = regexp.MustCompile(`(?is)\bORDER\s+BY\b.*\bLIMIT\b`)
)

func stripQuotedSQLSegmentsR64(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inS {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
			b.WriteByte(' ')
		case '"':
			inD = true
			b.WriteByte(' ')
		case '`':
			inB = true
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isBalancedBackticksAndParensR64(sqlStr string) bool {
	inS, inD, inB := false, false, false
	parenDepth := 0
	for i := 0; i < len(sqlStr); i++ {
		c := sqlStr[i]
		if inS {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			parenDepth++
		case ')':
			parenDepth--
			if parenDepth < 0 {
				return false
			}
		}
	}
	return !inS && !inD && !inB && parenDepth == 0
}

func hasOneArgJSONTypeR64(sqlStr string) bool {
	if !reFuzzR64JSONType.MatchString(sqlStr) {
		return false
	}
	inSingle, inDouble, inBacktick := false, false, false
	for i := 0; i < len(sqlStr); {
		ch := sqlStr[i]
		if inSingle {
			if ch == '\\' && i+1 < len(sqlStr) {
				i += 2
				continue
			}
			if ch == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i += 2
					continue
				}
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(sqlStr) {
				i += 2
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			i++
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i += 2
					continue
				}
				inBacktick = false
			}
			i++
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			i++
			continue
		case '"':
			inDouble = true
			i++
			continue
		case '`':
			inBacktick = true
			i++
			continue
		}
		if ch != 'j' && ch != 'J' {
			i++
			continue
		}
		loc := reFuzzR64JSONType.FindStringIndex(sqlStr[i:])
		if loc == nil || loc[0] != 0 {
			i++
			continue
		}
		openIdx := i + loc[1] - 1
		depth := 1
		topCommas := 0
		qS, qD, qB := false, false, false
		j := openIdx + 1
		for j < len(sqlStr) && depth > 0 {
			c := sqlStr[j]
			if qS {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '\'' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '\'' {
						j += 2
						continue
					}
					qS = false
				}
			} else if qD {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '"' {
					qD = false
				}
			} else if qB {
				if c == '`' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '`' {
						j += 2
						continue
					}
					qB = false
				}
			} else {
				switch c {
				case '\'':
					qS = true
				case '"':
					qD = true
				case '`':
					qB = true
				case '(':
					depth++
				case ')':
					depth--
				case ',':
					if depth == 1 {
						topCommas++
					}
				}
			}
			j++
		}
		if depth == 0 && topCommas == 0 {
			return true
		}
		i = openIdx + 1
	}
	return false
}

func extractFromBaseMatchedSegmentsR64(sqlStr string) []string {
	locs := reFuzzR64FromBaseMatched.FindAllStringIndex(sqlStr, -1)
	segs := make([]string, 0, len(locs))
	for _, loc := range locs {
		tail := sqlStr[loc[1]:]
		depth := 0
		inS, inD, inB := false, false, false
		end := len(tail)
		for i := 0; i < len(tail); i++ {
			c := tail[i]
			if inS {
				if c == '\\' && i+1 < len(tail) {
					i++
					continue
				}
				if c == '\'' {
					if i+1 < len(tail) && tail[i+1] == '\'' {
						i++
						continue
					}
					inS = false
				}
				continue
			}
			if inD {
				if c == '\\' && i+1 < len(tail) {
					i++
					continue
				}
				if c == '"' {
					inD = false
				}
				continue
			}
			if inB {
				if c == '`' {
					if i+1 < len(tail) && tail[i+1] == '`' {
						i++
						continue
					}
					inB = false
				}
				continue
			}
			switch c {
			case '\'':
				inS = true
			case '"':
				inD = true
			case '`':
				inB = true
			case '(':
				depth++
			case ')':
				if depth == 0 {
					end = i
					goto doneSeg
				}
				depth--
			}
		}
	doneSeg:
		segs = append(segs, stripQuotedSQLSegmentsR64(tail[:end]))
	}
	return segs
}

func hasMatchInFromBaseMatchedR64(sqlStr string) bool {
	for _, seg := range extractFromBaseMatchedSegmentsR64(sqlStr) {
		if reFuzzR64MatchPredicate.MatchString(seg) {
			return true
		}
	}
	return false
}

func splitTopLevelUnionAllBranchesR64(sqlStr string) []string {
	var branches []string
	depth := 0
	inS, inD, inB := false, false, false
	start := 0
	for i := 0; i < len(sqlStr); i++ {
		c := sqlStr[i]
		if inS {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+len("UNION ALL") <= len(sqlStr) && strings.EqualFold(sqlStr[i:i+len("UNION ALL")], "UNION ALL") {
				prevOK := i == 0 || sqlStr[i-1] == ' ' || sqlStr[i-1] == ')' || sqlStr[i-1] == '\n' || sqlStr[i-1] == '\t'
				nextPos := i + len("UNION ALL")
				nextOK := nextPos == len(sqlStr) || sqlStr[nextPos] == ' ' || sqlStr[nextPos] == '(' || sqlStr[nextPos] == '\n' || sqlStr[nextPos] == '\t'
				if prevOK && nextOK {
					branches = append(branches, strings.TrimSpace(sqlStr[start:i]))
					start = nextPos
					i = nextPos - 1
				}
			}
		}
	}
	if start < len(sqlStr) {
		branches = append(branches, strings.TrimSpace(sqlStr[start:]))
	}
	return branches
}

func stripTopLevelParenGroupsR64(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

func isSingleOuterParenExprR64(s string) bool {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "(") || !strings.HasSuffix(trimmed, ")") {
		return false
	}
	depth := 0
	inS, inD, inB := false, false, false
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if inS {
			if c == '\\' && i+1 < len(trimmed) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(trimmed) && trimmed[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(trimmed) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(trimmed) && trimmed[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i < len(trimmed)-1 {
				return false
			}
		}
	}
	return depth == 0
}

func skipLeadingWithCTEsR64(sqlStr string) string {
	trimmed := strings.TrimSpace(sqlStr)
	if len(trimmed) < 5 || !strings.EqualFold(trimmed[:4], "WITH") || (trimmed[4] != ' ' && trimmed[4] != '\t' && trimmed[4] != '\n') {
		return trimmed
	}
	depth := 0
	inS, inD, inB := false, false, false
	sawParen := false
	for i := 4; i < len(trimmed); i++ {
		c := trimmed[i]
		if inS {
			if c == '\\' && i+1 < len(trimmed) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(trimmed) && trimmed[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(trimmed) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(trimmed) && trimmed[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			depth++
			sawParen = true
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if sawParen && depth == 0 {
				rest := strings.TrimSpace(trimmed[i:])
				if strings.HasPrefix(rest, ",") {
					continue
				}
				if strings.HasPrefix(rest, "(") || (len(rest) >= 6 && strings.EqualFold(rest[:6], "SELECT")) {
					return rest
				}
			}
		}
	}
	return trimmed
}

func hasUnparenthesizedOrderByInUnionAllR64(sqlStr string) bool {
	body := skipLeadingWithCTEsR64(sqlStr)
	branches := splitTopLevelUnionAllBranchesR64(body)
	if len(branches) <= 1 {
		return false
	}
	for _, br := range branches {
		if isSingleOuterParenExprR64(br) {
			continue
		}
		topOnly := stripTopLevelParenGroupsR64(stripQuotedSQLSegmentsR64(br))
		if reFuzzR64OrderByLimit.MatchString(topOnly) {
			return true
		}
	}
	return false
}

var (
	reFuzzR65ScoreCall        = regexp.MustCompile(`(?i)\bscore\s*\(\s*\)`)
	reFuzzR65CastCoalesce     = regexp.MustCompile(`(?i)\bCAST\s*\(\s*COALESCE\s*\(`)
	reFuzzR65MatchAllKinds    = regexp.MustCompile(`(?i)\bMATCH_(?:ALL|ANY|PHRASE|PHRASE_PREFIX|REGEXP|BOOL_PREFIX)\b`)
	reFuzzR65RawUntrustedCast = regexp.MustCompile("(?i)\\bCAST\\s*\\(\\s*(?:`?(?:_nel|_elem|_x|_sub_elem(?:_\\d+)?|_helem)`?|json_extract_string\\([^)]*\\))\\s+AS\\s+(?:DOUBLE|BIGINT|LARGEINT|INT)\\b")
)

func hasScoreInFromBaseMatchedR65(sqlStr string) bool {
	for _, seg := range extractFromBaseMatchedSegmentsR64(sqlStr) {
		if reFuzzR65ScoreCall.MatchString(seg) {
			return true
		}
	}
	return false
}

func hasMatchInCastCoalesceR65(sqlStr string) bool {
	i := 0
	for i < len(sqlStr) {
		loc := reFuzzR65CastCoalesce.FindStringIndex(sqlStr[i:])
		if loc == nil {
			return false
		}
		start := i + loc[0]
		openIdx := strings.IndexByte(sqlStr[start:], '(')
		if openIdx < 0 {
			return false
		}
		j := start + openIdx
		depth := 0
		inS, inD, inB := false, false, false
		end := len(sqlStr)
		for j < len(sqlStr) {
			c := sqlStr[j]
			if inS {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '\'' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '\'' {
						j += 2
						continue
					}
					inS = false
				}
				j++
				continue
			}
			if inD {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '"' {
					inD = false
				}
				j++
				continue
			}
			if inB {
				if c == '`' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '`' {
						j += 2
						continue
					}
					inB = false
				}
				j++
				continue
			}
			switch c {
			case '\'':
				inS = true
			case '"':
				inD = true
			case '`':
				inB = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = j + 1
					goto checkBody
				}
			}
			j++
		}
	checkBody:
		if reFuzzR65MatchAllKinds.MatchString(stripQuotedSQLSegmentsR64(sqlStr[start:end])) {
			return true
		}
		i = start + openIdx + 1
	}
	return false
}

func hasRawUntrustedCastR65(sqlStr string) bool {
	locs := reFuzzR65RawUntrustedCast.FindAllStringIndex(sqlStr, -1)
	for _, loc := range locs {
		if loc[0] >= 4 && strings.EqualFold(sqlStr[loc[0]-4:loc[0]], "TRY_") {
			continue
		}
		return true
	}
	return false
}

func sanitizeFuzzyTextTokenR64(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 32; i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '_' || c == '-' {
			b.WriteByte(c)
		}
	}
	if strings.TrimSpace(b.String()) == "" {
		return "ny pizza"
	}
	return strings.TrimSpace(b.String())
}

func FuzzNormalizeDorisSQL(f *testing.F) {
	f.Add(uint8(0), uint8(0), "ny pizza", uint64(9223372036854776000))
	f.Add(uint8(1), uint8(1), "fast laptop", uint64(18446744073709551615))
	f.Add(uint8(2), uint8(2), "status:active", uint64(100))
	f.Add(uint8(3), uint8(3), "u4pruydqqvj", uint64(5000))
	f.Add(uint8(4), uint8(4), "quick fox", uint64(42))
	f.Add(uint8(6), uint8(5), "ab pizza", uint64(3))
	f.Add(uint8(7), uint8(6), "ny", uint64(9))
	f.Add(uint8(8), uint8(0), "x", uint64(15))
	f.Add(uint8(9), uint8(5), "laptop", uint64(21))

	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title":   {"type": "text", "search_analyzer": "syn_an"},
			"tag":     {"type": "keyword"},
			"wc":      {"type": "wildcard", "null_value": "_missing_wc_"},
			"ck":      {"type": "constant_keyword", "value": "pinned"},
			"uid":     {"type": "unsigned_long"},
			"price":   {"type": "double"},
			"scores":  {"type": "double"},
			"loc":     {"type": "geo_point"},
			"shape":   {"type": "geo_shape", "index": false},
			"dyn":     {"type": "object", "dynamic": true},
			"sayt":    {"type": "search_as_you_type"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"qty": {"type": "integer"}
				}
			}
		}
	}`), &spec); err != nil {
		f.Fatalf("unmarshal fuzz mapping: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "fuzz_r64_idx", &spec)
	if fb, ok := sch.Fields["scores"]; ok {
		fb.Kind = schema.StoragePromotedArray
		fb.IsMultiValued = true
		fb.ColumnName = "arr__scores"
		sch.Fields["scores"] = fb
	}
	cfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"sg": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny, new york", "fast, quick"},
				},
			},
			"analyzer": map[string]any{
				"syn_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "sg"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		f.Fatalf("ParseIndexAnalysisConfig: %v", err)
	}
	sch.AnalysisConfig = cfg

	f.Fuzz(func(t *testing.T, qMode uint8, aggMode uint8, rawTok string, numSeed uint64) {
		tok := sanitizeFuzzyTextTokenR64(rawTok)
		var qJSON string
		switch qMode % 10 {
		case 0:
			qJSON = fmt.Sprintf(`{"match": {"title": {"query": %q, "fuzziness": "AUTO", "minimum_should_match": "2<75%%"}}}`, "a "+tok)
		case 1:
			qJSON = fmt.Sprintf(`{"term": {"tag": %q}}`, tok)
		case 2:
			qJSON = `{"exists": {"field": "dyn.extra"}}`
		case 3:
			qJSON = fmt.Sprintf(`{"nested": {"path": "items", "query": {"term": {"items.sku": %q}}}}`, tok)
		case 4:
			qJSON = `{"geo_grid": {"loc": {"geohash": "u4p"}}}`
		case 5:
			qJSON = fmt.Sprintf(`{"script_score": {"query": {"match": {"title": %q}}, "script": {"source": "_score - 5.0"}}}`, tok)
		case 6:
			qJSON = fmt.Sprintf(`{"match_bool_prefix": {"title": {"query": %q, "fuzziness": "AUTO", "minimum_should_match": 1}}}`, tok+" xy")
		case 7:
			qJSON = fmt.Sprintf(`{"common": {"title": {"query": %q, "cutoff_frequency": 0.001, "low_freq_operator": "and", "minimum_should_match": 1}}}`, tok+" ab")
		case 8:
			qJSON = fmt.Sprintf(`{"bool": {"must": [{"match": {"title": {"query": %q, "fuzziness": "AUTO"}}}], "should": [{"match_bool_prefix": {"title": %q}}]}}`, "x "+tok, tok)
		default:
			qJSON = fmt.Sprintf(`{"function_score": {"query": {"match_bool_prefix": {"title": %q}}, "gauss": {"scores": {"origin": 50, "scale": 10}}}}`, tok)
		}

		var aggJSON string
		switch aggMode % 7 {
		case 0:
			aggJSON = fmt.Sprintf(`{
				"by_tag": {"terms": {"field": "tag", "size": 5}},
				"top_docs": {"top_hits": {"size": 3}},
				"filtered": {"filter": {"match": {"title": %q}}}
			}`, tok)
		case 1:
			interval := (numSeed % 100000) + 1
			aggJSON = fmt.Sprintf(`{
				"uid_hist": {"histogram": {"field": "uid", "interval": %d}},
				"uid_rng": {"range": {"field": "uid", "missing": %d, "ranges": [{"from": 0, "to": 100}]}}
			}`, interval, numSeed)
		case 2:
			aggJSON = fmt.Sprintf(`{
				"buckets": {"filters": {"filters": {"a": {"match": {"title": %q}}, "b": {"term": {"ck": "pinned"}}}}},
				"adj": {"adjacency_matrix": {"filters": {"x": {"match": {"title": %q}}, "y": {"term": {"tag": "v"}}}}}
			}`, tok, tok)
		case 3:
			aggJSON = `{
				"nested_items": {
					"nested": {"path": "items"},
					"aggs": {
						"avg_qty": {"avg": {"field": "items.qty"}},
						"qty_box": {"boxplot": {"field": "items.qty"}},
						"qty_pct": {"percentiles": {"field": "items.qty"}}
					}
				}
			}`
		case 4:
			aggJSON = fmt.Sprintf(`{
				"by_tag": {"terms": {"field": "tag", "size": 5}},
				"sig": {"significant_terms": {"field": "tag", "background_filter": {"match": {"title": %q}}}}
			}`, tok)
		case 5:
			aggJSON = `{
				"all_docs": {"global": {}, "aggs": {"sc_box": {"boxplot": {"field": "scores"}}}},
				"sc_pct": {"percentiles": {"field": "scores", "percents": [50, 95]}},
				"sc_ranks": {"percentile_ranks": {"field": "scores", "values": [10, 50]}}
			}`
		default:
			aggJSON = fmt.Sprintf(`{
				"mt": {"multi_terms": {"terms": [{"field": "uid", "value_type": "unsigned_long"}, {"field": "tag"}], "min_doc_count": 1, "order": [{"_count": "asc"}]}},
				"flt": {"filter": {"common": {"title": %q}}}
			}`, tok)
		}

		minScoreFrag := ""
		if numSeed%3 == 0 {
			minScoreFrag = `"min_score": 0.25,`
		}
		reqJSON := fmt.Sprintf(`{
			"size": 5,
			%s
			"query": %s,
			"post_filter": {"match": {"title": %q}},
			"aggs": %s
		}`, minScoreFrag, qJSON, tok, aggJSON)

		var req esast.SearchRequest
		if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
			t.Fatalf("unmarshal fuzzed SearchRequest failed: %v\npayload=%s", err, reqJSON)
		}
		tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: numSeed%2 == 1})
		if req.Query != nil {
			cq := tr.CompileQuery(req.Query, true, nil)
			if reFuzzR65MatchAllKinds.MatchString(stripQuotedSQLSegmentsR64(cq.ScoreSQL)) {
				t.Fatalf("MATCH_* predicate leaked into ScoreSQL: %s\npayload=%s", cq.ScoreSQL, reqJSON)
			}
			if reFuzzR65MatchAllKinds.MatchString(stripQuotedSQLSegmentsR64(cq.SafeWhereSQL)) {
				t.Fatalf("MATCH_* predicate leaked into SafeWhereSQL: %s\npayload=%s", cq.SafeWhereSQL, reqJSON)
			}
			if reFuzzR65MatchAllKinds.MatchString(stripQuotedSQLSegmentsR64(cq.WhereSQL)) && !cq.UsesFulltextMatch {
				t.Fatalf("MATCH_* emitted in WhereSQL without UsesFulltextMatch=true: %s\npayload=%s", cq.WhereSQL, reqJSON)
			}
			if hasMatchInCastCoalesceR65(cq.ScoreSQL) || hasMatchInCastCoalesceR65(cq.WhereSQL) {
				t.Fatalf("MATCH_* inside CAST(COALESCE(...)) in CompileQuery:\npayload=%s\nwhere=%s\nscore=%s", reqJSON, cq.WhereSQL, cq.ScoreSQL)
			}
		}
		plan, err := tr.BuildSearchPlan(&req)
		if err != nil {
			return
		}
		for _, sqlOut := range []string{plan.HitsSQL, plan.AggsSQL} {
			if strings.TrimSpace(sqlOut) == "" {
				continue
			}
			if !isBalancedBackticksAndParensR64(sqlOut) {
				t.Fatalf("unbalanced parens/backticks in transpiled SQL:\n%s", sqlOut)
			}
			if hasOneArgJSONTypeR64(sqlOut) {
				t.Fatalf("1-arg JSON_TYPE in transpiled SQL:\n%s", sqlOut)
			}
			if hasMatchInFromBaseMatchedR64(sqlOut) {
				t.Fatalf("MATCH_* predicate inside FROM base_matched consumer:\n%s", sqlOut)
			}
			if hasScoreInFromBaseMatchedR65(sqlOut) {
				t.Fatalf("score() call inside FROM base_matched consumer:\n%s", sqlOut)
			}
			if hasMatchInCastCoalesceR65(sqlOut) {
				t.Fatalf("MATCH_* inside CAST(COALESCE(...)):\n%s", sqlOut)
			}
			if hasRawUntrustedCastR65(sqlOut) {
				t.Fatalf("raw CAST on untrusted array/json expression:\n%s", sqlOut)
			}
			if hasUnparenthesizedOrderByInUnionAllR64(sqlOut) {
				t.Fatalf("unparenthesized ORDER BY ... LIMIT inside UNION ALL branch:\n%s", sqlOut)
			}
		}

		wrappedUnion := wrapUnionBranchesWithOuterOrderByR63([]string{
			fmt.Sprintf("SELECT 'a' AS `_agg_name`, `tag` AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched` GROUP BY `tag` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d", (numSeed%20)+1),
			"SELECT 'b' AS `_agg_name`, '_top' AS `_bucket_key`, CAST(1 AS DOUBLE) AS `_doc_count` FROM `base_matched` ORDER BY `_id` ASC LIMIT 3",
		})
		if hasUnparenthesizedOrderByInUnionAllR64(wrappedUnion) || !isBalancedBackticksAndParensR64(wrappedUnion) {
			t.Fatalf("wrapUnionBranchesWithOuterOrderByR63 violated Doris UNION ALL invariant:\n%s", wrappedUnion)
		}
	})
}
