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
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// ----------------------------------------------------------------------------
// Round 63 F10: Apache Doris 4.1.3 Strict-Cast (`enable_strict_cast = true`),
// Nereids 32-bit Unsigned `CONV` Typing, Escaped JSONPath, & Binary `_tsid` Sort
// ----------------------------------------------------------------------------

const (
	// base64URLAlphabetR63 is the 64-character RFC 4648 §5 Base64URL alphabet (`0..63`).
	base64URLAlphabetR63 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// asciiOrdered64AlphabetR63 maps indices `0..63` onto 64 strictly ascending printable
	// 7-bit ASCII characters (`0x30` `'0'` through `0x6F` `'o'`), giving an exact order
	// isomorphism between Base64URL-encoded 128-bit `_tsid` strings and unsigned `BytesRef`
	// byte order without invoking UTF-8 `FROM_BASE64(...)` on arbitrary binary hashes (`C-14`).
	asciiOrdered64AlphabetR63 = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmno"
)

// FormatSQLFloatR63 formats a finite `float64` in plain decimal notation (`'f'`) without
// scientific notation (`%v` emits `1e+06`), wrapping negative numbers in parentheses when
// requested so `- (-offset)` can never form a `--` SQL line comment (`C-15`).
func FormatSQLFloatR63(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "0"
	}
	if v == 0 {
		return "0"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// QuoteDorisJSONPathSegment escapes `\` -> `\\` FIRST and `"` -> `\"` SECOND, wrapping
// the segment in double quotes (`"..."`) so field names containing `.`, `*`, `[`, `]`,
// `@`, `-`, `"`, or `\` cannot inject JSONPath wildcards/subscripts or break quoting (`C-13`).
func QuoteDorisJSONPathSegment(seg string) string {
	escaped := strings.ReplaceAll(seg, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// BuildQuotedDorisJSONPaths returns `(nestedPath, dottedLiteralPath, hasDot)` with every
// JSONPath segment quoted via `QuoteDorisJSONPathSegment` (`C-13`).
func BuildQuotedDorisJSONPaths(field string) (nestedPath string, dottedLiteralPath string, hasDot bool) {
	clean := strings.TrimSpace(field)
	if clean == "" {
		return `$.""`, "", false
	}
	if !strings.Contains(clean, ".") {
		return "$." + QuoteDorisJSONPathSegment(clean), "", false
	}
	rawSegs := strings.Split(clean, ".")
	quotedSegs := make([]string, len(rawSegs))
	for i, s := range rawSegs {
		quotedSegs[i] = QuoteDorisJSONPathSegment(s)
	}
	nestedPath = "$." + strings.Join(quotedSegs, ".")
	dottedLiteralPath = "$." + QuoteDorisJSONPathSegment(clean)
	return nestedPath, dottedLiteralPath, true
}

// sqlRuntimeSourceJSONTypeIsArrayExpr returns a Doris 4.1.3 boolean predicate testing whether
// `field` inside `_source` is a JSON array (`JSON_TYPE(json_extract(_source, path)) = 'ARRAY'`),
// avoiding `LIKE '[%]'` false positives on scalar strings like `"[WARN] retry [1]"` (`C-08`).
func sqlRuntimeSourceJSONTypeIsArrayExpr(field string) string {
	nestedPath, dottedPath, hasDot := BuildQuotedDorisJSONPaths(field)
	if !hasDot {
		return fmt.Sprintf("JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) = 'ARRAY'", quoteStr(nestedPath))
	}
	return fmt.Sprintf("(JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) = 'ARRAY' OR (JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) IS NULL AND JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) = 'ARRAY'))",
		quoteStr(nestedPath), quoteStr(nestedPath), quoteStr(dottedPath))
}

// sqlRuntimeSourceDateMillisExpr coerces a scalar runtime string expression `scalarStr` to
// epoch milliseconds (`BIGINT`) under Doris 4.1.3 `enable_strict_cast = true` using `TRY_CAST`
// and `DATETIMEV2(6)` so fractional milliseconds are preserved without `ERROR 1105` (`C-08`).
func sqlRuntimeSourceDateMillisExpr(scalarStr string) string {
	noZ := fmt.Sprintf("REPLACE(REPLACE(%s, 'Z', ''), 'z', '')", scalarStr)
	dt6 := fmt.Sprintf("TRY_CAST(REPLACE(SUBSTRING(%s, 1, 26), 'T', ' ') AS DATETIMEV2(6))", noZ)
	isoMillis := fmt.Sprintf(
		"CAST(CAST(UNIX_TIMESTAMP(DATE_TRUNC(%s, 'second')) AS BIGINT) * 1000 + CAST(FLOOR(MICROSECOND(%s) / 1000.0) AS BIGINT) AS BIGINT)",
		dt6, dt6,
	)
	return fmt.Sprintf("COALESCE(TRY_CAST(%s AS BIGINT), %s)", scalarStr, isoMillis)
}

// sqlRuntimeSourceDateNanosExpr coerces a scalar runtime string expression `scalarStr` to
// epoch nanoseconds (`BIGINT`) under Doris 4.1.3 `enable_strict_cast = true` (`C-08`).
func sqlRuntimeSourceDateNanosExpr(scalarStr string) string {
	noZ := fmt.Sprintf("REPLACE(REPLACE(%s, 'Z', ''), 'z', '')", scalarStr)
	dt6 := fmt.Sprintf("TRY_CAST(REPLACE(SUBSTRING(%s, 1, 26), 'T', ' ') AS DATETIMEV2(6))", noZ)
	subNanoTail := fmt.Sprintf(
		"COALESCE(TRY_CAST(RPAD(REGEXP_EXTRACT(SUBSTRING(%s, 27, 3), '^([0-9]{1,3})', 1), 3, '0') AS BIGINT), 0)",
		noZ,
	)
	isoNanos := fmt.Sprintf(
		"CAST(CAST(UNIX_TIMESTAMP(DATE_TRUNC(%s, 'second')) AS BIGINT) * 1000000000 + CAST(MICROSECOND(%s) AS BIGINT) * 1000 + %s AS BIGINT)",
		dt6, dt6, subNanoTail,
	)
	return fmt.Sprintf("COALESCE(TRY_CAST(%s AS BIGINT), %s)", scalarStr, isoNanos)
}

// TranslateBase64URLOrderR63 applies the pure-ASCII 64-character order-preserving translation
// used by `sqlTSIDBinarySortExpr` in Go for testing and parity verification (`C-14`).
func TranslateBase64URLOrderR63(tsid string) string {
	var sb strings.Builder
	sb.Grow(len(tsid))
	for i := 0; i < len(tsid); i++ {
		idx := strings.IndexByte(base64URLAlphabetR63, tsid[i])
		if idx >= 0 && idx < len(asciiOrdered64AlphabetR63) {
			sb.WriteByte(asciiOrdered64AlphabetR63[idx])
		} else {
			sb.WriteByte(tsid[i])
		}
	}
	return sb.String()
}

// BuildIPv6PrefixMaskWhereSQL compiles an IPv6 CIDR prefix filter (`fe80::/10`, `ffff::/16`, etc.)
// into four unsigned 32-bit `CAST(CONV(SUBSTRING(hex32, pos, 8), 16, 10) AS BIGINT) & mask32 = exp32`
// clauses so Doris 4.1.3 Nereids never encounters `VARCHAR & BIGINT` or signed 64-bit overflow (`C-07`).
func BuildIPv6PrefixMaskWhereSQL(colExpr, cidr string) (string, bool) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipNet == nil {
		return "", false
	}
	ip16 := ipNet.IP.To16()
	if len(ip16) != 16 {
		return "", false
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 32 {
		// IPv4 CIDR mapped into last 32 bits of canonical 16-byte representation (`00000000000000000000FFFF...`).
		ones += 96
	} else if bits != 128 {
		return "", false
	}
	hex32 := sqlCanonicalIPHexExpr(colExpr)
	conds := []string{fmt.Sprintf("%s IS NOT NULL", hex32)}
	for i := 0; i < 4; i++ {
		rem := ones - i*32
		if rem <= 0 {
			break
		}
		expChunk := uint32(ip16[i*4])<<24 | uint32(ip16[i*4+1])<<16 | uint32(ip16[i*4+2])<<8 | uint32(ip16[i*4+3])
		subExpr := fmt.Sprintf("SUBSTRING(%s, %d, 8)", hex32, i*8+1)
		if rem >= 32 {
			conds = append(conds, fmt.Sprintf("(CAST(CONV(%s, 16, 10) AS BIGINT) & %d) = %d", subExpr, int64(0xffffffff), int64(expChunk)))
		} else {
			mask32 := uint32(0xffffffff) << (32 - rem)
			expected32 := expChunk & mask32
			conds = append(conds, fmt.Sprintf("(CAST(CONV(%s, 16, 10) AS BIGINT) & %d) = %d", subExpr, int64(mask32), int64(expected32)))
		}
	}
	return "(" + strings.Join(conds, " AND ") + ")", true
}

// coerceJSONNumberExactIntOrUintR63 preserves `int64`, `uint64 > math.MaxInt64`, or `float64`
// when decoding `json.Number` values in `_tsid` key maps (`C-14`, `F11`).
func coerceJSONNumberExactIntOrUintR63(num json.Number) any {
	raw := num.String()
	if iv, err := num.Int64(); err == nil {
		return iv
	}
	if u, err := strconv.ParseUint(raw, 10, 64); err == nil {
		return u
	}
	if fv, err := num.Float64(); err == nil {
		return fv
	}
	return raw
}

func hasTopLevelOrderByInUnionBranchR64(sqlStr string) bool {
	trimmed := strings.TrimSpace(sqlStr)
	if trimmed == "" {
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
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+len("ORDER BY") <= len(trimmed) && strings.EqualFold(trimmed[i:i+len("ORDER BY")], "ORDER BY") {
				prevOK := i == 0 || trimmed[i-1] == ' ' || trimmed[i-1] == ')' || trimmed[i-1] == '\n' || trimmed[i-1] == '\t'
				nextPos := i + len("ORDER BY")
				nextOK := nextPos == len(trimmed) || trimmed[nextPos] == ' ' || trimmed[nextPos] == '\n' || trimmed[nextPos] == '\t'
				if prevOK && nextOK {
					return true
				}
			}
		}
	}
	return false
}

// wrapUnionBranchesWithOuterOrderByR63 parenthesizes individual `UNION ALL` branches that carry
// a trailing `ORDER BY ... LIMIT ...` when multiple branches are joined by `UNION ALL` so
// MySQL / Apache Doris 4.1.3 parses each branch's `ORDER BY` unambiguously (`C-14`).
func wrapUnionBranchesWithOuterOrderByR63(branches []string) string {
	if len(branches) <= 1 {
		return strings.Join(branches, "\nUNION ALL\n")
	}
	wrapped := make([]string, len(branches))
	for i, b := range branches {
		if (strings.Contains(b, ") `_agg_sub_") && strings.Contains(b[strings.LastIndex(b, ") `_agg_sub_"):], " ORDER BY ")) || hasTopLevelOrderByInUnionBranchR64(b) {
			wrapped[i] = "(" + b + ")"
		} else {
			wrapped[i] = b
		}
	}
	return strings.Join(wrapped, "\nUNION ALL\n")
}

// ----------------------------------------------------------------------------
// Round 63 F12: Lucene BM25 (`k1 = 1.2`, `b = 0.75`) Scoring on `text` Fields
// ----------------------------------------------------------------------------

// SimilarityConfig describes a custom index similarity setting (`BM25` or `boolean`).
type SimilarityConfig struct {
	Type             string
	K1               *float64
	B                *float64
	DiscountOverlaps *bool
}

func (t *Transpiler) lookupRawFieldPropertyR63(fieldPath string) (esast.FieldProperty, bool) {
	if t == nil || t.Schema == nil || t.Schema.RawMapping == nil {
		return esast.FieldProperty{}, false
	}
	clean := strings.TrimSpace(fieldPath)
	if clean == "" {
		return esast.FieldProperty{}, false
	}
	segs := strings.Split(clean, ".")
	currProps := t.Schema.RawMapping.Properties
	var prop esast.FieldProperty
	for i, seg := range segs {
		if currProps == nil {
			return esast.FieldProperty{}, false
		}
		p, ok := currProps[seg]
		if !ok {
			return esast.FieldProperty{}, false
		}
		prop = p
		if i < len(segs)-1 {
			nextSeg := segs[i+1]
			if i == len(segs)-2 && p.Fields != nil {
				if subField, okSF := p.Fields[nextSeg]; okSF {
					return subField, true
				}
			}
			currProps = p.Properties
		}
	}
	return prop, true
}

// resolveBM25FieldParamsR63 returns `(true, k1, b)` when `origField` is a `text` field scored
// with Lucene BM25 (respecting `similarity: "boolean"`, `norms: false`, `index_options: "docs"`,
// and custom `TranspilerOptions.Similarities`), or `(false, 0, 0)` when ES uses constant score.
func (t *Transpiler) resolveBM25FieldParamsR63(origField string, b schema.FieldBinding) (bool, float64, float64) {
	cleanOrig := strings.TrimSpace(origField)
	if strings.HasSuffix(cleanOrig, ".keyword") || isExactKeywordField(cleanOrig, b) {
		return false, 0, 0
	}
	if b.ESType == "match_only_text" || b.IsVirtualSAYTSubfield || b.ESType == "search_as_you_type" {
		return false, 0, 0
	}
	isText := b.ESType == "text"
	if !isText && b.ESType == "" && (b.DorisType == schema.DorisString || b.DorisType == schema.DorisVarchar || b.Kind == schema.StorageDynamicVariant) {
		switch cleanOrig {
		case "_id", "_doc", "_index", "_routing", "_version", "_source", "_ignored", "_tsid", "_field_names":
			isText = false
		default:
			isText = true
		}
	}
	if !isText {
		return false, 0, 0
	}

	k1 := 1.2
	bParam := 0.75
	simName := "default"

	effPath := cleanOrig
	if b.AliasTarget != "" {
		effPath = b.AliasTarget
	}
	var fp esast.FieldProperty
	hasFP := false
	if p, ok := t.lookupRawFieldPropertyR63(effPath); ok {
		fp = p
		hasFP = true
		if strings.TrimSpace(p.Similarity) != "" {
			simName = strings.TrimSpace(p.Similarity)
		}
	}
	if strings.EqualFold(simName, "boolean") {
		return false, 0, 0
	}
	if t.Opts.LegacyFlatMatchScore && len(t.Opts.Similarities) == 0 && (!hasFP || (strings.TrimSpace(fp.Similarity) == "" && fp.Norms == nil && fp.IndexOptions == nil)) {
		return false, 0, 0
	}
	if len(t.Opts.Similarities) > 0 {
		if sc, ok := t.Opts.Similarities[simName]; ok {
			if strings.EqualFold(sc.Type, "boolean") {
				return false, 0, 0
			}
			if sc.K1 != nil && *sc.K1 >= 0 {
				k1 = *sc.K1
			}
			if sc.B != nil && *sc.B >= 0 && *sc.B <= 1 {
				bParam = *sc.B
			}
		}
	}
	if hasFP {
		if fp.Norms != nil && !*fp.Norms {
			bParam = 0.0
		}
		if ioStr, ok := fp.IndexOptions.(string); ok && strings.EqualFold(strings.TrimSpace(ioStr), "docs") {
			k1 = 0.0
			bParam = 0.0
		}
	}
	return true, k1, bParam
}

func (t *Transpiler) bm25TextColExprR63(resolvedField string, b schema.FieldBinding, nctx *nestedCtx) string {
	if !t.isBoundToNestedCtx(resolvedField, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		if arrCol := b.EffectiveArrayColumn(false); arrCol != "" {
			return fmt.Sprintf("ARRAY_JOIN(`%s`, ' ')", arrCol)
		}
	}
	return t.sqlColumnRef(resolvedField, false, nctx)
}

func formatBM25BoostR63(boost float64) string {
	if boost == 0 || math.Abs(boost) >= 1e-3 {
		return fmt.Sprintf("%.4f", boost)
	}
	return FormatSQLFloatR63(boost)
}

func (t *Transpiler) recordBM25RequirementR66(field, colExpr string, caseSensitive bool, terms []string) {
	if t == nil || len(terms) == 0 {
		return
	}
	var cleaned []string
	for _, tk := range terms {
		s := strings.TrimSpace(tk)
		if !caseSensitive {
			s = strings.ToLower(s)
		}
		if s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return
	}
	t.collectedBM25Reqs = append(t.collectedBM25Reqs, BM25QueryRequirement{
		Field:         field,
		ColExpr:       colExpr,
		CaseSensitive: caseSensitive,
		Terms:         cleaned,
	})
}

func (t *Transpiler) lookupBM25FieldStatsR66(colExpr, resolvedField, origField string) *BM25FieldTermStats {
	if t == nil || len(t.Opts.CorpusBM25Stats) == 0 {
		return nil
	}
	candidates := []string{
		colExpr,
		strings.Trim(colExpr, "`"),
		resolvedField,
		origField,
	}
	for _, k := range candidates {
		if k == "" {
			continue
		}
		if st, ok := t.Opts.CorpusBM25Stats[k]; ok && st != nil {
			return st
		}
	}
	return nil
}

func (t *Transpiler) buildBM25ClauseWithStatsR66(origField, resolvedField, colExpr, patInDblSpace string, caseSensitive bool, k1, bParam, boost float64, safePred string) string {
	if safePred == "FALSE" || strings.TrimSpace(patInDblSpace) == "" {
		return "0.0"
	}
	if boost == 0 {
		return fmt.Sprintf("(CASE WHEN %s THEN 0.0000 ELSE 0.0 END)", safePred)
	}
	strCol := fmt.Sprintf("COALESCE(CAST(%s AS STRING), '')", colExpr)
	pat := patInDblSpace
	if !caseSensitive {
		strCol = fmt.Sprintf("LOWER(%s)", strCol)
		pat = strings.ToLower(pat)
	}
	// Preserve intra-word apostrophes (e.g. "Al's" as 1 token) while turning edge apostrophes and punctuation into delimiters.
	stripEdgeApostrophes := fmt.Sprintf("REGEXP_REPLACE(%s, %s, ' ')", strCol, quoteStr(`(^|[^[:alnum:]_])'+|'+([^[:alnum:]_]|$)`))
	trimOne := fmt.Sprintf("TRIM(REGEXP_REPLACE(%s, %s, ' '))", stripEdgeApostrophes, quoteStr(`[^[:alnum:]_']+`))
	normDbl := fmt.Sprintf("CONCAT(' ', REPLACE(%s, ' ', '  '), ' ')", trimOne)
	patLit := quoteStr(pat)
	patRunes := utf8.RuneCountInString(pat)
	if patRunes <= 0 {
		patRunes = 1
	}
	tfExpr := fmt.Sprintf(
		"GREATEST(CAST(CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, %s, '')) AS DOUBLE) / %.1f, 1.0)",
		normDbl, normDbl, patLit, float64(patRunes),
	)
	dlExpr := fmt.Sprintf(
		"GREATEST(CAST(1 + CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, ' ', '')) AS DOUBLE), 1.0)",
		trimOne, trimOne,
	)

	terms := strings.Fields(pat)
	st := t.lookupBM25FieldStatsR66(colExpr, resolvedField, origField)
	avgdl := 2.0
	idfSum := 1.0
	if st != nil && st.TotalDocs > 0 {
		if st.AvgDL > 0 {
			avgdl = st.AvgDL
		} else {
			avgdl = 1.0
		}
		if len(terms) > 0 {
			idfSum = 0.0
			for _, term := range terms {
				var df int64
				if st.TermDocFreq != nil {
					var ok bool
					df, ok = st.TermDocFreq[term]
					if !ok && !caseSensitive {
						df = st.TermDocFreq[strings.ToLower(term)]
					}
				}
				if df <= 0 {
					df = 1
				}
				if df > st.TotalDocs {
					df = st.TotalDocs
				}
				idfSum += math.Log(1.0 + (float64(st.TotalDocs)-float64(df)+0.5)/(float64(df)+0.5))
			}
		}
	}

	scaleStr := FormatSQLFloatR63(boost * idfSum * (k1 + 1.0))
	denom := fmt.Sprintf(
		"((%s) + %s * (%s + %s * (%s) / %s))",
		tfExpr, FormatSQLFloatR63(k1), FormatSQLFloatR63(1.0-bParam), FormatSQLFloatR63(bParam), dlExpr, FormatSQLFloatR63(avgdl),
	)
	return fmt.Sprintf(
		"(CASE WHEN %s THEN (%s * (%s) / %s) ELSE 0.0 END)",
		safePred, scaleStr, tfExpr, denom,
	)
}

// buildBM25ClauseFromColAndPatternR63 emits pure scalar Apache Doris 4.1.3 SQL computing
// BM25 TF & field-length saturation for `patInDblSpace` (`" tok "` or `" t1  t2 "`).
func buildBM25ClauseFromColAndPatternR63(colExpr, patInDblSpace string, caseSensitive bool, k1, bParam, boost float64, safePred string) string {
	if safePred == "FALSE" || strings.TrimSpace(patInDblSpace) == "" {
		return "0.0"
	}
	if boost == 0 {
		return fmt.Sprintf("(CASE WHEN %s THEN 0.0000 ELSE 0.0 END)", safePred)
	}
	strCol := fmt.Sprintf("COALESCE(CAST(%s AS STRING), '')", colExpr)
	pat := patInDblSpace
	if !caseSensitive {
		strCol = fmt.Sprintf("LOWER(%s)", strCol)
		pat = strings.ToLower(pat)
	}
	normDbl := fmt.Sprintf("CONCAT(' ', REGEXP_REPLACE(%s, '[^[:alnum:]_]+', '  '), ' ')", strCol)
	patLit := quoteStr(pat)
	patRunes := utf8.RuneCountInString(pat)
	if patRunes <= 0 {
		patRunes = 1
	}
	tfExpr := fmt.Sprintf(
		"GREATEST(CAST(CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, %s, '')) AS DOUBLE) / %.1f, 1.0)",
		normDbl, normDbl, patLit, float64(patRunes),
	)
	trimOne := fmt.Sprintf("TRIM(REGEXP_REPLACE(%s, '[^[:alnum:]_]+', ' '))", strCol)
	dlExpr := fmt.Sprintf(
		"GREATEST(CAST(1 + CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, ' ', '')) AS DOUBLE), 1.0)",
		trimOne, trimOne,
	)
	denom := fmt.Sprintf(
		"((%s) + %s * (%s + %s * (%s) / 2.0))",
		tfExpr, FormatSQLFloatR63(k1), FormatSQLFloatR63(1.0-bParam), FormatSQLFloatR63(bParam), dlExpr,
	)
	return fmt.Sprintf(
		"(CASE WHEN %s THEN (%s * (%s) / %s) ELSE 0.0 END)",
		safePred, formatBM25BoostR63(boost), tfExpr, denom,
	)
}

func (t *Transpiler) compileBM25SingleTermScoreR63(
	origField, resolvedField string,
	b schema.FieldBinding,
	tok string,
	caseSensitive bool,
	boost float64,
	safePred string,
	nctx *nestedCtx,
) (string, bool) {
	useBM25, k1, bParam := t.resolveBM25FieldParamsR63(origField, b)
	if !useBM25 || strings.TrimSpace(tok) == "" {
		return "", false
	}
	colExpr := t.bm25TextColExprR63(resolvedField, b, nctx)
	t.recordBM25RequirementR66(resolvedField, colExpr, caseSensitive, []string{tok})
	if t.Opts.CorpusBM25Stats != nil {
		return t.buildBM25ClauseWithStatsR66(origField, resolvedField, colExpr, " "+tok+" ", caseSensitive, k1, bParam, boost, safePred), true
	}
	return buildBM25ClauseFromColAndPatternR63(colExpr, " "+tok+" ", caseSensitive, k1, bParam, boost, safePred), true
}

func (t *Transpiler) compileBM25MultiTokenMatchScoreR63(
	origField, resolvedField string,
	b schema.FieldBinding,
	tokens []string,
	caseSensitive bool,
	boost float64,
	overallSafePred string,
	nctx *nestedCtx,
) (string, bool) {
	useBM25, k1, bParam := t.resolveBM25FieldParamsR63(origField, b)
	if !useBM25 || len(tokens) == 0 {
		return "", false
	}
	if overallSafePred == "FALSE" {
		return "0.0", true
	}
	colExpr := t.bm25TextColExprR63(resolvedField, b, nctx)
	t.recordBM25RequirementR66(resolvedField, colExpr, caseSensitive, tokens)
	if boost == 0 {
		return fmt.Sprintf("(CASE WHEN %s THEN 0.0000 ELSE 0.0 END)", overallSafePred), true
	}
	emitClause := func(pat, pred string) string {
		if t.Opts.CorpusBM25Stats != nil {
			return t.buildBM25ClauseWithStatsR66(origField, resolvedField, colExpr, pat, caseSensitive, k1, bParam, boost, pred)
		}
		return buildBM25ClauseFromColAndPatternR63(colExpr, pat, caseSensitive, k1, bParam, boost, pred)
	}
	var termScores []string
	for _, tok := range tokens {
		tokTrim := strings.TrimSpace(tok)
		if tokTrim == "" {
			continue
		}
		tokPred := t.singleAnalyzedTokenWhereOnlyR63(resolvedField, b, tokTrim, caseSensitive, nctx)
		termScores = append(termScores, emitClause(" "+tokTrim+" ", tokPred))
	}
	if len(termScores) == 0 {
		return "", false
	}
	if len(termScores) == 1 {
		// If `overallSafePred` matches broader/identical docs, gate on `overallSafePred`.
		return emitClause(" "+strings.TrimSpace(tokens[0])+" ", overallSafePred), true
	}
	return fmt.Sprintf("(CASE WHEN %s THEN (%s) ELSE 0.0 END)", overallSafePred, strings.Join(termScores, " + ")), true
}

func (t *Transpiler) compileBM25PhraseScoreR63(
	origField, resolvedField string,
	b schema.FieldBinding,
	terms []string,
	caseSensitive bool,
	boost float64,
	safePred string,
	nctx *nestedCtx,
) (string, bool) {
	useBM25, k1, bParam := t.resolveBM25FieldParamsR63(origField, b)
	if !useBM25 || len(terms) == 0 {
		return "", false
	}
	var cleaned []string
	for _, tk := range terms {
		if s := strings.TrimSpace(tk); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return "", false
	}
	colExpr := t.bm25TextColExprR63(resolvedField, b, nctx)
	t.recordBM25RequirementR66(resolvedField, colExpr, caseSensitive, cleaned)
	pat := " " + strings.Join(cleaned, "  ") + " "
	if t.Opts.CorpusBM25Stats != nil {
		return t.buildBM25ClauseWithStatsR66(origField, resolvedField, colExpr, pat, caseSensitive, k1, bParam, boost, safePred), true
	}
	return buildBM25ClauseFromColAndPatternR63(colExpr, pat, caseSensitive, k1, bParam, boost, safePred), true
}

func (t *Transpiler) singleAnalyzedTokenWhereOnlyR63(field string, b schema.FieldBinding, tok string, caseSensitive bool, nctx *nestedCtx) string {
	rePat := quoteStr(buildAnalyzedTokenRegex(tok, caseSensitive))
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol)
	}
	col := t.sqlColumnRef(field, false, nctx)
	return fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat)
}

// compileAnalyzedTextTermPredicateR63 compiles `term` over an analyzed `text` / `match_only_text`
// field without a `.keyword` companion (`100_rank_rrf.yml`, `400_standard_retriever.yml`), matching
// any document whose analyzed token stream contains the exact unanalyzed term token (`F12`).
func (t *Transpiler) compileAnalyzedTextTermPredicateR63(
	origField, resolvedField string,
	b schema.FieldBinding,
	val any,
	caseInsensitive bool,
	nctx *nestedCtx,
) (pred string, termTok string, caseSens bool, handled bool) {
	isDynText := t.Opts.StrictTextTermRouting && t.Opts.DynamicTextFields != nil && t.Opts.DynamicTextFields[origField]
	isAnalyzedText := b.ESType == "text" || b.ESType == "match_only_text" || b.ESType == "annotated_text" || b.ESType == "annotated-text" || isDynText
	if !isAnalyzedText || strings.HasSuffix(origField, ".keyword") {
		return "", "", false, false
	}
	if b.KeywordCompanion != "" && !t.Opts.StrictTextTermRouting {
		return "", "", false, false
	}
	if strings.EqualFold(b.Analyzer, "keyword") || strings.EqualFold(b.Analyzer, "noop") {
		return "", "", false, false
	}
	if val == nil {
		return "FALSE", "", false, true
	}
	rawStr := fmt.Sprintf("%v", val)
	if rawStr == "" || strings.ContainsAny(rawStr, " \t\r\n") {
		return "FALSE", "", false, true
	}
	// If the field's index analyzer lowercases tokens (e.g. `standard`), an unanalyzed `term`
	// query containing uppercase characters cannot match unless `case_insensitive: true`.
	effAn := strings.TrimSpace(b.Analyzer)
	effCfg := t.effectiveAnalysisConfig()
	if effCfg != nil {
		effAn = effCfg.ResolveIndexAnalyzer(effAn)
	}
	if effAn == "" {
		effAn = "standard"
	}
	anCaseSens, isWS := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, analysis.Options{})
	if !anCaseSens {
		if !caseInsensitive && rawStr != strings.ToLower(rawStr) {
			return "FALSE", "", false, true
		}
		tok := strings.ToLower(rawStr)
		rePat := quoteStr(buildAnalyzedTokenRegexExactR63(tok, false, isWS))
		if !t.isBoundToNestedCtx(resolvedField, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
			arrCol := b.EffectiveArrayColumn(false)
			return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol), tok, false, true
		}
		col := t.sqlColumnRef(resolvedField, false, nctx)
		return fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat), tok, false, true
	}
	cs := !caseInsensitive
	rePat := quoteStr(buildAnalyzedTokenRegexExactR63(rawStr, cs, isWS))
	if !t.isBoundToNestedCtx(resolvedField, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol), rawStr, cs, true
	}
	col := t.sqlColumnRef(resolvedField, false, nctx)
	return fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat), rawStr, cs, true
}

// ----------------------------------------------------------------------------
// Round 63 F11: Exact Mappers (`unsigned_long`, `version`, `constant_keyword`,
// `geo_shape`, `_size`, `murmur3`, `counted_keyword`, `aggregate_metric_double`)
// ----------------------------------------------------------------------------

var maxUint64BigRatR63 = new(big.Rat).SetInt(new(big.Int).SetUint64(math.MaxUint64))

func parseUnsignedLongArbitraryRatR63(v any) (rat *big.Rat, isAboveInf bool, ok bool) {
	switch nv := v.(type) {
	case uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(nv)), false, true
	case int:
		return new(big.Rat).SetInt64(int64(nv)), false, true
	case int64:
		return new(big.Rat).SetInt64(nv), false, true
	case float64:
		if math.IsNaN(nv) || math.IsInf(nv, -1) {
			if math.IsInf(nv, -1) {
				return new(big.Rat).SetInt64(-1), false, true
			}
			return nil, false, false
		}
		if math.IsInf(nv, 1) {
			return nil, true, true
		}
		r := new(big.Rat).SetFloat64(nv)
		if r == nil {
			return nil, false, false
		}
		return r, false, true
	case json.Number:
		return parseUnsignedLongStringRatR63(nv.String())
	case string:
		return parseUnsignedLongStringRatR63(nv)
	default:
		return nil, false, false
	}
}

func parseUnsignedLongStringRatR63(raw string) (rat *big.Rat, isAboveInf bool, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, false, false
	}
	if strings.EqualFold(s, "inf") || strings.EqualFold(s, "+inf") || strings.EqualFold(s, "infinity") || strings.EqualFold(s, "+infinity") {
		return nil, true, true
	}
	if strings.EqualFold(s, "-inf") || strings.EqualFold(s, "-infinity") {
		return new(big.Rat).SetInt64(-1), false, true
	}
	r, okR := new(big.Rat).SetString(s)
	if !okR {
		return nil, false, false
	}
	return r, false, true
}

func ratFloorCeilUint64R63(r *big.Rat) (floorU uint64, isInt bool) {
	num := new(big.Int).Set(r.Num())
	den := r.Denom()
	q, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	return q.Uint64(), rem.Sign() == 0
}

// NormalizeUnsignedLongRangeBoundsExactR63 normalizes `unsigned_long` `gt`/`gte`/`lt`/`lte`
// bounds with arbitrary-precision rational arithmetic (`math/big.Rat`), avoiding IEEE-754
// `float64` rounding loss on 64-bit decimal strings like `"18446744073709551614.5"` (`F11`).
func NormalizeUnsignedLongRangeBoundsExactR63(gt, gte, lt, lte any) (outGT, outGTE, outLT, outLTE any, ok bool) {
	effMin := uint64(0)
	effMax := uint64(math.MaxUint64)
	hasLower := false
	hasUpper := false

	if lt != nil {
		r, aboveInf, valid := parseUnsignedLongArbitraryRatR63(lt)
		if !valid || (!aboveInf && r.Sign() <= 0) {
			return nil, nil, nil, nil, false
		}
		hasUpper = true
		if aboveInf || r.Cmp(maxUint64BigRatR63) > 0 {
			outLTE = uint64(math.MaxUint64)
		} else {
			floorU, isInt := ratFloorCeilUint64R63(r)
			if isInt {
				if floorU == 0 {
					return nil, nil, nil, nil, false
				}
				effMax = floorU - 1
				outLT = floorU
			} else {
				effMax = floorU
				outLTE = floorU
			}
		}
	}
	if lte != nil {
		r, aboveInf, valid := parseUnsignedLongArbitraryRatR63(lte)
		if !valid || (!aboveInf && r.Sign() < 0) {
			return nil, nil, nil, nil, false
		}
		var candMax uint64
		if aboveInf || r.Cmp(maxUint64BigRatR63) > 0 {
			candMax = math.MaxUint64
		} else {
			candMax, _ = ratFloorCeilUint64R63(r)
		}
		if !hasUpper || candMax < effMax {
			effMax = candMax
		}
		hasUpper = true
		if outLT != nil {
			if ltU, isU := outLT.(uint64); isU && candMax < ltU-1 {
				outLT = nil
				outLTE = candMax
			}
		} else if outLTE != nil {
			if prevU, isU := outLTE.(uint64); !isU || candMax < prevU {
				outLTE = candMax
			}
		} else {
			outLTE = candMax
		}
	}
	if gt != nil {
		r, aboveInf, valid := parseUnsignedLongArbitraryRatR63(gt)
		if !valid || aboveInf {
			return nil, nil, nil, nil, false
		}
		hasLower = true
		if r.Sign() < 0 {
			outGTE = uint64(0)
		} else if r.Cmp(maxUint64BigRatR63) >= 0 {
			return nil, nil, nil, nil, false
		} else {
			floorU, isInt := ratFloorCeilUint64R63(r)
			if floorU == math.MaxUint64 {
				return nil, nil, nil, nil, false
			}
			effMin = floorU + 1
			if isInt {
				outGT = floorU
			} else {
				outGTE = floorU + 1
			}
		}
	}
	if gte != nil {
		r, aboveInf, valid := parseUnsignedLongArbitraryRatR63(gte)
		if !valid || aboveInf {
			return nil, nil, nil, nil, false
		}
		var candMin uint64
		if r.Sign() < 0 {
			candMin = 0
		} else if r.Cmp(maxUint64BigRatR63) > 0 {
			return nil, nil, nil, nil, false
		} else {
			floorU, isInt := ratFloorCeilUint64R63(r)
			if isInt {
				candMin = floorU
			} else {
				if floorU == math.MaxUint64 {
					return nil, nil, nil, nil, false
				}
				candMin = floorU + 1
			}
		}
		if !hasLower || candMin > effMin {
			effMin = candMin
		}
		hasLower = true
		if outGT != nil {
			if gtU, isU := outGT.(uint64); isU && candMin > gtU+1 {
				outGT = nil
				outGTE = candMin
			}
		} else if outGTE != nil {
			if prevU, isU := outGTE.(uint64); !isU || candMin > prevU {
				outGTE = candMin
			}
		} else {
			outGTE = candMin
		}
	}
	if hasLower && hasUpper && effMin > effMax {
		return nil, nil, nil, nil, false
	}
	return outGT, outGTE, outLT, outLTE, true
}

// NormalizeESVersionRangeBoundR63 validates and normalizes a `version` field range bound,
// accepting full SemVer strings as well as 1- or 2-segment numeric version bounds like `"9999"` or `"1.2"` (`F11`).
func NormalizeESVersionRangeBoundR63(cand any) (string, bool) {
	if cand == nil {
		return "", false
	}
	var s string
	switch v := cand.(type) {
	case string:
		s = v
	case json.Number:
		s = v.String()
	case int:
		if v < 0 {
			return "", false
		}
		s = strconv.Itoa(v)
	case int64:
		if v < 0 {
			return "", false
		}
		s = strconv.FormatInt(v, 10)
	case uint64:
		s = strconv.FormatUint(v, 10)
	default:
		return "", false
	}
	if s == "" || strings.TrimSpace(s) != s {
		return "", false
	}
	if schema.ValidateSemver(s) {
		return s, true
	}
	// ES `version` range queries also accept relaxed numeric prefixes (`"9999"`, `"1.2"`, `"1.2.3.4.5"`).
	work := s
	if plusIdx := strings.IndexByte(work, '+'); plusIdx >= 0 {
		build := work[plusIdx+1:]
		work = work[:plusIdx]
		if !isValidSemverDotIdentListR63(build) {
			return "", false
		}
	}
	if dashIdx := strings.IndexByte(work, '-'); dashIdx >= 0 {
		pre := work[dashIdx+1:]
		work = work[:dashIdx]
		if !isValidSemverDotIdentListR63(pre) {
			return "", false
		}
		for _, preSeg := range strings.Split(pre, ".") {
			if isPureDigitsASCII(preSeg) && len(preSeg) > 1 && preSeg[0] == '0' {
				return "", false
			}
		}
	}
	if work == "" {
		return "", false
	}
	segs := strings.Split(work, ".")
	for _, seg := range segs {
		if !isPureDigitsASCII(seg) || (len(seg) > 1 && seg[0] == '0') {
			return "", false
		}
	}
	return s, true
}

func isValidSemverDotIdentListR63(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			isAlnumOrHyphen := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'
			if !isAlnumOrHyphen {
				return false
			}
		}
	}
	return true
}

// ConstantKeywordScalarExprR63 builds the scalar SQL expression for a `constant_keyword`
// field with configured `ConstantValue`: returns `rawCol` when present, `ConstantValue` when
// the field is omitted from `_source`, and `NULL` when `_source` explicitly sets `null` or `[]` (`F11`).
func ConstantKeywordScalarExprR63(rawCol string, field string, b schema.FieldBinding) string {
	if b.ESType != "constant_keyword" || !b.HasConstantValue || b.ConstantValue == nil || b.AdoptedConstantValue {
		return rawCol
	}
	pathField := field
	if len(b.SourceJSONPath) > 0 {
		pathField = strings.Join(b.SourceJSONPath, ".")
	}
	nestedPath, dottedPath, hasDot := BuildQuotedDorisJSONPaths(pathField)
	var absentCond string
	if !hasDot {
		absentCond = fmt.Sprintf("JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) IS NULL", quoteStr(nestedPath))
	} else {
		absentCond = fmt.Sprintf("(JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) IS NULL AND JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) IS NULL)",
			quoteStr(nestedPath), quoteStr(dottedPath))
	}
	constLit := quoteStr(fmt.Sprintf("%v", b.ConstantValue))
	return fmt.Sprintf("IF(%s IS NOT NULL, %s, IF(`_source` IS NOT NULL AND `_source` != '' AND %s, %s, NULL))",
		rawCol, rawCol, absentCond, constLit)
}

// IsSubpathUnderAggregateMetricDoubleR63 reports whether `field` is a dotted subpath (`X.Y`)
// underneath an `aggregate_metric_double` field `X` (`10_basic.yml`: `metric.min` has no sub-field mapping).
func IsSubpathUnderAggregateMetricDoubleR63(s *schema.IndexSchema, field string) bool {
	if s == nil || !strings.Contains(field, ".") {
		return false
	}
	for idx := strings.IndexByte(field, '.'); idx > 0; {
		prefix := field[:idx]
		if fb, ok := s.Fields[prefix]; ok && fb.ESType == "aggregate_metric_double" {
			return true
		}
		nextRel := strings.IndexByte(field[idx+1:], '.')
		if nextRel < 0 {
			break
		}
		idx = idx + 1 + nextRel
	}
	return false
}

func findAggregateMetricSubBindingR63(b schema.FieldBinding, metric string) (schema.FieldBinding, bool) {
	m := strings.ToLower(strings.TrimSpace(metric))
	if m == "" {
		return schema.FieldBinding{}, false
	}
	if len(b.AggregateMetrics) > 0 {
		allowed := false
		for _, am := range b.AggregateMetrics {
			if strings.EqualFold(strings.TrimSpace(am), m) {
				allowed = true
				break
			}
		}
		if !allowed {
			return schema.FieldBinding{}, false
		}
	}
	for _, sb := range schema.AggregateMetricSubColumns(b) {
		if strings.HasSuffix(sb.ColumnName, "__"+m) || strings.HasSuffix(sb.ESFieldPath, "."+m) {
			return sb, true
		}
	}
	return schema.FieldBinding{}, false
}

// CompileAggregateMetricExistsExprR63 builds the `exists` SQL predicate for an
// `aggregate_metric_double` field (`OR` across all configured sub-columns).
func CompileAggregateMetricExistsExprR63(b schema.FieldBinding) string {
	subs := schema.AggregateMetricSubColumns(b)
	if len(subs) == 0 {
		return "FALSE"
	}
	var conds []string
	for _, sb := range subs {
		if sb.ColumnName != "" {
			conds = append(conds, fmt.Sprintf("`%s` IS NOT NULL", sb.ColumnName))
		}
	}
	if len(conds) == 0 {
		return "FALSE"
	}
	if len(conds) == 1 {
		return conds[0]
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

// ResolveAggregateMetricDefaultBindingR63 returns the sub-column binding corresponding to
// `b.DefaultMetric` for `term`, `terms`, `range`, and `sort` on an `aggregate_metric_double` field.
func ResolveAggregateMetricDefaultBindingR63(b schema.FieldBinding) (schema.FieldBinding, bool) {
	defMetric := strings.TrimSpace(b.DefaultMetric)
	if defMetric == "" && len(b.AggregateMetrics) > 0 {
		defMetric = b.AggregateMetrics[0]
	}
	return findAggregateMetricSubBindingR63(b, defMetric)
}

func (t *Transpiler) appendTopLevelAggregateMetricDoubleR63(
	branches *[]string,
	fullAggName string,
	extraWhere string,
	spec esast.AggSpec,
) bool {
	var metricKind string
	var mSpec *esast.MetricAggSpec
	switch {
	case spec.Min != nil && spec.Min.Script == nil:
		metricKind, mSpec = "min", spec.Min
	case spec.Max != nil && spec.Max.Script == nil:
		metricKind, mSpec = "max", spec.Max
	case spec.Sum != nil && spec.Sum.Script == nil:
		metricKind, mSpec = "sum", spec.Sum
	case spec.Avg != nil && spec.Avg.Script == nil:
		metricKind, mSpec = "avg", spec.Avg
	case spec.ValueCount != nil && spec.ValueCount.Script == nil:
		metricKind, mSpec = "value_count", spec.ValueCount
	case spec.Stats != nil && spec.Stats.Script == nil:
		metricKind, mSpec = "stats", spec.Stats
	default:
		return false
	}
	if mSpec == nil || strings.TrimSpace(mSpec.Field) == "" {
		return false
	}
	_, b := t.resolveFieldInNestedCtx(mSpec.Field, false, nil)
	if b.ESType != "aggregate_metric_double" {
		return false
	}

	wClause := ""
	if extraWhere != "" && extraWhere != "TRUE" {
		wClause = " WHERE " + extraWhere
	}

	emitSimple := func(aggName, bucketKey, fn, subMetric string, withHaving bool) bool {
		sb, ok := findAggregateMetricSubBindingR63(b, subMetric)
		if !ok {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [%s] aggregation on aggregate_metric_double field [%s] that does not store [%s] metric", metricKind, mSpec.Field, subMetric))
			}
			return true
		}
		col := fmt.Sprintf("`%s`", sb.ColumnName)
		having := ""
		if withHaving {
			having = fmt.Sprintf(" HAVING COUNT(%s) > 0", col)
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s%s",
			quoteStr(aggName), quoteStr(bucketKey), fn, col, wClause, having,
		))
		return true
	}

	emitAvg := func(aggName, bucketKey string) bool {
		sbSum, okS := findAggregateMetricSubBindingR63(b, "sum")
		sbCnt, okC := findAggregateMetricSubBindingR63(b, "value_count")
		if !okS || !okC {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [avg] aggregation on aggregate_metric_double field [%s] that does not store both [sum] and [value_count] metrics", mSpec.Field))
			}
			return true
		}
		sumCol := fmt.Sprintf("`%s`", sbSum.ColumnName)
		cntCol := fmt.Sprintf("`%s`", sbCnt.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s) / NULLIF(SUM(CAST(%s AS DOUBLE)), 0), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s HAVING SUM(%s) > 0",
			quoteStr(aggName), quoteStr(bucketKey), sumCol, cntCol, wClause, cntCol,
		))
		if bucketKey == "_metric" {
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_avg_weight' AS `_bucket_key`, CAST(COALESCE(SUM(%s), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s HAVING SUM(%s) > 0",
				quoteStr(aggName), cntCol, wClause, cntCol,
			))
		}
		return true
	}

	switch metricKind {
	case "min":
		return emitSimple(fullAggName, "_metric", "MIN", "min", true)
	case "max":
		return emitSimple(fullAggName, "_metric", "MAX", "max", true)
	case "sum":
		return emitSimple(fullAggName, "_metric", "SUM", "sum", false)
	case "value_count":
		return emitSimple(fullAggName, "_metric", "SUM", "value_count", false)
	case "avg":
		return emitAvg(fullAggName, "_metric")
	case "stats":
		emitSimple(fullAggName+"._stats_count", "_stats_count", "SUM", "value_count", false)
		emitSimple(fullAggName+"._stats_min", "_stats_min", "MIN", "min", true)
		emitSimple(fullAggName+"._stats_max", "_stats_max", "MAX", "max", true)
		emitSimple(fullAggName+"._stats_sum", "_stats_sum", "SUM", "sum", false)
		emitAvg(fullAggName+"._stats_avg", "_stats_avg")
		return true
	}
	return false
}

func (t *Transpiler) appendSubAggregateMetricDoubleR63(
	branches *[]string,
	subFull string,
	fn string,
	fieldName string,
	b schema.FieldBinding,
	parentBucketExpr string,
	fromClause string,
	whereClause string,
) {
	switch fn {
	case "MIN":
		sb, ok := findAggregateMetricSubBindingR63(b, "min")
		if !ok {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [min] aggregation on aggregate_metric_double field [%s]", fieldName))
			}
			return
		}
		col := fmt.Sprintf("`%s`", sb.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(MIN(%s), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key` HAVING COUNT(%s) > 0",
			quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause, col,
		))
	case "MAX":
		sb, ok := findAggregateMetricSubBindingR63(b, "max")
		if !ok {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [max] aggregation on aggregate_metric_double field [%s]", fieldName))
			}
			return
		}
		col := fmt.Sprintf("`%s`", sb.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(MAX(%s), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key` HAVING COUNT(%s) > 0",
			quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause, col,
		))
	case "SUM":
		sb, ok := findAggregateMetricSubBindingR63(b, "sum")
		if !ok {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [sum] aggregation on aggregate_metric_double field [%s]", fieldName))
			}
			return
		}
		col := fmt.Sprintf("`%s`", sb.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key`",
			quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
		))
	case "COUNT":
		sb, ok := findAggregateMetricSubBindingR63(b, "value_count")
		if !ok {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [value_count] aggregation on aggregate_metric_double field [%s]", fieldName))
			}
			return
		}
		col := fmt.Sprintf("`%s`", sb.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key`",
			quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
		))
	case "AVG":
		sbSum, okS := findAggregateMetricSubBindingR63(b, "sum")
		sbCnt, okC := findAggregateMetricSubBindingR63(b, "value_count")
		if !okS || !okC {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Cannot compute [avg] aggregation on aggregate_metric_double field [%s]", fieldName))
			}
			return
		}
		sumCol := fmt.Sprintf("`%s`", sbSum.ColumnName)
		cntCol := fmt.Sprintf("`%s`", sbCnt.ColumnName)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s) / NULLIF(SUM(CAST(%s AS DOUBLE)), 0), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key` HAVING SUM(%s) > 0",
			quoteStr(subFull), parentBucketExpr, sumCol, cntCol, fromClause, whereClause, cntCol,
		))
		if !strings.HasSuffix(subFull, "._stats_avg") {
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s), 0) AS DOUBLE) AS `_doc_count` FROM %s WHERE %s GROUP BY `_bucket_key` HAVING SUM(%s) > 0",
				quoteStr(subFull+"._avg_weight"), parentBucketExpr, cntCol, fromClause, whereClause, cntCol,
			))
		}
	}
}

func (t *Transpiler) buildCountedTermsSourceArrayExprR63(effField string, b schema.FieldBinding) (arrExpr string, isPromotedCol bool) {
	if (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
		return b.EffectiveArrayColumn(true), true
	}
	col := t.sqlColumnRef(effField, true, nil)
	isArrayCond := sqlRuntimeSourceJSONTypeIsArrayExpr(effField)
	rawStr := sqlRuntimeSourceStringExpr(effField)
	return fmt.Sprintf("CASE WHEN %s THEN TRY_CAST(%s AS ARRAY<STRING>) WHEN %s IS NOT NULL THEN [CAST(%s AS STRING)] ELSE NULL END",
		isArrayCond, rawStr, col, col), false
}

// appendRound63TopLevelAggBranch handles Round-63 top-level aggregations (`counted_terms` and
// `aggregate_metric_double` metric aggs).
func (t *Transpiler) appendRound63TopLevelAggBranch(
	branches *[]string,
	subIdx *int,
	fullAggName string,
	extraWhere string,
	wherePrefix string,
	spec esast.AggSpec,
) bool {
	if t.appendTopLevelAggregateMetricDoubleR63(branches, fullAggName, extraWhere, spec) {
		return true
	}
	if spec.CountedTerms == nil {
		return false
	}
	ctSpec := spec.CountedTerms
	effField := strings.TrimSpace(ctSpec.Field)
	if effField == "" && ctSpec.Script != nil {
		if df, ok := extractSimpleDocFieldFromScript(ctSpec.Script); ok {
			effField = df
		}
	}
	_, b := t.resolveFieldInNestedCtx(effField, true, nil)
	size := t.maxAggBuckets()
	if capSz := t.capBucketSize(ctSpec.Size); capSz > size {
		size = capSz
	}
	*subIdx++
	arrRef, isPromoted := t.buildCountedTermsSourceArrayExprR63(effField, b)
	var explodeTarget string
	if isPromoted {
		explodeTarget = fmt.Sprintf("`%s`", arrRef)
	} else {
		explodeTarget = arrRef
	}
	elemExpr := "`_elem`"
	if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) {
		elemExpr = "LOWER(CAST(`_elem` AS STRING))"
	}
	bucketKeyExpr := fmt.Sprintf("CAST(%s AS STRING)", elemExpr)
	*branches = append(*branches, fmt.Sprintf(
		"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
			"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_t` AS `_elem` "+
			"WHERE %s`_elem` IS NOT NULL "+
			"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
			") `_agg_sub_%d`",
		quoteStr(fullAggName), bucketKeyExpr, explodeTarget, wherePrefix, size, *subIdx,
	))
	if subAggs := spec.SubAggs(); len(subAggs) > 0 {
		explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(%s) `_t` AS `_elem`", explodeTarget)
		explodeWhere := fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
		t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketKeyExpr, explodeFrom, explodeWhere, subAggs)
	}
	return true
}

// appendRound63GroupedSubAggBranch handles `counted_terms` and `aggregate_metric_double` `value_count`
// when nested under parent bucket/sampler aggregations.
func (t *Transpiler) appendRound63GroupedSubAggBranch(
	branches *[]string,
	subIdx *int,
	subFull string,
	parentBucketExpr string,
	fromClause string,
	whereClause string,
	subTableAlias string,
	subElemAlias string,
	nctx *nestedCtx,
	subSpec esast.AggSpec,
) bool {
	if subSpec.ValueCount != nil && subSpec.ValueCount.Script == nil && strings.TrimSpace(subSpec.ValueCount.Field) != "" {
		_, b := t.resolveFieldInNestedCtx(subSpec.ValueCount.Field, false, nctx)
		if b.ESType == "aggregate_metric_double" {
			t.appendSubAggregateMetricDoubleR63(branches, subFull, "COUNT", subSpec.ValueCount.Field, b, parentBucketExpr, fromClause, whereClause)
			return true
		}
	}
	if stSpec := subSpec.EffectiveStats(); stSpec != nil && stSpec.Script == nil && strings.TrimSpace(stSpec.Field) != "" {
		_, b := t.resolveFieldInNestedCtx(stSpec.Field, false, nctx)
		if b.ESType == "aggregate_metric_double" {
			t.appendSubAggregateMetricDoubleR63(branches, subFull+"._stats_count", "COUNT", stSpec.Field, b, parentBucketExpr, fromClause, whereClause)
			t.appendSubAggregateMetricDoubleR63(branches, subFull+"._stats_min", "MIN", stSpec.Field, b, parentBucketExpr, fromClause, whereClause)
			t.appendSubAggregateMetricDoubleR63(branches, subFull+"._stats_max", "MAX", stSpec.Field, b, parentBucketExpr, fromClause, whereClause)
			t.appendSubAggregateMetricDoubleR63(branches, subFull+"._stats_sum", "SUM", stSpec.Field, b, parentBucketExpr, fromClause, whereClause)
			t.appendSubAggregateMetricDoubleR63(branches, subFull+"._stats_avg", "AVG", stSpec.Field, b, parentBucketExpr, fromClause, whereClause)
			return true
		}
	}
	if subSpec.CountedTerms == nil {
		return false
	}
	ctSpec := subSpec.CountedTerms
	effField := strings.TrimSpace(ctSpec.Field)
	_, b := t.resolveFieldInNestedCtx(effField, true, nctx)
	size := t.maxAggBuckets()
	if capSz := t.capBucketSize(ctSpec.Size); capSz > size {
		size = capSz
	}
	arrRef, isPromoted := t.buildCountedTermsSourceArrayExprR63(effField, b)
	var explodeTarget string
	if isPromoted {
		explodeTarget = fmt.Sprintf("`%s`", arrRef)
	} else {
		explodeTarget = arrRef
	}
	elemExpr := subElemAlias
	if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) {
		elemExpr = fmt.Sprintf("LOWER(CAST(%s AS STRING))", subElemAlias)
	}
	childKeyExpr := fmt.Sprintf("CONCAT_WS('\\x1f', CAST(%s AS STRING), CAST(%s AS STRING))", parentBucketExpr, elemExpr)
	subFrom := appendLateralViewToFromClause(fromClause, fmt.Sprintf("LATERAL VIEW EXPLODE(%s) %s AS %s", explodeTarget, subTableAlias, subElemAlias))
	subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
	*subIdx++
	*branches = append(*branches, fmt.Sprintf(
		"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
			"FROM %s WHERE %s "+
			"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
			") `_agg_sub_%d`",
		quoteStr(subFull), childKeyExpr, subFrom, subWhere, size, *subIdx,
	))
	if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
		t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, subFrom, subWhere, nctx, nestedSubs)
	}
	return true
}

// CoerceMurmur3TermValueR63 coerces a `term` / `terms` query scalar on a `murmur3` field
// to its signed 64-bit Murmur3 hash (`F11`).
func CoerceMurmur3TermValueR63(val any) (int64, bool) {
	switch v := val.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case uint64:
		if v <= math.MaxInt64 {
			return int64(v), true
		}
		return schema.ComputeESMurmur3Hash(strconv.FormatUint(v, 10)), true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return iv, true
		}
		return schema.ComputeESMurmur3Hash(v.String()), true
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) {
			return int64(v), true
		}
		return 0, false
	case string:
		if iv, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return iv, true
		}
		return schema.ComputeESMurmur3Hash(v), true
	default:
		return 0, false
	}
}

// BuildGeoPointOrShapeLatLonExprsR63 extracts `(latExpr, lonExpr, notNullCond)` for a `geo_point`
// or `geo_shape` field, supporting `"lat,lon"`, WKT `"POINT (lon lat)"`, GeoJSON `{"type":"Point","coordinates":[lon,lat]}`,
// `[lon, lat]`, `{"lat":...,"lon":...}`, and scriptless runtime `geo_point`/`geo_shape` fields (`F11`).
func (t *Transpiler) BuildGeoPointOrShapeLatLonExprsR63(resolvedField string, b schema.FieldBinding) (latExpr, lonExpr, notNullCond string) {
	_, _, isRT := t.resolveScriptlessRuntimeField(resolvedField)
	if b.ESType != "geo_shape" && !b.FromRuntime && !isRT {
		return "", "", ""
	}
	// Preserve dynamic `_doc`['field']['coordinates'] path when `b.Kind == StorageDynamicVariant` and not runtime (`TestRound48TranspilerSpecCompliance`).
	if b.Kind == schema.StorageDynamicVariant && !b.FromRuntime && !isRT {
		return "", "", ""
	}
	var rawStrExpr string
	if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
		srcStr := sqlRuntimeSourceStringExpr(resolvedField)
		rawStrExpr = fmt.Sprintf("COALESCE(`%s`, %s)", b.ColumnName, srcStr)
	} else {
		rawStrExpr = sqlRuntimeSourceStringExpr(resolvedField)
	}
	latExpr, lonExpr = buildSingleGeoScalarLatLonSQLR63(rawStrExpr)
	notNullCond = fmt.Sprintf("%s IS NOT NULL AND %s IS NOT NULL", latExpr, lonExpr)
	return latExpr, lonExpr, notNullCond
}

func buildSingleGeoScalarLatLonSQLR63(rawStrExpr string) (latExpr, lonExpr string) {
	// Order of extraction (zero backslashes in regex patterns so SQL & Go string escaping never collide):
	// 1. JSON object `{"lat": ..., "lon": ...}`
	// 2. GeoJSON `{"type": "...", "coordinates": ...}` (1D `[lon, lat]` or nested `[[lon, lat], ...]`)
	// 3. WKT `POINT (lon lat)` and `BBOX (minLon, maxLon, maxLat, minLat)`
	// 4. JSON array `[lon, lat]` (when `JSON_TYPE(...) = 'ARRAY'`)
	// 5. `"lat,lon"` string (when not WKT or JSON)
	// 6. Fallback first coordinate pair in WKT `POLYGON` / `LINESTRING` / `MULTIPOINT`
	wktPointLon := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^POINT[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]+([-+0-9.eE]+)[[:space:]]*[)]$', 1) AS DOUBLE)", rawStrExpr)
	wktPointLat := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^POINT[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]+([-+0-9.eE]+)[[:space:]]*[)]$', 2) AS DOUBLE)", rawStrExpr)
	bboxMinLon := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^BBOX[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*[)]$', 1) AS DOUBLE)", rawStrExpr)
	bboxMaxLon := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^BBOX[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*[)]$', 2) AS DOUBLE)", rawStrExpr)
	bboxMaxLat := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^BBOX[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*[)]$', 3) AS DOUBLE)", rawStrExpr)
	bboxMinLat := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^BBOX[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)[[:space:]]*[)]$', 4) AS DOUBLE)", rawStrExpr)
	wktBBoxLon := fmt.Sprintf("((%s + %s) / 2.0)", bboxMinLon, bboxMaxLon)
	wktBBoxLat := fmt.Sprintf("((%s + %s) / 2.0)", bboxMaxLat, bboxMinLat)
	coordsJSON := fmt.Sprintf("json_extract_string(%s, '$.\"coordinates\"')", rawStrExpr)
	geoJSONLon := fmt.Sprintf("COALESCE(CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE), TRY_CAST(REGEXP_EXTRACT(%s, '^[[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)', 1) AS DOUBLE))", coordsJSON, coordsJSON)
	geoJSONLat := fmt.Sprintf("COALESCE(CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE), TRY_CAST(REGEXP_EXTRACT(%s, '^[[[:space:]]*([-+0-9.eE]+)[[:space:]]*,[[:space:]]*([-+0-9.eE]+)', 2) AS DOUBLE))", coordsJSON, coordsJSON)
	objLat := fmt.Sprintf("TRY_CAST(json_extract_string(%s, '$.\"lat\"') AS DOUBLE)", rawStrExpr)
	objLon := fmt.Sprintf("TRY_CAST(json_extract_string(%s, '$.\"lon\"') AS DOUBLE)", rawStrExpr)
	arrLon := fmt.Sprintf("CASE WHEN JSON_TYPE(TRY_CAST(%s AS JSON), '$') = 'ARRAY' THEN TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE) ELSE NULL END", rawStrExpr, rawStrExpr)
	arrLat := fmt.Sprintf("CASE WHEN JSON_TYPE(TRY_CAST(%s AS JSON), '$') = 'ARRAY' THEN TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE) ELSE NULL END", rawStrExpr, rawStrExpr)
	csvLat := fmt.Sprintf("CASE WHEN %s NOT LIKE '[%%' AND %s NOT REGEXP '^[[:space:]]*[A-Za-z{]' AND LOCATE(',', %s) > 0 THEN TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE) ELSE NULL END", rawStrExpr, rawStrExpr, rawStrExpr, rawStrExpr)
	csvLon := fmt.Sprintf("CASE WHEN %s NOT LIKE '[%%' AND %s NOT REGEXP '^[[:space:]]*[A-Za-z{]' AND LOCATE(',', %s) > 0 THEN TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE) ELSE NULL END", rawStrExpr, rawStrExpr, rawStrExpr, rawStrExpr)
	wktAnyLon := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^[A-Z]+[[:space:]]*[(]+[[:space:]]*([-+0-9.eE]+)[[:space:]]+([-+0-9.eE]+)', 1) AS DOUBLE)", rawStrExpr)
	wktAnyLat := fmt.Sprintf("TRY_CAST(REGEXP_EXTRACT(TRIM(%s), '(?i)^[A-Z]+[[:space:]]*[(]+[[:space:]]*([-+0-9.eE]+)[[:space:]]+([-+0-9.eE]+)', 2) AS DOUBLE)", rawStrExpr)

	latExpr = fmt.Sprintf("COALESCE(%s, %s, %s, %s, %s, %s, %s)", objLat, geoJSONLat, wktPointLat, wktBBoxLat, arrLat, csvLat, wktAnyLat)
	lonExpr = fmt.Sprintf("COALESCE(%s, %s, %s, %s, %s, %s, %s)", objLon, geoJSONLon, wktPointLon, wktBBoxLon, arrLon, csvLon, wktAnyLon)
	return latExpr, lonExpr
}

// sqlRuntimeGeoArrayExprR63 extracts a `geo_point` / `geo_shape` value from `_source` as an `ARRAY<STRING>`,
// keeping a single `[lon, lat]` coordinate pair array (`[-71.34, 41.12]`, where `TRY_CAST(... AS ARRAY<DOUBLE>) IS NOT NULL`)
// intact as a 1-element array while splitting multi-point arrays (`["41.12,-71.34", ...]`, `[[-71.34, 41.12], ...]`).
func sqlRuntimeGeoArrayExprR63(field string) string {
	rawStr := sqlRuntimeSourceStringExpr(field)
	isArrayCond := sqlRuntimeSourceJSONTypeIsArrayExpr(field)
	return fmt.Sprintf(
		"CASE WHEN %s IS NULL THEN NULL WHEN %s AND TRY_CAST(%s AS ARRAY<DOUBLE>) IS NULL THEN TRY_CAST(%s AS ARRAY<STRING>) ELSE [%s] END",
		rawStr, isArrayCond, rawStr, rawStr, rawStr,
	)
}

// evalGeoPointPredForFieldWithRelationR63 evaluates `buildCond(latExpr, lonExpr)` over scalar,
// promoted-array, nested, or scriptless-runtime `geo_point`/`geo_shape` fields, enforcing universal
// quantification (`ALL` elements match) when `rel == "WITHIN"` vs existential (`ANY` element matches)
// when `rel == "INTERSECTS"` (`101_geo_point_from_source.yml`, `102_geo_point_source_in_query.yml`).
func (t *Transpiler) evalGeoPointPredForFieldWithRelationR63(field, rel string, nctx *nestedCtx, buildCond func(latExpr, lonExpr string) string) string {
	isWithin := strings.EqualFold(strings.TrimSpace(rel), "WITHIN")
	resolvedField, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return "FALSE"
	}
	if nctx == nil {
		_, rtType, isRT := t.resolveScriptlessRuntimeField(field)
		if b.FromRuntime || (isRT && (rtType == "geo_point" || rtType == "geo_shape")) {
			srcField := resolvedField
			if srcField == "" {
				srcField = field
			}
			arrExpr := sqlRuntimeGeoArrayExprR63(srcField)
			if b.Kind == schema.StoragePromotedArray && b.EffectiveArrayColumn(true) != "" {
				arrExpr = fmt.Sprintf("COALESCE(`%s`, %s)", b.EffectiveArrayColumn(true), arrExpr)
			} else if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
				arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NOT NULL THEN [`%s`] ELSE %s END", b.ColumnName, b.ColumnName, arrExpr)
			}
			latX, lonX := buildSingleGeoScalarLatLonSQLR63("_x")
			validX := fmt.Sprintf("(_x IS NOT NULL AND %s IS NOT NULL AND %s IS NOT NULL)", latX, lonX)
			if isWithin {
				return fmt.Sprintf("(%s IS NOT NULL AND array_exists(_x -> %s, %s) AND NOT array_exists(_x -> %s AND NOT (%s), %s))",
					arrExpr, validX, arrExpr, validX, buildCond(latX, lonX), arrExpr)
			}
			return fmt.Sprintf("array_exists(_x -> %s AND (%s), %s)", validX, buildCond(latX, lonX), arrExpr)
		}
	}
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr, lonExpr := buildSingleGeoScalarLatLonSQLR63(elemExpr)
		return fmt.Sprintf("(%s IS NOT NULL AND %s IS NOT NULL AND %s IS NOT NULL AND %s)", elemExpr, latExpr, lonExpr, buildCond(latExpr, lonExpr))
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr, lonExpr := buildSingleGeoScalarLatLonSQLR63("_x")
		validX := fmt.Sprintf("(_x IS NOT NULL AND %s IS NOT NULL AND %s IS NOT NULL)", latExpr, lonExpr)
		if isWithin {
			return fmt.Sprintf("(%s IS NOT NULL AND array_exists(_x -> %s, %s) AND NOT array_exists(_x -> %s AND NOT (%s), %s))",
				arrCol, validX, arrCol, validX, buildCond(latExpr, lonExpr), arrCol)
		}
		return fmt.Sprintf("array_exists(_x -> %s AND (%s), %s)", validX, buildCond(latExpr, lonExpr), arrCol)
	}
	latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(resolvedField, b)
	return fmt.Sprintf("(%s AND %s)", notNullCond, buildCond(latExpr, lonExpr))
}

// ----------------------------------------------------------------------------
// Round 63 F13: Vector Search (`search.vectors` — Nested kNN Query, Quantized
// Dynamic Vector Fallback, Nonexistent Field `400`, & Multi-Map `sparse_vector`)
// ----------------------------------------------------------------------------

func (t *Transpiler) fieldBelongsToNestedPathR63(rawField, nestedPath string) bool {
	clean, _ := parseFieldBoost(rawField, 1.0)
	if strings.HasPrefix(clean, nestedPath+".") {
		return true
	}
	if t.Schema != nil {
		if fb := t.Schema.ResolveEffectiveField(clean, false); fb.NestedPath == nestedPath {
			return true
		}
	}
	return false
}

func (t *Transpiler) queryReferencesNestedPathR63(q *esast.Query, nestedPath string) bool {
	if q == nil || nestedPath == "" {
		return false
	}
	for k := range q.Term {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	if q.Terms != nil {
		for k := range q.Terms.Fields {
			if k != "boost" && k != "_name" && t.fieldBelongsToNestedPathR63(k, nestedPath) {
				return true
			}
		}
	}
	for k := range q.Range {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.Prefix {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.Wildcard {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.Regexp {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.Fuzzy {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.Match {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.MatchPhrase {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	for k := range q.MatchPhrasePrefix {
		if t.fieldBelongsToNestedPathR63(k, nestedPath) {
			return true
		}
	}
	if q.Exists != nil && t.fieldBelongsToNestedPathR63(q.Exists.Field, nestedPath) {
		return true
	}
	if q.KNN != nil && t.fieldBelongsToNestedPathR63(q.KNN.Field, nestedPath) {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if t.queryReferencesNestedPathR63(&q.Bool.Must[i], nestedPath) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if t.queryReferencesNestedPathR63(&q.Bool.Filter[i], nestedPath) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if t.queryReferencesNestedPathR63(&q.Bool.Should[i], nestedPath) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if t.queryReferencesNestedPathR63(&q.Bool.MustNot[i], nestedPath) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && t.queryReferencesNestedPathR63(&q.ConstantScore.Filter, nestedPath) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if t.queryReferencesNestedPathR63(&q.DisMax.Queries[i], nestedPath) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if t.queryReferencesNestedPathR63(&q.Boosting.Positive, nestedPath) || t.queryReferencesNestedPathR63(&q.Boosting.Negative, nestedPath) {
			return true
		}
	}
	return false
}

// buildVectorSourceFallbackColExprR63 builds a `dense_vector` `ARRAY<FLOAT>` SQL expression
// that falls back to `TRY_CAST(json_extract_string(\`_source\`, path) AS ARRAY<FLOAT>)` when
// dynamic/auto-dims quantized vectors (`int8_hnsw`, `int8_flat`, `bbq_*`) have not yet populated
// a promoted `vec__*` column (`41_knn_search_byte_quantized.yml`, `42_knn_search_int8_flat.yml`).
func buildVectorSourceFallbackColExprR63(resolvedField string, b schema.FieldBinding) string {
	pathField := resolvedField
	if len(b.SourceJSONPath) > 0 {
		pathField = strings.Join(b.SourceJSONPath, ".")
	}
	nestedPath, _, _ := BuildQuotedDorisJSONPaths(pathField)
	srcVecExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_source`, %s) AS ARRAY<FLOAT>)", quoteStr(nestedPath))
	if b.ColumnName != "" {
		return fmt.Sprintf("IF(`%s` IS NOT NULL AND array_size(`%s`) > 0, `%s`, %s)", b.ColumnName, b.ColumnName, b.ColumnName, srcVecExpr)
	}
	var pathBuilder strings.Builder
	segs := b.SourceJSONPath
	if len(segs) == 0 && resolvedField != "" {
		segs = strings.Split(resolvedField, ".")
	}
	for _, seg := range segs {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	return fmt.Sprintf("COALESCE(TRY_CAST(`_doc`%s AS ARRAY<FLOAT>), %s)", pathBuilder.String(), srcVecExpr)
}

func extractNestedKNNAndPostFiltersR63(q *esast.Query) (kq *esast.KNNQuery, postClauses []esast.Query, postMustNot []esast.Query, ok bool) {
	if q == nil {
		return nil, nil, nil, false
	}
	if q.KNN != nil {
		return q.KNN, nil, nil, true
	}
	if q.Bool == nil {
		return nil, nil, nil, false
	}
	// Support `{"nested": {"path": ..., "query": {"bool": {"must": [{"knn": ...}], "filter": [...]}}}}`
	// where `knn` executes parent-diversified top-k FIRST and sibling clauses act as post-filters (`130_knn_query_nested_search.yml`).
	var found *esast.KNNQuery
	var reqPost []esast.Query
	for i := range q.Bool.Must {
		if q.Bool.Must[i].KNN != nil && found == nil {
			found = q.Bool.Must[i].KNN
		} else {
			reqPost = append(reqPost, q.Bool.Must[i])
		}
	}
	for i := range q.Bool.Filter {
		if q.Bool.Filter[i].KNN != nil && found == nil {
			found = q.Bool.Filter[i].KNN
		} else {
			reqPost = append(reqPost, q.Bool.Filter[i])
		}
	}
	if found == nil && len(q.Bool.Should) == 1 && q.Bool.Should[0].KNN != nil {
		found = q.Bool.Should[0].KNN
	} else if found != nil && len(q.Bool.Should) > 0 && q.Bool.MinimumShouldMatch != nil {
		reqPost = append(reqPost, esast.Query{Bool: &esast.BoolQuery{
			Should:             q.Bool.Should,
			MinimumShouldMatch: q.Bool.MinimumShouldMatch,
		}})
	}
	if found == nil {
		return nil, nil, nil, false
	}
	return found, reqPost, q.Bool.MustNot, true
}

// compileNestedKNNQueryR63 compiles `{"nested": {"path": ..., "query": {"knn": ...}}}` (including
// `bool`-wrapped nested `knn` with sibling post-filters) with parent-diversified top-`k`/`num_candidates`,
// mixed root + nested `knn.filter` support, and `score_mode` (`130_knn_query_nested_search.yml`, `160_knn_query_missing_params.yml`).
func (t *Transpiler) compileNestedKNNQueryR63(nq *esast.NestedQuery, scoring bool) (CompiledQuery, bool) {
	if nq == nil {
		return CompiledQuery{}, false
	}
	kq, postClauses, postMustNot, hasKNN := extractNestedKNNAndPostFiltersR63(&nq.Query)
	if !hasKNN || kq == nil {
		return CompiledQuery{}, false
	}
	var corrCol string
	var ok bool
	if t.Schema != nil {
		corrCol, ok = t.Schema.NestedRoots[nq.Path]
	}
	if !ok {
		if nq.IgnoreUnmapped {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
		}
		if t.Schema != nil && (len(t.Schema.Fields) > 0 || len(t.Schema.NestedRoots) > 0) {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("[nested] failed to find nested object under path [%s]", nq.Path)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
		}
		corrCol = "n__" + schema.SanitizeDorisIdentifier(nq.Path)
	}

	// Validate k / num_candidates limits and compute effective parent-diversified bound.
	if kq.K < 0 {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: [k] must be greater than 0")
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	if kq.NumCandidates < 0 || kq.NumCandidates > 10000 {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] must be in [1, 10000]")
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	topLimit := 0
	if kq.K > 0 {
		effNumCand := kq.NumCandidates
		if effNumCand == 0 {
			effNumCand = min(10000, max(kq.K, int(math.Ceil(1.5*float64(kq.K)))))
		}
		if kq.K > effNumCand {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] cannot be less than [k]")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
		}
		topLimit = kq.K
	} else {
		effSize := t.Opts.CallerSize
		if effSize <= 0 {
			effSize = t.activeRequestSize
		}
		if effSize <= 0 {
			effSize = 10
		}
		effNumCand := kq.NumCandidates
		if effNumCand == 0 {
			effNumCand = min(10000, max(1, int(math.Ceil(1.5*float64(effSize)))))
		}
		topLimit = effNumCand
	}

	resolvedField, b := t.resolveFieldInNestedCtx(kq.Field, false, &nestedCtx{nestedPath: nq.Path})
	if t.Schema != nil && b.Kind == schema.StorageDynamicVariant && b.ESType == "" && !t.isMappedField(resolvedField) {
		if t.searchErr == nil {
			t.searchErr = esTranspilerError(fmt.Sprintf("all_shards_failed|query_shard_exception|failed to create query: field [%s] does not exist in the mapping", kq.Field))
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	if !t.checkFieldPositionalSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	elemType := strings.ToLower(strings.TrimSpace(b.VectorElementType))
	if elemType == "" {
		elemType = "float"
	}
	var qVec []float64
	if kq.QueryVectorFromHex {
		if elemType == "bit" {
			expanded, err := esast.ExpandHexBitVector(kq.QueryVectorHex)
			if err != nil {
				if t.searchErr == nil {
					t.searchErr = err
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
			}
			qVec = expanded
		} else {
			decoded, err := esast.DecodeHexSignedByteVector(kq.QueryVectorHex)
			if err != nil {
				if t.searchErr == nil {
					t.searchErr = err
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
			}
			qVec = decoded
		}
	} else {
		qVec = kq.QueryVector
	}
	if len(qVec) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	if b.VectorDims > 0 && elemType != "bit" && len(qVec) != b.VectorDims {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query vector has invalid dimension: [%d], expected [%d] for field [%s]", len(qVec), b.VectorDims, resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	metric := strings.ToLower(strings.TrimSpace(b.VectorMetric))
	if metric == "" {
		if elemType == "bit" {
			metric = "l2_norm"
		} else {
			metric = "cosine"
		}
	}

	vecParts := make([]string, len(qVec))
	for i, v := range qVec {
		vecParts[i] = strconv.FormatFloat(v, 'f', -1, 64)
	}
	vecLit := fmt.Sprintf("CAST([%s] AS ARRAY<FLOAT>)", strings.Join(vecParts, ", "))
	dim := len(qVec)

	relPath := t.nestedRelativeJSONPath(resolvedField, false, nq.Path)
	colExpr := fmt.Sprintf("TRY_CAST(json_extract_string(_nel, %s) AS ARRAY<FLOAT>)", quoteStr(relPath))
	baseCond := fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) = %d)", colExpr, colExpr, dim)
	safeCol := fmt.Sprintf("IF(array_size(%s) = %d, %s, %s)", colExpr, dim, colExpr, vecLit)
	var rawScoreExpr, simCond string
	if elemType == "bit" {
		l2Expr := fmt.Sprintf("L2_DISTANCE(%s, %s)", safeCol, vecLit)
		rawScoreExpr = fmt.Sprintf("((%d.0 - POW(%s, 2)) / %d.0)", dim, l2Expr, dim)
		if kq.Similarity != nil {
			simCond = fmt.Sprintf("(%s >= %s)", rawScoreExpr, strconv.FormatFloat(*kq.Similarity, 'f', -1, 64))
		}
	} else {
		switch metric {
		case "l2_norm", "l2":
			dExpr := fmt.Sprintf("L2_DISTANCE(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("(1.0 / (1.0 + POW(%s, 2)))", dExpr)
			if kq.Similarity != nil {
				effSim := quantizedL2SimThresholdR65(*kq.Similarity, b)
				simCond = fmt.Sprintf("(%s <= %s)", dExpr, strconv.FormatFloat(effSim, 'f', -1, 64))
			}
		case "dot_product":
			ipExpr := fmt.Sprintf("INNER_PRODUCT(%s, %s)", safeCol, vecLit)
			if elemType == "byte" {
				denom := 32768.0 * float64(dim)
				rawScoreExpr = fmt.Sprintf("GREATEST(0.5 + ((%s) / %s), 0.0)", ipExpr, strconv.FormatFloat(denom, 'f', -1, 64))
			} else {
				rawScoreExpr = fmt.Sprintf("GREATEST((1.0 + (%s)) / 2.0, 0.0)", ipExpr)
			}
			if kq.Similarity != nil {
				simCond = fmt.Sprintf("(%s >= %s)", ipExpr, strconv.FormatFloat(*kq.Similarity, 'f', -1, 64))
			}
		case "max_inner_product":
			ipExpr := fmt.Sprintf("INNER_PRODUCT(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("IF(%s < 0, 1.0 / (1.0 - (%s)), (%s) + 1.0)", ipExpr, ipExpr, ipExpr)
			if kq.Similarity != nil {
				simCond = fmt.Sprintf("(%s >= %s)", ipExpr, strconv.FormatFloat(*kq.Similarity, 'f', -1, 64))
			}
		default:
			baseCond, safeCol = buildCosineSafeExprsR61(colExpr, vecLit, dim)
			cdExpr := fmt.Sprintf("COSINE_DISTANCE(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("GREATEST((2.0 - (%s)) / 2.0, 0.0)", cdExpr)
			if kq.Similarity != nil {
				maxDist := 1.0 - *kq.Similarity
				simCond = fmt.Sprintf("(%s <= %s)", cdExpr, strconv.FormatFloat(maxDist, 'f', -1, 64))
			}
		}
	}

	childConds := []string{fmt.Sprintf("json_extract_string(_nel, %s) IS NOT NULL", quoteStr(relPath)), baseCond}
	if simCond != "" {
		childConds = append(childConds, simCond)
	}
	var rootFilterConds []string
	var rootSafeFilterConds []string
	usesFT := false
	for i := range kq.Filter {
		fq := &kq.Filter[i]
		if t.queryReferencesNestedPathR63(fq, nq.Path) {
			fc := t.CompileQuery(fq, false, &nestedCtx{nestedPath: nq.Path, elemVar: "_nel"})
			if fc.WhereSQL != "" && fc.WhereSQL != "TRUE" {
				childConds = append(childConds, fmt.Sprintf("(%s)", fc.WhereSQL))
			}
		} else {
			fc := t.CompileQuery(fq, false, nil)
			rootFilterConds = append(rootFilterConds, fmt.Sprintf("(%s)", fc.WhereSQL))
			rootSafeFilterConds = append(rootSafeFilterConds, fmt.Sprintf("(%s)", fc.EffectiveSafeWhere()))
			if fc.UsesFulltextMatch {
				usesFT = true
			}
		}
	}

	knnChildElemCond := strings.Join(childConds, " AND ")
	existsKNNChild := fmt.Sprintf("array_exists(_nel -> %s, `%s`)", knnChildElemCond, corrCol)
	preConds := []string{fmt.Sprintf("(`%s` IS NOT NULL AND %s)", corrCol, existsKNNChild)}
	preConds = append(preConds, rootFilterConds...)

	// Parent diversification inside `_knn_top` ALWAYS ranks parent docs by their best matching
	// child vector (`ARRAY_MAX` in Lucene `DiversifyingChildrenFloatKnnVectorQuery`).
	knnBestChildExpr := fmt.Sprintf("COALESCE(ARRAY_MAX(array_map(_nel -> IF(%s, %s, NULL), `%s`)), 0.0)",
		knnChildElemCond, rawScoreExpr, corrCol)

	preFilter := strings.Join(preConds, " AND ")
	if t.activeAliasWhere != "" && t.activeAliasWhere != "TRUE" {
		preFilter = fmt.Sprintf("(%s) AND (%s)", preFilter, t.activeAliasWhere)
	}

	// Sibling clauses inside `nested.query.bool` execute AFTER `_knn_top` parent diversification!
	// In Lucene `DiversifyingChildrenFloatKnnVectorQuery`, `knn` returns ONLY the diversified winning
	// child document per parent, so sibling nested post-filters only test that winning child vector (`130_knn_query_nested_search.yml`).
	postChildConds := append([]string(nil), childConds...)
	hasNestedPostFilter := false
	var postRootConds, postRootSafeConds []string
	for i := range postClauses {
		pq := &postClauses[i]
		if t.queryReferencesNestedPathR63(pq, nq.Path) {
			pc := t.CompileQuery(pq, false, &nestedCtx{nestedPath: nq.Path, elemVar: "_nel"})
			if pc.WhereSQL != "" && pc.WhereSQL != "TRUE" {
				postChildConds = append(postChildConds, fmt.Sprintf("(%s)", pc.WhereSQL))
				hasNestedPostFilter = true
			}
		} else {
			pc := t.CompileQuery(pq, false, nil)
			postRootConds = append(postRootConds, fmt.Sprintf("(%s)", pc.WhereSQL))
			postRootSafeConds = append(postRootSafeConds, fmt.Sprintf("(%s)", pc.EffectiveSafeWhere()))
			if pc.UsesFulltextMatch {
				usesFT = true
			}
		}
	}
	for i := range postMustNot {
		pq := &postMustNot[i]
		if t.queryReferencesNestedPathR63(pq, nq.Path) {
			pc := t.CompileQuery(pq, false, &nestedCtx{nestedPath: nq.Path, elemVar: "_nel"})
			if pc.WhereSQL != "" && pc.WhereSQL != "FALSE" {
				postChildConds = append(postChildConds, fmt.Sprintf("NOT (%s)", pc.WhereSQL))
				hasNestedPostFilter = true
			}
		} else {
			pc := t.CompileQuery(pq, false, nil)
			postRootConds = append(postRootConds, fmt.Sprintf("NOT (%s)", pc.WhereSQL))
			postRootSafeConds = append(postRootSafeConds, fmt.Sprintf("NOT (%s)", pc.EffectiveSafeWhere()))
			if pc.UsesFulltextMatch {
				usesFT = true
			}
		}
	}
	fullChildElemCond := strings.Join(postChildConds, " AND ")
	existsFullChild := fmt.Sprintf("array_exists(_nel -> %s, `%s`)", fullChildElemCond, corrCol)
	conds := []string{fmt.Sprintf("(`%s` IS NOT NULL AND %s)", corrCol, existsFullChild)}
	safeConds := []string{fmt.Sprintf("(`%s` IS NOT NULL AND %s)", corrCol, existsFullChild)}
	var postBestChildExpr string
	if hasNestedPostFilter {
		// Compare flat sibling `array_map` calls instead of embedding `knnBestChildExpr` inside an
		// outer lambda; Apache Doris 4.1.3 BE segfaults on nested higher-order lambda expressions.
		postBestChildExpr = fmt.Sprintf("ARRAY_MAX(array_map(_nel -> IF(%s, %s, NULL), `%s`))",
			fullChildElemCond, rawScoreExpr, corrCol)
		winningPostChildCond := fmt.Sprintf("(%s IS NOT NULL AND (%s) >= (%s) - 1e-12)",
			postBestChildExpr, postBestChildExpr, knnBestChildExpr)
		conds = append(conds, winningPostChildCond)
		safeConds = append(safeConds, winningPostChildCond)
	}
	conds = append(conds, rootFilterConds...)
	safeConds = append(safeConds, rootSafeFilterConds...)
	conds = append(conds, postRootConds...)
	safeConds = append(safeConds, postRootSafeConds...)
	filterSafeWhere := strings.Join(safeConds, " AND ")

	aggFn := "ARRAY_MAX"
	switch strings.ToLower(strings.TrimSpace(nq.ScoreMode)) {
	case "min":
		aggFn = "ARRAY_MIN"
	case "avg":
		aggFn = "ARRAY_AVG"
	case "sum":
		aggFn = "ARRAY_SUM"
	}
	childScoreAggExpr := fmt.Sprintf("COALESCE(%s(array_map(_nel -> IF(%s, %s, NULL), `%s`)), 0.0)",
		aggFn, fullChildElemCond, rawScoreExpr, corrCol)
	if hasNestedPostFilter {
		childScoreAggExpr = fmt.Sprintf("COALESCE(%s, 0.0)", postBestChildExpr)
	}

	if t.Schema != nil && t.Schema.DorisDB != "" && t.Schema.DorisTable != "" && topLimit > 0 {
		topSubquery := fmt.Sprintf("`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (ORDER BY %s DESC, `_id` ASC) AS `_rn` FROM `%s`.`%s` WHERE `__DORIS_DELETE_SIGN__` = 0 AND %s) `_knn_top` WHERE `_rn` <= %d)",
			knnBestChildExpr, t.Schema.DorisDB, t.Schema.DorisTable, preFilter, topLimit)
		conds = append(conds, topSubquery)
		safeConds = append(safeConds, topSubquery)
	}

	whereSQL := strings.Join(conds, " AND ")
	safeWhereSQL := strings.Join(safeConds, " AND ")

	boost := 1.0
	if kq.Boost != nil {
		boost *= *kq.Boost
	}
	if nq.Boost != nil {
		boost *= *nq.Boost
	}
	if nq.Query.Bool != nil && nq.Query.Bool.Boost != nil {
		boost *= *nq.Query.Bool.Boost
	}
	scoreSQL := "1.0"
	if strings.EqualFold(nq.ScoreMode, "none") {
		scoreSQL = "0.0"
	} else if scoring {
		boostStr := strconv.FormatFloat(boost, 'g', -1, 64)
		scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * (%s)) ELSE 0.0 END)",
			filterSafeWhere, boostStr, childScoreAggExpr)
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}, true
}

// buildSparseVectorTokenMaxWeightExprR63 builds a Doris 4.1.3 SQL expression for token `tok`
// inside `sparse_vector` field `resolvedField`, supporting single-object maps (`{"tok": 1.2}`),
// ES >= 8.15 multi-value arrays of maps (`[{"tok": 1.2}, {"tok": 2.5}]`), and arrays of parent
// objects (`[{"tokens": {"tok": 1.2}}]`, taking max weight) (`90_sparse_vector.yml`).
func (t *Transpiler) buildSparseVectorTokenMaxWeightExprR63(resolvedField, tok string, nctx *nestedCtx) string {
	scalarCol := t.sqlTypedColumnRef(resolvedField+"."+tok, 1.0, false, nctx)
	if nctx != nil {
		return scalarCol
	}
	segs := strings.Split(resolvedField, ".")
	var whenClauses []string
	for k := len(segs); k >= 1; k-- {
		prefixField := strings.Join(segs[:k], ".")
		isArrCond := sqlRuntimeSourceJSONTypeIsArrayExpr(prefixField)
		rawPrefixJSON := sqlRuntimeSourceStringExpr(prefixField)
		var remSegs []string
		for _, s := range segs[k:] {
			remSegs = append(remSegs, QuoteDorisJSONPathSegment(s))
		}
		remSegs = append(remSegs, QuoteDorisJSONPathSegment(tok))
		remPath := "$." + strings.Join(remSegs, ".")
		arrMaxExpr := fmt.Sprintf(
			"ARRAY_MAX(array_map(_el -> TRY_CAST(json_extract_string(_el, %s) AS DOUBLE), TRY_CAST(%s AS ARRAY<STRING>)))",
			quoteStr(remPath), rawPrefixJSON,
		)
		whenClauses = append(whenClauses, fmt.Sprintf("WHEN %s THEN %s", isArrCond, arrMaxExpr))
	}
	return fmt.Sprintf("(CASE %s ELSE %s END)", strings.Join(whenClauses, " "), scalarCol)
}

// compileSparseVectorTermQueryR63 compiles `term` queries targeting `sparse_vector` or
// `rank_features` fields (`{"term": {"ml.tokens": {"value": "walk", "boost": 1.9791}}}` in `90_sparse_vector.yml`),
// matching positive token weights and scoring by `boost * weight`.
func (t *Transpiler) compileSparseVectorTermQueryR63(cleanField string, val any, effBoost float64, scoring bool, nctx *nestedCtx) (CompiledQuery, bool) {
	resolvedField, b := t.resolveFieldInNestedCtx(cleanField, false, nctx)
	if b.ESType != "sparse_vector" {
		return CompiledQuery{}, false
	}
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	if val == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	tok := strings.TrimSpace(fmt.Sprintf("%v", val))
	if tok == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	wExpr := t.buildSparseVectorTokenMaxWeightExprR63(resolvedField, tok, nctx)
	pred := fmt.Sprintf("(%s IS NOT NULL AND %s > 0)", wExpr, wExpr)
	score := "0.0"
	if scoring && effBoost > 0 {
		score = fmt.Sprintf("(CASE WHEN %s THEN (%s * GREATEST(COALESCE(TRY_CAST(%s AS DOUBLE), 0.0), 0.0)) ELSE 0.0 END)",
			pred, strconv.FormatFloat(effBoost, 'g', -1, 64), wExpr)
	}
	return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}, true
}

// ----------------------------------------------------------------------------
// Round 63 F20 & F17: Query Analysis Helpers & Range / Date-Histogram Helpers
// ----------------------------------------------------------------------------

// analyzeTokensWithBuiltinGraphR63 tokenizes `text` with `pkg/analysis` built-in stemmer /
// language analyzers (`snowball`, `english`, `german`, etc.) when `cfg == nil` (`40_query_string.yml`).
func analyzeTokensWithBuiltinGraphR63(text, analyzerName string) ([]AnalyzedToken, bool) {
	an := strings.TrimSpace(analyzerName)
	if an == "" || !analysis.IsBuiltInAnalyzer(an) {
		return nil, false
	}
	switch strings.ToLower(an) {
	case "standard", "simple", "whitespace", "keyword", "stop":
		return nil, false
	}
	resp, err := analysis.Analyze(analysis.AnalyzeRequest{
		Text:     []string{text},
		Analyzer: an,
	})
	if err != nil || resp == nil {
		return nil, false
	}
	if len(resp.Tokens) == 0 {
		return nil, true
	}
	out := make([]AnalyzedToken, 0, len(resp.Tokens))
	for _, tk := range resp.Tokens {
		out = append(out, AnalyzedToken{
			Term:     tk.Token,
			Position: tk.Position,
		})
	}
	return out, true
}

// analyzerCaseAndWhitespaceFlagsR63 probes `analyzerName` against `cfg` to determine whether
// the analyzer preserves uppercase letters (`caseSensitive`) and whether it keeps punctuation
// attached inside whitespace-delimited tokens (`isWhitespace`) (`41_query_string_with_default_analyzer.yml`, `60_synonym_graph.yml`).
func analyzerCaseAndWhitespaceFlagsR63(analyzerName string, cfg *analysis.IndexAnalysisConfig, opts analysis.Options) (caseSensitive bool, isWhitespace bool) {
	an := strings.TrimSpace(analyzerName)
	lowerAn := strings.ToLower(an)
	if lowerAn == "whitespace" {
		return true, true
	}
	if lowerAn == "keyword" {
		return true, false
	}
	if gCase, err := analysis.AnalyzeForQuery("AaBbZz", an, cfg, opts); err == nil && !gCase.IsEmpty() {
		for _, seg := range gCase.Segments {
			for _, alt := range seg.Alternatives {
				for _, tk := range alt {
					if strings.ToLower(tk) != tk && strings.ToUpper(tk) != tk {
						caseSensitive = true
					}
				}
			}
		}
	}
	if gBoundary, err := analysis.AnalyzeForQuery("alpha,beta", an, cfg, opts); err == nil && len(gBoundary.Segments) == 1 {
		if len(gBoundary.Segments[0].Alternatives) == 1 && len(gBoundary.Segments[0].Alternatives[0]) == 1 {
			if strings.Contains(gBoundary.Segments[0].Alternatives[0][0], ",") {
				isWhitespace = true
			}
		}
	}
	return caseSensitive, isWhitespace
}

// expandRewrittenAllOfIntervalsR63 distributes `all_of` over child `any_of` intervals (when no
// `any_of.filter` restricts the inner disjunction), matching Lucene's default `rewrite: true`
// disjunction pulling (`230_interval_query.yml :: Test rewrite disjunctions`).
func expandRewrittenAllOfIntervalsR63(allOf *esast.IntervalsAllOf) ([]esast.IntervalsAllOf, bool) {
	if allOf == nil || len(allOf.Intervals) == 0 {
		return nil, false
	}
	hasExpandableAnyOf := false
	totalCombos := 1
	for i := range allOf.Intervals {
		sub := &allOf.Intervals[i]
		if sub.AnyOf != nil && sub.AnyOf.Filter == nil && len(sub.AnyOf.Intervals) > 1 {
			hasExpandableAnyOf = true
			totalCombos *= len(sub.AnyOf.Intervals)
			if totalCombos > 64 {
				return nil, false
			}
		}
	}
	if !hasExpandableAnyOf {
		return nil, false
	}
	var branches []esast.IntervalsAllOf
	cur := make([]esast.IntervalsRule, len(allOf.Intervals))
	var dfs func(idx int)
	dfs = func(idx int) {
		if idx == len(allOf.Intervals) {
			cp := make([]esast.IntervalsRule, len(cur))
			copy(cp, cur)
			branches = append(branches, esast.IntervalsAllOf{
				Intervals: cp,
				MaxGaps:   allOf.MaxGaps,
				Ordered:   allOf.Ordered,
				Filter:    allOf.Filter,
			})
			return
		}
		sub := allOf.Intervals[idx]
		if sub.AnyOf != nil && sub.AnyOf.Filter == nil && len(sub.AnyOf.Intervals) > 1 {
			for _, alt := range sub.AnyOf.Intervals {
				cur[idx] = alt
				dfs(idx + 1)
			}
			return
		}
		cur[idx] = sub
		dfs(idx + 1)
	}
	dfs(0)
	return branches, len(branches) > 1
}

func tagIntervalsBranchR63(spans []IntervalsSpan, branchID int) []IntervalsSpan {
	if len(spans) == 0 {
		return nil
	}
	out := make([]IntervalsSpan, len(spans))
	for i, sp := range spans {
		sp.Branch = branchID
		out[i] = sp
	}
	return out
}

// queryContainsKNNTreeR63 reports whether `q` contains any `knn` query node (including inside
// `bool`, `dis_max`, `boosting`, `constant_score`, `function_score`, or `nested`).
func queryContainsKNNTreeR63(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.KNN != nil {
		return true
	}
	if q.Nested != nil && queryContainsKNNTreeR63(&q.Nested.Query) {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsKNNTreeR63(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsKNNTreeR63(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsKNNTreeR63(&q.Bool.Should[i]) {
				return true
			}
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsKNNTreeR63(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil && (queryContainsKNNTreeR63(&q.Boosting.Positive) || queryContainsKNNTreeR63(&q.Boosting.Negative)) {
		return true
	}
	if q.ConstantScore != nil && queryContainsKNNTreeR63(&q.ConstantScore.Filter) {
		return true
	}
	if q.FunctionScore != nil && queryContainsKNNTreeR63(q.FunctionScore.Query) {
		return true
	}
	return false
}

// buildAnalyzedTokenRegexExactR63 builds a POSIX token-boundary regex honoring independent
// `caseSensitive` and `isWhitespace` flags (`41_query_string_with_default_analyzer.yml`, `60_synonym_graph.yml`).
func buildAnalyzedTokenRegexExactR63(tok string, caseSensitive, isWhitespace bool) string {
	ci := "(?i)"
	if caseSensitive {
		ci = ""
	}
	esc := escapeSQLRegexMetaR63(tok)
	if isWhitespace {
		return fmt.Sprintf("%s(^|[[:space:]])(%s)($|[[:space:]])", ci, esc)
	}
	return fmt.Sprintf("%s(^|[^[:alnum:]_])(%s)($|[^[:alnum:]_])", ci, esc)
}

func escapeSQLRegexMetaR63(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// dateRangeObjectBoundsSQLR63 builds `(lower, upper, rawLower, rawUpper)` epoch-millisecond
// `DOUBLE` SQL expressions for `date_range` fields whose `_source` / `_doc` bounds may be
// ISO-8601 date strings or epoch numbers (`10_histogram.yml :: date_histogram on range`).
func dateRangeObjectBoundsSQLR63(field string, b schema.FieldBinding, nctx *nestedCtx) (string, string, string, string) {
	if nctx != nil && nctx.elemVar != "" && (b.Kind == schema.StorageNestedSubfield || b.NestedPath == nctx.nestedPath) && nctx.nestedPath == b.NestedPath {
		relPath := strings.TrimSuffix(nestedRelPathR63(field, b.NestedPath), "")
		rawGte := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath+".gte"))
		rawGt := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath+".gt"))
		rawLte := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath+".lte"))
		rawLt := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath+".lt"))
		numGte := fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS DOUBLE)", nctx.elemVar, quoteStr(relPath+"._gte"))
		numGt := fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS DOUBLE)", nctx.elemVar, quoteStr(relPath+"._gt"))
		numLte := fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS DOUBLE)", nctx.elemVar, quoteStr(relPath+"._lte"))
		numLt := fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS DOUBLE)", nctx.elemVar, quoteStr(relPath+"._lt"))
		rawLower := fmt.Sprintf("COALESCE(%s, %s, CAST(%s AS DOUBLE), CAST(%s AS DOUBLE) + 1.0)",
			numGte, numGt, sqlRuntimeSourceDateMillisExpr(rawGte), sqlRuntimeSourceDateMillisExpr(rawGt))
		rawUpper := fmt.Sprintf("COALESCE(%s, %s, CAST(%s AS DOUBLE), CAST(%s AS DOUBLE) - 1.0)",
			numLte, numLt, sqlRuntimeSourceDateMillisExpr(rawLte), sqlRuntimeSourceDateMillisExpr(rawLt))
		return fmt.Sprintf("COALESCE(%s, -1e100)", rawLower), fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper), rawLower, rawUpper
	}
	baseExpr := rangeDocBaseExpr(field, b)
	pathField := field
	if len(b.SourceJSONPath) > 0 {
		pathField = strings.Join(b.SourceJSONPath, ".")
	}
	gteMs := sqlRuntimeSourceDateMillisExpr(sqlRuntimeSourceStringExpr(pathField + ".gte"))
	gtMs := sqlRuntimeSourceDateMillisExpr(sqlRuntimeSourceStringExpr(pathField + ".gt"))
	lteMs := sqlRuntimeSourceDateMillisExpr(sqlRuntimeSourceStringExpr(pathField + ".lte"))
	ltMs := sqlRuntimeSourceDateMillisExpr(sqlRuntimeSourceStringExpr(pathField + ".lt"))
	rawLower := fmt.Sprintf("COALESCE(TRY_CAST(CAST(%s['_gte'] AS STRING) AS DOUBLE), TRY_CAST(CAST(%s['_gt'] AS STRING) AS DOUBLE), CAST(%s AS DOUBLE), CAST(%s AS DOUBLE) + 1.0)",
		baseExpr, baseExpr, gteMs, gtMs)
	rawUpper := fmt.Sprintf("COALESCE(TRY_CAST(CAST(%s['_lte'] AS STRING) AS DOUBLE), TRY_CAST(CAST(%s['_lt'] AS STRING) AS DOUBLE), CAST(%s AS DOUBLE), CAST(%s AS DOUBLE) - 1.0)",
		baseExpr, baseExpr, lteMs, ltMs)
	return fmt.Sprintf("COALESCE(%s, -1e100)", rawLower), fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper), rawLower, rawUpper
}

func nestedRelPathR63(field, nestedPath string) string {
	rel := strings.TrimPrefix(field, nestedPath+".")
	segs := strings.Split(rel, ".")
	quoted := make([]string, len(segs))
	for i, s := range segs {
		quoted[i] = QuoteDorisJSONPathSegment(s)
	}
	return "$." + strings.Join(quoted, ".")
}

// buildDateRangeBucketExplodeSQLR63 explodes a `[effLoSQL, effHiSQL]` epoch-millisecond range
// into dense sample points guaranteed to cover both endpoints `effLoSQL` and `effHiSQL` as well as
// every calendar month/week/day in between (`10_histogram.yml`, `360_date_histogram.yml`).
func buildDateRangeBucketExplodeSQLR63(fromTable, effLoSQL, effHiSQL string, ivMs int64) (string, string) {
	minStep := float64(ivMs)
	if minStep <= 0 || minStep > 86400000.0 {
		minStep = 86400000.0 // 1 day guarantees hitting every calendar month/week/day + offsets
	}
	minStepStr := strconv.FormatFloat(minStep, 'f', -1, 64)
	stepExpr := fmt.Sprintf("GREATEST(%s, ((%s) - (%s)) / 2000.0)", minStepStr, effHiSQL, effLoSQL)
	// Number of steps = floor((hi - lo) / step) + 2 so the final `_off` clamps cleanly onto `effHiSQL` via `LEAST(...)`.
	countExpr := fmt.Sprintf(
		"CAST(LEAST(GREATEST(TRY_CAST(FLOOR(((%s) - (%s)) / (%s)) AS BIGINT) + 2, 1), 2005) AS INT)",
		effHiSQL, effLoSQL, stepExpr,
	)
	explodeFrom := appendLateralViewToFromClause(fromTable, fmt.Sprintf("LATERAL VIEW EXPLODE(ARRAY_RANGE(0, %s)) `_rng_t` AS `_off`", countExpr))
	valExpr := fmt.Sprintf("LEAST((%s) + TRY_CAST(`_off` AS DOUBLE) * (%s), (%s))", effLoSQL, stepExpr, effHiSQL)
	return explodeFrom, valExpr
}

// sortedRangeAggIndicesAscR63 returns slice indices into `rngSpec.Ranges` stably sorted by `(from, to)`
// ascending (`nil` `From` = `-Inf`, `nil` `To` = `+Inf`), matching Elasticsearch's canonical bucket order
// on non-keyed `range` and `date_range` aggregations (`40_range.yml :: Date Range Missing`).
func (t *Transpiler) sortedRangeAggIndicesAscR63(
	effField string,
	rngSpec *esast.RangeAggSpec,
	now time.Time,
) []int {
	if rngSpec == nil {
		return nil
	}
	n := len(rngSpec.Ranges)
	idxs := make([]int, n)
	for i := 0; i < n; i++ {
		idxs[i] = i
	}
	if n <= 1 || rngSpec.Keyed {
		return idxs
	}
	toBound := func(raw any, negInf bool) float64 {
		if raw == nil {
			if negInf {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		coerced := t.coerceRangeAggBoundWithNow(effField, rngSpec, raw, now)
		if fv, ok := parseFiniteFloatValue(coerced); ok {
			return fv
		}
		if negInf {
			return math.Inf(-1)
		}
		return math.Inf(1)
	}
	sort.SliceStable(idxs, func(a, b int) bool {
		ia, ib := idxs[a], idxs[b]
		fa := toBound(rngSpec.Ranges[ia].From, true)
		fb := toBound(rngSpec.Ranges[ib].From, true)
		if fa != fb {
			return fa < fb
		}
		ta := toBound(rngSpec.Ranges[ia].To, false)
		tb := toBound(rngSpec.Ranges[ib].To, false)
		return ta < tb
	})
	return idxs
}
