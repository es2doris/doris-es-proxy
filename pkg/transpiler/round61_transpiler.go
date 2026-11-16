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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// RawValuesAggPrefix prefixes companion 3-column raw value collection branches
// (`__raw_vals__<agg_path>`) emitted alongside approximate SQL metric branches
// for exact `percentiles`, `percentile_ranks`, `boxplot`, and `median_absolute_deviation`.
const RawValuesAggPrefix = "__raw_vals__"

// EscapeDorisSQLString safely escapes an arbitrary string for inclusion inside a
// single-quoted Doris / MySQL SQL string literal (`'...'`).
// Because Doris FE uses MySQL backslash-escaping by default (`\'` escapes a quote),
// NUL bytes are stripped first, backslashes are doubled (`\` -> `\\`), and single
// quotes are doubled (`'` -> `”`), preventing `\'` quote-smuggling SQL injection.
func EscapeDorisSQLString(s string) string {
	clean := strings.ReplaceAll(s, "\x00", "")
	clean = strings.ReplaceAll(clean, `\`, `\\`)
	clean = strings.ReplaceAll(clean, `'`, `''`)
	return clean
}

// IsSafeJSONNumberLiteral reports whether s is a strictly valid JSON numeric literal
// (`-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?`) safe to inline into SQL without quoting.
func IsSafeJSONNumberLiteral(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	i := 0
	if s[i] == '-' {
		i++
		if i >= len(s) {
			return false
		}
	}
	digits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		digits++
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		fracDigits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			fracDigits++
		}
		if fracDigits == 0 {
			return false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		expDigits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			expDigits++
		}
		if expDigits == 0 {
			return false
		}
	}
	return i == len(s)
}

// sqlCollectRawValuesBranch emits a 3-column companion branch collecting raw finite DOUBLE values
// for top-level exact quantiles (`percentiles`, `percentile_ranks`, `boxplot`, `median_absolute_deviation`).
func sqlCollectRawValuesBranch(fullAggName, valExpr, fromClause, whereClause string) string {
	w := ""
	trimmed := strings.TrimSpace(whereClause)
	if trimmed != "" {
		if strings.HasPrefix(strings.ToUpper(trimmed), "WHERE ") {
			w = " " + trimmed
		} else {
			w = " WHERE " + trimmed
		}
	}
	return fmt.Sprintf(
		"SELECT %s AS `_agg_name`, CONCAT('_vals:', COALESCE(ARRAY_JOIN(COLLECT_LIST(CAST(%s AS DOUBLE)), ','), '')) AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` FROM %s%s",
		quoteStr(RawValuesAggPrefix+fullAggName), valExpr, valExpr, fromClause, w,
	)
}

// sqlCollectGroupedRawValuesBranch emits a 3-column companion branch collecting raw finite DOUBLE values
// per parent bucket (`<parentBucketKey>\x1f_vals:<v1,v2,...>`).
func sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, valExpr, fromClause, whereClause string) string {
	return fmt.Sprintf(
		"SELECT %s AS `_agg_name`, CONCAT(CAST(%s AS STRING), '\\x1f_vals:', COALESCE(ARRAY_JOIN(COLLECT_LIST(CAST(%s AS DOUBLE)), ','), '')) AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
			"FROM %s WHERE %s GROUP BY %s",
		quoteStr(RawValuesAggPrefix+subFull), parentBucketExpr, valExpr, valExpr, fromClause, whereClause, parentBucketExpr,
	)
}

// ParseCollectedFloatValues parses a `_bucket_key` produced by `sqlCollectRawValuesBranch`
// (`_vals:1.5,2.5`) or `sqlCollectGroupedRawValuesBranch` (`<parentKey>\x1f_vals:1.5,2.5`).
func ParseCollectedFloatValues(bucketKey string) (parentBucketKey string, values []float64, ok bool) {
	rawPart := ""
	if strings.HasPrefix(bucketKey, "_vals:") {
		rawPart = strings.TrimPrefix(bucketKey, "_vals:")
	} else if idx := strings.LastIndex(bucketKey, "\x1f_vals:"); idx >= 0 {
		parentBucketKey = bucketKey[:idx]
		rawPart = bucketKey[idx+len("\x1f_vals:"):]
	} else {
		return "", nil, false
	}
	if strings.TrimSpace(rawPart) == "" {
		return parentBucketKey, nil, true
	}
	parts := strings.Split(rawPart, ",")
	values = make([]float64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if fv, err := strconv.ParseFloat(p, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			values = append(values, fv)
		}
	}
	return parentBucketKey, values, true
}

// BoxplotResult holds the 7 summary statistics of an Elasticsearch `boxplot` aggregation.
type BoxplotResult struct {
	Min   *float64
	Max   *float64
	Q1    *float64
	Q2    *float64
	Q3    *float64
	Lower *float64
	Upper *float64
}

// ComputeESBoxplot computes exact Elasticsearch `boxplot` summary values (`min`, `max`, `q1`, `q2`, `q3`,
// and Tukey `1.5 * IQR` whiskers `lower` and `upper` clamped to observed data points).
func ComputeESBoxplot(values []float64, compression float64) BoxplotResult {
	return ComputeESBoxplotWithVersion(values, compression, false)
}

// ComputeESBoxplotWithVersion computes exact Elasticsearch `boxplot` summary values with version-aware TDigest quartiles.
func ComputeESBoxplotWithVersion(values []float64, compression float64, es8Mode bool) BoxplotResult {
	pcts, err := ComputeESPercentilesWithVersion(values, []float64{0.0, 25.0, 50.0, 75.0, 100.0}, compression, false, 3, es8Mode)
	if err != nil || len(pcts) == 0 {
		return BoxplotResult{}
	}
	getPtr := func(k string) *float64 {
		if v, ok := pcts[k].(float64); ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
			cp := v
			return &cp
		}
		return nil
	}
	res := BoxplotResult{
		Min: getPtr("0.0"),
		Q1:  getPtr("25.0"),
		Q2:  getPtr("50.0"),
		Q3:  getPtr("75.0"),
		Max: getPtr("100.0"),
	}
	if res.Q1 == nil || res.Q3 == nil || res.Min == nil || res.Max == nil {
		return res
	}
	iqr := *res.Q3 - *res.Q1
	lowerFence := *res.Q1 - 1.5*iqr
	upperFence := *res.Q3 + 1.5*iqr

	sorted := make([]float64, 0, len(values))
	for _, v := range values {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			sorted = append(sorted, v)
		}
	}
	sort.Float64s(sorted)

	lowerVal := *res.Q1
	for _, v := range sorted {
		if v >= lowerFence {
			lowerVal = v
			break
		}
	}
	upperVal := *res.Q3
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i] <= upperFence {
			upperVal = sorted[i]
			break
		}
	}
	res.Lower = &lowerVal
	res.Upper = &upperVal
	return res
}

// ComputeESMedianAbsoluteDeviation computes the exact Elasticsearch `median_absolute_deviation`
// (`median(|x_i - median(X)|)`) over finite values, returning `nil` when empty.
func ComputeESMedianAbsoluteDeviation(values []float64, compression float64) *float64 {
	return ComputeESMedianAbsoluteDeviationWithVersion(values, compression, false)
}

// ComputeESMedianAbsoluteDeviationWithVersion computes `median_absolute_deviation` with version-aware TDigest medians.
func ComputeESMedianAbsoluteDeviationWithVersion(values []float64, compression float64, es8Mode bool) *float64 {
	clean := make([]float64, 0, len(values))
	for _, v := range values {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	medMap, err := ComputeESPercentilesWithVersion(clean, []float64{50.0}, compression, false, 3, es8Mode)
	if err != nil {
		return nil
	}
	med, ok := medMap["50.0"].(float64)
	if !ok {
		return nil
	}
	devs := make([]float64, len(clean))
	for i, v := range clean {
		devs[i] = math.Abs(v - med)
	}
	madMap, err := ComputeESPercentilesWithVersion(devs, []float64{50.0}, compression, false, 3, es8Mode)
	if err != nil {
		return nil
	}
	mad, ok := madMap["50.0"].(float64)
	if !ok {
		return nil
	}
	return &mad
}

// LuceneMurmurHash3X8632 implements Apache Lucene's exact `StringHelper.murmurhash3_x86_32(byte[], offset, len, seed)`
// used by Elasticsearch `terms` `include: { partition, num_partitions }` routing.
func LuceneMurmurHash3X8632(data []byte, seed uint32) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593

	h1 := seed
	roundedEnd := len(data) & ^0x3
	for i := 0; i < roundedEnd; i += 4 {
		k1 := binary.LittleEndian.Uint32(data[i : i+4])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	switch len(data) & 0x3 {
	case 3:
		k1 = uint32(data[roundedEnd+2]) << 16
		fallthrough
	case 2:
		k1 |= uint32(data[roundedEnd+1]) << 8
		fallthrough
	case 1:
		k1 |= uint32(data[roundedEnd])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data)) // #nosec G115 -- MurmurHash3_x86_32 mixes 32-bit byte length modulo 2^32
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1) // #nosec G115 -- Lucene StringHelper.murmurhash3_x86_32 returns signed 32-bit int
}

// TermsPartitionBucketMatch evaluates `Math.floorMod(StringHelper.murmurhash3_x86_32(utf8, 0), numPartitions) == partition`
// for string/keyword terms, or `Math.floorMod(Long.hashCode(val), numPartitions) == partition` when numeric.
func TermsPartitionBucketMatch(term string, isNumeric bool, partition, numPartitions int) bool {
	if numPartitions <= 0 || partition < 0 || partition >= numPartitions {
		return false
	}
	var h int64
	if isNumeric {
		if iv, err := strconv.ParseInt(strings.TrimSpace(term), 10, 64); err == nil {
			// Java Long.hashCode(long value) = (int)(value ^ (value >>> 32))
			javaHash := int32(uint32(uint64(iv) ^ (uint64(iv) >> 32))) // #nosec G115 -- Java Long.hashCode two's-complement 32-bit fold
			h = int64(javaHash)
		} else {
			h = int64(LuceneMurmurHash3X8632([]byte(term), 0))
		}
	} else {
		h = int64(LuceneMurmurHash3X8632([]byte(term), 0))
	}
	mod := h % int64(numPartitions)
	if mod < 0 {
		mod += int64(numPartitions)
	}
	return int(mod) == partition
}

// ParseTermsIncludePartition extracts `{partition, num_partitions}` from a `terms.include` value if present.
func ParseTermsIncludePartition(inc any) (partition int, numPartitions int, isPartition bool, err error) {
	if inc == nil {
		return 0, 0, false, nil
	}
	switch v := inc.(type) {
	case esast.TermsIncludePartition:
		if v.NumPartitions <= 0 {
			return 0, 0, true, fmt.Errorf("illegal_argument_exception: [num_partitions] must be greater than 0. Found [%d]", v.NumPartitions)
		}
		if v.Partition < 0 || v.Partition >= v.NumPartitions {
			return 0, 0, true, fmt.Errorf("illegal_argument_exception: [partition] must be greater than or equal to 0 and less than [num_partitions]. Found partition [%d] and num_partitions [%d]", v.Partition, v.NumPartitions)
		}
		return v.Partition, v.NumPartitions, true, nil
	case *esast.TermsIncludePartition:
		if v == nil {
			return 0, 0, false, nil
		}
		return ParseTermsIncludePartition(*v)
	case esast.TermsIncludeExclude:
		if v.Partition == nil && v.NumPartitions == nil {
			return 0, 0, false, nil
		}
		if v.NumPartitions == nil {
			return 0, 0, true, fmt.Errorf("parsing_exception: [include] requires [num_partitions] to be specified")
		}
		p := 0
		if v.Partition != nil {
			p = *v.Partition
		}
		return ParseTermsIncludePartition(esast.TermsIncludePartition{Partition: p, NumPartitions: *v.NumPartitions})
	case *esast.TermsIncludeExclude:
		if v == nil {
			return 0, 0, false, nil
		}
		return ParseTermsIncludePartition(*v)
	case map[string]any:
		rawP, hasP := v["partition"]
		rawNP, hasNP := v["num_partitions"]
		if !hasP && !hasNP {
			return 0, 0, false, nil
		}
		if !hasNP {
			return 0, 0, true, fmt.Errorf("parsing_exception: [include] requires [num_partitions] to be specified")
		}
		toInt := func(x any) (int, bool) {
			switch n := x.(type) {
			case int:
				return n, true
			case int64:
				return int(n), true
			case float64:
				if n == math.Trunc(n) {
					return int(n), true
				}
			}
			return 0, false
		}
		p, okP := 0, true
		if hasP {
			p, okP = toInt(rawP)
		}
		np, okNP := toInt(rawNP)
		if !okP || !okNP {
			return 0, 0, true, fmt.Errorf("parsing_exception: [include] partition parameters must be integers")
		}
		return ParseTermsIncludePartition(esast.TermsIncludePartition{Partition: p, NumPartitions: np})
	}
	return 0, 0, false, nil
}

// EncodeGeotileKey computes the Elasticsearch Web Mercator `"zoom/x/y"` slippy tile key for `(lat, lon)`.
func EncodeGeotileKey(lat, lon float64, precision int) (string, bool) {
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) {
		return "", false
	}
	if lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0 {
		return "", false
	}
	zoom := precision
	if zoom < 0 {
		zoom = 7
	}
	if zoom > 29 {
		zoom = 29
	}
	if zoom == 0 {
		return "0/0/0", true
	}
	n := int64(1) << zoom
	nf := float64(n)
	xtile := int64(math.Floor(((lon + 180.0) / 360.0) * nf))
	if xtile < 0 {
		xtile = 0
	} else if xtile >= n {
		xtile = n - 1
	}
	// Clamp latitude to Web Mercator projection bounds [-85.05112878, 85.05112878]
	clampedLat := lat
	if clampedLat > 85.05112877980659 {
		clampedLat = 85.05112877980659
	} else if clampedLat < -85.05112877980659 {
		clampedLat = -85.05112877980659
	}
	latRad := clampedLat * math.Pi / 180.0
	ytile := int64(math.Floor((1.0 - math.Log(math.Tan(math.Pi/4.0+latRad/2.0))/math.Pi) / 2.0 * nf))
	if ytile < 0 {
		ytile = 0
	} else if ytile >= n {
		ytile = n - 1
	}
	return fmt.Sprintf("%d/%d/%d", zoom, xtile, ytile), true
}

func (t *Transpiler) resolveGeoPointLatLonSQL(rawField string, nctx *nestedCtx) (latExpr, lonExpr, notNullCond string) {
	resolvedField, b := t.resolveFieldInNestedCtx(rawField, false, nctx)
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr = fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr = fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		notNullCond = fmt.Sprintf("%s IS NOT NULL AND %s != ''", elemExpr, elemExpr)
		return latExpr, lonExpr, notNullCond
	}
	return t.extractGeoPointExprs(resolvedField, b)
}

// EncodeGeotileSQL returns a Doris SQL expression computing the `"zoom/x/y"` Web Mercator slippy tile key.
func EncodeGeotileSQL(latExpr, lonExpr string, precision int) string {
	zoom := precision
	if zoom < 0 {
		zoom = 7
	}
	if zoom > 29 {
		zoom = 29
	}
	if zoom == 0 {
		return fmt.Sprintf("CASE WHEN %s IS NULL OR %s IS NULL THEN NULL ELSE '0/0/0' END", latExpr, lonExpr)
	}
	n := int64(1) << zoom
	nMinus1 := n - 1
	clampedLat := fmt.Sprintf("LEAST(GREATEST(CAST(%s AS DOUBLE), -85.05112877980659), 85.05112877980659)", latExpr)
	xExpr := fmt.Sprintf("LEAST(GREATEST(CAST(FLOOR(((CAST(%s AS DOUBLE) + 180.0) / 360.0) * %d.0) AS BIGINT), 0), %d)", lonExpr, n, nMinus1)
	yExpr := fmt.Sprintf("LEAST(GREATEST(CAST(FLOOR((1.0 - LN(TAN(PI() / 4.0 + ((%s) * PI() / 360.0))) / PI()) / 2.0 * %d.0) AS BIGINT), 0), %d)", clampedLat, n, nMinus1)
	return fmt.Sprintf("CASE WHEN %s IS NULL OR %s IS NULL THEN NULL ELSE CONCAT('%d/', CAST(%s AS STRING), '/', CAST(%s AS STRING)) END",
		latExpr, lonExpr, zoom, xExpr, yExpr)
}

// ComputeESVectorScore computes the exact Elasticsearch 8.15 vector similarity score (unboosted)
// for a single document vector and query vector.
func ComputeESVectorScore(docVec, queryVec []float64, metric, elemType string) (float64, bool) {
	if len(docVec) == 0 || len(docVec) != len(queryVec) {
		return 0, false
	}
	et := strings.ToLower(strings.TrimSpace(elemType))
	if et == "" {
		et = "float"
	}
	m := strings.ToLower(strings.TrimSpace(metric))
	if m == "" {
		if et == "bit" {
			m = "l2_norm"
		} else {
			m = "cosine"
		}
	}
	dim := len(queryVec)
	if et == "bit" {
		var l2Sq float64
		for i := 0; i < dim; i++ {
			d := docVec[i] - queryVec[i]
			l2Sq += d * d
		}
		return (float64(dim) - l2Sq) / float64(dim), true
	}
	switch m {
	case "l2_norm", "l2":
		var l2Sq float64
		for i := 0; i < dim; i++ {
			d := docVec[i] - queryVec[i]
			l2Sq += d * d
		}
		return 1.0 / (1.0 + l2Sq), true
	case "dot_product":
		var dot float64
		for i := 0; i < dim; i++ {
			dot += docVec[i] * queryVec[i]
		}
		if et == "byte" {
			sc := 0.5 + (dot / (32768.0 * float64(dim)))
			if sc < 0 {
				sc = 0
			}
			return sc, true
		}
		sc := (1.0 + dot) / 2.0
		if sc < 0 {
			sc = 0
		}
		return sc, true
	case "max_inner_product":
		var ip float64
		for i := 0; i < dim; i++ {
			ip += docVec[i] * queryVec[i]
		}
		if ip < 0 {
			return 1.0 / (1.0 - ip), true
		}
		return ip + 1.0, true
	default: // cosine
		var dot, normA, normB float64
		for i := 0; i < dim; i++ {
			dot += docVec[i] * queryVec[i]
			normA += docVec[i] * docVec[i]
			normB += queryVec[i] * queryVec[i]
		}
		if normA == 0 || normB == 0 {
			return 0, false
		}
		cos := dot / (math.Sqrt(normA) * math.Sqrt(normB))
		sc := (1.0 + cos) / 2.0
		if sc < 0 {
			sc = 0
		}
		return sc, true
	}
}

// PassesESVectorSimilarity checks whether `(docVec, queryVec)` satisfies an ES kNN `similarity` threshold
// in raw metric space (`d <= similarity` for `l2_norm`, `cos >= similarity` for `cosine`, `ip >= similarity` for inner product).
func PassesESVectorSimilarity(docVec, queryVec []float64, metric, elemType string, minSimilarity float64) bool {
	if len(docVec) == 0 || len(docVec) != len(queryVec) {
		return false
	}
	et := strings.ToLower(strings.TrimSpace(elemType))
	if et == "" {
		et = "float"
	}
	m := strings.ToLower(strings.TrimSpace(metric))
	if m == "" {
		m = "cosine"
	}
	dim := len(queryVec)
	if et == "bit" {
		sc, ok := ComputeESVectorScore(docVec, queryVec, m, et)
		return ok && sc >= minSimilarity
	}
	switch m {
	case "l2_norm", "l2":
		var l2Sq float64
		for i := 0; i < dim; i++ {
			d := docVec[i] - queryVec[i]
			l2Sq += d * d
		}
		return math.Sqrt(l2Sq) <= minSimilarity
	case "dot_product", "max_inner_product":
		var ip float64
		for i := 0; i < dim; i++ {
			ip += docVec[i] * queryVec[i]
		}
		return ip >= minSimilarity
	default: // cosine
		var dot, normA, normB float64
		for i := 0; i < dim; i++ {
			dot += docVec[i] * queryVec[i]
			normA += docVec[i] * docVec[i]
			normB += queryVec[i] * queryVec[i]
		}
		if normA == 0 || normB == 0 {
			return false
		}
		cos := dot / (math.Sqrt(normA) * math.Sqrt(normB))
		return cos >= minSimilarity
	}
}

// NestedKNNChildHit represents one matched nested child vector and its similarity score.
type NestedKNNChildHit struct {
	Offset int
	Child  map[string]any
	Score  float64
}

// EvaluateNestedKNNParentScore evaluates nested child vectors under a parent document and returns
// the maximum matching child vector score (parent diversification) along with all matching child hits
// sorted by `(Score DESC, Offset ASC)` for `knn.inner_hits`.
func EvaluateNestedKNNParentScore(
	children []map[string]any,
	relVectorField string,
	queryVec []float64,
	metric, elemType string,
	similarity *float64,
	boost float64,
) (bestScore float64, matched bool, childHits []NestedKNNChildHit) {
	for idx, ch := range children {
		if ch == nil {
			continue
		}
		rawV, exists := resolvePathInMLTMap(ch, relVectorField)
		if !exists || rawV == nil {
			continue
		}
		docVec, ok := coerceDocVectorFloat64(rawV, elemType)
		if !ok || len(docVec) != len(queryVec) {
			continue
		}
		if similarity != nil && !PassesESVectorSimilarity(docVec, queryVec, metric, elemType, *similarity) {
			continue
		}
		sc, ok := ComputeESVectorScore(docVec, queryVec, metric, elemType)
		if !ok {
			continue
		}
		boosted := sc * boost
		if !matched || boosted > bestScore {
			bestScore = boosted
			matched = true
		}
		childHits = append(childHits, NestedKNNChildHit{
			Offset: idx,
			Child:  ch,
			Score:  boosted,
		})
	}
	sort.Slice(childHits, func(i, j int) bool {
		if childHits[i].Score != childHits[j].Score {
			return childHits[i].Score > childHits[j].Score
		}
		return childHits[i].Offset < childHits[j].Offset
	})
	return bestScore, matched, childHits
}

func coerceDocVectorFloat64(raw any, elemType string) ([]float64, bool) {
	et := strings.ToLower(strings.TrimSpace(elemType))
	if str, ok := raw.(string); ok {
		if et == "bit" {
			vec, err := esast.ExpandHexBitVector(str)
			return vec, err == nil
		}
		if et == "byte" {
			vec, err := esast.DecodeHexSignedByteVector(str)
			return vec, err == nil
		}
		return nil, false
	}
	var floatSlice []float64
	switch arr := raw.(type) {
	case []float64:
		floatSlice = append(floatSlice, arr...)
	case []any:
		floatSlice = make([]float64, 0, len(arr))
		for _, elem := range arr {
			switch nv := elem.(type) {
			case float64:
				floatSlice = append(floatSlice, nv)
			case int:
				floatSlice = append(floatSlice, float64(nv))
			case int64:
				floatSlice = append(floatSlice, float64(nv))
			default:
				if fv, err := strconv.ParseFloat(fmt.Sprintf("%v", elem), 64); err == nil {
					floatSlice = append(floatSlice, fv)
				} else {
					return nil, false
				}
			}
		}
	default:
		return nil, false
	}
	if et == "bit" {
		expanded := make([]float64, 0, len(floatSlice)*8)
		for _, fv := range floatSlice {
			iv := int(fv)
			if iv < 0 {
				iv += 256
			}
			for mask := 0x80; mask > 0; mask >>= 1 {
				if iv&mask != 0 {
					expanded = append(expanded, 1.0)
				} else {
					expanded = append(expanded, 0.0)
				}
			}
		}
		return expanded, true
	}
	return floatSlice, true
}

func (t *Transpiler) isMappedField(resolvedField string) bool {
	if t.Schema == nil || resolvedField == "" {
		return true
	}
	if _, ok := t.Schema.Fields[resolvedField]; ok {
		return true
	}
	base := strings.TrimSuffix(resolvedField, ".keyword")
	if _, ok := t.Schema.Fields[base]; ok {
		return true
	}
	return false
}

// compileKNNRound61 compiles both top-level `req.KNN[i]` (`t.inTopLevelKNN == true`) and `Query.KNN`
// (`t.inTopLevelKNN == false`) with ES 8.15 `k`/`num_candidates` defaults & validation, hex byte/bit
// decoding, exact cosine/L2/MIP/dot_product scoring, nested parent diversification, and top-`k` SQL bounding.
func (t *Transpiler) compileKNNRound61(kq *esast.KNNQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if kq == nil || strings.TrimSpace(kq.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	// Validate k / num_candidates limits and compute effective top-k bound.
	topLimit := 0
	if t.inTopLevelKNN {
		if kq.K < 0 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [k] must be greater than 0")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if kq.NumCandidates < 0 || kq.NumCandidates > 10000 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] must be in [1, 10000]")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		effSize := t.activeRequestSize
		if effSize <= 0 {
			effSize = 10
		}
		effK := kq.K
		if effK == 0 {
			effK = effSize
		}
		effNumCand := kq.NumCandidates
		if effNumCand == 0 {
			effNumCand = min(10000, max(effK, int(math.Ceil(1.5*float64(effK)))))
		}
		if effK > effNumCand {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] cannot be less than [k]")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		topLimit = effK
	} else {
		if kq.K < 0 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [k] must be greater than 0")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if kq.NumCandidates < 0 || kq.NumCandidates > 10000 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] must be in [1, 10000]")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if kq.K > 0 {
			effNumCand := kq.NumCandidates
			if effNumCand == 0 {
				effNumCand = min(10000, max(kq.K, int(math.Round(1.5*float64(kq.K)))))
			}
			if kq.K > effNumCand {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [num_candidates] cannot be less than [k]")
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			topLimit = kq.K
		} else {
			effSize := t.activeRequestSize
			if effSize <= 0 {
				effSize = 10
			}
			effNumCand := kq.NumCandidates
			if effNumCand == 0 {
				effNumCand = min(10000, max(1, int(math.Round(1.5*float64(effSize)))))
			}
			topLimit = effNumCand
		}
	}

	resolvedField, b := t.resolveFieldInNestedCtx(kq.Field, false, nctx)
	if t.Schema != nil && len(t.Schema.Fields) > 0 && (t.Opts.ES8Compat || t.Schema.ES8Mode || (t.Schema.RawMapping != nil && strings.EqualFold(fmt.Sprintf("%v", t.Schema.RawMapping.Dynamic), "strict"))) && b.Kind == schema.StorageDynamicVariant && b.ESType == "" && !t.isMappedField(resolvedField) {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: failed to create query: field [%s] does not exist in the mapping", kq.Field)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if !t.checkFieldPositionalSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.Kind != schema.StoragePromotedVector && b.Kind != schema.StorageNestedSubfield && b.Kind != schema.StorageDynamicVariant && b.ESType != "dense_vector" && b.ESType != "knn_vector" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("cannot execute knn search on field [%s] of type [%s]", resolvedField, b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.Kind == schema.StorageNestedSubfield && b.ESType != "dense_vector" && b.ESType != "knn_vector" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("cannot execute knn search on field [%s] of type [%s]", resolvedField, b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
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
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			qVec = expanded
		} else {
			// ES 8.14+ decodes hex query_vector as signed int8 bytes for both `byte` and `float` fields.
			decoded, err := esast.DecodeHexSignedByteVector(kq.QueryVectorHex)
			if err != nil {
				if t.searchErr == nil {
					t.searchErr = err
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			qVec = decoded
		}
	} else {
		qVec = kq.QueryVector
	}
	if len(qVec) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	switch elemType {
	case "bit":
		if kq.QueryVectorFromHex {
			if b.VectorDims > 0 && len(qVec) != b.VectorDims {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: query vector has invalid bit dimension: [%d], expected [%d] for field [%s]", len(qVec), b.VectorDims, resolvedField)
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
		} else {
			if b.VectorDims > 0 && len(qVec) != b.VectorDims/8 {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: query vector has invalid byte length: [%d], expected [%d] bytes for [%d]-bit field [%s]", len(qVec), b.VectorDims/8, b.VectorDims, resolvedField)
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			expanded := make([]float64, 0, len(qVec)*8)
			for _, fv := range qVec {
				if math.IsNaN(fv) || math.IsInf(fv, 0) || fv != math.Trunc(fv) || fv < -128 || fv > 127 {
					if t.searchErr == nil {
						t.searchErr = fmt.Errorf("illegal_argument_exception: [bit] query_vector byte elements must be integers in [-128, 127] for field [%s]", resolvedField)
					}
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				iv := int(fv)
				if iv < 0 {
					iv += 256
				}
				for mask := 0x80; mask > 0; mask >>= 1 {
					if iv&mask != 0 {
						expanded = append(expanded, 1.0)
					} else {
						expanded = append(expanded, 0.0)
					}
				}
			}
			qVec = expanded
		}
	case "byte":
		if b.VectorDims > 0 && len(qVec) != b.VectorDims {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("query vector has invalid dimension: [%d], expected [%d] for field [%s]", len(qVec), b.VectorDims, resolvedField)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		for _, fv := range qVec {
			if math.IsNaN(fv) || math.IsInf(fv, 0) || fv != math.Trunc(fv) || fv < -128 || fv > 127 {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [byte] query_vector elements must be integers in [-128, 127] for field [%s]", resolvedField)
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
		}
	default:
		if b.VectorDims > 0 && len(qVec) != b.VectorDims {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("query vector has invalid dimension: [%d], expected [%d] for field [%s]", len(qVec), b.VectorDims, resolvedField)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}

	metric := strings.ToLower(strings.TrimSpace(b.VectorMetric))
	if metric == "" {
		if elemType == "bit" {
			metric = "l2_norm"
		} else {
			metric = "cosine"
		}
	}

	if elemType == "float" && metric == "dot_product" && len(qVec) > 0 {
		var sumSq float64
		for _, fv := range qVec {
			sumSq += fv * fv
		}
		if math.Abs(sumSq-1.0) > 1e-4 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: The [dot_product] similarity can only be used with unit-length vectors")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}
	if metric == "cosine" && elemType != "bit" && len(qVec) > 0 {
		var sumSq float64
		for _, fv := range qVec {
			sumSq += fv * fv
		}
		if sumSq == 0 {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: Zero-magnitude vectors are not supported when using [cosine] similarity")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}

	vecParts := make([]string, len(qVec))
	for i, v := range qVec {
		vecParts[i] = strconv.FormatFloat(v, 'f', -1, 64)
	}
	vecLit := fmt.Sprintf("CAST([%s] AS ARRAY<FLOAT>)", strings.Join(vecParts, ", "))
	dim := len(qVec)
	boost := 1.0
	if kq.Boost != nil {
		boost = *kq.Boost
	}

	buildScoreAndSimSQL := func(colExpr string) (baseCond, rawScoreExpr, simCond string) {
		baseCond = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) = %d)", colExpr, colExpr, dim)
		safeCol := fmt.Sprintf("IF(array_size(%s) = %d, %s, %s)", colExpr, dim, colExpr, vecLit)
		if elemType == "bit" {
			l2Expr := fmt.Sprintf("L2_DISTANCE(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("((%d.0 - POW(%s, 2)) / %d.0)", dim, l2Expr, dim)
			if kq.Similarity != nil {
				simCond = fmt.Sprintf("(%s >= %s)", rawScoreExpr, strconv.FormatFloat(*kq.Similarity, 'f', -1, 64))
			}
			return baseCond, rawScoreExpr, simCond
		}
		switch metric {
		case "l2_norm", "l2":
			dExpr := fmt.Sprintf("L2_DISTANCE(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("(1.0 / (1.0 + POW(%s, 2)))", dExpr)
			if kq.Similarity != nil {
				simCond = fmt.Sprintf("(%s <= %s)", dExpr, strconv.FormatFloat(*kq.Similarity, 'f', -1, 64))
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
		default: // cosine
			cdExpr := fmt.Sprintf("COSINE_DISTANCE(%s, %s)", safeCol, vecLit)
			rawScoreExpr = fmt.Sprintf("GREATEST((2.0 - (%s)) / 2.0, 0.0)", cdExpr)
			if kq.Similarity != nil {
				maxDist := 1.0 - *kq.Similarity
				simCond = fmt.Sprintf("(%s <= %s)", cdExpr, strconv.FormatFloat(maxDist, 'f', -1, 64))
			}
		}
		return baseCond, rawScoreExpr, simCond
	}

	// Root-level filter compilation (in ES, `knn.filter` ALWAYS filters root parent documents, even for nested vectors).
	var filterConds []string
	var safeFilterConds []string
	usesFT := false
	for i := range kq.Filter {
		fc := t.CompileQuery(&kq.Filter[i], false, nil)
		filterConds = append(filterConds, fmt.Sprintf("(%s)", fc.WhereSQL))
		safeFilterConds = append(safeFilterConds, fmt.Sprintf("(%s)", fc.EffectiveSafeWhere()))
		if fc.UsesFulltextMatch {
			usesFT = true
		}
	}

	// Nested child vector (`nested.vec`) with parent-diversified top-k!
	if b.Kind == schema.StorageNestedSubfield && nctx == nil && t.Schema != nil {
		corrCol := t.Schema.NestedRoots[b.NestedPath]
		if corrCol == "" {
			corrCol = "n__" + schema.SanitizeDorisIdentifier(b.NestedPath)
		}
		relPath := t.nestedRelativeJSONPath(resolvedField, false, b.NestedPath)
		childColExpr := fmt.Sprintf("CAST(json_extract(`_nel`, %s) AS ARRAY<FLOAT>)", quoteStr(relPath))
		baseCond, rawScoreExpr, simCond := buildScoreAndSimSQL(childColExpr)

		childElemCond := baseCond
		if simCond != "" {
			childElemCond = fmt.Sprintf("(%s AND %s)", baseCond, simCond)
		}
		existsChild := fmt.Sprintf("array_exists(_nel -> %s IS NOT NULL AND %s, `%s`)",
			fmt.Sprintf("json_extract(_nel, %s)", quoteStr(relPath)),
			strings.ReplaceAll(childElemCond, "`_nel`", "_nel"),
			corrCol,
		)
		conds := []string{fmt.Sprintf("(`%s` IS NOT NULL AND %s)", corrCol, existsChild)}
		safeConds := []string{fmt.Sprintf("(`%s` IS NOT NULL AND %s)", corrCol, existsChild)}
		conds = append(conds, filterConds...)
		safeConds = append(safeConds, safeFilterConds...)

		maxChildScoreExpr := fmt.Sprintf("COALESCE(ARRAY_MAX(array_map(_nel -> IF(%s, %s, NULL), `%s`)), 0.0)",
			strings.ReplaceAll(childElemCond, "`_nel`", "_nel"),
			strings.ReplaceAll(rawScoreExpr, "`_nel`", "_nel"),
			corrCol,
		)

		preFilter := strings.Join(conds, " AND ")
		if t.activeAliasWhere != "" && t.activeAliasWhere != "TRUE" {
			preFilter = fmt.Sprintf("(%s) AND (%s)", preFilter, t.activeAliasWhere)
		}
		if t.Schema.DorisDB != "" && t.Schema.DorisTable != "" && topLimit > 0 {
			topSubquery := fmt.Sprintf("`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (ORDER BY %s DESC, `_id` ASC) AS `_rn` FROM `%s`.`%s` WHERE `__DORIS_DELETE_SIGN__` = 0 AND %s) `_knn_top` WHERE `_rn` <= %d)",
				maxChildScoreExpr, t.Schema.DorisDB, t.Schema.DorisTable, preFilter, topLimit)
			conds = append(conds, topSubquery)
			safeConds = append(safeConds, topSubquery)
		}

		whereSQL := strings.Join(conds, " AND ")
		safeWhereSQL := strings.Join(safeConds, " AND ")
		scoreSQL := "1.0"
		if scoring {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%.4f * (%s)) ELSE 0.0 END)",
				safeWhereSQL, boost, maxChildScoreExpr)
		}
		return CompiledQuery{
			WhereSQL:          whereSQL,
			SafeWhereSQL:      safeWhereSQL,
			ScoreSQL:          scoreSQL,
			UsesFulltextMatch: usesFT,
		}
	}

	var colExpr string
	if b.ColumnName != "" {
		colExpr = fmt.Sprintf("`%s`", b.ColumnName)
	} else {
		if t.unindexedFields != nil && resolvedField != "" {
			t.unindexedFields[strings.TrimSuffix(resolvedField, ".keyword")] = true
		}
		var pathBuilder strings.Builder
		for _, seg := range b.SourceJSONPath {
			_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
		}
		colExpr = fmt.Sprintf("CAST(`_doc`%s AS ARRAY<FLOAT>)", pathBuilder.String())
	}

	baseCond, rawScoreExpr, simCond := buildScoreAndSimSQL(colExpr)
	var conds []string
	var safeConds []string
	conds = append(conds, baseCond)
	safeConds = append(safeConds, baseCond)
	conds = append(conds, filterConds...)
	safeConds = append(safeConds, safeFilterConds...)
	if simCond != "" {
		conds = append(conds, simCond)
		safeConds = append(safeConds, simCond)
	}

	preFilter := strings.Join(conds, " AND ")
	if t.activeAliasWhere != "" && t.activeAliasWhere != "TRUE" {
		preFilter = fmt.Sprintf("(%s) AND (%s)", preFilter, t.activeAliasWhere)
	}
	if nctx == nil && t.Schema != nil && t.Schema.DorisDB != "" && t.Schema.DorisTable != "" && topLimit > 0 {
		topSubquery := fmt.Sprintf("`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (ORDER BY %s DESC, `_id` ASC) AS `_rn` FROM `%s`.`%s` WHERE `__DORIS_DELETE_SIGN__` = 0 AND %s) `_knn_top` WHERE `_rn` <= %d)",
			rawScoreExpr, t.Schema.DorisDB, t.Schema.DorisTable, preFilter, topLimit)
		conds = append(conds, topSubquery)
		safeConds = append(safeConds, topSubquery)
	}

	whereSQL := strings.Join(conds, " AND ")
	safeWhereSQL := strings.Join(safeConds, " AND ")
	scoreSQL := "1.0"
	if scoring {
		scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%.4f * COALESCE(%s, 0.0)) ELSE 0.0 END)",
			safeWhereSQL, boost, rawScoreExpr)
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}
}

// foldNumericRangeBoundsOutOfBounds normalizes and folds out-of-bounds numeric range query bounds
// per Elasticsearch `510_range_query_out_of_bounds.yml`:
//   - Integer types (`byte`, `short`, `integer`, `long`, `unsigned_long`): folds fractional bounds
//     (`gt: 1.5` -> `gte: 2`, `lt: 1.5` -> `lte: 1`) and detects impossible ranges (`gt >= typeMax`,
//     `gte > typeMax`, `lt <= typeMin`, `lte < typeMin`, or `lower > upper`).
//   - Float types (`half_float`, `float`, `scaled_float`): clamps huge finite bounds instead of overflowing
//     `float32` / `ScalingFactor` to `±Inf` (`NULL`), and returns `alwaysFalse = true` when the range lies
//     strictly outside the representable finite range of the mapped type.
func foldNumericRangeBoundsOutOfBounds(
	b schema.FieldBinding,
	gt, gte, lt, lte any,
) (outGT, outGTE, outLT, outLTE any, alwaysFalse bool) {
	outGT, outGTE, outLT, outLTE = gt, gte, lt, lte
	toFloat := func(v any) (float64, bool) {
		if v == nil {
			return 0, false
		}
		switch x := v.(type) {
		case int:
			return float64(x), true
		case int64:
			return float64(x), true
		case uint64:
			return float64(x), true
		case float64:
			if math.IsNaN(x) {
				return 0, false
			}
			return x, true
		case json.Number:
			if fv, err := x.Float64(); err == nil && !math.IsNaN(fv) {
				return fv, true
			}
		case string:
			if fv, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil && !math.IsNaN(fv) {
				return fv, true
			}
		}
		return 0, false
	}

	switch b.ESType {
	case "byte", "short", "integer":
		var minI, maxI int64
		switch b.ESType {
		case "byte":
			minI, maxI = math.MinInt8, math.MaxInt8
		case "short":
			minI, maxI = math.MinInt16, math.MaxInt16
		default:
			minI, maxI = math.MinInt32, math.MaxInt32
		}
		lo, hi := minI, maxI
		hasLo, hasHi := false, false
		for _, pair := range []struct {
			val       any
			inclusive bool
		}{{gt, false}, {gte, true}} {
			if pair.val == nil {
				continue
			}
			fv, ok := toFloat(pair.val)
			if !ok {
				continue
			}
			if fv > float64(maxI) || (fv == float64(maxI) && !pair.inclusive) {
				return nil, nil, nil, nil, true
			}
			if fv < float64(minI) {
				hasLo = true
				continue
			}
			var cand int64
			if pair.inclusive {
				cand = int64(math.Ceil(fv))
			} else {
				cand = int64(math.Floor(fv)) + 1
			}
			if !hasLo || cand > lo {
				lo = cand
				hasLo = true
			}
		}
		for _, pair := range []struct {
			val       any
			inclusive bool
		}{{lt, false}, {lte, true}} {
			if pair.val == nil {
				continue
			}
			fv, ok := toFloat(pair.val)
			if !ok {
				continue
			}
			if fv < float64(minI) || (fv == float64(minI) && !pair.inclusive) {
				return nil, nil, nil, nil, true
			}
			if fv > float64(maxI) {
				hasHi = true
				continue
			}
			var cand int64
			if pair.inclusive {
				cand = int64(math.Floor(fv))
			} else {
				cand = int64(math.Ceil(fv)) - 1
			}
			if !hasHi || cand < hi {
				hi = cand
				hasHi = true
			}
		}
		if hasLo && hasHi && lo > hi {
			return nil, nil, nil, nil, true
		}
		if hasLo || hasHi {
			outGT, outLT = nil, nil
			if hasLo {
				outGTE = lo
			} else {
				outGTE = nil
			}
			if hasHi {
				outLTE = hi
			} else {
				outLTE = nil
			}
		}
		return outGT, outGTE, outLT, outLTE, false

	case "float", "half_float":
		maxAbs := float64(math.MaxFloat32)
		if b.ESType == "half_float" {
			maxAbs = 65504.0
		}
		if fv, ok := toFloat(gt); ok && !math.IsInf(fv, -1) && fv >= maxAbs {
			return nil, nil, nil, nil, true
		}
		if fv, ok := toFloat(gte); ok && fv > maxAbs {
			// Accept `3.4028235e38` which rounds to finite `float32(math.MaxFloat32)` in IEEE-754!
			if b.ESType == "float" && !math.IsInf(float64(float32(fv)), 0) {
				outGTE = float64(float32(fv))
			} else {
				return nil, nil, nil, nil, true
			}
		}
		if fv, ok := toFloat(lt); ok && !math.IsInf(fv, 1) && fv <= -maxAbs {
			return nil, nil, nil, nil, true
		}
		if fv, ok := toFloat(lte); ok && fv < -maxAbs {
			if b.ESType == "float" && !math.IsInf(float64(float32(fv)), 0) {
				outLTE = float64(float32(fv))
			} else {
				return nil, nil, nil, nil, true
			}
		}
		clamp := func(v any) any {
			fv, ok := toFloat(v)
			if !ok {
				return v
			}
			if fv > maxAbs {
				return maxAbs
			}
			if fv < -maxAbs {
				return -maxAbs
			}
			return v
		}
		outGT = clamp(outGT)
		outGTE = clamp(outGTE)
		outLT = clamp(outLT)
		outLTE = clamp(outLTE)
		return outGT, outGTE, outLT, outLTE, false

	case "scaled_float":
		if b.ScalingFactor > 0 {
			maxUnscaled := float64(math.MaxInt64) / b.ScalingFactor
			if fv, ok := toFloat(gt); ok && fv >= maxUnscaled {
				return nil, nil, nil, nil, true
			}
			if fv, ok := toFloat(gte); ok && fv > maxUnscaled {
				return nil, nil, nil, nil, true
			}
			if fv, ok := toFloat(lt); ok && fv <= -maxUnscaled {
				return nil, nil, nil, nil, true
			}
			if fv, ok := toFloat(lte); ok && fv < -maxUnscaled {
				return nil, nil, nil, nil, true
			}
			clampScaled := func(v any) any {
				fv, ok := toFloat(v)
				if !ok {
					return v
				}
				if fv > maxUnscaled {
					return maxUnscaled
				}
				if fv < -maxUnscaled {
					return -maxUnscaled
				}
				scaled := fv * b.ScalingFactor
				if math.IsInf(scaled, 0) || math.IsNaN(scaled) {
					return fv
				}
				return math.Round(scaled) / b.ScalingFactor
			}
			outGT = clampScaled(outGT)
			outGTE = clampScaled(outGTE)
			outLT = clampScaled(outLT)
			outLTE = clampScaled(outLTE)
		}
	}
	return outGT, outGTE, outLT, outLTE, false
}

// QueryHasIntervals recursively reports whether `q` contains any `intervals` query clause.
func QueryHasIntervals(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if len(q.Intervals) > 0 {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if QueryHasIntervals(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if QueryHasIntervals(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if QueryHasIntervals(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if QueryHasIntervals(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && QueryHasIntervals(&q.ConstantScore.Filter) {
		return true
	}
	if q.Boosting != nil && (QueryHasIntervals(&q.Boosting.Positive) || QueryHasIntervals(&q.Boosting.Negative)) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if QueryHasIntervals(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.FunctionScore != nil && QueryHasIntervals(q.FunctionScore.Query) {
		return true
	}
	if q.Nested != nil && QueryHasIntervals(&q.Nested.Query) {
		return true
	}
	return false
}

// IntervalsFieldLookupFunc resolves `(text, analyzer)` for a given field name on a candidate document
// (supporting `use_field` overrides inside `intervals` rules).
type IntervalsFieldLookupFunc func(field string) (texts []string, analyzer string)

// ScoreIntervalsSpans computes Lucene's `IntervalScorer` saturation score (`boost * (freq / (1 + freq))`,
// where `freq = sum(1 / (1 + span.Gaps))` over minimal matched intervals).
func ScoreIntervalsSpans(spans []IntervalsSpan, boost float64) float64 {
	minimal := minimizeIntervalsSpans(spans)
	if len(minimal) == 0 || boost == 0 {
		return 0.0
	}
	var sloppyFreq float64
	for _, sp := range minimal {
		gaps := sp.Gaps
		if gaps < 0 {
			gaps = 0
		}
		sloppyFreq += 1.0 / (1.0 + float64(gaps))
	}
	return boost * (sloppyFreq / (1.0 + sloppyFreq))
}

func dedupIntervalsSpansKeepNonMinimal(spans []IntervalsSpan) []IntervalsSpan {
	if len(spans) <= 1 {
		return spans
	}
	cp := make([]IntervalsSpan, len(spans))
	copy(cp, spans)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Start != cp[j].Start {
			return cp[i].Start < cp[j].Start
		}
		if cp[i].End != cp[j].End {
			return cp[i].End < cp[j].End
		}
		return cp[i].Gaps < cp[j].Gaps
	})
	out := make([]IntervalsSpan, 0, len(cp))
	for _, sp := range cp {
		if len(out) > 0 {
			prev := out[len(out)-1]
			if prev.Start == sp.Start && prev.End == sp.End && prev.Gaps == sp.Gaps {
				continue
			}
		}
		out = append(out, sp)
	}
	return out
}

// EvaluateIntervalsRuleWithFieldLookup evaluates an Elasticsearch `intervals` rule with full support
// for `use_field` cross-field token stream resolution, multi-valued field position offsets,
// non-destructive `any_of` span propagation into parent `all_of`, and `filter` relations.
func EvaluateIntervalsRuleWithFieldLookup(
	defaultField string,
	rule *esast.IntervalsRule,
	lookup IntervalsFieldLookupFunc,
	scriptEval func(script *esast.ScriptSpec, span IntervalsSpan) (bool, error),
) ([]IntervalsSpan, bool, error) {
	if rule == nil || lookup == nil {
		return nil, false, nil
	}

	type cachedStream struct {
		tokens   []AnalyzedToken
		analyzer string
	}
	streamCache := make(map[string]cachedStream)
	getStream := func(f string) cachedStream {
		target := strings.TrimSpace(f)
		if target == "" {
			target = defaultField
		}
		if cs, ok := streamCache[target]; ok {
			return cs
		}
		texts, an := lookup(target)
		var allToks []AnalyzedToken
		posOffset := 0
		for _, txt := range texts {
			toks := TokenizeByAnalyzerWithPositions(txt, an)
			maxPos := -1
			for _, tk := range toks {
				shifted := AnalyzedToken{
					Term:     tk.Term,
					Position: tk.Position + posOffset,
				}
				allToks = append(allToks, shifted)
				if shifted.Position > maxPos {
					maxPos = shifted.Position
				}
			}
			if maxPos >= posOffset {
				// Standard ES position_increment_gap = 100 between multi-valued array entries.
				posOffset = maxPos + 101
			}
		}
		cs := cachedStream{tokens: allToks, analyzer: an}
		streamCache[target] = cs
		return cs
	}

	var evalRule func(curField string, r *esast.IntervalsRule) ([]IntervalsSpan, error)
	applyFilter := func(curField string, spans []IntervalsSpan, f *esast.IntervalsFilter) ([]IntervalsSpan, error) {
		if f == nil || len(spans) == 0 {
			return spans, nil
		}
		filterByOther := func(cur []IntervalsSpan, otherRule *esast.IntervalsRule, negate bool, rel func(a, b IntervalsSpan) bool) ([]IntervalsSpan, error) {
			if otherRule == nil || len(cur) == 0 {
				return cur, nil
			}
			otherSpans, err := evalRule(curField, otherRule)
			if err != nil {
				return nil, err
			}
			var kept []IntervalsSpan
			for _, a := range cur {
				matchedRel := false
				for _, b := range otherSpans {
					if rel(a, b) {
						matchedRel = true
						break
					}
				}
				if negate {
					if !matchedRel {
						kept = append(kept, a)
					}
				} else if matchedRel {
					kept = append(kept, a)
				}
			}
			return kept, nil
		}

		var err error
		spans, err = filterByOther(spans, f.Containing, false, func(a, b IntervalsSpan) bool { return a.Start <= b.Start && a.End >= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotContaining, true, func(a, b IntervalsSpan) bool { return a.Start <= b.Start && a.End >= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.ContainedBy, false, func(a, b IntervalsSpan) bool { return a.Start >= b.Start && a.End <= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotContainedBy, true, func(a, b IntervalsSpan) bool { return a.Start >= b.Start && a.End <= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.Overlapping, false, func(a, b IntervalsSpan) bool { return a.Start <= b.End && b.Start <= a.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotOverlapping, true, func(a, b IntervalsSpan) bool { return a.Start <= b.End && b.Start <= a.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.After, false, func(a, b IntervalsSpan) bool { return a.Start > b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.Before, false, func(a, b IntervalsSpan) bool { return a.End < b.Start })
		if err != nil {
			return nil, err
		}

		if f.Script != nil && scriptEval != nil {
			var scriptKept []IntervalsSpan
			for _, sp := range spans {
				ok, err := scriptEval(f.Script, sp)
				if err != nil {
					return nil, err
				}
				if ok {
					scriptKept = append(scriptKept, sp)
				}
			}
			spans = scriptKept
		}
		return spans, nil
	}

	evalRule = func(curField string, r *esast.IntervalsRule) ([]IntervalsSpan, error) {
		if r == nil {
			return nil, nil
		}
		switch {
		case r.Match != nil:
			target := curField
			if strings.TrimSpace(r.Match.UseField) != "" {
				target = strings.TrimSpace(r.Match.UseField)
			}
			st := getStream(target)
			if len(st.tokens) == 0 {
				return nil, nil
			}
			effAn := r.Match.Analyzer
			if effAn == "" {
				effAn = st.analyzer
			}
			qToks := TokenizeByAnalyzer(r.Match.Query, effAn)
			if len(qToks) == 0 {
				return nil, nil
			}
			subLists := make([][]IntervalsSpan, len(qToks))
			for i, qt := range qToks {
				for _, dt := range st.tokens {
					if dt.Term == qt {
						subLists[i] = append(subLists[i], IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				}
			}
			spans := combineSubIntervals(subLists, r.Match.Ordered, r.Match.MaxGaps)
			return applyFilter(curField, spans, r.Match.Filter)

		case r.Prefix != nil:
			target := curField
			if strings.TrimSpace(r.Prefix.UseField) != "" {
				target = strings.TrimSpace(r.Prefix.UseField)
			}
			st := getStream(target)
			if len(st.tokens) == 0 {
				return nil, nil
			}
			effAn := r.Prefix.Analyzer
			if effAn == "" {
				effAn = st.analyzer
			}
			pfx := r.Prefix.Prefix
			if !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword") {
				pfx = strings.ToLower(pfx)
			}
			var spans []IntervalsSpan
			for _, dt := range st.tokens {
				if strings.HasPrefix(dt.Term, pfx) {
					spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
				}
			}
			return applyFilter(curField, spans, r.Prefix.Filter)

		case r.Wildcard != nil:
			target := curField
			if strings.TrimSpace(r.Wildcard.UseField) != "" {
				target = strings.TrimSpace(r.Wildcard.UseField)
			}
			st := getStream(target)
			if len(st.tokens) == 0 {
				return nil, nil
			}
			effAn := r.Wildcard.Analyzer
			if effAn == "" {
				effAn = st.analyzer
			}
			ci := !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword")
			re := wildcardPatternRegex(r.Wildcard.Pattern, ci)
			var spans []IntervalsSpan
			if re != nil {
				for _, dt := range st.tokens {
					if re.MatchString(dt.Term) {
						spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				}
			}
			return applyFilter(curField, spans, r.Wildcard.Filter)

		case r.Fuzzy != nil:
			target := curField
			if strings.TrimSpace(r.Fuzzy.UseField) != "" {
				target = strings.TrimSpace(r.Fuzzy.UseField)
			}
			st := getStream(target)
			if len(st.tokens) == 0 {
				return nil, nil
			}
			effAn := r.Fuzzy.Analyzer
			if effAn == "" {
				effAn = st.analyzer
			}
			term := r.Fuzzy.Term
			if !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword") {
				term = strings.ToLower(term)
			}
			fuzz := any("AUTO")
			if r.Fuzzy.Fuzziness != nil {
				fuzz = r.Fuzzy.Fuzziness
			}
			maxEdits := resolveFuzzyMaxEdits(fuzz, len([]rune(term)))
			allowTransp := true
			if r.Fuzzy.Transpositions != nil {
				allowTransp = *r.Fuzzy.Transpositions
			}
			var re *regexp.Regexp
			if maxEdits > 0 {
				pat := "^(" + buildFuzzyEditDistanceRegex(term, maxEdits, r.Fuzzy.PrefixLength, allowTransp) + ")$"
				re, _ = regexp.Compile(pat)
			}
			var spans []IntervalsSpan
			for _, dt := range st.tokens {
				if maxEdits <= 0 {
					if dt.Term == term {
						spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				} else if re != nil && re.MatchString(dt.Term) {
					spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
				}
			}
			return applyFilter(curField, spans, r.Fuzzy.Filter)

		case r.AllOf != nil:
			if len(r.AllOf.Intervals) == 0 {
				return nil, nil
			}
			subLists := make([][]IntervalsSpan, len(r.AllOf.Intervals))
			for i := range r.AllOf.Intervals {
				sl, err := evalRule(curField, &r.AllOf.Intervals[i])
				if err != nil {
					return nil, err
				}
				subLists[i] = sl
			}
			spans := combineSubIntervals(subLists, r.AllOf.Ordered, r.AllOf.MaxGaps)
			return applyFilter(curField, spans, r.AllOf.Filter)

		case r.AnyOf != nil:
			var all []IntervalsSpan
			for i := range r.AnyOf.Intervals {
				sl, err := evalRule(curField, &r.AnyOf.Intervals[i])
				if err != nil {
					return nil, err
				}
				all = append(all, sl...)
			}
			// Preserve non-minimal spans (e.g. `any_of: ["big", "big bad"]`) so parent `all_of(..., max_gaps: 0)`
			// can still match `"big bad"` + `"wolf"` on `"the big bad wolf"`.
			spans := dedupIntervalsSpansKeepNonMinimal(all)
			return applyFilter(curField, spans, r.AnyOf.Filter)
		}
		return nil, nil
	}

	spans, err := evalRule(defaultField, rule)
	if err != nil {
		return nil, false, err
	}
	minimal := minimizeIntervalsSpans(spans)
	return minimal, len(minimal) > 0, nil
}

// isUnsupportedMLTESType reports whether an ES field type is unsupported by `more_like_this`
// when `fail_on_unsupported_field` is enabled (which defaults to `true` in Elasticsearch).
func isUnsupportedMLTESType(esType string) bool {
	switch esType {
	case "", "text", "keyword", "constant_keyword", "wildcard", "match_only_text", "search_as_you_type", "completion", "flattened":
		return false
	default:
		return true
	}
}

func tokenizeMLTTextsWithAnalyzer(
	texts []string,
	analyzer string,
	stopSet map[string]bool,
	minWordLen, maxWordLen, minTermFreq, maxQueryTerms int,
) []string {
	var ordered []string
	seen := make(map[string]bool)
	counts := make(map[string]int)
	for _, txt := range texts {
		var rawToks []string
		if strings.EqualFold(analyzer, "keyword") {
			if txt != "" {
				rawToks = []string{txt}
			}
		} else {
			rawToks = TokenizeByAnalyzer(txt, analyzer)
		}
		for _, tok := range rawToks {
			lowerTok := strings.ToLower(tok)
			if stopSet[lowerTok] {
				continue
			}
			if minWordLen > 0 && len([]rune(tok)) < minWordLen {
				continue
			}
			if maxWordLen > 0 && len([]rune(tok)) > maxWordLen {
				continue
			}
			counts[tok]++
			if !seen[tok] {
				seen[tok] = true
				ordered = append(ordered, tok)
			}
		}
	}
	var tokens []string
	for _, tok := range ordered {
		if minTermFreq > 1 && counts[tok] < minTermFreq {
			continue
		}
		tokens = append(tokens, tok)
	}
	// When max_query_terms is set, ES selects highest-frequency terms first (preserving order on ties).
	if maxQueryTerms > 0 && len(tokens) > maxQueryTerms {
		type rankedTok struct {
			tok string
			cnt int
			idx int
		}
		ranked := make([]rankedTok, len(tokens))
		for i, tk := range tokens {
			ranked[i] = rankedTok{tok: tk, cnt: counts[tk], idx: i}
		}
		sort.Slice(ranked, func(i, j int) bool {
			if ranked[i].cnt != ranked[j].cnt {
				return ranked[i].cnt > ranked[j].cnt
			}
			return ranked[i].idx < ranked[j].idx
		})
		ranked = ranked[:maxQueryTerms]
		sort.Slice(ranked, func(i, j int) bool { return ranked[i].idx < ranked[j].idx })
		tokens = make([]string, len(ranked))
		for i, r := range ranked {
			tokens[i] = r.tok
		}
	}
	return tokens
}

// extractMLTLikeTextsForIndex extracts inline texts and same-index `_id` exclusions from `like` / `unlike`.
// Cross-index `LikeDocument` references (`_index != targetIndex`) do NOT exclude same-ID documents in `targetIndex`.
func extractMLTLikeTextsForIndex(v any, fields []string, targetIndex string) ([]string, []string) {
	texts, _ := extractMLTLikeTexts(v, fields)
	var excludedIDs []string
	seenIDs := make(map[string]bool)
	var collectIDs func(item any)
	collectIDs = func(item any) {
		switch lv := item.(type) {
		case []any:
			for _, sub := range lv {
				collectIDs(sub)
			}
		case map[string]any:
			if rawIdx, hasIdx := lv["_index"]; hasIdx && rawIdx != nil && targetIndex != "" {
				idxStr := strings.TrimSpace(fmt.Sprintf("%v", rawIdx))
				if idxStr != "" && idxStr != targetIndex {
					return
				}
			}
			if rawID, hasID := lv["_id"]; hasID && rawID != nil {
				idStr := strings.TrimSpace(fmt.Sprintf("%v", rawID))
				if idStr != "" && !seenIDs[idStr] {
					seenIDs[idStr] = true
					excludedIDs = append(excludedIDs, idStr)
				}
			}
		}
	}
	collectIDs(v)
	return texts, excludedIDs
}

func (t *Transpiler) compileMoreLikeThisRound61(mlt *esast.MoreLikeThisQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if mlt == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	failOnUnsupported := true
	if mlt.FailOnUnsupportedField != nil {
		failOnUnsupported = *mlt.FailOnUnsupportedField
	}

	var rawFields []string
	if len(mlt.Fields) == 0 {
		rawFields = []string{"_all_text"}
	} else {
		for _, f := range mlt.Fields {
			cleanF, fBoost := parseFieldBoost(f, 1.0)
			if strings.ContainsAny(cleanF, "*?") && t.Schema != nil {
				exp := t.expandFieldPatternForContext(f, nctx)
				for _, bf := range exp {
					_, b := t.resolveFieldInNestedCtx(bf.Field, false, nctx)
					if isUnsupportedMLTESType(b.ESType) {
						if failOnUnsupported {
							if !t.inLenientQuery && t.searchErr == nil {
								t.searchErr = fmt.Errorf("illegal_argument_exception: MoreLikeThis is not supported for field [%s] of type [%s]", bf.Field, b.ESType)
							}
							return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
						}
						continue
					}
					if bf.Boost != 1.0 {
						rawFields = append(rawFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
					} else {
						rawFields = append(rawFields, bf.Field)
					}
				}
				continue
			}
			if t.Schema != nil && cleanF != "_all_text" && cleanF != "*" {
				_, b := t.resolveFieldInNestedCtx(cleanF, false, nctx)
				if !t.checkFieldSearchable(cleanF, b) {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				if isUnsupportedMLTESType(b.ESType) {
					if failOnUnsupported {
						if !t.inLenientQuery && t.searchErr == nil {
							t.searchErr = fmt.Errorf("illegal_argument_exception: MoreLikeThis is not supported for field [%s] of type [%s]", cleanF, b.ESType)
						}
						return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
					}
					continue
				}
			}
			if fBoost != 1.0 {
				rawFields = append(rawFields, fmt.Sprintf("%s^%g", cleanF, fBoost))
			} else {
				rawFields = append(rawFields, cleanF)
			}
		}
	}
	if len(rawFields) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	targetIndex := ""
	if t.Schema != nil {
		targetIndex = t.Schema.IndexName
	}

	var combinedLike []any
	if mlt.Like != nil {
		combinedLike = append(combinedLike, mlt.Like)
	}
	if strings.TrimSpace(mlt.LikeText) != "" {
		combinedLike = append(combinedLike, mlt.LikeText)
	}
	for _, d := range mlt.Docs {
		combinedLike = append(combinedLike, d)
	}
	for _, id := range mlt.Ids {
		if strings.TrimSpace(id) != "" {
			combinedLike = append(combinedLike, map[string]any{"_id": id})
		}
	}

	texts, excludedIDs := extractMLTLikeTextsForIndex(combinedLike, mlt.Fields, targetIndex)
	stopSet := make(map[string]bool, len(mlt.StopWords))
	for _, sw := range mlt.StopWords {
		stopSet[strings.ToLower(sw)] = true
	}

	analyzer := strings.TrimSpace(mlt.Analyzer)
	if analyzer == "" && t.Schema != nil && len(rawFields) > 0 {
		firstF, _ := parseFieldBoost(rawFields[0], 1.0)
		if firstF != "_all_text" && firstF != "*" {
			_, fb := t.resolveFieldInNestedCtx(firstF, false, nctx)
			if isExactKeywordField(firstF, fb) {
				analyzer = "keyword"
			} else {
				analyzer = effectiveFieldSearchAnalyzer(fb)
			}
		}
	}

	minTF := mlt.MinTermFreq
	if mlt.MinTermFreq == 0 && len(texts) == 1 {
		minTF = 1
	}
	maxQT := mlt.MaxQueryTerms
	if maxQT <= 0 {
		maxQT = 25
	}

	tokens := tokenizeMLTTextsWithAnalyzer(texts, analyzer, stopSet, mlt.MinWordLength, mlt.MaxWordLength, minTF, maxQT)

	// In Elasticsearch `MoreLikeThis`, `unlike` subtracts terms from the selected `like` term set
	// (it does NOT append a document-level `MUST_NOT` query!).
	if mlt.Unlike != nil {
		unlikeTexts, _ := extractMLTLikeTextsForIndex(mlt.Unlike, mlt.Fields, targetIndex)
		unlikeTokens := tokenizeMLTTextsWithAnalyzer(unlikeTexts, analyzer, stopSet, mlt.MinWordLength, mlt.MaxWordLength, 1, 0)
		if len(unlikeTokens) > 0 {
			unlikeSet := make(map[string]bool, len(unlikeTokens))
			for _, ut := range unlikeTokens {
				unlikeSet[ut] = true
				unlikeSet[strings.ToLower(ut)] = true
			}
			filtered := make([]string, 0, len(tokens))
			for _, tk := range tokens {
				if !unlikeSet[tk] && !unlikeSet[strings.ToLower(tk)] {
					filtered = append(filtered, tk)
				}
			}
			tokens = filtered
		}
	}

	if len(tokens) == 0 && len(excludedIDs) > 0 && len(texts) == 0 && mlt.Unlike == nil && mlt.MinimumShouldMatch == nil {
		if !mlt.Include {
			var quotedIDs []string
			for _, id := range excludedIDs {
				quotedIDs = append(quotedIDs, quoteStr(id))
			}
			w := fmt.Sprintf("`_id` NOT IN (%s)", strings.Join(quotedIDs, ", "))
			return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: "1.0"}
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	}
	if len(tokens) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	boost := 1.0
	if mlt.Boost != nil {
		boost = *mlt.Boost
	}
	if mlt.BoostTerms > 0 {
		boost *= mlt.BoostTerms
	}

	// Default `minimum_should_match` in ES MLT is `"30%"` (at least 1 when >= 1 term).
	effMSM := mlt.MinimumShouldMatch
	if effMSM == nil {
		effMSM = "30%"
	}

	var tokenConds, safeTokenConds, scoreTerms []string
	usesFT := false
	for _, tok := range tokens {
		var fPreds, fSafePreds []string
		for _, f := range rawFields {
			cp := t.compileMatchField(f, tok, "or", boost, inScoring, nctx)
			if cp.WhereSQL != "FALSE" {
				fPreds = append(fPreds, cp.WhereSQL)
				fSafePreds = append(fSafePreds, cp.EffectiveSafeWhere())
				usesFT = usesFT || cp.UsesFulltextMatch
				if inScoring && cp.ScoreSQL != "0.0" {
					scoreTerms = append(scoreTerms, cp.ScoreSQL)
				}
			}
		}
		if len(fPreds) == 1 {
			tokenConds = append(tokenConds, fPreds[0])
			safeTokenConds = append(safeTokenConds, fSafePreds[0])
		} else if len(fPreds) > 1 {
			tokenConds = append(tokenConds, "("+strings.Join(fPreds, " OR ")+")")
			safeTokenConds = append(safeTokenConds, "("+strings.Join(fSafePreds, " OR ")+")")
		}
	}
	if len(tokenConds) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	minShould := parseMinShouldMatch(effMSM, len(tokenConds), true)
	if minShould > len(tokenConds) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	var whereSQL, safeWhereSQL string
	if minShould <= 1 {
		if len(tokenConds) == 1 {
			whereSQL = tokenConds[0]
			safeWhereSQL = safeTokenConds[0]
		} else {
			whereSQL = "(" + strings.Join(tokenConds, " OR ") + ")"
			safeWhereSQL = "(" + strings.Join(safeTokenConds, " OR ") + ")"
		}
	} else if minShould == len(tokenConds) {
		whereSQL = "(" + strings.Join(tokenConds, " AND ") + ")"
		safeWhereSQL = "(" + strings.Join(safeTokenConds, " AND ") + ")"
	} else {
		var intCasts []string
		for _, sc := range safeTokenConds {
			intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", sc))
		}
		msmCond := fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould)
		whereSQL = fmt.Sprintf("((%s) AND %s)", strings.Join(tokenConds, " OR "), msmCond)
		safeWhereSQL = msmCond
	}

	if !mlt.Include && len(excludedIDs) > 0 {
		var quotedIDs []string
		for _, id := range excludedIDs {
			quotedIDs = append(quotedIDs, quoteStr(id))
		}
		exclCond := fmt.Sprintf("`_id` NOT IN (%s)", strings.Join(quotedIDs, ", "))
		whereSQL = fmt.Sprintf("(%s AND %s)", whereSQL, exclCond)
		safeWhereSQL = fmt.Sprintf("(%s AND %s)", safeWhereSQL, exclCond)
	}

	scoreSQL := "0.0"
	if inScoring && boost != 0 {
		if len(scoreTerms) == 1 {
			scoreSQL = scoreTerms[0]
		} else if len(scoreTerms) > 1 {
			scoreSQL = "(" + strings.Join(scoreTerms, " + ") + ")"
		} else {
			scoreSQL = fmt.Sprintf("%g", boost)
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
}
