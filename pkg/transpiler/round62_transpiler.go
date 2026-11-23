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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// esTranspilerError preserves exact Elasticsearch wire error strings (including capitalization
// and trailing periods required by upstream YAML tests) without triggering staticcheck ST1005.
type esTranspilerError string

func (e esTranspilerError) Error() string { return string(e) }

// ----------------------------------------------------------------------------
// F10: Range Multi-Bucket Bounds Clamping & BIGINT Offset Explosion
// ----------------------------------------------------------------------------

// rangeHistogramClampedBoundsSQL resolves finite lower/upper SQL expressions for `histogram`
// and `date_histogram` over `*_range` fields, clamping half-open ranges (`{"gte": 10}` without
// `lte`, or `{"lte": 20}` without `gte`) to `hard_bounds`/`extended_bounds` when present or to
// the opposite finite endpoint so `ARRAY_RANGE` never overflows on `±1e100` sentinels.
func rangeHistogramClampedBoundsSQL(
	rawLoSQL, rawHiSQL string,
	hardMin, hardMax *float64,
	extMin, extMax *float64,
) (effLoSQL, effHiSQL string) {
	fallbackLo := rawHiSQL
	if hardMin != nil {
		minLit := strconv.FormatFloat(*hardMin, 'f', -1, 64)
		fallbackLo = fmt.Sprintf("LEAST(%s, %s)", minLit, rawHiSQL)
	} else if extMin != nil {
		minLit := strconv.FormatFloat(*extMin, 'f', -1, 64)
		fallbackLo = fmt.Sprintf("LEAST(%s, %s)", minLit, rawHiSQL)
	}

	fallbackHi := rawLoSQL
	if hardMax != nil {
		maxLit := strconv.FormatFloat(*hardMax, 'f', -1, 64)
		fallbackHi = fmt.Sprintf("GREATEST(%s, %s)", maxLit, rawLoSQL)
	} else if extMax != nil {
		maxLit := strconv.FormatFloat(*extMax, 'f', -1, 64)
		fallbackHi = fmt.Sprintf("GREATEST(%s, %s)", maxLit, rawLoSQL)
	}

	effLoSQL = fmt.Sprintf("COALESCE(%s, %s)", rawLoSQL, fallbackLo)
	effHiSQL = fmt.Sprintf("COALESCE(%s, %s)", rawHiSQL, fallbackHi)

	if hardMin != nil {
		effLoSQL = fmt.Sprintf("GREATEST(%s, %s)", effLoSQL, strconv.FormatFloat(*hardMin, 'f', -1, 64))
	}
	if hardMax != nil {
		effHiSQL = fmt.Sprintf("LEAST(%s, %s)", effHiSQL, strconv.FormatFloat(*hardMax, 'f', -1, 64))
	}
	return effLoSQL, effHiSQL
}

// buildRangeBucketExplodeSQL emits a Doris 4.1.3 `LATERAL VIEW EXPLODE(ARRAY_RANGE(0, ...))`
// clause using 64-bit `BIGINT` bucket indices and zero-based 32-bit `_off` offsets so sub-second
// 2026+ epoch millisecond timestamps (`FLOOR(ms / 100) > INT32_MAX`) never overflow 32-bit `INT`.
func buildRangeBucketExplodeSQL(
	baseTable, effLoSQL, effHiSQL string,
	offset, interval float64,
) (fromClause, bucketValSQL string) {
	if interval <= 0 {
		interval = 1.0
	}
	var loIdxBig, hiIdxBig string
	if offset == 0 {
		ivLit := strconv.FormatFloat(interval, 'f', -1, 64)
		if !strings.Contains(ivLit, ".") {
			ivLit += ".0"
		}
		loIdxBig = fmt.Sprintf("CAST(FLOOR((%s) / %s) AS BIGINT)", effLoSQL, ivLit)
		hiIdxBig = fmt.Sprintf("CAST(FLOOR((%s) / %s) AS BIGINT)", effHiSQL, ivLit)
		countInt := fmt.Sprintf("CAST(LEAST(GREATEST((%s) - (%s) + 1, 0), 10001) AS INT)", hiIdxBig, loIdxBig)
		fromClause = fmt.Sprintf("%s LATERAL VIEW EXPLODE(ARRAY_RANGE(0, %s)) `_rng_t` AS `_off`", baseTable, countInt)
		bucketValSQL = fmt.Sprintf("(CAST((%s) + CAST(`_off` AS BIGINT) AS DOUBLE) * %s)", loIdxBig, ivLit)
		return fromClause, bucketValSQL
	}
	offLit := FormatSQLFloatR63(offset)
	ivLit := FormatSQLFloatR63(interval)
	loIdxBig = fmt.Sprintf("CAST(FLOOR(((%s) - (%s)) / (%s)) AS BIGINT)", effLoSQL, offLit, ivLit)
	hiIdxBig = fmt.Sprintf("CAST(FLOOR(((%s) - (%s)) / (%s)) AS BIGINT)", effHiSQL, offLit, ivLit)
	countInt := fmt.Sprintf("CAST(LEAST(GREATEST((%s) - (%s) + 1, 0), 10001) AS INT)", hiIdxBig, loIdxBig)
	fromClause = fmt.Sprintf("%s LATERAL VIEW EXPLODE(ARRAY_RANGE(0, %s)) `_rng_t` AS `_off`", baseTable, countInt)
	bucketValSQL = fmt.Sprintf("(CAST((%s) + CAST(`_off` AS BIGINT) AS DOUBLE) * (%s) + (%s))", loIdxBig, ivLit, offLit)
	return fromClause, bucketValSQL
}

// ----------------------------------------------------------------------------
// F12: `_doc_count` & `_ignored` Pushdown Helpers
// ----------------------------------------------------------------------------

// sqlDocCountRowWeightExpr returns the per-row positive integer `_doc_count` weight expression
// (`COALESCE(TRY_CAST(json_extract_string(`_source`, '$."_doc_count"') AS BIGINT), 1)`).
func sqlDocCountRowWeightExpr() string {
	return fmt.Sprintf("COALESCE(TRY_CAST(json_extract_string(`_source`, %s) AS BIGINT), 1)", quoteStr(`$."_doc_count"`))
}

// sqlDocCountSumExpr returns `COALESCE(SUM(COALESCE(... _doc_count ..., 1)), 0)` when enabled
// (ES8 mode or explicit `_doc_count` mode), falling back to `COUNT(*)` otherwise.
func (t *Transpiler) sqlDocCountSumExpr() string {
	if t.useDocCountFieldSQL() {
		return fmt.Sprintf("COALESCE(SUM(%s), 0)", sqlDocCountRowWeightExpr())
	}
	return "COUNT(*)"
}

func (t *Transpiler) useDocCountFieldSQL() bool {
	if t.Schema != nil && t.Schema.SourceDisabled() {
		return false
	}
	return t.Opts.ES8Compat || (t.Schema != nil && t.Schema.ES8Mode)
}

func ignoredMetadataBinding() schema.FieldBinding {
	return schema.FieldBinding{
		ESFieldPath: "_ignored",
		ColumnName:  "_ignored",
		Kind:        schema.StoragePromotedArray,
		DorisType:   schema.DorisString,
		ESType:      "keyword",
	}
}

// ----------------------------------------------------------------------------
// F13: `ip_prefix` Aggregation Validation, SQL Pushdown & Canonical Formatting
// ----------------------------------------------------------------------------

// IPv4PrefixNetmask returns the dotted-quad IPv4 netmask string for `prefixLen` in `[0, 32]`.
func IPv4PrefixNetmask(prefixLen int) string {
	if prefixLen <= 0 {
		return "0.0.0.0"
	}
	if prefixLen >= 32 {
		return "255.255.255.255"
	}
	shift := 32 - prefixLen
	mask := uint32(0xffffffff) << shift
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], mask)
	return net.IP(b[:]).String()
}

// FormatIPPrefixBucketKey formats `rawIP` into its masked network address bucket key according
// to Elasticsearch `ip_prefix` 16-byte IPv6-mapped semantics (`ip_prefix.yml`):
//   - Every IP is normalized to its 16-byte IPv6 representation (`::ffff:a.b.c.d` for IPv4).
//   - When `!isIPv6`, the lower 4 bytes (`[12:16]`) are masked by `prefixLen` (`0..32`) and formatted as dotted IPv4.
//   - When `isIPv6`, all 16 bytes are masked by `prefixLen` (`0..128`) and formatted as RFC 5952 IPv6
//     (preserving `::ffff:a.b.c.d` notation when the masked 16-byte value remains IPv4-mapped).
func FormatIPPrefixBucketKey(rawIP string, prefixLen int, isIPv6, appendPrefixLen bool) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return "", false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "", false
	}
	var b16 [16]byte
	copy(b16[:], ip16)

	var out string
	if !isIPv6 {
		if prefixLen < 0 || prefixLen > 32 {
			return "", false
		}
		var mask uint32
		if prefixLen > 0 {
			mask = uint32(0xffffffff) << (32 - prefixLen)
		}
		v4 := binary.BigEndian.Uint32(b16[12:16]) & mask
		var out4 [4]byte
		binary.BigEndian.PutUint32(out4[:], v4)
		out = netip.AddrFrom4(out4).String()
	} else {
		if prefixLen < 0 || prefixLen > 128 {
			return "", false
		}
		fullBytes := prefixLen / 8
		remBits := prefixLen % 8
		for i := fullBytes; i < 16; i++ {
			if i == fullBytes && remBits > 0 {
				b16[i] &= byte(0xff << (8 - remBits))
			} else {
				b16[i] = 0
			}
		}
		addr := netip.AddrFrom16(b16)
		out = addr.String()
	}
	if appendPrefixLen {
		out = fmt.Sprintf("%s/%d", out, prefixLen)
	}
	return out, true
}

// CanonicalIPPrefixSortHex returns a 32-character uppercase hex key representing the 16-byte
// binary network address of an `ip_prefix` bucket key (stripping optional `/N` CIDR suffix)
// so buckets sort in ascending binary address order.
func CanonicalIPPrefixSortHex(bucketKey string) string {
	clean, _, _ := strings.Cut(strings.TrimSpace(bucketKey), "/")
	ip := net.ParseIP(clean)
	if ip == nil {
		return bucketKey
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return bucketKey
	}
	return strings.ToUpper(hex.EncodeToString(ip16))
}

// buildIPPrefixBucketKeySQL returns the Doris 4.1.3 SQL expression computing the `ip_prefix`
// network address bucket key and binary sort key from `colExpr`.
func buildIPPrefixBucketKeySQL(colExpr string, ipSpec *esast.IPPrefixAggSpec) (keySQL, sortHexSQL, validCondSQL string) {
	hex32 := sqlCanonicalIPHexExpr(colExpr)
	validCondSQL = fmt.Sprintf("(%s IS NOT NULL)", hex32)
	prefixLen := ipSpec.PrefixLength

	var baseKeySQL string
	if !ipSpec.IsIPv6 {
		var mask32 uint32
		if prefixLen >= 32 {
			mask32 = 0xffffffff
		} else if prefixLen > 0 {
			mask32 = uint32(0xffffffff) << (32 - prefixLen)
		}
		maskedNum := fmt.Sprintf("(CAST(CONV(RIGHT(%s, 8), 16, 10) AS BIGINT) & %d)", hex32, int64(mask32))
		baseKeySQL = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE IPV4_NUM_TO_STRING(CAST(%s AS BIGINT)) END", hex32, maskedNum)
		sortHexSQL = fmt.Sprintf("LPAD(HEX(%s), 8, '0')", maskedNum)
	} else {
		var chunks [4]string
		for i := 0; i < 4; i++ {
			chunkStartBit := i * 32
			subExpr := fmt.Sprintf("SUBSTRING(%s, %d, 8)", hex32, i*8+1)
			rem := prefixLen - chunkStartBit
			switch {
			case rem <= 0:
				chunks[i] = "'00000000'"
			case rem >= 32:
				chunks[i] = subExpr
			default:
				m := uint32(0xffffffff) << (32 - rem)
				chunks[i] = fmt.Sprintf("LPAD(HEX(CAST(CONV(%s, 16, 10) AS BIGINT) & %d), 8, '0')", subExpr, int64(m))
			}
		}
		maskedHex32 := fmt.Sprintf("CONCAT(%s, %s, %s, %s)", chunks[0], chunks[1], chunks[2], chunks[3])
		baseKeySQL = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE IPV6_NUM_TO_STRING(UNHEX(%s)) END", hex32, maskedHex32)
		sortHexSQL = maskedHex32
	}

	if ipSpec.EffectiveAppendPrefixLength() {
		keySQL = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE CONCAT(%s, '/%d') END", baseKeySQL, baseKeySQL, prefixLen)
	} else {
		keySQL = baseKeySQL
	}
	return keySQL, sortHexSQL, validCondSQL
}

// ----------------------------------------------------------------------------
// F15: `time_series` Bucket Aggregation & `_tsid` Decoding Helpers
// ----------------------------------------------------------------------------

// DecodeTSIDRawHex decodes a Base64URL-encoded `_tsid` string into its uppercase raw hex bytes
// for binary `BytesRef` ordering parity with Elasticsearch `TimeSeriesAggregator`.
func DecodeTSIDRawHex(tsid string) string {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tsid))
	if err != nil {
		return tsid
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// ParseTimeSeriesBucketKey splits a `time_series` SQL `_bucket_key` (`"<__tsid>|<__tsid_key_json>"`)
// into its Base64URL `_tsid` string and decoded dimension key map.
func ParseTimeSeriesBucketKey(raw string) (tsid string, keyMap map[string]any) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		_ = unmarshalTSIDKeyMap(trimmed, &keyMap)
		return "", keyMap
	}
	idPart, jsonPart, ok := strings.Cut(trimmed, "|")
	if !ok {
		return trimmed, map[string]any{}
	}
	if err := unmarshalTSIDKeyMap(jsonPart, &keyMap); err != nil || keyMap == nil {
		keyMap = map[string]any{}
	}
	return idPart, keyMap
}

func unmarshalTSIDKeyMap(rawJSON string, dst *map[string]any) error {
	dec := json.NewDecoder(strings.NewReader(rawJSON))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return err
	}
	for k, v := range m {
		if num, ok := v.(json.Number); ok {
			m[k] = coerceJSONNumberExactIntOrUintR63(num)
		}
	}
	*dst = m
	return nil
}

func sqlTSIDBinarySortExpr(tsidCol string) string {
	return fmt.Sprintf("TRANSLATE(%s, %s, %s)",
		tsidCol, quoteStr(base64URLAlphabetR63), quoteStr(asciiOrdered64AlphabetR63))
}

// ----------------------------------------------------------------------------
// F13 / F14 / F15 / F18: Round-62 Aggregation Tree Validation & SQL Compilation
// ----------------------------------------------------------------------------

func aggSpecPrimaryTypeName(spec esast.AggSpec) string {
	switch {
	case spec.RandomSampler != nil:
		return "random_sampler"
	case spec.DiversifiedSampler != nil:
		return "diversified_sampler"
	case spec.Sampler != nil:
		return "sampler"
	case spec.TimeSeries != nil:
		return "time_series"
	case spec.IPPrefix != nil:
		return "ip_prefix"
	case spec.Children != nil:
		return "children"
	case spec.Parent != nil:
		return "parent"
	case spec.Composite != nil:
		return "composite"
	case spec.Global != nil:
		return "global"
	case spec.AutoDateHistogram != nil:
		return "auto_date_histogram"
	case spec.VariableWidthHistogram != nil:
		return "variable_width_histogram"
	case spec.RareTerms != nil:
		return "rare_terms"
	default:
		return TypedAggKeyPrefix(&spec, nil)
	}
}

type aggAncestorInfo struct {
	name    string
	aggType string
}

// validateRound62AggTree validates `ip_prefix`, `time_series`, `random_sampler`, and `diversified_sampler`/`sampler`
// structural and field-type constraints across the entire aggregation tree.
func (t *Transpiler) validateRound62AggTree(aggs map[string]esast.AggSpec, ancestors []aggAncestorInfo, nctx *nestedCtx) {
	if len(aggs) == 0 || t.searchErr != nil {
		return
	}
	names := make([]string, 0, len(aggs))
	for k := range aggs {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		if t.searchErr != nil {
			return
		}
		spec := aggs[name]
		curType := aggSpecPrimaryTypeName(spec)

		// 1. ip_prefix validation
		if spec.IPPrefix != nil {
			if !spec.IPPrefix.IsIPv6 && (spec.IPPrefix.PrefixLength < 0 || spec.IPPrefix.PrefixLength > 32) {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [prefix_length] must be in range [0, 32] while value is [%d]", spec.IPPrefix.PrefixLength))
				return
			}
			if spec.IPPrefix.IsIPv6 && (spec.IPPrefix.PrefixLength < 0 || spec.IPPrefix.PrefixLength > 128) {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [prefix_length] must be in range [0, 128] while value is [%d]", spec.IPPrefix.PrefixLength))
				return
			}
			resolved, b := t.resolveFieldInNestedCtx(spec.IPPrefix.Field, true, nctx)
			if b.ESType != "" && b.ESType != "ip" {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Field [%s] of type [%s] is not supported for aggregation [ip_prefix]", spec.IPPrefix.Field, b.ESType))
				return
			}
			t.checkFieldDocValues(resolved, b)
		}

		// 2. random_sampler validation (random_sampler.yml)
		if spec.RandomSampler != nil {
			if len(ancestors) > 0 {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [random_sampler] aggregation [%s] cannot have a parent aggregation", name))
				return
			}
			if len(spec.SubAggs()) == 0 {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [random_sampler] aggregation [%s] must have sub-aggregations", name))
				return
			}
			if spec.RandomSampler.Probability == nil || *spec.RandomSampler.Probability <= 0 {
				pVal := 0.0
				if spec.RandomSampler.Probability != nil {
					pVal = *spec.RandomSampler.Probability
				}
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [probability] must be greater than 0.0, was [%v]", pVal))
				return
			}
			p := *spec.RandomSampler.Probability
			if (p > 0.5 && p != 1.0) || math.IsNaN(p) || math.IsInf(p, 0) {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [probability] must be between 0.0 and 0.5 or exactly 1.0, was [%v]", p))
				return
			}
			for childName, childSpec := range spec.SubAggs() {
				ct := aggSpecPrimaryTypeName(childSpec)
				switch ct {
				case "sampler", "diversified_sampler", "random_sampler", "time_series":
					t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [random_sampler] aggregation [%s] does not support sampling [%s] aggregation [%s]", name, ct, childName))
					return
				}
			}
		}

		// 3. sampler / diversified_sampler validation
		if samp := spec.EffectiveSampler(); samp != nil {
			if samp.ShardSize < 0 {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [shard_size] must be greater than 0. Found [%d] in [%s]", samp.ShardSize, name))
				return
			}
			if samp.MaxDocsPerValue < 0 {
				t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [max_docs_per_value] must be greater than 0. Found [%d] in [%s]", samp.MaxDocsPerValue, name))
				return
			}
			for childName, childSpec := range spec.SubAggs() {
				if childSpec.TimeSeries != nil {
					t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [%s] aggregation [%s] does not support sampling [time_series] aggregation [%s]", curType, name, childName))
					return
				}
			}
		}

		// 4. time_series validation (time_series.yml)
		if spec.TimeSeries != nil {
			if t.Schema != nil && t.Schema.IndexName != "" && !strings.EqualFold(strings.TrimSpace(t.Schema.IndexMode), "time_series") {
				t.searchErr = esTranspilerError("illegal_argument_exception: [time_series] aggregation can only be executed on indices with [index.mode: time_series]")
				return
			}
			for _, anc := range ancestors {
				switch anc.aggType {
				case "random_sampler", "sampler", "diversified_sampler":
					t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [%s] aggregation [%s] does not support sampling [time_series] aggregation [%s]", anc.aggType, anc.name, name))
					return
				case "composite":
					t.searchErr = esTranspilerError("illegal_argument_exception: [composite] aggregation is incompatible with time series execution mode")
					return
				case "global":
					t.searchErr = esTranspilerError("illegal_argument_exception: Time series aggregations cannot be used inside global aggregation.")
					return
				case "auto_date_histogram", "variable_width_histogram":
					var hasRate func(m map[string]esast.AggSpec) bool
					hasRate = func(m map[string]esast.AggSpec) bool {
						for _, sub := range m {
							if sub.Rate != nil || hasRate(sub.SubAggs()) {
								return true
							}
						}
						return false
					}
					if hasRate(spec.SubAggs()) {
						t.searchErr = esTranspilerError("illegal_argument_exception: Wrapping a time-series rate aggregation within a DeferableBucketAggregator is not supported")
						return
					}
					t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [%s] aggregation is incompatible with time series execution mode", anc.name))
					return
				}
			}
		}

		// 5. rare_terms inside time_series ancestor
		if spec.RareTerms != nil {
			for _, anc := range ancestors {
				if anc.aggType == "time_series" {
					t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: [%s] aggregation is incompatible with time series execution mode", name))
					return
				}
			}
		}

		nextNCtx := nctx
		if spec.Nested != nil && spec.Nested.Path != "" {
			nextNCtx = &nestedCtx{nestedPath: spec.Nested.Path}
		} else if spec.ReverseNested != nil {
			if rnPath, _ := spec.ReverseNested["path"].(string); strings.TrimSpace(rnPath) != "" {
				nextNCtx = &nestedCtx{nestedPath: strings.TrimSpace(rnPath)}
			} else {
				nextNCtx = nil
			}
		}
		nextAnc := append(append([]aggAncestorInfo(nil), ancestors...), aggAncestorInfo{name: name, aggType: curType})
		t.validateRound62AggTree(spec.SubAggs(), nextAnc, nextNCtx)
	}
}

func hasGlobalOrJoinAgg(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Global != nil || spec.Children != nil || spec.Parent != nil || hasGlobalOrJoinAgg(spec.SubAggs()) {
			return true
		}
	}
	return false
}

// buildRandomSamplerWhereSQL builds the Doris SQL predicate for `random_sampler`.
func buildRandomSamplerWhereSQL(rs *esast.RandomSamplerAggSpec, extraWhere string) string {
	prob := 0.1
	if rs != nil && rs.Probability != nil {
		prob = *rs.Probability
	}
	var seed int64
	if rs != nil && rs.Seed != nil {
		seed = *rs.Seed
	}
	sampleCond := "TRUE"
	if prob < 1.0 {
		threshold := int64(math.Round(prob * 2147483648.0))
		if threshold <= 0 {
			threshold = 1
		}
		seedStr := strconv.FormatInt(seed, 10)
		sampleCond = fmt.Sprintf("ABS(CAST(MURMUR_HASH3_32(`_id`, %s) AS BIGINT)) < %d", quoteStr(seedStr), threshold)
	}
	if extraWhere != "" && extraWhere != "TRUE" {
		if sampleCond == "TRUE" {
			return extraWhere
		}
		return fmt.Sprintf("(%s) AND (%s)", extraWhere, sampleCond)
	}
	return sampleCond
}

// buildSamplerSubqueryWhereSQL builds the Doris SQL `_id IN (...)` pushdown predicate for
// `sampler` and `diversified_sampler` (`shard_size` + `max_docs_per_value` window partitioning).
func (t *Transpiler) buildSamplerSubqueryWhereSQL(samp *esast.SamplerAggSpec, extraWhere, scoreSQL string) string {
	if samp == nil {
		return extraWhere
	}
	shardSize := samp.ShardSize
	if shardSize <= 0 {
		shardSize = 100
	}
	maxDocs := samp.MaxDocsPerValue
	if maxDocs <= 0 {
		maxDocs = 1
	}
	effScore := scoreSQL
	if effScore == "" {
		effScore = "1.0"
	}

	effField := strings.TrimSpace(samp.Field)
	if effField == "" && samp.Script != nil {
		if df, ok := extractSimpleDocFieldFromScript(samp.Script); ok {
			effField = df
		}
	}

	baseFilter := "1=1"
	if extraWhere != "" && extraWhere != "TRUE" {
		baseFilter = extraWhere
	}

	// Plain `sampler` (no diversification field or script): top `shard_size` docs by `(_score DESC, _id ASC)`.
	if effField == "" && samp.Script == nil {
		subSQL := fmt.Sprintf(
			"`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE %s ORDER BY CAST(%s AS DOUBLE) DESC, `_id` ASC LIMIT %d) `_smp_top`)",
			baseFilter, effScore, shardSize,
		)
		if extraWhere != "" && extraWhere != "TRUE" {
			return fmt.Sprintf("(%s) AND %s", extraWhere, subSQL)
		}
		return subSQL
	}

	dedupExpr := "`_id`"
	if effField != "" {
		_, b := t.resolveFieldInNestedCtx(effField, true, nil)
		if (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
			dedupExpr = fmt.Sprintf("CAST(element_at(`%s`, 1) AS STRING)", b.EffectiveArrayColumn(true))
		} else {
			dedupExpr = fmt.Sprintf("CAST(%s AS STRING)", t.sqlColumnRef(effField, true, nil))
		}
	}
	if samp.Script != nil {
		override := ""
		if effField != "" {
			override = dedupExpr
		}
		if se, ok := t.compilePolymorphicScriptExpr(samp.Script, effField, override, nil); ok {
			dedupExpr = fmt.Sprintf("CAST(%s AS STRING)", se)
		}
	}
	// Null dedup keys never deduplicate against non-null docs in ES DiversifiedSampler; keep unique per `_id` when NULL.
	partExpr := fmt.Sprintf("COALESCE(%s, CONCAT('__null_id__:', `_id`))", dedupExpr)
	subSQL := fmt.Sprintf(
		"`_id` IN (SELECT `_id` FROM ("+
			"SELECT `_id`, ROW_NUMBER() OVER (PARTITION BY `_ds_key` ORDER BY `_ds_score` DESC, `_id` ASC) AS `_ds_rn` FROM ("+
			"SELECT `_id`, %s AS `_ds_key`, CAST(%s AS DOUBLE) AS `_ds_score` "+
			"FROM `base_matched` WHERE %s ORDER BY `_ds_score` DESC, `_id` ASC LIMIT %d"+
			") `_ds_shard`"+
			") `_ds_part` WHERE `_ds_rn` <= %d)",
		partExpr, effScore, baseFilter, shardSize, maxDocs,
	)
	if extraWhere != "" && extraWhere != "TRUE" {
		return fmt.Sprintf("(%s) AND %s", extraWhere, subSQL)
	}
	return subSQL
}

// joinFieldDocExprOnAlias builds “ `<alias>`.`_doc`['jf'] “ (or “ `_doc`['jf'] “ when `alias == ""`).
func joinFieldDocExprOnAlias(alias, jf string) string {
	parts := strings.Split(jf, ".")
	var base strings.Builder
	if alias != "" {
		base.WriteString(alias + ".`_doc`")
	} else {
		base.WriteString("`_doc`")
	}
	for _, p := range parts {
		base.WriteString("[" + quoteStr(p) + "]")
	}
	return base.String()
}

func joinParentRoleCondOnAlias(alias, jf string, fb schema.FieldBinding, childType string) string {
	if len(fb.Relations) == 0 {
		return ""
	}
	baseExpr := joinFieldDocExprOnAlias(alias, jf)
	var parentNames []string
	for pName, v := range fb.Relations {
		matched := false
		switch cv := v.(type) {
		case string:
			matched = cv == childType
		case []string:
			for _, s := range cv {
				if s == childType {
					matched = true
					break
				}
			}
		case []any:
			for _, elem := range cv {
				if s, ok := elem.(string); ok && s == childType {
					matched = true
					break
				}
			}
		}
		if matched {
			parentNames = append(parentNames, pName)
		}
	}
	if len(parentNames) == 0 {
		return ""
	}
	sort.Strings(parentNames)
	var conds []string
	for _, pName := range parentNames {
		qName := quoteStr(pName)
		conds = append(conds, fmt.Sprintf("(CAST(%s AS STRING) = %s OR CAST(%s['name'] AS STRING) = %s)", baseExpr, qName, baseExpr, qName))
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

// buildChildrenAggWhereSQL builds the filter condition on `base_matched` selecting child documents
// of relation `childType` whose parent matched `parentExtraWhere`.
// Returns `"FALSE"` (0-doc bucket, no error) when no join field configures `childType` (`40_aggregations.yml`).
func (t *Transpiler) buildChildrenAggWhereSQL(childType, parentExtraWhere string) string {
	if t.Schema == nil || strings.TrimSpace(childType) == "" {
		return "FALSE"
	}
	var joinFields []string
	for fname, fb := range t.Schema.Fields {
		if fb.ESType == "join" && joinFieldHasChild(fb, childType) {
			joinFields = append(joinFields, fname)
		}
	}
	if len(joinFields) == 0 {
		return "FALSE"
	}
	sort.Strings(joinFields)
	pWhere := "1=1"
	if parentExtraWhere != "" && parentExtraWhere != "TRUE" {
		pWhere = parentExtraWhere
	}
	var disjuncts []string
	for _, jf := range joinFields {
		fb := t.Schema.Fields[jf]
		cExpr := joinFieldDocExprOnAlias("", jf)
		pRole := joinParentRoleCondOnAlias("", jf, fb, childType)
		pCond := pWhere
		if pRole != "" {
			pCond = fmt.Sprintf("(%s) AND %s", pWhere, pRole)
		}
		disjuncts = append(disjuncts, fmt.Sprintf(
			"(CAST(%s['name'] AS STRING) = %s AND %s['parent'] IS NOT NULL AND CAST(%s['parent'] AS STRING) IN (SELECT `_id` FROM `base_matched` WHERE %s))",
			cExpr, quoteStr(childType), cExpr, cExpr, pCond,
		))
	}
	if len(disjuncts) == 1 {
		return disjuncts[0]
	}
	return "(" + strings.Join(disjuncts, " OR ") + ")"
}

// buildParentAggWhereSQL builds the filter condition on `base_matched` selecting parent documents
// that have at least one matched child of relation `childType` under `childExtraWhere`.
// Note: in Elasticsearch `parent: {type: "child"}`, `type` names the child relation (`40_aggregations.yml`).
func (t *Transpiler) buildParentAggWhereSQL(childType, childExtraWhere string) string {
	if t.Schema == nil || strings.TrimSpace(childType) == "" {
		return "FALSE"
	}
	var joinFields []string
	for fname, fb := range t.Schema.Fields {
		if fb.ESType == "join" && joinFieldHasChild(fb, childType) {
			joinFields = append(joinFields, fname)
		}
	}
	if len(joinFields) == 0 {
		return "FALSE"
	}
	sort.Strings(joinFields)
	cWhere := "1=1"
	if childExtraWhere != "" && childExtraWhere != "TRUE" {
		cWhere = childExtraWhere
	}
	var disjuncts []string
	for _, jf := range joinFields {
		fb := t.Schema.Fields[jf]
		cExpr := joinFieldDocExprOnAlias("", jf)
		pRole := joinParentRoleCondOnAlias("", jf, fb, childType)
		rolePrefix := ""
		if pRole != "" {
			rolePrefix = pRole + " AND "
		}
		disjuncts = append(disjuncts, fmt.Sprintf(
			"(%s`_id` IN (SELECT DISTINCT CAST(%s['parent'] AS STRING) FROM `base_matched` WHERE (%s) AND CAST(%s['name'] AS STRING) = %s AND %s['parent'] IS NOT NULL))",
			rolePrefix, cExpr, cWhere, cExpr, quoteStr(childType), cExpr,
		))
	}
	if len(disjuncts) == 1 {
		return disjuncts[0]
	}
	return "(" + strings.Join(disjuncts, " OR ") + ")"
}

// appendRound62TopLevelAggBranch handles Round-62 top-level bucket aggregations (`ip_prefix`,
// `time_series`, `random_sampler`, `sampler`/`diversified_sampler`, `children`, `parent`).
func (t *Transpiler) appendRound62TopLevelAggBranch(
	branches *[]string,
	subIdx *int,
	fullAggName string,
	extraWhere string,
	wherePrefix string,
	spec esast.AggSpec,
) bool {
	if t.appendRound63TopLevelAggBranch(branches, subIdx, fullAggName, extraWhere, wherePrefix, spec) {
		return true
	}
	switch {
	case spec.RandomSampler != nil:
		rsWhere := buildRandomSamplerWhereSQL(spec.RandomSampler, extraWhere)
		wClause := ""
		if rsWhere != "" && rsWhere != "TRUE" {
			wClause = " WHERE " + rsWhere
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_sampler' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
			quoteStr(fullAggName), t.sqlDocCountSumExpr(), wClause,
		))
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			nextExtra := ""
			if rsWhere != "TRUE" {
				nextExtra = rsWhere
			}
			t.appendAggBranches(branches, subIdx, fullAggName, nextExtra, subAggs)
		}
		return true

	case spec.EffectiveSampler() != nil:
		samp := spec.EffectiveSampler()
		sampWhere := t.buildSamplerSubqueryWhereSQL(samp, extraWhere, t.activeMainScoreSQL)
		wClause := ""
		if sampWhere != "" && sampWhere != "TRUE" {
			wClause = " WHERE " + sampWhere
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_sampler' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
			quoteStr(fullAggName), t.sqlDocCountSumExpr(), wClause,
		))
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			nextExtra := ""
			if sampWhere != "TRUE" {
				nextExtra = sampWhere
			}
			t.appendAggBranches(branches, subIdx, fullAggName, nextExtra, subAggs)
		}
		return true

	case spec.IPPrefix != nil:
		ipSpec := spec.IPPrefix
		ipField, b := t.resolveFieldInNestedCtx(ipSpec.Field, true, nil)
		*subIdx++
		if (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
			arrCol := b.EffectiveArrayColumn(true)
			keySQL, sortHexSQL, validCond := buildIPPrefixBucketKeySQL("`_elem`", ipSpec)
			fromExpr := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
			wCond := fmt.Sprintf("%s`_elem` IS NOT NULL AND %s", wherePrefix, validCond)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key`, %s ORDER BY %s ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keySQL, fromExpr, wCond, sortHexSQL, sortHexSQL, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				dedupIdx := *subIdx
				dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`",
					dedupIdx, keySQL, dedupIdx, fromExpr, wCond, dedupIdx, dedupIdx, dedupIdx)
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx), dedupFrom, "1=1", subAggs)
			}
		} else {
			col := t.sqlColumnRef(ipField, true, nil)
			keySQL, sortHexSQL, validCond := buildIPPrefixBucketKeySQL(col, ipSpec)
			wCond := fmt.Sprintf("%s%s IS NOT NULL AND %s", wherePrefix, col, validCond)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key`, %s ORDER BY %s ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keySQL, t.sqlDocCountSumExpr(), wCond, sortHexSQL, sortHexSQL, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keySQL, "`base_matched`", wCond, subAggs)
			}
		}
		return true

	case spec.TimeSeries != nil:
		tsSpec := spec.TimeSeries
		limit := tsSpec.EffectiveSize()
		if tsSpec.ShardSize != nil && *tsSpec.ShardSize > limit {
			limit = *tsSpec.ShardSize
		}
		if limit > t.maxAggBuckets() {
			limit = t.maxAggBuckets()
		}
		tsBucketExpr := "CONCAT(`__tsid`, '|', COALESCE(`__tsid_key`, '{}'))"
		tsSortExpr := sqlTSIDBinarySortExpr("`__tsid`")
		wCond := fmt.Sprintf("%s`__tsid` IS NOT NULL", wherePrefix)
		*subIdx++
		*branches = append(*branches, fmt.Sprintf(
			"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count`, %s AS `_ts_ord` "+
				"FROM `base_matched` WHERE %s "+
				"GROUP BY `__tsid`, `__tsid_key` ORDER BY %s ASC LIMIT %d"+
				") `_agg_sub_%d` ORDER BY `_ts_ord` ASC LIMIT %d",
			quoteStr(fullAggName), tsBucketExpr, t.sqlDocCountSumExpr(), tsSortExpr, wCond, tsSortExpr, limit, *subIdx, limit,
		))
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			// Restrict sub-aggregations to the top `limit` series selected by `time_series`.
			dedupIdx := *subIdx
			topSeriesFrom := fmt.Sprintf(
				"`base_matched` INNER JOIN (SELECT `__tsid` AS `_ts_id_%d`, %s AS `_ts_bkey_%d` FROM `base_matched` WHERE %s GROUP BY `__tsid`, `__tsid_key` ORDER BY %s ASC LIMIT %d) `_ts_top_%d` ON `base_matched`.`__tsid` = `_ts_top_%d`.`_ts_id_%d`",
				dedupIdx, tsBucketExpr, dedupIdx, wCond, tsSortExpr, limit, dedupIdx, dedupIdx, dedupIdx,
			)
			subWhere := "1=1"
			if extraWhere != "" {
				subWhere = extraWhere
			}
			t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_ts_bkey_%d`", dedupIdx), topSeriesFrom, subWhere, subAggs)
		}
		return true

	case spec.Children != nil:
		childWhere := t.buildChildrenAggWhereSQL(spec.Children.Type, extraWhere)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_children' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE %s",
			quoteStr(fullAggName), t.sqlDocCountSumExpr(), childWhere,
		))
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			t.appendAggBranches(branches, subIdx, fullAggName, childWhere, subAggs)
		}
		return true

	case spec.Parent != nil:
		parentWhere := t.buildParentAggWhereSQL(spec.Parent.Type, extraWhere)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_parent' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE %s",
			quoteStr(fullAggName), t.sqlDocCountSumExpr(), parentWhere,
		))
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			t.appendAggBranches(branches, subIdx, fullAggName, parentWhere, subAggs)
		}
		return true
	}
	return false
}

// appendRound62GroupedSubAggBranch handles Round-62 bucket sub-aggregations (`ip_prefix`, `time_series`,
// `children`, `parent`) nested inside a parent multi-bucket aggregation (`terms`, `histogram`, etc.).
func (t *Transpiler) appendRound62GroupedSubAggBranch(
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
	if t.appendRound63GroupedSubAggBranch(branches, subIdx, subFull, parentBucketExpr, fromClause, whereClause, subTableAlias, subElemAlias, nctx, subSpec) {
		return true
	}
	switch {
	case subSpec.IPPrefix != nil:
		ipSpec := subSpec.IPPrefix
		ipField, b := t.resolveFieldInNestedCtx(ipSpec.Field, true, nctx)
		*subIdx++
		if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
			arrCol := b.EffectiveArrayColumn(true)
			keySQL, sortHexSQL, validCond := buildIPPrefixBucketKeySQL(subElemAlias, ipSpec)
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s", whereClause, subElemAlias, validCond)
			combKey := fmt.Sprintf("CONCAT(CAST(%s AS STRING), '\\x1f', CAST(%s AS STRING))", parentBucketExpr, keySQL)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key`, %s ORDER BY %s ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), combKey, subFrom, subWhere, sortHexSQL, sortHexSQL, t.maxAggBuckets(), *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				dedupIdx := *subIdx
				dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`",
					dedupIdx, combKey, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx), dedupFrom, "1=1", nil, nestedSubs)
			}
		} else {
			col := t.sqlColumnRef(ipField, true, nctx)
			keySQL, sortHexSQL, validCond := buildIPPrefixBucketKeySQL(col, ipSpec)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s", whereClause, col, validCond)
			combKey := fmt.Sprintf("CONCAT(CAST(%s AS STRING), '\\x1f', CAST(%s AS STRING))", parentBucketExpr, keySQL)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count`, %s AS `_ts_ord` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key`, %s ORDER BY %s ASC LIMIT %d"+
					") `_agg_sub_%d` ORDER BY `_ts_ord` ASC LIMIT %d",
				quoteStr(subFull), combKey, t.sqlDocCountSumExpr(), sortHexSQL, fromClause, subWhere, sortHexSQL, sortHexSQL, t.maxAggBuckets(), *subIdx, t.maxAggBuckets(),
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, combKey, fromClause, subWhere, nctx, nestedSubs)
			}
		}
		return true

	case subSpec.TimeSeries != nil:
		tsSpec := subSpec.TimeSeries
		limit := tsSpec.EffectiveSize()
		if limit > t.maxAggBuckets() {
			limit = t.maxAggBuckets()
		}
		tsBucketExpr := "CONCAT(`__tsid`, '|', COALESCE(`__tsid_key`, '{}'))"
		combKey := fmt.Sprintf("CONCAT(CAST(%s AS STRING), '\\x1f', %s)", parentBucketExpr, tsBucketExpr)
		tsSortExpr := sqlTSIDBinarySortExpr("`__tsid`")
		subWhere := fmt.Sprintf("(%s) AND `__tsid` IS NOT NULL", whereClause)
		*subIdx++
		*branches = append(*branches, fmt.Sprintf(
			"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count`, %s AS `_ts_ord` "+
				"FROM %s WHERE %s "+
				"GROUP BY `_bucket_key`, `__tsid` ORDER BY %s ASC LIMIT %d"+
				") `_agg_sub_%d` ORDER BY `_ts_ord` ASC LIMIT %d",
			quoteStr(subFull), combKey, t.sqlDocCountSumExpr(), tsSortExpr, fromClause, subWhere, tsSortExpr, limit*100, *subIdx, limit*100,
		))
		if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
			t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, combKey, fromClause, subWhere, nctx, nestedSubs)
		}
		return true

	case subSpec.Children != nil:
		childType := subSpec.Children.Type
		var joinFields []string
		if t.Schema != nil {
			for fname, fb := range t.Schema.Fields {
				if fb.ESType == "join" && joinFieldHasChild(fb, childType) {
					joinFields = append(joinFields, fname)
				}
			}
		}
		if len(joinFields) == 0 {
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, CAST(0 AS DOUBLE) AS `_doc_count` FROM %s WHERE FALSE GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause,
			))
			return true
		}
		sort.Strings(joinFields)
		*subIdx++
		jIdx := *subIdx
		var onDisj, pRoles []string
		for _, jf := range joinFields {
			fb := t.Schema.Fields[jf]
			cDoc := joinFieldDocExprOnAlias("`base_matched`", jf)
			onDisj = append(onDisj, fmt.Sprintf("(CAST(%s['name'] AS STRING) = %s AND CAST(%s['parent'] AS STRING) = `_jp_%d`.`_jp_id_%d`)",
				cDoc, quoteStr(childType), cDoc, jIdx, jIdx))
			if pr := joinParentRoleCondOnAlias("", jf, fb, childType); pr != "" {
				pRoles = append(pRoles, pr)
			}
		}
		pWhere := whereClause
		if len(pRoles) > 0 {
			pWhere = fmt.Sprintf("(%s) AND (%s)", whereClause, strings.Join(pRoles, " OR "))
		}
		joinFrom := fmt.Sprintf(
			"`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_jp_id_%d`, CAST(%s AS STRING) AS `_jp_bkey_%d` FROM %s WHERE %s) `_jp_%d` ON (%s)",
			jIdx, parentBucketExpr, jIdx, fromClause, pWhere, jIdx, strings.Join(onDisj, " OR "),
		)
		bKeyCol := fmt.Sprintf("`_jp_%d`.`_jp_bkey_%d`", jIdx, jIdx)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `base_matched`.`_id`) AS DOUBLE) AS `_doc_count` "+
				"FROM %s WHERE 1=1 GROUP BY `_bucket_key`",
			quoteStr(subFull), bKeyCol, joinFrom,
		))
		if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
			dedupFrom := fmt.Sprintf(
				"`base_matched` INNER JOIN (SELECT DISTINCT `base_matched`.`_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`",
				jIdx, bKeyCol, jIdx, joinFrom, jIdx, jIdx, jIdx,
			)
			t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, fmt.Sprintf("`_rn_bkey_%d`", jIdx), dedupFrom, "1=1", nil, nestedSubs)
		}
		return true

	case subSpec.Parent != nil:
		childType := subSpec.Parent.Type
		var joinFields []string
		if t.Schema != nil {
			for fname, fb := range t.Schema.Fields {
				if fb.ESType == "join" && joinFieldHasChild(fb, childType) {
					joinFields = append(joinFields, fname)
				}
			}
		}
		if len(joinFields) == 0 {
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, CAST(0 AS DOUBLE) AS `_doc_count` FROM %s WHERE FALSE GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause,
			))
			return true
		}
		sort.Strings(joinFields)
		*subIdx++
		jIdx := *subIdx
		jf0 := joinFields[0]
		cDoc0 := joinFieldDocExprOnAlias("", jf0)
		var cConds, pRoles []string
		for _, jf := range joinFields {
			fb := t.Schema.Fields[jf]
			cDoc := joinFieldDocExprOnAlias("", jf)
			cConds = append(cConds, fmt.Sprintf("(CAST(%s['name'] AS STRING) = %s AND %s['parent'] IS NOT NULL)", cDoc, quoteStr(childType), cDoc))
			if pr := joinParentRoleCondOnAlias("`base_matched`", jf, fb, childType); pr != "" {
				pRoles = append(pRoles, pr)
			}
		}
		cWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, strings.Join(cConds, " OR "))
		pRoleCond := "1=1"
		if len(pRoles) > 0 {
			pRoleCond = "(" + strings.Join(pRoles, " OR ") + ")"
		}
		joinFrom := fmt.Sprintf(
			"`base_matched` INNER JOIN (SELECT DISTINCT CAST(%s['parent'] AS STRING) AS `_jc_pid_%d`, CAST(%s AS STRING) AS `_jc_bkey_%d` FROM %s WHERE %s) `_jc_%d` ON `base_matched`.`_id` = `_jc_%d`.`_jc_pid_%d`",
			cDoc0, jIdx, parentBucketExpr, jIdx, fromClause, cWhere, jIdx, jIdx, jIdx,
		)
		bKeyCol := fmt.Sprintf("`_jc_%d`.`_jc_bkey_%d`", jIdx, jIdx)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `base_matched`.`_id`) AS DOUBLE) AS `_doc_count` "+
				"FROM %s WHERE %s GROUP BY `_bucket_key`",
			quoteStr(subFull), bKeyCol, joinFrom, pRoleCond,
		))
		if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
			dedupFrom := fmt.Sprintf(
				"`base_matched` INNER JOIN (SELECT DISTINCT `base_matched`.`_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`",
				jIdx, bKeyCol, jIdx, joinFrom, pRoleCond, jIdx, jIdx, jIdx,
			)
			t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, fmt.Sprintf("`_rn_bkey_%d`", jIdx), dedupFrom, "1=1", nil, nestedSubs)
		}
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// F18: `search.allow_expensive_queries == false` Validation (`320_disallow_queries.yml`)
// ----------------------------------------------------------------------------

// validateDisallowExpensiveQueries rejects expensive query types when `TranspilerOptions.DisallowExpensiveQueries`
// (`search.allow_expensive_queries: false`) is active, matching `search/320_disallow_queries.yml` and `parent-join/*`.
func (t *Transpiler) validateDisallowExpensiveQueries(req *esast.SearchRequest) error {
	if !t.Opts.DisallowExpensiveQueries || req == nil {
		return nil
	}
	if len(req.ScriptFields) > 0 {
		return esTranspilerError("query_shard_exception: [script] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
	}
	if err := t.checkExpensiveQueryNode(req.Query, nil); err != nil {
		return err
	}
	if err := t.checkExpensiveQueryNode(req.PostFilter, nil); err != nil {
		return err
	}
	if err := t.checkExpensiveQueryNode(req.AliasFilter, nil); err != nil {
		return err
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil {
			if err := t.checkExpensiveQueryNode(req.Rescore[i].Query.RescoreQuery, nil); err != nil {
				return err
			}
		}
	}
	return t.checkExpensiveAggQueries(req.EffectiveAggs(), nil)
}

func (t *Transpiler) checkExpensiveAggQueries(aggs map[string]esast.AggSpec, nctx *nestedCtx) error {
	for _, spec := range aggs {
		if spec.Filter != nil {
			if err := t.checkExpensiveQueryNode(spec.Filter, nctx); err != nil {
				return err
			}
		}
		if spec.Filters != nil {
			for _, fq := range spec.Filters.Filters {
				fqCopy := fq
				if err := t.checkExpensiveQueryNode(&fqCopy, nctx); err != nil {
					return err
				}
			}
			for i := range spec.Filters.AnonymousFilters {
				if err := t.checkExpensiveQueryNode(&spec.Filters.AnonymousFilters[i], nctx); err != nil {
					return err
				}
			}
		}
		if spec.Children != nil || spec.Parent != nil || spec.Nested != nil {
			return esTranspilerError("query_shard_exception: [joining] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
		if err := t.checkExpensiveAggQueries(spec.SubAggs(), nctx); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transpiler) isPrefixOptimisedField(rawField string, nctx *nestedCtx) bool {
	clean, _ := parseFieldBoost(rawField, 1.0)
	resolved, b := t.resolveFieldInNestedCtx(clean, false, nctx)
	if b.ESType == "search_as_you_type" || b.IsVirtualSAYTSubfield {
		return true
	}
	if (b.ESType == "text" || b.ESType == "match_only_text") && t.fieldHasIndexPrefixes(resolved, b) {
		return true
	}
	return false
}

func (t *Transpiler) isWildcardFieldType(rawField string, nctx *nestedCtx) bool {
	clean, _ := parseFieldBoost(rawField, 1.0)
	if strings.ContainsAny(clean, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(clean, nctx)
		if len(exp) == 0 {
			return false
		}
		for _, bf := range exp {
			_, fb := t.resolveFieldInNestedCtx(bf.Field, true, nctx)
			if fb.ESType != "wildcard" {
				return false
			}
		}
		return true
	}
	_, b := t.resolveFieldInNestedCtx(clean, true, nctx)
	return b.ESType == "wildcard"
}

func hasNonZeroFuzziness(fuzz any) bool {
	if fuzz == nil {
		return false
	}
	switch v := fuzz.(type) {
	case int:
		return v > 0
	case int64:
		return v > 0
	case float64:
		return v > 0
	case json.Number:
		f, err := v.Float64()
		return err == nil && f > 0
	case string:
		s := strings.TrimSpace(v)
		return s != "" && s != "0"
	default:
		return true
	}
}

func (t *Transpiler) checkExpensiveQueryNode(q *esast.Query, nctx *nestedCtx) error {
	if q == nil {
		return nil
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		return t.checkExpensiveQueryNode(q.Wrapper.Decoded, nctx)
	}
	if q.Nested != nil || q.HasChild != nil || q.HasParent != nil {
		return esTranspilerError("query_shard_exception: [joining] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
	}
	if q.Script != nil || q.ScriptScore != nil {
		return esTranspilerError("query_shard_exception: [script] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
	}
	if len(q.Fuzzy) > 0 {
		return esTranspilerError("query_shard_exception: [fuzzy] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
	}
	for _, me := range q.Match {
		if hasNonZeroFuzziness(me.Fuzziness) {
			return esTranspilerError("query_shard_exception: [fuzzy] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
	}
	for _, pe := range q.MatchBoolPrefix {
		if hasNonZeroFuzziness(pe.Fuzziness) {
			return esTranspilerError("query_shard_exception: [fuzzy] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
		// MatchBoolPrefix also executes a trailing prefix query unless single-token fuzzy-free on index_prefixes/SAYT.
		for field := range q.MatchBoolPrefix {
			if !t.isPrefixOptimisedField(field, nctx) {
				return esTranspilerError("query_shard_exception: [prefix] queries cannot be executed when 'search.allow_expensive_queries' is set to false. For optimised prefix queries on text fields please enable [index_prefixes].")
			}
		}
	}
	if q.MultiMatch != nil {
		if hasNonZeroFuzziness(q.MultiMatch.Fuzziness) {
			return esTranspilerError("query_shard_exception: [fuzzy] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
		if strings.EqualFold(q.MultiMatch.Type, "bool_prefix") {
			fields := q.MultiMatch.Fields
			for _, f := range fields {
				if !t.isPrefixOptimisedField(f, nctx) {
					return esTranspilerError("query_shard_exception: [prefix] queries cannot be executed when 'search.allow_expensive_queries' is set to false. For optimised prefix queries on text fields please enable [index_prefixes].")
				}
			}
		}
	}
	for field := range q.Prefix {
		if !t.isPrefixOptimisedField(field, nctx) {
			return esTranspilerError("query_shard_exception: [prefix] queries cannot be executed when 'search.allow_expensive_queries' is set to false. For optimised prefix queries on text fields please enable [index_prefixes].")
		}
	}
	for field := range q.Wildcard {
		if !t.isWildcardFieldType(field, nctx) {
			return esTranspilerError("query_shard_exception: [wildcard] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
	}
	for field := range q.Regexp {
		if !t.isWildcardFieldType(field, nctx) {
			return esTranspilerError("query_shard_exception: [regexp] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
	}
	for field := range q.Range {
		clean, _ := parseFieldBoost(field, 1.0)
		_, b := t.resolveFieldInNestedCtx(clean, false, nctx)
		switch b.ESType {
		case "text", "match_only_text", "keyword", "constant_keyword", "wildcard", "search_as_you_type":
			return esTranspilerError("query_shard_exception: [range] queries on [text] or [keyword] fields cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
	}
	for _, qs := range []*esast.QueryStringQuery{q.QueryString, q.SimpleQueryString} {
		if qs == nil {
			continue
		}
		if err := t.checkExpensiveQueryString(qs, q.SimpleQueryString == qs, nctx); err != nil {
			return err
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if err := t.checkExpensiveQueryNode(&q.Bool.Must[i], nctx); err != nil {
				return err
			}
		}
		for i := range q.Bool.Filter {
			if err := t.checkExpensiveQueryNode(&q.Bool.Filter[i], nctx); err != nil {
				return err
			}
		}
		for i := range q.Bool.Should {
			if err := t.checkExpensiveQueryNode(&q.Bool.Should[i], nctx); err != nil {
				return err
			}
		}
		for i := range q.Bool.MustNot {
			if err := t.checkExpensiveQueryNode(&q.Bool.MustNot[i], nctx); err != nil {
				return err
			}
		}
	}
	if q.ConstantScore != nil {
		if err := t.checkExpensiveQueryNode(&q.ConstantScore.Filter, nctx); err != nil {
			return err
		}
	}
	if q.Boosting != nil {
		if err := t.checkExpensiveQueryNode(&q.Boosting.Positive, nctx); err != nil {
			return err
		}
		if err := t.checkExpensiveQueryNode(&q.Boosting.Negative, nctx); err != nil {
			return err
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if err := t.checkExpensiveQueryNode(&q.DisMax.Queries[i], nctx); err != nil {
				return err
			}
		}
	}
	if q.FunctionScore != nil {
		if err := t.checkExpensiveQueryNode(q.FunctionScore.Query, nctx); err != nil {
			return err
		}
		if q.FunctionScore.ScriptScore != nil {
			return esTranspilerError("query_shard_exception: [script] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
		}
		for i := range q.FunctionScore.Functions {
			if q.FunctionScore.Functions[i].ScriptScore != nil {
				return esTranspilerError("query_shard_exception: [script] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
			if err := t.checkExpensiveQueryNode(q.FunctionScore.Functions[i].Filter, nctx); err != nil {
				return err
			}
		}
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		if err := t.checkExpensiveQueryNode(q.Pinned.Organic, nctx); err != nil {
			return err
		}
	}
	if q.SpanMulti != nil && q.SpanMulti.Match != nil {
		if err := t.checkExpensiveQueryNode(q.SpanMulti.Match, nctx); err != nil {
			return err
		}
	}
	return nil
}

var (
	reQSFieldRegexp  = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.*-]+):/[^/]+/`)
	reQSBareRegexp   = regexp.MustCompile(`(?:^|\s)/[^/]+/`)
	reQSFieldFuzzy   = regexp.MustCompile(`([A-Za-z0-9_.*-]+):[^\s~]+~[0-9]*`)
	reQSBareFuzzy    = regexp.MustCompile(`[^\s:~]+~[0-9]*(?:\s|$)`)
	reQSFieldRange   = regexp.MustCompile(`([A-Za-z0-9_.*-]+):\s*[\[\{][^\[\]\{\}]+[\]\}]`)
	reQSFieldWildPfx = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.*-]+):([^\s()]+)`)
)

func (t *Transpiler) checkExpensiveQueryString(qs *esast.QueryStringQuery, isSimple bool, nctx *nestedCtx) error {
	raw := strings.TrimSpace(qs.Query)
	if raw == "" {
		return nil
	}
	defaultFields := qs.Fields
	if len(defaultFields) == 0 && qs.DefaultField != "" {
		defaultFields = []string{qs.DefaultField}
	}
	if !isSimple {
		if m := reQSFieldRegexp.FindStringSubmatch(raw); m != nil {
			if !t.isWildcardFieldType(m[1], nctx) {
				return esTranspilerError("query_shard_exception: [regexp] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
		} else if reQSBareRegexp.MatchString(raw) {
			allWild := len(defaultFields) > 0
			for _, df := range defaultFields {
				if !t.isWildcardFieldType(df, nctx) {
					allWild = false
					break
				}
			}
			if !allWild {
				return esTranspilerError("query_shard_exception: [regexp] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
		}
		for _, m := range reQSFieldRange.FindAllStringSubmatch(raw, -1) {
			clean, _ := parseFieldBoost(m[1], 1.0)
			_, b := t.resolveFieldInNestedCtx(clean, false, nctx)
			switch b.ESType {
			case "text", "match_only_text", "keyword", "constant_keyword", "wildcard", "search_as_you_type":
				return esTranspilerError("query_shard_exception: [range] queries on [text] or [keyword] fields cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
		}
	}
	if reQSFieldFuzzy.MatchString(raw) || reQSBareFuzzy.MatchString(raw) {
		return esTranspilerError("query_shard_exception: [fuzzy] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
	}
	allowWildcard := qs.AnalyzeWildcard == nil || *qs.AnalyzeWildcard || isSimple
	_ = allowWildcard
	for _, m := range reQSFieldWildPfx.FindAllStringSubmatch(raw, -1) {
		fld, term := m[1], m[2]
		if strings.HasPrefix(term, "/") || strings.HasPrefix(term, "[") || strings.HasPrefix(term, "{") || strings.HasPrefix(term, "\"") {
			continue
		}
		if strings.HasSuffix(term, "*") && !strings.ContainsAny(term[:len(term)-1], "*?") && len(term) > 1 {
			if !t.isPrefixOptimisedField(fld, nctx) && !t.isWildcardFieldType(fld, nctx) {
				return esTranspilerError("query_shard_exception: [prefix] queries cannot be executed when 'search.allow_expensive_queries' is set to false. For optimised prefix queries on text fields please enable [index_prefixes].")
			}
		} else if strings.ContainsAny(term, "*?") && term != "*" {
			if !t.isWildcardFieldType(fld, nctx) {
				return esTranspilerError("query_shard_exception: [wildcard] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
		}
	}
	// Bare prefix / wildcard terms without field qualifier
	for _, tok := range strings.Fields(raw) {
		if strings.Contains(tok, ":") || strings.HasPrefix(tok, "\"") || tok == "*" || tok == "AND" || tok == "OR" || tok == "NOT" {
			continue
		}
		if strings.HasSuffix(tok, "*") && !strings.ContainsAny(tok[:len(tok)-1], "*?") && len(tok) > 1 {
			allOpt := len(defaultFields) > 0
			for _, df := range defaultFields {
				if !t.isPrefixOptimisedField(df, nctx) && !t.isWildcardFieldType(df, nctx) {
					allOpt = false
					break
				}
			}
			if !allOpt {
				return esTranspilerError("query_shard_exception: [prefix] queries cannot be executed when 'search.allow_expensive_queries' is set to false. For optimised prefix queries on text fields please enable [index_prefixes].")
			}
		} else if strings.ContainsAny(tok, "*?") {
			allWild := len(defaultFields) > 0
			for _, df := range defaultFields {
				if !t.isWildcardFieldType(df, nctx) {
					allWild = false
					break
				}
			}
			if !allWild {
				return esTranspilerError("query_shard_exception: [wildcard] queries cannot be executed when 'search.allow_expensive_queries' is set to false.")
			}
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// F17: Mapper-Extras (`search_as_you_type`, `match_only_text`, `rank_feature`, `scaled_float`)
// ----------------------------------------------------------------------------

// compileSAYTIndexPrefixTerm compiles `term` on `<field>._index_prefix` (`b.IsVirtualSAYTSubfield == true`).
// Edge n-grams up to 20 chars are materialized in `f__<field>___index_prefix` (`ARRAY<STRING>`);
// values longer than 20 runes fall back to prefix matching on the `_3gram` / root column.
func (t *Transpiler) compileSAYTIndexPrefixTerm(origField string, b schema.FieldBinding, val any, caseInsensitive bool, nctx *nestedCtx) string {
	valStr := fmt.Sprintf("%v", val)
	if val == nil || valStr == "" {
		return "FALSE"
	}
	rootField := strings.TrimSuffix(origField, "._index_prefix")
	_, rootB := t.resolveFieldInNestedCtx(rootField, false, nctx)
	effLower := b.EffectiveLowercase(false) || rootB.EffectiveLowercase(false)
	normVal := t.normalizeKeywordOrAnalyzerTerm(valStr, rootB, effLower || caseInsensitive)

	arrCol := b.EffectiveArrayColumn(false)
	if arrCol != "" && utf8.RuneCountInString(normVal) <= 20 && nctx == nil {
		if caseInsensitive && !effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(normVal), arrCol)
		}
		return fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(normVal))
	}
	return t.compileSAYTRootPrefix(rootField, rootB, valStr, caseInsensitive, nctx)
}

// compileSAYTRootPrefix compiles `prefix` on a root `search_as_you_type` field (`search-as-you-type/10_basic.yml`),
// routing to its `._index_prefix` `ARRAY<STRING>` column when `<= 20` runes or falling back to shingle/token-boundary
// prefix matching so multi-word infix prefixes (e.g. `"brown fo"` in `"quick brown fox"`) match accurately.
func (t *Transpiler) compileSAYTRootPrefix(field string, b schema.FieldBinding, val string, caseInsensitive bool, nctx *nestedCtx) string {
	if val == "" {
		return t.compileExistsPredicate(field, nctx)
	}
	effAn := t.effectiveQueryAnalyzerName(b, "")
	isWS := strings.EqualFold(effAn, "whitespace")
	wantCI := caseInsensitive || !isWS
	checkVal := val
	if !isWS {
		checkVal = strings.ToLower(val)
	}

	if nctx == nil && t.Schema != nil {
		idxPfxField := field + "._index_prefix"
		if pfxB, ok := t.Schema.Fields[idxPfxField]; ok && pfxB.EffectiveArrayColumn(false) != "" {
			arrCol := pfxB.EffectiveArrayColumn(false)
			if utf8.RuneCountInString(checkVal) <= 20 {
				if wantCI && isWS {
					return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(val), arrCol)
				}
				return fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(checkVal))
			}
			// Longer than 20 runes: check `._3gram` / `._4gram` / root regex prefix!
			for _, sfx := range []string{"._4gram", "._3gram", "._2gram"} {
				if shB, okSh := t.Schema.Fields[field+sfx]; okSh && shB.EffectiveArrayColumn(false) != "" {
					shCol := shB.EffectiveArrayColumn(false)
					likePat := quoteStr(escapeLikeLiteral(checkVal) + "%")
					if wantCI {
						return fmt.Sprintf("(%s OR array_exists(_x -> lower(_x) LIKE lower(%s), `%s`))",
							t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, val, wantCI, nctx), likePat, shCol)
					}
					return fmt.Sprintf("(%s OR array_exists(_x -> _x LIKE %s, `%s`))",
						t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, val, wantCI, nctx), likePat, shCol)
				}
			}
		}
	}
	return t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, val, wantCI, nctx)
}

// compileAnalyzedTokenOrPhrasePrefixRegex compiles a token-boundary prefix (or multi-token phrase prefix)
// regex predicate for analyzed `text`, `match_only_text`, and `search_as_you_type` fields.
func (t *Transpiler) compileAnalyzedTokenOrPhrasePrefixRegex(field string, b schema.FieldBinding, rawPrefix string, caseInsensitive bool, nctx *nestedCtx) string {
	effAn := t.effectiveQueryAnalyzerName(b, "")
	isWS := strings.EqualFold(effAn, "whitespace")
	ciFlag := "(?i)"
	if isWS && !caseInsensitive {
		ciFlag = ""
	}
	sep := "[^[:alnum:]_]+"
	startBoundary := "(^|[^[:alnum:]_])"
	if isWS {
		sep = "[[:space:]]+"
		startBoundary = "(^|[[:space:]])"
	}

	var parts []string
	if strings.ContainsAny(rawPrefix, " \t\r\n") {
		toks := TokenizeByAnalyzer(rawPrefix, effAn)
		for _, tk := range toks {
			parts = append(parts, regexp.QuoteMeta(tk))
		}
	} else {
		p := rawPrefix
		if !isWS || caseInsensitive {
			p = strings.ToLower(p)
		}
		parts = []string{regexp.QuoteMeta(p)}
	}
	if len(parts) == 0 {
		return "FALSE"
	}
	rePat := fmt.Sprintf("%s%s(%s)", ciFlag, startBoundary, strings.Join(parts, sep))
	qPat := quoteStr(rePat)

	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", qPat, arrCol)
	}
	col := t.sqlColumnRef(field, false, nctx)
	return fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, qPat)
}

// compileAnalyzedFieldPrefix handles `prefix` queries on analyzed `text` (including `index_prefixes`),
// `match_only_text`, and `search_as_you_type` fields (`match_only_text/10_basic.yml`, `190_index_prefix_search.yml`).
func (t *Transpiler) compileAnalyzedFieldPrefix(origField string, val string, caseInsensitive bool, nctx *nestedCtx) (string, bool) {
	if strings.HasSuffix(origField, ".keyword") {
		return "", false
	}
	rawField, rawB := t.resolveFieldInNestedCtx(origField, false, nctx)
	if rawB.AliasTarget != "" && strings.HasSuffix(rawB.AliasTarget, ".keyword") {
		return "", false
	}
	if rawB.ESType == "search_as_you_type" && !rawB.IsVirtualSAYTSubfield {
		if !t.checkFieldSearchable(rawField, rawB) || t.isNonStandardQueryRestrictedField(origField, rawB, "prefix") {
			return "FALSE", true
		}
		return t.compileSAYTRootPrefix(rawField, rawB, val, caseInsensitive, nctx), true
	}
	// Pure analyzed `match_only_text` or `text` without `.keyword` companion (or with `index_prefixes` enabled):
	if rawB.ESType == "match_only_text" || (rawB.ESType == "text" && (rawB.KeywordCompanion == "" || t.fieldHasIndexPrefixes(rawField, rawB))) {
		effAn := t.effectiveQueryAnalyzerName(rawB, "")
		if strings.EqualFold(effAn, "keyword") {
			return "", false
		}
		if !t.checkFieldSearchable(rawField, rawB) || t.isNonStandardQueryRestrictedField(origField, rawB, "prefix") {
			return "FALSE", true
		}
		if val == "" {
			return t.compileExistsPredicate(rawField, nctx), true
		}
		wantCI := caseInsensitive || !strings.EqualFold(effAn, "whitespace")
		return t.compileAnalyzedTokenOrPhrasePrefixRegex(rawField, rawB, val, wantCI, nctx), true
	}
	return "", false
}

// checkSpanFieldNotMatchOnlyText rejects `span_*` queries on `match_only_text` fields (`match_only_text/10_basic.yml`).
func (t *Transpiler) checkSpanFieldNotMatchOnlyText(field string, b schema.FieldBinding) bool {
	if b.ESType == "match_only_text" {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError(fmt.Sprintf("query_shard_exception: Cannot use [span] queries on [match_only_text] field [%s] — positions are not indexed", field))
		}
		return false
	}
	return true
}

func spanMultiTargetFields(q *esast.Query) []string {
	if q == nil {
		return nil
	}
	var out []string
	for k := range q.Prefix {
		out = append(out, k)
	}
	for k := range q.Wildcard {
		out = append(out, k)
	}
	for k := range q.Regexp {
		out = append(out, k)
	}
	for k := range q.Fuzzy {
		out = append(out, k)
	}
	for k := range q.Term {
		out = append(out, k)
	}
	if q.Terms != nil {
		for k := range q.Terms.Fields {
			out = append(out, k)
		}
	}
	for k := range q.Range {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (t *Transpiler) lookupMappedFieldProperty(field string, b schema.FieldBinding) (esast.FieldProperty, bool) {
	if t.Schema == nil || t.Schema.RawMapping == nil {
		return esast.FieldProperty{}, false
	}
	lookup := strings.TrimSpace(field)
	if b.AliasTarget != "" {
		lookup = b.AliasTarget
	} else if lookup == "" && b.ESFieldPath != "" {
		lookup = b.ESFieldPath
	}
	if lookup == "" {
		return esast.FieldProperty{}, false
	}
	return lookupFieldPropertyByPath(t.Schema.RawMapping.Properties, strings.Split(lookup, "."))
}

func (t *Transpiler) fieldHasIndexPrefixes(field string, b schema.FieldBinding) bool {
	fp, ok := t.lookupMappedFieldProperty(field, b)
	return ok && fp.IndexPrefixes != nil
}

func (t *Transpiler) effectiveAnalysisConfig() *analysis.IndexAnalysisConfig {
	if t == nil {
		return nil
	}
	if t.Opts.AnalysisConfig != nil {
		return t.Opts.AnalysisConfig
	}
	if t.Schema != nil {
		return t.Schema.AnalysisConfig
	}
	return nil
}

func (t *Transpiler) fieldNormalizerName(field string, b schema.FieldBinding) string {
	if fp, ok := t.lookupMappedFieldProperty(field, b); ok && strings.TrimSpace(fp.Normalizer) != "" {
		return strings.TrimSpace(fp.Normalizer)
	}
	return strings.TrimSpace(b.NormalizerName)
}

// resolveRankFeatureBindingAndNullValue resolves a `rank_feature` or `rank_features.<token>` field
// (inheriting parent `rank_features` `positive_score_impact` when querying `<field>.<feature>`!)
// and extracts any mapped `null_value` (`rank_feature/10_basic.yml`, `rank_features/10_basic.yml`).
func (t *Transpiler) resolveRankFeatureBindingAndNullValue(rawField string, nctx *nestedCtx) (resolved string, b schema.FieldBinding, nullVal *float64) {
	resolved, b = t.resolveFieldInNestedCtx(rawField, false, nctx)
	if t.Schema == nil {
		return resolved, b, nil
	}
	lookupField := resolved
	if b.AliasTarget != "" {
		lookupField = b.AliasTarget
	}
	if b.ESType == "" || (b.ESType == "rank_features" && b.PositiveScoreImpact == nil) {
		// Check parent `rank_features` mapping for dotted feature keys like `negative_reviews.1star`.
		for idx := strings.LastIndexByte(lookupField, '.'); idx > 0; idx = strings.LastIndexByte(lookupField[:idx], '.') {
			parentPath := lookupField[:idx]
			if pb, ok := t.Schema.Fields[parentPath]; ok && pb.ESType == "rank_features" {
				b.ESType = "rank_features"
				if pb.PositiveScoreImpact != nil {
					b.PositiveScoreImpact = pb.PositiveScoreImpact
				}
			}
			if t.Schema.RawMapping != nil {
				if pProp, ok := lookupFieldPropertyByPath(t.Schema.RawMapping.Properties, strings.Split(parentPath, ".")); ok && strings.EqualFold(strings.TrimSpace(pProp.Type), "rank_features") {
					b.ESType = "rank_features"
					if pProp.PositiveScoreImpact != nil {
						b.PositiveScoreImpact = pProp.PositiveScoreImpact
					}
					break
				}
			}
			if b.ESType == "rank_features" {
				break
			}
		}
	}
	if t.Schema.RawMapping != nil {
		if prop, ok := lookupFieldPropertyByPath(t.Schema.RawMapping.Properties, strings.Split(lookupField, ".")); ok {
			if nv, err := prop.RankFeatureNullValue(); err == nil && nv != nil && *nv > 0 {
				nullVal = nv
			}
		}
	}
	return resolved, b, nullVal
}

func lookupFieldPropertyByPath(props map[string]esast.FieldProperty, parts []string) (esast.FieldProperty, bool) {
	if len(parts) == 0 || len(props) == 0 {
		return esast.FieldProperty{}, false
	}
	full := strings.Join(parts, ".")
	if fp, ok := props[full]; ok {
		return fp, true
	}
	head := parts[0]
	fp, ok := props[head]
	if !ok {
		return esast.FieldProperty{}, false
	}
	if len(parts) == 1 {
		return fp, true
	}
	if sub, okP := lookupFieldPropertyByPath(fp.Properties, parts[1:]); okP {
		return sub, true
	}
	if len(parts) == 2 && len(fp.Fields) > 0 {
		if mf, okF := fp.Fields[parts[1]]; okF {
			return mf, true
		}
	}
	return esast.FieldProperty{}, false
}

// ----------------------------------------------------------------------------
// F22: Scriptless Runtime Fields Doris `_source` `JSON_EXTRACT` Pushdown
// ----------------------------------------------------------------------------

// resolveScriptlessRuntimeField resolves `field` if it is a scriptless runtime field declared in
// `TranspilerOptions.RuntimeMappings` (search-request `runtime_mappings`) or `IndexSchema.RawMapping.Runtime`
// (index-level `mappings.runtime`), including sub-fields of `type: "composite"` runtime fields.
func (t *Transpiler) resolveScriptlessRuntimeField(field string) (esast.FieldProperty, string, bool) {
	if t.Schema != nil && t.Schema.IsRuntimeEvalSchema {
		return esast.FieldProperty{}, "", false
	}
	clean := strings.TrimSpace(field)
	if clean == "" || strings.HasPrefix(clean, "_") {
		return esast.FieldProperty{}, "", false
	}

	checkMap := func(rtMap map[string]esast.FieldProperty, shadowsMapped bool) (esast.FieldProperty, string, bool) {
		if len(rtMap) == 0 {
			return esast.FieldProperty{}, "", false
		}
		if !shadowsMapped && t.Schema != nil {
			if mb, ok := t.Schema.Fields[clean]; ok && mb.ESType != "" {
				return esast.FieldProperty{}, "", false
			}
		}
		if fp, ok := rtMap[clean]; ok {
			if fp.Script != nil || strings.EqualFold(strings.TrimSpace(fp.Type), "composite") {
				return esast.FieldProperty{}, "", false
			}
			effType := normalizeRuntimeESType(fp.Type)
			return fp, effType, effType != ""
		}
		// Check composite runtime parent `<root>.<subKey>` when parent has `Script == nil`.
		for idx := strings.IndexByte(clean, '.'); idx > 0; {
			root := clean[:idx]
			sub := clean[idx+1:]
			if parentFP, ok := rtMap[root]; ok && strings.EqualFold(strings.TrimSpace(parentFP.Type), "composite") && parentFP.Script == nil {
				if subFP, okSub := parentFP.Fields[sub]; okSub && subFP.Script == nil {
					effType := normalizeRuntimeESType(subFP.Type)
					return subFP, effType, effType != ""
				}
			}
			nextRel := strings.IndexByte(clean[idx+1:], '.')
			if nextRel < 0 {
				break
			}
			idx = idx + 1 + nextRel
		}
		return esast.FieldProperty{}, "", false
	}

	recordIfIndexScriptless := func() {
		if t.unindexedFields != nil && !strings.ContainsAny(clean, "*?") && t.Schema != nil && t.Schema.RawMapping != nil {
			if _, _, isIdxRT := checkMap(t.Schema.RawMapping.Runtime, false); isIdxRT {
				t.unindexedFields[strings.TrimSuffix(clean, ".keyword")] = true
			}
		}
	}

	if fp, effType, ok := checkMap(t.Opts.RuntimeMappings, true); ok {
		recordIfIndexScriptless()
		return fp, effType, true
	}
	if t.Schema != nil && t.Schema.RawMapping != nil {
		if fp, effType, ok := checkMap(t.Schema.RawMapping.Runtime, false); ok {
			recordIfIndexScriptless()
			return fp, effType, true
		}
	}
	return esast.FieldProperty{}, "", false
}

func normalizeRuntimeESType(rawType string) string {
	rt := strings.ToLower(strings.TrimSpace(rawType))
	switch rt {
	case "keyword", "constant_keyword", "wildcard":
		return "keyword"
	case "long", "integer", "short", "byte":
		return "long"
	case "double", "float", "half_float", "scaled_float":
		return "double"
	case "boolean":
		return "boolean"
	case "ip":
		return "ip"
	case "date", "date_nanos":
		return rt
	case "geo_point", "geo_shape":
		return rt
	default:
		return ""
	}
}

func runtimeFieldBinding(field, effType string, fp esast.FieldProperty) schema.FieldBinding {
	dt := schema.DorisVarchar
	switch effType {
	case "long", "date", "date_nanos":
		dt = schema.DorisBigInt
	case "double":
		dt = schema.DorisDouble
	case "boolean":
		dt = schema.DorisBoolean
	}
	return schema.FieldBinding{
		ESFieldPath: field,
		Kind:        schema.StorageDynamicVariant,
		DorisType:   dt,
		ESType:      effType,
		Format:      fp.Format,
	}
}

// sqlRuntimeSourceStringExpr extracts `field` from `_source` supporting both nested JSON objects
// (`$."a"."b"`) and literal dotted keys (`$."a.b"`), matching ES `SourceLookup.extractValue` semantics (`C-13`).
func sqlRuntimeSourceStringExpr(field string) string {
	nestedPath, dottedPath, hasDot := BuildQuotedDorisJSONPaths(field)
	if !hasDot {
		return fmt.Sprintf("json_extract_string(`_source`, %s)", quoteStr(nestedPath))
	}
	return fmt.Sprintf("COALESCE(json_extract_string(`_source`, %s), json_extract_string(`_source`, %s))",
		quoteStr(nestedPath), quoteStr(dottedPath))
}

func sqlRuntimeSourceTypedExpr(field, effType string) string {
	rawStr := sqlRuntimeSourceStringExpr(field)
	isArrayCond := sqlRuntimeSourceJSONTypeIsArrayExpr(field)
	// Strip single-element JSON array wrapper `["x"]` / `[123]` ONLY when `JSON_TYPE` is `'ARRAY'` (`C-08`).
	scalarStr := fmt.Sprintf(
		"CASE WHEN %s THEN CAST(element_at(TRY_CAST(%s AS ARRAY<STRING>), 1) AS STRING) ELSE %s END",
		isArrayCond, rawStr, rawStr,
	)
	switch effType {
	case "long":
		return fmt.Sprintf("TRY_CAST(%s AS BIGINT)", scalarStr)
	case "double":
		return fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", scalarStr)
	case "boolean":
		return fmt.Sprintf("CASE WHEN LOWER(%s) IN ('true', '1') THEN TRUE WHEN LOWER(%s) IN ('false', '0') THEN FALSE ELSE NULL END", scalarStr, scalarStr)
	case "date":
		return sqlRuntimeSourceDateMillisExpr(scalarStr)
	case "date_nanos":
		return sqlRuntimeSourceDateNanosExpr(scalarStr)
	default:
		return scalarStr
	}
}

func sqlRuntimeSourceArrayExpr(field string) string {
	rawStr := sqlRuntimeSourceStringExpr(field)
	isArrayCond := sqlRuntimeSourceJSONTypeIsArrayExpr(field)
	return fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN %s THEN TRY_CAST(%s AS ARRAY<STRING>) ELSE [%s] END",
		rawStr, isArrayCond, rawStr, rawStr)
}

// ----------------------------------------------------------------------------
// F20 & F19: Query-Time `pkg/analysis` Integration & `validate_query` Explain
// ----------------------------------------------------------------------------

func (t *Transpiler) effectiveQueryAnalyzerName(b schema.FieldBinding, explicitAnalyzer string) string {
	if exp := strings.TrimSpace(explicitAnalyzer); exp != "" {
		return exp
	}
	if cfg := t.effectiveAnalysisConfig(); cfg != nil {
		if resolved := strings.TrimSpace(cfg.ResolveSearchAnalyzer(b.Analyzer, b.SearchAnalyzer)); resolved != "" {
			return resolved
		}
	}
	if sa := strings.TrimSpace(b.SearchAnalyzer); sa != "" {
		return sa
	}
	if a := strings.TrimSpace(b.Analyzer); a != "" {
		return a
	}
	return "standard"
}

func (t *Transpiler) hasCustomQueryAnalysis(analyzerName string) bool {
	an := strings.TrimSpace(analyzerName)
	cfg := t.effectiveAnalysisConfig()
	if cfg == nil {
		if an == "" || !analysis.IsBuiltInAnalyzer(an) {
			return false
		}
		switch strings.ToLower(an) {
		case "standard", "simple", "whitespace", "keyword", "stop":
			return false
		default:
			return true
		}
	}
	if an == "" {
		_, hasDS := cfg.AnalyzerDefs["default_search"]
		_, hasD := cfg.AnalyzerDefs["default"]
		return hasDS || hasD
	}
	if _, ok := cfg.AnalyzerDefs[an]; ok {
		return true
	}
	// Also use `pkg/analysis` for built-in stemmer/language analyzers when `AnalysisConfig` is active.
	switch strings.ToLower(an) {
	case "standard", "simple", "whitespace", "keyword":
		return false
	default:
		return true
	}
}

func (t *Transpiler) normalizeKeywordOrAnalyzerTerm(raw string, b schema.FieldBinding, forceLower bool) string {
	normName := t.fieldNormalizerName(b.ESFieldPath, b)
	if cfg := t.effectiveAnalysisConfig(); normName != "" && cfg != nil {
		if norm, err := analysis.NormalizeTerm(raw, normName, cfg, t.Opts.AnalysisOpts); err == nil {
			if forceLower {
				return strings.ToLower(norm)
			}
			return norm
		}
	}
	if forceLower || b.EffectiveLowercase(true) {
		return strings.ToLower(raw)
	}
	return raw
}

func (t *Transpiler) singleAnalyzedTokenSQL(field string, b schema.FieldBinding, tok string, caseSensitive bool, boost float64, scoring bool, nctx *nestedCtx) CompiledQuery {
	return t.singleAnalyzedTokenWithFlagsR63(field, b, tok, caseSensitive, caseSensitive, boost, scoring, nctx)
}

func (t *Transpiler) singleAnalyzedTokenWithFlagsR63(field string, b schema.FieldBinding, tok string, caseSensitive, isWhitespace bool, boost float64, scoring bool, nctx *nestedCtx) CompiledQuery {
	if b.IsVirtualSAYTSubfield && b.EffectiveArrayColumn(false) != "" && nctx == nil {
		arrCol := b.EffectiveArrayColumn(false)
		var pred string
		if caseSensitive {
			pred = fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(tok))
		} else {
			pred = fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(tok), arrCol)
		}
		sc := "0.0"
		if scoring {
			sc = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", pred, strconv.FormatFloat(boost, 'g', -1, 64))
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: sc}
	}
	rePat := quoteStr(buildAnalyzedTokenRegexExactR63(tok, caseSensitive, isWhitespace))
	var safePred string
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		safePred = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol)
	} else {
		col := t.sqlColumnRef(field, false, nctx)
		safePred = fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat)
	}
	sc := "0.0"
	if scoring {
		sc = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", safePred, strconv.FormatFloat(boost, 'g', -1, 64))
		if bm25Sc, ok := t.compileBM25SingleTermScoreR63(field, field, b, tok, caseSensitive, boost, safePred, nctx); ok {
			sc = bm25Sc
		}
	}
	return CompiledQuery{WhereSQL: safePred, SafeWhereSQL: safePred, ScoreSQL: sc}
}

func (t *Transpiler) multiTokenExactPhraseSQL(field string, b schema.FieldBinding, terms []string, slop int, trailingPrefix bool, caseSensitive bool, boost float64, scoring bool, nctx *nestedCtx) CompiledQuery {
	if len(terms) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if len(terms) == 1 && !trailingPrefix {
		return t.singleAnalyzedTokenSQL(field, b, terms[0], caseSensitive, boost, scoring, nctx)
	}
	if len(terms) == 1 && trailingPrefix {
		pred := t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, terms[0], !caseSensitive, nctx)
		sc := "0.0"
		if scoring {
			sc = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", pred, strconv.FormatFloat(boost, 'g', -1, 64))
			if bm25Sc, ok := t.compileBM25PhraseScoreR63(field, field, b, terms, caseSensitive, boost, pred, nctx); ok {
				sc = bm25Sc
			}
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: sc}
	}

	// Sloppy phrase (>0): all terms must appear in the field (within slop token gaps).
	if slop > 0 && len(terms) > 1 {
		var parts []string
		limit := len(terms)
		if trailingPrefix {
			limit = len(terms) - 1
		}
		for i := 0; i < limit; i++ {
			parts = append(parts, t.singleAnalyzedTokenSQL(field, b, terms[i], caseSensitive, 1.0, false, nctx).WhereSQL)
		}
		if trailingPrefix {
			parts = append(parts, t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, terms[len(terms)-1], !caseSensitive, nctx))
		}
		pred := "(" + strings.Join(parts, " AND ") + ")"
		sc := "0.0"
		if scoring {
			sc = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", pred, strconv.FormatFloat(boost, 'g', -1, 64))
			if bm25Sc, ok := t.compileBM25PhraseScoreR63(field, field, b, terms, caseSensitive, boost, pred, nctx); ok {
				sc = bm25Sc
			}
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: sc}
	}

	ciFlag := "(?i)"
	if caseSensitive {
		ciFlag = ""
	}
	escaped := make([]string, len(terms))
	for i, tk := range terms {
		escaped[i] = regexp.QuoteMeta(tk)
	}
	endBoundary := "($|[^[:alnum:]_])"
	if trailingPrefix {
		endBoundary = ""
	}
	rePat := fmt.Sprintf("%s(^|[^[:alnum:]_])(%s)%s", ciFlag, strings.Join(escaped, "[^[:alnum:]_]+"), endBoundary)
	qPat := quoteStr(rePat)

	var pred string
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		pred = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", qPat, arrCol)
	} else {
		col := t.sqlColumnRef(field, false, nctx)
		pred = fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, qPat)
	}
	sc := "0.0"
	if scoring {
		sc = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", pred, strconv.FormatFloat(boost, 'g', -1, 64))
		if bm25Sc, ok := t.compileBM25PhraseScoreR63(field, field, b, terms, caseSensitive, boost, pred, nctx); ok {
			sc = bm25Sc
		}
	}
	return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: sc}
}

// compileMatchWithAnalysisGraph compiles `match` using `analysis.AnalyzeTokens` and `analysis.BuildQueryTokenGraph`
// when `effectiveAnalysisConfig()` defines a custom analyzer or built-in non-trivial analyzer (supporting
// `ngram`, `edge_ngram`, `snowball`, `synonym`, `synonym_graph`, `minimum_should_match`, and `zero_terms_query`).
func (t *Transpiler) compileMatchWithAnalysisGraph(
	origField string,
	queryStr string,
	operator string,
	explicitAnalyzer string,
	zeroTermsQuery string,
	msm any,
	fuzziness any,
	prefixLen int,
	fuzzyTransp *bool,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) (CompiledQuery, bool) {
	return t.compileMatchWithAnalysisGraphOpts(
		origField, queryStr, operator, explicitAnalyzer, zeroTermsQuery,
		msm, fuzziness, prefixLen, fuzzyTransp, nil, boost, scoring, nctx,
	)
}

func (t *Transpiler) compileMatchWithAnalysisGraphOpts(
	origField string,
	queryStr string,
	operator string,
	explicitAnalyzer string,
	zeroTermsQuery string,
	msm any,
	fuzziness any,
	prefixLen int,
	fuzzyTransp *bool,
	autoSynPhrase *bool,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) (CompiledQuery, bool) {
	cleanField, fBoost := parseFieldBoost(origField, 1.0)
	if strings.ContainsAny(cleanField, "*?") {
		return CompiledQuery{}, false
	}
	resolved, b := t.resolveFieldInNestedCtx(cleanField, false, nctx)
	if isExactKeywordField(resolved, b) || b.ESType == "wildcard" || schema.IsRangeFieldType(b.ESType) || b.ESType == "ip" {
		return CompiledQuery{}, false
	}
	effAn := t.effectiveQueryAnalyzerName(b, explicitAnalyzer)
	if !t.hasCustomQueryAnalysis(effAn) {
		return CompiledQuery{}, false
	}
	if !t.checkFieldSearchable(resolved, b) || t.isNonStandardQueryRestrictedField(cleanField, b, "match") || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	effCfg := t.effectiveAnalysisConfig()
	tokens, err := analysis.AnalyzeTokens(queryStr, effAn, effCfg, t.Opts.AnalysisOpts)
	if err != nil {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("illegal_argument_exception: " + err.Error())
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	graph := analysis.BuildQueryTokenGraph(tokens)
	effBoost := boost * fBoost
	return t.compileMatchGraphToSQLR64(
		resolved, b, effAn, effCfg, graph, operator, msm, zeroTermsQuery,
		fuzziness, prefixLen, fuzzyTransp, autoSynPhrase, effBoost, scoring, nctx,
	), true
}

// combineMatchPredicatesR65 joins fulltext-capable predicates (`preds`) and their
// expression/projection-safe equivalents (`safePreds`), ensuring
// `CAST(COALESCE(..., FALSE) AS INT)` arithmetic never wraps `MATCH_*` operators.
func combineMatchPredicatesR65(preds, safePreds []string, isAnd bool, msm any) (whereSQL, safeWhereSQL string, impossible bool) {
	if msm != nil && parseMinShouldMatch(msm, len(preds), true) > len(preds) {
		return "FALSE", "FALSE", true
	}
	if isAnd {
		if len(preds) == 1 {
			return preds[0], safePreds[0], false
		}
		return "(" + strings.Join(preds, " AND ") + ")", "(" + strings.Join(safePreds, " AND ") + ")", false
	}
	if msm != nil {
		reqCount := parseMinShouldMatch(msm, len(preds), true)
		if reqCount > len(preds) {
			return "FALSE", "FALSE", true
		}
		if reqCount <= 1 {
			if len(preds) == 1 {
				return preds[0], safePreds[0], false
			}
			return "(" + strings.Join(preds, " OR ") + ")", "(" + strings.Join(safePreds, " OR ") + ")", false
		}
		if reqCount == len(preds) {
			return "(" + strings.Join(preds, " AND ") + ")", "(" + strings.Join(safePreds, " AND ") + ")", false
		}
		var casts []string
		for _, sp := range safePreds {
			casts = append(casts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", sp))
		}
		castSum := strings.Join(casts, " + ")
		return fmt.Sprintf("((%s) AND ((%s) >= %d))", strings.Join(preds, " OR "), castSum, reqCount),
			fmt.Sprintf("((%s) AND ((%s) >= %d))", strings.Join(safePreds, " OR "), castSum, reqCount),
			false
	}
	if len(preds) == 1 {
		return preds[0], safePreds[0], false
	}
	return "(" + strings.Join(preds, " OR ") + ")", "(" + strings.Join(safePreds, " OR ") + ")", false
}

func (t *Transpiler) compileMatchGraphToSQLR64(
	resolved string,
	b schema.FieldBinding,
	effAn string,
	effCfg *analysis.IndexAnalysisConfig,
	graph analysis.QueryTokenGraph,
	operator string,
	msm any,
	zeroTermsQuery string,
	fuzziness any,
	prefixLen int,
	fuzzyTransp *bool,
	autoSynPhrase *bool,
	effBoost float64,
	scoring bool,
	nctx *nestedCtx,
) CompiledQuery {
	if graph.IsEmpty() {
		if strings.EqualFold(zeroTermsQuery, "all") {
			return CompiledQuery{
				WhereSQL:     "TRUE",
				SafeWhereSQL: "TRUE",
				ScoreSQL:     strconv.FormatFloat(effBoost, 'g', -1, 64),
			}
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	if autoSynPhrase == nil {
		autoSynPhrase = t.autoGenSynPhraseQuery
	}
	autoPhrase := !t.Opts.DisableSynonymsPhraseQuery && graph.HasGraphSpans
	if autoSynPhrase != nil {
		autoPhrase = *autoSynPhrase && graph.HasGraphSpans
	}
	isAnd := strings.EqualFold(operator, "and")
	caseSensitive, isWhitespace := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, t.Opts.AnalysisOpts)

	var segPreds, segSafePreds, segScores []string
	usesFT := false

	for _, seg := range graph.Segments {
		if len(seg.Alternatives) == 0 {
			continue
		}
		var altPreds, altSafePreds, altScores []string
		appendAlt := func(cp CompiledQuery) {
			if cp.WhereSQL == "FALSE" {
				return
			}
			altPreds = append(altPreds, cp.WhereSQL)
			altSafePreds = append(altSafePreds, cp.EffectiveSafeWhere())
			if cp.UsesFulltextMatch {
				usesFT = true
			}
			if scoring && cp.ScoreSQL != "0.0" {
				altScores = append(altScores, cp.ScoreSQL)
			}
		}
		if seg.IsSingleTermAlternatives() {
			for _, tk := range seg.SingleTermAlternatives() {
				var cp CompiledQuery
				if hasNonZeroFuzziness(fuzziness) {
					cp = t.compileFuzzyFieldWithOpts(resolved, tk, "or", fuzziness, false, prefixLen, fuzzyTransp, 1.0, scoring, nctx)
				} else {
					cp = t.singleAnalyzedTokenWithFlagsR63(resolved, b, tk, caseSensitive, isWhitespace, 1.0, scoring, nctx)
				}
				appendAlt(cp)
			}
		} else {
			for _, alt := range seg.Alternatives {
				if len(alt) == 0 {
					continue
				}
				var cp CompiledQuery
				if len(alt) == 1 {
					if hasNonZeroFuzziness(fuzziness) {
						cp = t.compileFuzzyFieldWithOpts(resolved, alt[0], "or", fuzziness, false, prefixLen, fuzzyTransp, 1.0, scoring, nctx)
					} else {
						cp = t.singleAnalyzedTokenWithFlagsR63(resolved, b, alt[0], caseSensitive, isWhitespace, 1.0, scoring, nctx)
					}
				} else if autoPhrase {
					cp = t.multiTokenExactPhraseSQL(resolved, b, alt, 0, false, caseSensitive, 1.0, scoring, nctx)
				} else {
					var subParts, subSafeParts []string
					subFT := false
					for _, tk := range alt {
						subCP := t.singleAnalyzedTokenWithFlagsR63(resolved, b, tk, caseSensitive, isWhitespace, 1.0, false, nctx)
						subParts = append(subParts, subCP.WhereSQL)
						subSafeParts = append(subSafeParts, subCP.EffectiveSafeWhere())
						if subCP.UsesFulltextMatch {
							subFT = true
						}
					}
					joiner := " OR "
					if isAnd {
						joiner = " AND "
					}
					w := "(" + strings.Join(subParts, joiner) + ")"
					sw := "(" + strings.Join(subSafeParts, joiner) + ")"
					sc := "0.0"
					if scoring {
						sc = fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", sw)
					}
					cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: subFT}
				}
				appendAlt(cp)
			}
		}
		if len(altPreds) == 0 {
			if isAnd {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			continue
		}
		segW := altPreds[0]
		segSW := altSafePreds[0]
		if len(altPreds) > 1 {
			segW = "(" + strings.Join(altPreds, " OR ") + ")"
			segSW = "(" + strings.Join(altSafePreds, " OR ") + ")"
		}
		segPreds = append(segPreds, segW)
		segSafePreds = append(segSafePreds, segSW)
		if scoring {
			if len(altScores) == 1 {
				segScores = append(segScores, altScores[0])
			} else if len(altScores) > 1 {
				segScores = append(segScores, fmt.Sprintf("GREATEST(%s)", strings.Join(altScores, ", ")))
			}
		}
	}

	if len(segPreds) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	whereSQL, safeWhereSQL, impossible := combineMatchPredicatesR65(segPreds, segSafePreds, isAnd, msm)
	if impossible {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	scoreSQL := "0.0"
	if scoring {
		if len(segScores) > 0 {
			sumSc := segScores[0]
			if len(segScores) > 1 {
				sumSc = "(" + strings.Join(segScores, " + ") + ")"
			}
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), sumSc)
		} else {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64))
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
}

// compileCommonTermsQueryR64 compiles Elasticsearch `common` queries as well as `match` / `multi_match`
// queries with `cutoff_frequency`, splitting analyzed query tokens (including stacked synonym tokens)
// by corpus document frequency via `t.Opts.TermDocFreqFn` (falling back to English stopwords when nil).
func (t *Transpiler) compileCommonTermsQueryR64(
	origField string,
	qStr string,
	lowOp string,
	highOp string,
	cutoffFreq float64,
	msm any,
	explicitAnalyzer string,
	zeroTermsQuery string,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
	isCommonQuery bool,
) (CompiledQuery, bool) {
	cleanKey, fBoost := parseFieldBoost(origField, 1.0)
	if strings.ContainsAny(cleanKey, "*?") {
		return CompiledQuery{}, false
	}
	resolved, b := t.resolveFieldInNestedCtx(cleanKey, false, nctx)
	if isExactKeywordField(resolved, b) || b.ESType == "wildcard" || schema.IsRangeFieldType(b.ESType) || b.ESType == "ip" {
		return CompiledQuery{}, false
	}
	if !t.checkFieldSearchable(resolved, b) || t.isNonStandardQueryRestrictedField(cleanKey, b, "common") || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	effAn := t.effectiveQueryAnalyzerName(b, explicitAnalyzer)
	effCfg := t.effectiveAnalysisConfig()
	toks, err := analysis.AnalyzeTokens(qStr, effAn, effCfg, t.Opts.AnalysisOpts)
	if err != nil {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("illegal_argument_exception: " + err.Error())
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	effBoost := boost * fBoost
	if len(toks) == 0 {
		if strings.EqualFold(zeroTermsQuery, "all") {
			return CompiledQuery{
				WhereSQL:     "TRUE",
				SafeWhereSQL: "TRUE",
				ScoreSQL:     strconv.FormatFloat(effBoost, 'g', -1, 64),
			}, true
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	effLowOp := strings.ToLower(strings.TrimSpace(lowOp))
	if effLowOp == "" {
		effLowOp = "or"
	}
	explicitHighOp := strings.ToLower(strings.TrimSpace(highOp))
	effHighOp := explicitHighOp
	if effHighOp == "" {
		effHighOp = "or"
	}

	caseSensitive, isWhitespace := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, t.Opts.AnalysisOpts)
	var docCount int
	var dfs map[string]int
	hasCorpusStats := false
	effCutoff := cutoffFreq
	if effCutoff == 0 && isCommonQuery {
		effCutoff = 0.1
	}
	if t.Opts.TermDocFreqFn != nil && effCutoff > 0 {
		termSeen := make(map[string]bool, len(toks))
		var distinctTerms []string
		for _, tk := range toks {
			termKey := tk.Term
			if !caseSensitive {
				termKey = strings.ToLower(termKey)
			}
			if !termSeen[termKey] {
				termSeen[termKey] = true
				distinctTerms = append(distinctTerms, termKey)
			}
		}
		colExpr := t.bm25TextColExprR63(resolved, b, nctx)
		docCount, dfs = t.Opts.TermDocFreqFn(colExpr, distinctTerms, caseSensitive)
		hasCorpusStats = docCount > 0
	}

	var lowToks, highToks []analysis.Token
	for _, tk := range toks {
		isHigh := false
		if hasCorpusStats {
			termKey := tk.Term
			if !caseSensitive {
				termKey = strings.ToLower(termKey)
			}
			df := dfs[termKey]
			if df > 0 {
				if effCutoff >= 1.0 {
					isHigh = float64(df) >= effCutoff
				} else {
					isHigh = float64(df) >= effCutoff*float64(docCount)
				}
			}
		} else if cutoffFreq > 0 && defaultEnglishStopwords[strings.ToLower(tk.Term)] {
			isHigh = true
		}
		if isHigh {
			highToks = append(highToks, tk)
		} else {
			lowToks = append(lowToks, tk)
		}
	}

	var lowMSM, highMSM any
	scalarMSM := false
	if msmMap, isMap := msm.(map[string]any); isMap {
		lowMSM = msmMap["low_freq"]
		highMSM = msmMap["high_freq"]
	} else if msm != nil {
		lowMSM = msm
		scalarMSM = true
	}

	// Only high-frequency tokens matched.
	if len(lowToks) == 0 {
		if highMSM != nil {
			var tokPreds, tokSafePreds, tokScores []string
			usesFT := false
			for _, tk := range highToks {
				cp := t.singleAnalyzedTokenWithFlagsR63(resolved, b, tk.Term, caseSensitive, isWhitespace, 1.0, scoring, nctx)
				if cp.WhereSQL != "FALSE" {
					tokPreds = append(tokPreds, cp.WhereSQL)
					tokSafePreds = append(tokSafePreds, cp.EffectiveSafeWhere())
					if cp.UsesFulltextMatch {
						usesFT = true
					}
					if scoring && cp.ScoreSQL != "0.0" {
						tokScores = append(tokScores, cp.ScoreSQL)
					}
				}
			}
			if len(tokPreds) == 0 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
			}
			whereSQL, safeWhereSQL, impossible := combineMatchPredicatesR65(tokPreds, tokSafePreds, false, highMSM)
			if impossible {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
			}
			scoreSQL := "0.0"
			if scoring {
				if len(tokScores) > 0 {
					sumSc := tokScores[0]
					if len(tokScores) > 1 {
						sumSc = "(" + strings.Join(tokScores, " + ") + ")"
					}
					scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), sumSc)
				} else {
					scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64))
				}
			}
			return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}, true
		}
		opForHigh := effHighOp
		if explicitHighOp == "" && hasCorpusStats {
			opForHigh = "and"
		}
		graph := analysis.BuildQueryTokenGraph(highToks)
		return t.compileMatchGraphToSQLR64(resolved, b, effAn, effCfg, graph, opForHigh, nil, zeroTermsQuery, nil, 0, nil, nil, effBoost, scoring, nctx), true
	}

	lowGraph := analysis.BuildQueryTokenGraph(lowToks)
	effLowMSM := lowMSM
	if scalarMSM && !isCommonQuery && lowMSM != nil && len(lowGraph.Segments) > 0 {
		if req := parseMinShouldMatch(lowMSM, len(lowGraph.Segments), true); req > len(lowGraph.Segments) {
			effLowMSM = len(lowGraph.Segments)
		}
	}
	lowCompiled := t.compileMatchGraphToSQLR64(resolved, b, effAn, effCfg, lowGraph, effLowOp, effLowMSM, zeroTermsQuery, nil, 0, nil, nil, 1.0, scoring, nctx)

	if len(highToks) == 0 {
		if effBoost == 1.0 {
			return lowCompiled, true
		}
		lowSafe := lowCompiled.EffectiveSafeWhere()
		sc := "0.0"
		if scoring && lowCompiled.ScoreSQL != "" && lowCompiled.ScoreSQL != "0.0" {
			sc = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", lowSafe, strconv.FormatFloat(effBoost, 'g', -1, 64), lowCompiled.ScoreSQL)
		}
		return CompiledQuery{WhereSQL: lowCompiled.WhereSQL, SafeWhereSQL: lowSafe, ScoreSQL: sc, UsesFulltextMatch: lowCompiled.UsesFulltextMatch}, true
	}

	// Both low-frequency and high-frequency groups are non-empty.
	highGraph := analysis.BuildQueryTokenGraph(highToks)
	highCompiled := t.compileMatchGraphToSQLR64(resolved, b, effAn, effCfg, highGraph, effHighOp, highMSM, "", nil, 0, nil, nil, 1.0, scoring, nctx)

	lowRequired := effLowOp == "and" || effLowMSM != nil
	highRequired := effHighOp == "and" || highMSM != nil

	var whereSQL, safeWhereSQL string
	usesFT := false
	switch {
	case lowRequired && highRequired:
		if lowCompiled.WhereSQL == "FALSE" || highCompiled.WhereSQL == "FALSE" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
		}
		whereSQL = fmt.Sprintf("((%s) AND (%s))", lowCompiled.WhereSQL, highCompiled.WhereSQL)
		safeWhereSQL = fmt.Sprintf("((%s) AND (%s))", lowCompiled.EffectiveSafeWhere(), highCompiled.EffectiveSafeWhere())
		usesFT = lowCompiled.UsesFulltextMatch || highCompiled.UsesFulltextMatch
	case lowRequired:
		whereSQL = lowCompiled.WhereSQL
		safeWhereSQL = lowCompiled.EffectiveSafeWhere()
		usesFT = lowCompiled.UsesFulltextMatch
	case highRequired:
		whereSQL = highCompiled.WhereSQL
		safeWhereSQL = highCompiled.EffectiveSafeWhere()
		usesFT = highCompiled.UsesFulltextMatch
	default:
		switch {
		case lowCompiled.WhereSQL == "FALSE":
			whereSQL = highCompiled.WhereSQL
			safeWhereSQL = highCompiled.EffectiveSafeWhere()
			usesFT = highCompiled.UsesFulltextMatch
		case highCompiled.WhereSQL == "FALSE":
			whereSQL = lowCompiled.WhereSQL
			safeWhereSQL = lowCompiled.EffectiveSafeWhere()
			usesFT = lowCompiled.UsesFulltextMatch
		default:
			whereSQL = fmt.Sprintf("((%s) OR (%s))", lowCompiled.WhereSQL, highCompiled.WhereSQL)
			safeWhereSQL = fmt.Sprintf("((%s) OR (%s))", lowCompiled.EffectiveSafeWhere(), highCompiled.EffectiveSafeWhere())
			usesFT = lowCompiled.UsesFulltextMatch || highCompiled.UsesFulltextMatch
		}
	}
	if whereSQL == "FALSE" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	scoreSQL := "0.0"
	if scoring {
		var parts []string
		if lowCompiled.ScoreSQL != "" && lowCompiled.ScoreSQL != "0.0" {
			parts = append(parts, lowCompiled.ScoreSQL)
		}
		if highCompiled.ScoreSQL != "" && highCompiled.ScoreSQL != "0.0" {
			parts = append(parts, highCompiled.ScoreSQL)
		}
		if len(parts) > 0 {
			sumSc := parts[0]
			if len(parts) > 1 {
				sumSc = "(" + strings.Join(parts, " + ") + ")"
			}
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), sumSc)
		} else {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64))
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}, true
}

// compileMatchPhraseWithAnalysisGraph compiles `match_phrase` and `match_phrase_prefix` via
// `QueryTokenGraph.PhrasePaths` when custom `AnalysisConfig` is active (`50_synonyms.yml`, `60_synonym_graph.yml`).
func (t *Transpiler) compileMatchPhraseWithAnalysisGraph(
	origField string,
	queryStr string,
	slop int,
	explicitAnalyzer string,
	zeroTermsQuery string,
	isPrefix bool,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) (CompiledQuery, bool) {
	cleanField, fBoost := parseFieldBoost(origField, 1.0)
	if strings.ContainsAny(cleanField, "*?") {
		return CompiledQuery{}, false
	}
	resolved, b := t.resolveFieldInNestedCtx(cleanField, false, nctx)
	if isExactKeywordField(resolved, b) || schema.IsRangeFieldType(b.ESType) || b.ESType == "ip" {
		return CompiledQuery{}, false
	}
	effAn := t.effectiveQueryAnalyzerName(b, explicitAnalyzer)
	if !t.hasCustomQueryAnalysis(effAn) {
		return CompiledQuery{}, false
	}
	if !t.checkFieldSearchable(resolved, b) || t.isNonStandardQueryRestrictedField(cleanField, b, "match_phrase") || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	effCfg := t.effectiveAnalysisConfig()
	tokens, err := analysis.AnalyzeTokens(queryStr, effAn, effCfg, t.Opts.AnalysisOpts)
	if err != nil {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("illegal_argument_exception: " + err.Error())
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	graph := analysis.BuildQueryTokenGraph(tokens)
	effBoost := boost * fBoost
	if graph.IsEmpty() {
		if strings.EqualFold(zeroTermsQuery, "all") {
			return CompiledQuery{
				WhereSQL:     "TRUE",
				SafeWhereSQL: "TRUE",
				ScoreSQL:     strconv.FormatFloat(effBoost, 'g', -1, 64),
			}, true
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}

	paths := graph.PhrasePaths(64)
	if len(paths) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	caseSensitive, isWhitespace := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, t.Opts.AnalysisOpts)
	var disj, pathScores []string
	for _, p := range paths {
		clauseWeight := 1.0
		if len(paths) > 1 && len(p) > 1 {
			clauseWeight = 1.0 / float64(len(p))
		}
		var cp CompiledQuery
		if len(p) == 1 && !isPrefix {
			cp = t.singleAnalyzedTokenWithFlagsR63(resolved, b, p[0], caseSensitive, isWhitespace, clauseWeight, scoring, nctx)
		} else {
			cp = t.multiTokenExactPhraseSQL(resolved, b, p, slop, isPrefix, caseSensitive, clauseWeight, scoring, nctx)
		}
		if cp.WhereSQL != "FALSE" {
			disj = append(disj, cp.WhereSQL)
			if scoring && cp.ScoreSQL != "0.0" {
				pathScores = append(pathScores, cp.ScoreSQL)
			}
		}
	}
	if len(disj) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}, true
	}
	whereSQL := disj[0]
	if len(disj) > 1 {
		whereSQL = "(" + strings.Join(disj, " OR ") + ")"
	}
	scoreSQL := "0.0"
	if scoring {
		if len(pathScores) == 1 {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", whereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), pathScores[0])
		} else if len(pathScores) > 1 {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * GREATEST(%s)) ELSE 0.0 END)", whereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), strings.Join(pathScores, ", "))
		} else {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", whereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64))
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}, true
}

// compileMatchBoolPrefixRound62 compiles `match_bool_prefix` (and `multi_match` `bool_prefix` per-field clauses)
// with exact Elasticsearch semantics (`search/310_match_bool_prefix.yml` & `search-as-you-type/10_basic.yml`):
//   - Tokenizes query text using the field's search analyzer (honoring `whitespace` case preservation and custom `AnalysisConfig`).
//   - On `search_as_you_type` virtual shingle subfields (`._2gram`, `._3gram`, `._4gram`), forms N-shingles; if fewer than N tokens
//     exist in the query, returns `FALSE` so sibling root/`_index_prefix` fields carry short queries cleanly.
//   - Applies `fuzziness` ONLY to leading `0..len-2` term clauses, NEVER to the trailing prefix clause (`len-1`).
//   - Honors `operator` (`or`/`and`) and `minimum_should_match` across all token clauses.
func (t *Transpiler) compileMatchBoolPrefixRound62(rawField string, pe esast.PhraseEntry, scoring bool, nctx *nestedCtx) CompiledQuery {
	return t.compileMatchBoolPrefixRound62Opts(rawField, pe, nil, scoring, nctx)
}

func (t *Transpiler) compileMatchBoolPrefixRound62Opts(rawField string, pe esast.PhraseEntry, autoSynPhrase *bool, scoring bool, nctx *nestedCtx) CompiledQuery {
	cleanField, fBoost := parseFieldBoost(rawField, 1.0)
	effBoost := pe.Boost * fBoost

	if strings.ContainsAny(cleanField, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(rawField, nctx)
		if len(exp) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		var subs []esast.Query
		for _, bf := range exp {
			peCopy := pe
			peCopy.Boost = pe.Boost * bf.Boost
			subs = append(subs, esast.Query{MatchBoolPrefix: map[string]esast.PhraseEntry{bf.Field: peCopy}})
		}
		return t.compileDisMax(&esast.DisMaxQuery{Queries: subs}, scoring, nctx)
	}

	preferSAYTSub := strings.HasSuffix(cleanField, "._2gram") || strings.HasSuffix(cleanField, "._3gram") ||
		strings.HasSuffix(cleanField, "._4gram") || strings.HasSuffix(cleanField, "._index_prefix")
	resolved, b := t.resolveFieldInNestedCtx(cleanField, preferSAYTSub, nctx)
	if !t.checkFieldSearchable(resolved, b) || t.isNonStandardQueryRestrictedField(cleanField, b, "match_bool_prefix") || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	// Numeric / date / boolean / IP fields reject `match_bool_prefix` unless `lenient: true`.
	switch b.ESType {
	case "byte", "short", "integer", "long", "unsigned_long", "float", "half_float", "scaled_float", "double", "boolean", "date", "date_nanos", "ip":
		isLenient := t.inLenientQuery || (pe.Lenient != nil && *pe.Lenient)
		if !isLenient && t.searchErr == nil {
			t.searchErr = esTranspilerError(fmt.Sprintf("illegal_argument_exception: Can only use prefix queries on text and keyword fields - not on [%s] which is of type [%s]", cleanField, b.ESType))
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	effAn := t.effectiveQueryAnalyzerName(b, pe.Analyzer)
	isWS := strings.EqualFold(effAn, "whitespace")

	if !isExactKeywordField(resolved, b) && !b.IsVirtualSAYTSubfield && t.hasCustomQueryAnalysis(effAn) {
		effCfg := t.effectiveAnalysisConfig()
		toks, err := analysis.AnalyzeTokens(pe.Query, effAn, effCfg, t.Opts.AnalysisOpts)
		if err != nil {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = esTranspilerError("illegal_argument_exception: " + err.Error())
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		graph := analysis.BuildQueryTokenGraph(toks)
		if graph.IsEmpty() {
			if strings.EqualFold(pe.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: strconv.FormatFloat(effBoost, 'g', -1, 64)}
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		caseSens, isAnWS := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, t.Opts.AnalysisOpts)
		if autoSynPhrase == nil {
			autoSynPhrase = t.autoGenSynPhraseQuery
		}
		autoPhrase := !t.Opts.DisableSynonymsPhraseQuery && graph.HasGraphSpans
		if autoSynPhrase != nil {
			autoPhrase = *autoSynPhrase && graph.HasGraphSpans
		}
		isAnd := strings.EqualFold(pe.Operator, "and")
		var segPreds, segSafePreds, segScores []string
		usesFT := false
		for si, seg := range graph.Segments {
			isLast := si == len(graph.Segments)-1
			compilePrefixTok := func(ptk string) CompiledQuery {
				if !isAnWS && b.Kind == schema.StoragePromotedScalar && !b.NotIndexed && nctx == nil && !strings.ContainsAny(ptk, " \t\r\n'\"\\") {
					return t.compileMatchPhraseField(resolved, ptk, 0, 1.0, true, false, nctx)
				}
				sw := t.compileAnalyzedTokenOrPhrasePrefixRegex(resolved, b, ptk, !isAnWS, nctx)
				return CompiledQuery{WhereSQL: sw, SafeWhereSQL: sw}
			}
			var altPreds, altSafePreds, altScores []string
			appendAlt := func(w, sw, sc string, ft bool) {
				if w == "FALSE" {
					return
				}
				altPreds = append(altPreds, w)
				altSafePreds = append(altSafePreds, sw)
				if ft {
					usesFT = true
				}
				if scoring && sc != "" && sc != "0.0" {
					altScores = append(altScores, sc)
				}
			}
			if seg.IsSingleTermAlternatives() {
				for _, tk := range seg.SingleTermAlternatives() {
					var cp CompiledQuery
					var w, sw, sc string
					if isLast {
						cp = compilePrefixTok(tk)
						w, sw = cp.WhereSQL, cp.EffectiveSafeWhere()
						if scoring {
							sc = fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", sw)
						}
					} else if hasNonZeroFuzziness(pe.Fuzziness) {
						cp = t.compileFuzzyFieldWithOpts(resolved, tk, "or", pe.Fuzziness, false, pe.PrefixLength, pe.FuzzyTranspositions, 1.0, scoring, nctx)
						w, sw, sc = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.ScoreSQL
					} else {
						cp = t.singleAnalyzedTokenWithFlagsR63(resolved, b, tk, caseSens, isAnWS, 1.0, scoring, nctx)
						w, sw, sc = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.ScoreSQL
					}
					appendAlt(w, sw, sc, cp.UsesFulltextMatch)
				}
			} else {
				for _, alt := range seg.Alternatives {
					if len(alt) == 0 {
						continue
					}
					var cp CompiledQuery
					var w, sw, sc string
					ft := false
					if len(alt) == 1 {
						if isLast {
							cp = compilePrefixTok(alt[0])
							w, sw, ft = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.UsesFulltextMatch
							if scoring {
								sc = fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", sw)
							}
						} else if hasNonZeroFuzziness(pe.Fuzziness) {
							cp = t.compileFuzzyFieldWithOpts(resolved, alt[0], "or", pe.Fuzziness, false, pe.PrefixLength, pe.FuzzyTranspositions, 1.0, scoring, nctx)
							w, sw, sc, ft = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.ScoreSQL, cp.UsesFulltextMatch
						} else {
							cp = t.singleAnalyzedTokenWithFlagsR63(resolved, b, alt[0], caseSens, isAnWS, 1.0, scoring, nctx)
							w, sw, sc, ft = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.ScoreSQL, cp.UsesFulltextMatch
						}
					} else if autoPhrase {
						cp = t.multiTokenExactPhraseSQL(resolved, b, alt, 0, isLast, caseSens, 1.0, scoring, nctx)
						w, sw, sc, ft = cp.WhereSQL, cp.EffectiveSafeWhere(), cp.ScoreSQL, cp.UsesFulltextMatch
					} else {
						var subParts, subSafeParts []string
						for ai, tk := range alt {
							var subCP CompiledQuery
							if isLast && ai == len(alt)-1 {
								subCP = compilePrefixTok(tk)
							} else {
								subCP = t.singleAnalyzedTokenWithFlagsR63(resolved, b, tk, caseSens, isAnWS, 1.0, false, nctx)
							}
							subParts = append(subParts, subCP.WhereSQL)
							subSafeParts = append(subSafeParts, subCP.EffectiveSafeWhere())
							if subCP.UsesFulltextMatch {
								ft = true
							}
						}
						joiner := " OR "
						if isAnd {
							joiner = " AND "
						}
						w = "(" + strings.Join(subParts, joiner) + ")"
						sw = "(" + strings.Join(subSafeParts, joiner) + ")"
						if scoring {
							sc = fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", sw)
						}
					}
					appendAlt(w, sw, sc, ft)
				}
			}
			if len(altPreds) == 0 {
				if isAnd {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				continue
			}
			segW := altPreds[0]
			segSW := altSafePreds[0]
			if len(altPreds) > 1 {
				segW = "(" + strings.Join(altPreds, " OR ") + ")"
				segSW = "(" + strings.Join(altSafePreds, " OR ") + ")"
			}
			segPreds = append(segPreds, segW)
			segSafePreds = append(segSafePreds, segSW)
			if scoring && len(altScores) > 0 {
				if len(altScores) == 1 {
					segScores = append(segScores, altScores[0])
				} else {
					segScores = append(segScores, fmt.Sprintf("GREATEST(%s)", strings.Join(altScores, ", ")))
				}
			}
		}
		if len(segPreds) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		whereSQL, safeWhereSQL, impossible := combineMatchPredicatesR65(segPreds, segSafePreds, isAnd, pe.MinimumShouldMatch)
		if impossible {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		scoreSQL := "0.0"
		if scoring {
			sumSc := "1.0"
			if len(segScores) == 1 {
				sumSc = segScores[0]
			} else if len(segScores) > 1 {
				sumSc = "(" + strings.Join(segScores, " + ") + ")"
			}
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), sumSc)
		}
		return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
	}

	var tokens []string
	if strings.EqualFold(effAn, "keyword") && !b.IsVirtualSAYTSubfield {
		if pe.Query != "" {
			tokens = []string{t.normalizeKeywordOrAnalyzerTerm(pe.Query, b, false)}
		}
	} else if isExactKeywordField(resolved, b) && !b.IsVirtualSAYTSubfield && strings.TrimSpace(pe.Analyzer) == "" {
		if pe.Query != "" {
			tokens = []string{t.normalizeKeywordOrAnalyzerTerm(pe.Query, b, false)}
		}
	} else if t.hasCustomQueryAnalysis(effAn) {
		effCfg := t.effectiveAnalysisConfig()
		toks, err := analysis.AnalyzeTokens(pe.Query, effAn, effCfg, t.Opts.AnalysisOpts)
		if err != nil {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = esTranspilerError("illegal_argument_exception: " + err.Error())
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		graph := analysis.BuildQueryTokenGraph(toks)
		for _, pos := range graph.Positions {
			if len(pos.Terms) > 0 {
				tokens = append(tokens, pos.Terms[0])
			}
		}
	} else {
		filtered, allStop := filterStopwordTokens(pe.Query, effAn, pe.ZeroTermsQuery)
		if allStop {
			tokens = nil
		} else if len(filtered) > 0 && (strings.EqualFold(effAn, "stop") || strings.EqualFold(effAn, "english")) {
			tokens = filtered
		} else {
			tokens = TokenizeByAnalyzer(pe.Query, effAn)
		}
	}

	if len(tokens) == 0 {
		if strings.EqualFold(pe.ZeroTermsQuery, "all") {
			return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: strconv.FormatFloat(effBoost, 'g', -1, 64)}
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	// Virtual shingle subfields (`._2gram`, `._3gram`, `._4gram`) combine adjacent base tokens into shingles of size N.
	if b.IsVirtualSAYTSubfield {
		shingleN := 0
		switch {
		case strings.HasSuffix(cleanField, "._2gram"):
			shingleN = 2
		case strings.HasSuffix(cleanField, "._3gram"):
			shingleN = 3
		case strings.HasSuffix(cleanField, "._4gram"):
			shingleN = 4
		}
		if shingleN >= 2 {
			if len(tokens) < shingleN {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			shingles := make([]string, 0, len(tokens)-shingleN+1)
			for i := 0; i <= len(tokens)-shingleN; i++ {
				shingles = append(shingles, strings.Join(tokens[i:i+shingleN], " "))
			}
			tokens = shingles
		}
	}

	var clausePreds, clauseSafePreds, clauseScores []string
	usesFT := false
	for i := 0; i < len(tokens)-1; i++ {
		tok := tokens[i]
		var cp CompiledQuery
		if isExactKeywordField(resolved, b) && !b.IsVirtualSAYTSubfield {
			if hasNonZeroFuzziness(pe.Fuzziness) {
				cp = t.compileFuzzyFieldWithOpts(resolved, tok, "or", pe.Fuzziness, false, pe.PrefixLength, pe.FuzzyTranspositions, 1.0, scoring, nctx)
			} else {
				w := t.compileTermPredicate(resolved, tok, false, nctx)
				sc := "0.0"
				if scoring {
					sc = fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", w)
				}
				cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: sc}
			}
		} else if hasNonZeroFuzziness(pe.Fuzziness) && !b.IsVirtualSAYTSubfield {
			cp = t.compileFuzzyFieldWithOpts(resolved, tok, "or", pe.Fuzziness, false, pe.PrefixLength, pe.FuzzyTranspositions, 1.0, scoring, nctx)
		} else {
			cp = t.singleAnalyzedTokenSQL(resolved, b, tok, isWS, 1.0, scoring, nctx)
		}
		clausePreds = append(clausePreds, cp.WhereSQL)
		clauseSafePreds = append(clauseSafePreds, cp.EffectiveSafeWhere())
		if cp.UsesFulltextMatch {
			usesFT = true
		}
		if scoring {
			clauseScores = append(clauseScores, cp.ScoreSQL)
		}
	}

	// Trailing token is ALWAYS a prefix query (never fuzzy).
	lastTok := tokens[len(tokens)-1]
	var lastPred, lastSafePred string
	switch {
	case b.IsVirtualSAYTSubfield && b.EffectiveArrayColumn(false) != "" && nctx == nil:
		arrCol := b.EffectiveArrayColumn(false)
		likePat := quoteStr(escapeLikeLiteral(lastTok) + "%")
		if isWS {
			lastPred = fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, arrCol)
		} else {
			lastPred = fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, arrCol)
		}
		lastSafePred = lastPred
	case b.ESType == "search_as_you_type":
		lastPred = t.compileSAYTRootPrefix(resolved, b, lastTok, false, nctx)
		lastSafePred = lastPred
	case isExactKeywordField(resolved, b):
		lastPred = t.compilePrefixSingleField(resolved, lastTok, false, nctx)
		lastSafePred = lastPred
	case !isWS && b.Kind == schema.StoragePromotedScalar && !b.NotIndexed && nctx == nil && !strings.ContainsAny(lastTok, " \t\r\n'\"\\"):
		cp := t.compileMatchPhraseField(resolved, lastTok, 0, 1.0, true, false, nctx)
		lastPred = cp.WhereSQL
		lastSafePred = cp.EffectiveSafeWhere()
		if cp.UsesFulltextMatch {
			usesFT = true
		}
	default:
		lastPred = t.compileAnalyzedTokenOrPhrasePrefixRegex(resolved, b, lastTok, !isWS, nctx)
		lastSafePred = lastPred
	}
	clausePreds = append(clausePreds, lastPred)
	clauseSafePreds = append(clauseSafePreds, lastSafePred)
	if scoring {
		clauseScores = append(clauseScores, fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", lastSafePred))
	}

	isAnd := strings.EqualFold(pe.Operator, "and")
	if pe.MinimumShouldMatch != nil && !isAnd {
		if parseMinShouldMatch(pe.MinimumShouldMatch, len(clausePreds), true) > len(clausePreds) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}

	whereSQL, safeWhereSQL, impossible := combineMatchPredicatesR65(clausePreds, clauseSafePreds, isAnd, pe.MinimumShouldMatch)
	if impossible {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	scoreSQL := "0.0"
	if scoring {
		sumSc := "1.0"
		if len(clauseScores) == 1 {
			sumSc = clauseScores[0]
		} else if len(clauseScores) > 1 {
			sumSc = "(" + strings.Join(clauseScores, " + ") + ")"
		}
		scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%s * %s) ELSE 0.0 END)", safeWhereSQL, strconv.FormatFloat(effBoost, 'g', -1, 64), sumSc)
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
}

// expandMultiMatchBoolPrefixSAYTFields expands root `search_as_you_type` fields in a `multi_match`
// `type: "bool_prefix"` query into `[root, root._2gram, root._3gram]` (plus `._4gram` if mapped)
// when the caller specified only the root `search_as_you_type` field (`search-as-you-type/10_basic.yml`).
func (t *Transpiler) expandMultiMatchBoolPrefixSAYTFields(expanded []schema.BoostedField) []schema.BoostedField {
	if t.Schema == nil || len(expanded) == 0 {
		return expanded
	}
	seen := make(map[string]bool, len(expanded))
	for _, bf := range expanded {
		seen[bf.Field] = true
	}
	out := make([]schema.BoostedField, 0, len(expanded)*3)
	for _, bf := range expanded {
		out = append(out, bf)
		if fb, ok := t.Schema.Fields[bf.Field]; ok && fb.ESType == "search_as_you_type" && !fb.IsVirtualSAYTSubfield {
			for _, sfx := range []string{"._2gram", "._3gram", "._4gram"} {
				subName := bf.Field + sfx
				if !seen[subName] {
					if _, okSub := t.Schema.Fields[subName]; okSub {
						seen[subName] = true
						out = append(out, schema.BoostedField{Field: subName, Boost: bf.Boost})
					}
				}
			}
		}
	}
	return out
}

// FormatLuceneValidateExplanation formats an `esast.Query` into a Lucene-compatible query rewrite
// explanation string for `/_validate/query?explain=true` (`indices/validate_query/10_synonyms.yml`).
func FormatLuceneValidateExplanation(
	q *esast.Query,
	idxSchema *schema.IndexSchema,
	cfg *analysis.IndexAnalysisConfig,
	opts analysis.Options,
) string {
	if q == nil {
		return "*:*"
	}
	resolveAnalyzer := func(field, explicit string) string {
		if strings.TrimSpace(explicit) != "" {
			return strings.TrimSpace(explicit)
		}
		if idxSchema != nil {
			b := idxSchema.ResolveEffectiveField(field, false)
			if b.SearchAnalyzer != "" {
				return b.SearchAnalyzer
			}
			if b.Analyzer != "" {
				return b.Analyzer
			}
		}
		if cfg != nil {
			if _, ok := cfg.AnalyzerDefs["default_search"]; ok {
				return "default_search"
			}
			if _, ok := cfg.AnalyzerDefs["default"]; ok {
				return "default"
			}
		}
		return "standard"
	}

	switch {
	case q.MatchAll != nil:
		return "*:*"
	case q.MatchNone != nil:
		return "MatchNoDocsQuery(\"\")"
	case len(q.Term) > 0:
		keys := sortedMapKeys(q.Term)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s:%v", k, q.Term[k].Value))
		}
		return strings.Join(parts, " ")
	case len(q.Prefix) > 0:
		keys := sortedMapKeys(q.Prefix)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s:%s*", k, q.Prefix[k].Value))
		}
		return strings.Join(parts, " ")
	case len(q.Match) > 0:
		keys := sortedMapKeys(q.Match)
		var out []string
		for _, field := range keys {
			me := q.Match[field]
			qStr := fmt.Sprintf("%v", me.Query)
			an := resolveAnalyzer(field, me.Analyzer)
			out = append(out, formatAnalyzedMatchLuceneExplain(field, qStr, me.Operator, an, cfg, opts))
		}
		return strings.Join(out, " ")
	case len(q.MatchPhrase) > 0:
		keys := sortedMapKeys(q.MatchPhrase)
		var out []string
		for _, field := range keys {
			pe := q.MatchPhrase[field]
			an := resolveAnalyzer(field, pe.Analyzer)
			out = append(out, formatAnalyzedPhraseLuceneExplain(field, pe.Query, false, an, cfg, opts))
		}
		return strings.Join(out, " ")
	case len(q.MatchPhrasePrefix) > 0:
		keys := sortedMapKeys(q.MatchPhrasePrefix)
		var out []string
		for _, field := range keys {
			pe := q.MatchPhrasePrefix[field]
			an := resolveAnalyzer(field, pe.Analyzer)
			out = append(out, formatAnalyzedPhraseLuceneExplain(field, pe.Query, true, an, cfg, opts))
		}
		return strings.Join(out, " ")
	case len(q.MatchBoolPrefix) > 0:
		keys := sortedMapKeys(q.MatchBoolPrefix)
		var out []string
		for _, field := range keys {
			pe := q.MatchBoolPrefix[field]
			an := resolveAnalyzer(field, pe.Analyzer)
			out = append(out, formatAnalyzedBoolPrefixLuceneExplain(field, pe.Query, pe.Operator, an, cfg, opts))
		}
		return strings.Join(out, " ")
	case q.QueryString != nil || q.SimpleQueryString != nil:
		qs := q.QueryString
		if qs == nil {
			qs = q.SimpleQueryString
		}
		df := qs.DefaultField
		if df == "" && len(qs.Fields) > 0 {
			df = qs.Fields[0]
		}
		if df == "" {
			df = "_all"
		}
		an := resolveAnalyzer(df, qs.Analyzer)
		return formatQueryStringLuceneExplain(df, qs.Query, qs.DefaultOperator, an, cfg, opts)
	case q.Bool != nil:
		var clauses []string
		for i := range q.Bool.Must {
			clauses = append(clauses, "+"+FormatLuceneValidateExplanation(&q.Bool.Must[i], idxSchema, cfg, opts))
		}
		for i := range q.Bool.Filter {
			clauses = append(clauses, "#"+FormatLuceneValidateExplanation(&q.Bool.Filter[i], idxSchema, cfg, opts))
		}
		for i := range q.Bool.Should {
			clauses = append(clauses, FormatLuceneValidateExplanation(&q.Bool.Should[i], idxSchema, cfg, opts))
		}
		for i := range q.Bool.MustNot {
			clauses = append(clauses, "-"+FormatLuceneValidateExplanation(&q.Bool.MustNot[i], idxSchema, cfg, opts))
		}
		return strings.Join(clauses, " ")
	default:
		b, _ := json.Marshal(q)
		return string(b)
	}
}

func formatAnalyzedMatchLuceneExplain(field, text, operator, analyzer string, cfg *analysis.IndexAnalysisConfig, opts analysis.Options) string {
	graph, err := analysis.AnalyzeForQuery(text, analyzer, cfg, opts)
	if err != nil || graph.IsEmpty() {
		return "MatchNoDocsQuery(\"\")"
	}
	isAnd := strings.EqualFold(operator, "and")
	prefix := ""
	if isAnd && len(graph.Segments) > 1 {
		prefix = "+"
	}
	var segStrs []string
	for _, seg := range graph.Segments {
		if len(seg.Alternatives) == 1 && len(seg.Alternatives[0]) == 1 {
			segStrs = append(segStrs, fmt.Sprintf("%s%s:%s", prefix, field, seg.Alternatives[0][0]))
			continue
		}
		allSingle := true
		var synTerms []string
		for _, alt := range seg.Alternatives {
			if len(alt) != 1 {
				allSingle = false
				break
			}
			synTerms = append(synTerms, fmt.Sprintf("%s:%s", field, alt[0]))
		}
		if allSingle && len(synTerms) > 1 {
			segStrs = append(segStrs, fmt.Sprintf("%sSynonym(%s)", prefix, strings.Join(synTerms, " ")))
			continue
		}
		var altStrs []string
		for _, alt := range seg.Alternatives {
			if len(alt) == 1 {
				altStrs = append(altStrs, fmt.Sprintf("%s:%s", field, alt[0]))
			} else {
				altStrs = append(altStrs, fmt.Sprintf("%s:\"%s\"", field, strings.Join(alt, " ")))
			}
		}
		segStrs = append(segStrs, fmt.Sprintf("%s(%s)", prefix, strings.Join(altStrs, " ")))
	}
	if len(segStrs) == 1 {
		return segStrs[0]
	}
	return "(" + strings.Join(segStrs, " ") + ")"
}

func formatAnalyzedPhraseLuceneExplain(field, text string, isPrefix bool, analyzer string, cfg *analysis.IndexAnalysisConfig, opts analysis.Options) string {
	graph, err := analysis.AnalyzeForQuery(text, analyzer, cfg, opts)
	if err != nil || graph.IsEmpty() {
		return "MatchNoDocsQuery(\"\")"
	}
	if !graph.HasGraphSpans {
		var posParts []string
		for idx, pos := range graph.Positions {
			isLast := idx == len(graph.Positions)-1
			sfx := ""
			if isPrefix && isLast {
				sfx = "*"
			}
			if len(pos.Terms) == 1 {
				posParts = append(posParts, pos.Terms[0]+sfx)
			} else if len(pos.Terms) > 1 {
				withSfx := make([]string, len(pos.Terms))
				for i, tk := range pos.Terms {
					withSfx[i] = tk + sfx
				}
				posParts = append(posParts, "("+strings.Join(withSfx, " ")+")")
			}
		}
		if len(posParts) == 1 && !strings.HasPrefix(posParts[0], "(") && !isPrefix {
			return fmt.Sprintf("%s:%s", field, posParts[0])
		}
		return fmt.Sprintf("%s:\"%s\"", field, strings.Join(posParts, " "))
	}
	paths := graph.PhrasePaths(32)
	var pathStrs []string
	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		cp := append([]string(nil), p...)
		if isPrefix {
			cp[len(cp)-1] += "*"
		}
		pathStrs = append(pathStrs, fmt.Sprintf("%s:\"%s\"", field, strings.Join(cp, " ")))
	}
	if len(pathStrs) == 1 {
		return pathStrs[0]
	}
	return "(" + strings.Join(pathStrs, " ") + ")"
}

func formatAnalyzedBoolPrefixLuceneExplain(field, text, operator, analyzer string, cfg *analysis.IndexAnalysisConfig, opts analysis.Options) string {
	graph, err := analysis.AnalyzeForQuery(text, analyzer, cfg, opts)
	if err != nil || graph.IsEmpty() {
		return "MatchNoDocsQuery(\"\")"
	}
	isAnd := strings.EqualFold(operator, "and")
	pfx := ""
	if isAnd && len(graph.Positions) > 1 {
		pfx = "+"
	}
	var parts []string
	for idx, pos := range graph.Positions {
		isLast := idx == len(graph.Positions)-1
		if isLast {
			if len(pos.Terms) == 1 {
				parts = append(parts, fmt.Sprintf("%s%s:%s*", pfx, field, pos.Terms[0]))
			} else {
				var sub []string
				for _, tk := range pos.Terms {
					sub = append(sub, fmt.Sprintf("%s:%s*", field, tk))
				}
				parts = append(parts, fmt.Sprintf("%s(%s)", pfx, strings.Join(sub, " ")))
			}
			continue
		}
		if len(pos.Terms) == 1 {
			parts = append(parts, fmt.Sprintf("%s%s:%s", pfx, field, pos.Terms[0]))
		} else {
			var sub []string
			for _, tk := range pos.Terms {
				sub = append(sub, fmt.Sprintf("%s:%s", field, tk))
			}
			parts = append(parts, fmt.Sprintf("%sSynonym(%s)", pfx, strings.Join(sub, " ")))
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " ") + ")"
}

func formatQueryStringLuceneExplain(defaultField, raw, defaultOp, analyzer string, cfg *analysis.IndexAnalysisConfig, opts analysis.Options) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") && len(trimmed) >= 2 {
		inner := trimmed[1 : len(trimmed)-1]
		isPfx := strings.HasSuffix(inner, "*")
		if isPfx {
			inner = strings.TrimSuffix(inner, "*")
		}
		return formatAnalyzedPhraseLuceneExplain(defaultField, inner, isPfx, analyzer, cfg, opts)
	}
	if idx := strings.IndexByte(trimmed, ':'); idx > 0 && !strings.ContainsAny(trimmed[:idx], " \"") {
		fld := trimmed[:idx]
		rest := strings.TrimSpace(trimmed[idx+1:])
		return formatQueryStringLuceneExplain(fld, rest, defaultOp, analyzer, cfg, opts)
	}
	return formatAnalyzedMatchLuceneExplain(defaultField, trimmed, defaultOp, analyzer, cfg, opts)
}

// resolveDateHistogramBoundFloat converts a `date_histogram` `hard_bounds` or `extended_bounds`
// min/max value into a `*float64` epoch milliseconds pointer when valid.
func (t *Transpiler) resolveDateHistogramBoundFloatPtr(b schema.FieldBinding, format string, bound any) *float64 {
	if bound == nil {
		return nil
	}
	if ms, ok := t.resolveDateHistogramBoundMs(b, format, bound); ok {
		fv := float64(ms)
		return &fv
	}
	if str, ok := bound.(string); ok {
		if ms, okP := schema.ParseESDateWithFormatToEpochMillis(str, format, time.Now().UTC()); okP {
			fv := float64(ms)
			return &fv
		}
	}
	return nil
}

func resolveHistogramBoundFloatPtr(bound any) *float64 {
	if bound == nil {
		return nil
	}
	if fv, ok := resolveHistogramMissingFloat(bound); ok {
		return &fv
	}
	return nil
}
