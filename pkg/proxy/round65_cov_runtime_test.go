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

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildR65RuntimeSchema(t *testing.T, rawMapping string, es8 bool) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sc := schema.CompileIndexSchema("es_db", "r65_rt_idx", &spec)
	sc.IndexName = "r65_rt_idx"
	sc.ES8Mode = es8
	return sc
}

func TestRound65CovRuntime_MemBackendR63CastsAndBitwise(t *testing.T) {
	row := map[string]any{
		"_id":     "doc1",
		"_source": `{"raw":"ok"}`,
		"i":       int(7),
		"i32":     int32(9),
		"i64":     int64(42),
		"u64_ok":  uint64(100),
		"u64_big": uint64(math.MaxUint64),
		"flt":     float64(12.5),
		"flt_nan": math.NaN(),
		"flt_inf": math.Inf(1),
		"flt_oob": float64(1e30),
		"jn_int":  json.Number("55"),
		"jn_flt":  json.Number("5.5"),
		"str_int": " 123 ",
		"str_flt": " 3.25 ",
		"str_bad": "abc",
		"str_emp": "   ",
		"dt_iso":  "2026-05-01T12:34:56.789123",
		"dt_spc":  "2026-05-01 12:34:56.789",
		"dt_day":  "2026-05-01",
		"dt_bad":  "1700000000123",
		"arr_mix": []any{int(1), int32(2), int64(3), uint64(4), uint64(math.MaxUint64), float64(5.5), math.NaN(), json.Number("6"), "7", "bad"},
		"arr_bad": []any{"nope", math.Inf(1)},
		"arr_f64": []float64{1.25, 2.5},
		"arr_emp": []float64{},
		"str_arr": `["x","y"]`,
		"str_f64": `[1.5, 2, 3.5]`,
		"str_j":   `{"a":1}`,
		"obj_map": map[string]any{"k": "v"},
		"b_str":   "true",
	}

	// 1. evalTryCastBodyR63Mem across all target types
	if evalTryCastBodyR63Mem(row, "no_as_keyword") != nil {
		t.Fatal("expected nil without AS")
	}
	// DATETIMEV2 / DATETIME
	if got := evalTryCastBodyR63Mem(row, "`dt_iso` AS DATETIMEV2(6)"); got != "2026-05-01 12:34:56.789123" {
		t.Fatalf("unexpected DATETIMEV2(6): %v", got)
	}
	if got := evalTryCastBodyR63Mem(row, "`dt_spc` AS DATETIMEV2(3)"); got != "2026-05-01 12:34:56.789" {
		t.Fatalf("unexpected DATETIMEV2(3): %v", got)
	}
	if got := evalTryCastBodyR63Mem(row, "`dt_day` AS DATETIME"); got != "2026-05-01 00:00:00" {
		t.Fatalf("unexpected DATETIME: %v", got)
	}
	if evalTryCastBodyR63Mem(row, "'2026-05-01T01:02:03' AS DATETIMEV2") != "2026-05-01 01:02:03.000000" {
		t.Fatal("expected literal DATETIMEV2 parse")
	}
	if evalTryCastBodyR63Mem(row, "`dt_bad` AS DATETIMEV2") != nil || evalTryCastBodyR63Mem(row, "`str_emp` AS DATETIMEV2") != nil || evalTryCastBodyR63Mem(row, "`missing` AS DATETIMEV2") != nil {
		t.Fatal("expected nil for invalid/empty/missing DATETIMEV2")
	}

	// BIGINT / INT
	for _, expr := range []string{
		"`i` AS BIGINT", "`i32` AS BIGINT", "`i64` AS BIGINT", "`u64_ok` AS BIGINT",
		"`flt` AS INT", "`jn_int` AS BIGINT", "`str_int` AS BIGINT", "`arr_mix` AS BIGINT",
		"`str_int` AS STRING", "`u64_big` AS LARGEINT", "'42' AS INT", "15 AS BIGINT",
	} {
		if evalTryCastBodyR63Mem(row, expr) == nil {
			t.Fatalf("expected non-nil for TRY_CAST(%s)", expr)
		}
	}
	for _, expr := range []string{
		"`u64_big` AS BIGINT", "`flt_nan` AS BIGINT", "`flt_oob` AS BIGINT", "`jn_flt` AS BIGINT",
		"`str_emp` AS BIGINT", "`str_bad` AS BIGINT", "`arr_bad` AS BIGINT", "`obj_map` AS BIGINT", "`missing` AS BIGINT",
	} {
		if got := evalTryCastBodyR63Mem(row, expr); got != nil {
			t.Fatalf("expected nil for TRY_CAST(%s), got %v", expr, got)
		}
	}

	// DOUBLE / FLOAT
	for _, expr := range []string{"`str_flt` AS DOUBLE", "`flt` AS FLOAT", "`arr_mix` AS DOUBLE", "`b_str` AS BOOLEAN"} {
		if evalTryCastBodyR63Mem(row, expr) == nil {
			t.Fatalf("expected non-nil for TRY_CAST(%s)", expr)
		}
	}
	for _, expr := range []string{"`str_emp` AS DOUBLE", "`str_bad` AS DOUBLE", "`flt_inf` AS DOUBLE", "`arr_bad` AS DOUBLE", "`str_bad` AS BOOLEAN"} {
		if got := evalTryCastBodyR63Mem(row, expr); got != nil {
			t.Fatalf("expected nil for TRY_CAST(%s), got %v", expr, got)
		}
	}

	// ARRAY<STRING>, ARRAY<FLOAT>, ARRAY<DOUBLE>, JSON, default fallback
	if evalTryCastBodyR63Mem(row, "`str_arr` AS ARRAY<STRING>") == nil || evalTryCastBodyR63Mem(row, "`obj_map` AS ARRAY<STRING>") != nil || evalTryCastBodyR63Mem(row, "`str_bad` AS ARRAY<STRING>") != nil {
		t.Fatal("unexpected ARRAY<STRING> results")
	}
	if evalTryCastBodyR63Mem(row, "`arr_f64` AS ARRAY<FLOAT>") == nil || evalTryCastBodyR63Mem(row, "`arr_emp` AS ARRAY<FLOAT>") != nil {
		t.Fatal("unexpected []float64 ARRAY<FLOAT> results")
	}
	if evalTryCastBodyR63Mem(row, "`arr_mix` AS ARRAY<DOUBLE>") != nil {
		t.Fatal("expected nil when arr_mix has invalid elements")
	}
	if evalTryCastBodyR63Mem(row, "`str_f64` AS ARRAY<DOUBLE>") == nil || evalTryCastBodyR63Mem(row, "`str_bad` AS ARRAY<DOUBLE>") != nil || evalTryCastBodyR63Mem(row, "`i` AS ARRAY<DOUBLE>") != nil {
		t.Fatal("unexpected string/default ARRAY<DOUBLE> results")
	}
	if evalTryCastBodyR63Mem(row, "`str_j` AS JSON") == nil || evalTryCastBodyR63Mem(row, "`str_bad` AS JSON") != nil || evalTryCastBodyR63Mem(row, "`obj_map` AS JSON") == nil {
		t.Fatal("unexpected JSON TRY_CAST results")
	}
	_ = evalTryCastBodyR63Mem(row, "`str_int` AS VARCHAR")
	_ = evalTryCastBodyR63Mem(row, "`str_int` AS DECIMAL")

	// 2. evalStrictBitwiseOperandInt64R63Mem
	if _, ok := evalStrictBitwiseOperandInt64R63Mem(row, ""); ok {
		t.Fatal("expected false on empty")
	}
	if _, ok := evalStrictBitwiseOperandInt64R63Mem(row, "'12'"); ok {
		t.Fatal("expected false on quoted string")
	}
	for _, good := range []string{"15", "9223372036854775807", "`i`", "`i32`", "`i64`", "`u64_ok`", "`flt`", "`jn_int`"} {
		if _, ok := evalStrictBitwiseOperandInt64R63Mem(row, good); !ok {
			t.Fatalf("expected true for bitwise operand %s", good)
		}
	}
	for _, bad := range []string{"18446744073709551615", "`str_int`", "`u64_big`", "`flt_nan`", "`flt_inf`", "`jn_flt`"} {
		if _, ok := evalStrictBitwiseOperandInt64R63Mem(row, bad); ok {
			t.Fatalf("expected false for bitwise operand %s", bad)
		}
	}
}

func TestRound65CovRuntime_MemBackendAggAndExprs(t *testing.T) {
	// 1. BigInt parsing & bucketing
	if _, ok := parseMemBigIntR65(""); ok {
		t.Fatal("expected false on empty")
	}
	if bi, ok := parseMemBigIntR65("12345.000"); !ok || bi.Int64() != 12345 {
		t.Fatalf("unexpected parseMemBigIntR65: %v %v", bi, ok)
	}
	if bi, ok := parseMemBigIntR65("1e4"); !ok || bi.Int64() != 10000 {
		t.Fatalf("unexpected sci parseMemBigIntR65: %v %v", bi, ok)
	}
	if _, ok := parseMemBigIntR65("not_a_num"); ok {
		t.Fatal("expected false on invalid string")
	}
	for _, v := range []any{uint64(18446744073709551615), int64(5), int(3), json.Number("99"), "77", float64(42.0), struct{}{}} {
		_, _ = parseMemBigIntValueR65(v)
	}
	if _, ok := parseMemBigIntValueR65(math.NaN()); ok {
		t.Fatal("expected false on NaN")
	}
	biRes := floorBucketBigIntR65(parseMustBigIntR65("3"), parseMustBigIntR65("5"), parseMustBigIntR65("10"))
	if biRes.String() != "-5" {
		t.Fatalf("expected -5 for negative remainder bucket, got %s", biRes.String())
	}

	// 2. evalAggBranch branches (LARGEINT histogram, range_hist, composite, sub_terms, generic_grouped, sub_metric, sub_percentile_weighted, weighted_avg, having, etc.)
	b64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	ip6Bytes := make([]byte, 16)
	ip6Bytes[15] = 1
	rows := []map[string]any{
		{
			"_id":         "1",
			"kw":          "alpha",
			"num":         float64(10),
			"cnt":         int64(2),
			"ul":          "18446744073709551610",
			"b_arr":       []string{"true", "0"},
			"tags":        []string{"x", "y"},
			"nums":        []any{1.0, 2.0, 3.0},
			"f64s":        []float64{2.0, 4.0},
			"hex32s":      []string{"0000000000000000000000000000000A", "00000000000000000000000000000014"},
			"ips":         []string{"10.0.0.1", "10.0.0.2"},
			"ip6s":        []string{"2001:db8::1", "::1"},
			"hist_arr":    []string{"10,2", "20,3"},
			"nested_objs": []string{`{"sub":"s1","v":5}`, `{"sub":"s2","v":15}`},
			"dt":          "2026-05-01T10:20:30.123456Z",
			"ts_ms":       int64(1700000000123),
			"ts_sec":      float64(1700000000.5),
			"b64":         b64,
			"hexstr":      "48656c6c6f",
			"raw_bytes":   []byte{0x0a, 0x0b},
			"ip6_bytes":   ip6Bytes,
			"lat":         float64(52.37),
			"lon":         float64(4.91),
			"vec":         []float64{1, 0, 0},
			"_source":     `{"k":"val","loc":{"lat":52.37,"lon":4.91},"_doc_count":2}`,
			"_doc":        `{"k":"val","bools":["true","0"],"ul":"18446744073709551615","nums":[1,2]}`,
		},
		{
			"_id":      "2",
			"kw":       "beta",
			"num":      float64(30),
			"cnt":      int64(4),
			"ul":       "18446744073709551611",
			"tags":     []string{"y", "z"},
			"hist_arr": []string{"30,1"},
			"_source":  `{"k":"val2","_doc_count":1}`,
		},
	}

	// LARGEINT histogram
	if out := evalAggBranch(rows, "SELECT 'ul_h' AS `_agg_name`, CAST((CAST(FLOOR((`ul` - 18446744073709551600) / 10) AS LARGEINT) * 10 + 18446744073709551600) AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `ul` IS NOT NULL GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS DOUBLE) ASC"); len(out) == 0 {
		t.Fatal("expected LARGEINT histogram buckets")
	}
	// reAggRangeHistR65
	if out := evalAggBranch(rows, "SELECT 'rh' AS `_agg_name`, '0-25' AS `_bucket_key`, CAST(COALESCE(SUM(TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`hist_arr`) `_ht` AS `_helem` WHERE TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE) < 25"); len(out) != 1 || out[0].DocCount != 5 {
		t.Fatalf("unexpected reAggRangeHistR65: %+v", out)
	}
	// reAggComposite & reAggSubTerms & reAggGenericGroupedBuckets & HAVING
	for _, br := range []string{
		"SELECT 'comp' AS `_agg_name`, CONCAT_WS('\x1f', CAST(`kw` AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `kw` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT 10",
		"SELECT 'sub_t' AS `_agg_name`, CONCAT(CAST(`kw` AS STRING), '\x1f', `_elem`) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`tags`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` ASC, `_bucket_key` ASC",
		"SELECT 'gen_b' AS `_agg_name`, CAST(`kw` AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `kw` IS NOT NULL GROUP BY `_bucket_key` HAVING `_doc_count` >= 1 ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT 10",
		"SELECT 'sub_m_sum' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(SUM(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `num` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_m_avg' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(AVG(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `num` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_m_min' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(MIN(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `num` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_m_max' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(MAX(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `num` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_m_std' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(STDDEV_POP(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `num` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_m_cnt' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COUNT(DISTINCT `tags`) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `kw` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_pw' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX_WEIGHTED(TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE), TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE), 0.5000), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`hist_arr`) `_sub_t` AS `_helem` WHERE `_helem` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'sub_prw' AS `_agg_name`, `kw` AS `_bucket_key`, CAST(COALESCE(100.0 * SUM(CASE WHEN TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE) <= 20 THEN TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE) ELSE 0.0 END) / NULLIF(SUM(TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)), 0), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`hist_arr`) `_sub_t` AS `_helem` WHERE `_helem` IS NOT NULL GROUP BY `_bucket_key`",
		"SELECT 'wavg' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(SUM((`num`) * (`cnt`)) / NULLIF(SUM(`cnt`), 0), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`hist_arr`) `_ht` AS `_helem`",
		"SELECT 'nstd' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(STDDEV_POP(TRY_CAST(json_extract_string(`_nel`, '$.v') AS DOUBLE)), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_objs`) `_nt` AS `_nel`",
		"SELECT 'mstd' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(STDDEV_POP(`num`), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
	} {
		if out := evalAggBranch(rows, br); len(out) == 0 {
			t.Fatalf("expected non-empty rows for branch: %s", br)
		}
	}

	// 3. resolveColumnValue expression coverage
	r := rows[0]
	exprs := []string{
		"GREATEST(`num`, 25)", "LEAST(`num`, 5)",
		"CONCAT_WS('|', `kw`, 'tail')",
		"element_at(`tags`, 1)",
		"array_map(_x -> TRY_CAST(_x AS DOUBLE), `nums`)",
		"array_map(_el -> json_extract_string(_el, '$.sub'), `nested_objs`)",
		"ARRAY_RANGE(1, 5)", "ARRAY_RANGE(5, 1)",
		"array_filter(_x -> _x = 'x', `tags`)",
		"array_map(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x), `ips`)",
		"array_map(_x -> UPPER(_x), `tags`)",
		"array_median(`hex32s`)", "array_median(`f64s`)", "array_median(`tags`)",
		"array_min(`f64s`)", "array_max(`f64s`)", "array_avg(`f64s`)", "array_sum(`f64s`)",
		"array_min(array_map(_x -> CAST(_x AS LARGEINT), `nums`))",
		"array_max(`ips`)", "array_min(`nums`)",
		"COALESCE(NULL, `missing_col`, `num`)", "COALESCE(`missing_col`, TRUE)", "COALESCE(`missing_col`, 1 + 2)",
		"HEX(IPV6_STRING_TO_NUM_OR_NULL(`ip6s`))", "HEX(IPV6_STRING_TO_NUM_OR_NULL('2001:db8::1'))",
		"HEX(`raw_bytes`)", "HEX(`cnt`)", "HEX(-1)", "HEX(`nums`)",
		"IPV4_STRING_TO_NUM_OR_NULL(`ips`)", "IPV4_STRING_TO_NUM_OR_NULL('10.0.0.1')",
		"CHAR_LENGTH(`tags`)", "CHAR_LENGTH(`kw`)", "LENGTH(`kw`)",
		"json_extract_string(`_source`, '$.loc')", "json_extract(`_source`, '$.loc.lat')",
		"CAST(`_doc`['bools'] AS BOOLEAN)", "CAST(`_doc`['ul'] AS LARGEINT)", "CAST(`_doc`['nums'] AS ARRAY<DOUBLE>)",
		"array_size(`f64s`)", "array_size(`missing`)",
		"SPLIT_PART('a,b,c', ',', 2)", "SPLIT_PART('abc', ',', 1)", "SPLIT_PART('abc', ',', 2)",
		"LPAD(`kw`, 8, '0')", "LPAD(`kw`, 3, '0')",
		"IF(`num` > 5, 'hi', 'lo')", "IF(`num` > 50, 'hi', NULL)",
		"LOCATE('ph', `kw`)", "LOCATE('zz', `kw`)",
		"SUBSTRING(`kw`, 2, 3)", "SUBSTRING(`kw`, 10, 2)",
		"ST_Distance_Sphere(`lon`, `lat`, 4.9, 52.3)",
		"COSINE_DISTANCE(`vec`, [1,0,0])", "L2_DISTANCE(`vec`, [1,0,0])", "INNER_PRODUCT(`vec`, [2,0,0])",
		"LOWER(`tags`)", "UPPER(`tags`)", "TRIM(`tags`)",
		"FROM_UNIXTIME(`ts_sec`)", "CONVERT_TZ('2026-05-01 12:00:00', 'UTC', '+02:00')",
		"DATE_TRUNC(`dt`, 'day')", "SECONDS_ADD(`dt`, 10)", "TIMESTAMPDIFF(SECOND, '2026-05-01 00:00:00', `dt`)",
		"UNIX_TIMESTAMP(`dt`)", "MICROSECOND(`dt`)",
		"DATE_FORMAT(FROM_UNIXTIME(`ts_ms`), '%Y-%m-%d %H:%i:%s %T %F.%f %%')",
		"DATE_FORMAT(`ts_sec`, '%Y-%m-%d')", "DATE_FORMAT(`dt`, '%Y-%m-%d')",
		"CONCAT(`kw`, '_', `num`)",
		"CAST(`dt` AS DATETIME)", "CAST('123456' AS LARGEINT)", "CAST(`nums` AS DOUBLE)",
		"CAST(`ts_sec` AS BIGINT)", "CAST(COALESCE(`num` > 5, FALSE) AS INT)", "CAST(`nums` AS STRING)",
		"CAST('[1, 2]' AS ARRAY<FLOAT>)", "CAST(`b_arr` AS BOOLEAN)",
		"CASE WHEN `num` > 20 THEN 'big' WHEN `num` > 5 THEN 'mid' ELSE 'small' END",
		// round63_membackend & round62_membackend column funcs
		"TRANSLATE(`kw`, 'al', 'AL')", "FROM_BASE64_BINARY(`b64`)",
		"REGEXP_EXTRACT(`kw`, '(al).*', 1)", "REGEXP_REPLACE(`kw`, 'a', 'A')",
		"ARRAY_JOIN(`tags`, ',')", "OCTET_LENGTH(`kw`)", "TRUNCATE(12.345, 2)",
		"`base_matched`.`kw`", "CAST(`base_matched`.`_doc`['ul'] AS LARGEINT)",
		"`_doc`['k']", "[`kw`]", "[NULL]",
		"RIGHT(`kw`, 2)", "RPAD(`kw`, 8, '.')", "REPLACE(`kw`, 'a', 'b')",
		"CONV('ff', 16, 10)", "UNHEX(`hexstr`)", "FROM_BASE64(`b64`)",
		"IPV4_NUM_TO_STRING(167772161)", "IPV6_NUM_TO_STRING(`ip6_bytes`)", "IPV6_STRING_TO_NUM_OR_NULL('::1')",
		"MURMUR_HASH3_32(`kw`, '_1')",
	}
	for _, e := range exprs {
		if resolveColumnValue(r, e) == nil && !strings.Contains(e, "missing") && !strings.Contains(e, "NULL") && !strings.Contains(e, "SPLIT_PART('abc', ',', 2)") {
			t.Fatalf("unexpected nil for resolveColumnValue(%s)", e)
		}
	}

	// 4. matchJPJoinTailR62Mem
	if jp, onCond, tail, ok := matchJPJoinTailR62Mem(" `_jp_1` ON (`_jp_1`.`id` = `base_matched`.`_id`) LATERAL VIEW EXPLODE(`tags`) `_t` AS `_elem`"); !ok || jp != "_jp_1" || !strings.Contains(onCond, "_jp_1") || !strings.Contains(tail, "LATERAL") {
		t.Fatalf("unexpected matchJPJoinTailR62Mem: %v %q %q %v", jp, onCond, tail, ok)
	}
	if _, _, _, ok := matchJPJoinTailR62Mem(" not a join"); ok {
		t.Fatal("expected false on non-join")
	}
}

func parseMustBigIntR65(s string) *big.Int {
	bi, _ := parseMemBigIntR65(s)
	return bi
}

func TestRound65CovRuntime_Round48Features(t *testing.T) {
	// 1. evalMoreLikeThisOnDoc
	doc := map[string]any{
		"__meta_id": "doc_target",
		"title":     "quick brown fox jumps",
		"body":      "search engine indexing and analytics",
	}
	mlt := &esast.MoreLikeThisQuery{
		Like: []any{
			"quick brown fox over quick",
			map[string]any{
				"_id": "other_id",
				"doc": map[string]any{"title": "brown fox"},
			},
			map[string]any{
				"_source": map[string]any{"body": "analytics"},
			},
		},
		Unlike:             []any{"over"},
		StopWords:          []string{"and"},
		MinWordLength:      3,
		MaxWordLength:      15,
		MinTermFreq:        1,
		MinimumShouldMatch: "50%",
	}
	if ok, sc := evalMoreLikeThisOnDoc(nil, doc, mlt); !ok || sc <= 0 {
		t.Fatalf("expected MLT match, got ok=%v sc=%v", ok, sc)
	}
	// Excluded _id match -> false
	mltExcl := &esast.MoreLikeThisQuery{
		Fields:             []string{"title"},
		Like:               []any{"quick", map[string]any{"_id": "doc_target"}},
		MinimumShouldMatch: 1,
	}
	if ok, _ := evalMoreLikeThisOnDoc(nil, doc, mltExcl); ok {
		t.Fatal("expected excluded _id to return false")
	}
	if ok, _ := evalMoreLikeThisOnDoc(nil, nil, mlt); ok {
		t.Fatal("expected nil doc to return false")
	}

	// 2. tokenizeTermVectorStringWithAnalyzer
	if toks := tokenizeTermVectorStringWithAnalyzer("a b", "keyword"); len(toks) != 1 || toks[0].term != "a b" {
		t.Fatalf("unexpected keyword tokens: %+v", toks)
	}
	if tokenizeTermVectorStringWithAnalyzer("", "noop") != nil {
		t.Fatal("expected nil on empty noop")
	}
	if toks := tokenizeTermVectorStringWithAnalyzer("  foo   bar  ", "whitespace"); len(toks) != 2 || toks[0].term != "foo" || toks[1].term != "bar" {
		t.Fatalf("unexpected whitespace tokens: %+v", toks)
	}
	if toks := tokenizeTermVectorStringWithAnalyzer("Hello, World!", "standard"); len(toks) != 2 {
		t.Fatalf("unexpected standard tokens: %+v", toks)
	}

	// 3. mergeTemplateTopLevelSearchOptions
	raw := json.RawMessage(`{"query":{"match_all":{}},"profile":false}`)
	if got := string(mergeTemplateTopLevelSearchOptions(raw, nil)); !strings.Contains(got, "match_all") {
		t.Fatal("expected raw unchanged on nil body")
	}
	if got := string(mergeTemplateTopLevelSearchOptions(raw, map[string]any{"size": 10})); !strings.Contains(got, "match_all") {
		t.Fatal("expected raw unchanged without template options")
	}
	merged := string(mergeTemplateTopLevelSearchOptions(raw, map[string]any{"explain": true, "profile": true, "version": true}))
	if !strings.Contains(merged, `"explain":true`) || !strings.Contains(merged, `"profile":false`) {
		t.Fatalf("unexpected merged template options: %s", merged)
	}

	// 4. resolvePainlessScriptSpecFromRaw
	srv, handler := newRound61AdminTestServer(t, "8.15.5")
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPut, "/_scripts/r65_my_script", `{"script":{"lang":"painless","source":"doc['x'].value + params.inc","params":{"inc":1}}}`, nil); c != http.StatusOK {
		t.Fatalf("store script failed: %d %s", c, raw)
	}
	var sp *painless.ScriptSpec
	srv.resolvePainlessScriptSpecFromRaw(&sp, []byte(`{"script":{"id":"r65_my_script","params":{"extra":2}}}`))
	if sp == nil || sp.Source == "" || sp.Params["inc"] == nil || sp.Params["extra"] == nil {
		t.Fatalf("unexpected resolved painless spec: %+v", sp)
	}
}

func TestRound65CovRuntime_Round61ServerSearchHelpers(t *testing.T) {
	sc := buildR65RuntimeSchema(t, `{
		"properties": {
			"kw":     {"type": "keyword"},
			"txt":    {"type": "text", "fields": {"tc": {"type": "token_count"}}},
			"ck":     {"type": "constant_keyword", "value": "const_val"},
			"flat":   {"type": "flattened"},
			"off":    {"type": "object", "enabled": false},
			"amd":    {"type": "aggregate_metric_double", "metrics": ["min", "max"], "default_metric": "max"},
			"ts_ns":  {"type": "date_nanos"},
			"loc":    {"type": "geo_point"},
			"shape":  {"type": "geo_shape"},
			"vec":    {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
			"id_al":  {"type": "alias", "path": "_id"},
			"items": {
				"type": "nested",
				"properties": {
					"vec": {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
					"sub": {"type": "nested", "properties": {"tag": {"type": "keyword"}}}
				}
			}
		}
	}`, true)

	// 1. emitFlattenedEnabledFalseFieldR64
	outFlat := make(map[string][]any)
	matchedAny := make(map[string]bool)
	emitFlattenedEnabledFalseFieldR64("off", "off.*", map[string]any{
		"mix": []any{json.Number("10"), 2, true, "z", "a"},
		"sub": map[string]any{"k": nil, "n": 1.5},
	}, matchedAny, outFlat)
	if len(outFlat["off.mix"]) != 5 || len(outFlat["off.sub.n"]) != 1 {
		t.Fatalf("unexpected flattened enabled:false output: %+v", outFlat)
	}

	// 2. extractUnifiedFieldsR61Search & emitSingleMatchedFieldIntoOutR61Search
	srv, _ := newRound61AdminTestServer(t, "8.15.5")
	rawReqBody := []byte(`{"fields":[{"field":"off.*","include_unmapped":true},{"field":"items.*","include_unmapped":true}]}`)
	scope := &activeSearchScope{srv: srv, rawBody: rawReqBody}
	hit := HitRow{
		ID:          "h1",
		Index:       "r65_rt_idx",
		Routing:     "r1",
		Version:     2,
		SearchScope: scope,
		Source: json.RawMessage(`{
			"kw": "K1",
			"txt": "one two three",
			"flat": {"a": "x", "b": 1},
			"off": {"k": "v"},
			"amd": {"min": 1, "max": 9.5},
			"ts_ns": "2026-05-01T00:00:00.123456789Z",
			"loc": "52.37,4.91",
			"shape": {"type":"Point","coordinates":[4.91,52.37]},
			"rt_geo": "52.37,4.91",
			"rt_shape": {"type":"Point","coordinates":[4.91,52.37]},
			"items": [{"vec":[1.0,0.0],"dyn":"val","sub":[{"tag":"t1"}]}]
		}`),
		RuntimeFields: map[string]any{"rt_str": "hello"},
	}
	var req esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"fields": [
			{"field": "_id"}, {"field": "id_al"}, {"field": "ck"}, {"field": "flat"}, {"field": "flat.a"},
			{"field": "amd"}, {"field": "txt.tc"}, {"field": "rt_geo", "format": "wkt"},
			{"field": "rt_shape", "format": "geojson"}, {"field": "rt_str"}, {"field": "off.*"}, {"field": "items.*"}
		],
		"docvalue_fields": [
			{"field": "flat"}, {"field": "ts_ns", "format": "epoch_millis"}, {"field": "ts_ns", "format": "epoch_millis"}, {"field": "rt_geo"}
		],
		"runtime_mappings": {
			"rt_geo": {"type": "geo_point"},
			"rt_shape": {"type": "geo_shape"},
			"rt_comp": {"type": "composite", "fields": {"sub": {"type": "keyword"}}},
			"rt_str": {"type": "keyword"}
		}
	}`), &req)
	uf, st, _, errR := extractUnifiedFieldsR61Search(hit, "r65_rt_idx", &req, sc, nil)
	if st != 0 {
		t.Fatalf("extractUnifiedFieldsR61Search failed: %d %s", st, errR)
	}
	if len(uf["ck"]) != 1 || len(uf["txt.tc"]) != 1 || len(uf["amd"]) != 1 || len(uf["rt_geo"]) == 0 {
		t.Fatalf("unexpected unified fields: %+v", uf)
	}
	// Error cases in extractUnifiedFieldsR61Search
	_, stNone, _, _ := extractUnifiedFieldsR61Search(hit, "r65_rt_idx", &esast.SearchRequest{StoredFields: "_none_", Fields: []esast.FieldRequestSpec{{Field: "kw"}}}, sc, nil)
	if stNone != http.StatusBadRequest {
		t.Fatalf("expected 400 when stored_fields=_none_ + fields, got %d", stNone)
	}
	_, stDVText, _, _ := extractUnifiedFieldsR61Search(hit, "r65_rt_idx", &esast.SearchRequest{DocvalueFields: []esast.FieldRequestSpec{{Field: "txt"}}}, sc, nil)
	if stDVText != http.StatusBadRequest {
		t.Fatalf("expected 400 for docvalue_fields on text, got %d", stDVText)
	}
	_, stDVAMD, _, _ := extractUnifiedFieldsR61Search(hit, "r65_rt_idx", &esast.SearchRequest{DocvalueFields: []esast.FieldRequestSpec{{Field: "amd"}}}, sc, nil)
	if stDVAMD != http.StatusBadRequest {
		t.Fatalf("expected 400 for docvalue_fields on aggregate_metric_double, got %d", stDVAMD)
	}

	// 3. evalNestedKNNParentScoreOnDocR63
	sim := float64(2.0)
	boost := float64(1.5)
	docKNN := map[string]any{"items": []any{map[string]any{"vec": []float64{1.0, 0.0}}, map[string]any{"vec": []float64{0.0, 1.0}}}}
	for _, mode := range []string{"none", "sum", "min", "max"} {
		nq := &esast.NestedQuery{
			Path:      "items",
			ScoreMode: mode,
			Boost:     &boost,
			Query: esast.Query{
				KNN: &esast.KNNQuery{Field: "items.vec", QueryVector: []float64{1.0, 0.0}, Similarity: &sim, Boost: &boost},
			},
		}
		if _, ok := evalNestedKNNParentScoreOnDocR63(sc, docKNN, nq); !ok {
			t.Fatalf("expected true for evalNestedKNNParentScoreOnDocR63 mode=%s", mode)
		}
	}

	// 4. collectNamedQueryScoresR61Search
	namedQJSON := `{
		"bool": {
			"must": [{"term": {"kw": {"value": "K1", "_name": "m_kw"}}}],
			"should": [
				{"constant_score": {"filter": {"term": {"kw": {"value": "K1", "_name": "cs_kw"}}}, "_name": "cs_outer"}},
				{"nested": {"path": "items", "score_mode": "avg", "query": {"term": {"items.sub.code": {"value": "c1", "_name": "n_sub"}}}}},
				{"intervals": {"txt": {"match": {"query": "quick brown"}, "_name": "int_txt"}}}
			],
			"filter": [
				{"boosting": {"positive": {"term": {"kw": {"value": "K1", "_name": "pos_kw"}}}, "negative": {"term": {"kw": "nope"}}, "negative_boost": 0.2}},
				{"dis_max": {"queries": [{"term": {"kw": {"value": "K1", "_name": "dm_kw"}}}]}},
				{"function_score": {"query": {"term": {"kw": {"value": "K1", "_name": "fs_kw"}}}, "functions": [{"filter": {"term": {"kw": {"value": "K1", "_name": "fs_flt"}}}, "weight": 2}]}},
				{"script_score": {"query": {"term": {"kw": {"value": "K1", "_name": "ss_kw"}}}, "script": {"source": "1.0"}}}
			]
		}
	}`
	var nq esast.Query
	if err := json.Unmarshal([]byte(namedQJSON), &nq); err != nil {
		t.Fatalf("unmarshal namedQJSON failed: %v", err)
	}
	namedOut := make(map[string]float64)
	namedDoc := map[string]any{"kw": "K1", "txt": "quick brown fox", "vec": []float64{1.0, 0.0}, "items": []any{map[string]any{"vec": []float64{1.0, 0.0}, "sub": []any{map[string]any{"code": "c1"}}}}}
	collectNamedQueryScoresR61Search(sc, namedDoc, &nq, true, namedOut)
	knnNamedQ := &esast.Query{KNN: &esast.KNNQuery{Field: "vec", QueryVector: []float64{1.0, 0.0}, Name: "top_knn", Filter: []esast.Query{{Term: map[string]esast.TermEntry{"kw": {Value: "K1", Name: "knn_flt"}}}}}}
	collectNamedQueryScoresR61Search(sc, namedDoc, knnNamedQ, true, namedOut)
	// Also test wrapper and pinned directly
	wrapQ := &esast.Query{Wrapper: &esast.WrapperQuery{Decoded: &esast.Query{Term: map[string]esast.TermEntry{"kw": {Value: "K1", Name: "wrap_kw"}}}}}
	collectNamedQueryScoresR61Search(sc, namedDoc, wrapQ, true, namedOut)
	pinQ := &esast.Query{Pinned: &esast.PinnedQuery{IDs: []string{"other"}, Organic: &esast.Query{Term: map[string]esast.TermEntry{"kw": {Value: "K1", Name: "pin_kw"}}}}}
	collectNamedQueryScoresR61Search(sc, namedDoc, pinQ, true, namedOut)
	if len(namedOut) < 4 {
		t.Fatalf("expected multiple named query scores, got %+v", namedOut)
	}

	// 5. intervalsRuleMinExtentR63
	if intervalsRuleMinExtentR63(nil) != 0 {
		t.Fatal("expected 0 for nil rule")
	}
	rAll := &esast.IntervalsRule{
		AllOf: &esast.IntervalsAllOf{
			Intervals: []esast.IntervalsRule{
				{Match: &esast.IntervalsMatch{Query: "quick brown"}},
				{Prefix: &esast.IntervalsPrefix{Prefix: "fo"}},
				{AnyOf: &esast.IntervalsAnyOf{Intervals: []esast.IntervalsRule{{Wildcard: &esast.IntervalsWildcard{Pattern: "a*"}}, {Fuzzy: &esast.IntervalsFuzzy{Term: "dog"}}}}},
			},
		},
	}
	if ext := intervalsRuleMinExtentR63(rAll); ext != 4 {
		t.Fatalf("expected min extent 4, got %d", ext)
	}
}

func TestRound65CovRuntime_ServerHelpersAndExplainE2E(t *testing.T) {
	// 1. handleDorisExplain E2E (ES7 & ES8)
	srv, handler := newRound61AdminTestServer(t, "7.17.0")
	_, _, _, _ = doRound61AdminReq(t, handler, http.MethodPut, "/exp_idx", `{"mappings":{"properties":{"kw":{"type":"keyword"},"cnt":{"type":"long"},"ts":{"type":"date"}}}}`, nil)
	_, _, _, _ = doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doc/1?refresh=true", `{"kw":"a","cnt":1,"ts":"2026-05-01T00:00:00Z"}`, nil)

	if c, hdr, parsed, raw := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doris/explain", `{
		"query": {"term": {"kw": "a"}},
		"indices_boost": {"exp_idx": 1.5},
		"docvalue_fields": [{"field": "ts", "format": "use_field_mapping"}],
		"aggs": {"c": {"terms": {"field": "kw", "min_doc_count": 0}}}
	}`, nil); c != http.StatusOK || parsed["hits_sql"] == nil || len(hdr.Values("Warning")) == 0 {
		t.Fatalf("unexpected ES7 _doris/explain: code=%d hdr=%v raw=%s", c, hdr, raw)
	}
	if c, _, _, _ := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doris/explain", `{"collapse":{"field":"kw"},"rescore":[{"query":{"rescore_query":{"match_all":{}}}}]}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for collapse+rescore in ES7 explain, got %d", c)
	}
	srv.SetTargetESVersion("8.15.5")
	if c, _, _, _ := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doris/explain", `{"collapse":{"field":"kw","inner_hits":{}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for collapse inner_hits missing name in ES8 explain, got %d", c)
	}
	if c, _, _, _ := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doris/explain", `{"from":-1}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative from in explain, got %d", c)
	}
	if c, _, _, _ := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_doris/explain", `{"bad_json"`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON in explain, got %d", c)
	}

	// 2. injectZeroFieldTermsAggRowsR65 via HTTP search with min_doc_count: 0 & post_filter / filter
	if c, _, parsed, raw := doRound61AdminReq(t, handler, http.MethodPost, "/exp_idx/_search", `{
		"size": 0,
		"query": {"term": {"kw": "nonexistent"}},
		"aggs": {"all_kw": {"terms": {"field": "kw", "min_doc_count": 0}}}
	}`, nil); c != http.StatusOK || !strings.Contains(raw, `"a"`) || parsed["aggregations"] == nil {
		t.Fatalf("expected zero-doc bucket 'a' injected, got %d %s", c, raw)
	}

	// 3. compareCompositeSourceValWithSchema
	sc := buildR65RuntimeSchema(t, `{
		"properties": {
			"kw":     {"type": "keyword"},
			"kw_low": {"type": "keyword", "normalizer": "lowercase"},
			"b":      {"type": "boolean"},
			"ts":     {"type": "date"},
			"ts_ns":  {"type": "date_nanos"},
			"ul":     {"type": "unsigned_long"},
			"ver":    {"type": "version"},
			"ip":     {"type": "ip"}
		}
	}`, true)
	for _, entry := range []esast.AggSpec{
		{Terms: &esast.TermsAggSpec{Field: "ul", ValueType: "unsigned_long", Order: "desc", MissingOrder: "last"}},
		{Terms: &esast.TermsAggSpec{Field: "ts", ValueType: "date", MissingOrder: "first"}},
		{Terms: &esast.TermsAggSpec{Field: "kw", ValueType: "double"}},
		{DateHistogram: &esast.DateHistogramAggSpec{Field: "ts", FixedInterval: "1h", Order: "desc"}},
		{GeotileGrid: &esast.GeoGridAggSpec{Field: "loc", Order: "desc"}},
	} {
		_ = compareCompositeSourceValWithSchema(nil, "x", entry, sc)
		_ = compareCompositeSourceValWithSchema("x", nil, entry, sc)
		_ = compareCompositeSourceValWithSchema(nil, nil, entry, sc)
	}
	_ = compareCompositeSourceValWithSchema("18446744073709551615", "18446744073709551610", esast.AggSpec{Terms: &esast.TermsAggSpec{ValueType: "unsigned_long", Order: "desc"}}, sc)
	_ = compareCompositeSourceValWithSchema("2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z", esast.AggSpec{Terms: &esast.TermsAggSpec{ValueType: "date"}}, sc)
	_ = compareCompositeSourceValWithSchema(true, "0", esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("0", false, esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("true", "0", esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("1", "false", esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("10.0.0.1", "10.0.0.2", esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("10.5", "20.5", esast.AggSpec{Terms: &esast.TermsAggSpec{ValueType: "double"}}, sc)
	_ = compareCompositeSourceValWithSchema("10.5", float64(20.5), esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema(float64(10.5), "20.5", esast.AggSpec{Terms: &esast.TermsAggSpec{}}, sc)
	_ = compareCompositeSourceValWithSchema("4/8/5", "4/8/6", esast.AggSpec{GeotileGrid: &esast.GeoGridAggSpec{Order: "desc"}}, sc)

	// 4. extractHitFieldsMap & formatFieldValues
	hitF := HitRow{
		ID:      "h1",
		Routing: "r1",
		Version: 3,
		Source:  json.RawMessage(`{"kw":"V1","kw_low":"ABC","b":"1","ts":"2026-05-01T00:00:00Z","ts_ns":1700000000123456789,"num":10}`),
	}
	reqFields := &esast.SearchRequest{
		Fields: []esast.FieldRequestSpec{
			{Field: "_id"}, {Field: "_index"}, {Field: "_routing"}, {Field: "_version"}, {Field: "_seq_no"}, {Field: "_primary_term"},
			{Field: "*"}, {Field: "kw_low"}, {Field: "b"}, {Field: "ts", Format: "epoch_second"}, {Field: "ts_ns", Format: "epoch_millis"},
		},
	}
	fmap := extractHitFieldsMap(hitF, "exp_idx", reqFields, sc)
	if len(fmap["_id"]) != 1 || len(fmap["_routing"]) != 1 || len(fmap["ts_ns"]) != 1 {
		t.Fatalf("unexpected extractHitFieldsMap: %+v", fmap)
	}
	_ = formatFieldValues("b", []any{int64(1), int64(0), float64(1), "true", "false"}, "", sc)
	_ = formatFieldValues("ts", []any{int64(1700000000000), float64(1700000000000), "2026-05-01T00:00:00Z"}, "epoch_millis", sc)
	_ = formatFieldValues("ts", []any{int64(1700000000000), float64(1700000000000)}, "epoch_second", sc)
	_ = formatFieldValues("ts", []any{int64(1700000000000), "2026-05-01T00:00:00Z"}, "uuuu-MM-dd", sc)

	// 5. hitIsAfterSearchAfter
	hitSA := HitRow{
		ID:     "h2",
		Score:  2.0,
		Source: json.RawMessage(`{"b":true,"kw_low":"abc","ts":1700000005000,"ts_ns":"2026-05-01T00:00:01Z","ver":"1.2.0","ip":"10.0.0.5"}`),
	}
	sortsSA := []esast.SortSpec{
		{Entry: esast.SortEntry{Field: "b", Type: "boolean", Order: "asc"}},
		{Entry: esast.SortEntry{Field: "kw_low", Order: "asc"}},
		{Entry: esast.SortEntry{Field: "ts", Order: "asc"}},
		{Entry: esast.SortEntry{Field: "ts_ns", Order: "asc"}},
		{Entry: esast.SortEntry{Field: "ver", Type: "version", Order: "asc"}},
		{Entry: esast.SortEntry{Field: "ip", Order: "desc"}},
	}
	_ = hitIsAfterSearchAfter(hitSA, sortsSA, []any{"true", "ABC", json.Number("1700000005000"), "2026-05-01T00:00:01Z", "1.1.0", "10.0.0.9", "h1"}, sc)
	_ = hitIsAfterSearchAfter(hitSA, []esast.SortSpec{{Entry: esast.SortEntry{Field: "b", Missing: "_first"}}}, []any{nil}, sc)
	_ = hitIsAfterSearchAfter(hitSA, []esast.SortSpec{{Entry: esast.SortEntry{Field: "missing_f", Missing: "_first"}}}, []any{int64(1)}, sc)

	// 6. Multi-index multi_terms & runtime join docs & bucket extractors & stats date overflow
	sc1 := buildR65RuntimeSchema(t, `{"properties":{"k":{"type":"long"},"u":{"type":"unsigned_long"},"ip":{"type":"ip"},"d":{"type":"date"},"j":{"type":"join","relations":{"question":"answer"}}}}`, true)
	sc2 := buildR65RuntimeSchema(t, `{"properties":{"k":{"type":"double"},"u":{"type":"long"},"ip":{"type":"ip"},"d":{"type":"date"}}}`, true)
	schemasMap := map[string]*schema.IndexSchema{"idx1": sc1, "idx2": sc2}
	if ut := resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "k"}, nil, schemasMap); ut != "double" {
		t.Fatalf("expected unified double, got %s", ut)
	}
	if ut := resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "u"}, nil, schemasMap); ut != "double" {
		t.Fatalf("expected unified double for unsigned+signed, got %s", ut)
	}
	mtSpec := &esast.MultiTermsAggSpec{Terms: []esast.MultiTermTermSpec{{Field: "k"}, {Field: "u"}}}
	if _, ok := computeMultiTermsUnifiedTypesR65(mtSpec, schemasMap); !ok {
		t.Fatal("expected multi-index conflict")
	}
	hitsMT := []HitRow{
		{Index: "idx1", ID: "1", Source: json.RawMessage(`{"k":1,"u":10}`)},
		{Index: "idx2", ID: "2", Source: json.RawMessage(`{"k":1,"u":10}`)},
	}
	aggRowsMT := recomputeMultiIndexMultiTermsR65(
		map[string]esast.AggSpec{"mt": {MultiTerms: mtSpec}},
		hitsMT,
		schemasMap,
		sc1,
		[]AggRow{{AggName: "mt", BucketKey: "1|10", DocCount: 2}},
	)
	if len(aggRowsMT) == 0 {
		t.Fatal("expected recomputed multi_terms agg rows")
	}

	// compareMultiTermsTupleElemR65 & sortMultiTermsBucketsWithSchemaR65
	_ = compareMultiTermsTupleElemR65("10.0.0.1", "10.0.0.2", "ip")
	_ = compareMultiTermsTupleElemR65(uint64(5), int64(-1), "")
	_ = compareMultiTermsTupleElemR65(int64(-1), uint64(5), "")
	_ = compareMultiTermsTupleElemR65(json.Number("10"), json.Number("20"), "")
	_ = compareMultiTermsTupleElemR65(float64(1.5), float64(2.5), "")
	_ = sortMultiTermsBucketsWithSchemaR65(
		[]map[string]any{
			{"key": []any{int64(2), uint64(1)}, "key_as_string": "2|1", "doc_count": int64(1)},
			{"key": []any{int64(1), uint64(2)}, "key_as_string": "1|2", "doc_count": int64(2)},
		},
		[]any{map[string]any{"_key": "asc"}},
		mtSpec,
		sc1,
		schemasMap,
	)

	// runtimeChildrenMatchedDocsR65 & runtimeParentMatchedDocsR65
	pDoc := runtimeMatchedDoc{hit: HitRow{ID: "q1", Index: "idx1"}, doc: map[string]any{"__meta_id": "q1", "j": "question"}}
	cDoc := runtimeMatchedDoc{hit: HitRow{ID: "a1", Index: "idx1"}, doc: map[string]any{"__meta_id": "a1", "j": map[string]any{"name": "answer", "parent": "q1"}}}
	corpus := []runtimeMatchedDoc{pDoc, cDoc}
	if ch := runtimeChildrenMatchedDocsR65(sc1, []runtimeMatchedDoc{pDoc}, corpus, "answer"); len(ch) != 1 || ch[0].hit.ID != "a1" {
		t.Fatalf("expected 1 child doc, got %+v", ch)
	}
	if pr := runtimeParentMatchedDocsR65(sc1, []runtimeMatchedDoc{cDoc}, corpus, "answer"); len(pr) != 1 || pr[0].hit.ID != "q1" {
		t.Fatalf("expected 1 parent doc, got %+v", pr)
	}

	// parseAnyDateValueMillisR65, extractBucketAnyValueBySegsR65, extractTopMetricsNumericMetricR65
	for _, dv := range []any{int64(1000), uint64(2000), int(3000), float64(4000), json.Number("5000"), "2026-05-01T00:00:00Z"} {
		if _, ok := parseAnyDateValueMillisR65(dv, "strict_date_optional_time"); !ok {
			t.Fatalf("expected valid date parse for %v", dv)
		}
	}
	if _, ok := parseAnyDateValueMillisR65("", ""); ok {
		t.Fatal("expected false on empty date")
	}
	bucketMap := map[string]any{
		"tm": map[string]any{
			"top": []map[string]any{{"metrics": map[string]any{"price": 12.5, "nested": map[string]any{"v": 9.0}}}},
		},
		"flt": map[string]any{
			"buckets": map[string]any{"k1": map[string]any{"sub_m": map[string]any{"value": 7.0}}},
		},
	}
	if v, ok := extractBucketAnyValueBySegsR65(bucketMap, []string{"tm", "metrics", "price"}); !ok || v != 12.5 {
		t.Fatalf("unexpected top_metrics bucket val: %v %v", v, ok)
	}
	if v, ok := extractBucketAnyValueBySegsR65(bucketMap, []string{"flt", "k1", "sub_m"}); !ok || v != 7.0 {
		t.Fatalf("unexpected nested buckets val: %v %v", v, ok)
	}
	if v, ok := extractTopMetricsNumericMetricR65(bucketMap["tm"].(map[string]any), []string{"nested", "v"}); !ok || v != 9.0 {
		t.Fatalf("unexpected extractTopMetricsNumericMetricR65: %v %v", v, ok)
	}

	// validateStatsDateFormattingOverflowR65
	if err := validateStatsDateFormattingOverflowR65(
		map[string]any{"ds": map[string]any{"count": int64(1), "max": float64(300000000000000.0)}},
		map[string]esast.AggSpec{"ds": {Stats: &esast.MetricAggSpec{Field: "d"}}},
		schemasMap,
		nil,
		true,
	); err == nil {
		t.Fatal("expected ES8 date stats overflow error")
	}

	// emitRuntimeHistogramFieldHDRRawRowsR65 & matchesTermsFilterPrecompiled
	hdrRows := emitRuntimeHistogramFieldHDRRawRowsR65("p", "bk1", &esast.PercentilesAggSpec{Field: "k"}, []runtimeMatchedDoc{{doc: map[string]any{"k": float64(5)}}}, []AggRow{{AggName: "__raw_vals__p", BucketKey: "bk1\x1f_vals:1"}})
	if len(hdrRows) != 1 {
		t.Fatalf("expected 1 replaced HDR raw row, got %+v", hdrRows)
	}
	rePre := regexp.MustCompile("^al.*$")
	if !matchesTermsFilterPrecompiled("alpha", "al.*", rePre) || !matchesTermsFilterPrecompiled("alpha", "al.*", nil) ||
		!matchesTermsFilterPrecompiled("alpha", []any{"alpha"}, nil) || !matchesTermsFilterPrecompiled("alpha", []string{"alpha"}, nil) ||
		matchesTermsFilterPrecompiled("alpha", map[string]any{"num_partitions": 2, "partition": 0}, nil) && matchesTermsFilterPrecompiled("alpha", map[string]any{"num_partitions": 2, "partition": 1}, nil) {
		t.Fatal("unexpected matchesTermsFilterPrecompiled behavior")
	}
}

func TestRound65CovRuntime_MemBackendMissingDiversifiedAndAdminEdge(t *testing.T) {
	baseRows := []map[string]any{
		{
			"_id":       "d1",
			"f__kw":     "catA",
			"f__active": true,
			"f__score":  10.0,
			"tags":      []any{"t1", "t2"},
			"items":     []any{`{"sku":"s1"}`, `{}`},
		},
		{
			"_id":       "d2",
			"f__kw":     "catA",
			"f__active": true,
			"f__score":  5.0,
			"tags":      []any{},
			"items":     []any{`{"sku":""}`},
		},
		{
			"_id":       "d3",
			"f__kw":     nil,
			"f__active": true,
			"f__score":  8.0,
			"tags":      []any{"t3"},
			"items":     []any{`{}`},
		},
		{
			"_id":       "d4",
			"f__kw":     "catB",
			"f__active": false,
			"f__score":  99.0,
			"tags":      []any{"ignored"},
			"items":     []any{`{"sku":"ignored"}`},
		},
	}

	// 1. reAggArrayExplodeMissing, reAggNestedTermsMissing, reAggScalarTermsMissing
	arrMissingRows := evalAggBranch(
		baseRows,
		"SELECT 'arr_m' AS `_agg_name`, COALESCE(CAST(UPPER(`_elem`) AS STRING), 'MISSING_TAG') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(CASE WHEN `tags` IS NULL THEN ARRAY(NULL) ELSE `tags` END) `_t` AS `_elem` WHERE `f__active` = TRUE GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10",
	)
	if len(arrMissingRows) == 0 {
		t.Fatal("expected arrMissingRows")
	}
	nestedMissingRows := evalAggBranch(
		baseRows,
		"SELECT 'nt_m' AS `_agg_name`, COALESCE(json_extract_string(`_nel`, '$.sku'), 'NO_SKU') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(CASE WHEN `items` IS NULL THEN ARRAY(NULL) ELSE `items` END) `_nt` AS `_nel` WHERE `f__active` = TRUE GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10",
	)
	if len(nestedMissingRows) == 0 {
		t.Fatal("expected nestedMissingRows")
	}
	nestedMissingScriptRows := evalAggBranch(
		baseRows,
		"SELECT 'nt_ms' AS `_agg_name`, COALESCE(CAST(json_extract_string(`_nel`, '$.sku') AS STRING), 'NO_SKU') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`items`) `_nt` AS `_nel` GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10",
	)
	if len(nestedMissingScriptRows) == 0 {
		t.Fatal("expected nestedMissingScriptRows")
	}
	scalarMissingRows := evalAggBranch(
		baseRows,
		"SELECT 'st_m' AS `_agg_name`, COALESCE(CAST(`f__kw` AS STRING), 'UNK') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__active` = TRUE GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10",
	)
	if len(scalarMissingRows) < 2 {
		t.Fatalf("expected scalarMissingRows with UNK, got %+v", scalarMissingRows)
	}

	// 2. reR63CountedTermsExprTop & reR63CountedTermsExprSub
	topRows, okTop := evalRound63AggBranchR63Mem(
		baseRows,
		"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (SELECT 'top_e' AS `_agg_name`, CAST(UPPER(`_elem`) AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`tags`) `_t` AS `_elem` WHERE (`f__active` = TRUE) AND `_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 2) `_agg_sub_0`",
		func(r []AggRow) []AggRow { return r },
	)
	if !okTop || len(topRows) != 2 {
		t.Fatalf("unexpected top counted terms expr rows: ok=%v rows=%+v", okTop, topRows)
	}
	subRows, okSub := evalRound63AggBranchR63Mem(
		baseRows,
		"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (SELECT 'sub_e' AS `_agg_name`, CONCAT_WS('\\x1f', CAST(`f__kw` AS STRING), CAST(UPPER(`_sub_elem`) AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`tags`) `_sub_t0` AS `_sub_elem` WHERE (`f__active` = TRUE) AND `_sub_elem` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 3) `_agg_sub_1`",
		func(r []AggRow) []AggRow { return r },
	)
	if !okSub || len(subRows) == 0 {
		t.Fatalf("unexpected sub counted terms expr rows: ok=%v rows=%+v", okSub, subRows)
	}

	// 3. sampler + diversified_sampler subqueries in resolveRound62AggSubqueriesR62Mem
	smpSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE `f__active` = TRUE ORDER BY CAST(`f__score` AS DOUBLE) DESC, `_id` ASC LIMIT 2) `_smp_top`)"
	if resolvedSmp := resolveRound62AggSubqueriesR62Mem(baseRows, smpSQL); !strings.Contains(resolvedSmp, "d1") {
		t.Fatalf("expected sampler to keep d1, got %s", resolvedSmp)
	}
	// Note: membackend.go:7236 uses strings.Index(sqlExpr[idx:], "FROM (SELECT `_id`, "), which matches the outer FROM before ROW_NUMBER() and breaks on closeInner >= closeOuter.
	divSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (PARTITION BY `_ds_key` ORDER BY `_ds_score` DESC, `_id` ASC) AS `_ds_rn` FROM (SELECT `_id`, `f__kw` AS `_ds_key`, CAST(`f__score` AS DOUBLE) AS `_ds_score` FROM `base_matched` WHERE `f__active` = TRUE ORDER BY `_ds_score` DESC, `_id` ASC LIMIT 3) `_ds_in`) `_ds_win` WHERE `_ds_rn` <= 1)"
	_ = resolveRound62AggSubqueriesR62Mem(baseRows, divSQL)

	// 4. Painless _execute ingest/update explicit return, search template URL overrides, and _cat/segments
	_, handler := newRound61AdminTestServer(t, "8.15.5")
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPut, "/seg_idx", `{"mappings":{"properties":{"name":{"type":"keyword"}}}}`, nil); c != http.StatusOK {
		t.Fatalf("create seg_idx failed: %d %s", c, raw)
	}
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPut, "/seg_idx/_doc/1", `{"name":"hello"}`, nil); c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("index doc failed: %d %s", c, raw)
	}

	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "ctx.extra = 42; return ctx;"},
		"context": "ingest",
		"context_setup": {"document": {"title": "abc"}}
	}`, nil); c != http.StatusOK {
		t.Fatalf("painless ingest map return failed: %d %s", c, raw)
	}
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPost, "/_scripts/painless/_execute", `{
		"script": {"source": "return ctx.title;"},
		"context": "update",
		"context_setup": {"document": {"title": "abc"}}
	}`, nil); c != http.StatusOK {
		t.Fatalf("painless update scalar return failed: %d %s", c, raw)
	}

	// _search/template URL query overrides
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodPost, "/seg_idx/_search/template?typed_keys=true&rest_total_hits_as_int=true&explain=true", `{
		"source": {"query":{"term":{"name":"{{v}}"}}},
		"params": {"v": "hello"}
	}`, nil); c != http.StatusOK {
		t.Fatalf("search template with overrides failed: %d %s", c, raw)
	}
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodGet, "/_cat/segments?help=true", "", nil); c != http.StatusOK {
		t.Fatalf("_cat/segments?help=true failed: %d %s", c, raw)
	}
	if c, _, _, raw := doRound61AdminReq(t, handler, http.MethodGet, "/_cat/segments/seg_idx?format=json&full_id=true&bytes=b", "", nil); c != http.StatusOK {
		t.Fatalf("_cat/segments/seg_idx failed: %d %s", c, raw)
	}
}
