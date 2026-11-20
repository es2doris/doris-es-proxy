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
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound63_F10_MemBackendStrictCastJSONTypeAndConv(t *testing.T) {
	mb := NewMemoryBackend(false)
	ctx := context.Background()
	if err := mb.ExecDDL(ctx, "CREATE TABLE `doris_es`.`idx_r63` (`_id` VARCHAR(512), `f__kw` VARCHAR(1024), `f__str` STRING)"); err != nil {
		t.Fatal(err)
	}
	ndjson := []byte(`{"_id":"1","_version":1,"__DORIS_DELETE_SIGN__":0,"f__kw":18446744073709551615,"f__str":true,"_source":"{\"msg\":\"[WARN] retry [1]\",\"ts\":\"2023-11-14T22:13:20.123Z\",\"ts_ns\":\"2023-11-14T22:13:20.123456789Z\",\"a\\\"b\\\\c\":\"escaped-ok\",\"tags\":[\"x\",\"y\"],\"vec\":[1.5,2.5]}"}` + "\n")
	if err := mb.StreamLoad(ctx, "idx_r63", ndjson, true); err != nil {
		t.Fatal(err)
	}
	row := mb.tables["idx_r63"]["1"]
	if s, ok := row["f__kw"].(string); !ok || s != "18446744073709551615" {
		t.Fatalf("expected VARCHAR DDL StreamLoad coercion to string \"18446744073709551615\", got %T %v", row["f__kw"], row["f__kw"])
	}
	if s, ok := row["f__str"].(string); !ok || s != "true" {
		t.Fatalf("expected STRING DDL StreamLoad coercion to string \"true\", got %T %v", row["f__str"], row["f__str"])
	}

	// 1. `CONV(...)` returns `string` (`VARCHAR`), and unwrapped `CONV(...) & mask` is rejected!
	convVal := resolveColumnValue(row, "CONV('FE800000', 16, 10)")
	if s, ok := convVal.(string); !ok || s != "4269801472" {
		t.Fatalf("expected CONV to return string \"4269801472\", got %T %v", convVal, convVal)
	}
	if _, ok := evalBitwiseAndStrictR63Mem(row, []string{"CONV('FE800000', 16, 10)", "4290772992"}); ok {
		t.Fatalf("expected unwrapped CONV(...) & mask to be rejected")
	}
	if err := checkStrictNereidsSQLTypesR63Mem("SELECT `_id` FROM `doris_es`.`idx_r63` WHERE (CONV('FE800000', 16, 10) & 4290772992) = 4269801472"); err == nil {
		t.Fatalf("expected checkStrictNereidsSQLTypesR63Mem error on unwrapped CONV & mask")
	}
	if masked, ok := evalBitwiseAndStrictR63Mem(row, []string{"CAST(CONV('FE800000', 16, 10) AS BIGINT)", "4290772992"}); !ok || int64(masked) != 0xFE800000 {
		t.Fatalf("expected CAST(CONV(...) AS BIGINT) & mask = 0xFE800000, got ok=%v val=%v", ok, masked)
	}

	// 2. `JSON_TYPE(json_extract(_source, ...))` distinguishes `'STRING'` (`"[WARN] retry [1]"`) from `'ARRAY'` (`["x","y"]`).
	if jtMsg := resolveColumnValue(row, `JSON_TYPE(json_extract(`+"`_source`"+`, '$."msg"'))`); jtMsg != "STRING" {
		t.Fatalf("expected JSON_TYPE msg = STRING, got %v", jtMsg)
	}
	if jtTags := resolveColumnValue(row, `JSON_TYPE(json_extract(`+"`_source`"+`, '$."tags"'))`); jtTags != "ARRAY" {
		t.Fatalf("expected JSON_TYPE tags = ARRAY, got %v", jtTags)
	}

	// 3. `TRY_CAST` + `DATETIMEV2(6)` + `MICROSECOND` preserves fractional ms (`1700000000123`).
	if tryBad := resolveColumnValue(row, `TRY_CAST('2023-11-14T22:13:20.123Z' AS BIGINT)`); tryBad != nil {
		t.Fatalf("expected TRY_CAST ISO string AS BIGINT to return nil, got %v", tryBad)
	}
	dt6Val := resolveColumnValue(row, `TRY_CAST('2023-11-14 22:13:20.123456' AS DATETIMEV2(6))`)
	if dt6Val != "2023-11-14 22:13:20.123456" {
		t.Fatalf("unexpected DATETIMEV2(6) value: %v", dt6Val)
	}
	if usec := resolveColumnValue(row, `MICROSECOND(TRY_CAST('2023-11-14 22:13:20.123456' AS DATETIMEV2(6)))`); usec != int64(123456) {
		t.Fatalf("expected MICROSECOND = 123456, got %v", usec)
	}

	// 4. Escaped JSONPath segment extraction (`$."a\"b\\c"` SQL-quoted via `'$.\"a\\"b\\\\c\"'`), `TRANSLATE`, `REGEXP_EXTRACT`, `REGEXP_REPLACE`, `TRUNCATE`, `OCTET_LENGTH`, `ARRAY_JOIN`, `TRY_CAST` arrays.
	if escVal := resolveColumnValue(row, `json_extract_string(`+"`_source`"+`, '$."a\\"b\\\\c"')`); escVal != "escaped-ok" {
		t.Fatalf("expected escaped JSONPath segment = escaped-ok, got %v", escVal)
	}
	if trVal := resolveColumnValue(row, `TRANSLATE('AZaz09-_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', '0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`+"`"+`abcdefghijklmno')`); trVal != transpiler.TranslateBase64URLOrderR63("AZaz09-_") {
		t.Fatalf("unexpected TRANSLATE result: %v", trVal)
	}
	if rx := resolveColumnValue(row, `REGEXP_EXTRACT('POINT (-71.34 41.12)', '(?i)^POINT[[:space:]]*[(][[:space:]]*([-+0-9.eE]+)[[:space:]]+([-+0-9.eE]+)[[:space:]]*[)]$', 2)`); rx != "41.12" {
		t.Fatalf("expected REGEXP_EXTRACT group 2 = 41.12, got %v", rx)
	}
	if rr := resolveColumnValue(row, `REGEXP_REPLACE('hello, world! 123', '[^[:alnum:]_]+', '  ')`); rr != "hello  world  123" {
		t.Fatalf("unexpected REGEXP_REPLACE: %v", rr)
	}
	if trNum := resolveColumnValue(row, `TRUNCATE(-1.99, 0)`); trNum != float64(-1) {
		t.Fatalf("expected TRUNCATE(-1.99, 0) = -1, got %v", trNum)
	}
	if oct := resolveColumnValue(row, `OCTET_LENGTH('héllo')`); oct != int64(6) {
		t.Fatalf("expected OCTET_LENGTH('héllo') = 6, got %v", oct)
	}
	if aj := resolveColumnValue(row, `ARRAY_JOIN(TRY_CAST('["a","b","c"]' AS ARRAY<STRING>), ' ')`); aj != "a b c" {
		t.Fatalf("expected ARRAY_JOIN = 'a b c', got %v", aj)
	}
	if af := resolveColumnValue(row, `array_size(TRY_CAST('[1.5, 2.5]' AS ARRAY<FLOAT>))`); af != int64(2) {
		t.Fatalf("expected TRY_CAST ARRAY<FLOAT> size 2, got %v", af)
	}
}

func TestRound63TargetedConformanceProbe(t *testing.T) {
	probePat := os.Getenv("ROUND63_PROBE")
	logSQL := os.Getenv("ROUND63_LOG_SQL") == "1"
	for _, a := range os.Args {
		if strings.HasPrefix(a, "probe=") && probePat == "" {
			probePat = strings.TrimPrefix(a, "probe=")
		}
		if a == "logsql=1" {
			logSQL = true
		}
	}
	if probePat == "" {
		t.Skip("ROUND63_PROBE unset")
	}
	re := regexp.MustCompile(probePat)
	cacheRoot := filepath.Clean(filepath.Join("..", "..", ".cache"))
	for _, tc := range []struct {
		ver  string
		es8  bool
		dirs []string
	}{
		{
			ver: "7.10.2",
			es8: false,
			dirs: []string{
				filepath.Join(cacheRoot, "es-v7.10.2", "rest-api-spec", "src", "main", "resources", "rest-api-spec", "test"),
				filepath.Join(cacheRoot, "es-v7.10.2", "modules"),
				filepath.Join(cacheRoot, "es-v7.10.2", "plugins"),
			},
		},
		{
			ver: "8.15.5",
			es8: true,
			dirs: []string{
				filepath.Join(cacheRoot, "es-v8.15.5", "rest-api-spec", "src", "yamlRestTest", "resources", "rest-api-spec", "test"),
				filepath.Join(cacheRoot, "es-v8.15.5", "modules"),
				filepath.Join(cacheRoot, "es-v8.15.5", "plugins"),
				filepath.Join(cacheRoot, "es-v8.15.5", "x-pack", "plugin"),
			},
		},
	} {
		var existingDirs []string
		for _, d := range tc.dirs {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				existingDirs = append(existingDirs, d)
			}
		}
		if len(existingDirs) == 0 {
			continue
		}
		es8 := tc.es8
		ver := tc.ver
		newSection := func() (http.Handler, func()) {
			mb := NewMemoryBackend(logSQL)
			srv := NewServer("doris_es", mb, transpiler.TranspilerOptions{ES8Compat: es8})
			return srv.Handler(), func() { _ = srv.Close(context.Background()) }
		}
		opts := compliance.SuiteOptions{
			CorpusName:                  "probe-" + ver,
			TargetVersion:               ver,
			SupportedClusterFeatures:    compliance.DefaultSupportedClusterFeatures(),
			SupportedTestRunnerFeatures: compliance.DefaultSupportedTestRunnerFeatures(),
			ReuseSetupForReadOnlyFiles:  true,
		}
		card, err := compliance.ScoreMatchingFiles(opts, func(displayPath string) bool {
			return re.MatchString(displayPath)
		}, newSection, existingDirs...)
		if err != nil {
			t.Fatalf("v%s error: %v", ver, err)
		}
		t.Logf("[v%s] files=%d passed=%d failed=%d skipped=%d (%.2f%%)",
			ver, card.TotalFiles, card.SectionsPassed, card.SectionsFailed, card.SectionsSkipped, card.PassRatePct)
		for _, fs := range card.FailureSamples {
			t.Logf("  FAIL [v%s] %s :: %s -> %s", ver, fs.File, fs.Section, fs.Error)
		}
	}
}
