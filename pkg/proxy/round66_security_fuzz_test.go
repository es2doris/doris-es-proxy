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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func FuzzExpandIngestTemplate(f *testing.F) {
	f.Add("{{#join delimiter=|}}tags{{/join}} {{q}}", "hello", uint8(2))
	f.Add(strings.Repeat("{{#url}}", 33)+"{{q}}"+strings.Repeat("{{/url}}", 33), "a b", uint8(1))
	f.Add("{{#toJson}}nested{{/toJson}} {{#url}}{{big}}{{/url}}", "% %", uint8(35))
	f.Add("{{{raw}}}{{/url}}{{#url}}{{tags}}", "x&y=1", uint8(5))

	f.Fuzz(func(t *testing.T, tmpl, q string, nesting uint8) {
		if len(tmpl) > 8192 {
			tmpl = tmpl[:8192]
		}
		if len(q) > 8192 {
			q = q[:8192]
		}
		nested := any(q)
		depth := int(nesting % 40)
		for i := 0; i < depth; i++ {
			nested = map[string]any{"k": nested}
		}
		doc := map[string]any{
			"q":      q,
			"raw":    q,
			"tags":   []any{q, "two"},
			"big":    strings.Repeat(q, 4),
			"nested": nested,
		}
		out, err := expandIngestTemplate(tmpl, doc)
		if err == nil {
			if s, ok := out.(string); ok && len(s) > maxIngestTemplateOutputBytesR66 {
				t.Fatalf("expanded output exceeded max bytes: %d", len(s))
			}
		}
	})
}

func FuzzStrictNereidsSQLGuards(f *testing.F) {
	f.Add(`SELECT _id FROM db.tbl WHERE (CONV('FF', 16, 10) & 255) = 1`)
	f.Add(`SELECT _id FROM db.tbl WHERE JSON_TYPE(json_extract(_source, '$."a"')) = 'STRING'`)
	f.Add(`SELECT _id FROM db.tbl WHERE CAST(CONV('FF', 16, 10) AS LARGEINT) = 255`)
	f.Add(`SELECT _id FROM db.tbl WHERE JSON_EXISTS_PATH(_doc, '$.a')`)

	f.Fuzz(func(t *testing.T, sqlStr string) {
		if len(sqlStr) > 16384 {
			sqlStr = sqlStr[:16384]
		}
		_ = checkStrictNereidsSQLTypesR63Mem(sqlStr)
	})
}

func FuzzHistogramBoundsAndSQL(f *testing.F) {
	f.Add(float64(10), int64(5), float64(50), int64(math.MaxInt64), float64(1), float64(0))
	f.Add(float64(0), int64(-10), float64(1.5), int64(100001), float64(-5), float64(0.5))
	f.Add(math.NaN(), int64(3), math.Inf(1), int64(200), float64(0), float64(0))

	histSchema := &schema.IndexSchema{
		IndexName:  "fuzz_hist",
		DorisDB:    "es_db",
		DorisTable: "fuzz_hist",
		Fields: map[string]schema.FieldBinding{
			"h": {ESFieldPath: "h", ColumnName: "f__h", ESType: "histogram", DorisType: schema.DorisVariant},
			"n": {ESFieldPath: "n", ColumnName: "f__n", ESType: "double", DorisType: schema.DorisDouble},
		},
	}

	f.Fuzz(func(t *testing.T, v1 float64, c1 int64, v2 float64, c2 int64, interval, offset float64) {
		doc := map[string]any{
			"h": map[string]any{
				"values": []any{v1, v2},
				"counts": []any{c1, c2},
			},
			"n": v1,
		}
		expanded := collectMetricRawValuesOrHistogramR65(histSchema, doc, "h", []string{"h"})
		if len(expanded) > 100000 {
			t.Fatalf("collectMetricRawValuesOrHistogramR65 exceeded per-doc cap: %d", len(expanded))
		}

		docs := make([]runtimeMatchedDoc, 16)
		for i := range docs {
			docs[i] = runtimeMatchedDoc{rootSchema: histSchema, doc: doc}
		}
		rows := emitRuntimeHistogramFieldHDRRawRowsR65("p", "", &esast.PercentilesAggSpec{Field: "h"}, docs, nil)
		if len(rows) > 0 && rows[0].DocCount > 1000000 {
			t.Fatalf("emitRuntimeHistogramFieldHDRRawRowsR65 exceeded cumulative cap: %d", rows[0].DocCount)
		}

		minDocCount := 1
		hSpec := &esast.HistogramAggSpec{
			Field:       "n",
			Interval:    interval,
			Offset:      offset,
			MinDocCount: &minDocCount,
		}
		if !math.IsNaN(v1) && !math.IsInf(v1, 0) && !math.IsNaN(v2) && !math.IsInf(v2, 0) {
			_ = synthesizeHistogramBuckets([]AggRow{{BucketKey: "0", DocCount: 1}}, hSpec)
		}
		zero := 0
		plan, err := transpiler.NewTranspiler(histSchema, transpiler.TranspilerOptions{}).BuildSearchPlan(&esast.SearchRequest{
			Size: &zero,
			Aggs: map[string]esast.AggSpec{
				"hist": {Histogram: hSpec},
			},
		})
		if err == nil && plan.AggsSQL != "" {
			if sqlErr := checkStrictNereidsSQLTypesR63Mem(plan.AggsSQL); sqlErr != nil {
				t.Fatalf("generated histogram SQL failed Nereids guard: %v (sql=%s)", sqlErr, plan.AggsSQL)
			}
		}
	})
}

func FuzzMonitoringBulkNDJSON(f *testing.F) {
	f.Add("beats", "8.15.5", "10s", "Basic "+base64.StdEncoding.EncodeToString([]byte("writer:secret")), "{\"index\":{}}\n{\"cpu\":1}\n")
	f.Add("../bad", "7.1", "10s", "Basic "+base64.StdEncoding.EncodeToString([]byte("ghost:pw")), "{\"index\":{}}\n{\"cpu\":1}\n")
	f.Add("kibana", "7..8", "10s", "Bearer bad-tok", "not-json\n")
	f.Add("beats", "7", "5s", "ApiKey "+base64.StdEncoding.EncodeToString([]byte("bad_key:bad_sec")), "{}\n")

	f.Fuzz(func(t *testing.T, sysID, sysVer, interval, authHdr, ndjsonBody string) {
		if len(ndjsonBody) > 16384 {
			ndjsonBody = ndjsonBody[:16384]
		}
		mem := NewMemoryBackend(false)
		srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
		srv.SetTargetESVersion("8.15.5")
		srv.mu.Lock()
		srv.securityRoles["mon_writer"] = map[string]any{"cluster": []any{"manage_monitoring"}}
		srv.securityUsers["writer"] = map[string]any{"password": "secret", "roles": []any{"mon_writer"}, "enabled": true}
		srv.securityUsers["disabled"] = map[string]any{"password": "secret", "roles": []any{"superuser"}, "enabled": false}
		srv.securityAPIKeys["good_key"] = map[string]any{
			"id":              "good_key",
			"username":        "writer",
			"__secret_sha256": hashSecuritySecretR66("good_sec"),
			"invalidated":     false,
		}
		srv.mu.Unlock()
		defer func() { _ = srv.Close(t.Context()) }()

		target := "/_monitoring/bulk?system_id=" + url.QueryEscape(sysID) + "&system_api_version=" + url.QueryEscape(sysVer) + "&interval=" + url.QueryEscape(interval)
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(ndjsonBody))
		if authHdr != "" {
			req.Header.Set("Authorization", authHdr)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		trimmedID := strings.TrimSpace(sysID)
		trimmedVer := strings.TrimSpace(sysVer)
		if (!isValidMonitoringSystemIDR66(trimmedID) || !isValidMonitoringSystemAPIVersionR66(trimmedVer)) && rec.Code < 400 {
			t.Fatalf("invalid system_id=%q or system_api_version=%q unexpectedly returned %d", sysID, sysVer, rec.Code)
		}

		// Any invalid/untrusted Authorization header must fail closed.
		isTrustedAuth := false
		if parts := strings.SplitN(strings.TrimSpace(authHdr), " ", 2); len(parts) == 2 {
			sch := strings.ToLower(strings.TrimSpace(parts[0]))
			tok := strings.TrimSpace(parts[1])
			if dec, err := base64.StdEncoding.DecodeString(tok); err == nil {
				sDec := string(dec)
				if sch == "basic" && (sDec == "writer:secret" || sDec == "test_admin:x-pack-test-password") {
					isTrustedAuth = true
				} else if sch == "apikey" && sDec == "good_key:good_sec" {
					isTrustedAuth = true
				}
			}
		}
		if strings.TrimSpace(authHdr) != "" && !isTrustedAuth && rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("unexpected non-401/403 status %d for untrusted auth %q: %s", rec.Code, authHdr, rec.Body.String())
		}
	})
}

func FuzzAutoscalingByteSize(f *testing.F) {
	f.Add("10gb", float64(1024), int64(4))
	f.Add("NaN", math.NaN(), int64(2))
	f.Add("+Inf", math.Inf(1), int64(math.MaxInt64))
	f.Add("-10mb", float64(-1), int64(-3))
	f.Add("9223372036854775808b", float64(9223372036854775808.0), int64(10))

	f.Fuzz(func(t *testing.T, rawStr string, rawFloat float64, mulFactor int64) {
		if len(rawStr) > 1024 {
			rawStr = rawStr[:1024]
		}
		if b, err := parseAutoscalingByteSizeR65(rawStr); err == nil {
			if b < 0 {
				t.Fatalf("negative byte size returned without error: %d", b)
			}
			if mulFactor >= 0 {
				if p := saturatingMulInt64R66(b, mulFactor); p < 0 {
					t.Fatalf("saturatingMulInt64R66 wrapped negative: %d * %d = %d", b, mulFactor, p)
				}
			}
		}
		trimmed := strings.ToLower(strings.TrimSpace(rawStr))
		if trimmed == "nan" || trimmed == "inf" || trimmed == "+inf" || trimmed == "-inf" || trimmed == "infinity" {
			if _, err := parseAutoscalingByteSizeR65(rawStr); err == nil {
				t.Fatalf("expected non-finite byte size %q to fail", rawStr)
			}
		}

		fb, ferr := parseAutoscalingByteSizeR65(rawFloat)
		if (math.IsNaN(rawFloat) || math.IsInf(rawFloat, 0) || rawFloat < 0 || rawFloat >= maxFloatInt64ExclusiveR66) && ferr == nil {
			t.Fatalf("expected out-of-range/non-finite float64 %v to fail, got %d", rawFloat, fb)
		}
		_, _ = parseAutoscalingByteSizeR65(json.Number(rawStr))
	})
}
