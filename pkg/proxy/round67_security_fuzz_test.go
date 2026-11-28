package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func FuzzSQLAndFullESQLEQLEval(f *testing.F) {
	f.Add("SELECT a, COUNT(*) FROM logs WHERE host LIKE 'web-%' AND code >= 200 GROUP BY a ORDER BY a DESC LIMIT 10", "status == 200 AND msg RLIKE '^ok.*'", `process where event.action == "exec" and process.name regex "sh.*"`)
	f.Add("SELECT ?, UPPER(name) FROM idx WHERE tags IN ('x','y')", "NOT (x IN (1, 2, 3))", `sequence maxspan=5m [file where file.name like "*.exe"] [process where pid > 0]`)
	f.Add("SELECT 1 FROM idx WHERE a IS NOT NULL AND b BETWEEN 1 AND 5", "a =~ 'hello' OR !(b LIKE '%z%')", `any where true`)

	row := map[string]any{
		"a":    int64(42),
		"b":    3.14,
		"name": "web-01",
		"host": "web-01",
		"msg":  "ok_ready",
		"code": int64(200),
		"tags": []any{"x", "z"},
		"process": map[string]any{
			"name": "bash",
			"pid":  int64(100),
		},
		"event": map[string]any{
			"action": "exec",
		},
	}

	f.Fuzz(func(t *testing.T, sqlQ, esqlExpr, eqlQ string) {
		if len(sqlQ) > 2048 || len(esqlExpr) > 2048 || len(eqlQ) > 2048 {
			return
		}

		// 1. SQL tokenizer, parser, parameter substitution, and row expression eval.
		if _, err := substituteSQLParams(sqlQ, []any{"p1", int64(7), 1.5, true, nil}); err == nil {
			_ = err
		}
		if toks, err := tokenizeRound57SQL(sqlQ); err == nil {
			p := &sqlParser{toks: toks}
			if stmt, pErr := p.parseSelect(); pErr == nil && stmt != nil {
				for _, it := range stmt.items {
					_ = evalSQLExprOnRow(it.expr, row, []map[string]any{row})
				}
				if stmt.where != nil {
					_ = evalSQLExprOnRow(stmt.where, row, nil)
				}
			}
		}

		// 2. ES|QL expression tokenizer and evaluator.
		_ = tokenizeESQLExpr(esqlExpr)
		_ = evalESQLExpr(esqlExpr, row)
		_ = evalESQLCond(esqlExpr, row)

		// 3. EQL tokenizer, parser, and expression evaluator.
		if toks, err := tokenizeEQL(eqlQ); err == nil {
			ep := &eqlParser{toks: toks, allowImplicitWhere: true}
			if ast, eErr := ep.parseQuery(); eErr == nil && ast != nil {
				if ast.single.where != nil {
					_, _ = evalEQLExpr(ast.single.where, row)
				}
				for _, st := range ast.stages {
					if st.where != nil {
						_, _ = evalEQLExpr(st.where, row)
					}
				}
			}
		}
	})
}

func FuzzHistogramGapFillAndTimeZones(f *testing.F) {
	f.Add("America/New_York", int64(1704067200000), int64(1704240000000), float64(10), float64(0), "1d")
	f.Add("UTC", int64(0), int64(86400000*7), float64(5), float64(1), "1h")
	f.Add("+05:30", int64(1700000000000), int64(1700100000000), float64(0), float64(-3), "invalid")
	f.Add("Invalid/Zone", int64(-100000), int64(100000), float64(2.5), float64(0.5), "1M")

	f.Fuzz(func(t *testing.T, tzRaw string, minMs, maxMs int64, interval, offset float64, calInterval string) {
		if len(tzRaw) > 128 || len(calInterval) > 64 {
			return
		}
		_, _, _, _ = esast.ParseESTimeZone(tzRaw)
		loc := resolveAutoDateTimeZoneLocR62Search(tzRaw)

		if interval < 0 {
			interval = -interval
		}
		zero := 0
		rows := []AggRow{
			{BucketKey: fmt.Sprintf("%d", minMs), DocCount: 2, Value: 2},
			{BucketKey: fmt.Sprintf("%d", maxMs), DocCount: 3, Value: 3},
		}

		// Bounded numeric histogram gap fill (JSON roundtrip exercises UnmarshalJSON too).
		hPayload, _ := json.Marshal(map[string]any{
			"field":         "price",
			"interval":      interval,
			"offset":        offset,
			"min_doc_count": zero,
			"extended_bounds": map[string]any{
				"min": 0,
				"max": 100,
			},
			"hard_bounds": map[string]any{
				"min": -50,
				"max": 200,
			},
		})
		var hSpec esast.HistogramAggSpec
		if err := json.Unmarshal(hPayload, &hSpec); err == nil {
			numRows := []AggRow{
				{BucketKey: "0", DocCount: 1, Value: 1},
				{BucketKey: "50", DocCount: 2, Value: 2},
			}
			out := synthesizeHistogramBucketsWithBudgetR67(numRows, &hSpec, newHistBucketBudgetR67(1024))
			if len(out) > 100002 {
				t.Fatalf("histogram bucket explosion: %d", len(out))
			}
		}

		// Date histogram timezone & gap fill.
		for _, cand := range autoDateCandidatesR62Search {
			floored := floorAutoDateCandMillisR62Search(minMs, cand, loc)
			_ = stepAutoDateCandMillisR62Search(floored, cand, loc)
		}
		dhPayload, _ := json.Marshal(map[string]any{
			"field":             "@timestamp",
			"calendar_interval": calInterval,
			"time_zone":         tzRaw,
			"min_doc_count":     0,
		})
		var dhSpec esast.DateHistogramAggSpec
		if err := json.Unmarshal(dhPayload, &dhSpec); err == nil {
			_ = floorDateHistogramBucketFixedTZAwareR66(minMs, &dhSpec)
			out := synthesizeFixedTZDateHistogramBucketsWithBudgetR67(rows, &dhSpec, loc, newHistBucketBudgetR67(1024))
			if len(out) > 100002 {
				t.Fatalf("date_histogram bucket explosion: %d", len(out))
			}
		}
	})
}

func FuzzRound66SecurityConnectorInferenceHandlers(f *testing.F) {
	f.Add(uint8(0), "id1", `{"service":"openai","service_settings":{"api_key":"secret123","model_id":"m1"}}`)
	f.Add(uint8(1), "sec1", `{"name":"s1","value":"top-secret-value"}`)
	f.Add(uint8(2), "conn1", `{"last_sync_status":"ok","is_native":true,"index_name":"pwn"}`)
	f.Add(uint8(3), "u1", `{"grant_type":"password","username":"","password":""}`)
	f.Add(uint8(4), "tok1", `{}`)

	mb := NewMemoryBackend(false)
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	defer func() { _ = s.Close(context.Background()) }()
	h := s.Handler()

	f.Fuzz(func(t *testing.T, opSel uint8, rawID, body string) {
		if len(rawID) > 64 || len(body) > 4096 {
			return
		}
		// Keep IDs URL-safe and bounded cardinality so fuzz stays fast across CRUD mutations.
		safeID := fmt.Sprintf("fz_%d", opSel%8)
		for _, ch := range rawID {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
				safeID += string(ch)
				break
			}
		}

		// Also directly fuzz redaction & sanitization helpers.
		var obj map[string]any
		if json.Unmarshal([]byte(body), &obj) == nil && obj != nil {
			epCopy := redactInferenceEndpointCopyR67(map[string]any{"service_settings": obj})
			if ss, ok := epCopy["service_settings"].(map[string]any); ok {
				for k, v := range ss {
					if isSensitiveSettingKeyR67(k) && v != "" && v != "****" {
						t.Fatalf("unredacted sensitive key %q=%v", k, v)
					}
				}
			}
			secCopy := sanitizeConnectorSecretCopyR67(obj)
			if secCopy["value"] != nil || secCopy["__value"] != nil || secCopy["has_value"] != true {
				t.Fatalf("sanitizeConnectorSecretCopyR67 leaked value or missed has_value: %+v", secCopy)
			}
		}

		var method, target string
		switch opSel % 8 {
		case 0:
			method, target = http.MethodPut, "/_inference/text_embedding/"+safeID
		case 1:
			method, target = http.MethodGet, "/_inference/"+safeID
		case 2:
			method, target = http.MethodPut, "/_connector/_secret/"+safeID
		case 3:
			method, target = http.MethodGet, "/_connector/_secret/"+safeID
		case 4:
			method, target = http.MethodPost, "/_connector/"+safeID+"/_last_sync"
		case 5:
			method, target = http.MethodPost, "/_security/api_key/grant"
		case 6:
			method, target = http.MethodPost, "/_security/oauth2/token"
		default:
			method, target = http.MethodPost, "/_fleet/secrets"
		}

		req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("5xx status %d on %s %s: %s", rec.Code, method, target, rec.Body.String())
		}
		if method == http.MethodGet && strings.HasPrefix(target, "/_connector/_secret/") && rec.Code == http.StatusOK {
			var out map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &out) == nil {
				if _, hasVal := out["value"]; hasVal {
					t.Fatalf("GET %s returned raw secret value: %s", target, rec.Body.String())
				}
			}
		}
	})
}

func FuzzFilterPathGlobAndSourceQueryParam(f *testing.F) {
	f.Add("hits.hits._source.meta\\.dot,hits.total.*", "false", "a.*,meta.*", "secret.*", "5m")
	f.Add("**,*._id", "true", "title", "", "100ms")
	f.Add(`a\.b.c,items.*.name`, "a,b", "", "password", "bad")

	samplePayload := map[string]any{
		"took": 5,
		"hits": map[string]any{
			"total": map[string]any{"value": 1, "relation": "eq"},
			"hits": []any{
				map[string]any{
					"_id": "1",
					"_source": map[string]any{
						"meta.dot": "ok",
						"title":    "hi",
						"password": "hidden",
					},
				},
			},
		},
		"items": []any{
			map[string]any{"name": "one"},
		},
	}

	mb := NewMemoryBackend(false)
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	defer func() { _ = s.Close(context.Background()) }()
	h := s.Handler()

	f.Fuzz(func(t *testing.T, filterPath, sourceParam, srcInc, srcExc, keepAlive string) {
		if len(filterPath) > 512 || len(sourceParam) > 256 || len(srcInc) > 256 || len(srcExc) > 256 || len(keepAlive) > 64 {
			return
		}
		exprs := splitFilterPathExpressions(filterPath)
		for _, e := range exprs {
			_ = parseFilterPathSegments(e)
		}
		_ = applyFilterPathRound61(deepCloneDocMap(samplePayload), exprs)
		_, _ = parseESPositiveDuration(keepAlive)

		q := url.Values{}
		if filterPath != "" {
			q.Set("filter_path", filterPath)
		}
		if sourceParam != "" {
			q.Set("_source", sourceParam)
		}
		if srcInc != "" {
			q.Set("_source_includes", srcInc)
		}
		if srcExc != "" {
			q.Set("_source_excludes", srcExc)
		}
		target := "/missing_idx/_search?" + q.Encode()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		_ = hasExplicitURLSourceParamR61CRUD(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("unexpected 5xx %d on %s: %s", rec.Code, target, rec.Body.String())
		}
	})
}
