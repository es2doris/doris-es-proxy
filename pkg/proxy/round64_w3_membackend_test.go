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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound64W3DateHistRangeNullAndParensMemBackend(t *testing.T) {
	mb := NewMemoryBackend(false)
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	h := s.Handler()

	// Create mapping with date_range field and index single doc + check live search.
	putIdx := httptest.NewRequest(http.MethodPut, "/r64_range_idx", strings.NewReader(`{"mappings":{"properties":{"range":{"type":"date_range"}}}}`))
	putIdx.Header.Set("Content-Type", "application/json")
	recIdx := httptest.NewRecorder()
	h.ServeHTTP(recIdx, putIdx)
	if recIdx.Code != http.StatusOK {
		t.Fatalf("create index status=%d body=%s", recIdx.Code, recIdx.Body.String())
	}

	postDoc := httptest.NewRequest(http.MethodPost, "/r64_range_idx/_doc/1", strings.NewReader(`{"range":{"gte":"2015-01-01","lte":"2015-03-01"}}`))
	postDoc.Header.Set("Content-Type", "application/json")
	recDoc := httptest.NewRecorder()
	h.ServeHTTP(recDoc, postDoc)
	if recDoc.Code != http.StatusCreated {
		t.Fatalf("index doc status=%d body=%s", recDoc.Code, recDoc.Body.String())
	}

	searchReq := httptest.NewRequest(http.MethodPost, "/r64_range_idx/_search", strings.NewReader(`{"size":0,"aggs":{"histo":{"date_histogram":{"field":"range","calendar_interval":"month"}}}}`))
	searchReq.Header.Set("Content-Type", "application/json")
	recSearch := httptest.NewRecorder()
	h.ServeHTTP(recSearch, searchReq)
	if recSearch.Code != http.StatusOK {
		t.Fatalf("search status=%d body=%s", recSearch.Code, recSearch.Body.String())
	}
	var resp struct {
		Aggregations struct {
			Histo struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					DocCount    int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"histo"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(recSearch.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Aggregations.Histo.Buckets) != 3 {
		t.Fatalf("expected 3 monthly buckets, got %d (%s)", len(resp.Aggregations.Histo.Buckets), recSearch.Body.String())
	}

	// Verify parenthesized comparisons in evalWhereExpr and NULL propagation in CAST(UNIX_TIMESTAMP/MICROSECOND).
	row := mb.tables["r64_range_idx"]["1"]
	if !evalWhereExpr(row, "(1420070400000) <= (1425168000000)") {
		t.Fatalf("expected parenthesized numeric <= comparison to evaluate true")
	}
	gtDt := "TRY_CAST(REPLACE(SUBSTRING(REPLACE(REPLACE(json_extract_string(`_source`, '$.\"range\".\"gt\"'), 'Z', ''), 'z', ''), 1, 26), 'T', ' ') AS DATETIMEV2(6))"
	if v := resolveColumnValue(row, "CAST(UNIX_TIMESTAMP(DATE_TRUNC("+gtDt+", 'second')) AS BIGINT)"); v != nil {
		t.Fatalf("expected CAST(UNIX_TIMESTAMP(NULL) AS BIGINT) to propagate nil, got %#v", v)
	}
	if v := resolveColumnValue(row, "CAST(FLOOR(MICROSECOND("+gtDt+") / 1000.0) AS BIGINT)"); v != nil {
		t.Fatalf("expected CAST(FLOOR(MICROSECOND(NULL) / 1000.0) AS BIGINT) to propagate nil, got %#v", v)
	}
	_ = context.Background()
}

func TestRound64W3QueryTermDocFreqsAndCutoffWarning(t *testing.T) {
	mb := NewMemoryBackend(false)
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	h := s.Handler()

	putIdx := httptest.NewRequest(http.MethodPut, "/r64_df_idx", strings.NewReader(`{"mappings":{"properties":{"body":{"type":"text"}}}}`))
	putIdx.Header.Set("Content-Type", "application/json")
	recIdx := httptest.NewRecorder()
	h.ServeHTTP(recIdx, putIdx)
	if recIdx.Code != http.StatusOK {
		t.Fatalf("create index status=%d body=%s", recIdx.Code, recIdx.Body.String())
	}

	for id, body := range map[string]string{
		"1": `{"body":"Al's pancake the quick brown"}`,
		"2": `{"body":"the slow turtle"}`,
		"3": `{"body":"the quiet river"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/r64_df_idx/_doc/"+id, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("index doc %s status=%d body=%s", id, rec.Code, rec.Body.String())
		}
	}

	total, freqs := mb.QueryTermDocFreqs("r64_df_idx", "`f__body`", []string{"the", "quick", "al's"}, false)
	if total != 3 {
		t.Fatalf("expected totalDocs=3, got %d", total)
	}
	if freqs["the"] != 3 || freqs["quick"] != 1 || freqs["al's"] != 1 {
		t.Fatalf("unexpected term doc freqs: %#v", freqs)
	}

	// Verify cutoff_frequency emits deprecation Warning header in ES7 compat mode.
	for _, tc := range []struct {
		body    string
		wantSub string
	}{
		{
			body:    `{"query":{"match":{"body":{"query":"the quick","cutoff_frequency":0.5}}}}`,
			wantSub: "the [match] query can skip block of documents efficiently",
		},
		{
			body:    `{"query":{"multi_match":{"query":"the quick","fields":["body"],"cutoff_frequency":0.5}}}`,
			wantSub: "the [multi_match] query can skip block of documents efficiently",
		},
	} {
		req := httptest.NewRequest(http.MethodPost, "/r64_df_idx/_search", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("search status=%d body=%s", rec.Code, rec.Body.String())
		}
		warnHeader := strings.Join(rec.Header().Values("Warning"), " | ")
		if !strings.Contains(warnHeader, tc.wantSub) {
			t.Fatalf("expected Warning header %q, got %q", tc.wantSub, warnHeader)
		}
	}

	// Verify multi_match type=bool_prefix + cutoff_frequency does not emit deprecation Warning on 400 error.
	bpReq := httptest.NewRequest(http.MethodPost, "/r64_df_idx/_search", strings.NewReader(`{"query":{"multi_match":{"query":"quick","type":"bool_prefix","fields":["body"],"cutoff_frequency":0.5}}}`))
	bpReq.Header.Set("Content-Type", "application/json")
	bpRec := httptest.NewRecorder()
	h.ServeHTTP(bpRec, bpReq)
	if len(bpRec.Header().Values("Warning")) != 0 {
		t.Fatalf("expected no Warning header on bool_prefix+cutoff_frequency, got %v", bpRec.Header().Values("Warning"))
	}

	// Verify arithmetic wrapping lambda array_map expressions does not trigger recursive stack overflow.
	row := mb.tables["r64_df_idx"]["1"]
	lambdaArithExpr := "FLOOR(array_max(array_map(_x -> TRY_CAST(_x AS DOUBLE), `_doc`['missing_arr'])) + 1.0)"
	if v := resolveColumnValue(row, lambdaArithExpr); v != nil {
		t.Fatalf("expected nil for missing lambda arithmetic expr, got %#v", v)
	}
}
