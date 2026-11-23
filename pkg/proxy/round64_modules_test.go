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
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func decodeJSONRecR64(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("failed to decode JSON response (status=%d body=%s): %v", rec.Code, rec.Body.String(), err)
	}
	return m
}

func assertRecStatusR64(t *testing.T, rec *httptest.ResponseRecorder, want int, ctxMsg string) map[string]any {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s: expected HTTP %d, got %d body=%s", ctxMsg, want, rec.Code, rec.Body.String())
	}
	if len(bytes.TrimSpace(rec.Body.Bytes())) == 0 {
		return nil
	}
	return decodeJSONRecR64(t, rec)
}

func esqlColMapR64(resp map[string]any) map[string]string {
	out := make(map[string]string)
	cols, _ := resp["columns"].([]any)
	for _, cAny := range cols {
		if cm, ok := cAny.(map[string]any); ok {
			name, _ := cm["name"].(string)
			tp, _ := cm["type"].(string)
			out[name] = tp
		}
	}
	return out
}

func TestRound64_Modules_F9_ESQL(t *testing.T) {
	// 1. Verify ESQLSupportedFeaturesMapR64 (16 ES 8.15 keys) & RecordESQLFeatureUsageR64
	feat := ESQLSupportedFeaturesMapR64()
	if len(feat) != 16 {
		t.Fatalf("expected 16 esql.features keys, got %d: %+v", len(feat), feat)
	}
	for _, k := range []string{"dissect", "drop", "eval", "enrich", "from", "grok", "keep", "limit", "meta", "mv_expand", "rename", "row", "show", "sort", "stats", "where"} {
		if _, ok := feat[k]; !ok {
			t.Fatalf("missing expected esql.features key %q", k)
		}
	}
	RecordESQLFeatureUsageR64(feat, `FROM idx METADATA _id | WHERE x > 1 | EVAL y = 2 | STATS c = COUNT(*) | SORT c | LIMIT 5`)
	for _, k := range []string{"from", "meta", "where", "eval", "stats", "sort", "limit"} {
		if feat[k] != 1 {
			t.Fatalf("expected feature %q count=1, got %d", k, feat[k])
		}
	}

	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// 2. Standard index with `time_series_metric: counter` stays scalar numeric (`esql/45_non_tsdb_counter.yml`)
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_std_cnt", `{
		"settings": {"index.mode": "standard"},
		"mappings": {"properties": {"tx": {"type": "integer", "time_series_metric": "counter"}, "host": {"type": "keyword"}}}
	}`), http.StatusOK, "create r64_std_cnt")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_std_cnt/_doc/1", `{"tx": 5, "host": "h1"}`), http.StatusCreated, "index std_cnt")

	stdRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_std_cnt | WHERE tx == 5 | KEEP tx"}`), http.StatusOK, "non-tsdb counter query")
	if cols := esqlColMapR64(stdRes); cols["tx"] != "integer" {
		t.Fatalf("expected non-tsdb counter column type integer, got %q (%+v)", cols["tx"], stdRes)
	}

	// 3. TSDB index (`index.mode: time_series`) maps counter to `counter_long` and enforces cast in WHERE / SORT
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_tsdb_cnt", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {"properties": {
			"@timestamp": {"type": "date"},
			"host": {"type": "keyword", "time_series_dimension": true},
			"tx": {"type": "long", "time_series_metric": "counter"}
		}}
	}`), http.StatusOK, "create r64_tsdb_cnt")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_tsdb_cnt/_doc", `{"@timestamp":"2024-01-01T00:00:00Z","host":"h1","tx":7}`), http.StatusCreated, "index tsdb_cnt")

	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_tsdb_cnt | WHERE tx == 7"}`), http.StatusBadRequest, "bare counter in WHERE must fail")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_tsdb_cnt | SORT tx"}`), http.StatusBadRequest, "bare counter in SORT must fail")
	tsdbCastRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_tsdb_cnt | WHERE tx::long == 7 | STATS s = SUM(tx)"}`), http.StatusOK, "cast counter in WHERE and SUM in STATS")
	if vals, _ := tsdbCastRes["values"].([]any); len(vals) != 1 || fmt.Sprintf("%v", vals[0].([]any)[0]) != "7" {
		t.Fatalf("expected SUM(tx)=7, got %+v", tsdbCastRes)
	}

	// 4. Multivalue COUNT_DISTINCT, VALUES + empty/null static SUM/VALUES types, immediate LIMIT before STATS, profile.drivers cpu_nanos
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_mv", `{
		"mappings": {"properties": {
			"k": {"type": "keyword"},
			"tags": {"type": "keyword"},
			"iv": {"type": "integer"},
			"dv": {"type": "double"},
			"txt": {"type": "text"}
		}}
	}`), http.StatusOK, "create r64_mv")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_mv/_doc/1", `{"k":"a","tags":["x","y"],"iv":2,"dv":1.5,"txt":"hello world"}`), http.StatusCreated, "doc1")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_mv/_doc/2", `{"k":"b","tags":["y","z"],"iv":3,"dv":2.5,"txt":"foo bar"}`), http.StatusCreated, "doc2")

	mvStats := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"profile":true,"query":"FROM r64_mv | STATS cd = COUNT_DISTINCT(tags), vs = VALUES(txt)"}`), http.StatusOK, "multivalue stats")
	if cols := esqlColMapR64(mvStats); cols["vs"] != "text" || cols["cd"] != "long" {
		t.Fatalf("expected cd=long vs=text, got %+v", cols)
	}
	if vals, _ := mvStats["values"].([]any); len(vals) != 1 || fmt.Sprintf("%v", vals[0].([]any)[0]) != "3" {
		t.Fatalf("expected COUNT_DISTINCT(tags)=3 across multivalues, got %+v", mvStats["values"])
	}
	prof, _ := mvStats["profile"].(map[string]any)
	drivers, _ := prof["drivers"].([]any)
	if len(drivers) < 2 {
		t.Fatalf("expected at least 2 profile drivers, got %+v", prof)
	}
	for di := 0; di < 2; di++ {
		dm := drivers[di].(map[string]any)
		if _, ok := dm["took_nanos"]; !ok {
			t.Fatalf("driver %d missing took_nanos: %+v", di, dm)
		}
		if _, ok := dm["cpu_nanos"]; !ok {
			t.Fatalf("driver %d missing cpu_nanos: %+v", di, dm)
		}
	}

	// Empty STATS preserves static SUM types (integer->long, double->double, text->text)
	emptyStats := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_mv | WHERE k == \"none\" | STATS si = SUM(iv), sd = SUM(dv), vt = VALUES(txt)"}`), http.StatusOK, "empty STATS static types")
	if cols := esqlColMapR64(emptyStats); cols["si"] != "long" || cols["sd"] != "double" || cols["vt"] != "text" {
		t.Fatalf("expected si=long sd=double vt=text on empty STATS, got %+v", cols)
	}

	// Immediate LIMIT slices before downstream STATS
	limRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_mv | SORT k ASC | LIMIT 1 | STATS c = COUNT(*)"}`), http.StatusOK, "immediate LIMIT before STATS")
	if vals, _ := limRes["values"].([]any); len(vals) != 1 || fmt.Sprintf("%v", vals[0].([]any)[0]) != "1" {
		t.Fatalf("expected COUNT(*)=1 after LIMIT 1, got %+v", limRes)
	}

	// Multivalue STATS BY expansion
	byMV := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_mv | STATS c = COUNT(*) BY tags | SORT tags ASC"}`), http.StatusOK, "STATS BY multivalue")
	if vals, _ := byMV["values"].([]any); len(vals) != 3 {
		t.Fatalf("expected 3 buckets (x,y,z) from multivalue BY, got %+v", byMV)
	}

	// 5. Cross-index union ambiguous types (`esql/160_union_types.yml`)
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_u_ip", `{"mappings":{"properties":{"client_ip":{"type":"ip"}}}}`), http.StatusOK, "u_ip")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_u_kw", `{"mappings":{"properties":{"client_ip":{"type":"keyword"}}}}`), http.StatusOK, "u_kw")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_u_long", `{"mappings":{"properties":{"client_ip":{"type":"long"}}}}`), http.StatusOK, "u_long")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_u_ip/_doc/1", `{"client_ip":"172.21.3.15"}`), http.StatusCreated, "u_ip doc")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_u_kw/_doc/1", `{"client_ip":"172.21.3.15"}`), http.StatusCreated, "u_kw doc")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_u_long/_doc/1", `{"client_ip":12345}`), http.StatusCreated, "u_long doc")

	unionEval := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_u_ip,r64_u_kw | WHERE client_ip::ip == \"172.21.3.15\" | EVAL x = TO_IP(client_ip), y = TO_STRING(client_ip) | STATS c = COUNT(*) BY cip = client_ip::ip"}`), http.StatusOK, "union ambiguous compatible conversions")
	if vals, _ := unionEval["values"].([]any); len(vals) != 1 || fmt.Sprintf("%v", vals[0].([]any)[0]) != "2" || fmt.Sprintf("%v", vals[0].([]any)[1]) != "172.21.3.15" {
		t.Fatalf("expected union converted group count=2 ip=172.21.3.15, got %+v", unionEval)
	}
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_u_ip,r64_u_long | EVAL x = TO_IP(client_ip)"}`), http.StatusBadRequest, "union incompatible TO_IP with long must fail")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_u_ip,r64_u_kw | SORT client_ip"}`), http.StatusBadRequest, "union bare SORT must fail")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_query", `{"query":"FROM r64_u_ip,r64_u_kw | WHERE client_ip == \"172.21.3.15\""}`), http.StatusBadRequest, "union bare WHERE must fail")
}

func TestRound64_Modules_F9_EQL_C35_C36(t *testing.T) {
	// 1. EQL: non-greedy sequence + missing event interleaving + .keyword field expansion
	stageEvents := []any{map[string]any{"_id": "1"}, map[string]any{"_id": "2"}}
	absent := map[int][]eqlStageSpec{
		1: {{category: "process"}},
		2: {{category: "process"}},
	}
	interleaved := interleaveEQLMissingStageEventsRound63(stageEvents, absent)
	if len(interleaved) != 4 {
		t.Fatalf("expected 4 interleaved events with trailing missing stage, got %d: %+v", len(interleaved), interleaved)
	}
	if mLast, _ := interleaved[3].(map[string]any); mLast["missing"] != true {
		t.Fatalf("expected trailing missing marker at index 3, got %+v", interleaved[3])
	}

	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_eql", `{
		"mappings": {"properties": {
			"@timestamp": {"type": "date"},
			"event": {"properties": {"category": {"type": "keyword"}}},
			"user": {"properties": {"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
			"process": {"properties": {"name": {"type": "keyword"}}}
		}}
	}`), http.StatusOK, "create r64_eql")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/1", `{"@timestamp":"2024-01-01T00:00:01Z","event":{"category":"process"},"user":{"name":"alice"},"process":{"name":"init"}}`), http.StatusCreated, "eql doc 1")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/2", `{"@timestamp":"2024-01-01T00:00:02Z","event":{"category":"process"},"user":{"name":"alice"},"process":{"name":"run"}}`), http.StatusCreated, "eql doc 2")

	eqlRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_eql/search", `{
		"fields": [{"field": "*"}],
		"runtime_mappings": {"rt_tag": {"type": "keyword", "script": {"source": "emit('ok')"}}},
		"query": "sequence by user.name.keyword [process where process.name == \"init\"] [process where process.name == \"run\"]"
	}`), http.StatusOK, "EQL sequence query")
	hitsObj, _ := eqlRes["hits"].(map[string]any)
	seqs, _ := hitsObj["sequences"].([]any)
	if len(seqs) != 1 {
		t.Fatalf("expected 1 EQL sequence match, got %+v", eqlRes)
	}

	// Verify overlapping sequence matching (`a1, a2, b1, b2` -> 2 sequences) and `![...]` absent stage.
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/3", `{"@timestamp":"2024-01-01T00:00:03Z","event":{"category":"process"},"user":{"name":"bob"},"process":{"name":"init"}}`), http.StatusCreated, "eql bob 1")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/4", `{"@timestamp":"2024-01-01T00:00:04Z","event":{"category":"process"},"user":{"name":"bob"},"process":{"name":"init"}}`), http.StatusCreated, "eql bob 2")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/5", `{"@timestamp":"2024-01-01T00:00:05Z","event":{"category":"process"},"user":{"name":"bob"},"process":{"name":"run"}}`), http.StatusCreated, "eql bob 3")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_doc/6", `{"@timestamp":"2024-01-01T00:00:06Z","event":{"category":"process"},"user":{"name":"bob"},"process":{"name":"run"}}`), http.StatusCreated, "eql bob 4")

	eqlOverlap := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_eql/_eql/search", `{
		"query": "sequence by user.name [process where process.name == \"init\"] ![process where process.name == \"kill\"] [process where process.name == \"run\"]"
	}`), http.StatusOK, "EQL overlapping sequence with absent stage")
	if seqList, _ := eqlOverlap["hits"].(map[string]any)["sequences"].([]any); len(seqList) != 3 {
		t.Fatalf("expected 3 total overlapping sequences (1 alice + 2 bob), got %d: %+v", len(seqList), eqlOverlap)
	}

	// 2. C35: Attachment 8-key metadata on synthetic .docx & .doc (without "created")
	var docxFullBuf bytes.Buffer
	zw := zip.NewWriter(&docxFullBuf)
	if w, err := zw.Create("word/document.xml"); err == nil {
		_, _ = w.Write([]byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello ES 8.15 attachment test</w:t></w:r></w:p></w:body></w:document>`))
	}
	if w, err := zw.Create("docProps/core.xml"); err == nil {
		_, _ = w.Write([]byte(`<cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dcterms="http://purl.org/dc/terms/"><dc:creator>alice</dc:creator><cp:lastModifiedBy>bob</cp:lastModifiedBy><dcterms:created>2024-01-01T00:00:00Z</dcterms:created><dcterms:modified>2024-01-02T00:00:00Z</dcterms:modified></cp:coreProperties>`))
	}
	_ = zw.Close()
	attMeta, okAtt := ExtractIngestAttachmentRound63(base64.StdEncoding.EncodeToString(docxFullBuf.Bytes()), 100000, nil, true)
	if !okAtt {
		t.Fatalf("expected ExtractIngestAttachmentRound63 to succeed on valid docx")
	}
	for _, k := range []string{"content", "language", "author", "date", "content_length", "content_type", "modifier", "modified"} {
		if _, has := attMeta[k]; !has {
			t.Fatalf("expected attachment metadata key %q, got %+v", k, attMeta)
		}
	}
	if _, hasCreated := attMeta["created"]; hasCreated {
		t.Fatalf("expected attachment metadata NOT to contain 'created' by default, got %+v", attMeta)
	}

	// 3. C36: terms_enum FLS/DLS & API Key evaluation
	schemas := map[string]*schema.IndexSchema{
		"test_security": {
			RawMapping: &esast.MappingSpec{
				Properties: map[string]esast.FieldProperty{
					"ck":  {Type: "constant_keyword", Value: "const"},
					"foo": {Type: "keyword"},
				},
			},
		},
	}
	roles := map[string]map[string]any{
		"dls_all_role": {
			"indices": []any{map[string]any{
				"names": []any{"test_security"},
				"query": `{"term": {"ck": "const"}}`,
			}},
		},
		"dls_some_role": {
			"indices": []any{map[string]any{
				"names": []any{"test_security"},
				"query": `{"term": {"foo": "bar_dls"}}`,
			}},
		},
		"fls_role": {
			"indices": []any{map[string]any{
				"names":          []any{"test_security"},
				"field_security": map[string]any{"except": []any{"foo"}},
			}},
		},
	}
	users := map[string]map[string]any{
		"dls_all_user":  {"roles": []any{"dls_all_role"}},
		"dls_some_user": {"roles": []any{"dls_some_role"}},
		"fls_user":      {"roles": []any{"fls_role"}},
	}
	apiKeys := map[string]map[string]any{
		"good_key": {
			"username": "dls_all_user",
			"role_descriptors": map[string]any{
				"role-a": map[string]any{"index": []any{map[string]any{"names": []any{"test_security"}, "query": `{"term": {"ck": "const"}}`}}},
			},
		},
		"bad_key": {
			"username": "dls_all_user",
			"role_descriptors": map[string]any{
				"role-a": map[string]any{"index": []any{map[string]any{"names": []any{"test_security"}, "query": `{"term": {"foo": "bar_dls"}}`}}},
			},
		},
		"bounded_key": {
			"username": "dls_some_user",
			"role_descriptors": map[string]any{
				"role-a": map[string]any{"index": []any{map[string]any{"names": []any{"test_security"}, "query": `{"term": {"ck": "const"}}`}}},
			},
		},
	}
	basicHdr := func(u string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":pw"))
	}
	apiHdr := func(k string) string {
		return "ApiKey " + base64.StdEncoding.EncodeToString([]byte(k+":sec"))
	}
	if !EvaluateTermsEnumSecurityAccessR64(basicHdr("elastic"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected elastic superuser access allowed")
	}
	if !EvaluateTermsEnumSecurityAccessR64(basicHdr("dls_all_user"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected dls_all_user (constant_keyword) allowed")
	}
	if EvaluateTermsEnumSecurityAccessR64(basicHdr("dls_some_user"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected dls_some_user denied for terms_enum")
	}
	if EvaluateTermsEnumSecurityAccessR64(basicHdr("fls_user"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected fls_user denied for terms_enum")
	}
	if !EvaluateTermsEnumSecurityAccessR64(apiHdr("good_key"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected good_key allowed")
	}
	if EvaluateTermsEnumSecurityAccessR64(apiHdr("bad_key"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected bad_key denied")
	}
	if EvaluateTermsEnumSecurityAccessR64(apiHdr("bounded_key"), users, roles, apiKeys, schemas, []string{"test_security"}, "foo") {
		t.Fatalf("expected bounded_key (owned by dls_some_user) denied")
	}
}

func TestRound64_Modules_F4_Downsample(t *testing.T) {
	// 1. ValidateDownsampleUnsupportedAggR64 & ValidateDownsampleAggsSpecMapR64 (`20_unsupported_aggs.yml`)
	dsSchema := &schema.IndexSchema{
		Fields: map[string]schema.FieldBinding{
			"total_memory_used": {ESType: "aggregate_metric_double"},
			"ts":                {ESType: "date"},
		},
	}
	for _, aggType := range []string{"histogram", "range", "cardinality", "percentiles", "top_metrics"} {
		aggSpec := map[string]any{
			"my_agg": map[string]any{
				aggType: map[string]any{"field": "total_memory_used"},
			},
		}
		if aggType == "top_metrics" {
			aggSpec["my_agg"] = map[string]any{
				"top_metrics": map[string]any{
					"metrics": map[string]any{"field": "total_memory_used"},
					"sort":    map[string]any{"ts": "desc"},
				},
			}
		}
		err := ValidateDownsampleAggsSpecMapR64(aggSpec, dsSchema)
		var dsErr *DownsampleAggValidationErrorR64
		if !errors.As(err, &dsErr) || dsErr.Status != http.StatusBadRequest || dsErr.Type != "unsupported_aggregation_on_downsampled_index" {
			t.Fatalf("aggType %s: expected DownsampleAggValidationErrorR64, got %v", aggType, err)
		}
		wantReason := fmt.Sprintf("Field [total_memory_used] of type [aggregate_metric_double] is not supported for aggregation [%s]", aggType)
		if dsErr.Reason != wantReason {
			t.Fatalf("aggType %s: expected reason %q, got %q", aggType, wantReason, dsErr.Reason)
		}
	}
	// Allowed aggregations (nested inside date_histogram or alone)
	if err := ValidateDownsampleAggsSpecMapR64(map[string]any{
		"by_day": map[string]any{
			"date_histogram": map[string]any{"field": "ts", "calendar_interval": "1d"},
			"aggs": map[string]any{
				"max_mem": map[string]any{"max": map[string]any{"field": "total_memory_used"}},
			},
		},
	}, dsSchema); err != nil {
		t.Fatalf("expected date_histogram + max on aggregate_metric_double to be allowed, got %v", err)
	}

	// 2. End-to-end _downsample double downsample _doc_count summation, custom date_nanos format, tie-breaking, _tier_preference
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_ds_src", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["k8s.pod.uid"],
			"index.routing.allocation.include._tier_preference": "data_hot",
			"index.lifecycle.name": "some_pol"
		},
		"mappings": {"properties": {
			"@timestamp": {"type": "date_nanos", "format": "strict_date_optional_time_nanos||yyyy-MM-dd HH:mm:ss.SSSSSSSSS"},
			"k8s.pod.uid": {"type": "keyword", "time_series_dimension": true},
			"cpu": {"type": "double", "time_series_metric": "gauge"}
		}}
	}`), http.StatusOK, "create r64_ds_src")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_src/_doc", `{"@timestamp":"2024-01-01 00:05:00.000000000","k8s.pod.uid":"pod-a","cpu":10.0}`), http.StatusCreated, "ds doc 1")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_src/_doc", `{"@timestamp":"2024-01-01 00:15:00.000000000","k8s.pod.uid":"pod-a","cpu":20.0}`), http.StatusCreated, "ds doc 2")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_src/_doc", `{"@timestamp":"2024-01-01 00:25:00.000000000","k8s.pod.uid":"pod-b","cpu":5.0}`), http.StatusCreated, "ds doc 3")

	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_src/_downsample/r64_ds_1h", `{"fixed_interval":"1h"}`), http.StatusOK, "first downsample 1h")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_1h/_downsample/r64_ds_1d", `{"fixed_interval":"1d"}`), http.StatusOK, "second downsample 1d")

	// Check target mapping preserves date_nanos & custom format, and settings keep _tier_preference & strip lifecycle
	getDS1d := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodGet, "/r64_ds_1d", ""), http.StatusOK, "get r64_ds_1d")
	dsIdxObj := getDS1d["r64_ds_1d"].(map[string]any)
	dsProps := dsIdxObj["mappings"].(map[string]any)["properties"].(map[string]any)
	if tsProp := dsProps["@timestamp"].(map[string]any); tsProp["type"] != "date_nanos" {
		t.Fatalf("expected @timestamp type date_nanos preserved, got %+v", tsProp)
	}
	dsSettings := dsIdxObj["settings"].(map[string]any)["index"].(map[string]any)
	if alloc, _ := dsSettings["routing"].(map[string]any); alloc == nil {
		// Flat or nested _tier_preference check
		if dsSettings["routing.allocation.include._tier_preference"] != "data_hot" {
			t.Fatalf("expected _tier_preference preserved in downsampled settings, got %+v", dsSettings)
		}
	}
	if _, hasLC := dsSettings["lifecycle"]; hasLC {
		t.Fatalf("expected lifecycle stripped from downsampled index settings, got %+v", dsSettings)
	}
	// Verify summed _doc_count in r64_ds_1d for pod-a (2 docs)
	search1d := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_1d/_search", `{"query":{"term":{"k8s.pod.uid":"pod-a"}}}`), http.StatusOK, "search r64_ds_1d")
	hits1d := search1d["hits"].(map[string]any)["hits"].([]any)
	if len(hits1d) != 1 || fmt.Sprintf("%v", hits1d[0].(map[string]any)["_source"].(map[string]any)["_doc_count"]) != "2" {
		t.Fatalf("expected double-downsampled pod-a _doc_count=2, got %+v", hits1d)
	}

	// Check explicit failure fixture task name (`downsample-<target>-0-<interval> failed`)
	failDS := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_src/_downsample/failed-downsample-test", `{"fixed_interval":"1h"}`), http.StatusInternalServerError, "explicit failed-downsample fixture")
	if !strings.Contains(fmt.Sprintf("%v", failDS), "downsample-failed-downsample-test-0-1h") {
		t.Fatalf("expected failure message containing downsample-failed-downsample-test-0-1h, got %+v", failDS)
	}

	// Non-divisible interval triggers 400 error
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_1h/_downsample/r64_ds_bad", `{"fixed_interval":"90m"}`), http.StatusBadRequest, "non-multiple second downsample")

	// End-to-end HTTP search validation on downsampled index rejects unsupported aggs via ValidateDownsampleAggsSpecMapR64
	badSearchDS := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ds_1h/_search", `{
		"size": 0,
		"aggs": {"cpu_hist": {"histogram": {"field": "cpu", "interval": 10}}}
	}`), http.StatusBadRequest, "unsupported histogram agg on downsampled aggregate_metric_double")
	errObjDS, _ := badSearchDS["error"].(map[string]any)
	if errObjDS == nil || errObjDS["type"] != "unsupported_aggregation_on_downsampled_index" {
		t.Fatalf("expected unsupported_aggregation_on_downsampled_index error type, got %+v", badSearchDS)
	}
}

func TestRound64_Modules_F13_GeoGrid(t *testing.T) {
	// 1. Validation checks
	if err := ValidateGeoGridProcessorR64(map[string]any{"tile_type": "geotile"}); err == nil {
		t.Fatalf("expected error on missing field")
	}
	if err := ValidateGeoGridProcessorR64(map[string]any{"field": "g", "tile_type": "bogus"}); err == nil {
		t.Fatalf("expected error on unsupported tile_type")
	}
	if err := ValidateGeoGridProcessorR64(map[string]any{"field": "g", "tile_type": "geotile", "non_children_field": "nc"}); err == nil {
		t.Fatalf("expected error on non_children_field for geotile")
	}

	// 2. Geotile WKT + GeoJSON + hierarchy (`100_geo_grid_ingest.yml:206-225`)
	gtDoc := map[string]any{"geocell": "4/8/5"}
	if err := ApplyGeoGridProcessorR64(gtDoc, map[string]any{
		"field": "geocell", "tile_type": "geotile", "target_format": "wkt",
		"target_field": "shape", "parent_field": "parent", "children_field": "children", "precision_field": "precision",
	}); err != nil {
		t.Fatalf("geotile ApplyGeoGridProcessorR64 failed: %v", err)
	}
	if gtDoc["parent"] != "3/4/2" || gtDoc["precision"] != 4 {
		t.Fatalf("unexpected geotile parent/precision: %+v", gtDoc)
	}
	if !strings.HasPrefix(fmt.Sprintf("%v", gtDoc["shape"]), "BBOX (0.0, 22.5, 55.776573") {
		t.Fatalf("unexpected geotile WKT shape: %v", gtDoc["shape"])
	}
	if ch, _ := gtDoc["children"].([]any); len(ch) != 4 || ch[0] != "5/16/10" || ch[3] != "5/17/11" {
		t.Fatalf("unexpected geotile children: %+v", ch)
	}

	// 3. Geohash GeoJSON Envelope + children
	ghDoc := map[string]any{"geocell": "u17"}
	if err := ApplyGeoGridProcessorR64(ghDoc, map[string]any{
		"field": "geocell", "tile_type": "geohash", "target_format": "geojson",
		"parent_field": "parent", "children_field": "children", "precision_field": "precision",
	}); err != nil {
		t.Fatalf("geohash ApplyGeoGridProcessorR64 failed: %v", err)
	}
	if env, _ := ghDoc["geocell"].(map[string]any); env["type"] != "Envelope" || ghDoc["parent"] != "u1" || ghDoc["precision"] != 3 {
		t.Fatalf("unexpected geohash GeoJSON result: %+v", ghDoc)
	}
	if ch, _ := ghDoc["children"].([]any); len(ch) != 32 {
		t.Fatalf("expected 32 geohash children, got %d", len(ch))
	}

	// 4. Geohex WKT + GeoJSON + parent + children + nonChildren
	hxDoc := map[string]any{"geocell": "811fbffffffffff"}
	if err := ApplyGeoGridProcessorR64(hxDoc, map[string]any{
		"field": "geocell", "tile_type": "geohex", "target_format": "wkt",
		"target_field": "shape", "parent_field": "parent", "children_field": "children",
		"non_children_field": "nonChildren", "precision_field": "precision",
	}); err != nil {
		t.Fatalf("geohex WKT ApplyGeoGridProcessorR64 failed: %v", err)
	}
	if hxDoc["parent"] != "801ffffffffffff" || hxDoc["precision"] != 1 {
		t.Fatalf("unexpected geohex parent/precision: %+v", hxDoc)
	}
	if !strings.HasPrefix(fmt.Sprintf("%v", hxDoc["shape"]), "POLYGON ((") {
		t.Fatalf("unexpected geohex WKT shape: %v", hxDoc["shape"])
	}
	hxCh, _ := hxDoc["children"].([]any)
	hxNonCh, _ := hxDoc["nonChildren"].([]any)
	if len(hxCh) != 7 || len(hxNonCh) == 0 {
		t.Fatalf("expected 7 geohex children and >0 nonChildren, got %d / %d", len(hxCh), len(hxNonCh))
	}

	// 5. ignore_missing behavior
	missDoc := map[string]any{}
	if err := ApplyGeoGridProcessorR64(missDoc, map[string]any{"field": "geocell", "tile_type": "geotile", "ignore_missing": true}); err != nil {
		t.Fatalf("expected ignore_missing=true to succeed, got %v", err)
	}
	if err := ApplyGeoGridProcessorR64(missDoc, map[string]any{"field": "geocell", "tile_type": "geotile"}); err == nil {
		t.Fatalf("expected missing field error when ignore_missing=false")
	}
}

func TestRound64_Modules_F3_F18_F24_F26_F28(t *testing.T) {
	srv := newRound63ModulesIngestTestServer("8.15.5")
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// F3: ILM multi-wildcard 400, non-monotonic min_age 400, delete-in-use 400, downsample validation
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodGet, "/_ilm/policy/a*,b*", ""), http.StatusBadRequest, "multi-wildcard GET _ilm/policy")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/_ilm/policy/r64_bad_age", `{
		"policy": {"phases": {"warm": {"min_age": "5d", "actions": {}}, "cold": {"min_age": "1d", "actions": {}}}}
	}`), http.StatusBadRequest, "non-monotonic min_age")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/_ilm/policy/r64_bad_ds", `{
		"policy": {"phases": {"hot": {"actions": {"downsample": {"fixed_interval": "invalid_dur"}}}}}
	}`), http.StatusBadRequest, "invalid downsample action interval")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/_ilm/policy/r64_inuse_pol", `{
		"policy": {"phases": {"hot": {"actions": {}}, "warm": {"min_age": "1d", "actions": {}}}}
	}`), http.StatusOK, "put valid ILM policy")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/r64_ilm_idx", `{
		"settings": {"index.lifecycle.name": "r64_inuse_pol"}
	}`), http.StatusOK, "create index referencing ILM policy")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodDelete, "/_ilm/policy/r64_inuse_pol", ""), http.StatusBadRequest, "delete ILM policy in use")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ilm_idx/_ilm/retry", ""), http.StatusBadRequest, "ilm retry non-error state rejected")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/_ilm/move/r64_ilm_idx", `{
		"current_step": {"phase": "hot", "action": "complete", "name": "complete"},
		"next_step": {"phase": "hot", "action": "error", "name": "ERROR"}
	}`), http.StatusOK, "ilm move to ERROR step")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_ilm_idx/_ilm/retry", ""), http.StatusOK, "ilm retry from ERROR state")
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodGet, "/r64_ilm_idx/_ilm/explain", ""), http.StatusOK, "ilm explain")

	// F18: Synonyms rule error message & multi-index _reload_search_analyzers _shards.total
	badSynRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/_synonyms/r64_bad_syn", `{"synonyms_set":[{"id":"1","synonyms":"bad => a, b => c"}]}`), http.StatusBadRequest, "invalid synonym rule")
	if errObj, _ := badSynRes["error"].(map[string]any); errObj == nil {
		t.Fatalf("expected error payload on invalid synonym, got %+v", badSynRes)
	}
	assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/_synonyms/r64_good_syn", `{"synonyms_set":[{"id":"s1","synonyms":"quick, fast"}]}`), http.StatusOK, "put good synonym set")
	for _, idx := range []string{"r64_syn_1", "r64_syn_2"} {
		assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPut, "/"+idx, `{
			"settings": {
				"number_of_shards": 1, "number_of_replicas": 0,
				"analysis": {
					"filter": {"my_syn": {"type": "synonym_graph", "synonyms_set": "r64_good_syn"}},
					"analyzer": {"my_ana": {"tokenizer": "standard", "filter": ["lowercase", "my_syn"]}}
				}
			}
		}`), http.StatusOK, "create "+idx)
	}
	relRes := assertRecStatusR64(t, doRound63ModulesReq(t, h, http.MethodPost, "/r64_syn_1,r64_syn_2/_reload_search_analyzers", ""), http.StatusOK, "reload multi-index analyzers")
	if shards, _ := relRes["_shards"].(map[string]any); fmt.Sprintf("%v", shards["total"]) != "2" {
		t.Fatalf("expected _shards.total=2 across 2 indices, got %+v", relRes)
	}

	// F24: Attachment OOM / cycle bounds
	oversized := strings.Repeat("A", maxIngestAttachmentBase64Bytes+16)
	if _, ok := ExtractIngestAttachmentRound63(oversized, 1000, nil, true); ok {
		t.Fatalf("expected oversized base64 payload to be rejected")
	}
	var manyZip bytes.Buffer
	zwMany := zip.NewWriter(&manyZip)
	for i := 0; i < 4105; i++ {
		if w, err := zwMany.Create(fmt.Sprintf("f_%04d.txt", i)); err == nil {
			_, _ = w.Write([]byte("x"))
		}
	}
	_ = zwMany.Close()
	if out := extractOOXMLDocxAttachmentRound63(manyZip.Bytes(), 1000, true); out != nil {
		t.Fatalf("expected >4096 zip entries without document.xml to return nil, got %+v", out)
	}
	if streams := parseOLE2StreamsRound63(buildFuzzCyclicOLE2R64()); len(streams) != 0 {
		t.Fatalf("expected malformed cyclic OLE2 FAT stream map empty without hanging, got %+v", streams)
	}

	// F26: EQL join tuple cap = maxEQLJoinTuplesPerDoc (1024)
	arr40 := make([]any, 40)
	for i := range arr40 {
		arr40[i] = fmt.Sprintf("v_%d", i)
	}
	joinDoc := map[string]any{"k1": arr40, "k2": arr40}
	tuples := extractEQLJoinKeyTuplesRound63(joinDoc, []eqlExpr{&eqlFieldExpr{name: "k1"}, &eqlFieldExpr{name: "k2"}})
	if len(tuples) != maxEQLJoinTuplesPerDoc {
		t.Fatalf("expected join tuples capped at %d, got %d", maxEQLJoinTuplesPerDoc, len(tuples))
	}

	// F28: Concurrent SQL async atomic ID generation under -race
	var wg sync.WaitGroup
	ids := make(chan string, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- nextSQLAsyncSearchIDR64()
		}()
	}
	wg.Wait()
	close(ids)
	seenIDs := make(map[string]bool, 64)
	for id := range ids {
		if seenIDs[id] {
			t.Fatalf("duplicate SQL async ID generated: %q", id)
		}
		seenIDs[id] = true
	}
}
