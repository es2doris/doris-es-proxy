package proxy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound59Req(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, rec.Header(), parsed, raw
}

func assertESErrorTypeRound59(t *testing.T, resp map[string]any, wantType string) {
	t.Helper()
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in response, got: %v", resp)
	}
	gotType, _ := errObj["type"].(string)
	if gotType != wantType {
		t.Fatalf("expected error.type=%q, got %q (full=%v)", wantType, gotType, resp)
	}
}

func TestRound59_F2_SingleDocCRUDValidationAndUpdateFields(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	// 1. Missing-index 404 index_not_found_exception across GET/HEAD/DELETE/_source.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/no_such_r59/_doc/1", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET missing index, got %d (%v)", c, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "index_not_found_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/no_such_r59/_source/1", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on GET _source missing index, got %d (%v)", c, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "index_not_found_exception")
	}
	if c, _, _, raw := doRound59Req(t, h, http.MethodHead, "/no_such_r59/_doc/1", "", nil); c != http.StatusNotFound || raw != "" {
		t.Fatalf("expected clean 404 HEAD on missing index _doc, got %d body=%q", c, raw)
	}
	if c, _, _, raw := doRound59Req(t, h, http.MethodHead, "/no_such_r59/_source/1", "", nil); c != http.StatusNotFound || raw != "" {
		t.Fatalf("expected clean 404 HEAD on missing index _source, got %d body=%q", c, raw)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodDelete, "/no_such_r59/_doc/1", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on DELETE missing index, got %d (%v)", c, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "index_not_found_exception")
	}

	// Create index & document on srv, then verify a second server sharing MemoryBackend syncs on cache miss.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_crud", `{"mappings":{"properties":{"title":{"type":"keyword"},"count":{"type":"long"}}}}`, nil); c != http.StatusOK {
		t.Fatalf("PUT /r59_crud failed: %d %v", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_crud/_doc/1?refresh=true", `{"title":"init","count":5}`, nil); c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("PUT doc failed: %d %v", c, resp)
	}

	srv2 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if c, _, resp, _ := doRound59Req(t, srv2.Handler(), http.MethodGet, "/r59_crud/_doc/1", "", nil); c != http.StatusOK || resp["found"] != true {
		t.Fatalf("expected cache-miss catalog sync on srv2 GET doc, got %d %v", c, resp)
	}

	// 2. handlePutDoc op_type & auto-ID OCC/version validation.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_crud/_doc/2?op_type=bogus", `{"title":"x"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid op_type, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_crud/_create/2?op_type=index", `{"title":"x"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on /_create with op_type=index, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
	}
	for _, occParam := range []string{"if_seq_no=0", "if_primary_term=1", "version=2"} {
		if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_doc?"+occParam, `{"title":"auto"}`, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on auto-ID POST with %s, got %d", occParam, c)
		} else {
			assertESErrorTypeRound59(t, resp, "action_request_validation_exception")
		}
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_doc?op_type=create&refresh=true", `{"title":"auto_ok","count":1}`, nil); c != http.StatusCreated {
		t.Fatalf("expected 201 on auto-ID POST with op_type=create, got %d %v", c, resp)
	}

	// 3. handleUpdateDoc boolean strictness, missing index, and get.fields extraction.
	for _, badQuery := range []string{"doc_as_upsert=maybe", "detect_noop=nope"} {
		if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_update/1?"+badQuery, `{"doc":{"count":6}}`, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on %s, got %d", badQuery, c)
		} else {
			assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
		}
	}
	for _, badBody := range []string{
		`{"doc":{"count":6},"doc_as_upsert":"not_bool"}`,
		`{"doc":{"count":6},"detect_noop":123}`,
		`{"script":{"source":"ctx._source.count += 1"},"scripted_upsert":"bad"}`,
		`{"doc":{"count":6},"fields":123}`,
	} {
		if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_update/1", badBody, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on body %s, got %d (%v)", badBody, c, resp)
		}
	}
	// Missing index _update without upsert -> 404.
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/missing_upd_idx/_update/1", `{"doc":{"count":1}}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on _update against missing index without upsert, got %d", c)
	}

	// Update with body fields + _source: true.
	updBody := `{"doc":{"title":"updated_title","count":42},"_source":true,"fields":["title",{"field":"count"}]}`
	c, _, updResp, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_update/1?refresh=true", updBody, nil)
	if c != http.StatusOK {
		t.Fatalf("expected 200 on _update with fields, got %d %v", c, updResp)
	}
	getMap, _ := updResp["get"].(map[string]any)
	fieldsMap, _ := getMap["fields"].(map[string]any)
	if fieldsMap == nil {
		t.Fatalf("expected get.fields in _update response, got %v", updResp)
	}
	titleArr, _ := fieldsMap["title"].([]any)
	if len(titleArr) != 1 || titleArr[0] != "updated_title" {
		t.Fatalf("expected get.fields.title=[updated_title], got %v", fieldsMap)
	}

	// Update with ?fields=title query param (implicitly populates get.fields).
	c, _, updResp2, _ := doRound59Req(t, h, http.MethodPost, "/r59_crud/_update/1?fields=title&refresh=true", `{"doc":{"count":99}}`, nil)
	if c != http.StatusOK {
		t.Fatalf("expected 200 on _update?fields=title, got %d %v", c, updResp2)
	}
	getMap2, _ := updResp2["get"].(map[string]any)
	fieldsMap2, _ := getMap2["fields"].(map[string]any)
	if fieldsMap2 == nil || fieldsMap2["title"] == nil {
		t.Fatalf("expected get.fields.title on ?fields=title, got %v", updResp2)
	}
}

func TestRound59_F3_MultiPercolateAPI(t *testing.T) {
	_, h := newTestServerWithMock(t)

	// Setup percolate index and stored docs index.
	c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_perc", `{
		"mappings": {
			"properties": {
				"query": {"type": "percolator"},
				"message": {"type": "text"},
				"env": {"type": "keyword"}
			}
		}
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("PUT /r59_perc failed: %d %v", c, resp)
	}
	doRound59Req(t, h, http.MethodPut, "/r59_perc/_doc/q1?refresh=true", `{"env":"prod","query":{"match":{"message":"fox"}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_perc/_doc/q2?refresh=true", `{"env":"dev","query":{"match":{"message":"dog"}}}`, nil)

	doRound59Req(t, h, http.MethodPut, "/r59_docs", `{"mappings":{"properties":{"message":{"type":"text"}}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_docs/_doc/d1?refresh=true", `{"message":"quick brown fox"}`, nil)

	// 1. Method guards & framing errors.
	if code, _, _, _ := doRound59Req(t, h, http.MethodPut, "/_mpercolate", "", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT /_mpercolate, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodDelete, "/r59_perc/_mpercolate", "", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE /{index}/_mpercolate, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_mpercolate", "", map[string]string{"Content-Type": "application/x-ndjson"}); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty _mpercolate body, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_mpercolate", "{\"percolate\":{\"index\":\"r59_perc\"}}\n", map[string]string{"Content-Type": "application/x-ndjson"}); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on odd NDJSON lines in _mpercolate, got %d", code)
	}

	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_mpercolate", "{\"unknown_header\":{}}\n{\"doc\":{\"message\":\"fox\"}}\n", map[string]string{"Content-Type": "application/x-ndjson"}); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown header action in _mpercolate, got %d", code)
	}

	// 2. Multi-item batch: inline doc, multi-documents, count pair, stored-doc lookup + filter query/aggs, and inline error isolation!
	ndjson := strings.Join([]string{
		`{"percolate":{}}`,
		`{"doc":{"message":"the brown fox jumps"}}`,
		`{"percolate":{"index":"r59_perc"}}`,
		`{"documents":[{"message":"lazy dog"},{"message":"nothing"}]}`,
		`{"count":{"index":"r59_perc"}}`,
		`{"doc":{"message":"quick fox"}}`,
		`{"percolate":{"index":"r59_perc","percolate_index":"r59_docs","id":"d1"}}`,
		`{"query":{"term":{"env":"prod"}},"aggs":{"envs":{"terms":{"field":"env"}}},"_source":true,"track_total_hits":true}`,
		`{"percolate":{"index":"no_such_perc_idx"}}`,
		`{"doc":{"message":"fox"}}`,
		`{"percolate":{"index":"r59_perc","percolate_index":"no_such_lookup_idx","id":"d1"}}`,
		`{}`,
		`{"percolate":{"index":"r59_perc","percolate_index":"r59_docs","id":"missing_doc"}}`,
		`{}`,
		`{"percolate":{"index":"r59_perc"}}`,
		`{}`,
		"",
	}, "\n")

	code, _, mpResp, _ := doRound59Req(t, h, http.MethodGet, "/r59_perc/_mpercolate", ndjson, map[string]string{"Content-Type": "application/x-ndjson"})
	if code != http.StatusOK {
		t.Fatalf("GET /r59_perc/_mpercolate failed: %d %v", code, mpResp)
	}
	items, _ := mpResp["responses"].([]any)
	if len(items) != 8 {
		t.Fatalf("expected 8 responses, got %d (%v)", len(items), mpResp)
	}

	// Item 0: inline doc matches q1.
	it0 := items[0].(map[string]any)
	if it0["status"] != float64(200) {
		t.Fatalf("item 0 expected status 200, got %v", it0)
	}
	if len(it0["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("item 0 expected 1 hit, got %v", it0)
	}

	// Item 1: documents matches q2.
	it1 := items[1].(map[string]any)
	if it1["status"] != float64(200) || len(it1["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("item 1 expected 1 hit, got %v", it1)
	}

	// Item 2: count pair -> status 200, hits.hits empty, total.value == 1.
	it2 := items[2].(map[string]any)
	if it2["status"] != float64(200) {
		t.Fatalf("item 2 expected status 200, got %v", it2)
	}
	it2Hits := it2["hits"].(map[string]any)
	if len(it2Hits["hits"].([]any)) != 0 || it2Hits["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("item 2 count expected 0 hit rows and total=1, got %v", it2)
	}

	// Item 3: stored document d1 + filter query + aggs.
	it3 := items[3].(map[string]any)
	if it3["status"] != float64(200) || len(it3["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("item 3 stored-doc percolate failed: %v", it3)
	}
	if it3["aggregations"] == nil {
		t.Fatalf("item 3 expected aggregations, got %v", it3)
	}

	// Items 4..7: isolated inline errors (404, 404, 400, 400) without failing batch.
	if items[4].(map[string]any)["status"] != float64(404) {
		t.Fatalf("item 4 expected inline 404 for missing index, got %v", items[4])
	}
	if items[5].(map[string]any)["status"] != float64(404) {
		t.Fatalf("item 5 expected inline 404 for missing lookup index, got %v", items[5])
	}
	if items[6].(map[string]any)["status"] != float64(400) {
		t.Fatalf("item 6 expected inline 400 for missing stored doc, got %v", items[6])
	}
	if items[7].(map[string]any)["status"] != float64(400) {
		t.Fatalf("item 7 expected inline 400 for missing doc/id, got %v", items[7])
	}
}

func TestRound59_F4_OpenCloseLifecyclePersistenceAndGuards(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv1 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h1 := srv1.Handler()

	doRound59Req(t, h1, http.MethodPut, "/logs-001", `{}`, nil)
	doRound59Req(t, h1, http.MethodPut, "/logs-002", `{}`, nil)

	// Close logs-001.
	c, _, closeResp, _ := doRound59Req(t, h1, http.MethodPost, "/logs-001/_close", "", nil)
	if c != http.StatusOK || closeResp["acknowledged"] != true {
		t.Fatalf("POST /logs-001/_close failed: %d %v", c, closeResp)
	}

	// Closed index guards on _stats, _refresh, _flush, _flush/synced.
	for _, ep := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/logs-001/_stats"},
		{http.MethodPost, "/logs-001/_refresh"},
		{http.MethodPost, "/logs-001/_flush"},
		{http.MethodPost, "/logs-001/_flush/synced"},
	} {
		code, _, resp, _ := doRound59Req(t, h1, ep.method, ep.path, "", nil)
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 index_closed_exception on %s %s, got %d (%v)", ep.method, ep.path, code, resp)
		}
		assertESErrorTypeRound59(t, resp, "index_closed_exception")

		codeOK, _, _, _ := doRound59Req(t, h1, ep.method, ep.path+"?ignore_unavailable=true", "", nil)
		if codeOK != http.StatusOK {
			t.Fatalf("expected 200 with ignore_unavailable=true on %s %s, got %d", ep.method, ep.path, codeOK)
		}
	}

	// Persistence across fresh Server instance over shared MemoryBackend.
	srv2 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h2 := srv2.Handler()
	if code, _, resp, _ := doRound59Req(t, h2, http.MethodGet, "/logs-001/_stats", "", nil); code != http.StatusBadRequest {
		t.Fatalf("expected closed state persisted to srv2, got %d %v", code, resp)
	}

	// Wildcard _open defaults expand_wildcards=open,closed -> reopens logs-001 and returns shook_acknowledged: true!
	code, _, openResp, _ := doRound59Req(t, h2, http.MethodPost, "/logs-*/_open", "", nil)
	if code != http.StatusOK || openResp["acknowledged"] != true || openResp["shook_acknowledged"] != true {
		t.Fatalf("POST /logs-*/_open failed: %d %v", code, openResp)
	}
	if code, _, _, _ := doRound59Req(t, h2, http.MethodGet, "/logs-001/_stats", "", nil); code != http.StatusOK {
		t.Fatalf("expected 200 on /logs-001/_stats after wildcard _open, got %d", code)
	}

	// Verify reopened state persisted to srv3.
	srv3 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if code, _, _, _ := doRound59Req(t, srv3.Handler(), http.MethodGet, "/logs-001/_stats", "", nil); code != http.StatusOK {
		t.Fatalf("expected reopened state persisted to srv3, got %d", code)
	}

	// Reject closing a data stream directly.
	doRound59Req(t, h1, http.MethodPut, "/_index_template/r59_ds_tpl", `{"index_patterns":["r59-ds*"],"data_stream":{}}`, nil)
	doRound59Req(t, h1, http.MethodPut, "/_data_stream/r59-ds", `{}`, nil)
	if code, _, resp, _ := doRound59Req(t, h1, http.MethodPost, "/r59-ds/_close", "", nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 closing data stream directly, got %d %v", code, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
	}
}

func TestRound59_F5_RolloverConditionEngineCreationDateAndSettings(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	// Template matching rolled-over indices.
	doRound59Req(t, h, http.MethodPut, "/_index_template/r59_roll_tpl", `{
		"index_patterns": ["roll-*"],
		"template": {
			"settings": {"number_of_shards": 2, "refresh_interval": "5s"},
			"mappings": {"properties": {"msg": {"type": "keyword"}}}
		}
	}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_ingest/pipeline/r59_roll_pipe", `{"processors":[{"set":{"field":"piped","value":true}}]}`, nil)

	beforeMs := time.Now().UnixMilli()
	c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/roll-000001", `{
		"aliases": {"roll_alias": {"is_write_index": true}}
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("PUT /roll-000001 failed: %d %v", c, resp)
	}

	// Verify dynamic creation_date in GET _settings.
	_, _, stResp, _ := doRound59Req(t, h, http.MethodGet, "/roll-000001/_settings", "", nil)
	idxSt := stResp["roll-000001"].(map[string]any)["settings"].(map[string]any)["index"].(map[string]any)
	cdStr, _ := idxSt["creation_date"].(string)
	cdVal, err := strconv.ParseInt(cdStr, 10, 64)
	if err != nil || cdVal < beforeMs-1000 {
		t.Fatalf("expected real dynamic creation_date >= %d, got %q", beforeMs, cdStr)
	}

	// Validation failures on _rollover.
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover?dry_run=notbool", `{}`, nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid dry_run bool, got %d", code)
	}
	for _, badBody := range []string{
		`{"conditions":{"unknown_cond":1}}`,
		`{"conditions":{"max_docs":-1}}`,
		`{"conditions":{"max_age":"invalid_dur"}}`,
		`{"conditions":{"max_size":"99xyz"}}`,
		`{"settings":{"number_of_shards":0}}`,
		`{"aliases":{"roll-000001":{}}}`,
	} {
		if code, _, rErr, _ := doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover", badBody, nil); code != http.StatusBadRequest {
			t.Fatalf("expected 400 on rollover body %s, got %d (%v)", badBody, code, rErr)
		}
	}

	// Index 2 documents into roll-000001 (number_of_shards=2 -> primaryShardDocs=1).
	doRound59Req(t, h, http.MethodPut, "/roll-000001/_doc/1?refresh=true", `{"msg":"hello_world_payload_one"}`, nil)
	doRound59Req(t, h, http.MethodPut, "/roll-000001/_doc/2?refresh=true", `{"msg":"hello_world_payload_two"}`, nil)

	// max_docs=2 met, BUT min_docs=5 unmet -> rolled_over: false!
	c, _, rResp, _ := doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover", `{"conditions":{"max_docs":2,"min_docs":5}}`, nil)
	if c != http.StatusOK || rResp["rolled_over"] != false {
		t.Fatalf("expected rolled_over=false when min_docs unmet, got %d %v", c, rResp)
	}

	// max_primary_shard_docs=2 unmet (2 docs / 2 shards = 1) -> rolled_over: false!
	c, _, rResp, _ = doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover", `{"conditions":{"max_primary_shard_docs":2}}`, nil)
	if c != http.StatusOK || rResp["rolled_over"] != false {
		t.Fatalf("expected rolled_over=false when max_primary_shard_docs=2 unmet, got %d %v", c, rResp)
	}

	// Wait 5ms so max_age="1ms" is met alongside max_size="10b" & min_docs=2, test dry_run=true first.
	// Per ES rest-api-spec, dry_run=true evaluates all conditions to true while keeping rolled_over=false.
	time.Sleep(5 * time.Millisecond)
	c, _, dryResp, _ := doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover?dry_run=true", `{
		"conditions": {"max_age": "1ms", "max_size": "10b", "min_docs": 2}
	}`, nil)
	dryConds, _ := dryResp["conditions"].(map[string]any)
	if c != http.StatusOK || dryResp["rolled_over"] != false || dryResp["dry_run"] != true ||
		dryConds["[max_age: 1ms]"] != true || dryConds["[max_size: 10b]"] != true || dryConds["[min_docs: 2]"] != true {
		t.Fatalf("expected dry_run=true with rolled_over=false and all conditions=true, got %d %v", c, dryResp)
	}

	// Execute real rollover with custom settings + default_pipeline.
	c, _, realResp, _ := doRound59Req(t, h, http.MethodPost, "/roll_alias/_rollover", `{
		"conditions": {"max_primary_shard_docs": 1, "min_size": "10b"},
		"settings": {"index.number_of_replicas": 2, "index.default_pipeline": "r59_roll_pipe"}
	}`, nil)
	if c != http.StatusOK || realResp["rolled_over"] != true || realResp["new_index"] != "roll-000002" {
		t.Fatalf("expected rollover into roll-000002, got %d %v", c, realResp)
	}

	// Verify template + req.Settings + fresh creation_date applied on roll-000002!
	_, _, stResp2, _ := doRound59Req(t, h, http.MethodGet, "/roll-000002/_settings", "", nil)
	idxSt2 := stResp2["roll-000002"].(map[string]any)["settings"].(map[string]any)["index"].(map[string]any)
	if fmt.Sprintf("%v", idxSt2["number_of_shards"]) != "2" || fmt.Sprintf("%v", idxSt2["number_of_replicas"]) != "2" {
		t.Fatalf("expected template shards=2 & override replicas=2 on roll-000002, got %v", idxSt2)
	}
	if idxSt2["default_pipeline"] != "r59_roll_pipe" {
		t.Fatalf("expected default_pipeline=r59_roll_pipe on roll-000002, got %v", idxSt2)
	}
}

func TestRound59_F6_ShrinkSplitCloneCompliance(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	doRound59Req(t, h, http.MethodPut, "/_ingest/pipeline/r59_clone_pipe", `{"processors":[{"set":{"field":"cloned_pipe","value":"yes"}}]}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_resize_src", `{
		"settings": {
			"number_of_shards": 4,
			"number_of_replicas": 1,
			"default_pipeline": "r59_clone_pipe",
			"blocks.write": true
		},
		"mappings": {"properties": {"k": {"type": "keyword"}}}
	}`, nil)
	// Temporarily unblock write to index a doc with external version & routing.
	doRound59Req(t, h, http.MethodPut, "/r59_resize_src/_settings", `{"index.blocks.write":false}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_resize_src/_doc/d1?routing=r1&version=1&version_type=external&refresh=true", `{"k":"v1"}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_resize_src/_doc/d1?routing=r1&version=2&version_type=external&refresh=true", `{"k":"v2"}`, nil)

	// Method guard.
	if c, _, _, _ := doRound59Req(t, h, http.MethodGet, "/r59_resize_src/_clone/r59_dst", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET _clone, got %d", c)
	}

	// Closed source index guard.
	doRound59Req(t, h, http.MethodPut, "/r59_closed_src", `{}`, nil)
	doRound59Req(t, h, http.MethodPost, "/r59_closed_src/_close", "", nil)
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_closed_src/_clone/r59_closed_dst", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 index_closed_exception on closed _clone source, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "index_closed_exception")
	}

	// Data-stream source guard.
	doRound59Req(t, h, http.MethodPut, "/_index_template/r59_rs_ds_tpl", `{"index_patterns":["r59-rs-ds*"],"data_stream":{}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_data_stream/r59-rs-ds", `{}`, nil)
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59-rs-ds/_clone/r59_ds_dst", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on data-stream _clone source, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
	}

	// Invalid target name & alias collision.
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_resize_src/_clone/BAD_UPPER", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on uppercase target index, got %d", c)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_resize_src/_clone/r59_alias_bad", `{"aliases":{"r59_resize_src":{}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on alias colliding with concrete index, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "invalid_alias_name_exception")
	}

	// _split shard factor validation (source has 4 shards -> 4 and 6 fail, 8 succeeds).
	for _, badSplit := range []int{4, 6} {
		body := fmt.Sprintf(`{"settings":{"index.number_of_shards":%d}}`, badSplit)
		if c, _, _, _ := doRound59Req(t, h, http.MethodPost, fmt.Sprintf("/r59_resize_src/_split/r59_split_%d", badSplit), body, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 splitting 4 shards to %d, got %d", badSplit, c)
		}
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_resize_src/_split/r59_split_8", `{"settings":{"index.number_of_shards":8}}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 splitting 4 shards to 8, got %d %v", c, resp)
	}

	// _shrink shard factor validation (source has 4 shards -> 8 and 3 fail, 2 succeeds).
	for _, badShrink := range []int{8, 3} {
		body := fmt.Sprintf(`{"settings":{"index.number_of_shards":%d}}`, badShrink)
		if c, _, _, _ := doRound59Req(t, h, http.MethodPost, fmt.Sprintf("/r59_resize_src/_shrink/r59_shrink_%d", badShrink), body, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 shrinking 4 shards to %d, got %d", badShrink, c)
		}
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_resize_src/_shrink/r59_shrink_2", `{"settings":{"index.number_of_shards":2,"index.number_of_replicas":0}}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 shrinking 4 shards to 2, got %d %v", c, resp)
	}

	// Verify docVersions and docRouting copied on active server, and settings/pipelines/docs persisted across restart!
	c, _, gActive, _ := doRound59Req(t, h, http.MethodGet, "/r59_shrink_2/_doc/d1", "", nil)
	if c != http.StatusOK || gActive["_version"] != float64(2) || gActive["_routing"] != "r1" {
		t.Fatalf("expected copied doc version=2 & routing=r1 on shrunk index, got %d %v", c, gActive)
	}
	srv2 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h2 := srv2.Handler()
	c, _, gResp, _ := doRound59Req(t, h2, http.MethodGet, "/r59_shrink_2/_doc/d1", "", nil)
	if c != http.StatusOK || gResp["_version"] != float64(2) {
		t.Fatalf("expected copied doc version=2 persisted on shrunk index across restart, got %d %v", c, gResp)
	}
	// Index new doc into shrunk index without explicit pipeline -> copied default_pipeline runs!
	doRound59Req(t, h2, http.MethodPut, "/r59_shrink_2/_doc/d2?refresh=true", `{"k":"v_new"}`, nil)
	_, _, gResp2, _ := doRound59Req(t, h2, http.MethodGet, "/r59_shrink_2/_doc/d2", "", nil)
	srcMap2, _ := gResp2["_source"].(map[string]any)
	if srcMap2["cloned_pipe"] != "yes" {
		t.Fatalf("expected copied default_pipeline to execute on shrunk index, got %v", gResp2)
	}
}

func TestRound59_F7_EnrichSnapshotIsolationPersistenceGeoMatchAndREST(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	// 1. /_enrich/stats method guard, HEAD, and cache_stats.
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_enrich/stats", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /_enrich/stats, got %d", c)
	}
	if c, _, _, raw := doRound59Req(t, h, http.MethodHead, "/_enrich/stats", "", nil); c != http.StatusOK || raw != "" {
		t.Fatalf("expected 200 empty body on HEAD /_enrich/stats, got %d %q", c, raw)
	}
	c, _, statsResp, _ := doRound59Req(t, h, http.MethodGet, "/_enrich/stats", "", nil)
	if c != http.StatusOK || statsResp["cache_stats"] == nil {
		t.Fatalf("expected cache_stats in GET /_enrich/stats, got %d %v", c, statsResp)
	}

	// 2. Snapshot isolation after _execute + persistence across restart + HEAD / wildcard DELETE.
	doRound59Req(t, h, http.MethodPut, "/r59_enrich_src", `{"mappings":{"properties":{"k":{"type":"keyword"},"label":{"type":"keyword"}}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_enrich_src/_doc/1?refresh=true", `{"k":"k1","label":"snapshotted"}`, nil)

	if c, _, _, _ := doRound59Req(t, h, http.MethodHead, "/_enrich/policy/missing_pol", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on HEAD missing enrich policy, got %d", c)
	}
	doRound59Req(t, h, http.MethodPut, "/_enrich/policy/iso_pol", `{"match":{"indices":"r59_enrich_src","match_field":"k","enrich_fields":["label"]}}`, nil)
	if c, _, _, raw := doRound59Req(t, h, http.MethodHead, "/_enrich/policy/iso_pol", "", nil); c != http.StatusOK || raw != "" {
		t.Fatalf("expected 200 on HEAD existing enrich policy, got %d %q", c, raw)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/_enrich/policy/iso_pol/_execute", "", nil); c != http.StatusOK {
		t.Fatalf("POST _execute failed: %d %v", c, resp)
	}

	// Write a post-_execute doc k2 into r59_enrich_src WITHOUT re-executing iso_pol!
	doRound59Req(t, h, http.MethodPut, "/r59_enrich_src/_doc/2?refresh=true", `{"k":"k2","label":"leaked_live"}`, nil)

	// Verify on fresh Server instance (testing _execute persistence + strict snapshot isolation).
	srv2 := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h2 := srv2.Handler()
	c, _, simResp, _ := doRound59Req(t, h2, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"enrich": {"policy_name": "iso_pol", "field": "k", "target_field": "enr"}}]},
		"docs": [{"_source": {"k": "k1"}}, {"_source": {"k": "k2"}}]
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("simulate iso_pol failed: %d %v", c, simResp)
	}
	simDocs := simResp["docs"].([]any)
	doc0Src := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	doc1Src := simDocs[1].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if doc0Src["enr"] == nil {
		t.Fatalf("expected k1 to enrich from persisted snapshot, got %v", doc0Src)
	}
	if doc1Src["enr"] != nil {
		t.Fatalf("expected k2 NOT to leak from live source index after _execute, got %v", doc1Src)
	}

	// 3. Spatial geo_match across GeoJSON Polygon / Envelope / WKT + intersects/contains/within/disjoint.
	if c, _, _, _ := doRound59Req(t, h2, http.MethodPut, "/_enrich/policy/bad_geo", `{"geo_match":{"indices":"r59_enrich_src","match_field":"k","enrich_fields":["label"],"shape_relation":"bogus"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid shape_relation in PUT policy, got %d", c)
	}
	doRound59Req(t, h2, http.MethodPut, "/r59_geo_zones", `{"mappings":{"properties":{"zone_name":{"type":"keyword"},"geom":{"type":"geo_shape"}}}}`, nil)
	doRound59Req(t, h2, http.MethodPut, "/r59_geo_zones/_doc/z1?refresh=true", `{
		"zone_name": "downtown",
		"geom": {"type": "Polygon", "coordinates": [[[0.0, 0.0], [10.0, 0.0], [10.0, 10.0], [0.0, 10.0], [0.0, 0.0]]]}
	}`, nil)
	doRound59Req(t, h2, http.MethodPut, "/_enrich/policy/geo_pol", `{
		"geo_match": {"indices": "r59_geo_zones", "match_field": "geom", "enrich_fields": ["zone_name"]}
	}`, nil)
	doRound59Req(t, h2, http.MethodPost, "/_enrich/policy/geo_pol/_execute", "", nil)

	c, _, geoSim, _ := doRound59Req(t, h2, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"enrich": {"policy_name": "geo_pol", "field": "loc", "target_field": "inter_zone"}},
				{"enrich": {"policy_name": "geo_pol", "field": "loc", "target_field": "disjoint_zone", "shape_relation": "disjoint"}},
				{"enrich": {"policy_name": "geo_pol", "field": "big_box", "target_field": "within_zone", "shape_relation": "within", "ignore_missing": true}}
			]
		},
		"docs": [
			{"_source": {"loc": "POINT (5 5)", "big_box": {"type": "envelope", "coordinates": [[-5.0, 15.0], [15.0, -5.0]]}}},
			{"_source": {"loc": [50.0, 50.0]}}
		]
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("geo_match simulate failed: %d %v", c, geoSim)
	}
	gDocs := geoSim["docs"].([]any)
	g0 := gDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	g1 := gDocs[1].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if g0["inter_zone"] == nil || g0["disjoint_zone"] != nil || g0["within_zone"] == nil {
		t.Fatalf("unexpected geo_match result for inside point + outer envelope: %v", g0)
	}
	if g1["inter_zone"] != nil || g1["disjoint_zone"] == nil {
		t.Fatalf("unexpected geo_match result for outside point [50,50]: %v", g1)
	}

	// 4. Multi-policy comma + wildcard DELETE.
	doRound59Req(t, h2, http.MethodPut, "/_enrich/policy/del_a", `{"match":{"indices":"r59_enrich_src","match_field":"k","enrich_fields":["label"]}}`, nil)
	doRound59Req(t, h2, http.MethodPut, "/_enrich/policy/del_b1", `{"match":{"indices":"r59_enrich_src","match_field":"k","enrich_fields":["label"]}}`, nil)
	if c, _, _, _ := doRound59Req(t, h2, http.MethodDelete, "/_enrich/policy/del_a,del_b*", "", nil); c != http.StatusOK {
		t.Fatalf("expected 200 on comma/wildcard DELETE enrich policy, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h2, http.MethodHead, "/_enrich/policy/del_b1", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected del_b1 deleted, got %d", c)
	}
}

func TestRound59_F8_SnapshotRestoreMountAndGlobalState(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	// 1. Missing repository type -> 400 action_request_validation_exception.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/_snapshot/r59_repo", `{"settings":{"location":"/tmp/snap"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when snapshot repo type is missing, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "action_request_validation_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/_snapshot/r59_repo", `{"type":"fs","settings":{"location":"/tmp/snap"}}`, nil); c != http.StatusOK {
		t.Fatalf("PUT /_snapshot/r59_repo failed: %d %v", c, resp)
	}

	// 2. Setup global state (composable template, legacy template, cluster setting, pipeline) + index state.
	doRound59Req(t, h, http.MethodPut, "/_index_template/r59_comp_tpl", `{"index_patterns":["snap-comp-*"],"template":{"settings":{"number_of_shards":3}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_template/r59_leg_tpl", `{"index_patterns":["snap-leg-*"],"settings":{"number_of_replicas":1}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"indices.recovery.max_bytes_per_sec":"80mb"}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_ingest/pipeline/r59_snap_def", `{"processors":[{"set":{"field":"from_def","value":true}}]}`, nil)
	doRound59Req(t, h, http.MethodPut, "/_ingest/pipeline/r59_snap_fin", `{"processors":[{"set":{"field":"from_fin","value":true}}]}`, nil)

	doRound59Req(t, h, http.MethodPut, "/r59_snap_idx", `{
		"settings": {"default_pipeline": "r59_snap_def", "final_pipeline": "r59_snap_fin"},
		"aliases": {"r59_snap_alias": {}},
		"mappings": {"properties": {"v": {"type": "keyword"}}}
	}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_snap_idx/_doc/orig?refresh=true", `{"v":"original"}`, nil)

	// Take snapshot with include_global_state: true.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/_snapshot/r59_repo/snap_1", `{"include_global_state":true}`, nil); c != http.StatusOK {
		t.Fatalf("create snapshot failed: %d %v", c, resp)
	}

	// 3. _mount onto existing index -> 400 snapshot_restore_exception; _mount onto new index -> 200.
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/_snapshot/r59_repo/snap_1/_mount", `{"index":"r59_snap_idx"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 mounting onto existing open index, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "snapshot_restore_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/_snapshot/r59_repo/snap_1/_mount", `{"index":"r59_snap_idx","renamed_index":"r59_mounted_idx"}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 mounting onto new renamed_index, got %d %v", c, resp)
	}

	// 4. _restore onto OPEN index -> 400 snapshot_restore_exception!
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/_snapshot/r59_repo/snap_1/_restore", `{"indices":"r59_snap_idx"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 restoring onto open index, got %d", c)
	} else {
		assertESErrorTypeRound59(t, resp, "snapshot_restore_exception")
	}

	// 5. Mutate r59_snap_idx (add post-snapshot doc), close it, also test _mount onto closed -> 400, then _restore!
	doRound59Req(t, h, http.MethodPut, "/r59_snap_idx/_doc/post_snap?refresh=true", `{"v":"should_disappear"}`, nil)
	doRound59Req(t, h, http.MethodPost, "/r59_snap_idx/_close", "", nil)

	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/_snapshot/r59_repo/snap_1/_mount", `{"index":"r59_snap_idx"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 mounting onto existing closed index, got %d %v", c, resp)
	}

	// Wipe global templates & cluster setting before restore to prove include_global_state restores them!
	doRound59Req(t, h, http.MethodDelete, "/_index_template/r59_comp_tpl", "", nil)
	doRound59Req(t, h, http.MethodDelete, "/_template/r59_leg_tpl", "", nil)
	doRound59Req(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"indices.recovery.max_bytes_per_sec":null}}`, nil)

	c, _, resResp, _ := doRound59Req(t, h, http.MethodPost, "/_snapshot/r59_repo/snap_1/_restore", `{"indices":"r59_snap_idx","include_global_state":true}`, nil)
	if c != http.StatusOK {
		t.Fatalf("expected 200 restoring onto closed index, got %d %v", c, resResp)
	}
	shardsMap := resResp["snapshot"].(map[string]any)["shards"].(map[string]any)
	if shardsMap["total"] != float64(1) || shardsMap["successful"] != float64(1) {
		t.Fatalf("expected shards total=1 successful=1, got %v", resResp)
	}

	// Closed index must now be OPEN, post_snap doc must be GONE, orig doc + pipelines + global state restored!
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/r59_snap_idx/_stats", "", nil); code != http.StatusOK {
		t.Fatalf("expected restored index to be reopened, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/r59_snap_idx/_doc/post_snap", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected post-snapshot doc dropped during closed-index restore, got %d", code)
	}
	if code, _, gOrig, _ := doRound59Req(t, h, http.MethodGet, "/r59_snap_idx/_doc/orig", "", nil); code != http.StatusOK || gOrig["found"] != true {
		t.Fatalf("expected snapshotted doc restored, got %d %v", code, gOrig)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/_index_template/r59_comp_tpl", "", nil); code != http.StatusOK {
		t.Fatalf("expected composable template restored via include_global_state, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/_template/r59_leg_tpl", "", nil); code != http.StatusOK {
		t.Fatalf("expected legacy template restored via include_global_state, got %d", code)
	}
	_, _, csResp, _ := doRound59Req(t, h, http.MethodGet, "/_cluster/settings", "", nil)
	if !strings.Contains(fmt.Sprintf("%v", csResp["persistent"]), "80mb") {
		t.Fatalf("expected persistent cluster setting restored, got %v", csResp)
	}
}

func TestRound59_F9_WireStrictnessValidateQueryAndTermsEnum(t *testing.T) {
	_, h := newTestServerWithMock(t)

	doRound59Req(t, h, http.MethodPut, "/r59_w1", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_w2", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_w1/_doc/1?refresh=true", `{"tag":"alpha"}`, nil)
	doRound59Req(t, h, http.MethodPut, "/r59_w2/_doc/2?refresh=true", `{"tag":"alpha_two"}`, nil)

	// 1. Wire boolean query params: pretty, error_trace, human.
	for _, qp := range []string{"pretty=bogus", "error_trace=2", "human=nope"} {
		if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/?"+qp, "", nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on /?%s, got %d", qp, c)
		} else {
			assertESErrorTypeRound59(t, resp, "illegal_argument_exception")
		}
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodHead, "/r59_w1?pretty=bogus", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on HEAD with invalid pretty, got %d", c)
	}
	for _, okQP := range []string{"pretty", "pretty=true", "pretty=false", "error_trace=true", "human=false"} {
		if c, _, _, _ := doRound59Req(t, h, http.MethodGet, "/?"+okQP, "", nil); c != http.StatusOK {
			t.Fatalf("expected 200 on /?%s, got %d", okQP, c)
		}
	}

	// 2. Content-Type 406 Not Acceptable on non-empty body with unsupported explicit header.
	for _, badCT := range []string{"text/plain", "application/xml", "text/html; charset=utf-8"} {
		c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_search", `{"query":{"match_all":{}}}`, map[string]string{"Content-Type": badCT})
		if c != http.StatusNotAcceptable {
			t.Fatalf("expected 406 Not Acceptable for Content-Type %q, got %d", badCT, c)
		}
	}
	// Empty body with text/plain is allowed (GET with no payload).
	if c, _, _, _ := doRound59Req(t, h, http.MethodGet, "/r59_w1/_search", "", map[string]string{"Content-Type": "text/plain"}); c != http.StatusOK {
		t.Fatalf("expected 200 on empty-body GET with text/plain, got %d", c)
	}
	// Vendor ES JSON media type is accepted.
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_search", `{"query":{"match_all":{}}}`, map[string]string{"Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"}); c != http.StatusOK {
		t.Fatalf("expected 200 on vnd.elasticsearch+json, got %d", c)
	}
	// Raw upload endpoint /_ml/find_file_structure is exempt from 406.
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_ml/find_file_structure", "a,b\n1,2\n", map[string]string{"Content-Type": "text/csv"}); c == http.StatusNotAcceptable {
		t.Fatalf("expected /_ml/find_file_structure not to fail with 406")
	}

	// 3. _validate/query: ?explain=false omits explanations; invalid booleans -> 400.
	c, _, vFalse, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_validate/query?explain=false", `{"query":{"term":{"tag":"alpha"}}}`, nil)
	if c != http.StatusOK || vFalse["explanations"] != nil {
		t.Fatalf("expected ?explain=false to omit explanations, got %d %v", c, vFalse)
	}
	c, _, vTrue, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_validate/query?explain=true", `{"query":{"term":{"tag":"alpha"}}}`, nil)
	if c != http.StatusOK || vTrue["explanations"] == nil {
		t.Fatalf("expected ?explain=true to include explanations, got %d %v", c, vTrue)
	}
	for _, badVQ := range []string{"explain=nope", "rewrite=nope", "all_shards=nope"} {
		if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_validate/query?"+badVQ, `{"query":{"match_all":{}}}`, nil); code != http.StatusBadRequest {
			t.Fatalf("expected 400 on _validate/query?%s, got %d", badVQ, code)
		}
	}

	// 4. _terms_enum: method guard, timeout validation, and dynamic len(targets) _shards.
	if code, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_w1/_terms_enum", `{"field":"tag"}`, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT _terms_enum, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_terms_enum?timeout=bogus", `{"field":"tag"}`, nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid ?timeout in _terms_enum, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1/_terms_enum", `{"field":"tag","timeout":"-5s"}`, nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative body timeout in _terms_enum, got %d", code)
	}
	c, _, teResp, _ := doRound59Req(t, h, http.MethodPost, "/r59_w1,r59_w2/_terms_enum?timeout=5s", `{"field":"tag","string":"alp"}`, nil)
	if c != http.StatusOK {
		t.Fatalf("POST /r59_w1,r59_w2/_terms_enum failed: %d %v", c, teResp)
	}
	teShards := teResp["_shards"].(map[string]any)
	if teShards["total"] != float64(2) || teShards["successful"] != float64(2) {
		t.Fatalf("expected _shards total=2 successful=2 across 2 indices, got %v", teShards)
	}
}

func TestRound59_F27_F28_F29_IngestProcessorsCompliance(t *testing.T) {
	_, h := newTestServerWithMock(t)

	// 1. PUT pipeline negative validations across F27, F28, F29.
	invalidPipelines := []string{
		`{"processors":[{"set":{"field":"a","value":1,"copy_from":"b"}}]}`,
		`{"processors":[{"set":{"field":"a"}}]}`,
		`{"processors":[{"set":{"field":"a","value":"x","media_type":"application/xml"}}]}`,
		`{"processors":[{"set":{"field":"a","value":"x","override":"notbool"}}]}`,
		`{"processors":[{"rename":{"field":"a","target_field":"b","override":"notbool"}}]}`,
		`{"processors":[{"grok":{"field":"msg","patterns":["%{IP:ip}"],"ecs_compatibility":"v2"}}]}`,
		`{"processors":[{"grok":{"field":"msg","patterns":["%{A:a}"],"pattern_definitions":{"A":"%{B}","B":"%{A}"}}}]}`,
		`{"processors":[{"grok":{"field":"msg","patterns":["%{NO_SUCH_TOKEN:x}"]}}]}`,
		`{"processors":[{"redact":{"field":"msg","patterns":["%{IP:ip}"],"prefix":123}}]}`,
		`{"processors":[{"date":{"field":"ts","formats":["yyyy-MM-dd"],"locale":"123_bad"}}]}`,
		`{"processors":[{"date":{"field":"ts","formats":["yyyy-MM-dd"],"output_format":"unterminated 'quote"}}]}`,
		`{"processors":[{"date_index_name":{"field":"ts","date_rounding":"d","index_name_format":"bad 'quote"}}]}`,
		`{"processors":[{"bytes":{"field":"sz","ignore_missing":"notbool"}}]}`,
	}
	for i, badPipe := range invalidPipelines {
		code, _, resp, _ := doRound59Req(t, h, http.MethodPut, fmt.Sprintf("/_ingest/pipeline/r59_bad_%d", i), badPipe, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("case %d: expected 400 for invalid pipeline %s, got %d (%v)", i, badPipe, code, resp)
		}
	}

	// 2. F27 set media_type decoding + rename override:false default failure vs override:true.
	c, _, f27Sim, _ := doRound59Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"set": {"field": "json_obj", "value": "{\"n\":{{num}},\"ok\":true}", "media_type": "application/json"}},
				{"set": {"field": "plain_str", "value": "{\"n\":{{num}}}", "media_type": "text/plain"}},
				{"set": {"field": "form_map", "value": "user={{u}}&role=admin", "media_type": "application/x-www-form-urlencoded"}},
				{"rename": {"field": "src_f", "target_field": "existing_f", "on_failure": [{"set": {"field": "rename_err", "value": "{{_ingest.on_failure_message}}"}}]}},
				{"rename": {"field": "src_f", "target_field": "existing_f", "override": true}}
			]
		},
		"docs": [{"_source": {"num": 7, "u": "alice", "src_f": "winner", "existing_f": "occupied"}}]
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("F27 simulate failed: %d %v", c, f27Sim)
	}
	d27 := f27Sim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	jsonObj, _ := d27["json_obj"].(map[string]any)
	if jsonObj["n"] != float64(7) || jsonObj["ok"] != true {
		t.Fatalf("expected media_type application/json decoded map, got %v", d27["json_obj"])
	}
	if d27["plain_str"] != `{"n":7}` {
		t.Fatalf("expected media_type text/plain raw string, got %v", d27["plain_str"])
	}
	formMap, _ := d27["form_map"].(map[string]any)
	if formMap["user"] != "alice" || formMap["role"] != "admin" {
		t.Fatalf("expected x-www-form-urlencoded decoded map, got %v", d27["form_map"])
	}
	if !strings.Contains(fmt.Sprintf("%v", d27["rename_err"]), "already exists") {
		t.Fatalf("expected default override=false rename to trigger on_failure with 'already exists', got %v", d27)
	}
	if d27["existing_f"] != "winner" {
		t.Fatalf("expected second rename with override=true to overwrite existing_f, got %v", d27)
	}

	// 3. F28 grok & redact: IPv6 IPORHOST, ecs_compatibility: "v1", and redact default ignore_missing: false.
	c, _, f28Sim, _ := doRound59Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"grok": {"field": "host_line", "patterns": ["%{IPORHOST:h}"]}},
				{"grok": {"field": "http_line", "ecs_compatibility": "v1", "patterns": ["%{COMMONAPACHELOG}"]}},
				{"redact": {"field": "secret_line", "ecs_compatibility": "v1", "patterns": ["%{IP:client_ip}"], "prefix": "<", "suffix": ">"}},
				{"redact": {"field": "missing_secret", "patterns": ["%{IP:ip}"], "on_failure": [{"set": {"field": "redact_missing_err", "value": "caught"}}]}}
			]
		},
		"docs": [{
			"_source": {
				"host_line": "2001:db8::ff00:42:8329",
				"http_line": "198.51.100.7 - frank [10/Oct/2025:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 200 2326",
				"secret_line": "client connected from 203.0.113.9 today"
			}
		}]
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("F28 simulate failed: %d %v", c, f28Sim)
	}
	d28 := f28Sim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d28["h"] != "2001:db8::ff00:42:8329" {
		t.Fatalf("expected IPORHOST to match IPv6, got %v", d28["h"])
	}
	clientObj, _ := d28["client"].(map[string]any)
	if clientObj["address"] != "198.51.100.7" {
		t.Fatalf("expected ECS v1 client.address from COMMONAPACHELOG, got %v", d28)
	}
	if d28["secret_line"] != "client connected from <client_ip> today" {
		t.Fatalf("expected redact output with custom prefix/suffix, got %q", d28["secret_line"])
	}
	if d28["redact_missing_err"] != "caught" {
		t.Fatalf("expected redact ignore_missing=false default to fail on missing field, got %v", d28)
	}

	// 4. F29 date (French locale + templated output_format), date_index_name (German locale + templated index_name_format), and bytes!
	c, _, f29Sim, _ := doRound59Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"date": {"field": "fr_date", "formats": ["EEEE dd MMMM yyyy HH:mm:ss"], "locale": "fr-FR", "timezone": "UTC", "output_format": "{{fmt_out}}", "target_field": "parsed_fr"}},
				{"date_index_name": {"field": "de_date", "date_formats": ["dd. MMMM yyyy"], "locale": "de_DE", "index_name_prefix": "events-", "date_rounding": "M", "index_name_format": "{{idx_fmt}}"}},
				{"bytes": {"field": "good_bytes", "target_field": "parsed_bytes"}},
				{"bytes": {"field": "frac_bytes", "on_failure": [{"set": {"field": "frac_err", "value": "rejected"}}]}},
				{"bytes": {"field": "huge_bytes", "on_failure": [{"set": {"field": "huge_err", "value": "rejected"}}]}}
			]
		},
		"docs": [{
			"_source": {
				"fr_date": "mercredi 15 octobre 2025 14:30:00",
				"fmt_out": "yyyy/MM/dd HH:mm",
				"de_date": "15. Oktober 2025",
				"idx_fmt": "yyyy-MM",
				"good_bytes": ["1.5kb", "2mb"],
				"frac_bytes": "1.5b",
				"huge_bytes": "9999999999999pb"
			}
		}]
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("F29 simulate failed: %d %v", c, f29Sim)
	}
	simDoc29 := f29Sim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	d29 := simDoc29["_source"].(map[string]any)
	if d29["parsed_fr"] != "2025/10/15 14:30" {
		t.Fatalf("expected French date parsed and formatted to 2025/10/15 14:30, got %v", d29["parsed_fr"])
	}
	if simDoc29["_index"] != "events-2025-10" {
		t.Fatalf("expected date_index_name _index=events-2025-10, got %v", simDoc29["_index"])
	}
	pbSlice, _ := d29["parsed_bytes"].([]any)
	if len(pbSlice) != 2 || pbSlice[0] != float64(1536) || pbSlice[1] != float64(2097152) {
		t.Fatalf("expected parsed_bytes=[1536, 2097152], got %v", d29["parsed_bytes"])
	}
	if d29["frac_err"] != "rejected" || d29["huge_err"] != "rejected" {
		t.Fatalf("expected fractional bytes (1.5b) and overflow bytes (9999999999999pb) rejected, got %v", d29)
	}
}

func TestRound59_GeoShapesAndHelperEdgeCasesUnit(t *testing.T) {
	// Exercise diverse GeoJSON & WKT representations + spatial relations directly for high branch coverage.
	inputs := []any{
		"12.5, 45.2",
		map[string]any{"lat": 12.5, "lon": 45.2},
		[]any{45.2, 12.5},
		"POINT (45.2 12.5)",
		"BBOX (0, 20, 20, 0)",
		"LINESTRING (0 0, 5 5, 10 10)",
		"POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0))",
		map[string]any{"type": "MultiPoint", "coordinates": []any{[]any{1.0, 2.0}, []any{3.0, 4.0}}},
		map[string]any{"type": "LineString", "coordinates": []any{[]any{0.0, 0.0}, []any{5.0, 5.0}}},
		map[string]any{"type": "MultiLineString", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{2.0, 2.0}}}},
		map[string]any{"type": "MultiPolygon", "coordinates": []any{[]any{[]any{[]any{0.0, 0.0}, []any{4.0, 0.0}, []any{4.0, 4.0}, []any{0.0, 4.0}, []any{0.0, 0.0}}}}},
		map[string]any{"type": "GeometryCollection", "geometries": []any{map[string]any{"type": "Point", "coordinates": []any{2.0, 2.0}}}},
	}
	for i, in := range inputs {
		if _, ok := parseEnrichGeoShapeRound59(in); !ok {
			t.Fatalf("case %d: expected parseEnrichGeoShapeRound59(%T) to succeed", i, in)
		}
	}

	outerPoly := map[string]any{"type": "Polygon", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{10.0, 0.0}, []any{10.0, 10.0}, []any{0.0, 10.0}, []any{0.0, 0.0}}}}
	innerBox := "BBOX (2, 8, 8, 2)"
	if !enrichDocMatchesGeoValueRound59(map[string]any{"g": outerPoly}, "g", innerBox, "contains") {
		t.Fatalf("expected outerPoly contains innerBox")
	}
	if !enrichDocMatchesGeoValueRound59(map[string]any{"g": innerBox}, "g", outerPoly, "within") {
		t.Fatalf("expected innerBox within outerPoly")
	}
	crossingLine := "LINESTRING (-5 5, 15 5)"
	if !enrichDocMatchesGeoValueRound59(map[string]any{"g": outerPoly}, "g", crossingLine, "intersects") {
		t.Fatalf("expected crossingLine intersects outerPoly")
	}
	if enrichDocMatchesGeoValueRound59(map[string]any{"g": crossingLine}, "g", outerPoly, "within") {
		t.Fatalf("expected crossingLine NOT within outerPoly")
	}

	// Localized formatting round-trip across supported languages.
	tm := time.Date(2025, time.December, 25, 10, 0, 0, 0, time.UTC)
	for _, lang := range []string{"fr", "de", "es", "it", "pt", "nl"} {
		out := localizeFormattedDateOutputRound59("Thursday 25 December 2025", "EEEE dd MMMM yyyy", lang, tm)
		norm := normalizeLocalizedDateInputToEnglishRound59(out, lang)
		if !strings.Contains(norm, "December") || !strings.Contains(norm, "Thursday") {
			t.Fatalf("lang %s: expected round-trip back to English tokens, got out=%q norm=%q", lang, out, norm)
		}
		outShort := localizeFormattedDateOutputRound59("Thu 25 Dec 2025", "EEE dd MMM yyyy", lang, tm)
		normShort := normalizeLocalizedDateInputToEnglishRound59(outShort, lang)
		if !strings.Contains(normShort, "Dec") {
			t.Fatalf("lang %s: expected short month round-trip, got out=%q norm=%q", lang, outShort, normShort)
		}
	}

	// Direct duration, integer condition, date format, locale, and bytes helper checks.
	for _, d := range []string{"100nanos", "500micros", "10ms", "2s", "3m", "1.5h", "2d", "1w"} {
		if _, err := parseESDurationMillisRound59(d); err != nil {
			t.Fatalf("expected valid duration %q, got %v", d, err)
		}
	}
	for _, badD := range []string{"", "-5s", "10lightyears", "abc"} {
		if _, err := parseESDurationMillisRound59(badD); err == nil {
			t.Fatalf("expected error for invalid duration %q", badD)
		}
	}
	for _, v := range []any{int(5), int64(10), float64(3), json.Number("42")} {
		if _, err := parseStrictNonNegIntConditionRound59("max_docs", v); err != nil {
			t.Fatalf("expected valid int condition %v, got %v", v, err)
		}
	}
	for _, badV := range []any{int(-1), int64(-2), float64(1.5), json.Number("-3"), "abc"} {
		if _, err := parseStrictNonNegIntConditionRound59("max_docs", badV); err == nil {
			t.Fatalf("expected error for invalid int condition %v", badV)
		}
	}
	for _, bEl := range []any{"2kb", int(10), int64(20), float64(30), json.Number("40")} {
		if _, err := parseStrictIngestBytesElementRound59("sz", bEl); err != nil {
			t.Fatalf("expected valid byte element %v, got %v", bEl, err)
		}
	}
	for _, badB := range []any{"1.5b", int(-1), int64(-5), float64(2.5), json.Number("-1"), true} {
		if _, err := parseStrictIngestBytesElementRound59("sz", badB); err == nil {
			t.Fatalf("expected error for invalid byte element %v", badB)
		}
	}
	if err := validateESDateFormatPatternRound59("yyyy-MM-dd'T'HH:mm:ss''Z"); err != nil {
		t.Fatalf("expected valid quoted date pattern, got %v", err)
	}
	if err := validateESDateFormatPatternRound59("yyyy-MM-dd P"); err == nil {
		t.Fatalf("expected error for unknown pattern letter P")
	}
	if _, err := decodeIngestSetMediaTypeValueRound59("a=1&a=2", "application/x-www-form-urlencoded"); err != nil {
		t.Fatalf("expected multi-value form decode success, got %v", err)
	}
	if _, err := decodeIngestSetMediaTypeValueRound59(`[1, 2.5, {"x": 3}]`, "application/json"); err != nil {
		t.Fatalf("expected nested array/number JSON decode success, got %v", err)
	}
	if _, err := decodeIngestSetMediaTypeValueRound59(`{"a":1} trailing`, "application/json"); err == nil {
		t.Fatalf("expected trailing JSON content error")
	}

	// Additional GeoJSON / WKT shape representations (MultiPoint, LineString, MultiLineString,
	// MultiPolygon, GeometryCollection, WKT BBOX, JSON-string GeoJSON) & contains/disjoint relations.
	wktBBox := "BBOX (0, 10, 10, 0)"
	multiPt := map[string]any{"type": "MultiPoint", "coordinates": []any{[]any{2.0, 2.0}, []any{5.0, 5.0}}}
	lineGeo := map[string]any{"type": "LineString", "coordinates": []any{[]any{1.0, 1.0}, []any{4.0, 4.0}}}
	multiLineGeo := map[string]any{"type": "MultiLineString", "coordinates": []any{[]any{[]any{1.0, 1.0}, []any{3.0, 3.0}}}}
	multiPolyGeo := map[string]any{
		"type": "MultiPolygon",
		"coordinates": []any{
			[]any{[]any{[]any{1.0, 1.0}, []any{4.0, 1.0}, []any{4.0, 4.0}, []any{1.0, 4.0}, []any{1.0, 1.0}}},
		},
	}
	geomColl := map[string]any{
		"type":       "GeometryCollection",
		"geometries": []any{map[string]any{"type": "Point", "coordinates": []any{3.0, 3.0}}, lineGeo},
	}
	for _, candidate := range []any{multiPt, lineGeo, multiLineGeo, multiPolyGeo, geomColl, `{"type":"Point","coordinates":[5,5]}`} {
		if !enrichDocMatchesGeoValueRound59(map[string]any{"g": wktBBox}, "g", candidate, "contains") {
			t.Fatalf("expected wktBBox to contain %#v", candidate)
		}
		if enrichDocMatchesGeoValueRound59(map[string]any{"g": wktBBox}, "g", candidate, "disjoint") {
			t.Fatalf("expected wktBBox NOT disjoint with %#v", candidate)
		}
	}

	// Snapshot JSON-deserialized global state restore (composable + legacy templates + cluster settings)
	// plus _mpercolate & _update edge-case validations.
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()
	srv.restoreSnapshotExtraGlobalStateRound59(t.Context(), map[string]any{
		"__composable_templates": map[string]any{
			"r59_comp_tpl": map[string]any{"index_patterns": []any{"r59-c-*"}},
		},
		"__legacy_templates": map[string]any{
			"r59_leg_tpl": map[string]any{"index_patterns": []any{"r59-l-*"}},
		},
		"__cluster_persistent_settings": map[string]any{
			"indices.recovery.max_bytes_per_sec": "50mb",
		},
	})
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/_index_template/r59_comp_tpl", "", nil); code != http.StatusOK {
		t.Fatalf("expected 200 for restored composable template, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodGet, "/_template/r59_leg_tpl", "", nil); code != http.StatusOK {
		t.Fatalf("expected 200 for restored legacy template, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodDelete, "/_mpercolate", "", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE /_mpercolate, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_mpercolate", "{bad\n{}\n", nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on malformed _mpercolate header, got %d", code)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/_mpercolate", "{\"unknown\":{}}\n{}\n", nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown _mpercolate header key, got %d", code)
	}
	if code, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_edge_perc", `{"mappings":{"properties":{"query":{"type":"percolator"},"title":{"type":"text"}}}}`, nil); code != http.StatusOK {
		t.Fatalf("expected 200 creating r59_edge_perc, got %d (%v)", code, resp)
	}
	codeMP, _, mpEdge, _ := doRound59Req(t, h, http.MethodPost, "/r59_edge_perc/_mpercolate",
		"{\"percolate\":{}}\n{}\n{\"percolate\":{\"id\":\"missing-doc\"}}\n{}\n{\"percolate\":{\"index\":\"no_such_perc_idx\"}}\n{\"doc\":{\"title\":\"x\"}}\n", nil)
	if codeMP != http.StatusOK {
		t.Fatalf("expected 200 on _mpercolate inline error isolation, got %d (%v)", codeMP, mpEdge)
	}
	mpResps, _ := mpEdge["responses"].([]any)
	if len(mpResps) != 3 ||
		mpResps[0].(map[string]any)["status"] != float64(400) ||
		mpResps[1].(map[string]any)["status"] != float64(400) ||
		mpResps[2].(map[string]any)["status"] != float64(404) {
		t.Fatalf("expected inline [400, 400, 404] statuses in _mpercolate responses, got %#v", mpResps)
	}
	if code, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_edge_perc/_doc/1?refresh=true", `{"title":"hello"}`, nil); code != http.StatusCreated {
		t.Fatalf("expected 201 indexing doc 1, got %d (%v)", code, resp)
	}
	if code, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_edge_perc/_update/1?scripted_upsert=bad", `{"doc":{"title":"v2"}}`, nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid scripted_upsert query bool, got %d", code)
	}
	if code, _, upBody, _ := doRound59Req(t, h, http.MethodPost, "/r59_edge_perc/_update/1", `{"doc":{"title":"v2"},"fields":[{"field":"title"}]}`, nil); code != http.StatusOK || upBody["get"] == nil {
		t.Fatalf("expected 200 with get.fields on _update object fields array, got %d (%v)", code, upBody)
	}
}

func TestRound59_SchemaShredderTranspilerEndToEndHTTP(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	h := srv.Handler()

	// F10: unsigned_long > MaxInt64 exact 64-bit terms & composite aggs + signed long overflow 400
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f10_idx", `{
		"mappings": {
			"properties": {
				"ul": {"type": "unsigned_long"},
				"sl": {"type": "long"}
			}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F10 create index failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f10_idx/_doc/bad_sl", `{"sl": 9223372036854775808}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F10 expected 400 on signed long overflow, got %d (%v)", c, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "mapper_parsing_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f10_idx/_doc/1?refresh=true", `{"ul": 18446744073709551600, "sl": 42}`, nil); c != http.StatusCreated {
		t.Fatalf("F10 index doc 1 failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f10_idx/_doc/2?refresh=true", `{"ul": 18446744073709551615, "sl": 99}`, nil); c != http.StatusCreated {
		t.Fatalf("F10 index doc 2 failed: %d (%v)", c, resp)
	}
	cF10, _, _, rawF10 := doRound59Req(t, h, http.MethodPost, "/r59_f10_idx/_search", `{
		"size": 0,
		"aggs": {
			"ul_terms": {"terms": {"field": "ul", "order": {"_key": "asc"}}},
			"ul_comp": {"composite": {"sources": [{"u": {"terms": {"field": "ul"}}}]}}
		}
	}`, nil)
	if cF10 != http.StatusOK {
		t.Fatalf("F10 search failed: %d (%s)", cF10, rawF10)
	}
	decF10 := json.NewDecoder(strings.NewReader(rawF10))
	decF10.UseNumber()
	var parsedF10 map[string]any
	if err := decF10.Decode(&parsedF10); err != nil {
		t.Fatalf("F10 decode failed: %v", err)
	}
	aggsF10 := parsedF10["aggregations"].(map[string]any)
	tBuckets := aggsF10["ul_terms"].(map[string]any)["buckets"].([]any)
	if len(tBuckets) != 2 || fmt.Sprintf("%v", tBuckets[0].(map[string]any)["key"]) != "18446744073709551600" || fmt.Sprintf("%v", tBuckets[1].(map[string]any)["key"]) != "18446744073709551615" {
		t.Fatalf("F10 expected exact uint64 keys in terms agg, got %#v", tBuckets)
	}
	cBuckets := aggsF10["ul_comp"].(map[string]any)["buckets"].([]any)
	if len(cBuckets) != 2 || fmt.Sprintf("%v", cBuckets[0].(map[string]any)["key"].(map[string]any)["u"]) != "18446744073709551600" {
		t.Fatalf("F10 expected exact uint64 keys in composite agg, got %#v", cBuckets)
	}

	// F11: _source: {"enabled": false}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f11_nosrc", `{
		"mappings": {
			"_source": {"enabled": false},
			"properties": {
				"tag": {"type": "keyword"},
				"cnt": {"type": "long"}
			}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F11 create index failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f11_nosrc/_doc/1?refresh=true", `{"tag":"alpha","cnt":7}`, nil); c != http.StatusCreated {
		t.Fatalf("F11 index doc failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/r59_f11_nosrc/_source/1", "", nil); c != http.StatusBadRequest {
		t.Fatalf("F11 expected 400 on GET _source when disabled, got %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f11_nosrc/_update/1", `{"doc":{"cnt":8}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F11 expected 400 on _update when _source disabled, got %d (%v)", c, resp)
	} else {
		assertESErrorTypeRound59(t, resp, "document_source_missing_exception")
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f11_nosrc/_mget", `{"ids":["1"],"_source":true}`, nil); c != http.StatusBadRequest && resp["docs"] == nil {
		t.Fatalf("F11 unexpected _mget response: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f11_nosrc/_search", `{"_source":["tag"]}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F11 expected 400 on _search explicit _source when disabled, got %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f11_nosrc/_search", `{"docvalue_fields":["tag","cnt"]}`, nil); c != http.StatusOK {
		t.Fatalf("F11 expected 200 on docvalue_fields when _source disabled, got %d (%v)", c, resp)
	} else {
		hits := resp["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 1 || hits[0].(map[string]any)["_source"] != nil {
			t.Fatalf("F11 expected hit without _source, got %#v", hits)
		}
	}

	// F12: _source includes/excludes + GET _mapping metadata preservation + dynamic_date_formats
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f12_meta", `{
		"mappings": {
			"dynamic": "runtime",
			"_source": {"includes": ["keep_*", "custom_dt"], "excludes": ["keep_secret"]},
			"_routing": {"required": true},
			"_meta": {"owner": "platform"},
			"dynamic_date_formats": ["yyyy/MM/dd"]
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F12 create index failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/r59_f12_meta/_mapping", "", nil); c != http.StatusOK {
		t.Fatalf("F12 GET _mapping failed: %d (%v)", c, resp)
	} else {
		mObj := resp["r59_f12_meta"].(map[string]any)["mappings"].(map[string]any)
		if mObj["dynamic"] != "runtime" || mObj["_source"] == nil || mObj["_routing"] == nil || mObj["_meta"] == nil {
			t.Fatalf("F12 expected root mapping metadata preserved, got %#v", mObj)
		}
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f12_meta/_doc/1?routing=r1&refresh=true", `{"keep_pub":"ok","keep_secret":"no","drop_me":"bye"}`, nil); c != http.StatusCreated {
		t.Fatalf("F12 index doc failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodGet, "/r59_f12_meta/_doc/1?routing=r1", "", nil); c != http.StatusOK {
		t.Fatalf("F12 GET doc failed: %d (%v)", c, resp)
	} else {
		src := resp["_source"].(map[string]any)
		if src["keep_pub"] != "ok" || src["keep_secret"] != nil || src["drop_me"] != nil {
			t.Fatalf("F12 expected _source includes/excludes filtering, got %#v", src)
		}
	}

	// F13: Mapping limits (total_fields, depth, nested_objects, field_name_length) & index-level coerce/ignore_malformed
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits", `{
		"settings": {
			"index.mapping.total_fields.limit": 4,
			"index.mapping.depth.limit": 2,
			"index.mapping.nested_objects.limit": 2,
			"index.mapping.field_name_length.limit": 12,
			"index.mapping.coerce": false
		},
		"mappings": {
			"properties": {
				"n_items": {"type": "nested", "properties": {"k": {"type": "keyword"}}},
				"num": {"type": "integer"}
			}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F13 create index failed: %d (%v)", c, resp)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits/_doc/bad_coerce", `{"num": "42"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F13 expected 400 when index.mapping.coerce=false on string integer, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits/_doc/bad_depth", `{"a":{"b":{"c":1}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F13 expected 400 when exceeding depth.limit=2, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits/_doc/bad_nested", `{"n_items":[{"k":"1"},{"k":"2"},{"k":"3"}]}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F13 expected 400 when exceeding nested_objects.limit=2, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits/_doc/bad_fnlen", `{"extremely_long_field_name": 1}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F13 expected 400 when exceeding field_name_length.limit=12, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f13_limits/_doc/bad_total", `{"f1":1,"f2":2,"f3":3}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F13 expected 400 when exceeding total_fields.limit=4, got %d", c)
	}

	// F14: constant_keyword auto-adoption & null/missing non-injection
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f14_ck", `{
		"mappings": {"properties": {"env": {"type": "constant_keyword"}, "tag": {"type": "keyword"}}}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F14 create index failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f14_ck/_doc/1?refresh=true", `{"tag":"missing_env"}`, nil); c != http.StatusCreated {
		t.Fatalf("F14 index doc 1 failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f14_ck/_doc/2?refresh=true", `{"env":"staging","tag":"has_env"}`, nil); c != http.StatusCreated {
		t.Fatalf("F14 index doc 2 failed: %d (%v)", c, resp)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f14_ck/_doc/3?refresh=true", `{"env":"prod"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F14 expected 400 mismatching adopted constant_keyword value 'staging', got %d", c)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f14_ck/_search", `{"query":{"term":{"env":"staging"}}}`, nil); c != http.StatusOK {
		t.Fatalf("F14 search failed: %d (%v)", c, resp)
	} else if tot := resp["hits"].(map[string]any)["total"].(map[string]any)["value"]; tot != float64(1) {
		t.Fatalf("F14 expected only doc 2 (not missing-env doc 1) to match env=staging, got total=%v", tot)
	}

	// F15: dense_vector dot_product unit norm + byte/bit element_type knn
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f15_vec", `{
		"mappings": {
			"properties": {
				"dp": {"type": "dense_vector", "dims": 2, "similarity": "dot_product"},
				"bv": {"type": "dense_vector", "dims": 2, "element_type": "byte", "similarity": "l2_norm"},
				"bits": {"type": "dense_vector", "dims": 8, "element_type": "bit"}
			}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F15 create index failed: %d (%v)", c, resp)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPut, "/r59_f15_vec/_doc/bad_dp", `{"dp":[3.0, 4.0]}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F15 expected 400 on non-unit dot_product vector, got %d", c)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f15_vec/_doc/1?refresh=true", `{"dp":[1.0, 0.0], "bv":[10, -20], "bits":"f0"}`, nil); c != http.StatusCreated {
		t.Fatalf("F15 index doc 1 failed: %d (%v)", c, resp)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f15_vec/_search", `{"knn":{"field":"bits","query_vector":"f0","k":1,"num_candidates":5}}`, nil); c != http.StatusOK {
		t.Fatalf("F15 bit knn search failed: %d (%v)", c, resp)
	}

	// F16-F19: SemVer version sort, Lucene regexp automaton, max_terms_count, negative/reciprocal score, and calendar DST date_histogram
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPut, "/r59_f16_19", `{
		"settings": {"index.max_terms_count": 3},
		"mappings": {
			"properties": {
				"ver": {"type": "version"},
				"code": {"type": "keyword"},
				"val": {"type": "double"},
				"ts": {"type": "date"}
			}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F16-F19 create index failed: %d (%v)", c, resp)
	}
	bulkDocs := strings.Join([]string{
		`{"index":{"_id":"1"}}`, `{"ver":"1.10.0","code":"v9","val":2.0,"ts":"2026-01-15T12:00:00Z"}`,
		`{"index":{"_id":"2"}}`, `{"ver":"1.2.0","code":"v12","val":4.0,"ts":"2026-02-10T12:00:00Z"}`,
		`{"index":{"_id":"3"}}`, `{"ver":"1.0.0-alpha","code":"v5","val":8.0,"ts":"2026-03-08T06:30:00Z"}`,
		`{"index":{"_id":"4"}}`, `{"ver":"1.0.0-alpha.1","code":"v105","val":10.0,"ts":"2026-03-08T07:30:00Z"}`,
		`{"index":{"_id":"5"}}`, `{"ver":"1.0.0","code":"other","val":5.0,"ts":"2026-03-09T04:30:00Z"}`,
	}, "\n") + "\n"
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_bulk?refresh=true", bulkDocs, map[string]string{"Content-Type": "application/x-ndjson"}); c != http.StatusOK || resp["errors"] != false {
		t.Fatalf("F16-F19 bulk index failed: %d (%v)", c, resp)
	}

	// F16: SemVer sort order: 1.0.0-alpha (3) < 1.0.0-alpha.1 (4) < 1.0.0 (5) < 1.2.0 (2) < 1.10.0 (1)
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"sort":[{"ver":"asc"}]}`, nil); c != http.StatusOK {
		t.Fatalf("F16 sort search failed: %d (%v)", c, resp)
	} else {
		hits := resp["hits"].(map[string]any)["hits"].([]any)
		wantIDs := []string{"3", "4", "5", "2", "1"}
		for i, want := range wantIDs {
			if got := hits[i].(map[string]any)["_id"]; got != want {
				t.Fatalf("F16 SemVer sort pos %d: got _id=%v, want %s", i, got, want)
			}
		}
	}

	// F17: Lucene regexp <1-20>&~(v5) matches v9 (1) and v12 (2), excludes v5 (3) and v105 (4)
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"query":{"regexp":{"code":{"value":"v<1-20>&~(v5)","flags":"ALL"}}},"sort":[{"_id":"asc"}]}`, nil); c != http.StatusOK {
		t.Fatalf("F17 regexp search failed: %d (%v)", c, resp)
	} else {
		hits := resp["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 2 || hits[0].(map[string]any)["_id"] != "1" || hits[1].(map[string]any)["_id"] != "2" {
			t.Fatalf("F17 expected hits [1, 2], got %#v", hits)
		}
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"query":{"terms":{"code":["a", null]}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F17 expected 400 on null element in terms query, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"query":{"terms":{"code":["a","b","c","d"]}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F17 expected 400 when exceeding index.max_terms_count=3, got %d", c)
	}

	// F18: Negative score 400 & reciprocal (1/x) scoring
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"-1.0"}}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F18 expected 400 on negative script_score, got %d", c)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"query":{"function_score":{"query":{"term":{"_id":"1"}},"field_value_factor":{"field":"val","modifier":"reciprocal"}}}}`, nil); c != http.StatusOK {
		t.Fatalf("F18 reciprocal search failed: %d (%v)", c, resp)
	} else {
		sc := resp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_score"].(float64)
		if sc < 0.499 || sc > 0.501 {
			t.Fatalf("F18 expected reciprocal(2.0) == 0.5, got %v", sc)
		}
	}

	// F19: Calendar 1M + America/New_York DST date_histogram & invalid bounds/timezone 400
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"size":0,"aggs":{"dh":{"date_histogram":{"field":"ts","calendar_interval":"1d","time_zone":"Invalid/Zone"}}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F19 expected 400 on invalid time_zone, got %d", c)
	}
	if c, _, _, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{"size":0,"aggs":{"dh":{"date_histogram":{"field":"ts","calendar_interval":"1d","extended_bounds":{"min":"2026-05-01","max":"2026-01-01"}}}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("F19 expected 400 on reversed extended_bounds, got %d", c)
	}
	if c, _, resp, _ := doRound59Req(t, h, http.MethodPost, "/r59_f16_19/_search", `{
		"size": 0,
		"aggs": {
			"by_month": {"date_histogram": {"field": "ts", "calendar_interval": "1M"}},
			"by_ny_day": {"date_histogram": {"field": "ts", "calendar_interval": "1d", "time_zone": "America/New_York"}}
		}
	}`, nil); c != http.StatusOK {
		t.Fatalf("F19 calendar/DST date_histogram failed: %d (%v)", c, resp)
	} else {
		aggs := resp["aggregations"].(map[string]any)
		mBuckets := aggs["by_month"].(map[string]any)["buckets"].([]any)
		if len(mBuckets) != 3 {
			t.Fatalf("F19 expected 3 monthly buckets (Jan, Feb, Mar 2026), got %#v", mBuckets)
		}
		// Doc 3 (2026-03-08T06:30Z = 01:30 EST) and Doc 4 (2026-03-08T07:30Z = 03:30 EDT) are on 2026-03-08 in NY,
		// while Doc 5 (2026-03-09T04:30Z = 2026-03-09T00:30 EDT, NOT 23:30 EST!) is on 2026-03-09 in NY!
		nyBuckets := aggs["by_ny_day"].(map[string]any)["buckets"].([]any)
		var mar8Count, mar9Count float64
		for _, rawB := range nyBuckets {
			bm := rawB.(map[string]any)
			ks, _ := bm["key_as_string"].(string)
			if strings.HasPrefix(ks, "2026-03-08") {
				mar8Count = bm["doc_count"].(float64)
			}
			if strings.HasPrefix(ks, "2026-03-09") {
				mar9Count = bm["doc_count"].(float64)
			}
		}
		if mar8Count != 2 || mar9Count != 1 {
			t.Fatalf("F19 expected NY DST day buckets 2026-03-08=2 and 2026-03-09=1, got mar8=%v mar9=%v (all=%#v)", mar8Count, mar9Count, nyBuckets)
		}
	}
}

func TestRound59_TranspilerHooksUnitCoverage(t *testing.T) {
	// 1. formatUnsignedLongOrNumericTermsKeyRound59 across missing, blank, string/boolean/version skips,
	// unsigned_long (uint64 + negative fallback + format), signed int (int64 + float64 trunc + format), and float.
	if k, _, _, ok := formatUnsignedLongOrNumericTermsKeyRound59("__ES_MISSING_BUCKET__", nil, nil); !ok || k != nil {
		t.Fatalf("expected missing sentinel handled as nil, got %v %v", k, ok)
	}
	if _, _, _, ok := formatUnsignedLongOrNumericTermsKeyRound59("  ", nil, nil); ok {
		t.Fatalf("expected blank key unhandled")
	}
	for _, vt := range []string{"boolean", "date", "string", "ip"} {
		if _, _, _, ok := formatUnsignedLongOrNumericTermsKeyRound59("42", &esast.TermsAggSpec{ValueType: vt}, nil); ok {
			t.Fatalf("expected value_type=%s to skip numeric formatting", vt)
		}
	}
	if k, ks, hasKS, ok := formatUnsignedLongOrNumericTermsKeyRound59("18446744073709551610", &esast.TermsAggSpec{ValueType: "unsigned_long", Format: "0"}, nil); !ok || !hasKS || ks == "" || k != uint64(18446744073709551610) {
		t.Fatalf("unexpected unsigned_long formatted key: %v %q %v %v", k, ks, hasKS, ok)
	}
	if k, _, hasKS, ok := formatUnsignedLongOrNumericTermsKeyRound59("-7", &esast.TermsAggSpec{ValueType: "unsigned_long", Format: "0"}, nil); !ok || !hasKS || k != int64(-7) {
		t.Fatalf("unexpected unsigned_long negative fallback: %v %v %v", k, hasKS, ok)
	}
	if k, _, _, ok := formatUnsignedLongOrNumericTermsKeyRound59("-9", &esast.TermsAggSpec{ValueType: "unsigned_long"}, nil); !ok || k != int64(-9) {
		t.Fatalf("unexpected unsigned_long unformatted negative fallback: %v %v", k, ok)
	}
	if k, ks, hasKS, ok := formatUnsignedLongOrNumericTermsKeyRound59("123", &esast.TermsAggSpec{ValueType: "long", Format: "0000"}, nil); !ok || !hasKS || ks != "0123" || k != int64(123) {
		t.Fatalf("unexpected signed int formatted key: %v %q %v %v", k, ks, hasKS, ok)
	}
	if k, ks, hasKS, ok := formatUnsignedLongOrNumericTermsKeyRound59("45.0", &esast.TermsAggSpec{ValueType: "integer", Format: "000"}, nil); !ok || !hasKS || ks != "045" || k != int64(45) {
		t.Fatalf("unexpected float-truncated int formatted key: %v %q %v %v", k, ks, hasKS, ok)
	}
	if k, _, _, ok := formatUnsignedLongOrNumericTermsKeyRound59("45.0", &esast.TermsAggSpec{ValueType: "integer"}, nil); !ok || k != int64(45) {
		t.Fatalf("unexpected float-truncated int key: %v %v", k, ok)
	}
	if k, ks, hasKS, ok := formatUnsignedLongOrNumericTermsKeyRound59("3.5", &esast.TermsAggSpec{ValueType: "double", Format: "0.00"}, nil); !ok || !hasKS || ks != "3.50" || k != float64(3.5) {
		t.Fatalf("unexpected double formatted key: %v %q %v %v", k, ks, hasKS, ok)
	}

	// 2. buildMappingResponseMapRound59, filterDocumentSourceRound59 & applyDynamicRuntimeInferenceRound59.
	if m := buildMappingResponseMapRound59(nil); len(m) != 0 {
		t.Fatalf("expected empty map for nil schema, got %v", m)
	}
	tBool, fBool := true, false
	var fullMapSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic": "runtime",
		"_routing": {"required": true},
		"_meta": {"v": 1},
		"_source": {"includes": ["a*"]},
		"dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
		"dynamic_date_formats": ["yyyy/MM/dd"]
	}`), &fullMapSpec)
	fullMapSpec.DateDetection = &tBool
	fullMapSpec.NumericDetection = &tBool
	fullMapSpec.Subobjects = &fBool
	fullMapSpec.Runtime = map[string]esast.FieldProperty{"rt_f": {Type: "keyword"}}
	fullCompiled := schema.CompileIndexSchema("es_db", "r59_unit_map", &fullMapSpec)
	respMap := buildMappingResponseMapRound59(fullCompiled)
	for _, reqKey := range []string{"properties", "runtime", "dynamic", "_routing", "_meta", "_source", "dynamic_templates", "date_detection", "numeric_detection", "dynamic_date_formats", "subobjects"} {
		if _, ok := respMap[reqKey]; !ok {
			t.Fatalf("expected key %q in buildMappingResponseMapRound59, got %v", reqKey, respMap)
		}
	}
	if srcOut, inc := filterDocumentSourceRound59(json.RawMessage(`{"ab":1,"ac":2,"z":3}`), fullCompiled, &esast.SourceFilter{Excludes: []string{"ac"}}); !inc || !strings.Contains(string(srcOut), `"ab"`) || strings.Contains(string(srcOut), `"ac"`) {
		t.Fatalf("unexpected filterDocumentSourceRound59 result: %s (%v)", string(srcOut), inc)
	}
	if _, inc := filterDocumentSourceRound59(json.RawMessage(`{"ab":1}`), fullCompiled, &esast.SourceFilter{Disabled: true}); inc {
		t.Fatalf("expected reqFilter.Disabled to omit _source")
	}
	if _, inc := filterDocumentSourceRound59(nil, fullCompiled, nil); inc {
		t.Fatalf("expected empty rawSrc to omit _source")
	}
	if nextSpec, added := applyDynamicRuntimeInferenceRound59([]json.RawMessage{json.RawMessage(`{"new_dyn_rt": 123}`)}, &fullMapSpec); !added || nextSpec.Runtime["new_dyn_rt"].Type == "" {
		t.Fatalf("expected dynamic runtime field inferred, got added=%v spec=%+v", added, nextSpec)
	}

	// 3. Settings parsing & validation helpers.
	nestedSettings := map[string]any{
		"index": map[string]any{
			"mapping": map[string]any{
				"total_fields":      map[string]any{"limit": int64(50)},
				"depth.limit":       json.Number("10"),
				"nested_fields":     map[string]any{"limit": "15"},
				"nested_objects":    map[string]any{"limit": float64(100)},
				"field_name_length": map[string]any{"limit": int(40)},
				"coerce":            "true",
				"ignore_malformed":  "false",
			},
			"max_terms_count": 250,
		},
	}
	if err := parseAndApplyIndexMappingSettingsRound59(nestedSettings, fullCompiled); err != nil {
		t.Fatalf("expected valid nested settings to apply, got %v", err)
	}
	if fullCompiled.MaxTotalFields != 50 || fullCompiled.MaxDepth != 10 || fullCompiled.MaxNestedFields != 15 || fullCompiled.MaxNestedObjects != 100 || fullCompiled.MaxFieldNameLength != 40 || fullCompiled.MaxTermsCount != 250 {
		t.Fatalf("unexpected compiled limits after settings apply: %+v", fullCompiled)
	}
	for _, badSetting := range []map[string]any{
		{"index.mapping.total_fields.limit": nil},
		{"index.mapping.depth.limit": 0},
		{"index.mapping.nested_fields.limit": -1},
		{"index.mapping.nested_objects.limit": 1.5},
		{"index.mapping.field_name_length.limit": "abc"},
		{"index.mapping.coerce": "maybe"},
		{"index.mapping.ignore_malformed": 123},
		{"index.max_terms_count": 0},
	} {
		if err := parseAndApplyIndexMappingSettingsRound59(badSetting, fullCompiled); err == nil {
			t.Fatalf("expected error for bad setting %v", badSetting)
		}
	}

	// 4. Constant keyword scalar extraction & property update edge cases.
	for _, tc := range []struct {
		in   any
		segs []string
		want string
		ok   bool
	}{
		{nil, nil, "", false},
		{[]any{nil, "v1", "v1"}, nil, "v1", true},
		{json.Number("99"), nil, "99", true},
		{true, nil, "true", true},
		{float64(2.5), nil, "2.5", true},
		{int(7), nil, "7", true},
		{[]any{map[string]any{"k": "same"}, map[string]any{"k": "same"}}, []string{"k"}, "same", true},
	} {
		got, ok, err := extractFirstConstantKeywordScalarAtPathRound59(tc.in, tc.segs)
		if err != nil || ok != tc.ok || got != tc.want {
			t.Fatalf("extractFirstConstantKeywordScalarAtPathRound59(%#v, %v) = (%q, %v, %v), want (%q, %v, nil)", tc.in, tc.segs, got, ok, err, tc.want, tc.ok)
		}
	}
	for _, badCK := range []struct {
		in   any
		segs []string
	}{
		{map[string]any{"x": 1}, nil},
		{[]any{"a", "b"}, nil},
		{[]any{map[string]any{"k": "a"}, map[string]any{"k": "b"}}, []string{"k"}},
	} {
		if _, _, err := extractFirstConstantKeywordScalarAtPathRound59(badCK.in, badCK.segs); err == nil {
			t.Fatalf("expected error for constant_keyword input %#v", badCK)
		}
	}
	props := map[string]esast.FieldProperty{
		"top": {
			Type:   "keyword",
			Fields: map[string]esast.FieldProperty{"ck": {Type: "constant_keyword"}},
		},
		"grp": {
			Properties: map[string]esast.FieldProperty{"inner_ck": {Type: "constant_keyword"}},
		},
	}
	if !setConstantKeywordValueInPropsRound59(props, []string{"top", "ck"}, "adopted_mf") || props["top"].Fields["ck"].Value != "adopted_mf" {
		t.Fatalf("expected multi-field constant_keyword value set, got %+v", props)
	}
	if !setConstantKeywordValueInPropsRound59(props, []string{"grp", "inner_ck"}, "adopted_nested") || props["grp"].Properties["inner_ck"].Value != "adopted_nested" {
		t.Fatalf("expected nested property constant_keyword value set, got %+v", props)
	}
	if setConstantKeywordValueInPropsRound59(props, []string{"missing"}, "x") {
		t.Fatalf("expected false for missing prop")
	}

	// 5. compareCompositeVersionValuesRound59.
	verAgg := esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "ver", ValueType: "version"}}
	if cmp, ok := compareCompositeVersionValuesRound59("1.2.0", "1.10.0", verAgg, false, nil); !ok || cmp >= 0 {
		t.Fatalf("expected 1.2.0 < 1.10.0 asc, got cmp=%d ok=%v", cmp, ok)
	}
	if cmp, ok := compareCompositeVersionValuesRound59("1.2.0", "1.10.0", verAgg, true, nil); !ok || cmp <= 0 {
		t.Fatalf("expected 1.2.0 > 1.10.0 desc, got cmp=%d ok=%v", cmp, ok)
	}
	if _, ok := compareCompositeVersionValuesRound59("a", "b", esast.AggSpec{}, false, nil); ok {
		t.Fatalf("expected non-terms agg unhandled")
	}

	// 6. evalFieldValueFactorOnDocRound59 across all modifiers + domain errors + missing handling.
	f2 := 2.0
	if sc, ok, err := evalFieldValueFactorOnDocRound59(nil, map[string]any{}, &esast.FieldValueFactorSpec{Field: "x", Modifier: "reciprocal"}); err != nil || !ok || sc != 0.0 {
		t.Fatalf("expected missing field without missing param to return 0.0, got %v %v %v", sc, ok, err)
	}
	nanVal := math.NaN()
	if _, _, err := evalFieldValueFactorOnDocRound59(nil, map[string]any{}, &esast.FieldValueFactorSpec{Field: "x", Missing: &nanVal}); err == nil {
		t.Fatalf("expected error on NaN missing value")
	}
	for _, mod := range []string{"none", "log", "log1p", "log2p", "ln", "ln1p", "ln2p", "square", "sqrt", "reciprocal"} {
		sc, ok, err := evalFieldValueFactorOnDocRound59(nil, map[string]any{"x": 4.0}, &esast.FieldValueFactorSpec{Field: "x", Factor: &f2, Modifier: mod})
		if err != nil || !ok || sc <= 0 {
			t.Fatalf("modifier %s failed on x=4.0 factor=2.0: sc=%v ok=%v err=%v", mod, sc, ok, err)
		}
	}
	for _, badCase := range []struct {
		val float64
		mod string
	}{
		{0, "log"},
		{-1, "log1p"},
		{-2, "log2p"},
		{0, "ln"},
		{-1, "ln1p"},
		{-2, "ln2p"},
		{-1, "sqrt"},
		{0, "reciprocal"},
		{5, "no_such_modifier"},
	} {
		if _, _, err := evalFieldValueFactorOnDocRound59(nil, map[string]any{"x": badCase.val}, &esast.FieldValueFactorSpec{Field: "x", Modifier: badCase.mod}); err == nil {
			t.Fatalf("expected domain/unknown error for modifier=%s val=%v", badCase.mod, badCase.val)
		}
	}

	// 7. queryProducesCustomScoreRound59, evalRuntimeSearchScoreWithErrorRound59 & hit validators.
	scoreQueries := []string{
		`{"script_score":{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"2.0"}}},"script":{"source":"_score * 3.0"},"boost":1.5}}`,
		`{"function_score":{"query":{"match_all":{}},"script_score":{"script":{"source":"4.0"}},"weight":2.0,"max_boost":5.0,"boost":1.5}}`,
		`{"function_score":{"query":{"match_all":{}},"random_score":{"seed":42,"field":"_seq_no"},"weight":2.0}}`,
		`{"function_score":{"query":{"match_all":{}},"weight":3.0}}`,
		`{"function_score":{"query":{"match_all":{}},"score_mode":"first","functions":[{"filter":{"term":{"tag":"nope"}},"weight":99},{"script_score":{"script":{"source":"2.5"}},"weight":2.0},{"random_score":{"seed":1}}]}}`,
		`{"function_score":{"query":{"match_all":{}},"functions":[{"field_value_factor":{"field":"x","modifier":"sqrt"}},{"random_score":{"seed":7}},{"weight":1.5}]}}`,
		`{"bool":{"must":[{"match_all":{}},{"script_score":{"query":{"match_all":{}},"script":{"source":"2.0"}}}],"should":[{"term":{"tag":"ok"}},{"function_score":{"query":{"match_all":{}},"weight":1.5}}],"boost":2.0}}`,
		`{"dis_max":{"tie_breaker":0.3,"boost":1.2,"queries":[{"script_score":{"query":{"match_all":{}},"script":{"source":"2.0"}}},{"script_score":{"query":{"match_all":{}},"script":{"source":"5.0"}}},{"match_all":{}}]}}`,
		`{"boosting":{"positive":{"script_score":{"query":{"match_all":{}},"script":{"source":"4.0"}}},"negative":{"term":{"tag":"ok"}},"negative_boost":0.5,"boost":2.0}}`,
	}
	testDoc := map[string]any{"tag": "ok", "x": 9.0, "__meta_id": "1"}
	for i, qJSON := range scoreQueries {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("case %d unmarshal query failed: %v", i, err)
		}
		if !queryProducesCustomScoreRound59(&q) {
			t.Fatalf("case %d expected queryProducesCustomScoreRound59=true", i)
		}
		sc, err := evalRuntimeSearchScoreWithErrorRound59(nil, testDoc, &q, 1.0)
		if err != nil || sc < 0 {
			t.Fatalf("case %d evalRuntimeSearchScoreWithErrorRound59 failed: sc=%v err=%v", i, sc, err)
		}
	}
	var negQ esast.Query
	_ = json.Unmarshal([]byte(`{"script_score":{"query":{"match_all":{}},"script":{"source":"-2.0"}}}`), &negQ)
	if err := validateCustomSearchScoresOnRuntimeHitsRound59(nil, &negQ, []HitRow{{ID: "1", Score: 1.0, Source: json.RawMessage(`{"x":1}`)}}); err == nil {
		t.Fatalf("expected runtime hits validator to reject negative script_score")
	}
	if err := validateCustomSearchScoresOnSQLHitsRound59(&negQ, []HitRow{{ID: "1", Score: -0.5}}); err == nil {
		t.Fatalf("expected SQL hits validator to reject negative score")
	}

	// 8. DST wall-clock adjustment, calendar/fixed date_histogram bucket floor/step/synthesis & formatting.
	nyLoc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("failed to load America/New_York: %v", err)
	}
	// 2026-03-08 02:30 does not exist in America/New_York (springs forward 02:00 -> 03:00).
	adj := adjustWallTimeInLocRound59(2026, time.March, 8, 2, 30, 0, nyLoc)
	if adj.Hour() < 3 {
		t.Fatalf("expected spring-forward DST gap adjustment >= 03:00 EDT, got %v", adj)
	}
	sampleEpoch := time.Date(2026, time.May, 20, 15, 42, 18, 0, time.UTC).UnixMilli()
	for _, cal := range []string{"1m", "1h", "1d", "1w", "1M", "1q", "1y"} {
		spec := &esast.DateHistogramAggSpec{Field: "ts", CalendarInterval: cal, TimeZone: "America/New_York"}
		floored := floorDateHistogramBucketMillisRound59(sampleEpoch, spec)
		stepped := stepDateHistogramBucketMillisRound59(floored, spec)
		if stepped <= floored {
			t.Fatalf("calendar_interval=%s: expected stepped (%d) > floored (%d)", cal, stepped, floored)
		}
	}
	fixedNYSpec := &esast.DateHistogramAggSpec{Field: "ts", FixedInterval: "2h", TimeZone: "America/New_York"}
	fFixed := floorDateHistogramBucketMillisRound59(sampleEpoch, fixedNYSpec)
	if stepDateHistogramBucketMillisRound59(fFixed, fixedNYSpec) != fFixed+7200000 {
		t.Fatalf("expected 2h fixed step")
	}

	var dhSynthSpec esast.DateHistogramAggSpec
	if err := json.Unmarshal([]byte(`{
		"field": "ts",
		"calendar_interval": "1M",
		"time_zone": "America/New_York",
		"min_doc_count": 0,
		"extended_bounds": {"min": "2026-01-01", "max": "2026-04-01"},
		"hard_bounds": {"min": "2026-01-01", "max": "2026-03-15"}
	}`), &dhSynthSpec); err != nil {
		t.Fatalf("unmarshal dhSynthSpec failed: %v", err)
	}
	febStart := floorDateHistogramBucketMillisRound59(time.Date(2026, time.February, 10, 12, 0, 0, 0, time.UTC).UnixMilli(), &dhSynthSpec)
	mayStart := floorDateHistogramBucketMillisRound59(time.Date(2026, time.May, 10, 12, 0, 0, 0, time.UTC).UnixMilli(), &dhSynthSpec)
	synthesized := synthesizeDateHistogramBucketsRound59([]AggRow{
		{BucketKey: strconv.FormatInt(febStart, 10), DocCount: 3},
		{BucketKey: strconv.FormatInt(mayStart, 10), DocCount: 9},
	}, &dhSynthSpec)
	if len(synthesized) != 3 || synthesized[0].DocCount != 0 || synthesized[1].DocCount != 3 || synthesized[2].DocCount != 0 {
		t.Fatalf("expected 3 synthesized buckets (Jan=0, Feb=3, Mar=0) bounded by hard_bounds, got %+v", synthesized)
	}
	two := 2
	dhMin2Spec := &esast.DateHistogramAggSpec{Field: "ts", CalendarInterval: "1M", MinDocCount: &two}
	if kept := synthesizeDateHistogramBucketsRound59(synthesized, dhMin2Spec); len(kept) != 1 || kept[0].DocCount != 3 {
		t.Fatalf("expected min_doc_count=2 to keep only Feb bucket, got %+v", kept)
	}

	winterKey := formatDateHistogramKeyAsStringRound59(time.Date(2026, time.January, 15, 5, 0, 0, 0, time.UTC).UnixMilli(), &dhSynthSpec)
	summerKey := formatDateHistogramKeyAsStringRound59(time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC).UnixMilli(), &dhSynthSpec)
	if !strings.HasSuffix(winterKey, "-05:00") || !strings.HasSuffix(summerKey, "-04:00") {
		t.Fatalf("expected NY winter -05:00 and summer -04:00 offsets, got winter=%q summer=%q", winterKey, summerKey)
	}
	kolkataSpec := &esast.DateHistogramAggSpec{Field: "ts", CalendarInterval: "1d", TimeZone: "Asia/Kolkata"}
	if kolKey := formatDateHistogramKeyAsStringRound59(time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC).UnixMilli(), kolkataSpec); !strings.HasSuffix(kolKey, "+05:30") {
		t.Fatalf("expected Asia/Kolkata +05:30 offset, got %q", kolKey)
	}
	if mappingOrShredErrorTypeRound59(nil) != "mapper_parsing_exception" ||
		mappingOrShredErrorTypeRound59(fmt.Errorf("Limit of total fields [10] has been exceeded")) != "illegal_argument_exception" {
		t.Fatalf("unexpected mappingOrShredErrorTypeRound59 classification")
	}

	dtRow := map[string]any{"sec_col": float64(3661), "dt_col": "1970-01-02 01:01:01"}
	if got := resolveColumnValue(dtRow, "SECONDS_ADD(CAST('1970-01-01 00:00:00' AS DATETIME), `sec_col`)"); got != "1970-01-01 01:01:01.000000" {
		t.Fatalf("expected SECONDS_ADD result, got %v", got)
	}
	if got := resolveColumnValue(dtRow, "SECONDS_ADD('1970-01-01 00:00:00', 30 + 30)"); got != "1970-01-01 00:01:00.000000" {
		t.Fatalf("expected arithmetic SECONDS_ADD result, got %v", got)
	}
	for _, unit := range []string{"SECOND", "MINUTE", "HOUR", "DAY", "UNKNOWN"} {
		_ = resolveColumnValue(dtRow, fmt.Sprintf("TIMESTAMPDIFF(%s, '1970-01-01 00:00:00', `dt_col`)", unit))
	}
	_ = resolveColumnValue(dtRow, "FROM_UNIXTIME(`sec_col`)")
	_ = resolveColumnValue(dtRow, "FROM_UNIXTIME(30 + 30)")
	_ = resolveColumnValue(dtRow, "UNIX_TIMESTAMP(`dt_col`)")
}
