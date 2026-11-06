package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound46Raw(t *testing.T, srv *Server, method, path, body string) (int, string, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, raw, parsed
}

func TestRound46DeleteIndexAndReadVersionSemantics(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F13: DELETE missing concrete index returns 404 unless ignore_unavailable=true
	code, _, res := doRound46Raw(t, srv, http.MethodDelete, "/missing_idx_r46", "")
	if code != http.StatusNotFound {
		t.Fatalf("F13 expected 404 deleting missing concrete index, got %d: %+v", code, res)
	}
	code, _, res = doRound46Raw(t, srv, http.MethodDelete, "/missing_idx_r46?ignore_unavailable=true", "")
	if code != http.StatusOK || res["acknowledged"] != true {
		t.Fatalf("F13 expected 200 with ignore_unavailable=true, got %d: %+v", code, res)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodDelete, "/missing_wild_*?allow_no_indices=false", "")
	if code != http.StatusNotFound {
		t.Fatalf("F13 expected 404 on wildcard with allow_no_indices=false, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodDelete, "/missing_wild_*?allow_no_indices=true", "")
	if code != http.StatusOK {
		t.Fatalf("F13 expected 200 on wildcard with allow_no_indices=true, got %d", code)
	}

	// Create index and doc (version=1)
	doRound39JSON(t, srv, http.MethodPut, "/r46_ver_idx", `{"mappings":{"properties":{"title":{"type":"text"}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_ver_idx/_doc/1?version=1&version_type=external&refresh=true", `{"title":"v1 doc"}`)

	// F14: GET/HEAD _doc and _source with version matching and conflict
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version=1", "")
	if code != http.StatusOK {
		t.Fatalf("F14 expected 200 on matching version=1, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version=2", "")
	if code != http.StatusConflict {
		t.Fatalf("F14 expected 409 on mismatched version=2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/r46_ver_idx/_doc/1?version=2", "")
	if code != http.StatusConflict {
		t.Fatalf("F14 expected 409 on HEAD _doc with mismatched version=2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_source/1?version=2", "")
	if code != http.StatusConflict {
		t.Fatalf("F14 expected 409 on GET _source with mismatched version=2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/r46_ver_idx/_source/1?version=2", "")
	if code != http.StatusConflict {
		t.Fatalf("F14 expected 409 on HEAD _source with mismatched version=2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version=1&version_type=external_gt", "")
	if code != http.StatusConflict {
		t.Fatalf("F14 expected 409 on external_gt with equal version=1, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version=2&version_type=external_gt", "")
	if code != http.StatusOK {
		t.Fatalf("F14 expected 200 on external_gt with version=2 > 1, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version=0", "")
	if code != http.StatusBadRequest {
		t.Fatalf("F14 expected 400 on version=0, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/r46_ver_idx/_doc/1?version_type=bogus", "")
	if code != http.StatusBadRequest {
		t.Fatalf("F14 expected 400 on invalid version_type=bogus, got %d", code)
	}

	// F14 & F15: _mget validation & version conflict
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_mget", `{"ids":["1"]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F15 expected 400 on /_mget with ids and no default index, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_mget", `{"docs":[{"_id":"1"}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F15 expected 400 on /_mget with missing _index in docs item, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/r46_ver_idx/_mget", `{"docs":[{"_index":"r46_ver_idx"}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F15 expected 400 on /_mget with missing _id in docs item, got %d", code)
	}
	code, _, mgetRes := doRound46Raw(t, srv, http.MethodPost, "/r46_ver_idx/_mget", `{"docs":[{"_id":"1","version":99},{"_id":"1","version":1}]}`)
	if code != http.StatusOK {
		t.Fatalf("F14 expected 200 on _mget with per-item version conflict, got %d: %+v", code, mgetRes)
	}
	docsArr, _ := mgetRes["docs"].([]any)
	if len(docsArr) != 2 {
		t.Fatalf("expected 2 docs in _mget response, got %+v", mgetRes)
	}
	firstItem, _ := docsArr[0].(map[string]any)
	secondItem, _ := docsArr[1].(map[string]any)
	if firstItem["error"] == nil || secondItem["found"] != true {
		t.Fatalf("F14 expected first item version conflict error and second item found=true, got %+v", docsArr)
	}
}

func TestRound46AliasesIngestCatResolveDataStreamAndTemplates(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F16: HEAD /_alias when no aliases exist -> 404
	code, _, _ := doRound46Raw(t, srv, http.MethodHead, "/_alias", "")
	if code != http.StatusNotFound {
		t.Fatalf("F16 expected 404 on HEAD /_alias when no aliases exist, got %d", code)
	}
	// Unsupported method on /_alias -> 405
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_alias/foo", `{}`)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("F16 expected 405 on POST /_alias/foo, got %d", code)
	}

	doRound39JSON(t, srv, http.MethodPut, "/r46_idx_a", `{
		"mappings": {
			"runtime": {
				"rt_double": {"type": "double", "script": {"source": "emit(1.0)"}}
			},
			"properties": {
				"host": {"type": "keyword"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_idx_b", `{"mappings":{"properties":{"host":{"type":"keyword"}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_idx_a/_alias/alias_alpha", `{}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_idx_b/_alias/alias_beta", `{}`)

	// F16: GET /_aliases/{name} with comma-separated & exclusion pattern
	code, _, aliasRes := doRound46Raw(t, srv, http.MethodGet, "/_aliases/alias_*,-*beta", "")
	if code != http.StatusOK || aliasRes["r46_idx_a"] == nil || aliasRes["r46_idx_b"] != nil {
		t.Fatalf("F16 expected only r46_idx_a in /_aliases/alias_*,-*beta, got %d: %+v", code, aliasRes)
	}
	// F16: GET /{index}/_alias/{name} on non-existent index -> 404 index_not_found_exception
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/no_such_index/_alias/alias_alpha", "")
	if code != http.StatusNotFound {
		t.Fatalf("F16 expected 404 on GET /no_such_index/_alias/alias_alpha, got %d", code)
	}

	// F17: Ingest pipeline HEAD, wildcard GET, 404 on missing GET/DELETE, GET _simulate, and missing pipeline validation
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/pipe_one", `{"processors":[{"set":{"field":"x","value":1}}]}`)
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/pipe_two", `{"processors":[{"set":{"field":"y","value":2}}]}`)

	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/_ingest/pipeline/pipe_one", "")
	if code != http.StatusOK {
		t.Fatalf("F17 expected 200 on HEAD /_ingest/pipeline/pipe_one, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/_ingest/pipeline/pipe_missing", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on HEAD /_ingest/pipeline/pipe_missing, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/_ingest/pipeline/pipe_missing", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on GET /_ingest/pipeline/pipe_missing, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodDelete, "/_ingest/pipeline/pipe_missing", "")
	if code != http.StatusNotFound {
		t.Fatalf("F17 expected 404 on DELETE /_ingest/pipeline/pipe_missing, got %d", code)
	}
	code, _, pipeRes := doRound46Raw(t, srv, http.MethodGet, "/_ingest/pipeline/pipe_*", "")
	if code != http.StatusOK || pipeRes["pipe_one"] == nil || pipeRes["pipe_two"] == nil {
		t.Fatalf("F17 expected both pipe_one and pipe_two on wildcard GET, got %d: %+v", code, pipeRes)
	}
	code, _, simRes := doRound46Raw(t, srv, http.MethodGet, "/_ingest/pipeline/pipe_one/_simulate", `{"docs":[{"_source":{"msg":"hi"}}]}`)
	if code != http.StatusOK || simRes["docs"] == nil {
		t.Fatalf("F17 expected 200 on GET /_ingest/pipeline/pipe_one/_simulate, got %d: %+v", code, simRes)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{"docs":[{"_source":{"msg":"hi"}}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F17 expected 400 on POST /_ingest/pipeline/_simulate without pipeline, got %d", code)
	}

	// F18: _cat endpoints ?help, ?s=, ?h=, ?v=false, and docs.count/uuid
	code, helpBody, _ := doRound46Raw(t, srv, http.MethodGet, "/_cat/indices?help", "")
	if code != http.StatusOK || !strings.Contains(helpBody, "health") {
		t.Fatalf("F18 expected help output from /_cat/indices?help, got %d: %s", code, helpBody)
	}
	code, rawCat, _ := doRound46Raw(t, srv, http.MethodGet, "/_cat/indices?h=index,docs.count,uuid&s=index:desc&format=json", "")
	if code != http.StatusOK || !strings.Contains(rawCat, `"docs.count"`) || !strings.Contains(rawCat, `"uuid"`) {
		t.Fatalf("F18 expected filtered/sorted JSON from /_cat/indices, got %d: %s", code, rawCat)
	}

	// F20: _mapping/field & _field_caps include runtime fields and 404 on missing concrete index
	code, _, _ = doRound46Raw(t, srv, http.MethodGet, "/no_such_idx/_mapping/field/host", "")
	if code != http.StatusNotFound {
		t.Fatalf("F20 expected 404 on GET /no_such_idx/_mapping/field/host, got %d", code)
	}
	code, _, mfRes := doRound46Raw(t, srv, http.MethodGet, "/r46_idx_a/_mapping/field/rt_double", "")
	if code != http.StatusOK || mfRes["r46_idx_a"] == nil {
		t.Fatalf("F20 expected 200 on runtime field in _mapping/field, got %d: %+v", code, mfRes)
	}
	code, _, fcRes := doRound46Raw(t, srv, http.MethodGet, "/r46_idx_a/_field_caps?fields=rt_*", "")
	if code != http.StatusOK {
		t.Fatalf("F20 expected 200 on _field_caps for runtime field, got %d: %+v", code, fcRes)
	}
	fcFields, _ := fcRes["fields"].(map[string]any)
	if fcFields["rt_double"] == nil {
		t.Fatalf("F20 expected rt_double in _field_caps response, got %+v", fcRes)
	}

	// F21 & F19: Data streams HEAD, _rollover, empty name 400, and _resolve/index data_streams
	code, _, _ = doRound46Raw(t, srv, http.MethodPut, "/_data_stream", "")
	if code != http.StatusBadRequest {
		t.Fatalf("F21 expected 400 on PUT /_data_stream without name, got %d", code)
	}
	doRound39JSON(t, srv, http.MethodPut, "/_data_stream/ds-logs-r46", `{}`)
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/_data_stream/ds-logs-r46", "")
	if code != http.StatusOK {
		t.Fatalf("F21 expected 200 on HEAD /_data_stream/ds-logs-r46, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/_data_stream/ds-missing-r46", "")
	if code != http.StatusNotFound {
		t.Fatalf("F21 expected 404 on HEAD /_data_stream/ds-missing-r46, got %d", code)
	}
	code, _, rollRes := doRound46Raw(t, srv, http.MethodPost, "/_data_stream/ds-logs-r46/_rollover", `{}`)
	if code != http.StatusOK || rollRes["rolled_over"] != true {
		t.Fatalf("F21 expected 200 rolled_over=true on POST /_data_stream/ds-logs-r46/_rollover, got %d: %+v", code, rollRes)
	}
	code, _, resIdx := doRound46Raw(t, srv, http.MethodGet, "/_resolve/index/ds-logs-*,r46_idx_*,-r46_idx_b", "")
	if code != http.StatusOK {
		t.Fatalf("F19 expected 200 on /_resolve/index, got %d: %+v", code, resIdx)
	}
	dsArr, _ := resIdx["data_streams"].([]any)
	if len(dsArr) != 1 {
		t.Fatalf("F19 expected 1 data_stream in _resolve/index response, got %+v", resIdx)
	}

	// F24: Index template ?create=true and HEAD wildcard
	code, _, _ = doRound46Raw(t, srv, http.MethodPut, "/_index_template/tmpl_r46?create=true", `{"index_patterns":["logs-*"]}`)
	if code != http.StatusOK {
		t.Fatalf("F24 expected 200 creating tmpl_r46 with create=true, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPut, "/_index_template/tmpl_r46?create=true", `{"index_patterns":["logs-*"]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F24 expected 400 recreating existing tmpl_r46 with create=true, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodHead, "/_index_template/tmpl_*", "")
	if code != http.StatusOK {
		t.Fatalf("F24 expected 200 on HEAD /_index_template/tmpl_*, got %d", code)
	}
}

func TestRound46IndicesBoostURISearchExplainAndMutations(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r46_boost_1", `{"mappings":{"properties":{"title":{"type":"text"}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_boost_2", `{"mappings":{"properties":{"title":{"type":"text"}}}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_boost_2/_alias/alias_boost_2", `{}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_boost_1/_doc/a?refresh=true", `{"title":"common search term"}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_boost_2/_doc/b?refresh=true", `{"title":"common search term"}`)

	// F22 & F23: indices_boost + URI search params (?version=true&seq_no_primary_term=true&explain=true)
	code, _, searchRes := doRound46Raw(t, srv, http.MethodPost, "/r46_boost_1,r46_boost_2/_search?version=true&seq_no_primary_term=true&explain=true", `{
		"indices_boost": [
			{"r46_boost_1": 1.0},
			{"alias_boost_2": 10.0}
		],
		"query": {"match": {"title": "common"}}
	}`)
	if code != http.StatusOK {
		t.Fatalf("F22/F23 expected 200 on multi-index search with indices_boost, got %d: %+v", code, searchRes)
	}
	hits := searchRes["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	topHit := hits[0].(map[string]any)
	if topHit["_index"] != "r46_boost_2" || topHit["_version"] == nil || topHit["_seq_no"] == nil || topHit["_explanation"] == nil {
		t.Fatalf("F22/F23 expected r46_boost_2 ranked first with _version, _seq_no, and _explanation populated, got %+v", topHit)
	}

	// F25: _explain with routing mismatch, _source=true -> get sub-object
	code, _, expRes := doRound46Raw(t, srv, http.MethodPost, "/r46_boost_1/_explain/a?_source=true", `{"query":{"match":{"title":"common"}}}`)
	if code != http.StatusOK || expRes["matched"] != true || expRes["get"] == nil {
		t.Fatalf("F25 expected matched=true and get sub-object on _explain?_source=true, got %d: %+v", code, expRes)
	}

	// F30-F32: Ingest processors (unknown processor 400, set_security_user, numeric bytes, convert short/byte/unsigned_long/half_float/scaled_float, schemeless uri_parts)
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"totally_unknown_proc": {"field": "x"}}]},
		"docs": [{"_source": {"x": 1}}]
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F30 expected 400 on unknown ingest processor, got %d", code)
	}

	code, _, simRes := doRound46Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"set_security_user": {"field": "user_ctx"}},
				{"bytes": {"field": "num_bytes", "target_field": "parsed_bytes"}},
				{"convert": {"field": "s_val", "type": "short", "target_field": "short_out"}},
				{"convert": {"field": "b_val", "type": "byte", "target_field": "byte_out"}},
				{"convert": {"field": "u_val", "type": "unsigned_long", "target_field": "ulong_out"}},
				{"convert": {"field": "hf_val", "type": "half_float", "target_field": "hf_out"}},
				{"uri_parts": {"field": "raw_uri", "target_field": "uri_info"}}
			]
		},
		"docs": [{
			"_source": {
				"num_bytes": 2048,
				"s_val": "32000",
				"b_val": "120",
				"u_val": "18446744073709551615",
				"hf_val": "3.5",
				"raw_uri": "example.com:8080/api/v1"
			}
		}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("F30-F32 expected 200 on _simulate, got %d: %+v", code, simRes)
	}
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	uriInfo, _ := simDoc["uri_info"].(map[string]any)
	if simDoc["user_ctx"] == nil || simDoc["parsed_bytes"].(float64) != 2048 || (uriInfo["domain"] != "example.com" && uriInfo["host"] != "example.com") || uriInfo["port"].(float64) != 8080 {
		t.Fatalf("F30-F32 unexpected simulated doc: %+v", simDoc)
	}

	// F32: uri_parts and registered_domain default ignore_missing=false
	code, _, simMissing := doRound46Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"uri_parts": {"field": "missing_uri"}}]},
		"docs": [{"_source": {"other": "val"}}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 wrapper on _simulate with processor error, got %d", code)
	}
	firstSimDoc := simMissing["docs"].([]any)[0].(map[string]any)
	if firstSimDoc["error"] == nil {
		t.Fatalf("F32 expected error when missing_uri is absent and ignore_missing defaults to false, got %+v", firstSimDoc)
	}

	// F33 & F34: require_alias=true on _doc, _update, and _bulk, plus bulk per-item doc_as_upsert / detect_noop / _source
	code, _, _ = doRound46Raw(t, srv, http.MethodPut, "/r46_boost_2/_doc/req1?require_alias=true", `{"title":"direct index blocked"}`)
	if code != http.StatusNotFound {
		t.Fatalf("F34 expected 404 when require_alias=true targets concrete index r46_boost_2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPut, "/alias_boost_2/_doc/req1?require_alias=true&refresh=true", `{"title":"via alias allowed"}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("F34 expected 201 when require_alias=true targets alias_boost_2, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/r46_boost_2/_update/req1?require_alias=true", `{"doc":{"title":"updated"}}`)
	if code != http.StatusNotFound {
		t.Fatalf("F34 expected 404 on _update with require_alias=true targeting concrete index, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/alias_boost_2/_update/req1?require_alias=true", `{"doc":{"title":"updated"}}`)
	if code != http.StatusOK {
		t.Fatalf("F34 expected 200 on _update with require_alias=true targeting alias, got %d", code)
	}

	bulkPayload := strings.Join([]string{
		`{"update":{"_index":"r46_boost_2","_id":"req1","require_alias":true}}`,
		`{"doc":{"title":"should fail require_alias"}}`,
		`{"update":{"_index":"alias_boost_2","_id":"upsert_via_meta","require_alias":true,"doc_as_upsert":true,"_source":true}}`,
		`{"doc":{"title":"upserted via action meta"}}`,
		`{"update":{"_index":"alias_boost_2","_id":"upsert_via_meta","detect_noop":true}}`,
		`{"doc":{"title":"upserted via action meta"}}`,
	}, "\n") + "\n"
	code, _, bulkRes := doRound46Raw(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkPayload)
	if code != http.StatusOK {
		t.Fatalf("F33 expected 200 on /_bulk, got %d: %+v", code, bulkRes)
	}
	bulkItems := bulkRes["items"].([]any)
	item0 := bulkItems[0].(map[string]any)["update"].(map[string]any)
	item1 := bulkItems[1].(map[string]any)["update"].(map[string]any)
	item2 := bulkItems[2].(map[string]any)["update"].(map[string]any)
	if int(item0["status"].(float64)) != http.StatusNotFound {
		t.Fatalf("F33 expected item0 status 404 on require_alias failure, got %+v", item0)
	}
	if item1["result"] != "created" || item1["get"] == nil {
		t.Fatalf("F33 expected item1 result=created with get._source populated from action-meta doc_as_upsert/_source, got %+v", item1)
	}
	if item2["result"] != "noop" {
		t.Fatalf("F33 expected item2 result=noop, got %+v", item2)
	}

	// F35: _reindex / _update_by_query / _delete_by_query validation & requests_per_second / noops
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": "r46_boost_1"},
		"dest": {"index": "r46_boost_2", "op_type": "invalid_op"}
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F35 expected 400 on invalid dest.op_type, got %d", code)
	}
	code, _, _ = doRound46Raw(t, srv, http.MethodPost, "/r46_boost_1/_update_by_query", `{"conflicts":"bogus"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("F35 expected 400 on invalid conflicts value, got %d", code)
	}
	code, _, ubqRes := doRound46Raw(t, srv, http.MethodPost, "/r46_boost_1/_update_by_query?requests_per_second=250", `{
		"script": {"source": "ctx.op = 'noop'"}
	}`)
	if code != http.StatusOK || ubqRes["noops"].(float64) != 1 || ubqRes["requests_per_second"].(float64) != 250 {
		t.Fatalf("F35 expected noops=1 and requests_per_second=250 on _update_by_query, got %d: %+v", code, ubqRes)
	}

	// F1, F2, F3: End-to-end geo_distance, geo_bounding_box, and boolean match via Server + MemoryBackend
	doRound39JSON(t, srv, http.MethodPut, "/r46_geo_idx", `{
		"mappings": {
			"properties": {
				"city": {"type": "keyword"},
				"active": {"type": "boolean"},
				"loc": {"type": "geo_point"}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_geo_idx/_doc/nyc?refresh=true", `{"city":"NYC","active":true,"loc":{"lat":40.7128,"lon":-74.0060}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_geo_idx/_doc/jfk?refresh=true", `{"city":"JFK","active":true,"loc":{"lat":40.6413,"lon":-73.7781}}`)
	doRound39JSON(t, srv, http.MethodPut, "/r46_geo_idx/_doc/lax?refresh=true", `{"city":"LAX","active":false,"loc":{"lat":33.9416,"lon":-118.4085}}`)

	code, _, geoSearch := doRound46Raw(t, srv, http.MethodPost, "/r46_geo_idx/_search", `{
		"query": {
			"bool": {
				"must": [
					{"match": {"active": true}},
					{"geo_distance": {"distance": "30km", "loc": {"lat": 40.7128, "lon": -74.0060}}},
					{"geo_bounding_box": {"loc": {"top_left": {"lat": 41.0, "lon": -75.0}, "bottom_right": {"lat": 40.0, "lon": -73.0}}}}
				]
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("F1/F2/F3 expected 200 on geo search, got %d: %+v", code, geoSearch)
	}
	geoHits := geoSearch["hits"].(map[string]any)["hits"].([]any)
	if len(geoHits) != 2 {
		t.Fatalf("F1/F2/F3 expected 2 NYC/JFK hits within 30km and bounding box, got %d: %+v", len(geoHits), geoHits)
	}

	// Additional _cat/*, _data_stream, and bytes processor unit coverage
	doRound39JSON(t, srv, http.MethodPut, "/_data_stream/ds-r46-b", `{}`)
	for _, catPath := range []string{
		"/_cat/shards/r46_geo_idx?format=json&h=index,shard,prirep,state,docs&s=shard:desc",
		"/_cat/health?format=json&h=cluster,status,node.total",
		"/_cat/count/r46_geo_idx?format=json&h=count",
		"/_cat/nodes?format=json&h=name,ip,role&s=name",
		"/_data_stream/ds-r46-b",
		"/_data_stream",
	} {
		c, _, _ := doRound46Raw(t, srv, http.MethodGet, catPath, "")
		if c != http.StatusOK {
			t.Fatalf("expected 200 on %s, got %d", catPath, c)
		}
	}
	for _, unitStr := range []string{"512b", "2mb", "1gb", "1tb", "1pb"} {
		doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate",
			`{"pipeline":{"processors":[{"bytes":{"field":"sz","target_field":"out_sz"}}]},"docs":[{"_source":{"sz":"`+unitStr+`"}}]}`)
	}
}
