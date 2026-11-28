package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR67CovFeatServer(t *testing.T) (*Server, *MemoryBackend) {
	t.Helper()
	be := NewMemoryBackend(false)
	srv := NewServer("test_db", be, transpiler.TranspilerOptions{})
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, be
}

func doR67CovFeatHTTP(t *testing.T, srv *Server, method, path, body string, headers ...[2]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		hasCT := false
		for _, h := range headers {
			if strings.EqualFold(h[0], "Content-Type") {
				hasCT = true
				break
			}
		}
		if !hasCT {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func mustR67CovFeatHTTP(t *testing.T, srv *Server, method, path, body string, wantCode int, headers ...[2]string) map[string]any {
	t.Helper()
	rec := doR67CovFeatHTTP(t, srv, method, path, body, headers...)
	if rec.Code != wantCode {
		t.Fatalf("%s %s: status=%d, want %d; body=%s", method, path, rec.Code, wantCode, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		return nil
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func mustR67CovFeatJSON(t *testing.T, raw string, dst any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\npayload=%s", err, raw)
	}
}

func TestRound67Cov_Features_IngestProcessorsAndSimulate(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)

	// 1. Pipeline CRUD & validation errors (handleIngestPipeline & validateIngestPipelineProcessors)
	doR67CovFeatHTTP(t, srv, http.MethodPatch, "/_ingest/pipeline/p1", `{}`)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_json_conflict",
		`{"processors":[{"json":{"field":"msg","target_field":"out","add_to_root":true}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_json_bool",
		`{"processors":[{"json":{"field":"msg","ignore_missing":"nope"}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_kv",
		`{"processors":[{"kv":{"field":"msg","field_split":" ","value_split":"=","transform_key":"invalid"}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_kv_inc",
		`{"processors":[{"kv":{"field":"msg","field_split":" ","value_split":"=","include_keys":[""]}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_kv_exc",
		`{"processors":[{"kv":{"field":"msg","field_split":" ","value_split":"=","exclude_keys":"bad"}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_onfail",
		`{"processors":[{"set":{"field":"a","value":1,"on_failure":[]}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_prop",
		`{"processors":[{"set":{"field":"a","value":1,"unknown_cfg_prop":true}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_date",
		`{"processors":[{"date":{"field":"ts","formats":["INVALID_PATTERN_$$$"]}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_date_empty",
		`{"processors":[{"date":{"field":"ts","formats":[""]}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad_sort",
		`{"processors":[{"sort":{}}]}`, http.StatusBadRequest)

	// Valid sub-pipelines and stored script
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/sub_ok",
		`{"description":"sub pipe","version":1,"processors":[{"set":{"field":"from_sub","value":true}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/sub_fail",
		`{"processors":[{"fail":{"message":"boom from {{msg}}"}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/main_pipe",
		`{"description":"main pipe","version":1,"processors":[{"set":{"field":"main_ran","value":"yes"}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/final_pipe",
		`{"description":"final pipe","processors":[{"set":{"field":"final_ran","value":"yes"}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_scripts/r67_ing_script",
		`{"script":{"lang":"painless","source":"ctx.scripted = params.v;"}}`, http.StatusOK)

	// Version check & GET/HEAD/wildcard/DELETE
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/sub_ok?if_version=99",
		`{"processors":[{"set":{"field":"x","value":1}}]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_ingest/pipeline/sub_ok", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_ingest/pipeline/missing_pipe", "", http.StatusNotFound)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ingest/pipeline/sub_*", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ingest/pipeline/missing_pipe", "", http.StatusNotFound)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ingest/pipeline", "", http.StatusOK)

	// Grok & GeoIP stats endpoints
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ingest/processor/grok", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ingest/geoip/stats", "", http.StatusOK)

	// 2. HTTP Simulate comprehensive processor suite (verbose=true)
	plainB64 := base64.StdEncoding.EncodeToString([]byte("Hello attachment world!"))
	latinB64 := base64.RawStdEncoding.EncodeToString([]byte("caf\xe9 line"))
	simBody := fmt.Sprintf(`{
		"pipeline": {
			"description": "r67 full simulate",
			"processors": [
				{"pipeline": {"name": "{{sub_name}}", "tag": "call_sub", "description": "run sub", "if": "ctx.sub_name != null"}},
				{"pipeline": {"name": "sub_fail", "on_failure": [{"set": {"field": "recovered_pipe", "value": "{{_ingest.on_failure_message}}"}}]}},
				{"dissect": {"field": "raw_line", "pattern": "%%{a} %%{b}", "if": "ctx.raw_line != null"}},
				{"set": {"field": "s_opt", "value": "", "ignore_empty_value": true}},
				{"set": {"field": "existing", "value": "overwrite", "override": false}},
				{"set": {"field": "decoded_json", "value": "{\"k\":1}", "media_type": "application/json"}},
				{"default": {"field": "def_missing", "value": "fallback"}},
				{"rename": {"field": "ren_src", "target_field": "ren_dst"}},
				{"rename": {"field": "ren_absent", "target_field": "ren_dst2", "ignore_missing": true}},
				{"copy": {"field": "copy_src", "target_field": "copy_dst"}},
				{"remove": {"field": "drop_me"}},
				{"lowercase": {"field": "lo_arr"}},
				{"uppercase": {"field": "up_arr"}},
				{"trim": {"field": "trim_arr", "target_field": "trimmed_arr"}},
				{"split": {"field": "spl_arr", "separator": "{{spl_sep}}", "target_field": "split_out"}},
				{"join": {"field": "join_arr", "separator": "-"}},
				{"append": {"field": "app_single", "value": ["b", "c"]}},
				{"convert": {"field": "conv_arr", "type": "integer"}},
				{"gsub": {"field": "gsub_arr", "pattern": "\\d+", "replacement": "X", "target_field": "gsub_out"}},
				{"json": {"field": "json_str", "add_to_root": true, "add_to_root_conflict_strategy": "merge"}},
				{"json": {"field": "json_arr", "strict_json_parsing": true, "target_field": "json_arr_out"}},
				{"kv": {"field": "kv_str", "field_split": " ", "value_split": "=", "target_field": "kv_out", "prefix": "p_", "trim_key": "_", "trim_value": "\"", "transform_key": "lowercase", "strip_brackets": true, "include_keys": ["alpha", "beta"]}},
				{"kv": {"field": "kv_arr", "field_split": ";", "value_split": "::", "target_field": "kv_arr_out"}},
				{"dot_expander": {"field": "a.b", "path": "nested_map", "override": true}},
				{"dot_expander": {"field": "{{dyn_dot}}", "override": false}},
				{"urlencode": {"field": "url_raw"}},
				{"urldecode": {"field": "url_enc"}},
				{"bytes": {"field": "bytes_str"}},
				{"html_strip": {"field": "html_arr"}},
				{"date": {"field": "dt_arr", "formats": ["ISO8601"], "timezone": "{{tz}}", "locale": "en", "target_field": "dt_unix"}},
				{"date_index_name": {"field": "dt_single", "index_name_prefix": "{{idx_pref}}", "date_rounding": "w", "index_name_format": "yyyy-MM-dd", "timezone": "{{tz}}", "locale": "en"}},
				{"grok": {"field": "grok_msg", "patterns": ["^(?<level>\\w+) (?<num>\\d+)$"], "keep_empty_captures": false}},
				{"grok": {"field": "grok_arr", "patterns": ["(?<k1>\\w+)=(?<[deep][v]>\\d+:int)"]}},
				{"sort": {"field": "sort_arr"}},
				{"compact": {"field": "compact_map"}},
				{"dedup": {"field": "dedup_arr"}},
				{"fingerprint": {"fields": ["fp_a", "fp_b"], "method": "SHA-256", "salt": "s1", "target_field": "fp_hash"}},
				{"redact": {"field": "red_str", "patterns": ["%%{EMAILADDRESS:EMAIL}", "secret_[0-9]+"], "prefix": "[", "suffix": "]", "target_field": "red_out"}},
				{"redact": {"field": "red_arr", "patterns": ["\\d{4}"], "ignore_missing": true}},
				{"attachment": {"field": "att_plain", "target_field": "att1", "indexed_chars": 50, "properties": ["content", "content_length", "content_type", "language"]}},
				{"attachment": {"field": "att_latin", "target_field": "att2", "indexed_chars_field": "ic_len", "remove_binary": true}},
				{"csv": {"field": "csv_line", "target_fields": ["c1", "c2"]}},
				{"user_agent": {"field": "ua"}},
				{"uri_parts": {"field": "uri"}},
				{"registered_domain": {"field": "host", "target_field": "reg"}},
				{"network_direction": {"source_ip": "source.ip", "destination_ip": "destination.ip", "target_field": "net_dir", "internal_networks": ["10.0.0.0/8"]}},
				{"community_id": {"source_ip": "source.ip", "destination_ip": "destination.ip", "source_port": "source.port", "destination_port": "destination.port", "transport": "network.transport", "target_field": "cid"}},
				{"foreach": {"field": "fe_arr", "processor": {"uppercase": {"field": "_ingest._value"}}}},
				{"foreach": {"field": "fe_map", "processors": [{"set": {"field": "_ingest._value", "value": "seen_{{_ingest._key}}"}}]}},
				{"script": {"id": "r67_ing_script", "params": {"v": "ok"}}},
				{"script": {"lang": "painless", "source": "ctx._index = 'rerouted_idx'; ctx._id = 'new_doc_id'; ctx._routing = 'r1'; ctx._version = 2; ctx._if_seq_no = 5; ctx._if_primary_term = 1; ctx.inline_done = true;"}},
				{"inference": {"model_id": "m1", "target_field": "inf_res", "field_map": {"msg": "text_field"}}},
				{"set_security_user": {"field": "sec_user", "properties": ["username", "roles"]}},
				{"circle": {"field": "pt_circle", "shape_type": "geo_shape", "error_distance": 5.0}},
				{"geo_grid": {"field": "tile_in", "tile_type": "geotile", "target_field": "tile_out"}}
			]
		},
		"docs": [
			{
				"_index": "src_idx",
				"_id": "d1",
				"_source": {
					"sub_name": "sub_ok",
					"msg": "err",
					"raw_line": "hello world",
					"existing": "keep",
					"ren_src": "moved",
					"copy_src": "copied",
					"drop_me": "bye",
					"lo_arr": ["FOO", "BAR"],
					"up_arr": ["foo", "bar"],
					"trim_arr": [" hi "],
					"spl_sep": ",",
					"spl_arr": ["a,b", "c"],
					"join_arr": ["x", "y"],
					"app_single": "a",
					"conv_arr": ["1", "2"],
					"gsub_arr": ["id12", "id34"],
					"json_str": "{\"nested\":{\"k1\":1},\"top\":true}",
					"json_arr": ["{\"n\":1}"],
					"kv_str": "_alpha=\"[1]\" skip=2 _beta=\"v2\"",
					"kv_arr": ["k1::v1;k2::v2"],
					"nested_map": {"a.b": "expanded"},
					"dyn_dot": "x.y",
					"x.y": "top_dot",
					"url_raw": "a b+c",
					"url_enc": "a+b%%20c",
					"bytes_str": "2kb",
					"html_arr": ["<b>ok</b>"],
					"dt_arr": ["2024-06-05T12:00:00Z"],
					"dt_single": "2024-06-05T12:00:00Z",
					"tz": "UTC",
					"idx_pref": "logs-",
					"grok_msg": "INFO 42",
					"grok_arr": ["count=7"],
					"sort_arr": [3, 1, 2],
					"compact_map": {"k": "", "ok": "yes"},
					"dedup_arr": ["a", "a", "b"],
					"fp_a": "hello",
					"fp_b": "world",
					"red_str": "mail alice@example.com secret_123",
					"red_arr": ["pin 1234"],
					"att_plain": %q,
					"att_latin": %q,
					"ic_len": 20,
					"csv_line": "v1,v2",
					"ua": "Mozilla/5.0",
					"uri": "https://example.com/a?b=1",
					"host": "sub.example.co.uk",
					"source": {"ip": "10.0.0.1", "port": 1234},
					"destination": {"ip": "8.8.8.8", "port": 53},
					"network": {"transport": "udp"},
					"fe_arr": ["one", "two"],
					"fe_map": {"k1": "v1"},
					"pt_circle": "CIRCLE (10.0 20.0 100.0)",
					"tile_in": "3/1/2"
				}
			}
		]
	}`, plainB64, latinB64)
	simResp := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", simBody, http.StatusOK)
	if docs, _ := simResp["docs"].([]any); len(docs) != 1 {
		t.Fatalf("simulate expected 1 doc trace result, got %v", simResp)
	}

	// Simulate stored pipeline ID + pipeline on index write with default/final pipeline
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/sub_ok/_simulate?verbose=true",
		`{"docs":[{"_index":"i","_id":"1","_source":{"a":"b"}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ingest_w_idx",
		`{"settings":{"index":{"default_pipeline":"main_pipe","final_pipeline":"final_pipe"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ingest_w_idx/_doc/1?pipeline=sub_ok",
		`{"msg":"hi"}`, http.StatusCreated)
	_, _, _, _, _, _, metaOut, errPipe := srv.applyEffectiveAndFinalPipelinesWithMetaAndTypeR67(
		"ingest_w_idx", "_doc", "d2", "sub_ok", "main_pipe", "r0", json.RawMessage(`{"x":1}`))
	if errPipe != nil || len(metaOut) == 0 {
		t.Fatalf("applyEffectiveAndFinalPipelinesWithMetaAndTypeR67 err=%v meta=%v", errPipe, metaOut)
	}

	// 3. Direct executeSingleIngestProcessor edge/error branches not triggered in the happy simulation above
	var trace []map[string]any
	directCases := []struct {
		name    string
		doc     map[string]any
		proc    map[string]any
		depth   int
		wantErr bool
	}{
		{"empty_spec", map[string]any{"a": 1}, map[string]any{}, 0, false},
		{"if_false_no_trace", map[string]any{"a": 1}, map[string]any{"set": map[string]any{"field": "b", "value": 2, "if": "ctx.a == 999"}}, 0, false},
		{"pipeline_max_depth", map[string]any{}, map[string]any{"pipeline": map[string]any{"name": "sub_ok"}}, 17, true},
		{"fail_default_msg", map[string]any{}, map[string]any{"fail": map[string]any{"message": ""}}, 0, true},
		{"dissect_non_str_elem", map[string]any{"f": []any{123}}, map[string]any{"dissect": map[string]any{"field": "f", "pattern": "%{a}"}}, 0, true},
		{"rename_missing_err", map[string]any{}, map[string]any{"rename": map[string]any{"field": "no_such", "target_field": "dst"}}, 0, true},
		{"copy_same_field_err", map[string]any{"f": 1}, map[string]any{"copy": map[string]any{"field": "f", "target_field": "f"}}, 0, true},
		{"copy_missing_err", map[string]any{}, map[string]any{"copy": map[string]any{"field": "no_such", "target_field": "dst", "ignore_missing": false}}, 0, true},
		{"copy_scalar_anc", map[string]any{"f": "v", "s": "scalar"}, map[string]any{"copy": map[string]any{"field": "f", "target_field": "s.sub"}}, 0, true},
		{"remove_empty_err", map[string]any{}, map[string]any{"remove": map[string]any{}}, 0, true},
		{"remove_both_err", map[string]any{"a": 1}, map[string]any{"remove": map[string]any{"field": "a", "keep": "a"}}, 0, true},
		{"remove_missing_err", map[string]any{}, map[string]any{"remove": map[string]any{"field": "missing"}}, 0, true},
		{"lowercase_bad_elem", map[string]any{"a": []any{1}}, map[string]any{"lowercase": map[string]any{"field": "a"}}, 0, true},
		{"lowercase_bad_type", map[string]any{"a": 1}, map[string]any{"lowercase": map[string]any{"field": "a"}}, 0, true},
		{"uppercase_bad_elem", map[string]any{"a": []any{1}}, map[string]any{"uppercase": map[string]any{"field": "a"}}, 0, true},
		{"trim_bad_elem", map[string]any{"a": []any{1}}, map[string]any{"trim": map[string]any{"field": "a"}}, 0, true},
		{"trim_bad_type", map[string]any{"a": 1}, map[string]any{"trim": map[string]any{"field": "a"}}, 0, true},
		{"split_bad_regex", map[string]any{"a": "x"}, map[string]any{"split": map[string]any{"field": "a", "separator": "["}}, 0, true},
		{"split_bad_elem", map[string]any{"a": []any{1}}, map[string]any{"split": map[string]any{"field": "a", "separator": ","}}, 0, true},
		{"split_bad_type", map[string]any{"a": 1}, map[string]any{"split": map[string]any{"field": "a", "separator": ","}}, 0, true},
		{"gsub_bad_regex", map[string]any{"a": "x"}, map[string]any{"gsub": map[string]any{"field": "a", "pattern": "[", "replacement": ""}}, 0, true},
		{"json_dup_key_err", map[string]any{"j": `{"a":1,"a":2}`}, map[string]any{"json": map[string]any{"field": "j", "allow_duplicate_keys": false}}, 0, true},
		{"json_trailing_err", map[string]any{"j": `{"a":1} extra`}, map[string]any{"json": map[string]any{"field": "j", "strict_json_parsing": true}}, 0, true},
		{"json_root_non_obj", map[string]any{"j": `[1,2]`}, map[string]any{"json": map[string]any{"field": "j", "add_to_root": true}}, 0, true},
		{"json_root_arr", map[string]any{"j": []any{`{"a":1}`}}, map[string]any{"json": map[string]any{"field": "j", "add_to_root": true}}, 0, true},
		{"kv_bad_val_split", map[string]any{"k": "a=b"}, map[string]any{"kv": map[string]any{"field": "k", "field_split": " ", "value_split": "["}}, 0, true},
		{"kv_non_str_elem", map[string]any{"k": []any{1}}, map[string]any{"kv": map[string]any{"field": "k", "field_split": " ", "value_split": "="}}, 0, true},
		{"dot_exp_non_map_path", map[string]any{"p": "not_map"}, map[string]any{"dot_expander": map[string]any{"field": "a.b", "path": "p"}}, 0, false},
		{"html_strip_bad_elem", map[string]any{"h": []any{1}}, map[string]any{"html_strip": map[string]any{"field": "h"}}, 0, true},
		{"date_unix_formats", map[string]any{"d": "2024-06-05T12:00:00Z"}, map[string]any{"date": map[string]any{"field": "d", "formats": []any{"ISO8601"}, "output_format": "UNIX"}}, 0, false},
		{"date_unix_ms", map[string]any{"d": "2024-06-05T12:00:00Z"}, map[string]any{"date": map[string]any{"field": "d", "formats": []any{"ISO8601"}, "output_format": "UNIX_MS"}}, 0, false},
		{"grok_nomatch_err", map[string]any{"m": "zzz"}, map[string]any{"grok": map[string]any{"field": "m", "patterns": []any{"%{INT:n}"}}}, 0, true},
		{"sort_non_arr_err", map[string]any{"s": "str"}, map[string]any{"sort": map[string]any{"field": "s"}}, 0, true},
		{"compact_scalar_err", map[string]any{"c": 42}, map[string]any{"compact": map[string]any{"field": "c"}}, 0, true},
		{"dedup_non_arr_err", map[string]any{"d": "str"}, map[string]any{"dedup": map[string]any{"field": "d"}}, 0, true},
		{"redact_missing_err", map[string]any{}, map[string]any{"redact": map[string]any{"field": "m", "patterns": []any{"\\d+"}}}, 0, true},
		{"attachment_bad_b64", map[string]any{"a": "!!!invalid!!!"}, map[string]any{"attachment": map[string]any{"field": "a"}}, 0, true},
		{"foreach_drop", map[string]any{"items": []any{"bad"}}, map[string]any{"foreach": map[string]any{"field": "items", "processor": map[string]any{"drop": map[string]any{}}}}, 0, false},
		{"foreach_suberr", map[string]any{"items": []any{"ok", 1}}, map[string]any{"foreach": map[string]any{"field": "items", "processor": map[string]any{"uppercase": map[string]any{"field": "_ingest._value"}}}}, 0, true},
		{"foreach_map_drop", map[string]any{"mp": map[string]any{"k": "v"}}, map[string]any{"foreach": map[string]any{"field": "mp", "processor": map[string]any{"drop": map[string]any{}}}}, 0, false},
		{"inference_missing_id", map[string]any{"t": "hi"}, map[string]any{"inference": map[string]any{}}, 0, true},
		{"inference_ignore_missing", map[string]any{}, map[string]any{"inference": map[string]any{"model_id": "m1", "field_map": map[string]any{"missing": "x"}, "ignore_missing": true}}, 0, false},
		{"secuser_missing_field", map[string]any{}, map[string]any{"set_security_user": map[string]any{}}, 0, true},
		{"circle_bad_radius", map[string]any{"g": map[string]any{"type": "circle", "coordinates": []any{0.0, 0.0}, "radius": -5}}, map[string]any{"circle": map[string]any{"field": "g", "shape_type": "geo_shape"}}, 0, true},
		{"community_id_icmp", map[string]any{"sip": "192.0.2.1", "dip": "192.0.2.2", "sport": 8, "dport": 0, "proto": "icmp"}, map[string]any{"community_id": map[string]any{"source_ip": "sip", "destination_ip": "dip", "source_port": "sport", "destination_port": "dport", "transport": "proto"}}, 0, false},
		{"community_id_icmpv6", map[string]any{"sip": "2001:db8::1", "dip": "2001:db8::2", "sport": 128, "dport": 0, "proto": "ipv6-icmp"}, map[string]any{"community_id": map[string]any{"source_ip": "sip", "destination_ip": "dip", "source_port": "sport", "destination_port": "dport", "transport": "proto"}}, 0, false},
		{"unknown_proc_err", map[string]any{}, map[string]any{"not_a_processor": map[string]any{}}, 0, true},
	}
	for _, tc := range directCases {
		trPtr := &trace
		if tc.name == "if_false_no_trace" {
			trPtr = nil
		}
		_, _, _, _, _, err := executeSingleIngestProcessor(srv, tc.doc, tc.proc, tc.depth, trPtr)
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}

	// Clean delete pipelines
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/sub_ok", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/nonexistent", "", http.StatusNotFound)
}

func TestRound67Cov_Features_EnrichReindexRolloverCloneExplainTermsEnum(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)

	// 1. Enrich API + executeEnrichProcessor (match, range, geo_match)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/enrich_src", `{
		"mappings":{"properties":{
			"k":{"type":"keyword"},
			"rng":{"type":"integer_range"},
			"area":{"type":"geo_shape"},
			"extra":{"type":"keyword"}
		}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/enrich_src/_doc/1",
		`{"k":["u1","u2"],"rng":{"gte":10,"lte":20},"area":{"type":"envelope","coordinates":[[0,10],[10,0]]},"extra":"vip"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/enrich_src/_refresh", "", http.StatusOK)

	// Validation error paths
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_pol", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_pol2", `{"match":{"indices":"enrich_src","match_field":"k"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_multi",
		`{"match":{"indices":"enrich_src","match_field":"k","enrich_fields":["extra"]},"range":{"indices":"enrich_src","match_field":"rng","enrich_fields":["extra"]}}`, http.StatusBadRequest)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_match",
		`{"match":{"indices":["enrich_src"],"match_field":"k","enrich_fields":["extra"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_range",
		`{"range":{"indices":"enrich_src","match_field":"rng","enrich_fields":["extra"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_geo",
		`{"geo_match":{"indices":"enrich_src","match_field":"area","enrich_fields":["extra"]}}`, http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_enrich/policy/pol_match", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_enrich/policy/no_pol", "", http.StatusNotFound)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_enrich/policy/pol_*", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_enrich/policy/no_pol", "", http.StatusNotFound)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_enrich/policy", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_enrich/policy/pol_match/_execute?wait_for_completion=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_enrich/policy/pol_range/_execute?wait_for_completion=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_enrich/policy/pol_geo/_execute?wait_for_completion=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_enrich/_stats", "", http.StatusOK)

	for _, ep := range []struct {
		doc  map[string]any
		spec map[string]any
		err  bool
	}{
		{map[string]any{"who": "u1"}, map[string]any{"policy_name": "pol_match", "field": "who", "target_field": "enriched", "max_matches": 5}, false},
		{map[string]any{"score": 15}, map[string]any{"policy_name": "pol_range", "field": "score", "target_field": "enriched_rng"}, false},
		{map[string]any{"loc": map[string]any{"lat": 5.0, "lon": 5.0}}, map[string]any{"policy_name": "pol_geo", "field": "loc", "target_field": "enriched_geo"}, false},
		{map[string]any{"who": "u1", "enriched": "keep"}, map[string]any{"policy_name": "pol_match", "field": "who", "target_field": "enriched", "override": false}, false},
		{map[string]any{}, map[string]any{"policy_name": "pol_match", "field": "missing", "target_field": "out", "ignore_missing": false}, true},
		{map[string]any{"who": "u1"}, map[string]any{"policy_name": "pol_match", "field": "who", "target_field": "out", "max_matches": 999}, true},
		{map[string]any{"who": "u1"}, map[string]any{"policy_name": "unknown_pol", "field": "who", "target_field": "out"}, false},
	} {
		_, err := executeEnrichProcessor(srv, ep.doc, ep.spec)
		if ep.err && err == nil {
			t.Errorf("executeEnrichProcessor expected err for %v", ep.spec)
		}
		if !ep.err && err != nil {
			t.Errorf("executeEnrichProcessor unexpected err for %v: %v", ep.spec, err)
		}
	}
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_enrich/policy/pol_geo", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_enrich/policy/no_pol", "", http.StatusNotFound)

	// 2. Reindex (`POST /_reindex`)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/reidx_src", `{"mappings":{"properties":{"title":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"num":{"type":"integer"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/reidx_src/_doc/1", `{"title":"alpha","num":1}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/reidx_src/_doc/2", `{"title":"beta","num":2}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/reidx_src/_doc/3", `{"title":"gamma","num":3}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/reidx_src/_refresh", "", http.StatusOK)

	// Error cases
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_reindex", "", http.StatusMethodNotAllowed)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex",
		`{"conflicts":"bad","source":{"index":"reidx_src"},"dest":{"index":"reidx_dst"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst","op_type":"bad"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst","version_type":"bad"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst","routing":"bad_mode"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex?max_docs=1&slices=3",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst"}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst"},"script":{"id":"missing_script"}}`, http.StatusNotFound)

	// Real reindex with script, conflicts=proceed, slices, sort, max_docs
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex?conflicts=proceed&slices=2&max_docs=2",
		`{"source":{"index":["reidx_src"],"_source":{"includes":["title","num"]},"sort":[{"num":"asc"}]},"dest":{"index":"reidx_dst","version_type":"external"},"script":{"lang":"painless","source":"if (ctx._source.num == 2) { ctx.op = 'noop'; } ctx._source.copied = true;"}}`, http.StatusOK)
	// Async reindex
	asyncReidx := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_reindex?wait_for_completion=false",
		`{"source":{"index":"reidx_src"},"dest":{"index":"reidx_dst_async"}}`, http.StatusOK)
	if _, ok := asyncReidx["task"].(string); !ok {
		t.Fatalf("expected task string from async reindex, got %v", asyncReidx)
	}

	// 3. Rollover (`POST /{alias}/_rollover`)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/roll_idx-000001", `{
		"aliases":{"roll_alias":{"is_write_index":true}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/roll_idx-000001/_doc/1", `{"msg":"r1"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/roll_idx-000001/_refresh", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/roll_alias/_rollover?dry_run=true",
		`{"conditions":{"max_docs":1}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/roll_alias/_rollover",
		`{"conditions":{"max_docs":9999}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/roll_alias/_rollover",
		`{"conditions":{"max_docs":1},"settings":{"index":{"number_of_shards":1}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/roll_alias/_rollover/roll_idx-custom",
		`{"conditions":{"max_age":"1ms"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/missing_roll_alias/_rollover", `{}`, http.StatusNotFound)

	// 4. Resize / Clone / Shrink / Split (`/{index}/_clone|_shrink|_split/{target}`)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/resize_src",
		`{"settings":{"index":{"number_of_shards":2,"blocks":{"write":true}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/resize_src/_clone/resize_cloned", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/resize_src/_shrink/resize_shrunk",
		`{"settings":{"index":{"number_of_shards":1}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/split_src",
		`{"settings":{"index":{"number_of_shards":1,"number_of_routing_shards":4,"blocks":{"write":true}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/split_src/_split/split_dst",
		`{"settings":{"index":{"number_of_shards":2}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/resize_src/_clone/resize_cloned", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/resize_src/_clone/bad", "", http.StatusMethodNotAllowed)

	// 5. Explain Doc & Terms Enum
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/expl_idx", `{"mappings":{"properties":{"title":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"tag":{"type":"keyword"},"val":{"type":"double"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/expl_idx/_doc/1", `{"title":"Hello World","tag":"AlphaTerm","val":10}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_refresh", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_explain/1",
		`{"query":{"function_score":{"query":{"match":{"title":"hello"}},"functions":[{"weight":2}]}},"post_filter":{"term":{"tag":"AlphaTerm"}},"min_score":0.1}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/expl_idx/_doc/missing/_explain", `{"query":{"match_all":{}}}`, http.StatusNotFound)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_explain/1", `{"bad_key":{}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/expl_idx/_explain/1", "", http.StatusMethodNotAllowed)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_terms_enum",
		`{"field":"tag","string":"alpha","case_insensitive":true,"size":10,"search_after":"A","timeout":"5s"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/expl_idx/_terms_enum", `{"field":"_version"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_terms_enum", `{"field":"tag","timeout":"5m"}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_terms_enum", `{"field":"tag","size":0}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_terms_enum", `{"field":"tag","unknown_k":1}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/expl_idx/_terms_enum", "", http.StatusMethodNotAllowed)

	// 6. Resolve Index / Resolve Cluster / Validate Query / Search Shards / Upgrade / Cat / Doris Promote
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_cluster/settings",
		`{"persistent":{"cluster.remote.rem1.seeds":["127.0.0.1:9300"],"cluster.remote.rem1.skip_unavailable":true}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_resolve/cluster/rem*,missing_cluster", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_resolve/cluster", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_resolve/cluster", "", http.StatusMethodNotAllowed)

	reqResIdx := httptest.NewRequest(http.MethodGet, "/_resolve/index/expl*,reidx*", nil)
	reqResIdx.SetPathValue("index", "expl*,reidx*")
	recResIdx := httptest.NewRecorder()
	srv.handleResolveIndex(recResIdx, reqResIdx)
	if recResIdx.Code != http.StatusOK {
		t.Fatalf("handleResolveIndex status=%d body=%s", recResIdx.Code, recResIdx.Body.String())
	}

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_validate/query?explain=true&rewrite=true",
		`{"query":{"term":{"tag":"AlphaTerm"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_validate/query?explain=true",
		`{"bad_top":1}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/expl_idx/_validate/query?explain=not_bool", "", http.StatusBadRequest)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_aliases",
		`{"actions":[{"add":{"index":"expl_idx","alias":"expl_filtered_alias","filter":{"term":{"tag":"AlphaTerm"}}}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/expl_filtered_alias/_search_shards", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_upgrade", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_upgrade?human=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/expl_idx/_upgrade", "", http.StatusOK)
	srv.SetTargetESVersion("8.15.0")
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_upgrade", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_upgrade", "", http.StatusBadRequest,
		[2]string{"Accept", "application/vnd.elasticsearch+json; compatible-with=7"})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_upgrade", "", http.StatusBadRequest,
		[2]string{"Accept", "application/vnd.elasticsearch+json; compatible-with=7"})

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/shards?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/count?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/health?v", "", http.StatusOK)
	doR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_doris/promote", `{"field":"extra_f","type":"keyword"}`)
	doR67CovFeatHTTP(t, srv, http.MethodPost, "/expl_idx/_doris/promote", `{"bad":true}`)
}

func TestRound67Cov_Features_SecurityAuthRBACAndYAMLWire(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)

	// 1. base64EncodeStr + PBKDF2 helpers
	if got := base64EncodeStr("foo"); got != "Zm9v" {
		t.Fatalf("base64EncodeStr(foo)=%q", got)
	}
	if got := base64EncodeStr(""); got != "" {
		t.Fatalf("base64EncodeStr empty=%q", got)
	}
	if got := base64EncodeStr("f"); got != "Zg==" {
		t.Fatalf("base64EncodeStr(f)=%q", got)
	}
	if got := base64EncodeStr("fo"); got != "Zm8=" {
		t.Fatalf("base64EncodeStr(fo)=%q", got)
	}
	salt := []byte("testsalt12345678")
	dk := pbkdf2HMACSHA256R67([]byte("s3cr3t"), salt, 100, 32)
	encodedPBKDF2 := fmt.Sprintf("$pbkdf2-sha256$100$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk))
	if !verifyPBKDF2SHA256R67(encodedPBKDF2, "s3cr3t") || verifyPBKDF2SHA256R67(encodedPBKDF2, "wrong") {
		t.Fatalf("verifyPBKDF2SHA256R67 check failed")
	}
	if _, ok := decodePBKDF2SegmentR67("!!!bad"); ok {
		t.Fatalf("expected invalid pbkdf2 segment failure")
	}
	if !verifyStoredSecretR67(map[string]any{"password_hash": encodedPBKDF2}, "password_hash", "", []string{"password"}, "s3cr3t") {
		t.Fatalf("verifyStoredSecretR67 failed")
	}

	// 2. Wire YAML & filter_path & OpenSearch/ES compat media-type headers
	var yamlBuf strings.Builder
	writeYAMLValueWireR64(&yamlBuf, map[string]any{
		"name":   "es:test",
		"empty":  []any{},
		"nested": map[string]any{},
		"arr":    []any{"a", map[string]any{"k": "v"}},
		"flag":   true,
	}, 0, false)
	if !strings.Contains(yamlBuf.String(), "name:") {
		t.Fatalf("writeYAMLValueWireR64 empty output")
	}
	pats := [][]string{{"a", "b"}, {"c", "*"}}
	nextPats := advanceFilterPatterns(pats, "a")
	if len(nextPats) == 0 {
		t.Fatalf("advanceFilterPatterns expected match")
	}
	filtered, kept := filterIncludeNode(map[string]any{"a": map[string]any{"b": 1, "skip": 2}, "c": map[string]any{"d": 3}}, pats)
	if !kept || filtered == nil {
		t.Fatalf("filterIncludeNode expected match")
	}
	recYAML := doR67CovFeatHTTP(t, srv, http.MethodGet, "/?format=yaml&filter_path=cluster_name,version.number", "",
		[2]string{"Accept", "application/vnd.elasticsearch+json; compatible-with=8"})
	if recYAML.Code != http.StatusOK {
		t.Fatalf("YAML root status=%d body=%s", recYAML.Code, recYAML.Body.String())
	}
	recOS := doR67CovFeatHTTP(t, srv, http.MethodGet, "/", "",
		[2]string{"Accept", "application/vnd.opensearch+json; compatible-with=2"})
	if recOS.Code != http.StatusOK {
		t.Fatalf("OpenSearch compat status=%d", recOS.Code)
	}

	// 3. Seed index + docs before enabling auth for RBAC / DLS / FLS testing
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/sec_idx",
		`{"mappings":{"properties":{"tenant":{"type":"keyword"},"public_msg":{"type":"text"},"secret_col":{"type":"text"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/sec_idx/_doc/1", `{"tenant":"t1","public_msg":"hello t1","secret_col":"hidden1"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/sec_idx/_doc/2", `{"tenant":"t2","public_msg":"hello t2","secret_col":"hidden2"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/sec_idx/_refresh", "", http.StatusOK)

	// 4. Security API CRUD before enabling static inbound auth
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/role/dls_fls_role", `{
		"cluster":["monitor","read_slm"],
		"indices":[{
			"names":["sec_*"],
			"privileges":["read","view_index_metadata"],
			"field_security":{"grant":["*"],"except":["secret_col"]},
			"query":{"term":{"tenant":"t1"}}
		}]
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/role",
		`{"r_bulk":{"cluster":["all"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/role/dls_fls_role", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/role", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/role/dls_fls_role/_clear_cache", "", http.StatusOK)

	// Enable static admin auth before creating native dynamic users
	srv.SetAuth("elastic", "adminpass", "static-key-123")
	adminBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:adminpass"))

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/alice",
		`{"password":"alicePass1!","roles":["dls_fls_role"],"full_name":"Alice","email":"alice@example.com"}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/bob",
		`{"password":"bobPass1!","roles":["r_bulk"],"enabled":false}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/alice/_disable", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/alice/_enable", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/alice/_password", `{"password":"alicePass2!"}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/user/alice/_clear_cache", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/user/_has_privileges",
		`{"cluster":["monitor"],"index":[{"names":["sec_idx"],"privileges":["read"]}]}`, http.StatusOK, [2]string{"Authorization", adminBasic})

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/privilege/app1",
		`{"app1":{"read":{"actions":["data:read/*"],"metadata":{"k":"v"}}}}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/privilege/_builtin", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/privilege/app1", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/role_mapping/rm1",
		`{"roles":["dls_fls_role"],"enabled":true,"rules":{"field":{"username":"alice"}}}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/role_mapping", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/service", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/svc_tok1", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/enroll/kibana", `{}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/enroll/node", `{}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/realm/native/_clear_cache", "", http.StatusOK, [2]string{"Authorization", adminBasic})

	aliceBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alicePass2!"))

	// Unauthenticated blocked
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusUnauthorized)
	// Static admin authenticates
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusOK, [2]string{"Authorization", "ApiKey static-key-123"})

	// Dynamic user Alice authenticates, gets DLS+FLS on search, self-allowed paths work, disallowed endpoint 403
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusOK, [2]string{"Authorization", aliceBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/user/_has_privileges", `{"cluster":["monitor"]}`, http.StatusOK, [2]string{"Authorization", aliceBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/user/_privileges", "", http.StatusOK, [2]string{"Authorization", aliceBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_security/user/alice/_password", `{"password":"alicePass3!"}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	aliceBasic3 := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alicePass3!"))
	searchRes := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/sec_idx/_search", `{"query":{"match_all":{}}}`, http.StatusOK, [2]string{"Authorization", aliceBasic3})
	if hitsMap, ok := searchRes["hits"].(map[string]any); ok {
		if arr, okArr := hitsMap["hits"].([]any); okArr && len(arr) != 1 {
			t.Fatalf("expected 1 DLS-filtered hit, got %d (%v)", len(arr), arr)
		}
	}
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/role/forbidden_role", `{}`, http.StatusForbidden, [2]string{"Authorization", aliceBasic3})
	// run_as disabled user -> 401
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusUnauthorized,
		[2]string{"Authorization", adminBasic}, [2]string{"es-security-runas-user", "bob"})

	// OAuth2 token exchange + API key creation & grant + cleanup
	tokRes := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/oauth2/token",
		`{"grant_type":"password","username":"alice","password":"alicePass3!"}`, http.StatusOK)
	accessTok, _ := tokRes["access_token"].(string)
	refreshTok, _ := tokRes["refresh_token"].(string)
	if accessTok != "" {
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusOK,
			[2]string{"Authorization", "Bearer static-key-123"})
		mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/oauth2/token",
			fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":%q}`, refreshTok), http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/oauth2/token",
			fmt.Sprintf(`{"token":%q}`, accessTok), http.StatusOK, [2]string{"Authorization", adminBasic})
	}
	apiRes := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/api_key",
		`{"name":"k1","role_descriptors":{"d1":{"indices":[{"names":["sec_*"],"privileges":["read"]}]}}}`, http.StatusOK,
		[2]string{"Authorization", adminBasic})
	if encKey, ok := apiRes["encoded"].(string); ok && encKey != "" {
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/_authenticate", "", http.StatusOK,
			[2]string{"Authorization", "ApiKey " + encKey})
	}
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/api_key/grant",
		`{"grant_type":"password","username":"alice","password":"alicePass3!","api_key":{"name":"granted_k"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_security/api_key", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	if apiID, _ := apiRes["id"].(string); apiID != "" {
		mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_security/api_key/"+apiID+"/_clear_cache", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	}
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/api_key", `{"name":"k1"}`, http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/service/elastic/fleet-server/credential/token/svc_tok1", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/role_mapping/rm1", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/privilege/app1/read", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/user/alice", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/role/dls_fls_role", "", http.StatusOK, [2]string{"Authorization", adminBasic})
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_security/role", `{"names":["r_bulk"]}`, http.StatusOK, [2]string{"Authorization", adminBasic})
}

func TestRound67Cov_Features_SnapshotTransformRollupQueryRulesSynonymsSLMWatcherCCR(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)
	repoDir := t.TempDir()
	srv.SetStaticPathRepo([]string{repoDir})
	srv.SetStaticRepositoriesURLAllowedURLs([]string{"https://example.com/*"})

	// Seed indices for snapshot/transform/rollup/query rules
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/feat_idx", `{
		"mappings":{"properties":{"cat":{"type":"keyword"},"title":{"type":"text"},"amount":{"type":"double"},"ts":{"type":"date"}}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/feat_idx/_doc/1", `{"cat":"books","title":"shoes running","amount":12.5,"ts":"2025-01-01T00:00:00Z"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/feat_idx/_doc/2", `{"cat":"books","title":"boots hiking","amount":25.0,"ts":"2025-01-02T00:00:00Z"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/feat_idx/_refresh", "", http.StatusOK)

	// 1. Snapshot repo + snapshot + restore + mount + cleanup
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_snapshot/repo_fs",
		fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, repoDir), http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_snapshot/repo_url",
		`{"type":"url","settings":{"url":"https://example.com/snaps"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_snapshot/repo_fs", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_snapshot/_all", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_snapshot/repo_fs/_verify", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_snapshot/_status", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_snapshot/repo_url/snap_ro", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_snapshot/repo_fs/snap1?wait_for_completion=true",
		`{"indices":"feat_idx","include_global_state":true,"partial":true}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_snapshot/repo_fs/snap*", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_snapshot/repo_fs/snap1/_status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_snapshot/repo_fs/_cleanup", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_snapshot/repo_fs/snap1/_mount?wait_for_completion=true",
		`{"index":"feat_idx","renamed_index":"feat_mounted"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_snapshot/repo_fs/snap1/_restore?wait_for_completion=true",
		`{"indices":"feat_idx","rename_pattern":"(.+)","rename_replacement":"restored_$1","include_global_state":false}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_snapshot/repo_fs/snap1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_snapshot/repo_url", "", http.StatusOK)

	// 2. SLM policies & actions (repo_fs still present)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_slm/policy/slm1",
		`{"schedule":"0 30 1 * * ?","name":"<daily-{now/d}>","repository":"repo_fs","config":{"indices":["feat_idx"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_slm/policy/slm1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_slm/policy/slm1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_slm/policy/slm1/_execute", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_slm/stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_slm/status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_slm/stop", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_slm/start", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_slm/policy/slm1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_snapshot/repo_fs", "", http.StatusOK)

	// 3. Watcher
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_watcher/watch/w1", `{
		"trigger":{"schedule":{"interval":"10m"}},
		"input":{"search":{"request":{"indices":["feat_idx"],"body":{"query":{"match_all":{}}}}}},
		"condition":{"compare":{"ctx.payload.hits.total":{"gt":0}}},
		"actions":{"log_it":{"logging":{"text":"found"}}}
	}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_watcher/watch/w1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/watch/w1/_execute", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_watcher/watch/w1/_ack/log_it", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/watch/w1/_deactivate", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/watch/w1/_activate", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/_query/watches", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_watcher/stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_watcher/settings", `{"watcher.history.cleaner_service.enabled":true}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/_stop", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_watcher/_start", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_watcher/watch/w1", "", http.StatusOK)

	// 4. Transform + validation
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_transform/bad_tf", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/_preview", `{
		"source":{"index":["feat_idx"]},
		"pivot":{"group_by":{"cat":{"terms":{"field":"cat"}}},"aggregations":{"total_amt":{"sum":{"field":"amount"}}}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_transform/tf1", `{
		"source":{"index":"feat_idx"},
		"dest":{"index":"feat_tf_out"},
		"sync":{"time":{"field":"ts","delay":"10s"}},
		"frequency":"1m",
		"pivot":{"group_by":{"cat":{"terms":{"field":"cat"}}},"aggregations":{"total_amt":{"sum":{"field":"amount"}}}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/tf1/_update", `{"description":"updated tf"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/tf1/_update", `{"pivot":{}}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/tf1/_start", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_transform/tf1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_transform/tf1/_stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_transform/_node_stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/tf1/_stop", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/tf1/_reset", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_transform/_upgrade", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_transform/tf1?force=true", "", http.StatusOK)

	// 5. Rollup + RollupSearch + TypedKeys helper
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_rollup/job/rj1", `{
		"index_pattern":"feat_idx",
		"rollup_index":"feat_rollup",
		"cron":"0 * * * * ?",
		"page_size":100,
		"groups":{"terms":{"fields":["cat"]}},
		"metrics":[{"field":"amount","metrics":["sum","avg"]}]
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_rollup/job/rj1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_rollup/job/rj1/_start", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_rollup/data/rj1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/feat_idx/_rollup_search?typed_keys=true&rest_total_hits_as_int=true",
		`{"size":0,"aggs":{"by_cat":{"terms":{"field":"cat"}}}}`, http.StatusOK)
	tkOut := applyTypedKeysToRollupAggsR65(map[string]any{"by_cat": map[string]any{"buckets": []any{}}},
		map[string]esast.AggSpec{"by_cat": {Terms: &esast.TermsAggSpec{Field: "cat"}}})
	if _, ok := tkOut["terms#by_cat"]; !ok {
		t.Fatalf("applyTypedKeysToRollupAggsR65 expected terms#by_cat key, got %v", tkOut)
	}
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_rollup/job/rj1/_stop", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_rollup/job/rj1", "", http.StatusOK)

	// 6. Query Rules + Synonyms + CCR
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_query_rules/rs1", `{
		"rules":[
			{"rule_id":"r1","type":"pinned","criteria":[{"type":"contains","metadata":"q","values":["shoes"]},{"type":"fuzzy","metadata":"q","values":["shos"]},{"type":"gt","metadata":"price","values":[5]}],"actions":{"ids":["1"]}},
			{"rule_id":"r2","type":"exclude","criteria":[{"type":"exact","metadata":"q","values":["bad"]}],"actions":{"ids":["2"]}}
		]
	}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_query_rules", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_query_rules/rs1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_query_rules/rs1/_rule/r3",
		`{"rule_id":"r3","type":"pinned","criteria":[{"type":"prefix","metadata":"q","values":["run"]},{"type":"lte","metadata":"price","values":[100]}],"actions":{"docs":[{"_index":"feat_idx","_id":"1"}]}}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_query_rules/rs1/_rule/r3", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_query_rules/rs1/_test", `{"match_criteria":{"q":"running shoes","price":10}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/feat_idx/_search",
		`{"query":{"rule":{"match_criteria":{"q":"shoes","price":10},"ruleset_ids":["rs1"],"organic":{"match":{"title":"shoes"}}}}}`, http.StatusOK)
	if queryRuleLevenshtein("shoes", "shos") != 1 {
		t.Fatalf("unexpected levenshtein")
	}
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_query_rules/rs1/_rule/r3", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_query_rules/rs1", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_synonyms/syn1",
		`{"synonyms_set":[{"id":"s1","synonyms":"running, jogging"},{"id":"s2","synonyms":"fast => quick"}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_synonyms?size=1&from=0", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_synonyms/syn1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_synonyms/syn1/s3", `{"synonyms":"walk, stroll"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_synonyms/syn1/_reload", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_synonyms/syn1/s3", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_synonyms/syn1", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ccr_follow/_ccr/follow",
		`{"remote_cluster":"rem1","leader_index":"feat_idx"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/ccr_follow/_ccr/info", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/ccr_follow/_ccr/stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ccr/stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ccr_follow/_ccr/pause_follow", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ccr_follow/_ccr/resume_follow", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ccr_follow/_ccr/unfollow", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ccr_follow/_ccr/forget_follower",
		`{"follower_cluster":"local","follower_index":"ccr_follow","follower_index_uuid":"u1","leader_remote_cluster":"rem1"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ccr/auto_follow/af1",
		`{"remote_cluster":"rem1","leader_index_patterns":["feat_*"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ccr/auto_follow/af1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ccr/auto_follow/af1/_pause", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ccr/auto_follow/af1/_resume", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ccr/auto_follow/af1", "", http.StatusOK)
}

func TestRound67Cov_Features_MLConnectorsAppsTextProfilingLicenseAutoscaling(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ml_src", `{"mappings":{"properties":{"entity":{"type":"keyword"},"ip":{"type":"ip"},"msg":{"type":"text"},"val":{"type":"double"},"ts":{"type":"date"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ml_src/_doc/1", `{"entity":"n1","ip":"10.1.1.1","msg":"hello ml graph","val":10,"ts":"2025-01-01T00:00:00Z"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ml_src/_doc/2", `{"entity":"n1","ip":"10.1.1.1","msg":"hello ml two","val":20,"ts":"2025-01-01T01:00:00Z"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/ml_src/_doc/3", `{"entity":"n1","ip":"10.1.1.1","msg":"hello ml three","val":30,"ts":"2025-01-01T02:00:00Z"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ml_src/_refresh", "", http.StatusOK)

	// 1. ML API: Anomaly Detectors, Datafeeds, Trained Models, Calendars, Filters, Cat ML, DFA
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/info", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/set_upgrade_mode?enabled=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/set_upgrade_mode?enabled=false", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/anomaly_detectors/job1",
		`{"analysis_config":{"bucket_span":"1h","detectors":[{"function":"mean","field_name":"val"}]},"data_description":{"time_field":"ts"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_ml/anomaly_detectors/job1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_open", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_flush", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_update", `{"description":"upd"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/_stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/results/buckets", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/results/records", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/results/influencers", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/results/categories", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/model_snapshots", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_close", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/datafeeds/df1",
		`{"job_id":"job1","indices":["ml_src"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/df1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_start", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/df1/_stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/df1/_preview", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_update", `{"chunking_config":{"mode":"auto"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_stop", `{}`, http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1",
		`{"input":{"field_names":["msg"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1/model_aliases/tm_alias", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/trained_models/tm_alias", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_start", `{"number_of_allocations":1}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/trained_models/tm1/_stats", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/_infer", `{"docs":[{"msg":"predict me"}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/trained_models/tm1", "", http.StatusConflict)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/trained_models/tm1?force=true", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/calendars/cal1", `{"description":"maint"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/calendars/cal1/jobs/job1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/calendars/cal1/events",
		`{"events":[{"description":"window","start_time":"2025-01-01T00:00:00Z","end_time":"2025-01-01T01:00:00Z","event_id":"ev1"}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/calendars/cal1/events", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/calendars/cal1/events/ev1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/calendars/cal1/jobs/job1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/calendars/cal1", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_ml/filters/flt1", `{"items":["a"],"description":"safe"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/filters/flt1/_update", `{"add_items":["b"],"remove_items":["a"],"description":"upd"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ml/filters/flt1", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/ml/anomaly_detectors?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/ml/datafeeds?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/ml/trained_models?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/ml/jobs?v", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/_delete_expired_data", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/filters/flt1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/calendars/cal1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/datafeeds/df1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/job1", "", http.StatusOK)

	// 2. Inference endpoints
	for _, tc := range []struct {
		id, task, body string
	}{
		{"inf_dense", "text_embedding", `{"input":["hello world","second line"]}`},
		{"inf_sparse", "sparse_embedding", `{"input":"sparse query"}`},
		{"inf_rerank", "rerank", `{"query":"hello","input":["no match","hello world"]}`},
		{"inf_comp", "completion", `{"input":"prompt"}`},
	} {
		mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_inference/"+tc.task+"/"+tc.id,
			`{"service":"elasticsearch","service_settings":{"num_threads":1},"task_settings":{}}`, http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_inference/"+tc.task+"/"+tc.id, "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_inference/"+tc.task+"/"+tc.id, "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_inference/"+tc.task+"/"+tc.id, tc.body, http.StatusOK)
	}
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_inference/chunking/inf_dense", `{"input":"part one. part two"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_inference/bad_type/x1", `{"service":"s"}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_inference/text_embedding/inf_dense", "", http.StatusOK)

	// 3. Connectors + Secret + Sync Job
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/_secret/sec1", `{"value":"top_secret"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_connector/_secret/sec1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_connector/_secret/sec1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1", `{"name":"conn1","index_name":"ml_src","service_type":"github"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_connector/c1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_connector/c1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1/_name", `{"name":"conn1_renamed","description":"d"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1/_scheduling", `{"scheduling":{"enabled":true}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1/_configuration", `{"configuration":{"org":"azra"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1/_error", `{"error":"warn"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_connector/c1/_last_sync", `{"indexed_document_count":3}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_connector/c1/_check_in", `{}`, http.StatusOK)
	sj := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_connector/_sync_job", `{"connector_id":"c1","job_type":"full"}`, http.StatusCreated)
	if sjID, ok := sj["id"].(string); ok && sjID != "" {
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_connector/_sync_job/"+sjID, "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_connector/_sync_job/"+sjID+"/_cancel", "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_connector/_sync_job/"+sjID, "", http.StatusOK)
	}
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_connector/c1", "", http.StatusOK)

	// 4. Search Applications, Text Structure, Profiling, Autoscaling, License, XPack, Async Search, Health Report, SQL, Graph Explore, Nodes Shutdown
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_application/search_application/app1",
		`{"indices":["ml_src"],"template":{"script":{"source":"{\"query\":{\"match\":{\"msg\":\"{{q}}\"}}}"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_application/search_application/app1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_application/search_application/app1/_render_query", `{"params":{"q":"hello"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_application/search_application/app1/_search", `{"params":{"q":"hello"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_application/search_application/app1", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_text_structure/test_grok_pattern",
		`{"grok_pattern":"%{WORD:w} %{INT:n:int} %{NUMBER:f:float}","messages":["hello 42 3.14"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_text_structure/find_structure",
		"{\"a\":1,\"b\":\"x\"}\n{\"a\":2,\"b\":\"y\"}\n", http.StatusOK, [2]string{"Content-Type", "application/x-ndjson"})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_text_structure/find_structure?format=delimited&delimiter=,",
		`{"messages":["c1,c2","1,abc","2,def"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ml/find_file_structure?format=delimited&delimiter=,",
		"c1,c2\n1,abc\n2,def\n", http.StatusOK, [2]string{"Content-Type", "text/plain"})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_text_structure/find_field_structure",
		`{"messages":["a=1","a=2"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_text_structure/find_field_structure?index=ml_src&field=msg",
		"", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_profiling/status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_profiling/flamegraph", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_profiling/stacktraces", `{}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_profiling/topn_functions", `{"size":5}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_profiling/topn/functions", `{"size":5}`, http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_autoscaling/policy/ap1",
		`{"roles":["data"],"deciders":{"fixed":{"storage":"10gb","memory":"4gb"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_autoscaling/policy/ap1", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_autoscaling/capacity", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_autoscaling/policy/ap1", "", http.StatusOK)
	if err := validateAutoscalingDecidersR65(map[string]any{"unknown_decider": map[string]any{}}); err == nil {
		t.Fatalf("expected error on unknown autoscaling decider")
	}

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_license", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_license/start_basic?acknowledge=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_license/basic_status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_license/start_trial?type=platinum", "", http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_license/start_trial?acknowledge=true", "", http.StatusForbidden)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_license/trial_status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_xpack", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_xpack/usage", "", http.StatusOK)

	asRes := mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ml_src/_async_search",
		`{"query":{"match_all":{}},"aggs":{"by_e":{"terms":{"field":"entity"}}}}`, http.StatusOK)
	if asID, ok := asRes["id"].(string); ok && asID != "" {
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_async_search/status/"+asID, "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_async_search/"+asID+"?typed_keys=true", "", http.StatusOK)
		mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_async_search/"+asID, "", http.StatusOK)
	}

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_health_report?verbose=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_health_report", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_health_report/shards_availability", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_sql", `{"query":"SELECT entity, val FROM ml_src LIMIT 2"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_sql/translate", `{"query":"SELECT entity FROM ml_src"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_sql/close", `{"cursor":"missing"}`, http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/ml_src/_graph/explore",
		`{"controls":{"sample_size":10},"vertices":[{"field":"entity","min_doc_count":1,"size":5},{"field":"ip","min_doc_count":1,"size":5}]}`, http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_nodes/node1/shutdown", `{"type":"restart","reason":"maint"}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_nodes/node1/shutdown", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_nodes/node1/shutdown", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_nodes/shutdown", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_nodes/node1/shutdown", "", http.StatusOK)
}

func TestRound67Cov_Features_Round48SpecialQueriesRankEvalTermVectorsTemplates(t *testing.T) {
	srv, _ := newR67CovFeatServer(t)

	// 1. Seed indices for join, percolate, MLT, termvectors, rank_eval, templates, and data stream migrate
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/join_idx", `{
		"mappings":{"properties":{
			"rel":{"type":"join","relations":{"question":"answer"}},
			"body":{"type":"text"},
			"tag":{"type":"keyword"}
		}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/join_idx/_doc/q1", `{"rel":"question","body":"how to search","tag":"go"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/join_idx/_doc/a1?routing=q1", `{"rel":{"name":"answer","parent":"q1"},"body":"use dsl","tag":"answer"}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/perc_idx", `{"mappings":{"properties":{"query":{"type":"percolator"},"msg":{"type":"text"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/perc_idx/_doc/pq1", `{"query":{"match":{"msg":"alert"}}}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/tv_idx", `{"mappings":{"properties":{"title":{"type":"text"},"tags":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/tv_idx/_doc/1", `{"title":"search engine vector term analysis","tags":["t1","t2"]}`, http.StatusCreated)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_refresh", "", http.StatusOK)

	// Direct preResolveSpecialQueriesInQuery & named/KNN/inner_hits unit coverage
	compoundJSON := `{
		"bool":{
			"must":[
				{"has_child":{"type":"answer","score_mode":"sum","min_children":1,"max_children":5,"inner_hits":{"name":"ans"},"query":{"match":{"body":"dsl"}}}},
				{"has_parent":{"parent_type":"question","score":true,"inner_hits":{"name":"q"},"query":{"term":{"tag":"go"}}}},
				{"parent_id":{"type":"answer","id":"q1"}}
			],
			"should":[
				{"percolate":{"field":"query","document":{"msg":"alert triggered"}}},
				{"more_like_this":{"fields":["body"],"like":[{"_index":"join_idx","_id":"q1"}],"min_term_freq":1,"min_doc_freq":1}},
				{"constant_score":{"filter":{"match_all":{},"_name":"cs_name"}}},
				{"boosting":{"positive":{"match_all":{}},"negative":{"match_none":{}},"negative_boost":0.5}},
				{"dis_max":{"queries":[{"match_all":{}}]}},
				{"function_score":{"query":{"match_all":{}}}},
				{"script_score":{"query":{"match_all":{}},"script":{"source":"1.0"}}},
				{"nested":{"path":"sub","ignore_unmapped":true,"query":{"match_all":{}}}},
				{"pinned":{"ids":["q1"],"organic":{"match_all":{}}}},
				{"wrapper":{"query":"eyJtYXRjaF9hbGwiOnt9fQ=="}}
			]
		}
	}`
	var cq esast.Query
	mustR67CovFeatJSON(t, compoundJSON, &cq)
	if _, err := srv.preResolveSpecialQueriesInQuery(context.Background(), []string{"join_idx", "perc_idx"}, &cq); err != nil {
		t.Fatalf("preResolveSpecialQueriesInQuery err=%v", err)
	}
	if !queryHasNamedClauses(&cq) {
		t.Fatalf("expected named clause inside query")
	}
	testSchema := &schema.IndexSchema{
		IndexName: "join_idx",
		Fields: map[string]schema.FieldBinding{
			"tag": {ESFieldPath: "tag", ESType: "keyword"},
			"vec": {ESFieldPath: "vec", ESType: "dense_vector", VectorDims: 2},
		},
	}
	_ = collectMatchedQueryNames(testSchema, map[string]any{"tag": "go"}, &cq)
	knnSim := 0.5
	_ = evalTopLevelKNNMatchesDocR63(testSchema, map[string]any{"vec": []any{1.0, 0.0}},
		&esast.KNNQuery{Field: "vec", QueryVector: []float64{1.0, 0.0}, K: 1, Similarity: &knnSim})
	var ihSpec esast.InnerHitsSpec
	mustR67CovFeatJSON(t, `{"name":"ih","size":1,"from":0,"version":true,"seq_no_primary_term":true}`, &ihSpec)
	_ = buildJoinInnerHitsEnvelope([]HitRow{{Index: "join_idx", ID: "a1", Score: 1.5, Version: 1, SeqNo: 2, HasSeqNo: true, Source: json.RawMessage(`{"body":"use dsl"}`)}}, &ihSpec, testSchema)

	// 2. Painless Execute
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute",
		`{"script":{"source":"params.a + params.b","params":{"a":2,"b":3}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute",
		`{"script":{"source":"return _score * 2;"},"context":"score","context_setup":{"index":"tv_idx","query":{"match":{"title":"search"}},"document":{"title":"search"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute",
		`{"script":{"source":"return doc['tags'].value == 't1';"},"context":"filter","context_setup":{"index":"tv_idx","document":{"tags":"t1"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute",
		`{"script":{"source":"ctx._source.added = 1;"},"context":"update","context_setup":{"document":{"title":"x"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute",
		`{"script":{"source":"emit(42L);"},"context":"long_field","context_setup":{"document":{"title":"x"}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_scripts/painless/_execute", "", http.StatusMethodNotAllowed)

	// 3. Term Vectors & MTerm Vectors
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_termvectors/1",
		`{"fields":["ti*"],"filter":{"min_word_length":2,"max_word_length":10,"min_term_freq":1,"max_term_freq":5,"min_doc_freq":1,"max_doc_freq":10,"max_num_terms":10},"per_field_analyzer":{"title":"standard"},"realtime":false}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_termvectors",
		`{"doc":{"title":"artificial document text"},"fields":["title"]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_termvectors/1?version=-1", `{}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_mtermvectors",
		`{"docs":[{"_id":"1","fields":["title"]},{"_id":"missing_id"},{"doc":{"title":"inline"}}]}`, http.StatusOK)

	// 4. Rank Eval
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_rank_eval", `{
		"requests":[{"id":"r1","request":{"query":{"match":{"title":"search"}}},"ratings":[{"_index":"tv_idx","_id":"1","rating":2}]}],
		"metric":{"dcg":{"k":10,"normalize":true}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_scripts/rank_tpl",
		`{"script":{"lang":"mustache","source":"{\"query\":{\"match\":{\"title\":\"{{q}}\"}}}"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_rank_eval", `{
		"templates":[{"id":"tpl1","template":{"id":"rank_tpl"}}],
		"requests":[{"id":"r1","template_id":"tpl1","params":{"q":"search"},"ratings":[{"_id":"1","rating":1}]}],
		"metric":{"precision":{"k":5}}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_rank_eval", `{"requests":[]}`, http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_rank_eval",
		`{"requests":[{"id":"r1","request":{"query":{"match_all":{}},"aggs":{}},"ratings":[{"_index":"tv_idx","_id":"1","rating":1}]}]}`, http.StatusBadRequest)

	// 5. Stored Scripts, Render Search Template, Search Template, MSearch Template
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_scripts/search_tpl",
		`{"script":{"lang":"mustache","source":"{\"query\":{\"bool\":{\"must\":[{\"match\":{\"title\":\"{{q}}\"}}],\"filter\":{\"terms\":{\"tags\":{{#toJson}}tags{{/toJson}}}}}}}"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_scripts/search_tpl", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodHead, "/_scripts/search_tpl", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_scripts/mustache/leg_tpl",
		`{"script":{"lang":"mustache","source":"{\"size\":{{sz}}}"}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_scripts/mustache/leg_tpl", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_render/template", `{
		"source":"{\"tags\":{{#toJson}}tags{{/toJson}},\"joined\":\"{{#join delimiter='|'}}tags{{/join}}\",\"u\":\"{{#url}}uval{{/url}}\",\"inv\":\"{{^absent}}yes{{/absent}}\",\"raw\":{{{raw_json}}},\"esc\":\"{{&uval}}\",\"sec\":[{{#objs}}\"{{k}}\"{{/objs}}]}",
		"params":{"tags":["a","b"],"uval":"x y","raw_json":"{\"a\":1}","objs":[{"k":"v1"}]}
	}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_render/template/search_tpl",
		`{"params":{"q":"search","tags":["t1"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_search/template",
		`{"id":"search_tpl","params":{"q":"search","tags":["t1"]}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_msearch/template",
		"{\"index\":\"tv_idx\"}\n{\"id\":\"search_tpl\",\"params\":{\"q\":\"search\",\"tags\":[\"t1\"]}}\n{\"index\":\"tv_idx\"}\n{\"id\":\"missing_tpl\"}\n",
		http.StatusOK, [2]string{"Content-Type", "application/x-ndjson"})
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_msearch/template", "{\"index\":\"tv_idx\"}\n",
		http.StatusBadRequest, [2]string{"Content-Type", "application/x-ndjson"})

	// Direct evalMustacheBlockBounded check for budget/error guard
	budget := 500
	if _, err := evalMustacheBlockBounded("{{!comment}}{{#items}}{{.}}{{/items}}", map[string]any{"items": []any{"x", "y"}}, nil, 0, &budget); err != nil {
		t.Fatalf("evalMustacheBlockBounded err=%v", err)
	}

	// 6. Data stream migration + Round 48 Cat/Cluster/Index/ILM admin endpoints
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/mig_ds_backing", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_aliases",
		`{"actions":[{"add":{"index":"mig_ds_backing","alias":"mig_ds_alias"}}]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/mig_ds_alias", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/mig_ds_alias", "", http.StatusBadRequest)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/unknown_alias", "", http.StatusNotFound)

	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/segments?v", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/tasks?v&detailed=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cat/thread_pool/write,search?v&full_id=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPut, "/_index_template/tpl_cat",
		`{"index_patterns":["cat_*"],"priority":10}`, http.StatusOK)
	recCatTpl := httptest.NewRecorder()
	srv.handleCatTemplates(recCatTpl, httptest.NewRequest(http.MethodGet, "/_cat/templates?v", nil))
	if recCatTpl.Code != http.StatusOK {
		t.Fatalf("handleCatTemplates status=%d", recCatTpl.Code)
	}

	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_cluster/allocation/explain", `{"index":"tv_idx","shard":0,"primary":true}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_cluster/pending_tasks", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_cluster/reroute", `{"commands":[]}`, http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/tv_idx/_recovery?detailed=true&human=true", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/tv_idx/_segments", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/tv_idx/_shard_stores?status=all", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/tv_idx/_cache/clear", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodGet, "/_ilm/status", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ilm/stop", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodPost, "/_ilm/start", "", http.StatusOK)

	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_scripts/search_tpl", "", http.StatusOK)
	mustR67CovFeatHTTP(t, srv, http.MethodDelete, "/_scripts/rank_tpl", "", http.StatusOK)
}
