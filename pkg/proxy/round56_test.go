package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound56Raw(t *testing.T, srv *Server, method, path, body string) (int, string, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		if strings.Contains(body, "\n") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
			req.Header.Set("Content-Type", "application/x-ndjson")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
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

func TestRound56DataStreamLifecycleDownsampleAndEscapedDocIDs(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Template with lifecycle inherited on PUT /_data_stream/{name}
	code, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_index_template/r56_ds_tpl", `{
		"index_patterns": ["logs-r56-*"],
		"data_stream": {},
		"template": {
			"lifecycle": {"data_retention": "14d"}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT template, got %d", code)
	}

	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_data_stream/logs-r56-app", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT data stream, got %d", code)
	}

	code, _, getLC := doRound56Raw(t, srv, http.MethodGet, "/_data_stream/logs-r56-app/_lifecycle?include_defaults=true", "")
	if code != http.StatusOK || getLC["global_retention"] == nil {
		t.Fatalf("expected 200 with global_retention on GET lifecycle, got %d: %+v", code, getLC)
	}
	dsArr, _ := getLC["data_streams"].([]any)
	if len(dsArr) == 0 {
		t.Fatalf("expected non-empty data_streams in lifecycle response: %+v", getLC)
	}
	ds0, _ := dsArr[0].(map[string]any)
	lc0, _ := ds0["lifecycle"].(map[string]any)
	if lc0["data_retention"] != "14d" {
		t.Fatalf("expected inherited data_retention=14d, got %+v", lc0)
	}

	// Invalid durations rejected with 400
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_data_stream/logs-r56-app/_lifecycle", `{"data_retention": "-5d"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative data_retention, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_data_stream/logs-r56-app/_lifecycle", `{"data_retention": "invalid"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid data_retention, got %d", code)
	}

	// Update lifecycle & explain
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_data_stream/logs-r56-app/_lifecycle", `{"data_retention": "7d", "downsampling": [{"after": "1d", "fixed_interval": "1h"}]}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 updating lifecycle, got %d", code)
	}
	code, _, expRes := doRound56Raw(t, srv, http.MethodGet, "/logs-r56-app/_lifecycle/explain", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _lifecycle/explain, got %d", code)
	}
	expIndices, _ := expRes["indices"].(map[string]any)
	backingExp, _ := expIndices["logs-r56-app"].(map[string]any)
	if backingExp["managed_by_lifecycle"] != true {
		t.Fatalf("expected managed_by_lifecycle=true, got %+v", expRes)
	}

	// Delete lifecycle
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_data_stream/logs-r56-app/_lifecycle", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 deleting lifecycle, got %d", code)
	}

	// Downsample index + validation errors
	doRound56Raw(t, srv, http.MethodPut, "/r56_metrics_src", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword"},"cpu":{"type":"double"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_metrics_src/_doc/1?refresh=true", `{"@timestamp":"2026-01-01T00:10:00Z","host":"h1","cpu":0.4}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_metrics_src/_doc/2?refresh=true", `{"@timestamp":"2026-01-01T00:20:00Z","host":"h1","cpu":0.8}`)

	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/r56_metrics_src/_downsample/r56_metrics_dst", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when fixed_interval missing, got %d", code)
	}
	code, _, dsAck := doRound56Raw(t, srv, http.MethodPost, "/r56_metrics_src/_downsample/r56_metrics_dst", `{"fixed_interval":"1h"}`)
	if code != http.StatusOK || dsAck["acknowledged"] != true {
		t.Fatalf("expected 200 acknowledged=true on _downsample, got %d: %+v", code, dsAck)
	}
	code, _, cntRes := doRound56Raw(t, srv, http.MethodPost, "/r56_metrics_dst/_count", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 counting downsampled index, got %d", code)
	}
	if cnt, _ := toInt64(cntRes["count"]); cnt < 1 {
		t.Fatalf("expected >=1 doc in downsampled index, got %+v", cntRes)
	}

	// Escaped doc IDs containing #, ?, spaces, and /
	specialID := "doc#1?tag=alpha 2/sub"
	encID := url.PathEscape(specialID)
	code, _, putDoc := doRound56Raw(t, srv, http.MethodPut, "/r56_escaped_ids/_doc/"+encID+"?refresh=true", `{"v":"ok"}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("expected 201/200 indexing escaped doc ID, got %d: %+v", code, putDoc)
	}
	code, _, getDoc := doRound56Raw(t, srv, http.MethodGet, "/r56_escaped_ids/_doc/"+encID, "")
	if code != http.StatusOK || getDoc["_id"] != specialID {
		t.Fatalf("expected 200 and exact _id=%q on GET escaped doc, got %d: %+v", specialID, code, getDoc)
	}
}

func TestRound56MLDataFrameTrainedModelsAndAnomalySubRoutes(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Seed source index for Data Frame Analytics & _evaluate
	doRound56Raw(t, srv, http.MethodPut, "/r56_ml_src", `{"mappings":{"properties":{"actual":{"type":"double"},"predicted":{"type":"double"},"x":{"type":"double"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_ml_src/_doc/1?refresh=true", `{"actual":1.0,"predicted":1.0,"x":10.0}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_ml_src/_doc/2?refresh=true", `{"actual":0.0,"predicted":0.0,"x":20.0}`)

	// F3: _evaluate
	code, _, evalReg := doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", `{
		"index": "r56_ml_src",
		"evaluation": {"regression": {"actual_field": "actual", "predicted_field": "predicted"}}
	}`)
	if code != http.StatusOK || evalReg["regression"] == nil {
		t.Fatalf("expected 200 regression evaluation, got %d: %+v", code, evalReg)
	}

	// F3: Data Frame Analytics CRUD, _start, _stats, _preview, _explain, _cat, _stop, DELETE
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_ml/data_frame/analytics/r56_dfa", `{
		"source": {"index": ["r56_ml_src"]},
		"dest": {"index": "r56_ml_dst"},
		"analysis": {"outlier_detection": {}}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating dfa job, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/analytics/r56_dfa/_start", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 starting dfa job, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_ml/data_frame/analytics/r56_dfa", "")
	if code != http.StatusConflict {
		t.Fatalf("expected 409 deleting started dfa job without force, got %d", code)
	}
	code, rawCatDFA, _ := doRound56Raw(t, srv, http.MethodGet, "/_cat/ml_data_frame_analytics/r56_dfa?format=json", "")
	if code != http.StatusOK || !strings.Contains(rawCatDFA, "r56_dfa") {
		t.Fatalf("expected r56_dfa in _cat/ml_data_frame_analytics, got %d: %s", code, rawCatDFA)
	}
	code, _, dfaStats := doRound56Raw(t, srv, http.MethodGet, "/_ml/data_frame/analytics/r56_dfa/_stats", "")
	if code != http.StatusOK || dfaStats["data_frame_analytics"] == nil {
		t.Fatalf("expected 200 on dfa _stats, got %d: %+v", code, dfaStats)
	}
	code, _, dfaPrev := doRound56Raw(t, srv, http.MethodGet, "/_ml/data_frame/analytics/r56_dfa/_preview", "")
	if code != http.StatusOK || dfaPrev["preview"] == nil {
		t.Fatalf("expected 200 on dfa _preview, got %d: %+v", code, dfaPrev)
	}
	code, _, dfaExp := doRound56Raw(t, srv, http.MethodGet, "/_ml/data_frame/analytics/r56_dfa/_explain", "")
	if code != http.StatusOK || dfaExp["index_selection_explanation"] == nil {
		t.Fatalf("expected 200 on dfa _explain, got %d: %+v", code, dfaExp)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/analytics/r56_dfa/_stop", "")
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_ml/data_frame/analytics/r56_dfa", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 deleting stopped dfa job, got %d", code)
	}

	// F4: Trained models definition, vocabulary, aliases, deployment & _infer
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm", `{"description":"test","input":{"field_names":["text"]}}`)
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm/definition/0", `{"definition":"cGFydDA=","total_definition_length":6,"part":0,"total_parts":1}`)
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm/vocabulary", `{"vocabulary":["hello","world"]}`)
	code, _, vocabRes := doRound56Raw(t, srv, http.MethodGet, "/_ml/trained_models/r56_tm/vocabulary", "")
	if code != http.StatusOK || vocabRes["vocabulary"] == nil {
		t.Fatalf("expected 200 on GET vocabulary, got %d: %+v", code, vocabRes)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm/model_aliases/r56_tm_alias", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating model alias, got %d", code)
	}
	code, _, startDep := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_alias/deployment/_start", `{"number_of_allocations":1}`)
	if code != http.StatusOK || startDep["assignment"] == nil {
		t.Fatalf("expected 200 starting deployment via alias, got %d: %+v", code, startDep)
	}
	code, _, inferRes := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_alias/deployment/_infer", `{"docs":[{"text":"hello"}]}`)
	if code != http.StatusOK || inferRes["inference_results"] == nil {
		t.Fatalf("expected 200 on deployment/_infer, got %d: %+v", code, inferRes)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_ml/trained_models/r56_tm", "")
	if code != http.StatusConflict {
		t.Fatalf("expected 409 deleting deployed trained model without force, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_ml/trained_models/r56_tm?force=true", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 force-deleting trained model, got %d", code)
	}

	// F5: Anomaly detectors validate, _data, _flush, results, snapshots, _forecast, _reset
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate", `{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _validate, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", `{"function":"count"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _validate/detector, got %d", code)
	}
	code, _, estMem := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_estimate_model_memory", `{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]}}`)
	if code != http.StatusOK || estMem["model_memory_estimate"] == nil {
		t.Fatalf("expected 200 on _estimate_model_memory, got %d: %+v", code, estMem)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_ml/anomaly_detectors/r56_ad", `{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]},"data_description":{"time_field":"@timestamp"}}`)
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_data", `[{"@timestamp":"2026-01-01T00:00:00Z","v":1}]`)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 posting _data to closed job, got %d", code)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_open", "")
	code, _, dataRes := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_data", `[{"@timestamp":"2026-01-01T00:00:00Z","v":1},{"@timestamp":"2026-01-01T00:05:00Z","v":2}]`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 posting _data to opened job, got %d: %+v", code, dataRes)
	}
	if prc, _ := toInt64(dataRes["processed_record_count"]); prc != 2 {
		t.Fatalf("expected processed_record_count=2, got %+v", dataRes)
	}
	code, _, flushRes := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_flush", `{"calc_interim":true}`)
	if code != http.StatusOK || flushRes["flushed"] != true {
		t.Fatalf("expected 200 flushed=true, got %d: %+v", code, flushRes)
	}
	code, _, fcRes := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_forecast", `{"duration":"1d"}`)
	if code != http.StatusOK || fcRes["forecast_id"] == nil {
		t.Fatalf("expected 200 on _forecast, got %d: %+v", code, fcRes)
	}
	code, _, bktRes := doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_ad/results/buckets", "")
	if code != http.StatusOK || bktRes["buckets"] == nil {
		t.Fatalf("expected 200 on results/buckets, got %d: %+v", code, bktRes)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_close", "")
	code, _, rstRes := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_ad/_reset", "")
	if code != http.StatusOK || rstRes["reset"] != true {
		t.Fatalf("expected 200 reset=true on closed job, got %d: %+v", code, rstRes)
	}
}

func TestRound56SecurityProfilesSettingsAndCCSAPIKey(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	code, _, actRes := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/_activate", `{
		"grant_type": "password",
		"username": "r56_alice",
		"password": "secret"
	}`)
	if code != http.StatusOK || actRes["was_activated"] != true {
		t.Fatalf("expected 200 was_activated=true on _activate, got %d: %+v", code, actRes)
	}
	uid, _ := actRes["uid"].(string)
	if uid == "" {
		t.Fatalf("expected non-empty uid on _activate: %+v", actRes)
	}

	// Single GET omits "errors" when found; multi GET populates "errors" for missing UID
	code, _, getOne := doRound56Raw(t, srv, http.MethodGet, "/_security/profile/"+uid, "")
	if code != http.StatusOK || getOne["errors"] != nil {
		t.Fatalf("expected 200 without errors for single found profile, got %d: %+v", code, getOne)
	}
	code, _, getMulti := doRound56Raw(t, srv, http.MethodGet, "/_security/profile/"+uid+",missing_uid", "")
	if code != http.StatusOK || getMulti["errors"] == nil {
		t.Fatalf("expected 200 with errors for missing profile in multi-get, got %d: %+v", code, getMulti)
	}

	// _data, _disable, _has_privileges, _enable, _suggest_profiles
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_security/profile/"+uid+"/_data", `{"labels":{"team":"sec"},"application":{"theme":"dark"}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 updating profile _data, got %d", code)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_security/profile/"+uid+"/_disable", "")
	code, _, privDisabled := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/"+uid+"/_has_privileges", `{"cluster":["monitor"]}`)
	if code != http.StatusOK || privDisabled["has_all_requested"] != false {
		t.Fatalf("expected has_all_requested=false when disabled, got %d: %+v", code, privDisabled)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_security/profile/"+uid+"/_enable", "")
	code, _, privEnabled := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/"+uid+"/_has_privileges", `{"cluster":["monitor"]}`)
	if code != http.StatusOK || privEnabled["has_all_requested"] != true {
		t.Fatalf("expected has_all_requested=true when enabled, got %d: %+v", code, privEnabled)
	}
	code, _, sugRes := doRound56Raw(t, srv, http.MethodPost, "/_security/_suggest_profiles", `{"name":"alice"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _suggest_profiles, got %d", code)
	}
	profiles, _ := sugRes["profiles"].([]any)
	if len(profiles) == 0 {
		t.Fatalf("expected suggested profile match for 'alice': %+v", sugRes)
	}

	// _security/settings & cross_cluster/api_key
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_security/settings", `{"index":{"number_of_replicas":"0"}}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /_security/settings, got %d", code)
	}
	code, _, getSecSet := doRound56Raw(t, srv, http.MethodGet, "/_security/settings", "")
	if code != http.StatusOK || getSecSet["main"] == nil {
		t.Fatalf("expected 200 with main settings on GET /_security/settings, got %d: %+v", code, getSecSet)
	}
	code, _, ccsKey := doRound56Raw(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{
		"name": "r56_ccs_key",
		"access": {"search": [{"names": ["logs-*"]}]}
	}`)
	if code != http.StatusOK || ccsKey["encoded"] == nil {
		t.Fatalf("expected 200 creating cross_cluster api_key, got %d: %+v", code, ccsKey)
	}
	keyID, _ := ccsKey["id"].(string)
	code, _, updKey := doRound56Raw(t, srv, http.MethodPut, "/_security/cross_cluster/api_key/"+keyID, `{"access":{"replication":[{"names":["logs-*"]}]}}`)
	if code != http.StatusOK || updKey["updated"] != true {
		t.Fatalf("expected 200 updated=true on PUT cross_cluster/api_key/{id}, got %d: %+v", code, updKey)
	}
}

func TestRound56ESQLEngineTransformsGeoIPAndResolveCluster(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound56Raw(t, srv, http.MethodPut, "/r56_esql", `{"mappings":{"properties":{"dept":{"type":"keyword"},"salary":{"type":"long"},"tag":{"type":"keyword"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_esql/_doc/1?refresh=true", `{"dept":"eng","salary":100,"tag":"a|b"}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_esql/_doc/2?refresh=true", `{"dept":"eng","salary":200,"tag":"a|b"}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_esql/_doc/3?refresh=true", `{"dept":"sales","salary":80,"tag":"c"}`)

	// F7: ES|QL with pipe inside literal, positional params, WHERE, EVAL, STATS ... BY, SORT, RENAME, columnar
	code, _, esqlRes := doRound56Raw(t, srv, http.MethodPost, "/_query", `{
		"query": "FROM r56_esql /* pipe | inside comment */ | WHERE salary >= ? AND (tag == \"a|b\" OR dept IN (\"sales\")) | EVAL bonus = salary * 2 | STATS avg_bonus = AVG(bonus), cnt = COUNT(*) BY dept | RENAME cnt AS total_cnt | SORT avg_bonus DESC | KEEP dept, avg_bonus, total_cnt",
		"params": [80],
		"columnar": true
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on ES|QL query, got %d: %+v", code, esqlRes)
	}
	vals, _ := esqlRes["values"].([]any)
	if len(vals) != 3 {
		t.Fatalf("expected 3 columnar arrays in ES|QL values, got %+v", esqlRes)
	}
	deptCol, _ := vals[0].([]any)
	if len(deptCol) < 2 {
		t.Fatalf("expected 2 groups in deptCol, got %+v", deptCol)
	}
	if deptCol[0] != "eng" {
		t.Fatalf("expected first sorted group dept=eng, got %+v", deptCol)
	}

	// F8: Transforms _upgrade, _reset, _schedule_now, GeoIP database CRUD + stats, ILM migrate_to_data_tiers
	doRound56Raw(t, srv, http.MethodPut, "/_transform/r56_tf", `{"source":{"index":["r56_esql"]},"dest":{"index":"r56_tf_out"},"pivot":{"group_by":{"dept":{"terms":{"field":"dept"}}},"aggregations":{"c":{"value_count":{"field":"dept"}}}}}`)
	code, _, tfUpg := doRound56Raw(t, srv, http.MethodPost, "/_transform/_upgrade", "")
	if code != http.StatusOK || tfUpg["pending_transforms"] == nil {
		t.Fatalf("expected 200 on _transform/_upgrade, got %d: %+v", code, tfUpg)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_transform/r56_tf/_schedule_now", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _transform/{id}/_schedule_now, got %d", code)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodPost, "/_transform/r56_tf/_reset", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _transform/{id}/_reset, got %d", code)
	}

	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_ingest/geoip/database/r56_city", `{"database_file":"GeoLite2-City.mmdb"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT geoip database, got %d", code)
	}
	code, _, geoStats := doRound56Raw(t, srv, http.MethodGet, "/_ingest/geoip/stats", "")
	if code != http.StatusOK || geoStats["nodes"] == nil {
		t.Fatalf("expected 200 on GET geoip stats, got %d: %+v", code, geoStats)
	}
	code, _, _ = doRound56Raw(t, srv, http.MethodDelete, "/_ingest/geoip/database/r56_city", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on DELETE geoip database, got %d", code)
	}

	code, _, migRes := doRound56Raw(t, srv, http.MethodPost, "/_ilm/migrate_to_data_tiers?dry_run=true", `{}`)
	if code != http.StatusOK || migRes["dry_run"] != true {
		t.Fatalf("expected 200 dry_run=true on _ilm/migrate_to_data_tiers, got %d: %+v", code, migRes)
	}

	// F9: /_resolve/cluster, 3-seg /_cat/nodes/{id}, /_cat?help, and /_features/_reset
	doRound56Raw(t, srv, http.MethodPut, "/_cluster/settings", `{"persistent":{"cluster.remote.rc_east.seeds":["127.0.0.1:9300"]}}`)
	code, _, rcRes := doRound56Raw(t, srv, http.MethodGet, "/_resolve/cluster/rc_*", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on GET /_resolve/cluster/rc_*, got %d: %+v", code, rcRes)
	}
	rcMap, _ := rcRes["rc_east"].(map[string]any)
	if rcMap["connected"] != true {
		t.Fatalf("expected rc_east connected=true, got %+v", rcRes)
	}
	code, rawNodes, _ := doRound56Raw(t, srv, http.MethodGet, "/_cat/nodes/doris-fe-1?format=json", "")
	if code != http.StatusOK || !strings.Contains(rawNodes, "doris-fe-1") {
		t.Fatalf("expected 200 matching doris-fe-1 on 3-seg _cat/nodes, got %d: %s", code, rawNodes)
	}
	code, rawHelp, _ := doRound56Raw(t, srv, http.MethodGet, "/_cat?help", "")
	if code != http.StatusOK || !strings.Contains(rawHelp, "/_cat/indices") {
		t.Fatalf("expected 200 on /_cat?help, got %d: %s", code, rawHelp)
	}
	code, _, rstFeat := doRound56Raw(t, srv, http.MethodPost, "/_features/_reset", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /_features/_reset, got %d: %+v", code, rstFeat)
	}
}

func TestRound56IngestForeachRerouteAndJSONProcessors(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F27: foreach inner if using ctx._ingest._value + nested pipeline on_failure_pipeline
	doRound56Raw(t, srv, http.MethodPut, "/_ingest/pipeline/r56_child_fail", `{
		"processors": [{"fail": {"message": "boom from child"}}]
	}`)
	code, _, simRes := doRound56Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"foreach": {
						"field": "tags",
						"processor": {
							"uppercase": {
								"if": "ctx._ingest._value != 'skip'",
								"field": "_ingest._value"
							}
						}
					}
				},
				{
					"pipeline": {
						"name": "r56_child_fail",
						"on_failure": [
							{"set": {"field": "failed_in", "value": "{{_ingest.on_failure_pipeline}}"}}
						]
					}
				}
			]
		},
		"docs": [{"_index": "test", "_id": "1", "_source": {"tags": ["alpha", "skip", "beta"]}}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on F27 _simulate, got %d: %+v", code, simRes)
	}
	simDocs, _ := simRes["docs"].([]any)
	if len(simDocs) == 0 {
		t.Fatalf("expected simulated doc: %+v", simRes)
	}
	d0, _ := simDocs[0].(map[string]any)
	docInner, _ := d0["doc"].(map[string]any)
	src0, _ := docInner["_source"].(map[string]any)
	if src0["failed_in"] != "r56_child_fail" {
		t.Fatalf("expected failed_in=r56_child_fail, got %+v", src0)
	}
	if src0["_ingest"] != nil {
		t.Fatalf("expected no _ingest leaked into _source, got %+v", src0)
	}
	tagsOut, _ := src0["tags"].([]any)
	if len(tagsOut) < 3 {
		t.Fatalf("expected 3 tags in foreach output, got %+v", tagsOut)
	}
	if tagsOut[0] != "ALPHA" || tagsOut[1] != "skip" || tagsOut[2] != "BETA" {
		t.Fatalf("unexpected foreach output: %+v", tagsOut)
	}

	// F28: reroute validation + array fallback + short-circuit only on index change
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_ingest/pipeline/r56_bad_reroute", `{
		"processors": [{"reroute": {"destination": "x", "dataset": "y"}}]
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when destination and dataset both set, got %d", code)
	}
	code, _, rrSim := doRound56Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"reroute": {"dataset": ["missing.field", "service.name"], "namespace": "prod-us", "if": "true"}},
				{"set": {"field": "after_reroute", "value": true}}
			]
		},
		"docs": [
			{"_index": "logs-generic-default", "_id": "1", "_source": {"service": {"name": "pay-api"}}},
			{"_index": "logs-pay_api-prod_us", "_id": "2", "_source": {"service": {"name": "pay-api"}}}
		]
	}`)
	if code != http.StatusOK {
		// Note: static '-' in namespace ("prod-us") must fail validation with 400!
		if code != http.StatusBadRequest {
			t.Fatalf("unexpected status %d: %+v", code, rrSim)
		}
	}
	code, _, rrSim2 := doRound56Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"reroute": {"dataset": ["missing.field", "service.name"], "namespace": ["env.name"]}},
				{"set": {"field": "after_reroute", "value": true}}
			]
		},
		"docs": [
			{"_index": "logs-generic-default", "_id": "1", "_source": {"service": {"name": "pay-api"}, "env": {"name": "prod-us"}}},
			{"_index": "logs-pay_api-prod_us", "_id": "2", "_source": {"service": {"name": "pay-api"}, "env": {"name": "prod-us"}}}
		]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on dynamic reroute _simulate, got %d: %+v", code, rrSim2)
	}
	rrDocs, _ := rrSim2["docs"].([]any)
	if len(rrDocs) != 2 {
		t.Fatalf("expected 2 docs in reroute _simulate, got %+v", rrSim2)
	}
	rd0, _ := rrDocs[0].(map[string]any)["doc"].(map[string]any)
	rd1, _ := rrDocs[1].(map[string]any)["doc"].(map[string]any)
	if rd0["_index"] != "logs-pay_api-prod_us" || rd0["_source"].(map[string]any)["after_reroute"] != nil {
		t.Fatalf("expected doc0 rerouted and short-circuited, got %+v", rd0)
	}
	if rd1["_source"].(map[string]any)["after_reroute"] != true {
		t.Fatalf("expected doc1 NOT short-circuited when target _index unchanged, got %+v", rd1)
	}

	// F29: json processor duplicate keys & add_to_root_conflict_strategy
	code, _, _ = doRound56Raw(t, srv, http.MethodPut, "/_ingest/pipeline/r56_bad_json_conflict", `{
		"processors": [{"json": {"field": "raw", "add_to_root_conflict_strategy": "merge"}}]
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when add_to_root_conflict_strategy used without add_to_root=true, got %d", code)
	}
	code, _, dupSim := doRound56Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"json": {"field": "raw", "target_field": "parsed"}}]},
		"docs": [{"_index": "t", "_id": "1", "_source": {"raw": "{\"a\":1,\"nested\":{\"k\":1,\"k\":2}}"}}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 wrapper from _simulate, got %d", code)
	}
	dupDocs, _ := dupSim["docs"].([]any)
	if len(dupDocs) == 0 {
		t.Fatalf("expected non-empty docs in dupSim: %+v", dupSim)
	}
	if dupDocs[0].(map[string]any)["error"] == nil {
		t.Fatalf("expected per-doc duplicate key error when allow_duplicate_keys=false, got %+v", dupSim)
	}
	code, _, mergeSim := doRound56Raw(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"json": {"field": "raw", "add_to_root": true, "add_to_root_conflict_strategy": "merge", "allow_duplicate_keys": true}}]},
		"docs": [{"_index": "t", "_id": "1", "_source": {"cfg": {"keep": 1, "override": 1}, "raw": "{\"cfg\":{\"override\":2,\"override\":3,\"added\":4}}"}}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on json merge _simulate, got %d: %+v", code, mergeSim)
	}
	mDocs, _ := mergeSim["docs"].([]any)
	if len(mDocs) == 0 {
		t.Fatalf("expected doc in mergeSim: %+v", mergeSim)
	}
	mCfg, _ := mDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)["cfg"].(map[string]any)
	if mCfg == nil || mCfg["keep"] == nil || mCfg["added"] == nil {
		t.Fatalf("expected deep-merged root cfg preserving sibling keep=1 and added=4, got %+v", mCfg)
	}
}

func TestRound56ExtendedESQLFunctionsMLAndSecuritySubRoutes(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// 1. ES|QL functions, LIKE/RLIKE/NOT/IS NULL/arithmetic/METADATA/DROP/LIMIT/STATS
	doRound56Raw(t, srv, http.MethodPut, "/r56_fn", `{"mappings":{"properties":{"name":{"type":"keyword"},"val":{"type":"double"},"cnt":{"type":"long"},"flag":{"type":"boolean"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_fn/_doc/1?refresh=true", `{"name":"  Alpha_1  ","val":12.345,"cnt":-5,"flag":true}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_fn/_doc/2?refresh=true", `{"name":"Beta_2","val":7.5,"cnt":10,"flag":false}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_fn/_doc/3?refresh=true", `{"name":"Gamma","cnt":3}`)

	code, _, fnRes := doRound56Raw(t, srv, http.MethodPost, "/_query", `{
		"query": "FROM r56_fn METADATA _id, _index | WHERE name IS NOT NULL AND NOT (name LIKE \"*\\\\%*\") AND name LIKE \"*Alpha_?*\" AND name NOT LIKE \"ZZZ%\" AND name RLIKE \".*[A-Za-z]+.*\" AND name NOT RLIKE \"^ZZZ\" AND cnt NOT IN (999, ?) AND (val IS NULL OR val >= ?) AND flag == ? | EVAL trimmed = TRIM(name), low = TO_LOWER(trimmed), up = TO_UPPER(trimmed), ln = LENGTH(trimmed), s = CONCAT(low, \":\", TO_STRING(ABS(cnt))), i = TO_INT(\"42\"), i2 = TO_INT(flag), d = TO_DOUBLE(\"3.5\"), d2 = TO_DOUBLE(flag), b = TO_BOOLEAN(\"true\"), b2 = TO_BOOLEAN(0), r = ROUND( COALESCE(val, 1.25), 1 ), neg = -cnt, arith = (cnt + 10 - 2) * 3 / 2 % 5 | DROP flag | LIMIT 5",
		"params": [888, 1.0, true],
		"filter": {"match_all": {}}
	}`)
	if code != http.StatusOK || len(fnRes["values"].([]any)) != 1 {
		t.Fatalf("expected 200 with 1 matching row (Alpha_1) from extended ES|QL functions query, got %d: %+v", code, fnRes)
	}

	code, _, aggRes := doRound56Raw(t, srv, http.MethodPost, "/_query", `{
		"query": "FROM r56_fn | STATS c_all = COUNT(*), c_val = COUNT(val), cd = COUNT_DISTINCT(name), s_cnt = SUM(cnt), s_val = SUM(val), mn = MIN(cnt), mx = MAX(cnt), vs = VALUES(name)"
	}`)
	if code != http.StatusOK || len(aggRes["values"].([]any)) != 1 {
		t.Fatalf("expected 200 single summary row from ES|QL STATS aggregates, got %d: %+v", code, aggRes)
	}

	// 2. ML Data Frame _evaluate: regression, outlier_detection, binary_soft_classification
	doRound56Raw(t, srv, http.MethodPut, "/r56_eval_idx", `{"mappings":{"properties":{"actual":{"type":"double"},"predicted":{"type":"double"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_eval_idx/_doc/1?refresh=true", `{"actual":1.0,"predicted":0.9}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_eval_idx/_doc/2?refresh=true", `{"actual":0.0,"predicted":0.1}`)
	for _, evBody := range []string{
		`{"index":"r56_eval_idx","evaluation":{"regression":{"actual_field":"actual","predicted_field":"predicted"}}}`,
		`{"index":"r56_eval_idx","evaluation":{"outlier_detection":{"actual_field":"actual","predicted_probability_field":"predicted"}}}`,
		`{"index":"r56_eval_idx","evaluation":{"binary_soft_classification":{"actual_field":"actual","predicted_probability_field":"predicted"}}}`,
	} {
		code, _, evOut := doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", evBody)
		if code != http.StatusOK {
			t.Fatalf("expected 200 on data_frame/_evaluate %s, got %d: %+v", evBody, code, evOut)
		}
	}

	// 3. ML Anomaly Detectors extended sub-routes
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate", `{"analysis_config":{"detectors":[{"function":"count"}]}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _validate, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", `{"function":"count"}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _validate/detector, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_estimate_model_memory", `{"analysis_config":{"detectors":[{"function":"count"}]}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _estimate_model_memory, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_ml/anomaly_detectors/r56_anom_ext", `{"analysis_config":{"bucket_span":"1h","detectors":[{"function":"count"}]},"data_description":{"time_field":"@timestamp"}}`)
	doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/_open", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/_data", "{\"@timestamp\":\"2026-01-01T00:00:00Z\",\"v\":1}\n{\"@timestamp\":\"2026-01-01T00:05:00Z\",\"v\":2}\n"); c != http.StatusOK {
		t.Fatalf("expected 200 on NDJSON _data, got %d", c)
	}
	code, _, fcOut := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/_forecast", `{"duration":"1d"}`)
	if code != http.StatusOK || fcOut["forecast_id"] == nil {
		t.Fatalf("expected 200 on _forecast, got %d: %+v", code, fcOut)
	}
	fid := fcOut["forecast_id"].(string)
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/r56_anom_ext/_forecast/"+fid, ""); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE _forecast/{id}, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/_delete_expired_data", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _delete_expired_data, got %d", c)
	}
	for _, rp := range []string{
		"/_ml/anomaly_detectors/r56_anom_ext/results/buckets",
		"/_ml/anomaly_detectors/r56_anom_ext/results/buckets/1700000000000",
		"/_ml/anomaly_detectors/r56_anom_ext/results/overall_buckets",
		"/_ml/anomaly_detectors/r56_anom_ext/results/records",
		"/_ml/anomaly_detectors/r56_anom_ext/results/categories",
		"/_ml/anomaly_detectors/r56_anom_ext/results/influencers",
		"/_ml/anomaly_detectors/r56_anom_ext/model_snapshots",
	} {
		if c, _, _ := doRound56Raw(t, srv, http.MethodGet, rp, ""); c != http.StatusOK {
			t.Fatalf("expected 200 on GET %s, got %d", rp, c)
		}
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/model_snapshots/1/_update", `{"description":"kept","retain":true}`); c != http.StatusOK {
		t.Fatalf("expected 200 on snapshot _update, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/model_snapshots/1/_revert", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on snapshot _revert, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/r56_anom_ext/model_snapshots/1", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on snapshot DELETE, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_anom_ext/_reset?force=true", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _reset?force=true, got %d", c)
	}

	// 4. ML Trained Models extended sub-routes
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_ext", `{"description":"ext model","input":{"field_names":["text"]}}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_ext/definition/0", `{"definition":"chunk0","total_definition_length":6}`); c != http.StatusOK {
		t.Fatalf("expected 200 on definition/0 PUT, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_ext/deployment/_start?deployment_id=dep_ext", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/dep_ext/deployment/_update", `{"number_of_allocations":2}`); c != http.StatusOK {
		t.Fatalf("expected 200 on deployment/_update, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/dep_ext/deployment/_infer", `{"docs":[{"text":"hi"}]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on deployment/_infer, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/dep_ext/deployment/_stop", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on deployment/_stop, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_ext/model_aliases/alias_ext", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_ml/trained_models/r56_tm_ext/model_aliases/alias_ext", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE model_aliases, got %d", c)
	}

	// 5. Security profiles, settings & cross_cluster api_key extended sub-routes
	_, _, actProf := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/_activate", `{"grant":{"user":{"username":"alice","roles":["analyst"],"email":"alice@example.com","full_name":"Alice Ops"}}}`)
	uid := actProf["uid"].(string)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_security/profile/"+uid+"/_disable", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on profile _disable, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_security/profile/"+uid+"/_enable", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on profile _enable, got %d", c)
	}
	if c, _, hp := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/"+uid+"/_has_privileges", `{"cluster":["monitor"],"index":[{"names":["logs-*"],"privileges":["read"]}],"application":[{"application":"kibana","privileges":["read"],"resources":["space:default"]}]}`); c != http.StatusOK || hp["has_all_requested"] != true {
		t.Fatalf("expected 200 has_all_requested=true on profile _has_privileges, got %d: %+v", c, hp)
	}
	if c, _, sg := doRound56Raw(t, srv, http.MethodPost, "/_security/_suggest_profiles", `{"hint":{"text":"alice"},"size":5}`); c != http.StatusOK || sg["count"].(float64) < 1 {
		t.Fatalf("expected 200 matching profile on _suggest_profiles, got %d: %+v", c, sg)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_security/settings", `{"operator_privileges.enabled":true}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT _security/settings, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodGet, "/_security/settings", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on GET _security/settings, got %d", c)
	}
	code, _, ccKey := doRound56Raw(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{"name":"cc-east","expiration":"7d","access":{"search":[{"names":["logs-*"]}]},"metadata":{"env":"prod"}}`)
	if code != http.StatusOK || ccKey["id"] == nil {
		t.Fatalf("expected 200 on POST cross_cluster/api_key, got %d: %+v", code, ccKey)
	}
	ccID := ccKey["id"].(string)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_security/cross_cluster/api_key/"+ccID, `{"access":{"search":[{"names":["metrics-*"]}]},"expiration":"14d","metadata":{"env":"prod2"}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT cross_cluster/api_key/{id}, got %d", c)
	}

	// 6. Data frame analytics _stats/_preview/_explain/_update + _cat/ml + downsample settings variants + lifecycle DELETE
	doRound56Raw(t, srv, http.MethodPut, "/_ml/data_frame/analytics/r56_dfa_ext", `{"source":{"index":["r56_eval_idx"]},"dest":{"index":"r56_dfa_out","results_field":"ml_res"},"analysis":{"outlier_detection":{}}}`)
	for _, mPath := range [][2]string{
		{http.MethodGet, "/_ml/data_frame/analytics/_stats"},
		{http.MethodGet, "/_ml/data_frame/analytics/r56_dfa_ext/_stats"},
		{http.MethodPost, "/_ml/data_frame/analytics/_preview"},
		{http.MethodGet, "/_ml/data_frame/analytics/r56_dfa_ext/_preview"},
		{http.MethodPost, "/_ml/data_frame/analytics/_explain"},
		{http.MethodGet, "/_ml/data_frame/analytics/r56_dfa_ext/_explain"},
		{http.MethodPost, "/_ml/data_frame/analytics/r56_dfa_ext/_update"},
		{http.MethodGet, "/_cat/ml/data_frame/analytics?format=json"},
		{http.MethodGet, "/_cat/ml_data_frame_analytics?format=json"},
	} {
		reqBody := ""
		if mPath[0] == http.MethodPost {
			reqBody = `{"config":{"source":{"index":"r56_eval_idx"},"dest":{"index":"r56_dfa_out"},"analysis":{"regression":{"dependent_variable":"actual"}}},"description":"updated"}`
		}
		if c, _, _ := doRound56Raw(t, srv, mPath[0], mPath[1], reqBody); c != http.StatusOK {
			t.Fatalf("expected 200 on %s %s, got %d", mPath[0], mPath[1], c)
		}
	}
	doRound56Raw(t, srv, http.MethodPut, "/r56_ds_epoch", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword"}}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_ds_epoch/_doc/1?refresh=true", `{"@timestamp":1700000001000,"host":"h1"}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_ds_epoch/_doc/2?refresh=true", `{"@timestamp":"1700000005000","host":"h1"}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/r56_ds_epoch/_downsample/r56_ds_epoch_out", `{"settings":{"index":{"downsample":{"fixed_interval":"1h"}}}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on nested settings _downsample, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_index_template/r56_ds_lc_tpl", `{"index_patterns":["r56-dslc-*"],"data_stream":{},"template":{"lifecycle":{"data_retention":"7d"}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/_data_stream/r56-dslc-1", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodGet, "/_data_stream/r56-dslc-*/_lifecycle?include_defaults=true", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on wildcard GET _lifecycle, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_data_stream/r56-dslc-1/_lifecycle", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on DELETE _lifecycle, got %d", c)
	}
}

func TestRound56ErrorAndEdgeCases(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// Trained models: text_embedding, regression, pass_through, vocabulary HEAD/400, alias reassign/conflict, deployment 409/404
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_te", `{"input":{"field_names":["text"]},"inference_config":{"text_embedding":{"embedding_size":3}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_reg", `{"input":{"field_names":["x"]},"inference_config":{"regression":{}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_pt", `{"input":{"field_names":["x"]},"inference_config":{"pass_through":{}}}`)

	for _, mid := range []string{"r56_tm_te", "r56_tm_reg", "r56_tm_pt"} {
		if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/"+mid+"/_infer", `{"docs":[{"text":"hi","x":42}]}`); c != http.StatusOK {
			t.Fatalf("expected 200 on _infer for %s, got %d", mid, c)
		}
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_te/_infer", `{"docs":[]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty docs _infer, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_te/deployment/_infer", `{"docs":[{"text":"hi"}]}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 on unstarted deployment/_infer, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_te/deployment/_start?number_of_allocations=2&threads_per_allocation=2&queue_capacity=512&priority=high", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/r56_tm_te/deployment/_start", `{}`); c != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate deployment/_start, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/no_such_dep/deployment/_stop?allow_no_match=true", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on allow_no_match deployment/_stop, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/trained_models/no_such_dep/deployment/_stop", `{}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing deployment/_stop, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_te/model_aliases/shared_alias", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on model_alias create, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_reg/model_aliases/shared_alias", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on model_alias conflict without reassign, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_reg/model_aliases/shared_alias?reassign=true", `{}`); c != http.StatusOK {
		t.Fatalf("expected 200 on model_alias reassign=true, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodHead, "/_ml/trained_models/r56_tm_te/vocabulary", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on HEAD vocabulary, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_ml/trained_models/r56_tm_te/vocabulary", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing vocabulary array, got %d", c)
	}

	// Anomaly detection validation/error paths, GeoIP DB, ILM migrate, ES|QL edge syntax
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty _validate, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty _validate/detector, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_ml/anomaly_detectors/r56_closed_ad", `{"analysis_config":{"bucket_span":"1h","detectors":[{"function":"count"}]},"data_description":{"time_field":"timestamp"}}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_closed_ad/_data", `{"timestamp":1700000000000}`); c != http.StatusConflict {
		t.Fatalf("expected 409 on _data to closed job, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/r56_closed_ad/_forecast/missing_fc?allow_no_forecasts=true", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on allow_no_forecasts=true, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/r56_closed_ad/_forecast/missing_fc", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing forecast delete, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_ingest/geoip/database/r56_geo_1", `{"database_file":"GeoLite2-City.mmdb"}`)
	doRound56Raw(t, srv, http.MethodGet, "/_ingest/geoip/database", "")
	doRound56Raw(t, srv, http.MethodHead, "/_ingest/geoip/database/r56_geo_1", "")
	doRound56Raw(t, srv, http.MethodPost, "/_ilm/migrate_to_data_tiers?dry_run=true", `{}`)
	doRound56Raw(t, srv, http.MethodPost, "/_ilm/migrate_to_data_tiers", `{"legacy_template_to_delete":"old_tpl"}`)

	// ES|QL quoted strings with pipes, backticks, unary operators, DIV, %, computed BY expressions
	esqlEdge := `{"query":"ROW ` + "`x val`" + ` = -10, label = \"a|b\", flag = ? | EVAL pos = +` + "`x val`" + ` + 20, q = 17 / 5, rem = 17 % 5 | STATS total = SUM(pos) BY grp = label, parity = rem == 2","params":[true]}`
	if c, _, m := doRound56Raw(t, srv, http.MethodPost, "/_query", esqlEdge); c != http.StatusOK || len(m["values"].([]any)) != 1 {
		t.Fatalf("expected 200 and 1 grouped row on ES|QL edge query, got %d %#v", c, m)
	}

	// ES|QL full type-conversion/null/math branches in evalESQLFunc
	esqlFuncs := `{"query":"ROW n = null, b1 = true, b0 = false, i = -7, f = -3.75 | EVAL c0 = COALESCE(n, n), s0 = TO_STRING(n), ti1 = TO_INT(b1), ti0 = TO_INT(b0), tif = TO_INT(f), tis = TO_INT(\"4.9\"), tib = TO_INT(\"bad\"), td1 = TO_DOUBLE(b1), td0 = TO_DOUBLE(b0), tdb = TO_DOUBLE(\"bad\"), tb1 = TO_BOOL(b1), tb0 = TO_BOOL(0), tbs1 = TO_BOOL(\"true\"), tbs0 = TO_BOOL(\"false\"), tbb = TO_BOOL(\"maybe\"), tl0 = TO_LOWER(n), tu0 = TO_UPPER(n), tr0 = TRIM(n), ln0 = LENGTH(n), ri = ROUND(i), ai = ABS(i), af = ABS(f)"}`
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_query", esqlFuncs); c != http.StatusOK {
		t.Fatalf("expected 200 on ES|QL full function matrix, got %d", c)
	}

	// Security profile _has_privileges (cluster + index + application), _suggest_profiles hint object, settings HEAD & null delete, cross_cluster/api_key errors
	_, _, actResp := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/_activate", `{"grant_type":"password","username":"alice_sec","full_name":"Alice Security","email":"alice@example.com"}`)
	uid, _ := actResp["uid"].(string)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_security/profile/"+uid+"/_has_privileges", `{"cluster":["monitor"],"index":[{"names":["logs-*"],"privileges":["read"]}],"application":[{"application":"kibana","privileges":["read"]}]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on profile _has_privileges, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_security/_suggest_profiles", `{"hint":{"text":"alice"},"size":1}`); c != http.StatusOK {
		t.Fatalf("expected 200 on _suggest_profiles hint map, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPut, "/_security/settings", `{"xpack.security.Custom":"on"}`)
	doRound56Raw(t, srv, http.MethodHead, "/_security/settings", "")
	doRound56Raw(t, srv, http.MethodPut, "/_security/settings", `{"xpack.security.Custom":null}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{"name":""}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing cross_cluster api_key name, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{"name":"cc1"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing cross_cluster api_key access, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{"name":"cc1","access":{"search":[]},"expiration":"invalid"}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid cross_cluster api_key expiration, got %d", c)
	}
	if c, _, _ := doRound56Raw(t, srv, http.MethodPut, "/_security/cross_cluster/api_key/nonexistent_cck", `{"access":{"search":[]}}`); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing cross_cluster api_key update, got %d", c)
	}

	// Data stream lifecycle expand_wildcards=none, HEAD, 404 & _lifecycle/explain alias/404/HEAD + anomaly buckets/{ts}, categories/{id}, snapshots/{id}
	doRound56Raw(t, srv, http.MethodPut, "/_data_stream/r56-ew-ds", `{"lifecycle":{"data_retention":"5d","enabled":true}}`)
	doRound56Raw(t, srv, http.MethodGet, "/_data_stream/r56-ew-ds/_lifecycle?expand_wildcards=none&include_defaults=true", "")
	doRound56Raw(t, srv, http.MethodHead, "/_data_stream/r56-ew-ds/_lifecycle", "")
	doRound56Raw(t, srv, http.MethodHead, "/_data_stream/no-such-ds/_lifecycle", "")
	doRound56Raw(t, srv, http.MethodPut, "/r56_plain_idx", `{}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_plain_idx/_alias/r56_plain_alias", `{}`)
	doRound56Raw(t, srv, http.MethodGet, "/r56_plain_alias/_lifecycle/explain", "")
	doRound56Raw(t, srv, http.MethodHead, "/r56-ew-ds/_lifecycle/explain", "")
	if c, _, _ := doRound56Raw(t, srv, http.MethodGet, "/no_such_idx_lc/_lifecycle/explain?allow_no_indices=false", ""); c != http.StatusNotFound {
		t.Fatalf("expected 404 on _lifecycle/explain allow_no_indices=false, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_closed_ad/_open", `{}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_closed_ad/_reset", `{}`); c != http.StatusConflict {
		t.Fatalf("expected 409 on _reset of opened job without force=true, got %d", c)
	}
	doRound56Raw(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r56_closed_ad/_data", `{"timestamp":1700000000000,"v":10}`)
	doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_closed_ad/results/buckets/1700000000000", "")
	doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_closed_ad/results/buckets/999", "")
	doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_closed_ad/results/categories/1", "")
	doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_closed_ad/model_snapshots/1", "")
	doRound56Raw(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r56_closed_ad/model_snapshots/999", "")

	// ML data_frame/_evaluate validation & outlier_detection tp/fp/tn/fn + hit extraction helpers
	doRound56Raw(t, srv, http.MethodGet, "/_ml/data_frame/_evaluate", "")
	doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", `{}`)
	doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", `{"index":"r56_plain_idx"}`)
	doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", `{"index":"r56_plain_idx","evaluation":{"unknown":{}}}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_od_idx/_doc/1?refresh=true", `{"actual":true,"predicted":0.9}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_od_idx/_doc/2?refresh=true", `{"actual":false,"predicted":0.8}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_od_idx/_doc/3?refresh=true", `{"actual":0,"predicted":0.1}`)
	doRound56Raw(t, srv, http.MethodPut, "/r56_od_idx/_doc/4?refresh=true", `{"actual":1,"predicted":0.2}`)
	if c, _, _ := doRound56Raw(t, srv, http.MethodPost, "/_ml/data_frame/_evaluate", `{"index":"r56_od_idx","evaluation":{"outlier_detection":{}}}`); c != http.StatusOK {
		t.Fatalf("expected 200 on outlier_detection _evaluate, got %d", c)
	}
	if extractSearchResponseHitItems(nil) != nil || extractSearchResponseHitItems(map[string]any{"hits": "bad"}) != nil {
		t.Fatalf("expected nil from invalid extractSearchResponseHitItems")
	}
	anyHits := extractSearchResponseHitItems(map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"_source": []byte(`{"k":1}`)}}}})
	if len(anyHits) != 1 || extractHitSourceMap(anyHits[0])["k"] == nil || extractHitSourceMap(nil) != nil {
		t.Fatalf("unexpected extractHitSourceMap result")
	}
}
