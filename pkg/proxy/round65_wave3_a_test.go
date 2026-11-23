package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRound65Wave3A_TransformValidationAuthStatsCatAndPreview(t *testing.T) {
	srv, handler := newRound61AdminTestServer(t, "8.15.5")

	// 1. Setup source indices and docs
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/airline-data", `{
		"mappings": {
			"properties": {
				"airline": {"type": "keyword"},
				"responsetime": {"type": "double"},
				"time": {"type": "date"},
				"_isDeleted": {"type": "boolean"},
				"agg_metric": {"type": "aggregate_metric_double", "metrics": ["min", "max"], "default_metric": "min"}
			}
		}
	}`); c != http.StatusOK {
		t.Fatalf("create airline-data: %d %s", c, raw)
	}
	docs := []string{
		`{"time":"2017-02-18T00:00:00Z","airline":"foo","responsetime":1.0,"_isDeleted":false}`,
		`{"time":"2017-02-18T00:30:00Z","airline":"foo","responsetime":1.0,"_isDeleted":false}`,
		`{"time":"2017-02-18T01:00:00Z","airline":"bar","responsetime":42.0,"_isDeleted":false}`,
		`{"time":"2017-02-18T01:01:00Z","airline":"foo","responsetime":42.0,"_isDeleted":true}`,
	}
	for i, d := range docs {
		if c, _, _, raw := doR65Req(t, handler, http.MethodPut, fmt.Sprintf("/airline-data/_doc/%d?refresh=true", i+1), d); c != http.StatusCreated && c != http.StatusOK {
			t.Fatalf("index doc %d: %d %s", i+1, c, raw)
		}
	}

	// 2. Destination uppercase check before validateESIndexName
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_upper_dest", `{
		"source": {"index": "airline-data"},
		"dest": {"index": "DeStInAtIoN"},
		"pivot": {"group_by": {"airline": {"terms": {"field": "airline"}}}, "aggs": {"avg_response": {"avg": {"field": "responsetime"}}}}
	}`); c != http.StatusBadRequest || !strings.Contains(raw, "Destination index [DeStInAtIoN] must be lowercase") {
		t.Fatalf("expected Destination index must be lowercase, got %d %s", c, raw)
	}

	// 3. Bad scripted_metric script compilation fails with 400
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_bad_script", `{
		"source": {"index": "airline-data"},
		"dest": {"index": "tf-dest-bad-script"},
		"pivot": {
			"group_by": {"airline": {"terms": {"field": "airline"}}},
			"aggs": {
				"sumState": {
					"scripted_metric": {
						"init_script": {"source": "state.state = []"},
						"map_script": {"source": "state.state.add(1)"},
						"combine_script": {"source": "foobar boom"},
						"reduce_script": {"source": "return 1"}
					}
				}
			}
		}
	}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid scripted_metric script, got %d %s", c, raw)
	}

	// 4. latest.unique_key duplicate rejection
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_dup_uk", `{
		"source": {"index": "airline-data"},
		"dest": {"index": "tf-dest-dup"},
		"latest": {"unique_key": ["airline", "airline"], "sort": "time"}
	}`); c != http.StatusBadRequest || !strings.Contains(raw, "latest.unique_key elements must be unique, found duplicate element [airline]") {
		t.Fatalf("expected duplicate unique_key error, got %d %s", c, raw)
	}

	// 5. Alias source expansion and multi-target dest alias without write index
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/created-destination-index", `{}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/second-created-destination-index", `{}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"airline-data","alias":"source-index"}},
		{"add":{"index":"created-destination-index","alias":"source-index"}},
		{"add":{"index":"created-destination-index","alias":"dest2-index"}},
		{"add":{"index":"second-created-destination-index","alias":"dest2-index"}}
	]}`)
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_alias_overlap", `{
		"source": {"index": "source-index"},
		"dest": {"index": "created-destination-index"},
		"pivot": {"group_by": {"airline": {"terms": {"field": "airline"}}}, "aggs": {"c": {"value_count": {"field": "responsetime"}}}}
	}`); c != http.StatusBadRequest || !strings.Contains(raw, "Destination index [created-destination-index] is included in source expression [airline-data,created-destination-index]") {
		t.Fatalf("expected alias source expression expansion error, got %d %s", c, raw)
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_dest_nowrite", `{
		"source": {"index": "airline-data"},
		"dest": {"index": "dest2-index"},
		"pivot": {"group_by": {"airline": {"terms": {"field": "airline"}}}, "aggs": {"c": {"value_count": {"field": "responsetime"}}}}
	}`); c != http.StatusBadRequest || !strings.Contains(raw, "no write index is defined for alias dest2-index;") {
		t.Fatalf("expected dest2-index no write index error, got %d %s", c, raw)
	}

	// 6. PUT + GET authorization.roles + exclude_generated / for_export + _update
	for _, tid := range []string{"tf-alpha", "tf-beta", "tf-gamma"} {
		if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/"+tid, `{
			"source": {"index": "airline-data"},
			"dest": {"index": "tf-dest-`+tid+`"},
			"description": "initial",
			"pivot": {"group_by": {"airline": {"terms": {"field": "airline"}}}, "aggs": {"avg_response": {"avg": {"field": "responsetime"}}}}
		}`); c != http.StatusOK {
			t.Fatalf("PUT transform %s: %d %s", tid, c, raw)
		}
	}
	cGet, _, mGet, rawGet := doR65Req(t, handler, http.MethodGet, "/_transform/tf-alpha", "")
	if cGet != http.StatusOK {
		t.Fatalf("GET transform: %d %s", cGet, rawGet)
	}
	tr0 := mGet["transforms"].([]any)[0].(map[string]any)
	if authMap, ok := tr0["authorization"].(map[string]any); !ok || authMap["roles"] == nil {
		t.Fatalf("expected authorization.roles in GET transform, got %v", tr0)
	}
	cExp, _, mExp, rawExp := doR65Req(t, handler, http.MethodGet, "/_transform/tf-alpha?exclude_generated=true", "")
	if cExp != http.StatusOK {
		t.Fatalf("GET transform exclude_generated: %d %s", cExp, rawExp)
	}
	trExp := mExp["transforms"].([]any)[0].(map[string]any)
	if _, has := trExp["create_time"]; has {
		t.Fatalf("expected create_time removed with exclude_generated=true: %v", trExp)
	}
	if _, has := trExp["version"]; has {
		t.Fatalf("expected version removed with exclude_generated=true: %v", trExp)
	}
	cUpd, _, mUpd, rawUpd := doR65Req(t, handler, http.MethodPost, "/_transform/tf-alpha/_update", `{"description":"updated"}`)
	if cUpd != http.StatusOK || mUpd["authorization"] == nil {
		t.Fatalf("expected authorization on _update, got %d %s", cUpd, rawUpd)
	}

	// 7. Stats on missing transform in ES8 mode -> 200 empty; transport_address + pagination
	if cMiss, _, mMiss, rawMiss := doR65Req(t, handler, http.MethodGet, "/_transform/does-not-exist/_stats", ""); cMiss != http.StatusOK || r65Int(mMiss["count"]) != 0 {
		t.Fatalf("expected 200 count=0 for missing ES8 stats, got %d %s", cMiss, rawMiss)
	}
	cStats, _, mStats, rawStats := doR65Req(t, handler, http.MethodGet, "/_transform/tf-*/_stats?from=1&size=1", "")
	if cStats != http.StatusOK || r65Int(mStats["count"]) != 3 {
		t.Fatalf("expected total count=3 with pagination, got %d %s", cStats, rawStats)
	}
	stList := mStats["transforms"].([]any)
	if len(stList) != 1 || stList[0].(map[string]any)["id"] != "tf-beta" {
		t.Fatalf("expected tf-beta as paginated slice, got %v", stList)
	}
	if nodeMap := stList[0].(map[string]any)["node"].(map[string]any); nodeMap["transport_address"] == nil {
		t.Fatalf("expected node.transport_address in stats: %v", nodeMap)
	}

	// Check v7.10.2 preserves 404 on missing stats
	_, handlerV7 := newRound61AdminTestServer(t, "7.10.2")
	if cV7, _, _, _ := doR65Req(t, handlerV7, http.MethodGet, "/_transform/missing_t/_stats", ""); cV7 != http.StatusNotFound {
		t.Fatalf("expected 404 in v7.10.2 for missing transform stats, got %d", cV7)
	}

	// 8. /_cat/transforms?h=...,docp,cdtea,indexed_documents_exp_avg
	cCat, _, _, rawCat := doR65Req(t, handler, http.MethodGet, "/_cat/transforms/tf-*?v=true&h=id,docp,cdtea,indexed_documents_exp_avg,pdea", "")
	if cCat != http.StatusOK || !strings.Contains(rawCat, "docp") || !strings.Contains(rawCat, "cdtea") || !strings.Contains(rawCat, "0.00") {
		t.Fatalf("unexpected cat transforms output: %d %s", cCat, rawCat)
	}

	// 9. Preview latest strips leading '_' and runtime-only fields
	cPrevL, _, mPrevL, rawPrevL := doR65Req(t, handler, http.MethodPost, "/_transform/_preview", `{
		"source": {
			"index": "airline-data",
			"runtime_mappings": {
				"time-5m": {"type": "date", "script": "emit(doc['time'].value.toInstant().minus(5, ChronoUnit.MINUTES).toEpochMilli())"}
			}
		},
		"latest": {"unique_key": ["airline"], "sort": "time-5m"}
	}`)
	if cPrevL != http.StatusOK {
		t.Fatalf("preview latest failed: %d %s", cPrevL, rawPrevL)
	}
	prevLDocs := mPrevL["preview"].([]any)
	if len(prevLDocs) != 2 {
		t.Fatalf("expected 2 latest docs, got %d %s", len(prevLDocs), rawPrevL)
	}
	for _, rd := range prevLDocs {
		dm := rd.(map[string]any)
		if _, has := dm["_isDeleted"]; has {
			t.Fatalf("expected _isDeleted filtered from latest preview: %v", dm)
		}
		if _, has := dm["time-5m"]; has {
			t.Fatalf("expected runtime field time-5m omitted from latest preview: %v", dm)
		}
	}

	// 10. Preview pivot with runtime fields + warnings
	cPrevP, hdrPrevP, mPrevP, rawPrevP := doR65Req(t, handler, http.MethodPost, "/_transform/_preview", `{
		"source": {
			"index": "airline-data",
			"runtime_mappings": {
				"airline-upper": {"type": "keyword", "script": "emit(doc['airline'].value.toUpperCase())"},
				"responsetime_x_2": {"type": "double", "script": "emit(doc['responsetime'].value * 2.0)"},
				"time-5m": {"type": "date", "script": "emit(doc['time'].value.toInstant().minus(5, ChronoUnit.MINUTES).toEpochMilli())"}
			}
		},
		"pivot": {
			"group_by": {
				"airline": {"terms": {"field": "airline-upper"}},
				"by-hour": {"date_histogram": {"fixed_interval": "1h", "field": "time"}}
			},
			"aggs": {
				"avg_response": {"avg": {"field": "responsetime_x_2"}},
				"time.max": {"max": {"field": "time-5m"}}
			}
		}
	}`)
	if cPrevP != http.StatusOK {
		t.Fatalf("preview pivot runtime failed: %d %s", cPrevP, rawPrevP)
	}
	prevPDocs := mPrevP["preview"].([]any)
	if len(prevPDocs) != 3 {
		t.Fatalf("expected 3 runtime pivot docs, got %d %s", len(prevPDocs), rawPrevP)
	}
	if props := mPrevP["generated_dest_index"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any); props["time.max"].(map[string]any)["type"] != "date" {
		t.Fatalf("expected time.max deduced as date, got %v", props)
	}
	_ = hdrPrevP

	cWarn, hdrWarn, _, rawWarn := doR65Req(t, handler, http.MethodPost, "/_transform/_preview", `{
		"source": {
			"index": "airline-data",
			"runtime_mappings": {
				"airline-upper": {"type": "keyword", "script": "emit(doc['airline'].value.toUpperCase())"},
				"time-10m": {"type": "date", "script": "emit(doc['time'].value.toInstant().minus(10, ChronoUnit.MINUTES).toEpochMilli())"}
			}
		},
		"pivot": {
			"group_by": {"airline": {"terms": {"field": "airline-upper"}}},
			"aggs": {"avg_response": {"avg": {"field": "responsetime"}}}
		},
		"sync": {"time": {"field": "time-10m"}}
	}`)
	if cWarn != http.StatusOK {
		t.Fatalf("preview warning failed: %d %s", cWarn, rawWarn)
	}
	joinedW := strings.Join(hdrWarn.Values("Warning"), "\n")
	if !strings.Contains(joinedW, "all the group-by fields are script-based runtime fields") ||
		!strings.Contains(joinedW, "sync time field is a script-based runtime field") {
		t.Fatalf("expected runtime field warnings, got %q", joinedW)
	}
	_ = srv
}

func TestRound65Wave3A_RollupSearchAndTemplates(t *testing.T) {
	_, handler := newRound61AdminTestServer(t, "8.15.5")

	// Data stream resolvability for _rollup/data wildcard
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/_index_template/logs_tpl", `{
		"index_patterns": ["logs-*"],
		"data_stream": {},
		"template": {"mappings": {"properties": {"@timestamp": {"type": "date"}}}}
	}`)
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_data_stream/logs-generic-default", ""); c != http.StatusOK {
		t.Fatalf("create data stream: %d %s", c, raw)
	}
	if c, _, m, raw := doR65Req(t, handler, http.MethodGet, "/logs*/_rollup/data", ""); c != http.StatusOK || len(m) == 0 {
		t.Fatalf("expected 200 non-empty on GET /logs*/_rollup/data, got %d %s", c, raw)
	}

	// Put two rollup jobs writing to same rollup index
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/src_rollup_data", `{
		"mappings": {"properties": {"timestamp": {"type": "date"}, "partition": {"type": "keyword"}, "price": {"type": "double"}}}
	}`)
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_rollup/job/foo", `{
		"index_pattern": "src_rollup_data",
		"rollup_index": "foo_rollup",
		"cron": "*/30 * * * * ?",
		"page_size": 10,
		"groups": {"date_histogram": {"field": "timestamp", "calendar_interval": "1h"}, "terms": {"fields": ["partition"]}},
		"metrics": [{"field": "price", "metrics": ["max"]}]
	}`); c != http.StatusOK {
		t.Fatalf("put rollup foo: %d %s", c, raw)
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_rollup/job/foo2", `{
		"index_pattern": "src_rollup_data",
		"rollup_index": "foo_rollup",
		"cron": "*/30 * * * * ?",
		"page_size": 10,
		"groups": {"date_histogram": {"field": "timestamp", "calendar_interval": "1d"}, "terms": {"fields": ["partition"]}},
		"metrics": [{"field": "price", "metrics": ["max"]}]
	}`); c != http.StatusOK {
		t.Fatalf("put rollup foo2: %d %s", c, raw)
	}

	// Check dynamic_templates on foo_rollup mapping
	if c, _, mMap, raw := doR65Req(t, handler, http.MethodGet, "/foo_rollup", ""); c != http.StatusOK {
		t.Fatalf("get foo_rollup: %d %s", c, raw)
	} else {
		dts := mMap["foo_rollup"].(map[string]any)["mappings"].(map[string]any)["dynamic_templates"].([]any)
		if len(dts) < 2 {
			t.Fatalf("expected dynamic_templates on foo_rollup, got %s", raw)
		}
	}

	// Index rollup bucket docs for both jobs (gap at 06:00 for partition=a)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"foo_rollup"}}`,
		`{"timestamp.date_histogram.timestamp":"2017-01-01T05:00:00Z","timestamp.date_histogram.interval":"1h","timestamp.date_histogram._count":1,"partition.terms.value":"a","partition.terms._count":1,"price.max.value":1,"_rollup.id":"foo","_rollup.version":1}`,
		`{"index":{"_index":"foo_rollup"}}`,
		`{"timestamp.date_histogram.timestamp":"2017-01-01T06:00:00Z","timestamp.date_histogram.interval":"1h","timestamp.date_histogram._count":2,"partition.terms.value":"b","partition.terms._count":2,"price.max.value":2,"_rollup.id":"foo","_rollup.version":1}`,
		`{"index":{"_index":"foo_rollup"}}`,
		`{"timestamp.date_histogram.timestamp":"2017-01-01T07:00:00Z","timestamp.date_histogram.interval":"1h","timestamp.date_histogram._count":10,"partition.terms.value":"a","partition.terms._count":10,"price.max.value":3,"_rollup.id":"foo","_rollup.version":1}`,
		`{"index":{"_index":"foo_rollup"}}`,
		`{"timestamp.date_histogram.timestamp":"2017-01-01T05:00:00Z","timestamp.date_histogram.interval":"1h","timestamp.date_histogram._count":1,"partition.terms.value":"a","partition.terms._count":1,"price.max.value":1,"_rollup.id":"foo2","_rollup.version":1}`,
		`{"index":{"_index":"foo_rollup"}}`,
		`{"timestamp.date_histogram.timestamp":"2017-01-01T07:00:00Z","timestamp.date_histogram.interval":"1h","timestamp.date_histogram._count":10,"partition.terms.value":"a","partition.terms._count":10,"price.max.value":3,"_rollup.id":"foo2","_rollup.version":1}`,
	}, "\n") + "\n"
	if c, _, _, raw := doR65Req(t, handler, http.MethodPost, "/_bulk?refresh=true", bulkBody); c != http.StatusOK {
		t.Fatalf("bulk foo_rollup: %d %s", c, raw)
	}

	// Single job dedupe + empty bucket fill + typed_keys + format + Canada/Mountain timezone
	cRS, _, mRS, rawRS := doR65Req(t, handler, http.MethodPost, "/foo_rollup/_rollup_search?typed_keys=true", `{
		"size": 0,
		"query": {"term": {"partition": "a"}},
		"aggs": {
			"histo": {
				"date_histogram": {"field": "timestamp", "calendar_interval": "1h", "time_zone": "UTC"},
				"aggs": {"the_max": {"max": {"field": "price"}}}
			}
		}
	}`)
	if cRS != http.StatusOK {
		t.Fatalf("rollup_search failed: %d %s", cRS, rawRS)
	}
	buckets := mRS["aggregations"].(map[string]any)["date_histogram#histo"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets (05:00, 06:00 empty, 07:00), got %d %s", len(buckets), rawRS)
	}
	if r65Int(buckets[0].(map[string]any)["doc_count"]) != 1 || r65Int(buckets[1].(map[string]any)["doc_count"]) != 0 {
		t.Fatalf("unexpected doc_counts (dedupe/empty fill failed): %s", rawRS)
	}
	if _, ok := buckets[0].(map[string]any)["max#the_max"]; !ok {
		t.Fatalf("expected nested typed key max#the_max, got %v", buckets[0])
	}

	cFmt, _, mFmt, rawFmt := doR65Req(t, handler, http.MethodPost, "/foo_rollup/_rollup_search", `{
		"size": 0,
		"aggs": {
			"histo": {"date_histogram": {"field": "timestamp", "calendar_interval": "1h", "time_zone": "Canada/Mountain", "format": "yyyy-MM-dd HH"}}
		}
	}`)
	if cFmt != http.StatusOK {
		t.Fatalf("rollup_search tz+format: %d %s", cFmt, rawFmt)
	}
	fBuckets := mFmt["aggregations"].(map[string]any)["histo"].(map[string]any)["buckets"].([]any)
	// 2017-01-01T05:00Z is 2016-12-31 22:00 MST (-07:00 in Jan)
	if fBuckets[0].(map[string]any)["key_as_string"] != "2016-12-31 22" {
		t.Fatalf("expected timezone formatted bucket key '2016-12-31 22', got %v", fBuckets[0])
	}
}

func TestRound65Wave3A_SnapshotSearchableProfilingGraphHealthAnalytics(t *testing.T) {
	srv, handler := newRound61AdminTestServer(t, "8.15.5")

	// 1. Source-only snapshot partial failure on synthetic source
	repoDir := t.TempDir()
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/_snapshot/src_repo", `{"type":"source","settings":{"location":"`+repoDir+`"}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/idx_synth", `{"settings":{"index.mapping.source.mode":"synthetic"}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/idx_norm", `{}`)
	cSnap, _, mSnap, rawSnap := doR65Req(t, handler, http.MethodPut, "/_snapshot/src_repo/snap1?wait_for_completion=true", `{"indices":"idx_synth,idx_norm"}`)
	if cSnap != http.StatusOK || mSnap["snapshot"].(map[string]any)["state"] != "PARTIAL" {
		t.Fatalf("expected PARTIAL source-only snapshot, got %d %s", cSnap, rawSnap)
	}

	// 2. Searchable snapshots clear_cache / stats on non-snapshot index returns 404
	if cSS, _, _, rawSS := doR65Req(t, handler, http.MethodPost, "/idx_norm/_searchable_snapshots/cache/clear", ""); cSS != http.StatusNotFound || !strings.Contains(rawSS, "No searchable snapshots indices found") {
		t.Fatalf("expected 404 No searchable snapshots indices found, got %d %s", cSS, rawSS)
	}

	// 3. Profiling template + epoch_second @timestamp min/max agg
	if cP, _, _, rawP := doR65Req(t, handler, http.MethodGet, "/_profiling/status?wait_for_resources_created=true", ""); cP != http.StatusOK {
		t.Fatalf("profiling status: %d %s", cP, rawP)
	}
	if cB, _, _, rawB := doR65Req(t, handler, http.MethodPost, "/_bulk?refresh=true",
		`{"create":{"_index":"profiling-events-all"}}`+"\n"+`{"@timestamp":["1700504427"],"Stacktrace.count":[1],"Stacktrace.id":["S1"],"host.id":["H1"]}`+"\n"); cB != http.StatusOK {
		t.Fatalf("bulk profiling: %d %s", cB, rawB)
	}
	if cPS, _, mPS, rawPS := doR65Req(t, handler, http.MethodPost, "/profiling-events-all/_search", `{
		"size": 0,
		"aggs": {"min_time": {"min": {"field": "@timestamp"}}}
	}`); cPS != http.StatusOK || mPS["aggregations"].(map[string]any)["min_time"].(map[string]any)["value"] == nil {
		t.Fatalf("expected valid min agg on profiling @timestamp, got %d %s", cPS, rawPS)
	}

	// 4. Health API index allocation diagnosis ID + Analytics usage tracking
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/red_alloc_idx", `{"settings":{"number_of_shards":1,"number_of_replicas":0,"index.routing.allocation.enable":"none"}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodGet, "/_health_report", "")
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/analytics_idx", `{"mappings":{"properties":{"s":{"type":"integer"},"timestamp":{"type":"date"}}}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/analytics_idx/_doc/1?refresh=true", `{"s":1,"timestamp":"2017-01-01T05:00:00Z"}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPost, "/analytics_idx/_search", `{"size":0,"aggs":{"plot":{"boxplot":{"field":"s"}}}}`)

	cU, _, mU, rawU := doR65Req(t, handler, http.MethodGet, "/_xpack/usage", "")
	if cU != http.StatusOK {
		t.Fatalf("xpack usage: %d %s", cU, rawU)
	}
	diagRed := mU["health_api"].(map[string]any)["diagnoses"].(map[string]any)["red"].(map[string]any)
	if r65Int(diagRed["elasticsearch:health:shards_availability:diagnosis:enable_index_allocations"]) != 1 {
		t.Fatalf("expected enable_index_allocations diagnosis, got %s", rawU)
	}
	analyticsStats := mU["analytics"].(map[string]any)["stats"].(map[string]any)
	if r65Int(analyticsStats["boxplot_usage"]) != 1 {
		t.Fatalf("expected boxplot_usage=1, got %s", rawU)
	}

	// 5. Graph explore
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/graph_idx", `{"mappings":{"properties":{"keys":{"type":"integer"}}}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/graph_idx/_doc/1?refresh=true", `{"keys":[1,2,3]}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/graph_idx/_doc/2?refresh=true", `{"keys":[4,5,6]}`)
	cG, _, mG, rawG := doR65Req(t, handler, http.MethodPost, "/graph_idx/_graph/explore", `{"query":{"match":{"keys":1}},"vertices":[{"field":"keys","min_doc_count":1}]}`)
	if cG != http.StatusOK || len(mG["vertices"].([]any)) != 3 {
		t.Fatalf("expected 3 graph vertices, got %d %s", cG, rawG)
	}
	_ = srv
	_ = httptest.NewRequest
}
