package proxy

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type mockBM25SQLBackend struct {
	*MemoryBackend
	capturedQueries []string
	rowResults      map[string][]map[string]any
}

func (m *mockBM25SQLBackend) QueryRows(ctx context.Context, sqlStr string) ([]map[string]any, error) {
	m.capturedQueries = append(m.capturedQueries, sqlStr)
	for substr, rows := range m.rowResults {
		if substr == "" || strings.Contains(sqlStr, substr) {
			return rows, nil
		}
	}
	return []map[string]any{{
		"__bm25_total_rows": int64(2),
		"__bm25_n_0":        int64(2),
		"__bm25_avgdl_0":    2.5,
		"__bm25_df_0_0":     int64(1),
	}}, nil
}

func TestRound66LiveBM25PreQueryAndCorpusStats(t *testing.T) {
	mockBackend := &mockBM25SQLBackend{
		MemoryBackend: NewMemoryBackend(false),
		rowResults: map[string][]map[string]any{
			"FROM `es_db`.": {{
				"__bm25_total_rows": int64(5),
				"__bm25_n_0":        int64(5),
				"__bm25_avgdl_0":    "3.5",
				"__bm25_df_0_0":     "2",
			}},
		},
	}
	srv := NewServer("es_db", mockBackend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	h := srv.Handler()

	createRec := doRound65Req(t, h, http.MethodPut, "/articles", `{"mappings":{"properties":{"title":{"type":"text"}}}}`, nil)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", createRec.Code, createRec.Body.String())
	}

	rec := doRound65Req(t, h, http.MethodPost, "/articles/_search", `{"query":{"match":{"title":"don't"}}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(mockBackend.capturedQueries) != 1 {
		t.Fatalf("expected 1 batched BM25 pre-query SQL call, got %d: %v", len(mockBackend.capturedQueries), mockBackend.capturedQueries)
	}
	preQ := mockBackend.capturedQueries[0]
	if !strings.Contains(preQ, "SUM(CASE WHEN LOCATE(' don''t ', ") {
		t.Fatalf("expected intra-word apostrophe tokenization in batched SQL pre-query, got: %s", preQ)
	}
	if !strings.Contains(preQ, "WHERE `__DORIS_DELETE_SIGN__` = 0") {
		t.Fatalf("expected __DORIS_DELETE_SIGN__ = 0 in pre-query, got: %s", preQ)
	}
}

func TestRound66MatrixStatsWithBucketSelector(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()
	if rec := doRound65Req(t, h, http.MethodPut, "/test1", `{"mappings":{"properties":{"value1":{"type":"double"},"value2":{"type":"double"},"value3":{"type":"double"}}}}`, nil); rec.Code != 200 {
		t.Fatalf("create test1: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound65Req(t, h, http.MethodPut, "/test2", `{"mappings":{"properties":{"value1":{"type":"double"},"value2":{"type":"double"},"value4":{"type":"double"}}}}`, nil); rec.Code != 200 {
		t.Fatalf("create test2: %d %s", rec.Code, rec.Body.String())
	}
	for _, doc := range []string{
		`{"value1":"1.0d","value2":"10.0d","value3":"100.0d"}`,
		`{"value1":"2.0d","value2":"20.0d","value3":"200.0d"}`,
		`{"value1":"3.0d","value2":"10.0d","value3":"300.0d"}`,
	} {
		if rec := doRound65Req(t, h, http.MethodPost, "/test1/_doc", doc, nil); rec.Code >= 300 {
			t.Fatalf("index test1: %d %s", rec.Code, rec.Body.String())
		}
	}
	for _, doc := range []string{
		`{"value1":"1.0d","value2":"10.0d","value4":"100.0d"}`,
		`{"value1":"2.0d","value2":"20.0d","value4":"200.0d"}`,
		`{"value1":"3.0d","value2":"10.0d","value4":"300.0d"}`,
	} {
		if rec := doRound65Req(t, h, http.MethodPost, "/test2/_doc", doc, nil); rec.Code >= 300 {
			t.Fatalf("index test2: %d %s", rec.Code, rec.Body.String())
		}
	}
	doRound65Req(t, h, http.MethodPost, "/test1,test2/_refresh", `{}`, nil)
	noSelBody := `{"size":0,"aggs":{"matrix":{"filters":{"filters":[{"match_all":{}}]},"aggs":{"stats":{"matrix_stats":{"fields":["value1","value2"]}}}}}}`
	recNoSel := doRound65Req(t, h, http.MethodPost, "/test1,test2/_search", noSelBody, nil)
	t.Logf("noSelector=%s", recNoSel.Body.String())

	searchBody := `{"size":0,"aggs":{"matrix":{"filters":{"filters":[{"match_all":{}}]},"aggs":{"stats":{"matrix_stats":{"fields":["value1","value2"]}},"selector":{"bucket_selector":{"buckets_path":{"count":"stats[value1].counts","mean":"stats['value2'].means","variance":"stats['value1'].variances","skewness":"stats[value2].skewness","kurtosis":"stats[value1].kurtosis","covariance":"stats['value2'].covariance","correlation":"stats[value1].correlation"},"script":{"source":"params.count + params.mean + params.variance + params.skewness + params.kurtosis + params.covariance + params.correlation > params.threshold","lang":"painless","params":{"threshold":1.0}}}}}}}}`
	rec := doRound65Req(t, h, http.MethodPost, "/test1,test2/_search", searchBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	aggs, _ := resp["aggregations"].(map[string]any)
	matrix, _ := aggs["matrix"].(map[string]any)
	buckets, _ := matrix["buckets"].([]any)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 surviving matrix bucket after bucket_selector, got %d: %s", len(buckets), rec.Body.String())
	}
	b0, _ := buckets[0].(map[string]any)
	stats, _ := b0["stats"].(map[string]any)
	fields, _ := stats["fields"].([]any)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields in matrix_stats, got %d: %s", len(fields), rec.Body.String())
	}
}

func TestRound66Cluster12AggregateMetricRuntime(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()
	if rec := doRound65Req(t, h, http.MethodPut, "/source_r66", `{
		"settings":{"number_of_shards":1,"index":{"mode":"time_series","routing_path":["metricset"],"time_series":{"start_time":"2021-04-28T00:00:00Z","end_time":"2021-04-29T00:00:00Z"}}},
		"mappings":{
			"runtime":{
				"tx_kb":{"type":"double","script":"emit(doc['k8s.pod.network.tx'].value / 1024.0d);"}
			},
			"properties":{
				"@timestamp":{"type":"date"},
				"metricset":{"type":"keyword","time_series_dimension":true},
				"k8s":{"properties":{"pod":{"properties":{"network":{"properties":{"tx":{"type":"long","time_series_metric":"gauge"}}}}}}}
			}
		}
	}`, nil); rec.Code != 200 {
		t.Fatalf("create source: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound65Req(t, h, http.MethodPost, "/source_r66/_doc?refresh=true", `{"@timestamp":"2021-04-28T18:50:03.142Z","metricset":"pod","k8s":{"pod":{"network":{"tx":1434521831}}}}`, nil); rec.Code >= 300 {
		t.Fatalf("index 1: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound65Req(t, h, http.MethodPost, "/source_r66/_doc?refresh=true", `{"@timestamp":"2021-04-28T18:50:23.142Z","metricset":"pod","k8s":{"pod":{"network":{"tx":1434577921}}}}`, nil); rec.Code >= 300 {
		t.Fatalf("index 2: %d %s", rec.Code, rec.Body.String())
	}
	doRound65Req(t, h, http.MethodPut, "/source_r66/_settings", `{"index.blocks.write":true}`, nil)
	if rec := doRound65Req(t, h, http.MethodPost, "/source_r66/_downsample/target_r66", `{"fixed_interval":"1h"}`, nil); rec.Code != 200 {
		t.Fatalf("downsample: %d %s", rec.Code, rec.Body.String())
	}
	rec := doRound65Req(t, h, http.MethodPost, "/target_r66/_search", `{"fields":["tx_kb"]}`, nil)
	if rec.Code != 200 {
		t.Fatalf("search: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 downsampled hit, got %d: %s", len(hits), rec.Body.String())
	}
	txKB := hits[0].(map[string]any)["fields"].(map[string]any)["tx_kb"].([]any)[0].(float64)
	if txKB < 1400955.0 || txKB > 1400955.01 {
		t.Fatalf("expected tx_kb ~1400955.0009, got %v (%s)", txKB, rec.Body.String())
	}
}

func TestRound66Cluster5DSTDebug(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()
	if rec := doRound65Req(t, h, http.MethodPut, "/ds_src", `{
		"settings":{"number_of_shards":1,"index":{"mode":"time_series","routing_path":["uid"],"time_series":{"start_time":"2020-03-01T00:00:00Z","end_time":"2020-03-30T00:00:00Z"}}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"uid":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}
	}`, nil); rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	for _, ts := range []string{"2020-03-09T03:00:00Z", "2020-03-09T03:50:00Z", "2020-03-09T04:00:00Z", "2020-03-09T05:00:00Z"} {
		doRound65Req(t, h, http.MethodPost, "/ds_src/_doc", `{"@timestamp":"`+ts+`","uid":"001","m":10}`, nil)
	}
	doRound65Req(t, h, http.MethodPost, "/ds_src/_refresh", `{}`, nil)
	doRound65Req(t, h, http.MethodPut, "/ds_src/_settings", `{"index.blocks.write":true}`, nil)
	doRound65Req(t, h, http.MethodPost, "/ds_src/_downsample/ds_tgt", `{"fixed_interval":"15m"}`, nil)
	rec := doRound65Req(t, h, http.MethodPost, "/ds_tgt/_search", `{"size":0,"aggs":{"dh":{"date_histogram":{"field":"@timestamp","fixed_interval":"1d","time_zone":"America/New_York"}}},"query":{"range":{"@timestamp":{"gt":"2020-03-08T00:00:00Z","lt":"2020-03-10T00:00:00Z"}}}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("1d NY search failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	buckets := resp["aggregations"].(map[string]any)["dh"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 DST buckets across 2020-03-08/09, got %d: %s", len(buckets), rec.Body.String())
	}
}

func TestRound66Task1CollapseMaxScoreSQLAndCluster1TSIDOrder(t *testing.T) {
	// 1. CollapseMaxScoreSQL execution via SQLRowsBackend
	mockBackend := &mockBM25SQLBackend{
		MemoryBackend: NewMemoryBackend(false),
		rowResults: map[string][]map[string]any{
			"_overall_max_score": {{
				"_overall_max_score": 1.77,
			}},
		},
	}
	srvSQL := NewServer("es_db", mockBackend, transpiler.TranspilerOptions{})
	srvSQL.SetTargetESVersion("8.15.5")
	hSQL := srvSQL.Handler()
	_ = doRound65Req(t, hSQL, http.MethodPut, "/col_r66", `{"mappings":{"properties":{"grp":{"type":"keyword"},"title":{"type":"text"},"rank":{"type":"integer"}}}}`, nil)
	_ = doRound65Req(t, hSQL, http.MethodPost, "/col_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"grp":"a","title":"alpha alpha","rank":1}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"grp":"a","title":"alpha","rank":10}`+"\n", nil)
	colRec := doRound65Req(t, hSQL, http.MethodPost, "/col_r66/_search", `{
		"query":{"match":{"title":"alpha"}},
		"sort":[{"rank":"desc"}],
		"track_scores":true,
		"collapse":{"field":"grp"}
	}`, nil)
	if colRec.Code != http.StatusOK {
		t.Fatalf("collapse search failed: %d %s", colRec.Code, colRec.Body.String())
	}
	var colResp map[string]any
	_ = json.Unmarshal(colRec.Body.Bytes(), &colResp)
	if ms, _ := colResp["hits"].(map[string]any)["max_score"].(float64); math.Abs(ms-1.77) > 1e-9 {
		t.Fatalf("expected pre-collapse CollapseMaxScoreSQL max_score=1.77, got %v (%s)", ms, colRec.Body.String())
	}

	// 2. Cluster 1: _tsid Base64URL unsigned byte comparison vs ASCII order
	if compareTSIDRawBytesMem("-___", "AAAA") <= 0 {
		// Base64URL: '-' (62) > 'A' (0), whereas ASCII '-' (45) < 'A' (65)
		t.Fatalf("expected Base64URL order '-' (62) > 'A' (0)")
	}
	if compareTSIDRawBytesMem("zzzz", "aAAA") <= 0 {
		t.Fatalf("expected Base64URL order 'z' (51) > 'a' (26)")
	}
}

func TestRound66Cluster3MatrixStatsRejectAndCluster4TSDBRate(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Cluster 3: matrix_stats rejects missing field in one of the target indices with 400
	_ = doRound65Req(t, h, http.MethodPut, "/ms_a", `{"mappings":{"properties":{"v1":{"type":"double"},"v2":{"type":"double"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/ms_b", `{"mappings":{"properties":{"v1":{"type":"double"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ms_a/_doc/1?refresh=true", `{"v1":1,"v2":2}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ms_b/_doc/1?refresh=true", `{"v1":3}`, nil)
	msRec := doRound65Req(t, h, http.MethodPost, "/ms_a,ms_b/_search", `{"size":0,"aggs":{"ms":{"matrix_stats":{"fields":["v1","v2"]}}}}`, nil)
	if msRec.Code != http.StatusBadRequest || !strings.Contains(msRec.Body.String(), "illegal_argument_exception") {
		t.Fatalf("expected 400 illegal_argument_exception for matrix_stats partial field, got %d %s", msRec.Code, msRec.Body.String())
	}

	// Cluster 4: TSDB counter rate with reset & unit scaling
	_ = doRound65Req(t, h, http.MethodPut, "/ts_rate_r66", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"],"time_series":{"start_time":"2021-01-01T00:00:00Z","end_time":"2021-01-02T00:00:00Z"}}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"bytes":{"type":"long","time_series_metric":"counter"}}}
	}`, nil)
	bulkRateRec := doRound65Req(t, h, http.MethodPost, "/ts_rate_r66/_bulk?refresh=true",
		`{"index":{}}`+"\n"+`{"@timestamp":"2021-01-01T00:00:10Z","host":"h1","bytes":100}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2021-01-01T00:00:30Z","host":"h1","bytes":300}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2021-01-01T00:00:40Z","host":"h1","bytes":50}`+"\n"+
			`{"index":{}}`+"\n"+`{"@timestamp":"2021-01-01T00:00:50Z","host":"h1","bytes":150}`+"\n", nil)
	if bulkRateRec.Code != http.StatusOK || strings.Contains(bulkRateRec.Body.String(), `"errors":true`) {
		t.Fatalf("tsdb bulk failed: %d %s", bulkRateRec.Code, bulkRateRec.Body.String())
	}
	rateRec := doRound65Req(t, h, http.MethodPost, "/ts_rate_r66/_search", `{
		"size":0,
		"query":{"range":{"@timestamp":{"gte":"2021-01-01T00:00:00Z","lte":"2021-01-01T01:00:00Z"}}},
		"aggs":{
			"dh":{
				"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1},
				"aggs":{
					"ts":{
						"time_series":{"keyed":false},
						"aggs":{"r":{"rate":{"field":"bytes","unit":"second"}}}
					}
				}
			}
		}
	}`, nil)
	if rateRec.Code != http.StatusOK {
		t.Fatalf("tsdb rate failed: %d %s", rateRec.Code, rateRec.Body.String())
	}
	var rateResp map[string]any
	_ = json.Unmarshal(rateRec.Body.Bytes(), &rateResp)
	dhBuckets, _ := rateResp["aggregations"].(map[string]any)["dh"].(map[string]any)["buckets"].([]any)
	if len(dhBuckets) != 1 {
		t.Fatalf("expected 1 date_histogram bucket, got %d (%s)", len(dhBuckets), rateRec.Body.String())
	}
	tsBuckets := dhBuckets[0].(map[string]any)["ts"].(map[string]any)["buckets"].([]any)
	if len(tsBuckets) != 1 {
		t.Fatalf("expected 1 time_series bucket, got %d (%s)", len(tsBuckets), rateRec.Body.String())
	}
	val, _ := tsBuckets[0].(map[string]any)["r"].(map[string]any)["value"].(float64)
	// Counter delta across reset: (300-100) + 50 + (150-50) = 350 over (50s - 10s = 40s) -> 8.75 / sec
	if math.Abs(val-(350.0/40.0)) > 1e-6 {
		t.Fatalf("expected counter rate ~%v, got %v (%s)", 350.0/40.0, val, rateRec.Body.String())
	}
}

func TestRound66Cluster5OffsetCluster6ImplicitSortCluster7GeoGrid(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Cluster 5: non-aligned timezone emits downsampled_results_offset: true
	_ = doRound65Req(t, h, http.MethodPut, "/ds_off_src", `{
		"settings":{"number_of_shards":1,"index":{"mode":"time_series","routing_path":["uid"],"time_series":{"start_time":"2020-03-01T00:00:00Z","end_time":"2020-03-30T00:00:00Z"}}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"uid":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}
	}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ds_off_src/_doc?refresh=true", `{"@timestamp":"2020-03-09T03:00:00Z","uid":"u1","m":10}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/ds_off_src/_settings", `{"index.blocks.write":true}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ds_off_src/_downsample/ds_off_tgt", `{"fixed_interval":"1h"}`, nil)
	offRec := doRound65Req(t, h, http.MethodPost, "/ds_off_tgt/_search", `{"size":0,"aggs":{"dh":{"date_histogram":{"field":"@timestamp","fixed_interval":"1h","time_zone":"-01:15"}}}}`, nil)
	if offRec.Code != http.StatusOK || !strings.Contains(offRec.Body.String(), `"downsampled_results_offset":true`) {
		t.Fatalf("expected downsampled_results_offset:true, got %d %s", offRec.Code, offRec.Body.String())
	}

	// Cluster 6: ImplicitTimestampSort lifecycle (explicit at create vs dynamic + close/open)
	_ = doRound65Req(t, h, http.MethodPut, "/ts_exp_sort", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ts_exp_sort/_bulk?refresh=true",
		`{"index":{"_id":"a"}}`+"\n"+`{"@timestamp":"2022-01-01T00:00:00Z"}`+"\n"+
			`{"index":{"_id":"b"}}`+"\n"+`{"@timestamp":"2022-01-02T00:00:00Z"}`+"\n", nil)
	expSearch := doRound65Req(t, h, http.MethodPost, "/ts_exp_sort/_search", `{"query":{"match_all":{}}}`, nil)
	var expResp map[string]any
	_ = json.Unmarshal(expSearch.Body.Bytes(), &expResp)
	expHits := expResp["hits"].(map[string]any)["hits"].([]any)
	if expHits[0].(map[string]any)["_id"] != "b" {
		t.Fatalf("expected explicit @timestamp index default sort @timestamp DESC ('b' first), got %s", expSearch.Body.String())
	}

	_ = doRound65Req(t, h, http.MethodPut, "/ts_dyn_sort", `{}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ts_dyn_sort/_bulk?refresh=true",
		`{"index":{"_id":"a"}}`+"\n"+`{"@timestamp":"2022-01-01T00:00:00Z"}`+"\n"+
			`{"index":{"_id":"b"}}`+"\n"+`{"@timestamp":"2022-01-02T00:00:00Z"}`+"\n", nil)
	dynBefore := doRound65Req(t, h, http.MethodPost, "/ts_dyn_sort/_search", `{"query":{"match_all":{}}}`, nil)
	var dynBeforeResp map[string]any
	_ = json.Unmarshal(dynBefore.Body.Bytes(), &dynBeforeResp)
	if dynBeforeResp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_id"] != "a" {
		t.Fatalf("expected dynamic @timestamp index before close/open to sort by _id asc ('a' first), got %s", dynBefore.Body.String())
	}
	_ = doRound65Req(t, h, http.MethodPost, "/ts_dyn_sort/_close", ``, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ts_dyn_sort/_open", ``, nil)
	dynAfter := doRound65Req(t, h, http.MethodPost, "/ts_dyn_sort/_search", `{"query":{"match_all":{}}}`, nil)
	var dynAfterResp map[string]any
	_ = json.Unmarshal(dynAfter.Body.Bytes(), &dynAfterResp)
	if dynAfterResp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_id"] != "b" {
		t.Fatalf("expected dynamic @timestamp index after close/open to sort @timestamp DESC ('b' first), got %s", dynAfter.Body.String())
	}

	// Cluster 7: Java Math.toDegrees(atan(sinh)) 1-ULP precision for geotile ingest processor
	gotLat := geotileYToLatJavaR66(1, 2.0)
	if gotLat != 0.0 {
		t.Fatalf("expected geotileYToLatJavaR66(1, 2.0) == 0.0, got %v", gotLat)
	}
	docGG := map[string]any{"cell": "1/0/0"}
	if err := ApplyGeoGridProcessorR64(docGG, map[string]any{"field": "cell", "tile_type": "geotile", "target_field": "shape", "target_format": "wkt"}); err != nil {
		t.Fatalf("ApplyGeoGridProcessorR64 failed: %v", err)
	}
	if wkt, _ := docGG["shape"].(string); !strings.HasPrefix(wkt, "BBOX (") {
		t.Fatalf("expected BBOX WKT, got %v", docGG["shape"])
	}
}

func TestRound66Cluster8SignificantTextAndCluster9PartialTopHitsSort(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Cluster 8: significant_text profile + annotated_text stripping + overwrite heuristic reset on _forcemerge
	_ = doRound65Req(t, h, http.MethodPut, "/sig_r66", `{"mappings":{"properties":{"txt":{"type":"text"},"ann":{"type":"annotated_text"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/sig_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"txt":"good good rareterm","ann":"[Apple](Apple Inc.) gadget"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"txt":"bad word","ann":"Banana fruit"}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"txt":"bad word","ann":"Carrot veg"}`+"\n", nil)
	profRec := doRound65Req(t, h, http.MethodPost, "/sig_r66/_search", `{
		"size":0,"profile":true,
		"query":{"match":{"txt":"good"}},
		"aggs":{
			"st":{"significant_text":{"field":"txt"}},
			"sa":{"significant_text":{"field":"ann","min_doc_count":1}}
		}
	}`, nil)
	if profRec.Code != http.StatusOK {
		t.Fatalf("significant_text profile failed: %d %s", profRec.Code, profRec.Body.String())
	}
	profStr := profRec.Body.String()
	for _, key := range []string{`"total_buckets"`, `"values_fetched"`, `"chars_fetched"`, `"extract_ns"`, `"extract_count"`, `"collect_analyzed_ns"`, `"collect_analyzed_count"`} {
		if !strings.Contains(profStr, key) {
			t.Fatalf("expected profile debug key %s in response: %s", key, profStr)
		}
	}
	if strings.Contains(profStr, `"key":"inc"`) {
		t.Fatalf("expected annotated_text payload '(Apple Inc.)' stripped before significant_text tokens, got %s", profStr)
	}
	// Force merge clears unmerged/deleted heuristic history cleanly
	_ = doRound65Req(t, h, http.MethodPost, "/sig_r66/_doc/1?refresh=true", `{"txt":"good replaced","ann":"Apple gadget"}`, nil)
	fmRec := doRound65Req(t, h, http.MethodPost, "/sig_r66/_forcemerge?max_num_segments=1", ``, nil)
	if fmRec.Code != http.StatusOK {
		t.Fatalf("forcemerge failed: %d %s", fmRec.Code, fmRec.Body.String())
	}
	srv.mu.RLock()
	leftDeleted := len(srv.unmergedDeletedSources["sig_r66"])
	srv.mu.RUnlock()
	if leftDeleted != 0 {
		t.Fatalf("expected _forcemerge to clear unmergedDeletedSources, got %d", leftDeleted)
	}

	// Cluster 9: partial shard failure for unmapped nested top_hits.sort
	_ = doRound65Req(t, h, http.MethodPut, "/c9_other", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/c9_other/_doc/1?refresh=true", `{"k":"v"}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/c9_test", `{
		"mappings":{
			"runtime":{"users.last_script":{"type":"keyword","script":"emit(doc['users.last'].value)"}},
			"properties":{"users":{"type":"nested","properties":{"last":{"type":"keyword"}}}}
		}
	}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/c9_test/_doc/1?refresh=true", `{"users":[{"last":"Smith"}]}`, nil)
	partRec := doRound65Req(t, h, http.MethodPost, "/c9_other,c9_test/_search", `{
		"aggs":{"to-users":{"nested":{"path":"users"},"aggs":{"u":{"top_hits":{"sort":"users.last_script"}}}}}
	}`, nil)
	if partRec.Code != http.StatusOK {
		t.Fatalf("partial search failed: %d %s", partRec.Code, partRec.Body.String())
	}
	var partResp map[string]any
	_ = json.Unmarshal(partRec.Body.Bytes(), &partResp)
	if int(partResp["_shards"].(map[string]any)["failed"].(float64)) < 1 {
		t.Fatalf("expected _shards.failed >= 1, got %v", partResp["_shards"])
	}
	if int(partResp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)) != 1 {
		t.Fatalf("expected hits.total.value == 1 from c9_test only, got %v", partResp["hits"])
	}
	strictRec := doRound65Req(t, h, http.MethodPost, "/c9_other,c9_test/_search?allow_partial_search_results=false", `{
		"aggs":{"to-users":{"nested":{"path":"users"},"aggs":{"u":{"top_hits":{"sort":"users.last_script"}}}}}
	}`, nil)
	if strictRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when allow_partial_search_results=false, got %d %s", strictRec.Code, strictRec.Body.String())
	}
}

func TestRound66Cluster10TopMetricsCluster11MatchedFieldsCluster13RRF(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Cluster 10: top_metrics sort by score & geo_distance quantization
	_ = doRound65Req(t, h, http.MethodPut, "/tm_r66", `{"mappings":{"properties":{"loc":{"type":"geo_point"},"pop":{"type":"long"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/tm_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"loc":{"lat":40.7128,"lon":-74.006},"msg":"hello world","pop":8623000}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"loc":{"lat":34.0522,"lon":-118.2437},"msg":"hello","pop":4000000}`+"\n", nil)
	tmRec := doRound65Req(t, h, http.MethodPost, "/tm_r66/_search", `{
		"size":0,
		"query":{"match":{"msg":"hello"}},
		"aggs":{
			"by_sc":{"top_metrics":{"metrics":{"field":"pop"},"sort":{"_score":"desc"}}},
			"by_geo":{"top_metrics":{"metrics":{"field":"pop"},"sort":{"_geo_distance":{"loc":"POINT (-78.6382 35.7796)"}}}}
		}
	}`, nil)
	if tmRec.Code != http.StatusOK {
		t.Fatalf("top_metrics failed: %d %s", tmRec.Code, tmRec.Body.String())
	}
	var tmResp map[string]any
	_ = json.Unmarshal(tmRec.Body.Bytes(), &tmResp)
	geoDist := tmResp["aggregations"].(map[string]any)["by_geo"].(map[string]any)["top"].([]any)[0].(map[string]any)["sort"].([]any)[0].(float64)
	if math.Abs(geoDist-681335.0456554737) > 1e-6 {
		t.Fatalf("expected Lucene-quantized geo_distance 681335.0456554737, got %v", geoDist)
	}

	// Cluster 11: unified matched_fields (phrase slop on english + edge_ngram)
	_ = doRound65Req(t, h, http.MethodPut, "/hl_mf_r66", `{
		"settings":{
			"analysis":{
				"filter":{"my_edge_ngram":{"type":"edge_ngram","min_gram":2,"max_gram":20}},
				"analyzer":{"my_analyzer":{"tokenizer":"whitespace","filter":["my_edge_ngram"]}}
			}
		},
		"mappings":{
			"properties":{
				"title":{
					"type":"text",
					"fields":{
						"english":{"type":"text","analyzer":"english"},
						"ngram":{"type":"text","analyzer":"my_analyzer"}
					}
				}
			}
		}
	}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/hl_mf_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"dancing with the stars"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"title":"dance with star"}`+"\n", nil)
	hl1 := doRound65Req(t, h, http.MethodPost, "/hl_mf_r66/_search", `{
		"query":{"query_string":{"query":"\"dancing with the stars\"","fields":["title^5","title.english"],"phrase_slop":2}},
		"highlight":{"fields":{"title":{"matched_fields":["title.english"]}}}
	}`, nil)
	if !strings.Contains(hl1.Body.String(), `<em>dance with star</em>`) {
		t.Fatalf("expected phrase matched_fields highlight on stemmed doc, got %s", hl1.Body.String())
	}
	hl2 := doRound65Req(t, h, http.MethodPost, "/hl_mf_r66/_search", `{
		"query":{"query_string":{"query":"dan with star","fields":["title^5","title.ngram","title.english"]}},
		"highlight":{"fields":{"title":{"matched_fields":["title.ngram","title.english"]}}}
	}`, nil)
	if !strings.Contains(hl2.Body.String(), `<em>dance</em> <em>with</em> <em>star</em>`) || !strings.Contains(hl2.Body.String(), `<em>dancing</em> <em>with</em> the <em>stars</em>`) {
		t.Fatalf("expected multiple matched_fields token spans, got %s", hl2.Body.String())
	}

	// Cluster 13: RRF multi-shard knn tie-break ("3" shard 0 beats "1" shard 4)
	_ = doRound65Req(t, h, http.MethodPut, "/rrf_r66", `{
		"settings":{"number_of_shards":5,"number_of_replicas":0},
		"mappings":{"properties":{"text":{"type":"text"},"keyword":{"type":"keyword"},"vector":{"type":"dense_vector","dims":1,"index":true,"similarity":"l2_norm"}}}
	}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/rrf_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"text":"term term","keyword":"other","vector":[0.0]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"text":"other","keyword":"other","vector":[1.0]}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"text":"term","keyword":"keyword","vector":[2.0]}`+"\n", nil)
	rrfRec := doRound65Req(t, h, http.MethodPost, "/rrf_r66/_search", `{
		"size":1,
		"track_total_hits":true,
		"retriever":{"rrf":{
			"retrievers":[
				{"knn":{"field":"vector","query_vector":[0.0],"k":3,"num_candidates":3}},
				{"knn":{"field":"vector","query_vector":[1.0],"k":3,"num_candidates":3}},
				{"standard":{"query":{"term":{"text":"term"}}}},
				{"standard":{"query":{"match":{"keyword":"keyword"}}}}
			],
			"rank_window_size":2,
			"rank_constant":1
		}}
	}`, nil)
	if rrfRec.Code != http.StatusOK {
		t.Fatalf("rrf failed: %d %s", rrfRec.Code, rrfRec.Body.String())
	}
	var rrfResp map[string]any
	_ = json.Unmarshal(rrfRec.Body.Bytes(), &rrfResp)
	topID := rrfResp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_id"]
	if topID != "3" {
		t.Fatalf("expected RRF shard tie-break to rank _id '3' first, got %v (%s)", topID, rrfRec.Body.String())
	}
}

func TestRound66Cluster14IngestCluster15InnerHitsCluster16Capabilities(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Cluster 14a: uppercase non-string simulate error returns illegal_argument_exception
	simRec := doRound65Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline":{"processors":[{"uppercase":{"field":"f"}}]},
		"docs":[{"_index":"idx","_id":"1","_source":{"f":true}}]
	}`, nil)
	if simRec.Code != http.StatusOK || !strings.Contains(simRec.Body.String(), `"type":"illegal_argument_exception"`) {
		t.Fatalf("expected illegal_argument_exception in simulate, got %d %s", simRec.Code, simRec.Body.String())
	}

	// Cluster 14b: reroute with lazy rollover on destination data stream
	_ = doRound65Req(t, h, http.MethodPut, "/_ingest/pipeline/r66_rr1", `{"processors":[{"reroute":{"destination":"r66-ds2"}}]}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_ingest/pipeline/r66_rr2", `{"processors":[{"reroute":{"destination":"r66-ds3"}}]}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_index_template/r66_t1", `{"index_patterns":["r66-ds1"],"priority":1,"data_stream":{},"template":{"settings":{"index.default_pipeline":"r66_rr1"}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_index_template/r66_t2", `{"index_patterns":["r66-ds2"],"priority":1,"data_stream":{},"template":{"settings":{"index.default_pipeline":"r66_rr2"}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_index_template/r66_t3", `{"index_patterns":["r66-ds3"],"priority":1,"data_stream":{}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_data_stream/r66-ds1", ``, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_data_stream/r66-ds2", ``, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_data_stream/r66-ds3", ``, nil)
	// Update ds2 template to remove default_pipeline and mark ds2 lazy rollover
	_ = doRound65Req(t, h, http.MethodPut, "/_index_template/r66_t2_v2", `{"index_patterns":["r66-ds2"],"priority":2,"data_stream":{}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/r66-ds2/_rollover?lazy=true", `{}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/r66-ds1/_doc?refresh=true", `{"@timestamp":"2020-12-12T00:00:00Z","x":1}`, nil)
	ds2Rec := doRound65Req(t, h, http.MethodPost, "/r66-ds2/_search?refresh=true", `{"query":{"match_all":{}}}`, nil)
	var ds2Resp map[string]any
	_ = json.Unmarshal(ds2Rec.Body.Bytes(), &ds2Resp)
	if int(ds2Resp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)) != 1 {
		t.Fatalf("expected doc stopped in r66-ds2 after destination lazy rollover, got %s", ds2Rec.Body.String())
	}

	// Cluster 15: empty boxplot NaN + join inner_hits empty envelope on non-matching sibling hit
	_ = doRound65Req(t, h, http.MethodPut, "/bp_r66", `{"mappings":{"properties":{"n":{"type":"long"}}}}`, nil)
	bpRec := doRound65Req(t, h, http.MethodPost, "/bp_r66/_search", `{"size":0,"aggs":{"b":{"boxplot":{"field":"n"}}}}`, nil)
	if !strings.Contains(bpRec.Body.String(), `"min":"NaN"`) {
		t.Fatalf("expected NaN strings for empty ES8 boxplot, got %s", bpRec.Body.String())
	}
	_ = doRound65Req(t, h, http.MethodPut, "/pj_r66", `{"mappings":{"properties":{"kind":{"type":"keyword"},"rel":{"type":"join","relations":{"q":"a","p":"addr"}}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/pj_r66/_doc/1", `{"kind":"q","rel":{"name":"q"}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/pj_r66/_doc/2?routing=1", `{"kind":"a","rel":{"name":"a","parent":"1"}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/pj_r66/_doc/3?refresh=true", `{"kind":"p","rel":{"name":"p"}}`, nil)
	pjRec := doRound65Req(t, h, http.MethodPost, "/pj_r66/_search", `{
		"query":{"bool":{"should":[{"term":{"kind":"p"}},{"has_parent":{"parent_type":"q","query":{"match_all":{}},"inner_hits":{}}}]}}
	}`, nil)
	var pjResp map[string]any
	_ = json.Unmarshal(pjRec.Body.Bytes(), &pjResp)
	pjHits := pjResp["hits"].(map[string]any)["hits"].([]any)
	if len(pjHits) != 2 {
		t.Fatalf("expected 2 join/sibling hits, got %s", pjRec.Body.String())
	}
	ihQ := pjHits[0].(map[string]any)["inner_hits"].(map[string]any)["q"].(map[string]any)["hits"].(map[string]any)
	if int(ihQ["total"].(map[string]any)["value"].(float64)) != 0 {
		t.Fatalf("expected empty inner_hits envelope with total.value=0 on sibling hit, got %s", pjRec.Body.String())
	}

	// Cluster 16: capabilities cleanup preserves lazy_rollover_failure_store=false while allowing pruned caps
	capOK := doRound65Req(t, h, http.MethodGet, "/_capabilities?method=PUT&path=/{index}&capabilities=failure_store,esql_async,esql_enrich", ``, nil)
	var capOKResp map[string]any
	_ = json.Unmarshal(capOK.Body.Bytes(), &capOKResp)
	if capOKResp["supported"] != true {
		t.Fatalf("expected pruned capabilities supported=true, got %s", capOK.Body.String())
	}
	capNo := doRound65Req(t, h, http.MethodGet, "/_capabilities?method=PUT&path=/{index}&capabilities=lazy_rollover_failure_store", ``, nil)
	var capNoResp map[string]any
	_ = json.Unmarshal(capNo.Body.Bytes(), &capNoResp)
	if capNoResp["supported"] != false {
		t.Fatalf("expected lazy_rollover_failure_store supported=false, got %s", capNo.Body.String())
	}
}

func TestRound66Wave25_FinalFiveClosures(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// 1. date_histogram extended_bounds + offset + unmapped nested index omits pre-min 2015-12-31 bucket (`aggregations/histogram.yml`)
	_ = doRound65Req(t, h, http.MethodPut, "/dh_r66_nested", `{"mappings":{"properties":{"foo":{"type":"nested"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/dh_r66_nested/_bulk?refresh=true",
		`{"index":{}}`+"\n"+`{"foo":{"date":"2016-01-02"}}`+"\n"+`{"index":{}}`+"\n"+`{"foo":{"date":"2016-01-03"}}`+"\n", nil)
	_ = doRound65Req(t, h, http.MethodPut, "/dh_r66_unmapped", `{}`, nil)
	dhRec := doRound65Req(t, h, http.MethodPost, "/dh_r66_*/_search", `{
		"size":0,
		"aggs":{
			"foo":{
				"nested":{"path":"foo"},
				"aggs":{"histo":{"date_histogram":{"field":"foo.date","calendar_interval":"day","offset":"1h","extended_bounds":{"min":"2016-01-01","max":"2016-01-04"}}}}
			}
		}
	}`, nil)
	if dhRec.Code != http.StatusOK {
		t.Fatalf("dh search failed: %d %s", dhRec.Code, dhRec.Body.String())
	}
	var dhResp map[string]any
	_ = json.Unmarshal(dhRec.Body.Bytes(), &dhResp)
	dhBuckets := dhResp["aggregations"].(map[string]any)["foo"].(map[string]any)["histo"].(map[string]any)["buckets"].([]any)
	if len(dhBuckets) != 4 || dhBuckets[0].(map[string]any)["key_as_string"] != "2016-01-01T01:00:00.000Z" {
		t.Fatalf("expected 4 buckets starting 2016-01-01T01:00:00.000Z, got %s", dhRec.Body.String())
	}

	// 2. TSDB data_stream without explicit routing_path allows PUT _settings & downsample (`downsample/60_settings.yml`)
	_ = doRound65Req(t, h, http.MethodPut, "/_index_template/ds_ts_r66_tpl", `{
		"index_patterns":["ds-ts-r66-*"],
		"data_stream":{},
		"template":{
			"settings":{"index":{"mode":"time_series","routing":{"allocation":{"include":{"_tier_preference":"data_warm"}}},"lifecycle":{"name":"dummy-lc"}}},
			"mappings":{"properties":{"@timestamp":{"type":"date"},"metricset":{"type":"keyword","time_series_dimension":true},"val":{"type":"double","time_series_metric":"gauge"}}}
		}
	}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/_data_stream/ds-ts-r66-a", ``, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/ds-ts-r66-a/_bulk?refresh=true", `{"index":{}}`+"\n"+`{"@timestamp":"2021-04-28T18:50:04.467Z","metricset":"pod","val":10}`+"\n", nil)
	dsInfo := doRound65Req(t, h, http.MethodGet, "/_data_stream/ds-ts-r66-a", ``, nil)
	var dsObj map[string]any
	_ = json.Unmarshal(dsInfo.Body.Bytes(), &dsObj)
	backingIdx := dsObj["data_streams"].([]any)[0].(map[string]any)["indices"].([]any)[0].(map[string]any)["index_name"].(string)
	if putSet := doRound65Req(t, h, http.MethodPut, "/"+backingIdx+"/_settings", `{"index.blocks.write":true}`, nil); putSet.Code != http.StatusOK {
		t.Fatalf("expected PUT _settings 200 on TSDB data_stream backing index %s, got %d %s", backingIdx, putSet.Code, putSet.Body.String())
	}

	// 3. long_range Null bounds exact MinInt64/MaxInt64 term matching (`range/10_basic.yml`)
	_ = doRound65Req(t, h, http.MethodPut, "/lr_null_r66", `{"mappings":{"properties":{"lr":{"type":"long_range"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/lr_null_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"lr":{"gt":null,"lte":5}}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"lr":{"gte":null,"lte":5}}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"lr":{"lte":5}}`+"\n", nil)
	lrSearch := doRound65Req(t, h, http.MethodPost, "/lr_null_r66/_search?rest_total_hits_as_int=true", `{"size":0,"query":{"term":{"lr":{"value":-9223372036854775808}}}}`, nil)
	var lrResp map[string]any
	_ = json.Unmarshal(lrSearch.Body.Bytes(), &lrResp)
	if int(lrResp["hits"].(map[string]any)["total"].(float64)) != 2 {
		t.Fatalf("expected 2 hits for MinInt64 term on long_range gt:null, got %s", lrSearch.Body.String())
	}

	// 4. multi-value sparse_vector exists excludes empty [] while keeping empty {} (`search.vectors/90_sparse_vector.yml`) + JSON_LENGTH
	_ = doRound65Req(t, h, http.MethodPut, "/sv_exists_r66", `{"mappings":{"properties":{"ml.tokens":{"type":"sparse_vector"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPost, "/sv_exists_r66/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"ml":{"tokens":[{"a":1.0}]}}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"ml":{"tokens":{"b":2.0}}}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"ml":{"tokens":[]}}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"ml":{"tokens":{}}}`+"\n", nil)
	svSearch := doRound65Req(t, h, http.MethodPost, "/sv_exists_r66/_search?rest_total_hits_as_int=true", `{"query":{"exists":{"field":"ml.tokens"}}}`, nil)
	var svResp map[string]any
	_ = json.Unmarshal(svSearch.Body.Bytes(), &svResp)
	if int(svResp["hits"].(map[string]any)["total"].(float64)) != 3 {
		t.Fatalf("expected 3 hits for exists on sparse_vector (excluding [] but keeping {}), got %s", svSearch.Body.String())
	}
	sampleRow := map[string]any{"_source": `{"ml":{"tokens":["a","b"]},"obj":{"k":1},"s":"x"}`}
	if lArr, okA := evalColumnFuncR63Mem(sampleRow, `JSON_LENGTH(TRY_CAST(`+"`_source`"+` AS JSON), '$."ml"."tokens"')`); !okA || lArr != int64(2) {
		t.Fatalf("JSON_LENGTH array = (%#v, %v)", lArr, okA)
	}
	if lObj, okO := evalColumnFuncR63Mem(sampleRow, `JSON_LENGTH(TRY_CAST(`+"`_source`"+` AS JSON))`); !okO || lObj != int64(3) {
		t.Fatalf("JSON_LENGTH root obj = (%#v, %v)", lObj, okO)
	}
	if lSc, okS := evalColumnFuncR63Mem(sampleRow, `JSON_LENGTH(TRY_CAST(`+"`_source`"+` AS JSON), '$."s"')`); !okS || lSc != int64(1) {
		t.Fatalf("JSON_LENGTH scalar = (%#v, %v)", lSc, okS)
	}
}
