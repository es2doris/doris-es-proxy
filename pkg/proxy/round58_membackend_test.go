package proxy

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func indexRound58Docs(t *testing.T, mb *MemoryBackend, idxSchema *schema.IndexSchema, docs map[string]string) {
	t.Helper()
	ctx := context.Background()
	var lines []string
	for id, raw := range docs {
		rowBytes, err := schema.ShredDocument(idxSchema, id, 1, false, []byte(raw))
		if err != nil {
			t.Fatalf("shred doc %s failed: %v", id, err)
		}
		lines = append(lines, string(rowBytes))
	}
	if err := mb.StreamLoad(ctx, idxSchema.DorisTable, []byte(strings.Join(lines, "\n")), false); err != nil {
		t.Fatalf("StreamLoad failed: %v", err)
	}
}

func TestRound58MemBackend_IPCanonicalOrderAndRange_F11(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"ip":{"type":"ip"},"ips":{"type":"ip"}}}`), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_db", "r58_ip", &spec)
	mb := NewMemoryBackend(false)
	indexRound58Docs(t, mb, idxSchema, map[string]string{
		"1": `{"ip":"::1","ips":["::1","2001:db8::5"]}`,
		"2": `{"ip":"10.0.0.2","ips":["10.0.0.2"]}`,
		"3": `{"ip":"10.0.0.10","ips":["10.0.0.10"]}`,
		"4": `{"ip":"2001:db8::2","ips":["2001:db8::2"]}`,
		"5": `{"ip":"2001:db8::10","ips":["2001:db8::10"]}`,
		"6": `{}`,
	})
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	ctx := context.Background()

	// Asc sort with missing=_last: ::1 < 10.0.0.2 < 10.0.0.10 < 2001:db8::2 < 2001:db8::10 < null
	var srSort esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"size":10,"sort":[{"ip":{"order":"asc","missing":"_last"}}]}`), &srSort); err != nil {
		t.Fatal(err)
	}
	plan, err := tr.BuildSearchPlan(&srSort)
	if err != nil {
		t.Fatal(err)
	}
	hits, err := mb.QueryHits(ctx, plan.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"1", "2", "3", "4", "5", "6"}
	if len(hits) != len(wantOrder) {
		t.Fatalf("expected %d hits, got %d", len(wantOrder), len(hits))
	}
	for i, w := range wantOrder {
		if hits[i].ID != w {
			t.Fatalf("hit[%d] got ID=%s, want %s", i, hits[i].ID, w)
		}
	}

	// search_after ["10.0.0.10"] should return 4, 5, 6
	var srAfter esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"size":10,"sort":[{"ip":{"order":"asc"}}],"search_after":["10.0.0.10"]}`), &srAfter); err != nil {
		t.Fatal(err)
	}
	planAfter, err := tr.BuildSearchPlan(&srAfter)
	if err != nil {
		t.Fatal(err)
	}
	afterHits, err := mb.QueryHits(ctx, planAfter.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterHits) != 3 || afterHits[0].ID != "4" || afterHits[1].ID != "5" || afterHits[2].ID != "6" {
		t.Fatalf("unexpected search_after hits: %+v", afterHits)
	}

	// Cross-family range ["::1", "2001:db8::2"] includes IPv4 10.0.0.2 and 10.0.0.10
	var srRange esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query":{"range":{"ip":{"gte":"::1","lte":"2001:db8::2"}}},
		"aggs":{"r":{"ip_range":{"field":"ip","ranges":[{"from":"::1","to":"2001:db8::2"}]}}}
	}`), &srRange); err != nil {
		t.Fatal(err)
	}
	planRange, err := tr.BuildSearchPlan(&srRange)
	if err != nil {
		t.Fatal(err)
	}
	rHits, err := mb.QueryHits(ctx, planRange.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(rHits) != 4 {
		t.Fatalf("expected 4 cross-family IP range hits (1,2,3,4), got %d", len(rHits))
	}
	aggRows, err := mb.QueryAggs(ctx, planRange.AggsSQL)
	if err != nil {
		t.Fatal(err)
	}
	var foundIPRange bool
	for _, ar := range aggRows {
		if ar.AggName == "r" && ar.DocCount == 3 {
			foundIPRange = true
		}
	}
	if !foundIPRange {
		t.Fatalf("expected ip_range bucket doc_count=3 (::1, 10.0.0.2, 10.0.0.10 before exclusive 2001:db8::2), got %+v", aggRows)
	}
}

func TestRound58MemBackend_DateNanosAndDateRange_F10_F12(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"ts": {"type": "date_nanos"},
			"win": {"type": "date_range"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_db", "r58_dn", &spec)
	mb := NewMemoryBackend(false)
	indexRound58Docs(t, mb, idxSchema, map[string]string{
		"1": `{"ts":"2025-01-02T03:04:05.100000001Z","win":{"gte":"2025-01-01","lte":"2025-01-02"}}`,
		"2": `{"ts":"2025-01-02T03:04:05.100000002Z","win":{"gt":"2025-01-02","lte":"2025-01-04"}}`,
		"3": `{"ts":"2025-01-02T03:04:05.100000003Z","win":{"gte":"2025-01-05","lte":"2025-01-06"}}`,
	})
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	ctx := context.Background()

	// Sub-millisecond range & sort & date_histogram
	var sr esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {"range": {"ts": {"gt": "2025-01-02T03:04:05.100000001Z", "lte": "2025-01-02T03:04:05.100000003Z"}}},
		"sort": [{"ts": {"order": "desc"}}],
		"aggs": {"dh": {"date_histogram": {"field": "ts", "fixed_interval": "1s"}}}
	}`), &sr); err != nil {
		t.Fatal(err)
	}
	plan, err := tr.BuildSearchPlan(&sr)
	if err != nil {
		t.Fatal(err)
	}
	hits, err := mb.QueryHits(ctx, plan.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].ID != "3" || hits[1].ID != "2" {
		t.Fatalf("expected sub-ms hits [3, 2], got %+v", hits)
	}
	aggs, err := mb.QueryAggs(ctx, plan.AggsSQL)
	if err != nil {
		t.Fatal(err)
	}
	var dhCount int64
	for _, r := range aggs {
		if r.AggName == "dh" {
			dhCount += r.DocCount
		}
	}
	if dhCount != 2 {
		t.Fatalf("expected date_histogram count=2, got %d (%+v)", dhCount, aggs)
	}

	// F10: date_range gt:"2025-01-02" must NOT match doc 1 (lte:2025-01-02) and MUST match docs 2 and 3
	var srDR esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"range":{"win":{"gt":"2025-01-02"}}},"sort":[{"_id":"asc"}]}`), &srDR); err != nil {
		t.Fatal(err)
	}
	planDR, err := tr.BuildSearchPlan(&srDR)
	if err != nil {
		t.Fatal(err)
	}
	drHits, err := mb.QueryHits(ctx, planDR.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(drHits) != 2 || drHits[0].ID != "2" || drHits[1].ID != "3" {
		t.Fatalf("F10 expected docs [2, 3] for win gt 2025-01-02, got %+v", drHits)
	}
}

func TestRound58MemBackend_HistogramRankFeatureAndMustNot_F13_F14_F19(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"grp": {"type": "keyword"},
			"lat": {"type": "histogram"},
			"pr_neg": {"type": "rank_feature", "positive_score_impact": false},
			"title": {"type": "text"},
			"notes": {"type": "text"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_db", "r58_mix", &spec)
	mb := NewMemoryBackend(false)
	indexRound58Docs(t, mb, idxSchema, map[string]string{
		"1": `{"grp":"g1","lat":{"values":[10,20],"counts":[2,3]},"pr_neg":2.0,"title":"alpha service"}`,
		"2": `{"grp":"g1","lat":{"values":[20,40],"counts":[1,4]},"pr_neg":10.0,"notes":"beta worker"}`,
		"3": `{"grp":"g2","lat":{"values":[100],"counts":[0]},"title":"forbidden token"}`,
	})
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	ctx := context.Background()

	// F13: range on histogram (> 0 counts only!) + count-weighted top-level and sub-bucket aggs
	// Total positive counts across docs 1 & 2: 10x2, 20x4, 40x4 -> count=10, sum=20+80+160=260, avg=26, min=10, max=40
	var srHist esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {"range": {"lat": {"gte": 5, "lte": 150}}},
		"aggs": {
			"mn": {"min": {"field": "lat"}},
			"mx": {"max": {"field": "lat"}},
			"sm": {"sum": {"field": "lat"}},
			"av": {"avg": {"field": "lat"}},
			"vc": {"value_count": {"field": "lat"}},
			"st": {"stats": {"field": "lat"}},
			"pc": {"percentiles": {"field": "lat", "percents": [50]}},
			"pr": {"percentile_ranks": {"field": "lat", "values": [20]}},
			"bp": {"boxplot": {"field": "lat"}},
			"hb": {"histogram": {"field": "lat", "interval": 20}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"sub_av": {"avg": {"field": "lat"}},
					"sub_vc": {"value_count": {"field": "lat"}},
					"sub_pc": {"percentiles": {"field": "lat", "percents": [50]}},
					"sub_pr": {"percentile_ranks": {"field": "lat", "values": [20]}}
				}
			}
		}
	}`), &srHist); err != nil {
		t.Fatal(err)
	}
	planH, err := tr.BuildSearchPlan(&srHist)
	if err != nil {
		t.Fatal(err)
	}
	hHits, err := mb.QueryHits(ctx, planH.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(hHits) != 2 {
		t.Fatalf("F13 expected 2 hits with positive histogram counts (doc 3 has count=0), got %d", len(hHits))
	}
	hAggs, err := mb.QueryAggs(ctx, planH.AggsSQL)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]AggRow)
	for _, r := range hAggs {
		byName[r.AggName+":"+r.BucketKey] = r
	}
	if byName["mn:_metric"].Value != 10 || byName["mx:_metric"].Value != 40 || byName["sm:_metric"].Value != 260 || byName["av:_metric"].Value != 26 || byName["vc:_metric"].Value != 10 {
		t.Fatalf("F13 unexpected histogram metrics: %+v", byName)
	}
	if byName["pc:50.0"].Value != 20 || byName["pr:20.0"].Value != 60 {
		t.Fatalf("F13 unexpected histogram percentiles/ranks: pc=%+v pr=%+v", byName["pc:50.0"], byName["pr:20.0"])
	}
	if byName["by_grp.sub_av:g1"].Value != 26 || byName["by_grp.sub_vc:g1"].Value != 10 || byName["by_grp.sub_pc.50.0:g1"].Value != 20 || byName["by_grp.sub_pr.20.0:g1"].Value != 60 {
		t.Fatalf("F13 unexpected sub-agg weighted avg/vc/pc/pr: %+v", hAggs)
	}

	// F14: inverse rank_feature scoring -> smaller pr_neg (doc 1: 2.0) scores higher than larger pr_neg (doc 2: 10.0)
	var srRF esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query":{"rank_feature":{"field":"pr_neg","saturation":{"pivot":4}}}}`), &srRF); err != nil {
		t.Fatal(err)
	}
	planRF, err := tr.BuildSearchPlan(&srRF)
	if err != nil {
		t.Fatal(err)
	}
	rfHits, err := mb.QueryHits(ctx, planRF.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(rfHits) != 2 || rfHits[0].ID != "1" || rfHits[1].ID != "2" || !(rfHits[0].Score > rfHits[1].Score) {
		t.Fatalf("F14 expected doc 1 (pr_neg=2) > doc 2 (pr_neg=10), got %+v", rfHits)
	}

	// F19: must_not multi_match across nullable text fields (doc 1 has notes=NULL, doc 2 has title=NULL) MUST return both docs 1 & 2!
	var srMN esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {"bool": {"must_not": [{"multi_match": {"query": "forbidden", "fields": ["title", "notes", "dyn_missing"]}}]}},
		"sort": [{"_id": "asc"}]
	}`), &srMN); err != nil {
		t.Fatal(err)
	}
	planMN, err := tr.BuildSearchPlan(&srMN)
	if err != nil {
		t.Fatal(err)
	}
	mnHits, err := mb.QueryHits(ctx, planMN.HitsSQL)
	if err != nil {
		t.Fatal(err)
	}
	if len(mnHits) != 2 || mnHits[0].ID != "1" || mnHits[1].ID != "2" {
		t.Fatalf("F19 expected docs [1, 2] to survive NULL-safe must_not multi_match, got %+v", mnHits)
	}
}

func TestRound58TranspilerHooks_AllHelpers(t *testing.T) {
	// F11: compareCanonicalIPValuesRound58
	if cmp, ok := compareCanonicalIPValuesRound58("::1", "10.0.0.1"); !ok || cmp >= 0 {
		t.Fatalf("expected ::1 < 10.0.0.1, got cmp=%d ok=%v", cmp, ok)
	}
	if cmp, ok := compareCanonicalIPValuesRound58([]byte("::ffff:10.0.0.1"), "10.0.0.1"); !ok || cmp != 0 {
		t.Fatalf("expected ::ffff:10.0.0.1 == 10.0.0.1, got cmp=%d ok=%v", cmp, ok)
	}
	if _, ok := compareCanonicalIPValuesRound58("bad", "10.0.0.1"); ok {
		t.Fatalf("expected false on invalid IP")
	}
	if _, ok := canonicalIPHexRound58(nil); ok {
		t.Fatalf("expected false on nil IP")
	}
	if _, ok := canonicalIPHexRound58(123); ok {
		t.Fatalf("expected false on int IP")
	}

	// F12: formatDateNanosEpochRound58, formatDateNanosWithFormatRound58, parseDateNanosValueRound58
	ns := time.Date(2025, 1, 2, 3, 4, 5, 123456789, time.UTC).UnixNano()
	if got := formatDateNanosEpochRound58(ns); got != "2025-01-02T03:04:05.123456789Z" {
		t.Fatalf("unexpected formatted nanos: %s", got)
	}
	// Pre-1970 negative epoch nanos
	negNs := time.Date(1969, 12, 31, 23, 59, 59, 500_000_000, time.UTC).UnixNano()
	if got := formatDateNanosEpochRound58(negNs); got != "1969-12-31T23:59:59.500000000Z" {
		t.Fatalf("unexpected pre-1970 formatted nanos: %s", got)
	}
	if got := formatDateNanosWithFormatRound58(negNs, "epoch_millis"); got != int64(-500) {
		t.Fatalf("expected -500ms, got %v", got)
	}
	if got := formatDateNanosWithFormatRound58(negNs, "epoch_second"); got != int64(-1) {
		t.Fatalf("expected -1s, got %v", got)
	}
	if got := formatDateNanosWithFormatRound58(ns, "epoch_nanos"); got != ns {
		t.Fatalf("expected %d, got %v", ns, got)
	}
	if got := formatDateNanosWithFormatRound58(ns, "strict_date_optional_time"); got != "2025-01-02T03:04:05.123Z" {
		t.Fatalf("unexpected millis format: %v", got)
	}
	if got := formatDateNanosWithFormatRound58(ns, "yyyy-MM-dd"); got != "2025-01-02" {
		t.Fatalf("unexpected custom format: %v", got)
	}
	if pNs, ok := parseDateNanosValueRound58("2025-01-02T03:04:05.123456789Z", ""); !ok || pNs != ns {
		t.Fatalf("parse string nanos failed: %d %v", pNs, ok)
	}
	if pNs, ok := parseDateNanosValueRound58(int64(1735787045123), ""); !ok || pNs != 1735787045123*1_000_000 {
		t.Fatalf("parse epoch_millis int64 failed: %d %v", pNs, ok)
	}
	if pNs, ok := parseDateNanosValueRound58(json.Number("1735787045"), "epoch_second"); !ok || pNs != 1735787045*1_000_000_000 {
		t.Fatalf("parse epoch_second json.Number failed: %d %v", pNs, ok)
	}
	if pNs, ok := parseDateNanosValueRound58(1.5, "epoch_second"); !ok || pNs != 1_500_000_000 {
		t.Fatalf("parse float epoch_second failed: %d %v", pNs, ok)
	}
	if _, ok := parseDateNanosValueRound58(math.NaN(), ""); ok {
		t.Fatalf("expected NaN to fail")
	}

	// F13 & F15: histogram runtime evaluator + searchAsYouTypeSubfieldsRound58
	var mSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"h":{"type":"histogram"},"s2":{"type":"search_as_you_type","max_shingle_size":2}}}`), &mSpec)
	idxSchema := schema.CompileIndexSchema("es_db", "r58_hooks", &mSpec)
	if !isHistogramFieldInSchemaRound58(idxSchema, "h") || isHistogramFieldInSchemaRound58(idxSchema, "s2") || isHistogramFieldInSchemaRound58(nil, "h") {
		t.Fatalf("isHistogramFieldInSchemaRound58 mismatch")
	}
	subs := searchAsYouTypeSubfieldsRound58(idxSchema.ResolveField("s2"))
	if len(subs) != 2 || subs[0] != "._2gram" || subs[1] != "._index_prefix" {
		t.Fatalf("unexpected s2 subfields: %+v", subs)
	}

	sources := []json.RawMessage{
		json.RawMessage(`{"nested":{"h":{"values":[10,20],"counts":[2,3]}}}`),
		json.RawMessage(`{"nested":{"h":[{"values":[20,40],"counts":[1,4]}]}}`),
	}
	aggCases := []string{
		`{"min":{"field":"nested.h"}}`,
		`{"max":{"field":"nested.h"}}`,
		`{"sum":{"field":"nested.h"}}`,
		`{"avg":{"field":"nested.h"}}`,
		`{"value_count":{"field":"nested.h"}}`,
		`{"stats":{"field":"nested.h"}}`,
		`{"percentiles":{"field":"nested.h","percents":[25,50,75]}}`,
		`{"percentile_ranks":{"field":"nested.h","values":[15,20,50]}}`,
		`{"boxplot":{"field":"nested.h"}}`,
		`{"histogram":{"field":"nested.h","interval":10}}`,
	}
	for _, rawSpec := range aggCases {
		var as esast.AggSpec
		if err := json.Unmarshal([]byte(rawSpec), &as); err != nil {
			t.Fatal(err)
		}
		res, ok := evaluateHistogramAggFromSourcesRound58(as, "nested.h", sources)
		if !ok || res == nil {
			t.Fatalf("expected evaluateHistogramAggFromSourcesRound58 ok for %s", rawSpec)
		}
		emptyRes, okEmpty := evaluateHistogramAggFromSourcesRound58(as, "nested.h", nil)
		if !okEmpty || emptyRes == nil {
			t.Fatalf("expected empty evaluateHistogramAggFromSourcesRound58 ok for %s", rawSpec)
		}
	}

	// F16: applyAndValidateURISearchParamsRound58 valid & invalid cases
	okURL := "/idx/_search?q=foo&df=title&default_operator=AND&analyze_wildcard=true&lenient=false&version=true&seq_no_primary_term=false&explain&track_scores=true&min_score=0.5&size=5&from=2&terminate_after=50&batched_reduce_size=16&track_total_hits=100&sort=age:desc,_id&fields=a,b&docvalue_fields=c&_source=d,e&_source_includes=f&_source_excludes=g&stored_fields=_none_&routing=r1"
	reqHTTP := httptest.NewRequest(http.MethodGet, okURL, nil)
	var sr esast.SearchRequest
	if err := applyAndValidateURISearchParamsRound58(reqHTTP, &sr); err != nil {
		t.Fatalf("expected valid URI params to succeed, got %v", err)
	}
	if sr.Size == nil || *sr.Size != 5 || sr.From == nil || *sr.From != 2 || sr.TerminateAfter == nil || *sr.TerminateAfter != 50 || sr.BatchedReduceSize == nil || *sr.BatchedReduceSize != 16 {
		t.Fatalf("unexpected populated SearchRequest: %+v", sr)
	}

	badURLs := []string{
		"/idx/_search?size=abc",
		"/idx/_search?size=-1",
		"/idx/_search?from=abc",
		"/idx/_search?from=-2",
		"/idx/_search?terminate_after=0",
		"/idx/_search?terminate_after=-5",
		"/idx/_search?terminate_after=abc",
		"/idx/_search?batched_reduce_size=0",
		"/idx/_search?batched_reduce_size=abc",
		"/idx/_search?min_score=abc",
		"/idx/_search?min_score=NaN",
		"/idx/_search?track_total_hits=abc",
		"/idx/_search?track_total_hits=-2",
		"/idx/_search?explain=notabool",
		"/idx/_search?version=notabool",
		"/idx/_search?seq_no_primary_term=notabool",
		"/idx/_search?track_scores=notabool",
		"/idx/_search?analyze_wildcard=notabool",
		"/idx/_search?lenient=notabool",
		"/idx/_search?q=hi&default_operator=XOR",
		"/idx/_search?sort=age:sideways",
	}
	for _, bu := range badURLs {
		rBad := httptest.NewRequest(http.MethodGet, bu, nil)
		var srBad esast.SearchRequest
		if err := applyAndValidateURISearchParamsRound58(rBad, &srBad); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("expected illegal_argument_exception for %s, got %v", bu, err)
		}
	}
}
