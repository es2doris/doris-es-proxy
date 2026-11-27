package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR67TFServer(t *testing.T) (*Server, *MemoryBackend) {
	t.Helper()
	be := NewMemoryBackend(false)
	srv := NewServer("test_db", be, transpiler.TranspilerOptions{})
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, be
}

func doR67TFHTTP(t *testing.T, srv *Server, method, path, body string, headers ...[2]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
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

func mustR67TFHTTP(t *testing.T, srv *Server, method, path, body string, wantCode int, headers ...[2]string) map[string]any {
	t.Helper()
	rec := doR67TFHTTP(t, srv, method, path, body, headers...)
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

func r67TFCreateIndexAndDoc(t *testing.T, srv *Server, idx string, mappingsJSON string, docID string, docJSON string) {
	t.Helper()
	if mappingsJSON != "" {
		mustR67TFHTTP(t, srv, http.MethodPut, "/"+idx, mappingsJSON, http.StatusOK)
	} else {
		mustR67TFHTTP(t, srv, http.MethodPut, "/"+idx, `{}`, http.StatusOK)
	}
	if docID != "" && docJSON != "" {
		rec := doR67TFHTTP(t, srv, http.MethodPut, "/"+idx+"/_doc/"+docID+"?refresh=true", docJSON)
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("PUT /%s/_doc/%s failed: status=%d body=%s", idx, docID, rec.Code, rec.Body.String())
		}
	}
}

type r67TFRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f r67TFRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRound67TopUpFeat_CoalescerAndQueryCache(t *testing.T) {
	// 1. batchContainsDocID legacy fallback and edge cases
	if batchContainsDocID(nil, "doc1") {
		t.Fatal("expected false for nil batch")
	}
	if batchContainsDocID(&coalesceBatch{}, "") {
		t.Fatal("expected false for empty docID")
	}
	legacyBatch := &coalesceBatch{
		submissions: []*coalesceSubmission{
			nil,
			{data: []byte(`{"_id":"canceled_doc"}` + "\n"), canceled: true},
			{data: []byte("\n" + `not-json` + "\n" + `{"_id":"other_doc"}` + "\n" + `{"_id":"target_doc"}` + "\n")},
		},
		done: make(chan struct{}),
	}
	if !batchContainsDocID(legacyBatch, "target_doc") {
		t.Fatal("expected legacy fallback to find target_doc")
	}
	if batchContainsDocID(legacyBatch, "canceled_doc") {
		t.Fatal("expected canceled submission to be skipped")
	}
	if batchContainsDocID(legacyBatch, "missing_doc") {
		t.Fatal("expected missing_doc not found")
	}

	// 2. StreamLoadCoalescer Submit, Cancel, FlushTableIfDocPending (inflight), FlushTable, FlushAll
	inLoad := make(chan struct{})
	releaseLoad := make(chan struct{})
	var loadErrMu sync.Mutex
	var returnErr error
	c := newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		if table == "tbl_block" {
			close(inLoad)
			<-releaseLoad
		}
		loadErrMu.Lock()
		err := returnErr
		loadErrMu.Unlock()
		return err
	})
	c.Configure(200*time.Millisecond, 0) // maxBytes <= 0 fallback
	if err := c.Submit(context.Background(), "tbl_empty", []byte("   \n"), false); err != nil {
		t.Fatalf("empty submit error: %v", err)
	}
	canceledCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn()
	if err := c.Submit(canceledCtx, "tbl_empty", []byte(`{"_id":"1"}`), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Empty docID -> FlushTable
	if err := c.FlushTableIfDocPending(context.Background(), "tbl_missing", ""); err != nil {
		t.Fatalf("FlushTableIfDocPending empty docID: %v", err)
	}

	// Cancel one of two submissions sharing the same _id so cnt > 1 branch executes
	ctxA, cancelA := context.WithCancel(context.Background())
	errChA := make(chan error, 1)
	go func() {
		errChA <- c.Submit(ctxA, "tbl_dup", []byte(`{"_id":"dup1"}`+"\n"), false)
	}()
	time.Sleep(10 * time.Millisecond)
	ctxB, cancelB := context.WithCancel(context.Background())
	errChB := make(chan error, 1)
	go func() {
		errChB <- c.Submit(ctxB, "tbl_dup", []byte(`{"_id":"dup1"}`+"\n"), false)
	}()
	time.Sleep(10 * time.Millisecond)
	cancelA()
	if err := <-errChA; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected errChA context.Canceled, got %v", err)
	}
	if err := c.FlushTableIfDocPending(context.Background(), "tbl_dup", "dup1"); err != nil {
		t.Fatalf("FlushTableIfDocPending dup1: %v", err)
	}
	cancelB()
	if err := <-errChB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected errChB nil or context.Canceled, got %v", err)
	}

	// Inflight FlushTableIfDocPending & FlushTable waitBatches
	errBlock := make(chan error, 1)
	go func() {
		errBlock <- c.Submit(context.Background(), "tbl_block", []byte(`{"_id":"inflight_id"}`+"\n"), true)
	}()
	<-inLoad
	waitTimeoutCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	errFlushWait := c.FlushTableIfDocPending(waitTimeoutCtx, "tbl_block", "inflight_id")
	waitCancel()
	if !errors.Is(errFlushWait, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded waiting on inflight, got %v", errFlushWait)
	}
	close(releaseLoad)
	if err := <-errBlock; err != nil {
		t.Fatalf("errBlock: %v", err)
	}

	// Legacy c.batches & c.inflight in FlushTable and FlushAll
	loadErrMu.Lock()
	returnErr = errors.New("boom load")
	loadErrMu.Unlock()
	c.mu.Lock()
	c.batches["tbl_legacy"] = &coalesceBatch{
		submissions: []*coalesceSubmission{{data: []byte(`{"_id":"l1"}` + "\n")}},
		done:        make(chan struct{}),
		timer:       time.AfterFunc(time.Hour, func() {}),
	}
	doneLegacyInflight := make(chan struct{})
	c.inflight[&coalesceBatch{done: doneLegacyInflight, err: errors.New("inflight err")}] = "tbl_legacy"
	c.mu.Unlock()
	close(doneLegacyInflight)
	if err := c.FlushTable(context.Background(), "tbl_legacy"); err == nil {
		t.Fatal("expected FlushTable to return error")
	}

	// FlushAll with already expired deadline
	expCtx, expCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	if err := c.FlushAll(expCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded on expired FlushAll, got %v", err)
	}
	expCancel()

	// FlushAll with > maxConcurrentCoalescerFlushes tables and tight deadline to exercise sem select <-ctx.Done()
	cSlow := newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	cSlow.Configure(time.Hour, 1024*1024)
	for i := 0; i < maxConcurrentCoalescerFlushes+4; i++ {
		tbl := fmt.Sprintf("tbl_sem_%d", i)
		sh := cSlow.getOrCreateShard(tbl)
		sh.mu.Lock()
		sh.batch = &coalesceBatch{
			submissions: []*coalesceSubmission{{data: []byte(`{"_id":"x"}` + "\n")}},
			done:        make(chan struct{}),
			timer:       time.AfterFunc(time.Hour, func() {}),
		}
		sh.mu.Unlock()
	}
	cSlow.mu.Lock()
	cSlow.batches["tbl_legacy_sem"] = &coalesceBatch{
		submissions: []*coalesceSubmission{{data: []byte(`{"_id":"y"}` + "\n")}},
		done:        make(chan struct{}),
		timer:       time.AfterFunc(time.Hour, func() {}),
	}
	infWait := &coalesceBatch{done: make(chan struct{})}
	cSlow.inflight[infWait] = "tbl_legacy_inf"
	cSlow.mu.Unlock()
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	_ = cSlow.FlushAll(dlCtx)
	dlCancel()
	close(infWait.done)

	// Closed coalescer Submit path
	_ = c.Close(context.Background())
	loadErrMu.Lock()
	returnErr = nil
	loadErrMu.Unlock()
	if err := c.Submit(context.Background(), "tbl_closed", []byte(`{"_id":"z"}`+"\n"), false); err != nil {
		t.Fatalf("closed submit should delegate to loadFn: %v", err)
	}

	// 3. QueryResultCache and now date-math detection
	var nilQC *QueryResultCache
	nilQC.SetSecurityEpochFunc(func() uint64 { return 1 })
	if nilQC.currentSecurityEpoch() != 0 {
		t.Fatal("expected 0 epoch on nil cache")
	}

	qc := newQueryResultCache()
	if qc.currentSecurityEpoch() != 0 {
		t.Fatal("expected 0 epoch when fn nil")
	}
	qc.SetSecurityEpochFunc(func() uint64 { return 42 })
	if qc.currentSecurityEpoch() != 42 {
		t.Fatal("expected 42 epoch")
	}
	qc.Configure(time.Minute, 0) // defaults maxEntries
	qc.Configure(time.Minute, 2)

	if isNowDateMathString("") {
		t.Fatal("empty string should not be now")
	}
	if !isNowDateMathString("2025-01-01||now-1d") {
		t.Fatal("expected ||now-1d to be detected")
	}

	nowRange := map[string]esast.RangeCond{"ts": {GTE: "now-1h"}}
	nowQ := &esast.Query{Range: nowRange}
	if !containsNowDateMath(&esast.SearchRequest{KNN: esast.KNNSlice{{Filter: esast.QuerySlice{*nowQ}}}}, nil) {
		t.Fatal("expected KNN filter now detection")
	}
	if !containsNowDateMath(&esast.SearchRequest{Rescore: esast.RescoreSlice{{Query: &esast.RescoreQuerySpec{RescoreQuery: nowQ}}}}, nil) {
		t.Fatal("expected Rescore now detection")
	}
	if !containsNowDateMath(&esast.SearchRequest{Highlight: &esast.HighlightSpec{HighlightQuery: nowQ}}, nil) {
		t.Fatal("expected HighlightQuery now detection")
	}
	if !containsNowDateMath(&esast.SearchRequest{Highlight: &esast.HighlightSpec{Fields: map[string]any{"body": map[string]any{"highlight_query": map[string]any{"range": map[string]any{"ts": map[string]any{"gte": "now-1h"}}}}}}}, []byte(`"now-1h"`)) {
		t.Fatal("expected Highlight field now detection")
	}
	if !containsNowDateMath(&esast.SearchRequest{Sort: esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "x", Nested: &esast.NestedSortSpec{Filter: nowQ}}}}}, nil) {
		t.Fatal("expected Nested sort filter now detection")
	}

	// aggsContainNow branches
	if boundsContainNow(nil) {
		t.Fatal("expected boundsContainNow(nil) false")
	}
	for name, aggs := range map[string]map[string]esast.AggSpec{
		"filters_map":  {"a": {Filters: &esast.FiltersAggSpec{Filters: map[string]esast.Query{"f1": *nowQ}}}},
		"filters_anon": {"a": {Filters: &esast.FiltersAggSpec{AnonymousFilters: []esast.Query{*nowQ}}}},
		"dh_bounds":    {"a": {DateHistogram: &esast.DateHistogramAggSpec{Field: "ts", ExtendedBounds: &esast.HistogramBoundsSpec{Max: "now"}}}},
		"date_range":   {"a": {DateRange: &esast.RangeAggSpec{Field: "ts", Ranges: []esast.RangeAggBucket{{From: "now-1d"}}}}},
		"terms_bg":     {"a": {Terms: &esast.TermsAggSpec{Field: "k", BackgroundFilter: nowQ}}},
		"comp_terms":   {"a": {Composite: &esast.CompositeAggSpec{Sources: []map[string]esast.AggSpec{{"s": {Terms: &esast.TermsAggSpec{Field: "k", Missing: "now"}}}}}}},
		"comp_dh":      {"a": {Composite: &esast.CompositeAggSpec{Sources: []map[string]esast.AggSpec{{"s": {DateHistogram: &esast.DateHistogramAggSpec{Field: "ts", Missing: "now"}}}}}}},
	} {
		if !aggsContainNow(aggs) {
			t.Fatalf("expected aggsContainNow true for %s", name)
		}
	}

	// queryContainsNow branches
	for name, q := range map[string]*esast.Query{
		"dis_max":        {DisMax: &esast.DisMaxQuery{Queries: esast.QuerySlice{*nowQ}}},
		"boosting":       {Boosting: &esast.BoostingQuery{Positive: *nowQ}},
		"nested":         {Nested: &esast.NestedQuery{Path: "p", Query: *nowQ}},
		"func_query":     {FunctionScore: &esast.FunctionScoreQuery{Query: nowQ}},
		"func_rand":      {FunctionScore: &esast.FunctionScoreQuery{Functions: []esast.ScoreFunctionSpec{{RandomScore: &esast.RandomScoreSpec{}}}}},
		"func_filter":    {FunctionScore: &esast.FunctionScoreQuery{Functions: []esast.ScoreFunctionSpec{{Filter: nowQ}}}},
		"wrapper":        {Wrapper: &esast.WrapperQuery{Decoded: nowQ}},
		"has_child":      {HasChild: &esast.HasChildQuery{Type: "c", Query: *nowQ}},
		"has_parent":     {HasParent: &esast.HasParentQuery{ParentType: "p", Query: *nowQ}},
		"bool_filter":    {Bool: &esast.BoolQuery{Filter: esast.QuerySlice{*nowQ}}},
		"bool_should":    {Bool: &esast.BoolQuery{Should: esast.QuerySlice{*nowQ}}},
		"bool_must_not":  {Bool: &esast.BoolQuery{MustNot: esast.QuerySlice{*nowQ}}},
		"terms_contains": {Terms: &esast.TermsQuery{Fields: map[string][]any{"k": {"now-1h"}}}},
	} {
		if !queryContainsNow(q) {
			t.Fatalf("expected queryContainsNow true for %s", name)
		}
	}

	// buildQueryCacheKeyWithAuthAndParams & Put/Get/Eviction
	if _, ok := buildQueryCacheKeyWithAuthAndParams([]string{"idx"}, &esast.SearchRequest{PIT: &esast.PITSpec{ID: "p1"}}, "", 0, nil); ok {
		t.Fatal("expected PIT request not cacheable")
	}
	staticReq := &esast.SearchRequest{
		Query:       &esast.Query{Term: map[string]esast.TermEntry{"k": {Value: "v"}}},
		AliasFilter: &esast.Query{Term: map[string]esast.TermEntry{"tenant": {Value: "t1"}}},
		Routing:     "r1",
	}
	uParams := url.Values{"typed_keys": {"true"}, "pretty": {"true"}}
	key, ok := buildQueryCacheKeyWithAuthAndParams([]string{"idx"}, staticReq, "user1", 42, uParams)
	if !ok || !strings.Contains(key, "qp:typed_keys=true") {
		t.Fatalf("unexpected cache key: ok=%v key=%q", ok, key)
	}
	qc.PutWithMetaForAuthWithParams([]string{"idx"}, staticReq, "user1", uParams, map[string]any{"hits": map[string]any{"total": 1}}, []string{"f1"})
	// Large entry skipped
	qc.PutWithMetaForAuthWithParams([]string{"idx"}, staticReq, "user2", nil, map[string]any{"blob": strings.Repeat("a", DefaultQueryCacheMaxEntryBytes+10)}, nil)

	// Force expired entry cleanup and eviction
	req2 := &esast.SearchRequest{Query: &esast.Query{Term: map[string]esast.TermEntry{"k": {Value: "v2"}}}}
	req3 := &esast.SearchRequest{Query: &esast.Query{Term: map[string]esast.TermEntry{"k": {Value: "v3"}}}}
	qc.PutWithMetaForAuthWithParams([]string{"idx"}, req2, "user1", nil, map[string]any{"ok": true}, nil)
	qc.mu.Lock()
	for k, ent := range qc.entries {
		if strings.Contains(k, "v2") {
			ent.expiresAt = time.Now().Add(-time.Second)
			qc.entries[k] = ent
		}
	}
	qc.mu.Unlock()
	qc.PutWithMetaForAuthWithParams([]string{"idx"}, req3, "user1", nil, map[string]any{"ok": 3}, nil)

	// Corrupt raw JSON entry to trigger decode error branch in GetWithMetaForAuthWithParams
	k3, _ := buildQueryCacheKeyWithAuthAndParams([]string{"idx"}, req3, "user1", 42, nil)
	qc.mu.Lock()
	ent3 := qc.entries[k3]
	ent3.raw = []byte("{bad-json")
	qc.entries[k3] = ent3
	qc.mu.Unlock()
	if _, _, found := qc.GetWithMetaForAuthWithParams([]string{"idx"}, req3, "user1", nil); found {
		t.Fatal("expected false on corrupt cache entry")
	}

	got, meta, found := qc.GetWithMetaForAuthWithParams([]string{"idx"}, staticReq, "user1", uParams)
	if !found || got == nil || len(meta) != 1 || meta[0] != "f1" {
		t.Fatalf("expected cache hit with unindexed meta, got found=%v meta=%v", found, meta)
	}
}

func TestRound67TopUpFeat_IngestPipelinesAndProcessorsEdgeCases(t *testing.T) {
	srv, _ := newR67TFServer(t)

	// Pipeline CRUD + if_version + cycle + wildcard delete
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/", `{"processors":[]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_empty", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_bad?if_version=abc", `{"processors":[]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_missing?if_version=1", `{"processors":[]}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_nover", `{"processors":[{"set":{"field":"a","value":1}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_nover?if_version=1", `{"processors":[{"set":{"field":"a","value":2}}]}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_ver", `{"version":1,"processors":[{"set":{"field":"a","value":1}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_ver?if_version=2", `{"version":2,"processors":[]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_ver?if_version=1", `{"version":1,"processors":[]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_ver?if_version=1", `{"processors":[{"set":{"field":"a","value":2}}]}`, http.StatusOK)

	// Cycle detection (pipeline stored, detected on _simulate)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_cyc", `{"processors":[{"pipeline":{"name":"p_cyc"}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/p_cyc/_simulate", `{"docs":[{"_source":{"a":1}}]}`, http.StatusOK)

	// Sub-pipeline with on_failure that handles error and clears failure metadata
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_sub_onfail", `{
		"processors": [{"fail":{"message":"sub boom"}}],
		"on_failure": [{"set":{"field":"handled","value":true}}]
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_sub_drop", `{
		"processors": [{"fail":{"message":"drop boom"}}],
		"on_failure": [{"drop":{}}]
	}`, http.StatusOK)

	// Simulate verbose with pipeline processor (ignore_missing_pipeline + sub-pipeline on_failure)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", `{
		"pipeline": {
			"processors": [
				{"pipeline": {"name": "no_such_pipe", "ignore_missing_pipeline": true, "tag": "t1", "description": "d1", "if": "ctx.flag == true"}},
				{"pipeline": {"name": "p_sub_onfail", "tag": "t2", "description": "d2"}}
			]
		},
		"docs": [{"_index":"idx","_id":"1","_source":{"flag":true}}]
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"pipeline": {"name": "p_sub_drop"}}]},
		"docs": [{"_index":"idx","_id":"1","_source":{"x":1}}]
	}`, http.StatusOK)

	// Delete pipelines: missing literal, missing wildcard, comma/wildcard match
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/no_such_p", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/no_such_*", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ingest/pipeline/p_nover,p_ver*", ``, http.StatusOK)

	// Stored script for ingest script processor
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/r67tf_ing_del", `{"script":{"lang":"painless","source":"ctx.op = 'delete'"}}`, http.StatusOK)

	// Batch 1: dissect, set, rename, copy, remove, gsub, json, kv, dot_expander, urlencode, urldecode
	simRes := mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"dissect": {"field": "arr_lines", "pattern": "%{k}=%{v}", "target_field": "dis_out"}},
				{"set": {"field": "copied", "copy_from": "src_val", "ignore_empty_value": true}},
				{"set": {"field": "copied", "copy_from": "src_val", "override": false}},
				{"set": {"field": "json_set", "value": "{\"n\":1}", "media_type": "application/json", "override": true}},
				{"rename": {"field": "old_f", "target_field": "new_f"}},
				{"rename": {"field": "missing_f", "target_field": "x", "ignore_missing": true}},
				{"copy": {"field": "new_f", "target_field": "copied_f"}},
				{"copy": {"field": "missing_f", "target_field": "x"}},
				{"remove": {"field": ["tmp_rm1", "tmp_rm2"], "keep": ["keep_me", "arr_lines", "dis_out", "copied", "json_set", "new_f", "copied_f", "gfield", "jstr", "jarr", "kvstr", "kvarr", "uenc", "udec", "dot_parent"]}},
				{"gsub": {"field": "gfield", "pattern": "foo", "replacement": "bar", "target_field": "gsub_arr"}},
				{"json": {"field": "jstr", "add_to_root": true, "add_to_root_conflict_strategy": "merge"}},
				{"json": {"field": "jarr", "target_field": "jarr_parsed"}},
				{"kv": {"field": "kvstr", "field_split": "&", "value_split": "=", "strip_brackets": true, "trim_key": "_", "trim_value": " ", "transform_key": "lowercase", "exclude_keys": ["b"], "prefix": "p_", "target_field": "kv_out"}},
				{"kv": {"field": "kv_in_str", "field_split": "&", "value_split": "=", "include_keys": ["a"], "target_field": "kv_in_out"}},
				{"kv": {"field": "kvarr", "field_split": " ", "value_split": ":\\s*", "transform_key": "uppercase"}},
				{"dot_expander": {"field": "*", "override": false}},
				{"dot_expander": {"field": "a.b.c", "path": "dot_parent"}},
				{"urlencode": {"field": "uenc", "target_field": "uenc_out"}},
				{"urldecode": {"field": "udec", "target_field": "udec_out"}}
			]
		},
		"docs": [{
			"_index": "idx",
			"_id": "1",
			"_source": {
				"keep_me": 1,
				"arr_lines": ["x=1", "y=2"],
				"dis_out": "existing_scalar",
				"src_val": "hello",
				"old_f": "v1",
				"tmp_rm1": 1,
				"tmp_rm2": 2,
				"gfield": ["foo1", "foo2"],
				"jstr": "{\"_index\":\"blocked\",\"merged\":{\"k\":1}}",
				"jarr": ["{\"a\":1}", "{\"b\":2}"],
				"kvstr": "[_A_=\"hello\"&_A_='world'&_B_=skip]",
				"kv_in_str": "a=1&c=2",
				"kvarr": ["k1: v1 k2: v2"],
				"uenc": ["a b", "c/d"],
				"udec": ["a+b", "c%2Fd"],
				"a.b": "leaf",
				"dot_parent": {"a": {"b.c": "val"}}
			}
		}]
	}`, http.StatusOK)
	docsOut, _ := simRes["docs"].([]any)
	if len(docsOut) != 1 {
		t.Fatalf("expected 1 simulated doc, got %v", simRes)
	}

	// Batch 2: date_index_name, grok, fingerprint, redact, attachment, csv, user_agent, foreach (slice & map), script meta mutations
	b64UTF8 := base64.StdEncoding.EncodeToString([]byte("hello \u2603 world"))
	b64Latin1 := base64.StdEncoding.EncodeToString([]byte("hello latin1"))
	b64Bin := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00, 0x01})
	simRes2 := mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"date_index_name": {"field": "ts_epoch", "index_name_prefix": "logs-", "index_name_format": "xxxx-ww", "date_rounding": "w", "timezone": "UTC", "locale": "en", "target_field": "idx_w"}},
				{"date_index_name": {"field": "ts_epoch", "index_name_format": "UNIX_MS", "date_rounding": "h", "target_field": "idx_h"}},
				{"grok": {"field": "g_arr", "patterns": ["%{WORD:w} %{INT:num:int} %{QS:q}"], "ecs_compatibility": "v1", "trace_match": true, "keep_empty_captures": true, "target_field": "grok_out"}},
				{"fingerprint": {"exclude_fields": ["ts_epoch", "att1"], "method": "MD5", "salt": "s1", "target_field": "fp_md5"}},
				{"fingerprint": {"fields": ["msg"], "method": "SHA-1", "target_field": "fp_sha1"}},
				{"fingerprint": {"fields": ["msg"], "method": "SHA-384", "target_field": "fp_sha384"}},
				{"fingerprint": {"fields": ["msg"], "method": "SHA-512", "target_field": "fp_sha512"}},
				{"fingerprint": {"fields": ["msg"], "method": "MURMUR3", "target_field": "fp_m3"}},
				{"redact": {"field": "red_arr", "patterns": ["%{NUMBER:NUM}"], "prefix": "[", "suffix": "]"}},
				{"attachment": {"field": "att1", "target_field": "att_utf8", "indexed_chars_field": "ic_lim", "properties": ["content", "content_type"]}},
				{"attachment": {"field": "att2", "target_field": "att_latin1", "remove_binary": true}},
				{"attachment": {"field": "att3", "target_field": "att_bin", "indexed_chars": 2}},
				{"csv": {"field": "csv_line", "target_fields": ["c1", "c2", "c3"], "separator": ";", "quote": "'", "trim": true, "empty_value": "EMPTY"}},
				{"user_agent": {"field": "ua_edge", "target_field": "ua_e"}},
				{"user_agent": {"field": "ua_chrome", "target_field": "ua_c"}},
				{"foreach": {"field": "items", "processor": {"script": {"source": "ctx._ingest._value = ctx._ingest._value + '_x';"}}}},
				{"foreach": {"field": "kvmap", "processor": {"script": {"source": "if (ctx._ingest._key == 'dropk') { ctx._ingest._key = null; } else { ctx._ingest._value = ctx._ingest._value + 1; }"}}}},
				{"script": {"source": "ctx._index = 'mut_idx'; ctx._id = 'mut_id'; ctx._routing = 'mut_r'; ctx._version = 5; ctx._version_type = 'external'; ctx._if_seq_no = 1;"}}
			]
		},
		"docs": [{
			"_index": "idx",
			"_id": "1",
			"_source": {
				"ts_epoch": 1700000000000,
				"msg": "hello",
				"g_arr": ["alpha 12 \"hi\"", "beta 34 \"yo\""],
				"red_arr": ["call 12345", "pin 999"],
				"att1": "`+b64UTF8+`",
				"att2": "`+b64Latin1+`",
				"att3": "`+b64Bin+`",
				"ic_lim": 5,
				"csv_line": " 'x' ; ; '' ",
				"ua_edge": "Mozilla/5.0 (Windows NT 10.0) Edg/120.0.1",
				"ua_chrome": "Mozilla/5.0 Chrome/119.0.0",
				"items": ["a", "b"],
				"kvmap": {"k1": 10, "dropk": 99}
			}
		}]
	}`, http.StatusOK)
	docsOut2, _ := simRes2["docs"].([]any)
	if len(docsOut2) != 1 {
		t.Fatalf("expected 1 simulated doc in batch 2, got %v", simRes2)
	}

	// Error edge cases for ingest processors (trigger error handling branches)
	errorProcs := []string{
		`{"set":{"field":"a","copy_from":"no_such","ignore_missing":false}}`,
		`{"rename":{"field":"a","target_field":"a"}}`,
		`{"rename":{"field":"missing","target_field":"b"}}`,
		`{"copy":{"field":"a","target_field":"a"}}`,
		`{"copy":{"field":"missing","target_field":"b","ignore_missing":false}}`,
		`{"remove":{}}`,
		`{"gsub":{"field":"num","pattern":"a","replacement":"b"}}`,
		`{"json":{"field":"msg","add_to_root":true,"target_field":"t"}}`,
		`{"json":{"field":"badjson"}}`,
		`{"kv":{"field":"msg","field_split":"&","value_split":"[invalid"}}`,
		`{"fingerprint":{"fields":["a"],"exclude_fields":["b"]}}`,
		`{"fingerprint":{"fields":["msg"],"method":"BOGUS"}}`,
		`{"redact":{"field":"missing","patterns":["%{NUMBER}"]}}`,
		`{"redact":{"field":"num","patterns":["%{NUMBER}"]}}`,
		`{"attachment":{"field":"badb64"}}`,
		`{"csv":{"field":"num","target_fields":["c1"]}}`,
		`{"foreach":{"field":"num","processor":{"set":{"field":"x","value":1}}}}`,
		`{"foreach":{"field":"missing","processor":{"set":{"field":"x","value":1}}}}`,
		`{"script":{"id":"no_such_script_id"}}`,
		`{"script":{"id":"r67tf_ing_del"}}`,
	}
	for _, procJSON := range errorProcs {
		body := fmt.Sprintf(`{"pipeline":{"processors":[%s]},"docs":[{"_index":"idx","_id":"1","_source":{"a":1,"msg":"hello","num":42,"badjson":"{1","badb64":"!!!"}}]}`, procJSON)
		rec := doR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", body)
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status %d for %s: %s", rec.Code, procJSON, rec.Body.String())
		}
	}
}

func TestRound67TopUpFeat_ReindexRolloverResolveExplainEnrichResizeTermsEnum(t *testing.T) {
	srv, _ := newR67TFServer(t)

	// Seed indices & docs
	r67TFCreateIndexAndDoc(t, srv, "src_a", `{"mappings":{"properties":{"k":{"type":"keyword"},"v":{"type":"integer"},"ver":{"type":"version"},"flat":{"type":"flattened"},"tag":{"type":"keyword"}}}}`, "1", `{"k":"alpha","v":10,"ver":"1.2.3","flat":{"sub":"x"},"tag":"t1"}`)
	mustR67TFHTTP(t, srv, http.MethodPut, "/src_a/_doc/2?refresh=true", `{"k":"beta","v":20,"ver":"2.0.0","flat":{"sub":"y"},"tag":"t2"}`, http.StatusCreated)
	r67TFCreateIndexAndDoc(t, srv, "src_b", `{"mappings":{"properties":{"k":{"type":"keyword"},"v":{"type":"integer"}}}}`, "3", `{"k":"gamma","v":30}`)

	// 1. handleResolveCluster
	mustR67TFHTTP(t, srv, http.MethodPost, "/_resolve/cluster", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster?ignore_throttled=bad", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster?ignore_unavailable=bad", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster?allow_no_indices=bad", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster?expand_wildcards=bogus", ``, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_cluster/settings", `{
		"persistent": {
			"cluster.remote.rem1.seeds": ["127.0.0.1:9300"],
			"cluster.remote.rem1.skip_unavailable": "true",
			"cluster": {
				"remote": {
					"rem2": {"seeds": ["127.0.0.2:9300"], "skip_unavailable": true, "connected": false},
					"rem3": {"seeds": null}
				}
			}
		},
		"transient": {
			"cluster.remote.rem3.seeds": null
		}
	}`, http.StatusOK)
	resCl := mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster/(local):src_*,rem*:*?ignore_throttled=true&ignore_unavailable=true&allow_no_indices=false&expand_wildcards=open,closed", ``, http.StatusOK)
	if resCl["(local)"] == nil || resCl["rem1"] == nil {
		t.Fatalf("expected cluster entries in resolve cluster response: %v", resCl)
	}
	mustR67TFHTTP(t, srv, http.MethodGet, "/_resolve/cluster/unconf:idx", ``, http.StatusNotFound)

	// 2. handleEnrichAPI & executeEnrichProcessor
	mustR67TFHTTP(t, srv, http.MethodPost, "/_enrich/_stats", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_enrich/_stats", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_enrich/_stats", ``, http.StatusOK)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_empty", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_multi", `{"match":{},"range":{}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_unk", `{"unknown":{}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_geo", `{"geo_match":{"indices":["src_a"],"match_field":"k","enrich_fields":["v"],"shape_relation":123}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/bad_idx", `{"match":{"indices":[],"match_field":"k","enrich_fields":["v"]}}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_match", `{
		"elasticsearch_version": "8.0.0",
		"match": {"indices": ["src_a"], "match_field": "k", "enrich_fields": ["v", "tag"]}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_match", `{"match":{"indices":["src_a"],"match_field":"k","enrich_fields":["v"]}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_enrich/policy/pol_match/_execute", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_enrich/policy/pol_*", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_enrich/policy/no_such_pol", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_enrich/policy/pol_*", ``, http.StatusOK)

	// Range & geo_match enrich policies
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/pol_range", `{"range":{"indices":["src_a"],"match_field":"v","enrich_fields":["k"]}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_enrich/policy/pol_range/_execute", `{}`, http.StatusOK)

	// Simulate enrich processor with executed policy + entries + lookup + error max_matches
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"enrich": {"policy_name": "pol_match", "field": "key", "target_field": "enr", "max_matches": 2}},
				{"enrich": {"policy_name": "pol_match", "field": "key", "target_field": "enr", "override": false}},
				{"enrich": {"policy_name": "pol_match", "field": "key", "target_field": "enr_entries", "entries": {"alpha": {"found": true}}}}
			]
		},
		"docs": [{"_index":"idx","_id":"1","_source":{"key":"alpha"}}]
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_enrich/policy/pol_range", ``, http.StatusOK)

	// 3. handleRollover (errors, dry_run, alias rollover, data stream rollover)
	mustR67TFHTTP(t, srv, http.MethodGet, "/logs_alias/_rollover", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/logs_alias/_rollover?dry_run=bad", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_rollover", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/missing_alias/_rollover", `{}`, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPost, "/logs_alias/_rollover/INVALID_UPPER", `{}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPut, "/logs-000001", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"logs-000001","alias":"logs_alias","is_write_index":true}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/logs_alias/_rollover?dry_run=true", `{"conditions":{"max_docs":100}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_none", `{"processors":[{"set":{"field":"ro_p","value":1}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/p_none2", `{"processors":[{"set":{"field":"ro_f","value":2}}]}`, http.StatusOK)
	ro := mustR67TFHTTP(t, srv, http.MethodPost, "/logs_alias/_rollover", `{
		"settings": {"index.default_pipeline": "p_none", "index.final_pipeline": "p_none2"},
		"aliases": {"logs_ro_extra": {}}
	}`, http.StatusOK)
	if ro["rolled_over"] != true || ro["new_index"] != "logs-000002" {
		t.Fatalf("unexpected rollover response: %v", ro)
	}

	// Data stream rollover
	mustR67TFHTTP(t, srv, http.MethodPut, "/_index_template/ds_tpl_r67", `{"index_patterns":["ds_r67*"],"data_stream":{}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_data_stream/ds_r67", ``, http.StatusOK)
	roDS := mustR67TFHTTP(t, srv, http.MethodPost, "/ds_r67/_rollover", `{}`, http.StatusOK)
	if roDS["rolled_over"] != true {
		t.Fatalf("expected data stream rollover, got %v", roDS)
	}

	// 4. handleReindex (local + errors + async + global sort + script + conflict)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_reindex", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{"source":{"index":"src_a"},"dest":{"index":"dest_bad"},"conflicts":"bad"}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{"source":{"index":"src_a"},"dest":{"index":"dest_bad","op_type":"bad"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{"source":{"index":"src_a"},"dest":{"index":"dest_bad","version_type":"bad"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{"source":{"index":"src_a"},"dest":{"index":"dest_bad","routing":"bad_mode"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{"max_docs":1,"slices":2,"source":{"index":"src_a"},"dest":{"index":"dest_bad"}}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": ["src_a", "src_b"], "sort": [{"v": "desc"}], "_source": ["k", "v"]},
		"dest": {"index": "dest_local_r67", "routing": "=r1"},
		"script": {"source": "if (ctx._source.v == 20) { ctx.op = 'noop'; } else { ctx._source.reindexed = true; }"}
	}`, http.StatusOK)
	// Reindex create conflict with proceed
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"conflicts": "proceed",
		"source": {"index": "src_a"},
		"dest": {"index": "dest_local_r67", "op_type": "create"}
	}`, http.StatusOK)
	// Async reindex
	asyncRe := mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex?wait_for_completion=false", `{
		"source": {"index": "src_a"},
		"dest": {"index": "dest_async_r67"}
	}`, http.StatusOK)
	if asyncRe["task"] == nil {
		t.Fatalf("expected async task id, got %v", asyncRe)
	}

	// 5. executeRemoteReindexRound61 via mock RoundTripper
	st := getOrCreateServerStateR61CRUD(srv)
	st.mu.Lock()
	st.testRemoteWhitelist = "remote-es.example.com:9200"
	st.mu.Unlock()

	scrollCalls := 0
	serverRemoteReindexTransportsRound61.Store(srv, r67TFRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		var payload map[string]any
		if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/_search") && !strings.Contains(req.URL.Path, "/scroll") {
			payload = map[string]any{
				"_scroll_id": "scr_1",
				"hits": map[string]any{
					"hits": []any{
						map[string]any{"_index": "rem_idx", "_id": "r1", "_version": 2, "_source": map[string]any{"k": "one"}},
						map[string]any{"_index": "rem_idx", "_id": "r2", "_version": 2, "_source": map[string]any{"k": "noop_me"}},
						map[string]any{"_index": "rem_idx", "_id": "r3", "_version": 2, "_source": map[string]any{"k": "del_me"}},
					},
				},
			}
		} else if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/_search/scroll") {
			scrollCalls++
			payload = map[string]any{
				"_scroll_id": "scr_2",
				"hits":       map[string]any{"hits": []any{}},
			}
		} else {
			payload = map[string]any{"succeeded": true}
		}
		b, _ := json.Marshal(payload)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(b)),
		}, nil
	}))
	defer serverRemoteReindexTransportsRound61.Delete(srv)

	remRes := mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"source": {
			"index": "rem_idx",
			"size": 3,
			"routing": "rk",
			"remote": {
				"host": "http://remote-es.example.com:9200",
				"username": "u",
				"password": "p",
				"headers": {"X-Custom": "1"},
				"socket_timeout": "10s",
				"connect_timeout": "5s"
			}
		},
		"dest": {"index": "dest_remote_r67", "version_type": "external"},
		"script": {"source": "if (ctx._source.k == 'noop_me') { ctx.op = 'noop'; } else if (ctx._source.k == 'del_me') { ctx.op = 'delete'; } else { ctx._source.from_remote = true; }"}
	}`, http.StatusOK)
	if remRes["created"] == nil || scrollCalls == 0 {
		t.Fatalf("expected remote reindex to paginate scroll and create docs: %v scrollCalls=%d", remRes, scrollCalls)
	}
	// Remote reindex conflict (version_type: external with lower version)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": "rem_idx", "remote": {"host": "http://remote-es.example.com:9200"}},
		"dest": {"index": "dest_remote_r67", "version_type": "external"}
	}`, http.StatusConflict)

	// 6. handleExplainDoc
	mustR67TFHTTP(t, srv, http.MethodPut, "/src_a/_explain/1", `{}`, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/missing_idx/_explain/1", `{}`, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_explain/1", `{"bad_key":{}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_explain/missing_doc", `{"query":{"match_all":{}}}`, http.StatusNotFound)
	expOK := mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_explain/1?_source=true&stored_fields=k", `{
		"query": {"script_score": {"query": {"term": {"k": "alpha"}}, "script": {"source": "params._score * 2.0"}}}
	}`, http.StatusOK)
	if expOK["matched"] != true || expOK["get"] == nil {
		t.Fatalf("expected explain match with get section: %v", expOK)
	}
	expMin := mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_explain/1", `{
		"query": {"match_all": {}},
		"min_score": 999.0
	}`, http.StatusOK)
	if expMin["matched"] != false {
		t.Fatalf("expected explain min_score mismatch: %v", expMin)
	}
	expPF := mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_explain/1", `{
		"query": {"match_all": {}},
		"post_filter": {"term": {"k": "nope"}}
	}`, http.StatusOK)
	if expPF["matched"] != false {
		t.Fatalf("expected explain post_filter mismatch: %v", expPF)
	}

	// 7. handleTermsEnum
	mustR67TFHTTP(t, srv, http.MethodPut, "/src_a/_terms_enum", `{}`, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum?timeout=2m", `{"field":"k"}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"k","timeout":"2m"}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"k","size":0}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"k","bad":1}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"k","string":"al","case_insensitive":true}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"ver","string":"1."}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_terms_enum", `{"field":"flat.sub","search_after":"a"}`, http.StatusOK)

	// 8. handleResizeOrCloneIndex
	mustR67TFHTTP(t, srv, http.MethodGet, "/src_a/_clone/src_a_clone", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_clone/src_a_clone?copy_settings=false", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ds_r67/_clone/ds_clone", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/no_such_idx/_clone/tgt_clone", `{}`, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_clone/src_a", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_split/src_a_split_bad", `{"settings":{"index.number_of_routing_shards":4}}`, http.StatusBadRequest)
	cloneRes := mustR67TFHTTP(t, srv, http.MethodPost, "/src_a/_clone/src_a_cloned", `{
		"settings": {"index.default_pipeline": "p_none"},
		"aliases": {"src_a_cloned_alias": {}}
	}`, http.StatusOK)
	if cloneRes["acknowledged"] != true {
		t.Fatalf("expected clone acknowledged: %v", cloneRes)
	}
}

func TestRound67TopUpFeat_Round48PainlessScriptsRankEvalTermVectorsMigrateCat(t *testing.T) {
	srv, _ := newR67TFServer(t)
	r67TFCreateIndexAndDoc(t, srv, "r48_idx", `{"mappings":{"properties":{"title":{"type":"text"},"score_num":{"type":"integer"}}}}`, "1", `{"title":"hello world search","score_num":10}`)
	mustR67TFHTTP(t, srv, http.MethodPut, "/r48_idx/_doc/2?refresh=true", `{"title":"doris proxy analytics","score_num":20}`, http.StatusCreated)

	// 1. handleScriptsAPI
	mustR67TFHTTP(t, srv, http.MethodGet, "/_scripts/_context", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_scripts/_languages", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_scripts/painless/_context", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_scripts/", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1/boolean_field", `{"script":{"source":"emit(true)"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1/bad_ctx", `{"script":{"source":"1"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1", `{"script":"not_obj"}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1", `{"script":{"lang":"python","source":"1"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/s1", `{"script":{"lang":"mustache","source":"{{#unclosed"}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_scripts/mustache/tpl1", `{"script":{"lang":"mustache","inline":"{\"query\":{\"match\":{\"title\":\"{{q}}\"}}}"}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_scripts/tpl1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_scripts/missing_s", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_scripts/tpl1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_scripts/missing_s", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_scripts/missing_s", ``, http.StatusNotFound)

	// 2. handlePainlessExecute
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_scripts/painless/_execute", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{"script":{"id":"no_such_id"}}`, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{"context":"long_field","script":{"id":"tpl1"}}`, http.StatusBadRequest)

	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "score",
		"script": {"source": "params._score * doc['score_num'].value", "params": {"k": 2}},
		"context_setup": {"index": "r48_idx", "document": {"title": "hello", "score_num": 5}, "query": {"match_all": {}}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "filter",
		"script": {"source": "doc['score_num'].value > 3"},
		"context_setup": {"index": "r48_idx", "document": {"score_num": 5}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "ingest",
		"script": {"source": "ctx.added = 1;"},
		"context_setup": {"document": {"title": "hello"}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "long_field",
		"script": {"source": "emit(doc['score_num'].value * 2)"},
		"context_setup": {"index": "r48_idx", "document": {"score_num": 7}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "painless_test",
		"script": {"source": "return null;"}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_scripts/painless/_execute", `{
		"context": "painless_test",
		"script": {"source": "return 42;"}
	}`, http.StatusOK)

	// 3. handleMTermVectors
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_mtermvectors", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_mtermvectors", `{"bad_key":1}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_mtermvectors", `{"version":0,"ids":["1"]}`, http.StatusBadRequest)
	mtvRes := mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_mtermvectors?field_statistics=true&positions=true&offsets=true&term_statistics=true", `{
		"fields": ["title"],
		"docs": [
			{"_id": "1"},
			{"_id": "missing_id"}
		]
	}`, http.StatusOK)
	if mtvRes["docs"] == nil {
		t.Fatalf("expected docs in mtermvectors: %v", mtvRes)
	}
	mustR67TFHTTP(t, srv, http.MethodGet, "/r48_idx/_mtermvectors?ids=1,2", ``, http.StatusOK)

	// 4. handleRankEval
	mustR67TFHTTP(t, srv, http.MethodDelete, "/r48_idx/_rank_eval", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{},"dcg":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"aggs":{}},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"suggest":{}},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"highlight":{}},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"profile":true},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"explain":true},"ratings":[{"_id":"1","rating":1}]}],"metric":{"precision":{}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{"requests":[{"id":"q1","request":{"query":{"match_all":{}}},"ratings":[{"_index":"r48_idx","_id":"1","rating":-1}]}],"metric":{"dcg":{}}}`, http.StatusBadRequest)

	reRes := mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_rank_eval", `{
		"templates": [{"id": "inl1", "template": {"source": "{\"query\":{\"match\":{\"title\":\"{{q}}\"}}}"}}],
		"requests": [
			{"id": "q1", "template_id": "inl1", "params": {"q": "hello"}, "ratings": [{"_index": "r48_idx", "_id": "1", "rating": 2}]},
			{"id": "q2", "template_id": "tpl1", "params": {"q": "doris"}, "ratings": [{"_id": "2", "rating": 1}]},
			{"id": "q_miss", "template_id": "no_tpl", "ratings": []}
		],
		"metric": {"expected_reciprocal_rank": {"maximum_relevance": 3, "k": 5}}
	}`, http.StatusOK)
	if reRes["failures"] == nil || reRes["details"] == nil {
		t.Fatalf("unexpected rank_eval response: %v", reRes)
	}

	// 5. handleMigrateToDataStream
	mustR67TFHTTP(t, srv, http.MethodGet, "/_data_stream/_migrate/al_mig", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/r48_idx", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/missing_al", ``, http.StatusNotFound)

	mustR67TFHTTP(t, srv, http.MethodPut, "/mig-000001", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/mig-000002", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"mig-000001","alias":"al_mig","is_write_index":false}},{"add":{"index":"mig-000002","alias":"al_mig","is_write_index":true}}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/al_mig", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/al_mig", ``, http.StatusBadRequest)

	// 6. handleCatSegments
	mustR67TFHTTP(t, srv, http.MethodPost, "/_cat/segments", ``, http.StatusMethodNotAllowed)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_cat/segments?help=true", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_cat/segments/r48_idx?bytes=kb&full_id=true&format=json", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/r48_idx/_close", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_cat/segments/r48_idx", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_cat/segments/r48_idx?ignore_unavailable=true&format=json", ``, http.StatusOK)
}

func TestRound67TopUpFeat_SecurityAPIOAuth2ProfilesSAMLQueryDSL(t *testing.T) {
	srv, _ := newR67TFServer(t)

	// Role + User + Privileges + Password + Enable/Disable + Clear Cache
	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/role/r67_role", `{
		"cluster": ["monitor"],
		"indices": [{"names": ["logs-*"], "privileges": ["read"]}],
		"applications": [{"application": "kibana-*", "privileges": ["all"], "resources": ["*"]}],
		"run_as": ["other_u"]
	}`, http.StatusOK)
	srv.SetAuth("elastic", "adminpass", "static-key-123")
	adminAuth := [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:adminpass"))}

	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/user/r67_u1", `{
		"password": "pw1",
		"roles": ["r67_role"],
		"full_name": "R67 User",
		"email": "r67@example.com",
		"metadata": {"team": "core"}
	}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_security/user", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/user/r67_u1/_disable", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/user/r67_u1/_enable", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/user/r67_u1/_password", `{"password":"pw2"}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/user/r67_u1/_clear_cache", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_security/user/r67_u1/_has_privileges", `{"cluster":["monitor"]}`, http.StatusOK, adminAuth)

	basicAuth := [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("r67_u1:pw2"))}
	privs := mustR67TFHTTP(t, srv, http.MethodGet, "/_security/user/_privileges", ``, http.StatusOK, basicAuth)
	if privs["cluster"] == nil {
		t.Fatalf("expected cluster privileges for custom user: %v", privs)
	}

	// OAuth2 token: password, client_credentials, refresh_token, errors
	tokRes := mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{
		"grant_type": "password",
		"username": "r67_u1",
		"password": "pw2"
	}`, http.StatusOK)
	accessTok, _ := tokRes["access_token"].(string)
	refreshTok, _ := tokRes["refresh_token"].(string)
	if accessTok == "" || refreshTok == "" {
		t.Fatalf("expected oauth2 tokens: %v", tokRes)
	}
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"r67_u1","password":"wrong"}`, http.StatusUnauthorized)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"client_credentials","client_id":"r67_u1","client_secret":"pw2"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":"%s"}`, refreshTok), http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"refresh_token","refresh_token":"bad_ref"}`, http.StatusUnauthorized)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"unknown"}`, http.StatusBadRequest)

	// API key _grant (password & access_token), _clear_cache, _bulk_update, PUT /_security/api_key/{id}
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/_grant", `{"grant_type":"bogus"}`, http.StatusBadRequest)
	gkRes := mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/_grant", `{"grant_type":"password","username":"r67_u1","password":"pw2","api_key":{"name":"gk1","expiration":"1d"}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/_grant", fmt.Sprintf(`{"grant_type":"access_token","access_token":"%s","api_key":{"name":"gk2"}}`, accessTok), http.StatusUnauthorized)
	gkID, _ := gkRes["id"].(string)
	if gkID == "" {
		t.Fatalf("expected api key id from grant: %v", gkRes)
	}
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/"+gkID+"/_clear_cache", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/api_key/"+gkID, `{"metadata":{"env":"test"}}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/_bulk_update", fmt.Sprintf(`{"ids":["%s","missing_k"],"metadata":{"b":1}}`, gkID), http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/api_key/_bulk_update", fmt.Sprintf(`{"ids":["%s"]}`, gkID), http.StatusOK, adminAuth)

	// Cache clears + Security Query DSL + SAML
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/privilege/kibana/_clear_cache", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/service/ns/svc/_clear_cache", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/_query/api_key", `{"query":{"match_all":{}}}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/_query/user", `{"query":{"match_all":{}}}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/_query/role", `{"query":{"match_all":{}}}`, http.StatusOK, adminAuth)

	mustR67TFHTTP(t, srv, http.MethodGet, "/_security/saml/metadata/saml1", ``, http.StatusOK, adminAuth)
	recXML := doR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/metadata", `{"realm_name":"saml1"}`, adminAuth)
	if recXML.Code != http.StatusOK || !strings.Contains(recXML.Body.String(), "EntityDescriptor") {
		t.Fatalf("expected SAML XML metadata, got %d %s", recXML.Code, recXML.Body.String())
	}
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/prepare", `{"realm":"saml1"}`, http.StatusOK, adminAuth)
	samlAuth := mustR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/authenticate", `{"content":"PHNhbWw+PC9zYW1sPg=="}`, http.StatusOK, adminAuth)
	samlTok, _ := samlAuth["access_token"].(string)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/invalidate", `{"query_string":"SAMLResponse=abc"}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/logout", fmt.Sprintf(`{"token":"%s"}`, samlTok), http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/saml/complete_logout", `{}`, http.StatusOK, adminAuth)

	// Round56 Security Profiles, Settings, Cross-Cluster API Key
	profRes := mustR67TFHTTP(t, srv, http.MethodPost, "/_security/profile/_activate", `{
		"grant": {"user": {"username": "r67_u1", "roles": ["r67_role"], "email": "r67@example.com", "full_name": "R67"}}
	}`, http.StatusOK, adminAuth)
	uid, _ := profRes["uid"].(string)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/profile/"+uid+"/_data", `{
		"labels": {"team": "search"},
		"data": {"theme": "dark"}
	}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_security/profile/"+uid+",missing_uid", ``, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/profile/_has_privileges", fmt.Sprintf(`{"uids":["%s","missing_uid"],"privileges":{"cluster":["monitor"]}}`, uid), http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_security/profile/_suggest", fmt.Sprintf(`{"hint":{"text":"r67","uids":["%s"],"labels":{"team":["search"]}},"size":5}`, uid), http.StatusOK, adminAuth)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/settings", `{"tokens":{"enabled":true}}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_security/settings", ``, http.StatusOK, adminAuth)

	cck := mustR67TFHTTP(t, srv, http.MethodPost, "/_security/cross_cluster/api_key", `{
		"name": "cc_key1",
		"access": {"search": [{"names": ["logs-*"]}]},
		"expiration": "1d"
	}`, http.StatusOK, adminAuth)
	cckID, _ := cck["id"].(string)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/cross_cluster/api_key/"+cckID, `{
		"access": {"search": [{"names": ["*"]}]},
		"metadata": {"updated": true},
		"expiration": "2d"
	}`, http.StatusOK, adminAuth)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_security/cross_cluster/api_key/missing_cck", `{}`, http.StatusNotFound, adminAuth)
}

func TestRound67TopUpFeat_SnapshotRestoreMountRollupTransformRulesSynonymsML(t *testing.T) {
	srv, _ := newR67TFServer(t)

	// Seed index with docs, custom settings, pipeline, alias for Snapshot Restore/Mount & Rollup/Transform
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/pipeline/snap_pipe", `{"processors":[{"set":{"field":"piped","value":true}}]}`, http.StatusOK)
	r67TFCreateIndexAndDoc(t, srv, "snap_src", `{
		"settings": {"index.number_of_shards": 1, "index.default_pipeline": "snap_pipe", "index.refresh_interval": "5s"},
		"mappings": {"properties": {"ts": {"type": "date"}, "val": {"type": "integer"}, "grp": {"type": "keyword"}}},
		"aliases": {"snap_al": {"filter": {"term": {"grp": "g1"}}, "is_write_index": true, "routing": "r1"}}
	}`, "d1", `{"ts":"2025-01-01T00:00:00Z","val":10,"grp":"g1"}`)
	mustR67TFHTTP(t, srv, http.MethodPut, "/snap_src/_doc/d2?refresh=true", `{"ts":"2025-01-01T01:00:00Z","val":20,"grp":"g2"}`, http.StatusCreated)

	// 1. Snapshot repo + snapshot + _cleanup + _status + _restore + _mount
	mustR67TFHTTP(t, srv, http.MethodPut, "/_snapshot/repo1", `{"type":"fs","settings":{"location":"/tmp/r67_repo"}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_snapshot/repo1/snap1?wait_for_completion=true", `{"indices":"snap_src"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_snapshot/repo1/_cleanup", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_snapshot/repo1/_status", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_snapshot/repo1/snap1/_status", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_snapshot/repo1/snap1?verbose=true&index_names=true&include_repository=true&index_details=true", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_snapshot/repo1/snap1/_restore?wait_for_completion=true", `{
		"indices": "snap_src",
		"rename_pattern": "snap_(.+)",
		"rename_replacement": "restored_$1",
		"ignore_index_settings": ["index.refresh_interval"],
		"index_settings": {"index": {"number_of_replicas": 0}},
		"include_aliases": true
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_snapshot/repo1/snap1/_mount", `{
		"index": "snap_src",
		"renamed_index": "mounted_snap_src",
		"storage": "full_copy",
		"include_aliases": true
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_snapshot/repo1/snap1/_mount", `{"index":"snap_src","renamed_index":"mounted_snap_src"}`, http.StatusBadRequest)

	// 2. Rollup + selectSingleRollupJobDocsR65
	mustR67TFHTTP(t, srv, http.MethodPut, "/_rollup/job/bad_r", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_rollup/job/bad_u", `{"bogus":1}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_rollup/job/rj1", `{
		"index_pattern": "snap_src",
		"rollup_index": "rollup_out",
		"cron": "0 * * * * ?",
		"page_size": 100,
		"groups": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "time_zone": "Canada/Mountain"}, "terms": {"fields": ["grp"]}},
		"metrics": [{"field": "val", "metrics": ["sum", "avg"]}]
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_rollup/job/rj2", `{
		"index_pattern": "snap_src",
		"rollup_index": "rollup_out",
		"cron": "0 * * * * ?",
		"page_size": 100,
		"groups": {"date_histogram": {"field": "ts", "fixed_interval": "1d"}, "terms": {"fields": ["grp"]}},
		"metrics": [{"field": "val", "metrics": ["sum"]}]
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_rollup/job/rj1/_start", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_rollup/job/rj2/_start", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_rollup/data/rollup_out", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/rollup_out/_rollup/data", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/rollup_out/_rollup_search", `{
		"size": 0,
		"aggs": {"by_day": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}, "aggs": {"s": {"sum": {"field": "val"}}}}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_rollup/job/rj1/_stop", ``, http.StatusOK)

	// 3. Transform + TransformAction
	mustR67TFHTTP(t, srv, http.MethodPut, "/_transform/tx1", `{
		"source": {"index": ["snap_src"]},
		"dest": {"index": "tx1_dest"},
		"pivot": {"group_by": {"grp": {"terms": {"field": "grp"}}}, "aggregations": {"total_val": {"sum": {"field": "val"}}}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_start?from=2025-01-01T00:00:00Z", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_start", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_start", ``, http.StatusConflict)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_reset", ``, http.StatusConflict)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_update", `{"pivot":{}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_update", `{"sync":{"time":{"field":"ts"}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_update", `{"description":"updated tx"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_stop?force=true&wait_for_checkpoint=true", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_reset?force=true", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_transform/tx1/_stop", ``, http.StatusOK)

	// 4. Query Rules
	mustR67TFHTTP(t, srv, http.MethodPut, "/_query_rules/qr1", `{
		"rules": [{"rule_id": "r1", "type": "pinned", "criteria": [{"type": "exact", "metadata": "q", "values": ["shoes"]}], "actions": {"ids": ["1"]}}]
	}`, http.StatusCreated)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_query_rules", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_query_rules/qr1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_query_rules/qr1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_query_rules/qr1/_test", `{"match_criteria":{"q":"shoes"}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_query_rules/qr1/_rule/r2", `{"type":"pinned","criteria":[{"type":"exact","metadata":"q","values":["hat"]}],"actions":{"ids":["2"]}}`, http.StatusCreated)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_query_rules/qr1/_rule/r2", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_query_rules/qr1/_rule/r2", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_query_rules/qr1", ``, http.StatusOK)

	// 5. Synonyms
	mustR67TFHTTP(t, srv, http.MethodPut, "/_synonyms/syn1", `{"synonyms_set":[{"id":"s1","synonyms":"pc, personal computer"}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_synonyms", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_synonyms/syn1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_synonyms/syn1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_synonyms/syn1/_reload", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_synonyms/syn1/s2", `{"synonyms":"tv => television"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_synonyms/syn1/s2", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_synonyms/syn1/s2", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_synonyms/syn1", ``, http.StatusOK)

	// 6. Connector Secret + GeoIP Database
	mustR67TFHTTP(t, srv, http.MethodPost, "/_connector/_secret", `{"id":"sec1","name":"my_sec","value":"topsecret"}`, http.StatusCreated)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ingest/geoip/database/geo1", `{"config":{"max_mind":{"database_file":"GeoLite2-City.mmdb","account_id":"123"}}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_ingest/geoip/database/geo1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ingest/geoip/database/geo1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ingest/geoip/database/geo1", ``, http.StatusOK)

	// 7. ML: Anomaly Detectors + model_snapshots, Datafeeds, DataFrame Analytics, Trained Models
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate", `{"analysis_config":{"detectors":[{"function":"count"}]}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_validate/detector", `{"function":"count"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/_estimate_model_memory", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/anomaly_detectors/job1", `{"analysis_config":{"detectors":[{"function":"count"}]}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_open", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/_data", `{"@timestamp":1700000000000,"v":1}`+"\n", http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/model_snapshots", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/model_snapshots/1/_upgrade/_stats", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/model_snapshots/1/_update", `{"description":"upd","retain":true}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/model_snapshots/1/_revert", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job1/model_snapshots/1/_upgrade", `{}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ml/anomaly_detectors/job1/model_snapshots/1", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job1/results/buckets", ``, http.StatusOK)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/datafeeds/df1", `{"job_id":"job1","indices":["snap_src"]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/_stats", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/df1/_stats", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_start", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_update", `{"query_delay":"30s"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/datafeeds/df1/_preview", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/datafeeds/df1/_stop", ``, http.StatusOK)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/data_frame/analytics/dfa1", `{
		"source": {"index": "snap_src"},
		"dest": {"index": "dfa1_dest"},
		"analysis": {"outlier_detection": {}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/data_frame/analytics/_stats", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/data_frame/analytics/dfa1/_preview", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/data_frame/analytics/dfa1/_explain", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/data_frame/analytics/dfa1/_update", `{"description":"d"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/data_frame/analytics/dfa1/_start", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/data_frame/analytics/dfa1/_stop", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ml/data_frame/analytics/dfa1", ``, http.StatusOK)

	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1", `{"input":{"field_names":["text"]},"inference_config":{"text_embedding":{}}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1/model_aliases/tm1_alias", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1/definition/0", `{"part":1}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_ml/trained_models/tm1/vocabulary", `{"vocabulary":["hello","world"]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_ml/trained_models/tm1/vocabulary", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_start", `{"number_of_allocations":1,"threads_per_allocation":1,"queue_capacity":10,"priority":"high"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_update", `{"number_of_allocations":2,"priority":"low"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_cache/_clear", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_infer", `{"docs":[{"text":"hi"}]}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_ml/trained_models/tm1/deployment/_stop", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_ml/trained_models/tm1/model_aliases/tm1_alias", ``, http.StatusOK)
}

func TestRound67TopUpFeat_ESQLSQLAndEQLTemplatesPIT(t *testing.T) {
	srv, _ := newR67TFServer(t)

	// Seed indices & enrich policy for ES|QL, SQL, EQL
	r67TFCreateIndexAndDoc(t, srv, "ev_idx", `{
		"mappings": {"properties": {
			"@timestamp": {"type": "date"},
			"event": {"properties": {"category": {"type": "keyword"}}},
			"host": {"type": "keyword"},
			"pid": {"type": "integer"},
			"tags": {"type": "keyword"},
			"unused": {"type": "keyword"}
		}}
	}`, "e1", `{"@timestamp":"2025-01-01T00:00:00Z","event":{"category":"process"},"host":"h1","pid":10,"tags":["a","b"]}`)
	mustR67TFHTTP(t, srv, http.MethodPut, "/ev_idx/_doc/e2?refresh=true", `{"@timestamp":"2025-01-01T00:01:00Z","event":{"category":"file"},"host":"h1","pid":10,"tags":["c"]}`, http.StatusCreated)
	r67TFCreateIndexAndDoc(t, srv, "host_meta", `{"mappings":{"properties":{"host":{"type":"keyword"},"owner":{"type":"keyword"}}}}`, "h1", `{"host":"h1","owner":"alice"}`)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_enrich/policy/host_pol", `{"match":{"indices":["host_meta"],"match_field":"host","enrich_fields":["owner"]}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_enrich/policy/host_pol/_execute", `{}`, http.StatusOK)

	// 1. ES|QL: ENRICH, MV_EXPAND, RENAME, SORT, DROP, drop_null_columns, columnar, profile, csv/tsv/txt
	mustR67TFHTTP(t, srv, http.MethodPost, "/_query", `{
		"query": "FROM ev_idx | ENRICH host_pol ON host WITH owner | MV_EXPAND tags | RENAME owner AS host_owner | SORT pid DESC NULLS FIRST | DROP unused | LIMIT 5",
		"drop_null_columns": true,
		"columnar": true,
		"profile": true
	}`, http.StatusOK)
	for _, fmtName := range []string{"csv", "tsv", "txt"} {
		rec := doR67TFHTTP(t, srv, http.MethodPost, "/_query?format="+fmtName, `{"query":"FROM ev_idx | KEEP host, pid | LIMIT 2"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("ES|QL format=%s failed: %d %s", fmtName, rec.Code, rec.Body.String())
		}
	}
	mustR67TFHTTP(t, srv, http.MethodPost, "/_query", `{"query":"FROM ev_idx | MV_EXPAND"}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_query", `{"query":"FROM ev_idx | BOGUS_CMD 1"}`, http.StatusBadRequest)

	// 2. SQL: DESCRIBE, SHOW COLUMNS, SHOW TABLES LIKE, SELECT parameterized + columnar
	mustR67TFHTTP(t, srv, http.MethodPost, "/_sql", `{"query":""}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_sql", `{"query":"DESCRIBE ev_idx"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_sql", `{"query":"SHOW COLUMNS FROM ev_idx"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_sql", `{"query":"SHOW TABLES LIKE 'ev_%'"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/_sql", `{"query":"SELECT host, pid FROM ev_idx WHERE pid >= ? ORDER BY pid DESC","params":[5],"columnar":true,"fetch_size":10}`, http.StatusOK)

	// 3. EQL: event query, sequence query, async status/get/delete
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_eql/search", `{"query":""}`, http.StatusBadRequest)
	eqlEvt := mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_eql/search", `{
		"query": "process where pid >= 10",
		"filter": {"term": {"host": "h1"}},
		"size": 5
	}`, http.StatusOK)
	eqlID, _ := eqlEvt["id"].(string)
	if eqlID == "" {
		t.Fatalf("expected eql id: %v", eqlEvt)
	}
	mustR67TFHTTP(t, srv, http.MethodGet, "/_eql/search/status/"+eqlID, ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_eql/search/status/"+eqlID, ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodGet, "/_eql/search/"+eqlID, ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_eql/search/"+eqlID, ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_eql/search", `{
		"query": "sequence by host [process where pid >= 10] [file where host == \"h1\"]"
	}`, http.StatusOK)

	// 4. Templates (legacy /_template and composable /_index_template)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_template/missing_t", ``, http.StatusNotFound)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_template/leg_t1?template=leg-*", `{"mappings":{"_doc":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_template/leg_t1?template=leg-*&include_type_name=true", `{"mappings":{"_doc":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodHead, "/_template/leg_*", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_index_template/comp_bad", `{"index_patterns":["comp-*"],"composed_of":["missing_comp"]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_component_template/ok_comp", `{"template":{"mappings":{"properties":{"c":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_index_template/comp_ok?ignore_missing_component_template=true", `{
		"index_patterns": ["comp-*"],
		"priority": 100,
		"composed_of": ["ok_comp"],
		"template": {"mappings": {"properties": {"x": {"type": "keyword"}}}}
	}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_index_template/comp_ok?create=true", `{"index_patterns":["comp-*"]}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPut, "/_index_template/comp_overlap", `{"index_patterns":["comp-*"],"priority":100}`, http.StatusBadRequest)

	// 5. PIT (open, errors, delete single/array/_all/pit_all)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=bad", ``, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=5m", `{"bad_key":1}`, http.StatusBadRequest)
	pit1 := mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=5m", `{"index_filter":{"term":{"host":"h1"}}}`, http.StatusOK)
	pitID1, _ := pit1["id"].(string)
	pit2 := mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=5m", ``, http.StatusOK)
	pitID2, _ := pit2["id"].(string)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_pit", `{}`, http.StatusBadRequest)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_pit", fmt.Sprintf(`{"id":["%s","missing_pit"]}`, pitID1), http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_pit?id="+url.QueryEscape(pitID2), ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=5m", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_pit", `{"id":"_all"}`, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodPost, "/ev_idx/_pit?keep_alive=5m", ``, http.StatusOK)
	mustR67TFHTTP(t, srv, http.MethodDelete, "/_pit/_all", ``, http.StatusOK)
}
