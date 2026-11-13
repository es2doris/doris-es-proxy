package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doRound58Req(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, rec.Header(), parsed, raw
}

func TestRound58_F2_PITAndScrollLifecycle(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// Setup indices for PIT & Scroll tests.
	code, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/r58_pit_idx", `{"mappings":{"properties":{"tag":{"type":"keyword"},"val":{"type":"long"}}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /r58_pit_idx failed: %d", code)
	}
	doRound58Req(t, handler, http.MethodPut, "/r58_pit_idx/_doc/b?refresh=true", `{"tag":"same","val":10}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_pit_idx/_doc/a?refresh=true", `{"tag":"same","val":10}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_pit_idx/_doc/c?refresh=true", `{"tag":"other","val":20}`, nil)

	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/r58_pit_closed", `{}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /r58_pit_closed failed: %d", code)
	}
	code, _, _, _ = doRound58Req(t, handler, http.MethodPost, "/r58_pit_closed/_close", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /r58_pit_closed/_close failed: %d", code)
	}

	// 1. PIT method guards & validation
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/r58_pit_idx/_pit?keep_alive=1m", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /{index}/_pit, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/r58_pit_idx/_pit?keep_alive=1m", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT /{index}/_pit, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_pit?keep_alive=1m", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /_pit without index, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing keep_alive, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=invalid", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid keep_alive, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=-5m", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative keep_alive, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_nonexistent/_pit?keep_alive=1m", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing index PIT, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_closed/_pit?keep_alive=1m", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on closed index PIT, got %d", c)
	}

	// 2. Open PIT, deterministic tiebreaker, reject {index}+pit & invalid pit.keep_alive
	code, _, pitResp1, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=1m", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /r58_pit_idx/_pit failed: %d %v", code, pitResp1)
	}
	pitID1, _ := pitResp1["id"].(string)
	if pitID1 == "" {
		t.Fatalf("expected non-empty pit id, got %v", pitResp1)
	}

	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search", fmt.Sprintf(`{"pit":{"id":%q}}`, pitID1), nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when combining {index} and pit, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search", fmt.Sprintf(`{"pit":{"id":%q,"keep_alive":"bogus"}}`, pitID1), nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid pit.keep_alive in _search, got %d", c)
	}

	// Search with PIT on tied val=10 docs -> deterministic _id asc tiebreak ("a" then "b").
	code, _, sResp, _ := doRound58Req(t, handler, http.MethodPost, "/_search", fmt.Sprintf(`{
		"size": 2,
		"pit": {"id": %q, "keep_alive": "2m"},
		"sort": [{"val": "asc"}]
	}`, pitID1), nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_search with PIT failed: %d %v", code, sResp)
	}
	hitsArr, _ := sResp["hits"].(map[string]any)["hits"].([]any)
	if len(hitsArr) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hitsArr))
	}
	id0, _ := hitsArr[0].(map[string]any)["_id"].(string)
	id1, _ := hitsArr[1].(map[string]any)["_id"].(string)
	if id0 != "a" || id1 != "b" {
		t.Fatalf("expected deterministic _id tiebreak [a, b], got [%s, %s]", id0, id1)
	}

	// 3. DELETE /_pit with [valid, unknown] -> succeeded: false, num_freed: 1, pits details
	code, _, delResp, _ := doRound58Req(t, handler, http.MethodDelete, "/_pit", fmt.Sprintf(`{"id":[%q,"unknown_pit_id"]}`, pitID1), nil)
	if code != http.StatusOK {
		t.Fatalf("DELETE /_pit failed: %d %v", code, delResp)
	}
	if delResp["succeeded"] != false || delResp["num_freed"] != float64(1) {
		t.Fatalf("expected succeeded=false, num_freed=1, got %v", delResp)
	}
	pitsSlice, _ := delResp["pits"].([]any)
	if len(pitsSlice) != 2 {
		t.Fatalf("expected 2 pit statuses, got %v", delResp)
	}

	// Deleted PIT must return 404 search_context_missing_exception across _search, _count, _validate/query, and _msearch item.
	code, _, errResp, rawErr := doRound58Req(t, handler, http.MethodPost, "/_search", fmt.Sprintf(`{"pit":{"id":%q}}`, pitID1), nil)
	if code != http.StatusNotFound || !strings.Contains(rawErr, "search_context_missing_exception") {
		t.Fatalf("expected 404 search_context_missing_exception on deleted PIT _search, got %d %v", code, errResp)
	}
	code, _, _, rawErr = doRound58Req(t, handler, http.MethodPost, "/_count", fmt.Sprintf(`{"pit":{"id":%q}}`, pitID1), nil)
	if code != http.StatusNotFound || !strings.Contains(rawErr, "search_context_missing_exception") {
		t.Fatalf("expected 404 search_context_missing_exception on deleted PIT _count, got %d %s", code, rawErr)
	}
	code, _, valResp, rawErr := doRound58Req(t, handler, http.MethodPost, "/_validate/query", fmt.Sprintf(`{"pit":{"id":%q}}`, pitID1), nil)
	if code != http.StatusOK || valResp["valid"] != false {
		t.Fatalf("expected 200 valid=false on deleted PIT _validate/query, got %d %s", code, rawErr)
	}
	msearchBody := "{}\n" + fmt.Sprintf(`{"pit":{"id":%q}}`, pitID1) + "\n"
	code, _, msResp, rawMS := doRound58Req(t, handler, http.MethodPost, "/_msearch", msearchBody, nil)
	if code != http.StatusOK || !strings.Contains(rawMS, "search_context_missing_exception") {
		t.Fatalf("expected search_context_missing_exception in _msearch response, got %d %v", code, msResp)
	}

	// 4. DELETE /_pit/_all & TTL expiration
	_, _, pitResp2, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=1m", "", nil)
	pitID2, _ := pitResp2["id"].(string)
	code, _, delAllResp, _ := doRound58Req(t, handler, http.MethodDelete, "/_pit/_all", "", nil)
	if code != http.StatusOK || delAllResp["succeeded"] != true || delAllResp["num_freed"] != float64(1) {
		t.Fatalf("DELETE /_pit/_all unexpected: %d %v", code, delAllResp)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search", fmt.Sprintf(`{"pit":{"id":%q}}`, pitID2), nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 after DELETE /_pit/_all, got %d", c)
	}

	_, _, pitRespExp, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=2ms", "", nil)
	pitIDExp, _ := pitRespExp["id"].(string)
	time.Sleep(12 * time.Millisecond)
	if c, _, _, rawExp := doRound58Req(t, handler, http.MethodPost, "/_search", fmt.Sprintf(`{"pit":{"id":%q}}`, pitIDExp), nil); c != http.StatusNotFound || !strings.Contains(rawExp, "search_context_missing_exception") {
		t.Fatalf("expected 404 search_context_missing_exception on expired PIT, got %d %s", c, rawExp)
	}

	// 5. Scroll lifecycle: method guard, invalid duration, from>0, scroll+pit, clear & expiry
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_search/scroll", `{"scroll_id":"abc"}`, nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT /_search/scroll, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search?scroll=badttl", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid scroll duration, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search?scroll=1m", `{"from":1,"size":1}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on scroll with from > 0, got %d", c)
	}
	_, _, pitForScroll, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_pit?keep_alive=1m", "", nil)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search?scroll=1m", fmt.Sprintf(`{"pit":{"id":%q}}`, pitForScroll["id"]), nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on scroll combined with pit, got %d", c)
	}

	code, _, scInit, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search?scroll=1m", `{"size":1,"sort":[{"_id":"asc"}]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("initial scroll search failed: %d %v", code, scInit)
	}
	scID1, _ := scInit["_scroll_id"].(string)
	if scID1 == "" {
		t.Fatalf("expected _scroll_id, got %v", scInit)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"bad","scroll_id":%q}`, scID1), nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid scroll renewal TTL, got %d", c)
	}
	code, _, scPage2, _ := doRound58Req(t, handler, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, scID1), nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_search/scroll failed: %d %v", code, scPage2)
	}
	scID2, _ := scPage2["_scroll_id"].(string)

	// Clear scroll session via scID1 -> invalidates entire session including scID2!
	code, _, scDel, _ := doRound58Req(t, handler, http.MethodDelete, "/_search/scroll", fmt.Sprintf(`{"scroll_id":%q}`, scID1), nil)
	if code != http.StatusOK || scDel["succeeded"] != true || scDel["num_freed"] != float64(1) {
		t.Fatalf("DELETE /_search/scroll unexpected: %d %v", code, scDel)
	}
	code, _, _, rawScErr := doRound58Req(t, handler, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, scID2), nil)
	if code != http.StatusNotFound || !strings.Contains(rawScErr, "search_context_missing_exception") {
		t.Fatalf("expected 404 search_context_missing_exception after clearing scroll, got %d %s", code, rawScErr)
	}
	code, _, scDelUnknown, _ := doRound58Req(t, handler, http.MethodDelete, "/_search/scroll", `{"scroll_id":"nonexistent_scroll_tok"}`, nil)
	if code != http.StatusOK || scDelUnknown["succeeded"] != false || scDelUnknown["num_freed"] != float64(0) {
		t.Fatalf("expected succeeded=false, num_freed=0 for unknown scroll_id, got %d %v", code, scDelUnknown)
	}

	// Scroll _all & TTL expiry
	_, _, scInitAll, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search?scroll=1m", `{"size":1}`, nil)
	scIDAll, _ := scInitAll["_scroll_id"].(string)
	code, _, scDelAll, _ := doRound58Req(t, handler, http.MethodDelete, "/_search/scroll/_all", "", nil)
	if code != http.StatusOK || scDelAll["succeeded"] != true || scDelAll["num_freed"] != float64(1) {
		t.Fatalf("DELETE /_search/scroll/_all unexpected: %d %v", code, scDelAll)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll_id":%q}`, scIDAll), nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 after DELETE /_search/scroll/_all, got %d", c)
	}

	_, _, scExpInit, _ := doRound58Req(t, handler, http.MethodPost, "/r58_pit_idx/_search?scroll=2ms", `{"size":1}`, nil)
	scExpID, _ := scExpInit["_scroll_id"].(string)
	time.Sleep(12 * time.Millisecond)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll_id":%q}`, scExpID), nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on expired scroll_id, got %d", c)
	}
}

func TestRound58_F3_TransformAndRollupMaterialization(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Source data + ingest pipeline for pivot & latest transforms
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/r58_tx_pipe", `{
		"processors": [{"set": {"field": "enriched", "value": true}}]
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_orders", `{
		"mappings": {
			"properties": {
				"customer": {"type": "keyword"},
				"status":   {"type": "keyword"},
				"amount":   {"type": "double"},
				"ts":       {"type": "date"}
			}
		}
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_orders/_doc/1?refresh=true", `{"customer":"alice","status":"paid","amount":15,"ts":"2026-05-01T10:05:00Z"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_orders/_doc/2?refresh=true", `{"customer":"alice","status":"paid","amount":25,"ts":"2026-05-01T10:45:00Z"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_orders/_doc/3?refresh=true", `{"customer":"alice","status":"void","amount":999,"ts":"2026-05-01T10:50:00Z"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_orders/_doc/4?refresh=true", `{"customer":"bob","status":"paid","amount":50,"ts":"2026-05-01T11:15:00Z"}`, nil)

	pivotBody := `{
		"source": {
			"index": "r58_orders",
			"query": {"term": {"status": "paid"}}
		},
		"dest": {
			"index": "r58_orders_pivot",
			"pipeline": "r58_tx_pipe"
		},
		"pivot": {
			"group_by": {
				"customer": {"terms": {"field": "customer"}},
				"hour_bucket": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}},
				"amt_tier": {"histogram": {"field": "amount", "interval": 50}}
			},
			"aggregations": {
				"total_amt": {"sum": {"field": "amount"}},
				"avg_amt":   {"avg": {"field": "amount"}},
				"min_amt":   {"min": {"field": "amount"}},
				"max_amt":   {"max": {"field": "amount"}},
				"cnt_amt":   {"value_count": {"field": "amount"}},
				"uniq_cust": {"cardinality": {"field": "customer"}},
				"amt_stats": {"stats": {"field": "amount"}}
			}
		}
	}`

	// Preview ad-hoc pivot transform
	code, _, prevResp, _ := doRound58Req(t, handler, http.MethodPost, "/_transform/_preview", pivotBody, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_transform/_preview failed: %d %v", code, prevResp)
	}
	prevDocs, _ := prevResp["preview"].([]any)
	if len(prevDocs) != 2 {
		t.Fatalf("expected 2 preview buckets (alice@10h tier 0, bob@11h tier 50), got %d: %v", len(prevDocs), prevResp)
	}
	if genDest, _ := prevResp["generated_dest_index"].(map[string]any); genDest == nil {
		t.Fatalf("expected generated_dest_index in preview response, got %v", prevResp)
	}

	// Create, preview by id, start, inspect dest.index, _stats, _cat/transforms, and _stop
	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/_transform/tx_r58_pivot", pivotBody, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_transform/tx_r58_pivot failed: %d", code)
	}
	code, _, prevByID, _ := doRound58Req(t, handler, http.MethodPost, "/_transform/tx_r58_pivot/_preview", "", nil)
	if code != http.StatusOK || len(prevByID["preview"].([]any)) != 2 {
		t.Fatalf("POST /_transform/tx_r58_pivot/_preview failed: %d %v", code, prevByID)
	}
	code, _, _, _ = doRound58Req(t, handler, http.MethodPost, "/_transform/tx_r58_pivot/_start", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_transform/tx_r58_pivot/_start failed: %d", code)
	}

	code, _, destSearch, _ := doRound58Req(t, handler, http.MethodPost, "/r58_orders_pivot/_search", `{"query":{"term":{"customer":"alice"}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("search on pivot dest index failed: %d %v", code, destSearch)
	}
	destHits, _ := destSearch["hits"].(map[string]any)["hits"].([]any)
	if len(destHits) != 1 {
		t.Fatalf("expected 1 materialized doc for alice, got %d (%v)", len(destHits), destSearch)
	}
	aliceSrc, _ := destHits[0].(map[string]any)["_source"].(map[string]any)
	if aliceSrc["total_amt"] != float64(40) || aliceSrc["avg_amt"] != float64(20) || aliceSrc["enriched"] != true {
		t.Fatalf("unexpected materialized alice pivot doc: %v", aliceSrc)
	}

	code, _, statsResp, _ := doRound58Req(t, handler, http.MethodGet, "/_transform/tx_r58_pivot/_stats", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_transform/tx_r58_pivot/_stats failed: %d", code)
	}
	txStatsEntry := statsResp["transforms"].([]any)[0].(map[string]any)
	txStatsInner := txStatsEntry["stats"].(map[string]any)
	if txStatsEntry["state"] != "started" || txStatsInner["documents_processed"] != float64(3) || txStatsInner["documents_indexed"] != float64(2) {
		t.Fatalf("unexpected transform _stats: %v", txStatsEntry)
	}

	_, _, _, rawCatTx := doRound58Req(t, handler, http.MethodGet, "/_cat/transforms?format=json", "", nil)
	if !strings.Contains(rawCatTx, `"state":"started"`) {
		t.Fatalf("expected state=started in _cat/transforms, got %s", rawCatTx)
	}
	doRound58Req(t, handler, http.MethodPost, "/_transform/tx_r58_pivot/_stop", "", nil)
	_, _, _, rawCatTxStopped := doRound58Req(t, handler, http.MethodGet, "/_cat/transforms?format=json", "", nil)
	if !strings.Contains(rawCatTxStopped, `"state":"stopped"`) {
		t.Fatalf("expected state=stopped in _cat/transforms after _stop, got %s", rawCatTxStopped)
	}

	// 2. Latest transform
	latestBody := `{
		"source": {"index": "r58_orders"},
		"dest": {"index": "r58_orders_latest"},
		"latest": {
			"unique_key": ["customer"],
			"sort": "ts"
		}
	}`
	doRound58Req(t, handler, http.MethodPut, "/_transform/tx_r58_latest", latestBody, nil)
	code, _, _, _ = doRound58Req(t, handler, http.MethodPost, "/_transform/tx_r58_latest/_start", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_transform/tx_r58_latest/_start failed: %d", code)
	}
	_, _, latSearch, _ := doRound58Req(t, handler, http.MethodPost, "/r58_orders_latest/_search", `{"query":{"term":{"customer":"alice"}}}`, nil)
	latHits, _ := latSearch["hits"].(map[string]any)["hits"].([]any)
	if len(latHits) != 1 || latHits[0].(map[string]any)["_source"].(map[string]any)["status"] != "void" {
		t.Fatalf("expected latest doc for alice to be status=void (10:50Z), got %v", latHits)
	}

	// 3. Rollup materialization, _rollup/data, and _rollup_search (even after source index deletion!)
	rollupJobBody := `{
		"index_pattern": "r58_orders*",
		"rollup_index": "r58_rollup_dest",
		"cron": "0 */30 * * * ?",
		"page_size": 100,
		"groups": {
			"date_histogram": {"field": "ts", "fixed_interval": "1h"},
			"terms": {"fields": ["customer", "status"]},
			"histogram": {"fields": ["amount"], "interval": 25}
		},
		"metrics": [
			{"field": "amount", "metrics": ["min", "max", "sum", "avg", "value_count"]}
		]
	}`
	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/_rollup/job/rj_r58", rollupJobBody, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_rollup/job/rj_r58 failed: %d", code)
	}
	code, _, _, _ = doRound58Req(t, handler, http.MethodPost, "/_rollup/job/rj_r58/_start", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_rollup/job/rj_r58/_start failed: %d", code)
	}

	code, _, rjInfo, _ := doRound58Req(t, handler, http.MethodGet, "/_rollup/job/rj_r58", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_rollup/job/rj_r58 failed: %d", code)
	}
	rjStats := rjInfo["jobs"].([]any)[0].(map[string]any)["stats"].(map[string]any)
	if rjStats["documents_processed"].(float64) < 4 || rjStats["rollups_indexed"].(float64) < 1 {
		t.Fatalf("expected non-zero rollup stats, got %v", rjStats)
	}

	code, _, rData, _ := doRound58Req(t, handler, http.MethodGet, "/_rollup/data/rj_r58", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_rollup/data/rj_r58 failed: %d", code)
	}
	rjCapFields, _ := rData["rj_r58"].(map[string]any)["rollup_jobs"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	if len(rjCapFields) == 0 || rjCapFields["amount"] == nil || rjCapFields["ts"] == nil {
		t.Fatalf("expected populated rollup data fields, got %v", rData)
	}

	// _rollup_search must reject size > 0
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_rollup_dest/_rollup_search", `{"size":5}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _rollup_search with size > 0, got %d", c)
	}

	// Delete raw source index, then run _rollup_search against r58_rollup_dest!
	doRound58Req(t, handler, http.MethodDelete, "/r58_orders", "", nil)
	code, _, rsResp, _ := doRound58Req(t, handler, http.MethodPost, "/r58_rollup_dest/_rollup_search", `{
		"query": {"term": {"status": "paid"}},
		"aggs": {
			"by_customer": {
				"terms": {"field": "customer"},
				"aggs": {
					"sum_amt": {"sum": {"field": "amount"}},
					"avg_amt": {"avg": {"field": "amount"}},
					"min_amt": {"min": {"field": "amount"}},
					"max_amt": {"max": {"field": "amount"}},
					"cnt_amt": {"value_count": {"field": "amount"}}
				}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /r58_rollup_dest/_rollup_search failed: %d %v", code, rsResp)
	}
	rsBuckets, _ := rsResp["aggregations"].(map[string]any)["by_customer"].(map[string]any)["buckets"].([]any)
	if len(rsBuckets) != 2 {
		t.Fatalf("expected 2 customer buckets from rollup_search, got %v", rsResp)
	}
	foundAlice := false
	for _, rb := range rsBuckets {
		bm := rb.(map[string]any)
		if bm["key"] == "alice" {
			foundAlice = true
			if bm["doc_count"] != float64(2) ||
				bm["sum_amt"].(map[string]any)["value"] != float64(40) ||
				bm["avg_amt"].(map[string]any)["value"] != float64(20) ||
				bm["min_amt"].(map[string]any)["value"] != float64(15) ||
				bm["max_amt"].(map[string]any)["value"] != float64(25) ||
				bm["cnt_amt"].(map[string]any)["value"] != float64(2) {
				t.Fatalf("unexpected rollup agg values for alice: %v", bm)
			}
		}
	}
	if !foundAlice {
		t.Fatalf("expected alice bucket in rollup_search response: %v", rsBuckets)
	}
}

func TestRound58_F4_TemplatesAndDataStreamAppendOnly(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Namespace isolation between /_index_template and /_template
	code, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_template/leg_only", `{
		"index_patterns": ["leg-*"],
		"order": 5,
		"settings": {"refresh_interval": "5s"},
		"mappings": {"properties": {"from_leg_lo": {"type": "keyword"}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_template/leg_only failed: %d", code)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_index_template/leg_only", "", nil); c != http.StatusNotFound {
		t.Fatalf("legacy template must not appear in GET /_index_template, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodHead, "/_index_template/leg_only", "", nil); c != http.StatusNotFound {
		t.Fatalf("legacy template must not appear in HEAD /_index_template, got %d", c)
	}

	doRound58Req(t, handler, http.MethodPut, "/_component_template/ct_base", `{
		"template": {
			"settings": {"refresh_interval": "10s"},
			"mappings": {"properties": {"comp_field": {"type": "keyword"}, "override_me": {"type": "long"}}}
		}
	}`, nil)

	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/_index_template/comp_low", `{
		"index_patterns": ["app-*"],
		"priority": 100,
		"template": {
			"settings": {"max_result_window": 20000},
			"mappings": {"properties": {"low_only_field": {"type": "keyword"}}}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_index_template/comp_low failed: %d", code)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_template/comp_low", "", nil); c != http.StatusNotFound {
		t.Fatalf("composable template must not appear in GET /_template, got %d", c)
	}

	// Overlapping composable template with identical priority (100) must fail with 400!
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_index_template/comp_conflict", `{
		"index_patterns": ["app-prod-*"],
		"priority": 100,
		"template": {"mappings": {"properties": {"x": {"type": "keyword"}}}}
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on overlapping composable template with identical priority, got %d", c)
	}
	// Updating same template name with same priority must succeed (200).
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_index_template/comp_low", `{
		"index_patterns": ["app-*"],
		"priority": 100,
		"template": {"mappings": {"properties": {"low_only_field": {"type": "keyword"}}}}
	}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 when updating existing composable template, got %d", c)
	}

	// Higher priority composable winner + legacy template on same pattern (legacy must be ignored!)
	doRound58Req(t, handler, http.MethodPut, "/_template/leg_app_ignored", `{
		"index_patterns": ["app-*"],
		"order": 999,
		"mappings": {"properties": {"legacy_leaked_field": {"type": "keyword"}}}
	}`, nil)
	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/_index_template/comp_high", `{
		"index_patterns": ["app-prod-*"],
		"priority": 200,
		"composed_of": ["ct_base"],
		"version": 7,
		"_meta": {"owner": "platform"},
		"allow_auto_create": true,
		"template": {
			"settings": {"refresh_interval": "30s"},
			"mappings": {"properties": {"high_field": {"type": "keyword"}, "override_me": {"type": "keyword"}}}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_index_template/comp_high failed: %d", code)
	}

	// Verify GET /_index_template/comp_high preserves version, _meta, allow_auto_create
	code, _, getTpl, _ := doRound58Req(t, handler, http.MethodGet, "/_index_template/comp_high", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_index_template/comp_high failed: %d", code)
	}
	tplItem := getTpl["index_templates"].([]any)[0].(map[string]any)["index_template"].(map[string]any)
	if tplItem["version"] != float64(7) || tplItem["allow_auto_create"] != true || tplItem["_meta"].(map[string]any)["owner"] != "platform" {
		t.Fatalf("expected version/_meta/allow_auto_create preserved, got %v", tplItem)
	}

	// Create index matching both comp_low (100), comp_high (200), and leg_app_ignored:
	// ONLY comp_high (+ ct_base) may apply!
	doRound58Req(t, handler, http.MethodPut, "/app-prod-01", `{}`, nil)
	_, _, idxMeta, _ := doRound58Req(t, handler, http.MethodGet, "/app-prod-01?flat_settings=true", "", nil)
	idxEntry := idxMeta["app-prod-01"].(map[string]any)
	props := idxEntry["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["comp_field"] == nil || props["high_field"] == nil {
		t.Fatalf("expected ct_base + comp_high fields, got %v", props)
	}
	if props["override_me"].(map[string]any)["type"] != "keyword" {
		t.Fatalf("expected comp_high template mapping to override ct_base component mapping, got %v", props["override_me"])
	}
	if props["low_only_field"] != nil || props["legacy_leaked_field"] != nil {
		t.Fatalf("lower-priority composable or legacy template leaked into single-winner index: %v", props)
	}
	flatSet := idxEntry["settings"].(map[string]any)
	if flatSet["index.refresh_interval"] != "30s" {
		t.Fatalf("expected custom template setting index.refresh_interval=30s, got %v", flatSet)
	}

	// Legacy multi-template ascending order merge when NO composable template matches
	doRound58Req(t, handler, http.MethodPut, "/_template/leg_hi", `{
		"index_patterns": ["leg-sub-*"],
		"order": 20,
		"mappings": {"properties": {"from_leg_hi": {"type": "long"}}}
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/leg-sub-1", `{}`, nil)
	_, _, legIdxMeta, _ := doRound58Req(t, handler, http.MethodGet, "/leg-sub-1", "", nil)
	legProps := legIdxMeta["leg-sub-1"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if legProps["from_leg_lo"] == nil || legProps["from_leg_hi"] == nil {
		t.Fatalf("expected both legacy templates merged when no composable matches, got %v", legProps)
	}

	// 2. allow_auto_create: false blocks auto-creation (404)
	doRound58Req(t, handler, http.MethodPut, "/_index_template/no_autocreate", `{
		"index_patterns": ["locked-*"],
		"priority": 50,
		"allow_auto_create": false,
		"template": {"mappings": {"properties": {"a": {"type": "keyword"}}}}
	}`, nil)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/locked-001/_doc", `{"a":"x"}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 when allow_auto_create=false, got %d", c)
	}

	// 3. Data stream auto-creation from composable template + append-only guards
	code, _, _, _ = doRound58Req(t, handler, http.MethodPut, "/_index_template/ds_logs_tpl", `{
		"index_patterns": ["logs-auto-*"],
		"priority": 300,
		"data_stream": {},
		"template": {"mappings": {"properties": {"msg": {"type": "keyword"}}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_index_template/ds_logs_tpl failed: %d", code)
	}
	// Non-create PUT /{ds}/_doc/{id} on uncreated data stream template target -> 400
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/logs-auto-app/_doc/1", `{"@timestamp":"2026-05-01T00:00:00Z","msg":"hi"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on op_type=index PUT /{ds}/_doc/{id} for data_stream template, got %d", c)
	}
	// POST /{ds}/_doc (auto-ID create) auto-creates data stream!
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/logs-auto-app/_doc?refresh=true", `{"@timestamp":"2026-05-01T00:00:00Z","msg":"ok"}`, nil); c != http.StatusCreated {
		t.Fatalf("expected 201 on POST /logs-auto-app/_doc auto-creating data stream, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_data_stream/logs-auto-app", "", nil); c != http.StatusOK {
		t.Fatalf("expected auto-created data stream logs-auto-app to exist, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/logs-auto-app/_doc/2?op_type=index", `{"@timestamp":"2026-05-01T00:05:00Z","msg":"bad"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on explicit op_type=index against data stream, got %d", c)
	}

	// Bulk against data stream: create -> 201, index/update/delete -> per-item 400!
	bulkPayload := strings.Join([]string{
		`{"create":{"_id":"ds1"}}`,
		`{"@timestamp":"2026-05-01T01:00:00Z","msg":"c1"}`,
		`{"index":{"_id":"ds2"}}`,
		`{"@timestamp":"2026-05-01T02:00:00Z","msg":"i2"}`,
		`{"update":{"_id":"ds1"}}`,
		`{"doc":{"msg":"u1"}}`,
		`{"delete":{"_id":"ds1"}}`,
	}, "\n") + "\n"
	code, _, bulkResp, _ := doRound58Req(t, handler, http.MethodPost, "/logs-auto-app/_bulk?refresh=true", bulkPayload, nil)
	if code != http.StatusOK || bulkResp["errors"] != true {
		t.Fatalf("expected 200 with errors=true from _bulk on data stream, got %d %v", code, bulkResp)
	}
	items := bulkResp["items"].([]any)
	if items[0].(map[string]any)["create"].(map[string]any)["status"] != float64(201) {
		t.Fatalf("expected create item 201, got %v", items[0])
	}
	if items[1].(map[string]any)["index"].(map[string]any)["status"] != float64(400) ||
		items[2].(map[string]any)["update"].(map[string]any)["status"] != float64(400) ||
		items[3].(map[string]any)["delete"].(map[string]any)["status"] != float64(400) {
		t.Fatalf("expected 400 on index/update/delete bulk items against data stream, got %v", items)
	}

	// Single-doc DELETE and POST _update against data stream -> 400
	if c, _, _, _ := doRound58Req(t, handler, http.MethodDelete, "/logs-auto-app/_doc/ds1", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on DELETE /{ds}/_doc/{id}, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/logs-auto-app/_update/ds1", `{"doc":{"msg":"nope"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on POST /{ds}/_update/{id}, got %d", c)
	}

	// _reindex into data stream requires dest.op_type == "create"
	doRound58Req(t, handler, http.MethodPut, "/r58_reidx_ds_src/_doc/r1?refresh=true", `{"@timestamp":"2026-05-01T03:00:00Z","msg":"from_reidx"}`, nil)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_reindex", `{"source":{"index":"r58_reidx_ds_src"},"dest":{"index":"logs-auto-app"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _reindex into data stream without op_type=create, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/_reindex", `{"source":{"index":"r58_reidx_ds_src"},"dest":{"index":"logs-auto-app","op_type":"create"}}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 on _reindex into data stream with op_type=create, got %d", c)
	}
}

func TestRound58_F5_IndexResolutionWildcardsHiddenAndSingleDoc(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	doRound58Req(t, handler, http.MethodPut, "/r58_w_01", `{"mappings":{"properties":{"msg_a":{"type":"text"},"msg_b":{"type":"text"}}}}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_02", `{"mappings":{"properties":{"msg_a":{"type":"text"}}}}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_10", `{}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_hid", `{"settings":{"index.hidden":true}}`, nil)

	doRound58Req(t, handler, http.MethodPut, "/r58_w_01/_doc/1?refresh=true", `{"msg_a":"hello world","msg_b":"world peace"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_02/_doc/2?refresh=true", `{"msg_a":"hello galaxy"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_10/_doc/3?refresh=true", `{"msg_a":"hello universe"}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_w_hid/_doc/4?refresh=true", `{"msg_a":"hello hidden"}`, nil)

	// 1. ? single-char wildcard in HEAD, PUT _mapping, _search, and highlight.fields
	if c, _, _, _ := doRound58Req(t, handler, http.MethodHead, "/r58_w_0%3F", "", nil); c != http.StatusOK {
		t.Fatalf("expected 200 on HEAD /r58_w_0?, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/r58_w_0%3F/_mapping", `{"properties":{"added_q":{"type":"keyword"}}}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT /r58_w_0?/_mapping, got %d", c)
	}
	code, _, qSearch, _ := doRound58Req(t, handler, http.MethodPost, "/r58_w_0%3F/_search", `{
		"query": {"match": {"msg_a": "hello"}},
		"highlight": {"fields": {"msg_?": {}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /r58_w_0?/_search failed: %d %v", code, qSearch)
	}
	qHits := qSearch["hits"].(map[string]any)["hits"].([]any)
	if len(qHits) != 2 {
		t.Fatalf("expected r58_w_0? to match only r58_w_01 & r58_w_02 (2 hits), got %d", len(qHits))
	}
	hasHighlight := false
	for _, h := range qHits {
		if hl, ok := h.(map[string]any)["highlight"].(map[string]any); ok && hl["msg_a"] != nil {
			hasHighlight = true
		}
	}
	if !hasHighlight {
		t.Fatalf("expected highlight wildcard msg_? to highlight msg_a, got %v", qHits)
	}

	// 2. Single-doc endpoints reject comma-separated multi-targets & wildcards with 400
	for _, badIdx := range []string{"r58_w_01,r58_w_02", "r58_w_*", "r58_w_0%3F", "_all"} {
		if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/"+badIdx+"/_doc/9", `{"x":1}`, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on PUT /%s/_doc/9, got %d", badIdx, c)
		}
		if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/"+badIdx+"/_doc/1", "", nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on GET /%s/_doc/1, got %d", badIdx, c)
		}
		if c, _, _, _ := doRound58Req(t, handler, http.MethodDelete, "/"+badIdx+"/_doc/1", "", nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on DELETE /%s/_doc/1, got %d", badIdx, c)
		}
		if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/"+badIdx+"/_update/1", `{"doc":{"x":2}}`, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on POST /%s/_update/1, got %d", badIdx, c)
		}
	}

	// 3. index.hidden excluded from default wildcard expansion, included with expand_wildcards=open,hidden
	_, _, defWildSearch, _ := doRound58Req(t, handler, http.MethodGet, "/r58_w_*/_search", "", nil)
	if defWildSearch["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(3) {
		t.Fatalf("expected hidden index excluded from default wildcard _search (3 hits), got %v", defWildSearch)
	}
	_, _, hidWildSearch, _ := doRound58Req(t, handler, http.MethodGet, "/r58_w_*/_search?expand_wildcards=open,hidden", "", nil)
	if hidWildSearch["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(4) {
		t.Fatalf("expected hidden index included with expand_wildcards=open,hidden (4 hits), got %v", hidWildSearch)
	}

	// 4. _resolve/index honors index.hidden and expand_wildcards across indices, aliases, data_streams
	doRound58Req(t, handler, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"r58_w_01","alias":"r58_al_vis"}},{"add":{"index":"r58_w_01","alias":"r58_al_hid","is_hidden":true}}]}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_data_stream/r58_ds_vis", "", nil)

	_, _, resDefault, rawResDefault := doRound58Req(t, handler, http.MethodGet, "/_resolve/index/r58_*", "", nil)
	if strings.Contains(rawResDefault, "r58_w_hid") || strings.Contains(rawResDefault, "r58_al_hid") {
		t.Fatalf("hidden index/alias leaked into default _resolve/index: %s", rawResDefault)
	}
	if len(resDefault["aliases"].([]any)) != 1 || len(resDefault["data_streams"].([]any)) != 1 {
		t.Fatalf("expected 1 visible alias & 1 visible data_stream, got %v", resDefault)
	}

	_, _, resAll, _ := doRound58Req(t, handler, http.MethodGet, "/_resolve/index/r58_*?expand_wildcards=all", "", nil)
	foundHiddenTrue := false
	for _, ri := range resAll["indices"].([]any) {
		m := ri.(map[string]any)
		if m["name"] == "r58_w_hid" && m["hidden"] == true {
			foundHiddenTrue = true
		}
	}
	if !foundHiddenTrue {
		t.Fatalf("expected r58_w_hid with hidden:true in _resolve/index?expand_wildcards=all, got %v", resAll)
	}

	_, _, resNone, _ := doRound58Req(t, handler, http.MethodGet, "/_resolve/index/r58_*?expand_wildcards=none", "", nil)
	if len(resNone["indices"].([]any)) != 0 || len(resNone["aliases"].([]any)) != 0 || len(resNone["data_streams"].([]any)) != 0 {
		t.Fatalf("expected empty arrays for expand_wildcards=none on wildcard pattern, got %v", resNone)
	}
}

func TestRound58_F6_FieldCapsAndFieldMappingCompliance(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	doRound58Req(t, handler, http.MethodPut, "/r58_books", `{
		"mappings": {
			"properties": {
				"title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
				"pages": {"type": "long"},
				"secret_code": {"type": "keyword"},
				"author": {
					"type": "object",
					"properties": {"name": {"type": "keyword"}}
				},
				"reviews": {
					"type": "nested",
					"properties": {"stars": {"type": "integer"}}
				}
			}
		}
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_data_stream/r58_ds_fc", "", nil)

	// 1. Ordinary index omits implicit @timestamp in _field_caps & _mapping/field/*; data stream includes it
	_, _, fcBooks, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=*", "", nil)
	bookFields := fcBooks["fields"].(map[string]any)
	if bookFields["@timestamp"] != nil {
		t.Fatalf("ordinary index must not synthesize @timestamp in _field_caps, got %v", bookFields)
	}
	_, _, fmBooks, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_mapping/field/*", "", nil)
	if fmBooks["r58_books"].(map[string]any)["mappings"].(map[string]any)["@timestamp"] != nil {
		t.Fatalf("ordinary index must not synthesize @timestamp in _mapping/field/*")
	}

	_, _, fcDS, _ := doRound58Req(t, handler, http.MethodGet, "/r58_ds_fc/_field_caps?fields=*", "", nil)
	if fcDS["fields"].(map[string]any)["@timestamp"] == nil {
		t.Fatalf("data stream must include @timestamp in _field_caps, got %v", fcDS)
	}

	// 2. Method guard (405 on PUT / DELETE)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/r58_books/_field_caps?fields=*", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT _field_caps, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodDelete, "/r58_books/_field_caps?fields=*", "", nil); c != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on DELETE _field_caps, got %d", c)
	}

	// 3. -glob exclusions, types, filters (+metadata/-metadata/-multifield/-nested/-parent), include_unmapped
	_, _, fcExcl, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=*,-secret*", "", nil)
	if fcExcl["fields"].(map[string]any)["secret_code"] != nil || fcExcl["fields"].(map[string]any)["pages"] == nil {
		t.Fatalf("expected -secret* excluded while keeping pages, got %v", fcExcl["fields"])
	}

	_, _, fcTypes, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=*&types=long", "", nil)
	typesFields := fcTypes["fields"].(map[string]any)
	if len(typesFields) != 1 || typesFields["pages"] == nil {
		t.Fatalf("expected types=long to return only pages, got %v", typesFields)
	}

	_, _, fcOnlyMeta, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=*&filters=%2Bmetadata", "", nil)
	onlyMetaFields := fcOnlyMeta["fields"].(map[string]any)
	if onlyMetaFields["_id"] == nil || onlyMetaFields["pages"] != nil {
		t.Fatalf("expected +metadata to return only metadata fields, got %v", onlyMetaFields)
	}

	_, _, fcFiltered, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=*&filters=-metadata,-multifield,-nested,-parent", "", nil)
	filtFields := fcFiltered["fields"].(map[string]any)
	if filtFields["_id"] != nil || filtFields["title.raw"] != nil || filtFields["reviews"] != nil || filtFields["reviews.stars"] != nil || filtFields["author"] != nil {
		t.Fatalf("expected metadata, multifield, nested, and parent fields excluded, got %v", filtFields)
	}
	if filtFields["pages"] == nil || filtFields["author.name"] == nil {
		t.Fatalf("expected pages and author.name retained, got %v", filtFields)
	}

	_, _, fcUnmapped, _ := doRound58Req(t, handler, http.MethodGet, "/r58_books/_field_caps?fields=pages,ghost_field&include_unmapped=true", "", nil)
	if fcUnmapped["fields"].(map[string]any)["ghost_field"].(map[string]any)["unmapped"] == nil {
		t.Fatalf("expected unmapped entry for ghost_field when include_unmapped=true, got %v", fcUnmapped)
	}
}

func TestRound58_F7_GetIndexFlatSettingsMapping405AndAliases(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/r58_def_p", `{"processors":[]}`, nil)
	code, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/r58_settings_idx", `{
		"settings": {
			"index.refresh_interval": "15s",
			"index.default_pipeline": "r58_def_p",
			"analysis": {"analyzer": {"my_an": {"type": "standard"}}}
		},
		"mappings": {"properties": {"f1": {"type": "keyword"}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /r58_settings_idx failed: %d", code)
	}

	// 1. Nested vs flat_settings=true on GET /{index}
	_, _, nestedIdx, _ := doRound58Req(t, handler, http.MethodGet, "/r58_settings_idx", "", nil)
	nestedSettings := nestedIdx["r58_settings_idx"].(map[string]any)["settings"].(map[string]any)["index"].(map[string]any)
	if nestedSettings["refresh_interval"] != "15s" || nestedSettings["default_pipeline"] != "r58_def_p" || nestedSettings["provided_name"] != "r58_settings_idx" || nestedSettings["uuid"] == nil {
		t.Fatalf("expected full nested settings in GET /{index}, got %v", nestedSettings)
	}

	_, _, flatIdx, _ := doRound58Req(t, handler, http.MethodGet, "/r58_settings_idx?flat_settings=true", "", nil)
	flatSettings := flatIdx["r58_settings_idx"].(map[string]any)["settings"].(map[string]any)
	if flatSettings["index.refresh_interval"] != "15s" || flatSettings["index.default_pipeline"] != "r58_def_p" || flatSettings["index.provided_name"] != "r58_settings_idx" {
		t.Fatalf("expected flat dotted keys in GET /{index}?flat_settings=true, got %v", flatSettings)
	}

	// 2. /_mapping and /{index}/_mapping 405 guards & expand_wildcards
	for _, m := range []string{http.MethodDelete, http.MethodHead, http.MethodPut, http.MethodPost} {
		if c, _, _, _ := doRound58Req(t, handler, m, "/_mapping", `{}`, nil); c != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /_mapping, got %d", m, c)
		}
	}
	for _, m := range []string{http.MethodDelete, http.MethodHead} {
		if c, _, _, _ := doRound58Req(t, handler, m, "/r58_settings_idx/_mapping", "", nil); c != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /{index}/_mapping, got %d", m, c)
		}
	}
	_, _, noneMappings, _ := doRound58Req(t, handler, http.MethodGet, "/_mapping?expand_wildcards=none", "", nil)
	if len(noneMappings) != 0 {
		t.Fatalf("expected empty object on GET /_mapping?expand_wildcards=none, got %v", noneMappings)
	}

	// 3. POST /_aliases: comma-separated strings, -exclusions, is_hidden, remove.must_exist: false
	doRound58Req(t, handler, http.MethodPut, "/r58_al_1", `{}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_al_2", `{}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_al_skip", `{}`, nil)

	code, _, _, rawAlErr := doRound58Req(t, handler, http.MethodPost, "/_aliases", `{
		"actions": [
			{
				"add": {
					"indices": ["r58_al_*", "-r58_al_skip"],
					"aliases": ["al_a,al_b"],
					"is_hidden": true
				}
			},
			{
				"remove": {
					"index": "r58_al_1",
					"alias": "nonexistent_alias",
					"must_exist": false
				}
			}
		]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_aliases failed: %d %s", code, rawAlErr)
	}
	_, _, alGet, rawAlGet := doRound58Req(t, handler, http.MethodGet, "/_alias/al_*", "", nil)
	if alGet["r58_al_1"] == nil || alGet["r58_al_2"] == nil || alGet["r58_al_skip"] != nil {
		t.Fatalf("expected r58_al_1 & r58_al_2 aliased and r58_al_skip excluded, got %s", rawAlGet)
	}
	alMetaA := alGet["r58_al_1"].(map[string]any)["aliases"].(map[string]any)["al_a"].(map[string]any)
	if alMetaA["is_hidden"] != true {
		t.Fatalf("expected is_hidden=true preserved on alias metadata, got %v", alMetaA)
	}
}

func TestRound58_F8_ReindexUpdateDeleteByQueryCompliance(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. 405 Method Not Allowed on non-POST
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if c, _, _, _ := doRound58Req(t, handler, m, "/_reindex", "", nil); c != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /_reindex, got %d", m, c)
		}
		if c, _, _, _ := doRound58Req(t, handler, m, "/r58_missing/_update_by_query", "", nil); c != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /_update_by_query, got %d", m, c)
		}
		if c, _, _, _ := doRound58Req(t, handler, m, "/r58_missing/_delete_by_query", "", nil); c != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /_delete_by_query, got %d", m, c)
		}
	}

	// 2. Nonexistent concrete source index -> 404 index_not_found_exception (without creating dest!)
	code, _, _, rawReidx404 := doRound58Req(t, handler, http.MethodPost, "/_reindex", `{
		"source": {"index": "r58_no_such_src"},
		"dest": {"index": "r58_should_not_exist"}
	}`, nil)
	if code != http.StatusNotFound || !strings.Contains(rawReidx404, "index_not_found_exception") {
		t.Fatalf("expected 404 index_not_found_exception on missing reindex source, got %d %s", code, rawReidx404)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodHead, "/r58_should_not_exist", "", nil); c != http.StatusNotFound {
		t.Fatalf("failed _reindex must not create dest.index, got HEAD %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_no_such_src/_update_by_query", `{}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on _update_by_query missing index, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPost, "/r58_no_such_src/_delete_by_query", `{}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on _delete_by_query missing index, got %d", c)
	}

	// 3. Polymorphic source._source filtering & source.slice partitioning
	for i := 1; i <= 6; i++ {
		doRound58Req(t, handler, http.MethodPut, fmt.Sprintf("/r58_reidx_src/_doc/d%d?refresh=true", i),
			fmt.Sprintf(`{"keep_field":"v%d","secret_field":"sec%d","num":%d}`, i, i, i), nil)
	}

	code, _, _, _ = doRound58Req(t, handler, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {
			"index": "r58_reidx_src",
			"_source": {"includes": ["keep_*"], "excludes": ["secret_*"]}
		},
		"dest": {"index": "r58_reidx_filtered"}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("_reindex with object source._source failed: %d", code)
	}
	_, _, d1Get, _ := doRound58Req(t, handler, http.MethodGet, "/r58_reidx_filtered/_doc/d1", "", nil)
	d1Src := d1Get["_source"].(map[string]any)
	if d1Src["keep_field"] != "v1" || d1Src["secret_field"] != nil || d1Src["num"] != nil {
		t.Fatalf("expected _source filtered to keep_field only, got %v", d1Src)
	}

	// Sliced reindex (max=2: slice 0 + slice 1 must partition all 6 docs with zero overlap)
	_, _, sl0, _ := doRound58Req(t, handler, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r58_reidx_src", "_source": "keep_field", "slice": {"id": 0, "max": 2}},
		"dest": {"index": "r58_reidx_sliced"}
	}`, nil)
	_, _, sl1, _ := doRound58Req(t, handler, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r58_reidx_src", "_source": "keep_field", "slice": {"id": 1, "max": 2}},
		"dest": {"index": "r58_reidx_sliced"}
	}`, nil)
	c0, _ := sl0["created"].(float64)
	c1, _ := sl1["created"].(float64)
	if c0+c1 != 6 {
		t.Fatalf("expected slice 0 (%v) + slice 1 (%v) to create 6 disjoint docs total", c0, c1)
	}
}

func TestRound58_F9_HeadersFilterPathAndCatCompliance(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	doRound58Req(t, handler, http.MethodPut, "/r58_cat_small", `{}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_cat_small/_doc/1?refresh=true", `{"x":1}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_cat_small/_doc/2?refresh=true", `{"x":2}`, nil)

	doRound58Req(t, handler, http.MethodPut, "/r58_cat_large", `{}`, nil)
	for i := 1; i <= 10; i++ {
		doRound58Req(t, handler, http.MethodPut, fmt.Sprintf("/r58_cat_large/_doc/%d?refresh=true", i), `{"x":1}`, nil)
	}

	doRound58Req(t, handler, http.MethodPut, "/_index_template/r58_hdr_tpl", `{"index_patterns":["hdr-*"],"template":{}}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_data_stream/r58_hdr_ds", "", nil)

	// 1. X-Elastic-Product & X-Opaque-Id on HEAD and text/YAML endpoints
	headTargets := []string{
		"/r58_cat_small",
		"/r58_cat_small/_doc/1",
		"/_index_template/r58_hdr_tpl",
		"/_data_stream/r58_hdr_ds",
		"/_cat/indices",
	}
	for _, p := range headTargets {
		c, hdr, _, _ := doRound58Req(t, handler, http.MethodHead, p, "", map[string]string{"X-Opaque-Id": "op-58"})
		if c != http.StatusOK {
			t.Fatalf("HEAD %s failed: %d", p, c)
		}
		if hdr.Get("X-Elastic-Product") != "Elasticsearch" || hdr.Get("X-Opaque-Id") != "op-58" {
			t.Fatalf("HEAD %s missing ES headers: %v", p, hdr)
		}
	}

	// 2. filter_path escaped dots (\.) and root JSON array wildcard (*.index, *.docs\.count)
	code, _, _, rawFP := doRound58Req(t, handler, http.MethodGet, "/_cat/indices/r58_cat_*?format=json&filter_path=*.index,*.docs\\.count", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_cat/indices with filter_path failed: %d %s", code, rawFP)
	}
	var fpArr []map[string]any
	if err := json.Unmarshal([]byte(rawFP), &fpArr); err != nil || len(fpArr) != 2 {
		t.Fatalf("expected 2 filtered JSON array elements, got %s (%v)", rawFP, err)
	}
	if fpArr[0]["index"] == nil || fpArr[0]["docs.count"] == nil || fpArr[0]["health"] != nil {
		t.Fatalf("expected only index and docs.count retained via *.docs\\.count, got %v", fpArr[0])
	}

	// Escaped dot on flat_settings dotted keys
	_, _, fpFlat, _ := doRound58Req(t, handler, http.MethodGet, "/r58_cat_small?flat_settings=true&filter_path=r58_cat_small.settings.index\\.provided_name", "", nil)
	gotProv := fpFlat["r58_cat_small"].(map[string]any)["settings"].(map[string]any)["index.provided_name"]
	if gotProv != "r58_cat_small" {
		t.Fatalf("expected index.provided_name retained by escaped-dot filter_path, got %v", fpFlat)
	}

	// 3. _cat/* format negotiation, ?h= wildcards/aliases/validation, and ?s= numeric sorting & validation
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_cat/indices?format=xml", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsupported ?format=xml, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_cat/indices?h=unknown_col", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown ?h= header, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_cat/indices?s=unknown_col:asc", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown ?s= column, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodGet, "/_cat/indices?s=docs.count:sideways", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid ?s= sort direction, got %d", c)
	}

	// Numeric sort: 10 must come BEFORE 2 on docs.count:desc (lexicographic would put "2" before "10"!)
	code, _, _, rawSorted := doRound58Req(t, handler, http.MethodGet, "/_cat/indices/r58_cat_*?format=json&h=i,docs.*&s=docs.count:desc", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_cat/indices numeric sort failed: %d %s", code, rawSorted)
	}
	var sortedArr []map[string]any
	_ = json.Unmarshal([]byte(rawSorted), &sortedArr)
	if len(sortedArr) != 2 || sortedArr[0]["index"] != "r58_cat_large" || sortedArr[1]["index"] != "r58_cat_small" {
		t.Fatalf("expected numeric desc sort [r58_cat_large (10), r58_cat_small (2)], got %v", sortedArr)
	}
	if sortedArr[0]["docs.deleted"] == nil {
		t.Fatalf("expected h=docs.* wildcard to expand docs.count and docs.deleted, got %v", sortedArr[0])
	}

	// YAML format & Accept: text/plain negotiation
	code, yamlHdr, _, rawYAML := doRound58Req(t, handler, http.MethodGet, "/_cat/indices/r58_cat_small?format=yaml", "", map[string]string{"X-Opaque-Id": "yaml-58"})
	if code != http.StatusOK || !strings.Contains(yamlHdr.Get("Content-Type"), "yaml") || !strings.HasPrefix(rawYAML, "---\n") || yamlHdr.Get("X-Opaque-Id") != "yaml-58" {
		t.Fatalf("unexpected YAML cat response: %d %v %s", code, yamlHdr, rawYAML)
	}
	code, txtHdr, _, rawTxt := doRound58Req(t, handler, http.MethodGet, "/_cat/indices/r58_cat_small?v=true", "", map[string]string{"Accept": "text/plain"})
	if code != http.StatusOK || !strings.Contains(txtHdr.Get("Content-Type"), "text/plain") || !strings.Contains(rawTxt, "r58_cat_small") {
		t.Fatalf("unexpected Accept: text/plain cat response: %d %v %s", code, txtHdr, rawTxt)
	}
}

func TestRound58_F27_IngestCycleDetectionTerminateAndForeachRestore(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Direct & transitive cycle detection across processors, on_failure, and foreach
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_self", `{
		"processors": [{"pipeline": {"name": "p_self"}}]
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on direct self-referencing pipeline cycle, got %d", c)
	}

	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_a", `{"processors":[{"set":{"field":"x","value":1}}]}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_b", `{"processors":[{"pipeline":{"name":"p_a"}}]}`, nil)
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_a", `{
		"processors": [{"pipeline": {"name": "p_b"}}]
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on 2-node pipeline cycle p_a -> p_b -> p_a, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_a", `{
		"processors": [{"fail": {"message": "boom"}}],
		"on_failure": [{"pipeline": {"name": "p_b"}}]
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on on_failure pipeline cycle, got %d", c)
	}
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_a", `{
		"processors": [{"foreach": {"field": "arr", "processor": {"pipeline": {"name": "p_b"}}}}]
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on foreach pipeline cycle, got %d", c)
	}

	// 2. Sub-pipeline terminate halts outer pipeline AND foreach, while index final_pipeline still runs!
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_child_term", `{
		"processors": [
			{"set": {"field": "from_child", "value": true}},
			{"terminate": {}}
		]
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_outer_term", `{
		"processors": [
			{"pipeline": {"name": "p_child_term"}},
			{"set": {"field": "should_not_run", "value": true}}
		]
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_final_run", `{
		"processors": [{"set": {"field": "from_final", "value": true}}]
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_term_idx", `{
		"settings": {
			"index.default_pipeline": "p_outer_term",
			"index.final_pipeline": "p_final_run"
		}
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_term_idx/_doc/1?refresh=true", `{"init":1}`, nil)
	_, _, termDoc, _ := doRound58Req(t, handler, http.MethodGet, "/r58_term_idx/_doc/1", "", nil)
	termSrc := termDoc["_source"].(map[string]any)
	if termSrc["from_child"] != true || termSrc["should_not_run"] != nil || termSrc["from_final"] != true {
		t.Fatalf("expected child terminate to halt outer pipeline while preserving final_pipeline, got %v", termSrc)
	}

	// 3. Nested foreach restores outer _ingest._value when inner foreach fails under ignore_failure
	doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/p_nested_foreach_step", `{
		"processors": [
			{
				"foreach": {
					"field": "missing_inner_array",
					"ignore_failure": true,
					"processor": {"uppercase": {"field": "_ingest._value"}}
				}
			},
			{
				"script": {
					"source": "ctx.restored = ctx.restored == null ? [] : ctx.restored; ctx.restored.add(ctx._ingest._value.name)"
				}
			}
		]
	}`, nil)
	code, _, simResp, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"foreach": {
						"field": "groups",
						"processor": {"pipeline": {"name": "p_nested_foreach_step"}}
					}
				}
			]
		},
		"docs": [{"_source": {"groups": [{"name": "g1"}, {"name": "g2"}]}}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("nested foreach simulate failed: %d %v", code, simResp)
	}
	restoredOut := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)["restored"].([]any)
	if len(restoredOut) != 2 || restoredOut[0] != "g1" || restoredOut[1] != "g2" {
		t.Fatalf("expected outer _ingest._value restored after inner foreach failure, got %v", restoredOut)
	}
}

func TestRound58_F28_IngestCSVCompliance(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Reject duplicate target_fields at PUT time
	if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/csv_dup", `{
		"processors": [{"csv": {"field": "line", "target_fields": ["a", "b", "a"]}}]
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on duplicate csv.target_fields, got %d", c)
	}

	// 2. Empty line, TSV "\t\t", short row without trailing empty_value, and quoted empty cell ""
	code, _, simCSV, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"if": "ctx.mode == 'csv_emp'",
					"csv": {"field": "raw", "target_fields": ["c1", "c2", "c3", "c4"], "empty_value": "NA"}
				},
				{
					"if": "ctx.mode == 'csv_emp_no_ev'",
					"csv": {"field": "raw", "target_fields": ["c1", "c2"]}
				},
				{
					"if": "ctx.mode == 'tsv'",
					"csv": {"field": "raw", "separator": "\t", "target_fields": ["t1", "t2", "t3"], "empty_value": "EMPTY"}
				},
				{
					"if": "ctx.mode == 'quoted'",
					"csv": {"field": "raw", "target_fields": ["q1", "q2", "q3"]}
				}
			]
		},
		"docs": [
			{"_source": {"mode": "csv_emp", "raw": "\n"}},
			{"_source": {"mode": "csv_emp", "raw": "x,y"}},
			{"_source": {"mode": "tsv", "raw": "\t\t"}},
			{"_source": {"mode": "quoted", "raw": "a,\"\",c"}},
			{"_source": {"mode": "csv_emp_no_ev", "raw": ""}}
		]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("CSV simulate failed: %d %v", code, simCSV)
	}
	docs := simCSV["docs"].([]any)
	d0 := docs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d0["c1"] != nil {
		t.Fatalf("empty input line must not populate target_fields, got %v", d0)
	}
	d1 := docs[1].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d1["c1"] != "x" || d1["c2"] != "y" || d1["c3"] != nil || d1["c4"] != nil {
		t.Fatalf("short CSV row must not populate trailing columns c3/c4, got %v", d1)
	}
	d2 := docs[2].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d2["t1"] != "EMPTY" || d2["t2"] != "EMPTY" || d2["t3"] != "EMPTY" {
		t.Fatalf("expected '\\t\\t' to parse as 3 empty TSV columns, got %v", d2)
	}
	d3 := docs[3].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d3["q1"] != "a" || d3["q2"] != "" || d3["q3"] != "c" {
		t.Fatalf("expected quoted empty cell to set q2=\"\" when empty_value omitted, got %v", d3)
	}
	d4 := docs[4].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if d4["c1"] != nil {
		t.Fatalf("empty string without empty_value must not populate target_fields, got %v", d4)
	}
}

func TestRound58_F29_IngestDissectGrammarPaddingAndReroute(t *testing.T) {
	_, handler := newTestServerWithMock(t)

	// 1. Invalid dissect patterns rejected at PUT time (400)
	badPatterns := []string{
		`%{&dangling}`,
		`%{a}%{b}`,
		`%{a/1} %{b}`,
		`%{+a/0} %{b}`,
		`%{+a/notnum} %{b}`,
		`%{+} %{b}`,
		`%{*} %{b}`,
		`%{&} %{b}`,
	}
	for _, pat := range badPatterns {
		body := fmt.Sprintf(`{"processors":[{"dissect":{"field":"msg","pattern":%q}}]}`, pat)
		if c, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/bad_dissect", body, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on invalid dissect pattern %q, got %d", pat, c)
		}
	}

	// Valid anonymous skip %{} and named skip %{?skip} + right-padding -> stripping repeated spaces/tabs
	code, _, _, _ := doRound58Req(t, handler, http.MethodPut, "/_ingest/pipeline/good_dissect", `{
		"processors": [{
			"dissect": {
				"field": "msg",
				"pattern": "%{} %{?ignored->} %{col1->} %{*k} %{&k}"
			}
		}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected valid dissect pattern to succeed, got %d", code)
	}
	code, _, simDissect, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/good_dissect/_simulate", `{
		"docs": [{"_source": {"msg": "DROP SKIP     val_one      dyn_key dyn_val"}}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("dissect simulate failed: %d %v", code, simDissect)
	}
	disSrc := simDissect["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if disSrc["col1"] != "val_one" || disSrc["dyn_key"] != "dyn_val" {
		t.Fatalf("expected -> to strip repeated space padding and populate indirect key, got %v", disSrc)
	}

	// 2. reroute ignore_missing: false vs default true
	code, _, simReroute, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"reroute": {
						"destination": "logs-{{missing_target}}",
						"ignore_missing": false
					}
				}
			]
		},
		"docs": [{"_index": "logs-generic-default", "_source": {"msg": "hello"}}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("reroute simulate HTTP failed: %d", code)
	}
	simDoc0 := simReroute["docs"].([]any)[0].(map[string]any)
	if simDoc0["error"] == nil {
		t.Fatalf("expected reroute error when ignore_missing=false and template field is missing, got %v", simDoc0)
	}

	// Default ignore_missing: true keeps original _index without failing
	code, _, simRerouteOK, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"reroute": {
						"destination": "logs-{{missing_target}}"
					}
				}
			]
		},
		"docs": [{"_index": "logs-generic-default", "_source": {"msg": "hello"}}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("reroute default ignore_missing simulate failed: %d", code)
	}
	simDocOK := simRerouteOK["docs"].([]any)[0].(map[string]any)
	if simDocOK["error"] != nil || simDocOK["doc"].(map[string]any)["_index"] != "logs-generic-default" {
		t.Fatalf("expected reroute default ignore_missing=true to succeed cleanly, got %v", simDocOK)
	}

	// Explicit destination reroute halts subsequent processors even if target matches _index
	code, _, simRerouteHalt, _ := doRound58Req(t, handler, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"reroute": {"destination": "logs-generic-default"}},
				{"set": {"field": "after_reroute", "value": true}}
			]
		},
		"docs": [{"_index": "logs-generic-default", "_source": {"msg": "hello"}}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("reroute halt simulate failed: %d", code)
	}
	haltSrc := simRerouteHalt["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if haltSrc["after_reroute"] != nil {
		t.Fatalf("expected explicit destination reroute to halt pipeline, got %v", haltSrc)
	}
}

func TestRound58_ExtendedHelpersTransformRollupAndRerouteCoverage(t *testing.T) {
	// 1. Date math index expression & value comparison helpers
	if got := resolveDateMathIndexExpr("<logs-{now/d}>"); !strings.HasPrefix(got, "logs-") {
		t.Fatalf("expected resolved date math prefix logs-, got %q", got)
	}
	if got := resolveDateMathIndexExpr("<logs-{now/d|yyyy-MM-dd}-v1>"); !strings.HasPrefix(got, "logs-") || !strings.HasSuffix(got, "-v1") {
		t.Fatalf("expected custom format date math, got %q", got)
	}
	if got := resolveDateMathIndexExpr("<plain-idx>"); got != "plain-idx" {
		t.Fatalf("expected <plain-idx> -> plain-idx, got %q", got)
	}

	// Timestamp & interval parsing helpers
	tsInputs := []any{
		float64(1700000000000),
		int64(1700000000000),
		int(1700000000000),
		json.Number("1700000000000"),
		json.Number("1700000000000.5"),
		"2026-01-15T10:20:30Z",
		"2026-01-15 10:20:30",
		"2026-01-15",
		"1700000000000",
	}
	for _, in := range tsInputs {
		if _, ok := parseAnyTimestampMillis(in); !ok {
			t.Fatalf("expected parseAnyTimestampMillis(%#v) to succeed", in)
		}
	}
	if _, ok := parseAnyTimestampMillis(""); ok {
		t.Fatalf("expected empty string timestamp to fail")
	}
	if _, ok := parseAnyTimestampMillis("not-a-ts"); ok {
		t.Fatalf("expected invalid timestamp string to fail")
	}

	for _, iv := range []string{"", "1m", "1h", "1d", "1w", "month", "1M", "year", "1y", "15m"} {
		ms := parseCalendarOrFixedIntervalMillis(map[string]any{"calendar_interval": iv})
		if ms <= 0 {
			t.Fatalf("expected positive millis for %q, got %d", iv, ms)
		}
		if b := bucketDateMillis(1700000000000, map[string]any{"calendar_interval": iv}); b == "" {
			t.Fatalf("expected non-empty bucketDateMillis for %q", iv)
		}
	}

	if compareAnyDocValues("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z") >= 0 ||
		compareAnyDocValues("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z") <= 0 ||
		compareAnyDocValues("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z") != 0 {
		t.Fatalf("unexpected timestamp compareAnyDocValues result")
	}
	if compareAnyDocValues(1.5, 2.5) >= 0 || compareAnyDocValues(2.5, 1.5) <= 0 || compareAnyDocValues(2.0, 2.0) != 0 {
		t.Fatalf("unexpected numeric compareAnyDocValues result")
	}
	if compareAnyDocValues("alpha", "beta") >= 0 || compareAnyDocValues("beta", "alpha") <= 0 || compareAnyDocValues("alpha", "alpha") != 0 {
		t.Fatalf("unexpected string compareAnyDocValues result")
	}

	// 2. computeTransformMetricAgg across all metric types (non-empty and empty)
	sampleDocs := []map[string]any{
		{"v": 10.0, "tag": "a", "ts": "2026-01-01T00:00:00Z"},
		{"v": 30.0, "tag": "b", "ts": "2026-01-03T00:00:00Z"},
		{"v": 20.0, "tag": "a", "ts": "2026-01-02T00:00:00Z"},
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"avg": map[string]any{"field": "v"}}); got != 20.0 {
		t.Fatalf("expected avg=20.0, got %v", got)
	}
	if got := computeTransformMetricAgg(nil, map[string]any{"avg": map[string]any{"field": "v"}}); got != nil {
		t.Fatalf("expected empty avg=nil, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"min": map[string]any{"field": "v"}}); got != 10.0 {
		t.Fatalf("expected min=10.0, got %v", got)
	}
	if got := computeTransformMetricAgg(nil, map[string]any{"min": map[string]any{"field": "v"}}); got != nil {
		t.Fatalf("expected empty min=nil, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"max": map[string]any{"field": "v"}}); got != 30.0 {
		t.Fatalf("expected max=30.0, got %v", got)
	}
	if got := computeTransformMetricAgg(nil, map[string]any{"max": map[string]any{"field": "v"}}); got != nil {
		t.Fatalf("expected empty max=nil, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"value_count": map[string]any{"field": "v"}}); got != int64(3) {
		t.Fatalf("expected value_count=3, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"cardinality": map[string]any{"field": "tag"}}); got != int64(2) {
		t.Fatalf("expected cardinality=2, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"stats": map[string]any{"field": "v"}}); got.(map[string]any)["sum"] != 60.0 {
		t.Fatalf("expected stats.sum=60.0, got %v", got)
	}
	if got := computeTransformMetricAgg(nil, map[string]any{"stats": map[string]any{"field": "v"}}); got.(map[string]any)["count"] != int64(0) {
		t.Fatalf("expected empty stats.count=0, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"top_hits": map[string]any{"size": 2.0}}); len(got.([]any)) != 2 {
		t.Fatalf("expected top_hits size=2 slice, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"top_hits": map[string]any{"size": 1.0}}); got.(map[string]any)["v"] != 10.0 {
		t.Fatalf("expected top_hits size=1 map, got %v", got)
	}
	if got := computeTransformMetricAgg(sampleDocs, map[string]any{"latest": map[string]any{"sort": "ts"}}); got.(map[string]any)["v"] != 30.0 {
		t.Fatalf("expected latest by ts to pick v=30.0, got %v", got)
	}

	// 3. tryRenderMustacheStrict & executeRerouteProcessorRound58 dataset/namespace branches
	if s, ok := tryRenderMustacheStrict("a-{{{k}}}-b", map[string]any{"k": "val"}); !ok || s != "a-val-b" {
		t.Fatalf("expected triple mustache render a-val-b, got %q %v", s, ok)
	}
	if _, ok := tryRenderMustacheStrict("a-{{unclosed", map[string]any{"unclosed": "x"}); ok {
		t.Fatalf("expected unclosed mustache to fail")
	}
	if _, ok := tryRenderMustacheStrict("a-{{}}-b", map[string]any{}); ok {
		t.Fatalf("expected empty mustache key to fail")
	}
	rrDoc := map[string]any{
		"_index": "metrics-old-default",
		"svc":    "my-app",
		"data_stream": map[string]any{
			"namespace": "prod-eu",
		},
	}
	halted, err := executeRerouteProcessorRound58(rrDoc, map[string]any{
		"dataset":       []any{"missing_f", "svc"},
		"remove_fields": true,
	})
	if err != nil || !halted || rrDoc["_index"] != "metrics-my_app-prod_eu" {
		t.Fatalf("unexpected reroute dataset/namespace result: halted=%v err=%v doc=%v", halted, err, rrDoc)
	}
	if _, exists := rrDoc["svc"]; exists {
		t.Fatalf("expected remove_fields=true to remove svc, got %v", rrDoc)
	}

	// 4. End-to-end _rollup_search with bool/term/terms queries and min/max/avg/value_count/terms/date_histogram aggs
	_, handler := newTestServerWithMock(t)
	doRound58Req(t, handler, http.MethodPut, "/r58_ru_cov_src", `{
		"mappings": {"properties": {"ts": {"type": "date"}, "host": {"type": "keyword"}, "env": {"type": "keyword"}, "lat": {"type": "double"}}}
	}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_ru_cov_src/_doc/1?refresh=true", `{"ts":"2026-02-01T00:10:00Z","host":"h1","env":"prod","lat":10}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_ru_cov_src/_doc/2?refresh=true", `{"ts":"2026-02-01T00:20:00Z","host":"h1","env":"prod","lat":30}`, nil)
	doRound58Req(t, handler, http.MethodPut, "/r58_ru_cov_src/_doc/3?refresh=true", `{"ts":"2026-02-01T01:15:00Z","host":"h2","env":"dev","lat":50}`, nil)

	code, _, _, rawPutJob := doRound58Req(t, handler, http.MethodPut, "/_rollup/job/r58_ru_cov_job", `{
		"index_pattern": "r58_ru_cov_src",
		"rollup_index": "r58_ru_cov_dest",
		"cron": "0 * * * * ?",
		"page_size": 100,
		"groups": {
			"date_histogram": {"field": "ts", "fixed_interval": "1h"},
			"terms": {"fields": ["host", "env"]}
		},
		"metrics": [{"field": "lat", "metrics": ["min", "max", "sum", "avg", "value_count"]}]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT rollup job failed: %d %s", code, rawPutJob)
	}
	doRound58Req(t, handler, http.MethodPost, "/_rollup/job/r58_ru_cov_job/_start", "", nil)

	code, _, ruSearch, rawRuSearch := doRound58Req(t, handler, http.MethodPost, "/r58_ru_cov_dest/_rollup_search", `{
		"size": 0,
		"query": {
			"bool": {
				"must": [{"term": {"env": "prod"}}],
				"filter": [{"terms": {"host": ["h1", "h2"]}}],
				"must_not": [{"term": {"host": "h9"}}],
				"should": [{"term": {"host": "h1"}}]
			}
		},
		"aggs": {
			"min_lat": {"min": {"field": "lat"}},
			"max_lat": {"max": {"field": "lat"}},
			"avg_lat": {"avg": {"field": "lat"}},
			"cnt_lat": {"value_count": {"field": "lat"}},
			"by_host": {
				"terms": {"field": "host"},
				"aggs": {"sum_lat": {"sum": {"field": "lat"}}}
			},
			"by_hour": {
				"date_histogram": {"field": "ts", "fixed_interval": "1h"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("_rollup_search failed: %d %s", code, rawRuSearch)
	}
	aggs := ruSearch["aggregations"].(map[string]any)
	if aggs["min_lat"].(map[string]any)["value"] != 10.0 ||
		aggs["max_lat"].(map[string]any)["value"] != 30.0 ||
		aggs["avg_lat"].(map[string]any)["value"] != 20.0 ||
		aggs["cnt_lat"].(map[string]any)["value"] != 2.0 {
		t.Fatalf("unexpected _rollup_search metric aggs: %s", rawRuSearch)
	}
	if len(aggs["by_host"].(map[string]any)["buckets"].([]any)) != 1 ||
		len(aggs["by_hour"].(map[string]any)["buckets"].([]any)) != 1 {
		t.Fatalf("unexpected _rollup_search bucket aggs: %s", rawRuSearch)
	}
}
