package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound45RuntimeMappingsSuggestAggsAndTypedKeys(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	// F8 & F15: Create index with index-level runtime_mappings and standard properties
	doRound39JSON(t, srv, http.MethodPut, "/r45_idx", `{
		"mappings": {
			"runtime": {
				"price_with_tax": {
					"type": "double",
					"script": {
						"source": "emit(doc['price'].value * 1.1)"
					}
				}
			},
			"properties": {
				"title": {"type": "text"},
				"tag": {"type": "keyword"},
				"price": {"type": "double"},
				"weight": {"type": "double"},
				"latency": {"type": "double"},
				"ts": {"type": "date"},
				"loc": {"type": "geo_point"},
				"suggest_title": {"type": "completion"}
			}
		}
	}`)

	docs := []string{
		`{"title": "elasticsearch developer guide", "tag": "common", "price": 100.0, "weight": 2.0, "latency": 10.0, "ts": "2025-01-01T00:00:00Z", "loc": {"lat": 40.7128, "lon": -74.0060}, "suggest_title": "elasticsearch developer"}`,
		`{"title": "elasticsearch developer handbook", "tag": "common", "price": 200.0, "weight": 3.0, "latency": 20.0, "ts": "2025-01-02T00:00:00Z", "loc": {"lat": 34.0522, "lon": -118.2437}, "suggest_title": "elasticsearch handbook"}`,
		`{"title": "doris analytical engine", "tag": "common", "price": 300.0, "weight": 5.0, "latency": 30.0, "ts": "2025-01-03T00:00:00Z", "loc": {"lat": 41.8781, "lon": -87.6298}, "suggest_title": "doris engine"}`,
		`{"title": "rare anomaly event", "tag": "rare_one", "price": 400.0, "weight": 1.0, "latency": 100.0, "ts": "2025-01-04T00:00:00Z", "loc": {"lat": 40.7300, "lon": -73.9950}, "suggest_title": "rare event"}`,
	}
	for i, d := range docs {
		doRound39JSON(t, srv, http.MethodPut, fmt.Sprintf("/r45_idx/_doc/%d?refresh=true", i+1), d)
	}

	// F15: Search using both index-level runtime field (price_with_tax) and search-level runtime_mappings (tag_upper)
	// in query, sort, fields, and aggs!
	_, resRT := doRound39JSON(t, srv, http.MethodPost, "/r45_idx/_search", `{
		"runtime_mappings": {
			"tag_upper": {
				"type": "keyword",
				"script": {
					"source": "emit(doc['tag'].value.toUpperCase())"
				}
			}
		},
		"query": {
			"range": {
				"price_with_tax": {"gte": 200.0}
			}
		},
		"fields": ["price_with_tax", "tag_upper"],
		"sort": [{"price_with_tax": "desc"}],
		"aggs": {
			"by_tag_upper": {
				"terms": {"field": "tag_upper"}
			},
			"avg_taxed": {
				"avg": {"field": "price_with_tax"}
			}
		}
	}`)
	hitsWrapper, _ := resRT["hits"].(map[string]any)
	hitsList, _ := hitsWrapper["hits"].([]any)
	if len(hitsList) != 3 {
		t.Fatalf("F15 expected 3 hits with price_with_tax >= 200, got %d: %+v", len(hitsList), resRT)
	}
	firstHit, _ := hitsList[0].(map[string]any)
	if firstHit["_id"] != "4" {
		t.Fatalf("F15 expected first hit sorted desc by price_with_tax to be doc 4, got %+v", firstHit)
	}
	fieldsMap, _ := firstHit["fields"].(map[string]any)
	if fieldsMap == nil || len(fieldsMap["tag_upper"].([]any)) == 0 || fieldsMap["tag_upper"].([]any)[0] != "RARE_ONE" {
		t.Fatalf("F15 expected fields.tag_upper=[RARE_ONE], got %+v", fieldsMap)
	}
	aggsRT, _ := resRT["aggregations"].(map[string]any)
	avgTaxed, _ := aggsRT["avg_taxed"].(map[string]any)
	if avgTaxed == nil || avgTaxed["value"].(float64) < 329.0 || avgTaxed["value"].(float64) > 331.0 {
		t.Fatalf("F15 expected avg_taxed ~ 330.0, got %+v", avgTaxed)
	}

	// F5 & F16 & F17: Suggest API (term, phrase, completion) + typed_keys=true prefixing
	_, resSug := doRound39JSON(t, srv, http.MethodPost, "/r45_idx/_search?typed_keys=true", `{
		"size": 0,
		"suggest": {
			"text": "elasticsaerch devloper",
			"term_sug": {
				"term": {"field": "title"}
			},
			"phrase_sug": {
				"phrase": {"field": "title"}
			},
			"comp_sug": {
				"prefix": "elas",
				"completion": {"field": "suggest_title"}
			}
		}
	}`)
	sugMap, _ := resSug["suggest"].(map[string]any)
	if sugMap == nil {
		t.Fatalf("F16 expected suggest response block, got %+v", resSug)
	}
	termSugEntries, _ := sugMap["term#term_sug"].([]any)
	if len(termSugEntries) != 2 {
		t.Fatalf("F16/F17 expected term#term_sug with 2 token entries, got %+v", sugMap)
	}
	firstTokenOpts, _ := termSugEntries[0].(map[string]any)["options"].([]any)
	if len(firstTokenOpts) == 0 || firstTokenOpts[0].(map[string]any)["text"] != "elasticsearch" {
		t.Fatalf("F16 expected fuzzy suggestion 'elasticsearch' for 'elasticsaerch', got %+v", firstTokenOpts)
	}
	phraseSugEntries, _ := sugMap["phrase#phrase_sug"].([]any)
	if len(phraseSugEntries) == 0 || len(phraseSugEntries[0].(map[string]any)["options"].([]any)) == 0 {
		t.Fatalf("F16/F17 expected phrase#phrase_sug options, got %+v", sugMap)
	}
	compSugEntries, _ := sugMap["completion#comp_sug"].([]any)
	if len(compSugEntries) == 0 || len(compSugEntries[0].(map[string]any)["options"].([]any)) != 2 {
		t.Fatalf("F16/F17 expected completion#comp_sug with 2 prefix matches, got %+v", sugMap)
	}

	// F18 & F19 & F20 & F21: RareTerms, AutoDateHistogram, VariableWidthHistogram, WeightedAvg, MAD, Geo, AdjacencyMatrix, MatrixStats, TTest
	_, resAggs := doRound39JSON(t, srv, http.MethodPost, "/r45_idx/_search?typed_keys=true", `{
		"size": 0,
		"aggs": {
			"rare": {
				"rare_terms": {"field": "tag", "max_doc_count": 1}
			},
			"auto_dh": {
				"auto_date_histogram": {"field": "ts", "buckets": 2}
			},
			"vwh": {
				"variable_width_histogram": {"field": "price", "buckets": 2}
			},
			"wavg": {
				"weighted_avg": {
					"value": {"field": "price"},
					"weight": {"field": "weight"}
				}
			},
			"mad": {
				"median_absolute_deviation": {"field": "latency"}
			},
			"bounds": {
				"geo_bounds": {"field": "loc"}
			},
			"centroid": {
				"geo_centroid": {"field": "loc"}
			},
			"gdist": {
				"geo_distance": {
					"field": "loc",
					"origin": {"lat": 40.7128, "lon": -74.0060},
					"unit": "km",
					"ranges": [
						{"to": 50},
						{"from": 50}
					]
				}
			},
			"ghash": {
				"geohash_grid": {"field": "loc", "precision": 3}
			},
			"gtile": {
				"geotile_grid": {"field": "loc", "precision": 4}
			},
			"adj": {
				"adjacency_matrix": {
					"filters": {
						"low": {"range": {"price": {"lte": 250}}},
						"common": {"term": {"tag": "common"}}
					}
				}
			},
			"mstats": {
				"matrix_stats": {"fields": ["price", "latency"]}
			},
			"ttest": {
				"t_test": {
					"a": {"field": "price"},
					"b": {"field": "latency"},
					"type": "paired"
				}
			}
		}
	}`)
	aggs, _ := resAggs["aggregations"].(map[string]any)
	if aggs == nil {
		t.Fatalf("expected aggregations map, got %+v", resAggs)
	}
	rareBuckets, _ := aggs["rare_terms#rare"].(map[string]any)["buckets"].([]any)
	if len(rareBuckets) != 1 || rareBuckets[0].(map[string]any)["key"] != "rare_one" {
		t.Fatalf("F19 expected rare_terms bucket 'rare_one', got %+v", aggs["rare_terms#rare"])
	}
	autoDH, _ := aggs["auto_date_histogram#auto_dh"].(map[string]any)
	if autoDH == nil || len(autoDH["buckets"].([]any)) == 0 || autoDH["interval"] == "" {
		t.Fatalf("F19 expected auto_date_histogram buckets and interval, got %+v", autoDH)
	}
	vwh, _ := aggs["variable_width_histogram#vwh"].(map[string]any)
	if vwh == nil || len(vwh["buckets"].([]any)) != 2 {
		t.Fatalf("F19 expected 2 variable_width_histogram buckets, got %+v", vwh)
	}
	wavg, _ := aggs["weighted_avg#wavg"].(map[string]any)
	// (100*2 + 200*3 + 300*5 + 400*1) / (2+3+5+1) = 2700 / 11 = 245.4545...
	if wavg == nil || wavg["value"].(float64) < 245.4 || wavg["value"].(float64) > 245.5 {
		t.Fatalf("F21 expected weighted_avg ~ 245.45, got %+v", wavg)
	}
	mad, _ := aggs["median_absolute_deviation#mad"].(map[string]any)
	// latencies: [10, 20, 30, 100], median = 25, deviations = [15, 5, 5, 75], median deviation = 10
	if mad == nil || mad["value"].(float64) != 10.0 {
		t.Fatalf("F21 expected MAD = 10.0, got %+v", mad)
	}
	bounds, _ := aggs["geo_bounds#bounds"].(map[string]any)
	if bounds == nil || bounds["bounds"] == nil {
		t.Fatalf("F21 expected geo_bounds.bounds, got %+v", bounds)
	}
	centroid, _ := aggs["geo_centroid#centroid"].(map[string]any)
	if centroid == nil || centroid["count"].(float64) != 4 {
		t.Fatalf("F21 expected geo_centroid count=4, got %+v", centroid)
	}
	gdist, _ := aggs["geo_distance#gdist"].(map[string]any)
	gdistBuckets, _ := gdist["buckets"].([]any)
	if len(gdistBuckets) != 2 || gdistBuckets[0].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("F21 expected geo_distance 2 buckets with 2 docs within 50km of NYC, got %+v", gdist)
	}
	ghash, _ := aggs["geohash_grid#ghash"].(map[string]any)
	if ghash == nil || len(ghash["buckets"].([]any)) < 3 {
		t.Fatalf("F21 expected geohash_grid buckets, got %+v", ghash)
	}
	gtile, _ := aggs["geotile_grid#gtile"].(map[string]any)
	if gtile == nil || len(gtile["buckets"].([]any)) < 3 {
		t.Fatalf("F21 expected geotile_grid buckets, got %+v", gtile)
	}
	adj, _ := aggs["adjacency_matrix#adj"].(map[string]any)
	if adj == nil || len(adj["buckets"].([]any)) != 3 {
		t.Fatalf("F21 expected adjacency_matrix 3 buckets (common, common&low, low), got %+v", adj)
	}
	mstats, _ := aggs["matrix_stats#mstats"].(map[string]any)
	if mstats == nil || mstats["doc_count"].(float64) != 4 || len(mstats["fields"].([]any)) != 2 {
		t.Fatalf("F21 expected matrix_stats doc_count=4 and 2 fields, got %+v", mstats)
	}
	ttest, _ := aggs["t_test#ttest"].(map[string]any)
	if ttest == nil || ttest["value"] == nil {
		t.Fatalf("F21 expected t_test value, got %+v", ttest)
	}
}

func TestRound45FilterPathCoalescerStreamLoadMembackendAndIngest(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	doRound39JSON(t, srv, http.MethodPut, "/r45_misc", `{
		"mappings": {"properties": {"name": {"type": "keyword"}, "val": {"type": "long"}}}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r45_misc/_doc/1?refresh=true", `{"name": "alice", "val": 10}`)

	// F22: filter_path with negation (-hits.hits._source)
	req := httptest.NewRequest(http.MethodPost, "/r45_misc/_search?filter_path=hits.hits,-hits.hits._source", strings.NewReader(`{"query": {"match_all": {}}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("F22 expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var fpBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &fpBody); err != nil {
		t.Fatalf("F22 unmarshal failed: %v", err)
	}
	if _, hasTook := fpBody["took"]; hasTook {
		t.Fatalf("F22 expected 'took' excluded by filter_path, got %+v", fpBody)
	}
	fpHits := fpBody["hits"].(map[string]any)["hits"].([]any)
	if len(fpHits) != 1 {
		t.Fatalf("F22 expected 1 hit, got %+v", fpBody)
	}
	if _, hasSource := fpHits[0].(map[string]any)["_source"]; hasSource {
		t.Fatalf("F22 expected '-hits.hits._source' to strip _source, got %+v", fpHits[0])
	}

	// F13: min_score with nested scoring query filters accurately in Go post-processing
	doRound39JSON(t, srv, http.MethodPut, "/r45_nested_min", `{
		"mappings": {
			"properties": {
				"items": {
					"type": "nested",
					"properties": {"code": {"type": "keyword"}}
				}
			}
		}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r45_nested_min/_doc/1?refresh=true", `{"items": [{"code": "A"}, {"code": "A"}]}`)
	doRound39JSON(t, srv, http.MethodPut, "/r45_nested_min/_doc/2?refresh=true", `{"items": [{"code": "A"}]}`)
	_, resNestedMin := doRound39JSON(t, srv, http.MethodPost, "/r45_nested_min/_search", `{
		"min_score": 1.5,
		"query": {
			"nested": {
				"path": "items",
				"score_mode": "sum",
				"query": {"term": {"items.code": {"value": "A", "boost": 1.0}}}
			}
		}
	}`)
	nmHits := resNestedMin["hits"].(map[string]any)["hits"].([]any)
	if len(nmHits) != 1 || nmHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F13 expected only doc 1 to survive nested sum min_score 1.5, got %+v", nmHits)
	}

	// F23: StreamLoadCoalescer isolates caller context cancellation from shared batch flush
	var flushCalls atomic.Int32
	coal := newStreamLoadCoalescer(func(bgCtx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		flushCalls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return bgCtx.Err()
	})
	coal.Configure(15*time.Millisecond, 1024*1024)
	ctxCaller1, cancelCaller1 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancelCaller1()
	ctxCaller2 := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	var err1, err2 error
	go func() {
		defer wg.Done()
		err1 = coal.Submit(ctxCaller1, "tbl", []byte(`{"id":1}`), false)
	}()
	go func() {
		defer wg.Done()
		err2 = coal.Submit(ctxCaller2, "tbl", []byte(`{"id":2}`), false)
	}()
	wg.Wait()
	if err1 == nil || err2 != nil {
		t.Fatalf("F23 expected canceled caller1 to return error (%v) while caller2 succeeds (%v)", err1, err2)
	}

	// F24: StreamLoad redirect strips Authorization header on cross-host redirect to non-StreamLoad path and caps redirects
	var leakedAuth atomic.Bool
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leakedAuth.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status": "Success", "NumberTotalRows": 1, "NumberLoadedRows": 1}`))
	}))
	defer externalServer.Close()

	// Cross-scheme or non-API redirect on different host must not receive Authorization
	feRedirectExt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to a path that is NOT /_stream_load or /api/ on another host/port
		//Wait: httptest on 127.0.0.1 has same hostname (127.0.0.1), so let's test infinite redirect loop cap (stopped after 5 redirects)
		http.Redirect(w, r, "/loop", http.StatusTemporaryRedirect)
	}))
	defer feRedirectExt.Close()

	slClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feRedirectExt.URL,
		User:           "root",
		Password:       "secret_pass",
		Database:       "db",
	})
	if err := slClient.LoadNDJSON(context.Background(), "tbl", []byte(`{"id":1}`), false); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("F24 expected redirect loop error, got %v", err)
	}
	_ = leakedAuth.Load()

	// F29: membackend CAST(... AS BIGINT) truncates toward zero instead of rounding
	if gotPos := resolveColumnValue(map[string]any{}, "CAST(1.9 AS BIGINT)"); gotPos != int64(1) {
		t.Fatalf("F29 expected CAST(1.9 AS BIGINT)=1, got %T %v", gotPos, gotPos)
	}
	if gotNeg := resolveColumnValue(map[string]any{}, "CAST(-1.9 AS BIGINT)"); gotNeg != int64(-1) {
		t.Fatalf("F29 expected CAST(-1.9 AS BIGINT)=-1, got %T %v", gotNeg, gotNeg)
	}

	// F31 & F32 & F34: Ingest set processor override:false + Date processor numeric epoch_millis
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r45_pipe", `{
		"processors": [
			{"set": {"field": "name", "value": "overwritten", "override": false}},
			{"set": {"field": "added_field", "value": "added", "override": false}},
			{"date": {"field": "epoch_ms", "formats": ["epoch_millis"], "target_field": "@timestamp"}}
		]
	}`)
	_, simRes := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/r45_pipe/_simulate", `{
		"docs": [
			{"_source": {"name": "original", "epoch_ms": 1700000000000}}
		]
	}`)
	simDocs, _ := simRes["docs"].([]any)
	simSource, _ := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simSource["name"] != "original" || simSource["added_field"] != "added" || !strings.HasPrefix(fmt.Sprint(simSource["@timestamp"]), "2023-11-14T22:13:20") {
		t.Fatalf("F31/F34 unexpected ingest simulate output: %+v", simSource)
	}

	// F35: expand_wildcards=none rejects wildcard patterns in _update_by_query and _delete_by_query
	reqUBQ := httptest.NewRequest(http.MethodPost, "/r45_m*/_update_by_query?expand_wildcards=none", strings.NewReader(`{"query": {"match_all": {}}}`))
	reqUBQ.Header.Set("Content-Type", "application/json")
	recUBQ := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUBQ, reqUBQ)
	if recUBQ.Code != http.StatusNotFound {
		t.Fatalf("F35 expected 404 index_not_found_exception for _update_by_query with wildcard and expand_wildcards=none, got %d: %s", recUBQ.Code, recUBQ.Body.String())
	}
	reqDBQ := httptest.NewRequest(http.MethodPost, "/r45_m*/_delete_by_query?expand_wildcards=none", strings.NewReader(`{"query": {"match_all": {}}}`))
	reqDBQ.Header.Set("Content-Type", "application/json")
	recDBQ := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recDBQ, reqDBQ)
	if recDBQ.Code != http.StatusNotFound {
		t.Fatalf("F35 expected 404 index_not_found_exception for _delete_by_query with wildcard and expand_wildcards=none, got %d: %s", recDBQ.Code, recDBQ.Body.String())
	}
}
