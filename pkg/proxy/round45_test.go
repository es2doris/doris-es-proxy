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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
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

	// Additional coverage for t_test (homoscedastic, heteroscedastic, filters), geo_grid bounds (top_left/bottom_right, top_right/bottom_left, top/left/bottom/right),
	// geo_distance units (mi, yd, ft, in, cm, mm, nmi), rare_terms include/exclude + sub-aggs, runtime boxplot/string_stats/rate,
	// runtime_mappings types (boolean, long, date, ip, geo_point, composite), network_direction, community_id, _terms_enum, and _field_caps.
	doRound39JSON(t, srv, http.MethodPost, "/r45_misc/_search", `{
		"size": 10,
		"runtime_mappings": {
			"rt_bool": {"type": "boolean", "script": {"source": "emit(true)"}},
			"rt_long": {"type": "long", "script": {"source": "emit(42)"}},
			"rt_date": {"type": "date", "script": {"source": "emit('2025-01-01T00:00:00Z')"}},
			"rt_ip": {"type": "ip", "script": {"source": "emit('10.0.0.1')"}},
			"rt_geo": {"type": "geo_point", "script": {"source": "emit('40.71,-74.00')"}},
			"rt_comp": {
				"type": "composite",
				"script": {"source": "emit([name: 'alice'])"},
				"fields": {"name": {"type": "keyword"}}
			}
		},
		"fields": ["*"]
	}`)

	doRound39JSON(t, srv, http.MethodPut, "/r45_cov", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"a": {"type": "double"},
				"b": {"type": "double"},
				"ts": {"type": "date"},
				"loc": {"type": "geo_point"}
			}
		}
	}`)
	for i, d := range []string{
		`{"grp": "g1", "a": 10.0, "b": 12.0, "ts": "2025-01-01T00:00:00Z", "loc": {"lat": 40.71, "lon": -74.00}}`,
		`{"grp": "g1", "a": 20.0, "b": 25.0, "ts": "2025-01-01T01:00:00Z", "loc": {"lat": 34.05, "lon": -118.24}}`,
		`{"grp": "g2", "a": 15.0, "b": 30.0, "ts": "2025-02-01T00:00:00Z", "loc": {"lat": 41.87, "lon": 170.00}}`,
		`{"grp": "g2", "a": 35.0, "b": 45.0, "ts": "2026-01-01T00:00:00Z", "loc": {"lat": 37.77, "lon": -170.00}}`,
	} {
		doRound39JSON(t, srv, http.MethodPut, fmt.Sprintf("/r45_cov/_doc/%d?refresh=true", i+1), d)
	}

	_, covAggRes := doRound39JSON(t, srv, http.MethodPost, "/r45_cov/_search", `{
		"size": 0,
		"aggs": {
			"tt_homo": {
				"t_test": {
					"a": {"field": "a", "filter": {"term": {"grp": "g1"}}},
					"b": {"field": "b", "filter": {"term": {"grp": "g2"}}},
					"type": "homoscedastic"
				}
			},
			"tt_hetero": {
				"t_test": {
					"a": {"field": "a"},
					"b": {"field": "b"},
					"type": "heteroscedastic"
				}
			},
			"gh_tlbr": {
				"geohash_grid": {
					"field": "loc",
					"precision": 3,
					"size": 2,
					"bounds": {
						"top_left": {"lat": 50.0, "lon": -130.0},
						"bottom_right": {"lat": 30.0, "lon": -70.0}
					},
					"aggs": {"avg_a": {"avg": {"field": "a"}}}
				}
			},
			"gt_trbl": {
				"geotile_grid": {
					"field": "loc",
					"precision": 4,
					"bounds": {
						"top_right": {"lat": 50.0, "lon": -70.0},
						"bottom_left": {"lat": 30.0, "lon": -130.0}
					}
				}
			},
			"gh_box": {
				"geohash_grid": {
					"field": "loc",
					"precision": 2,
					"bounds": {"top": 50.0, "left": 160.0, "bottom": 30.0, "right": -160.0}
				}
			},
			"gd_mi": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "mi", "ranges": [{"to": 100}, {"from": 100}], "aggs": {"mx": {"max": {"field": "a"}}}}},
			"gd_yd": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "yd", "ranges": [{"to": 1000}]}},
			"gd_ft": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "ft", "ranges": [{"to": 1000}]}},
			"gd_in": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "in", "ranges": [{"to": 1000}]}},
			"gd_cm": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "cm", "ranges": [{"to": 1000}]}},
			"gd_mm": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "mm", "ranges": [{"to": 1000}]}},
			"gd_nmi": {"geo_distance": {"field": "loc", "origin": "40.71,-74.00", "unit": "nmi", "ranges": [{"to": 1000}]}},
			"rare_inc": {
				"rare_terms": {
					"field": "grp",
					"max_doc_count": 2,
					"include": "g.*",
					"exclude": "none",
					"aggs": {"min_a": {"min": {"field": "a"}}}
				}
			},
			"adh_sub": {
				"auto_date_histogram": {
					"field": "ts",
					"buckets": 3,
					"minimum_interval": "day",
					"aggs": {
						"r_sum": {"rate": {"field": "a", "unit": "day", "mode": "sum"}},
						"r_vc": {"rate": {"field": "a", "unit": "day", "mode": "value_count"}}
					}
				}
			},
			"vwh_sub": {
				"variable_width_histogram": {
					"field": "a",
					"buckets": 2,
					"aggs": {"sum_b": {"sum": {"field": "b"}}}
				}
			},
			"script_terms": {
				"terms": {
					"script": {"source": "doc['grp'].value"}
				},
				"aggs": {
					"bp": {"boxplot": {"field": "a"}},
					"ss": {"string_stats": {"field": "grp"}},
					"wavg_fmt": {
						"weighted_avg": {
							"value": {"field": "a"},
							"weight": {"field": "b"},
							"format": "0.00"
						}
					}
				}
			}
		}
	}`)
	if covAggRes["aggregations"] == nil {
		t.Fatalf("expected covAggRes aggregations, got %+v", covAggRes)
	}

	// Test network_direction and community_id ingest processors
	doRound39JSON(t, srv, http.MethodPut, "/_ingest/pipeline/r45_net_pipe", `{
		"processors": [
			{
				"network_direction": {
					"source_ip": "src_ip",
					"destination_ip": "dst_ip",
					"target_field": "net_dir",
					"internal_networks": ["private", "loopback", "link_local", "multicast", "198.51.100.0/24", "203.0.113.5"]
				}
			},
			{
				"community_id": {
					"source_ip": "src_ip",
					"destination_ip": "dst_ip",
					"source_port": "src_port",
					"destination_port": "dst_port",
					"transport": "proto",
					"icmp_type": "icmp_t",
					"icmp_code": "icmp_c",
					"target_field": "cid",
					"seed": 1
				}
			}
		]
	}`)
	_, netSim := doRound39JSON(t, srv, http.MethodPost, "/_ingest/pipeline/r45_net_pipe/_simulate", `{
		"docs": [
			{"_source": {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 12345, "dst_port": 53, "proto": "udp"}},
			{"_source": {"src_ip": "8.8.8.8", "dst_ip": "198.51.100.42", "src_port": 443, "dst_port": 54321, "proto": "tcp"}},
			{"_source": {"src_ip": "127.0.0.1", "dst_ip": "169.254.1.1", "icmp_t": 8, "icmp_c": 0, "proto": "icmp"}},
			{"_source": {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "icmp_t": 128, "icmp_c": 0, "proto": "icmpv6"}}
		]
	}`)
	if len(netSim["docs"].([]any)) != 4 {
		t.Fatalf("expected 4 simulated net docs, got %+v", netSim)
	}

	// Test _terms_enum and _field_caps with filters
	_, teRes := doRound39JSON(t, srv, http.MethodPost, "/r45_cov/_terms_enum", `{
		"field": "grp",
		"string": "G",
		"case_insensitive": true,
		"size": 5,
		"index_filter": {"range": {"a": {"gte": 10}}}
	}`)
	if len(teRes["terms"].([]any)) != 2 {
		t.Fatalf("expected 2 terms from _terms_enum, got %+v", teRes)
	}
	_, fcRes := doRound39JSON(t, srv, http.MethodPost, "/r45_cov/_field_caps?fields=grp,a", `{
		"index_filter": {"term": {"grp": "g1"}}
	}`)
	if fcRes["fields"] == nil {
		t.Fatalf("expected fields in _field_caps, got %+v", fcRes)
	}

	// Test filter_path with ** wildcard
	reqGlob := httptest.NewRequest(http.MethodPost, "/r45_cov/_search?filter_path=**.hits._id,-**._score", strings.NewReader(`{"size": 2}`))
	reqGlob.Header.Set("Content-Type", "application/json")
	recGlob := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recGlob, reqGlob)
	if recGlob.Code != http.StatusOK {
		t.Fatalf("expected 200 for ** filter_path, got %d", recGlob.Code)
	}
}

func TestRound45HelperAndTypedKeysPrefixCoverage(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`{"significant_text":{"field":"f"}}`, "significant_text"},
		{`{"significant_terms":{"field":"f"}}`, "sterms"},
		{`{"terms":{"field":"f"}}`, "sterms"},
		{`{"date_histogram":{"field":"f"}}`, "date_histogram"},
		{`{"histogram":{"field":"f","interval":10}}`, "histogram"},
		{`{"date_range":{"field":"f"}}`, "date_range"},
		{`{"ip_range":{"field":"f"}}`, "ip_range"},
		{`{"range":{"field":"f"}}`, "range"},
		{`{"filters":{}}`, "filters"},
		{`{"filter":{"match_all":{}}}`, "filter"},
		{`{"missing":{"field":"f"}}`, "missing"},
		{`{"nested":{"path":"p"}}`, "nested"},
		{`{"reverse_nested":{}}`, "reverse_nested"},
		{`{"global":{}}`, "global"},
		{`{"diversified_sampler":{"field":"f"}}`, "diversified_sampler"},
		{`{"sampler":{}}`, "sampler"},
		{`{"composite":{"sources":[{"s":{"terms":{"field":"f"}}}]}}`, "composite"},
		{`{"avg":{"field":"f"}}`, "avg"},
		{`{"sum":{"field":"f"}}`, "sum"},
		{`{"min":{"field":"f"}}`, "min"},
		{`{"max":{"field":"f"}}`, "max"},
		{`{"value_count":{"field":"f"}}`, "value_count"},
		{`{"cardinality":{"field":"f"}}`, "cardinality"},
		{`{"extended_stats":{"field":"f"}}`, "extended_stats"},
		{`{"stats":{"field":"f"}}`, "stats"},
		{`{"string_stats":{"field":"f"}}`, "string_stats"},
		{`{"percentiles":{"field":"f"}}`, "tdigest_percentiles"},
		{`{"percentile_ranks":{"field":"f","values":[10]}}`, "tdigest_percentile_ranks"},
		{`{"boxplot":{"field":"f"}}`, "boxplot"},
		{`{"top_hits":{}}`, "top_hits"},
		{`{"top_metrics":{"metrics":[{"field":"f"}],"sort":[{"f":"desc"}]}}`, "top_metrics"},
		{`{"scripted_metric":{}}`, "scripted_metric"},
		{`{"rate":{"field":"f"}}`, "rate"},
		{`{"avg_bucket":{"buckets_path":"p"}}`, "avg_bucket"},
		{`{"sum_bucket":{"buckets_path":"p"}}`, "sum_bucket"},
		{`{"min_bucket":{"buckets_path":"p"}}`, "min_bucket"},
		{`{"max_bucket":{"buckets_path":"p"}}`, "max_bucket"},
		{`{"stats_bucket":{"buckets_path":"p"}}`, "stats_bucket"},
		{`{"extended_stats_bucket":{"buckets_path":"p"}}`, "extended_stats_bucket"},
		{`{"percentiles_bucket":{"buckets_path":"p"}}`, "percentiles_bucket"},
		{`{"derivative":{"buckets_path":"p"}}`, "derivative"},
		{`{"cumulative_cardinality":{"buckets_path":"p"}}`, "cumulative_cardinality"},
		{`{"cumulative_sum":{"buckets_path":"p"}}`, "cumulative_sum"},
		{`{"moving_avg":{"buckets_path":"p"}}`, "moving_avg"},
		{`{"moving_fn":{"buckets_path":"p","window":5,"script":"1"}}`, "moving_fn"},
		{`{"serial_diff":{"buckets_path":"p"}}`, "serial_diff"},
		{`{"normalize":{"buckets_path":"p","method":" rescale_0_1"}}`, "normalize"},
		{`{"bucket_script":{"buckets_path":{"a":"p"},"script":"params.a"}}`, "bucket_script"},
		{`{"bucket_sort":{}}`, "bucket_sort"},
		{`{"bucket_selector":{"buckets_path":{"a":"p"},"script":"params.a > 0"}}`, "bucket_selector"},
	}
	for _, tc := range cases {
		var spec esast.AggSpec
		if err := json.Unmarshal([]byte(tc.raw), &spec); err != nil {
			t.Fatalf("unmarshal %s failed: %v", tc.raw, err)
		}
		if got := aggTypePrefix(spec); got != tc.want {
			t.Fatalf("aggTypePrefix(%s) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	if got := aggTypePrefix(esast.AggSpec{}); got != "agg" {
		t.Fatalf("aggTypePrefix(empty) = %q, want agg", got)
	}

	if isTableNotFoundError(nil) || !isTableNotFoundError(fmt.Errorf("Unknown table 'foo'")) {
		t.Fatalf("unexpected isTableNotFoundError result")
	}
	if isAllDigitsASCII("") || isAllDigitsASCII("12a") || !isAllDigitsASCII("12345") {
		t.Fatalf("unexpected isAllDigitsASCII result")
	}
	if !jsonStructurallyEqual(json.RawMessage(`{"a":1,"b":2}`), json.RawMessage(`{"b": 2, "a": 1}`)) || jsonStructurallyEqual(json.RawMessage(`invalid`), json.RawMessage(`{}`)) {
		t.Fatalf("unexpected jsonStructurallyEqual result")
	}
	if !enrichSingleSpecMatchesSingleValue([]any{"10.0.0.0/8"}, "10.1.2.3") ||
		!enrichSingleSpecMatchesSingleValue(map[string]any{"gte": 10, "gt": 9, "lte": 20, "lt": 21}, 15) ||
		enrichSingleSpecMatchesSingleValue(map[string]any{"gte": 10, "lte": 20}, 25) {
		t.Fatalf("unexpected enrichSingleSpecMatchesSingleValue result")
	}
	ihMap := map[string]any{
		"inner_hits": map[string]any{
			"comments": map[string]any{
				"hits": map[string]any{
					"total": map[string]any{"value": int64(3)},
				},
			},
		},
	}
	convertInnerHitsTotalToInt([]any{ihMap})
	convertInnerHitsTotalToInt([]map[string]any{ihMap})

	for _, in := range []any{nil, true, false, "true", "1", "false", "0", "other", 123} {
		_, _ = parseOptionalBoolAny(in)
	}
	_ = compactIngestMap(map[string]any{"a": "", "b": nil, "c": "keep", "d": []any{"", "x"}, "e": map[string]any{"k": ""}})
	_, _ = parseIngestSliceIndex("", 3)
	_, _ = parseIngestSliceIndex("abc", 3)
	_, _ = parseIngestSliceIndex("-1", 3)
	_, _ = parseIngestSliceIndex("-5", 3)
	_, _ = parseIngestSliceIndex("5", 3)
	dst := map[string]any{"nested": map[string]any{"keep": 1}, "existing": "old"}
	deepMergeIngestMap(dst, map[string]any{"nested": map[string]any{"added": 2}, "existing": "new"})
	deepMergeIngestMapWithOverride(dst, map[string]any{"existing": "ignored", "fresh": "val"}, false)

	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	doRound39JSON(t, srv, http.MethodPut, "/r45_geo_sa", `{
		"mappings": {"properties": {"loc": {"type": "geo_point"}}}
	}`)
	doRound39JSON(t, srv, http.MethodPut, "/r45_geo_sa/_doc/1?refresh=true", `{"loc": {"lat": 40.71, "lon": -74.00}}`)
	for _, u := range []string{"km", "mi", "yd", "ft", "in", "nmi", "cm", "mm"} {
		doRound39JSON(t, srv, http.MethodPost, "/r45_geo_sa/_search", fmt.Sprintf(`{
			"sort": [{"_geo_distance": {"loc": {"lat": 40.0, "lon": -74.0}, "order": "asc", "unit": %q}}],
			"search_after": [1.5]
		}`, u))
	}
}
