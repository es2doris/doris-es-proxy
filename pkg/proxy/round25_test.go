package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
)

func doRound25Req(t *testing.T, srv *Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var reqBody []byte
	if body != nil {
		switch b := body.(type) {
		case string:
			reqBody = []byte(b)
		case []byte:
			reqBody = b
		default:
			var err error
			reqBody, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var resp map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec.Code, resp
}

func TestRound25_P0_1_NestedDateIngestionSortScriptFieldsAndLucenePhrases(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound25Req(t, srv, http.MethodPut, "/r25_nested_dates", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"status": map[string]any{
					"type":       "keyword",
					"null_value": "ROOT_NULL",
				},
				"msg":  map[string]any{"type": "text"},
				"code": map[string]any{"type": "keyword"},
				"events": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"occurred_at": map[string]any{"type": "date"},
						"summary": map[string]any{
							"type":    "text",
							"copy_to": "events.all_text",
						},
						"all_text": map[string]any{"type": "text"},
						"status":   map[string]any{"type": "keyword"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_nested_dates/_doc/1?refresh=true", map[string]any{
		"msg":  "critical error in module",
		"code": "2025-A",
		"events": []any{
			map[string]any{
				"occurred_at": "2025-01-10T00:00:00Z",
				"summary":     "quick brown fox",
			},
			map[string]any{
				"occurred_at": "2025-03-15T00:00:00Z",
				"summary":     "lazy dog",
				"status":      "ACTIVE",
			},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_nested_dates/_doc/2?refresh=true", map[string]any{
		"msg":  "minor warning",
		"code": "2024-B",
		"events": []any{
			map[string]any{
				"occurred_at": "2025-02-20T00:00:00Z",
				"summary":     "quick jump",
			},
		},
	})

	// 1. Nested date range + nested sort + nested date_histogram + inner_hits script_fields/docvalue_fields
	code, resp := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "events",
				"query": map[string]any{
					"range": map[string]any{
						"events.occurred_at": map[string]any{
							"gte": "2025-02-01T00:00:00Z",
						},
					},
				},
				"inner_hits": map[string]any{
					"docvalue_fields": []any{"events.occurred_at"},
					"script_fields": map[string]any{
						"ts_ms": map[string]any{
							"script": "doc['events.occurred_at'].value",
						},
					},
				},
			},
		},
		"sort": []any{
			map[string]any{
				"events.occurred_at": map[string]any{
					"order": "desc",
					"nested": map[string]any{
						"path": "events",
					},
				},
			},
		},
		"aggs": map[string]any{
			"nested_ev": map[string]any{
				"nested": map[string]any{"path": "events"},
				"aggs": map[string]any{
					"by_month": map[string]any{
						"date_histogram": map[string]any{
							"field":          "events.occurred_at",
							"fixed_interval": "30d",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested date search status = %d, resp = %v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	if hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 first when sorted by events.occurred_at desc, got %v", hits[0].(map[string]any)["_id"])
	}
	ihHits := hits[0].(map[string]any)["inner_hits"].(map[string]any)["events"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(ihHits) != 1 {
		t.Fatalf("expected 1 inner hit for doc 1 >= 2025-02-01, got %d", len(ihHits))
	}
	ih0 := ihHits[0].(map[string]any)
	ihFields, _ := ih0["fields"].(map[string]any)
	if ihFields == nil || len(ihFields["ts_ms"].([]any)) == 0 || ihFields["ts_ms"].([]any)[0] == nil {
		t.Fatalf("expected non-nil inner_hits script_fields ts_ms, got %v", ihFields)
	}
	byMonthBuckets := resp["aggregations"].(map[string]any)["nested_ev"].(map[string]any)["by_month"].(map[string]any)["buckets"].([]any)
	if len(byMonthBuckets) == 0 {
		t.Fatalf("expected non-empty nested date_histogram buckets")
	}

	// 2. Verify root null_value ("ROOT_NULL") does NOT bleed into nested events.status
	_, respNull := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "events",
				"query": map[string]any{
					"term": map[string]any{"events.status": "ROOT_NULL"},
				},
			},
		},
	})
	if got := len(respNull["hits"].(map[string]any)["hits"].([]any)); got != 0 {
		t.Fatalf("expected 0 hits for ROOT_NULL on nested events.status, got %d", got)
	}

	// 3. Nested query_string phrase with relative field name & copy_to target
	_, respPhrase := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "events",
				"query": map[string]any{
					"query_string": map[string]any{
						"query": `summary:"quick brown"`,
					},
				},
			},
		},
	})
	if got := len(respPhrase["hits"].(map[string]any)["hits"].([]any)); got != 1 {
		t.Fatalf("expected 1 hit for nested query_string phrase, got %d", got)
	}

	_, respCopyTo := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "events",
				"query": map[string]any{
					"match": map[string]any{
						"events.all_text": "fox",
					},
				},
			},
		},
	})
	if got := len(respCopyTo["hits"].(map[string]any)["hits"].([]any)); got != 1 {
		t.Fatalf("expected 1 hit for nested copy_to field events.all_text, got %d", got)
	}

	// 4. query_string regex on default_field "*" / multi-field and simple_query_string trailing '-'
	_, respRegex := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"query":  "/crit(ical|eria)/",
				"fields": []any{"msg", "code"},
			},
		},
	})
	if got := len(respRegex["hits"].(map[string]any)["hits"].([]any)); got != 1 {
		t.Fatalf("expected 1 hit for multi-field query_string regex, got %d", got)
	}

	_, respSQS := doRound25Req(t, srv, http.MethodPost, "/r25_nested_dates/_search", map[string]any{
		"query": map[string]any{
			"simple_query_string": map[string]any{
				"query":  "2025-A",
				"fields": []any{"code"},
			},
		},
	})
	if got := len(respSQS["hits"].(map[string]any)["hits"].([]any)); got != 1 {
		t.Fatalf("expected 1 hit for simple_query_string with hyphen, got %d", got)
	}
}

func TestRound25_P0_2_CompositeSubAggsAndDynamicNestedFilters(t *testing.T) {
	srv, _ := newTestServer()

	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_comp_sub", map[string]any{
		"settings": map[string]any{
			"analysis": map[string]any{
				"normalizer": map[string]any{
					"lc_norm": map[string]any{
						"type":   "custom",
						"filter": []any{"lowercase"},
					},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"region": map[string]any{"type": "keyword"},
				"env": map[string]any{
					"type":       "keyword",
					"normalizer": "lc_norm",
				},
				"active": map[string]any{"type": "boolean"},
				"amount": map[string]any{"type": "double"},
			},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_comp_sub/_doc/1?refresh=true", map[string]any{
		"region": "us",
		"env":    "PROD",
		"active": true,
		"amount": 100,
		"items": []any{
			map[string]any{"sku": "A", "qty": 2},
			map[string]any{"sku": "B", "qty": 20},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_comp_sub/_doc/2?refresh=true", map[string]any{
		"region": "us",
		"env":    "prod",
		"active": true,
		"amount": 50,
		"items": []any{
			map[string]any{"sku": "A", "qty": 15},
		},
	})

	code, resp := doRound25Req(t, srv, http.MethodPost, "/r25_comp_sub/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_region": map[string]any{
				"terms": map[string]any{"field": "region"},
				"aggs": map[string]any{
					"comp_env": map[string]any{
						"composite": map[string]any{
							"sources": []any{
								map[string]any{"env": map[string]any{"terms": map[string]any{"field": "env"}}},
								map[string]any{"act": map[string]any{"terms": map[string]any{"field": "active"}}},
							},
						},
						"aggs": map[string]any{
							"total_amt": map[string]any{
								"sum": map[string]any{"field": "amount"},
							},
							"script_amt": map[string]any{
								"sum": map[string]any{"script": "doc['amount'].value * 2"},
							},
						},
					},
				},
			},
			"nested_filters": map[string]any{
				"filters": map[string]any{
					"filters": map[string]any{
						"high_qty_a": map[string]any{
							"nested": map[string]any{
								"path": "items",
								"query": map[string]any{
									"bool": map[string]any{
										"must": []any{
											map[string]any{"term": map[string]any{"items.sku": "A"}},
											map[string]any{"range": map[string]any{"items.qty": map[string]any{"gte": 10}}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("composite sub-agg status = %d, resp = %v", code, resp)
	}
	regBuckets := resp["aggregations"].(map[string]any)["by_region"].(map[string]any)["buckets"].([]any)
	if len(regBuckets) != 1 {
		t.Fatalf("expected 1 region bucket, got %d", len(regBuckets))
	}
	compBuckets := regBuckets[0].(map[string]any)["comp_env"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 1 {
		t.Fatalf("expected 1 normalized composite bucket, got %v", compBuckets)
	}
	cb0 := compBuckets[0].(map[string]any)
	keyMap := cb0["key"].(map[string]any)
	if keyMap["env"] != "prod" || keyMap["act"] != "true" {
		t.Fatalf("expected composite key env=prod, act=true, got %v", keyMap)
	}
	if cb0["total_amt"].(map[string]any)["value"] != float64(150) {
		t.Fatalf("expected total_amt = 150, got %v", cb0["total_amt"])
	}
	if cb0["script_amt"].(map[string]any)["value"] != float64(300) {
		t.Fatalf("expected script_amt = 300, got %v", cb0["script_amt"])
	}

	nfCnt := resp["aggregations"].(map[string]any)["nested_filters"].(map[string]any)["buckets"].(map[string]any)["high_qty_a"].(map[string]any)["doc_count"]
	if nfCnt != float64(1) {
		t.Fatalf("expected dynamic nested filter doc_count = 1 (only doc 2 has sku=A with qty>=10 in same element), got %v", nfCnt)
	}
}

func TestRound25_P0_3_ScriptedMetricFullParity(t *testing.T) {
	srv, _ := newTestServer()

	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_sm_1/_doc/1?refresh=true", map[string]any{
		"team": "alpha",
		"val":  10,
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_sm_1/_doc/2?refresh=true", map[string]any{
		"team": "beta",
		"val":  40,
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_sm_2/_doc/3?refresh=true", map[string]any{
		"team": "alpha",
		"val":  30,
	})

	smSpec := map[string]any{
		"init_script":    "_agg.sum = 0; _agg.cnt = 0;",
		"map_script":     "_agg.sum += doc['val'].value; _agg.cnt += 1;",
		"combine_script": "_agg.net = _agg.sum;",
		"reduce_script":  "def total = 0; for (s in _aggs) { total += s.net; } return ['net': total];",
	}
	smScalarSpec := map[string]any{
		"init_script":    "state.sum = 0;",
		"map_script":     "state.sum += doc['val'].value;",
		"combine_script": "return state.sum;",
		"reduce_script":  "def total = 0; for (s in states) { total += s; } return total;",
	}

	code, resp := doRound25Req(t, srv, http.MethodPost, "/r25_sm_1,r25_sm_2/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"overall_sm": map[string]any{
				"scripted_metric": smSpec,
			},
			"by_team": map[string]any{
				"terms": map[string]any{
					"field": "team",
					"order": map[string]any{"team_sm.net": "desc"},
				},
				"aggs": map[string]any{
					"team_sm": map[string]any{
						"scripted_metric": smSpec,
					},
					"scalar_sm": map[string]any{
						"scripted_metric": smScalarSpec,
					},
					"doubled_net": map[string]any{
						"bucket_script": map[string]any{
							"buckets_path": map[string]any{
								"n": "team_sm.net",
								"s": "scalar_sm",
							},
							"script": "params.n + params.s",
						},
					},
				},
			},
			"empty_filter": map[string]any{
				"filter": map[string]any{
					"term": map[string]any{"team": "nonexistent"},
				},
				"aggs": map[string]any{
					"empty_sm": map[string]any{
						"scripted_metric": smScalarSpec,
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("scripted_metric status = %d, resp = %v", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	overallVal := aggs["overall_sm"].(map[string]any)["value"].(map[string]any)
	if overallVal["net"] != float64(80) {
		t.Fatalf("expected multi-index reduced overall_sm.net = 80, got %v", overallVal)
	}
	teamBuckets := aggs["by_team"].(map[string]any)["buckets"].([]any)
	if len(teamBuckets) != 2 {
		t.Fatalf("expected 2 team buckets, got %d", len(teamBuckets))
	}
	b0 := teamBuckets[0].(map[string]any)
	if b0["team_sm"].(map[string]any)["value"].(map[string]any)["net"] != float64(40) {
		t.Fatalf("expected first bucket net = 40, got %v", b0)
	}
	if b0["doubled_net"].(map[string]any)["value"] != float64(80) {
		t.Fatalf("expected pipeline bucket_script doubled_net = 80, got %v", b0["doubled_net"])
	}
	emptySM := aggs["empty_filter"].(map[string]any)["empty_sm"].(map[string]any)["value"]
	if emptySM != float64(0) {
		t.Fatalf("expected empty_sm value = 0 (not nil), got %v", emptySM)
	}
}

func TestRound25_P0_4_PipelineAggsSingleBucketContainersRateAndBucketSort(t *testing.T) {
	srv, _ := newTestServer()

	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_pipe", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"ts":     map[string]any{"type": "date"},
				"group":  map[string]any{"type": "keyword"},
				"status": map[string]any{"type": "keyword"},
				"rev":    map[string]any{"type": "double"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"tag": map[string]any{"type": "keyword"},
					},
				},
			},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_pipe/_doc/1?refresh=true", map[string]any{
		"ts":     "2025-01-01T00:00:00Z",
		"group":  "g1",
		"status": "ok",
		"rev":    120,
		"items":  []any{map[string]any{"tag": "x"}},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_pipe/_doc/2?refresh=true", map[string]any{
		"ts":     "2025-01-02T00:00:00Z",
		"group":  "g2",
		"status": "ok",
		"rev":    240,
		"items":  []any{map[string]any{"tag": "x"}},
	})

	code, resp := doRound25Req(t, srv, http.MethodPost, "/r25_pipe/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":          "ts",
					"fixed_interval": "1d",
				},
				"aggs": map[string]any{
					"ok_only": map[string]any{
						"filter": map[string]any{"term": map[string]any{"status": "ok"}},
						"aggs": map[string]any{
							"hourly_rate": map[string]any{
								"rate": map[string]any{
									"field": "rev",
									"unit":  "1h",
								},
							},
							"rate_x2": map[string]any{
								"bucket_script": map[string]any{
									"buckets_path": map[string]any{"r": "hourly_rate"},
									"script":       "params.r * 2",
								},
							},
						},
					},
					"nested_items": map[string]any{
						"nested": map[string]any{"path": "items"},
						"aggs": map[string]any{
							"to_root": map[string]any{
								"reverse_nested": map[string]any{},
								"aggs": map[string]any{
									"root_rev": map[string]any{"sum": map[string]any{"field": "rev"}},
								},
							},
						},
					},
					"chained_rev": map[string]any{
						"bucket_script": map[string]any{
							"buckets_path": map[string]any{
								"v": "nested_items>to_root>root_rev",
							},
							"script": "params.v + 10",
						},
					},
					"sort_desc": map[string]any{
						"bucket_sort": map[string]any{
							"sort": []any{
								map[string]any{"_key": map[string]any{"order": "desc"}},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("pipeline agg status = %d, resp = %v", code, resp)
	}
	buckets := resp["aggregations"].(map[string]any)["by_day"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
	b0 := buckets[0].(map[string]any)
	// Sorted by _key desc -> 2025-01-02 (rev=240, 1h rate = 240/24 = 10, rate_x2 = 20, chained_rev = 250) is first!
	if b0["key_as_string"] != "2025-01-02T00:00:00.000Z" {
		t.Fatalf("expected bucket_sort _key desc to place 2025-01-02 first, got %v", b0["key_as_string"])
	}
	okOnly := b0["ok_only"].(map[string]any)
	if okOnly["hourly_rate"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected hourly_rate = 10, got %v", okOnly["hourly_rate"])
	}
	if okOnly["rate_x2"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected rate_x2 = 20 (using scaled rate), got %v", okOnly["rate_x2"])
	}
	if b0["chained_rev"].(map[string]any)["value"] != float64(250) {
		t.Fatalf("expected chained_rev through nested>reverse_nested = 250, got %v", b0["chained_rev"])
	}
}

func TestRound25_P0_5_HighlightInnerHitsFieldFormatsIgnoreAboveAndScriptScore(t *testing.T) {
	srv, _ := newTestServer()

	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_post", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":  map[string]any{"type": "text"},
				"active": map[string]any{"type": "boolean"},
				"ts":     map[string]any{"type": "date"},
				"tag": map[string]any{
					"type":         "keyword",
					"ignore_above": 5,
				},
				"comments": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"author": map[string]any{"type": "keyword"},
						"text":   map[string]any{"type": "text"},
					},
				},
			},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_post/_doc/1?refresh=true", map[string]any{
		"title":  "quick brown fox jumps",
		"active": true,
		"ts":     "2025-04-15T10:20:30Z",
		"tag":    "toolongtag",
		"comments": []any{
			map[string]any{"author": "alice", "text": "hello world"},
		},
	})

	code, resp := doRound25Req(t, srv, http.MethodPost, "/r25_post/_search", map[string]any{
		"query": map[string]any{
			"function_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{
								"match_phrase": map[string]any{
									"title": map[string]any{
										"query": "quick fox",
										"slop":  2,
									},
								},
							},
						},
						"should": []any{
							map[string]any{
								"nested": map[string]any{
									"path": "comments",
									"query": map[string]any{
										"term": map[string]any{"comments.author": "alice"},
									},
									"inner_hits": map[string]any{
										"name": "comm_ih",
										"size": 5,
										"highlight": map[string]any{
											"fields": map[string]any{"comments.author": map[string]any{}},
										},
									},
								},
							},
							map[string]any{
								"nested": map[string]any{
									"path": "comments",
									"query": map[string]any{
										"prefix": map[string]any{"comments.text": "hel"},
									},
									"inner_hits": map[string]any{
										"name": "comm_ih",
										"highlight": map[string]any{
											"fields": map[string]any{"comments.text": map[string]any{}},
										},
									},
								},
							},
							map[string]any{
								"script": map[string]any{
									"script": "doc['tag'].size() == 0",
									"boost":  4.0,
								},
							},
						},
					},
				},
				"functions": []any{
					map[string]any{
						"weight": 2.0,
					},
				},
				"boost_mode": "multiply",
			},
		},
		"fields": []any{
			"active",
			"tag",
			map[string]any{"field": "ts", "format": "yyyy-MM-dd"},
		},
		"highlight": map[string]any{
			"fields": map[string]any{
				"*": map[string]any{
					"pre_tags":  []any{"<i>"},
					"post_tags": []any{"</i>"},
				},
				"title": map[string]any{
					"pre_tags":  []any{"<b>"},
					"post_tags": []any{"</b>"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("post-processing search status = %d, resp = %v", code, resp)
	}
	hit := resp["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fields := hit["fields"].(map[string]any)
	if fields["active"].([]any)[0] != true {
		t.Fatalf("expected boolean field active=[true], got %v", fields["active"])
	}
	if fields["ts"].([]any)[0] != "2025-04-15" {
		t.Fatalf("expected formatted date field ts=['2025-04-15'], got %v", fields["ts"])
	}
	if _, hasTag := fields["tag"]; hasTag {
		t.Fatalf("expected ignore_above field 'tag' to be omitted from fields, got %v", fields["tag"])
	}

	hl := hit["highlight"].(map[string]any)["title"].([]any)
	if len(hl) != 1 || hl[0] != "<b>quick</b> brown <b>fox</b> jumps" {
		t.Fatalf("expected explicit title highlight with slop words '<b>quick</b> brown <b>fox</b> jumps', got %v", hl)
	}

	commIH := hit["inner_hits"].(map[string]any)["comm_ih"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(commIH) != 1 {
		t.Fatalf("expected 1 deduplicated inner hit for comm_ih, got %d", len(commIH))
	}
	ihHL := commIH[0].(map[string]any)["highlight"].(map[string]any)
	if len(ihHL["comments.author"].([]any)) == 0 || len(ihHL["comments.text"].([]any)) == 0 {
		t.Fatalf("expected merged inner_hits highlight to contain both comments.author and comments.text, got %v", ihHL)
	}
	if ihHL["comments.text"].([]any)[0] != "<em>hello</em> world" {
		t.Fatalf("expected prefix highlight on comments.text to highlight full word '<em>hello</em> world', got %v", ihHL["comments.text"])
	}
}

func TestRound25_P0_6_PainlessMapEntrySetRemoveContainsValueAndShortCircuit(t *testing.T) {
	doc := map[string]any{"x": 10}
	src := `
		def m = ['a': 1, 'b': 2];
		def hasTwo = m.containsValue(2);
		def removed = m.remove('b');
		def ok = true || (m.put('c', 99) != null);
		def pairs = [];
		for (entry in m.entrySet()) {
			pairs.add(String.format('%s=%d', entry.getKey(), entry.getValue()));
		}
		def list = ['first', 'second'];
		def popped = list.remove(0);
		return [
			'hasTwo': hasTwo,
			'removed': removed,
			'sizeAfterShortCircuit': m.size(),
			'pair0': pairs[0],
			'popped': popped,
			'hypot': Math.hypot(3, 4)
		];
	`
	res, err := painless.Eval(doc, src, nil)
	if err != nil {
		t.Fatalf("painless.Eval error: %v", err)
	}
	rm := res.(map[string]any)
	if rm["hasTwo"] != true {
		t.Fatalf("expected hasTwo=true, got %v", rm["hasTwo"])
	}
	if rm["removed"] != int64(2) {
		t.Fatalf("expected m.remove('b') to return 2, got %v", rm["removed"])
	}
	if rm["sizeAfterShortCircuit"] != int64(1) {
		t.Fatalf("expected short-circuit || to skip m.put('c', 99), got size %v", rm["sizeAfterShortCircuit"])
	}
	if rm["pair0"] != "a=1" {
		t.Fatalf("expected String.format('%%s=%%d') via entrySet() to return 'a=1', got %v", rm["pair0"])
	}
	if rm["popped"] != "first" {
		t.Fatalf("expected list.remove(0) to return 'first', got %v", rm["popped"])
	}
	if rm["hypot"] != int64(5) && rm["hypot"] != float64(5) {
		t.Fatalf("expected Math.hypot(3, 4) = 5, got %v", rm["hypot"])
	}

	// Verify params.* LHS mutations, x++/++x return values, boxed types, numeric suffixes (0L/0d), and .splitOnToken(
	stateParams := map[string]any{
		"count": int64(0),
		"items": []any{},
		"meta":  map[string]any{},
	}
	src2 := `
		Integer i = 0;
		Long l = 10L;
		Double d = 2.5d;
		ArrayList arr = new ArrayList();
		HashMap hm = new HashMap();
		def postInc = i++;
		def preInc = ++i;
		params.count += l;
		params.items.add('x');
		params.meta.put('k', d);
		def toks = 'a::b::c'.splitOnToken('::');
		arr.addAll(toks);
		hm.put('len', arr.size());
		return [
			'postInc': postInc,
			'preInc': preInc,
			'count': params.count,
			'items': params.items,
			'metaK': params.meta.k,
			'tokLen': hm.get('len')
		];
	`
	res2, err := painless.Eval(doc, src2, stateParams)
	if err != nil {
		t.Fatalf("painless.Eval (src2) error: %v", err)
	}
	rm2 := res2.(map[string]any)
	if rm2["postInc"] != int64(0) || rm2["preInc"] != int64(2) {
		t.Fatalf("expected postInc=0 and preInc=2, got postInc=%v preInc=%v", rm2["postInc"], rm2["preInc"])
	}
	if rm2["count"] != int64(10) {
		t.Fatalf("expected params.count = 10, got %v", rm2["count"])
	}
	if len(rm2["items"].([]any)) != 1 || rm2["items"].([]any)[0] != "x" {
		t.Fatalf("expected params.items = ['x'], got %v", rm2["items"])
	}
	if rm2["metaK"] != float64(2.5) {
		t.Fatalf("expected params.meta.k = 2.5, got %v", rm2["metaK"])
	}
	if rm2["tokLen"] != int64(3) {
		t.Fatalf("expected splitOnToken('::') length = 3, got %v", rm2["tokLen"])
	}
}

func TestRound25_P0_7_IngestAttachmentCSVKVgsubAndUpdateByQueryMetadata(t *testing.T) {
	srv, _ := newTestServer()

	rawText := "Hello Attachment World"
	b64Data := base64.StdEncoding.EncodeToString([]byte(rawText))

	code, simResp := doRound25Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"attachment": map[string]any{
						"field": "data",
					},
				},
				map[string]any{
					"csv": map[string]any{
						"field":          "csv_line",
						"target_fields":  []any{"col1", "col2", "col3"},
						"trim":           true,
						"ignore_missing": true,
					},
				},
				map[string]any{
					"kv": map[string]any{
						"field":        "kv_line",
						"field_split":  "&",
						"value_split":  "=",
						"include_keys": []any{"env", "ver"},
						"exclude_keys": []any{"secret"},
						"prefix":       "meta_",
					},
				},
				map[string]any{
					"gsub": map[string]any{
						"field":       "slug",
						"pattern":     `([a-z]+)-([0-9]+)`,
						"replacement": "$2_$1",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"data":     b64Data,
					"csv_line": ` "alpha, one" , beta , gamma `,
					"kv_line":  "env=prod&ver=42&secret=xyz&other=ignored",
					"slug":     "item-99",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate ingest status = %d, resp = %v", code, simResp)
	}
	docOut := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	att := docOut["attachment"].(map[string]any)
	if att["content"] != rawText {
		t.Fatalf("expected attachment.content = %q, got %v", rawText, att)
	}
	if docOut["col1"] != "alpha, one" || docOut["col2"] != "beta" || docOut["col3"] != "gamma" {
		t.Fatalf("expected quoted+trimmed csv columns, got col1=%v col2=%v col3=%v", docOut["col1"], docOut["col2"], docOut["col3"])
	}
	if docOut["meta_env"] != "prod" || docOut["meta_ver"] != "42" || docOut["meta_secret"] != nil || docOut["meta_other"] != nil {
		t.Fatalf("unexpected kv output: %v", docOut)
	}
	if docOut["slug"] != "99_item" {
		t.Fatalf("expected gsub capture group replacement '99_item', got %v", docOut["slug"])
	}

	// Verify _update_by_query rejects ctx._id mutation with 400
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_ubq/_doc/1?refresh=true", map[string]any{"v": 1})
	ubqCode, ubqResp := doRound25Req(t, srv, http.MethodPost, "/r25_ubq/_update_by_query", map[string]any{
		"script": map[string]any{
			"source": "ctx._id = '2'",
		},
	})
	if ubqCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when mutating ctx._id in _update_by_query, got %d (%v)", ubqCode, ubqResp)
	}
	if !strings.Contains(ubqResp["error"].(map[string]any)["reason"].(string), "ctx._id") {
		t.Fatalf("expected error reason mentioning ctx._id, got %v", ubqResp)
	}

	// Verify grok inline named captures (?<name>...), date_index_name template expansion, and copy deep-clone
	code, grokResp := doRound25Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"grok": map[string]any{
						"field":    "line",
						"patterns": []any{`(?<service>[a-z]+)-(?P<code_num:int>[0-9]+)`},
					},
				},
				map[string]any{
					"copy": map[string]any{
						"field":        "nested_obj",
						"target_field": "cloned_obj",
					},
				},
				map[string]any{
					"set": map[string]any{
						"field": "nested_obj.k",
						"value": "mutated",
					},
				},
				map[string]any{
					"date_index_name": map[string]any{
						"field":             "ts",
						"index_name_prefix": "{{service}}-",
						"date_rounding":     "d",
						"index_name_format": "yyyy-MM-dd",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"line":       "auth-204",
					"nested_obj": map[string]any{"k": "orig"},
					"ts":         "2025-05-01T12:00:00Z",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("grok/copy/date_index_name simulate status = %d, resp = %v", code, grokResp)
	}
	simDoc := grokResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	if simDoc["_index"] != "auth-2025-05-01" {
		t.Fatalf("expected templated date_index_name _index = 'auth-2025-05-01', got %v", simDoc["_index"])
	}
	simSrc := simDoc["_source"].(map[string]any)
	if simSrc["service"] != "auth" || simSrc["code_num"] != float64(204) {
		t.Fatalf("expected grok named captures service='auth', code_num=204, got %v", simSrc)
	}
	if simSrc["cloned_obj"].(map[string]any)["k"] != "orig" {
		t.Fatalf("expected deep-cloned copy to retain 'orig' after source mutation, got %v", simSrc["cloned_obj"])
	}

	// Verify _update with ingest pipeline rerouting _id writes a delete tombstone for the old _id
	_, _ = doRound25Req(t, srv, http.MethodPut, "/_ingest/pipeline/reroute_id_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"set": map[string]any{
					"field": "_id",
					"value": "rerouted_1",
				},
			},
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_upd_reroute", map[string]any{
		"settings": map[string]any{
			"index.default_pipeline": "reroute_id_pipe",
		},
	})
	_, _ = doRound25Req(t, srv, http.MethodPut, "/r25_upd_reroute/_doc/orig_1?pipeline=_none&refresh=true", map[string]any{"v": 1})
	uCode, _ := doRound25Req(t, srv, http.MethodPost, "/r25_upd_reroute/_update/orig_1?refresh=true", map[string]any{
		"doc": map[string]any{"v": 2},
	})
	if uCode != http.StatusOK {
		t.Fatalf("expected 200 on _update with reroute pipeline, got %d", uCode)
	}
	oldGetCode, _ := doRound25Req(t, srv, http.MethodGet, "/r25_upd_reroute/_doc/orig_1", nil)
	if oldGetCode != http.StatusNotFound {
		t.Fatalf("expected old _id 'orig_1' to be deleted after _update pipeline reroute, got %d", oldGetCode)
	}
	newGetCode, newGetResp := doRound25Req(t, srv, http.MethodGet, "/r25_upd_reroute/_doc/rerouted_1", nil)
	if newGetCode != http.StatusOK || newGetResp["_source"].(map[string]any)["v"] != float64(2) {
		t.Fatalf("expected new _id 'rerouted_1' to exist with v=2, got %d (%v)", newGetCode, newGetResp)
	}

	// Verify _msearch includes status:200 and honors rest_total_hits_as_int=true
	msReq := httptest.NewRequest(http.MethodPost, "/r25_upd_reroute/_msearch?rest_total_hits_as_int=true", strings.NewReader("{}\n{\"query\":{\"match_all\":{}}}\n"))
	msReq.Header.Set("Content-Type", "application/x-ndjson")
	msRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(msRec, msReq)
	if msRec.Code != http.StatusOK {
		t.Fatalf("msearch status = %d", msRec.Code)
	}
	var msResp map[string]any
	_ = json.Unmarshal(msRec.Body.Bytes(), &msResp)
	msItem := msResp["responses"].([]any)[0].(map[string]any)
	if msItem["status"] != float64(200) {
		t.Fatalf("expected _msearch sub-response status=200, got %v", msItem["status"])
	}
	if _, isNum := msItem["hits"].(map[string]any)["total"].(float64); !isNum {
		t.Fatalf("expected rest_total_hits_as_int=true to return numeric hits.total in _msearch, got %T (%v)", msItem["hits"].(map[string]any)["total"], msItem["hits"].(map[string]any)["total"])
	}
}
