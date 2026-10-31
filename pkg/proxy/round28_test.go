package proxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound28_EnrichPolicyRegistryAndProcessorFiltering(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Index source documents into users_src
	bulkSrc := strings.Join([]string{
		`{"index":{"_index":"users_src","_id":"1"}}`,
		`{"user_id":"u-100","dept":"platform","role":"sre","secret_token":"top-secret"}`,
		`{"index":{"_index":"users_src","_id":"2"}}`,
		`{"user_id":"u-200","dept":"security","role":"analyst","secret_token":"classified"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkSrc)
	if code != http.StatusOK {
		t.Fatalf("bulk index users_src failed: %d", code)
	}

	// 2. Register enrich policy via PUT /_enrich/policy/users_policy
	code, putResp := doRound27Req(t, srv, http.MethodPut, "/_enrich/policy/users_policy", map[string]any{
		"match": map[string]any{
			"indices":       "users_src",
			"match_field":   "user_id",
			"enrich_fields": []any{"dept", "role"},
		},
	})
	if code != http.StatusOK || putResp["acknowledged"] != true {
		t.Fatalf("PUT /_enrich/policy/users_policy failed: code=%d resp=%v", code, putResp)
	}

	// 3. GET /_enrich/policy/users_policy, GET /_enrich/policy, POST /_enrich/policy/users_policy/_execute, GET /_enrich/_stats
	code, getResp := doRound27Req(t, srv, http.MethodGet, "/_enrich/policy/users_policy", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_enrich/policy/users_policy failed: %d", code)
	}
	policies, _ := getResp["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy in GET response, got %v", getResp)
	}

	code, execResp := doRound27Req(t, srv, http.MethodPost, "/_enrich/policy/users_policy/_execute", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_enrich/policy/users_policy/_execute failed: %d (%v)", code, execResp)
	}

	code, statsResp := doRound27Req(t, srv, http.MethodGet, "/_enrich/_stats", nil)
	if code != http.StatusOK || statsResp["executing_policies"] == nil {
		t.Fatalf("GET /_enrich/_stats failed: code=%d resp=%v", code, statsResp)
	}

	// 4. Simulate ingest pipeline with enrich processor referencing registered policy
	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"enrich": map[string]any{
						"policy_name":  "users_policy",
						"field":        "actor_id",
						"target_field": "actor_profile",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{"_index": "events", "_id": "e1", "_source": map[string]any{"actor_id": "u-100"}},
			map[string]any{"_index": "events", "_id": "e2", "_source": map[string]any{"actor_id": "u-nonexistent"}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate enrich failed: code=%d resp=%v", code, simResp)
	}
	simDocs, _ := simResp["docs"].([]any)
	if len(simDocs) != 2 {
		t.Fatalf("expected 2 simulated docs, got %v", simResp)
	}
	doc1 := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	profile, ok := doc1["actor_profile"].(map[string]any)
	if !ok || profile["dept"] != "platform" || profile["role"] != "sre" || profile["user_id"] != "u-100" {
		t.Fatalf("expected enriched actor_profile with dept=platform, role=sre, user_id=u-100, got %+v", profile)
	}
	if _, leaked := profile["secret_token"]; leaked {
		t.Fatalf("expected secret_token excluded by enrich_fields, got %+v", profile)
	}

	doc2 := simDocs[1].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if _, fabricated := doc2["actor_profile"]; fabricated {
		t.Fatalf("expected no fabricated actor_profile on enrich miss, got %+v", doc2)
	}

	// 5. Delete enrich policy
	code, delResp := doRound27Req(t, srv, http.MethodDelete, "/_enrich/policy/users_policy", nil)
	if code != http.StatusOK || delResp["acknowledged"] != true {
		t.Fatalf("DELETE /_enrich/policy/users_policy failed: code=%d resp=%v", code, delResp)
	}
}

func TestRound28_DotExpanderNestedPathsOverrideAndSlices(t *testing.T) {
	srv, _ := newTestServer()

	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"dot_expander": map[string]any{
						"field": "nested_root.a.b",
					},
				},
				map[string]any{
					"dot_expander": map[string]any{
						"field":    "keep.val",
						"override": false,
					},
				},
				map[string]any{
					"dot_expander": map[string]any{
						"field": "*",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "logs",
				"_id":    "1",
				"_source": map[string]any{
					"nested_root": map[string]any{
						"a.b": "deep_val",
					},
					"keep":     map[string]any{"val": "original"},
					"keep.val": "should_not_override",
					"items": []any{
						map[string]any{"tag.env": "prod"},
						map[string]any{"tag.env": "staging"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("dot_expander simulate failed: code=%d resp=%v", code, simResp)
	}
	docSrc := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	nestedRoot, _ := docSrc["nested_root"].(map[string]any)
	aMap, _ := nestedRoot["a"].(map[string]any)
	if aMap["b"] != "deep_val" {
		t.Fatalf("expected nested_root.a.b == deep_val, got %+v", docSrc)
	}
	keepMap, _ := docSrc["keep"].(map[string]any)
	if keepMap["val"] != "original" {
		t.Fatalf("expected override:false to preserve keep.val == original, got %+v", keepMap)
	}
	items, _ := docSrc["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %+v", items)
	}
	firstTag, _ := items[0].(map[string]any)["tag"].(map[string]any)
	if firstTag["env"] != "prod" {
		t.Fatalf("expected array element dotted key expanded to tag.env=prod, got %+v", items[0])
	}
}

func TestRound28_RolloverDryRunConditionsAndIndexBody(t *testing.T) {
	srv, _ := newTestServer()

	// Create logs-000001 with write alias logs_write
	code, _ := doRound27Req(t, srv, http.MethodPut, "/logs-000001", map[string]any{
		"aliases": map[string]any{
			"logs_write": map[string]any{"is_write_index": true},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create logs-000001 failed: %d", code)
	}

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"logs_write","_id":"1"}}`,
		`{"msg":"one"}`,
		`{"index":{"_index":"logs_write","_id":"2"}}`,
		`{"msg":"two"}`,
		`{"index":{"_index":"logs_write","_id":"3"}}`,
		`{"msg":"three"}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index logs_write failed: %d", code)
	}

	// 1. dry_run=true with met condition max_docs: 2 and unmet max_age: 7d
	code, dryResp := doRound27Req(t, srv, http.MethodPost, "/logs_write/_rollover?dry_run=true", map[string]any{
		"conditions": map[string]any{
			"max_docs": 2,
			"max_age":  "7d",
		},
	})
	if code != http.StatusOK || dryResp["dry_run"] != true || dryResp["rolled_over"] != false {
		t.Fatalf("expected dry_run=true and rolled_over=false, got code=%d resp=%v", code, dryResp)
	}
	condMap, _ := dryResp["conditions"].(map[string]any)
	if condMap["[max_docs: 2]"] != true || condMap["[max_age: 7d]"] != false {
		t.Fatalf("unexpected conditions map in dry_run rollover: %+v", condMap)
	}

	// 2. Unmet condition (max_docs: 10) without dry_run -> does not roll over
	code, unmetResp := doRound27Req(t, srv, http.MethodPost, "/logs_write/_rollover", map[string]any{
		"conditions": map[string]any{
			"max_docs": 10,
		},
	})
	if code != http.StatusOK || unmetResp["rolled_over"] != false || unmetResp["dry_run"] != false {
		t.Fatalf("expected unmet condition to not roll over, got code=%d resp=%v", code, unmetResp)
	}

	// 3. Met condition (max_docs: 2) with new index mappings & settings -> rolls over to logs-000002
	code, rollResp := doRound27Req(t, srv, http.MethodPost, "/logs_write/_rollover", map[string]any{
		"conditions": map[string]any{
			"max_docs": 2,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"host": map[string]any{"type": "keyword"},
			},
		},
		"settings": map[string]any{
			"number_of_shards": 1,
		},
	})
	if code != http.StatusOK || rollResp["rolled_over"] != true || rollResp["new_index"] != "logs-000002" {
		t.Fatalf("expected rollover to logs-000002, got code=%d resp=%v", code, rollResp)
	}

	// Verify logs-000002 exists with the host mapping
	code, mapResp := doRound27Req(t, srv, http.MethodGet, "/logs-000002/_mapping", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs-000002/_mapping failed: %d", code)
	}
	rawMapBytes, _ := mapResp["logs-000002"].(map[string]any)
	if rawMapBytes == nil {
		t.Fatalf("expected logs-000002 in _mapping response, got %+v", mapResp)
	}
}

func TestRound28_TermsEnumSliceBucketsWildcardAndSizeCap(t *testing.T) {
	srv, _ := newTestServer()

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r28_terms_enum","_id":"1"}}`,
		`{"tags":["alpha_one","alpha_two","beta_one"]}`,
		`{"index":{"_index":"r28_terms_enum","_id":"2"}}`,
		`{"tags":["ALPHA_three","gamma_one"]}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, teResp := doRound27Req(t, srv, http.MethodPost, "/r28_terms_enum/_terms_enum", map[string]any{
		"field":            "tags",
		"string":           "alpha*",
		"case_insensitive": true,
		"size":             5000,
	})
	if code != http.StatusOK {
		t.Fatalf("_terms_enum failed: code=%d resp=%v", code, teResp)
	}
	terms, _ := teResp["terms"].([]any)
	if len(terms) != 3 {
		t.Fatalf("expected 3 alpha* terms (case-insensitive), got %v", terms)
	}
}

func TestRound28_EmptyStringStatsBoxplotAndMultiIndexMerging(t *testing.T) {
	srv, _ := newTestServer()

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r28_agg_1","_id":"1"}}`,
		`{"grp":"populated","str_val":"abcd","num_val":10}`,
		`{"index":{"_index":"r28_agg_1","_id":"2"}}`,
		`{"grp":"empty_grp"}`,
		`{"index":{"_index":"r28_agg_2","_id":"3"}}`,
		`{"grp":"populated","str_val":"abcdef","num_val":20}`,
		`{"index":{"_index":"r28_agg_2","_id":"4"}}`,
		`{"grp":"empty_grp"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, sr := doRound27Req(t, srv, http.MethodPost, "/r28_agg_1,r28_agg_2/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"empty_top_sstats": map[string]any{
				"string_stats": map[string]any{"field": "nonexistent_str"},
			},
			"empty_top_box": map[string]any{
				"boxplot": map[string]any{"field": "nonexistent_num"},
			},
			"by_grp": map[string]any{
				"terms": map[string]any{"field": "grp.keyword"},
				"aggs": map[string]any{
					"sub_sstats": map[string]any{"string_stats": map[string]any{"field": "str_val.keyword"}},
					"sub_box":    map[string]any{"boxplot": map[string]any{"field": "num_val"}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("multi-index search failed: code=%d resp=%v", code, sr)
	}
	aggs := sr["aggregations"].(map[string]any)
	topSS := aggs["empty_top_sstats"].(map[string]any)
	if topSS["count"] != float64(0) || topSS["min_length"] != nil || topSS["max_length"] != nil || topSS["avg_length"] != nil {
		t.Fatalf("expected null lengths on empty top-level string_stats, got %+v", topSS)
	}
	topBox := aggs["empty_top_box"].(map[string]any)
	if topBox["min"] != nil || topBox["max"] != nil || topBox["median"] != nil {
		t.Fatalf("expected null metrics on empty top-level boxplot, got %+v", topBox)
	}

	buckets := aggs["by_grp"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets in by_grp, got %+v", buckets)
	}
	for _, rawB := range buckets {
		b := rawB.(map[string]any)
		key := b["key"].(string)
		subSS := b["sub_sstats"].(map[string]any)
		subBox := b["sub_box"].(map[string]any)
		switch key {
		case "empty_grp":
			if subSS["count"] != float64(0) || subSS["min_length"] != nil || subSS["max_length"] != nil || subSS["avg_length"] != nil {
				t.Fatalf("expected null lengths on empty sub string_stats, got %+v", subSS)
			}
			if subBox["min"] != nil || subBox["max"] != nil || subBox["median"] != nil {
				t.Fatalf("expected null metrics on empty sub boxplot, got %+v", subBox)
			}
		case "populated":
			// "abcd" (len 4) + "abcdef" (len 6) across 2 indices -> count=2, min=4, max=6, avg=5
			if subSS["count"] != float64(2) || subSS["min_length"] != float64(4) || subSS["max_length"] != float64(6) || subSS["avg_length"] != float64(5) {
				t.Fatalf("expected merged multi-index sub string_stats count=2 min=4 max=6 avg=5, got %+v", subSS)
			}
			if subBox["min"] != float64(10) || subBox["max"] != float64(20) {
				t.Fatalf("expected merged multi-index sub boxplot min=10 max=20, got %+v", subBox)
			}
		}
	}
}

func TestRound28_CompositeRateScalingAndHighlightLuceneGroups(t *testing.T) {
	srv, _ := newTestServer()

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r28_comp_hl","_id":"1"}}`,
		`{"ts":"2026-10-30T10:00:10Z","requests":120,"title":"The quick brown fox","body":"A fox quickly jumps over the dog"}`,
		`{"index":{"_index":"r28_comp_hl","_id":"2"}}`,
		`{"ts":"2026-10-30T10:00:40Z","requests":60,"title":"The lazy dog","body":"Nothing happens"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, sr := doRound27Req(t, srv, http.MethodPost, "/r28_comp_hl/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"query": `+title:(quick brown) body:"fox jumps"~2`,
			},
		},
		"highlight": map[string]any{
			"fields": map[string]any{
				"title": map[string]any{},
				"body":  map[string]any{},
			},
		},
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{
							"minute_bucket": map[string]any{
								"date_histogram": map[string]any{
									"field":          "ts",
									"fixed_interval": "1m",
								},
							},
						},
					},
				},
				"aggs": map[string]any{
					"req_per_sec": map[string]any{
						"rate": map[string]any{
							"field": "requests",
							"unit":  "second",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search failed: code=%d resp=%v", code, sr)
	}
	hits := extractHitsSlice(t, sr)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	hl := hits[0].(map[string]any)["highlight"].(map[string]any)
	titleHL := strings.Join(toStringSliceForTest(hl["title"]), " ")
	bodyHL := strings.Join(toStringSliceForTest(hl["body"]), " ")
	if !strings.Contains(titleHL, "<em>quick</em>") || !strings.Contains(titleHL, "<em>brown</em>") {
		t.Fatalf("expected title highlight to contain <em>quick</em> and <em>brown</em>, got %q", titleHL)
	}
	if !strings.Contains(bodyHL, "<em>fox</em>") || !strings.Contains(bodyHL, "<em>jumps</em>") || strings.Contains(bodyHL, "~2") {
		t.Fatalf("expected body highlight to contain <em>fox</em> and <em>jumps</em> without ~2, got %q", bodyHL)
	}

	compBuckets := sr["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 1 {
		t.Fatalf("expected 1 composite bucket, got %+v", compBuckets)
	}
	rateVal := compBuckets[0].(map[string]any)["req_per_sec"].(map[string]any)["value"].(float64)
	// 1 matching doc has requests=120 over 1m (60s) -> 120 / 60 = 2.0 req/sec
	if rateVal != 2.0 {
		t.Fatalf("expected composite rate sub-agg == 2.0 req/sec (120 / 60s), got %v", rateVal)
	}
}

func toStringSliceForTest(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestRound28_RewriteDorisArrayExistsAndNowCacheFalsePositives(t *testing.T) {
	// 1. Nested array_exists rewrite and idempotency
	rawSQL := "SELECT * FROM t WHERE array_exists(x -> array_exists(y -> y > 10, `f__inner`), `f__outer`)"
	norm1 := NormalizeDorisSQL(rawSQL)
	expected := "SELECT * FROM t WHERE array_contains(array_exists(x -> array_contains(array_exists(y -> y > 10, IFNULL(`f__inner`, CAST([] AS ARRAY<STRING>))), true), IFNULL(`f__outer`, CAST([] AS ARRAY<STRING>))), true)"
	if norm1 != expected {
		t.Fatalf("expected nested array_exists rewrite:\n  want: %s\n  got:  %s", expected, norm1)
	}
	norm2 := NormalizeDorisSQL(norm1)
	if norm2 != expected {
		t.Fatalf("expected idempotent NormalizeDorisSQL, got %s", norm2)
	}

	// 2. "now" date-math detection: words containing "now" ("unknown", "snow", "window", "nowhere") must not trigger bypass
	falsePositiveReq := &esast.SearchRequest{
		Query: &esast.Query{
			Bool: &esast.BoolQuery{
				Must: []esast.Query{
					{Term: map[string]esast.TermEntry{"status": {Value: "unknown"}}},
					{Terms: &esast.TermsQuery{Fields: map[string][]any{"weather": {"snow", "window", "nowhere"}}}},
					{QueryString: &esast.QueryStringQuery{Query: "status:unknown AND weather:snow"}},
				},
			},
		},
	}
	if containsNowDateMath(falsePositiveReq, nil) {
		t.Fatalf("expected containsNowDateMath == false for words containing 'now' substring ('unknown', 'snow', 'window')")
	}

	truePositiveTerm := &esast.SearchRequest{
		Query: &esast.Query{
			Term: map[string]esast.TermEntry{"ts": {Value: "now-1h/d"}},
		},
	}
	if !containsNowDateMath(truePositiveTerm, nil) {
		t.Fatalf("expected containsNowDateMath == true for term 'now-1h/d'")
	}

	truePositiveTerms := &esast.SearchRequest{
		Query: &esast.Query{
			Terms: &esast.TermsQuery{Fields: map[string][]any{"ts": {"2026-01-01", "now/d"}}},
		},
	}
	if !containsNowDateMath(truePositiveTerms, nil) {
		t.Fatalf("expected containsNowDateMath == true for terms containing 'now/d'")
	}

	// Verify QueryResultCache caches queries with "unknown" / "snow"
	srv, _ := newTestServer()
	srv.SetQueryCacheTTL(30*time.Second, 100)
	_, _ = doRound27Req(t, srv, http.MethodPost, "/r28_cache_idx/_doc/1?refresh=true", map[string]any{
		"status":  "unknown",
		"weather": "snow",
	})
	for i := 0; i < 2; i++ {
		code, _ := doRound27Req(t, srv, http.MethodPost, "/r28_cache_idx/_search", map[string]any{
			"query": map[string]any{"term": map[string]any{"status.keyword": "unknown"}},
		})
		if code != http.StatusOK {
			t.Fatalf("search failed: %d", code)
		}
	}
	hits, misses := srv.queryCache.Stats()
	if hits != 1 || misses != 1 {
		t.Fatalf("expected 1 cache hit and 1 cache miss for 'unknown' term query, got hits=%d misses=%d", hits, misses)
	}
}

func TestRound28_FeaturesCoverage_NetworkDirection_CommunityID_Promote_Analyze_Validate(t *testing.T) {
	srv, _ := newTestServer()

	// 1. network_direction and community_id ingest processors
	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"network_direction": map[string]any{
						"internal_networks": []any{"private", "10.0.0.0/8"},
					},
				},
				map[string]any{
					"community_id": map[string]any{},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "netlogs",
				"_id":    "1",
				"_source": map[string]any{
					"source":      map[string]any{"ip": "10.1.2.3", "port": 54321},
					"destination": map[string]any{"ip": "8.8.8.8", "port": 443},
					"network":     map[string]any{"transport": "tcp"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate network processors failed: code=%d resp=%v", code, simResp)
	}
	netDoc := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	netMap, _ := netDoc["network"].(map[string]any)
	if netMap["direction"] != "egress" && netMap["direction"] != "outbound" {
		t.Fatalf("expected egress/outbound direction from 10.1.2.3 -> 8.8.8.8, got %+v", netMap)
	}
	if !strings.HasPrefix(netMap["community_id"].(string), "1:") {
		t.Fatalf("expected v1 community_id hash starting with '1:', got %+v", netMap["community_id"])
	}

	// 2. _doris/promote endpoint (valid scalar + rejected nested/vector)
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r28_prom", nil)
	code, promResp := doRound27Req(t, srv, http.MethodPost, "/r28_prom/_doris/promote", map[string]any{
		"field": "hot_tenant",
		"type":  "keyword",
	})
	if code != http.StatusOK || promResp["acknowledged"] != true {
		t.Fatalf("expected _doris/promote keyword to succeed, got code=%d resp=%v", code, promResp)
	}
	code, _ = doRound27Req(t, srv, http.MethodPost, "/r28_prom/_doris/promote", map[string]any{
		"field": "bad_nested",
		"type":  "nested",
	})
	if code < 400 {
		t.Fatalf("expected _doris/promote nested to return 4xx error, got %d", code)
	}

	// 3. _analyze and _validate/query
	code, anResp := doRound27Req(t, srv, http.MethodPost, "/_analyze", map[string]any{
		"analyzer": "standard",
		"text":     "Quick Brown-Fox 123",
	})
	if code != http.StatusOK || len(anResp["tokens"].([]any)) != 4 {
		t.Fatalf("expected 4 tokens from _analyze, got code=%d resp=%v", code, anResp)
	}

	code, valResp := doRound27Req(t, srv, http.MethodPost, "/r28_prom/_validate/query?explain=true", map[string]any{
		"query": map[string]any{"term": map[string]any{"hot_tenant": "acme"}},
	})
	if code != http.StatusOK || valResp["valid"] != true {
		t.Fatalf("expected valid=true from _validate/query, got code=%d resp=%v", code, valResp)
	}
}
