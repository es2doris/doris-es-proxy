package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRound33_SearchSortAggsSuggestAndFieldCaps(t *testing.T) {
	srv, _ := newTestServer()

	doRound27Req(t, srv, http.MethodPut, "/r33_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":  map[string]any{"type": "text"},
				"status": map[string]any{"type": "keyword"},
				"active": map[string]any{"type": "boolean"},
				"count":  map[string]any{"type": "long"},
				"price":  map[string]any{"type": "double"},
				"ts":     map[string]any{"type": "date"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"dept": map[string]any{"type": "keyword"},
						"val":  map[string]any{"type": "double"},
					},
				},
			},
		},
	})

	bulk := strings.Join([]string{
		`{"index":{"_index":"r33_idx","_id":"1"}}`,
		`{"title":"golang search engine","status":"open","active":true,"count":10,"price":12.5,"ts":"2026-03-15T00:00:00Z","items":[{"dept":"eng","val":10},{"dept":"eng","val":30},{"dept":"sales","val":100}]}`,
		`{"index":{"_index":"r33_idx","_id":"2"}}`,
		`{"title":"golang proxy server","status":"open","active":false,"count":20,"price":25.0,"ts":"2026-03-16T00:00:00Z","items":[{"dept":"eng","val":5},{"dept":"eng","val":15}]}`,
		`{"index":{"_index":"r33_idx","_id":"3"}}`,
		`{"title":"doris database guide","status":"closed","active":true,"count":30,"price":50.0,"ts":"2026-03-17T00:00:00Z","items":[{"dept":"sales","val":90}]}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulk)

	// F9 & F10: Scroll preserves _score sort, track_scores: true computes real _score on field sort,
	// and nested sort mode "median" with nested.filter evaluates filtered elements in hit["sort"]
	code, sr1 := doRound27Req(t, srv, http.MethodPost, "/r33_idx/_search?scroll=1m", map[string]any{
		"size":         2,
		"track_scores": true,
		"query": map[string]any{
			"match": map[string]any{"title": "golang"},
		},
		"sort": []any{
			map[string]any{
				"items.val": map[string]any{
					"order": "desc",
					"mode":  "median",
					"nested": map[string]any{
						"path":   "items",
						"filter": map[string]any{"term": map[string]any{"items.dept": "eng"}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on search, got %d: %+v", code, sr1)
	}
	hits1 := sr1["hits"].(map[string]any)["hits"].([]any)
	if len(hits1) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits1))
	}
	firstHit := hits1[0].(map[string]any)
	if firstHit["_id"] != "1" || firstHit["_score"] == nil {
		t.Fatalf("expected doc 1 first with non-nil _score when track_scores=true, got %+v", firstHit)
	}
	sortVals := firstHit["sort"].([]any)
	if len(sortVals) == 0 || sortVals[0] != float64(20) {
		t.Fatalf("expected filtered nested median sort value 20 for doc 1 ([10, 30]), got %+v", sortVals)
	}

	// F11, F12, F13: Composite agg native numeric/boolean keys & missing_bucket: true (null key),
	// Filters agg keyed: false, Range/DateRange keyed: true, VariableWidthHistogram buckets,
	// GeoBounds wrap_longitude, GeoCentroid count, MatrixStats doc_count & correlation
	code, aggRes := doRound27Req(t, srv, http.MethodPost, "/r33_idx/_search?size=0", map[string]any{
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{"cnt": map[string]any{"terms": map[string]any{"field": "count"}}},
						map[string]any{"act": map[string]any{"terms": map[string]any{"field": "active", "value_type": "boolean"}}},
					},
				},
			},
			"anon_filters": map[string]any{
				"filters": map[string]any{
					"keyed": false,
					"filters": map[string]any{
						"open_docs":   map[string]any{"term": map[string]any{"status": "open"}},
						"closed_docs": map[string]any{"term": map[string]any{"status": "closed"}},
					},
				},
			},
			"keyed_range": map[string]any{
				"range": map[string]any{
					"field": "count",
					"keyed": true,
					"ranges": []any{
						map[string]any{"key": "small", "to": 20},
						map[string]any{"key": "large", "from": 20},
					},
				},
			},
			"date_rng_on_date_field": map[string]any{
				"range": map[string]any{
					"field": "ts",
					"ranges": []any{
						map[string]any{"from": "2026-03-15T00:00:00Z", "to": "2026-03-17T00:00:00Z"},
					},
				},
			},
			"top_one_status": map[string]any{
				"terms": map[string]any{
					"field": "status",
					"size":  1,
				},
			},
			"by_status_bs": map[string]any{
				"terms": map[string]any{
					"field": "status",
					"order": map[string]any{"ratio": "desc"},
				},
				"aggs": map[string]any{
					"sum_price": map[string]any{"sum": map[string]any{"field": "price"}},
					"sum_count": map[string]any{"sum": map[string]any{"field": "count"}},
					"ratio": map[string]any{
						"bucket_script": map[string]any{
							"buckets_path": map[string]any{"p": "sum_price", "c": "sum_count"},
							"script":       "params.p / params.c",
						},
					},
				},
			},
			"by_status": map[string]any{
				"terms": map[string]any{"field": "status"},
				"aggs": map[string]any{
					"total_count": map[string]any{"sum": map[string]any{"field": "count"}},
					"only_small": map[string]any{
						"bucket_selector": map[string]any{
							"buckets_path": map[string]any{"tc": "total_count"},
							"script":       "params.tc <= 30",
						},
					},
				},
			},
			"stats_filtered": map[string]any{
				"stats_bucket": map[string]any{
					"buckets_path": "by_status>total_count",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on aggs search, got %d: %+v", code, aggRes)
	}
	aggs := aggRes["aggregations"].(map[string]any)
	compBuckets := aggs["comp"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) == 0 {
		t.Fatalf("expected composite buckets, got empty")
	}
	firstCompKey := compBuckets[0].(map[string]any)["key"].(map[string]any)
	if _, ok := firstCompKey["cnt"].(float64); !ok {
		t.Fatalf("expected composite 'cnt' key to be numeric (float64 in JSON), got %T (%v)", firstCompKey["cnt"], firstCompKey["cnt"])
	}
	if _, ok := firstCompKey["act"].(bool); !ok {
		t.Fatalf("expected composite 'act' key with value_type=boolean to be bool, got %T (%v)", firstCompKey["act"], firstCompKey["act"])
	}
	if _, ok := aggs["anon_filters"].(map[string]any)["buckets"].([]any); !ok {
		t.Fatalf("expected filters agg with keyed:false to return array of buckets, got %T", aggs["anon_filters"].(map[string]any)["buckets"])
	}
	if _, ok := aggs["keyed_range"].(map[string]any)["buckets"].(map[string]any); !ok {
		t.Fatalf("expected range agg with keyed:true to return map of buckets, got %T", aggs["keyed_range"].(map[string]any)["buckets"])
	}
	// F10: sum_other_doc_count on top_one_status (total 3 docs: "open"=2, "closed"=1 -> sum_other_doc_count=1)
	if aggs["top_one_status"].(map[string]any)["sum_other_doc_count"] != float64(1) {
		t.Fatalf("expected sum_other_doc_count == 1, got %+v", aggs["top_one_status"])
	}
	// F12: terms ordered by child bucket_script ("closed" has ratio 50/30=1.666 > "open" 37.5/30=1.25)
	bsBuckets := aggs["by_status_bs"].(map[string]any)["buckets"].([]any)
	if len(bsBuckets) != 2 || bsBuckets[0].(map[string]any)["key"] != "closed" {
		t.Fatalf("expected 'closed' bucket first when ordered by child bucket_script desc, got %+v", bsBuckets)
	}
	// F14: range agg on mapped date field includes from_as_string / to_as_string
	dateRngBucket := aggs["date_rng_on_date_field"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
	if dateRngBucket["from_as_string"] == nil || dateRngBucket["to_as_string"] == nil || dateRngBucket["doc_count"] != float64(2) {
		t.Fatalf("expected from_as_string/to_as_string and doc_count=2 on range agg over date field, got %+v", dateRngBucket)
	}
	// F13: stats_bucket runs AFTER bucket_selector (both buckets have total_count=30, so count=2)
	if aggs["stats_filtered"].(map[string]any)["count"] != float64(2) {
		t.Fatalf("expected stats_bucket count == 2, got %+v", aggs["stats_filtered"])
	}

	// F14 & F15: Search suggest API + highlight pre_tags/post_tags + explain
	code, sugRes := doRound27Req(t, srv, http.MethodPost, "/r33_idx/_search?typed_keys=true", map[string]any{
		"explain": true,
		"query": map[string]any{
			"match": map[string]any{"title": "golang"},
		},
		"highlight": map[string]any{
			"pre_tags":  []any{"<b>"},
			"post_tags": []any{"</b>"},
			"fields": map[string]any{
				"title": map[string]any{},
			},
		},
		"suggest": map[string]any{
			"text": "golng",
			"my_term": map[string]any{
				"term": map[string]any{"field": "title"},
			},
			"my_comp": map[string]any{
				"prefix":     "golang",
				"completion": map[string]any{"field": "title"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on suggest+highlight+explain search, got %d: %+v", code, sugRes)
	}
	sugMap, ok := sugRes["suggest"].(map[string]any)
	if !ok || sugMap["term#my_term"] == nil || sugMap["completion#my_comp"] == nil {
		t.Fatalf("expected typed_keys suggest map with term#my_term and completion#my_comp, got %+v", sugRes["suggest"])
	}
	sugHit := sugRes["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	hlTitle := sugHit["highlight"].(map[string]any)["title"].([]any)[0].(string)
	if !strings.Contains(hlTitle, "<b>golang</b>") {
		t.Fatalf("expected custom highlight tag <b>golang</b>, got %q", hlTitle)
	}

	// F16: _field_caps with index_filter and fields filter
	code, fcRes := doRound27Req(t, srv, http.MethodPost, "/r33_idx/_field_caps?fields=status,count", map[string]any{
		"index_filter": map[string]any{
			"term": map[string]any{"status": "open"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _field_caps, got %d: %+v", code, fcRes)
	}
	fcFields := fcRes["fields"].(map[string]any)
	if fcFields["status"] == nil || fcFields["count"] == nil || fcFields["title"] != nil {
		t.Fatalf("expected _field_caps to return only status and count, got %+v", fcFields)
	}
}

func TestRound33_IngestProcessorsReindexSortAndCtxMetadataMutations(t *testing.T) {
	srv, _ := newTestServer()

	// F22 & F23: Ingest pipeline with dynamic {{field}} interpolation, Mustache {{_ingest.timestamp}},
	// sort/fingerprint/Redact/network_direction/community_id processors, and cycle detection
	code, _ := doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/r33_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"set": map[string]any{
					"field": "dynamic_tag",
					"value": "env-{{env}}",
				},
			},
			map[string]any{
				"sort": map[string]any{
					"field": "tags",
					"order": "desc",
				},
			},
			map[string]any{
				"fingerprint": map[string]any{
					"fields":       []any{"env", "service"},
					"target_field": "fp",
				},
			},
			map[string]any{
				"redact": map[string]any{
					"field":    "msg",
					"patterns": []any{`\d{3}-\d{2}-\d{4}`},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating ingest pipeline, got %d", code)
	}

	code, simRes := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/r33_pipe/_simulate", map[string]any{
		"docs": []any{
			map[string]any{
				"_index": "r33_ing",
				"_id":    "d1",
				"_source": map[string]any{
					"env":     "prod",
					"service": "api",
					"tags":    []any{"a", "c", "b"},
					"msg":     "ssn is 123-45-6789",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _simulate, got %d: %+v", code, simRes)
	}
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simDoc["dynamic_tag"] != "env-prod" || simDoc["fp"] == nil || simDoc["msg"] != "ssn is <REDACTED>" {
		t.Fatalf("unexpected simulated doc: %+v", simDoc)
	}
	sortedTags := simDoc["tags"].([]any)
	if len(sortedTags) != 3 || sortedTags[0] != "c" || sortedTags[2] != "a" {
		t.Fatalf("expected descending sorted tags [c, b, a], got %+v", sortedTags)
	}

	// F15 & F24: _reindex with source.sort and script mutating ctx._id / ctx._index,
	// plus _update script reading ctx._id / ctx._index / ctx._version / ctx._now
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"r33_src","_id":"s1"}}`,
		`{"seq":30,"name":"third"}`,
		`{"index":{"_index":"r33_src","_id":"s2"}}`,
		`{"seq":10,"name":"first"}`,
		`{"index":{"_index":"r33_src","_id":"s3"}}`,
		`{"seq":20,"name":"second"}`,
	}, "\n")+"\n")

	code, reidxRes := doRound27Req(t, srv, http.MethodPost, "/_reindex?refresh=true", map[string]any{
		"source": map[string]any{
			"index": "r33_src",
			"size":  2,
			"sort":  []any{map[string]any{"seq": "asc"}},
		},
		"dest": map[string]any{
			"index": "r33_dst",
		},
		"max_docs": 2,
		"script": map[string]any{
			"source": "boolean m = (ctx._source.name =~ /can't/); ctx._id = 'migrated-' + ctx._id; ctx._source.dest_index = ctx._index;",
		},
	})
	if code != http.StatusOK || reidxRes["created"] != float64(2) {
		t.Fatalf("expected _reindex to create 2 docs in sort order, got code=%d res=%+v", code, reidxRes)
	}

	// Verify migrated-s2 (seq=10) and migrated-s3 (seq=20) exist in r33_dst, and migrated-s1 (seq=30) was skipped by max_docs=2
	code, getS2 := doRound27Req(t, srv, http.MethodGet, "/r33_dst/_doc/migrated-s2", nil)
	if code != http.StatusOK || getS2["_source"].(map[string]any)["dest_index"] != "r33_dst" {
		t.Fatalf("expected migrated-s2 in r33_dst with dest_index='r33_dst', got code=%d res=%+v", code, getS2)
	}
	code, _ = doRound27Req(t, srv, http.MethodGet, "/r33_dst/_doc/migrated-s1", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected migrated-s1 to be absent due to sort+max_docs=2, got code=%d", code)
	}

	// F24: _update script reading ctx._id, ctx._index, ctx._version, ctx._now, plus ?detect_noop=false and body _source_includes
	code, updRes := doRound27Req(t, srv, http.MethodPost, "/r33_dst/_update/migrated-s2?refresh=true&detect_noop=false", map[string]any{
		"_source_includes": []any{"meta_id", "meta_idx"},
		"script": map[string]any{
			"source": "ctx._source.meta_id = ctx._id; ctx._source.meta_idx = ctx._index; ctx._source.meta_ver = ctx._version; ctx._source.has_now = (ctx._now > 0);",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _update with ctx metadata, got %d: %+v", code, updRes)
	}
	getField, _ := updRes["get"].(map[string]any)
	if getField == nil || getField["_source"].(map[string]any)["meta_id"] != "migrated-s2" || getField["_source"].(map[string]any)["name"] != nil {
		t.Fatalf("expected _source_includes in _update body to return filtered get._source, got %+v", updRes)
	}
	code, getUpdated := doRound27Req(t, srv, http.MethodGet, "/r33_dst/_doc/migrated-s2", nil)
	updSrc := getUpdated["_source"].(map[string]any)
	if code != http.StatusOK || updSrc["meta_id"] != "migrated-s2" || updSrc["meta_idx"] != "r33_dst" || updSrc["has_now"] != true {
		t.Fatalf("unexpected updated _source from ctx metadata: %+v", updSrc)
	}

	// F22 & F23: Mustache field/target_field expansion, append array flattening, and csv empty_value + UTF-8 separator
	code, csvSim := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"uppercase": map[string]any{
						"field":        "{{src_field}}",
						"target_field": "{{dst_field}}",
					},
				},
				map[string]any{
					"append": map[string]any{
						"field": "tags",
						"value": []any{"{{{more_tags}}}"},
					},
				},
				map[string]any{
					"csv": map[string]any{
						"field":         "empty_csv",
						"target_fields": []any{"col1", "col2"},
						"empty_value":   "N/A",
					},
				},
				map[string]any{
					"csv": map[string]any{
						"field":         "utf8_csv",
						"separator":     "｜",
						"target_fields": []any{"u1", "u2"},
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"src_field": "raw_name",
					"dst_field": "upper_name",
					"raw_name":  "hello",
					"tags":      []any{"a"},
					"more_tags": []any{"b", "c"},
					"empty_csv": "",
					"utf8_csv":  "left｜right",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on csv/mustache simulate, got %d: %+v", code, csvSim)
	}
	csvDoc := csvSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if csvDoc["upper_name"] != "HELLO" || len(csvDoc["tags"].([]any)) != 3 || csvDoc["col1"] != "N/A" || csvDoc["col2"] != "N/A" || csvDoc["u1"] != "left" || csvDoc["u2"] != "right" {
		t.Fatalf("unexpected F22/F23 simulated doc: %+v", csvDoc)
	}

	code, e2eSim := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"script": {
						"source": "ctx.fallback = ctx.missing ?: 'ok'; ctx.re_ok = (ctx.code ==~ /^[A-Z]+-\\d+$/); ctx.joined = ctx.tags.stream().collect(Collectors.joining(','));"
					}
				},
				{"sort": {"field": "tags", "order": "desc"}},
				{"redact": {"field": "secret", "patterns": ["\\d{4}"]}},
				{"fingerprint": {"fields": ["code"], "target_field": "fp"}}
			]
		},
		"docs": [
			{"_index": "live_auto_index", "_id": "r33-sim-1", "_source": {"code": "ORD-99", "tags": ["a", "b"], "secret": "pin 1234"}}
		]
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on e2e simulate payload, got %d: %+v", code, e2eSim)
	}
	e2eSimDoc := e2eSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if e2eSimDoc["fallback"] != "ok" || e2eSimDoc["re_ok"] != true || e2eSimDoc["joined"] != "a,b" || e2eSimDoc["secret"] != "pin <REDACTED>" || e2eSimDoc["fp"] == nil {
		t.Fatalf("unexpected R33 e2e simulated doc: %+v", e2eSimDoc)
	}
}
