// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound38_F1_F2_ASTHighlightSourceFilterQueryStringAndGeoDistSort(t *testing.T) {
	// F1: HighlightSpec / HighlightFieldSpec single-string pre_tags, post_tags, matched_fields;
	// SourceFilter single-string includes/excludes; QueryStringQuery scalar query and single-string fields.
	var sr esast.SearchRequest
	raw := `{
		"_source": {
			"includes": "meta.*",
			"excludes": "meta.secret"
		},
		"query": {
			"bool": {
				"must": [
					{"query_string": {"query": 404, "fields": "status"}},
					{"multi_match": {"query": 200, "fields": "code"}},
					{"combined_fields": {"query": true, "fields": "active"}}
				]
			}
		},
		"highlight": {
			"pre_tags": "<em>",
			"post_tags": "</em>",
			"fields": {
				"title": {
					"pre_tags": "<b>",
					"post_tags": "</b>",
					"matched_fields": "title.english",
					"fragment_size": 120
				}
			}
		},
		"sort": [
			{
				"_geo_distance": {
					"pin.location": [-70, 40],
					"order": "desc",
					"unit": "km",
					"mode": "min",
					"missing": 1000,
					"nested": {
						"path": "pin",
						"max_children": 2,
						"nested": {
							"path": "pin.sub"
						}
					}
				}
			}
		]
	}`
	if err := json.Unmarshal([]byte(raw), &sr); err != nil {
		t.Fatalf("failed to unmarshal SearchRequest: %v", err)
	}
	if sr.Source == nil || len(sr.Source.Includes) != 1 || sr.Source.Includes[0] != "meta.*" || len(sr.Source.Excludes) != 1 || sr.Source.Excludes[0] != "meta.secret" {
		t.Fatalf("unexpected SourceFilter: %+v", sr.Source)
	}
	must := sr.Query.Bool.Must
	if len(must) != 3 || must[0].QueryString == nil || must[0].QueryString.Query != "404" || len(must[0].QueryString.Fields) != 1 || must[0].QueryString.Fields[0] != "status" {
		t.Fatalf("unexpected QueryStringQuery: %+v", must[0].QueryString)
	}
	if must[1].MultiMatch == nil || must[1].MultiMatch.Query != float64(200) || len(must[1].MultiMatch.Fields) != 1 || must[1].MultiMatch.Fields[0] != "code" {
		t.Fatalf("unexpected MultiMatchQuery: %+v", must[1].MultiMatch)
	}
	if must[2].CombinedFields == nil || must[2].CombinedFields.Query != true || len(must[2].CombinedFields.Fields) != 1 || must[2].CombinedFields.Fields[0] != "active" {
		t.Fatalf("unexpected CombinedFieldsQuery: %+v", must[2].CombinedFields)
	}
	if sr.Highlight == nil || len(sr.Highlight.PreTags) != 1 || sr.Highlight.PreTags[0] != "<em>" || len(sr.Highlight.PostTags) != 1 || sr.Highlight.PostTags[0] != "</em>" {
		t.Fatalf("unexpected HighlightSpec tags: %+v", sr.Highlight)
	}
	tf := sr.Highlight.FieldSpec("title")
	if len(tf.PreTags) != 1 || tf.PreTags[0] != "<b>" || len(tf.MatchedFields) != 1 || tf.MatchedFields[0] != "title.english" || tf.FragmentSize == nil || *tf.FragmentSize != 120 {
		t.Fatalf("unexpected HighlightFieldSpec for title: %+v", tf)
	}

	// F2: _geo_distance SortSpec MarshalJSON round-trip preserves order, mode, missing, nested.
	if len(sr.Sort) != 1 || sr.Sort[0].Entry.Field != "_geo_distance" {
		t.Fatalf("expected 1 _geo_distance sort, got %+v", sr.Sort)
	}
	if sr.Sort[0].Entry.Missing != "1000" {
		t.Fatalf("expected integral float64 missing '1000', got %q", sr.Sort[0].Entry.Missing)
	}
	marshaledSort, err := json.Marshal(sr.Sort[0])
	if err != nil {
		t.Fatalf("MarshalJSON SortSpec failed: %v", err)
	}
	var rtSort esast.SortSpec
	if err := json.Unmarshal(marshaledSort, &rtSort); err != nil {
		t.Fatalf("round-trip UnmarshalJSON SortSpec failed: %v", err)
	}
	if rtSort.Entry.Order != "desc" || rtSort.Entry.Mode != "min" || rtSort.Entry.Missing != "1000" ||
		rtSort.Entry.Nested == nil || rtSort.Entry.Nested.Path != "pin" ||
		rtSort.Entry.Nested.MaxChildren == nil || *rtSort.Entry.Nested.MaxChildren != 2 ||
		rtSort.Entry.Nested.Nested == nil || rtSort.Entry.Nested.Nested.Path != "pin.sub" {
		t.Fatalf("round-tripped _geo_distance sort lost metadata: %+v (nested=%+v)", rtSort.Entry, rtSort.Entry.Nested)
	}
}

func TestRound38_F3_F4_F5_F6_SchemaCopyToAliasExpandPatternAndShredder(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": "strict",
		"properties": {
			"src_str": {"type": "keyword", "copy_to": ["alias_target", "typed_int", "typed_date"]},
			"alias_target": {"type": "alias", "path": "real_target"},
			"broken_alias": {"type": "alias", "path": ""},
			"real_target": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword", "ignore_above": 10}
				}
			},
			"typed_int": {"type": "integer", "ignore_malformed": true},
			"typed_date": {"type": "date", "format": "yyyy/MM/dd", "ignore_malformed": false},
			"meta": {
				"type": "object",
				"dynamic": false
			},
			"matrix": {
				"type": "object",
				"properties": {
					"val": {"type": "integer"}
				}
			},
			"nested_items": {
				"type": "nested",
				"properties": {
					"score": {"type": "integer", "coerce": false}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "r38_schema", &mapping)

	// F3: copy_to on src_str should have resolved alias_target -> real_target in CopyTo slice.
	srcB := idxSchema.Fields["src_str"]
	if len(srcB.CopyTo) == 0 || srcB.CopyTo[0] != "real_target" {
		t.Fatalf("expected CopyTo[0] to resolve 'alias_target' -> 'real_target', got %+v", srcB.CopyTo)
	}

	// F4: ExpandFieldPattern("*") should not return broken_alias and should deduplicate alias_target vs real_target.
	expanded := idxSchema.ExpandFieldPattern("*")
	seenReal := 0
	for _, bf := range expanded {
		if bf.Field == "broken_alias" {
			t.Fatalf("expected broken_alias with empty path to be excluded from ExpandFieldPattern")
		}
		if bf.Field == "real_target" || bf.Field == "alias_target" {
			seenReal++
		}
	}
	if seenReal != 1 {
		t.Fatalf("expected exactly 1 entry for real_target/alias_target in ExpandFieldPattern('*'), got %d (%+v)", seenReal, expanded)
	}

	// F5 & F6: ShredDocument with dotted dynamic:false key, copy_to onto typed_int (ignore_malformed: true) and valid typed_date ("2026/05/01").
	shreddedBytes, err := schema.ShredDocument(idxSchema, "doc1", 1, false, json.RawMessage(`{
		"src_str": "2026/05/01",
		"meta.hidden": "secret_leak",
		"matrix": [[{"val": 7}]]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument valid doc failed: %v", err)
	}
	var row map[string]any
	_ = json.Unmarshal(shreddedBytes, &row)
	if strings.Contains(row["_all_text"].(string), "secret_leak") {
		t.Fatalf("expected dotted dynamic:false key 'meta.hidden' to be pruned from _all_text, got: %q", row["_all_text"])
	}
	// Because "2026/05/01" is not a valid integer for copy_to target typed_int (ignore_malformed: true), typed_int should be recorded in _ignored.
	ignored, _ := row["_ignored"].([]any)
	foundTypedIntIgnored := false
	for _, ig := range ignored {
		if ig == "typed_int" {
			foundTypedIntIgnored = true
		}
	}
	if !foundTypedIntIgnored {
		t.Fatalf("expected 'typed_int' in _ignored when copy_to fails integer coercion with ignore_malformed:true, got %+v", row["_ignored"])
	}

	// F6: custom date format "yyyy/MM/dd" must NOT fall back to default ISO date parsing when "2026-05-01" is given.
	if _, err := schema.ShredDocument(idxSchema, "doc_bad_date", 1, false, json.RawMessage(`{"typed_date": "2026-05-01"}`)); err == nil {
		t.Fatalf("expected ShredDocument to reject ISO date '2026-05-01' when format is strictly 'yyyy/MM/dd'")
	}

	// F5: nested array of slices [[{"unmapped": 1}]] under dynamic: "strict" must be rejected.
	if _, err := schema.ShredDocument(idxSchema, "doc_strict_2d", 1, false, json.RawMessage(`{"matrix": [[{"unmapped": 1}]]}`)); err == nil {
		t.Fatalf("expected ShredDocument to reject unmapped field inside 2D slice under dynamic:strict")
	}
}

func TestRound38_F11_F12_F13_MemBackendCountCoalescerCancelAndQueryCache(t *testing.T) {
	// F12: StreamLoadCoalescer omits cancelled caller's data when another caller in the same batch succeeds.
	var flushedPayloads []string
	var mu sync.Mutex
	c := newStreamLoadCoalescer(func(_ context.Context, _ string, payload []byte, _ bool) error {
		mu.Lock()
		flushedPayloads = append(flushedPayloads, string(payload))
		mu.Unlock()
		return nil
	})
	c.Configure(40*time.Millisecond, 1024*1024)

	ctxCancel, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	var errCanceled, errActive error
	go func() {
		defer wg.Done()
		errCanceled = c.Submit(ctxCancel, "tbl_f12", []byte(`{"id":"canceled_doc"}`), false)
	}()
	go func() {
		defer wg.Done()
		errActive = c.Submit(context.Background(), "tbl_f12", []byte(`{"id":"active_doc"}`), false)
	}()
	wg.Wait()
	if errCanceled == nil {
		t.Fatalf("expected cancelled caller to receive error")
	}
	if errActive != nil {
		t.Fatalf("expected active caller to succeed, got %v", errActive)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(flushedPayloads) != 1 || strings.Contains(flushedPayloads[0], "canceled_doc") || !strings.Contains(flushedPayloads[0], "active_doc") {
		t.Fatalf("expected flushed batch to contain only active_doc, got %+v", flushedPayloads)
	}

	// F13: containsNowDateMath detects "now" in Match / MultiMatch / CombinedFields and Math.random() / UUID.randomUUID() in scripts.
	for _, rawQ := range []string{
		`{"query": {"match": {"ts": "now-1d"}}}`,
		`{"query": {"multi_match": {"query": "now/d", "fields": ["ts"]}}}`,
		`{"query": {"combined_fields": {"query": "now", "fields": ["ts"]}}}`,
		`{"query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "Math.random()"}}}}`,
		`{"script_fields": {"rnd": {"script": {"source": "UUID.randomUUID()"}}}}`,
	} {
		var sr esast.SearchRequest
		if err := json.Unmarshal([]byte(rawQ), &sr); err != nil {
			t.Fatalf("unmarshal %s: %v", rawQ, err)
		}
		if !containsNowDateMath(&sr, []byte(rawQ)) {
			t.Fatalf("expected containsNowDateMath=true for %s", rawQ)
		}
	}

	// F11: MemBackend COUNT(*) and COUNT on keyword field under multi-valued parent terms agg.
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/r38_f11", `{
		"mappings": {
			"properties": {
				"tags": {"type": "keyword"},
				"label": {"type": "keyword"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/r38_f11/_doc/1?refresh=true", `{"tags": ["a", "b"], "label": "lbl1"}`)
	doReq(t, srv, http.MethodPut, "/r38_f11/_doc/2?refresh=true", `{"tags": ["a"], "label": "lbl2"}`)

	code, res := doReq(t, srv, http.MethodPost, "/r38_f11/_search", `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {"field": "tags"},
				"aggs": {
					"lbl_cnt": {"value_count": {"field": "label"}},
					"lbl_card": {"cardinality": {"field": "label"}}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d %+v", code, res)
	}
	buckets := res["aggregations"].(map[string]any)["by_tag"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %+v", buckets)
	}
	b0 := buckets[0].(map[string]any)
	if b0["lbl_cnt"].(map[string]any)["value"] != float64(2) || b0["lbl_card"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected lbl_cnt=2 and lbl_card=2 on keyword sub-agg, got %+v", b0)
	}
}

func TestRound38_F14_F15_F16_MSearchParamsTopHitsDedupAndScoring(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/r38_f15", `{
		"mappings": {
			"properties": {
				"prices": {"type": "integer"},
				"boost_val": {"type": "integer"}
			}
		}
	}`)
	// Document 1 has two values (12 and 15) that both fall into the same histogram bucket [10, 20) and range [10, 20).
	doReq(t, srv, http.MethodPut, "/r38_f15/_doc/1?refresh=true", `{"prices": [12, 15], "boost_val": 10}`)
	doReq(t, srv, http.MethodPut, "/r38_f15/_doc/2?refresh=true", `{"prices": [14], "boost_val": 50}`)

	// F14: /_msearch?typed_keys=true&rest_total_hits_as_int=true
	msearchBody := "{}\n" + `{"size":0,"aggs":{"max_p":{"max":{"field":"prices"}}}}` + "\n"
	codeMS, msRes := doReq(t, srv, http.MethodPost, "/r38_f15/_msearch?typed_keys=true&rest_total_hits_as_int=true", msearchBody)
	if codeMS != http.StatusOK {
		t.Fatalf("expected 200 from _msearch, got %d %+v", codeMS, msRes)
	}
	sub0 := msRes["responses"].([]any)[0].(map[string]any)
	if _, isNum := sub0["hits"].(map[string]any)["total"].(float64); !isNum {
		t.Fatalf("expected rest_total_hits_as_int to produce numeric hits.total in _msearch, got %T (%+v)", sub0["hits"].(map[string]any)["total"], sub0["hits"])
	}
	if _, hasTyped := sub0["aggregations"].(map[string]any)["max#max_p"]; !hasTyped {
		t.Fatalf("expected typed_keys prefix 'max#max_p' in _msearch sub-response, got %+v", sub0["aggregations"])
	}

	// F15 & F16: top_hits and top_metrics deduplicate same document within a bucket and sort by script_score under size:0.
	codeTH, thRes := doReq(t, srv, http.MethodPost, "/r38_f15/_search", `{
		"size": 0,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['boost_val'].value"}
			}
		},
		"aggs": {
			"hist": {
				"histogram": {"field": "prices", "interval": 10},
				"aggs": {
					"th": {"top_hits": {"size": 5}},
					"tm": {"top_metrics": {"metrics": {"field": "boost_val"}, "sort": [{"boost_val": "desc"}]}}
				}
			}
		}
	}`)
	if codeTH != http.StatusOK {
		t.Fatalf("expected 200, got %d %+v", codeTH, thRes)
	}
	histBuckets := thRes["aggregations"].(map[string]any)["hist"].(map[string]any)["buckets"].([]any)
	if len(histBuckets) != 1 {
		t.Fatalf("expected 1 histogram bucket, got %+v", histBuckets)
	}
	hb0 := histBuckets[0].(map[string]any)
	thHits := hb0["th"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(thHits) != 2 {
		t.Fatalf("expected 2 deduplicated hits in top_hits (not 3), got %d: %+v", len(thHits), thHits)
	}
	// Doc 2 has higher script_score (50 > 10), so it must be sorted first in top_hits under default _score desc sort!
	if thHits[0].(map[string]any)["_id"] != "2" || thHits[0].(map[string]any)["_score"] != float64(50) {
		t.Fatalf("expected doc '2' with _score=50 first in top_hits, got %+v", thHits)
	}
}

func TestRound38_F19_F20_TermsHistogramBucketSortNestedAndCompositeAgg(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/r38_f19", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"num": {"type": "integer"},
				"val": {"type": "integer"},
				"items": {
					"type": "nested",
					"properties": {
						"price": {"type": "integer"}
					}
				}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/r38_f19/_doc/1?refresh=true", `{"cat": "b", "num": 20, "val": 100, "items": [{"price": 5}, {"price": 15}]}`)
	doReq(t, srv, http.MethodPut, "/r38_f19/_doc/2?refresh=true", `{"cat": "a", "num": 100, "val": 10, "items": [{"price": 25}]}`)
	doReq(t, srv, http.MethodPut, "/r38_f19/_doc/3?refresh=true", `{"cat": "c", "num": 5, "items": [{"price": 8}]}`)

	// F19: object-form order {"sum_val": {"order": "asc"}}, bucket_sort with missing, and nested histogram/range sub-aggs.
	code19, res19 := doReq(t, srv, http.MethodPost, "/r38_f19/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {
					"field": "cat",
					"order": [{"sum_val.value": {"order": "desc"}}]
				},
				"aggs": {
					"sum_val": {"sum": {"field": "val"}},
					"sort_by_key": {
						"bucket_sort": {
							"sort": [{"_key": {"order": "asc"}}]
						}
					}
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"price_hist": {
						"histogram": {"field": "items.price", "interval": 10}
					},
					"price_range": {
						"range": {
							"field": "items.price",
							"ranges": [{"to": 10}, {"from": 10}]
						}
					}
				}
			}
		}
	}`)
	if code19 != http.StatusOK {
		t.Fatalf("expected 200 for F19 query, got %d %+v", code19, res19)
	}
	catBuckets := res19["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(catBuckets) != 3 || catBuckets[0].(map[string]any)["key"] != "a" || catBuckets[1].(map[string]any)["key"] != "b" || catBuckets[2].(map[string]any)["key"] != "c" {
		t.Fatalf("expected bucket_sort by _key asc to sort ['a','b','c'], got %+v", catBuckets)
	}
	nestedAgg := res19["aggregations"].(map[string]any)["nested_items"].(map[string]any)
	histB := nestedAgg["price_hist"].(map[string]any)["buckets"].([]any)
	if len(histB) < 2 {
		t.Fatalf("expected top-level nested histogram sub-agg to produce buckets, got %+v", histB)
	}

	// F20: composite agg on integer field sorts numerically (5, 20, 100 — not "100", "20", "5"), supports order: "desc", and returns numeric keys.
	code20, res20 := doReq(t, srv, http.MethodPost, "/r38_f19/_search", `{
		"size": 0,
		"aggs": {
			"comp_num": {
				"composite": {
					"sources": [
						{"n": {"terms": {"field": "num", "order": "desc"}}}
					]
				}
			}
		}
	}`)
	if code20 != http.StatusOK {
		t.Fatalf("expected 200 for F20 composite query, got %d %+v", code20, res20)
	}
	compBuckets := res20["aggregations"].(map[string]any)["comp_num"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 3 {
		t.Fatalf("expected 3 composite buckets, got %+v", compBuckets)
	}
	k0 := compBuckets[0].(map[string]any)["key"].(map[string]any)["n"]
	k1 := compBuckets[1].(map[string]any)["key"].(map[string]any)["n"]
	k2 := compBuckets[2].(map[string]any)["key"].(map[string]any)["n"]
	if k0 != float64(100) || k1 != float64(20) || k2 != float64(5) {
		t.Fatalf("expected numeric desc composite keys [100, 20, 5], got [%v (%T), %v, %v]", k0, k0, k1, k2)
	}
}

func TestRound38_F21_F22_F23_F24_F25_PainlessEnhancements(t *testing.T) {
	// F21: Special characters in bracket keys (`a^b`, `count(total)`, `k;v`, `x,y`)
	// F22: Structural List mutations inside user-defined functions (`void addTag(List l, String v) { l.add(v); }`)
	doc := map[string]any{
		"tags": []any{"init"},
	}
	err := painless.EvalPainless(doc, `
		void addAndSort(List list, String item) {
			list.add(item);
			list.add(0, "first");
		}
		addAndSort(ctx._source.tags, "last");
		ctx._source['a^b'] = 10;
		ctx._source['count(total)'] = 20;
		ctx._source['k;v'] = ctx._source['a^b'] + ctx._source['count(total)'];
	`, nil)
	if err != nil {
		t.Fatalf("EvalPainless F21/F22 failed: %v", err)
	}
	tags, _ := doc["tags"].([]any)
	if len(tags) != 3 || tags[0] != "first" || tags[1] != "init" || tags[2] != "last" {
		t.Fatalf("expected user-defined function to structurally mutate ctx._source.tags, got %+v", doc["tags"])
	}
	if doc["a^b"] != int64(10) || doc["count(total)"] != int64(20) || doc["k;v"] != int64(30) {
		t.Fatalf("expected special-char bracket keys to be set and resolved, got %+v", doc)
	}

	// F23: Stream Optional chaining (.findFirst().map(...).filter(...).orElse(...)), .peek(...), Collectors.groupingBy / summingInt / toMap / partitioningBy / averagingDouble / joining
	streamVal, err := painless.Eval(map[string]any{}, `
		List nums = [1, 2, 3, 4, 2];
		List seen = [];
		int optVal = nums.stream().peek(x -> seen.add(x)).filter(x -> x > 2).findFirst().map(x -> x * 10).filter(x -> x == 30).orElse(-1);
		int optFallback = nums.stream().filter(x -> x > 100).findFirst().orElseGet(() -> 99);
		boolean hasAny = nums.stream().filter(x -> x == 3).findFirst().isPresent();
		boolean noneBig = nums.stream().filter(x -> x > 100).findFirst().isEmpty();
		List side = [];
		nums.stream().filter(x -> x == 4).findFirst().ifPresent(x -> side.add(x));
		Map grouped = [1, 2, 3, 4].stream().collect(Collectors.groupingBy(x -> x % 2 == 0 ? 'even' : 'odd', Collectors.summingInt(x -> x)));
		Map mergedMap = nums.stream().collect(Collectors.toMap(x -> 'k' + (x % 2), x -> x, (a, b) -> a + b));
		Map partMap = [1, 2, 3, 4].stream().collect(Collectors.partitioningBy(x -> x > 2, Collectors.counting()));
		double avgVal = [2, 4].stream().collect(Collectors.averagingDouble(x -> x));
		String joined = ['a', 'b'].stream().collect(Collectors.joining(',', '[', ']'));
		List uniq = nums.stream().collect(Collectors.toSet());
		Map<String, Object> genMap = new HashMap<String, Object>();
		genMap.put('sz', uniq.size());
		return optVal + ":" + seen.size() + ":" + grouped['even'] + ":" + grouped['odd'] + ":" + optFallback + ":" + hasAny + ":" + noneBig + ":" + side.size() + ":" + mergedMap['k0'] + ":" + partMap['true'] + ":" + avgVal + ":" + joined + ":" + genMap['sz'];
	`, nil)
	if err != nil || streamVal != "30:5:6:4:99:true:true:1:8:2:3:[a,b]:4" {
		t.Fatalf("expected Stream Optional/peek/groupingBy result '30:5:6:4:99:true:true:1:8:2:3:[a,b]:4', got val=%v err=%v", streamVal, err)
	}

	// F24 & F25: Expression lambda assignment in Map.compute, (char)/(int)/(short)/(byte) casts, 2-arg Map.remove(k, v), 2-arg List.addAll(idx, c), and ZonedDateTime methods.
	miscVal, err := painless.Eval(map[string]any{}, `
		Map m = ['a': 5, 'b': 10];
		m.compute('a', (k, v) -> v = v + 15);
		boolean remFalse = m.remove('b', 999);
		boolean remTrue = m.remove('b', 10);
		List l = ['x', 'z'];
		l.addAll(1, ['y1', 'y2']);
		int codeA = (int) 'A';
		String chB = (char) 66;
		int sh = (short) 65535;
		int by = (byte) 255;
		ZonedDateTime zdt = ZonedDateTime.parse("2026-03-15T10:20:30Z").plusYears(1).plusMonths(2).minusDays(5).withHour(8).truncatedTo(ChronoUnit.HOURS);
		return m['a'] + "|" + remFalse + "|" + remTrue + "|" + String.join(",", l) + "|" + codeA + "|" + chB + "|" + sh + "|" + by + "|" + zdt.getYear() + "-" + zdt.getMonthValue() + "-" + zdt.getDayOfMonth() + "T" + zdt.getHour() + ":" + zdt.getMinute();
	`, nil)
	if err != nil || miscVal != "20|false|true|x,y1,y2,z|65|B|-1|-1|2027-5-10T8:0" {
		t.Fatalf("unexpected F24/F25 evaluation result: val=%v err=%v", miscVal, err)
	}
}

func TestRound38_F26_F27_F28_F29_F30_IngestCloneVersioningAliasesAndUpdateSource(t *testing.T) {
	srv, _ := newTestServer()

	// F26 & F27: Ingest script processor with if condition on ctx._routing and gsub with \$ and $USD.
	doReq(t, srv, http.MethodPut, "/_ingest/pipeline/r38_pipe", `{
		"processors": [
			{
				"gsub": {
					"field": "price_str",
					"pattern": "(\\d+)",
					"replacement": "\\$$1 $USD"
				}
			},
			{
				"script": {
					"if": "ctx._id == '1'",
					"source": "ctx._routing = 'custom_shard'; ctx.routed = true;"
				}
			}
		]
	}`)
	doReq(t, srv, http.MethodPut, "/r38_idx", `{
		"mappings": {
			"_routing": {"required": true},
			"properties": {
				"price_str": {"type": "keyword"},
				"routed": {"type": "boolean"},
				"extra": {"type": "keyword"}
			}
		}
	}`)
	cPut, putRes := doReq(t, srv, http.MethodPut, "/r38_idx/_doc/1?pipeline=r38_pipe&refresh=true", `{"price_str": "99", "extra": "keep"}`)
	if cPut != http.StatusCreated || putRes["_routing"] != "custom_shard" {
		t.Fatalf("expected 201 with _routing='custom_shard', got %d %+v", cPut, putRes)
	}

	// F30: POST /{index}/_update/{id} with "_source": ["price_str"] in body returns filtered get._source.
	cUpd, updRes := doReq(t, srv, http.MethodPost, "/r38_idx/_update/1?routing=custom_shard&refresh=true", `{
		"doc": {"extra": "updated"},
		"_source": ["price_str"]
	}`)
	if cUpd != http.StatusOK {
		t.Fatalf("expected 200 on _update, got %d %+v", cUpd, updRes)
	}
	getObj, _ := updRes["get"].(map[string]any)
	getSrc, _ := getObj["_source"].(map[string]any)
	if getSrc["price_str"] != "$99 $USD" || getSrc["extra"] != nil {
		t.Fatalf("expected get._source to have gsubbed price_str='$99 $USD' and omit 'extra', got %+v", updRes)
	}

	// F27: _clone copies s.docRouting to target index so GET with wrong routing or missing required routing is enforced.
	cClone, cloneRes := doReq(t, srv, http.MethodPost, "/r38_idx/_clone/r38_cloned", `{}`)
	if cClone != http.StatusOK {
		t.Fatalf("expected 200 on _clone, got %d %+v", cClone, cloneRes)
	}
	cGetCloned, getClonedRes := doReq(t, srv, http.MethodGet, "/r38_cloned/_doc/1?routing=custom_shard", "")
	if cGetCloned != http.StatusOK || getClonedRes["_routing"] != "custom_shard" {
		t.Fatalf("expected cloned index to preserve _routing='custom_shard', got %d %+v", cGetCloned, getClonedRes)
	}

	// F28: version_type=external conflict check on deleted tombstones.
	doReq(t, srv, http.MethodPut, "/r38_ext_ver/_doc/1?version=10&version_type=external&refresh=true", `{"v": 10}`)
	doReq(t, srv, http.MethodDelete, "/r38_ext_ver/_doc/1?version=20&version_type=external&refresh=true", "")
	// Stale external version 15 (<= tombstone version 20) MUST return 409 Conflict!
	cStale, _ := doReq(t, srv, http.MethodPut, "/r38_ext_ver/_doc/1?version=15&version_type=external&refresh=true", `{"v": 15}`)
	if cStale != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when indexing stale external version 15 over tombstone at version 20, got %d", cStale)
	}
	// Newer external version 25 (> 20) must succeed!
	cNewer, _ := doReq(t, srv, http.MethodPut, "/r38_ext_ver/_doc/1?version=25&version_type=external&refresh=true", `{"v": 25}`)
	if cNewer != http.StatusCreated {
		t.Fatalf("expected 201 Created when indexing external version 25 > 20, got %d", cNewer)
	}

	// F29: POST /_aliases with wildcard index pattern and remove_index, DELETE missing alias -> 404, GET /_data_stream -> 200.
	cMissingAlias, _ := doReq(t, srv, http.MethodDelete, "/r38_ext_ver/_alias/no_such_alias", "")
	if cMissingAlias != http.StatusNotFound {
		t.Fatalf("expected 404 when deleting nonexistent alias, got %d", cMissingAlias)
	}
	cAliases, _ := doReq(t, srv, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "r38_*", "alias": "all_r38"}},
			{"remove_index": {"index": "r38_cloned"}}
		]
	}`)
	if cAliases != http.StatusOK {
		t.Fatalf("expected 200 from POST /_aliases, got %d", cAliases)
	}
	cClonedCheck, _ := doReq(t, srv, http.MethodHead, "/r38_cloned", "")
	if cClonedCheck != http.StatusNotFound {
		t.Fatalf("expected r38_cloned to be deleted by remove_index action, got %d", cClonedCheck)
	}
	cDS, dsRes := doReq(t, srv, http.MethodGet, "/_data_stream", "")
	if cDS != http.StatusOK || dsRes["data_streams"] == nil {
		t.Fatalf("expected 200 with data_streams array from GET /_data_stream, got %d %+v", cDS, dsRes)
	}

	// F17: POST /_analyze with normalizer="custom_normalizer" emits single keyword token lowercased without whitespace splitting.
	cAn, anRes := doReq(t, srv, http.MethodPost, "/_analyze", `{
		"normalizer": "custom_normalizer",
		"text": "  Hello World 123  "
	}`)
	if cAn != http.StatusOK {
		t.Fatalf("expected 200 from POST /_analyze, got %d %+v", cAn, anRes)
	}
	tokens, _ := anRes["tokens"].([]any)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 single keyword token from custom_normalizer, got %+v", tokens)
	}
	tok0, _ := tokens[0].(map[string]any)
	if tok0["token"] != "  hello world 123  " {
		t.Fatalf("expected custom_normalizer token '  hello world 123  ', got %+v", tok0)
	}

	// ILM policy, data stream, cluster state, DDL, and dot_product kNN coverage.
	doReq(t, srv, http.MethodPut, "/_ilm/policy/r38_pol", `{"policy": {"phases": {"hot": {"actions": {}}}}}`)
	doReq(t, srv, http.MethodPut, "/_ilm/policy/r38_pol", `{"policy": {"phases": {"hot": {"actions": {}}}}}`)
	cHeadPol, _ := doReq(t, srv, http.MethodHead, "/_ilm/policy/r38_pol", "")
	if cHeadPol != http.StatusOK {
		t.Fatalf("expected 200 from HEAD /_ilm/policy/r38_pol, got %d", cHeadPol)
	}
	doReq(t, srv, http.MethodGet, "/_ilm/policy/r38_*", "")
	doReq(t, srv, http.MethodGet, "/_ilm/policy", "")
	doReq(t, srv, http.MethodGet, "/r38_idx/_ilm/explain", "")
	cDelPol, _ := doReq(t, srv, http.MethodDelete, "/_ilm/policy/r38_pol", "")
	if cDelPol != http.StatusOK {
		t.Fatalf("expected 200 from DELETE /_ilm/policy/r38_pol, got %d", cDelPol)
	}
	cDelPol404, _ := doReq(t, srv, http.MethodDelete, "/_ilm/policy/r38_pol", "")
	if cDelPol404 != http.StatusNotFound {
		t.Fatalf("expected 404 from deleting missing ILM policy, got %d", cDelPol404)
	}
	doReq(t, srv, http.MethodPut, "/_data_stream/r38_ds", `{}`)
	doReq(t, srv, http.MethodGet, "/_data_stream/r38_ds", "")
	cDelDS, _ := doReq(t, srv, http.MethodDelete, "/_data_stream/r38_ds", "")
	if cDelDS != http.StatusOK {
		t.Fatalf("expected 200 from DELETE /_data_stream/r38_ds, got %d", cDelDS)
	}
	doReq(t, srv, http.MethodGet, "/_cluster/state", "")
	doReq(t, srv, http.MethodGet, "/_cluster/stats", "")
	doReq(t, srv, http.MethodGet, "/r38_idx/_doris/ddl", "")
	doReq(t, srv, http.MethodGet, "/readyz", "")
	doReq(t, srv, http.MethodGet, "/healthz", "")

	// dot_product vector similarity on MemBackend
	doReq(t, srv, http.MethodPut, "/r38_vec", `{
		"mappings": {
			"properties": {
				"emb": {"type": "dense_vector", "dims": 2, "similarity": "dot_product"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/r38_vec/_doc/1?refresh=true", `{"emb": [0.8, 0.6]}`)
	doReq(t, srv, http.MethodPut, "/r38_vec/_doc/2?refresh=true", `{"emb": [0.1, 0.9]}`)
	cVec, vecRes := doReq(t, srv, http.MethodPost, "/r38_vec/_search", `{
		"knn": {"field": "emb", "query_vector": [1.0, 0.0], "k": 1, "num_candidates": 2}
	}`)
	vecHits, _ := vecRes["hits"].(map[string]any)["hits"].([]any)
	if cVec != http.StatusOK || len(vecHits) != 1 {
		t.Fatalf("expected 1 hit from dot_product kNN search, got %d %+v", cVec, vecRes)
	}
}
