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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newTestServer() (*Server, *MemoryBackend) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	return srv, mem
}

func doJSON(t *testing.T, srv *Server, method, path, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code >= 400 {
		t.Fatalf("%s %s failed (%d): %s", method, path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s invalid JSON (%v): %s", method, path, err, rec.Body.String())
	}
	return out
}

func TestRound15_KeywordCompanionAndLowercaseOnArrayAndNestedSubfield(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_kw_idx", `{
		"settings": {
			"analysis": {
				"normalizer": {
					"lc_norm": {"type": "custom", "filter": ["lowercase"]}
				}
			}
		},
		"mappings": {
			"properties": {
				"tags": {
					"type": "text",
					"array": true,
					"fields": {
						"keyword": {"type": "keyword", "normalizer": "lc_norm"}
					}
				},
				"items": {
					"type": "nested",
					"properties": {
						"label": {
							"type": "text",
							"fields": {
								"keyword": {"type": "keyword", "normalizer": "lc_norm"}
							}
						}
					}
				}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPut, "/r15_kw_idx/_doc/1", `{"tags": ["Alpha", "Beta"], "items": [{"label": "Gamma"}, {"label": "Delta"}]}`)
	doJSON(t, srv, http.MethodPut, "/r15_kw_idx/_doc/2", `{"tags": ["BETA", "Epsilon"], "items": [{"label": "GAMMA"}]}`)

	// 1. Term query on tags.keyword (case-insensitive via lc_norm) and nested items.label.keyword
	res := doJSON(t, srv, http.MethodPost, "/r15_kw_idx/_search", `{
		"query": {
			"bool": {
				"must": [
					{"term": {"tags.keyword": "ALPHA"}},
					{"nested": {"path": "items", "query": {"term": {"items.label.keyword": "gamma"}}}}
				]
			}
		},
		"aggs": {
			"tag_terms": {"terms": {"field": "tags.keyword", "size": 10}},
			"tag_card": {"cardinality": {"field": "tags.keyword"}}
		}
	}`)
	tot := int(res["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
	if tot != 1 {
		t.Fatalf("expected 1 hit for tags.keyword=ALPHA + nested items.label.keyword=gamma, got %d", tot)
	}
	aggs := res["aggregations"].(map[string]any)
	buckets := aggs["tag_terms"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 tag_terms buckets on doc 1, got %v", buckets)
	}
}

func TestRound15_CollapseOnArrayAndNestedSubfieldWithInnerHits(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_collapse_arr", `{
		"mappings": {
			"properties": {
				"groups": {"type": "keyword", "array": true},
				"score_val": {"type": "integer"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/r15_collapse_arr/_doc/1", `{"groups": ["g1", "g2"], "score_val": 100}`)
	doJSON(t, srv, http.MethodPut, "/r15_collapse_arr/_doc/2", `{"groups": ["g2"], "score_val": 50}`)

	res := doJSON(t, srv, http.MethodPost, "/r15_collapse_arr/_search", `{
		"collapse": {
			"field": "groups",
			"inner_hits": {
				"name": "group_docs",
				"size": 5,
				"sort": [{"score_val": "desc"}]
			}
		},
		"sort": [{"score_val": "desc"}]
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 collapsed hits (g1 and g2), got %d: %v", len(hits), hits)
	}
	// Group g2's inner_hits must include BOTH doc 1 (groups=["g1","g2"]) and doc 2 (groups=["g2"])
	secondHit := hits[1].(map[string]any)
	ihHits := secondHit["inner_hits"].(map[string]any)["group_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(ihHits) != 2 {
		t.Fatalf("expected 2 inner_hits in group g2 (including multi-valued doc 1), got %d: %v", len(ihHits), ihHits)
	}
}

func TestRound15_SearchAfterTotalHitsMissingSortAndMultiIndex(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_sa_1", `{"mappings": {"properties": {"rank": {"type": "integer"}, "big": {"type": "long"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r15_sa_2", `{"mappings": {"properties": {"rank": {"type": "integer"}, "big": {"type": "long"}}}}`)

	doJSON(t, srv, http.MethodPut, "/r15_sa_1/_doc/1", `{"rank": 10}`)
	doJSON(t, srv, http.MethodPut, "/r15_sa_1/_doc/2", `{"rank": 20}`)
	doJSON(t, srv, http.MethodPut, "/r15_sa_2/_doc/3", `{}`) // rank is NULL

	// Page 1: sort rank asc (missing: "_last"), size 2
	p1 := doJSON(t, srv, http.MethodPost, "/r15_sa_1,r15_sa_2/_search", `{
		"size": 2,
		"from": 5,
		"track_total_hits": true,
		"sort": [{"rank": {"order": "asc", "missing": "_last"}}, {"_id": "asc"}],
		"search_after": [10, "1"]
	}`)
	p1Total := int(p1["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
	if p1Total != 3 {
		t.Fatalf("expected hits.total.value=3 (all query matches, not cursor remainder), got %d", p1Total)
	}
	p1Hits := p1["hits"].(map[string]any)["hits"].([]any)
	if len(p1Hits) != 2 {
		t.Fatalf("expected 2 hits after [10, '1'] (doc 2 with rank=20 and doc 3 with rank=NULL), got %d: %v", len(p1Hits), p1Hits)
	}
	if p1Hits[0].(map[string]any)["_id"] != "2" || p1Hits[1].(map[string]any)["_id"] != "3" {
		t.Fatalf("unexpected hit order on search_after with missing=_last: %v", p1Hits)
	}

	// Verify large integer missing value in SortSpec does not format in scientific notation
	var sr esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"sort": [{"big": {"order": "asc", "missing": 1700000000000}}]}`), &sr); err != nil {
		t.Fatalf("unmarshal sort: %v", err)
	}
	if sr.Sort[0].Entry.Missing != "1700000000000" {
		t.Fatalf("expected exact integer missing string '1700000000000', got %q", sr.Sort[0].Entry.Missing)
	}
}

func TestRound15_DateNanosNestedDatesAndBooleanNormalization(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_types_idx", `{
		"mappings": {
			"properties": {
				"active": {"type": "boolean"},
				"flags": {"type": "boolean", "array": true},
				"ts_ns": {"type": "date_nanos"},
				"note": {"type": "text"},
				"events": {
					"type": "nested",
					"properties": {
						"at": {"type": "date"},
						"ok": {"type": "boolean"}
					}
				}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPut, "/r15_types_idx/_doc/1", `{
		"active": true,
		"flags": ["1", "false"],
		"ts_ns": "2026-05-01T00:00:00.123456789Z",
		"note": "true story",
		"events": [{"at": "2026-05-01T00:00:00Z", "ok": "true"}]
	}`)

	res := doJSON(t, srv, http.MethodPost, "/r15_types_idx/_search", `{
		"query": {
			"bool": {
				"must": [
					{"term": {"active": "TRUE"}},
					{"term": {"flags": 1}},
					{"range": {"ts_ns": {"gte": "2026-05-01T00:00:00Z"}}},
					{"query_string": {"query": "note:true"}},
					{"nested": {"path": "events", "query": {"bool": {"must": [
						{"term": {"events.ok": "1"}},
						{"range": {"events.at": {"gte": 1777593600000}}}
					]}}}}
				]
			}
		}
	}`)
	tot := int(res["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
	if tot != 1 {
		t.Fatalf("expected 1 hit for date_nanos + nested date + boolean coercion + note:true, got %d", tot)
	}
}

func TestRound15_NestedInnerHitsScoringOuterLambdaAndDuplicatePaths(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_nested_ih", `{
		"mappings": {
			"properties": {
				"comments": {
					"type": "nested",
					"properties": {
						"author": {"type": "keyword"},
						"votes": {"type": "integer"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/r15_nested_ih/_doc/1", `{
		"comments": [
			{"author": "alice", "votes": 2},
			{"author": "alice", "votes": 50},
			{"author": "bob", "votes": 10}
		]
	}`)

	res := doJSON(t, srv, http.MethodPost, "/r15_nested_ih/_search", `{
		"query": {
			"bool": {
				"should": [
					{
						"nested": {
							"path": "comments",
							"query": {
								"function_score": {
									"query": {"term": {"comments.author": "alice"}},
									"field_value_factor": {"field": "comments.votes", "factor": 2.0}
								}
							},
							"inner_hits": {
								"script_fields": {
									"double_votes": {"script": "doc['votes'].value * 2"}
								}
							}
						}
					},
					{
						"nested": {
							"path": "comments",
							"query": {"term": {"comments.author": "nonexistent"}},
							"inner_hits": {}
						}
					}
				]
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	ih := hits[0].(map[string]any)["inner_hits"].(map[string]any)["comments"].(map[string]any)["hits"].(map[string]any)
	ihList := ih["hits"].([]any)
	if len(ihList) != 2 {
		t.Fatalf("expected non-empty inner_hits (2 elements) not to be overwritten by second unnamed nested clause, got %d", len(ihList))
	}
	firstElem := ihList[0].(map[string]any)
	if firstElem["_score"].(float64) <= ihList[1].(map[string]any)["_score"].(float64) {
		t.Fatalf("expected nested inner_hits to be scored and ordered by relevance (votes=50 before votes=2), got %v", ihList)
	}
	fields := firstElem["fields"].(map[string]any)["double_votes"].([]any)
	if fields[0].(float64) != 100 {
		t.Fatalf("expected inner_hits script_fields double_votes=100, got %v", fields)
	}
}

func TestRound15_CompositeDescMissingBucketAndTermsMultiHopOrder(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_comp_idx", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"amt": {"type": "integer"},
				"items": {
					"type": "nested",
					"properties": {
						"price": {"type": "integer"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/r15_comp_idx/_doc/1", `{"cat": "a", "amt": 10, "items": [{"price": 100}]}`)
	doJSON(t, srv, http.MethodPut, "/r15_comp_idx/_doc/2", `{"cat": "b", "amt": 20, "items": [{"price": 5}]}`)
	doJSON(t, srv, http.MethodPut, "/r15_comp_idx/_doc/3", `{"cat": "c", "amt": 30, "items": [{"price": 50}]}`)
	doJSON(t, srv, http.MethodPut, "/r15_comp_idx/_doc/4", `{"amt": 40, "items": [{"price": 1}]}`)

	// 1. Composite with order: "desc", missing_bucket: true, size: 2, and after pagination
	p1 := doJSON(t, srv, http.MethodPost, "/r15_comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"sources": [
						{"cat": {"terms": {"field": "cat", "order": "desc", "missing_bucket": true}}}
					]
				}
			}
		}
	}`)
	b1 := p1["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(b1) != 2 || b1[0].(map[string]any)["key"].(map[string]any)["cat"] != "c" || b1[1].(map[string]any)["key"].(map[string]any)["cat"] != "b" {
		t.Fatalf("expected first page [c, b], got %v", b1)
	}
	p2 := doJSON(t, srv, http.MethodPost, "/r15_comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"after": {"cat": "b"},
					"sources": [
						{"cat": {"terms": {"field": "cat", "order": "desc", "missing_bucket": true}}}
					]
				}
			}
		}
	}`)
	b2 := p2["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(b2) != 2 || b2[0].(map[string]any)["key"].(map[string]any)["cat"] != "a" || b2[1].(map[string]any)["key"].(map[string]any)["cat"] != nil {
		t.Fatalf("expected second page [a, nil] on composite desc after 'b', got %v", b2)
	}

	// 2. Terms ordered by nested sub-aggregation `nested_items>total_price.value`
	res := doJSON(t, srv, http.MethodPost, "/r15_comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {
					"field": "cat",
					"order": {"nested_items>total_price.value": "desc"}
				},
				"aggs": {
					"nested_items": {
						"nested": {"path": "items"},
						"aggs": {
							"total_price": {"sum": {"field": "items.price"}}
						}
					}
				}
			}
		}
	}`)
	catBuckets := res["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(catBuckets) != 3 || catBuckets[0].(map[string]any)["key"] != "a" || catBuckets[1].(map[string]any)["key"] != "c" || catBuckets[2].(map[string]any)["key"] != "b" {
		t.Fatalf("expected by_cat ordered [a (100), c (50), b (5)], got %v", catBuckets)
	}
}

func TestRound15_PainlessReturnInForLoopLocalListAliasesAndSubList(t *testing.T) {
	// 1. return <expr>; inside a C-style for loop
	doc := map[string]any{"nums": []any{2.0, 5.0, 9.0, 12.0}}
	val, err := painless.Eval(doc, `
		for (int i = 0; i < doc['nums'].size(); i++) {
			if (doc['nums'][i] > 6) {
				return doc['nums'][i] * 10;
			}
		}
		return -1;
	`, nil)
	if err != nil || fmt.Sprintf("%v", val) != "90" {
		t.Fatalf("expected return inside for loop to yield 90, got %v (err=%v)", val, err)
	}

	// 2. Local list variable aliasing ctx._source.tags + .add(), .remove(), .subList(), .get(i) on LHS
	raw := []byte(`{"tags": ["a", "b", "c"], "items": [{"qty": 3}]}`)
	updated, _, err := painless.ApplyUpdateWithResult(raw, &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				def list = ctx._source.tags;
				list.add('d');
				list.remove(0);
				ctx._source.slice = list.subList(0, 2);
				ctx._source.items.get(0).qty += 7;
			`,
		},
	}, true)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	s := string(updated)
	if !strings.Contains(s, `"tags":["b","c","d"]`) || !strings.Contains(s, `"slice":["b","c"]`) || !strings.Contains(s, `"qty":10`) {
		t.Fatalf("unexpected mutated document: %s", s)
	}
}

func TestRound15_PainlessDocValuesAndSearchAggScripts(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_script_idx", `{
		"mappings": {
			"properties": {
				"name": {"type": "keyword"},
				"price": {"type": "double"},
				"qty": {"type": "integer"},
				"tags": {"type": "keyword", "array": true}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/r15_script_idx/_doc/1", `{"name": "item1", "price": 10.0, "qty": 3, "tags": ["x", "y"]}`)
	doJSON(t, srv, http.MethodPut, "/r15_script_idx/_doc/2", `{"name": "item2", "price": 25.0, "qty": 4, "tags": ["y"]}`)
	doJSON(t, srv, http.MethodPut, "/r15_script_idx/_doc/3", `{"name": "item3", "price": 5.0, "qty": 1}`)

	res := doJSON(t, srv, http.MethodPost, "/r15_script_idx/_search", `{
		"query": {
			"script_score": {
				"query": {
					"script": {
						"script": {
							"source": "!doc['tags'].empty && doc['price'].value * doc['qty'].value >= params.min_rev",
							"params": {"min_rev": 20}
						}
					}
				},
				"script": {
					"source": "doc['price'].value * doc['qty'].value"
				}
			}
		},
		"script_fields": {
			"revenue": {
				"script": {
					"source": "params._source.price * params._source.qty + doc['tags'].size()"
				}
			}
		},
		"sort": [
			{
				"_script": {
					"type": "number",
					"order": "asc",
					"script": {"source": "doc['price'].value * doc['qty'].value"}
				}
			}
		],
		"aggs": {
			"script_terms": {
				"terms": {
					"script": {"source": "doc['name'].value + '_' + doc['qty'].value"}
				}
			},
			"by_name": {
				"terms": {"field": "name"},
				"aggs": {
					"rev": {"sum": {"field": "price"}},
					"high_rev": {
						"bucket_selector": {
							"buckets_path": {"r": "rev"},
							"script": {
								"source": "params.r >= params.cutoff",
								"params": {"cutoff": 20}
							}
						}
					}
				}
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits matching script filter, got %d: %v", len(hits), hits)
	}
	firstHit := hits[0].(map[string]any)
	if firstHit["_id"] != "1" || firstHit["_score"].(float64) != 30.0 {
		t.Fatalf("expected first hit id=1 with script_score=30.0, got %v", firstHit)
	}
	revField := firstHit["fields"].(map[string]any)["revenue"].([]any)[0].(float64)
	if revField != 32.0 {
		t.Fatalf("expected script_fields revenue=32.0, got %v", revField)
	}
	aggs := res["aggregations"].(map[string]any)
	stBuckets := aggs["script_terms"].(map[string]any)["buckets"].([]any)
	if len(stBuckets) != 2 {
		t.Fatalf("expected 2 script_terms buckets, got %v", stBuckets)
	}
	byNameBuckets := aggs["by_name"].(map[string]any)["buckets"].([]any)
	if len(byNameBuckets) != 1 || byNameBuckets[0].(map[string]any)["key"] != "item2" {
		t.Fatalf("expected bucket_selector with script.params cutoff=20 to keep only item2, got %v", byNameBuckets)
	}

	// Verify function_score.script_score + functions[].script_score + bool.must_not/should script + post_filter script
	resFS := doJSON(t, srv, http.MethodPost, "/r15_script_idx/_search", `{
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [{"script": {"script": {"source": "doc['price'].value > 0"}}}],
						"must_not": [{"script": {"script": {"source": "doc['price'].value > 999"}}}]
					}
				},
				"boost_mode": "replace",
				"functions": [
					{
						"script_score": {
							"script": {"source": "doc['price'].value + params.bonus", "params": {"bonus": 5}}
						},
						"weight": 2
					}
				]
			}
		},
		"post_filter": {
			"script": {"script": {"source": "doc['qty'].value >= 2"}}
		}
	}`)
	fsHits := resFS["hits"].(map[string]any)["hits"].([]any)
	if len(fsHits) != 2 {
		t.Fatalf("expected 2 hits after post_filter script, got %d", len(fsHits))
	}
}

func TestRound15_IngestNestedOnFailureTemplatesDotExpanderAndProcessors(t *testing.T) {
	srv, _ := newTestServer()

	sim := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"foreach": {
						"field": "nums",
						"processor": {
							"convert": {
								"field": "_ingest._value",
								"type": "integer",
								"tag": "inner_conv"
							}
						},
						"on_failure": [
							{
								"set": {
									"field": "err_type",
									"value": "{{{_ingest.on_failure_processor_type}}}"
								}
							},
							{
								"set": {
									"field": "err_tag",
									"value": "{{_ingest.on_failure_processor_tag}}"
								}
							}
						]
					}
				},
				{"set": {"field": "nested.a", "value": 1}},
				{"dot_expander": {"field": "nested.b"}},
				{"copy": {"field": "nested.a", "target_field": "copied_a"}},
				{"grok": {"field": "log", "patterns": ["%{IP:client_ip} %{WORD:method} %{INT:status:int}"]}},
				{"sort": {"field": "arr", "order": "asc"}},
				{"compact": {"field": "sparse"}},
				{"csv": {"field": "csv_line", "target_fields": ["c1", "c2"], "trim": true}},
				{"uri_parts": {"field": "uri", "target_field": "parsed_url"}},
				{"registered_domain": {"field": "fqdn", "target_field": "dom"}},
				{"fingerprint": {"fields": ["c1", "c2"], "target_field": "fp"}},
				{"redact": {"field": "secret_msg", "patterns": ["%{EMAILADDRESS:EMAIL}"]}}
			]
		},
		"docs": [
			{
				"_source": {
					"nums": ["10", "bad_int"],
					"nested.b": 2,
					"log": "10.0.0.1 GET 200",
					"arr": [3, 1, 2],
					"sparse": ["x", null, "", "y"],
					"csv_line": " hello , world ",
					"uri": "https://user:pass@sub.example.co.uk:8443/path/file.txt?k=v#frag",
					"fqdn": "sub.example.co.uk",
					"secret_msg": "contact admin@example.com now"
				}
			}
		]
	}`)
	docOut := sim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if docOut["err_type"] != "convert" || docOut["err_tag"] != "inner_conv" {
		t.Fatalf("expected inner foreach processor type=convert and tag=inner_conv, got type=%v tag=%v", docOut["err_type"], docOut["err_tag"])
	}
	nestedMap := docOut["nested"].(map[string]any)
	if nestedMap["a"] != float64(1) || nestedMap["b"] != float64(2) {
		t.Fatalf("expected dot_expander to deep-merge into nested map, got %v", nestedMap)
	}
	if docOut["client_ip"] != "10.0.0.1" || docOut["status"] != float64(200) {
		t.Fatalf("expected grok extraction client_ip=10.0.0.1 status=200, got %v", docOut)
	}
	if docOut["secret_msg"] != "contact <EMAIL> now" {
		t.Fatalf("expected redact processor output 'contact <EMAIL> now', got %v", docOut["secret_msg"])
	}
	domMap := docOut["dom"].(map[string]any)
	if domMap["registered_domain"] != "example.co.uk" || domMap["subdomain"] != "sub" {
		t.Fatalf("expected registered_domain=example.co.uk subdomain=sub, got %v", domMap)
	}

	sim2 := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"urldecode": {"field": "urls"}},
				{"bytes": {"field": "sizes"}},
				{"html_strip": {"field": "htmls"}},
				{"date": {"field": "ts_raw", "formats": ["yyyy-MM-dd HH:mm:ss"], "timezone": "UTC", "output_format": "yyyy-MM-dd"}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "logs-", "date_rounding": "M", "date_formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "yr-", "date_rounding": "y", "target_field": "yr_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "wk-", "date_rounding": "w", "target_field": "wk_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "dy-", "date_rounding": "d", "target_field": "dy_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "hr-", "date_rounding": "h", "target_field": "hr_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "mn-", "date_rounding": "m", "target_field": "mn_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"date_index_name": {"field": "ts_raw", "index_name_prefix": "sc-", "date_rounding": "s", "target_field": "sc_idx", "formats": ["yyyy-MM-dd HH:mm:ss"]}},
				{"sort": {"field": "nums_desc", "order": "desc", "target_field": "sorted_desc"}},
				{"compact": {"field": "obj_sparse", "target_field": "obj_compact"}},
				{"fingerprint": {"fields": ["ts_raw"], "method": "SHA-384", "salt": "s1", "target_field": "fp384"}},
				{"fingerprint": {"fields": ["ts_raw"], "method": "SHA-512", "target_field": "fp512"}},
				{"csv": {"field": "csv_semi", "separator": ";", "quote": "'", "empty_value": "NA", "target_fields": ["f1", "f2", "f3"]}},
				{"user_agent": {"field": "ua1", "target_field": "ua_chrome"}},
				{"user_agent": {"field": "ua2", "target_field": "ua_safari"}},
				{"user_agent": {"field": "ua3", "target_field": "ua_ff"}},
				{"user_agent": {"field": "ua4", "target_field": "ua_edge"}},
				{"user_agent": {"field": "ua5", "target_field": "ua_curl"}}
			]
		},
		"docs": [
			{
				"_source": {
					"urls": ["a%20b", "c%2Fd"],
					"sizes": ["1kb", "2mb"],
					"htmls": ["<b>hi</b>", "<i>there</i>"],
					"ts_raw": "2025-05-15 14:30:45",
					"nums_desc": [1, 3, 2],
					"obj_sparse": {"keep": "yes", "empty_str": "", "nil_v": null, "empty_map": {}, "empty_arr": []},
					"csv_semi": "'hello;world';;tail",
					"ua1": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
					"ua2": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1.15",
					"ua3": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Firefox/119.0",
					"ua4": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Edg/120.0.0.0",
					"ua5": "curl/8.4.0 (Android)"
				}
			}
		]
	}`)
	doc2 := sim2["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if doc2["@timestamp"] != "2025-05-15" || doc2["f2"] != "NA" {
		t.Fatalf("expected @timestamp=2025-05-15 and f2=NA, got %v", doc2)
	}
}

func TestRound15_BulkSameIDVersionFloorArrayPromotionBeyond16AndReindex(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Bulk with 18 docs where doc #18 introduces an array on a field that was scalar in docs 1..17,
	// plus same-_id index -> delete -> create -> update in one batch.
	var sb strings.Builder
	for i := 1; i <= 17; i++ {
		_, _ = fmt.Fprintf(&sb, "{\"index\":{\"_index\":\"r15_bulk_idx\",\"_id\":\"%d\"}}\n", i)
		_, _ = fmt.Fprintf(&sb, "{\"tag\":\"scalar_%d\",\"val\":%d}\n", i, i)
	}
	sb.WriteString("{\"index\":{\"_index\":\"r15_bulk_idx\",\"_id\":\"18\"}}\n")
	sb.WriteString("{\"tag\":[\"arr_a\",\"arr_b\"],\"val\":18}\n")
	// Same-_id sequence on id "1": delete -> create -> update
	sb.WriteString("{\"delete\":{\"_index\":\"r15_bulk_idx\",\"_id\":\"1\"}}\n")
	sb.WriteString("{\"create\":{\"_index\":\"r15_bulk_idx\",\"_id\":\"1\"}}\n")
	sb.WriteString("{\"tag\":\"recreated\",\"val\":100}\n")
	sb.WriteString("{\"update\":{\"_index\":\"r15_bulk_idx\",\"_id\":\"1\"}}\n")
	sb.WriteString("{\"script\":{\"source\":\"ctx._source.val += 50\"}}\n")

	bulkRes := doJSON(t, srv, http.MethodPost, "/_bulk?refresh=true", sb.String())
	if bulkRes["errors"].(bool) {
		t.Fatalf("expected bulk errors=false, got %v", bulkRes)
	}

	// Verify doc 1 has val=150 and doc 18 matches term tag=arr_b
	doc1 := doJSON(t, srv, http.MethodGet, "/r15_bulk_idx/_doc/1", "")
	if doc1["_source"].(map[string]any)["val"].(float64) != 150 {
		t.Fatalf("expected doc 1 val=150 after same-batch delete->create->update, got %v", doc1)
	}
	arrSearch := doJSON(t, srv, http.MethodPost, "/r15_bulk_idx/_search", `{"query":{"term":{"tag":"arr_b"}}}`)
	if int(arrSearch["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)) != 1 {
		t.Fatalf("expected doc 18 array promotion beyond 16 sample docs to match tag=arr_b, got %v", arrSearch)
	}

	// 2. Reindex with top-level size, source._source filter, and ctx._id mutation
	reidx := doJSON(t, srv, http.MethodPost, "/_reindex", `{
		"size": 2,
		"source": {
			"index": "r15_bulk_idx",
			"_source": ["val"]
		},
		"dest": {
			"index": "r15_reindexed"
		},
		"script": {
			"source": "ctx._id = 'new_' + ctx._id"
		}
	}`)
	if int(reidx["created"].(float64)) != 2 {
		t.Fatalf("expected reindex created=2 with top-level size=2, got %v", reidx)
	}
	newDoc := doJSON(t, srv, http.MethodGet, "/r15_reindexed/_doc/new_1", "")
	newSrc := newDoc["_source"].(map[string]any)
	if _, hasTag := newSrc["tag"]; hasTag || newSrc["val"].(float64) != 150 {
		t.Fatalf("expected reindexed new_1 to have only filtered _source val=150, got %v", newSrc)
	}
}

func TestRound15_TopologicalSiblingPipelineAggsAndEmptyStatsBucket(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r15_pipe_idx", `{"mappings":{"properties":{"k":{"type":"keyword"},"v":{"type":"integer"}}}}`)
	doJSON(t, srv, http.MethodPut, "/r15_pipe_idx/_doc/1", `{"k":"a","v":10}`)
	doJSON(t, srv, http.MethodPut, "/r15_pipe_idx/_doc/2", `{"k":"b","v":20}`)

	res := doJSON(t, srv, http.MethodPost, "/r15_pipe_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_k": {
				"terms": {"field": "k"},
				"aggs": {
					"sum_v": {"sum": {"field": "v"}}
				}
			},
			"empty_filter": {
				"terms": {"field": "k", "include": "nonexistent"},
				"aggs": {
					"sum_v": {"sum": {"field": "v"}}
				}
			},
			"empty_stats": {
				"stats_bucket": {"buckets_path": "empty_filter>sum_v"}
			},
			"valid_stats": {
				"stats_bucket": {"buckets_path": "by_k>sum_v"}
			}
		}
	}`)
	aggs := res["aggregations"].(map[string]any)
	emptyStats := aggs["empty_stats"].(map[string]any)
	if emptyStats["min"] != nil || emptyStats["max"] != nil || emptyStats["avg"] != nil {
		t.Fatalf("expected empty stats_bucket to have min=nil, max=nil, avg=nil, got %v", emptyStats)
	}
	validStats := aggs["valid_stats"].(map[string]any)
	if validStats["avg"].(float64) != 15.0 {
		t.Fatalf("expected valid_stats avg=15.0, got %v", validStats)
	}
}

func TestRound15_RegexpCaseInsensitiveAndDoris4SearchFunc(t *testing.T) {
	sch := schema.CompileIndexSchema("es_compat", "r15_re", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"host": {Type: "keyword"},
			"tags": {Type: "keyword", MultiValued: true},
		},
	})
	tr := transpiler.NewTranspiler(sch, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})

	rePlan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{
			Regexp: map[string]esast.RegexpEntry{"host": {Value: "web-[0-9]+", CaseInsensitive: true}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSearchPlan regexp: %v", err)
	}
	if strings.Contains(rePlan.HitsSQL, "MATCH_REGEXP") || !strings.Contains(rePlan.HitsSQL, "REGEXP '(?i)web-[0-9]+'") {
		t.Fatalf("expected case-insensitive regexp to use REGEXP '(?i)...' instead of MATCH_REGEXP, got %s", rePlan.HitsSQL)
	}

	// Doris 4.0 SEARCH() should be used on scalar string host, but NOT on array column tags
	qsHostPlan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{
			QueryString: &esast.QueryStringQuery{Query: "host:prod AND host:us"},
		},
	})
	if err != nil || !strings.Contains(qsHostPlan.HitsSQL, "SEARCH(") {
		t.Fatalf("expected Doris 4.0 SEARCH() on scalar string host, got %s (err=%v)", qsHostPlan.HitsSQL, err)
	}
	qsArrPlan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{
			QueryString: &esast.QueryStringQuery{Query: "tags:prod AND tags:us"},
		},
	})
	if err != nil || strings.Contains(qsArrPlan.HitsSQL, "SEARCH(") {
		t.Fatalf("expected Doris 4.0 SEARCH() NOT to be emitted on ARRAY<STRING> column tags, got %s", qsArrPlan.HitsSQL)
	}
}
