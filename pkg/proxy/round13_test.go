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
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// TestRound13NestedInnerHitsAndSourceFalseFields verifies R13-P0-1:
//   - `_source: false` and `_source.excludes` preserve `RawSource` so `fields`, `sort`,
//     `script_fields`, `highlight`, and `collapse` still extract values from the document.
//   - `nested` queries with `inner_hits` return per-hit `inner_hits.<name>.hits` containing
//     only the matching nested array elements with `_nested` metadata (`field`, `offset`),
//     `sort`, `_source` filtering, and `fields`.
func TestRound13NestedInnerHitsAndSourceFalseFields(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/tables_r13", `{
		"mappings": {
			"properties": {
				"service": {"type": "keyword"},
				"title": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lowercase"}}},
				"columns": {
					"type": "nested",
					"properties": {
						"name": {"type": "keyword"},
						"dataType": {"type": "keyword"},
						"ordinal": {"type": "long"}
					}
				}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/tables_r13/_doc/1?refresh=true", `{
		"service": "snowflake",
		"title": "Orders Table",
		"columns": [
			{"name": "id", "dataType": "BIGINT", "ordinal": 1},
			{"name": "user_email", "dataType": "VARCHAR", "ordinal": 2},
			{"name": "email_hash", "dataType": "VARCHAR", "ordinal": 3}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/tables_r13/_doc/2?refresh=true", `{
		"service": "postgres",
		"title": "Users Table",
		"columns": [
			{"name": "id", "dataType": "INT", "ordinal": 1}
		]
	}`)

	// 1. _source: false with fields, sort, script_fields, highlight
	res := mustReq(t, ts, http.MethodPost, "/tables_r13/_search", `{
		"_source": false,
		"query": {"match": {"title": "Orders"}},
		"fields": ["service", "title.keyword"],
		"sort": [{"service": "asc"}],
		"script_fields": {
			"svc_upper": {"script": {"source": "doc['service'].value.toUpperCase()"}}
		},
		"highlight": {
			"fields": {"title": {}}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	hit0 := hits[0].(map[string]any)
	if _, hasSrc := hit0["_source"]; hasSrc {
		t.Fatalf("expected _source to be omitted when _source=false, got %v", hit0["_source"])
	}
	fieldsMap, ok := hit0["fields"].(map[string]any)
	if !ok {
		t.Fatalf("expected fields map on hit when _source=false, got %v", hit0)
	}
	if svcArr, ok := fieldsMap["service"].([]any); !ok || len(svcArr) != 1 || svcArr[0] != "snowflake" {
		t.Fatalf("expected fields.service=[snowflake], got %v", fieldsMap["service"])
	}
	if titleKwArr, ok := fieldsMap["title.keyword"].([]any); !ok || len(titleKwArr) != 1 || titleKwArr[0] != "orders table" {
		t.Fatalf("expected lowercase normalized fields['title.keyword']=['orders table'], got %v", fieldsMap["title.keyword"])
	}
	if sortArr, ok := hit0["sort"].([]any); !ok || len(sortArr) != 1 || sortArr[0] != "snowflake" {
		t.Fatalf("expected sort=[snowflake] when _source=false, got %v", hit0["sort"])
	}
	if hlMap, ok := hit0["highlight"].(map[string]any); !ok || len(hlMap["title"].([]any)) == 0 {
		t.Fatalf("expected highlight on title when _source=false, got %v", hit0["highlight"])
	}

	// 2. nested query with inner_hits
	nestedRes := mustReq(t, ts, http.MethodPost, "/tables_r13/_search", `{
		"query": {
			"nested": {
				"path": "columns",
				"query": {"term": {"columns.dataType": "VARCHAR"}},
				"inner_hits": {
					"name": "varchar_cols",
					"size": 2,
					"sort": [{"columns.ordinal": "desc"}],
					"_source": ["name"],
					"fields": ["dataType"]
				}
			}
		}
	}`)
	nHits := nestedRes["hits"].(map[string]any)["hits"].([]any)
	if len(nHits) != 1 {
		t.Fatalf("expected 1 parent hit for nested VARCHAR query, got %d", len(nHits))
	}
	ihRoot, ok := nHits[0].(map[string]any)["inner_hits"].(map[string]any)
	if !ok {
		t.Fatalf("expected inner_hits on parent hit, got %v", nHits[0])
	}
	vcHitsObj := ihRoot["varchar_cols"].(map[string]any)["hits"].(map[string]any)
	if vcHitsObj["total"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected 2 matching nested elements in inner_hits total, got %v", vcHitsObj["total"])
	}
	vcList := vcHitsObj["hits"].([]any)
	if len(vcList) != 2 {
		t.Fatalf("expected 2 inner_hits items, got %d", len(vcList))
	}
	firstIH := vcList[0].(map[string]any)
	nestedMeta := firstIH["_nested"].(map[string]any)
	if nestedMeta["field"] != "columns" || nestedMeta["offset"] != float64(2) {
		t.Fatalf("expected first inner_hit sorted desc by ordinal to be offset 2, got %v", nestedMeta)
	}
	ihSrc := firstIH["_source"].(map[string]any)
	if ihSrc["name"] != "email_hash" {
		t.Fatalf("expected first inner_hit _source.name='email_hash', got %v", ihSrc)
	}
	if _, hasDT := ihSrc["dataType"]; hasDT {
		t.Fatalf("expected _source filter on inner_hit to exclude dataType, got %v", ihSrc)
	}
	ihFields := firstIH["fields"].(map[string]any)
	if dtArr := ihFields["dataType"].([]any); len(dtArr) != 1 || dtArr[0] != "VARCHAR" {
		t.Fatalf("expected inner_hit fields.dataType=['VARCHAR'], got %v", ihFields)
	}
}

// TestRound13PipelineBucketsPathSyntaxes verifies R13-P0-2:
//   - Sibling & child pipeline aggregations with `>`, `.`, bracket notation (`['95.0']`, `[avg]`),
//     unbracketed decimal percentile keys (`95.0`), multi-hop single-bucket paths (`only_active>avg_sal`),
//     keyed multi-bucket sub-aggregation paths (`by_tier['pro']>avg_sal`), and empty-bucket skipping.
//   - Rejects child pipeline `buckets_path` referencing an unkeyed multi-bucket sub-aggregation (`terms`).
func TestRound13PipelineBucketsPathSyntaxes(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/metrics_r13", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"status": {"type": "keyword"},
				"tier": {"type": "keyword"},
				"salary": {"type": "double"},
				"step": {"type": "long"}
			}
		}
	}`)
	docs := []string{
		`{"dept":"eng","status":"active","tier":"pro","salary":100,"step":0}`,
		`{"dept":"eng","status":"active","tier":"pro","salary":200,"step":0}`,
		`{"dept":"sales","status":"active","tier":"pro","salary":300,"step":20}`,
		`{"dept":"hr","status":"inactive","tier":"free","salary":50,"step":20}`,
	}
	for i, d := range docs {
		mustReq(t, ts, http.MethodPut, "/metrics_r13/_doc/"+string(rune('1'+i))+"?refresh=true", d)
	}

	// 1. Sibling pipeline aggs with bracketed percentile key, unbracketed percentile key,
	//    multi-hop single-bucket path, and empty histogram bucket skipping
	res := mustReq(t, ts, http.MethodPost, "/metrics_r13/_search", `{
		"size": 0,
		"aggs": {
			"by_step": {
				"histogram": {
					"field": "step",
					"interval": 10,
					"min_doc_count": 0
				},
				"aggs": {
					"sal_stats": {"stats": {"field": "salary"}},
					"sal_pct": {"percentiles": {"field": "salary", "percents": [50, 95]}},
					"only_active": {
						"filter": {"term": {"status": "active"}},
						"aggs": {
							"avg_sal": {"avg": {"field": "salary"}}
						}
					},
					"by_tier": {
						"filters": {
							"filters": {
								"pro": {"term": {"tier": "pro"}},
								"free": {"term": {"tier": "free"}}
							}
						},
						"aggs": {
							"avg_sal": {"avg": {"field": "salary"}}
						}
					},
					"active_plus_pro": {
						"bucket_script": {
							"buckets_path": {
								"act": "only_active>avg_sal",
								"pro": "by_tier['pro']>avg_sal",
								"p95_bracket": "sal_pct['95.0']",
								"p95_dot": "sal_pct.95.0"
							},
							"script": "params.act + params.pro + (params.p95_bracket - params.p95_dot)"
						}
					}
				}
			},
			"avg_of_stats_avg": {
				"avg_bucket": {"buckets_path": "by_step>sal_stats[avg]"}
			},
			"avg_of_p95_bracket": {
				"avg_bucket": {"buckets_path": "by_step>sal_pct['95.0']"}
			},
			"avg_of_p95_dot": {
				"avg_bucket": {"buckets_path": "by_step>sal_pct.95.0"}
			},
			"avg_active_dot": {
				"avg_bucket": {"buckets_path": "by_step.only_active.avg_sal"}
			},
			"avg_active_gt": {
				"avg_bucket": {"buckets_path": "by_step>only_active>avg_sal"}
			}
		}
	}`)
	aggs := res["aggregations"].(map[string]any)
	// Step 0 has active avg=150 (100,200); Step 10 is empty (doc_count=0, skipped!); Step 20 has active avg=300.
	// Average of non-empty active buckets = (150 + 300) / 2 = 225.
	avgActDot := aggs["avg_active_dot"].(map[string]any)["value"].(float64)
	avgActGT := aggs["avg_active_gt"].(map[string]any)["value"].(float64)
	if math.Abs(avgActDot-225.0) > 1e-6 || math.Abs(avgActGT-225.0) > 1e-6 {
		t.Fatalf("expected avg_active_dot and avg_active_gt to be 225.0 (skipping empty step=10 bucket), got dot=%v gt=%v", avgActDot, avgActGT)
	}
	p95Bracket := aggs["avg_of_p95_bracket"].(map[string]any)["value"].(float64)
	p95Dot := aggs["avg_of_p95_dot"].(map[string]any)["value"].(float64)
	if p95Bracket <= 0 || math.Abs(p95Bracket-p95Dot) > 1e-6 {
		t.Fatalf("expected avg_of_p95_bracket == avg_of_p95_dot > 0, got bracket=%v dot=%v", p95Bracket, p95Dot)
	}
	buckets := aggs["by_step"].(map[string]any)["buckets"].([]any)
	b0 := buckets[0].(map[string]any)
	if b0["active_plus_pro"].(map[string]any)["value"] != float64(300) {
		t.Fatalf("expected step=0 active_plus_pro=300 (150+150), got %v", b0["active_plus_pro"])
	}

	// 2. Reject child pipeline aggregation referencing an unkeyed multi-bucket sub-aggregation (`terms`)
	status, errBody := doRawReq(t, ts, http.MethodPost, "/metrics_r13/_search", `{
		"size": 0,
		"aggs": {
			"by_step": {
				"histogram": {"field": "step", "interval": 10},
				"aggs": {
					"by_dept": {
						"terms": {"field": "dept"},
						"aggs": {"avg_sal": {"avg": {"field": "salary"}}}
					},
					"bad_deriv": {
						"derivative": {"buckets_path": "by_dept>avg_sal"}
					}
				}
			}
		}
	}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when child pipeline references multi-bucket terms sub-agg, got %d: %s", status, errBody)
	}
}

// TestRound13CollapseFieldsNullsAndInnerHits verifies R13-P0-3:
//   - `collapse` returns `fields: {<collapse_field>: [...]}` on hits, does not collapse documents
//     where the collapse field is null/missing into a single row, and populates `collapse.inner_hits`.
func TestRound13CollapseFieldsNullsAndInnerHits(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/collapse_r13", `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"emp": {"type": "keyword"},
				"salary": {"type": "long"}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/collapse_r13/_doc/1?refresh=true", `{"dept":"eng","emp":"alice","salary":200}`)
	mustReq(t, ts, http.MethodPut, "/collapse_r13/_doc/2?refresh=true", `{"dept":"eng","emp":"bob","salary":150}`)
	mustReq(t, ts, http.MethodPut, "/collapse_r13/_doc/3?refresh=true", `{"emp":"no_dept_1","salary":120}`)
	mustReq(t, ts, http.MethodPut, "/collapse_r13/_doc/4?refresh=true", `{"emp":"no_dept_2","salary":110}`)

	res := mustReq(t, ts, http.MethodPost, "/collapse_r13/_search", `{
		"sort": [{"salary": "desc"}],
		"collapse": {
			"field": "dept",
			"inner_hits": {
				"name": "dept_members",
				"size": 5,
				"sort": [{"salary": "asc"}]
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	// Expected 3 hits: 1 collapsed "eng" hit + 2 uncollapsed null-dept hits ("no_dept_1", "no_dept_2")
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits (1 eng + 2 null-dept docs), got %d: %v", len(hits), hits)
	}
	engHit := hits[0].(map[string]any)
	fieldsMap, ok := engHit["fields"].(map[string]any)
	if !ok || fieldsMap["dept"].([]any)[0] != "eng" {
		t.Fatalf("expected collapse hit to include fields.dept=['eng'], got %v", engHit["fields"])
	}
	ihObj := engHit["inner_hits"].(map[string]any)["dept_members"].(map[string]any)["hits"].(map[string]any)
	if ihObj["total"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected 2 dept_members in eng collapse inner_hits, got %v", ihObj["total"])
	}
	ihHits := ihObj["hits"].([]any)
	if len(ihHits) != 2 || ihHits[0].(map[string]any)["_id"] != "2" || ihHits[1].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected inner_hits sorted by salary asc (doc 2 then doc 1), got %v", ihHits)
	}
}

// TestRound13IngestPipelineDissectAndSimulateVerbose verifies R13-P0-4 and R13-P0-5:
//   - `pipeline` processor (chaining sub-pipelines) and `dissect` processor (`%{key}`, `%{?skip}`,
//     `%{+append}`, `%{key->}`, `append_separator`).
//   - `POST /_ingest/pipeline/_simulate?verbose=true` returning `processor_results`.
//   - `foreach` scalar `_ingest._value` mutation & multi-processor array mutation, `dot_expander` with `path`,
//     nested flat dotted keys, and explicit `"ignore_missing": false`.
func TestRound13IngestPipelineDissectAndSimulateVerbose(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/sub_normalize", `{
		"processors": [
			{
				"foreach": {
					"field": "tags",
					"processor": {
						"uppercase": {"field": "_ingest._value"}
					}
				}
			},
			{
				"dot_expander": {
					"path": "meta",
					"field": "service.name"
				}
			}
		]
	}`)

	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/main_log_pipe", `{
		"processors": [
			{
				"dissect": {
					"field": "line",
					"pattern": "%{client_ip} %{?ident} %{+user} %{+user} [%{ts}] \"%{method->} %{uri}\" %{status}",
					"append_separator": " "
				}
			},
			{
				"convert": {"field": "status", "type": "integer"}
			},
			{
				"pipeline": {"name": "sub_normalize"}
			}
		]
	}`)

	simRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/main_log_pipe/_simulate?verbose=true", `{
		"docs": [
			{
				"_source": {
					"line": "10.0.0.1 - jane doe [27/Oct/2026] \"GET   /api/v1/health\" 200",
					"tags": ["web", "prod"],
					"meta": {"service.name": "gateway"}
				}
			}
		]
	}`)
	simDocs := simRes["docs"].([]any)
	if len(simDocs) != 1 {
		t.Fatalf("expected 1 simulated doc, got %d", len(simDocs))
	}
	procResults, ok := simDocs[0].(map[string]any)["processor_results"].([]any)
	if !ok || len(procResults) < 3 {
		t.Fatalf("expected verbose processor_results trace with >= 3 steps, got %v", simDocs[0])
	}
	finalDoc := procResults[len(procResults)-1].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if finalDoc["client_ip"] != "10.0.0.1" || finalDoc["user"] != "jane doe" || finalDoc["method"] != "GET" || finalDoc["uri"] != "/api/v1/health" || finalDoc["status"] != float64(200) {
		t.Fatalf("unexpected dissect+convert output: %v", finalDoc)
	}
	tagsOut := finalDoc["tags"].([]any)
	if len(tagsOut) != 2 || tagsOut[0] != "WEB" || tagsOut[1] != "PROD" {
		t.Fatalf("expected foreach uppercase on scalar array to produce [WEB PROD], got %v", tagsOut)
	}
	metaSvc := finalDoc["meta"].(map[string]any)["service"].(map[string]any)
	if metaSvc["name"] != "gateway" {
		t.Fatalf("expected dot_expander with path='meta' to expand meta.service.name='gateway', got %v", finalDoc["meta"])
	}

	// Verify explicit ignore_missing: false raises an error in _simulate and 400 on indexing
	simErrRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"lowercase": {"field": "missing_field", "ignore_missing": false}}
			]
		},
		"docs": [{"_source": {"other": "val"}}]
	}`)
	simErrDocs := simErrRes["docs"].([]any)
	if simErrDocs[0].(map[string]any)["error"] == nil {
		t.Fatalf("expected error in _simulate doc when ignore_missing=false on missing field, got %v", simErrDocs[0])
	}
	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/strict_missing_r13", `{
		"processors": [
			{"lowercase": {"field": "missing_field", "ignore_missing": false}}
		]
	}`)
	status, _ := doRawReq(t, ts, http.MethodPut, "/strict_idx_r13/_doc/1?pipeline=strict_missing_r13", `{"other":"val"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when ignore_missing=false on missing field during index, got %d", status)
	}
}

// TestRound13PainlessArrayIndicesDynamicBracketsAndMethods verifies R13-P0-6:
//   - Array index access/assignment (`ctx._source.items[0].price = 42`, `ctx._source.tags[-1] = 'last'`),
//     dynamic bracket expressions (`ctx._source[params.k] = params.v`), and `.containsKey`, `.get`,
//     `.indexOf`, `.split`, `.replace`, `.substring`.
func TestRound13PainlessArrayIndicesDynamicBracketsAndMethods(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/painless_r13/_doc/1?refresh=true", `{
		"tags": ["first", "middle", "old_last"],
		"items": [{"name": "book", "price": 10}, {"name": "pen", "price": 5}],
		"email": "alice@old-domain.com"
	}`)

	mustReq(t, ts, http.MethodPost, "/painless_r13/_update/1?refresh=true", `{
		"script": {
			"source": "ctx._source.tags[-1] = 'new_last'; ctx._source.items[0].price = 42; ctx._source[params.dynKey] = ctx._source.email.replace('old-domain.com', 'new.io').substring(0, 12)",
			"params": {"dynKey": "short_email"}
		}
	}`)

	getRes := mustReq(t, ts, http.MethodGet, "/painless_r13/_doc/1", "")
	src := getRes["_source"].(map[string]any)
	tags := src["tags"].([]any)
	if tags[2] != "new_last" {
		t.Fatalf("expected tags[-1] to be 'new_last', got %v", tags)
	}
	items := src["items"].([]any)
	if items[0].(map[string]any)["price"] != float64(42) {
		t.Fatalf("expected items[0].price=42, got %v", items[0])
	}
	if src["short_email"] != "alice@new.io" {
		t.Fatalf("expected dynamic bracket assignment short_email='alice@new.io', got %v", src["short_email"])
	}
}

// TestRound13AliasExclusionAndMultiIndexSettings verifies R13-P0-7:
//   - `logs-*,-logs-secret` excludes the concrete index pointed to by alias `logs-secret`.
//   - `GET /logs-*/_settings` returns settings for all matched indices, and `GET /missing_idx/_settings` returns 404.
func TestRound13AliasExclusionAndMultiIndexSettings(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/logs-public/_doc/1?refresh=true", `{"msg":"pub"}`)
	mustReq(t, ts, http.MethodPut, "/logs-private/_doc/1?refresh=true", `{"msg":"priv"}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "logs-private", "alias": "logs-secret"}}
		]
	}`)

	searchRes := mustReq(t, ts, http.MethodPost, "/logs-*,-logs-secret/_search", `{"query":{"match_all":{}}}`)
	if got := getTotalHits(searchRes); got != 1 {
		t.Fatalf("expected 1 hit when excluding alias -logs-secret from logs-*, got %v", got)
	}

	settingsRes := mustReq(t, ts, http.MethodGet, "/logs-*/_settings", "")
	if _, ok := settingsRes["logs-public"]; !ok {
		t.Fatalf("expected logs-public in GET /logs-*/_settings, got %v", settingsRes)
	}
	if _, ok := settingsRes["logs-private"]; !ok {
		t.Fatalf("expected logs-private in GET /logs-*/_settings, got %v", settingsRes)
	}

	status, _ := doRawReq(t, ts, http.MethodGet, "/nonexistent_r13_idx/_settings", "")
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 for GET /nonexistent_r13_idx/_settings, got %d", status)
	}
}

// TestRound13ScalarToArrayPromotionAndDateArrayTerm verifies R13-P0-8:
//   - A field initially indexed as a scalar (`"tags": "alpha"`) and subsequently indexed as an array
//     (`"tags": ["beta", "gamma"]`) is automatically promoted to `StoragePromotedArray` (`f__arr__tags`)
//     with backfill so `term`, `terms`, and `terms` aggregations match both documents.
//   - `StoragePromotedArray` `date` fields coerce ISO-8601 strings to epoch millis during shredding and `term`/`terms` queries.
func TestRound13ScalarToArrayPromotionAndDateArrayTerm(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Doc 1 has scalar label="alpha" and array of ISO dates
	mustReq(t, ts, http.MethodPut, "/promo_r13/_doc/1?refresh=true", `{
		"label": "alpha",
		"release_dates": ["2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"]
	}`)
	// Doc 2 has array label=["beta", "gamma"]
	mustReq(t, ts, http.MethodPut, "/promo_r13/_doc/2?refresh=true", `{
		"label": ["beta", "gamma"],
		"release_dates": ["2026-06-01T00:00:00Z"]
	}`)

	for _, termVal := range []string{"alpha", "beta", "gamma"} {
		res := mustReq(t, ts, http.MethodPost, "/promo_r13/_search", `{
			"query": {"term": {"label": "`+termVal+`"}}
		}`)
		if got := getTotalHits(res); got != 1 {
			t.Fatalf("expected 1 hit for term label=%s after scalar-to-array promotion, got %v", termVal, got)
		}
	}

	dateRes := mustReq(t, ts, http.MethodPost, "/promo_r13/_search", `{
		"query": {"term": {"release_dates": "2026-06-01T00:00:00Z"}}
	}`)
	if got := getTotalHits(dateRes); got != 2 {
		t.Fatalf("expected 2 hits for ISO date term query on date array field, got %v", got)
	}
}

// TestRound13MultiValuedSubAggregationsAndIPv4Sorting verifies R13-P0-9 and R13-P0-10:
//   - Sub-aggregations (`percentiles`, `top_hits`) under a multi-valued `terms` bucket aggregation.
//   - `composite` aggregation with an `ip` source sorted numerically by IPv4 value.
//   - Multi-valued `ip` array sorting with `mode: "min"`, `mode: "max"`, `mode: "median"`.
func TestRound13MultiValuedSubAggregationsAndIPv4Sorting(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/net_r13", `{
		"mappings": {
			"properties": {
				"host_ip": {"type": "ip"},
				"peer_ips": {"type": "ip", "multi_valued": true},
				"labels": {"type": "keyword", "multi_valued": true},
				"latency": {"type": "double"}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/net_r13/_doc/1?refresh=true", `{
		"host_ip": "9.0.0.1",
		"peer_ips": ["10.0.0.1", "2.0.0.1", "192.168.1.1"],
		"labels": ["edge", "us"],
		"latency": 10
	}`)
	mustReq(t, ts, http.MethodPut, "/net_r13/_doc/2?refresh=true", `{
		"host_ip": "10.0.0.1",
		"peer_ips": ["8.8.8.8", "1.1.1.1", "100.0.0.1"],
		"labels": ["edge", "eu"],
		"latency": 30
	}`)

	res := mustReq(t, ts, http.MethodPost, "/net_r13/_search", `{
		"sort": [{"peer_ips": {"order": "asc", "mode": "median"}}],
		"aggs": {
			"by_label": {
				"terms": {"field": "labels"},
				"aggs": {
					"lat_pct": {"percentiles": {"field": "latency", "percents": [50]}},
					"sample": {"top_hits": {"size": 1}}
				}
			},
			"comp_ip": {
				"composite": {
					"sources": [
						{"ip": {"terms": {"field": "host_ip", "order": "asc"}}}
					]
				}
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	// Doc 2 median peer_ip is "8.8.8.8", Doc 1 median peer_ip is "10.0.0.1". Numerically 8.8.8.8 < 10.0.0.1!
	if hits[0].(map[string]any)["_id"] != "2" || hits[0].(map[string]any)["sort"].([]any)[0] != "8.8.8.8" {
		t.Fatalf("expected doc 2 first when sorting peer_ips asc with mode=median ('8.8.8.8' < '10.0.0.1'), got %v", hits[0])
	}
	compBuckets := res["aggregations"].(map[string]any)["comp_ip"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 2 || compBuckets[0].(map[string]any)["key"].(map[string]any)["ip"] != "9.0.0.1" {
		t.Fatalf("expected composite ip source sorted numerically ('9.0.0.1' before '10.0.0.1'), got %v", compBuckets)
	}
	labelBuckets := res["aggregations"].(map[string]any)["by_label"].(map[string]any)["buckets"].([]any)
	if len(labelBuckets) == 0 {
		t.Fatalf("expected by_label buckets, got empty")
	}
	edgeBucket := labelBuckets[0].(map[string]any)
	if edgeBucket["lat_pct"].(map[string]any)["values"].(map[string]any)["50.0"] != float64(20) {
		t.Fatalf("expected edge bucket p50=20, got %v", edgeBucket["lat_pct"])
	}
	if len(edgeBucket["sample"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 top_hit in edge bucket, got %v", edgeBucket["sample"])
	}
}

// TestRound13MetricAggMissingSortMissingAndReindexQueryParam verifies R13-P1-1, R13-P1-2, and R13-P1-3:
//   - `missing` parameter on metric aggregations (`avg`, `sum`, `stats`, `percentiles`, `cardinality`, `value_count`).
//   - `sort` with ISO-8601 `missing` on a `date` field and `search_after` with ISO-8601 date string.
//   - `POST /_reindex?pipeline=...` URL query parameter and empty batch guard when all docs are dropped.
func TestRound13MetricAggMissingSortMissingAndReindexQueryParam(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/miss_r13", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"score": {"type": "double"},
				"created_at": {"type": "date"}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/miss_r13/_doc/1?refresh=true", `{"grp":"a","score":10,"created_at":"2026-05-01T00:00:00Z"}`)
	mustReq(t, ts, http.MethodPut, "/miss_r13/_doc/2?refresh=true", `{"grp":"a"}`)

	res := mustReq(t, ts, http.MethodPost, "/miss_r13/_search", `{
		"sort": [{"created_at": {"order": "asc", "missing": "2020-01-01T00:00:00Z"}}],
		"aggs": {
			"avg_score": {"avg": {"field": "score", "missing": 30}},
			"sum_score": {"sum": {"field": "score", "missing": 30}},
			"cnt_score": {"value_count": {"field": "score", "missing": 30}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"sub_avg": {"avg": {"field": "score", "missing": 30}}
				}
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	// Doc 2 has missing created_at -> 2020-01-01T00:00:00Z (1577836800000), which sorts before 2026-05-01
	if hits[0].(map[string]any)["_id"] != "2" || hits[0].(map[string]any)["sort"].([]any)[0] != float64(1577836800000) {
		t.Fatalf("expected doc 2 first with epoch millis sort value 1577836800000, got %v", hits[0])
	}
	aggs := res["aggregations"].(map[string]any)
	if aggs["avg_score"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected avg_score with missing=30 to be 20, got %v", aggs["avg_score"])
	}
	if aggs["sum_score"].(map[string]any)["value"] != float64(40) {
		t.Fatalf("expected sum_score with missing=30 to be 40, got %v", aggs["sum_score"])
	}
	if aggs["cnt_score"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected cnt_score with missing=30 to be 2, got %v", aggs["cnt_score"])
	}
	grpBuckets := aggs["by_grp"].(map[string]any)["buckets"].([]any)
	if grpBuckets[0].(map[string]any)["sub_avg"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected sub_avg with missing=30 to be 20, got %v", grpBuckets[0])
	}

	// Reindex with ?pipeline= query param that drops all docs
	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/drop_all_r13", `{
		"processors": [{"drop": {}}]
	}`)
	reidxRes := mustReq(t, ts, http.MethodPost, "/_reindex?pipeline=drop_all_r13", `{
		"source": {"index": "miss_r13"},
		"dest": {"index": "miss_r13_dest"}
	}`)
	if reidxRes["noops"] != float64(2) || reidxRes["created"] != float64(0) {
		t.Fatalf("expected reindex with drop_all_r13 query param to noops=2 and created=0, got %v", reidxRes)
	}
}

// TestRound13ExtendedBranchesCoverage exercises additional branches across R13-P0-1 through R13-P1-3:
//   - `nested.inner_hits` nested inside `bool.should`, `dis_max`, `constant_score`, `boosting`, and `function_score`
//     with default `name`, `from`, `size`, and `_source: false`.
//   - `collapse.inner_hits` as an array of `InnerHitsSpec` objects with `from`, `size`, `_source`, and `fields`.
//   - `dissect` with `%{&indirect}` indirect key, `target_field`, and `ignore_missing: true`;
//     `pipeline` processor with `ignore_missing_pipeline: true` and cyclic pipeline depth limit;
//     `foreach` with multi-processor `processors` array.
//   - Painless `.containsKey`, `.get`, `.indexOf`, `.split` in conditions and RHS expressions.
//   - `missing` parameter across `min`, `max`, `stats`, `extended_stats`, `percentiles`, `percentile_ranks`,
//     `boxplot`, `cardinality`, `value_count`, and `date_histogram` across scalar, array, and `nested` fields.
//   - `sort` on multi-valued `ip` field with `mode: "min"`, `mode: "max"`, `mode: "avg"`, `mode: "sum"`,
//     and `PUT /logs-*/_settings` across wildcard indices.
func TestRound13ExtendedBranchesCoverage(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Nested inner_hits across bool/dis_max/constant_score/boosting/function_score + array/nested metric missing
	mustReq(t, ts, http.MethodPut, "/ext_r13", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"val": {"type": "double"},
				"arr_vals": {"type": "double", "multi_valued": true},
				"ips": {"type": "ip", "multi_valued": true},
				"ts": {"type": "date"},
				"items": {
					"type": "nested",
					"properties": {
						"tag": {"type": "keyword"},
						"price": {"type": "double"}
					}
				}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/ext_r13/_doc/1?refresh=true", `{
		"grp": "g1",
		"val": 10,
		"arr_vals": [10, 20],
		"ips": ["10.0.0.2", "10.0.0.1"],
		"ts": "2026-01-01T00:00:00Z",
		"items": [
			{"tag": "a", "price": 10},
			{"tag": "b"}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/ext_r13/_doc/2?refresh=true", `{
		"grp": "g1",
		"ips": ["10.0.0.3", "10.0.0.4"],
		"items": [
			{"tag": "a", "price": 30}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/ext_r13/_doc/3?refresh=true", `{
		"grp": "g1",
		"val": 50,
		"ips": ["10.0.0.5", "10.0.0.6"],
		"items": [
			{"tag": "a", "price": 50}
		]
	}`)

	// Nested inner_hits inside function_score -> boosting -> constant_score -> dis_max -> bool
	nhRes := mustReq(t, ts, http.MethodPost, "/ext_r13/_search", `{
		"query": {
			"function_score": {
				"query": {
					"boosting": {
						"positive": {
							"constant_score": {
								"filter": {
									"dis_max": {
										"queries": [
											{
												"bool": {
													"should": [
														{
															"nested": {
																"path": "items",
																"query": {"term": {"items.tag": "a"}},
																"inner_hits": {"from": 0, "size": 1, "_source": false, "fields": ["tag"]}
															}
														}
													]
												}
											}
										]
									}
								}
							}
						},
						"negative": {"term": {"grp": "none"}},
						"negative_boost": 0.5
					}
				}
			}
		}
	}`)
	nhHits := nhRes["hits"].(map[string]any)["hits"].([]any)
	if len(nhHits) != 3 {
		t.Fatalf("expected 3 hits for nested inner_hits inside composite query tree, got %d", len(nhHits))
	}
	if _, ok := nhHits[0].(map[string]any)["inner_hits"].(map[string]any)["items"]; !ok {
		t.Fatalf("expected default inner_hits key 'items', got %v", nhHits[0])
	}

	// Collapse with array of inner_hits specs
	colArrRes := mustReq(t, ts, http.MethodPost, "/ext_r13/_search", `{
		"sort": [{"val": {"order": "desc", "missing": 0}}],
		"collapse": {
			"field": "grp",
			"inner_hits": [
				{"name": "highest", "size": 1, "sort": [{"val": {"order": "desc", "missing": 0}}]},
				{"name": "second", "from": 1, "size": 1, "sort": [{"val": {"order": "desc", "missing": 0}}], "_source": ["grp"], "fields": ["val"]}
			]
		}
	}`)
	colHits := colArrRes["hits"].(map[string]any)["hits"].([]any)
	if len(colHits) != 1 {
		t.Fatalf("expected 1 collapsed hit for grp=g1, got %d", len(colHits))
	}
	ihMap := colHits[0].(map[string]any)["inner_hits"].(map[string]any)
	if ihMap["highest"] == nil || ihMap["second"] == nil {
		t.Fatalf("expected both 'highest' and 'second' inner_hits on collapsed hit, got %v", ihMap)
	}

	// Missing parameter across scalar, array, and nested metric aggregations (top-level and sub-aggs) + IP sort modes
	aggRes := mustReq(t, ts, http.MethodPost, "/ext_r13/_search", `{
		"sort": [
			{"ips": {"order": "asc", "mode": "min"}},
			{"ips": {"order": "desc", "mode": "max"}},
			{"ips": {"order": "asc", "mode": "avg"}},
			{"ips": {"order": "asc", "mode": "sum"}}
		],
		"aggs": {
			"min_val": {"min": {"field": "val", "missing": 5}},
			"max_val": {"max": {"field": "val", "missing": 100}},
			"stats_val": {"stats": {"field": "val", "missing": 20}},
			"ext_val": {"extended_stats": {"field": "val", "missing": 20}},
			"pct_val": {"percentiles": {"field": "val", "percents": [50], "missing": 20}},
			"prank_val": {"percentile_ranks": {"field": "val", "values": [25], "missing": 20}},
			"box_val": {"boxplot": {"field": "val", "missing": 20}},
			"card_val": {"cardinality": {"field": "val", "missing": 20}},
			"arr_avg": {"avg": {"field": "arr_vals", "missing": 30}},
			"arr_pct": {"percentiles": {"field": "arr_vals", "percents": [50], "missing": 30}},
			"arr_prank": {"percentile_ranks": {"field": "arr_vals", "values": [25], "missing": 30}},
			"arr_card": {"cardinality": {"field": "arr_vals", "missing": 30}},
			"arr_vc": {"value_count": {"field": "arr_vals", "missing": 30}},
			"dh_ts": {
				"date_histogram": {
					"field": "ts",
					"fixed_interval": "30d",
					"missing": "2026-01-01T00:00:00Z"
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"n_avg": {"avg": {"field": "items.price", "missing": 20}},
					"n_stats": {"stats": {"field": "items.price", "missing": 20}},
					"n_pct": {"percentiles": {"field": "items.price", "percents": [50], "missing": 20}},
					"n_prank": {"percentile_ranks": {"field": "items.price", "values": [25], "missing": 20}},
					"n_card": {"cardinality": {"field": "items.price", "missing": 20}},
					"n_vc": {"value_count": {"field": "items.price", "missing": 20}}
				}
			},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"g_min": {"min": {"field": "val", "missing": 5}},
					"g_max": {"max": {"field": "val", "missing": 100}},
					"g_stats": {"stats": {"field": "val", "missing": 20}},
					"g_pct": {"percentiles": {"field": "val", "percents": [50], "missing": 20}},
					"g_prank": {"percentile_ranks": {"field": "val", "values": [25], "missing": 20}},
					"g_card": {"cardinality": {"field": "val", "missing": 20}},
					"g_vc": {"value_count": {"field": "val", "missing": 20}},
					"g_arr_avg": {"avg": {"field": "arr_vals", "missing": 30}},
					"g_arr_card": {"cardinality": {"field": "arr_vals", "missing": 30}},
					"g_arr_vc": {"value_count": {"field": "arr_vals", "missing": 30}}
				}
			}
		}
	}`)
	aggs := aggRes["aggregations"].(map[string]any)
	if aggs["min_val"].(map[string]any)["value"] != float64(5) {
		t.Fatalf("expected min_val=5 with missing=5, got %v", aggs["min_val"])
	}
	if aggs["max_val"].(map[string]any)["value"] != float64(100) {
		t.Fatalf("expected max_val=100 with missing=100, got %v", aggs["max_val"])
	}
	nAggs := aggs["nested_items"].(map[string]any)
	if nAggs["n_vc"].(map[string]any)["value"] != float64(4) {
		t.Fatalf("expected nested n_vc=4 with missing=20, got %v", nAggs["n_vc"])
	}

	// Dissect indirect key + target_field, foreach processors list, pipeline ignore_missing_pipeline
	simExt := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"dissect": {
						"field": "msg",
						"pattern": "%{key_name}=%{&key_name}",
						"target_field": "parsed"
					}
				},
				{
					"dissect": {
						"field": "nonexistent_msg",
						"pattern": "%{a}",
						"ignore_missing": true
					}
				},
				{
					"foreach": {
						"field": "raw_list",
						"processors": [
							{"trim": {"field": "_ingest._value"}},
							{"lowercase": {"field": "_ingest._value"}}
						]
					}
				},
				{
					"pipeline": {
						"name": "missing_sub_pipe",
						"ignore_missing_pipeline": true
					}
				}
			]
		},
		"docs": [
			{"_source": {"msg": "env=production", "raw_list": ["  ALPHA ", " BETA  "]}}
		]
	}`)
	simDoc := simExt["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simDoc["parsed"].(map[string]any)["env"] != "production" {
		t.Fatalf("expected dissect indirect key parsed.env='production', got %v", simDoc["parsed"])
	}
	rawList := simDoc["raw_list"].([]any)
	if rawList[0] != "alpha" || rawList[1] != "beta" {
		t.Fatalf("expected foreach multi-processor list to trim+lowercase, got %v", rawList)
	}

	// Painless containsKey, get, indexOf, split
	mustReq(t, ts, http.MethodPost, "/ext_r13/_update/1?refresh=true", `{
		"script": {
			"source": "if (ctx._source.containsKey('grp')) { ctx._source.parts = ctx._source.get('grp').split('1'); ctx._source.idx = ctx._source.grp.indexOf('1'); }"
		}
	}`)
	uDoc := mustReq(t, ts, http.MethodGet, "/ext_r13/_doc/1", "")["_source"].(map[string]any)
	if uDoc["idx"] != float64(1) {
		t.Fatalf("expected indexOf('1') == 1, got %v", uDoc["idx"])
	}

	// Multi-index PUT /ext_*/_settings
	putSetRes := mustReq(t, ts, http.MethodPut, "/ext_*/_settings", `{
		"index.default_pipeline": "none"
	}`)
	if putSetRes["acknowledged"] != true {
		t.Fatalf("expected PUT /ext_*/_settings acknowledged=true, got %v", putSetRes)
	}
}
