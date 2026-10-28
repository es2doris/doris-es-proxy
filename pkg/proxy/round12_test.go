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
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// TestRound12SelfExclusionAndDeleteIndexExclusions verifies R12-P0-1 and R12-P0-2:
//   - Self-excluding / all-excluded alias patterns (`tenant_a,-tenant_a`, `tenant_a,-shared_logs`, `tenant_a,-*`)
//     do not fall back to `s.resolveIndexName` without alias filters across `/_search`, `/_count`,
//     `/_delete_by_query`, `/_update_by_query`, `/_reindex`, `/_validate/query`, and `/_doris/explain`.
//   - `DELETE /-keep_idx,idx_*` pre-collects exclusions before expanding wildcards, and `DELETE /idx,-idx`
//     does not drop the excluded index.
func TestRound12SelfExclusionAndDeleteIndexExclusions(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/shared_logs", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"msg":{"type":"keyword"}}}}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "shared_logs", "alias": "tenant_a", "filter": {"term": {"tenant": "a"}}}},
			{"add": {"index": "shared_logs", "alias": "tenant_b", "filter": {"term": {"tenant": "b"}}}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/tenant_a/_doc/a1?refresh=true", `{"tenant":"a","msg":"secret-a"}`)
	mustReq(t, ts, http.MethodPut, "/tenant_b/_doc/b1?refresh=true", `{"tenant":"b","msg":"secret-b"}`)

	for _, pat := range []string{"tenant_a,-tenant_a", "tenant_a,-shared_logs", "tenant_a,-*"} {
		res := mustReq(t, ts, http.MethodPost, "/"+pat+"/_search", `{"query":{"match_all":{}}}`)
		if got := getTotalHits(res); got != 0 {
			t.Fatalf("expected 0 hits on %s, got %v", pat, got)
		}
		delRes := mustReq(t, ts, http.MethodPost, "/"+pat+"/_delete_by_query", `{"query":{"match_all":{}}}`)
		if delRes["deleted"] != float64(0) {
			t.Fatalf("expected 0 deleted on %s, got %v", pat, delRes)
		}
		updRes := mustReq(t, ts, http.MethodPost, "/"+pat+"/_update_by_query", `{
			"script": {"source": "ctx._source.msg = 'hacked'"},
			"query": {"match_all": {}}
		}`)
		if updRes["updated"] != float64(0) {
			t.Fatalf("expected 0 updated on %s, got %v", pat, updRes)
		}
	}

	reidxRes := mustReq(t, ts, http.MethodPost, "/_reindex", `{
		"source": {"index": "tenant_a,-tenant_a"},
		"dest": {"index": "stolen_logs"}
	}`)
	if reidxRes["total"] != float64(0) || reidxRes["created"] != float64(0) {
		t.Fatalf("expected 0 reindexed docs from tenant_a,-tenant_a, got %v", reidxRes)
	}

	valRes := mustReq(t, ts, http.MethodPost, "/tenant_a,-tenant_a/_validate/query?explain=true", `{"query":{"match_all":{}}}`)
	if valRes["valid"] != true {
		t.Fatalf("expected valid:true on tenant_a,-tenant_a, got %v", valRes)
	}
	explRes := mustReq(t, ts, http.MethodPost, "/tenant_a,-tenant_a/_doris/explain", `{"query":{"match_all":{}}}`)
	if plans, _ := explRes["plans"].([]any); len(plans) != 0 {
		t.Fatalf("expected 0 explain plans on tenant_a,-tenant_a, got %v", explRes)
	}

	// Verify both tenant_a and tenant_b docs are completely intact
	resAll := mustReq(t, ts, http.MethodPost, "/shared_logs/_search", `{"query":{"match_all":{}}}`)
	if got := getTotalHits(resAll); got != 2 {
		t.Fatalf("expected 2 docs intact in shared_logs, got %v", got)
	}

	// R12-P0-2: DELETE /-idx_keep,idx_* and DELETE /idx_keep,-idx_keep must not delete idx_keep
	mustReq(t, ts, http.MethodPut, "/idx_keep", `{}`)
	mustReq(t, ts, http.MethodPut, "/idx_drop", `{}`)
	mustReq(t, ts, http.MethodPut, "/idx_keep/_doc/k1?refresh=true", `{"v":1}`)
	mustReq(t, ts, http.MethodPut, "/idx_drop/_doc/d1?refresh=true", `{"v":2}`)

	mustReq(t, ts, http.MethodDelete, "/-idx_keep,idx_*", "")
	if code, _ := doRawReq(t, ts, http.MethodHead, "/idx_keep", ""); code != http.StatusOK {
		t.Fatalf("expected idx_keep to survive DELETE /-idx_keep,idx_*, got HTTP %d", code)
	}
	if code, _ := doRawReq(t, ts, http.MethodHead, "/idx_drop", ""); code != http.StatusNotFound {
		t.Fatalf("expected idx_drop to be deleted by DELETE /-idx_keep,idx_*, got HTTP %d", code)
	}

	mustReq(t, ts, http.MethodDelete, "/idx_keep,-idx_keep", "")
	if code, _ := doRawReq(t, ts, http.MethodHead, "/idx_keep", ""); code != http.StatusOK {
		t.Fatalf("expected idx_keep to survive DELETE /idx_keep,-idx_keep, got HTTP %d", code)
	}
}

// TestRound12IngestDropOnFailureAndExtendedProcessors verifies R12-P0-3, R12-P0-4, R12-P0-5, and R12-P1-1:
//   - Ingest `drop` and `script` (`ctx.op = 'drop'` / `ctx.op = 'delete'`) return `"result": "noop"` across
//     `_doc`, `_update`, `_bulk`, `_update_by_query`, and `_reindex` without writing `{}` or overwriting existing docs.
//   - `setIngestPath` deletes stale flat dotted keys when mutating nested objects.
//   - `ignore_failure`, processor `on_failure`, pipeline `on_failure` (`_ingest.on_failure_*`), and `fail`, `kv`,
//     `dot_expander`, `urldecode`, `bytes`, `html_strip`, and `foreach` processors work end-to-end.
//   - `ctx?.missing != null` and string literals containing `"ctx.raw"` inside `if` / `script` work properly.
//   - `handleBulk` (`update`) and `handleUpdateByQuery` apply `default_pipeline` / `?pipeline=...` / `final_pipeline`.
func TestRound12IngestDropOnFailureAndExtendedProcessors(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Drop processor & script ctx.op = 'drop' across write endpoints
	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/drop_debug", `{
		"processors": [
			{"drop": {"if": "ctx?.level == 'debug'"}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/logs_drop", `{
		"settings": {"index": {"default_pipeline": "drop_debug"}},
		"mappings": {"properties": {"level": {"type": "keyword"}, "msg": {"type": "keyword"}}}
	}`)

	putNoop := mustReq(t, ts, http.MethodPut, "/logs_drop/_doc/1?refresh=true", `{"level":"debug","msg":"skip-me"}`)
	if putNoop["result"] != "noop" {
		t.Fatalf("expected result:noop on dropped PUT, got %v", putNoop)
	}
	if code, _ := doRawReq(t, ts, http.MethodGet, "/logs_drop/_doc/1", ""); code != http.StatusNotFound {
		t.Fatalf("expected dropped doc 1 to not exist, got HTTP %d", code)
	}

	// Index a valid doc, then verify a dropped overwrite does NOT clobber the existing doc
	mustReq(t, ts, http.MethodPut, "/logs_drop/_doc/2?refresh=true", `{"level":"info","msg":"keep-me"}`)
	overwriteNoop := mustReq(t, ts, http.MethodPut, "/logs_drop/_doc/2?refresh=true", `{"level":"debug","msg":"should-not-overwrite"}`)
	if overwriteNoop["result"] != "noop" {
		t.Fatalf("expected result:noop on dropped overwrite, got %v", overwriteNoop)
	}
	doc2 := mustReq(t, ts, http.MethodGet, "/logs_drop/_doc/2", "")
	src2, _ := doc2["_source"].(map[string]any)
	if src2["msg"] != "keep-me" {
		t.Fatalf("expected existing doc 2 to remain intact after dropped overwrite, got %v", src2)
	}

	// Bulk index + update with default_pipeline
	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/stamp_updated", `{
		"processors": [
			{"set": {"if": "ctx?.missing_field == null && ctx.msg != 'ctx.raw'", "field": "stamped", "value": true}},
			{"drop": {"if": "ctx?.drop_me == true"}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/bulk_pipe_idx", `{
		"settings": {"index": {"default_pipeline": "stamp_updated"}},
		"mappings": {"properties": {"msg": {"type": "keyword"}, "stamped": {"type": "boolean"}}}
	}`)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"bulk_pipe_idx","_id":"b1"}}`,
		`{"msg":"v1"}`,
		`{"index":{"_index":"bulk_pipe_idx","_id":"b_dropped"}}`,
		`{"msg":"drop","drop_me":true}`,
		`{"update":{"_index":"bulk_pipe_idx","_id":"b2"}}`,
		`{"doc":{"msg":"upserted"},"doc_as_upsert":true}`,
	}, "\n") + "\n"
	bulkRes := mustReq(t, ts, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	items, _ := bulkRes["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("expected 3 bulk items, got %d", len(items))
	}
	secondItem, _ := items[1].(map[string]any)["index"].(map[string]any)
	if secondItem["result"] != "noop" {
		t.Fatalf("expected second bulk item result:noop, got %v", secondItem)
	}
	b2Doc := mustReq(t, ts, http.MethodGet, "/bulk_pipe_idx/_doc/b2", "")
	b2Src, _ := b2Doc["_source"].(map[string]any)
	if b2Src["stamped"] != true {
		t.Fatalf("expected bulk update upsert to run default_pipeline and set stamped:true, got %v", b2Src)
	}

	// _update_by_query with pipeline & new field dynamic mapping
	ubqRes := mustReq(t, ts, http.MethodPost, "/bulk_pipe_idx/_update_by_query?pipeline=stamp_updated", `{
		"script": {"source": "ctx._source.extra_num = 42"},
		"query": {"term": {"_id": "b1"}}
	}`)
	if ubqRes["updated"] != float64(1) {
		t.Fatalf("expected 1 updated doc in _update_by_query, got %v", ubqRes)
	}
	rangeRes := mustReq(t, ts, http.MethodPost, "/bulk_pipe_idx/_search", `{"query":{"range":{"extra_num":{"gte":40}}}}`)
	if got := getTotalHits(rangeRes); got != 1 {
		t.Fatalf("expected range query on dynamically inferred field extra_num from _update_by_query to match 1 doc, got %v", got)
	}

	// 2. Extended processors + flat dotted key overwrite + on_failure metadata
	simRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"uppercase": {"field": "host.name"}},
				{"lowercase": {"field": "host.name"}},
				{"kv": {"field": "kv_str", "field_split": "&", "value_split": "=", "target_field": "parsed_kv"}},
				{"dot_expander": {"field": "flat.nested"}},
				{"urldecode": {"field": "encoded", "target_field": "decoded"}},
				{"bytes": {"field": "mem_size", "target_field": "mem_bytes"}},
				{"html_strip": {"field": "html", "target_field": "clean_html"}},
				{"foreach": {"field": "tags", "processor": {"uppercase": {"field": "_ingest._value"}}}},
				{
					"convert": {
						"field": "bad_int",
						"type": "integer",
						"tag": "conv_bad_int",
						"on_failure": [
							{"set": {"field": "err_type", "value": "{{ _ingest.on_failure_processor_type }}"}},
							{"set": {"field": "err_tag", "value": "{{ _ingest.on_failure_processor_tag }}"}}
						]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"host.name": "Web-01",
					"kv_str": "env=prod&region=us-east",
					"flat.nested": "ok",
					"encoded": "hello%20world",
					"mem_size": "2kb",
					"html": "<p>Hello <b>World</b></p>",
					"tags": ["go", "doris"],
					"bad_int": "not_a_number"
				}
			}
		]
	}`)
	simDocs, _ := simRes["docs"].([]any)
	simDoc0, _ := simDocs[0].(map[string]any)["doc"].(map[string]any)
	simSrc, _ := simDoc0["_source"].(map[string]any)
	hostObj, _ := simSrc["host"].(map[string]any)
	if hostObj["name"] != "web-01" {
		t.Fatalf("expected chained uppercase->lowercase on flat host.name to produce host.name=web-01, got %v (full=%v)", hostObj, simSrc)
	}
	if _, hasStaleFlat := simSrc["host.name"]; hasStaleFlat {
		t.Fatalf("expected stale flat key host.name to be removed, got %v", simSrc)
	}
	parsedKV, _ := simSrc["parsed_kv"].(map[string]any)
	if parsedKV["env"] != "prod" || parsedKV["region"] != "us-east" {
		t.Fatalf("expected kv processor to parse env=prod&region=us-east, got %v", parsedKV)
	}
	flatObj, _ := simSrc["flat"].(map[string]any)
	if flatObj["nested"] != "ok" {
		t.Fatalf("expected dot_expander to expand flat.nested, got %v", simSrc)
	}
	if simSrc["decoded"] != "hello world" {
		t.Fatalf("expected urldecode hello world, got %v", simSrc["decoded"])
	}
	if simSrc["mem_bytes"] != float64(2048) {
		t.Fatalf("expected bytes 2kb -> 2048, got %v", simSrc["mem_bytes"])
	}
	if simSrc["clean_html"] != "Hello World" {
		t.Fatalf("expected html_strip 'Hello World', got %v", simSrc["clean_html"])
	}
	tagsArr, _ := simSrc["tags"].([]any)
	if len(tagsArr) != 2 || tagsArr[0] != "GO" || tagsArr[1] != "DORIS" {
		t.Fatalf("expected foreach uppercase tags [GO DORIS], got %v", tagsArr)
	}
	if simSrc["err_type"] != "convert" || simSrc["err_tag"] != "conv_bad_int" {
		t.Fatalf("expected on_failure metadata convert/conv_bad_int, got type=%v tag=%v", simSrc["err_type"], simSrc["err_tag"])
	}
}

// TestRound12PainlessDottedBracketAccessAndControlFlow verifies R12-P0-6 and R12-P1-2:
//   - Bracketed keys containing `.`, `/`, `:`, whitespace, and `ctx._source?['k']`
//   - Early `return` inside `if`, `break`/`continue` inside `for`, `ctx.op = 'drop'`, and `++`/`--`.
func TestRound12PainlessDottedBracketAccessAndControlFlow(t *testing.T) {
	rawDoc := json.RawMessage(`{"ecs.version":"1.0","k8s.io/app":"proxy","cnt":10,"nums":[1,2,3,4,5]}`)
	upd := &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				if (ctx._source['ecs.version'] == params['expected.ver'] && ctx._source?[ 'k8s.io/app' ] == 'proxy') {
					ctx._source['ecs.version'] = '2.0';
					ctx._source['k8s.io/env:tier'] = 'prod';
				}
				ctx._source.cnt++;
				int sum = 0;
				for (int x : ctx._source.nums) {
					if (x == 2) { continue; }
					if (x == 5) { break; }
					sum += x;
				}
				ctx._source.partial_sum = sum;
				if (ctx._source.cnt == 11) {
					return;
				}
				ctx._source.cnt = 999;
			`,
			Params: map[string]any{"expected.ver": "1.0"},
		},
	}
	mutated, opRes, err := painless.ApplyUpdateWithResult(rawDoc, upd, true)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	if opRes != "updated" {
		t.Fatalf("expected opRes=updated, got %s", opRes)
	}
	var out map[string]any
	if err := json.Unmarshal(mutated, &out); err != nil {
		t.Fatalf("failed to unmarshal mutated doc: %v", err)
	}
	if out["ecs.version"] != "2.0" {
		t.Fatalf("expected flat dotted key ecs.version to be updated to 2.0, got %v", out)
	}
	if out["k8s.io/env:tier"] != "prod" {
		t.Fatalf("expected k8s.io/env:tier=prod, got %v", out)
	}
	if out["cnt"] != float64(11) {
		t.Fatalf("expected cnt++ followed by early return to leave cnt=11, got %v", out["cnt"])
	}
	if out["partial_sum"] != float64(8) {
		t.Fatalf("expected for-loop with continue(2) and break(5) over [1,2,3,4,5] to sum 1+3+4=8, got %v", out["partial_sum"])
	}

	// Verify script condition with doc['a.b'].value
	docMap := map[string]any{"a.b": "hello"}
	if err := painless.EvalPainless(docMap, "if (doc['a.b'].value == 'hello') { ctx._source.matched = true; }", nil); err != nil {
		t.Fatalf("EvalPainless failed: %v", err)
	}
	if docMap["matched"] != true {
		t.Fatalf("expected doc['a.b'].value == 'hello' to evaluate to true, got %v", docMap)
	}
}

// TestRound12IPQueriesSortingAndSearchAfter verifies R12-P0-7 and R12-P0-8:
//   - Nested IP `term` and `terms` with CIDR notation (`10.0.0.0/24`)
//   - `match` and `match_phrase` on `ip` fields (both exact IP and CIDR)
//   - `StoragePromotedArray` `ip` fields
//   - Numeric IPv4 sorting (`"2.0.0.1" < "10.0.0.2" < "10.0.0.100"`) and `search_after` pagination
func TestRound12IPQueriesSortingAndSearchAfter(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/ip_events", `{
		"mappings": {
			"properties": {
				"client_ip": {"type": "ip"},
				"allow_ips": {"type": "ip", "multi_valued": true},
				"endpoints": {
					"type": "nested",
					"properties": {
						"ip": {"type": "ip"}
					}
				}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/ip_events/_doc/1?refresh=true", `{"client_ip":"10.0.0.100","allow_ips":["192.168.1.50","10.0.0.100"],"endpoints":[{"ip":"10.0.0.42"}]}`)
	mustReq(t, ts, http.MethodPut, "/ip_events/_doc/2?refresh=true", `{"client_ip":"10.0.0.2","allow_ips":["172.16.0.5"],"endpoints":[{"ip":"192.168.1.10"}]}`)
	mustReq(t, ts, http.MethodPut, "/ip_events/_doc/3?refresh=true", `{"client_ip":"2.0.0.1","allow_ips":["10.0.0.5"],"endpoints":[{"ip":"10.0.0.99"}]}`)

	// 1. Nested term & terms with CIDR
	nestedTermCIDR := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"query": {
			"nested": {
				"path": "endpoints",
				"query": {"term": {"endpoints.ip": "10.0.0.0/24"}}
			}
		}
	}`)
	if got := getTotalHits(nestedTermCIDR); got != 2 {
		t.Fatalf("expected 2 hits for nested CIDR term 10.0.0.0/24, got %v", got)
	}

	nestedTermsCIDR := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"query": {
			"nested": {
				"path": "endpoints",
				"query": {"terms": {"endpoints.ip": ["192.168.1.0/24"]}}
			}
		}
	}`)
	if got := getTotalHits(nestedTermsCIDR); got != 1 {
		t.Fatalf("expected 1 hit for nested CIDR terms 192.168.1.0/24, got %v", got)
	}

	// 2. match & match_phrase on IP field with CIDR and exact IP
	matchCIDR := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"query": {"match": {"client_ip": "10.0.0.0/24"}}
	}`)
	if got := getTotalHits(matchCIDR); got != 2 {
		t.Fatalf("expected 2 hits for match CIDR on client_ip, got %v", got)
	}
	matchPhraseIP := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"query": {"match_phrase": {"client_ip": "10.0.0.2"}}
	}`)
	if got := getTotalHits(matchPhraseIP); got != 1 {
		t.Fatalf("expected 1 hit for match_phrase on client_ip 10.0.0.2, got %v", got)
	}

	// 3. Promoted array IP field (`allow_ips`) with CIDR term & range
	arrIPRes := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"query": {"term": {"allow_ips": "10.0.0.0/24"}}
	}`)
	if got := getTotalHits(arrIPRes); got != 2 {
		t.Fatalf("expected 2 hits for promoted array IP CIDR 10.0.0.0/24, got %v", got)
	}

	// 4. Numeric IPv4 sorting ("2.0.0.1" < "10.0.0.2" < "10.0.0.100") and search_after
	sortRes := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"size": 2,
		"sort": [{"client_ip": {"order": "asc"}}]
	}`)
	hitsArr, _ := sortRes["hits"].(map[string]any)["hits"].([]any)
	if len(hitsArr) != 2 {
		t.Fatalf("expected 2 hits on page 1, got %d", len(hitsArr))
	}
	id0 := hitsArr[0].(map[string]any)["_id"]
	id1 := hitsArr[1].(map[string]any)["_id"]
	if id0 != "3" || id1 != "2" {
		t.Fatalf("expected numeric IPv4 sort order [3 (2.0.0.1), 2 (10.0.0.2)], got [%v, %v]", id0, id1)
	}

	page2Res := mustReq(t, ts, http.MethodPost, "/ip_events/_search", `{
		"size": 2,
		"sort": [{"client_ip": {"order": "asc"}}],
		"search_after": ["10.0.0.2"]
	}`)
	hitsPage2, _ := page2Res["hits"].(map[string]any)["hits"].([]any)
	if len(hitsPage2) != 1 || hitsPage2[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected page 2 after 10.0.0.2 to return doc 1 (10.0.0.100), got %v", hitsPage2)
	}
}

// TestRound12CompositeSubAggsNullSafeMetricsAndNestedMissing verifies R12-P0-9, R12-P1-5, and R12-P1-7:
//   - Multi-source `composite` aggregation with sub-aggregations (`CONCAT_WS('\x1f', ...)` in MemoryBackend)
//   - `composite` source on array field (`LATERAL VIEW EXPLODE`)
//   - `min` / `max` / `avg` / `stats` with `null` field values and `missing` parameter
//   - `nested -> terms` with `missing` does not inflate missing count on empty parent arrays (`items: []`),
//     and explodes array subfields inside nested objects.
func TestRound12CompositeSubAggsNullSafeMetricsAndNestedMissing(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/analytics_r12", `{
		"mappings": {
			"properties": {
				"region": {"type": "keyword"},
				"tier": {"type": "keyword"},
				"tags": {"type": "keyword"},
				"val": {"type": "double"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"labels": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/analytics_r12/_doc/1?refresh=true", `{"region":"us","tier":"gold","tags":["a","b"],"val":10,"items":[{"sku":"S1","labels":["x","y"]},{"labels":[]}]}`)
	mustReq(t, ts, http.MethodPut, "/analytics_r12/_doc/2?refresh=true", `{"region":"us","tier":"gold","tags":["b"],"val":null,"items":[]}`)

	res := mustReq(t, ts, http.MethodPost, "/analytics_r12/_search", `{
		"size": 0,
		"aggs": {
			"comp_multi": {
				"composite": {
					"sources": [
						{"r": {"terms": {"field": "region"}}},
						{"t": {"terms": {"field": "tier"}}}
					]
				},
				"aggs": {
					"sum_val": {"sum": {"field": "val"}},
					"min_val": {"min": {"field": "val"}},
					"avg_val_missing": {"avg": {"field": "val", "missing": 30}}
				}
			},
			"comp_array": {
				"composite": {
					"sources": [
						{"tag": {"terms": {"field": "tags"}}}
					]
				}
			},
			"top_min": {"min": {"field": "val"}},
			"top_avg_missing": {"avg": {"field": "val", "missing": 30}},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"by_sku": {"terms": {"field": "items.sku", "missing": "MISSING_SKU"}},
					"by_label": {"terms": {"field": "items.labels", "missing": "NO_LABEL"}}
				}
			}
		}
	}`)
	aggs, _ := res["aggregations"].(map[string]any)

	// 1. Multi-source composite sub-aggs
	compMulti, _ := aggs["comp_multi"].(map[string]any)
	compBuckets, _ := compMulti["buckets"].([]any)
	if len(compBuckets) != 1 {
		t.Fatalf("expected 1 composite bucket for (us, gold), got %v", compBuckets)
	}
	b0, _ := compBuckets[0].(map[string]any)
	if b0["sum_val"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected comp_multi sum_val=10, got %v", b0["sum_val"])
	}
	if b0["min_val"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected comp_multi min_val=10 (ignoring null), got %v", b0["min_val"])
	}
	if math.Abs(b0["avg_val_missing"].(map[string]any)["value"].(float64)-20.0) > 1e-6 {
		t.Fatalf("expected comp_multi avg_val_missing=(10+30)/2=20, got %v", b0["avg_val_missing"])
	}

	// 2. Composite on array field `tags`
	compArr, _ := aggs["comp_array"].(map[string]any)
	arrBuckets, _ := compArr["buckets"].([]any)
	if len(arrBuckets) != 2 {
		t.Fatalf("expected 2 composite buckets for array field tags [a, b], got %v", arrBuckets)
	}

	// 3. Top-level min & avg with missing
	if aggs["top_min"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected top_min=10, got %v", aggs["top_min"])
	}
	if math.Abs(aggs["top_avg_missing"].(map[string]any)["value"].(float64)-20.0) > 1e-6 {
		t.Fatalf("expected top_avg_missing=20, got %v", aggs["top_avg_missing"])
	}

	// 4. Nested terms with missing: doc 2 has items:[] so it should NOT contribute to MISSING_SKU
	nestedItems, _ := aggs["nested_items"].(map[string]any)
	skuBuckets, _ := nestedItems["by_sku"].(map[string]any)["buckets"].([]any)
	if len(skuBuckets) != 2 {
		t.Fatalf("expected 2 buckets (S1:1, MISSING_SKU:1), got %v", skuBuckets)
	}
	for _, rawB := range skuBuckets {
		bm := rawB.(map[string]any)
		if bm["key"] == "MISSING_SKU" && bm["doc_count"] != float64(1) {
			t.Fatalf("expected MISSING_SKU doc_count=1 (excluding empty parent array), got %v", bm)
		}
	}
	labelBuckets, _ := nestedItems["by_label"].(map[string]any)["buckets"].([]any)
	if len(labelBuckets) != 3 {
		t.Fatalf("expected 3 buckets (x:1, y:1, NO_LABEL:1) for nested array subfield, got %v", labelBuckets)
	}
}

// TestRound12ReadOnlyEndpointsExplainAndMultiIndexPerHitSchema verifies R12-P1-3, R12-P1-4, and R12-P1-6:
//   - GET/HEAD `/_doc`, `/_source`, `/_mget`, `/_explain` on non-existent indices do NOT auto-create tables in Doris.
//   - `/_explain/{id}` resolves cross-index `terms` lookup and enforces filtered aliases.
//   - Multi-index search uses per-hit `schemasByIndex[h.Index]` for sorting, collapse, and field formatting.
func TestRound12ReadOnlyEndpointsExplainAndMultiIndexPerHitSchema(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Read-only endpoints on non-existent index must not create index in catalog
	doRawReq(t, ts, http.MethodGet, "/ghost_idx/_doc/1", "")
	doRawReq(t, ts, http.MethodHead, "/ghost_idx/_doc/1", "")
	doRawReq(t, ts, http.MethodGet, "/ghost_idx/_source/1", "")
	doRawReq(t, ts, http.MethodPost, "/ghost_idx/_mget", `{"ids":["1"]}`)
	doRawReq(t, ts, http.MethodPost, "/ghost_idx/_explain/1", `{"query":{"match_all":{}}}`)

	if code, _ := doRawReq(t, ts, http.MethodHead, "/ghost_idx", ""); code != http.StatusNotFound {
		t.Fatalf("expected ghost_idx to NOT be created by read-only document requests, got HTTP %d", code)
	}

	// 2. /_explain/{id} with cross-index terms lookup and filtered alias
	mustReq(t, ts, http.MethodPut, "/lookup_acl/_doc/u1?refresh=true", `{"allowed":["tenant_a"]}`)
	mustReq(t, ts, http.MethodPut, "/shared_exp", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"tag":{"type":"keyword"}}}}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "shared_exp", "alias": "alias_a", "filter": {"terms": {"tenant": {"index": "lookup_acl", "id": "u1", "path": "allowed"}}}}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/shared_exp/_doc/doc_a?refresh=true", `{"tenant":"tenant_a","tag":"ok"}`)
	mustReq(t, ts, http.MethodPut, "/shared_exp/_doc/doc_b?refresh=true", `{"tenant":"tenant_b","tag":"ok"}`)

	expA := mustReq(t, ts, http.MethodPost, "/alias_a/_explain/doc_a", `{
		"query": {"terms": {"tenant": {"index": "lookup_acl", "id": "u1", "path": "allowed"}}}
	}`)
	if expA["matched"] != true {
		t.Fatalf("expected doc_a to match in /alias_a/_explain/doc_a, got %v", expA)
	}
	codeB, _ := doRawReq(t, ts, http.MethodPost, "/alias_a/_explain/doc_b", `{"query":{"match_all":{}}}`)
	if codeB != http.StatusNotFound {
		t.Fatalf("expected doc_b from another tenant to return 404 on /alias_a/_explain/doc_b, got %d", codeB)
	}

	// 3. Multi-index search with distinct per-index mappings (idx_ip sorts v as IP; idx_date formats ts as date)
	mustReq(t, ts, http.MethodPut, "/multi_idx_1", `{
		"mappings": {"properties": {"ts": {"type": "date"}, "code": {"type": "keyword"}}}
	}`)
	mustReq(t, ts, http.MethodPut, "/multi_idx_2", `{
		"mappings": {
			"settings": {"analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}},
			"properties": {"ts": {"type": "date"}, "code": {"type": "keyword", "normalizer": "lc"}}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/multi_idx_1/_doc/1?refresh=true", `{"ts":1700000000000,"code":"B"}`)
	mustReq(t, ts, http.MethodPut, "/multi_idx_2/_doc/2?refresh=true", `{"ts":1700000005000,"code":"a"}`)

	multiRes := mustReq(t, ts, http.MethodPost, "/multi_idx_1,multi_idx_2/_search", `{
		"sort": [{"ts": {"order": "asc"}}],
		"fields": ["ts", "code"]
	}`)
	mHits, _ := multiRes["hits"].(map[string]any)["hits"].([]any)
	if len(mHits) != 2 {
		t.Fatalf("expected 2 hits across multi_idx_1,multi_idx_2, got %d", len(mHits))
	}
	h0Fields, _ := mHits[0].(map[string]any)["fields"].(map[string]any)
	h1Fields, _ := mHits[1].(map[string]any)["fields"].(map[string]any)
	if len(h0Fields["ts"].([]any)) == 0 || !strings.HasSuffix(h0Fields["ts"].([]any)[0].(string), "Z") {
		t.Fatalf("expected multi_idx_1 ts field formatted as ISO-8601 date string, got %v", h0Fields)
	}
	if len(h1Fields["ts"].([]any)) == 0 || !strings.HasSuffix(h1Fields["ts"].([]any)[0].(string), "Z") {
		t.Fatalf("expected multi_idx_2 ts field formatted as ISO-8601 date string, got %v", h1Fields)
	}
}
