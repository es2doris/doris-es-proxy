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

package sdkconformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type requestHeaderSpyTransportR63 struct {
	base             http.RoundTripper
	mu               sync.Mutex
	contentEncodings []string
	sniffRequests    int
}

func (s *requestHeaderSpyTransportR63) RoundTrip(req *http.Request) (*http.Response, error) {
	ce := req.Header.Get("Content-Encoding")
	isSniff := req.URL != nil && strings.HasPrefix(req.URL.Path, "/_nodes")
	s.mu.Lock()
	if ce != "" {
		s.contentEncodings = append(s.contentEncodings, req.Method+" "+req.URL.Path+":"+ce)
	}
	if isSniff {
		s.sniffRequests++
	}
	s.mu.Unlock()
	return s.base.RoundTrip(req)
}

func assertOKRespR63(t *testing.T, label string, res *esapi.Response, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatalf("%s transport error: %v", label, err)
	}
	var raw []byte
	if res.Body != nil {
		raw, _ = io.ReadAll(res.Body)
		_ = res.Body.Close()
	}
	if res.IsError() {
		t.Fatalf("%s returned error status %s: %s", label, res.Status(), string(raw))
	}
	return raw
}

func mustOKCallR63(t *testing.T, label string, fn func() (*esapi.Response, error)) []byte {
	t.Helper()
	res, err := fn()
	return assertOKRespR63(t, label, res, err)
}

func runRound63SDKConformanceSubtests(
	t *testing.T,
	ctx context.Context,
	targetURL string,
	idx string,
	aliasName string,
	esClient *elasticsearch.Client,
	wireTransport *wireConformanceTransport,
) {
	t.Helper()

	// Round63_01: HEAD Exists (200 & 404), GetSource, SearchShards, Ingest GetPipeline / ProcessorGrok / DeletePipeline
	t.Run("Round63_01_HeadExists_GetSource_SearchShards_And_IngestAdmin", func(t *testing.T) {
		exOK, err := esClient.Exists(idx, "order-1", esClient.Exists.WithContext(ctx))
		assertOKRespR63(t, "Exists(order-1)", exOK, err)

		exMiss, err := esClient.Exists(idx, "nonexistent-doc-404", esClient.Exists.WithContext(ctx))
		if err != nil {
			t.Fatalf("Exists(404) transport error: %v", err)
		}
		if exMiss.Body != nil {
			_ = exMiss.Body.Close()
		}
		if exMiss.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 from Exists(missing), got %d", exMiss.StatusCode)
		}

		srcRaw := mustOKCallR63(t, "GetSource(order-1)", func() (*esapi.Response, error) {
			return esClient.GetSource(idx, "order-1", esClient.GetSource.WithContext(ctx))
		})
		if !strings.Contains(string(srcRaw), "analytics") {
			t.Fatalf("expected GetSource payload to contain category analytics, got %s", string(srcRaw))
		}

		ssRes, err := esClient.SearchShards(
			esClient.SearchShards.WithIndex(idx),
			esClient.SearchShards.WithContext(ctx),
		)
		assertOKRespR63(t, "SearchShards", ssRes, err)

		r63PipeID := fmt.Sprintf("sdk_r63_pipe_%d", time.Now().UnixNano())
		putPRes, err := esClient.Ingest.PutPipeline(
			r63PipeID,
			strings.NewReader(`{"description":"r63 test pipeline","processors":[{"lowercase":{"field":"title"}}]}`),
			esClient.Ingest.PutPipeline.WithContext(ctx),
		)
		assertOKRespR63(t, "Ingest.PutPipeline", putPRes, err)

		getPRes, err := esClient.Ingest.GetPipeline(
			esClient.Ingest.GetPipeline.WithPipelineID(r63PipeID),
			esClient.Ingest.GetPipeline.WithContext(ctx),
		)
		assertOKRespR63(t, "Ingest.GetPipeline", getPRes, err)

		grokRes, err := esClient.Ingest.ProcessorGrok(esClient.Ingest.ProcessorGrok.WithContext(ctx))
		assertOKRespR63(t, "Ingest.ProcessorGrok", grokRes, err)

		delPRes, err := esClient.Ingest.DeletePipeline(
			r63PipeID,
			esClient.Ingest.DeletePipeline.WithContext(ctx),
		)
		assertOKRespR63(t, "Ingest.DeletePipeline", delPRes, err)

		wireTransport.assertNoViolations(t, "Round63_01_HeadExists_GetSource_SearchShards_And_IngestAdmin")
	})

	// Round63_02: Tasks (List, Get, Cancel) & Cluster Admin (State, AllocationExplain, Reroute, PendingTasks, ComponentTemplate Get/Exists)
	t.Run("Round63_02_Tasks_And_ClusterAdmin", func(t *testing.T) {
		// Launch an async UpdateByQuery(wait_for_completion=false) so Tasks.Get validates a real 200 task payload
		ubqAsyncRes, err := esClient.UpdateByQuery(
			[]string{idx},
			esClient.UpdateByQuery.WithWaitForCompletion(false),
			esClient.UpdateByQuery.WithBody(strings.NewReader(`{"query":{"match_all":{}}}`)),
			esClient.UpdateByQuery.WithContext(ctx),
		)
		ubqAsyncRaw := assertOKRespR63(t, "UpdateByQuery(async)", ubqAsyncRes, err)
		var asyncTask struct {
			Task string `json:"task"`
		}
		_ = json.Unmarshal(ubqAsyncRaw, &asyncTask)

		tListRes, err := esClient.Tasks.List(esClient.Tasks.List.WithContext(ctx))
		tListRaw := assertOKRespR63(t, "Tasks.List", tListRes, err)

		taskID := asyncTask.Task
		if taskID == "" {
			var parsedTasks struct {
				Nodes map[string]struct {
					Tasks map[string]any `json:"tasks"`
				} `json:"nodes"`
			}
			if json.Unmarshal(tListRaw, &parsedTasks) == nil {
				for _, n := range parsedTasks.Nodes {
					for tid := range n.Tasks {
						taskID = tid
						break
					}
				}
			}
		}
		if taskID != "" {
			tGetRes, tGetErr := esClient.Tasks.Get(taskID, esClient.Tasks.Get.WithContext(ctx))
			assertOKRespR63(t, "Tasks.Get("+taskID+")", tGetRes, tGetErr)
		} else {
			tGetMiss, tGetErr := esClient.Tasks.Get("doris-fe-1:999999", esClient.Tasks.Get.WithContext(ctx))
			if tGetErr != nil {
				t.Fatalf("Tasks.Get transport error: %v", tGetErr)
			}
			if tGetMiss.Body != nil {
				_ = tGetMiss.Body.Close()
			}
		}

		tCancelRes, err := esClient.Tasks.Cancel(esClient.Tasks.Cancel.WithContext(ctx))
		assertOKRespR63(t, "Tasks.Cancel", tCancelRes, err)

		stRes, err := esClient.Cluster.State(esClient.Cluster.State.WithContext(ctx))
		assertOKRespR63(t, "Cluster.State", stRes, err)

		aeRes, err := esClient.Cluster.AllocationExplain(esClient.Cluster.AllocationExplain.WithContext(ctx))
		if err != nil {
			t.Fatalf("Cluster.AllocationExplain transport error: %v", err)
		}
		if aeRes.Body != nil {
			_, _ = io.ReadAll(aeRes.Body)
			_ = aeRes.Body.Close()
		}

		rrRes, err := esClient.Cluster.Reroute(
			esClient.Cluster.Reroute.WithMetric("none"),
			esClient.Cluster.Reroute.WithBody(strings.NewReader(`{"commands":[]}`)),
			esClient.Cluster.Reroute.WithContext(ctx),
		)
		assertOKRespR63(t, "Cluster.Reroute(metric=none)", rrRes, err)

		ptRes, err := esClient.Cluster.PendingTasks(esClient.Cluster.PendingTasks.WithContext(ctx))
		assertOKRespR63(t, "Cluster.PendingTasks", ptRes, err)

		ctName := fmt.Sprintf("sdk_r63_ct_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Cluster.DeleteComponentTemplate(ctName); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})
		putCTRes, err := esClient.Cluster.PutComponentTemplate(
			ctName,
			strings.NewReader(`{"template":{"mappings":{"properties":{"ct_field":{"type":"keyword"}}}}}`),
			esClient.Cluster.PutComponentTemplate.WithContext(ctx),
		)
		assertOKRespR63(t, "Cluster.PutComponentTemplate", putCTRes, err)

		exCTRes, err := esClient.Cluster.ExistsComponentTemplate(ctName, esClient.Cluster.ExistsComponentTemplate.WithContext(ctx))
		assertOKRespR63(t, "Cluster.ExistsComponentTemplate", exCTRes, err)

		getCTRes, err := esClient.Cluster.GetComponentTemplate(
			esClient.Cluster.GetComponentTemplate.WithName(ctName),
			esClient.Cluster.GetComponentTemplate.WithContext(ctx),
		)
		assertOKRespR63(t, "Cluster.GetComponentTemplate", getCTRes, err)

		wireTransport.assertNoViolations(t, "Round63_02_Tasks_And_ClusterAdmin")
	})

	// Round63_03: Nodes Info (`/_nodes`, `/_nodes/_local/http`), Nodes Usage (`/_nodes/usage`, `/_nodes/_local/usage`), and HotThreads (`text/plain`)
	t.Run("Round63_03_NodesInfo_NodesUsage_And_HotThreads", func(t *testing.T) {
		niRes, err := esClient.Nodes.Info(esClient.Nodes.Info.WithContext(ctx))
		assertOKRespR63(t, "Nodes.Info", niRes, err)

		niLocalRes, err := esClient.Nodes.Info(
			esClient.Nodes.Info.WithNodeID("_local"),
			esClient.Nodes.Info.WithMetric("http", "jvm", "plugins"),
			esClient.Nodes.Info.WithContext(ctx),
		)
		assertOKRespR63(t, "Nodes.Info(_local)", niLocalRes, err)

		nuRes, err := esClient.Nodes.Usage(esClient.Nodes.Usage.WithContext(ctx))
		assertOKRespR63(t, "Nodes.Usage", nuRes, err)

		nuLocalRes, err := esClient.Nodes.Usage(
			esClient.Nodes.Usage.WithNodeID("_local"),
			esClient.Nodes.Usage.WithMetric("rest_actions"),
			esClient.Nodes.Usage.WithContext(ctx),
		)
		assertOKRespR63(t, "Nodes.Usage(_local)", nuLocalRes, err)

		htRes, err := esClient.Nodes.HotThreads(esClient.Nodes.HotThreads.WithContext(ctx))
		htRaw := assertOKRespR63(t, "Nodes.HotThreads", htRes, err)
		if len(htRaw) == 0 {
			t.Fatalf("expected non-empty text/plain output from Nodes.HotThreads")
		}

		wireTransport.assertNoViolations(t, "Round63_03_NodesInfo_NodesUsage_And_HotThreads")
	})

	// Round63_04: Cat Endpoints (both JSON schema-validated and text/plain wire-validated)
	t.Run("Round63_04_CatEndpoints_JSON_And_PlainText", func(t *testing.T) {
		mustOKCallR63(t, "Cat.Nodes(text)", func() (*esapi.Response, error) {
			return esClient.Cat.Nodes(esClient.Cat.Nodes.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Nodes(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Nodes(esClient.Cat.Nodes.WithFormat("json"), esClient.Cat.Nodes.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Shards(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Shards(esClient.Cat.Shards.WithIndex(idx), esClient.Cat.Shards.WithFormat("json"), esClient.Cat.Shards.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Fielddata(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Fielddata(esClient.Cat.Fielddata.WithFormat("json"), esClient.Cat.Fielddata.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Templates(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Templates(esClient.Cat.Templates.WithFormat("json"), esClient.Cat.Templates.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.ThreadPool(json)", func() (*esapi.Response, error) {
			return esClient.Cat.ThreadPool(esClient.Cat.ThreadPool.WithFormat("json"), esClient.Cat.ThreadPool.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Tasks(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Tasks(esClient.Cat.Tasks.WithFormat("json"), esClient.Cat.Tasks.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Recovery(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Recovery(esClient.Cat.Recovery.WithIndex(idx), esClient.Cat.Recovery.WithFormat("json"), esClient.Cat.Recovery.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Master(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Master(esClient.Cat.Master.WithFormat("json"), esClient.Cat.Master.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Plugins(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Plugins(esClient.Cat.Plugins.WithFormat("json"), esClient.Cat.Plugins.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Repositories(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Repositories(esClient.Cat.Repositories.WithFormat("json"), esClient.Cat.Repositories.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.PendingTasks(json)", func() (*esapi.Response, error) {
			return esClient.Cat.PendingTasks(esClient.Cat.PendingTasks.WithFormat("json"), esClient.Cat.PendingTasks.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.Nodeattrs(json)", func() (*esapi.Response, error) {
			return esClient.Cat.Nodeattrs(esClient.Cat.Nodeattrs.WithFormat("json"), esClient.Cat.Nodeattrs.WithContext(ctx))
		})
		mustOKCallR63(t, "Cat.ComponentTemplates(json)", func() (*esapi.Response, error) {
			return esClient.Cat.ComponentTemplates(esClient.Cat.ComponentTemplates.WithFormat("json"), esClient.Cat.ComponentTemplates.WithContext(ctx))
		})

		wireTransport.assertNoViolations(t, "Round63_04_CatEndpoints_JSON_And_PlainText")
	})

	// Round63_05: Indices Get, ExistsAlias, DeleteAlias, Stats, Recovery, Flush, Templates, Shrink, Split, Clone
	t.Run("Round63_05_IndicesLifecycle_Templates_ShrinkSplitClone_And_Flush", func(t *testing.T) {
		mustOKCallR63(t, "Indices.Get", func() (*esapi.Response, error) {
			return esClient.Indices.Get([]string{idx}, esClient.Indices.Get.WithContext(ctx))
		})

		mustOKCallR63(t, "Indices.ExistsAlias", func() (*esapi.Response, error) {
			return esClient.Indices.ExistsAlias([]string{aliasName}, esClient.Indices.ExistsAlias.WithIndex(idx), esClient.Indices.ExistsAlias.WithContext(ctx))
		})

		tmpAlias := idx + "_tmp_alias_r63"
		mustOKCallR63(t, "Indices.PutAlias(tmp)", func() (*esapi.Response, error) {
			return esClient.Indices.PutAlias([]string{idx}, tmpAlias, esClient.Indices.PutAlias.WithContext(ctx))
		})
		mustOKCallR63(t, "Indices.DeleteAlias(tmp)", func() (*esapi.Response, error) {
			return esClient.Indices.DeleteAlias([]string{idx}, []string{tmpAlias}, esClient.Indices.DeleteAlias.WithContext(ctx))
		})

		mustOKCallR63(t, "Indices.Stats(idx)", func() (*esapi.Response, error) {
			return esClient.Indices.Stats(esClient.Indices.Stats.WithIndex(idx), esClient.Indices.Stats.WithContext(ctx))
		})
		mustOKCallR63(t, "Indices.Stats(_all)", func() (*esapi.Response, error) {
			return esClient.Indices.Stats(esClient.Indices.Stats.WithIndex("_all"), esClient.Indices.Stats.WithContext(ctx))
		})

		mustOKCallR63(t, "Indices.Recovery", func() (*esapi.Response, error) {
			return esClient.Indices.Recovery(esClient.Indices.Recovery.WithIndex(idx), esClient.Indices.Recovery.WithContext(ctx))
		})

		mustOKCallR63(t, "Indices.Flush", func() (*esapi.Response, error) {
			return esClient.Indices.Flush(esClient.Indices.Flush.WithIndex(idx), esClient.Indices.Flush.WithContext(ctx))
		})

		// Composable ExistsIndexTemplate + Legacy _template CRUD
		compTpl := fmt.Sprintf("sdk_r63_itpl_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Indices.DeleteIndexTemplate(compTpl); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})
		mustOKCallR63(t, "Indices.PutIndexTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.PutIndexTemplate(
				compTpl,
				strings.NewReader(`{"index_patterns":["sdk-r63-itpl-*"],"template":{"settings":{"number_of_shards":1}}}`),
				esClient.Indices.PutIndexTemplate.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Indices.ExistsIndexTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.ExistsIndexTemplate(compTpl, esClient.Indices.ExistsIndexTemplate.WithContext(ctx))
		})

		legTpl := fmt.Sprintf("sdk_r63_leg_tpl_%d", time.Now().UnixNano())
		mustOKCallR63(t, "Indices.PutTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.PutTemplate(
				legTpl,
				strings.NewReader(`{"index_patterns":["sdk-r63-leg-*"],"settings":{"number_of_shards":1}}`),
				esClient.Indices.PutTemplate.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Indices.ExistsTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.ExistsTemplate([]string{legTpl}, esClient.Indices.ExistsTemplate.WithContext(ctx))
		})
		mustOKCallR63(t, "Indices.GetTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.GetTemplate(esClient.Indices.GetTemplate.WithName(legTpl), esClient.Indices.GetTemplate.WithContext(ctx))
		})
		mustOKCallR63(t, "Indices.DeleteTemplate", func() (*esapi.Response, error) {
			return esClient.Indices.DeleteTemplate(legTpl, esClient.Indices.DeleteTemplate.WithContext(ctx))
		})

		// Shrink, Split, Clone lifecycle on dedicated source index
		srcResizeIdx := fmt.Sprintf("sdk_r63_resize_src_%d", time.Now().UnixNano())
		shrunkIdx := srcResizeIdx + "_shrunk"
		splitIdx := srcResizeIdx + "_split"
		clonedIdx := srcResizeIdx + "_cloned"
		t.Cleanup(func() {
			for _, ti := range []string{srcResizeIdx, shrunkIdx, splitIdx, clonedIdx} {
				if r, e := esClient.Indices.Delete([]string{ti}); e == nil && r != nil {
					_ = r.Body.Close()
				}
			}
		})
		mustOKCallR63(t, "Indices.Create(srcResizeIdx)", func() (*esapi.Response, error) {
			return esClient.Indices.Create(
				srcResizeIdx,
				esClient.Indices.Create.WithBody(strings.NewReader(`{"settings":{"index.number_of_shards":2,"index.blocks.write":true}}`)),
				esClient.Indices.Create.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Indices.Shrink", func() (*esapi.Response, error) {
			return esClient.Indices.Shrink(
				srcResizeIdx,
				shrunkIdx,
				esClient.Indices.Shrink.WithBody(strings.NewReader(`{"settings":{"index.number_of_shards":1,"index.blocks.write":null}}`)),
				esClient.Indices.Shrink.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Indices.Split", func() (*esapi.Response, error) {
			return esClient.Indices.Split(
				srcResizeIdx,
				splitIdx,
				esClient.Indices.Split.WithBody(strings.NewReader(`{"settings":{"index.number_of_shards":4,"index.blocks.write":null}}`)),
				esClient.Indices.Split.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Indices.Clone", func() (*esapi.Response, error) {
			return esClient.Indices.Clone(
				srcResizeIdx,
				clonedIdx,
				esClient.Indices.Clone.WithBody(strings.NewReader(`{"settings":{"index.blocks.write":null}}`)),
				esClient.Indices.Clone.WithContext(ctx),
			)
		})

		wireTransport.assertNoViolations(t, "Round63_05_IndicesLifecycle_Templates_ShrinkSplitClone_And_Flush")
	})

	// Round63_06: SearchMvt Binary Vector Tile (`application/vnd.mapbox-vector-tile`)
	t.Run("Round63_06_SearchMVT_BinaryVectorTile", func(t *testing.T) {
		mvtIdx := fmt.Sprintf("sdk_r63_mvt_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Indices.Delete([]string{mvtIdx}); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})
		mustOKCallR63(t, "Indices.Create(mvtIdx)", func() (*esapi.Response, error) {
			return esClient.Indices.Create(
				mvtIdx,
				esClient.Indices.Create.WithBody(strings.NewReader(`{"mappings":{"properties":{"loc":{"type":"geo_point"}}}}`)),
				esClient.Indices.Create.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Index(mvt doc)", func() (*esapi.Response, error) {
			return esClient.Index(
				mvtIdx,
				strings.NewReader(`{"loc":[-122.4194,37.7749]}`),
				esClient.Index.WithDocumentID("g1"),
				esClient.Index.WithRefresh("true"),
				esClient.Index.WithContext(ctx),
			)
		})

		mvtRes, err := esClient.SearchMvt(
			[]string{mvtIdx},
			"loc",
			intPtr(0),
			intPtr(0),
			intPtr(0),
			esClient.SearchMvt.WithHeader(map[string]string{
				"Accept":          "application/vnd.mapbox-vector-tile",
				"Accept-Encoding": "gzip",
			}),
			esClient.SearchMvt.WithContext(ctx),
		)
		_ = assertOKRespR63(t, "SearchMvt", mvtRes, err)
		if !strings.HasPrefix(strings.ToLower(mvtRes.Header.Get("Content-Type")), "application/vnd.mapbox-vector-tile") {
			t.Fatalf("expected MVT Content-Type, got %q", mvtRes.Header.Get("Content-Type"))
		}
		if ce := mvtRes.Header.Get("Content-Encoding"); ce != "" {
			t.Fatalf("expected binary MVT response to skip gzip Content-Encoding, got %q", ce)
		}

		wireTransport.assertNoViolations(t, "Round63_06_SearchMVT_BinaryVectorTile")
	})

	// Round63_07: ILM Lifecycle & Snapshot Lifecycle
	t.Run("Round63_07_ILMLifecycle_And_SnapshotLifecycle", func(t *testing.T) {
		polName := fmt.Sprintf("sdk_r63_ilm_%d", time.Now().UnixNano())
		mustOKCallR63(t, "ILM.PutLifecycle", func() (*esapi.Response, error) {
			return esClient.ILM.PutLifecycle(
				polName,
				esClient.ILM.PutLifecycle.WithBody(strings.NewReader(`{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"30d"}}}}}}`)),
				esClient.ILM.PutLifecycle.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "ILM.GetLifecycle", func() (*esapi.Response, error) {
			return esClient.ILM.GetLifecycle(esClient.ILM.GetLifecycle.WithPolicy(polName), esClient.ILM.GetLifecycle.WithContext(ctx))
		})
		mustOKCallR63(t, "ILM.GetStatus", func() (*esapi.Response, error) {
			return esClient.ILM.GetStatus(esClient.ILM.GetStatus.WithContext(ctx))
		})
		mustOKCallR63(t, "ILM.ExplainLifecycle", func() (*esapi.Response, error) {
			return esClient.ILM.ExplainLifecycle(idx, esClient.ILM.ExplainLifecycle.WithContext(ctx))
		})
		mustOKCallR63(t, "ILM.DeleteLifecycle", func() (*esapi.Response, error) {
			return esClient.ILM.DeleteLifecycle(polName, esClient.ILM.DeleteLifecycle.WithContext(ctx))
		})

		repoName := fmt.Sprintf("sdk_r63_repo_%d", time.Now().UnixNano())
		snapName := "snap_1"
		restoredIdx := idx + "_restored_r63"
		t.Cleanup(func() {
			if r, e := esClient.Indices.Delete([]string{restoredIdx}); e == nil && r != nil {
				_ = r.Body.Close()
			}
			if r, e := esClient.Snapshot.DeleteRepository([]string{repoName}); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})

		mustOKCallR63(t, "Snapshot.CreateRepository", func() (*esapi.Response, error) {
			return esClient.Snapshot.CreateRepository(
				repoName,
				strings.NewReader(`{"type":"fs","settings":{"location":"sdk_r63_snap_loc"}}`),
				esClient.Snapshot.CreateRepository.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Snapshot.GetRepository", func() (*esapi.Response, error) {
			return esClient.Snapshot.GetRepository(
				esClient.Snapshot.GetRepository.WithRepository(repoName),
				esClient.Snapshot.GetRepository.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Snapshot.VerifyRepository", func() (*esapi.Response, error) {
			return esClient.Snapshot.VerifyRepository(repoName, esClient.Snapshot.VerifyRepository.WithContext(ctx))
		})
		mustOKCallR63(t, "Snapshot.Create", func() (*esapi.Response, error) {
			return esClient.Snapshot.Create(
				repoName,
				snapName,
				esClient.Snapshot.Create.WithWaitForCompletion(true),
				esClient.Snapshot.Create.WithBody(strings.NewReader(fmt.Sprintf(`{"indices":%q,"include_global_state":false}`, idx))),
				esClient.Snapshot.Create.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Snapshot.Get", func() (*esapi.Response, error) {
			return esClient.Snapshot.Get(repoName, []string{snapName}, esClient.Snapshot.Get.WithContext(ctx))
		})
		mustOKCallR63(t, "Snapshot.Restore", func() (*esapi.Response, error) {
			return esClient.Snapshot.Restore(
				repoName,
				snapName,
				esClient.Snapshot.Restore.WithWaitForCompletion(true),
				esClient.Snapshot.Restore.WithBody(strings.NewReader(fmt.Sprintf(
					`{"indices":%q,"rename_pattern":%q,"rename_replacement":%q}`,
					idx, idx, restoredIdx,
				))),
				esClient.Snapshot.Restore.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Snapshot.Delete", func() (*esapi.Response, error) {
			return esClient.Snapshot.Delete(repoName, []string{snapName}, esClient.Snapshot.Delete.WithContext(ctx))
		})
		mustOKCallR63(t, "Snapshot.DeleteRepository", func() (*esapi.Response, error) {
			return esClient.Snapshot.DeleteRepository([]string{repoName}, esClient.Snapshot.DeleteRepository.WithContext(ctx))
		})

		wireTransport.assertNoViolations(t, "Round63_07_ILMLifecycle_And_SnapshotLifecycle")
	})

	// Round63_08: Go SDK v8 Wire Protocol Fidelity:
	//   1. `CompressRequestBody: true` gzipped `/_bulk` + `/_search`
	//   2. `DiscoverNodesOnStart: true` live node sniffing against ephemeral `httptest.Server`
	//   3. Single-value `X-Opaque-Id` response header (`len == 1`) across search, bulk, and admin endpoints
	//   4. `/_mpercolate` NDJSON multi-percolate round-trip
	t.Run("Round63_08_WireProtocol_CompressRequestBody_DiscoverNodes_OpaqueID_And_MPercolate", func(t *testing.T) {
		spy := &requestHeaderSpyTransportR63{base: wireTransport}

		// 1. CompressRequestBody: true -> gzipped /_bulk + /_search
		compClient, err := elasticsearch.NewClient(elasticsearch.Config{
			Addresses:           []string{targetURL},
			CompressRequestBody: true,
			Transport:           spy,
		})
		if err != nil {
			t.Fatalf("NewClient(CompressRequestBody:true) failed: %v", err)
		}
		bulkNDJSON := fmt.Sprintf(`{"index":{"_index":%q,"_id":"gz-doc-1"}}`+"\n"+
			`{"title":"Gzipped Bulk Order","category":"analytics","quantity":5,"amount":55.0,"active":true,"created_at":"2026-11-02T10:00:00Z"}`+"\n", idx)
		bulkGzRes, err := compClient.Bulk(
			strings.NewReader(bulkNDJSON),
			compClient.Bulk.WithRefresh("true"),
			compClient.Bulk.WithContext(ctx),
		)
		assertOKRespR63(t, "Compressed Bulk", bulkGzRes, err)

		searchGzRes, err := compClient.Search(
			compClient.Search.WithIndex(idx),
			compClient.Search.WithBody(strings.NewReader(`{"query":{"match":{"title":"Gzipped"}}}`)),
			compClient.Search.WithContext(ctx),
		)
		searchGzRaw := assertOKRespR63(t, "Compressed Search", searchGzRes, err)
		if !strings.Contains(string(searchGzRaw), "gz-doc-1") {
			t.Fatalf("expected gz-doc-1 hit from compressed search, got %s", string(searchGzRaw))
		}

		spy.mu.Lock()
		gotEncs := append([]string(nil), spy.contentEncodings...)
		spy.mu.Unlock()
		if len(gotEncs) < 2 {
			t.Fatalf("expected >= 2 gzip-encoded SDK requests on wire, got %v", gotEncs)
		}

		// 2. DiscoverNodesOnStart: true live node sniffing against ephemeral httptest.Server port
		sniffSpy := &requestHeaderSpyTransportR63{base: wireTransport}
		sniffClient, err := elasticsearch.NewClient(elasticsearch.Config{
			Addresses:            []string{targetURL},
			DiscoverNodesOnStart: true,
			Transport:            sniffSpy,
		})
		if err != nil {
			t.Fatalf("NewClient(DiscoverNodesOnStart:true) failed: %v", err)
		}
		sniffInfoRes, err := sniffClient.Info(sniffClient.Info.WithContext(ctx))
		assertOKRespR63(t, "Sniffed Client Info()", sniffInfoRes, err)
		sniffSearchRes, err := sniffClient.Search(
			sniffClient.Search.WithIndex(idx),
			sniffClient.Search.WithBody(strings.NewReader(`{"size":1}`)),
			sniffClient.Search.WithContext(ctx),
		)
		assertOKRespR63(t, "Sniffed Client Search()", sniffSearchRes, err)
		sniffSpy.mu.Lock()
		sniffCount := sniffSpy.sniffRequests
		sniffSpy.mu.Unlock()
		if sniffCount < 1 {
			t.Fatalf("expected DiscoverNodesOnStart to issue >= 1 /_nodes sniff request, got %d", sniffCount)
		}

		// 3. Single-value `X-Opaque-Id` response header across search, bulk, and admin endpoints
		const opaqueVal = "sdk-v8-opaque-round63"
		checkSingleOpaque := func(label string, res *esapi.Response, callErr error) {
			t.Helper()
			assertOKRespR63(t, label, res, callErr)
			vals := res.Header.Values("X-Opaque-Id")
			if len(vals) != 1 || vals[0] != opaqueVal {
				t.Fatalf("%s: expected single X-Opaque-Id=[%q], got %v", label, opaqueVal, vals)
			}
		}

		sOpqRes, sOpqErr := esClient.Search(
			esClient.Search.WithIndex(idx),
			esClient.Search.WithBody(strings.NewReader(`{"query":{"match_all":{}},"size":1}`)),
			esClient.Search.WithOpaqueID(opaqueVal),
			esClient.Search.WithContext(ctx),
		)
		checkSingleOpaque("Search X-Opaque-Id", sOpqRes, sOpqErr)

		bOpqBody := fmt.Sprintf(`{"index":{"_index":%q,"_id":"opq-doc-1"}}`+"\n"+
			`{"title":"Opaque Check","category":"analytics","quantity":1,"amount":10.0,"active":true,"created_at":"2026-11-02T10:00:00Z"}`+"\n", idx)
		bOpqRes, bOpqErr := esClient.Bulk(
			strings.NewReader(bOpqBody),
			esClient.Bulk.WithOpaqueID(opaqueVal),
			esClient.Bulk.WithContext(ctx),
		)
		checkSingleOpaque("Bulk X-Opaque-Id", bOpqRes, bOpqErr)

		aOpqRes, aOpqErr := esClient.Cluster.Health(
			esClient.Cluster.Health.WithOpaqueID(opaqueVal),
			esClient.Cluster.Health.WithContext(ctx),
		)
		checkSingleOpaque("Cluster.Health X-Opaque-Id", aOpqRes, aOpqErr)

		// 4. `/_mpercolate` NDJSON multi-percolate round-trip via Go SDK v8 Perform()
		percIdx := fmt.Sprintf("sdk_r63_perc_%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if r, e := esClient.Indices.Delete([]string{percIdx}); e == nil && r != nil {
				_ = r.Body.Close()
			}
		})
		mustOKCallR63(t, "Indices.Create(percIdx)", func() (*esapi.Response, error) {
			return esClient.Indices.Create(
				percIdx,
				esClient.Indices.Create.WithBody(strings.NewReader(`{"mappings":{"properties":{"query":{"type":"percolator"},"message":{"type":"text"}}}}`)),
				esClient.Indices.Create.WithContext(ctx),
			)
		})
		mustOKCallR63(t, "Index(percolator query)", func() (*esapi.Response, error) {
			return esClient.Index(
				percIdx,
				strings.NewReader(`{"query":{"match":{"message":"bonsai"}}}`),
				esClient.Index.WithDocumentID("alert-bonsai"),
				esClient.Index.WithRefresh("true"),
				esClient.Index.WithContext(ctx),
			)
		})

		mpercNDJSON := fmt.Sprintf(`{"percolate":{"index":%q}}`+"\n"+`{"doc":{"message":"A new bonsai tree in the office"}}`+"\n", percIdx)
		mpercReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "/_mpercolate", strings.NewReader(mpercNDJSON))
		if err != nil {
			t.Fatalf("NewRequest(_mpercolate): %v", err)
		}
		mpercReq.Header.Set("Content-Type", "application/x-ndjson")
		mpercHTTPResp, err := esClient.Perform(mpercReq)
		if err != nil {
			t.Fatalf("esClient.Perform(/_mpercolate) failed: %v", err)
		}
		mpercRaw, _ := io.ReadAll(mpercHTTPResp.Body)
		_ = mpercHTTPResp.Body.Close()
		if mpercHTTPResp.StatusCode != http.StatusOK || !strings.Contains(string(mpercRaw), "alert-bonsai") {
			t.Fatalf("expected 200 and alert-bonsai match from /_mpercolate, status=%d body=%s",
				mpercHTTPResp.StatusCode, string(mpercRaw))
		}

		wireTransport.assertNoViolations(t, "Round63_08_WireProtocol_CompressRequestBody_DiscoverNodes_OpaqueID_And_MPercolate")
	})
}
