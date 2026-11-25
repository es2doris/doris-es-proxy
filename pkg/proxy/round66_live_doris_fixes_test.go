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
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound66StrictNereidsLambdaAndLateralViewGuards(t *testing.T) {
	nestedLambdaSQL := "SELECT 1 FROM tbl WHERE array_exists(_a -> array_exists(_b -> _b = 'x', `n__items`), `n__roots`)"
	if err := checkStrictNereidsSQLTypesR63Mem(nestedLambdaSQL); err == nil {
		t.Fatalf("expected nested lambda SQL to be rejected")
	}

	flatSiblingLambdaSQL := "SELECT ARRAY_MAX(array_map(_nel -> IF(_nel IS NOT NULL, 1.0, NULL), `n__paragraphs`)) FROM tbl WHERE array_exists(_nel -> _nel IS NOT NULL, `n__paragraphs`)"
	if err := checkStrictNereidsSQLTypesR63Mem(flatSiblingLambdaSQL); err != nil {
		t.Fatalf("expected flat sibling lambdas to be allowed, got error: %v", err)
	}

	lateralAfterJoinSQL := "SELECT `_id` FROM `base_matched` INNER JOIN (SELECT `_id` FROM tbl) `_d` ON `base_matched`.`_id` = `_d`.`_id` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem`"
	if err := checkStrictNereidsSQLTypesR63Mem(lateralAfterJoinSQL); err == nil {
		t.Fatalf("expected LATERAL VIEW after JOIN to be rejected")
	}

	lateralBeforeJoinSQL := "SELECT `_id` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` INNER JOIN (SELECT `_id` FROM tbl) `_d` ON `base_matched`.`_id` = `_d`.`_id`"
	if err := checkStrictNereidsSQLTypesR63Mem(lateralBeforeJoinSQL); err != nil {
		t.Fatalf("expected LATERAL VIEW before INNER JOIN to be allowed, got error: %v", err)
	}
}

func TestRound66MemoryBackendLateralViewBeforeJoinParity(t *testing.T) {
	baseRows := []map[string]any{
		{"_id": "1", "f__grp": "g1", "f__items": []any{"a", "b"}},
		{"_id": "2", "f__grp": "g2", "f__items": []any{"c"}},
	}
	fromClause := "`base_matched` LATERAL VIEW EXPLODE(`f__items`) `_t` AS `_elem` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, `f__grp` AS `_rn_bkey` FROM `base_matched` WHERE `f__grp` IS NOT NULL) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`"
	rows := expandFromClauseRows(baseRows, fromClause, "")
	if len(rows) != 3 {
		t.Fatalf("expected 3 expanded joined rows, got %d (%+v)", len(rows), rows)
	}
	seen := make(map[string]bool, 3)
	for _, r := range rows {
		key := fmt.Sprintf("%v|%v|%v", r["_id"], r["_rn_bkey"], r["_elem"])
		seen[key] = true
	}
	for _, want := range []string{"1|g1|a", "1|g1|b", "2|g2|c"} {
		if !seen[want] {
			t.Fatalf("missing expected expanded row %q in %v", want, seen)
		}
	}
}

func TestRound66MultiIndexWeightedAvgAndMatrixStatsKurtosis(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	mapping := `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"qty": {"type": "long"},
				"amd": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count", "avg"], "default_metric": "avg"}
			}
		}
	}`
	for _, idx := range []string{"wavg_1", "wavg_2"} {
		if rec := doRound65Req(t, h, http.MethodPut, "/"+idx, mapping, nil); rec.Code != http.StatusOK {
			t.Fatalf("create %s failed: %d %s", idx, rec.Code, rec.Body.String())
		}
	}

	// wavg_1: 1 doc (qty=10, amd={min:10,max:10,sum:10,value_count:1})
	if rec := doRound65Req(t, h, http.MethodPut, "/wavg_1/_doc/1", `{"grp":"a","qty":10,"amd":{"min":10,"max":10,"sum":10,"value_count":1}}`, nil); rec.Code >= 300 {
		t.Fatalf("index wavg_1 doc failed: %d %s", rec.Code, rec.Body.String())
	}
	// wavg_2: 3 docs (qty=20 each, amd total sum=60, value_count=3)
	for _, doc := range []struct {
		id, body string
	}{
		{"1", `{"grp":"a","qty":20,"amd":{"min":20,"max":20,"sum":20,"value_count":1}}`},
		{"2", `{"grp":"a","qty":20,"amd":{"min":20,"max":20,"sum":20,"value_count":1}}`},
		{"3", `{"grp":"a","qty":20,"amd":{"min":20,"max":20,"sum":40,"value_count":2}}`},
	} {
		// Keep doc 1,2,3 simple: sum=20, vc=1 each -> total sum=60, vc=3.
		_ = doc
	}
	for i := 1; i <= 3; i++ {
		body := `{"grp":"a","qty":20,"amd":{"min":20,"max":20,"sum":20,"value_count":1}}`
		if rec := doRound65Req(t, h, http.MethodPut, fmt.Sprintf("/wavg_2/_doc/%d", i), body, nil); rec.Code >= 300 {
			t.Fatalf("index wavg_2 doc %d failed: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	doRound65Req(t, h, http.MethodPost, "/wavg_1,wavg_2/_refresh", "", nil)

	// Single-index avg must not expose internal _avg_weight.
	recSingle := doRound65Req(t, h, http.MethodPost, "/wavg_1/_search", `{
		"size": 0,
		"aggs": {
			"scalar_avg": {"avg": {"field": "qty"}},
			"amd_avg": {"avg": {"field": "amd"}}
		}
	}`, nil)
	if recSingle.Code != http.StatusOK {
		t.Fatalf("single-index search failed: %d %s", recSingle.Code, recSingle.Body.String())
	}
	if strings.Contains(recSingle.Body.String(), "_avg_weight") {
		t.Fatalf("internal _avg_weight leaked into single-index JSON response:\n%s", recSingle.Body.String())
	}

	// Multi-index search must compute exact count-weighted avg: (10 + 20*3) / 4 = 17.5.
	recMulti := doRound65Req(t, h, http.MethodPost, "/wavg_1,wavg_2/_search", `{
		"size": 0,
		"aggs": {
			"scalar_avg": {"avg": {"field": "qty"}},
			"amd_avg": {"avg": {"field": "amd"}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"sub_scalar_avg": {"avg": {"field": "qty"}},
					"sub_amd_avg": {"avg": {"field": "amd"}}
				}
			}
		}
	}`, nil)
	if recMulti.Code != http.StatusOK {
		t.Fatalf("multi-index search failed: %d %s", recMulti.Code, recMulti.Body.String())
	}
	if strings.Contains(recMulti.Body.String(), "_avg_weight") {
		t.Fatalf("internal _avg_weight leaked into multi-index JSON response:\n%s", recMulti.Body.String())
	}
	var resp struct {
		Aggregations struct {
			ScalarAvg struct {
				Value float64 `json:"value"`
			} `json:"scalar_avg"`
			AmdAvg struct {
				Value float64 `json:"value"`
			} `json:"amd_avg"`
			ByGrp struct {
				Buckets []struct {
					Key          string `json:"key"`
					SubScalarAvg struct {
						Value float64 `json:"value"`
					} `json:"sub_scalar_avg"`
					SubAmdAvg struct {
						Value float64 `json:"value"`
					} `json:"sub_amd_avg"`
				} `json:"buckets"`
			} `json:"by_grp"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(recMulti.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal multi-index agg response failed: %v", err)
	}
	const wantWeighted = 17.5
	if math.Abs(resp.Aggregations.ScalarAvg.Value-wantWeighted) > 1e-9 {
		t.Fatalf("scalar weighted avg: got %v, want %v", resp.Aggregations.ScalarAvg.Value, wantWeighted)
	}
	if math.Abs(resp.Aggregations.AmdAvg.Value-wantWeighted) > 1e-9 {
		t.Fatalf("aggregate_metric_double weighted avg: got %v, want %v", resp.Aggregations.AmdAvg.Value, wantWeighted)
	}
	if len(resp.Aggregations.ByGrp.Buckets) != 1 {
		t.Fatalf("expected 1 terms bucket, got %+v", resp.Aggregations.ByGrp.Buckets)
	}
	if got := resp.Aggregations.ByGrp.Buckets[0].SubScalarAvg.Value; math.Abs(got-wantWeighted) > 1e-9 {
		t.Fatalf("sub scalar weighted avg: got %v, want %v", got, wantWeighted)
	}
	if got := resp.Aggregations.ByGrp.Buckets[0].SubAmdAvg.Value; math.Abs(got-wantWeighted) > 1e-9 {
		t.Fatalf("sub aggregate_metric_double weighted avg: got %v, want %v", got, wantWeighted)
	}

	// Verify matrix_stats kurtosis uses direct m2^2 denominator with high precision around large means.
	if rec := doRound65Req(t, h, http.MethodPut, "/mstats_kurt", `{"mappings":{"properties":{"x":{"type":"double"}}}}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("create mstats_kurt failed: %d %s", rec.Code, rec.Body.String())
	}
	for i, val := range []float64{1000001.0, 1000002.0, 1000003.0, 1000004.0, 1000005.0} {
		rec := doRound65Req(t, h, http.MethodPut, fmt.Sprintf("/mstats_kurt/_doc/%d", i+1), fmt.Sprintf(`{"x": %.1f}`, val), nil)
		if rec.Code >= 300 {
			t.Fatalf("index mstats doc %d failed: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	doRound65Req(t, h, http.MethodPost, "/mstats_kurt/_refresh", "", nil)
	recMS := doRound65Req(t, h, http.MethodPost, "/mstats_kurt/_search", `{
		"size": 0,
		"aggs": {"ms": {"matrix_stats": {"fields": ["x"]}}}
	}`, nil)
	if recMS.Code != http.StatusOK {
		t.Fatalf("matrix_stats search failed: %d %s", recMS.Code, recMS.Body.String())
	}
	var msResp struct {
		Aggregations struct {
			Ms struct {
				Fields []struct {
					Name     string  `json:"name"`
					Kurtosis float64 `json:"kurtosis"`
				} `json:"fields"`
			} `json:"ms"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(recMS.Body.Bytes(), &msResp); err != nil {
		t.Fatalf("unmarshal matrix_stats failed: %v", err)
	}
	if len(msResp.Aggregations.Ms.Fields) != 1 || math.Abs(msResp.Aggregations.Ms.Fields[0].Kurtosis-1.7) > 1e-9 {
		t.Fatalf("expected kurtosis=1.7, got %+v", msResp.Aggregations.Ms.Fields)
	}
}

type round66ExecDDLDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(query string) error
}

var (
	round66ExecDDLMockOnce sync.Once
	round66ExecDDLMockDrv  = &round66ExecDDLDriver{
		handlers: make(map[string]func(query string) error),
	}
)

func (d *round66ExecDDLDriver) Open(name string) (driver.Conn, error) {
	return &round66ExecDDLConn{dsn: name, drv: d}, nil
}

type round66ExecDDLConn struct {
	dsn string
	drv *round66ExecDDLDriver
}

func (c *round66ExecDDLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}
func (c *round66ExecDDLConn) Close() error              { return nil }
func (c *round66ExecDDLConn) Begin() (driver.Tx, error) { return nil, errors.New("not implemented") }
func (c *round66ExecDDLConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("no handler for %q", c.dsn)
	}
	if err := fn(query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(0), nil
}

func openRound66ExecDDLMockDB(t *testing.T, fn func(query string) error) *sql.DB {
	t.Helper()
	round66ExecDDLMockOnce.Do(func() {
		sql.Register("round66_execddl_mock", round66ExecDDLMockDrv)
	})
	dsn := t.Name()
	round66ExecDDLMockDrv.mu.Lock()
	round66ExecDDLMockDrv.handlers[dsn] = fn
	round66ExecDDLMockDrv.mu.Unlock()
	t.Cleanup(func() {
		round66ExecDDLMockDrv.mu.Lock()
		delete(round66ExecDDLMockDrv.handlers, dsn)
		round66ExecDDLMockDrv.mu.Unlock()
	})
	db, err := sql.Open("round66_execddl_mock", dsn)
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRound66ExecDDLSchemaChangeRetry(t *testing.T) {
	t.Run("transient_schema_change_retries_and_succeeds", func(t *testing.T) {
		var calls atomic.Int32
		errs := []error{
			errors.New("errCode = 2, detailMessage = Table[nested_text] state is SCHEMA_CHANGE"),
			errors.New("errCode = 2, detailMessage = Table[nested_text] is not normal, doing schema change"),
		}
		db := openRound66ExecDDLMockDB(t, func(string) error {
			n := int(calls.Add(1))
			if n <= len(errs) {
				return errs[n-1]
			}
			return nil
		})
		b := NewDorisSQLBackend(db, nil)
		if err := b.ExecDDL(context.Background(), "ALTER TABLE `db`.`t` ADD COLUMN `c` STRING;"); err != nil {
			t.Fatalf("expected ExecDDL retry to succeed, got: %v", err)
		}
		if got := calls.Load(); got != 3 {
			t.Fatalf("expected 3 attempts, got %d", got)
		}
	})

	t.Run("non_retryable_error_fails_immediately", func(t *testing.T) {
		var calls atomic.Int32
		db := openRound66ExecDDLMockDB(t, func(string) error {
			calls.Add(1)
			return errors.New("syntax error near ALTER")
		})
		b := NewDorisSQLBackend(db, nil)
		if err := b.ExecDDL(context.Background(), "ALTER TABLE bad;"); err == nil {
			t.Fatalf("expected syntax error to fail")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("expected 1 attempt without retry, got %d", got)
		}
	})

	t.Run("cancelled_context_aborts_backoff", func(t *testing.T) {
		var calls atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		db := openRound66ExecDDLMockDB(t, func(string) error {
			calls.Add(1)
			cancel()
			return errors.New("table state is SCHEMA_CHANGE")
		})
		b := NewDorisSQLBackend(db, nil)
		start := time.Now()
		if err := b.ExecDDL(ctx, "ALTER TABLE `db`.`t` ADD COLUMN `c` STRING;"); err == nil {
			t.Fatalf("expected error on cancelled context")
		}
		if time.Since(start) > time.Second {
			t.Fatalf("cancelled backoff took too long")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("expected 1 attempt before cancel, got %d", got)
		}
	})
}

func TestRound66NestedKNN100YMLSection7NestedTextE2E(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Exact index & mapping from search.vectors/100_knn_nested_search.yml Section 7 (nested_text).
	createBody := `{
		"mappings": {
			"properties": {
				"range": {"type": "long"},
				"other_nested_thing": {
					"type": "nested",
					"properties": {
						"text": {"type": "text"}
					}
				},
				"paragraphs": {
					"type": "nested",
					"properties": {
						"other_nested_thing": {
							"type": "nested",
							"properties": {
								"text": {"type": "text"},
								"vector": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"}
							}
						},
						"vector": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"}
					}
				}
			}
		}
	}`
	if rec := doRound65Req(t, h, http.MethodPut, "/nested_text", createBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("create nested_text failed: %d %s", rec.Code, rec.Body.String())
	}

	doc1 := `{
		"publish_date": "1",
		"paragraphs": [
			{"vector": [1, 1], "text": "some text"},
			{"vector": [1, 2], "text": "some text", "other_nested_thing": [{"text": "some text", "vector": [1, 2]}]}
		]
	}`
	doc2 := `{
		"paragraphs": [
			{"vector": [2, 1], "text": "some text"},
			{"vector": [2, 2], "text": "some text", "other_nested_thing": [{"text": "some text", "vector": [1, 2]}]}
		]
	}`
	if rec := doRound65Req(t, h, http.MethodPut, "/nested_text/_doc/1", doc1, nil); rec.Code >= 300 {
		t.Fatalf("index doc 1 failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound65Req(t, h, http.MethodPut, "/nested_text/_doc/2", doc2, nil); rec.Code >= 300 {
		t.Fatalf("index doc 2 failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound65Req(t, h, http.MethodPost, "/nested_text/_refresh", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", rec.Code, rec.Body.String())
	}

	// Verify dynamic publish_date ALTER DDL preserves ADD COLUMN before ADD INDEX.
	srv.mu.RLock()
	idxSchema := srv.indices["nested_text"]
	srv.mu.RUnlock()
	if idxSchema == nil {
		t.Fatalf("expected nested_text schema in server indices")
	}
	var baseSpec esast.MappingSpec
	var wrap struct {
		Mappings esast.MappingSpec `json:"mappings"`
	}
	if err := json.Unmarshal([]byte(createBody), &wrap); err != nil {
		t.Fatalf("unmarshal base spec failed: %v", err)
	}
	baseSpec = wrap.Mappings
	baseSchema := schema.CompileIndexSchema("default", idxSchema.DorisTable, &baseSpec)
	alterDDLs := schema.GenerateAlterTableDDL(baseSchema, idxSchema)
	seenAddIdx := false
	for _, stmt := range alterDDLs {
		if strings.Contains(strings.ToUpper(stmt), " ADD INDEX ") {
			seenAddIdx = true
		} else if seenAddIdx {
			t.Fatalf("expected all ADD COLUMN statements before ADD INDEX in nested_text ALTER DDLs, got %v", alterDDLs)
		}
	}

	// Inspect normalized Doris SQL for both 100 (top-level knn) and 130 (query.nested.query.knn) Section 7 queries.
	knnQueries := []struct {
		name string
		body string
	}{
		{
			name: "100_top_level_knn",
			body: `{
				"knn": {
					"field": "paragraphs.vector",
					"query_vector": [1, 2],
					"num_candidates": 10,
					"k": 10,
					"filter": {
						"bool": {
							"must_not": {
								"exists": {"field": "publish_date"}
							}
						}
					}
				}
			}`,
		},
		{
			name: "130_nested_query_knn",
			body: `{
				"query": {
					"nested": {
						"path": "paragraphs",
						"query": {
							"knn": {
								"field": "paragraphs.vector",
								"query_vector": [1, 2],
								"num_candidates": 10,
								"filter": {
									"bool": {
										"must_not": {
											"exists": {"field": "publish_date"}
										}
									}
								}
							}
						}
					}
				}
			}`,
		},
	}

	for _, tc := range knnQueries {
		var parsedReq esast.SearchRequest
		if err := json.Unmarshal([]byte(tc.body), &parsedReq); err != nil {
			t.Fatalf("%s unmarshal knn query failed: %v", tc.name, err)
		}
		plan, err := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{}).BuildSearchPlan(&parsedReq)
		if err != nil {
			t.Fatalf("%s BuildSearchPlan failed: %v", tc.name, err)
		}
		normSQL := NormalizeDorisSQL(plan.HitsSQL)
		if err := checkStrictNereidsSQLTypesR63Mem(normSQL); err != nil {
			t.Fatalf("%s strict Nereids check failed on normalized SQL: %v\nSQL:\n%s", tc.name, err, normSQL)
		}
		if strings.Contains(normSQL, "INNER_PRODUCT(") {
			t.Fatalf("%s normalized SQL must not contain INNER_PRODUCT on cosine kNN:\n%s", tc.name, normSQL)
		}
		if !strings.Contains(normSQL, "`f__publish_date` IS NULL") {
			t.Fatalf("%s normalized SQL must negate scalar exists directly to `f__publish_date` IS NULL:\n%s", tc.name, normSQL)
		}
		if strings.Contains(normSQL, "NOT COALESCE(`f__publish_date` IS NOT NULL, FALSE)") {
			t.Fatalf("%s normalized SQL must not wrap `f__publish_date` IS NOT NULL in NOT COALESCE:\n%s", tc.name, normSQL)
		}

		// Execute live Server + MemoryBackend search and verify hit _id == "2".
		recSearch := doRound65Req(t, h, http.MethodPost, "/nested_text/_search", tc.body, nil)
		if recSearch.Code != http.StatusOK {
			t.Fatalf("%s search nested_text failed: %d %s", tc.name, recSearch.Code, recSearch.Body.String())
		}
		var sr struct {
			Hits struct {
				Total struct {
					Value int `json:"value"`
				} `json:"total"`
				Hits []struct {
					ID string `json:"_id"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(recSearch.Body.Bytes(), &sr); err != nil {
			t.Fatalf("%s unmarshal search response failed: %v", tc.name, err)
		}
		if sr.Hits.Total.Value != 1 || len(sr.Hits.Hits) != 1 || sr.Hits.Hits[0].ID != "2" {
			t.Fatalf("%s unexpected search hits for Section 7 nested_text: %s", tc.name, recSearch.Body.String())
		}
	}
}

func TestRound66SparseVectorExistsEmptyArrayVsEmptyObjectE2E(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Exact mapping and documents from search.vectors/90_sparse_vector.yml multi-value section.
	createBody := `{
		"mappings": {
			"properties": {
				"text": {"type": "text"},
				"ml.tokens": {"type": "sparse_vector"},
				"embeddings": {"type": "sparse_vector"}
			}
		}
	}`
	if rec := doRound65Req(t, h, http.MethodPut, "/test", createBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("create test failed: %d %s", rec.Code, rec.Body.String())
	}
	docs := []struct {
		id   string
		body string
	}{
		{"1", `{"text":"running is good for you","ml":{"tokens":[{"running":2.4,"good":2.1},{"race":1.4}]}}`},
		{"2", `{"text":"walking is a healthy exercise","ml":{"tokens":{"walking":2.4,"exercise":2.0}}}`},
		{"3", `{"text":"empty array with no values - should not be retrieved in exists queries","ml":{"tokens":[]}}`},
		{"4", `{"text":"should still respond to exists queries if when empty","ml":{"tokens":{}}}`},
		{"5", `{"text":"other embeddings available only","embeddings":{"aardvark":0.5}}`},
	}
	for _, d := range docs {
		if rec := doRound65Req(t, h, http.MethodPut, "/test/_doc/"+d.id, d.body, nil); rec.Code >= 300 {
			t.Fatalf("index doc %s failed: %d %s", d.id, rec.Code, rec.Body.String())
		}
	}
	if rec := doRound65Req(t, h, http.MethodPost, "/test/_refresh", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", rec.Code, rec.Body.String())
	}

	recSearch := doRound65Req(t, h, http.MethodPost, "/test/_search?rest_total_hits_as_int=true", `{"query":{"exists":{"field":"ml.tokens"}}}`, nil)
	if recSearch.Code != http.StatusOK {
		t.Fatalf("exists search failed: %d %s", recSearch.Code, recSearch.Body.String())
	}
	var sr struct {
		Hits struct {
			Total int `json:"total"`
			Hits  []struct {
				ID string `json:"_id"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(recSearch.Body.Bytes(), &sr); err != nil {
		t.Fatalf("unmarshal sparse exists response failed: %v", err)
	}
	if sr.Hits.Total != 3 || len(sr.Hits.Hits) != 3 {
		t.Fatalf("expected 3 hits (docs 1, 2, 4; not empty array doc 3), got: %s", recSearch.Body.String())
	}
	for _, hit := range sr.Hits.Hits {
		if hit.ID == "3" || hit.ID == "5" {
			t.Fatalf("doc %s must not match exists on ml.tokens: %s", hit.ID, recSearch.Body.String())
		}
	}
}

func TestRound66IsTableNotFoundErrorPrecision(t *testing.T) {
	positives := []error{
		errors.New("errCode = 2, detailMessage = Unknown table 't'"),
		errors.New("Unknown database 'es_db'"),
		errors.New("Table 'db.t' doesn't exist"),
		errors.New("Table 'db.t' does not exist"),
		errors.New("Database [es_db] does not exist"),
	}
	for _, err := range positives {
		if !isTableNotFoundError(err) {
			t.Fatalf("expected isTableNotFoundError(%v) == true", err)
		}
	}
	negatives := []error{
		nil,
		errors.New("Column 'f__publish_date' does not exist"),
		errors.New("Function 'custom_fn' does not exist"),
		errors.New("Unknown column 'f__publish_date' in 'table list'"),
	}
	for _, err := range negatives {
		if isTableNotFoundError(err) {
			t.Fatalf("expected isTableNotFoundError(%v) == false", err)
		}
	}
}
