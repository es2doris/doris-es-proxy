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

package esast

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSearchRequestUnmarshal_OpenMetadataPayload(t *testing.T) {
	payload := `{
		"from": 0,
		"size": 20,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": {
							"multi_match": {
								"query": "customer_orders",
								"fields": ["name^10", "displayName^8", "description^2"],
								"operator": "and"
							}
						},
						"filter": [
							{"term": {"deleted": false}},
							{"term": {"serviceType": {"value": "BigQuery", "case_insensitive": true}}}
						]
					}
				},
				"functions": [
					{
						"filter": {"term": {"tier.tagFQN": "Tier.Tier1"}},
						"weight": 3.0
					},
					{
						"field_value_factor": {
							"field": "usageSummary.weeklyStats.count",
							"factor": 0.05,
							"modifier": "log1p",
							"missing": 0
						}
					}
				],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}
		},
		"aggs": {
			"serviceType": {"terms": {"field": "serviceType.keyword", "size": 10}},
			"columns_type": {
				"nested": {"path": "columns"},
				"aggs": {
					"by_type": {"terms": {"field": "columns.dataType", "size": 15}}
				}
			}
		},
		"sort": ["_score", {"updatedAt": {"order": "desc"}}]
	}`

	var req SearchRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("failed to unmarshal OpenMetadata search payload: %v", err)
	}
	if req.Size == nil || *req.Size != 20 {
		t.Fatalf("expected size 20, got %+v", req.Size)
	}
	if req.Query == nil || req.Query.FunctionScore == nil {
		t.Fatalf("expected function_score query")
	}
	boolQ := req.Query.FunctionScore.Query.Bool
	if len(boolQ.Must) != 1 || len(boolQ.Filter) != 2 {
		t.Fatalf("unexpected bool clauses: must=%d filter=%d", len(boolQ.Must), len(boolQ.Filter))
	}
	if len(req.EffectiveAggs()) != 2 {
		t.Fatalf("expected 2 aggs, got %d", len(req.EffectiveAggs()))
	}
	if len(req.Sort) != 2 || req.Sort[1].Entry.Field != "updatedAt" || req.Sort[1].Entry.Order != "desc" {
		t.Fatalf("unexpected sort spec: %+v", req.Sort)
	}
}

func TestParseBulkNDJSON(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"index":{"_index":"table_search_index","_id":"doc-1"}}`,
		`{"name":"orders","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}]}`,
		`{"delete":{"_index":"table_search_index","_id":"doc-2"}}`,
		"",
	}, "\n")

	ops, err := ParseBulkNDJSON(strings.NewReader(ndjson), "default_idx")
	if err != nil {
		t.Fatalf("ParseBulkNDJSON failed: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 bulk ops, got %d", len(ops))
	}
	if ops[0].Action != "index" || ops[0].ID != "doc-1" || string(ops[0].Source) != `{"name":"orders","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"}]}` {
		t.Fatalf("unexpected first op: %+v", ops[0])
	}
	if ops[1].Action != "delete" || ops[1].ID != "doc-2" {
		t.Fatalf("unexpected second op: %+v", ops[1])
	}
}
