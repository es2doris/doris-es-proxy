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
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzBulkNDJSONInvariants(f *testing.F) {
	seeds := []string{
		`{"index":{"_index":"logs","_id":"1"}}` + "\n" + `{"msg":"hello"}` + "\n",
		`{"create":{"_id":"2"}}` + "\n" + `{"count":42,"tags":["a","b"]}` + "\n",
		`{"update":{"_id":"3"}}` + "\n" + `{"doc":{"status":"ok"},"doc_as_upsert":true}` + "\n",
		`{"delete":{"_index":"logs","_id":"4"}}` + "\n",
		`{"index":{"_id":"5"}}` + "\n" + `{malformed_json` + "\n",
		`not_json_at_all` + "\n",
		"",
		"\n\n\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ops, err := ParseBulkNDJSON(bytes.NewReader(data), "default_idx")
		if err != nil {
			return
		}
		for _, op := range ops {
			if op.Action == "" {
				t.Fatalf("parsed bulk operation with empty Action: %+v", op)
			}
			if op.Index == "" {
				t.Fatalf("expected non-empty Index when defaultIndex is provided: %+v", op)
			}
		}
	})
}

func FuzzUnmarshalSearchRequest(f *testing.F) {
	seeds := []string{
		`{"query":{"match_all":{}}}`,
		`{"from":0,"size":10,"query":{"bool":{"must":[{"term":{"status":"200"}}],"should":[{"match":{"msg":"error"}}],"minimum_should_match":"75%"}}}`,
		`{"query":{"function_score":{"query":{"match":{"title":"doris"}},"weight":2.5,"score_mode":"multiply","functions":[{"weight":3},{"field_value_factor":{"field":"likes","factor":1.2,"modifier":"log1p","missing":1}}]}}}`,
		`{"sort":["_score",{"@timestamp":{"order":"desc"}},{"price":"asc"}],"_source":{"includes":["a.*"],"excludes":["b.secret"]}}`,
		`{"aggs":{"by_svc":{"terms":{"field":"service","size":5},"aggs":{"p95":{"percentiles":{"field":"latency","percents":[50,95,99]}}}}}}`,
		`{"knn":{"field":"vec","query_vector":[0.1,0.2,0.3],"k":5,"num_candidates":20}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		var req SearchRequest
		_ = json.Unmarshal(data, &req)
		_ = req.EffectiveAggs()

		var mapping MappingSpec
		_ = json.Unmarshal(data, &mapping)

		var tpl IndexTemplateRequest
		if err := json.Unmarshal(data, &tpl); err == nil {
			_ = tpl.EffectivePatterns()
			_ = tpl.EffectiveMappings()
		}
	})
}
