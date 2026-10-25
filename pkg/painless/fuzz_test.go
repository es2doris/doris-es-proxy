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

package painless

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvalPainless_RejectsExponentialAddAllAndRunawayLoops(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"a", "b"},
	}
	// 20 self-appending addAll statements would grow slice to 2 * 2^20 = 2,097,152 items without budget protection
	script := strings.Repeat("ctx._source.tags.addAll(ctx._source.tags);\n", 20)
	err := EvalPainless(doc, script, nil)
	if err == nil {
		t.Fatalf("expected EvalPainless to reject runaway addAll slice growth")
	}
}

func FuzzEvalPainless(f *testing.F) {
	f.Add([]byte(`{"tags":["PII"],"deleted":false,"count":1}`), "ctx._source.deleted = true; ctx._source.count += 1;")
	f.Add([]byte(`{"tags":["a","b"]}`), "for (x in ctx._source.tags) { ctx._source.tags.add(x); }")
	f.Add([]byte(`{"custom":{"k":"v"}}`), "if (ctx._source.custom.containsKey('k')) { ctx._source.custom.remove('k'); }")

	f.Fuzz(func(t *testing.T, rawDoc []byte, script string) {
		var doc map[string]any
		if err := json.Unmarshal(rawDoc, &doc); err != nil || doc == nil {
			return
		}
		_ = EvalPainless(doc, script, map[string]any{"p": "v"})
	})
}
