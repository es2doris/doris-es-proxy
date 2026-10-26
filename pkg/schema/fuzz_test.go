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

package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzParseESDateMath(f *testing.F) {
	seeds := []string{
		"now",
		"now-7d/d",
		"now+2h/h",
		"now-1w/w",
		"now-3M/M",
		"now-1y/y",
		"now-15m/m",
		"now-30s/s",
		"2026-10-25T12:00:00Z||+1d/d",
		"2026-10-25||/w",
		"1729773296789||-2h/h",
		"2026/10/25",
		"invalid-date||+999999y/d",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	fixedNow := time.Date(2026, 10, 25, 12, 34, 56, 0, time.UTC)
	f.Fuzz(func(t *testing.T, input string) {
		lower, ok1 := ParseESDateBoundToEpochMillis(input, fixedNow, false)
		upper, ok2 := ParseESDateBoundToEpochMillis(input, fixedNow, true)
		if ok1 != ok2 {
			t.Fatalf("ParseESDateBoundToEpochMillis(roundUp=false)=%v != (roundUp=true)=%v for %q", ok1, ok2, input)
		}
		if ok1 && upper < lower {
			t.Fatalf("expected inclusive upper bound (%d) >= lower bound (%d) for %q", upper, lower, input)
		}
	})
}

func FuzzInferAndShredDocument(f *testing.F) {
	seeds := []string{
		`{"service":"checkout","latency":42,"ok":true,"created_at":"2026-10-25T12:00:00Z","tags":["a","b"]}`,
		`{"nested":{"a":{"b":"deep"}},"vec":[0.1,0.2,0.3],"items":[{"sku":"S1"},{"sku":"S2"}]}`,
		`{"empty_arr":[],"null_val":null,"num_str":"123.45"}`,
		`null`,
		`[]`,
		`{invalid`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, rawDoc []byte) {
		inferred := InferMappingFromSampleDocs([]json.RawMessage{rawDoc})
		idxSchema := CompileIndexSchema("fuzz_db", "fuzz_idx", inferred)
		_ = GenerateCreateTableDDL(idxSchema)
		shredded, err := ShredDocument(idxSchema, "doc-1", 1, false, rawDoc)
		if err != nil {
			return
		}
		var out map[string]any
		if uErr := json.Unmarshal(shredded, &out); uErr != nil {
			t.Fatalf("ShredDocument emitted invalid JSON %q: %v", string(shredded), uErr)
		}
	})
}
