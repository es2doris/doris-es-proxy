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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
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

func FuzzValidateTSDBSettingsAndMappings(f *testing.F) {
	type seed struct {
		mode     string
		endCur   string
		endNext  string
		settings string
		mapping  string
		docID    string
	}
	seeds := []seed{
		{"time_series", "2026-10-25T12:00:00Z", "2026-10-25T13:00:00Z", `{"index":{"mode":"time_series","routing_path":["host"],"time_series":{"start_time":"2026-10-25T00:00:00Z","end_time":"2026-10-25T12:00:00Z"}}}`, `{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"cpu":{"type":"double","time_series_metric":"gauge"}}}`, "ts-id-1"},
		{"time_series", "2026-10-25T12:00:00Z", "2026-10-24T12:00:00Z", `{"index":{"mode":"time_series","sort":{"field":"@timestamp"}}}`, `{"properties":{"@timestamp":{"type":"date"},"dim":{"type":"keyword"}}}`, "bad"},
		{"standard", "", "", `{"index":{"routing_path":["host"]}}`, `{"_source":{"mode":"synthetic"},"properties":{"k":{"type":"keyword"}}}`, ""},
		{"logsdb", "", "", `{"index":{"mode":"logsdb","lookahead_time":"30m"}}`, `{"properties":{"msg":{"type":"text"}}}`, "doc-99"},
	}
	for _, s := range seeds {
		f.Add(s.mode, s.endCur, s.endNext, []byte(s.settings), []byte(s.mapping), s.docID)
	}
	f.Fuzz(func(t *testing.T, mode, endCur, endNext string, rawSettings, rawMapping []byte, docID string) {
		if len(rawSettings) > 8192 || len(rawMapping) > 8192 || len(mode) > 64 || len(docID) > 512 {
			return
		}
		var settings map[string]any
		_ = json.Unmarshal(rawSettings, &settings)
		_ = ValidateIndexModeSettings(mode, settings)
		_ = ValidateTSDBEndTimeUpdate(endCur, endNext)
		_ = ValidateTSDBDocID(docID, "ts_idx")

		var m esast.MappingSpec
		if json.Unmarshal(rawMapping, &m) == nil {
			_ = ValidateTSDBMapping(&m, []string{"host"})
		}
	})
}
