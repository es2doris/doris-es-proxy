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

package transpiler

import (
	"strings"
	"testing"
)

func TestRound64W3CommonTermsCutoffFrequencySplit(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"body": {"type": "text"}
		}
	}`)
	opts := TranspilerOptions{
		TermDocFreqFn: func(_ string, terms []string, _ bool) (int, map[string]int) {
			freqs := make(map[string]int, len(terms))
			for _, term := range terms {
				switch term {
				case "the":
					freqs[term] = 8
				default:
					freqs[term] = 1
				}
			}
			return 10, freqs
		},
	}
	tr := NewTranspiler(sch, opts)
	req := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"match": {
				"body": {
					"query": "the quick",
					"cutoff_frequency": 0.5
				}
			}
		}
	}`)
	plan, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	// Since "quick" (df=1/10 <= 0.5) is low-frequency and "the" (df=8/10 > 0.5) is high-frequency,
	// CommonTermsQuery requires low-frequency ("quick") and keeps high-frequency ("the") optional.
	if !strings.Contains(plan.HitsSQL, "quick") || !strings.Contains(plan.HitsSQL, "the") {
		t.Fatalf("expected both quick and the in HitsSQL, got: %s", plan.HitsSQL)
	}
	reqOnlyHigh := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"common": {
				"body": {
					"query": "the",
					"cutoff_frequency": 0.5,
					"high_freq_operator": "and"
				}
			}
		}
	}`)
	planHigh, err := tr.BuildSearchPlan(reqOnlyHigh)
	if err != nil {
		t.Fatalf("BuildSearchPlan common high-only failed: %v", err)
	}
	if !strings.Contains(planHigh.HitsSQL, "the") {
		t.Fatalf("expected 'the' in common high-only SQL, got: %s", planHigh.HitsSQL)
	}
}
