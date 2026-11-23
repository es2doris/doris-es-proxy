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

package analysis

import (
	"testing"
)

func TestRound65_OfflineCoverage_Analysis_W4(t *testing.T) {
	// 1. katakanaToHiragana (`plugins_analysis.go:1616`)
	if got := katakanaToHiragana("カタカナabcーァヶ"); got != "かたかなabcーぁゖ" {
		t.Fatalf("unexpected katakanaToHiragana: %q", got)
	}

	// 2. classifyNoriPOS (`plugins_analysis.go:1979`)
	if got := classifyNoriPOS(Token{Type: "VV"}); got != "NNG" {
		t.Fatalf("expected fallback NNG for VV, got %q", got)
	}
	if got := classifyNoriPOS(Token{Type: "UNKNOWN", Term: "은"}); got != "J" {
		t.Fatalf("expected Korean particle class J, got %q", got)
	}
	if got := classifyNoriPOS(Token{Type: "NR", Term: "하나"}); got != "NR" {
		t.Fatalf("expected NR preserved, got %q", got)
	}

	// 3. toFloat64Script (`script_eval.go:608`)
	for _, tc := range []struct {
		in   any
		want float64
		ok   bool
	}{
		{float64(1.5), 1.5, true},
		{float32(2.5), 2.5, true},
		{int(3), 3, true},
		{int64(4), 4, true},
		{int32(5), 5, true},
		{"not-float", 0, false},
	} {
		got, ok := toFloat64Script(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("toFloat64Script(%#v) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	// 4. parseGramIntValue (`tokenizers.go:381`)
	for _, tc := range []struct {
		in   any
		want int
		ok   bool
	}{
		{int(4), 4, true},
		{" 7, ", 7, true},
		{"bad", 0, false},
	} {
		got, ok := parseGramIntValue(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseGramIntValue(%#v) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	// 5. Custom normalizer with pattern_replace filter (`analysis-common/40_token_filters.yml`)
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analysis.filter.my_pattern_replace.type":        "pattern_replace",
		"index.analysis.filter.my_pattern_replace.pattern":     "^0+",
		"index.analysis.filter.my_pattern_replace.replacement": "",
		"index.analysis.normalizer.my_norm.type":               "custom",
		"index.analysis.normalizer.my_norm.filter":             []any{"lowercase", "my_pattern_replace"},
	}, Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}
	normed, err := NormalizeTerm("000000ABC", "my_norm", cfg, Options{})
	if err != nil || normed != "abc" {
		t.Fatalf("expected NormalizeTerm(\"000000ABC\") = \"abc\", got %q err=%v", normed, err)
	}
}
