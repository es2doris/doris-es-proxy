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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func buildDeepNestedObjectJSON(depth int) []byte {
	var b strings.Builder
	for i := 0; i < depth; i++ {
		b.WriteString(`{"k":`)
	}
	b.WriteByte('1')
	for i := 0; i < depth; i++ {
		b.WriteByte('}')
	}
	return []byte(b.String())
}

func buildDeepDottedKeyDocJSON(segments int) []byte {
	var b strings.Builder
	b.WriteString(`{"`)
	for i := 0; i < segments; i++ {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteByte('a')
	}
	b.WriteString(`":1}`)
	return []byte(b.String())
}

func TestRound66_VariantNormalizeDepthLimit(t *testing.T) {
	t.Parallel()

	// 1. 50,000-segment dotted key must fail fast with bounded error instead of O(D^2) alloc / stack overflow.
	deepDotted := buildDeepDottedKeyDocJSON(50000)
	for _, s := range []*IndexSchema{
		{},
		{MaxDepth: 100},
		CompileIndexSchema("es_db", "r66_depth_compiled", &esast.MappingSpec{}),
	} {
		_, err := ShredDocument(s, "dos-dotted", 1, false, deepDotted)
		if err == nil || !strings.Contains(err.Error(), "Document nesting depth exceeds limit [64]") {
			t.Fatalf("expected depth-limit error for 50k dotted key on schema %+v, got: %v", s, err)
		}
	}

	// 2. Boundary check: 64 segments / 64 nested maps allowed on uncompiled & MaxDepth:64 schemas; 65 rejected.
	ok64Dotted := buildDeepDottedKeyDocJSON(64)
	if _, err := ShredDocument(&IndexSchema{}, "ok-64-dot", 1, false, ok64Dotted); err != nil {
		t.Fatalf("expected 64-segment dotted key to succeed on unbounded IndexSchema, got: %v", err)
	}
	bad65Dotted := buildDeepDottedKeyDocJSON(65)
	if _, err := ShredDocument(&IndexSchema{}, "bad-65-dot", 1, false, bad65Dotted); err == nil || !strings.Contains(err.Error(), "[64]") {
		t.Fatalf("expected 65-segment dotted key to fail [64], got: %v", err)
	}

	ok64Nested := buildDeepNestedObjectJSON(64)
	if _, err := ShredDocument(&IndexSchema{}, "ok-64-obj", 1, false, ok64Nested); err != nil {
		t.Fatalf("expected 64 nested objects to succeed on unbounded IndexSchema, got: %v", err)
	}
	bad65Nested := buildDeepNestedObjectJSON(65)
	if _, err := ShredDocument(&IndexSchema{}, "bad-65-obj", 1, false, bad65Nested); err == nil || !strings.Contains(err.Error(), "[64]") {
		t.Fatalf("expected 65 nested objects to fail [64], got: %v", err)
	}

	// 3. Deeply nested slices must also be rejected cleanly.
	var sbSlices strings.Builder
	sbSlices.WriteString(`{"arr":`)
	for i := 0; i < 66; i++ {
		sbSlices.WriteByte('[')
	}
	sbSlices.WriteByte('1')
	for i := 0; i < 66; i++ {
		sbSlices.WriteByte(']')
	}
	sbSlices.WriteByte('}')
	if _, err := ShredDocument(&IndexSchema{}, "bad-slices", 1, false, []byte(sbSlices.String())); err == nil || !strings.Contains(err.Error(), "[64]") {
		t.Fatalf("expected 66 nested slices to fail [64], got: %v", err)
	}

	// 4. Deeply nested slices on a histogram field must fail cleanly rather than overflowing stack.
	var histSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"h":{"type":"histogram"}}}`), &histSpec); err != nil {
		t.Fatal(err)
	}
	histIdx := CompileIndexSchema("es_db", "r66_hist_depth", &histSpec)
	var histSlices strings.Builder
	histSlices.WriteString(`{"h":`)
	for i := 0; i < 70; i++ {
		histSlices.WriteByte('[')
	}
	histSlices.WriteString(`{"values":[1],"counts":[1]}`)
	for i := 0; i < 70; i++ {
		histSlices.WriteByte(']')
	}
	histSlices.WriteByte('}')
	if _, err := ShredDocument(histIdx, "bad-hist-slices", 1, false, []byte(histSlices.String())); err == nil {
		t.Fatalf("expected deeply nested histogram slices to return bounded depth error")
	}

	// 5. Direct helper depth bounds on normalizeVariantDocMapWithDepth & mergeVariantValueWithDepth.
	dottedMap := map[string]any{strings.Repeat("x.", 50000) + "leaf": 1}
	if _, _, err := normalizeVariantDocMapWithDepth(dottedMap, nil, "", 1, maxVariantNormalizeDepth); err == nil {
		t.Fatalf("expected normalizeVariantDocMapWithDepth to reject 50k dotted key")
	}
	if _, err := mergeVariantValueWithDepth(map[string]any{"a": 1}, map[string]any{"b": 2}, maxVariantNormalizeDepth+1, maxVariantNormalizeDepth); err == nil {
		t.Fatalf("expected mergeVariantValueWithDepth beyond maxDepth to fail")
	}
}

func FuzzShredVariantAndHistogram(f *testing.F) {
	f.Add([]byte(`{"a.b.c":1,"a":{"b":{"d":2}},"h":{"values":[1.0,2.0],"counts":[3,4]}}`), uint8(5), false)
	f.Add(buildDeepDottedKeyDocJSON(128), uint8(70), true)
	f.Add([]byte(`{"h":[[{"values":[1.5,2.5],"counts":[0,2]}]]}`), uint8(2), false)
	f.Add([]byte(`{"x":{"y":{"z":[1,2,3]}}}`), uint8(80), true)

	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"h":{"type":"histogram","ignore_malformed":true}}}`), &spec)
	histIdx := CompileIndexSchema("es_db", "fuzz_var_hist", &spec)
	unboundedIdx := &IndexSchema{}

	f.Fuzz(func(t *testing.T, raw []byte, dotRepeat uint8, useHist bool) {
		if len(raw) > 16384 {
			return
		}
		// Exercise ShredDocument on arbitrary bytes plus synthesized deeply dotted keys.
		for _, idx := range []*IndexSchema{unboundedIdx, histIdx} {
			if out, err := ShredDocument(idx, "fuzz", 1, false, raw); err == nil {
				if !json.Valid(out) {
					t.Fatalf("ShredDocument returned invalid JSON: %s", string(out))
				}
			}
		}

		// Exercise dotted-key variant normalization & merging directly with controlled fan-out.
		segs := int(dotRepeat%100) + 1
		dottedKey := strings.Repeat("d.", segs) + "v"
		m1 := map[string]any{dottedKey: 1, "d": map[string]any{"other": 2}}
		m2 := map[string]any{"d": map[string]any{"extra": 3}}
		_, _, errNorm := normalizeVariantDocMapWithDepth(m1, histIdx, "", 1, maxVariantNormalizeDepth)
		if segs+1 > maxVariantNormalizeDepth && errNorm == nil {
			t.Fatalf("expected error for dotted depth %d > %d", segs+1, maxVariantNormalizeDepth)
		}
		_, _ = mergeVariantValueWithDepth(m1, m2, 1, maxVariantNormalizeDepth)
		_, _, _ = normalizeVariantDocSliceWithDepth([]any{m1, []any{m2}}, histIdx, "arr", 1, maxVariantNormalizeDepth)

		// Exercise histogram validation directly.
		var parsed map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&parsed) == nil && parsed != nil {
			if useHist {
				_, _, _, _, _ = validateSingleHistogramObject(parsed, "h")
			}
			_, _ = buildVariantDocPayloadWithError(raw, parsed, false, unboundedIdx)
		}
	})
}

func TestRound66_ShredDocumentNestingPropertyBased(t *testing.T) {
	t.Parallel()

	genDoc := func(seed uint64, maxNodes int) ([]byte, int) {
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		maxObservedDepth := 1
		var buildNode func(curDepth int, budget *int) any
		buildNode = func(curDepth int, budget *int) any {
			if curDepth > maxObservedDepth {
				maxObservedDepth = curDepth
			}
			if *budget <= 0 || curDepth >= 96 {
				switch rng.IntN(4) {
				case 0:
					return rng.IntN(1000)
				case 1:
					return fmt.Sprintf("v_%d", rng.IntN(100))
				case 2:
					return rng.IntN(2) == 0
				default:
					return nil
				}
			}
			*budget--
			if rng.IntN(3) == 0 {
				n := rng.IntN(4)
				arr := make([]any, n)
				for i := 0; i < n; i++ {
					arr[i] = buildNode(curDepth+1, budget)
				}
				return arr
			}
			n := rng.IntN(3) + 1
			obj := make(map[string]any, n)
			for i := 0; i < n; i++ {
				dots := 0
				if rng.IntN(4) == 0 {
					dots = rng.IntN(40)
				}
				var kb strings.Builder
				for d := 0; d <= dots; d++ {
					if d > 0 {
						kb.WriteByte('.')
					}
					kb.WriteByte('k')
					kb.WriteByte(byte('0' + (d % 10)))
				}
				effDepth := curDepth + dots
				if effDepth > maxObservedDepth {
					maxObservedDepth = effDepth
				}
				if rng.IntN(5) == 0 {
					// Keep child object nested inside to stress both dots and objects.
					sub := buildNode(effDepth+1, budget)
					obj[kb.String()] = sub
				} else {
					obj[kb.String()] = "leaf"
				}
			}
			return obj
		}
		budget := maxNodes
		root := map[string]any{}
		if v := buildNode(1, &budget); v != nil {
			if m, ok := v.(map[string]any); ok {
				root = m
			} else {
				root["root"] = v
			}
		}
		b, _ := json.Marshal(root)
		return b, maxObservedDepth
	}

	unboundedIdx := &IndexSchema{}
	cfg := &quick.Config{MaxCount: 250}
	prop := func(seed uint64) bool {
		raw, _ := genDoc(seed, 48)
		out, err := ShredDocument(unboundedIdx, "prop-1", 1, false, raw)
		if err != nil {
			// Bounded error must be clean without panic/OOM.
			return len(err.Error()) > 0
		}
		if !json.Valid(out) {
			return false
		}
		var row map[string]any
		if uErr := json.Unmarshal(out, &row); uErr != nil {
			return false
		}
		return row["_id"] == "prop-1" && row["_doc"] != nil
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("ShredDocument property check failed: %v", err)
	}
}

func TestRound66_GeoPointStringElemAndLonWrapping(t *testing.T) {
	t.Parallel()

	// 1. Strict (ignore_malformed=false): `[182.22, "20.12"]` wraps lon to -177.78 and parses numeric string lat 20.12.
	var strictSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"location":{"type":"geo_point"}}}`), &strictSpec); err != nil {
		t.Fatal(err)
	}
	strictIdx := CompileIndexSchema("es_db", "r66_geo_strict", &strictSpec)

	rowBytes, err := ShredDocument(strictIdx, "003", 1, false, []byte(`{"location":[182.22, "20.12"]}`))
	if err != nil {
		t.Fatalf("expected [182.22, \"20.12\"] to succeed with lon wrapping, got: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(rowBytes, &row); err != nil {
		t.Fatal(err)
	}
	if row["f__location"] != "20.12,-177.78" {
		t.Fatalf("expected normalized geo_point \"20.12,-177.78\", got %#v", row["f__location"])
	}

	// Numeric string array `["45.99", "9.16"]` has string as element 0 (ES multi-value string mode, NOT [lon, lat]).
	if _, err := ShredDocument(strictIdx, "006", 1, false, []byte(`{"location":["45.99", "9.16"]}`)); err == nil {
		t.Fatalf("expected [\"45.99\", \"9.16\"] to fail when ignore_malformed=false")
	}

	// ignore_malformed=true matches `aggregations/ignored_metadata_field.yml` docs 003, 005, 006:
	// doc 003 (`[182.22, "20.12"]`) & doc 005 (`["45.33, 8.20"]`) succeed; doc 006 (`["45.99", "9.16"]`) is ignored.
	var ignSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"location":{"type":"geo_point","ignore_malformed":true}}}`), &ignSpec); err != nil {
		t.Fatal(err)
	}
	ignIdx := CompileIndexSchema("es_db", "r66_geo_ign", &ignSpec)

	for _, tc := range []struct {
		id      string
		doc     string
		want    any
		wantIgn bool
	}{
		{"003", `{"location":[182.22, "20.12"]}`, "20.12,-177.78", false},
		{"005", `{"location":["45.33, 8.20"]}`, "45.33,8.2", false},
		{"006", `{"location":["45.99", "9.16"]}`, nil, true},
	} {
		out, sErr := ShredDocument(ignIdx, tc.id, 1, false, []byte(tc.doc))
		if sErr != nil {
			t.Fatalf("doc %s ShredDocument unexpected err: %v", tc.id, sErr)
		}
		var r map[string]any
		_ = json.Unmarshal(out, &r)
		ign, _ := r["_ignored"].([]any)
		hasIgn := len(ign) > 0
		if hasIgn != tc.wantIgn {
			t.Fatalf("doc %s _ignored=%v, wantIgnored=%v (row=%v)", tc.id, ign, tc.wantIgn, r)
		}
		if !tc.wantIgn && r["f__location"] != tc.want {
			t.Fatalf("doc %s f__location=%#v, want %#v", tc.id, r["f__location"], tc.want)
		}
	}

	// Longitude wrapping & latitude/non-finite rejection boundaries
	for _, tc := range []struct {
		in      any
		wantOK  bool
		wantLat float64
		wantLon float64
	}{
		{[]any{182.22, "20.12"}, true, 20.12, -177.78},
		{[]any{-182.22, "-10.5"}, true, -10.5, 177.78},
		{[]any{180.0, 0.0}, true, 0.0, 180.0},
		{[]any{-180.0, 0.0}, true, 0.0, -180.0},
		{[]any{360.0, 0.0}, true, 0.0, 0.0},
		{map[string]any{"lat": 45.0, "lon": 540.0}, true, 45.0, -180.0},
		{[]any{0.0, 91.0}, false, 0, 0},
		{[]any{0.0, -91.0}, false, 0, 0},
		{[]any{math.NaN(), 0.0}, false, 0, 0},
		{[]any{math.Inf(1), 0.0}, false, 0, 0},
		{[]any{0.0, "NaN"}, false, 0, 0},
		{[]any{0.0, "Inf"}, false, 0, 0},
		{[]any{0.0, "1_0.5"}, false, 0, 0},
		{[]any{0.0, "0x1p2"}, false, 0, 0},
	} {
		_, lat, lon, ok := parseAndFormatGeoPointValue(tc.in)
		if ok != tc.wantOK {
			t.Fatalf("parseAndFormatGeoPointValue(%#v) ok=%v, want %v", tc.in, ok, tc.wantOK)
		}
		if ok && (math.Abs(lat-tc.wantLat) > 1e-9 || math.Abs(lon-tc.wantLon) > 1e-9) {
			t.Fatalf("parseAndFormatGeoPointValue(%#v) = (%v, %v), want (%v, %v)", tc.in, lat, lon, tc.wantLat, tc.wantLon)
		}
	}
}

func TestRound66_JavaFloatDoubleSuffixCoercion(t *testing.T) {
	t.Parallel()

	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"v1":{"type":"double"},"v2":{"type":"float"}}}`), &spec); err != nil {
		t.Fatal(err)
	}
	idx := CompileIndexSchema("es_db", "r66_java_float", &spec)

	out, err := ShredDocument(idx, "1", 1, false, []byte(`{"v1":"1.0d","v2":"10.5F"}`))
	if err != nil {
		t.Fatalf("expected Java float/double suffixes to coerce cleanly, got: %v", err)
	}
	var row map[string]any
	_ = json.Unmarshal(out, &row)
	if row["f__v1"] != 1.0 || row["f__v2"] != 10.5 {
		t.Fatalf("unexpected coerced float/double row values: v1=%#v v2=%#v", row["f__v1"], row["f__v2"])
	}

	for _, tc := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1.0d", 1.0, true},
		{"10.0D", 10.0, true},
		{"-2.5f", -2.5, true},
		{"1e3F", 1000.0, true},
		{"nan", 0, false},
		{"NaNd", 0, false},
		{"inf", 0, false},
		{"Inf", 0, false},
		{"-Infinity", 0, false},
		{"Infinityf", 0, false},
		{"1.0g", 0, false},
		{"1.0dd", 0, false},
		{"1.0 d", 0, false},
		{"1_0.0d", 0, false},
		{"0x1p2d", 0, false},
		{".d", 0, false},
	} {
		got, ok := parseCoercedFloatString(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseCoercedFloatString(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
		if !tc.ok {
			if _, sErr := ShredDocument(idx, "bad", 1, false, []byte(fmt.Sprintf(`{"v1":%q}`, tc.in))); sErr == nil {
				t.Fatalf("expected double field to reject %q", tc.in)
			}
		}
	}
}

func TestRound66_SyntheticSourcePreservesNumericDuplicates(t *testing.T) {
	t.Parallel()

	// Matches `downsample/10_basic.yml` SortedNumericDocValues semantics vs keyword SortedSetDocValues dedup.
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"values": {"type": "integer"},
			"doubles": {"type": "double"},
			"tags": {"type": "keyword"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idx := CompileIndexSchema("es_db", "r66_synth_dups", &spec)
	idx.ES8Mode = true

	shredded, err := ShredDocument(idx, "1", 1, false, []byte(`{"values":[2,1,1],"doubles":[3.5,1.5,3.5],"tags":["prod","backend","prod"]}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	_ = json.Unmarshal(shredded, &row)
	var src map[string]any
	dec := json.NewDecoder(strings.NewReader(row["_source"].(string)))
	dec.UseNumber()
	if err := dec.Decode(&src); err != nil {
		t.Fatal(err)
	}
	wantInts := []any{json.Number("1"), json.Number("1"), json.Number("2")}
	if !reflect.DeepEqual(src["values"], wantInts) {
		t.Fatalf("expected SortedNumericDocValues integer array %v preserving duplicates, got %#v", wantInts, src["values"])
	}
	wantDoubles := []any{json.Number("1.5"), json.Number("3.5"), json.Number("3.5")}
	if !reflect.DeepEqual(src["doubles"], wantDoubles) {
		t.Fatalf("expected SortedNumericDocValues double array %v preserving duplicates, got %#v", wantDoubles, src["doubles"])
	}
	wantTags := []any{"backend", "prod"}
	if !reflect.DeepEqual(src["tags"], wantTags) {
		t.Fatalf("expected SortedSetDocValues keyword array deduplicated %v, got %#v", wantTags, src["tags"])
	}
}

func TestRound66_RangeNullBoundsOffByOneFix(t *testing.T) {
	t.Parallel()

	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"long_range": {"type": "long_range"},
			"int_range": {"type": "integer_range"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idx := CompileIndexSchema("es_db", "r66_range_null", &spec)

	// 1. long_range `gt: null` -> MinInt64+1; `lt: null` -> MaxInt64-1 (`range/10_basic.yml` "Null bounds").
	checkLongRange := func(id, body string, wantGte, wantLte any, wantR string) {
		t.Helper()
		shredded, err := ShredDocument(idx, id, 1, false, []byte(body))
		if err != nil {
			t.Fatalf("doc %s ShredDocument failed: %v", id, err)
		}
		var row map[string]any
		dec := json.NewDecoder(bytes.NewReader(shredded))
		dec.UseNumber()
		_ = dec.Decode(&row)
		rngMap := row["_doc"].(map[string]any)["long_range"].(map[string]any)
		if fmt.Sprintf("%v", rngMap["_gte"]) != fmt.Sprintf("%v", wantGte) ||
			fmt.Sprintf("%v", rngMap["_lte"]) != fmt.Sprintf("%v", wantLte) ||
			!reflect.DeepEqual(rngMap["_r"], []any{wantR}) {
			t.Fatalf("doc %s unexpected range map %#v, want _gte=%v _lte=%v _r=[%q]", id, rngMap, wantGte, wantLte, wantR)
		}
	}

	checkLongRange("1", `{"long_range":{"gt":null,"lte":5}}`, json.Number("-9223372036854775807"), json.Number("5"), "-9223372036854775807,5")
	checkLongRange("2", `{"long_range":{"gte":null,"lte":5}}`, float64(-1e100), json.Number("5"), "-1e100,5")
	checkLongRange("4", `{"long_range":{"gte":10,"lt":null}}`, json.Number("10"), json.Number("9223372036854775806"), "10,9223372036854775806")
	checkLongRange("5", `{"long_range":{"gte":10,"lte":null}}`, json.Number("10"), float64(1e100), "10,1e100")
	checkLongRange("7", `{"long_range":{"gt":null,"lt":null}}`, json.Number("-9223372036854775807"), json.Number("9223372036854775806"), "-9223372036854775807,9223372036854775806")

	// 2. integer_range `gt: null` -> MinInt32+1; `lt: null` -> MaxInt32-1.
	irBytes, err := ShredDocument(idx, "ir1", 1, false, []byte(`{"int_range":{"gt":null,"lt":null}}`))
	if err != nil {
		t.Fatalf("integer_range gt:null, lt:null failed: %v", err)
	}
	var irRow map[string]any
	dec := json.NewDecoder(bytes.NewReader(irBytes))
	dec.UseNumber()
	_ = dec.Decode(&irRow)
	irMap := irRow["_doc"].(map[string]any)["int_range"].(map[string]any)
	if fmt.Sprintf("%v", irMap["_gte"]) != fmt.Sprintf("%d", math.MinInt32+1) ||
		fmt.Sprintf("%v", irMap["_lte"]) != fmt.Sprintf("%d", math.MaxInt32-1) {
		t.Fatalf("integer_range unexpected bounds: %#v", irMap)
	}

	// 3. Conflicting null + concrete bound must fail cleanly.
	for _, bad := range []string{
		`{"long_range":{"gt":null,"gte":1}}`,
		`{"long_range":{"lt":null,"lte":1}}`,
		`{"int_range":{"gt":null,"lte":-2147483648}}`,
	} {
		if _, err := ShredDocument(idx, "bad-range", 1, false, []byte(bad)); err == nil {
			t.Fatalf("expected error for invalid range %s", bad)
		}
	}
}

func BenchmarkBuildVariantDocPayload_DottedRejectAndValid(b *testing.B) {
	deepDoc := buildDeepDottedKeyDocJSON(50000)
	validDoc := []byte(`{"a.b.c":1,"a":{"b":{"d":[1,2,3]}}}`)
	idx := &IndexSchema{}

	b.Run("Reject50kDotted", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ShredDocument(idx, "id", 1, false, deepDoc); err == nil {
				b.Fatal("expected error")
			}
		}
	})
	b.Run("ValidDotted", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ShredDocument(idx, "id", 1, false, validDoc); err != nil {
				b.Fatal(err)
			}
		}
	})
}
