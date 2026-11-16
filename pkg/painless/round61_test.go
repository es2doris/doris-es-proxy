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
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRound61Painless_F21_ScriptSpecStringShorthandAndCtxGuards(t *testing.T) {
	// 1. JSON string shorthand
	var shorthand ScriptSpec
	if err := json.Unmarshal([]byte(`"ctx._source.count = 42"`), &shorthand); err != nil {
		t.Fatalf("unmarshal string shorthand failed: %v", err)
	}
	if shorthand.EffectiveSource() != "ctx._source.count = 42" || shorthand.Lang != "painless" {
		t.Fatalf("unexpected shorthand ScriptSpec: %+v", shorthand)
	}

	// 2. JSON object form with inline/source + params
	var objSpec ScriptSpec
	if err := json.Unmarshal([]byte(`{"source":"ctx._source.count += params.inc","params":{"inc":5}}`), &objSpec); err != nil {
		t.Fatalf("unmarshal object ScriptSpec failed: %v", err)
	}
	doc := map[string]any{"count": int64(10)}
	if op, err := EvalPainlessWithOp(doc, shorthand.EffectiveSource(), shorthand.Params); err != nil || (op != "" && op != "index") || doc["count"] != int64(42) {
		t.Fatalf("shorthand eval failed: op=%q err=%v doc=%v", op, err, doc)
	}
	if op, err := EvalPainlessWithOp(doc, objSpec.EffectiveSource(), objSpec.Params); err != nil || (op != "" && op != "index") || fmt.Sprintf("%v", doc["count"]) != "47" {
		t.Fatalf("object eval failed: op=%q err=%v doc=%v", op, err, doc)
	}
	if op, err := EvalPainlessWithOp(doc, "ctx.op = 'noop'", nil); err != nil || op != "noop" {
		t.Fatalf("explicit ctx.op eval failed: op=%q err=%v", op, err)
	}

	// 3. Unknown ctx key -> illegal_argument_exception
	_, err := EvalPainlessWithOp(map[string]any{"a": 1}, "ctx.junk = 1", map[string]any{"__is_update_doc": true})
	if err == nil || !strings.Contains(err.Error(), "junk") {
		t.Fatalf("expected unknown ctx.junk error, got %v", err)
	}

	// 4. Modifying ctx._id -> illegal_argument_exception
	_, err = EvalPainlessWithOp(map[string]any{"a": 1}, "ctx._id = 'mutated'", map[string]any{"_ctx_id": "orig", "__is_update_doc": true})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "_id") {
		t.Fatalf("expected ctx._id immutability error, got %v", err)
	}

	// 5. Invalid ctx.op & ES 8 ctx._version = -1 guard
	if err := ValidateUpdateCtxOp("bogus"); err == nil {
		t.Fatalf("expected invalid update ctx.op error")
	}
	if err := ValidateUBQCtxOp("none", true); err == nil {
		t.Fatalf("expected ES 8 UBQ ctx.op='none' to be rejected")
	}
	if err := ValidateUBQCtxOp("bogus", false); err == nil {
		t.Fatalf("expected ES 7 UBQ ctx.op='bogus' to be rejected")
	}
	if err := ValidateCtxVersion(int64(-1), true, true, true); err == nil {
		t.Fatalf("expected ES 8 mutated ctx._version=-1 to be rejected")
	}
	if err := ValidateCtxVersion(int64(-1), false, true, true); err != nil {
		t.Fatalf("expected ES 8 unmutated UBQ ctx._version=-1 to be allowed, got %v", err)
	}

	// 6. Self-referencing `ctx._source.ctx = ctx` -> ErrSelfReferencingIterable (`15_update.yml:120`)
	_, err = EvalPainlessWithOp(map[string]any{"x": 1}, "ctx._source.ctx = ctx", map[string]any{"__is_update_doc": true})
	if !errors.Is(err, ErrSelfReferencingIterable) {
		t.Fatalf("expected ErrSelfReferencingIterable on ctx._source.ctx = ctx, got %v", err)
	}
}

func TestRound61Painless_F24_DocValueGuardsTypedWrappersBooleanDupsAndJoda(t *testing.T) {
	rawDoc := map[string]any{
		"boolean":              []any{true, false, false},
		"boolean_no_dv":        true,
		"text":                 "Lots of text.",
		"text_no_fd":           "Lots of text.",
		"match_only_text":      []any{"Lots of text.", "even more text", "SOOOOO much text"},
		"token_count":          "count all these words please",
		"float":                3.141592654,
		"half_float":           3.141592654,
		"date":                 "2017/01/01",
		"iso_date":             "2017-01-01T12:11:12Z",
		"geo_point":            "41.12,-71.34",
		"ip":                   []any{"2001:db8::2:1", "10.1.2.3"},
		"flattened":            map[string]any{"top": 123, "dict": map[string]any{"abc": "def", "hij": "lmn"}, "list": []any{true}},
		"__meta_version":       int64(60),
		"__meta_seq_no":        int64(1),
		"__quantize_geo_point": true,
		"__field_formats":      map[string]string{"date": "yyyy/MM/dd"},
		"__field_types": map[string]string{
			"boolean":         "boolean",
			"boolean_no_dv":   "boolean",
			"text":            "text",
			"text_no_fd":      "text",
			"match_only_text": "match_only_text",
			"token_count":     "token_count",
			"float":           "float",
			"half_float":      "half_float",
			"date":            "date",
			"iso_date":        "date",
			"geo_point":       "geo_point",
			"ip":              "ip",
			"flattened":       "flattened",
		},
		"__disabled_doc_values": map[string]string{
			"boolean_no_dv":   DocValuesDisabledMessage("boolean_no_dv", "test", "boolean"),
			"text_no_fd":      DocValuesDisabledMessage("text_no_fd", "test", "text"),
			"match_only_text": DocValuesDisabledMessage("match_only_text", "test", "match_only_text"),
		},
	}
	evalDoc := make(map[string]any, len(rawDoc)+1)
	for k, v := range rawDoc {
		evalDoc[k] = v
	}
	evalDoc["__raw_source"] = rawDoc

	// 1. Guards on doc['...'] vs fallback to _source on field('...') / $('...')
	for _, blocked := range []string{"boolean_no_dv", "text_no_fd", "match_only_text"} {
		if _, err := Eval(evalDoc, fmt.Sprintf("doc['%s'].value", blocked), nil); err == nil {
			t.Fatalf("expected doc['%s'] to fail with illegal_argument_exception", blocked)
		}
	}
	if v, err := Eval(evalDoc, "$('boolean_no_dv', false)", nil); err != nil || v != true {
		t.Fatalf("expected $('boolean_no_dv', false) == true via _source, got %v (err=%v)", v, err)
	}
	// Disabled _source + disabled doc_values + store=false -> field('f') fails
	disabledSrcDoc := map[string]any{
		"__disabled_fields_api": map[string]string{
			"secret": FieldsAPIDisabledMessage("secret", "test"),
		},
	}
	if _, err := Eval(disabledSrcDoc, "field('secret').get('x')", nil); err == nil {
		t.Fatalf("expected field('secret') to fail when _source, doc_values, and store are all disabled")
	}

	// 2. 45_script_doc_values_cache.yml: $('text', '') + ' ' + doc['text'].value == 'Lots of text. lots'
	if v, err := Eval(evalDoc, "$('text', '') + ' ' + doc['text'].value", nil); err != nil || v != "Lots of text. lots" {
		t.Fatalf("expected 'Lots of text. lots', got %v (err=%v)", v, err)
	}

	// 3. match_only_text sorted raw values via field('match_only_text')
	if v, err := Eval(evalDoc, "String cat = ''; for (String s : field('match_only_text')) { cat += s; } cat + field('match_only_text').size();", nil); err != nil || v != "Lots of text.SOOOOO much texteven more text3" {
		t.Fatalf("unexpected match_only_text field iteration: %v (err=%v)", v, err)
	}

	// 4. token_count, float, half_float, flattened, _version & _seq_no
	if v, err := Eval(evalDoc, "doc['token_count'].value", nil); err != nil || v != int64(5) {
		t.Fatalf("expected token_count=5, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "doc['half_float'].value", nil); err != nil || math.Abs(v.(float64)-3.140625) > 1e-9 {
		t.Fatalf("expected IEEE-754 binary16 quantized half_float=3.140625, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "field('half_float').asDouble(0.0)", nil); err != nil || math.Abs(v.(float64)-3.140625) > 1e-9 {
		t.Fatalf("expected field('half_float').asDouble(0.0)=3.140625, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "field('flattened.dict.abc').get('dne') + '|' + doc['flattened'].size()", nil); err != nil || v != "def|4" {
		t.Fatalf("unexpected flattened access result: %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "field('_version').get(0) + ':' + field('_seq_no').get(0)", nil); err != nil || v != "60:1" {
		t.Fatalf("unexpected _version/_seq_no result: %v (err=%v)", v, err)
	}

	// 5. ES 8 non-dedup boolean [false, false, true] vs ES 7 dedup [false, true]
	evalDoc["__keep_boolean_dups"] = true
	if v, err := Eval(evalDoc, "doc['boolean'].size()", nil); err != nil || v != int64(3) {
		t.Fatalf("expected ES 8 boolean doc-values size 3 ([false, false, true]), got %v (err=%v)", v, err)
	}
	evalDoc["__keep_boolean_dups"] = false
	if v, err := Eval(evalDoc, "doc['boolean'].size()", nil); err != nil || v != int64(2) {
		t.Fatalf("expected ES 7 deduplicated boolean doc-values size 2 ([false, true]), got %v (err=%v)", v, err)
	}

	// 6. Custom-format date, DayOfWeekEnum.getDisplayName, IsoFields, 14 Joda methods & unknown ZonedDateTime method
	if v, err := Eval(evalDoc, "doc.date.value.dayOfWeekEnum.getDisplayName(TextStyle.FULL, Locale.ENGLISH)", nil); err != nil || v != "Sunday" {
		t.Fatalf("expected Sunday from yyyy/MM/dd 2017/01/01, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "doc['iso_date'].value.get(IsoFields.WEEK_OF_WEEK_BASED_YEAR) + ':' + doc['iso_date'].value.get(IsoFields.WEEK_BASED_YEAR)", nil); err != nil || v != "52:2016" {
		t.Fatalf("expected IsoFields 52:2016 on 2017-01-01, got %v (err=%v)", v, err)
	}
	deprecatedJoda := []string{
		"getCenturyOfEra", "getEra", "getHourOfDay", "getMillisOfDay", "getMillisOfSecond",
		"getMinuteOfDay", "getMinuteOfHour", "getMonthOfYear", "getSecondOfDay", "getSecondOfMinute",
		"getWeekOfWeekyear", "getWeekyear", "getYearOfCentury", "getYearOfEra",
	}
	for _, mName := range deprecatedJoda {
		_, err := Eval(evalDoc, fmt.Sprintf("doc['iso_date'].value.%s()", mName), nil)
		if err == nil || !strings.Contains(err.Error(), "UnsupportedOperationException") || !strings.Contains(err.Error(), "is no longer available") {
			t.Fatalf("expected UnsupportedOperationException for %s(), got %v", mName, err)
		}
	}
	if _, err := Eval(evalDoc, "doc['iso_date'].value.totallyBogusMethod()", nil); err == nil || !strings.Contains(err.Error(), "IllegalArgumentException") {
		t.Fatalf("expected IllegalArgumentException on unknown ZonedDateTime method, got %v", err)
	}

	// 7. IPAddress & quantized GeoPoint + GeoBoundingBox
	if v, err := Eval(evalDoc, "IPAddress a = new IPAddress('10.1.2.3'); a.isIPv4() && field('ip').asString(null) == '10.1.2.3'", nil); err != nil || v != true {
		t.Fatalf("expected IPAddress check true, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "doc['geo_point'].value.lat", nil); err != nil || math.Abs(v.(float64)-41.1199999647215) > 1e-12 {
		t.Fatalf("expected Lucene quantized lat 41.1199999647215, got %v (err=%v)", v, err)
	}
	if v, err := Eval(evalDoc, "doc['geo_point'].getBoundingBox().topLeft.lon", nil); err != nil || math.Abs(v.(float64)-(-71.34000004269183)) > 1e-12 {
		t.Fatalf("expected GeoBoundingBox topLeft.lon -71.34000004269183, got %v (err=%v)", v, err)
	}
}

func TestRound61Painless_F25_VectorFloat32HexByteBitAndDenseVectorFieldVal(t *testing.T) {
	doc := map[string]any{
		"fvec": []any{0.1, 0.2, 0.3},
		"bvec": "02fe09", // [2, -2, 9]
		"__field_types": map[string]string{
			"fvec":        "dense_vector",
			"bvec":        "dense_vector",
			"missing_vec": "dense_vector",
		},
		"__vector_element_types": map[string]string{
			"fvec":        "float",
			"bvec":        "byte",
			"missing_vec": "float",
		},
	}

	// 1. Exact runtime float32 accumulation matching Java VectorUtil.dotProduct (non-FMA IEEE-754 float32)
	q := []any{0.4, 0.5, 0.6}
	p0 := math.Float32frombits(math.Float32bits(float32(0.1) * float32(0.4)))
	p1 := math.Float32frombits(math.Float32bits(float32(0.2) * float32(0.5)))
	p2 := math.Float32frombits(math.Float32bits(float32(0.3) * float32(0.6)))
	sumF32 := math.Float32frombits(math.Float32bits(p0 + p1))
	sumF32 = math.Float32frombits(math.Float32bits(sumF32 + p2))
	wantDot := float64(sumF32)
	gotDot, err := EvalScore(doc, "dotProduct(params.q, 'fvec')", map[string]any{"q": q})
	if err != nil || gotDot != wantDot {
		t.Fatalf("expected exact float32 dotProduct %.17g, got %.17g (err=%v)", wantDot, gotDot, err)
	}

	// 2. Hex-encoded signed byte vector in both doc and params ("02fe09" = [2, -2, 9], "01ff02" = [1, -1, 2] -> dot = 2 + 2 + 18 = 22)
	gotByteDot, err := EvalScore(doc, "dotProduct(params.hexQ, 'bvec')", map[string]any{"hexQ": "01ff02"})
	if err != nil || gotByteDot != 22.0 {
		t.Fatalf("expected hex byte dotProduct=22.0, got %v (err=%v)", gotByteDot, err)
	}

	// 3. DenseVectorFieldVal methods on field('bvec') / $('bvec') + missing 2-arg default + non-iterable guard
	v, err := Eval(doc, "field('bvec').size() + ':' + field('bvec').get(1) + ':' + field('bvec').dotProduct(params.hexQ)", map[string]any{"hexQ": "01ff02"})
	if err != nil || (v != "3:-2.0:22" && v != "3:-2.0:22.0") {
		t.Fatalf("unexpected DenseVectorFieldVal result: %v (err=%v)", v, err)
	}
	if mv, err := Eval(doc, "$('missing_vec', null)", nil); err != nil || mv != nil {
		t.Fatalf("expected $('missing_vec', null) == nil, got %v (err=%v)", mv, err)
	}
	_, iterErr := Eval(doc, "double s = 0; for (def x : field('fvec')) { s += x; } return s;", nil)
	if iterErr == nil || !strings.Contains(iterErr.Error(), "UnsupportedOperationException") {
		t.Fatalf("expected UnsupportedOperationException iterating field('fvec'), got %v", iterErr)
	}
}

func TestRound61Painless_F26_MutableWriteFieldAPIAndUpdateMetadata(t *testing.T) {
	doc := map[string]any{
		"count": int64(5),
		"old":   "remove_me",
		"nest":  map[string]any{"bar": int64(10)},
	}
	params := map[string]any{
		"__is_update_doc": true,
		"__is_es8":        true,
		"_ctx_id":         "doc-1",
		"_ctx_index":      "idx-1",
		"_ctx_version":    int64(3),
	}
	src := `
		field('a.b').set(123);
		field('old').remove();
		field('count').transform(v -> v + 10);
		field('nest').doc().field('bar').set(200);
		if (metadata().id == 'doc-1') {
			metadata().op = 'noop';
		}
	`
	op, err := EvalPainlessWithOp(doc, src, params)
	if err != nil || op != "noop" {
		t.Fatalf("mutable Write Fields API failed: op=%q err=%v", op, err)
	}
	if _, stillHasOld := doc["old"]; stillHasOld {
		t.Fatalf("expected field('old').remove() to delete key, got %v", doc)
	}
	aMap, _ := doc["a"].(map[string]any)
	nestMap, _ := doc["nest"].(map[string]any)
	if aMap["b"] != int64(123) || doc["count"] != int64(15) || nestMap["bar"] != int64(200) {
		t.Fatalf("unexpected mutated doc: %v", doc)
	}

	// Upsert routing guard
	if err := CheckUpsertRoutingGuardRound61(true, "", "", "", false); err == nil {
		t.Fatalf("expected routing_missing_exception when routing is required and absent")
	}
	if err := CheckUpsertRoutingGuardRound61(false, "r1", "", "r2", false); err == nil {
		t.Fatalf("expected illegal_argument_exception when mutating _routing on upsert")
	}
}

func TestRound61Painless_F29_DoSHardeningPinnedCapsAndBoundedRegexCache(t *testing.T) {
	// 1. Regex pattern length cap (> 4096 rejected)
	oversized := strings.Repeat("a", MaxRegexPatternLen+1)
	if _, err := CompileBoundedRegex(oversized); err == nil {
		t.Fatalf("expected CompileBoundedRegex to reject pattern > %d chars", MaxRegexPatternLen)
	}
	if _, err := Eval(map[string]any{}, "Pattern.compile(params.p)", map[string]any{"p": oversized}); err == nil {
		t.Fatalf("expected Pattern.compile to reject oversized pattern")
	}

	// 2. Concurrent bounded LRU cache stress test (> RegexCacheCapacity = 1024 entries under -race)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pat := fmt.Sprintf("^item_%d_%d_(?<id>[0-9]+)$", worker, i)
				re, err := CompileBoundedRegex(pat)
				if err != nil || re == nil {
					t.Errorf("CompileBoundedRegex(%q) failed: %v", pat, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// 3. MaxPinnedElements (262,144) across multiple bounded 10,000-element allocations cannot be bypassed even by try/catch(Exception)
	_, err := Eval(map[string]any{}, `
		int total = 0;
		try {
			for (int i = 0; i < 30; i++) {
				List chunk = Collections.nCopies(10000, i);
				total += chunk.size();
			}
		} catch (Exception e) {
			return -1;
		}
		return total;
	`, nil)
	if err == nil || !strings.Contains(err.Error(), "PainlessError") {
		t.Fatalf("expected uncatchable PainlessError exceeding MaxPinnedElements, got %v", err)
	}

	// 4. MaxPinnedRefs (4,096) cannot be bypassed by try/catch(Exception)
	_, err = Eval(map[string]any{}, `
		int n = 0;
		try {
			for (int i = 0; i < 1500; i++) {
				List a = List.of(i);
				List b = List.of(i);
				List c = List.of(i);
				n += a.size() + b.size() + c.size();
			}
		} catch (Exception e) {
			return -1;
		}
		return n;
	`, nil)
	if err == nil || !strings.Contains(err.Error(), "PainlessError") {
		t.Fatalf("expected uncatchable PainlessError exceeding MaxPinnedRefs, got %v", err)
	}
}

func TestRound61Painless_CoverageAnalyzersGeoIPTimeAndVectors(t *testing.T) {
	// 1. AnalyzeStandardFielddataTokens & CountStandardAnalyzerTokens across nil, []any, []string, numeric, scalar
	if got := AnalyzeStandardFielddataTokens(nil); len(got) != 0 {
		t.Fatalf("expected empty tokens for nil, got %v", got)
	}
	if got := AnalyzeStandardFielddataTokens("   ...   "); len(got) != 0 {
		t.Fatalf("expected empty tokens for punctuation, got %v", got)
	}
	toks := AnalyzeStandardFielddataTokens([]any{nil, []string{"Beta Alpha", "alpha"}, 42})
	if len(toks) != 3 || toks[0] != "42" || toks[1] != "alpha" || toks[2] != "beta" {
		t.Fatalf("unexpected AnalyzeStandardFielddataTokens: %v", toks)
	}
	if c, ok := CountStandardAnalyzerTokens(nil); ok || c != 0 {
		t.Fatalf("expected (0,false) on nil CountStandardAnalyzerTokens")
	}
	if c, ok := CountStandardAnalyzerTokens([]any{nil, []string{"one two", "three"}, int64(4), "five"}); !ok || c != 8 {
		t.Fatalf("expected CountStandardAnalyzerTokens=8, got %d (ok=%v)", c, ok)
	}

	// 2. formatFlattenedScalarRound61 & ExtractFlattenedLeafStrings & resolveMappedFlattenedBaseRound61
	if len(ExtractFlattenedLeafStrings(nil, "")) != 0 {
		t.Fatalf("expected empty leaves on nil flattened root")
	}
	flatRoot := map[string]any{
		"str":     "hello",
		"b_true":  true,
		"b_false": false,
		"jnum":    json.Number("99"),
		"i":       int(7),
		"i64":     int64(8),
		"i32":     int32(9),
		"f64_int": float64(12.0),
		"f64_dec": float64(12.5),
		"f32_int": float32(3.0),
		"f32_dec": float32(3.25),
		"arr":     []any{map[string]any{"nested": "val"}, nil},
		"a.b":     "dotted_val",
	}
	allLeaves := ExtractFlattenedLeafStrings(flatRoot, "")
	if len(allLeaves) < 10 {
		t.Fatalf("unexpected flattened root leaves: %v", allLeaves)
	}
	subLeaves := ExtractFlattenedLeafStrings(flatRoot, "a.b")
	if len(subLeaves) != 1 || subLeaves[0] != "dotted_val" {
		t.Fatalf("unexpected flattened subPath leaves: %v", subLeaves)
	}
	arrSub := ExtractFlattenedLeafStrings([]any{map[string]any{"k": "v1"}, map[string]any{"k": "v2"}}, "k")
	if len(arrSub) != 2 {
		t.Fatalf("unexpected array flattened leaves: %v", arrSub)
	}
	rf, sp, ok := resolveMappedFlattenedBaseRound61(map[string]any{"__field_types": map[string]string{"meta": "flattened"}}, "meta.env.region")
	if !ok || rf != "meta" || sp != "env.region" {
		t.Fatalf("unexpected resolveMappedFlattenedBaseRound61: rf=%q sp=%q ok=%v", rf, sp, ok)
	}
	if _, _, ok := resolveMappedFlattenedBaseRound61(nil, ""); ok {
		t.Fatalf("expected false on nil params")
	}

	// 3. QuantizeLuceneGeoPoint, GeoBoundingBoxVal, computeGeoSliceBoundsRound61, evalDocFieldSliceGeoMethodRound61
	latHi, lonHi := QuantizeLuceneGeoPoint(90.0, 180.0)
	latLo, lonLo := QuantizeLuceneGeoPoint(-90.0, -180.0)
	if latHi <= 89.9 || lonHi <= 179.9 || latLo > -90.0 || lonLo > -180.0 {
		t.Fatalf("unexpected boundary quantized geo_point: (%v,%v) (%v,%v)", latHi, lonHi, latLo, lonLo)
	}
	var nilBox *GeoBoundingBoxVal
	if b, err := nilBox.MarshalJSON(); err != nil || string(b) != "null" || nilBox.String() != "null" {
		t.Fatalf("unexpected nil GeoBoundingBoxVal format")
	}
	if _, ok, _ := evalGeoBoundingBoxMethodRound61(nilBox, "top"); ok {
		t.Fatalf("expected nil GeoBoundingBoxVal method not handled")
	}
	box := &GeoBoundingBoxVal{
		TopLeft:     &GeoPointVal{Lat: 52.5, Lon: 4.0},
		BottomRight: &GeoPointVal{Lat: 50.0, Lon: 6.5},
	}
	if b, err := json.Marshal(box); err != nil || !strings.Contains(string(b), "top_left") || !strings.Contains(box.String(), "GeoBoundingBox") {
		t.Fatalf("unexpected GeoBoundingBoxVal json/string: %s / %s", string(b), box.String())
	}
	for _, m := range []string{"topLeft", "bottomRight", "top", "bottom", "left", "right", "toString"} {
		if _, ok, err := evalGeoBoundingBoxMethodRound61(box, m); !ok || err != nil {
			t.Fatalf("evalGeoBoundingBoxMethodRound61(%q) failed: ok=%v err=%v", m, ok, err)
		}
	}
	emptyBox := &GeoBoundingBoxVal{}
	for _, m := range []string{"top", "bottom", "left", "right"} {
		if v, ok, _ := evalGeoBoundingBoxMethodRound61(emptyBox, m); !ok || v != 0.0 {
			t.Fatalf("emptyBox %s expected 0.0, got %v", m, v)
		}
	}
	if _, _, _, mw0, mh0 := computeGeoSliceBoundsRound61(nil); mw0 != 0 || mh0 != 0 {
		t.Fatalf("expected zero bounds for empty slice")
	}
	if _, ok, _ := evalDocFieldSliceGeoMethodRound61(nil, "unknownMethod"); ok {
		t.Fatalf("expected unknown geo slice method to return ok=false")
	}
	if _, ok, err := evalDocFieldSliceGeoMethodRound61([]any{}, "getCentroid"); !ok || err == nil {
		t.Fatalf("expected empty geo slice getCentroid error")
	}
	if _, ok, err := evalDocFieldSliceGeoMethodRound61([]any{"not_a_geo_point"}, "getCentroid"); !ok || err == nil {
		t.Fatalf("expected invalid geo slice getCentroid error")
	}
	multiGeo := []any{"52.0,4.0", "50.0,6.0"}
	for _, m := range []string{"getCentroid", "getLabelPosition", "getBoundingBox", "getDimensionalType", "getMercatorWidth", "getMercatorHeight"} {
		if v, ok, err := evalDocFieldSliceGeoMethodRound61(multiGeo, m); !ok || err != nil || v == nil {
			t.Fatalf("evalDocFieldSliceGeoMethodRound61(%q) failed: v=%v ok=%v err=%v", m, v, ok, err)
		}
	}

	// 4. IPAddressVal parsing, methods, comparison, JSON
	var nilIP *IPAddressVal
	if b, _ := nilIP.MarshalJSON(); string(b) != "null" || nilIP.String() != "null" || !nilIP.Equals(nil) || nilIP.CompareTo(nil) != 0 {
		t.Fatalf("unexpected nil IPAddressVal behavior")
	}
	if _, err := ParseIPAddressVal("not-an-ip"); err == nil {
		t.Fatalf("expected error on invalid IP")
	}
	ip4, err := ParseIPAddressVal("127.0.0.1")
	if err != nil {
		t.Fatalf("ParseIPAddressVal v4: %v", err)
	}
	ip6, err := ParseIPAddressVal("fe80::1")
	if err != nil {
		t.Fatalf("ParseIPAddressVal v6: %v", err)
	}
	if nilIP.CompareTo(ip4) >= 0 || ip4.CompareTo(nilIP) <= 0 || ip4.Equals("127.0.0.1") || !ip4.Equals(ip4) {
		t.Fatalf("unexpected IPAddressVal CompareTo/Equals")
	}
	if b, err := json.Marshal(ip4); err != nil || string(b) != `"127.0.0.1"` {
		t.Fatalf("unexpected IPAddressVal MarshalJSON: %s (%v)", string(b), err)
	}
	for _, m := range []string{
		"toString", "getHostAddress", "toCanonicalString", "isIPv4", "isIPv6",
		"isLoopbackAddress", "isMulticastAddress", "isSiteLocalAddress", "isPrivate",
		"isLinkLocalAddress", "getAddress", "hashCode",
	} {
		if _, ok, err := evalIPAddressMethodRound61(ip4, m, nil, nil, nil, 0); !ok || err != nil {
			t.Fatalf("ip4 method %s failed: ok=%v err=%v", m, ok, err)
		}
		if _, ok, err := evalIPAddressMethodRound61(ip6, m, nil, nil, nil, 0); !ok || err != nil {
			t.Fatalf("ip6 method %s failed: ok=%v err=%v", m, ok, err)
		}
	}
	pMap := map[string]any{"other": ip6, "strIP": "127.0.0.1", "bad": 123}
	if eq, ok, err := evalIPAddressMethodRound61(ip4, "equals", []string{"params.other"}, nil, pMap, 0); !ok || err != nil || eq != false {
		t.Fatalf("unexpected ip4.equals(ip6): %v %v", eq, err)
	}
	if cmp, ok, err := evalIPAddressMethodRound61(ip4, "compareTo", []string{"params.strIP"}, nil, pMap, 0); !ok || err != nil || cmp != int64(0) {
		t.Fatalf("unexpected ip4.compareTo('127.0.0.1'): %v %v", cmp, err)
	}
	if _, _, err := evalIPAddressMethodRound61(ip4, "compareTo", []string{"null"}, nil, pMap, 0); err == nil {
		t.Fatalf("expected NullPointerException comparing IPAddress to null")
	}
	if _, _, err := evalIPAddressMethodRound61(ip4, "compareTo", []string{"params.bad"}, nil, pMap, 0); err == nil {
		t.Fatalf("expected ClassCastException comparing IPAddress to int")
	}

	// 5. Custom date pattern conversion, parseDocDateWithMappingFormatRound61, evalChronoOrIsoFieldOnTimeRound61
	_ = convertJavaSimpleDatePatternRound61("yy-M-d'T'h:mm:ss.SSSa ZZZZ X XX XXX ''lit'' MMM MMMM")
	for _, tc := range []struct {
		val any
		fmt string
	}{
		{"1700000000000", "epoch_millis"},
		{int64(1700000000000), "epoch_millis"},
		{"1700000000.5", "epoch_second"},
		{1700000000.5, "epoch_second"},
		{"20231114", "basic_date"},
		{"20231114T221320.000Z", "basic_date_time"},
		{"14-11-2023 22:13:20", "dd-MM-yyyy HH:mm:ss||epoch_millis"},
	} {
		if zdt, ok := parseDocDateWithMappingFormatRound61(tc.val, tc.fmt, false); !ok || zdt == nil {
			t.Fatalf("parseDocDateWithMappingFormatRound61(%v, %q) failed", tc.val, tc.fmt)
		}
	}
	refTm := time.Date(2024, 5, 15, 14, 30, 45, 123456789, time.UTC)
	for _, cf := range []string{
		"WEEK_OF_WEEK_BASED_YEAR", "WEEK_BASED_YEAR", "QUARTER_OF_YEAR", "DAY_OF_QUARTER",
		"YEAR_OF_ERA", "ERA", "MILLI_OF_DAY", "MILLI_OF_SECOND", "MICRO_OF_SECOND", "MICRO_OF_DAY",
		"NANO_OF_SECOND", "NANO_OF_DAY", "MINUTE_OF_DAY", "MINUTE_OF_HOUR", "SECOND_OF_DAY",
		"SECOND_OF_MINUTE", "HOUR_OF_DAY", "HOUR_OF_AMPM", "AMPM_OF_DAY", "DAY_OF_WEEK",
		"DAY_OF_MONTH", "DAY_OF_YEAR", "MONTH_OF_YEAR", "PROLEPTIC_MONTH", "EPOCH_DAY",
		"INSTANT_SECONDS", "OFFSET_SECONDS", "YEAR",
	} {
		if _, ok := evalChronoOrIsoFieldOnTimeRound61(refTm, cf); !ok {
			t.Fatalf("evalChronoOrIsoFieldOnTimeRound61(%q) returned ok=false", cf)
		}
	}
	bceTm := time.Date(0, 1, 2, 0, 0, 0, 0, time.UTC) // Sunday & year <= 0
	_, _ = evalChronoOrIsoFieldOnTimeRound61(bceTm, "YEAR_OF_ERA")
	_, _ = evalChronoOrIsoFieldOnTimeRound61(bceTm, "ERA")
	_, _ = evalChronoOrIsoFieldOnTimeRound61(bceTm, "AMPM_OF_DAY")
	_, _ = evalChronoOrIsoFieldOnTimeRound61(bceTm, "DAY_OF_WEEK")
	if _, ok := evalChronoOrIsoFieldOnTimeRound61(refTm, "NOT_A_FIELD"); ok {
		t.Fatalf("expected false for unknown chrono field")
	}

	// 6. DenseVectorVal, DenseVectorFieldVal, bit/byte/float vector metrics & error branches
	if _, _, err := DecodeHexSignedByteVector("abc"); err == nil {
		t.Fatalf("expected odd-length hex error")
	}
	if _, _, err := DecodeHexSignedByteVector("zzzz"); err == nil {
		t.Fatalf("expected invalid hex error")
	}
	_, _, _ = parseVectorValueRound61([]float32{1, 2}, "byte")
	_, _, _ = parseVectorValueRound61([]float64{1, 2}, "bit")
	if _, _, err := parseVectorValueRound61([]any{200}, "byte"); err == nil {
		t.Fatalf("expected out-of-range byte vector error")
	}
	var nilDVV *DenseVectorVal
	if b, _ := nilDVV.MarshalJSON(); string(b) != "null" || nilDVV.String() != "null" {
		t.Fatalf("unexpected nil DenseVectorVal format")
	}
	bitDVV := &DenseVectorVal{Name: "bv", ElemType: "bit", Floats: []float32{3, -1}, Bytes: []int8{3, -1}}
	if s := bitDVV.String(); s != "[3,-1]" {
		t.Fatalf("unexpected bit DenseVectorVal string: %s", s)
	}
	floatDVV := &DenseVectorVal{Name: "fv", ElemType: "float", Floats: []float32{3, 4}}
	if !strings.Contains(floatDVV.String(), "3") {
		t.Fatalf("unexpected float DenseVectorVal string: %s", floatDVV.String())
	}
	emptyDVF := &DenseVectorFieldVal{Name: "fv", ElemType: "float", Present: false}
	if !emptyDVF.IsEmpty() || emptyDVF.String() != "[]" {
		t.Fatalf("unexpected empty DenseVectorFieldVal")
	}
	if _, err := emptyDVF.GetValue(); err == nil {
		t.Fatalf("expected error on empty DenseVectorFieldVal.GetValue()")
	}
	if def, err := emptyDVF.GetWithDefault("fallback"); err != nil || def != "fallback" {
		t.Fatalf("unexpected GetWithDefault on empty: %v (%v)", def, err)
	}
	fullDVF := &DenseVectorFieldVal{Name: "fv", ElemType: "float", Present: true, Vec: floatDVV}
	if fullDVF.IsEmpty() {
		t.Fatalf("expected non-empty fullDVF")
	}
	if gv, err := fullDVF.GetValue(); err != nil || gv != floatDVV {
		t.Fatalf("unexpected fullDVF.GetValue(): %v %v", gv, err)
	}
	if gd, err := fullDVF.GetWithDefault(nil); err != nil || gd != floatDVV {
		t.Fatalf("unexpected fullDVF.GetWithDefault(): %v %v", gd, err)
	}

	vecParams := map[string]any{"q": []any{3.0, 4.0}, "qBit": []any{1, -1}, "defVec": []any{9.0, 9.0}}
	for _, m := range []string{"isEmpty", "size", "getDims", "getValue", "getMagnitude", "l1Norm", "l2Norm"} {
		if _, ok, err := evalDenseVectorMethodRound61(fullDVF, m, nil, nil, vecParams, 0); !ok || err != nil {
			t.Fatalf("fullDVF.%s() failed: ok=%v err=%v", m, ok, err)
		}
	}
	if _, ok, err := evalDenseVectorMethodRound61(bitDVV, "l1Norm", nil, nil, vecParams, 0); !ok || err != nil {
		t.Fatalf("bitDVV.l1Norm() failed: ok=%v err=%v", ok, err)
	}
	for _, m := range []string{"l1Norm", "l2Norm", "dotProduct", "cosineSimilarity"} {
		if _, ok, err := evalDenseVectorMethodRound61(fullDVF, m, []string{"params.q"}, nil, vecParams, 0); !ok || err != nil {
			t.Fatalf("fullDVF.%s(params.q) failed: ok=%v err=%v", m, ok, err)
		}
	}
	for _, m := range []string{"hamming", "l1Norm", "l2Norm"} {
		if _, ok, err := evalDenseVectorMethodRound61(bitDVV, m, []string{"params.qBit"}, nil, vecParams, 0); !ok || err != nil {
			t.Fatalf("bitDVV.%s(params.qBit) failed: ok=%v err=%v", m, ok, err)
		}
	}
	if _, _, err := evalDenseVectorMethodRound61(bitDVV, "cosineSimilarity", []string{"params.qBit"}, nil, vecParams, 0); err == nil {
		t.Fatalf("expected cosineSimilarity on bit vector to fail")
	}
	if _, _, err := evalDenseVectorMethodRound61(fullDVF, "hamming", []string{"params.q"}, nil, vecParams, 0); err == nil {
		t.Fatalf("expected hamming on float vector to fail")
	}
	_, _, _ = evalDenseVectorMethodRound61(fullDVF, "get", nil, nil, vecParams, 0)
	_, _, _ = evalDenseVectorMethodRound61(fullDVF, "get", []string{"1"}, nil, vecParams, 0)
	_, _, _ = evalDenseVectorMethodRound61(emptyDVF, "get", []string{"params.defVec"}, nil, vecParams, 0)
	_, _, _ = evalDenseVectorMethodRound61(fullDVF, "get", []string{"0", "0.0"}, nil, vecParams, 0)
	_, _, _ = evalDenseVectorMethodRound61(fullDVF, "get", []string{"9", "-1.0"}, nil, vecParams, 0)
	_, _, _ = evalDenseVectorMethodRound61(emptyDVF, "get", []string{"0", "params.defVec"}, nil, vecParams, 0)
	if _, _, err := evalDenseVectorMethodRound61(fullDVF, "get", []string{"99"}, nil, vecParams, 0); err == nil {
		t.Fatalf("expected IndexOutOfBoundsException on fullDVF.get(99)")
	}

	// 7. isMutableFieldsContextRound61, UpdateMetadataVal getField/setField, CheckUpsertRoutingGuardRound61
	if isMutableFieldsContextRound61(nil) {
		t.Fatalf("expected false on nil params")
	}
	if !isMutableFieldsContextRound61(map[string]any{"__mutable_fields_api": true}) ||
		!isMutableFieldsContextRound61(map[string]any{"__is_ubq": true}) ||
		!isMutableFieldsContextRound61(map[string]any{"_ctx_op": "index"}) ||
		!isMutableFieldsContextRound61(map[string]any{"_ingest": map[string]any{}}) ||
		isMutableFieldsContextRound61(map[string]any{"__strict_doc_mapping": true}) {
		t.Fatalf("unexpected isMutableFieldsContextRound61 truth table")
	}
	meta := &UpdateMetadataVal{
		Params: map[string]any{
			"_ctx_id":      "1",
			"_ctx_index":   "idx",
			"_ctx_version": int64(2),
			"_ctx_op":      "index",
			"_ctx_now":     int64(1000),
			"_ctx_routing": "r1",
		},
	}
	for _, prop := range []string{"id", "index", "version", "op", "now", "routing"} {
		if _, ok, err := meta.getField(prop); !ok || err != nil {
			t.Fatalf("meta.getField(%q) failed: ok=%v err=%v", prop, ok, err)
		}
	}
	meta.Params["__upsert_insert_mode"] = true
	meta.Params["__upsert_forbid_routing"] = true
	if _, _, err := meta.getField("routing"); err == nil {
		t.Fatalf("expected routing unavailable for insert error")
	}
	if err := meta.setField("op", "delete"); err != nil {
		t.Fatalf("expected valid op=delete, got %v", err)
	}
	for _, badProp := range []string{"routing", "id", "index", "version", "unknown_prop"} {
		if err := meta.setField(badProp, "x"); err == nil {
			t.Fatalf("expected meta.setField(%q) to fail", badProp)
		}
	}
	if err := meta.setField("op", "invalid_op"); err == nil {
		t.Fatalf("expected invalid op to fail")
	}
	meta.Params["__is_ubq"] = true
	meta.Params["__is_es8"] = true
	if err := meta.setField("op", "none"); err == nil {
		t.Fatalf("expected UBQ ES8 op=none to fail via metadata()")
	}
	if err := CheckUpsertRoutingGuardRound61(false, "r1", "r1", "r2", true); err == nil {
		t.Fatalf("expected existing doc routing mutation error")
	}
	if err := CheckUpsertRoutingGuardRound61(true, "r1", "r1", "r1", true); err != nil {
		t.Fatalf("expected matching routing to pass, got %v", err)
	}

	// 8. Round 60/eval vector array similarity, Duration.parse, Period.parse, HalfFloat edge cases, and Stream pipelines
	for _, fn := range []string{"dotProduct", "cosineSimilarity", "l1norm", "l2norm"} {
		if sc, err := evalVectorSimilarityRound60(fn, []float64{3, 4}, []any{3.0, 4.0}, nil, nil); err != nil || math.IsNaN(sc) {
			t.Fatalf("evalVectorSimilarityRound60(%s) failed: sc=%v err=%v", fn, sc, err)
		}
	}
	for _, bitsVal := range []uint16{0x0000, 0x8000, 0x0001, 0x7c00, 0xfc00, 0x7e00, 0x3c00} {
		_ = HalfFloatFromBits(bitsVal)
	}
	for _, fVal := range []float64{0, math.Copysign(0, -1), math.NaN(), math.Inf(1), math.Inf(-1), 1e-8, 1e6, 3.5} {
		_ = HalfFloatToBits(fVal)
	}
	if v, err := Eval(map[string]any{}, `
		Duration d = Duration.parse('P2DT3H4M5.5S');
		Period p = Period.parse('P1Y2M3W4D');
		List nums = [1, 2, 3, 4, 5];
		int sum = nums.stream().filter(x -> x > 1).mapToInt(x -> x * 2).sum();
		return d.toSeconds() + ':' + p.getDays() + ':' + sum;
	`, nil); err != nil || !strings.HasSuffix(fmt.Sprintf("%v", v), ":25:28") {
		t.Fatalf("Duration/Period/Stream eval failed: v=%v err=%v", v, err)
	}
	_ = normalizeSingleFieldDocValuesRound60([]any{3, 1, 2}, "long", false, false)
	_ = normalizeSingleFieldDocValuesRound60([]any{1.5, 2.5}, "float", false, true)
	fvRoot := map[string]any{"x": int64(10)}
	fv := &FieldVal{Name: "x", Root: fvRoot}
	if _, err := evalFieldValTransformRound61(fv, "v -> v + 5", fvRoot, map[string]any{}, 0); err != nil || fvRoot["x"] != int64(15) {
		t.Fatalf("evalFieldValTransformRound61 failed: err=%v root=%v", err, fvRoot)
	}
	if _, err := evalFieldValTransformRound61(fv, "not_a_lambda", fvRoot, map[string]any{}, 0); err == nil {
		t.Fatalf("expected non-lambda error on evalFieldValTransformRound61")
	}
	if v, err := Eval(map[string]any{}, `
		BigInteger bi = new BigInteger('12345');
		return bi.intValue() + ':' + bi.shortValue() + ':' + bi.byteValue() + ':' + bi.bitLength() + ':' + bi.toString();
	`, nil); err != nil || !strings.HasPrefix(fmt.Sprintf("%v", v), "12345:12345:") {
		t.Fatalf("BigInteger methods failed: v=%v err=%v", v, err)
	}
}
