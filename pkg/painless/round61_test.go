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
