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
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestRound63_F29_GrokPostExpansionCapAndInputBounds(t *testing.T) {
	// 1. Macro-bomb < 4096 bytes (`%{COMBINEDAPACHELOG}` repeated 50 times ~1,050 bytes -> >200 KB expanded)
	macroBomb := strings.Repeat("%{COMBINEDAPACHELOG} ", 50)
	if len(macroBomb) >= MaxRegexPatternLen {
		t.Fatalf("expected raw pattern < %d, got %d", MaxRegexPatternLen, len(macroBomb))
	}
	if _, err := CompileGrokPattern(macroBomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected post-expansion cap error on unnamed macro bomb, got: %v", err)
	}

	// Named capture macro-bomb (`%{COMBINEDAPACHELOG:log}` repeated 50 times)
	namedBomb := strings.Repeat("%{COMBINEDAPACHELOG:log} ", 50)
	if _, err := CompileGrokPattern(namedBomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected post-expansion cap error on named macro bomb, got: %v", err)
	}

	// CompileValidate and runtime Eval must also reject macro-bomb Grok patterns
	scriptBomb := "return grok('" + macroBomb + "').extract('test');"
	if err := CompileValidate(scriptBomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected CompileValidate to reject macro-bomb grok, got: %v", err)
	}
	if _, err := Eval(nil, scriptBomb, nil); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected Eval to reject macro-bomb grok, got: %v", err)
	}

	// Raw pattern > MaxRegexPatternLen rejected with safely truncated message
	hugeRaw := strings.Repeat("a", MaxRegexPatternLen+100)
	if _, err := CompileGrokPattern(hugeRaw); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") || len(err.Error()) > 512 {
		t.Fatalf("expected bounded error message for huge raw pattern, got: %v", err)
	}

	// 2. Single-macro normal `%{COMBINEDAPACHELOG}` still compiles & extracts cleanly
	ext, err := CompileGrokPattern("%{IP:client} %{WORD:method} %{INT:status:int}")
	if err != nil {
		t.Fatalf("unexpected error compiling valid grok: %v", err)
	}
	got := ext.Extract("192.168.1.10 GET 200")
	if got["client"] != "192.168.1.10" || got["method"] != "GET" || got["status"] != int64(200) {
		t.Fatalf("unexpected grok extraction: %#v", got)
	}

	// 3. Input > MaxGrokInputBytes (1 MiB) bounded on Extract / ExtractChecked / Painless grok & dissect
	oversized := strings.Repeat("x", MaxGrokInputBytes+1)
	if m := ext.Extract(oversized); m != nil {
		t.Fatalf("expected nil from Extract on >1MiB input, got: %#v", m)
	}
	if _, err := ext.ExtractChecked(oversized); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected illegal_argument_exception from GrokExtractor.ExtractChecked, got: %v", err)
	}

	dExt, err := CompileDissectPattern("%{a} %{b}")
	if err != nil {
		t.Fatalf("unexpected error compiling dissect: %v", err)
	}
	if m := dExt.Extract(oversized); m != nil {
		t.Fatalf("expected nil from DissectExtractor.Extract on >1MiB input, got: %#v", m)
	}
	if _, err := dExt.ExtractChecked(oversized); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected illegal_argument_exception from DissectExtractor.ExtractChecked, got: %v", err)
	}

	if _, err := Eval(nil, "return grok('%{WORD:w}').extract(params.big);", map[string]any{"big": oversized}); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected Painless grok.extract(>1MiB) error, got: %v", err)
	}
	if _, err := Eval(nil, "return dissect('%{w}').extract(params.big);", map[string]any{"big": oversized}); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected Painless dissect.extract(>1MiB) error, got: %v", err)
	}
}

func TestRound63_F21_DateSlashFormatDayOfWeekEnum(t *testing.T) {
	cases := []struct {
		dateStr  string
		wantDOW  int64
		wantName string
		wantDisp string
	}{
		{"1970/01/01", 4, "THURSDAY", "Thu"},
		{"2017/01/01", 7, "SUNDAY", "Sun"},
		{"2017/02/01", 3, "WEDNESDAY", "Wed"},
		{"2020/05/15", 5, "FRIDAY", "Fri"},
		{"2020-05-15", 5, "FRIDAY", "Fri"},
		{"2020-05-15T12:34:56Z", 5, "FRIDAY", "Fri"},
	}

	for _, tc := range cases {
		// Both with explicit __field_types and without __field_types
		for _, withMapping := range []bool{true, false} {
			var params map[string]any
			if withMapping {
				params = map[string]any{
					"__field_types":   map[string]string{"date": "date", "custom_d": "date"},
					"__field_formats": map[string]string{"date": "yyyy/MM/dd||strict_date_optional_time||epoch_millis"},
				}
			}
			doc := map[string]any{
				"date":     tc.dateStr,
				"custom_d": tc.dateStr,
			}

			// 20_scriptfield.yml exact expression: `doc.date.value.dayOfWeekEnum.value`
			v1, err := Eval(doc, "doc.date.value.dayOfWeekEnum.value", params)
			if err != nil || v1 != tc.wantDOW {
				t.Fatalf("date=%q mapping=%v doc.date.value.dayOfWeekEnum.value got (%#v, %v), want %d", tc.dateStr, withMapping, v1, err, tc.wantDOW)
			}

			// Bracket form + getValue() + getDisplayName() + name()
			v2, err := Eval(doc, "doc['date'].value.dayOfWeekEnum.getValue() + ':' + doc['date'].value.dayOfWeekEnum.name() + ':' + doc['date'].value.dayOfWeekEnum.getDisplayName(TextStyle.SHORT, Locale.ROOT)", params)
			wantCombo := FormatValueSafe(tc.wantDOW) + ":" + tc.wantName + ":" + tc.wantDisp
			if err != nil || v2 != wantCombo {
				t.Fatalf("date=%q mapping=%v bracket dayOfWeekEnum combo got (%#v, %v), want %q", tc.dateStr, withMapping, v2, err, wantCombo)
			}

			// Slash date on field not named `date`
			if strings.Contains(tc.dateStr, "/") || withMapping {
				v3, err := Eval(doc, "doc['custom_d'].value.dayOfWeekEnum.value", params)
				if err != nil || v3 != tc.wantDOW {
					t.Fatalf("date=%q mapping=%v doc['custom_d'].value.dayOfWeekEnum.value got (%#v, %v), want %d", tc.dateStr, withMapping, v3, err, tc.wantDOW)
				}
			}
		}
	}

	// Epoch millis date
	epochDoc := map[string]any{"date": int64(0)}
	epochParams := map[string]any{"__field_types": map[string]string{"date": "date"}}
	ev, err := Eval(epochDoc, "doc.date.value.dayOfWeekEnum.value", epochParams)
	if err != nil || ev != int64(4) {
		t.Fatalf("epoch 0 dayOfWeekEnum.value got (%#v, %v), want 4", ev, err)
	}
}

func TestRound63_F21_Float32DocValuesTokenCountConstantKeywordAndVersion(t *testing.T) {
	// 1. Float.toString & 50_script_doc_values.yml float accumulation
	floatCases := []struct {
		expr string
		want string
	}{
		{"Float.toString(1.0f)", "1.0"},
		{"Float.toString(0.0f)", "0.0"},
		{"Float.toString(-0.0f)", "-0.0"},
		{"Float.toString(1.2f)", "1.2"},
		{"Float.toString(1.0e7f)", "1.0E7"},
		{"Float.toString(1.0e-4f)", "1.0E-4"},
		{"Float.toString(Float.NaN)", "NaN"},
		{"Float.toString(Float.POSITIVE_INFINITY)", "Infinity"},
		{"Float.toString(Float.NEGATIVE_INFINITY)", "-Infinity"},
	}
	for _, fc := range floatCases {
		got, err := Eval(nil, fc.expr, nil)
		if err != nil || got != fc.want {
			t.Fatalf("%s -> (%#v, %v), want %q", fc.expr, got, err, fc.want)
		}
	}
	if FormatFloat32DocValue(float32(1.2)) != "1.2" || FormatFloat32DocValue(float32(1.0)) != "1.0" {
		t.Fatalf("unexpected FormatFloat32DocValue results")
	}

	searchParams := map[string]any{
		"__field_types": map[string]string{
			"float":  "float",
			"short":  "short",
			"const":  "constant_keyword",
			"const2": "constant_keyword",
			"ver":    "version",
		},
		"__constant_keyword_values": map[string]string{
			"const":  "the_same_everywhere",
			"const2": "the_same_but_different",
		},
	}

	docFloat := map[string]any{
		"float":   []any{1.2, -0.5, 100.3},
		"short":   []any{int64(18), int64(83)},
		"keyword": "abc",
		"ver":     []any{"1.10.0", "1.2.0", "1.0.0-alpha"},
	}
	fRes, err := Eval(docFloat, "float total = 0; for (float f : field('float')) { total += f; } Float.toString(total + field('float').size());", searchParams)
	if err != nil || fRes != "104.0" {
		t.Fatalf("50_script_doc_values float loop got (%#v, %v), want \"104.0\"", fRes, err)
	}

	emptyFloatRes, err := Eval(map[string]any{}, "float total = 0; for (float f : field('float')) { total += f; } Float.toString(total + field('float').size());", searchParams)
	if err != nil || emptyFloatRes != "0.0" {
		t.Fatalf("50_script_doc_values empty float loop got (%#v, %v), want \"0.0\"", emptyFloatRes, err)
	}

	shortRes, err := Eval(docFloat, "int total = 0; for (short s : field('short')) { total += s; } total + field('short').size();", searchParams)
	if err != nil || shortRes != int64(103) {
		t.Fatalf("short loop got (%#v, %v), want 103", shortRes, err)
	}

	// 2. constant_keyword (`10_script_values.yml`)
	ck1, err := Eval(docFloat, "field('const').get('doremi') + '_' + $('keyword', 'dne')", searchParams)
	if err != nil || ck1 != "the_same_everywhere_abc" {
		t.Fatalf("constant_keyword field('const') got (%#v, %v)", ck1, err)
	}
	ck2, err := Eval(docFloat, "field('const2').get(0, 'fasola') + '-' + doc['const'].value", searchParams)
	if err != nil || ck2 != "the_same_but_different-the_same_everywhere" {
		t.Fatalf("constant_keyword doc/field combo got (%#v, %v)", ck2, err)
	}

	// 3. Version (`mapper-version/50_script_values.yml`)
	verPresent, err := Eval(docFloat, "field('ver').get(new Version('')).toString() + '|' + doc['ver'].value", searchParams)
	if err != nil || verPresent != "1.0.0-alpha|1.0.0-alpha" {
		t.Fatalf("version sorted first value got (%#v, %v)", verPresent, err)
	}
	verMissing, err := Eval(map[string]any{}, "field('ver').get(new Version('')).toString()", searchParams)
	if err != nil || verMissing != "" {
		t.Fatalf("version missing default got (%#v, %v), want \"\"", verMissing, err)
	}
	verCmp, err := Eval(nil, "Version a = new Version('1.10.0'); Version b = new Version('1.2.0'); return a.compareTo(b) > 0 && !a.equals(b) && a.equals('1.10.0');", nil)
	if err != nil || verCmp != true {
		t.Fatalf("Version methods got (%#v, %v)", verCmp, err)
	}

	// 4. CountStandardAnalyzerTokens pre-counted numeric & string tokenization
	if n, ok := CountStandardAnalyzerTokens("The quick brown fox"); !ok || n != 4 {
		t.Fatalf("expected 4 tokens, got (%d, %v)", n, ok)
	}
	if n, ok := CountStandardAnalyzerTokens(float64(7)); !ok || n != 7 {
		t.Fatalf("expected pre-counted float64(7) -> 7, got (%d, %v)", n, ok)
	}
	if n, ok := CountStandardAnalyzerTokens(float32(5)); !ok || n != 5 {
		t.Fatalf("expected pre-counted float32(5) -> 5, got (%d, %v)", n, ok)
	}
}

func TestRound63_F21_UnsignedLongScriptValues(t *testing.T) {
	params := map[string]any{
		"__field_types": map[string]string{
			"ul":       "unsigned_long",
			"ul_multi": "unsigned_long",
		},
	}

	docs := []struct {
		id       string
		doc      map[string]any
		wantLong int64
		wantDbl  float64
	}{
		{"1", map[string]any{"ul": json.Number("0"), "ul_multi": []any{json.Number("18446744073709551615"), json.Number("9223372036854775808"), json.Number("0"), json.Number("0")}}, 0, 0.0},
		{"2", map[string]any{"ul": json.Number("9223372036854775807")}, math.MaxInt64, float64(uint64(9223372036854775807))},
		{"3", map[string]any{"ul": json.Number("9223372036854775808")}, math.MinInt64, float64(uint64(9223372036854775808))},
		{"4", map[string]any{"ul": json.Number("18446744073709551613")}, -3, float64(uint64(18446744073709551613))},
		{"5", map[string]any{"ul": json.Number("18446744073709551615")}, -1, float64(uint64(18446744073709551615))},
	}

	for _, tc := range docs {
		// doc['ul'].value returns signed 64-bit two's-complement long
		dv, err := Eval(tc.doc, "doc['ul'].value", params)
		if err != nil || dv != tc.wantLong {
			t.Fatalf("doc %s doc['ul'].value got (%#v, %v), want %d", tc.id, dv, err, tc.wantLong)
		}

		// field('ul').getValue(1000L) also returns signed 64-bit long
		fgv, err := Eval(tc.doc, "field('ul').getValue(1000L)", params)
		if err != nil || fgv != tc.wantLong {
			t.Fatalf("doc %s field('ul').getValue(1000L) got (%#v, %v), want %d", tc.id, fgv, err, tc.wantLong)
		}

		// field('ul').asBigInteger(...).doubleValue()
		asBI, err := Eval(tc.doc, "field('ul').asBigInteger(BigInteger.valueOf(Long.parseUnsignedLong('18446744073709551614'))).doubleValue()", params)
		if err != nil || asBI != tc.wantDbl {
			t.Fatalf("doc %s asBigInteger.doubleValue() got (%#v, %v), want %v", tc.id, asBI, err, tc.wantDbl)
		}

		// doc['ul'].value.doubleValue() > 9E18 matches ONLY doc 2 (`9223372036854775807`)
		matched, err := EvalFilter(tc.doc, "doc['ul'].value.doubleValue() > 9E18", params)
		if err != nil || matched != (tc.id == "2") {
			t.Fatalf("doc %s doubleValue() > 9E18 got (%v, %v), want %v", tc.id, matched, err, tc.id == "2")
		}

		// script_score `Math.abs(doc['ul'].value)` via EvalNumber must be non-negative on ALL 5 docs (including doc 3 = Long.MIN_VALUE!)
		score, ok, err := EvalNumber(tc.doc, "Math.abs(doc['ul'].value)", params)
		if err != nil || !ok || score < 0 {
			t.Fatalf("doc %s EvalNumber Math.abs(doc['ul'].value) got (%v, %v, %v), want >= 0", tc.id, score, ok, err)
		}
	}

	// Multi-value unsigned sorting on doc 1: [0, 0, 9223372036854775808, 18446744073709551615] -> [0, 0, MinInt64, -1]
	mvRes, err := Eval(docs[0].doc, "[field('ul_multi').getValue(1000L), field('ul_multi').getValue(1, 1000L), field('ul_multi').getValue(2, 1000L), field('ul_multi').getValue(3, 1000L)]", params)
	wantMV := []any{int64(0), int64(0), int64(math.MinInt64), int64(-1)}
	if err != nil || !reflect.DeepEqual(mvRes, wantMV) {
		t.Fatalf("ul_multi getValue got (%#v, %v), want %#v", mvRes, err, wantMV)
	}

	// field('ul').get(null) returns BigInteger 18446744073709551615 in Painless
	biStr, err := Eval(docs[4].doc, "BigInteger bi = field('ul').get(null); return bi.toString() + ':' + field('ul').asBigInteger().toString() + ':' + field('ul').asLong();", params)
	if err != nil || biStr != "18446744073709551615:18446744073709551615:-1" {
		t.Fatalf("field('ul').get(null) BigInteger got (%#v, %v)", biStr, err)
	}

	// Scripted Metric on doc 5 (`18446744073709551615`) -> 3.4028236692093846e38
	sqRes, err := Eval(docs[4].doc, "double v = field('ul').asBigInteger(BigInteger.ZERO).doubleValue(); return v * v;", params)
	if err != nil || sqRes != 3.4028236692093846e38 {
		t.Fatalf("scripted metric v*v got (%#v, %v), want 3.4028236692093846e38", sqRes, err)
	}

	// Long.*Unsigned* suite on doc['ul'].value = -1 (18446744073709551615 unsigned)
	unsignedOps, err := Eval(docs[4].doc, `
		long u = doc['ul'].value;
		long ten = 10L;
		return [
			Long.toUnsignedString(u),
			Long.toUnsignedString(u, 16),
			Long.compareUnsigned(u, 9223372036854775807L),
			Long.divideUnsigned(u, ten),
			Long.remainderUnsigned(u, ten),
			Long.parseUnsignedLong('18446744073709551615')
		];
	`, params)
	wantUOps := []any{
		"18446744073709551615",
		"ffffffffffffffff",
		int64(1),
		int64(1844674407370955161),
		int64(5),
		int64(-1),
	}
	if err != nil || !reflect.DeepEqual(unsignedOps, wantUOps) {
		t.Fatalf("Long.*Unsigned* ops got (%#v, %v), want %#v", unsignedOps, err, wantUOps)
	}
}

func TestRound63_F21_MetadataAndRoutingGuards(t *testing.T) {
	unmarshalDoc := func(raw json.RawMessage) map[string]any {
		var m map[string]any
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &m)
		}
		return m
	}

	// 1. Upsert insert without routing: `metadata().routing` throws `routing is unavailable for insert` (`25_script_upsert.yml`)
	req := &UpdateRequest{
		Script:         &ScriptSpec{Source: "ctx._source.foo = metadata().routing"},
		Upsert:         map[string]any{},
		ScriptedUpsert: true,
		MetaIndex:      "test_1",
		MetaID:         "1",
		IsES8:          true,
	}
	if _, _, err := ApplyUpdateWithResult(nil, req, false); err == nil || !strings.Contains(err.Error(), "routing is unavailable for insert") {
		t.Fatalf("expected 'routing is unavailable for insert', got: %v", err)
	}

	// Upsert insert with request routing DOES expose metadata().routing
	reqWithRouting := &UpdateRequest{
		Script:         &ScriptSpec{Source: "ctx._source.foo = metadata().routing + ':' + metadata().index"},
		Upsert:         map[string]any{},
		ScriptedUpsert: true,
		MetaIndex:      "test_1",
		MetaID:         "1",
		MetaRouting:    "shard-a",
		IsES8:          true,
	}
	upRaw, op, err := ApplyUpdateWithResult(nil, reqWithRouting, false)
	upDoc := unmarshalDoc(upRaw)
	if err != nil || upDoc["foo"] != "shard-a:test_1" || op != "created" {
		t.Fatalf("upsert with routing got (%#v, %q, %v)", upDoc, op, err)
	}

	// Upsert `metadata().op = 'noop'` and `metadata().op = 'create'` (`25_script_upsert.yml:140, 159`)
	reqNoop := &UpdateRequest{
		Script:         &ScriptSpec{Source: "metadata().op = 'noop'; ctx._source.bar = 'skipped?'"},
		Upsert:         map[string]any{},
		ScriptedUpsert: true,
		MetaIndex:      "test_1",
		MetaID:         "3",
		IsES8:          true,
	}
	_, noopRes, err := ApplyUpdateWithResult(nil, reqNoop, false)
	if err != nil || noopRes != "noop" {
		t.Fatalf("expected noop from metadata().op = 'noop', got (%q, %v)", noopRes, err)
	}

	reqCreate := &UpdateRequest{
		Script:         &ScriptSpec{Source: "metadata().op = 'create'; ctx._source.bar = 'created!'"},
		Upsert:         map[string]any{},
		ScriptedUpsert: true,
		MetaIndex:      "test_1",
		MetaID:         "3",
		IsES8:          true,
	}
	createdRaw, createRes, err := ApplyUpdateWithResult(nil, reqCreate, false)
	createdDoc := unmarshalDoc(createdRaw)
	if err != nil || createRes != "created" || createdDoc["bar"] != "created!" {
		t.Fatalf("expected created from metadata().op = 'create', got (%#v, %q, %v)", createdDoc, createRes, err)
	}

	// Update existing doc via local `Metadata m = metadata(); m.op = 'delete'` (`15_update.yml`)
	reqDel := &UpdateRequest{
		Script:    &ScriptSpec{Source: "Metadata m = metadata(); ctx._source.bar = m.id + '-extra'; m.op = 'delete'"},
		MetaIndex: "test_1",
		MetaID:    "2",
		IsES8:     true,
	}
	delRaw, delRes, err := ApplyUpdateWithResult(json.RawMessage(`{"foo":"bar"}`), reqDel, true)
	delDoc := unmarshalDoc(delRaw)
	if err != nil || delRes != "deleted" || delDoc["bar"] != "2-extra" {
		t.Fatalf("expected deleted from m.op = 'delete', got (%#v, %q, %v)", delDoc, delRes, err)
	}

	// Index-time field script guard (`__forbid_metadata_routing`)
	if _, err := Eval(map[string]any{"a": 1}, "return metadata().routing;", map[string]any{"__forbid_metadata_routing": true}); err == nil || !strings.Contains(err.Error(), "routing is unavailable") {
		t.Fatalf("expected index-time metadata().routing guard error, got: %v", err)
	}

	// Ingest `Metadata m = metadata()` mutation & `metadata().now` (`190_script_processor.yml:330`, `270_set_processor.yml:193`)
	ingDoc := map[string]any{
		"_ingest": map[string]any{"timestamp": "2023-06-15T10:20:30Z"},
	}
	ingParams := map[string]any{
		"_ctx_index": "logs",
		"_ctx_id":    "doc1",
	}
	if err := EvalPainless(ingDoc, "Metadata m = metadata(); m.index += '2'; m.id += 'extra'; m.routing = 'myRouting'; m.versionType = 'external'; m.version = 5; ctx.t = metadata().now;", ingParams); err != nil {
		t.Fatalf("ingest Metadata script failed: %v", err)
	}
	if ingParams["_ctx_index"] != "logs2" || ingParams["_ctx_id"] != "doc1extra" || ingParams["_ctx_routing"] != "myRouting" || ingParams["_ctx_version_type"] != "external" || ingParams["_ctx_version"] != int64(5) {
		t.Fatalf("unexpected synced ingest metadata params: %#v", ingParams)
	}
	if zdt, ok := ingDoc["t"].(*ZonedDateTimeVal); !ok || zdt == nil || zdt.GetYear() != 2023 {
		t.Fatalf("expected ZonedDateTimeVal for metadata().now, got %T (%#v)", ingDoc["t"], ingDoc["t"])
	}
}

func TestRound63_F22_IngestAndUpdateWriteFieldsAPI(t *testing.T) {
	// 1. Exact `Write Fields API` pipeline from `190_script_processor.yml:373-460`
	doc1 := map[string]any{
		"append":    []any{"one", "again", "another", "again"},
		"duplicate": []any{"bb", "aa", "aa"},
		"numbers":   []any{int64(1), nil, "2"},
		"src": map[string]any{
			"key1": "value1",
			"key2": "value2",
		},
		"dst": map[string]any{
			"key3": "value3",
			"key4": "value4",
		},
	}
	// Even if index mappings (__field_types) exist alongside _ingest, Write Fields API must preserve raw _source lists!
	ingParams := map[string]any{
		"_ingest": map[string]any{"timestamp": "2024-01-01T00:00:00Z"},
		"__field_types": map[string]string{
			"append":    "keyword",
			"duplicate": "keyword",
			"numbers":   "integer",
		},
	}
	pipelineScripts := []string{
		"field('create.depth').set('works');",
		"field('append').append('another')",
		"def a = field('append'); int i = 0; for (def value : a) { i += value.length(); } field('size').set(100 * a.size() + i);",
		"Collections.sort(field('duplicate').deduplicate().get(new ArrayList()));",
		"field('numbers').removeValuesIf(x -> x == null).transform(x -> x instanceof String ? Integer.parseInt(x) : x);",
		"field('src.key1').move('dst.key5'); field('src.key2').overwrite('dst.key3'); field('dst.key4').remove()",
	}
	for _, sc := range pipelineScripts {
		if err := EvalPainless(doc1, sc, ingParams); err != nil {
			t.Fatalf("Write Fields API script %q failed: %v", sc, err)
		}
	}

	if createMap, _ := doc1["create"].(map[string]any); createMap["depth"] != "works" {
		t.Fatalf("expected create.depth == 'works', got %#v", doc1["create"])
	}
	wantAppend := []any{"one", "again", "another", "again", "another"}
	if !reflect.DeepEqual(doc1["append"], wantAppend) {
		t.Fatalf("append mismatch: got %#v, want %#v", doc1["append"], wantAppend)
	}
	if doc1["size"] != int64(527) {
		t.Fatalf("expected size == 527, got %#v", doc1["size"])
	}
	if !reflect.DeepEqual(doc1["duplicate"], []any{"aa", "bb"}) {
		t.Fatalf("duplicate mismatch: got %#v", doc1["duplicate"])
	}
	if !reflect.DeepEqual(doc1["numbers"], []any{int64(1), int64(2)}) {
		t.Fatalf("numbers mismatch: got %#v", doc1["numbers"])
	}
	if srcMap, _ := doc1["src"].(map[string]any); len(srcMap) != 0 {
		t.Fatalf("expected empty src map, got %#v", srcMap)
	}
	wantDst := map[string]any{"key3": "value2", "key5": "value1"}
	if !reflect.DeepEqual(doc1["dst"], wantDst) {
		t.Fatalf("dst mismatch: got %#v, want %#v", doc1["dst"], wantDst)
	}

	// 2. Exact `Write Field Nested Document` pipeline from `190_script_processor.yml:472-560`
	nestedDoc := map[string]any{
		"records": []any{
			map[string]any{"region": "us-east-1"},
			map[string]any{"name": "id-123", "usage": int64(123)},
			map[string]any{"name": "id-456", "usage-value": int64(456)},
			map[string]any{"name": "id-789"},
			map[string]any{"usage": int64(789)},
			map[string]any{"name": "end-of-records"},
		},
	}
	nestedScript := `
		def records = field('records');
		def regionDoc = records.doc(0);
		regionDoc.field('region').move(field('region'));
		regionDoc.remove();

		def missingUsage = null;
		for (def doc : records.docs()) {
			def name = doc.field('name');
			def usage = doc.field('usage');
			if (name.exists()) {
				if (!usage.exists()) {
					def usageValue = doc.field('usage-value');
					if (usageValue.exists()) {
						usageValue.move('usage');
					} else {
						missingUsage = usage;
					}
				}
			} else if (usage.exists()) {
				if (missingUsage != null) {
					usage.move(missingUsage);
					missingUsage = null;
					doc.remove();
				}
			}
		}

		def end = records.doc(records.size() - 1);
		if (end.field('name').get('') == 'end-of-records') {
			end.remove();
		}
	`
	if err := EvalPainless(nestedDoc, nestedScript, map[string]any{"_ingest": map[string]any{}}); err != nil {
		t.Fatalf("Write Field Nested Document script failed: %v", err)
	}
	if nestedDoc["region"] != "us-east-1" {
		t.Fatalf("expected top-level region == 'us-east-1', got %#v", nestedDoc["region"])
	}
	wantRecords := []any{
		map[string]any{"name": "id-123", "usage": int64(123)},
		map[string]any{"name": "id-456", "usage": int64(456)},
		map[string]any{"name": "id-789", "usage": int64(789)},
	}
	if !reflect.DeepEqual(nestedDoc["records"], wantRecords) {
		t.Fatalf("nested records mismatch:\ngot:  %#v\nwant: %#v", nestedDoc["records"], wantRecords)
	}

	// 3. `_update` & `scripted_upsert` Write Field chaining (`15_update.yml:191`, `25_script_upsert.yml:203`)
	upsertWriteReq := &UpdateRequest{
		Script: &ScriptSpec{
			Source: "field('foo').set('bar').transform(x -> x + '-baz'); field('nest').doc().field('bar').set(200)",
		},
		Upsert:         map[string]any{},
		ScriptedUpsert: true,
		MetaIndex:      "test_1",
		MetaID:         "3",
		IsES8:          true,
	}
	resRaw, _, err := ApplyUpdateWithResult(nil, upsertWriteReq, false)
	if err != nil {
		t.Fatalf("25_script_upsert Write Field failed: %v", err)
	}
	var resDoc map[string]any
	_ = json.Unmarshal(resRaw, &resDoc)
	nestMap, _ := resDoc["nest"].(map[string]any)
	if resDoc["foo"] != "bar-baz" || nestMap["bar"] != float64(200) {
		t.Fatalf("unexpected upsert write field result: %#v", resDoc)
	}
}

func TestRound63_SemverVersionAndFieldValCoercionEdges(t *testing.T) {
	// Semver comparisons across core, pre-release numeric vs alpha, unequal lengths, and build metadata
	semverPairs := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"", "1.0.0", -1},
		{"1.0.0", "", 1},
		{"1.0.0+20130313", "1.0.0+exp.sha.511", 0},
		{"1.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha", 1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-2", "1.0.0-10", -1},
		{"1.0.0-10", "1.0.0-2", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.a", "1.b", -1},
		{"1.b", "1.a", 1},
	}
	for _, sp := range semverPairs {
		if got := CompareSemverStringsES(sp.a, sp.b); got != sp.want {
			t.Fatalf("CompareSemverStringsES(%q, %q) = %d, want %d", sp.a, sp.b, got, sp.want)
		}
	}

	var nilVer *VersionVal
	if nilVer.String() != "null" || nilVer.CompareTo("1.0") != -1 || !nilVer.Equals(nil) || nilVer.Equals("1.0") {
		t.Fatalf("unexpected nil VersionVal behavior")
	}
	if b, err := json.Marshal(nilVer); err != nil || string(b) != "null" {
		t.Fatalf("unexpected nil VersionVal JSON: %s, %v", string(b), err)
	}
	v := NewVersionVal("2.1.0")
	if b, err := json.Marshal(v); err != nil || string(b) != `"2.1.0"` {
		t.Fatalf("unexpected VersionVal JSON: %s, %v", string(b), err)
	}
	if v.CompareTo(2) <= 0 || v.Equals(42) {
		t.Fatalf("unexpected VersionVal non-string CompareTo/Equals")
	}

	// coerceToBigIntegerRound63 & coerceToLongFieldValRound63 across Go numeric types
	for _, sample := range []any{
		uint64(42), uint(42), uint32(42), int64(42), int(42), int32(42),
		json.Number("42"), "42", float64(42), float32(42),
	} {
		bi, err := coerceToBigIntegerRound63(sample, "f")
		if err != nil || bi == nil || bi.longValue() != 42 {
			t.Fatalf("coerceToBigIntegerRound63(%T) got (%#v, %v)", sample, bi, err)
		}
	}
	if _, err := coerceToBigIntegerRound63("not-a-number", "f"); err == nil {
		t.Fatalf("expected error from coerceToBigIntegerRound63 on invalid string")
	}
	if lv, err := coerceToLongFieldValRound63(uint64(math.MaxUint64), "f"); err != nil || lv != int64(-1) {
		t.Fatalf("expected -1 from coerceToLongFieldValRound63(MaxUint64), got (%#v, %v)", lv, err)
	}
	if _, err := coerceToLongFieldValRound63("bad-long", "f"); err == nil {
		t.Fatalf("expected error from coerceToLongFieldValRound63 on invalid string")
	}

	// constant_keyword with map[string]any
	if ck, ok := lookupConstantKeywordValueRound63(nil, map[string]any{"__constant_keyword_values": map[string]any{"k": "v"}}, "k"); !ok || ck != "v" {
		t.Fatalf("unexpected lookupConstantKeywordValueRound63: (%q, %v)", ck, ok)
	}

	// FieldDocVal Exists/Remove on single map vs slice, plus 2-arg FieldVal typed getters
	doc := map[string]any{
		"single_obj": map[string]any{"x": int64(1)},
		"nums":       []any{int64(10), int64(20)},
		"dates":      []any{"2020/01/01", "2021/06/15"},
		"geos":       []any{"40.7,-74.0", "34.0,-118.2"},
		"strs":       []any{"alpha", "beta"},
	}
	params := map[string]any{"_ingest": map[string]any{}}
	res, err := Eval(doc, `
		def sd = field('single_obj').doc();
		boolean exBefore = sd.exists();
		sd.remove();
		boolean exAfter = sd.exists();
		return [
			exBefore,
			exAfter,
			field('nums').asBigInteger(1, BigInteger.ZERO).longValue(),
			field('nums').asBigInteger(5, BigInteger.TEN).longValue(),
			field('nums').asLong(1, -1L),
			field('nums').asLong(5, -1L),
			field('nums').asDouble(1, -1.0),
			field('nums').asDouble(5, -1.0),
			field('dates').asDate(1, null).getYear(),
			field('dates').asDate(5, null),
			field('geos').asGeoPoint(1, null).getLat(),
			field('geos').asGeoPoint(5, null),
			field('strs').asString(1, 'def'),
			field('strs').asString(5, 'def')
		];
	`, params)
	if err != nil {
		t.Fatalf("FieldVal 2-arg getters script failed: %v", err)
	}
	gotArr, _ := res.([]any)
	if len(gotArr) != 14 || gotArr[0] != true || gotArr[1] != false || gotArr[2] != int64(20) || gotArr[3] != int64(10) ||
		gotArr[4] != int64(20) || gotArr[5] != int64(-1) || gotArr[6] != float64(20) || gotArr[7] != float64(-1) ||
		gotArr[8] != int64(2021) || gotArr[9] != nil || gotArr[10] != float64(34.0) || gotArr[11] != nil ||
		gotArr[12] != "beta" || gotArr[13] != "def" {
		t.Fatalf("unexpected 2-arg FieldVal results: %#v", gotArr)
	}
}

func TestRound63_ScriptSpecAndCtxValidationHelpers(t *testing.T) {
	var spec ScriptSpec
	if err := json.Unmarshal([]byte(`"ctx._source.a = 1"`), &spec); err != nil || spec.EffectiveSource() != "ctx._source.a = 1" {
		t.Fatalf("shorthand UnmarshalJSON failed: (%#v, %v)", spec, err)
	}
	if err := json.Unmarshal([]byte(`null`), &spec); err != nil || spec.Source != "" {
		t.Fatalf("null UnmarshalJSON failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"inline":"1+1","lang":"painless"}`), &spec); err != nil || spec.Source != "1+1" {
		t.Fatalf("inline UnmarshalJSON failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"code":"2+2"}`), &spec); err != nil || spec.Source != "2+2" {
		t.Fatalf("code UnmarshalJSON failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"source":"1","id":"s1"}`), &spec); err == nil {
		t.Fatalf("expected error specifying both source and id")
	}
	if err := json.Unmarshal([]byte(`[1,2,3]`), &spec); err == nil {
		t.Fatalf("expected error unmarshaling array into ScriptSpec")
	}

	if sc, err := EvalScore(map[string]any{"x": 2.5}, "params._source.x * 2", map[string]any{"_source": map[string]any{"x": 2.5}}); err != nil || sc != 5.0 {
		t.Fatalf("EvalScore valid got (%v, %v)", sc, err)
	}
	if _, err := EvalScore(nil, "return null;", nil); err == nil || !strings.Contains(err.Error(), "NullPointerException") {
		t.Fatalf("expected EvalScore null error, got: %v", err)
	}
	if _, err := EvalScore(nil, "return 'nope';", nil); err == nil || !strings.Contains(err.Error(), "ClassCastException") {
		t.Fatalf("expected EvalScore ClassCastException, got: %v", err)
	}

	if !AllowedUpdateCtxKeys("_source") || AllowedUpdateCtxKeys("bogus") {
		t.Fatalf("unexpected AllowedUpdateCtxKeys")
	}
	for _, ubq := range []bool{false, true} {
		for _, es8 := range []bool{false, true} {
			if FormatUnknownCtxKeyError("k", "v", ubq, es8) == nil {
				t.Fatalf("expected FormatUnknownCtxKeyError")
			}
			if FormatModifyCtxIDError(ubq, es8) == nil {
				t.Fatalf("expected FormatModifyCtxIDError")
			}
			if ValidateUBQCtxOp("bogus", es8) == nil || ValidateUBQCtxOp("noop", es8) != nil {
				t.Fatalf("unexpected ValidateUBQCtxOp")
			}
		}
	}
	if ValidateUpdateCtxOp("index") != nil || ValidateUpdateCtxOp("bogus") == nil {
		t.Fatalf("unexpected ValidateUpdateCtxOp")
	}
	if ValidateCtxVersion(-1, false, true, true) != nil || ValidateCtxVersion(-1, true, true, true) == nil || ValidateCtxVersion(2, false, false, true) != nil {
		t.Fatalf("unexpected ValidateCtxVersion")
	}

	cycMap := map[string]any{"a": 1}
	cycMap["self"] = cycMap
	if err := CheckSelfReferencingContainer(cycMap, "ctx"); err == nil || !strings.Contains(err.Error(), "Iterable object is self-referencing itself") {
		t.Fatalf("expected cyclic map error, got: %v", err)
	}
	cycSlice := make([]any, 1)
	cycSlice[0] = cycSlice
	if err := CheckSelfReferencingContainer(cycSlice, ""); err == nil {
		t.Fatalf("expected cyclic slice error")
	}

	if ValidateUBQAndUpdateCtx(nil, "1", false, true, false) != nil {
		t.Fatalf("expected nil ctxMap valid")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"bad": 1}, "1", false, true, false) == nil {
		t.Fatalf("expected unknown key error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"_id": "2"}, "1", true, true, false) == nil {
		t.Fatalf("expected modified _id error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"op": "bad"}, "1", true, true, false) == nil {
		t.Fatalf("expected bad UBQ op error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"op": "bad"}, "1", false, true, false) == nil {
		t.Fatalf("expected bad update op error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"_version": int64(-2)}, "1", false, true, true) == nil {
		t.Fatalf("expected negative version error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"_version": float64(-2)}, "1", false, true, true) == nil {
		t.Fatalf("expected negative float version error")
	}
	if ValidateUBQAndUpdateCtx(map[string]any{"_source": cycMap}, "1", false, true, false) == nil {
		t.Fatalf("expected cyclic _source error")
	}
}

func TestRound63_JavaTimeDurationPeriodMatcherAndMathCoverage(t *testing.T) {
	// 1. Duration, Period, MonthDay, YearMonth, LocalTime, LocalDateTime, DateTimeFormatter, ChronoField
	timeScript := `
		Duration d1 = Duration.parse('PT1H30M45.5S');
		Duration d2 = Duration.parse('-P2DT3H4M5.125S');
		Duration d3 = Duration.ofDays(1);
		Duration d4 = Duration.ofHours(2);
		Duration d5 = Duration.ofMinutes(3);
		Duration d6 = Duration.ofSeconds(4);
		Duration d7 = Duration.ofMillis(500);
		Period p1 = Period.parse('P1Y2M3W4D');
		Period p2 = Period.parse('-P1Y2M');
		MonthDay md1 = MonthDay.parse('--05-15');
		MonthDay md2 = MonthDay.of(5, 15);
		MonthDay md3 = MonthDay.from(LocalDate.of(2020, 5, 15));
		YearMonth ym1 = YearMonth.of(2020, 2);
		YearMonth ym2 = YearMonth.parse('2020-02');
		DayOfWeek dow1 = DayOfWeek.of(5);
		DayOfWeek dow2 = DayOfWeek.valueOf('FRIDAY');
		Month m1 = Month.of(2);
		Month m2 = Month.valueOf('FEBRUARY');
		LocalTime lt1 = LocalTime.ofSecondOfDay(3661);
		LocalTime lt2 = LocalTime.ofNanoOfDay(1000000000L);
		LocalTime lt3 = LocalTime.parse('10:15:30');
		LocalTime lt4 = LocalTime.of(10, 15, 30);
		LocalDate ld1 = LocalDate.of(2020, 5, 10);
		LocalDate ld2 = LocalDate.of(2020, 5, 13);
		LocalDateTime ldt1 = LocalDateTime.of(ld1, lt3);
		LocalDateTime ldt2 = LocalDateTime.of(2020, 5, 10, 10, 15, 30);
		Duration db = Duration.between(lt1, lt3);
		def daysList = ld1.datesUntil(ld2).collect(Collectors.toList());
		def zdtStart = ld1.atStartOfDay(ZoneId.of('UTC'));
		def odt = ldt1.atOffset(ZoneOffset.UTC);
		def fmtBasic = ld1.format(DateTimeFormatter.BASIC_ISO_DATE);
		def fmtLocal = lt3.format(DateTimeFormatter.ISO_LOCAL_TIME);
		ZonedDateTime z = ZonedDateTime.parse('2020-05-15T10:20:30Z');
		ZonedDateTime zMod = z.with(ChronoField.HOUR_OF_DAY, 8).with(ChronoField.MINUTE_OF_HOUR, 5).with(ChronoField.SECOND_OF_MINUTE, 1);
		return [
			d1.toMinutes(), d2.toHours() < 0, d3.toHours() + d4.toHours(), d5.toSeconds() + d6.toSeconds() + d7.toMillis(),
			p1.getYears(), p2.getMonths(), md1.toString() == md2.toString(), md3.toString(),
			ym1.isLeapYear(), ym2.lengthOfMonth(), dow1.getValue(), dow2.getValue(), m1.getValue(), m2.getValue(),
			lt1.toString(), lt2.toString(), lt4.toString(), ldt2.getYear(), db.toSeconds() > 0,
			daysList.size(), zdtStart.getYear(), odt.toString().length() > 0, fmtBasic, fmtLocal, zMod.getHour()
		];
	`
	tRes, err := Eval(nil, timeScript, nil)
	if err != nil {
		t.Fatalf("java.time coverage script failed: %v", err)
	}
	tArr, _ := tRes.([]any)
	if len(tArr) != 25 || tArr[0] != int64(90) || tArr[1] != true || tArr[19] != int64(3) || tArr[22] != "20200510" || tArr[24] != int64(8) {
		t.Fatalf("unexpected java.time results: %#v", tArr)
	}

	// 2. Regex Matcher hitEnd / requireEnd / region / lookingAt / groups
	reScript := `
		Pattern p1 = Pattern.compile('(?i)^foo|bar$');
		Matcher m1 = p1.matcher('ba');
		boolean nf1 = m1.find();
		boolean he1 = m1.hitEnd();

		Pattern p2 = Pattern.compile('(?m)(?-i:abc)\\z');
		Matcher m2 = p2.matcher('abc');
		boolean f2 = m2.matches();
		boolean re2 = m2.requireEnd();

		Pattern p3 = Pattern.compile('([a-z]+)-(\\d+)$');
		Matcher m3 = p3.matcher('xx hello-42');
		m3.region(3, 11);
		boolean la = m3.lookingAt();
		return [nf1, he1, f2, re2, la, m3.regionStart(), m3.regionEnd(), m3.group(1), m3.groupCount(), m3.start(), m3.end()];
	`
	rRes, err := Eval(nil, reScript, nil)
	if err != nil {
		t.Fatalf("Matcher coverage script failed: %v", err)
	}
	rArr, _ := rRes.([]any)
	if len(rArr) != 11 || rArr[4] != true || rArr[7] != "hello" || rArr[8] != int64(2) {
		t.Fatalf("unexpected Matcher results: %#v", rArr)
	}

	// 3. Math.* static suite & wrapper constants
	mathScript := `
		double s = Math.log10(100.0) + Math.exp(0.0) + Math.signum(-5.0) + Math.clamp(15, 0, 10) +
			Math.sin(0.0) + Math.cos(0.0) + Math.tan(0.0) + Math.asin(0.0) + Math.acos(1.0) +
			Math.atan(0.0) + Math.atan2(0.0, 1.0) + Math.sinh(0.0) + Math.cosh(0.0) + Math.tanh(0.0) +
			Math.cbrt(27.0) + Math.expm1(0.0) + Math.log1p(0.0) + Math.toRadians(180.0) + Math.toDegrees(Math.PI) +
			Math.hypot(3.0, 4.0) + Math.floor(2.9) + Math.ceil(2.1) + Math.round(2.6) + Math.pow(2.0, 3.0) + Math.sqrt(16.0);
		int sizes = Integer.SIZE + Long.SIZE + Double.SIZE + Float.SIZE + Short.SIZE + Byte.SIZE + Character.SIZE +
			Integer.BYTES + Long.BYTES + Double.BYTES + Float.BYTES + Short.BYTES + Byte.BYTES + Character.BYTES;
		boolean bounds = Float.MAX_VALUE > 0 && Float.MIN_VALUE > 0 && Double.isNaN(Double.NaN) && Double.isInfinite(Double.POSITIVE_INFINITY) && Double.isInfinite(Double.NEGATIVE_INFINITY);
		return [s > 200.0, sizes, bounds];
	`
	mRes, err := Eval(nil, mathScript, nil)
	if err != nil {
		t.Fatalf("Math & constants script failed: %v", err)
	}
	mArr, _ := mRes.([]any)
	if len(mArr) != 3 || mArr[0] != true || mArr[2] != true {
		t.Fatalf("unexpected Math results: %#v", mArr)
	}
}

func TestRound63_OptionalMethodRefsStreamCollectorsAndGeoWrappers(t *testing.T) {
	// 1. Optional, HexFormat, Objects.*, Comparator + Method References, Collection constructors & instanceof
	optScript := `
		List sink = new ArrayList();
		Optional.of('hi').ifPresent(x -> sink.add(x));
		Optional.empty().ifPresentOrElse(x -> sink.add('bad'), () -> sink.add('empty'));
		Optional.of('ok').ifPresentOrElse(x -> sink.add(x), () -> sink.add('bad'));
		String f1 = Optional.of('abcd').filter(s -> s.length() == 4).map(String::toUpperCase).orElse('no');
		String f2 = Optional.ofNullable(null).or(() -> Optional.of('fallback')).orElseGet(() -> 'other');
		int oi = OptionalInt.of(7).getAsInt() + (OptionalInt.empty().isEmpty() ? 1 : 0);
		long ol = OptionalLong.of(9L).getAsLong() + (OptionalLong.empty().isEmpty() ? 1L : 0L);
		double od = OptionalDouble.of(2.5).getAsDouble() + (OptionalDouble.empty().isEmpty() ? 0.5 : 0.0);
		int stLen = (int) Optional.of('z').stream().count() + (int) Optional.empty().stream().count();

		HexFormat hf = HexFormat.of().withPrefix('0x').withSuffix(';').withDelimiter(',').withUpperCase();
		String hexOut = hf.formatHex(new byte[]{(byte) 10, (byte) 255});
		HexFormat hfLow = hf.withLowerCase();

		int cmpObj = Objects.compare('a', 'b', Comparator.naturalOrder());
		String rne = Objects.requireNonNullElseGet(null, () -> 'supplied');
		int chk = Objects.checkIndex(1, 3);

		List words = new ArrayList(['bbb', 'a', 'cc']);
		Collections.sort(words, Comparator.comparingInt(String::length).reversed());
		words.replaceAll(s -> s.toUpperCase());

		List nums = (new ArrayList([1, 2, 3, null])).stream()
			.filter(Objects::nonNull)
			.map(String::valueOf)
			.collect(Collectors.toList());
		int sumRef = [1, 2, 3, 4].stream().reduce(0, Integer::sum);
		int maxRef = [1, 9, 3].stream().reduce(0, Integer::max);
		int minRef = [5, 2, 8].stream().reduce(99, Integer::min);

		Map mp = new LinkedHashMap();
		mp.put('k1', 1);
		mp.put('k2', 2);
		int mpSum = 0;
		mp.forEach((k, v) -> { mpSum += v; });

		URI u1 = new URI('https://example.com/a?q=1');
		URI u2 = new URI('https://example.com/a?q=1');
		URL url1 = new URL('https://example.com/a?q=1');
		URL url2 = new URL('https://example.com/a?q=1');
		OffsetTime ot1 = OffsetTime.parse('10:15:30+01:00');
		OffsetTime ot2 = OffsetTime.parse('10:15:30+01:00');
		Clock clk1 = Clock.fixed(Instant.parse('2020-01-01T00:00:00Z'), ZoneOffset.UTC);
		Clock clk2 = Clock.fixed(Instant.parse('2020-01-01T00:00:00Z'), ZoneOffset.UTC);
		ValueRange vr1 = ChronoField.MONTH_OF_YEAR.range();
		ValueRange vr2 = ChronoField.MONTH_OF_YEAR.range();
		IntSummaryStatistics iss = [1, 2, 3].stream().collect(Collectors.summarizingInt(x -> x));

		boolean instChecks = (words instanceof List) && (mp instanceof Map) && (new HashSet([1]) instanceof Set) &&
			(UUID.randomUUID() instanceof UUID) && (hf instanceof HexFormat) && (iss instanceof IntSummaryStatistics) &&
			(u1 instanceof URI) && (url1 instanceof URL) && (new StringBuilder('x') instanceof StringBuilder) &&
			(DayOfWeek.MONDAY instanceof DayOfWeek);

		return [
			sink.size(), f1, f2, oi, ol, od, stLen, hexOut, hfLow.formatHex(new byte[]{(byte) 10}),
			cmpObj < 0, rne, chk, words[0], nums.size(), sumRef, maxRef, minRef, mpSum,
			u1.equals(u2), url1.equals(url2), ot1.equals(ot2), clk1.equals(clk2), vr1.equals(vr2),
			u1.hashCode() == u2.hashCode(), url1.hashCode() == url2.hashCode(), instChecks
		];
	`
	oRes, err := Eval(nil, optScript, nil)
	if err != nil {
		t.Fatalf("Optional/Stream/MethodRef coverage script failed: %v", err)
	}
	oArr, _ := oRes.([]any)
	if len(oArr) != 26 || oArr[0] != int64(3) || oArr[1] != "ABCD" || oArr[2] != "fallback" || oArr[14] != int64(10) || oArr[25] != true {
		t.Fatalf("unexpected Optional/Stream results: %#v", oArr)
	}

	// 2. GeoPointVal distances, GeoBoundingBoxVal properties, IPAddressVal properties, and wrapper equality
	geoDoc := map[string]any{
		"geo": []any{"40.7128,-74.0060", "34.0522,-118.2437"},
		"ip4": "127.0.0.1",
		"ip6": "fe80::1",
		"ipm": "224.0.0.1",
		"ipp": "192.168.1.5",
	}
	geoParams := map[string]any{
		"__field_types": map[string]string{
			"geo": "geo_point",
			"ip4": "ip",
			"ip6": "ip",
			"ipm": "ip",
			"ipp": "ip",
		},
	}
	geoScript := `
		GeoPoint p1 = doc['geo'].get(0);
		GeoPoint p2 = new GeoPoint(40.7128, -74.0060);
		double arc = p1.arcDistance(40.0, -73.0);
		double plane = p1.planeDistance(40.0, -73.0);
		double gh = p1.geohashDistance('dr5regw3pg6f');
		def bb = doc['geo'].getBoundingBox();
		double boxSum = bb.top + bb.bottom + bb.left + bb.right + bb.topLeft.lat + bb.bottomRight.lon;
		IPAddress a4 = field('ip4').get(null);
		IPAddress a6 = field('ip6').get(null);
		IPAddress am = field('ipm').get(null);
		IPAddress ap = field('ipp').get(null);
		boolean ipFlags = a4.isIPv4() && a4.isLoopbackAddress() && a6.isIPv6() && a6.isLinkLocalAddress() && am.isMulticastAddress() && ap.isSiteLocalAddress() && (a4.getHostAddress() == '127.0.0.1');
		return [arc > 0, plane > 0, gh >= 0, boxSum != 0, ipFlags, p2.lat == 40.7128];
	`
	gRes, err := Eval(geoDoc, geoScript, geoParams)
	if err != nil {
		t.Fatalf("Geo/IP wrapper coverage script failed: %v", err)
	}
	gArr, _ := gRes.([]any)
	for i, b := range gArr {
		if b != true {
			t.Fatalf("geo/ip check %d failed in %#v", i, gArr)
		}
	}
}

func TestRound63_ExtendedEngineCoverageSuite(t *testing.T) {
	// 1. Stream terminal Optional chaining (`findFirst().filter().map().ifPresent()` / `ifPresentOrElse()` / `or()` / `stream()`)
	//    + Collectors.toMap with merge lambda, groupingBy, partitioningBy, summarizingLong/Double
	streamOptScript := `
		List log = new ArrayList();
		[10, 20, 30].stream().findFirst().filter(x -> x == 10).map(x -> x + 5).ifPresent(x -> log.add(x));
		[10, 20].stream().findFirst().filter(x -> x > 99).ifPresentOrElse(x -> log.add('hit'), () -> log.add('miss'));
		[10, 20].stream().findFirst().ifPresentOrElse(x -> log.add(x), () -> log.add('miss'));
		int vOr = [10].stream().findFirst().filter(x -> x < 0).or(() -> Optional.of(77)).orElse(0);
		int vGet = [10].stream().findFirst().filter(x -> x < 0).orElseGet(() -> 88);
		int vCnt = (int) [10].stream().findFirst().stream().count();

		Map merged = ['aa', 'ab', 'ba'].stream().collect(Collectors.toMap(s -> s.substring(0, 1), s -> 1, (a, b) -> a + b));
		Map grouped = ['aa', 'ab', 'b'].stream().collect(Collectors.groupingBy(s -> s.length()));
		Map part = [1, 2, 3, 4].stream().collect(Collectors.partitioningBy(x -> x % 2 == 0));
		LongSummaryStatistics lss = [10L, 20L].stream().collect(Collectors.summarizingLong(x -> x));
		DoubleSummaryStatistics dss = [1.5, 2.5].stream().collect(Collectors.summarizingDouble(x -> x));

		int feSum = 0;
		[1, 2, 3].stream().filter(x -> x > 1).forEach(x -> { feSum += x; });

		return [log.size(), log[0], log[1], vOr, vGet, vCnt, merged['a'], grouped[2].size(), part[true].size(), lss.getSum(), dss.getSum(), feSum];
	`
	soRes, err := Eval(nil, streamOptScript, nil)
	if err != nil {
		t.Fatalf("Stream Optional chaining script failed: %v", err)
	}
	soArr, _ := soRes.([]any)
	if len(soArr) != 12 || soArr[0] != int64(3) || soArr[1] != int64(15) || soArr[2] != "miss" || soArr[3] != int64(77) || soArr[6] != int64(2) || soArr[11] != int64(5) {
		t.Fatalf("unexpected Stream Optional results: %#v", soArr)
	}

	// 2. BigDecimal, BigInteger, BitSet range ops, StringJoiner, Character.* static methods
	numCharScript := `
		MathContext mc = new MathContext(4, RoundingMode.HALF_UP);
		BigDecimal bd1 = new BigDecimal('10.55');
		BigDecimal bd2 = new BigDecimal('3.0');
		def qr = bd1.divideAndRemainder(bd2, mc);
		BigDecimal p = new BigDecimal('1.5').pow(2, mc);
		BigDecimal sc = new BigDecimal('2.345').setScale(2, RoundingMode.HALF_UP);
		BigDecimal mn = bd1.min(bd2);
		BigDecimal mx = bd1.max(bd2);

		BigInteger bi1 = new BigInteger('100');
		BigInteger bi2 = new BigInteger('30');
		def biQR = bi1.divideAndRemainder(bi2);
		BigInteger biGcd = bi1.gcd(bi2);

		BitSet bs = new BitSet();
		bs.set(1, 5);
		bs.flip(3, 6);
		bs.clear(1, 2);
		int card = bs.cardinality();

		StringJoiner sj1 = new StringJoiner(',', '[', ']');
		sj1.setEmptyValue('EMPTY');
		String emptySJ = sj1.toString();
		sj1.add('a');
		StringJoiner sj2 = new StringJoiner('-');
		sj2.add('b');
		sj1.merge(sj2);

		int cc1 = Character.charCount(65);
		int cc2 = Character.charCount(0x1F600);
		def ch1 = Character.toChars(65);
		def ch2 = Character.toChars(0x1F600);
		String cs = Character.toString(66);
		boolean flags = Character.isValidCodePoint(0x1F600) && Character.isBmpCodePoint(65) &&
			Character.isSupplementaryCodePoint(0x1F600) && Character.isHighSurrogate(0xD83D) &&
			Character.isLowSurrogate(0xDE00) && Character.isSurrogate(0xD83D) &&
			Character.isSurrogatePair((char) 0xD83D, (char) 0xDE00) &&
			Character.toCodePoint((char) 0xD83D, (char) 0xDE00) == 0x1F600;

		return [qr.size(), p.doubleValue(), sc.toString(), mn.doubleValue(), mx.doubleValue(), biQR[0].longValue(), biGcd.longValue(), card, emptySJ, sj1.toString(), cc1 + cc2, ch1.size() + ch2.size(), cs, flags];
	`
	ncRes, err := Eval(nil, numCharScript, nil)
	if err != nil {
		t.Fatalf("Numeric/BitSet/Character script failed: %v", err)
	}
	ncArr, _ := ncRes.([]any)
	if len(ncArr) != 14 || ncArr[2] != "2.35" || ncArr[5] != int64(3) || ncArr[6] != int64(10) || ncArr[8] != "EMPTY" || ncArr[10] != int64(3) || ncArr[13] != true {
		t.Fatalf("unexpected Numeric/Character results: %#v", ncArr)
	}

	// 3. OffsetTime / Year / MonthDay `.with(ChronoField.*, ...)`, URI/OffsetTime compareTo, ZoneOffset, range()
	chronoScript := `
		OffsetTime ot = OffsetTime.parse('10:15:30+02:00');
		OffsetTime ot1 = ot.with(ChronoField.MILLI_OF_DAY, 3600000L);
		OffsetTime ot2 = ot.with(ChronoField.MICRO_OF_SECOND, 500L).with(ChronoField.NANO_OF_SECOND, 100L).with(ChronoField.OFFSET_SECONDS, 3600L);
		OffsetTime ot3 = ot.with(ChronoField.MICRO_OF_DAY, 7200000000L);
		OffsetTime ot4 = ot.with(ChronoField.NANO_OF_DAY, 3600000000000L);
		int otCmp = ot1.compareTo(ot2);
		String offStr = ot2.getOffset().toString();

		Year yr = Year.of(2020);
		Year yr1 = yr.with(ChronoField.YEAR, 2021);
		Year yr2 = yr.with(ChronoField.YEAR_OF_ERA, 2022);
		Year yr3 = yr.with(ChronoField.ERA, 0);

		MonthDay md = MonthDay.of(5, 10);
		MonthDay md1 = md.with(ChronoField.MONTH_OF_YEAR, 6).with(ChronoField.DAY_OF_MONTH, 20);
		ValueRange vr = LocalDate.of(2020, 2, 10).range(ChronoField.DAY_OF_MONTH);

		URI uA = new URI('https://a.example.com/p1');
		URI uB = new URI('https://b.example.com/p2');
		int uCmp = uA.compareTo(uB);
		ZoneOffset zo = ZoneOffset.of('+05:30:15');

		return [ot1.getHour(), ot3.getHour(), ot4.getHour(), otCmp != 0, offStr.length() > 0, yr1.getValue(), yr2.getValue(), yr3.getValue() <= 0, md1.toString(), vr.getMaximum(), uCmp < 0, zo.getTotalSeconds() > 0];
	`
	cRes, err := Eval(nil, chronoScript, nil)
	if err != nil {
		t.Fatalf("ChronoField/URI/ZoneOffset script failed: %v", err)
	}
	cArr, _ := cRes.([]any)
	if len(cArr) != 12 || cArr[0] != int64(1) || cArr[1] != int64(2) || cArr[8] != "--06-20" || cArr[9] != int64(29) || cArr[10] != true {
		t.Fatalf("unexpected ChronoField results: %#v", cArr)
	}

	// 4. Ingest `Processors.*` (both mutating `(ctx, field, ...)` and value forms)
	procDoc := map[string]any{
		"sz":   "2kb",
		"low":  "HELLO",
		"up":   "world",
		"tr":   "  spaced  ",
		"gs":   "a-b-c",
		"sp":   "x,y,z",
		"jn":   []any{"p", "q"},
		"conv": "123",
		"old":  "renamed_val",
		"rm":   "gone",
	}
	procScript := `
		Processors.bytes(ctx, 'sz');
		Processors.lowercase(ctx, 'low');
		Processors.uppercase(ctx, 'up');
		Processors.trim(ctx, 'tr');
		Processors.gsub(ctx, 'gs', '-', '_');
		Processors.split(ctx, 'sp', ',');
		Processors.join(ctx, 'jn', '|');
		Processors.convert(ctx, 'conv', 'integer');
		Processors.rename(ctx, 'old', 'new_key');
		Processors.remove(ctx, 'rm');
		Processors.append(ctx, 'arr', 'item1');
		long vBytes = Processors.bytes('1mb');
		String vLow = Processors.lowercase('ABC');
		String vUp = Processors.uppercase('abc');
		String vTrim = Processors.trim(' hi ');
		String vGsub = Processors.gsub('1.2.3', '\\.', '-');
		return [vBytes, vLow, vUp, vTrim, vGsub];
	`
	pRes, err := Eval(procDoc, procScript, map[string]any{"_ingest": map[string]any{}})
	if err != nil {
		t.Fatalf("Processors.* script failed: %v", err)
	}
	pArr, _ := pRes.([]any)
	if procDoc["sz"] != int64(2048) || procDoc["low"] != "hello" || procDoc["up"] != "WORLD" || procDoc["tr"] != "spaced" ||
		procDoc["gs"] != "a_b_c" || procDoc["jn"] != "p|q" || procDoc["conv"] != int64(123) || procDoc["new_key"] != "renamed_val" ||
		pArr[0] != int64(1048576) || pArr[4] != "1-2-3" {
		t.Fatalf("unexpected Processors.* result: doc=%#v res=%#v", procDoc, pArr)
	}

	// 5. Navigable TreeMap / TreeSet / ArrayDeque, Comparator.comparing().reversed(), braceless if/else, user classes & super, ctx direct map ops
	collClassScript := `
		class Base {
			int x;
			Base(int v) { this.x = v; }
			int calc() { return this.x * 2; }
			String toString() { return 'B:' + this.x; }
			int hashCode() { return this.x + 100; }
			boolean equals(Object o) { return o instanceof Base && ((Base) o).x == this.x; }
		}
		class Child extends Base {
			Child(int v) { super(v); }
			int calc() { return super.calc() + 1; }
		}
		Map makeMap() { Map m = new HashMap(); m.put('v', 10); return m; }

		Child ch = new Child(5);
		Child ch2 = new Child(5);
		Map holder = makeMap();
		holder.v += 5;

		TreeMap tm = new TreeMap();
		tm.put('b', 2); tm.put('d', 4); tm.put('f', 6);
		def ck = tm.ceilingKey('c');
		def fk = tm.floorKey('e');
		def hk = tm.higherKey('b');
		def lk = tm.lowerKey('f');
		def sm = tm.subMap('b', true, 'f', false);
		def hm = tm.headMap('d', true);
		def tlm = tm.tailMap('d', false);

		TreeSet ts = new TreeSet([10, 20, 30, 40]);
		def tsc = ts.ceiling(15);
		def tsf = ts.floor(25);
		def tsh = ts.higher(10);
		def tsl = ts.lower(40);
		def tss = ts.subSet(10, true, 30, true);

		ArrayDeque dq = new ArrayDeque();
		dq.offerFirst('a'); dq.offerLast('b'); dq.offerLast('a');
		dq.removeLastOccurrence('a');
		dq.removeFirstOccurrence('b');

		List objs = [ ['n': 2], ['n': 5], ['n': 1] ];
		Collections.sort(objs, Comparator.comparing(o -> o.n).reversed());
		int pairCmp = Objects.compare(['n': 1], ['n': 3], Comparator.comparing(o -> o.n).reversed());

		int br = 0;
		if (objs[0].n == 5) br = 10; else br = 20;
		if (objs[0].n == 99) br += 1; else br += 2;

		return [ch.calc(), ch.toString(), ch.hashCode(), ch.equals(ch2), holder.v, ck, fk, hk, lk, sm.size(), hm.size(), tlm.size(), tsc, tsf, tsh, tsl, tss.size(), dq.size(), objs[0].n, pairCmp > 0, br];
	`
	ccRes, err := Eval(nil, collClassScript, nil)
	if err != nil {
		t.Fatalf("Navigable/UserClass/Comparator script failed: %v", err)
	}
	ccArr, _ := ccRes.([]any)
	if len(ccArr) != 21 || ccArr[0] != int64(11) || ccArr[1] != "B:5" || ccArr[3] != true || ccArr[4] != int64(15) || ccArr[18] != int64(5) || ccArr[20] != int64(12) {
		t.Fatalf("unexpected Navigable/UserClass results: %#v", ccArr)
	}

	// 6. ctx direct map mutations (`mutateCtxDirectMapKey`), special bracket keys (`encodeBracketKey`), map compute/replaceAll/forEach on sourceMap
	ctxDoc := map[string]any{
		"a.b c/d:e-f+g*h%i?j!k=l<m>n&o|p(q)r[s]t{u}v,w;x^y~z#0": int64(99),
		"items": []any{"x", "y"},
	}
	ctxParams := map[string]any{"_ctx_op": "index"}
	if err := EvalPainless(ctxDoc, `
		ctx.put('_routing', 'r1');
		ctx.putIfAbsent('_routing', 'r2');
		ctx.remove('_routing');
		ctx.put('op', 'noop');
		ctx.remove('op');
		ctx.put('op', 'index');
		ctx.putIfAbsent('custom_top', 42);
		ctx.remove('custom_top');
		ctx._source.items.replaceAll(s -> s + '!');
		int valSpec = ctx._source['a.b c/d:e-f+g*h%i?j!k=l<m>n&o|p(q)r[s]t{u}v,w;x^y~z#0'];
		ctx._source.put('spec_val', valSpec);
		ctx.compute('comp_k', (k, v) -> v == null ? 10 : v + 1);
		ctx.compute('comp_k', (k, v) -> v + 5);
	`, ctxParams); err != nil {
		t.Fatalf("ctx direct map ops failed: %v", err)
	}
	if ctxDoc["spec_val"] != int64(99) || ctxDoc["comp_k"] != int64(15) {
		t.Fatalf("unexpected ctxDoc after direct mutations: %#v", ctxDoc)
	}

	// 7. Direct internal helper coverage (`parseISO8601DurationPainless`, `parseISO8601PeriodPainless`,
	//    `inspectEndAnchorPainless`, `painlessValuesEqual`, `painlessDeepEquals`, `HalfFloatToBits` subnormals, `BitSet.getRange`)
	for _, dStr := range []string{"PT1H2M3.5S", "-PT30S", "P2DT4H", "+P1D"} {
		if _, ok := parseISO8601DurationPainless(dStr); !ok {
			t.Fatalf("expected parseISO8601DurationPainless(%q) ok", dStr)
		}
	}
	if _, ok := parseISO8601DurationPainless("INVALID"); ok {
		t.Fatalf("expected parseISO8601DurationPainless invalid")
	}
	for _, pStr := range []string{"P1Y2M3W4D", "-P2Y6M", "+P3D"} {
		if _, ok := parseISO8601PeriodPainless(pStr); !ok {
			t.Fatalf("expected parseISO8601PeriodPainless(%q) ok", pStr)
		}
	}
	if _, ok := parseISO8601PeriodPainless("BAD"); ok {
		t.Fatalf("expected parseISO8601PeriodPainless invalid")
	}
	for _, pat := range []string{`(?im)foo|bar$`, `(?-i:abc)\z`, `(?:a|b)\Z`, `plain`} {
		_, _ = inspectEndAnchorPainless(pat)
	}
	// Subnormal & overflow half-float conversion
	_ = QuantizeHalfFloat(1e-7)
	_ = QuantizeHalfFloat(1e-9)
	_ = QuantizeHalfFloat(1e6)
	_ = QuantizeHalfFloat(1.0009765625)

	bs := &painlessBitSet{}
	_ = bs.setBit(2, true)
	_ = bs.setBit(5, true)
	if subBS, err := bs.getRange(1, 6); err != nil || subBS.cardinality() != 2 {
		t.Fatalf("unexpected BitSet.getRange: (%#v, %v)", subBS, err)
	}
	if !painlessDeepEquals([]any{int64(1), map[string]any{"k": "v"}}, []any{int64(1), map[string]any{"k": "v"}}) {
		t.Fatalf("expected painlessDeepEquals true")
	}
	if painlessDeepEquals([]any{1}, []any{1, 2}) {
		t.Fatalf("expected painlessDeepEquals false")
	}
}

func TestRound63_DeepEngineAndWrapperCoverageSuite(t *testing.T) {
	// 1. Exact Math.*, BigInteger bitwise/modular, BitSet traversal/boolean, StringBuilder mutations, String & Character extras
	deepScript := `
		long fd = Math.floorDiv(-7L, 3L);
		long fm = Math.floorMod(-7L, 3L);
		long ae = Math.addExact(10L, 20L) + Math.subtractExact(30L, 5L) + Math.multiplyExact(3L, 4L) +
			Math.incrementExact(5L) + Math.decrementExact(5L) + Math.negateExact(-3L) + Math.toIntExact(42L);
		int ge1 = Math.getExponent(0.0);
		int ge2 = Math.getExponent(Double.POSITIVE_INFINITY);
		int ge3 = Math.getExponent(8.0);
		boolean fin = Double.isFinite(1.5) && !Double.isFinite(Double.NaN) && Float.isFinite(1.5f);

		BigInteger b1 = new BigInteger('12');
		BigInteger b2 = new BigInteger('10');
		BigInteger bOr = b1.or(b2);
		BigInteger bAnd = b1.and(b2);
		BigInteger bXor = b1.xor(b2);
		BigInteger bAndNot = b1.andNot(b2);
		BigInteger bShl = b1.shiftLeft(2);
		BigInteger bShr = bShl.shiftRight(1);
		BigInteger bMod = b1.mod(new BigInteger('5'));
		BigInteger bMP = new BigInteger('3').modPow(new BigInteger('4'), new BigInteger('7'));
		BigInteger bMI = new BigInteger('3').modInverse(new BigInteger('11'));
		boolean bBits = b1.setBit(0).testBit(0) && !b1.clearBit(2).testBit(2) && b1.flipBit(1).testBit(1) && new BigInteger('13').isProbablePrime(10);

		BitSet bs1 = new BitSet();
		bs1.set(2); bs1.set(6);
		BitSet bs2 = new BitSet();
		bs2.set(6); bs2.set(9);
		boolean inter = bs1.intersects(bs2);
		int ns = bs1.nextSetBit(0);
		int nc = bs1.nextClearBit(2);
		int ps = bs1.previousSetBit(7);
		int pc = bs1.previousClearBit(6);
		bs1.or(bs2);
		bs1.and(bs2);
		bs1.xor(bs2);
		bs2.andNot(bs1);
		bs2.clear();

		StringBuilder sb = new StringBuilder('abcdef');
		sb.insert(2, 'XY');
		sb.delete(0, 1);
		sb.deleteCharAt(0);
		sb.replace(0, 2, 'zz');
		sb.reverse();
		sb.setLength(3);

		String s = 'HelloWorld';
		int ci = s.compareToIgnoreCase('helloworld');
		String cc = s.concat('!');
		boolean ce = s.contentEquals('HelloWorld');
		boolean ew = s.endsWith('World') && s.matches('Hello.*');
		int cp = s.codePointAt(0);
		String rep = 'ab'.repeat(3);
		boolean mir = Character.isMirrored((int) '(') && !Character.isMirrored((int) 'A');

		return [fd, fm, ae > 0, ge1, ge2, ge3, fin, bOr.longValue(), bAnd.longValue(), bXor.longValue(), bAndNot.longValue(), bShr.longValue(), bMod.longValue(), bMP.longValue(), bMI.longValue(), bBits, inter, ns, nc, ps, pc, sb.toString().length(), ci, cc, ce, ew, cp, rep, mir];
	`
	dRes, err := Eval(nil, deepScript, nil)
	if err != nil {
		t.Fatalf("Deep Math/BigInteger/BitSet/StringBuilder script failed: %v", err)
	}
	dArr, _ := dRes.([]any)
	if len(dArr) != 29 || dArr[0] != int64(-3) || dArr[1] != int64(2) || dArr[6] != true || dArr[7] != int64(14) || dArr[15] != true || dArr[28] != true {
		t.Fatalf("unexpected DeepEngine results: %#v", dArr)
	}

	// 2. Collections.* helpers + unmodifiable container enforcement
	collScript := `
		List l = new ArrayList([1, 2, 3, 2]);
		int freq = Collections.frequency(l, 2);
		boolean disj = Collections.disjoint(l, [9, 8]);
		Collections.rotate(l, 1);
		Collections.swap(l, 0, 1);
		Collections.replaceAll(l, 2, 99);
		List nc = Collections.nCopies(3, 'x');
		List sl = Collections.singletonList('only');
		Set ss = Collections.singleton('one');
		Map sm = Collections.singletonMap('k', 'v');
		Collections.fill(l, 7);
		return [freq, disj, l[0], nc.size(), sl.size(), ss.size(), sm['k']];
	`
	clRes, err := Eval(nil, collScript, nil)
	if err != nil {
		t.Fatalf("Collections.* script failed: %v", err)
	}
	clArr, _ := clRes.([]any)
	if len(clArr) != 7 || clArr[0] != int64(2) || clArr[1] != true || clArr[2] != int64(7) || clArr[6] != "v" {
		t.Fatalf("unexpected Collections.* results: %#v", clArr)
	}

	for _, immScript := range []string{
		"List u = Collections.unmodifiableList([1, 2]); u.add(3);",
		"List u = Collections.unmodifiableList([1, 2]); u.clear();",
		"Map u = Collections.unmodifiableMap(['a': 1]); u.put('b', 2);",
		"Map u = Collections.unmodifiableMap(['a': 1]); u.remove('a');",
		"Map u = Collections.unmodifiableMap(['a': 1]); u.clear();",
	} {
		if _, err := Eval(nil, immScript, nil); err == nil {
			t.Fatalf("expected UnsupportedOperationException for %q", immScript)
		}
	}

	// 3. UpdateMetadataVal immutable setter errors + CheckUpsertRoutingGuardRound61 + ValidateUpdateCtxMutations + round60WrapperEquals
	umv := &UpdateMetadataVal{Params: map[string]any{"__is_update_doc": true, "__is_es8": true}}
	for _, badProp := range []string{"id", "index", "routing", "version", "unknown_prop"} {
		if err := umv.setField(badProp, "x"); err == nil {
			t.Fatalf("expected UpdateMetadataVal.setField(%q) error", badProp)
		}
	}
	if err := umv.setField("op", "invalid_op"); err == nil {
		t.Fatalf("expected invalid op error on UpdateMetadataVal")
	}
	umvUpsert := &UpdateMetadataVal{Params: map[string]any{"__upsert_insert_mode": true}}
	if err := umvUpsert.setField("routing", "r1"); err == nil || !strings.Contains(err.Error(), "upsert") {
		t.Fatalf("expected upsert routing error, got: %v", err)
	}
	umvUBQ := &UpdateMetadataVal{Params: map[string]any{"__is_ubq": true, "__is_es8": true}}
	if err := umvUBQ.setField("op", "create"); err == nil {
		t.Fatalf("expected UBQ create op error on UpdateMetadataVal")
	}

	if CheckUpsertRoutingGuardRound61(true, "", "", "", false) == nil {
		t.Fatalf("expected routing_missing_exception")
	}
	if CheckUpsertRoutingGuardRound61(false, "r1", "", "r2", false) == nil {
		t.Fatalf("expected upsert routing change error")
	}
	if CheckUpsertRoutingGuardRound61(false, "", "r1", "r2", true) == nil {
		t.Fatalf("expected existing doc routing change error")
	}
	if CheckUpsertRoutingGuardRound61(true, "r1", "", "r1", false) != nil {
		t.Fatalf("expected valid routing guard")
	}
	if ValidateUpdateCtxMutations("1", map[string]any{"_id": "2"}) == nil {
		t.Fatalf("expected ValidateUpdateCtxMutations _id error")
	}
	if ValidateUpdateCtxMutations("1", map[string]any{"_id": "1", "_source": map[string]any{"a": 1}, "op": "index"}) != nil {
		t.Fatalf("expected ValidateUpdateCtxMutations valid")
	}

	// Symmetric round60WrapperEquals coverage across wrapper types
	zdt, _ := parseZonedDateTimeValRound60("2020-05-15T00:00:00Z", false)
	inst := zdt.ToInstant()
	gp := &GeoPointVal{Lat: 1.0, Lon: 2.0}
	br := newBytesRefValRound60([]byte("abc"))
	bb := newByteBufferValRound60([]byte("abc"))
	ver := NewVersionVal("1.2.3")
	eqPairs := [][2]any{
		{"2020-05-15T00:00:00Z", zdt},
		{"2020-05-15T00:00:00Z", inst},
		{gp, &GeoPointVal{Lat: 1.0, Lon: 2.0}},
		{br, newBytesRefValRound60([]byte("abc"))},
		{bb, newByteBufferValRound60([]byte("abc"))},
		{"1.2.3", ver},
		{[]any{1.0, 2.0}, []float64{1.0, 2.0}},
	}
	for _, pair := range eqPairs {
		if eq, handled := round60WrapperEquals(pair[0], pair[1]); !handled || !eq {
			t.Fatalf("expected round60WrapperEquals(%T, %T) == (true, true), got (%v, %v)", pair[0], pair[1], eq, handled)
		}
	}
}

func TestRound63_AdditionalReachableCoverageSuite(t *testing.T) {
	// 1. Year arithmetic, RHS map.remove(k, v) & containsAll/removeAll/retainAll, String.join varargs,
	//    Matcher region with anchoringBoundsDisabled, 2-arg Comparator lambdas, post-call property assignment
	s1 := `
		Map shared = ['v': 10];
		Map getShared(Map s) { return s; }
		int a = (getShared(shared).v = 20);
		int b = (getShared(shared).v += 7);

		Year y = Year.of(2020);
		Year y1 = y.plusYears(5).minusYears(2).withYear(2030);
		Year y2 = y1.plus(1, ChronoUnit.DECADES).plus(1, ChronoUnit.CENTURIES).plus(1, ChronoUnit.MILLENNIA).plus(Period.ofYears(3));

		Map m = ['a': 1, 'b': 2, 'c': 3];
		boolean rmOk = m.remove('a', 1);
		boolean rmNo = m.remove('b', 99);
		def rmOld = m.remove('c');

		List l = new ArrayList([1, 2, 3, 4]);
		boolean caOk = l.containsAll([1, 3]);
		boolean caNo = l.containsAll([1, 9]);
		boolean retChg = l.retainAll([1, 2]);
		boolean remChg = l.removeAll([2]);
		String jVar = String.join('-', 'x', 'y', 'z');

		Matcher mt1 = Pattern.compile('^abc$').matcher('xx abc yy');
		mt1.region(3, 6);
		mt1.useAnchoringBounds(false);
		boolean mFail = mt1.matches();
		Matcher mt2 = Pattern.compile('abc').matcher('xx abc yy');
		mt2.region(3, 6);
		boolean mPass = mt2.matches();

		List nums = new ArrayList([3, 1, 4, 2]);
		Collections.sort(nums, (x, z) -> z - x);
		Comparator cmpVar = Comparator.comparingInt(k -> k);
		Collections.sort(nums, cmpVar.reversed());
		int cPair = Objects.compare(2, 5, (x, z) -> z - x);

		return [a, b, y2.getValue(), rmOk, rmNo, rmOld, caOk, caNo, retChg, remChg, jVar, mFail, mPass, nums[0], cPair > 0];
	`
	r1, err := Eval(nil, s1, nil)
	if err != nil {
		t.Fatalf("s1 failed: %v", err)
	}
	a1, _ := r1.([]any)
	if len(a1) != 15 || a1[0] != int64(20) || a1[1] != int64(27) || a1[2] != int64(3143) || a1[3] != true || a1[4] != false || a1[10] != "x-y-z" || a1[11] != false || a1[12] != true {
		t.Fatalf("unexpected s1 results: %#v", a1)
	}

	// 2. ApplyUpdateWithResult AllowMetaMutation & IsUBQ branches
	allowReq := &UpdateRequest{
		Script:            &ScriptSpec{Source: "ctx._id = 'new-id'; ctx._index = 'new-idx'; ctx._routing = 'r9'; ctx._version = 4; ctx._source.x = 1"},
		AllowMetaMutation: true,
		IsES8:             true,
	}
	if _, op, err := ApplyUpdateWithResult(json.RawMessage(`{"x":0}`), allowReq, true); err != nil || op != "updated" || allowReq.MetaID != "new-id" || allowReq.MetaIndex != "new-idx" || allowReq.MetaRouting != "r9" || allowReq.MetaVersion != 4 {
		t.Fatalf("AllowMetaMutation failed: op=%q err=%v req=%#v", op, err, allowReq)
	}

	ubqNoop := &UpdateRequest{Script: &ScriptSpec{Source: "ctx.op = 'noop'"}, IsUBQ: true, IsES8: true}
	if _, op, err := ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), ubqNoop, true); err != nil || op != "noop" {
		t.Fatalf("UBQ noop failed: (%q, %v)", op, err)
	}
	ubqDel := &UpdateRequest{Script: &ScriptSpec{Source: "ctx.op = 'delete'"}, IsUBQ: true, IsES8: true}
	if _, op, err := ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), ubqDel, true); err != nil || op != "deleted" {
		t.Fatalf("UBQ delete failed: (%q, %v)", op, err)
	}
	ubqBad := &UpdateRequest{Script: &ScriptSpec{Source: "ctx.op = 'create'"}, IsUBQ: true, IsES8: true}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), ubqBad, true); err == nil {
		t.Fatalf("expected UBQ invalid op error")
	}

	// 3.UpdateMetadataVal compound assignment (`m.op += ''`, `metadata().op += ''`)
	compParams := map[string]any{"__is_update_doc": true, "__is_es8": true, "_ctx_op": "noop"}
	if opRes, err := EvalPainlessWithOp(map[string]any{"a": 1}, "Metadata m = metadata(); m.op += ''; metadata().op += '';", compParams); err != nil || opRes != "noop" {
		t.Fatalf("UpdateMetadataVal compound assign failed: (%q, %v)", opRes, err)
	}

	// 4. resolveWrapperPropertyRound60, evalInstanceOfPainless, unwrapPainlessInternalValue, and .length/.empty wrappers
	ip4, _ := ParseIPAddressVal("127.0.0.1")
	ip6, _ := ParseIPAddressVal("fe80::1")
	for _, prop := range []string{"hostAddress", "IPv4", "IPv6", "loopbackAddress", "multicastAddress", "siteLocalAddress", "linkLocalAddress"} {
		if _, ok := resolveWrapperPropertyRound60(ip4, prop); !ok {
			t.Fatalf("expected IPAddressVal prop %q", prop)
		}
		if _, ok := resolveWrapperPropertyRound60(ip6, prop); !ok {
			t.Fatalf("expected IPAddressVal v6 prop %q", prop)
		}
	}
	dvf := &DenseVectorFieldVal{Present: true, Vec: &DenseVectorVal{Floats: []float32{3, 4}, ElemType: "float"}}
	dvfMissing := &DenseVectorFieldVal{Present: false}
	for _, prop := range []string{"empty", "dims", "magnitude", "value"} {
		_, _ = resolveWrapperPropertyRound60(dvf, prop)
		_, _ = resolveWrapperPropertyRound60(dvfMissing, prop)
	}
	dvByte := &DenseVectorVal{Floats: []float32{1, 2}, Bytes: []int8{1, 2}, ElemType: "byte"}
	_, _ = resolveWrapperPropertyRound60(dvByte, "0")

	// evalInstanceOfPainless across temporal, regex, math, and ES wrapper types
	zdt, _ := parseZonedDateTimeValRound60("2020-05-15T10:20:30Z", false)
	instChecks := []struct {
		val any
		typ string
	}{
		{zdt, "ZonedDateTime"},
		{zdt.ToInstant(), "Instant"},
		{"2020-05-15", "LocalDate"},
		{"10:20:30", "LocalTime"},
		{"2020-05", "YearMonth"},
		{painlessYear{year: 2020}, "Year"},
		{painlessMonthDay{month: 5, day: 15}, "MonthDay"},
		{"/abc/", "Pattern"},
		{map[string]any{"k": 1}, "Metadata"},
		{&UpdateMetadataVal{}, "Metadata"},
		{NewVersionVal("1.0"), "Version"},
		{&GeoPointVal{Lat: 1, Lon: 2}, "GeoPoint"},
		{newBytesRefValRound60([]byte("a")), "BytesRef"},
		{newByteBufferValRound60([]byte("a")), "ByteBuffer"},
	}
	for _, ic := range instChecks {
		if !evalInstanceOfPainless(ic.val, ic.typ) {
			t.Fatalf("expected evalInstanceOfPainless(%T, %q) == true", ic.val, ic.typ)
		}
	}

	// unwrapPainlessInternalValue on slice with OffsetTime, URI, URL, large BigInteger, painlessEmptyOptional
	ot, _ := parsePainlessOffsetTime("10:15:30+01:00")
	uri, _ := newPainlessURIFromString("https://example.com")
	uVal, _ := newPainlessURLFromString("https://example.com")
	bigU, _ := coerceToBigIntegerRound63(uint64(math.MaxUint64), "u")
	unwrapped := unwrapPainlessInternalValue([]any{ot, uri, uVal, bigU, painlessEmptyOptional})
	if uSlice, ok := unwrapped.([]any); !ok || len(uSlice) != 5 || uSlice[3] != "18446744073709551615" || uSlice[4] != nil {
		t.Fatalf("unexpected unwrapPainlessInternalValue: %#v", unwrapped)
	}

	// .empty and .length on ByteBufferVal, BytesRefVal, []float64
	wrapDoc := map[string]any{
		"raw_binary": "AQID",
		"fslice":     []float64{1.0, 2.0},
	}
	wRes, err := Eval(wrapDoc, "def bb = field('raw_binary').get(); BytesRef br = doc['raw_binary'].value; return [bb.empty, bb.length, br.empty, br.length, params.fs.empty, params.fs.length];", map[string]any{"fs": []float64{1.0, 2.0}})
	if err != nil {
		t.Fatalf("wrapper .empty/.length failed: %v", err)
	}
	wArr, _ := wRes.([]any)
	if len(wArr) != 6 || wArr[0] != false || wArr[1] != int64(3) || wArr[3] != int64(3) || wArr[5] != int64(2) {
		t.Fatalf("unexpected wrapper .empty/.length: %#v", wArr)
	}
}

func TestRound63_FinalCoveragePushSuite(t *testing.T) {
	// 1. Inline literal collection ops, StringMonth/DOW .getValue(), wrapper constants, Integer/Long bit ops,
	//    Year.atDay/atMonth/atMonthDay, ZoneId.ofOffset, ZoneOffset, 7-arg URI, Collections.addAll, Arrays.copyOf,
	//    float32 *, /, %, assignment in condition, post-call ++/--, .clear() paths
	s := `
		Map shared = ['v': 5, 'sub': ['a': 1]];
		Map getS(Map x) { return x; }
		int pre = ++shared.v;
		int post = shared.v++;
		getS(shared).sub.clear();

		boolean r1 = [1, 2, 3].removeAll([2]);
		boolean r2 = [1, 2, 3].retainAll([2]);
		List c1 = [1, 2].concat([3]);
		boolean m1 = ['a': 1].remove('a', 1);
		def m2 = ['a': 1].remove('a');
		int ci1 = 'Abc'.compareToIgnoreCase('aBC');

		List months = ['JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE', 'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER', 'NOVEMBER', 'DECEMBER'];
		int mSum = 0;
		for (def mn : months) { mSum += mn.getValue(); }

		long bitOps = Integer.bitCount(7) + Long.bitCount(7L) + Integer.numberOfLeadingZeros(8) +
			Integer.numberOfTrailingZeros(8) + Long.numberOfLeadingZeros(8L) + Long.numberOfTrailingZeros(8L) +
			Integer.highestOneBit(10) + Integer.lowestOneBit(10) + Integer.rotateLeft(1, 2) + Integer.rotateRight(4, 1);
		boolean logOps = Boolean.logicalAnd(true, true) && Boolean.logicalOr(false, true) && Boolean.logicalXor(true, false);
		int dCmp = Double.compare(1.0, 2.0) + Float.compare(2.0f, 1.0f);
		long consts = Byte.MAX_VALUE + Byte.MIN_VALUE + Short.MAX_VALUE + Short.MIN_VALUE + (int) Character.MAX_VALUE + (int) Character.MIN_VALUE;

		Year yr = Year.of(2020);
		String ad = yr.atDay(60);
		String am = yr.atMonth(5);
		String amd = yr.atMonthDay(MonthDay.of(2, 29));
		ZoneId zid = ZoneId.ofOffset('UTC', ZoneOffset.ofHoursMinutesSeconds(2, 30, 15));
		OffsetTime otHalf = OffsetTime.parse('10:00:00Z').plus(1, ChronoUnit.HALF_DAYS);
		URI fullURI = new URI('http', 'user', 'example.com', 8080, '/p', 'q=1', 'frag');

		List ca = new ArrayList(['a']);
		Collections.addAll(ca, 'b', 'c');
		def cp1 = Arrays.copyOf([1, 2, 3], 5);
		def cp2 = Arrays.copyOfRange([1, 2, 3, 4], 1, 3);

		boolean condFlag = false;
		int condHit = 0;
		if (condFlag = true) { condHit = 1; }

		float fMul = params.f1 * params.f2;
		float fDiv = params.f1 / params.f2;
		float fMod = params.f1 % params.f2;

		int mapSum = 0;
		for (def entry : ['x': 3, 'y': 4]) { mapSum += entry.value; }
		double fsSum = 0;
		for (double d : params.fslice) { fsSum += d; }

		return [pre, post, shared.sub.size(), r1, r2, c1.size(), m1, m2, ci1, mSum, bitOps > 0, logOps, dCmp, consts != 0, ad, am, amd, zid.getId().length() > 0, otHalf.getHour(), fullURI.getPort(), ca.size(), cp1.length, cp2.length, condHit, fMul > 0, fDiv > 0, fMod >= 0, mapSum, fsSum];
	`
	res, err := Eval(nil, s, map[string]any{
		"f1":     float32(6.5),
		"f2":     float32(2.0),
		"fslice": []float64{1.5, 2.5},
	})
	if err != nil {
		t.Fatalf("FinalCoveragePushSuite script failed: %v", err)
	}
	arr, _ := res.([]any)
	if len(arr) != 29 || arr[0] != int64(6) || arr[1] != int64(6) || arr[9] != int64(78) || arr[14] != "2020-02-29" || arr[19] != int64(8080) || arr[20] != int64(3) || arr[23] != int64(1) {
		t.Fatalf("unexpected FinalCoveragePushSuite results: %#v", arr)
	}

	// 2. Direct sortPainlessSliceInPlace & evalPainlessComparatorPair parenthesized comparing/naturalOrder/reverseOrder
	sArr := []any{map[string]any{"n": int64(2)}, map[string]any{"n": int64(5)}, map[string]any{"n": int64(1)}}
	p := map[string]any{}
	if err := sortPainlessSliceInPlace(sArr, "(Comparator.comparing(o -> o.n)).reversed()", nil, p, 0); err != nil {
		t.Fatalf("sortPainlessSliceInPlace parenthesized comparing failed: %v", err)
	}
	numSlice := []any{int64(1), int64(3), int64(2)}
	_ = sortPainlessSliceInPlace(numSlice, "(Comparator.reverseOrder()).reversed()", nil, p, 0)
	_ = sortPainlessSliceInPlace(numSlice, "(Comparator.naturalOrder()).reversed()", nil, p, 0)
	_, _ = evalPainlessComparatorPair("(Comparator.comparing(o -> o.n)).reversed()", sArr[0], sArr[1], nil, p, 0)
	_, _ = evalPainlessComparatorPair("(Comparator.reverseOrder()).reversed()", int64(1), int64(2), nil, p, 0)
	_, _ = evalPainlessComparatorPair("(Comparator.naturalOrder()).reversed()", int64(1), int64(2), nil, p, 0)

	// 3. FormatValueSafe nil typed pointers, missing FieldVal zero-arg/1-arg getters, unsigned_long Go input types, DenseVector iteration
	nilWrappers := []any{
		(*IPAddressVal)(nil), (*DenseVectorVal)(nil), (*DenseVectorFieldVal)(nil),
		(*GeoBoundingBoxVal)(nil), (*ZonedDateTimeVal)(nil), (*InstantVal)(nil),
		(*DayOfWeekEnum)(nil), (*MonthEnum)(nil), (*GrokExtractor)(nil),
		(*DissectExtractor)(nil), (*GeoPointVal)(nil), (*BytesRefVal)(nil),
		(*ByteBufferVal)(nil), (*FieldVal)(nil), (*VersionVal)(nil),
		(*UpdateMetadataVal)(nil), (*PainlessLambda)(nil),
	}
	for _, nw := range nilWrappers {
		if FormatValueSafe(nw) != "null" {
			t.Fatalf("expected 'null' for %T, got %q", nw, FormatValueSafe(nw))
		}
	}

	// round60WrapperEquals additional types (IPAddressVal, GeoBoundingBoxVal, DayOfWeekEnum, MonthEnum, DenseVectorVal)
	ipA, _ := ParseIPAddressVal("10.0.0.1")
	boxA := &GeoBoundingBoxVal{TopLeft: &GeoPointVal{Lat: 10, Lon: -10}, BottomRight: &GeoPointVal{Lat: 0, Lon: 0}}
	dvA := &DenseVectorVal{Floats: []float32{1, 2}, ElemType: "float", Present: true}
	_, _ = round60WrapperEquals("10.0.0.1", ipA)
	_, _ = round60WrapperEquals(boxA, boxA)
	_, _ = round60WrapperEquals("MONDAY", DayOfWeekEnum{Value: 1, NameStr: "MONDAY"})
	_, _ = round60WrapperEquals("JANUARY", MonthEnum{Value: 1, NameStr: "JANUARY"})
	_, _ = round60WrapperEquals([]any{1.0, 2.0}, dvA)

	// unsigned_long normalization across Go uint64/uint/uint32/int64/int/string/BigInteger
	biBig, _ := coerceToBigIntegerRound63(uint64(99), "ul")
	ulNorm := normalizeSingleFieldDocValuesWithOptsRound61(
		[]any{uint64(10), uint(20), uint32(30), int64(40), int(50), "60", biBig},
		"unsigned_long", true, false, "", false,
	)
	if len(ulNorm) != 7 {
		t.Fatalf("expected 7 normalized unsigned_long values, got %#v", ulNorm)
	}

	// Missing FieldVal asBigInteger / asLong (0-arg and 1-arg) + VersionVal receiver methods + DenseVector foreach
	dvDoc := map[string]any{
		"vec": []any{1.0, 2.0, 3.0},
	}
	dvParams := map[string]any{
		"__field_types": map[string]string{"vec": "dense_vector", "ul": "unsigned_long"},
	}
	dvRes, err := Eval(dvDoc, `
		double vSum = 0;
		for (double x : doc['vec']) { vSum += x; }
		Version v = new Version('1.2.3');
		return [
			vSum,
			field('ul').asBigInteger(),
			field('ul').asLong(),
			field('ul').asBigInteger(BigInteger.ONE).longValue(),
			field('ul').asLong(42L),
			v.toString(),
			v.compareTo('1.2.0') > 0,
			v.equals('1.2.3')
		];
	`, dvParams)
	if err != nil {
		t.Fatalf("missing FieldVal / DenseVector foreach failed: %v", err)
	}
	dvArr, _ := dvRes.([]any)
	if len(dvArr) != 8 || dvArr[0] != float64(6.0) || dvArr[1] != nil || dvArr[2] != nil || dvArr[3] != int64(1) || dvArr[4] != int64(42) || dvArr[5] != "1.2.3" {
		t.Fatalf("unexpected dvArr: %#v", dvArr)
	}

	// Map.of duplicate key error & ctx._source.clear()
	if _, err := Eval(nil, "return Map.of('a', 1, 'a', 2);", nil); err == nil {
		t.Fatalf("expected IllegalArgumentException on Map.of duplicate key")
	}
	clrDoc := map[string]any{"a": 1, "b": 2}
	if err := EvalPainless(clrDoc, "ctx._source.clear();", nil); err != nil || len(clrDoc) != 0 {
		t.Fatalf("ctx._source.clear() failed: (%#v, %v)", clrDoc, err)
	}

	// 4. Default user-class toString/hashCode/equals, unary +, BigDecimal scientific toString,
	//    BCE Year YEAR_OF_ERA, Base64 raw decode, Class instanceof, fielddata & flattened & emit()
	extraScript := `
		class PlainObj { int k; PlainObj(int v) { this.k = v; } }
		PlainObj o1 = new PlainObj(3);
		PlainObj o2 = new PlainObj(3);
		int uPlus = +5 + (+2);
		String bdSci1 = new BigDecimal('1E-8').toString();
		String bdSci2 = new BigDecimal('123E-10').toString();
		long bceYoe = Year.of(-5).getLong(ChronoField.YEAR_OF_ERA);
		byte[] b64 = Base64.getDecoder().decode('YWJj');
		boolean clsInst = ('x'.getClass() instanceof Class);
		List blk = [1, 2, 3].stream().map(x -> { int y = x * 2; return y + 1; }).collect(Collectors.toList());
		return [o1.toString().length() > 0, o1.hashCode() != 0, o1.equals(o1), !o1.equals(o2), uPlus, bdSci1, bdSci2, bceYoe, b64.length, clsInst, blk[0]];
	`
	exRes, err := Eval(nil, extraScript, nil)
	if err != nil {
		t.Fatalf("extraScript failed: %v", err)
	}
	exArr, _ := exRes.([]any)
	if len(exArr) != 11 || exArr[0] != true || exArr[2] != true || exArr[3] != true || exArr[4] != int64(7) || exArr[7] != int64(6) || exArr[9] != true || exArr[10] != int64(3) {
		t.Fatalf("unexpected extraScript results: %#v", exArr)
	}

	// BigDecimal BigInteger/MathContext constructors, UUID(msb, lsb), HashMap(map), String(char[]/byte[]),
	// RHS ctx.remove(k, v), Objects.toString(stats / null, null), instanceof Math/BitSet/Joiner/Comparator/TemporalAdjuster
	ctorCtxDoc := map[string]any{"k": int64(1), "k2": int64(2)}
	ctorCtxParams := map[string]any{"_ctx_routing": "r1", "_ctx_op": "index"}
	ctorRes, err := Eval(ctorCtxDoc, `
		MathContext mc = new MathContext(3, RoundingMode.HALF_UP);
		BigDecimal bdEmpty = new BigDecimal();
		BigDecimal bdBIMC = new BigDecimal(new BigInteger('12345'), mc);
		BigDecimal bdBISc = new BigDecimal(new BigInteger('12345'), 2, mc);
		UUID uu = new UUID(123L, 456L);
		Map hmCopy = new HashMap(['x': 9]);
		String sChars = new String(new char[]{'h', 'i'});
		String sBytes = new String(new byte[]{(byte) 65, (byte) 66});
		boolean cr1 = ctx.remove('_routing', 'r1');
		boolean cr2 = ctx.remove('_routing', 'nope');
		boolean cr3 = ctx.remove('op', 'index');
		boolean cr4 = ctx.remove('k', 1);
		boolean cr5 = ctx._source.remove('k2', 2);
		IntSummaryStatistics st = [1, 2].stream().collect(Collectors.summarizingInt(z -> z));
		String ots1 = Objects.toString(st);
		def ots2 = Objects.toString(null, null);
		boolean moreInst = (bdBIMC instanceof BigDecimal) && (new BigInteger('5') instanceof BigInteger) &&
			(mc instanceof MathContext) && (TemporalAdjusters.firstDayOfMonth() instanceof TemporalAdjuster) &&
			(Comparator.naturalOrder() instanceof Comparator) && (new BitSet() instanceof BitSet) &&
			(new StringJoiner(',') instanceof StringJoiner) && (RoundingMode.HALF_UP instanceof RoundingMode) &&
			(ChronoField.YEAR instanceof ChronoField);
		return [bdEmpty.intValue(), bdBIMC.doubleValue() > 0, bdBISc.doubleValue() > 0, uu.toString().length() > 0, hmCopy['x'], sChars, sBytes, cr1, cr2, cr3, cr4, cr5, ots1.length() > 0, ots2 == null, moreInst];
	`, ctorCtxParams)
	if err != nil {
		t.Fatalf("ctor/ctx.remove script failed: %v", err)
	}
	ctArr, _ := ctorRes.([]any)
	if len(ctArr) != 15 || ctArr[4] != int64(9) || ctArr[5] != "hi" || ctArr[6] != "AB" || ctArr[7] != true || ctArr[8] != false || ctArr[14] != true {
		t.Fatalf("unexpected ctorArr: %#v", ctArr)
	}

	for _, rawSig := range []string{"java.util.List<String>", "java.lang.Integer[]", "java.math.BigDecimal", "java.time.ZonedDateTime", "Map.Entry<String,Object>"} {
		_ = normalizeDeclaredSignatureTypeRound59(rawSig)
	}

	// painlessValuesEqual, compareOrderedValues, isIncompleteControlHeader, parseZoneOffsetSecondsPainless, emit(ip), fielddata/flattened
	bdA, _ := parsePainlessBigDecimal("10.0")
	bdB, _ := parsePainlessBigDecimal("10.00")
	biA, _ := coerceToBigIntegerRound63(42, "f")
	biB, _ := coerceToBigIntegerRound63(42, "f")
	_ = painlessValuesEqual(nil, nil)
	_ = painlessValuesEqual(nil, 1)
	_ = painlessValuesEqual(bdA, bdB)
	_ = painlessValuesEqual(biA, biB)
	_ = painlessValuesEqual(int64(5), float64(5.0))
	_ = painlessValuesEqual(true, false)
	_ = painlessValuesEqual("a", "a")
	_ = painlessValuesEqual(map[string]any{"a": 1}, map[string]any{"a": 1})

	for _, op := range []string{"<", "<=", ">", ">="} {
		_ = compareOrderedValues("a", "b", op)
		_ = compareOrderedValues(bdA, bdB, op)
		_ = compareOrderedValues(biA, biB, op)
	}
	for _, hdr := range []string{"if (a > 0", "for (int i = 0;", "while (x", "x = 1"} {
		_ = isIncompleteControlHeader(hdr)
	}
	for _, zo := range []string{"Z", "+02", "-05:30", "+01:02:03", "UTC+03:00", "GMT-04:00", "bad"} {
		_, _ = parseZoneOffsetSecondsPainless(zo)
	}

	// __fielddata_tokens & __flattened_fields & runtime emit() for ip / date / geo_point
	fdDoc := map[string]any{
		"flat": map[string]any{"sub": map[string]any{"leaf": []any{"v2", "v1"}}},
	}
	fdParams := map[string]any{
		"__fielddata_tokens": map[string][]string{"txt": {"hello", "world"}},
		"__flattened_fields": map[string]bool{"flat": true},
		"__emit_field_type":  "ip",
	}
	emRes, err := Eval(fdDoc, "emit('192.168.0.1');", fdParams)
	if err != nil || emRes == nil {
		t.Fatalf("emit ip failed: (%#v, %v)", emRes, err)
	}
	ftRes, err := Eval(fdDoc, "return [doc['txt'].size(), doc['flat.sub.leaf'].size(), field('flat.sub.leaf').size()];", fdParams)
	if err != nil {
		t.Fatalf("fielddata/flattened failed: %v", err)
	}
	ftArr, _ := ftRes.([]any)
	if len(ftArr) != 3 || ftArr[0] != int64(2) || ftArr[1] != int64(2) || ftArr[2] != int64(2) {
		t.Fatalf("unexpected fielddata/flattened: %#v", ftArr)
	}
}

func TestRound63_JDKAndFieldWrapperEdgeCoverage(t *testing.T) {
	// 1. VersionVal, SemVer edge cases, and unsigned_long / FieldVal indexed overloads
	v := NewVersionVal("1.2.3")
	if v.String() != "1.2.3" || !v.Equals(NewVersionVal("1.2.3")) || !v.Equals("1.2.3") || v.Equals(42) {
		t.Fatalf("VersionVal methods failed")
	}
	var nilVer *VersionVal
	if nilVer.String() != "null" || !nilVer.Equals(nil) || nilVer.CompareTo("1.0.0") != -1 {
		t.Fatalf("nil VersionVal edge cases failed")
	}
	if jb, err := nilVer.MarshalJSON(); err != nil || string(jb) != "null" {
		t.Fatalf("nil VersionVal MarshalJSON failed: %s, %v", string(jb), err)
	}
	if jb, err := v.MarshalJSON(); err != nil || string(jb) != `"1.2.3"` {
		t.Fatalf("VersionVal MarshalJSON failed: %s, %v", string(jb), err)
	}
	semverPairs := [][3]any{
		{"", "1.0.0", -1},
		{"1.0.0", "", 1},
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha", 1},
		{"1.a.0", "1.b.0", -1},
	}
	for _, sp := range semverPairs {
		if got := CompareSemverStringsES(sp[0].(string), sp[1].(string)); got != sp[2].(int) {
			t.Fatalf("CompareSemverStringsES(%q, %q) = %d, want %d", sp[0], sp[1], got, sp[2])
		}
	}
	for _, cv := range []any{uint(7), uint32(8), int32(9), float32(10.0), float64(11.0)} {
		if bi, err := coerceToBigIntegerRound63(cv, "f"); err != nil || bi == nil {
			t.Fatalf("coerceToBigIntegerRound63(%T) failed: %v", cv, err)
		}
	}
	if _, err := coerceToBigIntegerRound63("not_a_num", "f"); err == nil {
		t.Fatalf("expected error on invalid BigInteger coercion")
	}
	if lv, err := coerceToLongFieldValRound63(uint64(42), "f"); err != nil || lv != int64(42) {
		t.Fatalf("coerceToLongFieldValRound63(uint64) = (%#v, %v)", lv, err)
	}
	if _, err := coerceToLongFieldValRound63("not_a_long", "f"); err == nil {
		t.Fatalf("expected error on invalid long coercion")
	}

	ulDoc := map[string]any{
		"ul":  []any{uint64(100), uint64(200)},
		"sub": map[string]any{"leaf": "ok"},
	}
	ulParams := map[string]any{
		"__field_types": map[string]string{"ul": "unsigned_long"},
	}
	ulIdxScript := `
		Version v1 = new Version('1.2.3');
		boolean veq = v1.equals(new Version('1.2.3')) && (v1.toString() == '1.2.3');
		long gv0 = field('ul').getValue(0, 0L);
		long gvOut = field('ul').getValue(5, 99L);
		BigInteger bi0 = field('ul').asBigInteger(0, BigInteger.ZERO);
		BigInteger biOut = field('ul').asBigInteger(5, BigInteger.ONE);
		long al0 = field('ul').asLong(0, 0L);
		long alOut = field('ul').asLong(5, 88L);
		String subLeaf = field('sub').doc().$('leaf', 'def');
		return [veq, gv0, gvOut, bi0.longValue(), biOut.longValue(), al0, alOut, subLeaf];
	`
	ulIdxRes, err := Eval(ulDoc, ulIdxScript, ulParams)
	if err != nil {
		t.Fatalf("ulIdxScript failed: %v", err)
	}
	ulArr, _ := ulIdxRes.([]any)
	if len(ulArr) != 8 || ulArr[0] != true || ulArr[1] != int64(100) || ulArr[2] != int64(99) || ulArr[4] != int64(1) || ulArr[6] != int64(88) || ulArr[7] != "ok" {
		t.Fatalf("unexpected ulIdxScript results: %#v", ulArr)
	}
	if _, err := Eval(nil, "return new Version('1.0.0').compareTo(null);", nil); err == nil {
		t.Fatalf("expected NPE on Version.compareTo(null)")
	}

	// 2. Character code points/surrogates/constants, BitSet clear/flip/equals, BigInteger.toByteArray,
	//    Double/Float.isFinite, Objects.*, Encoding.*, Arrays.copyOf*, OffsetTime.truncatedTo, Collections.*, ZoneId/ZoneOffset
	jdkScript := `
		String cs = Character.toString(65);
		boolean cv = Character.isValidCodePoint(65) && Character.isBmpCodePoint(65) &&
			Character.isSupplementaryCodePoint(0x1F600) && Character.isHighSurrogate((char)0xD83D) &&
			Character.isLowSurrogate((char)0xDE00) && Character.isSurrogate((char)0xD83D) &&
			Character.isSurrogatePair((char)0xD83D, (char)0xDE00);
		int tcp = Character.toCodePoint((char)0xD83D, (char)0xDE00);
		int cpa = Character.codePointAt('AB', 1);
		boolean cmir = Character.isMirrored((char)40);
		int chc = Character.hashCode((char)65);
		String cn1 = Character.getName(65);
		String cn2 = Character.getName(97);
		String cn3 = Character.getName(32);
		String cn4 = Character.getName(0x1F600);
		int cConsts = Byte.BYTES + Character.MIN_RADIX + Character.MAX_RADIX + Character.MIN_CODE_POINT +
			(Character.MAX_CODE_POINT > 0 ? 1 : 0) + (Character.MIN_SUPPLEMENTARY_CODE_POINT > 0 ? 1 : 0) +
			(Character.MIN_HIGH_SURROGATE > 0 ? 1 : 0) + (Character.MAX_HIGH_SURROGATE > 0 ? 1 : 0) +
			(Character.MIN_LOW_SURROGATE > 0 ? 1 : 0) + (Character.MAX_LOW_SURROGATE > 0 ? 1 : 0) +
			(Character.MIN_SURROGATE > 0 ? 1 : 0) + (Character.MAX_VALUE > 0 ? 1 : 0) +
			Pattern.UNIX_LINES + Pattern.COMMENTS + Pattern.LITERAL;

		BitSet bs = new BitSet();
		bs.set(1, 6);
		bs.flip(2);
		bs.flip(3, 5);
		bs.clear(1);
		bs.clear(3, 5);
		bs.clear();
		boolean bsEq = (bs == new BitSet());

		byte[] ba0 = BigInteger.ZERO.toByteArray();
		byte[] baPos = new BigInteger('255').toByteArray();
		byte[] baNeg = new BigInteger('-129').toByteArray();

		boolean fin = Double.isFinite(1.5) && Float.isFinite(1.5f) && Double.isFinite(10) &&
			Objects.isNull(null) && Objects.nonNull('x') && (Objects.toString(null, 'fb') == 'fb');
		String hexDec = Encoding.decodeHex(Encoding.encodeHex('abc'));
		String b64Raw = Encoding.decodeBase64('YWJjZA');
		def c1 = Arrays.copyOf([1, 2, 3], 2);
		def c2 = Arrays.copyOfRange([1, 2, 3], 1, 3);

		OffsetTime ot = OffsetTime.parse('14:30:45.123456789+02:00');
		int otChecks = [
			ot.truncatedTo(ChronoUnit.DAYS).toString(),
			ot.truncatedTo(ChronoUnit.HALF_DAYS).toString(),
			ot.truncatedTo(ChronoUnit.HOURS).toString(),
			ot.truncatedTo(ChronoUnit.MINUTES).toString(),
			ot.truncatedTo(ChronoUnit.SECONDS).toString(),
			ot.truncatedTo(ChronoUnit.MILLIS).toString(),
			ot.truncatedTo(ChronoUnit.MICROS).toString(),
			ot.truncatedTo(ChronoUnit.NANOS).toString(),
			ot.atDate(LocalDate.of(2020, 5, 15)).toString()
		].size();
		long otEpoch = ot.toEpochSecond(LocalDate.of(2020, 5, 15));

		List dst = [0, 0, 0];
		Collections.copy(dst, [7, 8]);
		List addList = [1];
		Collections.addAll(addList, 2, 3);
		List unmodL = Collections.unmodifiableList([1, 2]);
		Map unmodM = Collections.unmodifiableMap(['a': 1]);
		List syncL = Collections.synchronizedList([1]);
		int zIds = ZoneId.getAvailableZoneIds().size();
		String zo1 = ZoneOffset.ofHoursMinutesSeconds(1, 2, 3).toString();
		String zo2 = ZoneOffset.ofTotalSeconds(3600).toString();
		String zi1 = ZoneId.ofOffset('UTC', ZoneOffset.UTC).toString();
		String zi2 = ZoneId.ofOffset('GMT', ZoneOffset.ofHours(2)).toString();

		return [cs, cv, tcp, cpa, cmir, chc, cn1, cn2, cn3, cn4.length() > 0, cConsts > 0, bsEq,
			ba0.length, baPos.length, baNeg.length, fin, hexDec, b64Raw, c1.length, c2.length,
			otChecks, otEpoch > 0, dst[0], addList.size(), unmodL.size(), unmodM.size(), syncL.size(), zIds > 0, zo1, zo2, zi1, zi2];
	`
	jdkRes, err := Eval(nil, jdkScript, nil)
	if err != nil {
		t.Fatalf("jdkScript failed: %v", err)
	}
	jArr, _ := jdkRes.([]any)
	if len(jArr) != 32 || jArr[0] != "A" || jArr[1] != true || jArr[11] != true || jArr[15] != true || jArr[16] != "abc" || jArr[17] != "abcd" {
		t.Fatalf("unexpected jdkScript results: %#v", jArr)
	}

	// 3. Internal helper branch coverage (lookupCtxMapKeyPainless, painlessClassForValuePainless,
	//    evalTemporalRangePainless, applyArithmetic, toFloat64, round60WrapperEquals)
	for _, k := range []string{"_index", "_id", "_routing", "_version", "op"} {
		_, _ = lookupCtxMapKeyPainless(k, map[string]any{}, map[string]any{})
		_, _ = lookupCtxMapKeyPainless(k, map[string]any{"_index": "i", "_id": "1", "_routing": "r", "_version": 2}, map[string]any{})
		_, _ = lookupCtxMapKeyPainless(k, map[string]any{"__reindex_index": "i", "__reindex_id": "1", "__reindex_version": 2}, map[string]any{})
		_, _ = lookupCtxMapKeyPainless(k, map[string]any{}, map[string]any{"_ctx_index": "i", "_ctx_id": "1", "_ctx_routing": "r", "_ctx_version": 2, "_ctx_op": "index"})
	}

	classSamples := []any{
		nil,
		painlessClassObject{fullName: "java.lang.String", simpleName: "String"},
		map[string]any{"__exc_type": "DateTimeParseException"},
		map[string]any{"__exc_type": "DateTimeException"},
		map[string]any{"__exc_type": "NoSuchElementException"},
		map[string]any{"__exc_type": "PatternSyntaxException"},
		map[string]any{"__exc_type": "URISyntaxException"},
		map[string]any{"__exc_type": "IllegalArgumentException"},
		map[string]any{"__exc_type": "org.example.CustomException"},
		&painlessOptional{kind: "OptionalInt"},
		&painlessOptional{},
		&painlessClock{},
		&painlessOffsetTime{},
		&painlessURI{},
		&painlessURL{},
		&painlessPredicate{},
		int16(1),
		int8(2),
		float32(1.5),
		json.Number("42"),
		json.Number("3.14"),
	}
	for _, cs := range classSamples {
		co := painlessClassForValuePainless(cs)
		if co.String() == "" {
			t.Fatalf("empty class string for %T", cs)
		}
	}

	_, _ = evalTemporalRangePainless(painlessMonthDay{month: 2, day: 1}, painlessChronoField("DAY_OF_MONTH"))
	_, _ = evalTemporalRangePainless(painlessMonthDay{month: 4, day: 1}, painlessChronoField("DAY_OF_MONTH"))
	_, _ = evalTemporalRangePainless("2020-02-15", painlessChronoField("DAY_OF_MONTH"))
	_, _ = evalTemporalRangePainless("2020-02-15", painlessChronoField("DAY_OF_YEAR"))
	_, _ = evalTemporalRangePainless("2021-02-15", painlessChronoField("DAY_OF_YEAR"))
	_, _ = evalTemporalRangePainless("2021-02-15", painlessChronoField("ALIGNED_WEEK_OF_MONTH"))
	_, _ = evalTemporalRangePainless("2020-05-15", painlessChronoField("ALIGNED_WEEK_OF_MONTH"))
	_, _ = evalTemporalRangePainless("2020-05-15", painlessChronoField("YEAR_OF_ERA"))
	_, _ = evalTemporalRangePainless(painlessYear{year: 2020}, painlessChronoField("DAY_OF_YEAR"))
	_, _ = evalTemporalRangePainless(painlessYear{year: 2021}, painlessChronoField("DAY_OF_YEAR"))
	_, _ = evalTemporalRangePainless(painlessYear{year: -1}, painlessChronoField("YEAR_OF_ERA"))
	_, _ = evalTemporalRangePainless(painlessYear{year: 2021}, painlessChronoField("YEAR_OF_ERA"))

	_ = applyArithmetic([]any{1}, []any{2}, true)
	_ = applyArithmetic([]any{1}, 2, true)
	_ = applyArithmetic(map[string]any{"a": 1}, map[string]any{"b": 2}, true)
	_ = applyArithmetic(true, false, true)
	_, _ = toFloat64(nil)
	_, _ = toFloat64((*painlessBigDecimal)(nil))
	_, _ = toFloat64((*painlessBigInteger)(nil))
	_, _ = toFloat64(int(3))
	_, _ = toFloat64(int32(4))

	dv1 := &DenseVectorVal{Floats: []float32{1, 2}}
	dv2 := &DenseVectorVal{Floats: []float32{1, 2}}
	_, _ = round60WrapperEquals(dv1, dv2)
	_, _ = round60WrapperEquals(dv1, []any{1.0, 2.0})
	_, _ = round60WrapperEquals(dv1, "nope")
	_, _ = round60WrapperEquals((*DenseVectorVal)(nil), nil)
	dow := DayOfWeekEnum{Value: 1}
	_, _ = round60WrapperEquals(dow, &dow)
	_, _ = round60WrapperEquals(&dow, "MONDAY")
}

func FuzzEvalPainless(f *testing.F) {
	seeds := []string{
		"return doc['date'].value.dayOfWeekEnum.value;",
		"return Float.toString(1.2f);",
		"return field('u').asBigInteger(BigInteger.ZERO).toString();",
		"field('a.b').set('v'); return field('a.b').get(null);",
		"return metadata().get('_routing');",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, script string) {
		doc := map[string]any{
			"date": "2020/05/15",
			"u":    uint64(18446744073709551615),
			"a":    map[string]any{"b": "init"},
		}
		params := map[string]any{
			"_ingest": map[string]any{"timestamp": "2020-05-15T00:00:00Z"},
		}
		_, _ = Eval(doc, script, params)
	})
}
