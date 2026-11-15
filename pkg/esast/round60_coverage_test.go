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
	"encoding/json"
	"strings"
	"testing"
)

func TestRound60Coverage_FlexibleScalarIDsAndMGet(t *testing.T) {
	t.Parallel()

	// parseFlexibleScalarIDString & parseFlexibleScalarIDSlice
	if _, err := parseFlexibleScalarIDString(nil, "ctx"); err == nil {
		t.Fatal("expected error on nil scalar ID")
	}
	if _, err := parseFlexibleScalarIDString(map[string]any{"a": 1}, "ctx"); err == nil {
		t.Fatal("expected error on map scalar ID")
	}
	if s, err := parseFlexibleScalarIDString(json.Number("9223372036854775807"), "ctx"); err != nil || s != "9223372036854775807" {
		t.Fatalf("unexpected scalar ID: %q, err=%v", s, err)
	}

	if got, err := parseFlexibleScalarIDSlice(nil, "ids"); err != nil || got != nil {
		t.Fatalf("expected nil slice, got %v, err=%v", got, err)
	}
	strSlice := []string{"a", "b"}
	if got, err := parseFlexibleScalarIDSlice(strSlice, "ids"); err != nil || len(got) != 2 {
		t.Fatalf("expected string slice passthrough, got %v, err=%v", got, err)
	}
	mixed := []any{"doc-1", 42, int64(-7), 3.5, true, json.Number("100")}
	if got, err := parseFlexibleScalarIDSlice(mixed, "ids"); err != nil || len(got) != 6 || got[1] != "42" || got[4] != "true" {
		t.Fatalf("unexpected mixed ID slice: %v, err=%v", got, err)
	}
	if _, err := parseFlexibleScalarIDSlice([]any{"ok", []any{"nested"}}, "ids"); err == nil {
		t.Fatal("expected error for nested slice in IDs")
	}
	if _, err := parseFlexibleScalarIDSlice("not-an-array", "ids"); err == nil {
		t.Fatal("expected error for non-array IDs")
	}

	// MGetDocSpec.UnmarshalJSON
	var docEmpty MGetDocSpec
	if err := docEmpty.UnmarshalJSON([]byte("  null  ")); err != nil {
		t.Fatalf("unexpected null MGetDocSpec error: %v", err)
	}
	if err := docEmpty.UnmarshalJSON(nil); err != nil {
		t.Fatalf("unexpected empty MGetDocSpec error: %v", err)
	}
	if err := docEmpty.UnmarshalJSON([]byte(`"bad"`)); err == nil {
		t.Fatal("expected error for string MGetDocSpec")
	}

	var docAlt MGetDocSpec
	if err := json.Unmarshal([]byte(`{
		"index": "orders",
		"type": "_doc",
		"id": 12345,
		"_routing": 99,
		"_version": 3,
		"_version_type": "external"
	}`), &docAlt); err != nil {
		t.Fatalf("unexpected MGetDocSpec alt fields error: %v", err)
	}
	if docAlt.Index != "orders" || !docAlt.HasID || docAlt.ID != "12345" || docAlt.Routing != "99" || docAlt.Version == nil || *docAlt.Version != 3 || docAlt.VersionType != "external" {
		t.Fatalf("unexpected MGetDocSpec alt fields: %+v", docAlt)
	}

	var docCanon MGetDocSpec
	if err := json.Unmarshal([]byte(`{"_index":"idx","_type":"t","_id":"abc","routing":"r1","version":1,"version_type":"internal"}`), &docCanon); err != nil {
		t.Fatalf("unexpected canonical MGetDocSpec error: %v", err)
	}
	if docCanon.ID != "abc" || docCanon.Routing != "r1" {
		t.Fatalf("unexpected canonical MGetDocSpec: %+v", docCanon)
	}

	for _, bad := range []string{
		`{"_id": ["arr"]}`,
		`{"id": {"obj": 1}}`,
		`{"_id": "1", "routing": ["bad"]}`,
		`{"_id": "1", "_routing": {"bad": 1}}`,
		`{"_id": "1", "version": "not_int"}`,
	} {
		var d MGetDocSpec
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Fatalf("expected error for MGetDocSpec %s", bad)
		}
	}

	// MGetRequest.UnmarshalJSON
	var reqNull MGetRequest
	if err := reqNull.UnmarshalJSON([]byte("null")); err != nil {
		t.Fatalf("unexpected null MGetRequest error: %v", err)
	}
	var reqValid MGetRequest
	if err := json.Unmarshal([]byte(`{
		"ids": ["a", 2, true],
		"_routing": 77,
		"preference": "_local",
		"realtime": "false",
		"refresh": true
	}`), &reqValid); err != nil {
		t.Fatalf("unexpected MGetRequest error: %v", err)
	}
	if len(reqValid.IDs) != 3 || reqValid.Routing != "77" || reqValid.Realtime == nil || *reqValid.Realtime {
		t.Fatalf("unexpected MGetRequest: %+v", reqValid)
	}

	var reqRouting MGetRequest
	if err := json.Unmarshal([]byte(`{"ids":["1"],"routing":"shardA","realtime":true}`), &reqRouting); err != nil || reqRouting.Routing != "shardA" {
		t.Fatalf("unexpected MGetRequest routing: %+v, err=%v", reqRouting, err)
	}

	for _, bad := range []string{
		`"not_obj"`,
		`{"ids": "not_array"}`,
		`{"ids": [{"bad": 1}]}`,
		`{"routing": [1]}`,
		`{"_routing": {"bad": 1}}`,
		`{"realtime": "not_bool"}`,
	} {
		var r MGetRequest
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Fatalf("expected error for MGetRequest %s", bad)
		}
	}
}

func TestRound60Coverage_MLTBulkAndTemplates(t *testing.T) {
	t.Parallel()

	// MLTItem.UnmarshalJSON
	var mltText MLTItem
	if err := json.Unmarshal([]byte(`"quick brown fox"`), &mltText); err != nil || !mltText.IsText || mltText.Text != "quick brown fox" {
		t.Fatalf("unexpected MLTItem text: %+v, err=%v", mltText, err)
	}
	var mltDoc MLTItem
	if err := json.Unmarshal([]byte(`{
		"_index": "books",
		"_type": "_doc",
		"_id": "42",
		"_routing": "r2",
		"_source": {"title": "hello"},
		"fields": ["title"],
		"per_field_analyzer": {"title": "english"}
	}`), &mltDoc); err != nil {
		t.Fatalf("unexpected MLTItem doc error: %v", err)
	}
	if mltDoc.Routing != "r2" || mltDoc.Doc["title"] != "hello" || mltDoc.PerFieldAnalyzer["title"] != "english" {
		t.Fatalf("unexpected MLTItem doc: %+v", mltDoc)
	}
	var mltDoc2 MLTItem
	if err := json.Unmarshal([]byte(`{"doc":{"title":"world"},"routing":"r1"}`), &mltDoc2); err != nil || mltDoc2.Routing != "r1" {
		t.Fatalf("unexpected MLTItem doc2: %+v, err=%v", mltDoc2, err)
	}
	for _, bad := range []string{
		`null`,
		`""`,
		`"   "`,
		`123`,
		`{"unknown_mlt_key": 1}`,
		`{"doc": {"a": 1}, "fields": 123}`,
	} {
		var item MLTItem
		if err := json.Unmarshal([]byte(bad), &item); err == nil {
			t.Fatalf("expected MLTItem error on %s", bad)
		}
	}
	var badQuote MLTItem
	if err := badQuote.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Fatal("expected error on invalid JSON string MLTItem")
	}
	if err := badQuote.UnmarshalJSON([]byte(`{bad_json`)); err == nil {
		t.Fatal("expected error on invalid JSON object MLTItem")
	}

	// BulkActionMeta / unmarshalBulkActionMeta
	var bam BulkActionMeta
	if err := unmarshalBulkActionMeta(&bam, []byte("null")); err != nil {
		t.Fatalf("unexpected null bulk meta error: %v", err)
	}
	if err := unmarshalBulkActionMeta(&bam, []byte(`{
		"index": "logs",
		"id": 555,
		"_op_type": "create",
		"pipeline": "ingest-1",
		"routing": 10,
		"_routing": 20,
		"_if_seq_no": 1,
		"_if_primary_term": 2,
		"_version": 3,
		"_version_type": "external",
		"_retry_on_conflict": 4,
		"require_alias": true,
		"doc_as_upsert": true,
		"detect_noop": false,
		"_source": true,
		"_source_includes": ["a"],
		"_source_excludes": ["b"]
	}`)); err != nil {
		t.Fatalf("unexpected bulk meta alt error: %v", err)
	}
	if bam.Index != "logs" || !bam.HasID || bam.ID != "555" || bam.OpType != "create" || bam.Routing != "10" || bam.UnderscoreRouting != "20" {
		t.Fatalf("unexpected bulk meta alt result: %+v", bam)
	}

	var bamNullID BulkActionMeta
	if err := unmarshalBulkActionMeta(&bamNullID, []byte(`{"_index":"logs","_id":null}`)); err != nil || bamNullID.HasID {
		t.Fatalf("expected HasID=false on explicit null _id, got %+v, err=%v", bamNullID, err)
	}
	if err := unmarshalBulkActionMeta(&bamNullID, []byte(`{"_index":"logs","id":null}`)); err != nil || bamNullID.HasID {
		t.Fatalf("expected HasID=false on explicit null id, got %+v, err=%v", bamNullID, err)
	}

	for _, bad := range []string{
		`"not_obj"`,
		`{"_id": ""}`,
		`{"id": ""}`,
		`{"_id": ["arr"]}`,
		`{"id": {"obj": 1}}`,
		`{"routing": ["bad"]}`,
		`{"_routing": ["bad"]}`,
		`{"if_seq_no": "not_int"}`,
	} {
		var m BulkActionMeta
		if err := unmarshalBulkActionMeta(&m, []byte(bad)); err == nil {
			t.Fatalf("expected bulk meta error on %s", bad)
		}
	}

	// parseStringOrStringArray & unmarshalIndexTemplateRequest
	if got, err := parseStringOrStringArray(nil, "f"); err != nil || got != nil {
		t.Fatalf("expected nil from empty raw, got %v, err=%v", got, err)
	}
	if got, err := parseStringOrStringArray(json.RawMessage(`"logs-*"`), "f"); err != nil || len(got) != 1 || got[0] != "logs-*" {
		t.Fatalf("unexpected single string result: %v, err=%v", got, err)
	}
	if _, err := parseStringOrStringArray(json.RawMessage(`123`), "f"); err == nil {
		t.Fatal("expected error on numeric index_patterns")
	}
	if _, err := parseStringOrStringArray(json.RawMessage(`[123]`), "f"); err == nil {
		t.Fatal("expected error on numeric array element in index_patterns")
	}
	if _, err := parseStringOrStringArray(json.RawMessage(`"unterminated`), "f"); err == nil {
		t.Fatal("expected error on bad string JSON")
	}

	var tmplLegacy IndexTemplateRequest
	if err := unmarshalIndexTemplateRequest(&tmplLegacy, []byte("null")); err != nil {
		t.Fatalf("unexpected null template error: %v", err)
	}
	if err := json.Unmarshal([]byte(`{
		"template": "metrics-*",
		"patterns": "metrics-raw-*",
		"order": 5,
		"version": 2,
		"settings": {"number_of_shards": 1},
		"aliases": {"m_all": {}}
	}`), &tmplLegacy); err != nil {
		t.Fatalf("unexpected legacy template error: %v", err)
	}
	if !tmplLegacy.Legacy || len(tmplLegacy.IndexPatterns) != 1 || tmplLegacy.IndexPatterns[0] != "metrics-*" {
		t.Fatalf("unexpected legacy template: %+v", tmplLegacy)
	}

	var tmplComposable IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{
		"index_patterns": ["logs-*", "events-*"],
		"priority": 100,
		"composed_of": ["comp-a"],
		"template": {"settings": {"number_of_replicas": 0}},
		"_meta": {"owner": "platform"},
		"data_stream": {"hidden": false},
		"allow_auto_create": true
	}`), &tmplComposable); err != nil {
		t.Fatalf("unexpected composable template error: %v", err)
	}
	if tmplComposable.Legacy || tmplComposable.Template == nil || len(tmplComposable.IndexPatterns) != 2 {
		t.Fatalf("unexpected composable template: %+v", tmplComposable)
	}

	for _, bad := range []string{
		`{bad`,
		`{"index_patterns": 123}`,
		`{"patterns": 123}`,
		`{"template": 123}`,
	} {
		var tr IndexTemplateRequest
		if err := unmarshalIndexTemplateRequest(&tr, []byte(bad)); err == nil {
			t.Fatalf("expected template error on %s", bad)
		}
	}
}

func TestRound60Coverage_ScriptsCompletionAndFieldMeta(t *testing.T) {
	t.Parallel()

	// ScriptSpec.UnmarshalJSON & ParseScriptSpec
	var ss ScriptSpec
	if err := ss.UnmarshalJSON([]byte("null")); err != nil {
		t.Fatalf("unexpected null ScriptSpec error: %v", err)
	}
	if err := json.Unmarshal([]byte(`"doc['x'].value + 1"`), &ss); err != nil || ss.Source != "doc['x'].value + 1" || ss.Lang != "painless" {
		t.Fatalf("unexpected shorthand ScriptSpec: %+v, err=%v", ss, err)
	}
	if err := json.Unmarshal([]byte(`{
		"inline": "params.a * 2",
		"lang": "expression",
		"params": {"a": 3},
		"options": {"content_type": "application/json", "max_Compilations": 10}
	}`), &ss); err != nil {
		t.Fatalf("unexpected inline ScriptSpec error: %v", err)
	}
	if ss.Source != "params.a * 2" || ss.Lang != "expression" || ss.Options["max_Compilations"] != "10" {
		t.Fatalf("unexpected inline ScriptSpec: %+v", ss)
	}
	var ssStored ScriptSpec
	if err := json.Unmarshal([]byte(`{"id": "my-stored-script"}`), &ssStored); err != nil || ssStored.ID != "my-stored-script" || ssStored.Lang != "painless" {
		t.Fatalf("unexpected stored ScriptSpec: %+v, err=%v", ssStored, err)
	}

	for _, bad := range []string{
		`""`,
		`"   "`,
		`123`,
		`{}`,
		`{"unknown_key": "x"}`,
	} {
		var badSS ScriptSpec
		if err := json.Unmarshal([]byte(bad), &badSS); err == nil {
			t.Fatalf("expected ScriptSpec error on %s", bad)
		}
	}
	if err := ss.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Fatal("expected error on malformed string ScriptSpec")
	}
	if err := ss.UnmarshalJSON([]byte(`{malformed`)); err == nil {
		t.Fatal("expected error on malformed object ScriptSpec")
	}

	if got, err := ParseScriptSpec(nil); err != nil || got != nil {
		t.Fatalf("expected nil from ParseScriptSpec(nil), got %v, err=%v", got, err)
	}
	ptrSpec := &ScriptSpec{Source: "1", Lang: "painless"}
	if got, err := ParseScriptSpec(ptrSpec); err != nil || got != ptrSpec {
		t.Fatalf("expected pointer passthrough, got %v, err=%v", got, err)
	}
	if got, err := ParseScriptSpec(*ptrSpec); err != nil || got == nil || got.Source != "1" {
		t.Fatalf("expected value copy, got %v, err=%v", got, err)
	}
	if got, err := ParseScriptSpec("ctx._source.x = 1"); err != nil || got.Source != "ctx._source.x = 1" {
		t.Fatalf("expected string ParseScriptSpec, got %v, err=%v", got, err)
	}
	if _, err := ParseScriptSpec("   "); err == nil {
		t.Fatal("expected error on blank string ParseScriptSpec")
	}
	if got, err := ParseScriptSpec(map[string]any{"source": "doc['a'].value", "params": map[string]any{"k": 1}}); err != nil || got.Source != "doc['a'].value" {
		t.Fatalf("expected map ParseScriptSpec, got %v, err=%v", got, err)
	}
	if _, err := ParseScriptSpec(map[string]any{}); err == nil {
		t.Fatal("expected error on empty map ParseScriptSpec")
	}
	if _, err := ParseScriptSpec(func() {}); err == nil {
		t.Fatal("expected marshal error on func ParseScriptSpec")
	}

	// HDRConfig
	var nilHDR *HDRConfig
	if nilHDR.EffectiveSignificantDigits() != 3 {
		t.Fatal("expected default 3 for nil HDRConfig")
	}
	emptyHDR := &HDRConfig{}
	if emptyHDR.EffectiveSignificantDigits() != 3 {
		t.Fatal("expected default 3 for unset NumberOfSignificantValueDigits")
	}
	d4 := 4
	setHDR := &HDRConfig{NumberOfSignificantValueDigits: &d4}
	if setHDR.EffectiveSignificantDigits() != 4 {
		t.Fatal("expected 4 for configured HDRConfig")
	}

	// MatchBoolPrefixSpec
	var mbp MatchBoolPrefixSpec
	if err := json.Unmarshal([]byte(`"quick brown f"`), &mbp); err != nil || mbp.Query != "quick brown f" {
		t.Fatalf("unexpected MatchBoolPrefixSpec string: %+v, err=%v", mbp, err)
	}
	if err := json.Unmarshal([]byte(`{"query":"quick f","analyzer":"standard","operator":"and","minimum_should_match":1,"fuzziness":"AUTO","prefix_length":1,"max_expansions":10,"fuzzy_transpositions":true,"fuzzy_rewrite":"constant_score","lenient":true,"boost":1.5,"_name":"q1"}`), &mbp); err != nil {
		t.Fatalf("unexpected MatchBoolPrefixSpec object error: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"query":"quick","slop":2}`), &mbp); err == nil {
		t.Fatal("expected MatchBoolPrefixSpec to reject slop")
	}
	if err := validateMatchBoolPrefixRaw([]byte("null")); err != nil {
		t.Fatalf("unexpected null validateMatchBoolPrefixRaw: %v", err)
	}
	if err := validateMatchBoolPrefixRaw([]byte(`123`)); err == nil {
		t.Fatal("expected non-object error in validateMatchBoolPrefixRaw")
	}
	if err := validateMatchBoolPrefixRaw([]byte(`{"_name":"n","boost":2.0,"title":{"query":"hi"}}`)); err != nil {
		t.Fatalf("unexpected valid validateMatchBoolPrefixRaw error: %v", err)
	}
	if err := validateMatchBoolPrefixFieldClause([]byte(`{bad`)); err == nil {
		t.Fatal("expected malformed JSON error in validateMatchBoolPrefixFieldClause")
	}

	// CompletionContextDef & CompletionQueryContext & CompletionSuggester
	var ccd CompletionContextDef
	if err := ccd.UnmarshalJSON([]byte("null")); err != nil {
		t.Fatalf("unexpected null CompletionContextDef error: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"name":"loc","type":"GEO","path":"pin","precision":"5km","default":{"lat":1,"lon":2}}`), &ccd); err != nil || ccd.Type != "geo" {
		t.Fatalf("unexpected CompletionContextDef: %+v, err=%v", ccd, err)
	}
	for _, bad := range []string{
		`"str"`,
		`{"name":"c","type":"category","extra":1}`,
		`{"name":"  ","type":"category"}`,
		`{"name":"c","type":"unknown"}`,
	} {
		var badCCD CompletionContextDef
		if err := json.Unmarshal([]byte(bad), &badCCD); err == nil {
			t.Fatalf("expected CompletionContextDef error on %s", bad)
		}
	}

	var cqc CompletionQueryContext
	if err := json.Unmarshal([]byte(`"movies"`), &cqc); err != nil || cqc.Context != "movies" || cqc.Boost != 1.0 {
		t.Fatalf("unexpected scalar CompletionQueryContext: %+v, err=%v", cqc, err)
	}
	if err := json.Unmarshal([]byte(`{"lat": 43.66, "lon": -79.38}`), &cqc); err != nil || cqc.Boost != 1.0 {
		t.Fatalf("unexpected geo shorthand CompletionQueryContext: %+v, err=%v", cqc, err)
	}
	if err := json.Unmarshal([]byte(`{"context":"star","boost":2.5,"prefix":"true","precision":4,"neighbors":["5km"]}`), &cqc); err != nil || !cqc.Prefix || len(cqc.Neighbours) != 1 {
		t.Fatalf("unexpected full CompletionQueryContext: %+v, err=%v", cqc, err)
	}
	for _, bad := range []string{
		`null`,
		`{"boost": 2}`,
		`{"context": "a", "unknown": 1}`,
		`{"context": null}`,
		`{"context": "a", "boost": -1}`,
		`{"context": "a", "prefix": "not_bool"}`,
	} {
		var badCQC CompletionQueryContext
		if err := json.Unmarshal([]byte(bad), &badCQC); err == nil {
			t.Fatalf("expected CompletionQueryContext error on %s", bad)
		}
	}

	if m, err := parseCompletionQueryContextsMap([]byte("null")); err != nil || m != nil {
		t.Fatalf("expected nil contexts map, got %v, err=%v", m, err)
	}
	if _, err := parseCompletionQueryContextsMap([]byte(`123`)); err == nil {
		t.Fatal("expected error on non-object contexts map")
	}
	if _, err := parseCompletionQueryContextsMap([]byte(`{"cat": null}`)); err == nil {
		t.Fatal("expected error on null context entry")
	}
	if _, err := parseCompletionQueryContextsMap([]byte(`{"cat": [null]}`)); err == nil {
		t.Fatal("expected error on invalid context array element")
	}
	if _, err := parseCompletionQueryContextsMap([]byte(`{"cat": {"bad": 1}}`)); err == nil {
		t.Fatal("expected error on invalid single context object")
	}
	if m, err := parseCompletionQueryContextsMap([]byte(`{"cat": "books", "loc": [{"lat":1,"lon":2}]}`)); err != nil || len(m) != 2 {
		t.Fatalf("unexpected valid contexts map: %v, err=%v", m, err)
	}

	var cs CompletionSuggester
	if err := json.Unmarshal([]byte(`{
		"field": "suggest",
		"size": 5,
		"skip_duplicates": true,
		"contexts": {"cat": ["tech"]}
	}`), &cs); err != nil || cs.Field != "suggest" || cs.SkipDuplicates == nil || !*cs.SkipDuplicates {
		t.Fatalf("unexpected CompletionSuggester: %+v, err=%v", cs, err)
	}
	if err := json.Unmarshal([]byte(`123`), &cs); err == nil {
		t.Fatal("expected error on invalid CompletionSuggester")
	}

	// Field meta & FieldProperty round60 unmarshaling
	if m, err := ValidateAndNormalizeFieldMeta([]byte("null")); err != nil || m != nil {
		t.Fatalf("expected nil meta on null, got %v, err=%v", m, err)
	}
	if _, err := ValidateAndNormalizeFieldMeta([]byte(`"bad"`)); err == nil {
		t.Fatal("expected error on non-object meta")
	}
	if _, err := ValidateAndNormalizeFieldMeta([]byte(`{bad`)); err == nil {
		t.Fatal("expected error on malformed JSON meta")
	}
	if m, err := ValidateFieldMetaMap(nil); err != nil || m != nil {
		t.Fatalf("expected nil on empty meta map, got %v, err=%v", m, err)
	}
	if _, err := ValidateFieldMetaMap(map[string]any{"k1": "1", "k2": "2", "k3": "3", "k4": "4", "k5": "5", "k6": "6"}); err == nil {
		t.Fatal("expected error on >5 meta entries")
	}
	if _, err := ValidateFieldMetaMap(map[string]any{strings.Repeat("k", 21): "v"}); err == nil {
		t.Fatal("expected error on >20 char meta key")
	}
	if _, err := ValidateFieldMetaMap(map[string]any{"k": nil}); err == nil {
		t.Fatal("expected error on null meta value")
	}
	if _, err := ValidateFieldMetaMap(map[string]any{"k": strings.Repeat("v", 51)}); err == nil {
		t.Fatal("expected error on >50 char meta value")
	}
	if m, err := ValidateFieldMetaMap(map[string]any{"unit": "ms", "ver": 2}); err != nil || m["ver"] != "2" {
		t.Fatalf("unexpected valid meta map: %v, err=%v", m, err)
	}

	if err := ValidateFieldMetaStringMap(nil); err != nil {
		t.Fatalf("unexpected error on empty string meta map: %v", err)
	}
	if err := ValidateFieldMetaStringMap(map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"}); err == nil {
		t.Fatal("expected error on >5 string meta entries")
	}
	if err := ValidateFieldMetaStringMap(map[string]string{"": "1"}); err == nil {
		t.Fatal("expected error on empty string meta key")
	}
	if err := ValidateFieldMetaStringMap(map[string]string{"k": strings.Repeat("x", 51)}); err == nil {
		t.Fatal("expected error on >50 char string meta value")
	}
	if err := ValidateFieldMetaStringMap(map[string]string{"unit": "bytes"}); err != nil {
		t.Fatalf("unexpected valid string meta error: %v", err)
	}

	var fpNull FieldProperty
	if err := unmarshalFieldPropertyRound60(&fpNull, []byte("null")); err != nil {
		t.Fatalf("unexpected null FieldProperty error: %v", err)
	}
	// Single context object shorthand on FieldProperty
	fpSingleCtx, err := UnmarshalFieldPropertyStrict([]byte(`{
		"type": "completion",
		"meta": {"unit": "tag"},
		"contexts": {"name": "cat", "type": "category"}
	}`))
	if err != nil || len(fpSingleCtx.Contexts) != 1 || fpSingleCtx.Meta["unit"] != "tag" {
		t.Fatalf("unexpected fpSingleCtx: %+v, err=%v", fpSingleCtx, err)
	}
	if _, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"keyword","unknown_param":true}`)); err == nil {
		t.Fatal("expected strict FieldProperty to reject unknown_param")
	}
	if _, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"completion","contexts":{"name":"","type":"category"}}`)); err == nil {
		t.Fatal("expected strict FieldProperty to reject invalid single context")
	}
	if _, err := UnmarshalFieldPropertyStrict([]byte(`{"type":"completion","contexts":[{"name":"","type":"category"}]}`)); err == nil {
		t.Fatal("expected strict FieldProperty to reject invalid context array")
	}
}

func TestRound60Coverage_ASTBoostGeoRetrieverAndSort(t *testing.T) {
	t.Parallel()

	// Query-level boost propagation across all map-based leaf queries
	boostQueries := []string{
		`{"range": {"age": {"gte": 10}, "boost": 2.0}}`,
		`{"terms_set": {"tags": {"terms": ["a", "b"], "minimum_should_match_script": {"source": "1"}}, "boost": 1.5}}`,
		`{"term": {"status": "ok", "boost": 2.5}}`,
		`{"span_term": {"title": "quick", "boost": 1.2}}`,
		`{"intervals": {"title": {"match": {"query": "quick fox"}}, "boost": 3.0}}`,
		`{"prefix": {"title": "qu", "boost": 1.3}}`,
		`{"wildcard": {"title": "qu*", "boost": 1.4}}`,
		`{"regexp": {"title": "qu.*", "boost": 1.6}}`,
		`{"fuzzy": {"title": "quik", "boost": 1.7}}`,
		`{"match": {"title": "quick", "boost": 1.8}}`,
		`{"match_phrase": {"title": "quick fox", "boost": 1.9}}`,
		`{"match_phrase_prefix": {"title": "quick f", "boost": 2.1}}`,
		`{"match_bool_prefix": {"title": "quick f", "boost": 2.2}}`,
		`{"common": {"title": {"query": "the quick"}, "boost": 2.3}}`,
	}
	for _, qStr := range boostQueries {
		var q Query
		if err := json.Unmarshal([]byte(qStr), &q); err != nil {
			t.Fatalf("unexpected error unmarshaling boosted query %s: %v", qStr, err)
		}
	}

	// ParseWKTGeoShape across all geometry types and error cases
	validWKTs := []string{
		`POINT (-77.03653 38.897676)`,
		`BBOX (-74.1, -71.12, 40.73, 40.01)`,
		`ENVELOPE (-10, 10, 20, -20)`,
		`LINESTRING (-77.03653 38.897676, -77.009051 38.889939)`,
		`MULTIPOINT (10 40, 40 30, 20 20)`,
		`POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0), (2 2, 8 2, 8 8, 2 2))`,
		`MULTIPOLYGON (((0 0, 5 0, 5 5, 0 0)), ((10 10, 20 10, 20 20, 10 10)))`,
		`GEOMETRYCOLLECTION (POINT (1 2), LINESTRING (0 0, 1 1))`,
	}
	for _, wkt := range validWKTs {
		if m, err := ParseWKTGeoShape(wkt); err != nil || m == nil {
			t.Fatalf("expected valid WKT %q, got %v, err=%v", wkt, m, err)
		}
	}
	invalidWKTs := []string{
		`POINT`,
		`POINT (1)`,
		`POINT (abc def)`,
		`BBOX (1, 2, 3)`,
		`BBOX (a, b, c, d)`,
		`BBOX (-200, 10, 20, -20)`,
		`BBOX (-10, 10, -20, 20)`,
		`LINESTRING (0 0)`,
		`POLYGON (0 0, 1 1, 2 2)`,
		`POLYGON ((0 0, 1 1))`,
		`MULTIPOLYGON (0 0, 1 1, 2 2)`,
		`MULTIPOLYGON ((0 0, 1 1, 2 2))`,
		`MULTIPOLYGON (((0 0, 1 1)))`,
		`GEOMETRYCOLLECTION (INVALID (1 2))`,
		`TRIANGLE ((0 0, 1 1, 0 1))`,
	}
	for _, wkt := range invalidWKTs {
		if _, err := ParseWKTGeoShape(wkt); err == nil {
			t.Fatalf("expected error on invalid WKT %q", wkt)
		}
	}

	// ParseGeoPoint comprehensive inputs
	validGeoPoints := []any{
		json.RawMessage(`{"lat": 40.7, "lon": -74.0}`),
		[]byte(`[-74.0, 40.7]`),
		map[string]any{"type": "Point", "coordinates": []any{-74.0, 40.7}},
		map[string]any{"lat": 40.7, "lng": -74.0},
		[]any{-74.0, 40.7, 10.0},
		[]float64{-74.0, 40.7},
		"POINT (-74.0 40.7)",
		"40.7, -74.0",
		"dr5regw3pg6f",
	}
	for _, gp := range validGeoPoints {
		if _, _, err := ParseGeoPoint(gp); err != nil {
			t.Fatalf("expected valid geo_point %v, got err=%v", gp, err)
		}
	}
	invalidGeoPoints := []any{
		nil,
		json.RawMessage(`{bad`),
		[]byte(`{bad`),
		map[string]any{"type": "Polygon", "coordinates": []any{}},
		map[string]any{"type": "Point"},
		map[string]any{"lat": 40.7},
		map[string]any{"lat": 40.7, "lon": -74.0, "extra": 1},
		[]any{-74.0},
		[]float64{-74.0},
		"",
		"POINT -74 40",
		"POINT (1)",
		"POINT (a b)",
		"40.7, -74.0, 1, 2",
		"abc, def",
		12345,
	}
	for _, gp := range invalidGeoPoints {
		if _, _, err := ParseGeoPoint(gp); err == nil {
			t.Fatalf("expected error on invalid geo_point %v", gp)
		}
	}

	// SearchRequest with RRF/TextSimilarityReranker multiple filters & indices_boost
	var sr SearchRequest
	if err := json.Unmarshal([]byte(`{
		"indices_boost": [{"idx1": 1.5}, {"idx2": 0.5}],
		"retriever": {
			"rrf": {
				"retrievers": [
					{"standard": {"query": {"match_all": {}}, "filter": [{"term": {"a": "1"}}, {"term": {"b": "2"}}]}},
					{"rule": {"ruleset_ids": ["rs-1"], "retriever": {"text_similarity_reranker": {
						"retriever": {"standard": {}},
						"inference_id": "rerank-1",
						"inference_text": "hello",
						"field": "body",
						"min_score": 0.5,
						"filter": [{"term": {"c": "3"}}, {"term": {"d": "4"}}]
					}}}}
				],
				"filter": [{"term": {"x": "1"}}, {"term": {"y": "2"}}],
				"rank_window_size": 50,
				"rank_constant": 20
			}
		}
	}`), &sr); err != nil {
		t.Fatalf("unexpected retriever SearchRequest error: %v", err)
	}

	for _, badIB := range []string{
		`123`,
		`[123]`,
		`[{}]`,
		`[{"": 1.0}]`,
		`[{"idx": -1.0}]`,
	} {
		if _, err := parseIndicesBoost(json.RawMessage(badIB)); err == nil {
			t.Fatalf("expected indices_boost error on %s", badIB)
		}
	}

	// SortSpec: _script and _geo_distance with top-level & nested options
	validSorts := []string{
		`"_score"`,
		`"price"`,
		`{"_script": {"script": "doc['a'].value", "type": "number", "order": "desc", "mode": "max", "missing": "_last", "nested": {"path": "items"}}}`,
		`{"_script": {"script": "doc['s'].value"}, "type": "string", "order": "asc", "mode": "min", "missing": "zzz", "nested_path": "items", "nested_filter": {"term": {"items.k": "v"}}}`,
		`{"_geo_distance": {"pin": [{"lat": 40, "lon": -70}, {"lat": 41, "lon": -71}], "unit": "km"}, "order": "asc", "mode": "avg", "missing": "_last", "nested_path": "locs"}`,
	}
	for _, sJSON := range validSorts {
		var sp SortSpec
		if err := json.Unmarshal([]byte(sJSON), &sp); err != nil {
			t.Fatalf("unexpected SortSpec error on %s: %v", sJSON, err)
		}
	}
	invalidSorts := []string{
		`null`,
		`""`,
		`123`,
		`{}`,
		`{"_script": {"script": "1", "type": "number"}, "unknown_outer": 1}`,
		`{"_script": {"script": "1", "type": "number", "unknown_inner": 1}}`,
		`{"_script": {"script": "1", "type": "boolean"}}`,
		`{"_script": "not_obj"}`,
	}
	for _, sJSON := range invalidSorts {
		var sp SortSpec
		if err := json.Unmarshal([]byte(sJSON), &sp); err == nil {
			t.Fatalf("expected SortSpec error on %s", sJSON)
		}
	}

	// validateSingleOrMultiBucketsPath
	for _, okBP := range []any{
		"the_sum",
		map[string]any{"x": "the_sum"},
		[]any{"the_sum", "the_avg"},
	} {
		if err := validateSingleOrMultiBucketsPath(okBP, "bucket_script"); err != nil {
			t.Fatalf("unexpected buckets_path error on %v: %v", okBP, err)
		}
	}
	for _, badBP := range []any{
		nil,
		"  ",
		map[string]any{},
		map[string]any{"": "the_sum"},
		map[string]any{"x": 123},
		[]any{},
		[]any{""},
		[]any{123},
		42,
	} {
		if err := validateSingleOrMultiBucketsPath(badBP, "bucket_script"); err == nil {
			t.Fatalf("expected buckets_path error on %v", badBP)
		}
	}
}
