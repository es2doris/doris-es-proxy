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

package proxy

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound61PainlessProxy_TopologicalRuntimeMappingsAndCycleDetection(t *testing.T) {
	idxSchema := &schema.IndexSchema{
		IndexName: "rt_test",
		RawMapping: &esast.MappingSpec{
			Runtime: map[string]esast.FieldProperty{
				"rt_step1": {
					Type:   "long",
					Script: map[string]any{"source": "emit(doc['base'].value * 2)"},
				},
			},
			Properties: map[string]esast.FieldProperty{
				"base":      {Type: "long"},
				"date":      {Type: "date"},
				"geo_point": {Type: "geo_point"},
				"ip":        {Type: "ip"},
			},
		},
		Fields: map[string]schema.FieldBinding{
			"base":      {ESFieldPath: "base", ESType: "long"},
			"date":      {ESFieldPath: "date", ESType: "date"},
			"geo_point": {ESFieldPath: "geo_point", ESType: "geo_point"},
			"ip":        {ESFieldPath: "ip", ESType: "ip"},
		},
	}

	// Out-of-alphabetical-order search runtime_mappings: `a_step3` depends on `z_step2`, which depends on index `rt_step1`!
	reqMappings := map[string]esast.FieldProperty{
		"a_step3": {
			Type:   "long",
			Script: map[string]any{"source": "emit(doc['z_step2'].value + 7)"},
		},
		"z_step2": {
			Type:   "long",
			Script: map[string]any{"source": "emit(field('rt_step1').get(0) + 10)"},
		},
		"rt_dow": {
			Type:   "keyword",
			Script: map[string]any{"source": "for (date in field('date')) { emit(date.dayOfWeekEnum.getDisplayName(TextStyle.FULL, Locale.ENGLISH)); }"},
		},
		"rt_geo": {
			Type:   "geo_point",
			Script: map[string]any{"source": "def gp = doc['geo_point'].value; emit(gp.lat, gp.lon);"},
		},
		"rt_ip": {
			Type:   "ip",
			Script: map[string]any{"source": "emit(field('ip').asString(null))"},
		},
	}

	doc := map[string]any{
		"base":      int64(5),
		"date":      "2017-01-01T12:11:12Z",
		"geo_point": "41.12,-71.34",
		"ip":        "192.168.0.19",
	}
	evalDoc, modified, err := EvalRuntimeMappingsOnDocTopologicalRound61(idxSchema, reqMappings, doc, true)
	if err != nil || !modified {
		t.Fatalf("topological runtime evaluation failed: modified=%v err=%v", modified, err)
	}
	// base=5 -> rt_step1=10 -> z_step2=20 -> a_step3=27
	if doc["rt_step1"] != int64(10) || doc["z_step2"] != int64(20) || doc["a_step3"] != int64(27) {
		t.Fatalf("unexpected chained runtime values: rt_step1=%v z_step2=%v a_step3=%v", doc["rt_step1"], doc["z_step2"], doc["a_step3"])
	}
	if doc["rt_dow"] != "Sunday" || doc["rt_ip"] != "192.168.0.19" {
		t.Fatalf("unexpected rt_dow=%v rt_ip=%v", doc["rt_dow"], doc["rt_ip"])
	}
	geoMap, ok := doc["rt_geo"].(map[string]any)
	if !ok || math.Abs(geoMap["lat"].(float64)-41.1199999647215) > 1e-12 || math.Abs(geoMap["lon"].(float64)-(-71.34000004269183)) > 1e-12 {
		t.Fatalf("expected Lucene quantized runtime geo_point map, got %v", doc["rt_geo"])
	}
	// Downstream script_fields reading chained runtime field `doc['a_step3']` and `doc['rt_geo']`
	sfVal, err := painless.Eval(evalDoc, "doc['a_step3'].value + ':' + doc['rt_dow'].value + ':' + doc['rt_geo'].value.lat", nil)
	if err != nil || !strings.HasPrefix(sfVal.(string), "27:Sunday:41.1199999647215") {
		t.Fatalf("unexpected downstream script_fields output: %v (err=%v)", sfVal, err)
	}

	// Cycle detection: 3-node cycle A -> B -> C -> A
	cyclic := map[string]esast.FieldProperty{
		"f_a": {Type: "long", Script: map[string]any{"source": "emit(doc['f_c'].value + 1)"}},
		"f_b": {Type: "long", Script: map[string]any{"source": "emit(doc['f_a'].value + 1)"}},
		"f_c": {Type: "long", Script: map[string]any{"source": "emit(field('f_b').get(0) + 1)"}},
	}
	if _, err := TopoSortRuntimeMappingsRound61(cyclic); err == nil || !strings.Contains(err.Error(), "Cycle detected") {
		t.Fatalf("expected cycle detection error on 3-node cycle, got %v", err)
	}
	// Self-cycle X -> X
	selfCycle := map[string]esast.FieldProperty{
		"self_f": {Type: "long", Script: map[string]any{"source": "emit(doc['self_f'].value)"}},
	}
	if err := validateSearchRequestScriptsRound60(&esast.SearchRequest{RuntimeMappings: selfCycle}); err == nil || !strings.Contains(err.Error(), "Cycle detected") {
		t.Fatalf("expected validateSearchRequestScriptsRound60 to reject self-cycle, got %v", err)
	}
}

func TestRound61PainlessProxy_PrepareDocGuardsBooleanDupsFlattenedAndMeta(t *testing.T) {
	fFalse := false
	fTrue := true
	idxSchema := &schema.IndexSchema{
		IndexName:  "guard_idx",
		SourceMode: "disabled",
		RawMapping: &esast.MappingSpec{
			Dynamic: "strict",
			Source:  map[string]any{"enabled": false},
			Properties: map[string]esast.FieldProperty{
				"kw_nodv":        {Type: "keyword", DocValues: &fFalse},
				"kw_nodv_stored": {Type: "keyword", DocValues: &fFalse, Store: &fTrue},
				"txt_fd":         {Type: "text", Fielddata: true},
				"txt_nofd":       {Type: "text"},
				"mot":            {Type: "match_only_text"},
				"flag":           {Type: "boolean"},
				"flat":           {Type: "flattened"},
				"tc":             {Type: "token_count"},
				"hf":             {Type: "half_float"},
				"bvec":           {Type: "dense_vector", ElementType: "byte", Dims: 3},
			},
		},
		Fields: map[string]schema.FieldBinding{
			"kw_nodv":        {ESFieldPath: "kw_nodv", ESType: "keyword", DocValuesFalse: true},
			"kw_nodv_stored": {ESFieldPath: "kw_nodv_stored", ESType: "keyword", DocValuesFalse: true},
			"flag":           {ESFieldPath: "flag", ESType: "boolean"},
			"bvec":           {ESFieldPath: "bvec", ESType: "dense_vector", VectorDims: 3, VectorElementType: "byte"},
		},
	}

	rawDoc := map[string]any{
		"kw_nodv":        "hidden",
		"kw_nodv_stored": "stored_ok",
		"txt_fd":         "Quick Brown",
		"txt_nofd":       "No FD",
		"mot":            "Match Only",
		"flag":           []any{true, false, true},
		"flat":           map[string]any{"nested": map[string]any{"k": "v1"}},
		"tc":             "one two three",
		"hf":             3.141592654,
		"bvec":           "02fe09",
		"__meta_version": int64(50),
		"__meta_seq_no":  int64(7),
	}

	evalES8 := PrepareDocForRuntimeScriptRound61(idxSchema, rawDoc, true)
	if _, err := painless.Eval(evalES8, "doc['kw_nodv'].value", nil); err == nil {
		t.Fatalf("expected doc['kw_nodv'] to fail when doc_values:false")
	}
	if _, err := painless.Eval(evalES8, "field('kw_nodv').get('d')", nil); err == nil {
		t.Fatalf("expected field('kw_nodv') to fail when _source is disabled and store:false")
	}
	if v, err := painless.Eval(evalES8, "field('kw_nodv_stored').get('d')", nil); err != nil || v != "stored_ok" {
		t.Fatalf("expected store:true field('kw_nodv_stored') to succeed when _source disabled, got %v (err=%v)", v, err)
	}
	if _, err := painless.Eval(evalES8, "doc['txt_nofd'].value", nil); err == nil {
		t.Fatalf("expected doc['txt_nofd'] to fail when fielddata is disabled")
	}
	if _, err := painless.Eval(evalES8, "doc['mot'].value", nil); err == nil {
		t.Fatalf("expected doc['mot'] to fail on match_only_text")
	}
	if v, err := painless.Eval(evalES8, "doc['txt_fd'].value", nil); err != nil || v != "brown" {
		t.Fatalf("expected sorted analyzed token 'brown' for fielddata:true text, got %v (err=%v)", v, err)
	}
	if v, err := painless.Eval(evalES8, "doc['flag'].size()", nil); err != nil || v != int64(3) {
		t.Fatalf("expected ES 8 non-dedup boolean size 3, got %v (err=%v)", v, err)
	}
	evalES7 := PrepareDocForRuntimeScriptRound61(idxSchema, rawDoc, false)
	if v, err := painless.Eval(evalES7, "doc['flag'].size()", nil); err != nil || v != int64(2) {
		t.Fatalf("expected ES 7 dedup boolean size 2, got %v (err=%v)", v, err)
	}
	if v, err := painless.Eval(evalES8, "field('flat.nested.k').get('') + ':' + doc['tc'].value + ':' + field('_seq_no').get(0) + ':' + field('bvec').get(1)", nil); err != nil || v != "v1:3:7:-2.0" {
		t.Fatalf("unexpected combined evaluation: %v (err=%v)", v, err)
	}
}

func TestRound61PainlessProxy_ScriptFieldsAndScriptScoreErrorEnvelopesAndExplain(t *testing.T) {
	// 1. Compile error in script_fields ("while (true) {}") -> root_cause[0].type="script_exception", failed_shards[0].reason.caused_by.type="illegal_argument_exception"
	compErr := painless.CompileValidate("while (true) {}")
	status, payload := FormatScriptFieldsPhaseErrorRound61("test_idx", "bar", "while (true) {}", compErr)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 status, got %d", status)
	}
	errMap := payload["error"].(map[string]any)
	rc0 := errMap["root_cause"].([]map[string]any)[0]
	fs0 := errMap["failed_shards"].([]map[string]any)[0]["reason"].(map[string]any)
	cb := fs0["caused_by"].(map[string]any)
	if rc0["type"] != "script_exception" || rc0["reason"] != "compile error" || cb["type"] != "illegal_argument_exception" {
		t.Fatalf("unexpected script_fields compile error envelope: %v", payload)
	}

	// 2. Runtime UnsupportedOperationException in script_fields (Joda getCenturyOfEra)
	_, rtErr := painless.Eval(map[string]any{"d": "2017-01-01T12:11:12Z", "__field_types": map[string]string{"d": "date"}}, "$('d', null).getCenturyOfEra()", nil)
	_, rtPayload := FormatScriptFieldsPhaseErrorRound61("test_idx", "field", "$('d', null).getCenturyOfEra()", rtErr)
	rtCB := rtPayload["error"].(map[string]any)["failed_shards"].([]map[string]any)[0]["reason"].(map[string]any)["caused_by"].(map[string]any)
	if rtCB["type"] != "unsupported_operation_exception" || !strings.Contains(rtCB["reason"].(string), "[getCenturyOfEra] is no longer available") {
		t.Fatalf("unexpected runtime caused_by: %v", rtCB)
	}

	// 3. Negative score check (`30_search.yml:484`: "script score function must not produce negative scores, but got: [-9.0]")
	negErr := ValidateNonNegativeScriptScoreRound61(-9.0)
	if negErr == nil || !strings.Contains(negErr.Error(), "[-9.0]") {
		t.Fatalf("expected exact [-9.0] negative score error, got %v", negErr)
	}
	_, negPayload := FormatScriptScorePhaseErrorRound61("test_idx", "doc['num1'].value - 10.0", negErr)
	negRC := negPayload["error"].(map[string]any)["root_cause"].([]map[string]any)[0]
	if negRC["type"] != "illegal_argument_exception" || negRC["reason"] != "script score function must not produce negative scores, but got: [-9.0]" {
		t.Fatalf("unexpected negative score error envelope: %v", negPayload)
	}

	// 4. Vector runtime error in script_score preserves root_cause[0].type == "script_exception" + caused_by
	_, vecErr := painless.EvalScore(map[string]any{"__field_types": map[string]string{"v": "dense_vector"}}, "dotProduct(params.q, 'v')", map[string]any{"q": []any{1.0, 2.0}})
	_, vecPayload := FormatScriptScorePhaseErrorRound61("test_idx", "dotProduct(params.q, 'v')", vecErr)
	vecRC := vecPayload["error"].(map[string]any)["root_cause"].([]map[string]any)[0]
	vecShardCB := vecPayload["error"].(map[string]any)["failed_shards"].([]map[string]any)[0]["reason"].(map[string]any)["caused_by"].(map[string]any)
	if vecRC["type"] != "script_exception" || vecShardCB["type"] != "illegal_argument_exception" {
		t.Fatalf("unexpected vector script_score error envelope: %v", vecPayload)
	}

	// 5. BuildScriptScoreExplainNodeRound61
	expNode := BuildScriptScoreExplainNodeRound61(4.5, "_score * params.factor", map[string]any{"factor": 2.25}, map[string]any{"value": 2.0, "description": "sub"})
	if expNode["value"] != 4.5 || len(expNode["details"].([]map[string]any)) != 1 {
		t.Fatalf("unexpected script_score explain node: %v", expNode)
	}
}

func TestRound61PainlessProxy_ContextsAPIStoredScriptGuardAndUpdateFieldsAPI(t *testing.T) {
	ctxList := GetPainlessContextsPayloadRound61()["contexts"].([]string)
	if len(ctxList) == 0 || ctxList[0] != "aggregation_selector" {
		t.Fatalf("unexpected contexts list: %v", ctxList)
	}
	if st, detail := GetPainlessContextDetailPayloadRound61("score"); st != http.StatusOK || detail["name"] != "score" {
		t.Fatalf("expected 200 score context detail, got %d %v", st, detail)
	}
	if st, _ := GetPainlessContextDetailPayloadRound61("nonexistent_ctx"); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown Painless context, got %d", st)
	}
	if st, errObj, rejected := CheckStoredScriptRuntimeFieldContextRound61("long_field"); !rejected || st != http.StatusBadRequest || errObj["error"].(map[string]any)["caused_by"] == nil {
		t.Fatalf("expected runtime-field stored script context rejection with caused_by, got rejected=%v st=%d body=%v", rejected, st, errObj)
	}

	// EvalUpdateScriptWithFieldsAPIRound61 with JSON string shorthand ScriptSpec
	var spec painless.ScriptSpec
	if err := json.Unmarshal([]byte(`"field('profile.tier').set('gold'); field('legacy').remove();"`), &spec); err != nil {
		t.Fatalf("unmarshal shorthand failed: %v", err)
	}
	doc := map[string]any{"legacy": true}
	op, err := EvalUpdateScriptWithFieldsAPIRound61(doc, "id-1", "users", 2, "r1", true, true, spec, false, true)
	if err != nil || op != "index" {
		t.Fatalf("EvalUpdateScriptWithFieldsAPIRound61 failed: op=%q err=%v", op, err)
	}
	if _, hasLegacy := doc["legacy"]; hasLegacy || doc["profile"].(map[string]any)["tier"] != "gold" {
		t.Fatalf("unexpected updated doc: %v", doc)
	}
}
