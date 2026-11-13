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
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound59_MemBackendAndSQLBackendRewrites(t *testing.T) {
	ctx := context.Background()

	// Verify ApplyDSNAuth sets UTC time_zone while preserving prefix for existing DSN tests.
	dsn := ApplyDSNAuth("root@tcp(fe:9030)/es_db", "doris_ro", "s3cr3t")
	if !strings.HasPrefix(dsn, "doris_ro:s3cr3t@tcp(fe:9030)/es_db") || !strings.Contains(dsn, "time_zone=") {
		t.Fatalf("unexpected ApplyDSNAuth output: %s", dsn)
	}
	// Verify NormalizeDorisSQL wraps ARRAY<LARGEINT> in IFNULL(..., CAST([] AS ARRAY<LARGEINT>)).
	normArr := NormalizeDorisSQL("SELECT * FROM `es_db`.`t` WHERE array_exists(_x -> CAST(_x AS LARGEINT) >= 10, CAST(`arr__ul` AS ARRAY<LARGEINT>))")
	if !strings.Contains(normArr, "CAST([] AS ARRAY<LARGEINT>)") {
		t.Fatalf("expected ARRAY<LARGEINT> empty array fallback in NormalizeDorisSQL, got: %s", normArr)
	}
	rewrittenHits, ok := injectRawDocSelectIntoHitsSQL("SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_db`.`t` WHERE 1=1")
	if !ok || !strings.Contains(rewrittenHits, "CAST(`_doc` AS STRING) AS `_raw_doc`") {
		t.Fatalf("unexpected injectRawDocSelectIntoHitsSQL result: ok=%v sql=%s", ok, rewrittenHits)
	}

	// Build schema exercising F10 (unsigned_long), F11 (_source disabled), F13 (constant_keyword), F14 (bit vector), F15 (version), F16 (regexp), F19 (calendar DST date_histogram)
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"enabled": false},
		"properties": {
			"ul": {"type": "unsigned_long"},
			"uls": {"type": "unsigned_long"},
			"env": {"type": "constant_keyword", "value": "prod"},
			"bit_vec": {"type": "dense_vector", "dims": 8, "element_type": "bit"},
			"ver": {"type": "version"},
			"tags": {"type": "keyword"},
			"ts": {"type": "date"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	ulsProp := spec.Properties["uls"]
	ulsProp.MultiValued = true
	spec.Properties["uls"] = ulsProp
	tagsProp := spec.Properties["tags"]
	tagsProp.MultiValued = true
	spec.Properties["tags"] = tagsProp
	idxSchema := schema.CompileIndexSchema("es_db", "r59_mem", &spec)

	mem := NewMemoryBackend(false)
	docs := []struct {
		id   string
		body string
	}{
		{"1", `{"ul":18446744073709551615,"uls":[18446744073709551615,42],"env":"prod","bit_vec":"f0","ver":"1.0.0-alpha","tags":["item12","abc"],"ts":"2026-03-08T04:30:00Z"}`},
		{"2", `{"ul":18446744073709551614,"uls":[9223372036854775808],"bit_vec":"f8","ver":"1.0.0-2","tags":["item5","def"],"ts":"2026-03-08T05:30:00Z"}`},
		{"3", `{"ul":100,"env":null,"bit_vec":"0f","ver":"1.0.0","tags":["other"],"ts":"2026-04-15T12:00:00Z"}`},
	}
	var ndjson strings.Builder
	for i, d := range docs {
		rowBytes, err := schema.ShredDocument(idxSchema, d.id, int64(i+1), false, []byte(d.body))
		if err != nil {
			t.Fatalf("ShredDocument(%s) failed: %v", d.id, err)
		}
		ndjson.Write(rowBytes)
		ndjson.WriteByte('\n')
	}
	if err := mem.StreamLoad(ctx, idxSchema.DorisTable, []byte(ndjson.String()), true); err != nil {
		t.Fatalf("StreamLoad failed: %v", err)
	}

	// F11: GetDocByID & GetDocsByIDs populate RawSource from _doc even when _source is disabled ("")
	got1, found, err := mem.GetDocByID(ctx, "es_db", idxSchema.DorisTable, "1")
	if err != nil || !found || string(got1.Source) != "" || !strings.Contains(string(got1.EffectiveSource()), "18446744073709551615") {
		t.Fatalf("F11 GetDocByID unexpected result: found=%v Source=%q EffectiveSource=%s err=%v", found, got1.Source, got1.EffectiveSource(), err)
	}
	gotMap, err := mem.GetDocsByIDs(ctx, "es_db", idxSchema.DorisTable, []string{"1", "2"})
	if err != nil || len(gotMap) != 2 || len(gotMap["2"].EffectiveSource()) == 0 {
		t.Fatalf("F11 GetDocsByIDs unexpected result: %+v err=%v", gotMap, err)
	}

	tr := &transpiler.Transpiler{Schema: idxSchema}

	// F10: Exact uint64 distinct comparison (18446744073709551615 vs 18446744073709551614 must NOT collide!)
	var srUL esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"term":{"ul":18446744073709551615}},"aggs":{"by_ul":{"terms":{"field":"ul"}}}}`), &srUL)
	planUL, err := tr.BuildSearchPlan(&srUL)
	if err != nil {
		t.Fatal(err)
	}
	hitsUL, err := mem.QueryHits(ctx, planUL.HitsSQL)
	if err != nil || len(hitsUL) != 1 || hitsUL[0].ID != "1" {
		t.Fatalf("F10 expected only doc 1 to match MaxUint64, got %+v (err=%v)", hitsUL, err)
	}

	// F13: exists query on constant_keyword matches ONLY doc 1 (not doc 2 missing or doc 3 null)
	var srCKExists esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"exists":{"field":"env"}}}`), &srCKExists)
	planCK, err := tr.BuildSearchPlan(&srCKExists)
	if err != nil {
		t.Fatal(err)
	}
	hitsCK, err := mem.QueryHits(ctx, planCK.HitsSQL)
	if err != nil || len(hitsCK) != 1 || hitsCK[0].ID != "1" {
		t.Fatalf("F13 expected only doc 1 to match exists(env), got %+v (err=%v)", hitsCK, err)
	}

	// F14: bit dense_vector Hamming similarity scoring on MemoryBackend
	var srBit esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"knn":{"field":"bit_vec","query_vector":"f0","k":3,"num_candidates":3}}`), &srBit)
	planBit, err := tr.BuildSearchPlan(&srBit)
	if err != nil {
		t.Fatal(err)
	}
	hitsBit, err := mem.QueryHits(ctx, planBit.HitsSQL)
	if err != nil || len(hitsBit) != 3 || hitsBit[0].ID != "1" || math.Abs(hitsBit[0].Score-1.0) > 1e-6 || math.Abs(hitsBit[1].Score-0.875) > 1e-6 {
		t.Fatalf("F14 unexpected bit knn scores: %+v (err=%v)", hitsBit, err)
	}

	// F15: SemVer sort order on MemoryBackend ("1.0.0-2" < "1.0.0-alpha" < "1.0.0")
	var srVerSort esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"sort":[{"ver":"asc"}]}`), &srVerSort)
	planVer, err := tr.BuildSearchPlan(&srVerSort)
	if err != nil {
		t.Fatal(err)
	}
	hitsVer, err := mem.QueryHits(ctx, planVer.HitsSQL)
	if err != nil || len(hitsVer) != 3 || hitsVer[0].ID != "2" || hitsVer[1].ID != "1" || hitsVer[2].ID != "3" {
		t.Fatalf("F15 expected SemVer order [2 ('1.0.0-2'), 1 ('1.0.0-alpha'), 3 ('1.0.0')], got %+v (err=%v)", hitsVer, err)
	}

	// F16: Compound array regexp with numeric interval & complement ("item<1-20>&~(item5)" matches doc 1 ["item12"], not doc 2 ["item5"])
	var srReg esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"regexp":{"tags":"item<1-20>&~(item5)"}}}`), &srReg)
	planReg, err := tr.BuildSearchPlan(&srReg)
	if err != nil {
		t.Fatal(err)
	}
	hitsReg, err := mem.QueryHits(ctx, planReg.HitsSQL)
	if err != nil || len(hitsReg) != 1 || hitsReg[0].ID != "1" {
		t.Fatalf("F16 expected only doc 1 to match 'item<1-20>&~(item5)', got %+v (err=%v)", hitsReg, err)
	}

	// F19: Calendar 1d + DST America/New_York on MemoryBackend:
	// 2026-03-08T04:30:00Z = 2026-03-07T23:30:00-05:00 -> bucket 2026-03-07T00:00:00-05:00
	// 2026-03-08T05:30:00Z = 2026-03-08T00:30:00-05:00 -> bucket 2026-03-08T00:00:00-05:00
	var srDST esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"by_day":{"date_histogram":{"field":"ts","calendar_interval":"1d","time_zone":"America/New_York"}}}}`), &srDST)
	planDST, err := tr.BuildSearchPlan(&srDST)
	if err != nil {
		t.Fatal(err)
	}
	aggRows, err := mem.QueryAggs(ctx, planDST.AggsSQL)
	if err != nil {
		t.Fatalf("F19 QueryAggs failed: %v", err)
	}
	var dayBuckets []string
	for _, r := range aggRows {
		if r.AggName == "by_day" {
			dayBuckets = append(dayBuckets, r.BucketKey)
		}
	}
	if len(dayBuckets) != 3 || dayBuckets[0] != "1772859600000" || dayBuckets[1] != "1772946000000" || dayBuckets[2] != "1776225600000" {
		t.Fatalf("F19 expected 3 distinct NY DST day buckets [1772859600000, 1772946000000, 1776225600000], got %v", dayBuckets)
	}
}

func TestRound59_TranspilerHooksHelpers(t *testing.T) {
	// F10: formatUnsignedLongOrNumericTermsKeyRound59
	var ulSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"ul":{"type":"unsigned_long"},"cnt":{"type":"long"},"price":{"type":"double"},"ver":{"type":"version"}}}`), &ulSpec)
	idxSchema := schema.CompileIndexSchema("es_db", "r59_hooks", &ulSpec)

	kv, ks, hasKS, handled := formatUnsignedLongOrNumericTermsKeyRound59("18446744073709551615", &esast.TermsAggSpec{Field: "ul"}, idxSchema)
	if !handled || hasKS || kv != uint64(math.MaxUint64) || ks != "" {
		t.Fatalf("F10 unsigned_long terms key failed: kv=%T(%v) ks=%q hasKS=%v handled=%v", kv, kv, ks, hasKS, handled)
	}
	kv2, ks2, hasKS2, handled2 := formatUnsignedLongOrNumericTermsKeyRound59("42", &esast.TermsAggSpec{Field: "cnt", Format: "0000"}, idxSchema)
	if !handled2 || !hasKS2 || kv2 != int64(42) || ks2 != "0042" {
		t.Fatalf("F10 formatted long terms key failed: kv=%T(%v) ks=%q", kv2, kv2, ks2)
	}
	kv3, _, _, handled3 := formatUnsignedLongOrNumericTermsKeyRound59("19.95", &esast.TermsAggSpec{Field: "price"}, idxSchema)
	if !handled3 || kv3 != 19.95 {
		t.Fatalf("F10 double terms key failed: kv=%T(%v)", kv3, kv3)
	}

	// F11: buildMappingResponseMapRound59, filterDocumentSourceRound59, applyDynamicRuntimeInferenceRound59
	var metaSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic": "runtime",
		"_meta": {"owner": "platform"},
		"_source": {"excludes": ["secret"]},
		"date_detection": false,
		"numeric_detection": true,
		"dynamic_date_formats": ["yyyy/MM/dd"],
		"subobjects": true,
		"properties": {"id": {"type": "keyword"}}
	}`), &metaSpec)
	updatedSpec, rtChanged := applyDynamicRuntimeInferenceRound59([]json.RawMessage{json.RawMessage(`{"id":"1","dyn_num":"123"}`)}, &metaSpec)
	if !rtChanged || updatedSpec.Runtime["dyn_num"].Type != "long" {
		t.Fatalf("F11 applyDynamicRuntimeInferenceRound59 failed: changed=%v rt=%+v", rtChanged, updatedSpec.Runtime)
	}
	metaSchema := schema.CompileIndexSchema("es_db", "r59_meta", updatedSpec)
	respMap := buildMappingResponseMapRound59(metaSchema)
	for _, k := range []string{"properties", "runtime", "dynamic", "_meta", "_source", "date_detection", "numeric_detection", "dynamic_date_formats", "subobjects"} {
		if _, ok := respMap[k]; !ok {
			t.Fatalf("F11 missing key %q in buildMappingResponseMapRound59: %+v", k, respMap)
		}
	}
	filteredSrc, includeSrc := filterDocumentSourceRound59(json.RawMessage(`{"id":"1","secret":"hide","keep":"yes"}`), metaSchema, &esast.SourceFilter{Includes: []string{"keep", "secret"}})
	if !includeSrc || strings.Contains(string(filteredSrc), "secret") || !strings.Contains(string(filteredSrc), "keep") {
		t.Fatalf("F11 filterDocumentSourceRound59 failed: include=%v src=%s", includeSrc, filteredSrc)
	}

	// F12 & F17: parseAndApplyIndexMappingSettingsRound59
	if err := parseAndApplyIndexMappingSettingsRound59(map[string]any{
		"index": map[string]any{
			"mapping": map[string]any{
				"total_fields":      map[string]any{"limit": 500},
				"depth":             map[string]any{"limit": 12},
				"nested_fields":     map[string]any{"limit": 10},
				"nested_objects":    map[string]any{"limit": 250},
				"field_name_length": map[string]any{"limit": 64},
				"coerce":            false,
				"ignore_malformed":  true,
			},
			"max_terms_count": 128,
		},
	}, idxSchema); err != nil {
		t.Fatalf("F12/F17 valid settings failed: %v", err)
	}
	if idxSchema.MaxTotalFields != 500 || idxSchema.MaxDepth != 12 || idxSchema.MaxNestedFields != 10 ||
		idxSchema.MaxNestedObjects != 250 || idxSchema.MaxFieldNameLength != 64 || idxSchema.MaxTermsCount != 128 ||
		*idxSchema.DefaultCoerce || !*idxSchema.DefaultIgnoreMalformed {
		t.Fatalf("F12/F17 settings not applied cleanly: %+v", idxSchema)
	}
	if err := parseAndApplyIndexMappingSettingsRound59(map[string]any{"index.max_terms_count": 0}, idxSchema); err == nil {
		t.Fatalf("F17 expected max_terms_count=0 to fail")
	}
	if err := parseAndApplyIndexMappingSettingsRound59(map[string]any{"index.mapping.coerce": "maybe"}, idxSchema); err == nil {
		t.Fatalf("F12 expected invalid coerce boolean to fail")
	}

	// F13: adoptConstantKeywordValuesFromDocsRound59
	var ckAutoSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"service":{"type":"constant_keyword"}}}`), &ckAutoSpec)
	ckAutoSchema := schema.CompileIndexSchema("es_db", "r59_ck_auto", &ckAutoSpec)
	adopted, err := adoptConstantKeywordValuesFromDocsRound59(ckAutoSchema, []json.RawMessage{
		json.RawMessage(`{"other":1}`),
		json.RawMessage(`{"service":null}`),
		json.RawMessage(`{"service":"billing"}`),
	})
	if err != nil || !adopted || ckAutoSchema.Fields["service"].ConstantValue != "billing" || !ckAutoSchema.Fields["service"].HasConstantValue {
		t.Fatalf("F13 adoptConstantKeywordValuesFromDocsRound59 failed: adopted=%v err=%v field=%+v", adopted, err, ckAutoSchema.Fields["service"])
	}
	var ckConflictSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"service":{"type":"constant_keyword"}}}`), &ckConflictSpec)
	ckConflictSchema := schema.CompileIndexSchema("es_db", "r59_ck_conflict", &ckConflictSpec)
	if _, err := adoptConstantKeywordValuesFromDocsRound59(ckConflictSchema, []json.RawMessage{
		json.RawMessage(`{"service":"a"}`),
		json.RawMessage(`{"service":"b"}`),
	}); err == nil {
		t.Fatalf("F13 expected conflicting batch values on uninitialized constant_keyword to fail")
	}

	// F15: compareCompositeVersionValuesRound59
	cmp, isVer := compareCompositeVersionValuesRound59("1.10.0", "1.2.0", esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "ver"}}, false, idxSchema)
	if !isVer || cmp <= 0 {
		t.Fatalf("F15 expected '1.10.0' > '1.2.0', got cmp=%d isVer=%v", cmp, isVer)
	}

	// F18: evalFieldValueFactorOnDocRound59 & evalRuntimeSearchScoreWithErrorRound59
	fvfScore, ok, err := evalFieldValueFactorOnDocRound59(idxSchema, map[string]any{"price": 4.0}, &esast.FieldValueFactorSpec{
		Field:    "price",
		Modifier: "reciprocal",
	})
	if err != nil || !ok || math.Abs(fvfScore-0.25) > 1e-9 {
		t.Fatalf("F18 expected reciprocal(4.0) == 0.25, got %v (ok=%v err=%v)", fvfScore, ok, err)
	}
	missScore, ok, err := evalFieldValueFactorOnDocRound59(idxSchema, map[string]any{}, &esast.FieldValueFactorSpec{
		Field:    "price",
		Modifier: "log2p",
	})
	if err != nil || !ok || missScore != 0.0 {
		t.Fatalf("F18 expected missing field without missing param to return 0.0, got %v (err=%v)", missScore, err)
	}
	if _, _, err := evalFieldValueFactorOnDocRound59(idxSchema, map[string]any{"price": 0.0}, &esast.FieldValueFactorSpec{
		Field:    "price",
		Modifier: "log",
	}); err == nil {
		t.Fatalf("F18 expected log(0) domain violation error")
	}
	var negSS esast.Query
	_ = json.Unmarshal([]byte(`{"script_score":{"query":{"match_all":{}},"script":{"source":"-5.0"}}}`), &negSS)
	if !queryProducesCustomScoreRound59(&negSS) {
		t.Fatalf("F18 expected queryProducesCustomScoreRound59=true")
	}
	if _, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, map[string]any{}, &negSS, 1.0); err == nil {
		t.Fatalf("F18 expected negative script_score to return error")
	}

	// F19: synthesizeDateHistogramBucketsRound59 & formatDateHistogramKeyAsStringRound59 across DST
	zero := 0
	dhSpec := &esast.DateHistogramAggSpec{
		Field:            "ts",
		CalendarInterval: "1M",
		TimeZone:         "America/New_York",
		MinDocCount:      &zero,
		ExtendedBounds: &esast.HistogramBoundsSpec{
			Min: "2026-01-15",
			Max: "2026-04-15",
		},
	}
	synth := synthesizeDateHistogramBucketsRound59(nil, dhSpec)
	if len(synth) != 4 {
		t.Fatalf("F19 expected 4 monthly buckets Jan..Apr 2026, got %d: %+v", len(synth), synth)
	}
	janKey, _ := parseInt64TestHelper(synth[0].BucketKey)
	aprKey, _ := parseInt64TestHelper(synth[3].BucketKey)
	janStr := formatDateHistogramKeyAsStringRound59(janKey, dhSpec)
	aprStr := formatDateHistogramKeyAsStringRound59(aprKey, dhSpec)
	if !strings.HasSuffix(janStr, "-05:00") || !strings.HasSuffix(aprStr, "-04:00") {
		t.Fatalf("F19 expected winter -05:00 (%s) and summer -04:00 (%s) offsets", janStr, aprStr)
	}
}

func parseInt64TestHelper(s string) (int64, bool) {
	v, ok := toInt64(s)
	return v, ok
}
