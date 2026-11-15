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

func TestRound60_F3_F5_MGet_MLT_Bulk_Template_Script(t *testing.T) {
	// 1. MGetRequest & MGetDocSpec flexible scalar IDs and routing
	var mget MGetRequest
	rawMGet := `{"ids": [1, 2, "three"], "routing": 42, "docs": [{"_index": "idx", "_id": 100, "routing": 200}, {"id": 99.5, "_routing": 7}]}`
	if err := json.Unmarshal([]byte(rawMGet), &mget); err != nil {
		t.Fatalf("MGetRequest unmarshal failed: %v", err)
	}
	if len(mget.IDs) != 3 || mget.IDs[0] != "1" || mget.IDs[1] != "2" || mget.IDs[2] != "three" {
		t.Fatalf("unexpected MGetRequest.IDs: %#v", mget.IDs)
	}
	if mget.Routing != "42" {
		t.Fatalf("expected MGetRequest.Routing='42', got %q", mget.Routing)
	}
	if len(mget.Docs) != 2 || mget.Docs[0].ID != "100" || !mget.Docs[0].HasID || mget.Docs[0].Routing != "200" {
		t.Fatalf("unexpected MGetDocSpec[0]: %+v", mget.Docs[0])
	}
	if mget.Docs[1].ID != "99.5" || !mget.Docs[1].HasID || mget.Docs[1].Routing != "7" {
		t.Fatalf("unexpected MGetDocSpec[1]: %+v", mget.Docs[1])
	}

	// 2. MLTItem & MoreLikeThisQuery flexible numeric _id & routing
	var qMLT Query
	rawMLT := `{"more_like_this": {"fields": ["title"], "like": [{"_index": "idx", "_id": 1, "routing": 2}, "free text"]}}`
	if err := json.Unmarshal([]byte(rawMLT), &qMLT); err != nil {
		t.Fatalf("MoreLikeThisQuery unmarshal failed: %v", err)
	}
	var mltItem MLTItem
	if err := json.Unmarshal([]byte(`{"_index": "idx", "_id": 1, "routing": 2}`), &mltItem); err != nil {
		t.Fatalf("MLTItem unmarshal failed: %v", err)
	}
	if mltItem.ID != "1" || mltItem.Routing != "2" {
		t.Fatalf("expected MLTItem ID='1' Routing='2', got %+v", mltItem)
	}

	// 3. BulkActionMeta: HasID, empty _id rejection, op_type=create, and empty `{}` line message
	if _, err := ParseBulkNDJSON(strings.NewReader("{}\n"), "idx"); err == nil || err.Error() != "Malformed action/metadata line [1], expected FIELD_NAME but found [END_OBJECT]" {
		t.Fatalf("expected exact empty bulk line error, got: %v", err)
	}
	if _, err := ParseBulkNDJSON(strings.NewReader(`{"index":{"_id":""}}`+"\n"+`{"a":1}`+"\n"), "idx"); err == nil || !strings.Contains(err.Error(), "if _id is specified it must not be empty") {
		t.Fatalf("expected empty _id error in bulk, got: %v", err)
	}
	if _, err := ParseBulkNDJSON(strings.NewReader(`{"index":{"_id":1,"op_type":"bogus"}}`+"\n"+`{"a":1}`+"\n"), "idx"); err == nil {
		t.Fatalf("expected invalid op_type error in bulk")
	}
	ops, err := ParseBulkNDJSON(strings.NewReader(
		`{"index":{"_id":1,"routing":2,"op_type":"create"}}`+"\n"+
			`{"x":10}`+"\n"+
			`{"index":{"op_type":"index"}}`+"\n"+
			`{"x":20}`+"\n",
	), "default_idx")
	if err != nil {
		t.Fatalf("ParseBulkNDJSON valid failed: %v", err)
	}
	if len(ops) != 2 || ops[0].Action != "create" || !ops[0].HasID || ops[0].ID != "1" || ops[0].Routing != "2" {
		t.Fatalf("unexpected ops[0]: %+v", ops[0])
	}
	if ops[1].Action != "index" || ops[1].HasID {
		t.Fatalf("unexpected ops[1]: %+v", ops[1])
	}

	// 4. LegacyTemplateSpec / IndexTemplateRequest single string or string array index_patterns
	var tplSingle LegacyTemplateSpec
	if err := json.Unmarshal([]byte(`{"index_patterns": "test-*", "order": 1}`), &tplSingle); err != nil {
		t.Fatalf("LegacyTemplateSpec string index_patterns failed: %v", err)
	}
	if len(tplSingle.IndexPatterns) != 1 || tplSingle.IndexPatterns[0] != "test-*" {
		t.Fatalf("unexpected tplSingle.IndexPatterns: %#v", tplSingle.IndexPatterns)
	}
	var tplArr IndexTemplateRequest
	if err := json.Unmarshal([]byte(`{"index_patterns": ["test-*", "logs-*"]}`), &tplArr); err != nil {
		t.Fatalf("IndexTemplateRequest array index_patterns failed: %v", err)
	}
	if len(tplArr.IndexPatterns) != 2 {
		t.Fatalf("unexpected tplArr.IndexPatterns: %#v", tplArr.IndexPatterns)
	}

	// 5. ScriptSpec string shorthand & object form
	var ssShort ScriptSpec
	if err := json.Unmarshal([]byte(`"ctx._source.num++"`), &ssShort); err != nil {
		t.Fatalf("ScriptSpec string shorthand failed: %v", err)
	}
	if ssShort.Source != "ctx._source.num++" || ssShort.Lang != "painless" {
		t.Fatalf("unexpected ScriptSpec shorthand: %+v", ssShort)
	}
}

func TestRound60_F10_F12_F15_F16_F18_F19_F25_AST(t *testing.T) {
	// F10: 2nd-level collapse in inner_hits allowed; 3rd-level rejected
	var sr2Level SearchRequest
	raw2Level := `{"collapse":{"field":"a","inner_hits":{"name":"sub","collapse":{"field":"b"}}}}`
	if err := json.Unmarshal([]byte(raw2Level), &sr2Level); err != nil {
		t.Fatalf("expected 2nd-level collapse to succeed, got: %v", err)
	}
	if sr2Level.Collapse == nil || len(sr2Level.Collapse.InnerHits) != 1 || sr2Level.Collapse.InnerHits[0].Collapse == nil || sr2Level.Collapse.InnerHits[0].Collapse.Field != "b" {
		t.Fatalf("unexpected 2nd-level collapse AST: %+v", sr2Level.Collapse)
	}
	for _, bad3 := range []string{
		`{"collapse":{"field":"a","inner_hits":{"name":"sub","collapse":{"field":"b","inner_hits":{"name":"sub2"}}}}}`,
		`{"collapse":{"field":"a","inner_hits":{"name":"sub","collapse":{"field":"b","collapse":{"field":"c"}}}}}`,
	} {
		var srBad SearchRequest
		if err := json.Unmarshal([]byte(bad3), &srBad); err == nil {
			t.Fatalf("expected 3rd-level collapse/inner_hits to fail for %s", bad3)
		}
	}

	// F12: AggSpec.Meta object & null accepted; scalar/array rejected
	var srMeta SearchRequest
	if err := json.Unmarshal([]byte(`{"aggs":{"a1":{"meta":{"color":"blue"},"avg":{"field":"v"}},"a2":{"meta":null,"sum":{"field":"v"}}}}`), &srMeta); err != nil {
		t.Fatalf("AggSpec.Meta valid unmarshal failed: %v", err)
	}
	if srMeta.Aggs["a1"].Meta["color"] != "blue" || srMeta.Aggs["a2"].Meta != nil {
		t.Fatalf("unexpected AggSpec.Meta: a1=%v a2=%v", srMeta.Aggs["a1"].Meta, srMeta.Aggs["a2"].Meta)
	}
	for _, badMeta := range []string{
		`{"aggs":{"a1":{"meta":"bad","avg":{"field":"v"}}}}`,
		`{"aggs":{"a1":{"meta":[1,2],"avg":{"field":"v"}}}}`,
	} {
		var srBad SearchRequest
		if err := json.Unmarshal([]byte(badMeta), &srBad); err == nil || !strings.Contains(err.Error(), "[meta] must be an object") {
			t.Fatalf("expected [meta] must be an object error for %s, got: %v", badMeta, err)
		}
	}

	// F15: Percentiles & PercentileRanks TDigest/HDR/Format + numberOfSignificantValueDigits validation
	var srPct SearchRequest
	if err := json.Unmarshal([]byte(`{"aggs":{"p":{"percentiles":{"field":"v","format":"0.00","hdr":{"number_of_significant_value_digits":4}}},"pr":{"percentile_ranks":{"field":"v","values":[10,20],"tdigest":{"compression":200}}}}}`), &srPct); err != nil {
		t.Fatalf("Percentiles/PercentileRanks valid unmarshal failed: %v", err)
	}
	if srPct.Aggs["p"].Percentiles.HDR == nil || srPct.Aggs["p"].Percentiles.HDR.EffectiveSignificantDigits() != 4 || srPct.Aggs["p"].Percentiles.Format != "0.00" {
		t.Fatalf("unexpected Percentiles HDR/Format: %+v", srPct.Aggs["p"].Percentiles)
	}
	if srPct.Aggs["pr"].PercentileRanks.TDigest == nil || *srPct.Aggs["pr"].PercentileRanks.TDigest.Compression != 200 {
		t.Fatalf("unexpected PercentileRanks TDigest: %+v", srPct.Aggs["pr"].PercentileRanks)
	}
	for _, badHDR := range []string{
		`{"aggs":{"p":{"percentiles":{"field":"v","hdr":{"number_of_significant_value_digits":-1}}}}}`,
		`{"aggs":{"p":{"percentiles":{"field":"v","hdr":{"number_of_significant_value_digits":6}}}}}`,
		`{"aggs":{"p":{"percentiles":{"field":"v","hdr":{"number_of_significant_value_digits":null}}}}}`,
		`{"aggs":{"pr":{"percentile_ranks":{"field":"v","values":[1],"hdr":{"number_of_significant_value_digits":6}}}}}`,
	} {
		var srBad SearchRequest
		if err := json.Unmarshal([]byte(badHDR), &srBad); err == nil || !strings.Contains(err.Error(), "numberOfSignificantValueDigits must be between 0 and 5") {
			t.Fatalf("expected exact camelCase HDR error for %s, got: %v", badHDR, err)
		}
	}

	// F16: match_bool_prefix rejects slop and cutoff_frequency
	for _, badMBP := range []string{
		`{"match_bool_prefix":{"title":{"query":"quick brown f","slop":2}}}`,
		`{"match_bool_prefix":{"title":{"query":"quick brown f","cutoff_frequency":0.01}}}`,
	} {
		var qBad Query
		if err := json.Unmarshal([]byte(badMBP), &qBad); err == nil || !strings.Contains(err.Error(), "[match_bool_prefix] query does not support") {
			t.Fatalf("expected match_bool_prefix error for %s, got: %v", badMBP, err)
		}
	}

	// F18 & F19: FieldProperty.Meta, FieldProperty.Contexts, and query-time CompletionSuggestSpec.Contexts / SkipDuplicatesPtr
	var fp FieldProperty
	if err := json.Unmarshal([]byte(`{"type":"completion","meta":{"unit":"ms"},"contexts":[{"name":"cat","type":"category","path":"cat_field"},{"name":"loc","type":"geo","precision":"1km"}]}`), &fp); err != nil {
		t.Fatalf("FieldProperty completion+meta unmarshal failed: %v", err)
	}
	if fp.Meta["unit"] != "ms" || len(fp.Contexts) != 2 || fp.Contexts[0].Name != "cat" || fp.Contexts[1].Type != "geo" {
		t.Fatalf("unexpected FieldProperty Meta/Contexts: %+v", fp)
	}
	// >5 meta entries rejected
	var fpBadMeta FieldProperty
	if err := json.Unmarshal([]byte(`{"type":"keyword","meta":{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5","k6":"6"}}`), &fpBadMeta); err == nil {
		t.Fatalf("expected >5 field meta entries to fail")
	}

	var srSug SearchRequest
	rawSug := `{"suggest":{"s":{"prefix":"tim","completion":{"field":"suggest","skip_duplicates":true,"contexts":{"cat":["cafe",{"context":"book","boost":2,"prefix":true}],"loc":{"lat":43.66,"lon":-79.38}}}}}}`
	if err := json.Unmarshal([]byte(rawSug), &srSug); err != nil {
		t.Fatalf("CompletionSuggestSpec contexts unmarshal failed: %v", err)
	}
	cs := srSug.Suggest["s"].Completion
	if cs == nil || !cs.SkipDuplicates || cs.SkipDuplicatesPtr == nil || !*cs.SkipDuplicatesPtr || len(cs.Contexts["cat"]) != 2 || len(cs.Contexts["loc"]) != 1 {
		t.Fatalf("unexpected CompletionSuggestSpec: %+v", cs)
	}

	// F25: intervals filter.script
	var qInt Query
	rawInt := `{"intervals":{"title":{"all_of":{"intervals":[{"match":{"query":"foo"}},{"prefix":{"prefix":"ba","filter":{"script":"interval.start > 0"}}}],"filter":{"script":{"source":"interval.gaps == 0"}}}}}}`
	if err := json.Unmarshal([]byte(rawInt), &qInt); err != nil {
		t.Fatalf("intervals filter.script unmarshal failed: %v", err)
	}
	r := qInt.Intervals["title"]
	if r.AllOf == nil || r.AllOf.Filter == nil || r.AllOf.Filter.Script == nil || r.AllOf.Filter.Script.Source != "interval.gaps == 0" {
		t.Fatalf("unexpected intervals all_of filter.script: %+v", r.AllOf)
	}
	if r.AllOf.Intervals[1].Prefix == nil || r.AllOf.Intervals[1].Prefix.Filter == nil || r.AllOf.Intervals[1].Prefix.Filter.Script.Source != "interval.start > 0" {
		t.Fatalf("unexpected intervals prefix filter.script: %+v", r.AllOf.Intervals[1].Prefix)
	}
}
