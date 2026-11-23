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
	"testing"
)

func FuzzPainlessEval(f *testing.F) {
	seeds := []struct {
		doc    string
		script string
	}{
		{`{"count":10,"title":"init","tags":["a","b"]}`, `ctx._source.count = 10 - 3 - 2; ctx._source.title = '10' + '20'`},
		{`{"a":1,"b":0,"c":1}`, `if ((ctx._source.a == 1 || ctx._source.b == 1) && ctx._source.c == 1) { ctx._source.ok = true; }`},
		{`{"tags":["x","y","z"],"secret":"drop"}`, `ctx._source.remove('secret'); ctx._source.tags.remove(1); ctx._source.tags.add(params.tag)`},
		{`{"views":5}`, `ctx._source.views += params.inc; if (!(ctx._source.views < 0)) { ctx._source.valid = true; }`},
		{`{"status":"archived"}`, `if (ctx._source.status == 'archived') { ctx.op = 'delete'; }`},
		{`{"status":"same"}`, `ctx.op = 'noop'`},
		{`{"s":"abc"}`, `ctx._source.r = ctx._source.s.repeat(1L << 62)`},
		{`{"v":1}`, `ctx._source.bd = new BigDecimal('1e2147483647')`},
		{`{"v":1}`, `ctx._source.bd = new BigDecimal('1').movePointLeft(100000).toPlainString()`},
		{`{"v":1}`, `ctx._source.bd = new BigDecimal('2').pow(100000)`},
		{`{"v":1}`, `ctx._source.bi = BigInteger.valueOf(2).pow(100000)`},
		{`{"v":1}`, `ctx._source.bi = BigInteger.ONE.shiftLeft(100000)`},
		{`{"v":1}`, `ctx._source.bi = BigInteger.ZERO.setBit(100000)`},
		{`{"v":1}`, `BitSet bs = new BitSet(); bs.set(1 << 25); ctx._source.bs = bs.toString()`},
		{`{"v":1}`, `BitSet bs = new BitSet(); bs.set(0, 20000); ctx._source.bs = bs.cardinality()`},
		{`{"v":1}`, `BitSet bs = new BitSet(); bs.flip(0, 20000); ctx._source.bs = bs.cardinality()`},
		{`{"n":null}`, `ctx._source.nan_bi = field('n').asBigInteger(0L)`},
		// F7b: GeoShapeDocValues / WKT (Infinity, POLYGON, GEOMETRYCOLLECTION), hamming(), and score/filter
		{`{"geo_shape":"POLYGON((24.04725 59.942,24.04825 59.94125,24.04875 59.94125,24.04875 59.94175,24.048 59.9425,24.0475 59.94275,24.0465 59.94225,24.046 59.94225,24.04575 59.9425,24.04525 59.94225,24.04725 59.942))"}`, `ctx._source.c = doc['geo_shape'].getCentroid().lat; ctx._source.br = doc['geo_shape'].getBoundingBox().bottomRight().lon`},
		{`{"geo_shape":"GEOMETRYCOLLECTION(POINT(1 2),LINESTRING(0 0,3 4))"}`, `ctx._source.lp = doc['geo_shape'].getLabelPosition().lat; ctx._source.dim = doc['geo_shape'].getDimensionalType()`},
		{`{"geo_shape":"POINT(Infinity -Infinity)"}`, `ctx._source.c = doc['geo_shape'].getCentroid()`},
		{`{"geo_point":"41.12,-71.34"}`, `ctx._source.br = doc['geo_point'].getBoundingBox().bottomRight().lat`},
		{`{"vec":[0,111,-13,14,-124]}`, `ctx._source.h = hamming('006ff30e84', 'vec')`},
		{`{"vec":"006ff30e84"}`, `ctx._source.h = hamming([0,111,-13,14,-124], 'vec')`},
		{`{"score_base":3.5,"active":true}`, `return doc['score_base'].value * _score > 1.0 && ctx._source.active == true;`},
	}
	for _, s := range seeds {
		f.Add(s.doc, s.script)
	}
	f.Fuzz(func(t *testing.T, rawDoc string, scriptSrc string) {
		req := &UpdateRequest{
			Script: &ScriptSpec{
				Source: scriptSrc,
				Params: map[string]any{"inc": 3, "tag": "fuzz"},
			},
			Upsert: map[string]any{"seed": 1},
		}
		out, opRes, err := ApplyUpdateWithResult(json.RawMessage(rawDoc), req, len(rawDoc) > 0)
		if err == nil && opRes != "deleted" && opRes != "noop" && len(out) > 0 {
			var parsed map[string]any
			if uErr := json.Unmarshal(out, &parsed); uErr != nil {
				t.Fatalf("ApplyUpdateWithResult returned invalid JSON %q for script %q: %v", string(out), scriptSrc, uErr)
			}
		}
		_, _ = ParseGeoShapeDocValues(rawDoc)
		_, _ = ParseGeoShapeDocValues(scriptSrc)
		var docMap map[string]any
		if uErr := json.Unmarshal([]byte(rawDoc), &docMap); uErr == nil && docMap != nil {
			fuzzParams := map[string]any{
				"_score": 2.0,
				"__field_types": map[string]string{
					"geo_shape": "geo_shape",
					"geo_point": "geo_point",
					"vec":       "dense_vector",
				},
				"__vector_element_types": map[string]string{
					"vec": "byte",
				},
			}
			_, _ = EvalFilter(docMap, scriptSrc, fuzzParams)
			_, _, _ = EvalNumber(docMap, scriptSrc, fuzzParams)
			fuzzParams["__vector_element_types"] = map[string]string{"vec": "bit"}
			_, _, _ = EvalNumber(docMap, scriptSrc, fuzzParams)
		}
	})
}
