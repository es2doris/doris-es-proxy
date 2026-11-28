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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func buildRound67FuzzSchemas() []*IndexSchema {
	boolTrue := true
	boolFalse := false

	strictSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"vec_float": {
				Type:        "dense_vector",
				Dims:        4,
				ElementType: "float",
				Similarity:  "l2_norm",
			},
			"vec_bit": {
				Type:        "dense_vector",
				Dims:        16,
				ElementType: "bit",
			},
			"vec_byte": {
				Type:        "dense_vector",
				Dims:        4,
				ElementType: "byte",
				Similarity:  "cosine",
			},
			"vec_int4": {
				Type:        "dense_vector",
				Dims:        4,
				ElementType: "int4_quantized",
				Similarity:  "dot_product",
				IndexOptions: map[string]any{
					"type": "int4_hnsw",
				},
			},
			"sv": {
				Type: "sparse_vector",
			},
			"rf": {
				Type: "rank_features",
			},
			"flat": {
				Type: "flattened",
			},
		},
	}
	strictSchema := CompileIndexSchema("es_db", "round67_fuzz_strict", strictSpec)

	tolerantSpec := &esast.MappingSpec{
		Source: map[string]any{
			"mode": "synthetic",
		},
		Properties: map[string]esast.FieldProperty{
			"vec_float": {
				Type:            "dense_vector",
				Dims:            4,
				ElementType:     "float",
				Similarity:      "cosine",
				IgnoreMalformed: &boolTrue,
			},
			"vec_bit": {
				Type:            "dense_vector",
				Dims:            16,
				ElementType:     "bit",
				IgnoreMalformed: &boolTrue,
			},
			"vec_byte": {
				Type:            "dense_vector",
				Dims:            4,
				ElementType:     "byte",
				Similarity:      "cosine",
				IgnoreMalformed: &boolTrue,
			},
			"vec_int4": {
				Type:            "dense_vector",
				ElementType:     "int4_quantized",
				IgnoreMalformed: &boolTrue,
				Index:           &boolFalse,
			},
			"sv": {
				Type:            "sparse_vector",
				IgnoreMalformed: &boolTrue,
			},
			"rf": {
				Type:            "rank_features",
				IgnoreMalformed: &boolTrue,
			},
			"flat": {
				Type:            "flattened",
				IgnoreMalformed: &boolTrue,
			},
		},
	}
	tolerantSchema := CompileIndexSchema("es_db", "round67_fuzz_tolerant", tolerantSpec)
	return []*IndexSchema{strictSchema, tolerantSchema}
}

func assertValidNDJSONBytes(t *testing.T, raw []byte) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatalf("ShredDocument returned empty output")
	}
	for i, b := range raw {
		if b < 0x20 {
			t.Fatalf("ShredDocument emitted unescaped control byte 0x%02x at offset %d in %q", b, i, raw)
		}
	}
	if !json.Valid(raw) {
		t.Fatalf("ShredDocument emitted invalid JSON: %q", raw)
	}
	var decoded map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("failed to decode ShredDocument NDJSON row: %v (raw=%q)", err, raw)
	}
	if srcStr, ok := decoded["_source"].(string); ok && srcStr != "" {
		if !json.Valid([]byte(srcStr)) {
			t.Fatalf("emitted invalid _source JSON string: %q", srcStr)
		}
	}
}

func FuzzVectorAndFlattenedShredder(f *testing.F) {
	schemas := buildRound67FuzzSchemas()
	seeds := []struct {
		mode    uint8
		rawJSON string
		strA    string
		strB    string
	}{
		{0, `{"vec_float":[0.1,0.2,0.3,0.4],"vec_bit":"0f0f","vec_byte":[1,2,3,4],"vec_int4":[1,2,3,4],"sv":{"t1":1.5,"t2":0.25},"rf":{"a":2.0},"flat":{"k":{"sub":"v"},"arr":[1,2,"x"]}}`, "ab\x00cd", "0f1"},
		{1, `{"vec_float":["NaN","Inf","-Infinity",1.0],"vec_bit":"abc","vec_byte":[128,-129,0,1],"vec_int4":[1,2,3]}`, "NaN", "deadbeef"},
		{2, `{"sv":[{"tok1":1.2},{"tok2":3.4}],"rf":[{"f1":-1},{"f2":0}],"flat":{"deep":{"nested":{"x":true,"y":null}},"dot.k":"v\n\t\x1f"}}`, "foo.bar", "xyz"},
		{3, `{"vec_bit":[12,-5],"vec_byte":"01020304","sv":{"k":"NaN"},"flat":["scalar",{"m":1}]}`, "k\x01\x02", "00ff"},
		{4, `{"vec_float":[0,0,0,0],"vec_bit":[],"vec_byte":"zz","vec_int4":"bad","flat":{"":"empty"}}`, "\xff\xfe", "1"},
		{5, `null`, "", ""},
		{6, `[]`, "{", "}"},
	}
	for _, s := range seeds {
		f.Add(s.mode, []byte(s.rawJSON), s.strA, s.strB)
	}

	f.Fuzz(func(t *testing.T, mode uint8, rawJSON []byte, strA string, strB string) {
		docBytes := rawJSON
		if mode%3 == 0 {
			escapedA, _ := json.Marshal(strA)
			escapedB, _ := json.Marshal(strB)
			docBytes = []byte(fmt.Sprintf(
				`{"vec_float":[%s,1.0,2.0,3.0],"vec_bit":%s,"vec_byte":%s,"vec_int4":[1,2,3],"sv":[{"k":1.25},{%s:0.5}],"rf":{%s:2.5},"flat":{"a":{%s:%s},"arr":[%s,42,true]}}`,
				string(escapedA),
				string(escapedB),
				string(escapedB),
				string(escapedA),
				string(escapedB),
				string(escapedA),
				string(escapedB),
				string(escapedA),
			))
		} else if mode%3 == 1 && !strings.HasPrefix(strings.TrimSpace(string(rawJSON)), "{") {
			escapedA, _ := json.Marshal(strA)
			docBytes = []byte(fmt.Sprintf(`{"flat":{"raw":%s,"sub":[%s]},"vec_bit":%s,"sv":{%s:1.0}}`, string(escapedA), string(escapedA), string(escapedA), string(escapedA)))
		}

		for idx, sc := range schemas {
			out, err := ShredDocument(sc, fmt.Sprintf("fuzz-%d-%d", mode, idx), 1, false, docBytes)
			if err != nil {
				continue
			}
			assertValidNDJSONBytes(t, out)
		}
	})
}
