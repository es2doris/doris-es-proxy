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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound62_P0_NestedVectorShredderAndCopyOnWriteAutoDims(t *testing.T) {
	// 1. Nested hex-encoded byte & bit vectors stored as normalized float arrays inside n__<nested>
	var nestedSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"chunks": {
				"type": "nested",
				"properties": {
					"bvec": {"type": "dense_vector", "element_type": "byte", "similarity": "dot_product"},
					"bitvec": {"type": "dense_vector", "element_type": "bit"},
					"sub": {
						"properties": {
							"fvec": {"type": "dense_vector"}
						}
					}
				}
			},
			"root_bvec": {"type": "dense_vector", "element_type": "byte", "similarity": "dot_product"}
		}
	}`), &nestedSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&nestedSpec); err != nil {
		t.Fatalf("nested vector spec invalid: %v", err)
	}
	baseIdx := CompileIndexSchema("es-prod", "r62_nested_vec", &nestedSpec)
	baseIdx.ES8Mode = true

	rawDoc := []byte(`{
		"root_bvec": "7f80ff00",
		"chunks": [
			{"bvec": "7f80ff00", "bitvec": "f0", "sub": {"fvec": [0.5, 0.5]}},
			{"bvec": [1, 2, 3, 4], "bitvec": [-16], "sub": {"fvec": [0.25, 0.75]}}
		]
	}`)

	// Concurrent -race stress test: 16 goroutines simultaneously calling ShredDocument + InspectAutoDimsAndDynamicVectors + CloneWithLockedAutoDims
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if _, err := ShredDocument(baseIdx, fmt.Sprintf("doc-%d", id), 1, false, rawDoc); err != nil {
				t.Errorf("concurrent ShredDocument(%d) failed: %v", id, err)
				return
			}
			locked, dynVecs, err := InspectAutoDimsAndDynamicVectors(baseIdx, [][]byte{rawDoc})
			if err != nil {
				t.Errorf("concurrent InspectAutoDimsAndDynamicVectors(%d) failed: %v", id, err)
				return
			}
			cloned, _ := baseIdx.CloneWithAutoDimsAndDynamicVectors(locked, dynVecs)
			if cloned.Fields["chunks.bvec"].VectorDims != 4 || cloned.Fields["chunks.bitvec"].VectorDims != 8 || cloned.Fields["root_bvec"].VectorDims != 4 {
				t.Errorf("unexpected cloned dims: %+v", cloned.Fields)
			}
		}(g)
	}
	wg.Wait()

	// Verify baseIdx was NEVER mutated in place
	if baseIdx.Fields["root_bvec"].VectorDims != 0 || !baseIdx.Fields["root_bvec"].AutoDims {
		t.Fatalf("baseIdx was mutated in place: %+v", baseIdx.Fields["root_bvec"])
	}

	shredBytes, err := ShredDocument(baseIdx, "n1", 1, false, rawDoc)
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatal(err)
	}
	elems, ok := row["n__chunks"].([]any)
	if !ok || len(elems) != 2 {
		t.Fatalf("expected 2 serialized nested elements in n__chunks, got %#v", row["n__chunks"])
	}
	var elem0 map[string]any
	if err := json.Unmarshal([]byte(elems[0].(string)), &elem0); err != nil {
		t.Fatal(err)
	}
	wantBVec := []any{float64(127), float64(-128), float64(-1), float64(0)}
	if !reflect.DeepEqual(elem0["bvec"], wantBVec) {
		t.Fatalf("expected normalized nested byte vector %v, got %#v", wantBVec, elem0["bvec"])
	}
	wantBitVec := []any{float64(1), float64(1), float64(1), float64(1), float64(0), float64(0), float64(0), float64(0)}
	if !reflect.DeepEqual(elem0["bitvec"], wantBitVec) {
		t.Fatalf("expected normalized nested bit vector %v, got %#v", wantBitVec, elem0["bitvec"])
	}

	// 2. InspectAutoDimsAndDynamicVectors + CloneWithLockedAutoDims + GenerateAddColumnsDDL for ES8 [128..2048] dynamic float vectors
	vals128 := make([]string, 128)
	for i := range vals128 {
		vals128[i] = "0.25"
	}
	dynDoc := []byte(fmt.Sprintf(`{"root_bvec":"0102","dyn_emb":[%s],"nested_dyn":{"emb":[%s]}}`, strings.Join(vals128, ","), strings.Join(vals128, ",")))
	lockedDims, newDynVecs, err := InspectAutoDimsAndDynamicVectors(baseIdx, [][]byte{dynDoc})
	if err != nil {
		t.Fatalf("InspectAutoDimsAndDynamicVectors failed: %v", err)
	}
	if lockedDims["root_bvec"] != 2 || newDynVecs["dyn_emb"] != 128 || newDynVecs["nested_dyn.emb"] != 128 {
		t.Fatalf("unexpected inspected dims: locked=%+v dyn=%+v", lockedDims, newDynVecs)
	}
	cloned, newBindings := baseIdx.CloneWithAutoDimsAndDynamicVectors(lockedDims, newDynVecs)
	if len(newBindings) != 2 {
		t.Fatalf("expected 2 newly added dynamic vector bindings (not already-created root_bvec), got %+v", newBindings)
	}
	addDDLs := GenerateAddColumnsDDL(cloned, newBindings)
	if len(addDDLs) != 2 || !strings.Contains(addDDLs[0], "`es-prod`.`r62_nested_vec` ADD COLUMN `f__dyn_emb` ARRAY<FLOAT> NULL;") {
		t.Fatalf("unexpected GenerateAddColumnsDDL: %+v", addDDLs)
	}

	// Intra-batch dynamic vector dimension mismatch & zero-magnitude rejection
	vals130 := make([]string, 130)
	for i := range vals130 {
		vals130[i] = "0.5"
	}
	mismatchDoc := []byte(fmt.Sprintf(`{"dyn_emb":[%s]}`, strings.Join(vals130, ",")))
	if _, _, err := InspectAutoDimsAndDynamicVectors(baseIdx, [][]byte{dynDoc, mismatchDoc}); err == nil {
		t.Fatal("expected intra-batch dynamic vector dimension mismatch error")
	}
	zero128 := make([]string, 128)
	for i := range zero128 {
		zero128[i] = "0.0"
	}
	if _, _, err := InspectAutoDimsAndDynamicVectors(baseIdx, [][]byte{[]byte(fmt.Sprintf(`{"z":[%s]}`, strings.Join(zero128, ",")))}); err == nil || !strings.Contains(err.Error(), "Zero-magnitude") {
		t.Fatalf("expected zero-magnitude dynamic vector error, got %v", err)
	}
}

func TestRound62_P1_DorisDBUnificationAndBacktickEscaping(t *testing.T) {
	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"msg":{"type":"text"}}}`), &spec)

	idxHyphen := CompileIndexSchema("es-prod", "my-idx", &spec)
	if idxHyphen.DorisDB != "es-prod" {
		t.Fatalf("expected DorisDB preserved as 'es-prod', got %q", idxHyphen.DorisDB)
	}
	createDDL := GenerateCreateTableDDL(idxHyphen)
	if !strings.Contains(createDDL, "CREATE TABLE IF NOT EXISTS `es-prod`.`my__idx`") {
		t.Fatalf("expected unmangled `es-prod` in CREATE TABLE DDL, got:\n%s", createDDL)
	}

	idxEmpty := CompileIndexSchema("   ", "t1", nil)
	if idxEmpty.DorisDB != "default" {
		t.Fatalf("expected empty dorisDB to default to 'default', got %q", idxEmpty.DorisDB)
	}

	idxTick := CompileIndexSchema("db`tick", "t1", &spec)
	tickCreate := GenerateCreateTableDDL(idxTick)
	if !strings.Contains(tickCreate, "`db``tick`.`t1`") {
		t.Fatalf("expected backtick escaping in CREATE TABLE DDL, got:\n%s", tickCreate)
	}
	var spec2 esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"msg":{"type":"text"},"extra":{"type":"keyword"}}}`), &spec2)
	idxTick2 := CompileIndexSchema("db`tick", "t1", &spec2)
	alterDDLs := GenerateAlterTableDDL(idxTick, idxTick2)
	if len(alterDDLs) == 0 || !strings.Contains(alterDDLs[0], "ALTER TABLE `db``tick`.`t1`") {
		t.Fatalf("expected backtick escaping in ALTER TABLE DDL, got: %+v", alterDDLs)
	}
	promoDDLs := GeneratePromoteVariantFieldDDL(idxTick, "dyn_field", "keyword")
	if len(promoDDLs) == 0 || !strings.Contains(promoDDLs[0], "ALTER TABLE `db``tick`.`t1`") {
		t.Fatalf("expected backtick escaping in PromoteVariant DDL, got: %+v", promoDDLs)
	}
}

func TestRound62_F15_TSDBExactUpstreamHashesAndNativeTSIDColumn(t *testing.T) {
	// 1. Verify all exact test vectors from upstream ES `tsdb/25_id_generation.yml`
	var spec25 esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"metricset": {"type": "keyword", "time_series_dimension": true},
			"k8s": {
				"properties": {
					"pod": {
						"properties": {
							"uid": {"type": "keyword", "time_series_dimension": true},
							"name": {"type": "keyword"},
							"ip": {"type": "ip"}
						}
					}
				}
			}
		}
	}`), &spec25); err != nil {
		t.Fatal(err)
	}
	idx25 := CompileIndexSchema("es_db", "id_generation_test", &spec25)
	idx25.IndexMode = "time_series"
	idx25.RoutingPath = []string{"metricset", "k8s.pod.uid"}
	idx25.TimeSeriesStartTime = "2021-04-28T00:00:00Z"
	idx25.TimeSeriesEndTime = "2021-04-29T00:00:00Z"
	ApplyIndexModeDefaults(idx25)

	// Check native `__tsid` & `__tsid_key` DDL and `_tsid` field binding
	tsDDL := GenerateCreateTableDDL(idx25)
	if !strings.Contains(tsDDL, "`__tsid` VARCHAR(512) NULL") || !strings.Contains(tsDDL, "`__tsid_key` STRING NULL") || !strings.Contains(tsDDL, "INDEX `idx___tsid` (`__tsid`) USING INVERTED") {
		t.Fatalf("expected native __tsid and __tsid_key in TSDB DDL, got:\n%s", tsDDL)
	}
	tsidB := idx25.ResolveField("_tsid")
	if tsidB.ColumnName != "__tsid" || tsidB.Kind != StoragePromotedScalar || !tsidB.NotIndexed {
		t.Fatalf("unexpected _tsid FieldBinding: %+v", tsidB)
	}

	cases25 := []struct {
		ts        string
		uid       string
		wantID    string
		wantRHash string
		wantTSID  string
	}{
		{"2021-04-28T18:50:03.142Z", "df3145b3-0563-4d3b-a0f7-897eb2876ea9", "cn4excfoxSs_KdA5AAABeRnRFAY", "cn4exQ", "KCjEJ9R_BgO8TRX2QOd6dpQ5ihHD--qoyLTiOy0pmP6_RAIE-e0-dKQ"},
		{"2021-04-28T18:50:04.467Z", "947e4ced-1786-4e53-9e0c-5c447e959507", "cZZNs7B9sSWsyrL5AAABeRnRGTM", "cZZNsw", ""},
		{"2021-04-28T18:50:23.142Z", "df3145b3-0563-4d3b-a0f7-897eb2876ea9", "cn4excfoxSs_KdA5AAABeRnRYiY", "cn4exQ", "KCjEJ9R_BgO8TRX2QOd6dpQ5ihHD--qoyLTiOy0pmP6_RAIE-e0-dKQ"},
		{"2021-04-28T18:50:24.467Z", "947e4ced-1786-4e53-9e0c-5c447e959507", "cZZNs7B9sSWsyrL5AAABeRnRZ1M", "cZZNsw", ""},
		{"2021-04-28T18:50:44.467Z", "947e4ced-1786-4e53-9e0c-5c447e959507", "cZZNs7B9sSWsyrL5AAABeRnRtXM", "cZZNsw", ""},
		{"2021-04-28T18:50:53.142Z", "df3145b3-0563-4d3b-a0f7-897eb2876ea9", "cn4excfoxSs_KdA5AAABeRnR11Y", "cn4exQ", "KCjEJ9R_BgO8TRX2QOd6dpQ5ihHD--qoyLTiOy0pmP6_RAIE-e0-dKQ"},
		{"2021-04-28T18:51:03.142Z", "df3145b3-0563-4d3b-a0f7-897eb2876ea9", "cn4excfoxSs_KdA5AAABeRnR_mY", "cn4exQ", "KCjEJ9R_BgO8TRX2QOd6dpQ5ihHD--qoyLTiOy0pmP6_RAIE-e0-dKQ"},
		{"2021-04-28T18:51:04.467Z", "947e4ced-1786-4e53-9e0c-5c447e959507", "cZZNs7B9sSWsyrL5AAABeRnSA5M", "cZZNsw", ""},
		{"2021-04-28T18:52:04.467Z", "947e4ced-1786-4e53-9e0c-5c447e959507", "cZZNs7B9sSWsyrL5AAABeRnS7fM", "cZZNsw", ""},
	}
	for _, tc := range cases25 {
		docJSON := fmt.Sprintf(`{"@timestamp":%q,"metricset":"pod","k8s":{"pod":{"uid":%q,"name":"cat"}}}`, tc.ts, tc.uid)
		var doc map[string]any
		_ = json.Unmarshal([]byte(docJSON), &doc)
		tsid, docID, _, rHash, err := ComputeTSDBIdentityWithRoutingHash(idx25, doc, nil)
		if err != nil {
			t.Fatalf("ComputeTSDBIdentityWithRoutingHash(%s) failed: %v", tc.ts, err)
		}
		if docID != tc.wantID {
			t.Fatalf("for ts=%s uid=%s expected _id=%s, got %s", tc.ts, tc.uid, tc.wantID, docID)
		}
		if rHash != tc.wantRHash {
			t.Fatalf("for ts=%s uid=%s expected _ts_routing_hash=%s, got %s", tc.ts, tc.uid, tc.wantRHash, rHash)
		}
		if tc.wantTSID != "" && tsid != tc.wantTSID {
			t.Fatalf("expected _tsid=%s, got %s", tc.wantTSID, tsid)
		}

		// Verify ShredDocument populates __tsid and __tsid_key identically
		shredBytes, err := ShredDocument(idx25, docID, 1, false, []byte(docJSON))
		if err != nil {
			t.Fatalf("ShredDocument TSDB failed: %v", err)
		}
		var row map[string]any
		_ = json.Unmarshal(shredBytes, &row)
		if row["__tsid"] != tsid {
			t.Fatalf("expected row[__tsid]=%q, got %#v", tsid, row["__tsid"])
		}
		var keyMap map[string]any
		if err := json.Unmarshal([]byte(row["__tsid_key"].(string)), &keyMap); err != nil {
			t.Fatalf("invalid __tsid_key JSON: %v", err)
		}
		if keyMap["metricset"] != "pod" || keyMap["k8s.pod.uid"] != tc.uid {
			t.Fatalf("unexpected __tsid_key map: %+v", keyMap)
		}
	}

	// 2. Deep `dim.**.uid` and `dim.*.uid` test vectors from `25_id_generation.yml:386-461`
	for _, deepTC := range []struct {
		mappingJSON string
		routingGlob string
		docJSON     string
		wantID      string
	}{
		{
			`{"properties":{"@timestamp":{"type":"date"},"dim":{"properties":{"foo":{"properties":{"bar":{"properties":{"baz":{"properties":{"uid":{"type":"keyword","time_series_dimension":true}}}}}}}}}}}`,
			"dim.**.uid",
			`{"@timestamp":"2021-04-28T18:50:04.467Z","dim":{"foo":{"bar":{"baz":{"uid":"uid1"}}}}}`,
			"OcEOGchJrjH1fFX8AAABeRnRGTM",
		},
		{
			`{"properties":{"@timestamp":{"type":"date"},"dim":{"properties":{"foo":{"properties":{"uid":{"type":"keyword","time_series_dimension":true}}}}}}}`,
			"dim.*.uid",
			`{"@timestamp":"2021-04-28T18:50:04.467Z","dim":{"foo":{"uid":"uid1"}}}`,
			"8bgiqW9JKwAyp1bZAAABeRnRGTM",
		},
	} {
		var sp esast.MappingSpec
		_ = json.Unmarshal([]byte(deepTC.mappingJSON), &sp)
		idx := CompileIndexSchema("es_db", "rp_test", &sp)
		idx.IndexMode = "time_series"
		idx.RoutingPath = []string{deepTC.routingGlob}
		var doc map[string]any
		_ = json.Unmarshal([]byte(deepTC.docJSON), &doc)
		_, gotID, _, _, err := ComputeTSDBIdentityWithRoutingHash(idx, doc, nil)
		if err != nil || gotID != deepTC.wantID {
			t.Fatalf("expected _id=%s, got %s (err=%v)", deepTC.wantID, gotID, err)
		}
	}

	// 3. Flattened + keyword + numeric dimension `_tsid` vectors from `70_dimension_types.yml`
	var flatSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"uid": {"type": "keyword", "time_series_dimension": true},
			"deployment": {
				"type": "flattened",
				"time_series_dimensions": ["build.branch", "build.tag", "version.major"]
			}
		}
	}`), &flatSpec)
	flatIdx := CompileIndexSchema("es_db", "ts_flat", &flatSpec)
	flatIdx.IndexMode = "time_series"
	flatIdx.RoutingPath = []string{"uid", "deployment.build.tag"}

	for _, ftc := range []struct {
		docJSON  string
		wantTSID string
	}{
		{
			`{"@timestamp":"2021-04-28T18:35:34.467Z","uid":"df3145b3-0563-4d3b-a0f7-897eb2876ea9","deployment":{"build":{"sha":"16w3xaca09","branch":"release-8.8"},"region":"eu-west-2","version":{"major":8,"minor":8,"patch":1}}}`,
			"LPBzSKpPysYDR-l1jvYA8jPxTXebeRDHRzmKEcOUW9u_kzgC7pSzoi1utVcm",
		},
		{
			`{"@timestamp":"2021-04-28T18:35:44.467Z","uid":"947e4ced-1786-4e53-9e0c-5c447e959507","deployment":{"build":{"tag":"1516op6885","branch":"release-8.8"},"region":"eu-west-1","version":{"major":8,"minor":8,"patch":0}}}`,
			"MF1xFkQfNVXn4EbbAW53ge_xTXebKGmdvXkQx0d12oDh16FtfvP_ObklCa7gXDcmdA",
		},
	} {
		var d map[string]any
		dec := json.NewDecoder(strings.NewReader(ftc.docJSON))
		dec.UseNumber()
		_ = dec.Decode(&d)
		gotTSID, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(flatIdx, d, nil)
		if err != nil || gotTSID != ftc.wantTSID {
			t.Fatalf("expected flattened _tsid=%s, got %s (err=%v)", ftc.wantTSID, gotTSID, err)
		}
	}

	// Typed integer, unsigned_long, boolean, ip dimensions
	var typedDimSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"port": {"type": "integer", "time_series_dimension": true},
			"seq": {"type": "unsigned_long", "time_series_dimension": true},
			"ok": {"type": "boolean", "time_series_dimension": true},
			"addr": {"type": "ip", "time_series_dimension": true}
		}
	}`), &typedDimSpec)
	typedIdx := CompileIndexSchema("es_db", "ts_typed", &typedDimSpec)
	typedIdx.IndexMode = "time_series"
	var typedDoc map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"@timestamp":"2021-04-28T18:50:04.467Z","port":8080,"seq":42,"ok":true,"addr":"::ffff:10.0.0.1"}`))
	dec.UseNumber()
	_ = dec.Decode(&typedDoc)
	tsidT, docIDT, _, _, err := ComputeTSDBIdentityWithRoutingHash(typedIdx, typedDoc, nil)
	if err != nil || tsidT == "" || len(docIDT) != 27 {
		t.Fatalf("typed TSDB identity failed: tsid=%q id=%q err=%v", tsidT, docIDT, err)
	}
	keyMap, err := ExtractTSDBDimensionKeyMap(typedIdx, typedDoc)
	if err != nil || keyMap["port"] != int64(8080) || keyMap["ok"] != true || keyMap["addr"] != "10.0.0.1" {
		t.Fatalf("unexpected typed keyMap: %+v (err=%v)", keyMap, err)
	}
}

func TestRound62_F7_SyntheticSourceSubobjectsFalseAndLogsDB(t *testing.T) {
	// 1. Allow token_count, rank_feature, rank_features, percolator, search_as_you_type, sparse_vector, completion under synthetic _source
	var allowedSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"tc": {"type": "token_count", "analyzer": "standard"},
			"rf": {"type": "rank_feature", "null_value": 1.5},
			"rfs": {"type": "rank_features"},
			"pq": {"type": "percolator"},
			"sayt": {"type": "search_as_you_type"},
			"sv": {"type": "sparse_vector"},
			"comp": {"type": "completion"}
		}
	}`), &allowedSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&allowedSpec); err != nil {
		t.Fatalf("expected synthetic _source to allow extra field types, got %v", err)
	}

	// 2. ValidateMappingUpdateCompatibility: stored -> synthetic allowed; synthetic -> stored rejected
	var storedSpec, synthSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source":{"mode":"stored"},"properties":{"k":{"type":"keyword"}}}`), &storedSpec)
	_ = json.Unmarshal([]byte(`{"_source":{"mode":"synthetic"},"properties":{"k":{"type":"keyword"}}}`), &synthSpec)
	if err := ValidateMappingUpdateCompatibility(&storedSpec, &synthSpec); err != nil {
		t.Fatalf("expected stored -> synthetic update to succeed, got %v", err)
	}
	errRev := ValidateMappingUpdateCompatibility(&synthSpec, &storedSpec)
	if errRev == nil || !strings.Contains(errRev.Error(), "Cannot update parameter [mode] from [synthetic] to [stored]") {
		t.Fatalf("expected synthetic -> stored update rejection, got %v", errRev)
	}

	// 3. Object array flattening vs store_array_source:true / nested / unmapped / enabled:false retention (`20_synthetic_source.yml`)
	var objArrSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"dynamic": false,
		"properties": {
			"spans": {
				"properties": {
					"trace": {"properties": {"id": {"type": "keyword"}}},
					"span": {"properties": {"id": {"type": "keyword"}}}
				}
			},
			"preserved_objs": {
				"store_array_source": true,
				"properties": {
					"v": {"type": "long"}
				}
			},
			"dis": {"type": "object", "enabled": false}
		}
	}`), &objArrSpec); err != nil {
		t.Fatal(err)
	}
	objArrIdx := CompileIndexSchema("es_db", "r62_synth_arr", &objArrSpec)
	shredArr, err := ShredDocument(objArrIdx, "1", 1, false, []byte(`{
		"spans": [
			{"trace": {"id": "b"}, "span": {"id": "1"}},
			{"trace": {"id": "a"}, "span": {"id": "1"}}
		],
		"preserved_objs": [{"v": 20}, {"v": 10}],
		"dis": [{"x": 1}, {"x": 2}],
		"unmapped_arr": [{"n": 5, "f": 1.25}]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var rowArr map[string]any
	_ = json.Unmarshal(shredArr, &rowArr)
	var gotSynth map[string]any
	dec := json.NewDecoder(strings.NewReader(rowArr["_source"].(string)))
	dec.UseNumber()
	_ = dec.Decode(&gotSynth)

	spansMap, ok := gotSynth["spans"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapped object array 'spans' flattened to object, got %#v", gotSynth["spans"])
	}
	traceMap, _ := spansMap["trace"].(map[string]any)
	spanMap, _ := spansMap["span"].(map[string]any)
	if !reflect.DeepEqual(traceMap["id"], []any{"a", "b"}) || !reflect.DeepEqual(spanMap["id"], []any{"1", "1"}) {
		t.Fatalf("unexpected flattened spans: %#v", spansMap)
	}
	presSlice, ok := gotSynth["preserved_objs"].([]any)
	if !ok || len(presSlice) != 2 {
		t.Fatalf("expected store_array_source:true to preserve array of objects, got %#v", gotSynth["preserved_objs"])
	}
	if _, ok := gotSynth["dis"].([]any); !ok {
		t.Fatalf("expected enabled:false 'dis' array retained, got %#v", gotSynth["dis"])
	}
	if _, ok := gotSynth["unmapped_arr"].([]any); !ok {
		t.Fatalf("expected dynamic:false 'unmapped_arr' retained, got %#v", gotSynth["unmapped_arr"])
	}

	// Root enabled: false synthetic source retains full document
	var rootDisabledSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"enabled":false,"_source":{"mode":"synthetic"}}`), &rootDisabledSpec)
	rootDisIdx := CompileIndexSchema("es_db", "r62_root_dis", &rootDisabledSpec)
	shredRootDis, err := ShredDocument(rootDisIdx, "1", 1, false, []byte(`{"a.b": 42, "arr": [3, 1]}`))
	if err != nil {
		t.Fatal(err)
	}
	var rowRD map[string]any
	_ = json.Unmarshal(shredRootDis, &rowRD)
	if !strings.Contains(rowRD["_source"].(string), `"a":{"b":42}`) {
		t.Fatalf("expected root enabled:false synthetic _source to retain expanded doc, got %s", rowRD["_source"])
	}

	// 4. `91_metrics_no_subobjects.yml`: dynamic_templates `subobjects: false` + synthetic `_source`
	var tmplSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"dynamic_templates": [
			{
				"no_subobjects": {
					"match": "metrics",
					"mapping": {
						"type": "object",
						"subobjects": false,
						"properties": {
							"host.name": {"type": "keyword"}
						}
					}
				}
			}
		]
	}`), &tmplSpec); err != nil {
		t.Fatal(err)
	}
	metricsDoc := json.RawMessage(`{"metrics.host.name":"localhost","metrics.host.id":1,"metrics.time":10,"metrics.time.max":100,"metrics.time.min":1}`)
	inferred := InferMappingFromSampleDocsES8([]json.RawMessage{metricsDoc}, &tmplSpec)
	metricsProp := inferred.Properties["metrics"]
	if metricsProp.Subobjects == nil || *metricsProp.Subobjects {
		t.Fatalf("expected metrics.Subobjects=false, got %+v", metricsProp)
	}
	for _, leaf := range []string{"host.name", "host.id", "time", "time.max", "time.min"} {
		if _, exists := metricsProp.Properties[leaf]; !exists {
			t.Fatalf("expected literal dotted leaf %q in metrics.Properties, got %+v", leaf, metricsProp.Properties)
		}
	}
	metricsIdx := CompileIndexSchema("es_db", "r62_metrics_nosub", inferred)
	shredMetrics, err := ShredDocument(metricsIdx, "1", 1, false, metricsDoc)
	if err != nil {
		t.Fatalf("ShredDocument metrics_no_subobjects failed: %v", err)
	}
	var rowMetrics map[string]any
	_ = json.Unmarshal(shredMetrics, &rowMetrics)
	var gotMetricsSrc map[string]any
	_ = json.Unmarshal([]byte(rowMetrics["_source"].(string)), &gotMetricsSrc)
	mObj, ok := gotMetricsSrc["metrics"].(map[string]any)
	if !ok || mObj["host.name"] != "localhost" || mObj["time"] != float64(10) || mObj["time.max"] != float64(100) || mObj["time.min"] != float64(1) {
		t.Fatalf("unexpected synthetic _source for metrics_no_subobjects: %#v", gotMetricsSrc)
	}

	// 5. `logsdb/10_settings.yml`: logsdb defaults & rejecting TSDB settings on non-time_series mode
	logsIdx := CompileIndexSchema("es_db", "logs_idx", nil)
	logsIdx.IndexMode = "logsdb"
	ApplyIndexModeDefaults(logsIdx)
	if !logsIdx.SyntheticSource || logsIdx.SourceMode != "synthetic" {
		t.Fatalf("expected logsdb to default to synthetic _source, got %+v", logsIdx)
	}
	if wantSort := []string{"host.name", "@timestamp"}; !reflect.DeepEqual(LogsDBDefaultSortFields(), wantSort) {
		t.Fatalf("unexpected LogsDBDefaultSortFields: %+v", LogsDBDefaultSortFields())
	}
	for _, badSettings := range []map[string]any{
		{"index.mode": "logsdb", "index.routing_path": "host"},
		{"index.mode": "logsdb", "index.time_series.start_time": "2021-01-01T00:00:00Z"},
		{"index.mode": "logsdb", "index.time_series.end_time": "2021-01-02T00:00:00Z"},
		{"index.mode": "invalid_mode"},
	} {
		if _, _, _, _, err := ExtractTSDBSettings(badSettings); err == nil {
			t.Fatalf("expected ExtractTSDBSettings error for %+v", badSettings)
		}
	}
}

func TestRound62_ScriptHook_Ignored_SAYT_SparseVector_DateNanos_DynamicTemplates(t *testing.T) {
	// 1. SerializeFieldProperty normalizes string script & preserves include_in_parent/root & on_script_error
	var scriptSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"runtime": {
			"comp": {
				"type": "composite",
				"script": "emit(Map.of('a', 'x'))",
				"on_script_error": "continue",
				"fields": {"a": {"type": "keyword"}}
			}
		},
		"properties": {
			"price": {"type": "long"},
			"doubled": {"type": "long", "script": "emit(doc['price'].value * 2)", "on_script_error": "fail"},
			"safe_calc": {"type": "keyword", "script": "emit('bad')", "on_script_error": "continue"},
			"nest": {
				"type": "nested",
				"include_in_parent": true,
				"include_in_root": true,
				"properties": {
					"unidx": {"type": "keyword", "index": false}
				}
			}
		}
	}`), &scriptSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&scriptSpec); err != nil {
		t.Fatalf("valid script/composite mapping failed: %v", err)
	}
	serMap := SerializeMappingSpec(&scriptSpec)
	propsOut := serMap["properties"].(map[string]any)
	doubledOut := propsOut["doubled"].(map[string]any)
	scriptObj, ok := doubledOut["script"].(map[string]any)
	if !ok || scriptObj["lang"] != "painless" || scriptObj["source"] != "emit(doc['price'].value * 2)" || doubledOut["on_script_error"] != "fail" {
		t.Fatalf("expected normalized script object in serialized mapping, got %#v", doubledOut)
	}
	nestOut := propsOut["nest"].(map[string]any)
	if nestOut["include_in_parent"] != true || nestOut["include_in_root"] != true {
		t.Fatalf("expected include_in_parent/root in serialized mapping, got %#v", nestOut)
	}

	// Verify nested NotIndexed survives DeepMergeMappingProperties & CompileIndexSchema
	mergedProps := DeepMergeMappingProperties(nil, scriptSpec.Properties)
	scriptIdx := CompileIndexSchema("es_db", "r62_script", &esast.MappingSpec{Properties: mergedProps})
	if !scriptIdx.ResolveField("nest.unidx").NotIndexed {
		t.Fatalf("expected nested subfield nest.unidx to preserve NotIndexed=true, got %+v", scriptIdx.ResolveField("nest.unidx"))
	}

	// Register index-time script evaluator hook and verify emitted values shred into column while _source stays untouched!
	prevEval1 := GetIndexFieldScriptEvaluator()
	defer RegisterIndexFieldScriptEvaluator(prevEval1)
	RegisterIndexFieldScriptEvaluator(func(fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error) {
		if fieldPath == "safe_calc" {
			return nil, fmt.Errorf("simulated painless error")
		}
		if fieldPath == "doubled" {
			if n, ok := sourceDoc["price"].(json.Number); ok {
				iv, _ := n.Int64()
				return []any{iv * 2}, nil
			}
		}
		return nil, nil
	})
	rawIn := `{"price":21}`
	shredScript, err := ShredDocument(scriptIdx, "s1", 1, false, []byte(rawIn))
	if err != nil {
		t.Fatalf("ShredDocument with index-time script failed: %v", err)
	}
	var rowScript map[string]any
	_ = json.Unmarshal(shredScript, &rowScript)
	doubledArr, okDoubled := rowScript["f__doubled"].([]any)
	if !okDoubled || len(doubledArr) != 1 || doubledArr[0] != "42" {
		t.Fatalf("expected f__doubled=[\"42\"] from index-time script hook, got %#v", rowScript["f__doubled"])
	}
	if rowScript["_source"] != rawIn {
		t.Fatalf("expected verbatim _source=%q untouched by index-time script, got %q", rawIn, rowScript["_source"])
	}

	// Verify on_script_error="fail" propagates error
	RegisterIndexFieldScriptEvaluator(func(fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error) {
		if fieldPath == "doubled" {
			return nil, fmt.Errorf("boom_fail")
		}
		return nil, nil
	})
	if _, err := ShredDocument(scriptIdx, "s2", 1, false, []byte(rawIn)); err == nil || !strings.Contains(err.Error(), "boom_fail") {
		t.Fatalf("expected on_script_error=fail to propagate error, got %v", err)
	}
	RegisterIndexFieldScriptEvaluator(prevEval1)

	// 2. `_ignored` resolves to native StoragePromotedArray (`ColumnName: "_ignored"`)
	igB := scriptIdx.ResolveField("_ignored")
	if igB.Kind != StoragePromotedArray || igB.ColumnName != "_ignored" || !igB.IsMultiValued {
		t.Fatalf("expected _ignored to resolve to StoragePromotedArray('_ignored'), got %+v", igB)
	}

	// 3. `search_as_you_type` virtual subfields (`_2gram`, `_3gram`, `_4gram`, `_index_prefix`)
	var saytSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"a_field": {"type": "search_as_you_type", "analyzer": "simple", "max_shingle_size": 4}
		}
	}`), &saytSpec)
	saytIdx := CompileIndexSchema("es_db", "r62_sayt", &saytSpec)
	shredSAYT, err := ShredDocument(saytIdx, "1", 1, false, []byte(`{"a_field":"quick brown fox jump lazy dog"}`))
	if err != nil {
		t.Fatalf("ShredDocument SAYT failed: %v", err)
	}
	var rowSAYT map[string]any
	_ = json.Unmarshal(shredSAYT, &rowSAYT)
	g2, _ := rowSAYT["f__a_field___2gram"].([]any)
	g4, _ := rowSAYT["f__a_field___4gram"].([]any)
	pfx, _ := rowSAYT["f__a_field___index_prefix"].([]any)
	containsStr := func(arr []any, target string) bool {
		for _, x := range arr {
			if x == target {
				return true
			}
		}
		return false
	}
	if !containsStr(g2, "quick brown") || !containsStr(g2, "lazy dog") || !containsStr(g4, "fox jump lazy dog") {
		t.Fatalf("unexpected SAYT shingles: g2=%v g4=%v", g2, g4)
	}
	for _, wantPfx := range []string{"quick br", "jump la", "do"} {
		if !containsStr(pfx, wantPfx) {
			t.Fatalf("expected SAYT _index_prefix to contain %q, got %v", wantPfx, pfx)
		}
	}

	// 4. Multi-map `sparse_vector` & `rank_features` dot rejection
	var svSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"sv":{"type":"sparse_vector"},"rf":{"type":"rank_features"}}}`), &svSpec)
	svIdx := CompileIndexSchema("es_db", "r62_sv", &svSpec)
	shredSV, err := ShredDocument(svIdx, "1", 1, false, []byte(`{"sv":[{"a":1.0,"b":0.5},{"a":2.5,"c":-1.0}]}`))
	if err != nil {
		t.Fatalf("multi-map sparse_vector shred failed: %v", err)
	}
	var rowSV map[string]any
	_ = json.Unmarshal(shredSV, &rowSV)
	docSV, _ := rowSV["_doc"].(map[string]any)
	svMerged, _ := docSV["sv"].(map[string]any)
	if svMerged["a"] != 2.5 || svMerged["b"] != 0.5 {
		t.Fatalf("expected merged max positive float32 weights in sparse_vector, got %#v", svMerged)
	}
	if _, hasC := svMerged["c"]; hasC {
		t.Fatalf("expected non-positive token 'c' dropped from multi-map sparse_vector, got %#v", svMerged)
	}
	if _, err := ShredDocument(svIdx, "2", 1, false, []byte(`{"rf":{"qu.ux":1.0}}`)); err == nil || !strings.Contains(err.Error(), "do not support dots in feature names") {
		t.Fatalf("expected rank_features dotted key rejection, got %v", err)
	}

	// 5. `date_nanos` bounds `[1970-01-01T00:00:00Z, 2262-04-11T23:47:16.854775807Z]` (`80_date_nanos.yml`)
	var dnSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"date":{"type":"date_nanos"}}}`), &dnSpec)
	dnIdx := CompileIndexSchema("es_db", "r62_dn", &dnSpec)
	_, errPre1970 := ShredDocument(dnIdx, "1", 1, false, []byte(`{"date":"1969-10-28T12:12:12.123456789Z"}`))
	if errPre1970 == nil || !strings.Contains(errPre1970.Error(), "is before the epoch in 1970 and cannot be stored in nanosecond resolution") {
		t.Fatalf("expected pre-1970 date_nanos document_parsing_exception, got %v", errPre1970)
	}
	_, errPost2262 := ShredDocument(dnIdx, "2", 1, false, []byte(`{"date":"2263-10-29T12:12:12.123456789Z"}`))
	if errPost2262 == nil || !strings.Contains(errPost2262.Error(), "is after 2262-04-11T23:47:16.854775807 and cannot be stored in nanosecond resolution") {
		t.Fatalf("expected post-2262 date_nanos document_parsing_exception, got %v", errPost2262)
	}
	if _, ok := ParseESDateWithFormatToEpochNanos("-1", "", time.Now().UTC()); ok {
		t.Fatal("expected ParseESDateWithFormatToEpochNanos to reject negative epoch value")
	}

	// 6. `nested_objects.limit` suffix (`create/70_nested.yml`)
	scriptIdx.MaxNestedObjects = 2
	_, errLim := ShredDocument(scriptIdx, "nlim", 1, false, []byte(`{"nest":[{"unidx":"a"},{"unidx":"b"},{"unidx":"c"}]}`))
	if errLim == nil || !strings.Contains(errLim.Error(), "This limit can be set by changing the [index.mapping.nested_objects.limit] index level setting.") {
		t.Fatalf("expected nested_objects.limit suffix, got %v", errLim)
	}

	// 7. `dynamic_templates` list-valued `match`, `unmatch`, `path_match`, `path_unmatch`, `unmatch_mapping_type`
	var dtListSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic_templates": [
			{
				"list_rules": {
					"match_mapping_type": "*",
					"unmatch_mapping_type": ["boolean", "object"],
					"match": ["foo_*", "bar_*"],
					"unmatch": ["*_skip"],
					"path_match": ["root.*"],
					"path_unmatch": ["root.secret.*"],
					"mapping": {"type": "keyword"}
				}
			}
		]
	}`), &dtListSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&dtListSpec); err != nil {
		t.Fatalf("expected list-valued dynamic_templates to validate cleanly, got %v", err)
	}
	infDT := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"root":{"foo_id":123,"foo_skip":456,"flag_bool":true},"root":{"foo_id":123,"bar_ok":789,"foo_skip":456,"bar_flag":true}}`),
	}, &dtListSpec)
	rootProps := infDT.Properties["root"].Properties
	if rootProps["foo_id"].Type != "keyword" || rootProps["bar_ok"].Type != "keyword" {
		t.Fatalf("expected foo_id and bar_ok matched as keyword, got %+v", rootProps)
	}
	if rootProps["foo_skip"].Type != "long" || rootProps["bar_flag"].Type != "boolean" {
		t.Fatalf("expected foo_skip=long and bar_flag=boolean (unmatched), got %+v", rootProps)
	}
}

func TestRound62_AdditionalEdgeCasesAndDeepCloneCoverage(t *testing.T) {
	// 1. Rich CloneIndexSchema / deepCloneMappingSpec / deepCloneFieldProperty / cloneFieldBindingValue coverage
	var richSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"enabled": true,
		"subobjects": true,
		"date_detection": false,
		"numeric_detection": true,
		"dynamic_date_formats": ["yyyy/MM/dd"],
		"_routing": {"required": true},
		"_meta": {"owner": "platform"},
		"_source": {"mode": "synthetic", "includes": ["a*"], "excludes": ["a.secret"], "compress": true, "compress_threshold": "5kb"},
		"dynamic_templates": [{"dt": {"match": "dyn_*", "mapping": {"type": "keyword"}}}],
		"runtime": {
			"rt_kw": {"type": "keyword", "script": "emit('v')"}
		},
		"properties": {
			"nested_docs": {
				"type": "nested",
				"include_in_parent": true,
				"include_in_root": false,
				"properties": {
					"sub_sayt": {"type": "search_as_you_type", "analyzer": "whitespace", "max_shingle_size": 2}
				}
			},
			"rich_kw": {
				"type": "keyword",
				"index": true,
				"doc_values": true,
				"store": true,
				"store_array_source": true,
				"ignore_malformed": true,
				"coerce": false,
				"norms": false,
				"eager_global_ordinals": true,
				"copy_to": ["all_kw"],
				"meta": {"unit": "ms"},
				"fields": {
					"txt": {
						"type": "text",
						"index_phrases": true,
						"split_queries_on_whitespace": true,
						"enable_position_increments": false
					}
				}
			},
			"all_kw": {"type": "keyword"},
			"comp": {
				"type": "completion",
				"contexts": [{"name": "cat", "type": "category"}]
			},
			"flat": {"type": "flattened", "depth_limit": 10},
			"rf": {"type": "rank_feature", "positive_score_impact": false, "null_value": 1.0},
			"ts_dim": {"type": "keyword", "time_series_dimension": true},
			"ts_flat": {"type": "flattened", "time_series_dimensions": ["k1"]}
		}
	}`), &richSpec); err != nil {
		t.Fatal(err)
	}
	richIdx := CompileIndexSchema("es_db", "r62_rich", &richSpec)
	richIdx.FieldAddedAtSeqNo = map[string]int64{"rich_kw": 7}
	richIdx.RoutingPath = []string{"ts_dim"}
	clonedRich := richIdx.CloneIndexSchema()
	if clonedRich == nil || clonedRich.RawMapping == nil || clonedRich.SourceConfig == nil || clonedRich.FieldAddedAtSeqNo["rich_kw"] != 7 {
		t.Fatalf("unexpected clonedRich: %+v", clonedRich)
	}
	// CloneWithLockedAutoDims adding a dynamic vector inside a nested root + GenerateAddColumnsDDL on indexed scalar
	clonedNestedDyn, addedNested := richIdx.CloneWithLockedAutoDims(map[string]int{"nested_docs.dyn_vec": 128})
	if len(addedNested) != 1 || clonedNestedDyn.Fields["nested_docs.dyn_vec"].Kind != StorageNestedSubfield {
		t.Fatalf("expected nested dynamic vector binding, got %+v", addedNested)
	}
	ddls := GenerateAddColumnsDDL(clonedNestedDyn, []FieldBinding{clonedNestedDyn.Fields["all_kw"]})
	if len(ddls) != 2 || !strings.Contains(ddls[1], "ADD INDEX") {
		t.Fatalf("expected ADD COLUMN + ADD INDEX from GenerateAddColumnsDDL, got %+v", ddls)
	}

	// Shred nested SAYT virtual subfields
	if _, err := ShredDocument(richIdx, "ns1", 1, false, []byte(`{"nested_docs":[{"sub_sayt":"alpha beta gamma"}]}`)); err != nil {
		t.Fatalf("nested SAYT shred failed: %v", err)
	}

	// 2. Index-time script emitting multi-valued nested path (`setPathValueInMap` deep path + slice)
	var deepScriptSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"grp": {
				"properties": {
					"tags": {"type": "keyword", "script": "emit('t1'); emit('t2')"}
				}
			}
		}
	}`), &deepScriptSpec)
	deepScriptIdx := CompileIndexSchema("es_db", "r62_deep_script", &deepScriptSpec)
	prevEval2 := GetIndexFieldScriptEvaluator()
	defer RegisterIndexFieldScriptEvaluator(prevEval2)
	RegisterIndexFieldScriptEvaluator(func(fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error) {
		if fieldPath == "grp.tags" {
			return []any{"t1", "t2"}, nil
		}
		return nil, nil
	})
	if _, err := ShredDocument(deepScriptIdx, "ds1", 1, false, []byte(`{}`)); err != nil {
		t.Fatalf("deep script shred failed: %v", err)
	}
	RegisterIndexFieldScriptEvaluator(prevEval2)

	// 3. `flattenSubmapsForNoSubobjects` in `ReconstructSyntheticSource` + literal dotted doc in `ShredDocument`
	var rootNoSub esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"subobjects":false,"_source":{"mode":"synthetic"},"properties":{"a.b":{"type":"long"}}}`), &rootNoSub)
	noSubIdx := CompileIndexSchema("es_db", "r62_nosub", &rootNoSub)
	if _, err := ShredDocument(noSubIdx, "1", 1, false, []byte(`{"a.b":99,"a.c.d":"str"}`)); err != nil {
		t.Fatal(err)
	}
	synthNoSub := ReconstructSyntheticSource(noSubIdx, map[string]any{
		"a": map[string]any{"b": json.Number("99"), "c": map[string]any{"d": "str"}},
	}, nil)
	if synthNoSub["a.b"] != int64(99) || synthNoSub["a.c.d"] != "str" {
		t.Fatalf("expected flattened dotted keys under subobjects:false, got %#v", synthNoSub)
	}

	// Nil receiver / error-branch coverage for CloneWithLockedAutoDims, BindTSDBFields, ValidateIndexModeSettings, parseDynamicTemplatePatternList
	var nilIdx *IndexSchema
	if c, b := nilIdx.CloneWithLockedAutoDims(map[string]int{"v": 4}); c != nil || b != nil {
		t.Fatal("expected nil CloneWithLockedAutoDims on nil receiver")
	}
	if c, b := nilIdx.CloneWithAutoDimsAndDynamicVectors(nil, nil); c != nil || b != nil {
		t.Fatal("expected nil CloneWithAutoDimsAndDynamicVectors on nil receiver")
	}
	nilIdx.BindTSDBFields()
	if c, b := noSubIdx.CloneWithLockedAutoDims(map[string]int{"dyn.vec": 128}); c == nil || len(b) != 1 || c.Fields["dyn.vec"].VectorDims != 128 {
		t.Fatalf("expected subobjects:false dynamic vector clone, got %+v", b)
	}
	for _, badPat := range []any{123, []any{123}, "["} {
		if _, err := parseDynamicTemplatePatternList(badPat, "t1", "match", true); err == nil {
			t.Fatalf("expected error for invalid dynamic template pattern %#v", badPat)
		}
	}
	for _, badDim := range []struct {
		t string
		v any
	}{
		{"long", "not_int"},
		{"unsigned_long", "-1"},
		{"ip", "not_ip"},
		{"boolean", "not_bool"},
		{"date", "not_date"},
		{"keyword", []any{"a", "b"}},
		{"keyword", map[string]any{"a": 1}},
	} {
		if _, err := parseTSDBTypedDimensionScalar("dim", FieldBinding{ESType: badDim.t}, badDim.v); err == nil {
			t.Fatalf("expected parseTSDBTypedDimensionScalar error for type=%s val=%#v", badDim.t, badDim.v)
		}
	}

	// 4. TSDB typed dimensions: constant_keyword default, date dimension, string int/bool, large unsigned_long, emoji (>0xffff UTF-16 surrogate), >128 dims VInt
	var tsExtraSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"ck": {"type": "constant_keyword", "value": "const_v", "time_series_dimension": true},
			"dt_dim": {"type": "date", "time_series_dimension": true},
			"i_dim": {"type": "long", "time_series_dimension": true},
			"u_dim": {"type": "unsigned_long", "time_series_dimension": true},
			"b_dim": {"type": "boolean", "time_series_dimension": true},
			"emoji_🚀": {"type": "keyword", "time_series_dimension": true}
		}
	}`), &tsExtraSpec)
	tsExtraIdx := CompileIndexSchema("es_db", "ts_extra", &tsExtraSpec)
	tsExtraIdx.IndexMode = "time_series"
	var tsExtraDoc map[string]any
	_ = json.Unmarshal([]byte(`{
		"@timestamp": "2021-04-28T18:50:04.467Z",
		"dt_dim": "2021-04-28T00:00:00Z",
		"i_dim": "123",
		"u_dim": "18446744073709551615",
		"b_dim": "false",
		"emoji_🚀": ["rocket"]
	}`), &tsExtraDoc)
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(tsExtraIdx, tsExtraDoc, nil); err != nil {
		t.Fatalf("ComputeTSDBIdentityWithRoutingHash extra types failed: %v", err)
	}
	if vInt := appendLuceneVInt(nil, 300); len(vInt) != 2 {
		t.Fatalf("expected 2-byte Lucene VInt for 300, got %v", vInt)
	}

	// 5. `diagnoseDateNanosOutOfRangeError` on negative epoch integer & custom format
	var customDNSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"d":{"type":"date_nanos","format":"yyyy/MM/dd||epoch_nanos"}}}`), &customDNSpec)
	customDNIdx := CompileIndexSchema("es_db", "r62_custom_dn", &customDNSpec)
	if _, err := ShredDocument(customDNIdx, "1", 1, false, []byte(`{"d":-50}`)); err == nil || !strings.Contains(err.Error(), "before the epoch in 1970") {
		t.Fatalf("expected negative epoch_nanos pre-1970 error, got %v", err)
	}
	if _, err := ShredDocument(customDNIdx, "2", 1, false, []byte(`{"d":"1965/05/01"}`)); err == nil || !strings.Contains(err.Error(), "before the epoch in 1970") {
		t.Fatalf("expected custom format pre-1970 error, got %v", err)
	}

	// 6. `validateAutoDimsVectorBinding` errors (>4096, odd int4_hnsw, non-8 bit) & `parseDynamicTemplatePatternList`([]string)
	if err := validateAutoDimsVectorBinding(FieldBinding{ESFieldPath: "v", VectorElementType: "float"}, 5000); err == nil {
		t.Fatal("expected >4096 dims error")
	}
	if err := validateAutoDimsVectorBinding(FieldBinding{ESFieldPath: "v", VectorElementType: "bit"}, 10); err == nil {
		t.Fatal("expected bit dims % 8 != 0 error")
	}
	if err := validateAutoDimsVectorBinding(FieldBinding{ESFieldPath: "v", VectorIndexOptions: map[string]any{"type": "int4_hnsw"}}, 3); err == nil {
		t.Fatal("expected odd dims error on int4_hnsw")
	}
	if pats, err := parseDynamicTemplatePatternList([]string{"^a.*"}, "t1", "match", true); err != nil || len(pats) != 1 {
		t.Fatalf("unexpected []string pattern list result: %v, %v", pats, err)
	}
	if has, ok := matchesAnyDynamicTemplatePattern([]string{"foo_*", "bar_*"}, "bar_1", ""); !has || !ok {
		t.Fatal("expected []string matchesAnyDynamicTemplatePattern match")
	}
}
