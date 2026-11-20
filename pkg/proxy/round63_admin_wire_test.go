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
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound63TestServer(t *testing.T) *Server {
	t.Helper()
	backend := NewMemoryBackend(false)
	srv := NewServer("es_db", backend, transpiler.TranspilerOptions{})
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv
}

func doRound63Req(t *testing.T, h http.Handler, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, bodyReader)
	if body != nil && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRound63AnalyzeCyclicAliasStackOverflowGuard(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	// Seed an index whose RawMapping has a cyclic field alias `a -> b -> a` and a valid alias `good_alias -> kw_target`.
	srv.mu.Lock()
	srv.indices["cyc_idx"] = &schema.IndexSchema{
		IndexName:  "cyc_idx",
		DorisTable: "cyc_idx",
		Fields:     map[string]schema.FieldBinding{},
		RawMapping: &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"a":          {Type: "alias", Path: "b"},
				"b":          {Type: "alias", Path: "a"},
				"kw_target":  {Type: "keyword"},
				"good_alias": {Type: "alias", Path: "kw_target"},
			},
		},
	}
	srv.mu.Unlock()

	rec := doRound63Req(t, h, http.MethodPost, "/cyc_idx/_analyze", []byte(`{"field":"a","text":"hello world"}`), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 on cyclic alias analyze, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Cycle detected in field alias") {
		t.Fatalf("expected cycle error reason, got: %s", rec.Body.String())
	}

	// Direct helper fallback must also never stack-overflow.
	an, norm := srv.resolveAnalyzeFieldTargetR62Admin(context.Background(), "cyc_idx", "a", nil)
	if an != "standard" || norm != "" {
		t.Fatalf("expected fallback (standard, \"\"), got (%q, %q)", an, norm)
	}

	recOK := doRound63Req(t, h, http.MethodPost, "/cyc_idx/_analyze", []byte(`{"field":"good_alias","text":"Hello World"}`), nil)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on valid alias analyze, got %d: %s", recOK.Code, recOK.Body.String())
	}
}

func TestRound63ConcurrentClusterStatsNodesHttpAndMaxBodyBytesRace(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	recCreate := doRound63Req(t, h, http.MethodPut, "/race_idx", []byte(`{
		"mappings": {
			"properties": {
				"vec_dyn": {"type": "dense_vector"},
				"vec_3":   {"type": "dense_vector", "dims": 3, "index": true, "similarity": "cosine"},
				"sv":      {"type": "sparse_vector"}
			}
		}
	}`), nil)
	if recCreate.Code != http.StatusOK {
		t.Fatalf("create race_idx failed (%d): %s", recCreate.Code, recCreate.Body.String())
	}
	doRound63Req(t, h, http.MethodPut, "/race_idx/_doc/1?refresh=true", []byte(`{"vec_3":[1,2,3],"sv":{"tok":1.5}}`), nil)
	doRound63Req(t, h, http.MethodPut, "/_snapshot/race_repo", []byte(`{"type":"fs","settings":{"location":"loc"}}`), nil)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				switch id {
				case 0:
					srv.SetMaxRequestBodyBytes(int64(10*1024*1024 + i*1024))
					field := fmt.Sprintf("f_%d", i)
					doRound63Req(t, h, http.MethodPut, "/race_idx/_mapping",
						[]byte(fmt.Sprintf(`{"properties":{%q:{"type":"keyword"}}}`, field)), nil)
				case 1:
					r := doRound63Req(t, h, http.MethodGet, "/_cluster/stats?human=true", nil, nil)
					if r.Code != http.StatusOK {
						t.Errorf("cluster.stats returned %d", r.Code)
					}
				case 2:
					r := doRound63Req(t, h, http.MethodGet, "/_nodes/_local/http,jvm,plugins", nil, map[string]string{"Host": "es.internal"})
					if r.Code != http.StatusOK {
						t.Errorf("nodes.info returned %d", r.Code)
					}
				case 3:
					r := doRound63Req(t, h, http.MethodGet, "/_nodes/usage", nil, nil)
					if r.Code != http.StatusOK {
						t.Errorf("nodes.usage returned %d", r.Code)
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestRound63WireDecompressionGzipDeflateEmptyBodyAndBombs(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	doRound63Req(t, h, http.MethodPut, "/wire_idx", []byte(`{"mappings":{"properties":{"msg":{"type":"text"}}}}`), nil)

	// 1. Empty 0-byte body with Content-Encoding: gzip and deflate must succeed (not 400 EOF).
	for _, enc := range []string{"gzip", "x-gzip", "deflate", "identity", "gzip, identity"} {
		rec := doRound63Req(t, h, http.MethodPost, "/wire_idx/_refresh", []byte{}, map[string]string{
			"Content-Encoding": enc,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("empty body with Content-Encoding=%q failed (%d): %s", enc, rec.Code, rec.Body.String())
		}
	}

	// 2. Valid zlib-wrapped deflate request body
	var zBuf bytes.Buffer
	zw := zlib.NewWriter(&zBuf)
	_, _ = zw.Write([]byte(`{"msg":"from zlib deflate"}`))
	_ = zw.Close()
	recZlib := doRound63Req(t, h, http.MethodPost, "/wire_idx/_doc/z1?refresh=true", zBuf.Bytes(), map[string]string{
		"Content-Encoding": "deflate",
		"Content-Type":     "application/json",
	})
	if recZlib.Code != http.StatusCreated && recZlib.Code != http.StatusOK {
		t.Fatalf("zlib deflate write failed (%d): %s", recZlib.Code, recZlib.Body.String())
	}

	// 3. Valid raw RFC 1951 flate request body
	var fBuf bytes.Buffer
	fw, _ := flate.NewWriter(&fBuf, flate.BestSpeed)
	_, _ = fw.Write([]byte(`{"msg":"from raw flate"}`))
	_ = fw.Close()
	recFlate := doRound63Req(t, h, http.MethodPost, "/wire_idx/_doc/f1?refresh=true", fBuf.Bytes(), map[string]string{
		"Content-Encoding": "deflate",
		"Content-Type":     "application/json",
	})
	if recFlate.Code != http.StatusCreated && recFlate.Code != http.StatusOK {
		t.Fatalf("raw flate write failed (%d): %s", recFlate.Code, recFlate.Body.String())
	}

	// 4. Corrupt gzip & deflate streams -> 400; unsupported encoding -> 415
	recBadGz := doRound63Req(t, h, http.MethodPost, "/wire_idx/_search", []byte{0x1f, 0x8b, 0x00, 0xff}, map[string]string{
		"Content-Encoding": "gzip",
		"Content-Type":     "application/json",
	})
	if recBadGz.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on corrupt gzip, got %d", recBadGz.Code)
	}

	recBadDef := doRound63Req(t, h, http.MethodPost, "/wire_idx/_search", []byte{0x78, 0x9c, 0xff, 0xff, 0xff}, map[string]string{
		"Content-Encoding": "deflate",
		"Content-Type":     "application/json",
	})
	if recBadDef.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on corrupt zlib deflate, got %d", recBadDef.Code)
	}

	recUnsup := doRound63Req(t, h, http.MethodPost, "/wire_idx/_search", []byte(`{}`), map[string]string{
		"Content-Encoding": "br",
		"Content-Type":     "application/json",
	})
	if recUnsup.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 on br Content-Encoding, got %d", recUnsup.Code)
	}
	recMulti := doRound63Req(t, h, http.MethodPost, "/wire_idx/_search", []byte(`{}`), map[string]string{
		"Content-Encoding": "gzip, deflate",
		"Content-Type":     "application/json",
	})
	if recMulti.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 on multi Content-Encoding, got %d", recMulti.Code)
	}

	// 5. Decompression bomb bounded by maxBodyBytes -> 413
	srv.SetMaxRequestBodyBytes(512)
	defer srv.SetMaxRequestBodyBytes(DefaultMaxRequestBodyBytes)

	bigJSON := `{"msg":"` + strings.Repeat("A", 4096) + `"}`
	var bombGz bytes.Buffer
	gw := gzip.NewWriter(&bombGz)
	_, _ = gw.Write([]byte(bigJSON))
	_ = gw.Close()
	recBombGz := doRound63Req(t, h, http.MethodPost, "/wire_idx/_doc/bomb1", bombGz.Bytes(), map[string]string{
		"Content-Encoding": "gzip",
		"Content-Type":     "application/json",
	})
	if recBombGz.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on gzip bomb, got %d: %s", recBombGz.Code, recBombGz.Body.String())
	}

	var bombDef bytes.Buffer
	zwBomb := zlib.NewWriter(&bombDef)
	_, _ = zwBomb.Write([]byte(bigJSON))
	_ = zwBomb.Close()
	recBombDef := doRound63Req(t, h, http.MethodPost, "/wire_idx/_doc/bomb2", bombDef.Bytes(), map[string]string{
		"Content-Encoding": "deflate",
		"Content-Type":     "application/json",
	})
	if recBombDef.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on deflate bomb, got %d: %s", recBombDef.Code, recBombDef.Body.String())
	}
}

type flushTrackingRecorderR63 struct {
	*httptest.ResponseRecorder
	flushed int
}

func (f *flushTrackingRecorderR63) Flush() {
	f.flushed++
	f.ResponseRecorder.Flush()
}

func TestRound63WireResponseCompressionQualityWeightsFlusherAndMVT(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	// 1. Accept-Encoding quality weights & ?http_compression=false
	for _, ae := range []string{"gzip;q=0", "gzip;q=0.0", "identity;q=1, *;q=0", "deflate"} {
		rec := doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{"Accept-Encoding": ae})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / with Accept-Encoding=%q returned %d", ae, rec.Code)
		}
		if gotCE := rec.Header().Get("Content-Encoding"); gotCE != "" {
			t.Fatalf("Accept-Encoding=%q must NOT compress, got Content-Encoding=%q", ae, gotCE)
		}
	}

	recCompFalse := doRound63Req(t, h, http.MethodGet, "/?http_compression=false", nil, map[string]string{"Accept-Encoding": "gzip"})
	if recCompFalse.Code != http.StatusOK || recCompFalse.Header().Get("Content-Encoding") != "" {
		t.Fatalf("?http_compression=false must disable gzip, code=%d CE=%q body=%s",
			recCompFalse.Code, recCompFalse.Header().Get("Content-Encoding"), recCompFalse.Body.String())
	}

	recCompTrue := doRound63Req(t, h, http.MethodGet, "/?http_compression=true", nil, map[string]string{"Accept-Encoding": "gzip;q=0.8"})
	if recCompTrue.Code != http.StatusOK || recCompTrue.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("?http_compression=true with gzip;q=0.8 must compress, code=%d CE=%q",
			recCompTrue.Code, recCompTrue.Header().Get("Content-Encoding"))
	}

	recCompBad := doRound63Req(t, h, http.MethodGet, "/?http_compression=notabool", nil, nil)
	if recCompBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid http_compression, got %d", recCompBad.Code)
	}

	// 2. Binary MVT responses skip gzip even when Accept-Encoding: gzip is set
	doRound63Req(t, h, http.MethodPut, "/mvt_idx", []byte(`{"mappings":{"properties":{"loc":{"type":"geo_point"}}}}`), nil)
	doRound63Req(t, h, http.MethodPut, "/mvt_idx/_doc/1?refresh=true", []byte(`{"loc":{"lat":37.77,"lon":-122.41}}`), nil)
	recMVT := doRound63Req(t, h, http.MethodGet, "/mvt_idx/_mvt/loc/0/0/0", nil, map[string]string{
		"Accept":          "application/vnd.mapbox-vector-tile",
		"Accept-Encoding": "gzip",
	})
	if recMVT.Code != http.StatusOK {
		t.Fatalf("expected 200 on _mvt, got %d: %s", recMVT.Code, recMVT.Body.String())
	}
	if ce := recMVT.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("expected MVT binary response NOT to be gzip-compressed, got Content-Encoding=%q", ce)
	}

	// 3. Flush() on gzipResponseWriter & esFormatResponseWriter
	ft := &flushTrackingRecorderR63{ResponseRecorder: httptest.NewRecorder()}
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gzw := &gzipResponseWriter{
		ResponseWriter: &esFormatResponseWriter{ResponseWriter: ft},
		gz:             gz,
	}
	_, _ = gzw.Write([]byte(`{"ok":true}`))
	gzw.Flush()
	gzw.Close()
	if ft.flushed == 0 {
		t.Fatalf("expected Flush() to forward through gzipResponseWriter and esFormatResponseWriter")
	}
}

func TestRound63AcceptMediaNegotiationAndSniffPublishAddress(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	allowedAccepts := []string{
		"application/vnd.mapbox-vector-tile",
		"text/csv",
		"text/tab-separated-values",
		"text/plain",
		"application/yaml",
		"application/cbor",
		"application/smile",
		"application/vnd.elasticsearch+ndjson; compatible-with=8",
		"*/*",
	}
	for _, acc := range allowedAccepts {
		rec := doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{"Accept": acc})
		if rec.Code != http.StatusOK {
			t.Fatalf("Accept=%q should be accepted, got %d: %s", acc, rec.Code, rec.Body.String())
		}
	}

	rec406 := doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{"Accept": "video/mp4"})
	if rec406.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406 on unsupported Accept=video/mp4, got %d", rec406.Code)
	}

	recQZero := doRound63Req(t, h, http.MethodGet, "/", nil, map[string]string{"Accept": "application/json;q=0"})
	if recQZero.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406 on Accept=application/json;q=0, got %d", recQZero.Code)
	}

	// Sniffing publish_address derivation
	checkPub := func(headers map[string]string, wantPub string) {
		t.Helper()
		rec := doRound63Req(t, h, http.MethodGet, "/_nodes/_local/http", nil, headers)
		if rec.Code != http.StatusOK {
			t.Fatalf("/_nodes/_local/http returned %d: %s", rec.Code, rec.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("unmarshal nodes/http: %v", err)
		}
		nodes, _ := payload["nodes"].(map[string]any)
		for _, rawNode := range nodes {
			nm, _ := rawNode.(map[string]any)
			hm, _ := nm["http"].(map[string]any)
			if got, _ := hm["publish_address"].(string); got != wantPub {
				t.Fatalf("headers=%v: got publish_address=%q, want %q", headers, got, wantPub)
			}
		}
	}

	checkPub(map[string]string{"Host": "es.example.com"}, "es.example.com:80")
	checkPub(map[string]string{"Host": "es.example.com", "X-Forwarded-Proto": "https"}, "es.example.com:443")
	checkPub(map[string]string{"Host": "es.example.com", "X-Forwarded-Port": "8443"}, "es.example.com:8443")
	checkPub(map[string]string{"Host": "127.0.0.1:49152"}, "127.0.0.1:49152")
}

func TestRound63AdminTemplatesSettingsSyncedFlushRerouteAndNodesUsage(t *testing.T) {
	srv := newRound63TestServer(t)
	srv.SetTargetESVersion("8.15.5")
	h := srv.Handler()

	// 1. `/_nodes/usage` variants
	for _, p := range []string{"/_nodes/usage", "/_nodes/_local/usage", "/_nodes/usage/rest_actions", "/_nodes/_local/usage/aggregations"} {
		rec := doRound63Req(t, h, http.MethodGet, p, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", p, rec.Code, rec.Body.String())
		}
	}
	recHeadUsage := doRound63Req(t, h, http.MethodHead, "/_nodes/usage", nil, nil)
	if recHeadUsage.Code != http.StatusOK || recHeadUsage.Body.Len() != 0 {
		t.Fatalf("HEAD /_nodes/usage failed: code=%d len=%d", recHeadUsage.Code, recHeadUsage.Body.Len())
	}
	recBadUsage := doRound63Req(t, h, http.MethodGet, "/_nodes/usage/unknown_metric", nil, nil)
	if recBadUsage.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown nodes.usage metric, got %d", recBadUsage.Code)
	}
	recMissNode := doRound63Req(t, h, http.MethodGet, "/_nodes/nonexistent_node_xyz/usage", nil, nil)
	if recMissNode.Code != http.StatusOK {
		t.Fatalf("expected 200 empty nodes on unmatched node filter, got %d", recMissNode.Code)
	}

	// 2. Synced flush + shard commit.user_data.sync_id
	doRound63Req(t, h, http.MethodPut, "/sf_idx", []byte(`{"settings":{"index.number_of_shards":1}}`), nil)
	recSF := doRound63Req(t, h, http.MethodPost, "/sf_idx/_flush/synced", nil, nil)
	if recSF.Code != http.StatusOK {
		t.Fatalf("POST /sf_idx/_flush/synced returned %d: %s", recSF.Code, recSF.Body.String())
	}
	recStats := doRound63Req(t, h, http.MethodGet, "/sf_idx/_stats?level=shards", nil, nil)
	if !strings.Contains(recStats.Body.String(), `"sync_id"`) {
		t.Fatalf("expected sync_id in shard stats commit.user_data, got: %s", recStats.Body.String())
	}
	recSFAll := doRound63Req(t, h, http.MethodPost, "/_flush/synced", nil, nil)
	if recSFAll.Code != http.StatusOK {
		t.Fatalf("POST /_flush/synced returned %d", recSFAll.Code)
	}

	// 3. put_settings validation (unknown setting, non-dynamic setting, ?reopen=true)
	recGarbage := doRound63Req(t, h, http.MethodPut, "/sf_idx/_settings", []byte(`{"garbage":"garbage"}`), nil)
	if recGarbage.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown setting, got %d: %s", recGarbage.Code, recGarbage.Body.String())
	}
	recCodecOpen := doRound63Req(t, h, http.MethodPut, "/sf_idx/_settings", []byte(`{"index.codec":"best_compression"}`), nil)
	if recCodecOpen.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on static index.codec for open index, got %d: %s", recCodecOpen.Code, recCodecOpen.Body.String())
	}
	recCodecReopen := doRound63Req(t, h, http.MethodPut, "/sf_idx/_settings?reopen=true", []byte(`{"index.codec":"best_compression"}`), nil)
	if recCodecReopen.Code != http.StatusOK {
		t.Fatalf("expected 200 on index.codec with ?reopen=true, got %d: %s", recCodecReopen.Code, recCodecReopen.Body.String())
	}

	// 4. Composable index templates (`get_index_template`, `put_index_template` ignore_missing_component_templates, `simulate_index_template`)
	recComma := doRound63Req(t, h, http.MethodGet, "/_index_template/t1,t2", nil, nil)
	if recComma.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on comma-separated get_index_template, got %d", recComma.Code)
	}
	recWildMiss := doRound63Req(t, h, http.MethodGet, "/_index_template/non-matching-wildcard*", nil, nil)
	if recWildMiss.Code != http.StatusNotFound || strings.Contains(recWildMiss.Body.String(), `"error"`) || !strings.Contains(recWildMiss.Body.String(), `"index_templates"`) {
		t.Fatalf("expected 404 with index_templates:[] on unmatched wildcard, got %d: %s", recWildMiss.Code, recWildMiss.Body.String())
	}

	doRound63Req(t, h, http.MethodPut, "/_component_template/ct_red", []byte(`{"template":{"mappings":{"properties":{"f1":{"type":"keyword"}}}}}`), nil)
	recBadComp := doRound63Req(t, h, http.MethodPut, "/_index_template/tpl_bad", []byte(`{"index_patterns":["p-*"],"composed_of":["ct_red","ct_missing"],"ignore_missing_component_templates":["other"]}`), nil)
	if recBadComp.Code != http.StatusBadRequest || !strings.Contains(recBadComp.Body.String(), "missing component templates [ct_missing]") {
		t.Fatalf("expected 400 missing component templates [ct_missing], got %d: %s", recBadComp.Code, recBadComp.Body.String())
	}
	recGoodComp := doRound63Req(t, h, http.MethodPut, "/_index_template/tpl_good", []byte(`{"index_patterns":["p-*"],"composed_of":["ct_red","ct_missing"],"ignore_missing_component_templates":["ct_missing"]}`), nil)
	if recGoodComp.Code != http.StatusOK {
		t.Fatalf("expected 200 when missing component is ignored, got %d: %s", recGoodComp.Code, recGoodComp.Body.String())
	}

	// 5. get_mapping expand_wildcards=none & resolve_index system attribute & cluster.reroute warnings
	recMapNone := doRound63Req(t, h, http.MethodGet, "/sf_x*/_mapping?expand_wildcards=none", nil, nil)
	if recMapNone.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on wildcard get_mapping with expand_wildcards=none in ES8, got %d: %s", recMapNone.Code, recMapNone.Body.String())
	}
	recMapAllow := doRound63Req(t, h, http.MethodGet, "/sf_x*/_mapping?expand_wildcards=none&ignore_unavailable=true&allow_no_indices=true", nil, nil)
	if recMapAllow.Code != http.StatusOK || strings.TrimSpace(recMapAllow.Body.String()) != "{}" {
		t.Fatalf("expected 200 {} with ignore_unavailable=true&allow_no_indices=true, got %d: %s", recMapAllow.Code, recMapAllow.Body.String())
	}

	doRound63Req(t, h, http.MethodPut, "/.tasks", []byte(`{}`), nil)
	recResolve := doRound63Req(t, h, http.MethodGet, "/_resolve/index/.tasks?expand_wildcards=all", nil, nil)
	if recResolve.Code != http.StatusOK || !strings.Contains(recResolve.Body.String(), `"system"`) {
		t.Fatalf("expected system attribute in resolve_index for .tasks, got %d: %s", recResolve.Code, recResolve.Body.String())
	}

	recRerouteNone := doRound63Req(t, h, http.MethodPost, "/_cluster/reroute?metric=none", []byte(`{}`), nil)
	if recRerouteNone.Code != http.StatusOK || len(recRerouteNone.Header().Values("Warning")) != 0 {
		t.Fatalf("expected 200 and zero warnings for cluster.reroute?metric=none, code=%d warnings=%v",
			recRerouteNone.Code, recRerouteNone.Header().Values("Warning"))
	}
	recRerouteDef := doRound63Req(t, h, http.MethodPost, "/_cluster/reroute", []byte(`{}`), nil)
	if recRerouteDef.Code != http.StatusOK || len(recRerouteDef.Header().Values("Warning")) == 0 {
		t.Fatalf("expected deprecation warning on cluster.reroute without metric=none, code=%d warnings=%v",
			recRerouteDef.Code, recRerouteDef.Header().Values("Warning"))
	}
}

func TestRound63SearchShardsReindexSimulateAndTranslogCoverage(t *testing.T) {
	srv := newRound63TestServer(t)
	h := srv.Handler()

	// 1. Filtered aliases on _search_shards (single term filter + multi-alias bool.should filter + nested bool filter)
	doRound63Req(t, h, http.MethodPut, "/ss_idx", []byte(`{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`), nil)
	doRound63Req(t, h, http.MethodPost, "/_aliases", []byte(`{
		"actions": [
			{"add": {"index": "ss_idx", "alias": "ss_al_1", "filter": {"term": {"tag": "v1"}}}},
			{"add": {"index": "ss_idx", "alias": "ss_al_2", "filter": {"bool": {"must": [{"term": {"tag": {"value": "v2"}}}]}}}}
		]
	}`), nil)

	recSS1 := doRound63Req(t, h, http.MethodGet, "/ss_al_1/_search_shards", nil, nil)
	if recSS1.Code != http.StatusOK || !strings.Contains(recSS1.Body.String(), `"boost":1`) {
		t.Fatalf("expected boost:1 in single filtered alias search_shards, got %d: %s", recSS1.Code, recSS1.Body.String())
	}
	recSS2 := doRound63Req(t, h, http.MethodGet, "/ss_al_1,ss_al_2/_search_shards", nil, nil)
	if recSS2.Code != http.StatusOK || !strings.Contains(recSS2.Body.String(), `"adjust_pure_negative":true`) {
		t.Fatalf("expected adjust_pure_negative:true in multi-alias search_shards, got %d: %s", recSS2.Code, recSS2.Body.String())
	}

	// 2. Reindex remote unknown fields wire-order preservation
	reindexBody := []byte(`{"conflicts":"proceed","extra_arr":[1,2,{"k":"v"}],"source":{"size":10,"remote":{"host":"http://127.0.0.1:9200","weird":{"nested":true},"badkey":[1,2]},"index":"ss_idx"},"dest":{"index":"ss_dst"}}`)
	gotReason := rewriteReindexRemoteUnknownFieldsOrderR63(reindexBody, "fallback")
	if gotReason != "Unsupported fields in [remote]: [weird,badkey]" {
		t.Fatalf("expected [weird,badkey] order, got %q", gotReason)
	}
	reindexHTTPBody := []byte(`{"conflicts":"proceed","source":{"size":10,"remote":{"host":"http://127.0.0.1:9200","weird":{"nested":true},"badkey":[1,2]},"index":"ss_idx"},"dest":{"index":"ss_dst"}}`)
	recReindex := doRound63Req(t, h, http.MethodPost, "/_reindex", reindexHTTPBody, nil)
	if recReindex.Code != http.StatusBadRequest || !strings.Contains(recReindex.Body.String(), "[weird,badkey]") {
		t.Fatalf("expected 400 [weird,badkey] from /_reindex, got %d: %s", recReindex.Code, recReindex.Body.String())
	}

	// 3. Simulate index template lifecycle + include_defaults (`_simulate/{name}`, `_simulate_index/{name}`, `_simulate`)
	srv.SetTargetESVersion("8.15.5")
	doRound63Req(t, h, http.MethodPut, "/_index_template/lc_tpl", []byte(`{
		"index_patterns": ["lc-sim-*"],
		"priority": 50,
		"template": {"lifecycle": {"data_retention": "7d"}},
		"data_stream": {}
	}`), nil)

	recSimByName := doRound63Req(t, h, http.MethodPost, "/_index_template/_simulate/lc_tpl?include_defaults=true", nil, nil)
	if recSimByName.Code != http.StatusOK || !strings.Contains(recSimByName.Body.String(), `"rollover"`) || !strings.Contains(recSimByName.Body.String(), `"enabled":true`) {
		t.Fatalf("expected lifecycle.enabled and rollover on _simulate/lc_tpl, got %d: %s", recSimByName.Code, recSimByName.Body.String())
	}

	recSimIdx := doRound63Req(t, h, http.MethodPost, "/_index_template/_simulate_index/lc-sim-001?include_defaults=true", nil, nil)
	if recSimIdx.Code != http.StatusOK || !strings.Contains(recSimIdx.Body.String(), `"enabled":true`) {
		t.Fatalf("expected lifecycle.enabled on _simulate_index, got %d: %s", recSimIdx.Code, recSimIdx.Body.String())
	}

	recSimBody := doRound63Req(t, h, http.MethodPost, "/_index_template/_simulate?include_defaults=true", []byte(`{
		"index_patterns": ["adhoc-lc-*"],
		"template": {"lifecycle": {"data_retention": "14d"}},
		"data_stream": {}
	}`), nil)
	if recSimBody.Code != http.StatusOK || !strings.Contains(recSimBody.Body.String(), `"14d"`) {
		t.Fatalf("expected 14d lifecycle on _simulate body, got %d: %s", recSimBody.Code, recSimBody.Body.String())
	}

	// 4. get_mapping expand_wildcards=none concrete & allow_no_indices=false
	recMapConcrete := doRound63Req(t, h, http.MethodGet, "/ss_idx/_mapping?expand_wildcards=none", nil, nil)
	if recMapConcrete.Code != http.StatusOK {
		t.Fatalf("expected 200 on concrete open index with expand_wildcards=none, got %d", recMapConcrete.Code)
	}
	recMapConcreteMiss := doRound63Req(t, h, http.MethodGet, "/no_such_concrete/_mapping?expand_wildcards=none", nil, nil)
	if recMapConcreteMiss.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on missing concrete index with expand_wildcards=none, got %d", recMapConcreteMiss.Code)
	}
	recMapNoAllow := doRound63Req(t, h, http.MethodGet, "/no_such_wild*/_mapping?expand_wildcards=none&ignore_unavailable=true&allow_no_indices=false", nil, nil)
	if recMapNoAllow.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when allow_no_indices=false, got %d", recMapNoAllow.Code)
	}

	// 5. v7 soft_deletes.enabled=false translog retention warning suppression + nested settings + bad ?reopen
	srv.SetTargetESVersion("7.10.2")
	doRound63Req(t, h, http.MethodPut, "/v7_nolog_idx", []byte(`{"settings":{"index.soft_deletes.enabled":false}}`), nil)
	recTlog := doRound63Req(t, h, http.MethodPut, "/v7_nolog_idx/_settings", []byte(`{"settings":{"index":{"translog":{"retention":{"size":"-1","age":"-1"}}}}}`), nil)
	if recTlog.Code != http.StatusOK {
		t.Fatalf("expected 200 on translog retention update, got %d: %s", recTlog.Code, recTlog.Body.String())
	}
	for _, wv := range recTlog.Header().Values("Warning") {
		if strings.Contains(wv, "Translog retention settings") {
			t.Fatalf("expected translog retention warning to be suppressed when soft_deletes.enabled=false, got %q", wv)
		}
	}

	doRound63Req(t, h, http.MethodPost, "/v7_nolog_idx/_close", nil, nil)
	recAnalysisSet := doRound63Req(t, h, http.MethodPut, "/v7_nolog_idx/_settings", []byte(`{"analysis":{"analyzer":{"my_an":{"type":"standard"}}}}`), nil)
	if recAnalysisSet.Code != http.StatusOK {
		t.Fatalf("expected 200 on closed index analysis settings, got %d: %s", recAnalysisSet.Code, recAnalysisSet.Body.String())
	}
	doRound63Req(t, h, http.MethodPost, "/v7_nolog_idx/_open", nil, nil)

	recBadReopen := doRound63Req(t, h, http.MethodPut, "/v7_nolog_idx/_settings?reopen=notbool", []byte(`{"number_of_replicas":0}`), nil)
	if recBadReopen.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid ?reopen=notbool, got %d", recBadReopen.Code)
	}
}
