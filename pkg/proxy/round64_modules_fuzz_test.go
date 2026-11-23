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
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func buildFuzzDocxBytesR64(docText string, coreAuthor string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if w, err := zw.Create("word/document.xml"); err == nil {
		_, _ = w.Write([]byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + docText + `</w:t></w:r></w:p></w:body></w:document>`))
	}
	if w, err := zw.Create("docProps/core.xml"); err == nil {
		_, _ = w.Write([]byte(`<cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"><dc:creator>` + coreAuthor + `</dc:creator></cp:coreProperties>`))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func buildFuzzCyclicOLE2R64() []byte {
	// 512-byte CFBF header + sector 0 FAT with cyclic chain [1, 0, ENDOFCHAIN...]
	raw := make([]byte, 512*4)
	copy(raw[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(raw[0x1E:0x20], 9) // 512-byte sectors
	binary.LittleEndian.PutUint32(raw[0x2C:0x30], 1) // 1 FAT sector
	binary.LittleEndian.PutUint32(raw[0x30:0x34], 1) // first dir sector = 1
	binary.LittleEndian.PutUint32(raw[0x4C:0x50], 0) // DIFAT[0] = sector 0
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(raw[0x4C+i*4:0x4C+i*4+4], 0xFFFFFFFF)
	}
	// Sector 0 = FAT at offset 512: entry 0 = 1, entry 1 = 0 (2-node cycle)
	binary.LittleEndian.PutUint32(raw[512:516], 1)
	binary.LittleEndian.PutUint32(raw[516:520], 0)
	binary.LittleEndian.PutUint32(raw[520:524], 0xFFFFFFFE)
	return raw
}

func FuzzExtractIngestAttachment(f *testing.F) {
	docxB64 := base64.StdEncoding.EncodeToString(buildFuzzDocxBytesR64("Hello attachment fuzz world", "alice"))
	oleCycleB64 := base64.StdEncoding.EncodeToString(buildFuzzCyclicOLE2R64())
	f.Add(docxB64, int64(100000), true)
	f.Add(oleCycleB64, int64(1000), true)
	f.Add(base64.StdEncoding.EncodeToString([]byte("PK\x03\x04truncated")), int64(50), false)
	f.Add("not-valid-base64!!!", int64(10), true)
	f.Add("", int64(0), true)

	f.Fuzz(func(t *testing.T, payload string, indexedChars int64, isES8 bool) {
		if len(payload) > 256*1024 {
			payload = payload[:256*1024]
		}
		if res, ok := ExtractIngestAttachmentRound63(payload, indexedChars, nil, isES8); ok && res != nil {
			if txt, okS := res["content"].(string); okS && len(txt) > maxIngestAttachmentDecompressedBytes {
				t.Fatalf("extracted content exceeded cap: %d", len(txt))
			}
			if _, hasCreated := res["created"]; hasCreated {
				t.Fatalf("expected created key to be omitted by default")
			}
		}
		// Exercise raw ZIP/OLE2 decoders directly as well without requiring base64 wrapper.
		raw := []byte(payload)
		if len(raw) > 4 {
			if bytes.HasPrefix(raw, []byte{'P', 'K', 0x03, 0x04}) {
				_ = extractOOXMLDocxAttachmentRound63(raw, indexedChars, isES8)
			}
			if len(raw) >= 8 && bytes.Equal(raw[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
				_ = parseOLE2StreamsRound63(raw)
			}
		}
	})
}

func FuzzESQLAndEQL(f *testing.F) {
	f.Add("FROM events_* | WHERE client_ip::ip == \"10.0.0.1\" | STATS cd = COUNT_DISTINCT(tags), v = VALUES(msg) BY env | SORT cd DESC | LIMIT 5")
	f.Add("FROM tsdb | WHERE tx::long > 0 | EVAL r = COALESCE(tx::double, 1.0) | STATS s = SUM(tx)")
	f.Add("ROW a = 1, b = \"hello\" | EVAL c = CONCAT(b, TO_STRING(a)) | DROP a | KEEP b, c")
	f.Add("sequence by user.id [authentication where event.outcome == \"failure\"] ![process where process.name == \"cmd.exe\"]")
	f.Add("sequence with maxspan=5m [process where process.name == \"sh\"] [network where destination.port == 443] until [process where event.type == \"end\"]")
	f.Add("sample by host.name [event where event.category == \"process\"]")

	colTypes := map[string]string{
		"tx":        "counter_long",
		"client_ip": "unsupported",
		"tags":      "keyword",
		"msg":       "text",
		"env":       "keyword",
	}

	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 32*1024 {
			query = query[:32*1024]
		}
		stages := splitESQLStages(query)
		for _, st := range stages {
			rewritten := rewriteESQLDoubleColonCastsRound63(st)
			_ = inferESQLExprStaticTypeRound63(rewritten, colTypes)
			_ = esqlStripConversionWrappersR64(rewritten)
			_ = esqlFindBareCounterColumnR64(rewritten, colTypes)
		}
		counters := ESQLSupportedFeaturesMapR64()
		RecordESQLFeatureUsageR64(counters, query)

		toks, err := tokenizeEQL(query)
		if err == nil {
			p := &eqlParser{toks: toks}
			if ast, perr := p.parseQuery(); perr == nil && ast != nil {
				_ = collectEQLReferencedFieldsRound63(ast)
			}
		}
	})
}
