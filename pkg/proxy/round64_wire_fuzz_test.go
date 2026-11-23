package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Note: FuzzStreamLoadRedirect is defined in pkg/proxy/round64_infra_hardening_test.go.

func FuzzCompileGrokAndDissect(f *testing.F) {
	f.Add(`%{IP:client} %{WORD:method} %{URIPATHPARAM:request}`, "127.0.0.1 GET /index.html", "%{a} %{b} -> %{+b}", "foo bar baz", ",")
	f.Add(`%{CYCLE_A:a}`, "abc", "%{k1} - %{k2|trim}", "  one  - two ", "|")
	f.Add(`%{NUMBER:n:int} (?<tag>[a-z]+)`, "42 ok", "%{skip->}%{val}", "   hello", " ")
	f.Add(strings.Repeat("%{IP}", 64), "1.2.3.4", "%{}{%{}}", "x", "")
	f.Add(`(a+)+$`, "aaaaaaaaaaaaaaaa!", "%{missing_close", "abc", ",")

	f.Fuzz(func(t *testing.T, grokPat, sample, dissectPat, dissectInput, appendSep string) {
		if len(grokPat) > 32<<10 {
			grokPat = grokPat[:32<<10]
		}
		if len(dissectPat) > 8<<10 {
			dissectPat = dissectPat[:8<<10]
		}
		if len(sample) > 8<<10 {
			sample = sample[:8<<10]
		}
		if len(dissectInput) > 8<<10 {
			dissectInput = dissectInput[:8<<10]
		}

		customDefs := map[string]any{
			"CYCLE_A": "%{CYCLE_B}",
			"CYCLE_B": "%{CYCLE_A}",
			"EXTRA":   `\w+`,
		}
		re, types, _, err := compileGrokRegex(grokPat, customDefs)
		if err == nil && re != nil {
			if len(re.String()) > maxExpandedGrokRegexLen {
				t.Fatalf("compiled grok regex exceeded cap %d: len=%d", maxExpandedGrokRegexLen, len(re.String()))
			}
			_ = re.FindStringSubmatch(sample)
			_ = types
		}

		if jr, jErr := compileIngestJavaRegex(grokPat); jErr == nil && jr != nil {
			_ = jr.MatchString(sample)
		}

		_ = validateDissectPatternGrammar(dissectPat)
		_, _ = evalDissectPattern(dissectPat, dissectInput, appendSep)
	})
}

func FuzzRenderMustacheTemplate(f *testing.F) {
	f.Add(`{"query":{"match":{"title":"{{q}}"}}}`, `{"q":"hello world"}`)
	f.Add(`{"size":{{#toJson}}tags{{/toJson}},"query":{"terms":{"k":{{#join delimiter=","}}items{{/join}}}}}`, `{"tags":5,"items":["a","b","c"]}`)
	f.Add(strings.Repeat("{{#x}}", 40)+"{{y}}"+strings.Repeat("{{/x}}", 40), `{"x":true,"y":"ok"}`)
	f.Add(`{{#list}}{{.}},{{/list}}{{^empty}}none{{/empty}}`, `{"list":["one","two"],"empty":false}`)
	f.Add(`{{{raw}}}{{&amp}}`, `{"raw":"<tag>","amp":"a&b"}`)
	f.Add(`{"incomplete": "{{open"`, `{}`)

	f.Fuzz(func(t *testing.T, tplRaw, paramsJSON string) {
		if len(tplRaw) > 16<<10 {
			tplRaw = tplRaw[:16<<10]
		}
		if len(paramsJSON) > 16<<10 {
			paramsJSON = paramsJSON[:16<<10]
		}

		var params map[string]any
		dec := json.NewDecoder(strings.NewReader(paramsJSON))
		dec.UseNumber()
		if err := dec.Decode(&params); err != nil || params == nil {
			params = map[string]any{"q": paramsJSON}
		}

		var tplObj any = tplRaw
		var parsed any
		if json.Unmarshal([]byte(tplRaw), &parsed) == nil && parsed != nil {
			tplObj = parsed
		}

		out, err := renderMustacheSearchTemplate(tplObj, params)
		if err == nil && len(out) > maxMustacheOutputBytes*4 {
			t.Fatalf("rendered mustache output unexpectedly huge: %d", len(out))
		}
		_, _ = renderMustacheSearchTemplate(tplRaw, params)
	})
}

func FuzzDecompressRequestBody(f *testing.F) {
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, _ = gzw.Write([]byte(`{"query":{"match_all":{}}}`))
	_ = gzw.Close()

	var zlBuf bytes.Buffer
	zlw := zlib.NewWriter(&zlBuf)
	_, _ = zlw.Write([]byte(`{"query":{"match_all":{}}}`))
	_ = zlw.Close()

	var flBuf bytes.Buffer
	flw, _ := flate.NewWriter(&flBuf, flate.DefaultCompression)
	_, _ = flw.Write([]byte(`{"query":{"match_all":{}}}`))
	_ = flw.Close()

	// Also seed a raw RFC-1951 payload whose first two bytes happen to satisfy zlib CMF/FLG % 31 == 0!
	f.Add("gzip", gzBuf.Bytes(), int64(4096))
	f.Add("deflate", zlBuf.Bytes(), int64(4096))
	f.Add("deflate", flBuf.Bytes(), int64(4096))
	f.Add("gzip", gzBuf.Bytes(), int64(8))
	f.Add("deflate", []byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}, int64(1024))
	f.Add("gzip, deflate", []byte("not-compressed-junk"), int64(1024))
	f.Add("br", []byte("abc"), int64(64))

	f.Fuzz(func(t *testing.T, encHeader string, payload []byte, maxBytes int64) {
		if len(payload) > 32<<10 {
			payload = payload[:32<<10]
		}
		if maxBytes <= 0 {
			maxBytes = 1
		} else if maxBytes > 128<<10 {
			maxBytes = 128 << 10
		}

		req := httptest.NewRequest(http.MethodPost, "/_search", bytes.NewReader(payload))
		for _, tok := range strings.Split(encHeader, ";") {
			tok = strings.TrimSpace(tok)
			if tok != "" {
				req.Header.Add("Content-Encoding", tok)
			}
		}
		rec := httptest.NewRecorder()
		cleanup, ok := decompressRequestBodyR63Wire(rec, req, maxBytes)
		if cleanup != nil {
			defer cleanup()
		}
		if !ok {
			if rec.Code < 400 {
				t.Fatalf("decompressRequestBodyR63Wire returned !ok with non-error status %d", rec.Code)
			}
			return
		}
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBytes+1))
		if err == nil && int64(len(bodyBytes)) > maxBytes {
			t.Fatalf("decompressed body exceeded limit %d: got %d", maxBytes, len(bodyBytes))
		}
	})
}
