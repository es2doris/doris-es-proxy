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

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()
	_ = w.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func TestEnvHelpersAndRedactDSN(t *testing.T) {
	t.Setenv("TEST_STR_KEY", "  custom_val  ")
	if got := envOrDefault("TEST_STR_KEY", "fallback"); got != "custom_val" {
		t.Fatalf("expected custom_val, got %q", got)
	}
	if got := envOrDefault("TEST_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}

	for _, truthy := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("TEST_BOOL_KEY", truthy)
		if !envBoolOrDefault("TEST_BOOL_KEY", false) {
			t.Fatalf("expected true for %q", truthy)
		}
	}
	for _, falsy := range []string{"0", "false", "FALSE", "no", "off"} {
		t.Setenv("TEST_BOOL_KEY", falsy)
		if envBoolOrDefault("TEST_BOOL_KEY", true) {
			t.Fatalf("expected false for %q", falsy)
		}
	}
	t.Setenv("TEST_BOOL_KEY", "invalid")
	if !envBoolOrDefault("TEST_BOOL_KEY", true) {
		t.Fatalf("expected fallback true for invalid bool env")
	}

	if got := redactDSN("root:s3cr3t@tcp(127.0.0.1:9030)/es_compat"); got != "root:***@tcp(127.0.0.1:9030)/es_compat" {
		t.Fatalf("expected redacted password, got %q", got)
	}
	if got := redactDSN("root:s3cr3t@unix(/tmp/mysql.sock)/es_compat"); got != "root:***@unix(/tmp/mysql.sock)/es_compat" {
		t.Fatalf("expected redacted password for unix socket DSN, got %q", got)
	}
	if got := redactDSN("root:@tcp(127.0.0.1:9030)/es_compat"); got != "root:@tcp(127.0.0.1:9030)/es_compat" {
		t.Fatalf("expected empty password DSN unchanged, got %q", got)
	}
	if got := redactDSN("invalid-dsn"); got != "invalid-dsn" {
		t.Fatalf("expected non-tcp DSN unchanged, got %q", got)
	}

	t.Setenv("TEST_INT_KEY", "42")
	if got := envIntOrDefault("TEST_INT_KEY", 7); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	t.Setenv("TEST_INT_KEY", "not-an-int")
	if got := envIntOrDefault("TEST_INT_KEY", 7); got != 7 {
		t.Fatalf("expected fallback 7, got %d", got)
	}

	t.Setenv("TEST_DUR_KEY", "250ms")
	if got := envDurationOrDefault("TEST_DUR_KEY", 5*time.Second); got != 250*time.Millisecond {
		t.Fatalf("expected 250ms, got %v", got)
	}
	t.Setenv("TEST_DUR_KEY", "invalid-dur")
	if got := envDurationOrDefault("TEST_DUR_KEY", 5*time.Second); got != 5*time.Second {
		t.Fatalf("expected fallback 5s, got %v", got)
	}
}

func TestParseMappingJSON(t *testing.T) {
	wrapped := []byte(`{"mappings":{"properties":{"name":{"type":"text"}}}}`)
	spec, err := parseMappingJSON(wrapped)
	if err != nil || spec == nil || len(spec.Properties) != 1 {
		t.Fatalf("expected wrapped mapping to parse 1 property, got spec=%+v err=%v", spec, err)
	}

	direct := []byte(`{"properties":{"service":{"type":"keyword"}}}`)
	spec2, err := parseMappingJSON(direct)
	if err != nil || spec2 == nil || len(spec2.Properties) != 1 {
		t.Fatalf("expected direct mapping to parse 1 property, got spec=%+v err=%v", spec2, err)
	}

	if _, err := parseMappingJSON([]byte(`{invalid`)); err == nil {
		t.Fatalf("expected error on invalid mapping JSON")
	}
}

func TestSubcommands_Transpile_DDL_Doctor_MigrateSchema(t *testing.T) {
	tmpDir := t.TempDir()
	mappingFile := filepath.Join(tmpDir, "mapping.json")
	queryFile := filepath.Join(tmpDir, "query.json")

	if err := os.WriteFile(mappingFile, []byte(`{
		"mappings": {
			"properties": {
				"name": {"type": "text"},
				"serviceType": {"type": "keyword"},
				"embedding": {"type": "dense_vector", "dims": 3}
			}
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queryFile, []byte(`{
		"query": {"query_string": {"query": "name:orders"}},
		"aggs": {"by_svc": {"terms": {"field": "serviceType"}}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. transpile (SQL format + Doris 4.0 SEARCH() pushdown)
	sqlOut := captureStdout(t, func() {
		runTranspileSubcommand([]string{
			"--index", "table_search_index",
			"--db", "es_compat",
			"--mapping", mappingFile,
			"--query", queryFile,
			"--doris4-search-fn",
			"--format", "sql",
		})
	})
	if !strings.Contains(sqlOut, "-- [HitsSQL]") || !strings.Contains(sqlOut, "-- [AggsSQL") {
		t.Fatalf("expected HitsSQL and AggsSQL in transpile sql output, got:\n%s", sqlOut)
	}

	// 2. transpile (JSON format)
	jsonOut := captureStdout(t, func() {
		runTranspileSubcommand([]string{
			"--index", "table_search_index",
			"--db", "es_compat",
			"--mapping", mappingFile,
			"--query", queryFile,
			"--format", "json",
		})
	})
	if !strings.Contains(jsonOut, `"hits_sql"`) || !strings.Contains(jsonOut, `"create_table_ddl"`) {
		t.Fatalf("expected JSON keys in transpile json output, got:\n%s", jsonOut)
	}

	// 3. ddl subcommand
	ddlOut := captureStdout(t, func() {
		runDDLSubcommand([]string{
			"--index", "table_search_index",
			"--db", "es_compat",
			"--mapping", mappingFile,
		})
	})
	if !strings.Contains(ddlOut, "CREATE TABLE IF NOT EXISTS `es_compat`.`table_search_index`") ||
		!strings.Contains(ddlOut, "`f__embedding` ARRAY<FLOAT> NULL") {
		t.Fatalf("unexpected DDL output:\n%s", ddlOut)
	}

	// 4. doctor subcommand (with mock FE HTTP server)
	feServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"msg":"OK"}`))
	}))
	defer feServer.Close()

	docOut := captureStdout(t, func() {
		runDoctorSubcommand([]string{
			"--doris-dsn", "root:secret@tcp(127.0.0.1:1)/?timeout=50ms",
			"--doris-http", feServer.URL,
		})
	})
	if !strings.Contains(docOut, "root:***@tcp(127.0.0.1:1)") || !strings.Contains(docOut, "OK (HTTP 200)") {
		t.Fatalf("unexpected doctor output:\n%s", docOut)
	}

	// 5. migrate-schema subcommand (with mock ES _mapping server)
	esServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			".kibana": {"mappings": {"properties": {"hidden": {"type": "keyword"}}}},
			"orders_idx": {"mappings": {"properties": {"order_id": {"type": "keyword"}, "amount": {"type": "double"}}}}
		}`))
	}))
	defer esServer.Close()

	migOut := captureStdout(t, func() {
		runMigrateSchemaSubcommand([]string{
			"--es-url", esServer.URL,
			"--index", "_all",
			"--db", "es_migrated",
		})
	})
	if strings.Contains(migOut, ".kibana") {
		t.Fatalf("expected system index .kibana to be skipped, got:\n%s", migOut)
	}
	if !strings.Contains(migOut, "CREATE DATABASE IF NOT EXISTS `es_migrated`;") ||
		!strings.Contains(migOut, "CREATE TABLE IF NOT EXISTS `es_migrated`.`orders_idx`") {
		t.Fatalf("unexpected migrate-schema output:\n%s", migOut)
	}

	// 5b. migrate-schema with --out-dir, --es-api-key, --es-user/--es-password, and --es-insecure-skip-verify
	outDir := filepath.Join(tmpDir, "ddl_out")
	runMigrateSchemaSubcommand([]string{
		"--es-url", esServer.URL,
		"--index", "_all",
		"--db", "es_migrated",
		"--out-dir", outDir,
		"--es-api-key", "test-api-key",
		"--es-insecure-skip-verify",
	})
	if _, err := os.Stat(filepath.Join(outDir, "00_create_database.sql")); err != nil {
		t.Fatalf("expected 00_create_database.sql in --out-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "orders_idx.sql")); err != nil {
		t.Fatalf("expected orders_idx.sql in --out-dir: %v", err)
	}
	runMigrateSchemaSubcommand([]string{
		"--es-url", esServer.URL,
		"--index", "_all",
		"--db", "es_migrated",
		"--out-dir", outDir,
		"--es-user", "elastic",
		"--es-password", "changeme",
	})
	runMigrateSchemaSubcommand([]string{
		"--es-url", esServer.URL,
		"--index", "_all",
		"--db", "es_migrated",
		"--out-dir", outDir,
		"--es-api-key", "Bearer custom-token",
	})

	// 6. Stdin branches for transpile and ddl, plus main() version dispatch and doctor error branches
	oldStdin := os.Stdin
	oldArgs := os.Args
	defer func() {
		os.Stdin = oldStdin
		os.Args = oldArgs
	}()

	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wIn.WriteString(`{"query":{"match_all":{}}}`)
	_ = wIn.Close()
	os.Stdin = rIn
	os.Args = []string{"doris-es-proxy", "transpile", "--index", "stdin_idx"}
	stdinTranspileOut := captureStdout(t, func() {
		main()
	})
	_ = rIn.Close()
	if !strings.Contains(stdinTranspileOut, "stdin_idx") {
		t.Fatalf("expected stdin_idx in main() transpile output, got:\n%s", stdinTranspileOut)
	}

	rIn2, wIn2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wIn2.WriteString(`{"properties":{"host":{"type":"keyword"}}}`)
	_ = wIn2.Close()
	os.Stdin = rIn2
	os.Args = []string{"doris-es-proxy", "ddl", "--index", "stdin_ddl_idx"}
	stdinDDLOut := captureStdout(t, func() {
		main()
	})
	_ = rIn2.Close()
	if !strings.Contains(stdinDDLOut, "stdin_ddl_idx") || !strings.Contains(stdinDDLOut, "f__host") {
		t.Fatalf("expected stdin_ddl_idx and f__host in main() ddl output, got:\n%s", stdinDDLOut)
	}

	for _, verArg := range []string{"version", "--version", "-v"} {
		os.Args = []string{"doris-es-proxy", verArg}
		verOut := captureStdout(t, func() {
			main()
		})
		if !strings.Contains(verOut, "doris-es-proxy") {
			t.Fatalf("expected version output for %s, got %q", verArg, verOut)
		}
	}

	// Doctor with failing HTTP status (503) and unreachable HTTP port
	failFEServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failFEServer.Close()
	os.Args = []string{"doris-es-proxy", "doctor", "--doris-dsn", "root:@tcp(127.0.0.1:1)/?timeout=20ms", "--doris-http", failFEServer.URL}
	docFailOut := captureStdout(t, func() {
		main()
	})
	if !strings.Contains(docFailOut, "FAIL (HTTP 503)") {
		t.Fatalf("expected FAIL (HTTP 503) in doctor output, got:\n%s", docFailOut)
	}

	os.Args = []string{"doris-es-proxy", "doctor", "--doris-dsn", "root:@tcp(127.0.0.1:1)/?timeout=20ms", "--doris-http", "http://127.0.0.1:1"}
	docUnreachOut := captureStdout(t, func() {
		main()
	})
	if !strings.Contains(docUnreachOut, "UNREACHABLE") {
		t.Fatalf("expected UNREACHABLE in doctor output, got:\n%s", docUnreachOut)
	}
}

func TestRound62CLISecurityHardening(t *testing.T) {
	redacted := redactURLCredentials("https://elastic:s3cr3tPass@es-legacy.internal:9200")
	if strings.Contains(redacted, "s3cr3tPass") || !strings.Contains(redacted, "es-legacy.internal:9200") {
		t.Fatalf("expected credentials redacted from shadow URL, got %q", redacted)
	}
	fallbackRedacted := redactURLCredentials("user:topsecret@bad-scheme-host:9200\r\n")
	if strings.Contains(fallbackRedacted, "topsecret") || strings.ContainsAny(fallbackRedacted, "\r\n") {
		t.Fatalf("expected fallback redaction and CR/LF stripping, got %q", fallbackRedacted)
	}
	if got := escapeDorisBacktickIdent("es`db"); strings.Contains(got, "`") && !strings.Contains(got, "``") {
		t.Fatalf("expected unescaped backticks never present in escapeDorisBacktickIdent, got %q", got)
	}

	t.Setenv("DORIS_ES_REINDEX_REMOTE_WHITELIST", "es1.prod:9200,es2.prod:9200")
	t.Setenv("DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE", "true")
	if got := envOrDefault("DORIS_ES_REINDEX_REMOTE_WHITELIST", ""); got != "es1.prod:9200,es2.prod:9200" {
		t.Fatalf("unexpected DORIS_ES_REINDEX_REMOTE_WHITELIST: %q", got)
	}
	if !envBoolOrDefault("DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE", false) {
		t.Fatalf("expected DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE=true")
	}
	if got := redactURLCredentials(""); got != "" {
		t.Fatalf("expected empty string for empty shadow URL, got %q", got)
	}
	if got := redactURLCredentials("  \r\n "); got != "" {
		t.Fatalf("expected empty string for whitespace shadow URL, got %q", got)
	}
}

func TestRound65_ServerCLIAndSubcommandErrors(t *testing.T) {
	// 1. Flag validation and help output without starting listeners.
	var helpBuf bytes.Buffer
	err := runServerErr(context.Background(), []string{"--help"}, &helpBuf, nil)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected flag.ErrHelp, got %v", err)
	}
	if !strings.Contains(helpBuf.String(), "Usage: doris-es-proxy") || !strings.Contains(helpBuf.String(), "Server Flags:") {
		t.Fatalf("expected custom usage text, got:\n%s", helpBuf.String())
	}

	var stderrBuf bytes.Buffer
	for _, badArgs := range [][]string{
		{"--basic-auth-user", "elastic"},
		{"--basic-auth-pass", "secret"},
		{"--tls-cert", "/tmp/cert.pem"},
		{"--tls-key", "/tmp/key.pem"},
		{"--no-such-flag"},
	} {
		stderrBuf.Reset()
		if err := runServerErr(context.Background(), badArgs, &stderrBuf, nil); err == nil {
			t.Fatalf("expected error for args %v", badArgs)
		}
	}

	// 2. Full in-memory server configuration + TLS branch + graceful shutdown via mock listenFn (no sockets bound).
	ctx, cancel := context.WithCancel(context.Background())
	var observedAddr string
	var observedCert string
	var observedKey string
	var rootRespCode int
	err = runCLI(ctx, []string{
		"--listen", "127.0.0.1:0",
		"--doris-db", "r65_cli_db",
		"--in-memory",
		"--es-version", "8.15.5",
		"--shadow-es-url", "https://user:pass@shadow.internal:9200",
		"--auto-promote",
		"--bulk-coalesce-ms", "15",
		"--bulk-coalesce-bytes", "65536",
		"--query-cache-ttl", "5s",
		"--basic-auth-user", "elastic",
		"--basic-auth-pass", "changeme",
		"--api-key", "api-key-token",
		"--tls-cert", "/tmp/fake-cert.pem",
		"--tls-key", "/tmp/fake-key.pem",
		"--reindex-remote-whitelist", "es.remote:9200",
		"--reindex-remote-allow-private",
	}, strings.NewReader(""), &bytes.Buffer{}, &stderrBuf, func(s *http.Server, certFile, keyFile string) error {
		observedAddr = s.Addr
		observedCert = certFile
		observedKey = keyFile
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth("elastic", "changeme")
		rec := httptest.NewRecorder()
		s.Handler.ServeHTTP(rec, req)
		rootRespCode = rec.Code
		cancel()
		return http.ErrServerClosed
	})
	if err != nil {
		t.Fatalf("expected clean shutdown in-memory server run, got %v", err)
	}
	if observedAddr != "127.0.0.1:0" || observedCert != "/tmp/fake-cert.pem" || observedKey != "/tmp/fake-key.pem" {
		t.Fatalf("unexpected listen parameters: addr=%q cert=%q key=%q", observedAddr, observedCert, observedKey)
	}
	if rootRespCode != http.StatusOK {
		t.Fatalf("expected authenticated root handler 200 OK, got %d", rootRespCode)
	}

	// 3. Non-in-memory Doris SQL backend initialization path + unexpected listen error propagation.
	sqlCtx, sqlCancel := context.WithCancel(context.Background())
	defer sqlCancel()
	listenBoom := errors.New("synthetic bind failure")
	err = runServerErr(sqlCtx, []string{
		"--listen", "127.0.0.1:0",
		"--doris-dsn", "root:@tcp(127.0.0.1:1)/?timeout=20ms",
		"--doris-http", "http://127.0.0.1:1",
		"--doris-user", "admin",
		"--doris-password", "pw",
		"--doris-db", "es_sql_cli",
	}, &stderrBuf, func(s *http.Server, certFile, keyFile string) error {
		return listenBoom
	})
	if !errors.Is(err, listenBoom) {
		t.Fatalf("expected wrapped listenBoom error, got %v", err)
	}

	// 4. Error branches for transpile, ddl, doctor, migrate-schema subcommands + runCLI dispatch.
	tmpDir := t.TempDir()
	badJSONFile := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(badJSONFile, []byte(`{invalid`), 0o600); err != nil {
		t.Fatal(err)
	}
	validMappingFile := filepath.Join(tmpDir, "map.json")
	if err := os.WriteFile(validMappingFile, []byte(`{"properties":{"msg":{"type":"text"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var outBuf bytes.Buffer
	for _, tc := range [][]string{
		{"transpile", "--unknown-flag"},
		{"transpile", "--mapping", filepath.Join(tmpDir, "missing.json")},
		{"transpile", "--mapping", badJSONFile},
		{"transpile", "--mapping", validMappingFile, "--query", filepath.Join(tmpDir, "missing-query.json")},
	} {
		outBuf.Reset()
		stderrBuf.Reset()
		if err := runCLI(context.Background(), tc, strings.NewReader(`{}`), &outBuf, &stderrBuf, nil); err == nil {
			t.Fatalf("expected error for %v", tc)
		}
	}
	if err := runCLI(context.Background(), []string{"transpile"}, strings.NewReader(`{bad-json`), &outBuf, &stderrBuf, nil); err == nil {
		t.Fatal("expected invalid search JSON error")
	}
	if err := runCLI(context.Background(), []string{"transpile"}, strings.NewReader(`{"query":{"unsupported_fake_clause":{}}}`), &outBuf, &stderrBuf, nil); err == nil {
		t.Fatal("expected transpile error for unsupported query clause")
	}

	for _, tc := range [][]string{
		{"ddl", "--unknown-flag"},
		{"ddl", "--mapping", filepath.Join(tmpDir, "missing.json")},
		{"ddl", "--mapping", badJSONFile},
	} {
		if err := runCLI(context.Background(), tc, strings.NewReader(``), &outBuf, &stderrBuf, nil); err == nil {
			t.Fatalf("expected error for %v", tc)
		}
	}

	if err := runCLI(context.Background(), []string{"doctor", "--unknown-flag"}, strings.NewReader(""), &outBuf, &stderrBuf, nil); err == nil {
		t.Fatal("expected error for unknown doctor flag")
	}

	httpErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal error`))
	}))
	defer httpErrSrv.Close()

	httpBadJSONSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer httpBadJSONSrv.Close()

	httpGoodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"orders":{"mappings":{"properties":{"id":{"type":"keyword"}}}}}`))
	}))
	defer httpGoodSrv.Close()

	for _, tc := range [][]string{
		{"migrate-schema", "--unknown-flag"},
		{"migrate-schema", "--es-url", "http://127.0.0.1:0\x7f"},
		{"migrate-schema", "--es-url", "http://127.0.0.1:1"},
		{"migrate-schema", "--es-url", httpErrSrv.URL},
		{"migrate-schema", "--es-url", httpBadJSONSrv.URL},
		{"migrate-schema", "--es-url", httpGoodSrv.URL, "--out-dir", badJSONFile},
	} {
		if err := runCLI(context.Background(), tc, strings.NewReader(""), &outBuf, &stderrBuf, nil); err == nil {
			t.Fatalf("expected error for %v", tc)
		}
	}
}

func TestRound66_StaticRepoCLIFlagsAndEnv(t *testing.T) {
	if got := splitCommaTrimmedCLI(""); len(got) != 0 {
		t.Fatalf("expected nil/empty for blank splitCommaTrimmedCLI, got %v", got)
	}
	if got := splitCommaTrimmedCLI(" /a , , /b/c , "); len(got) != 2 || got[0] != "/a" || got[1] != "/b/c" {
		t.Fatalf("unexpected splitCommaTrimmedCLI output: %v", got)
	}

	repoA := t.TempDir()
	repoB := t.TempDir()
	assertStaticWiring := func(t *testing.T, args []string, expectedA, expectedURL string) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		var errBuf bytes.Buffer
		err := runServerErr(ctx, args, &errBuf, func(s *http.Server, certFile, keyFile string) error {
			defer cancel()
			// Dynamic PUT /_cluster/settings for path.repo / repositories.url.allowed_urls must reject with 400.
			for _, payload := range []string{
				`{"persistent":{"path.repo":["/tmp/evil"]}}`,
				`{"transient":{"repositories.url.allowed_urls":["http://*"]}}`,
			} {
				req := httptest.NewRequest(http.MethodPut, "/_cluster/settings", strings.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				s.Handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "illegal_argument_exception") {
					return fmt.Errorf("expected 400 illegal_argument_exception for %s, got %d: %s", payload, rec.Code, rec.Body.String())
				}
			}

			// GET /_cluster/settings?include_defaults=true must surface static defaults.
			reqDef := httptest.NewRequest(http.MethodGet, "/_cluster/settings?include_defaults=true", nil)
			recDef := httptest.NewRecorder()
			s.Handler.ServeHTTP(recDef, reqDef)
			if recDef.Code != http.StatusOK {
				return fmt.Errorf("GET _cluster/settings failed: %d %s", recDef.Code, recDef.Body.String())
			}
			bodyDef := recDef.Body.String()
			if !strings.Contains(bodyDef, expectedURL) {
				return fmt.Errorf("expected defaults.repositories.url.allowed_urls %q in %s", expectedURL, bodyDef)
			}

			// PUT fs repo under configured --path-repo / env must succeed; outside must fail 500.
			reqOK := httptest.NewRequest(http.MethodPut, "/_snapshot/fs_ok", strings.NewReader(fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, expectedA)))
			reqOK.Header.Set("Content-Type", "application/json")
			recOK := httptest.NewRecorder()
			s.Handler.ServeHTTP(recOK, reqOK)
			if recOK.Code != http.StatusOK {
				return fmt.Errorf("expected PUT fs repo in %q to succeed, got %d: %s", expectedA, recOK.Code, recOK.Body.String())
			}

			reqBad := httptest.NewRequest(http.MethodPut, "/_snapshot/fs_bad", strings.NewReader(`{"type":"fs","settings":{"location":"/etc"}}`))
			reqBad.Header.Set("Content-Type", "application/json")
			recBad := httptest.NewRecorder()
			s.Handler.ServeHTTP(recBad, reqBad)
			if recBad.Code == http.StatusOK {
				return fmt.Errorf("expected PUT fs repo outside path.repo to be rejected")
			}
			return http.ErrServerClosed
		})
		if err != nil {
			t.Fatalf("runServerErr failed: %v (stderr=%s)", err, errBuf.String())
		}
	}

	// 1. CLI flags
	assertStaticWiring(t, []string{
		"--listen", "127.0.0.1:0",
		"--doris-db", "r66_cli_db",
		"--in-memory",
		"--path-repo", filepath.ToSlash(repoA) + "," + filepath.ToSlash(repoB),
		"--repositories-url-allowed-urls", "http://127.0.0.1:*,https://snap.example/*",
	}, repoA, "https://snap.example/*")

	// 2. Env var fallback
	t.Setenv("DORIS_ES_PATH_REPO", filepath.ToSlash(repoB))
	t.Setenv("DORIS_ES_REPOSITORIES_URL_ALLOWED_URLS", "http://env.snap.internal/*")
	assertStaticWiring(t, []string{
		"--listen", "127.0.0.1:0",
		"--doris-db", "r66_env_db",
		"--in-memory",
	}, repoB, "http://env.snap.internal/*")
}
