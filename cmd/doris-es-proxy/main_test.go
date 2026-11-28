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
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	// 4. doctor subcommand (with mock FE HTTP server + non-zero exit verification)
	feServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"msg":"OK"}`))
	}))
	defer feServer.Close()

	var docOutBuf, docErrBuf bytes.Buffer
	oldExit := osExitFn
	exitCode := 0
	osExitFn = func(code int) {
		exitCode = code
	}
	docOut := captureStdout(t, func() {
		runDoctorSubcommand([]string{
			"--doris-dsn", "root:secret@tcp(127.0.0.1:1)/?timeout=50ms",
			"--doris-http", feServer.URL,
		})
	})
	osExitFn = oldExit
	if exitCode != 1 {
		t.Fatalf("expected doctor failure to invoke osExitFn(1), got %d", exitCode)
	}
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
	docOutBuf.Reset()
	docErrBuf.Reset()
	if err := runCLI(context.Background(), []string{"doctor", "--doris-dsn", "root:@tcp(127.0.0.1:1)/?timeout=20ms", "--doris-http", failFEServer.URL}, strings.NewReader(""), &docOutBuf, &docErrBuf, nil); err == nil {
		t.Fatalf("expected doctor to return non-zero error for HTTP 503 + unreachable MySQL")
	}
	if !strings.Contains(docOutBuf.String(), "FAIL (HTTP 503)") {
		t.Fatalf("expected FAIL (HTTP 503) in doctor output, got:\n%s", docOutBuf.String())
	}

	docOutBuf.Reset()
	docErrBuf.Reset()
	if err := runCLI(context.Background(), []string{"doctor", "--doris-dsn", "root:@tcp(127.0.0.1:1)/?timeout=20ms", "--doris-http", "http://127.0.0.1:1"}, strings.NewReader(""), &docOutBuf, &docErrBuf, nil); err == nil {
		t.Fatalf("expected doctor to return non-zero error for unreachable FE HTTP + MySQL")
	}
	if !strings.Contains(docOutBuf.String(), "UNREACHABLE") {
		t.Fatalf("expected UNREACHABLE in doctor output, got:\n%s", docOutBuf.String())
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

type mockDoctorSQLSpec struct {
	pingErr      error
	version      string
	versionErr   error
	comment      string
	commentErr   error
	backendsCols []string
	backendsRows [][]driver.Value
	backendsErr  error
	catalogCount int64
	catalogErr   error
}

var (
	mockDoctorSQLMu      sync.Mutex
	mockDoctorSQLByToken = make(map[string]mockDoctorSQLSpec)
	mockDoctorOnce       sync.Once
)

func registerMockDoctorSQLDriver(t *testing.T, token string, spec mockDoctorSQLSpec) {
	t.Helper()
	mockDoctorOnce.Do(func() {
		sql.Register("round67_doctor_mock", &mockDoctorDriver{})
	})
	mockDoctorSQLMu.Lock()
	mockDoctorSQLByToken[token] = spec
	mockDoctorSQLMu.Unlock()
	t.Cleanup(func() {
		mockDoctorSQLMu.Lock()
		delete(mockDoctorSQLByToken, token)
		mockDoctorSQLMu.Unlock()
	})
}

type mockDoctorDriver struct{}

func (d *mockDoctorDriver) Open(dsn string) (driver.Conn, error) {
	mockDoctorSQLMu.Lock()
	defer mockDoctorSQLMu.Unlock()
	for tok, spec := range mockDoctorSQLByToken {
		if strings.Contains(dsn, tok) {
			return &mockDoctorConn{spec: spec}, nil
		}
	}
	return &mockDoctorConn{}, nil
}

type mockDoctorConn struct {
	spec mockDoctorSQLSpec
}

func (c *mockDoctorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not implemented in mock")
}
func (c *mockDoctorConn) Close() error              { return nil }
func (c *mockDoctorConn) Begin() (driver.Tx, error) { return nil, errors.New("tx not supported") }

func (c *mockDoctorConn) Ping(context.Context) error {
	return c.spec.pingErr
}

func (c *mockDoctorConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

func (c *mockDoctorConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "SELECT VERSION()"):
		if c.spec.versionErr != nil {
			return nil, c.spec.versionErr
		}
		return &mockDoctorRows{
			cols: []string{"VERSION()"},
			rows: [][]driver.Value{{c.spec.version}},
		}, nil
	case strings.Contains(query, "@@version_comment"):
		if c.spec.commentErr != nil {
			return nil, c.spec.commentErr
		}
		return &mockDoctorRows{
			cols: []string{"@@version_comment"},
			rows: [][]driver.Value{{c.spec.comment}},
		}, nil
	case strings.Contains(query, "SHOW BACKENDS"):
		if c.spec.backendsErr != nil {
			return nil, c.spec.backendsErr
		}
		cols := c.spec.backendsCols
		if len(cols) == 0 {
			cols = []string{"BackendId", "Host", "HttpPort", "Alive"}
		}
		return &mockDoctorRows{
			cols: cols,
			rows: c.spec.backendsRows,
		}, nil
	case strings.Contains(query, "_es_catalog"):
		if c.spec.catalogErr != nil {
			return nil, c.spec.catalogErr
		}
		return &mockDoctorRows{
			cols: []string{"COUNT(*)"},
			rows: [][]driver.Value{{c.spec.catalogCount}},
		}, nil
	default:
		return &mockDoctorRows{cols: []string{"ok"}}, nil
	}
}

type mockDoctorRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *mockDoctorRows) Columns() []string { return r.cols }
func (r *mockDoctorRows) Close() error      { return nil }
func (r *mockDoctorRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

func TestRound67_RedactURLCredentialsAndLogBuilder(t *testing.T) {
	// Single URL redaction strips password and preserves host.
	single := redactURLCredentials("https://elastic:topSecret99@es.internal:9200/path?x=1")
	if strings.Contains(single, "topSecret99") || !strings.Contains(single, "es.internal:9200") {
		t.Fatalf("expected password stripped from URL, got %q", single)
	}

	// Empty username + password strips entire userinfo.
	emptyUser := redactURLCredentials("http://:onlySecret@fe.internal:8030")
	if strings.Contains(emptyUser, "onlySecret") || strings.Contains(emptyUser, "@") {
		t.Fatalf("expected empty-user password stripped cleanly, got %q", emptyUser)
	}

	// Comma-separated --doris-http endpoints redact every URL independently.
	multi := redactURLCredentials("http://u1:p1Secret@fe1:8030, https://u2:p2Secret@fe2:8030\r\n")
	if strings.Contains(multi, "p1Secret") || strings.Contains(multi, "p2Secret") || strings.ContainsAny(multi, "\r\n") {
		t.Fatalf("expected multi-URL credentials and CRLF stripped, got %q", multi)
	}
	if !strings.Contains(multi, "fe1:8030") || !strings.Contains(multi, "fe2:8030") {
		t.Fatalf("expected both FE hosts preserved in %q", multi)
	}

	// buildSlogLogger validates formats and levels.
	var jsonBuf bytes.Buffer
	jsonLog, err := buildSlogLogger("json", "warn", &jsonBuf)
	if err != nil {
		t.Fatalf("buildSlogLogger(json, warn) unexpected error: %v", err)
	}
	jsonLog.Info("should-not-appear")
	jsonLog.Warn("warn-visible", slog.String("k", "v"))
	outJSON := jsonBuf.String()
	if strings.Contains(outJSON, "should-not-appear") || !strings.Contains(outJSON, `"level":"WARN"`) || !strings.Contains(outJSON, `"k":"v"`) {
		t.Fatalf("unexpected JSON slog output: %q", outJSON)
	}

	var textBuf bytes.Buffer
	textLog, err := buildSlogLogger("TEXT", "DEBUG", &textBuf)
	if err != nil {
		t.Fatalf("buildSlogLogger(TEXT, DEBUG) unexpected error: %v", err)
	}
	textLog.Debug("debug-visible")
	if !strings.Contains(textBuf.String(), "level=DEBUG") || !strings.Contains(textBuf.String(), "debug-visible") {
		t.Fatalf("unexpected text slog output: %q", textBuf.String())
	}

	for _, bad := range []struct {
		fmt string
		lvl string
	}{
		{"xml", "info"},
		{"yaml", "debug"},
		{"json", "trace"},
		{"text", "fatal"},
	} {
		if _, err := buildSlogLogger(bad.fmt, bad.lvl, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected error for buildSlogLogger(%q, %q)", bad.fmt, bad.lvl)
		}
	}
}

func TestRound67_DorisVersionProbeAndVectorANNConfig(t *testing.T) {
	versionCases := []struct {
		raw  string
		want bool
	}{
		{"8.0.29-Doris-4.1.3", false},
		{"8.0.29-Doris-4.1.4", true},
		{"8.0.29-Doris-4.1.4-release", true},
		{"8.0.29-Doris-4.2.0", true},
		{"doris-4.1.3-rc01", false},
		{"doris-4.1.4-rc01", true},
		{"4.1.4", true},
		{"4.1.3", false},
		{"3.0.4", false},
		{"5.7.99", false},
		{"8.0.29", false},
		{"5.7.99 (Doris version doris-4.1.4-release)", true},
		{"5.7.99 (Doris version doris-4.1.3-release)", false},
		{"", false},
		{"invalid", false},
	}
	for _, tc := range versionCases {
		if got := dorisSupportsUniqueKeyANN(tc.raw); got != tc.want {
			t.Fatalf("dorisSupportsUniqueKeyANN(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}

	// Vector ANN resolution rules.
	ddlM, trM, push, uqANN, err := resolveVectorANNConfig("off", true, "")
	if err != nil || ddlM != "off" || trM != "off" || push || uqANN {
		t.Fatalf("off mismatch: (%q, %q, %v, %v, %v)", ddlM, trM, push, uqANN, err)
	}
	ddlM, trM, push, uqANN, err = resolveVectorANNConfig("auto", false, "")
	if err != nil || ddlM != "off" || trM != "off" || push || uqANN {
		t.Fatalf("auto on <=4.1.3 mismatch: (%q, %q, %v, %v, %v)", ddlM, trM, push, uqANN, err)
	}
	ddlM, trM, push, uqANN, err = resolveVectorANNConfig("auto", true, "")
	if err != nil || ddlM != "hnsw" || trM != "hnsw" || !push || !uqANN {
		t.Fatalf("auto on >=4.1.4 mismatch: (%q, %q, %v, %v, %v)", ddlM, trM, push, uqANN, err)
	}
	ddlM, trM, push, uqANN, err = resolveVectorANNConfig("ivf", false, "")
	if err != nil || ddlM != "ivf" || trM != "ivf" || push || uqANN {
		t.Fatalf("ivf on <=4.1.3 mismatch: (%q, %q, %v, %v, %v)", ddlM, trM, push, uqANN, err)
	}
	ddlM, trM, push, uqANN, err = resolveVectorANNConfig("ivf", true, "")
	if err != nil || ddlM != "ivf" || trM != "ivf" || !push || !uqANN {
		t.Fatalf("ivf on >=4.1.4 mismatch: (%q, %q, %v, %v, %v)", ddlM, trM, push, uqANN, err)
	}
	if _, _, _, _, err := resolveVectorANNConfig("pq", true, ""); err == nil {
		t.Fatalf("expected error for invalid --doris-vector-ann=pq")
	}
}

func TestRound67_NewServerFlagsAndValidation(t *testing.T) {
	// 1. Flag validation failures.
	invalidFlagCases := [][]string{
		{"--bm25-mode", "invalid-mode"},
		{"--bm25-max-rows", "0"},
		{"--bm25-max-rows", "-10"},
		{"--doris-replication-num", "0"},
		{"--doris-vector-ann", "bogus"},
		{"--catalog-sync-interval", "-1s"},
		{"--doris-max-open-conns", "0"},
		{"--doris-max-open-conns", "-5"},
		{"--doris-max-idle-conns", "-1"},
		{"--doris-conn-max-lifetime", "-1s"},
		{"--log-format", "xml"},
		{"--log-level", "verbose"},
	}
	for _, badArgs := range invalidFlagCases {
		var errBuf bytes.Buffer
		if err := runServerErr(context.Background(), badArgs, &errBuf, nil); err == nil {
			t.Fatalf("expected validation error for args %v", badArgs)
		}
	}

	// 2. Full Round-67 CLI flags wired in --in-memory mode with structured JSON logging.
	ctx, cancel := context.WithCancel(context.Background())
	var logOut bytes.Buffer
	err := runServerErr(ctx, []string{
		"--listen", "127.0.0.1:0",
		"--doris-db", "r67_flags_db",
		"--in-memory",
		"--bm25-mode", "doris-score",
		"--bm25-max-rows", "1234",
		"--doris-replication-num", "3",
		"--doris-replication-allocation", "tag.location.ssd:3",
		"--doris-cloud",
		"--doris-buckets-auto",
		"--doris-store-row-column=false",
		"--doris-vector-ann", "hnsw",
		"--catalog-sync-interval", "25ms",
		"--doris-max-open-conns", "25",
		"--doris-max-idle-conns", "5",
		"--doris-conn-max-lifetime", "2m",
		"--log-format", "json",
		"--log-level", "debug",
	}, &logOut, func(s *http.Server, _, _ string) error {
		defer cancel()
		time.Sleep(30 * time.Millisecond)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		s.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return fmt.Errorf("expected 200 OK on /, got %d", rec.Code)
		}
		// Verify DDL options & BM25 settings propagated by inspecting /_doris/ddl on a created index.
		putReq := httptest.NewRequest(http.MethodPut, "/r67_cli_vec", strings.NewReader(`{"mappings":{"properties":{"title":{"type":"text"}}}}`))
		putReq.Header.Set("Content-Type", "application/json")
		putRec := httptest.NewRecorder()
		s.Handler.ServeHTTP(putRec, putReq)
		if putRec.Code != http.StatusOK {
			return fmt.Errorf("PUT /r67_cli_vec failed: %d %s", putRec.Code, putRec.Body.String())
		}
		ddlReq := httptest.NewRequest(http.MethodGet, "/r67_cli_vec/_doris/ddl?format=txt", nil)
		ddlRec := httptest.NewRecorder()
		s.Handler.ServeHTTP(ddlRec, ddlReq)
		ddlTxt := ddlRec.Body.String()
		if !strings.Contains(ddlTxt, `"store_row_column" = "false"`) ||
			strings.Contains(ddlTxt, `"replication_num"`) ||
			strings.Contains(ddlTxt, `"replication_allocation"`) {
			return fmt.Errorf("expected CloudMode + store_row_column=false in DDL, got:\n%s", ddlTxt)
		}
		return http.ErrServerClosed
	})
	if err != nil {
		t.Fatalf("runServerErr with Round-67 flags failed: %v", err)
	}
	logs := logOut.String()
	if !strings.Contains(logs, `"msg":"http_request"`) || !strings.Contains(logs, `"msg":"background catalog sync loop enabled"`) {
		t.Fatalf("expected structured JSON logs from slog, got:\n%s", logs)
	}

	// 3. Env var defaults + --doris-http credential redaction in non-in-memory mode + --es-url redaction in migrate-schema.
	t.Setenv("BM25_MODE", "approx")
	t.Setenv("BM25_MAX_ROWS", "9999")
	t.Setenv("DORIS_REPLICATION_NUM", "2")
	t.Setenv("DORIS_REPLICATION_ALLOCATION", "tag.location.hot:2")
	t.Setenv("DORIS_CLOUD", "false")
	t.Setenv("DORIS_BUCKETS_AUTO", "true")
	t.Setenv("DORIS_STORE_ROW_COLUMN", "true")
	t.Setenv("DORIS_VECTOR_ANN", "auto")
	t.Setenv("CATALOG_SYNC_INTERVAL", "0s")
	t.Setenv("DORIS_MAX_OPEN_CONNS", "30")
	t.Setenv("DORIS_MAX_IDLE_CONNS", "7")
	t.Setenv("DORIS_CONN_MAX_LIFETIME", "3m")
	t.Setenv("LOG_FORMAT", "text")
	t.Setenv("LOG_LEVEL", "info")

	var sqlLogOut bytes.Buffer
	sqlCtx, sqlCancel := context.WithCancel(context.Background())
	defer sqlCancel()
	err = runServerErr(sqlCtx, []string{
		"--listen", "127.0.0.1:0",
		"--doris-dsn", "root:dbSecret123@tcp(127.0.0.1:1)/?timeout=20ms",
		"--doris-http", "http://feUser:feSecret456@127.0.0.1:1",
		"--doris-db", "r67_env_db",
	}, &sqlLogOut, func(s *http.Server, _, _ string) error {
		return http.ErrServerClosed
	})
	if err != nil {
		t.Fatalf("env fallback runServerErr failed: %v", err)
	}
	sqlLogs := sqlLogOut.String()
	if strings.Contains(sqlLogs, "dbSecret123") || strings.Contains(sqlLogs, "feSecret456") {
		t.Fatalf("expected credentials redacted from startup logs, got:\n%s", sqlLogs)
	}
	if !strings.Contains(sqlLogs, "max_open_conns=30") || !strings.Contains(sqlLogs, "max_idle_conns=7") {
		t.Fatalf("expected pool settings in text logs, got:\n%s", sqlLogs)
	}

	// migrate-schema error must also redact --es-url credentials.
	var migOut, migErr bytes.Buffer
	migRunErr := runMigrateSchemaSubcommandErr([]string{
		"--es-url", "http://esAdmin:esTopSecret789@127.0.0.1:1",
	}, &migOut, &migErr)
	if migRunErr == nil {
		t.Fatalf("expected migrate-schema error on unreachable ES URL")
	}
	if strings.Contains(migRunErr.Error(), "esTopSecret789") {
		t.Fatalf("expected --es-url password redacted from migrate-schema error, got: %v", migRunErr)
	}
}

func TestRound67_DoctorSubcommandHardened(t *testing.T) {
	feOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/bootstrap" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"msg":"OK"}`))
	}))
	defer feOK.Close()

	feFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer feFail.Close()

	// Helper replacing scheme with http://user:pass@... to verify --doris-http credential redaction.
	feOKWithCreds := strings.Replace(feOK.URL, "http://", "http://feadm:feSuperSecret@", 1)

	// 1. Healthy cluster with populated _es_catalog -> returns nil and redacts FE HTTP password.
	registerMockDoctorSQLDriver(t, "doc_case_ok", mockDoctorSQLSpec{
		version:      "8.0.29-Doris-4.1.4",
		comment:      "Doris version doris-4.1.4",
		backendsRows: [][]driver.Value{{"1", "10.0.0.1", "8040", "true"}},
		catalogCount: 7,
	})
	var outBuf, errBuf bytes.Buffer
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:dbPass@tcp(127.0.0.1:9030)/doc_case_ok",
		"--doris-http", feOKWithCreds,
		"--doris-db", "es_prod",
	}, &outBuf, &errBuf); err != nil {
		t.Fatalf("expected healthy doctor check to succeed, got: %v\noutput:\n%s", err, outBuf.String())
	}
	outStr := outBuf.String()
	if strings.Contains(outStr, "feSuperSecret") || strings.Contains(outStr, "dbPass") {
		t.Fatalf("expected doctor output to redact credentials, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "OK (1/1 alive)") || !strings.Contains(outStr, "OK (7 entries)") {
		t.Fatalf("expected alive backend and catalog entry checks in output:\n%s", outStr)
	}

	// 2. Fresh uninitialized cluster (missing database or missing _es_catalog) -> non-fatal NOT_INITIALIZED (ok).
	for i, catErr := range []error{
		errors.New("Error 1049 (42000): Unknown database 'es_fresh'"),
		errors.New("Error 1146 (42S02): Table 'es_fresh._es_catalog' doesn't exist"),
	} {
		tok := fmt.Sprintf("doc_case_uninit_%d", i)
		registerMockDoctorSQLDriver(t, tok, mockDoctorSQLSpec{
			version:      "8.0.29-Doris-4.1.3",
			comment:      "Doris",
			backendsRows: [][]driver.Value{{"1", "10.0.0.1", "8040", "true"}},
			catalogErr:   catErr,
		})
		outBuf.Reset()
		if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
			"--doris-dsn", "root:@tcp(127.0.0.1:9030)/" + tok,
			"--doris-http", feOK.URL,
			"--doris-db", "es_fresh",
		}, &outBuf, &errBuf); err != nil {
			t.Fatalf("expected missing catalog (%v) to be non-fatal, got err=%v\noutput:\n%s", catErr, err, outBuf.String())
		}
		if !strings.Contains(outBuf.String(), "NOT_INITIALIZED (ok)") {
			t.Fatalf("expected NOT_INITIALIZED (ok) in output:\n%s", outBuf.String())
		}
	}

	// 3. Fatal check failures must return non-nil error:
	// (a) MySQL ping failure
	registerMockDoctorSQLDriver(t, "doc_case_ping_err", mockDoctorSQLSpec{
		pingErr: errors.New("connection refused"),
	})
	outBuf.Reset()
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:@tcp(127.0.0.1:9030)/doc_case_ping_err",
		"--doris-http", feOK.URL,
	}, &outBuf, &errBuf); err == nil {
		t.Fatalf("expected error on MySQL ping failure")
	}

	// (b) 0 alive backends
	registerMockDoctorSQLDriver(t, "doc_case_zero_be", mockDoctorSQLSpec{
		version:      "4.1.3",
		backendsRows: [][]driver.Value{{"1", "10.0.0.1", "8040", "false"}},
		catalogCount: 1,
	})
	outBuf.Reset()
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:@tcp(127.0.0.1:9030)/doc_case_zero_be",
		"--doris-http", feOK.URL,
	}, &outBuf, &errBuf); err == nil || !strings.Contains(outBuf.String(), "FAIL (0/1 alive)") {
		t.Fatalf("expected error and 0/1 alive message, got err=%v output:\n%s", err, outBuf.String())
	}

	// (c) SHOW BACKENDS query error
	registerMockDoctorSQLDriver(t, "doc_case_be_err", mockDoctorSQLSpec{
		version:     "4.1.3",
		backendsErr: errors.New("privilege denied"),
	})
	outBuf.Reset()
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:@tcp(127.0.0.1:9030)/doc_case_be_err",
		"--doris-http", feOK.URL,
	}, &outBuf, &errBuf); err == nil {
		t.Fatalf("expected error on SHOW BACKENDS failure")
	}

	// (d) FE HTTP 503 with healthy MySQL + BE
	registerMockDoctorSQLDriver(t, "doc_case_http_fail", mockDoctorSQLSpec{
		version:      "4.1.3",
		backendsRows: [][]driver.Value{{"1", "10.0.0.1", "8040", "true"}},
		catalogCount: 1,
	})
	outBuf.Reset()
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:@tcp(127.0.0.1:9030)/doc_case_http_fail",
		"--doris-http", feFail.URL,
	}, &outBuf, &errBuf); err == nil || !strings.Contains(outBuf.String(), "FAIL (HTTP 503)") {
		t.Fatalf("expected error on FE HTTP 503, got err=%v output:\n%s", err, outBuf.String())
	}

	// (e) Non-missing catalog permission error must fail doctor
	registerMockDoctorSQLDriver(t, "doc_case_cat_perm", mockDoctorSQLSpec{
		version:      "4.1.3",
		backendsRows: [][]driver.Value{{"1", "10.0.0.1", "8040", "true"}},
		catalogErr:   errors.New("SELECT command denied to user"),
	})
	outBuf.Reset()
	if err := runDoctorSubcommandWithDriver("round67_doctor_mock", []string{
		"--doris-dsn", "root:@tcp(127.0.0.1:9030)/doc_case_cat_perm",
		"--doris-http", feOK.URL,
	}, &outBuf, &errBuf); err == nil {
		t.Fatalf("expected error on catalog permission failure")
	}
}

func TestRound67_SleepSubcommand(t *testing.T) {
	if err := runCLI(context.Background(), []string{"sleep", "1ms"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, nil); err != nil {
		t.Fatalf("sleep 1ms failed: %v", err)
	}
	if err := runCLI(context.Background(), []string{"sleep", "0"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, nil); err != nil {
		t.Fatalf("sleep 0 failed: %v", err)
	}
	if err := runCLI(context.Background(), []string{"sleep", "not-a-duration"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, nil); err == nil {
		t.Fatalf("expected error for invalid sleep duration")
	}
}
