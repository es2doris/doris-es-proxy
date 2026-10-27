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
}
