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
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

var version = "v0.21.0"

func envOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func envBoolOrDefault(key string, fallback bool) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch val {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envIntOrDefault(key string, fallback int) int {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return fallback
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			return parsed
		}
	}
	return fallback
}

func redactDSN(dsn string) string {
	atIdx := strings.LastIndexByte(dsn, '@')
	if atIdx <= 0 {
		return dsn
	}
	colonIdx := strings.IndexByte(dsn[:atIdx], ':')
	if colonIdx < 0 || colonIdx+1 == atIdx {
		return dsn
	}
	return dsn[:colonIdx+1] + "***" + dsn[atIdx:]
}

func redactURLCredentials(rawURL string) string {
	trimmed := strings.NewReplacer("\n", "", "\r", "").Replace(strings.TrimSpace(rawURL))
	if trimmed == "" {
		return ""
	}
	if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Redacted()
	}
	return redactDSN(trimmed)
}

func escapeDorisBacktickIdent(name string) string {
	return strings.ReplaceAll(schema.SanitizeDorisIdentifier(name), "`", "``")
}

type serverListenFunc func(srv *http.Server, tlsCertFile, tlsKeyFile string) error

func main() {
	err := runCLI(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		log.Fatalf("%v", err)
	}
}

func runCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, listenFn serverListenFunc) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			_, _ = fmt.Fprintf(stdout, "doris-es-proxy %s\n", version)
			return nil
		case "transpile":
			return runTranspileSubcommandErr(args[1:], stdin, stdout, stderr)
		case "ddl":
			return runDDLSubcommandErr(args[1:], stdin, stdout, stderr)
		case "doctor":
			return runDoctorSubcommandErr(args[1:], stdout, stderr)
		case "migrate-schema":
			return runMigrateSchemaSubcommandErr(args[1:], stdout, stderr)
		}
	}
	return runServerErr(ctx, args, stderr, listenFn)
}

func runServerErr(ctx context.Context, args []string, flagOut io.Writer, listenFn serverListenFunc) error {
	fs := flag.NewFlagSet("doris-es-proxy", flag.ContinueOnError)
	if flagOut != nil {
		fs.SetOutput(flagOut)
	}
	var (
		listenAddr                = fs.String("listen", envOrDefault("LISTEN_ADDR", ":9200"), "Elasticsearch HTTP REST listen address (env: LISTEN_ADDR)")
		dorisDSN                  = fs.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s&readTimeout=30s&writeTimeout=30s"), "Apache Doris FE MySQL wire protocol DSN (env: DORIS_DSN)")
		dorisHTTP                 = fs.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint for Stream Load (env: DORIS_HTTP)")
		dorisUser                 = fs.String("doris-user", envOrDefault("DORIS_USER", "root"), "Apache Doris username (env: DORIS_USER)")
		dorisPassword             = fs.String("doris-password", envOrDefault("DORIS_PASSWORD", ""), "Apache Doris password (env: DORIS_PASSWORD)")
		dorisDB                   = fs.String("doris-db", envOrDefault("DORIS_DB", "es_compat"), "Target Apache Doris database name (env: DORIS_DB)")
		shadowESURL               = fs.String("shadow-es-url", envOrDefault("SHADOW_ES_URL", ""), "Optional legacy Elasticsearch URL for dual-read shadow parity verification (env: SHADOW_ES_URL)")
		useDoris4SearchFunc       = fs.Bool("doris4-search-fn", envBoolOrDefault("DORIS4_SEARCH_FN", false), "Push query_string down to Apache Doris 4.0 SEARCH() SQL function (env: DORIS4_SEARCH_FN)")
		autoPromote               = fs.Bool("auto-promote", envBoolOrDefault("AUTO_PROMOTE", false), "Automatically promote hot unindexed _doc[...] VARIANT fields to f__* inverted index columns (env: AUTO_PROMOTE)")
		bulkCoalesceMs            = fs.Int("bulk-coalesce-ms", envIntOrDefault("BULK_COALESCE_MS", 0), "Group-commit Stream Load micro-batch window in milliseconds across concurrent writes (0 disables, env: BULK_COALESCE_MS)")
		bulkCoalesceBytes         = fs.Int("bulk-coalesce-bytes", envIntOrDefault("BULK_COALESCE_BYTES", proxy.DefaultBulkCoalesceMaxBytes), "Maximum byte size of a coalesced Stream Load batch before immediate flush (env: BULK_COALESCE_BYTES)")
		queryCacheTTL             = fs.Duration("query-cache-ttl", envDurationOrDefault("QUERY_CACHE_TTL", 0), "Optional TTL for caching search responses with automatic write invalidation (e.g. 5s, 0s disables, env: QUERY_CACHE_TTL)")
		basicAuthUser             = fs.String("basic-auth-user", envOrDefault("BASIC_AUTH_USER", ""), "Optional inbound HTTP Basic Auth username (env: BASIC_AUTH_USER)")
		basicAuthPass             = fs.String("basic-auth-pass", envOrDefault("BASIC_AUTH_PASS", ""), "Optional inbound HTTP Basic Auth password (env: BASIC_AUTH_PASS)")
		apiKey                    = fs.String("api-key", envOrDefault("API_KEY", ""), "Optional inbound Elasticsearch ApiKey / Bearer token (env: API_KEY)")
		tlsCertFile               = fs.String("tls-cert", envOrDefault("TLS_CERT_FILE", ""), "Optional TLS server certificate PEM file for HTTPS (env: TLS_CERT_FILE)")
		tlsKeyFile                = fs.String("tls-key", envOrDefault("TLS_KEY_FILE", ""), "Optional TLS private key PEM file for HTTPS (env: TLS_KEY_FILE)")
		reindexRemoteWhitelist    = fs.String("reindex-remote-whitelist", envOrDefault("DORIS_ES_REINDEX_REMOTE_WHITELIST", ""), "Static comma-separated host:port whitelist for remote _reindex (env: DORIS_ES_REINDEX_REMOTE_WHITELIST)")
		reindexRemoteAllowPrivate = fs.Bool("reindex-remote-allow-private", envBoolOrDefault("DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE", false), "Allow private, loopback, link-local, and CGNAT IPs for remote _reindex (env: DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE)")
		esTargetVersion           = fs.String("es-version", envOrDefault("ES_TARGET_VERSION", ""), "Optional explicit Elasticsearch compatibility version (e.g. 8.15.5 or 7.10.2, env: ES_TARGET_VERSION)")
		inMemoryMode              = fs.Bool("in-memory", envBoolOrDefault("IN_MEMORY", false), "Run with in-memory shredded Doris emulator (env: IN_MEMORY)")
		logSQL                    = fs.Bool("log-sql", envBoolOrDefault("LOG_SQL", false), "Log transpiled Apache Doris DDL, Stream Load, HitsSQL, and AggsSQL (env: LOG_SQL)")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: doris-es-proxy [subcommand] [flags]\n\nSubcommands:\n  transpile       Offline ES Query DSL -> Apache Doris SQL transpiler\n  ddl             Offline ES _mapping -> Apache Doris CREATE TABLE DDL compiler\n  doctor          Live Apache Doris cluster & inverted-index readiness checker\n  migrate-schema  Live Elasticsearch cluster -> Apache Doris DDL & template exporter\n  version         Print proxy version\n\nServer Flags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if (*basicAuthUser != "") != (*basicAuthPass != "") {
		return fmt.Errorf("both --basic-auth-user and --basic-auth-pass must be provided together when Basic Auth is enabled")
	}
	if (*tlsCertFile != "") != (*tlsKeyFile != "") {
		return fmt.Errorf("both --tls-cert and --tls-key must be provided together when TLS is enabled")
	}

	var backend proxy.DorisBackend
	if *inMemoryMode {
		backend = proxy.NewMemoryBackend(*logSQL)
		log.Printf("doris-es-proxy starting in --in-memory emulator mode on %s (Doris DB=%q, log-sql=%v)", *listenAddr, *dorisDB, *logSQL)
	} else {
		effectiveDSN := proxy.ApplyDSNAuth(*dorisDSN, *dorisUser, *dorisPassword)
		var sqlDB *sql.DB
		if effectiveDSN != "" {
			db, err := sql.Open("mysql", effectiveDSN)
			if err != nil {
				return fmt.Errorf("failed to configure Doris MySQL driver: %w", err)
			}
			db.SetMaxOpenConns(64)
			db.SetMaxIdleConns(16)
			db.SetConnMaxIdleTime(2 * time.Minute)
			db.SetConnMaxLifetime(5 * time.Minute)
			sqlDB = db
			defer func() { _ = sqlDB.Close() }()

			dbCtx, dbCancel := context.WithTimeout(ctx, 5*time.Second)
			// #nosec G201 -- identifier is strictly sanitized via schema.SanitizeDorisIdentifier and backtick-escaped
			createDBSQL := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", escapeDorisBacktickIdent(*dorisDB))
			if _, err := sqlDB.ExecContext(dbCtx, createDBSQL); err != nil {
				log.Printf("warning: initial Doris database bootstrap (%s) deferred until cluster is reachable: %v", createDBSQL, err)
			}
			dbCancel()
		}

		slClient := proxy.NewStreamLoadClient(proxy.StreamLoadConfig{
			FEHTTPEndpoint: *dorisHTTP,
			User:           *dorisUser,
			Password:       *dorisPassword,
			Database:       *dorisDB,
			Timeout:        30 * time.Second,
		})

		sqlBackend := proxy.NewDorisSQLBackend(sqlDB, slClient)
		sqlBackend.SetLogSQL(*logSQL)
		backend = sqlBackend
		log.Printf("doris-es-proxy listening on %s (Doris DB=%q, MySQL DSN=%q, FE HTTP=%q, log-sql=%v)", *listenAddr, *dorisDB, redactDSN(effectiveDSN), *dorisHTTP, *logSQL)
	}

	srv := proxy.NewServer(*dorisDB, backend, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *useDoris4SearchFunc,
	})
	if strings.TrimSpace(*esTargetVersion) != "" {
		srv.SetTargetESVersion(strings.TrimSpace(*esTargetVersion))
	}
	srv.SetStaticRemoteReindexWhitelist(*reindexRemoteWhitelist)
	srv.SetRemoteReindexAllowPrivateIPs(*reindexRemoteAllowPrivate)
	if *shadowESURL != "" {
		srv.SetShadowESURL(*shadowESURL)
		// #nosec G706 -- shadow URL credentials and CR/LF are stripped via redactURLCredentials
		log.Printf("shadow dual-read verification enabled against %s (metrics at GET /_doris/shadow_stats)", redactURLCredentials(*shadowESURL))
	}
	if *autoPromote {
		srv.SetAutoPromoteThreshold(3)
		log.Printf("auto-promote enabled: unindexed _doc[...] fields queried >= 3 times will be promoted to f__* columns")
	}
	if *bulkCoalesceMs > 0 {
		srv.SetBulkCoalesce(time.Duration(*bulkCoalesceMs)*time.Millisecond, *bulkCoalesceBytes)
		log.Printf("group-commit Stream Load coalescer enabled (window=%dms, max-bytes=%d)", *bulkCoalesceMs, *bulkCoalesceBytes)
	}
	if *queryCacheTTL > 0 {
		srv.SetQueryCacheTTL(*queryCacheTTL, proxy.DefaultQueryCacheMaxEntries)
		log.Printf("search query result cache enabled (ttl=%s, max-entries=%d)", *queryCacheTTL, proxy.DefaultQueryCacheMaxEntries)
	}
	if *basicAuthUser != "" || *basicAuthPass != "" || *apiKey != "" {
		srv.SetAuth(*basicAuthUser, *basicAuthPass, *apiKey)
		log.Printf("inbound HTTP authentication enabled (basic_auth=%v, api_key=%v)", *basicAuthUser != "" || *basicAuthPass != "", *apiKey != "")
	}
	bootCtx, bootCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := srv.BootstrapCatalog(bootCtx); err != nil {
		log.Printf("warning: initial _es_catalog bootstrap deferred: %v", err)
	}
	bootCancel()

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-sigCtx.Done()
		log.Printf("shutting down doris-es-proxy gracefully...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutCtx)
		_ = srv.Close(shutCtx)
	}()

	if listenFn == nil {
		listenFn = func(s *http.Server, certFile, keyFile string) error {
			if certFile != "" && keyFile != "" {
				return s.ListenAndServeTLS(certFile, keyFile)
			}
			return s.ListenAndServe()
		}
	}
	if *tlsCertFile != "" && *tlsKeyFile != "" {
		log.Printf("HTTPS TLS listener enabled (cert=%s)", *tlsCertFile)
	}
	serveErr := listenFn(httpServer, *tlsCertFile, *tlsKeyFile)
	stop()
	<-shutdownDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("server exited: %w", serveErr)
	}
	return nil
}

func runTranspileSubcommand(args []string) {
	if err := runTranspileSubcommandErr(args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatalf("%v", err)
	}
}

func runTranspileSubcommandErr(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("transpile", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	indexName := fs.String("index", "table_search_index", "Target Elasticsearch index name")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	mappingPath := fs.String("mapping", "", "Optional path to Elasticsearch mapping JSON file")
	queryPath := fs.String("query", "", "Optional path to Elasticsearch _search JSON file (defaults to stdin)")
	doris4Search := fs.Bool("doris4-search-fn", false, "Use Apache Doris 4.0 SEARCH() function")
	format := fs.String("format", "sql", "Output format: sql or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var mappingSpec *esast.MappingSpec
	if *mappingPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		raw, err := os.ReadFile(filepath.Clean(*mappingPath))
		if err != nil {
			return fmt.Errorf("failed to read --mapping %s: %w", *mappingPath, err)
		}
		mappingSpec, err = parseMappingJSON(raw)
		if err != nil {
			return fmt.Errorf("failed to parse --mapping %s: %w", *mappingPath, err)
		}
	}

	var queryBytes []byte
	var err error
	if *queryPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		queryBytes, err = os.ReadFile(filepath.Clean(*queryPath))
	} else {
		queryBytes, err = io.ReadAll(stdin)
	}
	if err != nil {
		return fmt.Errorf("failed to read search query payload: %w", err)
	}

	var req esast.SearchRequest
	if len(bytes.TrimSpace(queryBytes)) > 0 {
		if err := json.Unmarshal(queryBytes, &req); err != nil {
			return fmt.Errorf("invalid Elasticsearch _search JSON: %w", err)
		}
	}

	idxSchema := schema.CompileIndexSchema(*dorisDB, *indexName, mappingSpec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *doris4Search,
	})
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		return fmt.Errorf("transpile error: %w", err)
	}

	normHitsSQL := proxy.NormalizeDorisSQL(plan.HitsSQL)
	normAggsSQL := proxy.NormalizeDorisSQL(plan.AggsSQL)

	if strings.EqualFold(*format, "json") {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"index":               *indexName,
			"doris_database":      idxSchema.DorisDB,
			"doris_table":         idxSchema.DorisTable,
			"create_table_ddl":    schema.GenerateCreateTableDDL(idxSchema),
			"hits_sql":            plan.HitsSQL,
			"hits_sql_normalized": normHitsSQL,
			"aggs_sql":            plan.AggsSQL,
			"aggs_sql_normalized": normAggsSQL,
		})
		return nil
	}

	if normHitsSQL != "" {
		_, _ = fmt.Fprintf(stdout, "-- [HitsSQL] (%s.%s)\n%s;\n", idxSchema.DorisDB, idxSchema.DorisTable, normHitsSQL)
	}
	if normAggsSQL != "" {
		if normHitsSQL != "" {
			_, _ = fmt.Fprintln(stdout)
		}
		_, _ = fmt.Fprintf(stdout, "-- [AggsSQL - Nereids Multi-Cast CTE] (%s.%s)\n%s;\n", idxSchema.DorisDB, idxSchema.DorisTable, normAggsSQL)
	}
	return nil
}

func runDDLSubcommand(args []string) {
	if err := runDDLSubcommandErr(args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatalf("%v", err)
	}
}

func runDDLSubcommandErr(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ddl", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	indexName := fs.String("index", "table_search_index", "Target Elasticsearch index name")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	mappingPath := fs.String("mapping", "", "Optional path to Elasticsearch mapping JSON file (defaults to stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var raw []byte
	var err error
	if *mappingPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		raw, err = os.ReadFile(filepath.Clean(*mappingPath))
	} else {
		raw, err = io.ReadAll(stdin)
	}
	if err != nil {
		return fmt.Errorf("failed to read mapping JSON: %w", err)
	}

	var spec *esast.MappingSpec
	if len(bytes.TrimSpace(raw)) > 0 {
		spec, err = parseMappingJSON(raw)
		if err != nil {
			return fmt.Errorf("invalid Elasticsearch mapping JSON: %w", err)
		}
	}
	idxSchema := schema.CompileIndexSchema(*dorisDB, *indexName, spec)
	_, _ = fmt.Fprintln(stdout, schema.GenerateCreateTableDDL(idxSchema))
	return nil
}

func runDoctorSubcommand(args []string) {
	if err := runDoctorSubcommandErr(args, os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}

func runDoctorSubcommandErr(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	dorisDSN := fs.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s"), "Apache Doris FE MySQL DSN")
	dorisHTTP := fs.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint")
	dorisUser := fs.String("doris-user", envOrDefault("DORIS_USER", "root"), "Apache Doris username")
	dorisPassword := fs.String("doris-password", envOrDefault("DORIS_PASSWORD", ""), "Apache Doris password")
	if err := fs.Parse(args); err != nil {
		return err
	}

	effectiveDSN := proxy.ApplyDSNAuth(*dorisDSN, *dorisUser, *dorisPassword)
	_, _ = fmt.Fprintf(stdout, "==> doris-es-proxy %s Connectivity Doctor\n", version)
	_, _ = fmt.Fprintf(stdout, "  1. Checking Doris FE MySQL (%s)... ", redactDSN(effectiveDSN))
	db, err := sql.Open("mysql", effectiveDSN)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "FAIL (%v)\n", err)
		return err
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var verComment string
	if err := db.QueryRowContext(ctx, "SELECT @@version_comment").Scan(&verComment); err != nil {
		_, _ = fmt.Fprintf(stdout, "UNREACHABLE (%v)\n", err)
	} else {
		_, _ = fmt.Fprintf(stdout, "OK (%s)\n", verComment)
	}

	_, _ = fmt.Fprintf(stdout, "  2. Checking Doris FE HTTP (%s)... ", *dorisHTTP)
	client := &http.Client{Timeout: 3 * time.Second}
	// #nosec G704 -- operator-supplied --doris-http endpoint in CLI doctor subcommand
	resp, err := client.Get(strings.TrimRight(*dorisHTTP, "/") + "/api/bootstrap")
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "UNREACHABLE (%v)\n", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			_, _ = fmt.Fprintf(stdout, "FAIL (HTTP %d)\n", resp.StatusCode)
		} else {
			_, _ = fmt.Fprintf(stdout, "OK (HTTP %d)\n", resp.StatusCode)
		}
	}
	return nil
}

func runMigrateSchemaSubcommand(args []string) {
	if err := runMigrateSchemaSubcommandErr(args, os.Stdout, os.Stderr); err != nil {
		log.Fatalf("%v", err)
	}
}

func runMigrateSchemaSubcommandErr(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate-schema", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	esURL := fs.String("es-url", envOrDefault("ES_URL", "http://127.0.0.1:9200"), "Source Elasticsearch / OpenSearch HTTP URL (env: ES_URL)")
	indexPattern := fs.String("index", "_all", "Index name or pattern to migrate")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	outDir := fs.String("out-dir", "", "Optional directory to write per-index .sql DDL files (defaults to stdout)")
	esUser := fs.String("es-user", envOrDefault("ES_USER", ""), "Optional source Elasticsearch Basic Auth username (env: ES_USER)")
	esPassword := fs.String("es-password", envOrDefault("ES_PASSWORD", ""), "Optional source Elasticsearch Basic Auth password (env: ES_PASSWORD)")
	esAPIKey := fs.String("es-api-key", envOrDefault("ES_API_KEY", ""), "Optional source Elasticsearch ApiKey / Bearer token (env: ES_API_KEY)")
	esInsecure := fs.Bool("es-insecure-skip-verify", false, "Skip TLS certificate verification when connecting to source Elasticsearch")
	if err := fs.Parse(args); err != nil {
		return err
	}

	endpoint := strings.TrimRight(*esURL, "/") + "/" + url.PathEscape(*indexPattern) + "/_mapping"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *esInsecure {
		// #nosec G402 -- explicit operator flag --es-insecure-skip-verify for self-signed ES clusters
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpReq, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("invalid endpoint %s: %w", endpoint, err)
	}
	if *esAPIKey != "" {
		if strings.HasPrefix(strings.ToLower(*esAPIKey), "apikey ") || strings.HasPrefix(strings.ToLower(*esAPIKey), "bearer ") {
			httpReq.Header.Set("Authorization", *esAPIKey)
		} else {
			httpReq.Header.Set("Authorization", "ApiKey "+*esAPIKey)
		}
	} else if *esUser != "" || *esPassword != "" {
		httpReq.SetBasicAuth(*esUser, *esPassword)
	}
	// #nosec G704 -- operator-supplied --es-url in CLI migrate-schema subcommand
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to fetch mappings from %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read mapping response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mapping endpoint %s returned HTTP %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var byIndex map[string]struct {
		Mappings *esast.MappingSpec `json:"mappings"`
	}
	if err := json.Unmarshal(raw, &byIndex); err != nil {
		return fmt.Errorf("invalid Elasticsearch _mapping response: %w", err)
	}

	idxNames := make([]string, 0, len(byIndex))
	for k := range byIndex {
		if !strings.HasPrefix(k, ".") {
			idxNames = append(idxNames, k)
		}
	}
	sort.Strings(idxNames)

	if *outDir != "" {
		cleanDir := filepath.Clean(*outDir)
		if err := os.MkdirAll(cleanDir, 0o750); err != nil {
			return fmt.Errorf("failed to create --out-dir %s: %w", cleanDir, err)
		}
		dbSQL := fmt.Sprintf("-- Generated by doris-es-proxy %s migrate-schema\nCREATE DATABASE IF NOT EXISTS `%s`;\n", version, escapeDorisBacktickIdent(*dorisDB))
		if err := os.WriteFile(filepath.Join(cleanDir, "00_create_database.sql"), []byte(dbSQL), 0o600); err != nil {
			return fmt.Errorf("failed to write 00_create_database.sql: %w", err)
		}
		for _, idxName := range idxNames {
			entry := byIndex[idxName]
			compiled := schema.CompileIndexSchema(*dorisDB, idxName, entry.Mappings)
			safeCommentName := strings.NewReplacer("\n", " ", "\r", " ").Replace(idxName)
			ddlContent := fmt.Sprintf("-- Index: %s (Doris table: `%s`.`%s`)\n%s\n", safeCommentName, strings.ReplaceAll(compiled.DorisDB, "`", "``"), strings.ReplaceAll(compiled.DorisTable, "`", "``"), schema.GenerateCreateTableDDL(compiled))
			fileName := schema.SanitizeDorisIdentifier(idxName) + ".sql"
			if err := os.WriteFile(filepath.Join(cleanDir, fileName), []byte(ddlContent), 0o600); err != nil {
				return fmt.Errorf("failed to write %s: %w", fileName, err)
			}
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "-- Generated by doris-es-proxy %s migrate-schema\n", version)
	_, _ = fmt.Fprintf(stdout, "CREATE DATABASE IF NOT EXISTS `%s`;\n\n", escapeDorisBacktickIdent(*dorisDB))
	for _, idxName := range idxNames {
		entry := byIndex[idxName]
		compiled := schema.CompileIndexSchema(*dorisDB, idxName, entry.Mappings)
		safeCommentName := strings.NewReplacer("\n", " ", "\r", " ").Replace(idxName)
		_, _ = fmt.Fprintf(stdout, "-- Index: %s (Doris table: `%s`.`%s`)\n%s\n\n", safeCommentName, strings.ReplaceAll(compiled.DorisDB, "`", "``"), strings.ReplaceAll(compiled.DorisTable, "`", "``"), schema.GenerateCreateTableDDL(compiled))
	}
	return nil
}

func parseMappingJSON(raw []byte) (*esast.MappingSpec, error) {
	var createReq esast.IndexCreateRequest
	if err := json.Unmarshal(raw, &createReq); err == nil && createReq.Mappings != nil && len(createReq.Mappings.Properties) > 0 {
		return createReq.Mappings, nil
	}
	var spec esast.MappingSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}
