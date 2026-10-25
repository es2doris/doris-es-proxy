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
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

var version = "dev"

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

func redactDSN(dsn string) string {
	atIdx := strings.Index(dsn, "@tcp(")
	if atIdx <= 0 {
		return dsn
	}
	colonIdx := strings.IndexByte(dsn[:atIdx], ':')
	if colonIdx < 0 || colonIdx+1 == atIdx {
		return dsn
	}
	return dsn[:colonIdx+1] + "***" + dsn[atIdx:]
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("doris-es-proxy %s\n", version)
			return
		case "transpile":
			runTranspileSubcommand(os.Args[2:])
			return
		case "ddl":
			runDDLSubcommand(os.Args[2:])
			return
		case "doctor":
			runDoctorSubcommand(os.Args[2:])
			return
		case "migrate-schema":
			runMigrateSchemaSubcommand(os.Args[2:])
			return
		}
	}

	var (
		listenAddr          = flag.String("listen", envOrDefault("LISTEN_ADDR", ":9200"), "Elasticsearch HTTP REST listen address (env: LISTEN_ADDR)")
		dorisDSN            = flag.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s&readTimeout=30s&writeTimeout=30s"), "Apache Doris FE MySQL wire protocol DSN (env: DORIS_DSN)")
		dorisHTTP           = flag.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint for Stream Load (env: DORIS_HTTP)")
		dorisUser           = flag.String("doris-user", envOrDefault("DORIS_USER", "root"), "Apache Doris username (env: DORIS_USER)")
		dorisPassword       = flag.String("doris-password", envOrDefault("DORIS_PASSWORD", ""), "Apache Doris password (env: DORIS_PASSWORD)")
		dorisDB             = flag.String("doris-db", envOrDefault("DORIS_DB", "es_compat"), "Target Apache Doris database name (env: DORIS_DB)")
		shadowESURL         = flag.String("shadow-es-url", envOrDefault("SHADOW_ES_URL", ""), "Optional legacy Elasticsearch URL for dual-read shadow parity verification (env: SHADOW_ES_URL)")
		useDoris4SearchFunc = flag.Bool("doris4-search-fn", envBoolOrDefault("DORIS4_SEARCH_FN", false), "Push query_string down to Apache Doris 4.0 SEARCH() SQL function (env: DORIS4_SEARCH_FN)")
		autoPromote         = flag.Bool("auto-promote", envBoolOrDefault("AUTO_PROMOTE", false), "Automatically promote hot unindexed _doc[...] VARIANT fields to f__* inverted index columns (env: AUTO_PROMOTE)")
		inMemoryMode        = flag.Bool("in-memory", envBoolOrDefault("IN_MEMORY", false), "Run with in-memory shredded Doris emulator (env: IN_MEMORY)")
		logSQL              = flag.Bool("log-sql", envBoolOrDefault("LOG_SQL", false), "Log transpiled Apache Doris DDL, Stream Load, HitsSQL, and AggsSQL (env: LOG_SQL)")
	)
	flag.Parse()

	var backend proxy.DorisBackend
	if *inMemoryMode {
		backend = proxy.NewMemoryBackend(*logSQL)
		log.Printf("doris-es-proxy starting in --in-memory emulator mode on %s (Doris DB=%q, log-sql=%v)", *listenAddr, *dorisDB, *logSQL)
	} else {
		var sqlDB *sql.DB
		if *dorisDSN != "" {
			db, err := sql.Open("mysql", *dorisDSN)
			if err != nil {
				log.Fatalf("failed to configure Doris MySQL driver: %v", err)
			}
			db.SetMaxOpenConns(64)
			db.SetMaxIdleConns(16)
			db.SetConnMaxIdleTime(2 * time.Minute)
			db.SetConnMaxLifetime(5 * time.Minute)
			sqlDB = db
			defer func() { _ = sqlDB.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			// #nosec G201 -- identifier is strictly sanitized via schema.SanitizeDorisIdentifier
			createDBSQL := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", schema.SanitizeDorisIdentifier(*dorisDB))
			if _, err := sqlDB.ExecContext(ctx, createDBSQL); err != nil {
				log.Printf("warning: initial Doris database bootstrap (%s) deferred until cluster is reachable: %v", createDBSQL, err)
			}
			cancel()
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
		log.Printf("doris-es-proxy listening on %s (Doris DB=%q, MySQL DSN=%q, FE HTTP=%q, log-sql=%v)", *listenAddr, *dorisDB, redactDSN(*dorisDSN), *dorisHTTP, *logSQL)
	}

	srv := proxy.NewServer(*dorisDB, backend, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *useDoris4SearchFunc,
	})
	if *shadowESURL != "" {
		srv.SetShadowESURL(*shadowESURL)
		log.Printf("shadow dual-read verification enabled against %s (metrics at GET /_doris/shadow_stats)", *shadowESURL)
	}
	if *autoPromote {
		srv.SetAutoPromoteThreshold(3)
		log.Printf("auto-promote enabled: unindexed _doc[...] fields queried >= 3 times will be promoted to f__* columns")
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-sigCtx.Done()
		log.Printf("shutting down doris-es-proxy gracefully...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutCtx)
	}()

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server exited: %v", err)
	}
}

func runTranspileSubcommand(args []string) {
	fs := flag.NewFlagSet("transpile", flag.ExitOnError)
	indexName := fs.String("index", "table_search_index", "Target Elasticsearch index name")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	mappingPath := fs.String("mapping", "", "Optional path to Elasticsearch mapping JSON file")
	queryPath := fs.String("query", "", "Optional path to Elasticsearch _search JSON file (defaults to stdin)")
	doris4Search := fs.Bool("doris4-search-fn", false, "Use Apache Doris 4.0 SEARCH() function")
	format := fs.String("format", "sql", "Output format: sql or json")
	_ = fs.Parse(args)

	var mappingSpec *esast.MappingSpec
	if *mappingPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		raw, err := os.ReadFile(filepath.Clean(*mappingPath))
		if err != nil {
			log.Fatalf("failed to read --mapping %s: %v", *mappingPath, err)
		}
		mappingSpec, err = parseMappingJSON(raw)
		if err != nil {
			log.Fatalf("failed to parse --mapping %s: %v", *mappingPath, err)
		}
	}

	var queryBytes []byte
	var err error
	if *queryPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		queryBytes, err = os.ReadFile(filepath.Clean(*queryPath))
	} else {
		queryBytes, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatalf("failed to read search query payload: %v", err)
	}

	var req esast.SearchRequest
	if len(bytes.TrimSpace(queryBytes)) > 0 {
		if err := json.Unmarshal(queryBytes, &req); err != nil {
			log.Fatalf("invalid Elasticsearch _search JSON: %v", err)
		}
	}

	idxSchema := schema.CompileIndexSchema(*dorisDB, *indexName, mappingSpec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *doris4Search,
	})
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		log.Fatalf("transpile error: %v", err)
	}

	if strings.EqualFold(*format, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"index":            *indexName,
			"doris_database":   idxSchema.DorisDB,
			"doris_table":      idxSchema.DorisTable,
			"create_table_ddl": schema.GenerateCreateTableDDL(idxSchema),
			"hits_sql":         plan.HitsSQL,
			"aggs_sql":         plan.AggsSQL,
		})
		return
	}

	if plan.HitsSQL != "" {
		fmt.Printf("-- [HitsSQL] (%s.%s)\n%s;\n", idxSchema.DorisDB, idxSchema.DorisTable, plan.HitsSQL)
	}
	if plan.AggsSQL != "" {
		if plan.HitsSQL != "" {
			fmt.Println()
		}
		fmt.Printf("-- [AggsSQL - Nereids Multi-Cast CTE] (%s.%s)\n%s;\n", idxSchema.DorisDB, idxSchema.DorisTable, plan.AggsSQL)
	}
}

func runDDLSubcommand(args []string) {
	fs := flag.NewFlagSet("ddl", flag.ExitOnError)
	indexName := fs.String("index", "table_search_index", "Target Elasticsearch index name")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	mappingPath := fs.String("mapping", "", "Optional path to Elasticsearch mapping JSON file (defaults to stdin)")
	_ = fs.Parse(args)

	var raw []byte
	var err error
	if *mappingPath != "" {
		// #nosec G304 -- CLI subcommand explicitly reads user-specified local file path
		raw, err = os.ReadFile(filepath.Clean(*mappingPath))
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatalf("failed to read mapping JSON: %v", err)
	}

	var spec *esast.MappingSpec
	if len(bytes.TrimSpace(raw)) > 0 {
		spec, err = parseMappingJSON(raw)
		if err != nil {
			log.Fatalf("invalid Elasticsearch mapping JSON: %v", err)
		}
	}
	idxSchema := schema.CompileIndexSchema(*dorisDB, *indexName, spec)
	fmt.Println(schema.GenerateCreateTableDDL(idxSchema))
}

func runDoctorSubcommand(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	dorisDSN := fs.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s"), "Apache Doris FE MySQL DSN")
	dorisHTTP := fs.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint")
	_ = fs.Parse(args)

	fmt.Printf("==> doris-es-proxy %s Connectivity Doctor\n", version)
	fmt.Printf("  1. Checking Doris FE MySQL (%s)... ", redactDSN(*dorisDSN))
	db, err := sql.Open("mysql", *dorisDSN)
	if err != nil {
		fmt.Printf("FAIL (%v)\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var verComment string
	if err := db.QueryRowContext(ctx, "SELECT @@version_comment").Scan(&verComment); err != nil {
		fmt.Printf("UNREACHABLE (%v)\n", err)
	} else {
		fmt.Printf("OK (%s)\n", verComment)
	}

	fmt.Printf("  2. Checking Doris FE HTTP (%s)... ", *dorisHTTP)
	client := &http.Client{Timeout: 3 * time.Second}
	// #nosec G704 -- operator-supplied --doris-http endpoint in CLI doctor subcommand
	resp, err := client.Get(strings.TrimRight(*dorisHTTP, "/") + "/api/bootstrap")
	if err != nil {
		fmt.Printf("UNREACHABLE (%v)\n", err)
	} else {
		_ = resp.Body.Close()
		fmt.Printf("OK (HTTP %d)\n", resp.StatusCode)
	}
}

func runMigrateSchemaSubcommand(args []string) {
	fs := flag.NewFlagSet("migrate-schema", flag.ExitOnError)
	esURL := fs.String("es-url", "http://127.0.0.1:9200", "Source Elasticsearch / OpenSearch HTTP URL")
	indexPattern := fs.String("index", "_all", "Index name or pattern to migrate")
	dorisDB := fs.String("db", "es_compat", "Target Apache Doris database name")
	_ = fs.Parse(args)

	endpoint := strings.TrimRight(*esURL, "/") + "/" + url.PathEscape(*indexPattern) + "/_mapping"
	client := &http.Client{Timeout: 10 * time.Second}
	// #nosec G704 -- operator-supplied --es-url in CLI migrate-schema subcommand
	resp, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("failed to fetch mappings from %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read mapping response: %v", err)
	}

	var byIndex map[string]struct {
		Mappings *esast.MappingSpec `json:"mappings"`
	}
	if err := json.Unmarshal(raw, &byIndex); err != nil {
		log.Fatalf("invalid Elasticsearch _mapping response: %v", err)
	}

	idxNames := make([]string, 0, len(byIndex))
	for k := range byIndex {
		if !strings.HasPrefix(k, ".") {
			idxNames = append(idxNames, k)
		}
	}
	sort.Strings(idxNames)

	fmt.Printf("-- Generated by doris-es-proxy %s migrate-schema from %s\n", version, *esURL)
	fmt.Printf("CREATE DATABASE IF NOT EXISTS `%s`;\n\n", schema.SanitizeDorisIdentifier(*dorisDB))
	for _, idxName := range idxNames {
		entry := byIndex[idxName]
		compiled := schema.CompileIndexSchema(*dorisDB, idxName, entry.Mappings)
		fmt.Printf("-- Index: %s\n%s\n\n", idxName, schema.GenerateCreateTableDDL(compiled))
	}
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
