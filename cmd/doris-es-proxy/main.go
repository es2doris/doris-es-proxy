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
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "transpile":
			runTranspileSubcommand(os.Args[2:])
			return
		case "ddl":
			runDDLSubcommand(os.Args[2:])
			return
		}
	}

	var (
		listenAddr          = flag.String("listen", ":9200", "Elasticsearch HTTP REST listen address")
		dorisDSN            = flag.String("doris-dsn", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s&readTimeout=30s&writeTimeout=30s", "Apache Doris FE MySQL wire protocol DSN")
		dorisHTTP           = flag.String("doris-http", "http://127.0.0.1:8030", "Apache Doris FE HTTP endpoint for Stream Load")
		dorisUser           = flag.String("doris-user", "root", "Apache Doris username")
		dorisPassword       = flag.String("doris-password", "", "Apache Doris password")
		dorisDB             = flag.String("doris-db", "es_compat", "Target Apache Doris database name")
		useDoris4SearchFunc = flag.Bool("doris4-search-fn", false, "Push query_string down to Apache Doris 4.0 SEARCH() SQL function")
		inMemoryMode        = flag.Bool("in-memory", false, "Run with in-memory shredded Doris emulator (zero external containers required)")
		logSQL              = flag.Bool("log-sql", false, "Log transpiled Apache Doris DDL, Stream Load, HitsSQL, and AggsSQL")
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
		log.Printf("doris-es-proxy listening on %s (Doris DB=%q, MySQL DSN=%q, FE HTTP=%q, log-sql=%v)", *listenAddr, *dorisDB, *dorisDSN, *dorisHTTP, *logSQL)
	}

	srv := proxy.NewServer(*dorisDB, backend, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *useDoris4SearchFunc,
	})
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.BootstrapCatalog(bootCtx); err != nil {
		log.Printf("warning: initial _es_catalog bootstrap deferred: %v", err)
	}
	bootCancel()

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

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
		raw, err := os.ReadFile(*mappingPath)
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
		queryBytes, err = os.ReadFile(*queryPath)
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
		raw, err = os.ReadFile(*mappingPath)
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
