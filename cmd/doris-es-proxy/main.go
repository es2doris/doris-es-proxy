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
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func main() {
	var (
		listenAddr          = flag.String("listen", ":9200", "Elasticsearch HTTP REST listen address")
		dorisDSN            = flag.String("doris-dsn", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&multiStatements=true", "Apache Doris FE MySQL wire protocol DSN")
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

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server exited: %v", err)
	}
}
