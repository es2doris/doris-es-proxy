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
	"log/slog"
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
	"unicode"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

var (
	version  = "v0.23.0"
	osExitFn = os.Exit
)

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
	if strings.Contains(trimmed, ",") {
		parts := strings.Split(trimmed, ",")
		multiURL := true
		for _, part := range parts {
			if !strings.Contains(strings.TrimSpace(part), "://") {
				multiURL = false
				break
			}
		}
		if multiURL {
			redacted := make([]string, 0, len(parts))
			for _, part := range parts {
				redacted = append(redacted, redactURLCredentials(part))
			}
			return strings.Join(redacted, ",")
		}
	}
	if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && u.Host != "" {
		if u.User != nil {
			if uname := u.User.Username(); uname != "" {
				u.User = url.User(uname)
			} else {
				u.User = nil
			}
		}
		return u.String()
	}
	return redactDSN(trimmed)
}

func buildSlogLogger(format, level string, out io.Writer) (*slog.Logger, error) {
	if out == nil {
		out = os.Stderr
	}
	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		slogLevel = slog.LevelInfo
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q: must be one of debug, info, warn, error", level)
	}
	opts := &slog.HandlerOptions{Level: slogLevel}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(out, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(out, opts)), nil
	default:
		return nil, fmt.Errorf("invalid --log-format %q: must be one of json, text", format)
	}
}

func normalizeBM25ModeCLI(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", proxy.BM25ModeAuto:
		return proxy.BM25ModeAuto, nil
	case proxy.BM25ModeDorisScore:
		return proxy.BM25ModeDorisScore, nil
	case proxy.BM25ModeExactCorpusScan:
		return proxy.BM25ModeExactCorpusScan, nil
	case proxy.BM25ModeApprox:
		return proxy.BM25ModeApprox, nil
	default:
		return "", fmt.Errorf("invalid --bm25-mode %q: must be one of auto, doris-score, exact-corpus-scan, approx", mode)
	}
}

func parseDorisSemver(raw string) (major, minor, patch int, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, 0, 0, false
	}
	lower := strings.ToLower(trimmed)
	search := trimmed
	hasDorisMarker := false
	if idx := strings.LastIndex(lower, "doris"); idx >= 0 {
		hasDorisMarker = true
		search = trimmed[idx+len("doris"):]
	}

	// Scan for the first X.Y[.Z] numeric tuple in search.
	for i := 0; i < len(search); i++ {
		if !unicode.IsDigit(rune(search[i])) {
			continue
		}
		j := i
		for j < len(search) && (unicode.IsDigit(rune(search[j])) || search[j] == '.') {
			j++
		}
		tok := strings.Trim(search[i:j], ".")
		parts := strings.Split(tok, ".")
		if len(parts) < 2 || len(parts) > 3 {
			i = j
			continue
		}
		maj, err1 := strconv.Atoi(parts[0])
		min, err2 := strconv.Atoi(parts[1])
		pat := 0
		var err3 error
		if len(parts) == 3 {
			pat, err3 = strconv.Atoi(parts[2])
		}
		if err1 != nil || err2 != nil || err3 != nil {
			i = j
			continue
		}
		// Without an explicit "doris" marker, ignore bare MySQL wire-protocol versions (5.7.x / 8.0.x).
		if !hasDorisMarker && ((maj == 5 && min == 7) || (maj == 8 && min == 0)) {
			return 0, 0, 0, false
		}
		return maj, min, pat, true
	}
	return 0, 0, 0, false
}

func dorisSupportsUniqueKeyANN(rawVersion string) bool {
	maj, min, pat, ok := parseDorisSemver(rawVersion)
	if !ok {
		return false
	}
	if maj > 4 {
		return true
	}
	if maj < 4 {
		return false
	}
	if min > 1 {
		return true
	}
	if min < 1 {
		return false
	}
	return pat >= 4
}

func resolveVectorANNConfig(requestedMode string, allowUniqueKeyANN bool, tableKeyModel string) (ddlMode, transpileMode string, allowANNPushdown, ddlAllowUniqueANN bool, err error) {
	norm := strings.ToLower(strings.TrimSpace(requestedMode))
	isDupKey := strings.EqualFold(strings.TrimSpace(tableKeyModel), "duplicate")
	switch norm {
	case "", "off":
		return "off", "off", false, false, nil
	case "auto":
		if allowUniqueKeyANN || isDupKey {
			return "hnsw", "hnsw", true, allowUniqueKeyANN, nil
		}
		return "off", "off", false, false, nil
	case "hnsw", "ivf":
		return norm, norm, allowUniqueKeyANN || isDupKey, allowUniqueKeyANN, nil
	default:
		return "", "", false, false, fmt.Errorf("invalid --doris-vector-ann %q: must be one of off, auto, hnsw, ivf", requestedMode)
	}
}

func isDoctorMissingCatalogError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "error 1049") ||
		strings.Contains(msg, "unknown database") ||
		strings.Contains(msg, "error 1146") ||
		strings.Contains(msg, "42s02") ||
		strings.Contains(msg, "doesn't exist") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "unknown table")
}

func escapeDorisBacktickIdent(name string) string {
	return strings.ReplaceAll(schema.SanitizeDorisIdentifier(name), "`", "``")
}

func splitCommaTrimmedCLI(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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
		case "sleep":
			return runSleepSubcommandErr(ctx, args[1:])
		}
	}
	return runServerErr(ctx, args, stderr, listenFn)
}

func runSleepSubcommandErr(ctx context.Context, args []string) error {
	dur := 5 * time.Second
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		raw := strings.TrimSpace(args[0])
		if secs, err := strconv.Atoi(raw); err == nil {
			dur = time.Duration(secs) * time.Second
		} else if parsed, err := time.ParseDuration(raw); err == nil {
			dur = parsed
		} else {
			return fmt.Errorf("invalid sleep duration %q: %w", raw, err)
		}
	}
	if dur <= 0 {
		return nil
	}
	timer := time.NewTimer(dur)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return nil
	}
}

func probeDorisStartupVersion(ctx context.Context, sqlDB *sql.DB, sqlBackend *proxy.DorisSQLBackend) (string, error) {
	if sqlBackend == nil {
		return "", nil
	}
	ver, err := sqlBackend.ProbeDorisVersion(ctx)
	if err != nil {
		return "", err
	}
	if sqlDB != nil && !strings.Contains(strings.ToLower(ver), "doris") &&
		(strings.HasPrefix(ver, "5.7.") || strings.HasPrefix(ver, "8.0.")) {
		var verComment sql.NullString
		if cErr := sqlDB.QueryRowContext(ctx, "SELECT @@version_comment").Scan(&verComment); cErr == nil {
			comment := strings.TrimSpace(verComment.String)
			if comment != "" {
				return ver + " (" + comment + ")", nil
			}
		}
	}
	return ver, nil
}

func runServerErr(ctx context.Context, args []string, flagOut io.Writer, listenFn serverListenFunc) error {
	fs := flag.NewFlagSet("doris-es-proxy", flag.ContinueOnError)
	if flagOut != nil {
		fs.SetOutput(flagOut)
	}
	var (
		listenAddr                 = fs.String("listen", envOrDefault("LISTEN_ADDR", ":9200"), "Elasticsearch HTTP REST listen address (env: LISTEN_ADDR)")
		dorisDSN                   = fs.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s&readTimeout=30s&writeTimeout=30s"), "Apache Doris FE MySQL wire protocol DSN (env: DORIS_DSN)")
		dorisHTTP                  = fs.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint for Stream Load (env: DORIS_HTTP)")
		dorisUser                  = fs.String("doris-user", envOrDefault("DORIS_USER", "root"), "Apache Doris username (env: DORIS_USER)")
		dorisPassword              = fs.String("doris-password", envOrDefault("DORIS_PASSWORD", ""), "Apache Doris password (env: DORIS_PASSWORD)")
		dorisDB                    = fs.String("doris-db", envOrDefault("DORIS_DB", "es_compat"), "Target Apache Doris database name (env: DORIS_DB)")
		shadowESURL                = fs.String("shadow-es-url", envOrDefault("SHADOW_ES_URL", ""), "Optional legacy Elasticsearch URL for dual-read shadow parity verification (env: SHADOW_ES_URL)")
		useDoris4SearchFunc        = fs.Bool("doris4-search-fn", envBoolOrDefault("DORIS4_SEARCH_FN", false), "Push query_string down to Apache Doris 4.0 SEARCH() SQL function (env: DORIS4_SEARCH_FN)")
		autoPromote                = fs.Bool("auto-promote", envBoolOrDefault("AUTO_PROMOTE", false), "Automatically promote hot unindexed _doc[...] VARIANT fields to f__* inverted index columns (env: AUTO_PROMOTE)")
		bulkCoalesceMs             = fs.Int("bulk-coalesce-ms", envIntOrDefault("BULK_COALESCE_MS", 0), "Group-commit Stream Load micro-batch window in milliseconds across concurrent writes (0 disables, env: BULK_COALESCE_MS)")
		bulkCoalesceBytes          = fs.Int("bulk-coalesce-bytes", envIntOrDefault("BULK_COALESCE_BYTES", proxy.DefaultBulkCoalesceMaxBytes), "Maximum byte size of a coalesced Stream Load batch before immediate flush (env: BULK_COALESCE_BYTES)")
		queryCacheTTL              = fs.Duration("query-cache-ttl", envDurationOrDefault("QUERY_CACHE_TTL", 0), "Optional TTL for caching search responses with automatic write invalidation (e.g. 5s, 0s disables, env: QUERY_CACHE_TTL)")
		basicAuthUser              = fs.String("basic-auth-user", envOrDefault("BASIC_AUTH_USER", ""), "Optional inbound HTTP Basic Auth username (env: BASIC_AUTH_USER)")
		basicAuthPass              = fs.String("basic-auth-pass", envOrDefault("BASIC_AUTH_PASS", ""), "Optional inbound HTTP Basic Auth password (env: BASIC_AUTH_PASS)")
		apiKey                     = fs.String("api-key", envOrDefault("API_KEY", ""), "Optional inbound Elasticsearch ApiKey / Bearer token (env: API_KEY)")
		tlsCertFile                = fs.String("tls-cert", envOrDefault("TLS_CERT_FILE", ""), "Optional TLS server certificate PEM file for HTTPS (env: TLS_CERT_FILE)")
		tlsKeyFile                 = fs.String("tls-key", envOrDefault("TLS_KEY_FILE", ""), "Optional TLS private key PEM file for HTTPS (env: TLS_KEY_FILE)")
		reindexRemoteWhitelist     = fs.String("reindex-remote-whitelist", envOrDefault("DORIS_ES_REINDEX_REMOTE_WHITELIST", ""), "Static comma-separated host:port whitelist for remote _reindex (env: DORIS_ES_REINDEX_REMOTE_WHITELIST)")
		reindexRemoteAllowPrivate  = fs.Bool("reindex-remote-allow-private", envBoolOrDefault("DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE", false), "Allow private, loopback, link-local, and CGNAT IPs for remote _reindex (env: DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE)")
		pathRepo                   = fs.String("path-repo", envOrDefault("DORIS_ES_PATH_REPO", ""), "Static comma-separated root directories for snapshot path.repo (env: DORIS_ES_PATH_REPO)")
		repositoriesURLAllowedURLs = fs.String("repositories-url-allowed-urls", envOrDefault("DORIS_ES_REPOSITORIES_URL_ALLOWED_URLS", ""), "Static comma-separated URL patterns for snapshot repositories.url.allowed_urls (env: DORIS_ES_REPOSITORIES_URL_ALLOWED_URLS)")
		esTargetVersion            = fs.String("es-version", envOrDefault("ES_TARGET_VERSION", ""), "Optional explicit Elasticsearch compatibility version (e.g. 8.15.5 or 7.10.2, env: ES_TARGET_VERSION)")
		bm25Mode                   = fs.String("bm25-mode", envOrDefault("BM25_MODE", "auto"), "BM25 corpus stats mode: auto|doris-score|exact-corpus-scan|approx (env: BM25_MODE)")
		bm25MaxRows                = fs.Int("bm25-max-rows", envIntOrDefault("BM25_MAX_ROWS", 50000), "Row-count threshold above which --bm25-mode=auto skips full-table BM25 scans (env: BM25_MAX_ROWS)")
		dorisReplicationNum        = fs.Int("doris-replication-num", envIntOrDefault("DORIS_REPLICATION_NUM", 1), "Default Apache Doris table replication_num property (env: DORIS_REPLICATION_NUM)")
		dorisReplicationAlloc      = fs.String("doris-replication-allocation", envOrDefault("DORIS_REPLICATION_ALLOCATION", ""), "Optional Apache Doris table replication_allocation property (env: DORIS_REPLICATION_ALLOCATION)")
		dorisCloud                 = fs.Bool("doris-cloud", envBoolOrDefault("DORIS_CLOUD", false), "Omit replication properties for Apache Doris Cloud / storage-compute separation (env: DORIS_CLOUD)")
		dorisBucketsAuto           = fs.Bool("doris-buckets-auto", envBoolOrDefault("DORIS_BUCKETS_AUTO", false), "Emit DISTRIBUTED BY HASH(`_id`) BUCKETS AUTO when explicit shards/buckets are unset (env: DORIS_BUCKETS_AUTO)")
		dorisStoreRowColumn        = fs.Bool("doris-store-row-column", envBoolOrDefault("DORIS_STORE_ROW_COLUMN", true), "Set Apache Doris store_row_column table property for point lookups (env: DORIS_STORE_ROW_COLUMN)")
		dorisVectorANN             = fs.String("doris-vector-ann", envOrDefault("DORIS_VECTOR_ANN", "off"), "Vector ANN index/pushdown mode: off|auto|hnsw|ivf (env: DORIS_VECTOR_ANN)")
		catalogSyncInterval        = fs.Duration("catalog-sync-interval", envDurationOrDefault("CATALOG_SYNC_INTERVAL", 5*time.Second), "Periodic _es_catalog sync interval across proxy replicas (0s disables, env: CATALOG_SYNC_INTERVAL)")
		dorisMaxOpenConns          = fs.Int("doris-max-open-conns", envIntOrDefault("DORIS_MAX_OPEN_CONNS", 50), "Maximum open Doris MySQL connections in pool (must be > 0, env: DORIS_MAX_OPEN_CONNS)")
		dorisMaxIdleConns          = fs.Int("doris-max-idle-conns", envIntOrDefault("DORIS_MAX_IDLE_CONNS", 10), "Maximum idle Doris MySQL connections in pool (env: DORIS_MAX_IDLE_CONNS)")
		dorisConnMaxLifetime       = fs.Duration("doris-conn-max-lifetime", envDurationOrDefault("DORIS_CONN_MAX_LIFETIME", 5*time.Minute), "Maximum lifetime of a pooled Doris MySQL connection (env: DORIS_CONN_MAX_LIFETIME)")
		logFormat                  = fs.String("log-format", envOrDefault("LOG_FORMAT", "json"), "Structured log format: json|text (env: LOG_FORMAT)")
		logLevel                   = fs.String("log-level", envOrDefault("LOG_LEVEL", "info"), "Structured log level: debug|info|warn|error (env: LOG_LEVEL)")
		inMemoryMode               = fs.Bool("in-memory", envBoolOrDefault("IN_MEMORY", false), "Run with in-memory shredded Doris emulator (env: IN_MEMORY)")
		logSQL                     = fs.Bool("log-sql", envBoolOrDefault("LOG_SQL", false), "Log transpiled Apache Doris DDL, Stream Load, HitsSQL, and AggsSQL (env: LOG_SQL)")
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
	normBM25Mode, err := normalizeBM25ModeCLI(*bm25Mode)
	if err != nil {
		return err
	}
	if *bm25MaxRows <= 0 {
		return fmt.Errorf("--bm25-max-rows must be > 0, got %d", *bm25MaxRows)
	}
	if *dorisReplicationNum <= 0 {
		return fmt.Errorf("--doris-replication-num must be > 0, got %d", *dorisReplicationNum)
	}
	if _, _, _, _, err := resolveVectorANNConfig(*dorisVectorANN, false, ""); err != nil {
		return err
	}
	if *catalogSyncInterval < 0 {
		return fmt.Errorf("--catalog-sync-interval must be >= 0, got %s", *catalogSyncInterval)
	}
	if *dorisMaxOpenConns <= 0 {
		return fmt.Errorf("--doris-max-open-conns must be > 0, got %d", *dorisMaxOpenConns)
	}
	if *dorisMaxIdleConns < 0 {
		return fmt.Errorf("--doris-max-idle-conns must be >= 0, got %d", *dorisMaxIdleConns)
	}
	if *dorisConnMaxLifetime < 0 {
		return fmt.Errorf("--doris-conn-max-lifetime must be >= 0, got %s", *dorisConnMaxLifetime)
	}
	logger, err := buildSlogLogger(*logFormat, *logLevel, flagOut)
	if err != nil {
		return err
	}

	storeRowCol := *dorisStoreRowColumn
	ddlOpts := schema.DorisDDLOptions{
		ReplicationNum:        *dorisReplicationNum,
		ReplicationAllocation: strings.TrimSpace(*dorisReplicationAlloc),
		CloudMode:             *dorisCloud,
		BucketsAuto:           *dorisBucketsAuto,
		StoreRowColumn:        &storeRowCol,
	}

	var (
		backend           proxy.DorisBackend
		allowUniqueKeyANN bool
		dorisVer          string
	)
	if *inMemoryMode {
		backend = proxy.NewMemoryBackend(*logSQL)
		logger.Info("doris-es-proxy starting in --in-memory emulator mode",
			slog.String("listen", *listenAddr),
			slog.String("doris_db", *dorisDB),
			slog.Bool("log_sql", *logSQL),
		)
	} else {
		effectiveDSN := proxy.ApplyDSNAuth(*dorisDSN, *dorisUser, *dorisPassword)
		var sqlDB *sql.DB
		if effectiveDSN != "" {
			db, err := sql.Open("mysql", effectiveDSN)
			if err != nil {
				return fmt.Errorf("failed to configure Doris MySQL driver: %w", err)
			}
			sqlDB = db
			defer func() { _ = sqlDB.Close() }()
		}

		slClient := proxy.NewStreamLoadClient(proxy.StreamLoadConfig{
			FEHTTPEndpoint: *dorisHTTP,
			User:           *dorisUser,
			Password:       *dorisPassword,
			Database:       *dorisDB,
			Timeout:        30 * time.Second,
		})

		sqlBackend := proxy.NewDorisSQLBackend(sqlDB, slClient)
		if sqlDB != nil {
			sqlDB.SetMaxOpenConns(*dorisMaxOpenConns)
			sqlDB.SetMaxIdleConns(*dorisMaxIdleConns)
			sqlDB.SetConnMaxIdleTime(2 * time.Minute)
			sqlDB.SetConnMaxLifetime(*dorisConnMaxLifetime)

			dbCtx, dbCancel := context.WithTimeout(ctx, 5*time.Second)
			// #nosec G201 -- identifier is strictly sanitized via schema.SanitizeDorisIdentifier and backtick-escaped
			createDBSQL := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", escapeDorisBacktickIdent(*dorisDB))
			if _, err := sqlDB.ExecContext(dbCtx, createDBSQL); err != nil {
				logger.Warn("initial Doris database bootstrap deferred until cluster is reachable",
					slog.String("sql", createDBSQL),
					slog.String("error", err.Error()),
				)
			}
			dbCancel()

			verCtx, verCancel := context.WithTimeout(ctx, 3*time.Second)
			probedVer, verErr := probeDorisStartupVersion(verCtx, sqlDB, sqlBackend)
			verCancel()
			if verErr != nil {
				logger.Warn("startup Doris version probe failed; assuming Unique Key ANN unsupported until reachable",
					slog.String("error", verErr.Error()),
				)
			} else {
				dorisVer = probedVer
				allowUniqueKeyANN = dorisSupportsUniqueKeyANN(dorisVer)
				logger.Info("probed Apache Doris version",
					slog.String("version", dorisVer),
					slog.Bool("allow_unique_key_ann", allowUniqueKeyANN),
				)
			}
		}

		ddlANNMode, _, _, ddlAllowUniqueANN, _ := resolveVectorANNConfig(*dorisVectorANN, allowUniqueKeyANN, ddlOpts.TableKeyModel)
		ddlOpts.VectorANNMode = ddlANNMode
		ddlOpts.AllowUniqueKeyANN = ddlAllowUniqueANN
		sqlBackend.SetDDLOptions(ddlOpts)
		sqlBackend.SetLogSQL(*logSQL)
		backend = sqlBackend
		// #nosec G706 -- DSN and FE HTTP URL credentials and CR/LF are stripped via redactDSN/redactURLCredentials
		logger.Info("doris-es-proxy listening",
			slog.String("listen", *listenAddr),
			slog.String("doris_db", *dorisDB),
			slog.String("mysql_dsn", redactDSN(effectiveDSN)),
			slog.String("fe_http", redactURLCredentials(*dorisHTTP)),
			slog.Bool("log_sql", *logSQL),
			slog.Int("max_open_conns", *dorisMaxOpenConns),
			slog.Int("max_idle_conns", *dorisMaxIdleConns),
			slog.Duration("conn_max_lifetime", *dorisConnMaxLifetime),
		)
	}

	ddlANNMode, transpileANNMode, allowANNPushdown, ddlAllowUniqueANN, _ := resolveVectorANNConfig(*dorisVectorANN, allowUniqueKeyANN, ddlOpts.TableKeyModel)
	ddlOpts.VectorANNMode = ddlANNMode
	ddlOpts.AllowUniqueKeyANN = ddlAllowUniqueANN

	srv := proxy.NewServer(*dorisDB, backend, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: *useDoris4SearchFunc,
		VectorANNMode:       transpileANNMode,
		AllowANNPushdown:    allowANNPushdown,
	})
	srv.SetLogger(logger)
	srv.SetDorisDDLOptions(ddlOpts)
	srv.SetBM25Mode(normBM25Mode)
	srv.SetBM25MaxRows(int64(*bm25MaxRows))
	if strings.TrimSpace(*esTargetVersion) != "" {
		srv.SetTargetESVersion(strings.TrimSpace(*esTargetVersion))
	}
	srv.SetStaticRemoteReindexWhitelist(*reindexRemoteWhitelist)
	srv.SetRemoteReindexAllowPrivateIPs(*reindexRemoteAllowPrivate)
	if roots := splitCommaTrimmedCLI(*pathRepo); len(roots) > 0 {
		srv.SetStaticPathRepo(roots)
	}
	if allowedURLs := splitCommaTrimmedCLI(*repositoriesURLAllowedURLs); len(allowedURLs) > 0 {
		srv.SetStaticRepositoriesURLAllowedURLs(allowedURLs)
	}
	if *shadowESURL != "" {
		srv.SetShadowESURL(*shadowESURL)
		// #nosec G706 -- shadow URL credentials and CR/LF are stripped via redactURLCredentials
		logger.Info("shadow dual-read verification enabled",
			slog.String("shadow_es_url", redactURLCredentials(*shadowESURL)),
			slog.String("metrics_endpoint", "GET /_doris/shadow_stats"),
		)
	}
	if *autoPromote {
		srv.SetAutoPromoteThreshold(3)
		logger.Info("auto-promote enabled: unindexed _doc[...] fields queried >= 3 times will be promoted to f__* columns")
	}
	if *bulkCoalesceMs > 0 {
		srv.SetBulkCoalesce(time.Duration(*bulkCoalesceMs)*time.Millisecond, *bulkCoalesceBytes)
		logger.Info("group-commit Stream Load coalescer enabled",
			slog.Int("window_ms", *bulkCoalesceMs),
			slog.Int("max_bytes", *bulkCoalesceBytes),
		)
	}
	if *queryCacheTTL > 0 {
		srv.SetQueryCacheTTL(*queryCacheTTL, proxy.DefaultQueryCacheMaxEntries)
		logger.Info("search query result cache enabled",
			slog.Duration("ttl", *queryCacheTTL),
			slog.Int("max_entries", proxy.DefaultQueryCacheMaxEntries),
		)
	}
	if *basicAuthUser != "" || *basicAuthPass != "" || *apiKey != "" {
		srv.SetAuth(*basicAuthUser, *basicAuthPass, *apiKey)
		logger.Info("inbound HTTP authentication enabled",
			slog.Bool("basic_auth", *basicAuthUser != "" || *basicAuthPass != ""),
			slog.Bool("api_key", *apiKey != ""),
		)
	}
	bootCtx, bootCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := srv.BootstrapCatalog(bootCtx); err != nil {
		logger.Warn("initial _es_catalog bootstrap deferred", slog.String("error", err.Error()))
	}
	bootCancel()

	if *catalogSyncInterval > 0 {
		srv.SetCatalogSyncInterval(*catalogSyncInterval)
		logger.Info("background catalog sync loop enabled", slog.Duration("interval", *catalogSyncInterval))
	}

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
		logger.Info("shutting down doris-es-proxy gracefully...")
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
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
		logger.Info("HTTPS TLS listener enabled", slog.String("cert", *tlsCertFile))
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
		osExitFn(1)
	}
}

func runDoctorSubcommandErr(args []string, stdout, stderr io.Writer) error {
	return runDoctorSubcommandWithDriver("mysql", args, stdout, stderr)
}

func runDoctorSubcommandWithDriver(sqlDriver string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	dorisDSN := fs.String("doris-dsn", envOrDefault("DORIS_DSN", "root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s"), "Apache Doris FE MySQL DSN")
	dorisHTTP := fs.String("doris-http", envOrDefault("DORIS_HTTP", "http://127.0.0.1:8030"), "Apache Doris FE HTTP endpoint")
	dorisUser := fs.String("doris-user", envOrDefault("DORIS_USER", "root"), "Apache Doris username")
	dorisPassword := fs.String("doris-password", envOrDefault("DORIS_PASSWORD", ""), "Apache Doris password")
	dorisDB := fs.String("doris-db", envOrDefault("DORIS_DB", "es_compat"), "Target Apache Doris database name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}

	effectiveDSN := proxy.ApplyDSNAuth(*dorisDSN, *dorisUser, *dorisPassword)
	_, _ = fmt.Fprintf(stdout, "==> doris-es-proxy %s Connectivity Doctor\n", version)

	var failures []string
	mysqlOK := false

	_, _ = fmt.Fprintf(stdout, "  1. Checking Doris FE MySQL (%s)... ", redactDSN(effectiveDSN))
	db, err := sql.Open(sqlDriver, effectiveDSN)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "FAIL (%v)\n", err)
		failures = append(failures, fmt.Sprintf("FE MySQL open failed: %v", err))
	} else {
		defer func() { _ = db.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if pingErr := db.PingContext(ctx); pingErr != nil {
			_, _ = fmt.Fprintf(stdout, "UNREACHABLE (%v)\n", pingErr)
			failures = append(failures, fmt.Sprintf("FE MySQL unreachable: %v", pingErr))
		} else {
			var ver, verComment sql.NullString
			verErr := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver)
			commentErr := db.QueryRowContext(ctx, "SELECT @@version_comment").Scan(&verComment)
			if verErr != nil && commentErr != nil {
				_, _ = fmt.Fprintf(stdout, "FAIL (%v)\n", verErr)
				failures = append(failures, fmt.Sprintf("FE MySQL version query failed: %v", verErr))
			} else {
				mysqlOK = true
				vStr := strings.TrimSpace(ver.String)
				cStr := strings.TrimSpace(verComment.String)
				var summary string
				switch {
				case vStr != "" && cStr != "" && !strings.EqualFold(vStr, cStr):
					summary = vStr + " / " + cStr
				case vStr != "":
					summary = vStr
				default:
					summary = cStr
				}
				_, _ = fmt.Fprintf(stdout, "OK (%s)\n", summary)
			}
		}

		// 2. FE HTTP /api/bootstrap
		_, _ = fmt.Fprintf(stdout, "  2. Checking Doris FE HTTP (%s)... ", redactURLCredentials(*dorisHTTP))
		httpStatus, httpErr := checkDoctorFEHTTP(ctx, *dorisHTTP, *dorisUser, *dorisPassword)
		if httpErr != nil {
			if httpStatus >= 400 {
				_, _ = fmt.Fprintf(stdout, "FAIL (HTTP %d)\n", httpStatus)
			} else {
				_, _ = fmt.Fprintf(stdout, "UNREACHABLE (%v)\n", httpErr)
			}
			failures = append(failures, fmt.Sprintf("FE HTTP check failed: %v", httpErr))
		} else {
			_, _ = fmt.Fprintf(stdout, "OK (HTTP %d)\n", httpStatus)
		}

		// 3. SHOW BACKENDS (require >= 1 alive BE)
		_, _ = fmt.Fprintf(stdout, "  3. Checking Doris Backends (SHOW BACKENDS)... ")
		if !mysqlOK {
			_, _ = fmt.Fprintf(stdout, "SKIPPED (MySQL unreachable)\n")
		} else {
			nodes, beErr := proxy.NewDorisSQLBackend(db, nil).ShowBackendsTelemetry(ctx)
			if beErr != nil {
				_, _ = fmt.Fprintf(stdout, "FAIL (%v)\n", beErr)
				failures = append(failures, fmt.Sprintf("SHOW BACKENDS failed: %v", beErr))
			} else {
				aliveBEs := 0
				for _, node := range nodes {
					if node.Alive {
						aliveBEs++
					}
				}
				if aliveBEs < 1 {
					_, _ = fmt.Fprintf(stdout, "FAIL (0/%d alive)\n", len(nodes))
					failures = append(failures, fmt.Sprintf("no alive Doris backends (0/%d alive)", len(nodes)))
				} else {
					_, _ = fmt.Fprintf(stdout, "OK (%d/%d alive)\n", aliveBEs, len(nodes))
				}
			}
		}

		// 4. _es_catalog readability (non-fatal if fresh uninitialized cluster)
		safeDB := escapeDorisBacktickIdent(*dorisDB)
		_, _ = fmt.Fprintf(stdout, "  4. Checking Doris catalog (`%s`.`_es_catalog`)... ", safeDB)
		if !mysqlOK {
			_, _ = fmt.Fprintf(stdout, "SKIPPED (MySQL unreachable)\n")
		} else if strings.TrimSpace(*dorisDB) == "" {
			_, _ = fmt.Fprintf(stdout, "SKIPPED (--doris-db empty)\n")
		} else {
			// #nosec G201 -- identifier is strictly sanitized via schema.SanitizeDorisIdentifier and backtick-escaped
			catalogSQL := fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`_es_catalog`", safeDB)
			var catalogCount int64
			if catErr := db.QueryRowContext(ctx, catalogSQL).Scan(&catalogCount); catErr != nil {
				if isDoctorMissingCatalogError(catErr) {
					_, _ = fmt.Fprintf(stdout, "NOT_INITIALIZED (ok)\n")
				} else {
					_, _ = fmt.Fprintf(stdout, "FAIL (%v)\n", catErr)
					failures = append(failures, fmt.Sprintf("_es_catalog check failed: %v", catErr))
				}
			} else {
				_, _ = fmt.Fprintf(stdout, "OK (%d entries)\n", catalogCount)
			}
		}

		if len(failures) > 0 {
			return fmt.Errorf("doris-es-proxy doctor failed: %s", strings.Join(failures, "; "))
		}
		return nil
	}

	// Only reached when sql.Open itself failed: still report FE HTTP check.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = fmt.Fprintf(stdout, "  2. Checking Doris FE HTTP (%s)... ", redactURLCredentials(*dorisHTTP))
	httpStatus, httpErr := checkDoctorFEHTTP(ctx, *dorisHTTP, *dorisUser, *dorisPassword)
	if httpErr != nil {
		if httpStatus >= 400 {
			_, _ = fmt.Fprintf(stdout, "FAIL (HTTP %d)\n", httpStatus)
		} else {
			_, _ = fmt.Fprintf(stdout, "UNREACHABLE (%v)\n", httpErr)
		}
		failures = append(failures, fmt.Sprintf("FE HTTP check failed: %v", httpErr))
	} else {
		_, _ = fmt.Fprintf(stdout, "OK (HTTP %d)\n", httpStatus)
	}
	return fmt.Errorf("doris-es-proxy doctor failed: %s", strings.Join(failures, "; "))
}

func checkDoctorFEHTTP(ctx context.Context, rawEndpoints, defaultUser, defaultPass string) (int, error) {
	endpoints := splitCommaTrimmedCLI(rawEndpoints)
	if len(endpoints) == 0 {
		return 0, fmt.Errorf("empty --doris-http endpoint")
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastStatus := 0
	for _, rawEP := range endpoints {
		u, err := url.Parse(rawEP)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return 0, fmt.Errorf("invalid FE HTTP URL %q", redactURLCredentials(rawEP))
		}
		reqUser, reqPass := defaultUser, defaultPass
		hasAuth := defaultPass != ""
		if u.User != nil {
			if uname := u.User.Username(); uname != "" {
				reqUser = uname
			}
			if pw, ok := u.User.Password(); ok {
				reqPass = pw
				hasAuth = true
			}
			u.User = nil
		}
		target := strings.TrimRight(u.String(), "/") + "/api/bootstrap"
		// #nosec G704 -- operator-supplied --doris-http endpoint in CLI doctor subcommand
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return 0, err
		}
		if hasAuth && (reqUser != "" || reqPass != "") {
			req.SetBasicAuth(reqUser, reqPass)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode >= 400 {
			return resp.StatusCode, fmt.Errorf("HTTP %d from %s", resp.StatusCode, redactURLCredentials(rawEP))
		}
	}
	return lastStatus, nil
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
		return fmt.Errorf("invalid endpoint %s: %w", redactURLCredentials(endpoint), err)
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
		return fmt.Errorf("failed to fetch mappings from %s: %w", redactURLCredentials(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read mapping response from %s: %w", redactURLCredentials(endpoint), err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mapping endpoint %s returned HTTP %d: %s", redactURLCredentials(endpoint), resp.StatusCode, strings.TrimSpace(string(raw)))
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
