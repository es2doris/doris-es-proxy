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
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// DorisSQLBackend implements `DorisBackend` over a pooled `*sql.DB` (MySQL wire protocol :9030)
// for DDL, point queries, and search/aggregation SQL, paired with `StreamLoadClient` (:8030/:8040)
// for high-throughput `/_bulk` and single-document writes.
type DorisSQLBackend struct {
	db         *sql.DB
	streamLoad *StreamLoadClient
	logSQL     atomic.Bool
}

func NewDorisSQLBackend(db *sql.DB, streamLoad *StreamLoadClient) *DorisSQLBackend {
	if db != nil {
		db.SetMaxOpenConns(64)
		db.SetMaxIdleConns(16)
		db.SetConnMaxIdleTime(2 * time.Minute)
		db.SetConnMaxLifetime(5 * time.Minute)
	}
	return &DorisSQLBackend{
		db:         db,
		streamLoad: streamLoad,
	}
}

func (b *DorisSQLBackend) Ping(ctx context.Context) error {
	if b.db == nil {
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return b.db.PingContext(pingCtx)
}

func (b *DorisSQLBackend) SetLogSQL(enabled bool) {
	b.logSQL.Store(enabled)
}

func (b *DorisSQLBackend) ExecDDL(ctx context.Context, ddl string) error {
	if b.logSQL.Load() {
		log.Printf("[Doris DDL]\n%s", ddl)
	}
	if b.db == nil {
		return nil
	}
	_, err := b.db.ExecContext(ctx, ddl)
	return err
}

// NormalizeDorisSQL rewrites internal transpiler markers (`__DORIS_DELETE_SIGN__`, `'\x1f'`, and
// two-argument `array_exists(lambda, col)`) into Apache Doris 2.1/3.x/4.x FE-executable SQL.
func NormalizeDorisSQL(q string) string {
	return normalizeDorisSQL(q)
}

func normalizeDorisSQL(q string) string {
	q = strings.ReplaceAll(q, "`__DORIS_DELETE_SIGN__` = 0 AND ", "")
	q = strings.ReplaceAll(q, `'\x1f'`, "CHAR(31)")
	q = strings.ReplaceAll(q, "'\x1f'", "CHAR(31)")
	return rewriteDorisArrayExists(q)
}

func rewriteDorisArrayExists(q string) string {
	const prefix = "array_exists("
	if !strings.Contains(q, prefix) {
		return q
	}
	var out strings.Builder
	out.Grow(len(q) + 64)
	i := 0
	for i < len(q) {
		idx := strings.Index(q[i:], prefix)
		if idx < 0 {
			out.WriteString(q[i:])
			break
		}
		out.WriteString(q[i : i+idx])
		start := i + idx + len(prefix)
		depth := 1
		inQuote := false
		j := start
		lastTopComma := -1
		for j < len(q) && depth > 0 {
			ch := q[j]
			if inQuote {
				if ch == '\\' && j+1 < len(q) {
					j += 2
					continue
				}
				if ch == '\'' {
					inQuote = false
				}
			} else {
				switch ch {
				case '\'':
					inQuote = true
				case '(':
					depth++
				case ')':
					depth--
				case ',':
					if depth == 1 {
						lastTopComma = j
					}
				}
			}
			j++
		}
		if depth == 0 && lastTopComma > start {
			lambdaPart := strings.TrimSpace(q[start:lastTopComma])
			colPart := strings.TrimSpace(q[lastTopComma+1 : j-1])
			out.WriteString("array_contains(array_exists(")
			out.WriteString(lambdaPart)
			out.WriteString(", IFNULL(")
			out.WriteString(colPart)
			out.WriteString(", CAST([] AS ARRAY<STRING>))), true)")
			i = j
		} else {
			out.WriteString(prefix)
			i = start
		}
	}
	return out.String()
}

type traceMetaContextKey struct{}

// TraceMeta holds W3C TraceContext (`traceparent`), Elasticsearch `X-Opaque-Id`, and `X-Request-ID`
// values propagated as leading SQL comments into Doris FE `fe.audit.log`.
type TraceMeta struct {
	Traceparent string
	OpaqueID    string
	RequestID   string
}

// WithTraceMeta attaches TraceMeta to ctx.
func WithTraceMeta(ctx context.Context, meta TraceMeta) context.Context {
	return context.WithValue(ctx, traceMetaContextKey{}, meta)
}

// TraceMetaFromContext extracts TraceMeta from ctx if present.
func TraceMetaFromContext(ctx context.Context) (TraceMeta, bool) {
	if ctx == nil {
		return TraceMeta{}, false
	}
	m, ok := ctx.Value(traceMetaContextKey{}).(TraceMeta)
	return m, ok
}

func sanitizeSQLCommentToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 128 {
		s = s[:128]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < 0x20 || ch > 0x7e || ch == '*' || ch == '/' || ch == '\'' || ch == '"' || ch == ';' {
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func prependSQLTraceComment(ctx context.Context, q string) string {
	meta, ok := TraceMetaFromContext(ctx)
	if !ok {
		return q
	}
	var parts []string
	if tp := sanitizeSQLCommentToken(meta.Traceparent); tp != "" {
		parts = append(parts, "traceparent="+tp)
	}
	if opq := sanitizeSQLCommentToken(meta.OpaqueID); opq != "" {
		parts = append(parts, "opaque_id="+opq)
	}
	if reqID := sanitizeSQLCommentToken(meta.RequestID); reqID != "" {
		parts = append(parts, "request_id="+reqID)
	}
	if len(parts) == 0 {
		return q
	}
	return "/* " + strings.Join(parts, ", ") + " */ " + q
}

func (b *DorisSQLBackend) QueryHits(ctx context.Context, querySQL string) ([]HitRow, error) {
	querySQL = prependSQLTraceComment(ctx, normalizeDorisSQL(querySQL))
	if b.logSQL.Load() {
		log.Printf("[Doris HitsSQL]\n%s", querySQL)
	}
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.QueryContext(ctx, querySQL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var hits []HitRow
	for rows.Next() {
		var h HitRow
		var srcStr string
		var nullScore sql.NullFloat64
		if err := rows.Scan(&h.ID, &h.Version, &srcStr, &nullScore, &h.TotalHits); err != nil {
			return nil, err
		}
		if nullScore.Valid {
			h.Score = nullScore.Float64
		}
		h.Source = json.RawMessage(srcStr)
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

func (b *DorisSQLBackend) QueryAggs(ctx context.Context, aggsSQL string) ([]AggRow, error) {
	aggsSQL = prependSQLTraceComment(ctx, normalizeDorisSQL(aggsSQL))
	if b.logSQL.Load() {
		log.Printf("[Doris AggsSQL (Nereids Multi-Cast CTE)]\n%s", aggsSQL)
	}
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.QueryContext(ctx, aggsSQL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []AggRow
	for rows.Next() {
		var r AggRow
		var nullBucket sql.NullString
		var val float64
		if err := rows.Scan(&r.AggName, &nullBucket, &val); err != nil {
			return nil, err
		}
		if nullBucket.Valid {
			r.BucketKey = nullBucket.String
		}
		r.Value = val
		r.DocCount = int64(val)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *DorisSQLBackend) GetDocByID(ctx context.Context, dbName, table, id string) (*HitRow, bool, error) {
	if b.db == nil {
		return nil, false, nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	safeTable := schema.SanitizeDorisIdentifier(table)
	// #nosec G201 -- identifiers are strictly sanitized via schema.SanitizeDorisIdentifier
	q := fmt.Sprintf(
		"SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` = ? LIMIT 1",
		safeDB, safeTable,
	)
	var h HitRow
	var srcStr string
	// #nosec G701 -- parameterized _id query on strictly sanitized identifier
	err := b.db.QueryRowContext(ctx, q, id).Scan(&h.ID, &h.Version, &srcStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	h.Source = json.RawMessage(srcStr)
	h.Score = 1.0
	return &h, true, nil
}

func (b *DorisSQLBackend) GetDocsByIDs(ctx context.Context, dbName, table string, ids []string) (map[string]HitRow, error) {
	out := make(map[string]HitRow, len(ids))
	if b.db == nil || len(ids) == 0 {
		return out, nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	safeTable := schema.SanitizeDorisIdentifier(table)
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	// #nosec G201 -- identifiers are strictly sanitized and values are bound via ? placeholders
	q := fmt.Sprintf(
		"SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` IN (%s)",
		safeDB, safeTable, strings.Join(placeholders, ","),
	)
	// #nosec G701 -- parameterized IN query on strictly sanitized identifier
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var h HitRow
		var srcStr string
		if err := rows.Scan(&h.ID, &h.Version, &srcStr); err != nil {
			return nil, err
		}
		h.Source = json.RawMessage(srcStr)
		h.Score = 1.0
		out[h.ID] = h
	}
	return out, rows.Err()
}

func (b *DorisSQLBackend) StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	if b.streamLoad == nil {
		return nil
	}
	return b.streamLoad.LoadNDJSON(ctx, table, ndjson, syncRefresh)
}

func (b *DorisSQLBackend) InitCatalog(ctx context.Context, dbName string) error {
	if b.db == nil {
		return nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	ddl := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS `%s`.`_es_catalog` (\n"+
			"  `entity_type` VARCHAR(32) NOT NULL COMMENT 'index | alias | template',\n"+
			"  `entity_key` VARCHAR(512) NOT NULL COMMENT 'Index, alias, or template name',\n"+
			"  `payload_json` STRING NOT NULL COMMENT 'Serialized metadata JSON',\n"+
			"  `updated_epoch_ms` BIGINT NOT NULL COMMENT 'Monotonic sequence timestamp'\n"+
			")\n"+
			"ENGINE = OLAP\n"+
			"UNIQUE KEY(`entity_type`, `entity_key`)\n"+
			"DISTRIBUTED BY HASH(`entity_key`) BUCKETS 1\n"+
			"PROPERTIES (\n"+
			"  \"replication_num\" = \"1\",\n"+
			"  \"enable_unique_key_merge_on_write\" = \"true\",\n"+
			"  \"store_row_column\" = \"true\",\n"+
			"  \"compression\" = \"zstd\",\n"+
			"  \"function_column.sequence_col\" = \"updated_epoch_ms\"\n"+
			");",
		safeDB,
	)
	return b.ExecDDL(ctx, ddl)
}

func (b *DorisSQLBackend) UpsertCatalogEntry(ctx context.Context, dbName string, entry CatalogEntry) error {
	if b.db == nil {
		return nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via schema.SanitizeDorisIdentifier
	q := fmt.Sprintf(
		"INSERT INTO `%s`.`_es_catalog` (`entity_type`, `entity_key`, `payload_json`, `updated_epoch_ms`) VALUES (?, ?, ?, ?)",
		safeDB,
	)
	_, err := b.db.ExecContext(ctx, q, entry.EntityType, entry.EntityKey, entry.PayloadJSON, entry.UpdatedEpochMs)
	return err
}

func (b *DorisSQLBackend) DeleteCatalogEntry(ctx context.Context, dbName, entityType, entityKey string) error {
	if b.db == nil {
		return nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via schema.SanitizeDorisIdentifier
	q := fmt.Sprintf(
		"DELETE FROM `%s`.`_es_catalog` WHERE `entity_type` = ? AND `entity_key` = ?",
		safeDB,
	)
	_, err := b.db.ExecContext(ctx, q, entityType, entityKey)
	return err
}

func (b *DorisSQLBackend) LoadCatalogEntries(ctx context.Context, dbName string) ([]CatalogEntry, error) {
	if b.db == nil {
		return nil, nil
	}
	safeDB := schema.SanitizeDorisIdentifier(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via schema.SanitizeDorisIdentifier
	q := fmt.Sprintf(
		"SELECT `entity_type`, `entity_key`, `payload_json`, `updated_epoch_ms` FROM `%s`.`_es_catalog` ORDER BY `updated_epoch_ms` ASC",
		safeDB,
	)
	rows, err := b.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []CatalogEntry
	for rows.Next() {
		var e CatalogEntry
		if err := rows.Scan(&e.EntityType, &e.EntityKey, &e.PayloadJSON, &e.UpdatedEpochMs); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
