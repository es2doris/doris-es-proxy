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
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/go-sql-driver/mysql"
)

func stripRawDSNMultiStatements(dsn string) string {
	qIdx := strings.IndexByte(dsn, '?')
	if qIdx < 0 {
		return dsn
	}
	base := dsn[:qIdx]
	rawQuery := dsn[qIdx+1:]
	var kept []string
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, _, _ := strings.Cut(part, "=")
		if strings.EqualFold(strings.TrimSpace(k), "multiStatements") {
			continue
		}
		kept = append(kept, part)
	}
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

func sanitizeAndEscapeDorisIdent(ident string) string {
	return strings.ReplaceAll(schema.SanitizeDorisIdentifier(ident), "`", "``")
}

func escapeDorisDBIdent(db string) string {
	clean := strings.ReplaceAll(strings.TrimSpace(db), "\x00", "")
	return strings.ReplaceAll(clean, "`", "``")
}

// ApplyDSNAuth injects `user` and `password` into a go-sql-driver/mysql DSN when the DSN does
// not already specify an explicit password (or contains an unexpanded `$(DORIS_PASSWORD)` placeholder),
// and unconditionally strips `multiStatements=true` to prevent stacked-query execution.
func ApplyDSNAuth(dsn, user, password string) string {
	if strings.TrimSpace(dsn) == "" {
		return dsn
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return stripRawDSNMultiStatements(dsn)
	}
	cfg.MultiStatements = false
	if user != "" && (cfg.User == "" || cfg.User == "root") {
		cfg.User = user
	}
	if password != "" && (cfg.Passwd == "" || cfg.Passwd == "$(DORIS_PASSWORD)") {
		cfg.Passwd = password
	}
	if cfg.Params == nil {
		cfg.Params = make(map[string]string, 1)
	}
	for k := range cfg.Params {
		if strings.EqualFold(k, "multiStatements") {
			delete(cfg.Params, k)
		}
	}
	if _, hasTZ := cfg.Params["time_zone"]; !hasTZ {
		cfg.Params["time_zone"] = "'+00:00'"
	}
	return cfg.FormatDSN()
}

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

// NormalizeDorisSQL rewrites internal transpiler markers (`__DORIS_DELETE_SIGN__`, `'\x1f'`,
// `'\x1f_vals:'`, and two-argument `array_exists(lambda, col)`) into Apache Doris 2.1/3.x/4.x FE-executable SQL.
func NormalizeDorisSQL(q string) string {
	return normalizeDorisSQL(q)
}

func normalizeDorisSQL(q string) string {
	q = strings.ReplaceAll(q, "`__DORIS_DELETE_SIGN__` = 0 AND ", "")
	q = strings.ReplaceAll(q, "`__DORIS_DELETE_SIGN__` = 0", "1=1")
	q = rewriteDorisUnitSepLiterals(q)
	return rewriteDorisArrayExists(q)
}

func rewriteDorisUnitSepLiterals(q string) string {
	if !strings.Contains(q, `\x1f`) && !strings.Contains(q, "\x1f") && !strings.Contains(q, `\x1F`) {
		return q
	}
	var out strings.Builder
	out.Grow(len(q) + 32)
	inDoubleQuote := false
	inBacktick := false
	i := 0
	for i < len(q) {
		ch := q[i]
		if inDoubleQuote {
			if ch == '\\' && i+1 < len(q) {
				out.WriteString(q[i : i+2])
				i += 2
				continue
			}
			if ch == '"' {
				inDoubleQuote = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(q) && q[i+1] == '`' {
					out.WriteString("``")
					i += 2
					continue
				}
				inBacktick = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '"' {
			inDoubleQuote = true
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '`' {
			inBacktick = true
			out.WriteByte(ch)
			i++
			continue
		}
		if ch != '\'' {
			out.WriteByte(ch)
			i++
			continue
		}
		// Scan single-quoted SQL string literal `'...'`.
		j := i + 1
		closed := false
		for j < len(q) {
			c := q[j]
			if c == '\\' && j+1 < len(q) {
				j += 2
				continue
			}
			if c == '\'' {
				if j+1 < len(q) && q[j+1] == '\'' {
					j += 2
					continue
				}
				closed = true
				break
			}
			j++
		}
		if !closed {
			out.WriteString(q[i:])
			break
		}
		inner := q[i+1 : j]
		if !strings.Contains(inner, `\x1f`) && !strings.Contains(inner, "\x1f") && !strings.Contains(inner, `\x1F`) {
			out.WriteString(q[i : j+1])
			i = j + 1
			continue
		}
		var exprParts []string
		segStart := 0
		k := 0
		for k < len(inner) {
			if inner[k] == 0x1f {
				if k > segStart {
					exprParts = append(exprParts, "'"+inner[segStart:k]+"'")
				}
				exprParts = append(exprParts, "CHAR(31)")
				k++
				segStart = k
				continue
			}
			if k+4 <= len(inner) && inner[k] == '\\' && (inner[k+1] == 'x' || inner[k+1] == 'X') && inner[k+2] == '1' && (inner[k+3] == 'f' || inner[k+3] == 'F') {
				if k > segStart {
					exprParts = append(exprParts, "'"+inner[segStart:k]+"'")
				}
				exprParts = append(exprParts, "CHAR(31)")
				k += 4
				segStart = k
				continue
			}
			if inner[k] == '\\' && k+1 < len(inner) {
				k += 2
				continue
			}
			k++
		}
		if segStart < len(inner) {
			exprParts = append(exprParts, "'"+inner[segStart:]+"'")
		}
		if len(exprParts) == 1 {
			out.WriteString(exprParts[0])
		} else {
			out.WriteString("CONCAT(")
			out.WriteString(strings.Join(exprParts, ", "))
			out.WriteByte(')')
		}
		i = j + 1
	}
	return out.String()
}

func rewriteDorisArrayExists(q string) string {
	const prefix = "array_exists("
	if !strings.Contains(q, prefix) {
		return q
	}
	var out strings.Builder
	out.Grow(len(q) + 64)
	inOuterQuote := false
	inOuterDoubleQuote := false
	inOuterBacktick := false
	i := 0
	for i < len(q) {
		ch := q[i]
		if inOuterQuote {
			if ch == '\\' && i+1 < len(q) {
				out.WriteString(q[i : i+2])
				i += 2
				continue
			}
			if ch == '\'' {
				if i+1 < len(q) && q[i+1] == '\'' {
					out.WriteString("''")
					i += 2
					continue
				}
				inOuterQuote = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if inOuterDoubleQuote {
			if ch == '\\' && i+1 < len(q) {
				out.WriteString(q[i : i+2])
				i += 2
				continue
			}
			if ch == '"' {
				inOuterDoubleQuote = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if inOuterBacktick {
			if ch == '`' {
				inOuterBacktick = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '\'' {
			inOuterQuote = true
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '"' {
			inOuterDoubleQuote = true
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '`' {
			inOuterBacktick = true
			out.WriteByte(ch)
			i++
			continue
		}
		if !strings.HasPrefix(q[i:], prefix) {
			out.WriteByte(ch)
			i++
			continue
		}
		start := i + len(prefix)
		depth := 1
		inQuote := false
		inDoubleQuote := false
		inBacktick := false
		j := start
		lastTopComma := -1
		for j < len(q) && depth > 0 {
			c := q[j]
			if inQuote {
				if c == '\\' && j+1 < len(q) {
					j += 2
					continue
				}
				if c == '\'' {
					if j+1 < len(q) && q[j+1] == '\'' {
						j += 2
						continue
					}
					inQuote = false
				}
			} else if inDoubleQuote {
				if c == '\\' && j+1 < len(q) {
					j += 2
					continue
				}
				if c == '"' {
					inDoubleQuote = false
				}
			} else if inBacktick {
				if c == '`' {
					inBacktick = false
				}
			} else {
				switch c {
				case '\'':
					inQuote = true
				case '"':
					inDoubleQuote = true
				case '`':
					inBacktick = true
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
			lambdaPart := rewriteDorisArrayExists(strings.TrimSpace(q[start:lastTopComma]))
			colPart := rewriteDorisArrayExists(strings.TrimSpace(q[lastTopComma+1 : j-1]))
			alreadyWrapped := strings.HasPrefix(colPart, "IFNULL(") && strings.Contains(colPart, "CAST([] AS ARRAY<")
			if alreadyWrapped {
				out.WriteString("array_exists(")
				out.WriteString(lambdaPart)
				out.WriteString(", ")
				out.WriteString(colPart)
				out.WriteString(")")
			} else {
				emptyArrType := "ARRAY<STRING>"
				if strings.HasPrefix(colPart, "array_map(_x -> CAST(_x AS DOUBLE),") || strings.HasSuffix(colPart, " AS ARRAY<DOUBLE>)") {
					emptyArrType = "ARRAY<DOUBLE>"
				} else if strings.HasPrefix(colPart, "array_map(_x -> CAST(_x AS BIGINT),") || strings.HasSuffix(colPart, " AS ARRAY<BIGINT>)") {
					emptyArrType = "ARRAY<BIGINT>"
				} else if strings.HasPrefix(colPart, "array_map(_x -> CAST(_x AS LARGEINT),") || strings.HasSuffix(colPart, " AS ARRAY<LARGEINT>)") {
					emptyArrType = "ARRAY<LARGEINT>"
				}
				out.WriteString("array_contains(array_exists(")
				out.WriteString(lambdaPart)
				out.WriteString(", IFNULL(")
				out.WriteString(colPart)
				out.WriteString(", CAST([] AS ")
				out.WriteString(emptyArrType)
				out.WriteString("))), true)")
			}
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

func injectRawDocSelectIntoHitsSQL(q string) (string, bool) {
	const needle = "SELECT `_id`, `_version`, `_source`, "
	idx := strings.Index(q, needle)
	if idx < 0 {
		return q, false
	}
	// Only rewrite the outermost projection (either at index 0 or right after CTE `)` + newline).
	prefix := strings.TrimSpace(q[:idx])
	if prefix != "" && !strings.HasSuffix(prefix, ")") && !strings.HasSuffix(prefix, "*/") {
		return q, false
	}
	const replacement = "SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, "
	return q[:idx] + replacement + q[idx+len(needle):], true
}

func (b *DorisSQLBackend) QueryHits(ctx context.Context, querySQL string) ([]HitRow, error) {
	normSQL := normalizeDorisSQL(querySQL)
	withRawDocSQL, hasRawDocCol := injectRawDocSelectIntoHitsSQL(normSQL)
	execSQL := prependSQLTraceComment(ctx, withRawDocSQL)
	if b.logSQL.Load() {
		log.Printf("[Doris HitsSQL]\n%s", execSQL)
	}
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.QueryContext(ctx, execSQL)
	if err != nil && hasRawDocCol {
		fallbackSQL := prependSQLTraceComment(ctx, normSQL)
		if fbRows, fbErr := b.db.QueryContext(ctx, fallbackSQL); fbErr == nil {
			rows = fbRows
			err = nil
			hasRawDocCol = false
		}
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	if hasRawDocCol {
		if cols, colErr := rows.Columns(); colErr == nil && len(cols) < 6 {
			hasRawDocCol = false
		}
	}

	var hits []HitRow
	for rows.Next() {
		var h HitRow
		var nullID sql.NullString
		var nullVer sql.NullInt64
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var nullScore sql.NullFloat64
		var nullTotal sql.NullInt64
		if hasRawDocCol {
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullRawDoc, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		}
		if !nullID.Valid {
			continue
		}
		h.ID = nullID.String
		h.Version = nullVer.Int64
		h.TotalHits = nullTotal.Int64
		if nullScore.Valid {
			h.Score = nullScore.Float64
		} else {
			h.Score = math.NaN()
		}
		h.Source = json.RawMessage(nullSrc.String)
		if nullRawDoc.Valid && strings.TrimSpace(nullRawDoc.String) != "" {
			h.RawSource = mergeSourceWithDocVariantJSON(h.Source, json.RawMessage(nullRawDoc.String))
		}
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
		var nullAggName sql.NullString
		var nullBucket sql.NullString
		var nullVal sql.NullFloat64
		if err := rows.Scan(&nullAggName, &nullBucket, &nullVal); err != nil {
			return nil, err
		}
		if !nullAggName.Valid || !nullBucket.Valid {
			continue
		}
		r.AggName = nullAggName.String
		r.BucketKey = nullBucket.String
		if nullVal.Valid && !math.IsNaN(nullVal.Float64) && !math.IsInf(nullVal.Float64, 0) {
			r.Value = nullVal.Float64
			r.DocCount = int64(nullVal.Float64)
		} else {
			r.Weight = -1
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *DorisSQLBackend) GetDocByID(ctx context.Context, dbName, table, id string) (*HitRow, bool, error) {
	if b.db == nil {
		return nil, false, nil
	}
	safeDB := escapeDorisDBIdent(dbName)
	safeTable := sanitizeAndEscapeDorisIdent(table)
	// #nosec G201 -- identifiers are strictly sanitized via schema.SanitizeDorisIdentifier
	q := fmt.Sprintf(
		"SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1",
		safeDB, safeTable,
	)
	// #nosec G701 -- parameterized _id query on strictly sanitized identifier
	rows, err := b.db.QueryContext(ctx, q, id)
	if err != nil {
		// #nosec G201 -- identifiers are strictly sanitized via schema.SanitizeDorisIdentifier
		qNoDoc := fmt.Sprintf(
			"SELECT `_id`, `_version`, `_source`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1",
			safeDB, safeTable,
		)
		// #nosec G701 -- parameterized _id query on strictly sanitized identifier
		if fbRows, fbErr := b.db.QueryContext(ctx, qNoDoc, id); fbErr == nil {
			rows = fbRows
			err = nil
		} else {
			// #nosec G201 -- identifiers are strictly sanitized via schema.SanitizeDorisIdentifier
			qFallback := fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1",
				safeDB, safeTable,
			)
			// #nosec G701 -- parameterized _id query on strictly sanitized identifier
			if fbRows2, fbErr2 := b.db.QueryContext(ctx, qFallback, id); fbErr2 == nil {
				rows = fbRows2
				err = nil
			}
		}
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	var best HitRow
	var bestDeleted bool
	hasRow := false
	for rows.Next() {
		var h HitRow
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var delSign sql.NullInt64
		hasDelSignCol := false
		switch {
		case len(cols) >= 5:
			hasDelSignCol = true
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc, &nullRawDoc, &delSign); err != nil {
				return nil, false, err
			}
		case len(cols) == 4:
			hasDelSignCol = true
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc, &delSign); err != nil {
				return nil, false, err
			}
		default:
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc); err != nil {
				return nil, false, err
			}
		}
		if hasRow && h.Version < best.Version {
			continue
		}
		srcStr := nullSrc.String
		hasRow = true
		best = h
		best.Source = json.RawMessage(srcStr)
		if nullRawDoc.Valid && strings.TrimSpace(nullRawDoc.String) != "" {
			best.RawSource = mergeSourceWithDocVariantJSON(best.Source, json.RawMessage(nullRawDoc.String))
		}
		best.Score = 1.0
		if hasDelSignCol && delSign.Valid {
			bestDeleted = delSign.Int64 != 0 || (!nullSrc.Valid && !nullRawDoc.Valid)
		} else {
			bestDeleted = !nullSrc.Valid || (strings.TrimSpace(srcStr) == "" && strings.TrimSpace(nullRawDoc.String) == "")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if !hasRow {
		return nil, false, nil
	}
	if bestDeleted {
		return &best, false, nil
	}
	return &best, true, nil
}

const getDocsBatchChunkSize = 4096

func (b *DorisSQLBackend) GetDocsByIDs(ctx context.Context, dbName, table string, ids []string) (map[string]HitRow, error) {
	out := make(map[string]HitRow, len(ids))
	if b.db == nil || len(ids) == 0 {
		return out, nil
	}
	safeDB := escapeDorisDBIdent(dbName)
	safeTable := sanitizeAndEscapeDorisIdent(table)
	maxVer := make(map[string]int64, len(ids))
	for start := 0; start < len(ids); start += getDocsBatchChunkSize {
		end := start + getDocsBatchChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		if err := b.queryDocsBatchChunk(ctx, safeDB, safeTable, chunk, out, maxVer); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (b *DorisSQLBackend) queryDocsBatchChunk(
	ctx context.Context,
	safeDB, safeTable string,
	chunk []string,
	out map[string]HitRow,
	maxVer map[string]int64,
) error {
	placeholders := make([]string, len(chunk))
	args := make([]any, len(chunk))
	for i, id := range chunk {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")
	// #nosec G201 -- identifiers are strictly sanitized/backtick-escaped and values are bound via ? placeholders
	q := fmt.Sprintf(
		"SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC",
		safeDB, safeTable, inClause,
	)
	// #nosec G701 -- parameterized IN query on strictly sanitized identifier
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		// #nosec G201 -- identifiers are strictly sanitized/backtick-escaped and values are bound via ? placeholders
		qNoDoc := fmt.Sprintf(
			"SELECT `_id`, `_version`, `_source`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC",
			safeDB, safeTable, inClause,
		)
		// #nosec G701 -- parameterized IN query on strictly sanitized identifier
		if fbRows, fbErr := b.db.QueryContext(ctx, qNoDoc, args...); fbErr == nil {
			rows = fbRows
			err = nil
		} else {
			// #nosec G201 -- identifiers are strictly sanitized/backtick-escaped and values are bound via ? placeholders
			qFallback := fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC",
				safeDB, safeTable, inClause,
			)
			// #nosec G701 -- parameterized IN query on strictly sanitized identifier
			if fbRows2, fbErr2 := b.db.QueryContext(ctx, qFallback, args...); fbErr2 == nil {
				rows = fbRows2
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	for rows.Next() {
		var h HitRow
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var delSign sql.NullInt64
		hasDelSignCol := false
		switch {
		case len(cols) >= 5:
			hasDelSignCol = true
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc, &nullRawDoc, &delSign); err != nil {
				return err
			}
		case len(cols) == 4:
			hasDelSignCol = true
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc, &delSign); err != nil {
				return err
			}
		default:
			if err := rows.Scan(&h.ID, &h.Version, &nullSrc); err != nil {
				return err
			}
		}
		if prevVer, seen := maxVer[h.ID]; seen && h.Version < prevVer {
			continue
		}
		maxVer[h.ID] = h.Version
		srcStr := nullSrc.String
		var isDeleted bool
		if hasDelSignCol && delSign.Valid {
			isDeleted = delSign.Int64 != 0 || (!nullSrc.Valid && !nullRawDoc.Valid)
		} else {
			isDeleted = !nullSrc.Valid || (strings.TrimSpace(srcStr) == "" && strings.TrimSpace(nullRawDoc.String) == "")
		}
		if isDeleted {
			delete(out, h.ID)
			continue
		}
		h.Source = json.RawMessage(srcStr)
		if nullRawDoc.Valid && strings.TrimSpace(nullRawDoc.String) != "" {
			h.RawSource = mergeSourceWithDocVariantJSON(h.Source, json.RawMessage(nullRawDoc.String))
		}
		h.Score = 1.0
		out[h.ID] = h
	}
	return rows.Err()
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
	safeDB := escapeDorisDBIdent(dbName)
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
	safeDB := escapeDorisDBIdent(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via sanitizeAndEscapeDorisIdent
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
	safeDB := escapeDorisDBIdent(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via sanitizeAndEscapeDorisIdent
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
	safeDB := escapeDorisDBIdent(dbName)
	// #nosec G201 -- safeDB is strictly sanitized via sanitizeAndEscapeDorisIdent
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

// DeleteDocsByIDs physically deletes rows by _id from a Doris UNIQUE KEY MoW table
// so sequence_col (_version) floor is reset when a deleted document is later re-created with _version = 1.
func (b *DorisSQLBackend) DeleteDocsByIDs(ctx context.Context, dbName, table string, ids []string) error {
	if b.db == nil || len(ids) == 0 {
		return nil
	}
	safeDB := escapeDorisDBIdent(dbName)
	safeTable := sanitizeAndEscapeDorisIdent(table)
	if len(ids) == 1 {
		// #nosec G201 -- safeDB and safeTable are strictly sanitized via schema.SanitizeDorisIdentifier
		q := prependSQLTraceComment(ctx, fmt.Sprintf("DELETE FROM `%s`.`%s` WHERE `_id` = ?", safeDB, safeTable))
		if b.logSQL.Load() {
			// #nosec G706 -- sanitized identifier logged only when --log-sql is enabled
			log.Printf("[Doris SQL Delete] %s (id=%q)", q, ids[0])
		}
		_, err := b.db.ExecContext(ctx, q, ids[0]) // #nosec G701 -- safeDB and safeTable are strictly sanitized via schema.SanitizeDorisIdentifier
		return err
	}
	const chunkSize = 256
	for start := 0; start < len(ids); start += chunkSize {
		end := start + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		// #nosec G201 -- safeDB and safeTable are strictly sanitized via schema.SanitizeDorisIdentifier
		q := prependSQLTraceComment(ctx, fmt.Sprintf("DELETE FROM `%s`.`%s` WHERE `_id` IN (%s)", safeDB, safeTable, placeholders))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		if b.logSQL.Load() {
			// #nosec G706 -- sanitized identifier logged only when --log-sql is enabled
			log.Printf("[Doris SQL Delete] %s (count=%d)", q, len(chunk))
		}
		if _, err := b.db.ExecContext(ctx, q, args...); err != nil { // #nosec G701 -- safeDB and safeTable are strictly sanitized via schema.SanitizeDorisIdentifier
			return err
		}
	}
	return nil
}

// DorisBackendNodeTelemetry captures live per-BE storage, CPU, memory, and tablet telemetry
// returned by Apache Doris 4.1.3 `SHOW BACKENDS`.
type DorisBackendNodeTelemetry struct {
	BackendID             string
	Host                  string
	HttpPort              int
	Alive                 bool
	TabletNum             int64
	DataUsedCapacityBytes int64
	TrashUsedBytes        int64
	AvailCapacityBytes    int64
	TotalCapacityBytes    int64
	UsedPct               float64
	CpuCores              int
	MemLimitBytes         int64
	Version               string
}

// DorisTableDataTelemetry captures live per-table storage footprint, replica count, and row count
// returned by Apache Doris 4.1.3 `SHOW DATA FROM <db>`.
type DorisTableDataTelemetry struct {
	TableName       string
	SizeBytes       int64
	RemoteSizeBytes int64
	ReplicaCount    int64
	RowCount        int64
}

// DorisClusterTelemetry aggregates live Doris 4.1.3 `SHOW BACKENDS` and `SHOW DATA` telemetry
// for Elasticsearch `/_nodes/stats`, `/_cluster/stats`, `/_cat/nodes`, `/_cat/indices`, and `/_stats`.
type DorisClusterTelemetry struct {
	Backends           []DorisBackendNodeTelemetry
	Tables             map[string]DorisTableDataTelemetry
	AliveNodes         int
	TotalNodes         int
	TotalCapacityBytes int64
	DataUsedBytes      int64
	AvailCapacityBytes int64
	TotalTablets       int64
}

// TelemetryBackend is an optional extension implemented by *DorisSQLBackend to expose live
// Apache Doris 4.1.3 `SHOW BACKENDS` and `SHOW DATA` telemetry with graceful fallback.
type TelemetryBackend interface {
	ShowBackendsTelemetry(ctx context.Context) ([]DorisBackendNodeTelemetry, error)
	ShowDataTelemetry(ctx context.Context, dbName string) (map[string]DorisTableDataTelemetry, error)
	CollectClusterTelemetry(ctx context.Context, dbName string) *DorisClusterTelemetry
}

// ParseDorisCapacityBytes parses a Doris human-readable byte capacity string (such as
// "1.250 GB", "512.00 MB", "4.000 KiB", "0.000 ", or raw integer bytes "1048576") into bytes.
func ParseDorisCapacityBytes(raw string) int64 {
	s := strings.TrimSpace(raw)
	if s == "" || s == "-" || strings.EqualFold(s, "null") || strings.EqualFold(s, "n/a") {
		return 0
	}
	if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
		if iv < 0 {
			return 0
		}
		return iv
	}

	fields := strings.Fields(s)
	var numStr, unitStr string
	if len(fields) >= 2 {
		numStr = strings.ReplaceAll(fields[0], ",", "")
		unitStr = strings.ToUpper(strings.TrimSpace(fields[1]))
	} else {
		clean := strings.ReplaceAll(s, ",", "")
		splitIdx := len(clean)
		for i := 0; i < len(clean); i++ {
			c := clean[i]
			if (c < '0' || c > '9') && c != '.' && c != '-' && c != '+' {
				splitIdx = i
				break
			}
		}
		numStr = strings.TrimSpace(clean[:splitIdx])
		unitStr = strings.ToUpper(strings.TrimSpace(clean[splitIdx:]))
	}

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
		return 0
	}

	var mult float64
	switch unitStr {
	case "", "B", "BYTE", "BYTES":
		mult = 1
	case "K", "KB", "KIB":
		mult = 1024
	case "M", "MB", "MIB":
		mult = 1024 * 1024
	case "G", "GB", "GIB":
		mult = 1024 * 1024 * 1024
	case "T", "TB", "TIB":
		mult = 1024 * 1024 * 1024 * 1024
	case "P", "PB", "PIB":
		mult = 1024 * 1024 * 1024 * 1024 * 1024
	default:
		return 0
	}

	res := val * mult
	if res >= float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(math.Round(res))
}

// ParseDorisPercent parses a Doris percentage column such as "12.34 %" or "12.34%" into a float64 (12.34).
func ParseDorisPercent(raw string) float64 {
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "%"))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}

func scanDynamicStringRows(rows *sql.Rows) ([]map[string]string, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	lowerCols := make([]string, len(cols))
	for i, c := range cols {
		lowerCols[i] = strings.ToLower(strings.TrimSpace(c))
	}

	var result []map[string]string
	for rows.Next() {
		cells := make([]sql.NullString, len(cols))
		dest := make([]any, len(cols))
		for i := range cells {
			dest[i] = &cells[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		rowMap := make(map[string]string, len(cols))
		for i, key := range lowerCols {
			if cells[i].Valid {
				rowMap[key] = cells[i].String
			}
		}
		result = append(result, rowMap)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func firstNonEmptyCol(row map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(row[k]); v != "" {
			return v
		}
	}
	return ""
}

func parseDorisInt64Col(raw string) int64 {
	s := strings.ReplaceAll(strings.TrimSpace(raw), ",", "")
	if s == "" {
		return 0
	}
	if iv, err := strconv.ParseInt(s, 10, 64); err == nil && iv >= 0 {
		return iv
	}
	if fv, err := strconv.ParseFloat(s, 64); err == nil && fv >= 0 && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		return int64(fv)
	}
	return 0
}

// ShowBackendsTelemetry queries `SHOW BACKENDS` on Apache Doris (compatible with Doris 2.1, 3.x, and 4.1.3)
// using dynamic column-name scanning so version-specific column additions or reorderings never break scanning.
func (b *DorisSQLBackend) ShowBackendsTelemetry(ctx context.Context) ([]DorisBackendNodeTelemetry, error) {
	if b == nil || b.db == nil {
		return nil, nil
	}
	q := prependSQLTraceComment(ctx, "SHOW BACKENDS")
	if b.logSQL.Load() {
		log.Printf("[Doris SQL Telemetry] %s", q)
	}
	rows, err := b.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rowMaps, err := scanDynamicStringRows(rows)
	if err != nil {
		return nil, err
	}

	nodes := make([]DorisBackendNodeTelemetry, 0, len(rowMaps))
	for _, m := range rowMaps {
		aliveStr := firstNonEmptyCol(m, "alive")
		alive := strings.EqualFold(aliveStr, "true") || aliveStr == "1"
		httpPort := int(parseDorisInt64Col(firstNonEmptyCol(m, "httpport", "http_port")))
		cpuCores := int(parseDorisInt64Col(firstNonEmptyCol(m, "cpucores", "cpu_cores")))
		if cpuCores == 0 {
			if statusRaw := firstNonEmptyCol(m, "status"); strings.HasPrefix(statusRaw, "{") {
				var statusObj map[string]any
				if json.Unmarshal([]byte(statusRaw), &statusObj) == nil {
					if cVal, ok := statusObj["cpu_cores"]; ok {
						cpuCores = int(parseDorisInt64Col(fmt.Sprintf("%v", cVal)))
					}
				}
			}
		}

		dataUsed := ParseDorisCapacityBytes(firstNonEmptyCol(m, "datausedcapacity", "data_used_capacity"))
		trashUsed := ParseDorisCapacityBytes(firstNonEmptyCol(m, "trashusedcapacity", "trash_used_capacity"))
		availCap := ParseDorisCapacityBytes(firstNonEmptyCol(m, "availcapacity", "avail_capacity"))
		totalCap := ParseDorisCapacityBytes(firstNonEmptyCol(m, "totalcapacity", "total_capacity"))
		if totalCap == 0 && (dataUsed > 0 || availCap > 0) {
			totalCap = dataUsed + trashUsed + availCap
		} else if availCap == 0 && totalCap > dataUsed+trashUsed {
			availCap = totalCap - dataUsed - trashUsed
		}

		usedPct := ParseDorisPercent(firstNonEmptyCol(m, "usedpct", "used_pct", "maxdiskusedpct"))
		if usedPct == 0 && totalCap > 0 && dataUsed > 0 {
			usedPct = (float64(dataUsed) * 100.0) / float64(totalCap)
		}

		node := DorisBackendNodeTelemetry{
			BackendID:             firstNonEmptyCol(m, "backendid", "backend_id", "id"),
			Host:                  firstNonEmptyCol(m, "host", "ip"),
			HttpPort:              httpPort,
			Alive:                 alive,
			TabletNum:             parseDorisInt64Col(firstNonEmptyCol(m, "tabletnum", "tablet_num")),
			DataUsedCapacityBytes: dataUsed,
			TrashUsedBytes:        trashUsed,
			AvailCapacityBytes:    availCap,
			TotalCapacityBytes:    totalCap,
			UsedPct:               usedPct,
			CpuCores:              cpuCores,
			MemLimitBytes:         ParseDorisCapacityBytes(firstNonEmptyCol(m, "memlimit", "mem_limit")),
			Version:               firstNonEmptyCol(m, "version"),
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func isDorisShowDataSummaryRow(tableName string) bool {
	switch strings.ToLower(strings.TrimSpace(tableName)) {
	case "", "total", "quota", "left", "transaction quota":
		return true
	default:
		return false
	}
}

// ShowDataTelemetry queries `SHOW DATA FROM <dbName>` (gracefully falling back to `SHOW DATA` when
// database-scoped syntax is unsupported) and returns per-table byte sizes, replica counts, and row counts.
func (b *DorisSQLBackend) ShowDataTelemetry(ctx context.Context, dbName string) (map[string]DorisTableDataTelemetry, error) {
	out := make(map[string]DorisTableDataTelemetry)
	if b == nil || b.db == nil {
		return out, nil
	}

	var queries []string
	if trimmedDB := strings.TrimSpace(dbName); trimmedDB != "" {
		safeDB := escapeDorisDBIdent(trimmedDB)
		queries = append(queries, fmt.Sprintf("SHOW DATA FROM `%s`", safeDB))
	}
	queries = append(queries, "SHOW DATA")

	var rowMaps []map[string]string
	var lastErr error
	for _, rawSQL := range queries {
		q := prependSQLTraceComment(ctx, rawSQL)
		if b.logSQL.Load() {
			// #nosec G706 -- safeDB is sanitized via schema.SanitizeDorisIdentifier
			log.Printf("[Doris SQL Telemetry] %s", q)
		}
		rows, err := b.db.QueryContext(ctx, q) // #nosec G701 -- safeDB is strictly sanitized via schema.SanitizeDorisIdentifier
		if err != nil {
			lastErr = err
			continue
		}
		scanned, scanErr := scanDynamicStringRows(rows)
		_ = rows.Close()
		if scanErr != nil {
			lastErr = scanErr
			continue
		}
		rowMaps = scanned
		lastErr = nil
		break
	}
	if lastErr != nil {
		return out, lastErr
	}

	for _, m := range rowMaps {
		tbl := firstNonEmptyCol(m, "tablename", "table_name", "table")
		if isDorisShowDataSummaryRow(tbl) {
			continue
		}
		out[tbl] = DorisTableDataTelemetry{
			TableName:       tbl,
			SizeBytes:       ParseDorisCapacityBytes(firstNonEmptyCol(m, "size", "datasize", "data_size")),
			RemoteSizeBytes: ParseDorisCapacityBytes(firstNonEmptyCol(m, "remotesize", "remote_size")),
			ReplicaCount:    parseDorisInt64Col(firstNonEmptyCol(m, "replicacount", "replica_count")),
			RowCount:        parseDorisInt64Col(firstNonEmptyCol(m, "rowcount", "row_count")),
		}
	}
	return out, nil
}

// CollectClusterTelemetry gathers both `SHOW BACKENDS` and `SHOW DATA` telemetry from Apache Doris 4.1.3,
// degrading gracefully if either query fails due to privilege restrictions or mock SQL environments.
func (b *DorisSQLBackend) CollectClusterTelemetry(ctx context.Context, dbName string) *DorisClusterTelemetry {
	summary := &DorisClusterTelemetry{
		Tables: make(map[string]DorisTableDataTelemetry),
	}
	if b == nil || b.db == nil {
		return summary
	}

	if backends, err := b.ShowBackendsTelemetry(ctx); err == nil {
		summary.Backends = backends
		summary.TotalNodes = len(backends)
		for _, node := range backends {
			if node.Alive {
				summary.AliveNodes++
			}
			summary.TotalCapacityBytes += node.TotalCapacityBytes
			summary.DataUsedBytes += node.DataUsedCapacityBytes
			summary.AvailCapacityBytes += node.AvailCapacityBytes
			summary.TotalTablets += node.TabletNum
		}
	} else if b.logSQL.Load() {
		log.Printf("[Doris SQL Telemetry] SHOW BACKENDS fallback: %v", err)
	}

	if tables, err := b.ShowDataTelemetry(ctx, dbName); err == nil && tables != nil {
		summary.Tables = tables
	} else if err != nil && b.logSQL.Load() {
		log.Printf("[Doris SQL Telemetry] SHOW DATA fallback: %v", err)
	}

	return summary
}
