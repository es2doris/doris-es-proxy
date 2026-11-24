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
				if i+1 < len(q) && q[i+1] == '`' {
					out.WriteString("``")
					i += 2
					continue
				}
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
					if j+1 < len(q) && q[j+1] == '`' {
						j += 2
						continue
					}
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
				emptyArrType := detectDorisArrayFallbackType(lambdaPart, colPart)
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

func detectDorisArrayFallbackType(lambdaPart, colPart string) string {
	upper := strings.ToUpper(strings.TrimSpace(colPart))
	switch {
	case strings.HasSuffix(upper, " AS ARRAY<FLOAT>)"):
		return "ARRAY<FLOAT>"
	case strings.HasSuffix(upper, " AS ARRAY<BOOLEAN>)"):
		return "ARRAY<BOOLEAN>"
	case strings.HasSuffix(upper, " AS ARRAY<DATETIMEV2(3)>)"):
		return "ARRAY<DATETIMEV2(3)>"
	case strings.HasSuffix(upper, " AS ARRAY<DATETIMEV2(6)>)"):
		return "ARRAY<DATETIMEV2(6)>"
	case strings.HasSuffix(upper, " AS ARRAY<DATETIMEV2>)"):
		return "ARRAY<DATETIMEV2>"
	case strings.HasSuffix(upper, " AS ARRAY<DOUBLE>)"):
		return "ARRAY<DOUBLE>"
	case strings.HasSuffix(upper, " AS ARRAY<BIGINT>)"):
		return "ARRAY<BIGINT>"
	case strings.HasSuffix(upper, " AS ARRAY<LARGEINT>)"):
		return "ARRAY<LARGEINT>"
	case strings.HasSuffix(upper, " AS ARRAY<INT>)"):
		return "ARRAY<INT>"
	case strings.HasSuffix(upper, " AS ARRAY<STRING>)"), strings.HasSuffix(upper, " AS ARRAY<VARCHAR>)"):
		return "ARRAY<STRING>"
	}
	if strings.HasPrefix(upper, "ARRAY_MAP(") {
		if arrowIdx := strings.Index(upper, "->"); arrowIdx > 0 {
			afterArrow := upper[arrowIdx+2:]
			switch {
			case strings.Contains(afterArrow, " AS FLOAT),"):
				return "ARRAY<FLOAT>"
			case strings.Contains(afterArrow, " AS BOOLEAN),"):
				return "ARRAY<BOOLEAN>"
			case strings.Contains(afterArrow, " AS DATETIMEV2(3)),"):
				return "ARRAY<DATETIMEV2(3)>"
			case strings.Contains(afterArrow, " AS DATETIMEV2(6)),"):
				return "ARRAY<DATETIMEV2(6)>"
			case strings.Contains(afterArrow, " AS DATETIMEV2),"):
				return "ARRAY<DATETIMEV2>"
			case strings.Contains(afterArrow, " AS DOUBLE),"):
				return "ARRAY<DOUBLE>"
			case strings.Contains(afterArrow, " AS BIGINT),"):
				return "ARRAY<BIGINT>"
			case strings.Contains(afterArrow, " AS LARGEINT),"):
				return "ARRAY<LARGEINT>"
			case strings.Contains(afterArrow, " AS INT),"):
				return "ARRAY<INT>"
			case strings.Contains(afterArrow, " AS STRING),"), strings.Contains(afterArrow, " AS VARCHAR),"):
				return "ARRAY<STRING>"
			}
		}
	}
	if strings.HasPrefix(upper, "CASE WHEN ") {
		for _, arrType := range []string{
			"ARRAY<FLOAT>",
			"ARRAY<BOOLEAN>",
			"ARRAY<DATETIMEV2(3)>",
			"ARRAY<DATETIMEV2(6)>",
			"ARRAY<DATETIMEV2>",
			"ARRAY<DOUBLE>",
			"ARRAY<BIGINT>",
			"ARRAY<LARGEINT>",
			"ARRAY<INT>",
			"ARRAY<STRING>",
		} {
			if strings.Contains(upper, " AS "+arrType+")") {
				return arrType
			}
		}
	}
	if inferred, ok := detectDorisLambdaCastArrayType(lambdaPart); ok {
		return inferred
	}
	return "ARRAY<STRING>"
}

func isSQLIdentCharR64(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func stripOuterSQLParensR64(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		inSingle := false
		inDouble := false
		inBacktick := false
		balancedOuter := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if inSingle {
				if c == '\\' && i+1 < len(s) {
					i++
					continue
				}
				if c == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					inSingle = false
				}
				continue
			}
			if inDouble {
				if c == '\\' && i+1 < len(s) {
					i++
					continue
				}
				if c == '"' {
					inDouble = false
				}
				continue
			}
			if inBacktick {
				if c == '`' {
					if i+1 < len(s) && s[i+1] == '`' {
						i++
						continue
					}
					inBacktick = false
				}
				continue
			}
			switch c {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '`':
				inBacktick = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i < len(s)-1 {
					balancedOuter = false
				}
			}
			if !balancedOuter {
				break
			}
		}
		if !balancedOuter || depth != 0 {
			break
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func findTopLevelLambdaArrowR64(lambdaPart string) int {
	depth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(lambdaPart); i++ {
		c := lambdaPart[i]
		if inSingle {
			if c == '\\' && i+1 < len(lambdaPart) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(lambdaPart) && lambdaPart[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '\\' && i+1 < len(lambdaPart) {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if c == '`' {
				if i+1 < len(lambdaPart) && lambdaPart[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '-':
			if depth == 0 && i+1 < len(lambdaPart) && lambdaPart[i+1] == '>' {
				return i
			}
		}
	}
	return -1
}

func mapSQLScalarTypeToDorisArrayR64(rawType string) (string, bool) {
	norm := strings.ToUpper(strings.Join(strings.Fields(rawType), ""))
	switch norm {
	case "FLOAT":
		return "ARRAY<FLOAT>", true
	case "DOUBLE":
		return "ARRAY<DOUBLE>", true
	case "BOOLEAN", "BOOL":
		return "ARRAY<BOOLEAN>", true
	case "DATETIMEV2(3)":
		return "ARRAY<DATETIMEV2(3)>", true
	case "DATETIMEV2(6)":
		return "ARRAY<DATETIMEV2(6)>", true
	case "DATETIMEV2":
		return "ARRAY<DATETIMEV2>", true
	case "DATETIME":
		return "ARRAY<DATETIME>", true
	case "DATE":
		return "ARRAY<DATE>", true
	case "LARGEINT":
		return "ARRAY<LARGEINT>", true
	case "BIGINT":
		return "ARRAY<BIGINT>", true
	case "INT", "INTEGER":
		return "ARRAY<INT>", true
	case "SMALLINT":
		return "ARRAY<SMALLINT>", true
	case "TINYINT":
		return "ARRAY<TINYINT>", true
	case "STRING", "VARCHAR":
		return "ARRAY<STRING>", true
	default:
		return "", false
	}
}

func hasASCIIPrefixFoldR64(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a := s[i]
		b := prefix[i]
		if a == b {
			continue
		}
		if a >= 'a' && a <= 'z' {
			a -= 'a' - 'A'
		}
		if b >= 'a' && b <= 'z' {
			b -= 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func detectDorisLambdaCastArrayType(lambdaPart string) (string, bool) {
	arrowIdx := findTopLevelLambdaArrowR64(lambdaPart)
	if arrowIdx <= 0 {
		return "", false
	}
	param := stripOuterSQLParensR64(lambdaPart[:arrowIdx])
	if param == "" {
		return "", false
	}
	for i := 0; i < len(param); i++ {
		if !isSQLIdentCharR64(param[i]) {
			return "", false
		}
	}

	body := lambdaPart[arrowIdx+2:]
	inSingle := false
	inDouble := false
	inBacktick := false
	sawStringCast := false

	for i := 0; i < len(body); {
		c := body[i]
		if inSingle {
			if c == '\\' && i+1 < len(body) {
				i += 2
				continue
			}
			if c == '\'' {
				if i+1 < len(body) && body[i+1] == '\'' {
					i += 2
					continue
				}
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			if c == '\\' && i+1 < len(body) {
				i += 2
				continue
			}
			if c == '"' {
				inDouble = false
			}
			i++
			continue
		}
		if inBacktick {
			if c == '`' {
				if i+1 < len(body) && body[i+1] == '`' {
					i += 2
					continue
				}
				inBacktick = false
			}
			i++
			continue
		}
		switch c {
		case '\'':
			inSingle = true
			i++
			continue
		case '"':
			inDouble = true
			i++
			continue
		case '`':
			inBacktick = true
			i++
			continue
		}

		openParen := -1
		if i == 0 || !isSQLIdentCharR64(body[i-1]) {
			if hasASCIIPrefixFoldR64(body[i:], "TRY_CAST(") {
				openParen = i + len("TRY_CAST")
			} else if hasASCIIPrefixFoldR64(body[i:], "CAST(") {
				openParen = i + len("CAST")
			}
		}
		if openParen < 0 {
			i++
			continue
		}

		depth := 1
		qS, qD, qB := false, false, false
		asIdx := -1
		j := openParen + 1
		for j < len(body) && depth > 0 {
			ch := body[j]
			if qS {
				if ch == '\\' && j+1 < len(body) {
					j += 2
					continue
				}
				if ch == '\'' {
					if j+1 < len(body) && body[j+1] == '\'' {
						j += 2
						continue
					}
					qS = false
				}
			} else if qD {
				if ch == '\\' && j+1 < len(body) {
					j += 2
					continue
				}
				if ch == '"' {
					qD = false
				}
			} else if qB {
				if ch == '`' {
					if j+1 < len(body) && body[j+1] == '`' {
						j += 2
						continue
					}
					qB = false
				}
			} else {
				switch ch {
				case '\'':
					qS = true
				case '"':
					qD = true
				case '`':
					qB = true
				case '(':
					depth++
				case ')':
					depth--
				default:
					if depth == 1 && asIdx < 0 && hasASCIIPrefixFoldR64(body[j:], "AS") &&
						j > openParen+1 && (body[j-1] == ' ' || body[j-1] == '\t' || body[j-1] == '\n' || body[j-1] == ')') &&
						j+2 < len(body) && (body[j+2] == ' ' || body[j+2] == '\t' || body[j+2] == '\n') {
						asIdx = j
					}
				}
			}
			j++
		}

		if depth == 0 && asIdx > openParen+1 {
			argExpr := stripOuterSQLParensR64(body[openParen+1 : asIdx])
			typeExpr := body[asIdx+2 : j-1]
			if strings.EqualFold(argExpr, param) {
				if arrType, ok := mapSQLScalarTypeToDorisArrayR64(typeExpr); ok {
					if arrType != "ARRAY<STRING>" {
						return arrType, true
					}
					sawStringCast = true
				}
			}
		}
		i = openParen + 1
	}
	if sawStringCast {
		return "ARRAY<STRING>", true
	}
	return "", false
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
	return injectHitsSelectColumns(q, true, false)
}

func injectRawDocAndRoutingSelectIntoHitsSQL(q string) (string, bool) {
	return injectHitsSelectColumns(q, true, true)
}

func injectHitsSelectColumns(q string, includeRawDoc, includeRouting bool) (string, bool) {
	if !includeRawDoc && !includeRouting {
		return q, false
	}
	const needle = "SELECT `_id`, `_version`, `_source`, "
	if !strings.Contains(q, needle) {
		return q, false
	}

	var leafExtra, passthroughExtra strings.Builder
	if includeRawDoc {
		leafExtra.WriteString("CAST(`_doc` AS STRING) AS `_raw_doc`, ")
		passthroughExtra.WriteString("`_raw_doc`, ")
	}
	if includeRouting {
		leafExtra.WriteString("`_routing`, ")
		passthroughExtra.WriteString("`_routing`, ")
	}
	leafRepl := needle + leafExtra.String()
	passthroughRepl := needle + passthroughExtra.String()

	var out strings.Builder
	out.Grow(len(q) + 64)
	inSingle := false
	inDouble := false
	inBacktick := false
	changed := false

	for i := 0; i < len(q); {
		ch := q[i]
		if inSingle {
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
				inSingle = false
			}
			out.WriteByte(ch)
			i++
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(q) {
				out.WriteString(q[i : i+2])
				i += 2
				continue
			}
			if ch == '"' {
				inDouble = false
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
		if ch == '/' && i+1 < len(q) && q[i+1] == '*' {
			end := strings.Index(q[i+2:], "*/")
			if end < 0 {
				out.WriteString(q[i:])
				break
			}
			out.WriteString(q[i : i+2+end+2])
			i += 2 + end + 2
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			out.WriteByte(ch)
			i++
			continue
		case '"':
			inDouble = true
			out.WriteByte(ch)
			i++
			continue
		case '`':
			inBacktick = true
			out.WriteByte(ch)
			i++
			continue
		}
		if strings.HasPrefix(q[i:], needle) && isValidHitsSelectBoundary(q[:i]) {
			if selectBlockWrapsNestedHitsSelect(q[i+len(needle):], needle) {
				out.WriteString(passthroughRepl)
			} else {
				out.WriteString(leafRepl)
			}
			changed = true
			i += len(needle)
			continue
		}
		out.WriteByte(ch)
		i++
	}
	if !changed {
		return q, false
	}
	return out.String(), true
}

func isValidHitsSelectBoundary(prefix string) bool {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return true
	}
	if strings.HasSuffix(trimmed, ")") || strings.HasSuffix(trimmed, "(") || strings.HasSuffix(trimmed, "*/") {
		return true
	}
	upper := strings.ToUpper(trimmed)
	return strings.HasSuffix(upper, "UNION ALL") ||
		strings.HasSuffix(upper, "UNION DISTINCT") ||
		strings.HasSuffix(upper, "UNION")
}

func selectBlockWrapsNestedHitsSelect(rest string, needle string) bool {
	depth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if inSingle {
			if ch == '\\' && i+1 < len(rest) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(rest) && rest[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(rest) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(rest) && rest[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return false
			}
			depth--
		default:
			if depth == 0 && (ch == 'F' || ch == 'f') && hasSQLKeywordAt(rest, i, "FROM") {
				afterFrom := strings.TrimLeft(rest[i+4:], " \t\r\n")
				if !strings.HasPrefix(afterFrom, "(") {
					return false
				}
				subBody, ok := extractBalancedParenBody(afterFrom)
				if !ok {
					return false
				}
				return containsHitsSelectOutsideLiterals(subBody, needle)
			}
		}
	}
	return false
}

func hasSQLKeywordAt(s string, idx int, kw string) bool {
	if idx < 0 || idx+len(kw) > len(s) {
		return false
	}
	if !strings.EqualFold(s[idx:idx+len(kw)], kw) {
		return false
	}
	if idx > 0 {
		prev := s[idx-1]
		if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
			return false
		}
	}
	if idx+len(kw) < len(s) {
		next := s[idx+len(kw)]
		if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' {
			return false
		}
	}
	return true
}

func extractBalancedParenBody(s string) (string, bool) {
	if len(s) == 0 || s[0] != '(' {
		return "", false
	}
	depth := 1
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if inSingle {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], true
			}
		}
	}
	return "", false
}

func containsHitsSelectOutsideLiterals(s string, needle string) bool {
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSingle {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		default:
			if strings.HasPrefix(s[i:], needle) && isValidHitsSelectBoundary(s[:i]) {
				return true
			}
		}
	}
	return false
}

type hitsRowScanLayout int

const (
	hitsRowScan5Base hitsRowScanLayout = iota
	hitsRowScan6RawDoc
	hitsRowScan6Routing
	hitsRowScan7RawDocAndRouting
	hitsRowScan7RoutingAndRawDoc
)

func classifyHitsRowScanLayout(cols []string) hitsRowScanLayout {
	switch {
	case len(cols) >= 7:
		if strings.EqualFold(strings.TrimSpace(cols[3]), "_routing") {
			return hitsRowScan7RoutingAndRawDoc
		}
		return hitsRowScan7RawDocAndRouting
	case len(cols) == 6:
		if strings.EqualFold(strings.TrimSpace(cols[3]), "_routing") {
			return hitsRowScan6Routing
		}
		return hitsRowScan6RawDoc
	default:
		return hitsRowScan5Base
	}
}

func (b *DorisSQLBackend) QueryHits(ctx context.Context, querySQL string) ([]HitRow, error) {
	normSQL := normalizeDorisSQL(querySQL)
	withDocRoutingSQL, hasDocRoutingCols := injectRawDocAndRoutingSelectIntoHitsSQL(normSQL)
	execSQL := prependSQLTraceComment(ctx, withDocRoutingSQL)
	if b.logSQL.Load() {
		log.Printf("[Doris HitsSQL]\n%s", execSQL)
	}
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.QueryContext(ctx, execSQL)
	if err != nil && hasDocRoutingCols {
		// Graceful fallback 1: table has `_doc` VARIANT but lacks `_routing` (legacy/external Doris table).
		if withRawDocSQL, hasRawDoc := injectRawDocSelectIntoHitsSQL(normSQL); hasRawDoc {
			fbDocSQL := prependSQLTraceComment(ctx, withRawDocSQL)
			if fbRows, fbErr := b.db.QueryContext(ctx, fbDocSQL); fbErr == nil {
				rows = fbRows
				err = nil
			}
		}
		// Graceful fallback 2: bare `normSQL` when external table lacks both `_routing` and `_doc`.
		if err != nil {
			fallbackSQL := prependSQLTraceComment(ctx, normSQL)
			if fbRows2, fbErr2 := b.db.QueryContext(ctx, fallbackSQL); fbErr2 == nil {
				rows = fbRows2
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	scanLayout := classifyHitsRowScanLayout(cols)

	var hits []HitRow
	for rows.Next() {
		var h HitRow
		var nullID sql.NullString
		var nullVer sql.NullInt64
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var nullRouting sql.NullString
		var nullScore sql.NullFloat64
		var nullTotal sql.NullInt64
		switch scanLayout {
		case hitsRowScan7RawDocAndRouting:
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullRawDoc, &nullRouting, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		case hitsRowScan7RoutingAndRawDoc:
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullRouting, &nullRawDoc, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		case hitsRowScan6RawDoc:
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullRawDoc, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		case hitsRowScan6Routing:
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullRouting, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		default:
			if err := rows.Scan(&nullID, &nullVer, &nullSrc, &nullScore, &nullTotal); err != nil {
				return nil, err
			}
		}
		if !nullID.Valid {
			continue
		}
		h.ID = nullID.String
		h.Version = nullVer.Int64
		if nullRouting.Valid {
			h.Routing = nullRouting.String
		}
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

// QueryRows executes a read-only SQL query and returns rows keyed by column name.
func (b *DorisSQLBackend) QueryRows(ctx context.Context, querySQL string) ([]map[string]any, error) {
	normSQL := prependSQLTraceComment(ctx, normalizeDorisSQL(querySQL))
	if b.logSQL.Load() {
		log.Printf("[Doris RowsSQL]\n%s", normSQL)
	}
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.QueryContext(ctx, normSQL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			if rawB, ok := vals[i].([]byte); ok {
				row[col] = string(rawB)
			} else {
				row[col] = vals[i]
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

type docPointRowScanLayout int

const (
	docPointScan3Base docPointRowScanLayout = iota
	docPointScan4DelSign
	docPointScan4Routing
	docPointScan5RawDocDelSign
	docPointScan5RoutingDelSign
	docPointScan5RawDocRouting
	docPointScan6RawDocRoutingDelSign
)

func classifyDocPointRowScanLayout(cols []string) docPointRowScanLayout {
	switch {
	case len(cols) >= 6:
		return docPointScan6RawDocRoutingDelSign
	case len(cols) == 5:
		c3 := strings.ToLower(strings.TrimSpace(cols[3]))
		c4 := strings.ToLower(strings.TrimSpace(cols[4]))
		if c3 == "_routing" {
			return docPointScan5RoutingDelSign
		}
		if c4 == "_routing" {
			return docPointScan5RawDocRouting
		}
		return docPointScan5RawDocDelSign
	case len(cols) == 4:
		if strings.EqualFold(strings.TrimSpace(cols[3]), "_routing") {
			return docPointScan4Routing
		}
		return docPointScan4DelSign
	default:
		return docPointScan3Base
	}
}

func scanDocPointRow(
	rows *sql.Rows,
	layout docPointRowScanLayout,
	h *HitRow,
	nullSrc *sql.NullString,
	nullRawDoc *sql.NullString,
	nullRouting *sql.NullString,
	delSign *sql.NullInt64,
) (hasDelSignCol bool, err error) {
	switch layout {
	case docPointScan6RawDocRoutingDelSign:
		return true, rows.Scan(&h.ID, &h.Version, nullSrc, nullRawDoc, nullRouting, delSign)
	case docPointScan5RawDocDelSign:
		return true, rows.Scan(&h.ID, &h.Version, nullSrc, nullRawDoc, delSign)
	case docPointScan5RoutingDelSign:
		return true, rows.Scan(&h.ID, &h.Version, nullSrc, nullRouting, delSign)
	case docPointScan5RawDocRouting:
		return false, rows.Scan(&h.ID, &h.Version, nullSrc, nullRawDoc, nullRouting)
	case docPointScan4Routing:
		return false, rows.Scan(&h.ID, &h.Version, nullSrc, nullRouting)
	case docPointScan4DelSign:
		return true, rows.Scan(&h.ID, &h.Version, nullSrc, delSign)
	default:
		return false, rows.Scan(&h.ID, &h.Version, nullSrc)
	}
}

func (b *DorisSQLBackend) GetDocByID(ctx context.Context, dbName, table, id string) (*HitRow, bool, error) {
	if b.db == nil {
		return nil, false, nil
	}
	safeDB := escapeDorisDBIdent(dbName)
	safeTable := sanitizeAndEscapeDorisIdent(table)
	// #nosec G201 -- identifiers are strictly sanitized via schema.SanitizeDorisIdentifier
	candidates := []string{
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `_routing`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1", safeDB, safeTable),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1", safeDB, safeTable),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, `_routing`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1", safeDB, safeTable),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1", safeDB, safeTable),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` = ? ORDER BY `_version` DESC LIMIT 1", safeDB, safeTable),
	}
	var rows *sql.Rows
	var err error
	for i, q := range candidates {
		// #nosec G701 -- parameterized _id query on strictly sanitized identifier
		r, qErr := b.db.QueryContext(ctx, q, id)
		if qErr == nil {
			rows = r
			err = nil
			break
		}
		if i == 0 {
			err = qErr
		}
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	layout := classifyDocPointRowScanLayout(cols)
	var best HitRow
	var bestDeleted bool
	hasRow := false
	for rows.Next() {
		var h HitRow
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var nullRouting sql.NullString
		var delSign sql.NullInt64
		hasDelSignCol, scanErr := scanDocPointRow(rows, layout, &h, &nullSrc, &nullRawDoc, &nullRouting, &delSign)
		if scanErr != nil {
			return nil, false, scanErr
		}
		if hasRow && h.Version < best.Version {
			continue
		}
		if nullRouting.Valid {
			h.Routing = nullRouting.String
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
	candidates := []string{
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `_routing`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC", safeDB, safeTable, inClause),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC", safeDB, safeTable, inClause),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, `_routing`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC", safeDB, safeTable, inClause),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source`, `__DORIS_DELETE_SIGN__` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC", safeDB, safeTable, inClause),
		fmt.Sprintf("SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` IN (%s) ORDER BY `_version` ASC", safeDB, safeTable, inClause),
	}
	var rows *sql.Rows
	var err error
	for i, q := range candidates {
		// #nosec G701 -- parameterized IN query on strictly sanitized identifier
		r, qErr := b.db.QueryContext(ctx, q, args...)
		if qErr == nil {
			rows = r
			err = nil
			break
		}
		if i == 0 {
			err = qErr
		}
	}
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	layout := classifyDocPointRowScanLayout(cols)
	for rows.Next() {
		var h HitRow
		var nullSrc sql.NullString
		var nullRawDoc sql.NullString
		var nullRouting sql.NullString
		var delSign sql.NullInt64
		hasDelSignCol, scanErr := scanDocPointRow(rows, layout, &h, &nullSrc, &nullRawDoc, &nullRouting, &delSign)
		if scanErr != nil {
			return scanErr
		}
		if prevVer, seen := maxVer[h.ID]; seen && h.Version < prevVer {
			continue
		}
		maxVer[h.ID] = h.Version
		if nullRouting.Valid {
			h.Routing = nullRouting.String
		}
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
	if b.streamLoad != nil && len(nodes) > 0 {
		beHosts := make([]string, 0, len(nodes))
		for _, node := range nodes {
			if node.Host != "" {
				beHosts = append(beHosts, node.Host)
			}
		}
		if len(beHosts) > 0 {
			b.streamLoad.AllowBEHosts(beHosts)
		}
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
