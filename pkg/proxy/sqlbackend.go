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

	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// DorisSQLBackend implements `DorisBackend` over a pooled `*sql.DB` (MySQL wire protocol :9030)
// for DDL, point queries, and search/aggregation SQL, paired with `StreamLoadClient` (:8030/:8040)
// for high-throughput `/_bulk` and single-document writes.
type DorisSQLBackend struct {
	db         *sql.DB
	streamLoad *StreamLoadClient
	logSQL     bool
}

func NewDorisSQLBackend(db *sql.DB, streamLoad *StreamLoadClient) *DorisSQLBackend {
	return &DorisSQLBackend{
		db:         db,
		streamLoad: streamLoad,
	}
}

func (b *DorisSQLBackend) SetLogSQL(enabled bool) {
	b.logSQL = enabled
}

func (b *DorisSQLBackend) ExecDDL(ctx context.Context, ddl string) error {
	if b.logSQL {
		log.Printf("[Doris DDL]\n%s", ddl)
	}
	if b.db == nil {
		return nil
	}
	_, err := b.db.ExecContext(ctx, ddl)
	return err
}

func (b *DorisSQLBackend) QueryHits(ctx context.Context, querySQL string) ([]HitRow, error) {
	if b.logSQL {
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
	if b.logSQL {
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
	q := fmt.Sprintf(
		"SELECT `_id`, `_version`, `_source` FROM `%s`.`%s` WHERE `_id` = ? AND `__DORIS_DELETE_SIGN__` = 0 LIMIT 1",
		safeDB, safeTable,
	)
	var h HitRow
	var srcStr string
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

func (b *DorisSQLBackend) StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	if b.streamLoad == nil {
		return nil
	}
	return b.streamLoad.LoadNDJSON(ctx, table, ndjson, syncRefresh)
}
