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
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
)

type round61FakeQueryResult struct {
	cols []string
	rows [][]driver.Value
	err  error
}

type round61FakeDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(query string) round61FakeQueryResult
}

var (
	round61SQLDriverOnce sync.Once
	round61SQLDriverInst = &round61FakeDriver{
		handlers: make(map[string]func(query string) round61FakeQueryResult),
	}
)

func registerRound61SQLScenario(t *testing.T, fn func(query string) round61FakeQueryResult) *sql.DB {
	t.Helper()
	round61SQLDriverOnce.Do(func() {
		sql.Register("round61_doris_telemetry_mock", round61SQLDriverInst)
	})
	dsn := t.Name()
	round61SQLDriverInst.mu.Lock()
	round61SQLDriverInst.handlers[dsn] = fn
	round61SQLDriverInst.mu.Unlock()
	t.Cleanup(func() {
		round61SQLDriverInst.mu.Lock()
		delete(round61SQLDriverInst.handlers, dsn)
		round61SQLDriverInst.mu.Unlock()
	})
	db, err := sql.Open("round61_doris_telemetry_mock", dsn)
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (d *round61FakeDriver) Open(name string) (driver.Conn, error) {
	return &round61FakeConn{dsn: name, drv: d}, nil
}

type round61FakeConn struct {
	dsn string
	drv *round61FakeDriver
}

func (c *round61FakeConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare not used")
}

func (c *round61FakeConn) Close() error { return nil }

func (c *round61FakeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("tx not used")
}

func (c *round61FakeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("no handler registered for dsn %q", c.dsn)
	}
	res := fn(query)
	if res.err != nil {
		return nil, res.err
	}
	return &round61FakeRows{cols: res.cols, rows: res.rows}, nil
}

type round61FakeRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *round61FakeRows) Columns() []string { return r.cols }
func (r *round61FakeRows) Close() error      { return nil }
func (r *round61FakeRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	r.idx++
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		} else {
			dest[i] = nil
		}
	}
	return nil
}

func TestRound61_ParseDorisCapacityBytesAndPercent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want int64
	}{
		{"0.000 ", 0},
		{"", 0},
		{"-", 0},
		{"512 B", 512},
		{"1024", 1024},
		{"2.500 KB", 2560},
		{"1.000 MB", 1024 * 1024},
		{"1.500 GB", int64(1.5 * 1024 * 1024 * 1024)},
		{"2.000 TiB", 2 * 1024 * 1024 * 1024 * 1024},
		{"14.40GB", int64(math.Round(14.4 * 1024 * 1024 * 1024))},
	}
	for _, tc := range cases {
		if got := ParseDorisCapacityBytes(tc.raw); got != tc.want {
			t.Errorf("ParseDorisCapacityBytes(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}

	if got := ParseDorisPercent("12.50 %"); got != 12.5 {
		t.Errorf("ParseDorisPercent(\"12.50 %%\") = %v, want 12.5", got)
	}
	if got := ParseDorisPercent(""); got != 0 {
		t.Errorf("ParseDorisPercent(\"\") = %v, want 0", got)
	}
}

func TestRound61_DorisSQLBackend_ShowBackendsAndShowData_Doris413(t *testing.T) {
	t.Parallel()

	db := registerRound61SQLScenario(t, func(query string) round61FakeQueryResult {
		switch {
		case strings.Contains(query, "SHOW BACKENDS"):
			return round61FakeQueryResult{
				cols: []string{
					"BackendId", "Host", "HeartbeatPort", "BePort", "HttpPort", "BrpcPort",
					"ArrowFlightSqlPort", "LastStartTime", "LastHeartbeat", "Alive",
					"SystemDecommissioned", "TabletNum", "DataUsedCapacity", "TrashUsedCapacity",
					"AvailCapacity", "TotalCapacity", "UsedPct", "MaxDiskUsedPct",
					"RemoteUsedCapacity", "Tag", "ErrMsg", "Version", "Status",
					"HeartbeatFailureCounter", "NodeRole", "CpuCores", "MemLimit",
				},
				rows: [][]driver.Value{
					{
						"10002", "10.0.1.11", "9050", "9060", "8040", "8060",
						"-1", "2026-11-15 00:00:00", "2026-11-15 12:00:00", "true",
						"false", "42", "2.000 GB", "0.000 ",
						"98.000 GB", "100.000 GB", "2.00 %", "2.00 %",
						"0.000 ", `{"location":"default"}`, "", "doris-4.1.3-rc01", `{"lastSuccessReportTabletsTime":"2026-11-15"}`,
						"0", "mix", "16", "14.50 GB",
					},
					{
						"10003", "10.0.1.12", "9050", "9060", "8040", "8060",
						"-1", "2026-11-15 00:00:00", "2026-11-15 12:00:00", "false",
						"false", "18", "512.000 MB", "0.000 ",
						"99.500 GB", "100.000 GB", "0.50 %", "0.50 %",
						"0.000 ", `{"location":"default"}`, "heartbeat timeout", "doris-4.1.3-rc01", `{}`,
						"3", "mix", "8", "8.00 GB",
					},
				},
			}
		case strings.Contains(query, "SHOW DATA FROM `es_compat`"):
			return round61FakeQueryResult{
				cols: []string{"TableName", "Size", "ReplicaCount", "RemoteSize", "RowCount"},
				rows: [][]driver.Value{
					{"orders", "12.000 MB", "3", "0.000 ", "15420"},
					{"products", "512.000 KB", "1", "0.000 ", "420"},
					{"Total", "12.500 MB", "4", "0.000 ", ""},
					{"Quota", "10.000 TB", "", "", ""},
					{"Left", "9.999 TB", "", "", ""},
					{"Transaction Quota", "1000", "", "", ""},
				},
			}
		default:
			return round61FakeQueryResult{err: fmt.Errorf("unexpected SQL: %s", query)}
		}
	})

	backend := NewDorisSQLBackend(db, nil)
	var _ TelemetryBackend = backend

	summary := backend.CollectClusterTelemetry(context.Background(), "es_compat")
	if summary.TotalNodes != 2 || summary.AliveNodes != 1 {
		t.Fatalf("nodes = %d total / %d alive, want 2 / 1", summary.TotalNodes, summary.AliveNodes)
	}
	if summary.TotalTablets != 60 {
		t.Fatalf("TotalTablets = %d, want 60", summary.TotalTablets)
	}
	if summary.Backends[0].CpuCores != 16 || summary.Backends[0].Version != "doris-4.1.3-rc01" {
		t.Fatalf("unexpected backend[0]: %+v", summary.Backends[0])
	}
	if len(summary.Tables) != 2 {
		t.Fatalf("len(Tables) = %d, want 2 (summary rows filtered): %+v", len(summary.Tables), summary.Tables)
	}
	orders, ok := summary.Tables["orders"]
	if !ok || orders.SizeBytes != 12*1024*1024 || orders.ReplicaCount != 3 || orders.RowCount != 15420 {
		t.Fatalf("orders telemetry = %+v, ok=%v", orders, ok)
	}
}

func TestRound61_DorisSQLBackend_GracefulFallbackOnPermissionDeniedAndNilDB(t *testing.T) {
	t.Parallel()

	// 1. Nil backend / nil *sql.DB must never panic or error.
	var nilBackend *DorisSQLBackend
	if nodes, err := nilBackend.ShowBackendsTelemetry(context.Background()); err != nil || nodes != nil {
		t.Fatalf("nil backend ShowBackendsTelemetry = (%v, %v), want (nil, nil)", nodes, err)
	}
	emptyBackend := NewDorisSQLBackend(nil, nil)
	emptySummary := emptyBackend.CollectClusterTelemetry(context.Background(), "es_compat")
	if emptySummary == nil || len(emptySummary.Tables) != 0 || emptySummary.TotalNodes != 0 {
		t.Fatalf("unexpected emptySummary: %+v", emptySummary)
	}

	// 2. Non-admin user denied SHOW BACKENDS + SHOW DATA FROM fallback to SHOW DATA.
	db := registerRound61SQLScenario(t, func(query string) round61FakeQueryResult {
		switch {
		case strings.Contains(query, "SHOW BACKENDS"):
			return round61FakeQueryResult{
				err: errors.New("Error 1227 (42000): Access denied; you need (at least one of) the ADMIN privilege(s)"),
			}
		case strings.Contains(query, "SHOW DATA FROM"):
			return round61FakeQueryResult{
				err: errors.New("syntax fallback to unscoped SHOW DATA"),
			}
		case strings.TrimSpace(query) == "SHOW DATA":
			return round61FakeQueryResult{
				cols: []string{"TableName", "Size", "ReplicaCount"},
				rows: [][]driver.Value{
					{"events", "4.000 MB", "1"},
					{"Total", "4.000 MB", "1"},
				},
			}
		default:
			return round61FakeQueryResult{err: fmt.Errorf("unexpected query: %s", query)}
		}
	})

	b := NewDorisSQLBackend(db, nil)
	summary := b.CollectClusterTelemetry(context.Background(), "es_compat")
	if summary.TotalNodes != 0 {
		t.Fatalf("expected graceful zero nodes on SHOW BACKENDS permission error, got %d", summary.TotalNodes)
	}
	if ev, ok := summary.Tables["events"]; !ok || ev.SizeBytes != 4*1024*1024 {
		t.Fatalf("expected SHOW DATA fallback to populate events table, got %+v", summary.Tables)
	}
}
