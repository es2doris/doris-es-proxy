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

package e2e_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// liveDorisTier1UpstreamYAMLSpecs defines the curated 95-file Tier-1 upstream Elasticsearch v8.15.5
// YAML REST conformance corpus executed end-to-end against a live Apache Doris 4.1.3 FE+BE cluster.
var liveDorisTier1UpstreamYAMLSpecs = []string{
	// Bulk & Single-Doc CRUD
	"bulk/10_basic.yml",
	"bulk/12_noop.yml",
	"bulk/20_list_of_strings.yml",
	"bulk/50_refresh.yml",
	"bulk/80_cas.yml",
	"bulk/90_pipeline.yml",
	"index/10_with_id.yml",
	"index/15_without_id.yml",
	"index/20_optype.yml",
	"index/30_cas.yml",
	"index/60_refresh.yml",
	"create/10_with_id.yml",
	"get/10_basic.yml",
	"get/60_realtime_refresh.yml",
	"get/70_source_filtering.yml",
	"get/80_missing.yml",
	"mget/10_basic.yml",
	"mget/70_source_filtering.yml",
	"exists/10_basic.yml",
	"delete/10_basic.yml",
	"delete/20_cas.yml",
	"delete/60_missing.yml",
	"update/10_doc.yml",
	"update/16_noop.yml",
	"update/20_doc_upsert.yml",
	"update/22_doc_as_upsert.yml",
	"update/35_if_seq_no.yml",
	"update/80_source_filtering.yml",

	// Search, Pagination, Scroll, Multi-Search, Count, Explain & Field Caps
	"count/10_basic.yml",
	"count/20_query_string.yml",
	"explain/10_basic.yml",
	"search/10_source_filtering.yml",
	"search/60_query_string.yml",
	"search/70_response_filtering.yml",
	"search/90_search_after.yml",
	"search/110_field_collapsing.yml",
	"search/170_terms_query.yml",
	"search/220_total_hits_object.yml",
	"search/310_match_bool_prefix.yml",
	"search/330_fetch_fields.yml",
	"search/350_point_in_time.yml",
	"scroll/10_basic.yml",
	"scroll/11_clear.yml",
	"msearch/10_basic.yml",
	"field_caps/10_basic.yml",
	"field_caps/50_fieldtype_filter.yml",
	"cat.indices/10_basic.yml",
	"cat.fielddata/10_basic.yml",

	// Index Lifecycle, Mappings, Settings, Aliases & Templates
	"indices.create/10_basic.yml",
	"indices.delete/10_basic.yml",
	"indices.exists/10_basic.yml",
	"indices.get/10_basic.yml",
	"indices.get_mapping/10_basic.yml",
	"indices.put_mapping/10_basic.yml",
	"indices.get_field_mapping/10_basic.yml",
	"indices.put_alias/10_basic.yml",
	"indices.get_alias/10_basic.yml",
	"indices.delete_alias/10_basic.yml",
	"indices.exists_alias/10_basic.yml",
	"indices.update_aliases/10_basic.yml",
	"indices.put_settings/10_basic.yml",
	"indices.get_settings/10_basic.yml",
	"indices.refresh/10_basic.yml",
	"indices.put_index_template/10_basic.yml",
	"indices.get_index_template/10_basic.yml",
	"indices.simulate_index_template/10_basic.yml",
	"indices.rollover/10_basic.yml",
	"indices.validate_query/10_basic.yml",

	// Batch Mutations & Reindex
	"update_by_query/10_basic.yml",
	"delete_by_query/10_basic.yml",
	"reindex/10_basic.yml",

	// Core Bucket, Metric & Pipeline Aggregations + Vector kNN + Ingest
	"aggregations/terms.yml",
	"aggregations/histogram.yml",
	"aggregations/date_histogram.yml",
	"aggregations/range.yml",
	"aggregations/avg_metric.yml",
	"aggregations/sum_metric.yml",
	"aggregations/min_metric.yml",
	"aggregations/max_metric.yml",
	"aggregations/stats_metric.yml",
	"aggregations/extended_stats_metric.yml",
	"aggregations/cardinality_metric.yml",
	"aggregations/value_count_metric.yml",
	"aggregations/top_hits.yml",
	"aggregations/filter.yml",
	"aggregations/filters_bucket.yml",
	"aggregations/global.yml",
	"aggregations/missing.yml",
	"aggregations/nested.yml",
	"aggregations/avg_bucket.yml",
	"aggregations/sum_bucket.yml",
	"aggregations/stats_bucket.yml",
	"aggregations/cumulative_sum.yml",
	"aggregations/derivative.yml",
	"search.vectors/40_knn_search.yml",
	"ingest/20_crud.yml",
}

func buildTier1SpecFilter() map[string]bool {
	set := make(map[string]bool, len(liveDorisTier1UpstreamYAMLSpecs))
	for _, p := range liveDorisTier1UpstreamYAMLSpecs {
		set[p] = true
	}
	return set
}

func resolveE2EConformanceCacheDir() string {
	if envDir := strings.TrimSpace(os.Getenv("CONFORMANCE_CACHE_DIR")); envDir != "" {
		return envDir
	}
	for _, cand := range []string{
		filepath.Join("..", ".cache"),
		filepath.Join("..", "..", ".cache"),
		".cache",
	} {
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	return filepath.Join("..", ".cache")
}

func discoverUpstreamYAMLTestDirs(corpusRoot string) ([]string, error) {
	info, err := os.Stat(corpusRoot)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", corpusRoot)
	}
	var dirs []string
	err = filepath.WalkDir(filepath.Clean(corpusRoot), func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			return filepath.SkipDir
		}
		if strings.HasSuffix(filepath.ToSlash(p), "/rest-api-spec/test") {
			dirs = append(dirs, p)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	return dirs, nil
}

func resetLiveDorisDatabaseState(db *sql.DB, dorisDB string) error {
	escapedDB := strings.ReplaceAll(dorisDB, "`", "``")
	rows, err := db.Query(fmt.Sprintf("SHOW TABLES FROM `%s`", escapedDB))
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var tbl string
		if scanErr := rows.Scan(&tbl); scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
		tables = append(tables, tbl)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return closeErr
	}

	hasCatalog := false
	for _, tbl := range tables {
		if tbl == "_es_catalog" {
			hasCatalog = true
			continue
		}
		escapedTbl := strings.ReplaceAll(tbl, "`", "``")
		if _, dropErr := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s` FORCE", escapedDB, escapedTbl)); dropErr != nil {
			return dropErr
		}
	}
	if hasCatalog {
		var marker int
		if scanErr := db.QueryRow(fmt.Sprintf("SELECT 1 FROM `%s`.`_es_catalog` LIMIT 1", escapedDB)).Scan(&marker); scanErr == nil {
			if _, delErr := db.Exec(fmt.Sprintf("DELETE FROM `%s`.`_es_catalog` WHERE `entity_type` IS NOT NULL", escapedDB)); delErr != nil {
				if _, truncErr := db.Exec(fmt.Sprintf("TRUNCATE TABLE `%s`.`_es_catalog`", escapedDB)); truncErr != nil {
					return truncErr
				}
			}
		}
	}
	return nil
}

func waitForLiveDorisBEReady(t *testing.T, db *sql.DB, dorisDB string) {
	t.Helper()
	escapedDB := strings.ReplaceAll(dorisDB, "`", "``")
	probeDDL := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS `%s`.`_be_ready_probe` (`k` VARCHAR(64) NOT NULL) ENGINE=OLAP UNIQUE KEY(`k`) DISTRIBUTED BY HASH(`k`) BUCKETS 1 PROPERTIES (\"replication_num\" = \"1\")",
		escapedDB,
	)
	dropDDL := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`_be_ready_probe` FORCE", escapedDB)
	for attempt := 1; attempt <= 15; attempt++ {
		_, err := db.Exec(probeDDL)
		if err == nil {
			_, _ = db.Exec(dropDDL)
			return
		}
		if strings.Contains(err.Error(), "Failed to find enough backend") && attempt < 15 {
			t.Logf("Waiting for Doris BE heartbeat/disk report before YAML conformance (attempt %d/15)...", attempt)
			time.Sleep(3 * time.Second)
			continue
		}
		t.Fatalf("live Doris BE readiness probe failed: %v", err)
	}
}

// TestLiveDorisTier1SpecList_ValidatesAgainstUpstreamCache verifies that when the gitignored
// `.cache/es-v8.15.5` corpus is populated on disk, the curated Tier-1 list resolves to 80–100
// real upstream YAML files without typos.
func TestLiveDorisTier1SpecList_ValidatesAgainstUpstreamCache(t *testing.T) {
	v8Root := filepath.Join(resolveE2EConformanceCacheDir(), "es-v8.15.5")
	v8Dirs, err := discoverUpstreamYAMLTestDirs(v8Root)
	if err != nil || len(v8Dirs) == 0 {
		t.Skipf("skipping Tier-1 spec filename check (.cache/es-v8.15.5 absent at %s)", v8Root)
	}

	tier1Filter := buildTier1SpecFilter()
	if len(tier1Filter) < 80 || len(tier1Filter) > 100 {
		t.Fatalf("curated Tier-1 spec count = %d, want between 80 and 100", len(tier1Filter))
	}

	found := make(map[string]bool, len(tier1Filter))
	for _, rootDir := range v8Dirs {
		cleanRoot := filepath.Clean(rootDir)
		walkErr := filepath.WalkDir(cleanRoot, func(fullPath string, d fs.DirEntry, wErr error) error {
			if wErr != nil || d.IsDir() {
				return wErr
			}
			rel, relErr := filepath.Rel(cleanRoot, fullPath)
			if relErr != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if tier1Filter[relSlash] {
				found[relSlash] = true
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", cleanRoot, walkErr)
		}
	}

	var missing []string
	for spec := range tier1Filter {
		if !found[spec] {
			missing = append(missing, spec)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("curated Tier-1 specs missing from .cache/es-v8.15.5: %v", missing)
	}
}

// TestLiveDorisUpstreamYAMLConformance_E2E executes the curated ~90-file Tier-1 upstream
// Elasticsearch v8.15.5 YAML REST conformance suite against a live Apache Doris 4.1.3 cluster
// via ScoreMatchingFiles, resetting Doris table/catalog state cleanly between sections.
func TestLiveDorisUpstreamYAMLConformance_E2E(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("DORIS_E2E_DSN"))
	feHTTP := strings.TrimSpace(os.Getenv("DORIS_E2E_HTTP"))
	if dsn == "" || feHTTP == "" {
		t.Skip("Skipping live Apache Doris upstream YAML conformance E2E test (set DORIS_E2E_DSN and DORIS_E2E_HTTP to run)")
	}

	v8Root := filepath.Join(resolveE2EConformanceCacheDir(), "es-v8.15.5")
	v8Dirs, err := discoverUpstreamYAMLTestDirs(v8Root)
	if err != nil || len(v8Dirs) == 0 {
		if os.Getenv("CONFORMANCE_REQUIRE_UPSTREAM") == "1" {
			t.Fatalf("CONFORMANCE_REQUIRE_UPSTREAM=1 but v8.15.5 corpus missing at %s: %v", v8Root, err)
		}
		t.Skipf("Skipping live Doris YAML conformance (.cache/es-v8.15.5 absent at %s)", v8Root)
	}

	db, err := sql.Open("mysql", proxy.ApplyDSNAuth(dsn, "", ""))
	if err != nil {
		t.Fatalf("failed to open Doris MySQL connection: %v", err)
	}
	defer func() { _ = db.Close() }()

	dorisDB := fmt.Sprintf("es_yaml_e2e_%d", time.Now().Unix())
	if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", dorisDB)); err != nil {
		t.Fatalf("failed to create test Doris database %s: %v", dorisDB, err)
	}
	defer func() {
		_, _ = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s` FORCE", dorisDB))
	}()

	waitForLiveDorisBEReady(t, db, dorisDB)

	slClient := proxy.NewStreamLoadClient(proxy.StreamLoadConfig{
		FEHTTPEndpoint: feHTTP,
		User:           "root",
		Password:       "",
		Database:       dorisDB,
		Timeout:        30 * time.Second,
	})
	backend := proxy.NewDorisSQLBackend(db, slClient)

	// Ensure `_es_catalog` exists once up-front so per-section TRUNCATE is fast and deterministic.
	initSrv := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
	initSrv.SetBulkCoalesce(0, 0)
	initSrv.SetTargetESVersion("8.15.5")
	if bootErr := initSrv.BootstrapCatalog(context.Background()); bootErr != nil {
		t.Logf("initial BootstrapCatalog note: %v", bootErr)
	}
	_ = initSrv.Close(context.Background())

	tier1Set := buildTier1SpecFilter()
	matchTier1 := func(displayPath string) bool {
		return tier1Set[displayPath]
	}

	newLiveSectionHandler := func() (http.Handler, func()) {
		srv := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
		srv.SetBulkCoalesce(0, 0)
		srv.SetQueryCacheTTL(0, 0)
		srv.SetTargetESVersion("8.15.5")
		cleanup := func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Close(closeCtx)
			if resetErr := resetLiveDorisDatabaseState(db, dorisDB); resetErr != nil {
				t.Logf("warning: resetLiveDorisDatabaseState(%s) error: %v", dorisDB, resetErr)
			}
		}
		return srv.Handler(), cleanup
	}

	card, err := compliance.ScoreMatchingFiles(
		compliance.SuiteOptions{
			CorpusName:                 "live-doris-v8.15.5-tier1",
			TargetVersion:              "8.15.5",
			ReuseSetupForReadOnlyFiles: true,
		},
		matchTier1,
		newLiveSectionHandler,
		v8Dirs...,
	)
	if err != nil {
		t.Fatalf("ScoreMatchingFiles against live Doris failed: %v", err)
	}
	if card.ParseErrors != 0 {
		t.Errorf("live Doris Tier-1 YAML scorecard recorded %d parse errors (want 0)", card.ParseErrors)
	}

	t.Logf(
		"[Live Doris YAML Conformance %s] files=%d (skipped=%d, parse_errors=%d) sections=%d passed=%d failed=%d skipped=%d pass_rate=%.2f%%",
		card.Corpus,
		card.TotalFiles,
		card.FilesSkipped,
		card.ParseErrors,
		card.SectionsTotal,
		card.SectionsPassed,
		card.SectionsFailed,
		card.SectionsSkipped,
		card.PassRatePct,
	)

	if outJSON := strings.TrimSpace(os.Getenv("DORIS_LIVE_YAML_OUT_JSON")); outJSON != "" {
		if writeErr := card.WriteJSON(outJSON); writeErr != nil {
			t.Fatalf("writing DORIS_LIVE_YAML_OUT_JSON to %s: %v", outJSON, writeErr)
		}
	}

	minPassed := 50
	if rawMin := strings.TrimSpace(os.Getenv("DORIS_LIVE_YAML_MIN_PASSED")); rawMin != "" {
		parsedMin, convErr := strconv.Atoi(rawMin)
		if convErr != nil {
			t.Fatalf("invalid DORIS_LIVE_YAML_MIN_PASSED=%q: %v", rawMin, convErr)
		}
		minPassed = parsedMin
	}
	if card.SectionsPassed < minPassed {
		t.Fatalf(
			"live Doris upstream YAML conformance SectionsPassed = %d, below threshold %d (failed=%d skipped=%d pass_rate=%.2f%%)",
			card.SectionsPassed,
			minPassed,
			card.SectionsFailed,
			card.SectionsSkipped,
			card.PassRatePct,
		)
	}
}
