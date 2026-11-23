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
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
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

const liveDorisRemoteReindexWhitelistForTest = "127.0.0.1:*,[::1]:*,localhost:*,conformance.local:*"

// liveDorisTier1UpstreamYAMLSpecs defines the curated 206-file Tier-1 upstream Elasticsearch v8.15.5
// YAML REST conformance corpus executed end-to-end against a live Apache Doris 4.1.3 FE+BE cluster.
var liveDorisTier1UpstreamYAMLSpecs = []string{
	// Bulk & Single-Doc CRUD (28)
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

	// Search, Pagination, Scroll, Multi-Search, Count, Explain & Field Caps (20)
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

	// Index Lifecycle, Mappings, Settings, Aliases & Templates (20)
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

	// Batch Mutations & Reindex (3)
	"update_by_query/10_basic.yml",
	"delete_by_query/10_basic.yml",
	"reindex/10_basic.yml",

	// Core Bucket, Metric & Pipeline Aggregations + Vector kNN + Ingest (25)
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

	// Round 63 Tier-1 Expansion: REST Root, Data Streams, Runtime Fields, Analysis,
	// Mapper Extras, Percolator, Mustache, Painless, Ingest Processors & X-Pack Plugins (40)
	"ping/10_ping.yml",
	"info/10_info.yml",
	"info/20_lucene_version.yml",
	"data_stream/10_basic.yml",
	"data_stream/20_unsupported_apis.yml",
	"data_stream/30_auto_create_data_stream.yml",
	"data_stream/120_data_streams_stats.yml",
	"runtime_fields/10_keyword.yml",
	"runtime_fields/20_long.yml",
	"runtime_fields/30_double.yml",
	"runtime_fields/40_runtime_mappings.yml",
	"runtime_fields/60_boolean.yml",
	"analysis-common/10_basic.yml",
	"analysis-common/20_analyzers.yml",
	"analysis-common/30_tokenizers.yml",
	"analysis-common/40_token_filters.yml",
	"scaled_float/10_basic.yml",
	"token_count/10_basic.yml",
	"match_only_text/10_basic.yml",
	"rank_feature/10_basic.yml",
	"percolator/10_basic.yml",
	"percolator/20_matched_queries.yml",
	"lang_mustache/10_basic.yml",
	"lang_mustache/20_render_search_template.yml",
	"lang_mustache/30_search_template.yml",
	"painless/10_basic.yml",
	"painless/15_update.yml",
	"painless/20_scriptfield.yml",
	"painless/70_execute_painless_scripts.yml",
	"ingest/30_date_processor.yml",
	"ingest/40_mutate.yml",
	"ingest/90_simulate.yml",
	"ingest/270_set_processor.yml",
	"mapper-unsigned-long/10_basic.yml",
	"mapper-unsigned-long/20_null_value.yml",
	"mapper-constant-keyword/30_sort.yml",
	"mapper-version/40_synthetic_source.yml",
	"wildcard/20_regexp.yml",
	"rrf/100_rank_rrf.yml",
	"rrf/300_rrf_retriever.yml",

	// Round 64 Tier-1 Expansion: Clean Zero-Fail v8.15.5 Specs & F10-Unblocked Specs (70)
	"cluster.desired_nodes/10_basic.yml",
	"indices.stats/13_fields.yml",
	"cat.aliases/10_basic.yml",
	"nodes.info/50_metrics.yml",
	"cluster.desired_nodes/11_old_format.yml",
	"cluster.desired_balance/10_basic.yml",
	"indices.delete_alias/all_path_options.yml",
	"indices.put_index_template/15_composition.yml",
	"cluster.state/20_filtering.yml",
	"indices.stats/11_metric.yml",
	"snapshot.get/10_basic.yml",
	"cat.allocation/10_basic.yml",
	"cat.templates/10_basic.yml",
	"indices.get_mapping/50_wildcard_expansion.yml",
	"indices.stats/10_index.yml",
	"indices.stats/14_groups.yml",
	"aggregations/moving_fn.yml",
	"aggregations/bucket_sort.yml",
	"aggregations/ip_prefix.yml",
	"aggregations/scripted_metric_allow_list.yml",
	"aggregations/typed_keys.yml",
	"aggregations/percentiles_tdigest_metric.yml",
	"aggregations/rare_terms.yml",
	"aggregations/percentiles_hdr_metric.yml",
	"aggregations/pipeline.yml",
	"aggregations/max_bucket.yml",
	"aggregations/min_bucket.yml",
	"search/230_interval_query.yml",
	"search.highlight/50_synthetic_source.yml",
	"search/510_range_query_out_of_bounds.yml",
	"search.vectors/41_knn_search_half_byte_quantized.yml",
	"search.vectors/180_update_dense_vector_type.yml",
	"search.vectors/45_knn_search_bit.yml",
	"search.retrievers/10_standard_retriever.yml",
	"search.vectors/42_knn_search_int4_flat.yml",
	"search/400_synthetic_source.yml",
	"painless/146_dense_vector_bit_basic.yml",
	"painless/180_knn_and_binary_dv_fields_api.yml",
	"painless/185_knn_and_binary_byte_dv_fields_api.yml",
	"search.highlight/30_max_analyzed_offset.yml",
	"search.vectors/42_knn_search_flat.yml",
	"search/30_limits.yml",
	"search/370_profile.yml",
	"tsdb/10_settings.yml",
	"tsdb/25_id_generation.yml",
	"data_stream/150_tsdb.yml",
	"logsdb/10_settings.yml",
	"tsdb/40_search.yml",
	"tsdb/120_counter_fields.yml",
	"tsdb/90_unsupported_operations.yml",
	"esql/40_tsdb.yml",
	"data_stream/200_rollover_failure_store.yml",
	"esql/110_insensitive_equals.yml",
	"reindex/20_validation.yml",
	"update_by_query/20_validation.yml",
	"delete_by_query/20_validation.yml",
	"ingest/190_script_processor.yml",
	"update_by_query/80_scripting.yml",
	"reindex/85_scripting.yml",
	"reindex/90_remote.yml",
	"search/160_exists_query.yml",
	"painless/50_script_doc_values.yml",
	"search/161_exists_query_within_nested_query.yml",
	"search/390_doc_values_search.yml",
	"vector-tile/10_basic.yml",
	"nodes.stats/11_indices_metrics.yml",
	"runtime_fields/90_loops.yml",
	"tsdb/20_mapping.yml",
	"aggregations/time_series.yml",
	"runtime_fields/14_keyword_errors.yml",
}

type liveInProcessHandlerTransport struct {
	handler http.Handler
}

func (t liveInProcessHandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil && req.URL.Port() == "0" {
		return nil, fmt.Errorf("connect_exception: dial tcp %s: connect: connection refused", req.URL.Host)
	}
	if t.handler == nil {
		return nil, fmt.Errorf("connect_exception: nil in-process handler")
	}
	clone := req.Clone(req.Context())
	if clone.Body == nil {
		clone.Body = http.NoBody
	}
	if clone.RequestURI == "" && clone.URL != nil {
		clone.RequestURI = clone.URL.RequestURI()
	}
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, clone)
	resp := rec.Result()
	if resp.Body == nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	return resp, nil
}

func buildTier1SpecFilter() map[string]bool {
	set := make(map[string]bool, len(liveDorisTier1UpstreamYAMLSpecs))
	for _, p := range liveDorisTier1UpstreamYAMLSpecs {
		set[p] = true
	}
	return set
}

func deriveUpstreamSpecCategory(rootDir, relSlash string) string {
	trimmed := strings.TrimPrefix(relSlash, "./")
	if slashIdx := strings.IndexByte(trimmed, '/'); slashIdx > 0 {
		first := trimmed[:slashIdx]
		rest := trimmed[slashIdx+1:]
		if first == "specs" {
			if subIdx := strings.IndexByte(rest, '/'); subIdx > 0 {
				return rest[:subIdx]
			}
		}
		return first
	}
	rootSlash := filepath.ToSlash(rootDir)
	if modIdx := strings.Index(rootSlash, "/modules/"); modIdx >= 0 {
		afterMod := rootSlash[modIdx+len("/modules/"):]
		if endIdx := strings.IndexByte(afterMod, '/'); endIdx > 0 {
			return afterMod[:endIdx]
		}
		if afterMod != "" {
			return afterMod
		}
	}
	if plugIdx := strings.Index(rootSlash, "/x-pack/plugin/"); plugIdx >= 0 {
		afterPlug := rootSlash[plugIdx+len("/x-pack/plugin/"):]
		if endIdx := strings.IndexByte(afterPlug, '/'); endIdx > 0 {
			return afterPlug[:endIdx]
		}
		if afterPlug != "" {
			return afterPlug
		}
	}
	base := filepath.Base(rootSlash)
	if base != "" && base != "." && base != "/" && base != "test" {
		return base
	}
	return "root"
}

func computeUpstreamSpecDisplayPath(cleanRoot, relSlash string) string {
	cat := deriveUpstreamSpecCategory(cleanRoot, relSlash)
	if !strings.Contains(relSlash, "/") && cat != "" && cat != "root" {
		return cat + "/" + relSlash
	}
	return relSlash
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
// `.cache/es-v8.15.5` corpus is populated on disk, the curated Tier-1 list resolves to 200–220
// (specifically 206) unique upstream YAML files whose `displayPath` matches `ScoreMatchingFiles`.
func TestLiveDorisTier1SpecList_ValidatesAgainstUpstreamCache(t *testing.T) {
	tier1Filter := buildTier1SpecFilter()
	if len(tier1Filter) != len(liveDorisTier1UpstreamYAMLSpecs) {
		t.Fatalf("duplicate entries in liveDorisTier1UpstreamYAMLSpecs: unique=%d total=%d", len(tier1Filter), len(liveDorisTier1UpstreamYAMLSpecs))
	}
	if len(tier1Filter) < 200 || len(tier1Filter) > 220 {
		t.Fatalf("curated Tier-1 spec count = %d, want between 200 and 220", len(tier1Filter))
	}

	v8Root := filepath.Join(resolveE2EConformanceCacheDir(), "es-v8.15.5")
	v8Dirs, err := discoverUpstreamYAMLTestDirs(v8Root)
	if err != nil || len(v8Dirs) == 0 {
		t.Skipf("skipping Tier-1 spec filename check (.cache/es-v8.15.5 absent at %s)", v8Root)
	}

	found := make(map[string]bool, len(tier1Filter))
	for _, rootDir := range v8Dirs {
		cleanRoot := filepath.Clean(rootDir)
		walkErr := filepath.WalkDir(cleanRoot, func(fullPath string, d fs.DirEntry, wErr error) error {
			if wErr != nil || d.IsDir() {
				return wErr
			}
			lowerName := strings.ToLower(d.Name())
			if !strings.HasSuffix(lowerName, ".yml") && !strings.HasSuffix(lowerName, ".yaml") {
				return nil
			}
			rel, relErr := filepath.Rel(cleanRoot, fullPath)
			if relErr != nil {
				return nil
			}
			disp := computeUpstreamSpecDisplayPath(cleanRoot, filepath.ToSlash(rel))
			if tier1Filter[disp] {
				found[disp] = true
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

	// Verify ScoreMatchingFiles agrees 100% on all 206 displayPath entries and yields >= 1400 passed sections.
	memCard, scoreErr := compliance.ScoreMatchingFiles(
		compliance.SuiteOptions{
			CorpusName:                 "mem-tier1-validation",
			TargetVersion:              "8.15.5",
			ReuseSetupForReadOnlyFiles: true,
		},
		func(displayPath string) bool { return tier1Filter[displayPath] },
		func() (http.Handler, func()) {
			srv := proxy.NewServer("es_tier1_check", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
			srv.SetBulkCoalesce(0, 0)
			srv.SetQueryCacheTTL(0, 0)
			srv.SetTargetESVersion("8.15.5")
			h := srv.Handler()
			srv.SetRemoteReindexTransport(liveInProcessHandlerTransport{handler: h})
			srv.SetRemoteReindexWhitelistForTest(liveDorisRemoteReindexWhitelistForTest)
			return h, func() { _ = srv.Close(context.Background()) }
		},
		v8Dirs...,
	)
	if scoreErr != nil {
		t.Fatalf("ScoreMatchingFiles validation failed: %v", scoreErr)
	}
	if memCard.TotalFiles != len(tier1Filter) {
		t.Fatalf("ScoreMatchingFiles TotalFiles = %d, want %d (displayPath mismatch)", memCard.TotalFiles, len(tier1Filter))
	}
	if memCard.ParseErrors != 0 {
		t.Fatalf("ScoreMatchingFiles ParseErrors = %d, want 0", memCard.ParseErrors)
	}
	if memCard.SectionsPassed < 1400 {
		t.Fatalf("Tier-1 206-file suite SectionsPassed = %d, want >= 1400", memCard.SectionsPassed)
	}
	t.Logf("[Tier-1 206-File Precheck] files=%d sections=%d passed=%d failed=%d skipped=%d pass_rate=%.2f%%",
		memCard.TotalFiles, memCard.SectionsTotal, memCard.SectionsPassed, memCard.SectionsFailed, memCard.SectionsSkipped, memCard.PassRatePct)
}

// TestLiveDorisUpstreamYAMLConformance_E2E executes the curated 206-file Tier-1 upstream
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
	_, _ = backend.ShowBackendsTelemetry(context.Background())

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
		h := srv.Handler()
		srv.SetRemoteReindexTransport(liveInProcessHandlerTransport{handler: h})
		srv.SetRemoteReindexWhitelistForTest(liveDorisRemoteReindexWhitelistForTest)
		cleanup := func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Close(closeCtx)
			if resetErr := resetLiveDorisDatabaseState(db, dorisDB); resetErr != nil {
				t.Logf("warning: resetLiveDorisDatabaseState(%s) error: %v", dorisDB, resetErr)
			}
		}
		return h, cleanup
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

	maxLoggedFailures := 100
	if rawMaxFail := strings.TrimSpace(os.Getenv("DORIS_LIVE_YAML_MAX_FAILURE_SAMPLES")); rawMaxFail != "" {
		parsedMaxFail, convErr := strconv.Atoi(rawMaxFail)
		if convErr != nil || parsedMaxFail < 0 {
			t.Fatalf("invalid DORIS_LIVE_YAML_MAX_FAILURE_SAMPLES=%q: %v", rawMaxFail, convErr)
		}
		maxLoggedFailures = parsedMaxFail
	}
	for i, f := range card.FailureSamples {
		if i >= maxLoggedFailures {
			t.Logf("[Live Doris YAML Failure] ... (%d additional failure samples omitted)", len(card.FailureSamples)-maxLoggedFailures)
			break
		}
		t.Logf("[Live Doris YAML Failure %d/%d] file=%s section=%q err=%s", i+1, len(card.FailureSamples), f.File, f.Section, f.Error)
	}

	if outJSON := strings.TrimSpace(os.Getenv("DORIS_LIVE_YAML_OUT_JSON")); outJSON != "" {
		if writeErr := card.WriteJSON(outJSON); writeErr != nil {
			t.Fatalf("writing DORIS_LIVE_YAML_OUT_JSON to %s: %v", outJSON, writeErr)
		}
	}

	minPassed := 1400
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
