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

// liveDorisTier1UpstreamYAMLSpecs defines the curated 964-file Tier-1 upstream Elasticsearch v8.15.5
// YAML REST conformance corpus executed end-to-end against a live Apache Doris 4.1.3 FE+BE cluster.
// Excluded from the 971-file upstream v8.15.5 corpus (7 files):
//   - 5 setup/file-skipped specs: cluster.desired_nodes/11_old_format.yml, data_stream/lifecycle/{20_basic,30_not_found}.yml, indices.get_index_template/10_basic.yml, license/100_license.yml
//   - 2 all-section-skipped specs: delete_by_query/40_versioning.yml, parent-join/50_order_by.yml
var liveDorisTier1UpstreamYAMLSpecs = []string{
	// aggregate-metrics (9)
	"aggregate-metrics/100_synthetic_source.yml",
	"aggregate-metrics/10_basic.yml",
	"aggregate-metrics/110_field_caps.yml",
	"aggregate-metrics/20_min_max_agg.yml",
	"aggregate-metrics/30_sum_agg.yml",
	"aggregate-metrics/40_avg_agg.yml",
	"aggregate-metrics/50_value_count_agg.yml",
	"aggregate-metrics/80_raw_agg_metric_aggs.yml",
	"aggregate-metrics/90_tsdb_mappings.yml",
	// aggregations (77)
	"aggregations/adjacency_matrix.yml",
	"aggregations/auto_date_histogram.yml",
	"aggregations/avg_bucket.yml",
	"aggregations/avg_metric.yml",
	"aggregations/bucket_script.yml",
	"aggregations/bucket_selector.yml",
	"aggregations/bucket_sort.yml",
	"aggregations/cardinality_metric.yml",
	"aggregations/composite.yml",
	"aggregations/composite_sorted.yml",
	"aggregations/cumulative_sum.yml",
	"aggregations/date_agg_per_day_of_week.yml",
	"aggregations/date_histogram.yml",
	"aggregations/date_range.yml",
	"aggregations/derivative.yml",
	"aggregations/diversified_sampler.yml",
	"aggregations/doc_count_field.yml",
	"aggregations/empty_field_metric.yml",
	"aggregations/extended_stats_bucket.yml",
	"aggregations/extended_stats_metric.yml",
	"aggregations/filter.yml",
	"aggregations/filters_bucket.yml",
	"aggregations/geo_bounds_centroid.yml",
	"aggregations/geo_distance.yml",
	"aggregations/geohash_grid.yml",
	"aggregations/geotile_grid.yml",
	"aggregations/global.yml",
	"aggregations/global_with_aliases.yml",
	"aggregations/histogram.yml",
	"aggregations/ignored_metadata_field.yml",
	"aggregations/ip_prefix.yml",
	"aggregations/ip_range.yml",
	"aggregations/matrix_stats.yml",
	"aggregations/matrix_stats_multi_value_field.yml",
	"aggregations/matrix_stats_single_value_field.yml",
	"aggregations/max_bucket.yml",
	"aggregations/max_buckets.yml",
	"aggregations/max_metric.yml",
	"aggregations/median_absolute_deviation_metric.yml",
	"aggregations/min_bucket.yml",
	"aggregations/min_metric.yml",
	"aggregations/missing.yml",
	"aggregations/moving_fn.yml",
	"aggregations/nested.yml",
	"aggregations/painless_execute.yml",
	"aggregations/percentile_ranks_hdr_metric.yml",
	"aggregations/percentile_ranks_tdigest_metric.yml",
	"aggregations/percentiles_bucket.yml",
	"aggregations/percentiles_hdr_metric.yml",
	"aggregations/percentiles_tdigest_metric.yml",
	"aggregations/pipeline.yml",
	"aggregations/random_sampler.yml",
	"aggregations/range.yml",
	"aggregations/range_timezone_bug.yml",
	"aggregations/rare_terms.yml",
	"aggregations/sampler.yml",
	"aggregations/scripted_metric.yml",
	"aggregations/scripted_metric_allow_list.yml",
	"aggregations/serial_diff.yml",
	"aggregations/sig_terms.yml",
	"aggregations/significant_text.yml",
	"aggregations/significant_texts.yml",
	"aggregations/stats_bucket.yml",
	"aggregations/stats_metric.yml",
	"aggregations/stats_metric_fail_formatting.yml",
	"aggregations/sum_bucket.yml",
	"aggregations/sum_metric.yml",
	"aggregations/terms.yml",
	"aggregations/terms_disable_opt.yml",
	"aggregations/terms_flattened_field.yml",
	"aggregations/time_series.yml",
	"aggregations/top_hits.yml",
	"aggregations/top_hits_nested_metric.yml",
	"aggregations/typed_keys.yml",
	"aggregations/value_count_metric.yml",
	"aggregations/variable_width_histogram.yml",
	"aggregations/weighted_avg.yml",
	// analysis-common (6)
	"analysis-common/10_basic.yml",
	"analysis-common/20_analyzers.yml",
	"analysis-common/30_tokenizers.yml",
	"analysis-common/40_token_filters.yml",
	"analysis-common/50_char_filters.yml",
	"analysis-common/60_analysis_scripting.yml",
	// analysis_icu (2)
	"analysis_icu/10_basic.yml",
	"analysis_icu/20_search.yml",
	// analysis_kuromoji (2)
	"analysis_kuromoji/10_basic.yml",
	"analysis_kuromoji/20_search.yml",
	// analysis_nori (2)
	"analysis_nori/10_basic.yml",
	"analysis_nori/20_search.yml",
	// analysis_phonetic (5)
	"analysis_phonetic/10_metaphone.yml",
	"analysis_phonetic/20_double_metaphone.yml",
	"analysis_phonetic/30_beider_morse.yml",
	"analysis_phonetic/40_search.yml",
	"analysis_phonetic/50_daitch_mokotoff.yml",
	// analysis_smartcn (2)
	"analysis_smartcn/10_basic.yml",
	"analysis_smartcn/20_search.yml",
	// analysis_stempel (2)
	"analysis_stempel/10_basic.yml",
	"analysis_stempel/20_search.yml",
	// analysis_ukrainian (2)
	"analysis_ukrainian/10_basic.yml",
	"analysis_ukrainian/20_search.yml",
	// analytics (16)
	"analytics/100_tsdb.yml",
	"analytics/boxplot.yml",
	"analytics/cumulative_cardinality.yml",
	"analytics/empty_field_metric.yml",
	"analytics/histogram.yml",
	"analytics/matrix_stats.yml",
	"analytics/moving_percentiles.yml",
	"analytics/multi_terms.yml",
	"analytics/nested_top_metrics_sort.yml",
	"analytics/normalize.yml",
	"analytics/rate.yml",
	"analytics/reset_tracking_rate.yml",
	"analytics/string_stats.yml",
	"analytics/t_test.yml",
	"analytics/top_metrics.yml",
	"analytics/usage.yml",
	// async-search (2)
	"async-search/10_deprecation.yml",
	"async-search/20_keep_alive.yml",
	// async_search (2)
	"async_search/10_basic.yml",
	"async_search/20-with-poin-in-time.yml",
	// autoscaling (4)
	"autoscaling/delete_autoscaling_policy.yml",
	"autoscaling/get_autoscaling_capacity.yml",
	"autoscaling/get_autoscaling_policy.yml",
	"autoscaling/put_autoscaling_policy.yml",
	// bulk (10)
	"bulk/10_basic.yml",
	"bulk/11_dynamic_templates.yml",
	"bulk/12_noop.yml",
	"bulk/20_list_of_strings.yml",
	"bulk/30_big_string.yml",
	"bulk/40_source.yml",
	"bulk/50_refresh.yml",
	"bulk/60_deprecated.yml",
	"bulk/80_cas.yml",
	"bulk/90_pipeline.yml",
	// capabilities (1)
	"capabilities/10_basic.yml",
	// cat.aliases (4)
	"cat.aliases/10_basic.yml",
	"cat.aliases/20_headers.yml",
	"cat.aliases/30_json.yml",
	"cat.aliases/40_hidden.yml",
	// cat.allocation (1)
	"cat.allocation/10_basic.yml",
	// cat.count (1)
	"cat.count/10_basic.yml",
	// cat.fielddata (1)
	"cat.fielddata/10_basic.yml",
	// cat.health (1)
	"cat.health/10_basic.yml",
	// cat.indices (2)
	"cat.indices/10_basic.yml",
	"cat.indices/20_hidden.yml",
	// cat.nodeattrs (1)
	"cat.nodeattrs/10_basic.yml",
	// cat.nodes (1)
	"cat.nodes/10_basic.yml",
	// cat.plugins (1)
	"cat.plugins/10_basic.yml",
	// cat.recovery (1)
	"cat.recovery/10_basic.yml",
	// cat.repositories (1)
	"cat.repositories/10_basic.yml",
	// cat.segments (1)
	"cat.segments/10_basic.yml",
	// cat.shards (1)
	"cat.shards/10_basic.yml",
	// cat.snapshots (1)
	"cat.snapshots/10_basic.yml",
	// cat.tasks (1)
	"cat.tasks/10_basic.yml",
	// cat.templates (2)
	"cat.templates/10_basic.yml",
	"cat.templates/20_matching.yml",
	// cat.thread_pool (1)
	"cat.thread_pool/10_basic.yml",
	// cluster.allocation_explain (1)
	"cluster.allocation_explain/10_basic.yml",
	// cluster.component_template (1)
	"cluster.component_template/10_basic.yml",
	// cluster.desired_balance (1)
	"cluster.desired_balance/10_basic.yml",
	// cluster.desired_nodes (2)
	"cluster.desired_nodes/10_basic.yml",
	"cluster.desired_nodes/20_dry_run.yml",
	// cluster.health (3)
	"cluster.health/10_basic.yml",
	"cluster.health/20_request_timeout.yml",
	"cluster.health/30_indices_options.yml",
	// cluster.info (4)
	"cluster.info/10_info_all.yml",
	"cluster.info/20_info_http.yml",
	"cluster.info/30_info_thread_pool.yml",
	"cluster.info/40_info_script.yml",
	// cluster.pending_tasks (1)
	"cluster.pending_tasks/10_basic.yml",
	// cluster.prevalidate_node_removal (1)
	"cluster.prevalidate_node_removal/10_basic.yml",
	// cluster.put_settings (1)
	"cluster.put_settings/10_basic.yml",
	// cluster.remote_info (1)
	"cluster.remote_info/10_info.yml",
	// cluster.reroute (3)
	"cluster.reroute/10_basic.yml",
	"cluster.reroute/11_explain.yml",
	"cluster.reroute/20_deprecated_response_filtering.yml",
	// cluster.state (3)
	"cluster.state/10_basic.yml",
	"cluster.state/20_filtering.yml",
	"cluster.state/30_expand_wildcards.yml",
	// cluster.stats (4)
	"cluster.stats/10_analysis_stats.yml",
	"cluster.stats/10_basic.yml",
	"cluster.stats/20_analysis_stats_synonyms.yml",
	"cluster.stats/20_indexing_pressure.yml",
	// cluster.voting_config_exclusions (2)
	"cluster.voting_config_exclusions/10_basic.yml",
	"cluster.voting_config_exclusions/10_basic_compat.yml",
	// constant_keyword (2)
	"constant_keyword/10_basic.yml",
	"constant_keyword/20_dynamic_mapping.yml",
	// count (3)
	"count/10_basic.yml",
	"count/20_query_string.yml",
	"count/30_min_score.yml",
	// counted_keyword (2)
	"counted_keyword/10_basic.yml",
	"counted_keyword/20_no_index.yml",
	// create (6)
	"create/10_with_id.yml",
	"create/15_without_id.yml",
	"create/35_external_version.yml",
	"create/40_routing.yml",
	"create/60_refresh.yml",
	"create/70_nested.yml",
	// data_stream (23)
	"data_stream/100_delete_by_query.yml",
	"data_stream/10_basic.yml",
	"data_stream/110_update_by_query.yml",
	"data_stream/120_data_streams_stats.yml",
	"data_stream/130_migrate_to_data_stream.yml",
	"data_stream/140_data_stream_aliases.yml",
	"data_stream/150_tsdb.yml",
	"data_stream/160_unsupported_setting.yml",
	"data_stream/170_modify_data_stream.yml",
	"data_stream/180_simulate_existing_data_stream.yml",
	"data_stream/190_failure_store_redirection.yml",
	"data_stream/190_require_data_stream.yml",
	"data_stream/200_rollover_failure_store.yml",
	"data_stream/20_unsupported_apis.yml",
	"data_stream/30_auto_create_data_stream.yml",
	"data_stream/40_supported_apis.yml",
	"data_stream/50_delete_backing_indices.yml",
	"data_stream/60_get_backing_indices.yml",
	"data_stream/70_rollover_data_streams.yml",
	"data_stream/80_resolve_index_data_streams.yml",
	"data_stream/90_reindex.yml",
	"data_stream/lifecycle/10_explain_lifecycle.yml",
	"data_stream/lifecycle/190_create_data_stream_with_lifecycle.yml",
	// data_streams (1)
	"data_streams/10_data_stream_resolvability.yml",
	// delete (10)
	"delete/10_basic.yml",
	"delete/11_shard_header.yml",
	"delete/12_result.yml",
	"delete/20_cas.yml",
	"delete/25_external_version.yml",
	"delete/26_external_gte_version.yml",
	"delete/30_routing.yml",
	"delete/50_refresh.yml",
	"delete/60_missing.yml",
	"delete/70_tsdb.yml",
	// delete_by_query (5)
	"delete_by_query/10_basic.yml",
	"delete_by_query/20_validation.yml",
	"delete_by_query/50_wait_for_active_shards.yml",
	"delete_by_query/70_throttle.yml",
	"delete_by_query/80_slices.yml",
	// deprecation (1)
	"deprecation/10_basic.yml",
	// dlm (1)
	"dlm/10_usage.yml",
	// downsample (6)
	"downsample/10_basic.yml",
	"downsample/20_unsupported_aggs.yml",
	"downsample/30_date_histogram.yml",
	"downsample/40_runtime_fields.yml",
	"downsample/50_auto_date_histogram.yml",
	"downsample/60_settings.yml",
	// enrich (5)
	"enrich/10_basic.yml",
	"enrich/20_standard_index.yml",
	"enrich/30_tsdb_index.yml",
	"enrich/40_synthetic_source.yml",
	"enrich/50_data_stream.yml",
	// eql (5)
	"eql/10_basic.yml",
	"eql/20_runtime_mappings.yml",
	"eql/30_async_missing_events.yml",
	"eql/40_tsdb.yml",
	"eql/50_samples.yml",
	// esql (27)
	"esql/100_bug_fix.yml",
	"esql/10_basic.yml",
	"esql/110_all_null.yml",
	"esql/110_insensitive_equals.yml",
	"esql/120_profile.yml",
	"esql/130_spatial.yml",
	"esql/140_metadata.yml",
	"esql/150_lookup.yml",
	"esql/160_union_types.yml",
	"esql/161_union_types_subfields.yml",
	"esql/170_no_replicas.yml",
	"esql/20_aggs.yml",
	"esql/25_aggs_on_null.yml",
	"esql/30_types.yml",
	"esql/40_tsdb.yml",
	"esql/40_unsupported_types.yml",
	"esql/45_non_tsdb_counter.yml",
	"esql/50_index_patterns.yml",
	"esql/51_many_indexes.yml",
	"esql/60_enrich.yml",
	"esql/60_usage.yml",
	"esql/61_enrich_ip.yml",
	"esql/62_extra_enrich.yml",
	"esql/70_locale.yml",
	"esql/80_text.yml",
	"esql/81_text_exact_subfields.yml",
	"esql/90_non_indexed.yml",
	// exists (4)
	"exists/10_basic.yml",
	"exists/40_routing.yml",
	"exists/60_realtime_refresh.yml",
	"exists/70_defaults.yml",
	// explain (3)
	"explain/10_basic.yml",
	"explain/20_source_filtering.yml",
	"explain/30_query_string.yml",
	// features.get_features (1)
	"features.get_features/10_basic.yml",
	// features.reset_features (1)
	"features.reset_features/10_basic.yml",
	// field_caps (6)
	"field_caps/10_basic.yml",
	"field_caps/20_meta.yml",
	"field_caps/30_index_filter.yml",
	"field_caps/40_time_series.yml",
	"field_caps/50_fieldtype_filter.yml",
	"field_caps/60_non_empty_fields.yml",
	// get (12)
	"get/100_synthetic_source.yml",
	"get/10_basic.yml",
	"get/110_ignore_malformed.yml",
	"get/120_stored_fields_ignored.yml",
	"get/15_default_values.yml",
	"get/20_stored_fields.yml",
	"get/40_routing.yml",
	"get/50_with_headers.yml",
	"get/60_realtime_refresh.yml",
	"get/70_source_filtering.yml",
	"get/80_missing.yml",
	"get/90_versions.yml",
	// get_source (7)
	"get_source/10_basic.yml",
	"get_source/15_default_values.yml",
	"get_source/40_routing.yml",
	"get_source/60_realtime_refresh.yml",
	"get_source/70_source_filtering.yml",
	"get_source/80_missing.yml",
	"get_source/85_source_missing.yml",
	// graph (1)
	"graph/10_basic.yml",
	// health (4)
	"health/10_basic.yml",
	"health/10_usage.yml",
	"health/30_feature.yml",
	"health/40_diagnosis.yml",
	// ilm (8)
	"ilm/10_basic.yml",
	"ilm/20_move_to_step.yml",
	"ilm/30_retry.yml",
	"ilm/40_explain_lifecycle.yml",
	"ilm/60_operation_mode.yml",
	"ilm/60_remove_policy_for_index.yml",
	"ilm/70_downsampling.yml",
	"ilm/80_health.yml",
	// index (13)
	"index/10_with_id.yml",
	"index/12_result.yml",
	"index/15_without_id.yml",
	"index/20_optype.yml",
	"index/30_cas.yml",
	"index/35_external_version.yml",
	"index/36_external_gte_version.yml",
	"index/40_routing.yml",
	"index/60_refresh.yml",
	"index/70_require_alias.yml",
	"index/80_date_nanos.yml",
	"index/90_geo_point.yml",
	"index/91_metrics_no_subobjects.yml",
	// indices (1)
	"indices/validate_query/10_synonyms.yml",
	// indices.analyze (3)
	"indices.analyze/10_analyze.yml",
	"indices.analyze/10_synonyms.yml",
	"indices.analyze/20_analyze_limit.yml",
	// indices.blocks (1)
	"indices.blocks/10_basic.yml",
	// indices.clear_cache (1)
	"indices.clear_cache/10_basic.yml",
	// indices.clone (3)
	"indices.clone/10_basic.yml",
	"indices.clone/20_source_mapping.yml",
	"indices.clone/30_copy_settings.yml",
	// indices.create (3)
	"indices.create/10_basic.yml",
	"indices.create/20_synthetic_source.yml",
	"indices.create/30_dynamic_template.yml",
	// indices.delete (2)
	"indices.delete/10_basic.yml",
	"indices.delete/20_destructive_wildcard.yml",
	// indices.delete_alias (2)
	"indices.delete_alias/10_basic.yml",
	"indices.delete_alias/all_path_options.yml",
	// indices.deprecated.upgrade (1)
	"indices.deprecated.upgrade/10_basic_upgrade.yml",
	// indices.exists (2)
	"indices.exists/10_basic.yml",
	"indices.exists/20_read_only_index.yml",
	// indices.exists_alias (1)
	"indices.exists_alias/10_basic.yml",
	// indices.exists_template (1)
	"indices.exists_template/10_basic.yml",
	// indices.flush (1)
	"indices.flush/10_basic.yml",
	// indices.forcemerge (1)
	"indices.forcemerge/10_basic.yml",
	// indices.get (1)
	"indices.get/10_basic.yml",
	// indices.get_alias (3)
	"indices.get_alias/10_basic.yml",
	"indices.get_alias/20_empty.yml",
	"indices.get_alias/30_wildcards.yml",
	// indices.get_field_mapping (4)
	"indices.get_field_mapping/10_basic.yml",
	"indices.get_field_mapping/20_missing_field.yml",
	"indices.get_field_mapping/40_missing_index.yml",
	"indices.get_field_mapping/50_field_wildcards.yml",
	// indices.get_index_template (1)
	"indices.get_index_template/20_get_missing.yml",
	// indices.get_mapping (5)
	"indices.get_mapping/10_basic.yml",
	"indices.get_mapping/30_missing_index.yml",
	"indices.get_mapping/40_aliases.yml",
	"indices.get_mapping/50_wildcard_expansion.yml",
	"indices.get_mapping/60_empty.yml",
	// indices.get_settings (3)
	"indices.get_settings/10_basic.yml",
	"indices.get_settings/20_aliases.yml",
	"indices.get_settings/30_defaults.yml",
	// indices.get_template (2)
	"indices.get_template/10_basic.yml",
	"indices.get_template/20_get_missing.yml",
	// indices.open (2)
	"indices.open/10_basic.yml",
	"indices.open/20_multiple_indices.yml",
	// indices.put_alias (2)
	"indices.put_alias/10_basic.yml",
	"indices.put_alias/all_path_options.yml",
	// indices.put_index_template (2)
	"indices.put_index_template/10_basic.yml",
	"indices.put_index_template/15_composition.yml",
	// indices.put_mapping (2)
	"indices.put_mapping/10_basic.yml",
	"indices.put_mapping/all_path_options.yml",
	// indices.put_settings (4)
	"indices.put_settings/10_basic.yml",
	"indices.put_settings/11_reset.yml",
	"indices.put_settings/20_update_non_dynamic_settings.yml",
	"indices.put_settings/all_path_options.yml",
	// indices.put_template (2)
	"indices.put_template/10_basic.yml",
	"indices.put_template/10_basic_compat.yml",
	// indices.recovery (1)
	"indices.recovery/10_basic.yml",
	// indices.refresh (1)
	"indices.refresh/10_basic.yml",
	// indices.resolve_cluster (2)
	"indices.resolve_cluster/10_basic_resolve_cluster.yml",
	"indices.resolve_cluster/20_resolve_system_index.yml",
	// indices.resolve_index (2)
	"indices.resolve_index/10_basic_resolve_index.yml",
	"indices.resolve_index/20_resolve_system_index.yml",
	// indices.rollover (11)
	"indices.rollover/10_basic.yml",
	"indices.rollover/20_max_doc_condition.yml",
	"indices.rollover/25_max_shard_doc_condition.yml",
	"indices.rollover/30_max_size_condition.yml",
	"indices.rollover/35_max_primary_shard_size_condition.yml",
	"indices.rollover/40_mapping.yml",
	"indices.rollover/50_min_age_condition.yml",
	"indices.rollover/55_min_docs_condition.yml",
	"indices.rollover/60_min_primary_shard_docs_condition.yml",
	"indices.rollover/65_min_primary_shard_size_condition.yml",
	"indices.rollover/70_min_size_condition.yml",
	// indices.segments (1)
	"indices.segments/10_basic.yml",
	// indices.shard_stores (1)
	"indices.shard_stores/10_basic.yml",
	// indices.shrink (3)
	"indices.shrink/10_basic.yml",
	"indices.shrink/20_source_mapping.yml",
	"indices.shrink/30_copy_settings.yml",
	// indices.simulate_index_template (1)
	"indices.simulate_index_template/10_basic.yml",
	// indices.simulate_template (1)
	"indices.simulate_template/10_basic.yml",
	// indices.sort (2)
	"indices.sort/10_basic.yml",
	"indices.sort/20_nested.yml",
	// indices.split (6)
	"indices.split/10_basic.yml",
	"indices.split/20_source_mapping.yml",
	"indices.split/30_copy_settings.yml",
	"indices.split/40_routing_partition_size.yml",
	"indices.split/50_routing_required.yml",
	"indices.split/60_nested.yml",
	// indices.stats (13)
	"indices.stats/100_search_idle.yml",
	"indices.stats/10_index.yml",
	"indices.stats/11_metric.yml",
	"indices.stats/12_level.yml",
	"indices.stats/13_fields.yml",
	"indices.stats/14_groups.yml",
	"indices.stats/20_translog.yml",
	"indices.stats/30_segments.yml",
	"indices.stats/40_updates_on_refresh.yml",
	"indices.stats/50_disk_usage.yml",
	"indices.stats/60_field_usage.yml",
	"indices.stats/70_write_load.yml",
	"indices.stats/90_global_ordinals.yml",
	// indices.update_aliases (4)
	"indices.update_aliases/10_basic.yml",
	"indices.update_aliases/20_routing.yml",
	"indices.update_aliases/30_remove_index_and_replace_with_alias.yml",
	"indices.update_aliases/40_must_exist.yml",
	// indices.validate_query (2)
	"indices.validate_query/10_basic.yml",
	"indices.validate_query/20_query_string.yml",
	// inference (1)
	"inference/inference_crud.yml",
	// info (2)
	"info/10_info.yml",
	"info/20_lucene_version.yml",
	// ingest (42)
	"ingest/100_date_index_name_processor.yml",
	"ingest/10_basic.yml",
	"ingest/10_pipeline_with_mustache_templates.yml",
	"ingest/110_sort.yml",
	"ingest/120_grok.yml",
	"ingest/130_escape_dot.yml",
	"ingest/140_json.yml",
	"ingest/150_kv.yml",
	"ingest/15_info_ingest.yml",
	"ingest/160_urldecode.yml",
	"ingest/170_version.yml",
	"ingest/180_bytes_processor.yml",
	"ingest/190_script_processor.yml",
	"ingest/200_default_pipeline.yml",
	"ingest/200_dissect_processor.yml",
	"ingest/20_combine_processors.yml",
	"ingest/20_crud.yml",
	"ingest/210_conditional_processor.yml",
	"ingest/210_pipeline_processor.yml",
	"ingest/220_drop_processor.yml",
	"ingest/230_change_target_index.yml",
	"ingest/240_final_pipeline.yml",
	"ingest/250_csv.yml",
	"ingest/260_seq_no.yml",
	"ingest/270_set_processor.yml",
	"ingest/280_rename.yml",
	"ingest/290_versioned_update.yml",
	"ingest/30_date_processor.yml",
	"ingest/30_update_by_query_with_ingest.yml",
	"ingest/310_reroute_processor.yml",
	"ingest/320_uri_parts_processor.yml",
	"ingest/40_mutate.yml",
	"ingest/40_reindex_with_ingest.yml",
	"ingest/50_on_failure.yml",
	"ingest/50_script_processor_using_painless.yml",
	"ingest/60_fail.yml",
	"ingest/60_pipeline_timestamp_date_mapping.yml",
	"ingest/70_bulk.yml",
	"ingest/70_dynamic_templates.yml",
	"ingest/80_foreach.yml",
	"ingest/80_ingest_simulate.yml",
	"ingest/90_simulate.yml",
	// ingest-useragent (3)
	"ingest-useragent/10_basic.yml",
	"ingest-useragent/20_useragent_processor.yml",
	"ingest-useragent/30_custom_regex.yml",
	// ingest_attachment (3)
	"ingest_attachment/10_basic.yml",
	"ingest_attachment/20_attachment_processor.yml",
	"ingest_attachment/30_files_supported.yml",
	// ingest_geoip (4)
	"ingest_geoip/10_basic.yml",
	"ingest_geoip/20_geoip_processor.yml",
	"ingest_geoip/30_geoip_stats.yml",
	"ingest_geoip/40_geoip_databases.yml",
	// lang_expression (2)
	"lang_expression/10_basic.yml",
	"lang_expression/20_search.yml",
	// lang_mustache (6)
	"lang_mustache/10_basic.yml",
	"lang_mustache/20_render_search_template.yml",
	"lang_mustache/25_custom_functions.yml",
	"lang_mustache/30_search_template.yml",
	"lang_mustache/50_multi_search_template.yml",
	"lang_mustache/60_typed_keys.yml",
	// license (3)
	"license/10_feature_usage.yml",
	"license/20_put_license.yml",
	"license/30_enterprise_license.yml",
	// logsdb (1)
	"logsdb/10_settings.yml",
	// mapper-constant-keyword (3)
	"mapper-constant-keyword/10_script_values.yml",
	"mapper-constant-keyword/20_synthetic_source.yml",
	"mapper-constant-keyword/30_sort.yml",
	// mapper-unsigned-long (7)
	"mapper-unsigned-long/10_basic.yml",
	"mapper-unsigned-long/20_null_value.yml",
	"mapper-unsigned-long/30_multi_fields.yml",
	"mapper-unsigned-long/40_different_numeric.yml",
	"mapper-unsigned-long/50_script_values.yml",
	"mapper-unsigned-long/60_collapse.yml",
	"mapper-unsigned-long/70_time_series.yml",
	// mapper-version (3)
	"mapper-version/40_synthetic_source.yml",
	"mapper-version/50_script_values.yml",
	"mapper-version/60_script_sort_values.yml",
	// mapper_annotatedtext (2)
	"mapper_annotatedtext/10_basic.yml",
	"mapper_annotatedtext/20_synthetic_source.yml",
	// mapper_murmur3 (1)
	"mapper_murmur3/10_basic.yml",
	// mapper_size (1)
	"mapper_size/10_basic.yml",
	// match_only_text (1)
	"match_only_text/10_basic.yml",
	// mget (12)
	"mget/10_basic.yml",
	"mget/12_non_existent_index.yml",
	"mget/13_missing_metadata.yml",
	"mget/14_alias_to_multiple_indices.yml",
	"mget/15_ids.yml",
	"mget/17_default_index.yml",
	"mget/20_stored_fields.yml",
	"mget/40_routing.yml",
	"mget/60_realtime_refresh.yml",
	"mget/70_source_filtering.yml",
	"mget/80_deprecated.yml",
	"mget/90_synthetic_source.yml",
	// migration (2)
	"migration/10_get_feature_upgrade_status.yml",
	"migration/20_post_feature_upgrade.yml",
	// mlt (4)
	"mlt/10_basic.yml",
	"mlt/20_docs.yml",
	"mlt/25_docs_one_shard.yml",
	"mlt/30_unlike.yml",
	// modules (2; F17 corpus-qualified colliding module specs)
	"modules/analysis-common/indices.analyze/10_analyze.yml",
	"modules/ingest-common/ingest/10_basic.yml",
	// monitoring.bulk (1)
	"monitoring.bulk/10_basic_compat.yml",
	// monitoring (2)
	"monitoring/bulk/10_basic.yml",
	"monitoring/bulk/20_privileges.yml",
	// msearch (3)
	"msearch/10_basic.yml",
	"msearch/11_status.yml",
	"msearch/20_typed_keys.yml",
	// mtermvectors (3)
	"mtermvectors/10_basic.yml",
	"mtermvectors/20_deprecated.yml",
	"mtermvectors/30_routing.yml",
	// nodes.hot_threads (2)
	"nodes.hot_threads/10_basic.yml",
	"nodes.hot_threads/10_basic_compat.yml",
	// nodes.info (5)
	"nodes.info/10_basic.yml",
	"nodes.info/20_transport.yml",
	"nodes.info/30_settings.yml",
	"nodes.info/40_aggs.yml",
	"nodes.info/50_metrics.yml",
	// nodes.reload_secure_settings (1)
	"nodes.reload_secure_settings/10_basic.yml",
	// nodes.stats (10)
	"nodes.stats/10_basic.yml",
	"nodes.stats/11_indices_metrics.yml",
	"nodes.stats/20_response_filtering.yml",
	"nodes.stats/30_discovery.yml",
	"nodes.stats/40_store_stats.yml",
	"nodes.stats/50_indexing_pressure.yml",
	"nodes.stats/60_transport_stats.yml",
	"nodes.stats/70_repository_throttling_stats.yml",
	"nodes.stats/80_allocation_stats.yml",
	"nodes.stats/90_fs_watermark_stats.yml",
	// painless (32)
	"painless/100_terms_agg.yml",
	"painless/10_basic.yml",
	"painless/110_script_score_boost.yml",
	"painless/120_stored_scripts.yml",
	"painless/130_metric_agg.yml",
	"painless/140_dense_vector_basic.yml",
	"painless/145_dense_vector_byte_basic.yml",
	"painless/146_dense_vector_bit_basic.yml",
	"painless/150_dense_vector_l1l2.yml",
	"painless/151_dense_vector_byte_hamming.yml",
	"painless/155_dense_vector_byte_l1l2.yml",
	"painless/15_update.yml",
	"painless/160_dense_vector_special_cases.yml",
	"painless/165_dense_vector_byte_special_cases.yml",
	"painless/16_update2.yml",
	"painless/170_dense_vector_script_access.yml",
	"painless/175_dense_vector_byte_script_access.yml",
	"painless/17_update_error.yml",
	"painless/180_knn_and_binary_dv_fields_api.yml",
	"painless/185_knn_and_binary_byte_dv_fields_api.yml",
	"painless/20_scriptfield.yml",
	"painless/25_script_upsert.yml",
	"painless/30_search.yml",
	"painless/45_script_doc_values_cache.yml",
	"painless/50_script_doc_values.yml",
	"painless/55_script_doc_values_dup.yml",
	"painless/60_script_doc_values_binary.yml",
	"painless/65_runtime_doc_values.yml",
	"painless/70_execute_painless_scripts.yml",
	"painless/71_context_api.yml",
	"painless/80_script_score.yml",
	"painless/85_script_score_random_score.yml",
	"painless/90_interval_query_filter.yml",
	// parent-join (5)
	"parent-join/11_parent_child.yml",
	"parent-join/20_parent_join.yml",
	"parent-join/30_inner_hits.yml",
	"parent-join/40_aggregations.yml",
	"parent-join/60_synthetic_source.yml",
	// percolator (3)
	"percolator/10_basic.yml",
	"percolator/20_matched_queries.yml",
	"percolator/30_matched_complex_queries.yml",
	// ping (1)
	"ping/10_ping.yml",
	// profiling (1)
	"profiling/10_basic.yml",
	// range (2)
	"range/10_basic.yml",
	"range/20_synthetic_source.yml",
	// rank_eval (4)
	"rank_eval/10_basic.yml",
	"rank_eval/20_dcg.yml",
	"rank_eval/30_failures.yml",
	"rank_eval/40_rank_eval_templated.yml",
	// rank_feature (3)
	"rank_feature/10_basic.yml",
	"rank_feature/20_null_value.yml",
	"rank_feature/30_synthetic_source.yml",
	// rank_features (2)
	"rank_features/10_basic.yml",
	"rank_features/20_synthetic_source.yml",
	// redact (1)
	"redact/10_redact_processor.yml",
	// reindex (15)
	"reindex/100_tsdb.yml",
	"reindex/10_basic.yml",
	"reindex/110_synthetic_source.yml",
	"reindex/20_validation.yml",
	"reindex/25_no_auto_create.yml",
	"reindex/30_search.yml",
	"reindex/35_search_failures.yml",
	"reindex/40_versioning.yml",
	"reindex/50_routing.yml",
	"reindex/60_wait_for_active_shards.yml",
	"reindex/70_throttle.yml",
	"reindex/80_slices.yml",
	"reindex/85_scripting.yml",
	"reindex/90_remote.yml",
	"reindex/95_parent_join.yml",
	// repository_url (2)
	"repository_url/10_basic.yml",
	"repository_url/20_repository.yml",
	// rollup (8)
	"rollup/delete_job.yml",
	"rollup/get_jobs.yml",
	"rollup/get_rollup_caps.yml",
	"rollup/get_rollup_index_caps.yml",
	"rollup/put_job.yml",
	"rollup/rollup_search.yml",
	"rollup/start_job.yml",
	"rollup/stop_job.yml",
	// rrf (8)
	"rrf/100_rank_rrf.yml",
	"rrf/150_rank_rrf_pagination.yml",
	"rrf/200_rank_rrf_script.yml",
	"rrf/300_rrf_retriever.yml",
	"rrf/400_rrf_retriever_script.yml",
	"rrf/500_rrf_retriever_explain.yml",
	"rrf/550_rrf_sub_searches_explain.yml",
	"rrf/600_rrf_retriever_profile.yml",
	// runtime_fields (44)
	"runtime_fields/100_geo_point.yml",
	"runtime_fields/101_geo_point_from_source.yml",
	"runtime_fields/102_geo_point_source_in_query.yml",
	"runtime_fields/103_geo_point_calculated_at_index.yml",
	"runtime_fields/10_keyword.yml",
	"runtime_fields/110_composite.yml",
	"runtime_fields/111_search_time_composite.yml",
	"runtime_fields/114_composite_errors.yml",
	"runtime_fields/11_keyword_from_source.yml",
	"runtime_fields/12_keyword_source_in_query.yml",
	"runtime_fields/13_keyword_calculated_at_index.yml",
	"runtime_fields/14_keyword_errors.yml",
	"runtime_fields/150_nested_runtime_fields.yml",
	"runtime_fields/20_long.yml",
	"runtime_fields/21_long_from_source.yml",
	"runtime_fields/22_long_source_in_query.yml",
	"runtime_fields/23_long_calculated_at_index.yml",
	"runtime_fields/24_long_errors.yml",
	"runtime_fields/250_grok.yml",
	"runtime_fields/260_dissect.yml",
	"runtime_fields/270_synthetic_source.yml",
	"runtime_fields/30_double.yml",
	"runtime_fields/31_double_from_source.yml",
	"runtime_fields/32_double_source_in_query.yml",
	"runtime_fields/33_double_calculated_at_index.yml",
	"runtime_fields/34_double_errors.yml",
	"runtime_fields/40_date.yml",
	"runtime_fields/40_runtime_mappings.yml",
	"runtime_fields/41_date_from_source.yml",
	"runtime_fields/42_date_source_in_query.yml",
	"runtime_fields/43_date_calculated_at_index.yml",
	"runtime_fields/44_date_errors.yml",
	"runtime_fields/50_ip.yml",
	"runtime_fields/51_ip_from_source.yml",
	"runtime_fields/52_ip_source_in_query.yml",
	"runtime_fields/53_ip_calculated_at_index.yml",
	"runtime_fields/54_ip_errors.yml",
	"runtime_fields/60_boolean.yml",
	"runtime_fields/61_boolean_from_source.yml",
	"runtime_fields/62_boolean_source_in_query.yml",
	"runtime_fields/63_boolean_calculated_at_index.yml",
	"runtime_fields/64_boolean_errors.yml",
	"runtime_fields/80_multiple_indices.yml",
	"runtime_fields/90_loops.yml",
	// scaled_float (1)
	"scaled_float/10_basic.yml",
	// scripts (2)
	"scripts/20_get_script_context.yml",
	"scripts/25_get_script_languages.yml",
	// scroll (4)
	"scroll/10_basic.yml",
	"scroll/11_clear.yml",
	"scroll/12_slices.yml",
	"scroll/20_keep_alive.yml",
	// search (51)
	"search/100_stored_fields.yml",
	"search/10_cutoff_frequency.yml",
	"search/10_geo_bounding_box.yml",
	"search/10_source_filtering.yml",
	"search/10_type_query.yml",
	"search/110_field_collapsing.yml",
	"search/111_field_collapsing_with_max_score.yml",
	"search/112_field_collapsing_with_rescore.yml",
	"search/115_multiple_field_collapsing.yml",
	"search/120_batch_reduce_size.yml",
	"search/140_pre_filter_search_shards.yml",
	"search/150_rewrite_on_coordinator.yml",
	"search/160_exists_query.yml",
	"search/161_exists_query_within_nested_query.yml",
	"search/170_terms_query.yml",
	"search/180_locale_dependent_mapping.yml",
	"search/190_index_prefix_search.yml",
	"search/200_ignore_malformed.yml",
	"search/200_index_phrase_search.yml",
	"search/20_default_values.yml",
	"search/210_rescore_explain.yml",
	"search/220_total_hits_object.yml",
	"search/230_interval_query.yml",
	"search/240_date_nanos.yml",
	"search/250_distance_feature.yml",
	"search/260_parameter_validation.yml",
	"search/300_sequence_numbers.yml",
	"search/30_limits.yml",
	"search/310_match_bool_prefix.yml",
	"search/320_disallow_queries.yml",
	"search/330_fetch_fields.yml",
	"search/340_flattened.yml",
	"search/350_binary_field.yml",
	"search/350_point_in_time.yml",
	"search/360_combined_fields.yml",
	"search/370_profile.yml",
	"search/380_sort_segments_on_timestamp.yml",
	"search/390_doc_values_search.yml",
	"search/390_lookup_fields.yml",
	"search/400_synthetic_source.yml",
	"search/40_indices_boost.yml",
	"search/410_named_queries.yml",
	"search/500_date_range.yml",
	"search/510_fragment_trimming_fix.yml",
	"search/510_range_query_out_of_bounds.yml",
	"search/520_fetch_fields.yml",
	"search/60_query_string.yml",
	"search/70_response_filtering.yml",
	"search/80_indices_options.yml",
	"search/90_search_after.yml",
	"search/issue4895.yml",
	// search-as-you-type (3)
	"search-as-you-type/10_basic.yml",
	"search-as-you-type/20_highlighting.yml",
	"search-as-you-type/30_synthetic_source.yml",
	// search-business-rules (1)
	"search-business-rules/10_pinned_query.yml",
	// search.aggregation (1)
	"search.aggregation/10_moving_avg.yml",
	// search.highlight (7)
	"search.highlight/10_unified.yml",
	"search.highlight/20_fvh.yml",
	"search.highlight/30_max_analyzed_offset.yml",
	"search.highlight/40_keyword_ignore.yml",
	"search.highlight/50_synthetic_source.yml",
	"search.highlight/60_unified_matched_fields.yml",
	"search.highlight/issue69009.yml",
	// search.inner_hits (2)
	"search.inner_hits/10_basic.yml",
	"search.inner_hits/20_highlighting.yml",
	// search.query (8)
	"search.query/10_match.yml",
	"search.query/20_ngram_search.yml",
	"search.query/30_ngram_highligthing.yml",
	"search.query/40_query_string.yml",
	"search.query/41_query_string_with_default_analyzer.yml",
	"search.query/50_queries_with_synonyms.yml",
	"search.query/60_synonym_graph.yml",
	"search.query/70_intervals.yml",
	// search.retrievers (2)
	"search.retrievers/10_standard_retriever.yml",
	"search.retrievers/20_knn_retriever.yml",
	// search.sort (1)
	"search.sort/10_nested_path_filter.yml",
	// search.suggest (2)
	"search.suggest/20_phrase.yml",
	"search.suggest/30_synonyms.yml",
	// search.vectors (28)
	"search.vectors/100_knn_nested_search.yml",
	"search.vectors/101_knn_nested_search_bits.yml",
	"search.vectors/110_knn_query_with_filter.yml",
	"search.vectors/120_knn_query_multiple_shards.yml",
	"search.vectors/130_knn_query_nested_search.yml",
	"search.vectors/140_knn_query_with_other_queries.yml",
	"search.vectors/150_knn_search_missing_params.yml",
	"search.vectors/160_knn_query_missing_params.yml",
	"search.vectors/170_knn_search_hex_encoded_byte_vectors.yml",
	"search.vectors/175_knn_query_hex_encoded_byte_vectors.yml",
	"search.vectors/180_update_dense_vector_type.yml",
	"search.vectors/190_knn_query-with-k-param.yml",
	"search.vectors/40_knn_search.yml",
	"search.vectors/40_knn_search_cosine.yml",
	"search.vectors/41_knn_search_byte_quantized.yml",
	"search.vectors/41_knn_search_half_byte_quantized.yml",
	"search.vectors/42_knn_search_flat.yml",
	"search.vectors/42_knn_search_int4_flat.yml",
	"search.vectors/42_knn_search_int8_flat.yml",
	"search.vectors/45_knn_search_bit.yml",
	"search.vectors/45_knn_search_bit_flat.yml",
	"search.vectors/45_knn_search_byte.yml",
	"search.vectors/50_dense_vector_field_usage.yml",
	"search.vectors/60_dense_vector_dynamic_mapping.yml",
	"search.vectors/60_knn_search_filter_alias.yml",
	"search.vectors/70_dense_vector_telemetry.yml",
	"search.vectors/80_dense_vector_indexed_by_default.yml",
	"search.vectors/90_sparse_vector.yml",
	// search_shards (1)
	"search_shards/10_basic.yml",
	// searchable_snapshots (2)
	"searchable_snapshots/10_usage.yml",
	"searchable_snapshots/20_synthetic_source.yml",
	// simulate.ingest (1)
	"simulate.ingest/10_basic.yml",
	// slm (2)
	"slm/11_basic_slm.yml",
	"slm/20_health.yml",
	// snapshot (2)
	"snapshot/10_basic.yml",
	"snapshot/20_operator_privileges_disabled.yml",
	// snapshot.clone (1)
	"snapshot.clone/10_basic.yml",
	// snapshot.create (1)
	"snapshot.create/10_basic.yml",
	// snapshot.delete (1)
	"snapshot.delete/10_basic.yml",
	// snapshot.get (1)
	"snapshot.get/10_basic.yml",
	// snapshot.get_repository (2)
	"snapshot.get_repository/10_basic.yml",
	"snapshot.get_repository/20_repository_uuid.yml",
	// snapshot.restore (1)
	"snapshot.restore/10_basic.yml",
	// snapshot.status (1)
	"snapshot.status/10_basic.yml",
	// spatial (17)
	"spatial/100_geo_grid_ingest.yml",
	"spatial/10_cartesian_bounds.yml",
	"spatial/10_geo_bounds.yml",
	"spatial/110_geo_shape_parameters.yml",
	"spatial/120_position_geo_line.yml",
	"spatial/130_geo_shape_runtime.yml",
	"spatial/140_synthetic_source.yml",
	"spatial/20_cartesian_centroid.yml",
	"spatial/20_geo_centroid.yml",
	"spatial/30_geotile_grid.yml",
	"spatial/40_geohash_grid.yml",
	"spatial/50_feature_usage.yml",
	"spatial/60_geo_line.yml",
	"spatial/70_script_doc_values.yml",
	"spatial/80_geohex_grid.yml",
	"spatial/80_geohex_grid_geo_shape.yml",
	"spatial/90_geo_grid_query.yml",
	// sql (2)
	"sql/sql.yml",
	"sql/translate.yml",
	// suggest (5)
	"suggest/10_basic.yml",
	"suggest/20_completion.yml",
	"suggest/30_context.yml",
	"suggest/40_typed_keys.yml",
	"suggest/50_completion_with_multi_fields.yml",
	// synonyms (10)
	"synonyms/100_synonyms_no_system_index.yml",
	"synonyms/10_synonyms_put.yml",
	"synonyms/20_synonyms_get.yml",
	"synonyms/30_synonyms_delete.yml",
	"synonyms/40_synonyms_sets_get.yml",
	"synonyms/50_synonym_rule_put.yml",
	"synonyms/60_synonym_rule_get.yml",
	"synonyms/70_synonym_rule_delete.yml",
	"synonyms/80_synonyms_from_index.yml",
	"synonyms/90_synonyms_reloading_for_synset.yml",
	// tasks.cancel (1)
	"tasks.cancel/10_basic.yml",
	// tasks.get (1)
	"tasks.get/10_basic.yml",
	// tasks.list (1)
	"tasks.list/10_basic.yml",
	// terms_enum (2)
	"terms_enum/10_basic.yml",
	"terms_enum/20_fieldtypes.yml",
	// termvectors (4)
	"termvectors/10_basic.yml",
	"termvectors/10_payloads.yml",
	"termvectors/20_issue7121.yml",
	"termvectors/30_realtime.yml",
	// text_structure (4)
	"text_structure/find_field_structure.yml",
	"text_structure/find_message_structure.yml",
	"text_structure/find_structure.yml",
	"text_structure/test_grok_pattern.yml",
	// token_count (1)
	"token_count/10_basic.yml",
	// transform (11)
	"transform/preview_transforms.yml",
	"transform/transforms_cat_apis.yml",
	"transform/transforms_crud.yml",
	"transform/transforms_force_delete.yml",
	"transform/transforms_reset.yml",
	"transform/transforms_start_stop.yml",
	"transform/transforms_stats.yml",
	"transform/transforms_stats_continuous.yml",
	"transform/transforms_unattended.yml",
	"transform/transforms_update.yml",
	"transform/transforms_upgrade.yml",
	// transport-netty4 (1)
	"transport-netty4/10_basic.yml",
	// tsdb (18)
	"tsdb/05_dimension_and_metric_in_non_tsdb_index.yml",
	"tsdb/100_composite.yml",
	"tsdb/10_settings.yml",
	"tsdb/110_field_caps.yml",
	"tsdb/120_counter_fields.yml",
	"tsdb/130_position_fields.yml",
	"tsdb/140_routing_path.yml",
	"tsdb/150_runtime_fields.yml",
	"tsdb/15_timestamp_mapping.yml",
	"tsdb/20_mapping.yml",
	"tsdb/25_id_generation.yml",
	"tsdb/30_snapshot.yml",
	"tsdb/40_search.yml",
	"tsdb/50_alias.yml",
	"tsdb/60_add_dimensions.yml",
	"tsdb/70_dimension_types.yml",
	"tsdb/80_index_resize.yml",
	"tsdb/90_unsupported_operations.yml",
	// update (14)
	"update/100_synthetic_source.yml",
	"update/10_doc.yml",
	"update/11_shard_header.yml",
	"update/12_result.yml",
	"update/13_legacy_doc.yml",
	"update/16_noop.yml",
	"update/20_doc_upsert.yml",
	"update/22_doc_as_upsert.yml",
	"update/35_if_seq_no.yml",
	"update/40_routing.yml",
	"update/60_refresh.yml",
	"update/80_source_filtering.yml",
	"update/90_error.yml",
	"update/95_require_alias.yml",
	// update_by_query (11)
	"update_by_query/100_synthetic_source.yml",
	"update_by_query/10_basic.yml",
	"update_by_query/20_validation.yml",
	"update_by_query/30_new_fields.yml",
	"update_by_query/35_search_failure.yml",
	"update_by_query/40_versioning.yml",
	"update_by_query/50_consistency.yml",
	"update_by_query/60_throttle.yml",
	"update_by_query/70_slices.yml",
	"update_by_query/80_scripting.yml",
	"update_by_query/90_tsdb.yml",
	// vector-tile (2)
	"vector-tile/10_basic.yml",
	"vector-tile/20_aggregations.yml",
	// versionfield (2)
	"versionfield/10_basic.yml",
	"versionfield/20_scripts.yml",
	// voting_only_node (1)
	"voting_only_node/10_basic.yml",
	// wildcard (3)
	"wildcard/10_script_values.yml",
	"wildcard/10_wildcard_basic.yml",
	"wildcard/20_regexp.yml",
	// xpack (2)
	"xpack/10_basic.yml",
	"xpack/20_info.yml",
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

func buildSpecFilterMap(specs []string) map[string]bool {
	set := make(map[string]bool, len(specs))
	for _, p := range specs {
		set[p] = true
	}
	return set
}

func buildTier1SpecFilter() map[string]bool {
	return buildSpecFilterMap(liveDorisTier1UpstreamYAMLSpecs)
}

func parseLiveYAMLShardEnv(raw string) (idx, total int, enabled bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, 0, false, nil
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false, fmt.Errorf("invalid DORIS_LIVE_YAML_SHARD %q: expected <idx>/<total> (e.g. 1/3)", raw)
	}
	if strings.HasPrefix(parts[0], "+") || strings.HasPrefix(parts[1], "+") {
		return 0, 0, false, fmt.Errorf("invalid DORIS_LIVE_YAML_SHARD %q: unexpected '+' prefix", raw)
	}
	parsedIdx, errIdx := strconv.Atoi(parts[0])
	parsedTotal, errTotal := strconv.Atoi(parts[1])
	if errIdx != nil || errTotal != nil {
		return 0, 0, false, fmt.Errorf("invalid DORIS_LIVE_YAML_SHARD %q: non-integer shard index or total", raw)
	}
	if parsedTotal < 1 || parsedIdx < 1 || parsedIdx > parsedTotal {
		return 0, 0, false, fmt.Errorf("invalid DORIS_LIVE_YAML_SHARD %q: require 1 <= idx <= total (got %d/%d)", raw, parsedIdx, parsedTotal)
	}
	return parsedIdx, parsedTotal, true, nil
}

func countYAMLSpecSections(path string) int {
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- trusted local conformance test corpus path
	if err != nil {
		return 1
	}
	doc, parseErr := compliance.ParseSpecFile(string(raw))
	if parseErr != nil || doc == nil || len(doc.Sections) < 1 {
		return 1
	}
	return len(doc.Sections)
}

func partitionTier1SpecsWeighted(specs []string, weights map[string]int, shardIdx, totalShards int) []string {
	if totalShards < 1 || shardIdx < 1 || shardIdx > totalShards || len(specs) == 0 {
		return nil
	}
	type weightedSpec struct {
		spec   string
		weight int
	}
	items := make([]weightedSpec, 0, len(specs))
	for _, s := range specs {
		w := weights[s]
		if w < 1 {
			w = 1
		}
		items = append(items, weightedSpec{spec: s, weight: w})
	}
	// LPT: sort descending by section weight, tie-breaking ascending by displayPath.
	sort.Slice(items, func(i, j int) bool {
		if items[i].weight != items[j].weight {
			return items[i].weight > items[j].weight
		}
		return items[i].spec < items[j].spec
	})

	shardLoads := make([]int, totalShards)
	buckets := make([][]string, totalShards)
	for _, item := range items {
		bestShard := 0
		for s := 1; s < totalShards; s++ {
			if shardLoads[s] < shardLoads[bestShard] {
				bestShard = s
			}
		}
		buckets[bestShard] = append(buckets[bestShard], item.spec)
		shardLoads[bestShard] += item.weight
	}

	selected := buckets[shardIdx-1]
	sort.Strings(selected)
	return selected
}

func discoverTier1SpecPathsAndWeights(
	specs []string,
	v8Dirs []string,
) (paths map[string]string, weights map[string]int, duplicates map[string][]string, missing []string, err error) {
	type rawEntry struct {
		fullPath  string
		cleanRoot string
		dirIdx    int
		disp      string
		qualifier string
	}
	var rawEntries []rawEntry
	rawDispCounts := make(map[string]int)
	for dirIdx, rootDir := range v8Dirs {
		cleanRoot := filepath.Clean(rootDir)
		qualifier := deriveUpstreamCorpusQualifier(cleanRoot)
		walkErr := filepath.WalkDir(cleanRoot, func(fullPath string, d fs.DirEntry, wErr error) error {
			if wErr != nil || d.IsDir() {
				if d != nil && d.IsDir() && d.Name() == ".git" {
					return filepath.SkipDir
				}
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
			rawDispCounts[disp]++
			rawEntries = append(rawEntries, rawEntry{
				fullPath:  fullPath,
				cleanRoot: cleanRoot,
				dirIdx:    dirIdx,
				disp:      disp,
				qualifier: qualifier,
			})
			return nil
		})
		if walkErr != nil {
			return nil, nil, nil, nil, fmt.Errorf("walking %s: %w", cleanRoot, walkErr)
		}
	}

	qualifiedCounts := make(map[string]int, len(rawEntries))
	for i := range rawEntries {
		e := &rawEntries[i]
		if rawDispCounts[e.disp] > 1 && e.qualifier != "" && !strings.HasPrefix(e.disp, e.qualifier+"/") {
			e.disp = e.qualifier + "/" + e.disp
		}
		qualifiedCounts[e.disp]++
	}

	specSet := buildSpecFilterMap(specs)
	matched := make(map[string][]string, len(specSet))
	for _, e := range rawEntries {
		disp := e.disp
		if qualifiedCounts[disp] > 1 {
			fallbackPrefix := strings.Trim(filepath.ToSlash(filepath.Base(e.cleanRoot)), "/")
			if fallbackPrefix == "" || fallbackPrefix == "." || fallbackPrefix == "test" {
				fallbackPrefix = fmt.Sprintf("corpus_%d", e.dirIdx)
			}
			disp = fallbackPrefix + "/" + disp
		}
		if specSet[disp] {
			matched[disp] = append(matched[disp], e.fullPath)
		}
	}

	paths = make(map[string]string, len(specSet))
	weights = make(map[string]int, len(specSet))
	duplicates = make(map[string][]string)
	for spec := range specSet {
		files := matched[spec]
		switch len(files) {
		case 0:
			missing = append(missing, spec)
		case 1:
			paths[spec] = files[0]
			weights[spec] = countYAMLSpecSections(files[0])
		default:
			sort.Strings(files)
			duplicates[spec] = files
		}
	}
	sort.Strings(missing)
	return paths, weights, duplicates, missing, nil
}

func deriveUpstreamCorpusQualifier(rootDir string) string {
	rootSlash := filepath.ToSlash(rootDir)
	for _, marker := range []string{"/modules/", "/x-pack/plugin/", "/plugins/", "/x-pack/qa/"} {
		if idx := strings.Index(rootSlash, marker); idx >= 0 {
			rest := rootSlash[idx+1:]
			markerParts := strings.Count(strings.Trim(marker, "/"), "/") + 1
			parts := strings.Split(rest, "/")
			if len(parts) > markerParts && parts[markerParts] != "" {
				return strings.Join(parts[:markerParts+1], "/")
			}
		}
	}
	if strings.Contains(rootSlash, "/yamlRestTestV7Compat/") {
		return "v7compat"
	}
	return ""
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
	if plugIdx := strings.Index(rootSlash, "/plugins/"); plugIdx >= 0 {
		afterPlug := rootSlash[plugIdx+len("/plugins/"):]
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

// TestLiveDorisTier1SpecList_ValidatesAgainstUpstreamCache verifies shard parsing/LPT
// partitioning helpers and, when `.cache/es-v8.15.5` is populated on disk, validates that
// the curated Tier-1 list resolves 1:1 to unique upstream YAML files, balances
// cleanly across 3 shards, and passes `ScoreMatchingFiles` with 0 failures.
func TestLiveDorisTier1SpecList_ValidatesAgainstUpstreamCache(t *testing.T) {
	tier1Filter := buildTier1SpecFilter()
	if len(tier1Filter) != len(liveDorisTier1UpstreamYAMLSpecs) {
		t.Fatalf("duplicate entries in liveDorisTier1UpstreamYAMLSpecs: unique=%d total=%d", len(tier1Filter), len(liveDorisTier1UpstreamYAMLSpecs))
	}
	if len(tier1Filter) < 955 {
		t.Fatalf("curated Tier-1 spec count = %d, want >= 955", len(tier1Filter))
	}

	// Verify parseLiveYAMLShardEnv handles empty, valid, and invalid inputs cleanly.
	for _, validTC := range []struct {
		raw     string
		idx     int
		total   int
		enabled bool
	}{
		{raw: "", idx: 0, total: 0, enabled: false},
		{raw: "   ", idx: 0, total: 0, enabled: false},
		{raw: "1/1", idx: 1, total: 1, enabled: true},
		{raw: "1/3", idx: 1, total: 3, enabled: true},
		{raw: " 2/3 ", idx: 2, total: 3, enabled: true},
		{raw: "3/3", idx: 3, total: 3, enabled: true},
	} {
		idx, total, enabled, parseErr := parseLiveYAMLShardEnv(validTC.raw)
		if parseErr != nil {
			t.Fatalf("parseLiveYAMLShardEnv(%q) unexpected error: %v", validTC.raw, parseErr)
		}
		if idx != validTC.idx || total != validTC.total || enabled != validTC.enabled {
			t.Fatalf("parseLiveYAMLShardEnv(%q) = (%d, %d, %v), want (%d, %d, %v)",
				validTC.raw, idx, total, enabled, validTC.idx, validTC.total, validTC.enabled)
		}
	}
	for _, badShard := range []string{
		"0/3", "4/3", "1/0", "-1/3", "1/-3", "a/3", "1/b",
		"1", "1/2/3", "/", "1/", "/3", "+1/3", "1/+3", "1 / 3",
	} {
		if idx, total, enabled, parseErr := parseLiveYAMLShardEnv(badShard); parseErr == nil {
			t.Fatalf("parseLiveYAMLShardEnv(%q) unexpectedly succeeded: (%d, %d, %v)", badShard, idx, total, enabled)
		}
	}

	// Verify partitionTier1SpecsWeighted boundary checks and deterministic LPT tie-breaking.
	if got := partitionTier1SpecsWeighted(nil, nil, 1, 3); len(got) != 0 {
		t.Fatalf("expected empty slice for nil specs, got %v", got)
	}
	if got := partitionTier1SpecsWeighted([]string{"a.yml"}, nil, 0, 3); len(got) != 0 {
		t.Fatalf("expected empty slice for shardIdx=0, got %v", got)
	}
	if got := partitionTier1SpecsWeighted([]string{"a.yml"}, nil, 4, 3); len(got) != 0 {
		t.Fatalf("expected empty slice for shardIdx>totalShards, got %v", got)
	}
	if got := partitionTier1SpecsWeighted([]string{"a.yml"}, nil, 1, 0); len(got) != 0 {
		t.Fatalf("expected empty slice for totalShards=0, got %v", got)
	}
	synthSpecs := []string{"d.yml", "b.yml", "a.yml", "c.yml"}
	synthWeights := map[string]int{"a.yml": 10, "b.yml": 10, "c.yml": 6, "d.yml": 4}
	// Sorted by (-weight, spec): a.yml(10)->shard0, b.yml(10)->shard1, c.yml(6)->shard0(load 16) or shard1?
	// Wait: loads after a,b are [10, 10], tie breaks to lowest shard index 0 => c.yml(6)->shard0(load 16), d.yml(4)->shard1(load 14).
	s1 := partitionTier1SpecsWeighted(synthSpecs, synthWeights, 1, 2)
	s2 := partitionTier1SpecsWeighted(synthSpecs, synthWeights, 2, 2)
	if len(s1) != 2 || s1[0] != "a.yml" || s1[1] != "c.yml" || len(s2) != 2 || s2[0] != "b.yml" || s2[1] != "d.yml" {
		t.Fatalf("unexpected synthetic LPT shards: s1=%v s2=%v", s1, s2)
	}

	v8Root := filepath.Join(resolveE2EConformanceCacheDir(), "es-v8.15.5")
	v8Dirs, err := discoverUpstreamYAMLTestDirs(v8Root)
	if err != nil || len(v8Dirs) == 0 {
		t.Skipf("skipping Tier-1 spec filename check (.cache/es-v8.15.5 absent at %s)", v8Root)
	}

	paths, weights, duplicates, missing, specErr := discoverTier1SpecPathsAndWeights(liveDorisTier1UpstreamYAMLSpecs, v8Dirs)
	if specErr != nil {
		t.Fatalf("discoverTier1SpecPathsAndWeights failed: %v", specErr)
	}
	if len(duplicates) > 0 {
		t.Fatalf("curated Tier-1 specs matched multiple files (non-1:1 displayPath): %v", duplicates)
	}
	if len(missing) > 0 {
		t.Fatalf("curated Tier-1 specs missing from .cache/es-v8.15.5: %v", missing)
	}
	if len(paths) != len(tier1Filter) {
		t.Fatalf("resolved unique Tier-1 spec paths = %d, want %d", len(paths), len(tier1Filter))
	}

	// Verify 3-way weighted sharding produces a complete disjoint union and balanced section weights.
	const totalShards = 3
	seenAcrossShards := make(map[string]int, len(tier1Filter))
	shardWeights := make([]int, totalShards)
	shardFileCounts := make([]int, totalShards)
	for shardIdx := 1; shardIdx <= totalShards; shardIdx++ {
		shardSpecs := partitionTier1SpecsWeighted(liveDorisTier1UpstreamYAMLSpecs, weights, shardIdx, totalShards)
		shardFileCounts[shardIdx-1] = len(shardSpecs)
		for _, spec := range shardSpecs {
			seenAcrossShards[spec]++
			shardWeights[shardIdx-1] += weights[spec]
		}
		t.Logf("[Tier-1 Shard %d/%d] files=%d section_weight=%d", shardIdx, totalShards, len(shardSpecs), shardWeights[shardIdx-1])
	}
	if len(seenAcrossShards) != len(tier1Filter) {
		t.Fatalf("3-shard union covered %d specs, want %d", len(seenAcrossShards), len(tier1Filter))
	}
	for spec := range tier1Filter {
		if seenAcrossShards[spec] != 1 {
			t.Fatalf("spec %q appeared %d times across 3 shards, want 1", spec, seenAcrossShards[spec])
		}
	}
	minWeight, maxWeight := shardWeights[0], shardWeights[0]
	for _, w := range shardWeights[1:] {
		if w < minWeight {
			minWeight = w
		}
		if w > maxWeight {
			maxWeight = w
		}
	}
	if minWeight <= 0 {
		t.Fatalf("unexpected non-positive shard section weight: %v", shardWeights)
	}
	weightRatio := float64(maxWeight) / float64(minWeight)
	t.Logf("[Tier-1 Shard Balance] file_counts=%v section_weights=%v min=%d max=%d ratio=%.4f",
		shardFileCounts, shardWeights, minWeight, maxWeight, weightRatio)
	if weightRatio > 1.15 {
		t.Fatalf("3-shard section weight imbalance ratio = %.4f, want <= 1.15 (weights=%v)", weightRatio, shardWeights)
	}

	// Verify ScoreMatchingFiles agrees 1:1 on all Tier-1 displayPath entries, passes >= 4400 sections, and records 0 failures.
	memCard, scoreErr := compliance.ScoreMatchingFiles(
		compliance.SuiteOptions{
			CorpusName:                 "mem-tier1-validation",
			TargetVersion:              "8.15.5",
			DefaultAuthUser:            compliance.DefaultFixtureAuthUser,
			DefaultAuthPass:            compliance.DefaultFixtureAuthPass,
			ReuseSetupForReadOnlyFiles: true,
		},
		func(displayPath string) bool { return tier1Filter[displayPath] },
		func() (http.Handler, func()) {
			srv := proxy.NewServer("es_tier1_check", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
			srv.SetAllowTestFixtureAuth(true)
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
	if memCard.SectionsFailed != 0 {
		for i, f := range memCard.FailureSamples {
			if i >= 25 {
				break
			}
			t.Logf("[Tier-1 Precheck Failure %d/%d] file=%s section=%q err=%s", i+1, len(memCard.FailureSamples), f.File, f.Section, f.Error)
		}
		t.Fatalf("ScoreMatchingFiles SectionsFailed = %d, want 0", memCard.SectionsFailed)
	}
	if memCard.SectionsPassed < 4650 {
		t.Fatalf("Tier-1 %d-file suite SectionsPassed = %d, want >= 4650", len(tier1Filter), memCard.SectionsPassed)
	}
	t.Logf("[Tier-1 %d-File Precheck] files=%d sections=%d passed=%d failed=%d skipped=%d pass_rate=%.2f%%",
		len(tier1Filter), memCard.TotalFiles, memCard.SectionsTotal, memCard.SectionsPassed, memCard.SectionsFailed, memCard.SectionsSkipped, memCard.PassRatePct)
}

// TestLiveDorisUpstreamYAMLConformance_E2E executes the curated Tier-1 upstream
// Elasticsearch v8.15.5 YAML REST conformance suite (or a balanced weighted shard selected via
// DORIS_LIVE_YAML_SHARD=<idx>/<total>) against a live Apache Doris 4.1.3 cluster via
// ScoreMatchingFiles, resetting Doris table/catalog state cleanly between sections.
func TestLiveDorisUpstreamYAMLConformance_E2E(t *testing.T) {
	shardIdx, shardTotal, shardEnabled, shardErr := parseLiveYAMLShardEnv(os.Getenv("DORIS_LIVE_YAML_SHARD"))
	if shardErr != nil {
		t.Fatalf("%v", shardErr)
	}

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

	_, weights, duplicates, missing, specErr := discoverTier1SpecPathsAndWeights(liveDorisTier1UpstreamYAMLSpecs, v8Dirs)
	if specErr != nil {
		t.Fatalf("discoverTier1SpecPathsAndWeights failed: %v", specErr)
	}
	if len(duplicates) > 0 {
		t.Fatalf("curated Tier-1 specs matched multiple files (non-1:1 displayPath): %v", duplicates)
	}
	if len(missing) > 0 {
		t.Fatalf("curated Tier-1 specs missing from .cache/es-v8.15.5: %v", missing)
	}

	activeSpecs := liveDorisTier1UpstreamYAMLSpecs
	corpusName := "live-doris-v8.15.5-tier1"
	if shardEnabled {
		activeSpecs = partitionTier1SpecsWeighted(liveDorisTier1UpstreamYAMLSpecs, weights, shardIdx, shardTotal)
		corpusName = fmt.Sprintf("live-doris-v8.15.5-tier1-shard-%d-of-%d", shardIdx, shardTotal)
	}
	activeSectionWeight := 0
	for _, spec := range activeSpecs {
		activeSectionWeight += weights[spec]
	}
	if shardEnabled {
		t.Logf("[Live Doris YAML Shard %d/%d] selected_files=%d/%d section_weight=%d",
			shardIdx, shardTotal, len(activeSpecs), len(liveDorisTier1UpstreamYAMLSpecs), activeSectionWeight)
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
	initSrv.SetAllowTestFixtureAuth(true)
	initSrv.SetBulkCoalesce(0, 0)
	initSrv.SetTargetESVersion("8.15.5")
	if bootErr := initSrv.BootstrapCatalog(context.Background()); bootErr != nil {
		t.Logf("initial BootstrapCatalog note: %v", bootErr)
	}
	_ = initSrv.Close(context.Background())

	activeSet := buildSpecFilterMap(activeSpecs)
	matchTier1 := func(displayPath string) bool {
		return activeSet[displayPath]
	}

	newLiveSectionHandler := func() (http.Handler, func()) {
		srv := proxy.NewServer(dorisDB, backend, transpiler.TranspilerOptions{})
		srv.SetAllowTestFixtureAuth(true)
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
			CorpusName:                 corpusName,
			TargetVersion:              "8.15.5",
			DefaultAuthUser:            compliance.DefaultFixtureAuthUser,
			DefaultAuthPass:            compliance.DefaultFixtureAuthPass,
			ReuseSetupForReadOnlyFiles: true,
		},
		matchTier1,
		newLiveSectionHandler,
		v8Dirs...,
	)
	if err != nil {
		t.Fatalf("ScoreMatchingFiles against live Doris failed: %v", err)
	}
	if card.TotalFiles != len(activeSet) {
		t.Errorf("live Doris Tier-1 YAML scorecard TotalFiles = %d, want %d", card.TotalFiles, len(activeSet))
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

	minPassed := 4650
	if shardEnabled {
		minPassed = (activeSectionWeight * 85) / 100
		if minPassed < 1 {
			minPassed = 1
		}
	}
	if rawMin := strings.TrimSpace(os.Getenv("DORIS_LIVE_YAML_MIN_PASSED")); rawMin != "" {
		parsedMin, convErr := strconv.Atoi(rawMin)
		if convErr != nil || parsedMin < 0 {
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
