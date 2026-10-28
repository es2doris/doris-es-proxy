# Changelog

All notable changes to `doris-es-proxy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Aggregations & Pipeline Aggregations:** Added `extended_stats` (`sigma`, exact `sum_of_squares`, `std_deviation_bounds`, `null` metrics on empty sets), `string_stats`, `boxplot`, `percentile_ranks`, `top_metrics`, `rate` (with interval/unit scaling across `date_histogram` and `histogram`), `global` (escaping user `query` while respecting alias filters across single and multi-index searches), `sampler` & `diversified_sampler`, `reverse_nested`, `ip_range` (on scalar and multi-valued IP arrays), anonymous array `filters` + `other_bucket` / `other_bucket_key`, `composite` `missing_bucket: true` & `missing_order`, `normalize` pipeline aggregation (`percent_of_sum`, `rescale_0_1`, `rescale_0_100`, `mean`, `z-score`, `atan`), `moving_avg` & `moving_fn` (`shift`, `model: simple|linear|ewma`, `MovingFunctions.max|min|sum|stdDev`), `serial_diff`, `extended_stats_bucket`, `percentiles_bucket`, `terms` ordering by multi-value metrics (`stats.avg`, `percentiles.95.0`, `boxplot.q2`) with per-parent-bucket sort isolation, and recursive 2nd-level multi-bucket sub-aggregations (`terms`, `date_histogram`, `histogram`, `range`, `date_range`, `ip_range`, `filters`, `nested`, `reverse_nested`) under `terms` / `histogram` / `date_histogram` / `composite`.
- **Alias Engine, Ingest Pipelines & Wire Protocol:** Added filtered alias enforcement across single-doc reads/writes (`PUT/POST/GET/HEAD/DELETE /{alias}/_doc/{id}`, `_source`, `_mget`, `_update`, `_update_by_query`, `_bulk`, `_reindex`, `top_hits`/`top_metrics` `docLookup`, `/{alias}/_stats`, and cross-index `terms` lookup inside alias filters), pure top-level `knn` over filtered aliases, PIT-scoped `/_count` / `/_validate/query` / `/_doris/explain`, `-pattern` multi-index exclusions (`logs-*,-logs-secret`), `DELETE /{alias}` table-drop protection (`400`), wildcard `DELETE /{index}/_alias/prefix-*`, `POST /{index}/_terms_enum` (Kibana autocomplete), `GET/POST /{index}/_explain/{id}`, stateless `_es_catalog` persistence/rehydration (with cross-instance tombstone deletion sync) for indices/aliases/templates/pipelines, rollover read-alias retention, `HEAD /{index}/_alias/{name}`, and Painless comments (`//`, `/* */`), slash-delimited regex (`/.../` with escaped slashes and `[...]` classes), `doc['field'].value`, local variable declarations, boolean/regex RHS assignments, and chained null-safe navigation (`?.`).

### Security & Hardening
- Replaced `terms_set.minimum_should_match_script` threshold compilation with a strict recursive-descent expression parser (`parseSafeThresholdExpr`) supporting only numeric literals, `params.num_terms`, `doc['field'].size()`, `+`, `-`, `*`, `/`, `Math.min`, `Math.max`, `Math.floor`, `Math.ceil`, and `Math.abs`.
- Eliminated `sync.WaitGroup` reuse hazard and cross-table flush blocking in `StreamLoadCoalescer` by tracking per-batch `done` channels in `inflight map[*coalesceBatch]string`.
- Guarded `bucket_script` and Painless arithmetic (`+`, `-`, `*`, `/`) against floating-point overflow (`+Inf`/`-Inf`/`NaN`) and scientific notation (`1e-5`) mis-splitting.
- Expanded `validatePipelineAggs` to validate multi-hop sibling `buckets_path` (`a>b>c`), child pipeline `buckets_path` (`cumulative_sum`, `derivative`, `bucket_script`, `bucket_selector`), and cyclic dependencies among child pipeline aggregations (`HTTP 400`).
- Enforced `tls.VersionTLS12` minimum TLS version on the HTTPS listener and `Dockerfile` version injection (`-X main.version=${VERSION}`).

## [0.15.0] - 2026-10-27

### Added
- **Query DSL:** Added `match_bool_prefix`, `terms_set` (`minimum_should_match_field` and `minimum_should_match_script`), cross-index `terms` lookup (`{"terms":{"user_id":{"index":"users","id":"team-a","path":"members"}}}`), and multi-field `multi_match` `phrase` / `phrase_prefix` compilation.
- **Aggregations:** Added `composite` pagination (`after` cursor + `after_key` response envelope across `terms`, `histogram`, and `date_histogram` sources), `significant_terms` (foreground/background JLH scoring), and child pipeline aggregation topological dependency resolution (`bucket_script` referencing `cumulative_sum` or `derivative`).
- **Wire Protocol:** Added `GET/POST /{index}/_field_caps` and global response formatting parameters (`?filter_path=...`, `?human=true`, `?error_trace=true`).
- **Live Apache Doris 4.x E2E & DSIP:** Added live `apache/doris:all-in-one-4.1.3` E2E test suite (`.github/workflows/e2e-live-doris.yml`) and Apache Doris Improvement Proposal ([`docs/dsip-doris-es-proxy.md`](docs/dsip-doris-es-proxy.md)).

## [0.14.0] - 2026-10-27

### Added
- **Round-5 Production Hardening:** Added `StreamLoadCoalescer` (`--bulk-coalesce-ms`), `QueryResultCache` (`--query-cache-ttl`) with automatic write invalidation and `now` date-math bypass, inbound HTTP `Basic` / `ApiKey` / `Bearer` authentication, native HTTPS/TLS (`--tls-cert` / `--tls-key`), and `migrate-schema --out-dir`.
- **Packaging:** Added Helm chart (`deploy/helm/doris-es-proxy`), Prometheus `ServiceMonitor`, Grafana dashboard (`deploy/grafana/doris-es-proxy-dashboard.json`), and GitHub Actions release pipeline (`.github/workflows/release.yml`).
