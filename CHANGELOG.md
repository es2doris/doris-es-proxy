# Changelog

All notable changes to `doris-es-proxy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Aggregations & Pipeline Aggregations:** Added `extended_stats` (`sigma`, exact `sum_of_squares`, `std_deviation_bounds`, `null` metrics on empty sets), `string_stats`, `boxplot`, `percentile_ranks`, `top_metrics`, `rate` (with interval/unit scaling across `date_histogram` and `histogram`), `global` (escaping user `query` while respecting alias filters), `sampler` & `diversified_sampler`, `reverse_nested`, `ip_range` (on scalar and multi-valued IP arrays), anonymous array `filters` + `other_bucket` / `other_bucket_key`, `moving_avg` & `moving_fn` (`shift`, `model: simple|linear|ewma`, `MovingFunctions.max|min|sum|stdDev`), `serial_diff`, `extended_stats_bucket`, `percentiles_bucket`, and recursive 2-level `terms` $\rightarrow$ `terms` $\rightarrow$ metric/pipeline sub-aggregations.
- **Alias Engine, Ingest Pipelines & Wire Protocol:** Added filtered alias enforcement across single-doc reads/writes (`GET/HEAD/DELETE /{alias}/_doc/{id}`, `_source`, `_mget`, `_update`, `_bulk`, cross-index `terms` lookup), top-level `knn`, and `global` aggregations; stateless `_es_catalog` persistence and rehydration for `/_ingest/pipeline/{id}`, `index.default_pipeline`, and `index.final_pipeline`; rollover read-alias retention; `HEAD /{index}/_alias/{name}`; and Painless slash-delimited regex (`/.../`) and chained null-safe navigation (`?.`).

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
