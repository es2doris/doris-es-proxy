# Changelog

All notable changes to `doris-es-proxy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
