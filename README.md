# doris-es-proxy

[![CI](https://github.com/es2doris/doris-es-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/es2doris/doris-es-proxy/actions/workflows/ci.yml)
[![Live Apache Doris E2E](https://github.com/es2doris/doris-es-proxy/actions/workflows/e2e-live-doris.yml/badge.svg)](https://github.com/es2doris/doris-es-proxy/actions/workflows/e2e-live-doris.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/es2doris/doris-es-proxy)](https://goreportcard.com/report/github.com/es2doris/doris-es-proxy)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**`doris-es-proxy`** is a stateless, wire-compatible **Elasticsearch / OpenSearch HTTP REST & Query DSL adapter** backed 100% by **Apache Doris** (3.x / 4.x+).

Think **"FerretDB, but for the Elasticsearch HTTP REST API on top of Apache Doris"**: run metadata catalogs like **OpenMetadata** and **DataHub**—as well as legacy ELK search clients—directly against Apache Doris's native `VARIANT` columns, Lucene Inverted Indexes, BM25 scoring, and `UNIQUE KEY` Merge-on-Write tables with **zero Elasticsearch or OpenSearch containers**.

---

## Architecture

```mermaid
flowchart LR
    subgraph Clients["Search & Metadata Clients"]
        OM["OpenMetadata Server\n& SearchIndexing"]
        DH["DataHub GMS / MAE"]
        SDK["Elasticsearch / OpenSearch\nHTTP REST Clients"]
    end

    subgraph Proxy["doris-es-proxy (Go)"]
        Router["ES HTTP REST Router (:9200)\n(/_search, /_bulk, /_mapping, /_doc)"]
        Schema["Schema & Mapping Compiler\n(Promoted f__*, Nested n__*, _doc VARIANT)"]
        Transpiler["Query DSL + Multi-Facet Aggs\n→ Doris SQL Transpiler"]
        Painless["Embedded Painless\nScript Evaluator"]
        Shredder["Zero-Copy _source Shredder\n& Stream Load Client"]
    end

    subgraph Doris["Apache Doris 3.x / 4.x+ Cluster"]
        FE["Doris FE (:9030 MySQL / :8030 HTTP)\nNereids Multi-Cast CTE + Point Query"]
        BE["Doris BE Nodes (:8040 HTTP)\nMoW Unique Key + Lucene Inverted Index + VARIANT"]
    end

    OM & DH & SDK -->|"HTTP REST + Query DSL"| Router
    Router --> Transpiler
    Transpiler <--> Schema
    Transpiler -->|"MySQL Protocol (:9030)\nHits + Multi-Cast CTE Aggs"| FE
    Router --> Painless
    Router --> Shredder
    Shredder -->|"HTTP Stream Load (:8040)\nmerge_type=MERGE + group_commit"| BE
    FE --> BE
```

## Why `doris-es-proxy`? (TCO & Operational Footprint)

Data platform teams running **OpenMetadata** or **DataHub** on top of Apache Doris are traditionally forced to operate a dedicated 3-node JVM Elasticsearch/OpenSearch cluster just to index metadata entities. `doris-es-proxy` eliminates the second cluster entirely:

| Metric / Component | Traditional Stack (Doris + Elasticsearch Cluster) | Unified Stack (Doris + `doris-es-proxy`) |
| :--- | :--- | :--- |
| **Search JVM Heap / RAM** | **8 GB – 32+ GB RAM** (3x ES/OpenSearch JVM nodes) | **~25 MB RAM** (single stateless Go binary) |
| **Storage Engine & Compaction** | Duplicate Lucene segments + JVM GC pauses | Native Doris MoW `UNIQUE KEY` + Inverted Index + ZSTD `_source` |
| **Catalog & Alias State** | Dedicated ES Master quorum | Stored natively in Doris (`_es_catalog` MoW table) |
| **Nested Array Correlation** | Hidden Lucene child documents (`_nested` join overhead) | Two-stage Doris Inverted Index `array_contains` + `array_exists` lambda |
| **Multi-Facet Sidebar Aggs** | Per-shard global ordinals heap pressure | Single-scan Nereids Multi-Cast CTE (`WITH base_matched AS (...)`) |

---

## Side-by-Side: Elasticsearch Query DSL $\rightarrow$ Apache Doris SQL

Given an OpenMetadata `/_search` request combining full-text `multi_match`, correlated `nested` column predicates (`columns.name = "user_id" AND columns.dataType = "INT"`), `function_score` tier/popularity boosting, and multi-faceted sidebar `aggs`, `doris-es-proxy` compiles:

<table>
<tr>
<th>Elasticsearch HTTP Request (<code>POST /table_search_index/_search</code>)</th>
<th>Transpiled Apache Doris SQL (Nereids)</th>
</tr>
<tr>
<td>

```json
{
  "size": 10,
  "query": {
    "function_score": {
      "query": {
        "bool": {
          "must": [
            {
              "multi_match": {
                "query": "orders",
                "fields": ["name^10", "description^2"]
              }
            },
            {
              "nested": {
                "path": "columns",
                "query": {
                  "bool": {
                    "must": [
                      {"term": {"columns.name": "user_id"}},
                      {"term": {"columns.dataType": "INT"}}
                    ]
                  }
                }
              }
            }
          ],
          "filter": [{"term": {"deleted": false}}]
        }
      },
      "functions": [
        {
          "filter": {"term": {"tier.tagFQN": "Tier.Tier1"}},
          "weight": 3.0
        }
      ]
    }
  },
  "aggs": {
    "serviceType": {"terms": {"field": "serviceType"}},
    "tags": {"terms": {"field": "tags.tagFQN"}}
  }
}
```

</td>
<td>

```sql
-- 1. HitsSQL (Stage-1 Inverted Index + Stage-2 Correlated Lambda)
SELECT `_id`, `_version`, `_source`,
       CAST(((CASE WHEN LOWER(CAST(`f__name` AS STRING)) LIKE LOWER('%orders%')
                   THEN 10 ELSE 0 END) + ...)
            * (CASE WHEN `f__tier__tagFQN` = 'Tier.Tier1' THEN 3 ELSE 1 END)
            AS DOUBLE) AS `_score`,
       COUNT(*) OVER() AS `_total_hits`
FROM `es_compat`.`table_search_index`
WHERE `__DORIS_DELETE_SIGN__` = 0
  AND ((`f__name` MATCH_ANY 'orders' OR `f__description` MATCH_ANY 'orders')
   AND (`n__columns` IS NOT NULL
        AND array_contains(`n__columns__name`, 'user_id')
        AND array_contains(`n__columns__dataType`, 'INT')
        AND array_exists(_el -> (
              json_extract_string(_el, '$.name') = 'user_id'
              AND json_extract_string(_el, '$.dataType') = 'INT'
            ), `n__columns`))
   AND (`f__deleted` = FALSE))
ORDER BY `_score` DESC
LIMIT 10 OFFSET 0;

-- 2. AggsSQL (Single-Scan Nereids Multi-Cast CTE)
WITH `base_matched` AS (
  SELECT * FROM `es_compat`.`table_search_index`
  WHERE `__DORIS_DELETE_SIGN__` = 0 AND (...)
)
SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`,
       CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`
UNION ALL
SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (
  SELECT 'serviceType' AS `_agg_name`, CAST(`f__serviceType` AS STRING) AS `_bucket_key`,
         CAST(COUNT(*) AS DOUBLE) AS `_doc_count`
  FROM `base_matched` WHERE `f__serviceType` IS NOT NULL
  GROUP BY `f__serviceType` ORDER BY `_doc_count` DESC LIMIT 10
) `_agg_sub_1`
UNION ALL
SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM (
  SELECT 'tags' AS `_agg_name`, CAST(`_elem` AS STRING) AS `_bucket_key`,
         CAST(COUNT(*) AS DOUBLE) AS `_doc_count`
  FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags__tagFQN`) `_t` AS `_elem`
  WHERE `_elem` IS NOT NULL
  GROUP BY `_elem` ORDER BY `_doc_count` DESC LIMIT 10
) `_agg_sub_2`;
```

</td>
</tr>
</table>

---

## Key Capabilities

1. **Hybrid Storage & Exact `_source` Fidelity (`pkg/schema`)**
   - Maps each Elasticsearch index to an Apache Doris `UNIQUE KEY(_id)` Merge-on-Write (`enable_unique_key_merge_on_write = "true"`, `store_row_column = "true"`) table.
   - Persists index mappings, aliases, and index templates in `es_compat._es_catalog` so multiple `doris-es-proxy` replicas remain **100% stateless across restarts** with zero external Redis/etcd dependencies.
   - Preserves verbatim JSON in `_source` (`STRING` with ZSTD compression) alongside auto-shredded `_doc` (`VARIANT`) for dynamic fields and promoted `f__*` columns with dedicated `USING INVERTED` indexes (`parser = standard | unicode | ngram`, `support_phrase = true`, `lower_case = true`).
   - Preserves cross-field element correlation on Elasticsearch `nested` arrays of objects (`columns: [{"name": "id", "tags": ["PII"]}]`) via **Stage-1 Inverted-Index Bitmap Pre-Filters** (`array_contains(n__columns__name, ...)`) + **Stage-2 Vectorized Correlated Lambdas** (`array_exists(_el -> ..., n__columns)`).

2. **Query DSL, Deep Pagination & Multi-Faceted Aggregation Transpiler (`pkg/transpiler`)**
   - Compiles `bool` (`must`, `filter`, `should`, `must_not`, `minimum_should_match`), `term`, `terms`, `ids`, `range` (with ES date math `now-7d/d`), `exists`, `prefix`, `wildcard`, `regexp` (`MATCH_REGEXP`), `match`, `match_phrase` (with `~slop`), `match_phrase_prefix`, `multi_match` (with wildcard field boost expansion), `query_string` / `simple_query_string` (plus Apache Doris 4.0 `SEARCH()` pushdown), `nested`, `constant_score`, `function_score`, `collapse` (field collapsing via `ROW_NUMBER() OVER (PARTITION BY ...)`), `search_after` keyset pagination, and stateless `POST /_search/scroll` cursors.
   - Compiles multi-faceted `aggs` (`terms` on scalar and `ARRAY<STRING>` columns, `nested` aggregations via `LATERAL VIEW EXPLODE`, `date_histogram`, `histogram`, `range`, `filter`, `missing`, `cardinality`, `value_count`, `avg`, `sum`, `min`, `max`) into a single-scan **Nereids Multi-Cast CTE (`WITH base_matched AS (...)`)** query.

3. **High-Throughput `/_bulk` Stream Load, Group-Commit Coalescing & Embedded Painless Mutations (`pkg/painless`, `pkg/proxy`)**
   - Streams `/_bulk` NDJSON (`index`, `create`, `update`, `delete` via `__DORIS_DELETE_SIGN__ = 1`) into Doris HTTP Stream Load (`merge_type: MERGE`, `function_column.sequence_col: _version`) while preserving auth headers across FE `:8030` $\rightarrow$ BE `:8040` `307` redirects, with optional **group-commit micro-batch coalescing (`--bulk-coalesce-ms`, `--bulk-coalesce-bytes`)** across concurrent writers, automatic transient retry backoff (`502`/`503`/`504`, `TOO_MANY_VERSIONS`, `MEM_LIMIT_EXCEEDED`), transparent `Content-Encoding: gzip` request decompression, and `Accept-Encoding: gzip` response compression.
   - Optional **bounded TTL Query Result Cache (`--query-cache-ttl`)** accelerates repeated dashboard queries with automatic write/DDL cache invalidation for strict read-your-writes consistency.
   - Executes `POST /{index}/_update/{id}` and `POST /{index}/_update_by_query` using an embedded, bounded Painless script evaluator supporting OpenMetadata and DataHub's `ctx._source` property assignments, `if/else`, `for` loops, `ctx.op = "noop" | "delete"`, `.remove()`, `.add()`, `.putAll()`, and `.removeIf(x -> ...)` mutations.

4. **Enterprise FinOps, End-to-End Trace Correlation, Shadow Verification & Auto-Indexing Advisor (`pkg/proxy`)**
   - **Auto-Indexing Advisor (`GET /_doris/slowlog`)**: Tracks query execution latency and unindexed `_doc['...']` `VARIANT` sub-column scans, automatically emitting ready-to-run `ALTER TABLE ... ADD COLUMN ... ADD INDEX ... USING INVERTED` DDL recommendations.
   - **W3C `traceparent` & `X-Opaque-Id` SQL Audit Correlation**: Echoes `traceparent`, `X-Opaque-Id`, and `X-Request-ID` HTTP headers and prepends sanitized `/* traceparent=..., opaque_id=..., request_id=... */` comments to every Doris SQL statement so slow queries in Doris FE `fe.audit.log` correlate directly back to Kibana, Grafana, or application spans.
   - **Dual-Read Shadow Verification (`--shadow-es-url`, `GET /_doris/shadow_stats`)**: Replays `/_search` requests against an existing Elasticsearch/OpenSearch cluster and computes hit-count parity (`doris_total == es_total`), Top-K `_id` Jaccard overlap, and latency speedup factor.
   - **Embedded Interactive Playground (`GET /_doris/ui`)**: Zero-dependency browser UI for side-by-side Elasticsearch Query DSL $\rightarrow$ Apache Doris SQL transpilation, live execution, and DDL inspection.

---

## Elasticsearch REST & Query DSL Compatibility Matrix

| Category | Supported Endpoints & Features | Status |
| :--- | :--- | :--- |
| **Cluster, Cat & GUI Admin** | `GET /`, `/_cluster/health`, `/_cluster/settings`, `/_nodes`, `/_stats`, `/{index}/_stats`, `/_resolve/index/{name}`, `/{index}/_search_shards`, `/_cat/indices`, `/_cat/aliases`, `/_cat/nodes`, `/_cat/shards`, `/_cat/count`, `/_security/_authenticate`, `/_xpack`, `PUT/GET/HEAD/DELETE /{index}`, `/_mapping`, `GET /{index}/_mapping/field/{fields}`, `/_settings`, `/_aliases`, `/{alias}/_rollover`, `/_index_template`, `/_ingest/pipeline/{id}`, `GET/POST /_field_caps`, `/_validate/query`, `/_analyze`, `/_refresh`, `/healthz`, `/readyz`, `/metrics`, CORS (`OPTIONS` preflight), `Content-Encoding: gzip`, `vnd.elasticsearch+json; compatible-with=7\|8\|9` | ✅ Supported |
| **Ingestion & Mutations** | `POST /_bulk` (`index`, `create`, `update`, `delete` with per-item failure isolation, batched lookups, `?pipeline=<id>` execution, transient Stream Load retry backoff & **Dynamic Mapping Inference**), `PUT/POST/GET/HEAD/DELETE /{index}/_doc/{id}`, `PUT/POST /{index}/_create/{id}`, `GET /{index}/_source/{id}`, `POST /_mget`, `POST /{index}/_update/{id}`, `POST /{index}/_update_by_query`, `POST /{index}/_delete_by_query`, `POST /_reindex` | ✅ Supported |
| **Full-Text & Term DSL** | `bool`, `dis_max`, `boosting`, `match`, `match_phrase` (+ `slop`), `match_phrase_prefix`, `match_bool_prefix`, `multi_match`, `query_string` (+ `[min TO max]` & `_exists_:field`), `simple_query_string`, `term` (+ `case_insensitive`), `terms`, `ids`, `range` (+ date math), `exists`, `prefix`, `wildcard`, `regexp` | ✅ Supported |
| **Advanced Search & Scoring** | Vector / kNN search (`dense_vector`, `knn_vector` $\rightarrow$ Doris `ARRAY<FLOAT>` + `COSINE_DISTANCE` / `L2_DISTANCE` / `INNER_PRODUCT`, top-level `knn`, `query.knn`, hybrid `query` + `knn`), correlated `nested` queries, `function_score` (`field_value_factor`, `weight`, `score_mode`, `boost_mode`), `constant_score`, `post_filter`, `_source` filtering (`includes`/`excludes`), `fields` & `docvalue_fields` (`epoch_millis`), `highlight` (including `"*"` wildcard), `collapse`, `sort` (including `_doc` tie-breaker), `search_after` (null-safe), Point-in-Time (`POST /{index}/_pit`, `DELETE /_pit`), stateless `/_search/scroll`, `/_msearch`, `/_count` | ✅ Supported |
| **Aggregations & Sub-Aggs** | `terms` (scalar & array), `nested`, `date_histogram` (with `extended_bounds` & `min_doc_count: 0` zero-filling), `histogram`, `range`, `date_range` (+ date math), `filter`, `filters` (named multi-bucket), `missing`, `composite` (multi-column keyset pagination), `top_hits`, `cardinality`, `value_count`, `stats`, `percentiles`, `avg`, `sum`, `min`, `max`, plus **1-level Sub-Aggregations** (including `top_hits` inside buckets) | ✅ Supported |
| **Doris Introspection & FinOps** | `GET /_doris/ui` (Interactive Workbench + 1-Click Demo Seed + 1-Click Auto-Promote), `POST /{index}/_doris/explain`, `GET /{index}/_doris/ddl`, `GET /_doris/slowlog` (Auto-Indexing Advisor), `POST /{index}/_doris/promote` (Live Column + Inverted Index Promotion + existing document backfill + `--auto-promote`), `GET /_doris/shadow_stats` (`--shadow-es-url`), `?doris_explain=true`, `doris-es-proxy transpile`, `doris-es-proxy ddl`, `doris-es-proxy doctor`, `doris-es-proxy migrate-schema` | ✅ Supported |

---

## Transpiler & Shredder Micro-Benchmarks

Run `nix develop -c make bench` (`go test -bench=. -benchmem ./...`) to reproduce:

| Benchmark | Latency (`ns/op`) | Throughput | Memory (`B/op`) | Allocations (`allocs/op`) |
| :--- | :--- | :--- | :--- | :--- |
| `BenchmarkBuildSearchPlan_OpenMetadataComplex` (Full-Text + Correlated `nested` + `function_score` + 3 Multi-Facet CTE `aggs`) | **~20.5 µs** | **~48,700 plans/sec/core** | 19.6 KB | 290 |
| `BenchmarkShredDocument_OpenMetadataTable` (Promoted scalars + `ARRAY<STRING>` + correlated `nested` arrays + `_doc` `VARIANT`) | **~9.7 µs** | **~103,000 docs/sec/core** | 11.4 KB | 124 |

## Architectural Scope & Known Trade-offs

| Area | `doris-es-proxy` + Apache Doris Behavior | When to Keep Dedicated Elasticsearch |
| :--- | :--- | :--- |
| **Primary Workload Fit** | Metadata catalogs (**OpenMetadata**, **DataHub**), observability/log search, and hybrid analytical + full-text + vector workloads already running Apache Doris. | Applications relying on custom Java Elasticsearch plugins or custom TokenFilters. |
| **Relevance Scoring** | Combines Doris Inverted Index predicates (`MATCH_ANY` / `MATCH_ALL` / `MATCH_PHRASE`) with deterministic field-weighted SQL scoring, `function_score`, and vector distance (`COSINE_DISTANCE` / `L2_DISTANCE` / `INNER_PRODUCT`). | Workloads requiring custom Lucene `Similarity` classes or custom `script_score` Java plugins. |
| **Aggregation Depth** | Supports top-level and 1-level nested sub-aggregations (`date_histogram` / `terms` / `range` / `filters` $\rightarrow$ metric or `top_hits`) in a single Nereids Multi-Cast CTE scan. | Arbitrary $N$-level deep recursive bucket trees or `moving_avg` pipeline aggregations. |
| **Painless Scripting** | Embedded bounded AST interpreter supporting document mutations (`ctx._source.*`, `if/else`, `for`, `putAll`, `addAll`, `removeIf`, `ctx.op`) for `_update` and `_update_by_query`. | Full JVM Painless bytecode compilation or arbitrary `java.time.*` / regex class reflection. |

---

## Quick Start

### 1. Instant Interactive Demo (Zero Docker Required)

Run the end-to-end OpenMetadata search, correlated `nested` column filter, sidebar `aggs`, Painless mutation, and `/_doris/explain` walkthrough in 2 seconds using the built-in `--in-memory --log-sql` mode:

```bash
nix develop -c make demo
# or directly:
bash examples/quickstart.sh
```

### 2. Inspect Transpiled Doris SQL Offline (`transpile` & `ddl` CLI or `?_doris/explain`)

You can transpile any Elasticsearch `/_search` or mapping JSON directly from your terminal with zero server startup:

```bash
# Compile an Elasticsearch _search payload to Apache Doris HitsSQL + AggsSQL:
echo '{"query":{"match":{"name":"orders"}},"aggs":{"by_svc":{"terms":{"field":"serviceType"}}}}' \
  | ./bin/doris-es-proxy transpile --index table_search_index

# Generate the Apache Doris UNIQUE KEY Merge-on-Write CREATE TABLE DDL from an ES mapping:
echo '{"mappings":{"properties":{"name":{"type":"text"},"serviceType":{"type":"keyword"}}}}' \
  | ./bin/doris-es-proxy ddl --index table_search_index
```

Or pass `?doris_explain=true` on any live `POST /{index}/_search` request (or call `POST /{index}/_doris/explain`) to inspect the compiled `hits_sql`, `aggs_sql`, `create_table_ddl`, and `field_bindings` directly in the JSON response.

### 3. Run with a Live Apache Doris Cluster (Docker Compose)

```bash
docker compose up -d --build
ES_URL=http://127.0.0.1:9200 bash examples/quickstart.sh
```

### 4. Build, Benchmark, Fuzz & Run Tests

```bash
nix develop -c make check
nix develop -c make security
nix develop -c make bench
nix develop -c go test -fuzz=FuzzTranspilerBuildSearchPlan -fuzztime=5s ./pkg/transpiler
nix develop -c make build
./bin/doris-es-proxy --listen :9200 --doris-http http://127.0.0.1:8030 --doris-db es_compat --log-sql
```

### 5. Deploy on Kubernetes with Helm

```bash
helm upgrade --install doris-es-proxy ./deploy/helm/doris-es-proxy \
  --namespace doris-search --create-namespace \
  --set doris.httpEndpoint="http://doris-fe.doris.svc:8030" \
  --set doris.mysqlDSN="root:@tcp(doris-fe.doris.svc:9030)/es_compat"
```

### 6. Kubernetes, Helm Chart, Observability & Apache Doris DSIP

- **Helm Chart (HPA, PDB, Secret DSN, Prometheus `ServiceMonitor`)**: [`deploy/helm/doris-es-proxy`](deploy/helm/doris-es-proxy)
- **Grafana Dashboard & Prometheus `PrometheusRule` Alerts**: [`deploy/grafana/doris-es-proxy-dashboard.json`](deploy/grafana/doris-es-proxy-dashboard.json) & [`deploy/grafana/prometheus-alerts.yaml`](deploy/grafana/prometheus-alerts.yaml)
- **Kubernetes Standalone Manifests**: [`deploy/kubernetes/doris-es-proxy.yaml`](deploy/kubernetes/doris-es-proxy.yaml)
- **Apache Doris Improvement Proposal (DSIP)**: [`docs/dsip-doris-es-proxy.md`](docs/dsip-doris-es-proxy.md)
- **OpenMetadata & DataHub Configurations**: [`examples/README.md`](examples/README.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
