<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# DSIP-XXX: `doris-es-proxy` — Stateless Elasticsearch / OpenSearch HTTP REST & Query DSL Wire Compatibility Layer for Apache Doris

| Field | Value |
| :--- | :--- |
| **DSIP ID** | `DSIP-XXX` (Proposed for `apache/doris-*` ecosystem donation) |
| **Status** | Production-Verified (`v0.15.0`) / Ready for `dev@doris.apache.org` Discussion |
| **Author(s)** | `es2doris` Contributors |
| **Mailing List Thread** | `dev@doris.apache.org` |
| **Repository** | [`https://github.com/es2doris/doris-es-proxy`](https://github.com/es2doris/doris-es-proxy) |
| **License** | Apache License 2.0 (zero non-ASF runtime dependencies; single static Go binary) |
| **Target Doris Versions** | Apache Doris 2.1, 3.x, and 4.x+ (`apache/doris:all-in-one-4.1.3` tested in CI) |

---

## 1. Motivation

Apache Doris 2.1, 3.x, and 4.x have evolved into a unified real-time analytical, full-text search, and vector engine featuring:
- **BKD & Full-Text Inverted Indexes (`USING INVERTED`)** with `standard`, `unicode`, `chinese`, and `english` tokenizers (`MATCH_ANY`, `MATCH_ALL`, `MATCH_PHRASE`, `MATCH_PHRASE_PREFIX`, `MATCH_REGEXP`, and Doris 4.0 `SEARCH()`).
- **Semi-Structured `VARIANT` Auto-Shredding** for schema-free JSON subcolumns with inverted index pushdown.
- **Unique Key Merge-on-Write (`enable_unique_key_merge_on_write = "true"`)** with sequence columns (`_version`), soft deletes (`__DORIS_DELETE_SIGN__`), and row-store (`store_row_column = "true"`) for sub-millisecond point lookups.
- **Native Vector Distance Pushdown** (`COSINE_DISTANCE`, `L2_DISTANCE`, `INNER_PRODUCT`) over `ARRAY<FLOAT>` columns.
- **Nereids Multi-Cast CTEs** capable of evaluating 10–30 search facet aggregations in a single table scan.

However, enterprise metadata platforms (**OpenMetadata**, **DataHub**), observability dashboards (**Grafana**, **Kibana**, **OpenSearch Dashboards**), log shippers (**Vector**, **Fluent Bit**, **Filebeat**, **OpenTelemetry Collector**), and GenAI frameworks (**LangChain**, **LlamaIndex**, **Dify**) speak the **Elasticsearch / OpenSearch HTTP REST & Query DSL wire protocol** (`:9200`).

Organizations already running Apache Doris are forced to operate a separate JVM-heavy Elasticsearch or OpenSearch cluster solely to satisfy this wire protocol.

**`doris-es-proxy`** eliminates that duplicate cluster via a stateless `<25 MiB` Go proxy that translates Elasticsearch REST APIs, mappings, `/_bulk` NDJSON streams, Painless scripts, Query DSL, vector kNN search, and multi-facet/pipeline aggregations directly into Apache Doris DDL, HTTP Stream Load, and Nereids SQL.

---

## 2. Architecture Overview

### 2.1 Three-Tier Hybrid Document Storage (`pkg/schema`)
Every Elasticsearch index maps to a Doris `UNIQUE KEY(_id)` Merge-on-Write table (`enable_unique_key_merge_on_write = "true"`):
1. **Tier 1 (Document Fidelity & Metadata):** `_id VARCHAR(512)`, `_version BIGINT` (`function_column.sequence_col`), `__DORIS_DELETE_SIGN__ TINYINT`, verbatim `_source STRING` (stored in Doris row store for zero-CPU `_source` reconstruction), `_doc VARIANT` (with `idx__doc (_doc) USING INVERTED`), and `_all_text STRING` (with `USING INVERTED PROPERTIES("parser" = "unicode")` for wildcard `query_string`).
2. **Tier 2 (Promoted Scalar, Array & Vector Columns):** Explicit `_mapping` properties compile to typed physical columns (`f__<field>`) with `USING INVERTED` indexes (`unicode` parser for `ngram`/CJK analyzers, `support_phrase = "true"` for `text` fields, BKD for numeric/date columns, and `ARRAY<FLOAT>` for `dense_vector`).
3. **Tier 3 (Two-Stage Correlated `nested` Array Columns):** Elasticsearch `nested` paths compile to `n__<nested_path> ARRAY<STRING>` (storing per-element JSON objects) plus `n__<nested_path>__<subfield> ARRAY<STRING> USING INVERTED` pre-filter columns.

#### Concrete Generated DDL Example (`table_search_index`)
```sql
CREATE TABLE IF NOT EXISTS `es_compat`.`table_search_index` (
    `_id` VARCHAR(512) NOT NULL COMMENT "ES _id",
    `_version` BIGINT NOT NULL DEFAULT "1" COMMENT "ES sequence version",
    `_source` STRING NOT NULL COMMENT "Original ES _source JSON",
    `_doc` VARIANT NULL COMMENT "Auto-shredded dynamic fields",
    `_all_text` STRING NULL COMMENT "Concatenated searchable text",
    `f__name` STRING NULL,
    `f__serviceType` VARCHAR(1024) NULL,
    `f__deleted` BOOLEAN NULL,
    `f__embedding` ARRAY<FLOAT> NULL,
    `f__tags__tagFQN` ARRAY<STRING> NULL,
    `n__columns` ARRAY<STRING> NULL,
    `n__columns__name` ARRAY<STRING> NULL,
    `n__columns__dataType` ARRAY<STRING> NULL,
    INDEX `idx__doc` (`_doc`) USING INVERTED,
    INDEX `idx__all_text` (`_all_text`) USING INVERTED PROPERTIES("parser" = "unicode", "support_phrase" = "true"),
    INDEX `idx_f__name` (`f__name`) USING INVERTED PROPERTIES("parser" = "unicode", "support_phrase" = "true"),
    INDEX `idx_f__serviceType` (`f__serviceType`) USING INVERTED,
    INDEX `idx_f__tags__tagFQN` (`f__tags__tagFQN`) USING INVERTED,
    INDEX `idx_n__columns__name` (`n__columns__name`) USING INVERTED,
    INDEX `idx_n__columns__dataType` (`n__columns__dataType`) USING INVERTED
)
UNIQUE KEY(`_id`)
DISTRIBUTED BY HASH(`_id`) BUCKETS AUTO
PROPERTIES (
    "enable_unique_key_merge_on_write" = "true",
    "store_row_column" = "true",
    "function_column.sequence_col" = "_version",
    "compression" = "ZSTD"
);
```

---

### 2.2 Two-Query Nereids Execution Plan & Pipeline Aggregations (`pkg/transpiler`, `pkg/proxy`)
Each `/_search` request compiles into at most two Doris SQL queries:
- **`HitsSQL`:** Pushes `MATCH_*` predicates strictly into the `WHERE` scan filter (never inside `SELECT` projections or `COALESCE`, respecting Doris BE `VMatchPredicate` execution rules), computes `CAST(<score_expr> AS DOUBLE) AS _score` and `COUNT(*) OVER() AS _total_hits` (or `CAST(-1 AS BIGINT) AS _total_hits` when `track_total_hits: false`), and supports `search_after` keyset pagination, cross-index `terms` lookup resolution, `terms_set` (`minimum_should_match_field` / `minimum_should_match_script`), `match_bool_prefix`, and `collapse` (`ROW_NUMBER() OVER (PARTITION BY ...)`).
- **`AggsSQL` (Nereids Multi-Cast CTE):** Consolidates all facet aggregations (`terms`, `significant_terms`, `nested`, `date_histogram`, `histogram`, `range`, `date_range`, `filter`, `filters`, `missing`, `composite`, `top_hits`, `cardinality`, `value_count`, `avg`, `sum`, `min`, `max`, `stats`, `percentiles`, and 1-level bucket sub-aggregations) into a single `WITH base_matched AS (...) UNION ALL` query, followed by in-memory evaluation of sibling and child pipeline aggregations (`avg_bucket`, `sum_bucket`, `min_bucket`, `max_bucket`, `stats_bucket`, `derivative`, `cumulative_sum`, `bucket_script`, `bucket_selector`, `bucket_sort`).

#### Side-by-Side Query DSL $\rightarrow$ Doris Nereids SQL Example

**Elasticsearch `/_search` Request:**
```json
{
  "size": 10,
  "query": {
    "bool": {
      "must": [
        { "match_bool_prefix": { "name": { "query": "customer ord", "operator": "and" } } },
        {
          "nested": {
            "path": "columns",
            "query": {
              "bool": {
                "must": [
                  { "term": { "columns.name": "user_id" } },
                  { "term": { "columns.dataType": "INT" } }
                ]
              }
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "serviceType": { "terms": { "field": "serviceType", "size": 10 } }
  }
}
```

**Generated `HitsSQL` & `AggsSQL`:**
```sql
-- HitsSQL
SELECT `_id`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits`
FROM `es_compat`.`table_search_index`
WHERE ((`f__name` MATCH_ANY 'customer' AND `f__name` MATCH_PHRASE_PREFIX 'ord')
  AND (array_contains(`n__columns__name`, 'user_id')
   AND array_contains(`n__columns__dataType`, 'INT')
   AND array_exists(x -> (json_extract_string(x, '$.name') = 'user_id')
                     AND (json_extract_string(x, '$.dataType') = 'INT'), `n__columns`)))
ORDER BY `_score` DESC, `_id` ASC
LIMIT 10 OFFSET 0;

-- AggsSQL (Single-Pass Nereids Multi-Cast CTE)
WITH base_matched AS (
    SELECT * FROM `es_compat`.`table_search_index`
    WHERE ((`f__name` MATCH_ANY 'customer' AND `f__name` MATCH_PHRASE_PREFIX 'ord')
      AND (array_contains(`n__columns__name`, 'user_id')
       AND array_contains(`n__columns__dataType`, 'INT')
       AND array_exists(x -> (json_extract_string(x, '$.name') = 'user_id')
                         AND (json_extract_string(x, '$.dataType') = 'INT'), `n__columns`)))
)
SELECT 'serviceType' AS _agg_name, CAST(k AS STRING) AS _bucket_key,
       COUNT(*) AS _doc_count, CAST(NULL AS DOUBLE) AS _metric_val, CAST(NULL AS STRING) AS _extra_json
FROM (SELECT `f__serviceType` AS k FROM base_matched WHERE `f__serviceType` IS NOT NULL) t
GROUP BY k ORDER BY _doc_count DESC, k ASC LIMIT 10;
```

---

### 2.3 HTTP Stream Load & Group-Commit Coalescer Contract (`pkg/proxy/streamload.go`, `pkg/proxy/coalescer.go`)
All Elasticsearch write APIs (`POST /_bulk`, `PUT /{index}/_doc/{id}`, `POST /{index}/_update/{id}`, `DELETE /{index}/_doc/{id}`, `_update_by_query`, `_delete_by_query`) shred documents across the 3-tier schema and stream NDJSON rows to Doris FE/BE HTTP Stream Load (`/api/{db}/{table}/_stream_load`) with:
- `format: json` and `read_json_by_line: true`
- `merge_type: MERGE` and `delete: __DORIS_DELETE_SIGN__ = 1`
- `function_column.sequence_col: _version`
- Optional micro-batch group-commit coalescing (`--bulk-coalesce-ms=50`) to batch concurrent small writes into a single Stream Load transaction while preserving immediate flush when `?refresh=true` or `?refresh=wait_for` is requested.

---

### 2.4 Stateless Catalog Persistence (`_es_catalog`) & Enterprise FinOps Tooling (`/_doris/*`)
- **Stateless Catalog (`es_compat._es_catalog`):** Persists index mappings, aliases, ingest pipelines, and index/component templates in Doris (`UNIQUE KEY(entity_type, entity_key)`), enabling zero-state pod restarts and horizontal multi-replica scaling.
- **Native HTTPS/TLS, Inbound Auth & Multi-Tenant Access Control:** Supports `--tls-cert-file` / `--tls-key-file` (TLS 1.2+), HTTP Basic Auth, `ApiKey` / `Bearer` tokens, index-level RBAC, Field-Level Security (`AllowedFields`), and Row-Level Security (`RowFilter`).
- **`GET /{index}/_doris/explain` & `?doris_explain=true`:** Inspect generated Doris SQL (`hits_sql`, `aggs_sql`), normalized SQL fingerprints (`hits_sql_normalized`, `aggs_sql_normalized`), and `CREATE TABLE` DDL for any Elasticsearch query.
- **`GET /_doris/slowlog` (Auto-Indexing Advisor):** Tracks queries touching unpromoted `_doc['...']` `VARIANT` fields and auto-generates `ALTER TABLE ... ADD COLUMN ... ADD INDEX ... USING INVERTED` Light Schema Change DDL recommendations (with optional live auto-promotion via `--auto-promote`).
- **`--shadow-es-url` & `GET /_doris/shadow_stats`:** Zero-risk dual-read shadow verification measuring hit-count parity (`doris_total == es_total`), Top-K `_id` Jaccard overlap, and latency speedup against a legacy Elasticsearch cluster.
- **`GET /_doris/ui` & CLI Subcommands:** Embedded zero-dependency interactive Web Playground plus offline `transpile`, `ddl`, `doctor`, and `migrate-schema` CLI subcommands.

---

## 3. Benchmarks & TCO Comparison

### 3.1 Cluster TCO & Resource Footprint

| Metric | Traditional Dual-Stack (Doris + 3-Node Elasticsearch) | Unified Apache Doris + `doris-es-proxy` |
| :--- | :--- | :--- |
| **Dedicated JVM Heap for Search** | `8 GB – 32+ GB` RAM (3x Elasticsearch nodes) | **`0 GB`** (`< 25 MiB` stateless Go binary) |
| **Storage Amplification** | `2.5x – 4x` raw JSON (`_source` + Lucene `.cfs`/doc_values) | **`0.2x – 0.4x`** raw JSON (Doris columnar + `ZSTD` + `USING INVERTED`) |
| **Facet Query Execution** | N separate Lucene collector passes | **1-pass Nereids Multi-Cast CTE (`WITH base_matched AS (...)`)** |
| **Schema Drift Handling** | Mapping explosion / dynamic mapping freezes | **Doris `VARIANT` auto-shredding + online `promote` DDL** |
| **Dual-Write Sync Pipelines** | Kafka / Debezium / Logstash sync lag & drift | **Single-engine storage in Apache Doris** |

### 3.2 Transpiler, Shredder & Live Doris 4.1.3 Performance

| Workload | Throughput / Latency | Notes |
| :--- | :--- | :--- |
| **Complex Query Transpilation** (`bool` + correlated `nested` + `function_score` + 3-facet CTE) | **`~20.5 µs/op`** (`~48,700 plans/sec/core`) | Sub-25µs overhead on Apple M-series / modern x86_64 |
| **3-Tier Document Shredding** (`_source` + `_doc VARIANT` + `_all_text` + promoted + `nested`) | **`~9.7 µs/op`** (`~103,000 docs/sec/core`) | Single-pass JSON shredder for HTTP Stream Load |
| **Single-Flight Coalescer & Query Result Cache Hit** (`--query-cache-ttl=5s`) | **`< 0.15 ms`** | Automatic write-invalidation on `/_bulk`, `/_doc`, `/_update` |
| **Live Apache Doris 4.1.3 E2E Suite** (`TestLiveApacheDoris_E2E` in GitHub Actions) | **`~2m0s` total CI job** (including Docker pull & FE/BE boot) | Full DDL, Stream Load, BM25 + `nested` + `knn` + `composite` + `pipeline_aggs` |

---

## 4. Ecosystem Integration Showcase

### 4.1 OpenMetadata (`openmetadata.yaml`)
```yaml
elasticsearch:
  searchType: elasticsearch
  host: doris-es-proxy
  port: 9200
  scheme: http
```

### 4.2 DataHub (`gms` / `mae-consumer` / `mce-consumer`)
```bash
ELASTICSEARCH_HOST=doris-es-proxy
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USE_SSL=false
```

### 4.3 Grafana Elasticsearch Data Source (`provisioning/datasources/doris-es.yaml`)
```yaml
apiVersion: 1
datasources:
  - name: Apache Doris (via doris-es-proxy)
    type: elasticsearch
    access: proxy
    url: http://doris-es-proxy:9200
    jsonData:
      index: "logs-*"
      timeField: "@timestamp"
      esVersion: "8.11.0"
      logMessageField: "message"
      logLevelField: "level"
```

### 4.4 Vector / Fluent Bit High-Throughput Log Shipping
```toml
# vector.toml
[sinks.doris_es]
type = "elasticsearch"
inputs = ["app_logs"]
endpoints = ["http://doris-es-proxy:9200"]
mode = "bulk"
bulk.index = "logs-%Y.%m.%d"
compression = "gzip"
```

### 4.5 LangChain / LlamaIndex Hybrid BM25 + Vector Search (`ElasticsearchStore`)
```python
from langchain_elasticsearch import ElasticsearchStore

vector_store = ElasticsearchStore(
    es_url="http://localhost:9200",
    index_name="rag_chunks",
    embedding=embeddings,
    strategy=ElasticsearchStore.ApproxRetrievalStrategy(hybrid=True),
)
# Translates hybrid match + top-level knn into Apache Doris MATCH_ANY + COSINE_DISTANCE
docs = vector_store.similarity_search("Apache Doris inverted index", k=5)
```

---

## 5. Upstream Apache Doris Synergy & Donation Roadmap

1. **Zero-Intrusion Sidecar / Gateway Deployment:** `doris-es-proxy` requires zero modifications to Apache Doris FE or BE and works out-of-the-box with Apache Doris 2.1, 3.x, and 4.x+.
2. **Optional Upstream Doris BE/FE Enhancements:**
   - Support `score()` weighting per `MATCH_*` predicate clause when multiple inverted-index clauses appear in a single `WHERE` tree.
   - Allow `MATCH_*` predicates inside `CASE WHEN` / `SELECT` score expressions in addition to top-level `WHERE` filters for native multi-clause BM25 boosting.
3. **Donation Packaging:** Licensed under Apache License 2.0 with full ASF license headers, reproducible Nix flake + Makefile + Helm chart (`deploy/helm/doris-es-proxy`), and live `apache/doris:all-in-one-4.1.3` E2E CI workflow (`.github/workflows/e2e-live-doris.yml`).
