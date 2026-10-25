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

- **Status:** Proposal / Ready for `apache/doris-*` Ecosystem Donation
- **Repository:** `https://github.com/es2doris/doris-es-proxy`
- **License:** Apache License 2.0 (zero non-ASF dependencies; single static Go binary)
- **Target Doris Versions:** Apache Doris 2.1, 3.x, and 4.x+

---

## 1. Motivation

Apache Doris 2.1, 3.x, and 4.x have evolved into a unified real-time analytical and search engine featuring:
- **BKD & Full-Text Inverted Indexes (`USING INVERTED`)** with `standard`, `unicode`, `chinese`, and `english` tokenizers (`MATCH_ANY`, `MATCH_ALL`, `MATCH_PHRASE`, `MATCH_PHRASE_PREFIX`, `MATCH_REGEXP`, and Doris 4.0 `SEARCH()`).
- **Semi-Structured `VARIANT` Auto-Shredding** for schema-free JSON subcolumns with inverted index pushdown.
- **Unique Key Merge-on-Write (`enable_unique_key_merge_on_write = "true"`)** with sequence columns (`_version`) and row-store (`store_row_column = "true"`) for sub-millisecond point lookups.
- **Nereids Multi-Cast CTEs** capable of evaluating 10–30 search facet aggregations in a single table scan.

However, enterprise metadata platforms (**OpenMetadata**, **DataHub**), observability dashboards (**Grafana**, **Kibana**), log shippers (**Vector**, **Fluent Bit**, **Filebeat**, **OpenTelemetry Collector**), and GenAI frameworks (**LangChain**, **LlamaIndex**, **Dify**) speak the **Elasticsearch / OpenSearch HTTP REST & Query DSL wire protocol** (`:9200`).

Organizations already running Apache Doris are forced to operate a separate JVM-heavy Elasticsearch or OpenSearch cluster solely to satisfy this wire protocol.

**`doris-es-proxy`** eliminates that duplicate cluster via a stateless `<25 MiB` Go proxy that translates Elasticsearch REST APIs, mappings, `/_bulk` NDJSON streams, Painless scripts, Query DSL, and multi-facet aggregations directly into Apache Doris DDL, HTTP Stream Load, and Nereids SQL.

---

## 2. Architecture Overview

### 2.1 Three-Tier Hybrid Document Storage (`pkg/schema`)
Every Elasticsearch index maps to a Doris `UNIQUE KEY(_id)` Merge-on-Write table (`enable_light_schema_change = "true"`):
1. **Tier 1 (Document Fidelity & Metadata):** `_id`, `_version`, `__DORIS_DELETE_SIGN__`, verbatim `_source STRING` (stored in Doris row store for zero-CPU `_source` reconstruction), `_doc VARIANT` (with `USING INVERTED`), and `_all_text STRING` (for wildcard `query_string`).
2. **Tier 2 (Promoted Scalar & Array Columns):** Explicit `_mapping` properties compile to typed physical columns (`f__<field>`) with `USING INVERTED` indexes (`unicode` parser for `ngram`/CJK analyzers, BKD for numeric/date columns).
3. **Tier 3 (Two-Stage Correlated `nested` Array Columns):** Elasticsearch `nested` paths compile to `n__<nested_path> ARRAY<STRING>` (storing per-element JSON) plus `n__<nested_path>__<subfield> ARRAY<STRING> USING INVERTED` pre-filter columns.

### 2.2 Two-Query Nereids Execution Plan (`pkg/transpiler`)
Each `/_search` request compiles into at most two Doris SQL queries:
- **`HitsSQL`:** Pushes `MATCH_*` predicates strictly into the `WHERE` scan filter (never inside `SELECT` projections or `COALESCE`, respecting Doris BE `VMatchPredicate` execution rules), computes `CAST(<score_expr> AS DOUBLE) AS _score` and `COUNT(*) OVER() AS _total_hits`, and supports `search_after` keyset pagination and `collapse` (`ROW_NUMBER() OVER (PARTITION BY ...)`).
- **`AggsSQL` (Nereids Multi-Cast CTE):** Consolidates all facet aggregations (`terms`, `nested`, `date_histogram`, `histogram`, `range`, `filter`, `filters`, `missing`, `cardinality`, `value_count`, `avg`, `sum`, `min`, `max`, `stats`, `percentiles`, and 1-level bucket sub-aggregations) into a single `WITH base_matched AS (...) UNION ALL` query.

### 2.3 Stateless Catalog Persistence (`_es_catalog`)
Index mappings, aliases, and index templates are persisted in `es_compat._es_catalog` (`UNIQUE KEY(entity_type, entity_key)`), enabling horizontal multi-replica scaling and zero-state pod restarts.

### 2.4 Enterprise Migration & FinOps Tooling (`/_doris/*`)
- **`GET /{index}/_doris/explain` & `?doris_explain=true`:** Inspect generated Doris SQL and `CREATE TABLE` DDL for any Elasticsearch query.
- **`GET /_doris/slowlog` (Auto-Indexing Advisor):** Tracks queries touching unpromoted `_doc['...']` `VARIANT` fields and auto-generates `ALTER TABLE ... ADD COLUMN ... ADD INDEX ... USING INVERTED` Light Schema Change DDL recommendations.
- **`--shadow-es-url` & `GET /_doris/shadow_stats`:** Zero-risk dual-read shadow verification measuring hit-count parity (`doris_total == es_total`), Top-K `_id` Jaccard overlap, and latency speedup against a legacy Elasticsearch cluster.
- **`GET /_doris/ui`:** Embedded zero-dependency interactive Web Playground.
