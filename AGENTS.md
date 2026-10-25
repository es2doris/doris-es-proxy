# `doris-es-proxy` Agent Guide

## Overview
`doris-es-proxy` is a stateless Elasticsearch / OpenSearch HTTP REST & Query DSL wire-compatible proxy backed by Apache Doris (2.1 / 3.x / 4.x+).

## Package Structure
- `cmd/doris-es-proxy`: CLI entrypoint wiring MySQL connection pooling (`:9030`) and HTTP Stream Load (`:8030` -> `:8040`).
- `pkg/esast`: Elasticsearch Query DSL, Aggregation, Mapping, and `/_bulk` NDJSON AST parsers.
- `pkg/schema`: Index mapping compiler, Doris `UNIQUE KEY` Merge-on-Write + `USING INVERTED` DDL generator, and `_source` document shredder.
- `pkg/transpiler`: Query DSL + multi-faceted sidebar aggregation AST-to-Doris SQL transpiler.
- `pkg/painless`: Embedded Painless script interpreter and partial `doc` merger for `_update` and `_update_by_query`.
- `pkg/proxy`: HTTP REST router, response stitcher (`_source` filtering, `highlight`, facets), and `DorisSQLBackend` / `StreamLoadClient`.
- `e2e`: End-to-end OpenMetadata and DataHub workflow suites (`MemDorisBackend` + live Apache Doris E2E suite).

## Development Rules
- Always prefix terminal commands with `nix develop -c` (e.g., `nix develop -c go test -race ./...`).
- Never use `git commit --no-verify`.
