#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# fetch-conformance-specs.sh
#
# Idempotently sparse-clones upstream Elasticsearch REST API YAML test corpora
# and compiled wire-schema specifications into ${REPO_ROOT}/.cache/ (gitignored).
#
# LICENSE BOUNDARIES (STRICTLY ENFORCED):
#   1. elastic/elasticsearch @ v7.10.2          -> Apache-2.0
#   2. elastic/elasticsearch-specification @ 8.15 -> Apache-2.0
#   3. elastic/elasticsearch @ v8.15.5          -> Elastic License 2.0 / SSPL / AGPLv3
#      Fetched strictly out-of-tree at test/CI runtime into gitignored ${REPO_ROOT}/.cache/.
#      NEVER vendor, copy, or commit files from .cache/es-v8.15.5 into this repository.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_DIR="${CONFORMANCE_CACHE_DIR:-${REPO_ROOT}/.cache}"

ES_REPO_URL="https://github.com/elastic/elasticsearch.git"
ES_SPEC_REPO_URL="https://github.com/elastic/elasticsearch-specification.git"

COMMON_ES_MODULE_TEST_PATHS=(
  "modules/aggs-matrix-stats/src/yamlRestTest"
  "modules/ingest-common/src/yamlRestTest"
  "modules/lang-mustache/src/yamlRestTest"
  "modules/lang-painless/src/yamlRestTest"
  "modules/percolator/src/yamlRestTest"
  "modules/rank-eval/src/yamlRestTest"
  "modules/reindex/src/yamlRestTest"
)

V7_EXTRA_MODULE_TEST_PATHS=(
  "modules/analysis-common/src/yamlRestTest"
  "modules/mapper-extras/src/yamlRestTest"
  "modules/parent-join/src/yamlRestTest"
  "modules/lang-expression/src/yamlRestTest"
  "modules/geo/src/yamlRestTest"
)

ES8_EXTRA_MODULE_TEST_PATHS=(
  "modules/rest-root/src/yamlRestTest"
  "modules/aggregations/src/yamlRestTest"
  "modules/data-streams/src/yamlRestTest"
  "modules/runtime-fields-common/src/yamlRestTest"
  "modules/analysis-common/src/yamlRestTest"
  "modules/mapper-extras/src/yamlRestTest"
  "modules/parent-join/src/yamlRestTest"
  "modules/lang-expression/src/yamlRestTest"
  "modules/ingest-user-agent/src/yamlRestTest"
  "modules/ingest-geoip/src/yamlRestTest"
  "modules/ingest-attachment/src/yamlRestTest"
  "modules/transport-netty4/src/yamlRestTest"
  "x-pack/plugin/mapper-unsigned-long/src/yamlRestTest"
  "x-pack/plugin/mapper-constant-keyword/src/yamlRestTest"
  "x-pack/plugin/mapper-version/src/yamlRestTest"
  "x-pack/plugin/wildcard/src/yamlRestTest"
  "x-pack/plugin/rank-rrf/src/yamlRestTest"
)

sparse_clone_or_reuse() {
  local name="$1"
  local repo_url="$2"
  local branch="$3"
  local sentinel_rel="$4"
  shift 4
  local sparse_paths=("$@")
  local target_dir="${CACHE_DIR}/${name}"

  if [[ -d "${target_dir}/.git" && -e "${target_dir}/${sentinel_rel}" ]]; then
    local existing_sparse=""
    existing_sparse="$(git -C "${target_dir}" sparse-checkout list 2>/dev/null || true)"
    local all_present=1
    local sp=""
    for sp in "${sparse_paths[@]}"; do
      if ! printf '%s\n' "${existing_sparse}" | sed 's:/*$::' | grep -Fxq "${sp%/}"; then
        all_present=0
        break
      fi
    done
    if [[ "${all_present}" -eq 1 ]]; then
      echo "[fetch-conformance-specs] Reusing cached ${name} (${branch}) at ${target_dir}"
      return 0
    fi
  fi

  if [[ -d "${target_dir}" && ! -d "${target_dir}/.git" ]]; then
    rm -rf "${target_dir}"
  fi

  mkdir -p "${CACHE_DIR}"

  if [[ ! -d "${target_dir}/.git" ]]; then
    echo "[fetch-conformance-specs] Sparse-cloning ${name} (${repo_url} @ ${branch}) -> ${target_dir}"
    git clone \
      --branch "${branch}" \
      --depth 1 \
      --filter=blob:none \
      --sparse \
      "${repo_url}" \
      "${target_dir}"
  else
    echo "[fetch-conformance-specs] Updating sparse paths for ${name} at ${target_dir}"
  fi

  git -C "${target_dir}" sparse-checkout set "${sparse_paths[@]}"
}

main() {
  mkdir -p "${CACHE_DIR}"

  # 1. Elasticsearch v7.10.2 YAML REST test corpus (Apache-2.0)
  sparse_clone_or_reuse \
    "es-v7.10.2" \
    "${ES_REPO_URL}" \
    "v7.10.2" \
    "rest-api-spec/src/main/resources/rest-api-spec/test" \
    "rest-api-spec/src/main/resources/rest-api-spec/test" \
    "${COMMON_ES_MODULE_TEST_PATHS[@]}" \
    "${V7_EXTRA_MODULE_TEST_PATHS[@]}"

  # 2. Elasticsearch v8.15.5 YAML REST test corpus (fetched strictly out-of-tree into gitignored .cache/)
  sparse_clone_or_reuse \
    "es-v8.15.5" \
    "${ES_REPO_URL}" \
    "v8.15.5" \
    "rest-api-spec/src/yamlRestTest/resources/rest-api-spec/test" \
    "rest-api-spec/src/yamlRestTest/resources/rest-api-spec/test" \
    "${COMMON_ES_MODULE_TEST_PATHS[@]}" \
    "${ES8_EXTRA_MODULE_TEST_PATHS[@]}"

  # 3. Elasticsearch Specification 8.15 compiled schema.json + OpenAPI (Apache-2.0)
  sparse_clone_or_reuse \
    "es-specification" \
    "${ES_SPEC_REPO_URL}" \
    "8.15" \
    "output/schema/schema.json" \
    "output/schema" \
    "output/openapi"

  echo "[fetch-conformance-specs] Conformance corpora ready under ${CACHE_DIR}"
}

main "$@"
