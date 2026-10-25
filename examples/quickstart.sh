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

set -euo pipefail

ES_URL="${ES_URL:-http://127.0.0.1:19200}"
PROXY_PID=""

cleanup() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

pretty_json() {
  if command -v jq >/dev/null 2>&1; then
    jq .
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool
  else
    cat
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! curl -fsS "${ES_URL}/" >/dev/null 2>&1; then
  echo "==> No running server found at ${ES_URL}; starting doris-es-proxy (--in-memory --log-sql)..."
  (cd "${REPO_ROOT}" && CGO_ENABLED=0 go build -o bin/doris-es-proxy ./cmd/doris-es-proxy)
  "${REPO_ROOT}/bin/doris-es-proxy" --listen=127.0.0.1:19200 --in-memory --log-sql &
  PROXY_PID=$!
  for _ in {1..30}; do
    if curl -fsS "${ES_URL}/" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
fi

echo ""
echo "================================================================================"
echo " 1. Elasticsearch Handshake (GET /)"
echo "================================================================================"
curl -fsS "${ES_URL}/" | pretty_json

echo ""
echo "================================================================================"
echo " 2. Create OpenMetadata Index with Nested Columns & Multi-Fields (PUT /table_search_index)"
echo "================================================================================"
curl -fsS -X PUT "${ES_URL}/table_search_index" \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": {
      "properties": {
        "name": {
          "type": "text",
          "fields": {
            "keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"}
          }
        },
        "displayName": {"type": "text"},
        "description": {"type": "text"},
        "serviceType": {"type": "keyword"},
        "deleted": {"type": "boolean"},
        "updatedAt": {"type": "long"},
        "tier": {"properties": {"tagFQN": {"type": "keyword"}}},
        "tags": {"properties": {"tagFQN": {"type": "keyword"}}},
        "usageSummary": {
          "properties": {
            "weeklyStats": {"properties": {"count": {"type": "long"}}}
          }
        },
        "columns": {
          "type": "nested",
          "properties": {
            "name": {"type": "keyword"},
            "dataType": {"type": "keyword"},
            "tags": {"properties": {"tagFQN": {"type": "keyword"}}}
          }
        }
      }
    }
  }' | pretty_json

echo ""
echo "================================================================================"
echo " 3. High-Throughput Bulk Ingest (POST /_bulk?refresh=true)"
echo "================================================================================"
cat <<'EOF' | curl -fsS -X POST "${ES_URL}/_bulk?refresh=true" -H "Content-Type: application/x-ndjson" --data-binary @- | pretty_json
{"index":{"_index":"table_search_index","_id":"tbl-orders"}}
{"name":"Customer_Orders","displayName":"Customer Orders Fact Table","description":"All e-commerce customer orders and revenue","serviceType":"BigQuery","deleted":false,"updatedAt":1729773296001,"tier":{"tagFQN":"Tier.Tier1"},"tags":[{"tagFQN":"PII.Sensitive"},{"tagFQN":"Finance"}],"usageSummary":{"weeklyStats":{"count":250}},"columns":[{"name":"user_id","dataType":"INT","tags":[{"tagFQN":"PII.Sensitive"}]},{"name":"order_amount","dataType":"DECIMAL","tags":[{"tagFQN":"Finance"}]}]}
{"index":{"_index":"table_search_index","_id":"tbl-payments"}}
{"name":"Stripe_Payments","displayName":"Stripe Payments Ledger","description":"Payment transactions for customer orders","serviceType":"Snowflake","deleted":false,"updatedAt":1729773296002,"tier":{"tagFQN":"Tier.Tier2"},"tags":[{"tagFQN":"PII.Sensitive"}],"usageSummary":{"weeklyStats":{"count":80}},"columns":[{"name":"user_id","dataType":"VARCHAR","tags":[{"tagFQN":"PII.Sensitive"}]},{"name":"payment_id","dataType":"INT","tags":[]}]}
{"index":{"_index":"table_search_index","_id":"tbl-clicks"}}
{"name":"Web_Clicks","displayName":"Website Clickstream","description":"Anonymous browser click events","serviceType":"BigQuery","deleted":false,"updatedAt":1729773296003,"tags":[{"tagFQN":"Marketing"}],"usageSummary":{"weeklyStats":{"count":10}},"columns":[{"name":"session_id","dataType":"VARCHAR","tags":[]}]}
EOF

echo ""
echo "================================================================================"
echo " 4. Search + Correlated Nested Columns + Function Score + Sidebar Facets + Highlight"
echo "    (POST /table_search_index/_search)"
echo "================================================================================"
curl -fsS -X POST "${ES_URL}/table_search_index/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "from": 0,
    "size": 10,
    "_source": {"includes": ["name", "serviceType", "tier.*", "columns.name"]},
    "highlight": {
      "pre_tags": ["<em>"],
      "post_tags": ["</em>"],
      "fields": {"displayName": {}, "name": {}}
    },
    "query": {
      "function_score": {
        "query": {
          "bool": {
            "must": [
              {
                "multi_match": {
                  "query": "orders",
                  "fields": ["name^10", "displayName^5", "description^2"],
                  "operator": "and"
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
            "filter": [
              {"term": {"deleted": false}},
              {"term": {"tags.tagFQN": "PII.Sensitive"}}
            ]
          }
        },
        "functions": [
          {"filter": {"term": {"tier.tagFQN": "Tier.Tier1"}}, "weight": 3.0},
          {
            "field_value_factor": {
              "field": "usageSummary.weeklyStats.count",
              "factor": 0.05,
              "modifier": "log1p",
              "missing": 0
            }
          }
        ],
        "score_mode": "sum",
        "boost_mode": "multiply"
      }
    },
    "aggs": {
      "serviceType": {"terms": {"field": "serviceType", "size": 10}},
      "tags": {"terms": {"field": "tags.tagFQN", "size": 10}},
      "columns_by_type": {
        "nested": {"path": "columns"},
        "aggs": {
          "dataTypes": {"terms": {"field": "columns.dataType", "size": 10}}
        }
      }
    }
  }' | pretty_json

echo ""
echo "================================================================================"
echo " 5. Painless Script Mutation (POST /table_search_index/_update_by_query)"
echo "================================================================================"
curl -fsS -X POST "${ES_URL}/table_search_index/_update_by_query?refresh=true" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"term": {"serviceType": "BigQuery"}},
    "script": {
      "source": "ctx._source.tier = params.newTier;",
      "params": {"newTier": {"tagFQN": "Tier.Gold"}}
    }
  }' | pretty_json

echo ""
echo "================================================================================"
echo " 6. Verify Updated Document via Multi-Get (POST /table_search_index/_mget)"
echo "================================================================================"
curl -fsS -X POST "${ES_URL}/table_search_index/_mget" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["tbl-orders", "tbl-clicks"]}' | pretty_json

echo ""
echo "==> Quickstart demo completed successfully!"
