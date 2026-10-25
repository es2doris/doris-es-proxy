# Running `doris-es-proxy` Examples

## Option 1: Instant Local Demo (Zero Docker Required)

Run the end-to-end OpenMetadata search, nested column correlation, facet aggregation, and Painless mutation demo in under 2 seconds using the built-in `--in-memory --log-sql` Doris emulator:

```bash
make demo
# or directly:
bash examples/quickstart.sh
```

Every Elasticsearch REST call (`PUT /table_search_index`, `POST /_bulk`, `POST /table_search_index/_search`, `POST /table_search_index/_update_by_query`, `POST /table_search_index/_mget`) logs the exact Apache Doris `CREATE TABLE`, `HitsSQL`, and Nereids Multi-Cast CTE `AggsSQL` statements alongside the JSON responses.

---

## Option 2: Live Apache Doris Cluster via Docker Compose

Start a real Apache Doris FE + BE all-in-one container (`apache/doris:doris-all-in-one-2.1.7`) plus `doris-es-proxy` on `:9200`:

```bash
docker compose up -d --build
```

Once `doris-fe-be` is healthy, run the quickstart script against the live Doris container:

```bash
ES_URL=http://127.0.0.1:9200 bash examples/quickstart.sh
```

Or run the live Doris E2E test suite:

```bash
make test-e2e
```

---

## Option 3: Connecting OpenMetadata or DataHub to `doris-es-proxy`

Point OpenMetadata (`openmetadata.yaml` or environment variables) directly at `doris-es-proxy:9200`:

```yaml
elasticsearch:
  searchType: elasticsearch
  host: localhost # or doris-es-proxy in Docker network
  port: 9200
  scheme: http
```

Or for DataHub (`mae-consumer` / `gms`):

```bash
ELASTICSEARCH_HOST=doris-es-proxy
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USE_SSL=false
```
