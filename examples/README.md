# Running `doris-es-proxy` Examples & Ecosystem Integrations

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

Start a real Apache Doris FE + BE all-in-one container (`apache/doris:all-in-one-4.1.3`) plus `doris-es-proxy` on `:9200`:

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

## Option 3: Ecosystem Integration Configurations

### 1. OpenMetadata (`openmetadata.yaml`)

Point OpenMetadata directly at `doris-es-proxy:9200`:

```yaml
elasticsearch:
  searchType: elasticsearch
  host: localhost # or doris-es-proxy in Docker/K8s network
  port: 9200
  scheme: http
```

### 2. DataHub (`mae-consumer` / `gms`)

```bash
ELASTICSEARCH_HOST=doris-es-proxy
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USE_SSL=false
```

### 3. Grafana Elasticsearch Data Source (`provisioning/datasources/doris-es.yaml`)

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

### 4. Vector / Fluent Bit Log Shipping (`vector.toml`)

```toml
[sinks.doris_es]
type = "elasticsearch"
inputs = ["app_logs"]
endpoints = ["http://doris-es-proxy:9200"]
mode = "bulk"
bulk.index = "logs-%Y.%m.%d"
compression = "gzip"
```

### 5. LangChain / LlamaIndex Hybrid Vector + Full-Text Search

```python
from langchain_elasticsearch import ElasticsearchStore

vector_store = ElasticsearchStore(
    es_url="http://localhost:9200",
    index_name="rag_chunks",
    embedding=embeddings,
    strategy=ElasticsearchStore.ApproxRetrievalStrategy(hybrid=True),
)
docs = vector_store.similarity_search("Apache Doris inverted index", k=5)
```
