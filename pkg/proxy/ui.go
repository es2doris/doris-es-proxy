// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package proxy

import "net/http"

// handleDorisUI serves an embedded, zero-dependency interactive Web Playground at `GET /_doris/ui`
// for exploring ES-to-Doris SQL transpilation, `CREATE TABLE` DDL generation, index mappings,
// and Auto-Indexing Advisor recommendations.
func (s *Server) handleDorisUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(dorisPlaygroundHTML))
}

const dorisPlaygroundHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>doris-es-proxy — Interactive ES-to-Doris SQL & DDL Playground</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #4ade80;
    --amber: #fbbf24;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  header {
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #0b1120;
  }
  header h1 { margin: 0; font-size: 1.15rem; font-weight: 700; color: var(--accent); }
  header .sub { font-size: 0.85rem; color: var(--muted); }
  main {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    padding: 1rem 1.5rem;
    max-width: 1600px;
    margin: 0 auto;
  }
  @media (max-width: 960px) { main { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .card h2 {
    margin: 0;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .controls { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  input, select, button {
    background: #0f172a;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.75rem;
    font-size: 0.85rem;
  }
  button.primary {
    background: var(--accent);
    color: #0f172a;
    font-weight: 600;
    border: none;
    cursor: pointer;
  }
  button.secondary { cursor: pointer; }
  textarea, pre {
    width: 100%;
    min-height: 280px;
    margin: 0;
    padding: 0.75rem;
    background: #090d16;
    color: #e2e8f0;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.82rem;
    overflow: auto;
    white-space: pre-wrap;
  }
  .badge {
    font-size: 0.75rem;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent);
  }
</style>
</head>
<body>
<header>
  <div>
    <h1>doris-es-proxy Playground</h1>
    <div class="sub">Stateless Elasticsearch Query DSL &rarr; Apache Doris 4.x SQL &amp; Nereids Multi-Cast CTE Compiler</div>
  </div>
  <div class="controls">
    <button class="secondary" onclick="loadSlowlog()">Auto-Indexing Advisor (/_doris/slowlog)</button>
    <button class="secondary" onclick="loadShadowStats()">Shadow Parity (/_doris/shadow_stats)</button>
  </div>
</header>
<main>
  <section class="card">
    <h2>
      <span>1. Elasticsearch /_search Payload</span>
      <span class="badge">Input DSL</span>
    </h2>
    <div class="controls">
      <label for="idxInput">Index / Alias:</label>
      <input id="idxInput" value="table_search_index" />
      <button class="primary" onclick="runExplain()">Transpile SQL (/_doris/explain)</button>
      <button class="secondary" onclick="runLiveSearch()">Execute /_search</button>
    </div>
    <textarea id="dslInput">{
  "size": 10,
  "query": {
    "bool": {
      "must": [
        { "query_string": { "query": "+orders -staging" } }
      ],
      "filter": [
        { "term": { "deleted": false } },
        { "nested": {
            "path": "columns",
            "query": { "term": { "columns.dataType": "BIGINT" } }
          }
        }
      ]
    }
  },
  "aggs": {
    "by_service": {
      "terms": { "field": "serviceType", "size": 10 },
      "aggs": {
        "avg_usage": { "avg": { "field": "usageSummary.weeklyStats.count" } }
      }
    },
    "daily_updates": {
      "date_histogram": { "field": "updatedAt", "fixed_interval": "1d" }
    }
  }
}</textarea>
  </section>
  <section class="card">
    <h2>
      <span id="outTitle">2. Compiled Apache Doris SQL &amp; DDL</span>
      <span class="badge" id="outBadge">Nereids Ready</span>
    </h2>
    <pre id="sqlOutput">Click "Transpile SQL" or "Execute /_search" to inspect generated Apache Doris SQL...</pre>
  </section>
</main>
<script>
async function runExplain() {
  const idx = document.getElementById('idxInput').value || 'table_search_index';
  const dsl = document.getElementById('dslInput').value;
  document.getElementById('outTitle').textContent = '2. Compiled Apache Doris SQL & DDL (/_doris/explain)';
  const res = await fetch('/' + encodeURIComponent(idx) + '/_doris/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: dsl
  });
  const data = await res.json();
  let formatted = '-- [HitsSQL]\n' + (data.hits_sql || '(none)') + ';\n\n' +
                  '-- [AggsSQL - Nereids Multi-Cast CTE]\n' + (data.aggs_sql || '(none)') + ';\n\n' +
                  '-- [CREATE TABLE DDL]\n' + (data.create_table_ddl || '');
  document.getElementById('sqlOutput').textContent = formatted;
}
async function runLiveSearch() {
  const idx = document.getElementById('idxInput').value || 'table_search_index';
  const dsl = document.getElementById('dslInput').value;
  document.getElementById('outTitle').textContent = '2. Live /_search Response (?doris_explain=true)';
  const res = await fetch('/' + encodeURIComponent(idx) + '/_search?doris_explain=true', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: dsl
  });
  const data = await res.json();
  document.getElementById('sqlOutput').textContent = JSON.stringify(data, null, 2);
}
async function loadSlowlog() {
  document.getElementById('outTitle').textContent = 'Auto-Indexing Advisor & Slowlog (/_doris/slowlog)';
  const res = await fetch('/_doris/slowlog');
  const data = await res.json();
  document.getElementById('sqlOutput').textContent = JSON.stringify(data, null, 2);
}
async function loadShadowStats() {
  document.getElementById('outTitle').textContent = 'Dual-Read Shadow Parity Stats (/_doris/shadow_stats)';
  const res = await fetch('/_doris/shadow_stats');
  const data = await res.json();
  document.getElementById('sqlOutput').textContent = JSON.stringify(data, null, 2);
}
runExplain();
</script>
</body>
</html>
`
