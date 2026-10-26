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

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// HitRow represents a single matched document returned by Doris for Query 1 (HitsSQL).
type HitRow struct {
	Index     string
	ID        string
	Version   int64
	Source    json.RawMessage
	Score     float64
	TotalHits int64
}

// AggRow represents a single facet bucket or metric row returned by Doris for Query 2 (AggsSQL).
type AggRow struct {
	AggName   string
	BucketKey string
	DocCount  int64
	Value     float64
}

func (r AggRow) effectiveCount() int64 {
	if r.DocCount != 0 {
		return r.DocCount
	}
	return int64(r.Value)
}

func (r AggRow) effectiveValue() float64 {
	if r.Value != 0 {
		return r.Value
	}
	return float64(r.DocCount)
}

// DorisBackend abstracts the execution of DDL, SQL queries, point lookups, and Stream Loads
// against Apache Doris so the proxy can run against either a live Doris FE+BE cluster or an
// in-memory test harness.
type DorisBackend interface {
	Ping(ctx context.Context) error
	ExecDDL(ctx context.Context, ddl string) error
	QueryHits(ctx context.Context, sql string) ([]HitRow, error)
	QueryAggs(ctx context.Context, sql string) ([]AggRow, error)
	GetDocByID(ctx context.Context, db, table, id string) (*HitRow, bool, error)
	GetDocsByIDs(ctx context.Context, db, table string, ids []string) (map[string]HitRow, error)
	StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error
}

// CatalogEntry represents a persisted index schema, alias, or index template in Doris `_es_catalog`.
type CatalogEntry struct {
	EntityType     string `json:"entity_type"`      // "index" | "alias" | "template"
	EntityKey      string `json:"entity_key"`       // indexName, aliasName, or templateName
	PayloadJSON    string `json:"payload_json"`     // serialized MappingSpec, []string alias targets, or IndexTemplateRequest
	UpdatedEpochMs int64  `json:"updated_epoch_ms"` // monotonic epoch ms
}

// CatalogBackend is an optional extension of DorisBackend for persisting index mappings,
// aliases, and templates in Apache Doris (`_es_catalog`) so proxy instances remain 100% stateless
// across pod restarts and multi-replica horizontal scaling.
type CatalogBackend interface {
	InitCatalog(ctx context.Context, db string) error
	UpsertCatalogEntry(ctx context.Context, db string, entry CatalogEntry) error
	DeleteCatalogEntry(ctx context.Context, db, entityType, entityKey string) error
	LoadCatalogEntries(ctx context.Context, db string) ([]CatalogEntry, error)
}

// Server implements the Elasticsearch / OpenSearch HTTP REST API adapter backed by Apache Doris.
type Server struct {
	dorisDB              string
	backend              DorisBackend
	transpileOpts        transpiler.TranspilerOptions
	maxBodyBytes         int64
	slowTracker          *SlowQueryTracker
	shadowVerifier       *ShadowVerifier
	coalescer            *StreamLoadCoalescer
	queryCache           *QueryResultCache
	totalHTTPRequests    int64
	autoPromoteThreshold int64

	mu        sync.RWMutex
	indices   map[string]*schema.IndexSchema
	aliases   map[string][]string // aliasName -> ordered target indexNames
	templates map[string]esast.IndexTemplateRequest
	pipelines map[string]map[string]any
}

func NewServer(dorisDB string, backend DorisBackend, opts transpiler.TranspilerOptions) *Server {
	if dorisDB == "" {
		dorisDB = "es_compat"
	}
	s := &Server{
		dorisDB:        dorisDB,
		backend:        backend,
		transpileOpts:  opts,
		maxBodyBytes:   DefaultMaxRequestBodyBytes,
		slowTracker:    newSlowQueryTracker(),
		shadowVerifier: newShadowVerifier(""),
		queryCache:     newQueryResultCache(),
		indices:        make(map[string]*schema.IndexSchema),
		aliases:        make(map[string][]string),
		templates:      make(map[string]esast.IndexTemplateRequest),
		pipelines:      make(map[string]map[string]any),
	}
	s.coalescer = newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		return s.backend.StreamLoad(ctx, table, ndjson, syncRefresh)
	})
	return s
}

// SetBulkCoalesce configures group-commit Stream Load micro-batching across concurrent write requests.
func (s *Server) SetBulkCoalesce(window time.Duration, maxBytes int) {
	s.coalescer.Configure(window, maxBytes)
}

// SetQueryCacheTTL configures the bounded search response cache TTL (`<= 0` disables caching).
func (s *Server) SetQueryCacheTTL(ttl time.Duration, maxEntries int) {
	s.queryCache.Configure(ttl, maxEntries)
}

func (s *Server) streamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	err := s.coalescer.Submit(ctx, table, ndjson, syncRefresh)
	s.queryCache.InvalidateAll()
	return err
}

// BootstrapCatalog creates `_es_catalog` if supported by the backend and rehydrates
// all persisted index mappings, aliases, and templates into memory.
func (s *Server) BootstrapCatalog(ctx context.Context) error {
	cb, ok := s.backend.(CatalogBackend)
	if !ok {
		return nil
	}
	if err := cb.InitCatalog(ctx, s.dorisDB); err != nil {
		return err
	}
	return s.syncCatalogFromBackend(ctx)
}

func (s *Server) syncCatalogFromBackend(ctx context.Context) error {
	cb, ok := s.backend.(CatalogBackend)
	if !ok {
		return nil
	}
	entries, err := cb.LoadCatalogEntries(ctx, s.dorisDB)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		switch e.EntityType {
		case "template":
			var tpl esast.IndexTemplateRequest
			if err := json.Unmarshal([]byte(e.PayloadJSON), &tpl); err == nil {
				s.templates[e.EntityKey] = tpl
			}
		case "index":
			var spec esast.MappingSpec
			if len(strings.TrimSpace(e.PayloadJSON)) > 0 && e.PayloadJSON != "null" {
				_ = json.Unmarshal([]byte(e.PayloadJSON), &spec)
			}
			var specPtr *esast.MappingSpec
			if len(spec.Properties) > 0 || spec.Dynamic != nil {
				specPtr = &spec
			}
			s.indices[e.EntityKey] = schema.CompileIndexSchema(s.dorisDB, e.EntityKey, specPtr)
		case "alias":
			var targets []string
			if err := json.Unmarshal([]byte(e.PayloadJSON), &targets); err == nil {
				if len(targets) > 0 {
					s.aliases[e.EntityKey] = targets
				} else {
					delete(s.aliases, e.EntityKey)
				}
			}
		}
	}
	return nil
}

func (s *Server) persistTemplate(ctx context.Context, name string, tpl esast.IndexTemplateRequest) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(tpl); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "template",
				EntityKey:      name,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: time.Now().UnixMilli(),
			})
		}
	}
}

func (s *Server) persistIndex(ctx context.Context, indexName string, idxSchema *schema.IndexSchema) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		payload := "{}"
		if idxSchema != nil && idxSchema.RawMapping != nil {
			if raw, err := json.Marshal(idxSchema.RawMapping); err == nil {
				payload = string(raw)
			}
		}
		_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
			EntityType:     "index",
			EntityKey:      indexName,
			PayloadJSON:    payload,
			UpdatedEpochMs: time.Now().UnixMilli(),
		})
	}
}

func (s *Server) persistAlias(ctx context.Context, aliasName string, targets []string) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if len(targets) == 0 {
			_ = cb.DeleteCatalogEntry(ctx, s.dorisDB, "alias", aliasName)
			return
		}
		if raw, err := json.Marshal(targets); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "alias",
				EntityKey:      aliasName,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: time.Now().UnixMilli(),
			})
		}
	}
}

func (s *Server) deleteCatalogEntity(ctx context.Context, entityType, entityKey string) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		_ = cb.DeleteCatalogEntry(ctx, s.dorisDB, entityType, entityKey)
	}
}

// Handler returns an `http.Handler` that routes Elasticsearch / OpenSearch REST endpoints
// without `http.ServeMux` wildcard ambiguity between `/_alias/{name}` and `/{index}/_search`.
func (s *Server) Handler() http.Handler {
	return s.withWireMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.Trim(r.URL.Path, "/")
		if trimmed == "" {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			s.handleRootHandshake(w, r)
			return
		}
		segs := strings.Split(trimmed, "/")

		switch len(segs) {
		case 1:
			switch segs[0] {
			case "_bulk":
				s.handleBulk(w, r)
			case "_search":
				s.handleSearch(w, r)
			case "_msearch":
				s.handleMSearch(w, r)
			case "_mget":
				s.handleMGet(w, r)
			case "_count":
				s.handleCount(w, r)
			case "_stats":
				s.handleIndexStats(w, r)
			case "_search_shards":
				s.handleSearchShards(w, r)
			case "_reindex":
				s.handleReindex(w, r)
			case "_aliases":
				if r.Method == http.MethodPost {
					s.handleUpdateAliases(w, r)
				} else {
					s.handleGetAliases(w, r)
				}
			case "_alias":
				s.handleGetAliases(w, r)
			case "_refresh", "_flush":
				s.handleRefresh(w, r)
			case "_nodes":
				s.handleNodes(w, r)
			case "_mapping", "_mappings":
				s.handleGetAllMappings(w, r)
			case "_field_caps":
				s.handleFieldCaps(w, r)
			case "_analyze":
				s.handleAnalyze(w, r)
			case "_pit":
				s.handlePIT(w, r)
			case "metrics", "_prometheus":
				s.handleMetrics(w, r)
			case "healthz", "_healthz", "livez":
				s.handleHealthz(w, r)
			case "readyz", "_readyz":
				s.handleReadyz(w, r)
			case "_xpack":
				writeJSON(w, http.StatusOK, map[string]any{
					"build":    map[string]any{"hash": "doris-es-proxy", "date": "2026-10-25T00:00:00Z"},
					"license":  map[string]any{"type": "basic", "mode": "basic", "status": "active"},
					"features": map[string]any{"security": map[string]any{"available": true, "enabled": true}},
				})
			default:
				r.SetPathValue("index", segs[0])
				switch r.Method {
				case http.MethodPut:
					s.handleCreateIndex(w, r)
				case http.MethodGet:
					s.handleGetIndex(w, r)
				case http.MethodHead:
					s.handleHeadIndex(w, r)
				case http.MethodDelete:
					s.handleDeleteIndex(w, r)
				default:
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			}

		case 2:
			switch {
			case segs[0] == "_cluster" && segs[1] == "health":
				s.handleClusterHealth(w, r)
			case segs[0] == "_cluster" && segs[1] == "settings":
				s.handleClusterSettings(w, r)
			case segs[0] == "_cat" && segs[1] == "indices":
				s.handleCatIndices(w, r)
			case segs[0] == "_cat" && segs[1] == "aliases":
				s.handleCatAliases(w, r)
			case segs[0] == "_cat" && segs[1] == "nodes":
				s.handleCatNodes(w, r)
			case segs[0] == "_cat" && segs[1] == "shards":
				s.handleCatShards(w, r)
			case segs[0] == "_cat" && segs[1] == "count":
				s.handleCatCount(w, r)
			case segs[0] == "_cat" && segs[1] == "health":
				s.handleClusterHealth(w, r)
			case segs[0] == "_search" && segs[1] == "scroll":
				s.handleScroll(w, r)
			case segs[0] == "_doris" && segs[1] == "explain":
				s.handleDorisExplain(w, r)
			case segs[0] == "_doris" && segs[1] == "ui":
				s.handleDorisUI(w, r)
			case segs[0] == "_doris" && segs[1] == "slowlog":
				s.handleDorisSlowlog(w, r)
			case segs[0] == "_doris" && segs[1] == "shadow_stats":
				s.handleDorisShadowStats(w, r)
			case segs[0] == "_doris" && segs[1] == "metrics":
				s.handleMetrics(w, r)
			case segs[0] == "_validate" && segs[1] == "query":
				s.handleValidateQuery(w, r)
			case segs[0] == "_ingest" && segs[1] == "pipeline":
				s.handleIngestPipeline(w, r)
			case segs[0] == "_security" && segs[1] == "_authenticate":
				writeJSON(w, http.StatusOK, map[string]any{
					"username":  "elastic",
					"roles":     []string{"superuser"},
					"full_name": "doris-es-proxy",
					"email":     "",
					"metadata":  map[string]any{},
					"enabled":   true,
				})
			case segs[0] == "_alias":
				r.SetPathValue("name", segs[1])
				s.handleGetAliases(w, r)
			case segs[0] == "_index_template" || segs[0] == "_template" || segs[0] == "_component_template":
				r.SetPathValue("name", segs[1])
				s.handleIndexTemplate(w, r)
			default:
				r.SetPathValue("index", segs[0])
				switch segs[1] {
				case "_mapping", "_mappings":
					if r.Method == http.MethodGet {
						s.handleGetMapping(w, r)
					} else {
						s.handlePutMapping(w, r)
					}
				case "_settings":
					s.handleIndexSettings(w, r)
				case "_alias", "_aliases":
					s.handleGetIndexAliases(w, r)
				case "_search":
					s.handleSearch(w, r)
				case "_msearch":
					s.handleMSearch(w, r)
				case "_mget":
					s.handleMGet(w, r)
				case "_count":
					s.handleCount(w, r)
				case "_stats":
					s.handleIndexStats(w, r)
				case "_search_shards":
					s.handleSearchShards(w, r)
				case "_bulk":
					s.handleBulk(w, r)
				case "_refresh", "_flush", "_forcemerge":
					s.handleRefresh(w, r)
				case "_update_by_query":
					s.handleUpdateByQuery(w, r)
				case "_delete_by_query":
					s.handleDeleteByQuery(w, r)
				case "_field_caps":
					s.handleFieldCaps(w, r)
				case "_analyze":
					s.handleAnalyze(w, r)
				case "_pit":
					s.handlePIT(w, r)
				case "_rollover":
					r.SetPathValue("alias", segs[0])
					s.handleRollover(w, r)
				case "_doc", "_create":
					if r.Method == http.MethodPost {
						r.SetPathValue("id", esast.NextAutoID())
						s.handlePutDoc(w, r)
					} else {
						writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
					}
				default:
					writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
				}
			}

		case 3:
			if segs[0] == "_cluster" && segs[1] == "health" {
				r.SetPathValue("index", segs[2])
				s.handleClusterHealth(w, r)
				return
			}
			if segs[0] == "_resolve" && segs[1] == "index" {
				r.SetPathValue("name", segs[2])
				s.handleResolveIndex(w, r)
				return
			}
			if segs[0] == "_ingest" && segs[1] == "pipeline" {
				r.SetPathValue("id", segs[2])
				s.handleIngestPipeline(w, r)
				return
			}
			if segs[0] == "_cat" {
				r.SetPathValue("index", segs[2])
				r.SetPathValue("name", segs[2])
				switch segs[1] {
				case "indices":
					s.handleCatIndices(w, r)
					return
				case "aliases":
					s.handleCatAliases(w, r)
					return
				case "count":
					s.handleCatCount(w, r)
					return
				case "shards":
					s.handleCatShards(w, r)
					return
				}
			}
			if (segs[0] == "_mapping" || segs[0] == "_mappings") && segs[1] == "field" {
				r.SetPathValue("fields", segs[2])
				s.handleGetFieldMapping(w, r)
				return
			}
			r.SetPathValue("index", segs[0])
			if segs[1] == "_alias" || segs[1] == "_aliases" {
				r.SetPathValue("name", segs[2])
				s.handleIndexAliasByName(w, r)
				return
			}
			if segs[1] == "_doris" && segs[2] == "explain" {
				s.handleDorisExplain(w, r)
				return
			}
			if segs[1] == "_doris" && segs[2] == "ddl" {
				s.handleDorisDDL(w, r)
				return
			}
			if segs[1] == "_doris" && segs[2] == "slowlog" {
				s.handleDorisSlowlog(w, r)
				return
			}
			if segs[1] == "_doris" && segs[2] == "promote" {
				s.handleDorisPromoteField(w, r)
				return
			}
			if segs[1] == "_validate" && segs[2] == "query" {
				s.handleValidateQuery(w, r)
				return
			}
			if segs[1] == "_rollover" {
				r.SetPathValue("alias", segs[0])
				r.SetPathValue("new_index", segs[2])
				s.handleRollover(w, r)
				return
			}
			if segs[1] == "_mapping" || segs[1] == "_mappings" {
				if r.Method == http.MethodGet {
					s.handleGetMapping(w, r)
				} else {
					s.handlePutMapping(w, r)
				}
				return
			}
			if segs[1] == "_doc" && segs[2] == "_search" {
				s.handleSearch(w, r)
				return
			}
			if segs[1] == "_doc" && segs[2] == "_count" {
				s.handleCount(w, r)
				return
			}
			r.SetPathValue("id", segs[2])
			switch segs[1] {
			case "_doc", "_create":
				switch r.Method {
				case http.MethodPut, http.MethodPost:
					s.handlePutDoc(w, r)
				case http.MethodGet:
					s.handleGetDoc(w, r)
				case http.MethodHead:
					s.handleHeadDoc(w, r)
				case http.MethodDelete:
					s.handleDeleteDoc(w, r)
				default:
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			case "_update":
				s.handleUpdateDoc(w, r)
			case "_source":
				s.handleGetSource(w, r)
			default:
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			}

		case 4:
			if (segs[1] == "_mapping" || segs[1] == "_mappings") && segs[2] == "field" {
				r.SetPathValue("index", segs[0])
				r.SetPathValue("fields", segs[3])
				s.handleGetFieldMapping(w, r)
				return
			}
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)

		default:
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		}
	}))
}

func (s *Server) handleRootHandshake(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         "doris-es-proxy",
		"cluster_name": "apache-doris-search-cluster",
		"cluster_uuid": "doris-es-0000-0000-0000-000000000001",
		"version": map[string]any{
			"number":                              "7.10.2",
			"build_flavor":                        "default",
			"build_type":                          "tar",
			"build_hash":                          "doris4x",
			"lucene_version":                      "9.10.0",
			"minimum_wire_compatibility_version":  "6.8.0",
			"minimum_index_compatibility_version": "6.0.0-beta1",
		},
		"tagline": "You Know, for Search (Backed by Apache Doris)",
	})
}

func (s *Server) handleClusterHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	numIndices := len(s.indices)
	s.mu.RUnlock()

	status := "green"
	httpCode := http.StatusOK
	if err := s.backend.Ping(r.Context()); err != nil {
		status = "red"
		if r.URL.Query().Get("local") == "false" {
			httpCode = http.StatusServiceUnavailable
		}
	}

	writeJSON(w, httpCode, map[string]any{
		"cluster_name":                    "apache-doris-search-cluster",
		"status":                          status,
		"timed_out":                       false,
		"number_of_nodes":                 1,
		"number_of_data_nodes":            1,
		"active_primary_shards":           numIndices,
		"active_shards":                   numIndices,
		"relocating_shards":               0,
		"initializing_shards":             0,
		"unassigned_shards":               0,
		"delayed_unassigned_shards":       0,
		"number_of_pending_tasks":         0,
		"active_shards_percent_as_number": 100.0,
	})
}

func (s *Server) handleClusterSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		writeJSON(w, http.StatusOK, map[string]any{
			"acknowledged": true,
			"persistent":   map[string]any{},
			"transient":    map[string]any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"persistent": map[string]any{},
		"transient":  map[string]any{},
	})
}

func (s *Server) handleIndexSettings(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	if r.Method == http.MethodPut {
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		indexName: map[string]any{
			"settings": map[string]any{
				"index": map[string]any{
					"number_of_shards":   "1",
					"number_of_replicas": "0",
				},
			},
		},
	})
}

func (s *Server) handleNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "apache-doris-search-cluster",
		"nodes": map[string]any{
			"doris-fe-1": map[string]any{
				"name":    "doris-fe-1",
				"version": "7.10.2",
				"roles":   []string{"master", "data", "ingest"},
			},
		},
	})
}

func (s *Server) handleCatIndices(w http.ResponseWriter, r *http.Request) {
	var names []string
	if pat := r.PathValue("index"); pat != "" {
		names = s.resolveTargetIndices(pat)
	} else {
		s.mu.RLock()
		names = make([]string, 0, len(s.indices))
		for name := range s.indices {
			names = append(names, name)
		}
		s.mu.RUnlock()
	}
	sort.Strings(names)
	list := make([]map[string]any, 0, len(names))
	for _, name := range names {
		list = append(list, map[string]any{
			"health": "green",
			"status": "open",
			"index":  name,
		})
	}
	writeCatResponse(w, r, []string{"health", "status", "index"}, list)
}

func (s *Server) handleCatAliases(w http.ResponseWriter, r *http.Request) {
	namePattern := r.PathValue("name")
	s.mu.RLock()
	var list []map[string]any
	for alias, targets := range s.aliases {
		if namePattern != "" && namePattern != "*" && namePattern != "_all" && !matchWildcardPattern(namePattern, alias) {
			continue
		}
		for _, idx := range targets {
			list = append(list, map[string]any{
				"alias": alias,
				"index": idx,
			})
		}
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"alias", "index"}, list)
}

func (s *Server) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
	})
}

type scrollCursor struct {
	Index    string              `json:"idx"`
	Req      esast.SearchRequest `json:"req"`
	LastSort []any               `json:"after,omitempty"`
}

func encodeScrollCursor(indexName string, req *esast.SearchRequest, lastSort []any) string {
	c := scrollCursor{
		Index:    indexName,
		Req:      *req,
		LastSort: lastSort,
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "doris-scroll-eof"
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeScrollCursor(token string) (*scrollCursor, bool) {
	if token == "" || token == "doris-scroll-eof" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, false
	}
	var c scrollCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, false
	}
	return &c, true
}

func (s *Server) handleScroll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		writeJSON(w, http.StatusOK, map[string]any{"succeeded": true, "num_freed": 1})
		return
	}
	scrollID := r.URL.Query().Get("scroll_id")
	if r.Body != nil {
		var body struct {
			ScrollID any `json:"scroll_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			switch v := body.ScrollID.(type) {
			case string:
				if v != "" {
					scrollID = v
				}
			case []any:
				if len(v) > 0 {
					scrollID = fmt.Sprintf("%v", v[0])
				}
			}
		}
	}
	cursor, ok := decodeScrollCursor(scrollID)
	if !ok || len(cursor.LastSort) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"_scroll_id": "doris-scroll-eof",
			"took":       1,
			"timed_out":  false,
			"_shards":    map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
			"hits": map[string]any{
				"total":     map[string]any{"value": 0, "relation": "eq"},
				"max_score": nil,
				"hits":      []any{},
			},
		})
		return
	}
	req := cursor.Req
	zero := 0
	req.From = &zero
	req.SearchAfter = cursor.LastSort
	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), cursor.Index, &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	nextScrollID := "doris-scroll-eof"
	if hitsWrapper, ok := resp["hits"].(map[string]any); ok {
		if hitList, ok := hitsWrapper["hits"].([]map[string]any); ok && len(hitList) > 0 {
			if lastSort, ok := hitList[len(hitList)-1]["sort"].([]any); ok && len(lastSort) > 0 {
				nextScrollID = encodeScrollCursor(cursor.Index, &req, lastSort)
			}
		}
	}
	resp["_scroll_id"] = nextScrollID
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleIndexTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var tpl esast.IndexTemplateRequest
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &tpl); err != nil {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
					return
				}
			}
		}
		s.mu.Lock()
		s.templates[name] = tpl
		s.mu.Unlock()
		s.persistTemplate(r.Context(), name, tpl)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodHead:
		s.mu.RLock()
		_, ok := s.templates[name]
		s.mu.RUnlock()
		if !ok {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			_, ok = s.templates[name]
			s.mu.RUnlock()
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		s.mu.RLock()
		tpl, ok := s.templates[name]
		s.mu.RUnlock()
		if !ok {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			tpl, ok = s.templates[name]
			s.mu.RUnlock()
		}
		if !ok {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "index_template ["+name+"] missing")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"index_templates": []map[string]any{
				{"name": name, "index_template": tpl},
			},
		})
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.templates, name)
		s.mu.Unlock()
		s.deleteCatalogEntity(r.Context(), "template", name)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) matchingTemplateMappingsLocked(indexName string) *esast.MappingSpec {
	var merged *esast.MappingSpec
	tplNames := make([]string, 0, len(s.templates))
	for k := range s.templates {
		tplNames = append(tplNames, k)
	}
	sort.Strings(tplNames)
	for _, name := range tplNames {
		tpl := s.templates[name]
		for _, pat := range tpl.EffectivePatterns() {
			if matchWildcardPattern(pat, indexName) {
				if m := tpl.EffectiveMappings(); m != nil {
					merged = schema.MergeMappingSpecs(merged, m)
				}
				break
			}
		}
	}
	return merged
}

func (s *Server) handleCreateIndex(w http.ResponseWriter, r *http.Request) {
	indexName := r.PathValue("index")
	var req esast.IndexCreateRequest
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
		}
	}

	s.mu.RLock()
	oldSchema := s.indices[indexName]
	tplMappings := s.matchingTemplateMappingsLocked(indexName)
	s.mu.RUnlock()

	effectiveMappings := schema.MergeMappingSpecs(tplMappings, req.Mappings)
	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
	ddl := schema.GenerateCreateTableDDL(compiled)
	if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}
	if oldSchema != nil {
		for _, stmt := range schema.GenerateAlterTableDDL(oldSchema, compiled) {
			_ = s.backend.ExecDDL(r.Context(), stmt)
		}
		s.backfillIndexSchema(r.Context(), compiled)
	}

	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	s.indices[indexName] = compiled
	for alias := range req.Aliases {
		s.addAliasLocked(alias, indexName)
		aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
	}
	s.mu.Unlock()
	s.persistIndex(r.Context(), indexName, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(r.Context(), alias, targets)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"index":               indexName,
	})
}

func (s *Server) handleGetIndex(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	if len(targets) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+r.PathValue("index")+"]")
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := make(map[string]any)
	for _, indexName := range targets {
		idx, ok := s.indices[indexName]
		if !ok {
			continue
		}
		mappings := map[string]any{}
		if idx.RawMapping != nil {
			mappings["properties"] = idx.RawMapping.Properties
		}
		idxAliases := make(map[string]any)
		for alias, aliasTargets := range s.aliases {
			for _, t := range aliasTargets {
				if t == indexName {
					idxAliases[alias] = map[string]any{}
				}
			}
		}
		resp[indexName] = map[string]any{
			"aliases":  idxAliases,
			"mappings": mappings,
			"settings": map[string]any{"index": map[string]any{"number_of_shards": "1", "number_of_replicas": "0"}},
		}
	}
	if len(resp) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+r.PathValue("index")+"]")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("index")
	s.mu.RLock()
	_, isIndex := s.indices[raw]
	targets, isAlias := s.aliases[raw]
	s.mu.RUnlock()
	if !isIndex && (!isAlias || len(targets) == 0) {
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.RLock()
		_, isIndex = s.indices[raw]
		targets, isAlias = s.aliases[raw]
		s.mu.RUnlock()
	}
	if !isIndex && (!isAlias || len(targets) == 0) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteIndex(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	var targets []string
	if strings.ContainsAny(rawIndex, "*,") || rawIndex == "_all" {
		targets = s.resolveTargetIndices(rawIndex)
	} else {
		targets = []string{s.resolveIndexName(rawIndex)}
	}

	modifiedAliases := make(map[string][]string)
	var tablesToDrop []*schema.IndexSchema
	s.mu.Lock()
	for _, indexName := range targets {
		if idx, ok := s.indices[indexName]; ok {
			tablesToDrop = append(tablesToDrop, idx)
		}
		delete(s.indices, indexName)
		for alias := range s.aliases {
			s.removeAliasTargetLocked(alias, indexName)
			modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
		}
	}
	s.mu.Unlock()
	for _, indexName := range targets {
		s.deleteCatalogEntity(r.Context(), "index", indexName)
	}
	for alias, aliasTargets := range modifiedAliases {
		s.persistAlias(r.Context(), alias, aliasTargets)
	}

	for _, idx := range tablesToDrop {
		ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
		_ = s.backend.ExecDDL(r.Context(), ddl)
	}
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetAllMappings(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any, len(s.indices))
	for indexName, idx := range s.indices {
		props := map[string]esast.FieldProperty{}
		if idx.RawMapping != nil {
			props = idx.RawMapping.Properties
		}
		out[indexName] = map[string]any{
			"mappings": map[string]any{"properties": props},
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetMapping(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	if strings.ContainsAny(rawIndex, "*,") || rawIndex == "_all" {
		targets := s.resolveTargetIndices(rawIndex)
		s.mu.RLock()
		out := make(map[string]any, len(targets))
		for _, indexName := range targets {
			if idx, ok := s.indices[indexName]; ok {
				props := map[string]esast.FieldProperty{}
				if idx.RawMapping != nil {
					props = idx.RawMapping.Properties
				}
				out[indexName] = map[string]any{
					"mappings": map[string]any{"properties": props},
				}
			}
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, out)
		return
	}
	indexName := s.resolveIndexName(rawIndex)
	s.mu.RLock()
	idx, ok := s.indices[indexName]
	s.mu.RUnlock()
	if !ok {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+indexName+"]")
		return
	}
	props := map[string]esast.FieldProperty{}
	if idx.RawMapping != nil {
		props = idx.RawMapping.Properties
	}
	writeJSON(w, http.StatusOK, map[string]any{
		indexName: map[string]any{
			"mappings": map[string]any{"properties": props},
		},
	})
}

func (s *Server) handleGetFieldMapping(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	rawFields := r.PathValue("fields")
	if rawFields == "" {
		rawFields = "*"
	}
	fieldPatterns := strings.Split(rawFields, ",")

	s.mu.RLock()
	out := make(map[string]any, len(targets))
	for _, idxName := range targets {
		idxSchema, ok := s.indices[idxName]
		if !ok {
			continue
		}
		mappingsOut := make(map[string]any)
		for esPath, fb := range idxSchema.Fields {
			if !matchesAnyGlob(esPath, fieldPatterns) {
				continue
			}
			esType := "keyword"
			switch fb.DorisType {
			case schema.DorisBigInt:
				if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
					esType = "date"
				} else {
					esType = "long"
				}
			case schema.DorisDouble:
				esType = "double"
			case schema.DorisBoolean:
				esType = "boolean"
			case schema.DorisString:
				esType = "text"
			}
			lastSeg := esPath
			if dot := strings.LastIndexByte(esPath, '.'); dot >= 0 {
				lastSeg = esPath[dot+1:]
			}
			mappingsOut[esPath] = map[string]any{
				"full_name": esPath,
				"mapping": map[string]any{
					lastSeg: map[string]any{"type": esType},
				},
			}
		}
		if matchesAnyGlob("@timestamp", fieldPatterns) && mappingsOut["@timestamp"] == nil {
			mappingsOut["@timestamp"] = map[string]any{
				"full_name": "@timestamp",
				"mapping": map[string]any{
					"@timestamp": map[string]any{"type": "date"},
				},
			}
		}
		out[idxName] = map[string]any{"mappings": mappingsOut}
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutMapping(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}
	var spec esast.MappingSpec
	if err := json.Unmarshal(bodyBytes, &spec); err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}
	if len(spec.Properties) == 0 {
		var envelope struct {
			Mappings *esast.MappingSpec `json:"mappings"`
		}
		if err := json.Unmarshal(bodyBytes, &envelope); err == nil && envelope.Mappings != nil {
			spec = *envelope.Mappings
		}
	}

	s.mu.Lock()
	oldSchema := s.indices[indexName]
	var oldRaw *esast.MappingSpec
	if oldSchema != nil {
		oldRaw = oldSchema.RawMapping
	}
	mergedSpec := schema.MergeMappingSpecs(oldRaw, &spec)
	newSchema := schema.CompileIndexSchema(s.dorisDB, indexName, mergedSpec)
	s.indices[indexName] = newSchema
	s.mu.Unlock()
	s.persistIndex(r.Context(), indexName, newSchema)

	if oldSchema == nil {
		ddl := schema.GenerateCreateTableDDL(newSchema)
		if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
			return
		}
	} else {
		for _, stmt := range schema.GenerateAlterTableDDL(oldSchema, newSchema) {
			if err := s.backend.ExecDDL(r.Context(), stmt); err != nil {
				writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
				return
			}
		}
		s.backfillIndexSchema(r.Context(), newSchema)
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetAliases(w http.ResponseWriter, r *http.Request) {
	aliasFilter := r.PathValue("name")
	s.mu.RLock()
	defer s.mu.RUnlock()

	if aliasFilter != "" && aliasFilter != "*" && aliasFilter != "_all" {
		out := make(map[string]any)
		for alias, targets := range s.aliases {
			if matchWildcardPattern(aliasFilter, alias) {
				for _, idxName := range targets {
					if _, exists := s.indices[idxName]; exists {
						entry, ok := out[idxName].(map[string]any)
						if !ok {
							entry = map[string]any{"aliases": map[string]any{}}
							out[idxName] = entry
						}
						entry["aliases"].(map[string]any)[alias] = map[string]any{}
					}
				}
			}
		}
		if len(out) == 0 {
			writeESError(w, http.StatusNotFound, "alias_not_found_exception", "aliases ["+aliasFilter+"] missing")
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	out := make(map[string]any)
	for idxName := range s.indices {
		idxAliases := make(map[string]any)
		for alias, targets := range s.aliases {
			for _, t := range targets {
				if t == idxName {
					idxAliases[alias] = map[string]any{}
				}
			}
		}
		out[idxName] = map[string]any{"aliases": idxAliases}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetIndexAliases(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	s.mu.RLock()
	_, ok := s.indices[indexName]
	if !ok {
		s.mu.RUnlock()
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+indexName+"]")
		return
	}
	idxAliases := make(map[string]any)
	for alias, targets := range s.aliases {
		for _, t := range targets {
			if t == indexName {
				idxAliases[alias] = map[string]any{}
			}
		}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		indexName: map[string]any{"aliases": idxAliases},
	})
}

func (s *Server) handleIndexAliasByName(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	aliasName := r.PathValue("name")
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		s.mu.Lock()
		s.addAliasLocked(aliasName, indexName)
		targets := append([]string(nil), s.aliases[aliasName]...)
		s.mu.Unlock()
		s.persistAlias(r.Context(), aliasName, targets)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		s.mu.Lock()
		s.removeAliasTargetLocked(aliasName, indexName)
		targets := append([]string(nil), s.aliases[aliasName]...)
		s.mu.Unlock()
		s.persistAlias(r.Context(), aliasName, targets)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet:
		s.mu.RLock()
		targets := s.aliases[aliasName]
		found := false
		for _, t := range targets {
			if t == indexName {
				found = true
				break
			}
		}
		s.mu.RUnlock()
		if !found {
			writeESError(w, http.StatusNotFound, "alias_not_found_exception", "aliases ["+aliasName+"] missing")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			indexName: map[string]any{
				"aliases": map[string]any{aliasName: map[string]any{}},
			},
		})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) handleUpdateAliases(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Actions []map[string]struct {
			Index   string   `json:"index"`
			Indices []string `json:"indices"`
			Alias   string   `json:"alias"`
			Aliases []string `json:"aliases"`
		} `json:"actions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	modifiedAliases := make(map[string][]string)
	s.mu.Lock()
	for _, action := range payload.Actions {
		if add, ok := action["add"]; ok {
			indices := add.Indices
			if add.Index != "" {
				indices = append(indices, add.Index)
			}
			aliases := add.Aliases
			if add.Alias != "" {
				aliases = append(aliases, add.Alias)
			}
			for _, al := range aliases {
				for _, idx := range indices {
					s.addAliasLocked(al, idx)
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		}
		if rem, ok := action["remove"]; ok {
			indices := rem.Indices
			if rem.Index != "" {
				indices = append(indices, rem.Index)
			}
			aliases := rem.Aliases
			if rem.Alias != "" {
				aliases = append(aliases, rem.Alias)
			}
			for _, al := range aliases {
				for _, idx := range indices {
					if idx == "*" || idx == "_all" {
						delete(s.aliases, al)
					} else {
						s.removeAliasTargetLocked(al, idx)
					}
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		}
	}
	s.mu.Unlock()
	for al, targets := range modifiedAliases {
		s.persistAlias(r.Context(), al, targets)
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) addAliasLocked(alias, indexName string) {
	existing := s.aliases[alias]
	for _, t := range existing {
		if t == indexName {
			return
		}
	}
	s.aliases[alias] = append(existing, indexName)
}

func (s *Server) removeAliasTargetLocked(alias, indexName string) {
	existing := s.aliases[alias]
	if len(existing) == 0 {
		return
	}
	var filtered []string
	for _, t := range existing {
		if !matchWildcardPattern(indexName, t) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) == 0 {
		delete(s.aliases, alias)
	} else {
		s.aliases[alias] = filtered
	}
}

func (s *Server) handlePutDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	isCreate := strings.Contains(r.URL.Path, "/_create/") || strings.EqualFold(r.URL.Query().Get("op_type"), "create")
	if docID == "" {
		docID = esast.NextAutoID()
	}
	rawDoc, err := io.ReadAll(r.Body)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}
	docPayload := s.applyIngestPipelineIfPresent(r.URL.Query().Get("pipeline"), json.RawMessage(rawDoc))

	idxSchema := s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, []json.RawMessage{docPayload})
	if isCreate {
		if _, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID); err == nil && found {
			writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document already exists", docID))
			return
		}
	}
	nextVer := time.Now().UnixNano()
	shredded, err := schema.ShredDocument(idxSchema, docID, nextVer, false, docPayload)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.streamLoad(r.Context(), idxSchema.DorisTable, append(shredded, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      1,
		"result":        "created",
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       nextVer,
		"_primary_term": 1,
	})
}

func (s *Server) handleHeadDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	_, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil || !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetSource(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if !found {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", "document missing")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/vnd.elasticsearch+json") {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- Content-Type is application/json with X-Content-Type-Options: nosniff
	_, _ = w.Write(hit.Source)
}

func (s *Server) handleGetDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"_index": indexName,
			"_type":  "_doc",
			"_id":    docID,
			"found":  false,
		})
		return
	}
	resp := map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      hit.ID,
		"_version": hit.Version,
		"found":    true,
		"_source":  hit.Source,
	}
	if r.URL.Query().Get("_source") == "false" {
		delete(resp, "_source")
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMGet(w http.ResponseWriter, r *http.Request) {
	defaultIndex := s.resolveIndexName(r.PathValue("index"))
	var body struct {
		IDs  []string `json:"ids"`
		Docs []struct {
			Index  string              `json:"_index"`
			ID     string              `json:"_id"`
			Source *esast.SourceFilter `json:"_source,omitempty"`
		} `json:"docs"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	for _, id := range body.IDs {
		body.Docs = append(body.Docs, struct {
			Index  string              `json:"_index"`
			ID     string              `json:"_id"`
			Source *esast.SourceFilter `json:"_source,omitempty"`
		}{Index: defaultIndex, ID: id})
	}

	idsByIndex := make(map[string][]string)
	for _, spec := range body.Docs {
		idxName := defaultIndex
		if spec.Index != "" {
			idxName = s.resolveIndexName(spec.Index)
		}
		idsByIndex[idxName] = append(idsByIndex[idxName], spec.ID)
	}

	prefetched := make(map[string]map[string]HitRow, len(idsByIndex))
	for idxName, ids := range idsByIndex {
		idxSchema := s.ensureIndexSchema(r.Context(), idxName)
		if m, err := s.backend.GetDocsByIDs(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, ids); err == nil {
			prefetched[idxName] = m
		}
	}

	docsOut := make([]map[string]any, 0, len(body.Docs))
	for _, spec := range body.Docs {
		idxName := defaultIndex
		if spec.Index != "" {
			idxName = s.resolveIndexName(spec.Index)
		}
		hit, found := prefetched[idxName][spec.ID]
		if !found {
			docsOut = append(docsOut, map[string]any{
				"_index": idxName,
				"_type":  "_doc",
				"_id":    spec.ID,
				"found":  false,
			})
			continue
		}
		docItem := map[string]any{
			"_index":   idxName,
			"_type":    "_doc",
			"_id":      hit.ID,
			"_version": hit.Version,
			"found":    true,
		}
		if spec.Source == nil || !spec.Source.Disabled {
			docItem["_source"] = filterSourceJSON(hit.Source, spec.Source)
		}
		docsOut = append(docsOut, docItem)
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

func (s *Server) handleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	tombstone, err := schema.ShredDocument(idxSchema, docID, time.Now().UnixNano(), true, nil)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "internal_exception", err.Error())
		return
	}
	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.streamLoad(r.Context(), idxSchema.DorisTable, append(tombstone, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      2,
		"result":        "deleted",
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       2,
		"_primary_term": 1,
	})
}

func (s *Server) handleUpdateDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")

	var updReq painless.UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updReq); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}

	roSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	existingHit, found, err := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if !found && !updReq.DocAsUpsert && updReq.Upsert == nil && !updReq.ScriptedUpsert {
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}

	var baseSource json.RawMessage
	nextVersion := time.Now().UnixNano()
	if found {
		baseSource = existingHit.Source
		nextVersion = existingHit.Version + 1
	}

	mutatedSource, opResult, err := painless.ApplyUpdateWithResult(baseSource, &updReq, found)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
		return
	}

	if opResult != "noop" {
		isDelete := opResult == "deleted"
		var sampleDocs []json.RawMessage
		if !isDelete && len(mutatedSource) > 0 {
			sampleDocs = []json.RawMessage{mutatedSource}
		}
		idxSchema := s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, sampleDocs)
		shredded, err := schema.ShredDocument(idxSchema, docID, nextVersion, isDelete, mutatedSource)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
		syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
		if err := s.streamLoad(r.Context(), idxSchema.DorisTable, append(shredded, '\n'), syncRefresh); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      nextVersion,
		"result":        opResult,
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       nextVersion,
		"_primary_term": 1,
	})
}

func (s *Server) handleUpdateByQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	targets := s.resolveTargetIndices(r.PathValue("index"))
	if len(targets) == 0 {
		targets = []string{s.resolveIndexName(r.PathValue("index"))}
	}

	var body struct {
		MaxDocs *int                 `json:"max_docs,omitempty"`
		Query   *esast.Query         `json:"query,omitempty"`
		Script  *painless.ScriptSpec `json:"script,omitempty"`
	}
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
	}

	maxDocs := 0
	if body.MaxDocs != nil && *body.MaxDocs > 0 {
		maxDocs = *body.MaxDocs
	}
	if qMax := r.URL.Query().Get("max_docs"); qMax != "" {
		if parsed, err := strconv.Atoi(qMax); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	}

	totalMatched := 0
	totalUpdated := 0
	totalDeleted := 0
	batches := 0
	updSpec := &painless.UpdateRequest{Script: body.Script}

	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(r.Context(), indexName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any

		for {
			fetchSize := 1000
			if maxDocs > 0 && totalMatched+fetchSize > maxDocs {
				fetchSize = maxDocs - totalMatched
			}
			if fetchSize <= 0 {
				break
			}
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Query:       body.Query,
				Size:        &fetchSize,
				Sort:        esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter: searchAfter,
			})
			if err != nil {
				writeESError(w, http.StatusBadRequest, "query_shard_exception", err.Error())
				return
			}

			hits, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
			if err != nil {
				writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
				return
			}
			if len(hits) == 0 {
				break
			}
			batches++
			totalMatched += len(hits)

			var batchBuf bytes.Buffer
			for _, h := range hits {
				mutated, opRes, err := painless.ApplyUpdateWithResult(h.Source, updSpec, true)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
					return
				}
				if opRes == "noop" {
					continue
				}
				isDel := opRes == "deleted"
				shredded, err := schema.ShredDocument(idxSchema, h.ID, h.Version+1, isDel, mutated)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
					return
				}
				batchBuf.Write(shredded)
				batchBuf.WriteByte('\n')
				if isDel {
					totalDeleted++
				} else {
					totalUpdated++
				}
			}

			if batchBuf.Len() > 0 {
				if err := s.streamLoad(r.Context(), idxSchema.DorisTable, batchBuf.Bytes(), true); err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
					return
				}
			}
			searchAfter = []any{hits[len(hits)-1].ID}
			if len(hits) < fetchSize || (maxDocs > 0 && totalMatched >= maxDocs) {
				break
			}
		}
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":              tookMs,
		"timed_out":         false,
		"total":             totalMatched,
		"updated":           totalUpdated,
		"deleted":           totalDeleted,
		"batches":           batches,
		"version_conflicts": 0,
		"noops":             totalMatched - totalUpdated - totalDeleted,
		"failures":          []any{},
	})
}

func (s *Server) handleDeleteByQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	targets := s.resolveTargetIndices(r.PathValue("index"))
	if len(targets) == 0 {
		targets = []string{s.resolveIndexName(r.PathValue("index"))}
	}

	var body struct {
		MaxDocs *int         `json:"max_docs,omitempty"`
		Query   *esast.Query `json:"query,omitempty"`
	}
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
				return
			}
		}
	}

	maxDocs := 0
	if body.MaxDocs != nil && *body.MaxDocs > 0 {
		maxDocs = *body.MaxDocs
	}
	if qMax := r.URL.Query().Get("max_docs"); qMax != "" {
		if parsed, err := strconv.Atoi(qMax); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	}

	totalDeleted := 0
	batches := 0
	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(r.Context(), indexName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any

		for {
			fetchSize := 1000
			if maxDocs > 0 && totalDeleted+fetchSize > maxDocs {
				fetchSize = maxDocs - totalDeleted
			}
			if fetchSize <= 0 {
				break
			}
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Query:       body.Query,
				Size:        &fetchSize,
				Sort:        esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter: searchAfter,
			})
			if err != nil {
				writeESError(w, http.StatusBadRequest, "query_shard_exception", err.Error())
				return
			}

			hits, err := s.backend.QueryHits(r.Context(), plan.HitsSQL)
			if err != nil {
				writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
				return
			}
			if len(hits) == 0 {
				break
			}
			batches++

			var batchBuf bytes.Buffer
			for _, h := range hits {
				tombstone, err := schema.ShredDocument(idxSchema, h.ID, h.Version+1, true, nil)
				if err != nil {
					continue
				}
				batchBuf.Write(tombstone)
				batchBuf.WriteByte('\n')
				totalDeleted++
			}
			if batchBuf.Len() > 0 {
				if err := s.streamLoad(r.Context(), idxSchema.DorisTable, batchBuf.Bytes(), true); err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
					return
				}
			}
			searchAfter = []any{hits[len(hits)-1].ID}
			if len(hits) < fetchSize || (maxDocs > 0 && totalDeleted >= maxDocs) {
				break
			}
		}
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":              tookMs,
		"timed_out":         false,
		"total":             totalDeleted,
		"deleted":           totalDeleted,
		"batches":           batches,
		"version_conflicts": 0,
		"failures":          []any{},
	})
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defaultIndex := s.resolveIndexName(r.PathValue("index"))
	ops, err := esast.ParseBulkNDJSON(r.Body, defaultIndex)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", err.Error())
		return
	}

	defaultPipeline := r.URL.Query().Get("pipeline")
	// Collect sample docs per target index for dynamic mapping inference on auto-created indices.
	sampleDocsByIndex := make(map[string][]json.RawMessage)
	idsToFetchByIndex := make(map[string][]string)
	for idx := range ops {
		op := &ops[idx]
		if op.ParseErr != "" {
			continue
		}
		if (op.Action == "index" || op.Action == "create") && len(op.Source) > 0 && defaultPipeline != "" {
			op.Source = s.applyIngestPipelineIfPresent(defaultPipeline, op.Source)
		}
		idxName := s.resolveIndexName(op.Index)
		if (op.Action == "index" || op.Action == "create") && len(op.Source) > 0 && len(sampleDocsByIndex[idxName]) < 16 {
			sampleDocsByIndex[idxName] = append(sampleDocsByIndex[idxName], op.Source)
		} else if op.Action == "update" && len(op.Source) > 0 && len(sampleDocsByIndex[idxName]) < 16 {
			var u painless.UpdateRequest
			if err := json.Unmarshal(op.Source, &u); err == nil {
				if len(u.Doc) > 0 {
					if rawDoc, err := json.Marshal(u.Doc); err == nil {
						sampleDocsByIndex[idxName] = append(sampleDocsByIndex[idxName], rawDoc)
					}
				}
				if len(u.Upsert) > 0 {
					if rawUpsert, err := json.Marshal(u.Upsert); err == nil {
						sampleDocsByIndex[idxName] = append(sampleDocsByIndex[idxName], rawUpsert)
					}
				}
			}
		}
		if (op.Action == "update" || op.Action == "create") && op.ID != "" {
			idsToFetchByIndex[idxName] = append(idsToFetchByIndex[idxName], op.ID)
		}
	}
	for idxName, samples := range sampleDocsByIndex {
		_ = s.ensureWritableIndexSchemaWithDocs(r.Context(), idxName, samples)
	}
	existingByIndex := make(map[string]map[string]HitRow, len(idsToFetchByIndex))
	for idxName, ids := range idsToFetchByIndex {
		idxSchema := s.ensureIndexSchema(r.Context(), idxName)
		if m, err := s.backend.GetDocsByIDs(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, ids); err == nil {
			existingByIndex[idxName] = m
		}
	}

	byIndex := make(map[string]*bytes.Buffer)
	var items []map[string]any
	hasErrors := false
	seqBase := time.Now().UnixNano()

	for i, op := range ops {
		targetIndex := s.resolveIndexName(op.Index)
		if op.ParseErr != "" {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": "mapper_parsing_exception", "reason": op.ParseErr},
				},
			})
			continue
		}

		idxSchema := s.ensureIndexSchema(r.Context(), targetIndex)
		buf, ok := byIndex[idxSchema.DorisTable]
		if !ok {
			buf = &bytes.Buffer{}
			byIndex[idxSchema.DorisTable] = buf
		}

		if op.Action == "create" {
			if _, exists := existingByIndex[targetIndex][op.ID]; exists {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusConflict,
						"error":  map[string]any{"type": "version_conflict_engine_exception", "reason": fmt.Sprintf("[%s]: version conflict, document already exists", op.ID)},
					},
				})
				continue
			}
		}

		deleted := op.Action == "delete"
		sourceToShred := op.Source
		nextVer := seqBase + int64(i)

		if op.Action == "update" {
			var upd painless.UpdateRequest
			if err := json.Unmarshal(op.Source, &upd); err != nil {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusBadRequest,
						"error":  map[string]any{"type": "mapper_parsing_exception", "reason": err.Error()},
					},
				})
				continue
			}
			existingHit, found := existingByIndex[targetIndex][op.ID]
			if !found && !upd.DocAsUpsert && len(upd.Upsert) == 0 && !upd.ScriptedUpsert {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusNotFound,
						"error":  map[string]any{"type": "document_missing_exception", "reason": fmt.Sprintf("[%s]: document missing", op.ID)},
					},
				})
				continue
			}
			var baseSrc json.RawMessage
			if found {
				baseSrc = existingHit.Source
				if existingHit.Version+1 > nextVer {
					nextVer = existingHit.Version + 1
				}
			}
			merged, opRes, err := painless.ApplyUpdateWithResult(baseSrc, &upd, found)
			if err != nil {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusBadRequest,
						"error":  map[string]any{"type": "script_exception", "reason": err.Error()},
					},
				})
				continue
			}
			if opRes == "noop" {
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index":   targetIndex,
						"_type":    "_doc",
						"_id":      op.ID,
						"_version": existingHit.Version,
						"result":   "noop",
						"status":   http.StatusOK,
					},
				})
				continue
			}
			sourceToShred = merged
			if opRes == "deleted" {
				deleted = true
			}
		}

		shredded, err := schema.ShredDocument(idxSchema, op.ID, nextVer, deleted, sourceToShred)
		if err != nil {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": "mapper_parsing_exception", "reason": err.Error()},
				},
			})
			continue
		}
		buf.Write(shredded)
		buf.WriteByte('\n')

		if existingByIndex[targetIndex] == nil {
			existingByIndex[targetIndex] = make(map[string]HitRow)
		}
		if deleted {
			delete(existingByIndex[targetIndex], op.ID)
		} else {
			existingByIndex[targetIndex][op.ID] = HitRow{ID: op.ID, Version: nextVer, Source: sourceToShred}
		}

		status := http.StatusCreated
		result := "created"
		if deleted {
			status = http.StatusOK
			result = "deleted"
		} else if op.Action == "update" {
			status = http.StatusOK
			result = "updated"
		}
		items = append(items, map[string]any{
			op.Action: map[string]any{
				"_index":        targetIndex,
				"_type":         "_doc",
				"_id":           op.ID,
				"_version":      1,
				"result":        result,
				"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
				"_seq_no":       nextVer,
				"_primary_term": 1,
				"status":        status,
			},
		})
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	for dorisTable, buf := range byIndex {
		if buf.Len() == 0 {
			continue
		}
		if err := s.streamLoad(r.Context(), dorisTable, buf.Bytes(), syncRefresh); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":   tookMs,
		"errors": hasErrors,
		"items":  items,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req esast.SearchRequest
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
	}
	applyURISearchParams(r, &req)
	if r.URL.Query().Get("scroll") != "" {
		hasIDSort := false
		for _, sp := range req.Sort {
			if sp.Entry.Field == "_id" || sp.Entry.Field == "_doc" {
				hasIDSort = true
				break
			}
		}
		if !hasIDSort {
			req.Sort = append(req.Sort, esast.SortSpec{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}})
		}
	}

	rawIndex := r.PathValue("index")
	if rawIndex == "" && req.PIT != nil && req.PIT.ID != "" {
		if pitIdx, ok := decodePITIndex(req.PIT.ID); ok {
			rawIndex = pitIdx
		}
	}
	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), rawIndex, &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	if req.PIT != nil && req.PIT.ID != "" {
		resp["pit_id"] = req.PIT.ID
	}
	tookMs, _ := toInt64(resp["took"])
	syncShadow := r.URL.Query().Get("shadow_sync") == "true" || r.URL.Query().Get("shadow_sync") == "1"
	s.maybeRunShadowSearch(rawIndex, bodyBytes, resp, tookMs, syncShadow)

	if r.URL.Query().Get("scroll") != "" {
		scrollID := "doris-scroll-eof"
		if hitsWrapper, ok := resp["hits"].(map[string]any); ok {
			if hitList, ok := hitsWrapper["hits"].([]map[string]any); ok && len(hitList) > 0 {
				if lastSort, ok := hitList[len(hitList)-1]["sort"].([]any); ok && len(lastSort) > 0 {
					scrollID = encodeScrollCursor(rawIndex, &req, lastSort)
				}
			}
		}
		resp["_scroll_id"] = scrollID
	}
	if r.URL.Query().Get("doris_explain") == "true" || r.URL.Query().Get("doris_explain") == "1" {
		resp["_doris_explain"] = s.buildDorisExplainObject(r.Context(), rawIndex, &req)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDorisExplain(w http.ResponseWriter, r *http.Request) {
	var req esast.SearchRequest
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
	}
	applyURISearchParams(r, &req)
	writeJSON(w, http.StatusOK, s.buildDorisExplainObject(r.Context(), r.PathValue("index"), &req))
}

func (s *Server) handleDorisDDL(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	ddl := schema.GenerateCreateTableDDL(idxSchema)
	if r.URL.Query().Get("format") == "txt" || r.URL.Query().Get("format") == "sql" {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		// #nosec G705 -- Content-Type is text/plain with X-Content-Type-Options: nosniff
		_, _ = w.Write([]byte(ddl + "\n"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"index":            indexName,
		"doris_database":   idxSchema.DorisDB,
		"doris_table":      idxSchema.DorisTable,
		"create_table_ddl": ddl,
	})
}

func (s *Server) buildDorisExplainObject(ctx context.Context, rawIndexPattern string, req *esast.SearchRequest) map[string]any {
	targets := s.resolveTargetIndices(rawIndexPattern)
	if len(targets) == 0 {
		targets = []string{s.resolveIndexName(rawIndexPattern)}
	}
	var plans []map[string]any
	for _, indexName := range targets {
		idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		plan, err := tr.BuildSearchPlan(req)
		fieldBindings := make(map[string]any, len(idxSchema.Fields))
		for esPath, fb := range idxSchema.Fields {
			fieldBindings[esPath] = map[string]any{
				"column":            fb.ColumnName,
				"doris_type":        fb.DorisType,
				"keyword_companion": fb.KeywordCompanion,
				"prefilter_array":   fb.PrefilterArrayCol,
				"nested_path":       fb.NestedPath,
			}
		}
		entry := map[string]any{
			"index":                    indexName,
			"doris_database":           idxSchema.DorisDB,
			"doris_table":              idxSchema.DorisTable,
			"create_table_ddl":         schema.GenerateCreateTableDDL(idxSchema),
			"hits_sql":                 plan.HitsSQL,
			"aggs_sql":                 plan.AggsSQL,
			"field_bindings":           fieldBindings,
			"unindexed_variant_fields": plan.UnindexedVariantFields,
		}
		if err != nil {
			entry["error"] = err.Error()
		}
		plans = append(plans, entry)
	}
	out := map[string]any{
		"resolved_indices": targets,
		"doris_database":   s.dorisDB,
		"plans":            plans,
	}
	if len(plans) == 1 {
		out["hits_sql"] = plans[0]["hits_sql"]
		out["aggs_sql"] = plans[0]["aggs_sql"]
		out["create_table_ddl"] = plans[0]["create_table_ddl"]
		out["doris_table"] = plans[0]["doris_table"]
		out["unindexed_variant_fields"] = plans[0]["unindexed_variant_fields"]
	}
	return out
}

func (s *Server) handleFieldCaps(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	var filterPatterns []string
	if fieldsFilter := r.URL.Query().Get("fields"); fieldsFilter != "" {
		filterPatterns = append(filterPatterns, strings.Split(fieldsFilter, ",")...)
	}
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var body struct {
				Fields []string `json:"fields"`
			}
			if err := json.Unmarshal(bodyBytes, &body); err == nil && len(body.Fields) > 0 {
				if len(filterPatterns) == 1 && filterPatterns[0] == "*" {
					filterPatterns = body.Fields
				} else {
					filterPatterns = append(filterPatterns, body.Fields...)
				}
			}
		}
	}
	if len(filterPatterns) == 0 {
		filterPatterns = []string{"*"}
	}

	caps := make(map[string]map[string]map[string]any)
	addCap := func(field, esType string, searchable, aggregatable bool) {
		if !matchesAnyGlob(field, filterPatterns) {
			return
		}
		if caps[field] == nil {
			caps[field] = make(map[string]map[string]any)
		}
		caps[field][esType] = map[string]any{
			"type":         esType,
			"searchable":   searchable,
			"aggregatable": aggregatable,
		}
	}

	addCap("_id", "_id", true, true)
	addCap("_index", "_index", true, true)
	addCap("@timestamp", "date", true, true)

	s.mu.RLock()
	for _, idxName := range targets {
		idxSchema, ok := s.indices[idxName]
		if !ok {
			continue
		}
		for esPath, fb := range idxSchema.Fields {
			switch fb.DorisType {
			case schema.DorisBigInt:
				if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
					addCap(esPath, "date", true, true)
				} else {
					addCap(esPath, "long", true, true)
				}
			case schema.DorisDouble:
				addCap(esPath, "double", true, true)
			case schema.DorisBoolean:
				addCap(esPath, "boolean", true, true)
			case schema.DorisString:
				addCap(esPath, "text", true, false)
				if fb.KeywordCompanion != "" {
					addCap(esPath+".keyword", "keyword", true, true)
				}
			default:
				addCap(esPath, "keyword", true, true)
			}
		}
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"indices": targets,
		"fields":  caps,
	})
}

func (s *Server) handleMSearch(w http.ResponseWriter, r *http.Request) {
	defaultIndex := r.PathValue("index")
	if r.Body == nil {
		writeJSON(w, http.StatusOK, map[string]any{"took": 1, "responses": []any{}})
		return
	}
	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)

	responses := make([]map[string]any, 0)
	for {
		var headerLine []byte
		for scanner.Scan() {
			trimmed := bytes.TrimSpace(scanner.Bytes())
			if len(trimmed) > 0 {
				headerLine = append([]byte(nil), trimmed...)
				break
			}
		}
		if len(headerLine) == 0 {
			break
		}
		var bodyLine []byte
		if scanner.Scan() {
			bodyLine = append([]byte(nil), bytes.TrimSpace(scanner.Bytes())...)
		}

		var hdr struct {
			Index   any `json:"index"`
			Indices any `json:"indices"`
		}
		_ = json.Unmarshal(headerLine, &hdr)
		targetIdx := defaultIndex
		idxField := hdr.Index
		if idxField == nil {
			idxField = hdr.Indices
		}
		switch v := idxField.(type) {
		case string:
			if v != "" {
				targetIdx = v
			}
		case []any:
			var parts []string
			for _, item := range v {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			if len(parts) > 0 {
				targetIdx = strings.Join(parts, ",")
			}
		}

		var req esast.SearchRequest
		if len(bodyLine) > 0 {
			if err := json.Unmarshal(bodyLine, &req); err != nil {
				responses = append(responses, map[string]any{
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": "parsing_exception", "reason": err.Error()},
				})
				continue
			}
		}

		resp, status, errType, errReason := s.executeSearchRequest(r.Context(), targetIdx, &req)
		if errType != "" {
			responses = append(responses, map[string]any{
				"status": status,
				"error":  map[string]any{"type": errType, "reason": errReason},
			})
			continue
		}
		responses = append(responses, resp)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"took":      4,
		"responses": responses,
	})
}

func (s *Server) executeSearchRequest(
	ctx context.Context,
	rawIndexPattern string,
	req *esast.SearchRequest,
) (map[string]any, int, string, string) {
	start := time.Now()
	targets := s.resolveTargetIndices(rawIndexPattern)
	if len(targets) == 0 {
		// If wildcard pattern matched nothing, return empty 200 search response (like ES with allow_no_indices=true)
		if strings.Contains(rawIndexPattern, "*") || rawIndexPattern == "_all" {
			return buildESResponse(rawIndexPattern, nil, req, nil, nil, 1, nil), http.StatusOK, "", ""
		}
		targets = []string{s.resolveIndexName(rawIndexPattern)}
	}

	if cachedResp, hit := s.queryCache.Get(targets, req); hit {
		return cachedResp, http.StatusOK, "", ""
	}

	from := 0
	if req.From != nil && *req.From > 0 {
		from = *req.From
	}
	size := 10
	if req.Size != nil {
		size = *req.Size
	}

	var allHits []HitRow
	var allAggRows []AggRow
	var totalHitsSum int64
	var primarySchema *schema.IndexSchema

	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(ctx, indexName)
		if primarySchema == nil {
			primarySchema = idxSchema
		}
		subReq := *req
		if len(targets) > 1 && size > 0 {
			zero := 0
			fetchSize := from + size
			subReq.From = &zero
			subReq.Size = &fetchSize
		}

		idxStart := time.Now()
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		plan, err := tr.BuildSearchPlan(&subReq)
		if err != nil {
			return nil, http.StatusBadRequest, "search_phase_execution_exception", err.Error()
		}

		var (
			hits    []HitRow
			aggRows []AggRow
			hitsErr error
			aggsErr error
		)
		if plan.HitsSQL != "" && plan.AggsSQL != "" {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				hits, hitsErr = s.backend.QueryHits(ctx, plan.HitsSQL)
			}()
			go func() {
				defer wg.Done()
				aggRows, aggsErr = s.backend.QueryAggs(ctx, plan.AggsSQL)
			}()
			wg.Wait()
		} else if plan.HitsSQL != "" {
			hits, hitsErr = s.backend.QueryHits(ctx, plan.HitsSQL)
		} else if plan.AggsSQL != "" {
			aggRows, aggsErr = s.backend.QueryAggs(ctx, plan.AggsSQL)
		}

		if hitsErr != nil {
			return nil, http.StatusInternalServerError, "doris_query_exception", hitsErr.Error()
		}
		if aggsErr != nil {
			return nil, http.StatusInternalServerError, "doris_aggs_exception", aggsErr.Error()
		}

		var idxTotal int64
		for i := range hits {
			hits[i].Index = indexName
			if hits[i].TotalHits > idxTotal {
				idxTotal = hits[i].TotalHits
			}
		}
		if len(hits) == 0 && from > 0 && plan.AggsSQL == "" {
			zero := 0
			cntReq := subReq
			cntReq.From = &zero
			cntReq.Size = &zero
			if cntPlan, err := tr.BuildSearchPlan(&cntReq); err == nil && cntPlan.AggsSQL != "" {
				if cntRows, err := s.backend.QueryAggs(ctx, cntPlan.AggsSQL); err == nil {
					for _, cr := range cntRows {
						if cr.AggName == "__meta_total" {
							idxTotal = cr.effectiveCount()
						}
					}
				}
			}
		}
		allHits = append(allHits, hits...)

		for _, r := range aggRows {
			if r.AggName == "__meta_total" && idxTotal == 0 {
				idxTotal = r.effectiveCount()
			}
		}
		if len(targets) > 1 && idxTotal == 0 && req.PostFilter == nil {
			for _, r := range aggRows {
				if r.AggName == "__meta_total" {
					allAggRows = append(allAggRows, r)
				}
			}
		} else {
			allAggRows = append(allAggRows, aggRows...)
		}

		idxTookMs := time.Since(idxStart).Milliseconds()
		if idxTookMs <= 0 {
			idxTookMs = 1
		}
		threshold := s.getAutoPromoteThreshold()
		toPromote := s.slowTracker.recordWithThreshold(SlowQueryEntry{
			Timestamp:              time.Now().UTC().Format(time.RFC3339),
			Index:                  indexName,
			TookMs:                 idxTookMs,
			TotalHits:              idxTotal,
			HitsSQL:                plan.HitsSQL,
			AggsSQL:                plan.AggsSQL,
			UnindexedVariantFields: plan.UnindexedVariantFields,
		}, threshold)
		for _, fieldToPromote := range toPromote {
			_, _ = s.promoteFieldInternal(ctx, indexName, fieldToPromote, "keyword")
		}
		totalHitsSum += idxTotal
	}

	if len(targets) > 1 {
		sort.SliceStable(allHits, func(i, j int) bool {
			if len(req.Sort) > 0 {
				if cmp := compareHitRowsBySort(allHits[i], allHits[j], req.Sort, primarySchema); cmp != 0 {
					return cmp < 0
				}
			}
			if allHits[i].Score != allHits[j].Score {
				return allHits[i].Score > allHits[j].Score
			}
			return allHits[i].ID < allHits[j].ID
		})
		if from >= len(allHits) {
			allHits = nil
		} else {
			end := from + size
			if end > len(allHits) {
				end = len(allHits)
			}
			allHits = allHits[from:end]
		}
		for i := range allHits {
			allHits[i].TotalHits = totalHitsSum
		}
		allAggRows = mergeMultiIndexAggRows(allAggRows, totalHitsSum, req.EffectiveAggs())
	}

	if len(allHits) == 0 && totalHitsSum > 0 {
		hasMeta := false
		for _, r := range allAggRows {
			if r.AggName == "__meta_total" {
				hasMeta = true
				break
			}
		}
		if !hasMeta {
			allAggRows = append(allAggRows, AggRow{
				AggName:   "__meta_total",
				BucketKey: "_count",
				DocCount:  totalHitsSum,
				Value:     float64(totalHitsSum),
			})
		}
	}

	tookMs := time.Since(start).Milliseconds()
	if tookMs <= 0 {
		tookMs = 1
	}
	primaryIndex := targets[0]
	docLookup := func(id string) *HitRow {
		for i := range allHits {
			if allHits[i].ID == id {
				return &allHits[i]
			}
		}
		for _, tName := range targets {
			tSchema := s.getOrCompileReadOnlySchema(ctx, tName)
			if tSchema != nil {
				if h, found, err := s.backend.GetDocByID(ctx, tSchema.DorisDB, tSchema.DorisTable, id); err == nil && found {
					h.Index = tName
					return h
				}
			}
		}
		return nil
	}
	resp := buildESResponse(primaryIndex, primarySchema, req, allHits, allAggRows, tookMs, docLookup)
	s.queryCache.Put(targets, req, resp)
	return resp, http.StatusOK, "", ""
}

func compareHitRowsBySort(a, b HitRow, sorts []esast.SortSpec, idxSchema *schema.IndexSchema) int {
	valsA := extractHitSortValues(a, sorts, idxSchema)
	valsB := extractHitSortValues(b, sorts, idxSchema)
	for idx, s := range sorts {
		if idx >= len(valsA) || idx >= len(valsB) {
			break
		}
		va, vb := valsA[idx], valsB[idx]
		if va == nil && vb == nil {
			continue
		}
		if va == nil {
			return 1
		}
		if vb == nil {
			return -1
		}
		cmp := compareAny(va, vb)
		if cmp == 0 {
			continue
		}
		if strings.EqualFold(s.Entry.Order, "desc") {
			return -cmp
		}
		return cmp
	}
	return 0
}

func resolveAggSpecByPath(aggs map[string]esast.AggSpec, fullAggName string) esast.AggSpec {
	if len(aggs) == 0 || fullAggName == "" {
		return esast.AggSpec{}
	}
	if spec, ok := aggs[fullAggName]; ok {
		return spec
	}
	parts := strings.Split(fullAggName, ".")
	currMap := aggs
	var spec esast.AggSpec
	for i, part := range parts {
		s, ok := currMap[part]
		if !ok {
			return esast.AggSpec{}
		}
		spec = s
		if i < len(parts)-1 {
			currMap = spec.SubAggs()
		}
	}
	return spec
}

func mergeMultiIndexAggRows(rows []AggRow, totalHits int64, aggs map[string]esast.AggSpec) []AggRow {
	type key struct {
		agg    string
		bucket string
	}
	type mergeAcc struct {
		row   AggRow
		count int
	}
	merged := make(map[key]*mergeAcc)
	var order []key
	for _, r := range rows {
		if r.AggName == "__meta_total" {
			continue
		}
		k := key{agg: r.AggName, bucket: r.BucketKey}
		if existing, ok := merged[k]; ok {
			existing.count++
			spec := resolveAggSpecByPath(aggs, r.AggName)
			val := r.effectiveValue()
			switch {
			case r.BucketKey == "_stats_min" || spec.Min != nil:
				if val < existing.row.Value {
					existing.row.Value = val
					existing.row.DocCount = int64(val)
				}
			case r.BucketKey == "_stats_max" || spec.Max != nil:
				if val > existing.row.Value {
					existing.row.Value = val
					existing.row.DocCount = int64(val)
				}
			default:
				existing.row.DocCount += r.effectiveCount()
				existing.row.Value += val
			}
		} else {
			cp := r
			cp.DocCount = r.effectiveCount()
			cp.Value = r.effectiveValue()
			merged[k] = &mergeAcc{row: cp, count: 1}
			order = append(order, k)
		}
	}
	out := []AggRow{{AggName: "__meta_total", BucketKey: "_count", DocCount: totalHits, Value: float64(totalHits)}}
	for _, k := range order {
		acc := merged[k]
		spec := resolveAggSpecByPath(aggs, k.agg)
		if (k.bucket == "_stats_avg" || spec.Avg != nil || spec.Percentiles != nil) && acc.count > 1 {
			acc.row.Value /= float64(acc.count)
			acc.row.DocCount = int64(acc.row.Value)
		}
		out = append(out, acc.row)
	}
	return out
}

func (s *Server) handleCount(w http.ResponseWriter, r *http.Request) {
	var req esast.SearchRequest
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
	}
	applyURISearchParams(r, &req)
	zero := 0
	req.Size = &zero

	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), r.PathValue("index"), &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	var count int64
	if hitsObj, ok := resp["hits"].(map[string]any); ok {
		if totalObj, ok := hitsObj["total"].(map[string]any); ok {
			if v, ok := totalObj["value"].(int64); ok {
				count = v
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   count,
		"_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
	})
}

func applyURISearchParams(r *http.Request, req *esast.SearchRequest) {
	q := r.URL.Query()
	if qStr := q.Get("q"); qStr != "" && req.Query == nil {
		req.Query = &esast.Query{
			QueryString: &esast.QueryStringQuery{
				Query:           qStr,
				DefaultField:    q.Get("df"),
				DefaultOperator: q.Get("default_operator"),
			},
		}
	}
	if sizeStr := q.Get("size"); sizeStr != "" {
		if sz, err := strconv.Atoi(sizeStr); err == nil {
			req.Size = &sz
		}
	}
	if fromStr := q.Get("from"); fromStr != "" {
		if fr, err := strconv.Atoi(fromStr); err == nil {
			req.From = &fr
		}
	}
	if sortParam := q.Get("sort"); sortParam != "" && len(req.Sort) == 0 {
		for _, part := range strings.Split(sortParam, ",") {
			field := part
			order := "asc"
			if idx := strings.IndexByte(part, ':'); idx > 0 {
				field = part[:idx]
				order = part[idx+1:]
			}
			req.Sort = append(req.Sort, esast.SortSpec{
				Entry: esast.SortEntry{Field: field, Order: order},
			})
		}
	}
	if srcParam := q.Get("_source"); srcParam != "" && req.Source == nil {
		if srcParam == "false" {
			req.Source = &esast.SourceFilter{Disabled: true}
		} else if srcParam != "true" {
			req.Source = &esast.SourceFilter{Includes: strings.Split(srcParam, ",")}
		}
	}
	if inc := q.Get("_source_includes"); inc != "" {
		if req.Source == nil {
			req.Source = &esast.SourceFilter{}
		}
		req.Source.Includes = append(req.Source.Includes, strings.Split(inc, ",")...)
	}
	if exc := q.Get("_source_excludes"); exc != "" {
		if req.Source == nil {
			req.Source = &esast.SourceFilter{}
		}
		req.Source.Excludes = append(req.Source.Excludes, strings.Split(exc, ",")...)
	}
}

func buildESResponse(indexName string, idxSchema *schema.IndexSchema, req *esast.SearchRequest, hits []HitRow, aggRows []AggRow, tookMs int64, docLookup func(string) *HitRow) map[string]any {
	var totalHits int64
	var maxScore float64
	esHits := make([]map[string]any, 0, len(hits))
	if tookMs <= 0 {
		tookMs = 1
	}

	for _, h := range hits {
		if h.TotalHits > totalHits {
			totalHits = h.TotalHits
		}
		if h.Score > maxScore {
			maxScore = h.Score
		}
		hitIdx := h.Index
		if hitIdx == "" {
			hitIdx = indexName
		}
		hitMap := map[string]any{
			"_index": hitIdx,
			"_type":  "_doc",
			"_id":    h.ID,
			"_score": h.Score,
		}
		if req.Source == nil || !req.Source.Disabled {
			hitMap["_source"] = filterSourceJSON(h.Source, req.Source)
		}
		if req.Highlight != nil && len(req.Highlight.Fields) > 0 {
			if hl := buildHighlightMap(h.Source, req); len(hl) > 0 {
				hitMap["highlight"] = hl
			}
		}
		if len(req.Sort) > 0 {
			hitMap["sort"] = extractHitSortValues(h, req.Sort, idxSchema)
		}
		if len(req.Fields) > 0 || len(req.DocvalueFields) > 0 {
			if fm := extractHitFieldsMap(h, hitIdx, req, idxSchema); len(fm) > 0 {
				hitMap["fields"] = fm
			}
		}
		esHits = append(esHits, hitMap)
	}

	bucketsByAgg := make(map[string][]AggRow)
	for _, row := range aggRows {
		if row.AggName == "__meta_total" {
			if totalHits == 0 {
				totalHits = row.effectiveCount()
			}
			continue
		}
		bucketsByAgg[row.AggName] = append(bucketsByAgg[row.AggName], row)
	}

	aggsOut := buildAggsMap(indexName, "", req.EffectiveAggs(), bucketsByAgg, totalHits, docLookup)

	res := map[string]any{
		"took":      tookMs,
		"timed_out": false,
		"_shards":   map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
		"hits": map[string]any{
			"total": map[string]any{
				"value":    totalHits,
				"relation": "eq",
			},
			"max_score": maxScore,
			"hits":      esHits,
		},
	}
	if len(aggsOut) > 0 {
		res["aggregations"] = aggsOut
	}
	return res
}

func buildAggsMap(
	indexName string,
	prefix string,
	aggs map[string]esast.AggSpec,
	bucketsByAgg map[string][]AggRow,
	totalHits int64,
	docLookup func(string) *HitRow,
) map[string]any {
	aggsOut := make(map[string]any)
	for aggName, spec := range aggs {
		fullKey := aggName
		if prefix != "" {
			fullKey = prefix + "." + aggName
		}
		rows := bucketsByAgg[fullKey]
		switch {
		case spec.Terms != nil:
			if len(rows) > 1 {
				sort.SliceStable(rows, func(i, j int) bool {
					ci, cj := rows[i].effectiveCount(), rows[j].effectiveCount()
					if ci != cj {
						return ci > cj
					}
					return rows[i].BucketKey < rows[j].BucketKey
				})
			}
			limit := spec.Terms.Size
			if limit <= 0 {
				limit = 10
			}
			if len(rows) > limit {
				rows = rows[:limit]
			}
			b := make([]map[string]any, 0, len(rows))
			subAggs := spec.SubAggs()
			for _, r := range rows {
				bucketMap := map[string]any{
					"key":       r.BucketKey,
					"doc_count": r.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup)
				}
				b = append(b, bucketMap)
			}
			aggsOut[aggName] = map[string]any{
				"doc_count_error_upper_bound": 0,
				"sum_other_doc_count":         0,
				"buckets":                     b,
			}
		case spec.Nested != nil:
			nestedObj := map[string]any{"doc_count": totalHits}
			for subName, subSpec := range spec.SubAggs() {
				subRows := append([]AggRow(nil), bucketsByAgg[fullKey+"."+subName]...)
				if subSpec.Terms != nil {
					if len(subRows) > 1 {
						sort.SliceStable(subRows, func(i, j int) bool {
							ci, cj := subRows[i].effectiveCount(), subRows[j].effectiveCount()
							if ci != cj {
								return ci > cj
							}
							return subRows[i].BucketKey < subRows[j].BucketKey
						})
					}
					limit := subSpec.Terms.Size
					if limit <= 0 {
						limit = 10
					}
					if len(subRows) > limit {
						subRows = subRows[:limit]
					}
					b := make([]map[string]any, 0, len(subRows))
					for _, r := range subRows {
						b = append(b, map[string]any{
							"key":       r.BucketKey,
							"doc_count": r.effectiveCount(),
						})
					}
					nestedObj[subName] = map[string]any{
						"doc_count_error_upper_bound": 0,
						"sum_other_doc_count":         0,
						"buckets":                     b,
					}
				}
			}
			aggsOut[aggName] = nestedObj
		case spec.Filter != nil || spec.Missing != nil:
			var cnt int64
			if len(rows) > 0 {
				cnt = rows[0].effectiveCount()
			}
			filterObj := map[string]any{"doc_count": cnt}
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				for sk, sv := range buildAggsMap(indexName, fullKey, subAggs, bucketsByAgg, cnt, docLookup) {
					filterObj[sk] = sv
				}
			}
			aggsOut[aggName] = filterObj
		case spec.Filters != nil:
			byKey := make(map[string]int64, len(rows))
			for _, r := range rows {
				byKey[r.BucketKey] = r.effectiveCount()
			}
			bucketsMap := make(map[string]any, len(spec.Filters.Filters))
			subAggs := spec.SubAggs()
			for fk := range spec.Filters.Filters {
				bMap := map[string]any{
					"doc_count": byKey[fk],
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bMap, fullKey, fk, subAggs, bucketsByAgg, docLookup)
				}
				bucketsMap[fk] = bMap
			}
			aggsOut[aggName] = map[string]any{"buckets": bucketsMap}
		case spec.Cardinality != nil || spec.ValueCount != nil:
			var cnt int64
			if len(rows) > 0 {
				cnt = rows[0].effectiveCount()
			}
			aggsOut[aggName] = map[string]any{"value": cnt}
		case spec.Avg != nil || spec.Sum != nil || spec.Min != nil || spec.Max != nil:
			var val float64
			if len(rows) > 0 {
				val = rows[0].effectiveValue()
			}
			aggsOut[aggName] = map[string]any{"value": val}
		case spec.Stats != nil:
			statsMap := map[string]any{
				"count": int64(0),
				"min":   0.0,
				"max":   0.0,
				"avg":   0.0,
				"sum":   0.0,
			}
			var cntVal int64
			var sumVal float64
			var hasSum bool
			for _, r := range rows {
				switch r.BucketKey {
				case "_stats_count":
					cntVal = r.effectiveCount()
					statsMap["count"] = cntVal
				case "_stats_min":
					statsMap["min"] = r.effectiveValue()
				case "_stats_max":
					statsMap["max"] = r.effectiveValue()
				case "_stats_avg":
					statsMap["avg"] = r.effectiveValue()
				case "_stats_sum":
					sumVal = r.effectiveValue()
					hasSum = true
					statsMap["sum"] = sumVal
				}
			}
			if cntVal > 0 && hasSum {
				statsMap["avg"] = sumVal / float64(cntVal)
			}
			aggsOut[aggName] = statsMap
		case spec.Percentiles != nil:
			valuesMap := make(map[string]float64, len(rows))
			for _, r := range rows {
				valuesMap[r.BucketKey] = r.effectiveValue()
			}
			aggsOut[aggName] = map[string]any{"values": valuesMap}
		case spec.DateHistogram != nil:
			if len(rows) > 1 {
				sort.SliceStable(rows, func(i, j int) bool {
					ki, _ := strconv.ParseInt(rows[i].BucketKey, 10, 64)
					kj, _ := strconv.ParseInt(rows[j].BucketKey, 10, 64)
					return ki < kj
				})
			}
			b := make([]map[string]any, 0, len(rows))
			subAggs := spec.SubAggs()
			for _, r := range rows {
				epochMs, _ := strconv.ParseInt(r.BucketKey, 10, 64)
				keyStr := time.UnixMilli(epochMs).UTC().Format("2006-01-02T15:04:05.000Z")
				bucketMap := map[string]any{
					"key_as_string": keyStr,
					"key":           epochMs,
					"doc_count":     r.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup)
				}
				b = append(b, bucketMap)
			}
			aggsOut[aggName] = map[string]any{"buckets": b}
		case spec.Histogram != nil:
			if len(rows) > 1 {
				sort.SliceStable(rows, func(i, j int) bool {
					ki, _ := strconv.ParseFloat(rows[i].BucketKey, 64)
					kj, _ := strconv.ParseFloat(rows[j].BucketKey, 64)
					return ki < kj
				})
			}
			b := make([]map[string]any, 0, len(rows))
			subAggs := spec.SubAggs()
			for _, r := range rows {
				numKey, _ := strconv.ParseFloat(r.BucketKey, 64)
				bucketMap := map[string]any{
					"key":       numKey,
					"doc_count": r.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup)
				}
				b = append(b, bucketMap)
			}
			aggsOut[aggName] = map[string]any{"buckets": b}
		case spec.Range != nil || spec.DateRange != nil:
			rngSpec := spec.Range
			if rngSpec == nil {
				rngSpec = spec.DateRange
			}
			byKey := make(map[string]int64, len(rows))
			for _, r := range rows {
				byKey[r.BucketKey] = r.effectiveCount()
			}
			b := make([]map[string]any, 0, len(rngSpec.Ranges))
			subAggs := spec.SubAggs()
			for _, rng := range rngSpec.Ranges {
				ek := rng.EffectiveKey()
				entry := map[string]any{
					"key":       ek,
					"doc_count": byKey[ek],
				}
				if rng.From != nil {
					entry["from"] = rng.From
				}
				if rng.To != nil {
					entry["to"] = rng.To
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, entry, fullKey, ek, subAggs, bucketsByAgg, docLookup)
				}
				b = append(b, entry)
			}
			aggsOut[aggName] = map[string]any{"buckets": b}
		case spec.TopHits != nil:
			topHitsList := buildTopHitsList(indexName, rows, spec.TopHits, docLookup)
			aggsOut[aggName] = map[string]any{
				"hits": map[string]any{
					"total":     map[string]any{"value": len(topHitsList), "relation": "eq"},
					"max_score": 1.0,
					"hits":      topHitsList,
				},
			}
		case spec.Composite != nil:
			if len(rows) > 1 {
				sort.SliceStable(rows, func(i, j int) bool {
					return rows[i].BucketKey < rows[j].BucketKey
				})
			}
			compLimit := spec.Composite.Size
			if compLimit <= 0 {
				compLimit = 10
			}
			if len(rows) > compLimit {
				rows = rows[:compLimit]
			}
			var srcNames []string
			for _, srcMap := range spec.Composite.Sources {
				var ks []string
				for k := range srcMap {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				srcNames = append(srcNames, ks...)
			}
			buckets := make([]map[string]any, 0, len(rows))
			var afterKey map[string]any
			for _, r := range rows {
				parts := splitCompositeBucketKey(r.BucketKey)
				keyObj := make(map[string]any, len(srcNames))
				for i, sn := range srcNames {
					if i < len(parts) {
						keyObj[sn] = parts[i]
					}
				}
				afterKey = keyObj
				buckets = append(buckets, map[string]any{
					"key":       keyObj,
					"doc_count": r.effectiveCount(),
				})
			}
			compObj := map[string]any{"buckets": buckets}
			if afterKey != nil {
				compObj["after_key"] = afterKey
			}
			aggsOut[aggName] = compObj
		}
	}
	return aggsOut
}

func splitCompositeBucketKey(s string) []string {
	if strings.Contains(s, "\x1f") {
		return strings.Split(s, "\x1f")
	}
	if strings.Contains(s, "\\x1f") {
		return strings.Split(s, "\\x1f")
	}
	if strings.Contains(s, "x1f") {
		return strings.Split(s, "x1f")
	}
	return []string{s}
}

func trimSubAggBucketPrefix(bucketKey, parentBucketKey string) (string, bool) {
	for _, sep := range []string{"\x1f", "\\x1f", "x1f"} {
		prefix := parentBucketKey + sep
		if strings.HasPrefix(bucketKey, prefix) {
			return strings.TrimPrefix(bucketKey, prefix), true
		}
	}
	return "", false
}

func buildTopHitsList(
	defaultIndex string,
	rows []AggRow,
	spec *esast.TopHitsAggSpec,
	docLookup func(string) *HitRow,
) []map[string]any {
	limit := spec.EffectiveSize()
	type candidate struct {
		docID string
		hit   *HitRow
	}
	candidates := make([]candidate, 0, len(rows))
	for _, r := range rows {
		var h *HitRow
		if docLookup != nil {
			h = docLookup(r.BucketKey)
		}
		candidates = append(candidates, candidate{docID: r.BucketKey, hit: h})
	}
	if len(candidates) > 1 && len(spec.Sort) > 0 {
		sort.SliceStable(candidates, func(i, j int) bool {
			var ha, hb HitRow
			ha.ID = candidates[i].docID
			hb.ID = candidates[j].docID
			if candidates[i].hit != nil {
				ha = *candidates[i].hit
			}
			if candidates[j].hit != nil {
				hb = *candidates[j].hit
			}
			if cmp := compareHitRowsBySort(ha, hb, spec.Sort, nil); cmp != 0 {
				return cmp < 0
			}
			return ha.ID < hb.ID
		})
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	topHitsList := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		hitIdx := defaultIndex
		if c.hit != nil && c.hit.Index != "" {
			hitIdx = c.hit.Index
		}
		hitMap := map[string]any{
			"_index": hitIdx,
			"_type":  "_doc",
			"_id":    c.docID,
			"_score": 1.0,
		}
		if c.hit != nil {
			if spec.Source == nil || !spec.Source.Disabled {
				hitMap["_source"] = filterSourceJSON(c.hit.Source, spec.Source)
			}
		}
		topHitsList = append(topHitsList, hitMap)
	}
	return topHitsList
}

func attachSubAggsToBucket(
	indexName string,
	bucketMap map[string]any,
	parentFullKey string,
	parentBucketKey string,
	subAggs map[string]esast.AggSpec,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
) {
	for subName, subSpec := range subAggs {
		subFullKey := parentFullKey + "." + subName
		subRows := bucketsByAgg[subFullKey]
		switch {
		case subSpec.Cardinality != nil || subSpec.ValueCount != nil:
			var cnt int64
			for _, r := range subRows {
				if r.BucketKey == parentBucketKey {
					cnt = r.effectiveCount()
					break
				}
			}
			bucketMap[subName] = map[string]any{"value": cnt}
		case subSpec.Avg != nil || subSpec.Sum != nil || subSpec.Min != nil || subSpec.Max != nil:
			var val float64
			for _, r := range subRows {
				if r.BucketKey == parentBucketKey {
					val = r.effectiveValue()
					break
				}
			}
			bucketMap[subName] = map[string]any{"value": val}
		case subSpec.Terms != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			if len(matchingRows) > 1 {
				sort.SliceStable(matchingRows, func(i, j int) bool {
					ci, cj := matchingRows[i].effectiveCount(), matchingRows[j].effectiveCount()
					if ci != cj {
						return ci > cj
					}
					return matchingRows[i].BucketKey < matchingRows[j].BucketKey
				})
			}
			limit := subSpec.Terms.Size
			if limit <= 0 {
				limit = 10
			}
			if len(matchingRows) > limit {
				matchingRows = matchingRows[:limit]
			}
			childBuckets := make([]map[string]any, 0, len(matchingRows))
			for _, r := range matchingRows {
				childBuckets = append(childBuckets, map[string]any{
					"key":       r.BucketKey,
					"doc_count": r.effectiveCount(),
				})
			}
			bucketMap[subName] = map[string]any{
				"doc_count_error_upper_bound": 0,
				"sum_other_doc_count":         0,
				"buckets":                     childBuckets,
			}
		case subSpec.TopHits != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if docID, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = docID
					matchingRows = append(matchingRows, cp)
				}
			}
			topHitsList := buildTopHitsList(indexName, matchingRows, subSpec.TopHits, docLookup)
			bucketMap[subName] = map[string]any{
				"hits": map[string]any{
					"total":     map[string]any{"value": len(topHitsList), "relation": "eq"},
					"max_score": 1.0,
					"hits":      topHitsList,
				},
			}
		}
	}
}

func extractHitFieldsMap(h HitRow, hitIdx string, req *esast.SearchRequest, idxSchema *schema.IndexSchema) map[string][]any {
	specs := req.EffectiveFieldSpecs()
	if len(specs) == 0 {
		return nil
	}
	var doc map[string]any
	if len(h.Source) > 0 {
		dec := json.NewDecoder(bytes.NewReader(h.Source))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	out := make(map[string][]any)
	var allLeafScalars map[string][]any
	for _, spec := range specs {
		if spec.Field == "" {
			continue
		}
		switch spec.Field {
		case "_id":
			out["_id"] = []any{h.ID}
			continue
		case "_index":
			out["_index"] = []any{hitIdx}
			continue
		}
		cleanField := strings.TrimSuffix(strings.TrimSuffix(spec.Field, ".keyword"), ".ngram")
		if strings.Contains(cleanField, "*") {
			if allLeafScalars == nil {
				allLeafScalars = make(map[string][]any)
				collectAllLeafScalarPaths(doc, "", allLeafScalars)
			}
			for leafPath, vals := range allLeafScalars {
				if matchWildcardPattern(cleanField, leafPath) && len(vals) > 0 {
					out[leafPath] = formatFieldValues(leafPath, vals, spec.Format, idxSchema)
				}
			}
			continue
		}
		pathSegs := strings.Split(cleanField, ".")
		if idxSchema != nil {
			b := idxSchema.ResolveField(spec.Field)
			if len(b.SourceJSONPath) > 0 {
				pathSegs = b.SourceJSONPath
			}
		}
		vals := collectScalarValuesAtPath(doc, pathSegs)
		if len(vals) > 0 {
			out[spec.Field] = formatFieldValues(cleanField, vals, spec.Format, idxSchema)
		}
	}
	return out
}

func formatFieldValues(field string, vals []any, format string, idxSchema *schema.IndexSchema) []any {
	formatted := make([]any, 0, len(vals))
	for _, v := range vals {
		if jsonNum, ok := v.(json.Number); ok {
			if iv, err := jsonNum.Int64(); err == nil {
				v = iv
			} else if fv, err := jsonNum.Float64(); err == nil {
				v = fv
			}
		}
		if strVal, ok := v.(string); ok {
			if strings.EqualFold(format, "epoch_millis") {
				if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
					v = ms
				}
			} else if idxSchema != nil {
				b := idxSchema.ResolveField(field)
				if b.LowercaseNormalizer {
					v = strings.ToLower(strVal)
				}
			}
		}
		formatted = append(formatted, v)
	}
	return formatted
}

func collectAllLeafScalarPaths(node any, prefix string, out map[string][]any) {
	switch curr := node.(type) {
	case map[string]any:
		for k, v := range curr {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			collectAllLeafScalarPaths(v, full, out)
		}
	case []any:
		for _, item := range curr {
			collectAllLeafScalarPaths(item, prefix, out)
		}
	case nil:
	default:
		if prefix != "" {
			out[prefix] = append(out[prefix], curr)
		}
	}
}

func collectScalarValuesAtPath(node any, path []string) []any {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case map[string]any:
			return nil
		case []any:
			var res []any
			for _, item := range v {
				res = append(res, collectScalarValuesAtPath(item, nil)...)
			}
			return res
		default:
			return []any{v}
		}
	}
	switch curr := node.(type) {
	case map[string]any:
		return collectScalarValuesAtPath(curr[path[0]], path[1:])
	case []any:
		var res []any
		for _, item := range curr {
			res = append(res, collectScalarValuesAtPath(item, path)...)
		}
		return res
	}
	return nil
}

func extractHitSortValues(h HitRow, sorts []esast.SortSpec, idxSchema *schema.IndexSchema) []any {
	var doc map[string]any
	if len(h.Source) > 0 {
		dec := json.NewDecoder(bytes.NewReader(h.Source))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	out := make([]any, 0, len(sorts))
	for _, s := range sorts {
		switch s.Entry.Field {
		case "_score":
			out = append(out, h.Score)
		case "_id", "_doc":
			out = append(out, h.ID)
		default:
			cleanField := strings.TrimSuffix(strings.TrimSuffix(s.Entry.Field, ".keyword"), ".ngram")
			pathSegs := strings.Split(cleanField, ".")
			if idxSchema != nil {
				b := idxSchema.ResolveField(s.Entry.Field)
				if len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			val := lookupDocPath(doc, pathSegs)
			if jsonNum, ok := val.(json.Number); ok {
				if iv, err := jsonNum.Int64(); err == nil {
					val = iv
				} else if fv, err := jsonNum.Float64(); err == nil {
					val = fv
				}
			}
			if idxSchema != nil {
				b := idxSchema.ResolveField(s.Entry.Field)
				if strVal, ok := val.(string); ok {
					if b.LowercaseNormalizer {
						val = strings.ToLower(strVal)
					} else if b.DorisType == schema.DorisBigInt {
						if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
							val = ms
						}
					}
				}
			}
			out = append(out, val)
		}
	}
	return out
}

func lookupDocPath(node any, path []string) any {
	if node == nil || len(path) == 0 {
		return node
	}
	switch typed := node.(type) {
	case map[string]any:
		return lookupDocPath(typed[path[0]], path[1:])
	case []any:
		for _, elem := range typed {
			if v := lookupDocPath(elem, path); v != nil {
				return v
			}
		}
	}
	return nil
}

func filterSourceJSON(raw json.RawMessage, sf *esast.SourceFilter) json.RawMessage {
	if sf == nil || (len(sf.Includes) == 0 && len(sf.Excludes) == 0) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return raw
	}
	filtered := filterMapByPaths(doc, "", sf.Includes, sf.Excludes)
	out, err := json.Marshal(filtered)
	if err != nil {
		return raw
	}
	return json.RawMessage(out)
}

func filterMapByPaths(m map[string]any, prefix string, includes, excludes []string) map[string]any {
	out := make(map[string]any)
	for k, v := range m {
		fullPath := k
		if prefix != "" {
			fullPath = prefix + "." + k
		}
		if matchesAnyGlob(fullPath, excludes) {
			continue
		}
		if len(includes) > 0 {
			exactOrParentMatch := matchesAnyGlob(fullPath, includes)
			hasChildInclude := false
			for _, inc := range includes {
				if strings.HasPrefix(inc, fullPath+".") {
					hasChildInclude = true
					break
				}
			}
			if !exactOrParentMatch && !hasChildInclude {
				continue
			}
			if !exactOrParentMatch && hasChildInclude {
				if subMap, ok := v.(map[string]any); ok {
					out[k] = filterMapByPaths(subMap, fullPath, includes, excludes)
					continue
				}
				if subSlice, ok := v.([]any); ok {
					var newSlice []any
					for _, elem := range subSlice {
						if elemMap, ok := elem.(map[string]any); ok {
							newSlice = append(newSlice, filterMapByPaths(elemMap, fullPath, includes, excludes))
						} else {
							newSlice = append(newSlice, elem)
						}
					}
					out[k] = newSlice
					continue
				}
			}
		}
		if subMap, ok := v.(map[string]any); ok && len(excludes) > 0 {
			out[k] = filterMapByPaths(subMap, fullPath, nil, excludes)
			continue
		}
		out[k] = v
	}
	return out
}

func matchesAnyGlob(path string, patterns []string) bool {
	for _, pat := range patterns {
		if matchWildcardPattern(pat, path) {
			return true
		}
	}
	return false
}

func buildHighlightMap(raw json.RawMessage, req *esast.SearchRequest) map[string][]string {
	if req == nil || req.Highlight == nil || len(req.Highlight.Fields) == 0 {
		return nil
	}
	terms := extractQueryTerms(req.Query)
	if len(terms) == 0 {
		return nil
	}
	var quotedTerms []string
	seenTerms := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		term = strings.Trim(term, "*?\"")
		if len(term) == 0 {
			continue
		}
		lc := strings.ToLower(term)
		if _, exists := seenTerms[lc]; exists {
			continue
		}
		seenTerms[lc] = struct{}{}
		quotedTerms = append(quotedTerms, regexp.QuoteMeta(term))
	}
	if len(quotedTerms) == 0 {
		return nil
	}
	sort.SliceStable(quotedTerms, func(i, j int) bool {
		return len(quotedTerms[i]) > len(quotedTerms[j])
	})
	combinedRegex, err := regexp.Compile("(?i)(" + strings.Join(quotedTerms, "|") + ")")
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	preTag := "<em>"
	postTag := "</em>"
	if len(req.Highlight.PreTags) > 0 && req.Highlight.PreTags[0] != "" {
		preTag = req.Highlight.PreTags[0]
	}
	if len(req.Highlight.PostTags) > 0 && req.Highlight.PostTags[0] != "" {
		postTag = req.Highlight.PostTags[0]
	}

	out := make(map[string][]string)
	var allLeafPaths map[string][]string
	for field := range req.Highlight.Fields {
		cleanField := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
		if strings.Contains(cleanField, "*") {
			if allLeafPaths == nil {
				allLeafPaths = make(map[string][]string)
				collectAllLeafStringPaths(doc, "", allLeafPaths)
			}
			for leafPath, vals := range allLeafPaths {
				if matchWildcardPattern(cleanField, leafPath) {
					for _, v := range vals {
						highlighted, matched := highlightWithCombinedRegex(v, combinedRegex, preTag, postTag)
						if matched {
							out[leafPath] = append(out[leafPath], highlighted)
						}
					}
				}
			}
			continue
		}
		vals := collectStringValuesAtPath(doc, strings.Split(cleanField, "."))
		for _, v := range vals {
			highlighted, matched := highlightWithCombinedRegex(v, combinedRegex, preTag, postTag)
			if matched {
				out[field] = append(out[field], highlighted)
			}
		}
	}
	return out
}

func collectAllLeafStringPaths(node any, prefix string, out map[string][]string) {
	switch curr := node.(type) {
	case map[string]any:
		for k, v := range curr {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			collectAllLeafStringPaths(v, full, out)
		}
	case []any:
		for _, item := range curr {
			collectAllLeafStringPaths(item, prefix, out)
		}
	case string:
		if prefix != "" {
			out[prefix] = append(out[prefix], curr)
		}
	}
}

func collectStringValuesAtPath(node any, path []string) []string {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case string:
			return []string{v}
		case []any:
			var res []string
			for _, item := range v {
				res = append(res, collectStringValuesAtPath(item, nil)...)
			}
			return res
		}
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		return collectStringValuesAtPath(curr[path[0]], path[1:])
	case []any:
		var res []string
		for _, item := range curr {
			res = append(res, collectStringValuesAtPath(item, path)...)
		}
		return res
	}
	return nil
}

func highlightWithCombinedRegex(text string, re *regexp.Regexp, preTag, postTag string) (string, bool) {
	if re == nil || !re.MatchString(text) {
		return text, false
	}
	result := re.ReplaceAllStringFunc(text, func(m string) string {
		return preTag + m + postTag
	})
	return result, true
}

func extractQueryTerms(q *esast.Query) []string {
	var out []string
	collectTermsFromQuery(q, &out)
	return out
}

func collectTermsFromQuery(q *esast.Query, out *[]string) {
	if q == nil {
		return
	}
	for _, te := range q.Term {
		if s := strings.TrimSpace(fmt.Sprintf("%v", te.Value)); s != "" {
			*out = append(*out, s)
		}
	}
	if q.Terms != nil {
		for _, vals := range q.Terms.Fields {
			for _, v := range vals {
				if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
					*out = append(*out, s)
				}
			}
		}
	}
	for _, me := range q.Match {
		*out = append(*out, strings.Fields(fmt.Sprintf("%v", me.Query))...)
	}
	for _, pe := range q.MatchPhrase {
		if pe.Query != "" {
			*out = append(*out, pe.Query)
		}
	}
	for _, pe := range q.MatchPhrasePrefix {
		if pe.Query != "" {
			*out = append(*out, pe.Query)
		}
	}
	for _, pe := range q.MatchBoolPrefix {
		if pe.Query != "" {
			*out = append(*out, strings.Fields(pe.Query)...)
		}
	}
	if q.MultiMatch != nil && q.MultiMatch.Query != nil {
		*out = append(*out, strings.Fields(fmt.Sprintf("%v", q.MultiMatch.Query))...)
	}
	if q.QueryString != nil && q.QueryString.Query != "" {
		for _, tok := range strings.Fields(q.QueryString.Query) {
			if idx := strings.IndexByte(tok, ':'); idx >= 0 {
				tok = tok[idx+1:]
			}
			tok = strings.Trim(tok, "()*?\"+-")
			upper := strings.ToUpper(tok)
			if tok != "" && upper != "AND" && upper != "OR" && upper != "NOT" {
				*out = append(*out, tok)
			}
		}
	}
	if q.SimpleQueryString != nil && q.SimpleQueryString.Query != "" {
		*out = append(*out, strings.Fields(q.SimpleQueryString.Query)...)
	}
	for _, we := range q.Wildcard {
		if cleaned := strings.Trim(we.Value, "*?"); cleaned != "" {
			*out = append(*out, cleaned)
		}
	}
	for _, pe := range q.Prefix {
		if pe.Value != "" {
			*out = append(*out, pe.Value)
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectTermsFromQuery(&q.Bool.Must[i], out)
		}
		for i := range q.Bool.Should {
			collectTermsFromQuery(&q.Bool.Should[i], out)
		}
		for i := range q.Bool.Filter {
			collectTermsFromQuery(&q.Bool.Filter[i], out)
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectTermsFromQuery(&q.DisMax.Queries[i], out)
		}
	}
	if q.Boosting != nil {
		collectTermsFromQuery(&q.Boosting.Positive, out)
	}
	if q.Nested != nil {
		collectTermsFromQuery(&q.Nested.Query, out)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectTermsFromQuery(q.FunctionScore.Query, out)
	}
	if q.ConstantScore != nil {
		collectTermsFromQuery(&q.ConstantScore.Filter, out)
	}
}

func (s *Server) resolveTargetIndices(pattern string) []string {
	out := s.resolveTargetIndicesOnce(pattern)
	if len(out) == 0 {
		_ = s.syncCatalogFromBackend(context.Background())
		out = s.resolveTargetIndicesOnce(pattern)
	}
	return out
}

func (s *Server) resolveTargetIndicesOnce(pattern string) []string {
	if pattern == "" || pattern == "_all" || pattern == "*" {
		s.mu.RLock()
		defer s.mu.RUnlock()
		var all []string
		for name := range s.indices {
			all = append(all, name)
		}
		sort.Strings(all)
		return all
	}

	parts := strings.Split(pattern, ",")
	seen := make(map[string]bool)
	var out []string
	var needsSync bool

	s.mu.RLock()
	addTarget := func(idx string) {
		if idx != "" && !seen[idx] {
			seen[idx] = true
			out = append(out, idx)
		}
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") {
			continue
		}
		if strings.Contains(part, "*") {
			matchedAny := false
			for idxName := range s.indices {
				if matchWildcardPattern(part, idxName) {
					addTarget(idxName)
					matchedAny = true
				}
			}
			for alias, targets := range s.aliases {
				if matchWildcardPattern(part, alias) {
					for _, t := range targets {
						addTarget(t)
						matchedAny = true
					}
				}
			}
			if !matchedAny {
				needsSync = true
			}
			continue
		}
		if targets, ok := s.aliases[part]; ok && len(targets) > 0 {
			for _, t := range targets {
				addTarget(t)
			}
			continue
		}
		if _, isKnownIndex := s.indices[part]; !isKnownIndex {
			needsSync = true
		}
		addTarget(part)
	}
	s.mu.RUnlock()

	if needsSync {
		_ = s.syncCatalogFromBackend(context.Background())
		seen = make(map[string]bool)
		out = nil
		s.mu.RLock()
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") {
				continue
			}
			if strings.Contains(part, "*") {
				for idxName := range s.indices {
					if matchWildcardPattern(part, idxName) {
						addTarget(idxName)
					}
				}
				for alias, targets := range s.aliases {
					if matchWildcardPattern(part, alias) {
						for _, t := range targets {
							addTarget(t)
						}
					}
				}
				continue
			}
			if targets, ok := s.aliases[part]; ok && len(targets) > 0 {
				for _, t := range targets {
					addTarget(t)
				}
				continue
			}
			addTarget(part)
		}
		s.mu.RUnlock()
	}

	sort.Strings(out)
	return out
}

func (s *Server) resolveIndexName(nameOrAlias string) string {
	if nameOrAlias == "" {
		return "default_index"
	}
	if idx := strings.IndexByte(nameOrAlias, ','); idx > 0 {
		nameOrAlias = nameOrAlias[:idx]
	}
	s.mu.RLock()
	if targets, ok := s.aliases[nameOrAlias]; ok && len(targets) > 0 {
		s.mu.RUnlock()
		return targets[0]
	}
	if _, ok := s.indices[nameOrAlias]; ok {
		s.mu.RUnlock()
		return nameOrAlias
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	if targets, ok := s.aliases[nameOrAlias]; ok && len(targets) > 0 {
		return targets[0]
	}
	return nameOrAlias
}

func (s *Server) getOrCompileReadOnlySchema(ctx context.Context, indexName string) *schema.IndexSchema {
	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	if idx, ok := s.indices[indexName]; ok {
		s.mu.RUnlock()
		return idx
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(ctx)

	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	if idx, ok := s.indices[indexName]; ok {
		s.mu.RUnlock()
		return idx
	}
	tplMappings := s.matchingTemplateMappingsLocked(indexName)
	s.mu.RUnlock()

	return schema.CompileIndexSchema(s.dorisDB, indexName, tplMappings)
}

func (s *Server) ensureWritableIndexSchema(ctx context.Context, indexName string) *schema.IndexSchema {
	return s.ensureWritableIndexSchemaWithDocs(ctx, indexName, nil)
}

func (s *Server) ensureIndexSchema(ctx context.Context, indexName string) *schema.IndexSchema {
	return s.ensureWritableIndexSchemaWithDocs(ctx, indexName, nil)
}

func (s *Server) ensureWritableIndexSchemaWithDocs(ctx context.Context, indexName string, sampleDocs []json.RawMessage) *schema.IndexSchema {
	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok := s.indices[indexName]
	if ok {
		if len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0 {
			s.mu.RUnlock()
			return idx
		}
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(ctx)

	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok = s.indices[indexName]
	if ok && (len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0) {
		s.mu.RUnlock()
		return idx
	}
	var existingEmptySchema *schema.IndexSchema
	if ok {
		existingEmptySchema = idx
	}
	tplMappings := s.matchingTemplateMappingsLocked(indexName)
	if existingEmptySchema != nil && existingEmptySchema.RawMapping != nil {
		tplMappings = schema.MergeMappingSpecs(tplMappings, existingEmptySchema.RawMapping)
	}
	s.mu.RUnlock()

	effectiveMappings := tplMappings
	if len(sampleDocs) > 0 && (tplMappings == nil || tplMappings.Dynamic == nil || tplMappings.Dynamic == true || tplMappings.Dynamic == "true") {
		inferred := schema.InferMappingFromSampleDocs(sampleDocs)
		effectiveMappings = schema.MergeMappingSpecs(inferred, tplMappings)
	}

	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
	_ = s.backend.ExecDDL(ctx, schema.GenerateCreateTableDDL(compiled))
	if existingEmptySchema != nil {
		for _, stmt := range schema.GenerateAlterTableDDL(existingEmptySchema, compiled) {
			_ = s.backend.ExecDDL(ctx, stmt)
		}
	}
	s.mu.Lock()
	if existing, exists := s.indices[indexName]; exists && (len(existing.Fields) > 0 || len(existing.NestedRoots) > 0) {
		s.mu.Unlock()
		return existing
	}
	s.indices[indexName] = compiled
	s.mu.Unlock()
	s.persistIndex(ctx, indexName, compiled)
	return compiled
}

func (s *Server) handlePIT(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		writeJSON(w, http.StatusOK, map[string]any{
			"succeeded": true,
			"num_freed": 1,
		})
		return
	}
	rawIndex := r.PathValue("index")
	pitID := base64.RawURLEncoding.EncodeToString([]byte("pit:" + rawIndex))
	writeJSON(w, http.StatusOK, map[string]any{
		"id": pitID,
	})
}

func decodePITIndex(pitID string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(pitID)
	if err != nil {
		return "", false
	}
	s := string(raw)
	if strings.HasPrefix(s, "pit:") {
		return strings.TrimPrefix(s, "pit:"), true
	}
	return "", false
}

func matchWildcardPattern(pattern, target string) bool {
	if pattern == "*" || pattern == "_all" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}
	pIdx, tIdx := 0, 0
	starIdx, matchIdx := -1, 0
	for tIdx < len(target) {
		if pIdx < len(pattern) && pattern[pIdx] == target[tIdx] {
			pIdx++
			tIdx++
		} else if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = tIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			tIdx = matchIdx
		} else {
			return false
		}
	}
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

func setESCompatHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Opaque-Id, X-Request-ID, traceparent, tracestate, X-Elastic-Client-Meta, kbn-xsrf")
	w.Header().Set("Access-Control-Expose-Headers", "X-Elastic-Product, Warning, X-Opaque-Id, X-Request-ID, traceparent")
	if opaqueID := r.Header.Get("X-Opaque-Id"); opaqueID != "" {
		w.Header().Set("X-Opaque-Id", opaqueID)
	}
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}
	if tp := r.Header.Get("traceparent"); tp != "" {
		w.Header().Set("traceparent", tp)
	}
	accept := r.Header.Get("Accept")
	reqCT := r.Header.Get("Content-Type")
	switch {
	case strings.Contains(accept, "compatible-with=9") || strings.Contains(reqCT, "compatible-with=9"):
		w.Header().Set("Content-Type", "application/vnd.elasticsearch+json; compatible-with=9")
	case strings.Contains(accept, "compatible-with=8") || strings.Contains(reqCT, "compatible-with=8"):
		w.Header().Set("Content-Type", "application/vnd.elasticsearch+json; compatible-with=8")
	case strings.Contains(accept, "compatible-with=7") || strings.Contains(reqCT, "compatible-with=7"):
		w.Header().Set("Content-Type", "application/vnd.elasticsearch+json; compatible-with=7")
	default:
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeESError(w http.ResponseWriter, status int, errType, reason string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{
				{"type": errType, "reason": reason},
			},
			"type":   errType,
			"reason": reason,
		},
		"status": status,
	})
}
