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
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	Weight    int64
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

// AliasMetadata stores optional Elasticsearch alias filter, write-index flag, and routing metadata.
type AliasMetadata struct {
	Filter        *esast.Query `json:"filter,omitempty"`
	IsWriteIndex  *bool        `json:"is_write_index,omitempty"`
	Routing       string       `json:"routing,omitempty"`
	IndexRouting  string       `json:"index_routing,omitempty"`
	SearchRouting string       `json:"search_routing,omitempty"`
}

func (m AliasMetadata) isEmpty() bool {
	return m.Filter == nil && m.IsWriteIndex == nil && m.Routing == "" && m.IndexRouting == "" && m.SearchRouting == ""
}

func (m AliasMetadata) toMap() map[string]any {
	out := map[string]any{}
	if m.Filter != nil {
		out["filter"] = m.Filter
	}
	if m.IsWriteIndex != nil {
		out["is_write_index"] = *m.IsWriteIndex
	}
	if m.Routing != "" {
		out["routing"] = m.Routing
	}
	if m.IndexRouting != "" {
		out["index_routing"] = m.IndexRouting
	}
	if m.SearchRouting != "" {
		out["search_routing"] = m.SearchRouting
	}
	return out
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
	lastSeqVersion       int64

	authMu        sync.RWMutex
	basicAuthUser string
	basicAuthPass string
	apiKey        string

	mu                    sync.RWMutex
	indices               map[string]*schema.IndexSchema
	aliases               map[string][]string                 // aliasName -> ordered target indexNames
	aliasMeta             map[string]map[string]AliasMetadata // aliasName -> indexName -> metadata
	indexDefaultPipelines map[string]string                   // indexName -> default ingest pipeline ID
	indexFinalPipelines   map[string]string                   // indexName -> final ingest pipeline ID
	templates             map[string]esast.IndexTemplateRequest
	componentTemplates    map[string]map[string]any
	pipelines             map[string]map[string]any
}

func NewServer(dorisDB string, backend DorisBackend, opts transpiler.TranspilerOptions) *Server {
	if dorisDB == "" {
		dorisDB = "es_compat"
	}
	s := &Server{
		dorisDB:               dorisDB,
		backend:               backend,
		transpileOpts:         opts,
		maxBodyBytes:          DefaultMaxRequestBodyBytes,
		slowTracker:           newSlowQueryTracker(),
		shadowVerifier:        newShadowVerifier(""),
		queryCache:            newQueryResultCache(),
		indices:               make(map[string]*schema.IndexSchema),
		aliases:               make(map[string][]string),
		aliasMeta:             make(map[string]map[string]AliasMetadata),
		indexDefaultPipelines: make(map[string]string),
		indexFinalPipelines:   make(map[string]string),
		templates:             make(map[string]esast.IndexTemplateRequest),
		componentTemplates:    make(map[string]map[string]any),
		pipelines:             make(map[string]map[string]any),
	}
	s.coalescer = newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		err := s.backend.StreamLoad(ctx, table, ndjson, syncRefresh)
		s.queryCache.InvalidateAll()
		return err
	})
	return s
}

// SetAuth configures optional inbound HTTP Basic Auth (`basicUser` / `basicPass`) and/or
// Elasticsearch `ApiKey` / `Bearer` token authentication.
func (s *Server) SetAuth(basicUser, basicPass, apiKey string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.basicAuthUser = strings.TrimSpace(basicUser)
	s.basicAuthPass = basicPass
	s.apiKey = strings.TrimSpace(apiKey)
}

// Close flushes any buffered group-commit Stream Load batches and waits for in-flight flushes prior to server shutdown.
func (s *Server) Close(ctx context.Context) error {
	return s.coalescer.Close(ctx)
}

// SetBulkCoalesce configures group-commit Stream Load micro-batching across concurrent write requests.
func (s *Server) SetBulkCoalesce(window time.Duration, maxBytes int) {
	s.coalescer.Configure(window, maxBytes)
}

// SetQueryCacheTTL configures the bounded search response cache TTL (`<= 0` disables caching).
func (s *Server) SetQueryCacheTTL(ttl time.Duration, maxEntries int) {
	s.queryCache.Configure(ttl, maxEntries)
}

// SetMaxRequestBodyBytes configures the maximum HTTP request body size in bytes (`<= 0` uses DefaultMaxRequestBodyBytes).
func (s *Server) SetMaxRequestBodyBytes(maxBytes int64) {
	atomic.StoreInt64(&s.maxBodyBytes, maxBytes)
}

func (s *Server) streamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	err := s.coalescer.Submit(ctx, table, ndjson, syncRefresh)
	s.queryCache.InvalidateAll()
	return err
}

func (s *Server) allocVersion(minFloor int64) int64 {
	for {
		cur := atomic.LoadInt64(&s.lastSeqVersion)
		next := time.Now().UnixNano()
		if cur+1 > next {
			next = cur + 1
		}
		if minFloor > next {
			next = minFloor
		}
		if atomic.CompareAndSwapInt64(&s.lastSeqVersion, cur, next) {
			return next
		}
	}
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
		isDeleted := e.PayloadJSON == "__DELETED__"
		switch e.EntityType {
		case "template":
			if isDeleted {
				delete(s.templates, e.EntityKey)
				continue
			}
			var tpl esast.IndexTemplateRequest
			if err := json.Unmarshal([]byte(e.PayloadJSON), &tpl); err == nil {
				s.templates[e.EntityKey] = tpl
			}
		case "index":
			if isDeleted {
				delete(s.indices, e.EntityKey)
				delete(s.indexDefaultPipelines, e.EntityKey)
				delete(s.indexFinalPipelines, e.EntityKey)
				continue
			}
			var spec esast.MappingSpec
			var metaEnv struct {
				DefaultPipeline string `json:"_default_pipeline,omitempty"`
				FinalPipeline   string `json:"_final_pipeline,omitempty"`
			}
			if len(strings.TrimSpace(e.PayloadJSON)) > 0 && e.PayloadJSON != "null" {
				_ = json.Unmarshal([]byte(e.PayloadJSON), &spec)
				_ = json.Unmarshal([]byte(e.PayloadJSON), &metaEnv)
			}
			var specPtr *esast.MappingSpec
			if len(spec.Properties) > 0 || spec.Dynamic != nil {
				specPtr = &spec
			}
			s.indices[e.EntityKey] = schema.CompileIndexSchema(s.dorisDB, e.EntityKey, specPtr)
			if metaEnv.DefaultPipeline != "" {
				s.indexDefaultPipelines[e.EntityKey] = metaEnv.DefaultPipeline
			} else {
				delete(s.indexDefaultPipelines, e.EntityKey)
			}
			if metaEnv.FinalPipeline != "" {
				s.indexFinalPipelines[e.EntityKey] = metaEnv.FinalPipeline
			} else {
				delete(s.indexFinalPipelines, e.EntityKey)
			}
		case "pipeline":
			if isDeleted {
				delete(s.pipelines, e.EntityKey)
				continue
			}
			var pipe map[string]any
			if err := json.Unmarshal([]byte(e.PayloadJSON), &pipe); err == nil && pipe != nil {
				if s.pipelines == nil {
					s.pipelines = make(map[string]map[string]any)
				}
				s.pipelines[e.EntityKey] = pipe
			}
		case "alias":
			if isDeleted {
				delete(s.aliases, e.EntityKey)
				delete(s.aliasMeta, e.EntityKey)
				continue
			}
			var targets []string
			if err := json.Unmarshal([]byte(e.PayloadJSON), &targets); err == nil {
				if len(targets) > 0 {
					s.aliases[e.EntityKey] = targets
					delete(s.aliasMeta, e.EntityKey)
				} else {
					delete(s.aliases, e.EntityKey)
					delete(s.aliasMeta, e.EntityKey)
				}
			} else {
				var env struct {
					Targets []string                 `json:"targets"`
					Meta    map[string]AliasMetadata `json:"meta,omitempty"`
				}
				if err := json.Unmarshal([]byte(e.PayloadJSON), &env); err == nil {
					if len(env.Targets) > 0 {
						s.aliases[e.EntityKey] = env.Targets
						if len(env.Meta) > 0 {
							s.aliasMeta[e.EntityKey] = env.Meta
						} else {
							delete(s.aliasMeta, e.EntityKey)
						}
					} else {
						delete(s.aliases, e.EntityKey)
						delete(s.aliasMeta, e.EntityKey)
					}
				}
			}
		}
	}
	s.queryCache.InvalidateAll()
	return nil
}

func (s *Server) persistTemplate(ctx context.Context, name string, tpl esast.IndexTemplateRequest) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(tpl); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "template",
				EntityKey:      name,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) persistIngestPipeline(ctx context.Context, id string, body map[string]any) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(body); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "pipeline",
				EntityKey:      id,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteIngestPipelineCatalog(ctx context.Context, id string) {
	s.deleteCatalogEntity(ctx, "pipeline", id)
}

func (s *Server) persistIndex(ctx context.Context, indexName string, idxSchema *schema.IndexSchema) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		s.mu.RLock()
		defPipe := s.indexDefaultPipelines[indexName]
		finPipe := s.indexFinalPipelines[indexName]
		s.mu.RUnlock()

		payloadMap := make(map[string]any)
		if idxSchema != nil && idxSchema.RawMapping != nil {
			if len(idxSchema.RawMapping.Properties) > 0 {
				payloadMap["properties"] = idxSchema.RawMapping.Properties
			}
			if idxSchema.RawMapping.Dynamic != nil {
				payloadMap["dynamic"] = idxSchema.RawMapping.Dynamic
			}
		}
		if defPipe != "" {
			payloadMap["_default_pipeline"] = defPipe
		}
		if finPipe != "" {
			payloadMap["_final_pipeline"] = finPipe
		}
		payload := "{}"
		if len(payloadMap) > 0 {
			if raw, err := json.Marshal(payloadMap); err == nil {
				payload = string(raw)
			}
		}
		_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
			EntityType:     "index",
			EntityKey:      indexName,
			PayloadJSON:    payload,
			UpdatedEpochMs: s.allocVersion(0),
		})
	}
}

func (s *Server) persistAlias(ctx context.Context, aliasName string, targets []string) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if len(targets) == 0 {
			s.deleteCatalogEntity(ctx, "alias", aliasName)
			return
		}
		s.mu.RLock()
		metaByIdx := s.aliasMeta[aliasName]
		hasMeta := false
		metaCopy := make(map[string]AliasMetadata, len(metaByIdx))
		for k, v := range metaByIdx {
			if !v.isEmpty() {
				hasMeta = true
				metaCopy[k] = v
			}
		}
		s.mu.RUnlock()

		var raw []byte
		var err error
		if hasMeta {
			raw, err = json.Marshal(struct {
				Targets []string                 `json:"targets"`
				Meta    map[string]AliasMetadata `json:"meta"`
			}{Targets: targets, Meta: metaCopy})
		} else {
			raw, err = json.Marshal(targets)
		}
		if err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "alias",
				EntityKey:      aliasName,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteCatalogEntity(ctx context.Context, entityType, entityKey string) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		_ = cb.DeleteCatalogEntry(ctx, s.dorisDB, entityType, entityKey)
		_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
			EntityType:     entityType,
			EntityKey:      entityKey,
			PayloadJSON:    "__DELETED__",
			UpdatedEpochMs: s.allocVersion(0),
		})
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
			case "_template", "_index_template", "_component_template":
				s.handleIndexTemplate(w, r)
			case "_data_stream":
				s.handleDataStream(w, r)
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
			case segs[0] == "_cluster" && segs[1] == "state":
				s.handleClusterState(w, r)
			case segs[0] == "_cluster" && segs[1] == "stats":
				s.handleClusterStats(w, r)
			case segs[0] == "_nodes":
				s.handleNodes(w, r)
			case segs[0] == "_ilm" && segs[1] == "policy":
				s.handleILMPolicy(w, r)
			case segs[0] == "_ilm" && segs[1] == "explain":
				s.handleILMExplain(w, r)
			case segs[0] == "_ilm" && segs[1] == "status":
				writeJSON(w, http.StatusOK, map[string]any{"operation_mode": "RUNNING"})
			case segs[0] == "_data_stream":
				r.SetPathValue("name", segs[1])
				s.handleDataStream(w, r)
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
				s.handleSecurityAuthenticate(w, r)
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
				case "_terms_enum":
					s.handleTermsEnum(w, r)
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
			if segs[0] == "_cluster" && segs[1] == "state" {
				s.handleClusterState(w, r)
				return
			}
			if segs[0] == "_nodes" {
				s.handleNodes(w, r)
				return
			}
			if segs[0] == "_ilm" && segs[1] == "policy" {
				r.SetPathValue("policy", segs[2])
				s.handleILMPolicy(w, r)
				return
			}
			if segs[0] == "_resolve" && segs[1] == "index" {
				r.SetPathValue("name", segs[2])
				s.handleResolveIndex(w, r)
				return
			}
			if segs[0] == "_ingest" && segs[1] == "pipeline" {
				if segs[2] == "_simulate" {
					s.handleSimulateIngestPipeline(w, r)
					return
				}
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
			if segs[1] == "_ilm" && segs[2] == "explain" {
				s.handleILMExplain(w, r)
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
			case "_explain":
				s.handleExplainDoc(w, r)
			default:
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			}

		case 4:
			if segs[0] == "_cluster" && segs[1] == "state" {
				s.handleClusterState(w, r)
				return
			}
			if segs[0] == "_nodes" {
				s.handleNodes(w, r)
				return
			}
			if (segs[1] == "_mapping" || segs[1] == "_mappings") && segs[2] == "field" {
				r.SetPathValue("index", segs[0])
				r.SetPathValue("fields", segs[3])
				s.handleGetFieldMapping(w, r)
				return
			}
			if segs[0] == "_ingest" && segs[1] == "pipeline" && segs[3] == "_simulate" {
				r.SetPathValue("id", segs[2])
				s.handleSimulateIngestPipeline(w, r)
				return
			}
			if (segs[1] == "_doc" || segs[1] == "_explain") && segs[3] == "_explain" {
				r.SetPathValue("index", segs[0])
				r.SetPathValue("id", segs[2])
				s.handleExplainDoc(w, r)
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

func extractDefaultPipelineFromSettings(settings map[string]any) (string, bool) {
	if len(settings) == 0 {
		return "", false
	}
	if v, ok := settings["default_pipeline"].(string); ok {
		return strings.TrimSpace(v), true
	}
	if v, ok := settings["index.default_pipeline"].(string); ok {
		return strings.TrimSpace(v), true
	}
	if idxObj, ok := settings["index"].(map[string]any); ok {
		if v, ok := idxObj["default_pipeline"].(string); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func extractFinalPipelineFromSettings(settings map[string]any) (string, bool) {
	if len(settings) == 0 {
		return "", false
	}
	if v, ok := settings["final_pipeline"].(string); ok {
		return strings.TrimSpace(v), true
	}
	if v, ok := settings["index.final_pipeline"].(string); ok {
		return strings.TrimSpace(v), true
	}
	if idxObj, ok := settings["index"].(map[string]any); ok {
		if v, ok := idxObj["final_pipeline"].(string); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func (s *Server) resolveEffectivePipeline(indexName, reqPipeline, itemPipeline string) string {
	if p := strings.TrimSpace(itemPipeline); p != "" {
		if p == "_none" {
			return ""
		}
		return p
	}
	if p := strings.TrimSpace(reqPipeline); p != "" {
		if p == "_none" {
			return ""
		}
		return p
	}
	s.mu.RLock()
	defPipe, hasPipe := s.indexDefaultPipelines[indexName]
	_, hasIdx := s.indices[indexName]
	s.mu.RUnlock()
	if !hasPipe && !hasIdx {
		_ = s.syncCatalogFromBackend(context.Background())
		s.mu.RLock()
		defPipe = s.indexDefaultPipelines[indexName]
		s.mu.RUnlock()
	}
	if defPipe == "_none" {
		return ""
	}
	return defPipe
}

func (s *Server) resolveFinalPipeline(indexName string) string {
	s.mu.RLock()
	finPipe, hasPipe := s.indexFinalPipelines[indexName]
	_, hasIdx := s.indices[indexName]
	s.mu.RUnlock()
	if !hasPipe && !hasIdx {
		_ = s.syncCatalogFromBackend(context.Background())
		s.mu.RLock()
		finPipe = s.indexFinalPipelines[indexName]
		s.mu.RUnlock()
	}
	if finPipe == "_none" {
		return ""
	}
	return finPipe
}

func (s *Server) handleIndexSettings(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	if r.Method == http.MethodPut {
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		updated := false
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var settings map[string]any
			if err := json.Unmarshal(bodyBytes, &settings); err == nil {
				if p, found := extractDefaultPipelineFromSettings(settings); found {
					s.mu.Lock()
					if p == "" {
						delete(s.indexDefaultPipelines, indexName)
					} else {
						s.indexDefaultPipelines[indexName] = p
					}
					s.mu.Unlock()
					updated = true
				}
				if fp, found := extractFinalPipelineFromSettings(settings); found {
					s.mu.Lock()
					if fp == "" {
						delete(s.indexFinalPipelines, indexName)
					} else {
						s.indexFinalPipelines[indexName] = fp
					}
					s.mu.Unlock()
					updated = true
				}
			}
		}
		if updated {
			s.mu.RLock()
			idxSchema := s.indices[indexName]
			s.mu.RUnlock()
			s.persistIndex(r.Context(), indexName, idxSchema)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}
	s.mu.RLock()
	defPipe := s.indexDefaultPipelines[indexName]
	finPipe := s.indexFinalPipelines[indexName]
	s.mu.RUnlock()
	idxSettings := map[string]any{
		"number_of_shards":   "1",
		"number_of_replicas": "0",
	}
	if defPipe != "" {
		idxSettings["default_pipeline"] = defPipe
	}
	if finPipe != "" {
		idxSettings["final_pipeline"] = finPipe
	}
	writeJSON(w, http.StatusOK, map[string]any{
		indexName: map[string]any{
			"settings": map[string]any{
				"index": idxSettings,
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
				"name":              "doris-fe-1",
				"transport_address": "127.0.0.1:9300",
				"host":              "127.0.0.1",
				"ip":                "127.0.0.1",
				"version":           "7.10.2",
				"roles":             []string{"master", "data", "ingest"},
				"http": map[string]any{
					"bound_address":               []string{"0.0.0.0:9200"},
					"publish_address":             "127.0.0.1:9200",
					"max_content_length_in_bytes": DefaultMaxRequestBodyBytes,
				},
			},
		},
	})
}

func (s *Server) handleSecurityAuthenticate(w http.ResponseWriter, r *http.Request) {
	s.authMu.RLock()
	basicUser := s.basicAuthUser
	basicPass := s.basicAuthPass
	s.authMu.RUnlock()

	username := "elastic"
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		username = u
	} else if authHdr := strings.TrimSpace(r.Header.Get("Authorization")); len(authHdr) > 7 && strings.EqualFold(authHdr[:7], "ApiKey ") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHdr[7:])); err == nil {
			if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 && parts[0] != "" {
				username = parts[0]
			}
		}
	} else if basicUser != "" && basicPass != "" {
		username = basicUser
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":  username,
		"roles":     []string{"superuser"},
		"full_name": "doris-es-proxy",
		"email":     "",
		"metadata":  map[string]any{},
		"enabled":   true,
	})
}

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception", "request body exceeded max allowed size: "+err.Error())
			return nil, false
		}
		writeESError(w, http.StatusBadRequest, "parsing_exception", "failed to read request body: "+err.Error())
		return nil, false
	}
	return bodyBytes, true
}

func (s *Server) handleClusterState(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	indicesMeta := make(map[string]any, len(s.indices))
	for name, idx := range s.indices {
		var aliases []string
		for al, targets := range s.aliases {
			for _, t := range targets {
				if t == name {
					aliases = append(aliases, al)
				}
			}
		}
		mappings := map[string]any{}
		if idx.RawMapping != nil {
			mappings["_doc"] = map[string]any{"properties": idx.RawMapping.Properties}
		}
		indicesMeta[name] = map[string]any{
			"state":    "open",
			"settings": map[string]any{"index": map[string]any{"number_of_shards": "1", "number_of_replicas": "0"}},
			"mappings": mappings,
			"aliases":  aliases,
		}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_name": "apache-doris-search-cluster",
		"cluster_uuid": "doris-es-0000-0000-0000-000000000001",
		"master_node":  "doris-fe-1",
		"nodes": map[string]any{
			"doris-fe-1": map[string]any{
				"name":              "doris-fe-1",
				"transport_address": "127.0.0.1:9300",
				"roles":             []string{"master", "data", "ingest"},
			},
		},
		"metadata": map[string]any{
			"indices": indicesMeta,
		},
	})
}

func (s *Server) handleClusterStats(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	numIndices := len(s.indices)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "apache-doris-search-cluster",
		"cluster_uuid": "doris-es-0000-0000-0000-000000000001",
		"status":       "green",
		"indices": map[string]any{
			"count":  numIndices,
			"shards": map[string]any{"total": numIndices, "primaries": numIndices},
		},
		"nodes": map[string]any{
			"count":    map[string]any{"total": 1, "data": 1, "master": 1, "ingest": 1},
			"versions": []string{"7.10.2"},
		},
	})
}

func (s *Server) handleILMPolicy(w http.ResponseWriter, r *http.Request) {
	policy := r.PathValue("policy")
	switch r.Method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodHead:
		w.WriteHeader(http.StatusOK)
	default:
		if policy != "" {
			writeJSON(w, http.StatusOK, map[string]any{
				policy: map[string]any{
					"version":       1,
					"modified_date": "2026-01-01T00:00:00.000Z",
					"policy":        map[string]any{"phases": map[string]any{"hot": map[string]any{"actions": map[string]any{}}}},
				},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}
}

func (s *Server) handleILMExplain(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	indices := make(map[string]any, len(targets))
	for _, idx := range targets {
		indices[idx] = map[string]any{
			"index":   idx,
			"managed": false,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indices": indices})
}

func (s *Server) handleDataStream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"data_streams": []any{}})
	}
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
	list := make([]map[string]any, 0)
	aliasNames := make([]string, 0, len(s.aliases))
	for alias := range s.aliases {
		aliasNames = append(aliasNames, alias)
	}
	sort.Strings(aliasNames)
	for _, alias := range aliasNames {
		if namePattern != "" && namePattern != "*" && namePattern != "_all" && !matchWildcardPattern(namePattern, alias) {
			continue
		}
		targets := s.aliases[alias]
		metaByIdx := s.aliasMeta[alias]
		for _, idx := range targets {
			filterMark := "-"
			writeMark := "-"
			indexRouting := "-"
			searchRouting := "-"
			if metaByIdx != nil {
				m := metaByIdx[idx]
				if m.Filter != nil {
					filterMark = "*"
				}
				if m.IsWriteIndex != nil {
					if *m.IsWriteIndex {
						writeMark = "true"
					} else {
						writeMark = "false"
					}
				}
				if m.IndexRouting != "" {
					indexRouting = m.IndexRouting
				} else if m.Routing != "" {
					indexRouting = m.Routing
				}
				if m.SearchRouting != "" {
					searchRouting = m.SearchRouting
				} else if m.Routing != "" {
					searchRouting = m.Routing
				}
			}
			list = append(list, map[string]any{
				"alias":          alias,
				"index":          idx,
				"filter":         filterMark,
				"routing.index":  indexRouting,
				"routing.search": searchRouting,
				"is_write_index": writeMark,
			})
		}
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"alias", "index", "filter", "routing.index", "routing.search", "is_write_index"}, list)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	_ = s.coalescer.FlushAll(r.Context())
	s.queryCache.InvalidateAll()
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
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodDelete {
		numFreed := 1
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var body struct {
				ScrollID any `json:"scroll_id"`
			}
			if err := json.Unmarshal(bodyBytes, &body); err == nil {
				if arr, ok := body.ScrollID.([]any); ok && len(arr) > 0 {
					numFreed = len(arr)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"succeeded": true, "num_freed": numFreed})
		return
	}
	scrollID := r.URL.Query().Get("scroll_id")
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body struct {
			ScrollID any `json:"scroll_id"`
		}
		if err := json.Unmarshal(bodyBytes, &body); err == nil {
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
	if lastSort := extractLastHitSort(resp); len(lastSort) > 0 {
		nextScrollID = encodeScrollCursor(cursor.Index, &req, lastSort)
	}
	resp["_scroll_id"] = nextScrollID
	writeJSON(w, http.StatusOK, resp)
}

func extractLastHitSort(resp map[string]any) []any {
	hitsWrapper, ok := resp["hits"].(map[string]any)
	if !ok {
		return nil
	}
	switch hitList := hitsWrapper["hits"].(type) {
	case []map[string]any:
		if len(hitList) > 0 {
			if lastSort, ok := hitList[len(hitList)-1]["sort"].([]any); ok {
				return lastSort
			}
		}
	case []any:
		if len(hitList) > 0 {
			if lastHit, ok := hitList[len(hitList)-1].(map[string]any); ok {
				if lastSort, ok := lastHit["sort"].([]any); ok {
					return lastSort
				}
			}
		}
	}
	return nil
}

func (s *Server) handleIndexTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	isComponent := strings.Contains(r.URL.Path, "_component_template")
	if isComponent {
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var comp map[string]any
			bodyBytes, ok := readRequestBody(w, r)
			if !ok {
				return
			}
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &comp); err != nil {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
					return
				}
			}
			if comp == nil {
				comp = map[string]any{}
			}
			s.mu.Lock()
			s.componentTemplates[name] = comp
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		case http.MethodHead:
			s.mu.RLock()
			_, ok := s.componentTemplates[name]
			s.mu.RUnlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			s.mu.RLock()
			list := make([]map[string]any, 0, len(s.componentTemplates))
			for k, v := range s.componentTemplates {
				if name == "" || matchWildcardPattern(name, k) {
					list = append(list, map[string]any{"name": k, "component_template": v})
				}
			}
			s.mu.RUnlock()
			if name != "" && !strings.Contains(name, "*") && len(list) == 0 {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "component_template ["+name+"] missing")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"component_templates": list})
		case http.MethodDelete:
			s.mu.Lock()
			delete(s.componentTemplates, name)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		}
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var tpl esast.IndexTemplateRequest
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &tpl); err != nil {
				writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
				return
			}
		}
		s.mu.Lock()
		s.templates[name] = tpl
		s.mu.Unlock()
		s.persistTemplate(r.Context(), name, tpl)
		s.queryCache.InvalidateAll()
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
		_ = s.syncCatalogFromBackend(r.Context())
		trimmedPath := strings.Trim(r.URL.Path, "/")
		isLegacy := strings.HasPrefix(trimmedPath, "_template")
		if name == "" || strings.Contains(name, "*") {
			s.mu.RLock()
			if isLegacy {
				legacyOut := make(map[string]any, len(s.templates))
				for k, v := range s.templates {
					if name == "" || matchWildcardPattern(name, k) {
						legacyOut[k] = v
					}
				}
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, legacyOut)
				return
			}
			list := make([]map[string]any, 0, len(s.templates))
			for k, v := range s.templates {
				if name == "" || matchWildcardPattern(name, k) {
					list = append(list, map[string]any{"name": k, "index_template": v})
				}
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"index_templates": list})
			return
		}
		s.mu.RLock()
		tpl, ok := s.templates[name]
		s.mu.RUnlock()
		if !ok {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "index_template ["+name+"] missing")
			return
		}
		if isLegacy {
			writeJSON(w, http.StatusOK, map[string]any{name: tpl})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"index_templates": []map[string]any{
				{"name": name, "index_template": tpl},
			},
		})
	case http.MethodDelete:
		_ = s.syncCatalogFromBackend(r.Context())
		s.mu.Lock()
		_, existed := s.templates[name]
		delete(s.templates, name)
		s.mu.Unlock()
		if !existed {
			writeESError(w, http.StatusNotFound, "index_template_missing_exception", "index_template ["+name+"] missing")
			return
		}
		s.deleteCatalogEntity(r.Context(), "template", name)
		s.queryCache.InvalidateAll()
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
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
	}

	_ = s.syncCatalogFromBackend(r.Context())
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
	if p, found := extractDefaultPipelineFromSettings(req.Settings); found {
		if p == "" {
			delete(s.indexDefaultPipelines, indexName)
		} else {
			s.indexDefaultPipelines[indexName] = p
		}
	}
	if fp, found := extractFinalPipelineFromSettings(req.Settings); found {
		if fp == "" {
			delete(s.indexFinalPipelines, indexName)
		} else {
			s.indexFinalPipelines[indexName] = fp
		}
	}
	for alias, rawMeta := range req.Aliases {
		meta := parseAliasMetadata(rawMeta)
		s.addAliasWithMetaLocked(alias, indexName, meta)
		aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
	}
	s.mu.Unlock()
	s.persistIndex(r.Context(), indexName, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(r.Context(), alias, targets)
	}
	s.queryCache.InvalidateAll()

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"index":               indexName,
	})
}

func (s *Server) handleGetIndex(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
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
					idxAliases[alias] = s.getAliasMetaMapLocked(alias, indexName)
				}
			}
		}
		idxSettings := map[string]any{"number_of_shards": "1", "number_of_replicas": "0"}
		if defPipe := s.indexDefaultPipelines[indexName]; defPipe != "" {
			idxSettings["default_pipeline"] = defPipe
		}
		if finPipe := s.indexFinalPipelines[indexName]; finPipe != "" {
			idxSettings["final_pipeline"] = finPipe
		}
		resp[indexName] = map[string]any{
			"aliases":  idxAliases,
			"mappings": mappings,
			"settings": map[string]any{"index": idxSettings},
		}
	}
	if len(resp) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+r.PathValue("index")+"]")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
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
	_ = s.syncCatalogFromBackend(r.Context())

	parts := strings.Split(rawIndex, ",")
	var exclusions []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "-") {
			if excl := strings.TrimSpace(strings.TrimPrefix(part, "-")); excl != "" {
				exclusions = append(exclusions, excl)
			}
		}
	}
	isExcluded := func(idx string) bool {
		for _, excl := range exclusions {
			if excl == "_all" || excl == "*" || matchWildcardPattern(excl, idx) {
				return true
			}
		}
		return false
	}
	seen := make(map[string]bool)
	var targets []string

	addDeleteTarget := func(idx string) {
		if idx != "" && !seen[idx] && !isExcluded(idx) {
			seen[idx] = true
			targets = append(targets, idx)
		}
	}

	s.mu.RLock()
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") {
			continue
		}
		if part == "_all" || part == "*" {
			for idxName := range s.indices {
				addDeleteTarget(idxName)
			}
			continue
		}
		if strings.Contains(part, "*") {
			matchedIndex := false
			for idxName := range s.indices {
				if matchWildcardPattern(part, idxName) {
					addDeleteTarget(idxName)
					matchedIndex = true
				}
			}
			if !matchedIndex {
				for alias, aliasTargets := range s.aliases {
					if len(aliasTargets) > 0 && matchWildcardPattern(part, alias) {
						s.mu.RUnlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("The provided expression [%s] matches an alias, specify the corresponding concrete indices instead.", rawIndex))
						return
					}
				}
			}
			continue
		}
		_, isConcreteIndex := s.indices[part]
		aliasTargets, isAlias := s.aliases[part]
		if isAlias && len(aliasTargets) > 0 && !isConcreteIndex {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("The provided expression [%s] matches an alias, specify the corresponding concrete indices instead.", rawIndex))
			return
		}
		addDeleteTarget(part)
	}
	s.mu.RUnlock()

	modifiedAliases := make(map[string][]string)
	var tablesToDrop []*schema.IndexSchema
	s.mu.Lock()
	for _, indexName := range targets {
		if idx, ok := s.indices[indexName]; ok {
			tablesToDrop = append(tablesToDrop, idx)
		}
		delete(s.indices, indexName)
		delete(s.indexDefaultPipelines, indexName)
		delete(s.indexFinalPipelines, indexName)
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
	if len(out) == 0 && !strings.ContainsAny(rawIndex, "*,") && rawIndex != "_all" {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	writeJSON(w, http.StatusOK, out)
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
			esType := fb.ESType
			if esType == "" {
				esType = "keyword"
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
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
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
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetAliases(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
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
						entry["aliases"].(map[string]any)[alias] = s.getAliasMetaMapLocked(alias, idxName)
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
					idxAliases[alias] = s.getAliasMetaMapLocked(alias, idxName)
				}
			}
		}
		out[idxName] = map[string]any{"aliases": idxAliases}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetIndexAliases(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := r.PathValue("index")
	targets := s.resolveTargetIndices(rawIndex)
	if len(targets) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	s.mu.RLock()
	out := make(map[string]any, len(targets))
	for _, indexName := range targets {
		if _, ok := s.indices[indexName]; !ok {
			continue
		}
		idxAliases := make(map[string]any)
		for alias, aliasTargets := range s.aliases {
			for _, t := range aliasTargets {
				if t == indexName {
					idxAliases[alias] = s.getAliasMetaMapLocked(alias, indexName)
				}
			}
		}
		out[indexName] = map[string]any{"aliases": idxAliases}
	}
	s.mu.RUnlock()
	if len(out) == 0 {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleIndexAliasByName(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := r.PathValue("index")
	targetIndices := s.resolveTargetIndices(rawIndex)
	if len(targetIndices) == 0 {
		targetIndices = []string{s.resolveIndexName(rawIndex)}
	}
	aliasName := r.PathValue("name")
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var meta AliasMetadata
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &meta); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		s.mu.Lock()
		for _, indexName := range targetIndices {
			s.addAliasWithMetaLocked(aliasName, indexName, meta)
		}
		targets := append([]string(nil), s.aliases[aliasName]...)
		s.mu.Unlock()
		s.persistAlias(r.Context(), aliasName, targets)
		s.queryCache.InvalidateAll()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		modifiedAliases := make(map[string][]string)
		s.mu.Lock()
		if strings.ContainsAny(aliasName, "*?") || aliasName == "_all" {
			var matchingAliases []string
			for al := range s.aliases {
				if aliasName == "*" || aliasName == "_all" || matchWildcardPattern(aliasName, al) {
					matchingAliases = append(matchingAliases, al)
				}
			}
			for _, al := range matchingAliases {
				for _, indexName := range targetIndices {
					s.removeAliasTargetLocked(al, indexName)
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		} else {
			for _, indexName := range targetIndices {
				s.removeAliasTargetLocked(aliasName, indexName)
			}
			modifiedAliases[aliasName] = append([]string(nil), s.aliases[aliasName]...)
		}
		s.mu.Unlock()
		for al, targets := range modifiedAliases {
			s.persistAlias(r.Context(), al, targets)
		}
		s.queryCache.InvalidateAll()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet, http.MethodHead:
		targetSet := make(map[string]bool, len(targetIndices))
		for _, idx := range targetIndices {
			targetSet[idx] = true
		}
		s.mu.RLock()
		out := make(map[string]any)
		for al, targets := range s.aliases {
			if aliasName != "" && aliasName != "*" && aliasName != "_all" && !matchWildcardPattern(aliasName, al) {
				continue
			}
			for _, t := range targets {
				if !targetSet[t] {
					continue
				}
				entry, ok := out[t].(map[string]any)
				if !ok {
					entry = map[string]any{"aliases": map[string]any{}}
					out[t] = entry
				}
				entry["aliases"].(map[string]any)[al] = s.getAliasMetaMapLocked(al, t)
			}
		}
		s.mu.RUnlock()
		if len(out) == 0 {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "alias_not_found_exception", "aliases ["+aliasName+"] missing")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) handleUpdateAliases(w http.ResponseWriter, r *http.Request) {
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var payload struct {
		Actions []map[string]struct {
			Index         string       `json:"index"`
			Indices       []string     `json:"indices"`
			Alias         string       `json:"alias"`
			Aliases       []string     `json:"aliases"`
			Filter        *esast.Query `json:"filter,omitempty"`
			IsWriteIndex  *bool        `json:"is_write_index,omitempty"`
			Routing       string       `json:"routing,omitempty"`
			IndexRouting  string       `json:"index_routing,omitempty"`
			SearchRouting string       `json:"search_routing,omitempty"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
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
			meta := AliasMetadata{
				Filter:        add.Filter,
				IsWriteIndex:  add.IsWriteIndex,
				Routing:       add.Routing,
				IndexRouting:  add.IndexRouting,
				SearchRouting: add.SearchRouting,
			}
			for _, al := range aliases {
				for _, idx := range indices {
					s.addAliasWithMetaLocked(al, idx, meta)
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
						delete(s.aliasMeta, al)
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
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func parseAliasMetadata(raw any) AliasMetadata {
	if raw == nil {
		return AliasMetadata{}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return AliasMetadata{}
	}
	var meta AliasMetadata
	_ = json.Unmarshal(b, &meta)
	return meta
}

func (s *Server) addAliasWithMetaLocked(alias, indexName string, meta AliasMetadata) {
	existing := s.aliases[alias]
	found := false
	for _, t := range existing {
		if t == indexName {
			found = true
			break
		}
	}
	if !found {
		s.aliases[alias] = append(existing, indexName)
	}
	if !meta.isEmpty() {
		if s.aliasMeta[alias] == nil {
			s.aliasMeta[alias] = make(map[string]AliasMetadata)
		}
		s.aliasMeta[alias][indexName] = meta
	} else if s.aliasMeta[alias] != nil {
		delete(s.aliasMeta[alias], indexName)
	}
}

func (s *Server) getAliasMetaMapLocked(alias, indexName string) map[string]any {
	if byIdx := s.aliasMeta[alias]; byIdx != nil {
		if meta, ok := byIdx[indexName]; ok && !meta.isEmpty() {
			return meta.toMap()
		}
	}
	return map[string]any{}
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
		} else if s.aliasMeta[alias] != nil {
			delete(s.aliasMeta[alias], t)
		}
	}
	if len(filtered) == 0 {
		delete(s.aliases, alias)
		delete(s.aliasMeta, alias)
	} else {
		s.aliases[alias] = filtered
	}
}

func extractURLSourceFilter(r *http.Request) *esast.SourceFilter {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return nil
	}
	q := r.URL.Query()
	var sf *esast.SourceFilter
	if srcParam := q.Get("_source"); srcParam != "" {
		if srcParam == "false" {
			return &esast.SourceFilter{Disabled: true}
		}
		if srcParam != "true" {
			sf = &esast.SourceFilter{Includes: strings.Split(srcParam, ",")}
		}
	}
	if inc := q.Get("_source_includes"); inc != "" {
		if sf == nil {
			sf = &esast.SourceFilter{}
		}
		sf.Includes = append(sf.Includes, strings.Split(inc, ",")...)
	}
	if exc := q.Get("_source_excludes"); exc != "" {
		if sf == nil {
			sf = &esast.SourceFilter{}
		}
		sf.Excludes = append(sf.Excludes, strings.Split(exc, ",")...)
	}
	return sf
}

func (s *Server) handlePutDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(r.PathValue("index"))
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	docID := r.PathValue("id")
	isCreate := strings.Contains(r.URL.Path, "/_create/") || strings.EqualFold(r.URL.Query().Get("op_type"), "create")
	if docID == "" {
		docID = esast.NextAutoID()
	}
	rawDoc, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	docPayload, dropped, pipeErr := s.applyEffectiveAndFinalPipelines(indexName, r.URL.Query().Get("pipeline"), "", json.RawMessage(rawDoc))
	if pipeErr != nil {
		writeESError(w, http.StatusBadRequest, "ingest_processor_exception", pipeErr.Error())
		return
	}
	if dropped {
		writeJSON(w, http.StatusOK, map[string]any{
			"_index":        indexName,
			"_type":         "_doc",
			"_id":           docID,
			"_version":      -1,
			"result":        "noop",
			"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"_seq_no":       -1,
			"_primary_term": 1,
		})
		return
	}
	if aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, docPayload, aliasFilter) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("document [%s] does not match alias filter for write alias [%s]", docID, r.PathValue("index")))
		return
	}

	idxSchema := s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, []json.RawMessage{docPayload})
	var minVer int64
	wasExisting := false
	if isCreate || aliasFilter != nil {
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
	}
	if existing, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID); err == nil && found {
		if isCreate {
			writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document already exists", docID))
			return
		}
		if aliasFilter != nil && existing != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, existing.Source, aliasFilter) {
			writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", docID))
			return
		}
		wasExisting = true
		if existing != nil {
			minVer = existing.Version + 1
		}
	} else if existing != nil {
		minVer = existing.Version + 1
	}
	nextVer := s.allocVersion(minVer)
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

	status := http.StatusCreated
	result := "created"
	reportedVer := int64(1)
	if wasExisting {
		status = http.StatusOK
		result = "updated"
		reportedVer = nextVer
	}
	writeJSON(w, status, map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      reportedVer,
		"result":        result,
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       nextVer,
		"_primary_term": 1,
	})
}

func (s *Server) handleHeadDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(r.PathValue("index"))
	if readErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	docID := r.PathValue("id")
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil || !found || (hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetSource(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(r.PathValue("index"))
	if readErr != nil {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	docID := r.PathValue("id")
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter) {
		found = false
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
	urlSF := extractURLSourceFilter(r)
	if urlSF != nil && urlSF.Disabled {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "unable to fetch _source when _source is disabled")
		return
	}
	filteredSrc := filterSourceJSON(hit.Source, urlSF)
	if opts, ok := extractESResponseFormatOptions(w); ok && (opts.pretty || len(opts.filterPaths) > 0) {
		dec := json.NewDecoder(bytes.NewReader(filteredSrc))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err == nil {
			writeJSON(w, http.StatusOK, doc)
			return
		}
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/vnd.elasticsearch+json") {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- Content-Type is application/json with X-Content-Type-Options: nosniff
	_, _ = w.Write(filteredSrc)
}

func (s *Server) handleGetDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(r.PathValue("index"))
	if readErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	docID := r.PathValue("id")
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter) {
		found = false
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
	urlSF := extractURLSourceFilter(r)
	resp := map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      hit.ID,
		"_version": hit.Version,
		"found":    true,
	}
	if urlSF == nil || !urlSF.Disabled {
		resp["_source"] = filterSourceJSON(hit.Source, urlSF)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMGet(w http.ResponseWriter, r *http.Request) {
	rawDefaultIndex := r.PathValue("index")
	if rawDefaultIndex != "" {
		if _, _, err := s.resolveReadDocIndexWithFilter(rawDefaultIndex); err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
	}
	urlSF := extractURLSourceFilter(r)
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var body struct {
		IDs  []string `json:"ids"`
		Docs []struct {
			Index  string              `json:"_index"`
			ID     string              `json:"_id"`
			Source *esast.SourceFilter `json:"_source,omitempty"`
		} `json:"docs"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
		}
	}
	for _, id := range body.IDs {
		body.Docs = append(body.Docs, struct {
			Index  string              `json:"_index"`
			ID     string              `json:"_id"`
			Source *esast.SourceFilter `json:"_source,omitempty"`
		}{Index: rawDefaultIndex, ID: id})
	}

	idsByIndex := make(map[string][]string)
	for _, spec := range body.Docs {
		rawIdx := rawDefaultIndex
		if spec.Index != "" {
			rawIdx = spec.Index
		}
		idxName, _, readErr := s.resolveReadDocIndexWithFilter(rawIdx)
		if readErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
			return
		}
		idsByIndex[idxName] = append(idsByIndex[idxName], spec.ID)
	}

	prefetched := make(map[string]map[string]HitRow, len(idsByIndex))
	for idxName, ids := range idsByIndex {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		if m, err := s.backend.GetDocsByIDs(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, ids); err == nil {
			prefetched[idxName] = m
		}
	}

	docsOut := make([]map[string]any, 0, len(body.Docs))
	for _, spec := range body.Docs {
		rawIdx := rawDefaultIndex
		if spec.Index != "" {
			rawIdx = spec.Index
		}
		idxName, aliasFilter, _ := s.resolveReadDocIndexWithFilter(rawIdx)
		hit, found := prefetched[idxName][spec.ID]
		if found && !s.docMatchesAliasFilter(r.Context(), idxName, spec.ID, hit.Source, aliasFilter) {
			found = false
		}
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
		effSF := spec.Source
		if effSF == nil {
			effSF = urlSF
		}
		if effSF == nil || !effSF.Disabled {
			docItem["_source"] = filterSourceJSON(hit.Source, effSF)
		}
		docsOut = append(docsOut, docItem)
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

func (s *Server) handleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(r.PathValue("index"))
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	if aliasFilter != nil {
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		existingHit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
		if err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
			return
		}
		if !found || existingHit == nil || !s.docMatchesAliasFilter(r.Context(), indexName, docID, existingHit.Source, aliasFilter) {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"_index":        indexName,
				"_type":         "_doc",
				"_id":           docID,
				"_version":      1,
				"result":        "not_found",
				"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
				"_seq_no":       0,
				"_primary_term": 1,
			})
			return
		}
	}

	nextVer := s.allocVersion(0)
	tombstone, err := schema.ShredDocument(idxSchema, docID, nextVer, true, nil)
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
		"_seq_no":       nextVer,
		"_primary_term": 1,
	})
}

func (s *Server) handleUpdateDoc(w http.ResponseWriter, r *http.Request) {
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(r.PathValue("index"))
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	docID := r.PathValue("id")
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	var updReq painless.UpdateRequest
	if err := json.Unmarshal(bodyBytes, &updReq); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}

	roSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	_ = s.coalescer.FlushTable(r.Context(), roSchema.DorisTable)
	existingHit, found, err := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && aliasFilter != nil && (existingHit == nil || !s.docMatchesAliasFilter(r.Context(), indexName, docID, existingHit.Source, aliasFilter)) {
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}
	if !found && !updReq.DocAsUpsert && updReq.Upsert == nil && !updReq.ScriptedUpsert {
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}

	var baseSource json.RawMessage
	var minFloor int64
	if found {
		baseSource = existingHit.Source
		minFloor = existingHit.Version + 1
	}
	nextVersion := s.allocVersion(minFloor)

	mutatedSource, opResult, err := painless.ApplyUpdateWithResult(baseSource, &updReq, found)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
		return
	}

	if opResult != "noop" {
		isDelete := opResult == "deleted"
		if !isDelete && len(mutatedSource) > 0 {
			pipedDoc, dropped, pipeErr := s.applyEffectiveAndFinalPipelines(indexName, r.URL.Query().Get("pipeline"), "", mutatedSource)
			if pipeErr != nil {
				writeESError(w, http.StatusBadRequest, "ingest_processor_exception", pipeErr.Error())
				return
			}
			if dropped {
				writeJSON(w, http.StatusOK, map[string]any{
					"_index":        indexName,
					"_type":         "_doc",
					"_id":           docID,
					"_version":      nextVersion,
					"result":        "noop",
					"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"_seq_no":       nextVersion,
					"_primary_term": 1,
				})
				return
			}
			mutatedSource = pipedDoc
		}
		if !isDelete && aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, mutatedSource, aliasFilter) {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("updated document [%s] does not match alias filter for [%s]", docID, r.PathValue("index")))
			return
		}
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

	status := http.StatusOK
	if opResult == "created" {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{
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
	rawIndex := r.PathValue("index")
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 && !hasExclusionOrWildcard(rawIndex) {
		target, f := s.resolveIndexNameWithFilter(rawIndex)
		targets = []string{target}
		if f != nil {
			if aliasFilters == nil {
				aliasFilters = make(map[string]*esast.Query)
			}
			aliasFilters[target] = f
		}
	}

	var body struct {
		MaxDocs   *int                 `json:"max_docs,omitempty"`
		Conflicts string               `json:"conflicts,omitempty"`
		Pipeline  string               `json:"pipeline,omitempty"`
		Query     *esast.Query         `json:"query,omitempty"`
		Script    *painless.ScriptSpec `json:"script,omitempty"`
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
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
	if body.Query != nil && hasTermsLookupInQuery(body.Query) {
		s.resolveTermsLookupsInQuery(r.Context(), body.Query)
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)

	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(r.Context(), indexName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any
		effQuery := combineQueryWithAliasFilter(body.Query, aliasFilters[indexName])

		for {
			fetchSize := 1000
			if maxDocs > 0 && totalMatched+fetchSize > maxDocs {
				fetchSize = maxDocs - totalMatched
			}
			if fetchSize <= 0 {
				break
			}
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Query:          effQuery,
				Size:           &fetchSize,
				TrackTotalHits: false,
				Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter:    searchAfter,
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

			type pendingUpdate struct {
				id      string
				version int64
				isDel   bool
				source  json.RawMessage
			}
			var pending []pendingUpdate
			var sampleDocs []json.RawMessage
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
				if !isDel && len(mutated) > 0 {
					piped, dropped, pipeErr := s.applyEffectiveAndFinalPipelines(indexName, r.URL.Query().Get("pipeline"), body.Pipeline, mutated)
					if pipeErr != nil {
						writeESError(w, http.StatusBadRequest, "ingest_processor_exception", pipeErr.Error())
						return
					}
					if dropped {
						continue
					}
					mutated = piped
				}
				if !isDel && aliasFilters[indexName] != nil && !s.docMatchesAliasFilter(r.Context(), indexName, h.ID, mutated, aliasFilters[indexName]) {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("updated document [%s] does not match alias filter for [%s]", h.ID, r.PathValue("index")))
					return
				}
				if !isDel && len(mutated) > 0 && len(sampleDocs) < 16 {
					sampleDocs = append(sampleDocs, mutated)
				}
				pending = append(pending, pendingUpdate{id: h.ID, version: h.Version, isDel: isDel, source: mutated})
			}

			if len(sampleDocs) > 0 {
				idxSchema = s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, sampleDocs)
			}

			var batchBuf bytes.Buffer
			for _, pu := range pending {
				nextVer := s.allocVersion(pu.version + 1)
				shredded, err := schema.ShredDocument(idxSchema, pu.id, nextVer, pu.isDel, pu.source)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
					return
				}
				batchBuf.Write(shredded)
				batchBuf.WriteByte('\n')
				if pu.isDel {
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
	rawIndex := r.PathValue("index")
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 && !hasExclusionOrWildcard(rawIndex) {
		target, f := s.resolveIndexNameWithFilter(rawIndex)
		targets = []string{target}
		if f != nil {
			if aliasFilters == nil {
				aliasFilters = make(map[string]*esast.Query)
			}
			aliasFilters[target] = f
		}
	}

	var body struct {
		MaxDocs *int         `json:"max_docs,omitempty"`
		Query   *esast.Query `json:"query,omitempty"`
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
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
	if body.Query != nil && hasTermsLookupInQuery(body.Query) {
		s.resolveTermsLookupsInQuery(r.Context(), body.Query)
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)
	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(r.Context(), indexName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any
		effQuery := combineQueryWithAliasFilter(body.Query, aliasFilters[indexName])

		for {
			fetchSize := 1000
			if maxDocs > 0 && totalDeleted+fetchSize > maxDocs {
				fetchSize = maxDocs - totalDeleted
			}
			if fetchSize <= 0 {
				break
			}
			plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
				Query:          effQuery,
				Size:           &fetchSize,
				TrackTotalHits: false,
				Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
				SearchAfter:    searchAfter,
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
				nextVer := s.allocVersion(h.Version + 1)
				tombstone, err := schema.ShredDocument(idxSchema, h.ID, nextVer, true, nil)
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
	rawDefaultIndex := r.PathValue("index")
	if rawDefaultIndex != "" {
		if _, err := s.resolveWriteIndex(rawDefaultIndex); err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
	}
	defaultIndex := rawDefaultIndex
	if defaultIndex == "" {
		defaultIndex = "default_index"
	}
	ops, err := esast.ParseBulkNDJSON(r.Body, defaultIndex)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception", "bulk request body exceeded max allowed size: "+err.Error())
			return
		}
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", err.Error())
		return
	}

	defaultPipeline := r.URL.Query().Get("pipeline")
	droppedOps := make([]bool, len(ops))
	pipeErrs := make([]string, len(ops))
	// Collect sample docs per target index for dynamic mapping inference on auto-created indices.
	sampleDocsByIndex := make(map[string][]json.RawMessage)
	idsToFetchByIndex := make(map[string][]string)
	for idx := range ops {
		op := &ops[idx]
		if op.ParseErr != "" {
			continue
		}
		idxName, opAliasFilter, writeErr := s.resolveWriteIndexWithFilter(op.Index)
		if writeErr != nil {
			op.ParseErr = writeErr.Error()
			continue
		}
		if (op.Action == "index" || op.Action == "create") && len(op.Source) > 0 {
			piped, dropped, pipeErr := s.applyEffectiveAndFinalPipelines(idxName, defaultPipeline, op.Pipeline, op.Source)
			if pipeErr != nil {
				pipeErrs[idx] = pipeErr.Error()
				continue
			}
			if dropped {
				droppedOps[idx] = true
				continue
			}
			op.Source = piped
		}
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
		if (op.Action == "update" || op.Action == "create" || op.Action == "index" || (op.Action == "delete" && opAliasFilter != nil)) && op.ID != "" {
			idsToFetchByIndex[idxName] = append(idsToFetchByIndex[idxName], op.ID)
		}
	}
	for idxName, samples := range sampleDocsByIndex {
		_ = s.ensureWritableIndexSchemaWithDocs(r.Context(), idxName, samples)
	}
	existingByIndex := make(map[string]map[string]HitRow, len(idsToFetchByIndex))
	for idxName, ids := range idsToFetchByIndex {
		idxSchema := s.ensureIndexSchema(r.Context(), idxName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		if m, err := s.backend.GetDocsByIDs(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, ids); err == nil {
			existingByIndex[idxName] = m
		}
	}

	byIndex := make(map[string]*bytes.Buffer)
	var items []map[string]any
	hasErrors := false

	for opIdx, op := range ops {
		targetIndex, opAliasFilter, writeErr := s.resolveWriteIndexWithFilter(op.Index)
		if writeErr != nil {
			targetIndex = op.Index
		}
		if pipeErrs[opIdx] != "" {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": "ingest_processor_exception", "reason": pipeErrs[opIdx]},
				},
			})
			continue
		}
		if droppedOps[opIdx] {
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index":        targetIndex,
					"_type":         "_doc",
					"_id":           op.ID,
					"_version":      -1,
					"result":        "noop",
					"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"_seq_no":       -1,
					"_primary_term": 1,
					"status":        http.StatusOK,
				},
			})
			continue
		}
		if op.ParseErr != "" {
			hasErrors = true
			errType := "mapper_parsing_exception"
			if writeErr != nil {
				errType = "illegal_argument_exception"
			}
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": errType, "reason": op.ParseErr},
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

		if (op.Action == "index" || op.Action == "create") && opAliasFilter != nil {
			if op.Action == "index" {
				if existingHit, exists := existingByIndex[targetIndex][op.ID]; exists && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingHit.Source, opAliasFilter) {
					hasErrors = true
					items = append(items, map[string]any{
						op.Action: map[string]any{
							"_index": targetIndex,
							"_id":    op.ID,
							"status": http.StatusConflict,
							"error":  map[string]any{"type": "version_conflict_engine_exception", "reason": fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", op.ID)},
						},
					})
					continue
				}
			}
			if !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, op.Source, opAliasFilter) {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusBadRequest,
						"error":  map[string]any{"type": "illegal_argument_exception", "reason": fmt.Sprintf("document [%s] does not match alias filter for write alias [%s]", op.ID, op.Index)},
					},
				})
				continue
			}
		}

		deleted := op.Action == "delete"
		if deleted && opAliasFilter != nil {
			existingHit, found := existingByIndex[targetIndex][op.ID]
			if !found || !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingHit.Source, opAliasFilter) {
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index":        targetIndex,
						"_type":         "_doc",
						"_id":           op.ID,
						"_version":      1,
						"result":        "not_found",
						"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
						"_seq_no":       0,
						"_primary_term": 1,
						"status":        http.StatusNotFound,
					},
				})
				continue
			}
		}
		sourceToShred := op.Source
		var minFloor int64
		existingBeforeOp, wasExistingBeforeOp := existingByIndex[targetIndex][op.ID]
		if wasExistingBeforeOp {
			minFloor = existingBeforeOp.Version + 1
		}
		updateResult := ""

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
			if found && opAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingHit.Source, opAliasFilter) {
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
			if !found && !upd.DocAsUpsert && upd.Upsert == nil && !upd.ScriptedUpsert {
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
			updateResult = opRes
			if opRes == "deleted" {
				deleted = true
				sourceToShred = merged
			} else {
				if len(merged) > 0 {
					piped, dropped, pipeErr := s.applyEffectiveAndFinalPipelines(targetIndex, defaultPipeline, op.Pipeline, merged)
					if pipeErr != nil {
						hasErrors = true
						items = append(items, map[string]any{
							op.Action: map[string]any{
								"_index": targetIndex,
								"_id":    op.ID,
								"status": http.StatusBadRequest,
								"error":  map[string]any{"type": "ingest_processor_exception", "reason": pipeErr.Error()},
							},
						})
						continue
					}
					if dropped {
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
					merged = piped
				}
				sourceToShred = merged
				if opAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, merged, opAliasFilter) {
					hasErrors = true
					items = append(items, map[string]any{
						op.Action: map[string]any{
							"_index": targetIndex,
							"_id":    op.ID,
							"status": http.StatusBadRequest,
							"error":  map[string]any{"type": "illegal_argument_exception", "reason": fmt.Sprintf("updated document [%s] does not match alias filter for [%s]", op.ID, op.Index)},
						},
					})
					continue
				}
				if len(sourceToShred) > 0 {
					idxSchema = s.ensureWritableIndexSchemaWithDocs(r.Context(), targetIndex, []json.RawMessage{sourceToShred})
				}
			}
		}

		nextVer := s.allocVersion(minFloor)
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
		reportedVer := int64(1)
		if deleted {
			status = http.StatusOK
			result = "deleted"
			if wasExistingBeforeOp {
				reportedVer = nextVer
			}
		} else if op.Action == "update" {
			if updateResult == "created" {
				status = http.StatusCreated
				result = "created"
			} else {
				status = http.StatusOK
				result = "updated"
				reportedVer = nextVer
			}
		} else if op.Action == "index" && wasExistingBeforeOp {
			status = http.StatusOK
			result = "updated"
			reportedVer = nextVer
		}
		items = append(items, map[string]any{
			op.Action: map[string]any{
				"_index":        targetIndex,
				"_type":         "_doc",
				"_id":           op.ID,
				"_version":      reportedVer,
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
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
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

	rawIndex := extractPITIndex(r.PathValue("index"), req.PIT)
	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), rawIndex, &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	if req.PIT != nil && req.PIT.ID != "" {
		resp["pit_id"] = req.PIT.ID
	}

	if r.URL.Query().Get("scroll") != "" {
		scrollID := "doris-scroll-eof"
		if lastSort := extractLastHitSort(resp); len(lastSort) > 0 {
			scrollID = encodeScrollCursor(rawIndex, &req, lastSort)
		}
		resp["_scroll_id"] = scrollID
	}
	if r.URL.Query().Get("doris_explain") == "true" || r.URL.Query().Get("doris_explain") == "1" ||
		r.URL.Query().Get("_doris_explain") == "true" || r.URL.Query().Get("_doris_explain") == "1" {
		resp["_doris_explain"] = s.buildDorisExplainObject(r.Context(), rawIndex, &req)
	}
	if r.URL.Query().Get("rest_total_hits_as_int") == "true" {
		if hitsObj, ok := resp["hits"].(map[string]any); ok {
			if totalObj, ok := hitsObj["total"].(map[string]any); ok {
				hitsObj["total"] = totalObj["value"]
			}
		}
	}
	tookMs, _ := toInt64(resp["took"])
	syncShadow := r.URL.Query().Get("shadow_sync") == "true" || r.URL.Query().Get("shadow_sync") == "1"
	s.maybeRunShadowSearch(rawIndex, bodyBytes, resp, tookMs, syncShadow)

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDorisExplain(w http.ResponseWriter, r *http.Request) {
	var req esast.SearchRequest
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
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
	if req != nil {
		rawIndexPattern = extractPITIndex(rawIndexPattern, req.PIT)
	}
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndexPattern)
	if len(targets) == 0 && !hasExclusionOrWildcard(rawIndexPattern) {
		target, f := s.resolveIndexNameWithFilter(rawIndexPattern)
		targets = []string{target}
		if f != nil {
			if aliasFilters == nil {
				aliasFilters = make(map[string]*esast.Query)
			}
			aliasFilters[target] = f
		}
	}
	if req != nil && hasTermsLookupInSearchRequest(req) {
		req = s.resolveTermsLookupsInSearchRequest(ctx, req)
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(ctx, aliasFilters)
	var plans []map[string]any
	for _, indexName := range targets {
		idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		subReq := applyIndexAliasFilter(req, aliasFilters[indexName])
		plan, err := tr.BuildSearchPlan(subReq)
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
			"hits_sql_normalized":      NormalizeDorisSQL(plan.HitsSQL),
			"aggs_sql":                 plan.AggsSQL,
			"aggs_sql_normalized":      NormalizeDorisSQL(plan.AggsSQL),
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
		out["hits_sql_normalized"] = plans[0]["hits_sql_normalized"]
		out["aggs_sql"] = plans[0]["aggs_sql"]
		out["aggs_sql_normalized"] = plans[0]["aggs_sql_normalized"]
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
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
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
			switch {
			case fb.ESType != "":
				addCap(esPath, fb.ESType, true, fb.ESType != "text")
				if fb.KeywordCompanion != "" {
					addCap(esPath+".keyword", "keyword", true, true)
				}
			case fb.DorisType == schema.DorisBigInt:
				if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
					addCap(esPath, "date", true, true)
				} else {
					addCap(esPath, "long", true, true)
				}
			case fb.DorisType == schema.DorisDouble:
				addCap(esPath, "double", true, true)
			case fb.DorisType == schema.DorisBoolean:
				addCap(esPath, "boolean", true, true)
			case fb.DorisType == schema.DorisString:
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
			Index      any    `json:"index"`
			Indices    any    `json:"indices"`
			FilterPath string `json:"filter_path"`
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
		if fp := strings.TrimSpace(hdr.FilterPath); fp != "" {
			var subPaths []string
			for _, p := range strings.Split(fp, ",") {
				if p = strings.TrimSpace(p); p != "" {
					subPaths = append(subPaths, p)
				}
			}
			if filtered, ok := applyESFilterPath(resp, subPaths).(map[string]any); ok {
				resp = filtered
			}
		}
		responses = append(responses, resp)
	}
	if err := scanner.Err(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception", "msearch request body exceeded max allowed size: "+err.Error())
			return
		}
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
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
	if req != nil {
		rawIndexPattern = extractPITIndex(rawIndexPattern, req.PIT)
	}
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndexPattern)
	if len(targets) == 0 {
		// If wildcard or exclusion pattern matched nothing, return empty 200 search response (like ES with allow_no_indices=true)
		if hasExclusionOrWildcard(rawIndexPattern) {
			return buildESResponse(rawIndexPattern, nil, req, nil, nil, 1, nil), http.StatusOK, "", ""
		}
		target, f := s.resolveIndexNameWithFilter(rawIndexPattern)
		targets = []string{target}
		if f != nil {
			if aliasFilters == nil {
				aliasFilters = make(map[string]*esast.Query)
			}
			aliasFilters[target] = f
		}
	}

	if req != nil {
		if errMsg := validatePipelineAggs(req.EffectiveAggs()); errMsg != "" {
			return nil, http.StatusBadRequest, "illegal_argument_exception", errMsg
		}
		if hasTermsLookupInSearchRequest(req) {
			req = s.resolveTermsLookupsInSearchRequest(ctx, req)
		}
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(ctx, aliasFilters)

	cacheTargets := targets
	aliasHasNow := false
	if len(aliasFilters) > 0 {
		cacheTargets = make([]string, 0, len(targets)+1)
		cacheTargets = append(cacheTargets, "__alias_raw:"+rawIndexPattern)
		for _, t := range targets {
			if af := aliasFilters[t]; af != nil {
				if queryContainsNow(af) {
					aliasHasNow = true
				}
				if afBytes, err := json.Marshal(af); err == nil {
					if bytes.Contains(afBytes, []byte("now")) {
						aliasHasNow = true
					}
					cacheTargets = append(cacheTargets, t+"\x00af:"+string(afBytes))
					continue
				}
			}
			cacheTargets = append(cacheTargets, t)
		}
	}
	if !aliasHasNow {
		if cachedResp, cachedUnindexed, hit := s.queryCache.GetWithMeta(cacheTargets, req); hit {
			cachedResp["took"] = int64(1)
			if len(cachedUnindexed) > 0 && len(targets) > 0 {
				threshold := s.getAutoPromoteThreshold()
				toPromote := s.slowTracker.recordWithThreshold(SlowQueryEntry{
					Timestamp:              time.Now().UTC().Format(time.RFC3339),
					Index:                  targets[0],
					TookMs:                 1,
					UnindexedVariantFields: cachedUnindexed,
				}, threshold)
				for _, fieldToPromote := range toPromote {
					_, _ = s.promoteFieldInternal(ctx, targets[0], fieldToPromote, "keyword")
				}
			}
			return cachedResp, http.StatusOK, "", ""
		}
	}

	from := 0
	if req.From != nil && *req.From > 0 {
		from = *req.From
	}
	size := 10
	if req.Size != nil {
		size = *req.Size
	} else if len(req.KNN) > 0 && req.KNN[0].K > 0 {
		size = req.KNN[0].K
	}

	var allHits []HitRow
	var allAggRows []AggRow
	var totalHitsSum int64
	var primarySchema *schema.IndexSchema
	schemasByIndex := make(map[string]*schema.IndexSchema, len(targets))
	var allUnindexedFields []string
	seenUnindexed := make(map[string]struct{})

	for _, indexName := range targets {
		idxSchema := s.ensureIndexSchema(ctx, indexName)
		schemasByIndex[indexName] = idxSchema
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
		subReqPtr := applyIndexAliasFilter(&subReq, aliasFilters[indexName])

		idxStart := time.Now()
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		plan, err := tr.BuildSearchPlan(subReqPtr)
		if err != nil {
			return nil, http.StatusBadRequest, "search_phase_execution_exception", err.Error()
		}
		for _, uf := range plan.UnindexedVariantFields {
			if _, ok := seenUnindexed[uf]; !ok {
				seenUnindexed[uf] = struct{}{}
				allUnindexedFields = append(allUnindexedFields, uf)
			}
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
		if len(hits) == 0 && from > 0 && plan.AggsSQL == "" && req.ShouldTrackTotalHits() {
			zero := 0
			cntReq := *subReqPtr
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

		var hasNonZeroAggRow bool
		bucketCounts := make(map[string]int64, len(aggRows))
		for _, r := range aggRows {
			if r.AggName == "__meta_total" {
				if idxTotal == 0 {
					idxTotal = r.effectiveCount()
				}
				continue
			}
			if r.effectiveCount() != 0 || r.effectiveValue() != 0 {
				hasNonZeroAggRow = true
			}
			bucketCounts[r.AggName+"\x00"+r.BucketKey] = r.effectiveCount()
		}
		if !req.ShouldTrackTotalHits() && idxTotal == 0 && len(hits) > 0 {
			idxTotal = int64(len(hits))
		}
		effAggs := req.EffectiveAggs()
		var hasGlobalAggRow bool
		if idxTotal == 0 && len(effAggs) > 0 {
			for _, r := range aggRows {
				if isUnderGlobalAgg(effAggs, r.AggName) {
					hasGlobalAggRow = true
					break
				}
			}
		}
		if len(targets) > 1 && idxTotal == 0 && !hasGlobalAggRow && (req.PostFilter == nil || !hasNonZeroAggRow) {
			for _, r := range aggRows {
				if r.AggName == "__meta_total" {
					allAggRows = append(allAggRows, r)
				}
			}
		} else if len(targets) > 1 {
			emptyStatsAggs := make(map[string]bool)
			emptySubStatsBuckets := make(map[string]bool)
			statsCounts := make(map[string]int64)
			for _, r := range aggRows {
				if r.BucketKey == "_stats_count" || r.BucketKey == "_sstats_count" {
					statsCounts[r.AggName] = r.effectiveCount()
					if r.effectiveCount() == 0 {
						emptyStatsAggs[r.AggName] = true
					}
				} else if strings.HasSuffix(r.AggName, "._stats_count") {
					baseAgg := strings.TrimSuffix(r.AggName, "._stats_count")
					statsCounts[baseAgg+"\x00"+r.BucketKey] = r.effectiveCount()
					if r.effectiveCount() == 0 {
						emptySubStatsBuckets[baseAgg+"\x00"+r.BucketKey] = true
					}
				}
			}
			for _, r := range aggRows {
				if idxTotal == 0 && r.AggName != "__meta_total" && req.PostFilter == nil && !isUnderGlobalAgg(effAggs, r.AggName) {
					continue
				}
				if emptyStatsAggs[r.AggName] && r.BucketKey != "_stats_count" && r.BucketKey != "_sstats_count" {
					continue
				}
				if dot := strings.LastIndexByte(r.AggName, '.'); dot > 0 && strings.HasPrefix(r.AggName[dot+1:], "_stats_") && r.AggName[dot+1:] != "_stats_count" {
					if emptySubStatsBuckets[r.AggName[:dot]+"\x00"+r.BucketKey] {
						continue
					}
				}
				if r.BucketKey == "_stats_avg" || r.BucketKey == "_sstats_avg" {
					if cnt := statsCounts[r.AggName]; cnt > 0 {
						r.Weight = cnt
					}
				} else if strings.HasSuffix(r.AggName, "._stats_avg") {
					baseAgg := strings.TrimSuffix(r.AggName, "._stats_avg")
					if cnt := statsCounts[baseAgg+"\x00"+r.BucketKey]; cnt > 0 {
						r.Weight = cnt
					}
				}
				if r.AggName != "__meta_total" {
					spec := resolveAggSpecByPath(effAggs, r.AggName)
					if metricField := singleValueMetricField(spec); metricField != "" {
						if r.effectiveValue() == 0 && !indexSchemaHasField(idxSchema, metricField) {
							continue
						}
						parent := parentBucketAggPath(effAggs, r.AggName)
						var w int64
						if parent != "" {
							w = bucketCounts[parent+"\x00"+r.BucketKey]
							if w == 0 {
								w = bucketCounts[parent+":"+r.BucketKey+"\x00"+r.BucketKey]
							}
							if w == 0 {
								for _, sentinel := range []string{"_filter", "_missing", "_nested_doc_count", "_global", "_reverse_nested", "_sampler"} {
									if cw := bucketCounts[parent+"\x00"+sentinel]; cw > 0 {
										w = cw
										break
									}
								}
							}
							if w == 0 && (spec.Min != nil || spec.Max != nil || spec.Avg != nil || spec.Percentiles != nil || spec.PercentileRanks != nil || spec.Boxplot != nil) {
								continue
							}
						} else if idxTotal > 0 {
							w = idxTotal
						}
						if w > 0 && r.Weight == 0 && (spec.Avg != nil || spec.Percentiles != nil || spec.PercentileRanks != nil || spec.Boxplot != nil) {
							r.Weight = w
						}
					}
				}
				allAggRows = append(allAggRows, r)
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
				sI := schemasByIndex[allHits[i].Index]
				if sI == nil {
					sI = primarySchema
				}
				sJ := schemasByIndex[allHits[j].Index]
				if sJ == nil {
					sJ = primarySchema
				}
				if cmp := compareHitRowsBySortWithSchemas(allHits[i], allHits[j], req.Sort, sI, sJ); cmp != 0 {
					return cmp < 0
				}
			}
			if allHits[i].Score != allHits[j].Score {
				return allHits[i].Score > allHits[j].Score
			}
			return allHits[i].ID < allHits[j].ID
		})
		if req.Collapse != nil && req.Collapse.Field != "" && len(allHits) > 1 {
			seenCollapse := make(map[string]struct{}, len(allHits))
			deduped := make([]HitRow, 0, len(allHits))
			collapseSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: req.Collapse.Field}}}
			for _, h := range allHits {
				hSchema := schemasByIndex[h.Index]
				if hSchema == nil {
					hSchema = primarySchema
				}
				vals := extractHitSortValues(h, collapseSort, hSchema)
				if len(vals) > 0 && vals[0] != nil {
					ck := fmt.Sprintf("%v", vals[0])
					if _, exists := seenCollapse[ck]; exists {
						continue
					}
					seenCollapse[ck] = struct{}{}
				}
				deduped = append(deduped, h)
			}
			allHits = deduped
		}
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
				if h, found, err := s.backend.GetDocByID(ctx, tSchema.DorisDB, tSchema.DorisTable, id); err == nil && found && h != nil {
					if af := aliasFilters[tName]; af != nil && !s.docMatchesAliasFilter(ctx, tName, id, h.Source, af) {
						continue
					}
					h.Index = tName
					return h
				}
			}
		}
		return nil
	}
	resp := buildESResponseWithSchemas(primaryIndex, primarySchema, schemasByIndex, req, allHits, allAggRows, tookMs, docLookup)
	if !aliasHasNow {
		s.queryCache.PutWithMeta(cacheTargets, req, resp, allUnindexedFields)
	}
	return resp, http.StatusOK, "", ""
}

func hasTermsLookupInSearchRequest(req *esast.SearchRequest) bool {
	if req == nil {
		return false
	}
	if hasTermsLookupInQuery(req.Query) || hasTermsLookupInQuery(req.PostFilter) || hasTermsLookupInQuery(req.AliasFilter) {
		return true
	}
	for i := range req.KNN {
		for j := range req.KNN[i].Filter {
			if hasTermsLookupInQuery(&req.KNN[i].Filter[j]) {
				return true
			}
		}
	}
	for _, spec := range req.EffectiveAggs() {
		if hasTermsLookupInAggSpec(spec) {
			return true
		}
	}
	return false
}

func hasTermsLookupInAggSpec(spec esast.AggSpec) bool {
	if spec.Filter != nil && hasTermsLookupInQuery(spec.Filter) {
		return true
	}
	if spec.Filters != nil {
		for i := range spec.Filters.Filters {
			q := spec.Filters.Filters[i]
			if hasTermsLookupInQuery(&q) {
				return true
			}
		}
		for i := range spec.Filters.AnonymousFilters {
			if hasTermsLookupInQuery(&spec.Filters.AnonymousFilters[i]) {
				return true
			}
		}
	}
	for _, sub := range spec.SubAggs() {
		if hasTermsLookupInAggSpec(sub) {
			return true
		}
	}
	return false
}

func hasTermsLookupInQuery(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Terms != nil && len(q.Terms.Lookups) > 0 {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if hasTermsLookupInQuery(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if hasTermsLookupInQuery(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if hasTermsLookupInQuery(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if hasTermsLookupInQuery(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && hasTermsLookupInQuery(&q.ConstantScore.Filter) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if hasTermsLookupInQuery(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if hasTermsLookupInQuery(&q.Boosting.Positive) || hasTermsLookupInQuery(&q.Boosting.Negative) {
			return true
		}
	}
	if q.Nested != nil && hasTermsLookupInQuery(&q.Nested.Query) {
		return true
	}
	if q.FunctionScore != nil {
		if hasTermsLookupInQuery(q.FunctionScore.Query) {
			return true
		}
		for i := range q.FunctionScore.Functions {
			if hasTermsLookupInQuery(q.FunctionScore.Functions[i].Filter) {
				return true
			}
		}
	}
	if q.ScriptScore != nil && hasTermsLookupInQuery(q.ScriptScore.Query) {
		return true
	}
	if q.KNN != nil {
		for i := range q.KNN.Filter {
			if hasTermsLookupInQuery(&q.KNN.Filter[i]) {
				return true
			}
		}
	}
	return false
}

func (s *Server) resolveTermsLookupsInSearchRequest(ctx context.Context, req *esast.SearchRequest) *esast.SearchRequest {
	if req == nil {
		return nil
	}
	origAliasFilter := req.AliasFilter
	if raw, err := json.Marshal(req); err == nil {
		var cloned esast.SearchRequest
		if err := json.Unmarshal(raw, &cloned); err == nil {
			if origAliasFilter != nil {
				if afRaw, err := json.Marshal(origAliasFilter); err == nil {
					var afCloned esast.Query
					if err := json.Unmarshal(afRaw, &afCloned); err == nil {
						origAliasFilter = &afCloned
					}
				}
			}
			cloned.AliasFilter = origAliasFilter
			req = &cloned
		}
	}
	s.resolveTermsLookupsInQuery(ctx, req.Query)
	s.resolveTermsLookupsInQuery(ctx, req.PostFilter)
	s.resolveTermsLookupsInQuery(ctx, req.AliasFilter)
	for i := range req.KNN {
		for j := range req.KNN[i].Filter {
			s.resolveTermsLookupsInQuery(ctx, &req.KNN[i].Filter[j])
		}
	}
	for k, spec := range req.Aggs {
		s.resolveTermsLookupsInAggSpec(ctx, &spec)
		req.Aggs[k] = spec
	}
	for k, spec := range req.Aggregations {
		s.resolveTermsLookupsInAggSpec(ctx, &spec)
		req.Aggregations[k] = spec
	}
	return req
}

func (s *Server) resolveTermsLookupsInAliasFilters(ctx context.Context, aliasFilters map[string]*esast.Query) map[string]*esast.Query {
	if len(aliasFilters) == 0 {
		return aliasFilters
	}
	hasLookup := false
	for _, af := range aliasFilters {
		if hasTermsLookupInQuery(af) {
			hasLookup = true
			break
		}
	}
	if !hasLookup {
		return aliasFilters
	}
	out := make(map[string]*esast.Query, len(aliasFilters))
	for idx, af := range aliasFilters {
		if af != nil && hasTermsLookupInQuery(af) {
			if raw, err := json.Marshal(af); err == nil {
				var cloned esast.Query
				if err := json.Unmarshal(raw, &cloned); err == nil {
					s.resolveTermsLookupsInQuery(ctx, &cloned)
					out[idx] = &cloned
					continue
				}
			}
		}
		out[idx] = af
	}
	return out
}

type termsLookupDepthKey struct{}

func (s *Server) resolveTermsLookupsInAggSpec(ctx context.Context, spec *esast.AggSpec) {
	if spec == nil {
		return
	}
	if spec.Filter != nil {
		s.resolveTermsLookupsInQuery(ctx, spec.Filter)
	}
	if spec.Filters != nil {
		for k, q := range spec.Filters.Filters {
			s.resolveTermsLookupsInQuery(ctx, &q)
			spec.Filters.Filters[k] = q
		}
		for i := range spec.Filters.AnonymousFilters {
			s.resolveTermsLookupsInQuery(ctx, &spec.Filters.AnonymousFilters[i])
		}
	}
	for k, sub := range spec.Aggs {
		s.resolveTermsLookupsInAggSpec(ctx, &sub)
		spec.Aggs[k] = sub
	}
	for k, sub := range spec.Aggregations {
		s.resolveTermsLookupsInAggSpec(ctx, &sub)
		spec.Aggregations[k] = sub
	}
}

func (s *Server) resolveTermsLookupsInQuery(ctx context.Context, q *esast.Query) {
	if q == nil {
		return
	}
	depth, _ := ctx.Value(termsLookupDepthKey{}).(int)
	if depth >= 4 {
		return
	}
	ctx = context.WithValue(ctx, termsLookupDepthKey{}, depth+1)
	if q.Terms != nil && len(q.Terms.Lookups) > 0 {
		if q.Terms.Fields == nil {
			q.Terms.Fields = make(map[string][]any, len(q.Terms.Lookups))
		}
		for field, lookup := range q.Terms.Lookups {
			var resolvedVals []any
			lookupIdx, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(lookup.Index)
			if readErr == nil {
				lookupSchema := s.getOrCompileReadOnlySchema(ctx, lookupIdx)
				if lookupSchema != nil {
					_ = s.coalescer.FlushTable(ctx, lookupSchema.DorisTable)
					if hit, found, err := s.backend.GetDocByID(ctx, lookupSchema.DorisDB, lookupSchema.DorisTable, lookup.ID); err == nil && found && hit != nil && len(hit.Source) > 0 && s.docMatchesAliasFilter(ctx, lookupIdx, lookup.ID, hit.Source, aliasFilter) {
						dec := json.NewDecoder(bytes.NewReader(hit.Source))
						dec.UseNumber()
						var doc map[string]any
						if err := dec.Decode(&doc); err == nil {
							rawVals := collectScalarValuesAtPath(doc, strings.Split(lookup.Path, "."))
							for _, v := range rawVals {
								if jn, ok := v.(json.Number); ok {
									if iv, err := jn.Int64(); err == nil {
										v = iv
									} else if fv, err := jn.Float64(); err == nil {
										v = fv
									} else {
										v = jn.String()
									}
								}
								resolvedVals = append(resolvedVals, v)
							}
						}
					}
				}
			}
			if resolvedVals == nil {
				resolvedVals = []any{}
			}
			q.Terms.Fields[field] = resolvedVals
		}
		q.Terms.Lookups = nil
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			s.resolveTermsLookupsInQuery(ctx, &q.Bool.Must[i])
		}
		for i := range q.Bool.Should {
			s.resolveTermsLookupsInQuery(ctx, &q.Bool.Should[i])
		}
		for i := range q.Bool.Filter {
			s.resolveTermsLookupsInQuery(ctx, &q.Bool.Filter[i])
		}
		for i := range q.Bool.MustNot {
			s.resolveTermsLookupsInQuery(ctx, &q.Bool.MustNot[i])
		}
	}
	if q.ConstantScore != nil {
		s.resolveTermsLookupsInQuery(ctx, &q.ConstantScore.Filter)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			s.resolveTermsLookupsInQuery(ctx, &q.DisMax.Queries[i])
		}
	}
	if q.Boosting != nil {
		s.resolveTermsLookupsInQuery(ctx, &q.Boosting.Positive)
		s.resolveTermsLookupsInQuery(ctx, &q.Boosting.Negative)
	}
	if q.Nested != nil {
		s.resolveTermsLookupsInQuery(ctx, &q.Nested.Query)
	}
	if q.FunctionScore != nil {
		s.resolveTermsLookupsInQuery(ctx, q.FunctionScore.Query)
		for i := range q.FunctionScore.Functions {
			s.resolveTermsLookupsInQuery(ctx, q.FunctionScore.Functions[i].Filter)
		}
	}
	if q.ScriptScore != nil {
		s.resolveTermsLookupsInQuery(ctx, q.ScriptScore.Query)
	}
	if q.KNN != nil {
		for i := range q.KNN.Filter {
			s.resolveTermsLookupsInQuery(ctx, &q.KNN.Filter[i])
		}
	}
}

func singleValueMetricField(spec esast.AggSpec) string {
	switch {
	case spec.Min != nil:
		return spec.Min.Field
	case spec.Max != nil:
		return spec.Max.Field
	case spec.Avg != nil:
		return spec.Avg.Field
	case spec.Sum != nil:
		return spec.Sum.Field
	case spec.Percentiles != nil:
		return spec.Percentiles.Field
	case spec.PercentileRanks != nil:
		return spec.PercentileRanks.Field
	case spec.Boxplot != nil:
		return spec.Boxplot.Field
	default:
		return ""
	}
}

func isUnderGlobalAgg(aggs map[string]esast.AggSpec, fullAggName string) bool {
	if len(aggs) == 0 || fullAggName == "" {
		return false
	}
	parts := strings.Split(fullAggName, ".")
	currMap := aggs
	for _, part := range parts {
		spec, ok := currMap[part]
		if !ok {
			return false
		}
		if spec.Global != nil {
			return true
		}
		currMap = spec.SubAggs()
	}
	return false
}

func parentBucketAggPath(aggs map[string]esast.AggSpec, fullAggName string) string {
	parts := strings.Split(fullAggName, ".")
	currMap := aggs
	var matched []string
	for _, part := range parts {
		spec, ok := currMap[part]
		if !ok {
			break
		}
		matched = append(matched, part)
		currMap = spec.SubAggs()
	}
	if len(matched) <= 1 {
		return ""
	}
	return strings.Join(matched[:len(matched)-1], ".")
}

func indexSchemaHasField(idxSchema *schema.IndexSchema, field string) bool {
	if idxSchema == nil || len(idxSchema.Fields) == 0 {
		return true
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	if _, ok := idxSchema.Fields[field]; ok {
		return true
	}
	if _, ok := idxSchema.Fields[clean]; ok {
		return true
	}
	return false
}

func parseIPv4SortUint32(v any) (uint32, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil || strings.Contains(s, ":") {
		return 0, false
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), true
}

func compareHitRowsBySort(a, b HitRow, sorts []esast.SortSpec, idxSchema *schema.IndexSchema) int {
	return compareHitRowsBySortWithSchemas(a, b, sorts, idxSchema, idxSchema)
}

func compareHitRowsBySortWithSchemas(a, b HitRow, sorts []esast.SortSpec, schemaA, schemaB *schema.IndexSchema) int {
	valsA := extractHitSortValues(a, sorts, schemaA)
	valsB := extractHitSortValues(b, sorts, schemaB)
	for idx, s := range sorts {
		if idx >= len(valsA) || idx >= len(valsB) {
			break
		}
		va, vb := valsA[idx], valsB[idx]
		if va == nil && vb == nil {
			continue
		}
		missingFirst := s.Entry.Missing != "" && strings.EqualFold(s.Entry.Missing, "_first")
		if va == nil {
			if missingFirst {
				return -1
			}
			return 1
		}
		if vb == nil {
			if missingFirst {
				return 1
			}
			return -1
		}
		var cmp int
		if ipA, okA := parseIPv4SortUint32(va); okA {
			if ipB, okB := parseIPv4SortUint32(vb); okB {
				if ipA < ipB {
					cmp = -1
				} else if ipA > ipB {
					cmp = 1
				}
			} else {
				cmp = compareAny(va, vb)
			}
		} else {
			cmp = compareAny(va, vb)
		}
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
			if i > 0 && (strings.HasPrefix(part, "_stats_") || (len(part) > 0 && part[0] >= '0' && part[0] <= '9')) {
				return spec
			}
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
		row         AggRow
		count       int
		weightSum   int64
		weightedVal float64
	}
	merged := make(map[key]*mergeAcc)
	var order []key
	lastStatCount := make(map[key]int64)
	lastStatSum := make(map[key]float64)
	accumulateRow := func(r AggRow) {
		k := key{agg: r.AggName, bucket: r.BucketKey}
		spec := resolveAggSpecByPath(aggs, r.AggName)
		val := r.effectiveValue()
		w := r.Weight
		if w <= 0 {
			w = 1
		}
		isMin := r.BucketKey == "_stats_min" || strings.HasSuffix(r.AggName, "._stats_min") || spec.Min != nil ||
			(spec.Boxplot != nil && (r.BucketKey == "0.0" || strings.HasSuffix(r.AggName, ".0.0")))
		isMax := r.BucketKey == "_stats_max" || strings.HasSuffix(r.AggName, "._stats_max") || spec.Max != nil ||
			(spec.Boxplot != nil && (r.BucketKey == "100.0" || strings.HasSuffix(r.AggName, ".100.0")))
		if existing, ok := merged[k]; ok {
			existing.count++
			existing.weightSum += w
			existing.weightedVal += val * float64(w)
			switch {
			case isMin:
				if val < existing.row.Value {
					existing.row.Value = val
					existing.row.DocCount = int64(val)
				}
			case isMax:
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
			cp.Value = val
			merged[k] = &mergeAcc{
				row:         cp,
				count:       1,
				weightSum:   w,
				weightedVal: val * float64(w),
			}
			order = append(order, k)
		}
	}
	for _, r := range rows {
		if r.AggName == "__meta_total" {
			continue
		}
		switch {
		case r.BucketKey == "_stats_count":
			lastStatCount[key{agg: r.AggName, bucket: ""}] = r.effectiveCount()
		case strings.HasSuffix(r.AggName, "._stats_count"):
			lastStatCount[key{agg: strings.TrimSuffix(r.AggName, "._stats_count"), bucket: r.BucketKey}] = r.effectiveCount()
		case r.BucketKey == "_stats_sum":
			lastStatSum[key{agg: r.AggName, bucket: ""}] = r.effectiveValue()
		case strings.HasSuffix(r.AggName, "._stats_sum"):
			lastStatSum[key{agg: strings.TrimSuffix(r.AggName, "._stats_sum"), bucket: r.BucketKey}] = r.effectiveValue()
		case r.BucketKey == "_stats_std":
			sk := key{agg: r.AggName, bucket: ""}
			if cnt := lastStatCount[sk]; cnt > 0 {
				avg := lastStatSum[sk] / float64(cnt)
				std := r.effectiveValue()
				sq := float64(cnt) * (std*std + avg*avg)
				accumulateRow(AggRow{AggName: r.AggName, BucketKey: "_stats_sum_sq", DocCount: int64(sq), Value: sq})
			}
		case strings.HasSuffix(r.AggName, "._stats_std"):
			baseAgg := strings.TrimSuffix(r.AggName, "._stats_std")
			sk := key{agg: baseAgg, bucket: r.BucketKey}
			if cnt := lastStatCount[sk]; cnt > 0 {
				avg := lastStatSum[sk] / float64(cnt)
				std := r.effectiveValue()
				sq := float64(cnt) * (std*std + avg*avg)
				accumulateRow(AggRow{AggName: baseAgg + "._stats_sum_sq", BucketKey: r.BucketKey, DocCount: int64(sq), Value: sq})
			}
		}
		accumulateRow(r)
	}
	out := []AggRow{{AggName: "__meta_total", BucketKey: "_count", DocCount: totalHits, Value: float64(totalHits)}}
	for _, k := range order {
		acc := merged[k]
		spec := resolveAggSpecByPath(aggs, k.agg)
		isBoxplotQuartile := spec.Boxplot != nil && k.bucket != "0.0" && k.bucket != "100.0" &&
			!strings.HasSuffix(k.agg, ".0.0") && !strings.HasSuffix(k.agg, ".100.0")
		isAvgLike := k.bucket == "_stats_avg" || k.bucket == "_stats_std" || k.bucket == "_stats_entropy" ||
			strings.HasSuffix(k.agg, "._stats_avg") || strings.HasSuffix(k.agg, "._stats_std") || strings.HasSuffix(k.agg, "._stats_entropy") ||
			spec.Avg != nil || spec.Percentiles != nil || spec.PercentileRanks != nil || isBoxplotQuartile
		if isAvgLike && acc.count > 1 && acc.weightSum > 0 {
			acc.row.Value = acc.weightedVal / float64(acc.weightSum)
			acc.row.DocCount = int64(acc.row.Value)
		} else if isAvgLike && acc.count > 1 {
			acc.row.Value /= float64(acc.count)
			acc.row.DocCount = int64(acc.row.Value)
		}
		out = append(out, acc.row)
	}
	return out
}

func (s *Server) handleCount(w http.ResponseWriter, r *http.Request) {
	var req esast.SearchRequest
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	applyURISearchParams(r, &req)
	zero := 0
	req.Size = &zero
	req.TrackTotalHits = true

	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), r.PathValue("index"), &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	var count int64
	if hitsObj, ok := resp["hits"].(map[string]any); ok {
		if totalObj, ok := hitsObj["total"].(map[string]any); ok {
			if v, ok := toInt64(totalObj["value"]); ok {
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
	if tth := q.Get("track_total_hits"); tth != "" && req.TrackTotalHits == nil {
		if strings.EqualFold(tth, "false") {
			req.TrackTotalHits = false
		} else if strings.EqualFold(tth, "true") {
			req.TrackTotalHits = true
		} else if n, err := strconv.ParseInt(tth, 10, 64); err == nil {
			req.TrackTotalHits = n
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
	return buildESResponseWithSchemas(indexName, idxSchema, nil, req, hits, aggRows, tookMs, docLookup)
}

func buildESResponseWithSchemas(indexName string, idxSchema *schema.IndexSchema, schemasByIndex map[string]*schema.IndexSchema, req *esast.SearchRequest, hits []HitRow, aggRows []AggRow, tookMs int64, docLookup func(string) *HitRow) map[string]any {
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
		hitSchema := idxSchema
		if schemasByIndex != nil {
			if s, ok := schemasByIndex[hitIdx]; ok && s != nil {
				hitSchema = s
			}
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
			hitMap["sort"] = extractHitSortValues(h, req.Sort, hitSchema)
		}
		if len(req.Fields) > 0 || len(req.DocvalueFields) > 0 {
			if fm := extractHitFieldsMap(h, hitIdx, req, hitSchema); len(fm) > 0 {
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

	hitsEnvelope := map[string]any{
		"max_score": maxScore,
		"hits":      esHits,
	}
	if req.ShouldTrackTotalHits() {
		relation := "eq"
		reportedTotal := totalHits
		if thresh, ok := trackTotalHitsThreshold(req); ok && thresh > 0 && totalHits > thresh {
			reportedTotal = thresh
			relation = "gte"
		}
		hitsEnvelope["total"] = map[string]any{
			"value":    reportedTotal,
			"relation": relation,
		}
	}

	res := map[string]any{
		"took":      tookMs,
		"timed_out": false,
		"_shards":   map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
		"hits":      hitsEnvelope,
	}
	if len(aggsOut) > 0 {
		res["aggregations"] = aggsOut
	}
	return res
}

func trackTotalHitsThreshold(req *esast.SearchRequest) (int64, bool) {
	if req == nil || req.TrackTotalHits == nil {
		return 0, false
	}
	switch v := req.TrackTotalHits.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return iv, true
		}
	}
	return 0, false
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
		case spec.EffectiveTerms() != nil:
			termsSpec := spec.EffectiveTerms()
			isSig := spec.IsSignificantTerms()
			rows = filterAndSortTermsRows(rows, termsSpec, fullKey, "", bucketsByAgg)
			b := make([]map[string]any, 0, len(rows))
			subAggs := spec.SubAggs()
			sigTotal := totalHits
			for _, r := range rows {
				if dc := r.effectiveCount(); dc > sigTotal {
					sigTotal = dc
				}
			}
			bgDenom := float64(sigTotal)
			if bgDenom < 1 {
				bgDenom = 1
			}
			for _, r := range rows {
				docCnt := r.effectiveCount()
				bucketMap := map[string]any{
					"key":       r.BucketKey,
					"doc_count": docCnt,
				}
				if isSig {
					fgProb := float64(docCnt) / bgDenom
					score := math.Round(fgProb*float64(docCnt)*10000) / 10000
					if math.IsNaN(score) || math.IsInf(score, 0) {
						score = 0
					}
					bucketMap["score"] = score
					bucketMap["bg_count"] = docCnt
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				b = append(b, bucketMap)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggs(b, subAggs)
			}
			if isSig {
				aggsOut[aggName] = map[string]any{
					"doc_count": sigTotal,
					"bg_count":  sigTotal,
					"buckets":   b,
				}
			} else {
				aggsOut[aggName] = map[string]any{
					"doc_count_error_upper_bound": 0,
					"sum_other_doc_count":         0,
					"buckets":                     b,
				}
			}
		case spec.Nested != nil:
			nestedCnt := totalHits
			for _, r := range rows {
				if r.BucketKey == "_nested_doc_count" {
					nestedCnt = r.effectiveCount()
					break
				}
			}
			nestedObj := map[string]any{"doc_count": nestedCnt}
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				directSubAggs := make(map[string]esast.AggSpec)
				groupedSubAggs := make(map[string]esast.AggSpec)
				for sn, ss := range subAggs {
					switch {
					case ss.EffectiveTerms() != nil, ss.Cardinality != nil, ss.ValueCount != nil,
						ss.Avg != nil, ss.Sum != nil, ss.Min != nil, ss.Max != nil,
						ss.EffectiveStats() != nil, ss.StringStats != nil, ss.Percentiles != nil,
						ss.Boxplot != nil, ss.ReverseNested != nil:
						directSubAggs[sn] = ss
					default:
						groupedSubAggs[sn] = ss
					}
				}
				if len(directSubAggs) > 0 {
					for sk, sv := range buildAggsMap(indexName, fullKey, directSubAggs, bucketsByAgg, nestedCnt, docLookup) {
						nestedObj[sk] = sv
					}
				}
				if len(groupedSubAggs) > 0 {
					attachSubAggsToBucket(indexName, nestedObj, fullKey, "_nested_doc_count", groupedSubAggs, bucketsByAgg, docLookup)
				}
				_ = evaluateChildPipelineAggs([]map[string]any{nestedObj}, subAggs)
				evaluateSiblingPipelineAggs(subAggs, nestedObj)
			}
			aggsOut[aggName] = nestedObj
		case spec.Global != nil || spec.ReverseNested != nil || spec.EffectiveSampler() != nil:
			cnt := totalHits
			if len(rows) > 0 {
				cnt = rows[0].effectiveCount()
			}
			containerObj := map[string]any{"doc_count": cnt}
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				for sk, sv := range buildAggsMap(indexName, fullKey, subAggs, bucketsByAgg, cnt, docLookup) {
					containerObj[sk] = sv
				}
				_ = evaluateChildPipelineAggs([]map[string]any{containerObj}, subAggs)
				evaluateSiblingPipelineAggs(subAggs, containerObj)
			}
			aggsOut[aggName] = containerObj
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
				_ = evaluateChildPipelineAggs([]map[string]any{filterObj}, subAggs)
				evaluateSiblingPipelineAggs(subAggs, filterObj)
			}
			aggsOut[aggName] = filterObj
		case spec.Filters != nil:
			byKey := make(map[string]int64, len(rows))
			for _, r := range rows {
				byKey[r.BucketKey] = r.effectiveCount()
			}
			subAggs := spec.SubAggs()
			if spec.Filters.IsAnonymous {
				ordered := make([]map[string]any, 0, len(spec.Filters.AnonymousFilters)+1)
				for i := range spec.Filters.AnonymousFilters {
					fk := strconv.Itoa(i)
					bMap := map[string]any{"doc_count": byKey[fk]}
					if len(subAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, fullKey, fk, subAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if spec.Filters.OtherBucket {
					otherKey := spec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(subAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, fullKey, otherKey, subAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if len(subAggs) > 0 {
					ordered = evaluateChildPipelineAggs(ordered, subAggs)
				}
				aggsOut[aggName] = map[string]any{"buckets": ordered}
			} else {
				bucketsMap := make(map[string]any, len(spec.Filters.Filters)+1)
				for fk := range spec.Filters.Filters {
					bMap := map[string]any{
						"doc_count": byKey[fk],
					}
					if len(subAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, fullKey, fk, subAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					bucketsMap[fk] = bMap
				}
				if spec.Filters.OtherBucket {
					otherKey := spec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{
						"doc_count": byKey[otherKey],
					}
					if len(subAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, fullKey, otherKey, subAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					bucketsMap[otherKey] = bMap
				}
				if len(subAggs) > 0 {
					keys := make([]string, 0, len(bucketsMap))
					for fk := range bucketsMap {
						keys = append(keys, fk)
					}
					sort.Strings(keys)
					ordered := make([]map[string]any, 0, len(keys))
					for _, fk := range keys {
						if bm, ok := bucketsMap[fk].(map[string]any); ok {
							bm["__filter_key"] = fk
							bm["key"] = fk
							ordered = append(ordered, bm)
						}
					}
					ordered = evaluateChildPipelineAggs(ordered, subAggs)
					if spec.Filters.Keyed != nil && !*spec.Filters.Keyed {
						for _, bm := range ordered {
							delete(bm, "__filter_key")
						}
						aggsOut[aggName] = map[string]any{"buckets": ordered}
					} else {
						newBucketsMap := make(map[string]any, len(ordered))
						for _, bm := range ordered {
							fk, _ := bm["__filter_key"].(string)
							delete(bm, "__filter_key")
							delete(bm, "key")
							newBucketsMap[fk] = bm
						}
						aggsOut[aggName] = map[string]any{"buckets": newBucketsMap}
					}
				} else if spec.Filters.Keyed != nil && !*spec.Filters.Keyed {
					keys := make([]string, 0, len(bucketsMap))
					for fk := range bucketsMap {
						keys = append(keys, fk)
					}
					sort.Strings(keys)
					arr := make([]map[string]any, 0, len(keys))
					for _, fk := range keys {
						if bm, ok := bucketsMap[fk].(map[string]any); ok {
							bm["key"] = fk
							arr = append(arr, bm)
						}
					}
					aggsOut[aggName] = map[string]any{"buckets": arr}
				} else {
					aggsOut[aggName] = map[string]any{"buckets": bucketsMap}
				}
			}
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
		case spec.Rate != nil:
			var val float64
			if len(rows) > 0 {
				val = rows[0].effectiveValue()
			}
			aggsOut[aggName] = map[string]any{"value": val}
		case spec.EffectiveStats() != nil:
			aggsOut[aggName] = buildStatsAggObject(rows, spec.ExtendedStats)
		case spec.StringStats != nil:
			var cntVal int64
			var minLen, maxLen, avgLen, entropyVal float64
			for _, r := range rows {
				switch r.BucketKey {
				case "_stats_count", "_sstats_count":
					cntVal = r.effectiveCount()
				case "_stats_min", "_sstats_min":
					minLen = r.effectiveValue()
				case "_stats_max", "_sstats_max":
					maxLen = r.effectiveValue()
				case "_stats_avg", "_sstats_avg":
					avgLen = r.effectiveValue()
				case "_stats_entropy", "_sstats_entropy":
					entropyVal = r.effectiveValue()
				}
			}
			aggsOut[aggName] = map[string]any{
				"count":      cntVal,
				"min_length": int64(minLen),
				"max_length": int64(maxLen),
				"avg_length": avgLen,
				"entropy":    entropyVal,
			}
		case spec.Boxplot != nil:
			var minVal, maxVal, q1, q2, q3 float64
			for _, r := range rows {
				switch r.BucketKey {
				case "0.0", "_box_min":
					minVal = r.effectiveValue()
				case "100.0", "_box_max":
					maxVal = r.effectiveValue()
				case "25.0", "_box_q1":
					q1 = r.effectiveValue()
				case "50.0", "_box_q2":
					q2 = r.effectiveValue()
				case "75.0", "_box_q3":
					q3 = r.effectiveValue()
				}
			}
			iqr := q3 - q1
			lower := math.Max(minVal, q1-1.5*iqr)
			upper := math.Min(maxVal, q3+1.5*iqr)
			aggsOut[aggName] = map[string]any{
				"min":   minVal,
				"max":   maxVal,
				"q1":    q1,
				"q2":    q2,
				"q3":    q3,
				"lower": lower,
				"upper": upper,
			}
		case spec.Percentiles != nil:
			if spec.Percentiles.Keyed != nil && !*spec.Percentiles.Keyed {
				valuesArr := make([]map[string]any, 0, len(rows))
				for _, r := range rows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": r.effectiveValue(),
					})
				}
				aggsOut[aggName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]float64, len(rows))
				for _, r := range rows {
					valuesMap[r.BucketKey] = r.effectiveValue()
				}
				aggsOut[aggName] = map[string]any{"values": valuesMap}
			}
		case spec.PercentileRanks != nil:
			if spec.PercentileRanks.Keyed != nil && !*spec.PercentileRanks.Keyed {
				valuesArr := make([]map[string]any, 0, len(rows))
				for _, r := range rows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": r.effectiveValue(),
					})
				}
				aggsOut[aggName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]float64, len(rows))
				for _, r := range rows {
					valuesMap[r.BucketKey] = r.effectiveValue()
				}
				aggsOut[aggName] = map[string]any{"values": valuesMap}
			}
		case spec.DateHistogram != nil:
			rows = synthesizeDateHistogramBuckets(rows, spec.DateHistogram)
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
					scaleBucketRates(bucketMap, subAggs, &spec)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				b = append(b, bucketMap)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggs(b, subAggs)
			}
			aggsOut[aggName] = formatKeyedBuckets(b, spec.DateHistogram.Keyed, "key_as_string")
		case spec.Histogram != nil:
			rows = synthesizeHistogramBuckets(rows, spec.Histogram)
			if len(rows) > 1 {
				sort.SliceStable(rows, func(i, j int) bool {
					ki, _ := parseFiniteFloat(rows[i].BucketKey)
					kj, _ := parseFiniteFloat(rows[j].BucketKey)
					return ki < kj
				})
			}
			b := make([]map[string]any, 0, len(rows))
			subAggs := spec.SubAggs()
			for _, r := range rows {
				numKey, _ := parseFiniteFloat(r.BucketKey)
				bucketMap := map[string]any{
					"key":       numKey,
					"doc_count": r.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup)
					scaleBucketRates(bucketMap, subAggs, &spec)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				b = append(b, bucketMap)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggs(b, subAggs)
			}
			aggsOut[aggName] = formatKeyedBuckets(b, spec.Histogram.Keyed, "key")
		case spec.EffectiveRange() != nil:
			rngSpec := spec.EffectiveRange()
			isDateRange := spec.DateRange != nil
			isIPRange := spec.IPRange != nil
			nowUTC := time.Now().UTC()
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
				if rng.Mask != "" && isIPRange {
					entry["mask"] = rng.Mask
					if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(rng.Mask)); err == nil && ipNet != nil {
						startIP := ipNet.IP.To4()
						mask := ipNet.Mask
						if len(startIP) == 4 && len(mask) == 4 {
							endIP := net.IPv4(
								startIP[0]|^mask[0],
								startIP[1]|^mask[1],
								startIP[2]|^mask[2],
								startIP[3]|^mask[3],
							)
							entry["from"] = startIP.String()
							entry["to"] = endIP.String()
						}
					}
				}
				if rng.From != nil {
					entry["from"] = rng.From
					if isDateRange {
						if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", rng.From), nowUTC, false); ok {
							entry["from"] = float64(ms)
							entry["from_as_string"] = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
						}
					}
				}
				if rng.To != nil {
					entry["to"] = rng.To
					if isDateRange {
						if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", rng.To), nowUTC, false); ok {
							entry["to"] = float64(ms)
							entry["to_as_string"] = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
						}
					}
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, entry, fullKey, ek, subAggs, bucketsByAgg, docLookup)
					evaluateSiblingPipelineAggs(subAggs, entry)
				}
				b = append(b, entry)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggs(b, subAggs)
			}
			aggsOut[aggName] = formatKeyedBuckets(b, rngSpec.Keyed, "key")
		case spec.TopHits != nil:
			topHitsList := buildTopHitsList(indexName, rows, spec.TopHits, docLookup)
			thTotal := totalHits
			if int64(len(topHitsList)) > thTotal {
				thTotal = int64(len(topHitsList))
			}
			aggsOut[aggName] = map[string]any{
				"hits": map[string]any{
					"total":     map[string]any{"value": thTotal, "relation": "eq"},
					"max_score": 1.0,
					"hits":      topHitsList,
				},
			}
		case spec.TopMetrics != nil:
			aggsOut[aggName] = buildTopMetricsObject(rows, spec.TopMetrics, docLookup)
		case spec.Composite != nil:
			type compSrcMeta struct {
				name  string
				entry esast.AggSpec
			}
			var srcMetas []compSrcMeta
			for _, srcMap := range spec.Composite.Sources {
				var ks []string
				for k := range srcMap {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				for _, k := range ks {
					srcMetas = append(srcMetas, compSrcMeta{name: k, entry: srcMap[k]})
				}
			}
			type decodedCompRow struct {
				row    AggRow
				keyObj map[string]any
			}
			decoded := make([]decodedCompRow, 0, len(rows))
			for _, r := range rows {
				parts := splitCompositeBucketKey(r.BucketKey)
				keyObj := make(map[string]any, len(srcMetas))
				for i, sm := range srcMetas {
					if i < len(parts) {
						if parts[i] == "__ES_MISSING_BUCKET__" {
							keyObj[sm.name] = nil
							continue
						}
						partVal := any(parts[i])
						if sm.entry.DateHistogram != nil {
							if iv, err := strconv.ParseInt(parts[i], 10, 64); err == nil {
								partVal = iv
							}
						} else if sm.entry.Histogram != nil {
							if iv, err := strconv.ParseInt(parts[i], 10, 64); err == nil {
								partVal = iv
							} else if fv, ok := parseFiniteFloat(parts[i]); ok {
								partVal = fv
							}
						}
						keyObj[sm.name] = partVal
					}
				}
				if len(spec.Composite.After) > 0 {
					cmpAfter := 0
					for _, sm := range srcMetas {
						afterVal, ok := spec.Composite.After[sm.name]
						if !ok {
							continue
						}
						cmpAfter = compareCompositeSourceVal(keyObj[sm.name], afterVal, sm.entry)
						if cmpAfter != 0 {
							break
						}
					}
					if cmpAfter <= 0 {
						continue
					}
				}
				decoded = append(decoded, decodedCompRow{row: r, keyObj: keyObj})
			}
			if len(decoded) > 1 {
				sort.SliceStable(decoded, func(i, j int) bool {
					for _, sm := range srcMetas {
						cmp := compareCompositeSourceVal(decoded[i].keyObj[sm.name], decoded[j].keyObj[sm.name], sm.entry)
						if cmp != 0 {
							return cmp < 0
						}
					}
					return decoded[i].row.BucketKey < decoded[j].row.BucketKey
				})
			}
			compLimit := spec.Composite.Size
			if compLimit <= 0 {
				compLimit = 10
			}
			if compLimit > transpiler.DefaultMaxAggBuckets {
				compLimit = transpiler.DefaultMaxAggBuckets
			}
			if len(decoded) > compLimit {
				decoded = decoded[:compLimit]
			}
			buckets := make([]map[string]any, 0, len(decoded))
			var afterKey map[string]any
			subAggs := spec.SubAggs()
			for _, d := range decoded {
				afterKey = d.keyObj
				bucketMap := map[string]any{
					"key":       d.keyObj,
					"doc_count": d.row.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucket(indexName, bucketMap, fullKey, d.row.BucketKey, subAggs, bucketsByAgg, docLookup)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				buckets = append(buckets, bucketMap)
			}
			if len(subAggs) > 0 {
				buckets = evaluateChildPipelineAggs(buckets, subAggs)
			}
			compObj := map[string]any{"buckets": buckets}
			if afterKey != nil {
				compObj["after_key"] = afterKey
			}
			aggsOut[aggName] = compObj
		}
	}
	evaluateSiblingPipelineAggs(aggs, aggsOut)
	return aggsOut
}

func extractCompositeSourceOrder(order any) string {
	switch v := order.(type) {
	case string:
		return v
	case map[string]any:
		for _, dir := range v {
			if s, ok := dir.(string); ok {
				return s
			}
		}
	}
	return ""
}

func compareCompositeSourceVal(a, b any, entry esast.AggSpec) int {
	if a == nil && b == nil {
		return 0
	}
	var orderStr, missingOrder string
	switch {
	case entry.Terms != nil:
		orderStr = extractCompositeSourceOrder(entry.Terms.Order)
		missingOrder = entry.Terms.MissingOrder
	case entry.DateHistogram != nil:
		orderStr = extractCompositeSourceOrder(entry.DateHistogram.Order)
		missingOrder = entry.DateHistogram.MissingOrder
	case entry.Histogram != nil:
		orderStr = extractCompositeSourceOrder(entry.Histogram.Order)
		missingOrder = entry.Histogram.MissingOrder
	}
	desc := strings.EqualFold(orderStr, "desc")
	nullFirst := true
	if strings.EqualFold(missingOrder, "last") {
		nullFirst = false
	} else if strings.EqualFold(missingOrder, "first") {
		nullFirst = true
	} else if desc {
		nullFirst = false
	}
	if a == nil {
		if nullFirst {
			return -1
		}
		return 1
	}
	if b == nil {
		if nullFirst {
			return 1
		}
		return -1
	}
	cmp := compareAny(a, b)
	if desc {
		return -cmp
	}
	return cmp
}

func formatKeyedBuckets(buckets []map[string]any, keyed bool, keyField string) map[string]any {
	if keyed {
		bMap := make(map[string]any, len(buckets))
		for _, bm := range buckets {
			kStr := fmt.Sprintf("%v", bm[keyField])
			if kStr == "<nil>" || kStr == "" {
				kStr = fmt.Sprintf("%v", bm["key"])
			}
			bMap[kStr] = bm
		}
		return map[string]any{"buckets": bMap}
	}
	return map[string]any{"buckets": buckets}
}

func rateUnitToMs(unit string) int64 {
	trimmed := strings.TrimSpace(unit)
	if trimmed == "M" || trimmed == "1M" {
		return 30 * 86400 * 1000
	}
	switch strings.ToLower(trimmed) {
	case "ms", "millisecond", "milliseconds", "1ms":
		return 1
	case "s", "sec", "second", "seconds", "1s":
		return 1000
	case "m", "min", "minute", "minutes", "1m":
		return 60 * 1000
	case "h", "hr", "hour", "hours", "1h":
		return 3600 * 1000
	case "d", "day", "days", "1d":
		return 86400 * 1000
	case "w", "wk", "week", "weeks", "1w":
		return 7 * 86400 * 1000
	case "month", "months":
		return 30 * 86400 * 1000
	case "q", "quarter", "quarters", "1q":
		return 90 * 86400 * 1000
	case "y", "yr", "year", "years", "1y":
		return 365 * 86400 * 1000
	default:
		if trimmed == "" {
			return 0
		}
		dh := esast.DateHistogramAggSpec{FixedInterval: trimmed}
		return dh.EffectiveIntervalMs()
	}
}

func rateScaleFactor(rateSpec *esast.RateAggSpec, histSpec *esast.AggSpec) float64 {
	if rateSpec == nil || histSpec == nil {
		return 1.0
	}
	if histSpec.DateHistogram != nil {
		bucketMs := histSpec.DateHistogram.EffectiveIntervalMs()
		if bucketMs <= 0 {
			bucketMs = 86400000
		}
		unitMs := rateUnitToMs(rateSpec.Unit)
		if unitMs <= 0 {
			return 1.0
		}
		return float64(unitMs) / float64(bucketMs)
	}
	if histSpec.Histogram != nil && histSpec.Histogram.Interval > 0 {
		return 1.0 / histSpec.Histogram.Interval
	}
	return 1.0
}

func scaleBucketRates(bucketMap map[string]any, subAggs map[string]esast.AggSpec, histSpec *esast.AggSpec) {
	if bucketMap == nil || len(subAggs) == 0 || histSpec == nil {
		return
	}
	for subName, subSpec := range subAggs {
		subMap, ok := bucketMap[subName].(map[string]any)
		if !ok {
			continue
		}
		if subSpec.Rate != nil {
			scale := rateScaleFactor(subSpec.Rate, histSpec)
			if scale != 1.0 && scale > 0 {
				if v, okV := toFloat64(subMap["value"]); okV {
					subMap["value"] = v * scale
				}
			}
			continue
		}
		if grandSubAggs := subSpec.SubAggs(); len(grandSubAggs) > 0 {
			if childBuckets, okB := subMap["buckets"].([]map[string]any); okB {
				for _, cb := range childBuckets {
					scaleBucketRates(cb, grandSubAggs, histSpec)
				}
			} else if keyedBuckets, okK := subMap["buckets"].(map[string]any); okK {
				for _, v := range keyedBuckets {
					if cb, okCB := v.(map[string]any); okCB {
						scaleBucketRates(cb, grandSubAggs, histSpec)
					}
				}
			} else {
				scaleBucketRates(subMap, grandSubAggs, histSpec)
			}
		}
	}
}

func buildStatsAggObject(rows []AggRow, extSpec *esast.MetricAggSpec) map[string]any {
	statsMap := map[string]any{
		"count": int64(0),
		"min":   nil,
		"max":   nil,
		"avg":   nil,
		"sum":   0.0,
	}
	var cntVal int64
	var minVal, maxVal, sumVal, avgVal, sumSqVal, stdVal float64
	var hasMin, hasMax, hasSum, hasAvg, hasSumSq, hasStd bool
	for _, r := range rows {
		switch r.BucketKey {
		case "_stats_count":
			cntVal = r.effectiveCount()
			statsMap["count"] = cntVal
		case "_stats_min":
			minVal = r.effectiveValue()
			hasMin = true
		case "_stats_max":
			maxVal = r.effectiveValue()
			hasMax = true
		case "_stats_avg":
			avgVal = r.effectiveValue()
			hasAvg = true
		case "_stats_sum":
			sumVal = r.effectiveValue()
			hasSum = true
			statsMap["sum"] = sumVal
		case "_stats_sum_sq":
			sumSqVal = r.effectiveValue()
			hasSumSq = true
		case "_stats_std":
			stdVal = r.effectiveValue()
			hasStd = true
		}
	}
	if cntVal > 0 {
		if hasMin {
			statsMap["min"] = minVal
		} else {
			statsMap["min"] = 0.0
		}
		if hasMax {
			statsMap["max"] = maxVal
		} else {
			statsMap["max"] = 0.0
		}
		if hasSum {
			avgVal = sumVal / float64(cntVal)
			statsMap["avg"] = avgVal
		} else if hasAvg {
			statsMap["avg"] = avgVal
		} else {
			statsMap["avg"] = 0.0
		}
	}
	if extSpec != nil {
		if cntVal == 0 {
			statsMap["sum_of_squares"] = nil
			statsMap["variance"] = nil
			statsMap["variance_population"] = nil
			statsMap["variance_sampling"] = nil
			statsMap["std_deviation"] = nil
			statsMap["std_deviation_population"] = nil
			statsMap["std_deviation_sampling"] = nil
			statsMap["std_deviation_bounds"] = map[string]any{
				"upper":            nil,
				"lower":            nil,
				"upper_population": nil,
				"lower_population": nil,
				"upper_sampling":   nil,
				"lower_sampling":   nil,
			}
			return statsMap
		}
		var variancePop, varianceSampling float64
		if hasSumSq {
			variancePop = math.Max(0, (sumSqVal/float64(cntVal))-(avgVal*avgVal))
			if cntVal > 1 {
				varianceSampling = variancePop * float64(cntVal) / float64(cntVal-1)
			}
		} else if hasStd {
			variancePop = stdVal * stdVal
			if cntVal > 1 {
				varianceSampling = variancePop * float64(cntVal) / float64(cntVal-1)
			}
		}
		if !hasSumSq {
			sumSqVal = float64(cntVal) * (variancePop + avgVal*avgVal)
		}
		if !hasStd || hasSumSq {
			stdVal = math.Sqrt(variancePop)
		}
		stdSampling := math.Sqrt(varianceSampling)
		sigma := extSpec.EffectiveSigma()
		upperPop := avgVal + sigma*stdVal
		lowerPop := avgVal - sigma*stdVal
		upperSamp := avgVal + sigma*stdSampling
		lowerSamp := avgVal - sigma*stdSampling
		statsMap["sum_of_squares"] = sumSqVal
		statsMap["variance"] = variancePop
		statsMap["variance_population"] = variancePop
		statsMap["variance_sampling"] = varianceSampling
		statsMap["std_deviation"] = stdVal
		statsMap["std_deviation_population"] = stdVal
		statsMap["std_deviation_sampling"] = stdSampling
		statsMap["std_deviation_bounds"] = map[string]any{
			"upper":            upperPop,
			"lower":            lowerPop,
			"upper_population": upperPop,
			"lower_population": lowerPop,
			"upper_sampling":   upperSamp,
			"lower_sampling":   lowerSamp,
		}
	}
	return statsMap
}

func buildTopMetricsObject(rows []AggRow, spec *esast.TopMetricsAggSpec, docLookup func(string) *HitRow) map[string]any {
	if spec == nil {
		return map[string]any{"top": []any{}}
	}
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
	} else if len(candidates) > 1 {
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].docID < candidates[j].docID
		})
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	metricFields := spec.EffectiveMetricFields()
	topList := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		metricsMap := make(map[string]any, len(metricFields))
		var sortVals []any
		if c.hit != nil && len(c.hit.Source) > 0 {
			var doc map[string]any
			dec := json.NewDecoder(bytes.NewReader(c.hit.Source))
			dec.UseNumber()
			if err := dec.Decode(&doc); err == nil {
				for _, mf := range metricFields {
					cleanF := strings.TrimSuffix(strings.TrimSuffix(mf, ".keyword"), ".ngram")
					v := lookupDocPath(doc, strings.Split(cleanF, "."))
					if jn, ok := v.(json.Number); ok {
						if iv, err := jn.Int64(); err == nil {
							v = iv
						} else if fv, err := jn.Float64(); err == nil {
							v = fv
						}
					}
					metricsMap[mf] = v
				}
			}
			if len(spec.Sort) > 0 {
				sortVals = extractHitSortValues(*c.hit, spec.Sort, nil)
			}
		}
		entry := map[string]any{
			"metrics": metricsMap,
		}
		if len(sortVals) > 0 {
			entry["sort"] = sortVals
		} else {
			entry["sort"] = []any{c.docID}
		}
		topList = append(topList, entry)
	}
	return map[string]any{"top": topList}
}

func filterAndSortTermsRows(
	rows []AggRow,
	spec *esast.TermsAggSpec,
	fullKey string,
	parentBucketKey string,
	bucketsByAgg map[string][]AggRow,
) []AggRow {
	if spec == nil {
		return rows
	}
	cpRows := append([]AggRow(nil), rows...)
	minDocCount := int64(1)
	if spec.MinDocCount != nil {
		minDocCount = int64(*spec.MinDocCount)
	}
	var incRe, excRe *regexp.Regexp
	if s, ok := spec.Include.(string); ok {
		incRe, _ = regexp.Compile("^(?:" + s + ")$")
	}
	if s, ok := spec.Exclude.(string); ok {
		excRe, _ = regexp.Compile("^(?:" + s + ")$")
	}
	if spec.Include != nil || spec.Exclude != nil || minDocCount > 0 {
		filtered := make([]AggRow, 0, len(cpRows))
		for _, r := range cpRows {
			if minDocCount > 0 && r.effectiveCount() < minDocCount {
				continue
			}
			if spec.Include != nil && !matchesTermsFilterPrecompiled(r.BucketKey, spec.Include, incRe) {
				continue
			}
			if spec.Exclude != nil && matchesTermsFilterPrecompiled(r.BucketKey, spec.Exclude, excRe) {
				continue
			}
			filtered = append(filtered, r)
		}
		cpRows = filtered
	}
	type termsOrderCriterion struct {
		field       string
		desc        bool
		metricByKey map[string]float64
	}
	var criteria []termsOrderCriterion
	addCriterion := func(field string, v any) {
		desc := !strings.EqualFold(fmt.Sprintf("%v", v), "asc")
		var metricByKey map[string]float64
		if field != "_count" && field != "_key" && field != "_term" {
			normField := strings.ReplaceAll(strings.TrimSpace(field), ">", ".")
			for {
				openIdx := strings.IndexByte(normField, '[')
				if openIdx < 0 {
					break
				}
				closeIdx := strings.IndexByte(normField[openIdx:], ']')
				if closeIdx < 0 {
					break
				}
				closeIdx += openIdx
				inner := strings.Trim(normField[openIdx+1:closeIdx], "'\"")
				normField = normField[:openIdx] + "." + inner + normField[closeIdx+1:]
			}
			subName := normField
			prop := "value"
			var rowKey string
			if _, ok := bucketsByAgg[fullKey+"."+normField]; ok {
				rowKey = fullKey + "." + normField
			} else if _, ok := bucketsByAgg[fullKey+"."+normField+".0"]; ok {
				rowKey = fullKey + "." + normField + ".0"
			} else {
				if dot := strings.LastIndexByte(normField, '.'); dot > 0 {
					subName = normField[:dot]
					prop = normField[dot+1:]
				}
				rowKey = fullKey + "." + subName
				switch prop {
				case "", "value", "_count", "doc_count":
				case "count":
					rowKey = fullKey + "." + subName + "._stats_count"
				case "min", "min_length":
					if _, ok := bucketsByAgg[fullKey+"."+subName+".0.0"]; ok && len(bucketsByAgg[fullKey+"."+subName+"._stats_min"]) == 0 {
						rowKey = fullKey + "." + subName + ".0.0"
					} else {
						rowKey = fullKey + "." + subName + "._stats_min"
					}
				case "max", "max_length":
					if _, ok := bucketsByAgg[fullKey+"."+subName+".100.0"]; ok && len(bucketsByAgg[fullKey+"."+subName+"._stats_max"]) == 0 {
						rowKey = fullKey + "." + subName + ".100.0"
					} else {
						rowKey = fullKey + "." + subName + "._stats_max"
					}
				case "avg", "avg_length":
					rowKey = fullKey + "." + subName + "._stats_avg"
				case "sum":
					rowKey = fullKey + "." + subName + "._stats_sum"
				case "sum_of_squares":
					rowKey = fullKey + "." + subName + "._stats_sum_sq"
				case "std_deviation", "std_deviation_population":
					rowKey = fullKey + "." + subName + "._stats_std"
				case "q1":
					rowKey = fullKey + "." + subName + ".25.0"
				case "q2":
					rowKey = fullKey + "." + subName + ".50.0"
				case "q3":
					rowKey = fullKey + "." + subName + ".75.0"
				default:
					if _, ok := bucketsByAgg[fullKey+"."+subName+"."+prop]; ok {
						rowKey = fullKey + "." + subName + "." + prop
					} else if _, ok := bucketsByAgg[fullKey+"."+subName+"."+prop+".0"]; ok {
						rowKey = fullKey + "." + subName + "." + prop + ".0"
					} else if _, ok := bucketsByAgg[fullKey+"."+normField]; ok {
						rowKey = fullKey + "." + normField
					}
				}
			}
			subRows := bucketsByAgg[rowKey]
			metricByKey = make(map[string]float64, len(subRows))
			for _, sr := range subRows {
				k := sr.BucketKey
				if parentBucketKey != "" {
					trimmed, ok := trimSubAggBucketPrefix(k, parentBucketKey)
					if !ok {
						continue
					}
					k = trimmed
				}
				if prop == "_count" || prop == "doc_count" || prop == "count" {
					metricByKey[k] = float64(sr.effectiveCount())
				} else {
					metricByKey[k] = sr.effectiveValue()
				}
			}
		}
		criteria = append(criteria, termsOrderCriterion{field: field, desc: desc, metricByKey: metricByKey})
	}
	if spec.Order != nil {
		switch ov := spec.Order.(type) {
		case map[string]any:
			for k, v := range ov {
				addCriterion(k, v)
				break
			}
		case []any:
			for _, elem := range ov {
				if m, ok := elem.(map[string]any); ok {
					for k, v := range m {
						addCriterion(k, v)
						break
					}
				}
			}
		}
	}
	if len(criteria) == 0 {
		criteria = []termsOrderCriterion{{field: "_count", desc: true}}
	}
	if len(cpRows) > 1 {
		sort.SliceStable(cpRows, func(i, j int) bool {
			for _, c := range criteria {
				switch c.field {
				case "_key", "_term":
					if cpRows[i].BucketKey != cpRows[j].BucketKey {
						if c.desc {
							return cpRows[i].BucketKey > cpRows[j].BucketKey
						}
						return cpRows[i].BucketKey < cpRows[j].BucketKey
					}
				case "_count":
					ci, cj := cpRows[i].effectiveCount(), cpRows[j].effectiveCount()
					if ci != cj {
						if c.desc {
							return ci > cj
						}
						return ci < cj
					}
				default:
					vi, vj := c.metricByKey[cpRows[i].BucketKey], c.metricByKey[cpRows[j].BucketKey]
					if vi != vj {
						if c.desc {
							return vi > vj
						}
						return vi < vj
					}
				}
			}
			return cpRows[i].BucketKey < cpRows[j].BucketKey
		})
	}
	limit := spec.Size
	if limit <= 0 {
		limit = 10
	}
	if limit > transpiler.DefaultMaxAggBuckets {
		limit = transpiler.DefaultMaxAggBuckets
	}
	if len(cpRows) > limit {
		cpRows = cpRows[:limit]
	}
	return cpRows
}

func matchesTermsFilterPrecompiled(key string, filter any, precompiled *regexp.Regexp) bool {
	switch fv := filter.(type) {
	case string:
		if precompiled != nil {
			return precompiled.MatchString(key)
		}
		if re, err := regexp.Compile("^(?:" + fv + ")$"); err == nil {
			return re.MatchString(key)
		}
		return matchWildcardPattern(fv, key)
	case []any:
		for _, item := range fv {
			if fmt.Sprintf("%v", item) == key {
				return true
			}
		}
		return false
	case []string:
		for _, item := range fv {
			if item == key {
				return true
			}
		}
		return false
	}
	return false
}

func isBucketAggSpec(spec esast.AggSpec) bool {
	return spec.EffectiveTerms() != nil || spec.Histogram != nil || spec.DateHistogram != nil ||
		spec.Filters != nil || spec.Range != nil || spec.DateRange != nil || spec.IPRange != nil ||
		spec.Composite != nil || spec.Filter != nil || spec.Missing != nil || spec.Nested != nil ||
		spec.ReverseNested != nil || spec.Global != nil || spec.EffectiveSampler() != nil
}

func validateChildBucketMetricDep(parentAggName, childAggName, pathStr string, subAggs map[string]esast.AggSpec) string {
	pathStr = strings.TrimSpace(pathStr)
	if pathStr == "" {
		return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s] under [%s]", childAggName, parentAggName)
	}
	if pathStr == "_count" || pathStr == "doc_count" || pathStr == "_key" || pathStr == "key" {
		return ""
	}
	normPath := strings.ReplaceAll(pathStr, ">", ".")
	for {
		openIdx := strings.IndexByte(normPath, '[')
		if openIdx < 0 {
			break
		}
		closeIdx := strings.IndexByte(normPath[openIdx:], ']')
		if closeIdx < 0 {
			break
		}
		closeIdx += openIdx
		inner := strings.Trim(normPath[openIdx+1:closeIdx], "'\"")
		normPath = normPath[:openIdx] + "." + inner + normPath[closeIdx+1:]
	}
	segs := strings.Split(normPath, ".")
	currMap := subAggs
	var lastSpec esast.AggSpec
	for i, seg := range segs {
		targetSpec, exists := currMap[seg]
		if !exists {
			if i > 0 && !isBucketAggSpec(lastSpec) {
				// Property access on a multi-value metric (e.g. the_stats.avg or the_pct.95.0)
				return ""
			}
			if i == len(segs)-1 && isBucketAggSpec(lastSpec) && (seg == "_count" || seg == "doc_count") {
				return ""
			}
			return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] references non-existent sibling aggregation [%s]", pathStr, childAggName, seg)
		}
		lastSpec = targetSpec
		currMap = targetSpec.SubAggs()
	}
	if isBucketAggSpec(lastSpec) {
		return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, childAggName)
	}
	return ""
}

func validatePipelineAggs(aggs map[string]esast.AggSpec) string {
	for aggName, spec := range aggs {
		var pSpec *esast.PipelineAggSpec
		switch {
		case spec.AvgBucket != nil:
			pSpec = spec.AvgBucket
		case spec.SumBucket != nil:
			pSpec = spec.SumBucket
		case spec.MinBucket != nil:
			pSpec = spec.MinBucket
		case spec.MaxBucket != nil:
			pSpec = spec.MaxBucket
		case spec.StatsBucket != nil:
			pSpec = spec.StatsBucket
		case spec.ExtendedStatsBucket != nil:
			pSpec = spec.ExtendedStatsBucket
		case spec.PercentilesBucket != nil:
			pSpec = &esast.PipelineAggSpec{
				BucketsPath: spec.PercentilesBucket.BucketsPath,
				GapPolicy:   spec.PercentilesBucket.GapPolicy,
				Format:      spec.PercentilesBucket.Format,
			}
		}
		if pSpec != nil {
			pathStr := strings.TrimSpace(pSpec.EffectivePath())
			if pathStr == "" {
				return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s]", aggName)
			}
			normPath := pathStr
			for {
				openIdx := strings.IndexByte(normPath, '[')
				if openIdx < 0 {
					break
				}
				closeIdx := strings.IndexByte(normPath[openIdx:], ']')
				if closeIdx < 0 {
					break
				}
				closeIdx += openIdx
				inner := strings.Trim(normPath[openIdx+1:closeIdx], "'\"")
				normPath = normPath[:openIdx] + "." + inner + normPath[closeIdx+1:]
			}
			var containerPath []string
			metricPath := ""
			if strings.Contains(normPath, ">") {
				segs := strings.Split(normPath, ">")
				containerPath = segs[:len(segs)-1]
				metricPath = segs[len(segs)-1]
			} else if strings.Contains(normPath, ".") {
				parts := strings.SplitN(normPath, ".", 2)
				containerPath = []string{parts[0]}
				metricPath = parts[1]
			} else {
				containerPath = []string{normPath}
			}
			currMap := aggs
			var lastTargetSpec esast.AggSpec
			for _, seg := range containerPath {
				targetSpec, exists := currMap[seg]
				if !exists {
					return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] references non-existent aggregation [%s]", pathStr, aggName, seg)
				}
				lastTargetSpec = targetSpec
				currMap = targetSpec.SubAggs()
			}
			if metricPath == "" {
				if isBucketAggSpec(lastTargetSpec) {
					return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, aggName)
				}
			} else if metricPath != "_count" && metricPath != "doc_count" {
				mSegs := strings.Split(metricPath, ".")
				mCurr := currMap
				var mLast esast.AggSpec
				for mi, mSeg := range mSegs {
					mSpec, exists := mCurr[mSeg]
					if !exists {
						if mi > 0 && !isBucketAggSpec(mLast) {
							mLast = esast.AggSpec{}
							break
						}
						if mi == len(mSegs)-1 && isBucketAggSpec(mLast) && (mSeg == "_count" || mSeg == "doc_count") {
							mLast = esast.AggSpec{}
							break
						}
						return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] references non-existent metric aggregation [%s]", pathStr, aggName, mSeg)
					}
					mLast = mSpec
					mCurr = mSpec.SubAggs()
				}
				if isBucketAggSpec(mLast) {
					return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, aggName)
				}
			}
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			childDeps := make(map[string][]string)
			for subName, subSpec := range subAggs {
				switch {
				case subSpec.CumulativeSum != nil:
					p := subSpec.CumulativeSum.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{strings.Split(strings.Split(p, ">")[0], ".")[0]}
				case subSpec.Derivative != nil:
					p := subSpec.Derivative.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{strings.Split(strings.Split(p, ">")[0], ".")[0]}
				case subSpec.EffectiveMovingAvg() != nil:
					p := subSpec.EffectiveMovingAvg().EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{strings.Split(strings.Split(p, ">")[0], ".")[0]}
				case subSpec.SerialDiff != nil:
					p := subSpec.SerialDiff.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{strings.Split(strings.Split(p, ">")[0], ".")[0]}
				case subSpec.Normalize != nil:
					p := subSpec.Normalize.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					method := strings.ToLower(strings.TrimSpace(subSpec.Normalize.Method))
					switch method {
					case "", "percent_of_sum", "rescale_0_1", "rescale_0_100", "mean", "z-score", "z_score", "atan":
					default:
						return fmt.Sprintf("unknown normalize method [%s] for pipeline aggregation [%s] under [%s]", subSpec.Normalize.Method, subName, aggName)
					}
					childDeps[subName] = []string{strings.Split(strings.Split(p, ">")[0], ".")[0]}
				case subSpec.BucketScript != nil:
					if len(subSpec.BucketScript.BucketsPath) == 0 {
						return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s] under [%s]", subName, aggName)
					}
					var deps []string
					for _, p := range subSpec.BucketScript.BucketsPath {
						if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
							return errMsg
						}
						deps = append(deps, strings.Split(strings.Split(p, ">")[0], ".")[0])
					}
					childDeps[subName] = deps
				case subSpec.BucketSelector != nil:
					if len(subSpec.BucketSelector.BucketsPath) == 0 {
						return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s] under [%s]", subName, aggName)
					}
					for _, p := range subSpec.BucketSelector.BucketsPath {
						if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
							return errMsg
						}
					}
				}
			}
			for startNode := range childDeps {
				visiting := make(map[string]bool)
				var hasCycle func(string) bool
				hasCycle = func(curr string) bool {
					if visiting[curr] {
						return true
					}
					deps, ok := childDeps[curr]
					if !ok {
						return false
					}
					visiting[curr] = true
					for _, d := range deps {
						if hasCycle(d) {
							return true
						}
					}
					visiting[curr] = false
					return false
				}
				if hasCycle(startNode) {
					return fmt.Sprintf("cyclic pipeline aggregation dependency detected involving [%s] under [%s]", startNode, aggName)
				}
			}
			if errMsg := validatePipelineAggs(subAggs); errMsg != "" {
				return errMsg
			}
		}
	}
	return ""
}

func evaluateChildPipelineAggs(buckets []map[string]any, subAggs map[string]esast.AggSpec) []map[string]any {
	if len(buckets) == 0 || len(subAggs) == 0 {
		return buckets
	}
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)

	isChildMetricPipeline := func(spec esast.AggSpec) bool {
		return spec.CumulativeSum != nil || spec.Derivative != nil || spec.EffectiveMovingAvg() != nil ||
			spec.SerialDiff != nil || spec.Normalize != nil || spec.BucketScript != nil
	}
	depsForSpec := func(spec esast.AggSpec) []string {
		switch {
		case spec.CumulativeSum != nil:
			return []string{strings.Split(strings.Split(spec.CumulativeSum.EffectivePath(), ">")[0], ".")[0]}
		case spec.Derivative != nil:
			return []string{strings.Split(strings.Split(spec.Derivative.EffectivePath(), ">")[0], ".")[0]}
		case spec.EffectiveMovingAvg() != nil:
			return []string{strings.Split(strings.Split(spec.EffectiveMovingAvg().EffectivePath(), ">")[0], ".")[0]}
		case spec.SerialDiff != nil:
			return []string{strings.Split(strings.Split(spec.SerialDiff.EffectivePath(), ">")[0], ".")[0]}
		case spec.Normalize != nil:
			return []string{strings.Split(strings.Split(spec.Normalize.EffectivePath(), ">")[0], ".")[0]}
		case spec.BucketScript != nil:
			var deps []string
			for _, p := range spec.BucketScript.BucketsPath {
				deps = append(deps, strings.Split(strings.Split(p, ">")[0], ".")[0])
			}
			return deps
		}
		return nil
	}

	evaluated := make(map[string]bool, len(subNames))
	for pass := 0; pass <= len(subNames); pass++ {
		progressed := false
		for _, subName := range subNames {
			if evaluated[subName] {
				continue
			}
			spec := subAggs[subName]
			if !isChildMetricPipeline(spec) {
				evaluated[subName] = true
				continue
			}
			if pass < len(subNames) {
				ready := true
				for _, dep := range depsForSpec(spec) {
					if depSpec, exists := subAggs[dep]; exists && isChildMetricPipeline(depSpec) && !evaluated[dep] {
						ready = false
						break
					}
				}
				if !ready {
					continue
				}
			}
			switch {
			case spec.CumulativeSum != nil:
				pathStr := spec.CumulativeSum.EffectivePath()
				insertZeros := strings.EqualFold(spec.CumulativeSum.GapPolicy, "insert_zeros")
				var running float64
				for _, b := range buckets {
					v, ok := extractBucketMetricByPath(b, pathStr)
					if !ok && !insertZeros {
						continue
					}
					running += v
					b[subName] = map[string]any{"value": running}
				}
			case spec.Derivative != nil:
				pathStr := spec.Derivative.EffectivePath()
				insertZeros := strings.EqualFold(spec.Derivative.GapPolicy, "insert_zeros")
				var prev float64
				hasPrev := false
				for _, b := range buckets {
					curr, ok := extractBucketMetricByPath(b, pathStr)
					if !ok {
						if insertZeros {
							curr = 0
						} else {
							continue
						}
					}
					if hasPrev {
						b[subName] = map[string]any{"value": curr - prev}
					}
					prev = curr
					hasPrev = true
				}
			case spec.EffectiveMovingAvg() != nil:
				maSpec := spec.EffectiveMovingAvg()
				pathStr := maSpec.EffectivePath()
				insertZeros := strings.EqualFold(maSpec.GapPolicy, "insert_zeros")
				win := maSpec.EffectiveWindow()
				var history []float64
				for _, b := range buckets {
					curr, ok := extractBucketMetricByPath(b, pathStr)
					if !ok {
						if insertZeros {
							curr = 0
						} else {
							continue
						}
					}
					history = append(history, curr)
					endIdx := len(history) - 1
					if maSpec.Shift != nil {
						endIdx = len(history) - 2 + *maSpec.Shift
					}
					if endIdx < 0 {
						continue
					}
					if endIdx >= len(history) {
						endIdx = len(history) - 1
					}
					start := 0
					if endIdx+1 > win {
						start = endIdx + 1 - win
					}
					slice := history[start : endIdx+1]
					if len(slice) == 0 {
						continue
					}
					b[subName] = map[string]any{"value": evalMovingWindow(slice, maSpec)}
				}
			case spec.SerialDiff != nil:
				sdSpec := spec.SerialDiff
				pathStr := sdSpec.EffectivePath()
				insertZeros := strings.EqualFold(sdSpec.GapPolicy, "insert_zeros")
				lag := sdSpec.EffectiveLag()
				vals := make([]float64, len(buckets))
				valid := make([]bool, len(buckets))
				for i, b := range buckets {
					curr, ok := extractBucketMetricByPath(b, pathStr)
					if !ok && insertZeros {
						curr = 0
						ok = true
					}
					vals[i] = curr
					valid[i] = ok
					if i >= lag && valid[i] && valid[i-lag] {
						b[subName] = map[string]any{"value": vals[i] - vals[i-lag]}
					}
				}
			case spec.Normalize != nil:
				normSpec := spec.Normalize
				pathStr := normSpec.EffectivePath()
				insertZeros := strings.EqualFold(normSpec.GapPolicy, "insert_zeros")
				vals := make([]float64, len(buckets))
				valid := make([]bool, len(buckets))
				var sumVal, minVal, maxVal float64
				validCount := 0
				for i, b := range buckets {
					v, ok := extractBucketMetricByPath(b, pathStr)
					if !ok && insertZeros {
						v = 0
						ok = true
					}
					if ok {
						vals[i] = v
						valid[i] = true
						sumVal += v
						if validCount == 0 || v < minVal {
							minVal = v
						}
						if validCount == 0 || v > maxVal {
							maxVal = v
						}
						validCount++
					}
				}
				if validCount > 0 {
					meanVal := sumVal / float64(validCount)
					var sqDiffSum float64
					for i := range buckets {
						if valid[i] {
							d := vals[i] - meanVal
							sqDiffSum += d * d
						}
					}
					stdPop := math.Sqrt(sqDiffSum / float64(validCount))
					method := strings.ToLower(strings.TrimSpace(normSpec.Method))
					for i, b := range buckets {
						if !valid[i] {
							continue
						}
						v := vals[i]
						var normVal float64
						switch method {
						case "", "percent_of_sum":
							if sumVal != 0 {
								normVal = (v / sumVal) * 100.0
							}
						case "rescale_0_1":
							if maxVal > minVal {
								normVal = (v - minVal) / (maxVal - minVal)
							}
						case "rescale_0_100":
							if maxVal > minVal {
								normVal = ((v - minVal) / (maxVal - minVal)) * 100.0
							}
						case "mean":
							normVal = v - meanVal
						case "z-score", "z_score":
							if stdPop > 0 {
								normVal = (v - meanVal) / stdPop
							}
						case "atan":
							normVal = math.Atan(v)
						}
						outObj := map[string]any{"value": normVal}
						if normSpec.Format != "" {
							if strings.HasSuffix(normSpec.Format, "%") {
								outObj["value_as_string"] = fmt.Sprintf("%.2f%%", normVal)
							} else {
								outObj["value_as_string"] = fmt.Sprintf("%.2f", normVal)
							}
						}
						b[subName] = outObj
					}
				}
			case spec.BucketScript != nil:
				for _, b := range buckets {
					if val, ok := evalBucketScript(b, spec.BucketScript); ok && !math.IsNaN(val) && !math.IsInf(val, 0) {
						b[subName] = map[string]any{"value": val}
					}
				}
			}
			evaluated[subName] = true
			progressed = true
		}
		if !progressed {
			break
		}
	}

	for _, subName := range subNames {
		spec := subAggs[subName]
		if spec.BucketSelector != nil {
			filtered := make([]map[string]any, 0, len(buckets))
			for _, b := range buckets {
				if evalBucketSelector(b, spec.BucketSelector) {
					filtered = append(filtered, b)
				}
			}
			buckets = filtered
		}
	}
	for _, subName := range subNames {
		spec := subAggs[subName]
		if spec.BucketSort != nil {
			bs := spec.BucketSort
			if len(bs.Sort) > 0 && len(buckets) > 1 {
				sort.SliceStable(buckets, func(i, j int) bool {
					for _, sSpec := range bs.Sort {
						field := sSpec.Entry.Field
						desc := strings.EqualFold(sSpec.Entry.Order, "desc")
						if field == "_key" || field == "key" {
							ki, okStrI := buckets[i]["key"].(string)
							kj, okStrJ := buckets[j]["key"].(string)
							if okStrI && okStrJ {
								if ki != kj {
									if desc {
										return ki > kj
									}
									return ki < kj
								}
								continue
							}
						}
						vi, okI := extractBucketMetricByPath(buckets[i], field)
						vj, okJ := extractBucketMetricByPath(buckets[j], field)
						if !okI && !okJ {
							continue
						}
						if !okI {
							return false
						}
						if !okJ {
							return true
						}
						if vi != vj {
							if desc {
								return vi > vj
							}
							return vi < vj
						}
					}
					return false
				})
			}
			from := 0
			if bs.From != nil && *bs.From > 0 {
				from = *bs.From
			}
			if from >= len(buckets) {
				buckets = []map[string]any{}
			} else {
				buckets = buckets[from:]
				if bs.Size != nil && *bs.Size >= 0 && len(buckets) > *bs.Size {
					buckets = buckets[:*bs.Size]
				}
			}
		}
	}
	return buckets
}

func evalMovingWindow(slice []float64, maSpec *esast.MovingAvgAggSpec) float64 {
	if len(slice) == 0 {
		return 0
	}
	if maSpec != nil {
		src := extractScriptSourceString(maSpec.Script)
		switch {
		case strings.Contains(src, "MovingFunctions.max"):
			res := slice[0]
			for _, v := range slice[1:] {
				if v > res {
					res = v
				}
			}
			return res
		case strings.Contains(src, "MovingFunctions.min"):
			res := slice[0]
			for _, v := range slice[1:] {
				if v < res {
					res = v
				}
			}
			return res
		case strings.Contains(src, "MovingFunctions.sum"):
			var sum float64
			for _, v := range slice {
				sum += v
			}
			return sum
		case strings.Contains(src, "MovingFunctions.stdDev"):
			var sum float64
			for _, v := range slice {
				sum += v
			}
			mean := sum / float64(len(slice))
			var sqDiff float64
			for _, v := range slice {
				d := v - mean
				sqDiff += d * d
			}
			return math.Sqrt(sqDiff / float64(len(slice)))
		case strings.Contains(src, "MovingFunctions.linearWeightedAvg"):
			var wSum, wTotal float64
			for idx, v := range slice {
				w := float64(idx + 1)
				wSum += v * w
				wTotal += w
			}
			return wSum / wTotal
		case strings.Contains(src, "MovingFunctions.ewma"):
			alpha := 0.3
			ewma := slice[0]
			for idx := 1; idx < len(slice); idx++ {
				ewma = alpha*slice[idx] + (1-alpha)*ewma
			}
			return ewma
		}
		switch strings.ToLower(strings.TrimSpace(maSpec.Model)) {
		case "linear":
			var wSum, wTotal float64
			for idx, v := range slice {
				w := float64(idx + 1)
				wSum += v * w
				wTotal += w
			}
			return wSum / wTotal
		case "ewma":
			alpha := 0.3
			ewma := slice[0]
			for idx := 1; idx < len(slice); idx++ {
				ewma = alpha*slice[idx] + (1-alpha)*ewma
			}
			return ewma
		}
	}
	var sum float64
	for _, hv := range slice {
		sum += hv
	}
	return sum / float64(len(slice))
}

func evaluateSiblingPipelineAggs(aggs map[string]esast.AggSpec, aggsOut map[string]any) {
	// First evaluate any nested sibling pipeline aggregations inside single-bucket or multi-bucket containers,
	// then evaluate avg_bucket / sum_bucket / min_bucket / max_bucket / stats_bucket / extended_stats_bucket / percentiles_bucket.
	for aggName, spec := range aggs {
		if subMap, ok := aggsOut[aggName].(map[string]any); ok && len(spec.SubAggs()) > 0 {
			switch rawBuckets := subMap["buckets"].(type) {
			case []map[string]any:
				for _, b := range rawBuckets {
					evaluateSiblingPipelineAggs(spec.SubAggs(), b)
				}
			case map[string]any:
				for _, v := range rawBuckets {
					if b, okB := v.(map[string]any); okB {
						evaluateSiblingPipelineAggs(spec.SubAggs(), b)
					}
				}
			default:
				evaluateSiblingPipelineAggs(spec.SubAggs(), subMap)
			}
		}
	}
	for aggName, spec := range aggs {
		var pSpec *esast.PipelineAggSpec
		var mode string
		switch {
		case spec.AvgBucket != nil:
			pSpec, mode = spec.AvgBucket, "avg"
		case spec.SumBucket != nil:
			pSpec, mode = spec.SumBucket, "sum"
		case spec.MinBucket != nil:
			pSpec, mode = spec.MinBucket, "min"
		case spec.MaxBucket != nil:
			pSpec, mode = spec.MaxBucket, "max"
		case spec.StatsBucket != nil:
			pSpec, mode = spec.StatsBucket, "stats"
		case spec.ExtendedStatsBucket != nil:
			pSpec, mode = spec.ExtendedStatsBucket, "extended_stats"
		case spec.PercentilesBucket != nil:
			pSpec = &esast.PipelineAggSpec{
				BucketsPath: spec.PercentilesBucket.BucketsPath,
				GapPolicy:   spec.PercentilesBucket.GapPolicy,
				Format:      spec.PercentilesBucket.Format,
			}
			mode = "percentiles"
		}
		if pSpec == nil {
			continue
		}
		pathStr := pSpec.EffectivePath()
		vals := collectSiblingBucketValuesWithPolicy(aggsOut, pathStr, pSpec.GapPolicy)
		var sumVal, sumSqVal, minVal, maxVal, avgVal float64
		for i, v := range vals {
			sumVal += v
			sumSqVal += v * v
			if i == 0 || v < minVal {
				minVal = v
			}
			if i == 0 || v > maxVal {
				maxVal = v
			}
		}
		if len(vals) > 0 {
			avgVal = sumVal / float64(len(vals))
		}
		switch mode {
		case "avg":
			aggsOut[aggName] = map[string]any{"value": avgVal}
		case "sum":
			aggsOut[aggName] = map[string]any{"value": sumVal}
		case "min":
			aggsOut[aggName] = map[string]any{"value": minVal}
		case "max":
			aggsOut[aggName] = map[string]any{"value": maxVal}
		case "stats":
			aggsOut[aggName] = map[string]any{
				"count": int64(len(vals)),
				"min":   minVal,
				"max":   maxVal,
				"avg":   avgVal,
				"sum":   sumVal,
			}
		case "extended_stats":
			cnt := len(vals)
			var variancePop, varianceSampling float64
			if cnt > 0 {
				variancePop = math.Max(0, (sumSqVal/float64(cnt))-(avgVal*avgVal))
				if cnt > 1 {
					varianceSampling = variancePop * float64(cnt) / float64(cnt-1)
				}
			}
			stdPop := math.Sqrt(variancePop)
			stdSampling := math.Sqrt(varianceSampling)
			sigma := pSpec.EffectiveSigma()
			aggsOut[aggName] = map[string]any{
				"count":                    int64(cnt),
				"min":                      minVal,
				"max":                      maxVal,
				"avg":                      avgVal,
				"sum":                      sumVal,
				"sum_of_squares":           sumSqVal,
				"variance":                 variancePop,
				"variance_population":      variancePop,
				"variance_sampling":        varianceSampling,
				"std_deviation":            stdPop,
				"std_deviation_population": stdPop,
				"std_deviation_sampling":   stdSampling,
				"std_deviation_bounds": map[string]any{
					"upper":            avgVal + sigma*stdPop,
					"lower":            avgVal - sigma*stdPop,
					"upper_population": avgVal + sigma*stdPop,
					"lower_population": avgVal - sigma*stdPop,
					"upper_sampling":   avgVal + sigma*stdSampling,
					"lower_sampling":   avgVal - sigma*stdSampling,
				},
			}
		case "percentiles":
			sortedVals := append([]float64(nil), vals...)
			sort.Float64s(sortedVals)
			percents := spec.PercentilesBucket.EffectivePercents()
			computePct := func(p float64) float64 {
				if len(sortedVals) == 0 {
					return 0
				}
				if p <= 0 {
					return sortedVals[0]
				}
				if p >= 100 {
					return sortedVals[len(sortedVals)-1]
				}
				pos := (p / 100.0) * float64(len(sortedVals)-1)
				lowerIdx := int(math.Floor(pos))
				upperIdx := int(math.Ceil(pos))
				if lowerIdx == upperIdx {
					return sortedVals[lowerIdx]
				}
				frac := pos - float64(lowerIdx)
				return sortedVals[lowerIdx]*(1-frac) + sortedVals[upperIdx]*frac
			}
			if spec.PercentilesBucket.Keyed != nil && !*spec.PercentilesBucket.Keyed {
				arr := make([]map[string]any, 0, len(percents))
				for _, p := range percents {
					arr = append(arr, map[string]any{
						"key":   p,
						"value": computePct(p),
					})
				}
				aggsOut[aggName] = map[string]any{"values": arr}
			} else {
				vMap := make(map[string]float64, len(percents))
				for _, p := range percents {
					kStr := strconv.FormatFloat(p, 'f', -1, 64)
					if !strings.Contains(kStr, ".") {
						kStr += ".0"
					}
					vMap[kStr] = computePct(p)
				}
				aggsOut[aggName] = map[string]any{"values": vMap}
			}
		}
	}
}

func collectSiblingBucketValuesWithPolicy(aggsOut map[string]any, bucketsPath, gapPolicy string) []float64 {
	insertZeros := strings.EqualFold(gapPolicy, "insert_zeros")
	var containerPath []string
	metricPath := "_count"
	if strings.Contains(bucketsPath, ">") {
		segs := strings.Split(bucketsPath, ">")
		containerPath = segs[:len(segs)-1]
		if segs[len(segs)-1] != "" {
			metricPath = segs[len(segs)-1]
		}
	} else if strings.Contains(bucketsPath, ".") {
		parts := strings.SplitN(bucketsPath, ".", 2)
		containerPath = []string{parts[0]}
		if len(parts) == 2 && parts[1] != "" {
			metricPath = parts[1]
		}
	} else {
		containerPath = []string{bucketsPath}
	}
	if len(containerPath) == 0 {
		return nil
	}
	targetAgg, ok := aggsOut[containerPath[0]].(map[string]any)
	if !ok {
		return nil
	}
	var out []float64
	collectValuesFromAggContainer(targetAgg, containerPath[1:], metricPath, insertZeros, &out)
	return out
}

func collectValuesFromAggContainer(container map[string]any, remainingPath []string, metricPath string, insertZeros bool, out *[]float64) {
	if container == nil {
		return
	}
	if len(remainingPath) > 0 {
		nextSeg := remainingPath[0]
		rest := remainingPath[1:]
		if sub, ok := container[nextSeg].(map[string]any); ok {
			collectValuesFromAggContainer(sub, rest, metricPath, insertZeros, out)
			return
		}
		switch rawBuckets := container["buckets"].(type) {
		case []map[string]any:
			for _, b := range rawBuckets {
				if sub, ok := b[nextSeg].(map[string]any); ok {
					collectValuesFromAggContainer(sub, rest, metricPath, insertZeros, out)
				}
			}
		case map[string]any:
			var ks []string
			for k := range rawBuckets {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			for _, k := range ks {
				if b, ok := rawBuckets[k].(map[string]any); ok {
					if sub, ok := b[nextSeg].(map[string]any); ok {
						collectValuesFromAggContainer(sub, rest, metricPath, insertZeros, out)
					}
				}
			}
		}
		return
	}

	extractFromBucket := func(b map[string]any) {
		if dc, hasDC := toFloat64(b["doc_count"]); hasDC && dc == 0 && !insertZeros && metricPath != "_count" && metricPath != "doc_count" {
			return
		}
		if v, ok := extractBucketMetricByPath(b, metricPath); ok {
			*out = append(*out, v)
		} else if insertZeros {
			*out = append(*out, 0)
		}
	}

	switch rawBuckets := container["buckets"].(type) {
	case []map[string]any:
		for _, b := range rawBuckets {
			extractFromBucket(b)
		}
	case map[string]any:
		var ks []string
		for k := range rawBuckets {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			if b, ok := rawBuckets[k].(map[string]any); ok {
				extractFromBucket(b)
			}
		}
	default:
		extractFromBucket(container)
	}
}

func extractBucketMetricByPath(b map[string]any, metricPath string) (float64, bool) {
	metricPath = strings.TrimSpace(strings.ReplaceAll(metricPath, ">", "."))
	for {
		openIdx := strings.IndexByte(metricPath, '[')
		if openIdx < 0 {
			break
		}
		closeIdx := strings.IndexByte(metricPath[openIdx:], ']')
		if closeIdx < 0 {
			break
		}
		closeIdx += openIdx
		inner := strings.Trim(metricPath[openIdx+1:closeIdx], "'\"")
		metricPath = metricPath[:openIdx] + "." + inner + metricPath[closeIdx+1:]
	}
	switch metricPath {
	case "_count", "doc_count":
		return toFloat64(b["doc_count"])
	case "_key", "key":
		return toFloat64(b["key"])
	}
	subName := metricPath
	prop := "value"
	if dot := strings.IndexByte(metricPath, '.'); dot > 0 {
		subName = metricPath[:dot]
		prop = metricPath[dot+1:]
	}
	if subMap, ok := b[subName].(map[string]any); ok {
		if prop == "_count" || prop == "doc_count" {
			if v, okV := toFloat64(subMap["doc_count"]); okV {
				return v, true
			}
		}
		if v, okV := toFloat64(subMap[prop]); okV {
			return v, true
		}
		if valsMap, okVals := subMap["values"].(map[string]float64); okVals {
			if v, exists := valsMap[prop]; exists {
				return v, true
			}
		}
		if valsMapAny, okVals := subMap["values"].(map[string]any); okVals {
			if v, okV := toFloat64(valsMapAny[prop]); okV {
				return v, true
			}
		}
		if valsArr, okVals := subMap["values"].([]map[string]any); okVals {
			targetKey, hasFloatKey := parseFiniteFloat(prop)
			for _, item := range valsArr {
				if fmt.Sprintf("%v", item["key"]) == prop {
					if v, okV := toFloat64(item["value"]); okV {
						return v, true
					}
				}
				if hasFloatKey {
					if kf, okK := toFloat64(item["key"]); okK && math.Abs(kf-targetKey) < 1e-9 {
						if v, okV := toFloat64(item["value"]); okV {
							return v, true
						}
					}
				}
			}
		}
		if v, okV := extractBucketMetricByPath(subMap, prop); okV {
			return v, true
		}
		return 0, false
	}
	return toFloat64(b[metricPath])
}

func toFloat64(v any) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		return tv, true
	case int64:
		return float64(tv), true
	case int:
		return float64(tv), true
	case json.Number:
		if f, err := tv.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	}
	return 0, false
}

func evalBucketScript(b map[string]any, spec *esast.BucketSelectorAggSpec) (float64, bool) {
	if spec == nil {
		return 0, false
	}
	src := extractScriptSourceString(spec.Script)
	if src == "" {
		return 0, false
	}
	insertZeros := strings.EqualFold(spec.GapPolicy, "insert_zeros")
	vars := make(map[string]float64, len(spec.BucketsPath))
	for k, v := range spec.BucketsPath {
		val, ok := extractBucketMetricByPath(b, v)
		if !ok {
			if insertZeros {
				val = 0
			} else {
				return 0, false
			}
		}
		vars[k] = val
	}
	return evalBucketArithmeticExpr(src, vars)
}

func extractScriptSourceString(script any) string {
	var src string
	switch sv := script.(type) {
	case string:
		src = sv
	case map[string]any:
		if s, ok := sv["source"].(string); ok {
			src = s
		} else if s, ok := sv["inline"].(string); ok {
			src = s
		}
	}
	return strings.TrimSpace(src)
}

func evalBucketSelector(b map[string]any, spec *esast.BucketSelectorAggSpec) bool {
	if spec == nil {
		return true
	}
	src := extractScriptSourceString(spec.Script)
	if src == "" {
		return true
	}
	insertZeros := strings.EqualFold(spec.GapPolicy, "insert_zeros")
	vars := make(map[string]float64, len(spec.BucketsPath))
	for k, v := range spec.BucketsPath {
		val, ok := extractBucketMetricByPath(b, v)
		if !ok {
			if insertZeros {
				val = 0
			} else {
				return false
			}
		}
		vars[k] = val
	}
	return evalBucketSelectorExpr(src, vars)
}

func findMatchingTernaryColon(s string) int {
	depth := 0
	ternaryDepth := 0
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuotes = false
			}
			continue
		}
		if c == '\'' {
			inQuotes = true
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '?':
			if depth == 0 {
				ternaryDepth++
			}
		case ':':
			if depth == 0 {
				if ternaryDepth == 0 {
					return i
				}
				ternaryDepth--
			}
		}
	}
	return -1
}

func evalBucketSelectorExpr(expr string, vars map[string]float64) bool {
	return evalBucketSelectorExprDepth(expr, vars, 0)
}

func evalBucketSelectorExprDepth(expr string, vars map[string]float64, depth int) bool {
	if depth > 64 {
		return false
	}
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "return ") || strings.HasPrefix(expr, "return\t") || strings.HasPrefix(expr, "return(") {
		expr = strings.TrimSpace(strings.TrimPrefix(expr, "return"))
	}
	expr = strings.TrimSpace(strings.TrimSuffix(expr, ";"))
	expr = trimOuterParens(expr)
	if expr == "" {
		return true
	}
	if strings.EqualFold(expr, "true") {
		return true
	}
	if strings.EqualFold(expr, "false") {
		return false
	}
	if qIdx := findTopLevelOp(expr, "?"); qIdx > 0 {
		rest := expr[qIdx+1:]
		if cIdx := findMatchingTernaryColon(rest); cIdx > 0 {
			if evalBucketSelectorExprDepth(expr[:qIdx], vars, depth+1) {
				return evalBucketSelectorExprDepth(rest[:cIdx], vars, depth+1)
			}
			return evalBucketSelectorExprDepth(rest[cIdx+1:], vars, depth+1)
		}
	}
	if parts := splitTopLevelLogicalOp(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalBucketSelectorExprDepth(p, vars, depth+1) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelLogicalOp(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalBucketSelectorExprDepth(p, vars, depth+1) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(expr, "!") && !strings.HasPrefix(expr, "!=") {
		return !evalBucketSelectorExprDepth(expr[1:], vars, depth+1)
	}
	for _, op := range []string{">=", "<=", "!=", "==", ">", "<"} {
		if idx := findTopLevelOp(expr, op); idx > 0 {
			lVal, okL := evalBucketArithmeticExprDepth(expr[:idx], vars, depth+1)
			rVal, okR := evalBucketArithmeticExprDepth(expr[idx+len(op):], vars, depth+1)
			if !okL || !okR {
				return false
			}
			switch op {
			case ">=":
				return lVal >= rVal
			case "<=":
				return lVal <= rVal
			case "!=":
				return lVal != rVal
			case "==":
				return lVal == rVal
			case ">":
				return lVal > rVal
			case "<":
				return lVal < rVal
			}
		}
	}
	return false
}

func evalBucketArithmeticExpr(expr string, vars map[string]float64) (float64, bool) {
	return evalBucketArithmeticExprDepth(expr, vars, 0)
}

func evalBucketArithmeticExprDepth(expr string, vars map[string]float64, depth int) (float64, bool) {
	if depth > 64 {
		return 0, false
	}
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "return ") || strings.HasPrefix(expr, "return\t") || strings.HasPrefix(expr, "return(") {
		expr = strings.TrimSpace(strings.TrimPrefix(expr, "return"))
	}
	expr = strings.TrimSpace(strings.TrimSuffix(expr, ";"))
	expr = trimOuterParens(expr)
	if expr == "" {
		return 0, false
	}
	if qIdx := findTopLevelOp(expr, "?"); qIdx > 0 {
		rest := expr[qIdx+1:]
		if cIdx := findMatchingTernaryColon(rest); cIdx > 0 {
			if evalBucketSelectorExprDepth(expr[:qIdx], vars, depth+1) {
				return evalBucketArithmeticExprDepth(rest[:cIdx], vars, depth+1)
			}
			return evalBucketArithmeticExprDepth(rest[cIdx+1:], vars, depth+1)
		}
	}
	if parts := splitTopLevelBinaryMath(expr, '+'); len(parts) > 1 {
		sum := 0.0
		for _, p := range parts {
			v, ok := evalBucketArithmeticExprDepth(p, vars, depth+1)
			if !ok {
				return 0, false
			}
			sum += v
		}
		return sum, !math.IsNaN(sum) && !math.IsInf(sum, 0)
	}
	if parts := splitTopLevelBinaryMath(expr, '-'); len(parts) > 1 {
		res, ok := evalBucketArithmeticExprDepth(parts[0], vars, depth+1)
		if !ok {
			return 0, false
		}
		for _, p := range parts[1:] {
			v, okP := evalBucketArithmeticExprDepth(p, vars, depth+1)
			if !okP {
				return 0, false
			}
			res -= v
		}
		return res, !math.IsNaN(res) && !math.IsInf(res, 0)
	}
	if parts := splitTopLevelBinaryMath(expr, '*'); len(parts) > 1 {
		prod := 1.0
		for _, p := range parts {
			v, ok := evalBucketArithmeticExprDepth(p, vars, depth+1)
			if !ok {
				return 0, false
			}
			prod *= v
		}
		return prod, !math.IsNaN(prod) && !math.IsInf(prod, 0)
	}
	if parts := splitTopLevelBinaryMath(expr, '/'); len(parts) >= 2 {
		res, ok := evalBucketArithmeticExprDepth(parts[0], vars, depth+1)
		if !ok {
			return 0, false
		}
		for _, p := range parts[1:] {
			denom, okD := evalBucketArithmeticExprDepth(p, vars, depth+1)
			if !okD || denom == 0 {
				return 0, false
			}
			res /= denom
		}
		return res, !math.IsNaN(res) && !math.IsInf(res, 0)
	}
	for _, fn := range []struct {
		prefix string
		name   string
	}{
		{"Math.min(", "min"},
		{"Math.max(", "max"},
		{"Math.abs(", "abs"},
		{"Math.round(", "round"},
		{"Math.floor(", "floor"},
		{"Math.ceil(", "ceil"},
	} {
		if strings.HasPrefix(expr, fn.prefix) && strings.HasSuffix(expr, ")") {
			inner := expr[len(fn.prefix) : len(expr)-1]
			args := splitTopLevelArgs(inner)
			switch fn.name {
			case "min":
				if len(args) == 2 {
					a, okA := evalBucketArithmeticExprDepth(args[0], vars, depth+1)
					b, okB := evalBucketArithmeticExprDepth(args[1], vars, depth+1)
					if okA && okB {
						return math.Min(a, b), true
					}
				}
			case "max":
				if len(args) == 2 {
					a, okA := evalBucketArithmeticExprDepth(args[0], vars, depth+1)
					b, okB := evalBucketArithmeticExprDepth(args[1], vars, depth+1)
					if okA && okB {
						return math.Max(a, b), true
					}
				}
			case "abs":
				if v, ok := evalBucketArithmeticExprDepth(inner, vars, depth+1); ok {
					return math.Abs(v), true
				}
			case "round":
				if v, ok := evalBucketArithmeticExprDepth(inner, vars, depth+1); ok {
					return math.Round(v), true
				}
			case "floor":
				if v, ok := evalBucketArithmeticExprDepth(inner, vars, depth+1); ok {
					return math.Floor(v), true
				}
			case "ceil":
				if v, ok := evalBucketArithmeticExprDepth(inner, vars, depth+1); ok {
					return math.Ceil(v), true
				}
			}
			return 0, false
		}
	}
	if strings.HasPrefix(expr, "-") {
		if v, ok := evalBucketArithmeticExprDepth(expr[1:], vars, depth+1); ok {
			return -v, true
		}
	}
	if f, ok := parseFiniteFloat(expr); ok {
		return f, true
	}
	varKey := strings.TrimPrefix(expr, "params.")
	if v, exists := vars[varKey]; exists {
		return v, true
	}
	return 0, false
}

func parseFiniteFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func synthesizeDateHistogramBuckets(rows []AggRow, spec *esast.DateHistogramAggSpec) []AggRow {
	if spec == nil {
		return rows
	}
	intervalMs := spec.EffectiveIntervalMs()
	if intervalMs <= 0 {
		intervalMs = 86400000
	}
	nowUTC := time.Now().UTC()
	tzShiftMs := spec.EffectiveTimeZoneOffsetMs() - spec.EffectiveOffsetMs()
	floorDateBucket := func(ms int64) int64 {
		return int64(math.Floor(float64(ms+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
	}
	var hardMin, hardMax int64
	hasHardMin, hasHardMax := false, false
	if spec.HardBounds != nil {
		if spec.HardBounds.Min != nil {
			if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.HardBounds.Min), nowUTC, false); ok {
				hardMin = floorDateBucket(ms)
				hasHardMin = true
			}
		}
		if spec.HardBounds.Max != nil {
			if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.HardBounds.Max), nowUTC, true); ok {
				hardMax = floorDateBucket(ms)
				hasHardMax = true
			}
		}
	}
	if hasHardMin || hasHardMax {
		filtered := rows[:0]
		for _, r := range rows {
			k, err := strconv.ParseInt(r.BucketKey, 10, 64)
			if err != nil {
				continue
			}
			if (hasHardMin && k < hardMin) || (hasHardMax && k > hardMax) {
				continue
			}
			filtered = append(filtered, r)
		}
		rows = filtered
	}
	if spec.MinDocCount == nil || *spec.MinDocCount > 0 {
		return rows
	}

	byKey := make(map[int64]AggRow, len(rows))
	var minKey, maxKey int64
	hasObserved := false
	for _, r := range rows {
		if k, err := strconv.ParseInt(r.BucketKey, 10, 64); err == nil {
			byKey[k] = r
			if !hasObserved || k < minKey {
				minKey = k
			}
			if !hasObserved || k > maxKey {
				maxKey = k
			}
			hasObserved = true
		}
	}
	if spec.ExtendedBounds != nil {
		if spec.ExtendedBounds.Min != nil {
			if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.ExtendedBounds.Min), nowUTC, false); ok {
				extMin := floorDateBucket(ms)
				if !hasObserved || extMin < minKey {
					minKey = extMin
				}
			}
		}
		if spec.ExtendedBounds.Max != nil {
			if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.ExtendedBounds.Max), nowUTC, true); ok {
				extMax := floorDateBucket(ms)
				if !hasObserved || extMax > maxKey {
					maxKey = extMax
					hasObserved = true
				}
			}
		}
	}
	if !hasObserved && hasHardMin && hasHardMax {
		minKey = hardMin
		maxKey = hardMax
		hasObserved = true
	}
	if hasHardMin && (!hasObserved || minKey < hardMin) {
		minKey = hardMin
	}
	if hasHardMax && (!hasObserved || maxKey > hardMax) {
		maxKey = hardMax
	}
	if !hasObserved || maxKey < minKey {
		return rows
	}

	var out []AggRow
	for k := minKey; k <= maxKey && len(out) < transpiler.DefaultMaxAggBuckets; k += intervalMs {
		if existing, ok := byKey[k]; ok {
			out = append(out, existing)
		} else {
			out = append(out, AggRow{
				BucketKey: strconv.FormatInt(k, 10),
				DocCount:  0,
				Value:     0,
			})
		}
	}
	return out
}

func synthesizeHistogramBuckets(rows []AggRow, spec *esast.HistogramAggSpec) []AggRow {
	if spec == nil {
		return rows
	}
	interval := spec.Interval
	if math.IsNaN(interval) || math.IsInf(interval, 0) || interval <= 0 {
		interval = 1.0
	}
	offset := spec.Offset
	if math.IsNaN(offset) || math.IsInf(offset, 0) {
		offset = 0
	}
	var hardMin, hardMax float64
	hasHardMin, hasHardMax := false, false
	if spec.HardBounds != nil {
		if spec.HardBounds.Min != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.HardBounds.Min)); ok {
				hardMin = math.Floor((f-offset)/interval)*interval + offset
				hasHardMin = true
			}
		}
		if spec.HardBounds.Max != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.HardBounds.Max)); ok {
				hardMax = math.Floor((f-offset)/interval)*interval + offset
				hasHardMax = true
			}
		}
	}
	if hasHardMin || hasHardMax {
		filtered := rows[:0]
		for _, r := range rows {
			k, ok := parseFiniteFloat(r.BucketKey)
			if !ok {
				continue
			}
			if (hasHardMin && k < hardMin) || (hasHardMax && k > hardMax) {
				continue
			}
			filtered = append(filtered, r)
		}
		rows = filtered
	}
	if spec.MinDocCount == nil || *spec.MinDocCount > 0 {
		return rows
	}

	byKey := make(map[string]AggRow, len(rows))
	var minKey, maxKey float64
	hasObserved := false
	for _, r := range rows {
		if k, ok := parseFiniteFloat(r.BucketKey); ok {
			normKey := strconv.FormatFloat(k, 'f', -1, 64)
			byKey[normKey] = r
			if !hasObserved || k < minKey {
				minKey = k
			}
			if !hasObserved || k > maxKey {
				maxKey = k
			}
			hasObserved = true
		}
	}
	if spec.ExtendedBounds != nil {
		if spec.ExtendedBounds.Min != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.ExtendedBounds.Min)); ok {
				extMin := math.Floor((f-offset)/interval)*interval + offset
				if !hasObserved || extMin < minKey {
					minKey = extMin
				}
			}
		}
		if spec.ExtendedBounds.Max != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.ExtendedBounds.Max)); ok {
				extMax := math.Floor((f-offset)/interval)*interval + offset
				if !hasObserved || extMax > maxKey {
					maxKey = extMax
					hasObserved = true
				}
			}
		}
	}
	if !hasObserved && hasHardMin && hasHardMax {
		minKey = hardMin
		maxKey = hardMax
		hasObserved = true
	}
	if hasHardMin && (!hasObserved || minKey < hardMin) {
		minKey = hardMin
	}
	if hasHardMax && (!hasObserved || maxKey > hardMax) {
		maxKey = hardMax
	}
	if !hasObserved || maxKey < minKey {
		return rows
	}

	var out []AggRow
	for k := minKey; k <= maxKey+interval*1e-9 && len(out) < transpiler.DefaultMaxAggBuckets; k += interval {
		normKey := strconv.FormatFloat(k, 'f', -1, 64)
		if existing, ok := byKey[normKey]; ok {
			out = append(out, existing)
		} else {
			out = append(out, AggRow{
				BucketKey: normKey,
				DocCount:  0,
				Value:     0,
			})
		}
	}
	return out
}

func splitCompositeBucketKey(s string) []string {
	if strings.Contains(s, "\x1f") {
		return strings.Split(s, "\x1f")
	}
	if strings.Contains(s, "\\x1f") {
		return strings.Split(s, "\\x1f")
	}
	return []string{s}
}

func trimSubAggBucketPrefix(bucketKey, parentBucketKey string) (string, bool) {
	for _, sep := range []string{"\x1f", "\\x1f"} {
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
	from := spec.EffectiveFrom()
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
	} else if len(candidates) > 1 {
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].docID < candidates[j].docID
		})
	}
	if from > 0 {
		if from >= len(candidates) {
			candidates = nil
		} else {
			candidates = candidates[from:]
		}
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
			if len(spec.Sort) > 0 {
				hitMap["sort"] = extractHitSortValues(*c.hit, spec.Sort, nil)
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
	bucketDocCount, _ := toInt64(bucketMap["doc_count"])
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
		case subSpec.Avg != nil || subSpec.Sum != nil || subSpec.Min != nil || subSpec.Max != nil || subSpec.Rate != nil:
			var val float64
			found := false
			for _, r := range subRows {
				if r.BucketKey == parentBucketKey {
					val = r.effectiveValue()
					found = true
					break
				}
			}
			if !found && (subSpec.Avg != nil || subSpec.Min != nil || subSpec.Max != nil) {
				if dc, ok := bucketMap["doc_count"].(int64); ok && dc == 0 {
					bucketMap[subName] = map[string]any{"value": nil}
					continue
				}
			}
			bucketMap[subName] = map[string]any{"value": val}
		case subSpec.EffectiveStats() != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			for _, statKey := range []string{"_stats_count", "_stats_min", "_stats_max", "_stats_avg", "_stats_sum", "_stats_sum_sq", "_stats_std"} {
				for _, r := range bucketsByAgg[subFullKey+"."+statKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = statKey
						matchingRows = append(matchingRows, cp)
					}
				}
			}
			bucketMap[subName] = buildStatsAggObject(matchingRows, subSpec.ExtendedStats)
		case subSpec.Percentiles != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			seenPct := make(map[string]bool, len(matchingRows))
			for _, r := range matchingRows {
				seenPct[r.BucketKey] = true
			}
			for _, pct := range subSpec.Percentiles.EffectivePercents() {
				pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
				if !strings.Contains(pctKey, ".") {
					pctKey += ".0"
				}
				foundPct := seenPct[pctKey]
				for _, r := range bucketsByAgg[subFullKey+"."+pctKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = pctKey
						matchingRows = append(matchingRows, cp)
						foundPct = true
					}
				}
				if !foundPct {
					matchingRows = append(matchingRows, AggRow{BucketKey: pctKey, Value: 0})
				}
			}
			if subSpec.Percentiles.Keyed != nil && !*subSpec.Percentiles.Keyed {
				valuesArr := make([]map[string]any, 0, len(matchingRows))
				for _, r := range matchingRows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": r.effectiveValue(),
					})
				}
				bucketMap[subName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]float64, len(matchingRows))
				for _, r := range matchingRows {
					valuesMap[r.BucketKey] = r.effectiveValue()
				}
				bucketMap[subName] = map[string]any{"values": valuesMap}
			}
		case subSpec.Boxplot != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
				pctKey := fmt.Sprintf("%.1f", pct)
				for _, r := range bucketsByAgg[subFullKey+"."+pctKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = pctKey
						matchingRows = append(matchingRows, cp)
					}
				}
			}
			vals := make(map[string]float64, 5)
			for _, r := range matchingRows {
				vals[r.BucketKey] = r.effectiveValue()
			}
			q1, q3 := vals["25.0"], vals["75.0"]
			iqr := q3 - q1
			lower := math.Max(vals["0.0"], q1-1.5*iqr)
			upper := math.Min(vals["100.0"], q3+1.5*iqr)
			bucketMap[subName] = map[string]any{
				"min":   vals["0.0"],
				"max":   vals["100.0"],
				"q1":    q1,
				"q2":    vals["50.0"],
				"q3":    q3,
				"lower": lower,
				"upper": upper,
			}
		case subSpec.PercentileRanks != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			seenVal := make(map[string]bool, len(matchingRows))
			for _, r := range matchingRows {
				seenVal[r.BucketKey] = true
			}
			for _, v := range subSpec.PercentileRanks.Values {
				valKey := strconv.FormatFloat(v, 'f', -1, 64)
				if !strings.Contains(valKey, ".") {
					valKey += ".0"
				}
				foundVal := seenVal[valKey]
				for _, r := range bucketsByAgg[subFullKey+"."+valKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = valKey
						matchingRows = append(matchingRows, cp)
						foundVal = true
					}
				}
				if !foundVal {
					matchingRows = append(matchingRows, AggRow{BucketKey: valKey, Value: 0})
				}
			}
			if subSpec.PercentileRanks.Keyed != nil && !*subSpec.PercentileRanks.Keyed {
				valuesArr := make([]map[string]any, 0, len(matchingRows))
				for _, r := range matchingRows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": r.effectiveValue(),
					})
				}
				bucketMap[subName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]float64, len(matchingRows))
				for _, r := range matchingRows {
					valuesMap[r.BucketKey] = r.effectiveValue()
				}
				bucketMap[subName] = map[string]any{"values": valuesMap}
			}
		case subSpec.StringStats != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			for _, statKey := range []string{"_stats_count", "_stats_min", "_stats_max", "_stats_avg"} {
				for _, r := range bucketsByAgg[subFullKey+"."+statKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = statKey
						matchingRows = append(matchingRows, cp)
					}
				}
			}
			var cntVal int64
			var minVal, maxVal, avgVal float64
			for _, r := range matchingRows {
				switch r.BucketKey {
				case "_stats_count":
					cntVal = r.effectiveCount()
				case "_stats_min":
					minVal = r.effectiveValue()
				case "_stats_max":
					maxVal = r.effectiveValue()
				case "_stats_avg":
					avgVal = r.effectiveValue()
				}
			}
			bucketMap[subName] = map[string]any{
				"count":      cntVal,
				"min_length": int64(minVal),
				"max_length": int64(maxVal),
				"avg_length": avgVal,
				"entropy":    0.0,
			}
		case subSpec.Filter != nil || subSpec.Missing != nil || subSpec.EffectiveSampler() != nil || subSpec.ReverseNested != nil || subSpec.Nested != nil:
			var cnt int64
			for _, r := range subRows {
				if r.BucketKey == parentBucketKey {
					cnt = r.effectiveCount()
					break
				}
			}
			filterObj := map[string]any{"doc_count": cnt}
			if grandSubAggs := subSpec.SubAggs(); len(grandSubAggs) > 0 {
				attachSubAggsToBucket(indexName, filterObj, subFullKey, parentBucketKey, grandSubAggs, bucketsByAgg, docLookup)
				_ = evaluateChildPipelineAggs([]map[string]any{filterObj}, grandSubAggs)
				evaluateSiblingPipelineAggs(grandSubAggs, filterObj)
			}
			bucketMap[subName] = filterObj
		case subSpec.DateHistogram != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			matchingRows = synthesizeDateHistogramBuckets(matchingRows, subSpec.DateHistogram)
			if len(matchingRows) > 1 {
				sort.SliceStable(matchingRows, func(i, j int) bool {
					ki, _ := strconv.ParseInt(matchingRows[i].BucketKey, 10, 64)
					kj, _ := strconv.ParseInt(matchingRows[j].BucketKey, 10, 64)
					return ki < kj
				})
			}
			childBuckets := make([]map[string]any, 0, len(matchingRows))
			grandSubAggs := subSpec.SubAggs()
			for _, r := range matchingRows {
				epochMs, _ := strconv.ParseInt(r.BucketKey, 10, 64)
				keyStr := time.UnixMilli(epochMs).UTC().Format("2006-01-02T15:04:05.000Z")
				cb := map[string]any{
					"key_as_string": keyStr,
					"key":           epochMs,
					"doc_count":     r.effectiveCount(),
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucket(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup)
					scaleBucketRates(cb, grandSubAggs, &subSpec)
					evaluateSiblingPipelineAggs(grandSubAggs, cb)
				}
				childBuckets = append(childBuckets, cb)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggs(childBuckets, grandSubAggs)
			}
			bucketMap[subName] = formatKeyedBuckets(childBuckets, subSpec.DateHistogram.Keyed, "key_as_string")
		case subSpec.Histogram != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			matchingRows = synthesizeHistogramBuckets(matchingRows, subSpec.Histogram)
			if len(matchingRows) > 1 {
				sort.SliceStable(matchingRows, func(i, j int) bool {
					ki, _ := parseFiniteFloat(matchingRows[i].BucketKey)
					kj, _ := parseFiniteFloat(matchingRows[j].BucketKey)
					return ki < kj
				})
			}
			childBuckets := make([]map[string]any, 0, len(matchingRows))
			grandSubAggs := subSpec.SubAggs()
			for _, r := range matchingRows {
				numKey, _ := parseFiniteFloat(r.BucketKey)
				cb := map[string]any{
					"key":       numKey,
					"doc_count": r.effectiveCount(),
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucket(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup)
					scaleBucketRates(cb, grandSubAggs, &subSpec)
					evaluateSiblingPipelineAggs(grandSubAggs, cb)
				}
				childBuckets = append(childBuckets, cb)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggs(childBuckets, grandSubAggs)
			}
			bucketMap[subName] = formatKeyedBuckets(childBuckets, subSpec.Histogram.Keyed, "key")
		case subSpec.EffectiveRange() != nil:
			rngSpec := subSpec.EffectiveRange()
			isDateRange := subSpec.DateRange != nil
			isIPRange := subSpec.IPRange != nil
			nowUTC := time.Now().UTC()
			byKey := make(map[string]int64)
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					byKey[childKey] = r.effectiveCount()
				}
			}
			childBuckets := make([]map[string]any, 0, len(rngSpec.Ranges))
			grandSubAggs := subSpec.SubAggs()
			for _, rng := range rngSpec.Ranges {
				ek := rng.EffectiveKey()
				entry := map[string]any{
					"key":       ek,
					"doc_count": byKey[ek],
				}
				if rng.Mask != "" && isIPRange {
					entry["mask"] = rng.Mask
					if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(rng.Mask)); err == nil && ipNet != nil {
						startIP := ipNet.IP.To4()
						mask := ipNet.Mask
						if len(startIP) == 4 && len(mask) == 4 {
							endIP := net.IPv4(
								startIP[0]|^mask[0],
								startIP[1]|^mask[1],
								startIP[2]|^mask[2],
								startIP[3]|^mask[3],
							)
							entry["from"] = startIP.String()
							entry["to"] = endIP.String()
						}
					}
				}
				if rng.From != nil {
					entry["from"] = rng.From
					if isDateRange {
						if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", rng.From), nowUTC, false); ok {
							entry["from"] = float64(ms)
							entry["from_as_string"] = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
						}
					}
				}
				if rng.To != nil {
					entry["to"] = rng.To
					if isDateRange {
						if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", rng.To), nowUTC, false); ok {
							entry["to"] = float64(ms)
							entry["to_as_string"] = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
						}
					}
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucket(indexName, entry, subFullKey, parentBucketKey+"\x1f"+ek, grandSubAggs, bucketsByAgg, docLookup)
					evaluateSiblingPipelineAggs(grandSubAggs, entry)
				}
				childBuckets = append(childBuckets, entry)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggs(childBuckets, grandSubAggs)
			}
			bucketMap[subName] = formatKeyedBuckets(childBuckets, rngSpec.Keyed, "key")
		case subSpec.Filters != nil:
			byKey := make(map[string]int64)
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					byKey[childKey] = r.effectiveCount()
				}
			}
			grandSubAggs := subSpec.SubAggs()
			if subSpec.Filters.IsAnonymous {
				ordered := make([]map[string]any, 0, len(subSpec.Filters.AnonymousFilters)+1)
				for i := range subSpec.Filters.AnonymousFilters {
					fk := strconv.Itoa(i)
					bMap := map[string]any{"doc_count": byKey[fk]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+fk, grandSubAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+otherKey, grandSubAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if len(grandSubAggs) > 0 {
					ordered = evaluateChildPipelineAggs(ordered, grandSubAggs)
				}
				bucketMap[subName] = map[string]any{"buckets": ordered}
			} else {
				bucketsMap := make(map[string]any, len(subSpec.Filters.Filters)+1)
				for fk := range subSpec.Filters.Filters {
					bMap := map[string]any{"doc_count": byKey[fk]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+fk, grandSubAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					bucketsMap[fk] = bMap
				}
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucket(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+otherKey, grandSubAggs, bucketsByAgg, docLookup)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					bucketsMap[otherKey] = bMap
				}
				if len(grandSubAggs) > 0 {
					keys := make([]string, 0, len(bucketsMap))
					for fk := range bucketsMap {
						keys = append(keys, fk)
					}
					sort.Strings(keys)
					ordered := make([]map[string]any, 0, len(keys))
					for _, fk := range keys {
						if bm, ok := bucketsMap[fk].(map[string]any); ok {
							bm["__filter_key"] = fk
							bm["key"] = fk
							ordered = append(ordered, bm)
						}
					}
					ordered = evaluateChildPipelineAggs(ordered, grandSubAggs)
					if subSpec.Filters.Keyed != nil && !*subSpec.Filters.Keyed {
						for _, bm := range ordered {
							delete(bm, "__filter_key")
						}
						bucketMap[subName] = map[string]any{"buckets": ordered}
					} else {
						newBucketsMap := make(map[string]any, len(ordered))
						for _, bm := range ordered {
							fk, _ := bm["__filter_key"].(string)
							delete(bm, "__filter_key")
							delete(bm, "key")
							newBucketsMap[fk] = bm
						}
						bucketMap[subName] = map[string]any{"buckets": newBucketsMap}
					}
				} else if subSpec.Filters.Keyed != nil && !*subSpec.Filters.Keyed {
					keys := make([]string, 0, len(bucketsMap))
					for fk := range bucketsMap {
						keys = append(keys, fk)
					}
					sort.Strings(keys)
					arr := make([]map[string]any, 0, len(keys))
					for _, fk := range keys {
						if bm, ok := bucketsMap[fk].(map[string]any); ok {
							bm["key"] = fk
							arr = append(arr, bm)
						}
					}
					bucketMap[subName] = map[string]any{"buckets": arr}
				} else {
					bucketMap[subName] = map[string]any{"buckets": bucketsMap}
				}
			}
		case subSpec.EffectiveTerms() != nil:
			tSpec := subSpec.EffectiveTerms()
			isSig := subSpec.IsSignificantTerms()
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			matchingRows = filterAndSortTermsRows(matchingRows, tSpec, subFullKey, parentBucketKey, bucketsByAgg)
			parentCount := bucketDocCount
			for _, r := range matchingRows {
				if dc := r.effectiveCount(); dc > parentCount {
					parentCount = dc
				}
			}
			bgDenom := float64(parentCount)
			if bgDenom < 1 {
				bgDenom = 1
			}
			childBuckets := make([]map[string]any, 0, len(matchingRows))
			grandSubAggs := subSpec.SubAggs()
			for _, r := range matchingRows {
				docCnt := r.effectiveCount()
				cb := map[string]any{
					"key":       r.BucketKey,
					"doc_count": docCnt,
				}
				if isSig {
					fgProb := float64(docCnt) / bgDenom
					score := math.Round(fgProb*float64(docCnt)*10000) / 10000
					if math.IsNaN(score) || math.IsInf(score, 0) {
						score = 0
					}
					cb["score"] = score
					cb["bg_count"] = docCnt
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucket(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup)
					evaluateSiblingPipelineAggs(grandSubAggs, cb)
				}
				childBuckets = append(childBuckets, cb)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggs(childBuckets, grandSubAggs)
			}
			if isSig {
				bucketMap[subName] = map[string]any{
					"doc_count": parentCount,
					"bg_count":  parentCount,
					"buckets":   childBuckets,
				}
			} else {
				bucketMap[subName] = map[string]any{
					"doc_count_error_upper_bound": 0,
					"sum_other_doc_count":         0,
					"buckets":                     childBuckets,
				}
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
			thTotal := bucketDocCount
			if int64(len(topHitsList)) > thTotal {
				thTotal = int64(len(topHitsList))
			}
			bucketMap[subName] = map[string]any{
				"hits": map[string]any{
					"total":     map[string]any{"value": thTotal, "relation": "eq"},
					"max_score": 1.0,
					"hits":      topHitsList,
				},
			}
		case subSpec.TopMetrics != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if docID, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = docID
					matchingRows = append(matchingRows, cp)
				}
			}
			bucketMap[subName] = buildTopMetricsObject(matchingRows, subSpec.TopMetrics, docLookup)
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
		if strings.ContainsAny(cleanField, "*?") {
			if allLeafScalars == nil {
				allLeafScalars = make(map[string][]any)
				collectAllLeafScalarPaths(doc, "", allLeafScalars)
			}
			for leafPath, vals := range allLeafScalars {
				if matchWildcardPattern(cleanField, leafPath) && len(vals) > 0 {
					if _, alreadyExplicit := out[leafPath]; !alreadyExplicit {
						out[leafPath] = formatFieldValues(leafPath, vals, spec.Format, idxSchema)
					}
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
	isDateField := field == "@timestamp"
	if idxSchema != nil {
		b := idxSchema.ResolveField(field)
		if b.ESType == "date" || b.ESType == "date_nanos" {
			isDateField = true
		}
	}
	formatted := make([]any, 0, len(vals))
	for _, v := range vals {
		if jsonNum, ok := v.(json.Number); ok {
			if iv, err := jsonNum.Int64(); err == nil {
				v = iv
			} else if fv, err := jsonNum.Float64(); err == nil {
				v = fv
			}
		}
		switch typed := v.(type) {
		case string:
			if strings.EqualFold(format, "epoch_millis") {
				if ms, ok := schema.ParseESDateToEpochMillis(typed, time.Now().UTC()); ok {
					v = ms
				}
			} else if strings.EqualFold(format, "epoch_second") {
				if ms, ok := schema.ParseESDateToEpochMillis(typed, time.Now().UTC()); ok {
					v = ms / 1000
				}
			} else if idxSchema != nil {
				b := idxSchema.ResolveField(field)
				if b.LowercaseNormalizer {
					v = strings.ToLower(typed)
				}
			}
		case int64:
			if isDateField {
				if strings.EqualFold(format, "epoch_millis") {
					v = typed
				} else if strings.EqualFold(format, "epoch_second") {
					v = typed / 1000
				} else {
					v = time.UnixMilli(typed).UTC().Format("2006-01-02T15:04:05.000Z")
				}
			}
		case float64:
			if isDateField {
				ms := int64(typed)
				if strings.EqualFold(format, "epoch_millis") {
					v = ms
				} else if strings.EqualFold(format, "epoch_second") {
					v = ms / 1000
				} else {
					v = time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
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
		if next, exists := curr[path[0]]; exists {
			return collectScalarValuesAtPath(next, path[1:])
		}
		if len(path) > 1 {
			if flat, exists := curr[strings.Join(path, ".")]; exists {
				return collectScalarValuesAtPath(flat, nil)
			}
		}
		return nil
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
			rawVals := collectScalarValuesAtPath(doc, pathSegs)
			normVals := make([]any, 0, len(rawVals))
			for _, v := range rawVals {
				if jsonNum, ok := v.(json.Number); ok {
					if iv, err := jsonNum.Int64(); err == nil {
						v = iv
					} else if fv, err := jsonNum.Float64(); err == nil {
						v = fv
					}
				}
				if idxSchema != nil {
					b := idxSchema.ResolveField(s.Entry.Field)
					if strVal, ok := v.(string); ok {
						if b.LowercaseNormalizer {
							v = strings.ToLower(strVal)
						} else if b.DorisType == schema.DorisBigInt {
							if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
								v = ms
							}
						}
					}
				}
				normVals = append(normVals, v)
			}
			var val any
			if len(normVals) == 1 {
				val = normVals[0]
			} else if len(normVals) > 1 {
				val = reduceSortFieldValues(normVals, s.Entry.Mode, s.Entry.Order)
			} else if s.Entry.Missing != "" {
				mStr := s.Entry.Missing
				if !strings.EqualFold(mStr, "_last") && !strings.EqualFold(mStr, "_first") {
					if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
						val = iv
					} else if fv, err := strconv.ParseFloat(mStr, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						val = fv
					} else {
						val = s.Entry.Missing
					}
				}
			}
			out = append(out, val)
		}
	}
	return out
}

func reduceSortFieldValues(vals []any, mode, order string) any {
	if len(vals) == 0 {
		return nil
	}
	if len(vals) == 1 {
		return vals[0]
	}
	effMode := strings.ToLower(strings.TrimSpace(mode))
	if effMode == "" {
		if strings.EqualFold(order, "desc") {
			effMode = "max"
		} else {
			effMode = "min"
		}
	}
	nums := make([]float64, 0, len(vals))
	allInt := true
	allNumeric := true
	for _, v := range vals {
		if _, isInt := v.(int64); !isInt {
			allInt = false
		}
		if f, ok := toFloat64(v); ok {
			nums = append(nums, f)
		} else {
			allNumeric = false
			break
		}
	}
	if allNumeric && len(nums) > 0 {
		switch effMode {
		case "max":
			res := nums[0]
			for _, f := range nums[1:] {
				if f > res {
					res = f
				}
			}
			if allInt {
				return int64(res)
			}
			return res
		case "sum":
			var sum float64
			for _, f := range nums {
				sum += f
			}
			if allInt {
				return int64(sum)
			}
			return sum
		case "avg":
			var sum float64
			for _, f := range nums {
				sum += f
			}
			return sum / float64(len(nums))
		case "median":
			sorted := append([]float64(nil), nums...)
			sort.Float64s(sorted)
			mid := len(sorted) / 2
			if len(sorted)%2 == 1 {
				return sorted[mid]
			}
			return (sorted[mid-1] + sorted[mid]) / 2.0
		default: // "min"
			res := nums[0]
			for _, f := range nums[1:] {
				if f < res {
					res = f
				}
			}
			if allInt {
				return int64(res)
			}
			return res
		}
	}
	strs := make([]string, len(vals))
	allIPv4 := true
	for i, v := range vals {
		strs[i] = fmt.Sprintf("%v", v)
		if _, ok := parseIPv4SortUint32(strs[i]); !ok {
			allIPv4 = false
		}
	}
	if allIPv4 {
		sort.Slice(strs, func(i, j int) bool {
			ipI, _ := parseIPv4SortUint32(strs[i])
			ipJ, _ := parseIPv4SortUint32(strs[j])
			return ipI < ipJ
		})
	} else {
		sort.Strings(strs)
	}
	if effMode == "max" {
		return strs[len(strs)-1]
	}
	return strs[0]
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
			hasChildInclude := hasWildcardChildInclude(fullPath, includes)
			if !exactOrParentMatch && !hasChildInclude {
				continue
			}
			if !exactOrParentMatch && hasChildInclude {
				if subMap, ok := v.(map[string]any); ok {
					filteredSub := filterMapByPaths(subMap, fullPath, includes, excludes)
					if len(filteredSub) > 0 {
						out[k] = filteredSub
					}
					continue
				}
				if subSlice, ok := v.([]any); ok {
					var newSlice []any
					for _, elem := range subSlice {
						if elemMap, ok := elem.(map[string]any); ok {
							filteredElem := filterMapByPaths(elemMap, fullPath, includes, excludes)
							if len(filteredElem) > 0 {
								newSlice = append(newSlice, filteredElem)
							}
						}
					}
					if len(newSlice) > 0 {
						out[k] = newSlice
					}
					continue
				}
				continue
			}
		}
		if subMap, ok := v.(map[string]any); ok && len(excludes) > 0 {
			out[k] = filterMapByPaths(subMap, fullPath, nil, excludes)
			continue
		}
		if subSlice, ok := v.([]any); ok && len(excludes) > 0 {
			newSlice := make([]any, 0, len(subSlice))
			for _, elem := range subSlice {
				if elemMap, ok := elem.(map[string]any); ok {
					newSlice = append(newSlice, filterMapByPaths(elemMap, fullPath, nil, excludes))
				} else {
					newSlice = append(newSlice, elem)
				}
			}
			out[k] = newSlice
			continue
		}
		out[k] = v
	}
	return out
}

func hasWildcardChildInclude(fullPath string, includes []string) bool {
	pathSegs := strings.Split(fullPath, ".")
	for _, inc := range includes {
		if strings.HasPrefix(inc, fullPath+".") {
			return true
		}
		incSegs := strings.Split(inc, ".")
		matchedPrefix := true
		for i, ps := range pathSegs {
			if i >= len(incSegs) {
				matchedPrefix = false
				break
			}
			if starIdx := strings.IndexByte(incSegs[i], '*'); starIdx >= 0 {
				litPrefix := incSegs[i][:starIdx]
				if strings.HasPrefix(ps, litPrefix) {
					return true
				}
			}
			if !matchWildcardPattern(incSegs[i], ps) {
				matchedPrefix = false
				break
			}
		}
		if matchedPrefix && len(incSegs) > len(pathSegs) {
			return true
		}
	}
	return false
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
	out, _ := s.resolveTargetIndicesWithFilters(pattern)
	return out
}

func (s *Server) resolveTargetIndicesWithFilters(pattern string) ([]string, map[string]*esast.Query) {
	out, filters := s.resolveTargetIndicesWithFiltersOnce(pattern)
	if len(out) == 0 {
		_ = s.syncCatalogFromBackend(context.Background())
		out, filters = s.resolveTargetIndicesWithFiltersOnce(pattern)
	}
	return out, filters
}

func (s *Server) resolveTargetIndicesWithFiltersOnce(pattern string) ([]string, map[string]*esast.Query) {
	if pattern == "" || pattern == "_all" || pattern == "*" {
		s.mu.RLock()
		defer s.mu.RUnlock()
		var all []string
		for name := range s.indices {
			all = append(all, name)
		}
		sort.Strings(all)
		return all, nil
	}

	parts := strings.Split(pattern, ",")
	seen := make(map[string]bool)
	directNoFilter := make(map[string]bool)
	aliasFilters := make(map[string][]esast.Query)
	var out []string
	var needsSync bool

	addTarget := func(idx string, f *esast.Query) {
		if idx == "" {
			return
		}
		if !seen[idx] {
			seen[idx] = true
			out = append(out, idx)
		}
		if f == nil {
			directNoFilter[idx] = true
			delete(aliasFilters, idx)
		} else if !directNoFilter[idx] {
			aliasFilters[idx] = append(aliasFilters[idx], *f)
		}
	}

	removeTarget := func(idx string) {
		if !seen[idx] {
			return
		}
		delete(seen, idx)
		delete(directNoFilter, idx)
		delete(aliasFilters, idx)
		filtered := out[:0]
		for _, existing := range out {
			if existing != idx {
				filtered = append(filtered, existing)
			}
		}
		out = filtered
	}

	scanLocked := func(checkUnknown bool) {
		var excls []string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "-") {
				if excl := strings.TrimSpace(strings.TrimPrefix(part, "-")); excl != "" {
					excls = append(excls, excl)
				}
			}
		}
		isExcluded := func(name string) bool {
			for _, excl := range excls {
				if matchWildcardPattern(excl, name) {
					return true
				}
			}
			return false
		}

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.HasPrefix(part, "-") {
				excl := strings.TrimSpace(strings.TrimPrefix(part, "-"))
				if excl == "" {
					continue
				}
				snapshot := append([]string(nil), out...)
				for _, idxName := range snapshot {
					if matchWildcardPattern(excl, idxName) {
						removeTarget(idxName)
					}
				}
				continue
			}
			if part == "_all" || part == "*" {
				for idxName := range s.indices {
					if !isExcluded(idxName) {
						addTarget(idxName, nil)
					}
				}
				continue
			}
			if strings.Contains(part, "*") {
				matchedAny := false
				for idxName := range s.indices {
					if matchWildcardPattern(part, idxName) {
						matchedAny = true
						if !isExcluded(idxName) {
							addTarget(idxName, nil)
						}
					}
				}
				for alias, targets := range s.aliases {
					if matchWildcardPattern(part, alias) {
						matchedAny = true
						if isExcluded(alias) {
							continue
						}
						metaByIdx := s.aliasMeta[alias]
						for _, t := range targets {
							if isExcluded(t) {
								continue
							}
							var f *esast.Query
							if metaByIdx != nil {
								f = metaByIdx[t].Filter
							}
							addTarget(t, f)
						}
					}
				}
				if checkUnknown && !matchedAny {
					needsSync = true
				}
				continue
			}
			if targets, ok := s.aliases[part]; ok && len(targets) > 0 {
				if isExcluded(part) {
					continue
				}
				metaByIdx := s.aliasMeta[part]
				for _, t := range targets {
					if isExcluded(t) {
						continue
					}
					var f *esast.Query
					if metaByIdx != nil {
						f = metaByIdx[t].Filter
					}
					addTarget(t, f)
				}
				continue
			}
			if checkUnknown {
				if _, isKnownIndex := s.indices[part]; !isKnownIndex {
					needsSync = true
				}
			}
			if !isExcluded(part) {
				addTarget(part, nil)
			}
		}
	}

	s.mu.RLock()
	scanLocked(true)
	s.mu.RUnlock()

	if needsSync {
		_ = s.syncCatalogFromBackend(context.Background())
		seen = make(map[string]bool)
		directNoFilter = make(map[string]bool)
		aliasFilters = make(map[string][]esast.Query)
		out = nil
		s.mu.RLock()
		scanLocked(false)
		s.mu.RUnlock()
	}

	sort.Strings(out)
	var finalFilters map[string]*esast.Query
	if len(aliasFilters) > 0 {
		finalFilters = make(map[string]*esast.Query, len(aliasFilters))
		for idx, qs := range aliasFilters {
			if len(qs) == 1 {
				qCopy := qs[0]
				finalFilters[idx] = &qCopy
			} else if len(qs) > 1 {
				finalFilters[idx] = &esast.Query{
					Bool: &esast.BoolQuery{
						Should:             append([]esast.Query(nil), qs...),
						MinimumShouldMatch: 1,
					},
				}
			}
		}
	}
	return out, finalFilters
}

func combineQueryWithAliasFilter(q, aliasFilter *esast.Query) *esast.Query {
	if aliasFilter == nil {
		return q
	}
	if q == nil || q.MatchAll != nil {
		return &esast.Query{
			Bool: &esast.BoolQuery{
				Filter: []esast.Query{*aliasFilter},
			},
		}
	}
	return &esast.Query{
		Bool: &esast.BoolQuery{
			Must:   []esast.Query{*q},
			Filter: []esast.Query{*aliasFilter},
		},
	}
}

func applyIndexAliasFilter(req *esast.SearchRequest, aliasFilter *esast.Query) *esast.SearchRequest {
	if req == nil || aliasFilter == nil {
		return req
	}
	cp := *req
	af := *aliasFilter
	cp.AliasFilter = &af
	if len(req.KNN) > 0 {
		cpKNN := make([]esast.KNNQuery, len(req.KNN))
		for i, k := range req.KNN {
			cpK := k
			cpK.Filter = append(append([]esast.Query(nil), k.Filter...), *aliasFilter)
			cpKNN[i] = cpK
		}
		cp.KNN = cpKNN
	}
	return &cp
}

func (s *Server) resolveWriteIndex(nameOrAlias string) (string, error) {
	idx, _, err := s.resolveWriteIndexWithFilter(nameOrAlias)
	return idx, err
}

func (s *Server) resolveWriteIndexWithFilter(nameOrAlias string) (string, *esast.Query, error) {
	if nameOrAlias == "" {
		return "default_index", nil, nil
	}
	if idx := strings.IndexByte(nameOrAlias, ','); idx > 0 {
		nameOrAlias = nameOrAlias[:idx]
	}
	resolveLocked := func() (string, *esast.Query, bool, error) {
		if targets, ok := s.aliases[nameOrAlias]; ok && len(targets) > 0 {
			metaByIdx := s.aliasMeta[nameOrAlias]
			if len(targets) == 1 {
				var f *esast.Query
				if metaByIdx != nil && metaByIdx[targets[0]].Filter != nil {
					cp := *metaByIdx[targets[0]].Filter
					f = &cp
				}
				return targets[0], f, true, nil
			}
			var writeTargets []string
			for _, t := range targets {
				if metaByIdx != nil && metaByIdx[t].IsWriteIndex != nil && *metaByIdx[t].IsWriteIndex {
					writeTargets = append(writeTargets, t)
				}
			}
			if len(writeTargets) == 1 {
				var f *esast.Query
				if metaByIdx != nil && metaByIdx[writeTargets[0]].Filter != nil {
					cp := *metaByIdx[writeTargets[0]].Filter
					f = &cp
				}
				return writeTargets[0], f, true, nil
			}
			return "", nil, true, fmt.Errorf("alias [%s] has more than one index associated with it %v, cannot execute a single index op without is_write_index=true", nameOrAlias, targets)
		}
		if _, ok := s.indices[nameOrAlias]; ok {
			return nameOrAlias, nil, true, nil
		}
		return "", nil, false, nil
	}

	s.mu.RLock()
	resolved, filter, found, err := resolveLocked()
	s.mu.RUnlock()
	if found {
		return resolved, filter, err
	}

	_ = s.syncCatalogFromBackend(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	resolved, filter, found, err = resolveLocked()
	if found {
		return resolved, filter, err
	}
	return nameOrAlias, nil, nil
}

func (s *Server) resolveReadDocIndexWithFilter(nameOrAlias string) (string, *esast.Query, error) {
	if nameOrAlias == "" {
		return "default_index", nil, nil
	}
	if idx := strings.IndexByte(nameOrAlias, ','); idx > 0 {
		nameOrAlias = nameOrAlias[:idx]
	}
	resolveLocked := func() (string, *esast.Query, bool, error) {
		if targets, ok := s.aliases[nameOrAlias]; ok && len(targets) > 0 {
			if len(targets) > 1 {
				return "", nil, true, fmt.Errorf("alias [%s] has more than one index associated with it %v, cannot execute a single document read op", nameOrAlias, targets)
			}
			var f *esast.Query
			if metaByIdx := s.aliasMeta[nameOrAlias]; metaByIdx != nil && metaByIdx[targets[0]].Filter != nil {
				cp := *metaByIdx[targets[0]].Filter
				f = &cp
			}
			return targets[0], f, true, nil
		}
		if _, ok := s.indices[nameOrAlias]; ok {
			return nameOrAlias, nil, true, nil
		}
		return "", nil, false, nil
	}

	s.mu.RLock()
	resolved, filter, found, err := resolveLocked()
	s.mu.RUnlock()
	if found {
		return resolved, filter, err
	}

	_ = s.syncCatalogFromBackend(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	resolved, filter, found, err = resolveLocked()
	if found {
		return resolved, filter, err
	}
	return nameOrAlias, nil, nil
}

func (s *Server) docMatchesAliasFilter(ctx context.Context, indexName, docID string, rawSource json.RawMessage, filter *esast.Query) bool {
	if filter == nil {
		return true
	}
	if len(rawSource) == 0 {
		return false
	}
	idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
	if idxSchema == nil {
		idxSchema = schema.CompileIndexSchema(s.dorisDB, indexName, nil)
	}
	if idxSchema.RawMapping == nil || idxSchema.RawMapping.Dynamic == nil || idxSchema.RawMapping.Dynamic == true || idxSchema.RawMapping.Dynamic == "true" {
		inferred := schema.InferMappingFromSampleDocs([]json.RawMessage{rawSource})
		if inferred != nil && len(inferred.Properties) > 0 {
			merged := schema.MergeMappingSpecs(inferred, idxSchema.RawMapping)
			idxSchema = schema.CompileIndexSchema(s.dorisDB, indexName, merged)
		}
	}
	shreddedBytes, err := schema.ShredDocument(idxSchema, docID, 1, false, rawSource)
	if err != nil {
		return false
	}
	var row map[string]any
	dec := json.NewDecoder(bytes.NewReader(shreddedBytes))
	dec.UseNumber()
	if err := dec.Decode(&row); err != nil {
		return false
	}
	var docMap map[string]any
	docDec := json.NewDecoder(bytes.NewReader(rawSource))
	docDec.UseNumber()
	if err := docDec.Decode(&docMap); err == nil {
		row["_doc"] = docMap
	}
	effFilter := filter
	if hasTermsLookupInQuery(filter) {
		if raw, err := json.Marshal(filter); err == nil {
			var cloned esast.Query
			if err := json.Unmarshal(raw, &cloned); err == nil {
				s.resolveTermsLookupsInQuery(ctx, &cloned)
				effFilter = &cloned
			}
		}
	}
	t := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	cq := t.CompileQuery(effFilter, false, nil)
	whereExpr := strings.TrimSpace(cq.WhereSQL)
	if whereExpr == "" || whereExpr == "1=1" || strings.EqualFold(whereExpr, "TRUE") {
		return true
	}
	return evalWhereExpr(row, whereExpr)
}

func hasExclusionOrWildcard(rawIndex string) bool {
	if strings.Contains(rawIndex, "*") {
		return true
	}
	for _, part := range strings.Split(rawIndex, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, "-") || p == "_all" {
			return true
		}
	}
	return false
}

func (s *Server) resolveIndexNameWithFilter(nameOrAlias string) (string, *esast.Query) {
	if nameOrAlias == "" {
		return "default_index", nil
	}
	if idx := strings.IndexByte(nameOrAlias, ','); idx > 0 {
		nameOrAlias = nameOrAlias[:idx]
	}
	lookupLocked := func() (string, *esast.Query, bool) {
		if targets, ok := s.aliases[nameOrAlias]; ok && len(targets) > 0 {
			var f *esast.Query
			if metaByIdx := s.aliasMeta[nameOrAlias]; metaByIdx != nil && metaByIdx[targets[0]].Filter != nil {
				cp := *metaByIdx[targets[0]].Filter
				f = &cp
			}
			return targets[0], f, true
		}
		if _, ok := s.indices[nameOrAlias]; ok {
			return nameOrAlias, nil, true
		}
		return "", nil, false
	}
	s.mu.RLock()
	if resolved, f, ok := lookupLocked(); ok {
		s.mu.RUnlock()
		return resolved, f
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	if resolved, f, ok := lookupLocked(); ok {
		return resolved, f
	}
	return nameOrAlias, nil
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
	s.queryCache.InvalidateAll()
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

func extractPITIndex(rawIndex string, pit *esast.PITSpec) string {
	if rawIndex == "" && pit != nil && pit.ID != "" {
		if pitIdx, ok := decodePITIndex(pit.ID); ok && pitIdx != "" {
			return pitIdx
		}
	}
	return rawIndex
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
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == target
	}
	pIdx, tIdx := 0, 0
	starIdx, matchIdx := -1, 0
	for tIdx < len(target) {
		if pIdx < len(pattern) && (pattern[pIdx] == target[tIdx] || pattern[pIdx] == '?') {
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
	opts, _ := extractESResponseFormatOptions(w)
	if len(opts.filterPaths) > 0 {
		v = applyESFilterPath(v, opts.filterPaths)
	}
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if opts.pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
}

func writeESError(w http.ResponseWriter, status int, errType, reason string) {
	opts, _ := extractESResponseFormatOptions(w)
	rootCause := map[string]any{"type": errType, "reason": reason}
	errObj := map[string]any{
		"root_cause": []map[string]any{rootCause},
		"type":       errType,
		"reason":     reason,
	}
	if opts.errorTrace {
		trace := fmt.Sprintf("org.elasticsearch.ElasticsearchException$1: %s\n\tat org.elasticsearch.rest.BytesRestResponse.build(BytesRestResponse.java:140)", reason)
		rootCause["stack_trace"] = trace
		errObj["stack_trace"] = trace
	}
	writeJSON(w, status, map[string]any{
		"error":  errObj,
		"status": status,
	})
}
